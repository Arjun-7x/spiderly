"""
SPIDERLY - Scan orchestration.

Ties together host discovery -> port scanning -> service detection ->
HTTP enumeration -> findings, persisting every step to the database and
broadcasting real-time events to any connected WebSocket clients.
"""
import asyncio
import logging
import time
from typing import Dict, List, Set

from app.core.config import settings
from app.core.security import ValidationError, check_target_policy
from app.database import database as db
from app.scanner import host_discovery, port_scanner, service_detector, http_enum, findings as findings_engine

logger = logging.getLogger("spiderly.scans")

TERMINAL_EVENTS = {"scan.completed", "scan.failed", "scan.cancelled"}

# scan_id -> set of asyncio.Queue (one per connected websocket client)
_subscribers: Dict[str, Set[asyncio.Queue]] = {}

# scan_id -> the asyncio.Task running the scan (for cancellation / limits)
_scan_tasks: Dict[str, asyncio.Task] = {}

# scan_id -> per-port detection tasks (strong refs so they aren't GC'd, and so
# the scan can wait for / cancel its own stragglers).
_background_tasks: Dict[str, Set[asyncio.Task]] = {}

_detection_sem: asyncio.Semaphore | None = None


def _get_detection_sem() -> asyncio.Semaphore:
    global _detection_sem
    if _detection_sem is None:
        _detection_sem = asyncio.Semaphore(settings.DETECTION_CONCURRENCY)
    return _detection_sem


def active_scan_count() -> int:
    return sum(1 for t in _scan_tasks.values() if not t.done())


def start_scan(scan_id: str, target: str, ports: List[int], scan_mode: str) -> None:
    task = asyncio.create_task(run_scan(scan_id, target, ports, scan_mode))
    _scan_tasks[scan_id] = task
    task.add_done_callback(lambda _t, sid=scan_id: _scan_tasks.pop(sid, None))


def cancel_scan(scan_id: str) -> bool:
    """Request cancellation. Returns False if the scan isn't running here."""
    task = _scan_tasks.get(scan_id)
    if task is None or task.done():
        return False
    task.cancel()
    return True


def _track(scan_id: str, task: asyncio.Task) -> None:
    tasks = _background_tasks.setdefault(scan_id, set())
    tasks.add(task)
    task.add_done_callback(tasks.discard)


def subscribe(scan_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(scan_id, set()).add(q)
    return q


def unsubscribe(scan_id: str, q: asyncio.Queue) -> None:
    if scan_id in _subscribers:
        _subscribers[scan_id].discard(q)
        if not _subscribers[scan_id]:
            _subscribers.pop(scan_id, None)


async def _emit(scan_id: str, event_type: str, message: str, data: dict = None) -> None:
    row = await db.run(db._add_event, scan_id, event_type, message, data)
    for q in list(_subscribers.get(scan_id, [])):
        q.put_nowait(row)


async def _drain_background(scan_id: str) -> None:
    """Let per-port detection finish (bounded); cancel whatever is still running
    so nothing lands in the database after the scan is marked complete."""
    pending = list(_background_tasks.get(scan_id, ()))
    if not pending:
        return
    _, still_running = await asyncio.wait(pending, timeout=settings.POST_SCAN_GRACE_SECONDS)
    for t in still_running:
        t.cancel()
    if still_running:
        await asyncio.gather(*still_running, return_exceptions=True)
        await _emit(scan_id, "log",
                    f"{len(still_running)} service probe(s) timed out and were skipped.")


async def run_scan(scan_id: str, target: str, ports: List[int], scan_mode: str) -> None:
    started = time.time()
    open_ports: List[int] = []
    try:
        await _emit(scan_id, "scan.started", f"Reconnaissance started against {target}.", {"target": target})
        await _emit(scan_id, "log", f"Target validated: {target}")

        ip = await host_discovery.resolve_target(target)
        if ip != target:
            await _emit(scan_id, "log", f"Resolved {target} -> {ip}")
        check_target_policy(ip)  # enforced on the *resolved* address (hostnames can point anywhere)

        reachable = await host_discovery.check_reachable(ip)
        host_id = await db.run(db._add_host, scan_id, ip, reachable)
        await _emit(
            scan_id,
            "host.discovered",
            f"Host {ip} is {'reachable' if reachable else 'not responding to probes'}.",
            {"host_id": host_id, "address": ip, "reachable": reachable},
        )

        if not reachable:
            await _emit(scan_id, "log", "Host did not respond to reachability probes; continuing with full port scan anyway.")

        total = len(ports)
        scanned = 0

        async for result in port_scanner.scan_ports(ip, ports):
            scanned += 1
            if result.state == "open":
                open_ports.append(result.port)
                service_guess = service_detector.guess_service(result.port)
                port_id = await db.run(db._add_port, scan_id, host_id, result.port, "open", service_guess, None)
                await _emit(
                    scan_id, "port.discovered",
                    f"Port {result.port} discovered open ({service_guess}).",
                    {"port": result.port, "state": "open", "service_guess": service_guess,
                     "progress": {"scanned": scanned, "total": total}},
                )
                _track(scan_id, asyncio.create_task(_detect_service(scan_id, ip, port_id, result.port, service_guess)))
            elif scanned % 25 == 0 or scanned == total:
                await _emit(
                    scan_id, "progress",
                    f"Port enumeration: {scanned}/{total} probed.",
                    {"progress": {"scanned": scanned, "total": total}},
                )

        await _drain_background(scan_id)

        await db.run(db._finish_scan, scan_id, "completed", None)
        duration = round(time.time() - started, 2)
        await _emit(
            scan_id, "scan.completed",
            f"Scan complete. {len(open_ports)} open port(s) found in {duration}s.",
            {"open_ports": sorted(open_ports), "duration_seconds": duration},
        )
    except asyncio.CancelledError:
        # Top-level scan task: clean up and record the outcome, then end normally.
        for t in list(_background_tasks.get(scan_id, ())):
            t.cancel()
        await db.run(db._finish_scan, scan_id, "cancelled", "Cancelled by user.")
        await _emit(scan_id, "scan.cancelled", "Scan cancelled.", {"open_ports": sorted(open_ports)})
    except (ValidationError, host_discovery.ResolutionError) as exc:
        await db.run(db._finish_scan, scan_id, "failed", str(exc))
        await _emit(scan_id, "scan.failed", f"Scan refused: {exc}", {"error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan %s failed", scan_id)
        await db.run(db._finish_scan, scan_id, "failed", str(exc))
        await _emit(scan_id, "scan.failed", f"Scan failed: {exc}", {"error": str(exc)})
    finally:
        _background_tasks.pop(scan_id, None)


async def _detect_service(scan_id: str, ip: str, port_id: str, port: int, service_guess: str) -> None:
    async with _get_detection_sem():
        banner = await service_detector.grab_banner(ip, port)
        refined = service_detector.refine_service_from_banner(port, banner)
        version = service_detector.extract_version(refined, banner)

        if refined != service_guess or banner:
            await db.run(db._update_port_service, port_id, refined, banner, version)

        await _emit(
            scan_id, "service.detected",
            f"Port {port}: identified as {refined}" + (f" ({version})" if version else "")
            + "." + (" Banner captured." if banner else ""),
            {"port": port, "service": refined, "banner": banner, "version": version},
        )

        for f in findings_engine.evaluate_open_port(port, refined, banner):
            await db.run(db._add_finding, scan_id, f.title, f.severity, f.description, f.evidence,
                         f.affected_service, f.recommendation, port)
            await _emit(scan_id, "finding.created", f.title, {"severity": f.severity, "port": port})

        if http_enum.looks_like_http(port) or refined == "HTTP":
            info = await http_enum.fetch_metadata(ip, port)
            if info:
                await db.run(
                    db._add_http_metadata, scan_id, port_id, info.status_code, info.server_header,
                    info.title, info.content_type, info.tls, info.redirect_location,
                )
                await _emit(
                    scan_id, "http.detected",
                    f"HTTP metadata collected for port {port} (status {info.status_code}).",
                    {"port": port, "status_code": info.status_code, "title": info.title, "tls": info.tls},
                )
                for f in findings_engine.evaluate_http(port, info.status_code, info.server_header, info.tls, info.title):
                    await db.run(db._add_finding, scan_id, f.title, f.severity, f.description, f.evidence,
                                 f.affected_service, f.recommendation, port)
                    await _emit(scan_id, "finding.created", f.title, {"severity": f.severity, "port": port})
