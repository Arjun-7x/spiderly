"""
SPIDERLY - Async TCP connect-scan.

This performs a real TCP three-way-handshake connect scan (no raw
sockets / no root privileges required). Concurrency is bounded by a
semaphore so SPIDERLY never floods the target or the local network
stack, and every connection has a hard timeout.
"""
import asyncio
from dataclasses import dataclass
from typing import AsyncIterator, List

from app.core.config import settings


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"


async def _scan_one(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult:
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortResult(port, "open")
        except ConnectionRefusedError:
            return PortResult(port, "closed")
        except asyncio.TimeoutError:
            return PortResult(port, "filtered")
        except OSError:
            return PortResult(port, "filtered")


async def scan_ports(
    ip: str,
    ports: List[int],
    timeout: float = None,
    max_concurrency: int = None,
) -> AsyncIterator[PortResult]:
    """Yields PortResult objects as they complete (not in port order)."""
    timeout = timeout or settings.DEFAULT_TIMEOUT_SECONDS
    max_concurrency = max_concurrency or settings.MAX_CONCURRENT_PORT_SCANS
    sem = asyncio.Semaphore(max_concurrency)

    tasks = [asyncio.create_task(_scan_one(ip, p, timeout, sem)) for p in ports]
    try:
        for coro in asyncio.as_completed(tasks):
            yield await coro
    finally:
        # Scan cancelled or consumer stopped early: don't leave probes running.
        for t in tasks:
            if not t.done():
                t.cancel()
