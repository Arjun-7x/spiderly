import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.api.auth import Identity, authenticate, can_access, require_api_key
from app.core.config import settings
from app.core.ratelimit import scan_limiter
from app.core.security import (
    ValidationError, check_target_policy, parse_port_spec, validate_scan_mode, validate_target,
)
from app.database import database as db
from app.services import scan_manager

router = APIRouter(dependencies=[Depends(require_api_key)])
ws_router = APIRouter()  # WebSocket auth is checked manually (no Request object)


class ScanCreateRequest(BaseModel):
    target: str
    scan_mode: str = "quick"
    port_spec: str | None = None


async def _load_scan(scan_id: str, ident: Identity) -> dict:
    """Fetch a scan the caller may access. Someone else's scan looks exactly like
    a missing one (404) so scan IDs can't be probed for existence."""
    scan = await db.run(db._get_scan, scan_id)
    if not scan or not can_access(scan, ident):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.post("/scans")
async def create_scan(payload: ScanCreateRequest, request: Request, ident: Identity = Depends(require_api_key)):
    try:
        target = validate_target(payload.target)
        try:  # IP literals can be policy-checked immediately; hostnames after resolution
            import ipaddress
            ipaddress.ip_address(target)
            check_target_policy(target)
        except ValueError:
            pass
        mode = validate_scan_mode(payload.scan_mode)
        if mode == "quick":
            port_spec = settings.QUICK_PORTS
        elif mode == "standard":
            port_spec = settings.STANDARD_RANGE
        else:
            if not payload.port_spec:
                raise ValidationError("Custom scan mode requires a port_spec.")
            port_spec = payload.port_spec
        ports = parse_port_spec(port_spec)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    limiter_key = f"scan:{ident.name if settings.auth_enabled else (request.client.host if request.client else 'unknown')}"
    if not scan_limiter.allow(limiter_key, settings.SCAN_RATE_LIMIT, settings.SCAN_RATE_WINDOW):
        raise HTTPException(
            status_code=429,
            detail=f"Scan rate limit reached ({settings.SCAN_RATE_LIMIT} per {int(settings.SCAN_RATE_WINDOW)}s).",
            headers={"Retry-After": str(scan_limiter.retry_after(limiter_key, settings.SCAN_RATE_WINDOW))},
        )

    if scan_manager.active_scan_count() >= settings.MAX_ACTIVE_SCANS:
        raise HTTPException(
            status_code=429,
            detail=f"Too many scans running (limit {settings.MAX_ACTIVE_SCANS}). Wait for one to finish or cancel it.",
        )

    scan_id = db.new_id()
    await db.run(db._create_scan, scan_id, target, port_spec, mode, ident.name if settings.auth_enabled else None)
    scan_manager.start_scan(scan_id, target, ports, mode)

    return {"scan_id": scan_id, "target": target, "port_spec": port_spec, "scan_mode": mode, "status": "running"}


@router.get("/scans")
async def list_scans(ident: Identity = Depends(require_api_key)):
    return await db.run(db._list_scans, ident.owner_filter)


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, ident: Identity = Depends(require_api_key)):
    return await _load_scan(scan_id, ident)


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, ident: Identity = Depends(require_api_key)):
    scan = await _load_scan(scan_id, ident)
    if not scan_manager.cancel_scan(scan_id):
        raise HTTPException(status_code=409, detail=f"Scan is not running (status: {scan['status']}).")
    return {"scan_id": scan_id, "status": "cancelling"}


@router.get("/scans/{scan_id}/results")
async def get_results(scan_id: str, ident: Identity = Depends(require_api_key)):
    await _load_scan(scan_id, ident)
    results = await db.run(db._get_results, scan_id)
    if not results:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return results


@router.get("/scans/{scan_id}/events")
async def get_events(scan_id: str, ident: Identity = Depends(require_api_key)):
    await _load_scan(scan_id, ident)
    return await db.run(db._get_events, scan_id)


@ws_router.websocket("/ws/scans/{scan_id}")
async def scan_events_ws(websocket: WebSocket, scan_id: str):
    try:
        ident = authenticate(websocket.query_params.get("api_key"),
                             websocket.client.host if websocket.client else "unknown")
    except HTTPException:
        await websocket.close(code=1008)
        return
    await websocket.accept()

    scan = await db.run(db._get_scan, scan_id)
    if not scan or not can_access(scan, ident):
        await websocket.send_text(json.dumps({"event_type": "error", "message": "Scan not found.", "data": {}}))
        await websocket.close()
        return

    # Subscribe BEFORE replaying history so no event can fall into the gap;
    # then de-duplicate by id (an event may appear in both the replay and the queue).
    q = scan_manager.subscribe(scan_id)
    try:
        seen = set()
        for event in await db.run(db._get_events, scan_id):
            seen.add(event["id"])
            await websocket.send_text(json.dumps(event))
            if event["event_type"] in scan_manager.TERMINAL_EVENTS:
                await websocket.close()  # finished scan: history replayed, nothing more will come
                return

        while True:
            event = await q.get()
            if event["id"] in seen:
                continue
            await websocket.send_text(json.dumps(event))
            if event["event_type"] in scan_manager.TERMINAL_EVENTS:
                await websocket.close()
                return
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        scan_manager.unsubscribe(scan_id, q)
