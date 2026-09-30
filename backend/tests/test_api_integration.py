"""End-to-end tests: real TCP listener on localhost <-> real scanner <-> real API."""
import asyncio

import pytest

from app.core.config import settings
from app.services import scan_manager


async def _start_banner_server(banner: bytes = b"SSH-2.0-TestServer\r\n"):
    async def handle(_reader, writer):
        writer.write(banner)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _wait_for_status(client, scan_id, wanted, timeout=15):
    for _ in range(int(timeout / 0.1)):
        scan = (await client.get(f"/api/scans/{scan_id}")).json()
        if scan["status"] in wanted:
            return scan
        await asyncio.sleep(0.1)
    raise AssertionError(f"scan never reached {wanted}: {scan}")


async def test_full_scan_finds_open_port_and_identifies_ssh(client):
    server, port = await _start_banner_server()
    async with server:
        r = await client.post("/api/scans", json={"target": "127.0.0.1", "scan_mode": "custom", "port_spec": str(port)})
        assert r.status_code == 200
        scan_id = r.json()["scan_id"]
        await _wait_for_status(client, scan_id, {"completed"})

    results = (await client.get(f"/api/scans/{scan_id}/results")).json()
    open_ports = [p for p in results["ports"] if p["state"] == "open"]
    assert [p["port"] for p in open_ports] == [port]
    assert open_ports[0]["service_guess"] == "SSH"
    assert "SSH-2.0-TestServer" in open_ports[0]["banner"]
    assert results["findings"], "expected at least one finding"

    # Events replayed from history carry dict data, and end with a terminal event.
    events = (await client.get(f"/api/scans/{scan_id}/events")).json()
    assert events[-1]["event_type"] == "scan.completed"
    assert all(isinstance(e["data"], dict) for e in events)

    report = await client.get(f"/api/reports/{scan_id}")
    assert report.status_code == 200
    assert "default-src 'none'" in report.headers["content-security-policy"]


async def test_metadata_ip_is_rejected(client):
    r = await client.post("/api/scans", json={"target": "169.254.169.254", "scan_mode": "quick"})
    assert r.status_code == 422


async def test_bad_port_spec_is_422_not_500(client):
    r = await client.post("/api/scans", json={"target": "127.0.0.1", "scan_mode": "custom", "port_spec": "80-"})
    assert r.status_code == 422


async def test_unresolvable_host_fails_cleanly(client):
    r = await client.post("/api/scans", json={"target": "no-such-host.invalid", "scan_mode": "custom", "port_spec": "80"})
    assert r.status_code == 200
    scan = await _wait_for_status(client, r.json()["scan_id"], {"failed"})
    assert "resolve" in scan["error"].lower()


async def test_api_key_enforced_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "s3cret")
    assert (await client.get("/api/scans")).status_code == 401
    assert (await client.get("/api/scans", headers={"X-API-Key": "wrong"})).status_code == 401
    assert (await client.get("/api/scans", headers={"X-API-Key": "s3cret"})).status_code == 200
    assert (await client.get("/api/scans?api_key=s3cret")).status_code == 200
    assert (await client.get("/api/status")).status_code == 200  # health stays open


async def test_active_scan_limit_returns_429(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_ACTIVE_SCANS", 0)
    r = await client.post("/api/scans", json={"target": "127.0.0.1", "scan_mode": "custom", "port_spec": "80"})
    assert r.status_code == 429


async def test_cancel_running_scan(client, monkeypatch):
    # Make the scan slow: a listener that accepts but never speaks, plus a big-ish port list.
    async def hang(reader, writer):
        # Accept but never speak; end as soon as the scanner hangs up
        # (so `async with server` can shut down promptly).
        try:
            await reader.read()
        finally:
            writer.close()

    server = await asyncio.start_server(hang, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    monkeypatch.setattr(settings, "POST_SCAN_GRACE_SECONDS", 30)
    async with server:
        r = await client.post("/api/scans", json={"target": "127.0.0.1", "scan_mode": "custom", "port_spec": str(port)})
        scan_id = r.json()["scan_id"]
        await asyncio.sleep(0.5)  # port found; banner grab now stalling
        c = await client.post(f"/api/scans/{scan_id}/cancel")
        assert c.status_code == 200
        scan = await _wait_for_status(client, scan_id, {"cancelled"})
        assert scan["status"] == "cancelled"

    again = await client.post(f"/api/scans/{scan_id}/cancel")
    assert again.status_code == 409
    assert (await client.post("/api/scans/doesnotexist/cancel")).status_code == 404
    assert scan_manager.active_scan_count() == 0


async def test_interrupted_scans_are_marked_on_startup(client):
    from app.database import database as db
    await db.run(db._create_scan, "stale1", "127.0.0.1", "80", "custom")
    assert await db.run(db._mark_interrupted) == 1
    assert (await client.get("/api/scans/stale1")).json()["status"] == "interrupted"


async def test_version_is_stored_and_returned(client):
    server, port = await _start_banner_server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")
    async with server:
        r = await client.post("/api/scans", json={"target": "127.0.0.1", "scan_mode": "custom", "port_spec": str(port)})
        scan_id = r.json()["scan_id"]
        await _wait_for_status(client, scan_id, {"completed"})
    results = (await client.get(f"/api/scans/{scan_id}/results")).json()
    assert results["ports"][0]["version"] == "OpenSSH 9.6p1"
    events = (await client.get(f"/api/scans/{scan_id}/events")).json()
    detected = [e for e in events if e["event_type"] == "service.detected"][0]
    assert detected["data"]["version"] == "OpenSSH 9.6p1"


async def test_findings_carry_their_port(client):
    server, port = await _start_banner_server(b"220 (vsFTPd 3.0.5) FTP ready\r\n")
    async with server:
        r = await client.post("/api/scans", json={"target": "127.0.0.1", "scan_mode": "custom", "port_spec": str(port)})
        scan_id = r.json()["scan_id"]
        await _wait_for_status(client, scan_id, {"completed"})
    findings = (await client.get(f"/api/scans/{scan_id}/results")).json()["findings"]
    assert findings and all(f["port"] == port for f in findings)
