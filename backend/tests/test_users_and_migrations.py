import asyncio
import sqlite3

import pytest
from starlette.testclient import TestClient

from app.core.config import settings
from app.core.ratelimit import scan_limiter
from app.database import database as db
from app.main import app
from app.scanner.service_detector import extract_version


def _users(monkeypatch, admins=()):
    monkeypatch.setattr(settings, "API_KEYS", {"alice": "ka", "bob": "kb", "root": "kr"})
    monkeypatch.setattr(settings, "ADMIN_USERS", set(admins))


H = lambda k: {"X-API-Key": k}
SCAN = {"target": "127.0.0.1", "scan_mode": "custom", "port_spec": "1"}


async def _make(client, key):
    r = await client.post("/api/scans", json=SCAN, headers=H(key))
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


async def test_users_only_see_their_own_scans(client, monkeypatch):
    _users(monkeypatch)
    a = await _make(client, "ka")
    b = await _make(client, "kb")
    assert [s["id"] for s in (await client.get("/api/scans", headers=H("ka"))).json()] == [a]
    assert [s["id"] for s in (await client.get("/api/scans", headers=H("kb"))).json()] == [b]
    for path in ("", "/results", "/events"):
        # someone else's scan is indistinguishable from a missing one
        assert (await client.get(f"/api/scans/{b}{path}", headers=H("ka"))).status_code == 404
    assert (await client.get(f"/api/reports/{b}", headers=H("ka"))).status_code == 404
    assert (await client.post(f"/api/scans/{b}/cancel", headers=H("ka"))).status_code == 404
    assert (await client.get(f"/api/scans/{a}", headers=H("ka"))).status_code == 200


async def test_admin_user_and_shared_key_see_everything(client, monkeypatch):
    _users(monkeypatch, admins={"root"})
    monkeypatch.setattr(settings, "API_KEY", "shared")
    a = await _make(client, "ka")
    b = await _make(client, "kb")
    for key in ("kr", "shared"):
        ids = {s["id"] for s in (await client.get("/api/scans", headers=H(key))).json()}
        assert ids == {a, b}
        assert (await client.get(f"/api/scans/{a}", headers=H(key))).status_code == 200


async def test_scan_rate_limit_is_per_identity(client, monkeypatch):
    _users(monkeypatch)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT", 2)
    await _make(client, "ka"); await _make(client, "ka")
    r = await client.post("/api/scans", json=SCAN, headers=H("ka"))
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert (await client.post("/api/scans", json=SCAN, headers=H("kb"))).status_code == 200


async def test_repeated_bad_keys_get_locked_out(client, monkeypatch):
    _users(monkeypatch)
    monkeypatch.setattr(settings, "AUTH_FAIL_LIMIT", 3)
    for _ in range(3):
        assert (await client.get("/api/scans", headers=H("nope"))).status_code == 401
    locked = await client.get("/api/scans", headers=H("nope"))
    assert locked.status_code == 429
    # lockout applies to the client, even with a now-correct key, until the window passes
    assert (await client.get("/api/scans", headers=H("ka"))).status_code == 429


def test_require_auth_generates_key_when_none_configured(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
    with TestClient(app) as tc:
        assert settings.API_KEY, "a key should have been generated at startup"
        assert tc.get("/api/scans").status_code == 401
        assert tc.get("/api/scans", headers=H(settings.API_KEY)).status_code == 200
        assert tc.get("/api/status").json()["auth_required"] is True


def test_old_database_is_migrated_in_place(tmp_path, monkeypatch):
    path = str(tmp_path / "old.db")
    monkeypatch.setattr(settings, "DATABASE_PATH", path)
    conn = sqlite3.connect(path)  # a v0.1-shaped database: no created_by / version
    conn.executescript("""
        CREATE TABLE scans (id TEXT PRIMARY KEY, target TEXT NOT NULL, port_spec TEXT NOT NULL,
            scan_mode TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
            started_at REAL, completed_at REAL, error TEXT);
        CREATE TABLE ports (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, host_id TEXT NOT NULL,
            port INTEGER NOT NULL, state TEXT NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp',
            service_guess TEXT, banner TEXT, discovered_at REAL);
        INSERT INTO scans (id, target, port_spec, scan_mode, status) VALUES ('legacy', '10.0.0.1', '80', 'custom', 'completed');
    """)
    conn.commit(); conn.close()
    db.init_db(); db.init_db()  # idempotent
    legacy = db._get_scan("legacy")
    assert legacy["created_by"] is None
    db._create_scan("new", "10.0.0.2", "80", "custom", "alice")
    assert [s["id"] for s in db._list_scans("alice")] == ["new"]


@pytest.mark.parametrize("service,banner,expected", [
    ("SSH", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", "OpenSSH 9.6p1"),
    ("SSH", "SSH-2.0-dropbear_2022.83", "dropbear 2022.83"),
    ("FTP", "220 (vsFTPd 3.0.5)", "vsFTPd 3.0.5"),
    ("SMTP", "220 mail ESMTP Postfix", "Postfix"),
    ("MySQL", "5.5.5-10.6.12-MariaDB", "MariaDB 10.6.12"),
    ("MySQL", "\n5.7.42-log\x00", "MySQL 5.7.42"),
    ("Redis", "redis_version:7.2.4", "Redis 7.2.4"),
    ("HTTP", "HTTP/1.1 200 OK", None),
    ("SSH", None, None),
])
def test_version_extraction_never_guesses(service, banner, expected):
    assert extract_version(service, banner) == expected
