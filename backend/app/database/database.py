"""
SPIDERLY - Database layer (SQLite, accessed via a thread executor so it
never blocks the asyncio event loop that runs the scanner).
"""
import asyncio
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from app.core.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    port_spec TEXT NOT NULL,
    scan_mode TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    started_at REAL,
    completed_at REAL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    address TEXT NOT NULL,
    reachable INTEGER NOT NULL DEFAULT 0,
    discovered_at REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service_guess TEXT,
    banner TEXT,
    discovered_at REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS http_metadata (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    port_id TEXT NOT NULL,
    status_code INTEGER,
    server_header TEXT,
    title TEXT,
    content_type TEXT,
    tls INTEGER NOT NULL DEFAULT 0,
    redirect_location TEXT,
    FOREIGN KEY (port_id) REFERENCES ports(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    affected_service TEXT,
    recommendation TEXT,
    created_at REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scan_events (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    created_at REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id);
"""


def new_id() -> str:
    return uuid.uuid4().hex[:12]


@contextmanager
def _conn():
    conn = sqlite3.connect(settings.DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# (table, column, DDL) - applied idempotently so existing databases upgrade in place.
MIGRATIONS = [
    ("scans", "created_by", "ALTER TABLE scans ADD COLUMN created_by TEXT"),
    ("ports", "version", "ALTER TABLE ports ADD COLUMN version TEXT"),
    ("findings", "port", "ALTER TABLE findings ADD COLUMN port INTEGER"),
]


def _migrate(conn) -> None:
    for table, column, ddl in MIGRATIONS:
        cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in cols:
            conn.execute(ddl)


def init_db() -> None:
    with _conn() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)


def _mark_interrupted() -> int:
    """Scans still 'running' at startup were killed with the previous process."""
    with _conn() as conn:
        cur = conn.execute(
            "UPDATE scans SET status = 'interrupted', completed_at = ?, "
            "error = 'Backend restarted while the scan was running.' WHERE status = 'running'",
            (time.time(),),
        )
        return cur.rowcount


def _update_port_service(port_id: str, service: str, banner: Optional[str], version: Optional[str] = None) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE ports SET service_guess = ?, banner = ?, version = ? WHERE id = ?",
            (service, banner, version, port_id),
        )


def _check_health() -> bool:
    """Cheap connectivity check used by /api/status. Returns True if the
    database file can be opened and queried."""
    try:
        with _conn() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


async def run(fn, *args):
    """Run a blocking DB function off the event loop."""
    return await asyncio.to_thread(fn, *args)


# ---------- Sync implementations (called via `run`) ----------

def _create_scan(scan_id: str, target: str, port_spec: str, scan_mode: str, created_by: Optional[str] = None) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, port_spec, scan_mode, status, started_at, created_by) "
            "VALUES (?, ?, ?, ?, 'running', ?, ?)",
            (scan_id, target, port_spec, scan_mode, time.time(), created_by),
        )


def _finish_scan(scan_id: str, status: str, error: Optional[str] = None) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, completed_at = ?, error = ? WHERE id = ?",
            (status, time.time(), error, scan_id),
        )


def _add_host(scan_id: str, address: str, reachable: bool) -> str:
    host_id = new_id()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO hosts (id, scan_id, address, reachable, discovered_at) VALUES (?, ?, ?, ?, ?)",
            (host_id, scan_id, address, int(reachable), time.time()),
        )
    return host_id


def _add_port(scan_id: str, host_id: str, port: int, state: str, service_guess: str, banner: str) -> str:
    port_id = new_id()
    with _conn() as conn:
        conn.execute(
            "INSERT INTO ports (id, scan_id, host_id, port, state, service_guess, banner, discovered_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (port_id, scan_id, host_id, port, state, service_guess, banner, time.time()),
        )
    return port_id


def _add_http_metadata(scan_id: str, port_id: str, status_code, server_header, title, content_type, tls, redirect) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO http_metadata (id, scan_id, port_id, status_code, server_header, title, content_type, tls, redirect_location) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (new_id(), scan_id, port_id, status_code, server_header, title, content_type, int(tls), redirect),
        )


def _add_finding(scan_id: str, title: str, severity: str, description: str, evidence: str, affected_service: str,
                 recommendation: str, port: Optional[int] = None) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO findings (id, scan_id, title, severity, description, evidence, affected_service, recommendation, created_at, port) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (new_id(), scan_id, title, severity, description, evidence, affected_service, recommendation, time.time(), port),
        )


def _add_event(scan_id: str, event_type: str, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    row = {
        "id": new_id(),
        "scan_id": scan_id,
        "event_type": event_type,
        "message": message,
        "data": data or {},
        "created_at": time.time(),
    }
    with _conn() as conn:
        conn.execute(
            "INSERT INTO scan_events (id, scan_id, event_type, message, data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (row["id"], row["scan_id"], row["event_type"], row["message"], json.dumps(row["data"]), row["created_at"]),
        )
    return row


def _get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def _list_scans(owner: Optional[str] = None) -> List[Dict[str, Any]]:
    """All scans, or only those created by `owner` when given."""
    with _conn() as conn:
        if owner is None:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans WHERE created_by = ? ORDER BY started_at DESC", (owner,)
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            port_count = conn.execute(
                "SELECT COUNT(*) c FROM ports WHERE scan_id = ? AND state = 'open'", (d["id"],)
            ).fetchone()["c"]
            finding_count = conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE scan_id = ?", (d["id"],)
            ).fetchone()["c"]
            d["open_port_count"] = port_count
            d["finding_count"] = finding_count
            results.append(d)
        return results


def _get_results(scan_id: str) -> Dict[str, Any]:
    with _conn() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            return {}
        hosts = [dict(h) for h in conn.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)).fetchall()]
        ports = [dict(p) for p in conn.execute("SELECT * FROM ports WHERE scan_id = ? ORDER BY port", (scan_id,)).fetchall()]
        http_meta = [dict(m) for m in conn.execute("SELECT * FROM http_metadata WHERE scan_id = ?", (scan_id,)).fetchall()]
        findings = [dict(f) for f in conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
            "CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 2 ELSE 3 END",
            (scan_id,)
        ).fetchall()]
        return {
            "scan": dict(scan),
            "hosts": hosts,
            "ports": ports,
            "http_metadata": http_meta,
            "findings": findings,
        }


def _get_events(scan_id: str) -> List[Dict[str, Any]]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_events WHERE scan_id = ? ORDER BY created_at ASC, rowid ASC", (scan_id,)
        ).fetchall()
        events = [dict(r) for r in rows]
        for e in events:
            e["data"] = json.loads(e["data"]) if e["data"] else {}
        return events
