import json

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core.config import settings
from app.database import database as db
from app.main import app


def _seed_finished_scan():
    db._create_scan("done1", "127.0.0.1", "80", "custom")
    db._add_event("done1", "scan.started", "started", {"target": "127.0.0.1"})
    db._add_event("done1", "scan.completed", "done", {"open_ports": []})


def test_finished_scan_replays_history_then_closes():
    _seed_finished_scan()
    with TestClient(app) as tc, tc.websocket_connect("/api/ws/scans/done1") as ws:
        first = json.loads(ws.receive_text())
        second = json.loads(ws.receive_text())
        assert (first["event_type"], second["event_type"]) == ("scan.started", "scan.completed")
        assert isinstance(first["data"], dict)
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()  # server closes after the terminal event


def test_unknown_scan_reports_error():
    with TestClient(app) as tc, tc.websocket_connect("/api/ws/scans/nope") as ws:
        assert json.loads(ws.receive_text())["event_type"] == "error"


def test_websocket_requires_api_key(monkeypatch):
    _seed_finished_scan()
    monkeypatch.setattr(settings, "API_KEY", "k")
    with TestClient(app) as tc:
        with pytest.raises(WebSocketDisconnect):
            with tc.websocket_connect("/api/ws/scans/done1"):
                pass
        with tc.websocket_connect("/api/ws/scans/done1?api_key=k") as ws:
            assert json.loads(ws.receive_text())["event_type"] == "scan.started"
