import httpx
import pytest

from app.core.config import settings
from app.core.ratelimit import auth_fail_limiter, scan_limiter
from app.database import database as db
from app.main import app


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "API_KEY", "")
    monkeypatch.setattr(settings, "API_KEYS", {})
    monkeypatch.setattr(settings, "ADMIN_USERS", set())
    monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(settings, "SCAN_RATE_LIMIT", 1000)
    scan_limiter.reset()
    auth_fail_limiter.reset()
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    monkeypatch.setattr(settings, "ALLOWED_TARGET_NETWORKS", [])
    monkeypatch.setattr(settings, "MAX_ACTIVE_SCANS", 3)
    db.init_db()


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
