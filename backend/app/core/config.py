"""
SPIDERLY - Configuration
All tunables live here and can be overridden with environment variables
or a local ``backend/.env`` file (see ``.env.example``).
"""
import ipaddress
import os
from pathlib import Path
from typing import List


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines). Real environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_BACKEND_DIR = Path(__file__).resolve().parents[2]
_load_dotenv(_BACKEND_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _named_keys(name: str) -> dict:
    """'alice:key1,bob:key2' -> {'alice': 'key1', 'bob': 'key2'}"""
    out = {}
    for pair in os.environ.get(name, "").split(","):
        user, sep, key = pair.strip().partition(":")
        if sep and user and key:
            out[user] = key
    return out


def _networks(name: str) -> List[ipaddress._BaseNetwork]:
    raw = os.environ.get(name, "")
    return [ipaddress.ip_network(c.strip(), strict=False) for c in raw.split(",") if c.strip()]


class Settings:
    APP_NAME: str = "SPIDERLY"
    VERSION: str = "0.3.1"

    # Where the sqlite database file lives
    DATABASE_PATH: str = os.environ.get("SPIDERLY_DB_PATH", "spiderly.db")

    # Scan safety limits (protects the local machine and the target from abuse)
    MAX_CONCURRENT_PORT_SCANS: int = int(os.environ.get("SPIDERLY_MAX_CONCURRENCY", "200"))
    DEFAULT_TIMEOUT_SECONDS: float = float(os.environ.get("SPIDERLY_TIMEOUT", "0.75"))
    MAX_PORT_RANGE_SIZE: int = int(os.environ.get("SPIDERLY_MAX_PORTS", "5000"))
    MAX_ACTIVE_SCANS: int = int(os.environ.get("SPIDERLY_MAX_ACTIVE_SCANS", "3"))
    DETECTION_CONCURRENCY: int = int(os.environ.get("SPIDERLY_DETECTION_CONCURRENCY", "20"))
    POST_SCAN_GRACE_SECONDS: float = float(os.environ.get("SPIDERLY_POST_SCAN_GRACE", "20"))
    BANNER_READ_TIMEOUT: float = 1.0
    BANNER_READ_BYTES: int = 1024

    # Target policy. Link-local (incl. cloud metadata 169.254.169.254),
    # multicast, unspecified and reserved addresses are ALWAYS refused.
    # Set SPIDERLY_ALLOW_PRIVATE=false to also refuse loopback/RFC1918 targets,
    # and/or SPIDERLY_ALLOWED_TARGETS=10.0.0.0/24,192.168.56.0/24 to restrict
    # scans to an explicit allowlist of networks.
    ALLOW_PRIVATE_TARGETS: bool = _bool("SPIDERLY_ALLOW_PRIVATE", True)
    ALLOWED_TARGET_NETWORKS: list = _networks("SPIDERLY_ALLOWED_TARGETS")

    # Optional shared secret. When set, every /api route except /api/status
    # requires it via the X-API-Key header (or ?api_key= for WebSocket/report links).
    API_KEY: str = os.environ.get("SPIDERLY_API_KEY", "")

    # Per-user keys: SPIDERLY_API_KEYS="alice:key1,bob:key2". Each named user sees and
    # controls only their own scans, unless listed in SPIDERLY_ADMIN_USERS. The single
    # SPIDERLY_API_KEY above acts as the shared admin key ("default").
    API_KEYS: dict = _named_keys("SPIDERLY_API_KEYS")
    ADMIN_USERS: set = {u.strip() for u in os.environ.get("SPIDERLY_ADMIN_USERS", "").split(",") if u.strip()}

    # If true and no key is configured, a random admin key is generated at startup
    # and logged once (the Docker image turns this on so it is never open by default).
    REQUIRE_AUTH: bool = _bool("SPIDERLY_REQUIRE_AUTH", False)

    # Rate limits (sliding window, in-memory, per identity or client IP)
    SCAN_RATE_LIMIT: int = int(os.environ.get("SPIDERLY_SCAN_RATE_LIMIT", "10"))
    SCAN_RATE_WINDOW: float = float(os.environ.get("SPIDERLY_SCAN_RATE_WINDOW", "60"))
    AUTH_FAIL_LIMIT: int = int(os.environ.get("SPIDERLY_AUTH_FAIL_LIMIT", "10"))
    AUTH_FAIL_WINDOW: float = float(os.environ.get("SPIDERLY_AUTH_FAIL_WINDOW", "60"))

    @property
    def auth_enabled(self) -> bool:
        return bool(self.API_KEY or self.API_KEYS)

    # CORS - tighten this to your actual frontend origin in production
    ALLOWED_ORIGINS: list = [o.strip() for o in os.environ.get("SPIDERLY_ALLOWED_ORIGINS", "*").split(",") if o.strip()]

    # Scan modes -> port sets
    QUICK_PORTS: str = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,3000,3306,3389,5432,5900,6379,8000,8080,8443,8888,9200,27017"
    STANDARD_RANGE: str = "1-1024"


settings = Settings()
