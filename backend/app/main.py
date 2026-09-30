import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import reports, scans
from app.core import logging_utils
from app.core.config import settings
from app.database import database as db
from app.database.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("spiderly")
logging_utils.install()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    interrupted = await db.run(db._mark_interrupted)
    if interrupted:
        logger.warning("Marked %d scan(s) left 'running' by a previous process as interrupted.", interrupted)
    if settings.REQUIRE_AUTH and not settings.auth_enabled:
        settings.API_KEY = secrets.token_urlsafe(24)
        logger.warning("No API key configured; generated one for this run: %s", settings.API_KEY)
        logger.warning("Set SPIDERLY_API_KEY (or SPIDERLY_API_KEYS) to choose your own.")
    logger.info("SPIDERLY backend online. Database initialized at %s", settings.DATABASE_PATH)
    if settings.auth_enabled:
        logger.info("API authentication is ENABLED.")
    else:
        logger.warning("API authentication is DISABLED - only run this on a trusted, local network.")
    yield


app = FastAPI(title=settings.APP_NAME, version=settings.VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=False,  # auth is header/query based, never cookies
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/status")
async def status():
    db_ok = await db.run(db._check_health)
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "status": "online",
        "database": "connected" if db_ok else "unavailable",
        "websocket": "available",
        "auth_required": settings.auth_enabled,
        "active_scans": scans.scan_manager.active_scan_count(),
    }


app.include_router(scans.router, prefix="/api")
app.include_router(scans.ws_router, prefix="/api")
app.include_router(reports.router, prefix="/api")

# Serve the static frontend from the same origin when it's present
# (used by the Docker image; `python -m http.server` still works too).
_FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
