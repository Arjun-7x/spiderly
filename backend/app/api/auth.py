"""
Authentication / identity.

* No keys configured  -> auth disabled; everyone is the "anonymous" admin (localhost use).
* SPIDERLY_API_KEY    -> one shared admin key, identity "default".
* SPIDERLY_API_KEYS   -> named per-user keys; users only see their own scans
                         unless listed in SPIDERLY_ADMIN_USERS.
"""
import secrets
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, Request

from app.core.config import settings
from app.core.ratelimit import auth_fail_limiter


@dataclass(frozen=True)
class Identity:
    name: str
    is_admin: bool

    @property
    def owner_filter(self) -> Optional[str]:
        """Value to filter scans by (None = no filtering, i.e. sees everything)."""
        return None if self.is_admin else self.name


ANONYMOUS = Identity("anonymous", True)


def identify(provided: Optional[str]) -> Optional[Identity]:
    """Map a presented key to an identity, or None if invalid. Every configured
    key is compared (constant-time each) so timing doesn't reveal which matched."""
    if not settings.auth_enabled:
        return ANONYMOUS
    if not provided:
        return None
    found: Optional[Identity] = None
    if settings.API_KEY and secrets.compare_digest(provided, settings.API_KEY):
        found = Identity("default", True)
    for user, key in settings.API_KEYS.items():
        if secrets.compare_digest(provided, key) and found is None:
            found = Identity(user, user in settings.ADMIN_USERS)
    return found


def key_is_valid(provided: Optional[str]) -> bool:  # kept for callers that only need yes/no
    return identify(provided) is not None


def _client_id(request_or_ws) -> str:
    client = getattr(request_or_ws, "client", None)
    return client.host if client else "unknown"


def authenticate(provided: Optional[str], client_id: str) -> Identity:
    """Identity for a presented key; raises 401 (or 429 after repeated failures)."""
    fail_key = f"authfail:{client_id}"
    if auth_fail_limiter.is_limited(fail_key, settings.AUTH_FAIL_LIMIT, settings.AUTH_FAIL_WINDOW):
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts. Try again later.",
            headers={"Retry-After": str(auth_fail_limiter.retry_after(fail_key, settings.AUTH_FAIL_WINDOW))},
        )
    ident = identify(provided)
    if ident is None:
        auth_fail_limiter.record(fail_key)
        raise HTTPException(status_code=401, detail="Missing or invalid API key.")
    return ident


async def require_api_key(request: Request) -> Identity:
    provided = request.headers.get("x-api-key") or request.query_params.get("api_key")
    ident = authenticate(provided, _client_id(request))
    request.state.identity = ident
    return ident


def can_access(scan: dict, ident: Identity) -> bool:
    return ident.is_admin or scan.get("created_by") == ident.name
