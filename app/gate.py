"""Minimal access gate shared by the API and the Streamlit console.

Two modes, both keyed off ``PG_ACCESS_TOKEN``:

* a token is configured  -> every request must present it (Bearer header,
  ``X-PolicyGuard-Token`` header, or HTTP Basic), so the prototype can be
  reached from a LAN or a tunnel.
* no token configured    -> local-only: API calls from non-loopback clients are
  refused, and the console refuses a non-local Host header.

The default therefore keeps the demo frictionless on ``localhost`` while a
forgotten token cannot silently expose it.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import Settings, get_settings

# Also used by the API's CORS allow_headers, so the name lives in one place.
TOKEN_HEADER = "X-PolicyGuard-Token"
# Platform health checks cannot send credentials, so this one stays open.
OPEN_PATHS = {"/health"}
LOOPBACK_NAMES = {"localhost", "testclient", ""}


def is_local_host(host: str | None) -> bool:
    """True for loopback addresses and names."""
    name = (host or "").strip().lower()
    if name.startswith("["):  # [::1]:8501
        name = name[1:].split("]", 1)[0]
    return (
        name in LOOPBACK_NAMES
        or name == "::1"
        or name.startswith("127.")
    )


def is_local_host_header(host_header: str | None) -> bool:
    """Check a ``Host`` header such as ``localhost:8501`` or a full URL."""
    raw = (host_header or "").strip()
    if not raw:
        return True  # cannot tell (proxy/old Streamlit): do not lock the demo out
    if "://" in raw:
        return is_local_host(urlsplit(raw).hostname)
    host = raw if raw.startswith("[") else raw.split(":", 1)[0]
    return is_local_host(host)


def tokens_match(provided: str, expected: str) -> bool:
    """Constant-time comparison; empty values never match."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided, expected)


def _basic_credentials(header: str) -> tuple[str, str]:
    if not header.lower().startswith("basic "):
        return "", ""
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True)
    except (binascii.Error, ValueError):
        return "", ""
    user, _, password = decoded.decode("utf-8", "replace").partition(":")
    return user, password


def request_token(headers: Headers) -> str:
    """Pull a shared token out of the supported headers (case-insensitive)."""
    direct = (headers.get(TOKEN_HEADER) or "").strip()
    if direct:
        return direct
    auth = (headers.get("authorization") or "").strip()
    if not auth:
        return ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    user, password = _basic_credentials(auth)
    # `curl -u reviewer:<token>` and `curl -u <token>:` both work.
    return password or user


def unauthorized() -> JSONResponse:
    return JSONResponse(
        {"detail": "Access token required"},
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="PolicyGuard"'},
    )


def remote_disabled() -> JSONResponse:
    return JSONResponse(
        {
            "detail": (
                "Remote access is disabled: set PG_ACCESS_TOKEN to expose "
                "PolicyGuard beyond localhost."
            )
        },
        status_code=403,
    )


class AccessGateMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated API calls before they reach a route."""

    def __init__(self, app, settings: Settings | None = None):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS" or request.url.path in OPEN_PATHS:
            return await call_next(request)

        settings = self.settings or get_settings()
        if settings.access_token:
            if not tokens_match(request_token(request.headers), settings.access_token):
                return unauthorized()
        else:
            client = request.client.host if request.client else ""
            if not is_local_host(client):
                return remote_disabled()
        return await call_next(request)
