"""Regression tests for the access gate.

    pytest -q            # from the policyguard/ directory

Each test builds its own app with explicit settings, so no environment
variables, settings cache or module reloading are involved. Rules covered:
shared token (Bearer, custom header, Basic), 401 challenge, loopback-only
fallback, /health exemption, and the CORS allowlist.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.config import Settings
from app.gate import is_local_host_header

TOKEN = "test-token-123"
# Not a default origin: proves the allowlist comes from settings.
ORIGIN = "https://console.example.edu"
DEFAULT_ORIGIN = "http://localhost:8501"
REMOTE = ("203.0.113.9", 4444)  # TEST-NET-3, never a real client


def basic(user: str, password: str) -> dict[str, str]:
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


def make_app(*, token: str = ""):
    return create_app(
        Settings(access_token=token, allowed_origins=(ORIGIN,), llm_mode="mock")
    )


def client(app, host: tuple[str, int] | None = None) -> TestClient:
    return TestClient(app, client=host) if host else TestClient(app)


@pytest.fixture()
def gated_app():
    return make_app(token=TOKEN)


@pytest.fixture()
def open_app():
    return make_app()


CREDENTIALS = {
    "bearer": {"Authorization": f"Bearer {TOKEN}"},
    "custom-header": {"X-PolicyGuard-Token": TOKEN},
    "basic-password": basic("reviewer", TOKEN),
    "basic-username": basic(TOKEN, ""),
}
REJECTED = {
    "missing": {},
    "wrong-bearer": {"Authorization": "Bearer wrong-token"},
    "wrong-basic": basic("reviewer", "wrong-token"),
}


class TestTokenGate:
    @pytest.mark.parametrize("headers", CREDENTIALS.values(), ids=CREDENTIALS.keys())
    def test_supported_credentials_are_accepted(self, gated_app, headers):
        assert client(gated_app).get("/tools", headers=headers).status_code == 200

    @pytest.mark.parametrize("headers", REJECTED.values(), ids=REJECTED.keys())
    def test_missing_or_wrong_credentials_challenge(self, gated_app, headers):
        response = client(gated_app).get("/tools", headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Basic realm="PolicyGuard"'

    def test_state_changing_route_is_gated(self, gated_app):
        response = client(gated_app).post("/chat", json={"message": "hi", "role": "admin"})
        assert response.status_code == 401


class TestLoopbackFallback:
    def test_loopback_allowed_without_token(self, open_app):
        assert client(open_app).get("/tools").status_code == 200

    def test_remote_refused_without_token(self, open_app):
        response = client(open_app, REMOTE).get("/tools")
        assert response.status_code == 403
        assert "PG_ACCESS_TOKEN" in response.json()["detail"]

    def test_remote_requires_token_when_configured(self, gated_app):
        remote = client(gated_app, REMOTE)
        assert remote.get("/tools").status_code == 401
        assert remote.get("/tools", headers=CREDENTIALS["bearer"]).status_code == 200


class TestHealthExemption:
    def test_health_is_open_for_both_modes(self, gated_app, open_app):
        # Token mode: no credentials at all.
        assert client(gated_app).get("/health").status_code == 200
        # Local-only mode: a remote platform health checker.
        assert client(open_app, REMOTE).get("/health").status_code == 200


def preflight(app, origin: str):
    return client(app).options(
        "/chat",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )


class TestCorsAllowlist:
    def test_configured_origin_is_allowed(self, gated_app):
        response = preflight(gated_app, ORIGIN)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == ORIGIN
        assert "authorization" in response.headers["access-control-allow-headers"].lower()

    def test_origins_outside_the_list_get_no_grant(self, gated_app):
        # A Streamlit default origin, dropped by our explicit allowlist.
        response = preflight(gated_app, DEFAULT_ORIGIN)
        assert "access-control-allow-origin" not in response.headers

    def test_rejection_keeps_cors_headers_for_allowed_origin(self, gated_app):
        # Proves CORS wraps the gate: a browser sees the 401, not a CORS error.
        response = client(gated_app).get("/tools", headers={"Origin": ORIGIN})
        assert response.status_code == 401
        assert response.headers["access-control-allow-origin"] == ORIGIN


@pytest.mark.parametrize(
    "host,local",
    [
        ("localhost:8501", True),
        ("127.0.0.1:8501", True),
        ("[::1]:8501", True),
        ("192.168.1.20:8501", False),
        ("console.example.edu", False),
    ],
)
def test_console_host_locality(host, local):
    assert is_local_host_header(host) is local


def test_missing_host_header_fails_open():
    # Proxies and test harnesses may omit Host; the console must not lock out.
    assert is_local_host_header("") is True
