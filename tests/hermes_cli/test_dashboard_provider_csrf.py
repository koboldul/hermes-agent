"""Middleware tests for provider (OAuth/password) session CSRF — SEC-AUDIT-001
Alert 1: the refresh-only CSRF bypass and the whole class around it.

The bug: ``gated_auth_middleware`` refreshes an expired access token from the
refresh cookie and attaches ``request.state.session``, but the request cookies
carried NO access token. The old ``_cookie_csrf_identity`` read the access
cookie, saw nothing, returned ``None``, and the CSRF owner skipped Origin/token
checks entirely — so an unsafe cross-origin POST rode the victim's refresh
cookie straight through.

The fix classifies a request as cookie-authenticated by the PRESENCE of ANY
provider session cookie (access, refresh, provider, or the stable CSRF cookie),
and binds the anti-CSRF token to a stable ``hermes_session_csrf`` cookie minted
by ``GET /api/auth/csrf`` (never rotated), so token rotation cannot invalidate
it. These tests drive the real FastAPI middleware stack.

Run: ``scripts/run_tests.sh tests/hermes_cli/test_dashboard_provider_csrf.py``.
"""
from __future__ import annotations

import time as _time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server as ws
from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.cookies import (
    SESSION_AT_COOKIE,
    SESSION_CSRF_COOKIE,
    SESSION_PROVIDER_COOKIE,
    SESSION_RT_COOKIE,
)
from hermes_cli.dashboard_auth.ws_tickets import _reset_for_tests as _reset_tickets
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider, _sign

ORIGIN = "https://fly-app.fly.dev"
HOSTILE_ORIGIN = "https://evil.example.com"
CSRF_HEADER = "X-Hermes-CSRF-Token"


@pytest.fixture
def gated_app():
    """web_server.app in gated mode with a Stub provider (long-lived tokens)."""
    _reset_tickets()
    clear_providers()
    register_provider(StubAuthProvider(default_ttl=900))
    prev = {
        name: getattr(ws.app.state, name, None)
        for name in ("bound_host", "bound_port", "auth_required",
                     "local_browser_auth", "trusted_public_hosts",
                     "allowed_browser_origins")
    }
    ws.app.state.bound_host = "fly-app.fly.dev"
    ws.app.state.bound_port = 443
    ws.app.state.auth_required = True
    ws.app.state.local_browser_auth = False
    ws.app.state.trusted_public_hosts = frozenset()
    ws.app.state.allowed_browser_origins = frozenset()
    client = TestClient(ws.app, base_url=ORIGIN)
    yield client
    _reset_tickets()
    clear_providers()
    for name, value in prev.items():
        if value is None and name in ("trusted_public_hosts", "allowed_browser_origins"):
            value = frozenset()
        setattr(ws.app.state, name, value)


def _login(client: TestClient) -> None:
    """Full stub OAuth round trip → client holds access + refresh cookies."""
    r1 = client.get("/auth/login?provider=stub", follow_redirects=False)
    assert r1.status_code == 302
    state = r1.headers["location"].split("state=")[1]
    r2 = client.get(
        f"/auth/callback?code=stub_code&state={state}", follow_redirects=False
    )
    assert r2.status_code == 302


def _make_refresh_only(client: TestClient) -> None:
    """Leave the client with ONLY a valid refresh cookie (no access cookie).

    Models the refresh-only window: the access token expired/evicted, the gate
    must transparently refresh from the RT cookie.
    """
    valid_rt = _sign(
        {"sub": "stub-user-1", "kind": "refresh", "exp": int(_time.time()) + 30 * 86400}
    )
    client.cookies.clear()
    client.cookies.set(SESSION_RT_COOKIE, valid_rt)
    client.cookies.set(SESSION_PROVIDER_COOKIE, "stub")


def _fetch_csrf(client: TestClient) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


# ---------------------------------------------------------------------------
# The bypass, closed.
# ---------------------------------------------------------------------------


class TestRefreshOnlyBypassClosed:
    def test_refresh_only_unsafe_post_without_csrf_is_rejected(self, gated_app):
        """The core bypass: a refresh-only unsafe POST with no CSRF token MUST
        be rejected (was a silent bypass before the fix)."""
        _login(gated_app)
        _make_refresh_only(gated_app)
        r = gated_app.post("/api/auth/ws-ticket", headers={"origin": ORIGIN})
        assert r.status_code == 403, r.text

    def test_refresh_only_unsafe_post_from_hostile_origin_rejected(self, gated_app):
        """Even with a (bogus/leaked) token, a refresh-only unsafe POST from a
        hostile origin fails the exact-origin gate first."""
        _login(gated_app)
        _make_refresh_only(gated_app)
        r = gated_app.post(
            "/api/auth/ws-ticket",
            headers={"origin": HOSTILE_ORIGIN, CSRF_HEADER: "anything"},
        )
        assert r.status_code == 403, r.text

    def test_refresh_rotation_happens_even_on_csrf_rejection(self, gated_app):
        """The gate still refreshes + rotates cookies on the rejected request —
        so the SPA's next /api/auth/csrf sees a fresh access token — but the
        route never executes (403 before it)."""
        _login(gated_app)
        _make_refresh_only(gated_app)
        assert not [c for c in gated_app.cookies.jar if SESSION_AT_COOKIE in c.name]
        r = gated_app.post("/api/auth/ws-ticket", headers={"origin": ORIGIN})
        assert r.status_code == 403
        # A fresh access cookie was rotated onto the 403 response (applied to
        # the client jar), proving refresh ran before the CSRF rejection.
        assert [c for c in gated_app.cookies.jar if SESSION_AT_COOKIE in c.name]

    def test_no_body_mutation_route_requires_csrf(self, gated_app):
        """A no-body mutation (POST /auth/logout) still requires CSRF."""
        _login(gated_app)
        r = gated_app.post("/auth/logout", headers={"origin": ORIGIN}, follow_redirects=False)
        assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# Legitimate flows.
# ---------------------------------------------------------------------------


class TestLegitimateProviderCsrf:
    def test_refresh_then_csrf_fetch_then_retry_succeeds(self, gated_app):
        """The task's contract: refresh-only → 403 → GET fresh CSRF → retry OK."""
        _login(gated_app)
        _make_refresh_only(gated_app)
        # First unsafe attempt with no token → rejected.
        first = gated_app.post("/api/auth/ws-ticket", headers={"origin": ORIGIN})
        assert first.status_code == 403
        # SPA fetches a fresh CSRF token (gate refreshed the AT on the way).
        csrf = _fetch_csrf(gated_app)
        # Retry succeeds.
        retry = gated_app.post(
            "/api/auth/ws-ticket", headers={"origin": ORIGIN, CSRF_HEADER: csrf}
        )
        assert retry.status_code == 200, retry.text
        assert retry.json()["ticket"]

    def test_access_token_rotation_keeps_csrf_valid(self, gated_app):
        """A stable CSRF cookie means an access-token rotation does NOT
        invalidate an already-fetched anti-CSRF token: the SAME token still
        validates on a refresh-only (rotating) request."""
        _login(gated_app)
        csrf = _fetch_csrf(gated_app)  # mints the stable csrf cookie
        csrf_cookie_val = next(
            c.value for c in gated_app.cookies.jar if SESSION_CSRF_COOKIE in c.name
        )
        # Force refresh-only (access token gone → gate rotates), but keep the
        # SAME stable csrf cookie the browser still holds.
        _make_refresh_only(gated_app)
        gated_app.cookies.set(SESSION_CSRF_COOKIE, csrf_cookie_val)
        r = gated_app.post(
            "/api/auth/ws-ticket", headers={"origin": ORIGIN, CSRF_HEADER: csrf}
        )
        assert r.status_code == 200, r.text

    def test_normal_request_with_csrf_succeeds(self, gated_app):
        _login(gated_app)
        csrf = _fetch_csrf(gated_app)
        r = gated_app.post(
            "/api/auth/ws-ticket", headers={"origin": ORIGIN, CSRF_HEADER: csrf}
        )
        assert r.status_code == 200, r.text

    def test_missing_and_wrong_csrf_rejected(self, gated_app):
        _login(gated_app)
        csrf = _fetch_csrf(gated_app)
        # Missing.
        assert gated_app.post(
            "/api/auth/ws-ticket", headers={"origin": ORIGIN}
        ).status_code == 403
        # Wrong.
        assert gated_app.post(
            "/api/auth/ws-ticket", headers={"origin": ORIGIN, CSRF_HEADER: "wrong"}
        ).status_code == 403
        # Correct still works (not a one-shot).
        assert gated_app.post(
            "/api/auth/ws-ticket", headers={"origin": ORIGIN, CSRF_HEADER: csrf}
        ).status_code == 200

    def test_logout_requires_csrf_then_succeeds(self, gated_app):
        _login(gated_app)
        # Without CSRF → rejected.
        assert gated_app.post(
            "/auth/logout", headers={"origin": ORIGIN}, follow_redirects=False
        ).status_code == 403
        # With CSRF → logout proceeds (302 → /login) and clears cookies.
        csrf = _fetch_csrf(gated_app)
        r = gated_app.post(
            "/auth/logout",
            headers={"origin": ORIGIN, CSRF_HEADER: csrf},
            follow_redirects=False,
        )
        assert r.status_code in (302, 200), r.text


# ---------------------------------------------------------------------------
# CSRF cookie hygiene + exemptions.
# ---------------------------------------------------------------------------


class TestCsrfCookieAndExemptions:
    def test_csrf_cookie_is_httponly_and_token_is_not_the_cookie(self, gated_app):
        _login(gated_app)
        r = gated_app.get("/api/auth/csrf")
        assert r.status_code == 200
        set_cookie = r.headers.get("set-cookie", "").lower()
        assert SESSION_CSRF_COOKIE.lower() in set_cookie
        assert "httponly" in set_cookie
        # The returned token is the HMAC, never the raw opaque cookie value.
        token = r.json()["csrf_token"]
        cookie_val = next(
            (c.value for c in gated_app.cookies.jar if SESSION_CSRF_COOKIE in c.name),
            "",
        )
        assert cookie_val
        assert token != cookie_val

    def test_csrf_token_is_stable_across_fetches(self, gated_app):
        _login(gated_app)
        first = _fetch_csrf(gated_app)
        second = _fetch_csrf(gated_app)
        assert first == second  # bound to the stable cookie, not rotated

    def test_service_header_and_bearer_callers_are_exempt(self):
        """The classifier exempts explicit per-request credentials (bearer seam
        + trusted service-token header), never treating them as cookie auth."""
        # Bearer seam.
        bearer_req = SimpleNamespace(
            state=SimpleNamespace(token_authenticated=True),
            cookies={SESSION_RT_COOKIE: "rt"},
            headers={},
        )
        assert ws._is_cookie_authenticated(bearer_req) is False
        assert ws._cookie_csrf_identity(bearer_req) is None
        # Trusted service-token header.
        svc_req = SimpleNamespace(
            state=SimpleNamespace(),
            cookies={SESSION_RT_COOKIE: "rt"},
            headers={ws._SESSION_HEADER_NAME: ws._SESSION_TOKEN},
        )
        assert ws._is_cookie_authenticated(svc_req) is False
        assert ws._cookie_csrf_identity(svc_req) is None

    def test_any_provider_cookie_classifies_as_cookie_authenticated(self):
        for cookie_name in (SESSION_AT_COOKIE, SESSION_RT_COOKIE,
                             SESSION_PROVIDER_COOKIE, SESSION_CSRF_COOKIE):
            req = SimpleNamespace(
                state=SimpleNamespace(),
                cookies={cookie_name: "value"},
                headers={},
            )
            assert ws._is_cookie_authenticated(req) is True, cookie_name

    def test_no_cookies_is_not_cookie_authenticated(self):
        req = SimpleNamespace(state=SimpleNamespace(), cookies={}, headers={})
        assert ws._is_cookie_authenticated(req) is False
        assert ws._cookie_csrf_identity(req) is None
