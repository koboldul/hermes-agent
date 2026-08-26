"""Behavior tests for the loopback local-browser bootstrap auth (SEC-AUDIT-001).

These exercise the real FastAPI middleware stack + routes through the Starlette
TestClient — no source-text reading. They cover the work-package-1 regression
list: no reusable credential in unauthenticated assets, single-use bootstrap
exchange, cookie + anti-CSRF session, exact-origin enforcement, WS tickets,
Desktop/service compatibility, and non-interactive fail-closed startup.

Run through ``scripts/run_tests.sh tests/hermes_cli/test_dashboard_local_browser_auth.py``.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server as ws
from hermes_cli.dashboard_auth import clear_providers
from hermes_cli.dashboard_auth import local_browser as lb
from hermes_cli.dashboard_auth import ws_tickets

BOUND_ORIGIN = "http://127.0.0.1:9119"
SAME_ORIGIN_HEADERS = {"origin": BOUND_ORIGIN, "sec-fetch-site": "same-origin"}
OTHER_PORT_ORIGIN = "http://127.0.0.1:3000"


@pytest.fixture
def local_app(monkeypatch):
    """web_server.app configured for loopback local-browser mode + armed code.

    Yields ``(client, code)`` where ``code`` is the freshly-armed plaintext
    bootstrap code (as a real operator would read from their terminal).
    """
    lb._reset_for_tests()
    ws_tickets._reset_for_tests()
    clear_providers()
    prev = {
        name: getattr(ws.app.state, name, None)
        for name in ("bound_host", "bound_port", "auth_required",
                     "local_browser_auth", "trusted_public_hosts")
    }
    ws.app.state.bound_host = "127.0.0.1"
    ws.app.state.bound_port = 9119
    ws.app.state.auth_required = False
    ws.app.state.local_browser_auth = True
    ws.app.state.trusted_public_hosts = frozenset()
    code = lb.generate_bootstrap_code()
    client = TestClient(ws.app, base_url=BOUND_ORIGIN)
    yield client, code
    lb._reset_for_tests()
    ws_tickets._reset_for_tests()
    clear_providers()
    for name, value in prev.items():
        # Restore, but never leave frozenset-typed state as ``None`` (a stale
        # ``None`` would crash ``_is_accepted_host`` in a later test in the
        # same process — CI isolates per file, but keep multi-file runs clean).
        if value is None and name in ("trusted_public_hosts", "allowed_browser_origins"):
            value = frozenset()
        setattr(ws.app.state, name, value)


def _bootstrap(client: TestClient, code: str):
    """Drive a successful bootstrap exchange; return the response."""
    return client.post(
        "/api/auth/local/bootstrap",
        json={"code": code},
        headers=SAME_ORIGIN_HEADERS,
    )


def _authenticate(client: TestClient, code: str) -> str:
    """Complete the exchange and return the session-bound CSRF token."""
    r = _bootstrap(client, code)
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


# ---------------------------------------------------------------------------
# 1. Unauthenticated assets reveal no reusable credential.
# ---------------------------------------------------------------------------


class TestNoTokenInHtml:
    @staticmethod
    def _spa_app(tmp_path, monkeypatch, *, auth_required: bool, local_browser_auth: bool):
        """Mount the SPA on a FRESH app with the given per-app auth mode.

        ``_serve_index`` must read the mounted ``application.state`` — not a
        module global — so each app in a multi-app process serves its real
        mode. State is set on the returned app, not ``ws.app``.
        """
        from fastapi import FastAPI

        dist = tmp_path / "web_dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text(
            "<html><head><title>t</title></head><body>SPA</body></html>",
            encoding="utf-8",
        )
        monkeypatch.setattr(ws, "WEB_DIST", dist)
        spa_app = FastAPI()
        spa_app.state.auth_required = auth_required
        spa_app.state.local_browser_auth = local_browser_auth
        ws.mount_spa(spa_app)
        return spa_app

    def test_index_has_no_reusable_credential(self, tmp_path, monkeypatch):
        spa_app = self._spa_app(
            tmp_path, monkeypatch, auth_required=False, local_browser_auth=True
        )
        client = TestClient(spa_app, base_url=BOUND_ORIGIN)
        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "__HERMES_SESSION_TOKEN__" not in body
        assert ws._SESSION_TOKEN not in body
        assert "__HERMES_LOCAL_BROWSER_AUTH__=true" in body
        assert "__HERMES_AUTH_REQUIRED__=false" in body

    def test_serve_index_reads_per_app_state_not_global(self, tmp_path, monkeypatch):
        """Two apps mounted in one process serve their OWN mode flags — proves
        ``_serve_index`` reads ``application.state``, never the module global."""
        # A local-browser SPA app.
        local_app_ = self._spa_app(
            tmp_path / "a", monkeypatch, auth_required=False, local_browser_auth=True
        )
        # A gated SPA app (same process, different mode).
        gated_app_ = self._spa_app(
            tmp_path / "b", monkeypatch, auth_required=True, local_browser_auth=False
        )
        local_body = TestClient(local_app_, base_url=BOUND_ORIGIN).get("/").text
        gated_body = TestClient(gated_app_, base_url=BOUND_ORIGIN).get("/").text

        assert "__HERMES_LOCAL_BROWSER_AUTH__=true" in local_body
        assert "__HERMES_AUTH_REQUIRED__=false" in local_body
        assert "__HERMES_LOCAL_BROWSER_AUTH__=false" in gated_body
        assert "__HERMES_AUTH_REQUIRED__=true" in gated_body
        # Neither ever carries a reusable token.
        assert ws._SESSION_TOKEN not in local_body
        assert ws._SESSION_TOKEN not in gated_body

    def test_local_flag_reflects_actual_mode_not_merely_not_gated(self, tmp_path, monkeypatch):
        """A non-gated app that is NOT in local-browser mode (e.g. an odd
        headless-style state) must NOT advertise local-browser auth."""
        spa_app = self._spa_app(
            tmp_path, monkeypatch, auth_required=False, local_browser_auth=False
        )
        body = TestClient(spa_app, base_url=BOUND_ORIGIN).get("/").text
        assert "__HERMES_LOCAL_BROWSER_AUTH__=false" in body
        assert "__HERMES_AUTH_REQUIRED__=false" in body



# ---------------------------------------------------------------------------
# 2. Launch URL / process env carry no bootstrap material.
# ---------------------------------------------------------------------------


class TestLaunchCarriesNoSecret:
    def test_open_url_has_no_bootstrap_code(self, local_app, monkeypatch):
        _client, code = local_app
        captured = {}
        monkeypatch.setattr(ws.time, "sleep", lambda *_a, **_k: None)

        import webbrowser

        monkeypatch.setattr(webbrowser, "open", lambda url: captured.setdefault("url", url))
        monkeypatch.setenv("DISPLAY", ":0")  # allow browser-open path on Linux
        ws._maybe_open_browser("127.0.0.1", 9119, True, "")
        import time as _t

        for _ in range(50):
            if "url" in captured:
                break
            _t.sleep(0.02)
        assert captured.get("url") == "http://127.0.0.1:9119"
        assert code not in captured.get("url", "")

    def test_bootstrap_code_not_in_environment(self, local_app):
        import os

        _client, code = local_app
        assert all(code not in v for v in os.environ.values())


# ---------------------------------------------------------------------------
# 3. Unauthenticated callers cannot reach privileged surfaces.
# ---------------------------------------------------------------------------


class TestUnauthenticatedDenied:
    @pytest.mark.parametrize(
        "method,path,body",
        [
            ("post", "/api/env/reveal", {"key": "OPENAI_API_KEY"}),
            ("get", "/api/sessions", None),
            ("get", "/api/config", None),
            ("post", "/api/auth/ws-ticket", None),
            ("get", "/api/auth/csrf", None),
        ],
    )
    def test_requires_auth(self, local_app, method, path, body):
        client, _code = local_app
        fn = getattr(client, method)
        resp = fn(path, json=body) if body is not None else fn(path)
        assert resp.status_code == 401, f"{path} → {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# 4-6. Bootstrap exchange: single-use, replay/expiry fail closed, one winner.
# ---------------------------------------------------------------------------


class TestBootstrapExchange:
    def test_valid_code_creates_session_once(self, local_app):
        client, code = local_app
        r = _bootstrap(client, code)
        assert r.status_code == 200
        assert "csrf_token" in r.json()
        assert ws._LOCAL_SESSION_COOKIE in r.cookies or any(
            c.name == ws._LOCAL_SESSION_COOKIE for c in client.cookies.jar
        )

    def test_replay_of_consumed_code_fails(self, local_app):
        client, code = local_app
        assert _bootstrap(client, code).status_code == 200
        fresh = TestClient(ws.app, base_url=BOUND_ORIGIN)
        assert _bootstrap(fresh, code).status_code == 401

    def test_invalid_code_fails(self, local_app):
        client, _code = local_app
        assert _bootstrap(client, "NOPE-NOPE-NOPE-NOPE").status_code == 401

    def test_expired_code_fails(self, local_app, monkeypatch):
        client, _code = local_app
        lb._reset_for_tests()
        code = lb.generate_bootstrap_code(ttl_seconds=1, now=1000.0)
        # Consume against a clock past expiry.
        assert lb.consume_bootstrap_code(code, now=2000.0) is False

    def test_concurrent_exchange_one_success(self):
        lb._reset_for_tests()
        code = lb.generate_bootstrap_code()
        results = [lb.consume_bootstrap_code(code) for _ in range(5)]
        assert results.count(True) == 1

    def test_missing_origin_fails_closed(self, local_app):
        client, code = local_app
        # No Origin / Sec-Fetch-Site: cross-site or non-browser caller.
        resp = client.post("/api/auth/local/bootstrap", json={"code": code})
        assert resp.status_code == 403

    def test_cross_origin_bootstrap_fails_closed(self, local_app):
        client, code = local_app
        resp = client.post(
            "/api/auth/local/bootstrap",
            json={"code": code},
            headers={"origin": OTHER_PORT_ORIGIN, "sec-fetch-site": "same-site"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 9-14. Session principal, CSRF, WS ticket, logout, me, gated non-bypass.
# ---------------------------------------------------------------------------


class TestAuthenticatedSession:
    def test_me_reports_local_principal_without_opaque_id(self, local_app):
        client, code = local_app
        _authenticate(client, code)
        r = client.get("/api/auth/me")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["provider"] == ws._LOCAL_PROVIDER
        # The opaque session id (cookie value) never appears in the body.
        cookie_val = next(
            (c.value for c in client.cookies.jar if c.name == ws._LOCAL_SESSION_COOKIE),
            "",
        )
        assert cookie_val
        assert cookie_val not in str(body)

    def test_csrf_endpoint_returns_session_bound_token(self, local_app):
        client, code = local_app
        csrf = _authenticate(client, code)
        r = client.get("/api/auth/csrf")
        assert r.status_code == 200
        assert r.json()["csrf_token"] == csrf

    def test_ws_ticket_requires_csrf(self, local_app):
        client, code = local_app
        csrf = _authenticate(client, code)
        # Without CSRF header → 403.
        no_csrf = client.post("/api/auth/ws-ticket", headers={"origin": BOUND_ORIGIN})
        assert no_csrf.status_code == 403
        # With CSRF + origin → mint succeeds.
        ok = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: csrf},
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["ticket"]

    def test_wrong_and_cross_session_csrf_fail(self, local_app):
        client, code = local_app
        _authenticate(client, code)
        # Wrong token.
        bad = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: "wrong"},
        )
        assert bad.status_code == 403
        # A different session's token.
        other_sid, other_csrf = lb.create_session()
        cross = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: other_csrf},
        )
        assert cross.status_code == 403

    def test_logout_revokes_and_clears_cookie(self, local_app):
        client, code = local_app
        csrf = _authenticate(client, code)
        sid = next(
            c.value for c in client.cookies.jar if c.name == ws._LOCAL_SESSION_COOKIE
        )
        assert lb.verify_session(sid) is True
        r = client.post(
            "/api/auth/local/logout",
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: csrf},
        )
        assert r.status_code == 200
        assert lb.verify_session(sid) is False

    def test_reveal_reachable_only_with_principal(self, local_app):
        client, code = local_app
        csrf = _authenticate(client, code)
        # POST /api/env/reveal is a _require_token endpoint. With a valid local
        # principal + CSRF it reaches the handler (404 for an absent key), not
        # 401/403 at the auth layer.
        r = client.post(
            "/api/env/reveal",
            json={"key": "DEFINITELY_NOT_SET_XYZ"},
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: csrf},
        )
        assert r.status_code != 401 and r.status_code != 403, r.text
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# 17. A hostile page on another localhost port is blocked everywhere.
# ---------------------------------------------------------------------------


class TestCrossOriginAttackerBlocked:
    def test_cannot_submit_unsafe_request(self, local_app):
        client, code = local_app
        csrf = _authenticate(client, code)
        # Same-site cookie is sent to another PORT, but the exact-origin CSRF
        # check rejects the request even with a (leaked) correct token.
        resp = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": OTHER_PORT_ORIGIN, ws._CSRF_HEADER_NAME: csrf},
        )
        assert resp.status_code == 403

    def test_cannot_read_csrf_token(self, local_app):
        client, code = local_app
        _authenticate(client, code)
        resp = client.get(
            "/api/auth/csrf",
            headers={"origin": OTHER_PORT_ORIGIN, "sec-fetch-site": "same-site"},
        )
        assert resp.status_code == 403

    def test_cannot_connect_ws_from_other_origin(self, local_app):
        _client, _code = local_app
        ticket = ws_tickets.mint_ticket(user_id="local", provider=ws._LOCAL_PROVIDER)
        hostile = SimpleNamespace(
            query_params=SimpleNamespace(get=lambda k, d="": {"ticket": ticket}.get(k, d)),
            headers={"host": "127.0.0.1:9119", "origin": OTHER_PORT_ORIGIN},
            client=SimpleNamespace(host="127.0.0.1"),
            url=SimpleNamespace(path="/api/ws"),
        )
        assert ws._ws_host_origin_is_allowed(hostile) is False

    def test_same_origin_ws_allowed(self, local_app):
        _client, _code = local_app
        ticket = ws_tickets.mint_ticket(user_id="local", provider=ws._LOCAL_PROVIDER)
        legit = SimpleNamespace(
            query_params=SimpleNamespace(get=lambda k, d="": {"ticket": ticket}.get(k, d)),
            headers={"host": "127.0.0.1:9119", "origin": BOUND_ORIGIN},
            client=SimpleNamespace(host="127.0.0.1"),
            url=SimpleNamespace(path="/api/ws"),
        )
        assert ws._ws_host_origin_is_allowed(legit) is True


# ---------------------------------------------------------------------------
# 7-8, 15. WS auth: tickets accepted/single-use; legacy token rejected.
# ---------------------------------------------------------------------------


def _fake_ws(query: dict, *, path: str = "/api/ws"):
    return SimpleNamespace(
        query_params=SimpleNamespace(get=lambda k, d="": query.get(k, d)),
        headers={},
        client=SimpleNamespace(host="127.0.0.1"),
        url=SimpleNamespace(path=path),
    )


class TestLocalWsAuth:
    def test_ticket_accepted_and_single_use(self, local_app):
        _client, _code = local_app
        ticket = ws_tickets.mint_ticket(user_id="local", provider=ws._LOCAL_PROVIDER)
        assert ws._ws_auth_ok(_fake_ws({"ticket": ticket})) is True
        # Replay fails (single-use).
        assert ws._ws_auth_ok(_fake_ws({"ticket": ticket})) is False

    def test_internal_credential_accepted_for_server_children(self, local_app):
        _client, _code = local_app
        cred = ws_tickets.internal_ws_credential()
        assert ws._ws_auth_ok(_fake_ws({"internal": cred})) is True

    def test_legacy_query_token_rejected(self, local_app):
        _client, _code = local_app
        assert ws._ws_auth_ok(_fake_ws({"token": ws._SESSION_TOKEN})) is False

    def test_no_credential_rejected(self, local_app):
        _client, _code = local_app
        assert ws._ws_auth_ok(_fake_ws({})) is False

    def test_pty_child_url_uses_internal_credential(self, local_app):
        url = ws._build_gateway_ws_url()
        assert url is not None
        assert "internal=" in url
        assert "token=" not in url


# ---------------------------------------------------------------------------
# 9 (bypass), 10. Configured external auth / Desktop seeded-token compatibility.
# ---------------------------------------------------------------------------


class TestServiceAndGatedCompatibility:
    def test_service_header_token_still_authenticates(self, local_app):
        client, _code = local_app
        # The seeded/service token path is unchanged: a caller presenting the
        # header token reaches protected endpoints without a bootstrap cookie.
        r = client.post(
            "/api/env/reveal",
            json={"key": "DEFINITELY_NOT_SET_XYZ"},
            headers={ws._SESSION_HEADER_NAME: ws._SESSION_TOKEN},
        )
        assert r.status_code == 404  # reached handler, absent key

    def test_service_header_caller_exempt_from_csrf(self, local_app):
        client, _code = local_app
        # An unsafe request with the service header and NO CSRF token must not
        # be blocked by the CSRF owner (service-header callers unaffected).
        r = client.post(
            "/api/env/reveal",
            json={"key": "DEFINITELY_NOT_SET_XYZ"},
            headers={ws._SESSION_HEADER_NAME: ws._SESSION_TOKEN},
        )
        assert r.status_code != 403

    def test_bootstrap_disabled_when_gated(self, monkeypatch):
        # Configured external auth: the local bootstrap route is inert and
        # cannot be used to bypass the provider gate.
        prev_gated = getattr(ws.app.state, "auth_required", None)
        prev_local = getattr(ws.app.state, "local_browser_auth", None)
        ws.app.state.auth_required = True
        ws.app.state.local_browser_auth = False
        try:
            client = TestClient(ws.app, base_url=BOUND_ORIGIN)
            lb._reset_for_tests()
            code = lb.generate_bootstrap_code()
            r = client.post(
                "/api/auth/local/bootstrap",
                json={"code": code},
                headers=SAME_ORIGIN_HEADERS,
            )
            assert r.status_code in (401, 403, 404)
        finally:
            ws.app.state.auth_required = prev_gated
            ws.app.state.local_browser_auth = prev_local
            lb._reset_for_tests()


# ---------------------------------------------------------------------------
# 12. Cookie Path/Secure come from validated public_url or the direct request —
#     never spoofable Forwarded / X-Forwarded-* headers.
# ---------------------------------------------------------------------------


class TestCookiePathAndSecure:
    def test_raw_forwarded_prefix_is_ignored(self, local_app):
        # A spoofable X-Forwarded-Prefix from an untrusted peer must NOT change
        # the cookie Path — with no declared public_url the Path stays "/".
        client, code = local_app
        r = client.post(
            "/api/auth/local/bootstrap",
            json={"code": code},
            headers={**SAME_ORIGIN_HEADERS, "x-forwarded-prefix": "/evil"},
        )
        assert r.status_code == 200
        set_cookie = r.headers.get("set-cookie", "")
        assert "Path=/" in set_cookie
        assert "Path=/evil" not in set_cookie

    def test_spoofed_forwarded_proto_does_not_set_secure_over_http(self, local_app):
        # Over HTTP, a spoofed X-Forwarded-Proto: https must NOT flip Secure on
        # (proxy_headers is off in local mode, so the real scheme wins).
        client, code = local_app
        r = client.post(
            "/api/auth/local/bootstrap",
            json={"code": code},
            headers={
                **SAME_ORIGIN_HEADERS,
                "x-forwarded-proto": "https",
                "forwarded": "proto=https",
            },
        )
        assert r.status_code == 200
        assert "secure" not in r.headers.get("set-cookie", "").lower()

    def test_public_url_https_over_http_backend_marks_cookie_secure(self, local_app, monkeypatch):
        # A loopback public_url declared as HTTPS (TLS terminator in front of an
        # HTTP loopback backend) makes the cookie Secure AND honours its path
        # prefix, even though the backend connection is plain HTTP.
        client, code = local_app
        monkeypatch.setattr(
            "hermes_cli.dashboard_auth.prefix.resolve_public_url",
            lambda: "https://localhost:9119/hermes",
        )
        r = client.post(
            "/api/auth/local/bootstrap",
            json={"code": code},
            headers={"origin": "https://localhost:9119", "sec-fetch-site": "same-origin"},
        )
        assert r.status_code == 200, r.text
        set_cookie = r.headers.get("set-cookie", "").lower()
        assert "secure" in set_cookie
        assert "path=/hermes" in set_cookie


# ---------------------------------------------------------------------------
# 16. Non-interactive startup fails closed (no code emitted via URL/log).
# ---------------------------------------------------------------------------


class TestNonInteractiveFailsClosed:
    def test_refuses_without_terminal_or_provider(self, tmp_path, monkeypatch):
        clear_providers()
        dist = tmp_path / "web_dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<html></html>", encoding="utf-8")
        monkeypatch.setattr(ws, "WEB_DIST", dist)
        monkeypatch.setattr(ws, "_stdout_is_interactive", lambda: False)
        # Avoid actually binding a socket.
        import uvicorn

        monkeypatch.setattr(
            uvicorn, "Server", lambda config: (_ for _ in ()).throw(AssertionError("must not bind"))
        )
        # start_server mutates app.state (local_browser_auth/auth_required/...)
        # before raising, so snapshot + restore to keep this global state from
        # leaking into other tests in the same process.
        prev = {
            name: getattr(ws.app.state, name, None)
            for name in ("bound_host", "bound_port", "auth_required",
                         "local_browser_auth", "trusted_public_hosts",
                         "allowed_browser_origins")
        }
        try:
            with pytest.raises(SystemExit):
                ws.start_server(host="127.0.0.1", port=0, open_browser=False)
        finally:
            for name, value in prev.items():
                setattr(ws.app.state, name, value)


# ---------------------------------------------------------------------------
# 21. Route-table contract: every param-free privileged GET /api route fails
# closed unauthenticated; only the documented public allowlist is reachable.
# ---------------------------------------------------------------------------


class TestRouteTableFailsClosed:
    _ALLOWED_NONAUTH = None

    @staticmethod
    def _exempt() -> set:
        return set(ws._PUBLIC_API_PATHS) | {ws._LOCAL_BOOTSTRAP_PATH}

    def test_every_param_free_api_method_fails_closed(self, local_app):
        """Every registered privileged HTTP method (not just GET) on a
        parameter-free ``/api`` route MUST 401/403 an unauthenticated caller —
        auth runs before the handler, so a new route without an explicit public
        classification fails closed automatically."""
        client, _code = local_app
        allowed_nonauth = self._exempt()
        checked = 0
        leaked: list[tuple[str, str, int]] = []
        for route in ws.app.router.routes:
            path = getattr(route, "path", "")
            methods = getattr(route, "methods", None) or set()
            if not path.startswith("/api/") or "{" in path:
                continue
            if path in allowed_nonauth or path.startswith("/api/mcp/oauth/callback/"):
                continue
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                if method not in methods:
                    continue
                resp = client.request(method, path)
                checked += 1
                if resp.status_code not in (401, 403):
                    leaked.append((path, method, resp.status_code))
        assert checked > 0, "route table introspection found no privileged routes"
        assert not leaked, (
            "privileged /api routes reachable unauthenticated (not in the "
            f"public allowlist): {leaked}"
        )

    def test_all_ws_routes_reject_no_credential(self, local_app):
        """Every registered WebSocket route rejects an unauthenticated upgrade
        (no ticket / token / internal credential)."""
        from starlette.routing import WebSocketRoute

        ws_paths = [
            r.path for r in ws.app.router.routes if isinstance(r, WebSocketRoute)
        ]
        assert ws_paths, "no WebSocket routes discovered"
        for path in ws_paths:
            fake = _fake_ws({}, path=path)
            assert ws._ws_auth_ok(fake) is False, f"{path} accepted a no-credential WS"

    def test_all_ws_routes_reject_cross_origin(self, local_app):
        """Every registered WebSocket route rejects a cross-origin upgrade even
        with an otherwise-valid ticket (a hostile localhost port is blocked)."""
        from starlette.routing import WebSocketRoute

        ws_paths = [
            r.path for r in ws.app.router.routes if isinstance(r, WebSocketRoute)
        ]
        ticket = ws_tickets.mint_ticket(user_id="local", provider=ws._LOCAL_PROVIDER)
        for path in ws_paths:
            hostile = SimpleNamespace(
                query_params=SimpleNamespace(
                    get=lambda k, d="": {"ticket": ticket}.get(k, d)
                ),
                headers={"host": "127.0.0.1:9119", "origin": OTHER_PORT_ORIGIN},
                client=SimpleNamespace(host="127.0.0.1"),
                url=SimpleNamespace(path=path, scheme="ws"),
            )
            assert ws._ws_host_origin_is_allowed(hostile) is False, (
                f"{path} allowed a cross-origin WS upgrade"
            )


# ---------------------------------------------------------------------------
# CORS: exact-origin credentialed policy (plan §8).
# ---------------------------------------------------------------------------


class TestCors:
    def test_preflight_exact_origin_allowed(self, local_app):
        client, _code = local_app
        r = client.options(
            "/api/sessions/import",
            headers={
                "origin": BOUND_ORIGIN,
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type,x-hermes-csrf-token",
            },
        )
        assert r.status_code == 204
        assert r.headers.get("access-control-allow-origin") == BOUND_ORIGIN
        assert r.headers.get("access-control-allow-credentials") == "true"

    def test_preflight_hostile_localhost_port_denied(self, local_app):
        client, _code = local_app
        r = client.options(
            "/api/sessions/import",
            headers={
                "origin": OTHER_PORT_ORIGIN,
                "access-control-request-method": "POST",
            },
        )
        assert r.status_code == 403
        assert r.headers.get("access-control-allow-origin") is None

    def test_actual_request_from_hostile_port_gets_no_acao(self, local_app):
        client, _code = local_app
        r = client.get("/api/status", headers={"origin": OTHER_PORT_ORIGIN})
        # Response may still be 200 (public), but with NO ACAO the browser
        # blocks the cross-origin read.
        assert r.headers.get("access-control-allow-origin") is None

    def test_actual_request_same_origin_gets_credentialed_acao(self, local_app):
        client, _code = local_app
        r = client.get("/api/status", headers={"origin": BOUND_ORIGIN})
        assert r.headers.get("access-control-allow-origin") == BOUND_ORIGIN
        assert r.headers.get("access-control-allow-credentials") == "true"


# ---------------------------------------------------------------------------
# 11. Multi-profile routing isolation is preserved under local-browser auth.
# ---------------------------------------------------------------------------


class TestProfileRoutingIsolation:
    def test_local_auth_preserves_profile_routing(self, local_app, tmp_path, monkeypatch):
        """A local-authenticated request routes to the exact ``?profile=`` it
        names — the local principal is not a cross-profile authority, so the
        same profile-scoping (`_profile_scope` → `_resolve_profile_dir`) that
        gated/service callers go through still applies. Two isolated profiles
        must return their own secrets, never each other's."""
        client, code = local_app
        csrf = _authenticate(client, code)

        alpha = tmp_path / "alpha"
        alpha.mkdir()
        (alpha / ".env").write_text("PROFILE_MARKER=alpha-secret\n", encoding="utf-8")
        beta = tmp_path / "beta"
        beta.mkdir()
        (beta / ".env").write_text("PROFILE_MARKER=beta-secret\n", encoding="utf-8")
        mapping = {"alpha": alpha, "beta": beta}
        monkeypatch.setattr(ws, "_resolve_profile_dir", lambda name: mapping[name])

        hdr = {"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: csrf}
        ra = client.post(
            "/api/env/reveal",
            json={"key": "PROFILE_MARKER", "profile": "alpha"},
            headers=hdr,
        )
        rb = client.post(
            "/api/env/reveal",
            json={"key": "PROFILE_MARKER", "profile": "beta"},
            headers=hdr,
        )
        assert ra.status_code == 200, ra.text
        assert rb.status_code == 200, rb.text
        assert ra.json()["value"] == "alpha-secret"
        assert rb.json()["value"] == "beta-secret"


# ---------------------------------------------------------------------------
# 20. Host / Origin / Forwarded / X-Forwarded spoof matrix; direct-backend
#     impersonation; cookie security invariants.
# ---------------------------------------------------------------------------


class TestSpoofMatrix:
    def test_spoofed_host_header_rejected(self, local_app):
        client, _code = local_app
        # DNS-rebinding-style Host that doesn't match the bound interface.
        r = client.get("/api/status", headers={"host": "evil.test"})
        assert r.status_code == 400

    def test_xforwarded_headers_do_not_change_accepted_origin(self, local_app):
        client, code = local_app
        csrf = _authenticate(client, code)
        spoof = {
            "x-forwarded-host": "evil.example.com",
            "x-forwarded-proto": "https",
            "forwarded": "host=evil.example.com;proto=https",
        }
        # Correct Origin still works despite spoofed forwarding headers — the
        # accepted origin is the real Host/scheme, never X-Forwarded-*.
        ok = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: csrf, **spoof},
        )
        assert ok.status_code == 200, ok.text
        # A forged Origin matching the spoofed X-Forwarded-Host is still
        # rejected: the origin is not derived from those headers.
        bad = client.post(
            "/api/auth/ws-ticket",
            headers={
                "origin": "https://evil.example.com",
                ws._CSRF_HEADER_NAME: csrf,
                **spoof,
            },
        )
        assert bad.status_code == 403

    def test_direct_backend_cannot_impersonate_public_origin(self, local_app, monkeypatch):
        client, code = local_app
        csrf = _authenticate(client, code)
        # Operator declared a canonical public URL: it becomes the ONLY accepted
        # origin, so a request arriving directly at the loopback backend cannot
        # impersonate the proxied public origin.
        monkeypatch.setattr(
            "hermes_cli.dashboard_auth.prefix.resolve_public_url",
            lambda: "https://dash.example.com",
        )
        direct = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": BOUND_ORIGIN, ws._CSRF_HEADER_NAME: csrf},
        )
        assert direct.status_code == 403, direct.text
        # Fetching the token also fails from the non-public origin.
        via_public = client.post(
            "/api/auth/ws-ticket",
            headers={"origin": "https://dash.example.com", ws._CSRF_HEADER_NAME: csrf},
        )
        # The token was derived for this session, so with the declared public
        # origin the exact-origin gate passes and the mint succeeds.
        assert via_public.status_code == 200, via_public.text

    def test_local_session_cookie_security_attributes(self, local_app):
        client, code = local_app
        r = _bootstrap(client, code)
        assert r.status_code == 200
        set_cookie = r.headers.get("set-cookie", "").lower()
        assert ws._LOCAL_SESSION_COOKIE.lower() in set_cookie
        assert "httponly" in set_cookie
        assert "samesite=strict" in set_cookie
        assert "path=/" in set_cookie
        # Host-only: no Domain attribute pins it to the exact origin.
        assert "domain=" not in set_cookie
        # Loopback is HTTP, so Secure must NOT be set (it would lock the cookie
        # out of the browser); it is applied only over HTTPS.
        assert "secure" not in set_cookie

    def test_local_session_cookie_secure_over_https(self):
        prev = {
            name: getattr(ws.app.state, name, None)
            for name in ("bound_host", "bound_port", "auth_required",
                         "local_browser_auth", "trusted_public_hosts")
        }
        lb._reset_for_tests()
        ws.app.state.bound_host = "127.0.0.1"
        ws.app.state.bound_port = 9119
        ws.app.state.auth_required = False
        ws.app.state.local_browser_auth = True
        ws.app.state.trusted_public_hosts = frozenset()
        try:
            code = lb.generate_bootstrap_code()
            https_client = TestClient(ws.app, base_url="https://127.0.0.1:9119")
            r = https_client.post(
                "/api/auth/local/bootstrap",
                json={"code": code},
                headers={"origin": "https://127.0.0.1:9119", "sec-fetch-site": "same-origin"},
            )
            assert r.status_code == 200, r.text
            assert "secure" in r.headers.get("set-cookie", "").lower()
        finally:
            lb._reset_for_tests()
            for name, value in prev.items():
                setattr(ws.app.state, name, value)
