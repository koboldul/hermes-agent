"""Local browser bootstrap + session store for the loopback dashboard.

This module closes SEC-AUDIT-001 (loopback dashboard token disclosure). The
old loopback mode injected the reusable ``_SESSION_TOKEN`` into the SPA HTML,
so any process that could reach the loopback port could read it from an
unauthenticated page and drive every privileged API. This module replaces that
with a proof-of-launch-credential exchange that never places reusable material
in an unauthenticated response, a URL, a process argument, an environment
variable, or a log line.

Flow (loopback browser dashboard only — ``app.state.local_browser_auth``):

  1. ``hermes dashboard`` generates a single-use *bootstrap code* and prints it
     to the invoking terminal ONLY. The server stores only its digest.
  2. The browser opens a credential-free URL. The SPA renders a bootstrap-code
     form (there is no token in the HTML).
  3. The user types the code; the SPA POSTs it once to the exchange endpoint.
  4. The server consumes the code atomically (single-use, short-lived,
     constant-time compared) and mints a *local session*: a random opaque id
     whose digest is stored server-side and whose value is returned ONLY in a
     host-only ``HttpOnly; SameSite=Strict`` cookie.
  5. A session-bound anti-CSRF token is derived by HMAC over the opaque id with
     a per-process secret. The token is re-derivable for an authenticated
     same-origin request but unforgeable without the cookie (which is never
     exposed to JavaScript) AND the per-process secret (which never leaves the
     process). Nothing about the CSRF token is stored, so there is nothing to
     steal from the store.

Everything is in-memory and process-local: the dashboard is a single process,
so no distributed coordination is needed (mirrors ``ws_tickets`` /
``native_flow``). Restarting the server drops the store, which invalidates
every previously issued session and code — a deliberate property
("server-instance scoped"). A functional API (not a class) keeps ``time.time``
patchable in tests.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Tunables. All chosen to fail closed and stay bounded.
# ---------------------------------------------------------------------------

#: How long a printed bootstrap code stays valid before it must be relaunched.
BOOTSTRAP_TTL_SECONDS = 15 * 60
#: Absolute lifetime of a minted local session (relaunch required afterwards).
SESSION_ABSOLUTE_TTL_SECONDS = 12 * 60 * 60
#: Idle lifetime of a local session (no authenticated request within window).
SESSION_IDLE_TTL_SECONDS = 60 * 60
#: Upper bound on concurrently-live local sessions (one browser user in
#: practice; the cap stops an attacker who somehow guesses codes from growing
#: the store without bound).
MAX_SESSIONS = 64
#: Global failed-bootstrap-attempt budget within the rolling window.
BOOTSTRAP_MAX_ATTEMPTS = 20
#: Per-client failed-bootstrap-attempt budget within the rolling window.
BOOTSTRAP_MAX_ATTEMPTS_PER_CLIENT = 10
#: Rolling window for the failed-attempt budgets.
BOOTSTRAP_ATTEMPT_WINDOW_SECONDS = 60

_lock = threading.Lock()


def _now(now: Optional[float]) -> float:
    return time.time() if now is None else now


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# Per-process secret for CSRF derivation. Regenerated on import (i.e. per
# process), so a token derived by one server instance is meaningless to the
# next — the same "server-instance scoped" property the session store has.
# ---------------------------------------------------------------------------

_CSRF_SECRET = secrets.token_bytes(32)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def csrf_token_for_value(value: str) -> str:
    """Derive a session-bound anti-CSRF token from an opaque identity value.

    Pure function of ``(per-process secret, value)``. Used for both local
    sessions (``value`` = opaque local-session id) and provider sessions
    (``value`` = the session's access-token cookie), so one CSRF owner covers
    every cookie-authenticated dashboard request. Nothing is stored: the token
    is recomputed on demand for an authenticated same-origin caller and
    verified in constant time.
    """
    mac = hmac.new(_CSRF_SECRET, value.encode("utf-8"), hashlib.sha256).digest()
    return _b64url(mac)


def verify_csrf_for_value(value: str, presented: str) -> bool:
    """Constant-time check that ``presented`` matches the token for ``value``."""
    if not value or not presented:
        return False
    expected = csrf_token_for_value(value)
    return hmac.compare_digest(expected.encode("ascii"), presented.encode("ascii"))


# ---------------------------------------------------------------------------
# Bootstrap code (single active code, digest-only, single-use, expiring).
# ---------------------------------------------------------------------------


@dataclass
class _Bootstrap:
    digest: bytes
    expires_at: float
    consumed: bool = False


_bootstrap: Optional[_Bootstrap] = None

#: Failed-attempt ledgers for rate limiting. A *wrong* guess is recorded; a
#: correct guess consumes the code and is not a "failure".
_attempts: Deque[float] = deque()
_attempts_by_client: Dict[str, Deque[float]] = {}


def _format_code(raw: bytes) -> str:
    """Render high-entropy bytes as a human-typable dash-grouped code.

    Base32 without padding, uppercased, split into 4-char groups. 10 random
    bytes → 80 bits of entropy across 16 characters (``ABCD-EFGH-IJKL-MNOP``).
    Combined with a 15-minute TTL, single use, and the failed-attempt budgets
    below, this is far more than enough against online guessing.
    """
    body = base64.b32encode(raw).decode("ascii").rstrip("=").upper()
    return "-".join(body[i : i + 4] for i in range(0, len(body), 4))


def _normalise_code(code: str) -> str:
    """Canonicalise a user-typed code for comparison.

    Users may paste with or without dashes and in any case; strip separators
    and uppercase so ``abcd efgh`` and ``ABCD-EFGH`` match the stored digest.
    """
    return "".join(ch for ch in (code or "") if ch.isalnum()).upper()


def generate_bootstrap_code(*, ttl_seconds: int = BOOTSTRAP_TTL_SECONDS, now: Optional[float] = None) -> str:
    """Mint a fresh single-use bootstrap code and arm the store with its digest.

    Returns the *plaintext* code for one-time terminal display. Only the digest
    is retained; the plaintext is never stored, logged, or otherwise persisted.
    Arming a new code invalidates any previous one.
    """
    now = _now(now)
    code = _format_code(secrets.token_bytes(10))
    digest = _sha256(_normalise_code(code))
    with _lock:
        global _bootstrap
        _bootstrap = _Bootstrap(digest=digest, expires_at=now + ttl_seconds)
    return code


def bootstrap_is_armed(*, now: Optional[float] = None) -> bool:
    now = _now(now)
    with _lock:
        return bool(
            _bootstrap
            and not _bootstrap.consumed
            and _bootstrap.expires_at >= now
        )


def _prune_attempts_locked(now: float) -> None:
    cutoff = now - BOOTSTRAP_ATTEMPT_WINDOW_SECONDS
    while _attempts and _attempts[0] < cutoff:
        _attempts.popleft()
    empty_clients = []
    for client, dq in _attempts_by_client.items():
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            empty_clients.append(client)
    for client in empty_clients:
        _attempts_by_client.pop(client, None)


def _record_failed_attempt_locked(now: float, client_ip: str) -> None:
    _attempts.append(now)
    dq = _attempts_by_client.setdefault(client_ip or "", deque())
    dq.append(now)


def bootstrap_rate_limited(client_ip: str, *, now: Optional[float] = None) -> bool:
    """True when the failed-attempt budget (global or per-client) is exhausted."""
    now = _now(now)
    with _lock:
        _prune_attempts_locked(now)
        if len(_attempts) >= BOOTSTRAP_MAX_ATTEMPTS:
            return True
        dq = _attempts_by_client.get(client_ip or "")
        return bool(dq and len(dq) >= BOOTSTRAP_MAX_ATTEMPTS_PER_CLIENT)


def consume_bootstrap_code(
    code: str, *, client_ip: str = "", now: Optional[float] = None
) -> bool:
    """Atomically verify + consume a bootstrap code. Returns True exactly once.

    Fails closed for a missing/expired/already-consumed code, an empty input,
    or a wrong guess. A wrong guess is recorded against the rate-limit budgets
    and does NOT consume the still-valid code (so a legitimate operator can
    still complete the exchange after someone else fat-fingers it). The rolling
    budget stops online guessing regardless.
    """
    now = _now(now)
    normalised = _normalise_code(code)
    with _lock:
        _prune_attempts_locked(now)
        # Rate-limit BEFORE looking at the code so a flood can't turn into a
        # code-consuming oracle.
        if len(_attempts) >= BOOTSTRAP_MAX_ATTEMPTS:
            return False
        dq = _attempts_by_client.get(client_ip or "")
        if dq and len(dq) >= BOOTSTRAP_MAX_ATTEMPTS_PER_CLIENT:
            return False

        global _bootstrap
        entry = _bootstrap
        if entry is None or entry.consumed or entry.expires_at < now or not normalised:
            _record_failed_attempt_locked(now, client_ip)
            return False
        candidate = _sha256(normalised)
        if not hmac.compare_digest(candidate, entry.digest):
            _record_failed_attempt_locked(now, client_ip)
            return False
        # Correct code: consume atomically. A concurrent second call finds
        # ``consumed`` True and returns False, so exactly one caller wins.
        entry.consumed = True
        _bootstrap = None
        return True


# ---------------------------------------------------------------------------
# Local sessions (opaque id, digest-only, idle + absolute expiry, capacity).
# ---------------------------------------------------------------------------


@dataclass
class _SessionEntry:
    created_at: float
    idle_deadline: float
    absolute_deadline: float


_sessions: Dict[bytes, _SessionEntry] = {}  # digest(session_id) -> entry


def _gc_sessions_locked(now: float) -> None:
    dead = [
        key
        for key, entry in _sessions.items()
        if entry.idle_deadline < now or entry.absolute_deadline < now
    ]
    for key in dead:
        _sessions.pop(key, None)


def create_session(
    *,
    absolute_ttl_seconds: int = SESSION_ABSOLUTE_TTL_SECONDS,
    idle_ttl_seconds: int = SESSION_IDLE_TTL_SECONDS,
    now: Optional[float] = None,
) -> Tuple[str, str]:
    """Mint a local session. Returns ``(session_id, csrf_token)``.

    ``session_id`` is a 256-bit opaque value placed ONLY in the HttpOnly
    cookie; the server retains only its digest. ``csrf_token`` is the
    session-bound anti-CSRF token derived from the opaque id.
    """
    now = _now(now)
    session_id = secrets.token_urlsafe(32)
    digest = _sha256(session_id)
    with _lock:
        _gc_sessions_locked(now)
        # Bound the store. Evicting the oldest keeps a single active browser
        # session healthy while refusing unbounded growth.
        if len(_sessions) >= MAX_SESSIONS:
            oldest = min(_sessions.items(), key=lambda kv: kv[1].created_at)[0]
            _sessions.pop(oldest, None)
        _sessions[digest] = _SessionEntry(
            created_at=now,
            idle_deadline=now + idle_ttl_seconds,
            absolute_deadline=now + absolute_ttl_seconds,
        )
    return session_id, csrf_token_for_value(session_id)


def verify_session(
    session_id: str,
    *,
    touch: bool = True,
    idle_ttl_seconds: int = SESSION_IDLE_TTL_SECONDS,
    now: Optional[float] = None,
) -> bool:
    """Validate an opaque session id against the store.

    Refreshes the idle deadline on a successful validation (unless ``touch`` is
    False). Returns False for unknown, idle-expired, or absolutely-expired
    sessions and drops the expired entry.
    """
    if not session_id:
        return False
    now = _now(now)
    digest = _sha256(session_id)
    with _lock:
        _gc_sessions_locked(now)
        entry = _sessions.get(digest)
        if entry is None:
            return False
        if entry.idle_deadline < now or entry.absolute_deadline < now:
            _sessions.pop(digest, None)
            return False
        if touch:
            entry.idle_deadline = min(
                entry.absolute_deadline, now + idle_ttl_seconds
            )
        return True


def session_absolute_deadline(session_id: str) -> Optional[float]:
    """Return the absolute expiry of a live session, or None."""
    if not session_id:
        return None
    with _lock:
        entry = _sessions.get(_sha256(session_id))
        return entry.absolute_deadline if entry else None


def revoke_session(session_id: str) -> bool:
    """Drop a local session server-side. Returns True if one was removed."""
    if not session_id:
        return False
    with _lock:
        return _sessions.pop(_sha256(session_id), None) is not None


def active_session_count() -> int:
    with _lock:
        return len(_sessions)


def _reset_for_tests() -> None:
    """Test-only: drop all bootstrap + session + rate-limit state."""
    with _lock:
        global _bootstrap
        _bootstrap = None
        _sessions.clear()
        _attempts.clear()
        _attempts_by_client.clear()
