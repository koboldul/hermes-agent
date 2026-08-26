/**
 * Session-expiry recovery for the browser dashboard.
 *
 * SEC-AUDIT-001: the SPA no longer receives a reusable token in its HTML, so
 * a 401 / WS-4401 is never a "stale injected token" — it is an expired or
 * absent dashboard *session*:
 *
 *   * Gated (OAuth/password) mode — ``fetchJSON`` full-page-redirects to
 *     ``/login`` on the structured ``session_expired`` envelope, and a WS
 *     4401 is transient (the next connect mints a fresh single-use ticket), so
 *     nothing here fires.
 *   * Loopback local-browser mode — an expired session cookie must be
 *     re-proved. A single guarded reload returns to the ``LocalBrowserAuthGate``
 *     which re-checks the cookie (via ``/api/auth/csrf``): a still-valid cookie
 *     renders the app, an expired one shows the bootstrap-code form. This
 *     never "reloads a fresh token" — there is no token to reload.
 */
type StorageLike = Pick<Storage, "getItem" | "removeItem" | "setItem">;

const RELOAD_STORAGE_KEY = "hermes.authReloadAttempted";

function dashboardAuthRequired(): boolean {
  return typeof window !== "undefined" && !!window.__HERMES_AUTH_REQUIRED__;
}

function localBrowserAuth(): boolean {
  return typeof window !== "undefined" && !!window.__HERMES_LOCAL_BROWSER_AUTH__;
}

function reloadDashboardWindow(): void {
  if (typeof window !== "undefined") {
    window.location.reload();
  }
}

function dashboardSessionStorage(): StorageLike | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function clearDashboardReloadAttempt(
  storage: StorageLike | null = dashboardSessionStorage(),
): void {
  try {
    storage?.removeItem(RELOAD_STORAGE_KEY);
  } catch {
    /* privacy mode / blocked storage — ignore */
  }
}

/**
 * Reload once to return to the bootstrap gate. Latched via ``sessionStorage``
 * so a persistent auth failure cannot loop; the latch clears on the next
 * successful response (see ``fetchJSON``). Returns ``true`` when a reload was
 * triggered.
 */
export function attemptDashboardReloadOnce(
  storage: StorageLike | null = dashboardSessionStorage(),
  reload: () => void = reloadDashboardWindow,
): boolean {
  let alreadyReloaded = false;
  try {
    alreadyReloaded = storage?.getItem(RELOAD_STORAGE_KEY) === "1";
  } catch {
    /* privacy mode / blocked storage — fall through */
  }
  if (alreadyReloaded) {
    return false;
  }

  try {
    storage?.setItem(RELOAD_STORAGE_KEY, "1");
  } catch {
    /* privacy mode / blocked storage — best effort */
  }

  reload();
  return true;
}

/**
 * Recover from a WebSocket auth-failure close (code 4401).
 *
 *   * Gated mode → ``false`` (the next connect mints a fresh ticket).
 *   * Local-browser mode → return to the bootstrap gate (guarded reload).
 *   * Any other mode / close code → ``false``.
 */
export function maybeReturnToBootstrapGateOnWsAuthFailure(
  code: number,
  authRequired = dashboardAuthRequired(),
  storage: StorageLike | null = dashboardSessionStorage(),
  reload: () => void = reloadDashboardWindow,
  isLocalBrowserAuth = localBrowserAuth(),
): boolean {
  if (code !== 4401 || authRequired || !isLocalBrowserAuth) {
    return false;
  }
  return attemptDashboardReloadOnce(storage, reload);
}
