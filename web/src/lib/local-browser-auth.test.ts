// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildWsAuthParam,
  exchangeBootstrapCode,
  fetchJSON,
  getCsrfToken,
  isLocalBrowserAuthMode,
  localLogout,
  refreshCsrfToken,
} from "./api";

vi.mock("./dashboard-auth-reload", () => ({
  attemptDashboardReloadOnce: vi.fn(() => false),
  clearDashboardReloadAttempt: vi.fn(),
}));

const CSRF_HEADER = "X-Hermes-CSRF-Token";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

// Typed ``fetch`` mock so ``mock.calls`` carries the real
// ``[input, init?]`` tuple (not an inferred empty ``[]``). Callers that
// inspect call args use this instead of a bare ``vi.fn``.
type FetchMockImpl = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
function fetchMock(impl: FetchMockImpl) {
  return vi.fn<FetchMockImpl>(impl);
}

beforeEach(() => {
  Object.defineProperty(window, "__HERMES_LOCAL_BROWSER_AUTH__", {
    configurable: true,
    value: true,
    writable: true,
  });
  Object.defineProperty(window, "__HERMES_AUTH_REQUIRED__", {
    configurable: true,
    value: false,
    writable: true,
  });
  Object.defineProperty(window, "__HERMES_SESSION_TOKEN__", {
    configurable: true,
    value: undefined,
    writable: true,
  });
});

afterEach(async () => {
  // Clear the in-memory CSRF token so tests are order-independent.
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));
  await localLogout();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("local browser auth", () => {
  it("reports local-browser mode from the injected flag", () => {
    expect(isLocalBrowserAuthMode()).toBe(true);
  });

  it("captures the CSRF token from a successful bootstrap exchange", async () => {
    const mock = fetchMock(async () => jsonResponse({ ok: true, csrf_token: "csrf-123" }));
    vi.stubGlobal("fetch", mock);

    await exchangeBootstrapCode("ABCD-EFGH");

    expect(getCsrfToken()).toBe("csrf-123");
    const [url, init] = mock.mock.calls[0];
    expect(url).toBe("/api/auth/local/bootstrap");
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(JSON.parse(String(init?.body ?? "{}"))).toEqual({ code: "ABCD-EFGH" });
  });

  it("throws with the server detail when the bootstrap code is rejected", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ detail: "Invalid or expired bootstrap code" }, 401)),
    );
    await expect(exchangeBootstrapCode("bad")).rejects.toThrow(
      "Invalid or expired bootstrap code",
    );
    expect(getCsrfToken()).toBe("");
  });

  it("attaches the CSRF header to unsafe requests, not to safe ones", async () => {
    vi.stubGlobal(
      "fetch",
      fetchMock(async () => jsonResponse({ ok: true, csrf_token: "csrf-xyz" })),
    );
    await exchangeBootstrapCode("code");

    const mock = fetchMock(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", mock);

    await fetchJSON("/api/env", { method: "POST", body: "{}" });
    const postHeaders = mock.mock.calls[0][1]?.headers as Headers;
    expect(postHeaders.get(CSRF_HEADER)).toBe("csrf-xyz");

    await fetchJSON("/api/status");
    const getHeaders = mock.mock.calls[1][1]?.headers as Headers;
    expect(getHeaders.has(CSRF_HEADER)).toBe(false);
  });

  it("re-fetches the CSRF token after a reload", async () => {
    vi.stubGlobal(
      "fetch",
      fetchMock(async () => jsonResponse({ csrf_token: "reloaded-token" })),
    );
    const authed = await refreshCsrfToken();
    expect(authed).toBe(true);
    expect(getCsrfToken()).toBe("reloaded-token");
  });

  it("treats a 401 from the CSRF probe as unauthenticated", async () => {
    vi.stubGlobal("fetch", fetchMock(async () => jsonResponse({ detail: "Unauthorized" }, 401)));
    const authed = await refreshCsrfToken();
    expect(authed).toBe(false);
    expect(getCsrfToken()).toBe("");
  });

  it("mints a single-use ticket for the WS auth param in local mode", async () => {
    const mock = fetchMock(async () => jsonResponse({ ticket: "tkt-1", ttl_seconds: 30 }));
    vi.stubGlobal("fetch", mock);

    const [name, value] = await buildWsAuthParam();
    expect(name).toBe("ticket");
    expect(value).toBe("tkt-1");
    expect(mock.mock.calls[0][0]).toBe("/api/auth/ws-ticket");
  });

  it("refreshes the CSRF token and retries once after a 403 (rotation)", async () => {
    const mock = fetchMock(async (input, init) => {
      if (String(input) === "/api/auth/csrf") return jsonResponse({ csrf_token: "fresh" });
      const hdrs = init?.headers as Headers | undefined;
      if (!hdrs || !hdrs.get(CSRF_HEADER)) {
        return jsonResponse({ detail: "CSRF token invalid" }, 403);
      }
      return jsonResponse({ ok: true });
    });
    vi.stubGlobal("fetch", mock);

    const out = await fetchJSON<{ ok: boolean }>("/api/x", { method: "POST", body: "{}" });
    expect(out).toEqual({ ok: true });
    // The 403 triggered a CSRF refresh + one retry that carried the token.
    expect(mock.mock.calls.some((c) => String(c[0]) === "/api/auth/csrf")).toBe(true);
  });

  it("sends the CSRF header on local logout", async () => {
    vi.stubGlobal("fetch", fetchMock(async () => jsonResponse({ ok: true, csrf_token: "lt" })));
    await exchangeBootstrapCode("code");

    const mock = fetchMock(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", mock);

    await localLogout();
    const headers = mock.mock.calls[0][1]?.headers as Headers;
    expect(headers.get(CSRF_HEADER)).toBe("lt");
    // Logout clears the in-memory token.
    expect(getCsrfToken()).toBe("");
  });
});
