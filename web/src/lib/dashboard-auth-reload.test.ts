import { describe, expect, it, vi } from "vitest";

import {
  attemptDashboardReloadOnce,
  clearDashboardReloadAttempt,
  maybeReturnToBootstrapGateOnWsAuthFailure,
} from "./dashboard-auth-reload";

function makeStorage() {
  const values = new Map<string, string>();
  return {
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    removeItem(key: string) {
      values.delete(key);
    },
    setItem(key: string, value: string) {
      values.set(key, value);
    },
  };
}

describe("attemptDashboardReloadOnce", () => {
  it("reloads once and latches the attempt", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(attemptDashboardReloadOnce(storage, reload)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);

    expect(attemptDashboardReloadOnce(storage, reload)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("clears the latch when asked", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(attemptDashboardReloadOnce(storage, reload)).toBe(true);
    clearDashboardReloadAttempt(storage);
    expect(attemptDashboardReloadOnce(storage, reload)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(2);
  });
});

describe("maybeReturnToBootstrapGateOnWsAuthFailure", () => {
  it("reloads to the gate once for a local-browser 4401 close", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(
      // code, authRequired=false, storage, reload, isLocalBrowserAuth=true
      maybeReturnToBootstrapGateOnWsAuthFailure(4401, false, storage, reload, true),
    ).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("does not reload in gated mode, other close codes, or non-local modes", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    // Gated (authRequired=true) → the next connect re-mints a ticket.
    expect(
      maybeReturnToBootstrapGateOnWsAuthFailure(4401, true, storage, reload, false),
    ).toBe(false);
    // Non-4401 close code.
    expect(
      maybeReturnToBootstrapGateOnWsAuthFailure(4403, false, storage, reload, true),
    ).toBe(false);
    // Neither gated nor local-browser (no session-based auth): nothing to
    // return to — never reload-loop.
    expect(
      maybeReturnToBootstrapGateOnWsAuthFailure(4401, false, storage, reload, false),
    ).toBe(false);
    expect(reload).not.toHaveBeenCalled();
  });
});
