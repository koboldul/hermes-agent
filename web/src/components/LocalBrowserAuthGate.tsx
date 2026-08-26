/**
 * LocalBrowserAuthGate — the loopback dashboard's bootstrap-code sign-in
 * (SEC-AUDIT-001).
 *
 * In the loopback browser dashboard the server no longer injects a reusable
 * token into the HTML. Instead ``hermes dashboard`` prints a one-time
 * bootstrap code to the launching terminal; this gate collects that code,
 * exchanges it for an HttpOnly session cookie, and only then renders the app.
 * On a reload it first probes ``/api/auth/csrf`` (via ``refreshCsrfToken``) so
 * an already-authenticated session skips the form.
 *
 * The gate is inert outside local-browser mode (gated OAuth and the headless
 * service path handle their own auth), rendering children immediately.
 *
 * The bootstrap code, session id, and anti-CSRF token are never written to
 * localStorage/sessionStorage — the code lives only in this component's
 * transient state and the CSRF token only in module memory in ``api.ts``.
 */
import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { exchangeBootstrapCode, isLocalBrowserAuthMode, refreshCsrfToken } from "@/lib/api";

type Phase = "checking" | "need-code" | "exchanging" | "ready";

interface LocalBrowserAuthGateProps {
  children: ReactNode;
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-background p-6 text-foreground">
      {children}
    </div>
  );
}

export function LocalBrowserAuthGate({ children }: LocalBrowserAuthGateProps) {
  const [phase, setPhase] = useState<Phase>(() =>
    isLocalBrowserAuthMode() ? "checking" : "ready",
  );
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Gated (OAuth/password) mode: the gate middleware already authenticated the
  // document load, so render immediately but prefetch the session-bound CSRF
  // token so the first unsafe request avoids the 403 → refresh → retry hop.
  useEffect(() => {
    if (isLocalBrowserAuthMode()) return;
    if (typeof window !== "undefined" && window.__HERMES_AUTH_REQUIRED__) {
      void refreshCsrfToken();
    }
  }, []);

  useEffect(() => {
    if (!isLocalBrowserAuthMode()) return;
    let cancelled = false;
    void refreshCsrfToken().then((authed) => {
      if (cancelled) return;
      setPhase(authed ? "ready" : "need-code");
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (phase === "ready") return <>{children}</>;

  if (phase === "checking") {
    return (
      <Centered>
        <p className="text-sm text-muted-foreground">Connecting…</p>
      </Centered>
    );
  }

  const submitting = phase === "exchanging";

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = code.trim();
    if (!trimmed) {
      setError("Enter the code shown in your terminal.");
      return;
    }
    setError(null);
    setPhase("exchanging");
    try {
      await exchangeBootstrapCode(trimmed);
      setCode("");
      setPhase("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bootstrap failed");
      setPhase("need-code");
    }
  };

  return (
    <Centered>
      <form
        onSubmit={(e) => void onSubmit(e)}
        className="w-full max-w-sm space-y-4 rounded-lg border border-border bg-card p-6 shadow-sm"
        aria-label="Dashboard bootstrap sign-in"
      >
        <div className="space-y-1">
          <h1 className="text-lg font-semibold">Sign in to Hermes</h1>
          <p className="text-sm text-muted-foreground">
            Enter the one-time code printed in the terminal where you ran{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">hermes dashboard</code>.
          </p>
        </div>
        <input
          type="text"
          inputMode="text"
          autoComplete="one-time-code"
          autoFocus
          spellCheck={false}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="ABCD-EFGH-IJKL-MNOP"
          aria-label="Bootstrap code"
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm tracking-wider outline-none focus-visible:ring-2 focus-visible:ring-ring"
          disabled={submitting}
        />
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground transition-opacity disabled:opacity-60"
        >
          {submitting ? "Signing in…" : "Sign in"}
        </button>
        <p className="text-xs text-muted-foreground">
          The code is single-use and expires shortly. Restart{" "}
          <code className="rounded bg-muted px-1 py-0.5">hermes dashboard</code> to get a new
          one.
        </p>
      </form>
    </Centered>
  );
}

export default LocalBrowserAuthGate;
