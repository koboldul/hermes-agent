// Desktop Content-Security-Policy for the privileged application renderer.
//
// SECURITY (SEC-AUDIT-005): the application document owns `window.hermesDesktop`
// (files, terminal, clipboard, gateway). No remotely hosted <script> may ever
// execute there. This module produces and enforces a CSP whose `script-src`
// admits ONLY self-hosted application code plus the local plugin mechanism
// (blob: ES-module loader in src/contrib/runtime-loader.ts), and NEVER a remote
// origin. It intentionally leaves resource-fetching directives (img/connect/
// media/frame/style) unconstrained: the app connects to arbitrary local, remote
// and cloud gateways and renders cross-origin media/embeds, and clamping those
// here would break supported topologies without adding script-execution safety.
//
// The policy is ENFORCING (not Report-Only): a reintroduced remote script is
// blocked outright and surfaces as a renderer console error, which the main
// process already captures into desktop.log — so a regression fails visibly in
// development and CI rather than silently loading.

export interface CspOptions {
  /** Dev server origin (e.g. http://127.0.0.1:5174) when running under Vite. */
  devServer?: null | string
}

function originOf(rawUrl: null | string | undefined): null | string {
  if (!rawUrl) {
    return null
  }

  try {
    return new URL(rawUrl).origin
  } catch {
    return null
  }
}

/**
 * The self-hosted-only `script-src` token list.
 *
 * `'self'`         — the packaged bundle (file://) or the dev server.
 * `blob:`          — the local Desktop-plugin runtime loader imports plugin
 *                    code as a blob: ES module; this is the supported local
 *                    plugin mechanism the policy must retain.
 * `'unsafe-inline'`— the index.html boot script that pre-paints the theme, plus
 *                    Vite's inline module-preload shim. These are self-authored;
 *                    crucially, `'unsafe-inline'` does NOT permit a remote
 *                    `<script src>`, so the SEC-AUDIT-005 property still holds.
 * `'unsafe-eval'`  — defensive: some bundled libraries compile with Function();
 *                    like inline, it cannot load a remote script.
 *
 * NO `http(s):`, wildcard, or provider origin is ever included — that is the
 * whole point.
 */
export function scriptSrcTokens(options: CspOptions = {}): string[] {
  const tokens = ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'blob:']
  const devOrigin = originOf(options.devServer)

  // In dev the module graph is served from the Vite origin. It is usually the
  // document origin too ('self'), but pin it explicitly for setups where the
  // renderer host and asset host differ.
  if (devOrigin && !tokens.includes(devOrigin)) {
    tokens.push(devOrigin)
  }

  return tokens
}

/** The full Content-Security-Policy header value for the app renderer. */
export function desktopContentSecurityPolicy(options: CspOptions = {}): string {
  const directives = [
    `script-src ${scriptSrcTokens(options).join(' ')}`,
    // `<object>`/`<embed>` are a legacy script-execution vector with no use in
    // the app; deny them outright.
    "object-src 'none'",
    // Pin `<base>` so injected markup cannot repoint relative script/asset URLs.
    "base-uri 'self'",
    // The privileged renderer is always a top-level window; it must never be
    // embedded by anyone.
    "frame-ancestors 'none'"
  ]

  return directives.join('; ')
}

/**
 * True when a response URL belongs to the packaged/self-hosted application and
 * must therefore carry the CSP. Cross-origin embed documents (youtube.com,
 * a google-maps frame, an in-app browsed page) are explicitly NOT app origin —
 * clamping their CSP would break them.
 */
export function isAppOriginUrl(rawUrl: null | string | undefined, options: CspOptions = {}): boolean {
  if (!rawUrl) {
    return false
  }

  // Packaged app + its bundled assets load over file://.
  if (/^file:\/\//i.test(rawUrl)) {
    return true
  }

  const devOrigin = originOf(options.devServer)

  return Boolean(devOrigin && originOf(rawUrl) === devOrigin)
}

type HeaderMap = Record<string, string[] | string>

/**
 * Return response headers with exactly one enforcing CSP header set to `policy`,
 * dropping any pre-existing (case-insensitive) CSP/CSP-Report-Only header so the
 * app policy cannot be weakened or duplicated by an upstream one.
 */
export function withCspHeader(existing: HeaderMap | undefined, policy: string): HeaderMap {
  const next: HeaderMap = {}

  for (const [name, value] of Object.entries(existing ?? {})) {
    const lower = name.toLowerCase()

    if (lower === 'content-security-policy' || lower === 'content-security-policy-report-only') {
      continue
    }

    next[name] = value
  }

  next['Content-Security-Policy'] = [policy]

  return next
}

interface OnHeadersReceivedDetails {
  url: string
  responseHeaders?: HeaderMap
}

interface WebRequestLike {
  onHeadersReceived: (
    listener: (details: OnHeadersReceivedDetails, callback: (response: { responseHeaders?: HeaderMap }) => void) => void
  ) => void
}

interface SessionLike {
  webRequest: WebRequestLike
}

/**
 * Wire the enforcing CSP onto a session for app-origin responses only. Idempotent
 * per session in the sense that it installs a single onHeadersReceived listener.
 */
export function applyDesktopCsp(sessionLike: SessionLike, options: CspOptions = {}): void {
  const policy = desktopContentSecurityPolicy(options)

  sessionLike.webRequest.onHeadersReceived((details, callback) => {
    if (!isAppOriginUrl(details.url, options)) {
      callback({ responseHeaders: details.responseHeaders })

      return
    }

    callback({ responseHeaders: withCspHeader(details.responseHeaders, policy) })
  })
}
