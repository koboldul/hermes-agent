// Central privileged-IPC authorization for the Desktop main process.
//
// SECURITY (SEC-AUDIT-003 / SEC-AUDIT-005): every renderer-owned native
// capability (filesystem, git, terminal, HUD/pet windowing, link-title/favicon
// metadata, media capture) must be reachable ONLY from a registered application
// window's TRUSTED MAIN FRAME served from the packaged app origin. Matching a
// `webContents` id alone is insufficient: a remote subframe sharing a trusted
// `webContents`, a stale/destroyed sender, or a guest/preview renderer is NOT
// an app principal.
//
// The decision is a pure function (`authorizeDecision`) so it is exhaustively
// unit-testable; `authorizeSender` binds it to a live Electron IPC event, the
// trusted-window registry, and the configured app origin. Nothing here imports
// electron at runtime — it duck-types the event/webContents/frame so the policy
// runs under the node test project.

// ── Capabilities & window classes ────────────────────────────────────────────

// Narrow capabilities, one per functional area. A channel is bound to exactly
// one (see ipc-channel-policy.ts); a window class is granted only the ones its
// real renderer uses. There is deliberately NO generic "any privileged IPC"
// capability — that would re-authorize the whole surface for a limited window.
export type Capability =
  | 'clipboard'
  | 'config'
  | 'connection'
  | 'file'
  | 'fs'
  | 'git'
  | 'hud'
  | 'media'
  | 'metadata'
  | 'pet'
  | 'plugin'
  | 'quickentry'
  | 'session'
  | 'shell'
  | 'system'
  | 'terminal'
  | 'theme'
  | 'update'
  | 'wake'

/** The window classes that mount the Hermes preload bridge. */
export type WindowKind = 'hud' | 'instance' | 'petOverlay' | 'primary' | 'quickEntry' | 'secondary' | 'wakeIndicator'

// Benign, no-state shell channels EVERY window loads on boot (active-work,
// power, translucency, renderer-error logging). Held by every window class.
const SHELL_CAPABILITIES: readonly Capability[] = ['shell']

// Full chat surfaces (primary, secondary session, full instance, HUD chat) run
// the whole app and legitimately drive every capability.
const CHAT_CAPABILITIES: readonly Capability[] = [
  'shell',
  'theme',
  'quickentry',
  'wake',
  'pet',
  'hud',
  'metadata',
  'fs',
  'git',
  'terminal',
  'media',
  'connection',
  'session',
  'config',
  'update',
  'clipboard',
  'file',
  'plugin',
  'system'
]

const CAPABILITIES_BY_KIND: Record<WindowKind, readonly Capability[]> = {
  primary: CHAT_CAPABILITIES,
  secondary: CHAT_CAPABILITIES,
  instance: CHAT_CAPABILITIES,
  hud: CHAT_CAPABILITIES,
  // Quick-entry is gateway-less: it only forwards its captured text and reads
  // pushed state. It needs its own submit/dismiss + shared shell + theme, and
  // NOTHING else — no connection/session/config/file/clipboard/update/plugin.
  quickEntry: [...SHELL_CAPABILITIES, 'theme', 'quickentry'],
  // The pop-out mascot exchanges pet state/control + shared shell + theme only.
  petOverlay: [...SHELL_CAPABILITIES, 'theme', 'pet'],
  // The ambient wake cue only reads its own state; no theme, no other privilege.
  wakeIndicator: [...SHELL_CAPABILITIES, 'wake']
}

export function capabilitiesForKind(kind: WindowKind): Set<Capability> {
  return new Set(CAPABILITIES_BY_KIND[kind] ?? [])
}

// ── App-origin configuration ─────────────────────────────────────────────────

interface AppOriginConfig {
  /** Exact origins served by the dev server, e.g. http://127.0.0.1:5174. */
  appOrigins: string[]
  /** file:// pathname prefixes under which the packaged renderer is served. */
  appFilePathPrefixes: string[]
}

let originConfig: AppOriginConfig = { appOrigins: [], appFilePathPrefixes: [] }

export function configureIpcAuthz(config: Partial<AppOriginConfig>): void {
  originConfig = {
    appOrigins: config.appOrigins ?? originConfig.appOrigins,
    appFilePathPrefixes: config.appFilePathPrefixes ?? originConfig.appFilePathPrefixes
  }
}

/**
 * True when a frame URL is the packaged/self-hosted application. A cross-origin
 * subframe (an embedded provider, an in-app browsed page) is never app origin,
 * even inside an otherwise-trusted webContents.
 */
export function frameUrlIsAppOrigin(frameUrl: null | string | undefined, config: AppOriginConfig = originConfig): boolean {
  if (!frameUrl) {
    return false
  }

  let url: URL

  try {
    url = new URL(frameUrl)
  } catch {
    return false
  }

  if (url.protocol === 'http:' || url.protocol === 'https:') {
    return config.appOrigins.includes(url.origin)
  }

  if (url.protocol === 'file:') {
    let pathname: string

    try {
      pathname = decodeURIComponent(url.pathname)
    } catch {
      pathname = url.pathname
    }

    return config.appFilePathPrefixes.some(prefix => pathname === prefix || pathname.startsWith(prefix))
  }

  return false
}

// ── Trusted-window registry ──────────────────────────────────────────────────

interface RegisteredWindow {
  kind: WindowKind
  capabilities: Set<Capability>
}

interface WebContentsLike {
  id: number
  isDestroyed?: () => boolean
  once?: (event: 'destroyed', listener: () => void) => void
  mainFrame?: unknown
}

const registry = new Map<number, RegisteredWindow>()

/**
 * Mark a window's webContents as a trusted app principal. Auto-unregisters when
 * the webContents is destroyed so a recycled id can never inherit trust.
 */
export function registerTrustedWindow(webContents: WebContentsLike | null | undefined, kind: WindowKind): void {
  if (!webContents || typeof webContents.id !== 'number') {
    return
  }

  registry.set(webContents.id, { kind, capabilities: capabilitiesForKind(kind) })
  webContents.once?.('destroyed', () => registry.delete(webContents.id))
}

export function unregisterTrustedWindow(webContents: WebContentsLike | null | undefined): void {
  if (webContents && typeof webContents.id === 'number') {
    registry.delete(webContents.id)
  }
}

export function trustedWindow(id: number): RegisteredWindow | undefined {
  return registry.get(id)
}

/** Test/reset helper: clear the registry. */
export function __resetIpcAuthz(): void {
  registry.clear()
  originConfig = { appOrigins: [], appFilePathPrefixes: [] }
}

// ── Decision ─────────────────────────────────────────────────────────────────

export interface AuthzInput {
  registered: boolean
  destroyed: boolean
  hasFrame: boolean
  isMainFrame: boolean
  frameIsAppOrigin: boolean
  hasCapability: boolean
}

export type AuthzReason =
  | 'destroyed'
  | 'no-frame'
  | 'not-main-frame'
  | 'ok'
  | 'unregistered'
  | 'wrong-capability'
  | 'wrong-origin'

export interface AuthzResult {
  ok: boolean
  reason: AuthzReason
}

/** Pure authorization decision. Order is defensive: identity before capability. */
export function authorizeDecision(input: AuthzInput): AuthzResult {
  if (input.destroyed) {
    return { ok: false, reason: 'destroyed' }
  }

  if (!input.registered) {
    return { ok: false, reason: 'unregistered' }
  }

  if (!input.hasFrame) {
    return { ok: false, reason: 'no-frame' }
  }

  if (!input.isMainFrame) {
    return { ok: false, reason: 'not-main-frame' }
  }

  if (!input.frameIsAppOrigin) {
    return { ok: false, reason: 'wrong-origin' }
  }

  if (!input.hasCapability) {
    return { ok: false, reason: 'wrong-capability' }
  }

  return { ok: true, reason: 'ok' }
}

// ── Live-event binding ───────────────────────────────────────────────────────

interface FrameLike {
  parent?: unknown
  url?: string
}

interface IpcEventLike {
  sender?: (WebContentsLike & { mainFrame?: unknown }) | null
  senderFrame?: FrameLike | null
}

function isDestroyed(sender: WebContentsLike | null | undefined): boolean {
  return !sender || (typeof sender.isDestroyed === 'function' && sender.isDestroyed())
}

function isMainFrame(frame: FrameLike | null | undefined, sender: WebContentsLike | null | undefined): boolean {
  // EXACT object identity against the live webContents' current main frame is
  // the only trusted signal. A `parent === null` (or undefined) fallback is
  // forgeable/stale: a subframe object or a detached former-main-frame could
  // report a null parent and be trusted. WebFrameMain identities are stable, so
  // a genuine main-frame message satisfies `senderFrame === sender.mainFrame`;
  // anything else — subframe, forged frame, stale frame after navigation — fails
  // closed here.
  return Boolean(frame && sender && sender.mainFrame && frame === sender.mainFrame)
}

/** Authorize a live IPC event for a capability against the trusted registry. */
export function authorizeSender(event: IpcEventLike | null | undefined, capability: Capability): AuthzResult {
  const sender = event?.sender ?? null
  const frame = event?.senderFrame ?? null
  const reg = sender && typeof sender.id === 'number' ? registry.get(sender.id) : undefined

  return authorizeDecision({
    registered: Boolean(reg),
    destroyed: isDestroyed(sender),
    hasFrame: Boolean(frame),
    isMainFrame: isMainFrame(frame, sender),
    frameIsAppOrigin: frameUrlIsAppOrigin(frame?.url),
    hasCapability: Boolean(reg?.capabilities.has(capability))
  })
}

export class IpcAuthorizationError extends Error {
  constructor(capability: Capability, reason: AuthzReason) {
    super(`Unauthorized IPC (${capability}): ${reason}`)
    this.name = 'IpcAuthorizationError'
  }
}

type InvokeHandler = (event: any, ...args: any[]) => any
type SendHandler = (event: any, ...args: any[]) => void

/** Wrap an `ipcMain.handle` handler so it rejects unauthorized senders. */
export function guardInvoke(capability: Capability, handler: InvokeHandler): InvokeHandler {
  return (event, ...args) => {
    const decision = authorizeSender(event, capability)

    if (!decision.ok) {
      throw new IpcAuthorizationError(capability, decision.reason)
    }

    return handler(event, ...args)
  }
}

/** Wrap an `ipcMain.on` handler so it silently drops unauthorized senders. */
export function guardSend(capability: Capability, handler: SendHandler): SendHandler {
  return (event, ...args) => {
    if (!authorizeSender(event, capability).ok) {
      return
    }

    handler(event, ...args)
  }
}

type SyncHandler = (event: any, ...args: any[]) => any

/**
 * Wrap a synchronous (`event.returnValue`) `ipcMain.on` handler. On an
 * unauthorized sender it returns `safeDefault` rather than the real value, so a
 * subframe/guest/stale sender can never read privileged synchronous state. The
 * wrapped handler MUST return its value (the wrapper assigns `event.returnValue`).
 */
export function guardSync(capability: Capability, handler: SyncHandler, safeDefault: unknown = undefined): SendHandler {
  return (event, ...args) => {
    if (!authorizeSender(event, capability).ok) {
      event.returnValue = safeDefault

      return
    }

    event.returnValue = handler(event, ...args)
  }
}

// ── Permission handlers (media capture) ──────────────────────────────────────

export interface MediaPermissionInput {
  registered: boolean
  hasMediaCapability: boolean
  requestingUrlIsAppOrigin: boolean
  /** Electron's frame-identity signal for the request. Must be exactly true. */
  isMainFrame: boolean
  permission: string
  mediaTypes?: string[]
}

/**
 * Whether a media-capture permission may be granted. Deny-all unless the request
 * comes from a registered app window with the `media` capability, an app origin,
 * AND Electron proves it originates from the MAIN frame. If main-frame identity
 * cannot be proven (`isMainFrame` not strictly true) it fails closed rather than
 * trusting webContents + URL — a same-origin subframe must not capture. Mirrors
 * the identical decision for both the async request handler and the sync check
 * handler so neither platform path is a bypass.
 */
export function mediaPermissionDecision(input: MediaPermissionInput): boolean {
  if (
    !input.registered ||
    !input.hasMediaCapability ||
    !input.requestingUrlIsAppOrigin ||
    input.isMainFrame !== true
  ) {
    return false
  }

  if (input.permission === 'audioCapture' || input.permission === 'videoCapture') {
    return true
  }

  if (input.permission !== 'media') {
    return false
  }

  const mediaTypes = input.mediaTypes

  // Windows often omits mediaTypes for a capture request; don't deny on missing
  // metadata once identity is already established.
  if (!Array.isArray(mediaTypes) || mediaTypes.length === 0) {
    return true
  }

  return mediaTypes.includes('audio') || mediaTypes.includes('video')
}

/**
 * Resolve a media-permission request from a live webContents against the
 * registry. `requestingUrl` is the URL the capture is requested from and
 * `isMainFrame` is Electron's frame-identity signal (from the permission
 * details). Fails closed unless main-frame identity is proven.
 */
export function authorizeMediaPermission(
  webContents: WebContentsLike | null | undefined,
  permission: string,
  options: { requestingUrl?: null | string; mediaTypes?: string[]; isMainFrame?: boolean } = {}
): boolean {
  const reg = webContents && typeof webContents.id === 'number' ? registry.get(webContents.id) : undefined

  return mediaPermissionDecision({
    registered: Boolean(reg),
    hasMediaCapability: Boolean(reg?.capabilities.has('media')),
    requestingUrlIsAppOrigin: frameUrlIsAppOrigin(options.requestingUrl),
    isMainFrame: options.isMainFrame === true,
    permission,
    mediaTypes: options.mediaTypes
  })
}
