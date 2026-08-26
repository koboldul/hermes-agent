// SECURITY (SEC-AUDIT / A4 — Skills XPIA): a postMessage from the embedded Hub
// iframe is a PROPOSAL, never an authorization. This validates that a message is
// a well-formed skill-pick that came from the EXACT embedded hub window at the
// EXACT origin. It authorizes NOTHING — the caller must quarantine the proposal
// and require an explicit trusted-parent-UI confirmation before invoking any
// install RPC (which the server independently re-scans). A message can never be
// converted directly into an activation.

export interface HubSkillProposal {
  identifier: string
  name: string
  source: string
  installCmd: string
}

export interface HubMessageContext {
  /** The exact origin the embedded hub is loaded from. */
  expectedOrigin: string
  /** The exact `iframe.contentWindow` of the embedded hub. A message from any
   *  other window (a sibling iframe, a popup, the top window) is rejected even
   *  if it spoofs the origin string. */
  expectedSource: unknown
}

interface IncomingMessage {
  origin: string
  source: unknown
  data: unknown
}

/**
 * Return a validated skill-pick PROPOSAL, or null when the message is not an
 * exact-window, exact-origin, well-formed `hermes-skill-pick`. Returning a
 * proposal does NOT mean it may be installed — it means it is safe to SHOW the
 * user for explicit confirmation.
 */
export function evaluateHubMessage(event: IncomingMessage, ctx: HubMessageContext): HubSkillProposal | null {
  // Exact origin.
  if (event.origin !== ctx.expectedOrigin) {
    return null
  }

  // Exact source window. Without a live iframe window there is nothing to trust.
  if (!ctx.expectedSource || event.source !== ctx.expectedSource) {
    return null
  }

  const data = event.data as Record<string, unknown> | null

  if (!data || data.type !== 'hermes-skill-pick') {
    return null
  }

  const name = typeof data.name === 'string' ? data.name.trim() : ''

  if (!name) {
    return null
  }

  const identifierRaw = typeof data.identifier === 'string' ? data.identifier.trim() : ''

  return {
    identifier: identifierRaw || name,
    name,
    source: typeof data.source === 'string' ? data.source : '',
    installCmd: typeof data.installCmd === 'string' ? data.installCmd : ''
  }
}
