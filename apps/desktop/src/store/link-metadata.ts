import { Codecs, persistentAtom } from '@/lib/persisted'

// SECURITY (SEC-AUDIT-003): rendering a link or a site icon must make NO network
// request by default. Fetching a page <title> or a remote favicon discloses the
// user's public IP, timing, and a Desktop-specific User-Agent to whatever server
// the URL points at — merely because untrusted text was rendered. So automatic
// resolution is OFF by default; the user may opt in here (a documented privacy
// tradeoff). Even when on, the main process validates and pins every destination
// (electron/link-title-policy.ts), so it can never reach a private/loopback/
// metadata address.
const KEY = 'hermes.desktop.resolve-link-metadata'

export const $resolveLinkMetadata = persistentAtom<boolean>(KEY, false, Codecs.bool)

export function setResolveLinkMetadata(value: boolean): void {
  $resolveLinkMetadata.set(value)
}
