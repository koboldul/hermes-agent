// Channel → capability classification for the generic `main.ts` IPC surface.
//
// SECURITY (SEC-AUDIT-005): this is where each renderer-to-main channel is bound
// to the NARROWEST capability its real caller needs, so a limited helper window
// (quick-entry, pet overlay, wake indicator) is authorized for only the handful
// of channels its minimal renderer actually invokes — and denied backend,
// config, update, plugin, clipboard, file, fs, git, terminal, metadata and
// media operations. Full chat windows hold every capability.
//
// Determined by tracing the actual renderer surfaces:
//   - quick-entry-app  → quick-entry submit/dismiss + shared shell + theme
//   - pet-overlay-app  → pet-overlay:* (module) + shared shell + theme
//   - wake-indicator   → wake-indicator:get + shared shell (no theme)
//   - shared side effects loaded in EVERY window (main.tsx):
//       store/active-work → active-work, store/power → power-battery:get,
//       store/translucency → translucency, error-boundary → logs:renderer-error
//
// The default is the chat-only `system` capability, so a channel that is added
// later without a rule fails SAFE (chat-only) rather than leaking to a helper.

import type { Capability } from './ipc-authz'

interface Rule {
  match: (channel: string) => boolean
  capability: Capability
}

const exact = (channel: string, capability: Capability): Rule => ({
  match: c => c === channel,
  capability
})

const prefix = (channelPrefix: string, capability: Capability): Rule => ({
  match: c => c.startsWith(channelPrefix),
  capability
})

// Ordered: the first matching rule wins, so specific exacts precede broad prefixes.
const RULES: Rule[] = [
  // ── shell: benign, no-state shell channels EVERY window loads on boot ──
  exact('hermes:active-work', 'shell'),
  exact('hermes:power-battery:get', 'shell'),
  exact('hermes:translucency', 'shell'),
  exact('hermes:logs:renderer-error', 'shell'),

  // ── theme: window chrome/appearance (ThemeProvider — chat, quick, pet) ──
  exact('hermes:titlebar-theme', 'theme'),
  exact('hermes:native-theme', 'theme'),

  // ── quickentry: the quick-entry capture window's only privileged verbs ──
  exact('hermes:quick-entry:submit', 'quickentry'),
  exact('hermes:quick-entry:dismiss', 'quickentry'),

  // ── wake: the ambient wake indicator's read + the chat writer ──
  prefix('hermes:wake-indicator:', 'wake'),

  // ── metadata: link-title / favicon SSRF path (also gated in main.ts) ──
  exact('hermes:fetchLinkTitle', 'metadata'),
  exact('hermes:resolveFavicon', 'metadata'),

  // ── connection / gateway / profile / cloud resolution (chat) ──
  prefix('hermes:connection-config:', 'connection'),
  prefix('hermes:connections:', 'connection'),
  prefix('hermes:connection', 'connection'),
  prefix('hermes:cloud:', 'connection'),
  prefix('hermes:gateway:', 'connection'),
  exact('hermes:backend:touch', 'connection'),
  exact('hermes:agents:roster', 'connection'),
  exact('hermes:plugin-profile-routes', 'connection'),
  prefix('hermes:profile:', 'connection'),
  exact('hermes:get-remote-display-reason', 'connection'),

  // ── session / window management (chat) ──
  prefix('hermes:window:', 'session'),
  exact('hermes:ambient:claim', 'session'),

  // ── config / settings mutation (chat) ──
  prefix('hermes:data-url-read-max:', 'config'),
  prefix('hermes:setting:', 'config'),
  prefix('hermes:secret-storage:', 'config'),
  prefix('hermes:quick-entry:settings:', 'config'),
  exact('hermes:devtools:disable-f12', 'config'),
  exact('hermes:keep-awake', 'config'),
  prefix('hermes:zoom:', 'config'),
  exact('hermes:previewShortcutActive', 'config'),

  // ── update / bootstrap / uninstall (chat) ──
  prefix('hermes:updates:', 'update'),
  prefix('hermes:uninstall:', 'update'),
  prefix('hermes:bootstrap:', 'update'),
  prefix('hermes:boot-progress:', 'update'),

  // ── clipboard (chat) ──
  exact('hermes:readClipboard', 'clipboard'),
  exact('hermes:writeClipboard', 'clipboard'),
  exact('hermes:saveClipboardImage', 'clipboard'),

  // ── filesystem read/save/select/watch (chat) ──
  exact('hermes:readFileText', 'file'),
  exact('hermes:readFileDataUrl', 'file'),
  exact('hermes:readFileDataUrlForAttach', 'file'),
  exact('hermes:saveGatewayFile', 'file'),
  exact('hermes:saveImageBuffer', 'file'),
  exact('hermes:saveImageFromUrl', 'file'),
  exact('hermes:selectPaths', 'file'),
  exact('hermes:selectSavePath', 'file'),
  exact('hermes:watchDirectory', 'file'),
  exact('hermes:watchPreviewFile', 'file'),
  exact('hermes:stopPreviewFileWatch', 'file'),
  exact('hermes:workspace:sanitize', 'file'),
  prefix('hermes:ssh-config:', 'file'),
  prefix('hermes:logs:', 'file'),

  // ── plugin source (chat) ──
  exact('hermes:readPluginSource', 'plugin')
  // Everything else falls through to the chat-only `system` default below.
]

/**
 * The narrowest capability that authorizes a generic renderer-to-main channel.
 * Unmatched channels default to the chat-only `system` capability (fail safe).
 */
export function capabilityForChannel(channel: string): Capability {
  for (const rule of RULES) {
    if (rule.match(channel)) {
      return rule.capability
    }
  }

  return 'system'
}
