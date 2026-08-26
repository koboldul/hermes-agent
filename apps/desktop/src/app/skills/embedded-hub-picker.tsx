import { useStore } from '@nanostores/react'
import { memo, type PointerEvent as ReactPointerEvent, useEffect, useRef, useState } from 'react'

import { Button } from '@/components/ui/button'
import type { ProfileScope, SkillHubProposal } from '@/hermes'
import { useI18n } from '@/i18n'
import { Loader2 } from '@/lib/icons'
import { useStoreSelector } from '@/lib/use-session-slice'
import { cn } from '@/lib/utils'
import { $hubActions, activateHubSkill, proposeHubSkill, UPDATE_ALL_KEY, updateHubSkills } from '@/store/hub-actions'
import { notify, notifyError } from '@/store/notifications'
import { $paneHeightOverride, setPaneHeightOverride } from '@/store/panes'

import { evaluateHubMessage } from './hub-proposal'

// The REAL Skills Hub page (docs site) embedded as a one-click picker — the
// same trick the Bot Mode agent editor uses. `?embed=picker` hides the docs
// chrome and adds a "+ Add to this Agent" button per card, which posts
//   { type: 'hermes-skill-pick', name, identifier, installCmd, source }
// to the parent window. We validate the origin and route the install through
// the standard hub action pipeline (background action + tailed log + Skills
// list invalidation), scoped to the Capabilities profile selector.
const HUB_ORIGIN = 'https://hermes-agent.nousresearch.com'
const HUB_PICKER_URL = `${HUB_ORIGIN}/docs/skills?embed=picker`

// Hub viewport height: persisted through the shared pane store (same one the
// terminal/editor panes use), dragged from the section's TOP edge — "pull the
// hub up" — clamped so neither the hub nor the skills list above vanishes.
const HUB_PANE_ID = 'capabilities-hub'
const HUB_DEFAULT_PX = 380
const HUB_MIN_PX = 120
const HUB_MAX_VH = 0.75
// Collapse threshold, mirroring DetailPane: a persisted height at/below this
// reads as "collapsed to the header" (the toggle stores 0).
const HUB_COLLAPSED_PX = 4
// Room the sash must always leave for the content ABOVE the picker (the
// installed-skills list plus its strip) so dragging the hub up can never
// crush the list to zero and shove its chrome under the hub header.
const HUB_LIST_RESERVED_PX = 176

interface EmbeddedHubPickerProps {
  /** Kept mounted but fully hidden (display:none). The Capabilities view uses
   *  this to preserve the loaded hub iframe across tab switches — a plain
   *  unmount would reload the whole docs site on every return to Skills. */
  hidden?: boolean
  /** Names of skills already installed in the scoped profile — a pick that
   *  matches is refused with a toast instead of re-running the install. */
  installedNames: ReadonlySet<string>
  /** Capabilities profile-scope override — installs land in THIS profile;
   *  undefined/null targets the app-wide active profile. */
  profile?: ProfileScope
}

/** The Skills Hub browser for the Skills tab: a resizable iframe of the live
 *  hub where every card installs with one click. Expanded by default —
 *  discovery IS the point — with a collapse toggle (persisted, like every
 *  other pane) and an update-all action. Memoized: the iframe must not sit in
 *  the parent's keystroke/re-render path. */
export const EmbeddedHubPicker = memo(function EmbeddedHubPicker({
  hidden = false,
  installedNames,
  profile
}: EmbeddedHubPickerProps) {
  const { t } = useI18n()
  const h = t.skills.hub
  // Subscribe to the ONE flag this header renders, not the whole action map —
  // $hubActions churns on every tailed log line during an install.
  const updating = useStoreSelector($hubActions, actions => actions[UPDATE_ALL_KEY]?.running ?? false)
  // Collapse state rides the same persisted height override the sash writes
  // (0 = collapsed to the header), so "Hide the hub browser" survives tab
  // switches and restarts instead of re-expanding — and re-loading the docs
  // site — on every visit. Same contract as DetailPane.
  const heightOverride = useStore($paneHeightOverride(HUB_PANE_ID))
  const height = heightOverride ?? HUB_DEFAULT_PX
  const open = height > HUB_COLLAPSED_PX
  const [dragging, setDragging] = useState(false)
  const sectionRef = useRef<HTMLElement>(null)
  const iframeRef = useRef<HTMLIFrameElement>(null)
  // SECURITY (A4 — Skills XPIA): a message from the embedded hub is a PROPOSAL,
  // never an install. The pick is sent to the server (propose), which
  // quarantines the skill and returns its TRANSPORT-RESOLVED commit + whole-
  // bundle digest. That resolved identity is quarantined here until the user
  // explicitly confirms it in this trusted parent UI; only then does the app
  // call activate with the exact commit+digest, which the server re-verifies
  // against the same quarantined artifact before installing.
  const [pending, setPending] = useState<SkillHubProposal | null>(null)
  // True while a pick is being resolved on the server (propose in flight) or an
  // activation is running — blocks concurrent picks and disables the confirm.
  const [busy, setBusy] = useState(false)

  // Top-edge sash: dragging UP grows the hub (shrinking the skills list above,
  // which is the flex-1 sibling). Same gesture as DetailPane / the shell's
  // bottom panes; double-click resets to the default height. The iframe gets
  // pointer-events disabled for the duration or it swallows the pointermoves.
  const startDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) {
      return
    }

    event.preventDefault()
    const startY = event.clientY
    const startHeight = height
    // Clamp against the actual Capabilities column, not just the window: the
    // hub may never grow past "column minus the list's reserved strip", so
    // the installed list always keeps real height and its header/footer can't
    // end up sharing pixels with the hub header.
    const column = sectionRef.current?.parentElement
    const columnMax = column ? column.clientHeight - HUB_LIST_RESERVED_PX : Number.POSITIVE_INFINITY
    const max = Math.max(HUB_MIN_PX, Math.round(Math.min(window.innerHeight * HUB_MAX_VH, columnMax)))
    setDragging(true)

    const onMove = (move: globalThis.PointerEvent) => {
      setPaneHeightOverride(
        HUB_PANE_ID,
        Math.round(Math.min(max, Math.max(HUB_MIN_PX, startHeight + (startY - move.clientY))))
      )
    }

    const onUp = () => {
      window.removeEventListener('pointermove', onMove)
      setDragging(false)
    }

    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp, { once: true })
  }

  // Picker messages from the embedded hub page. Validated for EXACT origin AND
  // EXACT source window (the hub iframe), then resolved on the SERVER into a
  // pinned identity (propose) and QUARANTINED into `pending`. A message can
  // never trigger an install directly (A4). The user confirms the resolved
  // commit+digest in the dialog below, which calls activate.
  useEffect(() => {
    if (!open) {
      return undefined
    }

    const onMessage = (event: MessageEvent) => {
      const proposal = evaluateHubMessage(
        { origin: event.origin, source: event.source, data: event.data },
        { expectedOrigin: HUB_ORIGIN, expectedSource: iframeRef.current?.contentWindow ?? null }
      )

      if (!proposal) {
        return
      }

      // Already installed in this scope → tell the user, don't propose again.
      if (installedNames.has(proposal.name) || installedNames.has(proposal.identifier)) {
        notify({ kind: 'success', title: h.alreadyInstalled(proposal.name), message: '' })

        return
      }

      // One proposal at a time: ignore further picks while resolving/confirming.
      // `busy`/`pending` are in the effect deps so this closure reads fresh.
      if (busy || pending) {
        return
      }

      // Resolve the pinned identity on the server (fetch + scan + quarantine).
      // NO install happens here — the response is only shown for confirmation.
      setBusy(true)
      void proposeHubSkill(proposal.identifier, profile)
        .then(resolved => setPending(resolved))
        .catch(err => {
          notifyError(err, h.actionFailed)
        })
        .finally(() => setBusy(false))
    }

    window.addEventListener('message', onMessage)

    return () => window.removeEventListener('message', onMessage)
  }, [busy, h, installedNames, open, pending, profile])

  const confirmPending = () => {
    if (!pending || busy) {
      return
    }

    const proposal = pending
    setBusy(true)
    notify({ kind: 'success', title: h.installStarted(proposal.name), message: h.actionLog })
    void activateHubSkill(proposal, profile)
      .catch(err => notifyError(err, h.actionFailed))
      .finally(() => {
        // Close the dialog either way: on success it is installed; on any
        // failure the server-side proposal is consumed, so a retry must re-pick.
        setBusy(false)
        setPending(null)
      })
  }

  const cancelPending = () => {
    setBusy(false)
    setPending(null)
  }

  const updateAll = () => {
    notify({ kind: 'success', title: h.updateStarted, message: h.actionLog })
    void updateHubSkills(profile).catch(err => notifyError(err, h.actionFailed))
  }

  return (
    <section
      className={cn(
        // Shrinkable (no shrink-0) + overflow-hidden: the picker is a flex
        // child of the Capabilities column. Before, its fixed-height viewport
        // made the section's min-content height rigid, so a short window (or a
        // tall persisted drag height) starved the installed list to 0px and
        // the list's strip/footer painted straight over this header. Now the
        // section clips its own content and gives height back to the list;
        // min-h keeps the header row itself always visible.
        'relative flex min-h-9 flex-col overflow-hidden border-t border-(--ui-stroke-secondary)',
        hidden && 'hidden'
      )}
      ref={sectionRef}
    >
      {/* Top-edge drag sash — pull the whole hub section up/down. */}
      <div
        className="group/hubsash absolute inset-x-0 top-0 z-10 h-1 -translate-y-1/2 cursor-row-resize"
        onDoubleClick={() => setPaneHeightOverride(HUB_PANE_ID, undefined)}
        onPointerDown={startDrag}
      >
        <div
          className={cn(
            'absolute inset-x-0 top-1/2 h-px -translate-y-1/2 transition-colors',
            dragging ? 'bg-(--ui-stroke-secondary)' : 'group-hover/hubsash:bg-(--ui-stroke-secondary)'
          )}
        />
      </div>
      <div className="flex shrink-0 items-center justify-between px-3 py-1.5">
        <span className="text-[0.7rem] font-medium text-(--ui-text-tertiary)">{h.pickerTitle}</span>
        <div className="flex items-center gap-1">
          <Button disabled={updating} onClick={updateAll} size="xs" variant="text">
            {updating && <Loader2 className="size-3 animate-spin" />}
            {updating ? h.updating : h.updateAll}
          </Button>
          <Button onClick={() => setPaneHeightOverride(HUB_PANE_ID, open ? 0 : undefined)} size="xs" variant="text">
            {open ? h.pickerHide : h.pickerBrowse}
          </Button>
        </div>
      </div>
      {open && (
        <div className="flex min-h-0 flex-col gap-1 px-3 pb-2">
          {/* Resizable viewport: height comes from the top-edge drag sash
              above (persisted; double-click resets). flex-basis instead of a
              hard height so a short window shrinks the hub viewport rather
              than letting it spill over the list. The iframe is rendered
              oversized and scaled DOWN (133% × 0.75) so the hub page starts
              zoomed out — the cross-origin page itself can't be styled, but
              scaling the frame is ours. */}
          <div
            style={{
              border: '1px solid var(--ui-stroke-secondary)',
              borderRadius: 8,
              flex: `0 1 ${height}px`,
              maxWidth: '100%',
              minHeight: 0,
              minWidth: 320,
              overflow: 'hidden',
              position: 'relative',
              width: '100%'
            }}
          >
            <iframe
              ref={iframeRef}
              sandbox="allow-scripts allow-same-origin"
              src={HUB_PICKER_URL}
              style={{
                background: 'transparent',
                border: 'none',
                height: '133.34%',
                // While the sash drags, the cross-origin iframe must not eat
                // the pointermove stream.
                pointerEvents: dragging ? 'none' : 'auto',
                transform: 'scale(0.75)',
                transformOrigin: 'top left',
                width: '133.34%'
              }}
              title={h.pickerTitle}
            />
          </div>
          <p className="shrink-0 px-1 text-[0.65rem] leading-4 text-(--ui-text-quaternary)">{h.pickerHint}</p>
        </div>
      )}

      {/* A4 — while a pick is being resolved on the server (fetch + scan +
          quarantine), show a blocking spinner. No install can happen until the
          resolved identity is confirmed below. */}
      {busy && !pending && (
        <div
          className="absolute inset-0 z-20 flex items-center justify-center bg-(--ui-bg-primary)/80 p-4 backdrop-blur-sm"
          data-testid="hub-resolving"
        >
          <div className="flex items-center gap-2 text-[0.75rem] text-(--ui-text-tertiary)">
            <Loader2 className="size-3 animate-spin" />
            {h.confirmResolving}
          </div>
        </div>
      )}

      {/* A4 — trusted parent-UI confirmation. A hub message is a proposal; it is
          activated ONLY after the user confirms it here. Rendered by the parent
          app (never the iframe), so a compromised hub page cannot fabricate or
          auto-dismiss it. */}
      {pending && (
        <div
          aria-modal="true"
          className="absolute inset-0 z-20 flex items-center justify-center bg-(--ui-bg-primary)/80 p-4 backdrop-blur-sm"
          data-testid="hub-install-confirm"
          role="dialog"
        >
          <div className="w-full max-w-sm rounded-lg border border-(--ui-stroke-secondary) bg-(--ui-bg-elevated) p-4 shadow-xl">
            <p className="text-sm font-medium text-(--ui-text-primary)">{h.confirmTitle(pending.name)}</p>
            <p className="mt-2 text-[0.75rem] leading-5 text-(--ui-text-tertiary)">{h.confirmDetail}</p>
            <p className="mt-2 truncate font-mono text-[0.7rem] text-(--ui-text-quaternary)" title={pending.identifier}>
              {pending.identifier}
            </p>
            {pending.source && (
              <p className="mt-0.5 text-[0.7rem] text-(--ui-text-quaternary)">{h.confirmSource(pending.source)}</p>
            )}
            {/* Server-resolved identity the user is actually authorizing. The
                commit is the TRANSPORT-resolved 40-hex (or a warning when the
                source is network/mutable); the digest is the whole-bundle hash
                the server re-verifies on activate. */}
            <div className="mt-3 space-y-1 rounded-md border border-(--ui-stroke-secondary) bg-(--ui-bg-primary) p-2">
              {pending.commit ? (
                <p className="truncate font-mono text-[0.7rem] text-(--ui-text-tertiary)" title={pending.commit}>
                  <span className="text-(--ui-text-quaternary)">{h.confirmCommitLabel}: </span>
                  {pending.commit}
                </p>
              ) : (
                <p className="text-[0.7rem] text-(--ui-text-quaternary)">{h.confirmUnverifiedCommit}</p>
              )}
              <p
                className="truncate font-mono text-[0.7rem] text-(--ui-text-tertiary)"
                data-testid="hub-confirm-digest"
                title={pending.digest}
              >
                <span className="text-(--ui-text-quaternary)">{h.confirmDigestLabel}: </span>
                {pending.digest}
              </p>
            </div>
            <div className="mt-3 flex justify-end gap-2">
              <Button disabled={busy} onClick={cancelPending} size="xs" variant="text">
                {h.confirmCancel}
              </Button>
              <Button disabled={busy} onClick={confirmPending} size="xs" variant="default">
                {busy && <Loader2 className="size-3 animate-spin" />}
                {h.confirmInstall}
              </Button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
})
