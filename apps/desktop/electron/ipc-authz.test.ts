import assert from 'node:assert/strict'

import { afterEach, describe, test } from 'vitest'

import {
  __resetIpcAuthz,
  authorizeDecision,
  authorizeMediaPermission,
  authorizeSender,
  capabilitiesForKind,
  configureIpcAuthz,
  frameUrlIsAppOrigin,
  guardInvoke,
  guardSend,
  IpcAuthorizationError,
  mediaPermissionDecision,
  registerTrustedWindow,
  trustedWindow,
  unregisterTrustedWindow
} from './ipc-authz'

const DEV = 'http://127.0.0.1:5174'
const FILE_PREFIX = '/opt/hermes/dist/'
const APP_FRAME_URL = 'file:///opt/hermes/dist/index.html?win=secondary#/abc'

function configure() {
  configureIpcAuthz({ appOrigins: [DEV], appFilePathPrefixes: [FILE_PREFIX] })
}

// A minimal live webContents. `mainFrame` doubles as the identity object a real
// senderFrame would equal for the top frame.
function fakeWebContents(id: number, { destroyed = false }: { destroyed?: boolean } = {}) {
  const wc: any = {
    id,
    isDestroyed: () => destroyed,
    _destroyListeners: [] as (() => void)[],
    once(event: string, listener: () => void) {
      if (event === 'destroyed') {
        wc._destroyListeners.push(listener)
      }
    },
    destroy() {
      destroyed = true
      wc._destroyListeners.forEach(fn => fn())
    }
  }

  wc.mainFrame = { url: APP_FRAME_URL }

  return wc
}

// senderFrame IS the live main frame (exact identity — the only trusted signal).
function mainFrameEvent(wc: any) {
  return { sender: wc, senderFrame: wc.mainFrame }
}

// A subframe: a distinct frame object whose parent is the main frame.
function subFrameEvent(wc: any, url = 'https://www.instagram.com/embed.js') {
  return { sender: wc, senderFrame: { url, parent: wc.mainFrame } }
}

// A forged frame reporting a null parent but not identical to the live mainFrame.
function forgedNullParentEvent(wc: any, url = APP_FRAME_URL) {
  return { sender: wc, senderFrame: { url, parent: null } }
}

// A frame with an undefined parent, likewise not identical to the live mainFrame.
function undefinedParentEvent(wc: any, url = APP_FRAME_URL) {
  return { sender: wc, senderFrame: { url } }
}

// A frame that WAS the main frame but the webContents now has a different one.
function staleFormerMainFrameEvent(wc: any) {
  const former = wc.mainFrame
  wc.mainFrame = { url: APP_FRAME_URL }

  return { sender: wc, senderFrame: former }
}

afterEach(() => {
  __resetIpcAuthz()
})

describe('authorizeDecision (pure)', () => {
  const base = {
    registered: true,
    destroyed: false,
    hasFrame: true,
    isMainFrame: true,
    frameIsAppOrigin: true,
    hasCapability: true
  }

  test('grants a registered app main frame with the capability', () => {
    assert.deepEqual(authorizeDecision(base), { ok: true, reason: 'ok' })
  })

  test('rejects each failure mode with a specific reason', () => {
    assert.equal(authorizeDecision({ ...base, destroyed: true }).reason, 'destroyed')
    assert.equal(authorizeDecision({ ...base, registered: false }).reason, 'unregistered')
    assert.equal(authorizeDecision({ ...base, hasFrame: false }).reason, 'no-frame')
    assert.equal(authorizeDecision({ ...base, isMainFrame: false }).reason, 'not-main-frame')
    assert.equal(authorizeDecision({ ...base, frameIsAppOrigin: false }).reason, 'wrong-origin')
    assert.equal(authorizeDecision({ ...base, hasCapability: false }).reason, 'wrong-capability')
  })
})

describe('frameUrlIsAppOrigin', () => {
  test('accepts the dev origin and packaged file path, rejects remote/guest', () => {
    configure()

    assert.equal(frameUrlIsAppOrigin(`${DEV}/src/main.tsx`), true)
    assert.equal(frameUrlIsAppOrigin(APP_FRAME_URL), true)
    assert.equal(frameUrlIsAppOrigin('https://www.instagram.com/embed.js'), false)
    assert.equal(frameUrlIsAppOrigin('file:///etc/passwd'), false)
    assert.equal(frameUrlIsAppOrigin(null), false)
    assert.equal(frameUrlIsAppOrigin('not a url'), false)
  })
})

describe('capabilitiesForKind', () => {
  test('chat surfaces hold every capability; helpers are least-privilege', () => {
    for (const kind of ['primary', 'secondary', 'instance', 'hud'] as const) {
      const caps = capabilitiesForKind(kind)

      for (const cap of [
        'metadata',
        'fs',
        'git',
        'terminal',
        'media',
        'connection',
        'config',
        'update',
        'plugin',
        'clipboard',
        'file',
        'system'
      ] as const) {
        assert.ok(caps.has(cap), `chat ${kind} must hold ${cap}`)
      }
    }

    // Limited windows get ONLY the narrow set their real renderer uses.
    assert.deepEqual([...capabilitiesForKind('quickEntry')].sort(), ['quickentry', 'shell', 'theme'])
    assert.deepEqual([...capabilitiesForKind('petOverlay')].sort(), ['pet', 'shell', 'theme'])
    assert.deepEqual([...capabilitiesForKind('wakeIndicator')].sort(), ['shell', 'wake'])

    // No limited window may reach the sensitive/backend verbs.
    for (const kind of ['quickEntry', 'petOverlay', 'wakeIndicator'] as const) {
      const caps = capabilitiesForKind(kind)

      for (const cap of [
        'fs',
        'git',
        'terminal',
        'metadata',
        'media',
        'connection',
        'config',
        'update',
        'plugin',
        'clipboard',
        'file',
        'system'
      ] as const) {
        assert.equal(caps.has(cap), false, `${kind} must NOT hold ${cap}`)
      }
    }
  })
})

describe('registry lifecycle', () => {
  test('registers and auto-unregisters on destroy', () => {
    const wc = fakeWebContents(7)
    registerTrustedWindow(wc, 'primary')
    assert.ok(trustedWindow(7))

    wc.destroy()
    assert.equal(trustedWindow(7), undefined)
  })

  test('explicit unregister removes trust', () => {
    const wc = fakeWebContents(8)
    registerTrustedWindow(wc, 'secondary')
    unregisterTrustedWindow(wc)
    assert.equal(trustedWindow(8), undefined)
  })
})

describe('authorizeSender (live event)', () => {
  test('grants a registered chat main frame at app origin (exact frame identity)', () => {
    configure()
    const wc = fakeWebContents(1)
    registerTrustedWindow(wc, 'primary')

    assert.deepEqual(authorizeSender(mainFrameEvent(wc), 'metadata'), { ok: true, reason: 'ok' })
    assert.deepEqual(authorizeSender(mainFrameEvent(wc), 'fs'), { ok: true, reason: 'ok' })
    assert.deepEqual(authorizeSender(mainFrameEvent(wc), 'connection'), { ok: true, reason: 'ok' })
  })

  test('denies a remote subframe sharing a trusted webContents', () => {
    configure()
    const wc = fakeWebContents(2)
    registerTrustedWindow(wc, 'primary')

    assert.equal(authorizeSender(subFrameEvent(wc), 'fs').reason, 'not-main-frame')
  })

  test('denies a SAME-ORIGIN subframe of a trusted webContents', () => {
    configure()
    const wc = fakeWebContents(2_1)
    registerTrustedWindow(wc, 'primary')

    // Even an app-origin subframe is not an app principal — exact-identity fails.
    assert.equal(authorizeSender(subFrameEvent(wc, APP_FRAME_URL), 'fs').reason, 'not-main-frame')
  })

  test('denies a forged frame reporting parent === null', () => {
    configure()
    const wc = fakeWebContents(2_2)
    registerTrustedWindow(wc, 'primary')

    // A frame object with parent null but not the live mainFrame must fail closed.
    assert.equal(authorizeSender(forgedNullParentEvent(wc), 'fs').reason, 'not-main-frame')
  })

  test('denies a frame with an undefined parent', () => {
    configure()
    const wc = fakeWebContents(2_3)
    registerTrustedWindow(wc, 'primary')

    assert.equal(authorizeSender(undefinedParentEvent(wc), 'fs').reason, 'not-main-frame')
  })

  test('denies a stale former-main-frame after navigation', () => {
    configure()
    const wc = fakeWebContents(2_4)
    registerTrustedWindow(wc, 'primary')

    // The frame that used to be main is no longer sender.mainFrame → denied.
    assert.equal(authorizeSender(staleFormerMainFrameEvent(wc), 'fs').reason, 'not-main-frame')
  })

  test('denies a main frame that navigated to a non-app origin (rebinding/guest)', () => {
    configure()
    const wc = fakeWebContents(3)
    registerTrustedWindow(wc, 'primary')

    // The REAL main frame drifted to a non-app origin: identity passes, origin fails.
    wc.mainFrame.url = 'https://evil.example/'
    assert.equal(authorizeSender(mainFrameEvent(wc), 'fs').reason, 'wrong-origin')
  })

  test('denies an unregistered (guest) webContents', () => {
    configure()
    const wc = fakeWebContents(4)

    assert.equal(authorizeSender(mainFrameEvent(wc), 'fs').reason, 'unregistered')
  })

  test('denies a destroyed sender', () => {
    configure()
    const wc = fakeWebContents(5, { destroyed: true })
    registerTrustedWindow(wc, 'primary')

    assert.equal(authorizeSender(mainFrameEvent(wc), 'fs').reason, 'destroyed')
  })

  test('denies a sensitive capability the window class does not hold', () => {
    configure()
    const wc = fakeWebContents(6)
    registerTrustedWindow(wc, 'quickEntry')

    // Quick-entry holds shell/theme/quickentry but must not touch the sensitive
    // or backend verbs.
    assert.equal(authorizeSender(mainFrameEvent(wc), 'fs').reason, 'wrong-capability')
    assert.equal(authorizeSender(mainFrameEvent(wc), 'metadata').reason, 'wrong-capability')
    assert.equal(authorizeSender(mainFrameEvent(wc), 'connection').reason, 'wrong-capability')
    assert.equal(authorizeSender(mainFrameEvent(wc), 'quickentry').ok, true)
    assert.equal(authorizeSender(mainFrameEvent(wc), 'shell').ok, true)
  })

  test('denies a missing sender frame', () => {
    configure()
    const wc = fakeWebContents(9)
    registerTrustedWindow(wc, 'primary')

    assert.equal(authorizeSender({ sender: wc, senderFrame: null }, 'fs').reason, 'no-frame')
  })
})

describe('guard wrappers', () => {
  test('guardInvoke throws IpcAuthorizationError on deny, runs handler on allow', () => {
    configure()
    const wc = fakeWebContents(10)
    registerTrustedWindow(wc, 'primary')

    const handler = guardInvoke('fs', (_event, value: string) => `ok:${value}`)

    assert.equal(handler(mainFrameEvent(wc), 'x'), 'ok:x')
    assert.throws(() => handler(subFrameEvent(wc), 'x'), IpcAuthorizationError)
  })

  test('guardSend drops unauthorized senders and forwards authorized ones', () => {
    configure()
    const wc = fakeWebContents(11)
    registerTrustedWindow(wc, 'petOverlay')

    const seen: string[] = []
    const handler = guardSend('pet', (_event, value: string) => seen.push(value))

    handler(mainFrameEvent(wc), 'allowed')
    handler(subFrameEvent(wc), 'blocked')

    assert.deepEqual(seen, ['allowed'])
  })
})

describe('media permission authorization', () => {
  const base = {
    registered: true,
    hasMediaCapability: true,
    requestingUrlIsAppOrigin: true,
    isMainFrame: true,
    permission: 'media'
  }

  test('mediaPermissionDecision denies unless registered app + media + main frame', () => {
    assert.equal(mediaPermissionDecision({ ...base, registered: false }), false)
    assert.equal(mediaPermissionDecision({ ...base, hasMediaCapability: false }), false)
    assert.equal(mediaPermissionDecision({ ...base, requestingUrlIsAppOrigin: false }), false)
    // Same-origin subframe: identity not proven → fail closed.
    assert.equal(mediaPermissionDecision({ ...base, isMainFrame: false }), false)
    // Electron did not supply a main-frame signal at all → fail closed.
    assert.equal(mediaPermissionDecision({ ...base, isMainFrame: undefined as unknown as boolean }), false)
    assert.equal(mediaPermissionDecision({ ...base, permission: 'geolocation' }), false)
    assert.equal(mediaPermissionDecision({ ...base, mediaTypes: [] }), true)
  })

  test('authorizeMediaPermission grants a registered chat MAIN frame, denies otherwise', () => {
    configure()
    const chat = fakeWebContents(20)
    registerTrustedWindow(chat, 'primary')
    const guest = fakeWebContents(21)

    assert.equal(authorizeMediaPermission(chat, 'media', { requestingUrl: APP_FRAME_URL, isMainFrame: true }), true)
    // Correct window + origin but Electron reports a non-main frame (subframe).
    assert.equal(authorizeMediaPermission(chat, 'media', { requestingUrl: APP_FRAME_URL, isMainFrame: false }), false)
    // Correct window + origin but no main-frame proof → fail closed.
    assert.equal(authorizeMediaPermission(chat, 'media', { requestingUrl: APP_FRAME_URL }), false)
    assert.equal(
      authorizeMediaPermission(guest, 'media', { requestingUrl: 'https://evil.example', isMainFrame: true }),
      false
    )
    // Registered chat window but request from a remote origin (e.g. an embed).
    assert.equal(
      authorizeMediaPermission(chat, 'media', { requestingUrl: 'https://evil.example', isMainFrame: true }),
      false
    )
  })

  test('the pet overlay (no media capability) is denied capture', () => {
    configure()
    const pet = fakeWebContents(22)
    registerTrustedWindow(pet, 'petOverlay')

    assert.equal(authorizeMediaPermission(pet, 'media', { requestingUrl: APP_FRAME_URL, isMainFrame: true }), false)
  })
})
