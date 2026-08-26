import assert from 'node:assert/strict'

import { afterEach, describe, test } from 'vitest'

import {
  __resetIpcAuthz,
  authorizeSender,
  type Capability,
  configureIpcAuthz,
  registerTrustedWindow,
  type WindowKind
} from './ipc-authz'
import { capabilityForChannel } from './ipc-channel-policy'

const DEV = 'http://127.0.0.1:5174'
const FILE_PREFIX = '/opt/hermes/dist/'
const APP_FRAME_URL = 'file:///opt/hermes/dist/index.html?win=quick#/'

function configure() {
  configureIpcAuthz({ appOrigins: [DEV], appFilePathPrefixes: [FILE_PREFIX] })
}

function fakeWebContents(id: number) {
  const wc: any = { id, isDestroyed: () => false, once: () => {} }
  wc.mainFrame = { url: APP_FRAME_URL }

  return wc
}

function mainFrameEvent(wc: any) {
  return { sender: wc, senderFrame: wc.mainFrame }
}

// Representative privileged channels a LIMITED window must never reach, one per
// backend/config/update/plugin/clipboard/file/session/system/metadata area.
const BACKEND_CHANNELS = [
  'hermes:api',
  'hermes:connection',
  'hermes:connections:save',
  'hermes:data-url-read-max:set',
  'hermes:updates:apply',
  'hermes:readPluginSource',
  'hermes:writeClipboard',
  'hermes:readFileText',
  'hermes:window:openInstance',
  'hermes:fetchLinkTitle'
] as const

// Sensitive capabilities assigned inside the ipc modules / permission handler.
const MODULE_CAPS: Capability[] = ['fs', 'git', 'terminal', 'media']

afterEach(() => {
  __resetIpcAuthz()
})

function windowFor(kind: WindowKind, id: number) {
  configure()
  const wc = fakeWebContents(id)
  registerTrustedWindow(wc, kind)

  return wc
}

function allow(wc: any, capability: Capability) {
  return authorizeSender(mainFrameEvent(wc), capability).ok
}

function channelAllowed(wc: any, channel: string) {
  return authorizeSender(mainFrameEvent(wc), capabilityForChannel(channel)).ok
}

describe('least privilege — limited windows are denied backend channels', () => {
  for (const kind of ['quickEntry', 'petOverlay', 'wakeIndicator'] as const) {
    test(`${kind} is denied every representative backend/config/update/plugin/clipboard/file/metadata channel`, () => {
      const wc = windowFor(kind, 100)

      for (const channel of BACKEND_CHANNELS) {
        assert.equal(
          authorizeSender(mainFrameEvent(wc), capabilityForChannel(channel)).reason,
          'wrong-capability',
          `${kind} must be denied ${channel}`
        )
      }

      for (const cap of MODULE_CAPS) {
        assert.equal(
          authorizeSender(mainFrameEvent(wc), cap).reason,
          'wrong-capability',
          `${kind} must be denied ${cap}`
        )
      }
    })
  }
})

describe('least privilege — each limited window keeps exactly its required channels', () => {
  test('quick-entry: submit/dismiss + shell + theme work; nothing else', () => {
    const wc = windowFor('quickEntry', 200)

    assert.ok(channelAllowed(wc, 'hermes:quick-entry:submit'))
    assert.ok(channelAllowed(wc, 'hermes:quick-entry:dismiss'))
    assert.ok(channelAllowed(wc, 'hermes:active-work')) // shell
    assert.ok(channelAllowed(wc, 'hermes:power-battery:get')) // shell
    assert.ok(channelAllowed(wc, 'hermes:titlebar-theme')) // theme
    assert.ok(channelAllowed(wc, 'hermes:native-theme')) // theme

    // But its own settings channel (config) is chat-only.
    assert.equal(channelAllowed(wc, 'hermes:quick-entry:settings:set'), false)
    assert.equal(allow(wc, 'pet'), false)
    assert.equal(allow(wc, 'wake'), false)
  })

  test('pet overlay: pet + shell + theme work; nothing else', () => {
    const wc = windowFor('petOverlay', 201)

    assert.ok(allow(wc, 'pet'))
    assert.ok(channelAllowed(wc, 'hermes:active-work')) // shell
    assert.ok(channelAllowed(wc, 'hermes:titlebar-theme')) // theme

    assert.equal(allow(wc, 'quickentry'), false)
    assert.equal(allow(wc, 'wake'), false)
  })

  test('wake indicator: wake + shell work; NOT theme, NOT pet/quickentry', () => {
    const wc = windowFor('wakeIndicator', 202)

    assert.ok(channelAllowed(wc, 'hermes:wake-indicator:get')) // wake
    assert.ok(channelAllowed(wc, 'hermes:active-work')) // shell

    // Wake indicator has no ThemeProvider — theme must be denied too.
    assert.equal(channelAllowed(wc, 'hermes:titlebar-theme'), false)
    assert.equal(allow(wc, 'pet'), false)
    assert.equal(allow(wc, 'quickentry'), false)
  })
})

describe('full chat windows retain the broad set', () => {
  for (const kind of ['primary', 'secondary', 'instance', 'hud'] as const) {
    test(`${kind} is authorized for every backend channel and module capability`, () => {
      const wc = windowFor(kind, 300)

      for (const channel of BACKEND_CHANNELS) {
        assert.ok(channelAllowed(wc, channel), `${kind} should allow ${channel}`)
      }

      for (const cap of MODULE_CAPS) {
        assert.ok(allow(wc, cap), `${kind} should allow ${cap}`)
      }

      // ...and its helper/shell/pet/wake channels too.
      assert.ok(channelAllowed(wc, 'hermes:quick-entry:submit'))
      assert.ok(channelAllowed(wc, 'hermes:wake-indicator:set'))
      assert.ok(allow(wc, 'pet'))
      assert.ok(allow(wc, 'hud'))
    })
  }
})
