import assert from 'node:assert/strict'

import { afterEach, describe, test } from 'vitest'

import {
  __resetIpcAuthz,
  configureIpcAuthz,
  IpcAuthorizationError,
  registerTrustedWindow
} from './ipc-authz'
import { createIpcRegistrar, type IpcMainLike } from './ipc-registry'

const DEV = 'http://127.0.0.1:5174'
const FILE_PREFIX = '/opt/hermes/dist/'
const APP_FRAME_URL = 'file:///opt/hermes/dist/index.html?win=secondary#/abc'

function configure() {
  configureIpcAuthz({ appOrigins: [DEV], appFilePathPrefixes: [FILE_PREFIX] })
}

// A fake ipcMain that captures the (guard-wrapped) listener per channel so the
// test can invoke it directly with hostile senders — the same wrapped function
// Electron would call.
function fakeIpcMain() {
  const invoke = new Map<string, (event: any, ...args: any[]) => any>()
  const send = new Map<string, (event: any, ...args: any[]) => void>()

  const ipcMain: IpcMainLike = {
    handle: (channel, listener) => void invoke.set(channel, listener),
    on: (channel, listener) => void send.set(channel, listener)
  }

  return { ipcMain, invoke, send }
}

function fakeWebContents(id: number, { destroyed = false, frameUrl = APP_FRAME_URL } = {}) {
  const wc: any = { id, isDestroyed: () => destroyed, once: () => {} }
  wc.mainFrame = { url: frameUrl }

  return wc
}

// Event whose senderFrame IS the webContents' main frame (exact identity).
function mainFrameEvent(wc: any) {
  return { sender: wc, senderFrame: wc.mainFrame }
}

// A subframe: a distinct frame object whose parent is the main frame.
function subFrameEvent(wc: any, url = 'https://evil.example/') {
  return { sender: wc, senderFrame: { url, parent: wc.mainFrame } }
}

// A forged frame reporting a null parent but NOT identical to mainFrame.
function forgedNullParentEvent(wc: any, url = APP_FRAME_URL) {
  return { sender: wc, senderFrame: { url, parent: null } }
}

afterEach(() => {
  __resetIpcAuthz()
})

describe('IPC registrar — classification recording', () => {
  test('records the capability for guarded channels and null for public ones', () => {
    const { ipcMain } = fakeIpcMain()
    const reg = createIpcRegistrar(ipcMain)

    reg.handle('hermes:fs:readDir', 'fs', () => 'ok')
    reg.on('hermes:keep-awake', 'config', () => {})
    reg.sync('hermes:privileged:sync', 'config', () => 'secret', 'safe')
    reg.publicHandle('hermes:public:handle', () => 'pub')
    reg.publicOn('hermes:public:on', () => {})
    reg.publicSync('hermes:translucency:support', event => {
      event.returnValue = { glass: true }
    })

    assert.deepEqual(reg.registrations(), [
      { channel: 'hermes:fs:readDir', kind: 'handle', capability: 'fs' },
      { channel: 'hermes:keep-awake', kind: 'on', capability: 'config' },
      { channel: 'hermes:privileged:sync', kind: 'sync', capability: 'config' },
      { channel: 'hermes:public:handle', kind: 'handle', capability: null },
      { channel: 'hermes:public:on', kind: 'on', capability: null },
      { channel: 'hermes:translucency:support', kind: 'sync', capability: null }
    ])
  })
})

describe('IPC registrar — every guarded handler rejects hostile senders', () => {
  // Register one channel of each kind/capability, then drive the captured wrapped
  // listener with a valid sender and each hostile sender class.
  function harness() {
    configure()
    const { ipcMain, invoke, send } = fakeIpcMain()
    const reg = createIpcRegistrar(ipcMain)

    reg.handle('inv', 'file', (_event, value: string) => `handled:${value}`)
    reg.on('snd', 'file', (_event, sink: string[]) => sink.push('ran'))
    reg.sync('syn', 'file', () => 'REAL', 'SAFE')
    reg.publicHandle('pub', (_event, value: string) => `public:${value}`)

    return { invoke, send }
  }

  test('invoke: returns for a registered main frame, throws for every hostile sender', () => {
    const { invoke } = harness()
    const handler = invoke.get('inv')!

    const chat = fakeWebContents(1)
    registerTrustedWindow(chat, 'primary')
    assert.equal(handler(mainFrameEvent(chat), 'x'), 'handled:x')

    // Same-origin subframe of a trusted webContents.
    assert.throws(() => handler(subFrameEvent(chat, APP_FRAME_URL), 'x'), IpcAuthorizationError)
    // Remote subframe.
    assert.throws(() => handler(subFrameEvent(chat), 'x'), IpcAuthorizationError)
    // Forged main frame (parent null but not the real mainFrame object).
    assert.throws(() => handler(forgedNullParentEvent(chat), 'x'), IpcAuthorizationError)
    // Unregistered guest.
    const guest = fakeWebContents(2)
    assert.throws(() => handler(mainFrameEvent(guest), 'x'), IpcAuthorizationError)
    // Destroyed / stale sender.
    const dead = fakeWebContents(3, { destroyed: true })
    registerTrustedWindow(dead, 'primary')
    assert.throws(() => handler(mainFrameEvent(dead), 'x'), IpcAuthorizationError)
    // Main frame navigated to a non-app origin.
    const drifted = fakeWebContents(4, { frameUrl: 'https://evil.example/' })
    registerTrustedWindow(drifted, 'primary')
    assert.throws(() => handler(mainFrameEvent(drifted), 'x'), IpcAuthorizationError)
  })

  test('send: runs for a registered main frame, drops for hostile senders', () => {
    const { send } = harness()
    const handler = send.get('snd')!

    const chat = fakeWebContents(10)
    registerTrustedWindow(chat, 'primary')
    const sink: string[] = []

    handler(mainFrameEvent(chat), sink)
    handler(subFrameEvent(chat, APP_FRAME_URL), sink) // same-origin subframe dropped
    handler(subFrameEvent(chat), sink)
    handler(forgedNullParentEvent(chat), sink)
    handler(mainFrameEvent(fakeWebContents(11)), sink) // unregistered dropped

    assert.deepEqual(sink, ['ran'])
  })

  test('sync: real value for a registered main frame, safe default for hostile senders', () => {
    const { send } = harness()
    const handler = send.get('syn')!

    const chat = fakeWebContents(20)
    registerTrustedWindow(chat, 'primary')

    const ok: any = { sender: chat, senderFrame: chat.mainFrame, returnValue: undefined }
    handler(ok)
    assert.equal(ok.returnValue, 'REAL')

    for (const hostile of [
      subFrameEvent(chat, APP_FRAME_URL),
      subFrameEvent(chat),
      forgedNullParentEvent(chat),
      mainFrameEvent(fakeWebContents(21))
    ]) {
      const event: any = { ...hostile, returnValue: undefined }
      handler(event)
      assert.equal(event.returnValue, 'SAFE', 'hostile sync sender must get the safe default')
    }
  })

  test('public channels pass through for any sender', () => {
    const { invoke } = harness()
    const handler = invoke.get('pub')!
    const guest = fakeWebContents(30)

    assert.equal(handler(mainFrameEvent(guest), 'y'), 'public:y')
    assert.equal(handler(subFrameEvent(guest), 'z'), 'public:z')
  })
})
