// Central IPC registrar. Every renderer-to-main channel is registered through
// this so its authorization class is explicit and audited in one place:
//   - a `Capability` → the channel is guarded (registered app-window MAIN frame
//     at the packaged app origin; subframe/guest/stale/destroyed senders are
//     rejected via electron/ipc-authz);
//   - `public*`      → the channel is a safe, no-privilege, no-state OS/WM probe
//     that must answer before the frame has committed the app URL (the preload's
//     synchronous bootstrap). These are the ONLY unguarded channels.
//
// The registrar records every registration so a behavior test can drive each
// guarded handler with hostile senders and prove rejection without reading source.

import { type Capability, guardInvoke, guardSend, guardSync } from './ipc-authz'

export interface IpcMainLike {
  handle: (channel: string, listener: (event: any, ...args: any[]) => any) => void
  on: (channel: string, listener: (event: any, ...args: any[]) => void) => void
}

export type IpcRegistrationKind = 'handle' | 'on' | 'sync'

export interface IpcRegistration {
  channel: string
  kind: IpcRegistrationKind
  /** The required capability, or null when the channel is explicitly public. */
  capability: Capability | null
}

export interface IpcRegistrar {
  /** Guarded `ipcMain.handle` (invoke). Rejects unauthorized senders. */
  handle: (channel: string, capability: Capability, handler: (event: any, ...args: any[]) => any) => void
  /** Guarded `ipcMain.on` (fire-and-forget). Drops unauthorized senders. */
  on: (channel: string, capability: Capability, handler: (event: any, ...args: any[]) => void) => void
  /** Guarded synchronous `ipcMain.on` (`event.returnValue`). Returns `safeDefault`
   *  to unauthorized senders. The handler MUST return its value. */
  sync: (
    channel: string,
    capability: Capability,
    handler: (event: any, ...args: any[]) => any,
    safeDefault?: unknown
  ) => void
  /** Explicitly-public, unguarded invoke channel. */
  publicHandle: (channel: string, handler: (event: any, ...args: any[]) => any) => void
  /** Explicitly-public, unguarded fire-and-forget channel. */
  publicOn: (channel: string, handler: (event: any, ...args: any[]) => void) => void
  /** Explicitly-public, unguarded synchronous channel (handler sets returnValue). */
  publicSync: (channel: string, handler: (event: any, ...args: any[]) => void) => void
  /** Every registration made through this registrar, for auditing/testing. */
  registrations: () => IpcRegistration[]
}

export function createIpcRegistrar(ipcMain: IpcMainLike): IpcRegistrar {
  const records: IpcRegistration[] = []

  return {
    handle(channel, capability, handler) {
      records.push({ channel, kind: 'handle', capability })
      ipcMain.handle(channel, guardInvoke(capability, handler))
    },
    on(channel, capability, handler) {
      records.push({ channel, kind: 'on', capability })
      ipcMain.on(channel, guardSend(capability, handler))
    },
    sync(channel, capability, handler, safeDefault) {
      records.push({ channel, kind: 'sync', capability })
      ipcMain.on(channel, guardSync(capability, handler, safeDefault))
    },
    publicHandle(channel, handler) {
      records.push({ channel, kind: 'handle', capability: null })
      ipcMain.handle(channel, handler)
    },
    publicOn(channel, handler) {
      records.push({ channel, kind: 'on', capability: null })
      ipcMain.on(channel, handler)
    },
    publicSync(channel, handler) {
      records.push({ channel, kind: 'sync', capability: null })
      ipcMain.on(channel, handler)
    },
    registrations: () => records.slice()
  }
}
