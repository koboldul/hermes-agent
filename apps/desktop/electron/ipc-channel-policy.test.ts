import assert from 'node:assert/strict'

import { describe, test } from 'vitest'

import { capabilityForChannel } from './ipc-channel-policy'

describe('capabilityForChannel', () => {
  test('binds each representative channel to its narrow capability', () => {
    const cases: [string, string][] = [
      // shell (every window)
      ['hermes:active-work', 'shell'],
      ['hermes:power-battery:get', 'shell'],
      ['hermes:translucency', 'shell'],
      ['hermes:logs:renderer-error', 'shell'],
      // theme (chat, quick, pet)
      ['hermes:titlebar-theme', 'theme'],
      ['hermes:native-theme', 'theme'],
      // quickentry vs config split under the same prefix
      ['hermes:quick-entry:submit', 'quickentry'],
      ['hermes:quick-entry:dismiss', 'quickentry'],
      ['hermes:quick-entry:settings:get', 'config'],
      ['hermes:quick-entry:settings:set', 'config'],
      // wake
      ['hermes:wake-indicator:get', 'wake'],
      ['hermes:wake-indicator:set', 'wake'],
      // metadata
      ['hermes:fetchLinkTitle', 'metadata'],
      ['hermes:resolveFavicon', 'metadata'],
      // connection
      ['hermes:connection', 'connection'],
      ['hermes:connections:save', 'connection'],
      ['hermes:connection-config:apply', 'connection'],
      ['hermes:cloud:login', 'connection'],
      ['hermes:gateway:ws-url', 'connection'],
      ['hermes:backend:touch', 'connection'],
      ['hermes:profile:set', 'connection'],
      // session
      ['hermes:window:openInstance', 'session'],
      ['hermes:ambient:claim', 'session'],
      // config
      ['hermes:data-url-read-max:set', 'config'],
      ['hermes:setting:defaultProjectDir:set', 'config'],
      ['hermes:keep-awake', 'config'],
      ['hermes:zoom:set-percent', 'config'],
      // update
      ['hermes:updates:apply', 'update'],
      ['hermes:uninstall:run', 'update'],
      ['hermes:bootstrap:repair', 'update'],
      ['hermes:boot-progress:get', 'update'],
      // clipboard
      ['hermes:readClipboard', 'clipboard'],
      ['hermes:writeClipboard', 'clipboard'],
      ['hermes:saveClipboardImage', 'clipboard'],
      // file (logs:renderer-error is shell; logs:reveal is file)
      ['hermes:readFileText', 'file'],
      ['hermes:selectPaths', 'file'],
      ['hermes:ssh-config:hosts', 'file'],
      ['hermes:logs:reveal', 'file'],
      ['hermes:logs:recent', 'file'],
      // plugin
      ['hermes:readPluginSource', 'plugin'],
      // system default
      ['hermes:api', 'system'],
      ['hermes:openExternal', 'system'],
      ['hermes:notify', 'system'],
      ['hermes:requestMicrophoneAccess', 'system'],
      ['hermes:context-menu:copy-image', 'system'],
      // an unknown/future channel fails safe to chat-only `system`
      ['hermes:some-future-channel', 'system']
    ]

    for (const [channel, expected] of cases) {
      assert.equal(capabilityForChannel(channel), expected, channel)
    }
  })
})
