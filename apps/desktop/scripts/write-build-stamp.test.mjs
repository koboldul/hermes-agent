import assert from 'node:assert/strict'
import { test } from 'vitest'

import {
  FALLBACK_BRANCH,
  FALLBACK_COMMIT,
  fromCI,
  fromFallback,
  fromLocalGit,
  isFallbackCommit,
  requireAttestedStamp,
  resolveStamp,
  stampRejectionReason
} from './write-build-stamp.mjs'

test('A10: requireAttestedStamp only when the publish flag is set', () => {
  assert.equal(requireAttestedStamp({}), false)
  assert.equal(requireAttestedStamp({ HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: '0' }), false)
  assert.equal(requireAttestedStamp({ HERMES_DESKTOP_REQUIRE_ATTESTED_STAMP: '1' }), true)
})

test('A10: production rejects missing / all-zero / branch-only / short / dirty stamps', () => {
  // Accepts a real full-SHA clean stamp.
  assert.equal(stampRejectionReason({ commit: 'a'.repeat(40), branch: 'main', dirty: false }), null)
  // Missing commit.
  assert.match(stampRejectionReason({ commit: '' }), /no commit/)
  assert.match(stampRejectionReason(null), /no commit/)
  // All-zero / branch-only unpinned fallback.
  assert.match(
    stampRejectionReason({ commit: FALLBACK_COMMIT, branch: FALLBACK_BRANCH, dirty: false }),
    /placeholder\/all-zero|branch-only/
  )
  // Not a full 40-char SHA.
  assert.match(stampRejectionReason({ commit: 'abc1234', branch: 'main', dirty: false }), /full 40-character/)
  // Dirty tree even with a real SHA.
  assert.match(stampRejectionReason({ commit: 'b'.repeat(40), branch: 'main', dirty: true }), /dirty/)
})

test('fromCI reads GITHUB_SHA / GITHUB_REF_NAME but leaves dirty UNKNOWN (A5)', () => {
  assert.deepEqual(
    fromCI({ GITHUB_SHA: 'a'.repeat(40), GITHUB_REF_NAME: 'release' }),
    { commit: 'a'.repeat(40), branch: 'release', dirty: null, source: 'ci' }
  )
  assert.equal(fromCI({}), null)
})

test('fromLocalGit returns null when git rev-parse fails', () => {
  const stamp = fromLocalGit('/tmp/not-a-repo', () => null)
  assert.equal(stamp, null)
})

test('fromLocalGit reads HEAD + branch + dirty status', () => {
  const calls = []
  const execFn = (cmd) => {
    calls.push(cmd)
    if (cmd === 'git rev-parse HEAD') return 'b'.repeat(40)
    if (cmd === 'git rev-parse --abbrev-ref HEAD') return 'main'
    if (cmd === 'git status --porcelain -uno') return ' M apps/desktop/package.json'
    return null
  }
  assert.deepEqual(fromLocalGit('/repo', execFn), {
    commit: 'b'.repeat(40),
    branch: 'main',
    dirty: true,
    source: 'local'
  })
  assert.ok(calls.includes('git rev-parse HEAD'))
})

test('fromFallback uses the all-zero placeholder commit', () => {
  assert.deepEqual(fromFallback(), {
    commit: FALLBACK_COMMIT,
    branch: FALLBACK_BRANCH,
    dirty: false,
    source: 'fallback'
  })
  assert.equal(isFallbackCommit(FALLBACK_COMMIT), true)
  assert.equal(isFallbackCommit('a'.repeat(40)), false)
})

test('resolveStamp prefers CI over local git over fallback', () => {
  const ci = resolveStamp({
    env: { GITHUB_SHA: 'c'.repeat(40), GITHUB_REF_NAME: 'main' },
    // A5: the clean check DOES run for CI now (git is not skipped). Clean tree.
    execFn: (cmd) => (cmd.startsWith('git status') ? '' : 'x')
  })
  assert.equal(ci.source, 'ci')
  assert.equal(ci.commit, 'c'.repeat(40))
  assert.equal(ci.dirty, false)

  const local = resolveStamp({
    env: {},
    execFn: (cmd) => {
      if (cmd === 'git rev-parse HEAD') return 'd'.repeat(40)
      if (cmd === 'git rev-parse --abbrev-ref HEAD') return 'main'
      if (cmd === 'git status --porcelain -uno') return ''
      return null
    }
  })
  assert.equal(local.source, 'local')
  assert.equal(local.commit, 'd'.repeat(40))
  assert.equal(local.dirty, false)
})

test('A5: resolveStamp on CI with a DIRTY tree stamps dirty:true (never trusts GITHUB_SHA)', () => {
  const stamp = resolveStamp({
    env: { GITHUB_SHA: 'a'.repeat(40), GITHUB_REF_NAME: 'main' },
    execFn: (cmd) => (cmd.startsWith('git status') ? ' M apps/desktop/electron/main.ts' : '')
  })
  assert.equal(stamp.source, 'ci')
  assert.equal(stamp.dirty, true)
})

test('A5: resolveStamp on CI with git UNAVAILABLE fails closed (dirty:true)', () => {
  const stamp = resolveStamp({
    env: { GITHUB_SHA: 'a'.repeat(40), GITHUB_REF_NAME: 'main' },
    execFn: () => null
  })
  // fromCI resolved the commit, but the clean check couldn't run → dirty.
  assert.equal(stamp.commit, 'a'.repeat(40))
  assert.equal(stamp.dirty, true)
})

test('resolveStamp falls back when neither CI nor git is available', () => {
  const stamp = resolveStamp({ env: {}, execFn: () => null })
  assert.deepEqual(stamp, {
    commit: FALLBACK_COMMIT,
    branch: FALLBACK_BRANCH,
    dirty: false,
    source: 'fallback'
  })
})
