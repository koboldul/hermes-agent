// rebuild-native.mjs
import { rebuild } from '@electron/rebuild'
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { isMain } from './utils.mjs'
import { supplyChainAllowsUnverified } from './native-payload-verifier.mjs'
import packageJson from '../package.json' with { type: 'json' }
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// Supply-chain (WP4 item 2): @electron/rebuild downloads electron headers and
// compiles node-pty from source — a network native build with no manifest
// identity. Disabled by default; runs ONLY with an explicit config-only
// operator opt-in, never automatically.
function nativeRebuildOptIn() {
  try {
    const home = process.env.HERMES_HOME || join(homedir(), '.hermes')
    return supplyChainAllowsUnverified('electron-native', readFileSync(join(home, 'config.yaml'), 'utf8'))
  } catch {
    return false
  }
}

export async function rebuildNodePty({ arch = process.arch } = {}) {
  if (!nativeRebuildOptIn()) {
    throw new Error(
      '[rebuild-native] refusing the unverified native rebuild: @electron/rebuild fetches ' +
        'electron headers and builds node-pty from source with no manifest identity. Stage a ' +
        'lock-bound prebuild instead, or opt in explicitly ' +
        '(security.supply_chain.allow_unverified_components: ["electron-native"]). ' +
        'See docs/security/supply-chain-migration.md.'
    )
  }
  await rebuild({
    buildPath: projectRoot, // where node_modules lives
    electronVersion: packageJson.devDependencies.electron.replace('^', ''),
    arch,
    onlyModules: ['node-pty'],
    force: true
  })
}

if (isMain(import.meta.url)) {
  const [arch] = process.argv.slice(2)
  await rebuildNodePty({ arch })
}
