/**
 * Probe and install desktop runtime plugins from Git repositories.
 * Pure helpers are exported for unit tests; IPC handlers in main.ts call the
 * async entry points with a resolved git binary.
 */

import { execFile, spawn } from 'node:child_process'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const GITHUB_BROWSER_SEGMENTS = new Set(['tree', 'blob', 'commit'])

export interface ResolvedGitUrl {
  gitUrl: string
  subdir: string | null
}

export interface PluginComponentDetection {
  agent: boolean
  desktop: boolean
  agentName: string | null
  desktopName: string | null
  desktopSourceSubdir: string | null
}

export interface PluginProbeResult {
  ok: boolean
  agent: boolean
  desktop: boolean
  agentName?: string | null
  desktopName?: string | null
  warnings: string[]
  insecure: boolean
  error?: string
}

export interface DesktopPluginInstallResult {
  ok: boolean
  pluginName?: string
  path?: string
  error?: string
  digest?: string
}

export function resolvePluginGitUrl(identifier: string): ResolvedGitUrl {
  const trimmed = identifier.trim()

  if (!trimmed) {
    throw new Error('Plugin identifier is required.')
  }

  if (/^(https?:\/\/|git@|ssh:\/\/|file:\/\/)/.test(trimmed)) {
    if (trimmed.startsWith('https://github.com/')) {
      const rest = trimmed.slice('https://github.com/'.length).split(/[?#]/)[0].replace(/\/+$/, '')
      const parts = rest.split('/').filter(Boolean)

      if (parts.length >= 3 && parts[2] && GITHUB_BROWSER_SEGMENTS.has(parts[2])) {
        const repo = parts[1].replace(/\.git$/, '')
        let subdir: string | null = null

        if (parts[2] === 'tree' && parts.length >= 5) {
          subdir = parts.slice(4).join('/').replace(/\/+$/, '') || null
        }

        return { gitUrl: `https://github.com/${parts[0]}/${repo}.git`, subdir }
      }
    }

    if (trimmed.includes('#')) {
      const hashIdx = trimmed.indexOf('#')
      const gitUrl = trimmed.slice(0, hashIdx)
      const subdir = trimmed.slice(hashIdx + 1).replace(/^\/+|\/+$/g, '') || null

      return { gitUrl, subdir }
    }

    const marker = '.git/'

    if (trimmed.includes(marker)) {
      const idx = trimmed.indexOf(marker)
      const gitUrl = trimmed.slice(0, idx + marker.length - 1)
      const subdir = trimmed.slice(idx + marker.length).replace(/^\/+|\/+$/g, '') || null

      return { gitUrl, subdir }
    }

    return { gitUrl: trimmed, subdir: null }
  }

  const parts = trimmed.split('/').filter(Boolean)

  if (parts.length >= 2) {
    const [owner, repo, ...rest] = parts
    const gitUrl = `https://github.com/${owner}/${repo}.git`
    const subdir = rest.join('/').replace(/\/+$/, '') || null

    return { gitUrl, subdir }
  }

  throw new Error("Invalid plugin identifier. Use a Git URL or 'owner/repo' (optionally with a subdirectory).")
}

export function repoNameFromUrl(url: string): string {
  let name = url.replace(/\/+$/, '')

  if (name.endsWith('.git')) {
    name = name.slice(0, -4)
  }

  name = name.split('/').pop() || name

  if (name.includes(':')) {
    name = name.split(':').pop() || name
    name = name.split('/').pop() || name
  }

  return name
}

/** Stable on-disk folder for a desktop plugin. Never the clone temp dir or a generic `desktop/` folder. */
export function desktopPluginFolderName(gitUrl: string, subdir: string | null): string {
  if (subdir) {
    const last = subdir
      .split(/[/\\]/)
      .filter(part => part && part !== '.' && part !== 'desktop')
      .pop()

    if (last) {
      return last
    }
  }

  return repoNameFromUrl(gitUrl)
}

export function resolveSubdirWithin(cloneRoot: string, subdir: string): string {
  const root = path.resolve(cloneRoot)
  const candidate = path.resolve(root, subdir)

  if (candidate !== root && !candidate.startsWith(root + path.sep)) {
    throw new Error(`Plugin subdirectory '${subdir}' escapes the repository.`)
  }

  return candidate
}

function pathExistsSync(filePath: string): boolean {
  try {
    fs.accessSync(filePath)

    return true
  } catch {
    return false
  }
}

async function pathIsDirectory(filePath: string): Promise<boolean> {
  try {
    const stat = await fsp.stat(filePath)

    return stat.isDirectory()
  } catch {
    return false
  }
}

async function pathIsFile(filePath: string): Promise<boolean> {
  try {
    const stat = await fsp.stat(filePath)

    return stat.isFile()
  } catch {
    return false
  }
}

export function findDesktopEntry(pluginRoot: string): { entryFile: string; sourceSubdir: string } | null {
  const rootPlugin = path.join(pluginRoot, 'plugin.js')

  if (pathExistsSync(rootPlugin)) {
    return { entryFile: rootPlugin, sourceSubdir: '.' }
  }

  const nestedPlugin = path.join(pluginRoot, 'desktop', 'plugin.js')

  if (pathExistsSync(nestedPlugin)) {
    return { entryFile: nestedPlugin, sourceSubdir: 'desktop' }
  }

  return null
}

export async function detectPluginComponents(pluginRoot: string): Promise<PluginComponentDetection> {
  const hasYaml =
    pathExistsSync(path.join(pluginRoot, 'plugin.yaml')) || pathExistsSync(path.join(pluginRoot, 'plugin.yml'))

  const hasInit = pathExistsSync(path.join(pluginRoot, '__init__.py'))
  const hasPortable = pathExistsSync(path.join(pluginRoot, 'plugin.json'))
  const agent = (hasYaml && hasInit) || hasPortable

  const desktopEntry = findDesktopEntry(pluginRoot)
  const desktop = desktopEntry !== null

  let agentName: string | null = null

  if (agent) {
    agentName = path.basename(pluginRoot)

    if (hasYaml) {
      try {
        const yamlPath = pathExistsSync(path.join(pluginRoot, 'plugin.yaml'))
          ? path.join(pluginRoot, 'plugin.yaml')
          : path.join(pluginRoot, 'plugin.yml')

        const text = await fsp.readFile(yamlPath, 'utf8')
        const match = text.match(/^name:\s*['"]?([^'"\n]+)['"]?\s*$/m)

        if (match?.[1]) {
          agentName = match[1].trim()
        }
      } catch {
        // Fall back to directory name.
      }
    } else if (hasPortable) {
      try {
        const raw = await fsp.readFile(path.join(pluginRoot, 'plugin.json'), 'utf8')
        const parsed = JSON.parse(raw) as { name?: string }

        if (parsed.name) {
          agentName = parsed.name
        }
      } catch {
        // Fall back to directory name.
      }
    }
  }

  const desktopName = desktop
    ? desktopEntry!.sourceSubdir === '.'
      ? path.basename(pluginRoot)
      : path.basename(path.dirname(desktopEntry!.entryFile))
    : null

  return {
    agent,
    desktop,
    agentName,
    desktopName,
    desktopSourceSubdir: desktopEntry?.sourceSubdir ?? null
  }
}

function noninteractiveGitEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: 'echo',
    SSH_ASKPASS: 'echo'
  }
}

function runGit(gitBin: string, args: string[], cwd?: string): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(gitBin, args, {
      cwd,
      env: noninteractiveGitEnv(),
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true
    })

    let stderr = ''

    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      reject(new Error('Git clone timed out after 60 seconds.'))
    }, 60_000)

    child.stderr?.on('data', chunk => {
      stderr += String(chunk)
    })

    child.on('error', err => {
      clearTimeout(timer)
      reject(err)
    })

    child.on('close', code => {
      clearTimeout(timer)
      resolve({ code: code ?? 1, stderr })
    })
  })
}

async function cloneToTemp(gitBin: string, gitUrl: string): Promise<string> {
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'hermes-plugin-'))

  try {
    const { code, stderr } = await runGit(gitBin, ['clone', '--depth', '1', gitUrl, tmpRoot])

    if (code !== 0) {
      throw new Error(`Git clone failed:\n${stderr.trim()}`)
    }

    return tmpRoot
  } catch (err) {
    await fsp.rm(tmpRoot, { recursive: true, force: true }).catch(() => undefined)
    throw err
  }
}

async function resolvePluginRoot(cloneRoot: string, subdir: string | null): Promise<string> {
  if (!subdir) {
    return cloneRoot
  }

  const resolved = resolveSubdirWithin(cloneRoot, subdir)

  if (!(await pathIsDirectory(resolved))) {
    throw new Error(`Plugin subdirectory '${subdir}' does not exist in the repository.`)
  }

  return resolved
}

function insecureSchemeWarnings(gitUrl: string): { warnings: string[]; insecure: boolean } {
  if (gitUrl.startsWith('http://') || gitUrl.startsWith('file://')) {
    return {
      warnings: ['This URL uses an insecure or local scheme. Prefer https:// or git@ for production installs.'],
      insecure: true
    }
  }

  return { warnings: [], insecure: false }
}

export async function probePluginRepo(gitBin: string, identifier: string): Promise<PluginProbeResult> {
  try {
    const { gitUrl, subdir } = resolvePluginGitUrl(identifier)
    const { warnings, insecure } = insecureSchemeWarnings(gitUrl)
    const cloneRoot = await cloneToTemp(gitBin, gitUrl)

    try {
      const pluginRoot = await resolvePluginRoot(cloneRoot, subdir)
      const detected = await detectPluginComponents(pluginRoot)
      const repoFallback = repoNameFromUrl(gitUrl)

      if (!detected.agent && !detected.desktop) {
        return {
          ok: false,
          agent: false,
          desktop: false,
          warnings,
          insecure,
          error: 'No agent or desktop plugin artifacts found in this repository.'
        }
      }

      return {
        ok: true,
        agent: detected.agent,
        desktop: detected.desktop,
        agentName: detected.agentName ?? (detected.agent ? repoFallback : null),
        desktopName: detected.desktop ? desktopPluginFolderName(gitUrl, subdir) : null,
        warnings,
        insecure
      }
    } finally {
      await fsp.rm(cloneRoot, { recursive: true, force: true }).catch(() => undefined)
    }
  } catch (err) {
    return {
      ok: false,
      agent: false,
      desktop: false,
      warnings: [],
      insecure: false,
      error: err instanceof Error ? err.message : String(err)
    }
  }
}

async function copyDesktopTree(sourceDir: string, targetDir: string): Promise<void> {
  await fsp.mkdir(path.dirname(targetDir), { recursive: true })
  await fsp.cp(sourceDir, targetDir, { recursive: true, force: true })
}

/**
 * Supply-chain (WP4): desktop plugin install executes remote code. It is
 * disabled by default. The operator opts in through the canonical backend
 * config only — `security.supply_chain.allow_unverified_components` containing
 * the component id (or `"*"`). Lowering `enforce: false` does NOT authorize on
 * its own (scoped-consent rule, item 5): a single global switch must not
 * silently re-enable every mutable installer. There is no environment-variable
 * user interface; `HERMES_HOME` is used only to locate the profile's config
 * file. Fails closed (returns false) on any read/parse doubt.
 */
function extractSupplyChainBlock(text: string): string | null {
  const lines = text.split(/\r?\n/)
  const start = lines.findIndex(l => /^\s*supply_chain\s*:/.test(l))
  if (start < 0) {
    return null
  }
  const indent = lines[start].match(/^(\s*)/)?.[1].length ?? 0
  const out: string[] = []
  for (let j = start + 1; j < lines.length; j++) {
    const line = lines[j]
    if (line.trim() === '') {
      out.push(line)
      continue
    }
    const lineIndent = line.match(/^(\s*)/)?.[1].length ?? 0
    if (lineIndent <= indent) {
      break
    }
    out.push(line)
  }
  return out.join('\n')
}

export function supplyChainAllowsUnverified(component: string, configText: string): boolean {
  const block = extractSupplyChainBlock(configText)
  if (!block) {
    return false
  }
  // `enforce: false` alone must NOT authorize (WP4 item 5): authorization
  // always requires the explicit per-component allow-list (or the "*" sentinel).
  const listMatch = block.match(/allow_unverified_components\s*:\s*(\[[^\]]*\]|(?:\r?\n\s+-\s+[^\r\n]+)+)/i)
  if (!listMatch) {
    return false
  }
  const listText = listMatch[1].toLowerCase()
  const wanted = component.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(^|[\\[,"'\\s-])(${wanted}|\\*)([\\],"'\\s]|$)`).test(listText)
}

function desktopPluginInstallAllowed(): boolean {
  try {
    const home = process.env.HERMES_HOME || path.join(os.homedir(), '.hermes')
    const text = fs.readFileSync(path.join(home, 'config.yaml'), 'utf8')
    return supplyChainAllowsUnverified('plugins', text)
  } catch {
    return false
  }
}

// --- WP4 item 4: exact-ref + expected-digest desktop activation ------------

const _SHA40 = /^[0-9a-f]{40}$/i

/**
 * Deterministic sha256 over a desktop plugin tree (posix rel path + content),
 * order-independent. Mirrors the backend plugin_bundle_digest so a desktop
 * plugin's activated bytes are bound to an exact (ref, digest) identity.
 */
export async function desktopBundleDigest(dir: string): Promise<string> {
  const crypto = await import('node:crypto')
  const entries: string[] = []
  async function walk(cur: string, rel: string): Promise<void> {
    const items = await fsp.readdir(cur, { withFileTypes: true })
    for (const it of items) {
      const relPath = rel ? `${rel}/${it.name}` : it.name
      const parts = relPath.split('/')
      if (parts.includes('.git') || parts.includes('__pycache__') || parts.includes('node_modules')) {
        continue
      }
      const abs = path.join(cur, it.name)
      if (it.isDirectory()) {
        await walk(abs, relPath)
      } else if (it.isFile()) {
        entries.push(relPath)
      }
    }
  }
  await walk(dir, '')
  entries.sort()
  const top = crypto.createHash('sha256')
  for (const rel of entries) {
    top.update(rel, 'utf8')
    top.update(Buffer.from([0]))
    const buf = await fsp.readFile(path.join(dir, ...rel.split('/'))).catch(() => Buffer.from([0]))
    top.update(crypto.createHash('sha256').update(buf).digest())
  }
  return top.digest('hex')
}

export interface DesktopActivationInputs {
  pinnedRef?: string | null
  expectedDigest?: string | null
  computedDigest: string
  breakGlass: boolean
}

/**
 * Decide whether a desktop plugin may activate (WP4 item 4). Two allowed paths:
 *   1. Exact ref (40-hex commit) + an operator-supplied expected whole-bundle
 *      digest that matches the computed digest. Commit alone is NOT sufficient.
 *   2. Explicit break-glass opt-in (labelled unverified). Otherwise: deny.
 */
export function desktopActivationDecision(inputs: DesktopActivationInputs): { allow: boolean; reason: string } {
  const { pinnedRef, expectedDigest, computedDigest, breakGlass } = inputs
  if (pinnedRef && expectedDigest) {
    if (!_SHA40.test(pinnedRef)) {
      return { allow: false, reason: `pinned ref ${pinnedRef} is not a 40-char commit SHA` }
    }
    if (expectedDigest.toLowerCase() !== computedDigest.toLowerCase()) {
      return {
        allow: false,
        reason: `whole-bundle digest mismatch (expected ${expectedDigest.slice(0, 12)}…, got ${computedDigest.slice(0, 12)}…)`
      }
    }
    return { allow: true, reason: 'exact ref + expected digest verified' }
  }
  if (breakGlass) {
    return { allow: true, reason: 'explicit break-glass opt-in (unverified)' }
  }
  return {
    allow: false,
    reason:
      'desktop plugin install is disabled by default: provide an exact commit ref + expected ' +
      'whole-bundle digest, or opt in explicitly (security.supply_chain.' +
      'allow_unverified_components: ["plugins"]).'
  }
}

export interface DesktopPluginInstallOpts {
  pinnedRef?: string | null
  expectedDigest?: string | null
}

interface AtomicSwapArgs {
  stageDir: string
  targetDir: string
  backupDir: string
  hadExisting: boolean
  rename: (from: string, to: string) => Promise<void>
  rm: (p: string) => Promise<void>
}

/**
 * Atomic publish-with-rollback (WP4 item 2/4). Moves any existing install aside
 * to a backup, then renames the staged tree into place. On ANY failure the
 * previous install is restored from the backup — a force reinstall can never
 * lose the old working plugin, and a partial tree is never observable.
 * fs ops are injected so the rollback is unit-testable with a forced failure.
 */
export async function atomicSwapWithRollback(
  args: AtomicSwapArgs
): Promise<{ ok: boolean; movedAside: boolean; error?: string }> {
  const { stageDir, targetDir, backupDir, hadExisting, rename, rm } = args
  let movedAside = false
  try {
    if (hadExisting) {
      await rename(targetDir, backupDir)
      movedAside = true
    }
    await rename(stageDir, targetDir)
    return { ok: true, movedAside }
  } catch (err) {
    await rm(targetDir).catch(() => undefined)
    if (movedAside) {
      await rename(backupDir, targetDir).catch(() => undefined)
    }
    await rm(stageDir).catch(() => undefined)
    return { ok: false, movedAside: false, error: err instanceof Error ? err.message : String(err) }
  }
}

export async function installDesktopPluginFromGit(
  gitBin: string,
  identifier: string,
  desktopPluginsRoot: string,
  force = false,
  opts: DesktopPluginInstallOpts = {}
): Promise<DesktopPluginInstallResult> {
  try {
    const pinnedRef = opts.pinnedRef ?? null
    const expectedDigest = opts.expectedDigest ?? null
    const breakGlass = desktopPluginInstallAllowed()
    const hasPinnedPath = Boolean(pinnedRef && expectedDigest)
    // Supply-chain gate (WP4): remote code activation is disabled by default.
    // Proceed to clone only when a verified path is possible: an exact ref +
    // expected digest, or an explicit break-glass opt-in. Otherwise fail closed
    // before any network fetch.
    if (!breakGlass && !hasPinnedPath) {
      return {
        ok: false,
        error:
          'Desktop plugin install is disabled by default (supply-chain enforce): it runs ' +
          'remote code from a mutable source without a reviewed pinned identity. Provide an ' +
          'exact commit ref + expected whole-bundle digest, or allow it in the backend config ' +
          'security.supply_chain.allow_unverified_components: ["plugins"]. ' +
          'See docs/security/supply-chain-migration.md.'
      }
    }
    const { gitUrl, subdir } = resolvePluginGitUrl(identifier)
    const cloneRoot = await cloneToTemp(gitBin, gitUrl)
    // Check out the exact pinned commit so the computed digest reflects that
    // ref (a drifted HEAD then simply mismatches the expected digest and fails
    // closed). Best-effort fetch for the shallow clone.
    if (pinnedRef && _SHA40.test(pinnedRef)) {
      const fetched = await runGit(gitBin, ['-C', cloneRoot, 'fetch', '--depth', '1', 'origin', pinnedRef])
      if (fetched.code === 0) {
        await runGit(gitBin, ['-C', cloneRoot, 'checkout', '--force', pinnedRef])
      } else {
        await runGit(gitBin, ['-C', cloneRoot, 'checkout', '--force', pinnedRef])
      }
    }

    try {
      const pluginRoot = await resolvePluginRoot(cloneRoot, subdir)
      const detected = await detectPluginComponents(pluginRoot)

      if (!detected.desktop || !detected.desktopSourceSubdir) {
        return { ok: false, error: 'No desktop plugin.js found in this repository.' }
      }

      const sourceDir =
        detected.desktopSourceSubdir === '.' ? pluginRoot : path.join(pluginRoot, detected.desktopSourceSubdir)

      // Supply-chain (WP4 item 4): bind activation to an exact identity. Compute
      // the whole-bundle digest of the resolved source and decide BEFORE copying
      // anything into the live plugins tree. A pinned ref + matching expected
      // digest activates without break-glass; otherwise break-glass is required.
      const computedDigest = await desktopBundleDigest(sourceDir)
      const decision = desktopActivationDecision({ pinnedRef, expectedDigest, computedDigest, breakGlass })
      if (!decision.allow) {
        return { ok: false, error: `Refusing to activate desktop plugin: ${decision.reason}` }
      }

      const pluginName = desktopPluginFolderName(gitUrl, subdir)
      const targetDir = path.join(desktopPluginsRoot, pluginName)
      const targetPlugin = path.join(targetDir, 'plugin.js')

      const hadExisting = (await pathIsDirectory(targetDir)) || (await pathIsFile(targetPlugin))
      if (hadExisting && !force) {
        return {
          ok: false,
          error: `Desktop plugin '${pluginName}' already exists. Enable force reinstall to replace it.`
        }
      }

      // Atomic publication with rollback (WP4 item 2/4): stage into a sibling
      // temp dir, verify it, move any existing install ASIDE to a backup, then
      // rename the stage into place. On ANY failure the previous plugin (and its
      // metadata — the whole tree) is restored; a partial copy is never
      // observable as installed and force reinstall never loses the old plugin.
      const stamp = `${process.pid}-${Date.now()}`
      const stageDir = `${targetDir}.installing-${stamp}`
      const backupDir = `${targetDir}.backup-${stamp}`
      await fsp.rm(stageDir, { recursive: true, force: true }).catch(() => undefined)
      await copyDesktopTree(sourceDir, stageDir)
      if (!(await pathIsFile(path.join(stageDir, 'plugin.js')))) {
        await fsp.rm(stageDir, { recursive: true, force: true }).catch(() => undefined)
        return { ok: false, error: `Install staged but plugin.js is missing — previous install untouched.` }
      }

      let movedAside = false
      const swap = await atomicSwapWithRollback({
        stageDir,
        targetDir,
        backupDir,
        hadExisting,
        rename: (a, b) => fsp.rename(a, b),
        rm: (p) => fsp.rm(p, { recursive: true, force: true }).then(() => undefined)
      })
      if (!swap.ok) {
        return {
          ok: false,
          error: `Desktop plugin install failed (${swap.error}); the previous ${pluginName} install was preserved.`
        }
      }
      movedAside = swap.movedAside

      if (!(await pathIsFile(targetPlugin))) {
        // Published tree is broken — restore the backup and fail closed.
        await fsp.rm(targetDir, { recursive: true, force: true }).catch(() => undefined)
        if (movedAside) {
          await fsp.rename(backupDir, targetDir).catch(() => undefined)
        }
        return { ok: false, error: `Install completed but ${targetPlugin} is missing — previous install restored.` }
      }

      // Success: discard the backup.
      if (movedAside) {
        await fsp.rm(backupDir, { recursive: true, force: true }).catch(() => undefined)
      }

      return { ok: true, pluginName, path: targetDir, digest: computedDigest }
    } finally {
      await fsp.rm(cloneRoot, { recursive: true, force: true }).catch(() => undefined)
    }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

/** Resolve git binary via execFile which path on unix; caller passes Windows-resolved path. */
export function runGitVersion(gitBin: string): Promise<boolean> {
  return new Promise(resolve => {
    execFile(gitBin, ['--version'], { windowsHide: true, timeout: 5_000 }, err => {
      resolve(!err)
    })
  })
}
