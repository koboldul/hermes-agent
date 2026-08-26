// electron-zip.test.mjs — validate the ZIP reader against REAL zip bytes.
//
// Builds an actual .zip on disk with the OS zip writer (PowerShell
// Compress-Archive on Windows, `zip`/`python -m zipfile` elsewhere), then parses
// and extracts it with our dependency-free reader. This proves the reader
// against real-world ZIP output, not against our own writer.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, it } from 'vitest'

import { extractAll, listEntries, readCentralDirectory } from './electron-zip.mjs'

let work
let zipPath
let available = true

function makeZipWindows(dir, out) {
  const res = spawnSync(
    'powershell',
    ['-NoProfile', '-Command', `Compress-Archive -Path '${dir}\\*' -DestinationPath '${out}' -Force`],
    { encoding: 'utf8' }
  )
  return res.status === 0
}

function makeZipPython(dir, out) {
  const py = `import zipfile,os,sys\nroot=sys.argv[1]\nz=zipfile.ZipFile(sys.argv[2],'w',zipfile.ZIP_DEFLATED)\nfor base,_,files in os.walk(root):\n    for f in files:\n        full=os.path.join(base,f)\n        z.write(full, os.path.relpath(full, root))\nz.close()`
  for (const exe of ['python', 'python3']) {
    const res = spawnSync(exe, ['-c', py, dir, out], { encoding: 'utf8' })
    if (res.status === 0) return true
  }
  return false
}

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), 'hermes-zip-'))
  const src = join(work, 'src')
  mkdirSync(join(src, 'nested'), { recursive: true })
  writeFileSync(join(src, 'electron'), 'BINARY-CONTENT\n')
  writeFileSync(join(src, 'nested', 'app.txt'), 'nested file body\n')
  zipPath = join(work, 'test.zip')

  const ok =
    process.platform === 'win32'
      ? makeZipWindows(src, zipPath) || makeZipPython(src, zipPath)
      : makeZipPython(src, zipPath)
  if (!ok || !existsSync(zipPath)) available = false
})

afterAll(() => {
  if (work) rmSync(work, { recursive: true, force: true })
})

describe('electron-zip reader against a real OS-produced ZIP', () => {
  it('lists the archive members', () => {
    if (!available) return
    const names = listEntries(readFileSync(zipPath))
      .filter((e) => !e.isDir)
      .map((e) => e.name.replace(/\\/g, '/'))
      .sort()
    assert.ok(names.includes('electron'), `members: ${names.join(', ')}`)
    assert.ok(names.some((n) => n.endsWith('nested/app.txt')), `members: ${names.join(', ')}`)
  })

  it('extracts file contents byte-for-byte', () => {
    if (!available) return
    const map = extractAll(readFileSync(zipPath))
    const bin = [...map.entries()].find(([k]) => k.replace(/\\/g, '/') === 'electron')
    assert.ok(bin, 'electron member extracted')
    assert.equal(bin[1].toString(), 'BINARY-CONTENT\n')
    const nested = [...map.entries()].find(([k]) => k.replace(/\\/g, '/').endsWith('nested/app.txt'))
    assert.ok(nested, 'nested member extracted')
    assert.equal(nested[1].toString(), 'nested file body\n')
  })

  it('central directory parse yields the expected file count', () => {
    if (!available) return
    const files = readCentralDirectory(readFileSync(zipPath)).filter((e) => !e.isDir)
    assert.ok(files.length >= 2)
  })

  it('rejects a non-zip buffer', () => {
    assert.throws(() => readCentralDirectory(Buffer.from('not a zip at all')))
  })
})
