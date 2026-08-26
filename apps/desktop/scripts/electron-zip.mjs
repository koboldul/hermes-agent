// electron-zip.mjs — minimal, dependency-free ZIP reader/extractor for the A8
// verified electron staging path.
//
// Electron release archives are standard (non-zip64) ZIPs well under 4 GiB, so
// a classic End-Of-Central-Directory + Central-Directory walk is sufficient and
// AUTHORITATIVE (the central directory carries the real sizes/offsets, avoiding
// streaming/data-descriptor ambiguity). Only STORE (0) and DEFLATE (8) are
// supported — anything else fails closed. Symlink members (unix mode S_IFLNK)
// are surfaced so the caller can reject them.

import { inflateRawSync } from 'node:zlib'

const SIG_EOCD = 0x06054b50
const SIG_CD = 0x02014b50
const SIG_LFH = 0x04034b50

const S_IFMT = 0xf000
const S_IFLNK = 0xa000

function findEocd(buf) {
  // EOCD is at the end, optionally followed by a <=65535-byte comment.
  const min = 22
  if (buf.length < min) throw new Error('zip too small for EOCD')
  const start = Math.max(0, buf.length - (min + 0xffff))
  for (let i = buf.length - min; i >= start; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i
  }
  throw new Error('EOCD signature not found (not a ZIP or truncated)')
}

export function readCentralDirectory(buf) {
  const eocd = findEocd(buf)
  const count = buf.readUInt16LE(eocd + 10)
  const cdSize = buf.readUInt32LE(eocd + 12)
  const cdOffset = buf.readUInt32LE(eocd + 16)
  if (cdOffset === 0xffffffff || cdSize === 0xffffffff) {
    throw new Error('zip64 archive not supported')
  }
  const entries = []
  let p = cdOffset
  const end = cdOffset + cdSize
  for (let i = 0; i < count; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CD) {
      throw new Error(`corrupt central directory at entry ${i}`)
    }
    const flags = buf.readUInt16LE(p + 8)
    const method = buf.readUInt16LE(p + 10)
    const crc32 = buf.readUInt32LE(p + 16)
    const compressedSize = buf.readUInt32LE(p + 20)
    const uncompressedSize = buf.readUInt32LE(p + 24)
    const nameLen = buf.readUInt16LE(p + 28)
    const extraLen = buf.readUInt16LE(p + 30)
    const commentLen = buf.readUInt16LE(p + 32)
    const externalAttrs = buf.readUInt32LE(p + 38)
    const localHeaderOffset = buf.readUInt32LE(p + 42)
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen)
    const unixMode = (externalAttrs >>> 16) & 0xffff
    entries.push({
      name,
      method,
      flags,
      crc32,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      externalAttrs,
      unixMode,
      isSymlink: (unixMode & S_IFMT) === S_IFLNK,
      isDir: name.endsWith('/'),
      isExecutable: (unixMode & 0o111) !== 0
    })
    p += 46 + nameLen + extraLen + commentLen
    if (p > end + 4) break
  }
  return entries
}

// Read one entry's uncompressed bytes, driven by the central-directory record
// (authoritative sizes) and the local header (for the variable name/extra len).
export function readEntryBytes(buf, entry) {
  const off = entry.localHeaderOffset
  if (buf.readUInt32LE(off) !== SIG_LFH) {
    throw new Error(`bad local header for ${entry.name}`)
  }
  const nameLen = buf.readUInt16LE(off + 26)
  const extraLen = buf.readUInt16LE(off + 28)
  const dataStart = off + 30 + nameLen + extraLen
  const raw = buf.subarray(dataStart, dataStart + entry.compressedSize)
  if (entry.method === 0) {
    return Buffer.from(raw)
  }
  if (entry.method === 8) {
    return inflateRawSync(raw)
  }
  throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`)
}

// [{ name, isSymlink, isDir }] for member validation (read-only, no inflate).
export function listEntries(buf) {
  return readCentralDirectory(buf).map((e) => ({
    name: e.name,
    isSymlink: e.isSymlink,
    isDir: e.isDir
  }))
}

// Extract every file entry into a Map<relPath, Buffer>. Skips directory entries;
// throws on symlink members and unsupported methods (fail closed). The returned
// map is what the verifier hashes into the provenance tree digest. When
// `writeFile` is supplied, files are also written to disk under `destDir`.
export function extractAll(buf, { destDir, writeFile } = {}) {
  const out = new Map()
  const modes = new Map()
  for (const entry of readCentralDirectory(buf)) {
    if (entry.isDir) continue
    if (entry.isSymlink) {
      throw new Error(`refusing to extract symlink member: ${entry.name}`)
    }
    const rel = entry.name.replace(/\\/g, '/')
    if (rel.startsWith('/') || rel.split('/').some((s) => s === '..')) {
      throw new Error(`refusing unsafe archive path: ${entry.name}`)
    }
    const data = readEntryBytes(buf, entry)
    out.set(rel, data)
    modes.set(rel, entry.isExecutable ? 0o755 : 0o644)
    if (writeFile && destDir) {
      writeFile(destDir, rel, data, entry.isExecutable ? 0o755 : 0o644)
    }
  }
  return out
}
