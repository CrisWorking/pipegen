// Plan J sub-task J1 (DECISIONS #126, ruling S11): the paths git tracks, read from .git/index in-process, never by
// running git. The index is attacker-controlled binary: it is read through readBytesLimited (64 MB, no symbolic link at
// any level, a regular file) and parsed with every length checked. Anything this parser can't read with certainty is
// null ("index unknown"), and then the audit behaves as it did before J1: an index that lists FEWER paths than git
// tracks would make the quick secret check skip committed files, so every index form that does that is refused:
//   - a split index (`link` extension: most entries live in a shared index elsewhere),
//   - a sparse index (`sdir` extension, or any directory entry: one entry stands for a whole folder),
//   - a SHA-256 repository (32-byte object ids; `extensions.objectformat = sha256` in .git/config),
//   - a zero checksum (`index.skipHash`) or a wrong SHA-1 checksum, a version other than 2, 3 or 4,
//   - over 500,000 entries, a path over 4,096 bytes, a v4 strip count over the previous path, a path git itself
//     would refuse (empty, absolute, `.`, `..` or `.git` parts).
// `.git` is a real folder in `dir`, or (PL-B3) a linked worktree's `.git` file: a regular file of one line
// `gitdir: <path>` whose target is a real folder (no link at any level, read as written: a link followed by `..` is
// refused, as git refuses it) holding `commondir` (a submodule has none, read the same way) and a `gitdir` back-pointer
// that resolves to `<dir>/.git` exactly, so the file can't point the read at another checkout's index. The index is
// `<gitdir>/index`, the config `<commondir>/config`. Anything else is null, as before.
import { createHash } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import { isAbsolute, join, resolve, sep } from 'node:path';
import { readBytesLimited, readTextLimitedWithReason, regexLines } from './limits.js';

export const GIT_INDEX_LIMITS = Object.freeze({ maxBytes: 64 * 1024 * 1024, maxEntries: 500_000, maxPathBytes: 4096 });

const SHA1_BYTES = 20;
const HEADER_BYTES = 12;
/** ctime, mtime (8 each), dev, ino, mode, uid, gid, size (4 each), the object id (20), flags (2). */
const FIXED_ENTRY_BYTES = 62;
const EXTENDED_FLAG = 0x4000;
const NAME_MASK = 0x0fff;
const MODE_TYPE_MASK = 0o170000;
const MODE_DIR = 0o040000;

/**
 * The paths in the git index of the checkout at `dir` (repo-relative, forward slashes), or null when the index is
 * missing, unreadable, over 64 MB or 500,000 entries, in a form that may list fewer paths than git tracks, or damaged.
 */
export async function readGitIndexPaths(dir: string): Promise<ReadonlySet<string> | null> {
  const gitDir = await lstat(join(dir, '.git')).catch(() => null);
  if (gitDir === null || gitDir.isSymbolicLink()) return null;
  if (gitDir.isFile()) return readWorktreeIndex(dir);
  if (!gitDir.isDirectory()) return null;
  if (!(await sha1Repo(join(dir, '.git/config'), dir))) return null;
  const buf = await readBytesLimited(join(dir, '.git/index'), dir, GIT_INDEX_LIMITS.maxBytes);
  return buf === null ? null : parseGitIndex(buf);
}

/**
 * `target` (from `base`) as a real folder with no link at any level, or null. The path is resolved as written (a link
 * followed by `..` is not folded away, as git does not fold it) and must equal its lexical form.
 */
async function realFolder(base: string, target: string): Promise<string | null> {
  const path = resolve(base, target);
  const info = await lstat(path).catch(() => null);
  if (info === null || !info.isDirectory()) return null;
  const written = isAbsolute(target) ? target : `${base}${sep}${target}`;
  return (await realpath(written).catch(() => null)) === path ? path : null;
}

/** One line of a small text file under `root` (a trailing newline allowed), or null. */
async function oneLine(path: string, root: string): Promise<string | null> {
  const r = await readTextLimitedWithReason(path, root, 4096);
  if (!('text' in r)) return null;
  const line = r.text.replace(/\r?\n$/, '');
  return line === '' || /[\r\n\0]/.test(line) ? null : line;
}

/** The index of a linked worktree whose `.git` is a `gitdir:` file (see the file comment), or null. */
async function readWorktreeIndex(dir: string): Promise<ReadonlySet<string> | null> {
  const realDir = await realpath(dir).catch(() => null);
  if (realDir === null) return null;
  const pointer = await oneLine(join(dir, '.git'), dir);
  const target = pointer === null ? null : /^gitdir: (.+)$/.exec(pointer)?.[1];
  if (target === undefined || target === null) return null;
  const gitdir = await realFolder(realDir, target);
  if (gitdir === null) return null;
  const common = await oneLine(join(gitdir, 'commondir'), gitdir);
  if (common === null) return null; // a submodule's git folder has no commondir
  const back = await oneLine(join(gitdir, 'gitdir'), gitdir);
  if (back === null || resolve(gitdir, back) !== join(realDir, '.git')) return null;
  const commondir = await realFolder(gitdir, common);
  if (commondir === null) return null;
  if (!(await sha1Repo(join(commondir, 'config'), commondir))) return null;
  const buf = await readBytesLimited(join(gitdir, 'index'), gitdir, GIT_INDEX_LIMITS.maxBytes);
  return buf === null ? null : parseGitIndex(buf);
}

/**
 * True unless .git/config says the repo uses SHA-256 object ids (or can't be read safely: a link, over 1 MB, binary).
 * A repo without a config file reads as SHA-1, git's default. Matched loosely (any `objectformat` key set to anything
 * but sha1, in any section), so a config written to look odd gives null, never a misread index.
 */
async function sha1Repo(path: string, root: string): Promise<boolean> {
  if ((await lstat(path).catch(() => null)) === null) return true;
  const r = await readTextLimitedWithReason(path, root);
  if (!('text' in r)) return false;
  for (const line of regexLines(r.text)) {
    const m = /^\s*objectformat\s*=\s*"?([^"\s;#]*)/i.exec(line);
    if (m !== null && m[1]?.toLowerCase() !== 'sha1') return false;
  }
  return true;
}

/** The paths in an index file's bytes (versions 2, 3 and 4), or null; see the file comment for every refusal. */
export function parseGitIndex(buf: Buffer): ReadonlySet<string> | null {
  if (buf.length < HEADER_BYTES + SHA1_BYTES || buf.length > GIT_INDEX_LIMITS.maxBytes) return null;
  const bodyEnd = buf.length - SHA1_BYTES;
  const trailer = buf.subarray(bodyEnd);
  if (trailer.every((b) => b === 0)) return null;
  if (!createHash('sha1').update(buf.subarray(0, bodyEnd)).digest().equals(trailer)) return null;
  if (buf.toString('latin1', 0, 4) !== 'DIRC') return null;
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3 && version !== 4) return null;
  const count = buf.readUInt32BE(8);
  if (count > GIT_INDEX_LIMITS.maxEntries) return null;
  // the smallest entry: v4 has no padding (fixed part, a 1-byte strip count, a NUL); v2/v3 pad to 8 bytes
  if (count * (version === 4 ? FIXED_ENTRY_BYTES + 2 : 64) > bodyEnd - HEADER_BYTES) return null;

  const paths = new Set<string>();
  let at = HEADER_BYTES;
  let prev: Buffer = Buffer.alloc(0);
  for (let i = 0; i < count; i++) {
    const start = at;
    if (at + FIXED_ENTRY_BYTES > bodyEnd) return null;
    const mode = buf.readUInt32BE(at + 24);
    if ((mode & MODE_TYPE_MASK) === MODE_DIR) return null; // a sparse-index directory entry
    const flags = buf.readUInt16BE(at + 60);
    at += FIXED_ENTRY_BYTES;
    if ((flags & EXTENDED_FLAG) !== 0) {
      if (version === 2) return null;
      if (at + 2 > bodyEnd) return null;
      at += 2;
    }
    let name: Buffer;
    if (version === 4) {
      const strip = readVarint(buf, at, bodyEnd);
      if (strip === null || strip.value > prev.length) return null;
      at = strip.next;
      const nul = buf.indexOf(0, at);
      if (nul === -1 || nul >= bodyEnd) return null;
      if (prev.length - strip.value + (nul - at) > GIT_INDEX_LIMITS.maxPathBytes) return null;
      name = Buffer.concat([prev.subarray(0, prev.length - strip.value), buf.subarray(at, nul)]);
      at = nul + 1;
    } else {
      const nul = buf.indexOf(0, at);
      if (nul === -1 || nul >= bodyEnd) return null;
      if (nul - at > GIT_INDEX_LIMITS.maxPathBytes) return null;
      name = buf.subarray(at, nul);
      // padding: 1 to 8 NULs, so the entry's length is a multiple of 8
      const padded = start + Math.ceil((nul + 1 - start) / 8) * 8;
      if (padded > bodyEnd) return null;
      for (let p = nul; p < padded; p++) if (buf[p] !== 0) return null;
      at = padded;
    }
    const nameLength = flags & NAME_MASK;
    if (nameLength !== NAME_MASK && nameLength !== name.length) return null;
    const path = name.toString('utf8');
    if (!validPath(path)) return null;
    paths.add(path);
    prev = name;
  }

  // extensions: a 4-byte signature and a 4-byte size each, up to the checksum
  while (at < bodyEnd) {
    if (at + 8 > bodyEnd) return null;
    const sig = buf.toString('latin1', at, at + 4);
    const size = buf.readUInt32BE(at + 4);
    if (at + 8 + size > bodyEnd) return null;
    if (sig === 'link' || sig === 'sdir') return null;
    // a lowercase first letter marks an extension git must understand to read the index (git refuses an unknown one)
    if (!/^[A-Z]/.test(sig)) return null;
    at += 8 + size;
  }
  return paths;
}

/** git's offset varint (varint.c, decode_varint): 7 bits a byte, high bit set on every byte but the last, +1 per continuation. */
function readVarint(buf: Buffer, at: number, end: number): { value: number; next: number } | null {
  if (at >= end) return null;
  let byte = buf[at++] as number;
  let value = byte & 0x7f;
  while ((byte & 0x80) !== 0) {
    if (at >= end || value > GIT_INDEX_LIMITS.maxPathBytes) return null;
    value += 1;
    byte = buf[at++] as number;
    value = value * 128 + (byte & 0x7f);
  }
  return { value, next: at };
}

/** A path git would accept in its index (verify_path): relative, no empty, `.`, `..` or `.git` part. */
function validPath(path: string): boolean {
  if (path === '' || path.startsWith('/') || path.includes('\0')) return false;
  for (const part of path.split('/')) {
    if (part === '' || part === '.' || part === '..' || part.toLowerCase() === '.git') return false;
  }
  return true;
}
