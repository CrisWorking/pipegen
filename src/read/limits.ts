import { constants, type Stats } from 'node:fs';
import { lstat, open, readlink, realpath, type FileHandle } from 'node:fs/promises';
import { isAbsolute, join, relative, sep } from 'node:path';
import fg from 'fast-glob';
import { isMap, isPair, isScalar, isSeq, parseDocument } from 'yaml';

/** Read limits that protect the user's machine from hostile repos. Every reader goes through this file. */
export const READ_LIMITS = { maxFileBytes: 1_000_000, maxFiles: 20_000, maxAliasCount: 50, maxRegexLineBytes: 4096 } as const;

/** Folders never read: dependencies, VCS data, virtualenvs and build output. */
export const IGNORED_DIRS: readonly string[] = Object.freeze(['node_modules', '.git', '.venv', 'dist', 'build', 'vendor', 'target']);

/**
 * The first level of `rel` (a fixed path inside `dir`) that is a symbolic link, or null. A missing level ends the check.
 * Exported for the coverage mapper, which checks every level of a file it reads by path.
 */
export async function linkedLevel(dir: string, rel: string): Promise<string | null> {
  const parts = rel.split('/').filter((p) => p !== '' && p !== '.');
  for (let i = 0; i < parts.length; i++) {
    const info = await lstat(join(dir, ...parts.slice(0, i + 1))).catch(() => null);
    if (info === null) return null;
    if (info.isSymbolicLink()) return parts.slice(0, i + 1).join('/');
  }
  return null;
}

/**
 * Lists files under `dir` (relative, forward slashes). Never follows symlinks; stops after maxFiles.
 * A pattern whose fixed base (`.github/workflows` in `.github/workflows/*.yml`) passes through a symbolic link is
 * skipped, because the glob library would open that base by path and so follow the link; the link is reported
 * in `links` (only present when there is one).
 * When `found` is given, symbolic links met on the way (to files or folders) are collected in
 * `found.links` (at most maxFiles of them) so callers can say what they skipped; they are never followed.
 */
export async function listFiles(dir: string, patterns: string[], ignore: string[], found?: { links: string[] }): Promise<{ files: string[]; truncated: boolean; links?: string[] }> {
  const links: string[] = [];
  const usable: string[] = [];
  for (const pattern of patterns) {
    // The bases fast-glob will actually open: braces in a folder part (`l{n,x}k/*`) expand to several fixed bases.
    const bases = pattern.startsWith('!') ? [] : fg.generateTasks([pattern], { cwd: dir }).map((t) => t.base).filter((b) => b !== '.' && b !== '');
    let link: string | null = null;
    for (const base of bases) if (link === null) link = await linkedLevel(dir, base);
    if (link !== null) {
      if (!links.includes(link)) links.push(link);
      if (found && found.links.length < READ_LIMITS.maxFiles && !found.links.includes(link)) found.links.push(link);
      continue;
    }
    usable.push(pattern);
  }
  const done = (files: string[], truncated: boolean) => (links.length > 0 ? { files, truncated, links } : { files, truncated });
  if (usable.length === 0) return done([], false);
  const stream = fg.stream(usable, { cwd: dir, ignore, dot: true, onlyFiles: !found, objectMode: !!found, unique: true, suppressErrors: true, followSymbolicLinks: false });
  const files: string[] = [];
  for await (const entry of stream) {
    let rel: string;
    if (found) {
      const e = entry as unknown as { path: string; dirent: { isFile(): boolean; isSymbolicLink(): boolean } };
      if (e.dirent.isSymbolicLink()) {
        if (found.links.length < READ_LIMITS.maxFiles) found.links.push(e.path);
        continue;
      }
      if (!e.dirent.isFile()) continue;
      rel = e.path;
    } else {
      rel = String(entry);
    }
    if (files.length >= READ_LIMITS.maxFiles) {
      (stream as unknown as { destroy(): void }).destroy();
      return done(files, true);
    }
    files.push(rel);
  }
  return done(files, false);
}

/** A NUL byte in the first 8 KB means binary. */
export function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

export type Skipped = 'too-large' | 'binary' | 'link' | 'not-a-file' | 'unreadable';

/** Why a file was skipped, in plain English, for notes: `Skipped <path>: <reason>.` */
export const SKIP_REASON: Readonly<Record<Skipped, string>> = Object.freeze({
  'too-large': 'it is larger than 1 MB',
  binary: 'it is a binary file',
  link: 'it is a symbolic link',
  'not-a-file': 'it is not a regular file',
  unreadable: 'it could not be read',
});

/** READ_LIMITS.maxFiles as people write it (20,000). */
export const MAX_FILES_TEXT = READ_LIMITS.maxFiles.toLocaleString('en-US');

/**
 * Flags for opening a file that was just checked with lstat: never through a final symbolic link, and without blocking
 * on a FIFO (a plain open of a FIFO waits for a writer forever). Both are 0 where the platform has no such flag.
 */
const OPEN_CHECKED = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);

/**
 * P49, macOS: O_NOFOLLOW_ANY refuses a symbolic link at ANY level of the path, so the open itself can't be redirected by
 * a swapped folder. Used when Node exposes the constant (Node's fs.constants doesn't list it today, so then macOS keeps
 * the path checks below; threat model T51).
 */
const NOFOLLOW_ANY = (constants as unknown as Record<string, number | undefined>).O_NOFOLLOW_ANY ?? 0;

/**
 * P49, Linux: the real path of an open descriptor, read from /proc/self/fd (the kernel's own record of the opened file,
 * not a path that can be swapped). Null when /proc is not there (another platform, or /proc not mounted): then the path
 * checks are all there is (threat model T51).
 */
async function openedPath(fd: number): Promise<string | null> {
  if (process.platform !== 'linux') return null;
  try {
    return await readlink(`/proc/self/fd/${fd}`);
  } catch {
    return null;
  }
}

/** True for the error an O_NOFOLLOW open gives on a symbolic link (ELOOP; EMLINK on FreeBSD). */
const isLinkRefusal = (e: unknown): boolean => ['ELOOP', 'EMLINK'].includes(String((e as { code?: unknown } | null)?.code));

/** True when the stats describe the same file (device and inode). */
const sameFile = (a: { dev: number | bigint; ino: number | bigint }, b: { dev: number | bigint; ino: number | bigint }): boolean => a.dev === b.dev && a.ino === b.ino;

/**
 * `path` as a relative path under `root` (forward slashes), or null when it isn't under it. Used for the component check.
 */
function under(root: string, path: string): string | null {
  const rel = relative(root, path).split(sep).join('/');
  return rel === '' || rel === '..' || rel.startsWith('../') || isAbsolute(rel) ? null : rel;
}

/**
 * The root checks before the open (P46): `path` must be under `root`, and no level of it under the root may be a link.
 * Null when the read may go on (or when no root is given).
 */
async function checkBeforeOpen(path: string, root: string | undefined, rel: string | null): Promise<Skipped | null> {
  if (root === undefined) return null;
  if (rel === null) return 'unreadable';
  return (await linkedLevel(root, rel)) !== null ? 'link' : null;
}

/**
 * The checks after the open (P46, P49): the descriptor is the file lstat described; with `root`, the opened file itself
 * must be inside the repo (Linux: the descriptor's real path; path checks alone always leave a window, because a folder
 * can be swapped back and forth between any two of them), no level is a link at the second check, and the path still
 * leads to the opened file. Null when the read may go on.
 */
async function checkAfterOpen(handle: FileHandle, opened: Stats, info: Stats, path: string, root: string | undefined, rel: string | null): Promise<Skipped | null> {
  if (!sameFile(opened, info)) return 'unreadable';
  if (root === undefined || rel === null) return null;
  const real = await openedPath(handle.fd);
  if (real !== null) {
    const rootReal = await realpath(root);
    if (under(rootReal, real.replace(/ \(deleted\)$/, '')) === null) return 'link';
  }
  if ((await linkedLevel(root, rel)) !== null) return 'link';
  return sameFile(opened, await lstat(path)) ? null : 'unreadable';
}

/**
 * Like readTextLimited, but says why a file was skipped. lstat gives the reason first; then the file is opened without
 * following a symbolic link and without blocking (OPEN_CHECKED), the opened descriptor is checked again with fstat
 * (regular file, size), and at most maxFileBytes + 1 bytes are read from it. So a file swapped after the lstat check
 * (for a FIFO, a symlink, a bigger file) is skipped for the same reasons, and the read can't block or grow unbounded.
 *
 * P46: the descriptor must also be the file that lstat described (same device and inode), so a swap of the last
 * component between lstat and open is refused. With `root` (the repo folder the caller read `path` from), no level of
 * `path` under it may be a symbolic link, checked before the lstat and again after the open, and the file reached
 * through those checked folders after the open must be the opened one: a folder swapped for a link to somewhere else
 * between the checks and the open is refused (the open would have followed it to another file). Such a swap is
 * reported as `link` when a level is a link at the second check, else as `unreadable`.
 *
 * P49: path checks alone can't close that race (a folder swapped back and forth wins between any two of them), so with
 * `root` the opened descriptor is verified itself: on Linux its real path (/proc/self/fd) must be inside the root's real
 * path (`link` otherwise); on macOS the open uses O_NOFOLLOW_ANY when Node exposes it. Elsewhere, or without /proc,
 * only the path checks remain (threat model T51).
 *
 * `maxBytes` (default READ_LIMITS.maxFileBytes) is for a caller that must read a bigger text on purpose (the D1 guard reads package-lock.json).
 */
export async function readTextLimitedWithReason(path: string, root?: string, maxBytes: number = READ_LIMITS.maxFileBytes): Promise<{ text: string } | { skipped: Skipped }> {
  let handle: FileHandle | undefined;
  try {
    const rel = root === undefined ? null : under(root, path);
    const before = await checkBeforeOpen(path, root, rel);
    if (before !== null) return { skipped: before };
    const info = await lstat(path);
    if (info.isSymbolicLink()) return { skipped: 'link' };
    if (!info.isFile()) return { skipped: 'not-a-file' };
    if (info.size > maxBytes) return { skipped: 'too-large' };
    try {
      handle = await open(path, OPEN_CHECKED | (root !== undefined ? NOFOLLOW_ANY : 0));
    } catch (e) {
      if (isLinkRefusal(e)) return { skipped: 'link' };
      throw e;
    }
    const opened = await handle.stat();
    if (!opened.isFile()) return { skipped: 'not-a-file' };
    if (opened.size > maxBytes) return { skipped: 'too-large' };
    const after = await checkAfterOpen(handle, opened, info, path, root, rel);
    if (after !== null) return { skipped: after };
    const buf = await readAtMost(handle, opened.size, maxBytes + 1);
    if (buf.length > maxBytes) return { skipped: 'too-large' };
    return isBinary(buf) ? { skipped: 'binary' } : { text: buf.toString('utf8') };
  } catch {
    return { skipped: 'unreadable' };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Reads from the start of `handle` until the end of the file or `limit` bytes, whichever comes first. `expected` (the
 * fstat size) sizes the first buffer, so a small file never costs a buffer of `limit` bytes; a file that grew since
 * fstat is read on, in more pieces, up to `limit`. Callers pass one byte over their limit to tell "grew past it".
 */
async function readAtMost(handle: FileHandle, expected: number, limit: number): Promise<Buffer> {
  const parts: Buffer[] = [];
  let total = 0;
  let size = Math.max(1, Math.min(expected + 1, limit));
  while (total < limit) {
    const buf = Buffer.alloc(Math.min(size, limit - total));
    const { bytesRead } = await handle.read(buf, 0, buf.length, null);
    if (bytesRead === 0) break;
    parts.push(buf.subarray(0, bytesRead));
    total += bytesRead;
    size = LINE_CHUNK_BYTES;
  }
  return parts.length === 1 ? parts[0] : Buffer.concat(parts, total);
}

/** Text of a regular file, or null when it is missing, unreadable, a symlink, over 1 MB, or binary. */
export async function readTextLimited(path: string, root?: string): Promise<string | null> {
  const result = await readTextLimitedWithReason(path, root);
  return 'text' in result ? result.text : null;
}

/**
 * YAML with at most 50 aliases (guards against alias-bomb files). Throws when the limit is exceeded, on a syntax error,
 * or when a map repeats a key. yaml's own repeated-key check compares each key with every earlier key of its map, which
 * takes minutes on a hostile 1 MB map, so it is turned off and the same check runs in assertUniqueKeys, in one pass.
 * Warnings are passed on as yaml's parse() does.
 */
export function parseYamlLimited(text: string): unknown {
  const doc = parseDocument(text, { uniqueKeys: false });
  for (const warning of doc.warnings) process.emitWarning(warning);
  if (doc.errors.length > 0) throw doc.errors[0];
  assertUniqueKeys(doc.contents);
  return doc.toJS({ maxAliasCount: READ_LIMITS.maxAliasCount });
}

/**
 * yaml's rule for a repeated key (its default `uniqueKeys`): two keys are the same when they are the same node, or both
 * are scalars with the same value. Checked with a Set per map and an explicit stack, so the work is linear in the
 * number of nodes; aliases are not followed (each node is visited once).
 */
function assertUniqueKeys(root: unknown): void {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (isMap(node)) {
      const seen = new Set<unknown>();
      let emptyKey = false;
      for (const pair of node.items) {
        const key: unknown = pair.key;
        let repeated = false;
        if (key === null || key === undefined) {
          repeated = emptyKey;
          emptyKey = true;
        } else if (isScalar(key) && !(typeof key.value === 'number' && Number.isNaN(key.value))) {
          repeated = seen.has(key.value);
          seen.add(key.value);
        }
        if (repeated) throw new Error('Map keys must be unique');
        stack.push(key, pair.value);
      }
    } else if (isSeq(node)) {
      for (const item of node.items) stack.push(item);
    } else if (isPair(node)) {
      stack.push(node.key, node.value);
    }
  }
}

/** Only the lines of 4 KB or less; regex rules run on these so a huge line cannot stall a pattern. */
export function regexLines(text: string): string[] {
  return text.split(/\r?\n/).filter(regexSafe);
}

/** True when a repo-derived string is short enough (4 KB) to run a regex on. */
export function regexSafe(s: string): boolean {
  return Buffer.byteLength(s) <= READ_LIMITS.maxRegexLineBytes;
}

const LINE_CHUNK_BYTES = 64 * 1024;

/**
 * Plan P Task 1 (ruling PS4): reads a regular file line by line, for files that may be larger than maxFileBytes
 * (lockfiles). Never follows a symbolic link (lstat first, then O_NOFOLLOW, then the opened file is checked again), never
 * holds more than one chunk plus one line in memory, and stops at `maxBytes` (the size is checked before reading, and
 * the bytes read are counted, so a file that grows is still cut off). A NUL byte in the first chunk means binary. A line
 * longer than `maxLineBytes` is skipped whole and never built, so a regex never runs on it. `onLine` gets each line
 * without its line ending. A skipped file may already have passed some lines to `onLine` (when it grows past `maxBytes`
 * while being read): callers must drop what they collected when a file is skipped.
 */
export async function readLinesLimited(path: string, opts: { maxBytes: number; maxLineBytes: number }, onLine: (line: string) => void, root?: string): Promise<{ bytes: number } | { skipped: Skipped }> {
  let handle: FileHandle | undefined;
  try {
    const rel = root === undefined ? null : under(root, path);
    const before = await checkBeforeOpen(path, root, rel);
    if (before !== null) return { skipped: before };
    const info = await lstat(path);
    if (info.isSymbolicLink()) return { skipped: 'link' };
    if (!info.isFile()) return { skipped: 'not-a-file' };
    if (info.size > opts.maxBytes) return { skipped: 'too-large' };
    try {
      handle = await open(path, OPEN_CHECKED | (root !== undefined ? NOFOLLOW_ANY : 0));
    } catch (e) {
      if (isLinkRefusal(e)) return { skipped: 'link' };
      throw e;
    }
    const opened = await handle.stat();
    if (!opened.isFile()) return { skipped: 'not-a-file' };
    if (opened.size > opts.maxBytes) return { skipped: 'too-large' };
    const after = await checkAfterOpen(handle, opened, info, path, root, rel);
    if (after !== null) return { skipped: after };
    const buf = Buffer.alloc(LINE_CHUNK_BYTES);
    let parts: Buffer[] = [];
    let length = 0;
    let tooLong = false;
    let total = 0;
    const add = (piece: Buffer) => {
      if (tooLong || piece.length === 0) return;
      if (length + piece.length > opts.maxLineBytes) {
        tooLong = true;
        parts = [];
        return;
      }
      parts.push(Buffer.from(piece)); // a copy: buf is reused for the next chunk
      length += piece.length;
    };
    const end = () => {
      if (!tooLong) {
        const line = Buffer.concat(parts, length).toString('utf8');
        onLine(line.endsWith('\r') ? line.slice(0, -1) : line);
      }
      parts = [];
      length = 0;
      tooLong = false;
    };
    for (;;) {
      const { bytesRead } = await handle.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      const chunk = buf.subarray(0, bytesRead);
      if (total === 0 && isBinary(chunk)) return { skipped: 'binary' };
      total += bytesRead;
      if (total > opts.maxBytes) return { skipped: 'too-large' };
      let start = 0;
      for (let nl = chunk.indexOf(10, start); nl !== -1; nl = chunk.indexOf(10, start)) {
        add(chunk.subarray(start, nl));
        end();
        start = nl + 1;
      }
      add(chunk.subarray(start));
    }
    if (length > 0 || tooLong) end();
    return { bytes: total };
  } catch {
    return { skipped: 'unreadable' };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}
