// Pinned tool binaries pipegen runs on the user's machine (Plan B Task 7 Part 1): gitleaks for the required code
// bundle pass (Plan A Task 5, `audit --ai`), actionlint, and cosign. A wrong or tampered binary must never run.
//
// ensurePinnedBinary (ruling B3):
// - data/pinned-binaries.yml holds, per platform, the download URL, the archive's sha256 (as upstream's checksums
//   file lists it) and the sha256 of the one binary inside it. A raw-binary asset (cosign) has `archive: none`
//   and the two hashes are equal.
// - Download: https only, GitHub release hosts only, no credential, at most the pinned archive size (Task 4's
//   shared helper). The archive hash is checked BEFORE anything is unpacked.
// - Unpack in-process (node:zlib + src/util/tar.ts), never with a `tar` child process. The unpacked size is
//   bounded, only the one expected regular file is taken, and links, devices, `..` and absolute paths refuse the
//   whole archive. Then the binary hash is checked.
// - Write to a temp file (0700, created exclusively, no-follow) in a 0700 cache directory, then rename it into
//   place. The cache root ($XDG_CACHE_HOME or ~/.cache) is used on its real path, and every directory from the
//   tool dir up to `/` must belong to the user (or root) and be unwritable by others (a root-owned sticky dir such
//   as /tmp is fine), so nobody else can swap the binary between its check and its use.
// - Before EVERY return (a fresh download or a cached copy) the file is hashed again through one descriptor. On a
//   hash mismatch it is deleted and an error is raised: it is never run. Parallel runs are safe.
// - v0.1 supports linux and darwin on x64 and arm64 (ruling S27). The 7-day cooldown (S26) is checked on the data
//   file by a test, not at run time.
import { createHash, randomBytes } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, rename, rm, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { parse } from 'yaml';
import { z } from 'zod';
import type { ReviewedTool } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { TarError, readTarMember } from '../util/tar.js';
import { downloadRelease } from './pin.js';
import { isGitHubRepo } from './names.js';

export type PinnedName = 'actionlint' | 'cosign' | 'gitleaks';
export const PINNED_NAMES: readonly PinnedName[] = ['actionlint', 'cosign', 'gitleaks'];
export const PLATFORM_KEYS = ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'] as const;
export type PlatformKey = (typeof PLATFORM_KEYS)[number];

/** Upper bounds for any pinned asset (the real values are far below; cosign is the largest at about 150 MB). */
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_BINARY_BYTES = 512 * 1024 * 1024;
/** How much more than the binary itself a tar may unpack to (licence, readme, docs). Bounds a gzip bomb. */
export const TAR_SLACK_BYTES = 16 * 1024 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;
const ASSET_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const READ_CHUNK = 1024 * 1024;

const assetSchema = z.object({
  url: z.string(),
  archive: z.enum(['tar.gz', 'none']),
  archiveSize: z.number().int().positive().max(MAX_ARCHIVE_BYTES),
  archiveSha256: z.string().regex(HEX64),
  binarySize: z.number().int().positive().max(MAX_BINARY_BYTES),
  binarySha256: z.string().regex(HEX64),
}).strict().refine((a) => a.archive !== 'none' || (a.archiveSha256 === a.binarySha256 && a.archiveSize === a.binarySize), {
  message: 'a raw binary (archive: none) has one hash and one size: archiveSha256 = binarySha256, archiveSize = binarySize',
});

const entrySchema = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  repo: z.string().refine(isGitHubRepo, 'not a GitHub owner/name'),
  releasedAt: z.string().regex(ISO_DATE_RE),
  /** The file to take out of the archive (a plain name, no directory). */
  member: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/),
  platforms: z.object(Object.fromEntries(PLATFORM_KEYS.map((k) => [k, assetSchema])) as Record<PlatformKey, typeof assetSchema>).strict(),
}).strict().superRefine((e, ctx) => {
  for (const key of PLATFORM_KEYS) {
    if (!isReleaseUrl(e.platforms[key].url, e.repo, e.version)) {
      ctx.addIssue({ code: 'custom', path: ['platforms', key, 'url'], message: `must be https://github.com/${e.repo}/releases/download/v${e.version}/<asset>` });
    }
  }
});

/** data/pinned-binaries.yml: exactly gitleaks, actionlint and cosign. */
export const pinnedBinariesSchema = z.object({ gitleaks: entrySchema, actionlint: entrySchema, cosign: entrySchema }).strict();
export type PinnedBinaries = z.infer<typeof pinnedBinariesSchema>;
export type PinnedBinary = PinnedBinaries[PinnedName];
export type PinnedAsset = PinnedBinary['platforms'][PlatformKey];

/** A release download URL of exactly this repo and version on github.com (no query, port, credential or `..`). */
function isReleaseUrl(url: string, repo: string, version: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.href !== url || u.protocol !== 'https:' || u.hostname !== 'github.com') return false;
  if (u.port !== '' || u.username !== '' || u.password !== '' || u.search !== '' || u.hash !== '') return false;
  const prefix = `/${repo}/releases/download/v${version}/`;
  return u.pathname.startsWith(prefix) && ASSET_RE.test(u.pathname.slice(prefix.length));
}

export class PinnedBinaryError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(safeText(message, 600), options);
    this.name = 'PinnedBinaryError';
  }
}

/** Reads and validates data/pinned-binaries.yml (found through packageDataPath, ruling S2). */
export function loadPinnedBinaries(path: string = packageDataPath('pinned-binaries.yml')): PinnedBinaries {
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new PinnedBinaryError("pipegen's pinned-binaries.yml could not be read.", { cause: e });
  }
  return checkPins(raw);
}

function checkPins(raw: unknown): PinnedBinaries {
  const parsed = pinnedBinariesSchema.safeParse(raw);
  if (!parsed.success) {
    const where = parsed.error.issues[0]?.path.join('.') ?? '';
    throw new PinnedBinaryError(`pipegen's pinned-binaries data is invalid${where === '' ? '' : ` (at ${where})`}.`);
  }
  return parsed.data;
}

export interface PinnedBinaryDeps {
  /** Used for the download (no credential is ever passed to it). Default: global fetch. */
  fetch?: typeof fetch;
  /** The pins table. Default: data/pinned-binaries.yml. */
  pins?: PinnedBinaries;
  /** Default: process.platform / process.arch. */
  platform?: string;
  arch?: string;
  /** Default: Date.now (to tell a stale temp file from one another run is still writing). */
  now?: () => number;
  /** The home directory the default cache (~/.cache/pipegen/tools) is under. Default: os.homedir(). */
  home?: string;
  /** Read for XDG_CACHE_HOME. Default: process.env. */
  env?: Record<string, string | undefined>;
  /** The user the cache directories must belong to. Default: process.getuid(). */
  uid?: number;
}

/** A temp file left in a tool dir longer than this is from a run that died; it is removed. */
const STALE_TMP_MS = 3_600_000;
const TMP_RE = /^\.[a-z]+-[0-9a-f]{16}\.tmp$/;

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const errCode = (e: unknown) => (e as { code?: unknown } | null)?.code;

/**
 * Downloads (once) and verifies the pinned `name` binary for this platform, and returns its absolute path in
 * `<cache>/<name>-<version>/<name>` (default cache: $XDG_CACHE_HOME/pipegen/tools or ~/.cache/pipegen/tools,
 * on its real path). The returned file was hashed just now and matched the pinned binarySha256. Throws
 * PinnedBinaryError when anything doesn't check out; a binary whose hash doesn't match is deleted and never run.
 * Callers run the returned path right away (absolute path, no shell) and never keep it across operations.
 */
export async function ensurePinnedBinary(name: PinnedName, cacheDir?: string, deps: PinnedBinaryDeps = {}): Promise<string> {
  if (!(PINNED_NAMES as readonly string[]).includes(name)) throw new PinnedBinaryError(`pipegen has no pinned binary for ${String(name)}.`);
  const pins = deps.pins === undefined ? loadPinnedBinaries() : checkPins(deps.pins);
  const entry = pins[name];
  const what = `${name} ${entry.version}`;

  // platform (ruling S27)
  const platform = deps.platform ?? process.platform;
  const arch = deps.arch ?? process.arch;
  const key = `${platform}-${arch}`;
  if (!(PLATFORM_KEYS as readonly string[]).includes(key)) {
    throw new PinnedBinaryError(`pipegen's ${name} download needs Linux or macOS for now (WSL works). There is no pinned ${name} for ${key}; pipegen supports linux and darwin on x64 and arm64.`);
  }
  const asset = entry.platforms[key as PlatformKey];

  const uid = deps.uid ?? process.getuid?.();
  if (uid === undefined) throw new PinnedBinaryError('pipegen could not tell which user it runs as, so it will not set up its tool cache.');
  const toolDir = await prepareCache(name, entry.version, cacheDir, deps, uid);
  const target = join(toolDir, name);
  await removeStaleTemps(toolDir, uid, (deps.now ?? Date.now)());

  // a cached copy is re-checked before every use; a copy that vanished (another run, a cleanup) is fetched again
  for (let attempt = 0; attempt < 2; attempt++) {
    if ((await verifyCached(target, asset, what, uid)) === 'ok') return target;
    await install(target, toolDir, name, entry.member, asset, what, deps.fetch ?? fetch);
    if ((await verifyCached(target, asset, what, uid)) === 'ok') return target;
  }
  throw new PinnedBinaryError(`pipegen saved ${what} but it kept disappearing from its tool cache (${toolDir}); it was not run.`);
}

/** Download → archive hash → unpack in-process → binary hash → temp file → atomic rename. */
async function install(target: string, toolDir: string, name: string, member: string, asset: PinnedAsset, what: string, fetchFn: typeof fetch): Promise<void> {
  // download into one buffer of the pinned size (the helper refuses anything larger), hashing as it arrives
  const buf = Buffer.allocUnsafe(asset.archiveSize);
  const archiveHash = createHash('sha256');
  let got = 0;
  try {
    await downloadRelease(fetchFn, asset.url, asset.archiveSize, (chunk) => {
      buf.set(chunk, got);
      got += chunk.byteLength;
      archiveHash.update(chunk);
    });
  } catch (e) {
    throw new PinnedBinaryError(`Couldn't download ${what}: ${e instanceof Error ? e.message : 'unknown error'}`, { cause: e });
  }
  // the archive hash is checked BEFORE anything is unpacked
  if (got !== asset.archiveSize || archiveHash.digest('hex') !== asset.archiveSha256) {
    throw new PinnedBinaryError(`The download of ${what} doesn't match its pinned checksum, so pipegen refused it. Nothing was unpacked or run.`);
  }
  const archive = buf.subarray(0, got);

  // unpack in-process (no child process), then check the binary hash BEFORE anything is written
  const binary = asset.archive === 'none' ? archive : unpack(archive, member, asset, what);
  if (binary.length !== asset.binarySize || sha256(binary) !== asset.binarySha256) {
    throw new PinnedBinaryError(`The ${what} binary in the verified archive doesn't match its pinned checksum, so pipegen refused it. Nothing was written or run.`);
  }

  // temp file (0700, exclusive, no-follow) in the 0700 tool dir, then an atomic rename into place
  const tmp = join(toolDir, `.${name}-${randomBytes(8).toString('hex')}.tmp`);
  try {
    const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o700);
    try {
      await fh.writeFile(binary);
      await fh.chmod(0o700);
      await fh.sync();
    } finally {
      await fh.close();
    }
    await rename(tmp, target);
  } catch (e) {
    await rm(tmp, { force: true }).catch(() => {});
    throw new PinnedBinaryError(`Couldn't save ${what} in pipegen's tool cache.`, { cause: e });
  }
}

/** gunzip (bounded) + the in-process tar reader. */
function unpack(archive: Uint8Array, member: string, asset: PinnedAsset, what: string): Buffer {
  const limit = asset.binarySize + TAR_SLACK_BYTES;
  let tar: Buffer;
  try {
    tar = gunzipSync(archive, { maxOutputLength: limit });
  } catch (e) {
    const tooLarge = e instanceof RangeError || errCode(e) === 'ERR_BUFFER_TOO_LARGE';
    throw new PinnedBinaryError(tooLarge
      ? `The ${what} archive unpacks to more than ${limit} bytes, which is too large; pipegen refused it.`
      : `The ${what} archive is not a valid gzip file; pipegen refused it.`, { cause: e });
  }
  try {
    return readTarMember(tar, member, asset.binarySize);
  } catch (e) {
    if (e instanceof TarError) throw new PinnedBinaryError(`pipegen refused the ${what} archive. ${e.message}`, { cause: e });
    throw e;
  }
}

/**
 * Hashes the cached file through one file descriptor (opened without following a final symlink, and without
 * blocking on a FIFO) and says 'ok' only when it is a regular file of this user with the pinned size and hash.
 * 'missing' when there is no file (it will be downloaded). Only a real size or hash mismatch, or a symlink in its
 * place, deletes it; anything else odd is refused without deleting. Never run on a mismatch.
 */
async function verifyCached(path: string, asset: PinnedAsset, what: string, uid: number): Promise<'ok' | 'missing'> {
  const refuse = (why: string, deleted: boolean): never => {
    throw new PinnedBinaryError(deleted
      ? `The cached ${what} at ${path} ${why}, so pipegen deleted it and won't run it. Run the command again to download a fresh, verified copy.`
      : `The cached ${what} at ${path} ${why}; pipegen won't run it. Remove it and try again.`);
  };
  let fh;
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    if (errCode(e) === 'ENOENT') return 'missing';
    if (errCode(e) === 'ELOOP') {
      // unlink only if the path is still a symlink (not a good copy another run renamed into place meanwhile)
      const still = await lstat(path).catch(() => null);
      const removed = still !== null && still.isSymbolicLink() && (await unlink(path).then(() => true, () => false));
      return refuse('is a symbolic link, not the verified file', removed);
    }
    return refuse(`could not be opened safely (${safeText(String(errCode(e) ?? 'error'), 20)})`, false);
  }
  let mismatch: { dev: number; ino: number } | null = null;
  try {
    const st = await fh.stat();
    if (!st.isFile()) refuse('is not a regular file', false);
    if (st.uid !== uid) refuse('is not owned by you', false);
    if (st.size !== asset.binarySize) {
      mismatch = st;
    } else {
      const hash = createHash('sha256');
      const chunk = Buffer.alloc(READ_CHUNK);
      let size = 0;
      for (;;) {
        const { bytesRead } = await fh.read(chunk, 0, READ_CHUNK, null);
        if (bytesRead === 0) break;
        size += bytesRead;
        if (size > asset.binarySize) break;
        hash.update(chunk.subarray(0, bytesRead));
      }
      if (size !== asset.binarySize || hash.digest('hex') !== asset.binarySha256) mismatch = st;
    }
  } finally {
    await fh.close();
  }
  if (mismatch === null) return 'ok';
  // delete only the file that was checked (not a good copy another run renamed into place meanwhile)
  const now = await lstat(path).catch(() => null);
  const removed = now !== null && now.dev === mismatch.dev && now.ino === mismatch.ino && (await unlink(path).then(() => true, () => false));
  return refuse('changed since pipegen verified it (its checksum no longer matches)', removed);
}

/** Removes temp files (pipegen's own name pattern, regular files of this user) left over an hour by a run that died. */
async function removeStaleTemps(toolDir: string, uid: number, now: number): Promise<void> {
  let names: string[];
  try {
    names = await readdir(toolDir);
  } catch {
    return;
  }
  for (const n of names) {
    if (!TMP_RE.test(n)) continue;
    const p = join(toolDir, n);
    const info = await lstat(p).catch(() => null);
    if (info !== null && info.isFile() && info.uid === uid && now - info.mtimeMs > STALE_TMP_MS) await unlink(p).catch(() => {});
  }
}

/**
 * The tool dir `<root>/<name>-<version>`, where root is the given cacheDir, else $XDG_CACHE_HOME (when absolute) or
 * ~/.cache, followed by pipegen/tools. The root is resolved to its real path (a symlinked ~/.cache is fine), and
 * pipegen's own levels below it are created 0700. Then every directory from the tool dir up to `/` is checked,
 * OpenSSH StrictModes style: owned by you (pipegen's own levels) or by you or root (the rest), not a symlink, and
 * no group or other write, except a root-owned sticky directory such as /tmp. So nobody else can swap the binary
 * between its check and its use.
 */
async function prepareCache(name: string, version: string, cacheDir: string | undefined, deps: PinnedBinaryDeps, uid: number): Promise<string> {
  // the root, on its real path, and everything above it
  let root: string;
  const own: string[] = [];
  if (cacheDir !== undefined) {
    await mkdirOwn(cacheDir, true);
    root = await realDir(cacheDir);
  } else {
    const xdg = (deps.env ?? process.env).XDG_CACHE_HOME;
    const base = xdg !== undefined && isAbsolute(xdg) ? xdg : join(deps.home ?? homedir(), '.cache');
    await mkdirOwn(base, true);
    root = await realDir(base);
    own.push('pipegen', 'tools');
  }
  for (let dir = root; ; dir = dirname(dir)) {
    await checkDir(dir, uid, cacheDir !== undefined && dir === root);
    if (dirname(dir) === dir) break;
  }
  // pipegen's own levels: each created 0700 and checked before anything is created inside it
  let dir = root;
  for (const part of [...own, `${name}-${version}`]) {
    dir = join(dir, part);
    await mkdirOwn(dir, false);
    await checkDir(dir, uid, true);
  }
  return dir;
}

/** Creates a directory 0700 when it is missing (with its parents when `parents`). An existing one is checked later. */
async function mkdirOwn(dir: string, parents: boolean): Promise<void> {
  try {
    await mkdir(dir, { mode: 0o700, recursive: parents });
  } catch (e) {
    if (errCode(e) !== 'EEXIST') throw new PinnedBinaryError(`Couldn't create pipegen's tool cache directory ${dir}.`, { cause: e });
  }
}

async function realDir(dir: string): Promise<string> {
  try {
    return await realpath(dir);
  } catch (e) {
    throw new PinnedBinaryError(`Couldn't resolve pipegen's tool cache directory ${dir}.`, { cause: e });
  }
}

/** One directory on the path to the tool: see prepareCache. */
async function checkDir(dir: string, uid: number, pipegenOwned: boolean): Promise<void> {
  const refuse = (why: string, fix = ''): never => {
    throw new PinnedBinaryError(`pipegen won't keep tools under ${dir}: ${why}.${fix === '' ? '' : ` Fix it with: ${fix}`}`);
  };
  let info;
  try {
    info = await lstat(dir);
  } catch (e) {
    throw new PinnedBinaryError(`Couldn't check pipegen's tool cache directory ${dir}.`, { cause: e });
  }
  if (info.isSymbolicLink()) refuse('it is a symbolic link where pipegen keeps its own folder', `rm '${dir}'`);
  if (!info.isDirectory()) refuse('it is not a directory');
  const rootOwned = info.uid === 0;
  if (info.uid !== uid && (pipegenOwned || !rootOwned)) refuse('it is not owned by you' + (pipegenOwned ? '' : ' (or root)'));
  const sticky = (info.mode & 0o1000) !== 0;
  if ((info.mode & 0o022) !== 0 && !(rootOwned && sticky && !pipegenOwned)) {
    refuse('other users can write to it, so they could swap the tool pipegen runs', `chmod g-w,o-w '${dir}'`);
  }
}

/**
 * Ruling S25: a tool pinned here and also listed in reviewed-tools.yml (for user CI) must be the same release.
 * Returns one plain-English problem per mismatch (empty = consistent). A reviewed CLI entry from the same GitHub
 * repo must have the same version, and every hash it carries must be one of this release's archive or binary
 * hashes. Task 8 calls this on the real lists.
 */
export function checkPinnedAgainstReviewed(pins: PinnedBinaries, reviewed: readonly ReviewedTool[]): string[] {
  const problems: string[] = [];
  for (const name of PINNED_NAMES) {
    const entry = pins[name];
    const known = new Set(PLATFORM_KEYS.flatMap((k) => [entry.platforms[k].archiveSha256, entry.platforms[k].binarySha256]));
    for (const tool of reviewed) {
      const c = tool.candidate;
      if (c.kind !== 'cli' || typeof c.repo !== 'string' || c.repo.toLowerCase() !== entry.repo.toLowerCase()) continue;
      const id = safeText(tool.id, 80);
      if (c.version.replace(/^v/, '') !== entry.version) {
        problems.push(`${name}: the reviewed entry ${id} is version ${safeText(c.version, 40)}, but pinned-binaries.yml pins ${entry.version}.`);
      }
      const hashes = [c.pin.checksum, tool.step.cli?.install.checksum].filter((h): h is string => typeof h === 'string');
      if (hashes.length === 0) {
        problems.push(`${name}: the reviewed entry ${id} has no hash to compare with pinned-binaries.yml.`);
        continue;
      }
      for (const h of new Set(hashes)) {
        if (!known.has(h.toLowerCase())) problems.push(`${name}: the reviewed entry ${id} has a hash that pinned-binaries.yml doesn't list for ${entry.version}.`);
      }
    }
  }
  return problems;
}
