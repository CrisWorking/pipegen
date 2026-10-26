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
//   place. Every level of the cache path is lstat'ed: a symlink, another owner, or a directory other users can
//   write to is refused.
// - Before EVERY return (a fresh download or a cached copy) the file is hashed again. On a mismatch it is deleted
//   and an error is raised: it is never run.
// - v0.1 supports linux and darwin on x64 and arm64 (ruling S27); a release must be at least 7 days old (S26).
import { createHash, randomBytes } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, mkdir, open, rename, rm, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { parse } from 'yaml';
import { z } from 'zod';
import type { ReviewedTool } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { TarError, readTarMember } from '../util/tar.js';
import { COOLDOWN_DAYS, downloadRelease } from './pin.js';
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
const DAY_MS = 86_400_000;
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
  /** Default: Date.now (for the 7-day cooldown check). */
  now?: () => number;
  /** The home directory the default cache (~/.cache/pipegen/tools) is under. Default: os.homedir(). */
  home?: string;
  /** The user the cache directories must belong to. Default: process.getuid(). */
  uid?: number;
}

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const isMissing = (e: unknown) => (e as { code?: unknown } | null)?.code === 'ENOENT';

/**
 * Downloads (once) and verifies the pinned `name` binary for this platform, and returns its absolute path in
 * `<cacheDir>/<name>-<version>/<name>` (default cacheDir: ~/.cache/pipegen/tools). The returned file was hashed
 * just now and matched the pinned binarySha256. Throws PinnedBinaryError when anything doesn't check out; a
 * binary that fails a check is deleted and never run.
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
    throw new PinnedBinaryError(`audit --ai needs Linux or macOS for now (WSL works). pipegen has no pinned ${name} for ${key}; it supports linux and darwin on x64 and arm64.`);
  }
  const asset = entry.platforms[key as PlatformKey];

  // cooldown (ruling S26): a pin of a release under 7 days old (or dated in the future) is not used
  const now = (deps.now ?? Date.now)();
  const released = Date.parse(entry.releasedAt);
  if (!Number.isFinite(released) || released > now) throw new PinnedBinaryError(`The pinned ${what} has a release date in the future, which pipegen can't trust.`);
  if (now - released < COOLDOWN_DAYS * DAY_MS) throw new PinnedBinaryError(`The pinned ${what} was released less than ${COOLDOWN_DAYS} days ago; pipegen waits ${COOLDOWN_DAYS} days before using a new release.`);

  const uid = deps.uid ?? process.getuid?.();
  if (uid === undefined) throw new PinnedBinaryError('pipegen could not tell which user it runs as, so it will not set up its tool cache.');
  const toolDir = await prepareCache(name, entry.version, cacheDir, deps.home, uid);
  const target = join(toolDir, name);

  // a cached copy: re-checked before every use
  if ((await lstat(target).catch((e: unknown) => (isMissing(e) ? null : Promise.reject(e)))) !== null) {
    return verifyCached(target, asset, what, uid);
  }

  // download, then check the archive hash BEFORE unpacking anything
  let archive: Uint8Array;
  try {
    archive = await downloadRelease(deps.fetch ?? fetch, asset.url, asset.archiveSize);
  } catch (e) {
    throw new PinnedBinaryError(`Couldn't download ${what}: ${e instanceof Error ? e.message : 'unknown error'}`, { cause: e });
  }
  if (archive.length !== asset.archiveSize || sha256(archive) !== asset.archiveSha256) {
    throw new PinnedBinaryError(`The download of ${what} doesn't match its pinned checksum, so pipegen refused it. Nothing was unpacked or run.`);
  }

  // unpack in-process (no child process), then check the binary hash
  const binary = asset.archive === 'none' ? Buffer.from(archive) : unpack(archive, entry.member, asset, what);
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
  return verifyCached(target, asset, what, uid);
}

/** gunzip (bounded) + the in-process tar reader. */
function unpack(archive: Uint8Array, member: string, asset: PinnedAsset, what: string): Buffer {
  const limit = asset.binarySize + TAR_SLACK_BYTES;
  let tar: Buffer;
  try {
    tar = gunzipSync(archive, { maxOutputLength: limit });
  } catch (e) {
    const tooLarge = e instanceof RangeError || (e as { code?: unknown } | null)?.code === 'ERR_BUFFER_TOO_LARGE';
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
 * Hashes the cached file (opened without following links) and returns its path only when it matches. A file that
 * isn't a regular file of this user, or whose hash or size differ, is deleted and refused: it is never run.
 */
async function verifyCached(path: string, asset: PinnedAsset, what: string, uid: number): Promise<string> {
  const refuse = async (why: string): Promise<never> => {
    await unlink(path).catch(() => {});
    throw new PinnedBinaryError(`The cached ${what} at ${path} ${why}, so pipegen deleted it and won't run it. Run the command again to download a fresh, verified copy.`);
  };
  const info = await lstat(path);
  if (info.isDirectory()) throw new PinnedBinaryError(`The cached ${what} at ${path} is not a regular file (it is a directory); pipegen won't run it. Remove it and try again.`);
  if (!info.isFile()) return refuse('is not a regular file (it is a link or a special file)');
  if (info.uid !== uid) return refuse('is not owned by you');
  let fh;
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    return refuse('could not be opened safely');
  }
  const hash = createHash('sha256');
  let size = 0;
  try {
    const opened = await fh.stat();
    if (!opened.isFile() || opened.ino !== info.ino || opened.dev !== info.dev) return await refuse('changed while pipegen was checking it');
    const buf = Buffer.alloc(READ_CHUNK);
    for (;;) {
      const { bytesRead } = await fh.read(buf, 0, READ_CHUNK, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      if (size > asset.binarySize) break; // already wrong: no need to read the rest
      hash.update(buf.subarray(0, bytesRead));
    }
  } finally {
    await fh.close();
  }
  if (size !== asset.binarySize || hash.digest('hex') !== asset.binarySha256) return refuse('changed since pipegen verified it (its checksum no longer matches)');
  return path;
}

/**
 * Creates (0700) and checks every level of the cache path pipegen owns, and returns `<root>/<name>-<version>`.
 * Default root: <home>/.cache/pipegen/tools, where `.cache` may already exist (it must still be a real directory
 * of this user that others can't write to). A given cacheDir is created with its parents; it and the tool dir are
 * checked. Every level is lstat'ed: a symlink, another owner, or group/other write access is refused.
 */
async function prepareCache(name: string, version: string, cacheDir: string | undefined, home: string | undefined, uid: number): Promise<string> {
  let root: string;
  if (cacheDir === undefined) {
    const base = join(home ?? homedir(), '.cache');
    await level(base, uid, 0o002);
    await level(join(base, 'pipegen'), uid, 0o022);
    root = join(base, 'pipegen', 'tools');
  } else {
    // the parents of a given cache dir are the caller's choice; the dir itself must be pipegen's own
    if ((await lstat(cacheDir).catch((e: unknown) => (isMissing(e) ? null : Promise.reject(e)))) === null) {
      await mkdir(cacheDir, { recursive: true, mode: 0o700 });
    }
    root = cacheDir;
  }
  await level(root, uid, 0o022);
  const toolDir = join(root, `${name}-${version}`);
  await level(toolDir, uid, 0o022);
  return toolDir;
}

/** One level of the cache path: created 0700 when missing, then lstat'ed and checked. */
async function level(dir: string, uid: number, forbiddenModeBits: number): Promise<void> {
  try {
    await mkdir(dir, { mode: 0o700 });
  } catch (e) {
    if ((e as { code?: unknown } | null)?.code !== 'EEXIST') throw new PinnedBinaryError(`Couldn't create pipegen's tool cache directory ${dir}.`, { cause: e });
  }
  const info = await lstat(dir);
  if (info.isSymbolicLink()) throw new PinnedBinaryError(`pipegen's tool cache path ${dir} is a symbolic link; pipegen won't keep tools there. Remove the link and try again.`);
  if (!info.isDirectory()) throw new PinnedBinaryError(`pipegen's tool cache path ${dir} is not a directory.`);
  if (info.uid !== uid) throw new PinnedBinaryError(`pipegen's tool cache directory ${dir} is not owned by you; pipegen won't keep tools there.`);
  if ((info.mode & forbiddenModeBits) !== 0) throw new PinnedBinaryError(`Other users can write to pipegen's tool cache directory ${dir}; pipegen won't keep tools there. Run: chmod 700 '${dir}'`);
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
