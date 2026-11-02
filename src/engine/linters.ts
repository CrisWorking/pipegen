// Pinned tool binaries pipegen runs on the user's machine (Plan B Task 7 Part 1): betterleaks for the required code
// bundle secret scan (Plan A Task 5, `audit --ai`; Plan P Task 7), gitleaks as its fallback, actionlint and zizmor (the
// referee's workflow linters, 7b), and cosign. A
// wrong or tampered binary must never run.
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
// - v0.1 supports linux and darwin on x64 and arm64 (ruling S27). The 7-day cooldown (S26) is checked against each
//   entry's own pinnedOn when the file is read (and by a data-file test), not against today's date.
// - Like reviewed-tools.yml, every entry carries a human-review marker (reviewedBy / reviewedAt, PENDING until the
//   owner reviews it; review-marker.ts). A release build (PIPEGEN_RELEASE or NODE_ENV=production) refuses the
//   file while any entry is PENDING, before anything is downloaded; dev and test builds load it (final review I2).
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, rename, rm, unlink } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { parse } from 'yaml';
import { z } from 'zod';
import type { CreatedFile, ReviewedTool } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
// fix round 4 (B7): every cut of linter output (and of the files' paths) scrubs with the active vault first (the referee's)
import { activeSafeText as safeText } from '../util/known-values.js';
import { prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { TarError, readTarMember } from '../util/tar.js';
import { COOLDOWN_DAYS, downloadRelease } from './pin.js';
import { isReleaseBuild, listPending, PENDING, reviewMarkerProblems } from './review-marker.js';
import { ACTION_PATH_RE, WORKFLOW_PATH_RE } from './job-rules.js';
import { ASSET_RE, isGitHubRepo, SHA256_RE } from './names.js';
import type { Linters, RefereeIssue } from './referee.js';
import { loadReviewed } from './reviewed.js';

export type PinnedName = 'actionlint' | 'betterleaks' | 'cosign' | 'gitleaks' | 'zizmor';
export const PINNED_NAMES: readonly PinnedName[] = ['actionlint', 'betterleaks', 'cosign', 'gitleaks', 'zizmor'];
export const PLATFORM_KEYS = ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'] as const;
export type PlatformKey = (typeof PLATFORM_KEYS)[number];

/** Upper bounds for any pinned asset (the real values are far below; cosign is the largest at about 150 MB). */
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_BINARY_BYTES = 512 * 1024 * 1024;
/** How much more than the binary itself a tar may unpack to (licence, readme, docs). Bounds a gzip bomb. */
export const TAR_SLACK_BYTES = 16 * 1024 * 1024;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const READ_CHUNK = 1024 * 1024;
const DAY_MS = 86_400_000;

const assetSchema = z.object({
  url: z.string(),
  archive: z.enum(['tar.gz', 'none']),
  archiveSize: z.number().int().positive().max(MAX_ARCHIVE_BYTES),
  archiveSha256: z.string().regex(SHA256_RE),
  binarySize: z.number().int().positive().max(MAX_BINARY_BYTES),
  binarySha256: z.string().regex(SHA256_RE),
}).strict().refine((a) => a.archive !== 'none' || (a.archiveSha256 === a.binarySha256 && a.archiveSize === a.binarySize), {
  message: 'a raw binary (archive: none) has one hash and one size: archiveSha256 = binarySha256, archiveSize = binarySize',
});

const entrySchema = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  repo: z.string().refine(isGitHubRepo, 'not a GitHub owner/name'),
  releasedAt: z.string().regex(ISO_DATE_RE),
  /** When this entry was pinned; releasedAt must be at least the cooldown before it (ruling S26). */
  pinnedOn: z.string().regex(ISO_DATE_RE),
  /** The human review (review-marker.ts): PENDING until the owner reviews the entry, then a name and a date. */
  reviewedBy: z.string().max(100),
  reviewedAt: z.string().max(20),
  /** The file to take out of the archive (a plain name, no directory). */
  member: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/),
  platforms: z.object(Object.fromEntries(PLATFORM_KEYS.map((k) => [k, assetSchema])) as Record<PlatformKey, typeof assetSchema>).strict(),
}).strict().superRefine((e, ctx) => {
  for (const p of reviewMarkerProblems(e.reviewedBy, e.reviewedAt, e.pinnedOn.slice(0, 10))) ctx.addIssue({ code: 'custom', path: [p.field], message: p.message });
  if (!(Date.parse(e.pinnedOn) - Date.parse(e.releasedAt) >= COOLDOWN_DAYS * DAY_MS)) {
    ctx.addIssue({ code: 'custom', path: ['pinnedOn'], message: `the release must be at least ${COOLDOWN_DAYS} days older than pinnedOn (cooldown, ruling S26)` });
  }
  for (const key of PLATFORM_KEYS) {
    if (!isReleaseUrl(e.platforms[key].url, e.repo, e.version)) {
      ctx.addIssue({ code: 'custom', path: ['platforms', key, 'url'], message: `must be https://github.com/${e.repo}/releases/download/v${e.version}/<asset>` });
    }
  }
});

/** data/pinned-binaries.yml: exactly betterleaks, gitleaks, actionlint, cosign and zizmor. */
export const pinnedBinariesSchema = z.object({ betterleaks: entrySchema, gitleaks: entrySchema, actionlint: entrySchema, cosign: entrySchema, zizmor: entrySchema }).strict();
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

/** Validates the pins; a release build also refuses them while any entry is PENDING review (like loadReviewed). */
function checkPins(raw: unknown): PinnedBinaries {
  const parsed = pinnedBinariesSchema.safeParse(raw);
  if (!parsed.success) {
    const where = parsed.error.issues[0]?.path.join('.') ?? '';
    throw new PinnedBinaryError(`pipegen's pinned-binaries data is invalid${where === '' ? '' : ` (at ${where})`}.`);
  }
  if (isReleaseBuild()) {
    const pending = PINNED_NAMES.filter((n) => parsed.data[n].reviewedBy === PENDING);
    if (pending.length > 0) {
      throw new PinnedBinaryError(`This pipegen release refuses its pinned binaries: ${pending.length} of them still wait for human review (${listPending([...pending])}). pipegen runs nothing unreviewed on your machine.`);
    }
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

const CACHE_KIND: TrustedDirKind = {
  noun: 'tool cache', keeping: 'tools', risk: 'swap the tool pipegen runs',
  error: (message, cause) => new PinnedBinaryError(message, cause === undefined ? undefined : { cause }),
};

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
  if (cacheDir !== undefined) return prepareTrustedDir(cacheDir, [`${name}-${version}`], true, uid, CACHE_KIND);
  const xdg = (deps.env ?? process.env).XDG_CACHE_HOME;
  const base = xdg !== undefined && isAbsolute(xdg) ? xdg : join(deps.home ?? homedir(), '.cache');
  return prepareTrustedDir(base, ['pipegen', 'tools', `${name}-${version}`], false, uid, CACHE_KIND);
}

/**
 * Ruling S25: a tool pinned here and also listed in reviewed-tools.yml (for user CI) must be the same release.
 * Returns one plain-English problem per mismatch (empty = consistent). A reviewed CLI entry from the same GitHub
 * repo must have the same version, must install an asset this file pins for some platform, and every hash it
 * carries must be that platform's archive or binary hash (not merely some platform's). Task 8 calls this on the
 * real lists.
 */
export function checkPinnedAgainstReviewed(pins: PinnedBinaries, reviewed: readonly ReviewedTool[]): string[] {
  const problems: string[] = [];
  for (const name of PINNED_NAMES) {
    const entry = pins[name];
    for (const tool of reviewed) {
      const c = tool.candidate;
      if (c.kind !== 'cli' || typeof c.repo !== 'string' || c.repo.toLowerCase() !== entry.repo.toLowerCase()) continue;
      const id = safeText(tool.id, 80);
      if (c.version.replace(/^v/, '') !== entry.version) {
        problems.push(`${name}: the reviewed entry ${id} is version ${safeText(c.version, 40)}, but pinned-binaries.yml pins ${entry.version}.`);
      }
      const asset = tool.step.cli?.install.package;
      const platform = PLATFORM_KEYS.find((k) => typeof asset === 'string' && entry.platforms[k].url.endsWith(`/${asset}`));
      if (platform === undefined) {
        problems.push(`${name}: the reviewed entry ${id} installs a release asset pinned-binaries.yml doesn't list for ${entry.version}.`);
        continue;
      }
      const hashes = [c.pin.checksum, tool.step.cli?.install.checksum].filter((h): h is string => typeof h === 'string');
      if (hashes.length === 0) {
        problems.push(`${name}: the reviewed entry ${id} has no hash to compare with pinned-binaries.yml.`);
        continue;
      }
      const known = new Set([entry.platforms[platform].archiveSha256, entry.platforms[platform].binarySha256]);
      for (const h of new Set(hashes)) {
        if (!known.has(h.toLowerCase())) problems.push(`${name}: the reviewed entry ${id} has a hash that pinned-binaries.yml doesn't list for ${entry.version} ${platform}.`);
      }
    }
  }
  return problems;
}

// ---------- the referee's workflow linters (Plan B Task 7b, rulings S19 to S21) ----------
//
// ensureLinters: closures that give the pinned actionlint and zizmor. Each call runs ensurePinnedBinary again (the hash
// is re-checked) right before the spawn, so a binary swapped in the cache between two runs is never run (S20).
//
// runLinters: the linters run on a fresh temporary copy of the workflow files, one copy per repository (`app`,
// `central`). Nothing else is copied, and every run gets an explicit config path, so a repo's own .github/zizmor.yml,
// zizmor.yml or .github/actionlint.yaml is never read. The configs are the reviewed entries' pinned config text.
// Chosen: the central repo's composite action files (the referee still parses them) are copied too, and only zizmor
// reads them; actionlint gets the workflow files. zizmor runs with --no-ignores (no inline `# zizmor: ignore[...]`
// comment can silence a finding) and --strict-collection (an input it can't validate fails the run instead of being
// skipped with a warning). Anything that is not such a file is not copied and is an issue (it
// was not linted, so it is not cleared). The linters start with an empty environment plus what they need (S19).

const LINTER_TIMEOUT_MS = 120_000;
const LINTER_MAX_OUTPUT = 16 * 1024 * 1024;
/** zizmor's exit codes: 0 nothing found; 10 to 14 findings (by severity). Anything else is a failure. */
const ZIZMOR_FINDING_CODES: ReadonlySet<number> = new Set([10, 11, 12, 13, 14]);

/** The pinned linters as closures (nothing is downloaded until one is called). */
export function ensureLinters(cacheDir?: string, deps: PinnedBinaryDeps = {}): Linters {
  return {
    actionlint: () => ensurePinnedBinary('actionlint', cacheDir, deps),
    zizmor: () => ensurePinnedBinary('zizmor', cacheDir, deps),
  };
}

export interface RunLintersDeps {
  /** The reviewed list the pinned linter configs come from. Default: the real one. */
  reviewed?: ReviewedTool[];
  /** Default: the system temp directory. */
  tmp?: string;
  timeoutMs?: number;
}

/** A file path that may be copied: a workflow, or a composite action file (job-rules.ts: no `.`, `..` or empty segment). */
function lintablePath(path: string): 'workflow' | 'action' | null {
  if (WORKFLOW_PATH_RE.test(path)) return 'workflow';
  return ACTION_PATH_RE.test(path) ? 'action' : null;
}

/** The pinned config text of a reviewed linter (fixedInputs.config.content). */
function pinnedConfig(reviewed: readonly ReviewedTool[], id: string): string {
  const content = reviewed.find((t) => t.id === id)?.fixedInputs.config?.content;
  if (typeof content !== 'string') throw new PinnedBinaryError(`pipegen has no pinned config for ${id}.`);
  return content;
}

interface RunResult { code: number | null; stdout: string; failed: string | null }

/** Runs a linter with exactly this environment (nothing inherited); never throws. */
function spawnLinter(bin: string, args: string[], cwd: string, env: Record<string, string>, timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(bin, args, { cwd, env, timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: LINTER_MAX_OUTPUT, windowsHide: true, encoding: 'utf8' }, (err, stdout) => {
      if (err === null) return resolve({ code: 0, stdout, failed: null });
      const code = (err as { code?: unknown }).code;
      if (typeof code === 'number') return resolve({ code, stdout, failed: null });
      resolve({ code: null, stdout, failed: typeof code === 'string' ? code : 'did not finish' });
    });
  });
}

function parseJsonArray(text: string): unknown[] | null {
  try {
    const v: unknown = JSON.parse(text);
    return Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const cleanPath = (p: string): string => p.replace(/^(\.\/)+/, '');

type Issue = (check: 'actionlint' | 'zizmor', file: string, message: string, line?: number) => RefereeIssue;

function actionlintFindings(items: unknown[], issue: Issue, fallback: string): RefereeIssue[] {
  return items.map((it) => {
    const o = isObj(it) ? it : {};
    const line = typeof o.line === 'number' && Number.isInteger(o.line) && o.line > 0 ? o.line : undefined;
    return issue('actionlint', typeof o.filepath === 'string' ? cleanPath(o.filepath) : fallback, typeof o.message === 'string' ? o.message : 'a finding without a message', line);
  });
}

function zizmorFindings(items: unknown[], issue: Issue, fallback: string): RefereeIssue[] {
  return items.map((it) => {
    const o = isObj(it) ? it : {};
    const locations = Array.isArray(o.locations) ? o.locations.filter(isObj) : [];
    const loc = locations.find((l) => isObj(l.symbolic) && l.symbolic.kind === 'Primary') ?? locations[0];
    const symbolic = isObj(loc?.symbolic) ? loc.symbolic : {};
    const key = isObj(symbolic.key) ? symbolic.key : {};
    const local = isObj(key.Local) ? key.Local : {};
    const concrete = isObj(loc?.concrete) ? loc.concrete : {};
    const point = isObj(concrete.location) && isObj(concrete.location.start_point) ? concrete.location.start_point : {};
    // zizmor counts rows from 0
    const line = typeof point.row === 'number' && Number.isInteger(point.row) && point.row >= 0 ? point.row + 1 : undefined;
    const ident = typeof o.ident === 'string' ? o.ident : 'finding';
    const desc = typeof o.desc === 'string' ? o.desc : '';
    const note = typeof symbolic.annotation === 'string' && symbolic.annotation !== '' ? `: ${symbolic.annotation}` : '';
    return issue('zizmor', typeof local.verbatim_path === 'string' ? cleanPath(local.verbatim_path) : fallback, `${ident}: ${desc}${note}`, line);
  });
}

/**
 * Runs actionlint and zizmor over the workflow files (one temporary copy per repo, pipegen's own configs) and returns
 * their findings as issues, each with its repo, repo-relative file and line. Never throws and never skips silently: a
 * linter that can not start, crashes, exits with an unexpected code or prints JSON that doesn't parse is an issue, and so
 * is a missing token (zizmor's online audits, `impostor-commit` among them, need one; zizmor is then not started).
 */
export async function runLinters(files: CreatedFile[], linters: Linters, ghToken: string | null, deps: RunLintersDeps = {}): Promise<RefereeIssue[]> {
  const out: RefereeIssue[] = [];
  const mk = (repo: CreatedFile['repo']): Issue => (check, file, message, line) => ({
    file: safeText(file, 200), check, message: safeText(message, 300), repo, ...(line === undefined ? {} : { line }),
  });
  let reviewed: ReviewedTool[];
  try {
    reviewed = deps.reviewed ?? loadReviewed();
  } catch (e) {
    return [{ file: files[0]?.path ?? '', check: 'actionlint', message: safeText(`The workflow linters could not run: pipegen's reviewed list could not be read (${e instanceof Error ? e.message : 'error'}).`, 300) }];
  }
  let configs: { actionlint: string; zizmor: string };
  try {
    configs = { actionlint: pinnedConfig(reviewed, 'actionlint'), zizmor: pinnedConfig(reviewed, 'zizmor') };
  } catch (e) {
    return [{ file: files[0]?.path ?? '', check: 'actionlint', message: safeText(e instanceof Error ? e.message : 'The linter configs are missing.', 300) }];
  }
  const timeoutMs = deps.timeoutMs ?? LINTER_TIMEOUT_MS;

  for (const repo of ['app', 'central'] as const) {
    const mine = files.filter((f) => f.repo === repo);
    if (mine.length === 0) continue;
    const issue = mk(repo);
    const copied: { path: string; kind: 'workflow' | 'action' }[] = [];
    const seen = new Set<string>();
    for (const f of mine) {
      const kind = lintablePath(f.path);
      if (kind === null) out.push(issue('actionlint', f.path, `The file ${safeText(f.path, 80)} is not a workflow file, so it was not copied for the linters and is not cleared.`));
      else if (seen.has(f.path.toLowerCase())) out.push(issue('actionlint', f.path, `The file ${safeText(f.path, 80)} is listed twice (names are compared without case), so it was not linted and is not cleared.`));
      else { seen.add(f.path.toLowerCase()); copied.push({ path: f.path, kind }); }
    }
    if (copied.length === 0) continue;

    const dir = await mkdtemp(join(deps.tmp ?? tmpdir(), 'pipegen-lint-'));
    try {
      // the temp copy: workflow and action files only, exclusive create, no symlink followed
      const writeOne = async (rel: string, content: string): Promise<void> => {
        await mkdir(dirname(join(dir, rel)), { recursive: true, mode: 0o700 });
        const fh = await open(join(dir, rel), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try { await fh.writeFile(content); } finally { await fh.close(); }
      };
      const written: typeof copied = [];
      for (const c of copied) {
        try {
          await writeOne(c.path, (mine.find((f) => f.path === c.path) as CreatedFile).content);
          written.push(c);
        } catch {
          out.push(issue('actionlint', c.path, `The file ${safeText(c.path, 80)} could not be copied for the linters, so it is not cleared.`));
        }
      }
      if (written.length === 0) continue;
      await writeOne('actionlint.yaml', configs.actionlint);
      await writeOne('zizmor.yml', configs.zizmor);
      await mkdir(join(dir, 'zizmor-cache'), { mode: 0o700 });
      const first = written[0]?.path ?? '';

      // actionlint reads workflows only
      const workflows = written.filter((c) => c.kind === 'workflow').map((c) => c.path);
      if (workflows.length > 0) {
        let bin: string | null = null;
        try {
          bin = await linters.actionlint();
        } catch (e) {
          out.push(issue('actionlint', first, `actionlint could not be set up: ${e instanceof Error ? e.message : 'unknown error'} It was not run, so the files are not cleared.`));
        }
        if (bin !== null) {
          const r = await spawnLinter(bin, ['-config-file', join(dir, 'actionlint.yaml'), '-shellcheck=', '-pyflakes=', '-format', '{{json .}}', ...workflows], dir, { HOME: dir, NO_COLOR: '1' }, timeoutMs);
          if (r.code === 0) {
            // clean: nothing printed (or an empty list)
            const items = r.stdout.trim() === '' ? [] : parseJsonArray(r.stdout);
            if (items === null) out.push(issue('actionlint', first, 'actionlint said it found nothing but printed output pipegen could not read, so the files are not cleared.'));
            else out.push(...actionlintFindings(items, issue, first));
          } else if (r.code === 1) {
            const items = parseJsonArray(r.stdout);
            if (items === null || items.length === 0) out.push(issue('actionlint', first, 'actionlint reported problems but its output could not be read, so the files are not cleared.'));
            else out.push(...actionlintFindings(items, issue, first));
          } else {
            out.push(issue('actionlint', first, r.failed === null ? `actionlint failed (exit ${r.code}), so the files are not cleared.` : `actionlint could not run (${safeText(r.failed, 40)}), so the files are not cleared.`));
          }
        }
      }

      // zizmor, online: needs a token (impostor-commit and the other online audits); never a silent offline run
      if (ghToken === null) {
        out.push(issue('zizmor', first, 'zizmor was not run: it needs a GitHub token for its online audits (the impostor-commit check among them), and none was given, so the files are not cleared.'));
      } else {
        let bin: string | null = null;
        try {
          bin = await linters.zizmor();
        } catch (e) {
          out.push(issue('zizmor', first, `zizmor could not be set up: ${e instanceof Error ? e.message : 'unknown error'} It was not run, so the files are not cleared.`));
        }
        if (bin !== null) {
          const r = await spawnLinter(bin, ['--config', join(dir, 'zizmor.yml'), '--format', 'json', '--no-ignores', '--strict-collection', '--cache-dir', join(dir, 'zizmor-cache'), ...written.map((c) => c.path)], dir, { GH_TOKEN: ghToken, HOME: dir, NO_COLOR: '1' }, timeoutMs);
          if (r.code !== null && (r.code === 0 || ZIZMOR_FINDING_CODES.has(r.code))) {
            const items = parseJsonArray(r.stdout);
            if (items === null) out.push(issue('zizmor', first, 'zizmor printed output pipegen could not read, so the files are not cleared.'));
            else if (items.length === 0 && r.code !== 0) out.push(issue('zizmor', first, `zizmor reported findings (exit ${r.code}) but its list was empty, so the files are not cleared.`));
            else out.push(...zizmorFindings(items, issue, first));
          } else {
            out.push(issue('zizmor', first, r.failed === null ? `zizmor failed (exit ${r.code}), so the files are not cleared.` : `zizmor could not run (${safeText(r.failed, 40)}), so the files are not cleared.`));
          }
        }
      }
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  }
  return out;
}
