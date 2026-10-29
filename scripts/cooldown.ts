// 7-day cooldown check (DECISIONS #92), run by the `cooldown` job in .github/workflows/ci.yml on pull requests.
//
// It compares the BASE and HEAD copies of package-lock.json, data/reviewed-tools.yml and data/pinned-binaries.yml and
// fails when something new or changed is younger than 7 days. The date always comes from upstream, never from a
// date written in the file, and the pin must be tied to that upstream release:
//   - npm lockfile entries that are new or whose version/resolved/integrity changed (transitive ones too): the
//     name comes from the node_modules path, the version must exist in the registry, `resolved` must be the
//     registry tarball and `integrity` must equal the registry's dist.integrity; date = registry `time[version]`.
//     A packument over the byte cap (vite) is read as its version document (/<name>/<version>) for the integrity,
//     dated by the Last-Modified of a HEAD on the registry tarball (never earlier than the publish), never a bigger cap;
//   - reviewed tools (whole entry diffed): an action's SHA must be the commit of its tag, a release binary's asset
//     digest must belong to that GitHub release, a docker digest must be the tag's digest on Docker Hub, an npm/pip
//     tool's package (step.cli.install.package) is tied to candidate.pin.checksum and each step.cli.plugins entry to
//     its own checksum on its registry; date = release published_at / registry time. Archives a tool downloads at run
//     time, pinned in step.cli.env: the nuclei templates tarball must be listed with its sha256 in the release's
//     checksums file (GitHub records that file's digest) or be a release asset with that digest, dated by the release;
//     the semgrep rules commit's tree must be PIPEGEN_RULES_TREE, dated by GitHub's signature verified_at (the git
//     dates are the pusher's). A hash- or URL-shaped value at any field this script doesn't know fails, and so do a
//     duplicate or missing id;
//   - pinned binaries: every platform url and sha256 must belong to the GitHub release of that version.
// Anything that can't be tied and dated (lookup failed, 404, no digest, unreadable date, date in the future,
// a kind this script doesn't know) fails closed. A docker pin it can't date says "needs owner review".
//
// Emergency path (DECISIONS #103): when the only problem left is age, a PR labelled `security-fix` by a code owner
// passes anyway. Code owners are the users on the BASE commit's `.github/CODEOWNERS` `/data/` and `/scripts/` lines.
// The PR body needs a `Security-fix-reason:` line, and the grant is tied to the current head commit by a review, whose
// commit_id GitHub sets: with one owner, that owner's review on the head (APPROVED or COMMENTED, so it works on their
// own PR) with a line `Security-fix-approved`; with two or more, approvals on the head from owners other than the PR
// author (two, or one when the author is one of only two owners). So every new push needs a new review. The label is
// read from the API (PR labels and the latest `labeled` event), never from the event payload, and any API error fails
// closed. The young items and the reason are printed, so the exception stays visible.
//
// The CI job runs the BASE commit's copy of this file against the PR's files, so a PR can't weaken the check that
// judges it. Keep it dependency-free apart from `yaml`, and keep to syntax Node's type stripping can run
// (no enums, no parameter properties, no namespaces): `node scripts/cooldown.ts`.
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export const COOLDOWN_DAYS = 7;
export const MAX_LOOKUPS = 150;
export const LOOKUP_TIMEOUT_MS = 15_000;
export const MAX_BODY_BYTES = 32 * 1024 * 1024;
const DAY_MS = 86_400_000;
const CONCURRENCY = 6;

export const WATCHED_FILES = ['package.json', 'package-lock.json', 'data/reviewed-tools.yml', 'data/pinned-binaries.yml'] as const;
/** Read from the base checkout only: it names who may grant the emergency path. */
export const CODEOWNERS_FILE = '.github/CODEOWNERS';
/** File contents by repo-relative path; a missing file is absent or null. */
export type Files = Partial<Record<string, string | null>>;

export interface Finding {
  kind: 'npm' | 'pypi' | 'reviewed-tool' | 'pinned-binary' | 'lockfile' | 'security-fix';
  name: string;
  version: string;
  /** ISO publish date used for the decision, or null when none could be found. */
  date: string | null;
  /** What is wrong, in plain English. */
  problem: string;
  /** True when the problem is a failed lookup (retrying may help). */
  lookupFailed: boolean;
  /** True when the only problem is age (a readable upstream date under 7 days): the one thing `security-fix` lifts. */
  young: boolean;
}

/** How the emergency path was granted: by whom, why, and who confirmed or approved the head commit. */
export interface Emergency {
  labelledBy: string;
  reason: string;
  /** One owner: the owner whose `Security-fix-approved` review is on the head. Two or more: the approving owners. */
  approvers: string[];
  oneOwner: boolean;
}

export interface CooldownResult {
  ok: boolean;
  checked: number;
  findings: Finding[];
  /** Young items that passed only because of the `security-fix` label. */
  waived: Finding[];
  emergency?: Emergency;
  notes: string[];
}

/** The pull request being checked; without it there is no emergency path (local runs). */
export interface PrContext {
  repo: string;
  number: number;
  headSha: string;
}

export interface CooldownOptions {
  base: Files;
  head: Files;
  fetch: typeof fetch;
  now: Date;
  githubToken?: string;
  pr?: PrContext;
  maxLookups?: number;
  timeoutMs?: number;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);

/** A stable text for a value (keys sorted), minus the named keys at any depth. */
function canon(v: unknown, skip: ReadonlySet<string> = new Set()): string {
  const walk = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(walk);
    if (isObj(x)) return Object.fromEntries(Object.keys(x).filter((k) => !skip.has(k)).sort().map((k) => [k, walk(x[k])]));
    return x;
  };
  return JSON.stringify(walk(v)) ?? 'null';
}

class FileError extends Error {}

function yamlObj(file: string, text: string | null | undefined): Obj {
  if (!text) return {};
  let v: unknown;
  try {
    v = parseYaml(text);
  } catch {
    throw new FileError(`${file} is not valid YAML`);
  }
  return isObj(v) ? v : {};
}

// --- npm lockfile -------------------------------------------------------------------------------------------------

const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
const NPM_NAME = /^(@[a-z0-9~._-]+\/)?[a-z0-9~._-]+$/i;
export const REGISTRY = 'https://registry.npmjs.org/';

export interface LockEntry {
  /** The real package name (from the node_modules path; an alias resolves to the name in `resolved`). */
  name: string;
  version: string;
  resolved: string | undefined;
  integrity: string | undefined;
  /** Why this entry can't be trusted, if so. */
  bad?: string;
}

function parseLock(text: string): Obj {
  try {
    const v: unknown = JSON.parse(text);
    if (isObj(v)) return v;
  } catch {
    /* falls through */
  }
  throw new FileError('package-lock.json is not valid JSON');
}

/** Why a lockfile can't be read at all (old format, no `packages`), or undefined. */
export function lockfileProblem(text: string | null | undefined): string | undefined {
  if (!text) return undefined;
  const lock = parseLock(text);
  if (typeof lock.lockfileVersion !== 'number' || lock.lockfileVersion < 2) return 'lockfileVersion is below 2, so entries can not be verified';
  if (!isObj(lock.packages)) return 'the lockfile has no `packages` section, so entries can not be verified';
  return undefined;
}

/** The `workspaces` globs of a root package.json (array form or `{ packages }`). */
export function workspaceGlobs(pkgJson: string | null | undefined): string[] {
  if (!pkgJson) return [];
  let v: unknown;
  try {
    v = JSON.parse(pkgJson);
  } catch {
    throw new FileError('package.json is not valid JSON');
  }
  const w = isObj(v) ? v.workspaces : undefined;
  const list = Array.isArray(w) ? w : isObj(w) && Array.isArray(w.packages) ? w.packages : [];
  return list.filter((x): x is string => typeof x === 'string').map((g) => g.replace(/^\.\//, '').replace(/\/+$/, ''));
}

function isWorkspacePath(path: string, globs: readonly string[]): boolean {
  const p = path.replace(/^\.\//, '').replace(/\/+$/, '');
  if (p === '' || p.startsWith('/') || p.split('/').includes('..')) return false;
  return globs.some((g) => {
    const re = g.split('**').map((part) => part.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]+')).join('.+');
    return new RegExp(`^${re}$`).test(p);
  });
}

const REMOTE = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Entries of a package-lock.json. A key outside node_modules/, or a `link: true` entry, is skipped only when it is
 * a workspace declared in the root package.json and has no remote `resolved` and no `integrity`; any other such
 * entry is returned with `bad` set, so it fails.
 */
export function lockEntries(text: string | null | undefined, workspaces: readonly string[] = []): LockEntry[] {
  if (!text || lockfileProblem(text)) return [];
  const packages = (parseLock(text).packages ?? {}) as Obj;
  const out: LockEntry[] = [];
  for (const [path, entry] of Object.entries(packages)) {
    if (path === '' || !isObj(entry)) continue;
    const idx = path.lastIndexOf('node_modules/');
    if (idx < 0 || entry.link === true) {
      // A workspace member (by path), or a link to one.
      const target = entry.link === true ? str(entry.resolved) : path;
      const remote = REMOTE.test(str(entry.resolved) ?? '') || entry.integrity !== undefined;
      if (target !== undefined && !remote && isWorkspacePath(target, workspaces)) continue;
      out.push({ name: path, version: str(entry.version) ?? '', resolved: str(entry.resolved), integrity: str(entry.integrity), bad: 'a lockfile key outside node_modules/ or a link that is not a declared workspace (root package.json `workspaces`) with a local path' });
      continue;
    }
    const pathName = path.slice(idx + 'node_modules/'.length);
    const version = str(entry.version) ?? '';
    const resolved = str(entry.resolved);
    const integrity = str(entry.integrity);
    let name = pathName;
    let bad: string | undefined;
    const claimed = str(entry.name);
    if (claimed !== undefined && claimed !== pathName) {
      // Only an npm: alias may differ, and then the tarball must be the claimed package's.
      if (resolved?.startsWith(`${REGISTRY}${claimed}/-/`)) name = claimed;
      else bad = `entry name "${claimed}" differs from its path name "${pathName}" and its tarball does not match`;
    }
    out.push({ name, version, resolved, integrity, ...(bad ? { bad } : {}) });
  }
  return out;
}

const entryKey = (e: LockEntry): string => [e.name, e.version, e.resolved ?? '', e.integrity ?? ''].join('\0');

/** Entries in head that base didn't have: a new version, or the same version with another tarball or integrity. */
export function changedLockEntries(base: string | null | undefined, head: string | null | undefined, baseWs: readonly string[] = [], headWs: readonly string[] = []): LockEntry[] {
  const before = new Set(lockEntries(base, baseWs).map(entryKey));
  const seen = new Set<string>();
  const out: LockEntry[] = [];
  for (const e of lockEntries(head, headWs).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))) {
    const k = entryKey(e);
    if (before.has(k) || seen.has(k)) continue;
    seen.add(k);
    out.push(e);
  }
  return out;
}

// --- bounded network ----------------------------------------------------------------------------------------------

class LookupError extends Error {
  readonly notFound: boolean;
  readonly tooLarge: boolean;
  constructor(message: string, notFound = false, tooLarge = false) {
    super(message);
    this.notFound = notFound;
    this.tooLarge = tooLarge;
  }
}

const tooLarge = (): LookupError => new LookupError('response too large', false, true);

/** HTTP status as a problem; a GitHub API 403/429 says how to give a token (unauthenticated runs hit the rate limit). */
function httpProblem(url: string, res: Response, hasToken: boolean): string {
  const base = `HTTP ${res.status}`;
  if (!url.startsWith('https://api.github.com/') || (res.status !== 403 && res.status !== 429)) return base;
  const limited = res.status === 429 || res.headers.get('x-ratelimit-remaining') === '0';
  const why = limited ? 'GitHub API rate limit reached' : 'GitHub refused the request (rate limit or access)';
  return hasToken
    ? `${base}: ${why}; the GITHUB_TOKEN given may be rate-limited or lack read access`
    : `${base}: ${why}; no GITHUB_TOKEN was set (CI passes github.token; by hand run with GITHUB_TOKEN=$(gh auth token))`;
}

/** Reads a body up to the byte cap, cancelling the stream past it. */
async function readCapped(res: Response): Promise<Buffer> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw tooLarge();
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw tooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

async function request(f: typeof fetch, url: string, init: RequestInit, timeoutMs: number, hasToken: boolean): Promise<Response> {
  let res: Response;
  try {
    res = await f(url, { redirect: 'error', ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new LookupError(`request failed (${e instanceof Error ? e.name : 'error'})`);
  }
  if (res.status === 404) throw new LookupError('not found (404)', true);
  if (!res.ok) throw new LookupError(httpProblem(url, res, hasToken));
  return res;
}

async function getJson(f: typeof fetch, url: string, headers: Record<string, string>, timeoutMs: number, hasToken: boolean): Promise<unknown> {
  const res = await request(f, url, { headers: { accept: 'application/json', ...headers } }, timeoutMs, hasToken);
  try {
    return JSON.parse((await readCapped(res)).toString('utf8'));
  } catch (e) {
    if (e instanceof LookupError) throw e;
    throw new LookupError('unreadable response');
  }
}

/** Every request goes through here: counted against the cap, and one answer per URL (and method). */
interface Ctx {
  get: (url: string, headers?: Record<string, string>) => Promise<unknown>;
  /** A HEAD request's Last-Modified header (undefined when there is none). */
  lastModified: (url: string) => Promise<string | undefined>;
  /**
   * A file's bytes, capped. Redirects are followed (a release asset is served from another host), so the caller must
   * check the bytes against a digest it got from the API.
   */
  bytes: (url: string) => Promise<Buffer>;
  gh: Record<string, string>;
  notes: string[];
}

function makeCtx(opts: CooldownOptions, notes: string[]): Ctx {
  const cap = opts.maxLookups ?? MAX_LOOKUPS;
  const timeout = opts.timeoutMs ?? LOOKUP_TIMEOUT_MS;
  const hasToken = Boolean(opts.githubToken);
  const cache = new Map<string, Promise<unknown>>();
  const once = <T>(key: string, run: () => Promise<T>): Promise<T> => {
    let p = cache.get(key);
    if (!p) {
      p = cache.size >= cap ? Promise.reject(new LookupError(`lookup cap of ${cap} reached; split the PR`)) : run();
      cache.set(key, p);
      p.catch(() => undefined);
    }
    return p as Promise<T>;
  };
  return {
    notes,
    gh: opts.githubToken ? { authorization: `Bearer ${opts.githubToken}` } : {},
    get: (url, headers = {}) => once(url, () => getJson(opts.fetch, url, headers, timeout, hasToken)),
    lastModified: (url) => once(`HEAD ${url}`, async () => {
      const res = await request(opts.fetch, url, { method: 'HEAD' }, timeout, hasToken);
      await res.body?.cancel().catch(() => undefined);
      return str(res.headers.get('last-modified'));
    }),
    bytes: (url) => once(`GET ${url}`, async () => readCapped(await request(opts.fetch, url, { redirect: 'follow' }, timeout, hasToken))),
  };
}

export const npmUrl = (name: string): string => `${REGISTRY}${name.replace('/', '%2f')}`;

const SEGMENT = /^[A-Za-z0-9_.-]+$/;
/** `owner/name` as an encoded URL path, or undefined when a segment is odd or is `.` or `..`. */
export function repoPath(repo: string): string | undefined {
  const parts = repo.split('/');
  if (parts.length !== 2 || parts.some((p) => !SEGMENT.test(p) || p === '.' || p === '..')) return undefined;
  return parts.map(encodeURIComponent).join('/');
}
const TAG = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const tagPath = (tag: string): string | undefined => (TAG.test(tag) && !tag.includes('..') ? encodeURIComponent(tag) : undefined);

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++] as T);
  });
  await Promise.all(workers);
}

// --- tying a pin to an upstream date ------------------------------------------------------------------------------

/** A date (upstream, trusted) or a reason the pin can't be tied to one. */
type Outcome = { date: string } | { problem: string; lookupFailed?: boolean };
const fail = (problem: string): Outcome => ({ problem });

async function guard(fn: () => Promise<Outcome>): Promise<Outcome> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof LookupError) return { problem: `lookup failed: ${e.message}`, lookupFailed: !e.notFound };
    throw e;
  }
}

const sha256Of = (v: unknown): string | undefined => {
  const s = typeof v === 'string' ? v.toLowerCase().replace(/^sha256:/, '') : '';
  return /^[0-9a-f]{64}$/.test(s) ? s : undefined;
};

/** The registry's own tarball URL for a package version. */
const npmTarball = (name: string, version: string): string => `${REGISTRY}${name}/-/${name.includes('/') ? name.slice(name.indexOf('/') + 1) : name}-${version}.tgz`;

const HTTP_DATE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/**
 * An npm package version whose packument is over the byte cap: the version document must be this package version
 * with this integrity and the registry tarball; date = the Last-Modified of that tarball. The registry stores the
 * tarball when the version is published and a version can never be published again, so that date is never earlier
 * than the publish: it can only make a version look younger, never older.
 */
async function npmVersionOutcome(ctx: Ctx, name: string, version: string, integrity: string | undefined): Promise<Outcome> {
  const meta = await ctx.get(`${npmUrl(name)}/${encodeURIComponent(version)}`);
  if (!isObj(meta) || meta.name !== name || meta.version !== version) return fail('the registry version document is not for this package version');
  const dist = isObj(meta.dist) ? meta.dist : {};
  if (!integrity || integrity !== str(dist.integrity)) return fail('integrity does not match the registry dist.integrity');
  const tarball = npmTarball(name, version);
  if (str(dist.tarball) !== tarball) return fail('the registry dist.tarball is not the registry tarball of this version');
  const modified = await ctx.lastModified(tarball);
  if (!modified || !HTTP_DATE.test(modified) || Number.isNaN(Date.parse(modified))) {
    return fail('the packument is over the size cap and the registry tarball has no readable Last-Modified date');
  }
  // The version document's publish stamp, when the registry wrote one, counts too: the LATER of the two decides, so
  // either can only make the version look younger.
  const stamp = publishStamp(meta);
  return { date: new Date(Math.max(Date.parse(modified), stamp ?? 0)).toISOString() };
}

/** The ms timestamp in a version document's `_npmOperationalInternal.tmp` (`tmp/<name>_<version>_<ms>_<random>`), if readable. */
function publishStamp(meta: Obj): number | undefined {
  const tmp = isObj(meta._npmOperationalInternal) ? str(meta._npmOperationalInternal.tmp) : undefined;
  const m = /^tmp\/.+_(\d{12,14})_[0-9.]+$/.exec(tmp ?? '');
  const ms = m ? Number(m[1]) : NaN;
  return Number.isSafeInteger(ms) ? ms : undefined;
}

/** An npm package version: must exist in the registry; integrity must match; date = time[version]. */
async function npmOutcome(ctx: Ctx, name: string, version: string, integrity: string | undefined, resolved?: string): Promise<Outcome> {
  if (!NPM_NAME.test(name)) return fail('unusual package name');
  if (!SEMVER.test(version)) return fail('version is not valid semver');
  if (resolved !== undefined && resolved !== npmTarball(name, version)) return fail(`resolved is not the registry tarball of ${name}@${version}`);
  return guard(async () => {
    let doc: unknown;
    try {
      doc = await ctx.get(npmUrl(name));
    } catch (e) {
      // The full packument of a big package (vite: about 39 MB) is over the cap; the cap stays, the bounded path decides.
      if (e instanceof LookupError && e.tooLarge) return npmVersionOutcome(ctx, name, version, integrity);
      throw e;
    }
    const versions = isObj(doc) && isObj(doc.versions) ? doc.versions : undefined;
    const meta = versions?.[version];
    if (!isObj(meta)) return fail('this version does not exist in the registry');
    const dist = isObj(meta.dist) ? meta.dist : {};
    if (!integrity || integrity !== str(dist.integrity)) return fail('integrity does not match the registry dist.integrity');
    const time = isObj(doc) && isObj(doc.time) ? doc.time : {};
    const date = str(time[version]);
    return date ? { date } : fail('registry has no publish time for this version');
  });
}

/** A PyPI release: the file with this sha256 must exist; date = its upload time. */
async function pypiOutcome(ctx: Ctx, name: string, version: string, checksum: string | undefined): Promise<Outcome> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || !/^[A-Za-z0-9.!+_-]+$/.test(version)) return fail('unusual package name or version');
  const want = sha256Of(checksum);
  if (!want) return fail('no sha256 checksum to tie the pin to');
  return guard(async () => {
    const doc = await ctx.get(`https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);
    const files = isObj(doc) && Array.isArray(doc.urls) ? doc.urls : [];
    const hit = files.find((f) => isObj(f) && isObj(f.digests) && sha256Of(f.digests.sha256) === want);
    const date = isObj(hit) ? str(hit.upload_time_iso_8601) : undefined;
    if (!hit) return fail('no file of this PyPI release has the pinned sha256');
    return date ? { date } : fail('PyPI has no upload time for this file');
  });
}

async function releaseOf(ctx: Ctx, repo: string, tag: string): Promise<{ rel: Obj } | { problem: string }> {
  const r = repoPath(repo);
  const t = tagPath(tag);
  if (!r || !t) return { problem: 'repo or tag name is not a plain name' };
  const rel = await ctx.get(`https://api.github.com/repos/${r}/releases/tags/${t}`, ctx.gh);
  return isObj(rel) ? { rel } : { problem: 'unreadable release answer' };
}

/** Finds the asset by name in a GitHub release and ties it to the sha256; date = release published_at. */
async function assetOutcome(ctx: Ctx, repo: string, tag: string, asset: string, sha: string | undefined): Promise<Outcome> {
  const want = sha256Of(sha);
  if (!want) return fail('no sha256 to tie the asset to');
  return guard(async () => {
    const got = await releaseOf(ctx, repo, tag);
    if ('problem' in got) return got;
    const rel = got.rel;
    const assets = Array.isArray(rel.assets) ? rel.assets : [];
    const hit = assets.find((a) => isObj(a) && a.name === asset);
    if (!isObj(hit)) return fail(`asset ${asset} is not in the GitHub release ${tag}`);
    if (hit.browser_download_url !== `https://github.com/${repo}/releases/download/${tag}/${asset}`) return fail('asset url does not belong to this release');
    const theirs = sha256Of(hit.digest);
    if (!theirs) return fail('GitHub records no digest for this asset; needs owner review');
    if (theirs !== want) return fail('pinned sha256 differs from the digest of the release asset');
    // The youngest of the release date and the asset's own created_at / updated_at counts; any one missing fails.
    return youngest([rel.published_at, hit.created_at, hit.updated_at], 'release published_at, asset created_at and updated_at');
  });
}

/** The youngest of the dates (all must be readable ISO strings), or a failure. */
function youngest(dates: unknown[], what: string): Outcome {
  const ok = dates.map(str).filter((d): d is string => d !== undefined && ISO.test(d) && !Number.isNaN(Date.parse(d)));
  if (ok.length !== dates.length) return fail(`a date is missing or unreadable (needs ${what})`);
  return { date: ok.reduce((a, b) => (Date.parse(b) > Date.parse(a) ? b : a)) };
}

/**
 * What a tag of `r` (an encoded repo path) points to, following annotated tags (at most 3 hops). taggerDate is the
 * youngest tagger date seen, or 'none' for a lightweight tag.
 */
async function tagTarget(ctx: Ctx, r: string, t: string): Promise<{ obj: Obj; taggerDate: unknown }> {
  let ref = await ctx.get(`https://api.github.com/repos/${r}/git/ref/tags/${t}`, ctx.gh);
  let obj = isObj(ref) && isObj(ref.object) ? ref.object : {};
  let taggerDate: unknown = 'none';
  for (let hops = 0; obj.type === 'tag' && hops < 3; hops++) {
    ref = await ctx.get(`https://api.github.com/repos/${r}/git/tags/${encodeURIComponent(String(obj.sha))}`, ctx.gh);
    const tagger = isObj(ref) && isObj(ref.tagger) ? ref.tagger.date : undefined;
    if (taggerDate === 'none' || (str(tagger) && Date.parse(String(tagger)) > Date.parse(String(taggerDate)))) taggerDate = tagger;
    obj = isObj(ref) && isObj(ref.object) ? ref.object : {};
  }
  return { obj, taggerDate };
}

const BRANCH = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

/**
 * Undefined when `sha` is on `repo`'s default branch (an ancestor of its tip, or the tip), else a failure. The branch
 * is read from the repo, never assumed. GitHub serves a commit pushed only to a fork under the upstream repo's API and
 * archive URLs too (forks share objects), so a commit being readable there proves nothing; only the compare does:
 * `<sha>...<branch>` must be `ahead` or `identical`, with no commits behind and `sha` as the merge base.
 */
async function onDefaultBranch(ctx: Ctx, repo: string, sha: string): Promise<Outcome | undefined> {
  const r = repoPath(repo);
  if (!r || !/^[0-9a-f]{40}$/.test(sha)) return fail('repo or commit is not a plain name');
  const info = await ctx.get(`https://api.github.com/repos/${r}`, ctx.gh);
  const branch = isObj(info) ? str(info.default_branch) : undefined;
  if (!branch || !BRANCH.test(branch) || branch.split('/').some((p) => p === '.' || p === '..')) return fail(`${repo} has no readable default branch; needs owner review`);
  let cmp: unknown;
  try {
    cmp = await ctx.get(`https://api.github.com/repos/${r}/compare/${sha}...${branch.split('/').map(encodeURIComponent).join('/')}?per_page=1`, ctx.gh);
  } catch (e) {
    // A 404 says GitHub could not compare at all (the commit or the branch is unknown there), not that the commit is
    // off the branch: report the failed lookup as it is. Still a failure, like every other 404.
    if (e instanceof LookupError && e.notFound) return fail(`lookup failed: GitHub could not compare commit ${sha.slice(0, 12)} with the default branch (${branch}) of ${repo} (404); needs owner review`);
    throw e;
  }
  const on =isObj(cmp) && (cmp.status === 'ahead' || cmp.status === 'identical') && cmp.behind_by === 0 && isObj(cmp.merge_base_commit) && cmp.merge_base_commit.sha === sha;
  return on ? undefined : fail(`commit ${sha.slice(0, 12)} is not on the default branch (${branch}) of ${repo} (a fork's commit, or another branch); needs owner review`);
}

/** An action: the pinned SHA must be the commit its tag points to; date = the tag's release published_at. */
async function actionOutcome(ctx: Ctx, uses: string | undefined, repo: string | undefined, tag: string, sha: string | undefined): Promise<Outcome> {
  const m = /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/[^@]*)?@([0-9a-f]{40})$/.exec(uses ?? '');
  if (!m || !repo || !sha) return fail('action needs `uses: owner/repo@<40-hex sha>`, a repo and a pin sha');
  if (m[1] !== repo || m[2] !== sha) return fail('uses: does not match the candidate repo and pin sha');
  return guard(async () => {
    const r = repoPath(repo);
    const t = tagPath(tag);
    if (!r || !t) return fail('repo or tag name is not a plain name');
    const { obj, taggerDate } = await tagTarget(ctx, r, t);
    if (obj.type !== 'commit' || obj.sha !== sha) return fail('the pinned sha is not the commit of this tag');
    const got = await releaseOf(ctx, repo, tag);
    if ('problem' in got) return got;
    const release = got.rel;
    if (release.tag_name !== tag) return fail('the release is not for this tag');
    const target = str(release.target_commitish);
    if (target && /^[0-9a-f]{40}$/.test(target) && target !== sha) return fail('the release target commit is not the pinned sha');
    const commit = await ctx.get(`https://api.github.com/repos/${r}/git/commits/${sha}`, ctx.gh);
    const committed = isObj(commit) && isObj(commit.committer) ? commit.committer.date : undefined;
    const dates: unknown[] = [release.published_at, committed];
    if (taggerDate !== 'none') dates.push(taggerDate);
    return youngest(dates, 'release published_at, commit committer date and (annotated tags) tagger date');
  });
}

/** A Docker Hub image: the pinned digest must be the tag's digest; date = the tag's last push. */
async function dockerOutcome(ctx: Ctx, image: string, tag: string, digest: string | undefined): Promise<Outcome> {
  const parts = image.split('/');
  const hubOk = parts.length <= 2 && parts.every((p) => /^[a-z0-9][a-z0-9._-]*$/.test(p)) && !(parts.length === 2 && /[.:]/.test(parts[0] as string));
  if (!hubOk || !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(tag) || !/^sha256:[0-9a-f]{64}$/.test(digest ?? '')) {
    return fail('image is not a Docker Hub tag with a sha256 digest; needs owner review');
  }
  const [ns, name] = parts.length === 1 ? ['library', parts[0] as string] : (parts as [string, string]);
  return guard(async () => {
    const doc = await ctx.get(`https://hub.docker.com/v2/repositories/${encodeURIComponent(ns)}/${encodeURIComponent(name)}/tags/${encodeURIComponent(tag)}`);
    if (!isObj(doc) || doc.digest !== digest) return fail('the tag on Docker Hub does not point to the pinned digest; needs owner review');
    const date = str(doc.tag_last_pushed) ?? str(doc.last_updated);
    return date ? { date } : fail('Docker Hub gives no push date; needs owner review');
  });
}

/** The nuclei templates archive: a tag archive listed in the release's checksums file, or a release asset. */
const NT_REPO = 'projectdiscovery/nuclei-templates';
const NT_ARCHIVE = /^https:\/\/github\.com\/projectdiscovery\/nuclei-templates\/archive\/refs\/tags\/(v(\d{1,4}\.\d{1,4}\.\d{1,4}))\.tar\.gz$/;
const NT_ASSET = /^https:\/\/github\.com\/projectdiscovery\/nuclei-templates\/releases\/download\/(v\d{1,4}\.\d{1,4}\.\d{1,4})\/([A-Za-z0-9._-]{1,100}\.tar\.gz)$/;

async function templatesOutcome(ctx: Ctx, url: string | undefined, sha: string | undefined): Promise<Outcome> {
  const want = sha256Of(sha);
  if (!want) return fail('PIPEGEN_NUCLEI_TEMPLATES_SHA256 is not a sha256');
  const asset = NT_ASSET.exec(url ?? '');
  const m = NT_ARCHIVE.exec(url ?? '');
  if (!asset && !m) return fail('PIPEGEN_NUCLEI_TEMPLATES_URL is not a projectdiscovery/nuclei-templates tag archive or release asset; needs owner review');
  const tag = (asset ?? m)?.[1] as string;
  return guard(async () => {
    // The tag's commit must be on upstream's default branch (P44), whichever form the URL has.
    const { obj } = await tagTarget(ctx, NT_REPO, encodeURIComponent(tag));
    if (obj.type !== 'commit' || typeof obj.sha !== 'string') return fail(`the tag ${tag} does not point to a commit; needs owner review`);
    const off = await onDefaultBranch(ctx, NT_REPO, obj.sha);
    if (off) return off;
    if (asset) return assetOutcome(ctx, NT_REPO, tag, asset[2] as string, want);
    return archiveFromChecksums(ctx, tag, (m as RegExpExecArray)[2] as string, want);
  });
}

/** A tag archive (no digest recorded): its sha256 must be listed in the release's checksums file. */
async function archiveFromChecksums(ctx: Ctx, tag: string, ver: string, want: string): Promise<Outcome> {
  // GitHub makes the tag archive on request and records no digest for it; the release's own checksums file lists
  // it (as on pin day), and GitHub records that file's digest, so the downloaded file is checked against it.
  const got = await releaseOf(ctx, NT_REPO, tag);
  if ('problem' in got) return got;
  const rel = got.rel;
  if (rel.tag_name !== tag) return fail('the release is not for this tag');
  const sumsName = `nuclei-templates-${ver}_checksums.txt`;
  const sums = (Array.isArray(rel.assets) ? rel.assets : []).find((a) => isObj(a) && a.name === sumsName);
  if (!isObj(sums)) return fail(`the release has no ${sumsName}, so the tag archive can not be tied; needs owner review`);
  const sumsUrl = `https://github.com/${NT_REPO}/releases/download/${tag}/${sumsName}`;
  if (sums.browser_download_url !== sumsUrl) return fail('the checksums file url does not belong to this release');
  const digest = sha256Of(sums.digest);
  if (!digest) return fail('GitHub records no digest for the release checksums file; needs owner review');
  const body = await ctx.bytes(sumsUrl);
  if (createHash('sha256').update(body).digest('hex') !== digest) return fail('the downloaded checksums file does not match the digest GitHub records for it');
  const archive = `nuclei-templates-${ver}.tar.gz`;
  const listed = body.toString('utf8').split(/\r?\n/).map((l) => /^([0-9a-fA-F]{64})\s+\*?(\S+)$/.exec(l.trim())).find((x) => x?.[2] === archive);
  if (!listed || (listed[1] as string).toLowerCase() !== want) return fail(`the release checksums file does not list the pinned sha256 for ${archive}`);
  return youngest([rel.published_at, sums.created_at, sums.updated_at], 'release published_at, checksums file created_at and updated_at');
}

/** Only upstream's own repo (exact owner, repo and case); the commit in the URL is the pinned one. */
const RULES_REPO = 'semgrep/semgrep-rules';
const RULES_URL = /^https:\/\/github\.com\/semgrep\/semgrep-rules\/archive\/([0-9a-f]{40})\.tar\.gz$/;

/**
 * The semgrep rules archive: a repo archive at a commit. The commit's tree must be PIPEGEN_RULES_TREE; the date is the
 * `verification.verified_at` GitHub set when it verified the commit's signature. The git author and committer dates
 * are whatever the pusher wrote, so they are never used: an unsigned commit can't be dated and needs owner review.
 */
async function rulesOutcome(ctx: Ctx, url: string | undefined, tree: string | undefined): Promise<Outcome> {
  const m = RULES_URL.exec(url ?? '');
  if (!m) return fail(`PIPEGEN_RULES_URL is not https://github.com/${RULES_REPO}/archive/<40-character commit SHA>.tar.gz; needs owner review`);
  if (!/^[0-9a-f]{40}$/.test(tree ?? '')) return fail('PIPEGEN_RULES_TREE is not a 40-character tree SHA');
  const r = RULES_REPO;
  const sha = m[1] as string;
  return guard(async () => {
    const c = await ctx.get(`https://api.github.com/repos/${r}/git/commits/${sha}`, ctx.gh);
    if (!isObj(c) || c.sha !== sha) return fail('unreadable commit answer');
    if (!isObj(c.tree) || c.tree.sha !== tree) return fail('the commit tree is not PIPEGEN_RULES_TREE');
    const v = isObj(c.verification) ? c.verification : {};
    if (v.verified !== true) return fail('the rules commit has no signature GitHub verified, so there is no date GitHub set; needs owner review');
    const at = str(v.verified_at);
    if (!at || !ISO.test(at) || Number.isNaN(Date.parse(at))) return fail('GitHub gives no verified_at for the rules commit; needs owner review');
    // A signed commit in a fork is served under semgrep/semgrep-rules too: it must be on upstream's default branch.
    const off = await onDefaultBranch(ctx, RULES_REPO, sha);
    return off ?? { date: at };
  });
}

// --- reviewed tools and pinned binaries -----------------------------------------------------------------------------

/** A string that looks like a hash (40 or 64 hex, sha256:, sha512-) or a URL. */
const PIN_SHAPED = /[0-9a-f]{40}|sha256:|sha512-|[a-z][a-z0-9+.-]*:\/\//i;

/** Dotted paths (list items as `[]`) of every string value that looks like a hash or a URL. */
function pinShapedPaths(v: unknown, path = '', out: string[] = []): string[] {
  if (Array.isArray(v)) v.forEach((x) => pinShapedPaths(x, `${path}.[]`, out));
  else if (isObj(v)) for (const k of Object.keys(v)) pinShapedPaths(v[k], path ? `${path}.${k}` : k, out);
  else if (typeof v === 'string' && PIN_SHAPED.test(v)) out.push(path);
  return out;
}

const ARCHIVE_ENV = ['PIPEGEN_RULES_URL', 'PIPEGEN_RULES_SHA256', 'PIPEGEN_RULES_TREE', 'PIPEGEN_NUCLEI_TEMPLATES_URL', 'PIPEGEN_NUCLEI_TEMPLATES_SHA256'];
/**
 * Where a reviewed entry may hold a hash or a URL: the pins checked here, plus verifiedWith (pin-time signature
 * inputs, never installed) and wrappedImage.digest (a record of the image an action's own action.yml runs; the action
 * is tied by its SHA). Anything else that looks like a pin fails, so a new pin field can't be skipped silently.
 */
const REVIEWED_PIN_PATHS = [
  /^candidate\.pin\.(sha|checksum|digest)$/,
  /^step\.action\.uses$/,
  /^step\.cli\.install\.(checksum|digest)$/,
  /^step\.cli\.plugins\.\[\]\.checksum$/,
  new RegExp(`^(step\\.cli|fixedInputs)\\.env\\.(${ARCHIVE_ENV.join('|')})$`),
  /^verifiedWith\.[A-Za-z0-9_]+$/,
  /^wrappedImage\.digest$/,
];
/** Where a pinned binary may hold a hash or a URL (binarySha256 is the binary inside the tied archive). */
const BINARY_PIN_PATHS = [/^platforms\.[^.]+\.(url|archiveSha256|binarySha256)$/];

function unknownPins(entry: Obj, known: readonly RegExp[]): string[] {
  return [...new Set(pinShapedPaths(entry).filter((p) => !known.some((re) => re.test(p))))];
}
const unknownPinProblem = (paths: string[]): string =>
  `a hash- or URL-shaped value at ${paths.join(', ')}, a field this check does not tie to an upstream date; needs owner review`;

interface Item {
  kind: Finding['kind'];
  name: string;
  version: string;
  run: (ctx: Ctx) => Promise<Outcome>;
}

const REVIEWED_SKIP = new Set(['reviewedBy', 'reviewedAt', 'proofs']);
const BINARY_SKIP = new Set(['reviewedBy', 'reviewedAt']);

/**
 * One npm or pip package, tied to `checksum` on its registry: the tool's own package (with the candidate pin) or a
 * plugin (with its own checksum). Any other method can't be tied, so it fails rather than being skipped.
 */
function packageItem(tool: string, inst: unknown, label: string, checksum: string | undefined): Item {
  const o = isObj(inst) ? inst : {};
  const method = str(o.method);
  const pkg = str(o.package) ?? '';
  const version = str(o.version) ?? '';
  const name = `${tool} (${label}${pkg ? ` ${pkg}` : ''})`;
  if (method === 'npm') return { kind: 'npm', name, version, run: (ctx) => npmOutcome(ctx, pkg, version, checksum) };
  if (method === 'pip') return { kind: 'pypi', name, version, run: (ctx) => pypiOutcome(ctx, pkg, version, checksum) };
  return { kind: 'reviewed-tool', name, version, run: async () => fail(`install method "${method ?? '?'}" is not one this check can tie to an upstream date; needs owner review`) };
}

/** Everything to check for the added or changed entries of data/reviewed-tools.yml. */
export function reviewedItems(base: string | null | undefined, head: string | null | undefined): Item[] {
  const items: Item[] = [];
  const problem = (name: string, text: string): void => {
    items.push({ kind: 'reviewed-tool', name, version: '', run: async () => fail(text) });
  };
  // Entries by id. A duplicate or missing id would let one copy hide another, so in head it fails; in base, a
  // duplicated id is dropped, so its head entry counts as new and is checked.
  const index = (doc: Obj, isHead: boolean): Map<string, Obj> => {
    const m = new Map<string, Obj>();
    const dup = new Set<string>();
    if (!Array.isArray(doc.tools)) {
      if (isHead && Object.keys(doc).length > 0) problem('data/reviewed-tools.yml', '`tools` is not a list, so no entry can be checked');
      return m;
    }
    doc.tools.forEach((t, i) => {
      const id = isObj(t) ? str(t.id) : undefined;
      if (!isObj(t) || id === undefined) {
        if (isHead) problem(`data/reviewed-tools.yml entry ${i + 1}`, 'the entry has no id (or is not an entry), so it can not be compared or checked');
        return;
      }
      if (m.has(id)) dup.add(id);
      m.set(id, t);
    });
    for (const id of dup) {
      m.delete(id);
      if (isHead) problem(id, 'this id appears more than once in data/reviewed-tools.yml; one copy could hide another');
    }
    return m;
  };
  const before = index(yamlObj('data/reviewed-tools.yml', base), false);
  for (const [id, tool] of index(yamlObj('data/reviewed-tools.yml', head), true)) {
    const old = before.get(id);
    if (old && canon(old, REVIEWED_SKIP) === canon(tool, REVIEWED_SKIP)) continue;
    const odd = unknownPins(tool, REVIEWED_PIN_PATHS);
    if (odd.length > 0) problem(id, unknownPinProblem(odd));
    const cand = isObj(tool.candidate) ? tool.candidate : {};
    const step = isObj(tool.step) ? tool.step : {};
    const cli = isObj(step.cli) ? step.cli : undefined;
    const action = isObj(step.action) ? step.action : undefined;
    const pin = isObj(cand.pin) ? cand.pin : {};
    const kind = str(cand.kind);
    const repo = str(cand.repo);
    const version = str(cand.version) ?? '';
    const inst = cli && isObj(cli.install) ? cli.install : undefined;
    const label = (run: Item['run']): Item => ({ kind: 'reviewed-tool', name: id, version, run });
    // An install hash, when written, must be the candidate pin (as the loader requires), never an alternative.
    if (inst && str(inst.checksum) !== undefined && str(inst.checksum) !== str(pin.checksum)) items.push(label(async () => fail('step.cli.install.checksum differs from candidate.pin.checksum')));
    if (inst && str(inst.digest) !== undefined && str(inst.digest) !== str(pin.digest)) items.push(label(async () => fail('step.cli.install.digest differs from candidate.pin.digest')));
    if (kind === 'action' && action) {
      items.push(label((ctx) => actionOutcome(ctx, str(action.uses), repo, version, str(pin.sha))));
    } else if (kind === 'cli' && inst && inst.method === 'github-release') {
      const tag = str(inst.version) ?? '';
      items.push(label(async (ctx) => {
        if (tag !== version || !repo) return fail('install version differs from the candidate version, or there is no repo');
        return assetOutcome(ctx, repo, tag, str(inst.package) ?? '', str(pin.checksum));
      }));
    } else if (kind === 'cli' && inst && (inst.method === 'npm' || inst.method === 'pip')) {
      // The package is step.cli.install.package (candidate.id is pipegen's id); its hash is the candidate pin.
      if (str(inst.version) !== version) items.push(label(async () => fail('step.cli.install.version differs from the candidate version')));
      else items.push(packageItem(id, inst, 'tool', str(pin.checksum)));
    } else if (kind === 'docker' && inst && inst.method === 'docker') {
      items.push(label(async (ctx) => {
        if (str(inst.version) !== version) return fail('install version differs from the candidate version');
        return dockerOutcome(ctx, str(inst.package) ?? '', version, str(pin.digest));
      }));
    } else {
      items.push(label(async () => fail(`kind "${kind ?? '?'}" is not one this check can tie to an upstream date; needs owner review`)));
    }
    // Every plugin is its own package with its own checksum and date.
    if (cli && Array.isArray(cli.plugins)) cli.plugins.forEach((p, i) => items.push(packageItem(id, p, `plugin ${i + 1}`, isObj(p) ? str(p.checksum) : undefined)));
    else if (cli && cli.plugins !== undefined) items.push(label(async () => fail('step.cli.plugins is not a list')));
    // Archives the tool downloads at run time. step.cli.env and fixedInputs.env must agree on each value.
    const envs = [cli && isObj(cli.env) ? cli.env : {}, isObj(tool.fixedInputs) && isObj(tool.fixedInputs.env) ? tool.fixedInputs.env : {}];
    const has = (keys: string[]): boolean => envs.some((e) => keys.some((k) => k in e));
    const envValue = (k: string): { value?: string; problem?: string } => {
      const vals = envs.filter((e) => k in e).map((e) => e[k]);
      if (vals.some((v) => v !== vals[0])) return { problem: `step.cli.env.${k} and fixedInputs.env.${k} differ` };
      return { value: str(vals[0]) };
    };
    const archive = (what: string, keys: string[], run: (v: Record<string, string | undefined>, ctx: Ctx) => Promise<Outcome>): void => {
      if (!has(keys)) return;
      const got = keys.map((k) => [k, envValue(k)] as const);
      const bad = got.find(([, g]) => g.problem);
      items.push({
        kind: 'reviewed-tool', name: `${id} (${what})`, version,
        run: async (ctx) => (bad ? fail(bad[1].problem as string) : run(Object.fromEntries(got.map(([k, g]) => [k, g.value])), ctx)),
      });
    };
    archive('nuclei templates', ['PIPEGEN_NUCLEI_TEMPLATES_URL', 'PIPEGEN_NUCLEI_TEMPLATES_SHA256'], (v, ctx) => templatesOutcome(ctx, v.PIPEGEN_NUCLEI_TEMPLATES_URL, v.PIPEGEN_NUCLEI_TEMPLATES_SHA256));
    archive('semgrep rules', ['PIPEGEN_RULES_URL', 'PIPEGEN_RULES_SHA256', 'PIPEGEN_RULES_TREE'], (v, ctx) => rulesOutcome(ctx, v.PIPEGEN_RULES_URL, v.PIPEGEN_RULES_TREE));
  }
  return items;
}

const ASSET_URL = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/releases\/download\/([^/]+)\/([^/]+)$/;

/** Everything to check for the added or changed tools of data/pinned-binaries.yml. */
export function binaryItems(base: string | null | undefined, head: string | null | undefined): Item[] {
  const before = yamlObj('data/pinned-binaries.yml', base);
  const items: Item[] = [];
  for (const [name, tool] of Object.entries(yamlObj('data/pinned-binaries.yml', head))) {
    // (A duplicate tool key is a YAML error, which fails the whole check.)
    if (!isObj(tool)) {
      items.push({ kind: 'pinned-binary', name, version: '', run: async () => fail('not a tool entry (every top-level key of data/pinned-binaries.yml is a tool)') });
      continue;
    }
    if (name in before && canon(before[name], BINARY_SKIP) === canon(tool, BINARY_SKIP)) continue;
    const odd = unknownPins(tool, BINARY_PIN_PATHS);
    if (odd.length > 0) items.push({ kind: 'pinned-binary', name, version: str(tool.version) ?? '', run: async () => fail(unknownPinProblem(odd)) });
    const version = str(tool.version) ?? '';
    const repo = str(tool.repo);
    const platforms = isObj(tool.platforms) ? Object.entries(tool.platforms) : [];
    items.push({
      kind: 'pinned-binary', name, version,
      run: async (ctx) => {
        if (!repo || platforms.length === 0) return fail('no repo or no platforms');
        let newest: string | undefined;
        for (const [plat, p] of platforms) {
          const m = ASSET_URL.exec(isObj(p) ? (str(p.url) ?? '') : '');
          if (!m || m[1] !== repo) return fail(`${plat}: asset url is not a release asset of ${repo}`);
          if (m[2] !== `v${version}` && m[2] !== version) return fail(`${plat}: asset url is for tag ${m[2]}, not version ${version}`);
          const o = await assetOutcome(ctx, repo, m[2] as string, m[3] as string, isObj(p) ? str(p.archiveSha256) : undefined);
          if ('problem' in o) return { ...o, problem: `${plat}: ${o.problem}` };
          if (!newest || Date.parse(o.date) > Date.parse(newest)) newest = o.date;
        }
        return newest ? { date: newest } : fail('no date');
      },
    });
  }
  return items;
}

// --- the security-fix emergency path ------------------------------------------------------------------------------

export const SECURITY_FIX_LABEL = 'security-fix';
export const REASON_PREFIX = 'Security-fix-reason:';
export const MAX_REASON_CHARS = 300;
const MAX_TEXT_CHARS = 300;
const MAX_PAGES = 10;
const PAGE_SIZE = 100;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

// CSI and OSC escape sequences, and two-character escapes.
const ESCAPES = /\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007\u001b]*(?:\u0007|\u001b\\)?|[@-_])/g;

/** Text on one line with no escape sequences, control, bidi, zero-width or line-separator characters. */
function oneLine(s: string): string {
  return s.replace(ESCAPES, '').replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/gu, ' ').replace(/\s+/g, ' ').trim();
}

/** Caps by code point, and splits `::` so a printed line can never be a workflow command. */
function capped(s: string, max: number): string {
  const t = s.replace(/:{2,}/g, (m) => m.split('').join(' '));
  const cps = [...t];
  return cps.length > max ? `${cps.slice(0, max).join('')}…` : t;
}

/** Text from a file or an API, safe to print as part of one log line. */
export function plainText(s: string, max = MAX_TEXT_CHARS): string {
  return capped(oneLine(s), max);
}

/** Text a PR author wrote: plainText, and no @mention, link or markdown link left that could notify or render. */
export function inertText(s: string, max = MAX_TEXT_CHARS): string {
  const t = oneLine(s).replace(/@/g, '(at)').replace(/:\/\//g, '[:]//').replace(/\bwww\./gi, 'www[.]').replace(/\]\(/g, '] (').replace(/[<>`]/g, '');
  return capped(t, max);
}

/** The first `Security-fix-reason:` line of a PR body, made inert and capped; undefined when missing or empty. */
export function securityFixReason(body: unknown): string | undefined {
  if (typeof body !== 'string') return undefined;
  for (const line of body.split(/\r\n|\r|\n/)) {
    const m = /^\s*Security-fix-reason:(.*)$/.exec(line);
    if (!m) continue;
    // Only the first such line counts, even when it is empty.
    const reason = inertText((m[1] ?? '').slice(0, MAX_REASON_CHARS * 8), MAX_REASON_CHARS);
    return reason === '' ? undefined : reason;
  }
  return undefined;
}

/**
 * Who may grant the emergency path: the user logins on the `/data/` and `/scripts/` lines of the base CODEOWNERS
 * (the last line for a pattern wins, as on GitHub). Both lines must exist, hold only `@login` entries and agree.
 */
export function emergencyOwners(text: string | null | undefined): { owners: string[] } | { problem: string } {
  if (!text) return { problem: `the base commit has no ${CODEOWNERS_FILE}, so no code owner can grant the security-fix path` };
  const rules = new Map<string, string[]>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (line === '') continue;
    const [pattern, ...who] = line.split(/\s+/);
    rules.set(pattern as string, who);
  }
  const sets: string[][] = [];
  for (const pattern of ['/data/', '/scripts/']) {
    const who = rules.get(pattern);
    if (!who || who.length === 0) return { problem: `the base ${CODEOWNERS_FILE} has no owners on its ${pattern} line` };
    if (!who.every((w) => w.startsWith('@') && LOGIN.test(w.slice(1)))) {
      return { problem: `the base ${CODEOWNERS_FILE} ${pattern} line holds something other than user logins (teams and emails are not accepted here)` };
    }
    sets.push([...new Set(who.map((w) => w.slice(1).toLowerCase()))].sort());
  }
  if (canon(sets[0]) !== canon(sets[1])) return { problem: `the /data/ and /scripts/ lines of the base ${CODEOWNERS_FILE} list different users` };
  return { owners: sets[0] as string[] };
}

const loginOf = (v: unknown): string | undefined => (isObj(v) ? str(v.login) : undefined);

export const APPROVED_LINE = 'Security-fix-approved';
/** True when a review body has a line that is exactly `Security-fix-approved` after trimming. */
const confirmsHead = (body: unknown): boolean => typeof body === 'string' && body.split(/\r\n|\r|\n/).some((l) => l.trim() === APPROVED_LINE);

/** Every page of a GitHub list, or undefined when it is longer than the page cap. */
async function allPages(ctx: Ctx, url: string): Promise<unknown[] | undefined> {
  const out: unknown[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const got = await ctx.get(`${url}?per_page=${PAGE_SIZE}&page=${page}`, ctx.gh);
    if (!Array.isArray(got)) throw new LookupError('unreadable list answer');
    out.push(...got);
    if (got.length < PAGE_SIZE) return out;
  }
  return undefined;
}

type EmergencyOutcome = { granted: Emergency } | { absent: true } | { problem: string; lookupFailed?: boolean };

/** Whether the PR holds a valid `security-fix` grant. `absent` = the label is not on the PR. */
async function emergencyOutcome(ctx: Ctx, pr: PrContext, codeowners: string | null | undefined): Promise<EmergencyOutcome> {
  const r = repoPath(pr.repo);
  if (!r || !Number.isSafeInteger(pr.number) || pr.number < 1 || !/^[0-9a-f]{40}$/.test(pr.headSha)) return { problem: 'the PR context is malformed' };
  const api = `https://api.github.com/repos/${r}`;
  try {
    const doc = await ctx.get(`${api}/pulls/${pr.number}`, ctx.gh);
    if (!isObj(doc) || !Array.isArray(doc.labels)) return { problem: 'unreadable pull request answer' };
    if (!doc.labels.some((l) => isObj(l) && l.name === SECURITY_FIX_LABEL)) return { absent: true };
    if (!isObj(doc.head) || doc.head.sha !== pr.headSha) return { problem: 'the PR head moved since this run started; the run for the new head decides' };
    const author = loginOf(doc.user)?.toLowerCase();
    if (!author) return { problem: 'the PR author can not be read' };

    const found = emergencyOwners(codeowners);
    if ('problem' in found) return found;
    const { owners } = found;

    // The latest labeled/unlabeled event for the label counts; it must be `labeled`, by a code owner.
    const events = await allPages(ctx, `${api}/issues/${pr.number}/events`);
    if (!events) return { problem: `the PR has more than ${MAX_PAGES * PAGE_SIZE} events; can not tell who applied the label` };
    let last: Obj | undefined;
    for (const e of events) {
      if (isObj(e) && (e.event === 'labeled' || e.event === 'unlabeled') && isObj(e.label) && e.label.name === SECURITY_FIX_LABEL) last = e;
    }
    if (!last || last.event !== 'labeled') return { problem: 'no `labeled` event matches the security-fix label on the PR' };
    const by = loginOf(last.actor);
    if (!by || !owners.includes(by.toLowerCase())) {
      return { problem: `the security-fix label was applied by ${plainText(by ?? 'an unknown user', 60)}, who is not a code owner in the base ${CODEOWNERS_FILE}; a code owner has to apply it` };
    }

    const reason = securityFixReason(doc.body);
    if (!reason) return { problem: `the PR body has no non-empty "${REASON_PREFIX}" line (the first such line counts)` };

    const reviews = await allPages(ctx, `${api}/pulls/${pr.number}/reviews`);
    if (!reviews) return { problem: `the PR has more than ${MAX_PAGES * PAGE_SIZE} reviews` };
    const named: Array<[string, Obj]> = [];
    for (const rv of reviews) {
      const who = isObj(rv) ? loginOf(rv.user)?.toLowerCase() : undefined;
      if (!isObj(rv) || !who) return { problem: 'unreadable review answer' };
      if (rv.state !== 'PENDING') named.push([who, rv]);
    }

    if (owners.length < 2) {
      // One owner (R-E5): the label alone is not tied to a commit, so the owner confirms the head itself with a review
      // on it (APPROVED or COMMENTED; an owner can comment on their own PR) holding a line `Security-fix-approved`.
      // The latest such review per owner counts; a later dismissal or change request from that owner cancels it.
      const confirmed = new Map<string, string>();
      for (const [who, rv] of named) {
        if (!owners.includes(who)) continue;
        if (rv.state === 'DISMISSED' || rv.state === 'CHANGES_REQUESTED') confirmed.delete(who);
        else if ((rv.state === 'APPROVED' || rv.state === 'COMMENTED') && rv.commit_id === pr.headSha && confirmsHead(rv.body)) confirmed.set(who, loginOf(rv.user) ?? who);
      }
      if (confirmed.size === 0) {
        return { problem: `a code owner has to confirm the head commit ${pr.headSha.slice(0, 12)} with a review on it (approve or comment) holding a line "${APPROVED_LINE}"; needed again after every push` };
      }
      return { granted: { labelledBy: by, reason, approvers: [...confirmed.values()], oneOwner: true } };
    }

    // Two or more owners: the latest review of each user counts (a later comment, change request or dismissal
    // cancels an approval); it must approve the current head, by an owner who is not the PR author. Two such
    // approvals are needed, or one when only one owner other than the author exists (R-E3).
    const latest = new Map<string, Obj>(named);
    const approvers = [...latest].filter(([who, rv]) => rv.state === 'APPROVED' && rv.commit_id === pr.headSha && owners.includes(who) && who !== author).map(([who]) => who).sort();
    const needed = Math.max(1, Math.min(2, owners.filter((o) => o !== author).length));
    if (approvers.length < needed) {
      return { problem: `with ${owners.length} code owners the path needs ${needed} approving review(s) from code owners other than the PR author on the head commit ${pr.headSha.slice(0, 12)}; found ${approvers.length}` };
    }
    return { granted: { labelledBy: by, reason, approvers: approvers.map((a) => loginOf(latest.get(a)?.user) ?? a), oneOwner: false } };
  } catch (e) {
    if (e instanceof LookupError) return { problem: `GitHub lookup for the security-fix path failed: ${e.message}`, lookupFailed: !e.notFound };
    throw e;
  }
}

/** The PR context from the CI env (PR_REPO, PR_NUMBER, PR_HEAD_SHA): undefined when none is set, an error when malformed. */
export function prFromEnv(env: Record<string, string | undefined>): PrContext | undefined {
  const { PR_REPO: repo, PR_NUMBER: num, PR_HEAD_SHA: sha } = env;
  if (repo === undefined && num === undefined && sha === undefined) return undefined;
  if (!repo || !repoPath(repo) || !num || !/^[1-9][0-9]{0,9}$/.test(num) || !sha || !/^[0-9a-f]{40}$/.test(sha)) {
    throw new FileError('PR_REPO, PR_NUMBER or PR_HEAD_SHA is missing or malformed');
  }
  return { repo, number: Number(num), headSha: sha };
}

// --- the check ----------------------------------------------------------------------------------------------------

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** A problem when the date is too young (`young`), unreadable or in the future; otherwise undefined. */
function judge(date: string | undefined, now: Date): { problem: string; young: boolean } | undefined {
  if (!date || !ISO.test(date) || Number.isNaN(Date.parse(date))) return { problem: 'no readable publish date', young: false };
  const age = (now.getTime() - Date.parse(date)) / DAY_MS;
  if (age < 0) return { problem: 'publish date is in the future', young: false };
  if (age < COOLDOWN_DAYS) return { problem: `only ${age.toFixed(1)} days old (needs ${COOLDOWN_DAYS})`, young: true };
  return undefined;
}

export async function runCooldown(opts: CooldownOptions): Promise<CooldownResult> {
  const { base, head, now } = opts;
  const findings: Finding[] = [];
  const notes: string[] = [];
  const ctx = makeCtx(opts, notes);
  let checked = 0;

  const baseLock = base['package-lock.json'];
  const headLock = head['package-lock.json'];
  if (!headLock && baseLock) {
    findings.push({ kind: 'lockfile', name: 'package-lock.json', version: '', date: null, lookupFailed: false, problem: 'the lockfile was removed; it can not be checked', young: false });
  }
  const lockProblem = lockfileProblem(headLock);
  if (lockProblem) findings.push({ kind: 'lockfile', name: 'package-lock.json', version: '', date: null, lookupFailed: false, problem: lockProblem, young: false });

  type Job = { kind: Finding['kind']; name: string; version: string; run: () => Promise<Outcome> };
  const jobs: Job[] = [];
  for (const e of changedLockEntries(baseLock, headLock, workspaceGlobs(base['package.json']), workspaceGlobs(head['package.json']))) {
    jobs.push({
      kind: 'npm', name: e.name, version: e.version,
      run: async () => (e.bad ? fail(e.bad) : !e.resolved ? fail('entry has no resolved tarball') : npmOutcome(ctx, e.name, e.version, e.integrity, e.resolved)),
    });
  }
  for (const i of [...reviewedItems(base['data/reviewed-tools.yml'], head['data/reviewed-tools.yml']), ...binaryItems(base['data/pinned-binaries.yml'], head['data/pinned-binaries.yml'])]) {
    jobs.push({ kind: i.kind, name: i.name, version: i.version, run: () => i.run(ctx) });
  }

  await pool(jobs, CONCURRENCY, async (job) => {
    checked++;
    const o = await job.run();
    const verdict = 'problem' in o ? { problem: o.problem, young: false } : judge(o.date, now);
    if (verdict) {
      findings.push({
        kind: job.kind, name: job.name, version: job.version, date: 'date' in o ? o.date : null,
        problem: verdict.problem, lookupFailed: 'problem' in o && o.lookupFailed === true, young: verdict.young,
      });
    }
  });
  findings.sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  // The emergency path is asked only when age is the sole problem; it never lifts any other check.
  if (opts.pr && findings.length > 0 && findings.every((f) => f.young)) {
    const e = await emergencyOutcome(ctx, opts.pr, base[CODEOWNERS_FILE]);
    if ('granted' in e) {
      return { ok: true, checked, findings: [], waived: findings, emergency: e.granted, notes };
    }
    if ('problem' in e) {
      findings.push({ kind: 'security-fix', name: 'security-fix label', version: '', date: null, problem: e.problem, lookupFailed: e.lookupFailed === true, young: false });
    }
  }

  return { ok: findings.length === 0, checked, findings, waived: [], notes };
}

/** One finding as a log line; everything that came from a file or an API goes through plainText. */
const itemLine = (f: Finding): string =>
  `  - [${f.kind}] ${plainText(f.name)}${f.version ? ' ' + plainText(f.version, 80) : ''}: ${plainText(f.problem, 400)}${f.date ? ` (published ${plainText(f.date, 40)})` : ''}`;

/** Plain-text report for the job log. */
export function formatReport(r: CooldownResult): string {
  const lines: string[] = [];
  const e = r.emergency;
  if (r.ok && e && r.waived.length > 0) {
    lines.push(`cooldown: ok ONLY through the security-fix emergency path. ${r.checked} new or changed version(s) checked; these are younger than ${COOLDOWN_DAYS} days and pass only because of the label:`);
    for (const f of r.waived) lines.push(itemLine(f));
    const who = e.approvers.map((a) => plainText(a, 60)).join(', ');
    lines.push(e.oneOwner
      ? `Label applied by code owner ${plainText(e.labelledBy, 60)}; head commit confirmed by code owner ${who} with a ${APPROVED_LINE} review (CODEOWNERS lists one owner).`
      : `Label applied by code owner ${plainText(e.labelledBy, 60)}; approved on the head commit by code owners ${who}.`);
    lines.push(`${REASON_PREFIX} ${e.reason}`);
  } else if (r.ok) {
    lines.push(`cooldown: ok. ${r.checked} new or changed version(s) checked, none younger than ${COOLDOWN_DAYS} days.`);
  } else {
    lines.push(`cooldown: FAILED. These new or changed versions are not at least ${COOLDOWN_DAYS} days old (or could not be dated):`);
    for (const f of r.findings) lines.push(itemLine(f));
    if (r.findings.some((f) => f.lookupFailed)) {
      lines.push('Some lookups failed. The check fails closed. Re-run the failed job once the registry or GitHub is reachable again.');
    }
    if (r.findings.some((f) => f.young) && r.findings.some((f) => !f.young)) {
      lines.push('The security-fix emergency path only lifts the age rule; it is not considered while other problems remain.');
    }
    lines.push(`To fix: wait until the version is ${COOLDOWN_DAYS} days old, or pin an older release. An urgent security fix can use the security-fix emergency path. See docs/cooldown.md.`);
  }
  for (const n of r.notes) lines.push(`note: ${plainText(n, 400)}`);
  return lines.join('\n');
}

async function readIf(dir: string, rel: string): Promise<string | null> {
  const path = join(dir, rel);
  let info;
  try {
    info = await lstat(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new FileError(`${rel} can not be read`);
  }
  if (!info.isFile() || info.size > MAX_BODY_BYTES) throw new FileError(`${rel} is not a regular file of a sane size`);
  return readFile(path, 'utf8');
}

async function main(argv: string[]): Promise<number> {
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const baseDir = get('--base-dir');
  const headDir = get('--head-dir');
  if (!baseDir || !headDir) {
    console.error('usage: node cooldown.ts --base-dir <base checkout> --head-dir <PR checkout>');
    return 2;
  }
  const base: Files = {};
  const head: Files = {};
  for (const f of WATCHED_FILES) {
    base[f] = await readIf(baseDir, f);
    head[f] = await readIf(headDir, f);
  }
  base[CODEOWNERS_FILE] = await readIf(baseDir, CODEOWNERS_FILE);
  const pr = prFromEnv(process.env);
  const result = await runCooldown({ base, head, fetch, now: new Date(), githubToken: process.env.GITHUB_TOKEN, ...(pr ? { pr } : {}) });
  const report = formatReport(result);
  console.log(report);
  return result.ok ? 0 : 1;
}

if (import.meta.main) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      // Only our own fixed messages are printed, never parser output that could echo file content.
      console.error(`cooldown: error, failing closed: ${e instanceof FileError ? e.message : 'unexpected error'}`);
      process.exit(1);
    },
  );
}
