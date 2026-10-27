// 7-day cooldown check (DECISIONS #92), run by the `cooldown` job in .github/workflows/ci.yml on pull requests.
//
// It compares the BASE and HEAD copies of package-lock.json, data/reviewed-tools.yml and data/pinned-binaries.yml and
// fails when something new or changed is younger than 7 days. The date always comes from upstream, never from a
// date written in the file, and the pin must be tied to that upstream release:
//   - npm lockfile entries that are new or whose version/resolved/integrity changed (transitive ones too): the
//     name comes from the node_modules path, the version must exist in the registry, `resolved` must be the
//     registry tarball and `integrity` must equal the registry's dist.integrity; date = registry `time[version]`;
//   - reviewed tools (whole entry diffed): an action's SHA must be the commit of its tag, a release binary's asset
//     digest must belong to that GitHub release, a docker digest must be the tag's digest on Docker Hub, npm/pip
//     tools and plugins are checked on their registries; date = release published_at / registry time;
//   - pinned binaries: every platform url and sha256 must belong to the GitHub release of that version.
// Anything that can't be tied and dated (lookup failed, 404, no digest, unreadable date, date in the future,
// a kind this script doesn't know) fails closed. A docker pin it can't date says "needs owner review".
//
// The CI job runs the BASE commit's copy of this file against the PR's files, so a PR can't weaken the check that
// judges it. Keep it dependency-free apart from `yaml`, and keep to syntax Node's type stripping can run
// (no enums, no parameter properties, no namespaces): `node scripts/cooldown.ts`.
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
/** File contents by repo-relative path; a missing file is absent or null. */
export type Files = Partial<Record<string, string | null>>;

export interface Finding {
  kind: 'npm' | 'pypi' | 'reviewed-tool' | 'pinned-binary' | 'lockfile';
  name: string;
  version: string;
  /** ISO publish date used for the decision, or null when none could be found. */
  date: string | null;
  /** What is wrong, in plain English. */
  problem: string;
  /** True when the problem is a failed lookup (retrying may help). */
  lookupFailed: boolean;
}

export interface CooldownResult {
  ok: boolean;
  checked: number;
  findings: Finding[];
  notes: string[];
}

export interface CooldownOptions {
  base: Files;
  head: Files;
  fetch: typeof fetch;
  now: Date;
  githubToken?: string;
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
  constructor(message: string, notFound = false) {
    super(message);
    this.notFound = notFound;
  }
}

/** Reads a body up to the byte cap, cancelling the stream past it. */
async function readCapped(res: Response): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new LookupError('response too large');
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel().catch(() => undefined);
      throw new LookupError('response too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function getJson(f: typeof fetch, url: string, headers: Record<string, string>, timeoutMs: number): Promise<unknown> {
  let res: Response;
  try {
    res = await f(url, { headers: { accept: 'application/json', ...headers }, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new LookupError(`request failed (${e instanceof Error ? e.name : 'error'})`);
  }
  if (res.status === 404) throw new LookupError('not found (404)', true);
  if (!res.ok) throw new LookupError(`HTTP ${res.status}`);
  try {
    return JSON.parse(await readCapped(res));
  } catch (e) {
    if (e instanceof LookupError) throw e;
    throw new LookupError('unreadable response');
  }
}

/** Every request goes through here: counted against the cap, and one answer per URL. */
interface Ctx {
  get: (url: string, headers?: Record<string, string>) => Promise<unknown>;
  gh: Record<string, string>;
  notes: string[];
}

function makeCtx(opts: CooldownOptions, notes: string[]): Ctx {
  const cap = opts.maxLookups ?? MAX_LOOKUPS;
  const cache = new Map<string, Promise<unknown>>();
  return {
    notes,
    gh: opts.githubToken ? { authorization: `Bearer ${opts.githubToken}` } : {},
    get(url, headers = {}) {
      let p = cache.get(url);
      if (!p) {
        p = cache.size >= cap
          ? Promise.reject(new LookupError(`lookup cap of ${cap} reached; split the PR`))
          : getJson(opts.fetch, url, headers, opts.timeoutMs ?? LOOKUP_TIMEOUT_MS);
        cache.set(url, p);
        p.catch(() => undefined);
      }
      return p;
    },
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

/** An npm package version: must exist in the registry; integrity must match; date = time[version]. */
async function npmOutcome(ctx: Ctx, name: string, version: string, integrity: string | undefined, resolved?: string): Promise<Outcome> {
  if (!NPM_NAME.test(name)) return fail('unusual package name');
  if (!SEMVER.test(version)) return fail('version is not valid semver');
  if (resolved !== undefined) {
    const base = name.includes('/') ? name.slice(name.indexOf('/') + 1) : name;
    if (resolved !== `${REGISTRY}${name}/-/${base}-${version}.tgz`) return fail(`resolved is not the registry tarball of ${name}@${version}`);
  }
  return guard(async () => {
    const doc = await ctx.get(npmUrl(name));
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

/** An action: the pinned SHA must be the commit its tag points to; date = the tag's release published_at. */
async function actionOutcome(ctx: Ctx, uses: string | undefined, repo: string | undefined, tag: string, sha: string | undefined): Promise<Outcome> {
  const m = /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/[^@]*)?@([0-9a-f]{40})$/.exec(uses ?? '');
  if (!m || !repo || !sha) return fail('action needs `uses: owner/repo@<40-hex sha>`, a repo and a pin sha');
  if (m[1] !== repo || m[2] !== sha) return fail('uses: does not match the candidate repo and pin sha');
  return guard(async () => {
    const r = repoPath(repo);
    const t = tagPath(tag);
    if (!r || !t) return fail('repo or tag name is not a plain name');
    let ref = await ctx.get(`https://api.github.com/repos/${r}/git/ref/tags/${t}`, ctx.gh);
    let obj = isObj(ref) && isObj(ref.object) ? ref.object : {};
    let taggerDate: unknown = 'none';
    for (let hops = 0; obj.type === 'tag' && hops < 3; hops++) {
      ref = await ctx.get(`https://api.github.com/repos/${r}/git/tags/${encodeURIComponent(String(obj.sha))}`, ctx.gh);
      const tagger = isObj(ref) && isObj(ref.tagger) ? ref.tagger.date : undefined;
      if (taggerDate === 'none' || (str(tagger) && Date.parse(String(tagger)) > Date.parse(String(taggerDate)))) taggerDate = tagger;
      obj = isObj(ref) && isObj(ref.object) ? ref.object : {};
    }
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

// --- reviewed tools and pinned binaries -----------------------------------------------------------------------------

interface Item {
  kind: Finding['kind'];
  name: string;
  version: string;
  run: (ctx: Ctx) => Promise<Outcome>;
}

const REVIEWED_SKIP = new Set(['reviewedBy', 'reviewedAt', 'proofs']);
const BINARY_SKIP = new Set(['reviewedBy', 'reviewedAt']);

function installItems(tool: string, inst: unknown, label: string): Item[] {
  if (!isObj(inst)) return [];
  const method = str(inst.method);
  const pkg = str(inst.package) ?? '';
  const version = str(inst.version) ?? '';
  const checksum = str(inst.checksum);
  const mk = (kind: Finding['kind'], run: Item['run']): Item[] => [{ kind, name: `${tool} (${label} ${pkg})`, version, run }];
  if (method === 'npm') return mk('npm', (ctx) => npmOutcome(ctx, pkg, version, checksum));
  if (method === 'pip') return mk('pypi', (ctx) => pypiOutcome(ctx, pkg, version, checksum));
  return [];
}

/** Everything to check for the added or changed entries of data/reviewed-tools.yml. */
export function reviewedItems(base: string | null | undefined, head: string | null | undefined): Item[] {
  const index = (doc: Obj): Map<string, Obj> => {
    const m = new Map<string, Obj>();
    if (Array.isArray(doc.tools)) for (const t of doc.tools) if (isObj(t) && str(t.id)) m.set(t.id as string, t);
    return m;
  };
  const before = index(yamlObj('data/reviewed-tools.yml', base));
  const items: Item[] = [];
  for (const [id, tool] of index(yamlObj('data/reviewed-tools.yml', head))) {
    const old = before.get(id);
    if (old && canon(old, REVIEWED_SKIP) === canon(tool, REVIEWED_SKIP)) continue;
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
    if (kind === 'action' && action) {
      items.push(label((ctx) => actionOutcome(ctx, str(action.uses), repo, version, str(pin.sha))));
    } else if (kind === 'cli' && inst && inst.method === 'github-release') {
      const tag = str(inst.version) ?? '';
      items.push(label(async (ctx) => {
        if (tag !== version || !repo) return fail('install version differs from the candidate version, or there is no repo');
        return assetOutcome(ctx, repo, tag, str(inst.package) ?? '', str(pin.checksum));
      }));
    } else if (kind === 'cli' && inst && (inst.method === 'npm' || inst.method === 'pip')) {
      items.push(...installItems(id, inst, 'tool'));
    } else if (kind === 'docker' && inst && inst.method === 'docker') {
      items.push(label(async (ctx) => {
        if (str(inst.version) !== version) return fail('install version differs from the candidate version');
        return dockerOutcome(ctx, str(inst.package) ?? '', version, str(pin.digest));
      }));
    } else {
      items.push(label(async () => fail(`kind "${kind ?? '?'}" is not one this check can tie to an upstream date; needs owner review`)));
    }
    if (cli && Array.isArray(cli.plugins)) cli.plugins.forEach((p, i) => items.push(...installItems(id, p, `plugin ${i + 1}`)));
  }
  return items;
}

const ASSET_URL = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/releases\/download\/([^/]+)\/([^/]+)$/;

/** Everything to check for the added or changed tools of data/pinned-binaries.yml. */
export function binaryItems(base: string | null | undefined, head: string | null | undefined): Item[] {
  const before = yamlObj('data/pinned-binaries.yml', base);
  const items: Item[] = [];
  for (const [name, tool] of Object.entries(yamlObj('data/pinned-binaries.yml', head))) {
    if (!isObj(tool)) continue;
    if (name in before && canon(before[name], BINARY_SKIP) === canon(tool, BINARY_SKIP)) continue;
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

// --- the check ----------------------------------------------------------------------------------------------------

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** Returns a problem text when the date is too young, unreadable or in the future; otherwise undefined. */
function judge(date: string | undefined, now: Date): string | undefined {
  if (!date || !ISO.test(date) || Number.isNaN(Date.parse(date))) return 'no readable publish date';
  const age = (now.getTime() - Date.parse(date)) / DAY_MS;
  if (age < 0) return 'publish date is in the future';
  if (age < COOLDOWN_DAYS) return `only ${age.toFixed(1)} days old (needs ${COOLDOWN_DAYS})`;
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
    findings.push({ kind: 'lockfile', name: 'package-lock.json', version: '', date: null, lookupFailed: false, problem: 'the lockfile was removed; it can not be checked' });
  }
  const lockProblem = lockfileProblem(headLock);
  if (lockProblem) findings.push({ kind: 'lockfile', name: 'package-lock.json', version: '', date: null, lookupFailed: false, problem: lockProblem });

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
    const problem = 'problem' in o ? o.problem : judge(o.date, now);
    if (problem) {
      findings.push({
        kind: job.kind, name: job.name, version: job.version, date: 'date' in o ? o.date : null,
        problem, lookupFailed: 'problem' in o && o.lookupFailed === true,
      });
    }
  });
  findings.sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  return { ok: findings.length === 0, checked, findings, notes };
}

/** Plain-text report for the job log. */
export function formatReport(r: CooldownResult): string {
  const lines: string[] = [];
  if (r.ok) {
    lines.push(`cooldown: ok. ${r.checked} new or changed version(s) checked, none younger than ${COOLDOWN_DAYS} days.`);
  } else {
    lines.push(`cooldown: FAILED. These new or changed versions are not at least ${COOLDOWN_DAYS} days old (or could not be dated):`);
    for (const f of r.findings) {
      lines.push(`  - [${f.kind}] ${f.name}${f.version ? ' ' + f.version : ''}: ${f.problem}${f.date ? ` (published ${f.date})` : ''}`);
    }
    if (r.findings.some((f) => f.lookupFailed)) {
      lines.push('Some lookups failed. The check fails closed. Re-run the failed job once the registry or GitHub is reachable again.');
    }
    lines.push(`To fix: wait until the version is ${COOLDOWN_DAYS} days old, or pin an older release. See docs/cooldown.md.`);
  }
  for (const n of r.notes) lines.push(`note: ${n}`);
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
  const result = await runCooldown({ base, head, fetch, now: new Date(), githubToken: process.env.GITHUB_TOKEN });
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
