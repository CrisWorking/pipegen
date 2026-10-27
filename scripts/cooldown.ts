// 7-day cooldown check (DECISIONS #92), run by the `cooldown` job in .github/workflows/ci.yml on pull requests.
//
// It compares the BASE and HEAD copies of package-lock.json, data/reviewed-tools.yml and data/pinned-binaries.yml and
// fails when something new or changed is younger than 7 days:
//   - every npm package version that is new in the lockfile (transitive ones too): npm registry `time[version]`;
//   - every added or changed reviewed tool or pinned binary: the recorded date (releasedAt, else pinnedOn), and,
//     for GitHub-hosted tools, the release's `published_at` from api.github.com. The younger of the two counts.
// Anything that can't be dated (registry down, no date, unreadable date, date in the future) fails closed.
//
// The CI job runs the BASE commit's copy of this file against the PR's files, so a PR can't weaken the check that
// judges it. Keep it dependency-free apart from `yaml`, and keep to syntax Node's type stripping can run
// (no enums, no parameter properties, no namespaces): `node scripts/cooldown.ts`.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export const COOLDOWN_DAYS = 7;
export const MAX_LOOKUPS = 150;
export const LOOKUP_TIMEOUT_MS = 15_000;
export const MAX_BODY_BYTES = 32 * 1024 * 1024;
const DAY_MS = 86_400_000;
const CONCURRENCY = 6;

export const WATCHED_FILES = ['package-lock.json', 'data/reviewed-tools.yml', 'data/pinned-binaries.yml'] as const;
/** File contents by repo-relative path; a missing file is absent or null. */
export type Files = Partial<Record<string, string | null>>;

export interface Finding {
  kind: 'npm' | 'reviewed-tool' | 'pinned-binary';
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

// --- what changed -------------------------------------------------------------------------------------------------

/** name -> versions, from a package-lock.json (v2/v3 `packages`). Links and entries with no version are skipped. */
export function lockfileVersions(text: string | null | undefined): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  if (!text) return out;
  const lock: unknown = JSON.parse(text);
  const packages = isObj(lock) && isObj(lock.packages) ? lock.packages : {};
  for (const [path, entry] of Object.entries(packages)) {
    if (path === '' || !isObj(entry) || entry.link === true) continue;
    const version = str(entry.version);
    if (!version) continue;
    const idx = path.lastIndexOf('node_modules/');
    const name = str(entry.name) ?? (idx >= 0 ? path.slice(idx + 'node_modules/'.length) : path);
    let set = out.get(name);
    if (!set) out.set(name, (set = new Set()));
    set.add(version);
  }
  return out;
}

/** Versions in head that base didn't have. A removed package or an unchanged version is not listed. */
export function newNpmVersions(base: string | null | undefined, head: string | null | undefined): Array<{ name: string; version: string }> {
  const before = lockfileVersions(base);
  const out: Array<{ name: string; version: string }> = [];
  for (const [name, versions] of [...lockfileVersions(head)].sort(([a], [b]) => a.localeCompare(b))) {
    for (const version of [...versions].sort()) {
      if (!before.get(name)?.has(version)) out.push({ name, version });
    }
  }
  return out;
}

export interface PinChange {
  kind: 'reviewed-tool' | 'pinned-binary';
  name: string;
  version: string;
  repo: string | undefined;
  /** Whether a GitHub release can be looked up for it (not for container images). */
  github: boolean;
  recordedDate: string | undefined;
}

function yamlObj(text: string | null | undefined): Obj {
  if (!text) return {};
  const v: unknown = parseYaml(text);
  return isObj(v) ? v : {};
}

/** Added or changed entries of data/reviewed-tools.yml (compared by the `candidate`, the pin itself). */
export function changedReviewedTools(base: string | null | undefined, head: string | null | undefined): PinChange[] {
  const index = (doc: Obj): Map<string, Obj> => {
    const m = new Map<string, Obj>();
    if (Array.isArray(doc.tools)) for (const t of doc.tools) if (isObj(t) && str(t.id)) m.set(t.id as string, t);
    return m;
  };
  const before = index(yamlObj(base));
  const headDoc = yamlObj(head);
  const fileDate = str(headDoc.pinnedOn);
  const out: PinChange[] = [];
  for (const [id, tool] of index(headDoc)) {
    const cand = isObj(tool.candidate) ? tool.candidate : {};
    const old = before.get(id);
    if (old && JSON.stringify(old.candidate ?? null) === JSON.stringify(cand) && str(old.releasedAt) === str(tool.releasedAt)) continue;
    out.push({
      kind: 'reviewed-tool',
      name: id,
      version: str(cand.version) ?? '(no version)',
      repo: str(cand.repo),
      github: str(cand.kind) !== 'docker',
      recordedDate: str(tool.releasedAt) ?? fileDate,
    });
  }
  return out;
}

const REVIEW_ONLY_FIELDS = new Set(['reviewedBy', 'reviewedAt', 'pinnedOn']);

/** Added or changed tools of data/pinned-binaries.yml (a review-only edit is not a change). */
export function changedPinnedBinaries(base: string | null | undefined, head: string | null | undefined): PinChange[] {
  const strip = (v: unknown): string => JSON.stringify(v, (k, x: unknown) => (REVIEW_ONLY_FIELDS.has(k) ? undefined : x));
  const before = yamlObj(base);
  const out: PinChange[] = [];
  for (const [name, tool] of Object.entries(yamlObj(head))) {
    if (!isObj(tool)) continue;
    if (name in before && strip(before[name]) === strip(tool)) continue;
    out.push({
      kind: 'pinned-binary',
      name,
      version: str(tool.version) ?? '(no version)',
      repo: str(tool.repo),
      github: true,
      recordedDate: str(tool.releasedAt) ?? str(tool.pinnedOn),
    });
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

async function getJson(f: typeof fetch, url: string, headers: Record<string, string>, timeoutMs: number): Promise<unknown> {
  let res: Response;
  try {
    res = await f(url, { headers: { accept: 'application/json', ...headers }, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new LookupError(`request failed (${e instanceof Error ? e.name : 'error'})`);
  }
  if (res.status === 404) throw new LookupError('not found (404)', true);
  if (!res.ok) throw new LookupError(`HTTP ${res.status}`);
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new LookupError('response too large');
  try {
    const text = await res.text();
    if (text.length > MAX_BODY_BYTES) throw new LookupError('response too large');
    return JSON.parse(text);
  } catch (e) {
    if (e instanceof LookupError) throw e;
    throw new LookupError('unreadable response');
  }
}

export const npmUrl = (name: string): string => `https://registry.npmjs.org/${name.replace('/', '%2f')}`;

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++] as T);
  });
  await Promise.all(workers);
}

// --- the check ----------------------------------------------------------------------------------------------------

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

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
  const maxLookups = opts.maxLookups ?? MAX_LOOKUPS;
  const timeoutMs = opts.timeoutMs ?? LOOKUP_TIMEOUT_MS;
  const findings: Finding[] = [];
  const notes: string[] = [];
  let checked = 0;

  const npmNew = newNpmVersions(base['package-lock.json'], head['package-lock.json']);
  const pins = [
    ...changedReviewedTools(base['data/reviewed-tools.yml'], head['data/reviewed-tools.yml']),
    ...changedPinnedBinaries(base['data/pinned-binaries.yml'], head['data/pinned-binaries.yml']),
  ];
  const npmNames = [...new Set(npmNew.map((p) => p.name))];
  const githubPins = pins.filter((p) => p.github && p.repo);

  if (npmNames.length + githubPins.length > maxLookups) {
    findings.push({
      kind: 'npm', name: '(too many changes)', version: '', date: null, lookupFailed: false,
      problem: `${npmNames.length + githubPins.length} lookups needed, the cap is ${maxLookups}; split the PR`,
    });
    return { ok: false, checked, findings, notes };
  }

  // npm: one registry request per package name, then every new version of it is checked against the time map.
  const times = new Map<string, Obj | LookupError>();
  await pool(npmNames, CONCURRENCY, async (name) => {
    try {
      const doc = await getJson(opts.fetch, npmUrl(name), {}, timeoutMs);
      times.set(name, isObj(doc) && isObj(doc.time) ? doc.time : new LookupError('no `time` map in the registry answer'));
    } catch (e) {
      times.set(name, e as LookupError);
    }
  });
  for (const { name, version } of npmNew) {
    checked++;
    const t = times.get(name);
    if (t instanceof LookupError) {
      findings.push({ kind: 'npm', name, version, date: null, lookupFailed: true, problem: `registry lookup failed: ${t.message}` });
      continue;
    }
    const date = str(t?.[version]);
    const problem = date === undefined ? 'registry has no publish time for this version' : judge(date, now);
    if (problem) findings.push({ kind: 'npm', name, version, date: date ?? null, lookupFailed: false, problem });
  }

  // Pins: the recorded date, plus the GitHub release date where it can be read. The younger date counts.
  const gh: Record<string, string> = opts.githubToken ? { authorization: `Bearer ${opts.githubToken}` } : {};
  const upstream = new Map<PinChange, string | LookupError | null>();
  await pool(githubPins, CONCURRENCY, async (pin) => {
    const repo = pin.repo as string;
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
      upstream.set(pin, new LookupError('repo name is not a plain owner/name'));
      return;
    }
    const tags = pin.version.startsWith('v') ? [pin.version] : [`v${pin.version}`, pin.version];
    let last: LookupError | undefined;
    for (const tag of tags) {
      try {
        const rel = await getJson(opts.fetch, `https://api.github.com/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`, gh, timeoutMs);
        const when = isObj(rel) ? str(rel.published_at) : undefined;
        upstream.set(pin, when ?? new LookupError('release has no published_at'));
        return;
      } catch (e) {
        last = e as LookupError;
        if (!last.notFound) break;
      }
    }
    // No GitHub release for the tag (a plain tag): only the recorded date can be used.
    upstream.set(pin, last?.notFound ? null : (last as LookupError));
  });
  for (const pin of pins) {
    checked++;
    const label = `${pin.name} ${pin.version}`;
    const up = upstream.get(pin);
    if (up instanceof LookupError) {
      findings.push({ kind: pin.kind, name: pin.name, version: pin.version, date: pin.recordedDate ?? null, lookupFailed: true, problem: `GitHub release lookup failed: ${up.message}` });
      continue;
    }
    if (pin.github && pin.repo && up === null) notes.push(`${label}: no GitHub release found, only the recorded date was used`);
    // The recorded date must be readable and old enough; so must the upstream date when there is one.
    const candidates: Array<string | undefined> = up === null || up === undefined ? [pin.recordedDate] : [pin.recordedDate, up];
    for (const d of candidates) {
      const problem = judge(d, now);
      if (problem) {
        findings.push({ kind: pin.kind, name: pin.name, version: pin.version, date: d ?? null, lookupFailed: false, problem });
        break;
      }
    }
  }

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
  try {
    return await readFile(join(dir, rel), 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
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
      console.error(`cooldown: error, failing closed: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(1);
    },
  );
}
