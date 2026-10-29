// Release check (ruling S18), run only by .github/workflows/release.yml and by hand from docs/release.md. It is NOT part
// of pull-request CI: until the owner has reviewed the lists, it is expected to fail (the PENDING entries).
//
// Before a release it checks, and fails closed on every one of them:
//   1. no `reviewedBy`/`reviewedAt` PENDING (or missing) in data/reviewed-tools.yml and data/pinned-binaries.yml;
//   2. package.json has zero `dependencies` (everything shipped is bundled);
//   3. THIRD_PARTY_NOTICES equals what the current build (.build/meta.json) would generate;
//   4. the version in package.json equals the tag (`v1.2.3` <-> `1.2.3`);
//   5. the 7-day cooldown passes for everything that changed since the previous release tag (or for everything, on the
//      first release);
//   6. data/ai-prices.yml and data/github-plans.yml `checkedAt` is at most 30 days old;
//   7. the secret-scanner live tests pass on the real pinned scanners (scripts/scanner-live.ts): the canary tests, the
//      belt drift test and the chunk-size pin test, each present and passed, never skipped (the scanner upgrade
//      checklist, P34-P38).
// Claude never fills in `reviewedBy`; that is the owner's job. Keep to syntax Node's type stripping can run:
// `node scripts/release-check.ts --tag v1.2.3`.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { formatReport, runCooldown, WATCHED_FILES, type Files } from './cooldown.ts';
import { buildNotices, type Metafile, type Overrides } from './notices.ts';
import { runScannerLive, type ScannerCheck } from './scanner-live.ts';

export const MAX_DATA_AGE_DAYS = 30;
/** The first release has no earlier tag, so every pin is new; the normal cap of 150 lookups is too small for that. */
export const FIRST_RELEASE_MAX_LOOKUPS = 3000;
const DAY_MS = 86_400_000;
const TAG_RE = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)$/;

export interface Check {
  name: string;
  ok: boolean;
  /** One line per problem, plain English. Never file content. */
  problems: string[];
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

function parseObj(text: string | null | undefined): Obj | undefined {
  if (!text) return undefined;
  try {
    const v: unknown = parseYaml(text, { maxAliasCount: 0 });
    return isObj(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

const isPending = (v: unknown): boolean => typeof v !== 'string' || v.trim().toUpperCase() === 'PENDING' || v.trim() === '';

/** Entries of a trust-root file: `tools:` array (reviewed-tools.yml) or one top-level object per tool (pinned-binaries.yml). */
function entriesOf(doc: Obj): [string, unknown][] {
  if (Array.isArray(doc.tools)) return doc.tools.map((t, i): [string, unknown] => [isObj(t) && typeof t.id === 'string' ? t.id : `#${i + 1}`, t]);
  return Object.entries(doc).filter(([, v]) => isObj(v));
}

/** Check 1. */
export function checkPending(files: { 'data/reviewed-tools.yml'?: string | null; 'data/pinned-binaries.yml'?: string | null }): Check {
  const problems: string[] = [];
  for (const file of ['data/reviewed-tools.yml', 'data/pinned-binaries.yml'] as const) {
    const doc = parseObj(files[file]);
    if (!doc) {
      problems.push(`${file} is missing or unreadable`);
      continue;
    }
    const entries = entriesOf(doc);
    if (entries.length === 0) problems.push(`${file} lists no entries`);
    const pending = entries.filter(([, e]) => !isObj(e) || isPending(e.reviewedBy) || isPending(e.reviewedAt)).map(([id]) => id);
    if (pending.length > 0) {
      const shown = pending.length > 6 ? `${pending.slice(0, 6).join(', ')} and ${pending.length - 6} more` : pending.join(', ');
      problems.push(`${file}: ${pending.length} of ${entries.length} entries are not reviewed yet (PENDING): ${shown}`);
    }
  }
  return { name: 'no PENDING review entries', ok: problems.length === 0, problems };
}

/** Check 2. */
export function checkNoDependencies(packageJson: string | null | undefined): Check {
  const problems: string[] = [];
  try {
    const p: unknown = JSON.parse(packageJson ?? '');
    if (!isObj(p)) throw new Error('not an object');
    if ('dependencies' in p) {
      const d = p.dependencies;
      const names = isObj(d) ? Object.keys(d) : [];
      problems.push(names.length > 0 ? `package.json has runtime dependencies: ${names.join(', ')}` : 'package.json has a "dependencies" field; remove it');
    }
  } catch {
    problems.push('package.json is missing or unreadable');
  }
  return { name: 'zero runtime dependencies', ok: problems.length === 0, problems };
}

/** Check 3: the committed text against the text the current build generates. `generated` is null when it could not be built. */
export function checkNotices(committed: string | null | undefined, generated: string | null, buildError?: string): Check {
  const problems: string[] = [];
  if (generated === null) problems.push(`cannot generate the notices from the build: ${buildError ?? 'unknown error'}`);
  else if (!committed) problems.push('THIRD_PARTY_NOTICES is missing or empty');
  else if (committed !== generated) problems.push('THIRD_PARTY_NOTICES is stale; run `npm run build && npm run notices` and commit it');
  return { name: 'THIRD_PARTY_NOTICES is fresh', ok: problems.length === 0, problems };
}

/** Check 4. */
export function checkVersion(packageJson: string | null | undefined, tag: string | undefined): Check {
  const problems: string[] = [];
  const m = TAG_RE.exec(tag ?? '');
  if (!m) problems.push(`the tag ${JSON.stringify(tag ?? '')} is not of the form vMAJOR.MINOR.PATCH`);
  let version: unknown;
  try {
    const p: unknown = JSON.parse(packageJson ?? '');
    version = isObj(p) ? p.version : undefined;
  } catch {
    version = undefined;
  }
  if (typeof version !== 'string' || version === '') problems.push('package.json has no version');
  else if (m && m[1] !== version) problems.push(`package.json version ${version} does not match the tag ${tag}`);
  return { name: 'package.json version matches the tag', ok: problems.length === 0, problems };
}

/** Check 6: `checkedAt` of the two data files that freeze outside facts. */
export function checkDataFresh(files: { 'data/ai-prices.yml'?: string | null; 'data/github-plans.yml'?: string | null }, now: Date): Check {
  const problems: string[] = [];
  for (const file of ['data/ai-prices.yml', 'data/github-plans.yml'] as const) {
    const at = parseObj(files[file])?.checkedAt;
    const ms = typeof at === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(at) ? Date.parse(`${at}T00:00:00Z`) : NaN;
    if (!Number.isFinite(ms)) problems.push(`${file}: checkedAt is missing or not a YYYY-MM-DD date`);
    else if (ms > now.getTime() + DAY_MS) problems.push(`${file}: checkedAt ${at} is in the future`);
    else if (now.getTime() - ms > MAX_DATA_AGE_DAYS * DAY_MS) problems.push(`${file}: checkedAt ${at} is older than ${MAX_DATA_AGE_DAYS} days; re-check it against its source and update it`);
  }
  return { name: `data files checked within ${MAX_DATA_AGE_DAYS} days`, ok: problems.length === 0, problems };
}

/** Check 5. `base` is the previous release's files, or empty on the first release. */
export async function checkCooldown(base: Files, head: Files, fetchFn: typeof fetch, now: Date, githubToken?: string, firstRelease = false): Promise<Check> {
  try {
    const r = await runCooldown({ base, head, fetch: fetchFn, now, githubToken, ...(firstRelease ? { maxLookups: FIRST_RELEASE_MAX_LOOKUPS } : {}) });
    return { name: 'cooldown', ok: r.ok, problems: r.ok ? [] : formatReport(r).split('\n').filter((l) => l.trim() !== '') };
  } catch {
    return { name: 'cooldown', ok: false, problems: ['the cooldown check could not run (failing closed)'] };
  }
}

/** Check 7: `run` is runScannerLive for the repo root; anything it throws fails closed. */
export function checkScannerTests(run: () => ScannerCheck): Check {
  try {
    const c = run();
    return { name: c.name, ok: c.ok, problems: c.problems };
  } catch {
    return { name: 'secret-scanner live tests (canary, belt drift, chunk-size pin)', ok: false, problems: ['the secret-scanner live tests could not run (failing closed)'] };
  }
}

export function formatChecks(checks: Check[]): string {
  const lines = checks.flatMap((c) => [`${c.ok ? 'ok  ' : 'FAIL'} ${c.name}`, ...c.problems.map((p) => `       ${p}`)]);
  const failed = checks.filter((c) => !c.ok).length;
  lines.push(failed === 0 ? 'release-check: all checks passed.' : `release-check: ${failed} of ${checks.length} checks failed; do not release.`);
  return lines.join('\n');
}

function git(root: string, args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null;
  }
}

function readFileIf(root: string, rel: string): string | null {
  try {
    return readFileSync(join(root, rel), 'utf8');
  } catch {
    return null;
  }
}

async function main(argv: string[]): Promise<number> {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const tag = flag('--tag');
  if (!tag) {
    console.error('usage: node scripts/release-check.ts --tag vX.Y.Z');
    return 2;
  }
  const root = process.cwd();
  const read = (rel: string) => readFileIf(root, rel);

  let generated: string | null = null;
  let buildError: string | undefined;
  try {
    const meta = JSON.parse(readFileSync(join(root, '.build/meta.json'), 'utf8')) as Metafile;
    const overrides = JSON.parse(readFileSync(join(import.meta.dirname, 'notices-overrides.json'), 'utf8')) as Overrides;
    generated = buildNotices(root, meta, overrides).text;
  } catch (e) {
    buildError = (e as Error).message.split('\n')[0] + ' (run `npm run build` first)';
  }

  const head: Files = {};
  for (const f of WATCHED_FILES) head[f] = read(f);
  // The previous release tag, if any: the cooldown judges what changed since then.
  const prev = git(root, ['describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*', `${tag}^`])?.trim() ?? '';
  const base: Files = {};
  if (prev) for (const f of WATCHED_FILES) base[f] = git(root, ['show', `${prev}:${f}`]);
  const now = new Date();

  const checks = [
    checkPending({ 'data/reviewed-tools.yml': read('data/reviewed-tools.yml'), 'data/pinned-binaries.yml': read('data/pinned-binaries.yml') }),
    checkNoDependencies(read('package.json')),
    checkNotices(read('THIRD_PARTY_NOTICES'), generated, buildError),
    checkVersion(read('package.json'), tag),
    checkDataFresh({ 'data/ai-prices.yml': read('data/ai-prices.yml'), 'data/github-plans.yml': read('data/github-plans.yml') }, now),
    await checkCooldown(base, head, fetch, now, process.env.GITHUB_TOKEN, prev === ''),
    checkScannerTests(() => runScannerLive(root)),
  ];
  console.log(prev ? `release-check: cooldown base is ${prev}` : 'release-check: no earlier release tag; the cooldown checks every pin');
  console.log(formatChecks(checks));
  return checks.every((c) => c.ok) ? 0 : 1;
}

if (import.meta.main) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    () => {
      console.error('release-check: unexpected error, failing closed');
      process.exit(1);
    },
  );
}
