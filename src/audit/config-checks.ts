// Plan P Task 4: checks decided by reading files (and versions) instead of workflow runs. Rulings PB4, PS17, PS22, PS23, P2.
//
// The rule behind every function here (Global Constraint 2, PB4): anything pipegen can't confirm is never "covered". The
// repo is attacker-controlled, so every read goes through the read limits (1 MB, binary refused, YAML alias cap), a fixed
// path is checked at every level for symbolic links (never followed), a path that comes from a workflow (a run's folder)
// is checked to stay inside the repo, and every loop is bounded and linear.
//
// Layout (PB1): this module imports only types from ./coverage.js and ./coverage/types.js, plus the readers; never walk.ts.
// mapCoverage (../coverage.ts) calls it as its last steps: update-config, publishing, the coverage minimum, versionAdjust.
//
// Upstream facts encoded here (checked 2026-10-27):
// - Dependabot cooldown keys default-days, semver-major-days, semver-minor-days, semver-patch-days, include, exclude;
//   default-days is 3 when unset; `exclude` wins over `include`; security updates ignore it; `open-pull-requests-limit: 0`
//   turns version updates off; `directory` takes no glob, `directories` does:
//   https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference
// - Renovate: minimumReleaseAge is a duration string ("3 days", "1 hour"), allowed in packageRules; internalChecksFilter
//   defaults to "strict", which withholds an update until the age has passed ("none" and "flexible" do not); config file
//   names and their order:
//   https://docs.renovatebot.com/configuration-options/ and https://docs.renovatebot.com/key-concepts/minimum-release-age/
// - ESLint 10 drops the old configuration format ("Starting with ESLint v10.0.0, the old configuration format is no longer
//   supported"): https://eslint.org/docs/latest/use/migrate-to-10.0.0 ; ESLint 9 reached end of life on 2026-08-06 and
//   ESLint 8 on 2024-10-05: https://eslint.org/version-support/
// - Coverage minimums: coverage.py [report] fail_under (.coveragerc [report]; setup.cfg and tox.ini [coverage:report];
//   pyproject.toml [tool.coverage.report]; the first file that exists decides, .coveragerc before setup.cfg, tox.ini and
//   pyproject.toml): https://coverage.readthedocs.io/en/latest/config.html ; pytest-cov takes fail_under from that config when
//   --cov-fail-under is not given: https://github.com/pytest-dev/pytest-cov/blob/master/src/pytest_cov/plugin.py (cov_fail_under);
//   jest coverageThreshold (a positive number is a minimum percentage): https://jestjs.io/docs/configuration
import { lstat } from 'node:fs/promises';
import { join, posix } from 'node:path';
import picomatch from 'picomatch';
import { parse as parseToml } from 'smol-toml';
import { IGNORED_DIRS, SKIP_REASON, linkedLevel, listFiles, parseYamlLimited, readTextLimitedWithReason, regexLines, type Skipped } from '../read/limits.js';
import { asObj, dirOf } from '../read/manifest.js';
import type { Need, RepoProfile, Service } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { Coverage } from './coverage.js';
import type { Hit } from './coverage/types.js';

export const COOLDOWN_DAYS = 7;
const MAX_ENTRIES = 500;           // Dependabot `updates` entries read
const MAX_PATTERNS = 1000;         // directory patterns read in all
const MAX_REQUIREMENTS = 2000;     // (ecosystem, folder) pairs checked
const MAX_NODES = 100_000;         // nodes visited looking for YAML merge keys
const MAX_PATH = 200;

type Status = Coverage['status'];
interface Verdict { status: Status; why: string; by: string; where: string }
const rank: Record<Status, number> = { covered: 3, partial: 2, unknown: 1, missing: 0 };

// ---------- reading a fixed path ----------

type Read = { text: string } | { skipped: Skipped } | null;

const inRepo = (folder: string, name: string) => (folder === '.' ? name : `${folder}/${name}`);

/** A file at a fixed path under dir: null when absent; a symbolic link at any level, a big, binary or unreadable file → skipped. */
async function readAt(dir: string, rel: string): Promise<Read> {
  if ((await linkedLevel(dir, rel)) !== null) return { skipped: 'link' };
  const info = await lstat(join(dir, rel)).catch(() => null);
  if (info === null) return null;
  return readTextLimitedWithReason(join(dir, rel), dir);
}

/** A folder that came from a workflow: a clean relative path that stays inside the repo, else null. */
function cleanFolder(folder: string): string | null {
  if (folder.length > 512 || folder.startsWith('/') || folder.includes('\0') || safeText(folder) !== folder) return null;
  const n = posix.normalize(folder).replace(/\/+$/, '');
  if (n === '..' || n.startsWith('../')) return null;
  return n === '' ? '.' : n;
}

// ---------- Dependabot ----------

const DEPENDABOT_PATHS = ['.github/dependabot.yml', '.github/dependabot.yaml'] as const;
const DIR_CHARS = /^[A-Za-z0-9._@/-]*$/;
const GLOB_CHARS = /^[A-Za-z0-9._@/*-]*$/;

/** Whether any object in the parsed document (aliases followed once each) has a YAML merge key `<<`, within a node budget. */
function hasMergeKey(root: unknown): boolean | 'too-big' {
  const seen = new Set<object>();
  const stack: unknown[] = [root];
  let nodes = 0;
  while (stack.length > 0) {
    const x = stack.pop();
    if (x === null || typeof x !== 'object' || seen.has(x)) continue;
    seen.add(x);
    if (++nodes > MAX_NODES) return 'too-big';
    if (Array.isArray(x)) {
      for (const v of x) stack.push(v);
    } else {
      if (Object.hasOwn(x, '<<')) return true;
      for (const v of Object.values(x)) stack.push(v);
    }
  }
  return false;
}

interface Matcher { literals: Set<string>; globs: ((dir: string) => boolean)[]; cooldownOk: boolean }

/** `/` → '.', `/a/b/` → 'a/b'; null for anything with `..`, `.` parts, odd characters or `!`. */
function normalDir(raw: string, glob: boolean): string | null {
  if (raw.length > MAX_PATH || !(glob ? GLOB_CHARS : DIR_CHARS).test(raw)) return null;
  const t = raw.replace(/^\/+/, '').replace(/\/+$/, '');
  if (t === '') return '.';
  const segs = t.split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) return null;
  return t;
}

function cooldownOk(entry: Record<string, unknown>): boolean {
  if (!Object.hasOwn(entry, 'cooldown')) return false;
  const c = entry.cooldown;
  if (c === null || typeof c !== 'object' || Array.isArray(c)) return false;
  const o = c as Record<string, unknown>;
  const days = (v: unknown) => typeof v === 'number' && Number.isInteger(v) && v >= COOLDOWN_DAYS;
  if (!days(o['default-days'])) return false;
  for (const k of ['semver-major-days', 'semver-minor-days', 'semver-patch-days']) if (Object.hasOwn(o, k) && !days(o[k])) return false;
  // `include` limits the wait to the listed packages and `exclude` skips some: neither is a wait for every package
  return !Object.hasOwn(o, 'include') && !Object.hasOwn(o, 'exclude');
}

/** open-pull-requests-limit 0 (or a value that isn't a whole number) turns version updates off; so does ignoring every package. */
function entryOn(entry: Record<string, unknown>): boolean {
  if (Object.hasOwn(entry, 'open-pull-requests-limit')) {
    const v = entry['open-pull-requests-limit'];
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 1) return false;
  }
  // an `allow` list limits which dependencies are updated; only one that allows every dependency is no limit
  if (Object.hasOwn(entry, 'allow')) {
    const al = entry.allow;
    const everything = (r: unknown) => r !== null && typeof r === 'object' && Object.keys(r).length === 1 && (r as Record<string, unknown>)['dependency-name'] === '*';
    if (!Array.isArray(al) || !al.some(everything)) return false;
  }
  if (Object.hasOwn(entry, 'ignore')) {
    const ig = entry.ignore;
    if (!Array.isArray(ig)) return false;
    if (ig.some((r) => r !== null && typeof r === 'object' && /^\*+$/.test(String((r as Record<string, unknown>)['dependency-name'] ?? '')) && !Object.hasOwn(r as object, 'update-types'))) return false;
  }
  return true;
}

interface Requirement { ecos: readonly string[]; dir: string }

/** Where a Go module, or a Dockerfile, sits: found here because no reader sets language 'go' (ruling P2). */
async function listedFolders(dir: string): Promise<{ go: string[]; docker: string[]; node: string[]; python: string[]; truncated: boolean }> {
  const ignore = IGNORED_DIRS.map((d) => `**/${d}/**`);
  const found = await listFiles(dir, ['**/go.mod', '**/Dockerfile', '**/Dockerfile.*', '**/package.json', '**/pyproject.toml', '**/requirements*.txt'], ignore);
  const sets = { go: new Set<string>(), docker: new Set<string>(), node: new Set<string>(), python: new Set<string>() };
  for (const f of found.files) {
    const base = f.slice(f.lastIndexOf('/') + 1);
    const kind = base === 'go.mod' ? 'go' : base === 'package.json' ? 'node' : base === 'pyproject.toml' || base.startsWith('requirements') ? 'python' : 'docker';
    sets[kind].add(dirOf(f));
  }
  return { go: [...sets.go].sort(), docker: [...sets.docker].sort(), node: [...sets.node].sort(), python: [...sets.python].sort(), truncated: found.truncated };
}

async function dependabotVerdict(p: RepoProfile, dir: string): Promise<Verdict | null> {
  const reads: { rel: string; r: Read }[] = [];
  for (const rel of DEPENDABOT_PATHS) reads.push({ rel, r: await readAt(dir, rel) });
  const present = reads.filter((x) => x.r !== null);
  if (present.length === 0) return null;
  const first = present[0] as { rel: string; r: Exclude<Read, null> };
  const mk = (status: Status, why: string): Verdict => ({ status, why, by: 'dependabot', where: first.rel });
  for (const x of present) {
    const r = x.r as Exclude<Read, null>;
    if ('skipped' in r) return mk('unknown', `Dependabot's config file couldn't be read (${SKIP_REASON[r.skipped]}), so pipegen can't tell what it does.`);
  }
  if (present.length > 1) return mk('unknown', 'Both dependabot.yml and dependabot.yaml exist, so pipegen can\'t tell which one GitHub reads.');
  let doc: unknown;
  try {
    doc = parseYamlLimited((first.r as { text: string }).text);
  } catch {
    return mk('unknown', "Dependabot's config file isn't valid YAML that pipegen can read, so it can't tell what it does.");
  }
  const merge = hasMergeKey(doc);
  if (merge !== false) return mk('unknown', "Dependabot's config file uses YAML merge keys (or is too large), which pipegen doesn't follow, so it can't tell what it does.");
  const root = asObj(doc);
  if (root.version !== 2) return mk('partial', "Dependabot's config file isn't version 2, so GitHub may ignore it.");
  if (!Array.isArray(root.updates) || root.updates.length === 0) return mk('partial', "Dependabot's config file lists no updates.");
  if (root.updates.length > MAX_ENTRIES) return mk('unknown', "Dependabot's config file has more update entries than pipegen reads, so it can't tell.");

  // the entries that are on, by ecosystem
  const byEco = new Map<string, Matcher[]>();
  let patterns = 0;
  for (const raw of root.updates as unknown[]) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const e = raw as Record<string, unknown>;
    if (typeof e['package-ecosystem'] !== 'string') continue;
    // GitHub rejects the whole file when an entry has no schedule interval
    const interval = asObj(e.schedule).interval;
    if (typeof interval !== 'string' || interval === '') return mk('partial', "A Dependabot entry has no schedule.interval, so GitHub rejects the config file.");
    if (!entryOn(e)) continue;
    const m: Matcher = { literals: new Set(), globs: [], cooldownOk: cooldownOk(e) };
    let usable = true;
    const take = (v: unknown, glob: boolean) => {
      if (typeof v !== 'string') return void (usable = false);
      const n = normalDir(v, glob);
      if (n === null) return void (usable = false);
      if (++patterns > MAX_PATTERNS) return;
      if (!glob || !n.includes('*')) m.literals.add(n);
      else if (n.split('/').length > 8) usable = false;
      else {
        const test = picomatch(n, { dot: true });
        m.globs.push((d) => d !== '.' && test(d));
      }
    };
    if (Object.hasOwn(e, 'directory')) take(e.directory, false);
    if (Object.hasOwn(e, 'directories')) {
      if (!Array.isArray(e.directories)) usable = false;
      else for (const d of e.directories as unknown[]) take(d, true);
    }
    if (!Object.hasOwn(e, 'directory') && !Object.hasOwn(e, 'directories')) usable = false;
    if (patterns > MAX_PATTERNS) return mk('unknown', "Dependabot's config file lists more folders than pipegen reads, so it can't tell.");
    if (!usable) continue;
    const key = e['package-ecosystem'] as string;
    byEco.set(key, [...(byEco.get(key) ?? []), m]);
  }

  // what the repo needs
  const reqs: Requirement[] = [];
  let unchecked = false;
  if (p.services.length > 5000) return mk('unknown', 'There are more services than pipegen checks against the Dependabot file.');
  for (const s of p.services) {
    const sd = cleanFolder(s.path) ?? s.path;
    if (s.language === 'node') reqs.push({ ecos: [s.packageManager === 'bun' ? 'bun' : 'npm'], dir: sd });
    else if (s.language === 'python') reqs.push({ ecos: ['pip', 'uv'], dir: sd });
    else if (s.language === 'go') reqs.push({ ecos: ['gomod'], dir: sd });
    else if (s.language !== 'other') unchecked = true; // java, dotnet, ruby, php: pipegen has no rule for their ecosystem
    if ((s.dockerfile ?? '') !== '') reqs.push({ ecos: ['docker'], dir: dirOf(s.dockerfile as string) });
  }
  if (p.existingWorkflows.length > 0) reqs.push({ ecos: ['github-actions'], dir: '.' });
  const listed = await listedFolders(dir);
  for (const d of listed.go) reqs.push({ ecos: ['gomod'], dir: d });
  for (const d of listed.docker) reqs.push({ ecos: ['docker'], dir: d });
  // a manifest in a folder no service owns (the service reader skips it) still needs an entry
  for (const d of listed.node) reqs.push({ ecos: ['npm', 'bun'], dir: d });
  for (const d of listed.python) reqs.push({ ecos: ['pip', 'uv'], dir: d });
  if (reqs.length > MAX_REQUIREMENTS) return mk('unknown', 'There are more ecosystems and folders than pipegen checks against the Dependabot file.');
  if (reqs.length === 0) return mk('unknown', 'pipegen found no ecosystem it can check against the Dependabot file.');

  const missing = new Set<string>();
  let anyFolderGap = false;
  let cooldownGap = false;
  const seen = new Set<string>();
  for (const r of reqs) {
    const key = `${r.ecos.join('|')}\0${r.dir}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const matchers = r.ecos.flatMap((e) => byEco.get(e) ?? []);
    const hits = matchers.filter((m) => m.literals.has(r.dir) || m.globs.some((g) => g(r.dir)));
    if (hits.length === 0) {
      missing.add(r.ecos.join(' or '));
      if (matchers.length > 0) anyFolderGap = true;
    } else if (!hits.some((m) => m.cooldownOk)) cooldownGap = true;
  }
  if (missing.size > 0) {
    return mk('partial', `Dependabot has no active entry for ${[...missing].join(', ')}${anyFolderGap ? ' (some folders are not listed)' : ''}, so some dependencies are not updated by it.`);
  }
  if (cooldownGap) return mk('partial', `Dependabot's default wait is 3 days; pipegen uses ${COOLDOWN_DAYS}. Set cooldown default-days to at least ${COOLDOWN_DAYS} (with no lower per-type days, include or exclude) on every entry.`);
  if (unchecked) return mk('partial', "Dependabot covers the ecosystems pipegen checks, but pipegen doesn't check the entries for Java, .NET, Ruby or PHP code.");
  if (listed.truncated) return mk('unknown', 'The repo has too many files for pipegen to find every Go module and Dockerfile, so it can\'t tell that Dependabot lists them all.');
  return mk('covered', `Dependabot updates every ecosystem and folder pipegen found, each waiting at least ${COOLDOWN_DAYS} days (cooldown) before an update.`);
}

// ---------- Renovate ----------

// Renovate's search order (https://docs.renovatebot.com/configuration-options/); it stops at the first match.
const RENOVATE_PATHS = ['renovate.json', 'renovate.jsonc', 'renovate.json5', '.github/renovate.json', '.github/renovate.jsonc', '.github/renovate.json5',
  '.gitlab/renovate.json', '.gitlab/renovate.jsonc', '.gitlab/renovate.json5', '.renovaterc', '.renovaterc.json', '.renovaterc.jsonc', '.renovaterc.json5'] as const;

/** A Renovate duration in whole days: "7 days", "1 week", "168 hours" (days, weeks and hours only); null when pipegen can't place it. */
function renovateDays(v: unknown): number | null {
  if (typeof v !== 'string' || v.length > 40) return null;
  const m = /^(\d{1,6})\s?(h|hours?|d|days?|w|weeks?)$/i.exec(v.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] as string).toLowerCase();
  return unit.startsWith('h') ? n / 24 : unit.startsWith('d') ? n : n * 7;
}

async function renovateVerdict(dir: string, running: boolean): Promise<Verdict | null> {
  let found: { rel: string; text: string } | null = null;
  for (const rel of RENOVATE_PATHS) {
    const r = await readAt(dir, rel);
    if (r === null) continue;
    if ('skipped' in r) return { status: 'unknown', by: 'renovate', where: rel, why: `Renovate's config file couldn't be read (${SKIP_REASON[r.skipped]}), so pipegen can't tell what it does.` };
    found = { rel, text: r.text };
    break;
  }
  let config: unknown;
  let where: string;
  if (found !== null) {
    where = found.rel;
    if (/\.(json5|jsonc)$/.test(where)) return { status: 'partial', by: 'renovate', where, why: "Renovate's config is a JSON5 or JSONC file, and pipegen can't read JSON5 yet, so it can't tell whether it waits before updating." };
    try {
      config = JSON.parse(found.text);
    } catch {
      return { status: 'partial', by: 'renovate', where, why: "Renovate's config isn't plain JSON that pipegen can read (it may be JSON5), so it can't tell whether it waits before updating." };
    }
  } else {
    // the deprecated "renovate" key in package.json
    const pkg = await readAt(dir, 'package.json');
    if (pkg === null) return null;
    where = 'package.json';
    if ('skipped' in pkg) return { status: 'unknown', by: 'renovate', where, why: `package.json couldn't be read (${SKIP_REASON[pkg.skipped]}), so pipegen can't tell whether it holds a Renovate config.` };
    let parsed: unknown;
    try {
      parsed = JSON.parse(pkg.text);
    } catch {
      return { status: 'unknown', by: 'renovate', where, why: "package.json isn't valid JSON, so pipegen can't tell whether it holds a Renovate config." };
    }
    const o = asObj(parsed);
    if (!Object.hasOwn(o, 'renovate')) return null;
    config = o.renovate;
  }
  const part = (why: string): Verdict => ({ status: 'partial', by: 'renovate', where, why });
  if (config === null || typeof config !== 'object' || Array.isArray(config)) return part("Renovate's config isn't an object that pipegen can read.");
  const c = config as Record<string, unknown>;
  if (c.enabled === false) return part('Renovate is turned off in its config (enabled is false).');
  const extendsList = Array.isArray(c.extends) ? c.extends : typeof c.extends === 'string' ? [c.extends] : [];
  if (extendsList.some((x) => typeof x === 'string' && /^:?disableRenovate$/.test(x))) return part('Renovate is turned off by a preset in its config.');
  if (Object.hasOwn(c, 'internalChecksFilter') && c.internalChecksFilter !== 'strict') {
    return part(`Renovate's internalChecksFilter isn't "strict", so it can still open update pull requests before ${COOLDOWN_DAYS} days have passed.`);
  }
  for (const k of ['ignorePaths', 'ignoreDeps', 'schedule']) {
    if (Object.hasOwn(c, k)) return part(`Renovate's config sets ${k}, which can keep it from updating some or all dependencies, so pipegen can't tell that the wait covers them.`);
  }
  const matchAllRule = Array.isArray(c.packageRules) && (c.packageRules as unknown[]).some((r) => {
    if (r === null || typeof r !== 'object' || Array.isArray(r)) return false;
    const o = r as Record<string, unknown>;
    const d = renovateDays(o.minimumReleaseAge);
    const keys = Object.keys(o).filter((k) => k !== 'minimumReleaseAge');
    const names = o.matchPackageNames;
    const all = keys.length === 0 || (keys.length === 1 && keys[0] === 'matchPackageNames' && Array.isArray(names) && names.length === 1 && (names[0] === '*' || names[0] === '/.*/'));
    return d !== null && d >= COOLDOWN_DAYS && all;
  });
  if (!Object.hasOwn(c, 'minimumReleaseAge') && !(extendsList.length > 0 && matchAllRule)) {
    return part(extendsList.length > 0
      ? "Renovate's minimumReleaseAge is set by a preset pipegen can't read, if at all."
      : `Renovate's config sets no minimumReleaseAge, so new releases are updated at once; pipegen uses ${COOLDOWN_DAYS} days.`);
  }
  const days = Object.hasOwn(c, 'minimumReleaseAge') ? renovateDays(c.minimumReleaseAge) : COOLDOWN_DAYS; // absent only with a match-all rule
  if (days === null || days < COOLDOWN_DAYS) return part(`Renovate's minimumReleaseAge is shorter than ${COOLDOWN_DAYS} days, or pipegen can't read it.`);
  if (Object.hasOwn(c, 'packageRules')) {
    if (!Array.isArray(c.packageRules)) return part("Renovate's packageRules isn't a list that pipegen can read.");
    if (c.packageRules.length > 1000) return part("Renovate's packageRules is longer than pipegen reads.");
    for (const rule of c.packageRules as unknown[]) {
      if (rule !== null && typeof rule === 'object' && !Array.isArray(rule) && ((rule as Record<string, unknown>).enabled === false
        || ['ignorePaths', 'ignoreDeps', 'schedule'].some((k) => Object.hasOwn(rule, k)))) return part('A Renovate packageRules entry turns updates off or limits them, so pipegen can\'t tell that the wait covers every dependency.');
      if (rule === null || typeof rule !== 'object' || Array.isArray(rule) || !Object.hasOwn(rule, 'minimumReleaseAge')) continue;
      const d = renovateDays((rule as Record<string, unknown>).minimumReleaseAge);
      if (d === null || d < COOLDOWN_DAYS) return part(`A Renovate packageRules entry sets a minimumReleaseAge under ${COOLDOWN_DAYS} days, or pipegen can't read it.`);
    }
  }
  // a preset in `extends` can carry its own packageRules with a shorter age; only a match-all rule of the repo's own wins over it
  if (extendsList.length > 0 && !matchAllRule) return part("Renovate's config extends a preset, which may set a shorter minimumReleaseAge for some packages, and pipegen can't read presets.");
  if (!running) return part("Renovate's config waits at least 7 days, but pipegen can't see whether the Renovate app is installed (read access doesn't show GitHub Apps), and no workflow runs Renovate.");
  return { status: 'covered', by: 'renovate', where, why: `Renovate waits at least ${COOLDOWN_DAYS} days (minimumReleaseAge) before updating, and a workflow runs Renovate on a schedule.` };
}

const MISSING_UPDATE_WHY = 'No Dependabot or Renovate config was found, so nothing opens update pull requests.';

/**
 * The update-config row (Dependabot or Renovate; the better row wins). `renovateRuns`: a scheduled workflow runs Renovate
 * itself (the only sign pipegen can see that the app is in use).
 */
export async function updateConfigCoverage(_p: RepoProfile, need: Need, dir: string, renovateRuns = false): Promise<Coverage> {
  const verdicts = [await dependabotVerdict(_p, dir), await renovateVerdict(dir, renovateRuns)].filter((v): v is Verdict => v !== null);
  if (verdicts.length === 0) return { need, status: 'missing', why: MISSING_UPDATE_WHY };
  const best = verdicts.reduce((a, b) => (rank[b.status] > rank[a.status] ? b : a));
  return { need, status: best.status, by: best.by, where: best.where, why: best.why };
}

// ---------- coverage minimum ----------

type Family = 'vitest' | 'jest' | 'python';
/** The coverage signatures whose minimum a config file can set, and which files they read. */
export const MINIMUM_FAMILY: Readonly<Record<string, Family>> = Object.freeze({ 'vitest-cov': 'vitest', 'jest-cov': 'jest', 'pytest-cov': 'python' });

type Found = { kind: 'set'; file: string } | { kind: 'unreadable' } | { kind: 'js'; file: string } | { kind: 'none' };

const JS_EXTS = ['ts', 'mts', 'cts', 'js', 'mjs', 'cjs'] as const;

/** JS or TS text with its comments replaced by one space each (a comment is never replaced by nothing). Strings are kept whole. */
export function stripComments(text: string): string {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i] as string;
    const d = text[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && text[i] !== '\n') i++;
      out += ' ';
    } else if (c === '/' && d === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? n : end + 2;
      out += ' ';
    } else if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < n && text[j] !== c && (c === '`' || text[j] !== '\n')) j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, Math.min(j + 1, n));
      i = j + 1;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/** A coverageThreshold value that sets a minimum: an object holding a number above 0 (depth and size bounded). */
function thresholdSet(v: unknown): boolean {
  const stack: unknown[] = [v];
  let seen = 0;
  while (stack.length > 0 && seen++ < 1000) {
    const x = stack.pop();
    if (typeof x === 'number') {
      if (Number.isFinite(x) && x > 0) return true;
    } else if (x !== null && typeof x === 'object' && !Array.isArray(x)) {
      for (const k of Object.keys(x)) if (k !== '__proto__') stack.push((x as Record<string, unknown>)[k]);
    }
  }
  return false;
}

const positive = (v: unknown): boolean => typeof v === 'number' && Number.isFinite(v) && v > 0;
const positiveText = (s: string) => /^\d{1,6}(\.\d{1,6})?$/.test(s) && Number(s) > 0;

async function jsonConfig(dir: string, folder: string, name: string, pick: (o: Record<string, unknown>) => unknown): Promise<Found> {
  const r = await readAt(dir, inRepo(folder, name));
  if (r === null) return { kind: 'none' };
  if ('skipped' in r) return { kind: 'unreadable' };
  try {
    const o = asObj(JSON.parse(r.text));
    const v = pick(o);
    return v !== undefined && thresholdSet(v) ? { kind: 'set', file: name } : { kind: 'none' };
  } catch {
    return { kind: 'unreadable' };
  }
}

async function jsText(dir: string, folder: string, names: readonly string[]): Promise<Found> {
  let unreadable = false;
  let js: Found = { kind: 'none' };
  for (const name of names) {
    for (const ext of JS_EXTS) {
      const r = await readAt(dir, inRepo(folder, `${name}.${ext}`));
      if (r === null) continue;
      if ('skipped' in r) {
        unreadable = true;
        continue;
      }
      if (/\b(coverageThreshold|thresholds)\b/.test(stripComments(r.text))) js = { kind: 'js', file: `${name}.${ext}` };
    }
  }
  return unreadable ? { kind: 'unreadable' } : js;
}

/** `fail_under` in an INI section, the last value: 'none' (no such key), a number text, or null (not a plain number). */
function iniFailUnder(text: string, section: string): string | null | undefined {
  let inSection = false;
  let value: string | null | undefined;
  for (const raw of regexLines(text)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue;
    const h = /^\[([^\]]{1,100})\]$/.exec(line);
    if (h) {
      inSection = h[1] === section;
      continue;
    }
    if (!inSection) continue;
    const m = /^fail_under\s*[=:]\s*(.*)$/.exec(line);
    if (m) value = positiveText((m[1] as string).trim()) ? (m[1] as string).trim() : null;
  }
  return value;
}

async function pythonMinimum(dir: string, folder: string): Promise<Found> {
  // coverage.py reads the first of these that exists (and, for setup.cfg, tox.ini and pyproject.toml, has coverage settings)
  const rc = await readAt(dir, inRepo(folder, '.coveragerc'));
  if (rc !== null) {
    if ('skipped' in rc) return { kind: 'unreadable' };
    return positiveText(iniFailUnder(rc.text, 'report') ?? '') ? { kind: 'set', file: '.coveragerc' } : { kind: 'none' };
  }
  if ((await readAt(dir, inRepo(folder, '.coveragerc.toml'))) !== null) return { kind: 'unreadable' }; // not read yet
  for (const name of ['setup.cfg', 'tox.ini']) {
    const r = await readAt(dir, inRepo(folder, name));
    if (r === null) continue;
    if ('skipped' in r) return { kind: 'unreadable' };
    if (!regexLines(r.text).some((l) => /^\[coverage:[^\]]*\]\s*$/.test(l.trim()))) continue;
    return positiveText(iniFailUnder(r.text, 'coverage:report') ?? '') ? { kind: 'set', file: name } : { kind: 'none' };
  }
  const py = await readAt(dir, inRepo(folder, 'pyproject.toml'));
  if (py === null) return { kind: 'none' };
  if ('skipped' in py) return { kind: 'unreadable' };
  try {
    const tool = asObj(asObj(parseToml(py.text)).tool);
    const report = asObj(asObj(tool.coverage).report);
    return positive(report.fail_under) ? { kind: 'set', file: 'pyproject.toml' } : { kind: 'none' };
  } catch {
    return { kind: 'unreadable' };
  }
}

async function minimumIn(dir: string, folder: string, family: Family | undefined): Promise<Found> {
  const all: Found[] = [];
  const want = (f: Family) => family === undefined || family === f;
  if (want('jest')) {
    all.push(await jsonConfig(dir, folder, 'package.json', (o) => asObj(o.jest).coverageThreshold));
    all.push(await jsonConfig(dir, folder, 'jest.config.json', (o) => o.coverageThreshold));
    all.push(await jsText(dir, folder, ['jest.config']));
  }
  if (want('vitest')) all.push(await jsText(dir, folder, ['vitest.config', 'vite.config']));
  if (want('python')) all.push(await pythonMinimum(dir, folder));
  return all.find((f) => f.kind === 'set') ?? all.find((f) => f.kind === 'unreadable') ?? all.find((f) => f.kind === 'js') ?? { kind: 'none' };
}

/**
 * Whether the files in a service's folder set a coverage minimum above 0: 'set' (a number in package.json's jest key,
 * jest.config.json, or a coverage config file), 'none', or 'unknown' (a file couldn't be read, or the only sign is a
 * threshold setting in JS config text, which pipegen can't read). `runDir` is the folder the run happens in (default:
 * the service's folder).
 */
export async function coverageMinimum(dir: string, s: Service, runDir?: string): Promise<'set' | 'none' | 'unknown'> {
  const folder = cleanFolder(runDir ?? s.path);
  if (folder === null) return 'unknown';
  const f = await minimumIn(dir, folder, undefined);
  return f.kind === 'set' ? 'set' : f.kind === 'none' ? 'none' : 'unknown';
}

/**
 * PS17: a coverage run found by a signature that only measures (`never`) is partial until a minimum is found. `hit` is the
 * first partial run behind the row: the minimum is looked for in the folder it runs in, with the files its tool reads.
 */
export async function coverageMinimumRow(row: Coverage, hit: Pick<Hit, 'by' | 'reason' | 'dir' | 'subject' | 'where'> | undefined, dir: string): Promise<Coverage> {
  if (row.status !== 'partial' || hit === undefined || hit.reason !== 'never' || hit.by === undefined || hit.by !== row.by || hit.where !== row.where) return row;
  const family = Object.hasOwn(MINIMUM_FAMILY, hit.by) ? MINIMUM_FAMILY[hit.by] : undefined;
  if (family === undefined || hit.dir === null) return row;
  const folder = cleanFolder(hit.dir);
  if (folder === null) return row;
  const f = await minimumIn(dir, folder, family);
  switch (f.kind) {
    case 'set':
      return { ...row, status: 'covered', why: `${hit.subject} measures coverage and a minimum is set in ${f.file}, so a drop below it fails the run.` };
    case 'js':
      return { ...row, why: `${hit.subject} measures coverage; pipegen found a coverage threshold setting in ${f.file} but can't read JS config to confirm it.` };
    case 'unreadable':
      return { ...row, status: 'unknown', why: `${hit.subject} measures coverage, but pipegen couldn't read a config file that may set a minimum (a symbolic link, too large or not valid), so it can't tell.` };
    default:
      return { ...row, why: `${hit.subject} measures coverage but sets no minimum, so a drop can't fail the build.` };
  }
}

// ---------- publishing ----------

const TOKEN_SECRET = /(NPM|NODE_AUTH|PYPI|TWINE)/i;
const TOKEN_WORD = /(TOKEN|PASSWORD|KEY)/i;
const TRUSTED_NOTE = "Trusted publishing is set up on npmjs.com or PyPI, which pipegen can't see.";

/**
 * PB4 (a): publishing is never "covered" from the profile alone. A secret named like a registry token → partial; other
 * secrets, or none → unknown (pipegen can't see where trusted publishing is configured, nor which step a secret reaches).
 */
export function publishingCoverage(p: RepoProfile, need: Need): Coverage {
  const publishing = p.existingWorkflows.filter((w) => (w.publishes?.length ?? 0) > 0);
  if (publishing.length === 0) return { need, status: 'missing', why: 'No workflow that publishes a package was found.' };
  const where = publishing.map((w) => w.path).find((x) => safeText(x) === x);
  const loc = where === undefined ? {} : { where };
  const names = publishing.flatMap((w) => w.secretsUsed).filter((n) => n.toUpperCase() !== 'GITHUB_TOKEN');
  if (names.some((n) => TOKEN_SECRET.test(n) && TOKEN_WORD.test(n))) {
    return { need, status: 'partial', ...loc, why: `This repo publishes with a long-lived token; trusted publishing needs none. ${TRUSTED_NOTE}` };
  }
  if (names.length > 0) {
    return { need, status: 'unknown', ...loc, why: `A workflow that publishes uses a secret, and pipegen can't tell whether it reaches the publish step. ${TRUSTED_NOTE}` };
  }
  return { need, status: 'unknown', ...loc, why: `pipegen can't confirm trusted publishing from the workflow alone. ${TRUSTED_NOTE}` };
}

// ---------- versions ----------

const MIGRATE_HINT = "ESLint's migration tool (@eslint/migrate-config)";
const ESLINT_EOL: Readonly<Record<number, string>> = { 8: '2024-10-05', 9: '2026-08-06' };

/** PS22, PS23: the ESLint version facts adjust the lint rows of the service whose tool is eslint or an own script. */
export function versionAdjust(rows: Coverage[], p: RepoProfile): Coverage[] {
  const byName = new Map<string, Service>();
  for (const s of p.services) if (!byName.has(s.name)) byName.set(s.name, s);
  return rows.map((r) => {
    if ((r.need.category !== 'lint' && r.need.category !== 'format-lint') || r.need.service === undefined) return r;
    if (r.status !== 'covered' && r.status !== 'partial') return r;
    if (r.by !== 'eslint' && !(r.by ?? '').startsWith('your own ')) return r;
    const s = byName.get(r.need.service);
    const version = s?.quality.versions.eslint;
    if (s === undefined || version === undefined) return r;
    const major = Number(version.split('.')[0]);
    if (!Number.isInteger(major)) return r;
    const range = s.quality.fromRange.includes('eslint');
    if (range && major >= 9 && major < 10 && s.quality.eslintConfig === 'eslintrc') {
      return {
        ...r, status: 'partial',
        why: `package.json asks for at least ESLint ${major}, which can resolve to ESLint 10, and ESLint 10 doesn't read .eslintrc, so this run may check nothing until the config is migrated (${MIGRATE_HINT} does it).`,
      };
    }
    if (major >= 10 && s.quality.eslintConfig === 'eslintrc') {
      return {
        ...r, status: 'partial',
        why: `ESLint 10 doesn't read .eslintrc, so this run can't check anything until the config is migrated (${MIGRATE_HINT} does it).${range ? ' The ESLint version comes from package.json.' : ''}`,
      };
    }
    if (!range && major === 9 && s.quality.eslintConfig === 'eslintrc') {
      return {
        ...r, status: 'partial',
        why: `ESLint 9 reads eslint.config.js, not .eslintrc, so this will fail with "couldn't find an eslint.config file" unless ESLINT_USE_FLAT_CONFIG=false is set (pipegen can't see that variable); ${MIGRATE_HINT} does the migration. ESLint 9 reached end of life on ${ESLINT_EOL[9]}.`,
      }
    }
    const eol = Object.hasOwn(ESLINT_EOL, major) ? ESLINT_EOL[major] : undefined;
    if (eol === undefined) return r;
    return { ...r, why: `${r.why} ${range ? `package.json asks for at least ESLint ${major}, and ESLint ${major}` : `ESLint ${major}`} reached end of life on ${eol}.` };
  });
}

// ---------- ESLint on Vue, Svelte and Astro files (DECISIONS #104) ----------

const UI_FILES = new Set(['vue', 'nuxt', 'svelte', 'astro']);
const UI_FILES_WHY = "pipegen can't check yet that your ESLint config reads .vue, .svelte and .astro files (that takes a parser or plugin such as eslint-plugin-vue, and pipegen reads those in v0.2), so it can't say those files are linted.";

/**
 * A lint row that pipegen found as the repo's own ESLint, for a Vue, Nuxt, Svelte or Astro service: those files need an
 * ESLint plugin pipegen does not read yet, so the row is never a clean pass. Covered → partial with a note; a row that is
 * already partial, missing or unknown keeps its status and its own why.
 */
export function frameworkAdjust(rows: Coverage[], p: RepoProfile): Coverage[] {
  const byName = new Map<string, Service>();
  for (const s of p.services) if (!byName.has(s.name)) byName.set(s.name, s);
  return rows.map((r) => {
    if ((r.need.category !== 'lint' && r.need.category !== 'format-lint') || r.need.service === undefined || r.status !== 'covered') return r;
    if (r.by !== 'eslint' && !(r.by ?? '').startsWith('your own ')) return r;
    const s = byName.get(r.need.service);
    if (s === undefined || s.quality.eslintConfig === 'none' || !s.quality.uiFrameworks.some((f) => UI_FILES.has(f))) return r;
    return { ...r, status: 'partial', why: `${r.why} ${UI_FILES_WHY}` };
  });
}
