import { lstat } from 'node:fs/promises';
import { join as joinOs } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { Language, QualityConfig, QualityPackage, RepoFiles, Service, ServiceQuality, UiFramework } from '../types.js';
import { PATH_SHOWN_MAX, safeText } from '../util/safe-text.js';
import { IGNORED_DIRS, READ_LIMITS, SKIP_REASON, linkedLevel, listFiles, readLinesLimited, readTextLimitedWithReason, regexLines, regexSafe, type Skipped } from './limits.js';
import { REQUIREMENTS_FILE_RE, asObj, baseOf, dirOf, inDir, pythonNames, readPyproject, requirementLines, type Obj } from './manifest.js';

// Plan P Task 1: the facts the quality, security and supply-chain checks read, per service (ServiceQuality) and once
// per repo (RepoFiles). The repo is attacker-controlled:
// - Every file is read through src/read/limits.ts: never through a symbolic link (at any level of its path), at most
//   1 MB for a config, at most 64 MB for a lockfile and 128 MB of lockfiles per run (ruling PS4), lines over 4 KB skipped.
// - Lockfiles are scanned line by line for the QUALITY_PACKAGES only, never parsed whole. Each one is read once per run,
//   for every service and name together. A version that can't be read from the lockfile comes from the lower bound of
//   the package.json range, is listed in `fromRange` and is explained in a note; it is never guessed from a partial read.
// - Values are kept raw but validated (src/types.ts): a version must match VERSION_RE and an apiSpec path must be
//   unchanged by safeText, or it is dropped. Notes name files through safeText.
// - Other files are found in the file list readProject already built (no new glob per service). Fixed repo-level paths
//   (Dependabot, Renovate, licence config) are checked by path, so the 20,000-file cap can never hide them.

export const QUALITY_PACKAGES: readonly QualityPackage[] = Object.freeze(['typescript', 'eslint', 'prettier', '@biomejs/biome', 'oxlint', 'vitest', 'jest', 'c8', 'knip', 'vue-tsc', 'svelte-check', '@astrojs/check'] as const);
/** The only version shape kept: the plan's pattern (a prerelease of at most 40 characters, no build metadata). */
export const VERSION_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]{1,40})?$/;
/** Ruling PS4. Decimal megabytes, as READ_LIMITS.maxFileBytes (1 MB) is. */
export const LOCKFILE_MAX_BYTES = 64_000_000;
export const LOCKFILE_RUN_BUDGET_BYTES = 128_000_000;
export const MAX_GO_TEST_FILES = 2000;
export const MAX_K8S_YAML_FILES = 200;
const MAX_SPEC_DEPTH = 4; // folders inside the service
const MAX_LOCK_ENTRIES = 50_000;

export const emptyServiceQuality = (): ServiceQuality => ({ tsconfig: false, versions: {}, fromRange: [], eslintConfig: 'none', configs: [], uiFrameworks: [], pythonTyped: false, fuzzTargets: false, apiSpec: null });
export const emptyRepoFiles = (): RepoFiles => ({ dependabot: null, renovate: null, actionsLock: false, kubernetes: false, licenceConfig: null, secretsBaseline: false });

// ---------- the run ----------

type LockKind = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'bun-binary';
/** Per lockfile: entries for the QUALITY_PACKAGES (key encoding per kind, see lockScanner) and the workspace members it lists. */
interface LockIndex { kind: LockKind; entries: Map<string, string>; members: Set<string> }
type LockState = { index: LockIndex } | { unread: string };

/**
 * One audit run's shared state, so the work grows with files + services, not their product (ruling PS4): the file
 * list, which service owns each file, each lockfile's scan, the lockfile budget and the Go test file budget.
 */
export interface QualityRun {
  root: string;
  files: readonly string[];
  fileSet: ReadonlySet<string>;
  serviceDirs: readonly string[];
  /** Services that are workspace packages of the root package.json: they also use the root's declared tools. */
  workspaceDirs: ReadonlySet<string>;
  owned?: Map<string, string[]>;
  locks: Map<string, LockState>;
  present: Map<string, 'file' | 'link' | 'other' | null>;
  parsed: Map<string, Obj | null>;
  /** INI section names (setup.cfg, tox.ini), read once per run: a root file is shared by every Python service. */
  ini: Map<string, string[]>;
  lockBudget: number;
  goTestFiles: number;
}

export function newQualityRun(root: string, files: readonly string[], serviceDirs: readonly string[], workspaceDirs: Iterable<string> = []): QualityRun {
  return {
    root, files, fileSet: new Set(files), serviceDirs, workspaceDirs: new Set(workspaceDirs),
    locks: new Map(), present: new Map(), parsed: new Map(), ini: new Map(), lockBudget: LOCKFILE_RUN_BUDGET_BYTES, goTestFiles: MAX_GO_TEST_FILES,
  };
}

/** A run for a caller outside readProject: the same listing readProject makes (symbolic links never listed). */
async function listedRun(dir: string, serviceDir: string): Promise<QualityRun> {
  const listing = await listFiles(dir, ['**/*'], IGNORED_DIRS.map((d) => `**/${d}/**`));
  return newQualityRun(dir, listing.files.filter(regexSafe), [serviceDir]);
}

function note(notes: string[], line: string): void {
  if (!notes.includes(line)) notes.push(line);
}

const hostileNote = (rel: string) => `Skipped ${safeText(rel, PATH_SHOWN_MAX)}: its path has control or invisible characters, or is too long.`;
const ancestors = (path: string): string[] => {
  const out = [path];
  while (out[out.length - 1] !== '.') out.push(dirOf(out[out.length - 1] as string));
  return out;
};

/** Files of each service and not of a deeper one: each file walks up its folders once. */
function ownedFiles(run: QualityRun, serviceDir: string): string[] {
  if (!run.owned) {
    const dirs = new Set(run.serviceDirs);
    run.owned = new Map([...dirs].map((d) => [d, []]));
    for (const f of run.files) {
      for (let d = dirOf(f); ; d = dirOf(d)) {
        if (dirs.has(d)) {
          run.owned.get(d)?.push(f);
          break;
        }
        if (d === '.') break;
      }
    }
  }
  return run.owned.get(serviceDir) ?? [];
}

/** What is at `rel`: a regular file, a symbolic link at any level of its path, something else, or nothing. */
async function presence(run: QualityRun, rel: string): Promise<'file' | 'link' | 'other' | null> {
  const known = run.present.get(rel);
  if (known !== undefined) return known;
  let found: 'file' | 'link' | 'other' | null = null;
  if ((await linkedLevel(run.root, rel)) !== null) found = 'link';
  else {
    const info = await lstat(joinOs(run.root, rel)).catch(() => null);
    found = info === null ? null : info.isFile() ? 'file' : 'other';
  }
  run.present.set(rel, found);
  return found;
}

/** A file's text through the read limits, by path; a symbolic link at any level of the path is never followed. */
async function readRel(run: QualityRun, rel: string, notes: string[]): Promise<string | null> {
  const linked = await linkedLevel(run.root, rel);
  if (linked !== null) {
    note(notes, `Skipped ${safeText(linked, PATH_SHOWN_MAX)}: ${SKIP_REASON.link}.`);
    return null;
  }
  const result = await readTextLimitedWithReason(joinOs(run.root, rel), run.root);
  if ('text' in result) return result.text;
  note(notes, `Skipped ${safeText(rel, PATH_SHOWN_MAX)}: ${SKIP_REASON[result.skipped]}.`);
  return null;
}

/** A JSON or TOML file, parsed once per run; null when missing, skipped or unparsable (with a note). */
async function parsedFile(run: QualityRun, rel: string, notes: string[]): Promise<Obj | null> {
  if (run.parsed.has(rel)) return run.parsed.get(rel) ?? null;
  let value: Obj | null = null;
  // by path when it isn't listed (a run without a listing, or past the file cap); readRel refuses a linked path
  if (run.fileSet.has(rel) || (await presence(run, rel)) !== null) {
    const text = await readRel(run, rel, notes);
    if (text !== null) {
      try {
        const doc: unknown = rel.endsWith('.toml') ? parseToml(text) : JSON.parse(text);
        value = asObj(doc);
      } catch {
        note(notes, `Skipped ${safeText(rel, PATH_SHOWN_MAX)}: it could not be parsed.`);
      }
    }
  }
  run.parsed.set(rel, value);
  return value;
}

// ---------- lockfiles ----------

const QP = new Set<string>(QUALITY_PACKAGES);
const NODE_LOCKFILES: readonly [string, LockKind][] = [['pnpm-lock.yaml', 'pnpm'], ['yarn.lock', 'yarn'], ['bun.lock', 'bun'], ['bun.lockb', 'bun-binary'], ['npm-shrinkwrap.json', 'npm'], ['package-lock.json', 'npm']];
const DEP_GROUPS = new Set(['dependencies', 'devDependencies', 'optionalDependencies']);
const LOCK_SKIP: Readonly<Record<Skipped, string>> = { 'too-large': 'is larger than 64 MB', binary: 'is a binary file', link: 'is a symbolic link', 'not-a-file': 'is not a regular file', unreadable: 'could not be read' };

/** pnpm and yarn versions carry peer or patch suffixes: `9.1.1(jiti@1.21.0)`, `5.4.5_typescript@5.0.0` (pnpm 5). */
function cleanVersion(raw: string): string | undefined {
  const v = raw.trim().replace(/^['"]|['"]$/g, '').split('(')[0]?.split('_')[0] ?? '';
  return VERSION_RE.test(v) ? v : undefined;
}

const unquote = (s: string): string => s.trim().replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
/** `@scope/name@range` → `@scope/name`. */
const descriptorName = (d: string): string => d.slice(0, Math.max(0, d.indexOf('@', 1)));

/**
 * One line-by-line pass collecting the QUALITY_PACKAGES entries. Key encoding:
 * - npm: `p:<packages key>` (`p:node_modules/eslint`, `p:packages/web/node_modules/eslint`), `v1:<name>` for v1's
 *   top-level `dependencies`; members are the `packages` keys outside node_modules (workspace folders).
 * - pnpm: `<importer>\0<name>` (importer `.` for the root and for pnpm 5–8 single-project files); members are importers.
 * - yarn: the descriptor (`eslint@^9.0.0` classic, `eslint@npm:^9.0.0` berry).
 * - bun: the `packages` key (`eslint`, `a-plugin/eslint`); members are the `workspaces` keys.
 * Only the line patterns below are matched (linear, on lines of 4 KB or less); anything else is ignored.
 */
function lockScanner(kind: Exclude<LockKind, 'bun-binary'>): { onLine: (line: string) => void; index: LockIndex } {
  const index: LockIndex = { kind, entries: new Map(), members: new Set() };
  const set = (key: string, raw: string) => {
    const v = cleanVersion(raw);
    if (v !== undefined && index.entries.size < MAX_LOCK_ENTRIES && !index.entries.has(key)) index.entries.set(key, v);
  };
  const member = (key: string) => {
    if (index.members.size < MAX_LOCK_ENTRIES) index.members.add(key);
  };
  let section = '';
  let pending: string[] = [];
  if (kind === 'npm') {
    return {
      index, onLine: (line) => {
        const top = /^ {2}"([^"\\]{1,64})":/.exec(line);
        if (top) section = top[1] ?? '';
        const key = /^( *)"([^"\\]{1,1024})": \{\s*$/.exec(line);
        if (key) {
          pending = [];
          const [, indent = '', k = ''] = key;
          if (section === 'packages' && indent.length === 4) {
            // only the keys a lookup can ask for: `node_modules/<name>` and `<folder>/node_modules/<name>`
            const at = k.indexOf('node_modules/');
            if (at < 0) member(k);
            else if ((at === 0 || k[at - 1] === '/') && QP.has(k.slice(at + 13))) pending = [`p:${k}`];
          } else if (section === 'dependencies' && indent.length === 4 && QP.has(k)) pending = [`v1:${k}`];
          return;
        }
        const version = /^\s*"version":\s*"([^"\\]{1,200})"/.exec(line);
        if (version && pending.length > 0) set(pending[0] as string, version[1] ?? '');
        if (version || /^\s*\}/.test(line)) pending = [];
      },
    };
  }
  if (kind === 'pnpm') {
    let importer = '';
    let inGroup = false;
    let offset = 0;
    return {
      index, onLine: (line) => {
        const m = /^( *)('[^']{1,1024}'|"[^"]{1,1024}"|[^\s#'"][^:]{0,1023}?):(?:[ \t]+(.*))?$/.exec(line);
        if (!m) return;
        const indent = (m[1] ?? '').length;
        const key = unquote(m[2] ?? '');
        const rest = (m[3] ?? '').trim();
        if (indent === 0) {
          section = key;
          pending = [];
          // pnpm 5–8 without workspaces: top-level dependency groups belong to the root importer
          inGroup = DEP_GROUPS.has(key);
          importer = '.';
          offset = 0;
          if (key === 'importers') offset = 4;
          return;
        }
        if (section === 'importers' && indent === 2) {
          importer = key;
          member(key);
          inGroup = false;
          pending = [];
        } else if (section === 'importers' && indent === 4) {
          inGroup = DEP_GROUPS.has(key);
          pending = [];
        } else if (inGroup && indent === offset + 2) {
          pending = QP.has(key) ? [`${importer}\0${key}`] : [];
          if (pending.length > 0 && rest !== '' && rest !== '{}') set(pending[0] as string, rest); // pnpm 5: `eslint: 9.1.1`
        } else if (inGroup && indent === offset + 4 && key === 'version' && pending.length > 0) {
          set(pending[0] as string, rest);
          pending = [];
        }
      },
    };
  }
  if (kind === 'yarn') {
    return {
      index, onLine: (line) => {
        if (line === '' || line.startsWith('#')) return;
        if (!/^\s/.test(line)) {
          pending = line.endsWith(':') ? line.slice(0, -1).split(', ').map((d) => unquote(d.replace(/^"|"$/g, ''))).filter((d) => QP.has(descriptorName(d))) : [];
          return;
        }
        const version = /^ {2}version:? "?([^"\s]{1,200})"?\s*$/.exec(line);
        if (version && pending.length > 0) {
          for (const d of pending) set(d, version[1] ?? '');
          pending = [];
        }
      },
    };
  }
  return {
    index, onLine: (line) => {
      const top = /^ {2}"([^"\\]{1,64})":/.exec(line);
      if (top) section = top[1] ?? '';
      if (section === 'workspaces') {
        const ws = /^ {4}"([^"\\]{1,1024})": \{/.exec(line);
        if (ws) member(ws[1] ?? '');
      } else if (section === 'packages') {
        const pkg = /^ {4}"([^"\\]{1,1024})": \["([^"\\]{1,1200})"/.exec(line);
        const [, key = '', spec = ''] = pkg ?? [];
        const name = descriptorName(spec); // the spec is `<name>@<version>`
        if (pkg && QP.has(name) && (key === name || key.endsWith(`/${name}`))) set(key, spec.slice(name.length + 1));
      }
    },
  };
}

/** The lockfile's scan, once per run; refused past 64 MB or past the run's 128 MB budget (never partly used). */
async function lockState(run: QualityRun, rel: string, kind: LockKind, found: 'file' | 'link' | 'other'): Promise<LockState> {
  const known = run.locks.get(rel);
  if (known !== undefined) return known;
  const name = safeText(rel, PATH_SHOWN_MAX);
  let state: LockState;
  if (found === 'link') state = { unread: `${name} ${LOCK_SKIP.link}` };
  else if (found === 'other') state = { unread: `${name} ${LOCK_SKIP['not-a-file']}` };
  else if (kind === 'bun-binary') state = { unread: `${name} is a binary file pipegen does not read` };
  else {
    const info = await lstat(joinOs(run.root, rel)).catch(() => null);
    if (info === null) state = { unread: `${name} ${LOCK_SKIP.unreadable}` };
    else if (info.size > LOCKFILE_MAX_BYTES) state = { unread: `${name} ${LOCK_SKIP['too-large']}` };
    else if (info.size > run.lockBudget) state = { unread: `${name} was not read: the 128 MB of lockfiles pipegen reads in one run was used up` };
    else {
      run.lockBudget -= info.size;
      const scan = lockScanner(kind);
      const read = await readLinesLimited(joinOs(run.root, rel), { maxBytes: LOCKFILE_MAX_BYTES, maxLineBytes: READ_LIMITS.maxRegexLineBytes }, scan.onLine, run.root);
      state = 'skipped' in read ? { unread: `${name} ${LOCK_SKIP[read.skipped]}` } : { index: scan.index };
    }
  }
  run.locks.set(rel, state);
  return state;
}

/** The lockfile that applies to a service: its own folder's first, else the root's. */
async function lockFor(run: QualityRun, servicePath: string): Promise<{ rel: string; dir: string; state: LockState } | null> {
  for (const d of servicePath === '.' ? ['.'] : [servicePath, '.']) {
    for (const [name, kind] of NODE_LOCKFILES) {
      const rel = inDir(d, name);
      const found = await presence(run, rel);
      if (found !== null) return { rel, dir: d, state: await lockState(run, rel, kind, found) };
    }
  }
  return null;
}

/** The version a package (declared with `range` by the package.json in `owner`, relative to the lockfile) resolves to. */
function lockVersion(index: LockIndex, name: string, range: string, owner: string): string | undefined {
  const e = index.entries;
  const member = owner === '' || index.members.has(owner);
  switch (index.kind) {
    case 'npm':
      return owner === ''
        ? e.get(`p:node_modules/${name}`) ?? e.get(`v1:${name}`)
        : e.get(`p:${owner}/node_modules/${name}`) ?? (member ? e.get(`p:node_modules/${name}`) : undefined);
    case 'pnpm':
      return e.get(`${owner === '' ? '.' : owner}\0${name}`);
    case 'yarn':
      return range.includes(':') ? e.get(`${name}@${range}`) : e.get(`${name}@npm:${range}`) ?? e.get(`${name}@${range}`);
    case 'bun':
      return member ? e.get(name) : undefined;
    default:
      return undefined;
  }
}

/** The lower bound of a package.json range: `^`, `~`, `>=`, `=` or exact, with missing parts as 0 (`^9` → 9.0.0). */
export function rangeLowerBound(range: string): string | undefined {
  if (!regexSafe(range)) return undefined;
  const m = /^(?:\^|~|>=|=)?\s*v?(\d{1,9})(?:\.(\d{1,9})(?:\.(\d{1,9})(-[0-9A-Za-z.-]{1,40})?)?)?$/.exec(range.trim());
  if (!m) return undefined;
  const v = `${m[1]}.${m[2] ?? '0'}.${m[3] ?? '0'}${m[4] ?? ''}`;
  return VERSION_RE.test(v) ? v : undefined;
}

/** Each wanted name the package.json declares (dependencies, devDependencies, optionalDependencies) with its range. */
function declared(pkg: Obj | null, names: readonly QualityPackage[]): Map<QualityPackage, string> {
  const out = new Map<QualityPackage, string>();
  for (const name of names) {
    for (const group of DEP_GROUPS) {
      const range = asObj(pkg?.[group])[name];
      if (typeof range === 'string' && !out.has(name)) out.set(name, range);
    }
  }
  return out;
}

type Versions = { versions: ServiceQuality['versions']; fromRange: QualityPackage[]; note?: string };

async function versionsIn(run: QualityRun, servicePath: string, names: readonly QualityPackage[], notes: string[]): Promise<Versions> {
  const own = declared(await parsedFile(run, inDir(servicePath, 'package.json'), notes), names);
  // A workspace package also runs the root's tools (hoisted, or found up the folders by node).
  const fromRoot = servicePath !== '.' && run.workspaceDirs.has(servicePath) ? declared(await parsedFile(run, 'package.json', notes), names) : new Map<QualityPackage, string>();
  const versions: ServiceQuality['versions'] = {};
  const fromRange: QualityPackage[] = [];
  if (own.size === 0 && fromRoot.size === 0) return { versions, fromRange };
  const lock = await lockFor(run, servicePath);
  const missing: string[] = [];
  for (const name of names) {
    const inService = own.get(name);
    const range = inService ?? fromRoot.get(name);
    if (range === undefined) continue;
    // where the declaring package.json sits, relative to the lockfile's folder ('' = the lockfile's own package.json)
    const owner = inService === undefined || lock === null || lock.dir === servicePath ? '' : servicePath;
    const locked = lock !== null && 'index' in lock.state ? lockVersion(lock.state.index, name, range, owner) : undefined;
    if (locked !== undefined) {
      versions[name] = locked;
      continue;
    }
    const lower = rangeLowerBound(range);
    if (lower === undefined) continue;
    versions[name] = lower;
    fromRange.push(name);
    missing.push(name);
  }
  if (fromRange.length === 0) return { versions, fromRange };
  const why = lock === null ? 'no lockfile was found' : 'unread' in lock.state ? lock.state.unread : `they are not listed in ${safeText(lock.rel, PATH_SHOWN_MAX)}`;
  const where = servicePath === '.' ? 'the repository root' : safeText(servicePath, PATH_SHOWN_MAX);
  return { versions, fromRange, note: `Versions of ${missing.join(', ')} in ${where} come from package.json ranges (the lowest version each allows), not from a lockfile: ${why}.` };
}

/**
 * The QUALITY_PACKAGES versions a node service uses, from its lockfile (its own folder's, else the root's). A name the
 * lockfile can't give falls back to the lower bound of its package.json range and is listed in `fromRange`, with `note`
 * saying why. `run` shares lockfile scans and the lockfile budget across services (readProject passes one).
 */
export async function lockfileVersions(dir: string, servicePath: string, names: readonly QualityPackage[], run?: QualityRun): Promise<Versions> {
  return versionsIn(run ?? newQualityRun(dir, [], [servicePath]), servicePath, names, []);
}

// ---------- per-service facts ----------

const ESLINT_FLAT = ['js', 'mjs', 'cjs', 'ts', 'mts', 'cts'].map((x) => `eslint.config.${x}`);
const ESLINT_RC = ['.eslintrc', ...['js', 'cjs', 'json', 'yaml', 'yml'].map((x) => `.eslintrc.${x}`)];
const JS_EXT = ['js', 'cjs', 'mjs', 'ts', 'cts', 'mts'];
const UI: readonly [string, UiFramework][] = [['next', 'next'], ['nuxt', 'nuxt'], ['vue', 'vue'], ['svelte', 'svelte'], ['astro', 'astro'], ['react-native', 'react-native']];
const TYPE_CHECKERS = ['mypy', 'pyright', 'basedpyright'];

interface ConfigRule { config: QualityConfig; language: Language; files: string[]; pkgKey?: string; tool?: string; ini?: RegExp }
/** Config files are looked for in the service's folder and every folder above it (the tools search upwards). */
const CONFIG_RULES: readonly ConfigRule[] = [
  { config: 'biome', language: 'node', files: ['biome.json', 'biome.jsonc'] },
  { config: 'prettier', language: 'node', files: ['.prettierrc', ...['json', 'json5', 'yaml', 'yml', 'toml', ...JS_EXT].map((x) => `.prettierrc.${x}`), ...JS_EXT.map((x) => `prettier.config.${x}`)], pkgKey: 'prettier' },
  { config: 'knip', language: 'node', files: ['knip.json', 'knip.jsonc', '.knip.json', '.knip.jsonc', ...JS_EXT.flatMap((x) => [`knip.${x}`, `knip.config.${x}`])], pkgKey: 'knip' },
  { config: 'oxlint', language: 'node', files: ['.oxlintrc.json', '.oxlintrc.jsonc', ...JS_EXT.map((x) => `oxlint.config.${x}`)] },
  { config: 'ruff', language: 'python', files: ['ruff.toml', '.ruff.toml'], tool: 'ruff' },
  { config: 'black', language: 'python', files: [], tool: 'black' },
  { config: 'flake8', language: 'python', files: ['.flake8'], ini: /^flake8$/ },
  { config: 'pylint', language: 'python', files: ['.pylintrc', 'pylintrc'], tool: 'pylint', ini: /^pylint(\..+)?$/ },
  { config: 'mypy', language: 'python', files: ['mypy.ini', '.mypy.ini'], tool: 'mypy', ini: /^mypy$/ },
  { config: 'pyright', language: 'python', files: ['pyrightconfig.json'], tool: 'pyright' },
  { config: 'basedpyright', language: 'python', files: [], tool: 'basedpyright' },
];

/** Section names of an INI file (setup.cfg, tox.ini), line by line. */
async function iniSections(run: QualityRun, rel: string, notes: string[]): Promise<string[]> {
  if (!run.fileSet.has(rel)) return [];
  const cached = run.ini.get(rel);
  if (cached !== undefined) return cached;
  const text = await readRel(run, rel, notes);
  const sections = text === null ? [] : regexLines(text).flatMap((l) => /^\s*\[([^\]]{1,200})\]\s*$/.exec(l)?.[1]?.trim() ?? []);
  run.ini.set(rel, sections);
  return sections;
}

async function configsOf(run: QualityRun, s: Pick<Service, 'path' | 'language'>, notes: string[]): Promise<QualityConfig[]> {
  const found = new Set<QualityConfig>();
  const rules = CONFIG_RULES.filter((r) => r.language === s.language);
  if (rules.length === 0) return [];
  for (const d of ancestors(s.path)) {
    const has = (name: string) => run.fileSet.has(inDir(d, name));
    const pkg = s.language === 'node' ? await parsedFile(run, inDir(d, 'package.json'), notes) : null;
    const tool = s.language === 'python' ? asObj((await parsedFile(run, inDir(d, 'pyproject.toml'), notes))?.tool) : {};
    const ini = s.language === 'python' ? [...(await iniSections(run, inDir(d, 'setup.cfg'), notes)), ...(await iniSections(run, inDir(d, 'tox.ini'), notes))] : [];
    for (const r of rules) {
      const inIni = r.ini !== undefined && ini.some((sec) => r.ini?.test(sec) === true);
      if (r.files.some(has) || (r.pkgKey !== undefined && pkg !== null && r.pkgKey in pkg) || (r.tool !== undefined && r.tool in tool) || inIni) found.add(r.config);
    }
  }
  return CONFIG_RULES.map((r) => r.config).filter((c) => found.has(c));
}

async function eslintConfigOf(run: QualityRun, s: Pick<Service, 'path' | 'language'>, notes: string[]): Promise<ServiceQuality['eslintConfig']> {
  if (s.language !== 'node') return 'none';
  let flat = false;
  let rc = false;
  for (const d of ancestors(s.path)) {
    flat ||= ESLINT_FLAT.some((f) => run.fileSet.has(inDir(d, f)));
    rc ||= ESLINT_RC.some((f) => run.fileSet.has(inDir(d, f))) || 'eslintConfig' in (await parsedFile(run, inDir(d, 'package.json'), notes) ?? {});
  }
  return flat && rc ? 'both' : flat ? 'flat' : rc ? 'eslintrc' : 'none';
}

const SPEC_RE = /^(?:(?:openapi|swagger)\.(?:json|ya?ml)|.+\.openapi\.(?:json|ya?ml)|schema\.graphql)$/;

/** The shallowest spec file inside the service (not in another service's folder), at most 4 folders deep. */
function specFileOf(run: QualityRun, servicePath: string, notes: string[]): string | null {
  const relTo = (f: string) => (servicePath === '.' ? f : f.slice(servicePath.length + 1));
  const candidates = ownedFiles(run, servicePath)
    .filter((f) => relTo(f).split('/').length <= MAX_SPEC_DEPTH + 1 && SPEC_RE.test(baseOf(f)))
    .sort((a, b) => a.split('/').length - b.split('/').length || (a < b ? -1 : a > b ? 1 : 0));
  for (const f of candidates) {
    if (safeText(f) === f) return f;
    note(notes, hostileNote(f));
  }
  return null;
}

async function goFuzz(run: QualityRun, servicePath: string, notes: string[]): Promise<boolean> {
  for (const f of ownedFiles(run, servicePath).filter((x) => x.endsWith('_test.go'))) {
    if (run.goTestFiles <= 0) {
      note(notes, `Only the first ${MAX_GO_TEST_FILES.toLocaleString('en-US')} Go test files were checked for fuzz tests.`);
      return false;
    }
    run.goTestFiles--;
    const text = await readRel(run, f, notes);
    if (text !== null && regexLines(text).some((l) => /^func Fuzz[A-Z0-9_]/.test(l))) return true;
  }
  return false;
}

/**
 * The quality facts of one service. `s` needs only its folder, language and frameworks, so readProject can call it
 * before the Service is complete. Without `run`, the repo is listed here (as readProject lists it).
 */
export async function readServiceQuality(dir: string, s: Pick<Service, 'path' | 'language' | 'frameworks'>, notes: string[], run?: QualityRun): Promise<ServiceQuality> {
  const r = run ?? (await listedRun(dir, s.path));
  const q = emptyServiceQuality();
  q.tsconfig = r.fileSet.has(inDir(s.path, 'tsconfig.json'));
  q.configs = await configsOf(r, s, notes);
  q.eslintConfig = await eslintConfigOf(r, s, notes);

  let deps: Obj = {};
  let pythonDeps: string[] = [];
  if (s.language === 'node') {
    const pkg = await parsedFile(r, inDir(s.path, 'package.json'), notes);
    deps = { ...asObj(pkg?.optionalDependencies), ...asObj(pkg?.devDependencies), ...asObj(pkg?.dependencies) };
    const ownName = typeof pkg?.name === 'string' ? pkg.name : undefined;
    q.uiFrameworks = UI.filter(([dep]) => dep in deps && dep !== ownName).map(([, ui]) => ui);
    const v = await versionsIn(r, s.path, QUALITY_PACKAGES, notes);
    q.versions = v.versions;
    q.fromRange = v.fromRange;
    if (v.note !== undefined) note(notes, v.note);
  } else if (s.language === 'python') {
    const py = readPyproject(await parsedFile(r, inDir(s.path, 'pyproject.toml'), notes));
    const reqs = ownedFiles(r, s.path).filter((f) => dirOf(f) === s.path && REQUIREMENTS_FILE_RE.test(baseOf(f)));
    const reqNames: string[] = [];
    for (const f of reqs) {
      const text = await readRel(r, f, notes);
      if (text !== null) reqNames.push(...pythonNames(requirementLines(text)));
    }
    pythonDeps = [...py.all, ...reqNames];
    q.pythonTyped = q.configs.some((c) => c === 'mypy' || c === 'pyright' || c === 'basedpyright')
      || ownedFiles(r, s.path).some((f) => baseOf(f) === 'py.typed')
      || pythonDeps.some((n) => TYPE_CHECKERS.includes(n));
  }

  const spec = specFileOf(r, s.path, notes);
  q.apiSpec = spec !== null ? { kind: 'file', path: spec }
    : s.language === 'python' && s.frameworks.includes('fastapi') ? { kind: 'served', by: 'fastapi' }
      : s.language === 'node' && '@nestjs/swagger' in deps ? { kind: 'served', by: '@nestjs/swagger' }
        : null;
  q.fuzzTargets = '@jazzer.js/core' in deps || pythonDeps.includes('atheris') || (await goFuzz(r, s.path, notes));
  return q;
}

// ---------- repo files ----------

const DEPENDABOT = ['.github/dependabot.yml', '.github/dependabot.yaml'];
const RENOVATE = ['renovate.json', 'renovate.json5', '.github/renovate.json', '.github/renovate.json5', '.gitlab/renovate.json', '.gitlab/renovate.json5', '.renovaterc', '.renovaterc.json', '.renovaterc.json5'];
const LICENCE_CONFIGS = ['deny.toml', '.grant.yaml', '.fossa.yml'] as const;
/** The only folders whose YAML is read for Kubernetes manifests (also named in the report's "can't see" list). */
export const K8S_FOLDERS: readonly string[] = Object.freeze(['k8s', 'kubernetes', 'manifests', 'deploy', 'helm', 'charts']);
const K8S_DIRS = new Set(K8S_FOLDERS);

/** A regular file at a fixed path; a symbolic link at any level of it is noted and never followed. */
async function realFile(run: QualityRun, rel: string, notes: string[]): Promise<boolean> {
  const found = await presence(run, rel);
  if (found === 'link') note(notes, `Skipped ${safeText((await linkedLevel(run.root, rel)) ?? rel, PATH_SHOWN_MAX)}: ${SKIP_REASON.link}.`);
  return found === 'file';
}

async function firstReal<T extends string>(run: QualityRun, rels: readonly T[], notes: string[]): Promise<T | null> {
  for (const rel of rels) if (await realFile(run, rel, notes)) return rel;
  return null;
}

async function kubernetesOf(run: QualityRun, notes: string[]): Promise<boolean> {
  if (run.files.some((f) => baseOf(f) === 'Chart.yaml')) return true;
  const yaml = run.files.filter((f) => /\.ya?ml$/.test(f) && dirOf(f).split('/').some((seg) => K8S_DIRS.has(seg))).sort();
  for (const f of yaml.slice(0, MAX_K8S_YAML_FILES)) {
    const text = await readRel(run, f, notes);
    const lines = text === null ? [] : regexLines(text);
    if (lines.some((l) => /^apiVersion:\s*\S/.test(l)) && lines.some((l) => /^kind:\s*\S/.test(l))) return true;
  }
  // final review m1: a "not found" past the cap may be a manifest pipegen didn't read
  if (yaml.length > MAX_K8S_YAML_FILES) {
    note(notes, `Only the first ${MAX_K8S_YAML_FILES.toLocaleString('en-US')} YAML files in Kubernetes folders (${K8S_FOLDERS.join(', ')}) were checked for Kubernetes manifests.`);
  }
  return false;
}

/** The repo-level files the checks read, once per repo. Without `run`, the repo is listed here. */
export async function readRepoFiles(dir: string, notes: string[], run?: QualityRun): Promise<RepoFiles> {
  const r = run ?? (await listedRun(dir, '.'));
  const rootPkg = await parsedFile(r, 'package.json', notes);
  return {
    dependabot: await firstReal(r, DEPENDABOT, notes),
    renovate: (await firstReal(r, RENOVATE, notes)) ?? (rootPkg !== null && 'renovate' in rootPkg ? 'package.json' : null),
    actionsLock: (await realFile(r, '.github/actions.lock', notes)) || r.files.some((f) => f.startsWith('.github/') && baseOf(f) === 'actions.lock'),
    kubernetes: await kubernetesOf(r, notes),
    licenceConfig: await firstReal(r, LICENCE_CONFIGS, notes),
    secretsBaseline: await realFile(r, '.secrets.baseline', notes),
  };
}
