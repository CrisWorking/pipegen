import { lstat } from 'node:fs/promises';
import { basename, join as joinOs } from 'node:path';
import picomatch from 'picomatch';
import { parse as parseToml } from 'smol-toml';
import type { Language, Monorepo, OtherHookManager, PackageManager, RepoProfile, Service } from '../types.js';
import { PATH_SHOWN_MAX, safeText } from '../util/safe-text.js';
import { CODE_FILE_RE, PLAIN_PATH_RE, PORT_RULES, REQUIREMENTS_FILE_RE, asObj, asString, asStrings, baseOf, dirOf, inDir, isTestFile, pythonNames, readPyproject, requirementLines, type Obj } from './manifest.js';
import { readEnv } from './env.js';
import { copySources, dockerfilesOf, notStandaloneOf, type DockerCopy } from './service-kind.js';
import { finishProjectTypes, projectTypeOf, untrackedIgnoredOf } from './project-type.js';
import { newQualityRun, npmLockfileVersion as npmLockfileVersionOf, readRepoFiles, readServiceQuality, type QualityRun } from './quality.js';
import { readPrecommit, readWorkflows } from './workflows.js';
import { IGNORED_DIRS, MAX_FILES_TEXT, SKIP_REASON, listFiles, parseYamlLimited, readTextLimitedWithReason, regexLines, regexSafe } from './limits.js';

export class NotGitHubRepoError extends Error {}

type Profile = Omit<RepoProfile, 'private' | 'ownerType' | 'plan'>;

/**
 * Plan B 6d (DECISIONS #108): names of folders that are vendored or generated. Looked for at the top of the root and of each
 * service folder (listFiles leaves node_modules, vendor, dist and target out of the file list on purpose), plus any folder
 * named generated or __generated__ among the files. `build` and `out` are NOT here: build scripts live in such folders.
 */
const TOP_GENERATED = ['node_modules', 'vendor', 'dist', 'target', '.next', '.venv'];
const GENERATED_NAMES = new Set(['generated', '__generated__']);
const MAX_GENERATED_DIRS = 64;

/** Every config name of the hook managers pipegen knows. A symbolic link at one counts as "this repo has hooks" (fail toward not offering). */
const HOOK_CONFIG_NAMES: readonly string[] = [
  '.pre-commit-config.yaml', '.husky', '.githooks', '.overcommit.yml', '.huskyrc', '.huskyrc.json', '.huskyrc.js', '.huskyrc.cjs', '.huskyrc.yaml', '.huskyrc.yml', 'husky.config.js', 'husky.config.cjs',
  '.simple-git-hooks.json', '.simple-git-hooks.js', '.simple-git-hooks.cjs', '.simple-git-hooks.mjs', 'simple-git-hooks.js', 'simple-git-hooks.cjs', 'simple-git-hooks.mjs', 'simple-git-hooks.json',
  ...['', '.config/'].flatMap((d) => ['', '.'].flatMap((dot) => ['lefthook', 'lefthook-local'].flatMap((b) => ['yml', 'yaml', 'toml', 'json', 'jsonc'].map((e) => `${d}${d === '' ? dot : ''}${b}.${e}`)))),
];

/** Hook managers beyond pre-commit, husky 9 and lefthook (6d fix rounds 1 and 2): the repo already has hooks, so pipegen builds none. */
async function readOtherHookManagers(root: string, rootPkg: unknown): Promise<OtherHookManager[]> {
  const out = new Set<OtherHookManager>();
  const kind = async (rel: string): Promise<'file' | 'dir' | 'link' | null> => {
    const info = await lstat(joinOs(root, rel)).catch(() => null);
    return info === null ? null : info.isSymbolicLink() ? 'link' : info.isDirectory() ? 'dir' : info.isFile() ? 'file' : null;
  };
  const pkg = typeof rootPkg === 'object' && rootPkg !== null ? (rootPkg as Record<string, unknown>) : {};
  const has = (k: string) => Object.hasOwn(pkg, k);
  const dep = (n: string) => ['dependencies', 'devDependencies', 'optionalDependencies'].some((g) => typeof pkg[g] === 'object' && pkg[g] !== null && Object.hasOwn(pkg[g] as object, n));
  if (has('simple-git-hooks')) out.add('simple-git-hooks');
  if (has('husky')) out.add('husky-v4');
  if (has('gitHooks')) out.add('yorkie');
  if (has('pre-commit') || dep('pre-commit')) out.add('pre-commit-npm');
  for (const n of HOOK_CONFIG_NAMES) {
    const k = await kind(n);
    if (k === 'link') out.add('linked-config');
    else if (k === 'file') {
      if (n.includes('simple-git-hooks')) out.add('simple-git-hooks');
      else if (n.startsWith('.huskyrc') || n.startsWith('husky.config')) out.add('husky-v4');
      else if (n === '.overcommit.yml') out.add('overcommit');
    }
  }
  if (await kind('.githooks') === 'dir') out.add('githooks');
  if (!out.has('githooks')) {
    const cfg = await readTextLimitedWithReason(joinOs(root, '.git', 'config'), root);
    if ('text' in cfg && /^\s*hookspath\s*=/im.test(cfg.text)) out.add('githooks');
  }
  return [...out];
}

async function readGeneratedDirs(root: string, serviceDirs: readonly string[], files: readonly string[]): Promise<string[]> {
  const found = new Set<string>();
  for (const d of new Set(['.', ...serviceDirs])) {
    for (const name of TOP_GENERATED) {
      const rel = inDir(d, name);
      const info = await lstat(joinOs(root, rel)).catch(() => null);
      if (info !== null && info.isDirectory() && !info.isSymbolicLink() && PLAIN_PATH_RE.test(rel)) found.add(rel);
    }
  }
  for (const f of files) {
    const parts = f.split('/');
    for (let i = 0; i < parts.length - 1; i++) {
      if (GENERATED_NAMES.has(parts[i] as string)) {
        const rel = parts.slice(0, i + 1).join('/');
        if (PLAIN_PATH_RE.test(rel)) found.add(rel);
        break;
      }
    }
  }
  return [...found].sort().slice(0, MAX_GENERATED_DIRS);
}

const NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1';
const NODE_LOCKS: [string, PackageManager][] = [['pnpm-lock.yaml', 'pnpm'], ['yarn.lock', 'yarn'], ['bun.lockb', 'bun'], ['bun.lock', 'bun'], ['package-lock.json', 'npm']];
const PYTHON_LOCKS: [string, PackageManager][] = [['poetry.lock', 'poetry'], ['uv.lock', 'uv']];
const NODE_FRAMEWORKS: [string, string][] = [['express', 'express'], ['fastify', 'fastify'], ['@nestjs/core', '@nestjs/core'], ['next', 'next'], ['koa', 'koa'], ['@hapi/hapi', 'hapi'], ['hapi', 'hapi']];
/**
 * Python server frameworks, by their PyPI distribution names (what dependencies list; pythonNames lowercases them). Fix
 * round 1 (I5) adds aiohttp, tornado, starlette, sanic, quart, litestar and falcon (each project's PyPI name is its
 * import name too). Not werkzeug: Flask itself depends on it, and a library would look like an app.
 */
const PYTHON_FRAMEWORKS = ['flask', 'fastapi', 'django', 'aiohttp', 'tornado', 'starlette', 'sanic', 'quart', 'litestar', 'falcon'];
/** Every name readProject can put in Service.frameworks. */
export const SERVER_FRAMEWORKS: readonly string[] = [...new Set([...NODE_FRAMEWORKS.map(([, name]) => name), ...PYTHON_FRAMEWORKS])];
const NODE_TEST_FRAMEWORKS = ['jest', 'vitest', 'mocha', 'ava'];
const MAX_PORT_SCAN_FILES = 100;
/** Service.name pattern (types.ts identifier rule). Exported so the needs planner (Plan B Task 1) re-checks names before an AI prompt. */
export const SERVICE_NAME_RE = /^[A-Za-z0-9._@/-]{1,214}$/;
const MAX_WORKSPACE_PATTERNS = 100;
/** Manifests of an app that isn't a Node package: a folder holding one (and a Dockerfile) is a service next to Node workspaces. */
const OTHER_APP_MANIFESTS = ['pyproject.toml', 'setup.py', 'go.mod'];
const NOT_SERVICE_DIRS = ['.devcontainer', 'test', 'tests', '__tests__', 'fixtures', 'examples', 'docs'];
// Root files read by direct path so the file cap can never hide them.
const ROOT_FILES = ['package.json', 'pnpm-workspace.yaml', 'turbo.json', 'nx.json', '.nvmrc', '.node-version', '.python-version', 'pyproject.toml', 'setup.py', 'Dockerfile', ...NODE_LOCKS.map(([f]) => f), ...PYTHON_LOCKS.map(([f]) => f)];

interface Ctx { root: string; fileSet: Set<string>; notes: string[] }

const isUnder = (file: string, dir: string) => dir === '.' || file.startsWith(`${dir}/`);

function note(ctx: Ctx, line: string): void {
  if (!ctx.notes.includes(line)) ctx.notes.push(line);
}

/**
 * Service names are unique (needs and the AI schema key on them). When two services share a name, the one with the
 * first path (sorted) keeps it and each later one becomes <name>-2, <name>-3, … skipping any name already in use,
 * cut so it still fits SERVICE_NAME_RE, with a note.
 */
function uniqueServiceNames(ctx: Ctx, services: Service[]): void {
  const byPath = [...services].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const taken = new Set(services.map((s) => s.name));
  const kept = new Set<string>();
  for (const s of byPath) {
    if (!kept.has(s.name)) {
      kept.add(s.name);
      continue;
    }
    let renamed = '';
    for (let i = 2; renamed === '' || taken.has(renamed); i++) {
      const suffix = `-${i}`;
      renamed = s.name.slice(0, 214 - suffix.length) + suffix;
    }
    note(ctx, `Two services were both named ${s.name}; the second is called ${renamed} here.`);
    taken.add(renamed);
    kept.add(renamed);
    s.name = renamed;
  }
}

/** Reads a listed file through the read limits; a skipped file is noted in plain English. */
async function readFile(ctx: Ctx, rel: string): Promise<string | null> {
  if (!ctx.fileSet.has(rel)) return null;
  const result = await readTextLimitedWithReason(joinOs(ctx.root, rel), ctx.root);
  if ('text' in result) return result.text;
  note(ctx, `Skipped ${safeText(rel, PATH_SHOWN_MAX)}: ${SKIP_REASON[result.skipped]}.`);
  return null;
}

async function readStructured(ctx: Ctx, rel: string, parse: (text: string) => unknown): Promise<Obj | null> {
  const text = await readFile(ctx, rel);
  if (text === null) return null;
  try {
    return asObj(parse(text));
  } catch {
    note(ctx, `Skipped ${safeText(rel, PATH_SHOWN_MAX)}: it could not be parsed.`);
    return null;
  }
}
const readJson = (ctx: Ctx, rel: string) => readStructured(ctx, rel, (t) => JSON.parse(t));
const readToml = (ctx: Ctx, rel: string) => readStructured(ctx, rel, parseToml);
const readYaml = (ctx: Ctx, rel: string) => readStructured(ctx, rel, parseYamlLimited);

/** Owner and repo from the `origin` URL in .git/config, read as plain text. Never runs git. */
export async function readOrigin(root: string): Promise<{ owner: string; repo: string }> {
  const gitDir = joinOs(root, '.git');
  const gitInfo = await lstat(gitDir).catch(() => null);
  if (gitInfo === null) throw new NotGitHubRepoError('This folder is not a git repository (no .git folder found).');
  if (gitInfo.isSymbolicLink()) throw new NotGitHubRepoError('.git is a symbolic link; refusing to follow it.');
  if (gitInfo.isFile()) throw new NotGitHubRepoError('.git is a file, so this is a git worktree or submodule; run pipegen from the main checkout.');
  const config = await readTextLimitedWithReason(joinOs(gitDir, 'config'), root);
  if (!('text' in config)) throw new NotGitHubRepoError('.git/config is missing or is not a regular text file, so pipegen cannot read the remote.');
  let inOrigin = false;
  let url: string | undefined;
  for (const raw of regexLines(config.text)) {
    const line = raw.trim();
    const section = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"([^"]*)")?\s*\]$/.exec(line);
    if (section) inOrigin = section[1]?.toLowerCase() === 'remote' && section[2] === 'origin'; // section names ignore case, the subsection does not
    else if (inOrigin && url === undefined) url = /^url\s*=\s*(.+)$/i.exec(line)?.[1]?.trim().replace(/^"(.*)"$/, '$1');
  }
  if (url === undefined) throw new NotGitHubRepoError('This repository has no "origin" remote, so pipegen cannot tell which GitHub repository it is.');
  // Accepted forms (each with an optional .git): scp-style git@github.com:o/r; https to github.com/o/r, with or without
  // user info (a user name and token) before the host; ssh://git@github.com/o/r, also on port 22.
  // User info is matched only to be dropped: it is never stored, returned or printed. It is limited to RFC 3986
  // userinfo characters, so `\`, `?` or `#` can't make another host look like github.com.
  const m = /^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(url)
    ?? /^https:\/\/(?:[A-Za-z0-9._~%!$&'()*+,;=:-]+@)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(url)
    ?? /^ssh:\/\/git@github\.com(?::22)?\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(url);
  if (!m) throw new NotGitHubRepoError('The "origin" remote is not a GitHub repository. pipegen only works with GitHub.');
  const [owner, repo] = [m[1] as string, m[2] as string];
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(repo) || repo === '.' || repo === '..') {
    throw new NotGitHubRepoError('The "origin" remote has an owner or repository name that GitHub would not accept.');
  }
  return { owner, repo };
}

interface Shared {
  repo: string; serviceDirs: string[]; quality: QualityRun; copies: DockerCopy[];
  /** Plan J J2: git's untracked-and-ignored test (J1's rule), loaded once and only when a static generator is found. */
  untrackedIgnored: () => Promise<(rel: string) => boolean>;
}

async function readService(ctx: Ctx, dir: string, shared: Shared): Promise<Service> {
  const files = [...ctx.fileSet];
  const pkg = await readJson(ctx, inDir(dir, 'package.json'));
  const toml = await readToml(ctx, inDir(dir, 'pyproject.toml'));
  const requirementFiles = files.filter((f) => dirOf(f) === dir && REQUIREMENTS_FILE_RE.test(baseOf(f)));
  const requirements: { file: string; names: string[] }[] = [];
  for (const file of requirementFiles) {
    const text = await readFile(ctx, file);
    if (text !== null) requirements.push({ file, names: pythonNames(requirementLines(text)) });
  }
  const requirementNames = requirements.flatMap((r) => r.names);
  const py = readPyproject(toml);
  // DoD run (spf13/cobra): a go.mod makes a Go service, so the audit can say plainly that Go isn't supported yet
  const language: Language = pkg ? 'node' : toml || requirementFiles.length > 0 || ctx.fileSet.has(inDir(dir, 'setup.py')) ? 'python'
    : ctx.fileSet.has(inDir(dir, 'go.mod')) ? 'go' : 'other';
  // P60 (R4): the folder's other manifests: a Python or Go app beside its package.json is that language too
  const python = toml !== null && toml !== undefined || requirementFiles.length > 0 || ctx.fileSet.has(inDir(dir, 'setup.py'));
  const alsoLanguages = ([['python', python], ['go', ctx.fileSet.has(inDir(dir, 'go.mod'))]] as [Language, boolean][])
    .filter(([l, has]) => has && l !== language).map(([l]) => l);

  // Files that belong to this service and not to a deeper one.
  const owned = files.filter((f) => isUnder(f, dir) && !shared.serviceDirs.some((o) => o.length > dir.length && isUnder(f, o)));
  const relTo = (f: string) => (dir === '.' ? f : f.slice(dir.length + 1));
  const testFiles = owned.filter((f) => isTestFile(relTo(f)));

  const scope = dir === '.' ? ['.'] : [dir, '.'];
  // the first lockfile of the scope (the service's own folder, then the root): its package manager and its path
  const lockfileAt = (locks: [string, PackageManager][]) => scope.flatMap((d) => locks.filter(([name]) => ctx.fileSet.has(inDir(d, name))).map(([name, pm]) => ({ pm, rel: inDir(d, name) })))[0];
  const lockfile = (locks: [string, PackageManager][]) => lockfileAt(locks)?.pm;
  const pythonManager = (): PackageManager | undefined => lockfile(PYTHON_LOCKS) ?? (requirementFiles.length > 0 ? 'pip' : undefined);
  const packageManager = language === 'node' ? lockfile(NODE_LOCKS) : language === 'python' ? pythonManager() : undefined;
  // final review r1-3: the licence coverage reads which npm lockfile version it is (Trivy reads licences from it only from v2) and the
  // lockfile of a second language (a requirements.txt beside a package.json), so neither reads as covered when it is not
  const npmLock = packageManager === 'npm' ? lockfileAt(NODE_LOCKS) : undefined;
  const npmLockfileVersion = npmLock === undefined ? undefined : await npmLockfileVersionOf(shared.quality, npmLock.rel);
  const alsoPackageManagers = alsoLanguages.flatMap((l) => { const pm = l === 'python' ? pythonManager() : undefined; return pm === undefined ? [] : [pm]; });

  const firstLine = async (rels: string[]) => {
    for (const rel of rels) {
      const v = asString((await readFile(ctx, rel))?.split(/\r?\n/)[0]);
      if (v) return v;
    }
    return undefined;
  };
  const runtimeVersion = language === 'node'
    ? (await firstLine(scope.flatMap((d) => [inDir(d, '.nvmrc'), inDir(d, '.node-version')]))) ?? asString(asObj(pkg?.engines).node)
    : language === 'python'
      ? (await firstLine(scope.map((d) => inDir(d, '.python-version')))) ?? py.requires
      : undefined;

  const dockerfile = ctx.fileSet.has(inDir(dir, 'Dockerfile')) ? inDir(dir, 'Dockerfile') : undefined;
  const deps = asObj(pkg?.dependencies);
  const devDeps = asObj(pkg?.devDependencies);
  const pkgScripts = asObj(pkg?.scripts);
  const scripts = [...new Set([...Object.keys(pkgScripts), ...py.scripts])];
  // Plan U Task 5: the service's own package is never a framework it uses (the express package isn't an express app;
  // Flask's own pyproject is named Flask).
  const ownNode = asString(pkg?.name);
  const ownPython = py.name === undefined ? undefined : pythonNames([py.name])[0];
  const frameworks = language === 'node'
    ? NODE_FRAMEWORKS.filter(([dep]) => dep in deps && dep !== ownNode).map(([, name]) => name).filter((n, i, a) => a.indexOf(n) === i)
    : [...new Set(PYTHON_FRAMEWORKS.filter((f) => f !== ownPython && [...py.main, ...requirementNames].includes(f)))];

  const realTestScript = asString(pkgScripts.test) !== undefined && asString(pkgScripts.test) !== NPM_DEFAULT_TEST;
  const hasTests = testFiles.length > 0 || realTestScript;

  let testFramework: string | undefined;
  if (language === 'node') {
    testFramework = NODE_TEST_FRAMEWORKS.find((f) => f in deps || f in devDeps);
    if (!testFramework && Object.values(pkgScripts).some((s) => typeof s === 'string' && regexSafe(s) && /\bnode\s+(--\S+\s+)*--test\b/.test(s))) testFramework = 'node:test';
  } else if (language === 'python') {
    const names = [...py.all, ...requirementNames];
    if (names.includes('pytest')) testFramework = 'pytest';
    else if (await anyFileHasLine(ctx, testFiles.filter((f) => f.endsWith('.py')), /^\s*(import|from)\s+unittest\b/)) testFramework = 'unittest';
  }

  const port = (dockerfile ? await exposedPort(ctx, dockerfile) : undefined) ?? (await codePort(ctx, owned.filter((f) => !isTestFile(relTo(f)))));

  // Raw but validated (see src/types.ts): the declared name if valid, else the folder name if valid, else 'app'.
  const declared = asString(pkg?.name) ?? py.name;
  const folder = dir === '.' ? shared.repo : basename(dir);
  const name = [declared, folder].find((n): n is string => n !== undefined && SERVICE_NAME_RE.test(n)) ?? 'app';
  const env = await readEnv(ctx.root, { path: dir, name }, owned, { pkg, py, requirements });
  const quality = await readServiceQuality(ctx.root, { path: dir, language, frameworks }, ctx.notes, shared.quality);
  // P55 (batch B): a folder that runs only by its start script, but is a one-shot script, is built into another image, or is an email-template package
  const kind = {
    dir, read: (rel: string) => readFile(ctx, rel), fileSet: ctx.fileSet, copies: shared.copies, scripts: pkgScripts, deps, devDeps, frameworks,
    hasDockerfile: dockerfile !== undefined, port, language, serviceDirs: shared.serviceDirs,
  };
  const notStandalone = await notStandaloneOf(kind);
  // Plan J J2 (ruling B2): the type from the service's own files; finishProjectTypes completes it after the workflow pass
  const projectType = await projectTypeOf({ ...kind, manifest: pkg ?? {}, untrackedIgnored: shared.untrackedIgnored });
  return {
    name, path: dir, language, ...(alsoLanguages.length === 0 ? {} : { alsoLanguages }), ...(alsoPackageManagers.length === 0 ? {} : { alsoPackageManagers }), packageManager,
    ...(npmLockfileVersion === undefined ? {} : { npmLockfileVersion }), runtimeVersion, dockerfile, port, hasTests, testFramework, ...env, scripts, frameworks, quality,
    ...(notStandalone === undefined ? {} : { notStandalone }), projectType,
  };
}

async function anyFileHasLine(ctx: Ctx, files: string[], re: RegExp): Promise<boolean> {
  for (const f of files) {
    const text = await readFile(ctx, f);
    if (text !== null && regexLines(text).some((l) => re.test(l))) return true;
  }
  return false;
}

const validPort = (s: string | undefined): number | undefined => (s !== undefined && Number(s) >= 1 && Number(s) <= 65535 ? Number(s) : undefined);

async function exposedPort(ctx: Ctx, dockerfile: string): Promise<number | undefined> {
  const text = await readFile(ctx, dockerfile);
  for (const line of text === null ? [] : regexLines(text)) {
    const m = /^\s*EXPOSE\s+(\d{1,5})\b/i.exec(line);
    if (m) return validPort(m[1]);
  }
  return undefined;
}

/** A PORT default in the code: `process.env.PORT || 3000`, `port=8000`. Looks at the shallowest source files first. */
async function codePort(ctx: Ctx, files: string[]): Promise<number | undefined> {
  const sources = files.filter((f) => CODE_FILE_RE.test(f)).sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b)).slice(0, MAX_PORT_SCAN_FILES);
  for (const f of sources) {
    const text = await readFile(ctx, f);
    for (const line of text === null ? [] : regexLines(text)) {
      for (const rule of PORT_RULES) {
        const port = validPort(rule.exec(line)?.[1]);
        if (port) return port;
      }
    }
  }
  return undefined;
}

/** Workspace globs from pnpm-workspace.yaml or package.json `workspaces`. */
function workspacePatterns(pnpm: Obj | null, rootPkg: Obj | null): string[] {
  if (pnpm) return asStrings(pnpm.packages);
  const ws = rootPkg?.workspaces;
  return Array.isArray(ws) ? asStrings(ws) : asStrings(asObj(ws).packages);
}

/** Workspace patterns are matched in memory against the listed files; one that points outside the repo is refused. */
function usablePatterns(ctx: Ctx, all: string[]): string[] {
  if (all.length > MAX_WORKSPACE_PATTERNS) note(ctx, `Only the first ${MAX_WORKSPACE_PATTERNS} workspace patterns were used.`);
  return all.slice(0, MAX_WORKSPACE_PATTERNS).filter((p) => {
    const bare = p.replace(/^!/, '');
    const outside = !regexSafe(p) || bare.startsWith('/') || bare.startsWith('~') || /^[A-Za-z]:/.test(bare) || bare.split(/[\\/]/).includes('..');
    if (outside) note(ctx, `Ignored workspace pattern "${safeText(p, 60)}": it points outside the repository or is not valid.`);
    return !outside;
  });
}

function workspaceDirs(ctx: Ctx, patterns: string[]): string[] {
  const clean = (p: string) => p.replace(/^!/, '').replace(/^\.\//, '').replace(/\/+$/, '');
  const include = patterns.filter((p) => !p.startsWith('!')).map((p) => picomatch(`${clean(p)}/package.json`, { dot: true }));
  const exclude = patterns.filter((p) => p.startsWith('!')).map((p) => picomatch(`${clean(p)}/**`, { dot: true }));
  return [...ctx.fileSet]
    .filter((f) => baseOf(f) === 'package.json' && f !== 'package.json' && include.some((m) => m(f)) && !exclude.some((m) => m(f)))
    .map(dirOf)
    .sort();
}

export async function readProject(dir: string, opts?: { notes?: string[] }): Promise<Profile> {
  const notes = opts?.notes ?? [];
  const { owner, repo } = await readOrigin(dir);
  const ignore = IGNORED_DIRS.map((d) => `**/${d}/**`);
  const listing = await listFiles(dir, ['**/*'], ignore);
  const ctx: Ctx = { root: dir, fileSet: new Set(listing.files.filter(regexSafe)), notes };
  if (listing.truncated) note(ctx, `Only the first ${MAX_FILES_TEXT} files were read. Results may be incomplete.`);
  for (const name of ROOT_FILES) if (!ctx.fileSet.has(name) && (await lstat(joinOs(dir, name)).catch(() => null))) ctx.fileSet.add(name);

  const rootPkg = await readJson(ctx, 'package.json');
  const pnpmWs = ctx.fileSet.has('pnpm-workspace.yaml') ? await readYaml(ctx, 'pnpm-workspace.yaml') : null;
  const patterns = usablePatterns(ctx, workspacePatterns(pnpmWs, rootPkg));

  // Which directories are services: workspace packages that can run, else directories with a Dockerfile, else the root.
  let dirs: string[] = [];
  for (const pkgDir of patterns.length > 0 ? workspaceDirs(ctx, patterns) : []) {
    const scripts = asObj((await readJson(ctx, inDir(pkgDir, 'package.json')))?.scripts);
    if ('start' in scripts || 'dev' in scripts || ctx.fileSet.has(inDir(pkgDir, 'Dockerfile'))) dirs.push(pkgDir);
  }
  const workspaceMembers = [...dirs];
  const isAppDockerfile = (f: string) => baseOf(f) === 'Dockerfile' && !dirOf(f).split('/').some((s) => NOT_SERVICE_DIRS.includes(s));
  const dockerDirs = [...new Set([...ctx.fileSet].filter(isAppDockerfile).map(dirOf))].sort();
  if (dirs.length === 0) dirs = dockerDirs.length > 0 ? dockerDirs : ['.'];
  else {
    // A Node workspace list names Node packages only (DoD run, fastapi/full-stack-fastapi-template: backend/ was lost). A
    // folder with a Dockerfile and a Python or Go manifest beside it is a service the list can't name; a Dockerfile
    // folder without one (an nginx or database image) stays out, as before.
    // P50 (I3): one pass over the files for the folders holding a requirements file, and a Set of the service folders,
    // so this stays linear in the number of files (it was a scan of every file per Dockerfile folder)
    const requirementDirs = new Set<string>();
    for (const f of ctx.fileSet) if (REQUIREMENTS_FILE_RE.test(baseOf(f))) requirementDirs.add(dirOf(f));
    const taken = new Set(dirs);
    const otherApp = (d: string) => !ctx.fileSet.has(inDir(d, 'package.json'))
      && (OTHER_APP_MANIFESTS.some((m) => ctx.fileSet.has(inDir(d, m))) || requirementDirs.has(d));
    for (const d of dockerDirs) {
      if (d === '.' || taken.has(d) || !otherApp(d)) continue;
      taken.add(d);
      dirs.push(d);
    }
  }

  let monorepo: Monorepo = 'none';
  if (pnpmWs) monorepo = 'pnpm-workspaces';
  else if (patterns.length > 0) monorepo = ctx.fileSet.has('yarn.lock') ? 'yarn-workspaces' : 'npm-workspaces';
  else if (ctx.fileSet.has('turbo.json')) monorepo = 'turbo';
  else if (ctx.fileSet.has('nx.json')) monorepo = 'nx';
  else if (dirs.length > 1) monorepo = 'folders';

  // Plan P Task 1: one run for the quality facts, so each lockfile is read once and the read budgets hold for the repo.
  let untracked: Promise<(rel: string) => boolean> | undefined;
  const shared: Shared = {
    repo, serviceDirs: dirs, quality: newQualityRun(dir, [...ctx.fileSet], dirs, workspaceMembers), copies: [],
    untrackedIgnored: () => (untracked ??= untrackedIgnoredOf(dir)),
  };
  // P55 (batch B): what each Dockerfile copies into its image (read once; a folder it copies is part of that image)
  const known = new Set<string>(ctx.fileSet);
  for (const f of ctx.fileSet) for (let d = dirOf(f); d !== '.' && !known.has(d); d = dirOf(d)) known.add(d);
  for (const f of dockerfilesOf(ctx.fileSet)) {
    const text = await readFile(ctx, f);
    if (text !== null) shared.copies.push(...copySources(dirOf(f), text, (p) => known.has(p)).map((source) => ({ dockerDir: dirOf(f), source })));
  }
  const services: Service[] = [];
  for (const d of dirs) services.push(await readService(ctx, d, shared));
  uniqueServiceNames(ctx, services);

  const files = [...ctx.fileSet];
  const existingWorkflows = await readWorkflows(dir, files, ctx.notes);
  // Plan U Task 5: the repo's only service, at the root, published to its own registry by a workflow, is a package.
  const only = services.length === 1 ? services[0] : undefined;
  const registry = only?.language === 'node' ? 'npm' : only?.language === 'python' ? 'pypi' : undefined;
  if (only !== undefined && only.path === '.' && registry !== undefined && existingWorkflows.some((w) => w.publishes?.includes(registry))) only.publishedPackage = true;
  // Plan J J2 (ruling B2): library for a published package, server by baseRunnable, static-host evidence
  finishProjectTypes(services, existingWorkflows);
  // a detected folder is never a whole service (a workspace package called `generated`) nor one that holds a service: skipping it would skip code pipegen was asked to check
  const detected = await readGeneratedDirs(dir, dirs, files);
  const generatedDirs = detected.filter((g) => {
    const hit = dirs.find((d) => d !== '.' && (d === g || d.startsWith(`${g}/`)));
    if (hit !== undefined) note(ctx, `pipegen did not treat ${g} as a generated folder: it is, or holds, the service folder ${hit}.`);
    return hit === undefined;
  });
  const otherHookManagers = await readOtherHookManagers(dir, rootPkg);
  return {
    owner, repo, defaultBranch: 'main', monorepo, services, ...(generatedDirs.length === 0 ? {} : { generatedDirs }), ...(otherHookManagers.length === 0 ? {} : { otherHookManagers }),
    terraformDirs: [...new Set(files.filter((f) => f.endsWith('.tf')).map(dirOf))].sort(),
    hasCompose: files.some((f) => /^(docker-)?compose\.ya?ml$/.test(baseOf(f))),
    existingWorkflows, precommit: readPrecommit(dir), repoFiles: await readRepoFiles(dir, ctx.notes, shared.quality),
  };
}
