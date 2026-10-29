import { lstat } from 'node:fs/promises';
import { basename, join as joinOs } from 'node:path';
import picomatch from 'picomatch';
import { parse as parseToml } from 'smol-toml';
import type { Language, Monorepo, PackageManager, RepoProfile, Service } from '../types.js';
import { PATH_SHOWN_MAX, safeText } from '../util/safe-text.js';
import { CODE_FILE_RE, REQUIREMENTS_FILE_RE, asObj, asString, asStrings, baseOf, dirOf, inDir, isTestFile, pythonNames, readPyproject, requirementLines, type Obj } from './manifest.js';
import { readEnv } from './env.js';
import { newQualityRun, readRepoFiles, readServiceQuality, type QualityRun } from './quality.js';
import { readPrecommit, readWorkflows } from './workflows.js';
import { IGNORED_DIRS, MAX_FILES_TEXT, SKIP_REASON, listFiles, parseYamlLimited, readTextLimitedWithReason, regexLines, regexSafe } from './limits.js';

export class NotGitHubRepoError extends Error {}

type Profile = Omit<RepoProfile, 'private' | 'ownerType' | 'plan'>;

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
async function readOrigin(root: string): Promise<{ owner: string; repo: string }> {
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

interface Shared { repo: string; serviceDirs: string[]; quality: QualityRun }

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

  // Files that belong to this service and not to a deeper one.
  const owned = files.filter((f) => isUnder(f, dir) && !shared.serviceDirs.some((o) => o.length > dir.length && isUnder(f, o)));
  const relTo = (f: string) => (dir === '.' ? f : f.slice(dir.length + 1));
  const testFiles = owned.filter((f) => isTestFile(relTo(f)));

  const scope = dir === '.' ? ['.'] : [dir, '.'];
  const lockfile = (locks: [string, PackageManager][]) => scope.flatMap((d) => locks.filter(([name]) => ctx.fileSet.has(inDir(d, name)))).map(([, pm]) => pm)[0];
  const packageManager = language === 'node' ? lockfile(NODE_LOCKS) : language === 'python' ? lockfile(PYTHON_LOCKS) ?? (requirementFiles.length > 0 ? 'pip' : undefined) : undefined;

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
  return { name, path: dir, language, packageManager, runtimeVersion, dockerfile, port, hasTests, testFramework, ...env, scripts, frameworks, quality };
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
  const rules = [/\bPORT\b[^\n]{0,40}?(?:\|\||\?\?)\s*['"]?(\d{2,5})\b/, /\bport\s*=\s*(\d{2,5})\b/i, /\bPORT['"]\s*,\s*['"]?(\d{2,5})\b/];
  for (const f of sources) {
    const text = await readFile(ctx, f);
    for (const line of text === null ? [] : regexLines(text)) {
      for (const rule of rules) {
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
  const shared: Shared = { repo, serviceDirs: dirs, quality: newQualityRun(dir, [...ctx.fileSet], dirs, workspaceMembers) };
  const services: Service[] = [];
  for (const d of dirs) services.push(await readService(ctx, d, shared));
  uniqueServiceNames(ctx, services);

  const files = [...ctx.fileSet];
  const existingWorkflows = await readWorkflows(dir, files, ctx.notes);
  // Plan U Task 5: the repo's only service, at the root, published to its own registry by a workflow, is a package.
  const only = services.length === 1 ? services[0] : undefined;
  const registry = only?.language === 'node' ? 'npm' : only?.language === 'python' ? 'pypi' : undefined;
  if (only !== undefined && only.path === '.' && registry !== undefined && existingWorkflows.some((w) => w.publishes?.includes(registry))) only.publishedPackage = true;
  return {
    owner, repo, defaultBranch: 'main', monorepo, services,
    terraformDirs: [...new Set(files.filter((f) => f.endsWith('.tf')).map(dirOf))].sort(),
    hasCompose: files.some((f) => /^(docker-)?compose\.ya?ml$/.test(baseOf(f))),
    existingWorkflows, precommit: readPrecommit(dir), repoFiles: await readRepoFiles(dir, ctx.notes, shared.quality),
  };
}
