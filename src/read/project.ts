import { basename, join as joinOs } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { Language, Monorepo, PackageManager, RepoProfile, Service } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { listFiles, parseYamlLimited, readTextLimited, regexLines } from './limits.js';

export class NotGitHubRepoError extends Error {}

type Profile = Omit<RepoProfile, 'private' | 'ownerType' | 'plan'>;
type Obj = Record<string, unknown>;

const IGNORED_DIRS = ['node_modules', '.git', '.venv', 'dist', 'build', 'vendor', 'target'];
const NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1';
const NODE_LOCKS: [string, PackageManager][] = [['pnpm-lock.yaml', 'pnpm'], ['yarn.lock', 'yarn'], ['bun.lockb', 'bun'], ['bun.lock', 'bun'], ['package-lock.json', 'npm']];
const PYTHON_LOCKS: [string, PackageManager][] = [['poetry.lock', 'poetry'], ['uv.lock', 'uv']];
const NODE_FRAMEWORKS: [string, string][] = [['express', 'express'], ['fastify', 'fastify'], ['@nestjs/core', '@nestjs/core'], ['next', 'next'], ['koa', 'koa'], ['@hapi/hapi', 'hapi'], ['hapi', 'hapi']];
const PYTHON_FRAMEWORKS = ['flask', 'fastapi', 'django'];
const NODE_TEST_FRAMEWORKS = ['jest', 'vitest', 'mocha', 'ava'];
const MAX_PORT_SCAN_FILES = 100;

interface Ctx { root: string; fileSet: Set<string>; notes: string[] }

const asObj = (v: unknown): Obj => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
const asStrings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const asString = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined);
const inDir = (dir: string, name: string) => (dir === '.' ? name : `${dir}/${name}`);
const dirOf = (file: string) => (file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : '.');
const baseOf = (file: string) => file.slice(file.lastIndexOf('/') + 1);
const isUnder = (file: string, dir: string) => dir === '.' || file.startsWith(`${dir}/`);

function note(ctx: Ctx, line: string): void {
  if (!ctx.notes.includes(line)) ctx.notes.push(line);
}

/** Reads a listed file through the read limits; a skipped file is noted in plain English. */
async function readFile(ctx: Ctx, rel: string): Promise<string | null> {
  if (!ctx.fileSet.has(rel)) return null;
  const text = await readTextLimited(joinOs(ctx.root, rel));
  if (text === null) note(ctx, `Skipped ${safeText(rel)}: it is too large, binary or a link.`);
  return text;
}

async function readStructured(ctx: Ctx, rel: string, parse: (text: string) => unknown): Promise<Obj | null> {
  const text = await readFile(ctx, rel);
  if (text === null) return null;
  try {
    return asObj(parse(text));
  } catch {
    note(ctx, `Skipped ${safeText(rel)}: it could not be parsed.`);
    return null;
  }
}
const readJson = (ctx: Ctx, rel: string) => readStructured(ctx, rel, (t) => JSON.parse(t));
const readToml = (ctx: Ctx, rel: string) => readStructured(ctx, rel, parseToml);
const readYaml = (ctx: Ctx, rel: string) => readStructured(ctx, rel, parseYamlLimited);

/** Owner and repo from the `origin` URL in .git/config, read as plain text. Never runs git. */
async function readOrigin(root: string): Promise<{ owner: string; repo: string }> {
  const text = await readTextLimited(joinOs(root, '.git', 'config'));
  if (text === null) throw new NotGitHubRepoError('This folder is not a git repository (no .git/config found).');
  let inOrigin = false;
  let url: string | undefined;
  for (const raw of regexLines(text)) {
    const line = raw.trim();
    const section = /^\[(.+)\]$/.exec(line);
    if (section) inOrigin = /^remote\s+"origin"$/.test(section[1] ?? '');
    else if (inOrigin && url === undefined) url = /^url\s*=\s*(.+)$/.exec(line)?.[1]?.trim().replace(/^"(.*)"$/, '$1');
  }
  if (url === undefined) throw new NotGitHubRepoError('This repository has no "origin" remote, so pipegen cannot tell which GitHub repository it is.');
  const m = /^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(url) ?? /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(url);
  if (!m) throw new NotGitHubRepoError('The "origin" remote is not a GitHub repository. pipegen only works with GitHub.');
  return { owner: m[1] as string, repo: m[2] as string };
}

/** Package names from PEP 508 strings or requirements lines, lowercased with _ as -. */
function pythonNames(lines: string[]): string[] {
  return lines.flatMap((l) => {
    const name = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(l)?.[1];
    return name ? [name.toLowerCase().replace(/[._]/g, '-')] : [];
  });
}

interface PyInfo { main: string[]; all: string[]; scripts: string[]; requires?: string; name?: string }

function readPyproject(toml: Obj | null): PyInfo {
  const project = asObj(toml?.project);
  const poetry = asObj(asObj(toml?.tool).poetry);
  const poetryDeps = asObj(poetry.dependencies);
  const groups = Object.values(asObj(poetry.group)).flatMap((g) => Object.keys(asObj(asObj(g).dependencies)));
  const main = [...pythonNames(asStrings(project.dependencies)), ...Object.keys(poetryDeps).filter((k) => k !== 'python').map((k) => k.toLowerCase())];
  const extras = [
    ...Object.values(asObj(project['optional-dependencies'])).flatMap(asStrings),
    ...Object.values(asObj(toml?.['dependency-groups'])).flatMap(asStrings),
    ...asStrings(asObj(asObj(asObj(toml?.tool).uv))['dev-dependencies']),
  ];
  return {
    main,
    all: [...main, ...pythonNames(extras), ...groups.map((g) => g.toLowerCase()), ...Object.keys(asObj(poetry['dev-dependencies'])).map((k) => k.toLowerCase())],
    scripts: [...Object.keys(asObj(project.scripts)), ...Object.keys(asObj(poetry.scripts))],
    requires: asString(project['requires-python']) ?? asString(poetryDeps.python),
    name: asString(project.name) ?? asString(poetry.name),
  };
}

const isTestFile = (rel: string): boolean => {
  const segments = rel.split('/');
  const name = segments[segments.length - 1] ?? '';
  return segments.slice(0, -1).some((s) => ['test', 'tests', '__tests__'].includes(s)) || /^.+\.(test|spec)\..+$/.test(name) || /^test_.+\.py$/.test(name) || /_test\.py$/.test(name);
};

interface Shared { repo: string; serviceDirs: string[] }

async function readService(ctx: Ctx, dir: string, shared: Shared): Promise<Service> {
  const files = [...ctx.fileSet];
  const pkg = await readJson(ctx, inDir(dir, 'package.json'));
  const toml = await readToml(ctx, inDir(dir, 'pyproject.toml'));
  const requirementFiles = files.filter((f) => dirOf(f) === dir && /^requirements.*\.txt$/.test(baseOf(f)));
  const requirementNames = pythonNames((await Promise.all(requirementFiles.map((f) => readFile(ctx, f)))).flatMap((t) => (t === null ? [] : regexLines(t).filter((l) => !/^\s*(#|-)/.test(l)))));
  const py = readPyproject(toml);
  const language: Language = pkg ? 'node' : toml || requirementFiles.length > 0 || ctx.fileSet.has(inDir(dir, 'setup.py')) ? 'python' : 'other';

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
  const frameworks = language === 'node'
    ? NODE_FRAMEWORKS.filter(([dep]) => dep in deps).map(([, name]) => name).filter((n, i, a) => a.indexOf(n) === i)
    : [...new Set(PYTHON_FRAMEWORKS.filter((f) => [...py.main, ...requirementNames].includes(f)))];

  const realTestScript = asString(pkgScripts.test) !== undefined && asString(pkgScripts.test) !== NPM_DEFAULT_TEST;
  const hasTests = testFiles.length > 0 || realTestScript;

  let testFramework: string | undefined;
  if (language === 'node') {
    testFramework = NODE_TEST_FRAMEWORKS.find((f) => f in deps || f in devDeps);
    if (!testFramework && Object.values(pkgScripts).some((s) => typeof s === 'string' && /\bnode\s+(--\S+\s+)*--test\b/.test(s))) testFramework = 'node:test';
  } else if (language === 'python') {
    const names = [...py.all, ...requirementNames];
    if (names.includes('pytest')) testFramework = 'pytest';
    else if (await anyFileHasLine(ctx, testFiles.filter((f) => f.endsWith('.py')), /^\s*(import|from)\s+unittest\b/)) testFramework = 'unittest';
  }

  const port = (dockerfile ? await exposedPort(ctx, dockerfile) : undefined) ?? (await codePort(ctx, owned.filter((f) => !isTestFile(relTo(f)))));

  const name = asString(pkg?.name) ?? py.name ?? (dir === '.' ? shared.repo : basename(dir));
  return { name: safeText(name), path: dir, language, packageManager, runtimeVersion, dockerfile, port, hasTests, testFramework, envVars: [], dependsOn: [], scripts, frameworks };
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
  const sources = files.filter((f) => /\.(js|mjs|cjs|ts|py)$/.test(f)).sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b)).slice(0, MAX_PORT_SCAN_FILES);
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

export async function readProject(dir: string, opts?: { notes?: string[] }): Promise<Profile> {
  const notes = opts?.notes ?? [];
  const { owner, repo } = await readOrigin(dir);
  const ignore = IGNORED_DIRS.map((d) => `**/${d}/**`);
  const listing = await listFiles(dir, ['**/*'], ignore);
  const ctx: Ctx = { root: dir, fileSet: new Set(listing.files), notes };
  if (listing.truncated) note(ctx, 'Only the first 20,000 files were read.');

  const rootPkg = await readJson(ctx, 'package.json');
  const pnpmWs = ctx.fileSet.has('pnpm-workspace.yaml') ? await readYaml(ctx, 'pnpm-workspace.yaml') : null;
  const patterns = workspacePatterns(pnpmWs, rootPkg);

  // Which directories are services: workspace packages that can run, else directories with a Dockerfile, else the root.
  let dirs: string[] = [];
  if (patterns.length > 0) {
    const include = patterns.filter((p) => !p.startsWith('!')).map((p) => `${p.replace(/\/+$/, '')}/package.json`);
    const exclude = patterns.filter((p) => p.startsWith('!')).map((p) => `${p.slice(1).replace(/\/+$/, '')}/**`);
    const found = include.length === 0 ? [] : (await listFiles(dir, include, [...ignore, ...exclude])).files;
    for (const file of found.sort()) {
      const pkgDir = dirOf(file);
      if (pkgDir === '.') continue;
      const scripts = asObj((await readJson(ctx, file))?.scripts);
      if ('start' in scripts || 'dev' in scripts || ctx.fileSet.has(inDir(pkgDir, 'Dockerfile'))) dirs.push(pkgDir);
    }
  }
  const dockerDirs = [...new Set([...ctx.fileSet].filter((f) => baseOf(f) === 'Dockerfile').map(dirOf))].sort();
  if (dirs.length === 0) dirs = dockerDirs.length > 0 ? dockerDirs : ['.'];

  let monorepo: Monorepo = 'none';
  if (pnpmWs) monorepo = 'pnpm-workspaces';
  else if (patterns.length > 0) monorepo = ctx.fileSet.has('yarn.lock') ? 'yarn-workspaces' : 'npm-workspaces';
  else if (ctx.fileSet.has('turbo.json')) monorepo = 'turbo';
  else if (ctx.fileSet.has('nx.json')) monorepo = 'nx';
  else if (dirs.length > 1) monorepo = 'folders';

  const shared: Shared = { repo, serviceDirs: dirs };
  const services: Service[] = [];
  for (const d of dirs) services.push(await readService(ctx, d, shared));

  const files = [...ctx.fileSet];
  return {
    owner, repo, defaultBranch: 'main', monorepo, services,
    terraformDirs: [...new Set(files.filter((f) => f.endsWith('.tf')).map(dirOf))].sort(),
    hasCompose: files.some((f) => /^(docker-)?compose\.ya?ml$/.test(baseOf(f))),
    existingWorkflows: [], precommit: null,
  };
}
