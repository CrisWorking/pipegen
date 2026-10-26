import { join as joinOs, posix } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { Dependency, DependencyKind, Service } from '../types.js';
import { listFiles, parseYamlLimited, readTextLimited, regexLines, regexSafe } from './limits.js';
import { asObj, pythonNames, readPyproject } from './manifest.js';

// Only NAMES are ever kept. A value is read, looked at for at most a yes/no answer, and dropped on the same line.

const IGNORED_DIRS = ['node_modules', '.git', '.venv', 'dist', 'build', 'vendor', 'target'];
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const CODE_EXT = 'js,mjs,cjs,jsx,ts,tsx,mts,cts,py';
const COMPOSE_FILES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];
const CODE_REFS = [
  /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /process\.env\[\s*['"]([^'"]+)['"]\s*\]/g,
  /import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /os\.environ\[\s*['"]([^'"]+)['"]\s*\]/g,
  /os\.environ\.get\(\s*['"]([^'"]+)['"]/g,
  /os\.getenv\(\s*['"]([^'"]+)['"]/g,
];

/** Env var names a dependency owns: a name matches when a keyword starts it or follows an underscore in it. */
const KIND_KEYWORDS: Record<Exclude<DependencyKind, 'external'>, string[]> = {
  postgres: ['POSTGRES', 'PG', 'DATABASE_URL'], mysql: ['MYSQL', 'DATABASE_URL'], redis: ['REDIS'], mongodb: ['MONGO'], rabbitmq: ['RABBIT', 'AMQP'],
};
const KIND_PACKAGES: [DependencyKind, RegExp][] = [
  ['postgres', /^(pg|postgres|asyncpg|psycopg[a-z0-9-]*)$/],
  ['mysql', /^(mysql2|pymysql)$/],
  ['redis', /^(redis|ioredis)$/],
  ['mongodb', /^(mongodb|mongoose|pymongo)$/],
  ['rabbitmq', /^(amqplib|pika)$/],
];
// External services: package pattern, dependency name (the package, or the family when several packages share one account), env keyword.
const EXTERNAL: [RegExp, string | null, string][] = [
  [/^stripe$/, null, 'STRIPE'],
  [/^(@auth0\/.+|auth0)$/, 'auth0', 'AUTH0'],
  [/^twilio$/, null, 'TWILIO'],
  [/^@sendgrid\/.+$/, 'sendgrid', 'SENDGRID'],
  [/^openai$/, null, 'OPENAI'],
  [/^@anthropic-ai\/sdk$/, null, 'ANTHROPIC'],
  [/^firebase-admin$/, null, 'FIREBASE'],
  [/^(aws-sdk|@aws-sdk\/.+|boto3)$/, 'aws', 'AWS'],
];

interface Found { kind: DependencyKind; name: string; evidence: string; keywords: string[] }

const inDir = (dir: string, name: string) => (dir === '.' ? name : `${dir}/${name}`);
const validName = (s: string | undefined): s is string => s !== undefined && NAME_RE.test(s);

/** Name of an assignment line (`KEY=...`, `export KEY=...`) plus a yes/no for "the value is a postgres URL". The value is not returned. */
function parseAssignment(line: string): { name: string; postgresUrl: boolean } | null {
  const m = /^\s*(?:export\s+)?([^\s=#]+)\s*=(.*)$/.exec(line);
  if (!m || !validName(m[1])) return null;
  return { name: m[1], postgresUrl: isPostgresUrl(m[2]) };
}
const isPostgresUrl = (v: unknown): boolean => typeof v === 'string' && /^\s*['"]?postgres(ql)?:\/\//i.test(v);

async function envFileNames(root: string, rel: string, names: Set<string>, pgUrl: string[]): Promise<void> {
  const text = await readTextLimited(joinOs(root, rel));
  for (const line of text === null ? [] : regexLines(text)) {
    const a = parseAssignment(line);
    if (!a) continue;
    names.add(a.name);
    if (a.name === 'DATABASE_URL' && a.postgresUrl) pgUrl.push(`${rel}: DATABASE_URL`);
  }
}

/** Keys of `environment:` for the compose services that build this service (by name or build context). */
async function composeNames(root: string, composeRel: string, service: Pick<Service, 'path' | 'name'>, names: Set<string>, pgUrl: string[]): Promise<void> {
  const text = await readTextLimited(joinOs(root, composeRel));
  if (text === null) return;
  let doc: unknown;
  try { doc = parseYamlLimited(text); } catch { return; }
  const composeDir = composeRel.includes('/') ? composeRel.slice(0, composeRel.lastIndexOf('/')) : '.';
  for (const [cname, raw] of Object.entries(asObj(asObj(doc).services))) {
    const svc = asObj(raw);
    const build = svc.build;
    const context = typeof build === 'string' ? build : typeof asObj(build).context === 'string' ? (asObj(build).context as string) : undefined;
    const builtHere = context !== undefined && !/^[a-z]+:\/\//i.test(context) && posix.normalize(posix.join(composeDir, context)).replace(/\/$/, '') === (service.path === '.' ? '.' : service.path);
    if (!builtHere && cname !== service.name && cname !== posix.basename(service.path)) continue;
    const env = svc.environment;
    const entries: [string, unknown][] = Array.isArray(env)
      ? env.filter((e): e is string => typeof e === 'string').map((e) => { const i = e.indexOf('='); return i < 0 ? [e, undefined] : [e.slice(0, i), e.slice(i + 1)]; })
      : Object.entries(asObj(env));
    for (const [key, value] of entries) {
      if (!validName(key.trim())) continue;
      names.add(key.trim());
      if (key.trim() === 'DATABASE_URL' && isPostgresUrl(value)) pgUrl.push(`${composeRel}: DATABASE_URL`);
    }
  }
}

function codeNames(text: string, names: Set<string>): void {
  for (const line of regexLines(text)) {
    for (const re of CODE_REFS) {
      for (const m of line.matchAll(re)) if (validName(m[1])) names.add(m[1]);
    }
  }
}

/** Package names the service declares, with the manifest file they came from. */
async function packages(root: string, dir: string, rels: string[]): Promise<{ file: string; name: string }[]> {
  const out: { file: string; name: string }[] = [];
  const pkgFile = inDir(dir, 'package.json');
  const pkgText = await readTextLimited(joinOs(root, pkgFile));
  if (pkgText !== null) {
    try {
      const pkg = asObj(JSON.parse(pkgText));
      for (const n of [...Object.keys(asObj(pkg.dependencies)), ...Object.keys(asObj(pkg.devDependencies))]) out.push({ file: pkgFile, name: n });
    } catch { /* unparseable package.json: no packages */ }
  }
  const tomlFile = inDir(dir, 'pyproject.toml');
  const tomlText = await readTextLimited(joinOs(root, tomlFile));
  if (tomlText !== null) {
    try { for (const n of readPyproject(asObj(parseToml(tomlText))).all) out.push({ file: tomlFile, name: n }); } catch { /* unparseable */ }
  }
  for (const rel of rels.filter((f) => f.startsWith(dir === '.' ? '' : `${dir}/`) && !f.slice(dir === '.' ? 0 : dir.length + 1).includes('/') && /^requirements.*\.txt$/.test(f.slice(f.lastIndexOf('/') + 1)))) {
    const text = await readTextLimited(joinOs(root, rel));
    for (const n of pythonNames(text === null ? [] : regexLines(text).filter((l) => !/^\s*(#|-)/.test(l)))) out.push({ file: rel, name: n });
  }
  return out;
}

/** The prisma datasource provider, found line by line inside a `datasource` block. */
function prismaPostgres(text: string): boolean {
  let inDatasource = false;
  for (const line of regexLines(text)) {
    if (/^\s*datasource\s+\w+\s*\{/.test(line)) inDatasource = true;
    else if (/^\s*\}/.test(line)) inDatasource = false;
    else if (inDatasource && /^\s*provider\s*=\s*"postgresql"/.test(line)) return true;
  }
  return false;
}

const matchesKeyword = (name: string, keyword: string): boolean => name.startsWith(keyword) || name.includes(`_${keyword}`);

/** Env var names (never values) and the services this service depends on. `dir` is the repo root; `service.path` is relative to it.
 * `listed` is readProject's already-capped repo-relative file list, so no second walk is made; without it one capped walk of the service folder is done. */
export async function readEnv(dir: string, service: Pick<Service, 'path' | 'name'>, listed?: string[]): Promise<{ envVars: string[]; dependsOn: Dependency[] }> {
  const names = new Set<string>();
  const pgUrl: string[] = [];
  const base = service.path;

  for (const f of ['.env.example', '.env.sample', '.env']) await envFileNames(dir, inDir(base, f), names, pgUrl);
  const composeDirs = base === '.' ? ['.'] : [base, '.'];
  for (const d of composeDirs) for (const f of COMPOSE_FILES) await composeNames(dir, inDir(d, f), service, names, pgUrl);

  const isRelevant = (f: string) => regexSafe(f) && new RegExp(`\\.(${CODE_EXT.replaceAll(',', '|')})$`).test(f) || /(^|\/)schema\.prisma$/.test(f) || /^requirements[^/]*\.txt$/.test(f.slice(f.lastIndexOf('/') + 1));
  const underBase = (f: string) => base === '.' || f.startsWith(`${base}/`);
  const ignored = (f: string) => f.split('/').some((s) => IGNORED_DIRS.includes(s));
  const rels = listed
    ? listed.filter((f) => underBase(f) && !ignored(f) && isRelevant(f))
    : (await listFiles(joinOs(dir, base), [`**/*.{${CODE_EXT}}`, '**/schema.prisma', 'requirements*.txt'], IGNORED_DIRS.map((d) => `**/${d}/**`))).files.map((f) => inDir(base, f));
  const found: Found[] = [];
  for (const rel of rels) {
    if (/(^|\/)schema\.prisma$/.test(rel)) {
      const text = await readTextLimited(joinOs(dir, rel));
      if (text !== null && prismaPostgres(text)) found.push({ kind: 'postgres', name: 'postgres', evidence: `${rel}: datasource provider postgresql`, keywords: KIND_KEYWORDS.postgres });
    } else if (/\.(js|mjs|cjs|jsx|ts|tsx|mts|cts|py)$/.test(rel)) {
      const text = await readTextLimited(joinOs(dir, rel));
      if (text !== null) codeNames(text, names);
    }
  }

  for (const { file, name } of await packages(dir, base, rels)) {
    const kind = KIND_PACKAGES.find(([, re]) => re.test(name))?.[0];
    if (kind && kind !== 'external') {
      found.push({ kind, name: kind, evidence: `${file}: ${name}`, keywords: KIND_KEYWORDS[kind as Exclude<DependencyKind, 'external'>] });
      continue;
    }
    const ext = EXTERNAL.find(([re]) => re.test(name));
    if (ext) found.push({ kind: 'external', name: ext[1] ?? name, evidence: `${file}: ${name}`, keywords: [ext[2]] });
  }
  if (pgUrl[0]) found.push({ kind: 'postgres', name: 'postgres', evidence: pgUrl[0], keywords: KIND_KEYWORDS.postgres });

  const envVars = [...names].sort();
  const seen = new Set<string>();
  const dependsOn: Dependency[] = [];
  for (const f of found) {
    const key = `${f.kind}:${f.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    dependsOn.push({ kind: f.kind, name: f.name, evidence: f.evidence, envVars: envVars.filter((n) => f.keywords.some((k) => matchesKeyword(n, k))) });
  }
  return { envVars, dependsOn: dependsOn.sort((a, b) => `${a.kind}:${a.name}`.localeCompare(`${b.kind}:${b.name}`)) };
}
