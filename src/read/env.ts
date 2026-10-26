import { join as joinOs, posix } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { Dependency, DependencyKind, Service } from '../types.js';
import { parseYamlLimited, readTextLimited, regexLines, regexSafe } from './limits.js';
import { asObj, isTestFile, pythonNames, readPyproject } from './manifest.js';

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

/** True when `s` (starting right after an opening quote) contains the matching unescaped closing quote. */
function closesQuote(s: string, q: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\' && q !== "'") i++; // a backslash escapes only inside "..." and `...`; in '...' it is literal
    else if (s[i] === q) return true;
  }
  return false;
}
const isPostgresUrl = (v: unknown): boolean => typeof v === 'string' && regexSafe(v) && /^\s*['"]?postgres(ql)?:\/\//i.test(v);

/**
 * Names from a dotenv-style file. A value that opens a quote and does not close it on the same line is multi-line (a PEM key, JSON):
 * its continuation lines are skipped until the closing quote, so no part of a value can look like a name. A line over 4 KB inside
 * an open quote stays inside it. A file that ends inside an open quote just stops. The value itself is never kept.
 */
async function envFileNames(root: string, rel: string, names: Set<string>, pgUrl: string[]): Promise<void> {
  const text = await readTextLimited(joinOs(root, rel));
  let open: string | null = null;
  for (const line of text === null ? [] : text.split(/\r?\n/)) {
    if (open !== null) {
      if (closesQuote(line, open)) open = null; // char-by-char scan, no regex, so safe on any length
      continue;
    }
    if (!regexSafe(line)) {
      // Too long for a regex and never a name, but it may still open a multi-line quote whose next lines must be skipped.
      const eq = line.indexOf('=');
      if (eq >= 0 && !line.trimStart().startsWith('#')) {
        const rest = line.slice(eq + 1).trimStart();
        const q = rest[0];
        if ((q === '"' || q === "'" || q === '`') && !closesQuote(rest.slice(1), q)) open = q;
      }
      continue;
    }
    const m = /^\s*(?:export\s+)?([^\s=#]+)\s*=\s*(.*)$/.exec(line);
    if (!m || !validName(m[1])) continue;
    const rest = m[2] ?? '';
    const q = rest[0];
    if ((q === '"' || q === "'" || q === '`') && !closesQuote(rest.slice(1), q)) open = q;
    names.add(m[1]);
    if (m[1] === 'DATABASE_URL' && isPostgresUrl(rest.replace(/^\s*/, ''))) pgUrl.push(`${rel}: DATABASE_URL`);
  }
}

/** True when a compose `build` (string or `{ context }`) points at the service folder. Absolute, URL and repo-escaping contexts never match. */
function buildsHere(composeDir: string, build: unknown, servicePath: string): boolean {
  const context = typeof build === 'string' ? build : asObj(build).context;
  if (typeof context !== 'string' || !regexSafe(context)) return false;
  if (context.startsWith('/') || context.startsWith('\\') || /^[A-Za-z]:/.test(context) || /^[a-z][a-z0-9+.-]*:\/\//i.test(context) || context.startsWith('git@')) return false;
  const joined = posix.normalize(posix.join(composeDir, context.replace(/\\/g, '/'))).replace(/\/+$/, '') || '.';
  if (joined === '..' || joined.startsWith('../')) return false;
  return joined === servicePath;
}

/** Keys of `environment:` for the compose services that build this service (by build context; by name only when the compose service has no build). */
async function composeNames(root: string, composeRel: string, service: Pick<Service, 'path' | 'name'>, names: Set<string>, pgUrl: string[]): Promise<void> {
  const text = await readTextLimited(joinOs(root, composeRel));
  if (text === null) return;
  let doc: unknown;
  try { doc = parseYamlLimited(text); } catch { return; }
  const composeDir = composeRel.includes('/') ? composeRel.slice(0, composeRel.lastIndexOf('/')) : '.';
  for (const [cname, raw] of Object.entries(asObj(asObj(doc).services))) {
    const svc = asObj(raw);
    const build = svc.build;
    if (build === undefined) {
      if (cname !== service.name && cname !== posix.basename(service.path)) continue;
    } else if (!buildsHere(composeDir, build, service.path)) continue;
    const env = svc.environment;
    const entries: [string, unknown][] = Array.isArray(env)
      ? env.filter((e): e is string => typeof e === 'string' && regexSafe(e)).map((e) => { const i = e.indexOf('='); return i < 0 ? [e, undefined] : [e.slice(0, i), e.slice(i + 1)]; })
      : Object.entries(asObj(env));
    for (const [key, value] of entries) {
      if (!regexSafe(key) || !validName(key.trim())) continue;
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
  for (const rel of rels.filter((f) => regexSafe(f) && f.startsWith(dir === '.' ? '' : `${dir}/`) && !f.slice(dir === '.' ? 0 : dir.length + 1).includes('/') && /^requirements.*\.txt$/.test(f.slice(f.lastIndexOf('/') + 1)))) {
    const text = await readTextLimited(joinOs(root, rel));
    for (const n of pythonNames(text === null ? [] : regexLines(text).filter((l) => !/^\s*(#|-)/.test(l)))) out.push({ file: rel, name: n });
  }
  return out;
}

/** The prisma datasource provider, found line by line inside a `datasource` block. */
function prismaPostgres(text: string): boolean {
  let inDatasource = false;
  for (const line of regexLines(text)) {
    if (/^\s*datasource\s+\w+\s*\{[^}]*\bprovider\s*=\s*"postgresql"/.test(line)) return true;
    if (/^\s*datasource\s+\w+\s*\{/.test(line)) inDatasource = true;
    else if (/^\s*\}/.test(line)) inDatasource = false;
    else if (inDatasource && /^\s*provider\s*=\s*"postgresql"/.test(line)) return true;
  }
  return false;
}

const matchesKeyword = (name: string, keyword: string): boolean => name.startsWith(keyword) || name.includes(`_${keyword}`);

/** Env var names (never values) and the services this service depends on. `dir` is the repo root; `service.path` is relative to it.
 * `owned` is the repo-relative list of files that belong to this service and not to a deeper one (readProject's already-capped listing),
 * so there is no second walk and a parent service never inherits a nested service's names or dependencies. */
export async function readEnv(dir: string, service: Pick<Service, 'path' | 'name'>, owned: string[]): Promise<{ envVars: string[]; dependsOn: Dependency[] }> {
  const names = new Set<string>();
  const pgUrl: string[] = [];
  const base = service.path;

  for (const f of ['.env.example', '.env.sample', '.env']) await envFileNames(dir, inDir(base, f), names, pgUrl);
  const composeDirs = base === '.' ? ['.'] : [base, '.'];
  for (const d of composeDirs) for (const f of COMPOSE_FILES) await composeNames(dir, inDir(d, f), service, names, pgUrl);

  const baseName = (f: string) => f.slice(f.lastIndexOf('/') + 1);
  const isRelevant = (f: string) => regexSafe(f) && (new RegExp(`\\.(${CODE_EXT.replaceAll(',', '|')})$`).test(f) || baseName(f) === 'schema.prisma' || /^requirements[^/]*\.txt$/.test(baseName(f)));
  const relToBase = (f: string) => (base === '.' ? f : f.slice(base.length + 1));
  const rels = owned.filter((f) => (base === '.' || f.startsWith(`${base}/`)) && !f.split('/').some((p) => IGNORED_DIRS.includes(p)) && isRelevant(f));
  const found: Found[] = [];
  for (const rel of rels) {
    if (baseName(rel) === 'schema.prisma') {
      const text = await readTextLimited(joinOs(dir, rel));
      if (text !== null && prismaPostgres(text)) found.push({ kind: 'postgres', name: 'postgres', evidence: `${rel}: datasource provider postgresql`, keywords: KIND_KEYWORDS.postgres });
    } else if (/\.(js|mjs|cjs|jsx|ts|tsx|mts|cts|py)$/.test(rel) && !isTestFile(relToBase(rel))) {
      const text = await readTextLimited(joinOs(dir, rel));
      if (text !== null) codeNames(text, names);
    }
  }

  for (const { file, name } of await packages(dir, base, rels)) {
    if (!regexSafe(name)) continue;
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
