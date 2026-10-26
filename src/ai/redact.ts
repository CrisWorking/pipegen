import { execFile, type ExecFileException } from 'node:child_process';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import picomatch from 'picomatch';
import { IGNORED_DIRS, listFiles, readTextLimitedWithReason, regexSafe, type Skipped } from '../read/limits.js';
import { safeText } from '../util/safe-text.js';
import { gitleaksConfigPath } from './gitleaks-config.js';

export { isBinary } from '../read/limits.js';
export { gitleaksConfigPath } from './gitleaks-config.js';

/** Thrown by bundleText for a bundle that did not pass bundleCode's gitleaks check: nothing may be sent. */
export class GitleaksRequiredError extends Error {}
/** gitleaks could not run or gave an unusable result (not a finding): no bundle is returned. */
export class GitleaksError extends Error {}

export interface CodeBundle { files: { path: string; content: string }[]; bytes: number; truncated: boolean; gitleaksChecked: boolean; notes: string[] }

export interface BundleOptions {
  roots?: string[];
  maxBytes?: number;
  /** Higher numbers are kept first when the bundle is cut to maxBytes. Default: manifests and config, then entry points, routes, the rest. */
  priority?: (path: string) => number;
  knownValues?: string[];
  /** Path to the pinned gitleaks binary (Plan B's ensurePinnedBinary('gitleaks')). Without it the bundle is for counting only. */
  gitleaks?: string;
  /** gitleaks timeout; 60 s by default (tests set a short one). */
  gitleaksTimeoutMs?: number;
}

const R = '[REDACTED]';
const LONG_LINE = '[REDACTED: line too long]';
const DEFAULT_MAX_BYTES = 150_000;
const GITLEAKS_TIMEOUT_MS = 60_000;
const MAX_REPORT_BYTES = 64 * 1024 * 1024;
const MAX_LISTED_IN_NOTE = 10;

// ---------- excluded files ----------

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'poetry.lock', 'uv.lock', 'Pipfile.lock', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'go.sum'];

/**
 * Files never put in the AI code bundle: globs only, matched in order on the full repo-relative path
 * (case-insensitive, dotfiles included); the last pattern that matches wins, so a `!` pattern keeps a
 * file that an earlier pattern excluded, and a later pattern can exclude it again
 * (`secrets/.env.example` stays out). Binary files are skipped by content (isBinary), not by a pattern.
 */
export const EXCLUDED_PATTERNS: readonly string[] = Object.freeze([
  '**/.env*', '!**/.env.example', '!**/.env.sample', '**/.env*/**',
  '**/*.pem', '**/*.key', '**/id_rsa*', '**/id_dsa*', '**/id_ecdsa*', '**/id_ed25519*',
  '**/*secret*', '**/*secret*/**',
  '**/*.tfstate', '**/*.tfstate.backup', '**/*.tfvars', '**/*.tfvars.json',
  '**/.npmrc', '**/.netrc',
  '**/*.p12', '**/*.pfx', '**/*.jks',
  '**/kubeconfig', '**/kubeconfig.*', '**/*.kubeconfig', '**/.kube/config', '**/.kube/**',
  ...LOCKFILES.map((f) => `**/${f}`),
  ...IGNORED_DIRS.map((d) => `**/${d}/**`),
]);

const EXCLUDE_MATCHERS = EXCLUDED_PATTERNS.map((p) => {
  const negated = p.startsWith('!');
  return { negated, match: picomatch(negated ? p.slice(1) : p, { dot: true, nocase: true }) };
});

/** True when EXCLUDED_PATTERNS keeps this repo-relative (posix) path out of the bundle. */
export function isExcludedPath(path: string): boolean {
  let excluded = false;
  for (const m of EXCLUDE_MATCHERS) if (m.match(path)) excluded = !m.negated;
  return excluded;
}

// ---------- redaction ----------

// Token formats, each replaced whole. Names are what findSecretLike reports (never the value).
const TOKEN_RULES: readonly (readonly [string, RegExp])[] = [
  ['aws-access-key', /AKIA[0-9A-Z]{16}/g],
  ['github-token', /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ['github-fine-grained-token', /github_pat_[A-Za-z0-9_]{20,}/g],
  ['slack-token', /xox[abpr]-[A-Za-z0-9-]+/g],
  ['stripe-key', /sk_(?:live|test)_[A-Za-z0-9]{10,}/g],
  ['sk-api-key', /sk-[A-Za-z0-9_-]{20,}/g],
  ['jwt', /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g],
  ['slack-webhook', /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/g],
  ['google-api-key', /AIza[0-9A-Za-z_-]{35}/g],
  ['npm-token', /npm_[A-Za-z0-9]{36}/g],
];
// Connection string: keeps scheme, user and host; only the password between ':' and '@' is replaced.
const CONNECTION_STRING = /([a-z][a-z0-9+.-]*:\/\/[^:/\s]+:)[^@\s]+@/gi;
// A value assigned to a password-like name: the name and separator stay, the value is replaced.
const ASSIGNED_VALUE = /(password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*)\S+/gi;

// Private key markers, found without a regex so they are seen on lines of any length.
const MARK_START = '-----';
const KEY_TAIL = 'PRIVATE KEY';

/** Finds `-----BEGIN [A-Z ]*PRIVATE KEY-----` (or END) in `line` from `from`. Linear time. */
function findKeyMarker(line: string, kind: 'BEGIN' | 'END', from: number): { start: number; end: number } | null {
  const head = `${MARK_START}${kind} `;
  for (let i = line.indexOf(head, from); i >= 0; i = line.indexOf(head, i + 1)) {
    let j = i + head.length;
    while (j < line.length && (line[j] === ' ' || (line[j] >= 'A' && line[j] <= 'Z'))) j++;
    if (line.slice(i + head.length, j).endsWith(KEY_TAIL) && line.startsWith(MARK_START, j)) return { start: i, end: j + MARK_START.length };
  }
  return null;
}

function redactSegment(s: string): string {
  let out = s;
  for (const [, re] of TOKEN_RULES) out = out.replace(re, R);
  out = out.replace(CONNECTION_STRING, `$1${R}@`);
  return out.replace(ASSIGNED_VALUE, `$1$2${R}`);
}

/**
 * Replaces secret-like text with [REDACTED]. Works line by line: a line over 4 KB is replaced whole
 * (it is too long to scan safely), and a private key block is replaced whole, up to its END line, or to
 * the end of the text when it has none.
 */
export function redact(text: string): string {
  const out: string[] = [];
  let inKey = false;
  for (const line of text.split('\n')) {
    const startedInKey = inKey;
    const pieces: string[] = []; // plain text pieces, with R where a key block starts
    const plain: string[] = [];
    let pos = 0;
    for (;;) {
      if (inKey) {
        const end = findKeyMarker(line, 'END', pos);
        if (!end) break;
        pos = end.end;
        inKey = false;
      } else {
        const begin = findKeyMarker(line, 'BEGIN', pos);
        const seg = line.slice(pos, begin ? begin.start : line.length);
        pieces.push(seg);
        plain.push(seg);
        if (!begin) break;
        pieces.push(R);
        pos = begin.end;
        inKey = true;
      }
    }
    const startsBlock = pieces.includes(R);
    // A line that only continues (or closes) a block already shown as [REDACTED] is dropped.
    if (startedInKey && !startsBlock && plain.every((p) => p === '')) continue;
    if (!regexSafe(line)) {
      out.push(LONG_LINE);
      continue;
    }
    out.push(pieces.map((p) => (p === R ? R : redactSegment(p))).join(''));
  }
  return out.join('\n');
}

/**
 * Names of the secret-like formats found in `text` (token formats, private keys, connection string
 * passwords), never the values. Unlike redact() it ignores `name = value` assignments, which are common
 * in ordinary code. Lines over 4 KB are not scanned, except for private key markers.
 */
export function findSecretLike(text: string): string[] {
  const found = new Set<string>();
  for (const line of text.split('\n')) {
    if (findKeyMarker(line, 'BEGIN', 0)) found.add('private-key');
    if (!regexSafe(line)) continue;
    for (const [name, re] of TOKEN_RULES) if (line.search(re) >= 0) found.add(name);
    if (line.search(CONNECTION_STRING) >= 0) found.add('connection-string-password');
  }
  return [...found];
}

// ---------- known values ----------

const stripPadding = (s: string) => {
  let end = s.length;
  while (end > 0 && s[end - 1] === '=') end--;
  return s.slice(0, end);
};

/**
 * Replaces every value the user typed with [REDACTED]: the exact value, its base64 forms (standard and
 * URL-safe, with and without `=` padding) and its encodeURIComponent form. Empty and whitespace-only
 * values are ignored; longer forms are replaced first. Plain substring replacement, no regex.
 */
export function scrubKnownValues(text: string, values: string[]): string {
  const forms = new Set<string>();
  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    for (const v of new Set([raw, raw.trim()])) {
      if (v.trim() === '') continue;
      const b64 = Buffer.from(v, 'utf8').toString('base64');
      const urlSafe = b64.replaceAll('+', '-').replaceAll('/', '_');
      for (const f of [v, b64, stripPadding(b64), urlSafe, stripPadding(urlSafe)]) forms.add(f);
      try {
        forms.add(encodeURIComponent(v));
      } catch {
        // a lone surrogate has no URL-encoded form
      }
    }
  }
  const ordered = [...forms].filter((f) => f.trim() !== '').sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
  let out = text;
  for (const f of ordered) if (out.includes(f)) out = out.split(f).join(R);
  return out;
}

// ---------- default priority ----------

const MANIFEST_NAMES = new Set([
  'package.json', 'pnpm-workspace.yaml', 'turbo.json', 'nx.json', 'tsconfig.json', 'deno.json', '.nvmrc', '.node-version', '.python-version',
  'pyproject.toml', 'setup.py', 'setup.cfg', 'requirements.txt', 'pipfile', 'go.mod', 'cargo.toml', 'pom.xml', 'build.gradle', 'build.gradle.kts',
  'settings.gradle', 'gemfile', 'composer.json', 'makefile', 'procfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml',
  '.dockerignore', '.pre-commit-config.yaml', 'lefthook.yml', 'vercel.json', 'netlify.toml', 'fly.toml', 'app.yaml', 'serverless.yml',
]);
const ENTRY_NAMES = new Set(['index', 'main', 'app', 'server', 'cli', '__main__', 'manage', 'wsgi', 'asgi', 'program']);
const ROUTE_DIRS = new Set(['routes', 'route', 'router', 'routers', 'controllers', 'controller', 'handlers', 'api', 'views', 'endpoints']);

/** Manifests and config 3, entry points 2, routes 1, everything else 0. */
function defaultPriority(path: string): number {
  const parts = path.toLowerCase().split('/');
  const base = parts[parts.length - 1];
  const stem = base.includes('.') ? base.slice(0, base.indexOf('.')) : base;
  if (MANIFEST_NAMES.has(base) || base.startsWith('dockerfile') || (base.startsWith('requirements') && base.endsWith('.txt'))
    || base.endsWith('.csproj') || /\.config\.[cm]?[jt]s$/.test(base) || path.startsWith('.github/workflows/')) return 3;
  if (ENTRY_NAMES.has(stem)) return 2;
  if (parts.slice(0, -1).some((p) => ROUTE_DIRS.has(p)) || ['route', 'routes', 'router', 'urls', 'views'].includes(stem)) return 1;
  return 0;
}

// ---------- bundle ----------

type FileEntry = { path: string; content: string };

/** Notes in plain English: paths only (cleaned), never a value or file content. */
class Notes {
  private readonly lines: string[] = [];
  add(line: string): void {
    if (!this.lines.includes(line)) this.lines.push(line);
  }
  /** "<lead> a, b, c and 4 more." */
  addPaths(lead: string, paths: string[], show: (p: string) => string): void {
    if (paths.length === 0) return;
    const shown = paths.slice(0, MAX_LISTED_IN_NOTE).map(show).join(', ');
    const more = paths.length > MAX_LISTED_IN_NOTE ? ` and ${paths.length - MAX_LISTED_IN_NOTE} more` : '';
    this.add(`${lead} ${shown}${more}.`);
  }
  all(): string[] {
    return [...this.lines];
  }
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function normalizeRoots(roots: string[] | undefined): string[] | null {
  if (roots === undefined || roots.length === 0) return null;
  return roots.map((r) => {
    const s = String(r).replaceAll('\\', '/');
    if (s.startsWith('/') || /^[a-zA-Z]:/.test(s)) throw new Error(`Invalid root "${safeText(s)}": roots must be relative to the repo.`);
    const parts = s.split('/').filter((p) => p !== '' && p !== '.');
    if (parts.includes('..')) throw new Error(`Invalid root "${safeText(s)}": a root may not contain "..".`);
    return parts.join('/');
  });
}

const underRoot = (path: string, root: string) => root === '' || path === root || path.startsWith(`${root}/`);
const insideDir = (base: string, target: string) => {
  const rel = relative(base, target);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
};

/**
 * Collects the repo's code for the AI: lists files (symlinks never followed), drops EXCLUDED_PATTERNS
 * matches and binaries, reads within the read limits, then redact() → scrubKnownValues (if knownValues)
 * → the gitleaks pass (if opts.gitleaks) → cuts to maxBytes by priority (whole files, lowest priority
 * first). Without opts.gitleaks the result is for counting only: bundleText refuses it.
 */
export async function bundleCode(dir: string, opts: BundleOptions = {}): Promise<CodeBundle> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) throw new RangeError('maxBytes must be a positive number.');
  const roots = normalizeRoots(opts.roots);
  const priority = opts.priority ?? defaultPriority;
  const known = opts.knownValues ?? [];
  const scrub = (s: string) => (known.length > 0 ? scrubKnownValues(s, known) : s);
  const nameHidden = (p: string) => redact(p) !== p || scrub(p) !== p;
  const show = (p: string) => (nameHidden(p) ? '(a file whose name looks like a secret)' : safeText(p, 300));
  const notes = new Notes();
  const inRoots = (p: string) => roots === null || roots.some((r) => underRoot(p, r));

  const realRoot = await realpath(dir);
  const found = { links: [] as string[] };
  const listing = await listFiles(dir, ['**/*'], IGNORED_DIRS.map((d) => `**/${d}/**`), found);
  let truncated = listing.truncated;
  if (listing.truncated) notes.add('Stopped listing after 20,000 files; the rest were not read.');

  const links = found.links.filter(inRoots);
  let excluded = 0;
  let secretNames = 0;
  const candidates: { path: string; rank: number }[] = [];
  for (const path of listing.files) {
    if (!inRoots(path)) continue;
    if (isExcludedPath(path)) {
      excluded++;
      continue;
    }
    if (nameHidden(path)) {
      secretNames++;
      continue;
    }
    const rank = Number(priority(path));
    candidates.push({ path, rank: Number.isFinite(rank) ? rank : 0 });
  }
  candidates.sort((a, b) => b.rank - a.rank || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  // Read in priority order. Stop reading well past maxBytes: what is not read is never sent.
  const readBudget = Math.max(maxBytes * 2, maxBytes + 1_000_000);
  const skipped: Record<Skipped | 'outside', string[]> = { 'too-large': [], binary: [], link: [], 'not-a-file': [], unreadable: [], outside: [] };
  const tooBig: string[] = [];
  const overBudget: string[] = [];
  let collected: FileEntry[] = [];
  let collectedBytes = 0;
  for (const { path } of candidates) {
    if (collectedBytes >= readBudget) {
      overBudget.push(path);
      continue;
    }
    const abs = join(dir, path);
    const info = await lstat(abs).catch(() => null);
    if (info === null) { skipped.unreadable.push(path); continue; }
    if (info.isSymbolicLink()) { links.push(path); continue; }
    if (!info.isFile()) { skipped['not-a-file'].push(path); continue; }
    const real = await realpath(abs).catch(() => null);
    if (real === null || !insideDir(realRoot, real)) { skipped.outside.push(path); continue; }
    const result = await readTextLimitedWithReason(abs);
    if (!('text' in result)) {
      (result.skipped === 'link' ? links : skipped[result.skipped]).push(path);
      continue;
    }
    const content = scrub(redact(result.text));
    const bytes = Buffer.byteLength(content);
    if (bytes > maxBytes) { tooBig.push(path); continue; }
    collected.push({ path, content });
    collectedBytes += bytes;
  }

  notes.addPaths('Skipped symbolic links (never followed):', [...new Set(links)].sort(), show);
  notes.addPaths('Skipped binary files:', skipped.binary, show);
  notes.addPaths('Skipped files larger than 1 MB:', skipped['too-large'], show);
  notes.addPaths('Skipped files that are not regular files:', skipped['not-a-file'], show);
  notes.addPaths('Skipped files that resolve outside the repo:', skipped.outside, show);
  notes.addPaths('Skipped files that could not be read:', skipped.unreadable, show);
  if (excluded > 0) notes.add(`Left out ${plural(excluded, 'file that matches', 'files that match')} the excluded patterns (files that may hold secrets, lockfiles, dependency and build folders).`);
  if (secretNames > 0) notes.add(`Left out ${plural(secretNames, 'file whose name looks', 'files whose names look')} like a secret.`);

  let gitleaksChecked = false;
  if (opts.gitleaks !== undefined) {
    collected = await gitleaksPass(collected, opts.gitleaks, opts.gitleaksTimeoutMs ?? GITLEAKS_TIMEOUT_MS, notes, show);
    gitleaksChecked = true;
  } else {
    notes.add('gitleaks was not run: this bundle is for counting only and cannot be sent to the AI.');
  }

  // Cut to maxBytes: keep the highest-priority files that fit; once one does not fit, the rest are dropped.
  const files: FileEntry[] = [];
  const dropped: string[] = [];
  let bytes = 0;
  for (const f of collected) {
    const b = Buffer.byteLength(f.content);
    if (b > maxBytes) tooBig.push(f.path);
    else if (dropped.length === 0 && bytes + b <= maxBytes) {
      files.push(f);
      bytes += b;
    } else dropped.push(f.path);
  }
  dropped.push(...overBudget);
  if (tooBig.length > 0 || dropped.length > 0) truncated = true;
  notes.addPaths(`Left out files each larger than the size limit (${maxBytes} bytes):`, tooBig, show);
  notes.addPaths(`Left out lower-priority files to keep the bundle under the size limit (${maxBytes} bytes):`, dropped, show);

  const bundle: CodeBundle = {
    files: files.map((f) => Object.freeze({ path: f.path, content: f.content })),
    bytes,
    truncated,
    gitleaksChecked,
    notes: notes.all(),
  };
  Object.freeze(bundle.files);
  Object.freeze(bundle.notes);
  Object.freeze(bundle);
  if (gitleaksChecked) CHECKED.add(bundle);
  return bundle;
}

// ---------- gitleaks pass ----------

interface Finding { file: string; startLine?: number; endLine?: number; secret: string; match: string }

/** Runs gitleaks; resolves with its exit code, rejects (GitleaksError) on a spawn error, timeout or signal. */
function runGitleaks(bin: string, args: string[], cwd: string, timeoutMs: number): Promise<number> {
  const env: Record<string, string> = {};
  if (process.env.PATH !== undefined) env.PATH = process.env.PATH;
  if (process.env.HOME !== undefined) env.HOME = process.env.HOME;
  return new Promise((resolvePromise, reject) => {
    execFile(bin, args, { cwd, env, timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (err) => {
      if (err === null) return resolvePromise(0);
      const e = err as ExecFileException;
      if (e.killed && e.signal) return reject(new GitleaksError(`gitleaks did not finish within ${Math.round(timeoutMs / 1000)} s (or produced too much output) and was stopped.`));
      if (e.signal) return reject(new GitleaksError(`gitleaks was stopped by signal ${safeText(String(e.signal))}.`));
      if (typeof e.code === 'number') return resolvePromise(e.code);
      reject(new GitleaksError(`gitleaks could not be started (${safeText(String(e.code ?? 'unknown error'))}).`));
    });
  });
}

const intOrUndefined = (v: unknown) => (typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : undefined);

/** The report is built from repo-derived content: only File, StartLine/EndLine, Match and Secret are used, all type-checked. */
async function readReport(path: string): Promise<Finding[]> {
  const info = await lstat(path).catch(() => null);
  if (info === null || !info.isFile()) throw new GitleaksError('gitleaks wrote no report.');
  if (info.size > MAX_REPORT_BYTES) throw new GitleaksError('gitleaks wrote a report that is too large to read.');
  let data: unknown;
  try {
    data = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    throw new GitleaksError('gitleaks wrote a report pipegen could not read.');
  }
  if (!Array.isArray(data)) throw new GitleaksError('gitleaks wrote a report in an unexpected format.');
  return data.map((item: unknown) => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) throw new GitleaksError('gitleaks wrote a report in an unexpected format.');
    const o = item as Record<string, unknown>;
    if (typeof o.File !== 'string' || o.File === '') throw new GitleaksError('gitleaks wrote a finding without a file.');
    return {
      file: o.File,
      startLine: intOrUndefined(o.StartLine),
      endLine: intOrUndefined(o.EndLine),
      secret: typeof o.Secret === 'string' ? o.Secret : '',
      match: typeof o.Match === 'string' ? o.Match : '',
    };
  });
}

/** Replaces one finding in `content`; null when it cannot be located. Tries the reported lines first. */
function applyFinding(content: string, f: Finding): string | null {
  const wanted = [f.secret, f.match].filter((s) => s !== '');
  if (wanted.length === 0) return null;
  const lines = content.split('\n');
  const { startLine: s, endLine: e } = f;
  if (s !== undefined && e !== undefined && s <= e && e <= lines.length) {
    const seg = lines.slice(s - 1, e).join('\n');
    for (const w of wanted) {
      if (seg.includes(w)) return [...lines.slice(0, s - 1), seg.split(w).join(R), ...lines.slice(e)].join('\n');
    }
  }
  for (const w of wanted) if (content.includes(w)) return content.split(w).join(R);
  return null;
}

// gitleaks skips any line holding its inline allow comment; the bundle never carries one, so a repo cannot opt a line out.
const ALLOW_COMMENT = 'gitleaks' + ':allow';

async function gitleaksPass(files: FileEntry[], bin: string, timeoutMs: number, notes: Notes, show: (p: string) => string): Promise<FileEntry[]> {
  // An absolute path only: a bare name would be looked up on PATH.
  if (!isAbsolute(bin)) throw new GitleaksError('The gitleaks binary must be given as an absolute path.');
  const config = gitleaksConfigPath();
  if (!(await stat(config).catch(() => null))?.isFile()) throw new GitleaksError("pipegen's gitleaks config (data/gitleaks-bundle.toml) is missing.");
  const scanned = files.map((f) => ({ path: f.path, content: f.content.split(ALLOW_COMMENT).join('gitleaks-allow') }));
  const tmp = await realpath(await mkdtemp(join(tmpdir(), 'pipegen-gitleaks-')));
  try {
    await chmod(tmp, 0o700);
    // Neutral names: no repo file name (.gitleaksignore, .gitleaks.toml, allowlisted paths) reaches gitleaks.
    const names = scanned.map((_, i) => `f${String(i + 1).padStart(6, '0')}.txt`);
    for (let i = 0; i < scanned.length; i++) await writeFile(join(tmp, names[i]), scanned[i].content, { flag: 'wx', mode: 0o600 });
    const reportPath = join(tmp, 'report.json');
    const code = await runGitleaks(bin, ['detect', '--no-git', '--source', tmp, '--config', config, '--report-format', 'json', '--report-path', reportPath], tmp, timeoutMs);
    if (code !== 0 && code !== 1) throw new GitleaksError(`gitleaks failed (exit code ${code}).`);
    const findings = await readReport(reportPath);

    const index = new Map(names.map((n, i) => [n, i]));
    const perFile = new Map<number, Finding[]>();
    const drop = new Set<number>();
    const unplaced = new Set<number>();
    let strays = 0;
    for (const f of findings) {
      const abs = isAbsolute(f.file) ? resolve(f.file) : resolve(tmp, f.file);
      const i = insideDir(tmp, abs) ? index.get(relative(tmp, abs)) : undefined;
      if (i !== undefined) {
        perFile.set(i, [...(perFile.get(i) ?? []), f]);
        continue;
      }
      // Not one of the scanned files (outside the temp dir, or unknown): ignore the finding, and drop any
      // file it might relate to, by name or by the reported text.
      strays++;
      const named = index.get(f.file.replaceAll('\\', '/').split('/').pop() ?? '');
      if (named !== undefined) unplaced.add(named);
      scanned.forEach((s, j) => {
        if ((f.secret !== '' && s.content.includes(f.secret)) || (f.match !== '' && s.content.includes(f.match))) unplaced.add(j);
      });
    }
    let redacted = 0;
    for (const [i, list] of perFile) {
      list.sort((a, b) => (b.startLine ?? 0) - (a.startLine ?? 0));
      let content: string | null = scanned[i].content;
      for (const f of list) {
        content = applyFinding(content, f);
        if (content === null) break;
        redacted++;
      }
      if (content === null) drop.add(i);
      else scanned[i].content = content;
    }
    notes.add(`gitleaks checked the bundle: ${plural(redacted, 'finding', 'findings')} redacted.`);
    notes.addPaths('Left out because gitleaks found something pipegen could not locate to redact:', [...drop].sort((a, b) => a - b).map((i) => scanned[i].path), show);
    if (strays > 0) {
      notes.add(`Ignored ${plural(strays, 'gitleaks finding', 'gitleaks findings')} for a file outside the scanned folder.`);
      notes.addPaths('Left out because a gitleaks finding outside the scanned folder may relate to them:', [...unplaced].sort((a, b) => a - b).map((i) => scanned[i].path), show);
    }
    return scanned.filter((_, i) => !drop.has(i) && !unplaced.has(i));
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

// ---------- bundle text ----------

// Bundles that passed bundleCode's gitleaks check. They are frozen, so they cannot change afterwards;
// a copy or a hand-made object is not in the set and is refused.
const CHECKED = new WeakSet<object>();

/** Breaks any `<code-bundle` / `</code-bundle` in repo text so it cannot open or close the block. */
function neutralizeTags(s: string): string {
  let out = '';
  let from = 0;
  for (let i = s.indexOf('<', from); i >= 0; i = s.indexOf('<', i + 1)) {
    const k = s[i + 1] === '/' ? i + 2 : i + 1;
    if (s.slice(k, k + 11).toLowerCase() === 'code-bundle') {
      out += s.slice(from, k) + 'code_bundle';
      from = k + 11;
    }
  }
  return out + s.slice(from);
}

/**
 * The bundle as one text block inside <code-bundle>…</code-bundle>, files sorted by path, each under a
 * `--- path ---` header. Byte-identical for the same bundle. Throws GitleaksRequiredError unless the
 * bundle is bundleCode's own result after a gitleaks pass, so unchecked code can never reach a provider.
 */
export function bundleText(bundle: CodeBundle): string {
  if (bundle === null || typeof bundle !== 'object' || bundle.gitleaksChecked !== true || !CHECKED.has(bundle)) {
    throw new GitleaksRequiredError('This code bundle has not passed the required gitleaks check, so it cannot be sent to the AI.');
  }
  const files = [...bundle.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  let out = '<code-bundle>\n';
  for (const f of files) {
    const content = neutralizeTags(f.content);
    out += `--- ${neutralizeTags(safeText(f.path, 1000))} ---\n${content}${content === '' || content.endsWith('\n') ? '' : '\n'}`;
  }
  return `${out}</code-bundle>`;
}
