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

/** `bytes` is the exact UTF-8 size of bundleText(bundle) (wrapper and per-file headers included), never over maxBytes. */
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
  '**/.git-credentials', '**/.aws/credentials', '**/.aws/config', '**/credentials.json', '**/.pgpass', '**/.pypirc',
  '**/.docker/config.json', '**/*.env', '**/*.keystore', '**/*.ppk', '**/*.p8', '**/.htpasswd', '**/service-account*.json',
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
  // starts where a token starts (lookbehind): a failed match then costs one scan of the run, not one per 'eyJ'
  ['jwt', /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g],
  ['slack-webhook', /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/g],
  ['google-api-key', /AIza[0-9A-Za-z_-]{35}/g],
  ['npm-token', /npm_[A-Za-z0-9]{36}/g],
];
// Connection string (scheme, '://', user, ':', password, '@', host): scheme, user (may be empty) and host stay. Everything
// from the ':' after the user up to the LAST '@' of the authority is hidden, so an unencoded '@' in the
// password cannot leak the rest of it. The candidate runs to the next space or quote; hideConnectionPassword
// decides where the authority ends.
const CONNECTION_STRING = /((?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^:/\s@]*:)([^\s'"`<>]*)/gi;

function hideConnectionPassword(whole: string, head: string, rest: string): string {
  const first = rest.indexOf('@');
  if (first < 0) return whole; // no credentials (e.g. host:port)
  let authorityEnd = rest.length;
  for (const c of ['/', '?', '#']) {
    const k = rest.indexOf(c, first);
    if (k >= 0 && k < authorityEnd) authorityEnd = k;
  }
  return head + R + rest.slice(rest.lastIndexOf('@', authorityEnd - 1));
}

// A value given to a password-like name. The name may carry other name characters around the keyword
// (AWS_SECRET_ACCESS_KEY, apiKeyProd, db.password) and may be quoted ("password": ...); the separator is
// ':', '=', '=>' or ':='. The value is a quoted string (quotes kept, escapes honoured) or the next
// non-space run. Only the value is replaced. This also hides type annotations such as `token: string`:
// over-redacting is the safe direction. A match may only start where a name starts (the lookbehind), and
// the keyword is checked by a lookahead inside that name, so a long name is scanned once (linear time).
const KEYWORDS = 'password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|auth';
const ASSIGNED_VALUE = new RegExp(
  `((?<![\\w.-])(?=[\\w.-]*?(?:${KEYWORDS}))[\\w.-]+["'\`]?\\s*(?:=>|:=|:|=)\\s*)` +
  `("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|\`(?:[^\`\\\\]|\\\\.)*\`|\\S+)`,
  'gi',
);

function hideAssignedValue(_whole: string, head: string, value: string): string {
  const q = value[0];
  const quoted = value.length >= 2 && (q === '"' || q === "'" || q === '`') && value.endsWith(q);
  return head + (quoted ? q + R + q : R);
}

// Private key markers, found without a regex so they are seen on lines of any length.
const MARK_START = '-----';
const KEY_TAILS = ['PRIVATE KEY', 'PRIVATE KEY BLOCK'];

/** Finds `-----BEGIN [A-Z ]*PRIVATE KEY-----` or `... PRIVATE KEY BLOCK-----` (PGP), or END, in `line` from `from`. Linear time. */
function findKeyMarker(line: string, kind: 'BEGIN' | 'END', from: number): { start: number; end: number } | null {
  const head = `${MARK_START}${kind} `;
  for (let i = line.indexOf(head, from); i >= 0; i = line.indexOf(head, i + 1)) {
    let j = i + head.length;
    while (j < line.length && (line[j] === ' ' || (line[j] >= 'A' && line[j] <= 'Z'))) j++;
    const label = line.slice(i + head.length, j);
    if (KEY_TAILS.some((t) => label.endsWith(t)) && line.startsWith(MARK_START, j)) return { start: i, end: j + MARK_START.length };
  }
  return null;
}

function redactSegment(s: string): string {
  let out = s;
  for (const [, re] of TOKEN_RULES) out = out.replace(re, R);
  out = out.replace(CONNECTION_STRING, hideConnectionPassword);
  return out.replace(ASSIGNED_VALUE, hideAssignedValue);
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
    if (line.replace(CONNECTION_STRING, hideConnectionPassword) !== line) found.add('connection-string-password');
  }
  return [...found];
}

// ---------- known values ----------

const stripPadding = (s: string) => {
  let end = s.length;
  while (end > 0 && s[end - 1] === '=') end--;
  return s.slice(0, end);
};

/** Every form of a typed value that is looked for (see scrubKnownValues). */
function knownForms(values: string[]): string[] {
  const forms = new Set<string>();
  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    for (const v of new Set([raw, raw.trim()])) {
      if (v.trim() === '') continue;
      const b64 = Buffer.from(v, 'utf8').toString('base64');
      const urlSafe = b64.replaceAll('+', '-').replaceAll('/', '_');
      forms.add(v).add(b64).add(stripPadding(b64)).add(urlSafe).add(stripPadding(urlSafe));
      forms.add(JSON.stringify(v).slice(1, -1)); // as written inside a JSON string
      try {
        const enc = encodeURIComponent(v);
        const lower = enc.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()); // our own value, not repo text
        forms.add(enc).add(lower).add(enc.replaceAll('%20', '+')).add(lower.replaceAll('%20', '+')); // + form-encoded
      } catch {
        // a lone surrogate has no URL-encoded form
      }
    }
  }
  return [...forms].filter((f) => f.trim() !== '');
}

/**
 * Replaces every value the user typed with [REDACTED]: the exact value, its base64 forms (standard and
 * URL-safe, with and without `=` padding), its URL-encoded forms (encodeURIComponent, lowercase percent
 * escapes, `+` for spaces) and its JSON-escaped form. Empty and whitespace-only values are ignored.
 * Every occurrence of every form is found in the original text first (plain substring search, no regex),
 * overlapping or touching matches are merged, and each merged span becomes one [REDACTED], so overlapping
 * values cannot leave a piece behind.
 * Known limit: the base64 of a value embedded at a non-aligned offset inside a longer base64 blob (e.g.
 * base64 of "user:value") is not detected; the gitleaks pass is the second line of defence there.
 */
export function scrubKnownValues(text: string, values: string[]): string {
  const spans: [number, number][] = [];
  for (const f of knownForms(values)) {
    for (let i = text.indexOf(f); i >= 0; i = text.indexOf(f, i + 1)) spans.push([i, i + f.length]);
  }
  if (spans.length === 0) return text;
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  let out = '';
  let pos = 0;
  let [start, end] = spans[0];
  for (const [s, e] of spans) {
    if (s <= end) {
      end = Math.max(end, e);
      continue;
    }
    out += text.slice(pos, start) + R;
    pos = end;
    [start, end] = [s, e];
  }
  return out + text.slice(pos, start) + R + text.slice(end);
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
 * matches and binaries, reads within the read limits, then scrubKnownValues → redact() → scrubKnownValues
 * (known values only when given) → the gitleaks pass (if opts.gitleaks; it also removes every secret it
 * found from all files, and the known values again) → cuts to maxBytes by priority (whole files, lowest
 * priority first, sized as the final bundleText). Without opts.gitleaks the result is for counting only:
 * bundleText refuses it.
 */
export async function bundleCode(dir: string, opts: BundleOptions = {}): Promise<CodeBundle> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isFinite(maxBytes) || maxBytes < MIN_MAX_BYTES) throw new RangeError(`maxBytes must be a number of at least ${MIN_MAX_BYTES}.`);
  const roots = normalizeRoots(opts.roots);
  const priority = opts.priority ?? defaultPriority;
  const known = opts.knownValues ?? [];
  const scrub = (s: string) => (known.length > 0 ? scrubKnownValues(s, known) : s);
  // Known values first (so redact() cannot break one up and leave pieces), then redact(), then known values
  // again in case a redaction exposed a new exact match. The same order applies to file names.
  const clean = (s: string) => scrub(redact(scrub(s)));
  const flagged: string[] = []; // secrets the gitleaks pass found; a path holding one is never shown
  const nameHidden = (p: string) => clean(p) !== p || flagged.some((v) => p.includes(v));
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
    const entry = { path, content: clean(result.text) };
    const bytes = blockBytes(entry);
    if (WRAPPER_BYTES + bytes > maxBytes) { tooBig.push(path); continue; }
    collected.push(entry);
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
    collected = await gitleaksPass(collected, opts.gitleaks, opts.gitleaksTimeoutMs ?? GITLEAKS_TIMEOUT_MS, known, flagged, notes, show);
    gitleaksChecked = true;
  } else {
    notes.add('gitleaks was not run: this bundle is for counting only and cannot be sent to the AI.');
  }

  // Cut to maxBytes, counted as the exact size of bundleText (wrapper and per-file headers included): keep
  // the highest-priority files that fit; once one does not fit, the rest are dropped.
  const files: FileEntry[] = [];
  const dropped: string[] = [];
  let bytes = WRAPPER_BYTES;
  for (const f of collected) {
    const b = blockBytes(f);
    if (WRAPPER_BYTES + b > maxBytes) tooBig.push(f.path);
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

const PATHS_FILE = 'paths.txt';

/**
 * Scans the (already cleaned) files with gitleaks and returns what may be sent. Every finding is replaced
 * where it was reported; then every secret gitleaks found (and the known values) is removed from ALL files
 * in all its forms, so a secret reported on one line cannot survive on another line or in another file.
 * The bundle paths are scanned too (paths.txt, one per line, as bundleText shows them); a file whose path
 * gitleaks flags, or whose path holds a found secret, is left out. Found secrets are added to `flagged`.
 */
async function gitleaksPass(files: FileEntry[], bin: string, timeoutMs: number, known: string[], flagged: string[], notes: Notes, show: (p: string) => string): Promise<FileEntry[]> {
  // An absolute path only: a bare name would be looked up on PATH.
  if (!isAbsolute(bin)) throw new GitleaksError('The gitleaks binary must be given as an absolute path.');
  let config: string;
  try {
    config = gitleaksConfigPath();
  } catch (e) {
    throw new GitleaksError(e instanceof Error ? e.message : "pipegen's gitleaks config could not be found.");
  }
  const scanned = files.map((f) => ({ path: f.path, content: f.content.split(ALLOW_COMMENT).join('gitleaks-allow') }));
  const shownPaths = scanned.map((f) => displayPath(f.path));
  const tmp = await realpath(await mkdtemp(join(tmpdir(), 'pipegen-gitleaks-')));
  try {
    await chmod(tmp, 0o700);
    // Neutral names: no repo file name (.gitleaksignore, .gitleaks.toml, allowlisted paths) reaches gitleaks.
    const names = scanned.map((_, i) => `f${String(i + 1).padStart(6, '0')}.txt`);
    for (let i = 0; i < scanned.length; i++) await writeFile(join(tmp, names[i]), scanned[i].content, { flag: 'wx', mode: 0o600 });
    await writeFile(join(tmp, PATHS_FILE), shownPaths.join('\n').split(ALLOW_COMMENT).join('gitleaks-allow'), { flag: 'wx', mode: 0o600 });
    const reportPath = join(tmp, 'report.json');
    const code = await runGitleaks(bin, ['detect', '--no-git', '--source', tmp, '--config', config, '--report-format', 'json', '--report-path', reportPath], tmp, timeoutMs);
    if (code !== 0 && code !== 1) throw new GitleaksError(`gitleaks failed (exit code ${code}).`);
    const findings = await readReport(reportPath);

    const index = new Map(names.map((n, i) => [n, i]));
    const perFile = new Map<number, Finding[]>();
    const drop = new Set<number>();
    const unplaced = new Set<number>();
    const badPath = new Set<number>();
    const secrets = new Set<string>();
    let strays = 0;
    for (const f of findings) {
      // The secret-bearing text of every finding is removed everywhere below.
      const found = f.secret !== '' ? f.secret : f.match;
      if (found.trim() !== '' && found !== R) secrets.add(found);
      const abs = isAbsolute(f.file) ? resolve(f.file) : resolve(tmp, f.file);
      const rel = insideDir(tmp, abs) ? relative(tmp, abs) : undefined;
      if (rel === PATHS_FILE) {
        // A finding in a file name: leave out the files on the reported lines, and any whose path holds the text.
        const { startLine: s, endLine: e } = f;
        let hit = false;
        if (s !== undefined && e !== undefined && s <= e && e <= shownPaths.length) {
          for (let k = s - 1; k < e; k++) badPath.add(k);
          hit = true;
        }
        shownPaths.forEach((p, k) => {
          if ((f.secret !== '' && p.includes(f.secret)) || (f.match !== '' && p.includes(f.match))) {
            badPath.add(k);
            hit = true;
          }
        });
        if (!hit) shownPaths.forEach((_, k) => badPath.add(k)); // cannot tell which name: leave them all out
        continue;
      }
      const i = rel === undefined ? undefined : index.get(rel);
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

    // Remove every found secret (and the known values again) from every file, in all its forms, then check.
    flagged.push(...secrets);
    const everywhere = [...known, ...secrets];
    const leftover = new Set<number>();
    scanned.forEach((f, i) => {
      if (everywhere.length > 0) f.content = scrubKnownValues(f.content, everywhere);
      const bare = f.content.split(R).join('\u0000'); // a secret that is part of the word REDACTED is not a leftover
      if ([...secrets].some((v) => bare.includes(v))) leftover.add(i);
      if ([...secrets].some((v) => f.path.includes(v) || shownPaths[i].includes(v))) badPath.add(i);
    });

    const pathsOf = (set: Set<number>) => [...set].sort((a, b) => a - b).map((i) => scanned[i].path);
    notes.add(`gitleaks checked the bundle: ${plural(redacted, 'finding', 'findings')} redacted.`);
    notes.addPaths('Left out because gitleaks found something pipegen could not locate to redact:', pathsOf(drop), show);
    notes.addPaths('Left out because a found secret was still in them after redaction:', pathsOf(leftover), show);
    if (badPath.size > 0) notes.add(`Left out ${plural(badPath.size, 'file whose path', 'files whose paths')} gitleaks flagged as secret-like (names not shown).`);
    if (strays > 0) {
      notes.add(`Ignored ${plural(strays, 'gitleaks finding', 'gitleaks findings')} for a file outside the scanned folder.`);
      notes.addPaths('Left out because a gitleaks finding outside the scanned folder may relate to them:', pathsOf(unplaced), show);
    }
    return scanned.filter((_, i) => !drop.has(i) && !unplaced.has(i) && !leftover.has(i) && !badPath.has(i));
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
const OPEN_TAG = '<code-bundle>\n';
const CLOSE_TAG = '</code-bundle>';
const WRAPPER_BYTES = Buffer.byteLength(OPEN_TAG + CLOSE_TAG);
const MIN_MAX_BYTES = 64;

/** A path as bundleText shows it (and as the gitleaks pass scans it). */
function displayPath(path: string): string {
  return neutralizeTags(safeText(path, 1000));
}

/** One file's part of bundleText: header line, content, a final newline. */
function fileBlock(f: FileEntry): string {
  const content = neutralizeTags(f.content);
  return `--- ${displayPath(f.path)} ---\n${content}${content === '' || content.endsWith('\n') ? '' : '\n'}`;
}
const blockBytes = (f: FileEntry) => Buffer.byteLength(fileBlock(f));

export function bundleText(bundle: CodeBundle): string {
  if (bundle === null || typeof bundle !== 'object' || bundle.gitleaksChecked !== true || !CHECKED.has(bundle)) {
    throw new GitleaksRequiredError('This code bundle has not passed the required gitleaks check, so it cannot be sent to the AI.');
  }
  const files = [...bundle.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return OPEN_TAG + files.map(fileBlock).join('') + CLOSE_TAG;
}
