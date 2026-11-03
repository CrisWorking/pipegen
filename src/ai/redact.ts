import { execFile, type ChildProcess, type ExecFileException } from 'node:child_process';
import { rmSync } from 'node:fs';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import picomatch from 'picomatch';
import { IGNORED_DIRS, MAX_FILES_TEXT, listFiles, readTextLimitedWithReason, regexSafe, type Skipped } from '../read/limits.js';
import { onExit } from '../util/exit-hooks.js';
import { PATH_SHOWN_MAX, safeText } from '../util/safe-text.js';
import { LONG_LINE, R, code, decodedNamePieces, findSecretLike, highEntropyRuns, isDigit, isLetter, redact, replaceSpans, type Span } from './redact-core.js';
import { asScanned, CANARY_RULE, canaryLine, newCanary, PREFIX_LINES, SCAN_CHUNK_SAFE_BYTES, scannersWouldSkip } from './scan-staging.js';
import { SECRET_SCAN_EXIT, SecretScanError, secretScanArgv, secretScanConfigPath, skippedByDefaultPaths, type SecretScanner } from './secret-scan-config.js';

export { isBinary } from '../read/limits.js';
// the pure redaction core (C1b fix round 1): re-exported so every importer of redact.ts sees what it did
export { LONG_LINE, decodedNamePieces, findSecretLike, highEntropyRuns, redact };
// the shared scan-staging core (C1c)
export { SCAN_CHUNK_SAFE_BYTES };
export {
  chooseSecretScanner, SECRET_SCAN_EXIT, SECRET_SCANNER_ENV, secretScanArgv, secretScanConfigPath, SecretScanError, type SecretScanner, type SecretScannerName,
} from './secret-scan-config.js';

/** Thrown by bundleText for a bundle that did not pass bundleCode's secret scan: nothing may be sent. */
export class SecretScanRequiredError extends Error {}

/** `bytes` is the exact UTF-8 size of bundleText(bundle) (wrapper and per-file headers included), never over maxBytes. */
export interface CodeBundle {
  files: { path: string; content: string }[];
  bytes: number;
  truncated: boolean;
  secretScanChecked: boolean;
  notes: string[];
  /** P40/P45: what the secret scan found, for the audit report to mask everywhere. Empty without the secret scan. */
  found: ScanFound;
}

/**
 * P40/P45: what an `audit --ai` secret scan found, so the report can mask it in every string it prints (the plain-audit
 * parts too: RenderOptions.found). Never sent to the AI and never printed.
 */
export interface ScanFound {
  /** Every listed repo path (raw) the scan made secret; such a path is shown whole as HIDDEN_NAME. */
  names: readonly string[];
  /**
   * Found values of MIN_GLOBAL_SECRET characters or more (the reported secret and match), plus, for a decoded finding in
   * a file name (a base64-encoded secret as a name), the encoded text in that name: masked wherever they appear.
   */
  values: readonly string[];
  /** Shorter found values: masked only where they stand as a whole word (the rule for short values everywhere). */
  tokens: readonly string[];
}

/** A ScanFound with nothing in it (no secret scan). */
export const NOTHING_FOUND: ScanFound = Object.freeze({ names: Object.freeze([]), values: Object.freeze([]), tokens: Object.freeze([]) });

/** How a file name that looks like a secret is shown, in the bundle's notes and in the audit report. */
export const HIDDEN_NAME = '(a file whose name looks like a secret)';

export interface BundleOptions {
  roots?: string[];
  maxBytes?: number;
  /** Higher numbers are kept first when the bundle is cut to maxBytes. Default: manifests and config, then entry points, routes, the rest. */
  priority?: (path: string) => number;
  knownValues?: string[];
  /** The pinned secret scanner (Plan B's ensurePinnedBinary). Without it the bundle is for counting only. */
  secretScanner?: SecretScanner;
  /** The secret scan's timeout; 60 s by default (tests set a short one). */
  secretScanTimeoutMs?: number;
  /**
   * Only these repo paths may be read (null or absent: every file). `audit --ai` passes the files its consent screen
   * counted, so the secret-scanned bundle can only shrink: the cut to maxBytes runs over that same set and can't take
   * in a file the user wasn't shown (Plan U T4b review I1).
   */
  onlyPaths?: ReadonlySet<string> | null;
}

/** The note a bundle built without the secret scan carries (counting only). The audit leaves it out of its report (nothing is sent there). */
export const COUNTING_ONLY_NOTE = 'The secret scan was not run: this bundle is for counting only and cannot be sent to the AI.';
const DEFAULT_MAX_BYTES = 150_000;
const SECRET_SCAN_TIMEOUT_MS = 60_000;
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

/** One group of EXCLUDED_PATTERNS for the terminal (Plan U ruling S29): a label, a short plain-English list, the globs. */
export interface ExcludedGroup { label: string; summary: string; patterns: readonly string[] }

/**
 * EXCLUDED_PATTERNS grouped for the terminal (consent screen, audit summary; ruling S29): about 60 globs are unreadable
 * there. Markdown and JSON still list every pattern. Every non-negated pattern is in exactly one group (a test checks).
 */
export const EXCLUDED_PATTERN_GROUPS: readonly ExcludedGroup[] = Object.freeze([
  {
    label: 'secret files',
    summary: '.env files, anything named *secret*, .npmrc, .netrc, .git-credentials, credentials.json, .pgpass, .pypirc, .htpasswd',
    patterns: ['**/.env*', '**/.env*/**', '**/*.env', '**/*secret*', '**/*secret*/**', '**/.npmrc', '**/.netrc', '**/.git-credentials', '**/credentials.json', '**/.pgpass', '**/.pypirc', '**/.htpasswd'],
  },
  {
    label: 'keys',
    summary: '*.pem, *.key, SSH keys (id_rsa, id_ed25519…), *.p12, *.pfx, *.jks, *.keystore, *.ppk, *.p8',
    patterns: ['**/*.pem', '**/*.key', '**/id_rsa*', '**/id_dsa*', '**/id_ecdsa*', '**/id_ed25519*', '**/*.p12', '**/*.pfx', '**/*.jks', '**/*.keystore', '**/*.ppk', '**/*.p8'],
  },
  {
    label: 'cloud and Terraform state',
    summary: 'Terraform state and variables (*.tfstate, *.tfvars), kubeconfig, AWS and Docker credentials, service-account*.json',
    patterns: ['**/*.tfstate', '**/*.tfstate.backup', '**/*.tfvars', '**/*.tfvars.json', '**/kubeconfig', '**/kubeconfig.*', '**/*.kubeconfig', '**/.kube/config', '**/.kube/**', '**/.aws/credentials', '**/.aws/config', '**/.docker/config.json', '**/service-account*.json'],
  },
  { label: 'lockfiles', summary: LOCKFILES.join(', '), patterns: LOCKFILES.map((f) => `**/${f}`) },
  { label: 'dependency/build folders', summary: IGNORED_DIRS.map((d) => `${d}/`).join(', '), patterns: IGNORED_DIRS.map((d) => `**/${d}/**`) },
].map((g) => Object.freeze({ ...g, patterns: Object.freeze([...g.patterns]) })));

/** Files EXCLUDED_PATTERNS keeps although an earlier pattern excludes them (its `!` patterns): `.env.example`, `.env.sample`. */
export const EXCLUDED_KEPT: readonly string[] = Object.freeze(
  EXCLUDED_PATTERNS.filter((p) => p.startsWith('!')).map((p) => p.slice(1).replace(/^\*\*\//, '')),
);

/**
 * What is never sent to the AI, in plain words for the terminal (ruling S29): one `- label: summary` line per group,
 * binary files, then the files kept. Shared by the consent screen and the audit report, which indent it themselves.
 */
export function excludedSummaryLines(): string[] {
  return [
    ...EXCLUDED_PATTERN_GROUPS.map((g) => `- ${g.label}: ${g.summary}`),
    '- binary files (images, archives, compiled programs), found by their content',
    `kept: ${EXCLUDED_KEPT.join(', ')}`,
  ];
}

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

// ---------- known values ----------

const stripPadding = (s: string) => {
  let end = s.length;
  while (end > 0 && s[end - 1] === '=') end--;
  return s.slice(0, end);
};

const isHex = (c: number) => isDigit(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);

/** `s` with the two hex digits after each `%` in upper case. Same length; linear. */
function upperPercent(s: string): string {
  if (!s.includes('%')) return s;
  let out = '';
  let pos = 0;
  for (let i = s.indexOf('%'); i >= 0; i = s.indexOf('%', i + 1)) {
    if (i + 2 < s.length && isHex(code(s, i + 1)) && isHex(code(s, i + 2))) {
      out += s.slice(pos, i + 1) + s.slice(i + 1, i + 3).toUpperCase();
      pos = i + 3;
    }
  }
  return out + s.slice(pos);
}

/**
 * Plan E E0a (ruling B1): the hex and shifted-base64 forms are looked for only from this many UTF-8 bytes of a value, the vault's
 * shortest value (secrets.ts MIN_VALUE_LENGTH; a test keeps them equal). A shorter known value would give needles of a few
 * characters that ordinary hex or base64 text holds by chance.
 */
export const MIN_ENCODED_FORM_BYTES = 8;

/**
 * Plan E E0a (ruling B1): the base64 characters that depend only on `bytes` when they start at byte offset 0, 1 or 2 of a
 * longer encoded text (`user:value` in Basic auth, `value:` in Stripe's, a value inside a JSON blob). Sextet j covers bits
 * [6j, 6j+6) of the whole text, so with the value at bits [8k, 8k+8n) the characters ceil(8k/6) to floor((8k+8n)/6) are the
 * value's own, whatever comes before or after it; the GitHub runner masks the same core. At most 4 bits of the value stay in
 * the character on each side of the core.
 */
function base64Cores(bytes: Buffer): string[] {
  const cores: string[] = [];
  for (const k of [0, 1, 2]) {
    const enc = Buffer.concat([Buffer.alloc(k), bytes]).toString('base64');
    cores.push(enc.slice(Math.ceil((8 * k) / 6), Math.floor((8 * k + 8 * bytes.length) / 6)));
  }
  return cores;
}

/** Every form of a typed value that is looked for (see scrubKnownValues). */
function knownForms(values: string[]): string[] {
  const forms = new Set<string>();
  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    // bundleCode turns CRLF and lone CRs into LF before scrubbing, so a typed value holding them is looked for in those forms too
    const crlfOnly = raw.split('\r\n').join('\n');
    const lf = crlfOnly.split('\r').join('\n');
    for (const v of new Set([raw, raw.trim(), crlfOnly, crlfOnly.trim(), lf, lf.trim()])) {
      if (v.trim() === '') continue;
      const bytes = Buffer.from(v, 'utf8');
      const b64 = bytes.toString('base64');
      const urlSafe = b64.replaceAll('+', '-').replaceAll('/', '_');
      forms.add(v).add(b64).add(stripPadding(b64)).add(urlSafe).add(stripPadding(urlSafe));
      if (bytes.length >= MIN_ENCODED_FORM_BYTES) {
        // E0a: hex in either case, and the base64 core at byte offsets 0, 1 and 2 (both alphabets)
        const h = bytes.toString('hex');
        forms.add(h).add(h.toUpperCase());
        for (const core of base64Cores(bytes)) forms.add(core).add(core.replaceAll('+', '-').replaceAll('/', '_'));
      }
      const json = JSON.stringify(v).slice(1, -1); // as written inside a JSON string
      forms.add(json).add(json.replace(/[\u007f-\uffff]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)); // and ASCII-only JSON
      try {
        const enc = encodeURIComponent(v);
        forms.add(enc).add(enc.replaceAll('%20', '+')); // + form-encoded
        forms.add(encodeURI(v));
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
 * Percent escapes match in any hex case (`%2f` = `%2F`); encodeURI and ASCII-only JSON (`\u00e9`) forms count too.
 * Plan E E0a (ruling B1), for a value of MIN_ENCODED_FORM_BYTES or more: its hex (lower and upper case) and the base64 core
 * of the value at byte offset 0, 1 or 2 inside a longer base64 text (`user:value`), both alphabets. Every form is also looked
 * for across line breaks (LF, CRLF, CR, U+2028, U+2029, with the spaces and tabs next to them): a value split over lines,
 * and base64 or hex wrapped at fixed columns, is found and replaced together with the breaks inside it.
 * Known limits (the secret scan is the second line of defence there): a value whose own letters changed case; hex in mixed
 * case or with separators (`de:ad`); HTML-entity or language-specific escapes (Python `\xe9`); a value split by some other
 * character (the vault's fullScrub also tries the forms with every control and invisible removed).
 */
export function scrubKnownValues(text: string, values: string[]): string {
  return knownValueScrubber(values)(text);
}

/**
 * scrubKnownValues with the forms of `values` worked out once: the returned function scrubs any number of texts
 * (the audit renderers clean thousands of short strings with the same values).
 */
export function knownValueScrubber(values: readonly string[]): (text: string) => string {
  const forms = knownForms([...values]);
  const upperForms = new Set(forms.map(upperPercent));
  const anyPercent = forms.some((f) => f.includes('%'));
  return (text) => scrubWith(text, forms, upperForms, anyPercent);
}

const isBreak = (c: number) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;
const isBlank = (c: number) => c === 32 || c === 9;

/**
 * E0a (ruling B1): `text` with its line breaks taken out (LF, CR, U+2028, U+2029; with `blanks`, also the spaces and tabs
 * next to each break), and for each character of that view its index in `text`. Null when `text` has no line break. Linear:
 * each character is kept, skipped or taken back once.
 */
function joinedView(text: string, blanks: boolean): { view: string; at: Int32Array } | null {
  let i = 0;
  while (i < text.length && !isBreak(code(text, i))) i++;
  if (i === text.length) return null;
  const at = new Int32Array(text.length);
  let n = 0;
  for (let j = 0; j < text.length; j++) {
    if (!isBreak(code(text, j))) {
      at[n++] = j;
      continue;
    }
    if (!blanks) continue;
    while (n > 0 && isBlank(code(text, at[n - 1] as number))) n--;
    while (j + 1 < text.length && isBlank(code(text, j + 1))) j++;
  }
  let view = '';
  for (let k = 0; k < n;) {
    let e = k + 1;
    while (e < n && at[e] === (at[e - 1] as number) + 1) e++;
    view += text.slice(at[k], (at[e - 1] as number) + 1);
    k = e;
  }
  return { view, at: at.subarray(0, n) };
}

function scrubWith(text: string, forms: string[], upperForms: Set<string>, anyPercent: boolean): string {
  const spans: [number, number][] = [];
  // Spans are found on the text as it is (forms as they are), and on a copy with every %xx in upper case (same
  // length, so the spans apply to the original) against forms normalised the same way, so percent escapes match
  // in any hex case and a value right after a literal '%' is still found. E0a (ruling B1): both are also searched
  // in the text with its line breaks taken out (with and without the blanks next to them), and a span found there
  // is mapped back to the original, line breaks included.
  const views: { view: string; at: Int32Array | null }[] = [{ view: text, at: null }];
  for (const blanks of [false, true]) {
    const j = joinedView(text, blanks);
    if (j !== null && !views.some((v) => v.view === j.view)) views.push(j);
  }
  for (const { view, at } of views) {
    const hay = upperPercent(view);
    const searches: [string, Iterable<string>][] = [[view, forms]];
    if (hay !== view || anyPercent) searches.push([hay, upperForms]);
    const add = (s: number, e: number) => spans.push(at === null ? [s, e] : [at[s] as number, (at[e - 1] as number) + 1]);
    for (const [h, fs] of searches) {
      for (const f of fs) {
        // overlapping or touching matches of one form are one span (the same union, without a span per character of a
        // repeated pattern: a hostile log of 'aaaa…' would give millions)
        let s = -1;
        let e = -1;
        for (let i = h.indexOf(f); i >= 0; i = h.indexOf(f, i + 1)) {
          if (i <= e) {
            e = Math.max(e, i + f.length);
            continue;
          }
          if (s >= 0) add(s, e);
          [s, e] = [i, i + f.length];
        }
        if (s >= 0) add(s, e);
      }
    }
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

/**
 * Notes in plain English: paths only (cleaned), never a value or file content. A path note is rendered when all() is
 * called (ruling P39), so its names are shown as the secret scan left them: a name the scan flagged is masked, even
 * in a note added before the scan ran.
 */
class Notes {
  private readonly entries: (string | (() => string))[] = [];
  add(line: string): void {
    this.entries.push(line);
  }
  /** "<lead> a, b, c and 4 more." */
  addPaths(lead: string, paths: string[], show: (p: string) => string): void {
    if (paths.length === 0) return;
    const list = [...paths];
    this.entries.push(() => {
      const shown = list.slice(0, MAX_LISTED_IN_NOTE).map(show).join(', ');
      const more = list.length > MAX_LISTED_IN_NOTE ? ` and ${list.length - MAX_LISTED_IN_NOTE} more` : '';
      return `${lead} ${shown}${more}.`;
    });
  }
  all(): string[] {
    return [...new Set(this.entries.map((e) => (typeof e === 'string' ? e : e())))];
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
 * (known values only when given) → the secret scan (if opts.secretScanner; it also removes every secret it
 * found from all files, and the known values again) → cuts to maxBytes by priority (whole files, lowest
 * priority first, sized as the final bundleText). Without opts.secretScanner the result is for counting only:
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
  const clean = (s: string, path?: string) => scrub(redact(scrub(s), path === undefined ? undefined : { path }));
  const flagged: string[] = []; // secrets the secret scan found; a path holding one is never shown
  const flaggedTokens: string[] = []; // short ones (under 6 characters), matched only as whole tokens
  const reportValues: string[] = []; // P45: more text the report masks (matches, the encoded text of decoded name findings)
  // Checked on the raw name and on the name as shown (control characters removed), so a control character
  // inside a name cannot split a secret-like pattern.
  const nameHidden = (p: string) => {
    const shown = displayPath(p);
    return clean(p) !== p || clean(shown) !== shown || flagged.some((v) => p.includes(v) || shown.includes(v))
      || flaggedTokens.some((v) => tokenSpans(p, v).length > 0 || tokenSpans(shown, v).length > 0);
  };
  // P39: names the secret scan flagged as lines of its file list (filled by secretScanPass)
  const flaggedNames = new Set<string>();
  // P45: never cut here: the report masks found values first and cuts after (a cut could leave half a secret)
  // P45: in the checked bundle, a name longer than the scanner reads of it is hidden whole too
  const show = (p: string) => (flaggedNames.has(p) || nameHidden(p) || (opts.secretScanner !== undefined && tooLongToScan(p)) ? HIDDEN_NAME : safeText(p, PATH_SHOWN_MAX));
  const notes = new Notes();
  const inRoots = (p: string) => roots === null || roots.some((r) => underRoot(p, r));

  const realRoot = await realpath(dir);
  const found = { links: [] as string[] };
  const listing = await listFiles(dir, ['**/*'], IGNORED_DIRS.map((d) => `**/${d}/**`), found);
  let truncated = listing.truncated;
  if (listing.truncated) notes.add(`Stopped listing after ${MAX_FILES_TEXT} files; the rest were not read.`);

  const only = opts.onlyPaths ?? null;
  const links = found.links.filter((p) => inRoots(p) && (only === null || only.has(p)));
  let excluded = 0;
  let secretNames = 0;
  const candidates: { path: string; rank: number }[] = [];
  for (const path of listing.files) {
    if (!inRoots(path)) continue;
    if (only !== null && !only.has(path)) continue;
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
    const result = await readTextLimitedWithReason(abs, dir);
    if (!('text' in result)) {
      (result.skipped === 'link' ? links : skipped[result.skipped]).push(path);
      continue;
    }
    // Line endings normalised to LF first: the AI needs no CRs, and every later step then sees plain lines.
    const lf = result.text.split('\r\n').join('\n').split('\r').join('\n');
    const entry = { path, content: clean(lf, path) };
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

  let secretScanChecked = false;
  if (opts.secretScanner !== undefined) {
    // P39: the files the notes name but the scan doesn't read (skipped, over the size limit, past the read budget):
    // their names go through the scan too, in the file list, so a note never shows a name the scanner didn't check
    // P45: and every other name the audit report can print (excluded files such as .env, files outside the counted set,
    // every symbolic link), so a secret in any listed name is found by the scanner and masked in the whole report
    const named = [...new Set([...links, ...Object.values(skipped).flat(), ...tooBig, ...overBudget, ...listing.files, ...found.links])];
    collected = await secretScanPass(collected, opts.secretScanner, opts.secretScanTimeoutMs ?? SECRET_SCAN_TIMEOUT_MS, known, { long: flagged, short: flaggedTokens, report: reportValues }, notes, show, named, flaggedNames);
    secretScanChecked = true;
  } else {
    notes.add(COUNTING_ONLY_NOTE);
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

  // P40: every name in the listing the scan made secret, so the report can mask it outside these notes too
  const scanHidden = (p: string) => {
    const shown = displayPath(p);
    return flaggedNames.has(p) || tooLongToScan(p) || flagged.some((v) => p.includes(v) || shown.includes(v))
      || flaggedTokens.some((v) => tokenSpans(p, v).length > 0 || tokenSpans(shown, v).length > 0);
  };
  const hiddenNames = secretScanChecked ? [...new Set([...listing.files, ...found.links, ...flaggedNames])].filter(scanHidden).sort() : [];
  const scanFound: ScanFound = !secretScanChecked ? NOTHING_FOUND : Object.freeze({
    names: Object.freeze(hiddenNames),
    values: Object.freeze([...new Set([...flagged, ...reportValues])].filter((v) => v.length >= MIN_GLOBAL_SECRET && v !== R).sort()),
    tokens: Object.freeze([...new Set(flaggedTokens)].filter((v) => v.trim() !== '' && v !== R).sort()),
  });

  const bundle: CodeBundle = {
    files: files.map((f) => Object.freeze({ path: f.path, content: f.content })),
    bytes,
    truncated,
    secretScanChecked,
    notes: notes.all(),
    found: scanFound,
  };
  Object.freeze(bundle.files);
  Object.freeze(bundle.notes);
  Object.freeze(bundle);
  if (secretScanChecked) CHECKED.add(bundle);
  else COUNTED.set(bundle, realRoot);
  return bundle;
}

// ---------- the secret scan ----------

/**
 * One reported finding, lines already mapped to the content (see SCAN_PREFIX). `decoded`: the scanner found it in a
 * decoded form (a `decoded:*` tag, base64 or hex), so the reported text is not in the file. `onPrefix`: it was
 * reported on pipegen's own empty first line, so it can't be placed. `rule`: the RuleID ('' when absent), used only to
 * tell pipegen's canary findings (P34) apart.
 */
interface Finding { file: string; rule: string; startLine?: number; endLine?: number; secret: string; match: string; decoded: boolean; onPrefix: boolean }

// The prefix line, the canary (P34/P35/P37), the late magic numbers (Task 7 R1) and the chunk size (P36/P38) are the shared
// scan-staging core (src/ai/scan-staging.ts, C1c), which the gate's staged secrets scan uses too.

/** Maps a finding's lines from the file as written to its content; a finding on the prefix can't be placed. */
function unprefixed(f: Finding): Finding {
  if (f.startLine === undefined || f.endLine === undefined) return { ...f, startLine: undefined, endLine: undefined };
  if (f.startLine <= PREFIX_LINES) return { ...f, startLine: undefined, endLine: undefined, onPrefix: true };
  return { ...f, startLine: f.startLine - PREFIX_LINES, endLine: f.endLine - PREFIX_LINES };
}

/**
 * Review M1: while the scan runs, its temp folder (the redacted copies and the raw report) is removed if the process is
 * stopped by SIGINT or SIGTERM, or exits, before `finally` can run; the scanner is killed first. The hook lives in the one
 * exit-hook registry (D5, S8), which raises the signal again when no other handler is there, so the process still stops by
 * it. `release` unregisters the hook.
 */
function guardTempDir(dir: string): { child: ChildProcess | null; release: () => void } {
  const guard = { child: null as ChildProcess | null, release: () => {} };
  guard.release = onExit(() => {
    try {
      guard.child?.kill('SIGKILL');
    } catch { /* already gone */ }
    rmSync(dir, { recursive: true, force: true });
  });
  return guard;
}

/** Runs the scanner; resolves with its exit code, rejects (SecretScanError) on a spawn error, timeout or signal. */
function runScanner(name: string, bin: string, args: string[], cwd: string, timeoutMs: number, started: (c: ChildProcess) => void = () => {}): Promise<number> {
  const env: Record<string, string> = {};
  if (process.env.PATH !== undefined) env.PATH = process.env.PATH;
  if (process.env.HOME !== undefined) env.HOME = process.env.HOME;
  return new Promise((resolvePromise, reject) => {
    const child = execFile(bin, args, { cwd, env, timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (err) => {
      if (err === null) return resolvePromise(0);
      const e = err as ExecFileException;
      if (e.killed && e.signal) return reject(new SecretScanError(`${name} did not finish within ${Math.round(timeoutMs / 1000)} s (or produced too much output) and was stopped.`));
      if (e.signal) return reject(new SecretScanError(`${name} was stopped by signal ${safeText(String(e.signal))}.`));
      if (typeof e.code === 'number') return resolvePromise(e.code);
      reject(new SecretScanError(`${name} could not be started (${safeText(String(e.code ?? 'unknown error'))}).`));
    });
    started(child);
  });
}

const intOrUndefined = (v: unknown) => (typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : undefined);

/** The report is built from repo-derived content: only File, StartLine/EndLine, Match, Secret and Tags are used, all type-checked. */
async function readReport(name: string, path: string): Promise<Finding[]> {
  const info = await lstat(path).catch(() => null);
  if (info === null || !info.isFile()) throw new SecretScanError(`${name} wrote no report.`);
  if (info.size > MAX_REPORT_BYTES) throw new SecretScanError(`${name} wrote a report that is too large to read.`);
  let data: unknown;
  try {
    data = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    throw new SecretScanError(`${name} wrote a report pipegen could not read.`);
  }
  if (!Array.isArray(data)) throw new SecretScanError(`${name} wrote a report in an unexpected format.`);
  return data.map((item: unknown) => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) throw new SecretScanError(`${name} wrote a report in an unexpected format.`);
    const o = item as Record<string, unknown>;
    if (typeof o.File !== 'string' || o.File === '') throw new SecretScanError(`${name} wrote a finding without a file.`);
    if (o.Tags !== undefined && o.Tags !== null && !(Array.isArray(o.Tags) && o.Tags.every((t) => typeof t === 'string'))) {
      throw new SecretScanError(`${name} wrote a finding whose tags are not a list of words.`);
    }
    const tags = Array.isArray(o.Tags) ? (o.Tags as string[]) : [];
    return {
      file: o.File,
      rule: typeof o.RuleID === 'string' ? o.RuleID : '',
      startLine: intOrUndefined(o.StartLine),
      endLine: intOrUndefined(o.EndLine),
      secret: typeof o.Secret === 'string' ? o.Secret : '',
      match: typeof o.Match === 'string' ? o.Match : '',
      // betterleaks decodes base64/hex (up to depth 5) and reports the decoded text, which is not in the file (P31)
      decoded: tags.some((t) => t.toLowerCase().startsWith('decoded:')),
      onPrefix: false,
    };
  });
}

/**
 * Replaces one finding in `content`, on its reported lines only; null (the file is left out) when it cannot be
 * located there. Rulings P31 and P32 (Task 7 review I1): no path searches the whole file, since a whole-file search
 * could hit an unflagged plain copy elsewhere and leave the real (for example encoded) secret in place. So the file
 * is left out when the finding has no or invalid line numbers, when the value isn't on its lines, when it is decoded
 * (base64/hex: the reported text is by definition not in the file), or when it sits on pipegen's prefix. The found
 * value is still removed from every file afterwards (secretScanPass), so a plain copy elsewhere doesn't survive.
 */
function applyFinding(content: string, f: Finding): string | null {
  const wanted = [f.secret, f.match].filter((s) => s !== '');
  if (wanted.length === 0 || f.decoded || f.onPrefix) return null;
  const lines = content.split('\n');
  const { startLine: s, endLine: e } = f;
  if (s === undefined || e === undefined || !(s <= e && e <= lines.length)) return null;
  const seg = lines.slice(s - 1, e).join('\n');
  for (const w of wanted) {
    if (seg.includes(w)) return [...lines.slice(0, s - 1), seg.split(w).join(R), ...lines.slice(e)].join('\n');
  }
  return null;
}

// Both scanners skip a line holding `gitleaks:allow` or `betterleaks:allow` (live probe). The bundle never carries one
// (any case), so a repo cannot opt a line out; the scan also runs with --ignore-gitleaks-allow. Built at runtime, so
// this file holds neither comment itself.
const ALLOW_COMMENT = new RegExp('(gitleaks|betterleaks)' + ':allow', 'gi');
const neutralizeAllow = (s: string) => s.replace(ALLOW_COMMENT, (_m, tool: string) => `${tool}-allow`);

const PATHS_FILE = 'paths.txt';

/** One file-list piece: its lines, and for each line the index of the name it stands for (`owners`). */
interface PathPiece { name: string; owners: number[]; count: number; canary: string; written: string }

/** One scanned line of the file list and the index of the name it belongs to. */
interface NameLine { text: string; owner: number }

/**
 * Ruling P36: the bundle's file list as one or more pieces (paths.txt, paths2.txt, …), split at line boundaries so each
 * piece as written (prefix, paths, canary line) stays within SCAN_CHUNK_SAFE_BYTES, each with its own canary; all must
 * be confirmed. `first`/`count`: the shown paths a piece holds. Always at least one piece (an empty list has one too).
 */
/** At most this many extra starts per file-list line (scanLine). */
const MAX_LINE_STARTS = 24;

/**
 * P45: one file-list line as the scanners read it: the name, then, after a space each, the rest of the name from every
 * `/`, `-`, `_`, `+` or `=` in it (at most MAX_LINE_STARTS). The scanners decode a base64 text only from where its token
 * starts, and these characters are part of a base64 token, so in `config/<b64>.env` the token starts at `config` and
 * decodes to nothing (both pinned scanners miss it, measured). From each start an encoded secret begins a token of its
 * own. A finding anywhere on the line still names that one file.
 */
export function scanLine(name: string): string {
  const parts = [name];
  for (let i = 0; i < name.length - 1 && parts.length <= MAX_LINE_STARTS; i++) if ('/-_+='.includes(name[i] as string)) parts.push(name.slice(i + 1));
  return parts.join(' ');
}

function pathPieces(lines: NameLine[], scannerName: string): PathPiece[] {
  const pieces: PathPiece[] = [];
  const fixed = Buffer.byteLength(asScanned('x', newCanary())) - 1; // the prefix, the separators and a canary line
  let first = 0;
  while (pieces.length === 0 || first < lines.length) {
    let bytes = fixed;
    let count = 0;
    while (first + count < lines.length && bytes + Buffer.byteLength((lines[first + count] as NameLine).text) + (count > 0 ? 1 : 0) <= SCAN_CHUNK_SAFE_BYTES) {
      bytes += Buffer.byteLength((lines[first + count] as NameLine).text) + (count > 0 ? 1 : 0);
      count++;
    }
    if (count === 0 && first < lines.length) throw new SecretScanError(`A file name in the bundle is too long for ${scannerName} to scan safely; nothing was sent.`);
    const canary = newCanary();
    const part = lines.slice(first, first + count);
    const written = asScanned(part.map((l) => l.text).join('\n'), canary);
    // R1 for the paths too: the scanners would skip such a piece, and so never check those file names. Fail closed.
    if (scannersWouldSkip(written)) throw new SecretScanError(`The bundle's file list has a binary-format marker at a byte the ${scannerName} scanner sniffs, so it would not be scanned; nothing was sent.`);
    pieces.push({ name: pieces.length === 0 ? PATHS_FILE : `paths${pieces.length + 1}.txt`, owners: part.map((l) => l.owner), count, canary, written });
    first += count;
  }
  return pieces;
}

/** P48: at most this many extra scan lines (segments and decoded text) for one name; a name that needs more is hidden. */
export const MAX_NAME_LINES = 48;
/** P48: at most this many extra scan lines in all; names past it are hidden whole (failing closed). */
export const MAX_EXTRA_NAME_LINES = 200_000;

/**
 * P48: every line scanned for one name: the name (scanLine of the form the report shows), each of its path segments on
 * a line of its own (so a token starts at the segment, however deep), and pipegen's own decodings of it. Null when it
 * would take more than MAX_NAME_LINES extra lines: then the name is hidden instead (failing closed).
 */
function nameLines(path: string): string[] | null {
  const shown = scannedName(path);
  const extra = new Set<string>();
  for (const seg of shownForm(path).split('/')) if (seg.length >= MIN_GLOBAL_SECRET && seg !== shown) extra.add(seg);
  for (const piece of decodedNamePieces(shownForm(path))) extra.add(piece);
  if (extra.size > MAX_NAME_LINES) return null;
  return [scanLine(shown), ...[...extra].map((x) => x.replaceAll('\n', ' '))];
}

const isWordChar = (c: number) => isLetter(c) || isDigit(c) || c === 95; // [A-Za-z0-9_]

/** Spans of `v` in `text` where it stands as a whole token (no [A-Za-z0-9_] right before or after). Linear. */
export function tokenSpans(text: string, v: string): Span[] {
  const spans: Span[] = [];
  if (v === '') return spans;
  let from = 0;
  for (let i = text.indexOf(v, from); i >= 0; i = text.indexOf(v, from)) {
    const end = i + v.length;
    if ((i === 0 || !isWordChar(code(text, i - 1))) && (end >= text.length || !isWordChar(code(text, end)))) {
      spans.push([i, end]);
      from = end;
    } else {
      from = i + 1;
    }
  }
  return spans;
}
// A found secret shorter than this is not removed from every file (it would hit ordinary text).
export const MIN_GLOBAL_SECRET = 6;

/**
 * P45/P48: the parts of `name` whose decoding holds `value`, as the encoded text to mask; the shortest ones. Every
 * maximal run of base64/base64url characters is decoded at its four alignments (as decodedNamePieces does), and every
 * run of hex digits at its two; where the decoded bytes hold `value`, the encoded characters that produced those bytes
 * are the span. A part with percent-escapes is decoded whole. Linear in the name. Empty when nothing decodes to it.
 */
export function encodedSpans(name: string, value: string): string[] {
  if (value.length === 0) return [];
  const want = Buffer.from(value, 'utf8').toString('latin1');
  const hits: string[] = [];
  const add = (run: string, start: number, end: number) => hits.push(run.slice(Math.max(0, start), Math.min(run.length, end)));
  for (const run of name.match(/[A-Za-z0-9+/_=-]{8,}/g) ?? []) {
    for (let k = 0; k < 4 && k < run.length; k++) {
      const text = Buffer.from(run.slice(k), 'base64').toString('latin1');
      for (let i = text.indexOf(want); i >= 0; i = text.indexOf(want, i + 1)) add(run, k + Math.floor(i / 3) * 4, k + Math.ceil((i + want.length) / 3) * 4);
    }
  }
  for (const run of name.match(/[0-9a-fA-F]{16,}/g) ?? []) {
    for (let k = 0; k < 2; k++) {
      const text = Buffer.from(run.slice(k, k + Math.floor((run.length - k) / 2) * 2), 'hex').toString('latin1');
      for (let i = text.indexOf(want); i >= 0; i = text.indexOf(want, i + 1)) add(run, k + 2 * i, k + 2 * (i + want.length));
    }
  }
  for (const part of name.match(/[A-Za-z0-9_~%+-]*%[0-9a-fA-F]{2}[A-Za-z0-9_~%+-]*/g) ?? []) {
    try {
      if (decodeURIComponent(part).includes(value)) hits.push(part);
    } catch {
      // not valid percent-encoding: the scanners can't decode it either
    }
  }
  if (hits.length === 0) return [];
  const shortest = Math.min(...hits.map((h) => h.length));
  return [...new Set(hits.filter((h) => h.length === shortest))];
}

/** P45 fallback: the parts of a flagged name (split at `/` and `.`) of 8 characters or more, masked when the found text can't be placed. */
function nameParts(name: string): string[] {
  return [...new Set(name.split(/[/.]/).filter((p) => p.length >= 8))];
}

/**
 * Scans the (already cleaned) files with the secret scanner and returns what may be sent. Every finding is replaced
 * where it was reported; then every secret the scanner found (and the known values) is removed from ALL files
 * in all its forms, so a secret reported on one line cannot survive on another line or in another file.
 * The bundle paths are scanned too (paths.txt, one per line, as bundleText shows them); a file whose path
 * the scanner flags, or whose path holds a found secret, is left out. Found secrets are added to `flagged`.
 * Ruling P34: every scanned file and paths.txt carry a canary. A file whose canary did not come back is left out; a
 * scan that does not confirm paths.txt, or confirms none of the files, throws SecretScanError (it may have read nothing).
 */
async function secretScanPass(files: FileEntry[], scanner: SecretScanner, timeoutMs: number, known: string[], flagged: { long: string[]; short: string[]; report?: string[] }, notes: Notes, show: (p: string) => string, named: readonly string[] = [], flaggedNames: Set<string> = new Set()): Promise<FileEntry[]> {
  // An absolute path only: a bare name would be looked up on PATH.
  const { name, path: bin } = scanner;
  if (!isAbsolute(bin)) throw new SecretScanError(`The ${name} binary must be given as an absolute path.`);
  let config: string;
  try {
    config = secretScanConfigPath();
  } catch (e) {
    throw new SecretScanError(e instanceof Error ? e.message : `pipegen's ${name} config could not be found.`);
  }
  const canaried = files.map((f) => {
    const content = neutralizeAllow(f.content);
    const canary = newCanary();
    return { path: f.path, content, canary, written: asScanned(content, canary) };
  });
  const tooBig = canaried.filter((f) => Buffer.byteLength(f.written) > SCAN_CHUNK_SAFE_BYTES);
  notes.addPaths(`Left out because they are too large to secret-scan safely (over ${SCAN_CHUNK_SAFE_BYTES.toLocaleString('en-US')} bytes as scanned; the scanners read bigger files in pieces and can miss a secret cut between two):`, tooBig.map((f) => f.path), show);
  const sniffed = canaried.filter((f) => !tooBig.includes(f) && scannersWouldSkip(f.written));
  notes.addPaths('Left out because the secret scanners skip files shaped like this (a binary-format marker at a fixed byte):', sniffed.map((f) => f.path), show);
  const kept = canaried.filter((f) => !tooBig.includes(f) && !sniffed.includes(f));
  const scanned: FileEntry[] = kept.map((f) => ({ path: f.path, content: f.content }));
  const shownPaths = scanned.map((f) => displayPath(f.path));
  // P39: every other name a note may show (left out here, or before the scan) is scanned too, after the bundle's own
  const scannedPaths = new Set(scanned.map((f) => f.path));
  const others = [...new Set([...named, ...tooBig.map((f) => f.path), ...sniffed.map((f) => f.path)])].filter((p) => !scannedPaths.has(p));
  const shownOthers = others.map(displayPath);
  const made = await mkdtemp(join(tmpdir(), 'pipegen-secret-scan-'));
  const guard = guardTempDir(made);
  try {
    const tmp = await realpath(made);
    await chmod(tmp, 0o700);
    // Neutral names: no repo file name (.gitleaksignore, .gitleaks.toml, allowlisted paths) reaches the scanner.
    const names = scanned.map((_, i) => `f${String(i + 1).padStart(6, '0')}.txt`);
    // P48: each name as several lines (the name, its segments, pipegen's own decodings), each tied to that name. A name
    // that needs too many lines, or comes after the total cap, is not scanned in full: it is hidden instead.
    const lines: NameLine[] = [];
    const unscannable: number[] = [];
    let extraLines = 0;
    const allNames = [...scanned.map((f) => f.path), ...others];
    allNames.forEach((p, k) => {
      const all = nameLines(p);
      if (all === null || extraLines + all.length - 1 > MAX_EXTRA_NAME_LINES) {
        unscannable.push(k);
        lines.push({ text: neutralizeAllow(scanLine(scannedName(p))), owner: k });
        return;
      }
      extraLines += all.length - 1;
      for (const text of all) lines.push({ text: neutralizeAllow(text), owner: k });
    });
    const pieces = pathPieces(lines, name);
    // P34 belt: the default path allowlist matches the absolute path, so a temp folder under node_modules/ (or another
    // folder it lists) would hide every file. Refused before anything is written; the canaries below are the guarantee.
    if ([...names, ...pieces.map((p) => p.name)].some((n) => skippedByDefaultPaths(join(tmp, n)))) {
      throw new SecretScanError(`The secret scan's temp folder ${safeText(tmp)} is under a folder the ${name} scanner skips (such as node_modules); set TMPDIR to another folder and run again. Nothing was sent.`);
    }
    for (let i = 0; i < scanned.length; i++) await writeFile(join(tmp, names[i]), kept[i].written, { flag: 'wx', mode: 0o600 });
    for (const piece of pieces) await writeFile(join(tmp, piece.name), piece.written, { flag: 'wx', mode: 0o600 });
    const reportPath = join(tmp, 'report.json');
    const code = await runScanner(name, bin, secretScanArgv(name, tmp, config, reportPath), tmp, timeoutMs, (c) => { guard.child = c; });
    if (code !== SECRET_SCAN_EXIT.clean && code !== SECRET_SCAN_EXIT.found) throw new SecretScanError(`${name} failed (exit code ${code}).`);
    const reported = (await readReport(name, reportPath)).map(unprefixed);
    // "found" with nothing listed is a scan that went wrong (betterleaks exits 1 on a config error, with no report)
    if (code === SECRET_SCAN_EXIT.found && reported.length === 0) throw new SecretScanError(`${name} reported findings but listed none.`);

    const relOf = (file: string) => {
      const abs = isAbsolute(file) ? resolve(file) : resolve(tmp, file);
      return insideDir(tmp, abs) ? relative(tmp, abs) : undefined;
    };
    const index = new Map(names.map((n, i) => [n, i]));
    const pieceOf = new Map(pieces.map((p) => [p.name, p]));
    // P34: take the canary findings out. One counts only when its value is exactly the token written to the file it is
    // reported against, on that file's last line. P35: any other canary-rule finding (another file's token, an unknown
    // value, a file outside the folder) is never dropped: it stays a real finding, and the scanned file it names is
    // left out (one in a paths piece leaves out the files on its lines, as any file-name finding does).
    const canaryOf = new Map<string, { token: string; line: number }>([
      ...names.map((n, i): [string, { token: string; line: number }] => [n, { token: kept[i].canary, line: canaryLine(kept[i].written) }]),
      ...pieces.map((p): [string, { token: string; line: number }] => [p.name, { token: p.canary, line: canaryLine(p.written) }]),
    ]);
    const seen = new Map<string, { count: number; onLine: boolean }>();
    const foreign = new Set<number>();
    const findings: Finding[] = [];
    for (const f of reported) {
      const rel = f.rule === CANARY_RULE ? relOf(f.file) : undefined;
      const own = rel === undefined ? undefined : canaryOf.get(rel);
      if (rel !== undefined && own !== undefined && own.token === f.secret) {
        const s = seen.get(rel) ?? { count: 0, onLine: true };
        s.count++;
        if (f.startLine !== own.line || f.endLine !== own.line) s.onLine = false;
        seen.set(rel, s);
        continue;
      }
      findings.push(f);
      const i = rel === undefined ? undefined : index.get(rel);
      if (i !== undefined) foreign.add(i);
    }
    // exactly once, on the last line: anything else (none, twice, elsewhere) is unexplained, and the file is not sent
    const read = (n: string) => seen.get(n)?.count === 1 && seen.get(n)?.onLine === true;
    if (!pieces.every((p) => read(p.name))) throw new SecretScanError(`${name} did not confirm it read the bundle's file list, so the file names may not have been checked; nothing was sent.`);
    const unconfirmed = new Set(names.flatMap((n, i) => (seen.has(n) ? [] : [i])));
    const misreported = new Set(names.flatMap((n, i) => (seen.has(n) && !read(n) ? [i] : [])));
    if (scanned.length > 0 && unconfirmed.size + misreported.size === scanned.length) throw new SecretScanError(`${name} did not confirm it read the bundle's files, so they may not have been checked; nothing was sent.`);

    const perFile = new Map<number, Finding[]>();
    const drop = new Set<number>();
    const unplaced = new Set<number>();
    const badPath = new Set<number>();
    const allShown = [...shownPaths, ...shownOthers];
    // a name line k of the file list: a bundle file (k < scanned.length) is left out; another one is masked in notes
    const flagName = (k: number) => {
      if (k < scanned.length) badPath.add(k);
      else flaggedNames.add(others[k - scanned.length]);
    };
    // P48: a name too big to scan in full is treated as flagged (failing closed); so is one the entropy belt matches,
    // whatever the scanner said: its file is left out, the name hidden, and the high-entropy text masked everywhere
    for (const k of unscannable) flagName(k);
    allNames.forEach((p, k) => {
      const runs = highEntropyRuns(shownForm(p));
      if (runs.length === 0) return;
      flagName(k);
      flagged.report?.push(...runs);
    });
    const secrets = new Set<string>();
    const shortSecrets = new Set<string>();
    const shortHit = new Set<number>();
    let strays = 0;
    for (const f of findings) {
      // The secret-bearing text of every finding is removed everywhere below, unless it is too short to
      // remove safely everywhere (it would hit ordinary text): then only the reported file is left out.
      const found = f.secret !== '' ? f.secret : f.match;
      const short = found.length < MIN_GLOBAL_SECRET;
      if (found.trim() !== '' && found !== R) (short ? shortSecrets : secrets).add(found);
      const texts = [f.secret, f.match].filter((t) => t.length >= MIN_GLOBAL_SECRET);
      flagged.report?.push(...texts);
      const rel = relOf(f.file);
      const piece = rel === undefined ? undefined : pieceOf.get(rel);
      if (piece !== undefined) {
        // A finding in a file name: leave out the files on the reported lines, and any whose path holds the text.
        const { startLine: s, endLine: e } = f;
        let hit = false;
        const onLines: number[] = [];
        // a finding that starts on a name line but is reported as ending past the last name (both scanners end a decoded
        // match at column 0 of the next line) still names only lines from its start: none before it can hold it
        if (s !== undefined && e !== undefined && s >= 1 && s <= e && s <= piece.count) {
          for (let k = s - 1; k < Math.min(e, piece.count); k++) {
            flagName(piece.owners[k] as number);
            onLines.push(piece.owners[k] as number);
          }
          hit = true;
        }
        allShown.forEach((p, k) => {
          if (texts.some((t) => p.includes(t))) {
            flagName(k);
            hit = true;
          }
        });
        if (!hit) allShown.forEach((_, k) => flagName(k)); // cannot tell which name: leave them all out (mask the others)
        // P45: a decoded finding (the found text is not in the name as written): the report masks the encoded text in
        // the name, so the same encoded secret is masked in every other string too
        if (found.trim() !== '' && found !== R) {
          for (const k of hit ? onLines : allShown.map((_, j) => j)) {
            const shown = allShown[k];
            if (texts.some((t) => shown.includes(t)) || found === '') continue;
            const spans = encodedSpans(shown, found);
            if (spans.length > 0) flagged.report?.push(...spans);
            else if (hit) flagged.report?.push(...nameParts(shown)); // can't tell where: every longer part of that name
          }
        }
        continue;
      }
      const i = rel === undefined ? undefined : index.get(rel);
      if (i !== undefined) {
        if (short) shortHit.add(i);
        else perFile.set(i, [...(perFile.get(i) ?? []), f]);
        continue;
      }
      // Not one of the scanned files (outside the temp dir, or unknown): ignore the finding, and drop any
      // file it might relate to, by name or by the reported text.
      strays++;
      const named = index.get(f.file.replaceAll('\\', '/').split('/').pop() ?? '');
      if (named !== undefined) unplaced.add(named);
      scanned.forEach((s, j) => {
        if (texts.some((t) => s.content.includes(t))) unplaced.add(j);
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
    flagged.long.push(...secrets);
    flagged.short.push(...shortSecrets);
    const everywhere = [...known, ...secrets];
    const leftover = new Set<number>();
    // Short values: removed only as whole tokens (not inside a longer word), and a path holding one is left out.
    scanned.forEach((f, i) => {
      for (const v of shortSecrets) {
        f.content = replaceSpans(f.content, tokenSpans(f.content, v));
        if (tokenSpans(f.path, v).length > 0 || tokenSpans(shownPaths[i], v).length > 0) badPath.add(i);
      }
      if (everywhere.length > 0) f.content = scrubKnownValues(f.content, everywhere);
      const bare = f.content.split(R).join('\u0000'); // a secret that is part of the word REDACTED is not a leftover
      if ([...secrets].some((v) => bare.includes(v))) leftover.add(i);
      if ([...secrets].some((v) => f.path.includes(v) || shownPaths[i].includes(v))) badPath.add(i);
    });

    // a flagged path is masked in every note, also one that leaves the file out for another reason
    for (const i of badPath) flaggedNames.add(scanned[i].path);
    const pathsOf = (set: Set<number>) => [...set].sort((a, b) => a - b).map((i) => scanned[i].path);
    notes.add(`${name} checked the bundle: ${plural(redacted, 'finding', 'findings')} redacted.`);
    notes.addPaths(`Left out because ${name} did not confirm it read them:`, pathsOf(unconfirmed), show);
    notes.addPaths(`Left out because ${name} reported their check marker more than once or on an unexpected line:`, pathsOf(misreported), show);
    notes.addPaths(`Left out because ${name} reported a check marker in them that pipegen did not write there:`, pathsOf(foreign), show);
    notes.addPaths(`Left out because ${name} found something pipegen could not locate to redact:`, pathsOf(drop), show);
    notes.addPaths('Left out because a found secret was still in them after redaction:', pathsOf(leftover), show);
    if (shortHit.size > 0) notes.add(`Left out ${plural(shortHit.size, 'file', 'files')} where ${name} found a short value (under ${MIN_GLOBAL_SECRET} characters); elsewhere it is removed only where it stands as a whole word.`);
    if (badPath.size > 0) notes.add(`Left out ${plural(badPath.size, 'file whose path', 'files whose paths')} ${name} flagged as secret-like (names not shown).`);
    if (strays > 0) {
      notes.add(`Ignored ${plural(strays, `${name} finding`, `${name} findings`)} for a file outside the scanned folder.`);
      notes.addPaths(`Left out because a ${name} finding outside the scanned folder may relate to them:`, pathsOf(unplaced), show);
    }
    return scanned.filter((_, i) => !unconfirmed.has(i) && !misreported.has(i) && !foreign.has(i) && !drop.has(i) && !unplaced.has(i) && !leftover.has(i) && !badPath.has(i) && !shortHit.has(i));
  } finally {
    // every way out (a result, any error): the copies and the raw report go; the signal hooks go after
    try {
      guard.child?.kill('SIGKILL'); // a no-op once it exited
      await rm(made, { recursive: true, force: true });
    } finally {
      guard.release();
    }
  }
}

/** What secretScanText found in one text: see there. */
export interface TextScan {
  /** The text's own lines (1-based) a finding was reported on, sorted. */
  lines: number[];
  /** Every found text (the reported secret and match) of MIN_GLOBAL_SECRET characters or more. */
  values: string[];
  /** A finding that names no line of the text (none, invalid, pipegen's prefix or the canary's lines) or another file. */
  unplaced: boolean;
}

/**
 * Plan E E0a (ruling B1, step 7): the secret scan over one text, such as the fix loop's log excerpt, with the scanner, config,
 * argv, prefix line, canary (P34) and private temp folder of bundleCode's pass. Allow comments are neutralised first (same
 * length per line, so lines don't move). It reports where findings are rather than editing the text, so the caller decides
 * what to drop. Throws SecretScanError when the scan can't run or gives an unusable result, when the text as written is over
 * SCAN_CHUNK_SAFE_BYTES or shaped like a format the scanners skip (scannersWouldSkip), and when the canary did not come back
 * exactly once, on its own line: the scan may have read nothing.
 */
export async function secretScanText(text: string, scanner: SecretScanner, timeoutMs: number = SECRET_SCAN_TIMEOUT_MS): Promise<TextScan> {
  const { name, path: bin } = scanner;
  if (!isAbsolute(bin)) throw new SecretScanError(`The ${name} binary must be given as an absolute path.`);
  let config: string;
  try {
    config = secretScanConfigPath();
  } catch (e) {
    throw new SecretScanError(e instanceof Error ? e.message : `pipegen's ${name} config could not be found.`);
  }
  const content = neutralizeAllow(String(text));
  const canary = newCanary();
  const written = asScanned(content, canary);
  if (Buffer.byteLength(written) > SCAN_CHUNK_SAFE_BYTES) throw new SecretScanError(`The text is too large to secret-scan whole (over ${SCAN_CHUNK_SAFE_BYTES.toLocaleString('en-US')} bytes as scanned).`);
  if (scannersWouldSkip(written)) throw new SecretScanError(`The text has a binary-format marker at a fixed byte, so ${name} would skip it.`);
  const made = await mkdtemp(join(tmpdir(), 'pipegen-secret-scan-'));
  const guard = guardTempDir(made);
  try {
    const tmp = await realpath(made);
    await chmod(tmp, 0o700);
    const file = 'f000001.txt';
    if (skippedByDefaultPaths(join(tmp, file))) {
      throw new SecretScanError(`The secret scan's temp folder ${safeText(tmp)} is under a folder the ${name} scanner skips (such as node_modules); set TMPDIR to another folder and run again. Nothing was sent.`);
    }
    await writeFile(join(tmp, file), written, { flag: 'wx', mode: 0o600 });
    const reportPath = join(tmp, 'report.json');
    const code = await runScanner(name, bin, secretScanArgv(name, tmp, config, reportPath), tmp, timeoutMs, (c) => { guard.child = c; });
    if (code !== SECRET_SCAN_EXIT.clean && code !== SECRET_SCAN_EXIT.found) throw new SecretScanError(`${name} failed (exit code ${code}).`);
    const reported = (await readReport(name, reportPath)).map(unprefixed);
    if (code === SECRET_SCAN_EXIT.found && reported.length === 0) throw new SecretScanError(`${name} reported findings but listed none.`);
    const own = canaryLine(written);
    const contentLines = content === '' ? 0 : content.split('\n').length - (content.endsWith('\n') ? 1 : 0);
    const isOurs = (f: Finding) => {
      const abs = isAbsolute(f.file) ? resolve(f.file) : resolve(tmp, f.file);
      return insideDir(tmp, abs) && relative(tmp, abs) === file;
    };
    let seen = 0;
    let onLine = true;
    const lines = new Set<number>();
    const values = new Set<string>();
    let unplaced = false;
    for (const f of reported) {
      // P34: our canary counts only as itself, on its line; any other canary-rule finding is a real one
      if (f.rule === CANARY_RULE && f.secret === canary && isOurs(f)) {
        seen++;
        if (f.startLine !== own || f.endLine !== own) onLine = false;
        continue;
      }
      for (const t of [f.secret, f.match]) if (t.length >= MIN_GLOBAL_SECRET && t !== R) values.add(t);
      const { startLine: s, endLine: e } = f;
      if (!isOurs(f) || s === undefined || e === undefined || !(s <= e && e <= contentLines)) {
        unplaced = true;
        continue;
      }
      for (let l = s; l <= e; l++) lines.add(l);
    }
    if (seen !== 1 || !onLine) throw new SecretScanError(`${name} did not confirm it read the text, so it may not have been checked; nothing was sent.`);
    return { lines: [...lines].sort((a, b) => a - b), values: [...values], unplaced };
  } finally {
    try {
      guard.child?.kill('SIGKILL');
      await rm(made, { recursive: true, force: true });
    } finally {
      guard.release();
    }
  }
}

// ---------- bundle text ----------

// Bundles that passed bundleCode's secret scan. They are frozen, so they cannot change afterwards;
// a copy or a hand-made object is not in the set and is refused.
const CHECKED = new WeakSet<object>();
// Bundles bundleCode built without the secret scan (counting only), with the real path of the folder they were built from.
const COUNTED = new WeakMap<object, string>();

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
 * `--- path ---` header. Byte-identical for the same bundle. Throws SecretScanRequiredError unless the
 * bundle is bundleCode's own result after a secret scan, so unchecked code can never reach a provider.
 */
const OPEN_TAG = '<code-bundle>\n';
const CLOSE_TAG = '</code-bundle>';
const WRAPPER_BYTES = Buffer.byteLength(OPEN_TAG + CLOSE_TAG);
const MIN_MAX_BYTES = 64;

/** A path as bundleText shows it (and as the secret scan scans it). */
function displayPath(path: string): string {
  return neutralizeTags(safeText(path, SCAN_NAME_MAX));
}

/**
 * P45: a name is scanned (and shown to the AI) cut at this many code points. A longer name has characters the scanner
 * never saw, so the audit report hides it whole (HIDDEN_NAME), wherever it would show it.
 */
const SCAN_NAME_MAX = 1000;

/** A name as every output shows it before its own escaping: cleaned (safeText), not cut. */
const shownForm = (path: string): string => safeText(path, Number.MAX_SAFE_INTEGER);

/** P45: true when the name is longer than what the scanner reads of it. */
export function tooLongToScan(path: string): boolean {
  return Array.from(shownForm(path)).length > SCAN_NAME_MAX;
}

/**
 * P45: the text scanned for one name: exactly the string the report can show (cleaned, before any escaping), and also
 * the form the AI gets (displayPath) when that differs. A name too long to scan whole is scanned cut (and hidden whole).
 */
function scannedName(path: string): string {
  const shown = displayPath(path);
  if (tooLongToScan(path)) return shown;
  const full = shownForm(path);
  return full === shown ? full : `${full} ${shown}`;
}

/** One file's part of bundleText: header line, content, a final newline. */
function fileBlock(f: FileEntry): string {
  const content = neutralizeTags(f.content);
  return `--- ${displayPath(f.path)} ---\n${content}${content === '' || content.endsWith('\n') ? '' : '\n'}`;
}
const blockBytes = (f: FileEntry) => Buffer.byteLength(fileBlock(f));

/** bundleCode's own result after a secret scan (a copy, a hand-made object or a counting-only bundle is not). */
const isChecked = (bundle: CodeBundle): boolean =>
  bundle !== null && typeof bundle === 'object' && bundle.secretScanChecked === true && CHECKED.has(bundle);

export function bundleText(bundle: CodeBundle): string {
  if (!isChecked(bundle)) {
    throw new SecretScanRequiredError('This code bundle has not passed the required secret scan, so it cannot be sent to the AI.');
  }
  const files = [...bundle.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return OPEN_TAG + files.map(fileBlock).join('') + CLOSE_TAG;
}

// ---------- bundle summary (the consent screen's file facts) ----------

let makeSummary: (files: number, bytes: number, topFolders: readonly string[]) => BundleSummary;
/** Every BundleSummary bundleSummary() made: `private constructor` is TypeScript only (review M1). */
const ISSUED_SUMMARIES = new WeakSet<object>();

/**
 * What a secret-scanned code bundle holds, for the consent screen: the number of files, `bytes` (the exact size of
 * bundleText) and the top-level folders, most files first. Only bundleSummary() makes one: the constructor is private
 * and a private field makes the type nominal, so an object literal doesn't type-check, and consentText also refuses
 * anything isSummary() rejects (a cast or a copy). So the screen always counts the bundle that will be sent
 * (final review batch 2, I1).
 */
export class BundleSummary {
  readonly #fromCheckedBundle = true;

  private constructor(readonly files: number, readonly bytes: number, readonly topFolders: readonly string[]) {
    Object.freeze(this);
  }

  /** True only for an object bundleSummary() made (not one made with `new` through a cast, nor a subclass's). */
  static isSummary(x: unknown): x is BundleSummary {
    return typeof x === 'object' && x !== null && #fromCheckedBundle in x && ISSUED_SUMMARIES.has(x);
  }

  static {
    makeSummary = (files, bytes, topFolders) => {
      const made = new BundleSummary(files, bytes, Object.freeze([...topFolders]));
      ISSUED_SUMMARIES.add(made);
      return made;
    };
  }
}

/**
 * The consent facts of `bundle`. Throws SecretScanRequiredError unless it is bundleCode's own result after a secret
 * scan (as bundleText does), so the screen never describes code that can't be sent or wasn't checked. Top folders
 * are the raw first path segments (consentText cleans them for the terminal); files at the top level have none.
 */
export function bundleSummary(bundle: CodeBundle): BundleSummary {
  if (!isChecked(bundle)) {
    throw new SecretScanRequiredError('This code bundle has not passed the required secret scan, so pipegen can\'t ask to send it.');
  }
  return makeSummary(bundle.files.length, bundle.bytes, bundleTopFolders(bundle));
}

/** The raw first path segments of a bundle's files, most files first (files at the top level have none). */
export function bundleTopFolders(bundle: CodeBundle): string[] {
  const counts = new Map<string, number>();
  for (const f of bundle.files) {
    const cut = f.path.indexOf('/');
    if (cut > 0) counts.set(f.path.slice(0, cut), (counts.get(f.path.slice(0, cut)) ?? 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([name]) => name);
}

/**
 * The real path of the folder a COUNTING-ONLY bundle (bundleCode without the secret scan) was built from, or null for any other
 * object (a checked bundle, a copy, a hand-made one). The audit's consent summary (src/audit/consent-token.ts) uses it.
 */
export function countedBundleRoot(bundle: unknown): string | null {
  return typeof bundle === 'object' && bundle !== null ? COUNTED.get(bundle) ?? null : null;
}
