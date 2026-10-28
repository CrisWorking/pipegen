import { execFile, type ChildProcess, type ExecFileException } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { rmSync } from 'node:fs';
import { chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import picomatch from 'picomatch';
import { IGNORED_DIRS, MAX_FILES_TEXT, listFiles, readTextLimitedWithReason, regexSafe, type Skipped } from '../read/limits.js';
import { safeText } from '../util/safe-text.js';
import { SECRET_SCAN_EXIT, SecretScanError, secretScanArgv, secretScanConfigPath, skippedByDefaultPaths, type SecretScanner } from './secret-scan-config.js';

export { isBinary } from '../read/limits.js';
export {
  chooseSecretScanner, SECRET_SCAN_EXIT, SECRET_SCANNER_ENV, secretScanArgv, secretScanConfigPath, SecretScanError, type SecretScanner, type SecretScannerName,
} from './secret-scan-config.js';

/** Thrown by bundleText for a bundle that did not pass bundleCode's secret scan: nothing may be sent. */
export class SecretScanRequiredError extends Error {}

/** `bytes` is the exact UTF-8 size of bundleText(bundle) (wrapper and per-file headers included), never over maxBytes. */
export interface CodeBundle { files: { path: string; content: string }[]; bytes: number; truncated: boolean; secretScanChecked: boolean; notes: string[] }

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

const R = '[REDACTED]';
/** What redact() puts in place of a line too long to scan (over 4 KB): the whole line is hidden. */
export const LONG_LINE = '[REDACTED: line too long]';
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

// ---------- redaction ----------
//
// Everything here runs in linear time on lines of at most 4 KB: the token formats are regexes with a
// fixed prefix, and the shapes that need context (JWTs, connection strings, password-like assignments)
// are hand-written scans that look at each character a bounded number of times.

// Token formats, each replaced whole. Names are what findSecretLike reports (never the value).
const TOKEN_RULES: readonly (readonly [string, RegExp])[] = [
  ['aws-access-key', /AKIA[0-9A-Z]{16}/g],
  ['github-token', /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ['github-fine-grained-token', /github_pat_[A-Za-z0-9_]{20,}/g],
  ['slack-token', /xox[abpr]-[A-Za-z0-9-]+/g],
  ['stripe-key', /sk_(?:live|test)_[A-Za-z0-9]{10,}/g],
  ['sk-api-key', /sk-[A-Za-z0-9_-]{20,}/g],
  ['slack-webhook', /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/g],
  ['google-api-key', /AIza[0-9A-Za-z_-]{35}/g],
  ['npm-token', /npm_[A-Za-z0-9]{36}/g],
];

type Span = [number, number];

/** `s` with each span (sorted, not overlapping) replaced by [REDACTED]. */
function replaceSpans(s: string, spans: Span[]): string {
  if (spans.length === 0) return s;
  const sorted = spans.filter(([a, b]) => b > a).sort((x, y) => x[0] - y[0]); // empty spans: nothing to hide
  let out = '';
  let pos = 0;
  for (const [a, b] of sorted) {
    if (b <= pos) continue; // inside a span already replaced
    out += s.slice(pos, Math.max(a, pos)) + (a >= pos ? R : '');
    pos = b;
  }
  return out + s.slice(pos);
}

const code = (s: string, i: number) => s.charCodeAt(i);
const isLetter = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isUpper = (c: number) => c >= 65 && c <= 90;
const isLower = (c: number) => c >= 97 && c <= 122;
const isDigit = (c: number) => c >= 48 && c <= 57;
const isB64Url = (c: number) => isLetter(c) || isDigit(c) || c === 95 /* _ */ || c === 45 /* - */;
const isSchemeChar = (c: number) => isLetter(c) || isDigit(c) || c === 43 /* + */ || c === 46 /* . */ || c === 45 /* - */;
const isSpace = (c: number) => c === 32 || c === 9 || c === 13 || c === 10 || c === 12 || c === 11;
const isNameChar = (c: number) => isLetter(c) || isDigit(c) || c === 95 || c === 46 || c === 45; // [A-Za-z0-9_.-]

/**
 * JWTs: `eyJ` + three dot-separated base64url segments (the first two at least 4 characters, the signature
 * possibly empty for unsigned tokens), also when
 * glued after other characters. After a failed candidate the scan resumes at the end of its first segment,
 * since every later `eyJ` inside that segment would fail the same way: linear time.
 */
function jwtSpans(s: string): Span[] {
  const spans: Span[] = [];
  let from = 0;
  for (let i = s.indexOf('eyJ', from); i >= 0; i = s.indexOf('eyJ', from)) {
    let j = i + 3;
    while (j < s.length && isB64Url(code(s, j))) j++;
    const seg1End = j;
    let ok = seg1End - i >= 4 && code(s, j) === 46; // '.'
    let k = j + 1;
    if (ok) {
      while (k < s.length && isB64Url(code(s, k))) k++;
      ok = k - (j + 1) >= 4 && code(s, k) === 46;
    }
    let m = k + 1;
    if (ok) {
      while (m < s.length && isB64Url(code(s, m))) m++; // the signature may be empty (alg "none")
    }
    if (ok) {
      spans.push([i, m]);
      from = m;
    } else {
      from = Math.max(seg1End, i + 1);
    }
  }
  return spans;
}

/**
 * Passwords in URLs (scheme, '://', user, ':', password, '@', host): the scheme, the user and the host stay. For each
 * `://` with a scheme before it, the token is the non-space run after it and the authority runs to the first
 * `/`, `?` or `#` (extended over a `/` while the next path segment holds an `@`, for a password with a
 * `/` in it). The userinfo is everything before the authority's LAST `@`; the password is what follows its
 * first `:`. When the authority has no such `user:password@` (it stopped at a `?` or `#` inside the
 * password, or the user holds an `@`), the whole token is used: from the authority's first `:` to the
 * token's last `@` before a host-like character (hiding too much is the safe side). Each character is
 * visited a bounded number of times: linear time.
 * Known limits (the secret scan's connection-string rule covers them): with user `admin`, password `P@ss#2024` and
 * host `db`, the `2024` stays (the authority ends at the `#` and already holds user:password@; a later `@`
 * could as well be in a query, `?y=z@w`); and a password with `#` or `?` before a percent-encoded socket
 * host (`@%2Fvar%2Frun/db`), whose `@` is not followed by a host-like character.
 */
function connectionSpans(s: string): Span[] {
  const spans: Span[] = [];
  const n = s.length;
  // lastHostAt[i]: the last '@' followed by a host-like character (letter, digit, '[') in s[i .. end of the
  // non-space run holding i], or -1. One right-to-left pass, made on first use.
  let lastHostAt: Int32Array | null = null;
  const lastHostAtFrom = (i: number) => {
    if (lastHostAt === null) {
      lastHostAt = new Int32Array(n + 1).fill(-1);
      let cur = -1;
      for (let p = n - 1; p >= 0; p--) {
        const c = code(s, p);
        if (isSpace(c)) cur = -1;
        else if (c === 64 && cur === -1 && p + 1 < n && (isLetter(code(s, p + 1)) || isDigit(code(s, p + 1)) || code(s, p + 1) === 91)) cur = p;
        lastHostAt[p] = cur;
      }
    }
    return i < n ? lastHostAt[i] : -1;
  };
  let from = 0;
  for (let sep = s.indexOf('://', from); sep >= 0; sep = s.indexOf('://', from)) {
    from = sep + 1;
    if (sep === 0 || !isSchemeChar(code(s, sep - 1))) continue; // no scheme
    const start = sep + 3; // token start
    // authority: up to the first '/', '?', '#' or space (it never runs past the next '://', which holds a '/')
    let authEnd = start;
    while (authEnd < n) {
      const c = code(s, authEnd);
      if (c === 47 || c === 63 || c === 35 || isSpace(c)) break;
      authEnd++;
    }
    // a '/' inside the password: extend while the next path segment holds an '@' (a segment never crosses a '://')
    while (authEnd < n && code(s, authEnd) === 47) {
      let segEnd = authEnd + 1;
      let hasAt = false;
      while (segEnd < n) {
        const c = code(s, segEnd);
        if (c === 47 || c === 63 || c === 35 || isSpace(c)) break;
        if (c === 64) hasAt = true;
        segEnd++;
      }
      if (!hasAt) break;
      authEnd = segEnd;
    }
    let at = -1;
    for (let p = authEnd - 1; p >= start; p--) if (code(s, p) === 64) { at = p; break; }
    let colon = -1;
    const colonLimit = at >= 0 ? at : authEnd;
    for (let p = start; p < colonLimit; p++) if (code(s, p) === 58) { colon = p; break; }
    if (at >= 0 && colon >= 0) {
      if (at > colon + 1) spans.push([colon + 1, at]);
    } else {
      // No user:password in the authority (it may have stopped at a '#' or '?' inside the password, or the
      // user holds an '@'): work on the whole token. Take its last '@' before a host-like character and the
      // first ':' of the authority before that '@'; hide what lies between. The ':' scan stays inside the
      // authority, so this stays linear.
      const tokAt = lastHostAtFrom(start);
      if (tokAt > start) {
        let c2 = -1;
        const limit = Math.min(authEnd, tokAt); // the ':' must be in the authority (not in a nested URL)
        for (let p = start; p < limit; p++) if (code(s, p) === 58) { c2 = p; break; }
        if (c2 >= 0 && tokAt > c2 + 1) spans.push([c2 + 1, tokAt]);
      }
    }
    // resume right after this '://' (a later one may sit inside this authority), but never inside a hidden span
    const last = spans.length > 0 ? spans[spans.length - 1][1] : 0;
    from = Math.max(sep + 1, last);
  }
  // spans are produced in order and never overlap (each scan resumes after the previous span)
  return spans;
}

/** Spans of a token-rule regex in `s`. */
function regexSpans(s: string, re: RegExp): Span[] {
  const spans: Span[] = [];
  re.lastIndex = 0;
  for (let m = re.exec(s); m !== null; m = re.exec(s)) {
    spans.push([m.index, m.index + m[0].length]);
    if (m[0].length === 0) re.lastIndex++;
  }
  return spans;
}

// ----- password-like assignments -----

const KEYWORD = /password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret/i;
const AUTH_SCHEMES = new Set(['bearer', 'basic', 'token', 'digest']);

// Words holding "auth" that are not credentials. Longest first, so the longest one is tried first.
const SAFE_AUTH_WORDS = ['authoritative', 'authorities', 'authenticity', 'authorship', 'authoring', 'authority', 'authentic', 'authored', 'authors', 'author'];

/**
 * True when a name (a run of [A-Za-z0-9_.-]) holds a password-like keyword. `auth` anywhere counts
 * (authkey, AUTHPASS, xauth, basicAuth, auth_token, authorization) unless every occurrence is part of a
 * known harmless word (author, authority, authentic and their forms) or of a bare oauth/OAuth.
 */
function isSecretName(name: string): boolean {
  if (KEYWORD.test(name)) return true;
  const lower = name.toLowerCase();
  for (let i = lower.indexOf('auth'); i >= 0; i = lower.indexOf('auth', i + 1)) {
    if (lower.startsWith('authorization', i)) return true;
    if (i > 0 && lower[i - 1] === 'o') continue; // oauth
    if (SAFE_AUTH_WORDS.some((w) => lower.startsWith(w, i))) continue;
    return true;
  }
  return false;
}

const isQuote = (c: number) => c === 34 || c === 39 || c === 96; // " ' `

/**
 * Index of the quote closing the one at `open` (backslash escapes honoured), looked for before `limit`, or -1. With
 * `doubled`, a doubled quote is an escape too (`'it''s'` in YAML single quotes and SQL, `"a""b"` in CSV): two quotes
 * in a row do not close the value, except right after the opening quote (`''` is an empty value). Linear.
 */
function closingQuote(s: string, open: number, limit = s.length, doubled = false): number {
  const q = code(s, open);
  for (let j = open + 1; j < limit; j++) {
    const c = code(s, j);
    if (c === 92) j++; // backslash
    else if (c === q) {
      if (doubled && j > open + 1 && j + 1 < limit && code(s, j + 1) === q) j++; // a doubled quote: an escaped quote
      else return j;
    }
  }
  return -1;
}

const skipBlanks = (s: string, i: number) => {
  while (i < s.length && (code(s, i) === 32 || code(s, i) === 9)) i++;
  return i;
};

/**
 * Hides values given to password-like names. A name is a run of [A-Za-z0-9_.-] holding a keyword
 * (password, passwd, pwd, secret, token, api key, private key, access key, client secret, or auth; see
 * isSecretName); it may be quoted or a subscript (`env["DB_PASSWORD"]`). Forms covered:
 * - `name SEP value` with SEP one of `=`, `:`, `=>`, `:=`: a quoted value (single, double, backtick,
 *   or triple quotes) has its inside replaced, quotes kept; an unquoted value hides the rest of the line;
 *   an empty value or a YAML block indicator (`|`, `>`, with `-`/`+`) starts an indented block, which
 *   redact() hides line by line.
 * - Authorization with a Bearer/Basic/Token/Digest value: the scheme word stays, what follows is hidden.
 * - long CLI flags `--name value` / `--name=value`;
 * - XML on one line: an element named after a secret (`<password>`, `<db:password ...>`) has its
 *   value="..." attributes hidden, and its text up to a matching end tag, or, without one on the line, up
 *   to the next `<` or the end of the line; a quoted attribute value holding a secret name
 *   (`key="DbPassword"`, `key="Smtp:Password"`, `name="db.password"`) hides the tag's value="..."
 *   attributes and the element's text the same way. Other attributes are scanned as ordinary
 *   `name="value"` assignments. Such a start tag that ends its line (and comes from its own name or a
 *   name="..."/key="..." attribute) starts an indented block, like an empty value.
 * - A value that is only `{` or `[` (a JSON-style object or array opened at the end of the line) starts an
 *   indented block too.
 * Known limits (the secret scan is the second line there, including its connection-string rule): a quoted value
 * that continues on the next lines (e.g. Python/TOML triple quotes spanning lines), XML values split across
 * lines in code files (no block rule there), an unescaped `<` inside an attribute value (illegal in XML;
 * HTML/JSX only: the tag is taken to end there, so the tail of that value may be sent), string
 * concatenation after the first quoted part (`"abc" + "def"`), setter calls (`setPassword("x")`), keys with spaces (`"api key"`) and non-ASCII names; the names `authorisation` and
 * `authentication` (they start with a word on the safe list) and `oauthkey` (a bare oauth); and two
 * connection-string shapes (see connectionSpans): a password holding `#` after a user:password@ part (a
 * postgres URL with user `admin`, password `P@ss#2024` and host `db` is only partly hidden, since the `@`
 * after the `#` cannot be told apart from an `@` in a query such as `?y=z@w`), and a percent-encoded socket
 * host after the `@` (password `pa#ss`, host `%2Fvar%2Frun`). Also:
 * text after an unrelated end tag or after a self-closing secret tag (`<password/>x`) is not element text and is scanned as ordinary text;
 * a value whose block is not more indented than its key (`"Passwords":` then `{` at the same indent, an unindented `<setting>`/`<value>` pair);
 * only name="..."/key="..." (or the element's own name) start a block; other attributes (`id="DbPassword"`) do not;
 * Over-redacting is the safe direction: type annotations such as `token: string` lose their type too.
 * With `workflow` (a GitHub workflow or action file, see isWorkflowPath), a `name SEP value` whose value is
 * exactly one allowed expression is kept (see isAllowedWorkflowValue); every other rule is unchanged.
 */
function assignmentSpans(s: string, workflow = false): { spans: Span[]; block: boolean } {
  const spans: Span[] = [];
  const n = s.length;
  let block = false;
  const tags = tagTables(s);
  let handledTag = -1; // tags are reached in order of their '<', so one number marks those already handled
  let handledBlockable = false;
  // The text of a start tag ending at `tagEnd`: up to a matching end tag on the line, or, without one, up to the
  // next '<' or the end of the line (over-hiding is the safe side, and it also covers a '>' inside an attribute
  // value, which ends the tag early). These stretches never overlap from one tag to the next: linear. A
  // blockable tag (named after a secret, or with a secret name="..."/key="...") that ends its line may have its
  // value on the next, more-indented lines (.NET <setting ...> then <value>), so it starts a block.
  const hideElementText = (qname: string, tagEnd: number, blockable: boolean) => {
    const close = tags.closerAfter(qname, tagEnd);
    if (close > tagEnd + 1) spans.push([tagEnd + 1, close]);
    else if (close < 0) {
      const lt = s.indexOf('<', tagEnd + 1);
      const stop = lt < 0 ? n : lt;
      if (stop > tagEnd + 1) spans.push([tagEnd + 1, stop]);
      if (blockable && skipBlanks(s, tagEnd + 1) >= n) block = true;
    }
  };
  // The tag opened at `open`: hide its value="..." attributes and, for a start tag, its text (see above). A tag is
  // handled once, or twice when it first came from an attribute that cannot start a block.
  const handleTag = (open: number, blockable: boolean) => {
    if (open < handledTag || (open === handledTag && (handledBlockable || !blockable))) return;
    handledBlockable = open === handledTag ? handledBlockable || blockable : blockable;
    handledTag = open;
    const tag = tags.tagAt(open);
    spans.push(...valueAttributeSpans(s, open, tag.end));
    if (tag.closed && code(s, tag.end - 1) !== 47 /* not self-closing */) {
      let e = open + 1;
      while (e < n && (isNameChar(code(s, e)) || code(s, e) === 58)) e++;
      if (e > open + 1) hideElementText(s.slice(open + 1, e), tag.end, blockable);
    }
  };
  // The run of name characters, ':', '/' and blanks around a name (as in key="Smtp:Password"). Runs never
  // overlap and names come in order, so only the last one is kept and each character is walked once.
  // Returns null for a run already looked at (the answer would be the same).
  let runA = -1;
  let runB = -1;
  const newAttributeRun = (from: number, to: number): Span | null => {
    if (from >= runA && from < runB) return null;
    let a = from;
    while (a > 0 && isAttributeRunChar(code(s, a - 1))) a--;
    let b = to;
    while (b < n && isAttributeRunChar(code(s, b))) b++;
    runA = a;
    runB = b;
    return [a, b];
  };
  let i = 0;
  while (i < n) {
    if (!isNameChar(code(s, i))) { i++; continue; }
    const start = i;
    while (i < n && isNameChar(code(s, i))) i++;
    const name = s.slice(start, i);
    if (!isSecretName(name)) continue;
    const before = start > 0 ? code(s, start - 1) : -1;
    let p = i;

    // XML element named after a secret: <name>, <name attr="...">, <ns:name ...>. Its value="..." attributes
    // are hidden, and its text when a matching </name> follows on the line. The scan then goes on from just
    // after the name, so the tag's other attributes (password="...") and the rest of the line are still
    // checked; a `<` that is not a tag (`i <token && y`) changes nothing else. All lookups use one-pass
    // tables, so this stays linear.
    let lt = -1; // the '<' opening this element, if any
    if (before === 60 /* < */) lt = start - 1;
    else if (before === 58 /* : */) { // a namespace prefix: walk back over it (each prefix is walked once)
      let b = start - 2;
      while (b >= 0 && isNameChar(code(s, b))) b--;
      if (b >= 0 && b < start - 2 && code(s, b) === 60) lt = b;
    }
    if (lt >= 0 && (p >= n || code(s, p) === 62 || code(s, p) === 32 || code(s, p) === 9 || code(s, p) === 47)) handleTag(lt, true);
    // A quoted attribute value holding a secret name, .NET/Spring style: <add key="DbPassword" value="..."/>,
    // also key="Smtp:Password", "App/DbPassword", "Smtp Password". Hides every value="..." attribute of
    // the tag, and the element's text when a matching end tag follows (<property name="db.password">x</property>).
    const run = name.startsWith('--') ? null : newAttributeRun(start, i);
    if (run !== null) {
      const [a, b] = run;
      const q = b < n ? code(s, b) : -1;
      if ((q === 34 || q === 39) && a > 0 && code(s, a - 1) === q) {
        const eq = skipBlanksBack(s, a - 2);
        if (eq >= 0 && code(s, eq) === 61 /* = */) {
          const open = tags.enclosing(start);
          if (open >= 0) {
            const attrEnd = skipBlanksBack(s, eq - 1) + 1; // the attribute's name: name="..." and key="..." can start a block
            let attrStart = attrEnd;
            while (attrStart > open && isNameChar(code(s, attrStart - 1))) attrStart--;
            const attr = s.slice(attrStart, attrEnd).toLowerCase();
            handleTag(open, attr === 'name' || attr === 'key');
          }
        }
      }
    }
    // long CLI flag: --name value, --name=value, --name = value, --name: value, --name := value
    if (name.startsWith('--')) {
      let q = skipBlanks(s, p);
      if (s.startsWith(':=', q)) q += 2;
      else if (code(s, q) === 61 || code(s, q) === 58) q++;
      const v = skipBlanks(s, q);
      if (v === p || v >= n) continue; // nothing separates the flag from what follows, or no value
      if (isQuote(code(s, v))) {
        const close = closingQuote(s, v);
        const end = close < 0 ? n : close;
        if (end > v + 1) spans.push([v + 1, end]);
        i = close < 0 ? n : close + 1;
      } else {
        let e = v;
        while (e < n && !isSpace(code(s, e))) e++;
        spans.push([v, e]);
        i = e;
      }
      continue;
    }
    // name SEP value (the name may be quoted, or a subscript: ["name"])
    if (p < n && isQuote(code(s, p))) p++;
    if (p < n && code(s, p) === 93 /* ] */) p++;
    p = skipBlanks(s, p);
    if (s.startsWith('=>', p) || s.startsWith(':=', p)) p += 2;
    else if (p < n && (code(s, p) === 58 || code(s, p) === 61)) p++; // : =
    else continue;
    const v = skipBlanks(s, p);
    if (v >= n) { block = true; break; } // empty: the value may be on the next, indented lines
    // a JSON-style object or array opened at the end of the line ("Passwords": {): its members are on the next, indented lines
    if ((code(s, v) === 123 /* { */ || code(s, v) === 91 /* [ */) && skipBlanks(s, v + 1) >= n) { block = true; break; }
    const header = blockHeader(s, v);
    if (header !== null) { // the value is on the next, indented lines
      block = true;
      if (header.comment >= 0) spans.push([header.comment, n]);
      break;
    }
    // Workflow and action files only: a value that is exactly one plain context reference (or id-token's
    // write|read|none, or secrets' inherit) holds no secret and stays. It runs to the end of the line, so nothing
    // is left to scan; the more-indented lines after it (where a plain YAML value can go on) are hidden as a block.
    if (workflow && isAllowedWorkflowValue(name, s, v)) { block = true; break; }
    const c = code(s, v);
    // Authorization: <scheme> <credentials>
    if (name.toLowerCase().includes('authorization')) {
      const inner = isQuote(c) ? v + 1 : v;
      let w = inner;
      while (w < n && isLetter(code(s, w))) w++;
      if (AUTH_SCHEMES.has(s.slice(inner, w).toLowerCase()) && (code(s, w) === 32 || code(s, w) === 9)) {
        const credStart = skipBlanks(s, w);
        const close = isQuote(c) ? closingQuote(s, v) : -1;
        const end = close < 0 ? n : close;
        if (end > credStart) spans.push([credStart, end]);
        if (close < 0) { block = true; break; } // unquoted (or unclosed): the rest of the line, and it may go on like a plain value
        i = close + 1;
        continue;
      }
    }
    if (isQuote(c)) {
      const triple = c !== 96 && s.startsWith(s[v].repeat(3), v);
      if (triple) {
        const close = s.indexOf(s[v].repeat(3), v + 3);
        const end = close < 0 ? n : close;
        if (end > v + 3) spans.push([v + 3, end]);
        if (close < 0) { block = true; break; } // the string goes on over the next lines
        i = close + 3;
        continue;
      }
      // Two readings of the closing quote, both hidden: the first quote (a backslash escape only), and, for ' and ", the
      // first quote that is not doubled ('it''s', "a""b"). The scan goes on after the first reading, so whatever that
      // reading finds after it (another secret name) is still hidden: the doubled reading only ever adds hiding.
      const close = closingQuote(s, v);
      const far = close < 0 || c === 96 ? close : closingQuote(s, v, n, true);
      const end = far < 0 ? n : far;
      if (end > v + 1) spans.push([v + 1, end]);
      // Unclosed: a YAML double- (or single-) quoted value goes on over the next lines; hide the more-indented ones.
      if (far < 0) { block = true; break; }
      i = close + 1;
      continue;
    }
    spans.push([v, n]); // unquoted: the rest of the line
    // A plain (unquoted) YAML scalar, or an INI value, goes on over the more-indented lines after it: start a block,
    // which redact() hides line by line (config-like files only).
    block = true;
    break;
  }
  return { spans, block };
}

const skipBlanksBack = (s: string, i: number) => {
  while (i >= 0 && (code(s, i) === 32 || code(s, i) === 9)) i--;
  return i;
};

const isAttributeRunChar = (c: number) => isNameChar(c) || c === 58 /* : */ || c === 47 /* / */ || c === 32 || c === 9;

/**
 * Lookups for `<...>` tags on one line, each table built in one pass on first use:
 * - enclosing(i): the '<' of the tag around i (a '<' before i with no '>' between), or -1;
 * - tagAt(open): where that tag ends: at its '>' (closed), or, when another '<' or the end of the line
 *   comes first, there (not closed). Tags found this way never overlap, so scanning each one is linear;
 * - closerAfter(name, from): the '<' of the first `</name` (any case, then '>' or a blank) after `from`, or -1.
 */
function tagTables(s: string) {
  const n = s.length;
  let lastLt: Int32Array | null = null;
  let lastGt: Int32Array | null = null;
  let nextStop: Int32Array | null = null; // next '<' or '>' at or after i, or n
  let closers: Map<string, number[]> | null = null;
  const build = () => {
    lastLt = new Int32Array(n);
    lastGt = new Int32Array(n);
    nextStop = new Int32Array(n + 1);
    let lt = -1;
    let gt = -1;
    for (let p = 0; p < n; p++) {
      if (code(s, p) === 60) lt = p;
      if (code(s, p) === 62) gt = p;
      lastLt[p] = lt;
      lastGt[p] = gt;
    }
    nextStop[n] = n;
    for (let p = n - 1; p >= 0; p--) nextStop[p] = code(s, p) === 60 || code(s, p) === 62 ? p : nextStop[p + 1];
  };
  return {
    enclosing(i: number): number {
      if (lastLt === null || lastGt === null) build();
      const open = lastLt![i];
      return open < 0 || lastGt![i] > open ? -1 : open;
    },
    tagAt(open: number): { end: number; closed: boolean } {
      if (nextStop === null) build();
      const end = nextStop![open + 1];
      return { end, closed: end < n && code(s, end) === 62 };
    },
    closerAfter(name: string, from: number): number {
      if (closers === null) {
        closers = new Map();
        for (let k = s.indexOf('</'); k >= 0; k = s.indexOf('</', k + 2)) {
          let e = k + 2;
          while (e < n && (isNameChar(code(s, e)) || code(s, e) === 58)) e++;
          if (e === k + 2 || (e < n && code(s, e) !== 62 && code(s, e) !== 32 && code(s, e) !== 9)) continue;
          const key = s.slice(k + 2, e).toLowerCase();
          const list = closers.get(key);
          if (list === undefined) closers.set(key, [k]);
          else list.push(k);
        }
      }
      const list = closers.get(name.toLowerCase());
      if (list === undefined) return -1;
      let lo = 0;
      let hi = list.length; // first position > from (binary search)
      while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (list[mid] > from) hi = mid;
        else lo = mid + 1;
      }
      return lo < list.length ? list[lo] : -1;
    },
  };
}

/** Spans of the inside of every `value="..."` attribute in the tag s[start..end) (a quote left open ends at `end`). */
function valueAttributeSpans(s: string, start: number, end: number): Span[] {
  const spans: Span[] = [];
  const lower = s.slice(start, end).toLowerCase();
  for (let k = lower.indexOf('value'); k >= 0; k = lower.indexOf('value', k + 5)) {
    const at = start + k;
    if (!isSpace(code(s, at - 1))) continue;
    let q = skipBlanks(s, at + 5);
    if (q >= end || code(s, q) !== 61) continue;
    q = skipBlanks(s, q + 1);
    if (q >= end || (code(s, q) !== 34 && code(s, q) !== 39)) continue;
    const close = closingQuote(s, q, end);
    const stop = close < 0 ? end : close;
    if (stop > q + 1) spans.push([q + 1, stop]);
  }
  return spans;
}

/**
 * When the value after `name:` is only a YAML block header, the real value is on the next, more-indented
 * lines. A header is: optional anchors/tags (`&pw`, `!secret`, `!!str`), then optionally a block indicator
 * (`|` or `>` with up to two of an indentation digit and `+`/`-`), then optionally a `#` comment. A bare
 * comment (`name: # note`) counts too. Returns where the comment starts (-1 for none), or null when the value
 * is something else.
 */
function blockHeader(s: string, v: number): { comment: number } | null {
  const n = s.length;
  let q = v;
  let consumed = false;
  while (q < n && (code(s, q) === 38 /* & */ || code(s, q) === 33 /* ! */)) {
    let e = q + 1;
    while (e < n && !isSpace(code(s, e))) e++;
    q = skipBlanks(s, e);
    consumed = true;
  }
  if (q < n && (code(s, q) === 124 || code(s, q) === 62)) { // | >
    let e = q + 1;
    for (let k = 0; k < 2 && e < n; k++) {
      const c = code(s, e);
      if ((c >= 49 && c <= 57) || c === 43 || c === 45) e++;
      else break;
    }
    if (e < n && !isSpace(code(s, e)) && code(s, e) !== 35) return null; // e.g. "|x": a value
    q = skipBlanks(s, e);
    consumed = true;
  }
  if (q >= n) return consumed ? { comment: -1 } : null;
  if (code(s, q) === 35 /* # */) return { comment: q };
  return null;
}

// ----- private keys -----

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

// ----- workflow allow-list -----

/**
 * True for a GitHub Actions workflow (`.github/workflows/<name>.yml` or `.yaml`, directly in that folder; any
 * folder above it) or an action metadata file (`action.yml` or `action.yaml`, in any folder). Exact,
 * case-sensitive names; a path with a backslash or with an empty, `.` or `..` segment never counts, so
 * `.github/workflows/../../x.yml` is not a workflow.
 */
function isWorkflowPath(path: string): boolean {
  if (path.includes('\\')) return false;
  const parts = path.split('/');
  if (parts[0] === '') parts.shift(); // an absolute path
  if (parts.some((p) => p === '' || p === '.' || p === '..')) return false;
  const base = parts[parts.length - 1];
  if (base === 'action.yml' || base === 'action.yaml') return true;
  const yaml = (base.endsWith('.yml') && base.length > 4) || (base.endsWith('.yaml') && base.length > 5);
  return yaml && parts.length >= 3 && parts[parts.length - 2] === 'workflows' && parts[parts.length - 3] === '.github';
}

// Sticky, anchored at the value's start and at the end of the piece, so each test looks only at the value. The
// character classes around each repeat don't overlap, so a failed test costs at most the length of what it read.
// A value may be wrapped in one pair of matching quotes, and followed by blanks only (no comment, nothing else).
const WORKFLOW_REF = /(["']?)\$\{\{ *(?:secrets|vars|github|env|inputs|steps|needs|matrix)\.[A-Za-z0-9_.-]+ *\}\}\1[ \t]*$/y;
const ID_TOKEN_VALUE = /(["']?)(?:write|read|none)\1[ \t]*$/y;
const INHERIT_VALUE = /(["']?)inherit\1[ \t]*$/y;

const stickyTest = (re: RegExp, s: string, at: number) => {
  re.lastIndex = at;
  return re.test(s);
};

/**
 * True when the value starting at `v` (running to the end of `s`) is one of the harmless workflow values: exactly
 * one `${{ <context>.<name> }}` reference (context secrets, vars, github, env, inputs, steps, needs or matrix; name
 * [A-Za-z0-9_.-]+; spaces allowed inside the braces), `write`, `read` or `none` under the key `id-token`, or
 * `inherit` under the key `secrets`. Anything else on the value (a second reference, an operator, a default, a
 * function call, text before or after, a comment) makes it an ordinary value, hidden as before.
 */
function isAllowedWorkflowValue(name: string, s: string, v: number): boolean {
  if (stickyTest(WORKFLOW_REF, s, v)) return true;
  if (name === 'id-token') return stickyTest(ID_TOKEN_VALUE, s, v);
  if (name === 'secrets') return stickyTest(INHERIT_VALUE, s, v);
  return false;
}

/** One plain piece of a line (no key markers, at most 4 KB) with every rule applied, in order. */
function redactSegment(s: string, workflow = false): { text: string; block: boolean } {
  let out = s;
  for (const [, re] of TOKEN_RULES) out = replaceSpans(out, regexSpans(out, re));
  out = replaceSpans(out, jwtSpans(out));
  out = replaceSpans(out, connectionSpans(out));
  const a = assignmentSpans(out, workflow);
  return { text: replaceSpans(out, a.spans), block: a.block };
}

/** Leading blanks of a line: their length and their width in columns (a tab advances to the next multiple of 8). */
const indentOf = (line: string): { chars: number; cols: number } => {
  let i = 0;
  let cols = 0;
  for (; i < line.length; i++) {
    if (line[i] === ' ') cols++;
    else if (line[i] === '\t') cols = (Math.floor(cols / 8) + 1) * 8;
    else break;
  }
  return { chars: i, cols };
};

// Code files, where `name:` followed by an indented block is ordinary code (`class TokenStore:`), not a value.
const CODE_EXTENSIONS = new Set([
  '.py', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.go', '.rb', '.java', '.kt', '.kts', '.scala', '.cs', '.php',
  '.rs', '.swift', '.c', '.h', '.cpp', '.hpp', '.m', '.sh', '.bash', '.zsh', '.ps1', '.lua', '.pl', '.r', '.dart', '.ex', '.exs', '.clj', '.groovy',
]);
// Template and backup suffixes, removed (repeatedly) before the extension is looked at: app.py.bak is code, config.yml.example is not.
const WRAPPER_SUFFIXES = new Set(['.example', '.sample', '.dist', '.tpl', '.tmpl', '.template', '.j2', '.jinja', '.jinja2', '.bak', '.orig', '.old', '.default', '.local']);

/** True for a known code file (CODE_EXTENSIONS, after template/backup suffixes are removed); any other name may hold config. */
function isCodePath(path: string): boolean {
  let base = path.slice(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1).toLowerCase();
  for (;;) {
    const dot = base.lastIndexOf('.');
    if (dot <= 0 || !WRAPPER_SUFFIXES.has(base.slice(dot))) break;
    base = base.slice(0, dot);
  }
  const dot = base.lastIndexOf('.');
  return dot > 0 && CODE_EXTENSIONS.has(base.slice(dot));
}

/** The name of a TOML/INI section header line (`[name]`, `[[name]]`, then only blanks or a `#`/`;` comment), or null. */
function sectionName(line: string): string | null {
  const open = skipBlanks(line, 0);
  if (code(line, open) !== 91 /* [ */) return null;
  const from = code(line, open + 1) === 91 ? open + 2 : open + 1;
  const close = line.indexOf(']', from);
  if (close < 0) return null;
  let after = from === open + 2 && code(line, close + 1) === 93 ? close + 2 : close + 1;
  after = skipBlanks(line, after);
  if (after < line.length && code(line, after) !== 35 /* # */ && code(line, after) !== 59 /* ; */) return null;
  return line.slice(from, close);
}

/** True when `s` is only a plain key name (`[A-Za-z0-9_."'-]+`) with blanks around it. Hand-checked, linear. */
function isPlainKey(s: string): boolean {
  const a = skipBlanks(s, 0);
  let b = a;
  while (b < s.length && (isNameChar(code(s, b)) || code(s, b) === 34 || code(s, b) === 39)) b++;
  return b > a && skipBlanks(s, b) >= s.length;
}

/** True for a TOML/INI section name holding a secret name ([secrets], [database.password], [auth]) or "credential". */
const isSecretSection = (section: string) =>
  section.split(/[^A-Za-z0-9_.-]+/).some((part) => part !== '' && (isSecretName(part) || part.toLowerCase().includes('credential')));

/**
 * A line inside a secret section: when the text before its first `=` or `:` is a plain key name, the key is
 * kept (through the same rules as any other text) and what follows the separator is hidden; any other line
 * (no separator, a key that is not a plain name, a line over 4 KB) is hidden whole, indentation kept.
 */
function hideSectionValue(line: string): string {
  let sep = -1;
  for (let j = 0; j < line.length; j++) {
    const c = code(line, j);
    if (c === 61 || c === 58) { sep = j; break; }
  }
  if (sep < 0 || !regexSafe(line) || !isPlainKey(line.slice(0, sep))) return line.slice(0, indentOf(line).chars) + R;
  const key = redactSegment(line.slice(0, sep)).text;
  const v = skipBlanks(line, sep + 1);
  return v >= line.length ? key + line.slice(sep) : key + line.slice(sep, v) + R; // an empty value (a list on the next lines) is hidden there
}

/**
 * Replaces secret-like text with [REDACTED]. Works line by line (the `\r`s at the end of a line count as
 * part of the line end, so CRLF text behaves like LF text), with a little state:
 * - a private key block is replaced whole, up to its END line, or to the end of the text when it has none;
 * - after a password-like name with an empty value, a YAML block header, an unquoted value (a plain YAML scalar
 *   or an INI value can go on over the next lines) or an unclosed quoted value, every following line that is
 *   more indented than that line is hidden (blank lines stay blank). A TOML/INI section header among those
 *   hidden lines still starts a secret section (see below), but never ends one. This block rule is off only when
 *   `hint.path` is a known code file (.py, .js, .ts, .go, .java, … after removing template and backup
 *   suffixes such as .example, .j2, .bak), where it would hide ordinary code (`class TokenStore:`); same-line
 *   values are still hidden there. Every other file (YAML, JSON, Markdown, unknown or no extension) and a
 *   call without a path keep it. The same files also hide every value under a TOML/INI section header named
 *   after a secret (`[secrets]`, `[database.password]`), up to the next section header;
 * - a line over 4 KB is replaced whole (it is too long to scan safely), and so are the more-indented
 *   lines right after it, since it may have opened such a block (in every kind of file);
 * - in a GitHub workflow or action file (`hint.path` is `.github/workflows/<name>.yml|yaml` or
 *   `action.yml|yaml`), a key whose whole value is one plain `${{ secrets|vars|github|env|inputs|steps|needs|matrix.<name> }}`
 *   reference keeps it, and so do `id-token` with write/read/none and `secrets` with inherit. The token
 *   formats, JWTs and connection strings are replaced first, so a token on such a line is still hidden (and the
 *   value is then no longer one plain reference). The more-indented lines after a kept value are hidden. A
 *   nested `secrets:` mapping is still hidden whole (its key has an empty value).
 */
export function redact(text: string, hint?: { path?: string }): string {
  const blockRule = hint?.path === undefined || !isCodePath(hint.path);
  const workflow = hint?.path !== undefined && isWorkflowPath(hint.path);
  const out: string[] = [];
  let inKey = false;
  let blockCols = -1; // >= 0 while hiding an indented value block
  let secretSection = false; // inside a TOML/INI [section] named after a secret
  for (const raw of text.split('\n')) {
    let lineEnd = raw.length;
    while (lineEnd > 0 && raw.charCodeAt(lineEnd - 1) === 13) lineEnd--;
    const cr = raw.slice(lineEnd); // every trailing '\r', put back on output
    const line = raw.slice(0, lineEnd);
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
    // A line that only continues (or closes) a key block already shown as [REDACTED] is dropped.
    if (startedInKey && !startsBlock && plain.every((p) => p === '')) continue;
    if (blockCols >= 0) {
      if (line.trim() === '') {
        out.push(raw); // blank: nothing to hide
        continue;
      }
      const ind = indentOf(line);
      if (ind.cols > blockCols) {
        // A TOML/INI section header hidden here still starts a secret section, as below. It never ends one: the
        // header may as well be part of the hidden value, and ending a section would show lines it hides.
        if (blockRule && !startedInKey && !startsBlock && !secretSection) {
          const section = sectionName(line);
          if (section !== null) secretSection = isSecretSection(section);
        }
        out.push(line.slice(0, ind.chars) + R + cr);
        continue;
      }
      blockCols = -1;
    }
    // TOML/INI sections (block rule files only): under a [section] whose name holds a secret name ([secrets],
    // [database.password], [auth]) or "credential" ([credentials], [aws.credentials]), every value is hidden,
    // up to the next section header.
    if (blockRule && !startedInKey && !startsBlock) {
      const section = sectionName(line);
      if (section !== null) secretSection = isSecretSection(section);
      else if (secretSection && line.trim() !== '') {
        out.push(hideSectionValue(line) + cr);
        // A block the line would start outside a section (after a plain or empty value, or a line over 4 KB) starts here
        // too, so a section never shows a line that the same text outside a section would hide.
        if (!regexSafe(line) || redactSegment(line, workflow).block) blockCols = indentOf(line).cols;
        continue;
      }
    }
    if (!regexSafe(line)) {
      // Not scanned, so it may have started an indented value block: hide the more-indented lines after it too.
      out.push(LONG_LINE + cr);
      blockCols = indentOf(line).cols;
      continue;
    }
    let block = false;
    out.push(pieces.map((p) => {
      if (p === R) return R;
      const r = redactSegment(p, workflow);
      block ||= r.block;
      return r.text;
    }).join('') + cr);
    if (block && blockRule) blockCols = indentOf(line).cols;
  }
  return out.join('\n');
}

/**
 * Names of the secret-like formats found in `text` (token formats, JWTs, private keys, connection string
 * passwords), never the values. Unlike redact() it ignores `name = value` assignments, which are common
 * in ordinary code. Lines over 4 KB are not scanned, except for private key markers.
 */
export function findSecretLike(text: string): string[] {
  const found = new Set<string>();
  for (const line of text.split('\n')) {
    if (findKeyMarker(line, 'BEGIN', 0)) found.add('private-key');
    if (!regexSafe(line)) continue;
    for (const [name, re] of TOKEN_RULES) if (regexSpans(line, re).length > 0) found.add(name);
    if (jwtSpans(line).length > 0) found.add('jwt');
    if (connectionSpans(line).length > 0) found.add('connection-string-password');
  }
  return [...found];
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
      const b64 = Buffer.from(v, 'utf8').toString('base64');
      const urlSafe = b64.replaceAll('+', '-').replaceAll('/', '_');
      forms.add(v).add(b64).add(stripPadding(b64)).add(urlSafe).add(stripPadding(urlSafe));
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
 * Known limits (the secret scan is the second line of defence there): the base64 of a value embedded at a
 * non-aligned offset inside a longer base64 blob (e.g. base64 of "user:value"); a value whose own letters
 * changed case; HTML-entity or language-specific escapes (Python `\xe9`).
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

function scrubWith(text: string, forms: string[], upperForms: Set<string>, anyPercent: boolean): string {
  const spans: [number, number][] = [];
  // Spans are found twice and united: on the text as it is (forms as they are), and on a copy with every
  // %xx in upper case (same length, so the spans apply to the original) against forms normalised the same
  // way, so percent escapes match in any hex case and a value right after a literal '%' is still found.
  const hay = upperPercent(text);
  const searches: [string, Iterable<string>][] = [[text, forms]];
  if (hay !== text || anyPercent) searches.push([hay, upperForms]);
  for (const [h, fs] of searches) {
    for (const f of fs) {
      for (let i = h.indexOf(f); i >= 0; i = h.indexOf(f, i + 1)) spans.push([i, i + f.length]);
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
  // Checked on the raw name and on the name as shown (control characters removed), so a control character
  // inside a name cannot split a secret-like pattern.
  const nameHidden = (p: string) => {
    const shown = displayPath(p);
    return clean(p) !== p || clean(shown) !== shown || flagged.some((v) => p.includes(v) || shown.includes(v))
      || flaggedTokens.some((v) => tokenSpans(p, v).length > 0 || tokenSpans(shown, v).length > 0);
  };
  const show = (p: string) => (nameHidden(p) ? '(a file whose name looks like a secret)' : safeText(p, 300));
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
    const result = await readTextLimitedWithReason(abs);
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
    collected = await secretScanPass(collected, opts.secretScanner, opts.secretScanTimeoutMs ?? SECRET_SCAN_TIMEOUT_MS, known, { long: flagged, short: flaggedTokens }, notes, show);
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

  const bundle: CodeBundle = {
    files: files.map((f) => Object.freeze({ path: f.path, content: f.content })),
    bytes,
    truncated,
    secretScanChecked,
    notes: notes.all(),
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

/**
 * Ruling P30 (Task 7 review C1): both pinned scanners sniff a file's first bytes and silently skip one that looks like
 * a binary format (%PDF-, MZ, %!PS, {\rtf1, SQLite format 3, FWS, …), with a clean exit. So every scanned file, and
 * paths.txt, is written after this prefix (nothing pipegen scans starts with a magic number), and every reported line
 * is moved back by the lines it adds. test/betterleaks-live.test.ts checks the review's 11 heads on both scanners.
 */
const SCAN_PREFIX = '\n';
const PREFIX_LINES = 1;

/**
 * Task 7 re-review R1: the prefix only helps for magic numbers at byte 0. Both scanners also sniff a few formats at a
 * fixed later byte of the file as written (tar's `ustar` at 257, DICOM's `DICM` at 128, ISO 9660's `CD001` at 32769,
 * 34817 and 36865) and skip such a file with a clean exit. A file matching one is left out before the scan.
 */
const LATE_MAGIC: ReadonlyArray<readonly [number, string]> = [[257, 'ustar'], [128, 'DICM'], [32769, 'CD001'], [34817, 'CD001'], [36865, 'CD001']];

function scannersWouldSkip(written: string): boolean {
  const buf = Buffer.from(written, 'utf8');
  return LATE_MAGIC.some(([at, magic]) => buf.subarray(at, at + magic.length).toString('latin1') === magic);
}

/**
 * Ruling P34 (final review I2): a scanner can skip a file and still exit clean, and the causes keep coming (magic bytes
 * at offset 0 (P30) or later (R1), and a scan path under node_modules/ that the default path allowlist matches). So
 * pipegen ends every scanned file, and paths.txt, with one line holding a fresh random canary that data/gitleaks-bundle.toml's
 * `pipegen-canary` rule reports, and accepts a file only when that file's own canary came back reported against it,
 * exactly once. The canary goes AFTER the content, behind a blank line (so it never joins the content's last line), so
 * the reported lines of real findings don't move. Canary findings are removed before any real finding is applied.
 */
const CANARY_RULE = 'pipegen-canary';
const newCanary = () => `${CANARY_RULE}-${randomBytes(16).toString('hex')}`;
/** A file as the scanner sees it: the prefix, the content, a blank line, the canary on its own line. */
const asScanned = (content: string, canary: string) => `${SCAN_PREFIX}${content}${content === '' || content.endsWith('\n') ? '' : '\n'}\n${canary}\n`;

/** Maps a finding's lines from the file as written to its content; a finding on the prefix can't be placed. */
function unprefixed(f: Finding): Finding {
  if (f.startLine === undefined || f.endLine === undefined) return { ...f, startLine: undefined, endLine: undefined };
  if (f.startLine <= PREFIX_LINES) return { ...f, startLine: undefined, endLine: undefined, onPrefix: true };
  return { ...f, startLine: f.startLine - PREFIX_LINES, endLine: f.endLine - PREFIX_LINES };
}

/**
 * Review M1: while the scan runs, its temp folder (the redacted copies and the raw report) is removed if the process is
 * stopped by SIGINT or SIGTERM, or exits, before `finally` can run; the scanner is killed first. After cleaning up, a
 * signal is raised again when no other handler is there, so the process still stops by it. `release` removes the hooks.
 */
function guardTempDir(dir: string): { child: ChildProcess | null; release: () => void } {
  const guard = { child: null as ChildProcess | null, release: () => {} };
  const clean = () => {
    try {
      guard.child?.kill('SIGKILL');
    } catch { /* already gone */ }
    rmSync(dir, { recursive: true, force: true });
  };
  const onSignal = (sig: NodeJS.Signals) => {
    try {
      clean();
    } finally {
      guard.release();
      if (process.listenerCount(sig) === 0) process.kill(process.pid, sig);
    }
  };
  const onExit = () => {
    try {
      clean();
    } catch { /* best effort while exiting */ }
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  process.once('exit', onExit);
  guard.release = () => {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
    process.removeListener('exit', onExit);
  };
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

const isWordChar = (c: number) => isLetter(c) || isDigit(c) || c === 95; // [A-Za-z0-9_]

/** Spans of `v` in `text` where it stands as a whole token (no [A-Za-z0-9_] right before or after). Linear. */
function tokenSpans(text: string, v: string): Span[] {
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
const MIN_GLOBAL_SECRET = 6;

/**
 * Scans the (already cleaned) files with the secret scanner and returns what may be sent. Every finding is replaced
 * where it was reported; then every secret the scanner found (and the known values) is removed from ALL files
 * in all its forms, so a secret reported on one line cannot survive on another line or in another file.
 * The bundle paths are scanned too (paths.txt, one per line, as bundleText shows them); a file whose path
 * the scanner flags, or whose path holds a found secret, is left out. Found secrets are added to `flagged`.
 * Ruling P34: every scanned file and paths.txt carry a canary. A file whose canary did not come back is left out; a
 * scan that does not confirm paths.txt, or confirms none of the files, throws SecretScanError (it may have read nothing).
 */
async function secretScanPass(files: FileEntry[], scanner: SecretScanner, timeoutMs: number, known: string[], flagged: { long: string[]; short: string[] }, notes: Notes, show: (p: string) => string): Promise<FileEntry[]> {
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
  const sniffed = canaried.filter((f) => scannersWouldSkip(f.written));
  notes.addPaths('Left out because the secret scanners skip files shaped like this (a binary-format marker at a fixed byte):', sniffed.map((f) => f.path), show);
  const kept = canaried.filter((f) => !sniffed.includes(f));
  const scanned: FileEntry[] = kept.map((f) => ({ path: f.path, content: f.content }));
  const shownPaths = scanned.map((f) => displayPath(f.path));
  const made = await mkdtemp(join(tmpdir(), 'pipegen-secret-scan-'));
  const guard = guardTempDir(made);
  try {
    const tmp = await realpath(made);
    await chmod(tmp, 0o700);
    // Neutral names: no repo file name (.gitleaksignore, .gitleaks.toml, allowlisted paths) reaches the scanner.
    const names = scanned.map((_, i) => `f${String(i + 1).padStart(6, '0')}.txt`);
    // P34 belt: the default path allowlist matches the absolute path, so a temp folder under node_modules/ (or another
    // folder it lists) would hide every file. Refused before anything is written; the canaries below are the guarantee.
    if ([...names, PATHS_FILE].some((n) => skippedByDefaultPaths(join(tmp, n)))) {
      throw new SecretScanError(`The secret scan's temp folder ${safeText(tmp)} is under a folder the ${name} scanner skips (such as node_modules); set TMPDIR to another folder and run again. Nothing was sent.`);
    }
    for (let i = 0; i < scanned.length; i++) await writeFile(join(tmp, names[i]), kept[i].written, { flag: 'wx', mode: 0o600 });
    const pathsCanary = newCanary();
    const pathsText = asScanned(neutralizeAllow(shownPaths.join('\n')), pathsCanary);
    // R1 for the paths too: the scanners would skip paths.txt, and so never check the file names. Fail closed.
    if (scannersWouldSkip(pathsText)) throw new SecretScanError(`The bundle's file list has a binary-format marker at a byte the ${name} scanner sniffs, so it would not be scanned; nothing was sent.`);
    await writeFile(join(tmp, PATHS_FILE), pathsText, { flag: 'wx', mode: 0o600 });
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
    // P34: take the canary findings out. One counts only when its token is the one written to the file it is reported
    // against; a canary-rule finding with any other text (canary-shaped text in a repo file) is not a secret, and dropped.
    const canaryOf = new Map<string, string>([...names.map((n, i): [string, string] => [n, kept[i].canary]), [PATHS_FILE, pathsCanary]]);
    const confirmed = new Map<string, number>();
    const findings: Finding[] = [];
    for (const f of reported) {
      if (f.rule !== CANARY_RULE) {
        findings.push(f);
        continue;
      }
      const rel = relOf(f.file);
      if (rel !== undefined && canaryOf.has(rel) && f.secret === canaryOf.get(rel)) confirmed.set(rel, (confirmed.get(rel) ?? 0) + 1);
    }
    const read = (n: string) => confirmed.get(n) === 1;
    if (!read(PATHS_FILE)) throw new SecretScanError(`${name} did not confirm it read the bundle's file list, so the file names may not have been checked; nothing was sent.`);
    const unread = new Set(names.flatMap((n, i) => (read(n) ? [] : [i])));
    if (scanned.length > 0 && unread.size === scanned.length) throw new SecretScanError(`${name} did not confirm it read the bundle's files, so they may not have been checked; nothing was sent.`);

    const index = new Map(names.map((n, i) => [n, i]));
    const perFile = new Map<number, Finding[]>();
    const drop = new Set<number>();
    const unplaced = new Set<number>();
    const badPath = new Set<number>();
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
      const rel = relOf(f.file);
      if (rel === PATHS_FILE) {
        // A finding in a file name: leave out the files on the reported lines, and any whose path holds the text.
        const { startLine: s, endLine: e } = f;
        let hit = false;
        if (s !== undefined && e !== undefined && s <= e && e <= shownPaths.length) {
          for (let k = s - 1; k < e; k++) badPath.add(k);
          hit = true;
        }
        shownPaths.forEach((p, k) => {
          if (texts.some((t) => p.includes(t))) {
            badPath.add(k);
            hit = true;
          }
        });
        if (!hit) shownPaths.forEach((_, k) => badPath.add(k)); // cannot tell which name: leave them all out
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

    const pathsOf = (set: Set<number>) => [...set].sort((a, b) => a - b).map((i) => scanned[i].path);
    notes.add(`${name} checked the bundle: ${plural(redacted, 'finding', 'findings')} redacted.`);
    notes.addPaths(`Left out because ${name} did not confirm it read them:`, pathsOf(unread), show);
    notes.addPaths(`Left out because ${name} found something pipegen could not locate to redact:`, pathsOf(drop), show);
    notes.addPaths('Left out because a found secret was still in them after redaction:', pathsOf(leftover), show);
    if (shortHit.size > 0) notes.add(`Left out ${plural(shortHit.size, 'file', 'files')} where ${name} found a short value (under ${MIN_GLOBAL_SECRET} characters); elsewhere it is removed only where it stands as a whole word.`);
    if (badPath.size > 0) notes.add(`Left out ${plural(badPath.size, 'file whose path', 'files whose paths')} ${name} flagged as secret-like (names not shown).`);
    if (strays > 0) {
      notes.add(`Ignored ${plural(strays, `${name} finding`, `${name} findings`)} for a file outside the scanned folder.`);
      notes.addPaths(`Left out because a ${name} finding outside the scanned folder may relate to them:`, pathsOf(unplaced), show);
    }
    return scanned.filter((_, i) => !unread.has(i) && !drop.has(i) && !unplaced.has(i) && !leftover.has(i) && !badPath.has(i) && !shortHit.has(i));
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
  return neutralizeTags(safeText(path, 1000));
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
