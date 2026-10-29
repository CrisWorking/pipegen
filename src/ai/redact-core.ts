// Plan C Task C1b fix round 1 (review I3): the pure redaction core. Patterns, maskers and the secret-shaped file-name logic
// of redact.ts (P39/P40/P45/P48) live here with NO imports at all: no child_process, no picomatch, no limits.js (fast-glob,
// yaml), nothing from node: or npm. The gate bundle (gate/dist, where C6 refuses child_process) imports this file, and
// redact.ts re-exports it, so one tested list serves the AI bundler and the gate. test/module-graph.test.ts keeps it a leaf.

/** What the maskers put in place of a secret. */
export const R = '[REDACTED]';
/** What redact() puts in place of a line too long to scan (over 4 KB): the whole line is hidden. */
export const LONG_LINE = '[REDACTED: line too long]';
/** A copy of limits.ts READ_LIMITS.maxRegexLineBytes (a test keeps the two equal). */
export const MAX_REGEX_LINE_BYTES = 4096;

/** True when a repo-derived string is short enough (4 KB) to run a regex on. A copy of limits.ts regexSafe (no import). */
export function regexSafe(s: string): boolean {
  return Buffer.byteLength(s) <= MAX_REGEX_LINE_BYTES;
}

// ---------- redaction ----------
//
// Everything here runs in linear time on lines of at most 4 KB: the token formats are regexes with a
// fixed prefix, and the shapes that need context (JWTs, connection strings, password-like assignments)
// are hand-written scans that look at each character a bounded number of times.

// Token formats, each replaced whole. Names are what findSecretLike reports (never the value).
const TOKEN_RULES: readonly (readonly [string, RegExp])[] = [
  // AKIA long-term keys, ASIA temporary (STS) keys, and the other documented access-key id prefixes; the body is the old [0-9A-Z] class (a superset of base32)
  ['aws-access-key', /(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[0-9A-Z]{16}/g],
  ['github-token', /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ['github-fine-grained-token', /github_pat_[A-Za-z0-9_]{20,}/g],
  ['slack-token', /xox[abpr]-[A-Za-z0-9-]+/g],
  ['stripe-key', /sk_(?:live|test)_[A-Za-z0-9]{10,}/g],
  ['sk-api-key', /sk-[A-Za-z0-9_-]{20,}/g],
  ['slack-webhook', /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]+/g],
  ['google-api-key', /AIza[0-9A-Za-z_-]{35}/g],
  ['npm-token', /npm_[A-Za-z0-9]{36}/g],
];

export type Span = [number, number];

/** `s` with each span (sorted, not overlapping) replaced by [REDACTED]. */
export function replaceSpans(s: string, spans: Span[]): string {
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

export const code = (s: string, i: number) => s.charCodeAt(i);
export const isLetter = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isUpper = (c: number) => c >= 65 && c <= 90;
const isLower = (c: number) => c >= 97 && c <= 122;
export const isDigit = (c: number) => c >= 48 && c <= 57;
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


// ---------- secret-shaped names (P48) ----------

/** P48: a decoded piece of a name is scanned when it has at least this many printable characters in a row. */
const MIN_DECODED_PIECE = 8;

/** Printable ASCII runs of MIN_DECODED_PIECE or more characters in decoded bytes (read as latin1, one char per byte). */
function readablePieces(bytes: Buffer): string[] {
  return bytes.toString('latin1').match(new RegExp(`[\\x20-\\x7e]{${MIN_DECODED_PIECE},}`, 'g')) ?? [];
}

/**
 * P48: pipegen's own decoding of a name, so it doesn't depend on where the scanners start a token. Every maximal run of
 * base64 or base64url characters is decoded from each of its first four characters (the four alignments: a secret that
 * starts anywhere in the run is decoded whole in one of them), every run of hex digits from each of its first two, and
 * the name once with percent-escapes decoded. The readable pieces are returned (deduplicated, in order).
 */
export function decodedNamePieces(name: string): string[] {
  const out = new Set<string>();
  for (const run of name.match(/[A-Za-z0-9+/_=-]{12,}/g) ?? []) {
    for (let k = 0; k < 4 && k < run.length; k++) for (const p of readablePieces(Buffer.from(run.slice(k), 'base64'))) out.add(p);
  }
  for (const run of name.match(/[0-9a-fA-F]{16,}/g) ?? []) {
    for (let k = 0; k < 2; k++) {
      const even = run.slice(k, k + Math.floor((run.length - k) / 2) * 2);
      for (const p of readablePieces(Buffer.from(even, 'hex'))) out.add(p);
    }
  }
  if (/%[0-9a-fA-F]{2}/.test(name)) {
    const decoded = name.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return Buffer.from(m.replaceAll('%', ''), 'hex').toString('latin1');
      }
    });
    if (decoded !== name) out.add(decoded);
  }
  for (const p of [...out]) if (name.includes(p)) out.delete(p); // already on the name's own line
  return [...out];
}

/** Shannon entropy of a string, in bits per character. */
function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * P48 belt: the part of a name that looks like an encoded secret whatever the scanner says: in one path segment, a run
 * of 20 or more base64 characters (`+`, `=`, letters, digits) holding both letters and digits, with a Shannon entropy of
 * at least 3.5 bits per character (3.0 when the run is only hex digits). Measured on 36,862 real file names (express,
 * flask, trpc, left-pad, next.js): 11 match (0.03%; none in express, flask, trpc or left-pad; in next.js 7 hashed font
 * and lockfile names and 4 `classPrivateField{Get,Set}2.js` babel helpers), and 92% of random base64, base64url and hex
 * secrets of 15 to 45 bytes do. Returns the matching runs.
 */
export function highEntropyRuns(name: string): string[] {
  const hits: string[] = [];
  for (const seg of name.split('/')) {
    for (const run of seg.match(/[A-Za-z0-9+=]{20,}/g) ?? []) {
      if (!/\d/.test(run) || !/[A-Za-z]/.test(run)) continue;
      if (entropy(run) >= (/^[0-9a-fA-F]+$/.test(run) ? 3.0 : 3.5)) hits.push(run);
    }
  }
  return hits;
}

// ---------- for the gate (C1b fix round 1) ----------

const RUN = /[A-Za-z0-9+=]{20,}/g;

/**
 * The text of a tool's message as it may be written to an artifact: redact() (token formats, JWTs, private keys,
 * connection-string passwords, password-like assignments), then every run of 20 or more base64 characters that the
 * entropy belt (highEntropyRuns) matches, per token. A fingerprint over the masked text stays stable, because masking is
 * a pure function of the text.
 */
export function maskText(text: string): string {
  return redact(text).replace(RUN, (run) => (highEntropyRuns(run).length > 0 ? R : run));
}

/** The longest name secretShapedName reads; a longer one counts as secret-shaped (failing closed, as P48 does for a name it cannot scan in full). */
export const MAX_NAME_CHARS = 4096;

const looksSecret = (text: string): boolean => redact(text) !== text || findSecretLike(text).length > 0 || highEntropyRuns(text).length > 0;

/**
 * True when a file name or path looks like a secret (P39/P40/P45/P48, scanner-free): the name (a token
 * anywhere in it is inside the whole name; the entropy belt reads each segment itself) and pipegen's own decodings of it (base64 at four alignments, hex, percent-escapes)
 * hold a token shape, a JWT, a connection-string password, a password-like assignment or a high-entropy run.
 */
export function secretShapedName(name: string): boolean {
  if (name.length > MAX_NAME_CHARS) return true;
  if (looksSecret(name)) return true;
  return decodedNamePieces(name).some(looksSecret);
}
