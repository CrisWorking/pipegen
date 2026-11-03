// Plan E E0a (ruling B1): the one form in which a CI log reaches the AI. Global constraint: "Logs reach the AI only as a code-extracted
// error excerpt, redacted (Plan A), scrubbed of every value the user typed, inside a block marked as untrusted." The untrusted block is the
// fix loop's (E7); classifyFailure (E7) reads the raw log locally, and only this excerpt leaves the machine (S15).
//
// errorExcerpt runs the ruling's seven steps in order:
//   1. the GitHub timestamp prefix (and a leading BOM) is taken off each line;
//   2. whole ANSI CSI and OSC sequences are removed;
//   3. a line that still holds ESC or a C1 control is dropped (with a vault, fullScrub would show the whole excerpt as one [REDACTED]),
//      and so is what may be a private key body after it: up to the next END marker when any reading of the dropped line (ruling
//      E0a-R1: escape sequences removed whole, ESC and C1 removed, every non-printable removed) says PRIVATE or KEY, else while the
//      lines look like armor (base64, armor headers, blank lines); a line step 2 changed starts the same hide when one of its
//      readings says PRIVATE or KEY, but stays shown. A dropped line stays in place, as all its readings and tagged,
//      through the whole-log scrub and redact below, going only after them, so redact still sees a BEGIN line or a `password:` line
//      that held an escape (security scan findings);
//   4. the error lines and EXCERPT_CONTEXT_LINES around each are picked, at most EXCERPT_MAX_LINES lines and EXCERPT_MAX_BYTES;
//   5. Plan A redact;
//   6. the composed scrubber (the caller's: vault.scrubber() then knownValueScrubber over the placeholders and the throwaway scratch
//      keys; no values list exists), through scrubForDisplay's fullScrub with finish = identity, per line and then on the whole text;
//   7. the secret scan (betterleaks, or gitleaks with the switch) over the excerpt: a finding drops its line, and every line that holds
//      a found text; a finding that can't be placed withholds the excerpt.
// Scrub before cutting (D5 review I1): step 4 never cuts inside a line (a line is shown whole or not at all; a line over 4 KB is
// Plan A's LONG_LINE), and before it the scrubber and redact also run over the whole cleaned log, so a value split across lines at
// the edge of a picked window, or a private key whose BEGIN line is outside it, is gone before any line is picked.
// The secret scan runs a process, so errorExcerpt is async and takes the pinned scanner: the ruling's `(logs, scrub): string` can't
// run step 7.
import { createHash, randomBytes } from 'node:crypto';
import { MAX_REGEX_LINE_BYTES } from '../ai/redact-core.js';
import { redact, secretScanText, type SecretScanner } from '../ai/redact.js';
import { LATE_MAGIC, SCAN_PREFIX, scannersWouldSkip } from '../ai/scan-staging.js';
import { holdsEscape, scrubForDisplay, stripChars } from '../util/known-values.js';

/** Lines shown before and after each error line. */
export const EXCERPT_CONTEXT_LINES = 5;
/** The most lines an excerpt has (the "not shown" markers included). */
export const EXCERPT_MAX_LINES = 150;
/** The most UTF-8 bytes an excerpt has. */
export const EXCERPT_MAX_BYTES = 64 * 1024;
/** With no error line, the end of the log: this many lines at most. */
export const EXCERPT_TAIL_LINES = 30;
/** What errorExcerpt returns when the secret scan found something it could not place on a line of the excerpt. */
export const EXCERPT_WITHHELD = '[log excerpt withheld: the secret scan found something it could not place on a line]';
/**
 * Only the last this many UTF-16 units of a log are read (cut at a line start). The first HEAD_GUARD_LINES lines after such a cut are
 * never shown: a value split across the cut has its other part outside what the scrubber saw. A private key block is not left to that
 * count (security scan finding 2): when the cut-off head ends inside a key block, the tail is hidden up to the block's END line (with no
 * END in the tail, up to the first line that isn't armor-shaped), and armor-shaped lines at the start of the tail are hidden anyway.
 */
export const MAX_LOG_CHARS = 4 * 1024 * 1024;
const HEAD_GUARD_LINES = 64;
/** Windows tried at most in step 4 (a log of nothing but error lines stays linear). */
const MAX_WINDOWS_TRIED = 10_000;

// GitHub's per-line prefix: an ISO 8601 UTC time with up to 9 fraction digits, then one space.
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z(?: |$)/;
// Whole sequences only. OSC: ESC ] body, ended by BEL or ESC \ (an unterminated one stays, and step 3 drops its line).
// CSI: ESC [ parameter bytes, intermediate bytes, final byte. The classes are disjoint, so each scan is linear.
const OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g;
const CSI = /\u001b\[[0-?]*[ -/]*[@-~]/g;
// An error line: GitHub's error annotation, npm's, the test runners' fail marks, and the usual words (case-insensitive).
const ERROR_LINE = /##\[error\]|npm err!|[✕✖×]|error|fail|fatal|panic|exception|traceback|\b(?:denied|refused|cannot|unable|timed? ?out|not found|no such file|expected)\b|\bexit(?:ed)? (?:with )?(?:code|status) [1-9]/i;

const identity = (s: string) => s;
const bytesOf = (s: string) => Buffer.byteLength(s, 'utf8');
const marker = (n: number) => `[… ${n} line${n === 1 ? '' : 's'} not shown …]`;
/** The largest a marker line can be (it counts toward the byte cap before the real one is known). */
const MARKER_BYTES = bytesOf(marker(Number.MAX_SAFE_INTEGER)) + 1;

/** Steps 1-2 on one line, whether step 3 drops it (it still holds ESC or a C1 control), and the line before step 2 when step 2 changed it. */
function cleanLine(raw: string): { line: string; drop: boolean; before: string | null } {
  let line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
  if (line.startsWith('\ufeff')) line = line.slice(1);
  line = line.replace(TIMESTAMP, '');
  const before = line;
  if (line.includes('\u001b')) line = line.replace(OSC, '').replace(CSI, '');
  return { line, drop: holdsEscape(line), before: line === before ? null : before };
}

// Private key markers as Plan A redact finds them (redact-core.ts findKeyMarker: `-----BEGIN [A-Z ]*PRIVATE KEY-----`, or `PRIVATE KEY
// BLOCK`, or END). A copy: that function is not exported, and redact-core.ts is in the gate bundle, so it is left untouched.
const KEY_TAILS = ['PRIVATE KEY', 'PRIVATE KEY BLOCK'];
/** The start of the last `kind` key marker in `line`, or -1. Linear: each `-----BEGIN ` is looked at once. */
function lastKeyMarker(line: string, kind: 'BEGIN' | 'END'): number {
  const head = `-----${kind} `;
  let last = -1;
  for (let i = line.indexOf(head); i >= 0; i = line.indexOf(head, i + 1)) {
    let j = i + head.length;
    while (j < line.length && (line[j] === ' ' || (line[j] as string >= 'A' && line[j] as string <= 'Z'))) j++;
    if (KEY_TAILS.some((t) => line.slice(i + head.length, j).endsWith(t)) && line.startsWith('-----', j)) last = i;
  }
  return last;
}

/** Whether `text` ends inside a private key block: its last key marker is a BEGIN. Each line is looked at once, from the end. */
function endsInsideKey(text: string): boolean {
  for (let to = text.length; to > 0;) {
    const k = text.lastIndexOf('PRIVATE KEY', to - 1);
    if (k < 0) return false;
    const from = text.lastIndexOf('\n', k) + 1;
    const end = text.indexOf('\n', k);
    const line = text.slice(from, end < 0 ? text.length : end);
    const begin = lastKeyMarker(line, 'BEGIN');
    const close = lastKeyMarker(line, 'END');
    if (begin >= 0 || close >= 0) return begin > close;
    to = from;
  }
  return false;
}

// A line of a private key body as PEM or PGP armor writes it: base64 (64 columns; the last line shorter, maybe with padding), one of its
// headers, or a blank line (between the headers and the body, or anywhere in a pasted key). Anchored, one class per run: linear.
const ARMOR = /^[ \t]*(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9+/]+={1,2}|(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|MessageID):.*|)[ \t]*$/;
const isArmor = (line: string) => bytesOf(line) > MAX_REGEX_LINE_BYTES || ARMOR.test(line) || lastKeyMarker(line, 'END') >= 0;

// A dropped line's escape sequences, removed whole (follow-up scan finding): OSC (ESC ] or C1 OSC, ended by BEL, ST or ESC \), CSI (ESC [
// or C1 CSI), any other ESC sequence (intermediates and one final byte), then any ESC or C1 left. Ruling E0a-R1 (b): the OSC body
// excludes both introducers, so an unterminated run of them is read once (linear), and lines over MAX_REGEX_LINE_BYTES skip this reading.
const DROPPED_OSC = /(?:\u001b\]|\u009d)[^\u0007\u001b\u009c\u009d]*(?:\u0007|\u009c|\u001b\\)/g;
const DROPPED_CSI = /(?:\u001b\[|\u009b)[\u0030-\u003f]*[\u0020-\u002f]*[\u0040-\u007e]?/g;
const DROPPED_ESC = /\u001b[\u0020-\u002f]*[\u0030-\u007e]?/g;
const ESC_C1 = /[\u001b\u0080-\u009f]/g;
const withoutSequences = (line: string) => line.replace(DROPPED_OSC, '').replace(DROPPED_CSI, '').replace(DROPPED_ESC, '').replace(ESC_C1, '');
/**
 * Ruling E0a-R1 (a): the readings of a dropped line, since no one way of taking escapes out is right for every line (a sequence's final
 * byte can be a letter of the marker): whole sequences removed (lines within MAX_REGEX_LINE_BYTES only), only the ESC and C1 characters
 * removed, and every non-printable character removed (stripChars: controls, bidi, invisibles). Duplicates once.
 */
function readings(line: string): string[] {
  const chars = line.replace(ESC_C1, '');
  const all = [...(bytesOf(line) <= MAX_REGEX_LINE_BYTES ? [withoutSequences(line)] : []), chars, stripChars(line)];
  return [...new Set(all)];
}
/** Ruling E0a-R1 (a): a word of a key name in a reading, either one, any case. */
const NAMES_KEY = /private|key/i;

/**
 * Step 4: the error windows (or the end of the log), in line order, with a marker for every gap between two of them. A window that
 * does not fit in what is left shrinks around its centre (the error line; the last line for the end of the log) until it does.
 */
function pick(lines: string[]): string[] {
  const n = lines.length;
  if (n === 0) return [];
  const errors: number[] = [];
  for (let i = 0; i < n; i++) if (bytesOf(lines[i] as string) <= MAX_REGEX_LINE_BYTES && ERROR_LINE.test(lines[i] as string)) errors.push(i);
  // each window as its candidates, widest first: the first error (often the cause), then the last ones going back (nearest the failure)
  const centres = errors.length === 0 ? [] : [errors[0] as number, ...errors.slice(1).reverse()];
  const candidates = (k: number): [number, number][] => {
    if (errors.length === 0) return Array.from({ length: Math.min(n, EXCERPT_TAIL_LINES) }, (_, t) => [n - Math.min(n, EXCERPT_TAIL_LINES) + t, n - 1]);
    const e = centres[k] as number;
    return Array.from({ length: EXCERPT_CONTEXT_LINES + 1 }, (_, t) => [Math.max(0, e - EXCERPT_CONTEXT_LINES + t), Math.min(n - 1, e + EXCERPT_CONTEXT_LINES - t)]);
  };
  const windows = errors.length === 0 ? 1 : Math.min(centres.length, MAX_WINDOWS_TRIED);
  let runs: [number, number][] = [];
  let count = 0;
  let bytes = 0;
  const chosen = new Uint8Array(n);
  for (let k = 0; k < windows && count < EXCERPT_MAX_LINES; k++) {
    for (const [a, b] of candidates(k)) {
      let addLines = 0;
      let addBytes = 0;
      for (let i = a; i <= b; i++) {
        if (chosen[i] === 1) continue;
        addLines++;
        addBytes += bytesOf(lines[i] as string) + 1;
      }
      if (addLines === 0) break;
      const merged = mergeRun(runs, [a, b]);
      const markers = merged.length - 1;
      if (count + addLines + markers > EXCERPT_MAX_LINES || bytes + addBytes + markers * MARKER_BYTES > EXCERPT_MAX_BYTES) continue;
      for (let i = a; i <= b; i++) chosen[i] = 1;
      runs = merged;
      count += addLines;
      bytes += addBytes;
      break;
    }
  }
  const out: string[] = [];
  runs.forEach(([a, b], k) => {
    if (k > 0) out.push(marker(a - (runs[k - 1] as [number, number])[1] - 1));
    for (let i = a; i <= b; i++) out.push(lines[i] as string);
  });
  return out;
}

/** `runs` (sorted, apart) with [a, b] added: touching or overlapping runs become one. */
function mergeRun(runs: [number, number][], add: [number, number]): [number, number][] {
  const out: [number, number][] = [];
  for (const r of [...runs, add].sort((x, y) => x[0] - y[0])) {
    const last = out[out.length - 1];
    if (last !== undefined && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push([r[0], r[1]]);
  }
  return out;
}

/** Whole lines dropped from the start until the excerpt is within EXCERPT_MAX_LINES and EXCERPT_MAX_BYTES (nothing is cut). */
function capLines(lines: string[]): string[] {
  let bytes = lines.reduce((s, l) => s + bytesOf(l) + 1, 0) - (lines.length > 0 ? 1 : 0);
  let from = 0;
  while (from < lines.length && (lines.length - from > EXCERPT_MAX_LINES || bytes > EXCERPT_MAX_BYTES)) {
    bytes -= bytesOf(lines[from] as string) + 1;
    from++;
  }
  return lines.slice(from);
}

/** Step 7's guard: the line that holds a format marker the scanners sniff at a fixed byte (scannersWouldSkip), or -1. */
function lineAtMagic(lines: string[]): number {
  const buf = Buffer.from(SCAN_PREFIX + lines.join('\n'), 'utf8');
  for (const [at, magic] of LATE_MAGIC) {
    if (buf.subarray(at, at + magic.length).toString('latin1') !== magic) continue;
    let line = -1; // the prefix line holds no byte of the text
    for (let i = buf.indexOf(0x0a); i >= 0 && i < at; i = buf.indexOf(0x0a, i + 1)) line++;
    return line;
  }
  return -1;
}

/**
 * The excerpt of a failing CI log that the fix loop may send to the AI (ruling B1; the steps are in this file's header). `scrub` is the
 * composed known-value scrubber. Throws SecretScanError when the secret scan can't run or does not confirm it read the excerpt: then
 * nothing may be sent.
 */
export async function errorExcerpt(logs: string, scrub: (text: string) => string, scanner: SecretScanner, opts: { timeoutMs?: number } = {}): Promise<string> {
  let text = String(logs);
  let guard = 0;
  let cut = false;
  let insideKey = false;
  if (text.length > MAX_LOG_CHARS) {
    const from = text.indexOf('\n', text.length - MAX_LOG_CHARS);
    insideKey = endsInsideKey(from < 0 ? text : text.slice(0, from));
    text = from < 0 ? '' : text.slice(from + 1);
    guard = HEAD_GUARD_LINES;
    cut = true;
  }
  // steps 1-3. A dropped line is kept in place for now, with its escape sequences removed whole and a random tag after its indentation
  // and at its end (so redact's indent and key rules still see it, and every piece of it redact keeps carries a tag); it goes after the
  // whole-log pass. Lines that may be a private key body are hidden the same way:
  // - up to the next END marker line, after a cut inside a key block or after a dropped line that names a private key (fail closed: its
  //   marker may be unreadable);
  // - with no END marker ahead, or after any other dropped line, while the lines look like armor (base64, armor headers, blank lines).
  const tag = `\u0000pipegen-dropped-${randomBytes(8).toString('hex')}\u0000`;
  // a dropped line's copy for redact holds all its readings, one after another (redact finds a marker in whichever kept it whole)
  const lines0 = text.split('\n').map((raw) => {
    const c = cleanLine(raw);
    // a line step 2 changed is shown as step 2 left it, but its readings still decide the key hide (a CSI's final byte can be a letter
    // of the marker: `PRIVATE ESC[1;3KEY` reads as `PRIVATE EY` once the sequence is gone)
    if (!c.drop) {
      const rs = c.before === null ? [c.line] : [c.line, ...readings(c.before)];
      return { line: c.line, drop: false, ends: rs.some((r) => lastKeyMarker(r, 'END') >= 0), namesKey: c.before !== null && rs.some((r) => NAMES_KEY.test(r)) };
    }
    const rs = readings(c.line);
    return { line: rs.join(' '), drop: true, ends: rs.some((r) => lastKeyMarker(r, 'END') >= 0), namesKey: rs.some((r) => NAMES_KEY.test(r)) };
  });
  const nextEnd = new Int32Array(lines0.length);
  for (let i = lines0.length - 1, next = -1; i >= 0; i--) {
    if ((lines0[i] as { ends: boolean }).ends) next = i;
    nextEnd[i] = next;
  }
  let hideTo = -1;
  let armor = false;
  const startKeyHide = (from: number) => {
    const end = from < lines0.length ? (nextEnd[from] as number) : -1;
    if (end >= 0) hideTo = Math.max(hideTo, end);
    else armor = true;
  };
  if (cut) {
    if (insideKey) startKeyHide(0);
    else armor = true;
  }
  const cleaned = lines0.map(({ line, drop, ends, namesKey }, i) => {
    let hidden = drop || i <= hideTo;
    if (namesKey && !ends && i >= hideTo) startKeyHide(i + 1);
    else if (drop && i >= hideTo) armor = true;
    else if (armor && i > hideTo) {
      if (isArmor(line)) hidden = true;
      if (!isArmor(line) || lastKeyMarker(line, 'END') >= 0) armor = false;
    }
    if (!hidden) return line;
    const indent = /^[ \t]*/.exec(line)?.[0] ?? '';
    return `${indent}${tag}${line.slice(indent.length)}${tag}`;
  });
  // scrub before cutting: the whole cleaned log, before any line is picked (merged lines only lower the count, so the guard still covers);
  // then every line that still carries the tag goes
  const whole = redact(scrub(cleaned.join('\n'))).split('\n').slice(guard).filter((l) => !l.includes(tag));
  // step 4
  const picked = pick(whole);
  if (picked.length === 0) return '';
  // step 5
  const redacted = redact(picked.join('\n'));
  // step 6: per line first, so a hit in one line's display or stripped form doesn't flatten the others; then the whole text
  const check = { scrubber: () => scrub };
  const perLine = redacted.split('\n').map((l) => scrubForDisplay(check, l, identity)).join('\n');
  let lines = capLines(scrubForDisplay(check, perLine, identity).split('\n'));
  // step 7
  for (let k = 0; k < LATE_MAGIC.length && scannersWouldSkip(SCAN_PREFIX + lines.join('\n')); k++) {
    const at = lineAtMagic(lines);
    if (at < 0) break;
    lines = lines.filter((_, i) => i !== at);
  }
  if (lines.join('\n') === '') return '';
  const scan = await secretScanText(lines.join('\n'), scanner, opts.timeoutMs);
  if (scan.unplaced) return EXCERPT_WITHHELD;
  const drop = new Set(scan.lines);
  return lines.filter((l, i) => !drop.has(i + 1) && !scan.values.some((v) => l.includes(v))).join('\n');
}

// ---------- the error signature ----------

const TOKEN = /\S+/g;
const DATE_TIME = /\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?/g;
const TIME = /\b\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d{1,9})?\b/g;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const NUMBER = /\d+/g;
// after NUMBER every digit run is one 0, so a run of 7 or more here holds hex letters (a commit, a hash, an address)
const HEX_RUN = /\b(?:0x)?[0-9a-f]{7,}\b/gi;

/**
 * The fix loop's "same error twice" key (Plan E Task 5): the excerpt with every word holding a path separator (`/` or `\`, so URLs and
 * `file:line:col` too) made `<path>`, dates and times `<time>`, UUIDs `<id>`, every digit run `0`, then hex runs of 7 or more `<hex>`,
 * blanks collapsed; then its sha256 (hex). Every pattern is linear.
 */
export function errorSignature(excerpt: string): string {
  const norm = String(excerpt)
    .replace(TOKEN, (t) => (t.includes('/') || t.includes('\\') ? '<path>' : t))
    .replace(DATE_TIME, '<time>')
    .replace(TIME, '<time>')
    .replace(UUID, '<id>')
    .replace(NUMBER, '0')
    .replace(HEX_RUN, '<hex>')
    .replace(/\s+/g, ' ')
    .trim();
  return createHash('sha256').update(norm, 'utf8').digest('hex');
}
