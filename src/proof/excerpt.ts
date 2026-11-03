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
//      readings says PRIVATE or KEY, but stays shown. Every reading is also redacted apart, and indented-value blocks, secret sections
//      and key blocks any reading (or a suspect line's shape) opens are hidden in the excerpt itself; see unscannedExcerpt. Lines stay
//      in place, untagged, for the whole-log redact, and hidden lines go only after the cross-line scrub (security scans 1-5);
//   4. the error lines and EXCERPT_CONTEXT_LINES around each are picked, at most EXCERPT_MAX_LINES lines and EXCERPT_MAX_BYTES;
//   5. Plan A redact;
//   6. the composed scrubber (the caller's: vault.scrubber() then knownValueScrubber over the placeholders and the throwaway scratch
//      keys; no values list exists), through scrubForDisplay's fullScrub with finish = identity, per line and then on the whole text;
//   7. the secret scan (betterleaks, or gitleaks with the switch) over the excerpt: a finding drops its line, and every line that holds
//      a found text; a finding that can't be placed withholds the excerpt.
// Scrub before cutting (D5 review I1): step 4 never cuts inside a line (a line is shown whole or not at all; a line over 4 KB is
// Plan A's LONG_LINE), and before it the scrubber (per line, then across lines) and redact also run over the whole cleaned log, so a
// value split across lines at the edge of a picked window, or a private key whose BEGIN line is outside it, is gone before any line is
// picked.
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
/** Readings probed at most (scan 5): past this many, the log is mostly garbage and the excerpt is empty (fail closed). */
const MAX_PROBES = 300_000;
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
/** findKeyMarker itself (copied): the first `kind` key marker in `line` from `from`, or null. */
function keyMarkerFrom(line: string, kind: 'BEGIN' | 'END', from: number): { start: number; end: number } | null {
  const head = `-----${kind} `;
  for (let i = line.indexOf(head, from); i >= 0; i = line.indexOf(head, i + 1)) {
    let j = i + head.length;
    while (j < line.length && (line[j] === ' ' || (line[j] as string >= 'A' && line[j] as string <= 'Z'))) j++;
    if (KEY_TAILS.some((t) => line.slice(i + head.length, j).endsWith(t)) && line.startsWith('-----', j)) return { start: i, end: j + 5 };
  }
  return null;
}

/**
 * Which lines of `lines` redact's output keeps, in order: redact drops a line only when it starts inside a key block, opens none, and
 * holds nothing outside key blocks (redact-core.ts, the first rule of its line loop; replayed here with the same marker rules).
 */
function redactKeeps(lines: string[]): number[] {
  const kept: number[] = [];
  let inKey = false;
  lines.forEach((raw, i) => {
    let end = raw.length;
    while (end > 0 && raw.charCodeAt(end - 1) === 13) end--;
    const line = raw.slice(0, end);
    const started = inKey;
    let opens = false;
    let empty = true;
    for (let pos = 0; ;) {
      if (inKey) {
        const m = keyMarkerFrom(line, 'END', pos);
        if (m === null) break;
        pos = m.end;
        inKey = false;
      } else {
        const m = keyMarkerFrom(line, 'BEGIN', pos);
        if (line.slice(pos, m === null ? line.length : m.start) !== '') empty = false;
        if (m === null) break;
        opens = true;
        pos = m.end;
        inKey = true;
      }
    }
    if (!(started && !opens && empty)) kept.push(i);
  });
  return kept;
}

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
// Tested on the trimmed line, so there are no blank quantifiers next to each other (scan 6).
const ARMOR = /^(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9+/]+={1,2}|(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|MessageID):.*)?$/;
const isArmor = (line: string) => bytesOf(line) > MAX_REGEX_LINE_BYTES || ARMOR.test(line.trim()) || lastKeyMarker(line, 'END') >= 0;

// A dropped line's escape sequences, removed whole (follow-up scan finding): OSC (ESC ] or C1 OSC, ended by BEL, ST or ESC \), CSI (ESC [
// or C1 CSI), any other ESC sequence (intermediates and one final byte), then any ESC or C1 left. Ruling E0a-R1 (b): the OSC body
// excludes both introducers, so an unterminated run of them is read once (linear), and lines over MAX_REGEX_LINE_BYTES skip this reading.
const DROPPED_OSC = /(?:\u001b\]|\u009d)[^\u0007\u001b\u009c\u009d]*(?:\u0007|\u009c|\u001b\\)/g;
const DROPPED_CSI = /(?:\u001b\[|\u009b)[\u0030-\u003f]*[\u0020-\u002f]*[\u0040-\u007e]?/g;
const DROPPED_ESC = /\u001b[\u0020-\u002f]*[\u0030-\u007e]?/g;
const ESC_C1 = /[\u001b\u0080-\u009f]/g;
const withoutSequences = (line: string) => line.replace(DROPPED_OSC, '').replace(DROPPED_CSI, '').replace(DROPPED_ESC, '').replace(ESC_C1, '');
// the sequences again, with their final byte kept: a final byte can be a letter the sequence "ate" from a key marker
const keepFinal = (m: string) => {
  const last = m.charCodeAt(m.length - 1);
  return m.length > 1 && last >= 0x40 && last <= 0x7e && !(m.length === 2 && (last === 0x5b || last === 0x5d)) ? m[m.length - 1] as string : '';
};
const withFinals = (line: string) => line.replace(DROPPED_CSI, keepFinal).replace(DROPPED_ESC, keepFinal).replace(ESC_C1, '');
const LINE_SEPS = /[\u2028\u2029]/g;

/**
 * Ruling E0a-R1 (a), widened by scan 4: the readings of a line, since no one way of taking escapes and invisible characters out is right
 * for every line (a sequence's final byte can be a letter of the marker; a CR, LS or tab can split it): escape sequences removed whole, the
 * same with their final bytes kept (both for lines within MAX_REGEX_LINE_BYTES only), and only the ESC and C1 characters removed; and each
 * of those with every non-printable character removed too (stripChars: controls, bidi, invisibles; and LS/PS). Duplicates once.
 */
function readings(line: string): string[] {
  const guarded = bytesOf(line) <= MAX_REGEX_LINE_BYTES ? [withoutSequences(line), withFinals(line)] : [];
  const base = [...guarded, line.replace(ESC_C1, '')];
  // fuzz (scan 4): a sequence and an LS in one line need both taken out, so each reading also has its non-printable-free form
  return [...new Set([...base, ...base.map((r) => stripChars(r).replace(LINE_SEPS, ''))])];
}
/** Ruling E0a-R1 (a): a word of a key name in a reading, either one, any case. */
const NAMES_KEY = /private|key/i;
/**
 * Scan 5 fuzz, failing closed the same way: a word of a secret name as redact-core's isSecretName knows them (its KEYWORD, `auth` and
 * `credential`; a superset, any case). Garbage nested inside a sequence can leave a key name no reading puts back together, so a
 * suspect line holding one opens an indented-value block (and a section, when it is a `[` line) whatever redact says of its readings.
 */
const NAMES_SECRET = /password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|auth|credential/i;
/**
 * Scan 5 fuzz, by shape rather than by name: an inserted final byte can't be told from an eaten letter, so no reading may hold the
 * key's real name. A suspect line shaped like a block opener (`name:` with an empty value, or a YAML `|`/`>` block) opens an
 * indented-value block, and one shaped like a section header (`[name]` alone) a section, whatever the name. Linear: opensBlock works
 * by hand, HEADER_SHAPE is anchored with one quantifier per run.
 */
function opensBlock(r: string): boolean {
  // by hand (scan 6: adjacent blank quantifiers backtrack): trailing blanks, a YAML block indicator (`|`, `>`, then `-`, `+` or digits),
  // blanks again, then a `:`
  let t = r.trimEnd();
  let k = t.length;
  while (k > 0 && '-+0123456789'.includes(t[k - 1] as string)) k--;
  if (k > 0 && (t[k - 1] === '|' || t[k - 1] === '>')) t = t.slice(0, k - 1).trimEnd();
  return t.endsWith(':');
}
// blanks and SGR colour codes (a colour code before the text is the usual case, and swallows nothing; another CSI's intermediates can
// be the indentation's spaces), then a character that isn't printable: an OSC or another sequence, a C1, a control,
// LS/PS or an invisible, any of which can have swallowed the indentation
const INDENT_UNSURE = /^(?:[ \t]|\u001b\[[0-9;]*m)*[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/;
// a run a 16-character window of a secret could show in
const LONG_RUN = /[A-Za-z0-9+/]{16,}/;
const HEADER_SHAPE = /^[ \t]*\[[^\]]*\]\]?[ \t]*(?:[#;].*)?$/;
// a `[` first, and a word of a secret name before the first `]`: a header whatever follows it (a sequence's final byte may have
// become its `[`, and garbage may follow it)
const SECRET_IN_HEADER = new RegExp(`^[ \\t]*\\[[^\\]]*(?:${NAMES_SECRET.source})`, 'i');

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

interface Read {
  /** The line as shown (steps 1-2), or null when step 3 drops it. */
  shown: string | null;
  /** Its readings that differ from the shown line (all of them for a dropped line): each is redacted on its own (scan 5). */
  probe: string[];
  /** OR across the line and its readings: an END key marker; a word of a key name (only for a line step 2 changed, dropped or holding
   *  a character stripChars or LS/PS would take out); armor-shaped. */
  ends: boolean;
  namesKey: boolean;
  armor: boolean;
  /** The smallest indentation (redact's columns) of the line and its readings (where a block it opens starts), and the largest (a line
   *  continues an open block when any reading of it is more indented); whether any reading is blank; whether every one is a section header. */
  cols: number;
  colsMax: number;
  blank: boolean;
  header: boolean;
  /** What stands for a dropped line in the log text redact reads: its first reading. */
  rep: string;
  /** Whether the line was read more than one way (step 2 changed it, step 3 drops it, or it holds a non-printable). */
  suspect: boolean;
  /** Dropped, or holding anything but SGR codes and tabs that a reading takes out: no reading of it can be trusted. */
  messy: boolean;
  /** Whether the raw line has an escape, a C1 or another non-printable (a tab aside) before its first printable character: then its
   *  indentation can't be trusted (an inserted sequence can swallow it). */
  indentUnsure: boolean;
  /** A suspect line (as for namesKey) with a word of a secret name in any reading; and whether a reading starts with `[`. */
  namesSecret: boolean;
  bracket: boolean;
  opener: boolean;
}

/** redact-core's indentOf columns (a tab goes to the next multiple of 8). A copy: that function is not exported. */
function indentCols(line: string): number {
  let cols = 0;
  for (const ch of line) {
    if (ch === ' ') cols++;
    else if (ch === '\t') cols = (Math.floor(cols / 8) + 1) * 8;
    else break;
  }
  return cols;
}
// redact-core's sectionName shape: `[name]` or `[[name]]`, then only blanks or a comment
const SECTION_HEADER = /^[ \t]*\[\[?[^\]]*\]\]?[ \t]*(?:[#;].*)?$/;

// an SGR colour code: the one sequence step 2 removes that changes no text (only its final `m` can be an eaten letter)
const SGR = /\u001b\[[0-9;]*m/g;

function readLine(raw: string): Read {
  const c = cleanLine(raw);
  const base = c.drop ? null : c.line;
  // printable ASCII and spaces only (the usual line): nothing to read another way
  const suspect = c.drop || c.before !== null || (/[^\u0020-\u007e]/.test(c.line) && stripChars(c.line).replace(LINE_SEPS, '') !== c.line);
  // messy: dropped, or holding anything but SGR colour codes that a reading would take out (an OSC, a cursor move, a CSI with
  // intermediates, a control other than a tab, an invisible, LS/PS): then no reading can be trusted, and the fail-closed name and shape
  // rules apply. A line whose only change is SGR codes (or tabs) is read as shown, with an eaten `m` put back (the readings that
  // remove ESC alone leave a colour code's `[`).
  // scan 6: and any line holding a character known-values strips (controls, bidi, invisibles; a tab aside) or LS/PS, SGR codes apart
  const noSgr = (c.before ?? c.line).replace(SGR, '').replaceAll('\t', '');
  const messy = c.drop || (suspect && stripChars(noSgr).replace(LINE_SEPS, '') !== noSgr);
  const rs = messy ? readings(c.before ?? c.line)
    : suspect ? [...new Set([...(c.before === null ? [] : [withFinals(c.before)]), stripChars(c.line).replace(LINE_SEPS, '')])] : [];
  const all = base === null ? rs : [base, ...rs];
  return {
    shown: base,
    probe: rs.filter((r) => r !== base && r.trim() !== ''),
    ends: all.some((r) => lastKeyMarker(r, 'END') >= 0),
    namesKey: messy && all.some((r) => NAMES_KEY.test(r)),
    armor: all.some(isArmor),
    cols: all.length === 0 ? 0 : Math.min(...all.map(indentCols)),
    colsMax: all.length === 0 ? 0 : Math.max(...all.map(indentCols)),
    blank: all.length === 0 || all.some((r) => r.trim() === ''),
    header: all.length > 0 && all.every((r) => SECTION_HEADER.test(r)),
    rep: rs[0] ?? '',
    suspect,
    messy,
    indentUnsure: suspect && INDENT_UNSURE.test(c.before ?? c.line),
    namesSecret: messy && all.some((r) => NAMES_SECRET.test(r)),
    // a suspect line opens a section when a reading has a header's shape, or (dropped: garbage can stand before the `[`) a `[` and a
    // later `]` anywhere; and a block when a reading has a block opener's shape
    bracket: messy && (all.some((r) => bytesOf(r) <= MAX_REGEX_LINE_BYTES && (HEADER_SHAPE.test(r) || SECRET_IN_HEADER.test(r) || (c.drop && /\[[^\]]*\]/.test(r))))
      // the `[` can be a sequence's own and the name split: a `[` in one reading and a `]` ending one is enough
      || (all.some((r) => r.includes('[')) && all.some((r) => r.trimEnd().endsWith(']')))),
    opener: messy && all.some(opensBlock),
  };
}

/** What redact does with one reading of a line, on its own (scan 5). */
interface Probe { hit: boolean; block: boolean; section: boolean; key: boolean }

/**
 * Scan 5: each reading is redacted apart from the log, so a reading never sits between two real lines. All readings go in one text,
 * each as a group: a marker line, the reading, a more-indented probe line (hidden when the reading starts an indented-value block), a
 * `key = value` probe line at indent 0 (hidden when it starts a secret section), then an END key marker and a plain section header that
 * reset redact's key and section state. The probe lines carry a random nonce, so log text can't pose as them.
 */
function probeReadings(jobs: string[]): Probe[] {
  if (jobs.length === 0) return [];
  const nonce = randomBytes(6).toString('hex');
  const reset = `-----END RSA ${KEY_TAILS[0]}-----\n[pgreset${nonce}]`;
  const lineB = (g: number, r: string) => `${' '.repeat(indentCols(r))}  zz${nonce}p${g}b`;
  const lineC = (g: number) => `zz${nonce}p${g}c = v`;
  const text = jobs.map((r, g) => `zz${nonce}p${g}a\n${r}\n${lineB(g, r)}\n${lineC(g)}\n${reset}`).join('\n');
  const out = redact(text).split('\n');
  const at = new Map<string, number>();
  out.forEach((l, i) => at.set(l, i));
  return jobs.map((r, g) => {
    const m = at.get(`zz${nonce}p${g}a`);
    // a reading that opens a key hides both probe lines by itself: that is the key hide, not a block or a section
    const key = lastKeyMarker(r, 'BEGIN') > lastKeyMarker(r, 'END');
    return { hit: m === undefined || out[m + 1] !== r, block: !key && !at.has(lineB(g, r)), section: !key && !at.has(lineC(g)), key };
  });
}

/**
 * Steps 1-6 of errorExcerpt, without the secret scan: NOT safe to send. Exported for the excerpt's fuzz test (the scan only removes
 * lines, so what holds here holds for errorExcerpt). `maxLogChars` replaces MAX_LOG_CHARS in tests only.
 */
export function unscannedExcerpt(logs: string, scrub: (text: string) => string, testOpts: { maxLogChars?: number } = {}): string[] {
  const maxLogChars = testOpts.maxLogChars ?? MAX_LOG_CHARS;
  let text = String(logs);
  let guard = 0;
  let cut = false;
  let insideKey = false;
  if (text.length > maxLogChars) {
    const from = text.indexOf('\n', text.length - maxLogChars);
    insideKey = endsInsideKey(from < 0 ? text : text.slice(0, from));
    text = from < 0 ? '' : text.slice(from + 1);
    guard = HEAD_GUARD_LINES;
    cut = true;
  }
  // steps 1-3. Each real line stays in the log text redact reads once, in place and untagged (scan 5: nothing may sit between two real
  // lines or change one, or redact's block rules stop linking them). A dropped line is there as its first reading. The readings of a
  // line are redacted apart (probeReadings), and their verdicts are ORed:
  // - a reading in which redact hides something on the line itself: the line is hidden;
  // - one that starts an indented-value block: the more-indented (and blank) lines after it are hidden;
  // - one that starts a secret section: the lines after it are hidden up to the next section header;
  // - a messy line (dropped, or holding anything but SGR codes and tabs that a reading takes out) opens a block: an inserted sequence
  //   can swallow a block opener's `:` itself. A messy line opens a section when a reading has a header's shape (HEADER_SHAPE), a
  //   secret word inside its first `[...]`, a `[` in one reading and a `]` ending one, or (dropped) any `[...]`: inserted bytes can
  //   split or change any word past repair, so shape decides, not name;
  // - the parent of every suspect line (the nearest earlier line indented less) is probed as well, so a block it opens goes on through
  //   a line whose readings disagree on its indentation; a line continues an open block when any reading is more indented or blank, or
  //   when garbage stands before its first printable character (INDENT_UNSURE); only a header that is not messy ends a section; a suspect line
  //   whose scrubbed readings hold a long base64 run goes on with armor;
  // - one that opens a private key, or a messy line that names one (PRIVATE or KEY in any reading):
  //   hidden up to the next END marker line (to the end of the log when a reading opened a key and no END follows), else while the
  //   lines look like armor (base64, armor headers, blank lines). The same after a cut inside a key block, and armor mode after any
  //   other dropped line and at the start of a cut tail. A line that is armor while that lasts is always hidden.
  // Dropped lines and the head guard's are hidden too.
  const lines0 = text.split('\n').map(readLine);
  // scan 5 fuzz: a suspect line can end redact's own block early (an LS in its indentation), so the block's parent is probed too: the
  // nearest earlier non-blank line indented less than any reading of the suspect line (a monotonic stack: linear)
  const parents = new Set<number>();
  const stack: { cols: number; i: number }[] = [];
  lines0.forEach((r, i) => {
    const own = r.shown ?? r.rep;
    if (r.suspect) {
      // with its indentation unsure, any ancestor can be the block's opener: all of them (the 32 nearest) are probed
      for (let k = stack.length - 1, n = 0; k >= 0 && n < 32; k--) {
        const e = stack[k] as { cols: number; i: number };
        if (e.cols < r.colsMax || r.indentUnsure) {
          if (!(lines0[e.i] as Read).suspect) parents.add(e.i);
          n++;
          if (!r.indentUnsure) break;
        }
      }
    }
    if (own.trim() === '') return;
    const cols = indentCols(own);
    while (stack.length > 0 && (stack[stack.length - 1] as { cols: number }).cols >= cols) stack.pop();
    stack.push({ cols, i });
  });
  const jobs: string[] = [];
  // each reading scrubbed first, as the log text is before redact, so a known value doesn't count as a hit
  const jobOf: number[][] = lines0.map((r, i) =>
    [...r.probe, ...(parents.has(i) ? [r.shown ?? r.rep] : [])].map((x) => jobs.push(scrub(x).split('\n').join(' ')) - 1));
  // a log made of garbage would need millions of probes: past the budget nothing is shown (fail closed)
  if (jobs.length > MAX_PROBES) return [];
  const probes = probeReadings(jobs);
  const nextEnd = new Int32Array(lines0.length);
  for (let i = lines0.length - 1, next = -1; i >= 0; i--) {
    if ((lines0[i] as Read).ends) next = i;
    nextEnd[i] = next;
  }
  let hideTo = -1;
  let armor = false;
  let blockCols = -1;
  let section = false;
  const startKeyHide = (from: number, opened: boolean) => {
    const end = from < lines0.length ? (nextEnd[from] as number) : -1;
    if (end >= 0) hideTo = Math.max(hideTo, end);
    else if (opened) hideTo = lines0.length - 1;
    else armor = true;
  };
  if (cut) {
    if (insideKey) startKeyHide(0, false);
    else armor = true;
  }
  const hiddenAt = lines0.map((r, i) => {
    let hidden = r.shown === null || i <= hideTo || i < guard;
    // a suspect line's indentation and shape can't be trusted (an inserted sequence can swallow both), so only a clean line ends an
    // open block, section or armor run
    if (blockCols >= 0) {
      if (r.indentUnsure || r.blank || r.colsMax > blockCols) hidden = true;
      else blockCols = -1;
    }
    if (section) {
      if (r.header && !r.messy) section = false;
      else hidden = true;
    }
    // scan 4: the armor check comes first, so an armor line is hidden even when it also starts a key hide. A suspect line whose
    // scrubbed readings still hold a long base64 run goes on with armor too (a sequence can leave a body line's rest in no shape)
    const longRun = r.suspect && (jobOf[i] as number[]).some((j) => LONG_RUN.test(jobs[j] as string));
    if (armor && i > hideTo) {
      if (r.armor || longRun) hidden = true;
      if ((!r.armor && !longRun) || r.ends) armor = false;
    }
    const verdict = (jobOf[i] as number[]).map((j) => probes[j] as Probe);
    if (verdict.some((p) => p.hit)) hidden = true;
    // a dropped line can't be read for sure (garbage nested in a sequence splits any word), so it fails closed on every multi-line rule
    // fuzz: an OSC can swallow a block opener's `:` itself, so any messy line opens a block (more-indented lines after it are hidden)
    const unreadable = r.messy || r.namesSecret;
    if (verdict.some((p) => p.block) || unreadable || r.opener) blockCols = blockCols < 0 ? r.cols : Math.min(blockCols, r.cols);
    if (verdict.some((p) => p.section) || r.bracket) section = true;
    const opened = verdict.some((p) => p.key);
    if (i >= hideTo) {
      if ((r.namesKey || opened) && !r.ends) startKeyHide(i + 1, opened);
      else if (r.shown === null) armor = true;
    }
    return hidden;
  });
  // scrub before cutting, and before redact can cut a value: each line on its own (no line count changes), then redact over the whole
  // log. redactKeeps tells which input line each output line is; a count that doesn't match fails closed.
  // one scrub of the whole text when it merges no lines (the usual case); per line only when a value spans lines (caught again below)
  const plain = lines0.map((r) => r.shown ?? r.rep);
  let mainLines = scrub(plain.join('\n')).split('\n');
  if (mainLines.length !== plain.length) mainLines = plain.map((l) => scrub(l).split('\n').join(' '));
  const redactedLines = redact(mainLines.join('\n')).split('\n');
  const kept = redactKeeps(mainLines);
  if (redactedLines.length !== kept.length) return [];
  // then the hidden lines get a random tag at both ends, made only of line-break characters (the scrubber's joined views take them
  // out, so a value split across a hidden line is still found), the whole log is scrubbed across lines, and every line that still
  // carries a tag goes: a value span that swallows one tag of a hidden line keeps the other in the merged line
  const tag = `\r${Array.from(randomBytes(6), (b) => Array.from({ length: 8 }, (_, k) => ((b >> k) & 1 ? '\u2029' : '\u2028')).join('')).join('')}\r`;
  const tagged = redactedLines.map((l, j) => {
    if (!(hiddenAt[kept[j] as number] as boolean)) return l;
    const indent = /^[ \t]*/.exec(l)?.[0] ?? '';
    return `${indent}${tag}${l.slice(indent.length)}${tag}`;
  });
  const whole = scrub(tagged.join('\n')).split('\n').filter((l) => !l.includes(tag));
  // step 4
  const picked = pick(whole);
  if (picked.length === 0) return [];
  // step 5
  const redacted = redact(picked.join('\n'));
  // step 6: per line first, so a hit in one line's display or stripped form doesn't flatten the others; then the whole text
  const check = { scrubber: () => scrub };
  const perLine = redacted.split('\n').map((l) => scrubForDisplay(check, l, identity)).join('\n');
  return capLines(scrubForDisplay(check, perLine, identity).split('\n'));
}

/**
 * The excerpt of a failing CI log that the fix loop may send to the AI (ruling B1; the steps are in this file's header). `scrub` is the
 * composed known-value scrubber. Throws SecretScanError when the secret scan can't run or does not confirm it read the excerpt: then
 * nothing may be sent.
 */
export async function errorExcerpt(logs: string, scrub: (text: string) => string, scanner: SecretScanner, opts: { timeoutMs?: number } = {}): Promise<string> {
  let lines = unscannedExcerpt(logs, scrub);
  if (lines.length === 0) return '';
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
