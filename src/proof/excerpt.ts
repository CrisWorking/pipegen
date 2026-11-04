// Plan E E0a (ruling B1; fix round 1, ruling E0a-R4): the one form in which a CI log reaches the AI. Global constraint: "Logs reach the
// AI only as a code-extracted error excerpt, redacted (Plan A), scrubbed of every value the user typed, inside a block marked as
// untrusted." The untrusted block is the fix loop's (E7); classifyFailure (E7) reads the raw log locally, and only this excerpt leaves
// the machine (S15).
//
// errorExcerpt runs the ruling's seven steps in order:
//   1. the GitHub timestamp prefix (and a leading BOM) is taken off each line;
//   2. whole ANSI CSI and OSC sequences are removed. A line where a removed run of sequences sat between two word characters is
//      dropped (fix round 1, C1(b)): a sequence's parameter and final bytes may have been a value's characters;
//   3. a line that still holds ESC or a C1 control is dropped (with a vault, fullScrub would show the whole excerpt as one [REDACTED]);
//   4. the error lines and EXCERPT_CONTEXT_LINES around each are picked, at most EXCERPT_MAX_LINES lines and EXCERPT_MAX_BYTES;
//   5. Plan A redact;
//   6. the composed scrubber (the caller's: vault.scrubber() then knownValueScrubber over the placeholders and the throwaway scratch
//      keys; no values list exists), through scrubForDisplay's fullScrub with finish = identity, per line and then on the whole text;
//   7. the secret scan (betterleaks, or gitleaks with the switch) over the excerpt: a finding drops its line, and every line that holds
//      a found text; a finding that can't be placed withholds the excerpt.
// Scrub before cutting (D5 review I1): step 4 never cuts inside a line (a line is shown whole or not at all; a line over 4 KB is Plan
// A's LONG_LINE), and before it the whole cleaned log goes through the scrubber, redact and the hide rules of unscannedExcerpt, so a
// value split across lines at the edge of a window, or a key or secret block whose opening line is outside it, is gone before any line
// is picked. Where a line can't be read for sure, it is hidden rather than read again in a new way (ruling E0a-R4): less context for
// the AI, never a leak.
// The secret scan runs a process, so errorExcerpt is async and takes the pinned scanner (ruling E0a-R3); any throw means nothing may be
// sent. The boundary that keeps typed values out is structural (ruling E0a-R5, DECISIONS #113): errorExcerpt requires evidence that the
// run held only placeholders or throwaway keys (ScratchKeys' brand, E4), so no typed value is in the log at all; the rules below are defence in depth, and the
// shapes they still miss are recorded limits.
import { createHash, randomBytes } from 'node:crypto';
import { findKeyMarker, indentOf, MAX_REGEX_LINE_BYTES } from '../ai/redact-core.js';
import { redact, secretScanText, type SecretScanner } from '../ai/redact.js';
import { LATE_MAGIC, SCAN_PREFIX, scannersWouldSkip } from '../ai/scan-staging.js';
import { holdsEscape, scrubForDisplay, stripChars } from '../util/known-values.js';
import { evidenceCovers, isExcerptEvidence, type ExcerptEvidence } from './keys.js';

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
 * count: when the last HEAD_KEY_LINES lines of the cut-off head leave a key open (in any reading of a line, as in the tail), the tail
 * is hidden up to the block's END line, or with no END while it looks like armor; armor-shaped lines at the start of a tail are hidden
 * anyway. The caller (E7) must also bound the log it holds: this cap applies to what it passes.
 */
export const MAX_LOG_CHARS = 1024 * 1024;
const HEAD_GUARD_LINES = 64;
const HEAD_KEY_LINES = 1024;
/** Readings probed with redact at most: past this many, the log is mostly garbage and the excerpt is empty (fail closed). */
const MAX_PROBES = 300_000;
/** Characters the value passes may scrub in all (each is a copy of the suspect lines' surroundings): past it, empty (fail closed). */
const MAX_VALUE_PASS_CHARS = 48 * 1024 * 1024;
/** Non-armor lines armor mode looks past for more armor (a foreign line inside a key body). */
const ARMOR_GAP = 3;
/** Windows tried at most in step 4 (a log of nothing but error lines stays linear). */
const MAX_WINDOWS_TRIED = 10_000;

// GitHub's per-line prefix: an ISO 8601 UTC time with up to 9 fraction digits, then one space.
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z(?: |$)/;
// Step 2: whole sequences only. OSC: ESC ] body, ended by BEL or ESC \ (an unterminated one stays, and step 3 drops its line). CSI: ESC [
// parameter bytes, intermediate bytes, final byte. The classes are disjoint, so the scan is linear.
const SEQUENCE = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)|\u001b\[[0-?]*[ -/]*[@-~]/g;
// a character a value (or its base64) can hold next to a removed sequence: a sequence glued between two of them may have eaten some
const WORD = /[A-Za-z0-9_+/=-]/;
// An error line: GitHub's error annotation, npm's, the test runners' fail marks, and the usual words (case-insensitive).
const ERROR_LINE = /##\[error\]|npm err!|[✕✖×]|error|fail|fatal|panic|exception|traceback|\b(?:denied|refused|cannot|unable|timed? ?out|not found|no such file|expected)\b|\bexit(?:ed)? (?:with )?(?:code|status) [1-9]/i;

const identity = (s: string) => s;
const bytesOf = (s: string) => Buffer.byteLength(s, 'utf8');
const marker = (n: number) => `[… ${n} line${n === 1 ? '' : 's'} not shown …]`;
/** The largest a marker line can be (it counts toward the byte cap before the real one is known). */
const MARKER_BYTES = bytesOf(marker(Number.MAX_SAFE_INTEGER)) + 1;

/**
 * Steps 1-2 on one line; whether step 3 drops it (it still holds ESC or a C1 control, or step 2 removed a run of sequences glued between
 * two WORD characters); and the line before step 2 when step 2 changed it.
 */
function cleanLine(raw: string): { line: string; drop: boolean; before: string | null } {
  let line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
  if (line.startsWith('\ufeff')) line = line.slice(1);
  line = line.replace(TIMESTAMP, '');
  if (!line.includes('\u001b')) return { line, drop: holdsEscape(line), before: null };
  const before = line;
  let out = '';
  let pos = 0;
  let glued = false;
  for (const m of before.matchAll(SEQUENCE)) {
    const at = m.index as number;
    out += before.slice(pos, at);
    pos = at + m[0].length;
    // a run of adjacent sequences counts as one: its neighbours are the characters around the whole run (the check waits for the
    // run's last sequence, whose next character is not an ESC)
    const next = before[pos];
    if (next !== undefined && next !== '\u001b' && out.length > 0 && WORD.test(out[out.length - 1] as string) && WORD.test(next)) glued = true;
  }
  line = out + before.slice(pos);
  return { line, drop: glued || holdsEscape(line), before: line === before ? null : before };
}

// Private key markers as Plan A redact finds them: redact-core.ts findKeyMarker itself (exported by E9; E0a had a copy here, because
// redact-core.ts is in the gate bundle and E0a left it untouched). Re-exported under the old name for the differential test.
const KEY_TAILS = ['PRIVATE KEY', 'PRIVATE KEY BLOCK'];
export const keyMarkerFrom = findKeyMarker;
/** The start of the last `kind` key marker in `line`, or -1. */
function lastKeyMarker(line: string, kind: 'BEGIN' | 'END'): number {
  let last = -1;
  for (let m = keyMarkerFrom(line, kind, 0); m !== null; m = keyMarkerFrom(line, kind, m.start + 1)) last = m.start;
  return last;
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

// A line of a private key body as PEM or PGP armor writes it: base64 (64 columns; the last line shorter, maybe with padding), one of its
// headers, or a blank line. Tested on the trimmed line, so no blank quantifiers sit next to each other (scan 6): linear.
const ARMOR = /^(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9+/]+={1,2}|(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset|MessageID):.*)?$/;
const isArmor = (line: string) => bytesOf(line) > MAX_REGEX_LINE_BYTES || ARMOR.test(line.trim()) || lastKeyMarker(line, 'END') >= 0;

// The readings' sequence removal, for a line step 3 drops or one step 2 changed: OSC (ESC ] or C1 OSC, ended by BEL, ST or ESC \; its body
// excludes both introducers, so an unterminated run is read once), CSI (ESC [ or C1 CSI), any other ESC sequence, then any ESC or C1 left.
const DROPPED_OSC = /(?:\u001b\]|\u009d)[^\u0007\u001b\u009c\u009d]*(?:\u0007|\u009c|\u001b\\)/g;
const DROPPED_CSI = /(?:\u001b\[|\u009b)[0-?]*[ -/]*[@-~]?/g;
const DROPPED_ESC = /\u001b[ -/]*[0-~]?/g;
const ESC_C1 = /[\u001b\u0080-\u009f]/g;
const withoutSequences = (line: string) => line.replace(DROPPED_OSC, '').replace(DROPPED_CSI, '').replace(DROPPED_ESC, '').replace(ESC_C1, '');
// the sequences again, with their final byte kept: a final byte can be a letter the sequence "ate"
const keepFinal = (m: string) => {
  const last = m.charCodeAt(m.length - 1);
  return m.length > 1 && last >= 0x40 && last <= 0x7e && !(m.length === 2 && (last === 0x5b || last === 0x5d)) ? m[m.length - 1] as string : '';
};
const withFinals = (line: string) => line.replace(DROPPED_CSI, keepFinal).replace(DROPPED_ESC, keepFinal).replace(ESC_C1, '');
const LINE_SEPS = /[\u2028\u2029]/g;

/**
 * The readings of a messy line (ruling E0a-R1, widened by scan 4): escape sequences removed whole, the same with their final bytes kept
 * (both for lines within MAX_REGEX_LINE_BYTES only), and only the ESC and C1 characters removed; and each of those with every
 * non-printable character removed too (stripChars: controls, bidi, invisibles; and LS/PS). Duplicates once.
 */
function readings(line: string): string[] {
  const guarded = bytesOf(line) <= MAX_REGEX_LINE_BYTES ? [withoutSequences(line), withFinals(line)] : [];
  const base = [...guarded, line.replace(ESC_C1, '')];
  return [...new Set([...base, ...base.map((r) => stripChars(r).replace(LINE_SEPS, ''))])];
}
/** A word of a key name in a reading of a messy line, either one, any case (ruling E0a-R1). */
const NAMES_KEY = /private|key/i;
/**
 * Fix round 2 (q3): a messy line whose reading starts with `[` and holds a word of a secret name (redact-core's isSecretName words, a
 * superset) before its first `]`, or with no `]` at all, opens a secret section: an escape can eat the header's `]` or `[`. Anchored, one
 * `[^\]]*` run before the words: linear (lines within MAX_REGEX_LINE_BYTES only).
 */
const SECRET_IN_HEADER = /^[ \t]*\[[^\]]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|auth|credential)/i;
// Garbage before the first printable character: past the leading blanks and SGR colour codes (a colour code before the text is the
// usual case, and swallows nothing; another CSI's intermediates can be the indentation's spaces), a character that isn't printable: an
// OSC or another sequence, a C1, a control, LS/PS or an invisible, any of which can have swallowed the indentation. The prefix is taken
// off first (fix round 1: as one pattern, the starred prefix could match nothing and let a colour code's own ESC count).
const LEAD = /^(?:[ \t]|\u001b\[[0-9;]*m)+/;
const NOT_PRINTABLE = /^[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u2028\u2029\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/;
const indentIsUnsure = (s: string) => NOT_PRINTABLE.test(s.replace(LEAD, ''));
// a run a 16-character window of a key body could show in
const LONG_RUN = /[A-Za-z0-9+/]{16,}/;
// redact-core's sectionName shape: `[name]` or `[[name]]`, then only blanks or a comment
const SECTION_HEADER = /^[ \t]*\[\[?[^\]]*\]\]?[ \t]*(?:[#;].*)?$/;
/**
 * Fix round 1 (vault fuzz): the length of the token a line has at its end, or at its start past the indentation (non-blank characters:
 * a typed value can hold any printable character, `%` and quotes too). No reading of a messy line (dropped lines included) can be
 * trusted (two insertions can need opposite readings, a payload can stand between two pieces), so a line whose token at an edge it shares
 * with a messy line, or a messy line's own token at an edge, is MIN_SPLIT_PIECE characters or longer may hold a piece of a value split
 * across the two lines, and is hidden.
 */
function edgeRun(line: string, atEnd: boolean): number {
  const blank = (ch: string | undefined) => ch === ' ' || ch === '\t';
  let n = 0;
  if (atEnd) { for (let i = line.length - 1; i >= 0 && !blank(line[i]); i--) n++; return n; }
  let i = 0;
  while (i < line.length && blank(line[i])) i++;
  for (; i < line.length && !blank(line[i]); i++) n++;
  return n;
}
const MIN_SPLIT_PIECE = 8;
/** edgeRun of a shown line, as shown and with every non-printable taken out (a tab or an invisible can split the token), the longer. */
const edgeOf = (r: { shown: string | null }, atEnd: boolean) =>
  (r.shown === null ? 0 : Math.max(edgeRun(r.shown, atEnd), edgeRun(stripChars(r.shown).replace(LINE_SEPS, ''), atEnd)));
/** A `[` and a `]` after it (by hand: a regex here is quadratic on a line of `[`). */
const bracketPair = (r: string) => { const i = r.indexOf('['); return i >= 0 && r.indexOf(']', i + 1) > i; };

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
  /** What stands for a dropped line in the log text redact reads: its first reading. */
  rep: string;
  /** Read more than one way: step 2 changed it, step 3 drops it, or it holds a character stripChars or LS/PS would take out. */
  suspect: boolean;
  /** Dropped, or holding anything but SGR codes and tabs that a reading takes out: no reading of it can be trusted. */
  messy: boolean;
  /** Its readings that differ from the shown line (all of them for a dropped line): each is redacted on its own (scan 5). */
  probe: string[];
  /** Every form the value passes scrub it in (a suspect line): the line and its readings (which include the invisible-free forms). */
  forms: string[];
  /** OR across the line and its readings: an END key marker; a key opened and not closed; armor-shaped. */
  ends: boolean;
  opensKey: boolean;
  armor: boolean;
  /** A messy line with PRIVATE or KEY in a reading (ruling E0a-R1). */
  namesKey: boolean;
  /** The smallest indentation (redact's columns) of the line and its readings (where a block it opens starts), and the largest (a line
   *  continues an open block when any reading of it is more indented); whether any reading is blank; whether every one is a header. */
  cols: number;
  colsMax: number;
  blank: boolean;
  header: boolean;
  /** Garbage before its first printable character: its indentation can't be trusted (an inserted sequence can swallow it). */
  indentUnsure: boolean;
  /** A messy line that may open a secret section: a reading shaped like a header or starting with `[` and a secret word before any
   *  `]` (SECRET_IN_HEADER), a `[` in one reading and a `]` ending one, or (dropped) any `[...]`. */
  bracket: boolean;
}

/** redact-core's indentOf columns (a tab goes to the next multiple of 8): the core's own helper since E9. Exported for the differential test. */
export function indentCols(line: string): number {
  return indentOf(line).cols;
}

// an SGR colour code: the one sequence step 2 removes that changes no text (unless glued, which step 2 drops)
const SGR = /\u001b\[[0-9;]*m/g;

function readLine(raw: string): Read {
  const c = cleanLine(raw);
  const base = c.drop ? null : c.line;
  // printable ASCII and spaces only (the usual line): nothing to read another way
  const suspect = c.drop || c.before !== null || (/[^ -~]/.test(c.line) && stripChars(c.line).replace(LINE_SEPS, '') !== c.line);
  // messy: dropped, or holding anything but SGR colour codes and tabs that a reading takes out (an OSC, a cursor move, a CSI with
  // intermediates, a control, an invisible, LS/PS); a line whose only change is SGR codes or tabs is read as shown, plus an eaten `m`
  // put back (the readings that remove ESC alone leave a colour code's `[`)
  const noSgr = (c.before ?? c.line).replace(SGR, '').replaceAll('\t', '');
  const messy = c.drop || (suspect && stripChars(noSgr).replace(LINE_SEPS, '') !== noSgr);
  const rs = messy ? readings(c.before ?? c.line)
    : suspect ? [...new Set([...(c.before === null ? [] : [withFinals(c.before)]), stripChars(c.line).replace(LINE_SEPS, '')])] : [];
  const all = base === null ? rs : [base, ...rs];
  return {
    shown: base,
    rep: rs[0] ?? '',
    suspect,
    messy,
    probe: rs.filter((r) => r !== base && r.trim() !== ''),
    forms: suspect ? [...new Set([base ?? c.line, ...rs])] : [],
    ends: all.some((r) => lastKeyMarker(r, 'END') >= 0),
    opensKey: all.some((r) => lastKeyMarker(r, 'BEGIN') > lastKeyMarker(r, 'END')),
    armor: all.some(isArmor),
    namesKey: messy && all.some((r) => NAMES_KEY.test(r)),
    cols: all.length === 0 ? 0 : Math.min(...all.map(indentCols)),
    colsMax: all.length === 0 ? 0 : Math.max(...all.map(indentCols)),
    blank: all.length === 0 || all.some((r) => r.trim() === ''),
    header: all.length > 0 && all.every((r) => SECTION_HEADER.test(r)),
    indentUnsure: suspect && indentIsUnsure(c.before ?? c.line),
    bracket: messy && (all.some((r) => (bytesOf(r) <= MAX_REGEX_LINE_BYTES && (SECTION_HEADER.test(r) || SECRET_IN_HEADER.test(r))) || (c.drop && bracketPair(r)))
      || (all.some((r) => r.includes('[')) && all.some((r) => r.trimEnd().endsWith(']')))),
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
  // E9: a reading may leave a quoted value open (redact then hides up to its closing quote): the line after the END marker closes every
  // kind of quote redact tracks (" ' ` and their triples), so one reading never hides the groups after it
  const reset = `-----END RSA ${KEY_TAILS[0]}-----\n"""'''\`\n[pgreset${nonce}]`;
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


// ---------- scrubbing across lines, with line identity ----------

const LINE_ID_BITS = 23; // MAX_LOG_CHARS + 1 lines at most
/** A line's start marker for a cross-line scrub: its index, as line-break characters only (the scrubber's joined views take them out). */
const lineId = (i: number) => `\r${Array.from({ length: LINE_ID_BITS }, (_, k) => ((i >> k) & 1 ? '\u2029' : '\u2028')).join('')}\r`;
const LINE_ID = new RegExp(`\\r([\\u2028\\u2029]{${LINE_ID_BITS}})\\r`, 'g');
const LINE_ID_AT_START = new RegExp(`^\\r([\\u2028\\u2029]{${LINE_ID_BITS}})\\r`);
const idOf = (bits: string) => [...bits].reduce((n, ch, k) => n | ((ch === '\u2029' ? 1 : 0) << k), 0);

/**
 * `lines` scrubbed as one text, and for each output line the input lines it was built from (a value span across a line break merges
 * lines). With no merge (the usual case) one plain scrub; otherwise again with each line's id at its start: a span that crosses a line
 * break swallows the id after it, so an output line is the lines from its own id to the next output line's. Null when an output line
 * has no id (fail closed).
 */
function scrubLines(lines: string[], scrub: (text: string) => string): { out: string[]; from: number[][] } | null {
  const plainOut = scrub(lines.join('\n')).split('\n');
  if (plainOut.length === lines.length) return { out: plainOut, from: lines.map((_, i) => [i]) };
  const marked = scrub(lines.map((l, i) => lineId(i) + l).join('\n')).split('\n');
  const firsts: number[] = [];
  for (const l of marked) {
    const m = LINE_ID_AT_START.exec(l);
    if (m === null) return null;
    firsts.push(idOf(m[1] as string));
  }
  const from = firsts.map((a, o) => Array.from({ length: (o + 1 < firsts.length ? (firsts[o + 1] as number) : lines.length) - a }, (_, k) => a + k));
  return { out: marked.map((l) => l.replace(LINE_ID, '')), from };
}

/**
 * Fix round 1 (C1(a), I1): the value passes. A suspect line is read several ways (Read.forms), and the shown line may hold only part of a
 * value that another form holds whole, alone or with a neighbour. Pass k scrubs every suspect line as its k-th form, with the lines next
 * to it, across lines; suspect runs and their neighbours only, apart from each other (a NUL line between them stops a span). Then:
 * - a merge (a value across lines in some form): every line of the merged group is hidden;
 * - a hit on a form that isn't the shown line: hidden when the line is messy, or when its shown form holds no value itself (a colour code
 *   that only coloured a value doesn't hide the line).
 * True per hidden line; null past MAX_VALUE_PASS_CHARS (fail closed).
 */
function valuePasses(lines0: Read[], scrub: (text: string) => string): Uint8Array | null {
  const n = lines0.length;
  const hide = new Uint8Array(n);
  const inRun = new Uint8Array(n);
  let passes = 0;
  lines0.forEach((r, i) => {
    if (!r.suspect) return;
    for (let j = Math.max(0, i - 1); j <= Math.min(n - 1, i + 1); j++) inRun[j] = 1;
    passes = Math.max(passes, r.forms.length);
  });
  const shownHit = new Map<number, boolean>();
  let budget = MAX_VALUE_PASS_CHARS;
  for (let k = 0; k < passes; k++) {
    const idx: number[] = [];
    const text: string[] = [];
    for (let i = 0; i < n; i++) {
      if (inRun[i] !== 1) continue;
      if (idx.length > 0 && (idx[idx.length - 1] as number) !== i - 1) { idx.push(-1); text.push('\u0000'); }
      const r = lines0[i] as Read;
      idx.push(i);
      text.push(r.suspect ? (r.forms[Math.min(k, r.forms.length - 1)] as string) : (r.shown ?? r.rep));
    }
    // a pass only needs the runs where some line has a k-th form of its own
    if (k > 0 && !idx.some((i) => i >= 0 && (lines0[i] as Read).forms.length > k)) continue;
    budget -= text.reduce((s, t) => s + t.length + 1, 0);
    if (budget < 0) return null;
    const res = scrubLines(text, scrub);
    if (res === null) return null;
    res.from.forEach((group, o) => {
      const members = group.map((g) => idx[g] as number).filter((i) => i >= 0);
      if (members.length > 1) { for (const i of members) hide[i] = 1; return; }
      const i = members[0];
      if (i === undefined) return;
      const r = lines0[i] as Read;
      const form = text[group[0] as number] as string;
      if (!r.suspect || form === r.shown || res.out[o] === form) return;
      if (!shownHit.has(i)) shownHit.set(i, r.shown !== null && scrub(r.shown) !== r.shown);
      if (r.messy || !shownHit.get(i)) hide[i] = 1;
    });
  }
  return hide;
}

/**
 * Whether a cut-off head leaves a private key open, read as the tail is (I2): 'opened' when its last key marker is a BEGIN, or when, in
 * its last HEAD_KEY_LINES lines, a reading of a line opened a key that no END closed; 'named' when a messy line there names a key (PRIVATE
 * or KEY) and no END followed; else null.
 */
function headLeavesKeyOpen(head: string): 'opened' | 'named' | null {
  if (endsInsideKey(head)) return 'opened';
  let from = head.length;
  for (let k = 0; k < HEAD_KEY_LINES && from > 0; k++) from = Math.max(0, head.lastIndexOf('\n', from - 1));
  let open: 'opened' | 'named' | null = null;
  for (const raw of head.slice(from).split('\n')) {
    const r = readLine(raw);
    if (r.ends && !r.opensKey) open = null;
    else if (r.opensKey) open = 'opened';
    else if (r.namesKey && open === null) open = 'named';
  }
  return open;
}

/** `line` with its first `n` blank-separated tokens (and the blanks after them) taken off. Linear. */
function dropTokens(line: string, n: number): string {
  let i = 0;
  const blank = (k: number) => line[k] === ' ' || line[k] === '\t';
  while (i < line.length && blank(i)) i++;
  for (let t = 0; t < n && i < line.length; t++) {
    while (i < line.length && !blank(i)) i++;
    while (i < line.length && blank(i)) i++;
  }
  return line.slice(i);
}
/** Leading tokens the canonical passes drop at most: a per-line prefix such as buildkit's `#7 0.300`, `api-1  |` or `app:build:`. */
const MAX_PREFIX_TOKENS = 3;

/**
 * Fix round 2 (q1, q5): the canonical passes. Every line as shown (a dropped line as its first reading), with every non-printable taken
 * out (tabs, invisibles, LS/PS), is scrubbed over the whole log across lines, as it is and with its first 1 to MAX_PREFIX_TOKENS tokens
 * dropped (a container or monorepo tool's per-line prefix between two pieces of a wrapped value). Every line of a merged group is hidden.
 * Null when a pass can't map its output (fail closed).
 */
function canonicalPasses(lines0: Read[], scrub: (text: string) => string): Uint8Array | null {
  const hide = new Uint8Array(lines0.length);
  const canon = lines0.map((r) => stripChars(r.shown ?? r.rep).replace(LINE_SEPS, ''));
  for (let n = 0; n <= MAX_PREFIX_TOKENS; n++) {
    const res = scrubLines(n === 0 ? canon : canon.map((l) => dropTokens(l, n)), scrub);
    if (res === null) return null;
    for (const group of res.from) if (group.length > 1) for (const i of group) hide[i] = 1;
  }
  return hide;
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

/**
 * Steps 1-6 of errorExcerpt, without the secret scan: NOT safe to send, and no other src/ file may use it (test/excerpt-r1.test.ts).
 * Exported for the excerpt's tests (the scan only removes lines, so what holds here holds for errorExcerpt). `maxLogChars` replaces
 * MAX_LOG_CHARS in tests only.
 */
export function unscannedExcerpt(logs: string, scrub: (text: string) => string, testOpts: { maxLogChars?: number } = {}): string[] {
  const maxLogChars = testOpts.maxLogChars ?? MAX_LOG_CHARS;
  let text = String(logs);
  let guard = 0;
  let cut = false;
  let insideKey: 'opened' | 'named' | null = null;
  if (text.length > maxLogChars) {
    const from = text.indexOf('\n', text.length - maxLogChars);
    insideKey = headLeavesKeyOpen(from < 0 ? text : text.slice(0, from));
    text = from < 0 ? '' : text.slice(from + 1);
    guard = HEAD_GUARD_LINES;
    cut = true;
  }
  // Steps 1-3, and the hide rules. Every real line stays once, in place and untagged, in the text redact reads (a dropped line as its
  // first reading), so redact's own block and key rules link it to the lines around it (scan 5). A line is hidden when:
  // - step 3 drops it (an escape left, or a sequence glued between word characters), or it is in the head guard;
  // - its token next to a neighbour is MIN_SPLIT_PIECE characters or longer (edgeRun, as shown) and it or that neighbour is messy
  //   (dropped lines are messy): no reading of a messy line can be trusted (two insertions can need opposite readings, a sequence's
  //   payload can stand between two pieces of a value, the value passes pair forms index by index), so a value split across the two
  //   lines can't be checked;
  // - a value pass (valuePasses) finds part of a value in it, alone or with a neighbour (fix round 1, C1(a) and I1);
  // - a canonical pass (canonicalPasses) finds a value across it and other lines, with non-printables out and up to MAX_PREFIX_TOKENS
  //   leading tokens dropped (fix round 2: a value wrapped under per-line prefixes, or over 3 or more lines);
  // - redact, on one of its readings apart from the log (probeReadings), hides something on it;
  // - it is in a block, section or key a line before it opened:
  //   - an indented-value block: opened by a reading redact sees as one, or by any messy line (an inserted sequence can swallow a
  //     block opener's `:` or split its name); it goes on while any reading of a line is more indented or blank, or while garbage stands
  //     before a line's first printable character (indentIsUnsure); the parent of each suspect line (the nearest earlier line indented
  //     less; all the nearest 32 ancestors when its indentation is unsure) is probed too, so a block opened there is followed;
  //   - a secret section: opened by a reading redact sees as one, or by a messy line with Read.bracket; it ends only at a header that
  //     is not messy;
  //   - a private key: opened by a reading holding a BEGIN, or a messy line naming a key (NAMES_KEY), or a cut inside a key (the head
  //     read the same way, headLeavesKeyOpen); hidden up to the next END marker line (to the end of the log when a reading opened a
  //     key and no END follows), else while the lines look like armor (base64, armor headers, blank lines; a suspect line whose scrubbed readings
  //     hold a long base64 run counts as armor; a foreign line with armor within ARMOR_GAP lines after it is hidden and doesn't end
  //     the run). Armor mode also follows any other dropped line, and starts a cut tail. While armor mode lasts, an armor line is
  //     hidden even when it also starts a key hide (scan 4).
  // - its text is part of a value that spans lines (the whole-text scrub before redact merged it with a neighbour).
  const lines0 = text.split('\n').map(readLine);
  const parents = new Set<number>();
  const stack: { cols: number; i: number }[] = [];
  lines0.forEach((r, i) => {
    const own = r.shown ?? r.rep;
    if (r.suspect) {
      // the stack holds the ancestors, indentation rising; at most 32 of them are looked at (M2: a step count, not a match count)
      for (let k = stack.length - 1, steps = 0; k >= 0 && steps < 32; k--, steps++) {
        const e = stack[k] as { cols: number; i: number };
        if (e.cols < r.colsMax || r.indentUnsure) {
          if (!(lines0[e.i] as Read).suspect) parents.add(e.i);
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
  // each reading scrubbed first, as the log text is before redact, so a known value doesn't count as a redact hit
  const jobOf: number[][] = lines0.map((r, i) =>
    [...r.probe, ...(parents.has(i) ? [r.shown ?? r.rep] : [])].map((x) => jobs.push(scrub(x).split('\n').join(' ')) - 1));
  // a log made of garbage would need millions of probes: past the budget nothing is shown (fail closed)
  if (jobs.length > MAX_PROBES) return [];
  const probes = probeReadings(jobs);
  const valueHide = valuePasses(lines0, scrub);
  const canonHide = canonicalPasses(lines0, scrub);
  if (valueHide === null || canonHide === null) return [];
  // armor-shaped in some reading, or (a suspect line) its scrubbed readings hold a long base64 run (a sequence can leave a body line's
  // rest in no shape)
  const armorish = Uint8Array.from(lines0, (r, i) => (r.armor || (r.suspect && (jobOf[i] as number[]).some((j) => LONG_RUN.test(jobs[j] as string))) ? 1 : 0));
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
    if (insideKey !== null) startKeyHide(0, insideKey === 'opened');
    else armor = true;
  }
  const hiddenAt = lines0.map((r, i) => {
    let hidden = r.shown === null || i <= hideTo || i < guard || valueHide[i] === 1 || canonHide[i] === 1
      || [i - 1, i + 1].some((j) => {
        // a messy (or dropped) line, or a messy neighbour: no reading of a messy line can be trusted (two insertions can need opposite
        // readings, a sequence's payload can stand between two pieces of a value), so a long enough token at the shared edge may be a piece
        const y = lines0[j];
        return y !== undefined && (y.messy || r.messy) && edgeOf(r, j > i) >= MIN_SPLIT_PIECE;
      });
    if (blockCols >= 0) {
      if (r.indentUnsure || r.blank || r.colsMax > blockCols) hidden = true;
      else blockCols = -1;
    }
    if (section) {
      if (r.header && !r.messy) section = false;
      else hidden = true;
    }
    if (armor && i > hideTo) {
      // a foreign line inside a key body (parallel job output) doesn't end armor mode when armor follows within ARMOR_GAP lines: it is
      // hidden with the body
      const goesOn = armorish[i] === 1 || armorish.subarray(i + 1, i + 1 + ARMOR_GAP).includes(1);
      if (goesOn) hidden = true;
      if (!goesOn || r.ends) armor = false;
    }
    const verdict = (jobOf[i] as number[]).map((j) => probes[j] as Probe);
    if (verdict.some((p) => p.hit)) hidden = true;
    if (verdict.some((p) => p.block) || r.messy) blockCols = blockCols < 0 ? r.cols : Math.min(blockCols, r.cols);
    if (verdict.some((p) => p.section) || r.bracket) section = true;
    const opened = verdict.some((p) => p.key);
    if (i >= hideTo) {
      if ((r.namesKey || opened) && !r.ends) startKeyHide(i + 1, opened);
      else if (r.shown === null) armor = true;
    }
    return hidden;
  });
  // Scrub before redact can cut a value: the whole text once, or each line on its own when a value spans lines (no line count may
  // change before redact); then redact over the whole log, redactKeeps telling which input line each output line is (a count that
  // doesn't match fails closed); then the scrubber across lines again, and every output line built from a hidden line goes (fix round
  // 1, I3: scrubLines gives each output line its input lines, so no tag can be swallowed).
  const plain = lines0.map((r) => r.shown ?? r.rep);
  const pre = scrubLines(plain, scrub);
  if (pre === null) return [];
  let mainLines = pre.out;
  if (mainLines.length !== plain.length) {
    // a value across lines: redact could cut one piece and leave the other unmatched (a Basic auth header wrapped over two lines), so
    // every line of a merged group is hidden, and each line is scrubbed on its own for redact
    for (const group of pre.from) if (group.length > 1) for (const i of group) hiddenAt[i] = true;
    mainLines = plain.map((l) => scrub(l).split('\n').join(' '));
  }
  const redactedLines = redact(mainLines.join('\n')).split('\n');
  const kept = redactKeeps(mainLines);
  if (redactedLines.length !== kept.length) return [];
  const scrubbed = scrubLines(redactedLines, scrub);
  if (scrubbed === null) return [];
  const whole = scrubbed.out.filter((_, o) => !(scrubbed.from[o] as number[]).some((j) => hiddenAt[kept[j] as number] as boolean));
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
 * Ruling E0a-R5 (DECISIONS #113), the structural boundary: an excerpt is only ever built from a run whose scratch secrets were all
 * placeholders or pipegen's throwaway keys, never from a run that held a value the user typed. The evidence is an unforgeable brand
 * that only ScratchKeys (keys.ts) mints, through a ticket that brackets the run (E4 carry); a part that fails only once real keys
 * are in place is classified locally and never goes to the AI. errorExcerpt checks the brand at run time, so a cast, a copy or a
 * look-alike object can't get past it.
 */
export type { ExcerptEvidence };

/**
 * Throws unless `evidence` is an object ScratchKeys.evidence minted (E0a-R5) for this exact finished (run id, attempt), not
 * revoked by a later store of a user value (E4 fix rounds 1 and 2: M1, R1).
 */
function checkEvidence(evidence: unknown, runId: unknown, attempt: unknown): void {
  if (!isExcerptEvidence(evidence)) {
    throw new Error('errorExcerpt needs the evidence ScratchKeys mints for a run that held only placeholders or throwaway keys (ruling E0a-R5); nothing was built.');
  }
  if (!evidenceCovers(evidence, runId, attempt)) {
    throw new Error('errorExcerpt takes a log only of a run attempt its evidence was minted for (and not after a store of your values), and this log\'s run id and attempt are not one of them; nothing was built.');
  }
}

/**
 * The excerpt of a failing CI log that the fix loop may send to the AI (ruling B1; the steps are in this file's header). `scrub` is the
 * composed known-value scrubber; `evidence` is ruling E0a-R5's, and `opts.runId` / `opts.attempt` the run attempt the log comes
 * from, which the evidence must name (both checked first, before any work). The vault scrub, redact and the secret
 * scan stay as defence in depth. Throws when the evidence is wrong, or SecretScanError when the secret scan can't run or does not confirm
 * it read the excerpt: on any throw nothing may be sent.
 */
export async function errorExcerpt(logs: string, scrub: (text: string) => string, scanner: SecretScanner, evidence: ExcerptEvidence, opts: { runId: number; attempt: number; timeoutMs?: number }): Promise<string> {
  checkEvidence(evidence, opts?.runId, opts?.attempt);
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
