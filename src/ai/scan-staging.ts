// The pure scan-staging core (C1c), shared by the audit's secret pass before `audit --ai` (src/ai/redact.ts, rulings P30-P38)
// and the gate's staged secrets scan (gate/src/stage.ts): how a file is written for the secret scanners (a prefix line, the
// content, a blank line, a fresh canary line), the canary's shape, the chunk size both pinned scanners read whole, the late
// magic numbers they sniff, and how a file larger than one chunk is cut into overlapping pieces.
//
// A leaf: no import of any kind (test/scan-staging-core.test.ts). Buffer and crypto.getRandomValues are globals of Node.

/**
 * Ruling P30 (Task 7 review C1): both pinned scanners sniff a file's first bytes and silently skip one that looks like a binary
 * or archive format (%PDF-, MZ, PK\x03\x04, \x1f\x8b, …), with a clean exit. So every scanned file is written after this
 * prefix (one empty line: no magic number starts with a newline), and every reported line is moved back by the lines it adds.
 */
export const SCAN_PREFIX = '\n';
export const PREFIX_LINES = 1;

/**
 * Task 7 re-review R1: the prefix only helps for magic numbers at byte 0. Both scanners also sniff a few formats at a fixed
 * later byte of the file as written (tar's `ustar` at 257, DICOM's `DICM` at 128, ISO 9660's `CD001` at 32769, 34817 and
 * 36865) and skip such a file with a clean exit.
 */
export const LATE_MAGIC: ReadonlyArray<readonly [number, string]> = Object.freeze([[257, 'ustar'], [128, 'DICM'], [32769, 'CD001'], [34817, 'CD001'], [36865, 'CD001']] as const);

/** True when the file as written has one of LATE_MAGIC at its byte: the scanners would skip it. */
export function scannersWouldSkip(written: string | Uint8Array): boolean {
  const buf = typeof written === 'string' ? Buffer.from(written, 'utf8') : Buffer.from(written.buffer, written.byteOffset, written.byteLength);
  return LATE_MAGIC.some(([at, magic]) => buf.subarray(at, at + magic.length).toString('latin1') === magic);
}

/**
 * Ruling P34 (final review I2): a scanner can skip a file and still exit clean, and the causes keep coming (magic bytes at
 * offset 0 (P30) or later (R1), a path on the default allowlist, a size limit). So every scanned file ends with one line holding
 * a fresh random canary that the `pipegen-canary` rule reports, and a file counts as scanned only when its own canary came back
 * reported against it, exactly once. The canary goes AFTER the content, behind a blank line (so it never joins the content's last
 * line), so the reported lines of real findings don't move.
 * Rulings P35/P37: the rule matches only a whole line that is exactly one token, and repo text is not rewritten.
 */
export const CANARY_RULE = 'pipegen-canary';
const CANARY_HEX = 32;
/** The length of a canary token. */
export const CANARY_LENGTH = CANARY_RULE.length + 1 + CANARY_HEX;
const CANARY_RE = /^pipegen-canary-[0-9a-f]{32}$/;
/** A fresh canary: `pipegen-canary-` and 32 random hex digits (16 bytes from the platform's CSPRNG). */
export function newCanary(): string {
  const bytes = new Uint8Array(CANARY_HEX / 2);
  globalThis.crypto.getRandomValues(bytes);
  return `${CANARY_RULE}-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}
/** True for a text that is exactly one canary token. */
export const isCanary = (text: string): boolean => CANARY_RE.test(text);
/**
 * The rule both scanners are given (TOML, appended to `[extend] useDefault = true`): it reports a canary line. Not a secret: its
 * findings are taken out before any real finding is used. Same regex as data/gitleaks-bundle.toml's (a test compares them).
 */
export const CANARY_RULE_TOML = `[[rules]]
id = "${CANARY_RULE}"
description = "pipegen scan marker (proves the file was read)"
regex = '''(?m)^pipegen-canary-[0-9a-f]{32}$'''
keywords = ["pipegen-canary-"]
`;

/** A file as the scanner sees it: the prefix, the content, a blank line, the canary on its own line. */
export const asScanned = (content: string, canary: string): string => `${SCAN_PREFIX}${content}${content === '' || content.endsWith('\n') ? '' : '\n'}\n${canary}\n`;
/** asScanned on bytes (any bytes, not only UTF-8): what the gate's stage step writes. */
export function asScannedBytes(content: Uint8Array, canary: string): Buffer {
  const needsNewline = content.length > 0 && content[content.length - 1] !== 0x0a;
  return Buffer.concat([Buffer.from(SCAN_PREFIX), content, Buffer.from(`${needsNewline ? '\n' : ''}\n${canary}\n`)]);
}
/** The canary's line in `written` (asScanned's text), as a finding reports it after the prefix lines are taken off: its last line. */
export const canaryLine = (written: string): number => {
  let n = 0;
  for (let i = written.indexOf('\n'); i >= 0; i = written.indexOf('\n', i + 1)) n++;
  return n - PREFIX_LINES;
};
/** The canary's line in a file asScannedBytes wrote, counted as the scanner counts it (the prefix line is line 1). */
export function writtenCanaryLine(written: Uint8Array): number {
  let n = 0;
  for (const c of written) if (c === 0x0a) n++;
  return n;
}

/**
 * Ruling P36 (P34 verify review I-A): both pinned scanners read a file in 100,000-byte chunks, each stretched by up to 25,000 bytes
 * to the next blank line, and otherwise cut at byte 125,000 even mid-line: a secret across that cut is in neither piece and is
 * never found, while the canary at the end is still reported. A file of at most one chunk is read as one piece, so a file is only
 * scanned whole when its copy AS WRITTEN (prefix, content, canary line) is at most this many bytes: one chunk minus a 10% margin.
 * Ruling P38: test/secret-scan-skip-live.test.ts "P38 pin" checks this live on both pinned scanners.
 */
export const SCAN_CHUNK_SAFE_BYTES = 90_000;

/** The most asScannedBytes adds to a content: the prefix, a newline to end the content, the blank line and the canary line. */
export const SCAN_OVERHEAD_BYTES = SCAN_PREFIX.length + 1 + 1 + CANARY_LENGTH + 1;
/** The largest content one piece holds, so that the piece as written is at most SCAN_CHUNK_SAFE_BYTES. */
export const PIECE_BYTES = SCAN_CHUNK_SAFE_BYTES - SCAN_OVERHEAD_BYTES;

/**
 * C1c: how many bytes two neighbouring pieces of a large file share. Any run of at most this many bytes lies wholly inside one
 * piece, and a cut falls on a line end whenever a line end is in reach, so a single-line match is only ever cut on a line longer
 * than PIECE_BYTES minus this. 16 KiB: above the 8 KiB floor of the C1c ruling and above the longest bounded match of any rule of
 * the two pinned default configs (gate/src/generated/secrets-path-rules.ts records it, a test compares), and it holds a
 * 16384-bit RSA private key in PEM (about 12.7 KB), the longest multi-line secret of the unbounded rules seen in practice. The
 * scanners themselves give a whole file no overlap at all at their own 125,000-byte cut (P36).
 */
export const PIECE_OVERLAP_BYTES = 16 * 1024;

/** One piece of a file: its bytes `[offset, offset + length)`, the 1-based line of its first byte and that byte's 0-based column. */
export interface Piece { offset: number; length: number; line: number; column: number }

/**
 * The pieces a file is scanned in (C1c). A file of at most `pieceBytes` is one piece. A larger one is cut into pieces of at most
 * `pieceBytes`, each sharing at least `overlap` bytes with the next one. A piece ends at a line end when one lies past the first
 * `overlap` bytes of the piece, and the next one starts at the last line start that keeps the overlap; on a line too long for
 * that the cut falls mid-line. Linear in the file.
 */
export function planPieces(content: Uint8Array, opts: { pieceBytes?: number; overlap?: number } = {}): Piece[] {
  const size = content.length;
  const P = opts.pieceBytes ?? PIECE_BYTES;
  const O = opts.overlap ?? PIECE_OVERLAP_BYTES;
  if (!Number.isInteger(P) || !Number.isInteger(O) || O < 1 || P <= 2 * O) throw new Error('planPieces: the piece size must be more than twice the overlap');
  if (size <= P) return [{ offset: 0, length: size, line: 1, column: 0 }];
  const buf = Buffer.from(content.buffer, content.byteOffset, content.byteLength);
  const pieces: Piece[] = [];
  // the line and column of `start`, kept up to date as start moves forward
  let start = 0;
  let line = 1;
  let lineStart = 0;
  for (;;) {
    let end = Math.min(start + P, size);
    if (end < size) {
      // the last line end in (start + O, end]: a line start there is a cut that splits no line
      const nl = buf.lastIndexOf(0x0a, end - 1);
      if (nl >= start + O) end = nl + 1;
    }
    pieces.push({ offset: start, length: end - start, line, column: start - lineStart });
    if (end >= size) return pieces;
    // the next piece starts at the last line start at or before end - O (and after start); else mid-line at end - O
    const limit = end - O;
    const nl = buf.lastIndexOf(0x0a, limit - 1);
    const next = nl >= start ? nl + 1 : limit;
    for (let i = buf.indexOf(0x0a, start); i >= 0 && i < next; i = buf.indexOf(0x0a, i + 1)) { line++; lineStart = i + 1; }
    start = next;
  }
}

/**
 * The line of the original file that line `writtenLine` of a piece as written stands for (the prefix line is line 1).
 * `contentLines` is the number of lines the piece's content spans. A line on the prefix maps to the piece's first line, and a
 * line past the content (the blank line, the canary) to its last.
 */
export function originalLine(piece: Piece, writtenLine: number, contentLines: number): number {
  const inPiece = Math.min(Math.max(writtenLine - PREFIX_LINES, 1), Math.max(contentLines, 1));
  return piece.line + inPiece - 1;
}
