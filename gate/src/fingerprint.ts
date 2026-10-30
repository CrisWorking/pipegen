// Plan C Task C1b: fingerprints (preflight-scan B5, S10, S11). A wrong fingerprint makes a new finding look old (a false
// pass) or leaks a secret, so everything here is built to fail the other way:
//
// - Non-secrets (S10): sha256(tool \0 ruleId \0 uri \0 message). The tool's own partialFingerprints are never read. The line is
//   never part of it (the message loses the finding's own line numbers as whole tokens). A finding whose path could not be
//   mapped uses `unmapped:<uriId>` (a hash of the raw uri) so two different unmapped files are two findings. Image findings
//   (trivy-image) drop the image name and digest (no uri, no digest in the message); web findings (nuclei) drop scheme,
//   host and port; ZAP is pluginid \0 method \0 url path.
// - Secrets with a key (B5): `secret:` + HMAC-SHA256(key, tool \0 ruleId \0 bytes of the region in the scanned workspace file).
//   The scanner ran with --redact, so the SARIF holds no secret; the bytes come from the file the scanner read. If the region
//   cannot be read, the line form `secret:` + HMAC(key, 'line' \0 tool \0 ruleId \0 uri \0 line) is used and flagged (a moved
//   secret then looks new: fail closed).
// - Secrets without a key (a fork): `secret-nokey:` + sha256(tool \0 ruleId \0 uri \0 line); the gate judges these by the
//   added-line rule. Whether a missing key is allowed is the caller's (keyProblem).
//
// The region read (the only workspace read the scrub does, B5/S21) is data only: no link anywhere on the path (checked by
// lstat on every level, O_NOFOLLOW on the file, and, where /proc exists, the opened descriptor's real path must lie inside
// the workspace), a regular file, never blocking (O_NONBLOCK, FIFOs refused before the open), the region at most 64 KiB, and
// at most 16 MiB of the file scanned to reach it.
import { createHash, createHmac } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readlinkSync, readSync, realpathSync } from 'node:fs';
import { join, sep } from 'node:path';
import { maskText } from '../../src/ai/redact-core.js';
import type { ParsedFinding } from './parse-common.js';

export const FP_KEY_MIN = 32;
export const REGION_MAX_BYTES = 64 * 1024;
const FILE_SCAN_MAX = 16 * 1024 * 1024;

/**
 * How a fingerprint was made (written as `pipegenFpBy`, read back by C2). The forms differ in what they can see:
 * - content forms: `hash` (every non-secret: tool, rule, file, message), `region` (a secret: an HMAC over the bytes the
 *   scanner matched), `quoted` (an HMAC over a message that quotes a string) and `file` (C1c: a staged file the secrets scanner
 *   did not confirm it read, `secret:not-scanned`: an HMAC over the sha256 of the whole original file). The same text gives the
 *   same value wherever it moves, so C2 counts them per (tool, fingerprint) and an extra occurrence is new.
 * - position forms: `line` (a secret whose region could not be read, and every trivy secret: an HMAC of the place),
 *   `nokey` (a secret without a key, a fork: a hash of the place) and `quoted-nokey` (the same for a quoting rule). They hold
 *   no content, so a secret REPLACED in place keeps its value. C2 must read them as new when the count says so, or when any
 *   line of the finding is on an added line of the diff, or when it has no mapped repository file (review I1).
 */
export type FpBy = 'hash' | 'region' | 'quoted' | 'file' | 'line' | 'nokey' | 'quoted-nokey';
export const CONTENT_FORMS: readonly FpBy[] = Object.freeze(['hash', 'region', 'quoted', 'file'] as const);
export const POSITION_FORMS: readonly FpBy[] = Object.freeze(['line', 'nokey', 'quoted-nokey'] as const);
/** True for a fingerprint that holds no content of the finding (see FpBy). */
export const isPositionForm = (by: FpBy): boolean => POSITION_FORMS.includes(by);
export interface FpContext {
  /** PIPEGEN_FP_KEY. Empty or absent: the no-key form. A key that keyProblem refuses must not be passed (the caller stops first). */
  fpKey?: string;
  /** GITHUB_WORKSPACE as the scanners saw it: the folder the secret regions are read from. */
  workspace?: string;
  /** Called with the bytes of every region that was read (the scrub uses them to check that none reaches its output). */
  onRegion?: (bytes: Buffer) => void;
  /** The files read so far in this scrub (fingerprintAll makes one when this is absent). */
  cache?: RegionCache;
  /**
   * C1c, a staged scan: the region of a secret finding as the scanner read it, from the staged copy (the finding itself carries the
   * ORIGINAL file and line by then). When this gives a result, the workspace is not read for that finding.
   */
  regionOf?: (f: ParsedFinding) => RegionResult | undefined;
  /** C1c: the sha256 of the original file of a `secret:not-scanned` finding, which takes the `file` form. */
  fileHashOf?: (f: ParsedFinding) => string | undefined;
}
export interface FpResult {
  fingerprint: string;
  by: FpBy;
  /** Why the line form was used (never holds file text or the key). */
  note?: string;
}
export type FingerprintedFinding = ParsedFinding & { fingerprint: string; fpBy: FpBy; fpNote?: string };

const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
const hmac = (key: string, data: string | Buffer): string => createHmac('sha256', key).update(data).digest('hex');
/** A NUL would blur the field borders of a hashed record, so it is replaced in every field. */
const field = (s: string | number | undefined): string => (s === undefined ? '' : String(s).replaceAll('\0', '�'));

/** S11: a public id of the key (never the key): the first 8 bytes of HMAC-SHA256(key, "pipegen-key-id"), hex. */
export function keyId(key: string): string {
  return hmac(key, 'pipegen-key-id').slice(0, 16);
}

/**
 * Why `PIPEGEN_FP_KEY` cannot be used, or undefined. `needed`: the result holds a secret finding, or the tool is a secrets tool.
 * Empty on a non-fork event: missing (a writer deleting the secret must fail closed). Not empty and under 32 characters: too
 * short, on any event. A fork needs no key. The texts never hold the key.
 */
export function keyProblem(key: string | undefined, fork: boolean, needed: boolean): string | undefined {
  if (!needed) return undefined;
  if (key === undefined || key === '') {
    return fork ? undefined : 'PIPEGEN_FP_KEY is missing (an empty key is only allowed on a fork pull request), so secret fingerprints cannot be made';
  }
  if (key.length < FP_KEY_MIN) return `PIPEGEN_FP_KEY is too short: it needs at least ${FP_KEY_MIN} characters`;
  // printable ASCII without a quote or a backslash: JSON then writes the key as it is, so the last check of the scrub sees it
  return /^[\x20-\x7e]*$/.test(key) && !/["\\]/.test(key) ? undefined : 'PIPEGEN_FP_KEY must be printable ASCII without a double quote or a backslash';
}

// ---------- message ----------

/**
 * The text of a message or a name with everything secret-shaped masked: the shared core of redact.ts (src/ai/redact-core.ts:
 * token formats, JWTs, private keys, connection-string passwords, password-like assignments and the entropy belt per token).
 * A message may quote the matched text (bandit does for hard-coded passwords, semgrep for a metavariable); this is the same
 * guard for what is written and for what is hashed, so a fingerprint never covers a recognised secret. Not a secret scanner:
 * the secrets tools' messages are never carried at all.
 */
export const maskSecretShapes = (text: string): string => maskText(text);

/**
 * The message as it enters a fingerprint: whitespace collapsed, and the finding's own start and end line numbers removed
 * wherever they stand as a whole number (not part of a word, a version or a decimal), so a line shift cannot change it.
 */
export function normaliseMessage(message: string, lines: readonly number[]): string {
  const own = new Set(lines);
  return message.replace(/(?<![\w.])\d+(?!\w|\.\d)/g, (m) => (own.has(Number(m)) ? '' : m)).replace(/\s+/g, ' ').trim();
}

// ---------- the region ----------

/**
 * How a secrets tool's region columns map to bytes (measured on the pinned betterleaks 1.9.0 and gitleaks 8.30.1, C1b): both
 * count BYTES from 1 (not UTF-16 units, although SARIF says so; Go slices strings by byte) and write the end column
 * INCLUSIVE. gitleaks is one too high on every line after the first (its column counts the newline before the line), at the
 * start and at the end. A tool not listed here has columns that are placeholders or unmeasured: its region is never read.
 */
const COLUMN_RULES: Readonly<Record<string, { shiftAfterFirstLine: number }>> = Object.freeze(Object.assign(Object.create(null) as Record<string, { shiftAfterFirstLine: number }>, {
  betterleaks: { shiftAfterFirstLine: 0 },
  gitleaks: { shiftAfterFirstLine: 1 },
}));

export type RegionResult = { ok: true; bytes: Buffer } | { ok: false; reason: string };
/** A region and where it is in its file: bytes `[from, to)`. */
export type RegionSpan = { ok: true; bytes: Buffer; from: number; to: number } | { ok: false; reason: string };
const no = (reason: string): { ok: false; reason: string } => ({ ok: false, reason });

/** One workspace file as the region reader holds it: its bytes (at most FILE_SCAN_MAX), and the offsets of the line starts found so far. */
type FileRead = { ok: true; buf: Buffer; got: number; size: number; starts: number[]; atEnd: boolean } | { ok: false; reason: string };

/**
 * The files read during one scrub, by workspace path, so a file that many findings point into is read once (review m3: 2000
 * findings in a 16 MiB file took 25 s). The answer for a file that could not be read is kept as well. Bounded: past
 * CACHE_MAX_BYTES of buffers the cache starts again, so a result with findings in very many large files stays small.
 */
const CACHE_MAX_BYTES = 128 * 1024 * 1024;
export class RegionCache {
  private readonly files = new Map<string, FileRead>();
  private bytes = 0;
  get(file: string, load: () => FileRead): FileRead {
    const known = this.files.get(file);
    if (known !== undefined) return known;
    const made = load();
    if (made.ok) {
      if (this.bytes + made.buf.length > CACHE_MAX_BYTES) { this.files.clear(); this.bytes = 0; }
      this.bytes += made.buf.length;
    }
    this.files.set(file, made);
    return made;
  }
}

/** Opens one workspace file for the region reader: no link on the path, a regular file, never blocking, inside the workspace. Never throws. */
function loadWorkspaceFile(workspace: string, file: string): FileRead {
  const bad = (reason: string): FileRead => ({ ok: false, reason });
  let fd: number | undefined;
  try {
    const wsReal = realpathSync(workspace);
    // every level: no link, folders until the last, a regular file at the end (lstat does not follow)
    let cur = workspace;
    const parts = file.split('/').filter((x) => x !== '' && x !== '.');
    if (parts.length === 0) return bad('the path is not inside the workspace');
    let last = lstatSync(cur);
    for (const [i, part] of parts.entries()) {
      cur = join(cur, part);
      try {
        last = lstatSync(cur);
      } catch (e) {
        return bad((e as NodeJS.ErrnoException).code === 'ENOENT' ? 'the file is missing' : 'the file cannot be read');
      }
      if (last.isSymbolicLink()) return bad('the file or a folder on its path is a link');
      if (i < parts.length - 1 && !last.isDirectory()) return bad('a folder on the path is not a folder');
    }
    if (!last.isFile()) return bad('the path is not a regular file');
    try {
      fd = openSync(cur, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    } catch (e) {
      return bad((e as NodeJS.ErrnoException).code === 'ELOOP' ? 'the file or a folder on its path is a link' : 'the file cannot be opened');
    }
    const opened = fstatSync(fd);
    if (!opened.isFile()) return bad('the path is not a regular file');
    if (opened.dev !== last.dev || opened.ino !== last.ino) return bad('the file changed while it was opened');
    let real: string | undefined;
    try {
      real = readlinkSync(`/proc/self/fd/${fd}`).replace(/ \(deleted\)$/, '');
    } catch { /* no /proc here: the checks above are all there is */ }
    if (real !== undefined && !real.startsWith(wsReal + sep)) return bad('the opened file is outside the workspace');

    const want = Math.min(opened.size, FILE_SCAN_MAX);
    const buf = Buffer.alloc(want);
    let got = 0;
    while (got < want) {
      const n = readSync(fd, buf, got, want - got, got);
      if (n === 0) break;
      got += n;
    }
    return { ok: true, buf, got, size: opened.size, starts: [0], atEnd: false };
  } catch {
    return bad('the file cannot be read');
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

/** The offset where line `n` (1-based) starts, or undefined when the file has fewer lines (within what was read). */
function lineStart(f: Extract<FileRead, { ok: true }>, n: number): number | undefined {
  while (f.starts.length < n && !f.atEnd) {
    const nl = f.buf.indexOf(0x0a, f.starts[f.starts.length - 1]);
    if (nl === -1 || nl >= f.got) f.atEnd = true;
    else f.starts.push(nl + 1);
  }
  const at = f.starts[n - 1];
  return at === undefined || at >= f.got ? undefined : at;
}

/**
 * The bytes of the region of a secret finding in the workspace file it names, or why they cannot be read. Never throws.
 * `cache`: the files already read in this scrub (see RegionCache); without one, the file is read for this call only.
 */
export function readRegion(workspace: string, f: ParsedFinding, cache?: RegionCache): RegionResult {
  const span = regionSpan(workspace, f, cache);
  return span.ok ? { ok: true, bytes: span.bytes } : span;
}

/** readRegion, with the byte offsets of the region in its file (the staged scrub maps them back through the manifest, C1c). */
export function regionSpan(workspace: string, f: ParsedFinding, cache?: RegionCache): RegionSpan {
  const rule = Object.hasOwn(COLUMN_RULES, f.tool) ? COLUMN_RULES[f.tool] : undefined;
  if (rule === undefined) return no(`the columns of ${f.tool} are not known (they are placeholders there), so the region is not read`);
  const { line, startColumn, endColumn } = f;
  const endLine = f.endLine ?? line;
  if (line === undefined || startColumn === undefined || endColumn === undefined || endLine === undefined) return no('the finding has no complete region');
  const startCol = startColumn - (line >= 2 ? rule.shiftAfterFirstLine : 0);
  const endCol = endColumn - (endLine >= 2 ? rule.shiftAfterFirstLine : 0);
  if (endLine < line || startCol < 1 || endCol < 1 || (endLine === line && endCol < startCol)) return no('the region is empty or its end is before its start');
  const file = f.file;
  if (file === undefined || file === '' || file.startsWith('/') || file.includes('\0') || file.includes('\\') || file.split('/').some((x) => x === '..')) return no('the path is not inside the workspace');
  try {
    const read = (cache ?? new RegionCache()).get(file, () => loadWorkspaceFile(workspace, file));
    if (!read.ok) return no(read.reason);
    const first = lineStart(read, line);
    const last = lineStart(read, endLine);
    if (first === undefined || last === undefined) return no(read.got < read.size ? 'the region is too far into a large file' : 'the region is outside the file');
    const lineEnd = (at: number): number => {   // exclusive end of the line starting at `at` (before its newline)
      const nl = read.buf.indexOf(0x0a, at);
      return nl === -1 || nl >= read.got ? read.got : nl;
    };
    const from = first + startCol - 1;
    const to = last + endCol;   // end column inclusive: the exclusive offset is the column itself
    if (from >= lineEnd(first) || to > lineEnd(last)) return no('the region is outside the file');
    if (to - from > REGION_MAX_BYTES) return no('the region is over 64 KiB');
    if (to - from < 1) return no('the region is empty or its end is before its start');
    const bytes = Buffer.from(read.buf.subarray(from, to));
    // a NUL cannot be in text a scanner matched in a source file; it is the sign of a file the scanner and the scrub read differently (review C1)
    if (bytes.includes(0)) return no('the region holds a NUL byte');
    return { ok: true, bytes, from, to };
  } catch {
    return no('the file cannot be read');
  }
}

// ---------- fingerprints ----------

type Profile = 'file' | 'image' | 'web' | 'zap';
const PROFILES: Readonly<Record<string, Profile>> = Object.freeze(Object.assign(Object.create(null) as Record<string, Profile>, { 'trivy-image': 'image', nuclei: 'web', 'zap-baseline': 'zap' }));
const profileOf = (tool: string): Profile => (Object.hasOwn(PROFILES, tool) ? PROFILES[tool] : 'file');

/** The path part of an identity: the mapped file, `unmapped:<hash of the raw uri>`, or empty (no uri, or an image or a web target, which is not a repository file). */
function uriSlot(f: ParsedFinding): string {
  if (f.file !== undefined) return field(f.file);
  return f.uriUnmapped ? `unmapped:${field(f.uriId)}` : '';
}

/** The message with what is specific to the profile removed (an image digest, a web host); not masked, not normalised. */
function profileMessage(f: ParsedFinding, profile: Profile): string {
  let m = f.message;
  if (profile === 'image') m = m.replace(/@?\bsha256:[0-9a-fA-F]{16,}/g, '');
  if (profile === 'web') m = m.replace(/\bhttps?:\/\/[^\s/]+/gi, '').replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, '');
  return m;
}
const ownLines = (f: ParsedFinding): number[] => [f.line, f.endLine].filter((n): n is number => n !== undefined);

/** The message as it is hashed and written: profile-specific parts removed, everything secret-shaped masked (so no fingerprint covers a recognised secret), then normalised. */
function nonSecretMessage(f: ParsedFinding, profile: Profile): string {
  return normaliseMessage(maskSecretShapes(profileMessage(f, profile)), ownLines(f));
}

/**
 * Rules whose message quotes the matched string (bandit's hard-coded password checks): the message is a secret in all but name.
 * Its fingerprint is an HMAC over the message with the key (so two different strings in one file differ and nothing guessable is
 * hashed), and without a key it covers no message at all, only the line (so it is noisier, never weaker).
 */
const QUOTING_RULES: Readonly<Record<string, readonly string[]>> = Object.freeze(Object.assign(Object.create(null) as Record<string, readonly string[]>, { bandit: ['B105', 'B106', 'B107'] }));
export function isQuotingFinding(f: Pick<ParsedFinding, 'tool' | 'ruleId'>): boolean {
  return Object.hasOwn(QUOTING_RULES, f.tool) && QUOTING_RULES[f.tool].includes(f.ruleId);
}

/** The fingerprint of one finding (see the top of this file). Never throws; never returns a fingerprint that holds the key or any file text. */
export function fingerprintFinding(f: ParsedFinding, ctx: FpContext): FpResult {
  const profile = profileOf(f.tool);
  if (profile === 'zap') return { fingerprint: sha([field(f.ruleId), field(f.method), uriSlotZap(f)].join('\0')), by: 'hash' };
  if (!f.secret && isQuotingFinding(f)) {
    const base = [field(f.tool), field(f.ruleId), uriSlot(f)];
    const key = ctx.fpKey ?? '';
    return key === ''
      ? { fingerprint: `quoted-nokey:${sha([...base, field(f.line)].join('\0'))}`, by: 'quoted-nokey' }
      : { fingerprint: `quoted:${hmac(key, [...base, field(normaliseMessage(profileMessage(f, profile), ownLines(f)))].join('\0'))}`, by: 'quoted' };   // keyed, so the quoted string itself is covered: two strings in one file differ
  }
  if (!f.secret) {
    return { fingerprint: sha([field(f.tool), field(f.ruleId), profile === 'file' ? uriSlot(f) : '', field(nonSecretMessage(f, profile))].join('\0')), by: 'hash' };
  }
  const key = ctx.fpKey ?? '';
  const where = [field(f.tool), field(f.ruleId)];
  if (key === '') return { fingerprint: `secret-nokey:${sha([...where, uriSlot(f), field(f.line)].join('\0'))}`, by: 'nokey' };
  const fileHash = ctx.fileHashOf?.(f);
  if (fileHash !== undefined) return { fingerprint: `secret:${hmac(key, ['file', ...where, field(fileHash)].join('\0'))}`, by: 'file' };
  const staged = ctx.regionOf?.(f);
  let why: string;
  if (staged !== undefined) {
    if (staged.ok) {
      ctx.onRegion?.(staged.bytes);
      return { fingerprint: `secret:${hmac(key, Buffer.concat([Buffer.from(`${where.join('\0')}\0`), staged.bytes]))}`, by: 'region' };
    }
    why = staged.reason;
  } else if (f.file === undefined) why = 'the finding has no file in the workspace';
  else if (ctx.workspace === undefined || ctx.workspace === '') why = 'no workspace to read the region from';
  else {
    const region = readRegion(ctx.workspace, f, ctx.cache);
    if (region.ok) {
      ctx.onRegion?.(region.bytes);
      return { fingerprint: `secret:${hmac(key, Buffer.concat([Buffer.from(`${where.join('\0')}\0`), region.bytes]))}`, by: 'region' };
    }
    why = region.reason;
  }
  return { fingerprint: `secret:${hmac(key, ['line', ...where, uriSlot(f), field(f.line)].join('\0'))}`, by: 'line', note: `fingerprint by line: ${why}` };
}

/** ZAP (S10): the path of the alert's url, or `unmapped:<hash>` for a url it could not read, or empty for an alert with no instance. */
function uriSlotZap(f: ParsedFinding): string {
  return f.file !== undefined ? field(f.file) : f.uriUnmapped ? `unmapped:${field(f.uriId)}` : '';
}

/** Every finding with its fingerprint, how it was made (`fpBy`) and, for the line form, why (`fpNote`). */
export function fingerprintAll(findings: readonly ParsedFinding[], ctx: FpContext): FingerprintedFinding[] {
  const shared: FpContext = { ...ctx, cache: ctx.cache ?? new RegionCache() };
  return findings.map((f) => {
    const r = fingerprintFinding(f, shared);
    return { ...f, fingerprint: r.fingerprint, fpBy: r.by, ...(r.note === undefined ? {} : { fpNote: r.note }) };
  });
}
