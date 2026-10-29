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
import type { ParsedFinding } from './parse-common.js';

export const FP_KEY_MIN = 32;
export const REGION_MAX_BYTES = 64 * 1024;
const FILE_SCAN_MAX = 16 * 1024 * 1024;

export type FpBy = 'hash' | 'region' | 'line' | 'nokey';
export interface FpContext {
  /** PIPEGEN_FP_KEY. Empty or absent: the no-key form. A key that keyProblem refuses must not be passed (the caller stops first). */
  fpKey?: string;
  /** GITHUB_WORKSPACE as the scanners saw it: the folder the secret regions are read from. */
  workspace?: string;
  /** Called with the bytes of every region that was read (the scrub uses them to check that none reaches its output). */
  onRegion?: (bytes: Buffer) => void;
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
  return key.length < FP_KEY_MIN ? `PIPEGEN_FP_KEY is too short: it needs at least ${FP_KEY_MIN} characters` : undefined;
}

// ---------- message ----------

const SHAPES: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bsk-[A-Za-z0-9_-]{20,}/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\bhttps:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
  /\bAIza[0-9A-Za-z_-]{35}/g,
  /\bnpm_[A-Za-z0-9]{36}/g,
  /\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}/g,
];
/**
 * The message of a finding with the well-known secret shapes replaced by [REDACTED]. A message may quote the matched text
 * (bandit does for hard-coded passwords); this is the same guard for what is written and for what is hashed, so a
 * fingerprint never covers a recognised token. Not a secret scanner: the secrets tools' messages are never carried at all.
 */
export function maskSecretShapes(text: string): string {
  let out = text;
  for (const re of SHAPES) out = out.replace(re, '[REDACTED]');
  return out;
}

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
const no = (reason: string): RegionResult => ({ ok: false, reason });

/** The bytes of the region of a secret finding in the workspace file it names, or why they cannot be read. Never throws. */
export function readRegion(workspace: string, f: ParsedFinding): RegionResult {
  const rule = Object.hasOwn(COLUMN_RULES, f.tool) ? COLUMN_RULES[f.tool] : undefined;
  if (rule === undefined) return no(`the columns of ${f.tool} are not known (they are placeholders there), so the region is not read`);
  const { line, startColumn, endColumn } = f;
  const endLine = f.endLine ?? line;
  if (line === undefined || startColumn === undefined || endColumn === undefined || endLine === undefined) return no('the finding has no complete region');
  const startCol = startColumn - (line >= 2 ? rule.shiftAfterFirstLine : 0);
  const endCol = endColumn - (endLine >= 2 ? rule.shiftAfterFirstLine : 0);
  if (endLine < line || startCol < 1 || endCol < 1 || (endLine === line && endCol < startCol)) return no('the region is empty or its end is before its start');
  const file = f.file;
  if (file === undefined || file === '' || file.startsWith('/') || file.includes('\0') || file.includes('\\') || file.split('/').some((s) => s === '..')) return no('the path is not inside the workspace');
  let fd: number | undefined;
  try {
    const wsReal = realpathSync(workspace);
    // every level: no link, folders until the last, a regular file at the end (lstat does not follow)
    let cur = workspace;
    const parts = file.split('/').filter((s) => s !== '' && s !== '.');
    if (parts.length === 0) return no('the path is not inside the workspace');
    let last = lstatSync(cur);
    for (const [i, part] of parts.entries()) {
      cur = join(cur, part);
      try {
        last = lstatSync(cur);
      } catch (e) {
        return no((e as NodeJS.ErrnoException).code === 'ENOENT' ? 'the file is missing' : 'the file cannot be read');
      }
      if (last.isSymbolicLink()) return no('the file or a folder on its path is a link');
      if (i < parts.length - 1 && !last.isDirectory()) return no('a folder on the path is not a folder');
    }
    if (!last.isFile()) return no('the path is not a regular file');
    try {
      fd = openSync(cur, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    } catch (e) {
      return no((e as NodeJS.ErrnoException).code === 'ELOOP' ? 'the file or a folder on its path is a link' : 'the file cannot be opened');
    }
    const opened = fstatSync(fd);
    if (!opened.isFile()) return no('the path is not a regular file');
    if (opened.dev !== last.dev || opened.ino !== last.ino) return no('the file changed while it was opened');
    let real: string | undefined;
    try {
      real = readlinkSync(`/proc/self/fd/${fd}`).replace(/ \(deleted\)$/, '');
    } catch { /* no /proc here: the checks above are all there is */ }
    if (real !== undefined && !real.startsWith(wsReal + sep)) return no('the opened file is outside the workspace');

    const want = Math.min(opened.size, FILE_SCAN_MAX);
    const buf = Buffer.alloc(want);
    let got = 0;
    while (got < want) {
      const n = readSync(fd, buf, got, want - got, got);
      if (n === 0) break;
      got += n;
    }
    // line starts (offsets) up to the end line
    const starts: number[] = [0];
    for (let at = 0; starts.length < endLine; ) {
      const nl = buf.indexOf(0x0a, at);
      if (nl === -1 || nl >= got) break;
      at = nl + 1;
      starts.push(at);
    }
    if (starts.length < endLine || starts[endLine - 1] >= got) return no(got < opened.size ? 'the region is too far into a large file' : 'the region is outside the file');
    const lineEnd = (n: number): number => {   // exclusive end of line n's content (before its newline)
      const nl = buf.indexOf(0x0a, starts[n - 1]);
      return nl === -1 || nl >= got ? got : nl;
    };
    const from = starts[line - 1] + startCol - 1;
    const to = starts[endLine - 1] + endCol;   // end column inclusive: the exclusive offset is the column itself
    if (from >= lineEnd(line) || to > lineEnd(endLine)) return no('the region is outside the file');
    if (to - from > REGION_MAX_BYTES) return no('the region is over 64 KiB');
    if (to - from < 1) return no('the region is empty or its end is before its start');
    return { ok: true, bytes: Buffer.from(buf.subarray(from, to)) };
  } catch {
    return no('the file cannot be read');
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
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

function nonSecretMessage(f: ParsedFinding, profile: Profile): string {
  let m = maskSecretShapes(f.message);
  if (profile === 'image') m = m.replace(/@?\bsha256:[0-9a-fA-F]{16,}/g, '');
  if (profile === 'web') m = m.replace(/\bhttps?:\/\/[^\s/]+/gi, '').replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/g, '');
  return normaliseMessage(m, [f.line, f.endLine].filter((n): n is number => n !== undefined));
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
      ? { fingerprint: `quoted-nokey:${sha([...base, field(f.line)].join('\0'))}`, by: 'nokey' }
      : { fingerprint: `quoted:${hmac(key, [...base, field(nonSecretMessage(f, profile))].join('\0'))}`, by: 'hash' };
  }
  if (!f.secret) {
    return { fingerprint: sha([field(f.tool), field(f.ruleId), profile === 'file' ? uriSlot(f) : '', field(nonSecretMessage(f, profile))].join('\0')), by: 'hash' };
  }
  const key = ctx.fpKey ?? '';
  const where = [field(f.tool), field(f.ruleId)];
  if (key === '') return { fingerprint: `secret-nokey:${sha([...where, uriSlot(f), field(f.line)].join('\0'))}`, by: 'nokey' };
  let why: string;
  if (f.file === undefined) why = 'the finding has no file in the workspace';
  else if (ctx.workspace === undefined || ctx.workspace === '') why = 'no workspace to read the region from';
  else {
    const region = readRegion(ctx.workspace, f);
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
  return findings.map((f) => {
    const r = fingerprintFinding(f, ctx);
    return { ...f, fingerprint: r.fingerprint, fpBy: r.by, ...(r.note === undefined ? {} : { fpNote: r.note }) };
  });
}
