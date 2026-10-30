// Plan C Task C1c: neutral-name staging for the secrets scan (review-C1b-r1 R1-C3, review-C1b-r2 R2-C1). Two doors let a pull
// request hide a live key from betterleaks and gitleaks while the gate passes:
//   - the default configs' PATH allowlists (node_modules/, package-lock.json, go.sum, *.svg, *.pdf, an unanchored gitleaks\.toml,
//     …): a key in such a path is never reported, and neither tool can switch that off from a config;
//   - in dir mode both skip any file they take for an archive, by its extension OR its first bytes.
// So the stage step (gate action, mode `stage`) copies every regular file of the checkout into a fresh runner-temp folder, under a
// neutral name `fNNNNNNNN.txt` (or one rule-target suffix, gate/src/generated/secrets-path-rules.ts), written as the audit writes
// what it scans (src/ai/scan-staging.ts, rulings P34-P38): a prefix line (no magic number starts with a newline), the original
// bytes, a blank line and a fresh canary line. A file larger than one chunk becomes overlapping pieces, each with its own prefix,
// canary and offset. The manifest maps every staged name back to the original path (raw bytes, base64), size, sha256, offset,
// line and canary. The scanner runs with its cwd in the staged folder (its ignore-file lookup uses the cwd, and the folder holds
// only neutral names), and the scrub (scrub.ts with `stage`) proves coverage: every staged file must have its own canary reported
// against it, exactly once; one without was not scanned and becomes a critical `secret:not-scanned` finding.
//
// The walk is by raw bytes (Buffer paths): a name that is not UTF-8 would make Node's string mode return its U+FFFD look-alike
// twice. Links are never followed and never staged (an in-repo target is staged at its own path). Only the root `.git` is left out.
// Above a file-count or a total-size cap the step stops and stages nothing (fail closed, said so).
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, rmSync, writeSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import {
  asScannedBytes, CANARY_RULE, isCanary, newCanary, originalLine, PIECE_BYTES, PIECE_OVERLAP_BYTES, planPieces, SCAN_CHUNK_SAFE_BYTES, SCAN_PREFIX, scannersWouldSkip, writtenCanaryLine, type Piece,
} from '../../src/ai/scan-staging.js';
import { RegionCache, regionSpan, type RegionResult } from './fingerprint.js';
import { PATH_RULES } from './generated/secrets-path-rules.js';
import type { ParsedFinding } from './parse-common.js';
import { normaliseUri } from './sarif.js';
import { PATH_SHOWN_MAX, safeText } from '../../src/util/safe-text.js';

/** At most this many regular files are staged; above it the step stages nothing and fails. */
export const MAX_STAGE_FILES = 200_000;
/** At most this many bytes in all (the original files); above it the step stages nothing and fails. Copying doubles the disk use. */
export const MAX_STAGE_BYTES = 1024 * 1024 * 1024;
/**
 * At most this many bytes written to the stage folder in all (fix round 1, I1): every file once, a large file also as its overlapping
 * pieces. The pieces write about 1.23 times the file for short lines (a piece of PIECE_BYTES advances by PIECE_BYTES minus the overlap),
 * but cuts fall on line ends, so with long regular lines a piece advances less: measured worst case (review-C1c-r1 n2) 2.31 times the
 * file at lines of about 46 KB (minified bundles), so up to about 3.3 times with the whole copy. The effective checkout cap for such
 * content is therefore about 750 MB, not 1 GiB; above it the step fails closed (a tool error) and removes what it wrote.
 */
export const MAX_STAGED_BYTES = 2.5 * 1024 * 1024 * 1024;
/** The manifest is read back by the scrub; a bigger one is refused. */
const MAX_MANIFEST_BYTES = 256 * 1024 * 1024;
/** Names have eight digits. */
const MAX_NAMES = 99_999_999;
export const STAGE_FILES_DIR = 'files';
export const STAGE_MANIFEST = 'manifest.json';
const MANIFEST_VERSION = 1;

export class StageError extends Error {}

// ---------- suffixes ----------

const RULES = PATH_RULES.map((r) => ({ ...r, re: new RegExp(r.pattern.replace(/^\(\?i\)/, ''), r.pattern.startsWith('(?i)') ? 'iu' : 'u') }));
/** Every suffix a staged name may have: the neutral `.txt` and the rule-target suffixes of the pinned path rules. */
export const STAGE_SUFFIXES: readonly string[] = Object.freeze(['.txt', ...new Set(PATH_RULES.flatMap((r) => r.suffixes))]);
const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
/** A staged name: `f`, eight digits, one suffix of STAGE_SUFFIXES. */
export const STAGED_NAME_RE = new RegExp(`^f\\d{8}(?:${STAGE_SUFFIXES.map(escape).join('|')})$`);

/**
 * The suffix the staged copy of `path` (repository-relative, raw bytes or text) gets: the suffix of the pinned path rule whose own
 * pattern matches the path (the listed suffix the name itself ends with, in any case, else the rule's first), or `.txt`. The rules'
 * patterns are tested on the ORIGINAL path, so a staged name fires exactly the path rules the original would have.
 */
export function suffixFor(path: Uint8Array | string): string {
  const text = typeof path === 'string' ? path : Buffer.from(path).toString('utf8');
  const lower = text.toLowerCase();
  const hits = new Set<string>();
  for (const r of RULES) {
    if (!r.re.test(text)) continue;
    hits.add(r.suffixes.find((s) => lower.endsWith(s)) ?? (r.suffixes[0] as string));
  }
  if (hits.size > 1) throw new StageError('two path rules of the pinned scanners target one file with different suffixes, which the stage step can not give it');
  return [...hits][0] ?? '.txt';
}

// ---------- the walk ----------

interface Found { abs: Buffer; rel: Buffer; size: number; dev: number; ino: number }
const SLASH = Buffer.from('/');
const GIT = Buffer.from('.git');

/** Every regular file under the workspace (raw-byte names, sorted per folder), the root `.git` left out, links never followed. */
function walk(ws: Buffer, maxFiles: number, maxBytes: number): { files: Found[]; links: number; other: number } {
  const files: Found[] = [];
  let links = 0;
  let other = 0;
  let bytes = 0;
  const visit = (abs: Buffer, rel: Buffer): void => {
    let names: Buffer[];
    try {
      names = readdirSync(abs, { encoding: 'buffer' });
    } catch {
      throw new StageError('a folder of the checkout can not be read, so the secrets scan would not cover it: nothing was staged');
    }
    names.sort(Buffer.compare);
    for (const name of names) {
      if (rel.length === 0 && name.equals(GIT)) continue;
      const a = Buffer.concat([abs, SLASH, name]);
      const r = rel.length === 0 ? name : Buffer.concat([rel, SLASH, name]);
      const st = lstatSync(a);
      if (st.isSymbolicLink()) links++;
      else if (st.isDirectory()) visit(a, r);
      else if (st.isFile()) {
        files.push({ abs: a, rel: r, size: st.size, dev: st.dev, ino: st.ino });
        bytes += st.size;
        if (files.length > maxFiles) throw new StageError(`the checkout has more than ${maxFiles} files, so pipegen does not stage it and the secrets scan does not run: it is not scanned (fail closed)`);
        if (bytes > maxBytes) throw new StageError(`the checkout has more than ${maxBytes} bytes of files, so pipegen does not stage it and the secrets scan does not run: it is not scanned (fail closed)`);
      } else other++;
    }
  };
  visit(ws, Buffer.alloc(0));
  return { files, links, other };
}

/** A file's bytes, never through a link, a regular file that is still the one the walk saw. */
function readFound(f: Found): Buffer {
  let fd: number | undefined;
  try {
    fd = openSync(f.abs, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    const st = fstatSync(fd);
    if (!st.isFile() || st.dev !== f.dev || st.ino !== f.ino || st.size !== f.size) throw new StageError('a file of the checkout changed while it was staged: nothing was staged');
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    if (got !== buf.length) throw new StageError('a file of the checkout changed while it was staged: nothing was staged');
    return buf;
  } catch (e) {
    if (e instanceof StageError) throw e;
    throw new StageError('a file of the checkout can not be read, so the secrets scan would not cover it: nothing was staged');
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

function writeNew(path: string, bytes: Uint8Array, mode: number): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
  try {
    let at = 0;
    while (at < bytes.length) at += writeSync(fd, bytes, at, bytes.length - at);
  } finally {
    closeSync(fd);
  }
}

const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
/** The lines a content spans (at least 1): its newlines, and one more when it does not end with one. */
const linesOf = (b: Uint8Array): number => {
  let n = 0;
  for (const c of b) if (c === 0x0a) n++;
  return Math.max(1, n + (b.length > 0 && b[b.length - 1] !== 0x0a ? 1 : 0));
};

/** A real folder (no link) that exists, or a new one made here (its parent must be a real folder). */
function ensureFolder(path: string, what: string): void {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    try { mkdirSync(path, { mode: 0o755 }); } catch { throw new StageError(`${what} can not be created`); }
    st = lstatSync(path);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new StageError(`${what} is not a real folder (a link or a file), so pipegen will not stage there`);
}

export interface StageOptions {
  /** GITHUB_WORKSPACE: the checkout. */
  workspace: string;
  /** `$RUNNER_TEMP/pipegen-stage/<artifact>`: must not exist yet. */
  stage: string;
  maxFiles?: number;
  maxBytes?: number;
  /** The cap on the bytes written (MAX_STAGED_BYTES). */
  maxStagedBytes?: number;
  /** Tests only: the piece size and overlap (the defaults are the shared core's). Never an action input (C5). */
  pieceBytes?: number;
  overlap?: number;
}
export type StageOutcome =
  | { status: 'ok'; files: number; staged: number; bytes: number; skippedLinks: number; skippedOther: number }
  | { status: 'error'; error: string };

/** One staged file (or piece) as the manifest records it. `path` is the original repository-relative path, raw bytes in base64. */
export interface ManifestEntry {
  name: string; path: string; size: number; sha256: string;
  offset: number; length: number; line: number; column: number; lines: number; canaryLine: number;
  canary: string; stagedSize: number; stagedSha256: string; piece: number; pieces: number; lateMagic?: true;
}

/**
 * Stages the checkout for the secrets scan (see the top of this file). Writes `<stage>/files/f00000001…` and `<stage>/manifest.json`
 * (the manifest last, so a step that stopped half way leaves none and the scrub fails closed), then makes all of it read-only (a
 * speed bump: no repository code runs in the secrets job; what guards it is the job rule and the scrub's check of the folder).
 */
export function stageWorkspace(o: StageOptions): StageOutcome {
  let made = false;
  try {
    if (!isAbsolute(o.workspace) || !isAbsolute(o.stage)) throw new StageError('the workspace and the stage folder must be absolute paths');
    const wsStat = lstatSync(o.workspace, { throwIfNoEntry: false });
    if (wsStat === undefined || wsStat.isSymbolicLink() || !wsStat.isDirectory()) throw new StageError('the workspace is not a real folder (missing, a link or a file)');
    const found = walk(Buffer.from(o.workspace), o.maxFiles ?? MAX_STAGE_FILES, o.maxBytes ?? MAX_STAGE_BYTES);
    // the caps held: only now is anything made
    ensureFolder(dirname(o.stage), 'the folder of the stage folders');
    try { mkdirSync(o.stage, { mode: 0o700 }); } catch { throw new StageError('the stage folder exists already or can not be created, so pipegen will not stage over it'); }
    made = true;
    const filesDir = join(o.stage, STAGE_FILES_DIR);
    mkdirSync(filesDir, { mode: 0o700 });
    const entries: ManifestEntry[] = [];
    let bytes = 0;
    let written = 0;
    const maxStaged = o.maxStagedBytes ?? MAX_STAGED_BYTES;
    for (const f of found.files) {
      const content = readFound(f);
      bytes += content.length;
      const suffix = suffixFor(f.rel);
      const hash = sha256(content);
      const pieces: Piece[] = planPieces(content, { ...(o.pieceBytes === undefined ? {} : { pieceBytes: o.pieceBytes }), ...(o.overlap === undefined ? {} : { overlap: o.overlap }) });
      // fix round 1, I1: a file of more than one piece is ALSO staged whole (piece 0): the pieces cover the scanner's own chunk cut (P36), the
      // whole copy what only the whole file shows: a composite rule whose component is far away, a multi-line key longer than the overlap
      const parts: { p: Piece; k: number }[] = [...(pieces.length > 1 ? [{ p: { offset: 0, length: content.length, line: 1, column: 0 }, k: 0 }] : []), ...pieces.map((p, i) => ({ p, k: i + 1 }))];
      for (const { p, k } of parts) {
        if (entries.length >= MAX_NAMES) throw new StageError('too many staged files for eight-digit names');
        const name = `f${String(entries.length + 1).padStart(8, '0')}${suffix}`;
        const canary = newCanary();
        const part = content.subarray(p.offset, p.offset + p.length);
        const out = asScannedBytes(part, canary);
        written += out.length;
        if (written > maxStaged) throw new StageError(`the stage folder would hold more than ${maxStaged} bytes (large files are staged whole and as pieces), so pipegen stops and the secrets scan does not run: it is not scanned (fail closed)`);
        writeNew(join(filesDir, name), out, 0o444);
        entries.push({
          name, path: f.rel.toString('base64'), size: content.length, sha256: hash,
          offset: p.offset, length: p.length, line: p.line, column: p.column, lines: linesOf(part), canaryLine: writtenCanaryLine(out),
          canary, stagedSize: out.length, stagedSha256: sha256(out), piece: k, pieces: pieces.length,
          ...(scannersWouldSkip(out) ? { lateMagic: true as const } : {}),
        });
      }
    }
    const manifest = {
      pipegenStage: MANIFEST_VERSION, prefixBytes: Buffer.byteLength(SCAN_PREFIX), canaryRule: CANARY_RULE,
      pieceBytes: o.pieceBytes ?? PIECE_BYTES, overlap: o.overlap ?? PIECE_OVERLAP_BYTES,
      skipped: { links: found.links, other: found.other }, files: entries,
    };
    writeNew(join(o.stage, STAGE_MANIFEST), Buffer.from(JSON.stringify(manifest)), 0o444);
    chmodSync(filesDir, 0o555);
    chmodSync(o.stage, 0o555);
    return { status: 'ok', files: found.files.length, staged: entries.length, bytes, skippedLinks: found.links, skippedOther: found.other };
  } catch (e) {
    // a step that stopped half way leaves nothing (no manifest was written, so the scrub would fail closed anyway)
    if (made) try { chmodTree(o.stage); rmSync(o.stage, { recursive: true, force: true }); } catch { /* the missing manifest still fails the scrub */ }
    return { status: 'error', error: e instanceof StageError ? e.message : 'the checkout could not be staged for the secrets scan, so it is not scanned' };
  }
}

/** Makes a half-written stage folder writable again, so it can be removed (only folders this step made). */
function chmodTree(dir: string): void {
  const st = lstatSync(dir, { throwIfNoEntry: false });
  if (st === undefined || st.isSymbolicLink() || !st.isDirectory()) return;
  chmodSync(dir, 0o700);
  for (const n of readdirSync(dir)) chmodTree(join(dir, n));
}

// ---------- reading the stage back (the scrub) ----------

/** Whether a folder listing holds exactly `names` (fix round 1, I2: each list sorted once, so linear after the sort). */
export function listingMatches(listed: readonly string[], names: readonly string[]): boolean {
  if (listed.length !== names.length) return false;
  const a = [...listed].sort();
  const b = [...names].sort();
  return a.every((n, i) => n === b[i]);
}

export interface Stage { dir: string; files: string; prefixBytes: number; entries: ManifestEntry[]; byName: Map<string, ManifestEntry> }

/** A regular file, no link, at most `max` bytes. */
function readPlain(path: string, max: number, what: string): Buffer {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (st === undefined) throw new StageError(`${what} is missing (the stage step did not finish)`);
  if (st.isSymbolicLink() || !st.isFile()) throw new StageError(`${what} is not a regular file`);
  if (st.size > max) throw new StageError(`${what} is over its size cap`);
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY);
    const o = fstatSync(fd);
    if (!o.isFile() || o.dev !== st.dev || o.ino !== st.ino) throw new StageError(`${what} changed while it was read`);
    const buf = Buffer.alloc(o.size);
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n === 0) break;
      got += n;
    }
    return buf.subarray(0, got);
  } catch (e) {
    if (e instanceof StageError) throw e;
    throw new StageError(`${what} can not be read`);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

const isInt = (v: unknown, min = 0): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min;
const HEX64 = /^[0-9a-f]{64}$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Reads and checks a stage folder for the scrub: the manifest (strict shape, names `f00000001…` in order), and the scan folder
 * holding exactly those files, each a regular file of the recorded size and sha256 (so the bytes the scrub reads are the ones the
 * stage step wrote and the scanner was given). Throws StageError.
 */
export function readStage(stage: string): Stage {
  if (!isAbsolute(stage)) throw new StageError('the stage folder is not an absolute path');
  for (const [p, what] of [[stage, 'the stage folder'], [join(stage, STAGE_FILES_DIR), 'the staged files folder']] as const) {
    const st = lstatSync(p, { throwIfNoEntry: false });
    if (st === undefined || st.isSymbolicLink() || !st.isDirectory()) throw new StageError(`${what} is missing or not a real folder`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(readPlain(join(stage, STAGE_MANIFEST), MAX_MANIFEST_BYTES, 'the stage manifest').toString('utf8'));
  } catch (e) {
    if (e instanceof StageError) throw e;
    throw new StageError('the stage manifest is not JSON');
  }
  const bad = (m: string): never => { throw new StageError(`the stage manifest ${m}`); };
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return bad('is not an object');
  const d = doc as Record<string, unknown>;
  if (d.pipegenStage !== MANIFEST_VERSION || d.prefixBytes !== Buffer.byteLength(SCAN_PREFIX) || d.canaryRule !== CANARY_RULE) bad('is not one this gate writes');
  if (!Array.isArray(d.files)) return bad('has no file list');
  const entries: ManifestEntry[] = d.files.map((x: unknown, i: number): ManifestEntry => {
    if (typeof x !== 'object' || x === null || Array.isArray(x)) return bad(`entry ${i + 1} is not an object`);
    const e = x as Record<string, unknown>;
    const name = e.name;
    if (typeof name !== 'string' || !STAGED_NAME_RE.test(name) || name.slice(0, 9) !== `f${String(i + 1).padStart(8, '0')}`) bad(`entry ${i + 1} has a name out of order or form`);
    if (typeof e.path !== 'string' || e.path === '' || !B64.test(e.path) || Buffer.from(e.path, 'base64').toString('base64') !== e.path) bad(`entry ${i + 1} has a path that is not base64`);
    for (const k of ['size', 'offset', 'length', 'column', 'stagedSize'] as const) if (!isInt(e[k])) bad(`entry ${i + 1} has a ${k} that is not a whole number`);
    for (const k of ['line', 'lines', 'canaryLine', 'pieces'] as const) if (!isInt(e[k], 1)) bad(`entry ${i + 1} has a ${k} that is not a positive whole number`);
    if (!isInt(e.piece)) bad(`entry ${i + 1} has a piece that is not a whole number`);
    // piece 0 is the whole copy of a file of several pieces (fix round 1, I1)
    if (e.piece === 0 && (e.offset !== 0 || e.length !== e.size || e.line !== 1 || e.column !== 0 || (e.pieces as number) < 2)) bad(`entry ${i + 1} is a whole copy that is not its whole file`);
    if (typeof e.sha256 !== 'string' || !HEX64.test(e.sha256) || typeof e.stagedSha256 !== 'string' || !HEX64.test(e.stagedSha256)) bad(`entry ${i + 1} has a hash that is not sha256`);
    if (typeof e.canary !== 'string' || !isCanary(e.canary)) bad(`entry ${i + 1} has a canary that is not a canary`);
    if ((e.offset as number) + (e.length as number) > (e.size as number) || (e.piece as number) > (e.pieces as number)) bad(`entry ${i + 1} has a piece outside its file`);
    if (e.lateMagic !== undefined && e.lateMagic !== true) bad(`entry ${i + 1} has an odd lateMagic`);
    return e as unknown as ManifestEntry;
  });
  const filesDir = join(stage, STAGE_FILES_DIR);
  const listed = readdirSync(filesDir, { encoding: 'buffer' }).map((b) => b.toString('latin1'));
  if (!listingMatches(listed, entries.map((e) => e.name))) throw new StageError('the staged files folder does not hold exactly the files of the manifest');
  for (const e of entries) {
    const b = readPlain(join(filesDir, e.name), e.stagedSize, `the staged file ${e.name}`);
    if (b.length !== e.stagedSize || sha256(b) !== e.stagedSha256) throw new StageError(`the staged file ${e.name} is not the one the stage step wrote`);
  }
  return { dir: stage, files: filesDir, prefixBytes: d.prefixBytes as number, entries, byName: new Map(entries.map((e) => [e.name, e])) };
}

// ---------- the scanner's findings, mapped back ----------

export const NOT_SCANNED_RULE = 'secret:not-scanned';
/**
 * gitleaks 8.30.1 counts a column one too high on every line after the first of the CHUNK it reads (fingerprint.ts COLUMN_RULES), and it
 * reads a file in 100,000-byte chunks cut at blank lines: on the FIRST line of each chunk (the line after a blank-line cut) the +1 is
 * dropped (measured, review-C1c-r1 n3). A piece fits one chunk, so the rule holds there; in the whole copy of a large file a finding's
 * chunk is not known, so no gitleaks column there is trusted: both readings are tried, and a region is never read from them.
 */
const shiftUnreliable = (tool: string, e: ManifestEntry): boolean => tool === 'gitleaks' && e.stagedSize > SCAN_CHUNK_SAFE_BYTES;
const CANARY_RULE_ID = `secret:${CANARY_RULE}`;

/** The original path of an entry as a finding carries it: the text when it is a plain UTF-8 path, else unmapped with a hash of its bytes. */
function pathFields(e: ManifestEntry): Pick<ParsedFinding, 'file' | 'uriUnmapped' | 'uriId' | 'displayPath'> {
  const raw = Buffer.from(e.path, 'base64');
  let text: string | undefined;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { text = undefined; }
  if (text !== undefined && normaliseUri(text, { encoding: 'raw' }) === text) return { file: text, uriUnmapped: false, uriId: undefined };
  // no lossless text for this name (not UTF-8, a control character, …): unmapped, told apart from any other file by its own bytes, with a
  // display form for people (fix round 1, m2), never used to match or fingerprint
  return { file: undefined, uriUnmapped: true, uriId: createHash('sha256').update(Buffer.concat([Buffer.from('pipegen-path-bytes\0'), raw])).digest('hex').slice(0, 32), displayPath: displayPathOf(raw) };
}

/**
 * A name's raw bytes as text a person can find the file by (fix round 1, m2): valid UTF-8 as itself, every byte that is not part of valid
 * UTF-8 and every control character as `\xNN`, U+FFFD as `\u{fffd}` (so `k\xff.js` and the real `k\u{fffd}.js` differ), a backslash
 * doubled; then cleaned by safeText. For display only: never a match key, never in a fingerprint.
 */
export function displayPathOf(raw: Uint8Array): string {
  const b = Buffer.from(raw);
  let out = '';
  let i = 0;
  while (i < b.length) {
    const c = b[i] as number;
    const len = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
    let ch: string | undefined;
    if (len > 0 && i + len <= b.length) {
      try { ch = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(i, i + len)); } catch { ch = undefined; }
    }
    if (ch === undefined) { out += `\\x${c.toString(16).padStart(2, '0')}`; i++; continue; }
    const cp = ch.codePointAt(0) as number;
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) out += `\\x${cp.toString(16).padStart(2, '0')}`;
    else if (cp === 0xfffd) out += '\\u{fffd}';
    else if (ch === '\\') out += '\\\\';
    else out += ch;
    i += len;
  }
  return safeText(out, PATH_SHOWN_MAX);
}

export interface StagedFindings {
  findings: ParsedFinding[];
  /** The region of each mapped secret finding, from the staged copy (fingerprint.ts FpContext.regionOf). */
  regionOf: (f: ParsedFinding) => RegionResult | undefined;
  /** The sha256 of the original file of each `secret:not-scanned` finding and each whole-file finding (FpContext.fileHashOf). */
  fileHashOf: (f: ParsedFinding) => string | undefined;
  notes: string[];
}

/**
 * The scanner's findings on a stage folder, as findings on the checkout (C1c):
 * - every finding must name a staged file of the manifest exactly, or the result is refused (StageError: a tool error);
 * - a `pipegen-canary` finding on a staged file's own canary line whose bytes are that file's canary is a coverage proof and is
 *   taken out; any other canary-rule finding is a real finding (P35);
 * - a staged file (or piece) without exactly one proof was not scanned: a critical `secret:not-scanned` finding over its lines;
 * - every other finding gets the original path and lines, its region is read from the staged copy (the bytes the scanner saw), and
 *   one found twice in the overlap of two pieces is kept once (same rule, same original bytes);
 * - a finding with no line is about the whole file (pkcs12-file fires on the path alone): once per file, fingerprinted by the
 *   original file's content (the `file` form), so a replaced certificate is new.
 */
export function applyStage(parsed: readonly ParsedFinding[], stage: Stage, tool: string): StagedFindings {
  const cache = new RegionCache();
  const proofs = new Map<string, number>();
  const real: { f: ParsedFinding; e: ManifestEntry }[] = [];
  for (const f of parsed) {
    const e = f.file === undefined ? undefined : stage.byName.get(f.file);
    if (e === undefined) throw new StageError('a finding names a file the stage step did not write, so it can not be mapped back to the checkout');
    if (f.ruleId === CANARY_RULE_ID && f.line === e.canaryLine && (f.endLine ?? f.line) === e.canaryLine) {
      const span = regionSpan(stage.files, f, cache);
      // gitleaks in the whole copy of a large file (measured live, fix round 1): the canary line follows a blank-line cut, so it may be
      // the first line of a chunk, where gitleaks drops its +1; its columns count at either reading
      const unshifted = shiftUnreliable(tool, e) && f.startColumn !== undefined && f.endColumn !== undefined
        ? regionSpan(stage.files, { ...f, startColumn: f.startColumn + 1, endColumn: f.endColumn + 1 }, cache) : undefined;
      if ((span.ok && span.bytes.toString('latin1') === e.canary) || (unshifted?.ok === true && unshifted.bytes.toString('latin1') === e.canary)) {
        proofs.set(e.name, (proofs.get(e.name) ?? 0) + 1);
        continue;
      }
    }
    real.push({ f, e });
  }
  // the pieces first, then the whole copies: a whole-copy finding a piece also reports (same rule, same ORIGINAL BYTE RANGE) is kept once,
  // from the piece. Never by line: two keys of one rule on one long line are two findings (review-C1c-r1 n1).
  real.sort((a, b) => (a.e.piece === 0 ? 1 : 0) - (b.e.piece === 0 ? 1 : 0));
  const pieceKeys = new Set<string>();
  const regions = new Map<ParsedFinding, RegionResult>();
  const hashes = new Map<ParsedFinding, string>();
  const out: ParsedFinding[] = [];
  const seen = new Set<string>();
  for (const { f, e } of real) {
    const span = regionSpan(stage.files, f, cache);
    const piece: Piece = { offset: e.offset, length: e.length, line: e.line, column: e.column };
    const line = f.line === undefined ? undefined : originalLine(piece, f.line, e.lines);
    const endLine = f.line === undefined ? undefined : originalLine(piece, f.endLine ?? f.line, e.lines);
    const at = (n: number): number => e.offset + Math.min(Math.max(n - stage.prefixBytes, 0), e.length);
    // a finding with no line is about the whole file (pkcs12-file fires on the name alone, line 0): one per file, by its content
    const whole = f.line === undefined;
    const key = whole ? `${f.ruleId}\0${e.path}\0whole`
      : span.ok ? `${f.ruleId}\0${e.path}\0${at(span.from)}\0${at(span.to)}` : `${f.ruleId}\0${e.path}\0${e.name}\0${f.line}\0${f.startColumn}\0${f.endLine}\0${f.endColumn}`;
    // gitleaks columns in a whole copy may be read either way (shiftUnreliable): the other reading (+1 on both columns) is that of a
    // first line of a chunk. Dropped only when that reading is exactly a piece finding's byte range; otherwise kept, in the line form.
    const alt = !whole && shiftUnreliable(tool, e) && f.startColumn !== undefined && f.endColumn !== undefined
      ? regionSpan(stage.files, { ...f, startColumn: f.startColumn + 1, endColumn: f.endColumn + 1 }, cache) : undefined;
    const altKey = alt?.ok === true ? `${f.ruleId}\0${e.path}\0${at(alt.from)}\0${at(alt.to)}` : undefined;
    if (seen.has(key) || (altKey !== undefined && pieceKeys.has(altKey))) continue;
    seen.add(key);
    if (e.piece !== 0 && !whole) pieceKeys.add(key);
    const { startColumn: _s, endColumn: _e, ...rest } = f;
    const mapped: ParsedFinding = { ...rest, ...pathFields(e), ...(line === undefined ? {} : { line }), ...(endLine === undefined ? {} : { endLine }) };
    if (mapped.uriId === undefined) delete mapped.uriId;
    if (whole) hashes.set(mapped, e.sha256);
    // a gitleaks finding only the whole copy of a large file has: its columns are not reliable there, so the line form (fail closed)
    else if (shiftUnreliable(tool, e)) regions.set(mapped, { ok: false, reason: 'gitleaks columns are not reliable in the whole copy of a large file (its +1 is dropped on the first line of each chunk)' });
    else regions.set(mapped, span.ok ? { ok: true, bytes: span.bytes } : { ok: false, reason: span.reason });
    out.push(mapped);
  }
  const unscanned = stage.entries.filter((e) => proofs.get(e.name) !== 1);
  for (const e of unscanned) {
    const f: ParsedFinding = {
      tool, ruleId: NOT_SCANNED_RULE, severity: 'critical', secret: true,
      message: `not scanned: the secrets scanner did not report this file's canary exactly once, so it may not have read it${e.lateMagic === true ? ' (it has a binary-format marker at a byte the scanners sniff)' : ''}`,
      ...pathFields(e), line: e.line, endLine: e.line + e.lines - 1,
    };
    if (f.uriId === undefined) delete f.uriId;
    hashes.set(f, e.sha256);
    out.push(f);
  }
  const notes = [`staged ${new Set(stage.entries.map((e) => e.path)).size} file(s) under neutral names as ${stage.entries.length} scanned piece(s)`];
  if (unscanned.length > 0) notes.push(`${unscanned.length} staged piece(s) not scanned (no canary reported): each is a critical not-scanned finding`);
  return { findings: out, regionOf: (f) => regions.get(f), fileHashOf: (f) => hashes.get(f), notes };
}
