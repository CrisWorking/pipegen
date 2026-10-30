// Plan C Task C5a: the result artifacts the gate reads (rulings B4, S7, S15, S16; Review Focus 7). Everything about an artifact is hostile:
// the listing (any job of the run can upload, a fork's run can too), the zip, the bytes inside. The rules, in the order they are applied:
//   1. Only the exact expected name (resultArtifactName, from the trusted job list) is ever asked for; nothing else is listed or downloaded.
//   2. The listing (GET .../actions/runs/{this run}/artifacts?name=): exactly one artifact of that name (v4 names are unique in a run), of
//      THIS run, not expired, with a size within the cap. The size is checked from the metadata BEFORE any download.
//   3. The zip: exactly one entry, a regular file (no folder, no link, no device), a plain name (no `/`, `\`, `..`, NUL, leading dot) equal to
//      the expected file when the caller knows it, not encrypted, stored or deflated, no zip64, the headers agreeing with each other and
//      the bytes laid out with nothing in front or between, the inflated size within the cap (a zip bomb stops at the cap) and equal to
//      the header, the CRC right.
//   4. The sha256 of the file bytes (decide.ts compares it with the producing job's `-sha256` output) and the file read back strictly
//      (scrub.ts readScrubbed).
// Any failure is `tampered` (the gate blocks), never a guess. An artifact that is simply not there is `missing` (decide.ts says whether
// that blocks: a required result missing blocks, a non-blocking one is a note).
import { createHash } from 'node:crypto';
import { crc32, inflateRawSync } from 'node:zlib';
import type { ResultFile } from './decide.js';
import { readScrubbed, type ScrubFormat } from './scrub.js';

/** The scrubbed artifact as listed (ruling S7: scrubbed artifact at most 16 MiB). */
export const MAX_RESULT_ZIP_BYTES = 16 * 1024 * 1024;
/** The file inside it, inflated. */
export const MAX_RESULT_FILE_BYTES = 16 * 1024 * 1024;
/** A result file name as the renderer writes it (tool-flags.ts RESULT_FILE). */
const FILE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const natInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

// ---------- the listing ----------

export type Pick = { ok: true; id: number; size: number } | { ok: false; missing: boolean; problem: string };

/**
 * The one artifact named exactly `name` of run `runId` in a listing answer, before any download. `missing` when the answer holds none of
 * that name; any other problem (two of the name, another run, expired, no id or size, over the size cap, an answer that is not the API's
 * shape or is cut) is tampered.
 */
export function pickArtifact(listing: unknown, want: { name: string; runId: number; maxBytes?: number }): Pick {
  const bad = (problem: string): Pick => ({ ok: false, missing: false, problem });
  const max = want.maxBytes ?? MAX_RESULT_ZIP_BYTES;
  if (!isPlain(listing)) return bad('the artifact list is not an object');
  const list = own(listing, 'artifacts');
  if (!Array.isArray(list)) return bad('the artifact list has no artifacts');
  const total = own(listing, 'total_count');
  if (total !== undefined && (!natInt(total) || total > list.length)) return bad('the artifact list is cut (fewer entries than its total)');
  if (!list.every(isPlain)) return bad('an entry of the artifact list is not an object');
  const named = (list as Record<string, unknown>[]).filter((a) => own(a, 'name') === want.name);
  if (named.length === 0) return { ok: false, missing: true, problem: `no artifact named ${want.name}` };
  if (named.length > 1) return bad(`${named.length} artifacts are named ${want.name}`);
  const a = named[0] as Record<string, unknown>;
  const run = own(a, 'workflow_run');
  if (!isPlain(run) || own(run, 'id') !== want.runId) return bad('the artifact is not of this workflow run');
  if (own(a, 'expired') !== false) return bad('the artifact is expired or does not say');
  const id = own(a, 'id');
  const size = own(a, 'size_in_bytes');
  if (!posInt(id)) return bad('the artifact has no valid id');
  if (!natInt(size)) return bad('the artifact has no valid size');
  if (size > max) return bad(`the artifact is over the size cap (${max} bytes)`);
  return { ok: true, id, size };
}

// ---------- the zip ----------

export type ZipRead = { ok: true; name: string; bytes: Uint8Array } | { ok: false; problem: string };
const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;
const DD_SIG = 0x08074b50;

/**
 * The one regular file of a zip, checked as the header says (rule 3). `expectedFile`: the file name the result must have (the reviewed
 * entry's output file); `maxBytes`: the inflated cap (default MAX_RESULT_FILE_BYTES). Never throws.
 */
export function readZipEntry(zip: Uint8Array, opts: { expectedFile?: string; maxBytes?: number }): ZipRead {
  try {
    return readZip(zip, opts.maxBytes ?? MAX_RESULT_FILE_BYTES, opts.expectedFile);
  } catch {
    return { ok: false, problem: 'the zip could not be read' };
  }
}

function readZip(zip: Uint8Array, maxBytes: number, expectedFile: string | undefined): ZipRead {
  const bad = (problem: string): ZipRead => ({ ok: false, problem: `the zip is refused: ${problem}` });
  if (!(zip instanceof Uint8Array)) return bad('not bytes');
  const b = Buffer.from(zip.buffer, zip.byteOffset, zip.byteLength);
  if (b.length < 22 + 46 + 30) return bad('too short');
  // the end record: the last signature within the last 65,557 bytes whose comment runs exactly to the end of the file
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 0xffff); i--) {
    if (b.readUInt32LE(i) === EOCD_SIG && i + 22 + b.readUInt16LE(i + 20) === b.length) { eocd = i; break; }
  }
  if (eocd < 0) return bad('no end record');
  const disk = b.readUInt16LE(eocd + 4); const cdDisk = b.readUInt16LE(eocd + 6);
  const onDisk = b.readUInt16LE(eocd + 8); const total = b.readUInt16LE(eocd + 10);
  const cdSize = b.readUInt32LE(eocd + 12); const cdAt = b.readUInt32LE(eocd + 16);
  if (disk !== 0 || cdDisk !== 0) return bad('a multi-part zip');
  if (onDisk === 0xffff || total === 0xffff || cdSize === 0xffffffff || cdAt === 0xffffffff) return bad('a zip64 archive');
  if (onDisk !== 1 || total !== 1) return bad(`${total} entries, not exactly one`);
  if (cdAt + cdSize !== eocd) return bad('the central directory is not where the end record says');
  // the one central directory entry, which must fill the directory exactly
  const c = cdAt;
  if (b.readUInt32LE(c) !== CEN_SIG) return bad('no central directory entry');
  const madeBy = b.readUInt16LE(c + 4);
  const flags = b.readUInt16LE(c + 8);
  const method = b.readUInt16LE(c + 10);
  const crc = b.readUInt32LE(c + 16);
  const csize = b.readUInt32LE(c + 20);
  const usize = b.readUInt32LE(c + 24);
  const nameLen = b.readUInt16LE(c + 28); const extraLen = b.readUInt16LE(c + 30); const commentLen = b.readUInt16LE(c + 32);
  const diskStart = b.readUInt16LE(c + 34);
  const external = b.readUInt32LE(c + 38);
  const localAt = b.readUInt32LE(c + 42);
  if (46 + nameLen + extraLen + commentLen !== cdSize) return bad('the central directory holds more than one entry');
  if (diskStart !== 0) return bad('a multi-part zip');
  if (csize === 0xffffffff || usize === 0xffffffff || localAt === 0xffffffff) return bad('zip64 sizes');
  if ((flags & 0x01) !== 0 || (flags & 0x40) !== 0) return bad('an encrypted entry');
  if (method !== 0 && method !== 8) return bad('a compression method other than stored or deflate');
  const nameBytes = b.subarray(c + 46, c + 46 + nameLen);
  const name = nameBytes.toString('utf8');
  if (!Buffer.from(name, 'utf8').equals(nameBytes)) return bad('the entry name is not UTF-8');
  if (!FILE_NAME_RE.test(name)) return bad('the entry is not a plain file name (a path, a folder, a link name or a hidden name)');
  if (expectedFile !== undefined && name !== expectedFile) return bad('the entry is not the expected result file');
  const host = madeBy >> 8;
  const mode = external >>> 16;
  if (host === 3 && (mode & S_IFMT) !== 0 && (mode & S_IFMT) !== S_IFREG) return bad('the entry is not a regular file (a link, a folder or a device)');
  if ((external & 0x10) !== 0) return bad('the entry is a folder');
  // the local header: at the very start, agreeing with the directory
  if (localAt !== 0) return bad('bytes in front of the entry');
  if (b.readUInt32LE(0) !== LOC_SIG) return bad('no local header');
  const lflags = b.readUInt16LE(6);
  const lmethod = b.readUInt16LE(8);
  const lname = b.readUInt16LE(26); const lextra = b.readUInt16LE(28);
  if (lflags !== flags || lmethod !== method) return bad('the local header disagrees with the directory');
  if (!b.subarray(30, 30 + lname).equals(nameBytes)) return bad('the local header names another file');
  const dataAt = 30 + lname + lextra;
  const dataEnd = dataAt + csize;
  if (dataEnd > cdAt) return bad('the entry runs past the central directory');
  const descriptor = (flags & 0x08) !== 0;
  if (!descriptor) {
    if (b.readUInt32LE(14) !== crc || b.readUInt32LE(18) !== csize || b.readUInt32LE(22) !== usize) return bad('the local header sizes disagree with the directory');
    if (dataEnd !== cdAt) return bad('bytes between the entry and the central directory');
  } else {
    const rest = cdAt - dataEnd;
    const at = dataEnd;
    const withSig = rest === 16 && b.readUInt32LE(at) === DD_SIG;
    const off = withSig ? 4 : rest === 12 ? 0 : -1;
    if (off < 0) return bad('bytes between the entry and the central directory');
    if (b.readUInt32LE(at + off) !== crc || b.readUInt32LE(at + off + 4) !== csize || b.readUInt32LE(at + off + 8) !== usize) return bad('the data descriptor disagrees with the directory');
  }
  // the bytes: within the cap (inflation stops there), the size and the CRC as declared
  if (usize > maxBytes) return bad('the file is over the size cap');
  const raw = b.subarray(dataAt, dataEnd);
  let data: Buffer;
  if (method === 0) {
    if (csize !== usize) return bad('a stored entry whose sizes differ');
    data = Buffer.from(raw);
  } else {
    try { data = inflateRawSync(raw, { maxOutputLength: Math.max(1, Math.min(maxBytes, usize + 1)) }); } catch { return bad('the file does not inflate within its declared size and the size cap (a zip bomb, or broken data)'); }
  }
  if (data.length !== usize) return bad('the inflated size is not the declared size');
  if (crc32(data) !== crc) return bad('the CRC does not match');
  return { ok: true, name, bytes: new Uint8Array(data) };
}

// ---------- reading one result ----------

/** The reads a result needs (the GitHub adapter, or a fake). */
export interface ResultIo {
  /** `GET /repos/{owner}/{name}/actions/runs/{runId}/artifacts?name={artifactName}`. */
  listRunArtifacts(owner: string, name: string, runId: number, artifactName: string): Promise<unknown>;
  /** The zip bytes of an artifact, at most `maxBytes` (`GET .../actions/artifacts/{id}/zip`). */
  artifactZip(owner: string, name: string, id: number, maxBytes: number): Promise<Uint8Array>;
}
export type Download = { kind: 'missing' } | { kind: 'file'; file: ResultFile };

const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
const tamperedFile = (problem: string): Download => ({ kind: 'file', file: { sha256: '', read: { findings: [], notes: [] }, problem } });

/**
 * One result artifact of this run, by its exact name: `missing` when the listing has none of that name; otherwise a file, whose
 * `problem` is set when any check failed (decide.ts calls it tampered).
 */
export async function downloadResult(io: ResultIo, want: { owner: string; repo: string; runId: number; name: string; format: ScrubFormat; expectedFile?: string }): Promise<Download> {
  let listing: unknown;
  try { listing = await io.listRunArtifacts(want.owner, want.repo, want.runId, want.name); } catch { return tamperedFile('the artifact list could not be read'); }
  const pick = pickArtifact(listing, { name: want.name, runId: want.runId });
  if (!pick.ok) return pick.missing ? { kind: 'missing' } : tamperedFile(pick.problem);
  let zip: Uint8Array;
  try { zip = await io.artifactZip(want.owner, want.repo, pick.id, MAX_RESULT_ZIP_BYTES); } catch { return tamperedFile('the artifact could not be downloaded'); }
  if (!(zip instanceof Uint8Array) || zip.length > MAX_RESULT_ZIP_BYTES) return tamperedFile('the artifact download is not bytes within the size cap');
  const entry = readZipEntry(zip, want.expectedFile === undefined ? {} : { expectedFile: want.expectedFile });
  if (!entry.ok) return tamperedFile(entry.problem);
  return { kind: 'file', file: { sha256: sha256(entry.bytes), read: readScrubbed(entry.bytes, want.format, MAX_RESULT_FILE_BYTES) } };
}
