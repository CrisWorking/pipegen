// Shared by the two scanner-result parsers (sarif.ts, zap.ts). Pure TypeScript: no Node import, no dependency, so the
// gate can bundle it (C6) and nothing here can touch a file, a process or the network.
//
// The input is hostile (preflight-scan S7): a PR author controls the code that was scanned, and a broken or compromised
// tool can write anything. So:
// - the text is parsed once, with no reviver;
// - only FIXED paths are read, each through `getOwn` (own properties only, never the prototype chain) and a type check;
//   a read field of the wrong type is a tool error, an unknown key is never walked, copied or merged;
// - attacker strings are looked up only in a Map or a null-prototype table, never as `obj[key]` on a plain object;
// - a parser never throws: anything it cannot read is a `toolError`, and a tool error never counts as clean.
import type { Finding } from '../../src/types.js';
import { safeText } from '../../src/util/safe-text.js';

export const MAX_RAW_BYTES = 64 * 1024 * 1024;
export const MAX_RESULTS_PER_RUN = 50_000;
export const MAX_RUNS = 20;
export const MAX_MESSAGE_CHARS = 2000;
export const MAX_ID_CHARS = 1024;
export const MAX_URI_CHARS = 4096;

export interface ParseLimits { maxBytes: number; maxResults: number; maxRuns: number }
export const DEFAULT_LIMITS: Readonly<ParseLimits> = Object.freeze({ maxBytes: MAX_RAW_BYTES, maxResults: MAX_RESULTS_PER_RUN, maxRuns: MAX_RUNS });
export function limitsFrom(partial: Partial<ParseLimits> | undefined): ParseLimits {
  return { ...DEFAULT_LIMITS, ...partial };
}

/**
 * What a parser returns for one result. It is a Finding without its fingerprint: the fingerprint is C1b's (HMAC for a
 * secret, a hash of tool, rule, path and message for the rest), and a finding with a made-up or empty fingerprint would
 * let every finding share one count. `uriUnmapped`: the result named a path that could not be mapped to a repository
 * file (so `file` is undefined and, for a secret on a fork, the finding counts as new). `method`: ZAP only.
 * For C1b: `secret` (the finding is a secret, by its tool or its tag), the rest of the region (`startColumn`, `endLine`,
 * `endColumn`, as the tool wrote them: the unit and the end rule are per tool, see fingerprint.ts) and `uriId`, a hash of the
 * raw uri of an unmapped finding (never the uri itself), so that two different unmapped files are not one finding.
 */
export interface ParsedFinding extends Omit<Finding, 'fingerprint'> {
  uriUnmapped: boolean; method?: string; secret: boolean; startColumn?: number; endLine?: number; endColumn?: number; uriId?: string;
}

/** `toolError` is set when the scan cannot be called clean (then `findings` is empty). `notes` are for people. */
export interface ParseResult { findings: ParsedFinding[]; toolError?: string; notes: string[] }

/** A read that failed: caught in `guarded`, turned into `toolError`. The message is built from structure, with any file text cleaned and cut. */
export class ReadError extends Error {}
export function fail(message: string): never {
  throw new ReadError(message);
}

/** Runs a reader; whatever it throws becomes a tool error (nothing is ever thrown to the caller). */
export function guarded(read: (notes: string[]) => ParsedFinding[]): ParseResult {
  const notes: string[] = [];
  try {
    return { findings: read(notes), notes };
  } catch (e) {
    return { findings: [], toolError: e instanceof ReadError ? e.message : 'the result could not be read (unexpected shape)', notes };
  }
}

/** The text of a result file as a string: the size cap first (bytes), then strict UTF-8. */
export function readText(input: string | Uint8Array, maxBytes: number): string {
  if (typeof input === 'string') {
    // bytes >= characters, and bytes <= 3 * characters (UTF-16 code unit to UTF-8)
    const size = input.length > maxBytes ? input.length : input.length * 3 <= maxBytes ? 0 : new TextEncoder().encode(input).byteLength;
    if (size > maxBytes) fail(`the result is over the size cap (${maxBytes} bytes)`);
    return input;
  }
  if (input.byteLength > maxBytes) fail(`the result is over the size cap (${maxBytes} bytes)`);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch {
    fail('the result is not valid UTF-8');
  }
}

/** JSON.parse once, no reviver. */
export function parseJsonOnce(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    fail('the result is not valid JSON');
  }
}

/** The bytes of a result file as parsed JSON (size cap, strict UTF-8, one parse), or the tool error saying why not. */
export function readJson(input: string | Uint8Array, maxBytes: number): { json: unknown; toolError?: undefined } | { toolError: string } {
  try {
    return { json: parseJsonOnce(readText(input, maxBytes)) };
  } catch (e) {
    return { toolError: e instanceof ReadError ? e.message : 'the result could not be read' };
  }
}

export type Obj = Record<string, unknown>;
export function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/** An own property or undefined: never the prototype chain, so `__proto__`, `constructor` and `toString` are only ever data. */
export function getOwn(o: Obj, key: string): unknown {
  return Object.hasOwn(o, key) ? o[key] : undefined;
}

/** What a failure message says about a file value: a short cleaned excerpt, never more. */
export function shown(v: unknown, max = 40): string {
  return typeof v === 'string' ? JSON.stringify(safeText(v, max)) : typeof v;
}

/** An optional string field: absent is undefined, any other type fails. */
export function optStr(o: Obj, key: string, where: string): string | undefined {
  const v = getOwn(o, key);
  if (v === undefined) return undefined;
  if (typeof v !== 'string') fail(`${where}: ${key} is not a string`);
  return v;
}
/** An optional nested object: absent is undefined, any other type (an array, a scalar, a deep structure) fails. */
export function optObj(o: Obj, key: string, where: string): Obj | undefined {
  const v = getOwn(o, key);
  if (v === undefined) return undefined;
  if (!isObj(v)) fail(`${where}: ${key} is not an object`);
  return v;
}
/** An optional list: absent is undefined, any other type fails. */
export function optList(o: Obj, key: string, where: string): unknown[] | undefined {
  const v = getOwn(o, key);
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) fail(`${where}: ${key} is not a list`);
  return v;
}
/** An optional list of strings. */
export function optStrList(o: Obj, key: string, where: string): string[] | undefined {
  const list = optList(o, key, where);
  if (list === undefined) return undefined;
  for (const item of list) if (typeof item !== 'string') fail(`${where}: ${key} holds a value that is not a string`);
  return list as string[];
}

/** A text cut to `max` UTF-16 units without splitting a surrogate pair. Raw otherwise: it is cleaned where it leaves pipegen. */
export function cutText(s: string, max = MAX_MESSAGE_CHARS): string {
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const last = cut.charCodeAt(cut.length - 1);
  return last >= 0xd800 && last <= 0xdbff ? cut.slice(0, -1) : cut;
}

/** A line number: a whole number from 1 to 2^31 - 1, else undefined. A value of another type fails. */
export function lineOf(v: unknown, where: string): number | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'number') fail(`${where}: the line is not a number`);
  return Number.isInteger(v) && v >= 1 && v <= 2 ** 31 - 1 ? v : undefined;
}

const K = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
/** sha256 of the UTF-8 bytes of a text, as hex. Plain TypeScript (no Node import, see the top of this file); tested against node:crypto. */
export function sha256Hex(text: string): string {
  const data = new TextEncoder().encode(text);
  const padded = new Uint8Array(((data.length + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor((data.length * 8) / 2 ** 32));
  view.setUint32(padded.length - 4, (data.length * 8) >>> 0);
  const h = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  return Array.from(h, (x) => x.toString(16).padStart(8, '0')).join('');
}

/** A short stable id of a raw uri that could not be mapped: 128 bits of its sha256, so the uri itself is never kept. */
export function uriIdOf(uri: string): string {
  return sha256Hex(uri.slice(0, MAX_URI_CHARS)).slice(0, 32);
}
