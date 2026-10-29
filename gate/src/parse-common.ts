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
 */
export interface ParsedFinding extends Omit<Finding, 'fingerprint'> { uriUnmapped: boolean; method?: string }

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
