// Reading a JUnit report from a test run, as a worker (v0.2 Plan E, E5; ruling S8; the Plan D D8 carries).
// The XML is written by repo code, so it is hostile. parseJunit refuses what it can, but a parser that runs out of memory or time
// would take the whole CLI with it. This wrapper therefore:
//   1. checks the SIZE before reading: a file over the cap is refused from its size alone (stat, or the byte length of what
//      the download already holds), and its bytes are never decoded or handed to a parser;
//   2. parses in a worker_threads Worker with resourceLimits and a time limit, so running out of memory, a crash, a hang or a
//      reply that is not what the worker protocol says is a caught error;
//   3. turns every one of those into `{ ok: false, reason: 'report unreadable: ...' }`. A refusal, a timeout, a crash and a limit
//      hit are never a pass, and never "no results" either: the caller shows the reason as the result.
// The worker entry is the build's `junit-thread.js` next to this module (Plan G adds the tsup entry with the proof wiring). From
// the TypeScript sources there is none, so a caller may pass `workerUrl`; with neither, the report is unreadable (fails closed).
import { existsSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { Worker, type ResourceLimits } from 'node:worker_threads';
import { safeText } from '../util/safe-text.js';
import { MAX_JUNIT_BYTES, MAX_JUNIT_CASES, ID_MAX, type TestCaseResult } from './junit.js';

/** The worker's memory and stack limits. A parse that needs more is a caught ERR_WORKER_OUT_OF_MEMORY, not a crashed CLI. */
export const JUNIT_RESOURCE_LIMITS: Readonly<ResourceLimits> = Object.freeze({
  maxOldGenerationSizeMb: 1536, maxYoungGenerationSizeMb: 64, codeRangeSizeMb: 32, stackSizeMb: 4,
});
/** The most time a parse may take (parseJunit's slowest accepted shapes take about 3 s). */
export const JUNIT_TIMEOUT_MS = 30_000;

export type JunitRead = { ok: true; cases: TestCaseResult[] } | { ok: false; reason: string };
export interface JunitReadOptions {
  /** Tests only: a smaller size cap than MAX_JUNIT_BYTES (never a larger one). */
  maxBytes?: number;
  timeoutMs?: number;
  resourceLimits?: ResourceLimits;
  /** The worker entry (default: junit-thread.js next to this module). */
  workerUrl?: URL;
}

const PREFIX = 'report unreadable: ';
const unreadable = (why: string): JunitRead => ({ ok: false, reason: `${PREFIX}${safeText(why, 300)}` });
const STATUS = new Set(['pass', 'fail', 'skip']);

function capOf(opts: JunitReadOptions): number {
  const m = opts.maxBytes;
  return typeof m === 'number' && Number.isSafeInteger(m) && m >= 0 && m < MAX_JUNIT_BYTES ? m : MAX_JUNIT_BYTES;
}
const tooBig = (size: number, cap: number): string => `${size} bytes is over the ${cap}-byte limit, so it was not read`;

/** The worker's cases, checked again here: a list of { id, status } within the caps. Anything else is unreadable. */
function checked(message: unknown): JunitRead {
  if (typeof message !== 'object' || message === null) return unreadable('the parser sent an answer pipegen does not understand');
  const m = message as { ok?: unknown; cases?: unknown; error?: unknown };
  if (m.ok === false) return unreadable(typeof m.error === 'string' ? m.error : 'the parser refused it');
  if (m.ok !== true || !Array.isArray(m.cases) || m.cases.length > MAX_JUNIT_CASES) return unreadable('the parser sent an answer pipegen does not understand');
  const cases: TestCaseResult[] = [];
  for (const c of m.cases as unknown[]) {
    if (typeof c !== 'object' || c === null) return unreadable('the parser sent an answer pipegen does not understand');
    const { id, status } = c as { id?: unknown; status?: unknown };
    if (typeof id !== 'string' || id.length > ID_MAX * 4 || typeof status !== 'string' || !STATUS.has(status)) return unreadable('the parser sent an answer pipegen does not understand');
    cases.push({ id, status: status as TestCaseResult['status'] });
  }
  return { ok: true, cases };
}

function run(bytes: Uint8Array, opts: JunitReadOptions): Promise<JunitRead> {
  const url = opts.workerUrl ?? new URL('./junit-thread.js', import.meta.url);
  let present = false;
  try { present = url.protocol === 'file:' && existsSync(url); } catch { present = false; }
  if (!present) return Promise.resolve(unreadable('the report reader is not available in this build'));
  const timeoutMs = opts.timeoutMs ?? JUNIT_TIMEOUT_MS;
  return new Promise<JunitRead>((resolve) => {
    let done = false;
    let worker: Worker;
    const finish = (r: JunitRead): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      void worker?.terminate().catch(() => undefined);
      resolve(r);
    };
    const timer = setTimeout(() => finish(unreadable(`reading it took longer than ${Math.round(timeoutMs / 1000)} s`)), timeoutMs);
    try {
      // a copy: the caller's buffer is never handed over (or detached) by the worker
      worker = new Worker(url, { workerData: { bytes: Uint8Array.from(bytes) }, resourceLimits: { ...JUNIT_RESOURCE_LIMITS, ...opts.resourceLimits }, stdout: false, stderr: false });
    } catch (e) {
      finish(unreadable(`the parser could not start (${e instanceof Error ? e.message : 'unknown'})`));
      return;
    }
    worker.once('message', (m: unknown) => finish(checked(m)));
    worker.once('error', (e: unknown) => {
      const code = (e as { code?: unknown } | null)?.code;
      finish(unreadable(code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'the parser ran out of memory' : `the parser crashed (${e instanceof Error ? e.message : 'unknown'})`));
    });
    worker.once('exit', () => finish(unreadable('the parser stopped without an answer')));
  });
}

/** A report already in memory (a downloaded artifact file): over the cap is refused from its length alone, before any decoding. */
export function readJunitBytes(bytes: Uint8Array, opts: JunitReadOptions = {}): Promise<JunitRead> {
  if (!(bytes instanceof Uint8Array)) return Promise.resolve(unreadable('it is not a file'));
  const cap = capOf(opts);
  if (bytes.byteLength > cap) return Promise.resolve(unreadable(tooBig(bytes.byteLength, cap)));
  return run(bytes, opts);
}

/** A report on disk: the size is read from the open file first, and a file over the cap is never read. */
export async function readJunitFile(path: string, opts: JunitReadOptions = {}): Promise<JunitRead> {
  const cap = capOf(opts);
  let handle;
  try {
    handle = await open(path, 'r');
    const st = await handle.stat();
    if (!st.isFile()) return unreadable('it is not a regular file');
    if (st.size > cap) return unreadable(tooBig(st.size, cap));
    // read at most cap + 1 bytes: a file that grew after the stat is still caught
    const buf = Buffer.alloc(Math.min(st.size, cap) + 1);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    if (bytesRead > cap) return unreadable(tooBig(bytesRead, cap));
    return await run(buf.subarray(0, bytesRead), opts);
  } catch (e) {
    return unreadable(`the file could not be read (${e instanceof Error ? e.message : 'unknown'})`);
  } finally {
    await handle?.close().catch(() => undefined);
  }
}
