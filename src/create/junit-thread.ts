// The worker side of junit-worker.ts (v0.2 Plan E, E5, ruling S8): it decodes the bytes it is given as strict UTF-8 and runs the
// hardened parseJunit. It posts one message, { ok: true, cases } or { ok: false, error }, and never reads a file or the network.
// Nothing else imports this file; junit-worker.ts starts it as a worker_threads Worker with resourceLimits.
import { parentPort, workerData } from 'node:worker_threads';
import { parseJunit } from './junit.js';

if (parentPort !== null) {
  try {
    const data = workerData as { bytes?: unknown } | null;
    if (data === null || typeof data !== 'object' || !(data.bytes instanceof Uint8Array)) throw new Error('no report bytes given');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(data.bytes);
    parentPort.postMessage({ ok: true, cases: parseJunit(text) });
  } catch (e) {
    parentPort.postMessage({ ok: false, error: e instanceof Error ? e.message : 'the report could not be parsed' });
  }
}
