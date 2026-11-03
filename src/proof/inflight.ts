// Plan E E4 (E0b carry; ruling B2; threat T12): the writes a proof has in flight. A Ctrl-C starts E8's cleanup while the
// proof's own code may still be awaiting a write it already sent: a secret store, a PR create or merge, a push. If the
// cleanup listed the scratch secrets (or PRs, or branches) before that write landed, the write would land after the
// cleanup and stay behind. So every such write is registered here, synchronously before its request starts, and removed
// when it ends; E8's interrupt hook calls settleWrites() first, then deletes, then lists again.
//
// trackWrite also checks the sticky stop gate (interrupting(), E0b) before it starts the work, so no tracked write starts
// once a stop has begun. guardedWrite and gitPush check the gate again inside, also before every rate-limit retry.
// Labels are fixed texts with names only (a secret's name, a branch), never a value.
import { interrupting } from '../util/exit-hooks.js';
import type { ProofTransport } from './snapshot.js';
import { ScratchGuardError } from './target.js';

interface Pending { what: string; done: Promise<void> }
const pending = new Map<number, Pending>();
let next = 0;

/**
 * Runs `work` as a tracked write: refused (ScratchGuardError, nothing started) once a stop has begun; registered before the
 * work's first await; removed when it settles. The work's result or error passes through.
 */
export function trackWrite<T>(what: string, work: () => Promise<T>): Promise<T> {
  if (interrupting()) return Promise.reject(new ScratchGuardError(`pipegen is stopping; ${what} was not started.`));
  let p: Promise<T>;
  try {
    p = work();
  } catch (e) {
    return Promise.reject(e);
  }
  const id = next++;
  const done = Promise.resolve(p).then(() => {}, () => {}).finally(() => { pending.delete(id); });
  pending.set(id, { what: String(what), done });
  return p;
}

/** The labels of the writes still in flight, oldest first. */
export function writesInFlight(): string[] {
  return [...pending.values()].map((p) => p.what);
}

/**
 * Waits until no tracked write is in flight (E8's cleanup calls it before it deletes and lists), at most `timeoutMs`
 * (default 30 s), or until `signal` aborts. `settled` false: `pending` names what was still in flight.
 */
export async function settleWrites(opts: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<{ settled: boolean; pending: string[] }> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stop = new Promise<'stop'>((done) => {
    timer = setTimeout(() => done('stop'), Math.max(0, timeoutMs));
    if (opts.signal?.aborted) done('stop');
    opts.signal?.addEventListener('abort', () => done('stop'), { once: true });
  });
  try {
    while (pending.size > 0) {
      const all = Promise.all([...pending.values()].map((p) => p.done)).then(() => 'done' as const);
      if (await Promise.race([all, stop]) === 'stop') break;
    }
  } finally {
    clearTimeout(timer);
  }
  return { settled: pending.size === 0, pending: writesInFlight() };
}

/** A transport whose pushes are tracked writes (every proof push after setup goes through one; E8/Plan G wrap setup's too). */
export function trackedTransport(transport: ProofTransport): ProofTransport {
  return Object.freeze({
    push: (to, from, refs, opts) => trackWrite(`push of ${Array.isArray(refs) ? refs.map((r) => String(r?.branch)).join(', ') : 'a branch'}`, () => transport.push(to, from, refs, opts)),
  } satisfies ProofTransport);
}
