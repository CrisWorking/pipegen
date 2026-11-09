// v0.2 Plan V M5 (lease carry): the app's lease for the commands that write the repo's settings and files outside a proof: deliver
// (and deliverCentral), finish and update. run, cleanup and uninstall already take it (S20). One pipegen per app repo on this machine, so
// `pipegen finish` can't interleave its lock writes with an uninstall's phase A (or update's pull requests with finish), leaving the repo
// half-locked. The lease is the same file as the proof's (`<cache>/pipegen/<owner>__<repo>/lease.json`), with the same rules: a live
// process on this machine holding it → a stop naming its command; a lease left by a process that is gone → taken over; an unreadable
// lease or one of another machine → a stop. It is taken before the command's first GitHub call, given back on every exit path (the
// returned release, in the caller's finally) and, on a signal or a plain exit, by the exit hook acquireLease registers. While a stop is
// under way (interrupting()) the release is skipped: the exit hook drops the lease after the interrupt hooks end (G-LEASE-R1, sec M1).
// Only the lease is taken: the proof's state file in the same folder is not read (G-LEASE-R1, spec I1).
//
// A caller that already holds the lease (run holds it from its start, then delivers and finishes in the same process) passes its store
// down (`held`): the lease is not taken a second time (that would stop on this very process), and it stays held when the callee ends.
import { randomBytes } from 'node:crypto';
import type { LocalRecordDeps } from '../deliver/record.js';
import { StateError, StateStore, type LeaseCommand, type StateDeps } from './state.js';
import { ProofStopError, type ProofApp } from './target.js';
import { interrupting } from '../util/exit-hooks.js';

/** Gives the lease back (a no-op for a lease the caller passed down). Safe to call twice. */
export type ReleaseLease = () => void;

/** The state folder of the local record folder's user (the same home and environment, so the same lease file as run's). */
export function stateDepsOf(local: LocalRecordDeps | undefined): StateDeps {
  const l = local ?? {};
  return { ...(l.home === undefined ? {} : { home: l.home }), ...(l.env === undefined ? {} : { env: l.env }), ...(l.uid === undefined ? {} : { uid: l.uid }) };
}

/**
 * Takes the lease of `app` for `command`, or checks that `held` (a caller's store) holds it. Throws ProofStopError (another pipegen holds
 * it, or an unreadable lease) or StateError (the state folder can't be trusted, or `held` doesn't hold this app's lease); nothing is
 * read from or sent to GitHub then. Returns how to give it back.
 */
export async function holdAppLease(app: Pick<ProofApp, 'owner' | 'repo'>, command: LeaseCommand, o: { held?: StateStore | undefined; state: StateDeps }): Promise<ReleaseLease> {
  if (o.held !== undefined) {
    // the caller's lease, never a second one: a store that doesn't hold this app's lease is a stop (fail closed), not a new lease
    if (!o.held.holdsLeaseFor(app)) throw new StateError(`pipegen ${command} was handed a lease it doesn't hold for ${app.owner}/${app.repo}; it changes nothing.`);
    return () => {};
  }
  // G-LEASE-R1 (spec I1): the lease only; the saved proof state is not read (finish and update never use it)
  const store = await StateStore.openForLease(app, o.state);
  store.acquireLease(`${command}-${randomBytes(6).toString('hex')}`, command);
  // G-LEASE-R1 (sec M1): while a stop is under way the interrupt hooks may still write to GitHub; the lease stays until the exit hook
  // acquireLease registered drops it, at the end of the hook phase
  return () => { if (!interrupting()) store.releaseLease(); };
}

/** Whether `e` is the lease's own stop (another pipegen holds it, or its folder or file can't be trusted). */
export function isLeaseStop(e: unknown): e is ProofStopError | StateError {
  return e instanceof ProofStopError || e instanceof StateError;
}
