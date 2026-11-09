// Plan E Task 7 / E8 (spec §19; plan Global Constraints; rulings B2, S3, S9, S14, S18, S20; threats T12, T38): the cleanup
// right after the proof, before the preview, also on a failure, a cap stop and Ctrl-C; and `pipegen cleanup`.
// cleanupAfterProof(gh, t, store, keys, { canDeleteRepo }), in this order:
//   1. waits (bounded) for the GitHub writes still in flight (inflight.ts settleWrites): a store or push the proof had
//      already sent may land, and must land before the lists below; what doesn't settle is a leftover;
//   2. the scratch SECRETS first, always: every secret listed from the API, plus every name the state file recorded and
//      this process stored (a list may lag behind a store), deleted, then listed again (keys.ts deleteAll);
//   3. every scratch run still going is cancelled (a wait that stopped without cancelling, a rate stop in the minutes
//      check (E6 M6), a cancel that failed before a Ctrl-C (E6 M7)), force-cancelled when the cancel fails;
//   4. the scratch repo is DELETED only when the token may delete repos (Auth.canDeleteRepos) AND deleteScratchRepo proves
//      it is the repo pipegen created: the exact name, pipegen's marker, and the id recorded at creation (S3, E1-R4, S9);
//   5. otherwise it is EMPTIED: every open proof PR closed, every recorded and listed proof/* branch deleted and the
//      branches listed again (a push killed mid-way may have landed: E0c/E2), every run deleted (logs and artifacts with
//      it), every Actions cache, every code scanning analysis (S18) and every Actions variable (S14) deleted, and the
//      default branch reset to one empty commit (git's empty tree; B6); the user is told how to delete it:
//      `gh repo delete <owner>/pipegen-proof-<repo> --yes`;
//   6. the central `proof/<runId>` branch (private projects) is deleted and read again.
// Every write is target.ts cleanupWrite (or deleteScratchRepo, or the secret delete): the removal writes the guard lets
// through while a stop is under way, so the Ctrl-C cleanup runs the same path. Already-deleted items (404, 409, 422) are
// fine. Whatever couldn't be removed is a leftover, recorded in the state file as it is found (synchronously).
// The vault is never wiped here: its values are still needed at delivery (Plan D Task 4). Ctrl-C wipes it (B2).
import type { Octokit } from '@octokit/rest';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, hideToken, isAnonymousClient } from '../github/client.js';
import type { CliIO } from '../cli/io.js';
import { SecretVault } from '../create/secrets.js';
import type { AiSpendMeter } from '../ai/spend-meter.js';
import type { PipelineDraft } from '../types.js';
import { onInterrupt, type InterruptContext } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { CapReachedError, type CapReached } from './caps.js';
import { settleWrites } from './inflight.js';
import { ScratchKeys, ScratchKeysError } from './keys.js';
import { MinutesMeter, proofStart } from './minutes.js';
import type { PollClock } from './run.js';
import { StateError, StateStore, type RunState } from './state.js';
import {
  assertCentral, assertScratch, cleanupWrite, deleteScratchRepo, githubRead, isProofTarget, ProofStopError, proofTarget, ScratchGuardError, validBranchName,
  type CleanupOp, type GuardedRepo, type ProofTarget,
} from './target.js';

/** How long the cleanup waits for writes in flight, and for cancelled runs to end, by default. */
export const CLEANUP_SETTLE_MS = 30_000;
export const CLEANUP_CANCEL_WAIT_MS = 30_000;
/** The minutes read before the run deletes: at most this long (fix round 2, N-2). */
export const CLEANUP_MEASURE_MS = 15_000;
const CANCEL_POLL_MS = 5_000;
/** List pages the cleanup reads at most (100 items each). */
export const CLEANUP_LIST_PAGES = 10;
/** The interrupt hooks' deadline (B2's default): long enough for the secrets, the cancels and the branches. */
export const CLEANUP_DEADLINE_MS = 90_000;

export interface CleanupOptions {
  /** Auth.canDeleteRepos (S9): only then may the scratch repo be deleted (still only after deleteScratchRepo's checks). */
  canDeleteRepo: boolean;
  /** The interrupt hook's signal: the waits stop when it aborts. */
  signal?: AbortSignal;
  /** Where each leftover goes besides the result (default: the state file, store.record). */
  leftover?: (item: string) => void;
  clock?: PollClock;
  rateClock?: RateClock;
  settleMs?: number;
  cancelWaitMs?: number;
  /** How long the minutes read before the run deletes may take (default CLEANUP_MEASURE_MS; fix round 2, N-2). */
  measureMs?: number;
  /** The proof's meters (fix round 1, I-6): saved before anything else and again, read, before any run is deleted. */
  meters?: () => ProofMeters | undefined;
}
export interface CleanupResult {
  repoDeleted: boolean;
  leftovers: string[];
  /** For the user: why the repo was emptied and not deleted, and the command that deletes it. */
  message?: string;
  /** GitHub answered 404 for the scratch repo, which pipegen didn't delete: gone by hand, or the token can't reach it. */
  scratchMissing?: true;
}

const realClock: PollClock = { now: () => Date.now(), sleep: (ms) => new Promise((ok) => setTimeout(ok, ms)) };
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const statusOf = (e: unknown): unknown => (e as { status?: unknown } | null)?.status;
/** GitHub's answers for something already gone (or already in the asked state). */
const GONE = new Set([404, 409, 410, 422]);
/** A run delete: only "not there" is gone (review M-5: a 409 or 422 may mean the run is still going). */
const RUN_GONE = new Set([404, 410]);
const said = (e: unknown): string => {
  const st = statusOf(e);
  return typeof st === 'number' && Number.isInteger(st) ? `HTTP ${st}` : 'no answer';
};
const deleteCommand = (s: GuardedRepo): string => `gh repo delete ${s.fullName} --yes`;

/** One cleanup per store and run in this process: a second call (a cap stop, then the finally; or Ctrl-C during it) joins it. */
const running = new WeakMap<StateStore, Map<string, Promise<CleanupResult>>>();

/**
 * The cleanup right after the proof (proven, failed or stopped), before the preview; also on errors and Ctrl-C (see the
 * header). Returns what it did; it never throws for something it couldn't remove (that is a leftover), only for a guard
 * refusal (a bug) or a state that isn't this target's.
 */
export function cleanupAfterProof(gh: Octokit, t: ProofTarget, store: StateStore, keys: ScratchKeys, opts: CleanupOptions): Promise<CleanupResult> {
  if (!isProofTarget(t)) return Promise.reject(new ScratchGuardError('the proof target was not made by proofTarget.'));
  const st = store.state;
  if (st === null || st.runId !== t.runId || st.app.owner !== t.owner || st.app.repo !== t.appRepo) {
    return Promise.reject(new StateError('The proof state is not the state of this proof target.'));
  }
  let byRun = running.get(store);
  if (byRun === undefined) running.set(store, byRun = new Map());
  const have = byRun.get(t.runId);
  if (have !== undefined) return have;
  const p = clean(gh, t, store, keys, opts);
  byRun.set(t.runId, p);
  return p;
}

async function clean(gh: Octokit, t: ProofTarget, store: StateStore, keys: ScratchKeys, opts: CleanupOptions): Promise<CleanupResult> {
  const app = { owner: t.owner, repo: t.appRepo };
  const s = assertScratch(t, app);
  const rate = opts.rateClock ?? clockOf(gh);
  const clock = opts.clock ?? realClock;
  const st = store.state as RunState;
  const before = new Set(st.leftovers);
  let left: string[] = [];
  const dropped = new Set<string>();
  const leftover = (item: string): void => {
    const line = safeText(hideToken(String(item)), 500);
    if (left.includes(line)) return;
    left.push(line);
    store.record(line);
    try { opts.leftover?.(line); } catch { /* a reporter that throws doesn't stop the cleanup */ }
  };
  // fix round 1 (review I-1): a state write never stops the cleanup; each one is best-effort (record falls back to stderr)
  const save = (change: (n: RunState) => void): void => { try { store.update(change); } catch { /* the cleanup goes on */ } };
  const hard = (e: unknown): void => {
    if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
  };
  const write = async (r: GuardedRepo, op: CleanupOp): Promise<'done' | 'gone' | string> => {
    try {
      await cleanupWrite(gh, r, op, rate);
      return 'done';
    } catch (e) {
      // review I-3: a value the guard won't send (a name GitHub listed) is this item's leftover, never an abort of the rest
      if (e instanceof ScratchGuardError) return 'pipegen won\'t send that name or id';
      hard(e);
      if (isRateStop(e)) return 'GitHub\'s rate limit';
      const code = statusOf(e);
      return typeof code === 'number' && (op.op === 'delete-run' ? RUN_GONE : GONE).has(code) ? 'gone' : said(e);
    }
  };
  /** The secrets: listed and recorded names deleted, then listed again (keys.ts deleteAll). `quiet`: the first pass, reported by the second. */
  const secrets = async (quiet: boolean): Promise<boolean> => {
    try {
      await keys.deleteAll({ ...(quiet ? { waitMs: 0, leftover: () => {} } : { leftover }), alsoNames: [...((store.state as RunState).secretNames), ...Object.keys(keys.stored())] });
      return true;
    } catch (e) {
      if (statusOf(e) === 401 && !isAnonymousClient(gh)) {
        // review M-7: said before the stop goes on, so the user knows the keys may be there
        leftover(`the secrets of ${s.fullName} may still be there (GitHub refused pipegen's token while deleting them); delete them in ${s.fullName} → Settings → Secrets and variables → Actions`);
        throw githubTokenRejected();
      }
      if (quiet) return false;
      if (e instanceof ScratchKeysError) leftover(e.message);
      else leftover(`pipegen couldn't confirm every secret of ${s.fullName} is deleted (${isRateStop(e) ? 'GitHub\'s rate limit' : said(e)}); check ${s.fullName} → Settings → Secrets and variables → Actions`);
      return false;
    }
  };

  // 0. the meters as they are now (review I-6; nothing read yet)
  save((n) => { applyMeters(n, opts.meters?.()); });

  // a scratch repo pipegen deleted before (pipegen cleanup again): when GitHub says it is gone, nothing of it is left (review I-5)
  let skipScratch = st.scratchDeleted === true && await repoSeen(gh, s, rate) === 'missing';
  let scratchMissing = false;

  // 1. the secrets first, without waiting for anything (review I-2: a second Ctrl-C may come at any moment)
  if (!skipScratch && !(await secrets(true)) && await repoSeen(gh, s, rate) === 'missing') {
    // gone, or the token can't reach it: nothing pipegen can list there, so one leftover instead of a false list of them
    skipScratch = true;
    scratchMissing = true;
    leftover(`pipegen can't see ${s.fullName} (it was deleted, or your token can't reach it); if it still exists, delete it: ${deleteCommand(s)}`);
  }

  // 2. the writes in flight land (or are named), then the secrets once more: a store that landed late is deleted too
  const settled = await settleWrites({ timeoutMs: opts.settleMs ?? CLEANUP_SETTLE_MS, ...(opts.signal === undefined ? {} : { signal: opts.signal }) });
  for (const w of settled.pending) leftover(`a GitHub write was still in flight when the cleanup started (${w}); it may have landed after it`);
  if (!skipScratch) await secrets(false);

  let repoDeleted = false;
  let message: string | undefined;
  if (!skipScratch) {
    // 3. every run still going is stopped
    const runs = await listRuns(gh, s, rate).catch((e: unknown) => { hard(e); leftover(`the runs of ${s.fullName} could not be listed; cancel any still running there`); return null; });
    const active = (runs ?? []).filter((r) => r.status !== 'completed').map((r) => r.id);
    const cancelled: number[] = [];
    for (const id of active) {
      const res = await write(s, { op: 'cancel-run', runId: id });
      if (res === 'done') { cancelled.push(id); continue; }
      if (res === 'gone') continue;
      const force = await write(s, { op: 'force-cancel-run', runId: id });
      if (force !== 'done' && force !== 'gone') leftover(`run ${id} of ${s.fullName} could not be cancelled (${force}); cancel it there`);
    }

    // the minutes used, measured before any run is deleted (review I-6: a resume restores them, never a fresh budget)
    const measured = await measureMinutes(gh, t, st, opts.meters?.(), rate, { ms: opts.measureMs ?? CLEANUP_MEASURE_MS, ...(opts.signal === undefined ? {} : { signal: opts.signal }) });
    save((n) => {
      applyMeters(n, opts.meters?.());
      if (measured !== null) n.minutesUsed = Math.max(n.minutesUsed, measured);
    });

    // 4. the repo deleted, when the token may and it is provably the one pipegen created
    let why = 'your token can\'t delete repos';
    if (opts.canDeleteRepo) {
      try {
        const res = await deleteScratchRepo(gh, s, st.scratchRepoId, rate);
        repoDeleted = res.deleted;
        if (!res.deleted) why = res.why ?? 'GitHub didn\'t delete it';
      } catch (e) {
        if (e instanceof ScratchGuardError) throw e;
        hard(e);
        why = isRateStop(e) ? 'GitHub\'s rate limit stopped the delete' : `the delete failed (${said(e)})`;
      }
    }
    if (repoDeleted) {
      // review I-5: what this cleanup couldn't remove in the scratch repo went with it
      for (const l of left) if (l.includes(s.fullName)) dropped.add(l);
      left = left.filter((l) => !dropped.has(l));
      save((n) => { n.scratchDeleted = true; n.runsDeleted = true; delete n.scratchRepoId; });
    } else {
      // 5. emptied instead
      const runsDeleted = await empty(gh, t, s, store, { write, leftover, hard, rate, clock, cancelled, opts });
      message = `pipegen emptied ${s.fullName} but didn't delete it: ${why}. To delete it: ${deleteCommand(s)}`;
      if (runsDeleted) save((n) => { n.runsDeleted = true; });
    }
  } else if (scratchMissing) {
    message = `pipegen can't see ${s.fullName}. If it still exists, delete it: ${deleteCommand(s)}`;
  } else {
    message = `${s.fullName} was already deleted.`;
  }

  // 6. the central proof/<runId> branch (as recorded now: a push in flight at the start was recorded before it began)
  const central = (store.state as RunState).branches.filter((b) => b.repo === 'central');
  if (central.length > 0) {
    const c = assertCentral(t, app);
    for (const b of central) {
      if (b.ref !== `proof/${t.runId}`) { leftover(`the branch ${b.ref} of ${c.fullName} is not this run's; delete it there`); continue; }
      const res = await write(c, { op: 'delete-branch', branch: b.ref });
      if (res !== 'done' && res !== 'gone') { leftover(`the branch ${b.ref} of ${c.fullName} could not be deleted (${res}); delete it there`); continue; }
      if (await refExists(gh, c, b.ref, rate).catch((e: unknown) => { hard(e); return true; })) leftover(`the branch ${b.ref} of ${c.fullName} is still there; delete it there`);
    }
  }

  // the leftovers of this cleanup replace those an earlier cleanup of this run recorded (each was looked for again above);
  // anything recorded meanwhile by someone else (the interrupt registry: a hook cut by its deadline) stays
  save((n) => {
    // fix round 2 (N-1): a repo pipegen can't see wasn't looked at again, so what earlier cleanups recorded about it stays
    // (the central repo's were looked at again in step 6)
    const unchecked = (l: string): boolean => scratchMissing && !l.includes(`${t.owner}/${t.central}`);
    n.leftovers = [...new Set([...left, ...n.leftovers.filter((l) => !dropped.has(l) && (unchecked(l) || !before.has(l)))])];
    n.cleanupDone = n.leftovers.length === 0;
    if (n.stage === 'proven') n.stage = 'cleaned';
  });
  return { repoDeleted, leftovers: [...left], ...(message === undefined ? {} : { message }), ...(scratchMissing ? { scratchMissing: true as const } : {}) };
}

/** What a meter getter gives (Plan G's meters; `fromServer`: the proof start came from GitHub's clock, minutes.ts proofStart). */
export interface ProofMeters { minutes?: MinutesMeter; ai?: AiSpendMeter; fromServer?: boolean }

/** The meters into the state (the higher of saved and now; the proof start once, with its source). */
function applyMeters(n: RunState, m: ProofMeters | undefined): void {
  if (m === undefined) return;
  if (m.minutes !== undefined) {
    n.minutesUsed = Math.max(n.minutesUsed, m.minutes.used);
    n.proofStart ??= { at: m.minutes.since, fromServer: m.fromServer ?? false };
  }
  if (m.ai !== undefined) n.aiCostUsd = Math.max(n.aiCostUsd, m.ai.usedUsd);
}

/**
 * The minutes used, read from GitHub before the runs are deleted (review I-6): the meter's own read when there is one;
 * without one (`pipegen cleanup` after a kill), a meter over the saved proof start. A read that fails counts as the whole
 * cap (an unknown spend never gives a resume a fresh budget). null: nothing to measure (no meter, no saved start).
 */
async function measureMinutes(gh: Octokit, t: ProofTarget, st: RunState, m: ProofMeters | undefined, rate: RateClock, limit: { ms: number; signal?: AbortSignal }): Promise<number | null> {
  // fix round 2 (N-2): the read is bounded (its N+1 requests must not hold up the cleanup on the Ctrl-C path); a read that is
  // cut gives the meter's last count, or (no meter) the whole cap. Final review N2-a: a cleanup already cut (the signal
  // aborted) never starts the read, and the read's outcome is handled the moment it starts: a rejection (a 401, a rate
  // stop) that comes after the cut is caught, never an unhandled rejection; it counts as a read that failed.
  const bounded = async (start: () => Promise<unknown>): Promise<boolean> => {
    if (limit.signal?.aborted === true) return false;
    let settled: Promise<boolean>;
    try {
      settled = start().then(() => true, () => false);
    } catch {
      return false;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const cut = new Promise<false>((done) => {
      timer = setTimeout(() => done(false), Math.max(0, limit.ms));
      onAbort = () => done(false);
      limit.signal?.addEventListener('abort', onAbort, { once: true });
    });
    try {
      return await Promise.race([settled, cut]);
    } finally {
      clearTimeout(timer);
      if (onAbort !== undefined) limit.signal?.removeEventListener('abort', onAbort);
    }
  };
  if (m?.minutes !== undefined) {
    const meter = m.minutes;
    await bounded(() => meter.add(gh, t, { clock: rate }));
    return m.minutes.used;
  }
  if (st.proofStart === undefined) return null;
  const meter = new MinutesMeter(st.cap, st.proofStart.at);
  if ((st.minutesBase ?? 0) > 0) meter.restore(st.minutesBase as number);   // fix round 2 (N-3): base + the runs since the start
  if (!(await bounded(() => meter.add(gh, t, { clock: rate })))) return st.cap;
  return meter.problem === null ? meter.used : Math.max(meter.used, st.cap);
}

/** GitHub's answer for the scratch repo: there, gone (404), or unknown (anything else). */
async function repoSeen(gh: Octokit, s: GuardedRepo, rate: RateClock): Promise<'present' | 'missing' | 'unknown'> {
  try {
    await githubRead(gh, 'GET /repos/{owner}/{repo}', { owner: s.owner, repo: s.repo }, rate);
    return 'present';
  } catch (e) {
    return statusOf(e) === 404 ? 'missing' : 'unknown';
  }
}

interface EmptyCtx {
  write: (r: GuardedRepo, op: CleanupOp) => Promise<'done' | 'gone' | string>;
  leftover: (item: string) => void;
  hard: (e: unknown) => void;
  rate: RateClock;
  clock: PollClock;
  cancelled: number[];
  opts: CleanupOptions;
}

/** Step 5: empties the scratch repo. Returns true when it deleted at least one run (their minutes can't be listed again). */
async function empty(gh: Octokit, t: ProofTarget, s: GuardedRepo, store: StateStore, c: EmptyCtx): Promise<boolean> {
  const st = store.state as RunState;
  const unread = (what: string) => (e: unknown): null => { c.hard(e); c.leftover(`the ${what} of ${s.fullName} could not be listed; check them there`); return null; };

  // the cancelled runs get a moment to end (a run still going can't be deleted); then force-cancel
  const waitMs = c.opts.cancelWaitMs ?? CLEANUP_CANCEL_WAIT_MS;
  let going = [...c.cancelled];
  for (let waited = 0; going.length > 0 && waited < waitMs && c.opts.signal?.aborted !== true; waited += CANCEL_POLL_MS) {
    await c.clock.sleep(CANCEL_POLL_MS);
    const still: number[] = [];
    for (const id of going) if (!(await runDone(gh, s, id, c.rate).catch((e: unknown) => { c.hard(e); return false; }))) still.push(id);
    going = still;
  }
  for (const id of going) {
    const res = await c.write(s, { op: 'force-cancel-run', runId: id });
    if (res !== 'done' && res !== 'gone') c.leftover(`run ${id} of ${s.fullName} could not be cancelled (${res}); cancel it there`);
  }

  // PRs: every open one from a proof branch (recorded or listed), closed
  const recordedHeads = new Set(st.prs.map((p) => p.head));
  const scratchBranches = new Set(st.branches.filter((b) => b.repo === 'scratch').map((b) => b.ref));
  const open = await listOpenPrs(gh, s, c.rate).catch(unread('open PRs'));
  const toClose = new Set<number>();
  if (open === null) for (const p of st.prs) { if (p.number !== undefined) toClose.add(p.number); }
  else for (const p of open) if (p.head.startsWith('proof/') || recordedHeads.has(p.head) || scratchBranches.has(p.head)) toClose.add(p.number);
  for (const n of toClose) {
    const res = await c.write(s, { op: 'close-pr', pr: n });
    if (res !== 'done' && res !== 'gone') c.leftover(`PR #${n} of ${s.fullName} could not be closed (${res}); close it there`);
  }

  // branches: recorded and listed proof/*, deleted; then listed again (a killed push may have landed: E0c, E2)
  for (let round = 0; round < 2; round++) {
    const listed = await listProofBranches(gh, s, c.rate).catch(round === 0 ? unread('proof branches') : () => null);
    const names = new Set<string>([...(round === 0 ? scratchBranches : []), ...(listed ?? [])]);
    names.delete(t.defaultBranch);
    if (round === 1) {
      if (listed === null) { c.leftover(`the proof branches of ${s.fullName} could not be listed again after the delete; delete any proof/ branch there`); break; }
      if (names.size === 0) break;
    }
    for (const b of names) {
      if (!validBranchName(b)) {
        // review I-3: a name GitHub listed that pipegen won't send (git allows it, pipegen's guard doesn't)
        c.leftover(`the branch ${safeText(b, 120)} of ${s.fullName} has a name pipegen won't send; delete it there`);
        continue;
      }
      const res = await c.write(s, { op: 'delete-branch', branch: b });
      if (res !== 'done' && res !== 'gone') c.leftover(`the branch ${b} of ${s.fullName} could not be deleted (${res}); delete it there`);
    }
    if (round === 1) {
      const again = await listProofBranches(gh, s, c.rate).catch(() => null);
      for (const b of again ?? [...names]) c.leftover(`the branch ${safeText(b, 120)} of ${s.fullName} is still there; delete it there`);
    }
  }

  // runs (their logs and artifacts go with them)
  let deletedRuns = false;
  const runs = await listRuns(gh, s, c.rate).catch(unread('workflow runs'));
  for (const r of runs ?? []) {
    const res = await c.write(s, { op: 'delete-run', runId: r.id });
    if (res === 'done') deletedRuns = true;
    else if (res !== 'gone') c.leftover(`run ${r.id} of ${s.fullName} could not be deleted (${res}); delete it there (its logs and artifacts go with it)`);
  }
  // listed again (review M-5): a run GitHub didn't delete is a leftover
  if (runs !== null && runs.length > 0) {
    const again = await listRuns(gh, s, c.rate).catch(() => null);
    if (again === null) c.leftover(`the workflow runs of ${s.fullName} could not be listed again after the delete; check them there`);
    else for (const r of again) c.leftover(`run ${r.id} of ${s.fullName} is still there; delete it there (its logs and artifacts go with it)`);
  }

  // Actions caches, code scanning analyses (S18), Actions variables (S14)
  for (const kind of ['cache', 'analysis', 'variable'] as const) {
    const items = await listOf(gh, s, kind, c.rate).catch(unread(KIND_TEXT[kind]));
    if (items === null) continue;
    if (kind === 'analysis') await deleteAnalyses(gh, s, items as number[], c);
    else for (const id of items) {
      const op: CleanupOp = kind === 'cache' ? { op: 'delete-cache', cacheId: id as number } : { op: 'delete-variable', name: id as string };
      const res = await c.write(s, op);
      if (res !== 'done' && res !== 'gone') c.leftover(`the ${KIND_ONE[kind]} ${safeText(String(id), 120)} of ${s.fullName} could not be deleted (${res}); delete it there`);
    }
    const again = items.length === 0 ? [] : await listOf(gh, s, kind, c.rate).catch(() => null);
    if (again === null) c.leftover(`the ${KIND_TEXT[kind]} of ${s.fullName} could not be listed again after the delete; check them there`);
    else for (const id of again) c.leftover(`the ${KIND_ONE[kind]} ${safeText(String(id), 120)} of ${s.fullName} is still there; delete it there`);
  }

  // the default branch: one empty commit (the base snapshot holds the user's code)
  let reset = false;
  try {
    const made = await cleanupWrite(gh, s, { op: 'empty-commit' }, c.rate);
    await cleanupWrite(gh, s, { op: 'reset-default-branch', sha: (made.data as { sha: string }).sha }, c.rate);
    reset = true;
  } catch (e) {
    c.hard(e);
  }
  if (!reset) c.leftover(`the default branch ${t.defaultBranch} of ${s.fullName} still holds a copy of your code; delete the repo: ${deleteCommand(s)}`);
  return deletedRuns;
}

/**
 * Code scanning analyses (S18; review M-6): GitHub deletes only the most recent analysis of a set, and its answer names the
 * next one (next_analysis_url, or confirm_delete_url for the last). So: newest first (highest id), following those links
 * (only to an analysis of this scratch repo), with confirm_delete. What is still listed afterwards is a leftover.
 */
async function deleteAnalyses(gh: Octokit, s: GuardedRepo, ids: readonly number[], c: EmptyCtx): Promise<void> {
  const done = new Set<number>();
  for (const start of [...ids].sort((a, b) => b - a)) {
    let id: number | null = start;
    for (let hops = 0; id !== null && !done.has(id) && hops < 1_000; hops++) {
      done.add(id);
      let data: unknown;
      try {
        data = (await cleanupWrite(gh, s, { op: 'delete-analysis', analysisId: id }, c.rate)).data;
      } catch (e) {
        if (!(e instanceof ScratchGuardError)) c.hard(e);
        if (statusOf(e) === 404) break;
        c.leftover(`the code scanning analysis ${id} of ${s.fullName} could not be deleted (${isRateStop(e) ? 'GitHub\'s rate limit' : said(e)}); delete it there`);
        break;
      }
      id = nextAnalysis(data, s);
    }
  }
}

/** The analysis id GitHub's delete answer names next, when it is one of this scratch repo's. */
function nextAnalysis(data: unknown, s: GuardedRepo): number | null {
  if (!isPlain(data)) return null;
  for (const key of ['next_analysis_url', 'confirm_delete_url']) {
    const u = data[key];
    if (typeof u !== 'string' || u.length > 500) continue;
    let url: URL;
    try { url = new URL(u); } catch { continue; }
    const m = /^\/repos\/([^/]+)\/([^/]+)\/code-scanning\/analyses\/(\d{1,15})$/.exec(url.pathname);
    if (url.origin === 'https://api.github.com' && m !== null && m[1]?.toLowerCase() === s.owner.toLowerCase() && m[2]?.toLowerCase() === s.repo.toLowerCase()) return Number(m[3]);
  }
  return null;
}

const KIND_TEXT = { cache: 'Actions caches', analysis: 'code scanning analyses', variable: 'Actions variables' } as const;
const KIND_ONE = { cache: 'Actions cache', analysis: 'code scanning analysis', variable: 'Actions variable' } as const;

// ---------- reads ----------

/** Every run of the scratch repo (id, status). Throws when the list can't be read in full. */
async function listRuns(gh: Octokit, s: GuardedRepo, rate: RateClock): Promise<{ id: number; status: string }[]> {
  const out = new Map<number, string>();
  for (let page = 1; page <= CLEANUP_LIST_PAGES; page++) {
    const d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs', { owner: s.owner, repo: s.repo, per_page: 100, page }, rate)).data;
    if (!isPlain(d) || !Array.isArray(d.workflow_runs) || typeof d.total_count !== 'number') throw new Error('unreadable');
    for (const r of d.workflow_runs as unknown[]) {
      if (!isPlain(r) || !posInt(r.id) || typeof r.status !== 'string') throw new Error('unreadable');
      out.set(r.id, r.status);
    }
    if (out.size >= d.total_count || d.workflow_runs.length === 0) return [...out].map(([id, status]) => ({ id, status }));
  }
  throw new Error('too many runs');
}

async function runDone(gh: Octokit, s: GuardedRepo, id: number, rate: RateClock): Promise<boolean> {
  try {
    const d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}', { owner: s.owner, repo: s.repo, run_id: id }, rate)).data;
    return isPlain(d) && d.id === id && d.status === 'completed';
  } catch (e) {
    if (statusOf(e) === 404) return true;
    throw e;
  }
}

async function listOpenPrs(gh: Octokit, s: GuardedRepo, rate: RateClock): Promise<{ number: number; head: string }[]> {
  const out: { number: number; head: string }[] = [];
  for (let page = 1; page <= CLEANUP_LIST_PAGES; page++) {
    const d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/pulls', { owner: s.owner, repo: s.repo, state: 'open', per_page: 100, page }, rate)).data;
    if (!Array.isArray(d)) throw new Error('unreadable');
    for (const p of d as unknown[]) {
      const head = isPlain(p) && isPlain(p.head) ? p.head : null;
      if (!isPlain(p) || !posInt(p.number) || head === null || typeof head.ref !== 'string') throw new Error('unreadable');
      out.push({ number: p.number, head: head.ref });
    }
    if (d.length < 100) return out;
  }
  throw new Error('too many PRs');
}

/** The scratch repo's proof/* branches (names without refs/heads/). */
async function listProofBranches(gh: Octokit, s: GuardedRepo, rate: RateClock): Promise<string[]> {
  const d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}', { owner: s.owner, repo: s.repo, ref: 'heads/proof/', per_page: 100 }, rate)).data;
  if (!Array.isArray(d)) throw new Error('unreadable');
  return (d as unknown[]).map((r) => {
    const ref = isPlain(r) ? r.ref : undefined;
    if (typeof ref !== 'string' || !ref.startsWith('refs/heads/proof/')) throw new Error('unreadable');
    return ref.slice('refs/heads/'.length);
  });
}

async function refExists(gh: Octokit, r: GuardedRepo, branch: string, rate: RateClock): Promise<boolean> {
  try {
    await githubRead(gh, 'GET /repos/{owner}/{repo}/git/ref/{ref}', { owner: r.owner, repo: r.repo, ref: `heads/${branch}` }, rate);
    return true;
  } catch (e) {
    if (statusOf(e) === 404) return false;
    throw e;
  }
}

/** Ids of the Actions caches or code scanning analyses, names of the Actions variables. Code scanning off (403/404): none. */
async function listOf(gh: Octokit, s: GuardedRepo, kind: 'cache' | 'analysis' | 'variable', rate: RateClock): Promise<(number | string)[]> {
  const out: (number | string)[] = [];
  for (let page = 1; page <= CLEANUP_LIST_PAGES; page++) {
    let d: unknown;
    try {
      d = (await githubRead(gh, kind === 'cache' ? 'GET /repos/{owner}/{repo}/actions/caches' : kind === 'analysis' ? 'GET /repos/{owner}/{repo}/code-scanning/analyses' : 'GET /repos/{owner}/{repo}/actions/variables',
        { owner: s.owner, repo: s.repo, per_page: 100, page }, rate)).data;
    } catch (e) {
      // a private repo without code scanning answers 403 or 404 ("not enabled"): it holds no analysis (S18)
      if (kind === 'analysis' && (statusOf(e) === 403 || statusOf(e) === 404)) return [];
      throw e;
    }
    const list = kind === 'analysis' ? d : isPlain(d) ? d[kind === 'cache' ? 'actions_caches' : 'variables'] : undefined;
    if (!Array.isArray(list)) throw new Error('unreadable');
    for (const x of list as unknown[]) {
      const v = isPlain(x) ? (kind === 'variable' ? x.name : x.id) : undefined;
      if (kind === 'variable' ? typeof v !== 'string' : !posInt(v)) throw new Error('unreadable');
      out.push(v as number | string);
    }
    if (list.length < 100) return out;
  }
  throw new Error('too many');
}

// ---------- Ctrl-C (B2; carries E0b) ----------

/**
 * Registers the proof's two interrupt hooks, in this order (E0b-1: hooks run in registration order): FIRST the state saved
 * as `interrupted` (with the meters, when given), THEN the cleanup. Both record leftovers synchronously in the state file.
 * Plan G calls it before the proof's first GitHub write: until then the store refuses to record (so to make) a branch, a PR
 * or a repo. Returns the unregister function (both hooks).
 */
export function armProofCleanup(store: StateStore, cleanup: (ctx: InterruptContext) => Promise<unknown>, opts: { deadlineMs?: number; meters?: () => ProofMeters | undefined } = {}): () => void {
  if (store.state === null) throw new StateError('The proof state must be started before its cleanup is registered.');
  const record = (item: string): void => store.record(item);
  const offSave = onInterrupt(async () => {
    try { store.update((n) => { applyMeters(n, opts.meters?.()); }); } catch { /* the stage below is what matters */ }
    store.setStage('interrupted');
  }, { label: 'saving the proof state', deadlineMs: 5_000, record });
  const offClean = onInterrupt(async (ctx) => { await cleanup(ctx); }, { label: 'removing your keys and the proof from the scratch repo', deadlineMs: opts.deadlineMs ?? CLEANUP_DEADLINE_MS, record });
  store.markArmed(true);
  return () => {
    store.markArmed(false);
    offClean();
    offSave();
  };
}

/** Final review I-2: what a finished proof says, for the state: passed or not, its final draft, why it stopped, the cap. */
export interface ProofVerdict { ok: boolean; draft?: PipelineDraft; stopped?: string; cap?: CapReached['kind'] }

const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

/**
 * The verdict of a FixOutcome (fix.ts proveWithFixes): a pass only when `result.ok` is exactly true, the loop didn't stop
 * (`stopped`) or reach a cap (`cap`), and it gives its final draft. Anything else, or anything that can't be read, is not
 * a pass (fails closed).
 */
export function proofVerdict(outcome: unknown): ProofVerdict {
  if (!isRecord(outcome)) return { ok: false };
  const draft = isRecord(outcome.draft) ? outcome.draft as unknown as PipelineDraft : undefined;
  const stopped = typeof outcome.stopped === 'string' ? outcome.stopped : undefined;
  const kind = isRecord(outcome.cap) ? outcome.cap.kind : undefined;
  const cap = kind === 'ai-cost' || kind === 'actions-minutes' ? kind : undefined;
  const ok = isRecord(outcome.result) && outcome.result.ok === true && stopped === undefined && outcome.cap === undefined && draft !== undefined;
  return { ok, ...(draft === undefined ? {} : { draft }), ...(stopped === undefined ? {} : { stopped }), ...(cap === undefined ? {} : { cap }) };
}

/**
 * Plan G G0 (E-F2 m1): the verdict of `base` (proofVerdict over the outcome) made only stricter by a reader's `extra`: a pass
 * only when both pass, always `base`'s draft and cap (a reader adds a cap only when base has none), and the reader's reason
 * when it gives one. A reader that is absent leaves `base` as it is.
 */
function stricterVerdict(base: ProofVerdict, extra: ProofVerdict | undefined): ProofVerdict {
  if (extra === undefined) return base;
  const r: Record<string, unknown> = isRecord(extra) ? extra : {};
  const ok = base.ok === true && r.ok === true;
  const stopped = typeof r.stopped === 'string' && r.stopped !== '' ? r.stopped : base.stopped;
  const cap = base.cap ?? (r.cap === 'ai-cost' || r.cap === 'actions-minutes' ? r.cap : undefined);
  return { ok, ...(base.draft === undefined ? {} : { draft: base.draft }), ...(stopped === undefined ? {} : { stopped }), ...(cap === undefined ? {} : { cap }) };
}

/**
 * The proof stage with its cleanup right after it, before anything is shown (spec §19): `prove` runs, then `cleanup` runs
 * on EVERY path (proven, failed, a cap stop that throws or returns, an error), and no state write can skip it (review I-1:
 * the stage moves are best-effort). An error of `prove` is thrown again after the cleanup; a CapReachedError → stopped.
 * Final review I-2: when `prove` returns, its verdict (`verdict`, default proofVerdict: a FixOutcome) and final draft are
 * saved first (recordVerdict); then proving → proven → cleaned only when it passed and that save worked, else proving →
 * stopped ('proof-failed', or the cap it reached), from which a resume proves again and never delivers. Plan G shows the
 * preview only after this returns.
 * Plan G G0 (E-F2 m1): `verdict` may only make the result stricter. The outcome is always read by proofVerdict as well; it is a
 * pass only when both say so, the draft saved is always the FixOutcome's own (a reader can't swap it), and a reader's `stopped`
 * reason is kept when it refuses. A prove that returns after the stage left `proving` (a cap stop that saved `stopped`) records
 * no verdict: recordVerdict is refused outside `proving`, and the resume proves again.
 */
export async function proveThenClean<T>(
  store: StateStore, prove: () => Promise<T>, cleanup: () => Promise<CleanupResult>, verdict?: (outcome: T) => ProofVerdict,
  opts: { stopDraft?: () => PipelineDraft | undefined } = {},
): Promise<{ outcome: T; cleanup: CleanupResult }> {
  const best = (f: () => void): void => { try { f(); } catch { /* a state write never skips the cleanup */ } };
  let outcome!: T;
  let failed = false;
  let failure: unknown;
  try {
    outcome = await prove();
  } catch (e) {
    failed = true;
    failure = e;
  }
  if (failed) {
    if (failure instanceof CapReachedError && store.state?.stage !== 'stopped') { const kind = failure.cap.kind; best(() => store.setStage('stopped', { stoppedBy: kind })); }
    // G14-R1 (spec M2): a stop mid-proof (ProofStopError) keeps the latest draft the proof ran, as a failed verdict (a resume starts from
    // it and proves it again; never a pass)
    const stopDraft = failure instanceof ProofStopError && store.state?.stage === 'proving' ? opts.stopDraft?.() : undefined;
    if (stopDraft !== undefined) {
      let saved = false;
      best(() => { store.recordVerdict({ ok: false, draft: stopDraft, stopped: (failure as Error).message }); saved = true; });
      if (saved) best(() => store.setStage('stopped', { stoppedBy: 'proof-failed' }));
    }
  } else {
    let v: ProofVerdict;
    try { v = stricterVerdict(proofVerdict(outcome), verdict === undefined ? undefined : verdict(outcome)); } catch { v = { ok: false }; }
    // G0 (E-F2 m1, G0-R1 I2): a verdict is recorded while proving; after a cap stop that already saved `stopped` (from proving) the
    // verdict is recorded as failed with the final draft, so a resume starts from the AI-fixed draft and never passes
    const st0 = store.state;
    const stoppedFromProving = st0?.stage === 'stopped' && st0.interruptedAt === 'proving';
    if (stoppedFromProving) v = { ...v, ok: false };
    if (st0?.stage === 'proving' || stoppedFromProving) {
      let saved = false;
      best(() => { store.recordVerdict(v); saved = true; });
      // the draft couldn't be saved (a secret value in it, the state format, the disk): never a pass a resume could deliver
      if (!saved) best(() => store.recordVerdict({ ok: false, stopped: 'pipegen couldn\'t save the proof\'s verdict and final draft' }));
    }
    // the stage follows the verdict as SAVED (a pass with its draft), never the reader's word alone
    if (store.state?.stage === 'proving') {
      const stoppedBy = v.cap ?? 'proof-failed';
      best(() => (store.state?.proofOk === true ? store.setStage('proven') : store.setStage('stopped', { stoppedBy })));
    }
  }
  let done: CleanupResult;
  try {
    done = await cleanup();
  } catch (e) {
    if (failed) throw failure;
    throw e;
  }
  if (failed) throw failure;
  if (store.state?.stage === 'proven') best(() => store.setStage('cleaned'));
  return { outcome, cleanup: done };
}

/**
 * stopAtCap's `saveState` (fix round 1, I-6): the meters first (a resume restores them), then the stage `stopped` with the
 * cap that stopped it.
 */
export function saveStopState(store: StateStore, meters?: () => ProofMeters | undefined): (cap: CapReached) => void {
  return (cap) => {
    try { store.update((n) => { applyMeters(n, meters?.()); }); } catch { /* the stage below still moves, or stopAtCap names the problem */ }
    store.setStage('stopped', { stoppedBy: cap.kind });
  };
}

// ---------- resume (S20; carries E6) ----------

/**
 * The minutes meter of a resumed proof. `since` is the saved proof start by GitHub's clock (never this machine's), and
 * nothing is restored on top of it: the runs since then are listed again and counted once. Only when the cleanup deleted
 * runs (or the repo) can they no longer be listed: then the meter starts at a new proof start by GitHub's clock
 * (minutes.ts proofStart) and the saved minutes are restored, so each minute counts once either way.
 */
export async function minutesForResume(gh: Octokit, t: ProofTarget, s: Pick<RunState, 'cap' | 'minutesUsed' | 'proofStart' | 'runsDeleted' | 'minutesBase'>, opts: { clock?: RateClock; store?: StateStore } = {}): Promise<MinutesMeter> {
  if (s.proofStart !== undefined && s.runsDeleted !== true) {
    // the runs since the start are listed again; what came before it (fix round 2, N-3) is restored
    const kept = new MinutesMeter(s.cap, s.proofStart.at);
    if ((s.minutesBase ?? 0) > 0) kept.restore(s.minutesBase as number);
    return kept;
  }
  const start = await proofStart(gh, t, opts.clock === undefined ? {} : { clock: opts.clock });
  const m = new MinutesMeter(s.cap, start.at);
  if (s.minutesUsed > 0) m.restore(s.minutesUsed);
  // fix round 2 (N-3): the new window and its base are saved, so a later count (a cleanup with no meter, after a kill) is
  // base + the runs since the new start, never just the new runs
  opts.store?.update((n) => {
    n.proofStart = { at: start.at, fromServer: start.fromServer };
    n.minutesBase = s.minutesUsed;
    n.runsDeleted = false;
  });
  return m;
}

/**
 * The AI spend of a resumed run (B4 restore): the saved spend is added to the new meter. The meter's sticky `refused` flag
 * is not saved: a restored spend at the cap refuses the next call again (and latches it again), so nothing is lost.
 */
export function restoreAiSpend(meter: AiSpendMeter, s: Pick<RunState, 'aiCostUsd'>): void {
  if (s.aiCostUsd > 0) meter.restore(s.aiCostUsd);
}

// ---------- `pipegen cleanup` ----------

/**
 * Plan E Task 7's `cleanup(gh, owner, s)`: removes what a saved proof left in GitHub (the same cleanup as after a proof; the
 * vault is empty here, so nothing of the user's is held). Takes the lease first: never while another pipegen works on the repo.
 */
export async function cleanupLeftovers(gh: Octokit, store: StateStore, opts: { canDeleteRepo: boolean; clock?: PollClock; cancelWaitMs?: number; settleMs?: number; io: Pick<CliIO, 'prompt' | 'out' | 'err'> }): Promise<CleanupResult> {
  const st = store.state;
  if (st === null) throw new StateError('There is no saved proof state.');
  // Plan V M5: a lease the caller already holds (uninstall's run 2) stays held after: giving it back would leave a gap in which another
  // pipegen (finish, update) could take it in the middle of the caller's run
  const took = !store.holdsLeaseFor(st.app);
  store.acquireLease(st.runId, 'cleanup');
  try {
    const t = proofTarget(st.app, { runId: st.runId });
    const keys = new ScratchKeys(gh, t, new SecretVault(), { io: opts.io, leftover: () => {} });
    return await cleanupAfterProof(gh, t, store, keys, {
      canDeleteRepo: opts.canDeleteRepo, settleMs: opts.settleMs ?? 0,
      ...(opts.clock === undefined ? {} : { clock: opts.clock }), ...(opts.cancelWaitMs === undefined ? {} : { cancelWaitMs: opts.cancelWaitMs }),
    });
  } finally {
    if (took) store.releaseLease();
  }
}
