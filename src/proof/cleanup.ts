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
import { onInterrupt, type InterruptContext } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { CapReachedError } from './caps.js';
import { settleWrites } from './inflight.js';
import { ScratchKeys, ScratchKeysError } from './keys.js';
import { MinutesMeter, proofStart } from './minutes.js';
import type { PollClock } from './run.js';
import { StateError, StateStore, type RunState } from './state.js';
import {
  assertCentral, assertScratch, cleanupWrite, deleteScratchRepo, githubRead, isProofTarget, proofTarget, ScratchGuardError,
  type CleanupOp, type GuardedRepo, type ProofTarget,
} from './target.js';

/** How long the cleanup waits for writes in flight, and for cancelled runs to end, by default. */
export const CLEANUP_SETTLE_MS = 30_000;
export const CLEANUP_CANCEL_WAIT_MS = 30_000;
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
}
export interface CleanupResult {
  repoDeleted: boolean;
  leftovers: string[];
  /** For the user: why the repo was emptied and not deleted, and the command that deletes it. */
  message?: string;
}

const realClock: PollClock = { now: () => Date.now(), sleep: (ms) => new Promise((ok) => setTimeout(ok, ms)) };
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const statusOf = (e: unknown): unknown => (e as { status?: unknown } | null)?.status;
/** GitHub's answers for something already gone (or already in the asked state). */
const GONE = new Set([404, 409, 410, 422]);
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
  const left: string[] = [];
  const leftover = (item: string): void => {
    const line = safeText(hideToken(String(item)), 500);
    if (left.includes(line)) return;
    left.push(line);
    store.record(line);
    try { opts.leftover?.(line); } catch { /* a reporter that throws doesn't stop the cleanup */ }
  };
  const hard = (e: unknown): void => {
    if (e instanceof ScratchGuardError) throw e;
    if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
  };
  const write = async (r: GuardedRepo, op: CleanupOp): Promise<'done' | 'gone' | string> => {
    try {
      await cleanupWrite(gh, r, op, rate);
      return 'done';
    } catch (e) {
      hard(e);
      if (isRateStop(e)) return 'GitHub\'s rate limit';
      const code = statusOf(e);
      return typeof code === 'number' && GONE.has(code) ? 'gone' : said(e);
    }
  };

  // 1. the writes in flight land (or are named) before anything is listed
  const settled = await settleWrites({ timeoutMs: opts.settleMs ?? CLEANUP_SETTLE_MS, ...(opts.signal === undefined ? {} : { signal: opts.signal }) });
  for (const w of settled.pending) leftover(`a GitHub write was still in flight when the cleanup started (${w}); it may have landed after it`);

  // 2. the secrets, first, always
  try {
    await keys.deleteAll({ leftover, alsoNames: [...st.secretNames, ...Object.keys(keys.stored())] });
  } catch (e) {
    hard(e);
    if (e instanceof ScratchKeysError) leftover(e.message);
    else leftover(`pipegen couldn't confirm every secret of ${s.fullName} is deleted (${isRateStop(e) ? 'GitHub\'s rate limit' : said(e)}); check ${s.fullName} → Settings → Secrets and variables → Actions`);
  }

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

  // 4. the repo deleted, when the token may and it is provably the one pipegen created
  let repoDeleted = false;
  let why = 'your token can\'t delete repos';
  if (opts.canDeleteRepo) {
    try {
      const res = await deleteScratchRepo(gh, s, st.scratchRepoId, rate);
      repoDeleted = res.deleted;
      if (!res.deleted) why = res.why ?? 'GitHub didn\'t delete it';
    } catch (e) {
      hard(e);
      why = isRateStop(e) ? 'GitHub\'s rate limit stopped the delete' : `the delete failed (${said(e)})`;
    }
  }
  let runsDeleted = repoDeleted;
  let message: string | undefined;
  if (repoDeleted) {
    store.update((n) => { n.scratchDeleted = true; n.runsDeleted = true; delete n.scratchRepoId; });
  } else {
    // 5. emptied instead
    runsDeleted = await empty(gh, t, s, store, { write, leftover, hard, rate, clock, cancelled, opts });
    message = `pipegen emptied ${s.fullName} but didn't delete it: ${why}. To delete it: ${deleteCommand(s)}`;
    if (runsDeleted) store.update((n) => { n.runsDeleted = true; });
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
  store.update((n) => {
    n.leftovers = [...new Set([...left, ...n.leftovers.filter((l) => !before.has(l))])];
    n.cleanupDone = n.leftovers.length === 0;
    if (n.stage === 'proven') n.stage = 'cleaned';
  });
  return { repoDeleted, leftovers: [...left], ...(message === undefined ? {} : { message }) };
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
      const res = await c.write(s, { op: 'delete-branch', branch: b });
      if (res !== 'done' && res !== 'gone') c.leftover(`the branch ${b} of ${s.fullName} could not be deleted (${res}); delete it there`);
    }
    if (round === 1) {
      const again = await listProofBranches(gh, s, c.rate).catch(() => null);
      for (const b of again ?? [...names]) c.leftover(`the branch ${b} of ${s.fullName} is still there; delete it there`);
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

  // Actions caches, code scanning analyses (S18), Actions variables (S14)
  for (const kind of ['cache', 'analysis', 'variable'] as const) {
    const items = await listOf(gh, s, kind, c.rate).catch(unread(KIND_TEXT[kind]));
    if (items === null) continue;
    for (const id of items) {
      const op: CleanupOp = kind === 'cache' ? { op: 'delete-cache', cacheId: id as number } : kind === 'analysis' ? { op: 'delete-analysis', analysisId: id as number } : { op: 'delete-variable', name: id as string };
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
export function armProofCleanup(store: StateStore, cleanup: (ctx: InterruptContext) => Promise<unknown>, opts: { deadlineMs?: number; meters?: () => { minutes?: MinutesMeter; ai?: AiSpendMeter } } = {}): () => void {
  if (store.state === null) throw new StateError('The proof state must be started before its cleanup is registered.');
  const record = (item: string): void => store.record(item);
  const offSave = onInterrupt(async () => {
    const m = opts.meters?.();
    if (m !== undefined) {
      try {
        store.saveMeters({
          ...(m.minutes === undefined ? {} : { minutes: { used: m.minutes.used, since: m.minutes.since } }),
          ...(m.ai === undefined ? {} : { aiUsedUsd: m.ai.usedUsd }),
        });
      } catch { /* the stage below is what matters; a refused write records itself */ }
    }
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

/**
 * The proof stage with its cleanup right after it, before anything is shown (spec §19): `prove` runs, then `cleanup` runs
 * whatever happened (proven, failed, a cap stop, an error), then the stage moves (proving → proven → cleaned; a cap stop:
 * stopped). An error of `prove` is thrown again after the cleanup. Plan G shows the preview only after this returns.
 */
export async function proveThenClean<T>(store: StateStore, prove: () => Promise<T>, cleanup: () => Promise<CleanupResult>): Promise<{ outcome: T; cleanup: CleanupResult }> {
  let outcome: T;
  try {
    outcome = await prove();
  } catch (e) {
    if (e instanceof CapReachedError && store.state?.stage !== 'stopped') {
      try { store.setStage('stopped', { stoppedBy: e.cap.kind }); } catch { /* recorded below by the cleanup */ }
    }
    await cleanup();
    throw e;
  }
  store.setStage('proven');
  const done = await cleanup();
  if (store.state?.stage === 'proven') store.setStage('cleaned');
  return { outcome, cleanup: done };
}

// ---------- resume (S20; carries E6) ----------

/**
 * The minutes meter of a resumed proof. `since` is the saved proof start by GitHub's clock (never this machine's), and
 * nothing is restored on top of it: the runs since then are listed again and counted once. Only when the cleanup deleted
 * runs (or the repo) can they no longer be listed: then the meter starts at a new proof start by GitHub's clock
 * (minutes.ts proofStart) and the saved minutes are restored, so each minute counts once either way.
 */
export async function minutesForResume(gh: Octokit, t: ProofTarget, s: Pick<RunState, 'cap' | 'minutesUsed' | 'proofStart' | 'runsDeleted'>, opts: { clock?: RateClock } = {}): Promise<MinutesMeter> {
  if (s.proofStart !== undefined && s.runsDeleted !== true) return new MinutesMeter(s.cap, s.proofStart.at);
  const start = await proofStart(gh, t, opts);
  const m = new MinutesMeter(s.cap, start.at);
  if (s.minutesUsed > 0) m.restore(s.minutesUsed);
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
  store.acquireLease(st.runId);
  try {
    const t = proofTarget(st.app, { runId: st.runId });
    const keys = new ScratchKeys(gh, t, new SecretVault(), { io: opts.io, leftover: () => {} });
    return await cleanupAfterProof(gh, t, store, keys, {
      canDeleteRepo: opts.canDeleteRepo, settleMs: opts.settleMs ?? 0,
      ...(opts.clock === undefined ? {} : { clock: opts.clock }), ...(opts.cancelWaitMs === undefined ? {} : { cancelWaitMs: opts.cancelWaitMs }),
    });
  } finally {
    store.releaseLease();
  }
}
