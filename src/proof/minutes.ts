// Plan E Task 6 / E6 (ruling S12; F4): the Actions minutes meter, one of the proof's two hard caps (plan Global Constraints:
// "Two hard caps, both 2× the estimate shown at consent"). The cap is Estimates.setupMinutesCap, the number the consent
// screen showed; it is never computed again here.
// - add(gh, t) lists EVERY run of the scratch repo created since the proof started (GET …/actions/runs?created=>=<start>),
//   not only the runs pipegen holds handles for (a late run, another workflow, a re-run count too), then each run's jobs
//   with filter=all (every attempt's jobs; GitHub's default, latest, would miss re-run attempts).
// - A job that never got a runner counts 0: queued, waiting, no started_at, or (ruling E6-R1) concluded `skipped`. A
//   started job counts max(1, ceil(Δ / 60 s)): Δ = completed_at − started_at once it finished, now − started_at while it runs.
// - GitHub's clock, never this machine's (review I1): "now" is the newest `date` header of GitHub's answers in this read,
//   and the `created>=` window starts MINUTES_SKEW_MARGIN_MS before the proof start (proofStart takes it from GitHub too).
//   An answer without a date header: "now" is the latest of this machine's clock and every time the answer shows (never
//   an under-count), and the read counts as unreadable (GitHub always sends a date; three such reads stop the proof).
// - The count never goes down (a run deleted later was still billed). A read that fails keeps the last count; after
//   MINUTES_UNREAD_LIMIT failed reads in a row the meter is `blind`, and minutesStop stops the proof (fail closed: an
//   unmetered proof could pass the cap).
// - restore(minutes): a resumed run adds what its saved state says was used before (E8).
// Reads only (githubRead); the cancels on the cap go through run.ts's cancelRuns (guardedWrite, then force-cancel).
import type { Octokit } from '@octokit/rest';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import type { PollClock } from './run.js';
import { assertScratch, githubRead, isProofTarget, ScratchGuardError, type GuardedRepo, type ProofTarget } from './target.js';

/** Run list pages read at most (100 runs each). A proof with more runs than this can't be metered: it counts as unreadable. */
export const MINUTES_RUN_PAGES = 10;
/** Job pages read per run at most (100 jobs each). */
export const MINUTES_JOB_PAGES = 5;
/** Failed reads in a row after which the meter is blind (the proof stops). */
export const MINUTES_UNREAD_LIMIT = 3;
/** minutesStop reads the minutes at most this often. */
export const MINUTES_REFRESH_MS = 60_000;
/** The run window starts this long before the proof start, so a clock difference can't drop the proof's first runs. */
export const MINUTES_SKEW_MARGIN_MS = 10 * 60_000;

const MINUTE_MS = 60_000;
/** GitHub's time form (ISO 8601, UTC). */
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
/** Job statuses of a job that hasn't started on a runner. */
const NOT_STARTED = new Set(['queued', 'waiting', 'pending', 'requested']);

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const timeOf = (v: unknown): number => (typeof v === 'string' && TIME_RE.test(v) ? Date.parse(v) : Number.NaN);

/** GitHub's `created` filter for runs created at or after `since` (whole seconds, rounded down so no run is missed). The caller widens `since`. */
export function createdSince(since: number): string {
  return `>=${new Date(Math.floor(since / 1000) * 1000).toISOString().replace('.000Z', 'Z')}`;
}

/**
 * The minutes one job counts at `now` (S12), or null when the job can't be read. No runner (not started, or skipped,
 * ruling E6-R1): 0. Started: max(1, ceil(Δ / 60 s)) with Δ up to completed_at (finished) or `now` (still running).
 */
export function jobBilledMinutes(job: unknown, now: number): number | null {
  if (!isPlain(job) || typeof job.status !== 'string') return null;
  if (NOT_STARTED.has(job.status) || job.started_at === null || job.started_at === undefined || job.conclusion === 'skipped') return 0;
  const start = timeOf(job.started_at);
  if (Number.isNaN(start)) return null;
  let end = now;
  if (job.status === 'completed') {
    const c = timeOf(job.completed_at);
    if (!Number.isNaN(c)) end = c;   // finished without an end time: counted up to now (never less)
  }
  return Math.max(1, Math.ceil((end - start) / MINUTE_MS));
}

class Unreadable extends Error {}

/** What one read saw of GitHub's clock: the newest `date` header, and the newest time in the answers (ms; NaN: none). */
export interface Seen { server: number; newest: number; undated: boolean }
const later = (a: number, b: number): number => (Number.isNaN(a) ? b : Number.isNaN(b) ? a : Math.max(a, b));
/** The `date` header of an answer (ms), NaN when missing or unreadable. */
function dateOf(headers: Record<string, unknown>): number {
  const d = headers.date;
  return typeof d === 'string' && d.length <= 64 ? Date.parse(d) : Number.NaN;
}
/** githubRead that records GitHub's clock in `seen`. */
async function read(gh: Octokit, route: string, params: Record<string, unknown>, rate: RateClock, seen: Seen): Promise<unknown> {
  const r = await githubRead(gh, route, params, rate);
  const d = dateOf(r.headers);
  if (Number.isNaN(d)) seen.undated = true;
  else seen.server = later(seen.server, d);
  return r.data;
}
const note = (seen: Seen, ...times: unknown[]): void => {
  for (const v of times) seen.newest = later(seen.newest, timeOf(v));
};

/**
 * The proof start by GitHub's clock (the `date` header of a read of the scratch repo's runs). Without one, this machine's
 * clock minus MINUTES_SKEW_MARGIN_MS (the stricter reading: an earlier start counts more runs, never fewer).
 */
export async function proofStart(gh: Octokit, t: ProofTarget, opts: { clock?: RateClock } = {}): Promise<{ at: number; fromServer: boolean }> {
  if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
  const s = assertScratch(t, { owner: t.owner, repo: t.appRepo });
  const r = await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs', { owner: s.owner, repo: s.repo, per_page: 1 }, opts.clock ?? clockOf(gh));
  const d = dateOf(r.headers);
  return Number.isNaN(d) ? { at: Date.now() - MINUTES_SKEW_MARGIN_MS, fromServer: false } : { at: d, fromServer: true };
}

/** The Actions minutes meter of one proof (S12). */
export class MinutesMeter {
  /** The hard cap (Estimates.setupMinutesCap). */
  readonly cap: number;
  /** When the proof started (ms since the epoch): runs created from then on count. */
  readonly since: number;
  /** Why the last read failed, or null when it worked. Plain text from fixed words and numbers. */
  problem: string | null = null;
  /** The scratch repo the meter last read (its name), or null before the first read. */
  scratch: string | null = null;
  #listed = 0;
  #restored = 0;
  #fails = 0;

  constructor(cap: number, since: Date | number) {
    if (typeof cap !== 'number' || !Number.isFinite(cap) || cap < 0) throw new Error('The Actions minutes cap must be a finite number of minutes, 0 or more.');
    const at = since instanceof Date ? since.getTime() : since;
    if (typeof at !== 'number' || !Number.isFinite(at)) throw new Error('The proof start time for the minutes meter is not a time.');
    this.cap = cap;
    this.since = at;
  }

  /** The minutes used: what restore() added plus the highest count of the scratch repo's runs so far. */
  get used(): number {
    return this.#restored + this.#listed;
  }

  /** The cap is reached (used ≥ cap): no more runs. */
  get exceeded(): boolean {
    return this.used >= this.cap;
  }

  /** MINUTES_UNREAD_LIMIT reads in a row failed: the minutes are unknown, so the proof stops (fail closed). */
  get blind(): boolean {
    return this.#fails >= MINUTES_UNREAD_LIMIT;
  }

  /** Resume: adds the minutes the saved state says the run already used. Anything but a number ≥ 0 is refused (thrown). */
  restore(minutes: number): void {
    if (typeof minutes !== 'number' || !(minutes >= 0)) throw new Error('The minutes restored from the saved state must be a number of minutes, 0 or more.');
    this.#restored += minutes;
  }

  /**
   * Reads every run of the scratch repo created since the proof started and their jobs (filter=all), and updates the count.
   * A rate stop or a rejected token is thrown; any other failure keeps the last count and is recorded (problem, blind).
   */
  async add(gh: Octokit, t: ProofTarget, opts: { clock?: RateClock } = {}): Promise<void> {
    if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
    const s = assertScratch(t, { owner: t.owner, repo: t.appRepo });
    this.scratch = t.scratch;
    const rate = opts.clock ?? clockOf(gh);
    const seen: Seen = { server: Number.NaN, newest: Number.NaN, undated: false };
    let total = 0;
    try {
      const jobs: unknown[] = [];
      for (const r of await listScratchRuns(gh, s, this.since, rate, seen)) jobs.push(...await runJobs(gh, s, r.id, rate, seen));
      // GitHub's now; without a date on every answer, the latest of this machine's clock and every time shown (never less)
      const now = seen.undated || Number.isNaN(seen.server) ? later(later(Date.now(), seen.newest), seen.server) : later(seen.server, seen.newest);
      for (const j of jobs) total += jobBilledMinutes(j, now) as number;
      if (seen.undated) {
        this.#listed = Math.max(this.#listed, total);
        throw new Unreadable(`GitHub's answer about the runs of ${s.fullName} had no date, so its clock is unknown`);
      }
    } catch (e) {
      if (isRateStop(e)) throw e;
      if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
      this.#fails++;
      this.problem = e instanceof Unreadable ? e.message : `the Actions minutes of ${s.fullName} could not be read (${said(e)})`;
      return;
    }
    this.#fails = 0;
    this.problem = null;
    this.#listed = Math.max(this.#listed, total);
  }
}

const said = (e: unknown): string => {
  const st = (e as { status?: unknown } | null)?.status;
  return typeof st === 'number' && Number.isInteger(st) ? `HTTP ${st}` : 'no answer';
};

/**
 * Every run of the scratch repo created since `since` (any workflow, event, branch or status): id and status. Throws
 * Unreadable (or GitHub's error) when the list can't be read in full.
 */
export async function listScratchRuns(gh: Octokit, s: GuardedRepo, since: number, rate: RateClock, seen: Seen = { server: Number.NaN, newest: Number.NaN, undated: false }): Promise<{ id: number; status: string }[]> {
  const runs = new Map<number, string>();
  const created = createdSince(since - MINUTES_SKEW_MARGIN_MS);
  for (let page = 1; page <= MINUTES_RUN_PAGES; page++) {
    const d = await read(gh, 'GET /repos/{owner}/{repo}/actions/runs', { owner: s.owner, repo: s.repo, created, per_page: 100, page }, rate, seen);
    if (!isPlain(d) || !Array.isArray(d.workflow_runs) || typeof d.total_count !== 'number') throw new Unreadable(`the runs of ${s.fullName} could not be read`);
    for (const r of d.workflow_runs as unknown[]) {
      if (!isPlain(r) || !posInt(r.id) || typeof r.status !== 'string') throw new Unreadable(`the runs of ${s.fullName} could not be read`);
      runs.set(r.id, r.status);
      note(seen, r.created_at, r.updated_at, r.run_started_at);
    }
    if (runs.size >= d.total_count) return [...runs].map(([id, status]) => ({ id, status }));
    if (d.workflow_runs.length === 0) throw new Unreadable(`the run list of ${s.fullName} is cut short`);
  }
  throw new Unreadable(`${s.fullName} has more runs than pipegen reads`);
}

/** Every job of one run, each attempt's (filter=all), checked readable (jobBilledMinutes gives a number for each). */
async function runJobs(gh: Octokit, s: GuardedRepo, runId: number, rate: RateClock, seen: Seen): Promise<unknown[]> {
  const jobs: unknown[] = [];
  for (let page = 1; page <= MINUTES_JOB_PAGES; page++) {
    const d = await read(gh, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs', { owner: s.owner, repo: s.repo, run_id: runId, filter: 'all', per_page: 100, page }, rate, seen);
    if (!isPlain(d) || !Array.isArray(d.jobs) || typeof d.total_count !== 'number') throw new Unreadable(`the jobs of run ${runId} could not be read`);
    for (const j of d.jobs as unknown[]) {
      if (!isPlain(j) || j.run_id !== runId || jobBilledMinutes(j, 0) === null) throw new Unreadable(`the jobs of run ${runId} could not be read`);
      note(seen, j.started_at, j.completed_at);
      jobs.push(j);
    }
    if (jobs.length >= d.total_count) return jobs;
    if (d.jobs.length === 0) throw new Unreadable(`the jobs of run ${runId} are cut short`);
  }
  throw new Unreadable(`run ${runId} has more jobs than pipegen reads`);
}

/**
 * The minutes cap as WaitOptions.shouldStop (E4's hook, checked before every poll): reads the minutes at most every
 * `everyMs` (default MINUTES_REFRESH_MS) and says stop when the cap is reached or the meter is blind.
 */
export function minutesStop(gh: Octokit, t: ProofTarget, meter: MinutesMeter, opts: { everyMs?: number; clock?: PollClock; rateClock?: RateClock } = {}): () => Promise<boolean> {
  const every = opts.everyMs ?? MINUTES_REFRESH_MS;
  const now = () => (opts.clock === undefined ? Date.now() : opts.clock.now());
  let last = Number.NEGATIVE_INFINITY;
  return async () => {
    const at = now();
    if (at - last >= every) {
      last = at;
      await meter.add(gh, t, opts.rateClock === undefined ? {} : { clock: opts.rateClock });
    }
    return meter.exceeded || meter.blind;
  };
}
