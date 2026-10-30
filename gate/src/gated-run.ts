// Plan C Task C8: findGatedRun, the proof behind verify-first (Plan G) and the proof's verify-lookup (Plan E).
//
// Before a deploy, pipegen must show that THE EXACT COMMIT being deployed passed the gate in a trusted run: a push run of pipegen.yml on the
// default branch of this repository, for that sha, whose latest attempt has exactly one job named GATE_CHECK_NAME and that job concluded
// success. A false "found" lets unverified code deploy, so every doubt is "not ok", and nothing the API says is believed without a check.
//
// What is reused from C3 (baseline.ts), not copied: `runFieldsTrusted` (event push, exact workflow path, head_repository.id equal to the
// repository's id, head_branch equal to the default branch, a 40-hex head_sha) and `judgeRun` (those fields, then the tag named like the
// default branch, then `inDefaultHistory`, which resolves the branch commit on EVERY call and is never cached). Added here: head_sha equals
// the commit asked for; for private repositories the central workflow; the latest attempt's jobs; waiting.
//
// Run selection (the documented choice): the runs of one commit (a re-push, a second workflow run, a re-run that made a new attempt) are
// judged one by one. ANY ONE trusted run whose latest attempt has exactly one gate job with conclusion success is enough: a failed latest
// attempt in one run does not veto another trusted successful run, because the commit did pass the gate in a trusted run. A run that is not
// trusted never counts, whatever its jobs say. "Latest attempt" is the run's own `run_attempt`, and only that attempt's jobs are read
// (GET /actions/runs/{id}/attempts/{n}/jobs): an older attempt that succeeded is never used for a run whose latest attempt failed. The attempt
// number comes from the run list answer of the same poll; a re-run that starts after that answer is seen at the next poll (until then the
// attempt that is read is still a real, finished attempt of a trusted run for this commit).
//
// Private repositories: the run's `referenced_workflows` must hold an entry whose `path` starts with `<central.pathPrefix>@` AND whose `sha`
// field equals `central.sha`, on the same entry. The two are checked separately and the text after `@` is never read: when the central
// workflow is pinned by SHA the entry has no `ref` (DECISIONS #78), and a path can say anything. Every entry for that prefix must carry the
// expected sha (one central workflow, one commit); no such entry is also a refusal.
//
// Waiting: a trusted run that is queued or in progress is waited for, polling (pollMs) up to waitMs, through the injectable sleep and clock.
// Only the list is polled while waiting; the trust and the jobs are read fresh when a run is finished. Calls are budgeted (maxCalls): a budget
// that runs out is an error, never a pass. Any API error (rate limit, 5xx, network) is an error with a reason: the proof cannot be made.
import { judgeRun, runFieldsTrusted, WORKFLOW_PATH, type GateGithub, type Lookup, type RepoRef } from './baseline.js';
import { GitHubApiError } from './github-adapter.js';

export interface GatedRunOpts {
  workflowPath: string;                            // '.github/workflows/pipegen.yml' (the only one run trust is defined for)
  gateJobName: string;                             // GATE_CHECK_NAME
  central?: { pathPrefix: string; sha: string };   // private repos: '<owner>/pipelines/.github/workflows/<repo>--merge.yml' + the expected central commit
  waitMs?: number;                                 // default 30 min
  pollMs?: number;                                 // default 20 s (raised so that a long wait is at most MAX_POLLS polls)
  sleep?: (ms: number) => Promise<void>; now?: () => number;   // for tests
  /** The most GitHub calls one search may make (default DEFAULT_MAX_CALLS). */
  maxCalls?: number;
}
export type GatedRun =
  | { ok: true; runId: number; url: string }
  | { ok: false; reason: 'none' | 'wrong-central' | 'gate-failed' | 'timeout' | 'error'; detail: string };

export const DEFAULT_WAIT_MS = 30 * 60_000;
export const DEFAULT_POLL_MS = 20_000;
/** A wait is stretched, not cut: the poll interval is at least waitMs / MAX_POLLS, so even 6 hours stays within the call budget. */
export const MAX_POLLS = 300;
/** Calls per search: a 30 minute wait is about 90 list calls plus the judging of a finished run (about 10). */
export const DEFAULT_MAX_CALLS = 400;
/** Runs of one commit that are judged per poll; more than this and the search cannot say (error). */
export const MAX_CANDIDATES = 20;
export const JOBS_PER_PAGE = 100;
/** 500 jobs in one attempt at the most; more and a second gate job could hide beyond them. */
export const JOB_PAGE_CAP = 5;
const SHA_RE = /^[0-9a-f]{40}$/;
const ACTIVE = new Set(['queued', 'in_progress', 'waiting', 'pending', 'requested']);

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

class BudgetError extends Error {}
/** A short fixed text for a failed call: only the adapter's own messages (they name the call and the status) are repeated. */
const why = (what: string, e: unknown): string => (e instanceof BudgetError ? `${what}: the call budget is used up` : e instanceof GitHubApiError ? `${what}: ${e.message}` : `${what}: the request failed`);

type Verdict = { kind: 'ok' } | { kind: 'failed'; detail: string } | { kind: 'error'; detail: string };

/** The gate job of ONE attempt: exactly one job named gateJobName, completed with conclusion success. */
async function attemptVerdict(gh: GateGithub, repo: RepoRef, runId: number, attempt: number, gateJobName: string): Promise<Verdict> {
  const what = `the jobs of run ${runId} attempt ${attempt}`;
  const jobs: unknown[] = [];
  let total = -1;
  try {
    for (let page = 1; page <= JOB_PAGE_CAP; page++) {
      const answer = await gh.listAttemptJobs(repo.owner, repo.name, runId, attempt, page, JOBS_PER_PAGE);
      const t = isPlain(answer) ? own(answer, 'total_count') : undefined;
      const list = isPlain(answer) ? own(answer, 'jobs') : undefined;
      if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0 || !Array.isArray(list)) return { kind: 'error', detail: `${what} could not be read (the answer is not a job list)` };
      if (total !== -1 && t !== total) return { kind: 'error', detail: `${what} changed while they were read` };
      total = t;
      jobs.push(...list);
      if (jobs.length >= total) break;
      if (list.length === 0) return { kind: 'error', detail: `${what} could not be read (the list is cut short)` };
    }
  } catch (e) {
    return { kind: 'error', detail: why(`${what} could not be read`, e) };
  }
  if (jobs.length < total) return { kind: 'error', detail: `${what} are more than the ${JOB_PAGE_CAP * JOBS_PER_PAGE} that are read, so a second gate job could hide` };
  if (jobs.length > total) return { kind: 'error', detail: `${what} could not be read (more jobs than the total)` };
  const gate: Record<string, unknown>[] = [];
  for (const j of jobs) {
    if (!isPlain(j)) return { kind: 'error', detail: `${what} could not be read (a job is not an object)` };
    // a job of another run or attempt in this list is an answer that is not the one asked for
    if (own(j, 'run_id') !== runId) return { kind: 'error', detail: `${what} could not be read (a job belongs to another run)` };
    const a = own(j, 'run_attempt');
    if (a !== undefined && a !== attempt) return { kind: 'error', detail: `${what} could not be read (a job belongs to another attempt)` };
    if (own(j, 'name') === gateJobName) gate.push(j);
  }
  if (gate.length === 0) return { kind: 'failed', detail: `run ${runId} has no job named ${gateJobName} in its latest attempt` };
  if (gate.length > 1) return { kind: 'failed', detail: `in the latest attempt of run ${runId} more than one job reports as the gate` };
  const g = gate[0] as Record<string, unknown>;
  const conclusion = own(g, 'conclusion');
  const shown = typeof conclusion === 'string' && /^[a-z_]{1,30}$/.test(conclusion) ? conclusion : 'not readable';
  if (own(g, 'status') !== 'completed' || conclusion !== 'success') return { kind: 'failed', detail: `the gate job of run ${runId} did not succeed in its latest attempt (${shown})` };
  return { kind: 'ok' };
}

/** Why the run did not call the central workflow at the expected commit, or undefined. Path prefix and sha field, separately, on the same entry. */
function centralProblem(run: Record<string, unknown>, central: { pathPrefix: string; sha: string }): string | undefined {
  const refs = own(run, 'referenced_workflows');
  if (!Array.isArray(refs)) return `run ${String(own(run, 'id'))} lists no referenced workflows`;
  const mine = refs.filter((e): e is Record<string, unknown> => isPlain(e) && typeof own(e, 'path') === 'string' && (own(e, 'path') as string).startsWith(`${central.pathPrefix}@`));
  if (mine.length === 0) return `run ${String(own(run, 'id'))} did not call the central workflow`;
  if (mine.some((e) => own(e, 'sha') !== central.sha)) return `run ${String(own(run, 'id'))} called the central workflow at a different commit than the expected one`;
  return undefined;
}

export async function findGatedRun(gh0: GateGithub, repo: RepoRef, sha: string, o: GatedRunOpts): Promise<GatedRun> {
  const error = (detail: string): GatedRun => ({ ok: false, reason: 'error', detail });
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) return error('the commit is not a 40-character lower-case sha');
  if (!isPlain(repo) || !posInt(repo.id) || typeof repo.owner !== 'string' || typeof repo.name !== 'string' || typeof repo.defaultBranch !== 'string' || repo.defaultBranch === '') return error('the repository is not known');
  if (o.workflowPath !== WORKFLOW_PATH) return error('run trust is defined for .github/workflows/pipegen.yml only');
  const central = o.central;
  if (central !== undefined && (!SHA_RE.test(central.sha) || typeof central.pathPrefix !== 'string' || central.pathPrefix === '' || central.pathPrefix.includes('@'))) return error('the central workflow or its commit is not usable');
  const waitMs = o.waitMs ?? DEFAULT_WAIT_MS;
  if (typeof waitMs !== 'number' || !Number.isFinite(waitMs) || waitMs < 0) return error('the wait time is not usable');
  const pollMs = Math.max(1, o.pollMs ?? DEFAULT_POLL_MS, Math.ceil(waitMs / MAX_POLLS));
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? realSleep;
  const budget = { left: o.maxCalls ?? DEFAULT_MAX_CALLS, spent: false };
  const spend = (): void => { if (budget.left <= 0) { budget.spent = true; throw new BudgetError(); } budget.left--; };
  // only the calls this search needs, each one counted; the rest of the client is not reachable from here
  const gh = {
    compare: (...a: Parameters<GateGithub['compare']>) => { spend(); return gh0.compare(...a); },
    branchHead: (...a: Parameters<GateGithub['branchHead']>) => { spend(); return gh0.branchHead(...a); },
    tagExists: (...a: Parameters<GateGithub['tagExists']>) => { spend(); return gh0.tagExists(...a); },
    listRuns: (...a: Parameters<GateGithub['listRuns']>) => { spend(); return gh0.listRuns(...a); },
    listAttemptJobs: (...a: Parameters<GateGithub['listAttemptJobs']>) => { spend(); return gh0.listAttemptJobs(...a); },
  } as unknown as GateGithub;
  const url = (id: number): string => `https://github.com/${repo.owner}/${repo.name}/actions/runs/${id}`;
  const start = now();
  /** Runs judged trusted while still running: only the decision to keep waiting. A finished run is always judged afresh. */
  const waitingFor = new Set<number>();

  for (;;) {
    let listed: unknown;
    try {
      listed = await gh.listRuns(repo.owner, repo.name, { workflow: 'pipegen.yml', branch: repo.defaultBranch, event: 'push', headSha: sha, page: 1, perPage: 100 });
    } catch (e) {
      return error(why('the runs of this commit could not be listed', e));
    }
    const runs = isPlain(listed) ? own(listed, 'workflow_runs') : undefined;
    if (!Array.isArray(runs)) return error('the runs of this commit could not be read (the answer is not a run list)');

    const lk: Lookup = {};
    const errors: string[] = [];
    const failed: string[] = [];
    const wrongCentral: string[] = [];
    let active = 0;
    let considered = 0;
    for (const r of runs) {
      if (!runFieldsTrusted(r, repo) || own(r, 'head_sha') !== sha) continue;
      if (++considered > MAX_CANDIDATES) { errors.push(`more than ${MAX_CANDIDATES} runs for this commit`); break; }
      const id = own(r, 'id') as number;
      if (central !== undefined) {
        const c = centralProblem(r, central);
        if (c !== undefined) { wrongCentral.push(c); continue; }
      }
      const attempt = own(r, 'run_attempt');
      if (!posInt(attempt)) { errors.push(`run ${id} has no usable run_attempt`); continue; }
      const status = own(r, 'status');
      const isActive = typeof status === 'string' && ACTIVE.has(status);
      if (!isActive && status !== 'completed') { errors.push(`run ${id} has a status this search does not know`); continue; }
      if (isActive && waitingFor.has(id)) { active++; continue; }
      const j = await judgeRun(gh, r, repo, undefined, lk);
      if (!j.ok) {
        if (j.why === 'untrusted' || j.why === 'history') continue;
        errors.push(j.why === 'tag' ? 'a tag named like the default branch exists, so no run is trusted until it is deleted' : `run ${id} could not be checked against the default branch`);
        continue;
      }
      if (isActive) { waitingFor.add(id); active++; continue; }
      const v = await attemptVerdict(gh, repo, id, attempt, o.gateJobName);
      if (v.kind === 'ok') return { ok: true, runId: id, url: url(id) };
      (v.kind === 'failed' ? failed : errors).push(v.detail);
    }

    if (budget.spent) return error(`the call budget of ${o.maxCalls ?? DEFAULT_MAX_CALLS} calls is used up, so the gated run could not be found`);
    if (errors.length > 0) return error(errors[0] as string);
    if (active > 0) {
      const left = waitMs - (now() - start);
      if (left <= 0) return { ok: false, reason: 'timeout', detail: `a run for this commit was still running after ${Math.round(waitMs / 60_000)} minutes` };
      await sleep(Math.min(pollMs, left));
      continue;
    }
    if (failed.length > 0) return { ok: false, reason: 'gate-failed', detail: failed[0] as string };
    if (wrongCentral.length > 0) return { ok: false, reason: 'wrong-central', detail: wrongCentral[0] as string };
    return { ok: false, reason: 'none', detail: `no trusted push run of pipegen.yml on ${repo.defaultBranch} was found for this commit; re-run the pipeline on this commit (runs older than the retention period no longer exist)` };
  }
}
