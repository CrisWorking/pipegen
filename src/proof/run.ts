// Plan E Task 3 / sub-task E4 (spec §19; rulings B3, S2, S11, S13, S27; F11): the proof's PRs and runs in the scratch repo
// `pipegen-proof-<repo>`, the same flow the user's repo will see:
//   1. the proof branch is pushed (E2) → the PUSH runs of its head sha (the push layer);
//   2. a PR into the scratch default branch → the PULL_REQUEST runs of the same sha (the merge layer, the harness, the
//      compat copies);
//   3. main only, and only when the merge layer passed: the merge, with sha = the proven head (GitHub refuses it if the head
//      moved) → the PUSH runs of the merge commit on the default branch (the deploy layer, the harness verify-lookup).
//      Planted and dispute PRs are closed, never merged; every other proof PR must be closed before a merge (S27).
//   Re-runs (B3): a FAST-FORWARD commit on top of the PR's current head (never a force-push of a proof branch); the open PR
//   re-runs (synchronize) and the push-layer jobs skip. A deploy re-run after a merge: resetBase (the base snapshot forced
//   back onto the scratch default branch, which starts no run: the base holds no workflow), then a FRESH branch
//   proof/<runId>/<variant>-<round> and a new PR.
// Runs start only by push and pull_request: pipegen never calls the workflow_dispatch endpoint (plan Global Constraints; the
// guard refuses it too).
//
// Matching (findRuns): GET …/actions/runs?head_sha=&event= and then, each checked: this scratch repo's id (repository and
// head_repository: no fork's run), the exact head sha, event, head branch and workflow path, and for a pull_request run the
// PR number when GitHub lists it. Only handles findRuns made are waited for (registered, frozen). The CLI's Plan C
// findGatedRun is the harness's verify-lookup (E3); it doesn't fit here (it trusts push runs of pipegen.yml on the
// default branch only).
// Waiting: no run within NO_RUN_MS (120 s) is the actionable stop "No workflow run started on pipegen-proof-<repo>. Is
// GitHub Actions enabled there?" (S13 backstop). Then each run is polled (backoff 15 s → 60 s) until it completes, the time
// cap passes (cancelled, timed_out), shouldStop() says so (cancelled, returned), or a stop has begun (returned at once; E8's
// cleanup cancels). A finished run's jobs are read with filter=all (re-run attempts too), its conclusion mapped (S13), its
// result artifacts downloaded and the logs of the latest attempt's failed jobs and of the coverage job fetched (S2, S11).
// Every write is guardedWrite; the PR create, merge and the pushes are tracked writes (inflight.ts).
import type { Octokit } from '@octokit/rest';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { GATE_RESULT_ARTIFACT } from '../engine/artifact-names.js';
import { RESULT_ARTIFACT_PREFIX } from '../types.js';
import { interrupting } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { downloadJobLog, downloadRunArtifacts, type ArtifactFile, type DownloadDeps } from './download.js';
import { trackedTransport, trackWrite } from './inflight.js';
import {
  buildProofBranch, pushCommit, type BaseSnapshot, type ProofBranch, type ProofFile, type ProofSession, type ProofTransport, type Variant,
} from './snapshot.js';
import {
  assertScratch, githubRead, guardedWrite, isProofTarget, ProofStopError, ScratchGuardError, validBranchName, type GuardedRepo, type ProofTarget,
} from './target.js';

export type RunEvent = 'push' | 'pull_request';
/** A run findRuns matched. Only findRuns makes one (registered); waitForRuns takes no other. */
export interface RunHandle { readonly workflow: string; readonly runId: number; readonly url: string; readonly event: RunEvent; readonly headSha: string }
/** GitHub's conclusions (S13): the plan's four plus startup_failure, action_required, neutral, skipped and stale. */
export type RunConclusion = 'success' | 'failure' | 'cancelled' | 'timed_out' | 'startup_failure' | 'action_required' | 'neutral' | 'skipped' | 'stale';
export interface JobOutcome {
  id: number;
  name: string;
  /** The run attempt this job belongs to (filter=all lists every attempt's jobs). */
  attempt: number;
  status: string;
  conclusion: string | null;
  /** The job's log (latest attempt's failed jobs and the coverage job): the most recent 8 MiB. */
  log?: string;
  logCut?: boolean;
  logProblem?: string;
}
export interface RunOutcome {
  handle: RunHandle;
  conclusion: RunConclusion;
  /** What the conclusion means for the user (S13), or why pipegen stopped waiting. Plain text built from fixed words and checked names. */
  note?: string;
  /** Set when pipegen stopped waiting (shouldStop, the time cap, a stop): the run did not finish while watched. */
  stopped?: true;
  /** The run's latest attempt. */
  attempt: number;
  jobs: JobOutcome[];
  /** Result artifacts (pipegen-out-*, pipegen-gate-result), each its single file. */
  artifacts: Map<string, ArtifactFile>;
  /** Artifact name → why it couldn't be read (E5: "report unreadable"). */
  artifactProblems: Map<string, string>;
}
export interface PollClock { now(): number; sleep(ms: number): Promise<void> }
export interface RunQuery { headSha: string; event: RunEvent; workflows: readonly string[]; branch: string; pr?: number }
export interface WaitOptions {
  /** The most a wait may take (each wait: the push runs, the PR runs, the merge runs). */
  timeoutMs: number;
  onTick?: (status: string) => void;
  /** Checked before every poll: true → the runs still going are cancelled and the outcomes returned (the minutes cap). */
  shouldStop?: () => boolean;
  clock?: PollClock;
  rateClock?: RateClock;
  download?: DownloadDeps;
  /** Jobs whose log is fetched besides the failed ones (default: the coverage job, isCoverageJob). */
  logJob?: (job: { name: string; conclusion: string | null }) => boolean;
  /** Artifacts to download (default: isResultArtifact). */
  wantArtifact?: (name: string) => boolean;
}
export interface ProofWorkflows {
  /** Workflow files that run on a push of the proof branch. */
  push: readonly string[];
  /** Workflow files that run on the PR. */
  pullRequest: readonly string[];
  /** Workflow files that run on the push of the merge commit to the default branch (default: push). */
  merge?: readonly string[];
}
export interface VariantProof {
  outcomes: RunOutcome[];
  pr?: number;
  prUrl?: string;
  /** main, merged: the merge commit. */
  mergeSha?: string;
  /** The PR was closed (planted, dispute). */
  closed: boolean;
  /** pipegen stopped waiting (shouldStop, the time cap or a stop): nothing after it was done. */
  stopped: boolean;
  /** Workflows that never started within NO_RUN_MS, while others did. */
  missing: { event: RunEvent; workflow: string }[];
}

/** S13: no run within this long after the push or the PR is the "is Actions enabled" stop. */
export const NO_RUN_MS = 120_000;
/** Poll backoff (plan Task 3): 15 s, ×1.5, up to 60 s. */
export const POLL_START_MS = 15_000;
export const POLL_MAX_MS = 60_000;
/** While waiting for runs to show up. */
export const START_POLL_MS = 10_000;
/** Runs one query may list, and jobs one run may have (5 pages). */
const MAX_RUNS_LISTED = 100;
const JOB_PAGES = 5;
/** Logs fetched per run, at most. */
const MAX_LOGS_PER_RUN = 20;
const SHA_RE = /^[0-9a-f]{40}$/;
const WORKFLOW_RE = /^\.github\/workflows\/[A-Za-z0-9._-]{1,200}\.ya?ml$/;
const PROOF_NAME_RE = /^[a-z0-9][a-z0-9-]{0,80}$/;
const ACTIVE = new Set(['queued', 'in_progress', 'waiting', 'pending', 'requested']);
const FAILED_JOB = new Set(['failure', 'timed_out', 'startup_failure']);

const realClock: PollClock = { now: () => Date.now(), sleep: (ms) => new Promise((ok) => setTimeout(ok, ms)) };
const handles = new WeakMap<object, { target: ProofTarget; branch: string }>();
/** Each scratch repo's id (one read per target). */
const repoIds = new WeakMap<ProofTarget, number>();

/** The result artifacts the proof reads: pipegen-out-* and pipegen-gate-result (E5 picks from them). */
export const isResultArtifact = (name: string): boolean => name.startsWith(RESULT_ARTIFACT_PREFIX) || name === GATE_RESULT_ARTIFACT;
/** The coverage job (S11): its green log holds the measured lines. */
export const isCoverageJob = (job: { name: string }): boolean => /\bcoverage\b/i.test(job.name);

export const noRunMessage = (t: ProofTarget): string => `No workflow run started on ${t.scratch}. Is GitHub Actions enabled there?`;

const KNOWN: ReadonlySet<string> = new Set(['success', 'failure', 'cancelled', 'timed_out', 'startup_failure', 'action_required', 'neutral', 'skipped', 'stale']);
/** S13: GitHub's conclusion, with what it means for the user. Anything pipegen doesn't know is a failure (fail closed). */
export function mapConclusion(raw: unknown, scratch: string): { conclusion: RunConclusion; note?: string } {
  if (typeof raw !== 'string' || !KNOWN.has(raw)) {
    return { conclusion: 'failure', note: `GitHub gave the run a conclusion pipegen doesn't know (${safeText(String(raw), 40)}), so it counts as failed` };
  }
  const c = raw as RunConclusion;
  switch (c) {
    case 'startup_failure': return { conclusion: c, note: `a workflow could not start (an action pipegen uses isn't reachable from ${scratch})` };
    case 'action_required': return { conclusion: c, note: `the run waits for an approval in ${scratch} (Actions → the run → Approve and run); it proves nothing until it runs` };
    case 'neutral': return { conclusion: c, note: 'the run ended neutral (neither passed nor failed), which proves nothing' };
    case 'skipped': return { conclusion: c, note: 'the run was skipped' };
    case 'stale': return { conclusion: c, note: 'GitHub marked the run stale (it did not finish in time), so it proves nothing' };
    default: return { conclusion: c };
  }
}

// ---------- small helpers ----------

function hard(gh: Octokit, e: unknown): void {
  if (isRateStop(e)) throw e;
  if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
}
const said = (e: unknown): string => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' && Number.isInteger(s) ? `HTTP ${s}` : 'no answer';
};
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const scratchOf = (t: ProofTarget): GuardedRepo => assertScratch(t, { owner: t.owner, repo: t.appRepo });
function checkTarget(t: ProofTarget): void {
  if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
}
/** A branch of this run's proof (proof/<runId>/<name>), else ScratchGuardError. */
function proofBranch(t: ProofTarget, branch: string): string {
  const prefix = `proof/${t.runId}/`;
  if (typeof branch !== 'string' || !branch.startsWith(prefix) || !PROOF_NAME_RE.test(branch.slice(prefix.length)) || !validBranchName(branch)) {
    throw new ScratchGuardError(`"${safeText(String(branch), 100)}" is not a proof branch of this run.`);
  }
  return branch;
}
/** main, or a round of it (main-<n>): the only branches ever merged. */
const isMainBranch = (t: ProofTarget, branch: string): boolean => new RegExp(`^proof/${t.runId}/main(?:-(?:[2-9]|[1-9][0-9]))?$`).test(branch);

async function scratchRepoId(gh: Octokit, t: ProofTarget, s: GuardedRepo, clock: RateClock): Promise<number> {
  const known = repoIds.get(t);
  if (known !== undefined) return known;
  let d: unknown;
  try {
    d = (await githubRead(gh, 'GET /repos/{owner}/{repo}', { owner: s.owner, repo: s.repo }, clock)).data;
  } catch (e) {
    hard(gh, e);
    throw new ProofStopError(`pipegen couldn't read ${s.fullName} (${said(e)}).`);
  }
  const id = isPlain(d) ? d.id : undefined;
  const full = isPlain(d) ? d.full_name : undefined;
  if (!posInt(id) || typeof full !== 'string' || full.toLowerCase() !== s.fullName.toLowerCase()) throw new ProofStopError(`GitHub's answer about ${s.fullName} could not be read.`);
  repoIds.set(t, id);
  return id;
}

// ---------- pull requests ----------

interface PrSeen { number: number; state: string; merged: boolean; headRef: string; headSha: string; headRepo: string; baseRef: string; url: string }
function prOf(d: unknown): PrSeen | null {
  if (!isPlain(d) || !posInt(d.number) || typeof d.state !== 'string' || !isPlain(d.head) || !isPlain(d.base)) return null;
  const headRepo = isPlain(d.head.repo) && typeof d.head.repo.full_name === 'string' ? d.head.repo.full_name : '';
  if (typeof d.head.ref !== 'string' || typeof d.head.sha !== 'string' || typeof d.base.ref !== 'string') return null;
  return { number: d.number, state: d.state, merged: d.merged === true, headRef: d.head.ref, headSha: d.head.sha, headRepo, baseRef: d.base.ref, url: typeof d.html_url === 'string' ? d.html_url : '' };
}
const prUrl = (s: GuardedRepo, n: number): string => `https://github.com/${s.fullName}/pull/${n}`;

/** Opens the PR proof branch → the scratch default branch (a tracked write). GitHub's answer must be that PR, from this repo. */
export async function openProofPr(gh: Octokit, t: ProofTarget, branch: string, clock: RateClock = clockOf(gh)): Promise<{ number: number; url: string }> {
  checkTarget(t);
  const s = scratchOf(t);
  const head = proofBranch(t, branch);
  const res = await trackWrite(`pull request ${head}`, () => guardedWrite(gh, s, 'POST /repos/{owner}/{repo}/pulls', {
    title: `pipegen proof ${t.runId}: ${head.slice(`proof/${t.runId}/`.length)}`,
    head, base: t.defaultBranch,
    body: 'A pipegen proof run (scratch repo only). pipegen closes or merges it and deletes it with the scratch repo\'s cleanup.',
  }, clock));
  const pr = prOf(res.data);
  if (pr === null || pr.headRef !== head || pr.baseRef !== t.defaultBranch || pr.headRepo.toLowerCase() !== s.fullName.toLowerCase()) {
    throw new ProofStopError(`GitHub's answer to opening the proof PR in ${s.fullName} doesn't name that PR.`);
  }
  return { number: pr.number, url: prUrl(s, pr.number) };
}

async function readPr(gh: Octokit, s: GuardedRepo, pr: number, clock: RateClock): Promise<PrSeen> {
  let d: unknown;
  try {
    d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner: s.owner, repo: s.repo, pull_number: pr }, clock)).data;
  } catch (e) {
    hard(gh, e);
    throw new ProofStopError(`pipegen couldn't read PR #${pr} of ${s.fullName} (${said(e)}).`);
  }
  const seen = prOf(d);
  if (seen === null || seen.number !== pr) throw new ProofStopError(`GitHub's answer about PR #${pr} of ${s.fullName} could not be read.`);
  return seen;
}

/**
 * Merges the main proof PR with sha = `headSha`, the head the PR runs proved (GitHub refuses the merge if the head moved),
 * and returns the merge commit. Refused before any write: a PR that isn't open, isn't from main (or a main round) of this
 * run into the default branch, whose head isn't `headSha`; or any OTHER open PR in the scratch repo (S27: the planted and
 * dispute PRs are closed before the main merge).
 */
export async function mergeProofPr(gh: Octokit, t: ProofTarget, pr: number, headSha: string, clock: RateClock = clockOf(gh)): Promise<string> {
  checkTarget(t);
  const s = scratchOf(t);
  if (!posInt(pr)) throw new ScratchGuardError('the PR number is not a number.');
  if (typeof headSha !== 'string' || !SHA_RE.test(headSha)) throw new ScratchGuardError('the proven head is not a 40-hex commit sha.');
  const seen = await readPr(gh, s, pr, clock);
  if (seen.state !== 'open' || seen.merged) throw new ProofStopError(`PR #${pr} of ${s.fullName} is not open; pipegen merges only the open main proof PR.`);
  if (!isMainBranch(t, seen.headRef) || seen.headRepo.toLowerCase() !== s.fullName.toLowerCase() || seen.baseRef !== t.defaultBranch) {
    throw new ScratchGuardError(`PR #${pr} is not the main proof PR of this run; planted and dispute PRs are closed, never merged.`);
  }
  if (seen.headSha !== headSha) throw new ProofStopError(`PR #${pr}'s head is ${safeText(seen.headSha, 40)}, not the proven head ${headSha}; pipegen merges only what it proved.`);
  let list: unknown;
  try {
    list = (await githubRead(gh, 'GET /repos/{owner}/{repo}/pulls', { owner: s.owner, repo: s.repo, state: 'open', per_page: 100 }, clock)).data;
  } catch (e) {
    hard(gh, e);
    throw new ProofStopError(`pipegen couldn't list the open PRs of ${s.fullName} (${said(e)}).`);
  }
  if (!Array.isArray(list) || list.length >= 100) throw new ProofStopError(`pipegen couldn't read the open PRs of ${s.fullName}.`);
  const others = list.map(prOf).filter((p) => p === null || p.number !== pr);
  if (others.length > 0) {
    throw new ProofStopError(`Other PRs are still open in ${s.fullName} (${others.map((p) => (p === null ? '?' : `#${p.number}`)).join(', ')}); pipegen must close the planted and dispute PRs before it merges the main one.`);
  }
  const res = await trackWrite(`merge of PR #${pr}`, () => guardedWrite(gh, s, 'PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', { pull_number: pr, sha: headSha, merge_method: 'merge' }, clock));
  const d = res.data;
  const sha = isPlain(d) ? d.sha : undefined;
  if (!isPlain(d) || d.merged !== true || typeof sha !== 'string' || !SHA_RE.test(sha)) throw new ProofStopError(`GitHub didn't confirm the merge of PR #${pr} in ${s.fullName}.`);
  return sha;
}

/** Closes a proof PR (planted, dispute; or main when the proof stops). */
export async function closeProofPr(gh: Octokit, t: ProofTarget, pr: number, clock: RateClock = clockOf(gh)): Promise<void> {
  checkTarget(t);
  if (!posInt(pr)) throw new ScratchGuardError('the PR number is not a number.');
  const res = await guardedWrite(gh, scratchOf(t), 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}', { pull_number: pr, state: 'closed' }, clock);
  const seen = prOf(res.data);
  if (seen !== null && seen.state !== 'closed') throw new ProofStopError(`GitHub didn't confirm PR #${pr} is closed.`);
}

/** B3: the base snapshot forced back onto the scratch default branch (the base holds no workflow, so no run starts). */
export async function resetBase(s: ProofSession, base: BaseSnapshot, transport: ProofTransport): Promise<void> {
  if (base?.commit?.kind !== 'base' || base.commit.sha !== base.sha) throw new ScratchGuardError('resetBase takes only the base snapshot of its proof session.');
  await pushCommit(s, base.commit, trackedTransport(transport));
}

// ---------- runs ----------

/** One query's runs, each checked (see the file comment); handles registered for waitForRuns. */
export async function findRuns(gh: Octokit, t: ProofTarget, q: RunQuery, clock: RateClock = clockOf(gh)): Promise<RunHandle[]> {
  checkTarget(t);
  const s = scratchOf(t);
  if (typeof q.headSha !== 'string' || !SHA_RE.test(q.headSha)) throw new ScratchGuardError('the head sha is not a 40-hex commit sha.');
  if (q.event !== 'push' && q.event !== 'pull_request') throw new ScratchGuardError('pipegen waits only for push and pull_request runs.');
  for (const w of q.workflows) if (typeof w !== 'string' || !WORKFLOW_RE.test(w)) throw new ScratchGuardError(`"${safeText(String(w), 100)}" is not a workflow file path.`);
  if (q.branch !== t.defaultBranch) proofBranch(t, q.branch);
  const id = await scratchRepoId(gh, t, s, clock);
  let d: unknown;
  try {
    d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs', { owner: s.owner, repo: s.repo, head_sha: q.headSha, event: q.event, per_page: MAX_RUNS_LISTED }, clock)).data;
  } catch (e) {
    hard(gh, e);
    throw new ProofStopError(`pipegen couldn't list the workflow runs of ${s.fullName} (${said(e)}).`);
  }
  if (!isPlain(d) || !Array.isArray(d.workflow_runs) || typeof d.total_count !== 'number') throw new ProofStopError(`GitHub's list of the workflow runs of ${s.fullName} could not be read.`);
  if (d.total_count > MAX_RUNS_LISTED) throw new ProofStopError(`${s.fullName} lists more than ${MAX_RUNS_LISTED} runs for one commit; pipegen can't tell which are its own.`);
  const wanted = new Set(q.workflows);
  const out: RunHandle[] = [];
  for (const r of d.workflow_runs as unknown[]) {
    if (!isPlain(r) || !posInt(r.id)) continue;
    const repoId = isPlain(r.repository) ? r.repository.id : undefined;
    const headRepoId = isPlain(r.head_repository) ? r.head_repository.id : undefined;
    if (repoId !== id || headRepoId !== id) continue;                       // a fork's run, or another repo's
    if (r.head_sha !== q.headSha || r.event !== q.event || r.head_branch !== q.branch) continue;
    if (typeof r.path !== 'string' || !wanted.has(r.path)) continue;
    if (q.event === 'pull_request' && q.pr !== undefined && Array.isArray(r.pull_requests) && r.pull_requests.length > 0
      && !r.pull_requests.some((p) => isPlain(p) && p.number === q.pr)) continue;
    const url = `https://github.com/${s.fullName}/actions/runs/${r.id}`;
    const h: RunHandle = Object.freeze({ workflow: r.path, runId: r.id, url, event: q.event, headSha: q.headSha });
    handles.set(h, { target: t, branch: q.branch });
    out.push(h);
  }
  return out.sort((a, b) => q.workflows.indexOf(a.workflow) - q.workflows.indexOf(b.workflow) || a.runId - b.runId);
}

/**
 * Waits until every workflow of `q` has a run, or NO_RUN_MS passed: none at all is the S13 stop; some missing are
 * returned as missing. A stop or shouldStop returns what was found.
 */
async function awaitStart(gh: Octokit, t: ProofTarget, q: RunQuery, opts: WaitOptions): Promise<{ handles: RunHandle[]; missing: string[]; stopped: boolean }> {
  const clock = opts.clock ?? realClock;
  const rate = opts.rateClock ?? clockOf(gh);
  const start = clock.now();
  let found: RunHandle[] = [];
  for (;;) {
    if (interrupting() || opts.shouldStop?.() === true) return { handles: found, missing: [], stopped: true };
    found = await findRuns(gh, t, q, rate);
    const missing = q.workflows.filter((w) => !found.some((h) => h.workflow === w));
    if (missing.length === 0) return { handles: found, missing, stopped: false };
    const waited = clock.now() - start;
    if (waited >= NO_RUN_MS) {
      if (found.length === 0) throw new ProofStopError(noRunMessage(t));
      return { handles: found, missing, stopped: false };
    }
    opts.onTick?.(`waiting for the ${q.event} runs to start in ${t.scratch} (${found.length} of ${q.workflows.length})`);
    await clock.sleep(Math.min(START_POLL_MS, NO_RUN_MS - waited));
  }
}

async function readJobs(gh: Octokit, s: GuardedRepo, runId: number, clock: RateClock): Promise<JobOutcome[] | string> {
  const jobs: JobOutcome[] = [];
  for (let page = 1; page <= JOB_PAGES; page++) {
    let d: unknown;
    try {
      d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs', { owner: s.owner, repo: s.repo, run_id: runId, filter: 'all', per_page: 100, page }, clock)).data;
    } catch (e) {
      hard(gh, e);
      return `the jobs of run ${runId} could not be read (${said(e)})`;
    }
    if (!isPlain(d) || !Array.isArray(d.jobs) || typeof d.total_count !== 'number') return `the jobs of run ${runId} could not be read`;
    for (const j of d.jobs as unknown[]) {
      if (!isPlain(j) || !posInt(j.id) || j.run_id !== runId || typeof j.name !== 'string' || typeof j.status !== 'string') return `the jobs of run ${runId} could not be read`;
      const attempt = posInt(j.run_attempt) ? j.run_attempt : 1;
      jobs.push({ id: j.id, name: safeText(j.name, 200), attempt, status: j.status, conclusion: typeof j.conclusion === 'string' ? j.conclusion : null });
    }
    if (jobs.length >= d.total_count) return jobs;
    if (d.jobs.length === 0) return `the jobs of run ${runId} are cut short`;
  }
  return `run ${runId} has more jobs than pipegen reads`;
}

interface Pending { h: RunHandle; attempt: number }

/**
 * Polls the runs until each completes, then collects it (jobs, logs, artifacts). shouldStop → the runs still going are
 * cancelled and every outcome returned; the time cap → the same, those runs timed_out; a stop that has begun → returned at
 * once, nothing sent (E8's cleanup cancels). Takes only handles findRuns made for `t`.
 */
export async function waitForRuns(gh: Octokit, t: ProofTarget, hs: readonly RunHandle[], opts: WaitOptions): Promise<RunOutcome[]> {
  checkTarget(t);
  for (const h of hs) if (handles.get(h)?.target !== t) throw new ScratchGuardError('waitForRuns takes only runs findRuns matched for this target.');
  const s = scratchOf(t);
  const clock = opts.clock ?? realClock;
  const rate = opts.rateClock ?? clockOf(gh);
  const deadline = clock.now() + Math.max(0, opts.timeoutMs);
  const done = new Map<RunHandle, RunOutcome>();
  let pending: Pending[] = hs.map((h) => ({ h, attempt: 1 }));
  let interval = POLL_START_MS;
  const empty = (p: Pending, conclusion: RunConclusion, note: string): RunOutcome =>
    ({ handle: p.h, conclusion, note, stopped: true, attempt: p.attempt, jobs: [], artifacts: new Map(), artifactProblems: new Map() });
  const cancelAll = async (why: string, conclusion: RunConclusion): Promise<void> => {
    for (const p of pending) {
      let note = why;
      try {
        await guardedWrite(gh, s, 'POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel', { run_id: p.h.runId }, rate);
      } catch (e) {
        if (isRateStop(e)) throw e;
        note = `${why}; pipegen couldn't cancel it (${e instanceof ScratchGuardError ? 'stopping' : said(e)})`;
      }
      done.set(p.h, empty(p, conclusion, note));
    }
    pending = [];
  };
  for (;;) {
    if (interrupting()) {
      for (const p of pending) done.set(p.h, empty(p, 'cancelled', 'pipegen is stopping; the run was not watched to its end'));
      pending = [];
      break;
    }
    if (opts.shouldStop?.() === true) {
      await cancelAll('stopped by pipegen before it finished (cancelled)', 'cancelled');
      break;
    }
    const still: Pending[] = [];
    for (const p of pending) {
      let d: unknown;
      try {
        d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs/{run_id}', { owner: s.owner, repo: s.repo, run_id: p.h.runId }, rate)).data;
      } catch (e) {
        hard(gh, e);
        still.push(p);   // a failed poll is tried again at the next one
        continue;
      }
      if (!isPlain(d) || d.id !== p.h.runId || d.head_sha !== p.h.headSha || typeof d.status !== 'string') throw new ProofStopError(`GitHub's answer about run ${p.h.runId} of ${s.fullName} could not be read.`);
      const attempt = posInt(d.run_attempt) ? d.run_attempt : 1;
      if (d.status !== 'completed') {
        if (!ACTIVE.has(d.status)) throw new ProofStopError(`Run ${p.h.runId} of ${s.fullName} has a status pipegen doesn't know (${safeText(d.status, 40)}).`);
        still.push({ h: p.h, attempt });
        continue;
      }
      done.set(p.h, await collect(gh, s, p.h, attempt, d.conclusion, opts, rate));
    }
    pending = still;
    if (pending.length === 0) break;
    opts.onTick?.(`${hs.length - pending.length} of ${hs.length} runs finished in ${t.scratch}`);
    const left = deadline - clock.now();
    if (left <= 0) {
      await cancelAll(`pipegen stopped waiting after ${Math.round(opts.timeoutMs / 60_000)} minutes (cancelled)`, 'timed_out');
      break;
    }
    await clock.sleep(Math.min(interval, left));
    interval = Math.min(POLL_MAX_MS, interval * 1.5);
  }
  return hs.map((h) => done.get(h) as RunOutcome);
}

async function collect(gh: Octokit, s: GuardedRepo, h: RunHandle, attempt: number, raw: unknown, opts: WaitOptions, rate: RateClock): Promise<RunOutcome> {
  const { conclusion, note } = mapConclusion(raw, s.repo);
  const out: RunOutcome = { handle: h, conclusion, ...(note === undefined ? {} : { note }), attempt, jobs: [], artifacts: new Map(), artifactProblems: new Map() };
  const jobs = await readJobs(gh, s, h.runId, rate);
  if (typeof jobs === 'string') out.artifactProblems.set('(jobs)', jobs);
  else out.jobs = jobs;
  // logs: the latest attempt's failed jobs and the coverage job (S2, S11)
  const extra = opts.logJob ?? isCoverageJob;
  const dl = { ...(opts.download ?? {}), clock: rate };
  let logs = 0;
  for (const j of out.jobs) {
    if (j.attempt !== attempt) continue;
    if (!(j.conclusion !== null && FAILED_JOB.has(j.conclusion)) && !extra(j)) continue;
    if (++logs > MAX_LOGS_PER_RUN) { j.logProblem = `more than ${MAX_LOGS_PER_RUN} logs in one run; not fetched`; continue; }
    const l = await downloadJobLog(gh, s, j.id, dl);
    if (l.log !== undefined) { j.log = l.log; if (l.cut) j.logCut = true; }
    if (l.problem !== undefined) j.logProblem = l.problem;
  }
  const arts = await downloadRunArtifacts(gh, s, h.runId, opts.wantArtifact ?? isResultArtifact, dl);
  out.artifacts = arts.files;
  for (const [k, v] of arts.problems) out.artifactProblems.set(k, v);
  return out;
}

async function waitEvent(gh: Octokit, t: ProofTarget, q: RunQuery, opts: WaitOptions, into: VariantProof): Promise<RunOutcome[]> {
  if (q.workflows.length === 0) return [];
  const started = await awaitStart(gh, t, q, opts);
  for (const w of started.missing) into.missing.push({ event: q.event, workflow: w });
  if (started.stopped) {
    into.stopped = true;
    // runs already found are cancelled the same way (unless a stop has begun: E8 then cancels)
    const outs = started.handles.length === 0 ? [] : await waitForRuns(gh, t, started.handles, { ...opts, shouldStop: () => true });
    into.outcomes.push(...outs);
    return outs;
  }
  const outs = await waitForRuns(gh, t, started.handles, opts);
  into.outcomes.push(...outs);
  if (outs.some((o) => o.stopped === true)) into.stopped = true;
  return outs;
}

const notStopping = (): void => {
  if (interrupting()) throw new ProofStopError('pipegen is stopping; the proof does not go on.');
};

/**
 * One variant, already pushed (E2's pushProofSetup or a re-run): the push runs of its head, the PR (`pr`: the open one a
 * re-run pushed to) and its runs, then for main with `merge` (and `mergeWhen`, default: every PR run succeeded) the merge
 * with the proven head and the merge commit's push runs. A non-main variant is never merged (ScratchGuardError): its PR is
 * closed after its runs (unless `keepOpen`, for its own fix loop).
 */
export async function proveVariant(gh: Octokit, t: ProofTarget, v: { branch: ProofBranch; merge: boolean; workflows: ProofWorkflows; pr?: number; keepOpen?: boolean },
  opts: WaitOptions & { mergeWhen?: (prOutcomes: RunOutcome[]) => boolean }): Promise<VariantProof> {
  checkTarget(t);
  const branch = proofBranch(t, v.branch.branch);
  if (!SHA_RE.test(v.branch.sha)) throw new ScratchGuardError('the proof branch head is not a 40-hex commit sha.');
  const main = isMainBranch(t, branch);
  if (v.merge && !main) throw new ScratchGuardError(`only the main proof PR is ever merged; ${branch} is closed after its runs.`);
  const rate = opts.rateClock ?? clockOf(gh);
  const into: VariantProof = { outcomes: [], closed: false, stopped: false, missing: [] };
  // 1. the push layer
  await waitEvent(gh, t, { headSha: v.branch.sha, event: 'push', workflows: v.workflows.push, branch }, opts, into);
  if (into.stopped) return into;
  // 2. the PR (a new one, or the open one a re-run pushed to) and its runs
  notStopping();
  if (v.pr === undefined) {
    const pr = await openProofPr(gh, t, branch, rate);
    into.pr = pr.number;
    into.prUrl = pr.url;
  } else {
    into.pr = v.pr;
    into.prUrl = prUrl(scratchOf(t), v.pr);
  }
  const prOuts = await waitEvent(gh, t, { headSha: v.branch.sha, event: 'pull_request', workflows: v.workflows.pullRequest, branch, pr: into.pr }, opts, into);
  if (into.stopped) return into;
  // 3. merge (main) or close (planted, dispute)
  notStopping();
  if (!main) {
    if (v.keepOpen === true) return into;   // a dispute or planted fix loop re-runs it; mergeProofPr refuses while it is open (S27)
    await closeProofPr(gh, t, into.pr, rate);
    into.closed = true;
    return into;
  }
  if (!v.merge) return into;
  const ok = opts.mergeWhen ?? ((o: RunOutcome[]) => o.length > 0 && o.every((x) => x.conclusion === 'success'));
  if (!ok(prOuts)) return into;
  into.mergeSha = await mergeProofPr(gh, t, into.pr, v.branch.sha, rate);
  await waitEvent(gh, t, { headSha: into.mergeSha, event: 'push', workflows: v.workflows.merge ?? v.workflows.push, branch: t.defaultBranch }, opts, into);
  return into;
}

/**
 * B3: a fix-loop re-run. A FAST-FORWARD commit with `files` on top of the PR's current head (which must be `branch.sha`),
 * pushed without force (a tracked write); then the push runs (their jobs skip while the PR is open) and the PR's
 * synchronize runs of the new head.
 */
export async function rerunProof(gh: Octokit, t: ProofTarget, s: ProofSession, v: { branch: ProofBranch; pr: number; files: readonly ProofFile[]; pipegenWorkflows: ReadonlySet<string>; workflows: ProofWorkflows },
  opts: WaitOptions & { transport: ProofTransport }): Promise<{ branch: ProofBranch; proof: VariantProof; outcomes: RunOutcome[] }> {
  checkTarget(t);
  if (s.target !== t) throw new ScratchGuardError('the proof session was made for another target.');
  const branch = proofBranch(t, v.branch.branch);
  const rate = opts.rateClock ?? clockOf(gh);
  const seen = await readPr(gh, scratchOf(t), v.pr, rate);
  if (seen.state !== 'open' || seen.headRef !== branch) throw new ProofStopError(`PR #${v.pr} is not the open PR of ${branch}.`);
  if (seen.headSha !== v.branch.sha) throw new ProofStopError(`${v.branch.sha.slice(0, 12)} is not the head of PR #${v.pr} (${safeText(seen.headSha, 40).slice(0, 12)}); a re-run builds on the head it proved.`);
  const round = roundOf(t, branch, v.branch.variant);
  notStopping();
  const c = await buildProofBranch(s, v.branch.variant, [v.files], { pipegenWorkflows: v.pipegenWorkflows, parent: v.branch.sha, ...(round === undefined ? {} : { round }) });
  if (c.branch !== branch) throw new ScratchGuardError('the re-run commit is for another branch.');
  await pushCommit(s, c, trackedTransport(opts.transport));
  const next: ProofBranch = { variant: v.branch.variant, branch, sha: c.sha, commits: [...c.commits] };
  const proof = await proveVariant(gh, t, { branch: next, merge: false, workflows: v.workflows, pr: v.pr }, opts);
  return { branch: next, proof, outcomes: proof.outcomes };
}

/** The round of a round branch (proof/<runId>/<variant>-<n>), or undefined for the variant's own branch. */
function roundOf(t: ProofTarget, branch: string, variant: Variant): number | undefined {
  const own = `proof/${t.runId}/${variant}`;
  if (branch === own) return undefined;
  const m = new RegExp(`^${own.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-([2-9]|[1-9][0-9])$`).exec(branch);
  if (m === null) throw new ScratchGuardError(`${branch} is not a branch of the ${variant} variant.`);
  return Number(m[1]);
}

/**
 * B3: the deploy layer again after a merge. The fresh branch proof/<runId>/<variant>-<round> is built first (base +
 * `files`; a round already used is refused before anything is pushed), then resetBase, then the push, then the variant's
 * proof with a new PR (merged for main).
 */
export async function redeployProof(gh: Octokit, t: ProofTarget, s: ProofSession, v: { base: BaseSnapshot; variant: Variant; round: number; files: readonly ProofFile[]; pipegenWorkflows: ReadonlySet<string>; workflows: ProofWorkflows },
  opts: WaitOptions & { transport: ProofTransport; mergeWhen?: (prOutcomes: RunOutcome[]) => boolean }): Promise<VariantProof & { branch: ProofBranch }> {
  checkTarget(t);
  if (s.target !== t) throw new ScratchGuardError('the proof session was made for another target.');
  notStopping();
  const c = await buildProofBranch(s, v.variant, [v.files], { pipegenWorkflows: v.pipegenWorkflows, round: v.round });
  await resetBase(s, v.base, opts.transport);
  notStopping();
  await pushCommit(s, c, trackedTransport(opts.transport));
  const branch: ProofBranch = { variant: v.variant, branch: c.branch, sha: c.sha, commits: [...c.commits] };
  const proof = await proveVariant(gh, t, { branch, merge: v.variant === 'main', workflows: v.workflows }, opts);
  return { ...proof, branch };
}
