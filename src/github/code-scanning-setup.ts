// GitHub's CodeQL default setup (hand checks 2026-10-29, fix 2, ruling P55). Default setup runs CodeQL without any
// workflow file in the repo, so the coverage mapper (which reads workflow files) can't see it, and fastapi's code-scan
// rows read "missing" while CodeQL scanned every pull request.
//
// How it is read (read-only GETs, the run's one rate budget):
// 1. With a token: GET /repos/{o}/{r}/code-scanning/default-setup. GitHub lists it under the fine-grained permission
//    "Administration: read" (https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens,
//    checked 2026-10-29), which pipegen's read-only token doesn't ask for, and a classic token gets "You are not
//    authorized to read code scanning default setup" unless its user administers the repo. So a 403 or 404 here says
//    nothing about the setup; pipegen goes on to step 2. A 403 "Code scanning is not enabled" settles it: off.
// 2. GET /repos/{o}/{r}/actions/workflows (Actions: read, in pipegen's read-only token; anonymous works on a public
//    repo): default setup shows there as the dynamic workflow `dynamic/github-code-scanning/codeql`. Active → on;
//    listed and not active, or not listed in a complete list → off.
// 3. Only for "on" from step 2 (which doesn't name the languages): the latest completed run of that dynamic workflow on
//    the default branch, and its jobs, named "Analyze (<language>)". If either can't be read, the languages stay unknown.
// Anything else (no access, no answer, a list longer than one page without it) is unknown with a plain why. A rate stop
// is thrown (the caller keeps what it has and says so). Nothing here is ever written to GitHub.
import type { Octokit } from '@octokit/rest';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { githubTokenRejected, isAnonymousClient, isNoAnswer } from './client.js';

export type DefaultSetup =
  | { state: 'on'; languages: string[] | null; source: 'setup' | 'workflow' }
  | { state: 'off' }
  | { state: 'unknown'; why: string };

/** The dynamic workflow GitHub runs for CodeQL default setup. */
export const CODEQL_DYNAMIC = 'dynamic/github-code-scanning/codeql';
const LANGUAGE = /^[a-z][a-z0-9-]{0,39}$/;
const PER_PAGE = 100;

const statusOf = (e: unknown): number | undefined => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' ? s : undefined;
};
const messageOf = (e: unknown): string => {
  const err = e as { message?: unknown; response?: { data?: { message?: unknown } } } | null;
  const m = err?.response?.data?.message ?? err?.message;
  return typeof m === 'string' ? m : '';
};
const notEnabled = (e: unknown) => statusOf(e) === 403 && /code scanning is not enabled|advanced security must be enabled/i.test(messageOf(e));

type Got<T> = { ok: true; data: T } | { ok: false; error: unknown };
async function get<T>(gh: Octokit, call: () => Promise<{ data: T }>, clock: RateClock): Promise<Got<T>> {
  try {
    return { ok: true, data: (await withRateLimit(call, clock)).data };
  } catch (e) {
    if (isRateStop(e)) throw e;
    if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    return { ok: false, error: e };
  }
}

const languagesOf = (v: unknown): string[] | null => {
  if (!Array.isArray(v)) return null;
  const out = v.filter((x): x is string => typeof x === 'string' && LANGUAGE.test(x));
  return [...new Set(out)].sort();
};

/** Is CodeQL default setup on for owner/repo, and which languages does it scan? See the header for the steps. */
export async function readDefaultSetup(
  gh: Octokit, owner: string, repo: string, defaultBranch: string, clock: RateClock, anonymous: boolean = isAnonymousClient(gh),
): Promise<DefaultSetup> {
  if (!anonymous) {
    const setup = await get(gh, () => gh.rest.codeScanning.getDefaultSetup({ owner, repo }), clock);
    if (setup.ok) {
      const d = setup.data as { state?: unknown; languages?: unknown };
      if (d.state === 'configured') return { state: 'on', languages: languagesOf(d.languages), source: 'setup' };
      if (d.state === 'not-configured') return { state: 'off' };
    } else if (notEnabled(setup.error)) {
      return { state: 'off' };
    }
  }
  const list = await get(gh, () => gh.rest.actions.listRepoWorkflows({ owner, repo, per_page: PER_PAGE }), clock);
  if (!list.ok) {
    const why = isNoAnswer(list.error)
      ? "GitHub didn't answer when pipegen asked"
      : anonymous
        ? "GitHub didn't show this repo's workflow list without a token"
        : "this token can't read it (GitHub shows the setup itself only with Administration: read, and the workflow list with Actions: read)";
    return { state: 'unknown', why: `pipegen couldn't check whether GitHub's CodeQL default setup is on: ${why}.` };
  }
  const data = list.data as { total_count?: unknown; workflows?: unknown };
  const workflows = Array.isArray(data.workflows) ? (data.workflows as { id?: unknown; path?: unknown; state?: unknown }[]) : null;
  if (workflows === null) return { state: 'unknown', why: "pipegen couldn't check whether GitHub's CodeQL default setup is on: GitHub's workflow list couldn't be read." };
  const codeql = workflows.find((w) => w?.path === CODEQL_DYNAMIC);
  if (codeql === undefined) {
    const total = typeof data.total_count === 'number' ? data.total_count : Number.POSITIVE_INFINITY;
    return total <= workflows.length
      ? { state: 'off' }
      : { state: 'unknown', why: "pipegen couldn't check whether GitHub's CodeQL default setup is on: the repo has more workflows than pipegen reads in one page." };
  }
  if (codeql.state !== 'active') return { state: 'off' };
  return { state: 'on', languages: typeof codeql.id === 'number' ? await dynamicLanguages(gh, owner, repo, codeql.id, defaultBranch, clock) : null, source: 'workflow' };
}

/** The languages the latest completed default-setup run on the default branch analysed ("Analyze (python)"), or null. */
async function dynamicLanguages(gh: Octokit, owner: string, repo: string, workflowId: number, branch: string, clock: RateClock): Promise<string[] | null> {
  const runs = await get(gh, () => gh.rest.actions.listWorkflowRuns({ owner, repo, workflow_id: workflowId, branch, status: 'completed', per_page: 1 }), clock);
  if (!runs.ok) return null;
  const run = (runs.data as { workflow_runs?: { id?: unknown }[] }).workflow_runs?.[0];
  if (typeof run?.id !== 'number') return null;
  const runId = run.id;
  const jobs = await get(gh, () => gh.rest.actions.listJobsForWorkflowRun({ owner, repo, run_id: runId, per_page: PER_PAGE }), clock);
  if (!jobs.ok) return null;
  const list = (jobs.data as { jobs?: { name?: unknown }[] }).jobs;
  if (!Array.isArray(list)) return null;
  const names = list.map((j) => (typeof j?.name === 'string' ? /^Analyze \(([a-z][a-z0-9-]{0,39})\)$/.exec(j.name)?.[1] : undefined)).filter((x): x is string => x !== undefined);
  return names.length === 0 ? null : [...new Set(names)].sort();
}
