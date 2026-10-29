// The last completed run of one workflow on the default branch (hand checks 2026-10-29, fix 3, ruling P55). A check
// can be "covered" by a step that exists and can fail the build, while the workflow fails on every run (the secrets
// repo's `node --test test/` never ran a test). The run's conclusion is the one signal pipegen can read for that.
//
// GET /repos/{o}/{r}/actions/workflows/{file}/runs?branch=<default>&status=completed&exclude_pull_requests=true&per_page=1
// (a pull request opened from a fork's branch of the same name is not a run on the default branch): Actions: read (in the
// read-only token; anonymous works on a public repo). One call per workflow; a rate stop is thrown (the caller keeps
// what it has and says so); anything else is a plain "couldn't read" with its kind. Read-only.
import type { Octokit } from '@octokit/rest';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { githubTokenRejected, isAnonymousClient, isNoAnswer } from './client.js';

export type LastRun =
  | { state: 'read'; conclusion: string; createdAt: string | null }
  | { state: 'none' }
  | { state: 'unread'; why: 'access' | 'network' | 'answer' };

/** A workflow file directly under .github/workflows, as the API takes it (its file name). */
const FILE = /^\.github\/workflows\/([A-Za-z0-9._-]{1,200}\.ya?ml)$/;
export const workflowFileName = (path: string): string | null => FILE.exec(path)?.[1] ?? null;

export async function lastCompletedRun(gh: Octokit, owner: string, repo: string, workflowPath: string, branch: string, clock: RateClock): Promise<LastRun> {
  const file = workflowFileName(workflowPath);
  if (file === null) return { state: 'unread', why: 'answer' };
  let data: unknown;
  try {
    data = (await withRateLimit(() => gh.rest.actions.listWorkflowRuns({ owner, repo, workflow_id: file, branch, status: 'completed', exclude_pull_requests: true, per_page: 1 }), clock)).data;
  } catch (e) {
    if (isRateStop(e)) throw e;
    const status = (e as { status?: unknown } | null)?.status;
    if (status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    return { state: 'unread', why: isNoAnswer(e) ? 'network' : 'access' };
  }
  const runs = (data as { workflow_runs?: unknown } | null)?.workflow_runs;
  if (!Array.isArray(runs)) return { state: 'unread', why: 'answer' };
  const run = runs[0] as { conclusion?: unknown; created_at?: unknown } | undefined;
  if (run === undefined) return { state: 'none' };
  if (typeof run.conclusion !== 'string') return { state: 'unread', why: 'answer' };
  const at = typeof run.created_at === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(run.created_at) ? run.created_at : null;
  return { state: 'read', conclusion: run.conclusion, createdAt: at };
}
