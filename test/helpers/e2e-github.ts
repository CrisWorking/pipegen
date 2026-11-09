// v0.2 Plan G G16: the fake GitHub of the local end-to-end run (test/cli-run-e2e.test.ts). It is FinishGitHub (deliver-github.ts +
// finish-github.ts: repos, git data, pull requests, rulesets, environments, secrets, variables) plus the few reads `pipegen run`'s own
// stages make before and after the delivery (the token's user, the capability probes, the gate's pinned commit). Its Octokit is a REAL
// Octokit whose requests are answered by `request` here, so every stage that calls `gh.rest.*` runs its real code. It also keeps the
// proof's record: every push, run, artifact and cleanup step the e2e's proof ops make is written to `proof`, on one timeline with the
// GitHub calls (`timeline`). No network.
import { Octokit } from '@octokit/rest';
import { makeOctokit } from '../../src/github/client.js';
import type { Call, Repo } from './deliver-github.js';
import { FinishGitHub } from './finish-github.js';

type Obj = Record<string, any>;
const fail = (status: number, message = 'Not Found'): never => {
  throw Object.assign(new Error(message), { status, response: { status, headers: {}, data: { message } } });
};

/**
 * What the proof did on the fake GitHub that no GitHub call shows: the commits the (recording) git transport pushed, and the runs the recorded
 * answers gave. The API side of the proof (the secrets, the branches, the runs, the empty commit) is in `calls` and `timeline` like any other call.
 */
export interface ProofRecord {
  /** Every push of the git transport: the repo, the branch and the file paths of the pushed commit (read back from the proof session's own repo). */
  pushes: { repo: string; branch: string; files: string[] }[];
  /** Every proof run the fake answered. */
  runs: { variant: string; event: string; conclusion: string; jobs: string[]; artifacts: string[] }[];
}

/** A made-up credential the fake accepts (built at run time: nothing secret-like in a committed file). */
export const E2E_VALUE = ['e2e', 'made', 'up', 'value', '0'.repeat(16)].join('-');

export class E2eGitHub extends FinishGitHub {
  /** The routes no one answered (a test fails on any it did not expect). */
  readonly unrouted: string[] = [];
  /** One ordered log of the proof's steps and the milestones the run reaches (the preview, the delivery), for order checks. */
  readonly timeline: string[] = [];
  readonly proof: ProofRecord = { pushes: [], runs: [] };
  /** The Actions runs of each repo (full name, lower case), as the proof's scratch repo lists them; the cleanup deletes them. */
  readonly #runs = new Map<string, { id: number; status: string; created_at: string }[]>();
  #runId = 7000;
  /** GitHub's clock, as the `date` header of the lists the minutes meter reads. */
  serverDate = new Date(Date.UTC(2026, 10, 7, 10, 2, 0)).toUTCString();
  /** Commits the fake answers for without holding a repo's history: `owner/repo@sha` (the gate at its pinned commit). */
  readonly knownCommits = new Set<string>();
  /** The token user and the plan GitHub reports for it. */
  login = 'CrisWorking';
  plan = 'pro';

  /** A finished workflow run in `fullName` (the proof's recorded answers; the real cleanup lists and deletes it). */
  addRun(fullName: string): number {
    const id = this.#runId++;
    const list = this.#runs.get(fullName.toLowerCase()) ?? [];
    list.push({ id, status: 'completed', created_at: '2026-11-07T10:00:30Z' });
    this.#runs.set(fullName.toLowerCase(), list);
    return id;
  }
  /** The ids of the runs `fullName` still lists. */
  actionRuns(fullName: string): number[] { return (this.#runs.get(fullName.toLowerCase()) ?? []).map((r) => r.id); }
  /** A push of the recording git transport landing: the branch now points at `sha` (the commit's objects live in the proof session's own repo). */
  land(fullName: string, branch: string, sha: string): void { this.repo(fullName).refs.set(`heads/${branch}`, sha); }

  /** The steps of the proof worth ordering against each other, written to the timeline as the call arrives (what the route is, not what the test claims). */
  #note(route: string, p: Obj): void {
    const scratch = /^pipegen-proof-/.test(String(p.repo));
    const ref = String(p.ref ?? '');
    if (route === 'DELETE /repos/{owner}/{repo}/automated-security-fixes' && scratch) this.timeline.push('setup: dependabot updates off');
    else if (route === 'GET /repos/{owner}/{repo}/actions/runs' && scratch && p.head_sha !== undefined) this.timeline.push('setup: no-run check');
    else if (route === 'PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}' && scratch) this.timeline.push(`scratch secret stored:${String(p.secret_name)}`);
    else if (route === 'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}' && scratch) this.timeline.push(`scratch secret deleted:${String(p.secret_name)}`);
    else if (route === 'DELETE /repos/{owner}/{repo}/git/refs/{ref}' && ref.startsWith('heads/proof/')) this.timeline.push(`${scratch ? 'scratch' : 'central'} proof branch deleted:${ref}`);
    else if (route === 'DELETE /repos/{owner}/{repo}/actions/runs/{run_id}' && scratch) this.timeline.push('scratch run deleted');
    else if (route === 'PATCH /repos/{owner}/{repo}/git/refs/{ref}' && scratch && ref === 'heads/main') this.timeline.push('scratch default branch reset');
  }

  /** The real Octokit, with every request answered here. */
  override octokit(): Octokit {
    const gh = makeOctokit(E2E_VALUE, { fetch: (() => { throw new Error('the e2e has no network'); }) as unknown as typeof fetch, log: () => {} });
    gh.hook.wrap('request', (async (_request: unknown, options: Obj) => {
      const route = `${String(options.method)} ${String(options.url)}`;
      // the parameters Octokit merged into the options (path, query and body), without its own plumbing
      const { method: _m, url: _u, headers: _h, request: _r, baseUrl: _b, mediaType: _mt, ...params } = options;
      return this.request(route, params);
    }) as never);
    return gh;
  }

  override async request(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown; headers: Record<string, string> }> {
    const p = params as Obj;
    const ok = (data: unknown, status = 200, headers: Record<string, string> = {}) => ({ status, data, headers });
    this.#note(route, p);
    const named = (): Repo => {
      const r = this.repos.get(`${String(p.owner)}/${String(p.repo)}`.toLowerCase());
      return r === undefined ? fail(404) : r;
    };
    const log = (): void => { this.calls.push({ route, params: { ...params } }); };
    switch (route) {
      case 'GET /user':
        this.calls.push({ route, params: { ...params } });
        return ok({ login: this.login, id: 1, type: 'User', plan: { name: this.plan } });
      case 'GET /repos/{owner}/{repo}/commits/{ref}': {
        this.calls.push({ route, params: { ...params } });
        if (this.knownCommits.has(`${String(p.owner)}/${String(p.repo)}@${String(p.ref)}`.toLowerCase())) return ok({ sha: String(p.ref) });
        const r = this.repos.get(`${String(p.owner)}/${String(p.repo)}`.toLowerCase());
        if (r === undefined) return fail(404);
        const sha = r.commits.has(String(p.ref)) ? String(p.ref) : r.refs.get(`heads/${String(p.ref)}`);
        return sha === undefined ? fail(404) : ok({ sha });
      }
      case 'GET /repos/{owner}/{repo}/environments': {
        this.calls.push({ route, params: { ...params } });
        const r = this.repos.get(`${String(p.owner)}/${String(p.repo)}`.toLowerCase());
        if (r === undefined) return fail(404);
        return ok({ total_count: r.envs.size, environments: [...r.envs].map(([name, e]) => ({ id: e.id, name, deployment_branch_policy: e.deployment_branch_policy })) });
      }
      case 'GET /repos/{owner}/{repo}/code-scanning/analyses':
        this.calls.push({ route, params: { ...params } });
        return ok([]);
      // ---- what pushProofSetup and cleanupAfterProof read and write in the scratch repo (and the central proof branch) ----
      case 'DELETE /repos/{owner}/{repo}/automated-security-fixes':
        log();
        named();
        return ok({}, 204);
      case 'GET /repos/{owner}/{repo}/actions/workflows':
        log();
        named();
        return ok({ total_count: 0, workflows: [] });
      case 'GET /repos/{owner}/{repo}/actions/runs': {
        log();
        named();
        // a run for a given head sha: the fake's runs belong to no commit of the base, so the no-run check finds none
        const runs = p.head_sha === undefined ? (this.#runs.get(`${String(p.owner)}/${String(p.repo)}`.toLowerCase()) ?? []) : [];
        return ok({ total_count: runs.length, workflow_runs: runs.map((r) => ({ id: r.id, status: r.status, conclusion: 'success', created_at: r.created_at, updated_at: r.created_at, run_started_at: r.created_at })) }, 200, { date: this.serverDate });
      }
      case 'GET /repos/{owner}/{repo}/actions/runs/{run_id}': {
        log();
        named();
        const run = (this.#runs.get(`${String(p.owner)}/${String(p.repo)}`.toLowerCase()) ?? []).find((r) => r.id === Number(p.run_id));
        return run === undefined ? fail(404) : ok({ id: run.id, status: run.status, conclusion: 'success' }, 200, { date: this.serverDate });
      }
      case 'GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs': {
        log();
        named();
        const run = (this.#runs.get(`${String(p.owner)}/${String(p.repo)}`.toLowerCase()) ?? []).find((r) => r.id === Number(p.run_id));
        if (run === undefined) return fail(404);
        return ok({ total_count: 1, jobs: [{ id: run.id * 10, run_id: run.id, status: 'completed', conclusion: 'success', started_at: '2026-11-07T10:00:40Z', completed_at: '2026-11-07T10:01:10Z' }] }, 200, { date: this.serverDate });
      }
      case 'DELETE /repos/{owner}/{repo}/actions/runs/{run_id}': {
        log();
        named();
        const key = `${String(p.owner)}/${String(p.repo)}`.toLowerCase();
        const list = this.#runs.get(key) ?? [];
        if (!list.some((r) => r.id === Number(p.run_id))) return fail(404);
        this.#runs.set(key, list.filter((r) => r.id !== Number(p.run_id)));
        return ok({}, 204);
      }
      case 'GET /repos/{owner}/{repo}/actions/secrets': {
        log();
        const r = named();
        const secrets = [...r.stored].map(([name, at]) => ({ name, created_at: at, updated_at: at }));
        return ok({ total_count: secrets.length, secrets });
      }
      case 'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}': {
        log();
        const r = named();
        return r.stored.delete(String(p.secret_name)) ? ok({}, 204) : fail(404);
      }
      case 'GET /repos/{owner}/{repo}/actions/variables': {
        log();
        named();
        const vars = [...this.x(`${String(p.owner)}/${String(p.repo)}`).variables].map(([name, v]) => ({ name, value: v.value, created_at: v.created_at, updated_at: v.created_at }));
        return ok({ total_count: vars.length, variables: vars });
      }
      case 'DELETE /repos/{owner}/{repo}/actions/variables/{name}': {
        log();
        named();
        return this.x(`${String(p.owner)}/${String(p.repo)}`).variables.delete(String(p.name)) ? ok({}, 204) : fail(404);
      }
      case 'GET /repos/{owner}/{repo}/actions/caches':
        log();
        named();
        return ok({ total_count: 0, actions_caches: [] });
      case 'GET /repos/{owner}/{repo}/git/matching-refs/{ref}': {
        log();
        const r = named();
        return ok([...r.refs].filter(([name]) => name.startsWith(String(p.ref))).map(([name, sha]) => ({ ref: `refs/${name}`, object: { sha, type: 'commit' } })));
      }
      case 'DELETE /repos/{owner}/{repo}/git/refs/{ref}': {
        log();
        const r = named();
        return r.refs.delete(String(p.ref)) ? ok({}, 204) : fail(422, 'Reference does not exist');
      }
      case 'POST /repos/{owner}/{repo}/git/commits': {
        // the base fake answers {sha}; GitHub also names the tree and the parents (the cleanup's empty commit is checked against them)
        const res = await super.request(route, params);
        return { ...res, data: { ...(res.data as Obj), tree: { sha: p.tree }, parents: (p.parents as string[]).map((sha) => ({ sha })) } };
      }
      default:
        break;
    }
    try {
      return await super.request(route, params);
    } catch (e) {
      if (/has no route/.test(String((e as Error).message))) this.unrouted.push(route);
      throw e;
    }
  }

  /** The files (path -> text) of a branch's head, or null when the branch is not there. */
  filesOn(fullName: string, branch: string): Map<string, string> | null {
    const r = this.repo(fullName);
    const sha = r.refs.get(`heads/${branch}`);
    const commit = sha === undefined ? undefined : r.commits.get(sha);
    const tree = commit === undefined ? undefined : r.trees.get(commit.tree);
    if (tree === undefined) return null;
    return new Map([...tree].filter(([, e]) => e.type === 'blob').map(([path, e]) => [path, r.blobs.get(e.sha) ?? ''] as [string, string]));
  }

  /** The write calls that touched the repo `name` (anything but GET). */
  writesTo(name: string): Call[] { return this.writes().filter((c) => String(c.params.repo).toLowerCase() === name.toLowerCase()); }
}
