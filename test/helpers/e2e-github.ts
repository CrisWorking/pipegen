// v0.2 Plan G G16: the fake GitHub of the local end-to-end run (test/cli-run-e2e.test.ts). It is FinishGitHub (deliver-github.ts +
// finish-github.ts: repos, git data, pull requests, rulesets, environments, secrets, variables) plus the few reads `pipegen run`'s own
// stages make before and after the delivery (the token's user, the capability probes, the gate's pinned commit). Its Octokit is a REAL
// Octokit whose requests are answered by `request` here, so every stage that calls `gh.rest.*` runs its real code. It also keeps the
// proof's record: every push, run, artifact and cleanup step the e2e's proof ops make is written to `proof`, on one timeline with the
// GitHub calls (`timeline`). No network.
import { Octokit } from '@octokit/rest';
import { makeOctokit } from '../../src/github/client.js';
import type { Call } from './deliver-github.js';
import { FinishGitHub } from './finish-github.js';

type Obj = Record<string, any>;
const fail = (status: number, message = 'Not Found'): never => {
  throw Object.assign(new Error(message), { status, response: { status, headers: {}, data: { message } } });
};

/** What the proof did on the fake GitHub (written by the e2e's proof ops). */
export interface ProofRecord {
  /** Every push of a proof branch: the repo, the branch and the file paths. */
  pushes: { repo: string; branch: string; files: string[] }[];
  /** Every proof run the fake answered. */
  runs: { variant: string; event: string; conclusion: string; jobs: string[]; artifacts: string[] }[];
  /** The scratch values the proof stores for its runs: stored once, deleted by the cleanup. */
  scratch: { stored: string[]; deleted: boolean };
  /** The cleanup steps, in order. */
  cleanup: string[];
}

/** A made-up credential the fake accepts (built at run time: nothing secret-like in a committed file). */
export const E2E_VALUE = ['e2e', 'made', 'up', 'value', '0'.repeat(16)].join('-');

export class E2eGitHub extends FinishGitHub {
  /** The routes no one answered (a test fails on any it did not expect). */
  readonly unrouted: string[] = [];
  /** One ordered log of the proof's steps and the milestones the run reaches (the preview, the delivery), for order checks. */
  readonly timeline: string[] = [];
  readonly proof: ProofRecord = { pushes: [], runs: [], scratch: { stored: [], deleted: false }, cleanup: [] };
  /** Commits the fake answers for without holding a repo's history: `owner/repo@sha` (the gate at its pinned commit). */
  readonly knownCommits = new Set<string>();
  /** The token user and the plan GitHub reports for it. */
  login = 'CrisWorking';
  plan = 'pro';

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
    const ok = (data: unknown, status = 200) => ({ status, data, headers: {} });
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
