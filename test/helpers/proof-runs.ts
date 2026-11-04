// E4: a stateful fake of the scratch repo's pull requests and workflow runs (the `extra` routes of proof-github.ts world()),
// with response shapes as GitHub gives them (runs: id, path, event, head_sha, head_branch, status, conclusion, run_attempt,
// repository / head_repository ids, pull_requests; jobs with filter=all across attempts). A push (through the fake transport),
// a PR open (pull_request) or a merge (push on the merge sha) starts the runs the test lists for that event; each run then
// moves queued → in_progress → completed over `steps` polls of GET /actions/runs/{id}. No network.
import type { GuardedRepo } from '../../src/proof/target.js';
import type { ProofTransport } from '../../src/proof/snapshot.js';
import type { PushRef, PushRepoHandle } from '../../src/proof/git.js';
import type { Call, Reply } from './fake-http.js';
import { OWNER, SCRATCH } from './scratch-secrets.js';

export const STORE = 'https://pipelinesghubeus22.actions.githubusercontent.com';
export const REPO_ID = 1000 + SCRATCH.length;   // proof-github.ts world()'s id for the repo
const R = `/repos/${OWNER}/${SCRATCH}`;

export interface FakeJob { name: string; conclusion: string | null; attempt?: number; log?: string }
export interface FakeRun {
  id: number; path: string; event: 'push' | 'pull_request'; head_sha: string; head_branch: string; status: string; conclusion: string | null;
  run_attempt: number; pr?: number; jobs: FakeJob[]; artifacts: { name: string; zip: Uint8Array }[]; polls: number; steps: number;
  repoId?: number; headRepoId?: number;
}
/** What a workflow does on an event: its jobs (and their conclusions), artifacts, how many polls it takes. */
export interface Plan { jobs?: FakeJob[]; conclusion?: string; artifacts?: { name: string; zip: Uint8Array }[]; steps?: number; attempt?: number }
export interface FakePr { number: number; head: string; headSha: string; base: string; state: 'open' | 'closed'; merged: boolean; mergeSha?: string }

export interface RunsFake {
  runs: FakeRun[];
  prs: FakePr[];
  pushes: { branch: string; sha: string; force: boolean; from: PushRepoHandle }[];
  cancels: number[];
  /** E6 (S12): runs POST …/force-cancel was sent for. */
  forceCancels: number[];
  /** Runs a cancel doesn't stop (they go on until force-cancelled); any other run ends cancelled on its cancel. */
  ignoreCancel: Set<number>;
  /** POST …/force-cancel answers this status (default 202, the run ends cancelled). */
  forceStatus?: number;
  /** POST …/cancel answers this status (default 202) and changes nothing. */
  cancelStatus?: number;
  merges: { pr: number; sha: string }[];
  /** event → workflow path → what it does (a function sees the sha and branch). Missing: no run for that workflow. */
  plans: { push: Record<string, Plan | ((sha: string, branch: string) => Plan | undefined)>; pull_request: Record<string, Plan | ((sha: string, branch: string) => Plan | undefined)> };
  /** Runs are listed only after this many list calls (default 0). */
  listDelay: number;
  /** No run is ever started (Actions disabled). */
  actionsOff: boolean;
  /** PATCH /pulls/{n} answers this body (and changes nothing). */
  closeAnswer?: unknown;
  /** Extra runs listed for any query (foreign or look-alike runs). `unfiltered`: listed whatever the query asks (a hostile answer). */
  noise: (Partial<FakeRun> & { unfiltered?: boolean })[];
  handler: (c: Call) => Reply | undefined;
  transport: ProofTransport;
  /** Starts the runs for a push of `sha` to `branch`. */
  pushed(branch: string, sha: string): void;
}

let ids = 9000;
const json = (status: number, body: unknown): Reply => ({ status, body });

export function runsFake(defaultBranch = 'main'): RunsFake {
  const f: RunsFake = {
    runs: [], prs: [], pushes: [], cancels: [], forceCancels: [], ignoreCancel: new Set(), merges: [], plans: { push: {}, pull_request: {} }, listDelay: 0, actionsOff: false, noise: [],
    handler: () => undefined, transport: undefined as never, pushed: () => {},
  };
  let lists = 0;
  const start = (event: 'push' | 'pull_request', sha: string, branch: string, pr?: number) => {
    if (f.actionsOff) return;
    for (const [path, p0] of Object.entries(f.plans[event])) {
      const p = typeof p0 === 'function' ? p0(sha, branch) : p0;
      if (p === undefined) continue;
      const openPr = f.prs.some((x) => x.state === 'open' && x.head === branch);
      const jobs = (p.jobs ?? [{ name: 'build', conclusion: 'success' }]).map((j) => ({ ...j, conclusion: event === 'push' && openPr && branch !== defaultBranch ? 'skipped' : j.conclusion }));
      f.runs.push({
        id: ids++, path, event, head_sha: sha, head_branch: branch, status: 'queued', conclusion: null, run_attempt: p.attempt ?? 1,
        ...(pr === undefined ? {} : { pr }), jobs, artifacts: p.artifacts ?? [], polls: 0, steps: p.steps ?? 2,
        _final: p.conclusion ?? (jobs.some((j) => j.conclusion === 'failure') ? 'failure' : 'success'),
      } as FakeRun);
    }
  };
  f.pushed = (branch, sha) => start('push', sha, branch);
  f.transport = {
    push: async (to: GuardedRepo, from: PushRepoHandle, refs: readonly PushRef[], opts?: { force?: boolean }) => {
      for (const r of refs) {
        f.pushes.push({ branch: r.branch, sha: r.sha, force: opts?.force === true, from });
        if (to.kind === 'scratch' && r.branch.startsWith('proof/')) {
          start('push', r.sha, r.branch);
          // a push to the head branch of an open PR re-runs it (synchronize)
          for (const pr of f.prs.filter((x) => x.state === 'open' && x.head === r.branch)) {
            pr.headSha = r.sha;
            start('pull_request', r.sha, r.branch, pr.number);
          }
        }
      }
    },
  };
  const runBody = (r: FakeRun) => ({
    id: r.id, name: r.path.split('/').pop(), path: r.path, event: r.event, head_sha: r.head_sha, head_branch: r.head_branch, status: r.status,
    conclusion: r.conclusion, run_attempt: r.run_attempt, html_url: `https://github.com/${OWNER}/${SCRATCH}/actions/runs/${r.id}`,
    repository: { id: r.repoId ?? REPO_ID }, head_repository: { id: r.headRepoId ?? REPO_ID },
    pull_requests: r.pr === undefined ? [] : [{ number: r.pr, head: { ref: r.head_branch, sha: r.head_sha } }],
  });
  const prBody = (p: FakePr) => ({
    number: p.number, state: p.state, merged: p.merged, html_url: `https://github.com/${OWNER}/${SCRATCH}/pull/${p.number}`,
    head: { ref: p.head, sha: p.headSha, repo: { full_name: `${OWNER}/${SCRATCH}`, id: REPO_ID } }, base: { ref: p.base, repo: { full_name: `${OWNER}/${SCRATCH}` } },
  });
  f.handler = (c) => {
    const path = decodeURIComponent(c.url.pathname);
    if (!path.startsWith(R)) return undefined;
    const rest = path.slice(R.length);
    const q = c.url.searchParams;
    if (c.method === 'GET' && rest === '/actions/runs') {
      lists++;
      const visible = lists > f.listDelay ? f.runs : [];
      // noise runs take the asked sha unless they name one (look-alikes the matching must refuse)
      const asked = (r: { head_sha: string; event: string }) => (!q.has('head_sha') || r.head_sha === q.get('head_sha')) && (!q.has('event') || r.event === q.get('event'));
      const noise = f.noise.map((n) => ({ u: n.unfiltered === true, r: runBody({ id: ids++, path: '.github/workflows/x.yml', event: 'push', head_sha: q.get('head_sha') ?? '0'.repeat(40), head_branch: 'x', status: 'completed', conclusion: 'success', run_attempt: 1, jobs: [], artifacts: [], polls: 0, steps: 0, ...n } as FakeRun) }));
      const list = [...visible.map(runBody).filter(asked), ...noise.filter((x) => x.u || asked(x.r)).map((x) => x.r)];
      return json(200, { total_count: list.length, workflow_runs: list });
    }
    let m = /^\/actions\/runs\/(\d+)$/.exec(rest);
    if (m && c.method === 'GET') {
      const r = f.runs.find((x) => x.id === Number(m?.[1]));
      if (r === undefined) return json(404, { message: 'Not Found' });
      r.polls++;
      if (r.status !== 'completed') {
        r.status = r.polls >= r.steps ? 'completed' : 'in_progress';
        if (r.status === 'completed') r.conclusion = (r as unknown as { _final: string })._final;
      }
      return json(200, runBody(r));
    }
    m = /^\/actions\/runs\/(\d+)\/jobs$/.exec(rest);
    if (m && c.method === 'GET') {
      const r = f.runs.find((x) => x.id === Number(m?.[1]));
      if (r === undefined) return json(404, { message: 'Not Found' });
      const filter = q.get('filter') ?? 'latest';
      const jobs = r.jobs.map((j, i) => ({ id: r.id * 100 + i, run_id: r.id, name: j.name, status: 'completed', conclusion: j.conclusion, run_attempt: j.attempt ?? r.run_attempt }))
        .filter((j) => filter === 'all' || j.run_attempt === r.run_attempt);
      const per = Number(q.get('per_page') ?? '30');
      const page = Number(q.get('page') ?? '1');
      return json(200, { total_count: jobs.length, jobs: jobs.slice((page - 1) * per, page * per) });
    }
    m = /^\/actions\/runs\/(\d+)\/artifacts$/.exec(rest);
    if (m && c.method === 'GET') {
      const r = f.runs.find((x) => x.id === Number(m?.[1]));
      const arts = (r?.artifacts ?? []).map((a, i) => ({ id: (r?.id ?? 0) * 10 + i, name: a.name, size_in_bytes: a.zip.length, expired: false, workflow_run: { id: r?.id } }));
      return json(200, { total_count: arts.length, artifacts: arts });
    }
    m = /^\/actions\/artifacts\/(\d+)\/zip$/.exec(rest);
    if (m && c.method === 'GET') return { status: 302, headers: { location: `${STORE}/art/${m[1]}` } };
    m = /^\/actions\/jobs\/(\d+)\/logs$/.exec(rest);
    if (m && c.method === 'GET') return { status: 302, headers: { location: `${STORE}/log/${m[1]}` } };
    m = /^\/actions\/runs\/(\d+)\/cancel$/.exec(rest);
    if (m && c.method === 'POST') {
      const id = Number(m[1]);
      f.cancels.push(id);
      if (f.cancelStatus !== undefined) return json(f.cancelStatus, { message: 'Server Error' });
      const r = f.runs.find((x) => x.id === id);
      if (r !== undefined && r.status === 'completed') return json(409, { message: 'Cannot cancel a workflow run that is completed.' });
      if (r !== undefined && !f.ignoreCancel.has(id)) { r.status = 'completed'; r.conclusion = 'cancelled'; }
      return json(202, {});
    }
    m = /^\/actions\/runs\/(\d+)\/force-cancel$/.exec(rest);
    if (m && c.method === 'POST') {
      const id = Number(m[1]);
      f.forceCancels.push(id);
      if (f.forceStatus !== undefined) return json(f.forceStatus, { message: 'Server Error' });
      const r = f.runs.find((x) => x.id === id);
      if (r !== undefined) { r.status = 'completed'; r.conclusion = 'cancelled'; }
      return json(202, {});
    }
    if (rest === '/pulls' && c.method === 'POST') {
      const b = JSON.parse(c.body ?? '{}') as { head: string; base: string };
      const head = f.pushes.filter((p) => p.branch === b.head).at(-1);
      const pr: FakePr = { number: f.prs.length + 7, head: b.head, headSha: head?.sha ?? '0'.repeat(40), base: b.base, state: 'open', merged: false };
      f.prs.push(pr);
      start('pull_request', pr.headSha, pr.head, pr.number);
      return json(201, prBody(pr));
    }
    if (rest === '/pulls' && c.method === 'GET') {
      const list = f.prs.filter((p) => (q.get('state') ?? 'open') === 'all' || p.state === (q.get('state') ?? 'open'));
      return json(200, list.map(prBody));
    }
    m = /^\/pulls\/(\d+)$/.exec(rest);
    if (m) {
      const pr = f.prs.find((p) => p.number === Number(m?.[1]));
      if (pr === undefined) return json(404, { message: 'Not Found' });
      if (c.method === 'GET') return json(200, prBody(pr));
      if (c.method === 'PATCH') {
        if (f.closeAnswer !== undefined) return json(200, f.closeAnswer);   // an answer pipegen can't read; the PR stays as it was
        pr.state = (JSON.parse(c.body ?? '{}') as { state: 'closed' }).state;
        return json(200, prBody(pr));
      }
    }
    m = /^\/pulls\/(\d+)\/merge$/.exec(rest);
    if (m && c.method === 'PUT') {
      const pr = f.prs.find((p) => p.number === Number(m?.[1]));
      const b = JSON.parse(c.body ?? '{}') as { sha?: string };
      if (pr === undefined) return json(404, { message: 'Not Found' });
      if (b.sha !== pr.headSha) return json(409, { message: 'Head branch was modified. Review and try the merge again.' });
      const sha = (ids++).toString(16).padStart(40, 'e');
      pr.merged = true; pr.state = 'closed'; pr.mergeSha = sha;
      f.merges.push({ pr: pr.number, sha });
      start('push', sha, defaultBranch);
      return json(200, { sha, merged: true, message: 'Pull Request successfully merged' });
    }
    return undefined;
  };
  return f;
}

/** The store side of the fake (artifact zips and job logs), served from the runs. */
export function storeRoutes(f: RunsFake): (c: Call) => Reply | undefined {
  return (c) => {
    if (c.url.origin !== STORE) return undefined;
    const m = /^\/(art|log)\/(\d+)$/.exec(c.url.pathname);
    if (m === null) return { status: 404, body: {} };
    const id = Number(m[2]);
    if (m[1] === 'art') {
      const run = f.runs.find((r) => Math.floor(id / 10) === r.id);
      const a = run?.artifacts[id % 10];
      return a === undefined ? { status: 404, body: {} } : { raw: a.zip, headers: { 'content-type': 'application/zip' } };
    }
    const run = f.runs.find((r) => Math.floor(id / 100) === r.id);
    const j = run?.jobs[id % 100];
    return j === undefined ? { status: 404, body: {} } : { raw: j.log ?? `log of ${j.name}`, headers: { 'content-type': 'text/plain' } };
  };
}
