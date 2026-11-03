// Plan E Task 3 / E4 (rulings B3, S2, S11, S13, S27; F11): proof PRs, run matching and the waits. A real makeOctokit
// client over the stateful fakes (proof-github.ts world() + proof-runs.ts); the proof branches are built by the real E2
// session (git, local only) and pushed through a recording transport; the poll clock is fake (no real waiting).
// interrupting() is mocked. No network.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runGit } from '../src/proof/git.js';
import {
  closeProofPr, findRuns, mapConclusion, mergeProofPr, NO_RUN_MS, openProofPr, proveVariant, redeployProof, rerunProof, resetBase, waitForRuns,
  type PollClock, type RunHandle,
} from '../src/proof/run.js';
import { buildBase, buildProofBranch, openProofSession, pushProofBranch, type BaseSnapshot, type ProofSession } from '../src/proof/snapshot.js';
import { proofTarget, ProofStopError, ScratchGuardError, type ProofTarget } from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { fakeFetch } from './helpers/fake-http.js';
import { world } from './helpers/proof-github.js';
import { REPO_ID, runsFake, storeRoutes, type RunsFake } from './helpers/proof-runs.js';
import { app, OWNER, SCRATCH } from './helpers/scratch-secrets.js';
import { REAL_GIT } from './helpers/git-recorder.js';
import { makeZip } from './helpers/zip.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); });

const PIPEGEN = '.github/workflows/pipegen.yml';
const MERGE = '.github/workflows/pipegen-merge.yml';
const HARNESS = '.github/workflows/pipegen-proof-harness.yml';
const WORKFLOWS = { push: [PIPEGEN], pullRequest: [MERGE, HARNESS], merge: [PIPEGEN, HARNESS] };
const R = `/repos/${OWNER}/${SCRATCH}`;
const ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };

function fakeClock(): PollClock & { t: number; sleeps: number[] } {
  const c = { t: 0, sleeps: [] as number[], now: () => c.t, sleep: async (ms: number) => { c.sleeps.push(ms); c.t += ms; } };
  return c;
}
/** The parents of a commit in the session's push repo (cat-file, one of the plumbing commands runGit allows). */
async function parentsOf(from: unknown, sha: string): Promise<string[]> {
  const text = Buffer.from(await runGit(from as never, ['cat-file', 'commit', sha])).toString('utf8');
  return [...text.matchAll(/^parent ([0-9a-f]{40})$/gm)].map((m) => m[1] as string);
}
function userRepo(): string {
  const d = mkdtempSync(join(tmpdir(), 'pg-e4-'));
  execFileSync(REAL_GIT, ['init', '-q', '-b', 'main'], { cwd: d, env: ENV });
  mkdirSync(join(d, 'src'));
  writeFileSync(join(d, 'src', 'app.js'), 'console.log(1);\n');
  execFileSync(REAL_GIT, ['add', '-A'], { cwd: d, env: ENV });
  execFileSync(REAL_GIT, ['commit', '-qm', 'one'], { cwd: d, env: ENV });
  return d;
}

interface Env { f: RunsFake; g: ReturnType<typeof world>; t: ProofTarget; clock: ReturnType<typeof fakeClock>; store: ReturnType<typeof fakeFetch>; opts: { timeoutMs: number; clock: PollClock; download: { fetch: typeof fetch } } }
function env(setup: (f: RunsFake) => void = () => {}): Env {
  const f = runsFake();
  setup(f);
  const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f.handler });
  const store = fakeFetch(new Proxy({}, { get: (_t, k) => (typeof k === 'string' ? (c: Parameters<ReturnType<typeof storeRoutes>>[0]) => storeRoutes(f)(c) ?? { status: 404, body: {} } : undefined) }) as never);
  const clock = fakeClock();
  return { f, g, t: proofTarget(app(), { runId: '20261103-120000-abcdef' }), clock, store, opts: { timeoutMs: 30 * 60_000, clock, download: { fetch: store.fetch } } };
}
/** A real proof session with the base and main + planted proof branches, pushed through the fake's transport. */
async function session(e: Env): Promise<{ s: ProofSession; base: BaseSnapshot; main: { variant: 'main'; branch: string; sha: string; commits: string[] }; planted: { variant: 'planted'; branch: string; sha: string; commits: string[] } }> {
  const s = await openProofSession(e.t);
  const base = await buildBase(s, userRepo(), { io: { err: () => {} } });
  const main = await pushProofBranch(s, 'main', [[{ path: 'pipegen.txt', content: 'proof\n' }]], { transport: e.f.transport, pipegenWorkflows: new Set() });
  const planted = await pushProofBranch(s, 'planted', [[{ path: 'pipegen-planted/key.txt', content: 'x\n' }]], { transport: e.f.transport, pipegenWorkflows: new Set() });
  return { s, base, main: main as never, planted: planted as never };
}
const simplePlans = (f: RunsFake) => {
  f.plans.push[PIPEGEN] = { jobs: [{ name: 'pipegen / build', conclusion: 'success' }] };
  f.plans.pull_request[MERGE] = { jobs: [{ name: 'pipegen / gate', conclusion: 'success' }] };
  f.plans.pull_request[HARNESS] = { jobs: [{ name: 'egress-check', conclusion: 'success' }] };
  f.plans.push[HARNESS] = (_sha, branch) => (branch === 'main' ? { jobs: [{ name: 'verify-lookup', conclusion: 'success' }] } : undefined);
};

describe('E4 proof PRs', () => {
  it('pr: opens proof branch → default branch PR', async () => {
    const e = env(simplePlans);
    const { main } = await session(e);
    const pr = await openProofPr(e.g.gh, e.t, main.branch);
    expect(pr).toEqual({ number: 7, url: `https://github.com/${OWNER}/${SCRATCH}/pull/7` });
    const create = e.g.calls.find((c) => c.method === 'POST' && c.url.pathname === `${R}/pulls`);
    expect(JSON.parse(create?.body ?? '{}')).toMatchObject({ head: main.branch, base: 'main' });
    // only proof/<runId>/<name> branches of this run; never the default branch or another run's
    for (const bad of ['main', 'proof/20261103-120000-abcdee/main', 'proof/20261103-120000-abcdef/../x', 'feature/x', 'proof/20261103-120000-abcdef/Main']) {
      await expect(openProofPr(e.g.gh, e.t, bad), bad).rejects.toThrow(ScratchGuardError);
    }
    expect(e.g.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });

  it('pr: merge uses the proven head sha; planted PR closed, never merged', async () => {
    const e = env(simplePlans);
    const { main, planted } = await session(e);
    const p = await proveVariant(e.g.gh, e.t, { branch: planted, merge: false, workflows: WORKFLOWS }, e.opts);
    expect(p.closed).toBe(true);
    expect(e.f.prs.find((x) => x.number === p.pr)).toMatchObject({ state: 'closed', merged: false });
    expect(e.f.merges).toEqual([]);
    // the planted (or any non-main) variant is never merged, whatever the caller asks
    await expect(proveVariant(e.g.gh, e.t, { branch: planted, merge: true, workflows: WORKFLOWS }, e.opts)).rejects.toThrow(ScratchGuardError);
    const m = await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: WORKFLOWS }, e.opts);
    expect(e.f.merges).toEqual([{ pr: m.pr, sha: m.mergeSha }]);
    const put = e.g.calls.find((c) => c.method === 'PUT' && c.url.pathname.endsWith(`/pulls/${m.pr}/merge`));
    expect(JSON.parse(put?.body ?? '{}')).toEqual({ sha: main.sha, merge_method: 'merge' });
    // mergeProofPr checks the PR first: another head sha, a planted head, a closed PR, or another proof PR still open → refused
    const e2 = env(simplePlans);
    const s2 = await session(e2);
    const prMain = await openProofPr(e2.g.gh, e2.t, s2.main.branch);
    const prPlanted = await openProofPr(e2.g.gh, e2.t, s2.planted.branch);
    await expect(mergeProofPr(e2.g.gh, e2.t, prMain.number, s2.main.sha)).rejects.toThrow(/close the planted/);   // S27
    await expect(mergeProofPr(e2.g.gh, e2.t, prPlanted.number, s2.planted.sha)).rejects.toThrow(ScratchGuardError);
    await closeProofPr(e2.g.gh, e2.t, prPlanted.number);
    await expect(mergeProofPr(e2.g.gh, e2.t, prMain.number, 'f'.repeat(40))).rejects.toThrow(/not the proven head/);
    await expect(mergeProofPr(e2.g.gh, e2.t, prMain.number, 'nope')).rejects.toThrow(ScratchGuardError);
    expect(e2.f.merges).toEqual([]);
    const sha = await mergeProofPr(e2.g.gh, e2.t, prMain.number, s2.main.sha);
    expect(sha).toMatch(/^[0-9a-f]{40}$/);
    await expect(mergeProofPr(e2.g.gh, e2.t, prMain.number, s2.main.sha)).rejects.toThrow(/not open/);
  });
});

describe('E4 runs', () => {
  it('run: push runs, then pull_request runs, then push runs on the merge sha, matched by head_sha and event', async () => {
    const e = env((f) => {
      simplePlans(f);
      // look-alikes the matching must ignore: a fork's run, another repo's, another event, another sha, another branch
      const b = 'proof/20261103-120000-abcdef/main';
      f.noise = [{ path: PIPEGEN, event: 'push', head_branch: b, headRepoId: 1 }, { path: MERGE, event: 'pull_request', head_branch: b, repoId: 2 },
        { path: `${PIPEGEN}@refs/heads/x`, event: 'push', head_branch: b }, { path: PIPEGEN, event: 'push', head_branch: 'proof/20261103-120000-abcdef/other' },
        // an answer that ignores the query: another event, another sha, another PR's run
        { path: PIPEGEN, event: 'pull_request', head_branch: b, unfiltered: true }, { path: PIPEGEN, event: 'push', head_branch: b, head_sha: 'd'.repeat(40), unfiltered: true },
        { path: MERGE, event: 'pull_request', head_branch: b, pr: 999 }];
    });
    const { main } = await session(e);
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: WORKFLOWS }, e.opts);
    const shape = p.outcomes.map((o) => [o.handle.event, o.handle.workflow, o.handle.headSha === main.sha ? 'proof' : o.handle.headSha === p.mergeSha ? 'merge' : 'other', o.conclusion]);
    expect(shape).toEqual([
      ['push', PIPEGEN, 'proof', 'success'],
      ['pull_request', MERGE, 'proof', 'success'], ['pull_request', HARNESS, 'proof', 'success'],
      ['push', PIPEGEN, 'merge', 'success'], ['push', HARNESS, 'merge', 'success'],
    ]);
    // the order of the writes: the PR after the push runs finished, the merge after the PR runs finished
    const order = e.g.seen().filter((x) => x.startsWith('POST') || x.startsWith('PUT'));
    expect(order).toEqual([`POST ${R}/pulls`, `PUT ${R}/pulls/${p.pr}/merge`]);
    // the queries ask by head_sha and event
    const queries = e.g.calls.filter((c) => c.url.pathname === `${R}/actions/runs`).map((c) => `${c.url.searchParams.get('event')}:${c.url.searchParams.get('head_sha')?.slice(0, 7)}`);
    expect(new Set(queries)).toEqual(new Set([`push:${main.sha.slice(0, 7)}`, `pull_request:${main.sha.slice(0, 7)}`, `push:${p.mergeSha?.slice(0, 7)}`]));
    // findRuns alone: only exact matches of this repo (ids), sha, event, workflow path and branch
    const handles = await findRuns(e.g.gh, e.t, { headSha: main.sha, event: 'push', workflows: [PIPEGEN], branch: main.branch });
    expect(handles.map((h) => h.workflow)).toEqual([PIPEGEN]);
    expect(await findRuns(e.g.gh, e.t, { headSha: main.sha, event: 'push', workflows: [PIPEGEN], branch: `proof/${e.t.runId}/planted` })).toEqual([]);
    await expect(findRuns(e.g.gh, e.t, { headSha: main.sha, event: 'push', workflows: [PIPEGEN], branch: 'feature/x' })).rejects.toThrow(ScratchGuardError);
    expect(await findRuns(e.g.gh, e.t, { headSha: main.sha, event: 'push', workflows: [MERGE], branch: main.branch })).toEqual([]);
    expect(e.f.runs.every((r) => r.repoId === undefined || r.repoId === REPO_ID)).toBe(true);
  });

  it('run: no run appears within 120s → actionable error', async () => {
    const e = env((f) => { simplePlans(f); f.actionsOff = true; });
    const { main } = await session(e);
    const err = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: WORKFLOWS }, e.opts).catch((x: unknown) => x);
    expect(err).toBeInstanceOf(ProofStopError);
    expect((err as Error).message).toBe(`No workflow run started on ${SCRATCH}. Is GitHub Actions enabled there?`);
    expect(NO_RUN_MS).toBe(120_000);
    expect(e.clock.t).toBeGreaterThanOrEqual(120_000);
    expect(e.clock.t).toBeLessThan(140_000);
    expect(e.g.writes()).toEqual([]);   // no PR was opened
    // a run that shows up late (within the 120 s) is waited for
    const late = env((f) => { simplePlans(f); f.listDelay = 3; });
    const s2 = await session(late);
    const ok = await proveVariant(late.g.gh, late.t, { branch: s2.main, merge: false, workflows: { push: [PIPEGEN], pullRequest: [] } }, late.opts);
    expect(ok.outcomes.map((o) => o.conclusion)).toEqual(['success']);
    // some workflows start, one never does: reported missing, not waited for forever
    const part = env((f) => { f.plans.push[PIPEGEN] = {}; });
    const s3 = await session(part);
    const p3 = await proveVariant(part.g.gh, part.t, { branch: s3.main, merge: false, workflows: { push: [PIPEGEN, HARNESS], pullRequest: [] } }, part.opts);
    expect(p3.missing).toEqual([{ event: 'push', workflow: HARNESS }]);
  });

  it('run: downloads artifacts; logs for failed jobs and the coverage job', async () => {
    const zip = Buffer.from(makeZip({ entries: [{ name: 'result.json', data: '{"ok":true}' }] }));
    const e = env((f) => {
      f.plans.push[PIPEGEN] = {
        jobs: [{ name: 'pipegen / coverage (api)', conclusion: 'success', log: 'All files | 91.2 |' }, { name: 'pipegen / lint', conclusion: 'failure', log: 'Error: lint' },
          { name: 'pipegen / build', conclusion: 'success' }, { name: 'pipegen / slow', conclusion: 'timed_out', log: 'timed out' }],
        artifacts: [{ name: 'pipegen-gate-result', zip }, { name: 'pipegen-out-sast--api', zip }, { name: 'user-thing', zip }],
      };
    });
    const { main } = await session(e);
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: { push: [PIPEGEN], pullRequest: [] } }, e.opts);
    const o = p.outcomes[0];
    expect(o?.conclusion).toBe('failure');
    expect([...(o?.artifacts.keys() ?? [])].sort()).toEqual(['pipegen-gate-result', 'pipegen-out-sast--api']);
    expect(o?.artifacts.get('pipegen-gate-result')?.bytes.toString()).toBe('{"ok":true}');
    const logs = Object.fromEntries((o?.jobs ?? []).map((j) => [j.name, j.log]));
    expect(logs).toEqual({ 'pipegen / coverage (api)': 'All files | 91.2 |', 'pipegen / lint': 'Error: lint', 'pipegen / build': undefined, 'pipegen / slow': 'timed out' });
    // the store calls carried no credential
    for (const c of e.store.calls) expect(c.headers.authorization).toBeUndefined();
    // a caller's own choice of extra log jobs
    const e2 = env((f) => { f.plans.push[PIPEGEN] = { jobs: [{ name: 'a', conclusion: 'success' }, { name: 'b', conclusion: 'success' }] }; });
    const s2 = await session(e2);
    const p2 = await proveVariant(e2.g.gh, e2.t, { branch: s2.main, merge: false, workflows: { push: [PIPEGEN], pullRequest: [] } }, { ...e2.opts, logJob: (j) => j.name === 'b' });
    expect(p2.outcomes[0]?.jobs.map((j) => j.log)).toEqual([undefined, 'log of b']);
  });

  it('run: shouldStop true → cancels runs and returns', async () => {
    const e = env((f) => { f.plans.push[PIPEGEN] = { steps: 1_000 }; f.plans.push[HARNESS] = { steps: 1_000 }; });
    const { main } = await session(e);
    let polls = 0;
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: { push: [PIPEGEN, HARNESS], pullRequest: [MERGE], merge: [PIPEGEN] } }, { ...e.opts, shouldStop: () => ++polls > 3 });
    expect(p.stopped).toBe(true);
    expect(e.f.cancels.sort()).toEqual(e.f.runs.filter((r) => r.head_sha === main.sha).map((r) => r.id).sort());
    expect(e.f.cancels).toHaveLength(2);
    expect(p.outcomes.every((o) => o.conclusion === 'cancelled' && /stopped/.test(o.note ?? ''))).toBe(true);
    expect(e.f.prs).toEqual([]);   // nothing after the stop: no PR, no merge
    // a stop that has begun (Ctrl-C): no cancel is sent (E8's cleanup does it), the wait returns at once
    const e2 = env((f) => { f.plans.push[PIPEGEN] = { steps: 1_000 }; });
    const s2 = await session(e2);
    const handles = await findRuns(e2.g.gh, e2.t, { headSha: s2.main.sha, event: 'push', workflows: [PIPEGEN], branch: s2.main.branch });
    vi.mocked(interrupting).mockReturnValue(true);
    const out = await waitForRuns(e2.g.gh, e2.t, handles, e2.opts);
    expect(out[0]).toMatchObject({ stopped: true, conclusion: 'cancelled', note: expect.stringMatching(/pipegen is stopping/) });
    expect(e2.f.cancels).toEqual([]);
    expect(e2.clock.t).toBe(0);   // returned at once: no poll, no wait
    vi.mocked(interrupting).mockReturnValue(false);
    // the time cap: runs still going are cancelled and reported timed out
    const e3 = env((f) => { f.plans.push[PIPEGEN] = { steps: 1_000 }; });
    const s3 = await session(e3);
    const h3 = await findRuns(e3.g.gh, e3.t, { headSha: s3.main.sha, event: 'push', workflows: [PIPEGEN], branch: s3.main.branch });
    const o3 = await waitForRuns(e3.g.gh, e3.t, h3, { ...e3.opts, timeoutMs: 5 * 60_000 });
    expect(o3[0]).toMatchObject({ conclusion: 'timed_out', stopped: true });
    expect(e3.f.cancels).toEqual([h3[0]?.runId]);
    // the poll backs off from 15 s to 60 s
    expect(e3.clock.sleeps.slice(0, 5)).toEqual([15_000, 22_500, 33_750, 50_625, 60_000]);
  });

  it('run: the workflow_dispatch endpoint is never called', async () => {
    const e = env(simplePlans);
    const { main } = await session(e);
    await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: WORKFLOWS }, e.opts);
    expect(e.g.calls.some((c) => /dispatches/.test(c.url.pathname))).toBe(false);
    // and no proof module names the endpoint (the guard refuses it too: test/proof-target.test.ts)
    const { readdirSync, readFileSync } = await import('node:fs');
    const dir = join(import.meta.dirname, '..', 'src', 'proof');
    // (target.ts names it only in the guard's refusal list)
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && x !== 'target.ts')) {
      const src = readFileSync(join(dir, f), 'utf8').replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '');
      expect(src, f).not.toMatch(/\/dispatches|createWorkflowDispatch|workflow_dispatch'\s*\)/);
    }
  });

  it('run: startup_failure / action_required / neutral / stale conclusions mapped', async () => {
    expect(mapConclusion('success', SCRATCH)).toEqual({ conclusion: 'success' });
    expect(mapConclusion('failure', SCRATCH)).toEqual({ conclusion: 'failure' });
    expect(mapConclusion('startup_failure', SCRATCH)).toEqual({ conclusion: 'startup_failure', note: `a workflow could not start (an action pipegen uses isn't reachable from ${SCRATCH})` });
    expect(mapConclusion('action_required', SCRATCH)).toMatchObject({ conclusion: 'action_required', note: expect.stringMatching(/approv/) });
    expect(mapConclusion('neutral', SCRATCH)).toMatchObject({ conclusion: 'neutral', note: expect.stringMatching(/proves nothing/) });
    expect(mapConclusion('stale', SCRATCH)).toMatchObject({ conclusion: 'stale', note: expect.stringMatching(/stale/) });
    expect(mapConclusion('skipped', SCRATCH)).toMatchObject({ conclusion: 'skipped' });
    for (const odd of [null, undefined, 'weird', 7, 'SUCCESS']) expect(mapConclusion(odd, SCRATCH), String(odd)).toMatchObject({ conclusion: 'failure', note: expect.stringMatching(/doesn't know/) });
    // end to end: the run's conclusion and note come through
    const e = env((f) => { f.plans.push[PIPEGEN] = { conclusion: 'startup_failure', jobs: [] }; });
    const { main } = await session(e);
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: { push: [PIPEGEN], pullRequest: [] } }, e.opts);
    expect(p.outcomes[0]).toMatchObject({ conclusion: 'startup_failure', note: expect.stringContaining(SCRATCH) });
  });

  it('run: jobs read with filter=all (re-run attempts)', async () => {
    const e = env((f) => {
      f.plans.push[PIPEGEN] = { attempt: 2, jobs: [{ name: 'test', conclusion: 'failure', attempt: 1, log: 'first try' }, { name: 'test', conclusion: 'success', attempt: 2 }] };
    });
    const { main } = await session(e);
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: { push: [PIPEGEN], pullRequest: [] } }, e.opts);
    const o = p.outcomes[0];
    expect(o?.attempt).toBe(2);
    expect(o?.jobs.map((j) => [j.name, j.attempt, j.conclusion])).toEqual([['test', 1, 'failure'], ['test', 2, 'success']]);
    expect(e.g.calls.filter((c) => c.url.pathname.endsWith('/jobs')).every((c) => c.url.searchParams.get('filter') === 'all')).toBe(true);
    // a failed job of an older attempt gets no log fetched (only the latest attempt's)
    expect(o?.jobs[0]?.log).toBeUndefined();
  });
});

describe('E4 re-runs (B3)', () => {
  it('run: re-push re-runs the open PR; push-layer jobs skipped', async () => {
    const e = env(simplePlans);
    const { s, main } = await session(e);
    const first = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: WORKFLOWS }, e.opts);
    const r = await rerunProof(e.g.gh, e.t, s, { branch: main, pr: first.pr as number, files: [{ path: 'pipegen.txt', content: 'fixed\n' }], pipegenWorkflows: new Set(), workflows: WORKFLOWS },
      { ...e.opts, transport: e.f.transport });
    expect(r.branch.branch).toBe(main.branch);
    expect(r.branch.sha).not.toBe(main.sha);
    const push = r.outcomes.filter((o) => o.handle.event === 'push');
    const pull = r.outcomes.filter((o) => o.handle.event === 'pull_request');
    expect(push.map((o) => o.handle.headSha)).toEqual([r.branch.sha]);
    expect(push.flatMap((o) => o.jobs.map((j) => j.conclusion))).toEqual(['skipped']);   // the push layer skips while the PR is open
    expect(pull.map((o) => [o.handle.workflow, o.handle.headSha])).toEqual([[MERGE, r.branch.sha], [HARNESS, r.branch.sha]]);
    expect(e.f.prs).toHaveLength(1);   // the same PR re-ran (synchronize); no new PR
  });

  it('run: re-run pushes a fast-forward commit; never a force-push of the proof branch', async () => {
    const e = env(simplePlans);
    const { s, main } = await session(e);
    const first = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: WORKFLOWS }, e.opts);
    const r = await rerunProof(e.g.gh, e.t, s, { branch: main, pr: first.pr as number, files: [{ path: 'b.txt', content: 'b\n' }], pipegenWorkflows: new Set(), workflows: WORKFLOWS }, { ...e.opts, transport: e.f.transport });
    const push = e.f.pushes.at(-1);
    expect(push).toMatchObject({ branch: main.branch, sha: r.branch.sha, force: false });
        expect(await parentsOf(push?.from, r.branch.sha)).toEqual([main.sha]);   // one parent: the commit the PR proved before
    expect(e.f.pushes.filter((p) => p.branch.startsWith('proof/')).every((p) => !p.force)).toBe(true);
    // a stale parent (not the branch's head) is refused before anything is pushed
    const n = e.f.pushes.length;
    await expect(rerunProof(e.g.gh, e.t, s, { branch: main, pr: first.pr as number, files: [{ path: 'c.txt', content: 'c\n' }], pipegenWorkflows: new Set(), workflows: WORKFLOWS }, { ...e.opts, transport: e.f.transport }))
      .rejects.toThrow(/not the head/);
    expect(e.f.pushes.length).toBe(n);
  });

  it('run: deploy re-run after a merge → base reset, new PR', async () => {
    const e = env(simplePlans);
    const { s, base, main } = await session(e);
    const first = await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: WORKFLOWS }, e.opts);
    expect(first.mergeSha).toBeDefined();
    const again = await redeployProof(e.g.gh, e.t, s, { base, variant: 'main', round: 2, files: [{ path: 'pipegen.txt', content: 'v2\n' }], pipegenWorkflows: new Set(), workflows: WORKFLOWS },
      { ...e.opts, transport: e.f.transport });
    // the default branch was put back on the base commit (forced, the base only), then a new PR from a fresh branch was merged
    const reset = e.f.pushes.find((p) => p.branch === 'main');
    expect(reset).toMatchObject({ sha: base.sha, force: true });
    expect(e.f.prs.map((p) => [p.number, p.head, p.merged])).toEqual([[first.pr, main.branch, true], [again.pr, again.branch.branch, true]]);
    expect(again.pr).not.toBe(first.pr);
    expect(e.f.merges.map((m) => m.pr)).toEqual([first.pr, again.pr]);
    // resetBase takes only the base snapshot of its own session: a proof commit (a real record) is refused, nothing pushed
    const proofCommit = await buildProofBranch(s, 'main', [[{ path: 'q.txt', content: 'q\n' }]], { pipegenWorkflows: new Set(), parent: main.sha });
    const n = e.f.pushes.length;
    await expect(resetBase(s, { ...base, commit: proofCommit }, e.f.transport)).rejects.toThrow(ScratchGuardError);
    await expect(resetBase(s, { ...base, sha: main.sha }, e.f.transport)).rejects.toThrow(ScratchGuardError);
    expect(e.f.pushes.length).toBe(n);
  });

  it('run: deploy re-run uses a fresh branch name after resetBase', async () => {
    const e = env(simplePlans);
    const { s, base, main } = await session(e);
    await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: WORKFLOWS }, e.opts);
    const again = await redeployProof(e.g.gh, e.t, s, { base, variant: 'main', round: 2, files: [{ path: 'x.txt', content: '2\n' }], pipegenWorkflows: new Set(), workflows: WORKFLOWS }, { ...e.opts, transport: e.f.transport });
    expect(again.branch.branch).toBe(`proof/${e.t.runId}/main-2`);
    const pushes = e.f.pushes.map((p) => p.branch);
    expect(pushes.indexOf('main')).toBeLessThan(pushes.indexOf(`proof/${e.t.runId}/main-2`));   // reset first
    // its first commit has the base as its only parent
    expect(await parentsOf(e.f.pushes.at(-1)?.from, again.branch.sha)).toEqual([base.sha]);
    // a round branch builds only on the base or itself (never on main's commits); rounds are 2..99
    await expect(buildProofBranch(s, 'main', [[{ path: 'y', content: 'y' }]], { pipegenWorkflows: new Set(), parent: main.sha, round: 3 })).rejects.toThrow(/builds only on the base/);
    for (const round of [0, 1, 100, 2.5, NaN]) await expect(buildProofBranch(s, 'main', [[{ path: 'y', content: 'y' }]], { pipegenWorkflows: new Set(), round }), String(round)).rejects.toThrow(/round/);
    // the same round twice: refused (a fresh name each time)
    await expect(redeployProof(e.g.gh, e.t, s, { base, variant: 'main', round: 2, files: [{ path: 'z.txt', content: 'z\n' }], pipegenWorkflows: new Set(), workflows: WORKFLOWS }, { ...e.opts, transport: e.f.transport }))
      .rejects.toThrow(/fresh/);
  });
});

describe('E4 fix round 1 (review M2, M5, M7)', () => {
  it('mergeWhen default: a pull_request workflow that never started means no merge, with the reason', async () => {
    const e = env((f) => {
      f.plans.push[PIPEGEN] = {};
      f.plans.pull_request[MERGE] = {};          // the harness never starts on the PR
      f.plans.push[HARNESS] = undefined as never;
    });
    const { main } = await session(e);
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: true, workflows: WORKFLOWS }, e.opts);
    expect(p.missing).toEqual([{ event: 'pull_request', workflow: HARNESS }]);
    expect(p.mergeSha).toBeUndefined();
    expect(e.f.merges).toEqual([]);
    expect(p.notMerged).toMatch(new RegExp(`${HARNESS.replace(/\./g, '\\.')}.*never started`));
    // a failed PR run: no merge either, named
    const e2 = env((f) => { simplePlans(f); f.plans.pull_request[MERGE] = { jobs: [{ name: 'pipegen / gate', conclusion: 'failure' }] }; });
    const s2 = await session(e2);
    const p2 = await proveVariant(e2.g.gh, e2.t, { branch: s2.main, merge: true, workflows: WORKFLOWS }, e2.opts);
    expect(e2.f.merges).toEqual([]);
    expect(p2.notMerged).toMatch(/failure/);
  });

  it('closeProofPr: an answer pipegen can\'t read is not "closed"; the PR is reported as a leftover', async () => {
    const e = env((f) => { simplePlans(f); f.closeAnswer = { weird: true }; });
    const { planted } = await session(e);
    const left: string[] = [];
    const p = await proveVariant(e.g.gh, e.t, { branch: planted, merge: false, workflows: WORKFLOWS }, { ...e.opts, leftover: (x) => left.push(x) });
    expect(p.closed).toBe(false);
    expect(left).toEqual([expect.stringMatching(new RegExp(`PR #${p.pr}.*may still be open`))]);
    expect(p.leftovers).toEqual(left);
    const l2: string[] = [];
    expect(await closeProofPr(e.g.gh, e.t, p.pr as number, { leftover: (x) => l2.push(x) })).toBe(false);
    expect(l2).toHaveLength(1);
  });

  it('shouldStop: runs that start after the stop are found again and cancelled (bounded); what can\'t be cancelled is a leftover', async () => {
    const e = env((f) => { f.plans.push[PIPEGEN] = { steps: 1_000 }; });
    const { main } = await session(e);
    let polls = 0;
    let late = false;
    const left: string[] = [];
    const p = await proveVariant(e.g.gh, e.t, { branch: main, merge: false, workflows: { push: [PIPEGEN], pullRequest: [] } }, {
      ...e.opts, leftover: (x) => left.push(x),
      shouldStop: () => {
        if (++polls <= 2) return false;
        if (!late) { late = true; e.f.pushed(main.branch, main.sha); }   // a second run of the same sha starts as pipegen stops
        return true;
      },
    });
    expect(p.stopped).toBe(true);
    const ofMain = e.f.runs.filter((r) => r.head_sha === main.sha).map((r) => r.id).sort();
    expect(ofMain).toHaveLength(2);
    expect([...new Set(e.f.cancels)].sort()).toEqual(ofMain);
    expect(e.clock.t).toBeLessThan(10 * 60_000);
    expect(left).toEqual([]);
  });
});

describe('E4 runs: handles', () => {
  it('waitForRuns takes only handles findRuns made for this target', async () => {
    const e = env(simplePlans);
    const forged: RunHandle = { workflow: PIPEGEN, runId: 1, url: 'x', event: 'push', headSha: 'a'.repeat(40) };
    await expect(waitForRuns(e.g.gh, e.t, [forged], e.opts)).rejects.toThrow(ScratchGuardError);
    const { main } = await session(e);
    const h = await findRuns(e.g.gh, e.t, { headSha: main.sha, event: 'push', workflows: [PIPEGEN], branch: main.branch });
    const other = proofTarget(app(), { runId: '20261103-120000-abcde1' });
    await expect(waitForRuns(e.g.gh, other, h, e.opts)).rejects.toThrow(ScratchGuardError);
  });
});
