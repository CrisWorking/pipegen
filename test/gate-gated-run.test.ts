// Plan C Task C8: findGatedRun and the find-run mode (preflight S18, Review Focus 12, DECISIONS #78). Written first.
// Before a deploy pipegen must prove that the EXACT commit being deployed passed the gate in a trusted push run of pipegen.yml on the default
// branch of this repository: a false "found" lets unverified code deploy. Everything the API says is hostile, and every doubt is "not ok".
//
// The run-selection choice (documented, tested): several runs for one sha (a re-push, a re-run that made a new attempt of one run, a second
// workflow run) are judged one by one; ANY ONE trusted run whose latest attempt has exactly one gate job concluding success is enough. A failed
// latest attempt in one run does not veto a trusted successful run: the commit did pass the gate in a trusted run.
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { WORKFLOW_PATH, type GateGithub, type RunQuery } from '../gate/src/baseline.js';
import { findGatedRun, type GatedRun, type GatedRunOpts } from '../gate/src/gated-run.js';
import { API_ROOT, GitHubApiError, githubAdapter, type AdapterOptions, type GateGithubAdapter } from '../gate/src/github-adapter.js';
import { main, MODE_INPUTS, type MainDeps } from '../gate/src/main.js';
import { GATE_CHECK_NAME } from '../src/types.js';
import { GATE_MODES, PIPEGEN_GATE_USES, RENDERER_INPUTS, rendererInputProblems } from '../src/engine/tool-flags.js';
import { CRED, outputsOf, runner, type Runner } from './helpers/gate-world.js';

const ROOT = resolve(import.meta.dirname, '..');
const SHA = '1'.repeat(40);
const TIP = 'e'.repeat(40);
const CSHA = 'c'.repeat(40);
const PREFIX = 'acme/pipelines/.github/workflows/app--merge.yml';
const REPO = { owner: 'acme', name: 'app', id: 7, defaultBranch: 'main' };
const GH_IN = ['github', 'token'].join('-');
type Obj = Record<string, unknown>;

const run = (over: Obj = {}): Obj => ({
  id: 1001, event: 'push', path: WORKFLOW_PATH, head_repository: { id: 7 }, head_branch: 'main', head_sha: SHA, status: 'completed', conclusion: 'success', run_attempt: 1,
  referenced_workflows: [], ...over,
});
const central = (over: Obj = {}): Obj => ({ path: `${PREFIX}@refs/heads/main`, sha: CSHA, ref: 'refs/heads/main', ...over });
const job = (over: Obj = {}): Obj => ({ id: 5001, run_id: 1001, run_attempt: 1, name: GATE_CHECK_NAME, status: 'completed', conclusion: 'success', ...over });
const err = (m = 'boom'): Error => new Error(m);

/** A scripted GitHub. `runs` may change by poll; every call is logged. */
class Fake {
  calls: string[] = [];
  polls = 0;
  runs: ((poll: number) => unknown) | unknown = [];
  jobs = new Map<string, unknown>();            // `${runId}:${attempt}` -> array of jobs, or the whole answer
  history = new Map<string, unknown>();         // sha -> compare answer
  fallbackCompare: unknown = { status: 'ahead' };
  tag: unknown = false;
  tip: unknown = { ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } };
  lastQuery: RunQuery | undefined;
  private out(a: unknown): unknown { if (a instanceof Error) throw a; return a; }
  async listRuns(_o: string, _n: string, q: RunQuery): Promise<unknown> {
    this.calls.push(`runs ${q.page}`); this.polls++; this.lastQuery = q;
    const r = typeof this.runs === 'function' ? (this.runs as (p: number) => unknown)(this.polls) : this.runs;
    this.out(r);
    return Array.isArray(r) ? { total_count: r.length, workflow_runs: r } : r;
  }
  async listAttemptJobs(_o: string, _n: string, runId: number, attempt: number, page: number, perPage: number): Promise<unknown> {
    this.calls.push(`jobs ${runId} ${attempt} ${page}`);
    const a = this.jobs.has(`${runId}:${attempt}`) ? this.jobs.get(`${runId}:${attempt}`) : new Error('404');
    this.out(a);
    return Array.isArray(a) ? { total_count: a.length, jobs: a.slice((page - 1) * perPage, page * perPage) } : a;
  }
  async branchHead(): Promise<unknown> { this.calls.push('tip'); return this.out(this.tip); }
  async tagExists(): Promise<boolean> { this.calls.push('tag'); return this.out(this.tag) as boolean; }
  async compare(_o: string, _n: string, base: string, head: string): Promise<unknown> { this.calls.push(`compare ${base.slice(0, 2)}...${head.slice(0, 2)}`); return this.out(this.history.has(base) ? this.history.get(base) : this.fallbackCompare); }
  gh(): GateGithub { return this as unknown as GateGithub; }
  count(prefix: string): number { return this.calls.filter((c) => c.startsWith(prefix)).length; }
}
/** A fake clock: sleeping moves time. */
function clock(): { now: () => number; sleep: (ms: number) => Promise<void>; slept: number[] } {
  let t = 1_000_000;
  const slept: number[] = [];
  return { now: () => t, sleep: async (ms) => { slept.push(ms); t += ms; }, slept };
}
function opts(c = clock(), over: Partial<GatedRunOpts> = {}): GatedRunOpts {
  return { workflowPath: WORKFLOW_PATH, gateJobName: GATE_CHECK_NAME, waitMs: 30 * 60_000, pollMs: 20_000, sleep: c.sleep, now: c.now, ...over };
}
const find = (f: Fake, over: Partial<GatedRunOpts> = {}, sha = SHA, repo = REPO): Promise<GatedRun> => findGatedRun(f.gh(), repo, sha, opts(clock(), over));
const goodWorld = (): Fake => { const f = new Fake(); f.runs = [run()]; f.jobs.set('1001:1', [job()]); return f; };
const okRun = (id: number, over: Obj = {}): [Obj, Obj[]] => [run({ id, ...over }), [job({ run_id: id })]];
const reason = (r: GatedRun): string => (r.ok ? 'ok' : r.reason);

describe('findGatedRun: a trusted push run with a successful gate', () => {
  it('trusted push run with successful gate → ok, with the run id and its url (built here, not taken from the server)', async () => {
    const f = goodWorld();
    f.runs = [run({ html_url: 'https://evil.example/x' })];
    const r = await find(f);
    expect(r).toEqual({ ok: true, runId: 1001, url: 'https://github.com/acme/app/actions/runs/1001' });
  });
  it('asks the runs of pipegen.yml for this commit, event push, on the default branch; the filters are only narrowing', async () => {
    const f = goodWorld();
    await find(f);
    expect(f.lastQuery).toMatchObject({ workflow: 'pipegen.yml', branch: 'main', event: 'push', headSha: SHA, page: 1 });
    expect(f.lastQuery?.status).toBeUndefined();
  });
  it('uses the latest attempt\'s jobs: GET .../attempts/{run_attempt}/jobs', async () => {
    const f = goodWorld();
    await find(f);
    expect(f.calls.filter((c) => c.startsWith('jobs'))).toEqual(['jobs 1001 1 1']);
  });
  it('a sha that is not 40 lower-case hex is an error before any call', async () => {
    for (const bad of ['A'.repeat(40), '1'.repeat(39), '1'.repeat(41), 'main', '', ` ${SHA}`]) {
      const f = goodWorld();
      const r = await find(f, {}, bad);
      expect(reason(r), bad).toBe('error');
      expect(f.calls, bad).toEqual([]);
    }
  });
  it('a workflow path other than pipegen.yml\'s is an error (trust is judged for that one file)', async () => {
    const f = goodWorld();
    expect(reason(await find(f, { workflowPath: '.github/workflows/other.yml' }))).toBe('error');
    expect(f.calls).toEqual([]);
  });
});

describe('findGatedRun: a run is trusted only by its own fields (C3 trust, reused)', () => {
  const ignored = async (over: Obj): Promise<void> => {
    const f = goodWorld();
    f.runs = [run(over)];
    const r = await find(f);
    expect(r.ok, JSON.stringify(over)).toBe(false);
    expect(reason(r), JSON.stringify(over)).toBe('none');
  };
  it('pull_request run for the same sha ignored', async () => { await ignored({ event: 'pull_request' }); });
  it('workflow_dispatch, schedule and merge_group runs ignored', async () => { for (const event of ['workflow_dispatch', 'schedule', 'merge_group', 'workflow_run']) await ignored({ event }); });
  it('run from another head_repository.id ignored (a fork with the same names)', async () => { await ignored({ head_repository: { id: 8, name: 'app', full_name: 'acme/app' } }); await ignored({ head_repository: { id: '7' } }); await ignored({ head_repository: null }); });
  it('head_branch not default ignored', async () => { for (const b of ['dev', 'main2', 'Main', 'refs/heads/main', '', null]) await ignored({ head_branch: b }); });
  it('a run for another sha ignored, even if the server listed it', async () => { await ignored({ head_sha: '2'.repeat(40) }); await ignored({ head_sha: 'F'.repeat(40) }); });
  it('another workflow path ignored', async () => { for (const p of ['.github/workflows/other.yml', '.github/workflows/pipegen.yml@refs/heads/main', 'pipegen.yml', '.github/workflows/Pipegen.yml']) await ignored({ path: p }); });
  it('inherited properties are not run fields', async () => {
    const f = goodWorld();
    const proto = { event: 'push', path: WORKFLOW_PATH, head_branch: 'main', head_sha: SHA, head_repository: { id: 7 }, id: 1001, status: 'completed', run_attempt: 1 };
    f.runs = [Object.create(proto) as Obj];
    expect(reason(await find(f))).toBe('none');
  });
  it('tag named main (sha not in the default history) ignored: compare behind or diverged', async () => {
    for (const status of ['behind', 'diverged']) {
      const f = goodWorld();
      f.history.set(SHA, { status });
      const r = await find(f);
      expect(r.ok, status).toBe(false);
      expect(f.count('jobs'), 'no jobs are read for an untrusted run').toBe(0);
    }
  });
  it('a tag named like the default branch exists → not ok (the belt), and no jobs are read', async () => {
    const f = goodWorld();
    f.tag = true;
    const r = await find(f);
    expect(r.ok).toBe(false);
    expect(reason(r)).toBe('error');
    expect(f.count('jobs')).toBe(0);
  });
  it('the tag lookup failing is not ok', async () => {
    const f = goodWorld();
    f.tag = err();
    expect(reason(await find(f))).toBe('error');
  });
  it('the branch commit resolves to a tag (not a commit), to another ref, or the lookup errors → not ok', async () => {
    for (const tip of [{ ref: 'refs/heads/main', object: { type: 'tag', sha: TIP } }, { ref: 'refs/tags/main', object: { type: 'commit', sha: TIP } }, { ref: 'refs/heads/main', object: { type: 'commit', sha: 'Z' } }, err(), null, []]) {
      const f = goodWorld();
      f.tip = tip;
      expect(reason(await find(f)), JSON.stringify(tip)).toBe('error');
    }
  });
  it('compare errors or answers without a status → not ok', async () => {
    for (const a of [err(), {}, { status: 5 }, null]) {
      const f = goodWorld();
      f.history.set(SHA, a);
      expect((await find(f)).ok).toBe(false);
    }
  });
  it('the branch commit is resolved fresh for every judgement and never cached (a run in progress, then done: two tip lookups)', async () => {
    const f = goodWorld();
    f.runs = (p: number): unknown => [run({ status: p === 1 ? 'in_progress' : 'completed' })];
    const r = await find(f);
    expect(r.ok).toBe(true);
    expect(f.count('tip')).toBe(2);
    expect(f.count('tag')).toBe(2);
  });
});

describe('findGatedRun: the central workflow (private repositories)', () => {
  const C = { pathPrefix: PREFIX, sha: CSHA };
  const withRefs = (refs: unknown, over: Partial<GatedRunOpts> = {}): Promise<GatedRun> => {
    const f = goodWorld();
    f.runs = [run({ referenced_workflows: refs })];
    return find(f, { central: C, ...over });
  };
  it('the entry path starts with prefix@ and its sha field is the expected one → ok', async () => { expect((await withRefs([central()])).ok).toBe(true); });
  it('pinned by SHA: the entry has no ref field (DECISIONS #78), the path\'s @ part is a sha → still ok', async () => {
    expect((await withRefs([{ path: `${PREFIX}@${CSHA}`, sha: CSHA }])).ok).toBe(true);
    expect((await withRefs([{ path: `${PREFIX}@refs/heads/main`, sha: CSHA }])).ok).toBe(true);
  });
  it('referenced workflow path matches but sha field differs → not ok [Review Focus 12]', async () => {
    const r = await withRefs([central({ sha: 'd'.repeat(40) })]);
    expect(reason(r)).toBe('wrong-central');
  });
  it('path ref shows the expected sha but the sha field differs → not ok (the ref after @ is never trusted)', async () => {
    expect(reason(await withRefs([{ path: `${PREFIX}@${CSHA}`, sha: 'd'.repeat(40) }]))).toBe('wrong-central');
    expect(reason(await withRefs([{ path: `${PREFIX}@${CSHA}`, ref: CSHA }]))).toBe('wrong-central');   // no sha field at all
  });
  it('right sha but wrong path prefix → not ok', async () => {
    for (const path of [`other/pipelines/.github/workflows/app--merge.yml@refs/heads/main`, `${PREFIX}x@refs/heads/main`, `${PREFIX}-evil@refs/heads/main`, `x${PREFIX}@refs/heads/main`, PREFIX, `acme/pipelines/.github/workflows/App--merge.yml@refs/heads/main`]) {
      expect(reason(await withRefs([central({ path })])), path).toBe('wrong-central');
    }
  });
  it('the two are checked on the SAME entry: one entry with the prefix and another with the sha is not enough', async () => {
    expect(reason(await withRefs([central({ sha: 'd'.repeat(40) }), { path: 'other/x.yml@main', sha: CSHA }]))).toBe('wrong-central');
  });
  it('an entry with the prefix and a wrong sha next to a good one fails closed (one central workflow, one commit)', async () => {
    expect(reason(await withRefs([central(), central({ sha: 'd'.repeat(40) })]))).toBe('wrong-central');
    expect((await withRefs([{ path: 'actions/other@v1', sha: 'a'.repeat(40) }, central()])).ok).toBe(true);   // an unrelated reusable workflow is fine
  });
  it('no referenced_workflows, or one that is not a list of entries → not ok', async () => {
    for (const refs of [undefined, [], null, 'x', {}, [null], [5], ['x'], [{ sha: CSHA }], [{ path: 5, sha: CSHA }], [{ path: `${PREFIX}@x`, sha: 5 }]]) {
      const f = goodWorld();
      const r0 = run();
      delete r0.referenced_workflows;
      f.runs = [refs === undefined ? r0 : run({ referenced_workflows: refs })];
      expect(reason(await find(f, { central: C })), JSON.stringify(refs)).toBe('wrong-central');
    }
  });
  it('the sha field is compared exactly (case, length)', async () => {
    for (const sha of [CSHA.toUpperCase(), CSHA.slice(1), `${CSHA}0`, ` ${CSHA}`]) expect(reason(await withRefs([central({ sha })])), sha).toBe('wrong-central');
  });
  it('an expected central sha that is not 40 lower-case hex, or an empty prefix, is an error before any call', async () => {
    for (const bad of [{ pathPrefix: PREFIX, sha: CSHA.toUpperCase() }, { pathPrefix: PREFIX, sha: 'main' }, { pathPrefix: '', sha: CSHA }, { pathPrefix: `${PREFIX}@x`, sha: CSHA }]) {
      const f = goodWorld();
      expect(reason(await find(f, { central: bad })), JSON.stringify(bad)).toBe('error');
      expect(f.calls).toEqual([]);
    }
  });
  it('without a central, referenced_workflows is not looked at (public repositories)', async () => { expect((await withRefs([])).ok).toBe(false); const f = goodWorld(); expect((await find(f)).ok).toBe(true); });
  it('a run with the wrong central is not waited for', async () => {
    const f = goodWorld();
    f.runs = [run({ status: 'in_progress', referenced_workflows: [central({ sha: 'd'.repeat(40) })] })];
    const c = clock();
    const r = await findGatedRun(f.gh(), REPO, SHA, opts(c, { central: C }));
    expect(reason(r)).toBe('wrong-central');
    expect(c.slept).toEqual([]);
  });
});

describe('findGatedRun: the gate job of the latest attempt (S18)', () => {
  const withJobs = (jobs: unknown, over: Obj = {}): Promise<GatedRun> => {
    const f = new Fake();
    f.runs = [run(over)];
    f.jobs.set(`1001:${typeof over.run_attempt === 'number' ? over.run_attempt : 1}`, jobs);
    return find(f);
  };
  it('gate job failed → gate-failed', async () => {
    for (const conclusion of ['failure', 'cancelled', 'skipped', 'timed_out', 'neutral', 'action_required', null, 'Success', 'success ']) {
      expect(reason(await withJobs([job({ conclusion })])), String(conclusion)).toBe('gate-failed');
    }
  });
  it('the gate job must be completed as well as successful', async () => { expect(reason(await withJobs([job({ status: 'in_progress', conclusion: 'success' })]))).toBe('gate-failed'); });
  it('no job named like the gate → gate-failed; jobs with similar names do not count', async () => {
    for (const name of ['gate', 'pipegen/gate', 'pipegen / gate ', 'Pipegen / gate', 'pipegen / gate / x', ' pipegen / gate', 'pipegen / gate\n']) {
      expect(reason(await withJobs([job({ name })])), name).toBe('gate-failed');
    }
    expect(reason(await withJobs([]))).toBe('gate-failed');
  });
  it('two jobs named GATE_CHECK_NAME in the attempt → not ok ("more than one job reports as the gate")', async () => {
    const r = await withJobs([job(), job({ id: 5002 })]);
    expect(reason(r)).toBe('gate-failed');
    expect(r.ok ? '' : r.detail).toMatch(/more than one job reports as the gate/);
    expect(reason(await withJobs([job({ conclusion: 'failure' }), job({ id: 5002 })]))).toBe('gate-failed');   // one real failure, one fake success
    expect(reason(await withJobs([job(), job({ id: 5002, conclusion: 'skipped' })]))).toBe('gate-failed');
  });
  it('the gate job among others is found by its exact name, whatever the order', async () => {
    expect((await withJobs([job({ id: 1, name: 'scan' }), job(), job({ id: 3, name: 'deploy', conclusion: 'failure' })])).ok).toBe(true);
  });
  it('the latest attempt only: an older attempt succeeded but the latest failed → not ok for that run (the older attempt is never read)', async () => {
    const f = new Fake();
    f.runs = [run({ run_attempt: 2 })];
    f.jobs.set('1001:1', [job()]);
    f.jobs.set('1001:2', [job({ run_attempt: 2, conclusion: 'failure' })]);
    const r = await find(f);
    expect(reason(r)).toBe('gate-failed');
    expect(f.calls.filter((c) => c.startsWith('jobs'))).toEqual(['jobs 1001 2 1']);
  });
  it('a re-run that succeeded after a failed attempt → ok', async () => {
    const f = new Fake();
    f.runs = [run({ run_attempt: 2 })];
    f.jobs.set('1001:1', [job({ conclusion: 'failure' })]);
    f.jobs.set('1001:2', [job({ run_attempt: 2 })]);
    expect((await find(f)).ok).toBe(true);
  });
  it('a job that is not of this run or this attempt makes the answer unusable (error), even if it looks like a success', async () => {
    expect(reason(await withJobs([job({ run_id: 999 })]))).toBe('error');
    expect(reason(await withJobs([job({ run_attempt: 7 })]))).toBe('error');
    expect(reason(await withJobs([job(), { name: 'x', run_id: 'z' }]))).toBe('error');
  });
  it('a jobs answer that is not what the API gives → error (never ok)', async () => {
    for (const a of [null, [], {}, { jobs: [] }, { total_count: 1 }, { total_count: 'x', jobs: [job()] }, { total_count: 1, jobs: 'x' }, { total_count: 1, jobs: [null] }, { total_count: 1, jobs: [5] }, err(), 'x']) {
      const f = new Fake();
      f.runs = [run()];
      f.jobs.set('1001:1', a);
      const r = await find(f);
      expect(r.ok, JSON.stringify(a)).toBe(false);
    }
  });
  it('every page of jobs is read: a second gate job on page 2 is found', async () => {
    const many = Array.from({ length: 150 }, (_, i) => job({ id: 100 + i, name: `build-${i}` }));
    many[2] = job({ id: 2 });
    many[120] = job({ id: 3 });
    const f = new Fake();
    f.runs = [run()];
    f.jobs.set('1001:1', many);
    const r = await find(f);
    expect(reason(r)).toBe('gate-failed');
    expect(f.calls.filter((c) => c.startsWith('jobs'))).toEqual(['jobs 1001 1 1', 'jobs 1001 1 2']);
    many[120] = job({ id: 3, name: 'x' });
    expect((await find(f)).ok).toBe(true);
  });
  it('more jobs than the page cap can read → error (the rest could hide a second gate job)', async () => {
    const f = new Fake();
    f.runs = [run()];
    f.jobs.set('1001:1', Array.from({ length: 700 }, (_, i) => job({ id: 100 + i, name: i === 0 ? GATE_CHECK_NAME : `b-${i}` })));
    expect(reason(await find(f))).toBe('error');
  });
});

describe('findGatedRun: several runs for one sha (re-pushes, re-runs): any one trusted successful run is enough', () => {
  it('a failed latest attempt in one run does not veto another trusted successful run (either order)', async () => {
    const [a, aj] = okRun(1001);
    const [b, bj] = okRun(1002, { run_attempt: 3 });
    for (const runs of [[a, b], [b, a]]) {
      const f = new Fake();
      f.runs = runs;
      f.jobs.set('1001:1', aj);
      f.jobs.set('1002:3', [job({ run_id: 1002, run_attempt: 3, conclusion: 'failure' })]);
      const r = await find(f);
      expect(r).toMatchObject({ ok: true, runId: 1001 });
    }
  });
  it('all trusted runs failed → gate-failed; an untrusted successful run next to them does not rescue it', async () => {
    const f = new Fake();
    f.runs = [run({ id: 1001 }), run({ id: 1002, event: 'pull_request' }), run({ id: 1003, head_repository: { id: 9 } })];
    f.jobs.set('1001:1', [job({ conclusion: 'failure' })]);
    for (const id of [1002, 1003]) f.jobs.set(`${id}:1`, [job({ run_id: id })]);
    const r = await find(f);
    expect(reason(r)).toBe('gate-failed');
    expect(f.calls.filter((c) => c.startsWith('jobs'))).toEqual(['jobs 1001 1 1']);
  });
  it('a failed run and a run in progress: waits for the second, and is ok when it passes', async () => {
    const f = new Fake();
    f.runs = (p: number): unknown => [run({ id: 1001 }), run({ id: 1002, status: p < 3 ? 'in_progress' : 'completed' })];
    f.jobs.set('1001:1', [job({ conclusion: 'failure' })]);
    f.jobs.set('1002:1', [job({ run_id: 1002 })]);
    const c = clock();
    const r = await findGatedRun(f.gh(), REPO, SHA, opts(c));
    expect(r).toMatchObject({ ok: true, runId: 1002 });
    expect(c.slept).toEqual([20_000, 20_000]);
  });
  it('an error on one run does not hide a trusted success on another; an error with no success is an error', async () => {
    const f = new Fake();
    f.runs = [run({ id: 1001 }), run({ id: 1002 })];
    f.jobs.set('1001:1', err());
    f.jobs.set('1002:1', [job({ run_id: 1002 })]);
    expect(await find(f)).toMatchObject({ ok: true, runId: 1002 });
    f.jobs.set('1002:1', [job({ run_id: 1002, conclusion: 'failure' })]);
    expect(reason(await find(f))).toBe('error');
  });
});

describe('findGatedRun: waiting', () => {
  it('run in progress → waits (every pollMs), then ok when it finishes', async () => {
    for (const status of ['queued', 'in_progress', 'waiting', 'pending', 'requested']) {
      const f = goodWorld();
      f.runs = (p: number): unknown => [run({ status: p < 4 ? status : 'completed' })];
      const c = clock();
      const r = await findGatedRun(f.gh(), REPO, SHA, opts(c));
      expect(r.ok, status).toBe(true);
      expect(c.slept, status).toEqual([20_000, 20_000, 20_000]);
      expect(f.count('jobs'), 'jobs are read once, when the run is done').toBe(1);
    }
  });
  it('still in progress after 30 min → timeout, within the time (the last sleep is cut to the time left)', async () => {
    const f = goodWorld();
    f.runs = [run({ status: 'in_progress' })];
    const c = clock();
    const r = await findGatedRun(f.gh(), REPO, SHA, opts(c, { waitMs: 30 * 60_000, pollMs: 25_000 }));
    expect(reason(r)).toBe('timeout');
    expect(c.slept.reduce((a, b) => a + b, 0)).toBe(30 * 60_000);
    expect(Math.max(...c.slept)).toBeLessThanOrEqual(25_000);
    expect(f.count('jobs')).toBe(0);
  });
  it('waitMs 0: one look, no sleep; a run in progress is a timeout, a finished one is judged', async () => {
    const f = goodWorld();
    f.runs = [run({ status: 'in_progress' })];
    const c = clock();
    expect(reason(await findGatedRun(f.gh(), REPO, SHA, opts(c, { waitMs: 0 })))).toBe('timeout');
    expect(c.slept).toEqual([]);
    expect((await find(goodWorld(), { waitMs: 0 })).ok).toBe(true);
  });
  it('a run that finishes with a failed gate while waiting → gate-failed', async () => {
    const f = goodWorld();
    f.runs = (p: number): unknown => [run({ status: p < 2 ? 'queued' : 'completed' })];
    f.jobs.set('1001:1', [job({ conclusion: 'failure' })]);
    expect(reason(await find(f))).toBe('gate-failed');
  });
  it('a new attempt started while waiting is read as the latest attempt', async () => {
    const f = new Fake();
    f.runs = (p: number): unknown => [p < 2 ? run({ status: 'in_progress' }) : run({ run_attempt: 2 })];
    f.jobs.set('1001:2', [job({ run_attempt: 2 })]);
    expect((await find(f)).ok).toBe(true);
  });
  it('an unknown run status is an error, not a wait and not a pass', async () => {
    for (const status of ['weird', '', null, 5, undefined]) {
      const f = goodWorld();
      f.runs = [run({ status })];
      expect(reason(await find(f)), String(status)).toBe('error');
    }
  });
  it('no matching run (expired or never made) → none, with "re-run the pipeline on this commit", and it does not wait', async () => {
    const f = goodWorld();
    f.runs = [];
    const c = clock();
    const r = await findGatedRun(f.gh(), REPO, SHA, opts(c));
    expect(r).toMatchObject({ ok: false, reason: 'none' });
    expect(r.ok ? '' : r.detail).toMatch(/re-run the pipeline on this commit/);
    expect(c.slept).toEqual([]);
  });
});

describe('findGatedRun: the call budget and API errors fail closed', () => {
  it('the call budget is exhausted while waiting → error (never ok, never an endless wait)', async () => {
    const f = goodWorld();
    f.runs = [run({ status: 'in_progress' })];
    const c = clock();
    const r = await findGatedRun(f.gh(), REPO, SHA, opts(c, { waitMs: 6 * 3600_000, maxCalls: 12 }));
    expect(r.ok).toBe(false);
    expect(['error', 'timeout']).toContain(reason(r));
    expect(r.ok ? '' : r.detail).toMatch(/budget/);
    expect(f.calls.length).toBeLessThanOrEqual(12);
  });
  it('the default budget is finite: a 6 h wait on a run that never ends stops (the poll interval is stretched), within the budget, never ok', async () => {
    const f = goodWorld();
    f.runs = [run({ status: 'in_progress' })];
    const r = await findGatedRun(f.gh(), REPO, SHA, opts(clock(), { waitMs: 6 * 3600_000 }));
    expect(r.ok).toBe(false);
    expect(f.calls.length).toBeLessThan(1000);
  });
  it('a budget that runs out in the middle of judging a finished run is not a pass', async () => {
    for (let max = 0; max <= 7; max++) {
      const f = goodWorld();
      const r = await findGatedRun(f.gh(), REPO, SHA, opts(clock(), { maxCalls: max }));
      expect(r.ok, `max ${max}`).toBe(max >= 5);   // list, tag, tip, compare and jobs: 5 calls make the proof, one fewer never does
      expect(f.calls.length).toBeLessThanOrEqual(max);
    }
  });
  it('a typical 30 min wait stays within the default budget', async () => {
    const f = goodWorld();
    f.runs = (p: number): unknown => [run({ status: p < 90 ? 'in_progress' : 'completed' })];
    const r = await find(f);
    expect(r.ok).toBe(true);
    expect(f.calls.length).toBeLessThan(150);
  });
  it('the run list failing (rate limit, 5xx, network) → error with a reason, never ok', async () => {
    for (const e of [err('rate limit'), new GitHubApiError('x: GitHub rate limit', { status: 403, rateLimited: true }), new GitHubApiError('x', { status: 502 })]) {
      const f = goodWorld();
      f.runs = e;
      const r = await find(f);
      expect(reason(r)).toBe('error');
      expect(r.ok ? '' : r.detail.length).toBeGreaterThan(10);
    }
  });
  it('the error text never carries the error\'s own message (it may hold what the server wrote)', async () => {
    const f = goodWorld();
    f.runs = err('SECRET-IN-MESSAGE ghp_x');
    const r = await find(f);
    expect(JSON.stringify(r)).not.toContain('SECRET-IN-MESSAGE');
  });
  it('a hostile run list: not an object, no workflow_runs, not an array → error', async () => {
    for (const a of [null, 5, 'x', [], {}, { workflow_runs: 'x' }, { workflow_runs: null }, { workflow_runs: {} }]) {
      const f = goodWorld();
      f.runs = a;
      const r = await find(f);
      expect(r.ok, JSON.stringify(a)).toBe(false);
    }
    const f = goodWorld();
    f.runs = [null, 5, 'x', [], run()];
    expect((await find(f)).ok).toBe(true);   // junk entries are skipped; the trusted run is still found
  });
  it('a run without a usable id or attempt → error, never a pass', async () => {
    for (const over of [{ id: 0 }, { id: -1 }, { id: 1.5 }, { id: '1001' }, { id: undefined }, { run_attempt: 0 }, { run_attempt: '1' }, { run_attempt: undefined }, { run_attempt: 1.5 }]) {
      const f = goodWorld();
      f.runs = [run(over)];
      const r = await find(f);
      expect(r.ok, JSON.stringify(over)).toBe(false);
    }
  });
  it('property: 300 random damages to a passing world never give ok, unless the damage left it passing', async () => {
    let seed = 12345;
    const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
    const damages: ((r: Obj, j: Obj[], f: Fake) => void)[] = [
      (r) => { r.event = 'pull_request'; }, (r) => { r.head_branch = 'dev'; }, (r) => { r.head_repository = { id: 9 }; }, (r) => { r.path = 'x'; }, (r) => { r.head_sha = '2'.repeat(40); },
      (_r, j) => { (j[0] as Obj).conclusion = 'failure'; }, (_r, j) => { (j[0] as Obj).name = 'x'; }, (_r, j) => { j.push(job({ id: 9 })); },
      (_r, _j, f) => { f.history.set(SHA, { status: 'behind' }); }, (_r, _j, f) => { f.tag = true; }, (_r, _j, f) => { f.tip = null; }, (r) => { r.status = 'in_progress'; },
    ];
    for (let i = 0; i < 300; i++) {
      const r = run();
      const j = [job()];
      const f = new Fake();
      const picks = new Set<number>();
      for (let k = 0, n = 1 + rnd(3); k < n; k++) picks.add(rnd(damages.length));
      for (const p of picks) (damages[p] as (r: Obj, j: Obj[], f: Fake) => void)(r, j, f);
      f.runs = [r];
      f.jobs.set('1001:1', j);
      const res = await findGatedRun(f.gh(), REPO, SHA, opts(clock(), { waitMs: 0 }));
      expect(res.ok, [...picks].join(',')).toBe(false);
    }
  });
});

// ---------- the REST adapter: the two calls this task adds ----------

describe('the adapter: runs for a commit, and the jobs of one attempt', () => {
  const TK = ['to', 'ken'].join('');
  const mk = (): { gh: GateGithubAdapter; urls: string[] } => {
    const urls: string[] = [];
    const f = (async (url: string) => { urls.push(String(url)); return new Response(JSON.stringify({ ok: 1 }), { status: 200 }); }) as unknown as typeof fetch;
    return { gh: githubAdapter({ [TK]: CRED, fetch: f } as unknown as AdapterOptions), urls };
  };
  it('listRuns with a head sha and no status filter; the old form is unchanged', async () => {
    const { gh, urls } = mk();
    await gh.listRuns('acme', 'app', { workflow: 'pipegen.yml', branch: 'main', event: 'push', headSha: SHA, page: 1, perPage: 100 });
    await gh.listRuns('acme', 'app', { workflow: 'pipegen.yml', branch: 'main', event: 'push', status: 'success', page: 2, perPage: 100 });
    expect(urls).toEqual([
      `${API_ROOT}/repos/acme/app/actions/workflows/pipegen.yml/runs?event=push&branch=main&head_sha=${SHA}&per_page=100&page=1`,
      `${API_ROOT}/repos/acme/app/actions/workflows/pipegen.yml/runs?event=push&branch=main&status=success&per_page=100&page=2`,
    ]);
  });
  it('listRuns refuses a head sha that is not 40 lower-case hex, and any status but success', async () => {
    const { gh, urls } = mk();
    const q = { workflow: 'pipegen.yml', branch: 'main', event: 'push' as const, page: 1, perPage: 100 };
    for (const headSha of ['main', 'A'.repeat(40), SHA.slice(1), `${SHA}&x=1`, '']) await expect(gh.listRuns('acme', 'app', { ...q, headSha })).rejects.toThrow(GitHubApiError);
    await expect(gh.listRuns('acme', 'app', { ...q, status: 'completed' } as unknown as RunQuery)).rejects.toThrow(GitHubApiError);
    expect(urls).toEqual([]);
  });
  it('listAttemptJobs is GET /actions/runs/{id}/attempts/{n}/jobs with the page and size; ids, pages and sizes are checked', async () => {
    const { gh, urls } = mk();
    await gh.listAttemptJobs('acme', 'app', 1001, 2, 3, 100);
    expect(urls).toEqual([`${API_ROOT}/repos/acme/app/actions/runs/1001/attempts/2/jobs?per_page=100&page=3`]);
    for (const [id, at, p, per] of [[0, 1, 1, 100], [1, 0, 1, 100], [1.5, 1, 1, 100], [1, 1, 0, 100], [1, 1, 6, 100], [1, 1, 1, 101], [1, 1, 1, 0], [Number.NaN, 1, 1, 100]] as const) {
      await expect(gh.listAttemptJobs('acme', 'app', id, at, p, per)).rejects.toThrow(GitHubApiError);
    }
    expect(urls.length).toBe(1);
  });
});

// ---------- the find-run mode ----------

const NOW = new Date('2026-10-30T12:00:00Z');
const PAYLOAD = (priv: unknown = true): Obj => ({ repository: { id: 7, name: 'app', full_name: 'acme/app', owner: { login: 'acme' }, default_branch: 'main', ...(priv === undefined ? {} : { private: priv }) } });
interface Ran { code: number; out: string; lines: string[]; outputs: Record<string, string>; r: Runner; f: Fake; github: number }
async function go(inputs: Record<string, string | undefined>, f: Fake = goodWorld(), o: { payload?: unknown; deps?: Partial<MainDeps>; tokenFactory?: boolean } = {}): Promise<Ran> {
  const r = runner(inputs, { event: 'workflow_run', sha: SHA, payload: o.payload ?? PAYLOAD() });
  const chunks: string[] = [];
  let github = 0;
  const code = await main({
    env: r.env, now: () => NOW, write: (t) => { chunks.push(t); },
    github: ((_opts: AdapterOptions) => { github++; return f as unknown as GateGithubAdapter; }) as MainDeps['github'],
    ...o.deps,
  });
  const out = chunks.join('');
  return { code, out, lines: out.split('\n').filter((l) => l !== ''), outputs: outputsOf(r.output), r, f, github };
}
const FR = (over: Record<string, string | undefined> = {}): Record<string, string | undefined> => ({ mode: 'find-run', sha: SHA, 'central-workflow': PREFIX, 'central-sha': CSHA, [GH_IN]: CRED, ...over });
const centralWorld = (): Fake => { const f = goodWorld(); f.runs = [run({ referenced_workflows: [central()] })]; return f; };

describe('mode find-run', () => {
  it('action: find-run mode outputs run-id and run-url on success, exit 0', async () => {
    const x = await go(FR(), centralWorld());
    expect(x.code).toBe(0);
    expect(x.outputs).toEqual({ 'run-id': '1001', 'run-url': 'https://github.com/acme/app/actions/runs/1001' });
    expect(x.out).not.toMatch(/::error::/);
  });
  it('action: find-run mode fails when not ok (exit 1, ::error:: with the reason, empty outputs)', async () => {
    const f = centralWorld();
    f.jobs.set('1001:1', [job({ conclusion: 'failure' })]);
    const x = await go(FR(), f);
    expect(x.code).toBe(1);
    expect(x.out).toMatch(/::error::.*gate-failed/);
    expect(x.outputs).toEqual({ 'run-id': '', 'run-url': '' });
    for (const [reasonName, setup] of [['none', (g: Fake) => { g.runs = []; }], ['wrong-central', (g: Fake) => { g.runs = [run({ referenced_workflows: [central({ sha: 'd'.repeat(40) })] })]; }], ['error', (g: Fake) => { g.runs = err(); }]] as const) {
      const g = centralWorld();
      setup(g);
      const y = await go(FR(), g);
      expect(y.code, reasonName).toBe(1);
      expect(y.out, reasonName).toContain(reasonName);
      expect(y.outputs['run-id'], reasonName).toBe('');
    }
  });
  it('the token is masked first, before anything else is written, and never appears afterwards', async () => {
    const x = await go(FR(), centralWorld());
    expect(x.lines[0]).toBe(`::add-mask::${CRED}`);
    expect(x.lines.slice(1).some((l) => l.startsWith('::add-mask::'))).toBe(false);
    const f = centralWorld();
    f.runs = err(`GitHub said ${CRED}`);
    const y = await go(FR(), f);
    expect(y.out.split('\n').slice(1).join('\n')).not.toContain(CRED);
  });
  it('the sha input must be 40 lower-case hex: upper-case, short, long, a name or an expression text is a settings error with no GitHub call', async () => {
    for (const sha of ['A'.repeat(40), 'a'.repeat(39), 'a'.repeat(41), 'main', '${{ github.sha }}', `${'a'.repeat(39)}g`, '0x' + 'a'.repeat(38)]) {
      const f = centralWorld();
      const x = await go(FR({ sha }), f);
      expect(x.code, sha).toBe(1);
      expect(x.out, sha).toMatch(/::error::.*sha/);
      expect(x.f.calls, sha).toEqual([]);
      expect(x.outputs, sha).toEqual({ 'run-id': '', 'run-url': '' });
    }
    const none = await go(FR({ sha: undefined }), centralWorld());
    expect(none.code).toBe(1);
    expect(none.f.calls).toEqual([]);
  });
  it('central-workflow and central-sha go together; central-sha is a 40-hex commit; central-workflow a plain path without @ or ..', async () => {
    for (const bad of [{ 'central-sha': undefined }, { 'central-workflow': undefined }, { 'central-sha': CSHA.toUpperCase() }, { 'central-sha': 'main' }, { 'central-workflow': `${PREFIX}@main` }, { 'central-workflow': '../x.yml' }, { 'central-workflow': '/abs.yml' }, { 'central-workflow': 'a b' }]) {
      const x = await go(FR(bad), centralWorld());
      expect(x.code, JSON.stringify(bad)).toBe(1);
      expect(x.f.calls, JSON.stringify(bad)).toEqual([]);
    }
  });
  it('a private repository (or one that does not say) needs the central inputs; a public one may go without', async () => {
    for (const priv of [true, undefined, 'yes', null]) {
      const x = await go(FR({ 'central-workflow': undefined, 'central-sha': undefined }), goodWorld(), { payload: PAYLOAD(priv) });
      expect(x.code, String(priv)).toBe(1);
      expect(x.f.calls, String(priv)).toEqual([]);
    }
    const pub = await go(FR({ 'central-workflow': undefined, 'central-sha': undefined }), goodWorld(), { payload: PAYLOAD(false) });
    expect(pub.code).toBe(0);
    expect(pub.outputs['run-id']).toBe('1001');
  });
  it('timeout-minutes: default 30; a whole number of 1 to 360; anything else is a settings error', async () => {
    for (const bad of ['0', '-1', '361', '1e2', '30.5', 'abc', '030', '99999', '1 2', '0x10']) {
      const x = await go(FR({ 'timeout-minutes': bad }), centralWorld());
      expect(x.code, bad).toBe(1);
      expect(x.out, bad).toMatch(/::error::.*timeout-minutes/);
      expect(x.f.calls, bad).toEqual([]);
    }
    const waiting = (): Fake => { const f = centralWorld(); f.runs = [run({ status: 'in_progress', referenced_workflows: [central()] })]; return f; };
    const timed = async (timeout: string | undefined): Promise<number> => {
      let t = 0;
      const slept: number[] = [];
      const x = await go(FR({ 'timeout-minutes': timeout }), waiting(), { deps: { now: () => new Date(NOW.getTime() + t), sleep: async (ms) => { slept.push(ms); t += ms; } } });
      expect(x.code).toBe(1);
      expect(x.out).toMatch(/::error::.*timeout/);
      return slept.reduce((a, b) => a + b, 0);
    };
    expect(await timed(undefined)).toBe(30 * 60_000);
    expect(await timed('2')).toBe(2 * 60_000);
    expect(await timed('360')).toBeLessThanOrEqual(360 * 60_000);
  });
  it('waits for a run in progress through the injected sleep, then succeeds', async () => {
    const f = centralWorld();
    f.runs = (p: number): unknown => [run({ status: p < 3 ? 'in_progress' : 'completed', referenced_workflows: [central()] })];
    const slept: number[] = [];
    const x = await go(FR(), f, { deps: { sleep: async (ms) => { slept.push(ms); } } });
    expect(x.code).toBe(0);
    expect(slept).toEqual([20_000, 20_000]);
  });
  it('fails closed on every error: no token, a missing event payload, another repository\'s payload, a client that throws', async () => {
    expect((await go(FR({ [GH_IN]: undefined }), centralWorld())).code).toBe(1);
    const noEvent = runner(FR(), { event: 'workflow_run', sha: SHA, payload: PAYLOAD() });
    delete noEvent.env.GITHUB_EVENT_PATH;
    const chunks: string[] = [];
    expect(await main({ env: noEvent.env, now: () => NOW, write: (t) => { chunks.push(t); }, github: (() => centralWorld() as unknown as GateGithubAdapter) as MainDeps['github'] })).toBe(1);
    const other = await go(FR(), centralWorld(), { payload: { repository: { ...(PAYLOAD() as { repository: Obj }).repository, full_name: 'evil/app', owner: { login: 'evil' } } } });
    expect(other.code).toBe(1);
    expect(other.f.calls).toEqual([]);
    const thrown = runner(FR(), { event: 'workflow_run', sha: SHA, payload: PAYLOAD() });
    const out: string[] = [];
    expect(await main({ env: thrown.env, now: () => NOW, write: (t) => { out.push(t); }, github: (() => { throw new Error('SECRET'); }) as MainDeps['github'] })).toBe(1);
    expect(out.join('')).not.toContain('SECRET');
    expect(outputsOf(thrown.output)).toEqual({ 'run-id': '', 'run-url': '' });
  });
  it('an input of another mode is refused under find-run (fp-key, jobs, block-from)', async () => {
    for (const extra of [{ 'fp-key': 'k'.repeat(40) }, { jobs: '{}' }, { 'block-from': 'x' }, { artifact: 'x' }]) {
      const x = await go(FR(extra), centralWorld());
      expect(x.code, JSON.stringify(extra)).toBe(1);
      expect(x.f.calls).toEqual([]);
    }
  });
  it('find-run never reads GITHUB_WORKSPACE', async () => {
    const r = runner(FR(), { event: 'workflow_run', sha: SHA, payload: PAYLOAD() });
    const read: string[] = [];
    const env = new Proxy(r.env, { get(t, k) { if (typeof k === 'string') read.push(k); return Reflect.get(t, k); } });
    await main({ env, now: () => NOW, write: () => undefined, github: (() => centralWorld() as unknown as GateGithubAdapter) as MainDeps['github'] });
    expect(read).not.toContain('GITHUB_WORKSPACE');
  });
});

// ---------- action.yml and RENDERER_INPUTS parity ----------

describe('action.yml and RENDERER_INPUTS cover find-run', () => {
  const ACTION = parse(readFileSync(join(ROOT, 'gate/action.yml'), 'utf8')) as { inputs: Record<string, { description: string }>; outputs: Record<string, { description: string }> };
  const ROW = RENDERER_INPUTS[PIPEGEN_GATE_USES] as NonNullable<(typeof RENDERER_INPUTS)[string]>;
  const FIND_RUN = ['mode', 'sha', 'central-workflow', 'central-sha', 'timeout-minutes', GH_IN];
  it('the find-run inputs are exactly sha, central-workflow, central-sha, timeout-minutes and github-token (plus mode), in the row, in MODE_INPUTS and in action.yml', () => {
    expect([...MODE_INPUTS['find-run']].sort()).toEqual([...FIND_RUN].sort());
    for (const n of FIND_RUN) {
      expect(Object.keys(ROW), n).toContain(n);
      expect(Object.keys(ACTION.inputs), n).toContain(n);
    }
    for (const n of ['sha', 'central-workflow', 'central-sha', 'timeout-minutes']) {
      expect(ACTION.inputs[n]?.description, n).toMatch(/^find-run:/);
      expect(Object.hasOwn(ACTION.inputs[n] as object, 'default'), n).toBe(false);
      for (const m of GATE_MODES) expect(ROW[n]?.whenWith?.check({ mode: m }) ?? true, `${n} in ${m}`).toBe(m === 'find-run');
    }
    expect(Object.keys(ACTION.inputs).sort()).toEqual(Object.keys(ROW).sort());
  });
  it('the timeout-minutes row accepts 1 to 360 as plain digits and nothing else', () => {
    const p = (v: string): string[] => rendererInputProblems(PIPEGEN_GATE_USES, { mode: 'find-run', 'timeout-minutes': v });
    for (const good of ['1', '30', '99', '100', '359', '360']) expect(p(good), good).toEqual([]);
    for (const bad of ['0', '361', '400', '030', '-1', '1.5', '', '${{ github.run_id }}', '30 ', 'x']) expect(p(bad).length, bad).toBeGreaterThan(0);
    expect(rendererInputProblems(PIPEGEN_GATE_USES, { mode: 'gate', 'timeout-minutes': '30' }).some((x) => /timeout-minutes/.test(x))).toBe(true);
  });
  it('outputs run-id and run-url are declared and say they are find-run\'s', () => {
    for (const n of ['run-id', 'run-url']) expect(ACTION.outputs[n]?.description, n).toMatch(/^find-run:/);
  });
});

// ---------- the bundle ----------

describe('the bundle runs find-run end to end on a fixture world', () => {
  const BUNDLE = join(ROOT, 'gate/dist/index.js');
  const PRELOAD = join(ROOT, 'test/helpers/fake-github-preload.mjs');
  function runNode(env: Record<string, string>): Promise<{ code: number | null; stdout: string }> {
    return new Promise((done) => {
      const child = spawn(process.execPath, ['--import', PRELOAD, BUNDLE], { env: { PATH: process.env.PATH ?? '', ...env }, cwd: tmpdir() });
      let stdout = '';
      child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      child.stderr.on('data', (d: Buffer) => { stdout += d.toString(); });
      child.on('close', (code) => { done({ code, stdout }); });
    });
  }
  const table = (jobs: unknown[], over: Obj = {}): string => {
    const file = join(mkdtempSync(join(tmpdir(), 'pipegen-c8-')), 'fake-gh.json');
    const R = '/repos/acme/app';
    writeFileSync(file, JSON.stringify({
      routes: {
        [`${R}/git/ref/heads/main`]: { ref: 'refs/heads/main', object: { type: 'commit', sha: TIP } },
        [`${R}/compare/${SHA}...${TIP}`]: { status: 'ahead' },
        [`${R}/actions/runs/1001/attempts/1/jobs?per_page=100&page=1`]: { total_count: jobs.length, jobs },
      },
      zips: {}, runs: { 1: { total_count: 1, workflow_runs: [run({ referenced_workflows: [central()], ...over })] } },
    }));
    return file;
  };
  it('a trusted run with a good gate: exit 0, run-id and run-url', async () => {
    const r = runner(FR(), { event: 'workflow_run', sha: SHA, payload: PAYLOAD() });
    const x = await runNode({ ...r.env, PIPEGEN_FAKE_GH: table([job()]) });
    expect(x.stdout).not.toMatch(/::error::/);
    expect(x.code).toBe(0);
    expect(outputsOf(r.output)).toEqual({ 'run-id': '1001', 'run-url': 'https://github.com/acme/app/actions/runs/1001' });
  });
  it('a failed gate, two gate jobs, and a wrong central sha: exit 1', async () => {
    for (const [jobs, over] of [[[job({ conclusion: 'failure' })], {}], [[job(), job({ id: 2 })], {}], [[job()], { referenced_workflows: [central({ sha: 'd'.repeat(40) })] }]] as const) {
      const r = runner(FR(), { event: 'workflow_run', sha: SHA, payload: PAYLOAD() });
      const x = await runNode({ ...r.env, PIPEGEN_FAKE_GH: table([...jobs], { ...over }) });
      expect(x.code).toBe(1);
      expect(x.stdout).toMatch(/::error::/);
      expect(outputsOf(r.output)['run-id']).toBe('');
    }
  });
});
