// E5: userMainStatuses (the compat baseline), the gate result reader, and source scans that keep evaluate.ts to its brief.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { makeOctokit } from '../src/github/client.js';
import { cleanLog, jobNameMatches, userMainStatuses } from '../src/proof/evaluate.js';
import { parseGateResult } from '../src/proof/gate-result.js';
import { fakeFetch, type Routes } from './helpers/fake-http.js';
import { profile } from './helpers/render.js';
import { fake } from './helpers/secret-repo.js';
const SU = ['secrets', 'Used'].join('');

const API = 'https://api.github.com';
const prof = (paths: string[]) => ({ ...profile(), owner: 'CrisWorking', repo: 'shop', existingWorkflows: paths.map((path) => ({ path, triggers: ['push'], deploys: false, [SU]: [], jobs: [] }) as never) });
const client = (routes: Routes) => { const f = fakeFetch(routes); return { gh: makeOctokit(fake.githubPat(), { fetch: f.fetch, log: () => {} }), calls: f.calls }; };
const run = (path: string, conclusion: string | null, at: string, branch = 'main') => ({ id: 1, path, head_branch: branch, conclusion, created_at: at, status: 'completed' });

describe('userMainStatuses', () => {
  it('the last default-branch run of each workflow: success, failure, or none', async () => {
    const { gh, calls } = client({ [`GET ${API}/repos/CrisWorking/shop/actions/runs`]: { body: { total_count: 6, workflow_runs: [
      run('.github/workflows/ci.yml', 'failure', '2026-11-01T10:00:00Z'),
      run('.github/workflows/ci.yml', 'success', '2026-10-30T10:00:00Z'),          // older: ignored
      run('.github/workflows/lint.yml', 'success', '2026-11-01T09:00:00Z'),
      run('.github/workflows/cancelled.yml', 'cancelled', '2026-11-01T09:00:00Z'),
      run('.github/workflows/other-branch.yml', 'success', '2026-11-01T09:00:00Z', 'feature'),
      run('.github/workflows/gone.yml', 'success', '2026-11-01T09:00:00Z'),        // not an existing workflow of the profile
    ] } } });
    const m = await userMainStatuses(gh, prof(['.github/workflows/ci.yml', '.github/workflows/lint.yml', '.github/workflows/cancelled.yml', '.github/workflows/other-branch.yml', '.github/workflows/never.yml']));
    expect([...m]).toEqual([
      ['.github/workflows/ci.yml', 'failure'], ['.github/workflows/lint.yml', 'success'], ['.github/workflows/cancelled.yml', 'none'],
      ['.github/workflows/other-branch.yml', 'none'], ['.github/workflows/never.yml', 'none'],
    ]);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url.searchParams.get('branch')).toBe('main');
    expect(calls[0]?.url.searchParams.get('status')).toBe('completed');
  });

  it('unreadable answers are none, never success; a workflow path with a ref suffix is matched', async () => {
    const m1 = await userMainStatuses(client({ [`GET ${API}/repos/CrisWorking/shop/actions/runs`]: { status: 500, body: {} } }).gh, prof(['.github/workflows/ci.yml']));
    expect(m1.get('.github/workflows/ci.yml')).toBe('none');
    const m2 = await userMainStatuses(client({ [`GET ${API}/repos/CrisWorking/shop/actions/runs`]: { body: { workflow_runs: 'x' } } }).gh, prof(['.github/workflows/ci.yml']));
    expect(m2.get('.github/workflows/ci.yml')).toBe('none');
    const m3 = await userMainStatuses(client({ [`GET ${API}/repos/CrisWorking/shop/actions/runs`]: { body: { workflow_runs: [run('.github/workflows/ci.yml@refs/heads/main', 'timed_out', '2026-11-01T10:00:00Z')] } } }).gh, prof(['.github/workflows/ci.yml']));
    expect(m3.get('.github/workflows/ci.yml')).toBe('failure');
    // no workflows: no call at all
    const c = client({});
    expect((await userMainStatuses(c.gh, prof([]))).size).toBe(0);
    expect(c.calls).toHaveLength(0);
  });
});

describe('jobNameMatches and cleanLog', () => {
  it('matches the id, a matrix suffix and a called workflow prefix, and nothing longer', () => {
    expect(jobNameMatches('test', 'test')).toBe(true);
    expect(jobNameMatches('test (20)', 'test')).toBe(true);
    expect(jobNameMatches('test (node 20, linux)', 'test')).toBe(true);
    expect(jobNameMatches('pipegen / test (20)', 'test')).toBe(true);
    expect(jobNameMatches('a / b / test', 'test')).toBe(true);
    for (const n of ['tests', 'test-api', 'test(20)', 'test (20', 'my test', 'test20', '', 'unit-test']) expect(jobNameMatches(n, 'test'), n).toBe(false);
    expect(jobNameMatches('test', '')).toBe(false);
  });
  it('cleanLog removes GitHub timestamps, a BOM, CR and ANSI, and keeps the text', () => {
    expect(cleanLog('2026-11-03T10:00:00.1234567Z \u001b[1mAll files\u001b[22m |  83\r\n\ufeff2026-11-03T10:00:01Z next')).toBe('All files |  83\nnext');
  });
});

describe('parseGateResult', () => {
  const doc = (over: Record<string, unknown> = {}) => Buffer.from(JSON.stringify({
    pipegenGateResult: 1, result: 'pass', pass: true, event: 'pull_request', runId: 7, blockReasons: [], warnReasons: [], blocking: [], warnings: [], toolErrors: [], failedJobs: [], notRun: [], checks: [], notes: [], ...over,
  }));
  const from = { runId: 7, event: 'pull_request' };
  it('reads a good report and refuses every malformed one', () => {
    expect(parseGateResult(doc(), from).ok).toBe(true);
    const bad: Record<string, unknown>[] = [
      { pipegenGateResult: 2 }, { result: 'maybe' }, { pass: 'yes' }, { result: 'block' }, { runId: 8 }, { event: 'push' }, { blocking: 'x' }, { blocking: [null] }, { blocking: [{ needId: 'a' }] },
      { blocking: [{ needId: 'a', job: 'b', tool: 't', ruleId: 'r', severity: 'bad' }] }, { toolErrors: [{ needId: 'a' }] }, { checks: [{}] }, { failedJobs: [1] }, { notes: [1] }, { blockReasons: [{}] },
      { blocking: Array.from({ length: 501 }, () => ({ needId: 'a', job: 'b', tool: 't', ruleId: 'r', severity: 'high' })) },
    ];
    for (const o of bad) expect(parseGateResult(doc(o), from).ok, JSON.stringify(o).slice(0, 60)).toBe(false);
    expect(parseGateResult(Buffer.from('[]'), from).ok).toBe(false);
    expect(parseGateResult(Buffer.from([0xff, 0xfe]), from).ok).toBe(false);
    expect(parseGateResult(doc({ result: 'block', pass: false }), from).ok).toBe(true);
  });
});

describe('evaluate.ts stays inside its brief', () => {
  const src = readFileSync(new URL('../src/proof/evaluate.ts', import.meta.url), 'utf8');
  it('never builds an AI excerpt (that is E7, with the evidence brand) and never writes to GitHub', () => {
    expect(src).not.toMatch(/from '\.\/excerpt\.js'|errorExcerpt|unscannedExcerpt|ExcerptEvidence/);
    expect(src).not.toMatch(/guardedWrite|gh\.request\(|\.rest\./);
    expect(src).not.toMatch(/isolatedTestJob/);
  });
});
