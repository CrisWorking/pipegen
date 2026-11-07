// v0.2 Plan E, E5 (Task 4; rulings S8-S11, S23, E5-R1): evaluate() turns finished proof runs into one verdict per part. A false
// "proven" ships a pipeline pipegen never showed working, so anything unreadable, missing or ambiguous is never a pass.
import { describe, expect, it, vi } from 'vitest';
import { parseJunit } from '../src/create/junit.js';
import { evaluate, evaluateProof, type EvalContext, type VariantRuns } from '../src/proof/evaluate.js';
import type { PartResult, ProofResult } from '../src/types.js';
import {
  c1b, COMPAT_PREFIX, ctxOf, draftOf, file, gateDoc, gateFinding, GATE_RESULT_ARTIFACT, greenMain, HARNESS_PATH, harnessJob, job, matchPlanted, MERGE, needOf, PIPEGEN, plantedRuns,
  PLANTED_ITEMS, resultArtifactName, run, spec,
} from './helpers/proof-eval.js';
// names spelled at run time (see test/no-secret-literals.test.ts)
const MS = ['missing', 'Sec', 'rets'].join('');
const FLAG = ['sec', 'ret'].join('');

const part = (r: ProofResult, p: PartResult['part']): PartResult | undefined => r.parts.find((x) => x.part === p && x.needId === undefined);
const need = (r: ProofResult, p: PartResult['part'], id: string): PartResult | undefined => r.parts.find((x) => x.part === p && x.needId === id);
const statuses = (r: ProofResult): Record<string, string> => Object.fromEntries(r.parts.filter((x) => x.needId === undefined).map((x) => [x.part, x.status]));
const D = (): ReturnType<typeof draftOf> => draftOf();
const both = (d = D(), main: VariantRuns = greenMain(d), planted: VariantRuns = plantedRuns(d)): VariantRuns[] => [main, planted];
const prRun = (main: VariantRuns) => main.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'pull_request') as VariantRuns['outcomes'][number];
const harnessPr = (main: VariantRuns) => main.outcomes.find((o) => o.handle.workflow === HARNESS_PATH && o.handle.event === 'pull_request') as VariantRuns['outcomes'][number];
const harnessMerge = (main: VariantRuns) => main.outcomes.find((o) => o.handle.workflow === HARNESS_PATH && o.handle.event === 'push') as VariantRuns['outcomes'][number];
const mergeRun = (main: VariantRuns) => main.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'push' && o.handle.headSha === MERGE) as VariantRuns['outcomes'][number];
const setConclusion = (o: VariantRuns['outcomes'][number], name: string, conclusion: string | null, log?: string): void => {
  const j = o.jobs.find((x) => x.name === name);
  if (j === undefined) throw new Error(`no job ${name}`);
  j.conclusion = conclusion;
  j.status = conclusion === null ? 'in_progress' : 'completed';
  if (log !== undefined) j.log = log;
};
const setGate = (o: VariantRuns['outcomes'][number], d: ReturnType<typeof draftOf>, opts: Omit<Parameters<typeof gateDoc>[0], 'runId'>): void => { o.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ ...opts, runId: o.handle.runId }, d)); };
const xml = (cases: [string, 'pass' | 'fail' | 'skip'][]): string =>
  `<testsuites><testsuite name="s">${cases.map(([n, s]) => `<testcase classname="a.test.ts" name="${n}">${s === 'fail' ? '<failure message="x"/>' : s === 'skip' ? '<skipped/>' : ''}</testcase>`).join('')}</testsuite></testsuites>`;
const readJunit: NonNullable<EvalContext['readJunit']> = async (bytes) => { try { return { ok: true, cases: parseJunit(Buffer.from(bytes).toString('utf8')) }; } catch (e) { return { ok: false, reason: `report unreadable: ${(e as Error).message}` }; } };

describe('evaluate', () => {
  it('evaluate: all green → ok and every part proven', async () => {
    const r = await evaluate(D(), both(), ctxOf());
    expect(statuses(r)).toEqual({ pipeline: 'proven', tests: 'proven', docker: 'proven', compose: 'proven', precommit: 'proven', 'deploy-verify': 'proven' });
    expect(r.parts.filter((p) => p.status !== 'proven')).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.runUrls.length).toBeGreaterThan(3);
    expect(new Set(r.runUrls).size).toBe(r.runUrls.length);
  });

  it('evaluate: sarif missing for blocking need → pipeline failed with need id', async () => {
    const d = D();
    const main = greenMain(d);
    prRun(main).artifacts.delete(resultArtifactName('sast', 'api'));
    const r = await evaluate(d, both(d, main), ctxOf());
    expect(need(r, 'pipeline', 'sast')).toMatchObject({ status: 'failed' });
    expect(need(r, 'pipeline', 'sast')?.detail).toMatch(/sast/);
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(r.ok).toBe(false);
    // an artifact that could not be read is "report unreadable", with the reason
    const main2 = greenMain(d);
    const o = prRun(main2);
    o.artifacts.delete(resultArtifactName('deps', 'api'));
    o.artifactProblems.set(resultArtifactName('deps', 'api'), 'the artifact is larger than the cap');
    const r2 = await evaluate(d, both(d, main2), ctxOf());
    expect(need(r2, 'pipeline', 'deps')?.detail).toMatch(/report unreadable.*larger than the cap/);
  });

  it('evaluate: app-start fails with missing STRIPE key → compose not-proven', async () => {
    const d = draftOf({ notProven: [{ part: 'compose', [MS]: ['STRIPE_SECRET_KEY'], reason: 'no stripe key' }] });
    const main = greenMain(d);
    setConclusion(harnessPr(main), 'pipegen proof: app-start', 'failure', 'api-1  | Error: STRIPE_SECRET_KEY is not set\napi-1 exited with code 1');
    harnessPr(main).conclusion = 'failure';
    const r = await evaluate(d, both(d, main), ctxOf());
    expect(part(r, 'compose')).toMatchObject({ status: 'not-proven' });
    expect(part(r, 'compose')?.detail).toMatch(/STRIPE_SECRET_KEY/);
    // the same failure without the name in the draft's missing secrets is a real failure
    const r2 = await evaluate(draftOf(), both(draftOf(), main), ctxOf());
    expect(part(r2, 'compose')?.status).toBe('failed');
    // a name that only contains the missing one (a longer name) does not count
    const main3 = greenMain(d);
    setConclusion(harnessPr(main3), 'pipegen proof: app-start', 'failure', 'XSTRIPE_SECRET_KEY_2 is not set');
    expect(part(await evaluate(d, both(d, main3), ctxOf()), 'compose')?.status).toBe('failed');
  });

  it('evaluate: planted item missed → pipeline failed naming tool and item', async () => {
    const d = D();
    const r = await evaluate(d, both(d, greenMain(d), plantedRuns(d, { skip: (f) => f.file === 'pipegen-planted/sast.js' })), ctxOf());
    const n = need(r, 'pipeline', 'sast');
    expect(n?.status).toBe('failed');
    expect(n?.detail).toContain("semgrep didn't catch the planted eval of user input");
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(r.ok).toBe(false);
  });

  it('evaluate: gate passes on the planted PR → pipeline failed', async () => {
    const d = D();
    const planted = plantedRuns(d, { gateConclusion: 'success', result: 'pass' });
    const r = await evaluate(d, both(d, greenMain(d), planted), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toMatch(/gate didn't block planted problems/);
    // a gate that blocked but whose report says pass is a contradiction, not a block
    const odd = plantedRuns(d, { gateConclusion: 'failure', result: 'pass' });
    expect(part(await evaluate(d, both(d, greenMain(d), odd), ctxOf()), 'pipeline')?.status).toBe('failed');
    // no planted variant at all: the scanners are not shown to catch anything
    const none = await evaluate(d, [greenMain(d)], ctxOf());
    expect(part(none, 'pipeline')?.status).toBe('failed');
    expect(none.ok).toBe(false);
  });

  it('evaluate: created Dockerfile image with critical/high fixable CVE → docker failed', async () => {
    const d = draftOf({ created: [{ path: 'api/Dockerfile', content: 'FROM x', part: 'docker', reason: 'r', repo: 'app' }], choices: { 'ignore-unfixed': 'true' } });
    const main = greenMain(d);
    setGate(prRun(main), d, { result: 'warn', warnings: [gateFinding('image-scan', 'trivy', { severity: 'critical', job: 'image-scan--api', ruleId: 'CVE-2025-1', isNew: null })] });
    const r = await evaluate(d, both(d, main, plantedRuns(d)), ctxOf());
    expect(part(r, 'docker')?.status).toBe('failed');
    expect(part(r, 'docker')?.detail).toMatch(/the base image has critical\/high CVEs with a fixed version or no fix info/);   // E9 (E5-R3)
    expect(part(r, 'docker')?.detail).toContain('CVE-2025-1');
    // the same finding on an existing (not created) Dockerfile is not docker's to judge
    const existing = draftOf();
    const main2 = greenMain(existing);
    setGate(prRun(main2), existing, { result: 'warn', warnings: [gateFinding('image-scan', 'trivy', { severity: 'critical', job: 'image-scan--api' })] });
    expect(part(await evaluate(existing, both(existing, main2), ctxOf()), 'docker')?.status).toBe('proven');
    // medium and low do not count
    const main3 = greenMain(d);
    setGate(prRun(main3), d, { result: 'warn', warnings: [gateFinding('image-scan', 'trivy', { severity: 'medium', job: 'image-scan--api' })] });
    expect(part(await evaluate(d, both(d, main3), ctxOf()), 'docker')?.status).toBe('proven');
  });

  it('evaluate: created Dockerfile image findings read from the gate\'s warnings on the installing PR', async () => {
    const d = draftOf({ created: [{ path: 'api/Dockerfile', content: 'FROM x', part: 'docker', reason: 'r', repo: 'app' }] });
    // an installing PR: the gate passes and the findings are warnings only
    const main = greenMain(d);
    setGate(prRun(main), d, { result: 'warn', warnings: [gateFinding('image-scan', 'trivy', { severity: 'high', job: 'image-scan--api', ruleId: 'CVE-2025-2' })] });
    const r = await evaluate(d, both(d, main), ctxOf());
    expect(part(r, 'docker')?.status).toBe('failed');
    expect(part(r, 'docker')?.detail).toContain('CVE-2025-2');
    // the pipeline part is not failed by a warning
    expect(part(r, 'pipeline')?.status).toBe('proven');
    // an unreadable result.json: the findings are unknown, so docker is not proven for a created Dockerfile
    const main2 = greenMain(d);
    prRun(main2).artifacts.set(GATE_RESULT_ARTIFACT, file(GATE_RESULT_ARTIFACT, 'result.json', '{'));
    const r2 = await evaluate(d, both(d, main2), ctxOf());
    expect(part(r2, 'docker')?.status).not.toBe('proven');
  });

  it('evaluate: verify-lookup read from the merge-to-default push run', async () => {
    const d = D();
    const ok = await evaluate(d, both(d), ctxOf());
    expect(part(ok, 'deploy-verify')?.status).toBe('proven');
    // verify-lookup failed on the merge run, green elsewhere: failed
    const main = greenMain(d);
    setConclusion(harnessMerge(main), 'pipegen proof: verify-lookup', 'failure', 'find-run: no gated run found for this sha');
    harnessMerge(main).conclusion = 'failure';
    expect(part(await evaluate(d, both(d, main), ctxOf()), 'deploy-verify')?.status).toBe('failed');
    // a green verify-lookup on a PR run (or a run of another sha) is not the merge push run
    const main2 = greenMain(d);
    main2.outcomes = main2.outcomes.filter((o) => o !== harnessMerge(main2));
    setConclusion(harnessPr(main2), 'pipegen proof: verify-lookup', 'success');
    main2.outcomes.push(run({ workflow: HARNESS_PATH, event: 'push', sha: 'c'.repeat(40), jobs: [harnessJob('verify-lookup')] }));
    const r2 = await evaluate(d, both(d, main2), ctxOf());
    expect(part(r2, 'deploy-verify')?.status).toBe('failed');
    expect(part(r2, 'deploy-verify')?.detail).toMatch(/merge/);
    // never merged: failed, with the reason
    const main3 = greenMain(d);
    delete (main3 as { mergeSha?: string }).mergeSha;
    main3.notMerged = 'the PR layer failed';
    main3.outcomes = main3.outcomes.filter((o) => o.handle.headSha !== MERGE);
    const r3 = await evaluate(d, both(d, main3), ctxOf());
    expect(part(r3, 'deploy-verify')?.status).toBe('failed');
    expect(part(r3, 'pipeline')?.status).toBe('failed');
  });

  it('evaluate: floor need is never not-proven', async () => {
    const d = draftOf({ notProven: [{ part: 'tests', [MS]: ['DATABASE_URL'], reason: 'x' }] });
    const main = greenMain(d);
    setConclusion(prRun(main), 'unit-tests--api', 'failure', 'Error: DATABASE_URL is not set');
    prRun(main).conclusion = 'failure';
    const r = await evaluate(d, both(d, main), ctxOf({ keys: 'placeholder' }));
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(r.parts.some((p) => p.status === 'not-proven' && (p.part === 'tests' || p.needId === 'unit-tests'))).toBe(false);
    // a refused placeholder key is also a failure for a floor part
    const main2 = greenMain(d);
    setConclusion(prRun(main2), 'unit-tests--api', 'failure', 'HTTP 401 Unauthorized: invalid api key');
    expect(part(await evaluate(d, both(d, main2), ctxOf({ keys: 'placeholder' })), 'tests')?.status).toBe('failed');
    // the same signatures on a part that covers no floor need (compose) are not-proven
    const main3 = greenMain(d);
    setConclusion(harnessPr(main3), 'pipegen proof: app-start', 'failure', 'HTTP 401 Unauthorized: invalid api key');
    expect(part(await evaluate(d, both(d, main3), ctxOf({ keys: 'placeholder' })), 'compose')?.status).toBe('not-proven');
    // the pipeline part covers the floor needs: a failed scanner job with a missing secret name is failed
    const main4 = greenMain(d);
    setConclusion(prRun(main4), 'sast--api', 'failure', 'DATABASE_URL is not set');
    const r4 = await evaluate(d, both(d, main4), ctxOf());
    expect(part(r4, 'pipeline')?.status).toBe('failed');
    expect(need(r4, 'pipeline', 'sast')?.status).toBe('failed');
  });

  it('evaluate: placeholder key refused by external host → not-proven "needs your real test key"', async () => {
    const d = D();
    const refused = 'api-1  | Error: Request failed with status code 401\napi-1  | {"error":{"message":"Invalid API Key provided"}}';
    const make = (): VariantRuns => { const m = greenMain(d); setConclusion(harnessPr(m), 'pipegen proof: app-start', 'failure', refused); return m; };
    for (const keys of ['placeholder', 'none'] as const) {
      const r = await evaluate(d, both(d, make()), ctxOf({ keys }));
      expect(part(r, 'compose')).toMatchObject({ status: 'not-proven' });
      expect(part(r, 'compose')?.detail).toContain('needs your real test key');
    }
    // with the user's real keys stored, a refusal is a real failure
    expect(part(await evaluate(d, both(d, make()), ctxOf({ keys: 'real' })), 'compose')?.status).toBe('failed');
    // a connection error to an external host is not-proven; one to a compose service name or loopback is a failure
    const ext = greenMain(d);
    setConclusion(harnessPr(ext), 'pipegen proof: app-start', 'failure', 'Error: getaddrinfo ENOTFOUND api.stripe.com');
    const re = await evaluate(d, both(d, ext), ctxOf());
    expect(part(re, 'compose')?.status).toBe('not-proven');
    expect(part(re, 'compose')?.detail).toContain('api.stripe.com');
    for (const text of ['Error: connect ECONNREFUSED 127.0.0.1:5432', 'Error: getaddrinfo ENOTFOUND db', 'Error: getaddrinfo ENOTFOUND registry.npmjs.org']) {
      const m = greenMain(d);
      setConclusion(harnessPr(m), 'pipegen proof: app-start', 'failure', text);
      expect(part(await evaluate(d, both(d, m), ctxOf()), 'compose')?.status, text).toBe('failed');
    }
  });
});

describe('compat', () => {
  const compat = (conclusion: string, log?: string, wf = 'ci.yml'): VariantRuns['outcomes'][number] =>
    run({ workflow: `${COMPAT_PREFIX}${wf}`, event: 'pull_request', conclusion: conclusion === 'success' ? 'success' : 'failure', jobs: [job('build', conclusion, log === undefined ? {} : { log })] });
  const withCompat = (o: VariantRuns['outcomes'][number], d = D()): VariantRuns[] => { const m = greenMain(d); m.outcomes.push(o); return both(d, m); };

  it('compat: failing before and after → not pipegen\'s fault', async () => {
    const r = await evaluate(D(), withCompat(compat('failure', 'tests failed')), ctxOf({ userMain: new Map([['.github/workflows/ci.yml', 'failure']]) }));
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(part(r, 'pipeline')?.detail).toMatch(/ci\.yml.*failed on your main too/);
    expect(r.ok).toBe(true);
  });

  it('compat: success before, failure after → pipeline failed naming workflow', async () => {
    const r = await evaluate(D(), withCompat(compat('failure', 'tests failed')), ctxOf({ userMain: new Map([['.github/workflows/ci.yml', 'success']]) }));
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toContain('pipegen broke .github/workflows/ci.yml');
    expect(r.ok).toBe(false);
    // a green copy next to a green main is fine
    expect(part(await evaluate(D(), withCompat(compat('success')), ctxOf({ userMain: new Map([['.github/workflows/ci.yml', 'success']]) })), 'pipeline')?.status).toBe('proven');
    // no run of the user's main to compare with: never a pass for that workflow, and never a fault pipegen can fix
    for (const userMain of [new Map([['.github/workflows/ci.yml', 'none' as const]]), new Map()]) {
      const r2 = await evaluate(D(), withCompat(compat('failure', 'x')), ctxOf({ userMain }));
      const n = r2.parts.find((p) => p.status === 'not-proven' && /ci\.yml/.test(p.detail));
      expect(n, 'a not-proven note for the workflow').toBeDefined();
      expect(r2.parts.some((p) => p.status === 'failed')).toBe(false);
    }
  });

  it('compat: an empty secret is ignored with a note', async () => {
    for (const log of ['Error: Input required and not supplied: token', 'the secret API_KEY is empty', 'secret FOO not set']) {
      const r = await evaluate(D(), withCompat(compat('failure', log)), ctxOf({ userMain: new Map([['.github/workflows/ci.yml', 'success']]) }));
      expect(part(r, 'pipeline')?.status, log).toBe('proven');
      expect(part(r, 'pipeline')?.detail).toMatch(/ci\.yml.*secret/);
    }
    // a different failure on the same copy is not ignored
    const r2 = await evaluate(D(), withCompat(compat('failure', 'Error: 3 tests failed')), ctxOf({ userMain: new Map([['.github/workflows/ci.yml', 'success']]) }));
    expect(part(r2, 'pipeline')?.status).toBe('failed');
  });

  it('compat: dropped jobs listed as not compared', async () => {
    const notCompared = [{ workflow: '.github/workflows/deploy.yml', job: 'release', why: 'it uses a secret' }];
    const r = await evaluate(D(), both(), ctxOf({ notCompared }));
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(part(r, 'pipeline')?.detail).toContain('not compared: .github/workflows/deploy.yml/release (it uses a secret)');
    expect(r.parts.filter((p) => p.status === 'failed')).toEqual([]);
  });

  it('compat: a copy that never ran is a note, not a pass of that workflow and not a failure', async () => {
    const m = greenMain();
    m.missing = [{ event: 'pull_request', workflow: `${COMPAT_PREFIX}ci.yml` }];
    const r = await evaluate(D(), both(D(), m), ctxOf());
    expect(part(r, 'pipeline')?.detail).toMatch(/ci\.yml.*did not run/);
    expect(part(r, 'pipeline')?.status).toBe('proven');
  });
});

describe('evaluate: pipeline from the gate job and result.json', () => {
  it('evaluate: pipeline read from the gate job conclusion with result.json as report', async () => {
    const d = D();
    // gate job red, report says pass: the job decides
    const a = greenMain(d);
    setConclusion(prRun(a), 'gate', 'failure');
    prRun(a).conclusion = 'failure';
    const ra = await evaluate(d, both(d, a), ctxOf());
    expect(part(ra, 'pipeline')?.status).toBe('failed');
    // gate job green, report says block: contradiction, not a pass
    const b = greenMain(d);
    setGate(prRun(b), d, { result: 'block', blocking: [gateFinding('sast', 'semgrep', { file: 'a.js' })] });
    const rb = await evaluate(d, both(d, b), ctxOf());
    expect(part(rb, 'pipeline')?.status).toBe('failed');
    // gate job green, report missing / unreadable / of another run or event: report unreadable
    for (const [label, make] of [
      ['missing', (m: VariantRuns) => prRun(m).artifacts.delete(GATE_RESULT_ARTIFACT)],
      ['problem', (m: VariantRuns) => { prRun(m).artifacts.delete(GATE_RESULT_ARTIFACT); prRun(m).artifactProblems.set(GATE_RESULT_ARTIFACT, 'the zip has two entries'); }],
      ['garbage', (m: VariantRuns) => prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, file(GATE_RESULT_ARTIFACT, 'result.json', 'not json'))],
      ['other run', (m: VariantRuns) => prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: 424242 }, d))],
      ['other event', (m: VariantRuns) => prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(m).handle.runId, event: 'push' }, d))],
      ['wrong file name', (m: VariantRuns) => prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, file(GATE_RESULT_ARTIFACT, 'other.json', '{}'))],
      ['inconsistent flags', (m: VariantRuns) => prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(m).handle.runId, result: 'block', pass: true }, d))],
    ] as const) {
      const m = greenMain(d);
      make(m);
      const r = await evaluate(d, both(d, m), ctxOf());
      expect(part(r, 'pipeline')?.status, label).toBe('failed');
      expect(part(r, 'pipeline')?.detail, label).toMatch(/report unreadable/);
      expect(r.ok, label).toBe(false);
    }
    // no gate job in any PR run: failed
    const c = greenMain(d);
    prRun(c).jobs = prRun(c).jobs.filter((j) => j.name !== 'gate');
    expect(part(await evaluate(d, both(d, c), ctxOf()), 'pipeline')?.status).toBe('failed');
    // the gate named as a called workflow's job ("caller / gate") is the gate
    const e = greenMain(d);
    prRun(e).jobs.find((j) => j.name === 'gate')!.name = 'pipegen / gate';
    expect(part(await evaluate(d, both(d, e), ctxOf()), 'pipeline')?.status).toBe('proven');
    // blocking findings in a gate that passed are a contradiction
    const f = greenMain(d);
    setGate(prRun(f), d, { result: 'pass', blocking: [gateFinding('sast', 'semgrep')] });
    expect(part(await evaluate(d, both(d, f), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('every pipegen job must have finished green in every layer (push, pull request, merge)', async () => {
    const d = D();
    for (const conclusion of ['failure', 'cancelled', 'timed_out', 'startup_failure', 'action_required', null, 'weird'] as const) {
      for (const pick of [prRun, mergeRun, (m: VariantRuns) => m.outcomes[0] as VariantRuns['outcomes'][number]]) {
        const m = greenMain(d);
        const o = pick(m);
        o.jobs[0]!.conclusion = conclusion;
        o.jobs[0]!.status = conclusion === null ? 'in_progress' : 'completed';
        const r = await evaluate(d, both(d, m), ctxOf());
        expect(part(r, 'pipeline')?.status, `${String(conclusion)}`).toBe('failed');
      }
    }
    // a run that failed without a failed job (startup_failure) is failed too
    const m = greenMain(d);
    mergeRun(m).conclusion = 'startup_failure';
    mergeRun(m).note = 'a workflow could not start';
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toContain('a workflow could not start');
    // a stopped proof and a workflow that never started are failed
    const s = greenMain(d);
    prRun(s).stopped = true;
    expect(part(await evaluate(d, both(d, s), ctxOf()), 'pipeline')?.status).toBe('failed');
    const t = greenMain(d);
    t.missing = [{ event: 'pull_request', workflow: PIPEGEN }];
    expect(part(await evaluate(d, both(d, t), ctxOf()), 'pipeline')?.status).toBe('failed');
    // skipped jobs are normal (event-conditional jobs)
    const u = greenMain(d);
    u.outcomes[0]!.jobs.push(job('deploy-verify', 'skipped'));
    expect(part(await evaluate(d, both(d, u), ctxOf()), 'pipeline')?.status).toBe('proven');
    // a failed run with no pipegen run in a layer: the PR layer is required
    const w = greenMain(d);
    w.outcomes = w.outcomes.filter((o) => o !== prRun(w));
    expect(part(await evaluate(d, both(d, w), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('a harness egress-check that failed means the egress control failed open: pipeline failed', async () => {
    const d = D();
    const m = greenMain(d);
    setConclusion(harnessPr(m), 'pipegen proof: egress-check', 'failure', 'the request to example.com succeeded');
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toMatch(/egress/);
    // the check must have run
    const m2 = greenMain(d);
    harnessPr(m2).jobs = harnessPr(m2).jobs.filter((j) => !/egress-check/.test(j.name));
    expect(part(await evaluate(d, both(d, m2), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('matrix and called-workflow job names match their need: "test (20)", "pipegen / sast--api (a, b)"', async () => {
    const d = D();
    const m = greenMain(d);
    const o = prRun(m);
    o.jobs.find((j) => j.name === 'sast--api')!.name = 'pipegen / sast--api (node 20, linux)';
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.status).toBe('proven');
    // a failing matrix entry fails the need
    o.jobs.push(job('sast--api (node 22, linux)', 'failure'));
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    // a job whose name merely starts with the id is not the id
    const m2 = greenMain(d);
    prRun(m2).jobs.find((j) => j.name === 'sast--api')!.name = 'sast--api-extra';
    expect(part(await evaluate(d, both(d, m2), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('a blocking need the gate reports as a tool error, a failed job or not run is a failure naming it', async () => {
    const d = D();
    for (const opts of [
      { toolErrors: [{ needId: 'deps', job: 'deps--api', tool: 'osv-scanner', base: false, blocks: true, reason: 'sarif unreadable' }] },
      { failedJobs: [{ needId: 'deps', job: 'deps--api' }] },
      { notRun: [{ needId: 'deps', job: 'deps--api' }] },
      { checks: [{ needId: 'secrets', job: 'secrets', tool: 'gitleaks', judgedBy: 'findings', state: 'ok' }] },
    ]) {
      const m = greenMain(d);
      setGate(prRun(m), d, opts);
      const r = await evaluate(d, both(d, m), ctxOf());
      expect(part(r, 'pipeline')?.status, JSON.stringify(opts)).toBe('failed');
      expect(r.parts.some((p) => p.part === 'pipeline' && p.needId !== undefined && p.status === 'failed'), JSON.stringify(opts)).toBe(true);
    }
  });
});

describe('planted', () => {
  it('evaluate: planted C1b placements each in result.json blocking findings', async () => {
    const d = D();
    const ok = await evaluate(d, both(d), ctxOf());
    expect(part(ok, 'pipeline')?.status).toBe('proven');
    for (const gone of ['node_modules/x.js', 'go.sum']) {
      const r = await evaluate(d, both(d, greenMain(d), plantedRuns(d, { skip: (f) => f.file === gone })), ctxOf());
      const n = r.parts.find((p) => p.part === 'pipeline' && p.needId === 'secrets' && p.status === 'failed');
      expect(n?.detail, gone).toContain(gone);
      expect(n?.detail).toContain("gitleaks didn't catch the planted secret");
      expect(r.ok).toBe(false);
    }
    // a placement with a name that is not UTF-8 is matched on its readable part
    const r2 = await evaluate(d, both(d, greenMain(d), plantedRuns(d, { skip: (f) => (f.file ?? '').startsWith('pipegen-c1b/k') })), ctxOf());
    expect(r2.parts.find((p) => p.needId === 'secrets' && p.status === 'failed')).toBeDefined();
    // a finding that is not from the secrets check (another need at that file) does not count
    const d3 = D();
    const planted = plantedRuns(d3, { skip: (f) => f.file === 'go.sum' });
    const doc = planted.outcomes[0]!;
    setGate(doc, d3, { result: 'block', blocking: [gateFinding('sast', 'semgrep', { file: 'go.sum' }), gateFinding('sast', 'semgrep', { file: 'pipegen-planted/sast.js', job: 'sast--api' }), gateFinding('deps', 'osv-scanner', { file: 'pipegen-planted/package.json', job: 'deps--api' }),
      ...c1b().filter((p) => p.kind === 'secret' && p.path !== 'go.sum').map((p) => gateFinding('secrets', 'gitleaks', { file: p.path, [FLAG]: true }))] });
    const r3 = await evaluate(d3, both(d3, greenMain(d3), planted), ctxOf());
    expect(r3.parts.find((p) => p.needId === 'secrets' && p.status === 'failed')?.detail).toContain('go.sum');
    // the integrity warning for the .gitleaksignore is a note, never a failure
    expect(part(ok, 'pipeline')?.detail).toMatch(/\.gitleaksignore/);
  });

  it('planted: an unreadable or missing planted report is a failure, not a pass', async () => {
    const d = D();
    const r = await evaluate(d, both(d, greenMain(d), plantedRuns(d, { omitResult: true })), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toMatch(/report unreadable/);
    const stopped = plantedRuns(d);
    stopped.outcomes[0]!.stopped = true;
    expect(part(await evaluate(d, both(d, greenMain(d), stopped), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('planted: a blocking floor scanner with no planted item is failed, a non-floor one is not-proven', async () => {
    // name kept (Plan E); it now asserts (G0, F-3): floor sast/deps failed, a non-floor scanner a note that stays blocking
    const d = D();
    // no Plan F items at all: sast and deps (floor) are not shown to catch anything
    const r = await evaluate(d, both(d), ctxOf({ plantedItems: [] }));
    expect(need(r, 'pipeline', 'sast')?.status).toBe('failed');
    expect(need(r, 'pipeline', 'deps')?.status).toBe('failed');
    // a non-floor scanner (image-scan) without an item: Plan G G0 (F-3) a note in the pipeline's detail, it stays blocking, never
    // a not-proven need entry (draft.notProven)
    expect(need(r, 'pipeline', 'image-scan')).toBeUndefined();
    const shown = await evaluate(d, both(d), ctxOf({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan') }));
    expect(part(shown, 'pipeline')?.detail).toMatch(/image-scan--api \(trivy-image\) has no planted item, so it is not shown to catch anything; it stays blocking/);
    // items given but no matcher: ambiguous, failed
    const r2 = await evaluate(d, both(d), ctxOf({ matchPlanted: undefined }));
    expect(part(r2, 'pipeline')?.status).toBe('failed');
  });

  it('evaluate: DAST on ZAP not-proven (warn) until the -J fixture exists', async () => {
    // name kept (Plan E); it now asserts (G0-R1 I1, F-3): ZAP stays blocking, shown as a note, never warn-only or a not-proven need
    const d = draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('dast', { service: 'api' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec('zap-baseline', 'dast', 'api')],
    });
    const items = PLANTED_ITEMS.filter((i) => i.category !== 'image-scan');   // this draft has no image scan (G0-R1 m1)
    const r = await evaluate(d, both(d), ctxOf({ plantedItems: items }));
    expect(need(r, 'pipeline', 'dast')).toBeUndefined();
    expect(part(r, 'pipeline')?.detail).toMatch(/\(ZAP\) has no planted item[^;]*not shown to catch anything; the draft keeps it a blocking check/);
    expect(part(r, 'pipeline')?.detail).not.toMatch(/warn only/);
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(r.ok).toBe(true);
    // even with a planted dast item: ZAP is no scanner pipegen reads planted items from, so the item is missed, never a pass
    const withItem = await evaluate(d, both(d), ctxOf({ plantedItems: [...items, { id: 'dast-x', category: 'dast', item: 'x', file: 'pipegen-planted/dast.js', needKey: 'dast--api' }] }));
    expect(need(withItem, 'pipeline', 'dast')).toBeUndefined();
    expect(part(withItem, 'pipeline')?.status).toBe('failed');
  });

  it('evaluate: nuclei need without a planted item → not-proven note', async () => {
    // name kept (Plan E); it now asserts (G0, F-3): a note in the pipeline's detail, never a not-proven need entry
    const d = draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('dast', { service: 'api' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec('nuclei', 'dast', 'api')],
    });
    const r = await evaluate(d, both(d), ctxOf({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan') }));   // no image scan here (G0-R1 m1)
    // Plan G G0 (F-3): a note in the pipeline's detail (it stays blocking), never a not-proven need entry
    expect(need(r, 'pipeline', 'dast')).toBeUndefined();
    expect(part(r, 'pipeline')?.detail).toMatch(/nuclei.*no planted item/);
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(r.ok).toBe(true);
  });
});

describe('E5-R1: scanner mounts that Bullfrog refuses', () => {
  const MOUNT = 'docker: Error response from daemon: bullfrog: mounting the host path /home/runner/work/shop/shop is not allowed while sudo is disabled';
  const refuse = (m: VariantRuns, d: ReturnType<typeof draftOf>, jobName = 'sast--api'): void => {
    const o = prRun(m);
    setConclusion(o, jobName, 'failure', `##[group]Run docker run semgrep\n${MOUNT}\n##[error]Process completed with exit code 125.`);
    setConclusion(o, 'gate', 'failure');
    o.conclusion = 'failure';
    o.artifacts.delete(resultArtifactName('sast', 'api'));
    setGate(o, d, { result: 'block', failedJobs: [{ needId: 'sast', job: jobName }], blockReasons: [`required check semgrep (sast--api) did not succeed (failure)`] });
  };

  // E9 decision (rulings E5-R1/E5-R2 withdrawn): since gate-v0.2.2 pipegen's scanner steps copy their folders in (no bind mount, E3-R7),
  // and the proof workflow check refuses a mount before push. A refused mount on a scanner job is therefore a FAILED pipeline (a floor
  // need, spec §19), named as a tool error (the fix loop never asks the AI about it), never not-proven and never a pass.
  it('a scanner job that failed because Bullfrog refused a mount fails the pipeline as a tool error (E9: no longer not-proven pending gate-v0.2.2)', async () => {
    const d = D();
    const m = greenMain(d);
    refuse(m, d);
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(need(r, 'pipeline', 'sast')).toMatchObject({ status: 'failed' });
    expect(need(r, 'pipeline', 'sast')?.detail).toMatch(/tool error/);
    expect(need(r, 'pipeline', 'sast')?.detail).toMatch(/Bullfrog/);
    expect(need(r, 'pipeline', 'sast')?.detail).not.toMatch(/pending/);
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(r.parts.some((p) => p.status === 'not-proven' && p.part === 'pipeline')).toBe(false);
    expect(r.ok).toBe(false);
  });

  it('classified by its signature: the exact daemon line, on a failed scanner job, in a log', async () => {
    const d = D();
    // the same text on a green job, or without the daemon prefix, is not the signature
    for (const log of ['bullfrog: mounting the host path /x is not allowed while sudo is disabled', 'Error: something else failed', MOUNT.replace('is not allowed', 'is allowed')]) {
      const m = greenMain(d);
      refuse(m, d);
      setConclusion(prRun(m), 'sast--api', 'failure', log);
      const r = await evaluate(d, both(d, m), ctxOf());
      expect(need(r, 'pipeline', 'sast')?.status, log).toBe('failed');
    }
    // on a job that is not a scanner (unit-tests) it is a plain failure
    const m2 = greenMain(d);
    setConclusion(prRun(m2), 'unit-tests--api', 'failure', MOUNT);
    const r2 = await evaluate(d, both(d, m2), ctxOf());
    expect(part(r2, 'tests')?.status).toBe('failed');
    expect(r2.parts.some((p) => p.status === 'not-proven')).toBe(false);
    // the same on a scanner job that is not in the pull request's layer of the gate list is still its own failure
    const m3 = greenMain(d);
    setConclusion(prRun(m3), 'sast--api', 'failure', 'Error response from daemon: mounting the host path /x is not allowed while sudo is disabled');
    expect(part(await evaluate(d, both(d, m3), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('a second, real failure next to the refused mount is still failed', async () => {
    const d = D();
    const m = greenMain(d);
    refuse(m, d);
    setConclusion(prRun(m), 'deps--api', 'failure', 'osv-scanner: 3 vulnerabilities found');
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(need(r, 'pipeline', 'deps')?.status).toBe('failed');
    expect(need(r, 'pipeline', 'sast')?.status).toBe('failed');   // E9: a refused mount fails too (no longer not-proven)
    // a gate block with a reason that does not come from the refused job is a real block
    const m2 = greenMain(d);
    refuse(m2, d);
    setGate(prRun(m2), d, { result: 'block', failedJobs: [{ needId: 'sast', job: 'sast--api' }], blockReasons: ['the protected file .github/workflows/x.yml changed'] });
    expect(part(await evaluate(d, both(d, m2), ctxOf()), 'pipeline')?.status).toBe('failed');
    // blocking findings from another scanner on the main PR are real
    const m3 = greenMain(d);
    refuse(m3, d);
    setGate(prRun(m3), d, { result: 'block', blocking: [gateFinding('secrets', 'gitleaks', { file: 'a.js', [FLAG]: true })], failedJobs: [{ needId: 'sast', job: 'sast--api' }], blockReasons: ['required check semgrep (sast--api) did not succeed (failure)'] });
    expect(part(await evaluate(d, both(d, m3), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('the planted run: a refused scanner fails as a tool error (E9), not as "didn\'t catch"', async () => {
    const d = D();
    const planted = plantedRuns(d, { skip: (f) => f.file === 'pipegen-planted/sast.js' });
    setConclusion(planted.outcomes[0]!, 'sast--api', 'failure', MOUNT);
    const r = await evaluate(d, both(d, greenMain(d), planted), ctxOf());
    expect(need(r, 'pipeline', 'sast')?.status).toBe('failed');
    expect(need(r, 'pipeline', 'sast')?.detail).toMatch(/tool error: .*Bullfrog/);
    expect(r.parts.filter((p) => p.status === 'failed').every((p) => /Bullfrog/.test(p.detail ?? ''))).toBe(true);
    expect(r.ok).toBe(false);
  });
});

describe('tests', () => {
  const created = [{ service: 'api', staticCount: 2 }];
  const dT = (): ReturnType<typeof draftOf> => draftOf();
  const withJunit = (first: string | null, repeat: string | null, d = dT()): VariantRuns => {
    const m = greenMain(d);
    if (first !== null) prRun(m).artifacts.set('pipegen-out-junit-api', file('pipegen-out-junit-api', 'junit.xml', first));
    if (repeat !== null) harnessPr(m).artifacts.set('pipegen-out-junit-repeat-api', file('pipegen-out-junit-repeat-api', 'junit.xml', repeat));
    harnessPr(m).jobs.push(harnessJob('tests-repeat'));
    return m;
  };
  const cx = (over: Partial<EvalContext> = {}): EvalContext => ctxOf({ createdTests: created, readJunit, harnessJobs: ['egress-check', 'app-start', 'verify-lookup', 'tests-repeat'], ...over });
  const GOOD = xml([['s > a', 'pass'], ['s > b', 'pass']]);

  it('evaluate: created tests pass twice → tests proven', async () => {
    const d = dT();
    const r = await evaluate(d, both(d, withJunit(GOOD, GOOD, d)), cx());
    expect(part(r, 'tests')?.status).toBe('proven');
    expect(r.ok).toBe(true);
  });

  it('evaluate: tests pass once and fail on repeat → tests failed, flaky ids named', async () => {
    const d = dT();
    const r = await evaluate(d, both(d, withJunit(GOOD, xml([['s > a', 'pass'], ['s > b', 'fail']]), d)), cx());
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'tests')?.detail).toContain('a.test > s > b');
    expect(part(r, 'tests')?.detail).toMatch(/flaky/);
    expect(r.ok).toBe(false);
    // the other way round
    const r2 = await evaluate(d, both(d, withJunit(xml([['s > a', 'pass'], ['s > b', 'fail']]), GOOD, d)), cx());
    expect(part(r2, 'tests')?.status).toBe('failed');
    // failing both times: a plain failure (not flaky)
    const bad = xml([['s > a', 'pass'], ['s > b', 'fail']]);
    const r3 = await evaluate(d, both(d, withJunit(bad, bad, d)), cx());
    expect(part(r3, 'tests')?.status).toBe('failed');
    expect(part(r3, 'tests')?.detail).not.toMatch(/flaky/);
  });

  it('evaluate: created tests: skipped > 0 or executed ≠ static count → tests failed', async () => {
    const d = dT();
    const skipped = xml([['s > a', 'pass'], ['s > b', 'skip']]);
    expect(part(await evaluate(d, both(d, withJunit(skipped, skipped, d)), cx()), 'tests')?.status).toBe('failed');
    const one = xml([['s > a', 'pass']]);
    const r = await evaluate(d, both(d, withJunit(one, one, d)), cx());
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'tests')?.detail).toMatch(/1 test.*2/);
    const three = xml([['s > a', 'pass'], ['s > b', 'pass'], ['s > c', 'pass']]);
    expect(part(await evaluate(d, both(d, withJunit(three, three, d)), cx()), 'tests')?.status).toBe('failed');
    // exactly the static count passes
    expect(part(await evaluate(d, both(d, withJunit(GOOD, GOOD, d)), cx()), 'tests')?.status).toBe('proven');
    // the same ids twice (a repeated id could hide a failure) is refused by sameResults
    const dup = xml([['s > a', 'pass'], ['s > a', 'pass']]);
    expect(part(await evaluate(d, both(d, withJunit(dup, dup, d)), cx()), 'tests')?.status).toBe('failed');
    // zero tests: never proven
    const zero = '<testsuites><testsuite name="s"></testsuite></testsuites>';
    const rz = await evaluate(d, both(d, withJunit(zero, zero, d)), cx({ createdTests: [{ service: 'api', staticCount: 0 }] }));
    expect(part(rz, 'tests')?.status).toBe('failed');
  });

  it('evaluate: unreadable JUnit → "report unreadable", never pass or "no results"', async () => {
    const d = dT();
    // the reader refuses (a worker timeout, a size, a DOCTYPE)
    const refuse = vi.fn(async () => ({ ok: false as const, reason: 'report unreadable: reading it took longer than 30 s' }));
    const r = await evaluate(d, both(d, withJunit(GOOD, GOOD, d)), cx({ readJunit: refuse }));
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'tests')?.detail).toContain('report unreadable: reading it took longer than 30 s');
    expect(part(r, 'tests')?.detail).not.toMatch(/no results/i);
    expect(refuse).toHaveBeenCalled();
    // a download problem, a missing report, and a repeat report that is garbage
    const m2 = withJunit(null, GOOD, d);
    prRun(m2).artifactProblems.set('pipegen-out-junit-api', 'the artifact is over the size cap');
    const r2 = await evaluate(d, both(d, m2), cx());
    expect(part(r2, 'tests')?.status).toBe('failed');
    expect(part(r2, 'tests')?.detail).toMatch(/report unreadable.*size cap/);
    const r3 = await evaluate(d, both(d, withJunit(null, GOOD, d)), cx());
    expect(part(r3, 'tests')?.status).toBe('failed');
    expect(part(r3, 'tests')?.detail).toMatch(/report unreadable|not uploaded/);
    expect(part(r3, 'tests')?.detail).not.toMatch(/no results/i);
    const r4 = await evaluate(d, both(d, withJunit(GOOD, '<!DOCTYPE x>', d)), cx());
    expect(part(r4, 'tests')?.status).toBe('failed');
    expect(part(r4, 'tests')?.detail).toMatch(/report unreadable/);
    // the reader throwing is unreadable too
    const r5 = await evaluate(d, both(d, withJunit(GOOD, GOOD, d)), cx({ readJunit: async () => { throw new Error('boom'); } }));
    expect(part(r5, 'tests')?.status).toBe('failed');
    // the repeat job red is a failure even with both reports fine
    const m6 = withJunit(GOOD, GOOD, d);
    setConclusion(harnessPr(m6), 'pipegen proof: tests-repeat', 'failure');
    expect(part(await evaluate(d, both(d, m6), cx()), 'tests')?.status).toBe('failed');
    // the repeat job missing although the harness rendered it
    const m7 = withJunit(GOOD, GOOD, d);
    harnessPr(m7).jobs = harnessPr(m7).jobs.filter((j) => !/tests-repeat/.test(j.name));
    expect(part(await evaluate(d, both(d, m7), cx()), 'tests')?.status).toBe('failed');
  });

  it('evaluate: existing suites judged by job result; JUnit only for created tests', async () => {
    const d = dT();
    const reader = vi.fn(readJunit);
    const m = greenMain(d);
    // a junk JUnit artifact must not matter when no tests were created
    prRun(m).artifacts.set('pipegen-out-junit-api', file('pipegen-out-junit-api', 'junit.xml', '<!DOCTYPE bad>'));
    const ok = await evaluate(d, both(d, m), ctxOf({ readJunit: reader }));
    expect(part(ok, 'tests')?.status).toBe('proven');
    expect(reader).not.toHaveBeenCalled();
    // a red existing suite is failed by its job
    const m2 = greenMain(d);
    setConclusion(prRun(m2), 'unit-tests--api', 'failure', '2 tests failed');
    const r2 = await evaluate(d, both(d, m2), ctxOf({ readJunit: reader }));
    expect(part(r2, 'tests')?.status).toBe('failed');
    expect(part(r2, 'tests')?.detail).toContain('unit-tests--api');
    // a skipped suite is not a proven one (the job did not run)
    const m3 = greenMain(d);
    setConclusion(prRun(m3), 'unit-tests--api', 'skipped');
    expect(part(await evaluate(d, both(d, m3), ctxOf()), 'tests')?.status).toBe('failed');
    // a missing suite job is failed
    const m4 = greenMain(d);
    prRun(m4).jobs = prRun(m4).jobs.filter((j) => j.name !== 'unit-tests--api');
    expect(part(await evaluate(d, both(d, m4), ctxOf()), 'tests')?.status).toBe('failed');
    expect(reader).not.toHaveBeenCalled();
  });

  it('tests: no tests need and no created tests → not-proven with a note (nothing floor to prove); skipped by --skip → not-proven, ok unaffected', async () => {
    const noTests = draftOf({ needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('gate', { floor: true })] });
    const r = await evaluate(noTests, both(noTests), ctxOf());
    expect(part(r, 'tests')?.status).toBe('not-proven');
    expect(part(r, 'tests')?.detail).toMatch(/no tests/);
    const skipped = draftOf({ skipped: [{ part: 'tests', reason: 'no time' }] });
    const m = greenMain(skipped);
    prRun(m).jobs = prRun(m).jobs.filter((j) => j.name !== 'unit-tests--api');
    const rs = await evaluate(skipped, both(skipped, m), ctxOf());
    expect(part(rs, 'tests')?.status).toBe('not-proven');
    expect(part(rs, 'tests')?.detail).toMatch(/--skip.*no time/);
  });

  it('evaluate: created tests read with the real worker', async () => {
    const { build } = await import('esbuild');
    const { mkdtempSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { pathToFileURL } = await import('node:url');
    const { readJunitBytes } = await import('../src/create/junit-worker.js');
    const dir = mkdtempSync(join(tmpdir(), 'eval-worker-'));
    try {
      const out = join(dir, 'junit-thread.mjs');
      await build({ entryPoints: [new URL('../src/create/junit-thread.ts', import.meta.url).pathname], bundle: true, platform: 'node', format: 'esm', outfile: out, logLevel: 'silent' });
      const d = dT();
      const real: EvalContext['readJunit'] = (bytes) => readJunitBytes(bytes, { workerUrl: pathToFileURL(out) });
      expect(part(await evaluate(d, both(d, withJunit(GOOD, GOOD, d)), cx({ readJunit: real })), 'tests')?.status).toBe('proven');
      expect(part(await evaluate(d, both(d, withJunit(GOOD, xml([['s > a', 'pass'], ['s > b', 'fail']]), d)), cx({ readJunit: real })), 'tests')?.status).toBe('failed');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('coverage', () => {
  const covDraft = (): ReturnType<typeof draftOf> => draftOf({
    needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('coverage', { service: 'api' }), needOf('gate', { floor: true })],
    steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api')],
  });
  const withLog = (log: string | undefined, conclusion = 'success'): { d: ReturnType<typeof draftOf>; m: VariantRuns } => {
    const d = covDraft();
    const m = greenMain(d, {});
    prRun(m).jobs.push(job('coverage--api', conclusion, log === undefined ? {} : { log }));
    return { d, m };
  };
  const ts = '2026-11-03T10:00:00.1234567Z ';
  const table = (lines: string): string => [
    `${ts}----------|---------|----------|---------|---------|-------------------`, `${ts}File      | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s`,
    `${ts}----------|---------|----------|---------|---------|-------------------`, `${ts}All files |   ${lines} |    70.1 |   88 |   ${lines} |`, `${ts}  src     |   ${lines} |    70.1 |   88 |   ${lines} |`,
  ].join('\n');

  it('evaluate: coverage measured from the green coverage job log (timestamps, ANSI, CR stripped)', async () => {
    const cases: [string, number][] = [
      [table('83.5'), 83.5],
      [table('83.5').replaceAll('\n', '\r\n'), 83.5],
      [table('83.5').replace('All files', '\u001b[1m\u001b[32mAll files\u001b[39m\u001b[22m').replace('83.5 |    70.1', '83.5\u001b[0m |    70.1'), 83.5],
      [`\ufeff${table('91')}`, 91],
    ];
    for (const [log, want] of cases) {
      const { d, m } = withLog(log);
      const full = await evaluateProof(d, both(d, m), ctxOf());
      expect(full.coverage.measured, JSON.stringify(log).slice(0, 60)).toBe(want);
      expect(full.coverage.decision?.blocking).toBe(true);
      expect(need(full.result, 'tests', 'coverage')).toMatchObject({ status: 'proven' });
      expect(need(full.result, 'tests', 'coverage')?.detail).toContain(String(want));
    }
    // the notes of coverageNotes (the repo's own higher minimum) are carried
    const { d, m } = withLog(table('83.5'));
    const rn = await evaluateProof(d, both(d, m), ctxOf({ existingMinimum: 95 }));
    expect(rn.coverage.decision?.notes.join(' ')).toMatch(/95%/);
    // low coverage: non-blocking with a note, still proven (nothing failed)
    const low = withLog(table('40'));
    const rl = await evaluateProof(low.d, both(low.d, low.m), ctxOf());
    expect(rl.coverage.decision).toMatchObject({ choice: null, blocking: false });
    expect(need(rl.result, 'tests', 'coverage')?.detail).toMatch(/not blocking/);
  });

  it('coverage: a log that cannot be read is not-proven for coverage, never a number', async () => {
    for (const log of [undefined, 'no table here', `${ts}All files | 1 | 2 | 3 | 150 |`, `${ts}All files | a | b | c | d |`]) {
      const { d, m } = withLog(log);
      const full = await evaluateProof(d, both(d, m), ctxOf());
      expect(full.coverage.measured, String(log)).toBeNull();
      expect(need(full.result, 'tests', 'coverage')?.status, String(log)).toBe('not-proven');
      // E5-R5 (fix round 2): an unreadable coverage log caps the floor tests part; it is never left proven
      expect(part(full.result, 'tests')?.status, String(log)).toBe('not-proven');
      expect(full.result.ok, String(log)).toBe(false);
    }
    // a failed coverage job is not read for a number
    const bad = withLog(table('90'), 'failure');
    const rb = await evaluateProof(bad.d, both(bad.d, bad.m), ctxOf());
    expect(rb.coverage.measured).toBeNull();
    expect(part(rb.result, 'tests')?.status).toBe('failed');
  });
});

describe('carried notes and parts', () => {
  it('E2 notes (symlink, LFS in a docker service) make docker not-proven; edited-workflow notes are carried without failing the proof', async () => {
    const d = D();
    const r = await evaluate(d, both(d), ctxOf({ carried: [
      { part: 'docker', [MS]: [], reason: 'The build folder of api holds a symlink (api/link), so docker is not proven for api.' },
      { part: 'pipeline', [MS]: [], reason: "pipegen's change to .github/workflows/ci.yml edits a workflow that may hold your content; not proven." },
    ] as never }));
    expect(part(r, 'docker')?.status).toBe('not-proven');
    expect(part(r, 'docker')?.detail).toMatch(/symlink/);
    expect(r.parts.some((p) => p.part === 'pipeline' && p.status === 'not-proven' && /ci\.yml/.test(p.detail))).toBe(true);
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(r.ok).toBe(true);
    // a docker part that FAILED stays failed under the note
    const main = greenMain(d);
    setConclusion(prRun(main), 'image-build--api', 'failure', 'build failed');
    const r2 = await evaluate(d, both(d, main), ctxOf({ carried: [{ part: 'docker', [MS]: [], reason: 'symlink' }] as never }));
    expect(part(r2, 'docker')?.status).toBe('failed');
  });

  it('docker needs the image build and app-start; compose and docker are not-proven when the harness has no app-start', async () => {
    const d = D();
    const m = greenMain(d);
    setConclusion(prRun(m), 'image-build--api', 'failure', 'npm ERR! build failed');
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'docker')?.status).toBe('failed');
    const m2 = greenMain(d);
    setConclusion(harnessPr(m2), 'pipegen proof: app-start', 'failure', 'api exited with code 1');
    const r2 = await evaluate(d, both(d, m2), ctxOf());
    expect(part(r2, 'docker')?.status).toBe('failed');
    expect(part(r2, 'compose')?.status).toBe('failed');
    const m3 = greenMain(d);
    harnessPr(m3).jobs = harnessPr(m3).jobs.filter((j) => !/app-start/.test(j.name));
    harnessMerge(m3).jobs = harnessMerge(m3).jobs.filter((j) => !/app-start/.test(j.name));
    const r3 = await evaluate(d, both(d, m3), ctxOf({ harnessJobs: ['egress-check', 'verify-lookup'], harnessNotes: ["app-start: the draft has no docker-compose.pipegen.yml, so the app start is not proven here."] }));
    expect(part(r3, 'compose')?.status).toBe('not-proven');
    expect(part(r3, 'compose')?.detail).toMatch(/no docker-compose/);
    expect(part(r3, 'docker')?.status).toBe('not-proven');
    // the harness rendered app-start but it never ran: failed
    const r4 = await evaluate(d, both(d, m3), ctxOf());
    expect(part(r4, 'compose')?.status).toBe('failed');
  });

  it('precommit: the hooks job must be green; a missing or skipped job is not proven; no hooks need → no part', async () => {
    const d = D();
    const m = greenMain(d);
    setConclusion(prRun(m), 'hooks', 'failure', 'trailing whitespace');
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'precommit')?.status).toBe('failed');
    const m2 = greenMain(d);
    prRun(m2).jobs = prRun(m2).jobs.filter((j) => j.name !== 'hooks');
    expect(part(await evaluate(d, both(d, m2), ctxOf()), 'precommit')?.status).toBe('failed');
    const none = draftOf({ needs: draftOf().needs.filter((n) => n.id !== 'hooks') });
    expect(part(await evaluate(none, both(none), ctxOf()), 'precommit')).toBeUndefined();
  });

  it('GJ precommit: a pre-commit or husky repository\'s hooks are not proven through hooks-ci (no CI runner): not proven, never failed, never proven', async () => {
    for (const manager of ['pre-commit', 'husky'] as const) {
      const d0 = D();
      const d = { ...d0, profile: { ...d0.profile, precommit: manager } };
      // no hooks job runs (pipegen writes none there): not proven with the reason, not failed
      const m = greenMain(d);
      prRun(m).jobs = prRun(m).jobs.filter((j) => j.name !== 'hooks');
      const r = part(await evaluate(d, both(d, m), ctxOf()), 'precommit');
      expect(r?.status, manager).toBe('not-proven');
      expect(JSON.stringify(r), manager).toMatch(new RegExp(`own ${manager} hooks have no CI runner`));
      // a green job of that name proves nothing either
      expect(part(await evaluate(d, both(d, greenMain(d)), ctxOf()), 'precommit')?.status, manager).toBe('not-proven');
    }
    // a lefthook repository is still held to its hooks job
    const d0 = D();
    const lh = { ...d0, profile: { ...d0.profile, precommit: 'lefthook' as const } };
    const m = greenMain(lh);
    prRun(m).jobs = prRun(m).jobs.filter((j) => j.name !== 'hooks');
    expect(part(await evaluate(lh, both(lh, m), ctxOf()), 'precommit')?.status).toBe('failed');
  });

  it('deploy-verify: sign-roundtrip is required when the harness rendered it', async () => {
    const d = D();
    const m = greenMain(d);
    harnessPr(m).jobs.push(harnessJob('sign-roundtrip', 'failure'));
    const r = await evaluate(d, both(d, m), ctxOf({ harnessJobs: ['egress-check', 'app-start', 'verify-lookup', 'sign-roundtrip'] }));
    expect(part(r, 'deploy-verify')?.status).toBe('failed');
    expect(part(r, 'deploy-verify')?.detail).toMatch(/sign-roundtrip/);
    // not rendered (signing none): no requirement
    expect(part(await evaluate(d, both(d, greenMain(d)), ctxOf()), 'deploy-verify')?.status).toBe('proven');
  });

  it('findings come from the main PR result.json; minutesUsed is the caller\'s; variants other than main and planted are ignored', async () => {
    const d = D();
    const main = greenMain(d);
    setGate(prRun(main), d, { result: 'warn', warnings: [gateFinding('image-scan', 'trivy', { severity: 'low', file: 'x' })] });
    const dispute: VariantRuns = { variant: 'dispute-sast-a', outcomes: [run({ jobs: [job('gate', 'failure')], conclusion: 'failure' })] };
    const r = await evaluate(d, [...both(d, main), dispute], ctxOf({ minutesUsed: 12 }));
    expect(r.findings.map((f) => f.tool)).toContain('trivy');
    expect(r.minutesUsed).toBe(12);
    expect(part(r, 'pipeline')?.status).toBe('proven');
  });

  it('an invalid input is a failed pipeline, never an exception that reads as a pass', async () => {
    const d = D();
    const r = await evaluate(d, [], ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(r.ok).toBe(false);
    const r2 = await evaluate(d, [{ variant: 'main', outcomes: [null as never] }], ctxOf());
    expect(r2.ok).toBe(false);
    expect(matchPlanted([], [], new Map())).toEqual({ caught: [], missed: [] });
  });
});

describe('owned checks fail in any layer; skipped parts do not hide a red job', () => {
  it('a test, hooks, image-build or deploy-verify job that failed on the push or merge layer is failed, whatever the pull request showed', async () => {
    const d = D();
    const cases: [string, string, (m: VariantRuns) => VariantRuns['outcomes'][number], string][] = [
      ['unit-tests--api', 'tests', mergeRun, 'merge'],
      ['hooks', 'precommit', (m) => m.outcomes[0] as VariantRuns['outcomes'][number], 'push'],
      ['image-build--api', 'docker', mergeRun, 'merge'],
      ['deploy-verify', 'deploy-verify', mergeRun, 'merge'],
    ];
    for (const [name, p, pick, label] of cases) {
      const m = greenMain(d);
      const o = pick(m);
      if (!o.jobs.some((j) => j.name === name)) o.jobs.push(job(name, 'failure'));
      else setConclusion(o, name, 'failure');
      const r = await evaluate(d, both(d, m), ctxOf());
      expect(part(r, p as PartResult['part'])?.status, `${name} on ${label}`).toBe('failed');
      expect(r.ok, name).toBe(false);
    }
  });

  it('with the part skipped by --skip, its red job is the pipeline\'s to report', async () => {
    const d = draftOf({ skipped: [{ part: 'precommit', reason: 'slow hooks' }] });
    const m = greenMain(d);
    setConclusion(prRun(m), 'hooks', 'failure', 'x');
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'precommit')?.status).toBe('not-proven');
    expect(part(r, 'pipeline')?.status).toBe('failed');
  });
});

describe('gate block attribution is exact (no substring matching)', () => {
  const MOUNT = 'docker: Error response from daemon: bullfrog: mounting the host path /w is not allowed while sudo is disabled';
  const setup = (reasons: string[], over: Record<string, unknown> = {}) => {
    const d = D();
    const m = greenMain(d);
    const o = prRun(m);
    setConclusion(o, 'sast--api', 'failure', MOUNT);
    setConclusion(o, 'gate', 'failure');
    o.conclusion = 'failure';
    o.artifacts.delete(resultArtifactName('sast', 'api'));
    setGate(o, d, { result: 'block', failedJobs: [{ needId: 'sast', job: 'sast--api' }], blockReasons: reasons, ...over });
    return { d, m };
  };
  const exact = 'required check semgrep (sast--api) did not succeed (failure)';
  it('the exact reason the gate writes for the refused job is explained (by the refused job\'s own failure, E9)', async () => {
    const { d, m } = setup([exact]);
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    // only the refused job's own failure: the gate's block is explained by it, not reported again as an unexplained block
    // only the refused job's own failure (the part line repeats it): the gate's block is explained by it, never reported again
    const failed = r.parts.filter((p) => p.part === 'pipeline' && p.status === 'failed');
    expect(failed.length).toBeGreaterThan(0);
    for (const p of failed) expect(p.detail).toMatch(/^sast: tool error: .*Bullfrog/);
  });
  it('a reason that only contains the job id, adds text, or is unrelated is unexplained: pipeline failed', async () => {
    for (const reasons of [[exact, 'required check semgrep (sast--api-e2e) did not succeed (failure)'], [`${exact}; also the protected file changed`], ['sast--api'], ['sast--api failed'], [exact, 'pipeline files changed or suppressions added without code-owner approval on the current commit']]) {
      const { d, m } = setup(reasons);
      expect(part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.status, reasons.join('|')).toBe('failed');
    }
  });
  it('a failed gate with no block reasons is unexplained', async () => {
    const { d, m } = setup([]);
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.status).toBe('failed');
  });
  it('a reason for a job id that is only a prefix of the refused one does not count', async () => {
    const { d, m } = setup([exact], { failedJobs: [{ needId: 'sast', job: 'sast--api-e2e' }] });
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.status).toBe('failed');
  });
  it('a blocking tool error on an owned job explains the block only when that job really failed', async () => {
    const d = D();
    const toolErr = { needId: 'unit-tests', job: 'unit-tests--api', base: false, blocks: true, reason: 'x' };
    const reason = 'tool error in unit-tests (unit-tests--api): re-run the job';
    const green = greenMain(d);
    setConclusion(prRun(green), 'gate', 'failure');
    setGate(prRun(green), d, { result: 'block', toolErrors: [toolErr], blockReasons: [reason] });
    // unit-tests did not fail: nobody reports it, so the gate's block is the pipeline's failure
    expect(part(await evaluate(d, both(d, green), ctxOf()), 'pipeline')?.status).toBe('failed');
    // unit-tests failed: the tests part reports it, and the explained block does not fail the pipeline twice
    const red = greenMain(d);
    setConclusion(prRun(red), 'gate', 'failure');
    setConclusion(prRun(red), 'unit-tests--api', 'failure', 'boom');
    setGate(prRun(red), d, { result: 'block', toolErrors: [toolErr], blockReasons: [reason] });
    const r = await evaluate(d, both(d, red), ctxOf());
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.status).toBe('not-proven');   // the explained block is never a proven gate (fix round 1, C1)
    expect(r.ok).toBe(false);
  });
});

describe('a compat run is never a source of proof', () => {
  const compatWith = (artifacts: ReturnType<typeof file>[]) => run({ workflow: `${COMPAT_PREFIX}ci.yml`, event: 'pull_request', jobs: [job('build')], artifacts });
  it('a compat artifact named like a pipegen result is a failure and supplies nothing', async () => {
    const d = D();
    const m = greenMain(d);
    m.outcomes.push(compatWith([file('pipegen-out-junit-api', 'junit.xml', xml([['s > a', 'pass'], ['s > b', 'pass']])), file('pipegen-out-sast--api', 'results.sarif', '{}')]));
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toMatch(/compat copy .*ci\.yml.*pipegen result artifact/);
    // the same in the planted variant and the gate result name
    const p = plantedRuns(d);
    p.outcomes.push(compatWith([file(GATE_RESULT_ARTIFACT, 'result.json', '{}')]));
    expect(part(await evaluate(d, both(d, greenMain(d), p), ctxOf()), 'pipeline')?.status).toBe('failed');
  });
  it('the created tests are not proven by a compat run holding both JUnit reports', async () => {
    const d = D();
    const GOOD = xml([['s > a', 'pass'], ['s > b', 'pass']]);
    const m = greenMain(d);
    m.outcomes.push(compatWith([file('pipegen-out-junit-api', 'junit.xml', GOOD), file('pipegen-out-junit-repeat-api', 'junit.xml', GOOD)]));
    harnessPr(m).jobs.push(harnessJob('tests-repeat'));
    const r = await evaluate(d, both(d, m), ctxOf({ createdTests: [{ service: 'api', staticCount: 2 }], readJunit, harnessJobs: ['egress-check', 'app-start', 'verify-lookup', 'tests-repeat'] }));
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'tests')?.detail).toMatch(/not uploaded/);
    expect(r.ok).toBe(false);
  });
  it('the repeat report counts only from the harness run (a pipegen PR run holding it is not the repeat)', async () => {
    const d = D();
    const GOOD = xml([['s > a', 'pass'], ['s > b', 'pass']]);
    const m = greenMain(d);
    prRun(m).artifacts.set('pipegen-out-junit-api', file('pipegen-out-junit-api', 'junit.xml', GOOD));
    prRun(m).artifacts.set('pipegen-out-junit-repeat-api', file('pipegen-out-junit-repeat-api', 'junit.xml', GOOD));
    harnessPr(m).jobs.push(harnessJob('tests-repeat'));
    const r = await evaluate(d, both(d, m), ctxOf({ createdTests: [{ service: 'api', staticCount: 2 }], readJunit, harnessJobs: ['egress-check', 'app-start', 'verify-lookup', 'tests-repeat'] }));
    expect(part(r, 'tests')?.status).toBe('failed');
  });
  it('a result artifact for a need counts only from the run holding that need\'s job', async () => {
    const d = D();
    const m = greenMain(d);
    prRun(m).artifacts.delete(resultArtifactName('sast', 'api'));
    m.outcomes[0]!.artifacts.set(resultArtifactName('sast', 'api'), file(resultArtifactName('sast', 'api'), 'results.sarif', '{}'));   // the push run holds no sast job
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(need(r, 'pipeline', 'sast')?.status).toBe('failed');
  });
  it('a gate report in a compat or harness run is never read as the gate\'s', async () => {
    const d = D();
    const m = greenMain(d);
    prRun(m).artifacts.delete(GATE_RESULT_ARTIFACT);
    harnessPr(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: harnessPr(m).handle.runId }, d));
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.status).toBe('failed');
  });
});
