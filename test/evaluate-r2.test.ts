// E5 fix round 1 (review-E5.md, probes P1-P6): a failed job never turns into a pass, the floor scanners need evidence, a missing
// main variant proves nothing, a created Dockerfile needs its image-scan result, a hostile coverage log cannot switch the check off.
import { describe, expect, it } from 'vitest';
import { evaluate, evaluateProof, type EvalContext, type VariantRuns } from '../src/proof/evaluate.js';
import type { PartResult, ProofResult } from '../src/types.js';
import {
  COMPAT_PREFIX, ctxOf, draftOf, file, gateDoc, gateFinding, GATE_RESULT_ARTIFACT, greenMain, HARNESS_PATH, harnessJob, job, MERGE, needOf, PIPEGEN, PLANTED_ITEMS, plantedRuns, resultArtifactName, run, spec,
} from './helpers/proof-eval.js';

type O = VariantRuns['outcomes'][number];
const part = (r: ProofResult, p: PartResult['part']): PartResult | undefined => r.parts.find((x) => x.part === p && x.needId === undefined);
const ent = (r: ProofResult, p: PartResult['part'], id: string): PartResult[] => r.parts.filter((x) => x.part === p && x.needId === id);
const prRun = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'pull_request') as O;
const set = (o: O, name: string, conclusion: string | null, log?: string): void => {
  const j = o.jobs.find((x) => x.name === name);
  if (j === undefined) throw new Error(`no job ${name}`);
  j.conclusion = conclusion; j.status = conclusion === null ? 'in_progress' : 'completed';
  if (log !== undefined) j.log = log;
};
const MS = ['missing', 'Sec', 'rets'].join('');
const CREATED = [{ part: 'docker' as const, path: 'api/Dockerfile', content: 'FROM x', reason: 'r', repo: 'app' as const }];
const ts = '2026-11-03T10:00:00.1234567Z ';
const table = (n: string): string => [`${ts}File      | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s`, `${ts}All files |   ${n} |    70.1 |   88 |   ${n} |`].join('\n');
const covDraft = (extra: Partial<Parameters<typeof draftOf>[0]> = {}) => draftOf({
  needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('coverage', { service: 'api' }), needOf('gate', { floor: true })],
  steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api')], ...extra,
});
const noImage = (): Partial<EvalContext> => ({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan'), harnessJobs: ['egress-check', 'verify-lookup'] });
const blockDoc = (o: O, d: ReturnType<typeof draftOf>, jobId: string, needId: string, tool: string): void => {
  set(o, 'gate', 'failure'); o.conclusion = 'failure';
  o.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: o.handle.runId, result: 'block', failedJobs: [{ needId, job: jobId }], blockReasons: [`required check ${tool} (${jobId}) did not succeed (failure)`] }, d));
};

describe('C1: a failed job never turns into a pass', () => {
  it('P5: a failed coverage job whose log names an external host fails tests, and the gate block is not explained', async () => {
    const d = covDraft();
    const m = greenMain(d);
    prRun(m).jobs.push(job('coverage--api', 'failure', { log: `${ts}getaddrinfo ENOTFOUND telemetry.example.com\n${ts}ERROR: Coverage for lines (41%) does not meet global threshold (60%)` }));
    blockDoc(prRun(m), d, 'coverage--api', 'coverage', 'coverage');
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf(noImage()));
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.status).not.toBe('proven');
    expect(r.ok).toBe(false);
  });

  it('P5b: the same with a missing secret name in the log', async () => {
    const d = covDraft({ notProven: [{ part: 'tests', reason: 'x', [MS]: ['STRIPE_SECRET_KEY'] }] });
    const m = greenMain(d);
    prRun(m).jobs.push(job('coverage--api', 'failure', { log: `${ts}STRIPE_SECRET_KEY is not set\n${ts}ERROR: Coverage for lines (41%) does not meet global threshold (60%)` }));
    blockDoc(prRun(m), d, 'coverage--api', 'coverage', 'coverage');
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf(noImage()));
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.status).not.toBe('proven');
    expect(r.ok).toBe(false);
  });

  it('P6: an image-build failure with an external host in its log is docker not-proven and the gate block is NOT explained: pipeline failed, ok false', async () => {
    const d = draftOf();
    const m = greenMain(d);
    set(prRun(m), 'image-build--api', 'failure', 'npm ERR! getaddrinfo ENOTFOUND registry.example.com');
    blockDoc(prRun(m), d, 'image-build--api', 'image-build', 'image-build');
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
    expect(part(r, 'docker')?.status).toBe('not-proven');
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.detail).toMatch(/gate blocked/);
    expect(r.ok).toBe(false);
  });

  it('an explained gate block (an owned job that failed for real) is never a proven pipeline: the summary does not say the gate passed', async () => {
    const d = draftOf();
    const m = greenMain(d);
    set(prRun(m), 'unit-tests--api', 'failure', 'boom');
    blockDoc(prRun(m), d, 'unit-tests--api', 'unit-tests', 'unit-tests');
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'pipeline')?.status).toBe('not-proven');
    expect(part(r, 'pipeline')?.detail).toMatch(/gate blocked the main pull request/);
    expect(part(r, 'pipeline')?.detail).not.toMatch(/gate passed/);
    expect(r.ok).toBe(false);
  });

  it('a failed coverage job that did not run (skipped) is a failure, not a note', async () => {
    const d = covDraft();
    const m = greenMain(d);
    prRun(m).jobs.push(job('coverage--api', 'skipped'));
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf(noImage()));
    expect(part(r, 'tests')?.status).toBe('failed');
  });
});

describe('I1: the secrets scanner is proven only by a planted secret it found', () => {
  it('P2: no planted secret placement at all fails the pipeline with a reason', async () => {
    const d = draftOf();
    for (const planted of [[], [{ kind: 'integrity-warning' as const, path: '.gitleaksignore', pathBytes: Buffer.from('.gitleaksignore'), line: 0 }]]) {
      const r = await evaluate(d, [greenMain(d), plantedRuns(d, { skip: (f) => !String(f.file).startsWith('pipegen-planted') })], ctxOf({ planted }));
      expect(part(r, 'pipeline')?.status).toBe('failed');
      expect(ent(r, 'pipeline', 'secrets')[0]?.detail).toMatch(/no planted secret was expected/);
      expect(r.ok).toBe(false);
    }
  });
  it('a floor scanner the planted run has no result for (its need is not a findings check) is failed, never silent', async () => {
    const d = draftOf({ steps: draftOf().steps.filter((s) => s.needId !== 'secrets') });
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(r.parts.some((p) => p.part === 'pipeline' && p.needId === 'secrets' && p.status === 'failed')).toBe(true);
  });
});

describe('I2: a missing main variant proves nothing', () => {
  it('P1: tests, deploy-verify and every part read from main are failed or not-proven, never proven', async () => {
    const d = draftOf();
    const r = await evaluate(d, [plantedRuns(d)], ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    expect(part(r, 'tests')?.status).toBe('failed');
    expect(part(r, 'deploy-verify')?.status).toBe('failed');
    for (const p of ['docker', 'compose', 'precommit'] as const) expect(part(r, p)?.status, p).toBe('not-proven');
    expect(r.parts.filter((p) => p.needId === undefined && p.status === 'proven')).toEqual([]);
    expect(r.ok).toBe(false);
  });
});

describe('I3: a created Dockerfile needs its image-scan result', () => {
  const withoutScan = () => { const b = draftOf(); return draftOf({ created: CREATED, needs: b.needs.filter((n) => n.id !== 'image-scan'), steps: b.steps.filter((s) => s.needId !== 'image-scan') }); };
  it('P3a: with the image scan read from its job, docker is proven', async () => {
    const d = draftOf({ created: CREATED });
    expect(part(await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf()), 'docker')?.status).toBe('proven');
  });
  it('P3b: no image-scan need at all: docker is not-proven (not a floor part), never proven', async () => {
    const d = withoutScan();
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan') }));
    expect(part(r, 'docker')?.status).toBe('not-proven');
    expect(part(r, 'docker')?.detail).toMatch(/image scan/);
  });
  it('P3c: a non-blocking image scan with a tool error and no artifact is not read: docker not-proven', async () => {
    const b = draftOf();
    const d = draftOf({ created: CREATED, needs: b.needs.map((n) => (n.id === 'image-scan' ? { ...n, blocking: false } : n)) });
    const m = greenMain(d);
    for (const k of [...prRun(m).artifacts.keys()]) if (k.includes('image-scan')) prRun(m).artifacts.delete(k);
    prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(m).handle.runId, toolErrors: [{ needId: 'image-scan', job: 'image-scan--api', tool: 'trivy-image', base: false, blocks: false, reason: 'no sarif' }] }, d));
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
    expect(part(r, 'docker')?.status).toBe('not-proven');
  });
  it('each part of the evidence is required: its artifact, its check in the report, no tool error', async () => {
    const d = draftOf({ created: CREATED });
    const noArtifact = greenMain(d); prRun(noArtifact).artifacts.delete(resultArtifactName('image-scan', 'api'));
    expect(part(await evaluate(d, [noArtifact, plantedRuns(d)], ctxOf()), 'docker')?.status).not.toBe('proven');
    const noCheck = greenMain(d);
    prRun(noCheck).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(noCheck).handle.runId, checks: [{ needId: 'secrets', job: 'secrets', tool: 'gitleaks', judgedBy: 'findings', state: 'ok' }] }, d));
    expect(part(await evaluate(d, [noCheck, plantedRuns(d)], ctxOf()), 'docker')?.status).not.toBe('proven');
    const err = greenMain(d);
    prRun(err).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(err).handle.runId, toolErrors: [{ needId: 'image-scan', job: 'image-scan--api', tool: 'trivy-image', base: false, blocks: true, reason: 'x' }] }, d));
    expect(part(await evaluate(d, [err, plantedRuns(d)], ctxOf()), 'docker')?.status).not.toBe('proven');
  });
  it('m5: the failure text does not claim the CVEs are fixable', async () => {
    const d = draftOf({ created: CREATED });
    const m = greenMain(d);
    prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(m).handle.runId, result: 'warn', warnings: [gateFinding('image-scan', 'trivy', { severity: 'high', job: 'image-scan--api', ruleId: 'CVE-1' })] }, d));
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
    expect(part(r, 'docker')?.status).toBe('failed');
    // E9: a finding with no fixable flag (an older gate) is still a failure, said as "no fix info", never claimed fixable
    expect(part(r, 'docker')?.detail).toContain('with a fixed version or no fix info');
    expect(part(r, 'docker')?.detail).not.toMatch(/fixable/);
  });
});

describe('I4: a hostile coverage log cannot lower or switch off the check', () => {
  const cov = async (log: string, over: Partial<EvalContext> = {}) => {
    const d = covDraft();
    const m = greenMain(d);
    prRun(m).jobs.push(job('coverage--api', 'success', { log }));
    return evaluateProof(d, [m, plantedRuns(d)], ctxOf({ ...noImage(), ...over }));
  };
  it('P4: a fake 1% row next to the real 85%: the minimum is chosen from the highest row (85) and the check fails on the lowest (1), with a note', async () => {
    const real = await cov(table('85'));
    const r = await cov(`${ts}All files | 1 | 1 | 1 | 1 |\n${table('85')}`);
    expect(r.coverage.measured).toBe(85);
    expect(r.coverage.lowest).toBe(1);
    expect(r.coverage.decision?.choice).toBe(real.coverage.decision?.choice);
    expect(r.coverage.decision?.blocking).toBe(true);
    const e = ent(r.result, 'tests', 'coverage')[0];
    expect(e?.status).toBe('failed');
    expect(e?.detail).toMatch(/several .*All files.* rows.*1.*85/);
    expect(r.result.ok).toBe(false);
  });
  it('a fake 99% row next to the real 85%: the minimum can only go up, and the real 85% then fails it', async () => {
    const real = await cov(table('85'));
    const r = await cov(`${ts}All files | 99 | 1 | 1 | 99 |\n${table('85')}`);
    expect(r.coverage.measured).toBe(99);
    expect(Number(r.coverage.decision?.choice)).toBeGreaterThanOrEqual(Number(real.coverage.decision?.choice));
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).toBe('failed');
    expect(r.result.ok).toBe(false);
  });
  it('the same rows in the other order, and rows with CR progress prefixes, give the same answer', async () => {
    expect((await cov(`${table('92')}\n${ts}All files | 1 | 1 | 1 | 1 |`)).coverage.measured).toBe(92);
    const r = await cov(`${ts}progress 10%\rAll files |  83 |  1 |  1 |  83 |\n`);
    expect(r.coverage.measured).toBe(83);
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).toBe('proven');
  });
  it('equal rows are one measurement; the summary of a long log is found at its tail', async () => {
    const r = await cov(`${table('83.5')}\n${table('83.5')}`);
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).toBe('proven');
    const long = await cov(`${'noise line of test output\n'.repeat(60_000)}${table('88')}`);
    expect(long.coverage.measured).toBe(88);
  });
  it('a single low row is the repo\'s own measurement: not blocking with a note (D6), not failed', async () => {
    const r = await cov(table('40'));
    expect(r.coverage.decision).toMatchObject({ choice: null, blocking: false });
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).toBe('proven');
  });
  it('m8: two matrix legs of one coverage need at different values give the lowest', async () => {
    const d = covDraft();
    const m = greenMain(d);
    prRun(m).jobs = prRun(m).jobs.filter((j) => j.name !== 'coverage--api');
    prRun(m).jobs.push(job('coverage--api (a)', 'success', { log: table('83.5') }), job('coverage--api (b)', 'success', { log: table('61') }));
    expect((await evaluateProof(d, [m, plantedRuns(d)], ctxOf(noImage()))).coverage.measured).toBe(61);
  });
});

describe('minor findings', () => {
  it('m2: a repo with no tests need and no created tests is ok (nothing floor to prove); a carried not-proven note on a floor tests part keeps ok false', async () => {
    const noTests = draftOf({ needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('gate', { floor: true })] });
    const r = await evaluate(noTests, [greenMain(noTests), plantedRuns(noTests)], ctxOf({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan'), harnessJobs: ['egress-check', 'verify-lookup'] }));
    expect(part(r, 'tests')?.status).toBe('not-proven');
    expect(r.ok).toBe(true);
    const d = draftOf();
    const rc = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf({ carried: [{ part: 'tests', [MS]: [], reason: 'LFS test fixtures are pointers' }] as never }));
    expect(part(rc, 'tests')?.status).toBe('not-proven');
    expect(rc.ok).toBe(false);
  });
  it('m3: a proven pipeline names the needs that are only not-proven and claims nothing it did not show', async () => {
    const d = draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('dast', { service: 'api' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec('zap-baseline', 'dast', 'api')],
    });
    // G0-R1 I1: ZAP is no longer a not-proven need; the not-proven dast need here is a carried note (E2's kind), as the m3 rule needs one
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf({ ...noImage(), harnessJobs: ['egress-check', 'app-start', 'verify-lookup'], carried: [{ part: 'pipeline', needId: 'dast', [MS]: [], reason: 'the app could not be started for DAST' }] as never }));
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(part(r, 'pipeline')?.detail).toMatch(/not proven: .*dast/);
    expect(part(r, 'pipeline')?.detail).not.toMatch(/every blocking scanner/);
  });
  it('m4: a pipegen or harness run whose job list could not be read is unreadable, never green', async () => {
    const d = draftOf();
    for (const pick of [(m: VariantRuns) => m.outcomes[3] as O, (m: VariantRuns) => m.outcomes[4] as O, (m: VariantRuns) => m.outcomes[1] as O]) {
      const m = greenMain(d);
      const o = pick(m);
      o.jobs = []; o.artifactProblems.set('(jobs)', 'the jobs of the run could not be read');
      const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
      expect(part(r, 'pipeline')?.status).toBe('failed');
      expect(part(r, 'pipeline')?.detail).toMatch(/report unreadable.*jobs of the run could not be read/);
    }
    const l = greenMain(d); (l.outcomes[1] as O).artifactProblems.set('(listing)', 'the artifact list could not be read');
    expect(part(await evaluate(d, [l, plantedRuns(d)], ctxOf()), 'pipeline')?.status).toBe('failed');
  });
  it('m7: only the draft\'s pipegen workflow paths and the harness are trusted', async () => {
    const d = draftOf();
    const m = greenMain(d);
    for (const o of m.outcomes) if (o.handle.workflow === PIPEGEN) (o.handle as { workflow: string }).workflow = '.github/workflows/evil.yml';
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('failed');
    // the same runs are trusted when the draft created that workflow (pipegen's own file)
    const d2 = draftOf({ created: [{ path: '.github/workflows/evil.yml', content: 'x', part: 'pipeline', reason: 'r', repo: 'app' }] });
    const m2 = greenMain(d2);
    for (const o of m2.outcomes) if (o.handle.workflow === PIPEGEN) (o.handle as { workflow: string }).workflow = '.github/workflows/evil.yml';
    const p2 = plantedRuns(d2);
    for (const o of p2.outcomes) (o.handle as { workflow: string }).workflow = '.github/workflows/evil.yml';
    expect(part(await evaluate(d2, [m2, p2], ctxOf()), 'pipeline')?.status).toBe('proven');
    // an unknown workflow holding a pipegen result artifact is a failure
    const x = greenMain(d);
    x.outcomes.push(run({ workflow: '.github/workflows/other.yml', event: 'pull_request', jobs: [job('b')], artifacts: [file('pipegen-out-junit-api', 'junit.xml', '<x/>')] }));
    expect(part(await evaluate(d, [x, plantedRuns(d)], ctxOf()), 'pipeline')?.status).toBe('failed');
  });
  it('m9: nuclei gets one not-proven entry for its need', async () => {
    // name kept (Plan E); it now asserts (G0, F-3): no not-proven entry for its need, one note in the pipeline's detail
    const d = draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('dast', { service: 'api' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec('nuclei', 'dast', 'api')],
    });
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf(noImage()));
    // Plan G G0 (F-3): a blocking scanner with no planted item stays blocking and is shown in the pipeline's detail, once; it is
    // never a not-proven need entry (which would reach draft.notProven)
    expect(ent(r, 'pipeline', 'dast')).toHaveLength(0);
    expect(r.parts.find((p) => p.part === 'pipeline' && p.needId === undefined)?.detail.match(/deferred/g)).toHaveLength(1);
  });
});
void COMPAT_PREFIX; void HARNESS_PATH; void harnessJob; void MERGE;
