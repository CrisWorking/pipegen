// E5 fix round 2 (review-E5-r1.md): the coverage row cap fails closed, the not-proven dedup keeps the detail, only pipegen's own app files
// are trusted workflows, no shared module state, the image scan is bound to the Dockerfile's service, an unreadable coverage log caps.
import { describe, expect, it } from 'vitest';
import { evaluate, evaluateProof, type EvalContext, type VariantRuns } from '../src/proof/evaluate.js';
import type { PartResult, ProofResult } from '../src/types.js';
import {
  COMPAT_PREFIX, ctxOf, draftOf, gateDoc, GATE_RESULT_ARTIFACT, greenMain, job, needOf, PIPEGEN, PLANTED_ITEMS, plantedRuns, run, spec,
} from './helpers/proof-eval.js';

type O = VariantRuns['outcomes'][number];
const part = (r: ProofResult, p: PartResult['part']): PartResult | undefined => r.parts.find((x) => x.part === p && x.needId === undefined);
const ent = (r: ProofResult, p: PartResult['part'], id: string): PartResult[] => r.parts.filter((x) => x.part === p && x.needId === id);
const prRun = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'pull_request') as O;
const MS = ['missing', 'Sec', 'rets'].join('');
const note = (reason: string) => ({ part: 'pipeline' as const, reason, [MS]: [] as string[] }) as unknown as import('../src/types.js').NotProven;
const ts = '2026-11-03T10:00:00.1234567Z ';
const table = (n: string): string => [`${ts}File      | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s`, `${ts}All files |   ${n} |    70.1 |   88 |   ${n} |`].join('\n');
const covDraft = (cov: Parameters<typeof needOf>[1] = {}) => draftOf({
  needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('coverage', { service: 'api', ...cov }), needOf('gate', { floor: true })],
  steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api')],
});
const noImage = (): Partial<EvalContext> => ({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan'), harnessJobs: ['egress-check', 'verify-lookup'] });
const cov = async (log: string, cn: Parameters<typeof needOf>[1] = {}) => {
  const d = covDraft(cn);
  const m = greenMain(d);
  prRun(m).jobs.push(job('coverage--api', 'success', { log }));
  return evaluateProof(d, [m, plantedRuns(d)], ctxOf(noImage()));
};

describe('I4 (round 2): the coverage row cap fails closed', () => {
  it('R1: 10 000 fake 100% rows before the real 61% summary: the real row is still read, the check fails, ok false', async () => {
    const fake = `${ts}All files | 100 | 1 | 1 | 100 |\n`.repeat(10_000);
    const r = await cov(`${fake}${table('61')}`);
    expect(r.result.ok).toBe(false);
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).not.toBe('proven');
    expect(r.coverage.decision).toBeNull();
  });
  it('more rows than the cap and no real summary: the coverage need fails (never proven, never silently cut)', async () => {
    const r = await cov(`${ts}All files | 100 | 1 | 1 | 100 |\n`.repeat(10_001));
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).toBe('failed');
    expect(ent(r.result, 'tests', 'coverage')[0]?.detail).toMatch(/more than 10000|too many/);
    expect(r.result.ok).toBe(false);
  });
  it('exactly the cap is still read', async () => {
    const r = await cov(`${ts}All files | 90 | 1 | 1 | 90 |\n`.repeat(10_000));
    expect(r.coverage.measured).toBe(90);
  });
});

describe('dedup (round 2): distinct not-proven notes without a need id are all kept', () => {
  it('R2: two compat no-baseline copies and two carried pipeline notes give four details', async () => {
    const d = draftOf();
    const m = greenMain(d);
    m.outcomes.push(run({ workflow: `${COMPAT_PREFIX}ci.yml`, event: 'pull_request', jobs: [job('build', 'failure', { log: 'boom' })] }));
    m.outcomes.push(run({ workflow: `${COMPAT_PREFIX}lint.yml`, event: 'pull_request', jobs: [job('lint', 'failure', { log: 'boom' })] }));
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf({ carried: [note('pipegen edited ci.yml: not proven'), note('pipegen edited release.yml: not proven')] }));
    const text = r.parts.filter((p) => p.part === 'pipeline').map((p) => p.detail).join('\n');
    expect(text).toContain('ci.yml failed in the scratch repo');
    expect(text).toContain('lint.yml failed in the scratch repo');
    expect(text).toContain('pipegen edited ci.yml');
    expect(text).toContain('pipegen edited release.yml');
  });
  it('the same note twice is still one entry', async () => {
    const d = draftOf();
    const n = note('pipegen edited ci.yml: not proven');
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf({ carried: [n, n] }));
    expect(r.parts.filter((p) => p.detail.includes('pipegen edited ci.yml'))).toHaveLength(1);
  });
});

describe('m7 (round 2): only pipegen\'s own new app files are trusted workflows', () => {
  const renamed = (d: ReturnType<typeof draftOf>, path: string): VariantRuns[] => {
    const m = greenMain(d);
    for (const o of m.outcomes) if (o.handle.workflow === PIPEGEN) (o.handle as { workflow: string }).workflow = path;
    const p = plantedRuns(d);
    for (const o of p.outcomes) (o.handle as { workflow: string }).workflow = path;
    return [m, p];
  };
  const W = '.github/workflows/ci.yml';
  it('a created app workflow is trusted (control)', async () => {
    const d = draftOf({ created: [{ path: W, content: 'x', part: 'pipeline', reason: 'r', repo: 'app' }] });
    expect(part(await evaluate(d, renamed(d, W), ctxOf()), 'pipeline')?.status).toBe('proven');
  });
  it('an edited user workflow (inserted) is not trusted', async () => {
    const d = draftOf({ created: [{ path: W, content: 'x', part: 'pipeline', reason: 'r', repo: 'app', inserted: { original: 'y', jobs: ['gate'], needs: [] } }] });
    expect(part(await evaluate(d, renamed(d, W), ctxOf()), 'pipeline')?.status).toBe('failed');
  });
  it('a central-repo path is not trusted', async () => {
    const d = draftOf({ created: [{ path: W, content: 'x', part: 'pipeline', reason: 'r', repo: 'central' }] });
    expect(part(await evaluate(d, renamed(d, W), ctxOf()), 'pipeline')?.status).toBe('failed');
  });
});

describe('no shared module state between evaluations', () => {
  it('two evaluations in flight over the same runs with different trusted workflows do not read each other\'s kinds', async () => {
    const W = '.github/workflows/extra.yml';
    const d1 = covDraft();
    d1.created.push({ path: W, content: 'x', part: 'pipeline', reason: 'r', repo: 'app' });
    const d2 = covDraft();
    const m = greenMain(d1);
    prRun(m).jobs.push(job('coverage--api', 'success', { log: table('85') }));
    // the failure sits in the push layer: only the late read of the trusted kinds (after the awaits) sees it
    (m.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'push') as O).jobs.push(job('coverage--api', 'failure', { log: 'boom' }));
    for (const o of m.outcomes) if (o.handle.workflow === PIPEGEN) (o.handle as { workflow: string }).workflow = W;
    const p = plantedRuns(d1);
    for (const o of p.outcomes) (o.handle as { workflow: string }).workflow = W;
    const c1 = ctxOf({ ...noImage(), createdTests: [{ service: 'api', staticCount: 1 }] });
    const solo = ent((await evaluate(d1, [m, p], c1)), 'tests', 'coverage')[0]?.status;
    expect(solo).toBe('failed');
    const [a] = await Promise.all([evaluate(d1, [m, p], c1), evaluate(d2, [m, p], ctxOf(noImage()))]);
    expect(ent(a, 'tests', 'coverage')[0]?.status).toBe(solo);
  });
});

describe('I3 residual (round 2): the image scan is bound to the created Dockerfile\'s service', () => {
  const CREATED = [{ part: 'docker' as const, path: 'api/Dockerfile', content: 'FROM x', reason: 'r', repo: 'app' as const }];
  it('a scan of another service does not count for the created Dockerfile of api', async () => {
    const b = draftOf();
    const d = draftOf({ created: CREATED, needs: b.needs.map((n) => (n.id === 'image-scan' ? { ...n, service: 'worker' } : n)), steps: b.steps.map((s) => (s.needId === 'image-scan' ? { ...s, service: 'worker' } : s)) });
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf({ plantedItems: PLANTED_ITEMS.filter((i) => i.category !== 'image-scan') }));
    expect(part(r, 'docker')?.status).toBe('not-proven');
    expect(part(r, 'docker')?.detail).toMatch(/image scan/);
  });
  it('a Dockerfile that belongs to no service is not-proven (no bound evidence)', async () => {
    const d = draftOf({ created: [{ ...CREATED[0]!, path: "elsewhere/Dockerfile" }] });
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf());
    expect(part(r, 'docker')?.status).toBe('not-proven');
  });
  it.each(['did not report', 'skipped', 'tampered', 'not run (fork PR)', 'did not report; no coverage'])('a gate check that says "%s" is not a read scan', async (state) => {
    const d = draftOf({ created: CREATED });
    const m = greenMain(d);
    const checks = [{ needId: 'secrets', job: 'secrets', tool: 'gitleaks', judgedBy: 'findings', state: 'passed' }, { needId: 'image-scan', job: 'image-scan--api', tool: 'trivy-image', judgedBy: 'findings', state }];
    prRun(m).artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: prRun(m).handle.runId, checks }, d));
    const r = await evaluate(d, [m, plantedRuns(d)], ctxOf());
    expect(part(r, 'docker')?.status).toBe('not-proven');
    expect(part(r, 'docker')?.detail).toContain(state.split(';')[0]);
  });
  it('a service is bound by its recorded Dockerfile path, or by its folder', async () => {
    const byField = draftOf({ created: [{ ...CREATED[0]!, path: 'build/Dockerfile.api' }] });
    byField.profile.services[0]!.dockerfile = 'build/Dockerfile.api';
    expect(part(await evaluate(byField, [greenMain(byField), plantedRuns(byField)], ctxOf()), 'docker')?.status).toBe('proven');
    const byDir = draftOf({ created: CREATED });
    delete byDir.profile.services[0]!.dockerfile;
    expect(part(await evaluate(byDir, [greenMain(byDir), plantedRuns(byDir)], ctxOf()), 'docker')?.status).toBe('proven');
  });
  it('control: the bound scan, read, proves docker', async () => {
    const d = draftOf({ created: CREATED });
    expect(part(await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf()), 'docker')?.status).toBe('proven');
  });
});

describe('unreadable coverage log (round 2)', () => {
  it('on a floor tests part it caps the part: tests is never proven, ok false', async () => {
    const r = await cov('no table here at all');
    expect(part(r.result, 'tests')?.status).toBe('not-proven');
    expect(r.result.ok).toBe(false);
    expect(r.coverage.decision).toBeNull();
  });
  it('a floor coverage need is failed, never not-proven', async () => {
    const r = await cov('no table here at all', { floor: true });
    expect(ent(r.result, 'tests', 'coverage')[0]?.status).toBe('failed');
    expect(part(r.result, 'tests')?.status).toBe('failed');
    expect(r.result.ok).toBe(false);
  });
});
