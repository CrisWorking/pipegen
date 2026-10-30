// Plan C, C0b fix round 1: every attack of the C0b review as a regression test (review-C0b.md findings 1-10, task-C0b-fix-round-1.md).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { GateJobListError, gateJobList } from '../src/engine/gate-job-list.js';
import { checkJobOrder, jobOutputsFor, jobOutputsProblems, NO_SCANS, type ScanFact } from '../src/engine/job-rules.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  dedupeJobSteps, RenderError, renderBaselineCheckStep, renderGateStep, renderJobPrelude, renderPlatformStep, renderProjectScript, renderScrub, renderStep, renderUpload, scanFactOf, scrubbedPath, stepsToYaml,
  type RenderContext, type RenderedStep, type RenderResult,
} from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { rendererInputProblems } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, ReviewedTool, StepSpec } from '../src/types.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { renderGateUploads, renderStage as renderStageC1c } from '../src/engine/render-step.js';
import { isStagedTool } from '../src/engine/tool-flags.js';

// object keys spelled at run time (see test/no-secret-literals.test.ts)
const NS = ['needs', 'Sec', 'rets'].join('');
const SEC = ['sec', 'rets'].join('');
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');

// ---------- builders ----------

/** `${{ secrets.NAME }}`, built at run time (test/no-secret-literals.test.ts). */
const sref = (n: string): string => ['${{', `secrets.${n}`, '}}'].join(' ');
const p = platform();
const GATE = gateEntry();
const app = service({ name: 'app', path: '.', scripts: ['test', 'lint'] });
const web = service({ name: 'web', path: 'web', scripts: ['test'] });
const prof = { ...profile([app, web]), repoFiles: { ...emptyRepoFiles(), kubernetes: true } };
const ctx: RenderContext = { profile: prof, targets: { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080', k8sDir: 'k8s' } };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const needOf = (id: string, svcName?: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svcName === undefined ? {} : { service: svcName }), why: 't', blocking: true, floor: false });
const draftOf = (specs: StepSpec[], needs: Need[]): PipelineDraft => ({
  profile: prof, capabilities: caps, needs, steps: specs, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const LINTERS: Linters = { actionlint: async () => '/stub/actionlint', zizmor: async () => '/stub/zizmor' };
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, [...reviewedList(), GATE], LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const has = (r: RefereeReport, check: string, re?: RegExp): boolean => r.issues.some((i) => i.check === check && (re === undefined || re.test(i.message)));

type Job = Record<string, unknown>;
const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });
/** `raw`: steps written as plain YAML, for hostile steps the emitter itself refuses (the referee must refuse them too). */
function workflow(jobs: Record<string, Job>, raw = false): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) {
    const steps = j.steps as RenderedStep[];
    doc.setIn(['jobs', id, 'steps'], raw ? doc.createNode(steps.map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(steps));
  }
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
const prelude = (over: Parameters<typeof renderJobPrelude>[0] = {}): RenderedStep[] => renderJobPrelude(over, p).steps;

interface Block { steps: RenderedStep[]; scrub: RenderedStep; upload: RenderedStep; artifact: string; scan: { stepId: string; fact: ScanFact }; result: RenderResult }
/** The tool steps, the scrub and the upload of one spec (no prelude): what Plan G puts after the checkout. */
function block(spec: StepSpec, c: RenderContext = ctx): Block {
  const t = entry(spec.tool.id);
  const result = renderStep(spec, t, p, c);
  const out = result.output;
  if (out === null || (out.format !== 'sarif' && out.format !== 'zap-json')) throw new Error('not a findings tool');
  const artifact = resultArtifactName(spec.needId, spec.service, c.base === true ? { base: true } : undefined);
  const scrub = renderScrub(artifact, out.path, t.id, out.format, GATE);
  const upload = renderUpload(artifact, scrubbedPath(out.path), p);
  const scan = scanFactOf(result, t.id);
  if (scan === null) throw new Error('no scan fact');
  const stage = isStagedTool(t.id) ? [renderStageC1c(artifact, t.id, GATE)] : [];   // C1c: a secrets scan reads the stage folder its stage step filled
  return { steps: [...stage, ...result.steps, scrub, upload], scrub, upload, artifact, scan, result };
}
const gitleaksSpec = (): StepSpec => specFor(entry('gitleaks'), { needId: 'secrets' });
const semgrepSpec = (svc: string): StepSpec => specFor(entry('semgrep'), { needId: 'sast', service: svc });
const facts = (...bs: Block[]): ReadonlyMap<string, ScanFact> => new Map(bs.map((b) => [b.scan.stepId, b.scan.fact]));
const scrubOf = (steps: RenderedStep[]): RenderedStep => steps.find((s) => s.id?.startsWith('scrub-')) as RenderedStep;
const withScrub = (steps: RenderedStep[], f: (s: RenderedStep) => RenderedStep): RenderedStep[] => steps.map((s) => (s.id?.startsWith('scrub-') ? f(s) : s));


// ---------- the jobs of a full draft ----------
const specs = [gitleaksSpec(), semgrepSpec('app'), semgrepSpec('web')];
const needs = [needOf('secrets'), needOf('sast', 'app'), needOf('sast', 'web'), needOf('unit-tests', 'app'), needOf('gate')];
const d = draftOf(specs, needs);
const entries = gateJobList(d);
const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
type BaseRef = 'pull-request-base' | 'none';
function jobs(baseRef: BaseRef = 'pull-request-base'): Record<string, Job> {
  const out: Record<string, Job> = {};
  for (const spec of specs) {
    const b = block(spec);
    const id = `${spec.needId}${spec.service === undefined ? '' : `--${spec.service}`}`;
    out[id] = job(dedupeJobSteps([...prelude(), ...b.steps], { id, scans: facts(b) }), { outputs: jobOutputsFor(b.steps) });
  }
  const script = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps;
  out['unit-tests--app'] = job(dedupeJobSteps(script, { id: 'unit-tests--app', scans: NO_SCANS }));
  const baseBlocks = specs.map((s) => block(s, { ...ctx, base: true }));
  const baseSteps = [...prelude(baseRef === 'none' ? {} : { baseRef: true }), ...baseBlocks.flatMap((b) => b.steps)];
  out['base-scan'] = job(baseSteps, { outputs: jobOutputsFor(baseBlocks.flatMap((b) => b.steps)) });
  out.gate = job([renderGateStep(GATE, entries), ...renderGateUploads(p)], { name: 'gate', if: 'always()', needs: [...entries.map((e) => e.job), 'base-scan'], permissions: GATE_PERM });
  return out;
}
function wfOn(on: unknown, jobsIn: Record<string, Job>, raw = false): CreatedFile {
  const f = workflow(jobsIn, raw);
  return { ...f, content: f.content.replace(/^on:\n  pull_request: null\n/m, `on: ${JSON.stringify(on)}\n`) };
}
const gs = (j: Record<string, Job>): RenderedStep => (j.gate?.steps as RenderedStep[])[0] as RenderedStep;
const withGate = (j: Record<string, Job>, steps: RenderedStep[], over: Job = {}): Record<string, Job> => ({ ...j, gate: { ...(j.gate as Job), steps, ...over } });

describe('the baseline: the attack harness draft is clean', () => {
  it('A0: the full draft passes with 0 issues', async () => {
    expect(show(await run([workflow(jobs())], d))).toBe('');
  });
});

describe('finding 1: the job gate decides (ruling 1)', () => {
  const FR = (j: Record<string, Job>): RenderedStep => ({ ...gs(j), with: { mode: 'find-run', sha: '${{ github.sha }}', [GH_IN]: sref('GITHUB_TOKEN') } });
  const NI = (j: Record<string, Job>): RenderedStep => ({ ...gs(j), with: { mode: 'nightly', [GH_IN]: sref('GITHUB_TOKEN') } });
  it('A6: no gate step, a find-run step or a nightly step in the job gate → not-gate-readable', async () => {
    const j = jobs();
    for (const [name, steps] of [['empty', []], ['find-run', [FR(j)]], ['nightly', [NI(j)]]] as const) {
      const r = await run([workflow(withGate(j, [...steps]), true)], d);
      expect(has(r, 'not-gate-readable', /exactly once, in mode gate/), `${name}: ${show(r)}`).toBe(true);
    }
  });
  it('the gate runs even when the draft has no check for it to wait for', async () => {
    const dd = draftOf([], []);
    const noStep = job([], { name: 'gate', if: 'always()', permissions: GATE_PERM });
    expect(has(await run([workflow({ gate: noStep })], dd), 'not-gate-readable', /exactly once, in mode gate/)).toBe(true);
    const ok = job([renderGateStep(GATE, []), ...renderGateUploads(p)], { name: 'gate', if: 'always()', permissions: GATE_PERM });
    expect(show(await run([workflow({ gate: ok })], dd))).toBe('');
  });
  it('A9: two gate steps (mode gate twice, or mode gate and find-run) → not-gate-readable', async () => {
    const j = jobs();
    for (const steps of [[gs(j), FR(j)], [gs(j), structuredClone(gs(j))], [FR(j), gs(j)]]) {
      const r = await run([workflow(withGate(j, steps), true)], d);
      expect(has(r, 'not-gate-readable', /exactly once, in mode gate/), show(r)).toBe(true);
    }
  });
});

describe('finding 2: the gate always runs (ruling 2)', () => {
  it('A7: the job gate without if: always() → refused; with another condition → refused; with always() → fine', async () => {
    const j = jobs();
    const { if: _i, ...noIf } = j.gate as Job;
    expect(has(await run([workflow({ ...j, gate: noIf })], d), 'not-gate-readable', /must have if: always\(\)/)).toBe(true);
    for (const cond of ['success()', 'failure()', '!cancelled()']) {
      expect((await run([workflow({ ...j, gate: { ...(j.gate as Job), if: cond } })], d)).ok, cond).toBe(false);
    }
    expect(show(await run([workflow(j)], d))).toBe('');
  });
});

describe('finding 3: the listed jobs are the real checks (ruling 3)', () => {
  it('A1: a job-status entry whose job is only a checkout, the real script running elsewhere → refused', async () => {
    const j = jobs();
    const r = await run([workflow({ ...j, 'unit-tests--app': job(prelude()), 'tests-real': j['unit-tests--app'] as Job })], d);
    expect(has(r, 'not-gate-readable', /belongs to the job "unit-tests--app".* but sits in the job "tests-real"/), show(r)).toBe(true);
    expect(has(r, 'not-gate-readable', /holds no step of the check/), show(r)).toBe(true);
  });
  it('A1b: a findings entry whose job is only a checkout, the scan, scrub and upload elsewhere → refused', async () => {
    const j = jobs();
    const r = await run([workflow({ ...j, 'sast--web': job(prelude()), elsewhere: j['sast--web'] as Job })], d);
    expect(has(r, 'not-gate-readable', /belongs to the job "sast--web".* but sits in the job "elsewhere"/), show(r)).toBe(true);
    expect(has(r, 'not-gate-readable', /holds no step of the check/), show(r)).toBe(true);
    expect(has(r, 'not-gate-readable', /scrub step of the result .* sits in the job "elsewhere"/), show(r)).toBe(true);
  });
  it('a findings job that holds the tool but declares none of the outputs, or only some → refused', async () => {
    const j = jobs();
    const noOut = { ...(j['sast--app'] as Job) };
    delete noOut.outputs;
    const r = await run([workflow({ ...j, 'sast--app': noOut })], d);
    expect(has(r, 'not-gate-readable', /must declare the output "pipegen-out-sast--app-sha256"/), show(r)).toBe(true);
    const some = { ...(j['sast--app'] as Job), outputs: Object.fromEntries(Object.entries(j['sast--app']?.outputs as Record<string, string>).filter(([k]) => !k.endsWith('-error'))) };
    expect(has(await run([workflow({ ...j, 'sast--app': some })], d), 'not-gate-readable', /must declare the output "pipegen-out-sast--app-error"/)).toBe(true);
  });
  it('a findings job that runs the tool but holds no scrub, or no upload, of its artifact → refused', async () => {
    const j = jobs();
    const steps = j['sast--app']?.steps as RenderedStep[];
    const noScrub = steps.filter((s) => !s.id?.startsWith('scrub-'));
    const r1 = await run([workflow({ ...j, 'sast--app': { ...(j['sast--app'] as Job), steps: noScrub, outputs: undefined } }, true)], d);
    expect(has(r1, 'not-gate-readable', /holds no scrub step of the result "pipegen-out-sast--app"/), show(r1)).toBe(true);
    const noUpload = steps.filter((s) => !s.uses?.startsWith('actions/upload-artifact@'));
    const r2 = await run([workflow({ ...j, 'sast--app': { ...(j['sast--app'] as Job), steps: noUpload } }, true)], d);
    expect(has(r2, 'not-gate-readable', /does not upload the result "pipegen-out-sast--app"/), show(r2)).toBe(true);
  });
  it('A10: the base twin of a check in the head job (and its scrub) → refused; base twins only in base-scan', async () => {
    const j = jobs();
    const bb = block(gitleaksSpec(), { ...ctx, base: true });
    const steps = [...(j.secrets?.steps as RenderedStep[]), ...bb.steps];
    const r = await run([workflow({ ...j, [SEC]: { ...(j.secrets as Job), steps, outputs: jobOutputsFor(steps) } }, true)], d);
    expect(has(r, 'not-gate-readable', /belongs to the job "base-scan".* but sits in the job "secrets"/), show(r)).toBe(true);
  });
  it('A11: base-scan holding the head renders (the PR twin of a check) → refused', async () => {
    const j = jobs();
    const bs = specs.map((s) => block(s));
    const steps = [...prelude({ baseRef: true }), ...bs.flatMap((b) => b.steps)];
    const r = await run([workflow({ ...j, 'base-scan': job(steps, { outputs: jobOutputsFor(steps) }) }, true)], d);
    expect(has(r, 'not-gate-readable', /belongs to the job "secrets".* but sits in the job "base-scan"/), show(r)).toBe(true);
  });
  it('A13: one artifact uploaded by two jobs → refused', async () => {
    const j = jobs();
    const r = await run([workflow({ ...j, 'sast-dup': structuredClone(j['sast--web']) as Job })], d);
    expect(has(r, 'not-gate-readable', /uploaded by more than one step/), show(r)).toBe(true);
  });
});

describe('finding 4: no silent drop in the job list (ruling 4)', () => {
  const dupe = (a: string, b: string, scripts = ['test']): PipelineDraft => {
    const pr = { ...profile([service({ name: a, path: 'a', scripts }), service({ name: b, path: 'b', scripts })]), repoFiles: emptyRepoFiles() };
    return { ...draftOf([], [needOf('unit-tests', a), needOf('unit-tests', b)]), profile: pr };
  };
  it('A8: Web App and web-app (one slug) → GateJobListError', () => {
    expect(() => gateJobList(dupe('Web App', 'web-app'))).toThrow(GateJobListError);
    expect(() => gateJobList(dupe('Web App', 'web-app'))).toThrow(/same job/);
  });
  it('two names that share their first 40 characters → GateJobListError', () => {
    const base = 'a'.repeat(40);
    expect(() => gateJobList(dupe(`${base}-one`, `${base}-two`))).toThrow(GateJobListError);
  });
  it('the same need and service on two layers is still one entry (an exact duplicate is not a collision)', () => {
    const dd = draftOf([], [needOf('unit-tests', 'app'), { ...needOf('unit-tests', 'app'), layer: 'push' }]);
    expect(gateJobList(dd)).toHaveLength(1);
  });
  it('A8s/A8r: through the referee, a collision is not-gate-readable', async () => {
    const dd = dupe('Web App', 'web-app');
    const ok = draftOf([], [needOf('unit-tests', 'app')]);
    const step = renderGateStep(GATE, gateJobList(ok));
    const r = await run([workflow({ gate: job([step], { name: 'gate', if: 'always()', permissions: GATE_PERM }) })], dd);
    expect(has(r, 'not-gate-readable', /same job/), show(r)).toBe(true);
  });
});

describe('finding 5: base-scan checks out the base, and only the base (ruling 5)', () => {
  const bs = (j: Record<string, Job>): RenderedStep[] => j['base-scan']?.steps as RenderedStep[];
  const withBase = (j: Record<string, Job>, steps: RenderedStep[]): Record<string, Job> => ({ ...j, 'base-scan': { ...(j['base-scan'] as Job), steps } });
  it('A2: no ref on the base-scan checkout → refused', async () => {
    const r = await run([workflow(jobs('none'))], d);
    expect(has(r, 'injection', /needs a ref/), show(r)).toBe(true);
  });
  it('A4: a second checkout in base-scan → refused', async () => {
    const j = jobs();
    const steps = bs(j);
    const bent = [steps[0] as RenderedStep, prelude()[0] as RenderedStep, ...steps.slice(1)];
    const r = await run([workflow(withBase(j, bent), true)], d);
    expect(has(r, 'injection', /exactly one checkout/), show(r)).toBe(true);
  });
  it('the checkout is the first step of base-scan after the harden step; a step before it → refused', async () => {
    const j = jobs();
    const steps = bs(j);
    const [first, ...rest] = steps;
    const harden = renderStep(specFor(entry('bullfrog'), { needId: 'egress' }), entry('bullfrog'), p, ctx).steps;
    const ok = await run([workflow(withBase(j, [...harden, first as RenderedStep, ...rest]), true)], d);
    expect(has(ok, 'injection', /checkout/), show(ok)).toBe(false);
    const late = await run([workflow(withBase(j, [rest[0] as RenderedStep, first as RenderedStep, ...rest.slice(1)]), true)], d);
    expect(has(late, 'injection', /first step/), show(late)).toBe(true);
  });
  it('checkJobOrder / dedupeJobSteps: the base-scan rules, directly', () => {
    const one = prelude({ baseRef: true });
    expect(checkJobOrder(one, { id: 'base-scan' })).toEqual([]);
    expect(checkJobOrder(prelude(), { id: 'base-scan' }).join(' ')).toMatch(/needs a ref/);
    expect(checkJobOrder([...one, ...prelude()], { id: 'base-scan' }).join(' ')).toMatch(/exactly one checkout/);
    expect(checkJobOrder([], { id: 'base-scan' }).join(' ')).toMatch(/exactly one checkout/);
    expect(() => dedupeJobSteps(prelude({ baseRef: true }), { id: 'secrets', scans: NO_SCANS })).toThrow(RenderError);   // the base ref outside base-scan
  });
});

describe('minor findings (ruling 6)', () => {
  const U = 'crisworking/pipegen/gate';
  const pol = (block: string[], warn: string[]): string => JSON.stringify({ block, warn });
  const bad = (t: string): boolean => rendererInputProblems(U, { policy: t }, { mode: 'gate', policy: t }).length > 0;
  it('7: a policy must block at least critical and high, with no duplicate and no severity in both lists', () => {
    expect(bad(pol([], []))).toBe(true);
    expect(bad(pol(['info'], ['critical', 'high']))).toBe(true);
    expect(bad(pol(['critical'], ['medium']))).toBe(true);
    expect(bad(pol(['high'], ['medium']))).toBe(true);
    expect(bad(pol(['critical', 'high', 'high'], ['medium']))).toBe(true);
    expect(bad(pol(['critical', 'high', 'medium'], ['medium']))).toBe(true);
    expect(bad(pol(['critical', 'high'], ['medium', 'medium']))).toBe(true);
    expect(bad(pol(['critical', 'high'], ['medium']))).toBe(false);
    expect(bad(pol(['critical', 'high', 'medium'], ['low']))).toBe(false);
    expect(bad(pol(['critical', 'high'], []))).toBe(false);
  });
  it('10: dedupeJobSteps needs the scan facts (a call without them is refused at run time too)', () => {
    const g = block(gitleaksSpec());
    expect(() => (dedupeJobSteps as (s: RenderedStep[], j?: unknown) => unknown)([...prelude(), ...g.steps])).toThrow(RenderError);
    expect(() => dedupeJobSteps([...prelude(), ...g.steps], { scans: facts(g) })).not.toThrow();
  });
  it('6 (M2): jobOutputsProblems with two scrub steps for one artifact is refused on its own', () => {
    const g = block(gitleaksSpec());
    const twice = [...prelude(), ...g.result.steps, g.scrub, { ...g.scrub, id: 'scrub-ffffffffffffffff' }];
    expect(jobOutputsProblems('secrets', jobOutputsFor([g.scrub]), twice).join('\n')).toMatch(/more than one scrub step/);
  });
  it('6 (M28): an expression in a job\'s needs is refused', async () => {
    const j = jobs();
    const r = await run([workflow({ ...j, gate: { ...(j.gate as Job), needs: [...entries.map((e) => e.job), '${{ github.ref }}'] } })], d);
    expect(has(r, 'injection', /expression .* in needs/), show(r)).toBe(true);
  });
});

// ---------- C3: the gate action's own mode for the job baseline-check ----------

describe('C3: mode baseline-check runs in the job baseline-check and nowhere else', () => {
  // the step the renderer writes; `over` adds or replaces inputs (raw YAML only: the emitter refuses a hostile expression)
  const BC = (_j: Record<string, Job>, over: Record<string, string | undefined> = {}): RenderedStep => {
    const s = renderBaselineCheckStep(GATE);
    return Object.keys(over).length === 0 ? s : { ...s, with: { ...(s.with as Record<string, string>), ...(over as Record<string, string>) } };
  };
  const BC_JOB = (steps: RenderedStep[]): Job => job(steps, { permissions: { contents: 'read', actions: 'read' } });
  it('the job baseline-check with one gate step in mode baseline-check passes the referee', async () => {
    const j = jobs();
    expect(show(await run([workflow({ ...j, 'baseline-check': BC_JOB([BC(j)]) })], d))).toBe('');
    expect(BC(j).with).toEqual({ mode: 'baseline-check', [GH_IN]: sref('GITHUB_TOKEN'), [FP_IN]: sref('PIPEGEN_FP_KEY') });
  });
  it('mode baseline-check in any other job is refused (a tool job, the gate, nightly, pipegen-verify)', async () => {
    const j = jobs();
    const other = (id: string, extra: Job): Record<string, Job> => ({ ...j, [id]: { ...(j[id] ?? job([])), ...extra } });
    const r1 = await run([workflow(other('sast--app', { steps: [...((j['sast--app'] as Job).steps as RenderedStep[]), BC(j)] }), true)], d);
    expect(has(r1, 'permissions', /gate action/), show(r1)).toBe(true);
    const r2 = await run([workflow(withGate(j, [BC(j)]), true)], d);
    expect(has(r2, 'not-gate-readable', /exactly once, in mode gate/), show(r2)).toBe(true);
    const r3 = await run([workflow({ ...j, nightly: job([BC(j)], { permissions: { contents: 'read', actions: 'read', issues: 'write' } }) }, true)], d);
    expect(has(r3, 'permissions', /baseline-check/), show(r3)).toBe(true);
    const r4 = await run([workflow({ ...j, 'pipegen-verify': job([BC(j)], { permissions: { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' }, environment: 'pipegen-signing' }) }, true)], d);
    expect(has(r4, 'permissions', /baseline-check/), show(r4)).toBe(true);
  });
  it('the job baseline-check runs only mode baseline-check, exactly once (no gate, nightly or find-run step; not two)', async () => {
    const j = jobs();
    const FR = { ...gs(j), with: { mode: 'find-run', sha: '${{ github.sha }}', [GH_IN]: sref('GITHUB_TOKEN') } };
    const NI = { ...gs(j), with: { mode: 'nightly', [GH_IN]: sref('GITHUB_TOKEN') } };
    for (const [name, steps] of [['gate', [gs(j)]], ['find-run', [FR]], ['nightly', [NI]], ['two', [BC(j), BC(j)]], ['none', []], ['baseline-check and find-run', [BC(j), FR]]] as const) {
      const r = await run([workflow({ ...j, 'baseline-check': BC_JOB([...steps]) }, true)], d);
      expect(has(r, 'permissions', /baseline-check/), `${name}: ${show(r)}`).toBe(true);
    }
  });
  it('mode baseline-check takes only its inputs: token and key, no gate or nightly input', async () => {
    const j = jobs();
    for (const extra of [{ jobs: '${{ toJSON(needs) }}' }, { 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}' }, { 'merged-at': '2026-10-29T12:00:00Z' }, { sha: '${{ github.sha }}' }]) {
      const r = await run([workflow({ ...j, 'baseline-check': BC_JOB([BC(j, extra)]) }, true)], d);
      expect(has(r, 'template', /allowed only in mode/), `${Object.keys(extra)[0]}: ${show(r)}`).toBe(true);
    }
    const r = await run([workflow({ ...j, 'baseline-check': BC_JOB([BC(j, { [GH_IN]: sref('PIPEGEN_FP_KEY') })]) }, true)], d);
    expect(r.ok).toBe(false);
  });
});

// ---------- C3 fix round 1 (review-C3 m2, m9) ----------

describe('C3 fix round 1: baseline-check row and recorded-date checks', () => {
  it('m9: the job baseline-check holds the key, so its row allows no checkout (nor any step but harden, download-artifact and the gate step)', async () => {
    const j = jobs();
    const co = prelude()[0] as RenderedStep;
    const bc = renderBaselineCheckStep(GATE);
    const perm = { contents: 'read', actions: 'read' };
    const r = await run([workflow({ ...j, 'baseline-check': job([co, bc], { permissions: perm }) })], d);
    expect(has(r, 'permissions', /checkout/), show(r)).toBe(true);
    expect(show(await run([workflow({ ...j, 'baseline-check': job([bc], { permissions: perm }) })], d))).toBe('');
  });
  it('m2: block-from-recorded must be a real calendar date (no 2026-02-30, 2026-04-31, 0000-01-01) in the renderer row and so in the referee', () => {
    const base: Record<string, string> = { mode: 'nightly', [GH_IN]: sref('GITHUB_TOKEN'), 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', 'merged-at': '2026-10-29T12:00:00Z' };
    expect(rendererInputProblems('crisworking/pipegen/gate', { ...base, 'block-from-recorded': '2028-02-29' }, { ...base, 'block-from-recorded': '2028-02-29' })).toEqual([]);
    for (const bad of ['2026-02-30', '2026-04-31', '2027-02-29', '0000-01-01', '2026-13-01', '2026-00-10']) {
      const w = { ...base, 'block-from-recorded': bad };
      expect(rendererInputProblems('crisworking/pipegen/gate', w, w).some((x) => /block-from-recorded/.test(x)), bad).toBe(true);
    }
  });
});
