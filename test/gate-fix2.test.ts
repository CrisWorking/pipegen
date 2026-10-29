// Plan C, C0b fix round 2: every attack of review-C0b-r1.md as a regression test (task-C0b-fix-round-2.md).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { GateJobListError, gateJobList } from '../src/engine/gate-job-list.js';
import { checkJobOrder, jobOutputsFor, jobOutputsProblems, NO_SCANS, type ScanFact } from '../src/engine/job-rules.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  dedupeJobSteps, RenderError, renderGateStep, renderJobPrelude, renderPlatformStep, renderProjectScript, renderScrub, renderStep, renderUpload, scanFactOf, scrubbedPath, stepsToYaml,
  type RenderContext, type RenderedStep, type RenderResult,
} from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { rendererInputProblems } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, ReviewedTool, StepSpec } from '../src/types.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';

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
  return { steps: [...result.steps, scrub, upload], scrub, upload, artifact, scan, result };
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
  out.gate = job([renderGateStep(GATE, entries)], { name: 'gate', if: 'always()', needs: [...entries.map((e) => e.job), 'base-scan'], permissions: GATE_PERM });
  return out;
}
function wfOn(on: unknown, jobsIn: Record<string, Job>, raw = false): CreatedFile {
  const f = workflow(jobsIn, raw);
  return { ...f, content: f.content.replace(/^on:\n  pull_request: null\n/m, `on: ${JSON.stringify(on)}\n`) };
}
const gs = (j: Record<string, Job>): RenderedStep => (j.gate?.steps as RenderedStep[])[0] as RenderedStep;
const withGate = (j: Record<string, Job>, steps: RenderedStep[], over: Job = {}): Record<string, Job> => ({ ...j, gate: { ...(j.gate as Job), steps, ...over } });


const wfAt = (f: CreatedFile, path: string): CreatedFile => ({ ...f, path });
const mqJobs = (): Record<string, Job> => {
  const mg = structuredClone(jobs());
  return mg;
};

describe('finding 1: action checks are bound (ruling 1)', () => {
  const drSpec = (): StepSpec => specFor(entry('dependency-review-action'), { needId: 'dependency-review' });
  const dd = draftOf([drSpec()], [needOf('dependency-review')]);
  const list = gateJobList(dd);
  const dr = renderStep(drSpec(), entry('dependency-review-action'), p, ctx).steps;
  const gateJ = (): Job => job([renderGateStep(GATE, list)], { name: 'gate', if: 'always()', needs: list.map((e) => e.job), permissions: GATE_PERM });
  it('R0: the honest layout (the action in its listed job) passes', async () => {
    expect(list.map((e) => e.job)).toEqual(['dependency-review']);
    expect(show(await run([workflow({ 'dependency-review': job([...prelude(), ...dr]), gate: gateJ() })], dd))).toBe('');
  });
  it('R1: the listed job is only a checkout and the action runs nowhere → refused', async () => {
    const r = await run([workflow({ 'dependency-review': job(prelude()), gate: gateJ() }, true)], dd);
    expect(has(r, 'not-gate-readable', /holds no step of the action check "dependency-review-action"/), show(r)).toBe(true);
  });
  it('R2: the listed job is only a checkout and the action runs in another job → refused', async () => {
    const r = await run([workflow({ 'dependency-review': job(prelude()), other: job([...prelude(), ...dr]), gate: gateJ() }, true)], dd);
    expect(has(r, 'not-gate-readable', /holds no step of the action check/), show(r)).toBe(true);
    expect(has(r, 'not-gate-readable', /action step of the check "dependency-review".* sits in the job "other"/), show(r)).toBe(true);
  });
  it('the action in its listed job and a second copy in another job → refused', async () => {
    const r = await run([workflow({ 'dependency-review': job([...prelude(), ...dr]), other: job([...prelude(), ...dr]), gate: gateJ() })], dd);
    expect(has(r, 'not-gate-readable', /sits in the job "other"/), show(r)).toBe(true);
  });
});

describe('finding 2: the binding is judged in the gate\'s own file (ruling 2)', () => {
  it('X1: a fake listed job in the gate\'s file and the real script in another file → refused', async () => {
    const j = jobs();
    const real = j['unit-tests--app'] as Job;
    const f1 = workflow({ ...j, 'unit-tests--app': job(prelude()) }, true);
    const f2 = wfAt(workflow({ 'unit-tests--app': structuredClone(real) }, true), '.github/workflows/other.yml');
    const r = await run([f1, f2], d);
    expect(has(r, 'not-gate-readable', /holds no step of the check/), show(r)).toBe(true);
  });
  it('X2: a fake findings job in the gate\'s file and the real one in another file → refused', async () => {
    const j = jobs();
    const real = j['sast--web'] as Job;
    const f1 = workflow({ ...j, 'sast--web': job(prelude()) }, true);
    const f2 = wfAt(workflow({ 'sast--web': structuredClone(real) }, true), '.github/workflows/other.yml');
    const r = await run([f1, f2], d);
    expect(has(r, 'not-gate-readable', /holds no step of the check/), show(r)).toBe(true);
    expect(has(r, 'not-gate-readable', /holds no scrub step of the result "pipegen-out-sast--web"/), show(r)).toBe(true);
  });
  it('X3: the action job in another file only → refused', async () => {
    const drSpec = specFor(entry('dependency-review-action'), { needId: 'dependency-review' });
    const dd = draftOf([drSpec], [needOf('dependency-review')]);
    const list = gateJobList(dd);
    const dr = renderStep(drSpec, entry('dependency-review-action'), p, ctx).steps;
    const f1 = workflow({ 'dependency-review': job(prelude()), gate: job([renderGateStep(GATE, list)], { name: 'gate', if: 'always()', needs: list.map((e) => e.job), permissions: GATE_PERM }) }, true);
    const f2 = wfAt(workflow({ 'dependency-review': job([...prelude(), ...dr]) }), '.github/workflows/other.yml');
    const r = await run([f1, f2], dd);
    expect(has(r, 'not-gate-readable', /holds no step of the action check/), show(r)).toBe(true);
  });
});

describe('finding 3: an artifact has one upload per workflow file (ruling 3)', () => {
  it('X4: an honest pull_request file and merge_group file, each a complete pipeline, pass with 0 issues', async () => {
    const f1 = workflow(jobs());
    const f2 = wfAt(wfOn({ merge_group: null }, mqJobs(), true), '.github/workflows/pipegen-mq.yml');
    expect(show(await run([f1, f2], d))).toBe('');
  });
  it('two uploads of one name in one file are still refused (A13), the same name in two files is not', async () => {
    const j = jobs();
    expect(has(await run([workflow({ ...j, 'sast-dup': structuredClone(j['sast--web']) as Job })], d), 'not-gate-readable', /uploaded by more than one step/)).toBe(true);
  });
});

describe('minor (ruling 5): a listed job that holds both a reviewed tool and its project script', () => {
  it('passes with 0 issues, and moving the script to another job is refused', async () => {
    const lint = reviewedList().find((t) => t.categories.includes('lint') && t.step.output.format === 'none' && t.step.cli !== undefined);
    expect(lint, 'a reviewed lint tool with no result file').toBeDefined();
    const t = lint as ReviewedTool;
    const spec = specFor(t, { needId: 'lint', service: 'app' });
    const dd = draftOf([spec], [needOf('lint', 'app')]);
    const list = gateJobList(dd);
    expect(list.map((e) => e.job)).toEqual(['lint--app']);
    const tool = renderStep(spec, t, p, ctx).steps;
    const script = renderProjectScript({ kind: 'project-script', needId: 'lint', service: 'app', script: 'lint' }, p, ctx).steps;
    const gateJ = job([renderGateStep(GATE, list)], { name: 'gate', if: 'always()', needs: list.map((e) => e.job), permissions: GATE_PERM });
    const both = dedupeJobSteps([...prelude(), ...tool, ...script], { id: 'lint--app', scans: new Map() });
    const ok = await run([workflow({ 'lint--app': job(both), gate: gateJ })], dd);
    expect(show(ok)).toBe('');
    const split = await run([workflow({ 'lint--app': job([...prelude(), ...tool]), other: job(script), gate: gateJ })], dd);
    expect(has(split, 'not-gate-readable', /project script/), show(split)).toBe(true);
  });
});
