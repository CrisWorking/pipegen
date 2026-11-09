// v0.2 Plan G G17 group A (the hardening round; rows 1, 5, 6, 7 of task-G17-brief.md): the referee holds what only assemble held before
// (G5 m3), refuses a gate holder outside the B2 layout, refuses an app-repo copy of the central required workflow, and never lets one
// service's floor check drop out of the gate's list while another service's check of the same need keeps the gate's floor satisfied.
import { describe, expect, it } from 'vitest';
import { Document } from 'yaml';
import { CALLER_WORKFLOW, LOCAL_MERGE_WORKFLOW, PUSH_WORKFLOW, WORKFLOW_CONCURRENCY } from '../src/engine/job-rules.js';
import { referee, type RefereeReport } from '../src/engine/referee.js';
import { renderJobPrelude, renderStep, stepsToYaml, type RenderedStep } from '../src/engine/render-step.js';
import type { CreatedFile, PipelineDraft, ReviewedTool } from '../src/types.js';
import { draftOf, GATE, job, jobsOf, needOf, p, prof, run, show, specs, workflow as stepsWorkflow, type Job } from './helpers/gate-pipeline.js';
import { reviewedList, specFor } from './helpers/render.js';
import { withEgress } from './helpers/egress-step.js';

const d = draftOf();
/** The helper's workflow, also with reusable-workflow caller jobs (a job with `uses` and no steps). */
function workflow(jobs: Record<string, Job>, top: Record<string, unknown> = {}): CreatedFile {
  if (Object.values(jobs).every((j) => Array.isArray(j.steps))) return stepsWorkflow(jobs, top);
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, ...top, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) if (Array.isArray(j.steps)) doc.setIn(['jobs', id, 'steps'], stepsToYaml(withEgress(j.steps as RenderedStep[])));
  return { path: CALLER_WORKFLOW, content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
const at = (f: CreatedFile, path: string, repo: CreatedFile['repo'] = 'app'): CreatedFile => ({ ...f, path, repo });
const has = (r: RefereeReport, check: string, re: RegExp): boolean => r.issues.some((i) => i.check === check && re.test(i.message));
const CONC = { concurrency: { ...WORKFLOW_CONCURRENCY } };
const gateFile = (top: Record<string, unknown> = {}): CreatedFile => workflow(jobsOf(d), { ...CONC, ...top });
const GATE_PERMS = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
/** The local merge file (public layout) and pipegen.yml's merge caller. */
const merge = (call: unknown = null): CreatedFile => at(workflow(jobsOf(d), { on: { workflow_call: call } }), LOCAL_MERGE_WORKFLOW);
const caller = (over: Job = {}, top: Record<string, unknown> = CONC, path = CALLER_WORKFLOW): CreatedFile =>
  at(workflow({ pipegen: { name: 'pipegen', uses: `./${LOCAL_MERGE_WORKFLOW}`, permissions: GATE_PERMS, ...over } }, top), path);
const FP = ['PIPEGEN', 'FP', 'KEY'].join('_');
const SLACK = ['PIPEGEN', 'SLACK', 'WEBHOOK'].join('_');
const ref = (n: string): string => `\${{ ${['sec', 'rets'].join('')}.${n} }}`;

describe('G17 row 1 (G5 m3): the referee holds the guarantees only assemble held', () => {
  it('G17 row 1a: a whole file declares no workflow_call input or output (secrets only)', async () => {
    for (const call of [{ inputs: { ref: { type: 'string' } } }, { outputs: { x: { value: 'y' } } }, { secrets: {}, inputs: {} }]) {
      const r = await run([caller(), merge(call)], d);
      expect(has(r, 'injection', /declares a workflow_call input or output/), `${JSON.stringify(call)}: ${show(r)}`).toBe(true);
    }
    for (const call of [null, {}, { secrets: { [FP]: { required: false } } }]) {
      const r = await run([caller(call === null || Object.keys(call).length === 0 ? {} : { secrets: { [FP]: ref(FP) } }), merge(call)], d);
      expect(has(r, 'injection', /declares a workflow_call input or output/), `${JSON.stringify(call)}: ${show(r)}`).toBe(false);
    }
  });
  it('G17 row 1b: pipegen.yml and pipegen-push.yml carry the workflow concurrency', async () => {
    const r = await run([workflow(jobsOf(d))], d);
    expect(has(r, 'template', /must carry the workflow concurrency/), show(r)).toBe(true);
    expect(show(await run([gateFile()], d))).toBe('');
    const push = at(workflow({ a: job(renderJobPrelude({}, p).steps) }, { on: { push: { 'branches-ignore': ['main'] } } }), PUSH_WORKFLOW);
    expect(has(await run([gateFile(), push], d), 'template', /must carry the workflow concurrency/)).toBe(true);
    expect(has(await run([gateFile(), at(workflow({ a: job(renderJobPrelude({}, p).steps) }, { on: { push: { 'branches-ignore': ['main'] } }, ...CONC }), PUSH_WORKFLOW)], d), 'template', /must carry the workflow concurrency/)).toBe(false);
  });
  it('G17 row 1d: a caller maps no secret its callee does not declare and read', async () => {
    const declared = { secrets: { [FP]: { required: false } } };
    // the control: the scrub steps of the merge file read the fingerprint key, which it declares and its caller maps
    expect(show(await run([caller({ secrets: { [FP]: ref(FP) } }), merge(declared)], d))).toBe('');
    // an allowed name the callee neither declares nor reads (G5 attacks 13, 14, P5)
    const r1 = await run([caller({ secrets: { [FP]: ref(FP), [SLACK]: ref(SLACK) } }), merge(declared)], d);
    expect(has(r1, 'permissions', new RegExp(`passes the secret "${SLACK}", which the called workflow does not declare and read`)), show(r1)).toBe(true);
    // declared but never read
    const r2 = await run([caller({ secrets: { [FP]: ref(FP), [SLACK]: ref(SLACK) } }), merge({ secrets: { [FP]: { required: false }, [SLACK]: { required: false } } })], d);
    expect(has(r2, 'permissions', new RegExp(`passes the secret "${SLACK}", which the called workflow does not declare and read`)), show(r2)).toBe(true);
    // read but not declared (GitHub would refuse the call)
    const r3 = await run([caller({ secrets: { [FP]: ref(FP) } }), merge(null)], d);
    expect(has(r3, 'permissions', new RegExp(`passes the secret "${FP}", which the called workflow does not declare and read`)), show(r3)).toBe(true);
  });
  it('G17 row 1e: a public draft carries no central pin', async () => {
    const pinned: PipelineDraft = { ...d, centralPin: { repo: 'o/pipelines', sha: 'c'.repeat(40) } };
    expect(d.profile.private).toBe(false);
    expect(has(await run([gateFile()], pinned), 'template', /A public repository keeps its workflows in the app/)).toBe(true);
    expect(has(await run([gateFile()], d), 'template', /A public repository keeps its workflows in the app/)).toBe(false);
  });
});

describe('G17 row 5 (open question 4): no app or central workflow outside the B2 layout holds or calls the gate', () => {
  it('G17 row 5: ci.yml with workflow_dispatch holding the gate, or calling the merge file, is refused; the layout files are not', async () => {
    const outside = /outside pipegen's layout/;
    const ci = await run([at(workflow(jobsOf(d), { on: { workflow_dispatch: null, pull_request: null } }), '.github/workflows/ci.yml')], d);
    expect(has(ci, 'not-gate-readable', outside), show(ci)).toBe(true);
    const calls = await run([merge(), caller({}, { on: { workflow_dispatch: null } }, '.github/workflows/ci.yml')], d);
    expect(has(calls, 'not-gate-readable', outside), show(calls)).toBe(true);
    const central = await run([at(workflow(jobsOf(d), { on: { workflow_call: null } }), '.github/workflows/r--sign.yml', 'central')], d);
    expect(has(central, 'not-gate-readable', outside), show(central)).toBe(true);
    // the layout: pipegen.yml holding it, the local merge file holding it and pipegen.yml calling it, the central merge file
    expect(has(await run([gateFile()], d), 'not-gate-readable', outside)).toBe(false);
    expect(has(await run([caller(), merge()], d), 'not-gate-readable', outside)).toBe(false);
    expect(has(await run([at(workflow(jobsOf(d), { on: { workflow_call: null } }), '.github/workflows/r--merge.yml', 'central')], d), 'not-gate-readable', outside)).toBe(false);
  });
});

describe('G17 row 6 (open question 5): the required-workflow form is central-only', () => {
  it('G17 row 6: an app-repo workflow named <name>--required.yml is refused', async () => {
    for (const path of ['.github/workflows/r--required.yml', '.github/workflows/other--required.yaml']) {
      const r = await run([gateFile(), at(caller({}, { on: { pull_request: null } }), path), merge()], d);
      expect(has(r, 'template', /--required\.yml is the central org required workflow/), `${path}: ${show(r)}`).toBe(true);
    }
    expect(has(await run([caller(), merge()], d), 'template', /--required\.yml is the central org required workflow/)).toBe(false);
  });
});

describe('G17 row 7 (G9 carry 13): a per-service floor check never drops out while another check of the same need keeps the gate\'s floor', () => {
  /** gitleaks edited to write JUnit (every reviewed floor tool writes SARIF today: the edit is the shape B7 demotes, as in referee.test.ts). */
  const list = (): ReviewedTool[] => reviewedList().map((t) => (t.id === 'gitleaks' ? { ...t, step: { ...t.step, output: { ...t.step.output, format: 'junit' as const } } } : t));
  const unreadable = (): ReviewedTool => list().find((t) => t.id === 'gitleaks') as ReviewedTool;
  const go = (files: CreatedFile[], dr: PipelineDraft): Promise<RefereeReport> => referee(files, dr, p, list(), { actionlint: async () => '/stub', zizmor: async () => '/stub' }, 'tok', { runLinters: async () => [] });
  const SEC = ['sec', 'rets'].join('');
  const withWeb = (needs: PipelineDraft['needs'], steps: PipelineDraft['steps']): { dr: PipelineDraft; files: CreatedFile[] } => {
    const web = specFor(unreadable(), { needId: SEC, service: 'web' });
    const dr = draftOf({ needs: [...needs, needOf(SEC, 'web')], steps: [...steps, web] });
    const jobs = { ...jobsOf(dr), [`${SEC}--web`]: job([...renderJobPrelude({}, p).steps, ...renderStep(web, unreadable(), p, { profile: dr.profile }).steps]) };
    return { dr, files: [workflow(jobs, CONC)] };
  };
  it('G17 row 7: one service\'s floor check writes nothing readable while the same need stays in the gate\'s list → refused', async () => {
    const { dr, files } = withWeb(draftOf().needs, specs());
    const r = await go(files, dr);
    expect(r.demoted).toContain(`${SEC}--web`);
    expect(has(r, 'not-gate-readable', new RegExp(`floor check "${SEC}" for "web" writes nothing the gate can read, while another check of "${SEC}" is in the gate's list`)), show(r)).toBe(true);
  });
  it('G17 row 7: a floor check demoted with no other check of its need stays a note (B7)', async () => {
    const needs = draftOf().needs.filter((n) => n.id !== SEC);
    const { dr, files } = withWeb(needs, specs().filter((s) => s.needId !== SEC));
    const r = await go(files, dr);
    expect(r.demoted).toContain(`${SEC}--web`);
    expect(has(r, 'not-gate-readable', /floor check/), show(r)).toBe(false);
  });
});
