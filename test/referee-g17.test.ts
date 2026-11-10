// v0.2 Plan G G17 group A (the hardening round; rows 1, 5, 6, 7 of task-G17-brief.md): the referee holds what only assemble held before
// (G5 m3), refuses a gate holder outside the B2 layout, refuses an app-repo copy of the central required workflow, and never lets one
// service's floor check drop out of the gate's list while another service's check of the same need keeps the gate's floor satisfied.
import { describe, expect, it } from 'vitest';
import { Document } from 'yaml';
import { CALLER_WORKFLOW, LOCAL_MERGE_WORKFLOW, PUSH_WORKFLOW, WORKFLOW_CONCURRENCY } from '../src/engine/job-rules.js';
import { referee, VERIFY_JOB, type RefereeReport } from '../src/engine/referee.js';
import { VERIFY_JOB_ID } from '../src/layers/assemble.js';
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
const SEC_CTX = ['sec', 'rets'].join('');
const ref = (n: string): string => `\${{ ${SEC_CTX}.${n} }}`;

describe('G17 row 1 (G5 m3): the referee holds the guarantees only assemble held', () => {
  it('G17 row 1a: a whole file declares no workflow_call input or output (secrets only)', async () => {
    for (const call of [{ inputs: { ref: { type: 'string' } } }, { outputs: { x: { value: 'y' } } }, { [SEC_CTX]: {}, inputs: {} }]) {
      const r = await run([caller(), merge(call)], d);
      expect(has(r, 'injection', /declares a workflow_call input or output/), `${JSON.stringify(call)}: ${show(r)}`).toBe(true);
    }
    for (const call of [null, {}, { [SEC_CTX]: { [FP]: { required: false } } }]) {
      const r = await run([caller(call === null || Object.keys(call).length === 0 ? {} : { [SEC_CTX]: { [FP]: ref(FP) } }), merge(call)], d);
      expect(has(r, 'injection', /declares a workflow_call input or output/), `${JSON.stringify(call)}: ${show(r)}`).toBe(false);
    }
  });
  it('G17 row 1b: pipegen.yml and pipegen-push.yml carry the workflow concurrency', async () => {
    const NO_CONC = { concurrency: undefined };
    const r = await run([workflow(jobsOf(d), NO_CONC)], d);
    expect(has(r, 'template', /must carry the workflow concurrency/), show(r)).toBe(true);
    expect(show(await run([gateFile()], d))).toBe('');
    const push = at(workflow({ a: job(renderJobPrelude({}, p).steps) }, { on: { push: { 'branches-ignore': ['main'] } }, ...NO_CONC }), PUSH_WORKFLOW);
    expect(has(await run([gateFile(), push], d), 'template', /must carry the workflow concurrency/)).toBe(true);
    expect(has(await run([gateFile(), at(workflow({ a: job(renderJobPrelude({}, p).steps) }, { on: { push: { 'branches-ignore': ['main'] } }, ...CONC }), PUSH_WORKFLOW)], d), 'template', /must carry the workflow concurrency/)).toBe(false);
  });
  it('G17 row 1d: a caller maps no secret its callee does not declare and read', async () => {
    const declared = { [SEC_CTX]: { [FP]: { required: false } } };
    // the control: the scrub steps of the merge file read the fingerprint key, which it declares and its caller maps
    expect(show(await run([caller({ [SEC_CTX]: { [FP]: ref(FP) } }), merge(declared)], d))).toBe('');
    // an allowed name the callee neither declares nor reads (G5 attacks 13, 14, P5)
    const r1 = await run([caller({ [SEC_CTX]: { [FP]: ref(FP), [SLACK]: ref(SLACK) } }), merge(declared)], d);
    expect(has(r1, 'permissions', new RegExp(`passes the secret "${SLACK}", which the called workflow does not declare and read`)), show(r1)).toBe(true);
    // declared but never read
    const r2 = await run([caller({ [SEC_CTX]: { [FP]: ref(FP), [SLACK]: ref(SLACK) } }), merge({ [SEC_CTX]: { [FP]: { required: false }, [SLACK]: { required: false } } })], d);
    expect(has(r2, 'permissions', new RegExp(`passes the secret "${SLACK}", which the called workflow does not declare and read`)), show(r2)).toBe(true);
    // read but not declared (GitHub would refuse the call)
    const r3 = await run([caller({ [SEC_CTX]: { [FP]: ref(FP) } }), merge(null)], d);
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
  // G17A-R1 sec I3: the gate builds its floor from its job list (gate/src/settings.ts floorNeeds), which holds no demoted check, so a floor
  // findings check demoted alone is never reported missing (only secrets is always in the floor): refused like the per-service case
  it('G17A-R1 sec I3: a floor check demoted with no other check of its need is refused too (the gate floors only what its job list holds)', async () => {
    const needs = draftOf().needs.filter((n) => n.id !== SEC);
    const { dr, files } = withWeb(needs, specs().filter((s) => s.needId !== SEC));
    const r = await go(files, dr);
    expect(r.demoted).toContain(`${SEC}--web`);
    expect(has(r, 'not-gate-readable', new RegExp(`floor check "${SEC}" for "web" writes nothing the gate can read`)), show(r)).toBe(true);
  });
  it('G17A-R1 sec I3 (probe "row7 alone"): sast demoted alone (one service, semgrep writing JUnit) is refused', async () => {
    const sgList = (): ReviewedTool[] => reviewedList().map((t) => (t.id === 'semgrep' ? { ...t, step: { ...t.step, output: { ...t.step.output, format: 'junit' as const } } } : t));
    const sg = sgList().find((t) => t.id === 'semgrep') as ReviewedTool;
    const webSpec = specFor(sg, { needId: 'sast', service: 'web' });
    const base = draftOf();
    const dr = draftOf({ needs: [...base.needs.filter((n) => n.id !== 'sast'), needOf('sast', 'web')], steps: [...specs().filter((s) => s.needId !== 'sast'), webSpec] });
    const jobs = { ...jobsOf(dr), 'sast--web': job([...renderJobPrelude({}, p).steps, ...renderStep(webSpec, sg, p, { profile: dr.profile }).steps]) };
    const r = await referee([workflow(jobs, CONC)], dr, p, sgList(), { actionlint: async () => '/stub', zizmor: async () => '/stub' }, 'tok', { runLinters: async () => [] });
    expect(r.demoted).toContain('sast--web');
    expect(has(r, 'not-gate-readable', /floor check "sast" for "web" writes nothing the gate can read/), show(r)).toBe(true);
  });
  // G17A-R1 sec M1 (the row 7 survivor): the rule is the floor's only; a non-floor findings check demoted for one service is B7's note
  it('G17 row 7: a non-floor findings check demoted for one service while another service keeps it in the gate\'s list stays a note (B7)', async () => {
    const iacList = (): ReviewedTool[] => reviewedList().map((t) => (t.id === 'trivy-config' ? { ...t, step: { ...t.step, output: { ...t.step.output, format: 'junit' as const } } } : t));
    const tc = iacList().find((t) => t.id === 'trivy-config') as ReviewedTool;
    const kl = iacList().find((t) => t.id === 'kube-linter') as ReviewedTool;
    const webSpec = specFor(tc, { needId: 'iac', service: 'web' });
    const appSpec = specFor(kl, { needId: 'iac', service: 'app' });
    const nf = (svc: string) => ({ ...needOf('iac', svc), floor: false });
    const base = draftOf();
    const dr = draftOf({ profile: { ...base.profile, repoFiles: { ...base.profile.repoFiles, kubernetes: true } }, needs: [...base.needs, nf('app'), nf('web')], steps: [...specs(), appSpec, webSpec] });
    const jobs = { ...jobsOf(dr), 'iac--web': job([...renderJobPrelude({}, p).steps, ...renderStep(webSpec, tc, p, { profile: dr.profile }).steps]) };
    const r = await referee([workflow(jobs, CONC)], dr, p, iacList(), { actionlint: async () => '/stub', zizmor: async () => '/stub' }, 'tok', { runLinters: async () => [] });
    expect(r.demoted, show(r)).toContain('iac--web');
    expect(r.demoted, show(r)).not.toContain('iac--app');
    expect(show(r)).not.toMatch(/floor check/);
  });
});

describe('G17A-R1 sec N1, spec M4: a callee reads a mapped secret only in an expression, by its exact name', () => {
  const SLACK_DECLARED = { [SEC_CTX]: { [FP]: { required: false }, [SLACK]: { required: false } } };
  /** The local merge file with one more job whose last step runs `text` (written into the YAML as is: the renderer takes no expression). */
  const mergeWith = (call: unknown, text: string): CreatedFile => {
    const f = at(workflow({ ...jobsOf(d), note: job([...renderJobPrelude({}, p).steps, { name: 'notify', run: 'echo NOTE_TEXT' }]) }, { on: { workflow_call: call } }), LOCAL_MERGE_WORKFLOW);
    expect(f.content.split('NOTE_TEXT').length).toBe(2);
    return { ...f, content: f.content.replace('NOTE_TEXT', text) };
  };
  const expr = (inner: string): string => `\${{ ${inner} }}`;
  const passes = caller({ [SEC_CTX]: { [FP]: ref(FP), [SLACK]: ref(SLACK) } });
  const unread = new RegExp(`passes the secret "${SLACK}", which the called workflow does not declare and read`);
  it('G17A-R1 sec N1: secrets.NAME outside ${{ }} (a step name, run text) reads nothing', async () => {
    const named = await run([passes, mergeWith(SLACK_DECLARED, `notify with ${SEC_CTX}.${SLACK}`)], d);
    expect(has(named, 'permissions', unread), show(named)).toBe(true);
    const read = await run([passes, mergeWith(SLACK_DECLARED, ref(SLACK))], d);
    expect(has(read, 'permissions', unread), show(read)).toBe(false);
  });
  it('G17A-R1 spec M4: the bracket form and any spelling of the context read the name; the name itself matches exactly, as declared', async () => {
    const bracket = await run([passes, mergeWith(SLACK_DECLARED, expr(`${SEC_CTX}['${SLACK}']`))], d);
    expect(has(bracket, 'permissions', unread), show(bracket)).toBe(false);
    const upper = await run([passes, mergeWith(SLACK_DECLARED, expr(`${SEC_CTX.toUpperCase()}.${SLACK}`))], d);
    expect(has(upper, 'permissions', unread), show(upper)).toBe(false);
    // declaresSecret and readsSecret agree: the name is compared exactly in both (a name read in another case is not the declared one)
    const lowerRead = await run([passes, mergeWith(SLACK_DECLARED, ref(SLACK.toLowerCase()))], d);
    expect(has(lowerRead, 'permissions', unread), show(lowerRead)).toBe(true);
    const lowerDeclared = { [SEC_CTX]: { [FP]: { required: false }, [SLACK.toLowerCase()]: { required: false } } };
    const r = await run([passes, mergeWith(lowerDeclared, ref(SLACK))], d);
    expect(has(r, 'permissions', unread), show(r)).toBe(true);
  });
});

describe('G17A-R2 spec M-2: the referee\'s verify job id is assemble\'s', () => {
  it('G17A-R2: the referee\'s VERIFY_JOB is assemble\'s VERIFY_JOB_ID', () => {
    expect(VERIFY_JOB).toBe(VERIFY_JOB_ID);
  });
});

// ---------- PL-F3: an insert-refusal gap is proven by re-running the deploy layer's insert ----------
describe('PL-F3: the referee re-runs the insert for an insert-refusal gap', () => {
  const DEPLOY = '.github/workflows/deploy.yml';
  const deployText = (needs: string): string => ['on:', '  push:', '    branches: [main]', 'jobs:', '  build:', '    runs-on: ubuntu-latest', '    steps:', '      - run: npm run build', '  deploy:', `    needs: ${needs}`, '    runs-on: ubuntu-latest', '    environment: production', '    steps:', '      - run: ./scripts/ship.sh', ''].join('\n');
  const forged = /deploy\.yml is listed as a gap, but pipegen's deploy layer protects it/;
  const judgeGap = (text: string, why: string, branch = 'main'): Promise<RefereeReport> => {
    const dr = { ...d, profile: { ...d.profile, defaultBranch: branch, existingWorkflows: [{ path: DEPLOY, triggers: ['push'], deploys: true, jobs: [] }] }, doc: { transcript: [], deployGaps: [{ path: DEPLOY, triggers: ['push'], why }], lockNotes: [], estimates: { monthlyMinutes: 0, includedMinutes: null }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] } } as unknown as PipelineDraft;
    return referee([gateFile()], dr, p, reviewedList(), { actionlint: async () => '/stub', zizmor: async () => '/stub' }, 'tok', { runLinters: async () => [], workflowTexts: new Map([[DEPLOY, text]]) });
  };
  it('gap text starts with INSERT_REFUSED_GAP but the insert succeeds → refused', async () => {
    const r = await judgeGap(deployText('build'), 'pipegen can not add its check without changing the rest of the file: x');
    expect(r.issues.some((i) => forged.test(i.message)), JSON.stringify(r.issues)).toBe(true);
  });
  it('real refusal → accepted', async () => {
    const why = 'pipegen can not add its check without changing the rest of the file: the needs of its job "deploy" use a YAML anchor or a quoted job name; write the job names plainly';
    const r = await judgeGap(deployText('"build"'), why);
    expect(r.issues.some((i) => forged.test(i.message)), JSON.stringify(r.issues)).toBe(false);
    // the same file with another refusal reason than the insert's own: refused
    const other = await judgeGap(deployText('"build"'), 'pipegen can not add its check without changing the rest of the file: x');
    expect(other.issues.some((i) => forged.test(i.message)), JSON.stringify(other.issues)).toBe(true);
  });
  it('PL-F3 R1: the re-run keeps the needs-only jobs (a weak self-hosted job with flow steps is not refused) → a forged steps reason is refused', async () => {
    const text = ['on:', '  push:', '    branches: [main]', 'permissions:', '  contents: read', 'jobs:', '  warm:', '    runs-on: self-hosted', '    steps: [{run: ./warm.sh}]', '  deploy:', '    needs: warm', '    runs-on: ubuntu-latest', '    environment: production', '    steps:', '      - run: ./scripts/ship.sh', ''].join('\n');
    const why = 'pipegen can not add its check without changing the rest of the file: its job "warm" has no block list of steps to start with pipegen\'s head check; write its steps as a - list, then run pipegen again';
    const r = await judgeGap(text, why);
    expect(r.issues.some((i) => forged.test(i.message)), JSON.stringify(r.issues)).toBe(true);
  });
  it('PL-F3 R1: the re-run throws (a default branch that is not a plain name) → the gap is refused (fail closed)', async () => {
    const text = deployText('build').replace('branches: [main]', 'branches: [release+1]');
    const r = await judgeGap(text, 'pipegen can not add its check without changing the rest of the file: x', 'release+1');
    expect(r.issues.some((i) => forged.test(i.message)), JSON.stringify(r.issues)).toBe(true);
  });
});
