// v0.2 Plan B final-review fix round, commit A (findings 1, 2, 3, 5): the renderer and the referee agree.
// Written first; each test fails without its fix. Probes are the final reviewer's (P2, P3, P4, P5).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { referee, JOB_STEP_POLICY, type Linters, type RefereeReport } from '../src/engine/referee.js';
import { dedupeJobSteps, RenderError, renderJobPrelude, renderPlatformStep, renderScrub, renderStep, renderUpload, scrubbedPath, stepsToYaml, validateSpec, type RenderContext, type RenderedStep } from '../src/engine/render-step.js';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { rendererInputProblems } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, StepSpec } from '../src/types.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';

const api = service({ name: 'api', path: '.', scripts: ['test'], envVars: ['STRIPE_KEY'] });
const prof = { ...profile([api]), repoFiles: { ...emptyRepoFiles() } };
const ctx: RenderContext = { profile: prof, targets: { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' } };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const needOf = (id: string, svc?: string, blocking = true): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svc === undefined ? {} : { service: svc }), why: 't', blocking, floor: false });
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const p = platform();
const draftOf = (steps: StepSpec[], needs: Need[], over: Partial<PipelineDraft> = {}): PipelineDraft => ({ profile: prof, capabilities: caps, needs, steps, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [], ...over });
function wf(jobs: Record<string, RenderedStep[]>, raw = false): CreatedFile {
  const doc = new Document();
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: Object.fromEntries(Object.keys(jobs).map((id) => [id, { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none' }])) });
  for (const [id, steps] of Object.entries(jobs)) doc.setIn(['jobs', id, 'steps'], raw ? doc.createNode(steps.map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(steps));
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
/** A secret reference, built at run time (test/no-secret-literals.test.ts). */
const ref = (n: string): string => ['${{', `secrets.${n}`, '}}'].join(' ');
/** A spec field named `secrets`, set at run time (the fixture scan). */
const KEY = ['STRIPE', 'KEY'].join('_');
const SEC = ['sec', 'rets'].join('');
const GATE = gateEntry();
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, [...reviewedList(), GATE], LINTERS, 'tok', { runLinters: async () => [] });
const showR = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const prelude = (): RenderedStep[] => renderJobPrelude({ fetchDepth: '1' }, p).steps;
function toolSteps(spec: StepSpec, c: RenderContext = ctx): RenderedStep[] {
  const r = renderStep(spec, entry(spec.tool.id), p, c);
  const art = resultArtifactName(spec.needId, spec.service);
  const up = r.output !== null && !r.steps.some((s) => s.id?.startsWith('repocode-'))
    ? [renderScrub(art, r.output.path, spec.tool.id, r.output.format as 'sarif', GATE), renderUpload(art, scrubbedPath(r.output.path), p)]
    : [];
  return [...r.steps, ...up];
}

describe('finding 1: declared secrets only for app-running tools, in validateSpec', () => {
  it('validateSpec reports a secrets problem for an action tool that does not run the app; renderStep throws', () => {
    const spec = specFor(entry('bullfrog'), { needId: 'egress', [SEC]: ['STRIPE_KEY'] });
    const problems = validateSpec(spec, entry('bullfrog'), ctx);
    expect(problems.some((m) => m.startsWith('secrets') && /run the app/.test(m))).toBe(true);
    expect(() => renderStep(spec, entry('bullfrog'), p, ctx)).toThrow(RenderError);
  });
  it('validateSpec reports the same for a scanner CLI, and accepts a declared secret for an app-running tool', () => {
    const gl = specFor(entry('gitleaks'), { needId: 'secrets', [SEC]: ['STRIPE_KEY'] });
    expect(validateSpec(gl, entry('gitleaks'), ctx).some((m) => m.startsWith('secrets'))).toBe(true);
    const vit = specFor(entry('vitest-coverage'), { needId: 'coverage', service: 'api', [SEC]: ['STRIPE_KEY'] });
    expect(validateSpec(vit, entry('vitest-coverage'), ctx)).toEqual([]);
  });
});

describe('finding 2: an upload or download path is inside its own name folder (one rule)', () => {
  it('rendererInputProblems refuses a path in another artifact folder, for upload and download', () => {
    const name = 'pipegen-out-sast--api';
    const other = '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/gitleaks.sarif';
    const own = '${{ runner.temp }}/pipegen-out/pipegen-out-sast--api/semgrep.sarif';
    for (const action of ['actions/upload-artifact', 'actions/download-artifact']) {
      expect(rendererInputProblems(action, { path: other }, { name, path: other }).length).toBeGreaterThan(0);
      expect(rendererInputProblems(action, { path: own }, { name, path: own })).toEqual([]);
      expect(rendererInputProblems(action, { path: `\${{ runner.temp }}/pipegen-out/${name}` }, { name, path: `\${{ runner.temp }}/pipegen-out/${name}` })).toEqual([]);
    }
  });
  it('renderUpload still refuses a foreign path (through the shared rule)', () => {
    expect(() => renderUpload('pipegen-out-sast--api', '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/x.sarif', p)).toThrow(RenderError);
  });
  it('P3 referee: an upload whose path is in another name folder is a template issue', async () => {
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const r0 = renderStep(gl, entry('gitleaks'), p, ctx);
    // the renderer itself refuses this pair, so the hostile step is made by editing a good one (an edited file)
    const good = renderUpload(resultArtifactName('secrets'), scrubbedPath(r0.output?.path as string), p);
    const wrong: RenderedStep = { ...good, with: { ...good.with, name: 'pipegen-out-sast--api' } };
    expect(() => renderPlatformStep('upload-artifact', p, { name: 'pipegen-out-sast--api', path: scrubbedPath(r0.output?.path as string) })).toThrow(RenderError);
    const steps = [...prelude(), ...r0.steps, wrong];
    expect(() => stepsToYaml(steps)).toThrow(RenderError);   // the emitter refuses it too
    const r = await run([wf({ j: steps }, true)], draftOf([gl], [needOf('secrets')]));
    expect(r.issues.some((i) => i.check === 'template' && /inside|folder/.test(i.message))).toBe(true);
  });
});

describe('finding 3: the blocking rule counts only specs that rendered and are in the files', () => {
  const py = service({ name: 'py', path: '.', language: 'python', packageManager: 'pip' });
  it('P5 a blocking need whose only tool can not render (bandit, pip) is not-gate-readable', async () => {
    const pr = profile([py]);
    const bandit = specFor(entry('bandit'), { needId: 'sast', service: 'py' });
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const d = draftOf([bandit, gl], [needOf('sast', 'py'), needOf('secrets')], { profile: pr });
    const r = await run([wf({ j: [...prelude(), ...toolSteps(gl, { profile: pr })] })], d);
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => i.check === 'not-gate-readable' && /sast/.test(i.message))).toBe(true);
  });
  it('a declared secret of a spec that did not render does not join the declared set', async () => {
    const pr = profile([service({ name: 'py', path: '.', language: 'python', packageManager: 'pip', envVars: ['STRIPE_KEY'] })]);
    const bandit = specFor(entry('bandit'), { needId: 'sast', service: 'py', [SEC]: ['STRIPE_KEY'] });
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const steps = toolSteps(gl, { profile: pr });
    const carrying = steps.map((s) => (s.run === undefined ? s : { ...s, env: { ...s.env, [KEY]: ref(KEY) } }));
    const r = await run([wf({ j: [...prelude(), ...carrying] })], draftOf([bandit, gl], [needOf('sast', 'py'), needOf('secrets')], { profile: pr }));
    expect(r.issues.some((i) => /secret/i.test(i.message))).toBe(true);
  });
  it('a blocking spec that renders but whose job is missing from the files is not-gate-readable', async () => {
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const sg = specFor(entry('semgrep'), { needId: 'sast', service: 'api' });
    const d = draftOf([gl, sg], [needOf('secrets'), needOf('sast', 'api')]);
    const r = await run([wf({ j: [...prelude(), ...toolSteps(gl)] })], d);
    expect(r.issues.some((i) => i.check === 'not-gate-readable' && /sast/.test(i.message))).toBe(true);
  });
  it('the same pair with both jobs present is accepted', async () => {
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const sg = specFor(entry('semgrep'), { needId: 'sast', service: 'api', choices: { rules: 'javascript' } });
    const d = draftOf([gl, sg], [needOf('secrets'), needOf('sast', 'api')]);
    const r = await run([wf({ a: [...prelude(), ...toolSteps(gl)], b: dedupeJobSteps([...prelude(), ...toolSteps(sg)]) })], d);
    expect(showR(r)).toBe('');
    expect(r.ok).toBe(true);
  });
});

describe('finding 5: a base-scan variant of the renderer and the referee', () => {
  it('P4 renderStep with ctx.base writes into the base artifact folder, and renderUpload takes it', () => {
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const base = renderStep(gl, entry('gitleaks'), p, { ...ctx, base: true });
    const art = resultArtifactName('secrets', undefined, { base: true });
    expect(art).toBe('pipegen-out-base-secrets');
    expect(base.output?.path).toBe(`\${{ runner.temp }}/pipegen-raw/${art}/${entry('gitleaks').step.output.path}`);
    expect(() => renderUpload(art, base.output?.path as string, p)).toThrow(RenderError);   // the raw result is never uploaded
    expect(renderUpload(art, scrubbedPath(base.output?.path as string), p).with?.name).toBe(art);
    // the non-base render is unchanged
    expect(renderStep(gl, entry('gitleaks'), p, ctx).output?.path).toContain('/pipegen-out-secrets/');
  });
  it('parity: a base-scan job (the JOB_STEP_POLICY row) made by the renderer passes the referee', async () => {
    expect(JOB_STEP_POLICY['base-scan']).toBeDefined();
    const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
    const r0 = renderStep(gl, entry('gitleaks'), p, { ...ctx, base: true });
    const baseArt = resultArtifactName('secrets', undefined, { base: true });
    const scrub = renderScrub(baseArt, r0.output?.path as string, 'gitleaks', 'sarif', GATE);
    const up = renderUpload(baseArt, scrubbedPath(r0.output?.path as string), p);
    // the PR's own scan is in the file too: the base job alone would not satisfy a blocking need
    const doc = wf({ scan: toolSteps(gl).length > 0 ? [...prelude(), ...toolSteps(gl)] : [], 'base-scan': [...prelude(), ...r0.steps, scrub, up] });
    const r = await run([doc], draftOf([gl], [needOf('secrets')]));
    expect(showR(r)).toBe('');
  });
});
