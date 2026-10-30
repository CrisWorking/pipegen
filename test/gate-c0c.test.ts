// Plan C, C0c: the carry-forwards of review-C0b-r2.md (CF1 spec tools cover their need, CF2 listed actions bound, CF3a one fail-closed base form).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { gateJobList } from '../src/engine/gate-job-list.js';
import { checkJobOrder, jobOutputsFor, NO_SCANS, type ScanFact } from '../src/engine/job-rules.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  validateSpec, dedupeJobSteps, RenderError, renderGateStep, renderJobPrelude, renderPlatformStep, renderProjectScript, renderScrub, renderStep, renderUpload, scanFactOf, scrubbedPath, stepsToYaml,
  type RenderContext, type RenderedStep, type RenderResult,
} from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY, NEED_IDS } from '../src/engine/need-ids.js';
import { BASE_CHECKOUT_REF, rendererInputProblems } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, ReviewedTool, StepSpec } from '../src/types.js';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { renderStage as renderStageC1c } from '../src/engine/render-step.js';
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



const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
const gateJ = (list: ReturnType<typeof gateJobList>): Job => job([renderGateStep(GATE, list)], { name: 'gate', if: 'always()', needs: list.map((e) => e.job), permissions: GATE_PERM });
const harden = (): RenderedStep[] => renderStep(specFor(entry('bullfrog'), { needId: 'egress' }), entry('bullfrog'), p, ctx).steps;

describe('CF1: a spec\'s tool must cover its need', () => {
  const ALL = (): ReviewedTool[] => [...reviewedList(), GATE];
  it('E: dependency-review paired with bullfrog, checkout, upload-artifact, build-push, the gate action or eslint is refused by the referee', async () => {
    for (const toolId of ['bullfrog', 'actions-checkout', 'actions-upload-artifact', 'docker-build-push-action', 'pipegen-gate', 'eslint']) {
      const t = ALL().find((x) => x.id === toolId) as ReviewedTool;
      expect(t, toolId).toBeDefined();
      const spec = specFor(t, { needId: 'dependency-review' });
      const dd = draftOf([spec], [needOf('dependency-review')]);
      const r = await run([workflow({ 'dependency-review': job(prelude()), gate: gateJ([]) }, true)], dd);
      expect(has(r, 'unreviewed', /does not cover the check "dependency-review"/), `${toolId}: ${show(r)}`).toBe(true);
    }
  });
  it('E2: validateSpec refuses a cli tool of another category as the check (eslint for dependency-review)', () => {
    const spec = specFor(entry('eslint'), { needId: 'dependency-review', service: 'app' });
    expect(validateSpec(spec, entry('eslint'), ctx).join('\n')).toMatch(/does not cover the check "dependency-review"/);
    expect(() => renderStep(spec, entry('eslint'), p, ctx)).toThrow(/does not cover/);
  });
  it('every reviewed entry with every need it claims passes the coverage rule (validateSpec and the referee)', async () => {
    let n = 0;
    for (const t of ALL()) {
      for (const c of t.categories) {
        const needId = (NEED_IDS as readonly string[]).includes(c) ? c : undefined;
        if (needId === undefined) continue;
        n++;
        const spec = specFor(t, { needId });
        expect(validateSpec(spec, t, ctx).join('\n'), `${t.id} for ${needId}`).not.toMatch(/does not cover/);
        const r = await run([workflow({ gate: gateJ([]) })], draftOf([spec], [needOf(needId)]));
        expect(r.issues.some((i) => /does not cover/.test(i.message)), `${t.id} for ${needId}`).toBe(false);
      }
    }
    expect(n).toBeGreaterThan(40);
  });
});

describe('CF2: every action of a listed check sits in its listed job', () => {
  const buildSpec = (): StepSpec => specFor(entry('docker-build-push-action'), { needId: 'image-build', service: 'app' });
  it('IB: an image-build--app job holding only a checkout is refused', async () => {
    const dd = draftOf([buildSpec()], [needOf('image-build', 'app')]);
    const list = gateJobList(dd);
    expect(list.map((e) => e.job)).toEqual(['image-build--app']);
    const r = await run([workflow({ 'image-build--app': job(prelude()), gate: gateJ(list) }, true)], dd);
    expect(has(r, 'not-gate-readable', /holds no step of the action check "docker-build-push-action"/), show(r)).toBe(true);
  });
  it('EG: an egress job without bullfrog is refused', async () => {
    const spec = specFor(entry('bullfrog'), { needId: 'egress' });
    const dd = draftOf([spec], [needOf('egress')]);
    const list = gateJobList(dd);
    const r = await run([workflow({ egress: job(prelude()), gate: gateJ(list) }, true)], dd);
    expect(has(r, 'not-gate-readable', /holds no step of the action check "bullfrog"/), show(r)).toBe(true);
  });
  it('the honest layout passes: the build in image-build--app (push false), the harden step in egress and in every other job', async () => {
    const script = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps;
    const specs = [buildSpec(), specFor(entry('bullfrog'), { needId: 'egress' })];
    const dd = draftOf(specs, [needOf('image-build', 'app'), needOf('egress'), needOf('unit-tests', 'app')]);
    const list = gateJobList(dd);
    const build = renderStep(buildSpec(), entry('docker-build-push-action'), p, { ...ctx, targets: { image: 'ghcr.io/o/app:pr-1' } }).steps;
    const jobsMap: Record<string, Job> = {
      'image-build--app': job([...prelude(), ...build]),
      egress: job([...harden(), ...prelude()]),
      'unit-tests--app': job(dedupeJobSteps([...harden(), ...script], { id: 'unit-tests--app', scans: NO_SCANS })),
      gate: gateJ(list),
    };
    expect(show(await run([workflow(jobsMap)], dd))).toBe('');
  });
});

describe('CF3a: one event-switched base form', () => {
  const ZERO = '0'.repeat(40);
  const EXPR = `\${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event_name == 'merge_group' && github.event.merge_group.base_sha || github.event_name == 'push' && github.event.before || '${ZERO}' }}`;
  const specs = [gitleaksSpec(), semgrepSpec('app')];
  const needs = [needOf('secrets'), needOf('sast', 'app')];
  const d = draftOf(specs, needs);
  const entries = gateJobList(d);
  function jobs(over: (steps: RenderedStep[]) => RenderedStep[] = (s) => s): Record<string, Job> {
    const out: Record<string, Job> = {};
    for (const spec of specs) {
      const b = block(spec);
      const id = `${spec.needId}${spec.service === undefined ? '' : `--${spec.service}`}`;
      out[id] = job(dedupeJobSteps([...prelude(), ...b.steps], { id, scans: facts(b) }), { outputs: jobOutputsFor(b.steps) });
    }
    const baseBlocks = specs.map((s) => block(s, { ...ctx, base: true }));
    const steps = over([...prelude({ baseRef: true }), ...baseBlocks.flatMap((b) => b.steps)]);
    out['base-scan'] = job(steps, { outputs: jobOutputsFor(steps) });   // C5a: with the base-sha output of its base checkout
    out.gate = job([renderGateStep(GATE, entries)], { name: 'gate', if: 'always()', needs: [...entries.map((e) => e.job), 'base-scan'], permissions: GATE_PERM });
    return out;
  }
  const wfOn = (on: unknown, j: Record<string, Job>): CreatedFile => {
    const f = workflow(j, true);
    return { ...f, content: f.content.replace(/^on:\n  pull_request: null\n/m, `on: ${JSON.stringify(on)}\n`) };
  };

  it('C5a: the base-scan job of these layouts hands the gate base-sha (the commit its base checkout checked out)', () => {
    expect(jobs()['base-scan']?.outputs).toMatchObject({ 'base-sha': '${{ steps.pipegen-checkout.outputs.commit }}' });
  });
  it('the expression is the one ruled form (a commit sha as the fallback, never a ref name)', () => {
    expect(BASE_CHECKOUT_REF).toBe(EXPR);
    expect(prelude({ baseRef: true })[0]?.with?.ref).toBe(EXPR);
  });
  it('it is accepted in every trigger layout, a called workflow included', async () => {
    for (const on of ['pull_request', { merge_group: null }, { push: { branches: ['main'] } }, { pull_request: null, merge_group: null, push: { branches: ['main'] } }, { pull_request: null, workflow_dispatch: null }, { workflow_call: null }]) {
      const r = await run([wfOn(on, jobs())], d);
      expect(show(r), JSON.stringify(on)).toBe('');
    }
  });
  it('a called workflow with no caller in files is judged the same (no caller inference)', async () => {
    const f = { ...wfOn({ workflow_call: null }, jobs()), path: '.github/workflows/pipegen-merge.yml' };
    expect(show(await run([f], d))).toBe('');
  });
  it('every other ref form is refused in base-scan, in every layout', async () => {
    const forms = [
      '${{ github.event.pull_request.base.sha }}', '${{ github.event.merge_group.base_sha }}', '${{ github.event.before }}',
      'main', ZERO, `\${{ '${ZERO}' }}`, EXPR.replace(`'${ZERO}'`, "'main'"), EXPR.replace("'push'", "'pull_request'"), EXPR.replace(' || github.event_name', ' && github.event_name'),
      `${EXPR} `, EXPR.replace('}}', "|| github.head_ref }}"), '${{ github.event.pull_request.head.sha }}', '${{ github.sha }}', '',
    ];
    for (const ref of forms) {
      const j = jobs((steps) => steps.map((s, i) => (i === 0 ? { ...s, with: { ...s.with, ref } } : s)));
      for (const on of ['pull_request', { workflow_call: null }]) {
        const r = await run([wfOn(on, j)], d);
        expect(r.ok, `${JSON.stringify(ref)} under ${JSON.stringify(on)}`).toBe(false);
      }
    }
    const direct = (ref: string): string[] => checkJobOrder([{ ...prelude({ baseRef: true })[0] as RenderedStep, with: { ...prelude({ baseRef: true })[0]?.with, ref } }], { id: 'base-scan' });
    expect(direct(EXPR)).toEqual([]);
    expect(direct('${{ github.event.before }}').join(' ')).toMatch(/its ref must be exactly/);
    expect(rendererInputProblems('actions/checkout', { ref: ZERO }).length).toBeGreaterThan(0);
    expect(rendererInputProblems('actions/checkout', { ref: EXPR })).toEqual([]);
  });
  it('the other base-scan rules hold: no ref, a second checkout, a checkout that is not first', () => {
    expect(checkJobOrder(prelude(), { id: 'base-scan' }).join(' ')).toMatch(/needs a ref/);
    expect(checkJobOrder([...prelude({ baseRef: true }), ...prelude()], { id: 'base-scan' }).join(' ')).toMatch(/exactly one checkout/);
    expect(checkJobOrder([{ name: 'x', run: 'true' }, ...prelude({ baseRef: true })], { id: 'base-scan' }).join(' ')).toMatch(/first step/);
    expect(checkJobOrder(prelude({ baseRef: true }), { id: 'base-scan' })).toEqual([]);
    expect(checkJobOrder(prelude({ baseRef: true }), { id: 'secrets' }).join(' ')).toMatch(/base-scan/);   // a ref outside base-scan
  });
  it('the expression, read with the Actions rules (&& and || on strings, an empty value is false), gives the base of each event and never the head', () => {
    const body = EXPR.slice(3, -3).trim();
    const js = body.replace(/github\.event_name/g, 'ev.name').replace(/github\.event\.pull_request\.base\.sha/g, 'ev.pr').replace(/github\.event\.merge_group\.base_sha/g, 'ev.mg').replace(/github\.event\.before/g, 'ev.before').replace(/==/g, '===');
    const evalWith = (ev: { name: string; pr?: string; mg?: string; before?: string }): unknown => new Function('ev', `return (${js});`)(ev);
    const PR = 'a'.repeat(40); const MG = 'b'.repeat(40); const BEFORE = 'c'.repeat(40);
    expect(evalWith({ name: 'pull_request', pr: PR })).toBe(PR);
    expect(evalWith({ name: 'merge_group', mg: MG })).toBe(MG);
    expect(evalWith({ name: 'push', before: BEFORE })).toBe(BEFORE);
    expect(evalWith({ name: 'push', before: ZERO })).toBe(ZERO);
    for (const name of ['schedule', 'workflow_dispatch', 'workflow_call', 'issue_comment', 'pull_request_target', 'push-ish']) expect(evalWith({ name, pr: PR, mg: MG, before: BEFORE }), name).toBe(ZERO);
    // a payload that lacks the field falls through to the commit-sha sentinel, never to an empty ref (which would check out the head)
    expect(evalWith({ name: 'pull_request' })).toBe(ZERO);
    expect(evalWith({ name: 'push' })).toBe(ZERO);
  });
  it('actionlint accepts the checkout step with the expression (cached binary, skipped when absent)', () => {
    const bin = join(homedir(), '.cache', 'pipegen', 'tools', 'actionlint-1.7.12', 'actionlint');
    if (!existsSync(bin)) return;
    const dir = mkdtempSync(join(tmpdir(), 'c0c-'));
    const file = join(dir, 'w.yml');
    writeFileSync(file, `name: t\non: [pull_request, merge_group, push]\njobs:\n  base-scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@${'1'.repeat(40)}\n        with:\n          ref: "${EXPR}"\n`);
    expect(() => execFileSync(bin, ['-no-color', file], { stdio: 'pipe' })).not.toThrow();
  });
});
