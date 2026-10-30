// Plan C final-review fix round A (final-fix-A.md), written first (strict test-first).
// Ruling 1 (Important 1): one helper, gateStepInputs(draft), builds every input of the gate step in mode gate; renderGateStep and the referee
// both use it, and the referee requires the file's gate step `with` to equal it exactly (no missing input, no extra input, no other value).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { gateJobList, GateJobListError, type JobListEntry } from '../src/engine/gate-job-list.js';
import { gateStepInputs, licenceLockfilesOf, nightlyStepInputs } from '../src/engine/gate-inputs.js';
import { TRIVY_LICENCE_LOCKFILES } from '../src/engine/licence-lockfiles.js';
import { PIPEGEN_GATE_USES, rendererInputProblems } from '../src/engine/tool-flags.js';
import { licenceCoverage } from '../gate/src/facts.js';
import { jobOutputsFor, NO_SCANS, type ScanFact } from '../src/engine/job-rules.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  dedupeJobSteps, RenderError, renderFindingsBlock, renderGateStep, renderGateUploads, renderJobPrelude, renderNightlyStep, renderProjectScript, renderStep, stepsToYaml,
  type RenderContext, type RenderedStep,
} from '../src/engine/render-step.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { gateToolView, resolveSettings } from '../gate/src/settings.js';
import type { Capabilities, CreatedFile, Need, NotProven, PipelineDraft, Service, StepSpec } from '../src/types.js';
import { entry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';

// object keys spelled at run time (see test/no-secret-literals.test.ts)
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
const MISSING = ['missing', 'Sec' + 'rets'].join('') as 'missingSecrets';
/** A not-proven entry of the draft (the part and reason do not matter here). */
const np = (needId: string | undefined, reason: string): NotProven => ({ part: 'pipeline', ...(needId === undefined ? {} : { needId }), reason, [MISSING]: [] } as NotProven);

// ---------- a realistic pipeline: secrets, sast and deps of a service with a lockfile, its unit tests, the base scan and the gate ----------

const p = platform();
const GATE = entry('pipegen-gate');
const app = service({ name: 'app', path: '.', scripts: ['test'] });
const web = service({ name: 'web', path: 'apps/web', scripts: ['test'] });
const prof = { ...profile([app, web]), repoFiles: emptyRepoFiles() };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const needOf = (id: string, svc?: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svc === undefined ? {} : { service: svc }), why: 't', blocking: true, floor: true });
const specs: StepSpec[] = [specFor(entry('betterleaks'), { needId: 'secrets' }), specFor(entry('semgrep'), { needId: 'sast', service: 'app' }), specFor(entry('osv-scanner'), { needId: 'deps', service: 'app' })];
const needs = [needOf('secrets'), needOf('sast', 'app'), needOf('deps', 'app'), needOf('unit-tests', 'app'), needOf('gate')];
const draftOf = (over: Partial<PipelineDraft> = {}): PipelineDraft => ({
  profile: prof, capabilities: caps, needs, steps: specs, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [], ...over,
});
const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
type Job = Record<string, unknown>;
const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });
/** The gate job's steps are written as plain YAML (an edited gate step can hold what the emitter itself refuses; the referee must refuse it too). */
function workflow(jobs: Record<string, Job>): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) {
    const steps = j.steps as RenderedStep[];
    doc.setIn(['jobs', id, 'steps'], id === 'gate' ? doc.createNode(steps.map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(steps));
  }
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
/** The whole rendered pipeline for a draft; `gateStep` replaces the rendered gate step (an edited one). */
function jobs(d: PipelineDraft, gateStep?: RenderedStep): Record<string, Job> {
  const out: Record<string, Job> = {};
  const ctx: RenderContext = { profile: d.profile };
  const findings = d.steps.filter((s) => s.output.format === 'sarif');   // the other specs' jobs are the caller's
  const blocks = findings.map((s) => renderFindingsBlock(s, entry(s.tool.id), p, ctx, GATE));
  const baseBlocks = findings.map((s) => renderFindingsBlock(s, entry(s.tool.id), p, { ...ctx, base: true }, GATE));
  findings.forEach((s, i) => {
    const b = blocks[i] as NonNullable<(typeof blocks)[number]>;
    const id = `${s.needId}${s.service === undefined ? '' : `--${s.service}`}`;
    out[id] = job(dedupeJobSteps([...renderJobPrelude({}, p).steps, ...b.steps], { id, scans: new Map([[b.scan.stepId, b.scan.fact]]) }), { outputs: jobOutputsFor(b.steps) });
  });
  out['unit-tests--app'] = job(dedupeJobSteps(renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps, { id: 'unit-tests--app', scans: NO_SCANS }));
  const bs = [...renderJobPrelude({ baseRef: true }, p).steps, ...baseBlocks.flatMap((b) => b.steps)];
  out['base-scan'] = job(dedupeJobSteps(bs, { id: 'base-scan', scans: new Map<string, ScanFact>(baseBlocks.map((b) => [b.scan.stepId, b.scan.fact])) }), { outputs: jobOutputsFor(bs), permissions: { contents: 'read', actions: 'read' } });
  const list: JobListEntry[] = gateJobList(d);
  out.gate = job([gateStep ?? renderGateStep(GATE, d), ...renderGateUploads(p)], { if: 'always()', needs: [...list.map((e) => e.job), 'base-scan'], permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } });
  return out;
}
/** The pipeline with the gate step's `with` changed by `edit` (a copy of the honest one). */
const withEdited = (d: PipelineDraft, edit: (w: Record<string, string>) => void): Record<string, Job> => {
  const honest = renderGateStep(GATE, d);
  const w = { ...(honest.with as Record<string, string>) };
  edit(w);
  return jobs(d, { ...honest, with: w });
};
/** A tool's own rendered steps (no prelude), with the draft's profile. */
const renderStepFor = (spec: StepSpec, d: PipelineDraft): RenderedStep[] => renderStep(spec, entry(spec.tool.id), p, { profile: d.profile }).steps;
const refusedForGateInputs = (r: RefereeReport): boolean => !r.ok && r.issues.some((i) => i.check === 'not-gate-readable' || i.check === 'template' || i.check === 'unreviewed');

describe('ruling 1: gateStepInputs, the one source of every input of the gate step', () => {
  it('gateStepInputs: the expression inputs, the job list of gateJobList(draft) and the service roots from profile.services[].path', () => {
    const d = draftOf();
    const w = gateStepInputs(d);
    expect(w.mode).toBe('gate');
    expect(w.jobs).toBe('${{ toJSON(needs) }}');
    expect(w['block-from']).toBe('${{ vars.PIPEGEN_BLOCK_FROM }}');
    expect(JSON.parse(w['job-list'] as string)).toEqual(JSON.parse(JSON.stringify(gateJobList(d))));
    expect(JSON.parse(w['service-roots'] as string)).toEqual(['.', 'apps/web']);
    // nothing in the draft asks for these, so they are not rendered at all
    for (const k of ['not-proven', 'skipped', 'policy', 'protected-paths', 'block-from-recorded']) expect(Object.hasOwn(w, k), k).toBe(false);
  });

  it('gateStepInputs: skipped from draft.skipped (--skip tests → the test needs), not-proven from draft.notProven need ids, the gate settings from draft.gateSettings', () => {
    const d = draftOf({
      skipped: [{ part: 'tests', reason: 'skipped with --skip on 2026-10-30' }, { part: 'slack', reason: 'x' }],
      notProven: [np('lint', 'no secret'), np('lint', 'again'), np(undefined, 'no need')],
      gateSettings: { blockFromRecorded: '2026-11-14', policy: { block: ['critical', 'high'], warn: ['medium'] }, protectedPaths: ['ops/**'] },
    });
    const w = gateStepInputs(d);
    expect(JSON.parse(w.skipped as string)).toEqual(['unit-tests', 'full-tests', 'migration-check']);
    expect(JSON.parse(w['not-proven'] as string)).toEqual(['lint']);
    expect(w['block-from-recorded']).toBe('2026-11-14');
    expect(JSON.parse(w.policy as string)).toEqual({ block: ['critical', 'high'], warn: ['medium'] });
    expect(JSON.parse(w['protected-paths'] as string)).toEqual(['ops/**']);
  });

  it('gateStepInputs: a draft value the gate would refuse is a GateJobListError (never a literal the gate blocks on): a floor need not proven, a bad date, a bad service folder', () => {
    expect(() => gateStepInputs(draftOf({ notProven: [np('secrets', 'x')] }))).toThrow(GateJobListError);
    expect(() => gateStepInputs(draftOf({ gateSettings: { blockFromRecorded: '2026-02-30' } }))).toThrow(GateJobListError);
    expect(() => gateStepInputs(draftOf({ profile: { ...prof, services: [service({ name: 'x', path: '../up' })] } }))).toThrow(GateJobListError);
    expect(() => gateStepInputs(draftOf({ gateSettings: { protectedPaths: ['/etc/**'] } }))).toThrow(GateJobListError);
  });

  it('renderGateStep: the step\'s with IS gateStepInputs(draft); a draft the gate would refuse is a RenderError', () => {
    const d = draftOf({ gateSettings: { blockFromRecorded: '2026-11-14' } });
    expect(renderGateStep(GATE, d).with).toEqual(gateStepInputs(d));
    expect(() => renderGateStep(GATE, draftOf({ gateSettings: { blockFromRecorded: 'soon' } }))).toThrow(RenderError);
  });
});

describe('ruling 1: the gate reads the rendered step without a settings error', () => {
  it('resolveSettings over the honest with (the runner\'s values put in for the expressions): no error, the service roots and the draft\'s settings', () => {
    const d = draftOf({ skipped: [{ part: 'tests', reason: 'x' }], gateSettings: { blockFromRecorded: '2026-11-14', protectedPaths: ['ops/**'] } });
    const w = { ...(renderGateStep(GATE, d).with as Record<string, string>), jobs: '{}', 'block-from': '', [GH_IN]: 'tok', [FP_IN]: '' };
    const s = resolveSettings(w, { private: false, reviewed: gateToolView(reviewedList()) });
    expect(s.errors).toEqual([]);
    expect(s.serviceRoots).toEqual(['.', 'apps/web']);
    expect(s.skipped.map((x) => x.needId)).toEqual(['unit-tests', 'full-tests', 'migration-check']);
    expect(s.blockFromRecorded).toBe('2026-11-14');
    expect(s.protectedPaths).toContain('ops/**');
    expect(s.protectedPaths).toContain('/apps/web/.prettierignore');
  });
});

describe('ruling 1: the referee holds the gate step to gateStepInputs(draft), exactly', () => {
  it('the honest render passes with 0 issues (with every optional input the draft gives, too)', async () => {
    const d = draftOf();
    expect(show(await run([workflow(jobs(d))], d))).toBe('');
    const full = draftOf({
      skipped: [{ part: 'tests', reason: 'x' }],
      notProven: [np('lint', 'x')],
      gateSettings: { blockFromRecorded: '2026-11-14', policy: { block: ['critical', 'high'], warn: ['medium'] }, protectedPaths: ['ops/**'] },
    });
    expect(show(await run([workflow(jobs(full))], full))).toBe('');
  });

  it('the final review\'s case (a): a gate step without service-roots (the gate would block every run) is refused', async () => {
    const d = draftOf();
    const r = await run([workflow(withEdited(d, (w) => { delete w['service-roots']; }))], d);
    expect(r.ok).toBe(false);
    expect(show(r)).toMatch(/service-roots/);
  });

  it('the final review\'s case (b): skipped ["unit-tests"] that the draft does not give (a failed unit-test job would pass as skipped) is refused', async () => {
    const d = draftOf();
    const r = await run([workflow(withEdited(d, (w) => { w.skipped = '["unit-tests"]'; }))], d);
    expect(r.ok).toBe(false);
    expect(show(r)).toMatch(/skipped/);
  });

  it('the other literals of the final review\'s case (b) are refused too: service-roots elsewhere, a later recorded date, extra protected paths, not-proven, skipped deps', async () => {
    const d = draftOf({ gateSettings: { blockFromRecorded: '2026-11-14' } });
    for (const [k, v] of [['service-roots', '["nowhere"]'], ['block-from-recorded', '2099-01-01'], ['protected-paths', '["docs/**"]'], ['not-proven', '["unit-tests"]'], ['skipped', '["deps"]'], ['policy', '{"block":[],"warn":["critical","high","medium","low","info"]}']] as const) {
      const r = await run([workflow(withEdited(d, (w) => { w[k] = v; }))], d);
      expect(refusedForGateInputs(r), `${k}=${v}: ${show(r)}`).toBe(true);
      expect(show(r), k).toMatch(new RegExp(k));
    }
  });

  it('every input of the honest step, removed or changed one at a time, is refused; an extra input the draft does not give is refused', async () => {
    const d = draftOf({
      skipped: [{ part: 'tests', reason: 'x' }],
      notProven: [np('lint', 'x')],
      gateSettings: { blockFromRecorded: '2026-11-14', policy: { block: ['critical', 'high'], warn: ['medium'] }, protectedPaths: ['ops/**'] },
    });
    const honest = renderGateStep(GATE, d).with as Record<string, string>;
    // a value that is not the draft's, per input (of the same schema for the literals; the emitter refuses other expressions, so plain text for those)
    const other: Record<string, string> = {
      mode: 'nightly', jobs: '{}', 'job-list': '[]', 'not-proven': '["lint","format"]', skipped: '["unit-tests"]',
      policy: '{"block":["critical"],"warn":["high","medium"]}', 'protected-paths': '["ops/**","more/**"]', 'service-roots': '["."]',
      'block-from': '2026-01-01', 'block-from-recorded': '2026-11-15', [GH_IN]: 'tok', [FP_IN]: 'k',
    };
    for (const k of Object.keys(honest)) {
      const removed = await run([workflow(withEdited(d, (w) => { delete w[k]; }))], d);
      expect(removed.ok, `without ${k}`).toBe(false);
      expect(other[k], `a changed value for ${k}`).toBeDefined();
      const changed = await run([workflow(withEdited(d, (w) => { w[k] = other[k] as string; }))], d);
      expect(changed.ok, `${k} changed`).toBe(false);
    }
    const lean = draftOf();
    for (const [k, v] of [['not-proven', '["lint"]'], ['policy', '{"block":["critical","high"],"warn":["medium"]}'], ['protected-paths', '["ops/**"]'], ['block-from-recorded', '2026-11-14'], ['skipped', '[]']] as const) {
      const r = await run([workflow(withEdited(lean, (w) => { w[k] = v; }))], lean);
      expect(r.ok, `extra ${k}`).toBe(false);
      expect(show(r), k).toMatch(new RegExp(`${k}.*(?:does not give|not the)|(?:does not give|not the).*${k}`));
    }
  });
});

// ---------- ruling 2 (Important 3): licences ----------

describe('ruling 2: the licence check\'s coverage per lockfile, from the profile', () => {
  const svc = (name: string, path: string, over: Partial<Service>): Service => service({ name, path, scripts: name === 'app' ? ['test'] : [], ...over });
  const licProf = {
    ...profile([
      svc('app', '.', {}), svc('API', 'api', { language: 'python', packageManager: 'uv' }), svc('cli', 'cli', { language: 'go', packageManager: undefined as never }),
      svc('docs', 'docs', { packageManager: undefined as never }), svc('tool', 'tool', { language: 'python', packageManager: 'pip', alsoLanguages: ['go'] }),
    ]),
    repoFiles: emptyRepoFiles(),
  };
  const licSpecs: StepSpec[] = [...specs, specFor(entry('trivy-licence'), { needId: 'licences' })];
  const licDraft = (over: Partial<PipelineDraft> = {}): PipelineDraft => draftOf({ profile: licProf, steps: licSpecs, needs: [...needs, needOf('licences')], ...over });
  const WANT = [
    { service: 'app', lockfiles: [{ kind: 'npm', read: true }] },
    { service: 'api', lockfiles: [{ kind: 'uv', read: false }] },
    { service: 'cli', lockfiles: [{ kind: 'go', read: false }] },
    { service: 'docs', lockfiles: [] },
    { service: 'tool', lockfiles: [{ kind: 'pip', read: false }, { kind: 'go', read: false }] },
  ];

  it('the reviewed table (trivy v0.76.0 docs, cited in the module): only npm\'s package-lock.json carries licences by itself; yarn, pnpm, bun, pip and go need installed packages; poetry, uv and an unknown manager never', () => {
    expect(TRIVY_LICENCE_LOCKFILES.npm.licences).toBe('lockfile');
    for (const k of ['yarn', 'pnpm', 'bun', 'pip', 'go'] as const) expect(TRIVY_LICENCE_LOCKFILES[k].licences, k).toBe('installed');
    for (const k of ['poetry', 'uv', 'other'] as const) expect(TRIVY_LICENCE_LOCKFILES[k].licences, k).toBe('never');
    // every package manager the reader can find has a row
    for (const pm of ['npm', 'pnpm', 'yarn', 'bun', 'pip', 'poetry', 'uv', 'other'] as const) expect(Object.hasOwn(TRIVY_LICENCE_LOCKFILES, pm), pm).toBe(true);
  });

  it('licenceLockfilesOf: per service (its slug), each lockfile kind the profile found and whether trivy reads it (no install step is rendered before the scan yet, so only the lockfile kind counts)', () => {
    expect(licenceLockfilesOf(licDraft())).toEqual(WANT);
  });

  it('gateStepInputs: licence-lockfiles exactly when the job list has a licences check', () => {
    expect(JSON.parse(gateStepInputs(licDraft())['licence-lockfiles'] as string)).toEqual(WANT);
    expect(Object.hasOwn(gateStepInputs(draftOf()), 'licence-lockfiles')).toBe(false);
  });

  it('the referee: the honest pipeline passes; a licence-lockfiles that says uv is read, drops a service or is missing is refused', async () => {
    const d = licDraft();
    expect(show(await run([workflow(jobs(d))], d))).toBe('');
    const lied = WANT.map((e) => (e.service === 'api' ? { service: 'api', lockfiles: [{ kind: 'npm', read: true }] } : e));
    for (const edit of [
      (w: Record<string, string>) => { w['licence-lockfiles'] = JSON.stringify(lied); },
      (w: Record<string, string>) => { w['licence-lockfiles'] = JSON.stringify(WANT.slice(1)); },
      (w: Record<string, string>) => { delete w['licence-lockfiles']; },
    ]) {
      const r = await run([workflow(withEdited(d, edit))], d);
      expect(r.ok, show(r)).toBe(false);
      expect(show(r)).toMatch(/licence-lockfiles/);
    }
  });

  it('RENDERER_INPUTS / the gate: licence-lockfiles is a JSON list of { service, lockfiles: [{ kind, read }] }, mode gate only; a kind trivy never reads can not be marked read', () => {
    const problems = (v: string, mode = 'gate'): string[] => rendererInputProblems(PIPEGEN_GATE_USES, { 'licence-lockfiles': v }, { mode, 'licence-lockfiles': v });
    expect(problems(JSON.stringify(WANT))).toEqual([]);
    expect(problems('[]')).toEqual([]);
    expect(problems(JSON.stringify(WANT), 'nightly').length).toBeGreaterThan(0);
    for (const bad of ['x', '{}', '[1]', '[{"service":"app"}]', '[{"service":"App","lockfiles":[]}]', '[{"service":"app","lockfiles":[{"kind":"cargo","read":true}]}]',
      '[{"service":"app","lockfiles":[{"kind":"uv","read":true}]}]', '[{"service":"app","lockfiles":[{"kind":"npm","read":"yes"}]}]', '[{"service":"app","lockfiles":[{"kind":"npm","read":true,"x":1}]}]',
      '[{"service":"app","lockfiles":[],"x":1}]']) {
      expect(problems(bad).length, bad).toBeGreaterThan(0);
    }
  });

  it('the gate: resolveSettings reads it, gatherGateInput\'s coverage names each service and kind that is not covered, never "clean"', () => {
    const w = { ...(renderGateStep(GATE, licDraft()).with as Record<string, string>), jobs: '{}', 'block-from': '', [GH_IN]: 'tok', [FP_IN]: '' };
    const s = resolveSettings(w, { private: false, reviewed: gateToolView(reviewedList()) });
    expect(s.errors).toEqual([]);
    expect(s.licenceLockfiles).toEqual(WANT);
    expect(licenceCoverage(s.licenceLockfiles)).toEqual([
      'api: uv: not covered (lockfile type)', 'cli: go: not covered (lockfile type)', 'docs: not covered (no lockfile)', 'tool: pip: not covered (lockfile type)', 'tool: go: not covered (lockfile type)',
    ]);
    expect(licenceCoverage([])).toEqual(['not covered (no lockfile)']);
    expect(licenceCoverage([{ service: 'app', lockfiles: [{ kind: 'npm', read: true }] }])).toEqual([]);
    expect(licenceCoverage(undefined)).toEqual(['coverage per lockfile not known (the gate step has no licence-lockfiles input)']);
    const bad = resolveSettings({ ...w, 'licence-lockfiles': '[{"service":"api","lockfiles":[{"kind":"uv","read":true}]}]' }, { private: false, reviewed: gateToolView(reviewedList()) });
    expect(bad.errors.join('\n')).toMatch(/licence-lockfiles input is refused/);
  });
});

// ---------- ruling 3 (Important 5): warn-first from the draft ----------

describe('ruling 3: warn-first from the draft (#96, S12)', () => {
  const lintSpec = (): StepSpec => specFor(entry('eslint'), { needId: 'lint', service: 'app' });
  const wfDraft = (warnFirst: PipelineDraft['warnFirst'], over: Partial<PipelineDraft> = {}): PipelineDraft =>
    draftOf({ steps: [...specs, lintSpec()], needs: [...needs, { ...needOf('lint', 'app'), floor: false }], ...(warnFirst === undefined ? {} : { warnFirst }), ...over });

  it('gateJobList sets warnFirst { since } on every entry of a need in draft.warnFirst, and on no other', () => {
    const list = gateJobList(wfDraft({ lint: { since: '2026-11-01' } }));
    expect(list.find((e) => e.needId === 'lint')?.warnFirst).toEqual({ since: '2026-11-01' });
    for (const e of list.filter((x) => x.needId !== 'lint')) expect(e.warnFirst, e.job).toBeUndefined();
    expect(gateJobList(wfDraft(undefined)).some((e) => e.warnFirst !== undefined)).toBe(false);
  });

  it('a floor need in draft.warnFirst is a GateJobListError (the gate would block: warn-first never reaches a floor check, #13); a bad date fails the job-list schema', () => {
    for (const id of ['secrets', 'sast', 'deps', 'unit-tests']) expect(() => gateJobList(wfDraft({ [id]: { since: '2026-11-01' } })), id).toThrow(GateJobListError);
    expect(() => gateStepInputs(wfDraft({ lint: { since: '2026-13-01' } }))).toThrow(GateJobListError);
  });

  it('the referee: the honest pipeline with a warn-first check passes; the job list without the warnFirst (or with another since) is refused', async () => {
    const lintJob = (d: PipelineDraft): Job => job(dedupeJobSteps([...renderJobPrelude({ node: {} }, p).steps, ...renderStepFor(lintSpec(), d)], { id: 'lint--app', scans: NO_SCANS }));
    const d = wfDraft({ lint: { since: '2026-11-01' } });
    const all: Record<string, Job> = { ...jobs(d), 'lint--app': lintJob(d) };
    expect(show(await run([workflow(all)], d))).toBe('');
    const plain = gateStepInputs(wfDraft(undefined))['job-list'] as string;
    const later = (gateStepInputs(d)['job-list'] as string).replace('"since":"2026-11-01"', '"since":"2026-12-01"');
    for (const literal of [plain, later]) {
      const honest = renderGateStep(GATE, d);
      const edited = { ...all, gate: { ...(all.gate as Job), steps: [{ ...honest, with: { ...honest.with, 'job-list': literal } }, ...renderGateUploads(p)] } };
      const r = await run([workflow(edited)], d);
      expect(r.ok).toBe(false);
      expect(show(r)).toMatch(/job-list is not the list this pipeline needs/);
    }
  });

  it('nightlyStepInputs: the nightly step\'s inputs, with warn-first = the warn-first needs of the job list, once each, and the recorded date', () => {
    const d = wfDraft({ lint: { since: '2026-11-01' } }, { gateSettings: { blockFromRecorded: '2026-11-14' } });
    const w = nightlyStepInputs(d);
    expect(w).toEqual({
      mode: 'nightly', 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', 'block-from-recorded': '2026-11-14', 'warn-first': '[{"needId":"lint","since":"2026-11-01"}]',
      [GH_IN]: '${{ secrets.GITHUB_TOKEN }}', [FP_IN]: '${{ secrets.PIPEGEN_FP_KEY }}',
    });
    expect(Object.hasOwn(nightlyStepInputs(draftOf()), 'warn-first')).toBe(false);
    expect(renderNightlyStep(GATE, d).with).toEqual(w);
  });

  it('the referee: a nightly step must equal nightlyStepInputs(draft): no warn-first, another since or an extra input is refused', async () => {
    const d = wfDraft({ lint: { since: '2026-11-01' } });
    const nightlyJob = (step: RenderedStep): Job => job([step], { permissions: { contents: 'read', actions: 'read', issues: 'write' } });
    const base: Record<string, Job> = { ...jobs(d), 'lint--app': job(dedupeJobSteps([...renderJobPrelude({ node: {} }, p).steps, ...renderStepFor(lintSpec(), d)], { id: 'lint--app', scans: NO_SCANS })) };
    const honest = renderNightlyStep(GATE, d);
    expect(show(await run([workflow({ ...base, nightly: nightlyJob(honest) })], d))).toBe('');
    const edits: ((w: Record<string, string>) => void)[] = [
      (w) => { delete w['warn-first']; },
      (w) => { w['warn-first'] = '[{"needId":"lint","since":"2026-12-01"}]'; },
      (w) => { w['block-from-recorded'] = '2026-11-14'; },
    ];
    for (const edit of edits) {
      const w = { ...(honest.with as Record<string, string>) };
      edit(w);
      const r = await run([workflow({ ...base, nightly: nightlyJob({ ...honest, with: w }) })], d);
      expect(r.ok, JSON.stringify(w)).toBe(false);
      expect(show(r)).toMatch(/nightly step/);
    }
  });

  it('RENDERER_INPUTS: warn-first in mode nightly only, a JSON list of { needId, since } (a real date, each need once)', () => {
    const problems = (v: string, mode = 'nightly'): string[] => rendererInputProblems(PIPEGEN_GATE_USES, { 'warn-first': v }, { mode, 'warn-first': v });
    expect(problems('[{"needId":"lint","since":"2026-11-01"}]')).toEqual([]);
    expect(problems('[]')).toEqual([]);
    expect(problems('[{"needId":"lint","since":"2026-11-01"}]', 'gate').length).toBeGreaterThan(0);
    for (const bad of ['x', '{}', '[{"needId":"lint"}]', '[{"needId":"Lint","since":"2026-11-01"}]', '[{"needId":"lint","since":"2026-02-30"}]', '[{"needId":"lint","since":"2026-11-01","x":1}]',
      '[{"needId":"lint","since":"2026-11-01"},{"needId":"lint","since":"2026-11-02"}]']) {
      expect(problems(bad).length, bad).toBeGreaterThan(0);
    }
  });
});
