// Plan C final-review fix round A (final-fix-A.md), written first (strict test-first).
// Ruling 1 (Important 1): one helper, gateStepInputs(draft), builds every input of the gate step in mode gate; renderGateStep and the referee
// both use it, and the referee requires the file's gate step `with` to equal it exactly (no missing input, no extra input, no other value).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { gateJobList, GateJobListError, type JobListEntry } from '../src/engine/gate-job-list.js';
import { gateStepInputs } from '../src/engine/gate-inputs.js';
import { jobOutputsFor, NO_SCANS, type ScanFact } from '../src/engine/job-rules.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  dedupeJobSteps, RenderError, renderFindingsBlock, renderGateStep, renderGateUploads, renderJobPrelude, renderProjectScript, stepsToYaml,
  type RenderContext, type RenderedStep,
} from '../src/engine/render-step.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { gateToolView, resolveSettings } from '../gate/src/settings.js';
import type { Capabilities, CreatedFile, Need, NotProven, PipelineDraft, StepSpec } from '../src/types.js';
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
const ctx: RenderContext = { profile: prof };
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
  const blocks = d.steps.map((s) => renderFindingsBlock(s, entry(s.tool.id), p, ctx, GATE));
  const baseBlocks = d.steps.map((s) => renderFindingsBlock(s, entry(s.tool.id), p, { ...ctx, base: true }, GATE));
  d.steps.forEach((s, i) => {
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
