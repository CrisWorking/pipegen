// A realistic rendered pipeline for referee tests (the builder of test/gate-final-a.test.ts, shared): betterleaks, semgrep and osv of a
// service, its unit tests, the base scan and the gate, over two services. `workflow` writes the gate job's steps as plain YAML, so an
// edited gate step (or an edited env) can hold what the emitter itself refuses; the referee must refuse it too.
import { Document } from 'yaml';
import { gateJobList, type JobListEntry } from '../../src/engine/gate-job-list.js';
import { jobOutputsFor, NO_SCANS, type ScanFact } from '../../src/engine/job-rules.js';
import { NEED_ID_CATEGORY } from '../../src/engine/need-ids.js';
import { referee, type Linters, type RefereeReport } from '../../src/engine/referee.js';
import {
  dedupeJobSteps, renderFindingsBlock, renderGateStep, renderGateUploads, renderJobPrelude, renderProjectScript, renderRangeBlock, stepsToYaml,
  type RenderContext, type RenderedStep,
} from '../../src/engine/render-step.js';
import { emptyRepoFiles } from '../../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, ReviewedTool, StepSpec } from '../../src/types.js';
import { entry, platform, profile, reviewedList, service, specFor } from './render.js';

export const p = platform();
export const GATE = entry('pipegen-gate');
const app = service({ name: 'app', path: '.', scripts: ['test'] });
const web = service({ name: 'web', path: 'apps/web', scripts: ['test'] });
export const prof = { ...profile([app, web]), repoFiles: emptyRepoFiles() };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
export const needOf = (id: string, svc?: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svc === undefined ? {} : { service: svc }), why: 't', blocking: true, floor: true });
export const specs = (): StepSpec[] => [specFor(entry('betterleaks'), { needId: 'secrets' }), specFor(entry('semgrep'), { needId: 'sast', service: 'app' }), specFor(entry('osv-scanner'), { needId: 'deps', service: 'app' })];
const needs = [needOf('secrets'), needOf('sast', 'app'), needOf('deps', 'app'), needOf('unit-tests', 'app'), needOf('gate')];
export const draftOf = (over: Partial<PipelineDraft> = {}): PipelineDraft => ({
  profile: prof, capabilities: caps, needs, steps: specs(), created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [], ...over,
});
const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
export const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
export const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
export type Job = Record<string, unknown>;
export const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });

/** The workflow file of these jobs; `top` adds top-level keys (a workflow-level env, say). */
export function workflow(jobs: Record<string, Job>, top: Record<string, unknown> = {}): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, ...top, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) {
    const steps = j.steps as RenderedStep[];
    doc.setIn(['jobs', id, 'steps'], id === 'gate' ? doc.createNode(steps.map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(steps));
  }
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}

export interface JobsOptions {
  /** Replaces the rendered gate step (an edited one). */
  gateStep?: RenderedStep;
  /** C9: the secrets job's commit-range block (renderRangeBlock, after a full-history checkout) is rendered unless this is false. */
  range?: boolean;
}
/** C9: the job id of the secrets check (spelled at run time, see test/no-secret-literals.test.ts). */
export const SEC_JOB = ['sec', 'rets'].join('');
/** C9: the honest secrets job ends with the commit-range block, and its checkout takes the whole history. */
export function rangeExtra(spec: StepSpec, gate: ReviewedTool = GATE): { steps: RenderedStep[]; scans: [string, ScanFact][]; fetchDepth: '0' } | undefined {
  if (spec.needId !== SEC_JOB || spec.service !== undefined) return undefined;
  const b = renderRangeBlock(entry('betterleaks'), p, gate);
  return { steps: b.steps, scans: [[b.scan.stepId, b.scan.fact]], fetchDepth: '0' };
}
/** A job of these jobs with its steps changed by `edit`. */
export const editSteps = (jobs: Record<string, Job>, id: string, edit: (s: RenderedStep) => RenderedStep): Record<string, Job> =>
  ({ ...jobs, [id]: { ...(jobs[id] as Job), steps: ((jobs[id] as Job).steps as RenderedStep[]).map(edit) } });

/** The whole rendered pipeline for a draft. */
export function jobsOf(d: PipelineDraft, o: JobsOptions = {}): Record<string, Job> {
  const out: Record<string, Job> = {};
  const ctx: RenderContext = { profile: d.profile };
  const findings = d.steps.filter((s) => s.output.format === 'sarif');   // the other specs' jobs are the caller's
  const blocks = findings.map((s) => renderFindingsBlock(s, entry(s.tool.id), p, ctx, GATE));
  const baseBlocks = findings.map((s) => renderFindingsBlock(s, entry(s.tool.id), p, { ...ctx, base: true }, GATE));
  findings.forEach((s, i) => {
    const b = blocks[i] as NonNullable<(typeof blocks)[number]>;
    const id = `${s.needId}${s.service === undefined ? '' : `--${s.service}`}`;
    const extra = o.range === false ? undefined : rangeExtra(s);
    const steps = [...renderJobPrelude(extra === undefined ? {} : { fetchDepth: extra.fetchDepth }, p).steps, ...b.steps, ...(extra?.steps ?? [])];
    out[id] = job(dedupeJobSteps(steps, { id, scans: new Map([[b.scan.stepId, b.scan.fact], ...(extra?.scans ?? [])]) }), { outputs: jobOutputsFor(steps) });
  });
  out['unit-tests--app'] = job(dedupeJobSteps(renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps, { id: 'unit-tests--app', scans: NO_SCANS }));
  const bs = [...renderJobPrelude({ baseRef: true }, p).steps, ...baseBlocks.flatMap((b) => b.steps)];
  out['base-scan'] = job(dedupeJobSteps(bs, { id: 'base-scan', scans: new Map<string, ScanFact>(baseBlocks.map((b) => [b.scan.stepId, b.scan.fact])) }), { outputs: jobOutputsFor(bs), permissions: { contents: 'read', actions: 'read' } });
  const list: JobListEntry[] = gateJobList(d);
  out.gate = job([o.gateStep ?? renderGateStep(GATE, d), ...renderGateUploads(p)], { if: 'always()', needs: [...new Set([...list.map((e) => e.job), 'base-scan'])], permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } });
  return out;
}
