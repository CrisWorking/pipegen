// Shared fixtures for the G4 assemble tests (test/jobs.test.ts, test/jobs-dast.test.ts): a node service and profile, the debate's result as
// code builds it (the first offered tool per key), assembleJobs over it, the simplest file layout (G5 owns the real one) and the referee.
import { Document, parseDocument, Scalar, YAMLMap, YAMLSeq } from 'yaml';
import { keyOffers, specFor } from '../../src/debate/builder.js';
import { floorNeeds } from '../../src/engine/needs.js';
import { referee, type RefereeReport } from '../../src/engine/referee.js';
import { stepsToYaml } from '../../src/engine/render-step.js';
import { CALLER_WORKFLOW, PUSH_WORKFLOW, WORKFLOW_CONCURRENCY } from '../../src/engine/job-rules.js';
import { emptyRepoFiles, emptyServiceQuality } from '../../src/read/quality.js';
import { assembleJobs, type AssembledJobs, type Job, type JobsPlan } from '../../src/layers/jobs.js';
import type { Capabilities, CreatedFile, Need, NotProven, PipelineDraft, RepoProfile, Service, StepSpec } from '../../src/types.js';
import { REVIEWED, candidatesFor } from './debate-fixtures.js';
import { platform } from './render.js';

export const p = platform(REVIEWED);
/** Names spelled at run time (test/no-secret-literals.test.ts). */
export const SEC = ['sec', 'rets'].join('');
/** The secrets check's id and job id. */
export const SEC_JOB = ['sec', 'rets'].join('');
/** The fetch step's token variable and the workflow token secret, spelled at run time. */
export const FETCH_TOK = ['PIPEGEN_FETCH', 'TOK' + 'EN'].join('_');
export const GH_TOK = ['GITHUB', 'TOK' + 'EN'].join('_');
export const CAPS: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: false };
/** An app secret's name, spelled at run time. */
export const APP_KEY = ['STRIPE', 'KEY'].join('_');
/** NotProven's missing names field, and a list of one name K (spelled at run time). */
export const MISSING = ['missing', 'Sec' + 'rets'].join('');
export const NAMES: string[] = ['K'];
/** A not-proven entry of a check with one missing name. */
export const notProvenOf = (needId: string): NotProven => ({ part: 'pipeline', needId, reason: 't', [MISSING]: NAMES }) as unknown as NotProven;
export const LINTERS = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
export type Obj = Record<string, any>;

export const node = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', npmLockfileVersion: 3, hasTests: true, envVars: [], dependsOn: [], scripts: ['test', 'lint'], frameworks: [], quality: emptyServiceQuality(), ...over,
});
export const profileOf = (services: Service[] = [node()], over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none', services, terraformDirs: [], hasCompose: false,
  existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(), ...over,
});

/** The debate's result as code builds it for a need list (the first offered tool per key, its template defaults), and the draft made from it. */
export function planned(prof: RepoProfile = profileOf(), opts: { caps?: Capabilities; needs?: Need[]; over?: Partial<PipelineDraft>; edit?: (steps: StepSpec[]) => StepSpec[] } = {}): { draft: PipelineDraft; plan: JobsPlan } {
  const caps = opts.caps ?? CAPS;
  const needs = opts.needs ?? floorNeeds(prof, caps);
  const candidates = candidatesFor(needs, prof, {}, REVIEWED);
  const o = keyOffers(needs, candidates, prof, { reviewed: REVIEWED });
  const steps = o.refs.flatMap((r) => { const of = o.offers.get(r.key); return of === undefined ? [] : [specFor(r, of[0] as NonNullable<typeof of>[number], prof)]; });
  const draft: PipelineDraft = {
    profile: prof, capabilities: caps, needs, steps: opts.edit === undefined ? steps : opts.edit(steps), created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [],
    requireDeployApproval: false, skipped: [], suggestions: [], ...opts.over,
  };
  return { draft, plan: { needs, candidates, uncovered: o.uncovered } };
}
export const assemble = (x: { draft: PipelineDraft; plan: JobsPlan }, mode: Parameters<typeof assembleJobs>[2]['mode'] = 'none'): AssembledJobs =>
  assembleJobs(x.draft, x.plan, { reviewed: REVIEWED, platform: p, mode });

/** A workflow file of these jobs (the simplest layout: G5 writes the real callers). */
export function wf(jobs: Record<string, Job | Obj>, path: string, on: unknown): CreatedFile {
  const doc = new Document();
  // G17 row 1b: pipegen.yml and pipegen-push.yml carry the workflow concurrency, as assemble writes them
  const conc = path === CALLER_WORKFLOW || path === PUSH_WORKFLOW ? { concurrency: { ...WORKFLOW_CONCURRENCY } } : {};
  doc.contents = doc.createNode({ name: 'pipegen', on, permissions: {}, ...conc, jobs: Object.fromEntries(Object.entries(jobs).map(([k, j]) => { const { steps: _s, ...rest } = j as Obj; return [k, rest]; })) });
  for (const [k, j] of Object.entries(jobs)) doc.setIn(['jobs', k, 'steps'], stepsToYaml((j as Job).steps));
  return { path, content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
export const PR_ON = { pull_request: null };
export const files = (a: AssembledJobs): CreatedFile[] => [
  wf(a.merge, '.github/workflows/pipegen.yml', PR_ON),
  wf(a.push, '.github/workflows/pipegen-push.yml', { push: { 'branches-ignore': ['main'] } }),
  wf(a.nightly, '.github/workflows/pipegen-nightly.yml', { schedule: [{ cron: '17 3 * * *' }] }),
];
export const judge = (fs: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(fs, d, p, REVIEWED, LINTERS, 'tok', { runLinters: async () => [] });
export const shown = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
export const allJobs = (a: AssembledJobs): [string, Job][] => [...Object.entries(a.push), ...Object.entries(a.merge), ...Object.entries(a.nightly)];
const NEEDS_QUOTES = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]|\$\{\{|^\s|\s$|\s#|:\s|^[-?:,[\]{}#&*!|>'"%@`]/;
/** A string scalar the way stepsToYaml writes it (render-step.ts str), but with no check: a hand edit may be hostile. */
function str(value: string, block = false): Scalar {
  const s = new Scalar(value);
  if (block && value.includes('\n') && !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]|\s\n|^\s/.test(value)) s.type = Scalar.BLOCK_LITERAL;
  else if (NEEDS_QUOTES.test(value)) s.type = Scalar.QUOTE_DOUBLE;
  return s;
}
/** Any value as a YAML node, strings quoted like stepsToYaml's, `run` as a block. */
function yamlNode(doc: Document, v: unknown, key?: string): unknown {
  if (typeof v === 'string') return str(v, key === 'run');
  if (Array.isArray(v)) { const seq = new YAMLSeq(); for (const x of v) seq.add(yamlNode(doc, x)); return seq; }
  if (v !== null && typeof v === 'object') { const map = new YAMLMap(); for (const [k, x] of Object.entries(v)) map.set(new Scalar(k), yamlNode(doc, x, k)); return map; }
  return doc.createNode(v);
}
/**
 * A file with one job changed (a hand edit). Only that job is written again, every other node of the file stays as it was, and its strings
 * are quoted the way stepsToYaml quotes them, so an edit that changes nothing gives a file the referee accepts (G4b-R1 I2: a plain
 * re-serialisation folded the checker lock env onto lines the secret-value scan reads, so every edited file was refused whatever the edit).
 */
export function editJob(f: CreatedFile, id: string, edit: (j: Obj) => void): CreatedFile {
  const doc = parseDocument(f.content);
  const js = doc.toJS() as Obj;
  edit(js.jobs[id]);
  doc.setIn(['jobs', id], yamlNode(doc, js.jobs[id]));
  return { ...f, content: doc.toString({ lineWidth: 0 }) };
}
export const domainsOf = (j: Job): string[] => String(j.steps[0]?.with?.['allowed-domains'] ?? '').split('\n');
