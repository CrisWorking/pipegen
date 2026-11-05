// E5: builders for evaluate() tests: a draft (needs and steps), finished runs (jobs, artifacts, logs) and the gate's result.json.
// Shapes follow src/proof/run.ts (RunOutcome) and gate/src/main.ts (resultDoc). No network.
import { createHash } from 'node:crypto';
import { GATE_RESULT_ARTIFACT, resultArtifactName } from '../../src/engine/artifact-names.js';
import { gateJobList, jobIdFor } from '../../src/engine/gate-job-list.js';
import { NEED_ID_CATEGORY } from '../../src/engine/need-ids.js';
import type { PlantedPlacement } from '../../src/proof/snapshot.js';
import { COMPAT_PREFIX, HARNESS_PATH } from '../../src/proof/harness.js';
import type { ArtifactFile } from '../../src/proof/download.js';
import type { JobOutcome, RunConclusion, RunEvent, RunOutcome } from '../../src/proof/run.js';
import type { EvalContext, VariantRuns } from '../../src/proof/evaluate.js';
import type { CreatedFile, Need, PipelineDraft, StepSpec } from '../../src/types.js';
import { emptyRepoFiles } from '../../src/read/quality.js';
import { entry, profile, service, specFor } from './render.js';
const FLAG = ['sec', 'ret'].join('');

export const PIPEGEN = '.github/workflows/pipegen.yml';
export const HEAD = 'a'.repeat(40);
export const MERGE = 'b'.repeat(40);
export const KEEP = 'proof: ';

const needOf = (id: string, over: Partial<Need> = {}): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, why: 't', blocking: true, floor: false, ...over });
const spec = (tool: string, needId: string, svc?: string, over: Partial<StepSpec> = {}): StepSpec => specFor(entry(tool), { needId, ...(svc === undefined ? {} : { service: svc }), ...over });

export interface DraftOpts { needs?: Need[]; steps?: StepSpec[]; created?: CreatedFile[]; notProven?: object[]; skipped?: PipelineDraft['skipped']; choices?: Record<string, string> }
/** secrets, sast, deps, unit-tests, image-build, image-scan (all for service api), hooks, gate and deploy-verify. */
export function draftOf(o: DraftOpts = {}): PipelineDraft {
  const prof = { ...profile([service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000 })]), repoFiles: emptyRepoFiles(), owner: 'CrisWorking', repo: 'shop', private: true };
  const needs = o.needs ?? [
    needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }),
    needOf('image-build', { service: 'api' }), needOf('image-scan', { service: 'api' }), needOf('hooks', { layer: 'pre-commit' }), needOf('gate', { floor: true }), needOf('deploy-verify', { layer: 'deploy' }),
  ];
  const steps = o.steps ?? [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec('trivy-image', 'image-scan', 'api', o.choices === undefined ? {} : { choices: o.choices })];
  return {
    profile: prof,
    capabilities: { branchProtection: true, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: true, attestations: false, codeScanning: false, keylessSigningAllowed: false },
    needs, steps, created: o.created ?? [], notProven: (o.notProven ?? []) as PipelineDraft['notProven'], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: o.skipped ?? [], suggestions: [],
  };
}
export { needOf, spec };

export const job = (name: string, conclusion: string | null = 'success', over: Partial<JobOutcome> = {}): JobOutcome => ({
  id: Math.floor(Math.random() * 1e9), name, attempt: 1, status: conclusion === null ? 'in_progress' : 'completed', conclusion, ...over,
});
export const file = (artifact: string, name: string, text: string | Buffer): ArtifactFile => {
  const bytes = Buffer.isBuffer(text) ? text : Buffer.from(text);
  return { artifact, file: name, bytes, sha256: createHash('sha256').update(bytes).digest('hex') };
};
let runIds = 1000;
export interface RunSpec { workflow?: string; event?: RunEvent; sha?: string; conclusion?: RunConclusion; jobs?: JobOutcome[]; artifacts?: ArtifactFile[]; problems?: Record<string, string>; stopped?: true; runId?: number; attempt?: number }
export function run(s: RunSpec): RunOutcome {
  const runId = s.runId ?? ++runIds;
  const workflow = s.workflow ?? PIPEGEN;
  const event = s.event ?? 'pull_request';
  return {
    handle: { workflow, runId, url: `https://github.com/CrisWorking/pipegen-proof-shop/actions/runs/${runId}`, event, headSha: s.sha ?? HEAD },
    conclusion: s.conclusion ?? 'success', attempt: s.attempt ?? 1, jobs: s.jobs ?? [],
    artifacts: new Map((s.artifacts ?? []).map((a) => [a.artifact, a])), artifactProblems: new Map(Object.entries(s.problems ?? {})), ...(s.stopped ? { stopped: true as const } : {}),
  };
}

export interface GateOpts { result?: 'pass' | 'warn' | 'block'; pass?: boolean; blocking?: object[]; warnings?: object[]; runId: number; event?: string; failedJobs?: object[]; notRun?: object[]; toolErrors?: object[]; checks?: object[]; blockReasons?: string[] }
export const gateFinding = (needId: string, tool: string, over: object = {}): object => ({ needId, job: needId, tool, ruleId: 'rule', severity: 'high', isNew: null, [FLAG]: false, ...over });
export function gateDoc(o: GateOpts, list: PipelineDraft): ArtifactFile {
  const result = o.result ?? 'pass';
  const checks = o.checks ?? gateJobList(list).map((e) => ({ needId: e.needId, job: e.job, ...(e.tool === undefined ? {} : { tool: e.tool }), judgedBy: e.format === 'sarif' ? 'findings' : 'job status', state: e.format === 'sarif' ? 'no findings' : 'passed' }));
  const doc = {
    pipegenGateResult: 1, result, pass: o.pass ?? result !== 'block', mode: 'warn', event: o.event ?? 'pull_request', sha: HEAD, runId: o.runId,
    blockReasons: o.blockReasons ?? [], warnReasons: [], counted: null, blocking: o.blocking ?? [], warnings: o.warnings ?? [], toolErrors: o.toolErrors ?? [],
    failedJobs: o.failedJobs ?? [], notRun: o.notRun ?? [], checks, notes: [], baseline: 'x', marker: 'x',
  };
  return file(GATE_RESULT_ARTIFACT, 'result.json', JSON.stringify(doc));
}

/** The names of the jobs a green PR run holds for a draft: every gate-list job, hooks, gate. */
export function pipegenJobs(d: PipelineDraft, extra: string[] = ['hooks', 'gate']): string[] {
  return [...new Set([...gateJobList(d).map((e) => e.job), ...extra])];
}
export const resultArtifacts = (d: PipelineDraft): ArtifactFile[] => gateJobList(d).filter((e) => e.artifact !== undefined).map((e) => file(e.artifact as string, 'results.sarif', '{"version":"2.1.0","runs":[]}'));

export const harnessJob = (id: string, conclusion: string | null = 'success', over: Partial<JobOutcome> = {}): JobOutcome => job(`pipegen proof: ${id}`, conclusion, over);

export interface GreenOpts { draft?: PipelineDraft; mergeSha?: string }
/** A fully green main variant: push run, PR run (pipegen, harness), merge run (pipegen, harness). Returns the runs for tweaking. */
export function greenMain(d: PipelineDraft = draftOf(), o: { mergeSha?: string; extraPrJobs?: JobOutcome[] } = {}): VariantRuns {
  const prRun = run({ event: 'pull_request', jobs: [...pipegenJobs(d).map((n) => job(n)), ...(o.extraPrJobs ?? [])], artifacts: [...resultArtifacts(d)], runId: 1 });
  prRun.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: 1 }, d));
  const mergeSha = o.mergeSha ?? MERGE;
  return {
    variant: 'main', mergeSha,
    outcomes: [
      run({ event: 'push', jobs: [job('secrets'), job('hooks')] }),
      prRun,
      run({ workflow: HARNESS_PATH, event: 'pull_request', jobs: [harnessJob('egress-check'), harnessJob('app-start'), harnessJob('verify-lookup', 'skipped')] }),
      run({ event: 'push', sha: mergeSha, jobs: [...pipegenJobs(d, ['gate', 'deploy-verify']).map((n) => job(n))] }),
      run({ workflow: HARNESS_PATH, event: 'push', sha: mergeSha, jobs: [harnessJob('egress-check'), harnessJob('app-start', 'skipped'), harnessJob('verify-lookup')] }),
    ],
  };
}
// Plan G G0 (F-2): every item names its job (needKey), as plantedFiles' items do; evaluate judges an item by that job only
export const PLANTED_ITEMS = [
  { id: 'sast-eval', category: 'sast', item: 'eval of user input', file: 'pipegen-planted/sast.js', needKey: 'sast--api' },
  { id: 'deps-vuln', category: 'deps', item: 'vulnerable dependency', file: 'pipegen-planted/package.json', needKey: 'deps--api' },
  { id: 'image-cve', category: 'image-scan', item: 'vulnerable base image', file: 'pipegen-planted/Dockerfile', needKey: 'image-scan--api' },
];
export const c1b = (): PlantedPlacement[] => [
  { kind: 'secret', path: 'node_modules/x.js', pathBytes: Buffer.from('node_modules/x.js'), rule: 'generic-api-key', line: 1 },
  { kind: 'secret', path: 'go.sum', pathBytes: Buffer.from('go.sum'), rule: 'generic-api-key', line: 1 },
  { kind: 'secret', path: 'pipegen-c1b/k�y.txt', pathBytes: Buffer.concat([Buffer.from('pipegen-c1b/k'), Buffer.from([0xe9]), Buffer.from('y.txt')]), rule: 'generic-api-key', line: 1, nonUtf8: true },
  { kind: 'integrity-warning', path: '.gitleaksignore', pathBytes: Buffer.from('.gitleaksignore'), line: 0 },
];
/** A planted variant whose gate blocks and reports a finding for every planted item. */
export function plantedRuns(d: PipelineDraft = draftOf(), o: { skip?: (f: { file?: string }) => boolean; gateConclusion?: string; result?: 'pass' | 'warn' | 'block'; omitResult?: boolean } = {}): VariantRuns {
  const blocking = [
    ...c1b().filter((p) => p.kind === 'secret').map((p) => gateFinding('secrets', 'gitleaks', { file: p.path, line: p.line, [FLAG]: true, ruleId: 'generic-api-key' })),
    ...PLANTED_ITEMS.map((p) => gateFinding(p.category, p.category === 'sast' ? 'semgrep' : p.category === 'image-scan' ? 'trivy' : 'osv-scanner', { file: p.file, job: `${p.category}--api` })),
  ].filter((f) => o.skip === undefined || !o.skip(f as { file?: string }));
  const pr = run({ event: 'pull_request', runId: 2, jobs: [...pipegenJobs(d, ['hooks']).map((n) => job(n)), job('gate', o.gateConclusion ?? 'failure')], conclusion: 'failure', artifacts: [] });
  if (o.omitResult !== true) pr.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: 2, result: o.result ?? 'block', blocking }, d));
  return { variant: 'planted', outcomes: [pr] };
}
export const matchPlanted: NonNullable<EvalContext['matchPlanted']> = (found, expected) => {
  const caught = expected.filter((e) => found.some((f) => f.file === e.file)).map((e) => e.id);
  return { caught, missed: expected.filter((e) => !caught.includes(e.id)).map((e) => e.id) };
};
export function ctxOf(over: Partial<EvalContext> = {}): EvalContext {
  return {
    userMain: new Map(), notCompared: [], planted: c1b(), plantedItems: PLANTED_ITEMS, matchPlanted, keys: 'real', harnessJobs: ['egress-check', 'app-start', 'verify-lookup'], ...over,
  };
}
export { COMPAT_PREFIX, HARNESS_PATH, jobIdFor, resultArtifactName, GATE_RESULT_ARTIFACT };
