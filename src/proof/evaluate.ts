// Plan E Task 4 / sub-task E5 (spec §19; rulings S8-S11, S23, E5-R1; Plan D carries): the finished proof runs become ONE verdict
// per part: proven, failed (with a precise reason that names the tool, item, need or workflow) or not-proven (with a note).
// This is the integrity core of the proof. A false "proven" ships a pipeline pipegen never showed working, and a "no results"
// read as a pass is the same failure, so the rule is: anything unreadable, missing, skipped or ambiguous is NEVER a pass.
//
// What it reads (E4's RunOutcome: runs, their latest attempt's jobs, downloaded result artifacts, capped logs of the failed
// jobs and of the coverage job). It never builds an AI excerpt (E7, with the evidence brand): logs are read only here, locally,
// to classify a failure.
//
// Parts and what proves them (one PartResult without a needId per part; PartResults with a needId are its details):
//   pipeline (all needs; covers every floor need)
//     main PR layer, merge layer (and any push layer run): every pipegen job finished green; the gate job is green on the PR and its
//     result.json (a REPORT, never authority, S9) is readable, belongs to this run and event, and agrees; every blocking findings
//     need has its result artifact and a check in the report; the harness egress-check is green. The planted PR: the gate job
//     BLOCKS, its report says so, and every blocking scanner caught its planted item (the C1b placements by file, Plan F's items
//     through the injected matcher). A compat copy that fails where the user's main passes is "pipegen broke <workflow>".
//   tests      existing suites by job result (JUnit only for created tests, S8); created tests: the JUnit of the run and of the
//              harness repeat are read in a worker, executed == the static count, skipped == 0, all pass, same results twice.
//   docker     image build jobs and the harness app-start; for a created Dockerfile also the image scan's critical/high findings
//              from the gate's warnings (S10).
//   compose    the harness app-start.
//   precommit  the hooks job.
//   deploy-verify  the harness verify-lookup on the push run of the MERGE commit, and sign-roundtrip when it was rendered.
// Not-proven (a failing part's logs name a missing secret, an external host refused the placeholder key, an external host can't
// be reached) never applies to a part that covers a floor need (spec §19): that is failed. One exception is a ruling, not a log
// reading: a scanner job that failed because Bullfrog refused its bind mount (E3-R7) is not-proven pending gate-v0.2.2 (E5-R1),
// and it keeps the pipeline from being proven (ok is false), so it is never a pass either.
import type { Octokit } from '@octokit/rest';
import { coverageNotes, measuredLines, type CoverageDecision } from '../create/coverage.js';
import { sameResults, type TestCaseResult } from '../create/junit.js';
import { readJunitBytes, type JunitRead } from '../create/junit-worker.js';
import { GATE_RESULT_ARTIFACT, slug } from '../engine/artifact-names.js';
import { gateJobList, GateJobListError, jobIdFor, FINDINGS_CATEGORIES, type JobListEntry } from '../engine/gate-job-list.js';
import { NEED_ID_CATEGORY } from '../engine/need-ids.js';
import { isRateStop } from '../engine/github-rate.js';
import { clockOf } from '../github/client.js';
import { FLOOR_NEEDS, type Finding, type NotProven, type Part, type PartResult, type PipelineDraft, type ProofResult, type RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { asFindings, gateResultOf, type GateFinding, type GateResultDoc } from './gate-result.js';
import { COMPAT_PREFIX, HARNESS_PATH, type HarnessJobId, type NotCompared } from './harness.js';
import type { JobOutcome, RunEvent, RunOutcome, VariantProof } from './run.js';
import type { PlantedPlacement, Variant } from './snapshot.js';
import { githubRead } from './target.js';

// ---------- the inputs ----------

/** One variant's finished runs: what proveVariant returned (E4), with the variant it was for. */
export interface VariantRuns {
  variant: Variant;
  outcomes: RunOutcome[];
  /** main, merged: the merge commit. Its push runs are the deploy layer. */
  mergeSha?: string;
  stopped?: boolean;
  missing?: VariantProof['missing'];
  notMerged?: string;
}
/** A created (starter) test run: its service and the validator's static test count (Plan D countTests). */
export interface CreatedTestRun { service: string; staticCount: number }
/** A planted item of Plan F (injected): what the scanner of `category` must catch. */
export interface PlantedItem { id: string; category: string; item: string; file?: string }
export type KeysMode = 'none' | 'placeholder' | 'real';
export interface EvalContext {
  /** The last default-branch run of each of the user's own workflows, by path (userMainStatuses). A path not listed is 'none'. */
  userMain: ReadonlyMap<string, 'success' | 'failure' | 'none'>;
  /** Compat jobs E3 could not copy: listed in the pipeline detail, never proven or failed. */
  notCompared: readonly NotCompared[];
  /** The planted secrets E owns (C1b, snapshot.ts plantedSecretPlacements), each expected by file. */
  planted: readonly PlantedPlacement[];
  /** Plan F's planted items and its matcher (injected). Items without a matcher can't be judged: failed. */
  plantedItems?: readonly PlantedItem[];
  matchPlanted?: (found: Finding[], expected: PlantedItem[], toolsByCategory: Map<string, string>) => { caught: string[]; missed: string[] };
  /** ScratchKeys.mode: 'none' is treated as 'placeholder' (S15). */
  keys: KeysMode;
  /** The harness jobs E3 rendered (Harness.jobs ids) and its notes (why a job isn't there). */
  harnessJobs: readonly HarnessJobId[];
  harnessNotes?: readonly string[];
  /** E2's not-proven notes (symlink or LFS in a docker service, an edited user workflow). */
  carried?: readonly NotProven[];
  /** Created tests (Plan G turns them on; never in v0.2 until D7-R7): the JUnit of their runs is read. */
  createdTests?: readonly CreatedTestRun[];
  /** Reads a JUnit report (default: readJunitBytes, the worker). Never trusted to throw nothing: a throw is "report unreadable". */
  readJunit?: (bytes: Uint8Array) => Promise<JunitRead>;
  /** Pipegen's own workflow files (default: the workflow files the draft creates, else .github/workflows/pipegen.yml). Runs of any other file are untrusted. */
  pipegenWorkflows?: readonly string[];
  /** The repo's own coverage minimum (readExistingMinimum), for the coverage notes. */
  existingMinimum?: number | null;
  /** The minutes meter's total (E6). */
  minutesUsed?: number;
}
export interface Evaluation {
  result: ProofResult;
  /** The measured lines of the coverage job(s) (S11) and what coverageNotes makes of the lowest; null when it could not be read. */
  coverage: { measured: number | null; lowest: number | null; decision: CoverageDecision | null };
  /** The failed jobs behind a part (or part:needId): their names and raw logs, for E7's classifier and excerpt. */
  evidence: Map<string, { jobs: string[]; log: string }>;
}

// ---------- names, logs and signatures ----------

export const HARNESS_JOB_PREFIX = 'pipegen proof: ';
/** The Bullfrog refusal of a bind mount (spike S8: the Docker daemon's own line while sudo is disabled). */
export const BULLFROG_MOUNT_RE = /Error response from daemon: bullfrog: mounting the host path [^\r\n]{1,300} is not allowed while sudo is disabled/;
export const E5_R1_NOTE = "its scanner step's bind mount was refused by Bullfrog (egress control with sudo off); pending gate-v0.2.2 (scanner steps without bind mounts), so it is not proven yet";
const EMPTY_SECRET_RE = /Input required and not supplied|secret.*(?:empty|not set)/i;
const KEY_REFUSED_RE = /\b(?:401|403)\b[^\n]{0,80}(?:unauthori[sz]ed|forbidden|invalid|denied)|invalid[ _-]?api[ _-]?key|incorrect api key|api key (?:is )?(?:invalid|incorrect)|authentication failed|invalid[_ ]?token/i;
const CONNECT_RE = /(?:getaddrinfo\s+(?:ENOTFOUND|EAI_AGAIN)|connect\s+(?:ECONNREFUSED|ETIMEDOUT|ECONNRESET|EHOSTUNREACH)|ENOTFOUND|EAI_AGAIN|Could not resolve host:?)\s+([A-Za-z0-9.-]{1,253})/g;
/** Hosts pipegen's own plumbing depends on: a failure to reach one is not "an external dependency of the app". */
const PLUMBING_HOST_RE = /(?:^|\.)(?:github\.com|githubusercontent\.com|npmjs\.org|npmjs\.com|pypi\.org|pythonhosted\.org|ghcr\.io|docker\.io|docker\.com|cloudflare\.docker\.com)$/i;
const PRIVATE_IP_RE = /^(?:127\.|10\.|0\.0\.0\.0$|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z(?: |$)/;
const ANSI = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)|\u001b\[[0-?]*[ -/]*[@-~]|\u001b[ -/]*[0-~]?/g;
const MAX_LOG_READ = 8 * 1024 * 1024;

/** A job log as plain lines: the GitHub timestamp prefix, a BOM, CR and ANSI sequences removed (S11). For reading only, never for display. */
export function cleanLog(log: string): string {
  const text = String(log).slice(-MAX_LOG_READ);
  return text.split('\n').map((l) => {
    let s = l.endsWith('\r') ? l.slice(0, -1) : l;
    if (s.startsWith('\ufeff')) s = s.slice(1);
    return s.replace(TIMESTAMP, '').replace(ANSI, '');
  }).join('\n');
}
const st = (s: unknown, n = 120): string => safeText(String(s), n);
const isRec = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null;

/** Whether `name` (an exact secret name) appears in `text` as a whole word of the characters a name holds. */
function mentionsName(text: string, name: string): boolean {
  if (name === '') return false;
  for (let at = text.indexOf(name); at >= 0; at = text.indexOf(name, at + 1)) {
    const before = text[at - 1], after = text[at + name.length];
    if ((before === undefined || !/[A-Za-z0-9_]/.test(before)) && (after === undefined || !/[A-Za-z0-9_]/.test(after))) return true;
  }
  return false;
}
/** The first host an app could not reach that is neither a compose service, an address of the runner nor package-registry plumbing. */
function externalHost(text: string): string | null {
  for (const m of text.matchAll(CONNECT_RE)) {
    const host = (m[1] as string).replace(/\.$/, '');
    if (!host.includes('.') || PRIVATE_IP_RE.test(host) || /^\d+\.\d+\.\d+\.\d+$/.test(host) || PLUMBING_HOST_RE.test(host)) continue;
    return host;
  }
  return null;
}

// ---------- jobs and runs ----------

type Kind = 'pipegen' | 'harness' | 'compat' | 'other';
/** Only the draft's own pipegen workflow files and the harness are trusted sources of proof (m7); a compat copy is the user's; anything else is untrusted. */
const kindOfPath = (workflow: string, trusted: ReadonlySet<string>): Kind => (workflow === HARNESS_PATH ? 'harness' : workflow.startsWith(COMPAT_PREFIX) ? 'compat' : trusted.has(workflow) ? 'pipegen' : 'other');
const DEFAULT_PIPEGEN = new Set(['.github/workflows/pipegen.yml']);
const kindOf = (workflow: string): Kind => kindOfPath(workflow, DEFAULT_PIPEGEN);
/** The kind of each outcome of the evaluation under way (set synchronously at its start, before any await). */
const KINDS = new WeakMap<object, Kind>();
const TOP_WORKFLOW_RE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
function trustedWorkflows(draft: PipelineDraft, ctx: EvalContext): Set<string> {
  const out = new Set<string>(ctx.pipegenWorkflows ?? []);
  for (const f of draft.created) if (TOP_WORKFLOW_RE.test(f.path) && f.path !== HARNESS_PATH && !f.path.startsWith(COMPAT_PREFIX)) out.add(f.path);
  return out.size > 0 ? out : new Set(DEFAULT_PIPEGEN);
}
/** `caller / callee (matrix)` → `callee`, and the id with its matrix suffix stripped. A name equal to the id, or the id plus ` (…)`, matches it. */
export function jobNameMatches(name: string, id: string): boolean {
  if (typeof name !== 'string' || id === '') return false;
  const at = name.lastIndexOf(' / ');
  const base = (at < 0 ? name : name.slice(at + 3)).trim();
  return base === id || (base.startsWith(`${id} (`) && base.endsWith(')'));
}
interface Hit { job: JobOutcome; run: RunOutcome }
/** The latest attempt of each distinct job name of a run (filter=all lists every attempt). */
function latest(jobs: readonly JobOutcome[]): JobOutcome[] {
  const best = new Map<string, JobOutcome>();
  for (const j of jobs) {
    if (!isRec(j) || typeof j.name !== 'string') continue;
    const have = best.get(j.name);
    if (have === undefined || (typeof j.attempt === 'number' ? j.attempt : 0) >= (typeof have.attempt === 'number' ? have.attempt : 0)) best.set(j.name, j);
  }
  return [...best.values()];
}
const hitsIn = (runs: readonly RunOutcome[], match: (name: string) => boolean): Hit[] => runs.flatMap((run) => latest(run.jobs).filter((job) => match(job.name)).map((job) => ({ job, run })));
const ok = (j: JobOutcome): boolean => j.conclusion === 'success';
const jobSkipped = (j: JobOutcome): boolean => j.conclusion === 'skipped';
type State = 'success' | 'failed' | 'skipped' | 'absent';
function stateOf(hits: readonly Hit[]): State {
  if (hits.length === 0) return 'absent';
  if (hits.some((h) => !ok(h.job) && !jobSkipped(h.job))) return 'failed';
  return hits.every((h) => jobSkipped(h.job)) ? 'skipped' : 'success';
}
const failing = (hits: readonly Hit[]): Hit[] => hits.filter((h) => !ok(h.job) && !jobSkipped(h.job));
const describeJob = (h: Hit): string => {
  const c = h.job.conclusion;
  return `${st(h.job.name, 80)} ${c === null || h.job.status !== 'completed' ? 'did not finish' : c === 'failure' ? 'failed' : `ended ${st(c, 30)}`} (${h.run.handle.event})`;
};

/** A check another part owns: failed when it failed in ANY pipegen layer (push, pull request, merge); proven only when it also ran green in `required`. */
function ownedState(layers: Layers, required: readonly RunOutcome[], id: string): { state: State; hits: Hit[] } {
  const all = hitsIn(ofKind([...layers.push, ...layers.pr, ...layers.merge], 'pipegen'), (n) => jobNameMatches(n, id));
  if (failing(all).length > 0) return { state: 'failed', hits: all };
  return { state: stateOf(hitsIn(required, (n) => jobNameMatches(n, id))), hits: all };
}

interface Layers { push: RunOutcome[]; pr: RunOutcome[]; merge: RunOutcome[] }
function layersOf(v: VariantRuns): Layers {
  const out: Layers = { push: [], pr: [], merge: [] };
  for (const o of v.outcomes) {
    if (!isRec(o) || !isRec(o.handle) || !Array.isArray(o.jobs) || !(o.artifacts instanceof Map) || !(o.artifactProblems instanceof Map)) throw new Error('a run outcome is malformed');
    const e: RunEvent = o.handle.event;
    if (e === 'pull_request') out.pr.push(o);
    else if (v.mergeSha !== undefined && o.handle.headSha === v.mergeSha) out.merge.push(o);
    else out.push.push(o);
  }
  return out;
}
const ofKind = (runs: readonly RunOutcome[], k: Kind): RunOutcome[] => runs.filter((r) => (KINDS.get(r) ?? kindOf(r.handle.workflow)) === k);

// ---------- the verdict collector ----------

interface Verdict { part: Part; needId?: string; status: 'failed' | 'not-proven' | 'proven'; detail: string; /** a not-proven that keeps its part from being proven */ caps: boolean; url?: string }
class Sheet {
  readonly verdicts: Verdict[] = [];
  readonly notes = new Map<Part, string[]>();
  readonly evidence = new Map<string, { jobs: string[]; log: string }>();
  /** The gate job did not pass on the main pull request: ok can never be true. */
  gateMainFailed = false;
  private readonly seen = new Set<string>();
  fail(part: Part, detail: string, needId?: string, url?: string): void { this.add({ part, ...(needId === undefined ? {} : { needId }), status: 'failed', detail, caps: false, ...(url === undefined ? {} : { url }) }); }
  notProven(part: Part, detail: string, opts: { needId?: string; caps?: boolean; url?: string } = {}): void {
    this.add({ part, ...(opts.needId === undefined ? {} : { needId: opts.needId }), status: 'not-proven', detail, caps: opts.caps === true, ...(opts.url === undefined ? {} : { url: opts.url }) });
  }
  proven(part: Part, needId: string, detail: string): void { this.add({ part, needId, status: 'proven', detail, caps: false }); }
  note(part: Part, text: string): void { const l = this.notes.get(part) ?? []; if (!l.includes(text)) l.push(text); this.notes.set(part, l); }
  private add(v: Verdict): void {
    const key = v.status === 'not-proven' && !v.caps ? `${v.part}|${v.needId ?? ''}|np` : `${v.part}|${v.needId ?? ''}|${v.status}|${v.detail}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.verdicts.push(v);
  }
  evidenceOf(key: string, hits: readonly Hit[]): void {
    const have = this.evidence.get(key) ?? { jobs: [], log: '' };
    for (const h of hits.slice(0, 5)) {
      if (!have.jobs.includes(h.job.name)) have.jobs.push(st(h.job.name, 120));
      if (typeof h.job.log === 'string' && have.log.length < MAX_LOG_READ) have.log += `${have.log === '' ? '' : '\n'}${h.job.log}`;
    }
    this.evidence.set(key, have);
  }
}

// ---------- classification of a failing part ----------

interface Classified { status: 'failed' | 'not-proven'; detail: string }
class Judge {
  readonly missing: string[];
  constructor(private readonly draft: PipelineDraft, private readonly keys: KeysMode) {
    this.missing = [...new Set(draft.notProven.flatMap((n) => (Array.isArray(n.missingSecrets) ? n.missingSecrets : [])).filter((n) => typeof n === 'string' && n !== ''))];
  }
  /** A part that covers a floor need is never not-proven (spec §19). Otherwise the logs of its failed jobs may name a missing secret, a refused placeholder key or an external host. */
  classify(floor: boolean, failed: readonly Hit[], what: string): Classified {
    const names = failed.map((h) => describeJob(h)).join(', ');
    if (!floor) {
      const text = cleanLog(failed.map((h) => (typeof h.job.log === 'string' ? h.job.log : '')).join('\n'));
      const named = this.missing.filter((n) => mentionsName(text, n));
      if (named.length > 0) return { status: 'not-proven', detail: `${what}: ${names}; its log names ${named.map((n) => st(n, 80)).join(', ')}, which was not given, so it is not proven` };
      if (this.keys !== 'real' && KEY_REFUSED_RE.test(text)) return { status: 'not-proven', detail: `${what}: ${names}; an external host refused the placeholder key: needs your real test key` };
      const host = externalHost(text);
      if (host !== null) return { status: 'not-proven', detail: `${what}: ${names}; it could not reach ${st(host, 100)}, an external host, so it is not proven` };
    }
    return { status: 'failed', detail: `${what}: ${names}` };
  }
}

// ---------- the evaluation ----------

/** The checks another part reports (category → the --skip part name that switches that part off). */
const OWNER_PART: Readonly<Record<string, { part: Part; skip: string }>> = Object.freeze({
  'image-build': { part: 'docker', skip: 'docker' }, hooks: { part: 'precommit', skip: 'precommit' }, 'hooks-ci': { part: 'precommit', skip: 'precommit' },
  'unit-tests': { part: 'tests', skip: 'tests' }, 'full-tests': { part: 'tests', skip: 'tests' }, coverage: { part: 'tests', skip: 'tests' }, 'deploy-verify': { part: 'deploy-verify', skip: 'deploy' },
});
const TESTS_CATEGORIES: ReadonlySet<string> = new Set(['unit-tests', 'full-tests']);
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const categoryOf = (needId: string, declared?: string): string => (declared !== undefined && declared !== '' ? declared : (Object.hasOwn(NEED_ID_CATEGORY, needId) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[needId] as string : needId));
const needsTests = (draft: PipelineDraft): boolean => draft.needs.some((n) => TESTS_CATEGORIES.has(categoryOf(n.id, n.category)));
const SEVERE: ReadonlySet<string> = new Set(['critical', 'high']);
const MAX_DETAIL = 1500;

const joined = (xs: readonly string[]): string => safeText(xs.join('; '), MAX_DETAIL);
const inFolderNeed = (n: { id: string; service?: string }): string => jobIdFor(n.id, n.service);

export async function evaluateProof(draft: PipelineDraft, runs: readonly VariantRuns[], ctx: EvalContext): Promise<Evaluation> {
  try {
    return await evaluateInner(draft, runs, ctx);
  } catch (e) {
    // anything that cannot be read is a failed pipeline, never an exception that a caller could take for "nothing wrong"
    const why = e instanceof GateJobListError ? `the gate's job list could not be computed (${st(e.message, 200)})` : `the proof's results could not be read (${st(e instanceof Error ? e.message : 'unknown', 200)})`;
    return {
      result: { ok: false, parts: [{ part: 'pipeline', status: 'failed', detail: `report unreadable: ${why}` }], findings: [], minutesUsed: ctx?.minutesUsed ?? 0, runUrls: [] },
      coverage: { measured: null, lowest: null, decision: null }, evidence: new Map(),
    };
  }
}

/** The plan's evaluate(): the ProofResult. evaluateProof also returns the measured coverage and the evidence of failed jobs. */
export async function evaluate(draft: PipelineDraft, runs: readonly VariantRuns[], ctx: EvalContext): Promise<ProofResult> {
  return (await evaluateProof(draft, runs, ctx)).result;
}

async function evaluateInner(draft: PipelineDraft, runs: readonly VariantRuns[], ctx: EvalContext): Promise<Evaluation> {
  if (!Array.isArray(runs)) throw new Error('the runs are not a list');
  const sheet = new Sheet();
  const judge = new Judge(draft, ctx.keys);
  const main = runs.find((v) => v.variant === 'main');
  const planted = runs.find((v) => v.variant === 'planted');
  const jobList = gateJobList(draft);
  const skipped = new Map<string, string>(draft.skipped.map((s) => [s.part, s.reason]));
  const mainLayers = main === undefined ? { push: [], pr: [], merge: [] } : layersOf(main);
  const plantedLayers = planted === undefined ? { push: [], pr: [], merge: [] } : layersOf(planted);
  const trusted = trustedWorkflows(draft, ctx);
  for (const v of runs) for (const o of v.outcomes) if (isRec(o) && isRec(o.handle) && typeof o.handle.workflow === 'string') KINDS.set(o, kindOfPath(o.handle.workflow, trusted));
  const allUrls = new Set<string>();
  for (const v of runs) for (const o of v.outcomes) if (isRec(o) && isRec(o.handle) && typeof o.handle.url === 'string') allUrls.add(o.handle.url);

  // which jobs belong to which need (for the refused-mount signature and the ownership of the other parts)
  const scannerJobs = new Map<string, string>();   // job id → need id
  const ownedJobs = new Map<string, Part>();
  for (const n of draft.needs) {
    const cat = categoryOf(n.id, n.category);
    if (FINDINGS_CATEGORIES.has(cat)) scannerJobs.set(inFolderNeed(n), n.id);
    // a job another part reports is that part's, unless the user skipped the part (then nobody else would see it fail)
    const owner = OWNER_PART[cat];
    if (owner !== undefined && !skipped.has(owner.skip)) ownedJobs.set(inFolderNeed(n), owner.part);
  }
  // a part covers a floor need: the pipeline always; tests only when the draft has a unit-tests or full-tests need (m2)
  const floorOf = (part: Part): boolean => part === 'pipeline' || (part === 'tests' && needsTests(draft));
  const refusedIn = (runsOf: readonly RunOutcome[]): Map<string, Hit[]> => {
    const out = new Map<string, Hit[]>();
    for (const [job, needId] of scannerJobs) {
      const hits = failing(hitsIn(ofKind(runsOf, 'pipegen'), (n) => jobNameMatches(n, job))).filter((h) => typeof h.job.log === 'string' && BULLFROG_MOUNT_RE.test(cleanLog(h.job.log)));
      if (hits.length > 0) out.set(needId, [...(out.get(needId) ?? []), ...hits]);
    }
    return out;
  };
  const refusedNote = (needId: string, hits: readonly Hit[]): void => {
    sheet.notProven('pipeline', `${st(needId, 60)}: ${E5_R1_NOTE}`, { needId, caps: true, url: hits[0]?.run.handle.url });
    sheet.evidenceOf(`pipeline:${needId}`, hits);
  };

  // ===== pipeline: main =====
  let gateMain: GateResultDoc | null = null;
  if (main === undefined) sheet.fail('pipeline', 'the main variant was not proven, so the pipeline is not shown to work');
  else {
    gateMain = pipelineMain(draft, main, mainLayers, ctx, sheet, jobList, scannerJobs, ownedJobs, refusedIn, refusedNote, judge, floorOf);
  }
  // ===== pipeline: planted =====
  if (planted === undefined) sheet.fail('pipeline', "the planted variant was not proven, so the scanners are not shown to catch anything and the gate is not shown to block planted problems");
  else plantedChecks(draft, planted, plantedLayers, ctx, sheet, jobList, scannerJobs, refusedIn, refusedNote);

  // ===== the harness jobs and the other parts =====
  const harnessPr = ofKind(mainLayers.pr, 'harness');
  const harnessMerge = ofKind(mainLayers.merge, 'harness');
  const pipegenPr = ofKind(mainLayers.pr, 'pipegen');
  const pipegenMerge = ofKind(mainLayers.merge, 'pipegen');
  const harnessId = (id: HarnessJobId) => (name: string): boolean => name === `${HARNESS_JOB_PREFIX}${id}`;
  const rendered = (id: HarnessJobId): boolean => ctx.harnessJobs.includes(id);

  // egress-check (pipeline): both events
  if (main !== undefined) {
    for (const [label, rs] of [['pull request', harnessPr], ['merge', harnessMerge]] as const) {
      if (label === 'merge' && main.mergeSha === undefined) continue;
      if (rs.length === 0) { sheet.fail('pipeline', `the proof harness did not run on the ${label}, so the egress control is not shown to block a forbidden host`); continue; }
      const hits = hitsIn(rs, harnessId('egress-check'));
      const s = stateOf(hits);
      if (s === 'failed') { sheet.fail('pipeline', `the egress control failed open or broke: ${failing(hits).map(describeJob).join(', ')}`, undefined, hits[0]?.run.handle.url); sheet.evidenceOf('pipeline', failing(hits)); }
      else if (s !== 'success') sheet.fail('pipeline', `the harness egress-check did not run on the ${label}, so the egress control is not shown to block a forbidden host`);
    }
  }

  // app-start (compose; docker also needs it)
  type AppState = { state: State | 'not-rendered'; hits: Hit[] };
  const appHits = hitsIn(harnessPr, harnessId('app-start'));
  const app: AppState = !rendered('app-start') ? { state: 'not-rendered', hits: [] } : { state: stateOf(appHits), hits: appHits };
  const appNote = (): string => (ctx.harnessNotes ?? []).filter((n) => /app-start/.test(n)).map((n) => st(n, 300)).join(' ') || 'the harness has no app-start job';
  const appVerdict = (part: Part): void => {
    if (main === undefined) { sheet.notProven(part, 'the main variant was not proven, so the app start is not proven', { caps: true }); return; }
    if (app.state === 'not-rendered') sheet.notProven(part, `app start: ${appNote()}`, { caps: true });
    else if (app.state === 'absent' || app.state === 'skipped') sheet.fail(part, 'the harness app-start did not run, so the app is not shown to start');
    else if (app.state === 'failed') {
      const f = judge.classify(floorOf(part), failing(app.hits), 'app-start');
      if (f.status === 'failed') sheet.fail(part, f.detail, undefined, app.hits[0]?.run.handle.url); else sheet.notProven(part, f.detail, { caps: true, url: app.hits[0]?.run.handle.url });
      sheet.evidenceOf(part, failing(app.hits));
    }
  };

  // compose
  if (skipped.has('compose')) sheet.notProven('compose', `skipped by you (--skip): ${st(skipped.get('compose'), 200)}`, { caps: true });
  else if (draft.created.some((f) => f.part === 'compose') || rendered('app-start') || (ctx.harnessNotes ?? []).some((n) => /app-start/.test(n))) appVerdict('compose');

  // docker
  const imageBuilds = draft.needs.filter((n) => categoryOf(n.id, n.category) === 'image-build');
  const createdDockerfile = draft.created.some((f) => f.part === 'docker' && /(^|\/)Dockerfile[^/]*$/.test(f.path));
  const carriedDocker = (ctx.carried ?? []).some((n) => n.part === 'docker');
  if (skipped.has('docker')) sheet.notProven('docker', `skipped by you (--skip): ${st(skipped.get('docker'), 200)}`, { caps: true });
  else if (imageBuilds.length > 0 || createdDockerfile || carriedDocker) {
    if (main === undefined) sheet.notProven('docker', 'the main variant was not proven, so docker is not proven', { caps: true });
    for (const n of (main === undefined ? [] : imageBuilds)) {
      const id = inFolderNeed(n);
      const { state: s, hits } = ownedState(mainLayers, pipegenPr, id);
      if (s === 'failed') {
        const f = judge.classify(false, failing(hits), `image build ${st(id, 80)}`);
        if (f.status === 'failed') sheet.fail('docker', f.detail, n.id, hits[0]?.run.handle.url); else sheet.notProven('docker', f.detail, { needId: n.id, caps: true, url: hits[0]?.run.handle.url });
        sheet.evidenceOf('docker', failing(hits));
      } else if (s !== 'success') sheet.fail('docker', `the image build job ${st(id, 80)} did not run on the pull request`, n.id);
    }
    if (imageBuilds.length > 0 || createdDockerfile) appVerdict('docker');
    if (createdDockerfile && main !== undefined) {
      // a created Dockerfile's base image is proven only by an image-scan result READ from the trusted run (I3): the scan's check, its
      // artifact from the run of its job, no tool error, and no critical/high finding. Without it: not-proven (docker covers no floor need).
      const g = gateMain;
      const scans = jobList.filter((e) => e.category === 'image-scan' && e.range !== true);
      if (scans.length === 0) sheet.notProven('docker', 'the draft has no image scan check for the created Dockerfile, so its base image is not proven', { caps: true });
      for (const e of scans) {
        const why: string[] = [];
        const hits = hitsIn(pipegenPr, (name) => jobNameMatches(name, e.job));
        if (stateOf(hits) !== 'success') why.push('its job did not finish green on the pull request');
        if (e.artifact === undefined || !hits.some((h) => h.run.artifacts.has(e.artifact as string))) why.push('its result artifact is missing');
        if (g === null) why.push("the gate's report is unreadable");
        else {
          if (!g.checks.some((c) => c.needId === e.needId && c.job === e.job)) why.push("the gate's report has no check for it");
          if (g.toolErrors.some((t) => t.needId === e.needId && t.job === e.job)) why.push('the gate reports a tool error for it');
        }
        if (why.length > 0) sheet.notProven('docker', `the image scan ${st(e.job, 80)} was not read (${why.join('; ')}), so the created Dockerfile's base image is not proven`, { needId: e.needId, caps: true });
      }
      if (g !== null) {
        const severe = [...g.blocking, ...g.warnings].filter((f) => (f.needId === 'image-scan' || categoryOf(f.needId) === 'image-scan') && SEVERE.has(f.severity));
        if (severe.length > 0) {
          const ids = [...new Set(severe.map((f) => st(f.ruleId, 60)))].slice(0, 8).join(', ');
          sheet.fail('docker', `the base image has critical/high (fix info unknown until gate-v0.2.2) CVEs (${ids}); another base image tag is needed`, 'image-scan');
        }
      }
    }
  }
  for (const n of ctx.carried ?? []) {
    if (n.part === 'docker') sheet.notProven('docker', st(n.reason, 400), { caps: true });
    else sheet.notProven(n.part, st(n.reason, 400), { ...(n.needId === undefined ? {} : { needId: n.needId }), caps: n.part !== 'pipeline' });
  }

  // precommit
  const hooks = draft.needs.filter((n) => ['hooks', 'hooks-ci'].includes(categoryOf(n.id, n.category)));
  if (skipped.has('precommit')) sheet.notProven('precommit', `skipped by you (--skip): ${st(skipped.get('precommit'), 200)}`, { caps: true });
  else if (hooks.length > 0 && main === undefined) sheet.notProven('precommit', 'the main variant was not proven, so the hooks are not proven', { caps: true });
  else for (const n of hooks) {
    const id = inFolderNeed(n);
    const { state: s, hits } = ownedState(mainLayers, pipegenPr, id);
    if (s === 'failed') {
      const f = judge.classify(false, failing(hits), `hooks ${st(id, 80)}`);
      if (f.status === 'failed') sheet.fail('precommit', f.detail, n.id, hits[0]?.run.handle.url); else sheet.notProven('precommit', f.detail, { needId: n.id, caps: true });
      sheet.evidenceOf('precommit', failing(hits));
    } else if (s !== 'success') sheet.fail('precommit', `the hooks job ${st(id, 80)} did not run on the pull request`, n.id);
  }

  // deploy-verify
  if (skipped.has('deploy')) sheet.notProven('deploy-verify', `skipped by you (--skip): ${st(skipped.get('deploy'), 200)}`, { caps: true });
  else {
    if (main !== undefined && main.mergeSha === undefined) sheet.fail('deploy-verify', main.notMerged !== undefined ? `the pull request was not merged, so verify-lookup did not run (${st(main.notMerged, 300)})` : 'the pull request was not merged, so verify-lookup did not run');
    else if (main === undefined) sheet.fail('deploy-verify', 'the main variant was not proven, so verify-lookup is not proven');
    else if (main !== undefined) {
      if (!rendered('verify-lookup')) sheet.notProven('deploy-verify', `verify-lookup is not rendered in the harness (${(ctx.harnessNotes ?? []).map((n) => st(n, 200)).join(' ') || 'no reason given'})`, { caps: true });
      else {
        const hits = hitsIn(harnessMerge, harnessId('verify-lookup'));
        const s = stateOf(hits);
        if (s === 'failed') { sheet.fail('deploy-verify', `verify-lookup on the push run of the merge to the default branch: ${failing(hits).map(describeJob).join(', ')}`, undefined, hits[0]?.run.handle.url); sheet.evidenceOf('deploy-verify', failing(hits)); }
        else if (s !== 'success') sheet.fail('deploy-verify', 'verify-lookup did not run on the push run of the merge to the default branch, so the gated run lookup is not shown to work');
      }
      for (const n of draft.needs.filter((x) => categoryOf(x.id, x.category) === 'deploy-verify')) {
        const id = inFolderNeed(n);
        const { state: s, hits } = ownedState(mainLayers, pipegenMerge, id);
        if (s === 'failed') { sheet.fail('deploy-verify', `the deploy-verify job ${failing(hits).map(describeJob).join(', ')}`, n.id, hits[0]?.run.handle.url); sheet.evidenceOf('deploy-verify', failing(hits)); }
        else if (s !== 'success') sheet.fail('deploy-verify', `the deploy-verify job ${st(id, 80)} did not run on the merge`, n.id);
      }
    }
    if (rendered('sign-roundtrip')) {
      const hits = hitsIn(harnessPr, harnessId('sign-roundtrip'));
      const s = stateOf(hits);
      if (s === 'failed') { sheet.fail('deploy-verify', `sign-roundtrip: ${failing(hits).map(describeJob).join(', ')}`, undefined, hits[0]?.run.handle.url); sheet.evidenceOf('deploy-verify', failing(hits)); }
      else if (s !== 'success') sheet.fail('deploy-verify', 'sign-roundtrip did not run, so signing is not shown to work');
    }
  }

  // tests and coverage
  const coverage = await testsPart(draft, main, mainLayers, ctx, sheet, judge, skipped, harnessPr, harnessId, rendered);

  // ===== assemble =====
  const parts = assemble(sheet, draft, ctx, { main: main !== undefined, floorOf });
  const findings = gateMain === null ? [] : asFindings([...gateMain.blocking, ...gateMain.warnings]);
  const partOk = (p: PartResult): boolean => p.status === 'proven';
  const overall = PART_ORDER.map((pt) => parts.find((p) => p.part === pt && p.needId === undefined)).filter((p): p is PartResult => p !== undefined);
  const okAll = !sheet.gateMainFailed && !parts.some((p) => p.status === 'failed')
    && overall.every((p) => partOk(p) || !(p.part === 'pipeline' || (p.part === 'tests' && floorOf('tests') && !skipped.has('tests'))));
  return {
    result: { ok: okAll, parts, findings, minutesUsed: typeof ctx.minutesUsed === 'number' && Number.isFinite(ctx.minutesUsed) ? ctx.minutesUsed : 0, runUrls: [...allUrls] },
    coverage, evidence: sheet.evidence,
  };
}

/** The conclusions a failed job can carry in the gate's own text `required check <tool> (<job>) did not succeed (<result>)`. */
const GATE_RESULTS = ['failure', 'cancelled', 'timed_out', 'skipped', 'startup_failure', 'action_required', 'neutral', 'stale'] as const;
/**
 * Whether EVERY reason of a failed gate is a job whose failure is reported elsewhere (E5-R1 refused scanners, owned jobs that failed).
 * result.json gives no job id per reason, so a reason counts only when it equals, character for character, the text gate/src/decide.ts
 * writes for a structured entry (failedJobs, or a blocking toolError) of an explained job. Anything else is unexplained: a reason that
 * only contains a job id (`test` inside `test-e2e`), extra text, no reasons at all, a finding, a not-run fork check, a settings error.
 */
export function blockExplained(d: GateResultDoc, jobList: readonly JobListEntry[], explained: ReadonlySet<string>): boolean {
  if (d.pass || d.blocking.length > 0 || d.notRun.length > 0 || d.blockReasons.length === 0) return false;
  const expected = new Set<string>();
  const toolOf = (job: string): string | null => { const e = jobList.find((x) => x.job === job); return e === undefined ? null : (e.tool ?? e.needId); };
  let refs = 0;
  for (const f of d.failedJobs) {
    const tool = toolOf(f.job);
    if (!explained.has(f.job) || tool === null) return false;
    for (const r of GATE_RESULTS) expected.add(`required check ${tool} (${f.job}) did not succeed (${r})`);
    refs++;
  }
  for (const t of d.toolErrors) {
    if (!t.blocks) continue;
    if (!explained.has(t.job)) return false;
    expected.add(`tool error in ${t.tool ?? t.needId} (${t.job})${t.base ? ' on the base commit' : ''}: re-run the job`);
    refs++;
  }
  return refs > 0 && d.blockReasons.every((r) => expected.has(r));
}

// ---------- pipeline: main variant ----------

type RefusedIn = (runs: readonly RunOutcome[]) => Map<string, Hit[]>;
function pipelineMain(
  draft: PipelineDraft, main: VariantRuns, layers: Layers, ctx: EvalContext, sheet: Sheet, jobList: readonly JobListEntry[],
  scannerJobs: ReadonlyMap<string, string>, ownedJobs: ReadonlyMap<string, Part>, refusedIn: RefusedIn, refusedNote: (needId: string, hits: readonly Hit[]) => void,
  judge: Judge, floorOf: (p: Part) => boolean,
): GateResultDoc | null {
  const prP = ofKind(layers.pr, 'pipegen');
  const mergeP = ofKind(layers.merge, 'pipegen');
  const pushP = ofKind(layers.push, 'pipegen');
  unreadableRuns(layers, sheet);
  // layers that must have run
  if (main.stopped === true || [...layers.push, ...layers.pr, ...layers.merge].some((o) => o.stopped === true)) sheet.fail('pipeline', 'the proof was stopped before every run finished, so the pipeline is not proven');
  for (const m of main.missing ?? []) {
    if (kindOf(m.workflow) === 'compat') sheet.note('pipeline', `compat: ${st(m.workflow.replace(COMPAT_PREFIX, '.github/workflows/'), 100)} did not run in the scratch repo (path or branch filters?), so it is not compared`);
    else sheet.fail('pipeline', `${st(m.workflow, 100)} never started on the ${m.event === 'pull_request' ? 'pull request' : 'push'}`);
  }
  if (prP.length === 0) sheet.fail('pipeline', "pipegen's workflow did not run on the pull request");
  if (main.mergeSha === undefined) sheet.fail('pipeline', main.notMerged !== undefined ? `the pull request was not merged, so the deploy layer did not run (${st(main.notMerged, 300)})` : 'the pull request was not merged, so the deploy layer did not run');
  else if (mergeP.length === 0) sheet.fail('pipeline', "pipegen's workflow did not run on the merge to the default branch");
  if (ofKind(layers.pr, 'harness').length === 0 && !(main.missing ?? []).some((m) => m.workflow === HARNESS_PATH)) sheet.fail('pipeline', 'the proof harness did not run on the pull request');

  // refused scanner mounts (E5-R1) and the jobs they explain
  const refused = new Map<string, Hit[]>();
  for (const rs of [prP, mergeP, pushP]) for (const [needId, hits] of refusedIn(rs)) refused.set(needId, [...(refused.get(needId) ?? []), ...hits]);
  for (const [needId, hits] of refused) refusedNote(needId, hits);
  const refusedJobs = new Set([...refused.values()].flat().map((h) => h.job));
  // jobs whose failure is reported elsewhere: a refused scanner (E5-R1), or an owned job that really failed in some layer (its part then
  // fails or is not-proven for it, because ownedState says failed and the part runs classify on it)
  // An owned job explains a block only when its part FAILS for it: a failure the evaluator can only call not-proven (an external host, a
  // missing secret in its log) is ambiguous, so it never explains a gate block on the main PR (C1).
  const failedOwned = [...ownedJobs].filter(([id, owner]) => {
    const o = ownedState(layers, prP, id);
    return o.state === 'failed' && judge.classify(floorOf(owner), failing(o.hits), id).status === 'failed';
  }).map(([id]) => id);
  const explainedIds = new Set<string>([...failedOwned, ...[...scannerJobs].filter(([, n]) => refused.has(n)).map(([j]) => j)]);
  const isExplained = (jobId: string): boolean => explainedIds.has(jobId);

  // every pipegen job in every layer: green, except the jobs other parts own and the refused ones
  const gateName = (n: string): boolean => jobNameMatches(n, 'gate');
  for (const [label, rs] of [['push', pushP], ['pull request', prP], ['merge', mergeP]] as const) {
    for (const run of rs) {
      let anyFailed = false;
      for (const j of latest(run.jobs)) {
        if (ok(j) || jobSkipped(j) || gateName(j.name) || refusedJobs.has(j)) continue;
        if ([...ownedJobs.keys()].some((id) => jobNameMatches(j.name, id))) continue;
        anyFailed = true;
        const need = [...scannerJobs].find(([id]) => jobNameMatches(j.name, id));
        sheet.fail('pipeline', `${label}: ${describeJob({ job: j, run })} in ${st(run.handle.workflow.replace('.github/workflows/', ''), 60)}`, need?.[1], run.handle.url);
        sheet.evidenceOf(need === undefined ? 'pipeline' : `pipeline:${need[1]}`, [{ job: j, run }]);
      }
      if (!anyFailed && run.conclusion !== 'success' && !latest(run.jobs).some((j) => !ok(j) && !jobSkipped(j))) {
        sheet.fail('pipeline', `${label}: the run of ${st(run.handle.workflow.replace('.github/workflows/', ''), 60)} ended ${st(run.conclusion, 30)}${run.note === undefined ? '' : ` (${st(run.note, 300)})`}`, undefined, run.handle.url);
      }
    }
  }

  // the jobs of the gate list must exist on the PR (those other parts own are theirs to report)
  for (const e of jobList) {
    if (e.range === true || isExplained(e.job)) continue;
    if (hitsIn(prP, (n) => jobNameMatches(n, e.job)).length === 0) sheet.fail('pipeline', `the job ${st(e.job, 80)} did not run on the pull request`, e.needId);
  }

  // the gate: the job decides, result.json reports
  const gateHits = hitsIn(prP, gateName);
  const gateRun = gateHits[0]?.run;
  let doc: GateResultDoc | null = null;
  if (gateHits.length === 0 || gateRun === undefined) {
    if (prP.length > 0) sheet.fail('pipeline', 'the gate job did not run on the pull request');
    return null;
  }
  const read = gateResultOf(gateRun);
  if (read.ok) doc = read.doc;
  const gateState = stateOf(gateHits);
  if (gateState !== 'success') sheet.gateMainFailed = true;
  if (gateState === 'success') {
    if (!read.ok) sheet.fail('pipeline', `the gate passed but its result.json is not usable: ${read.reason}`, undefined, gateRun.handle.url);
    else if (!read.doc.pass || read.doc.blocking.length > 0) sheet.fail('pipeline', 'the gate job passed but its report says it blocked (or lists blocking findings): the two disagree, so neither is trusted', undefined, gateRun.handle.url);
  } else if (gateState === 'failed') {
    // the gate blocked the main PR. Fine only when every reason is a job that is explained elsewhere (another part owns it, or its mount was refused)
    const d = read.ok ? read.doc : null;
    const explained = d !== null && blockExplained(d, jobList, explainedIds);
    if (!explained || d === null) {
      const why = d === null ? read.ok ? '' : ` (${(read as { reason: string }).reason})` : d.blocking.length > 0 ? `: ${d.blocking.slice(0, 5).map((f) => `${st(f.tool, 40)} ${st(f.ruleId, 60)}${f.file === undefined ? '' : ` in ${st(f.file, 80)}`}`).join(', ')}` : d.blockReasons.length > 0 ? `: ${d.blockReasons.slice(0, 3).map((r) => st(r, 160)).join(' | ')}` : '';
      sheet.fail('pipeline', `the gate blocked the pull request${why}`, undefined, gateRun.handle.url);
      sheet.evidenceOf('pipeline', failing(gateHits));
    } else sheet.notProven('pipeline', `the gate blocked the main pull request because of ${[...new Set([...d.failedJobs.map((f) => f.job), ...d.toolErrors.filter((t) => t.blocks).map((t) => t.job)])].map((j) => st(j, 60)).join(', ')} (reported by their own parts), so the gate is not shown to pass`, { caps: true, url: gateRun.handle.url });
  } else sheet.fail('pipeline', 'the gate job did not run to a result on the pull request', undefined, gateRun.handle.url);

  // each blocking need: its result artifact and its check in the report
  if (doc !== null || !read.ok) {
    for (const e of jobList) {
      if (!e.blocking || e.range === true || isExplained(e.job)) continue;
      if (e.tool !== undefined && /^zap/.test(e.tool)) continue;
      if (e.artifact !== undefined) {
        // the artifact must come from the run of the job that produced it, a pipegen workflow run (never a compat copy's)
        const producers = hitsIn(prP, (n) => jobNameMatches(n, e.job)).map((h) => h.run);
        const has = producers.some((r) => r.artifacts.has(e.artifact as string));
        const problem = producers.map((r) => r.artifactProblems.get(e.artifact as string)).find((p) => p !== undefined);
        if (!has) sheet.fail('pipeline', problem !== undefined ? `report unreadable: the result of ${st(e.needId, 60)} (${st(e.artifact, 100)}): ${st(problem, 200)}` : `the result of ${st(e.needId, 60)} (${st(e.artifact, 100)}) is missing`, e.needId);
      }
      if (doc !== null) {
        if (!doc.checks.some((c) => c.needId === e.needId && c.job === e.job)) sheet.fail('pipeline', `the gate has no result for ${st(e.needId, 60)} (${st(e.job, 80)})`, e.needId);
        for (const t of doc.toolErrors) if (t.needId === e.needId && t.job === e.job && t.blocks) sheet.fail('pipeline', `${st(t.tool ?? e.tool ?? e.needId, 60)}'s output for ${st(e.needId, 60)} could not be used: ${st(t.reason, 200)}`, e.needId);
        for (const f of [...doc.failedJobs, ...doc.notRun]) if (f.needId === e.needId && f.job === e.job) sheet.fail('pipeline', `the gate reports ${st(e.needId, 60)} (${st(e.job, 80)}) as failed or not run`, e.needId);
      }
    }
  }

  compat(main, layers, ctx, sheet);
  for (const n of ctx.notCompared) sheet.note('pipeline', `not compared: ${st(n.workflow, 100)}/${st(n.job, 80)} (${st(n.why, 200)})`);
  zapAndNuclei(draft, sheet, jobList);
  return doc;
}

function zapAndNuclei(draft: PipelineDraft, sheet: Sheet, jobList: readonly JobListEntry[]): void {
  for (const e of jobList) {
    if (e.tool !== undefined && /^zap/.test(e.tool)) sheet.notProven('pipeline', `${st(e.needId, 60)}: DAST on ZAP is not proven (warn only) until a real ZAP -J fixture exists`, { needId: e.needId });
  }
  void draft;
}

// ---------- compat copies ----------

/** m4: a pipegen or harness run whose jobs or artifact list could not be read is unreadable, never green. */
function unreadableRuns(layers: Layers, sheet: Sheet): void {
  const all = [...layers.push, ...layers.pr, ...layers.merge];
  for (const run of ofKind(all, 'pipegen').concat(ofKind(all, 'harness'))) {
    for (const key of ['(jobs)', '(listing)']) {
      const why = run.artifactProblems.get(key);
      if (why !== undefined) sheet.fail('pipeline', `report unreadable: ${key === '(jobs)' ? 'the jobs' : 'the artifact list'} of the run of ${st(run.handle.workflow.replace('.github/workflows/', ''), 60)} (${run.handle.event}): ${st(why, 200)}`, undefined, run.handle.url);
    }
  }
}

/** A compat copy is the user's own workflow: it never legitimately holds a pipegen result. Its artifacts are never a source of proof, and holding one is a failure. */
function compatSpoof(layers: Layers, sheet: Sheet): void {
  for (const run of [...ofKind([...layers.push, ...layers.pr, ...layers.merge], 'compat'), ...ofKind([...layers.push, ...layers.pr, ...layers.merge], 'other')]) {
    const spoof = [...run.artifacts.keys(), ...run.artifactProblems.keys()].filter((n) => n === GATE_RESULT_ARTIFACT || n.startsWith('pipegen-out-'));
    if (spoof.length > 0) sheet.fail('pipeline', `the ${kindOf(run.handle.workflow) === 'compat' ? 'compat copy' : 'untrusted workflow'} ${st(run.handle.workflow.replace(COMPAT_PREFIX, '.github/workflows/'), 100)} carries a pipegen result artifact (${spoof.slice(0, 3).map((n) => st(n, 80)).join(', ')}); it is ignored as a source of proof`, undefined, run.handle.url);
  }
}


function compat(main: VariantRuns, layers: Layers, ctx: EvalContext, sheet: Sheet): void {
  compatSpoof(layers, sheet);
  for (const run of ofKind(layers.pr, 'compat')) {
    const user = run.handle.workflow.replace(COMPAT_PREFIX, '.github/workflows/');
    const jobs = latest(run.jobs);
    const bad = jobs.filter((j) => !ok(j) && !jobSkipped(j));
    const failedRun = bad.length > 0 || run.conclusion !== 'success';
    if (!failedRun) continue;
    const hits = bad.map((job) => ({ job, run }));
    const log = cleanLog(bad.map((j) => (typeof j.log === 'string' ? j.log : '')).join('\n'));
    const before = ctx.userMain.get(user) ?? 'none';
    const name = st(user, 120);
    if (EMPTY_SECRET_RE.test(log)) { sheet.note('pipeline', `compat: ${name} failed in the scratch repo because a secret is empty there; ignored (not pipegen's change)`); continue; }
    if (before === 'success') { sheet.fail('pipeline', `pipegen broke ${name}: its copy failed in the scratch repo (${hits.map(describeJob).join(', ') || st(run.conclusion, 30)}) and it passes on your main`, undefined, run.handle.url); sheet.evidenceOf('pipeline', hits); }
    else if (before === 'failure') sheet.note('pipeline', `compat: ${name} failed in the scratch repo and failed on your main too, so it is not pipegen's fault`);
    else sheet.notProven('pipeline', `compat: ${name} failed in the scratch repo and there is no run of it on your main to compare with, so pipegen can't tell whether it broke it`, { url: run.handle.url });
  }
  void main;
}

// ---------- the planted variant ----------

const normFile = (s: string): string => s.replace(/[^\x20-\x7e]/g, '');
function plantedChecks(
  draft: PipelineDraft, planted: VariantRuns, layers: Layers, ctx: EvalContext, sheet: Sheet, jobList: readonly JobListEntry[],
  scannerJobs: ReadonlyMap<string, string>, refusedIn: RefusedIn, refusedNote: (needId: string, hits: readonly Hit[]) => void,
): void {
  const prP = ofKind(layers.pr, 'pipegen');
  if (planted.stopped === true || layers.pr.some((o) => o.stopped === true)) { sheet.fail('pipeline', 'the proof was stopped before the planted pull request finished, so the scanners are not shown to catch anything'); return; }
  if (prP.length === 0) { sheet.fail('pipeline', "pipegen's workflow did not run on the planted pull request, so the gate is not shown to block planted problems"); return; }
  compatSpoof(layers, sheet);
  unreadableRuns(layers, sheet);
  const refused = refusedIn(prP);
  for (const [needId, hits] of refused) refusedNote(needId, hits);
  const gateHits = hitsIn(prP, (n) => jobNameMatches(n, 'gate'));
  const gateRun = gateHits[0]?.run;
  if (gateRun === undefined) { sheet.fail('pipeline', "the gate job did not run on the planted pull request, so the gate is not shown to block planted problems"); return; }
  // a block is the gate job's conclusion `failure` and nothing else: cancelled, timed out or unfinished is not "blocked"
  const gs = stateOf(gateHits);
  const read = gateResultOf(gateRun);
  if (gs === 'success') sheet.fail('pipeline', "the gate didn't block planted problems: it passed on the planted pull request", undefined, gateRun.handle.url);
  else if (gs !== 'failed' || gateHits.some((h) => h.job.conclusion !== 'failure')) { sheet.fail('pipeline', 'the gate job did not finish on the planted pull request, so it is not shown to block planted problems', undefined, gateRun.handle.url); return; }
  if (!read.ok) { sheet.fail('pipeline', `the planted pull request's gate report is not usable, so no scanner is shown to catch its planted item: ${read.reason}`, undefined, gateRun.handle.url); return; }
  const doc = read.doc;
  if (doc.pass) { sheet.fail('pipeline', "the gate didn't block planted problems: its report says it passed", undefined, gateRun.handle.url); return; }

  const refusedNeeds = new Set(refused.keys());
  const scanners = jobList.filter((e) => e.blocking && e.range !== true && e.format === 'sarif' && e.tool !== undefined && FINDINGS_CATEGORIES.has(e.category) && !/^zap/.test(e.tool) && [...scannerJobs.values()].includes(e.needId));
  const toolsByCategory = new Map<string, string>();
  const needOfCategory = new Map<string, string>();
  for (const e of scanners) { if (!toolsByCategory.has(e.category)) toolsByCategory.set(e.category, e.tool as string); if (!needOfCategory.has(e.category)) needOfCategory.set(e.category, e.needId); }
  const blocking = doc.blocking;
  const items = ctx.plantedItems ?? [];

  // the floor scanners come from the draft's floor needs, not only from the filtered job list: one with no result to read is failed
  for (const n of draft.needs) {
    const cat = categoryOf(n.id, n.category);
    if ((FLOOR.has(n.id) || FLOOR.has(cat)) && FINDINGS_CATEGORIES.has(cat) && !toolsByCategory.has(cat) && !refusedNeeds.has(n.id)) {
      sheet.fail('pipeline', `${st(n.id, 60)}: no scanner result for it is read from the planted run, so it is not shown to catch anything`, n.id, gateRun.handle.url);
    }
  }
  // secrets: every C1b placement, by file; at least one placement must be expected (an empty list proves nothing)
  const secretsTool = toolsByCategory.get('secrets');
  if (secretsTool !== undefined && !refusedNeeds.has('secrets')) {
    if (!ctx.planted.some((p) => p.kind === 'secret')) sheet.fail('pipeline', `${st(secretsTool, 60)}: no planted secret was expected, so secrets is not shown to catch anything`, 'secrets', gateRun.handle.url);
    const secretFindings = blocking.filter((f) => f.needId === 'secrets' || f.secret);
    for (const p of ctx.planted) {
      if (p.kind !== 'secret') continue;
      const seen = secretFindings.some((f) => f.file !== undefined && (p.nonUtf8 === true ? normFile(f.file) === normFile(p.path) : f.file === p.path));
      if (!seen) sheet.fail('pipeline', `${st(secretsTool, 60)} didn't catch the planted secret in ${st(p.path, 120)}`, 'secrets', gateRun.handle.url);
    }
    const ig = ctx.planted.find((p) => p.kind === 'integrity-warning');
    if (ig !== undefined) {
      const w = doc.warnings.some((f) => f.file === ig.path) || blocking.some((f) => f.file === ig.path) || doc.warnReasons.some((r) => r.includes(ig.path));
      sheet.note('pipeline', w ? `the planted ${st(ig.path, 60)} was reported as an integrity warning, as intended` : `the planted ${st(ig.path, 60)} was not reported as an integrity warning (a note only: the blocking check is the secrets)`);
    }
  }

  // Plan F's items, by category
  const wanted = items.filter((i) => toolsByCategory.has(i.category) && !refusedNeeds.has(needOfCategory.get(i.category) as string));
  if (wanted.length > 0) {
    if (ctx.matchPlanted === undefined) sheet.fail('pipeline', 'planted items were given but no matcher, so no scanner is shown to catch its item');
    else {
      const m = ctx.matchPlanted(asFindings(blocking), wanted.map((w) => ({ ...w })), new Map(toolsByCategory));
      const missed = new Set(Array.isArray(m?.missed) ? m.missed : []);
      const caught = new Set(Array.isArray(m?.caught) ? m.caught : []);
      for (const w of wanted) {
        // an item neither caught nor missed is not shown to have been caught
        if (missed.has(w.id) || !caught.has(w.id)) sheet.fail('pipeline', `${st(toolsByCategory.get(w.category) as string, 60)} didn't catch the planted ${st(w.item, 120)}`, needOfCategory.get(w.category), gateRun.handle.url);
      }
    }
  }
  // blocking scanners with no planted item at all: not shown to catch anything (a floor need is failed, never not-proven)
  for (const [category, tool] of toolsByCategory) {
    const needId = needOfCategory.get(category) as string;
    if (category === 'secrets' || refusedNeeds.has(needId) || tool === 'nuclei') continue;
    if (items.some((i) => i.category === category)) continue;
    const floor = FLOOR.has(needId) || FLOOR.has(category);
    const text = `${st(tool, 60)}: no planted item for ${st(needId, 60)}, so it is not shown to catch anything`;
    if (floor) sheet.fail('pipeline', text, needId);
    else sheet.notProven('pipeline', text, { needId });
  }
  // dast with nuclei: deferred (S23)
  for (const e of jobList) if (e.tool === 'nuclei' && !items.some((i) => i.category === e.category)) {
    sheet.notProven('pipeline', `${st(e.needId, 60)}: nuclei has no planted item yet (deferred), so it is not shown to catch anything: no planted item`, { needId: e.needId });
  }
  void draft;
}

// ---------- tests and coverage ----------

async function readReport(ctx: EvalContext, bytes: Uint8Array): Promise<JunitRead> {
  try {
    const r = await (ctx.readJunit ?? ((b: Uint8Array) => readJunitBytes(b)))(bytes);
    if (!isRec(r) || typeof r.ok !== 'boolean') return { ok: false, reason: 'report unreadable: the reader gave no answer' };
    if (r.ok === true && Array.isArray((r as { cases?: unknown }).cases)) return r as JunitRead;
    return { ok: false, reason: typeof (r as { reason?: unknown }).reason === 'string' ? `${(r as { reason: string }).reason.startsWith('report unreadable') ? '' : 'report unreadable: '}${st((r as { reason: string }).reason, 300)}` : 'report unreadable: the reader refused it' };
  } catch (e) {
    return { ok: false, reason: `report unreadable: ${st(e instanceof Error ? e.message : 'the reader failed', 200)}` };
  }
}

export const junitArtifactNames = (service: string): { first: string; repeat: string } => ({ first: `pipegen-out-junit-${slug(service)}`, repeat: `pipegen-out-junit-repeat-${slug(service)}` });

async function testsPart(
  draft: PipelineDraft, main: VariantRuns | undefined, layers: Layers, ctx: EvalContext, sheet: Sheet, judge: Judge, skipped: ReadonlyMap<string, string>,
  harnessPr: readonly RunOutcome[], harnessId: (id: HarnessJobId) => (name: string) => boolean, rendered: (id: HarnessJobId) => boolean,
): Promise<{ measured: number | null; lowest: number | null; decision: CoverageDecision | null }> {
  const none = { measured: null, lowest: null, decision: null };
  const floorTests = needsTests(draft);
  if (skipped.has('tests')) { sheet.notProven('tests', `skipped by you (--skip): ${st(skipped.get('tests'), 200)}`, { caps: true }); return none; }
  if (main === undefined) { sheet.fail('tests', 'the main variant was not proven, so the tests are not proven'); return none; }
  const prP = ofKind(layers.pr, 'pipegen');
  const needs = draft.needs.filter((n) => TESTS_CATEGORIES.has(categoryOf(n.id, n.category)));
  const created = ctx.createdTests ?? [];
  if (needs.length === 0 && created.length === 0) sheet.notProven('tests', 'there are no tests to prove: the draft has no test check and no created tests', { caps: true });
  // existing suites: by job result (JUnit is read only for created tests, S8)
  for (const n of needs) {
    const id = inFolderNeed(n);
    const { state: s, hits } = ownedState(layers, prP, id);
    if (s === 'failed') {
      const f = judge.classify(floorTests, failing(hits), `test job`);
      if (f.status === 'failed') sheet.fail('tests', f.detail, n.id, hits[0]?.run.handle.url); else sheet.notProven('tests', f.detail, { needId: n.id, caps: true });
      sheet.evidenceOf('tests', failing(hits));
    } else if (s !== 'success') sheet.fail('tests', `the test job ${st(id, 80)} did not run on the pull request (${s === 'skipped' ? 'skipped' : 'missing'}), so the tests are not proven`, n.id);
  }
  // created tests: the JUnit of both runs
  const findArtifact = (name: string, runs: readonly RunOutcome[]): { file?: Uint8Array; problem?: string } => {
    for (const r of runs) { const p = r.artifactProblems.get(name); if (p !== undefined) return { problem: p }; }
    for (const r of runs) { const f = r.artifacts.get(name); if (f !== undefined) return { file: f.bytes }; }
    return {};
  };
  // the first run's JUnit only from pipegen's own PR runs; the repeat's only from the harness run that holds the tests-repeat job
  const firstRuns = prP;
  const repeatRuns = hitsIn(harnessPr, harnessId('tests-repeat')).map((h) => h.run);
  for (const c of created) {
    const names = junitArtifactNames(c.service);
    const svc = st(c.service, 60);
    const get = async (artifact: string, label: string, from: readonly RunOutcome[]): Promise<TestCaseResult[] | null> => {
      const a = findArtifact(artifact, from);
      if (a.file === undefined) { sheet.fail('tests', a.problem !== undefined ? `report unreadable: the ${label} JUnit of ${svc}: ${st(a.problem, 200)}` : `the ${label} JUnit report of ${svc} (${st(artifact, 100)}) was not uploaded, so its tests are not proven`, 'created-tests'); return null; }
      const r = await readReport(ctx, a.file);
      if (!r.ok) { sheet.fail('tests', `${label} JUnit of ${svc}: ${r.reason}`, 'created-tests'); return null; }
      return r.cases;
    };
    const first = await get(names.first, 'first-run', firstRuns);
    if (first !== null) {
      const skippedN = first.filter((x) => x.status === 'skip').length;
      const failedN = first.filter((x) => x.status === 'fail').length;
      if (first.length === 0) sheet.fail('tests', `the JUnit report of ${svc} has no test, so nothing is proven`, 'created-tests');
      else if (skippedN > 0) sheet.fail('tests', `${skippedN} of the created tests of ${svc} were skipped: a test that skips itself proves nothing`, 'created-tests');
      else if (first.length !== c.staticCount) sheet.fail('tests', `the created tests of ${svc} executed ${first.length} test${first.length === 1 ? '' : 's'}, but the validator counted ${c.staticCount}`, 'created-tests');
      else if (failedN > 0) sheet.fail('tests', `${failedN} of the created tests of ${svc} failed: ${first.filter((x) => x.status === 'fail').slice(0, 5).map((x) => st(x.id, 120)).join(', ')}`, 'created-tests');
    }
    if (rendered('tests-repeat')) {
      const hits = hitsIn(harnessPr, harnessId('tests-repeat'));
      const s = stateOf(hits);
      if (s === 'failed') { sheet.fail('tests', `the repeat run of the created tests failed: ${failing(hits).map(describeJob).join(', ')}`, 'created-tests', hits[0]?.run.handle.url); sheet.evidenceOf('tests', failing(hits)); }
      else if (s !== 'success') sheet.fail('tests', 'the repeat run of the created tests did not run, so flaky tests are not ruled out', 'created-tests');
    }
    const repeat = await get(names.repeat, 'repeat', repeatRuns);
    if (first !== null && repeat !== null) {
      const same = sameResults(first, repeat);
      if (!same.ok) {
        const flaky = same.flaky.length > 0 ? `flaky: ${same.flaky.map((f) => st(f, 120)).join(', ')}` : same.reason !== undefined ? st(same.reason, 200) : 'the two runs differ';
        sheet.fail('tests', `the created tests of ${svc} did not give the same result twice (${flaky})`, 'created-tests');
      }
    }
  }

  // coverage (S11): the green coverage job's log. A hostile log may only make things STRICTER: every "All files" row is read;
  // the HIGHEST per job chooses the minimum (a fake low row can't lower it or switch the check off; a fake high one only raises it)
  // and the LOWEST decides whether this proof's check passes (a fake low row can only make it fail).
  const covNeeds = draft.needs.filter((n) => categoryOf(n.id, n.category) === 'coverage');
  let measured: number | null = null;
  let lowest: number | null = null;
  let unreadable = false;
  for (const n of covNeeds) {
    const id = inFolderNeed(n);
    const { state: s, hits: allHits } = ownedState(layers, prP, id);
    const hits = hitsIn(prP, (name) => jobNameMatches(name, id));
    if (s === 'failed') {
      // the tests part covers floor needs: a failed coverage job is failed, whatever its log says (C1)
      const f = judge.classify(floorTests, failing(allHits), `coverage job`);
      if (f.status === 'failed') sheet.fail('tests', f.detail, n.id, allHits[0]?.run.handle.url); else sheet.notProven('tests', f.detail, { needId: n.id, caps: true });
      sheet.evidenceOf('tests', failing(allHits));
      unreadable = true;
      continue;
    }
    if (s !== 'success') { sheet.fail('tests', `the coverage job ${st(id, 80)} did not run on the pull request, so no coverage was measured`, n.id); unreadable = true; continue; }
    const legs = hits.filter((h) => ok(h.job)).map((h) => coverageRows(typeof h.job.log === 'string' ? h.job.log : ''));
    if (legs.length === 0 || legs.some((r) => r.length === 0)) {
      sheet.notProven('tests', `coverage ${st(id, 80)}: the measured lines could not be read from the job log, so the coverage check is not proven`, { needId: n.id });
      unreadable = true;
      continue;
    }
    const high = Math.min(...legs.map((r) => Math.max(...r)));
    const low = Math.min(...legs.map((r) => Math.min(...r)));
    measured = measured === null ? high : Math.min(measured, high);
    lowest = lowest === null ? low : Math.min(lowest, low);
    const own = coverageNotes(high, ctx.existingMinimum ?? null);
    const rows = [...new Set(legs.flat())].sort((x, y) => x - y);
    const conflict = legs.some((r) => new Set(r).size > 1);
    const strict = own.choice !== null && low < Number(own.choice);
    const text = `coverage ${st(id, 80)}: ${high}% of lines measured${own.notes.length > 0 ? `; ${own.notes.map((x) => st(x, 200)).join('; ')}` : ''}`;
    if (strict) sheet.fail('tests', `${text}; ${conflict ? `several 'All files' rows (${rows.map((r) => `${r}%`).join(', ')}): the highest sets the minimum (${own.choice}%) and the lowest (${low}%) decides, so the check fails` : `the lowest leg (${low}%) is under the minimum ${own.choice}%`}`, n.id);
    else sheet.proven('tests', n.id, conflict ? `${text}; several 'All files' rows (${rows.map((r) => `${r}%`).join(', ')}): the highest sets the minimum and the lowest decides` : text);
  }
  if (covNeeds.length === 0 || measured === null || unreadable) return { measured: unreadable ? null : measured, lowest: unreadable ? null : lowest, decision: null };
  return { measured, lowest, decision: coverageNotes(measured, ctx.existingMinimum ?? null) };
}

/** Every "All files" percentage-of-lines row of a log (timestamps, ANSI and CR progress stripped, the tail kept), invalid rows ignored. */
export function coverageRows(log: string): number[] {
  const out: number[] = [];
  for (const raw of String(log).slice(-MAX_LOG_READ).split('\n')) {
    let line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    const cr = line.lastIndexOf('\r');
    if (cr >= 0) line = line.slice(cr + 1);
    if (line.startsWith('\ufeff')) line = line.slice(1);
    line = line.replace(TIMESTAMP, '').replace(ANSI, '');
    if (!/^\s*All files\s*\|/.test(line)) continue;
    const v = measuredLines(line);
    if (v !== null) out.push(v);
    if (out.length >= 10_000) break;
  }
  return out;
}

// ---------- assemble the parts ----------

const PART_ORDER: readonly Part[] = ['pipeline', 'tests', 'docker', 'compose', 'precommit', 'deploy-verify'];
function assemble(sheet: Sheet, draft: PipelineDraft, ctx: EvalContext, _o: { main: boolean; floorOf: (p: Part) => boolean }): PartResult[] {
  const parts: PartResult[] = [];
  const emitted = new Set<Part>();
  const urlOf = (vs: readonly Verdict[]): { logsUrl: string } | Record<string, never> => { const u = vs.find((v) => v.url !== undefined)?.url; return u === undefined ? {} : { logsUrl: u }; };
  const partsWithVerdicts = new Set(sheet.verdicts.map((v) => v.part));
  const proof = (p: Part): boolean => PART_ORDER.includes(p) || partsWithVerdicts.has(p);
  for (const part of [...PART_ORDER, ...[...partsWithVerdicts].filter((p) => !PART_ORDER.includes(p))]) {
    const vs = sheet.verdicts.filter((v) => v.part === part);
    const overallFailed = vs.filter((v) => v.status === 'failed');
    const capping = vs.filter((v) => v.status === 'not-proven' && v.caps);
    const notes = sheet.notes.get(part) ?? [];
    const applicable = part === 'pipeline' || part === 'tests' || part === 'deploy-verify' || partsWithVerdicts.has(part) || hasPositive(part, draft, ctx);
    if (!applicable || !proof(part)) continue;
    emitted.add(part);
    if (overallFailed.length > 0) parts.push({ part, status: 'failed', detail: joined(overallFailed.map((v) => v.detail)), ...urlOf(overallFailed) });
    else if (capping.length > 0) parts.push({ part, status: 'not-proven', detail: joined(capping.map((v) => v.detail)), ...urlOf(capping) });
    else {
      const np = [...new Set(vs.filter((v) => v.status === 'not-proven' && v.needId !== undefined).map((v) => st(v.needId, 60)))];
      parts.push({ part, status: 'proven', detail: joined([POSITIVE[part] as string, ...notes, ...(np.length > 0 ? [`not proven: ${np.join(', ')}`] : [])]) });
    }
    // details: every verdict with a need, and the not-proven notes that do not cap the part (the part's verdict is its FIRST entry)
    for (const v of vs) {
      if (v.needId === undefined && v.status !== 'not-proven') continue;
      if (v.needId === undefined && v.caps) continue;
      parts.push({ part: v.part, ...(v.needId === undefined ? {} : { needId: v.needId }), status: v.status, detail: v.detail, ...urlOf([v]) });
    }
  }
  return parts;
}
const POSITIVE: Readonly<Record<string, string>> = {
  pipeline: 'pipegen\'s jobs finished green on the pull request and the merge, the gate passed on the main pull request and blocked the planted one, and the scanners with a planted item caught it',
  tests: 'the tests passed', docker: 'the image build and the app start passed', compose: 'the app started', precommit: 'the hooks passed', 'deploy-verify': 'the gated run was found on the merge to the default branch',
};
/** A part with nothing wrong and nothing to prove is left out, except the ones every proof has. */
function hasPositive(part: Part, draft: PipelineDraft, ctx: EvalContext): boolean {
  const cat = (n: { id: string; category: string }): string => categoryOf(n.id, n.category);
  switch (part) {
    case 'docker': return draft.needs.some((n) => cat(n) === 'image-build') || draft.created.some((f) => f.part === 'docker');
    case 'compose': return draft.created.some((f) => f.part === 'compose') || ctx.harnessJobs.includes('app-start');
    case 'precommit': return draft.needs.some((n) => ['hooks', 'hooks-ci'].includes(cat(n)));
    default: return false;
  }
}

// ---------- the user's main (Task 4: userMainStatuses) ----------

/**
 * The last completed default-branch run of each of the user's own workflows (compat copies compare against it). One list call;
 * a workflow with no completed run in the list, a cancelled or skipped last run, or anything unreadable is 'none': an
 * unknown baseline is never taken for a pass. Only success is 'success'; failure, timed_out and startup_failure are 'failure'.
 */
export async function userMainStatuses(gh: Octokit, p: RepoProfile): Promise<Map<string, 'success' | 'failure' | 'none'>> {
  const out = new Map<string, 'success' | 'failure' | 'none'>();
  const paths = p.existingWorkflows.map((w) => w.path).filter((x) => typeof x === 'string' && /^\.github\/workflows\/[^/]+\.ya?ml$/.test(x));
  for (const w of paths) out.set(w, 'none');
  if (paths.length === 0) return out;
  let data: unknown;
  try {
    data = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs', { owner: p.owner, repo: p.repo, branch: p.defaultBranch, status: 'completed', per_page: 100 }, clockOf(gh))).data;
  } catch (e) {
    if (isRateStop(e)) throw e;
    return out;
  }
  if (!isRec(data) || !Array.isArray(data.workflow_runs)) return out;
  const done = new Set<string>();
  const runs = (data.workflow_runs as unknown[]).filter(isRec).sort((a, b) => Date.parse(String(b.created_at ?? '')) - Date.parse(String(a.created_at ?? '')));
  for (const r of runs) {
    if (typeof r.path !== 'string' || r.head_branch !== p.defaultBranch) continue;
    const path = r.path.split('@')[0] as string;
    if (!out.has(path) || done.has(path)) continue;
    done.add(path);
    out.set(path, r.conclusion === 'success' ? 'success' : r.conclusion === 'failure' || r.conclusion === 'timed_out' || r.conclusion === 'startup_failure' ? 'failure' : 'none');
  }
  return out;
}
