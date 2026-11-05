// v0.2 Plan G Task 2, file half (sub-task G5; rulings B2, B5, S16, S25, S28 a / G-P1; carries G1-R1/R1b, G3, G4, C8r1, D4-r1, E-b8/E-b9, G41, P-6):
// the jobs G4 assembles, laid out into the files pipegen delivers. Nothing here renders a step: every job is G4's (jobs.ts) or G3's
// (central.ts), and every form is the one job-rules.ts shares with the referee.
//
// The layout (ruling B2), one trigger set per file (G1-R2 I1, rendered in full: G1-R3):
// - app `.github/workflows/pipegen.yml`: push [<default>] (exactly, C3), pull_request (bare), pull_request_review [submitted, dismissed]; the
//   caller job `pipegen` (name `pipegen`) of the merge workflow, whose job `gate` (name `gate`) makes the required check GATE_CHECK_NAME; the
//   deploy jobs (G7's, `if: DEPLOY_PUSH_IF`, needing `pipegen`), and the sign job (keyless inline) or the caller of the central sign workflow;
// - app `pipegen-push.yml`: push to every branch but the default; `pr-check` and the push-layer checks, each `if: PR_CHECK_IF` (they skip when
//   the branch has an open pull request, which the merge layer covers; the file never runs on the default branch); no gate. Left out when the
//   push layer has no check;
// - app `pipegen-nightly.yml`: schedule only (NIGHTLY_CRON); the nightly job (B5: it calls no merge workflow and holds no not-proven list);
// - private repository (central layout): the three app files hold only caller jobs, each pinned to the recorded central commit
//   (`<owner>/pipelines/.github/workflows/<name>--{merge,push,nightly}.yml@<sha>`, centralWorkflowFile, one name derivation, S16); the merge
//   caller's `uses` is centralWorkflowPath's (C8r1). A private draft without a valid central pin is refused;
// - public repository (local layout, G2/G43): pipegen.yml calls `./.github/workflows/pipegen-merge.yml`; the push and nightly jobs are inline
//   in their own files (a local push or nightly callee would be the file itself; G1: the push file is accepted inline only). No central file.
//   A public draft with a central pin is refused (find-run would look for a central workflow that does not exist).
// The workflow concurrency (G1-R1/R1b) is at the top of pipegen.yml and pipegen-push.yml only; no workflow_dispatch, no input anywhere.
//
// Callers (plan "Caller permissions", "Secrets"): top-level `permissions: {}` in every file; each caller job grants exactly the union of the
// called workflow's job permissions (callerPermissions, held to the referee's permission table), and passes exactly the secrets the called
// jobs read, each by its own name (callerSecrets; never `secrets: inherit`, never GITHUB_TOKEN, which GitHub gives every called workflow);
// the called workflow declares the same names under workflow_call. The central sign workflow takes nothing (G3, S21).
//
// The not-proven list (G-S2, B2, B5): the gate step's `not-proven` literal, on one line of the merge file marked `# pipegen:not-proven`
// (central `<name>--merge.yml` private, `pipegen-merge.yml` public; both protected paths). No caller input, no copy in any other file.
//
// Also: the pipegen-verify job (verifyJob: the gate action's find-run mode, waiting for the gated run, in pipegen-signing; G7 places it into
// the deploy workflows and adds the digest hand-off and the signature checks), the Dependabot entry (dependabotFile, 7-day cooldown, the user's bytes untouched), and
// judgeAssembled: the one referee call over every file of the delivery (the workflows, docker-compose.pipegen.yml and the other created
// files together, D4-r1).
//
// assemble refuses (AssembleError) besides what G4 refuses: a layout that is not the repository's, a private draft without a valid central pin
// or a public one with one, a gate entry that is not the reviewed one, a deploy job with an environment or a condition of its own (G41: no
// job waits for a person in a push run), a sign job without image-publish (nothing to sign), an existing Dependabot file whose text was not
// given (never a blind overwrite), a path the draft already holds, and any file that breaks its own layout checks (checkLayout).
import { isDeepStrictEqual } from 'node:util';
import { Document, isMap, isScalar, isSeq, parse, type Scalar } from 'yaml';
import { centralWorkflowFile, centralWorkflowPath, type CentralLayer } from '../engine/central-path.js';
import { dependabotFile } from '../engine/created-builders.js';
import {
  CALLER_WORKFLOW, createdPathProblem, defaultPushTrigger, DEPLOY_PUSH_IF, featurePushTrigger, jobOutputsFor, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PR_CHECK_IF, PR_CHECK_JOB,
  PR_REVIEW_TRIGGER, PUSH_WORKFLOW, renderPrCheckStep, WORKFLOW_CONCURRENCY, type RenderedStep,
} from '../engine/job-rules.js';
import { COMMIT_SHA_RE, isGitHubRepo } from '../engine/names.js';
import type { PlatformActions } from '../engine/pin.js';
import { signingMode, type SigningMode } from '../github/signing-mode.js';
import { JOB_PERMISSIONS, referee, SIGNING_ENVIRONMENT, type Linters, type RefereeDeps, type RefereeReport } from '../engine/referee.js';
import { RenderError } from '../engine/render-error.js';
import { renderFindRunStep, stepsToYaml } from '../engine/render-step.js';
import type { BaseImage } from '../engine/base-images.js';
import { IMAGE_PUBLISH_JOB, sharedWorkflows, signCallerJob, signPermissions, SIGN_JOB_ID } from './central.js';
import { AssembleError, assembleJobs, egressStepFor, JOB_RUNNER, type Job, type JobsPlan } from './jobs.js';
import type { CreatedFile, PipelineDraft, ReviewedTool } from '../types.js';
import { safeText } from '../util/safe-text.js';

// ---------- constants ----------

/** The caller job of the merge workflow in pipegen.yml: id and name `pipegen`, so the gate job `gate` reports as GATE_CHECK_NAME. */
export const MERGE_CALLER_JOB = 'pipegen';
/** The caller jobs of the central push and nightly workflows (private): named apart from the gate's check. */
export const PUSH_CALLER_JOB = 'pipegen-push';
export const NIGHTLY_CALLER_JOB = 'pipegen-nightly';
const CALLER_NAME: Readonly<Record<'merge' | 'push' | 'nightly', string>> = Object.freeze({ merge: 'pipegen', push: 'pipegen push', nightly: 'pipegen nightly' });
/** The nightly schedule (plan "Caller triggers"). */
export const NIGHTLY_CRON = '17 3 * * *';
/** The comment that marks the not-proven line of the merge file (G-S2): `not-proven: '[...]' # pipegen:not-proven`. */
export const NOT_PROVEN_MARK = 'pipegen:not-proven';
/** The verify-first job's id (the referee's permission and step tables are keyed by it). */
export const VERIFY_JOB_ID = 'pipegen-verify';
/**
 * G5-R1 m1 (G40): the verify job's find-run waits until the gated push run of pipegen.yml is over, so it waits for that run's worst case:
 * the longest chain of job limits in pipegen.yml (the merge caller counting as its called workflow's longest chain, the sign caller as its
 * sign job, each deploy job as its own `timeout-minutes`), plus this grace for the listing and the hand-over between jobs. Queue time before a
 * job starts is not counted (live checklist).
 */
export const VERIFY_GRACE_MINUTES = 10;
/** The verify job's own limit is its wait plus this margin, so a run that finishes at the end of the wait is still read. */
export const VERIFY_MARGIN_MINUTES = 15;
/** GitHub's longest job (and the find-run wait's upper bound). */
const MAX_JOB_MINUTES = 360;
/** The keys a deploy job (G7) may carry: those pipegen writes; `if` and `environment` are refused with their own reason. */
const DEPLOY_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'runs-on', 'timeout-minutes', 'needs', 'permissions', 'cache-mode', 'outputs', 'steps', 'if', 'environment']);
/** G5-R1 m5: the signing secrets (the cosign key and its password, cosign's and Sigstore's own variables) reach only the sign job, through its environment. */
const SIGNING_SECRET_RE = /^(?:PIPEGEN_COSIGN_|COSIGN_|SIGSTORE_|TUF_)/;
/** The pr-check job's limit (one API call). */
const PR_CHECK_MINUTES = 10;
/** Where a new Dependabot file goes, and the two spellings GitHub reads. */
const DEPENDABOT_PATH = '.github/dependabot.yml';
const DEPENDABOT_PLACES: readonly string[] = ['.github/dependabot.yml', '.github/dependabot.yaml'];
/** A job id as pipegen writes one (the referee's rule). */
const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;
/** A secret name the referee accepts in a caller's mapping (SECRET_REF_RE's name). */
const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]{0,99}$/;
/** The jobs the verify job's permission row gives: read the runs, the image and its attestations. */
const VERIFY_PERMISSIONS: Readonly<Record<string, 'read'>> = Object.freeze({ contents: 'read', actions: 'read', packages: 'read', attestations: 'read' });
/** The job ids pipegen.yml reserves for its own jobs (a deploy job may not take one). */
const RESERVED_IDS: ReadonlySet<string> = new Set([MERGE_CALLER_JOB, SIGN_JOB_ID, VERIFY_JOB_ID, PUSH_CALLER_JOB, NIGHTLY_CALLER_JOB, PR_CHECK_JOB, 'gate']);

// ---------- types ----------

/** `central`: a private repository calls its central workflows; `local`: a public one keeps every workflow in the app (ruling B2). */
export type Layout = 'central' | 'local';
/**
 * What assemble needs (ruling S25, with the safer reading's additions, see the G5 report): the reviewed gate entry, the reviewed list, the
 * platform actions, the signing mode (signingMode for delivery, PROOF_SIGNING_MODE for the proof), the layout (it must be the repository's),
 * and `plan`, the debate's result G4 checks every step against (the steps come from draft.steps only). `deploy`: the deploy layer's jobs (G7:
 * image-publish, sbom), placed into pipegen.yml; `dependabot`: the existing Dependabot file's text, required when one exists.
 */
export interface AssembleOpts {
  gate: ReviewedTool; reviewed: readonly ReviewedTool[]; platform: PlatformActions; mode: SigningMode; layout: Layout; plan: JobsPlan;
  deploy?: Readonly<Record<string, Job>>; dependabot?: string; baseImages?: readonly BaseImage[];
}
/** A reusable-workflow caller job as pipegen writes it. */
export interface CallerJob { name?: string; uses: string; needs?: string[]; if?: string; permissions: Record<string, 'read' | 'write'>; secrets?: Record<string, string> }
export interface AssembledFiles {
  /** The draft as assembled (AssembledJobs.draft): the referee, the gate inputs, PIPEGEN.md and the proof read this one. */
  draft: PipelineDraft;
  /** The files to deliver: the app's workflows, the central ones (private), the Dependabot file. */
  files: CreatedFile[];
  /** The pipegen-verify job for the deploy workflows (G7 places it); null when the deploy part is skipped. */
  verify: Job | null;
  notes: string[];
}

const fail = (m: string): never => { throw new AssembleError(m); };
const show = (s: unknown): string => JSON.stringify(safeText(String(s), 60));
const own = <T>(o: Readonly<Record<string, T>>, k: string): T | undefined => (Object.hasOwn(o, k) ? o[k] : undefined);
const uniq = (xs: readonly string[]): string[] => [...new Set(xs)];
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
/** A RenderError of a shared renderer, as the AssembleError of this layout. */
function guard<T>(f: () => T): T {
  try { return f(); } catch (e) { if (e instanceof RenderError) return fail(e.message); throw e; }
}

// ---------- permissions and secrets ----------

/**
 * The permissions a caller job grants the workflow it calls: the union of the called jobs' permissions, `write` over `read` (a called job can
 * not get more than its caller job gives). Each job's own permissions must fit its row of the referee's permission table (JOB_PERMISSIONS,
 * plus `contents: read`), so the union is never more than the table allows: anything else, and any level but read or write, is refused.
 */
export function callerPermissions(calledJobs: readonly { job: string; permissions: Record<string, 'read' | 'write'> }[]): Record<string, 'read' | 'write'> {
  const out: Record<string, 'read' | 'write'> = {};
  for (const { job, permissions } of calledJobs) {
    if (!isObj(permissions)) fail(`The job ${show(job)} declares no permissions map.`);
    const row: Readonly<Record<string, string>> = { contents: 'read', ...(own(JOB_PERMISSIONS, job) ?? {}) };
    for (const [k, v] of Object.entries(permissions)) {
      if (v !== 'read' && v !== 'write') fail(`The job ${show(job)} sets ${show(k)} to ${show(v)}, which is not read or write.`);
      const cap = own(row, k);
      if (cap === undefined || (v === 'write' && cap !== 'write')) fail(`The job ${show(job)} asks for ${safeText(k, 40)}: ${v}, more than a job with this id may have (the referee's permission table).`);
      if (v === 'write' || own(out, k) === undefined) out[k] = v;
    }
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

/** Every string of a value (keys too), depth first. */
function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) { out.push(k); strings(x, out); }
  return out;
}
/** The `secrets` context word inside an expression body (not part of a longer name or a property). */
const SECRETS_WORD_RE = /(?<![\w.-])secrets(?![\w-])/g;
const SECRET_PROP_RE = /^\s*\.\s*([A-Za-z0-9_]+)(?![\w-])/;

/**
 * The secrets a caller passes to the workflow it calls: exactly the names the called jobs read (`${{ secrets.NAME }}` in any expression of
 * theirs), each as `${{ secrets.NAME }}` under its own name. GITHUB_TOKEN is not passed (GitHub gives it to every called workflow). The names
 * come from what the jobs read, so a step secret, a not-proven check's missing name (its step reads it) and PIPEGEN_FP_KEY (every scrub) are
 * all mapped, and a name no job reads never is. Any other use of the `secrets` context (an index, toJSON, a name not in upper case) is refused.
 */
export function callerSecrets(calledJobs: Readonly<Record<string, unknown>>): Record<string, string> {
  const names = new Set<string>();
  for (const s of strings(calledJobs)) {
    for (const m of s.matchAll(/\$\{\{([\s\S]*?)\}\}/g)) {
      const body = m[1] as string;
      for (const w of body.matchAll(SECRETS_WORD_RE)) {
        const prop = SECRET_PROP_RE.exec(body.slice((w.index ?? 0) + w[0].length));
        const name = prop?.[1];
        if (name === undefined || !SECRET_NAME_RE.test(name)) fail(`A called job uses the secrets context in a form pipegen does not map (${safeText(body.trim(), 60)}): only \${{ secrets.NAME }}, NAME in upper case.`);
        if (SIGNING_SECRET_RE.test(name as string)) fail(`A called job reads the signing secret ${show(name)}; it reaches only the sign job, through the ${SIGNING_ENVIRONMENT} environment, and no caller maps it.`);
        if (name !== 'GITHUB_TOKEN') names.add(name as string);
      }
    }
  }
  return Object.fromEntries([...names].sort().map((n) => [n, `\${{ secrets.${n} }}`]));
}

/**
 * The workflow_call trigger of a called workflow: the secrets its caller maps, each declared (GitHub refuses a mapped name the called workflow
 * does not declare), none an input or output. `required: false`: the caller maps every declared name anyway (checkLayout), and a not-proven
 * check's secret the user has not set yet must not stop the whole run (live checklist: an unset secret passed under a declared name).
 */
const callTrigger = (secrets: Readonly<Record<string, string>>): Obj => ({ workflow_call: Object.keys(secrets).length === 0 ? {} : { secrets: Object.fromEntries(Object.keys(secrets).map((n) => [n, { required: false }])) } });

/** The caller job of a called workflow's jobs: the union of their permissions and the secrets they read, nothing else (no `with`). */
function callerOf(name: string, uses: string, called: Readonly<Record<string, Job>>): CallerJob {
  const permissions = callerPermissions(Object.entries(called).map(([job, j]) => ({ job, permissions: j.permissions })));
  const secrets = callerSecrets(called);
  return { name, uses, permissions, ...(Object.keys(secrets).length === 0 ? {} : { secrets }) };
}

// ---------- the files ----------

/** A job with its keys in the order pipegen writes them. */
function ordered(j: Job): Job {
  const keys: (keyof Job)[] = ['name', 'runs-on', 'timeout-minutes', 'needs', 'if', 'permissions', 'environment', 'concurrency', 'cache-mode', 'outputs', 'steps'];
  // G5-R1 m2: a key pipegen does not write is refused, never dropped
  for (const k of Object.keys(j)) if (!(keys as string[]).includes(k)) fail(`A job has the key ${show(k)}, which pipegen does not write.`);
  const out: Partial<Record<keyof Job, unknown>> = {};
  for (const k of keys) if (j[k] !== undefined) out[k] = j[k];
  return out as unknown as Job;
}

interface WorkflowSpec { path: string; repo: CreatedFile['repo']; name: string; on: Obj; concurrency?: boolean; jobs: Readonly<Record<string, Job | CallerJob>>; reason: string; comment: string }

/** A workflow file: `permissions: {}`, the jobs (steps through stepsToYaml), the not-proven mark on the gate step's not-proven line. */
function workflowFile(w: WorkflowSpec): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(w.jobs).map(([id, j]) => { const { steps: _s, ...rest } = j as Job; return [id, rest]; }));
  doc.contents = doc.createNode({ name: w.name, on: w.on, permissions: {}, ...(w.concurrency === true ? { concurrency: { ...WORKFLOW_CONCURRENCY } } : {}), jobs: plain });
  for (const [id, j] of Object.entries(w.jobs)) if (Array.isArray((j as Job).steps)) doc.setIn(['jobs', id, 'steps'], stepsToYaml((j as Job).steps));
  markNotProven(doc);
  doc.commentBefore = ` ${w.comment}`;
  return { path: w.path, content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: w.reason, repo: w.repo };
}

/** The gate step's `not-proven` value gets the trailing `# pipegen:not-proven` comment (the job gate, the step in mode gate). */
function markNotProven(doc: Document): void {
  const steps = doc.getIn(['jobs', 'gate', 'steps'], true);
  if (!isSeq(steps)) return;
  for (const step of steps.items) {
    if (!isMap(step)) continue;
    const withs = step.get('with', true);
    if (!isMap(withs) || withs.get('mode') !== 'gate') continue;
    const pair = withs.items.find((p) => isScalar(p.key) && p.key.value === 'not-proven');
    if (pair !== undefined && isScalar(pair.value)) (pair.value as Scalar).comment = ` ${NOT_PROVEN_MARK}`;
  }
}

/** The pr-check job (BP-6): the egress step and the one lookup step; `pull-requests: read`; its output has-pr. */
function prCheckJob(): Job {
  const steps: RenderedStep[] = [egressStepFor([], { userSecret: false, dockerNetworks: false, job: PR_CHECK_JOB }), renderPrCheckStep()];
  return { 'runs-on': JOB_RUNNER, 'timeout-minutes': PR_CHECK_MINUTES, permissions: { contents: 'read', 'pull-requests': 'read' }, 'cache-mode': 'none', outputs: jobOutputsFor(steps), steps };
}

/** The central pin of a private draft, checked (C8r1): `<owner>/pipelines` at a 40-character commit. */
function centralPinOf(draft: PipelineDraft): { repo: string; sha: string } {
  const pin = draft.centralPin;
  const owner = draft.profile.owner;
  if (pin === undefined || !isObj(pin) || typeof pin.repo !== 'string' || typeof pin.sha !== 'string' || typeof owner !== 'string'
    || pin.repo.toLowerCase() !== `${owner.toLowerCase()}/pipelines` || !isGitHubRepo(pin.repo) || !COMMIT_SHA_RE.test(pin.sha)) {
    return fail('A private repository calls its central workflows from <owner>/pipelines at the commit pipegen recorded, and the draft has no valid central pin (<owner>/pipelines at a 40-character commit).');
  }
  return { repo: pin.repo, sha: pin.sha };
}

/** The layer's `uses` of the central repo at the pin. */
const centralUses = (pin: { repo: string; sha: string }, project: string, layer: CentralLayer): string =>
  `${layer === 'merge' ? centralWorkflowPath(pin.repo, project) : `${pin.repo}/${centralWorkflowFile(project, layer)}`}@${pin.sha}`;

// ---------- assemble ----------

/**
 * The delivered files of a draft (see the file header): G4's jobs (assembleJobs over `opts.plan`) laid out for the repository's layout.
 * Throws AssembleError for what it or G4 refuses.
 */
export function assemble(input: PipelineDraft, opts: AssembleOpts): AssembledFiles {
  const prof = input.profile;
  // 1. the layout is the repository's, never the caller's word
  if (opts.layout !== 'central' && opts.layout !== 'local') fail(`${show(opts.layout)} is not a layout pipegen writes (central or local).`);
  if (typeof prof.private !== 'boolean') fail('Whether the repository is private is not known, so its layout can not be chosen.');
  const layout: Layout = prof.private ? 'central' : 'local';
  if (opts.layout !== layout) fail(`A ${prof.private ? 'private' : 'public'} repository uses the ${layout} layout (ruling B2), not ${opts.layout}.`);
  const project = prof.repo;
  if (typeof prof.owner !== 'string' || typeof project !== 'string' || !isGitHubRepo(`${prof.owner}/${project}`)) fail(`The repository ${show(`${String(prof.owner)}/${String(project)}`)} is not a plain GitHub owner/name.`);
  const pin = layout === 'central' ? centralPinOf(input) : null;
  if (layout === 'local' && input.centralPin !== undefined) fail('A public repository keeps its workflows in the app (its central repo holds records only), so its draft carries no central pin: with one, its find-run step would look for a central workflow that is not there.');
  // 2. the gate is the reviewed entry
  const gateEntry = opts.reviewed.find((t) => t.id === 'pipegen-gate');
  if (gateEntry === undefined || !isDeepStrictEqual(gateEntry, opts.gate)) fail('The gate entry is not the reviewed pipegen-gate entry of the reviewed list.');
  // 3. the jobs (G4: every refusal of the job half happens here)
  const a = assembleJobs(input, opts.plan, { reviewed: opts.reviewed, platform: opts.platform, mode: opts.mode, ...(opts.baseImages === undefined ? {} : { baseImages: opts.baseImages }) });
  const draft = a.draft;
  const notes = [...a.notes];
  const deploySkipped = input.skipped.some((s) => s.part === 'deploy');
  const def = draft.profile.defaultBranch;
  const files: CreatedFile[] = [];

  // 4. merge: the called workflow with the gate, and pipegen.yml
  const mergePath = layout === 'central' ? centralWorkflowFile(project, 'merge') : LOCAL_MERGE_WORKFLOW;
  const mergeRepo: CreatedFile['repo'] = layout === 'central' ? 'central' : 'app';
  const mergeCaller = callerOf(CALLER_NAME.merge, pin === null ? `./${LOCAL_MERGE_WORKFLOW}` : centralUses(pin, project, 'merge'), a.merge);
  files.push(workflowFile({
    path: mergePath, repo: mergeRepo, name: 'pipegen merge', on: callTrigger(mergeCaller.secrets ?? {}), jobs: orderedAll(a.merge),
    reason: `The merge layer of ${project}: every check, the base scan and the gate (the required check ${CALLER_NAME.merge} / gate).`,
    comment: `pipegen: the merge layer of ${project}, called by its pipegen.yml only; written by pipegen. The not-proven list, when there is one, is the gate step's marked line.`,
  }));
  const appJobs: Record<string, Job | CallerJob> = { [MERGE_CALLER_JOB]: mergeCaller };
  // the deploy jobs (G7) run on a push to the default branch only, after the gate
  const deploy = opts.deploy ?? {};
  if (Object.keys(deploy).length > 0 && deploySkipped) fail('The deploy part is skipped (--skip deploy), but deploy jobs were given.');
  for (const [id, j] of Object.entries(deploy)) {
    if (!JOB_ID_RE.test(id) || RESERVED_IDS.has(id)) fail(`${show(id)} is not a deploy job id pipegen writes (or it is one of pipegen's own).`);
    if (!isObj(j)) fail(`The deploy job ${show(id)} is not a job.`);
    // G5-R1 m2: env, services, secrets, a container, a strategy, ... would change what runs; refused with the key's name, never dropped
    for (const k of Object.keys(j)) if (!DEPLOY_JOB_KEYS.has(k)) fail(`The deploy job ${show(id)} has the key ${show(k)}, which pipegen does not write on a deploy job.`);
    if (!Array.isArray(j.steps)) fail(`The deploy job ${show(id)} is not a job of steps.`);
    const limit = j['timeout-minutes'];
    if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > MAX_JOB_MINUTES) fail(`The deploy job ${show(id)} has no timeout-minutes of its own (1 to ${MAX_JOB_MINUTES}); the verify job's wait is computed from it.`);
    if (j.needs !== undefined && (!Array.isArray(j.needs) || j.needs.some((n) => typeof n !== 'string'))) fail(`The deploy job ${show(id)} has needs that are not a list of job ids.`);
    for (const n of j.needs ?? []) if (n !== MERGE_CALLER_JOB && !Object.hasOwn(deploy, n)) fail(`The deploy job ${show(id)} needs ${show(n)}, which is not a job of ${CALLER_WORKFLOW}.`);
    if (j.environment !== undefined) fail(`The deploy job ${show(id)} runs in an environment; a job in pipegen's push run never waits for a person or holds an environment's secrets (G41), so it is not written.`);
    if (j.if !== undefined) fail(`The deploy job ${show(id)} has a condition of its own; deploy jobs run exactly on a push to the default branch, after the gate.`);
    appJobs[id] = ordered({ ...j, needs: uniq([MERGE_CALLER_JOB, ...(j.needs ?? [])]), if: DEPLOY_PUSH_IF });
  }
  // G5-R1 I1: a delivery that publishes images signs them with the repository's own mode; mode none (the proof's, or a caller's) is only for a
  // repository whose own mode is none and whose draft records no signing plan (S21: no caller picks a mode, and none is a downgrade)
  if (Object.keys(deploy).length > 0 && opts.mode === 'none') {
    const own0 = signingMode(prof, input.capabilities);
    if (own0 !== 'none' || input.signing !== undefined) fail(`A delivery that publishes images signs them with the repository's own signing mode (${show(input.signing?.mode ?? own0)}), never with mode none.`);
  }
  // the signing (G3): keyless inline (public), or the central sign workflow and its caller (private); both after image-publish
  if (a.sign !== null) {
    if (!Object.hasOwn(deploy, IMAGE_PUBLISH_JOB)) fail(`The images are signed after the job ${IMAGE_PUBLISH_JOB} pushes them (the deploy layer); without it there is nothing to sign, so pipegen writes no sign job.`);
    const needs = [MERGE_CALLER_JOB, IMAGE_PUBLISH_JOB];
    if (layout === 'central') {
      const shared = guard(() => sharedWorkflows(draft, opts.mode, { reviewed: opts.reviewed, platform: opts.platform }));
      files.push(...shared);
      const caller = guard(() => signCallerJob(draft, opts.mode, needs)) as unknown as CallerJob | null;
      if (caller === null || shared.length !== 1) return fail('The central sign workflow or its caller could not be written.');
      const signJobs = (parse((shared[0] as CreatedFile).content) as { jobs: Record<string, Job> }).jobs;
      if (!isDeepStrictEqual(caller.permissions, callerPermissions(Object.entries(signJobs).map(([job, sj]) => ({ job, permissions: sj.permissions }))))) fail('The sign caller does not grant exactly what the sign workflow\'s job asks for.');
      appJobs[SIGN_JOB_ID] = caller;
    } else {
      appJobs[SIGN_JOB_ID] = ordered({ ...(a.sign as unknown as Job), needs, if: DEPLOY_PUSH_IF });
      if (!isDeepStrictEqual(a.sign.permissions, signPermissions(draft.signing?.mode as 'key-env' | 'keyless'))) fail('The sign job does not ask for exactly what its mode needs.');
    }
  }
  const callerOn = { push: guard(() => defaultPushTrigger(def)), pull_request: null, pull_request_review: { types: [...PR_REVIEW_TRIGGER.types] } };
  files.push(workflowFile({
    path: CALLER_WORKFLOW, repo: 'app', name: 'pipegen', on: callerOn, concurrency: true, jobs: appJobs,
    reason: 'Runs the merge layer on pull requests, reviews and pushes to the default branch (the required check), then the deploy jobs on the default branch.',
    comment: 'pipegen: the merge layer and the gate for pull requests and the default branch; written by pipegen (code-owner protected).',
  }));

  // 5. push: pr-check and the push-layer checks, each skipped when the branch has an open pull request
  if (Object.keys(a.push).length > 0) {
    const pushJobs: Record<string, Job> = { [PR_CHECK_JOB]: prCheckJob() };
    for (const [id, j] of Object.entries(a.push)) {
      if (id === PR_CHECK_JOB || j.if !== undefined) fail(`The push-layer job ${show(id)} can not carry the pr-check skip.`);
      pushJobs[id] = ordered({ ...j, needs: uniq([PR_CHECK_JOB, ...(j.needs ?? [])]), if: PR_CHECK_IF });
    }
    const pushOn = { push: guard(() => featurePushTrigger(def)) };
    const comment = 'pipegen: the push layer for every branch but the default (its checks skip when the branch has an open pull request); written by pipegen.';
    const reason = 'Runs the push layer on pushes to other branches than the default, unless the branch has an open pull request.';
    if (pin === null) files.push(workflowFile({ path: PUSH_WORKFLOW, repo: 'app', name: 'pipegen push', on: pushOn, concurrency: true, jobs: pushJobs, reason, comment }));
    else {
      const caller = callerOf(CALLER_NAME.push, centralUses(pin, project, 'push'), pushJobs);
      files.push(workflowFile({ path: centralWorkflowFile(project, 'push'), repo: 'central', name: 'pipegen push', on: callTrigger(caller.secrets ?? {}), jobs: pushJobs, reason, comment: `pipegen: the push layer of ${project}, called by its pipegen-push.yml only; written by pipegen.` }));
      files.push(workflowFile({ path: PUSH_WORKFLOW, repo: 'app', name: 'pipegen push', on: pushOn, concurrency: true, jobs: { [PUSH_CALLER_JOB]: caller }, reason, comment }));
    }
  }

  // 6. nightly (B5): the nightly job on schedule; no merge workflow, no not-proven list
  {
    const nightlyOn = { schedule: [{ cron: NIGHTLY_CRON }] };
    const nightlyJobs = orderedAll(a.nightly);
    const comment = 'pipegen: the nightly issues (warn-ending, finish-missing, updates); written by pipegen. It never pushes a file.';
    const reason = 'Opens the nightly issues: the warning period ending, finish not run, pipegen updates.';
    if (pin === null) files.push(workflowFile({ path: NIGHTLY_WORKFLOW, repo: 'app', name: 'pipegen nightly', on: nightlyOn, jobs: nightlyJobs, reason, comment }));
    else {
      const caller = callerOf(CALLER_NAME.nightly, centralUses(pin, project, 'nightly'), nightlyJobs);
      files.push(workflowFile({ path: centralWorkflowFile(project, 'nightly'), repo: 'central', name: 'pipegen nightly', on: callTrigger(caller.secrets ?? {}), jobs: nightlyJobs, reason, comment: `pipegen: the nightly job of ${project}, called by its pipegen-nightly.yml only; written by pipegen.` }));
      files.push(workflowFile({ path: NIGHTLY_WORKFLOW, repo: 'app', name: 'pipegen nightly', on: nightlyOn, jobs: { [NIGHTLY_CALLER_JOB]: caller }, reason, comment }));
    }
  }

  // 7. the verify-first job (G7 places it into the deploy workflows)
  let verify: Job | null = null;
  if (!deploySkipped) {
    const mergeMinutes = chainMinutes(a.merge, (id) => (a.merge[id] as Job)['timeout-minutes']);
    const signMinutes = a.sign?.['timeout-minutes'] ?? 0;
    const runMinutes = chainMinutes(appJobs as Readonly<Record<string, { needs?: string[] }>>, (id) => (id === MERGE_CALLER_JOB ? mergeMinutes : id === SIGN_JOB_ID ? signMinutes : deploy[id]?.['timeout-minutes']));
    const waitMinutes = runMinutes + VERIFY_GRACE_MINUTES;
    if (waitMinutes + VERIFY_MARGIN_MINUTES > MAX_JOB_MINUTES) fail(`The gated run can take ${runMinutes} minutes, longer than the verify job can wait (a job runs at most ${MAX_JOB_MINUTES} minutes).`);
    verify = verifyJob(draft, { gate: opts.gate, reviewed: opts.reviewed, platform: opts.platform, waitMinutes });
  }

  // 8. Dependabot (P-6, D0b): the github-actions entry appended to the user's file, or a new file; Renovate is kept
  const rf = draft.profile.repoFiles;
  if (rf.renovate !== null) addNote(notes, 'This repository uses Renovate, which keeps its own update settings, so pipegen adds no Dependabot file (set minimumReleaseAge: "7 days" in Renovate for the same cooldown).');
  else if (rf.dependabot !== null && !DEPENDABOT_PLACES.includes(rf.dependabot)) addNote(notes, 'The repository\'s Dependabot file is not at a path GitHub reads, so pipegen adds no entry.');
  else {
    if (rf.dependabot !== null && typeof opts.dependabot !== 'string') fail(`The repository has a Dependabot file (${show(rf.dependabot)}), but its text was not given, so pipegen can not append its entry without overwriting the file.`);
    if (rf.dependabot === null && opts.dependabot !== undefined) fail('No Dependabot file exists, but an existing text was given.');
    const original = rf.dependabot === null ? '' : (opts.dependabot as string);
    let r: ReturnType<typeof dependabotFile>;
    try { r = dependabotFile(original, draft); } catch (e) { return fail(`The Dependabot entry can not be built: ${safeText(e instanceof Error ? e.message : String(e), 200)}.`); }
    if ('note' in r) addNote(notes, r.note);
    else files.push({ path: rf.dependabot ?? DEPENDABOT_PATH, content: r.content, part: 'pipeline', reason: 'Keeps the pinned actions up to date, each update at least 7 days old (cooldown).', repo: 'app', edited: { original } });
  }

  checkLayout(files, draft, layout);
  return { draft, files, verify, notes };
}

function orderedAll(jobs: Readonly<Record<string, Job>>): Record<string, Job> {
  return Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, ordered(j)]));
}
function addNote(notes: string[], line: string): void { if (!notes.includes(line)) notes.push(line); }

/**
 * The pipegen-verify job (plan "Verify-first"), as far as the layout goes: the egress step, then the gate action in find-run mode (findGatedRun:
 * the trusted push run of pipegen.yml on the default branch for the deployed commit, through the central workflow at the pin for a private
 * repository, layout inline for a public one), which waits `waitMinutes` for a run in progress (assemble computes it from the gated run's worst case, G5-R1 m1). It runs in pipegen-signing whenever the
 * repository has environments (only default-branch deploys pass it), with exactly the verify row's read permissions, cache-mode none, and
 * outlives its wait by VERIFY_MARGIN_MINUTES. The deploy layer (G7) places it into the deploy workflows and adds, after the find-run step, the
 * digest download by the found run's id, the digest check and the signature check of each image (B3 a, c, d): the referee's order rule reads
 * the gate action as a step that could change what runs after it, so those steps need G7's order exception, and none is written here.
 */
export function verifyJob(draft: PipelineDraft, deps: { gate: ReviewedTool; reviewed: readonly ReviewedTool[]; platform: PlatformActions; waitMinutes: number; sha?: 'github.sha' | 'workflow_run' }): Job {
  const wait = deps.waitMinutes;
  if (!Number.isInteger(wait) || wait < 1 || wait + VERIFY_MARGIN_MINUTES > MAX_JOB_MINUTES) fail(`The verify job's wait ${show(wait)} is not 1 to ${MAX_JOB_MINUTES - VERIFY_MARGIN_MINUTES} whole minutes.`);
  const central = draft.centralPin === undefined ? undefined : { ...centralPinOf(draft), project: draft.profile.repo };
  if (central !== undefined && draft.profile.private !== true) fail('A public repository\'s verify job looks for its gate inline, so its draft carries no central pin.');
  const find = guard(() => renderFindRunStep(deps.gate, { ...(central === undefined ? {} : { central }), sha: deps.sha ?? 'github.sha', timeoutMinutes: wait }));
  const steps = [egressStepFor([], { userSecret: false, dockerNetworks: false, job: VERIFY_JOB_ID }), find];
  return {
    'runs-on': JOB_RUNNER, 'timeout-minutes': wait + VERIFY_MARGIN_MINUTES, permissions: { ...VERIFY_PERMISSIONS },
    ...(draft.capabilities.environments === true ? { environment: SIGNING_ENVIRONMENT } : {}), 'cache-mode': 'none', steps,
  };
}

// ---------- the layout checks ----------

/**
 * The checks every assembled set passes before it leaves (a second net under the referee, on what this file itself guarantees): each path is
 * a plain created path and no composite action is written (E-b9); no path twice, none the draft already holds; in every workflow each `needs`
 * names a job of the same file, no workflow_dispatch, no workflow_call input, no `secrets: inherit`, no caller `with`, no environment but the
 * signing one and only on sign and pipegen-verify (G41); no cycle of `needs`; the not-proven mark is on exactly one line, the merge file's, when the draft has a not-proven check, and nowhere else.
 */
function checkLayout(files: readonly CreatedFile[], draft: PipelineDraft, layout: Layout): void {
  const seen = new Set<string>(draft.created.map((f) => `${f.repo}:${f.path}`));
  const mergeKey = layout === 'central' ? `central:${centralWorkflowFile(draft.profile.repo, 'merge')}` : `app:${LOCAL_MERGE_WORKFLOW}`;
  const notProven = draft.notProven.some((n) => typeof n.needId === 'string');
  let marks = 0;
  for (const f of files) {
    const key = `${f.repo}:${f.path}`;
    const where = show(key);
    const problem = createdPathProblem(f.path);
    if (problem !== null) fail(`The file ${where} has a path pipegen does not write: ${problem}.`);
    if (/^\.github\/actions\//i.test(f.path)) fail(`The file ${where} is a composite action; pipegen renders none (E-b9).`);
    if (seen.has(key)) fail(`The file ${where} is already in the draft (or written twice); one source per path.`);
    seen.add(key);
    const marked = f.content.split('\n').filter((l) => l.includes(NOT_PROVEN_MARK)).length;
    if (marked > 0 && (key !== mergeKey || marked !== 1)) fail(`The file ${where} holds the not-proven mark where pipegen never writes it.`);
    if (key === mergeKey) marks = marked;
    if (!f.path.startsWith('.github/workflows/')) continue;
    const wf = parse(f.content) as Obj;
    const on = wf.on;
    if (!isObj(on) || Object.hasOwn(on, 'workflow_dispatch')) fail(`The file ${where} has no trigger map, or a workflow_dispatch.`);
    const call = (on as Obj).workflow_call;
    if (isObj(call) && Object.keys(call).some((k) => k !== 'secrets')) fail(`The file ${where} declares a workflow_call input or output.`);
    const jobs = isObj(wf.jobs) ? wf.jobs : fail(`The file ${where} has no jobs.`);
    for (const [id, j] of Object.entries(jobs)) {
      if (!isObj(j)) fail(`The job ${show(id)} of ${where} is not a map.`);
      const job = j as Obj;
      for (const n of Array.isArray(job.needs) ? job.needs : job.needs === undefined ? [] : [job.needs]) if (typeof n !== 'string' || !Object.hasOwn(jobs, n)) fail(`The job ${show(id)} of ${where} needs ${show(n)}, which is not a job of that file.`);
      if (job.secrets === 'inherit') fail(`The job ${show(id)} of ${where} passes every secret.`);
      if (job.uses !== undefined && job.with !== undefined) fail(`The caller job ${show(id)} of ${where} passes an input.`);
      if (job.environment !== undefined && !(job.environment === SIGNING_ENVIRONMENT && (id === SIGN_JOB_ID || id === VERIFY_JOB_ID))) fail(`The job ${show(id)} of ${where} runs in an environment; only the sign and verify jobs run in ${SIGNING_ENVIRONMENT} (no job waits for a person, G41).`);
    }
    chainMinutes(jobs as Record<string, Obj>, () => 1);   // no cycle of needs
  }
  if (marks !== (notProven ? 1 : 0)) fail(`The merge workflow has ${marks} lines marked ${NOT_PROVEN_MARK}; it has exactly one when the draft has a not-proven check, else none.`);
}

/**
 * The longest chain of `needs` among jobs, each job counting `weight(id)` minutes (a job missing its limit counts GitHub's 360). A cycle is
 * refused.
 */
function chainMinutes(jobs: Readonly<Record<string, { needs?: unknown }>>, weight: (id: string) => number | undefined): number {
  const memo = new Map<string, number>();
  const at = (id: string, path: ReadonlySet<string>): number => {
    const m = memo.get(id);
    if (m !== undefined) return m;
    if (path.has(id)) return fail(`The job ${show(id)} needs itself through a cycle.`);
    const j = jobs[id];
    const needs = j === undefined ? [] : Array.isArray(j.needs) ? (j.needs as string[]) : [];
    const w = weight(id);
    const d = (typeof w === 'number' && Number.isFinite(w) ? w : MAX_JOB_MINUTES) + Math.max(0, ...needs.map((n) => at(n, new Set([...path, id]))));
    memo.set(id, d);
    return d;
  };
  return Math.max(0, ...Object.keys(jobs).map((id) => at(id, new Set())));
}

// ---------- the one referee call ----------

export interface JudgeAssembledDeps {
  platform: PlatformActions; reviewed: readonly ReviewedTool[]; linters: Linters; ghToken: string | null; refereeDeps?: RefereeDeps;
  /** Files of the same delivery made after assemble (PIPEGEN.md, CODEOWNERS): judged in the same call. */
  extra?: readonly CreatedFile[];
  /** The referee (tests inject a spy). */
  referee?: typeof referee;
}
/**
 * The one referee call over every file of the delivery (D4-r1 C4): the draft's created files (docker-compose.pipegen.yml among them), the
 * assembled workflows and Dependabot file, and `extra`, against the assembled draft. Split, the runtime-env and compose-up steps of a test
 * job would be unrecognised (the compose plan counts only when its file is judged in the same call).
 */
export function judgeAssembled(a: AssembledFiles, deps: JudgeAssembledDeps): Promise<RefereeReport> {
  const files = [...a.draft.created, ...a.files, ...(deps.extra ?? [])];
  return (deps.referee ?? referee)(files, a.draft, deps.platform, [...deps.reviewed], deps.linters, deps.ghToken, deps.refereeDeps ?? {});
}
