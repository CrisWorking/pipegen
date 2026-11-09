// v0.2 Plan G Task 2, job half (sub-task G4): the concrete jobs of each layer, built from the debate's decided steps and pipegen's own rules.
// G5 lays them out into files and callers (triggers, the pr-check skip, the caller permissions, the central or local layout); nothing here
// writes a file. Every job is made only of the shared renderers (render-step.ts, render-cli.ts, image-handoff.ts, signing.ts, egress.ts, the
// G1/G2 forms of job-rules.ts), so the referee recognises each step by its content.
//
// What assembleJobs refuses (AssembleError, before anything is rendered):
// - a floor need in the draft's not-proven list (the gate would block on every run, and a floor check is never optional);
// - a blocking need the debate left uncovered (F carry 5: never guessed), with its plain reason; the v0.2 limits below are reported instead;
// - a step that is not specFor over keyOffers(DebateResult) for its need key (F carry 5, Plan F ruling S22): an unreviewed tool, a suggestion
//   (mention-only, never run), a tool not offered for that key, or a pick outside what was offered; `secrets` and `needsServices` are the
//   draft's own additions (the renderer and the referee judge them);
// - a draft whose needs are not the debate's (one source);
// - a blocking check pipegen can not render (a pnpm service, a Python project script, ...): never dropped silently;
// - starter tests in the draft while the isolated starter-test job is switched off (ISOLATED_TEST_JOB, ruling D7-R7, S19);
// - a job that holds a user secret and would need a shared-CDN egress set (E3-R3, E-b5);
// - GJ (Plan J): an image build, image scan, DAST or API DAST need for a service the plan builds no image for (noImageServices, read from
//   skippedChecks: a static site, or a service that doesn't run). The jobs follow the needs list only; the type is never read again here.
//
// What it leaves out, each with a note (the returned draft no longer holds them, so the gate's job list, the referee and PIPEGEN.md agree):
// - the parts skipped with --skip (tests, precommit, deploy; the others make no job); the secrets scan and the gate are never skippable;
// - v0.2 limits: api-dast and PyPI publishing (S31); Scorecard (PF-3: the action runs a tag-pinned image); fuzzing (v0.3); an image build
//   that can not be rendered (a sub-folder service, ruling S8) and the scans of that image; an osv-scanner run for a service with no lockfile
//   (G12: it exits 128); a non-blocking DAST check whose app pipegen can not start in a container. A blocking one stops (G4-R1, G0-R1);
// - GJ (Plan J fix wave I1, DECISIONS #122): workflow lint runs zizmor, plus poutine when a workflow runs on pull_request_target or
//   issue_comment, never actionlint. Its steps are code-chosen (withLintSteps: every offered tool, each once), so the debate can not pick one
//   in place of the other; a draft step running another tool is refused. When zizmor isn't on the reviewed list the check is only a
//   suggestion: no job, its needs leave the draft, a note says so;
// - GJ (DECISIONS #122): hooks-ci of a pre-commit or husky repository (no reviewed runner for its hooks: NO_HOOKS_CI_MANAGERS) is a plain
//   note, never lefthook in their place; its needs leave the draft (the proof reports those hooks as not proven).
//
// The jobs (one per need key: the gate's job list is keyed by jobIdFor, so the estimate's JOB_GROUP grouping is not applied, see the G4 report):
// - every job starts with the reviewed egress step (Bullfrog block, E0d per job: github-core plus the sets its tools need; P-3), then its checkout;
//   runs on a hosted label, `timeout-minutes` 30, `cache-mode: none`, `contents: read` unless the permission table gives its id more;
// - findings jobs: renderFindingsBlock (stage for the secrets tools, the scan, the scrub, the upload of exactly resultArtifactName), and the
//   outputs `<artifact>-sha256|-status|-error` (jobOutputsFor). The merge layer's secrets job adds the pre-push head fetch (C9r1) and the
//   commit-range block (C9) after a full-history checkout;
// - job-status jobs: the tool's steps, or the project's own script first (it brings its own checkout), or the repo's own tool (G4b: a
//   TypeScript service's tsc at its lockfile version, after the guarded npm ci and a run-time lockfile check; no key, no secret); a test job of a service with
//   dependencies gets the runtime env and compose up, only when the draft holds the compose file pipegen computes (D4);
// - DAST (G4-R1, dast-handoff.ts): `dast-run--<svc>` with no key and no secret starts the app in containers only (pipegen's compose file, or
//   the checked image archive on 127.0.0.1), runs the reviewed scan and hands the raw result on with its sha256; `dast--<svc>` (the gate's
//   job) checks that sha256, scrubs and uploads; no base twin;
// - image-build--<svc>: the reviewed build-push with no push on the default docker driver (no setup-buildx: with the docker-container
//   builder the image never reaches the local store and `docker image save` fails, G2 carry), the archive step and its upload; the image scans
//   read that archive after its sha256 check (B6), with no base twin (C-MUST-1);
// - base-scan: the base checkout (BASE_CHECKOUT_REF), the base twin of every findings check; dependency and licence scans always, the others
//   only when baseline-check reports no trusted baseline (BASELINE_MISSING_IF, G21); it needs baseline-check and outputs base-sha;
// - baseline-check (the gate in mode baseline-check, output `found`), gate (renderGateStep over the returned draft, its uploads, `if:
//   always()`, needs = every job of the gate's list plus base-scan), nightly (renderNightlyStep: the warn-ending, finish-missing, update and
//   warn-first issues; issues: write here only; no checkout, so it never pushes a file; concurrency pipegen-nightly);
// - sign: G3's job for the delivered mode (signingMode), none for the proof (PROOF_SIGNING_MODE) or a skipped deploy; an attest job that can
//   not be written is "not signed" with a note, never another mode. GJ (Plan J): a signing or attestation need on a service that builds no image is report-only:
//   its image leaves the signing plan, and with no service building an image there is no sign job at all; a note each (PIPEGEN.md, G9).
import { isDeepStrictEqual } from 'node:util';
import { keyOffers, specFor, BuilderError, workflowLintAvailable, type Offer } from '../debate/builder.js';
import type { DebateResult } from '../debate/debate.js';
import { needKeyOf, NeedKeyError, type NeedRef } from '../debate/need-ref.js';
import { COMPOSE_PATH, planCompose } from '../create/compose.js';
import { ArtifactNameError, resultArtifactName, slug } from '../engine/artifact-names.js';
import { baseImageRef, loadBaseImages, nodeBaseImageId, type BaseImage } from '../engine/base-images.js';
import { dockerfilesOf } from '../engine/created-judges/compose.js';
import { egressSetsForTool, renderEgressStep, SHARED_CDN_SETS, type EgressSet } from '../engine/egress.js';
import { gateJobList, GateJobListError, jobIdFor, PIPEGEN_JOB_CATEGORIES, resultFormat } from '../engine/gate-job-list.js';
import { SKIPPED_PART_NEEDS } from '../engine/gate-inputs.js';
import { ARCHIVE_TOOL_IDS, renderImageArchiveScan, renderImageBuild } from '../engine/image-handoff.js';
import { dastStartOf, nightlyDastSpec, NIGHTLY_DAST_TOOL, renderDastRun, renderDastScrub, zapActiveNotRunNote, zapActiveSpec, ZAP_ACTIVE_JOB_MINUTES, ZAP_ACTIVE_LANE, ZAP_ACTIVE_TOOL, type DastStart } from '../engine/dast-handoff.js';
import {
  BASE_ALWAYS_CATEGORIES, BASELINE_CHECK_JOB, dastRunJobId, BASELINE_MISSING_ALWAYS_IF, BASELINE_MISSING_IF, IMAGE_BUILD_NEED, imageBuildJobId, isReviewed,
  isScrubStep, jobOutputsFor, CODE_SCANNING_JOB, DAST_UPLOAD_JOB, dastLaneOf, dastNightlyCategory, dastResultArtifact, type DastLane, HISTORY_UPLOAD_JOB, SECRETS_HISTORY_CATEGORY, SECRETS_HISTORY_JOB, NIGHTLY_CONCURRENCY, NIGHTLY_IF, NO_SCANS, SCORECARD_IF, SCORECARD_JOB, ZIZMOR_ONLINE_JOB, renderRangeFetchStep, type RenderedStep, type ScanFact,
} from '../engine/job-rules.js';
import { NEED_ID_CATEGORY, SCHEDULED_CATEGORIES } from '../engine/need-ids.js';
import { MINIMUM_CATEGORIES, NO_HOOKS_CI_MANAGERS, NO_IMAGE_CATEGORIES, noImageServices, riskyTriggersOf, WORKFLOW_LINT_EXTRA, WORKFLOW_LINT_TOOL, workflowLintTools } from '../engine/needs.js';
import { parseImageRef } from '../engine/names.js';
import { PLATFORM_ACTION_IDS, type PlatformActions } from '../engine/pin.js';
import { APP_RUNNING_CATEGORIES, renderStarterTestRun } from '../engine/render-cli.js';
import { RenderError } from '../engine/render-error.js';
import {
  dedupeJobSteps, renderBaselineCheckStep, renderComposeUp, renderFindingsBlock, renderGateStep, renderGateUploads, renderJobPrelude, renderNightlyStep,
  renderHistoryBlock, renderPlatformStep, renderZizmorOnline, renderProjectScript, renderRangeBlock, renderRepoTool, renderRuntimeEnv, renderScorecardBlock, renderScrub, renderStep, renderUpload, scanFactOf, scrubbedPath,
  SCORECARD_ARTIFACT, SCORECARD_CATEGORY, type RenderContext,
} from '../engine/render-step.js';
import { projectScriptFor, repoToolFor, repoToolProblem, type RepoToolStep } from '../engine/reviewed.js';
import { PLATFORM_USES, RANGE_TOOL } from '../engine/tool-flags.js';
import { signedImageOwner } from '../engine/signing.js';
import { codeSecurityAvailable } from '../github/availability.js';
import type { SigningMode } from '../github/signing-mode.js';
import { signJob, type SignJob } from './central.js';
import type { Need, NeedCategory, PipelineDraft, ReviewedTool, Service, SkippablePart, StepSpec } from '../types.js';
import { FLOOR_NEEDS } from '../types.js';
import { safeText } from '../util/safe-text.js';

// ---------- constants ----------

/** The runner every job pipegen writes runs on (a hosted label, the referee's list). */
export const JOB_RUNNER = 'ubuntu-24.04';
/** Every job's timeout (G40: the verify job's wait must exceed it). */
export const JOB_MINUTES = 30;
/**
 * Ruling D7-R7 (S19): the isolated starter-test job is rendered (starterTestJob), but the switch stays off until a reviewed change flips it after
 * the live acceptance (probes f1b, f2, f3, o2, e1, e3 as hostile tests in that job). While it is off, no starter test is created (Plan D:
 * createStarterTests returns a not-proven note unless the isolated-job switch is passed as true, and pipegen never passes it), and a draft that holds
 * one is refused here.
 */
export const ISOLATED_TEST_JOB: boolean = false;
/** E3-R3 (E-b5): the egress sets whose hosts serve anyone's content (release assets, the OSV API, the Trivy DB mirror): never in a job with a user secret. */
export { SHARED_CDN_SETS };
/** The job id prefix of the isolated starter-test job (one per service). */
export const STARTER_TEST_JOB = 'starter-tests';
/** The gate job's name: the required check is `pipegen / gate` (GATE_CHECK_NAME) through the caller job `pipegen`. */
const GATE_JOB_NAME = 'gate';

/** v0.2 limits: categories pipegen does not render yet, each with the line the notes (and PIPEGEN.md) carry. */
export const NOT_RENDERED_V02: Readonly<Partial<Record<NeedCategory, string>>> = Object.freeze({
  'api-dast': 'API testing against the API spec is not available yet: its tool (schemathesis) needs a reviewed hash-locked closure of its Python dependencies, planned for v0.4.',
  fuzzing: 'Fuzzing is built in v0.3.',
});
/** The PyPI publish action (S31): it builds or pulls a container at run time, so it is not rendered in v0.2. */
const PYPI_PUBLISH_ID = 'pypi-publish';
/** GJ (DECISIONS #122): the note of hooks-ci for a hook manager pipegen has no reviewed CI runner for. */
export const HOOKS_CI_NOTES: Readonly<Record<string, string>> = Object.freeze({
  'pre-commit': "This repository's hooks are pre-commit's, and pipegen has no reviewed pre-commit runner yet, so CI does not run them: add `pre-commit run --all-files` to your own CI.",
  husky: "husky's hooks are shell scripts, so there is no one command pipegen can run in CI: call the same script from a workflow step yourself.",
});
/** GJ-R1 (reviews spec I2, sec M2): the note when a workflow runs on a risky trigger but poutine is not offered (not on the reviewed list). */
export const POUTINE_NOT_RUN = `A workflow runs on pull_request_target or issue_comment, which takes untrusted input, but pipegen can't offer ${WORKFLOW_LINT_EXTRA} for this run (it is not on the reviewed list, or not yet proven for a full run), so ${WORKFLOW_LINT_EXTRA} is not run; ${WORKFLOW_LINT_TOOL} still lints the workflows.`;
/** GJ (DECISIONS #122): the note when zizmor, workflow lint's one tool, is not on the reviewed list. */
export const WORKFLOW_LINT_SUGGESTION = `Workflow lint runs ${WORKFLOW_LINT_TOOL} only, and ${WORKFLOW_LINT_TOOL} is not on pipegen's reviewed list in this version, so it is only a suggestion: add ${WORKFLOW_LINT_TOOL} to your own CI to lint the workflows.`;
export const PYPI_PUBLISH_NOTE = 'Publishing to PyPI is not rendered yet: the publish action builds or pulls a container at run time, and pipegen runs only images pinned by digest.';

/**
 * The needs a part skipped with --skip takes out of the jobs: tests the gate's own list (SKIPPED_PART_NEEDS, so the gate shows them as skipped);
 * precommit the pre-commit layer and its CI proof (hooks-ci); deploy the deploy layer. The others (docker, compose, locks, slack, test-migration)
 * are created files or settings, not jobs. The secrets scan and the gate are never a part (SkippablePart).
 */
export function skippedByPart(part: SkippablePart, n: Pick<Need, 'id' | 'layer' | 'category'>): boolean {
  if (part === 'tests') return SKIPPED_PART_NEEDS.tests.includes(n.id);
  if (part === 'precommit') return n.layer === 'pre-commit' || n.category === 'hooks-ci';
  if (part === 'deploy') return n.layer === 'deploy';
  return false;
}

// ---------- types ----------

/** One job as G5 writes it (keys in this order). */
export interface Job {
  name?: string; 'runs-on': string; 'timeout-minutes': number; needs?: string[]; if?: string; permissions: Record<string, 'read' | 'write'>;
  environment?: string; concurrency?: string; 'cache-mode': 'none'; outputs?: Record<string, string>; steps: RenderedStep[];
}
/** What the jobs are made with: the reviewed list (the gate entry included), the platform actions, and the signing mode (signingMode, or PROOF_SIGNING_MODE). */
export interface JobsDeps { reviewed: readonly ReviewedTool[]; platform: PlatformActions; mode: SigningMode; baseImages?: readonly BaseImage[] }
/** The parts of the debate's result the jobs come from (F carry 5): its needs, its final candidates map, its uncovered needs. */
export type JobsPlan = Pick<DebateResult, 'needs' | 'candidates' | 'uncovered'>;
export interface AssembledJobs {
  /** The draft the jobs were rendered from: the input without the skipped parts and the v0.2 limits. The referee, the gate inputs and PIPEGEN.md read this one. */
  draft: PipelineDraft;
  /** The push layer's checks (G5 adds pr-check and the skip condition). */
  push: Record<string, Job>;
  /** The merge layer: its checks, the image builds and scans, baseline-check, base-scan and gate. */
  merge: Record<string, Job>;
  /** The nightly job (the scheduled checks of v0.2 are limits, see NOT_RENDERED_V02). */
  nightly: Record<string, Job>;
  /** G3's sign job for the delivered mode; null for none, the proof, a skipped deploy and an attest job that can not be written. */
  sign: SignJob | null;
  notes: string[];
  /**
   * GJ-R1 (reviews sec M4, spec M4): the minimum checks (MINIMUM_CATEGORIES) the jobs leave without a job, each with its plain reason: workflow
   * lint when zizmor is not on the reviewed list (also in draft.suggestions), a deps check whose only scanner has no lockfile to read. Every
   * other minimum check is a written job (assembleJobs asserts it). The preview and PIPEGEN.md (G9) show these as not covered.
   */
  uncoveredMinimum: UncoveredMinimum[];
}

/**
 * GJ-R2 (review GJ-r1 N3): one minimum check of the plan left without a job, per need (its id and service), with its plain reason and the tool
 * that would run it (routed into draft.suggestions, so the preview and PIPEGEN.md show it; a floor check is never not-proven).
 */
export interface UncoveredMinimum { category: string; needId: string; service?: string; why: string; tool?: { name: string; repo: string } }

export class AssembleError extends Error {}

const fail = (m: string): never => { throw new AssembleError(m); };
const show = (s: unknown): string => JSON.stringify(safeText(String(s), 60));
const categoryOf = (id: string): string | undefined => (Object.hasOwn(NEED_ID_CATEGORY, id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[id] : undefined);
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const isFloor = (needId: string): boolean => FLOOR.has(needId) || FLOOR.has(categoryOf(needId) ?? '');
const isFindings = (t: ReviewedTool): boolean => resultFormat(t.step.output.format) === 'sarif' || t.step.output.format === 'zap-json';
const keyOf = (n: { id: string; service?: string }): string => {
  try { return needKeyOf(n); } catch (e) { if (e instanceof NeedKeyError) return fail(e.message); throw e; }
};
const where = (n: { id?: string; needId?: string; service?: string }): string => `${show(n.id ?? n.needId)}${n.service === undefined ? '' : ` for ${show(n.service)}`}`;

// ---------- the checks before anything renders ----------

/** F carry 5: every step is specFor over keyOffers of the debate's result, for its own need key (the picks only from what was offered). */
function checkSteps(draft: PipelineDraft, plan: JobsPlan, reviewed: readonly ReviewedTool[]): void {
  let offers: ReturnType<typeof keyOffers>;
  try { offers = keyOffers(plan.needs, plan.candidates, draft.profile, { reviewed }); } catch (e) { if (e instanceof NeedKeyError) return fail(e.message); throw e; }
  const refs = new Map<string, NeedRef>(offers.refs.map((r) => [r.key, r]));
  draft.steps.forEach((spec, i) => {
    const at = `The step ${i + 1} (${spec?.needId === undefined ? 'no check' : where(spec)})`;
    if (spec === null || typeof spec !== 'object' || typeof spec.needId !== 'string' || spec.tool === null || typeof spec.tool !== 'object') return fail(`${at} is not a step.`);
    const key = keyOf({ id: spec.needId, ...(spec.service === undefined ? {} : { service: spec.service }) });
    const ref = refs.get(key);
    const offer: Offer | undefined = (offers.offers.get(key) ?? []).find((o) => o.entry.id === spec.tool.id);
    if (ref === undefined || offer === undefined || !isReviewed(spec.tool)) {
      return fail(`${at} runs ${show(spec.tool.id)}, which is not a reviewed tool pipegen offered for that check (a suggestion is only mentioned, never run).`);
    }
    const { tuning, ...rest } = spec.choices ?? {};
    const picks = { choices: Object.fromEntries(Object.entries(rest).filter((e): e is [string, string] => typeof e[1] === 'string')), ...(tuning === undefined ? {} : { tuning }) };
    let built: StepSpec;
    try { built = specFor(ref, offer, draft.profile, picks); } catch (e) { if (e instanceof BuilderError) return fail(`${at} has a pick that was not offered for it.`); throw e; }
    const { secrets: _s, needsServices: _n, ...own } = spec;
    if (!isDeepStrictEqual(JSON.parse(JSON.stringify(own)), JSON.parse(JSON.stringify(built)))) fail(`${at} is not the step pipegen builds for ${show(spec.tool.id)} from the debate's choice (a field was changed).`);
  });
}

const UNCOVERED_REASON: Readonly<Record<string, string>> = Object.freeze({
  'none-offered': 'reviewed tools exist for it, but none fits this repository',
  'no-reviewed-tool': 'pipegen has no reviewed tool for it yet',
  'no-repo-tool': "the repository has no tool of its own for it that pipegen can run",
});

// ---------- egress ----------

/** The package-registry sets a service's own install needs (npm → npm, pip/poetry/uv → pypi). */
export function packageSets(svcs: readonly (Service | undefined)[]): EgressSet[] {
  const out = new Set<EgressSet>();
  for (const s of svcs) {
    if (s?.packageManager === 'npm') out.add('npm');
    else if (s?.packageManager === 'pip' || s?.packageManager === 'poetry' || s?.packageManager === 'uv') out.add('pypi');
  }
  return [...out];
}
/** The registry set of a pinned image reference. */
function imageSet(ref: string): EgressSet {
  const at = ref.indexOf('@');
  const image = parseImageRef((at === -1 ? ref : ref.slice(0, at)).replace(/:[^/:]*$/, ''));
  if (image === null) return fail(`The image ${safeText(ref, 120)} is on a registry pipegen has no egress set for.`);
  return image.registry === 'ghcr.io' ? 'ghcr' : 'dockerhub';
}
/**
 * The egress step of a job (E0d per job): github-core plus `sets`, sorted, each once. A job that holds a user secret (a declared app secret)
 * never gets a shared-CDN set (E3-R3): refused, never rendered without it (the job would fail at DNS) or with it (a host anyone can serve from).
 */
export function egressStepFor(sets: readonly EgressSet[], opts: { userSecret: boolean; dockerNetworks: boolean; job: string }): RenderedStep {
  const list = [...new Set(sets)].sort();
  const shared = list.filter((s) => SHARED_CDN_SETS.has(s));
  if (opts.userSecret && shared.length > 0) fail(`The job ${show(opts.job)} holds a secret of the app, but its tools need the shared-CDN egress set ${shared.join(', ')} (hosts that serve anyone's content); pipegen never gives such a set to a job with a user secret (E3-R3).`);
  return renderEgressStep(list, { dockerNetworks: opts.dockerNetworks });
}
/** The sets a job's steps need besides its tools': the repository's own npm install. */
const installSets = (steps: readonly RenderedStep[], svc: Service | undefined): EgressSet[] => (steps.some((s) => s.id?.startsWith('pipegen-npm-ci-') === true) ? packageSets([svc]).concat(['npm']) : []);

// ---------- the builder ----------

interface Ctx {
  draft: PipelineDraft; deps: JobsDeps; byId: Map<string, ReviewedTool>; gate: ReviewedTool; notes: string[];
  /** the runtime env and the images of the compose file pipegen computes, when the draft holds exactly that file (D4) */
  compose: { env: ReturnType<typeof planCompose>['env']; images: EgressSet[] } | null;
}

function toolOf(c: Pick<Ctx, 'byId'>, id: string): ReviewedTool {
  const t = c.byId.get(id);
  if (t === undefined || !isReviewed(t.candidate)) return fail(`The reviewed list has no reviewed ${show(id)} entry.`);
  return t;
}
const job = (steps: RenderedStep[], over: Partial<Job> = {}): Job => {
  const outputs = jobOutputsFor(steps);
  return {
    'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, permissions: { contents: 'read' }, 'cache-mode': 'none',
    ...(Object.keys(outputs).length > 0 ? { outputs } : {}), ...over, steps,
  };
};
/** Whether any need of this need id and service blocks (the referee's rule, G2-R1 I1); none at all counts as blocking. */
const blocks = (draft: PipelineDraft, needId: string, service: string | undefined): boolean => {
  const m = draft.needs.filter((n) => n.id === needId && n.service === service);
  return m.length === 0 || m.some((n) => n.blocking !== false);
};
const serviceNamed = (draft: PipelineDraft, name: string | undefined): Service | undefined => (name === undefined ? undefined : draft.profile.services.find((s) => s.name === name));

/** A check job (findings or job status) for one need key on one layer. */
function checkJob(c: Ctx, need: Need, specs: readonly StepSpec[], range: boolean): Job {
  const id = jobIdFor(need.id, need.service);
  const svc = serviceNamed(c.draft, need.service);
  const ctx: RenderContext = { profile: c.draft.profile, blocking: blocks(c.draft, need.id, need.service) };
  const body: RenderedStep[] = [];
  const scans = new Map<string, ScanFact>();
  const sets: EgressSet[] = [];
  let fullHistory = range;
  let userSecret = false;
  let script = false;
  for (const spec of specs) {
    const t = toolOf(c, spec.tool.id);
    sets.push(...egressSetsForTool(t));
    if ((spec.secrets ?? []).length > 0) userSecret = true;
    if (isFindings(t)) {
      const b = renderFindingsBlock(spec, t, c.deps.platform, ctx, c.gate);
      body.push(...b.steps);
      scans.set(b.scan.stepId, b.scan.fact);
      if (b.result.fullHistory === true) fullHistory = true;
    } else {
      const r = renderStep(spec, t, c.deps.platform, ctx);
      body.push(...r.steps);
      if (r.fullHistory === true) fullHistory = true;
    }
  }
  if (specs.length === 0) {
    const ps = svc === undefined ? null : projectScriptFor(need, svc);
    // G4b: else the repo's own tool (a TypeScript service's tsc at its lockfile version): a job-status check, no scrub, no key, no secret
    const rt = svc === undefined || ps !== null ? null : repoToolFor(need, svc);
    if (ps === null && rt === null) return fail(`Nothing runs the check ${where(need)}.`);
    body.push(...(ps !== null ? renderProjectScript(ps, c.deps.platform, ctx) : renderRepoTool(rt as RepoToolStep, c.deps.platform, ctx)).steps);
    script = true;
  }
  if (range) {
    const rt = toolOf(c, RANGE_TOOL);
    const b = renderRangeBlock(rt, c.deps.platform, c.gate);
    sets.push(...egressSetsForTool(rt));
    // C9r1: the pre-push head fetch right before the range block (after the head scan's own steps)
    body.push(renderRangeFetchStep(), ...b.steps);
    scans.set(b.scan.stepId, b.scan.fact);
  }
  // a project script or a repo tool brings its own checkout and setup (item 38), so no prelude; any other job checks out first (fetch depth per its tools)
  const prelude = script ? [] : renderJobPrelude(fullHistory ? { fetchDepth: '0' } : {}, c.deps.platform).steps;
  let steps = [...prelude, ...body];
  // D4: a test job of a service with dependencies starts them first (runtime env, then compose up), only with pipegen's own compose file
  const compose = c.compose !== null && svc !== undefined && svc.dependsOn.length > 0 && APP_RUNNING_CATEGORIES.has(categoryOf(need.id) ?? '') && scans.size === 0;
  if (compose && c.compose !== null) {
    const at = steps.findIndex((s) => s.run !== undefined || (s.uses !== undefined && !/^pipegen-(?:checkout|setup-node-\d{1,3}|setup-python)$/.test(s.id ?? '') && s.id !== undefined));
    const cut = at < 0 ? steps.length : at;
    steps = [...steps.slice(0, cut), renderRuntimeEnv(c.compose.env), renderComposeUp(), ...steps.slice(cut)];
    sets.push('dockerhub', ...c.compose.images);
  }
  sets.push(...installSets(steps, svc));
  const egress = egressStepFor(sets, { userSecret, dockerNetworks: compose, job: id });
  return job(dedupeJobSteps([egress, ...steps], { id, scans }));
}

/** image-build--<svc> (B6; G2 carry: the default docker driver, no setup-buildx, so the image reaches the local store for `docker image save`). */
function imageBuildJob(c: Ctx, spec: StepSpec): Job {
  const service = spec.service as string;
  const id = imageBuildJobId(service);
  const buildPush = c.deps.platform['build-push'];
  if (buildPush?.id !== PLATFORM_ACTION_IDS['build-push'] || buildPush.candidate.id !== spec.tool.id) return fail(`The image build of ${show(service)} is not the reviewed build-push step.`);
  const built = renderImageBuild(spec, buildPush, c.deps.platform, { profile: c.draft.profile, blocking: true });
  const prelude = renderJobPrelude({}, c.deps.platform).steps;
  // the Dockerfile's own base images and package installs (live checklist: the build's network under Bullfrog)
  const egress = egressStepFor(['dockerhub', 'ghcr', ...packageSets([serviceNamed(c.draft, service)])], { userSecret: (spec.secrets ?? []).length > 0, dockerNetworks: true, job: id });
  const steps = dedupeJobSteps([egress, ...prelude, ...built.steps], { id, scans: NO_SCANS });
  return { 'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, permissions: { contents: 'read' }, 'cache-mode': 'none', outputs: built.outputs, steps };
}

/** A scan of the PR's own image, on its archive (B6): needs its image build, no checkout, the scrub and the upload of its result. */
function imageScanJob(c: Ctx, spec: StepSpec): Job {
  const service = spec.service as string;
  const id = jobIdFor(spec.needId, service);
  const t = toolOf(c, spec.tool.id);
  const r = renderImageArchiveScan(spec, t, c.deps.platform, { profile: c.draft.profile, blocking: blocks(c.draft, spec.needId, service) });
  const steps: RenderedStep[] = [...r.steps];
  const scans = new Map<string, ScanFact>();
  if (r.output !== null && isFindings(t)) {
    const fact = scanFactOf(r, t.id);
    if (fact === null) return fail(`The image scan ${where(spec)} has no scan step.`);
    const artifact = resultArtifactName(spec.needId, service);
    steps.push(renderScrub(artifact, r.output.path, t.id, r.output.format as 'sarif' | 'zap-json', c.gate), renderUpload(artifact, scrubbedPath(r.output.path), c.deps.platform));
    scans.set(fact.stepId, fact.fact);
  }
  const egress = egressStepFor(egressSetsForTool(t), { userSecret: (spec.secrets ?? []).length > 0, dockerNetworks: false, job: id });
  return job(dedupeJobSteps([egress, ...steps], { id, scans }), { needs: [imageBuildJobId(service)] });
}

/** G4-R1: the two jobs of a DAST check: the key-free run job (the app in containers, the scan, the raw hand-off) and the gate's scrub job. */
function dastJobs(c: Ctx, spec: StepSpec, start: DastStart, blocking: boolean = blocks(c.draft, spec.needId, spec.service)): { run: Job; scrub: Job } {
  const service = spec.service as string;
  const t = toolOf(c, spec.tool.id);
  const runId = dastRunJobId(service, dastLaneOf(spec.needId));
  const checkout = start.kind === 'compose' ? renderJobPrelude({}, c.deps.platform).steps : [];
  const r = renderDastRun(spec, t, c.deps.platform, c.draft, start, { blocking, checkout });
  // the containers and the scanner's own hosts; the app's container is reached over the Docker networks (published on 127.0.0.1)
  const sets: EgressSet[] = [...egressSetsForTool(t), 'dockerhub', ...(start.kind === 'compose' && c.compose !== null ? c.compose.images : [])];
  const runEgress = egressStepFor(sets, { userSecret: false, dockerNetworks: true, job: runId });
  const run = job(dedupeJobSteps([runEgress, ...r.steps], { id: runId, scans: NO_SCANS }), r.needs.length > 0 ? { needs: r.needs } : {});
  const sc = renderDastScrub(spec, t, c.deps.platform, c.draft, c.gate, start.url);
  const id = jobIdFor(spec.needId, service);
  const scrubEgress = egressStepFor([], { userSecret: false, dockerNetworks: false, job: id });
  const scrub = job(dedupeJobSteps([scrubEgress, ...sc.steps], { id, scans: new Map([[sc.scan.stepId, sc.scan.fact]]) }), { needs: [runId] });
  return { run, scrub };
}

/**
 * base-scan (plan "Base scan", G1, G17, G21, G32): the base checkout, then the base twin of every findings check of the merge layer that runs
 * in a job of its own (not the image archive scans, which have no twin yet). Dependency and licence scans always; the others only when
 * baseline-check reports no trusted baseline: their install and run steps carry BASELINE_MISSING_IF, their scrub and upload the always() form.
 */
function baseScanJob(c: Ctx, specs: readonly StepSpec[]): Job {
  const always: RenderedStep[] = [];
  const later: RenderedStep[] = [];
  const scans = new Map<string, ScanFact>();
  const sets: EgressSet[] = [];
  let fullHistory = false;
  for (const spec of specs) {
    const t = toolOf(c, spec.tool.id);
    const b = renderFindingsBlock(spec, t, c.deps.platform, { profile: c.draft.profile, base: true, blocking: blocks(c.draft, spec.needId, spec.service) }, c.gate);
    scans.set(b.scan.stepId, b.scan.fact);
    sets.push(...egressSetsForTool(t));
    if (b.result.fullHistory === true) fullHistory = true;
    if (BASE_ALWAYS_CATEGORIES.has(categoryOf(spec.needId) ?? '')) { always.push(...b.steps); continue; }
    // the shared pipegen- steps (setup) stay unconditional: every base scan of the job may need them
    later.push(...b.steps.map((s) => (s.id?.startsWith('pipegen-') === true ? s
      : { ...s, if: isScrubStep(s) || s.uses?.startsWith(`${c.deps.platform['upload-artifact'].step.action?.uses ?? '\0'}`) === true ? BASELINE_MISSING_ALWAYS_IF : BASELINE_MISSING_IF })));
  }
  const prelude = renderJobPrelude({ baseRef: true, ...(fullHistory ? { fetchDepth: '0' as const } : {}) }, c.deps.platform).steps;
  const body = [...prelude, ...always, ...later];
  const egress = egressStepFor([...sets, ...installSets(body, undefined)], { userSecret: false, dockerNetworks: false, job: 'base-scan' });
  return job(dedupeJobSteps([egress, ...body], { id: 'base-scan', scans }), { needs: [BASELINE_CHECK_JOB], permissions: { contents: 'read', actions: 'read' } });
}

/** The isolated starter-test job of one service (D7-iso, rendered while ISOLATED_TEST_JOB is off): no secret, a read-only token, egress blocked but for the install, nothing handed on. */
export function starterTestJob(svc: Service, deps: Pick<JobsDeps, 'reviewed' | 'platform' | 'baseImages'>): { id: string; job: Job } {
  const byId = new Map(deps.reviewed.map((t) => [t.id, t]));
  const vitest = toolOf({ byId }, 'vitest-coverage');
  let id: string;
  try { id = `${STARTER_TEST_JOB}--${slug(svc.name)}`; } catch (e) { if (e instanceof ArtifactNameError) return fail(`The service ${show(svc.name)} has no letters or digits in its name.`); throw e; }
  if (svc.language !== 'node' || svc.packageManager !== 'npm') return fail(`The starter tests of ${show(svc.name)} run only for an npm service.`);
  const list = deps.baseImages ?? loadBaseImages();
  const prelude = renderJobPrelude({ node: { runtimeVersion: svc.runtimeVersion } }, deps.platform).steps;
  // the Node major from the setup-node step itself (its action), wherever it stands in the prelude
  const major = prelude.find((s) => s.uses?.startsWith(`${PLATFORM_USES['setup-node']}@`) === true)?.with?.['node-version'];
  if (major === undefined) return fail('The Node setup step has no node-version.');
  const image = baseImageRef(nodeBaseImageId(svc.runtimeVersion, list).id, list);
  const run = renderStarterTestRun(svc, { vitest, image, nodeMajor: major, artifact: resultArtifactName('starter-tests', svc.name) });
  // the registry during the install, the base image's registry for the pull; the tests themselves run in a container with no network
  const egress = egressStepFor([...egressSetsForTool(vitest), 'npm', imageSet(image)], { userSecret: false, dockerNetworks: false, job: id });
  return { id, job: { 'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, permissions: { contents: 'read' }, 'cache-mode': 'none', steps: [egress, ...prelude, ...run] } };
}

// ---------- assemble ----------

/** Which part of the plan a need key is, for one layer's jobs: a check job, an image build, an image scan, or nothing (handled elsewhere). */
type Role = 'check' | 'image-build' | 'image-scan' | 'dast' | 'none';
function roleOf(c: Ctx, need: Need, specs: readonly StepSpec[]): Role {
  const category = categoryOf(need.id) ?? need.category;
  if (PIPEGEN_JOB_CATEGORIES.has(category) || category === 'egress' || category === 'update-config' || SCHEDULED_CATEGORIES.has(category as NeedCategory)) return 'none';
  if (need.id === IMAGE_BUILD_NEED && specs.some((s) => s.tool.id === PLATFORM_ACTION_IDS['build-push'])) return 'image-build';
  if (specs.some((s) => ARCHIVE_TOOL_IDS.has(s.tool.id))) return 'image-scan';
  if (category === 'dast' && specs.length > 0) return 'dast';
  return 'check';
}

/**
 * The jobs of every layer for a draft built from the debate's result (see the file header). Throws AssembleError for what it refuses, and lets a
 * RenderError of a blocking check through as an AssembleError with its reason.
 */
export function assembleJobs(input: PipelineDraft, plan: JobsPlan, deps: JobsDeps): AssembledJobs {
  const notes: string[] = [];
  const byId = new Map(deps.reviewed.map((t) => [t.id, t]));
  const gate = toolOf({ byId }, 'pipegen-gate');
  // 1. refusals that need no render
  const floor = [...new Set(input.notProven.flatMap((n) => (typeof n.needId === 'string' && isFloor(n.needId) ? [n.needId] : [])))];
  if (floor.length > 0) fail(`The draft marks the floor check ${floor.map(show).join(', ')} as not proven, but a floor check is always required; pipegen does not assemble it.`);
  if (!isDeepStrictEqual(input.needs, plan.needs)) fail('The draft\'s needs are not the debate\'s needs, so its steps can not be checked against what was offered.');
  if (input.created.some((f) => f.part === 'tests') && !ISOLATED_TEST_JOB) fail('The draft holds starter tests, but the isolated starter-test job is switched off until its live acceptance (ruling D7-R7), so no starter test runs.');
  // GJ: the plan builds no image for these services (skippedChecks), so no image, DAST or API DAST check may be planned for them
  const noImage = noImageServices(input.profile, input.capabilities);
  for (const n of input.needs) {
    if (n.service === undefined || !NO_IMAGE_CATEGORIES.has(categoryOf(n.id) ?? n.category) || !noImage.has(n.service)) continue;
    fail(`The draft plans the check ${where(n)}, but pipegen builds no image for that service (${noImage.get(n.service) as string}), so it has nothing to build, scan or start; pipegen never writes that job.`);
  }
  // GJ (DECISIONS #122): workflow lint is zizmor alone; without it on the reviewed list the check is a suggestion only
  const lintSuggestion = !workflowLintAvailable(deps.reviewed);   // the predicate keyOffers uses too (review spec M4)
  const uncoveredMinimum = new Map<string, UncoveredMinimum>();
  const minKey = (n: { id: string; service?: string }): string => `${n.id}\u0000${n.service ?? ''}`;
  const isMinimum = (n: Pick<Need, 'id' | 'category' | 'layer'>): boolean => n.layer === 'merge' && (MINIMUM_CATEGORIES as readonly string[]).includes(categoryOf(n.id) ?? n.category);
  const markUncovered = (n: Need, why: string, tool?: { name: string; repo: string }): void => {
    if (!isMinimum(n) || uncoveredMinimum.has(minKey(n))) return;
    uncoveredMinimum.set(minKey(n), { category: categoryOf(n.id) ?? n.category, needId: n.id, ...(n.service === undefined ? {} : { service: n.service }), why, ...(tool === undefined ? {} : { tool }) });
  };
  const isLint = (n: Pick<Need, 'id' | 'category'>): boolean => (categoryOf(n.id) ?? n.category) === 'workflow-lint';
  // GJ (DECISIONS #122): a pre-commit or husky repository's hooks-ci is a note only (no reviewed runner for those hooks)
  const hooksNote = input.profile.precommit !== null && NO_HOOKS_CI_MANAGERS.has(input.profile.precommit) ? HOOKS_CI_NOTES[input.profile.precommit] : undefined;
  const isHooksCi = (n: Pick<Need, 'id' | 'category'>): boolean => (categoryOf(n.id) ?? n.category) === 'hooks-ci';
  const skipped = (n: Need): SkippablePart | undefined => input.skipped.map((s) => s.part).find((part) => skippedByPart(part, n));
  const limitOf = (n: Pick<Need, 'id' | 'category'>): string | undefined => {
    const cat = (categoryOf(n.id) ?? n.category) as NeedCategory;
    return Object.hasOwn(NOT_RENDERED_V02, cat) ? NOT_RENDERED_V02[cat] : undefined;
  };
  const stop: string[] = [];
  for (const u of plan.uncovered) {
    if (!u.blocking) continue;
    const n = input.needs.filter((x) => keyOf(x) === u.key);
    if (n.length > 0 && n.every((x) => skipped(x) !== undefined)) continue;
    // G16 F2: a skipped part's need is never an uncovered blocking need, even when the draft's needs no longer hold it (--skip tests)
    if (n.length === 0 && input.skipped.some((s) => skippedByPart(s.part, { id: u.needId, layer: 'merge', category: categoryOf(u.needId) ?? u.needId }))) continue;
    if (lintSuggestion && isLint({ id: u.needId, category: categoryOf(u.needId) ?? u.needId })) { addNote(notes, WORKFLOW_LINT_SUGGESTION); continue; }
    if (hooksNote !== undefined && isHooksCi({ id: u.needId, category: categoryOf(u.needId) ?? u.needId })) { addNote(notes, hooksNote); continue; }
    const limit = limitOf({ id: u.needId, category: categoryOf(u.needId) ?? u.needId });
    if (limit !== undefined) { addNote(notes, limit); continue; }
    // G4b: a repo built-in that can not run says why in its own plain words (fixed text, repoToolProblem)
    const svc = serviceNamed(input, u.service);
    const why = u.reason === 'no-repo-tool' && svc !== undefined ? repoToolProblem({ id: u.needId, ...(u.service === undefined ? {} : { service: u.service }) }, svc) : null;
    stop.push(`${where(u)}: ${why ?? UNCOVERED_REASON[u.reason] ?? 'no reviewed tool covers it'}`);
  }
  if (stop.length > 0) fail(`pipegen stopped before writing the pipeline: these blocking checks have no tool it can run (${stop.join('; ')}). It never guesses a tool.`);
  input = withLintSteps(input, plan, deps.reviewed);
  checkSteps(input, plan, deps.reviewed);
  // GJ-R1 (reviews spec I2, sec M2): a risky trigger with poutine not offered: zizmor runs alone, and the note says poutine is not run
  if (riskyTriggersOf(input.profile).length > 0 && input.needs.some(isLint) && !lintSuggestion && !input.steps.some((st) => isLint({ id: st.needId, category: categoryOf(st.needId) ?? st.needId }) && st.tool.id === WORKFLOW_LINT_EXTRA)) addNote(notes, POUTINE_NOT_RUN);

  // 2. the draft as assembled: no skipped part, no v0.2 limit
  const dropped = new Set<Need>();
  for (const n of input.needs) {
    const part = skipped(n);
    if (part !== undefined) { dropped.add(n); continue; }
    const limit = limitOf(n);
    if (limit !== undefined && n.layer !== 'pre-commit') { dropped.add(n); addNote(notes, limit); }
    if (lintSuggestion && isLint(n)) { dropped.add(n); addNote(notes, WORKFLOW_LINT_SUGGESTION); markUncovered(n, WORKFLOW_LINT_SUGGESTION, { name: WORKFLOW_LINT_TOOL, repo: 'zizmorcore/zizmor' }); }
    if (hooksNote !== undefined && isHooksCi(n)) { dropped.add(n); addNote(notes, hooksNote); }
  }
  for (const p of input.skipped) addNote(notes, `The part ${show(p.part)} is skipped (--skip), so it has no job.`);
  let draft = narrowed(input, dropped);
  const composeFile = draft.created.find((f) => f.repo === 'app' && f.path === COMPOSE_PATH);
  const list = deps.baseImages ?? loadBaseImages();
  let compose: Ctx['compose'] = null;
  if (composeFile !== undefined) {
    const cp = planCompose(draft.profile, list, dockerfilesOf(draft.created));
    if (cp.text !== null && cp.text === composeFile.content) compose = { env: cp.env, images: list.map((b) => imageSet(`${b.image}:${b.tag}@${b.digest}`)) };
    else addNote(notes, 'The draft\'s docker-compose.pipegen.yml is not the file pipegen computes, so no job starts it.');
  }
  // the PyPI publish step (S31) and the scans of an image no job builds, and osv without a lockfile (G12), are left out before the render
  const leaveOut = new Set<StepSpec>();
  for (const s of draft.steps) {
    if (s.tool.id === PYPI_PUBLISH_ID) { leaveOut.add(s); addNote(notes, PYPI_PUBLISH_NOTE); }
    if (s.tool.id === 'osv-scanner' && !hasLockfile(draft, s.service)) { leaveOut.add(s); addNote(notes, `${s.service === undefined ? 'The repository' : `The service ${show(s.service)}`} has no lockfile, so osv-scanner has nothing to read (it would fail); its ${show(s.needId)} check is not run.`); }
  }
  const c: Ctx = { draft, deps, byId, gate, notes, compose };
  const builds = new Map<string, Job>();
  for (const s of draft.steps) {
    if (leaveOut.has(s) || s.needId !== IMAGE_BUILD_NEED || s.tool.id !== PLATFORM_ACTION_IDS['build-push'] || s.service === undefined) continue;
    if (!draft.needs.some((n) => n.layer === 'merge' && n.id === IMAGE_BUILD_NEED && n.service === s.service)) continue;
    try { builds.set(s.service, imageBuildJob(c, s)); } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
      addNote(notes, `The image of ${show(s.service)} is not built or scanned yet: ${safeText(e.message, 200)}`);
      leaveOut.add(s);
    }
  }
  for (const s of draft.steps) if (ARCHIVE_TOOL_IDS.has(s.tool.id) && (s.service === undefined || !builds.has(s.service))) leaveOut.add(s);
  // the needs whose every step was left out go too (a findings check with nothing readable is no check of the gate's list)
  const keep = draft.steps.filter((s) => !leaveOut.has(s));
  const gone = new Set<Need>();
  for (const n of draft.needs) {
    const had = draft.steps.some((s) => s.needId === n.id && s.service === n.service);
    const has = keep.some((s) => s.needId === n.id && s.service === n.service);
    if (had && !has) {
      gone.add(n);
      const left = draft.steps.find((s) => s.needId === n.id && s.service === n.service && leaveOut.has(s));
      const tool = left === undefined ? undefined : { name: left.tool.id, repo: left.tool.repo };
      const lock = left?.tool.id === 'osv-scanner' && !hasLockfile(draft, n.service) ? ' (no lockfile to read: commit one to turn the check on)' : '';
      markUncovered(n, `The check ${where(n)} has no job: its tool ${show(left?.tool.id ?? 'none')} can not run here${lock}, so it is not covered.`, tool);
    }
  }
  draft = narrowed({ ...draft, steps: keep }, gone);
  c.draft = draft;
  // G4-R1: where each DAST check's app starts (containers only); a blocking one that can not start stops, a non-blocking one leaves with a note
  const starts = new Map<StepSpec, DastStart>();
  const noStart = new Set<Need>();
  for (const s of draft.steps) {
    if (categoryOf(s.needId) !== 'dast' || s.service === undefined || !draft.needs.some((n) => n.layer === 'merge' && n.id === s.needId && n.service === s.service)) continue;
    const st = dastStartOf(draft, s.service, list);
    if (!('problem' in st)) { starts.set(s, st); continue; }
    // GJ-R3 (O3): an unsure type is a server by rule; the user may say it is a static site
    const unsure = draft.profile.services.find((x) => x.name === s.service)?.projectType?.unsure === true;
    const tip = unsure ? ` Its type is unsure, so pipegen treats it as a server; if it is a static site, run with --type ${safeText(s.service, 60)}=static-site.` : '';
    if (blocks(draft, s.needId, s.service)) fail(`The blocking check ${where(s)} can not run: ${st.problem}. pipegen never makes it warn-only or leaves it out.${tip}`);
    addNote(notes, `The non-blocking check ${where(s)} is not run: ${st.problem}.`);
    for (const n of draft.needs) if (n.id === s.needId && n.service === s.service) noStart.add(n);
  }
  if (noStart.size > 0) { draft = narrowed(draft, noStart); c.draft = draft; }

  // 3. the layers
  const push: Record<string, Job> = {};
  const merge: Record<string, Job> = {};
  const specsOf = (n: Need): StepSpec[] => draft.steps.filter((s) => s.needId === n.id && s.service === n.service);
  const add = (into: Record<string, Job>, n: Need): void => {
    const specs = specsOf(n);
    const role = roleOf(c, n, specs);
    if (role === 'none') return;
    const id = role === 'image-build' ? imageBuildJobId(n.service as string) : jobIdFor(n.id, n.service);
    if (Object.hasOwn(into, id)) return;
    if (role === 'image-build') { const b = builds.get(n.service as string); if (b !== undefined) into[id] = b; return; }
    if (role === 'dast') {
      if (n.layer !== 'merge') return;
      const spec = specs.find((s) => starts.has(s));
      if (spec === undefined) return;
      const jobs = dastJobs(c, spec, starts.get(spec) as DastStart);
      into[dastRunJobId(n.service as string)] = jobs.run;
      into[id] = jobs.scrub;
      return;
    }
    if (role === 'image-scan') {
      if (n.layer !== 'merge') return;
      into[id] = imageScanJob(c, specs.find((s) => ARCHIVE_TOOL_IDS.has(s.tool.id)) as StepSpec);
      return;
    }
    if (specs.length === 0 && !n.blocking) {
      const svc = serviceNamed(draft, n.service);
      if (svc === undefined || (projectScriptFor(n, svc) === null && repoToolFor(n, svc) === null)) return;   // a non-blocking check nothing runs: no job (the gate does not list it)
    }
    const range = n.layer === 'merge' && n.id === 'secrets' && n.service === undefined && specs.some((s) => isFindings(toolOf(c, s.tool.id)));
    try { into[id] = checkJob(c, n, specs, range); } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError || e instanceof GateJobListError)) throw e;
      if (blocks(draft, n.id, n.service)) fail(`The blocking check ${where(n)} can not be written: ${safeText(e.message, 300)}`);
      addNote(notes, `The non-blocking check ${where(n)} is not run: ${safeText(e.message, 200)}`);
    }
  };
  for (const n of draft.needs) if (n.layer === 'push') add(push, n);
  for (const n of draft.needs) if (n.layer === 'merge') add(merge, n);
  // a non-blocking check that could not be written leaves the draft too, so the gate does not read a result nobody makes
  const unwritten = new Set(draft.needs.filter((n) => n.layer === 'merge' && roleOf(c, n, specsOf(n)) === 'check' && specsOf(n).length > 0 && !Object.hasOwn(merge, jobIdFor(n.id, n.service))));
  if (unwritten.size > 0) { draft = narrowed(draft, unwritten); c.draft = draft; }

  // the secrets scan is always there (the floor, never skippable)
  if (!Object.hasOwn(merge, jobIdFor('secrets'))) fail('The draft has no repository-wide secrets scan in the merge layer; it is always part of the pipeline.');
  const baseSpecs = draft.steps.filter((s) => draft.needs.some((n) => n.layer === 'merge' && n.id === s.needId && n.service === s.service) && !ARCHIVE_TOOL_IDS.has(s.tool.id) && categoryOf(s.needId) !== 'dast' && s.tool.id !== PLATFORM_ACTION_IDS['build-push'] && isFindings(toolOf(c, s.tool.id)) && toolOf(c, s.tool.id).candidate.kind !== 'action');
  merge[BASELINE_CHECK_JOB] = job([egressStepFor([], { userSecret: false, dockerNetworks: false, job: BASELINE_CHECK_JOB }), renderBaselineCheckStep(gate)], { permissions: { contents: 'read', actions: 'read' } });
  merge['base-scan'] = baseScanJob(c, baseSpecs);
  let listJobs: string[];
  try { listJobs = gateJobList(draft).map((e) => e.job); } catch (e) { if (e instanceof GateJobListError) return fail(e.message); throw e; }
  const missing = [...new Set(listJobs)].filter((j) => !Object.hasOwn(merge, j));
  if (missing.length > 0) fail(`The gate would wait for jobs that are not written (${missing.map(show).join(', ')}).`);
  let gateStep: RenderedStep;
  try { gateStep = renderGateStep(gate, draft); } catch (e) { if (e instanceof RenderError) return fail(e.message); throw e; }
  merge.gate = {
    name: GATE_JOB_NAME, 'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, needs: [...new Set([...listJobs, 'base-scan'])], if: 'always()',
    permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' }, 'cache-mode': 'none',
    steps: [egressStepFor([], { userSecret: false, dockerNetworks: false, job: 'gate' }), gateStep, ...renderGateUploads(deps.platform)],
  };
  const nightly: Record<string, Job> = {
    nightly: {
      'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, permissions: { contents: 'read', actions: 'read', issues: 'write' }, concurrency: NIGHTLY_CONCURRENCY, 'cache-mode': 'none',
      steps: [egressStepFor([], { userSecret: false, dockerNetworks: false, job: 'nightly' }), renderNightlyStep(gate, draft)],
    },
  };

  // G15a round 3 (PF-3): Scorecard weekly, reported and never gated (a scheduled category: never on the gate's list). Its image runs as a
  // docker step by the reviewed digest, with the job's read token and no secret; the scrubbed result goes to code scanning from its own job
  // (security-events: write is never in the job that runs the image)
  for (const n of draft.needs.filter((x) => x.layer === 'merge' && (categoryOf(x.id) ?? x.category) === 'scorecard')) {
    const spec = specsOf(n).find((s) => toolOf(c, s.tool.id).id === 'scorecard-action');
    if (spec === undefined) continue;
    try {
      const tool = toolOf(c, spec.tool.id);
      const steps = renderScorecardBlock(tool, deps.platform, gate);
      nightly[SCORECARD_JOB] = {
        'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, if: SCORECARD_IF, permissions: { contents: 'read', actions: 'read' }, 'cache-mode': 'none',
        steps: [egressStepFor(egressSetsForTool(tool), { userSecret: false, dockerNetworks: false, job: SCORECARD_JOB }), ...steps],
      };
      const scrubbed = `\${{ runner.temp }}/pipegen-out/${SCORECARD_ARTIFACT}`;
      nightly[CODE_SCANNING_JOB] = {
        'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, needs: [SCORECARD_JOB], permissions: { contents: 'read', 'security-events': 'write', actions: 'read' }, 'cache-mode': 'none',
        steps: [
          egressStepFor([], { userSecret: false, dockerNetworks: false, job: CODE_SCANNING_JOB }),
          { ...renderPlatformStep('download-artifact', deps.platform, { name: SCORECARD_ARTIFACT, path: scrubbed }), name: 'Download the scrubbed Scorecard result' },
          { ...renderPlatformStep('upload-sarif', deps.platform, { sarif_file: `${scrubbed}/scorecard.sarif`, category: SCORECARD_CATEGORY }), name: 'Upload the Scorecard result to code scanning' },
        ],
      };
    } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
      addNote(notes, `OpenSSF Scorecard is not run: ${safeText(e.message, 200)}`);
    }
  }

  // G15a round 4 (b1, P-4): betterleaks over the whole history, nightly, when the merge layer scans the repository for secrets. Reported
  // through code scanning from its own upload job, never gated; with no code scanning nothing would report it, so it is not written
  const repoSecrets = draft.needs.some((n) => n.layer === 'merge' && n.id === 'secrets' && n.service === undefined && specsOf(n).some((s) => isFindings(toolOf(c, s.tool.id))));
  if (repoSecrets && !codeSecurityAvailable(draft.profile, draft.capabilities)) {
    addNote(notes, 'The nightly scan of the whole history for secrets is not run: it reports through code scanning, which this repository does not have.');
  } else if (repoSecrets) {
    try {
      const tool = toolOf(c, RANGE_TOOL);
      const b = renderHistoryBlock(tool, deps.platform, gate);
      const prelude = renderJobPrelude({ fetchDepth: '0' }, deps.platform).steps;
      nightly[SECRETS_HISTORY_JOB] = job(dedupeJobSteps([egressStepFor(egressSetsForTool(tool), { userSecret: false, dockerNetworks: false, job: SECRETS_HISTORY_JOB }), ...prelude, ...b.steps], { id: SECRETS_HISTORY_JOB, scans: new Map([[b.scan.stepId, b.scan.fact]]) }));
      const scrubbed = `\${{ runner.temp }}/pipegen-out/${b.artifact}`;
      const file = (b.result.output as { path: string }).path.split('/').pop() as string;
      nightly[HISTORY_UPLOAD_JOB] = {
        'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, needs: [SECRETS_HISTORY_JOB], permissions: { contents: 'read', 'security-events': 'write', actions: 'read' }, 'cache-mode': 'none',
        steps: [
          egressStepFor([], { userSecret: false, dockerNetworks: false, job: HISTORY_UPLOAD_JOB }),
          { ...renderPlatformStep('download-artifact', deps.platform, { name: b.artifact, path: scrubbed }), name: 'Download the scrubbed full-history secrets result' },
          { ...renderPlatformStep('upload-sarif', deps.platform, { sarif_file: `${scrubbed}/${file}`, category: SECRETS_HISTORY_CATEGORY }), name: 'Upload the full-history secrets result to code scanning' },
        ],
      };
    } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
      addNote(notes, `The nightly scan of the whole history for secrets is not run: ${safeText(e.message, 200)}`);
    }
  }

  // G15a round 5 (b2, P-4): zizmor online, nightly, when the merge layer lints the workflows with zizmor (offline there). The same reviewed entry
  // under its online policy (no --offline, the host named) with the job's read token as GH_TOKEN; contents: read; a job-status check, never gated
  const lintsWithZizmor = draft.needs.some((n) => n.layer === 'merge' && isLint(n) && specsOf(n).some((s) => s.tool.id === WORKFLOW_LINT_TOOL));
  if (lintsWithZizmor) {
    try {
      const tool = toolOf(c, WORKFLOW_LINT_TOOL);
      const r = renderZizmorOnline(tool, deps.platform, { profile: draft.profile });
      const prelude = renderJobPrelude({}, deps.platform).steps;
      nightly[ZIZMOR_ONLINE_JOB] = job(dedupeJobSteps([egressStepFor(egressSetsForTool(tool), { userSecret: false, dockerNetworks: false, job: ZIZMOR_ONLINE_JOB }), ...prelude, ...r.steps], { id: ZIZMOR_ONLINE_JOB, scans: NO_SCANS }));
    } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
      addNote(notes, `zizmor's online checks are not run nightly: ${safeText(e.message, 200)}`);
    }
  }

  // G15a round 4 (b3, P-4): the nightly DAST scan. For each app the merge layer scans (a merge DAST check with a container start), nuclei with
  // its pinned templates in the same key-free run job and scrub job, then code-scanning-dast uploads every scrubbed result. Reported, never
  // gated (rendered as blocking, so no narrowing value). No code scanning: not written. Round 6: the ZAP AF active scan beside it, in its own
  // pair (zap-active-run--<svc>, zap-active--<svc>); when it can not be written, nuclei still runs and a note says so
  const nightlyDast = [...starts].filter(([s]) => draft.steps.includes(s) && draft.needs.some((n) => n.layer === 'merge' && n.id === s.needId && n.service === s.service));
  if (nightlyDast.length > 0 && !codeSecurityAvailable(draft.profile, draft.capabilities)) {
    addNote(notes, 'The nightly DAST scan is not run: it reports through code scanning, which this repository does not have.');
  } else if (nightlyDast.length > 0) {
    try {
      const nuclei = toolOf(c, NIGHTLY_DAST_TOOL);
      const af = c.byId.get(ZAP_ACTIVE_TOOL);
      let afProblem: string | null = af === undefined || !isReviewed(af.candidate) ? 'the reviewed list has no reviewed ZAP AF entry.' : null;
      // one lane's pair for a service: its jobs (with the archive start's image build), its scrub job id, the download and upload of its result
      type Part = { lane: DastLane; jobs: Record<string, Job>; scrubId: string; uploads: RenderedStep[] };
      const partOf = (ns: StepSpec, start: DastStart, label: string): Part => {
        const service = ns.service as string;
        const lane = dastLaneOf(ns.needId);
        const pair = dastJobs(c, ns, start, true);
        const id = jobIdFor(ns.needId, service);
        const jobs: Record<string, Job> = {};
        // the archive start reads the image this run builds: the nightly file builds it too (the same image-build job, no push)
        for (const need of pair.run.needs ?? []) {
          const b = builds.get(service);
          if (need !== imageBuildJobId(service) || b === undefined) return fail(`The nightly DAST scan of ${show(service)} needs ${show(need)}, which the nightly file does not build.`);
          jobs[need] = b;
        }
        // the AF plan can run longer than the default job time (its run job only)
        jobs[dastRunJobId(service, lane)] = lane === ZAP_ACTIVE_LANE ? { ...pair.run, 'timeout-minutes': ZAP_ACTIVE_JOB_MINUTES } : pair.run;
        jobs[id] = pair.scrub;
        const artifact = dastResultArtifact(service, lane);
        const scrubbed = `\${{ runner.temp }}/pipegen-out/${artifact}`;
        const file = (ns.output.path.split('/').pop() as string);
        return { lane, jobs, scrubId: id, uploads: [
          { ...renderPlatformStep('download-artifact', deps.platform, { name: artifact, path: scrubbed }), name: `Download the scrubbed nightly ${label} result of ${slug(service)}` },
          { ...renderPlatformStep('upload-sarif', deps.platform, { sarif_file: `${scrubbed}/${file}`, category: dastNightlyCategory(service, lane) }), name: `Upload the nightly ${label} result of ${slug(service)} to code scanning` },
        ] };
      };
      const parts: Part[] = [];
      const done = new Set<string>();
      for (const [spec, start] of nightlyDast) {
        const service = spec.service as string;
        if (done.has(dastRunJobId(service))) continue;
        done.add(dastRunJobId(service));
        parts.push(partOf(nightlyDastSpec(spec, nuclei), start, 'DAST'));
        // round 6: the ZAP AF active scan of the same app, in its own lane; a refusal keeps nuclei and says why (the AF lane is all or nothing)
        if (af === undefined || afProblem !== null) continue;
        try {
          parts.push(partOf(zapActiveSpec(spec, af), start, 'ZAP active scan'));
        } catch (e) {
          if (!(e instanceof RenderError || e instanceof ArtifactNameError || e instanceof AssembleError)) throw e;
          afProblem = safeText(e.message, 200);
        }
      }
      const kept = parts.filter((x) => afProblem === null || x.lane !== ZAP_ACTIVE_LANE);
      if (afProblem !== null) addNote(notes, zapActiveNotRunNote(afProblem));
      const pairs: Record<string, Job> = Object.assign({}, ...kept.map((x) => x.jobs)) as Record<string, Job>;
      const uploads = kept.flatMap((x) => x.uploads);
      const scrubIds = kept.map((x) => x.scrubId);
      Object.assign(nightly, pairs);
      nightly[DAST_UPLOAD_JOB] = {
        'runs-on': JOB_RUNNER, 'timeout-minutes': JOB_MINUTES, needs: scrubIds, permissions: { contents: 'read', 'security-events': 'write', actions: 'read' }, 'cache-mode': 'none',
        steps: [egressStepFor([], { userSecret: false, dockerNetworks: false, job: DAST_UPLOAD_JOB }), ...uploads],
      };
    } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError || e instanceof AssembleError)) throw e;
      addNote(notes, `The nightly DAST scan is not run: ${safeText(e.message, 200)}`);
    }
  }

  // 4. signing: G3's job for the delivered mode, none for the proof or a skipped deploy. GJ: a signing or attestation need on a service that
  // builds no image is report-only (its image leaves the plan; with no service building an image there is nothing to sign at all)
  for (const n of draft.needs) {
    const cat = categoryOf(n.id) ?? n.category;
    if (n.layer === 'deploy' && (cat === 'signing' || cat === 'attestation') && n.service !== undefined && noImage.has(n.service)) addNote(notes, reportOnlyNote(n.service));
  }
  if (draft.signing !== undefined && draft.signing !== null && Array.isArray(draft.signing.images)) {
    // GJ-R1 (sec M3): by slug; an image of no profile service is refused, one of a no-image service is report-only
    const images = draft.signing.images.filter((i) => {
      const o = signedImageOwner(draft.profile, draft.capabilities, i?.service);
      if (!o.ok && !o.reportOnly) fail(`The signing plan signs the image of ${o.why}, so nothing builds it; pipegen never signs it.`);
      if (!o.ok) addNote(notes, reportOnlyNote(String(i.service)));
      return o.ok;
    });
    if (images.length !== draft.signing.images.length) {
      const { signing: _s, ...rest } = draft;
      draft = images.length > 0 ? { ...rest, signing: { ...draft.signing, images } } : rest;
    }
  }
  const imageNone = draft.profile.services.every((s) => noImage.has(s.name));
  let sign: SignJob | null = null;
  if (deps.mode !== 'none' && !input.skipped.some((p) => p.part === 'deploy') && !imageNone) {
    try { sign = signJob(draft, deps.mode, { reviewed: deps.reviewed, platform: deps.platform }); } catch (e) {
      if (!(e instanceof RenderError) || deps.mode !== 'attest') throw e;
      addNote(notes, `The images are not signed: the attest signing job could not be written (${safeText(e.message, 200)}), and pipegen never falls back to another mode.`);
    }
  }
  if (deps.mode === 'none' || input.skipped.some((p) => p.part === 'deploy') || imageNone) { const { signing: _s, ...rest } = draft; draft = rest; }
  // GJ-R1/R2 (reviews sec M4, spec M4, GJ-r1 N3): every minimum need of the plan (per need: id and service) is a written job or listed as
  // uncovered, never dropped silently; each uncovered one goes into the suggestions with its reason
  const kept = new Set(draft.needs.map(minKey));
  for (const n of input.needs) {
    if (!isMinimum(n)) continue;
    const written = (categoryOf(n.id) ?? n.category) === 'gate' ? Object.hasOwn(merge, 'gate') : kept.has(minKey(n)) && Object.hasOwn(merge, jobIdFor(n.id, n.service));
    if (!written && !uncoveredMinimum.has(minKey(n))) fail(`The minimum check ${where(n)} has no job and no reason pipegen can show; it never drops silently.`);
  }
  const suggestions = [...draft.suggestions];
  for (const u of uncoveredMinimum.values()) {
    if (u.tool === undefined || suggestions.some((sg) => sg.name === u.tool?.name && sg.why === u.why)) continue;
    suggestions.push({ name: u.tool.name, repo: u.tool.repo, why: u.why });
  }
  if (suggestions.length !== draft.suggestions.length) draft = { ...draft, suggestions };
  // G7 (carry G4→G7, ruling S31's pattern): the deploy layer's sbom and egress needs have no job of pipegen's in v0.2. pipegen never changes
  // the user's own deploy jobs, so their network is not locked (pipegen's image-publish and verify jobs start with the egress block; the
  // keyless and attest sign jobs have none, threat model T52: the per-run OIDC token host), and no reviewed job makes the published image's SBOM yet.
  // Neither is counted as covered: each leaves the draft with a plain note.
  const release = new Set(draft.needs.filter((n) => n.layer === 'deploy' && RELEASE_ONLY_NOTES.has(categoryOf(n.id) ?? n.category)));
  for (const n of release) addNote(notes, RELEASE_ONLY_NOTES.get(categoryOf(n.id) ?? n.category) as string);
  if (release.size > 0) draft = narrowed(draft, release);
  // G15a-R7 spec 2: no Monday double run. The nightly file has a second cron entry when Scorecard runs weekly; every nightly job but Scorecard and
  // the jobs that follow it (its code-scanning upload, through needs) runs only on the nightly entry
  for (const [id, j] of Object.entries(nightly)) {
    if (id === SCORECARD_JOB || (j.needs ?? []).includes(SCORECARD_JOB)) continue;
    if (j.if !== undefined) fail(`The nightly job ${show(id)} already has a condition, so it can not be limited to the nightly cron.`);
    nightly[id] = { ...j, if: NIGHTLY_IF };
  }
  return { draft, push, merge, nightly, sign, notes, uncoveredMinimum: [...uncoveredMinimum.values()] };
}

function addNote(notes: string[], line: string): void { if (!notes.includes(line)) notes.push(line); }

/**
 * GJ (DECISIONS #122): workflow lint's steps are code-chosen: for each workflow-lint need key, specFor of every tool keyOffers offers for it
 * (zizmor, plus poutine on a risky trigger: workflowLintTools), in place of the debate's pick, so neither runs without the other. A draft
 * whose workflow-lint step runs another tool is returned as it is (checkSteps refuses it with its own reason).
 */
function withLintSteps(draft: PipelineDraft, plan: JobsPlan, reviewed: readonly ReviewedTool[]): PipelineDraft {
  const isLintStep = (s: StepSpec): boolean => categoryOf(s?.needId) === 'workflow-lint';
  const tools = workflowLintTools(draft.profile);
  if (draft.steps.some((s) => isLintStep(s) && !tools.includes(s?.tool?.id))) return draft;
  let offers: ReturnType<typeof keyOffers>;
  try { offers = keyOffers(plan.needs, plan.candidates, draft.profile, { reviewed }); } catch (e) { if (e instanceof NeedKeyError) return draft; throw e; }
  const code = offers.refs.filter((r) => categoryOf(r.id) === 'workflow-lint').flatMap((r) => (offers.offers.get(r.key) ?? []).map((o) => specFor(r, o, draft.profile)));
  return { ...draft, steps: [...draft.steps.filter((s) => !isLintStep(s)), ...code] };
}

/** G7: the deploy-layer needs pipegen writes no job for in v0.2, each with its note (and PIPEGEN.md line, G9): never counted as covered. */
export const RELEASE_ONLY_NOTES: ReadonlyMap<string, string> = new Map([
  ['sbom', 'The SBOM of the published image is not made yet: no reviewed job of pipegen\'s builds it after the image is published (v0.2). The image checks of pull requests still run.'],
  ['egress', 'Your own deploy jobs keep their open network: pipegen never changes them (it only adds the pipegen-verify job they wait for). pipegen\'s own image publish and verify jobs run behind the network lock; a keyless or attest signing job does not, because it needs a per-run token host that can not be listed exactly (only pipegen\'s own steps run there).'],
]);

/** GJ: the note (and the PIPEGEN.md line, G9) of a signing or attestation need on a service that builds no image. */
const reportOnlyNote = (service: string): string => `The service ${show(service)} builds no image, so its signing is report-only: pipegen signs nothing for it (sign its deployed files with cosign sign-blob yourself if you need it).`;

/** The draft without these needs, and without the steps no remaining need runs (a step is per need key, every layer). */
function narrowed(draft: PipelineDraft, drop: ReadonlySet<Need>): PipelineDraft {
  if (drop.size === 0) return draft;
  const needs = draft.needs.filter((n) => !drop.has(n));
  const steps = draft.steps.filter((s) => needs.some((n) => n.id === s.needId && n.service === s.service));
  return { ...draft, needs, steps };
}

/** Whether osv-scanner has a lockfile to read: the service's own (or, repo-wide, any service's) package manager the reader found. */
function hasLockfile(draft: PipelineDraft, service: string | undefined): boolean {
  const svcs = service === undefined ? draft.profile.services : draft.profile.services.filter((s) => s.name === service);
  return svcs.some((s) => s.packageManager !== undefined || (s.alsoPackageManagers ?? []).length > 0);
}
