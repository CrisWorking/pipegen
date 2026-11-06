// The referee (Plan B Task 7 Part 2, sub-task 7a: the static checks). pipegen's last line of defence: it reads the
// finished files pipegen is about to propose and refuses anything unsafe. It PARSES, it does not trust: it judges the
// files themselves, never what the renderer meant to write, and treats every file as hostile (Plan G may also edit a
// user's own workflow). Every check fails closed.
// - Parsing (ruling S29): one YAML document, unique keys, no anchors, aliases, `<<` merge keys, tags or directives, so no
//   key can hide from the walkers below. Job-level `uses:` (reusable workflows) and step-level `uses:` are both walked.
// - Run-time slot values (an image digest, a local URL, a repo path) are checked by shape only (slots.ts `slotProblem`): the
//   referee can not know which image or URL is the right one, so Plan G binds the values it writes (final review minor 15).
// - Pins: every `uses:` is a reviewed entry (the platform actions, the draft's tools, pipegen's own gate and watcher), the
//   central `<owner>/pipelines/` repo at a 40-character SHA. A local `./` action is refused outright (fix round 2). The
//   comparison uses the whole `uses` path, sub-path included (S14). A tag or branch is `unpinned`; any other commit is `unknown-pin`.
// - Only reviewed tools, only as their template: an action step must carry exactly its entry's fixed inputs, its choices
//   inside their lists, and otherwise only RENDERER_INPUTS, each judged by its own checker and `whenWith` (S15). A run step
//   must BE a step the renderer makes for this draft (the draft's tools and the project scripts its needs call for): it is
//   recognised by content, never by its id. Anything else is `unreviewed` (or `template` when it reuses a rendered id).
// - Expressions: the renderer's own checkExpressions judges every step (one source of truth). Secrets (S9) only as
//   `${{ secrets.X }}` under the name X, X in the allowed set, and a declared app secret only on a step that runs the app.
// - Permissions (S17): `permissions: {}` at the top, and every job within JOB_PERMISSIONS by its exact id.
// - Caches: `cache-mode: none` on every job with steps; no actions/cache, no cache inputs; trivy only with its pinned
//   in-memory cache config (S3).
// - Order (S6 c): the renderer's own checkJobOrder runs over every parsed job; a run step not recognised by content counts
//   as repo code whatever its id says.
// - The gate's wiring (Plan C C0b): job `outputs` only in the forms of jobOutputsProblems (job-rules.ts); the gate step in mode gate only in
//   the job `gate`, with its `with` equal to gateStepInputs(draft) (the `job-list` literal = gateJobList(draft), every other input from the draft too;
//   final review fix round A) and `needs` covering every listed job (else `not-gate-readable`);
//   each scrub step equal to its scan step (tool, format, id; job-rules.ts scrubChainProblems); a checkout `ref` only in `base-scan`.
// - The gate's check name comes from GATE_CHECK_NAME; the blocking rule (B7) demotes a findings check whose tool writes no
//   SARIF; findSecretLike runs over every file (S18). The workflow linters (actionlint, zizmor) run through `deps.runLinters`
//   (default: linters.ts runLinters, 7b), which tests replace with a stub.
import { isDeepStrictEqual } from 'node:util';
import { isMap, isScalar, LineCounter, visit, type Document, type Node as YamlNode, type Pair } from 'yaml';
import { findSecretLike } from '../ai/redact.js';
import { activeSafeText as safeText, anyString, anyYamlScalar, scrubForDisplay, vaultHolds, withActiveVault } from '../util/known-values.js';
import { GATE_CHECK_NAME, type CreatedFile, type KnownValueCheck, type OutputFormat, type PipegenInserted, type PipelineDraft, type ReviewedTool, type RuntimeEnv, type Service, type StepSpec } from '../types.js';
import { ArtifactNameError, resultArtifactName, slug } from './artifact-names.js';
import { FINDINGS_CATEGORIES, gateJobList, GateJobListError, jobIdFor, PIPEGEN_JOB_CATEGORIES, readableFormat, type JobListEntry } from './gate-job-list.js';
import { GATE_JSON_INPUTS, gateStepInputs, NIGHTLY_JSON_INPUTS, nightlyStepInputs } from './gate-inputs.js';
import { runLinters } from './linters.js';
import { COMMIT_SHA_RE, parseImageRef } from './names.js';
import { NEED_ID_CATEGORY, toolCoversNeed } from './need-ids.js';
import { PLATFORM_ACTION_IDS, type PlatformActions } from './pin.js';
import { APP_RUNNING_CATEGORIES, renderRangeScan, TRIVY_LAUNCH_RE } from './render-cli.js';
import { EXPR, own, show } from './render-error.js';
import { isObj, parseYaml, uniq, type Obj, type Parsed } from './yaml-parse.js';
import { docRecomputeProblem } from '../deliver/docs.js';
import { createdFileProblems, duplicatePathProblems, type CreatedInputs, type CreatedRule } from './created-files.js';
import {
  ACTION_PATH_RE, CALLER_WORKFLOW, checkExpressions, createdPathProblem, checkJobOrder, defaultPushTrigger, DEPLOY_PUSH_IF, featurePushTrigger, gateResultUploadProblems, IF_VALUES,
  CALLER_TRIGGERS, IMAGE_ARCHIVE_STEP_ID, IMAGE_BUILD_NEED, imageBuildJobId, imageBuildSlugOf, imageCheckStepId, isDangerousName, isReviewed, isScrubStep, isStageStep, jobOutputsProblems, LOCAL_MERGE_WORKFLOW, narrowingChoiceProblem, NIGHTLY_CONCURRENCY, NIGHTLY_WORKFLOW, PR_CHECK_IF, PR_CHECK_JOB,
  PR_REVIEW_TRIGGER, PUSH_WORKFLOW, renderPrCheckStep, REQUIRED_JOB, REQUIRED_NAME, requiredWorkflowForm, renderRangeFetchStep, SECRET_REF_RE, SIGN_STEP_ID_RE, BASE_ALWAYS_CATEGORIES, BASELINE_CHECK_JOB, DAST_HANDOFF_STEP_ID, dastAppStepId, dastCheckStepId, dastRunJobId, dastRunSlugOf, DAST_CHECK_ID_RE, BASELINE_MISSING_ALWAYS_IF, BASELINE_MISSING_IF, BASELINE_STEP_IFS,
  STEP_KEYS as STEP_KEY_LIST, WORKFLOW_CONCURRENCY, WORKFLOW_PATH_RE, type RenderedStep, type ScanFact,
} from './job-rules.js';
import { signingMode } from '../github/signing-mode.js';
import { containerRefusal, RenderError, renderComposeUp, renderProjectScript, renderRepoTool, renderRuntimeEnv, renderStep, sameDedupeContent, type RenderContext } from './render-step.js';
import { COMPOSE_PATH, planCompose } from '../create/compose.js';
import { dockerfilesOf } from './created-judges/compose.js';
import { loadBaseImages } from './base-images.js';
import { centralWorkflowFile, centralWorkflowPath } from './central-path.js';
import { projectScriptFor, repoToolFor } from './reviewed.js';
import { slotProblem, type SlotKind } from './slots.js';
import { expectedSigningSteps, signedImageOwner } from './signing.js';
import { NO_IMAGE_CATEGORIES, noImageServices, publishedImageServices, WORKFLOW_LINT_TOOL } from './needs.js';
import { FIND_RUN_STEP_ID, renderDigestStep, renderHeadCheckStep, renderPublishDigestStep } from './deploy-steps.js';
import { ARCHIVE_TOOL_IDS, imageBuildTag, renderImageArchiveScan, renderImageBuild } from './image-handoff.js';
import { dastStartOf, renderDastRun, renderDastScrub } from './dast-handoff.js';
import { SHARED_CDN_SETS } from './egress.js';
import { EGRESS_DOMAIN_SETS } from './egress-sets.js';
import { allowedDomainsProblem, ARGV_POLICIES, BULLFROG_USES, CACHE_LOCKS, GATE_OPTIONAL_UPLOADS, PLAIN_REL_RE, PLATFORM_USES, RANGE_TOOL, RENDERER_INPUTS, rendererInputProblems, SCRUB_SECRET, uploadIfNoFiles } from './tool-flags.js';

// ---------- the report ----------

/** What a check found. `'quality-bar'` is gone (F10): no static rule produces it. */
export type RefereeCheck = 'unpinned' | 'unknown-pin' | 'unreviewed' | 'permissions' | 'injection' | 'not-gate-readable' | 'cache' | 'template' | 'actionlint' | 'zizmor' | 'secret-value';
/**
 * `line` (1-based) when the finding has one (the linters, 7b): in an edited user workflow it decides between an issue and a
 * note. `repo`: which repository's file it is (7b knows it, one temp copy per repo); a finding is matched to its file by repo
 * and path, and one that can not be matched to exactly one file stays an issue.
 */
export interface RefereeIssue { file: string; check: RefereeCheck; message: string; line?: number; repo?: CreatedFile['repo'] }
/**
 * `ok` = no issue. `demoted`: the needs whose blocking was turned off (B7), by need key (`<needId>`, or
 * `<needId>--<service slug>` for a per-service need, as in the result artifact name), each with a note. `notes`: what the
 * caller should tell the user but that blocks nothing (demotions, steps that could not be rendered, linter findings on
 * a user's own lines).
 */
export interface RefereeReport { ok: boolean; issues: RefereeIssue[]; demoted: string[]; notes: string[] }

/** The pinned linters, as re-verifying closures (ruling S20): each call checks the binary's hash again right before it runs. */
export interface Linters { actionlint: () => Promise<string>; zizmor: () => Promise<string> }
/** The linter run (7b's runLinters): actionlint and zizmor over the workflow files, findings as issues. */
export type RunLinters = (files: CreatedFile[], linters: Linters, ghToken: string | null) => Promise<RefereeIssue[]>;
/** The injectable parts. `runLinters` defaults to the real one (linters.ts); a throwing runner is an issue. */
export interface RefereeDeps { runLinters?: RunLinters; /** the created-file rules (default: CREATED_RULES); tests inject their own */ createdRules?: readonly CreatedRule[]; /** what delivery knows (D0b): the central CODEOWNERS path, PIPEGEN.md's shas, the vault check */ createdInputs?: CreatedInputs; /** the secret vault (D5): a value the user gave pipegen inside any file is an issue */ vault?: KnownValueCheck }

// ---------- the tables ----------

type Level = 'read' | 'write';
/**
 * The permissions a job may have beyond `contents: read`, by its EXACT job id (ruling S17). Every other job may have
 * `contents: read` only. Plan G names its jobs with these ids; a reusable-workflow caller may also have the union of the
 * called file's jobs (when that file is in `files`).
 */
export const JOB_PERMISSIONS: Readonly<Record<string, Readonly<Record<string, Level>>>> = Object.freeze({
  'pr-check': { 'pull-requests': 'read' },
  'pipegen-verify': { actions: 'read', packages: 'read', attestations: 'read' },
  'code-scanning': { 'security-events': 'write', actions: 'read' },
  gate: { actions: 'read', 'pull-requests': 'read' },
  'base-scan': { actions: 'read' },
  'baseline-check': { actions: 'read' },
  'image-publish': { packages: 'write' },
  sign: { 'id-token': 'write', packages: 'write', attestations: 'write' },
  nightly: { actions: 'read', issues: 'write' },
  watch: { issues: 'write', actions: 'read' },
  notify: { 'pull-requests': 'read', checks: 'read' },
  'merged-red': { 'pull-requests': 'read', checks: 'read' },
});
/** The environment `pipegen-verify` runs in when the plan has environments (design §19): only default-branch deploys pass. */
export const SIGNING_ENVIRONMENT = 'pipegen-signing';
/** pipegen's own secrets (gate fingerprint key, cosign key, Slack webhook) and the workflow token: allowed besides the draft's declared ones (S9). */
export const PIPEGEN_SECRETS: readonly string[] = ['PIPEGEN_FP_KEY', 'PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD', 'PIPEGEN_SLACK_WEBHOOK', 'GITHUB_TOKEN'];
/** G2 (B3 b): the cosign key and its password (the signing environment's secrets) reach only a sign step, recognised by content (signing.ts). */
const SIGNING_KEY_SECRETS: ReadonlySet<string> = new Set(['PIPEGEN_COSIGN_KEY', 'PIPEGEN_COSIGN_PASSWORD']);
/** Ruling B7: the checks the gate judges by their findings; their tool must write SARIF (DAST: ZAP's JSON too). Every other category is judged by job status. */
export { FINDINGS_CATEGORIES };   // defined in gate-job-list.ts (the job list needs the same set)

/**
 * What a step is, recognised by its content (the reviewed entry its `uses` and template match, or the rendered step its
 * run text equals), never by its id alone. `repo-code`: a step that runs or loads the repository's code (tests, project
 * scripts, the repo's npm ci); `central`: an action from the central pipelines repo; `unrecognised`: anything else.
 */
export type StepKind = 'checkout' | 'setup' | 'harden' | 'upload-artifact' | 'download-artifact' | 'upload-sarif' | 'attest' | 'docker-login' | 'setup-buildx' | 'build-push'
  | 'gate' | 'watcher' | 'tool' | 'scrub' | 'stage' | 'central' | 'repo-code' | 'unrecognised'
  /** G1 (BP-6): the pr-check lookup step, recognised by its exact content (renderPrCheckStep); only in the job pr-check */
  | 'pr-check'
  /**
   * G2 (B3 b, d; B6): the cosign install and sign steps (job sign only), the cosign or gh install and verify steps (job pipegen-verify only),
   * the image archive step (its own image-build--<service> job only) and the archive's hash check of a scanner job, each recognised by its
   * exact content (signing.ts, image-handoff.ts) for this draft
   */
  | 'sign' | 'verify' | 'image-archive' | 'image-check'
  /** G7 (B3 a): image-publish's digest step (job image-publish only), recognised by its exact content (deploy-steps.ts) */
  | 'publish-digest';
/** pipegen's own actions by reviewed-entry id (Plan C adds the gate entry, Plan H the watcher entry, under these ids). */
export const PIPEGEN_ACTION_IDS = { gate: 'pipegen-gate', watcher: 'pipegen-watcher' } as const;
/** The step kind of each reviewed action entry that is not an ordinary tool, by entry id. The gate entry is kind `gate`, except a recognised scrub step of it (isScrubStep: judgeUses). */
const ENTRY_KIND: Readonly<Record<string, StepKind>> = Object.freeze({
  ...Object.fromEntries(Object.entries({ checkout: 'checkout', 'setup-node': 'setup', 'setup-python': 'setup', 'upload-artifact': 'upload-artifact', 'download-artifact': 'download-artifact',
    'upload-sarif': 'upload-sarif', attest: 'attest', 'docker-login': 'docker-login', 'setup-buildx': 'setup-buildx', 'build-push': 'build-push' } satisfies Record<keyof PlatformActions, StepKind>)
    .map(([k, kind]) => [PLATFORM_ACTION_IDS[k as keyof PlatformActions], kind])),
  bullfrog: 'harden', [PIPEGEN_ACTION_IDS.gate]: 'gate', [PIPEGEN_ACTION_IDS.watcher]: 'watcher',
});
/**
 * The steps each job of the permission table may hold (7a fix round 1, ruling 1), by step kind. A job with power (any
 * permission beyond `contents: read`, an `environment:`, or a secret other than the declared app secrets) runs only what
 * that power is for: no repo-code step and no unrecognised step, ever. A privileged job whose id is not here is refused.
 * pipegen's own gate and watcher actions are allowed only in the rows that list them.
 * DOCUMENTED RESIDUAL: `image-publish` builds the repository's Dockerfile with the reviewed build-push step. That build is
 * the repo's code running with `packages: write`; it is allowed there and nowhere else, because publishing the image is the
 * job's purpose (the image is then signed and verified by digest).
 */
export const JOB_STEP_POLICY: Readonly<Record<string, readonly StepKind[]>> = Object.freeze({
  'pr-check': ['harden', 'checkout', 'pr-check'],
  // G2: the verify steps of the draft's signing plan (B3 b, d); G7: the head check and the digest step are verify steps too (deploy-steps.ts)
  'pipegen-verify': ['harden', 'checkout', 'download-artifact', 'gate', 'verify'],
  'code-scanning': ['harden', 'download-artifact', 'upload-sarif'],
  // no checkout: the gate never reads the workspace (Plan C ruling S21); it reads the event, the job outputs and the API
  // C5b: the gate's own uploads (result, baseline, clean-run marker) after the gate step, and no other upload (checkJobOrder, gateUploadProblems)
  gate: ['harden', 'download-artifact', 'gate', 'upload-artifact'],
  'base-scan': ['harden', 'checkout', 'setup', 'stage', 'tool', 'scrub', 'upload-artifact'],
  // no checkout: this job holds PIPEGEN_FP_KEY and reads only the API and artifacts (C3 review m9, like the gate job's S21)
  'baseline-check': ['harden', 'download-artifact', 'gate'],
  // G7 (B3 a): the publish digest step and the upload of the digest folder, after the build (job-rules.ts publishTailAt)
  'image-publish': ['harden', 'checkout', 'setup-buildx', 'docker-login', 'build-push', 'publish-digest', 'upload-artifact'],
  // G2: the cosign sign steps of the draft's signing plan (B3 b); attest mode signs with the reviewed actions/attest
  sign: ['harden', 'checkout', 'download-artifact', 'docker-login', 'attest', 'sign'],
  // no checkout: the nightly job holds PIPEGEN_FP_KEY (it verifies the baseline) and reads only the API; the identity comes from GITHUB_REPOSITORY (C7 fix round 1)
  nightly: ['harden', 'download-artifact', 'gate'],
  watch: ['harden', 'checkout', 'watcher'],
  notify: ['harden', 'download-artifact'],
  'merged-red': ['harden', 'download-artifact'],
});
/** The only jobs that may run in the signing environment (its secrets sign and verify). */
const SIGNING_JOBS: ReadonlySet<string> = new Set(['sign', 'pipegen-verify']);
/** The triggers pipegen writes (ruling 7): `pull_request_target`, `workflow_run` and the rest are never in a file pipegen writes whole. */
const TRIGGERS: ReadonlySet<string> = new Set(['push', 'pull_request', 'merge_group', 'schedule', 'workflow_dispatch', 'workflow_call']);
/**
 * GitHub-hosted runner labels, as a plain string (ruling 6). A self-hosted runner keeps state between runs, which breaks the
 * no-cache rule (spec §19); self-hosted support would be a future, explicit opt-in.
 */
const HOSTED_RUNNERS: ReadonlySet<string> = new Set(['ubuntu-latest', 'ubuntu-24.04', 'ubuntu-22.04', 'ubuntu-24.04-arm', 'ubuntu-22.04-arm']);
/** GitHub's owner name rule (the same pattern as src/github/client.ts), checked again here: the central prefix is built from it. */
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
/**
 * Any status-function call (success(), always(), failure(), cancelled()): GitHub adds its implicit `success() && (…)` only when
 * an if holds none. Over-approximated on purpose (review-7a-r2): no \b, so `x-success(` matches; a name inside a string literal
 * matches too (refusing it is only stricter, and a quote stripper that lexes differently from GitHub's could hide a real call).
 * Non-ASCII is refused before this runs, so JS \s covers every whitespace GitHub's lexer skips.
 */
const STATUS_CALL_RE = /(?:success|always|failure|cancelled)\s*\(/i;

/** Parentheses never below zero and back to zero at the end, and every single-quoted string closed ('' is an escape). */
function balanced(e: string): boolean {
  let depth = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") {
      let closed = false;
      for (i++; i < e.length; i++) if (e[i] === "'") { if (e[i + 1] === "'") i++; else { closed = true; break; } }
      if (!closed) return false;
    } else if (c === '(') depth++;
    else if (c === ')' && --depth < 0) return false;
  }
  return depth === 0;
}

/** Whether an expression holds `||` outside parentheses and quoted strings. */
function topLevelOr(e: string): boolean {
  let depth = 0;
  for (let i = 0; i < e.length; i++) {
    const c = e[i];
    if (c === "'") {
      for (i++; i < e.length; i++) if (e[i] === "'") { if (e[i + 1] === "'") i++; else break; }
    } else if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === '|' && e[i + 1] === '|' && depth === 0) return true;
  }
  return false;
}

/**
 * Ruling 1 (fix round 2), loosened after review-7a-r2: the `if:` of a user job pipegen gated with `needs:` may be absent, an
 * expression with no status-function call at all (GitHub runs it as `success() && (…)`, so it still respects the needs),
 * exactly `success()`, or `success() && <expr>` where <expr> holds no status call and no `||` at its top level. Anything else
 * can run the job although pipegen's job failed (`success() || …`, `!success()`, `always()`, `!cancelled()`).
 * Refused first: non-ASCII (U+0085 is whitespace to GitHub's .NET lexer but not to JS \s; U+017F folds to 'S' in .NET only),
 * more than one `${{ }}` or text outside it, whitespace included (read by GitHub as a truthy string; a value with no `${{` may be trimmed), any `{` or `}` left after the unwrap (GitHub
 * ends the expression at the first `}}`, so `${{ x }}}` is a truthy string template; expressions have no brace syntax, so braces
 * inside string literals are refused too, which is only stricter), an empty condition, and unbalanced
 * parentheses or quotes (GitHub refuses the workflow; the referee says so itself). A YAML boolean is not a string: refused.
 */
export function gatedIfAllowed(cond: unknown): boolean {
  if (cond === undefined) return true;
  if (typeof cond !== 'string' || !/^[\t\n\r\x20-\x7e]*$/.test(cond)) return false;
  let e = cond;
  if (cond.includes(EXPR)) {
    // the wrapper is judged on the untrimmed value: whitespace outside it is literal text, which GitHub reads as a (truthy) string template
    const wrapped = /^\$\{\{([\s\S]*)\}\}$/.exec(cond);
    if (wrapped === null) return false;
    e = (wrapped[1] as string).trim();
  } else e = cond.trim();
  if (e === '' || e.includes(EXPR) || /[{}]/.test(e) || !balanced(e)) return false;
  if (!STATUS_CALL_RE.test(e)) return true;
  if (/^success\(\s*\)$/i.test(e)) return true;
  const m = /^success\(\s*\)\s*&&([\s\S]+)$/i.exec(e);
  if (m === null) return false;
  const rest = m[1] as string;
  return rest.trim() !== '' && !STATUS_CALL_RE.test(rest) && !topLevelOr(rest);
}

const LEVEL: Readonly<Record<string, number>> = { none: 0, read: 1, write: 2 };
const JOB_ID_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;
const STEP_KEYS: ReadonlySet<string> = new Set(STEP_KEY_LIST);
const TOP_KEYS: ReadonlySet<string> = new Set(['name', 'run-name', 'on', 'permissions', 'env', 'concurrency', 'jobs']);
const STEPS_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'runs-on', 'needs', 'if', 'permissions', 'environment', 'concurrency', 'outputs', 'env', 'steps', 'timeout-minutes', 'services', 'cache-mode']);
const CALLER_JOB_KEYS: ReadonlySet<string> = new Set(['name', 'uses', 'with', 'secrets', 'needs', 'if', 'permissions']);
const ACTION_KEYS: ReadonlySet<string> = new Set(['name', 'description', 'author', 'inputs', 'outputs', 'runs', 'branding']);
const CACHE_INPUT_RE = /(?:^|[-_])cache(?:$|[-_])/i;
/** Any `secrets.X` reference inside an expression, however it is spaced. */
const SECRET_USE_RE = /\$\{\{[^}]*?\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g;
const TRIVY_CONFIG = ARGV_POLICIES['trivy-config']?.config;

/** Sentinel targets the referee renders with: two sets, so the env values that differ are the run-time slots (B6). */
const SENTINELS = [
  { image: `ghcr.io/pipegen-referee/a@sha256:${'a'.repeat(64)}`, url: 'http://localhost:1', k8sDir: 'pipegen-referee-a' },
  { image: `ghcr.io/pipegen-referee/b@sha256:${'b'.repeat(64)}`, url: 'http://localhost:2', k8sDir: 'pipegen-referee-b' },
] as const;

/** G2: the sources of the steps the signing plan and the image hand-off make (signing.ts, image-handoff.ts), and the step kind of each. */
const SIGN_SOURCE = 'sign';
const VERIFY_SOURCE = 'verify';
const IMAGE_ARCHIVE_SOURCE = 'image-archive';
const IMAGE_CHECK_SOURCE = 'image-check';
/** G4b: the source prefix of a repo built-in's steps (`repotool:<need id>:<service>`); they are repo code, like a project script's. */
const REPO_TOOL_SOURCE = 'repotool';
/** A scanner of the PR's own image on its archive (B6): the head check itself, rendered another way (so it counts as the spec's step). */
const ARCHIVE_SUFFIX = ':archive';
/** G7: the deploy layer's own steps (deploy-steps.ts): the verify job's head check and digest step, image-publish's digest step. */
const DEPLOY_HEAD_SOURCE = 'deploy-head';
const DEPLOY_DIGEST_SOURCE = 'deploy-digest';
const PUBLISH_DIGEST_SOURCE = 'publish-digest';
const SOURCE_KIND: Readonly<Record<string, StepKind>> = Object.freeze({ [SIGN_SOURCE]: 'sign', [VERIFY_SOURCE]: 'verify', [IMAGE_ARCHIVE_SOURCE]: 'image-archive', [IMAGE_CHECK_SOURCE]: 'image-check',
  [DEPLOY_HEAD_SOURCE]: 'verify', [DEPLOY_DIGEST_SOURCE]: 'verify', [PUBLISH_DIGEST_SOURCE]: 'publish-digest',
  // G4-R1: the raw DAST result's hash check (it reads a download and the run job's output only, like a checker)
  'dast-check': 'tool' });
const sourceKind = (source: string): StepKind | undefined => { const head = source.slice(0, source.indexOf(':')); return source.includes(':') ? own(SOURCE_KIND, head) : undefined; };
/** The service slug a source of the image hand-off names (`image-archive:<slug>`, `image-check:<slug>`). */
const sourceSlug = (source: string): string => source.slice(source.indexOf(':') + 1);
/** The image tools that scan the archive (image-handoff.ts, one source) and the reviewed build-push entry. */
const ARCHIVE_TOOLS: ReadonlySet<string> = ARCHIVE_TOOL_IDS;
const BUILD_PUSH_ID = PLATFORM_ACTION_IDS['build-push'];
/** The slot kinds whose base twin must scan another input than the head (C-MUST-1): an image, or the app at a URL. */
const TWIN_SLOT_KINDS: ReadonlySet<SlotKind> = new Set(['image-digest', 'local-url']);

type Add = (file: string, check: RefereeCheck, message: string, line?: number, repo?: CreatedFile['repo']) => void;
const hasExpr = (v: unknown): boolean => (typeof v === 'string' ? v.includes(EXPR) : Array.isArray(v) ? v.some(hasExpr) : isObj(v) ? Object.entries(v).some(([k, x]) => k.includes(EXPR) || hasExpr(x)) : false);

// ---------- parsing (S29) ----------


/** The lines (1-based) a node covers, from its first character to the end of its value. */
function linesOf(lc: LineCounter, from: number, to: number, into: Set<number>): void {
  const a = lc.linePos(from).line;
  const b = lc.linePos(Math.max(from, to - 1)).line;
  for (let l = a; l <= b; l++) into.add(l);
}

function jobPair(doc: Document, id: string): Pair<YamlNode, YamlNode> | undefined {
  const jobs = doc.get('jobs', true);
  if (!isMap(jobs)) return undefined;
  return jobs.items.find((p) => isScalar(p.key) && p.key.value === id) as Pair<YamlNode, YamlNode> | undefined;
}

/**
 * The lines of an edited user workflow on which a linter finding is an issue, for 7b and the referee: the jobs pipegen
 * added, the `needs:` of the user's jobs it touched and those jobs' `if:`, and the user's top-level `on`, `env`,
 * `defaults` and `permissions`, which apply to pipegen's jobs too (7a fix round 1, ruling 5). A finding elsewhere is on the
 * user's own lines (a note). Null for a file pipegen wrote whole (every line is judged) or one that can not be read
 * (judged whole too: fail closed).
 */
export function pipegenLines(file: CreatedFile): ReadonlySet<number> | null {
  const mark = file.inserted;
  if (mark === undefined) return null;
  const r = parseYaml(file.content, 'user');
  if (!('parsed' in r)) return null;
  const { doc, lines } = r.parsed;
  const out = new Set<number>();
  for (const id of mark.jobs) {
    const p = jobPair(doc, id);
    if (p?.key?.range && p.value?.range) linesOf(lines, p.key.range[0], p.value.range[1], out);
  }
  for (const n of mark.needs) {
    const p = jobPair(doc, n.job);
    for (const key of ['needs', 'if']) {
      const q = isMap(p?.value) ? (p.value.items.find((x) => isScalar(x.key) && x.key.value === key) as Pair<YamlNode, YamlNode> | undefined) : undefined;
      if (q?.key?.range && q.value?.range) linesOf(lines, q.key.range[0], q.value.range[1], out);
    }
  }
  if (isMap(doc.contents)) {
    for (const q of doc.contents.items as Pair<YamlNode, YamlNode>[]) {
      if (isScalar(q.key) && ['on', 'env', 'defaults', 'permissions'].includes(String(q.key.value)) && q.key.range && q.value?.range) linesOf(lines, q.key.range[0], q.value.range[1], out);
    }
  }
  return out;
}

// ---------- what the renderer makes for this draft ----------

interface Expected {
  step: RenderedStep;
  /** env keys whose values are run-time slots, with their kind (judged by slots.ts, not by equality) */
  slots: Map<string, SlotKind>;
  source: string; appRunning: boolean; blocking: boolean;
  /** the last run step of its spec: the tool's own run (before it come installs and checks); only this one makes the spec "present" (R2) */
  final: boolean;
  /** the tool reads the checked-out workspace (every scanner but the image and URL ones): its job needs the locked checkout first */
  readsWorkspace: boolean;
  /** the job id of the check this step is for (jobIdFor of its need and service), and the job it must run in: that same id, or `base-scan` for the base twin (C0b fix round 1, ruling 3) */
  need?: string; owner?: string;
}

/** A judged job, kept for the checks that need every file judged first (the gate's binding to the jobs it lists). */
interface JobRecord { file: string; id: string; judged: readonly Judged[]; outputs: unknown }
/** The key of a workflow file in every map of the referee. */
const fileKey = (f: CreatedFile): string => `${f.repo}:${f.path}`;

interface Expectations {
  runs: Expected[];
  runIds: Set<string>;
  /** `owner/repo[/path]@sha` (path lower case) → its reviewed action entry */
  actions: Map<string, ReviewedTool>;
  actionPaths: Set<string>;
  /** `<image>@sha256:<digest>` of the reviewed docker entries */
  images: Set<string>;
  declared: Set<string>;
  allowed: Set<string>;
  /** the sources (`spec:<i>`) of the cli specs that rendered, and those of them a parsed file holds a step of (the blocking rule, finding 3) */
  rendered: Set<string>;
  matched: Set<string>;
  /** source → the pins each of its `pipegen-npm-ci-…` steps carries */
  npmPins: Map<string, Map<string, string[]>>;
  byId: Map<string, ReviewedTool>;
  /** checks that need every file judged first (the gate's job list), run once after the last file */
  deferred: (() => void)[];
  /** every steps job judged, in every file */
  jobs: JobRecord[];
  /** C-MUST-1 (G2): the image or URL slot value of every recognised scan step, by source, for the base-twin rule */
  twinInputs: { source: string; keys: string[]; file: CreatedFile }[];
}

const coreOf = (s: RenderedStep): Obj => ({ id: s.id, uses: s.uses, with: s.with, run: s.run, shell: s.shell, env: s.env, 'working-directory': s['working-directory'] });
const usesKey = (uses: string): { path: string; ref: string } | null => {
  const at = uses.lastIndexOf('@');
  return at <= 0 ? null : { path: uses.slice(0, at).toLowerCase(), ref: uses.slice(at + 1) };
};
const sameCandidate = (a: ReviewedTool['candidate'], b: ReviewedTool['candidate']): boolean =>
  a.id === b.id && a.kind === b.kind && a.repo === b.repo && a.version === b.version && isDeepStrictEqual(a.pin, b.pin);
const pinLines = (json: string | undefined): string[] | null => {
  try {
    const list: unknown = JSON.parse(json ?? '[]');
    return Array.isArray(list) ? list.map((p) => JSON.stringify(p)) : null;
  } catch {
    return null;
  }
};

function slotKindOf(value: string, a: (typeof SENTINELS)[number]): SlotKind | undefined {
  if (value === a.image) return 'image-digest';
  if (value === a.url) return 'local-url';
  if (value === a.k8sDir) return 'repo-path';
  return undefined;
}

/**
 * Whether a cli tool reads the checked-out workspace: every one does, except those whose only run-time values are an image
 * or a URL (trivy-image, syft, nuclei) and a docker tool that mounts only a fresh work folder (zap). Unknown: it does.
 */
function readsWorkspace(entryId: string): boolean {
  const pol = own(ARGV_POLICIES, entryId);
  if (pol === undefined) return true;
  if (pol.method === 'docker' && pol.mount?.source === 'work') return false;
  const kinds = Object.values(pol.slots ?? {});
  return !(kinds.length > 0 && kinds.every((k) => k === 'image-digest' || k === 'local-url'));
}

/** The job id of a check (the gate's job list key), or undefined for a name that cannot make one. */
function keyOf(needId: string, service: string | undefined): string | undefined {
  try { return jobIdFor(needId, service); } catch (e) { if (e instanceof GateJobListError) return undefined; throw e; }
}

function expectations(draft: PipelineDraft, platform: PlatformActions, reviewed: readonly ReviewedTool[], add: Add, notes: string[], composeEnv: RuntimeEnv | null): Expectations {
  const byId = new Map(reviewed.map((t) => [t.id, t]));
  const actions = new Map<string, ReviewedTool>();
  const images = new Set<string>();
  for (const t of [...reviewed, ...Object.values(platform)]) {
    if (!isReviewed(t?.candidate)) continue;
    const uses = t.step.action?.uses;
    if (t.candidate.kind === 'action' && uses !== undefined) {
      const k = usesKey(uses);
      if (k !== null && k.ref === t.candidate.pin.sha) actions.set(`${k.path}@${k.ref}`, t);
    }
    const install = t.step.cli?.install;
    if (install?.method === 'docker' && t.candidate.pin.digest !== undefined) images.add(`${install.package}@${t.candidate.pin.digest}`);
  }
  const ex: Expectations = {
    runs: [], runIds: new Set(), actions, actionPaths: new Set([...actions.keys()].map((k) => k.slice(0, k.lastIndexOf('@')))), images,
    declared: new Set(), allowed: new Set(PIPEGEN_SECRETS), rendered: new Set(), matched: new Set(), npmPins: new Map(), byId, deferred: [], jobs: [], twinInputs: [],
  };
  const ctxs: RenderContext[] = SENTINELS.map((t) => ({ profile: draft.profile, targets: { ...t } }));
  /** GJ: whether the draft plans the need a step is for (its id and service); a step without one is no step of pipegen's */
  const hasNeed = (spec: unknown): boolean => isObj(spec) && draft.needs.some((n) => n.id === spec.needId && n.service === spec.service);
  /** G2 (B6): the services whose image build the draft holds and pipegen can render (their archive is what the image scanners read) */
  const imageBuilds = new Set<string>();
  for (const spec of draft.steps) {
    const t = isObj(spec) && isObj(spec.tool) && typeof spec.tool.id === 'string' ? byId.get(spec.tool.id) : undefined;
    if (!hasNeed(spec)) continue;
    if (t?.id !== BUILD_PUSH_ID || !isReviewed(spec.tool) || !sameCandidate(spec.tool, t.candidate) || spec.needId !== IMAGE_BUILD_NEED || typeof spec.service !== 'string') continue;
    try { renderImageBuild(spec, t, platform, { profile: draft.profile }); imageBuilds.add(spec.service); } catch (e) { if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e; }
  }
  // G2-R1 I1: a spec blocks when ANY need of its id and service blocks, whatever the layer and order (the gate reads the merge-layer need;
  // a non-blocking copy on another layer must never let a narrowing value through). No such need: blocking (fail closed).
  const blockingOf = (needId: string, service: string | undefined): boolean => {
    const matching = draft.needs.filter((n) => n.id === needId && n.service === service);
    // (GJ-R1, review spec M3) every caller is behind hasNeed now, so `matching` is never empty there; the clause stays as a defensive
    // fail-closed default (no such need counts as blocking) for any later caller
    return matching.length === 0 || matching.some((n) => n.blocking !== false);
  };
  const record = (source: string, results: RenderedStep[][], appRunning: boolean, blocking: boolean, readsWorkspace: boolean, need: string | undefined, owner: string | undefined): void => {
    const [a, b] = results as [RenderedStep[], RenderedStep[]];
    const pins = new Map<string, string[]>();
    const lastRun = a.map((s) => s.run !== undefined).lastIndexOf(true);
    a.forEach((s, i) => {
      if (s.id?.startsWith('pipegen-npm-ci-') === true) pins.set(s.id, pinLines(s.env?.PIPEGEN_NPM_EXPECT) ?? []);
      if (s.run === undefined) return;
      const other = b[i];
      const slots = new Map<string, SlotKind>();
      for (const [k, v] of Object.entries(s.env ?? {})) {
        if (other?.env?.[k] === v) continue;
        const kind = slotKindOf(v, SENTINELS[0]);
        if (kind !== undefined) slots.set(k, kind);
      }
      ex.runs.push({ step: s, slots, source, appRunning, blocking, readsWorkspace, final: i === lastRun, ...(need === undefined ? {} : { need }), ...(owner === undefined ? {} : { owner }) });
      if (s.id !== undefined) ex.runIds.add(s.id);
    });
    ex.npmPins.set(source, pins);
  };

  draft.steps.forEach((spec: StepSpec, i) => {
    const t = isObj(spec) && isObj(spec.tool) && typeof spec.tool.id === 'string' ? byId.get(spec.tool.id) : undefined;
    // GJ: a step is recognised only for a need the draft plans (its id and service): a job without its need is never let through
    if (!hasNeed(spec)) {
      add(`draft.steps[${i}]`, 'unreviewed', `The step for ${show(spec?.needId)}${typeof spec?.service === 'string' ? ` for ${show(spec.service)}` : ''} (${show(spec?.tool?.id)}) has no need of its own in the draft, so it is no step of pipegen's and no job may run it.`);
      return;
    }
    if (t === undefined || !isReviewed(spec.tool) || !isReviewed(t.candidate) || !sameCandidate(spec.tool, t.candidate)) {
      add(`draft.steps[${i}]`, 'unreviewed', `The step for ${show(spec?.needId)} runs ${show(spec?.tool?.id)}, which is not an entry of the reviewed list at its reviewed pin; pipegen never runs it, not even as a non-blocking job (it belongs in the suggestions).`);
      return;
    }
    if (!toolCoversNeed(t.categories, spec.needId)) {
      add(`draft.steps[${i}]`, 'unreviewed', `The step for ${show(spec.needId)} runs ${show(t.id)}, which does not cover the check ${show(spec.needId)} (its categories are ${t.categories.map((c) => show(c)).join(', ')}); a tool of another kind would leave the check undone, so it is not run.`);
      return;
    }
    const blocking = blockingOf(spec.needId, spec.service);
    if (t.candidate.kind === 'action') {   // actions are judged by their template (judgeAction), not by a re-render
      // G2 (F2-R11): a blocking need's action spec never carries a narrowing value (an image build that pushes), chosen or by default
      if (blocking) {
        for (const [name, offered] of Object.entries(t.choices)) {
          const given = isObj(spec.choices) ? own(spec.choices, name) : undefined;
          const problem = narrowingChoiceProblem(name, typeof given === 'string' ? given : String(offered[0]));
          if (problem !== null) add(`draft.steps[${i}]`, 'unreviewed', `The step for ${show(spec.needId)} (${show(t.id)}): ${problem}.`);
        }
      }
      for (const n of spec.secrets ?? []) ex.declared.add(n);
      // G2 (B6): an image build for a service: its archive step, in that service's image-build job only (the build itself is judged by its binding)
      if (t.id === BUILD_PUSH_ID && spec.needId === IMAGE_BUILD_NEED && typeof spec.service === 'string') {
        try {
          const archive = renderImageBuild(spec, t, platform, { profile: draft.profile }).steps.filter((x) => x.id === IMAGE_ARCHIVE_STEP_ID);
          record(`${IMAGE_ARCHIVE_SOURCE}:${slug(spec.service)}`, [archive, archive], false, true, false, undefined, undefined);
        } catch (e) {
          if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
          notes.push(`The image build for ${show(spec.service)} can not be rendered, so no archive step may claim to be it: ${safeText(e.message, 200)}`);
        }
      }
      return;
    }
    const appRunning = t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
    // G2-R1 I2 (B6): when the draft builds this service's image, its image scans read only that image's archive (recorded below): no
    // registry form (it could scan any image by digest, leaving the PR's own unscanned) and no base twin (there is no base build yet)
    if (ARCHIVE_TOOLS.has(t.id) && typeof spec.service === 'string' && imageBuilds.has(spec.service)) {
      for (const n of spec.secrets ?? []) ex.declared.add(n);
      return;
    }
    // G4-R1 (design A): a DAST check runs in its own key-free run job (dast-run--<svc>, the app in containers only) and is scrubbed in the
    // gate's job dast--<svc> after the hash check of the handed-off raw result; it has no base twin (nothing is recorded for base-scan)
    if (own(NEED_ID_CATEGORY as Readonly<Record<string, string>>, spec.needId) === 'dast' && typeof spec.service === 'string') {
      try {
        const start = dastStartOf(draft, spec.service);
        if ('problem' in start) { notes.push(`The DAST check for ${show(spec.service)} can not run (${safeText(start.problem, 200)}), so no step may claim to be it.`); return; }
        const need = keyOf(spec.needId, spec.service);
        const runJob = dastRunJobId(spec.service);
        record(`spec:${i}`, ctxs.map((c) => renderStep(spec, t, platform, { ...c, blocking }).steps), appRunning, blocking, readsWorkspace(t.id), need, runJob);
        const run = renderDastRun(spec, t, platform, draft, start, { blocking, checkout: [] }).steps;
        const handoff = run.filter((x) => x.id === DAST_HANDOFF_STEP_ID);
        record(`${DAST_HANDOFF_SOURCE}:${slug(spec.service)}`, [handoff, handoff], false, true, false, undefined, undefined);
        const app = run.filter((x) => x.id === dastAppStepId(spec.service as string));
        if (app.length > 0) record(`${DAST_APP_SOURCE}:${slug(spec.service)}`, [app, app], false, true, false, undefined, undefined);
        // the archive's hash check before the start: the image hand-off's own check step (its kind and rules)
        const archiveCheck = run.filter((x) => x.id === imageCheckStepId(spec.service as string));
        if (archiveCheck.length > 0) record(`${IMAGE_CHECK_SOURCE}:${slug(spec.service)}`, [archiveCheck, archiveCheck], false, true, false, undefined, undefined);
        const check = renderDastScrub(spec, t, platform, draft, ex.byId.get(PIPEGEN_ACTION_IDS.gate) ?? t, start.url).steps.filter((x) => x.id === dastCheckStepId(spec.service as string));
        record(`${DAST_CHECK_SOURCE}:${i}`, [check, check], false, true, false, undefined, undefined);
        ex.rendered.add(`spec:${i}`);
        for (const n of spec.secrets ?? []) ex.declared.add(n);
      } catch (e) {
        if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
        notes.push(`The DAST step for ${show(spec.needId)} (${t.id}) can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
      }
      return;
    }
    try {
      const need = keyOf(spec.needId, spec.service);
      // G2 (F2-R11): rendered as the need blocks, so a narrowed scan of a blocking need is no step of pipegen's
      record(`spec:${i}`, ctxs.map((c) => renderStep(spec, t, platform, { ...c, blocking }).steps), appRunning, blocking, readsWorkspace(t.id), need, need);
      // the target-branch variant (the base-scan job): the same spec, rendered into the base artifact folder
      record(`spec:${i}:base`, ctxs.map((c) => renderStep(spec, t, platform, { ...c, base: true, blocking }).steps), appRunning, blocking, readsWorkspace(t.id), need, 'base-scan');
      ex.rendered.add(`spec:${i}`);
      // only a spec that rendered declares its secrets (one that did not names no step, so nothing may carry them)
      for (const n of spec.secrets ?? []) ex.declared.add(n);
    } catch (e) {
      if (!(e instanceof RenderError)) throw e;
      notes.push(`The step for ${show(spec.needId)} (${t.id}) can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
    }
  });
  for (const v of ex.declared) ex.allowed.add(v);
  // G2 (B6): the scanners of the PR's own image read its archive (no base twin: there is no base build yet), after the hash check of that
  // service's archive; only for a service whose image build is in the draft
  draft.steps.forEach((spec: StepSpec, i) => {
    const t = isObj(spec) && isObj(spec.tool) && typeof spec.tool.id === 'string' ? byId.get(spec.tool.id) : undefined;
    if (t === undefined || !hasNeed(spec) || !ARCHIVE_TOOLS.has(t.id) || !isReviewed(spec.tool) || !sameCandidate(spec.tool, t.candidate) || typeof spec.service !== 'string' || !imageBuilds.has(spec.service)) return;
    try {
      const blocking = blockingOf(spec.needId, spec.service);
      const r = renderImageArchiveScan(spec, t, platform, { profile: draft.profile, blocking });
      const check = r.steps.filter((x) => x.id === imageCheckStepId(spec.service as string));
      const scan = r.steps.filter((x) => x.run !== undefined && !check.includes(x));
      const need = keyOf(spec.needId, spec.service);
      record(`${IMAGE_CHECK_SOURCE}:${slug(spec.service)}`, [check, check], false, true, false, undefined, undefined);
      record(`spec:${i}${ARCHIVE_SUFFIX}`, [scan, scan], false, blocking, false, need, need);
      ex.rendered.add(`spec:${i}`);
    } catch (e) {
      if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
      notes.push(`The scan of the image archive for ${show(spec.needId)} (${t.id}) can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
    }
  });
  // G2 (B3 b, d): the sign and verify steps of the draft's signing plan, one source each per image. Keyless writes the image name and the
  // workflow identity to Sigstore's public log, so a private repository never signs keyless (S21: the mode is a literal pipegen chose)
  if (draft.signing?.mode === 'keyless' && draft.profile.private !== false) add('(draft)', 'permissions', 'The draft signs keyless, which writes the image name and the signing workflow to a public transparency log; a private repository signs with key-env or attest only.');
  // G3-R2 M1: the plan's mode is the one pipegen chooses from the repository and its probed capabilities (signing-mode.ts), never another
  // (key-env without the proven branch policy would use a key any branch can read; a public repository has no central signing)
  if (draft.signing !== undefined && draft.signing !== null) {
    const chosen = signingMode(draft.profile, draft.capabilities);
    if (draft.signing.mode !== chosen) add('(draft)', 'permissions', `The draft's signing mode ${show(String(draft.signing.mode))} is not the mode pipegen chooses for this repository and its capabilities (${show(chosen)}).`);
  }
  // GJ (Plan J): a service the plan builds no image for (skippedChecks: a static site, or one that doesn't run) has no image check, DAST or
  // API DAST planned, and its signing is report-only: a plan that signs its image would sign something no job builds
  const noImage = noImageServices(draft.profile, draft.capabilities);
  draft.needs.forEach((n, i) => {
    const category = isObj(n) && typeof n.id === 'string' ? (own(NEED_ID_CATEGORY as Readonly<Record<string, string>>, n.id) ?? n.category) : undefined;
    if (!isObj(n) || typeof n.service !== 'string' || !NO_IMAGE_CATEGORIES.has(String(category)) || !noImage.has(n.service)) return;
    add(`draft.needs[${i}]`, 'unreviewed', `The draft plans the check ${show(n.id)} for ${show(n.service)}, but the plan builds no image for it (${safeText(noImage.get(n.service) as string, 200)}), so there is nothing to build, scan or start; no job may run it.`);
  });
  if (draft.signing !== undefined && draft.signing !== null && Array.isArray(draft.signing.images)) {
    // GJ-R1 (sec M3): matched by slug (the identity of the digest artifacts); an image of no profile service is refused too
    for (const img of draft.signing.images) {
      const o = signedImageOwner(draft.profile, draft.capabilities, isObj(img) ? img.service : undefined);
      if (o.ok) continue;
      add('(draft)', 'permissions', o.reportOnly
        ? `The draft signs the image of ${show(String((img as { service?: unknown }).service))}, but the plan builds no image for it (${safeText(o.why, 200)}): its signing is report-only, so no step may sign it.`
        : `The draft signs the image of ${safeText(o.why, 200)}: nothing builds that image, so no step may sign it.`);
    }
  }
  const signing = expectedSigningSteps(draft, reviewed);
  notes.push(...signing.notes.map((n) => safeText(n, 400)));
  signing.sign.forEach((steps, k) => record(`${SIGN_SOURCE}:${k}`, [steps, steps], false, true, false, undefined, undefined));
  signing.verify.forEach((steps, k) => record(`${VERIFY_SOURCE}:${k}`, [steps, steps], false, true, false, undefined, undefined));
  // G7 (B3 a, carry G1→G7): the verify job's head check, and per published image its digest step and image-publish's digest step
  try {
    const head = [renderHeadCheckStep(draft.profile.defaultBranch)];
    record(`${DEPLOY_HEAD_SOURCE}:head`, [head, head], false, true, false, undefined, undefined);
  } catch (e) { if (!(e instanceof RenderError)) throw e; notes.push(`The head check of the verify job can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`); }
  for (const service of publishedImageServices(draft.profile, draft.capabilities)) {
    try {
      const digest = [renderDigestStep(service)];
      const published = [renderPublishDigestStep(service)];
      record(`${DEPLOY_DIGEST_SOURCE}:${slug(service)}`, [digest, digest], false, true, false, undefined, undefined);
      record(`${PUBLISH_DIGEST_SOURCE}:${slug(service)}`, [published, published], false, true, false, undefined, undefined);
    } catch (e) { if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e; notes.push(`The digest steps of ${show(service)} can not be rendered, so no step may claim to be them: ${safeText(e.message, 200)}`); }
  }
  // C9: the secrets job's commit-range scan (the reviewed betterleaks entry in git mode), whichever tool scans the HEAD tree: its install and
  // its one checker step belong to the secrets job (the gate's job list has its range entry exactly when the draft has a repo-wide secrets check)
  const rangeTool = byId.get(RANGE_TOOL);
  if (draft.steps.some((s) => isObj(s) && s.needId === 'secrets' && s.service === undefined) && rangeTool !== undefined && isReviewed(rangeTool.candidate)) {
    try {
      const need = keyOf('secrets', undefined);
      record('range:secrets', ctxs.map(() => renderRangeScan(rangeTool).steps), false, true, true, need, need);
      // G4 (C9r1): the pre-push head fetch before it, pipegen's own step with the job's token (optional: without it a private repository's force-push blocks once)
      record(RANGE_FETCH_SOURCE, ctxs.map(() => [renderRangeFetchStep()]), false, true, false, undefined, undefined);
    } catch (e) {
      if (!(e instanceof RenderError)) throw e;
      notes.push(`The commit-range secrets scan can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
    }
  }
  // the project's own scripts its needs call for (ruling S10): the only other run steps pipegen makes
  for (const need of draft.needs) {
    for (const s of draft.profile.services) {
      const ps = projectScriptFor(need, s);
      if (ps === null) continue;
      try {
        const key = keyOf(need.id, need.service);
        record(`script:${need.id}:${s.name}`, ctxs.map((c) => renderProjectScript(ps, platform, c).steps), false, need.blocking, true, key, key);
      } catch (e) {
        if (!(e instanceof RenderError)) throw e;
      }
    }
  }
  // G4b (ruling G4-R3, DECISIONS #95): the repo's own tool a need calls for (a TypeScript service's tsc at its lockfile version), re-derived
  // from the profile by repoToolFor and rendered by renderRepoTool: its steps are accepted only in exactly that form (string equality, like
  // every run step here), only in its own check's job, and only when it rendered (the blocking rule counts it only then)
  for (const need of draft.needs) {
    for (const s of draft.profile.services) {
      const rt = repoToolFor(need, s);
      if (rt === null) continue;
      const source = `${REPO_TOOL_SOURCE}:${need.id}:${s.name}`;
      try {
        const key = keyOf(need.id, need.service);
        record(source, ctxs.map((c) => renderRepoTool(rt, platform, c).steps), false, need.blocking, true, key, key);
        ex.rendered.add(source);
      } catch (e) {
        if (!(e instanceof RenderError || e instanceof ArtifactNameError)) throw e;
        notes.push(`The repository's own tool for ${show(need.id)} can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
      }
    }
  }
  // G1 (BP-6): the pr-check lookup step, one exact form for every draft (it reads the API with the job's token, never the workspace)
  record(PR_CHECK_SOURCE, ctxs.map(() => [renderPrCheckStep()]), false, true, false, undefined, undefined);
  // D4 (rulings B6, I1): the runtime-env and compose-up steps, only when pipegen computes a compose file, that file is among the files judged together and
  // it passed the compose judge (composeEnv is that plan's runtime env, else null). The runtime-env step is the exact re-render of it. Without the file
  // compose-up would run a compose file pipegen did not judge (an unowned one, S3), so neither step is recognised.
  if (composeEnv !== null) {
    try {
      const rt = renderRuntimeEnv(composeEnv);
      record(RUNTIME_ENV_SOURCE, ctxs.map(() => [rt]), false, true, false, undefined, undefined);
      record('compose-up', ctxs.map(() => [renderComposeUp()]), false, true, false, undefined, undefined);
    } catch (e) {
      if (!(e instanceof RenderError)) throw e;
      notes.push(`The runtime environment for the test services can not be rendered, so no step may claim to be it: ${safeText(e.message, 200)}`);
    }
  }
  return ex;
}

// ---------- judging one file ----------

interface FileCtx {
  file: CreatedFile; add: Add; ex: Expectations; draft: PipelineDraft;
  /** the file's own parsed top level (its triggers and jobs: the layout rules of G1 read them) */
  js: Obj;
  /** every parsed workflow and action file, by `<repo>:<path>` */
  others: Map<string, Parsed>;
  /** how many times the name PIPEGEN_DB_PASSWORD sits inside runtime-env steps recognised by content (D4): the only place it may be */
  dbPwOk: number;
}

const issueFor = (fc: FileCtx) => (check: RefereeCheck, message: string): void => fc.add(fc.file.path, check, message);

/** The event names of an `on:` value (a name, a list of names, or a map by name); null when it is none of those. */
function triggersOf(on: unknown): string[] | null {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.every((x) => typeof x === 'string') ? (on as string[]) : null;
  if (isObj(on)) return Object.keys(on);
  return null;
}

/**
 * The central `<owner>/pipelines/` prefix and the one commit pipegen recorded for it (ruling 2), or null: the owner must
 * pass GitHub's owner rule again here (an empty or odd owner never makes a prefix), and `draft.centralPin` must name that
 * repo at a 40-character commit. Without it every central `uses` is unknown-pin.
 */
function centralOf(draft: PipelineDraft): { prefix: string; sha: string; repo: string } | null {
  const owner = draft.profile.owner;
  const pin = draft.centralPin;
  if (typeof owner !== 'string' || !OWNER_RE.test(owner) || pin === undefined || !isObj(pin)) return null;
  if (typeof pin.repo !== 'string' || pin.repo.toLowerCase() !== `${owner.toLowerCase()}/pipelines` || typeof pin.sha !== 'string' || !COMMIT_SHA_RE.test(pin.sha)) return null;
  return { prefix: `${owner.toLowerCase()}/pipelines/`, sha: pin.sha, repo: pin.repo };
}
/** A `uses` path that looks like any owner's central pipelines repo. */
const CENTRAL_LIKE_RE = /^[^/]*\/pipelines\//;

/** The workflow's own top level (a file pipegen wrote whole). */
function judgeTop(fc: FileCtx, js: Obj): void {
  const bad = issueFor(fc);
  for (const k of Object.keys(js)) if (!TOP_KEYS.has(k)) bad('template', `The top-level key ${show(k)} is not one pipegen writes (defaults, for one, would change every run step).`);
  const p = js.permissions;
  if (!isObj(p) || Object.keys(p).length > 0) bad('permissions', 'The workflow must start from `permissions: {}`, so a job gets only what it declares.');
  for (const k of ['name', 'run-name']) if (hasExpr(js[k])) bad('injection', `The workflow's ${k} holds an expression (\${{), which pipegen never writes there.`);
  const triggers = triggersOf(js.on);
  // G1 (rulings B1, G1-R1, G1-R2 I2): a workflow's concurrency is the one exact form, at the top of the two app callers only (never a called workflow);
  // any other value, a plain group too, is refused (a shared group cancels or queues other refs' runs, the default branch's among them)
  if (js.concurrency !== undefined && !concurrencyFormOk(fc, js, triggers ?? [])) {
    bad('injection', `The workflow's concurrency is not pipegen's one form (group ${WORKFLOW_CONCURRENCY.group}, cancel-in-progress: true), which it writes only at the top of ${CALLER_WORKFLOW} or ${PUSH_WORKFLOW}, never in a called workflow; no other concurrency, a plain group included, is accepted.`);
  }
  judgeTriggerSet(fc, js, triggers);
  if (triggers === null || triggers.length === 0) bad('template', 'The workflow has no triggers pipegen can read.');
  else for (const t of triggers) {
    // G1 (rulings B1, B2): the approval re-run, exactly its form, only in pipegen.yml
    if (t === 'pull_request_review') {
      if (!prReviewFormOk(fc, js)) bad('template', `The trigger pull_request_review is written only in ${CALLER_WORKFLOW} of the app, exactly as { types: [${PR_REVIEW_TRIGGER.types.join(', ')}] } (the approval re-run).`);
      continue;
    }
    if (!TRIGGERS.has(t)) bad('template', `The trigger ${show(t)} is not one pipegen writes (only ${[...TRIGGERS].join(', ')}, and pull_request_review in ${CALLER_WORKFLOW}).`);
  }
  judgeEnv(fc, js.env, 'the workflow');
  judgeLayout(fc, js, triggers);
  judgeSignCall(fc, js, triggers);
}

/**
 * G3 (ruling S21): a called workflow that holds the sign job declares nothing under workflow_call (no input, secret or output). The signing
 * mode, the image names and the digest hand-off are literals of the file, and the key reaches the job through its own environment, so no
 * value a caller passes can choose what is signed or how (the sign steps can not read an input anyway: checkExpressions refuses it).
 */
function judgeSignCall(fc: FileCtx, js: Obj, triggers: readonly string[] | null): void {
  if (triggers === null || !triggers.includes('workflow_call') || !isObj(js.jobs) || !Object.keys(js.jobs).some((id) => id.toLowerCase() === 'sign')) return;
  const call = isObj(js.on) ? js.on.workflow_call : undefined;
  if (call === undefined || call === null || (isObj(call) && Object.keys(call).length === 0)) return;
  issueFor(fc)('injection', 'A called workflow that holds the job sign declares no input, secret or output under workflow_call: the signing mode, the images and the key are literals of the file and its environment, never values a caller passes (ruling S21).');
}

/** A workflow- or job-level env: plain values only (no expression, no secret) and no name that changes how code runs. */
function judgeEnv(fc: FileCtx, env: unknown, where: string): void {
  if (env === undefined) return;
  const bad = issueFor(fc);
  if (!isObj(env)) { bad('template', `The env of ${where} is not a map.`); return; }
  for (const [k, v] of Object.entries(env)) {
    if (isDangerousName(k)) bad('injection', `The env of ${where} sets ${show(k)}, which changes how code runs on the runner (every step and action of the job would see it).`);
    if (typeof v !== 'string' && typeof v !== 'number' && typeof v !== 'boolean') bad('template', `The env value ${show(k)} of ${where} is not plain text.`);
    if (hasExpr(v)) bad('injection', `The env value ${show(k)} of ${where} holds an expression; secrets and values reach only the steps that need them.`);
  }
}

// ---------- Plan G's layout (G1: rulings B1, B2 referee side; carries C3, C5a, C7s, BP-6) ----------
// Each form is the job-rules.ts constant or builder the renderer uses, compared by equality. A file's role comes from its path and its exact
// triggers, never from what it claims to be: pipegen.yml (the caller: push on the default branch only), the push file (every other branch, no
// gate) and the rest.

/** The source name of the pr-check lookup step among the expected run steps. */
const PR_CHECK_SOURCE = 'pr-check';
/** G4-R1: the sources of the DAST hand-off step (run job), the archive start (run job) and the raw result's hash check (scrub job). */
const DAST_HANDOFF_SOURCE = 'dast-handoff';
const DAST_APP_SOURCE = 'dast-app';
const DAST_CHECK_SOURCE = 'dast-check';
/** G4 (C9r1): the source name of the pre-push head fetch step of the secrets job. */
const RANGE_FETCH_SOURCE = 'range-fetch';
/** The gate job's own name (the second half of GATE_CHECK_NAME). */
const GATE_JOB_NAME = GATE_CHECK_NAME.split(' / ')[1] as string;
/** How deep the layout rules follow reusable-workflow calls; a deeper chain is read as holding what they look for (fail closed). */
const MAX_CALL_DEPTH = 10;

/** The merge caller job of pipegen.yml: the first half of GATE_CHECK_NAME (job `pipegen`, name `pipegen`). */
const MERGE_CALLER_ID = GATE_CHECK_NAME.split(' / ')[0] as string;
const isCallerFile = (fc: FileCtx): boolean => fc.file.repo === 'app' && fc.file.path === CALLER_WORKFLOW;
/** G8: the project's central org required workflow (`<name>--required.yml`). */
const isRequiredFile = (fc: FileCtx): boolean => fc.file.repo === 'central' && typeof fc.draft.profile.repo === 'string' && fc.file.path === centralWorkflowFile(fc.draft.profile.repo, 'required');
/** Whether a push trigger's value is exactly CALLER_WORKFLOW's form for this draft's default branch (a default branch with no exact form: never). */
function isDefaultOnlyPush(v: unknown, defaultBranch: string): boolean {
  try { return isDeepStrictEqual(v, defaultPushTrigger(defaultBranch)); } catch (e) { if (e instanceof RenderError) return false; throw e; }
}
function isFeaturePush(v: unknown, defaultBranch: string): boolean {
  try { return isDeepStrictEqual(v, featurePushTrigger(defaultBranch)); } catch (e) { if (e instanceof RenderError) return false; throw e; }
}
/** Whether a workflow's push may run on a branch other than the default, or on a tag: any push trigger but the exact default-only form (unreadable triggers: yes). */
function pushOffDefault(on: unknown, triggers: readonly string[] | null, defaultBranch: string): boolean {
  if (triggers === null) return true;
  return triggers.includes('push') && !(isObj(on) && isDefaultOnlyPush(on.push, defaultBranch));
}
/** The exact per-ref concurrency, at the top of one of the two app callers, in a file nothing calls (a called workflow sharing its caller's group deadlocks). */
function concurrencyFormOk(fc: FileCtx, js: Obj, triggers: readonly string[]): boolean {
  return fc.file.repo === 'app' && (fc.file.path === CALLER_WORKFLOW || fc.file.path === PUSH_WORKFLOW) && !triggers.includes('workflow_call')
    && isDeepStrictEqual(js.concurrency, { ...WORKFLOW_CONCURRENCY });
}
/** pull_request_review exactly in its form, and only in CALLER_WORKFLOW (B1, B2). */
function prReviewFormOk(fc: FileCtx, js: Obj): boolean {
  return isCallerFile(fc) && isObj(js.on) && isDeepStrictEqual(js.on.pull_request_review, { types: [...PR_REVIEW_TRIGGER.types] });
}
/**
 * The push file (ruling B2), the one file a pr-check skip may sit in: the app's PUSH_WORKFLOW whose only trigger is exactly the
 * every-branch-but-the-default push, or the central `<project>--push.yml` whose only trigger is workflow_call. Neither may hold or call the
 * gate (prCheckIfProblem checks that too).
 */
function isPushFile(fc: FileCtx): boolean {
  const on = fc.js.on;
  if (fc.file.repo === 'app' && fc.file.path === PUSH_WORKFLOW) return isObj(on) && Object.keys(on).length === 1 && isFeaturePush(on.push, fc.draft.profile.defaultBranch);
  if (fc.file.repo === 'central' && typeof fc.draft.profile.repo === 'string' && fc.file.path === centralWorkflowFile(fc.draft.profile.repo, 'push')) {
    const t = triggersOf(on);
    return t !== null && t.length === 1 && t[0] === 'workflow_call';
  }
  return false;
}

/**
 * Controller ruling G1-R-sec: the push caller, the one workflow allowed to call a push file. The app's PUSH_WORKFLOW whose only trigger is the
 * every-branch-but-the-default push and that holds or calls no gate (C5a refuses one there anyway).
 */
function isPushCaller(fc: FileCtx): boolean {
  const on = fc.js.on;
  return fc.file.repo === 'app' && fc.file.path === PUSH_WORKFLOW && isObj(on) && Object.keys(on).length === 1 && isFeaturePush(on.push, fc.draft.profile.defaultBranch)
    && !reaches(fc, fc.file.repo, fc.js.jobs, holdsGate);
}
/**
 * Whether a caller job's `uses` names a push file (the central `<project>--push.yml`, or the app's PUSH_WORKFLOW), by the path alone: whether
 * pipegen writes that file or not, so a call can not slip past while the file is missing (judgeCaller refuses that call on its own).
 */
function callsPushFile(fc: FileCtx, repo: CreatedFile['repo'], uses: unknown): boolean {
  if (typeof uses !== 'string') return false;
  const project = fc.draft.profile.repo;
  const centralPush = typeof project === 'string' ? centralWorkflowFile(project, 'push').toLowerCase() : null;
  if (uses.startsWith('./')) {
    const rel = uses.slice(2).toLowerCase();
    return (repo === 'app' && rel === PUSH_WORKFLOW.toLowerCase()) || (repo === 'central' && rel === centralPush);
  }
  const k = usesKey(uses);
  if (k === null || centralPush === null) return false;
  // any owner's pipelines repo, at any commit: the call is refused whatever the pin (the pin itself is judgeCaller's)
  const m = /^[^/]+\/pipelines\/(.+)$/.exec(k.path);
  return m !== null && m[1] === centralPush;
}

/** The workflow file a caller job's `uses` names, when pipegen is writing it (the same resolution as judgeCaller, without issues: those are its). */
function calledFileOf(fc: FileCtx, repo: CreatedFile['repo'], uses: unknown): { parsed: Parsed; repo: CreatedFile['repo']; key: string } | undefined {
  if (typeof uses !== 'string') return undefined;
  if (uses.startsWith('./')) {
    const rel = uses.slice(2);
    const key = `${repo}:${rel}`;
    const parsed = WORKFLOW_PATH_RE.test(rel) && PLAIN_REL_RE.test(rel) ? fc.others.get(key) : undefined;
    return parsed === undefined ? undefined : { parsed, repo, key };
  }
  const k = usesKey(uses);
  const central = centralOf(fc.draft);
  if (k === null || central === null || !k.path.startsWith(central.prefix) || k.ref !== central.sha) return undefined;
  const rel = k.path.slice(central.prefix.length);
  const key = `central:${rel}`;
  const parsed = WORKFLOW_PATH_RE.test(rel) ? fc.others.get(key) : undefined;
  return parsed === undefined ? undefined : { parsed, repo: 'central', key };
}
const stepsOf = (j: Obj): Obj[] => (Array.isArray(j.steps) ? j.steps.filter(isObj) : []);
/** A job or check name as GitHub might match it (G1-R2 m1): trimmed, lower case, spaces collapsed, no space around a slash, slashes collapsed. */
const normName = (v: unknown): string | undefined => (typeof v === 'string' ? v.trim().toLowerCase().replace(/\s*\/+\s*/g, '/').replace(/\s+/g, ' ') : undefined);
const GATE_NAMES: ReadonlySet<string> = new Set([normName(GATE_JOB_NAME) as string, normName(GATE_CHECK_NAME) as string]);
/** Whether a name reads as the gate's job or check name once normalized. */
const gateNameLike = (v: unknown): boolean => { const n = normName(v); return n !== undefined && GATE_NAMES.has(n); };
/** The gate, by any sign: the job id gate (any case), a job named like the gate's check (normalized), or a step in gate mode (whatever action it names). */
const holdsGate = (id: string, j: Obj): boolean => id.toLowerCase() === 'gate' || gateNameLike(j.name) || stepsOf(j).some((s) => isObj(s.with) && s.with.mode === 'gate');
/** What a scheduled run never holds (C7s): baseline-check and find-run read the event's repository payload, which schedule has not; and the gate (B2). */
const SCHEDULE_FORBIDDEN_MODES: ReadonlySet<string> = new Set(['baseline-check', 'find-run', 'gate']);
const scheduleForbidden = (id: string, j: Obj): boolean => id === 'baseline-check' || id === 'gate' || stepsOf(j).some((s) => isObj(s.with) && SCHEDULE_FORBIDDEN_MODES.has(String(s.with.mode)));
/**
 * Whether jobs (and the workflows their caller jobs call, transitively) hold what `hit` looks for. A call that can not be resolved is judgeCaller's
 * issue. G1-R2 m3: a call past MAX_CALL_DEPTH is not followed and never counts as a hit (it would make a job a gate holder); `walk.tooDeep` marks
 * it, and judgeLayoutJobs refuses such a chain on its own.
 */
function reaches(fc: FileCtx, repo: CreatedFile['repo'], jobs: unknown, hit: (id: string, j: Obj) => boolean, depth = 0, seen: Set<string> = new Set(), walk?: { tooDeep: boolean }): boolean {
  if (!isObj(jobs)) return false;
  for (const [id, j] of Object.entries(jobs)) {
    if (!isObj(j)) continue;
    if (hit(id, j)) return true;
    const c = j.uses === undefined ? undefined : calledFileOf(fc, repo, j.uses);
    if (c === undefined || seen.has(c.key)) continue;
    if (depth >= MAX_CALL_DEPTH) { if (walk !== undefined) walk.tooDeep = true; continue; }
    seen.add(c.key);
    if (reaches(fc, c.repo, c.parsed.js.jobs, hit, depth + 1, seen, walk)) return true;
  }
  return false;
}

/**
 * G1-R2 I1 (ruling B2): each file of the layout runs on its own triggers and nothing else. pipegen.yml: push (default-only, C3), pull_request
 * (bare) and pull_request_review (its form), any of them, no other (workflow_call, workflow_dispatch, merge_group or schedule would let an event
 * that is not a push to the default branch reach its deploy jobs as `push`, or run the gate without a pull request). pipegen-push.yml: exactly
 * the feature push. pipegen-nightly.yml: schedule only (cron entries). A called workflow (any central file, the local merge file, or any file
 * with workflow_call): workflow_call only. Other app workflows are not part of the layout and keep the general trigger list.
 */
function judgeTriggerSet(fc: FileCtx, js: Obj, triggers: readonly string[] | null): void {
  if (triggers === null) return;   // judgeTop refuses unreadable triggers
  const bad = (m: string): void => fc.add(fc.file.path, 'template', m, undefined, fc.file.repo);
  const on = js.on;
  const app = fc.file.repo === 'app';
  if (app && fc.file.path === CALLER_WORKFLOW) {
    const ok = triggers.every((t) => CALLER_TRIGGERS.includes(t)) && (isObj(on) ? !Object.hasOwn(on, 'pull_request') || on.pull_request === null : triggers.every((t) => t === 'pull_request'));
    if (!ok) bad(`${CALLER_WORKFLOW} runs only on push [<default>], pull_request (with no filter) and pull_request_review [${PR_REVIEW_TRIGGER.types.join(', ')}], nothing else: another trigger could reach its deploy jobs as a push that is not to the default branch, or run the gate without a pull request.`);
    return;
  }
  if (app && fc.file.path === PUSH_WORKFLOW) {
    if (!(isObj(on) && Object.keys(on).length === 1 && isFeaturePush(on.push, fc.draft.profile.defaultBranch))) bad(`${PUSH_WORKFLOW} runs only on the push to every branch but the default (branches-ignore: [<default>]), nothing else.`);
    return;
  }
  if (app && fc.file.path === NIGHTLY_WORKFLOW) {
    const crons = isObj(on) ? on.schedule : undefined;
    const ok = isObj(on) && Object.keys(on).length === 1 && Array.isArray(crons) && crons.length > 0 && crons.every((c) => isObj(c) && Object.keys(c).length === 1 && typeof c.cron === 'string');
    if (!ok) bad(`${NIGHTLY_WORKFLOW} runs only on schedule (its cron entries), nothing else.`);
    return;
  }
  if (isRequiredFile(fc)) {
    // G8: the org required workflow, in its one form (requiredWorkflow, src/layers/locks.ts): pull_request (bare) only, one job that calls the
    // project's central merge workflow at the recorded commit; GitHub runs it from the central repo, so it holds nothing else
    // (review m1) the whole file deep-equals requiredWorkflowForm built from pipegen.yml's merge caller judged in the same call
    const pin = centralOf(fc.draft);
    const want = pin === null ? null : `${centralWorkflowPath(pin.repo, fc.draft.profile.repo)}@${pin.sha}`;
    const callerJobs = fc.others.get(`app:${CALLER_WORKFLOW}`)?.js.jobs;
    const caller = isObj(callerJobs) ? callerJobs[MERGE_CALLER_ID] : undefined;
    const ok = want !== null && isObj(caller) && caller.uses === want && isDeepStrictEqual(js, requiredWorkflowForm(want, { permissions: caller.permissions, secrets: caller.secrets }));
    if (!ok) bad(`The org required workflow runs only on pull_request (with no filter) and holds one job, ${REQUIRED_JOB} named ${REQUIRED_NAME}, that calls the project's central merge workflow at the recorded commit with exactly the permissions and secrets of the merge caller in ${CALLER_WORKFLOW} (judged in the same call), nothing else.`);
    return;
  }
  if (!app || fc.file.path === LOCAL_MERGE_WORKFLOW || triggers.includes('workflow_call')) {
    if (!(triggers.length === 1 && triggers[0] === 'workflow_call')) bad('A called workflow runs only on workflow_call (a central file, the local merge file, or any file with workflow_call): another trigger would run its jobs outside the caller that grants their permissions and passes their secrets.');
  }
}

/** A file pipegen writes whole: C3 (pipegen.yml's push trigger), then the job rules of the layout. */
function judgeLayout(fc: FileCtx, js: Obj, triggers: readonly string[] | null): void {
  const defaultBranch = fc.draft.profile.defaultBranch;
  if (isCallerFile(fc) && (triggers ?? []).includes('push') && !(isObj(js.on) && isDefaultOnlyPush(js.on.push, defaultBranch))) {
    fc.add(fc.file.path, 'template', `${CALLER_WORKFLOW}'s push trigger must be exactly branches: [${safeText(String(defaultBranch), 100)}] (the default branch, written as a plain name), with no tags, no other branch, no pattern and no path filter (C3): a tag or another branch named like the default would start a run whose head looks trusted.`, undefined, fc.file.repo);
  }
  judgeLayoutJobs(fc, js.on, triggers, js.jobs);
}

/**
 * C5a: a workflow whose push may run on another branch than the default (or a tag) holds no gate job, no job named like the gate and calls no
 * workflow that holds one: a push has no pull request, so its gate result would mean nothing (the gate action refuses to pass there too).
 * C7s (and B2): a workflow with schedule holds no baseline-check, find-run or gate, and calls none. `only`: the jobs pipegen inserted in a user's file.
 */
function judgeLayoutJobs(fc: FileCtx, on: unknown, triggers: readonly string[] | null, jobs: unknown, only?: readonly string[]): void {
  const picked = !isObj(jobs) ? {} : only === undefined ? jobs : Object.fromEntries(Object.entries(jobs).filter(([id]) => only.includes(id)));
  // controller ruling G1-R-sec: the push file's jobs carry the pr-check skip, so only the push caller (no gate, no pull request) may call it; called
  // from a workflow that holds or calls the gate, or runs on pull requests, the skip would hide scanners the gate reads (a skipped job counts as passed)
  if (!isPushCaller(fc)) {
    for (const [id, j] of Object.entries(picked)) {
      if (isObj(j) && callsPushFile(fc, fc.file.repo, j.uses)) {
        fc.add(fc.file.path, 'not-gate-readable', `The job ${show(id)} calls the push workflow, but only the push caller (${PUSH_WORKFLOW}, whose only trigger is the push to every branch but the default and which holds or calls no gate) may call the push workflow: its jobs skip when the branch has a pull request, which in any other run could hide a check the gate reads (G1-R-sec).`, undefined, fc.file.repo);
      }
    }
  }
  if (pushOffDefault(on, triggers, fc.draft.profile.defaultBranch) && reaches(fc, fc.file.repo, picked, holdsGate)) {
    fc.add(fc.file.path, 'not-gate-readable', `The workflow runs on pushes to a branch other than the default (or to tags), so it may hold no gate job, no job named like the gate (${GATE_CHECK_NAME}) and call no workflow that holds one (C5a): a push has no pull request, so a gate there decides nothing that can be trusted. The gate runs from ${CALLER_WORKFLOW}, whose push runs on the default branch only, and on pull requests.`, undefined, fc.file.repo);
  }
  // G1-R2 m3: a chain of calls deeper than GitHub runs (or than pipegen follows) is refused outright
  const walk = { tooDeep: false };
  reaches(fc, fc.file.repo, picked, () => false, 0, new Set(), walk);
  if (walk.tooDeep) fc.add(fc.file.path, 'template', `The workflow calls a chain of reusable workflows deeper than ${MAX_CALL_DEPTH} levels, which pipegen does not follow or write.`, undefined, fc.file.repo);
  // G1-R2 m2: triggers pipegen can not read count as schedule (fail closed, as in the push rule)
  if ((triggers === null || triggers.includes('schedule')) && reaches(fc, fc.file.repo, picked, scheduleForbidden)) {
    fc.add(fc.file.path, 'template', 'The workflow runs on schedule, whose event carries no repository payload, so it holds no baseline-check or find-run step, no gate (mode gate), no job baseline-check or gate, and calls no workflow that holds one (C7s); the nightly job is the one gate mode a scheduled run has.', undefined, fc.file.repo);
  }
}

/**
 * A job's `if:` (ruling 4, and G1's two forms). A job that feeds the gate is never skipped on a condition (a skipped job counts as passed);
 * only the gate itself runs always(). Two exact forms besides, each only where it can hide no gate-feeding job: the pr-check skip on a
 * push-layer job of the push file, and the deploy condition on a deploy job of pipegen.yml that needs the gate. Anything else: refused.
 */
function judgeJobIf(fc: FileCtx, id: string, j: Obj, where: string): void {
  if (j.if === undefined) return;
  const bad = issueFor(fc);
  if (j.if === PR_CHECK_IF) { const p = prCheckIfProblem(fc, id, j); if (p !== null) bad('template', `${where}: ${p}`); return; }
  if (j.if === DEPLOY_PUSH_IF) { const p = deployIfProblem(fc, id, j); if (p !== null) bad('template', `${where}: ${p}`); return; }
  if (typeof j.if !== 'string' || !IF_VALUES.has(j.if)) bad('injection', `${where} has an if: pipegen does not write.`);
  else if (!(id === 'gate' && j.if === 'always()')) bad('template', `${where} has if: ${safeText(j.if, 20)}; a job that feeds the gate runs whenever its workflow does (a skipped job counts as passed).`);
}

function prCheckIfProblem(fc: FileCtx, id: string, j: Obj): string | null {
  const what = `the pr-check skip (if: ${PR_CHECK_IF}) is written only on a push-layer job of the push file`;
  if (j.uses !== undefined || id === PR_CHECK_JOB) return `${what}, never on the job ${PR_CHECK_JOB} itself or on a caller job.`;
  if (!isPushFile(fc)) return `${what} (${PUSH_WORKFLOW} whose only trigger is the push to every branch but the default, or the central <project>--push.yml), never in another file.`;
  if (reaches(fc, fc.file.repo, fc.js.jobs, holdsGate)) return `${what}, and this file holds or calls the gate: the skip could hide a job the gate reads (a skipped job counts as passed).`;
  const jobs = isObj(fc.js.jobs) ? fc.js.jobs : {};
  if (!needsList(j.needs).includes(PR_CHECK_JOB) || !isObj(jobs[PR_CHECK_JOB])) return `${what}, on a job that needs the job ${PR_CHECK_JOB} of the same file.`;
  return null;
}

function deployIfProblem(fc: FileCtx, id: string, j: Obj): string | null {
  const what = `the deploy condition (if: ${DEPLOY_PUSH_IF}) is written only on a deploy job of ${CALLER_WORKFLOW}`;
  if (!isCallerFile(fc)) return `${what}, never in another file.`;
  if (!(isObj(fc.js.on) && isDefaultOnlyPush(fc.js.on.push, fc.draft.profile.defaultBranch))) return `${what}, whose push trigger is exactly branches: [<default>] (here it is not), so the job runs on a push to the default branch only.`;
  const jobs = isObj(fc.js.jobs) ? fc.js.jobs : {};
  const holders = Object.entries(jobs).filter(([hid, hj]) => isObj(hj) && reaches(fc, fc.file.repo, { [hid]: hj }, holdsGate)).map(([hid]) => hid);
  if (holders.includes(id)) return `${what}, never on the gate or the job that calls it (the required check would be skipped on every pull request).`;
  if (!needsList(j.needs).some((n) => typeof n === 'string' && holders.includes(n))) return `${what}, on a job that needs the job holding the gate (${holders.length === 0 ? 'none in this file' : holders.join(', ')}), so it deploys only what passed it.`;
  return null;
}

function judgeJobs(fc: FileCtx, jobs: unknown, only?: readonly string[]): void {
  if (!isObj(jobs) || Object.keys(jobs).length === 0) { issueFor(fc)('template', 'The workflow has no jobs map.'); return; }
  for (const [id, j] of Object.entries(jobs)) if (only === undefined || only.includes(id)) judgeJob(fc, id, j);
}

/** The highest level of each permission a job with this id may have: `contents: read`, plus its row of JOB_PERMISSIONS. */
function ceilingOf(id: string): Record<string, number> {
  const allowed: Record<string, number> = { contents: LEVEL.read as number };
  for (const [k, v] of Object.entries(own(JOB_PERMISSIONS, id) ?? {})) allowed[k] = Math.max(allowed[k] ?? 0, LEVEL[v] as number);
  return allowed;
}

/**
 * Whether a job holds power (ruling 1): any permission beyond `contents: read`, an environment, or a secret that is not a declared app secret.
 * `secrets` are those the job's steps name, except the fingerprint key on a recognised scrub step (judgeStepPolicy, Plan C ruling B1 part 5).
 * DOCUMENTED RESIDUAL (C0a fix round 1): a job with a scrub step holds no repo code (checkJobOrder), but a reviewed native tool in it (gitleaks, trivy,
 * osv-scanner, ...) that hostile input turns into code execution could still read the key from the runner. The bullfrog harden step (no sudo,
 * egress limited to allowed domains) is the mitigation; the key's value is an HMAC key for fingerprints and baselines, not a deploy credential.
 */
function privileged(j: Obj, secrets: ReadonlySet<string>, ex: Expectations): boolean {
  const p = j.permissions;
  if (typeof p === 'string') return true;
  if (isObj(p) && Object.entries(p).some(([k, v]) => (k === 'contents' ? v !== 'read' && v !== 'none' : v !== 'none'))) return true;
  if (j.environment !== undefined) return true;
  return [...secrets].some((n) => !ex.declared.has(n) || PIPEGEN_SECRETS.includes(n));
}

function judgeJob(fc: FileCtx, id: string, j: unknown): void {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  if (!JOB_ID_RE.test(id)) bad('template', `${where} has an id pipegen does not write.`);
  if (!isObj(j)) { bad('template', `${where} is not a map.`); return; }
  const caller = j.uses !== undefined;
  const keys = caller ? CALLER_JOB_KEYS : STEPS_JOB_KEYS;
  for (const k of Object.keys(j)) if (!keys.has(k)) bad('template', `${where} has the key ${show(k)}, which pipegen never writes on a job${k === 'container' || k === 'strategy' || k === 'continue-on-error' || k === 'defaults' ? ' (it changes what runs or whether a failure counts)' : ''}.`);
  // expressions: nowhere on a job except the forms below (a caller's explicit secrets) and the job outputs, which jobOutputsProblems judges (ruling B3)
  for (const k of ['name', 'runs-on', 'needs', 'environment', 'concurrency', 'timeout-minutes', 'with']) if (hasExpr(j[k])) bad('injection', `${where} has an expression (\${{) in ${k}, which pipegen does not write there.`);
  judgeJobIf(fc, id, j, where);
  // G1-R2 I2: a job's concurrency only as the nightly job's own form (B5), on the job nightly
  if (j.concurrency !== undefined && !(id === 'nightly' && j.concurrency === NIGHTLY_CONCURRENCY)) bad('injection', `${where} has a concurrency; pipegen writes a job concurrency only on the job nightly, exactly ${NIGHTLY_CONCURRENCY} (no shared group may cancel or queue another run's job).`);
  if (j['timeout-minutes'] !== undefined && !(typeof j['timeout-minutes'] === 'number' && Number.isInteger(j['timeout-minutes']) && j['timeout-minutes'] >= 1 && j['timeout-minutes'] <= 360)) bad('template', `${where} has a timeout-minutes that is not 1 to 360.`);
  judgeEnv(fc, j.env, where);
  judgeGateName(fc, id, j);
  const calledPerms = caller ? judgeCaller(fc, id, j) : undefined;
  judgePermissions(fc, id, j, calledPerms);
  const envName = isObj(j.environment) ? j.environment.name : j.environment;
  // GitHub environment names are not case-sensitive (fix round 2, ruling 4): any spelling of the signing environment counts
  const signing = typeof envName === 'string' && envName.toLowerCase() === SIGNING_ENVIRONMENT;
  if (id === 'pipegen-verify' && fc.draft.capabilities.environments && envName !== SIGNING_ENVIRONMENT) {
    bad('permissions', `${where} must run in the environment ${SIGNING_ENVIRONMENT} (only deploys from the default branch pass it).`);
  }
  if (signing && !SIGNING_JOBS.has(id)) bad('permissions', `${where} runs in ${SIGNING_ENVIRONMENT} (in any spelling), whose secrets only the sign and pipegen-verify jobs may get.`);
  else if (signing && envName !== SIGNING_ENVIRONMENT) bad('permissions', `${where} must name the environment exactly ${SIGNING_ENVIRONMENT}.`);
  if (caller) return;
  if (typeof j['runs-on'] !== 'string' || !HOSTED_RUNNERS.has(j['runs-on'])) {
    bad('template', `${where} must run on a GitHub-hosted runner (${[...HOSTED_RUNNERS].join(', ')}); a self-hosted runner keeps state between runs.`);
  }
  if (j['cache-mode'] !== 'none') bad('cache', `${where} must have cache-mode: none (no cache of any kind may feed the gate, a build, a signature or a verification).`);
  judgeServices(fc, where, j.services);
  if (!Array.isArray(j.steps)) { bad('template', `${where} has no list of steps.`); judgeOutputs(fc, id, where, j, []); return; }
  const judged = judgeJobSteps(fc, where, j.steps, true, id);
  fc.ex.jobs.push({ file: fileKey(fc.file), id, judged, outputs: j.outputs });
  judgeOutputs(fc, id, where, j, judged);
  judgeStepPolicy(fc, id, where, j, judged);
  judgeGateSteps(fc, id, where, j, judged);
  judgeSigningJob(fc, where, j, judged);
  if (id === 'sign') { judgeSignPermissions(fc, where, j, judged); judgeSignJobSteps(fc, where, judged); }
  judgeBaselineIfs(fc, id, where, j, judged);
  judgeDastJobs(fc, id, where, j, judged);
  judgeEgress(fc, id, where, j, judged);
  judgeCosignEnv(fc, where, j, judged);
  judgeImageHandoff(fc, id, where, j, judged);
  judgeRegistryWrite(fc, where, j, judged);
  if (id === 'pipegen-verify') judgeVerifyJob(fc, where, j, judged);
}

/**
 * G7 (B3 a, c, e; carries G1→G7, G5→G7 2 and 3, G40): what the verify job must hold, in this order after its egress step: the gate's
 * find-run step (exactly one; its wait shorter than the job's own limit, G40), the head check (the deploy is a push to the default branch
 * and its commit is still that branch's head), and for each image pipegen publishes here its digest step (the gated run's digest artifact by
 * run id, DIGEST_RE-checked) and, whenever the repository's own signing mode signs (re-derived from the repository and its capabilities,
 * never the draft's recorded plan, carry G5→G7 1), that image's signature check after the digest. A verify job assembled in mode none for a
 * signing repository, or in attest mode before the reviewed gh entry exists (G15), has no signature check and is refused.
 */
function judgeVerifyJob(fc: FileCtx, where: string, j: Obj, judged: readonly Judged[]): void {
  // `template`: a verify job that is not the form pipegen writes (each part below is what makes it a proof)
  const bad = (m: string): void => fc.add(fc.file.path, 'template', `${where} ${m}`);
  const finds = judged.flatMap((x, i) => (x.kind === 'gate' && x.step.with?.mode === 'find-run' ? [i] : []));
  if (finds.length !== 1 || judged.some((x) => x.kind === 'gate' && x.step.with?.mode !== 'find-run')) { bad('holds exactly one gate step, in mode find-run (it proves the commit passed the gate in the trusted run).'); return; }
  const find = finds[0] as number;
  if (judged[find]?.step.id !== FIND_RUN_STEP_ID) bad(`gives its find-run step the id ${FIND_RUN_STEP_ID} (the digest step reads its run id).`);
  const wait = Number(judged[find]?.step.with?.['timeout-minutes'] ?? 30);
  const limit = j['timeout-minutes'];
  if (typeof limit !== 'number' || !Number.isInteger(wait) || limit <= wait) bad(`must outlive its find-run wait (${wait} minutes): its timeout-minutes ${show(limit)} is not longer, so a run that ends near the wait's end would be cut (G40).`);
  const at = (source: string): number => judged.findIndex((x) => x.match?.source === source && x.match.final);
  const head = at(`${DEPLOY_HEAD_SOURCE}:head`);
  if (head < 0 || head < find) bad('holds the head check after its find-run step (the deployed commit must still be the head of the default branch, so an older commit never deploys after a newer one).');
  const mode = signingMode(fc.draft.profile, fc.draft.capabilities);
  const plan = fc.draft.signing;
  for (const service of publishedImageServices(fc.draft.profile, fc.draft.capabilities)) {
    let s: string;
    try { s = slug(service); } catch (e) { if (e instanceof ArtifactNameError) continue; throw e; }
    const digest = at(`${DEPLOY_DIGEST_SOURCE}:${s}`);
    if (digest < 0 || digest < find) { bad(`holds the digest step of ${show(service)} after its find-run step (the image is published here, so its digest comes from the gated run's artifact, checked as sha256:<64 hex>).`); continue; }
    if (mode === 'none') continue;
    const k = plan === undefined || plan === null || !Array.isArray(plan.images) ? -1 : plan.images.findIndex((i) => { try { return slug(String(i?.service)) === s; } catch { return false; } });
    const verify = k < 0 ? -1 : at(`${VERIFY_SOURCE}:${k}`);
    if (verify < 0 || verify < digest) bad(`must check the signature of the image of ${show(service)} after its digest step: this repository signs in mode ${mode}, so a deploy of an image pipegen did not sign (or one verified in mode none) is never let through.`);
  }
  // nothing of the verify job's own may come before the find-run step but its egress block
  judged.slice(0, find).forEach((x, i) => { if (x.kind !== 'harden') bad(`step ${i + 1} comes before its find-run step; only the egress block may.`); });
}

/**
 * G2-R1 I3 (B6: image-publish on a default-branch push only) and controller ruling G2-R-sec2: a job that writes to the image registry (a
 * build that pushes, or `packages: write`, the sign job included) runs only in a default-branch-push context:
 * - a deploy job of pipegen.yml with the deploy condition (deployIfProblem holds it to pipegen.yml, a default-only push and the gate); or
 * - a job of a workflow whose only trigger is workflow_call and whose every caller among the judged files is a caller job of pipegen.yml
 *   with the deploy condition and needs, in a pipegen.yml whose push is default-only (one level; at least one caller).
 * Anything else, a context pipegen can not verify included, is refused (fail closed).
 */
function judgeRegistryWrite(fc: FileCtx, where: string, j: Obj, judged: readonly Judged[]): void {
  const pushes = judged.some((x) => x.entryId === BUILD_PUSH_ID && x.step.with?.push !== 'false');
  const packages = isObj(j.permissions) && j.permissions.packages === 'write';
  if (!pushes && !packages) return;
  if (isCallerFile(fc) && j.if === DEPLOY_PUSH_IF) return;
  if (reachedOnlyFromDeployCallers(fc)) return;
  fc.add(fc.file.path, 'permissions', `${where} writes to the image registry (${pushes ? 'a build that pushes' : 'packages: write'}), which pipegen does only in a deploy job of ${CALLER_WORKFLOW} with if: ${DEPLOY_PUSH_IF} (a push to the default branch), or in a called workflow reached only from such a caller job, never on a pull request or a feature-branch push.`);
}

/** G2-R-sec2: the file runs only on workflow_call, and every judged job that calls it is a caller job of pipegen.yml with the deploy condition. */
function reachedOnlyFromDeployCallers(fc: FileCtx): boolean {
  const triggers = triggersOf(fc.js.on);
  if (triggers === null || triggers.length !== 1 || triggers[0] !== 'workflow_call') return false;
  const me = fileKey(fc.file).toLowerCase();
  let callers = 0;
  for (const [key, parsed] of fc.others) {
    const repo = key.slice(0, key.indexOf(':')) as CreatedFile['repo'];
    const path = key.slice(key.indexOf(':') + 1);
    const jobs = isObj(parsed.js.jobs) ? parsed.js.jobs : {};
    for (const cj of Object.values(jobs)) {
      if (!isObj(cj) || cj.uses === undefined) continue;
      if (calledFileOf(fc, repo, cj.uses)?.key.toLowerCase() !== me) continue;
      callers++;
      // the caller job carries the deploy condition, in pipegen.yml whose push is default-only, and needs a job (deployIfProblem: the gate)
      const defaultOnly = isObj(parsed.js.on) && isDefaultOnlyPush(parsed.js.on.push, fc.draft.profile.defaultBranch);
      if (!(repo === 'app' && path === CALLER_WORKFLOW && cj.if === DEPLOY_PUSH_IF && defaultOnly && needsList(cj.needs).length > 0)) return false;
    }
  }
  return callers > 0;
}

/** G2 (B3 b; Plan G Task 1): a key-env sign step reads the signing key, which lives in the signing environment only, so its job runs there. */
function judgeSigningJob(fc: FileCtx, where: string, j: Obj, judged: readonly Judged[]): void {
  const keyed = judged.some((x) => x.kind === 'sign' && [...x.secrets].some((n) => SIGNING_KEY_SECRETS.has(n)));
  const envName = isObj(j.environment) ? j.environment.name : j.environment;
  if (keyed && envName !== SIGNING_ENVIRONMENT) fc.add(fc.file.path, 'permissions', `${where} signs with the cosign key, which only the environment ${SIGNING_ENVIRONMENT} holds (default-branch deploys only): the job must run in environment ${SIGNING_ENVIRONMENT}.`);
}

/**
 * G3 (plan Global Constraints "Signing", Task 1 "permissions follow the referee table" per mode; fix round G3-R2 I1): the sign job asks only
 * for what the draft's signing mode uses, with the step that uses it. The OIDC token (`id-token: write`) only in keyless mode with the keyless
 * sign step (cosign signs with the job's identity) or in attest mode with actions/attest (GitHub's signing); never next to a key-env
 * signature, which signs with the environment's key (a spare OIDC token could log in wherever the repository's identity is trusted).
 * `attestations: write` only in attest mode with actions/attest. An actions/attest step runs in job sign only in attest mode: in any other
 * mode it would attest a digest that is not the signed image's, and unlock the permissions above.
 */
function judgeSignPermissions(fc: FileCtx, where: string, j: Obj, judged: readonly Judged[]): void {
  const p = isObj(j.permissions) ? j.permissions : {};
  const mode = fc.draft.signing?.mode;
  const attest = judged.some((x) => x.kind === 'attest');
  // the sign step itself (its id; the cosign install is a sign-kind step too, with no secret either), recognised by content, naming no key
  const keyless = judged.some((x) => x.kind === 'sign' && typeof x.step.id === 'string' && SIGN_STEP_ID_RE.test(x.step.id) && ![...x.secrets].some((n) => SIGNING_KEY_SECRETS.has(n)));
  if (attest && mode !== 'attest') fc.add(fc.file.path, 'permissions', `${where} holds an actions/attest step, which runs in the job sign only in attest mode (the draft signs ${mode === undefined ? 'nothing' : show(String(mode))}).`);
  const oidcOk = (mode === 'keyless' && keyless) || (mode === 'attest' && attest);
  if (p['id-token'] === 'write' && !oidcOk) fc.add(fc.file.path, 'permissions', `${where} asks for id-token: write, which only the keyless sign step (keyless mode) or actions/attest (attest mode) uses; a key-env signature signs with the environment's key.`);
  if (p.attestations === 'write' && !(mode === 'attest' && attest)) fc.add(fc.file.path, 'permissions', `${where} asks for attestations: write, which only actions/attest in attest mode uses.`);
}

/**
 * G3-R3: a job that holds a cosign sign step holds the signing identity (key-env: the environment's cosign key; keyless: the job's OIDC
 * token), so nothing runs in it but pipegen's own steps: the digest download, the pinned cosign install and the sign step (recognised by
 * content; the step logs in to the registry with cosign itself). No action besides the download (a registry login action, a checkout, an
 * egress step, actions/attest) and no other run step: any of them could read the key or the token, or swap what the sign step runs.
 */
const SIGN_JOB_KINDS: ReadonlySet<StepKind> = new Set(['download-artifact', 'sign']);
function judgeSignJobSteps(fc: FileCtx, where: string, judged: readonly Judged[]): void {
  if (!judged.some((x) => x.kind === 'sign' && typeof x.step.id === 'string' && SIGN_STEP_ID_RE.test(x.step.id))) return;
  judged.forEach((x, i) => {
    // G4 (carry G3 ruling 5, P-3): the one exception, the reviewed egress step (Bullfrog, its template judged like any action) as the job's first step
    if (x.kind === 'harden' && i === 0) return;
    if (!SIGN_JOB_KINDS.has(x.kind)) fc.add(fc.file.path, 'permissions', `${where}, step ${i + 1} (${show(String(x.step.name ?? x.step.uses ?? x.kind))}): the job holds the signing identity, so it runs only the egress step (first), the digest download, the pinned cosign install and the sign step (which logs in with cosign itself), never another step or action.`);
  });
}

/**
 * G4 (G21, carry G1→G4): a step that carries a base-scan baseline condition (BASELINE_MISSING_IF on a tool or stage step, the always() form on a
 * scrub or an upload; judgeStep holds the kinds) sits in the job base-scan, which needs baseline-check (the output it reads), and belongs to the
 * base twin of a check whose category may skip its base run when a trusted baseline exists: never a dependency, licence or image scan
 * (BASE_ALWAYS_CATEGORIES), and never a shared step (the checkout, a setup) that every base scan of the job needs.
 */
function judgeBaselineIfs(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  const held = judged.filter((x) => typeof x.step.if === 'string' && BASELINE_STEP_IFS.has(x.step.if));
  if (held.length === 0) return;
  if (id !== 'base-scan') { bad('template', `${where} has a step with the base scan's baseline condition, which only the job base-scan writes.`); return; }
  if (!needsList(j.needs).includes(BASELINE_CHECK_JOB)) bad('template', `${where} has steps that read the output of the job ${BASELINE_CHECK_JOB}, but does not need it.`);
  const baseNames = new Map<string, string>();
  for (const spec of fc.draft.steps) {
    if (!isObj(spec) || typeof spec.needId !== 'string') continue;
    try { baseNames.set(resultArtifactName(spec.needId, spec.service, { base: true }), spec.needId); } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; }
  }
  for (const x of held) {
    let needId: string | undefined;
    const m = x.match === undefined ? null : /^spec:(\d+):base$/.exec(x.match.source);
    if (m !== null) needId = fc.draft.steps[Number(m[1])]?.needId;
    else if (x.kind === 'scrub' || x.kind === 'stage') needId = baseNames.get(String(x.step.with?.artifact));
    else if (x.kind === 'upload-artifact') needId = baseNames.get(String(x.step.with?.name));
    const category = needId === undefined ? undefined : own(NEED_ID_CATEGORY as Readonly<Record<string, string>>, needId);
    if (category === undefined) bad('template', `${where}: the step ${show(x.step.name)} carries the baseline condition but is not part of a check's base scan (a shared step runs for every base scan of the job).`);
    else if (BASE_ALWAYS_CATEGORIES.has(category)) bad('template', `${where}: the step ${show(x.step.name)} of the ${show(category)} base scan carries the baseline condition, but dependency, licence and image scans always run on the base commit.`);
  }
}

/**
 * G4-R1 (design A): a DAST check's own steps (the reviewed scan) run only in its run job `dast-run--<svc>`, its hand-off step only there, its
 * archive start only there; the run job names no secret and no token (the fingerprint key never reaches a job that runs the app: a scrub
 * there is the order rule's keyJob refusal) and runs in no environment; the scrub job's hash check sits in `dast--<svc>`, which needs that run
 * job (else it reads nothing, or another run's artifact).
 */
function judgeDastJobs(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  for (const x of judged) {
    const src = x.match?.source ?? '';
    const m = /^spec:(\d+)$/.exec(src);
    const spec = m === null ? undefined : fc.draft.steps[Number(m[1])];
    const dast = spec !== undefined && isObj(spec) && own(NEED_ID_CATEGORY as Readonly<Record<string, string>>, spec.needId) === 'dast' && typeof spec.service === 'string';
    if (dast && id !== safeRunId(spec.service as string)) bad('permissions', `${where}: the DAST step ${show(x.step.name)} runs only in its own job ${show(safeRunId(spec.service as string))}, which holds no key and no secret.`);
    for (const head of [DAST_HANDOFF_SOURCE, DAST_APP_SOURCE]) {
      if (src.startsWith(`${head}:`) && id !== `dast-run--${src.slice(head.length + 1)}`) bad('permissions', `${where}: the step ${show(x.step.name)} belongs to the DAST run job dast-run--${src.slice(head.length + 1)} only.`);
    }
    const c = typeof x.step.id === 'string' ? DAST_CHECK_ID_RE.exec(x.step.id) : null;
    if (c !== null) {
      if (id !== `dast--${c[1] as string}`) bad('permissions', `${where}: the hash check of the raw DAST result sits only in the job dast--${c[1] as string}.`);
      if (!needsList(j.needs).includes(`dast-run--${c[1] as string}`)) bad('not-gate-readable', `${where} checks the raw DAST result of dast-run--${c[1] as string} but does not need that job.`);
    }
  }
  if (dastRunSlugOf(id) !== null) {
    const names = new Set(judged.flatMap((x) => [...x.secrets]));
    if (names.size > 0) bad('permissions', `${where} runs the app for its DAST scan, so it names no secret (it names ${[...names].map((n) => show(n)).join(', ')}): the fingerprint key and every secret stay out of a job that runs the app.`);
    if (JSON.stringify(j.steps ?? []).includes('github.token') || j.environment !== undefined) bad('permissions', `${where} runs the app for its DAST scan, so it gets no token and no environment.`);
  }
}
const safeRunId = (service: string): string => { try { return dastRunJobId(service); } catch (e) { if (e instanceof ArtifactNameError) return '?'; throw e; } };

/** G4-R1 (E3-R3): the hosts of the shared-CDN egress sets (anyone can serve from them). */
const SHARED_CDN_HOSTS: ReadonlySet<string> = new Set([...SHARED_CDN_SETS].flatMap((s) => EGRESS_DOMAIN_SETS[s]));
/**
 * G4-R1 (E0d, P-3 as a referee backstop): every job pipegen writes with steps starts with exactly one reviewed egress step (Bullfrog, its
 * template judged like any action), except the keyless sign job (its Sigstore and OIDC hosts are in no reviewed set; documented in
 * central.ts). E3-R3: a job whose steps name a user secret (a declared app secret, not pipegen's own) has no shared-CDN set in its egress list.
 */
function judgeEgress(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  const keylessSign = id === 'sign' && fc.draft.signing?.mode === 'keyless' && judged.some((x) => x.kind === 'sign' && typeof x.step.id === 'string' && SIGN_STEP_ID_RE.test(x.step.id) && ![...x.secrets].some((n) => SIGNING_KEY_SECRETS.has(n)));
  const hardens = judged.filter((x) => x.kind === 'harden');
  if (!keylessSign && (judged[0]?.kind !== 'harden' || hardens.length !== 1)) bad('permissions', `${where} must start with pipegen's egress step (the reviewed Bullfrog block, once, first): without it the job's network is open.`);
  const userSecret = judged.some((x) => [...x.secrets].some((n) => fc.ex.declared.has(n) && !PIPEGEN_SECRETS.includes(n)));
  if (!userSecret) return;
  for (const h of hardens) {
    const hosts = String(h.step.with?.['allowed-domains'] ?? '').split('\n').map((x) => x.trim());
    const shared = hosts.filter((x) => SHARED_CDN_HOSTS.has(x));
    if (shared.length > 0) bad('permissions', `${where} holds a secret of the app, but its egress list opens shared-CDN hosts (${shared.map((x) => show(x)).join(', ')}) that serve anyone's content; pipegen never gives a job with a user secret such a set (E3-R3).`);
  }
}

/** G4 (carry G3 re-review r2): no COSIGN_, SIGSTORE_ or TUF_ variable (they change what cosign verifies or trusts) in a job that holds a cosign step, at any level. */
const COSIGN_ENV_RE = /^(?:COSIGN|SIGSTORE|TUF)_/i;
function judgeCosignEnv(fc: FileCtx, where: string, j: Obj, judged: readonly Judged[]): void {
  if (!judged.some((x) => x.kind === 'sign' || x.kind === 'verify')) return;
  const levels: [string, unknown][] = [['the workflow', fc.js.env], [where, j.env], ...judged.map((x, i): [string, unknown] => [`${where}, step ${i + 1}`, x.step.env])];
  for (const [at, env] of levels) {
    if (!isObj(env)) continue;
    for (const k of Object.keys(env)) if (COSIGN_ENV_RE.test(k)) fc.add(fc.file.path, 'injection', `The env of ${at} sets ${show(k)}, which changes what cosign signs, verifies or trusts; a job that holds a cosign step sets none.`);
  }
}

/** The draft's service whose slug is this, or undefined (none, or a name that has none). */
function serviceBySlug(draft: PipelineDraft, s: string): Service | undefined {
  return draft.profile.services.find((x) => { try { return slug(x.name) === s; } catch (e) { if (e instanceof ArtifactNameError) return false; throw e; } });
}
const isRootPath = (path: string): boolean => path === '.' || path === '' || path === './';

/**
 * G2 (B6, carry C0c): the image hand-off and the build binding.
 * - build-push runs only in a job `image-build--<svc>` or `image-publish`. In `image-build--<svc>` it builds exactly that service's Dockerfile
 *   (the template's context is the repository root, so the service must be at the root, ruling S8), never pushes, and tags the local tag its
 *   archive step saves; in `image-publish`, it builds the Dockerfile of a service at the root.
 * - a scanner job reads an archive only after the hash check of that service's archive, in the same job, and needs that service's image build.
 */
function judgeImageHandoff(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  const buildSlug = imageBuildSlugOf(id);
  judged.forEach((x, i) => {
    if (x.entryId !== BUILD_PUSH_ID) return;
    const at = `${where}, step ${i + 1}`;
    const w = x.step.with ?? {};
    if (id === 'image-publish') {
      if (!fc.draft.profile.services.some((svc) => isRootPath(svc.path) && svc.dockerfile !== undefined && svc.dockerfile !== '' && w.file === svc.dockerfile)) {
        bad('template', `${at}: build-push in image-publish builds the Dockerfile of a service at the repository root (its build context), not ${show(String(w.file ?? '(none)'))}.`);
      }
      return;
    }
    if (buildSlug === null) { bad('template', `${at}: build-push runs only in an image-build--<service> job (no push) or image-publish, so a build is always bound to one service.`); return; }
    const svc = serviceBySlug(fc.draft, buildSlug);
    if (svc === undefined) { bad('template', `${at}: the job ${show(id)} is the image build of no service of this repository.`); return; }
    if (!isRootPath(svc.path)) bad('template', `${at}: the service ${show(svc.name)} is in a sub-folder, but the build context is the repository root, so pipegen can not build its image yet.`);
    if (svc.dockerfile === undefined || svc.dockerfile === '' || w.file !== svc.dockerfile) bad('template', `${at}: an image build builds the Dockerfile of the service ${show(svc.name)} (${show(svc.dockerfile ?? '(none)')}), not ${show(String(w.file ?? '(none)'))}.`);
    if (w.push !== 'false') bad('template', `${at}: an image build for a check never pushes (push must be false; the scanners get the image as an archive).`);
    // with the archive (B6), the build tags exactly the image the archive step saves (a build with no archive step hands nothing on)
    if (judged.some((y) => y.kind === 'image-archive') && w.tags !== imageBuildTag(svc.name)) bad('template', `${at}: an image build tags exactly ${show(imageBuildTag(svc.name))}, the image its archive step saves.`);
  });
  // the archive scans: each after the hash check of its service's archive, in this job; the job needs that service's image build
  const needs = needsList(j.needs);
  judged.forEach((x, i) => {
    const src = x.match?.source;
    if (x.kind === 'image-check' && src !== undefined && !needs.includes(imageBuildJobId(sourceSlug(src)))) {
      bad('not-gate-readable', `${where}, step ${i + 1}: the hash check reads the output of ${show(imageBuildJobId(sourceSlug(src)))}, so the job must need that job (without it the check has nothing to compare and fails).`);
    }
    const m = src === undefined ? null : /^spec:(\d+):archive$/.exec(src);
    if (m === null) return;
    const service = fc.draft.steps[Number(m[1])]?.service;
    let s: string | null = null;
    try { s = typeof service === 'string' ? slug(service) : null; } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; }
    const checked = s !== null && judged.slice(0, i).some((y) => y.kind === 'image-check' && y.match?.source === `${IMAGE_CHECK_SOURCE}:${s}`);
    if (!checked) bad('not-gate-readable', `${where}, step ${i + 1}: it reads the image archive before that archive's hash check in this job (the check of its sha256 against the image build must come first).`);
  });
}

/** The job's `outputs`: only the forms of jobOutputsProblems (one rule for the renderer's jobOutputsFor and this judge), else `injection` (ruling B3). */
function judgeOutputs(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  for (const problem of jobOutputsProblems(id, j.outputs, judged.map((x) => x.step))) fc.add(fc.file.path, 'injection', `In ${where}: ${problem}`);
}

/**
 * The find-run step's layout, central-workflow and central-sha against the draft. The pin is the VALIDATED one (centralOf: `<owner>/pipelines` at a
 * 40-hex commit), never the raw `draft.centralPin`: a pin that is set but invalid is itself an issue (it makes every central `uses` unknown-pin),
 * and `inline` is not accepted for it. No pin at all: inline, and no central input.
 */
function judgeFindRunLayout(fc: FileCtx, where: string, withs: Obj): void {
  const bad = issueFor(fc);
  const pin = centralOf(fc.draft);
  if (pin === null && fc.draft.centralPin !== undefined) { bad('template', `${where}: the draft's central pin is not a valid central pin (<owner>/pipelines at a 40-character commit), so the find-run step's central layout can not be judged.`); return; }
  const want = pin === null ? 'inline' : 'central';
  if (withs.layout !== want) { bad('template', `${where}: the find-run step's layout must be ${want} for this pipeline (it is ${show(withs.layout)}); the gate it looks for runs ${want === 'central' ? 'in the central workflow' : 'inline in pipegen.yml'}.`); return; }
  if (pin === null) {
    if (withs['central-workflow'] !== undefined || withs['central-sha'] !== undefined) bad('template', `${where}: layout inline takes no central-workflow or central-sha.`);
    return;
  }
  // exactly the path the renderer derives (one helper), so an @, a .., another repository or another file is refused
  const path = centralWorkflowPath(pin.repo, fc.draft.profile.repo);
  if (withs['central-workflow'] !== path) bad('template', `${where}: the find-run step's central-workflow must be exactly ${show(path)}.`);
  if (withs['central-sha'] !== pin.sha) bad('template', `${where}: the find-run step's central-sha must be the commit pipegen recorded for the central repository.`);
}

/**
 * A nightly step (mode nightly) holds exactly nightlyStepInputs(draft) (final review fix round A, ruling 3): no missing, extra or other input. Its
 * `warn-first` list must be the warn-first checks of this draft's job list, so the nightly never opens a "switch to blocking" issue for another
 * check, and never misses one. Deferred: the job list counts only the steps the parsed files hold.
 */
function judgeNightlyInputs(fc: FileCtx, where: string, withs: Record<string, unknown>): void {
  const bad = issueFor(fc);
  fc.ex.deferred.push(() => {
    let want: Record<string, string>;
    try {
      want = nightlyStepInputs(fc.draft, { formatOf: reviewedFormatOf(fc.ex) });
    } catch (e) {
      if (!(e instanceof GateJobListError || e instanceof ArtifactNameError)) throw e;
      bad('template', `${where}: the nightly step's inputs for this pipeline can not be made (${safeText(e.message, 300)}).`);
      return;
    }
    for (const k of [...new Set([...Object.keys(want), ...Object.keys(withs)])]) {
      const name = show(safeText(k, 40));
      if (!Object.hasOwn(want, k)) bad('template', `${where}: the nightly step has the input ${name}, which this pipeline's draft does not give it.`);
      else if (!Object.hasOwn(withs, k)) bad('template', `${where}: the nightly step has no ${name} input, which this pipeline's draft gives it.`);
      else if (!sameInput(NIGHTLY_JSON_INPUTS, withs[k], want[k] as string, k)) bad('template', `${where}: the nightly step's ${name} input is not the value this pipeline's draft gives it.`);
    }
  });
}

/**
 * The job `gate` decides (C0b fix round 1, rulings 1 to 3). It runs the gate action exactly once, in mode `gate` (whatever the
 * draft holds: with no checks the gate still has to run), and has `if: always()` (a skipped required check counts as passed). The
 * gate action in mode `gate` runs in no other job. Its `job-list` literal must equal gateJobList(draft) with `needs` covering every
 * listed job, and each listed job must really hold the check it is listed for (judgeListedJobs). The list and job checks run after
 * every file is judged (the list counts only the steps a parsed file holds, and the scanner jobs may come after the gate in a file).
 */
function judgeGateSteps(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  const gateKind = judged.filter((x) => x.kind === 'gate');
  const gates = gateKind.filter((x) => x.step.with?.mode === 'gate');
  // C3: the gate action's mode baseline-check (it verifies the stored baseline's signature) runs in the job baseline-check, exactly
  // once and alone, and in no other job
  const baselineSteps = gateKind.filter((x) => x.step.with?.mode === 'baseline-check');
  if (id === 'baseline-check') {
    if (gateKind.length !== 1 || baselineSteps.length !== 1) {
      bad('permissions', `${where} must run the gate action exactly once, in mode baseline-check (it has ${gateKind.length} gate step${gateKind.length === 1 ? '' : 's'}${gateKind.length === 0 ? '' : `, modes ${gateKind.map((x) => show(String(x.step.with?.mode ?? 'none'))).join(', ')}`}); this job checks the stored baseline and decides nothing else.`);
    }
    return;
  }
  if (baselineSteps.length > 0) bad('permissions', `${where} runs the gate action in mode baseline-check, which only the job baseline-check does.`);
  // C8 fix round 1: a find-run step names where the gate runs, and that must be what the draft says: `central` exactly when pipegen recorded a central pin
  for (const x of gateKind.filter((k) => k.step.with?.mode === 'find-run')) judgeFindRunLayout(fc, where, x.step.with ?? {});
  // final review fix round A (ruling 3): a nightly step's inputs are nightlyStepInputs(draft) exactly (its warn-first list and recorded date come from the draft)
  for (const x of gateKind.filter((k) => k.step.with?.mode === 'nightly')) judgeNightlyInputs(fc, where, isObj(x.step.with) ? x.step.with : {});
  if (id !== 'gate') {
    if (gates.length > 0) bad('not-gate-readable', `${where} runs the gate action in mode gate, which only the job gate does (the required check ${GATE_CHECK_NAME} is its result).`);
    return;
  }
  if (j.if !== 'always()') bad('not-gate-readable', `${where} must have if: always(): without it a failing check skips the gate, and a skipped required check counts as passed.`);
  if (gateKind.length !== 1 || gates.length !== 1) {
    bad('not-gate-readable', `${where} must run the gate action exactly once, in mode gate (it has ${gateKind.length} gate step${gateKind.length === 1 ? '' : 's'}${gateKind.length === 0 ? '' : `, modes ${gateKind.map((x) => show(String(x.step.with?.mode ?? 'none'))).join(', ')}`}); otherwise the required check ${GATE_CHECK_NAME} decides nothing.`);
    return;
  }
  const g = gates[0] as Judged;
  // fix round 1 (ruling 1): the result upload right after the gate step, so the job can not succeed without the gate's result
  // fix round 2 (review-C5b-r1 r1-1): with the gate step found here, never searched again; and no id on it, so the job rules (which know the
  // gate step by content, without an id) and this judge can never disagree about which step it is
  if (g.step.id !== undefined) bad('not-gate-readable', `${where}: the gate step has an id, which pipegen never gives it; the job rules know the gate step by its content, so an id would make them miss it.`);
  for (const problem of gateResultUploadProblems(judged.map((x) => x.step), judged.indexOf(g))) bad('not-gate-readable', `${where}: ${problem}`);
  const needs = needsList(j.needs).filter((x): x is string => typeof x === 'string');
  if (g.step.with?.jobs === undefined) bad('not-gate-readable', `${where}: the gate step has no jobs input, so it would not see the results of the jobs it needs.`);
  const literal = g.step.with?.['job-list'];
  const withs: Record<string, unknown> = isObj(g.step.with) ? g.step.with : {};
  fc.ex.deferred.push(() => {
    let expected: JobListEntry[];
    let want: Record<string, string>;
    try {
      expected = gateJobList(fc.draft, { formatOf: reviewedFormatOf(fc.ex) });
      want = gateStepInputs(fc.draft, { formatOf: reviewedFormatOf(fc.ex) });
    } catch (e) {
      if (!(e instanceof GateJobListError || e instanceof ArtifactNameError)) throw e;
      bad('not-gate-readable', `${where}: the job list of this pipeline can not be made (${safeText(e.message, 300)}), so the gate has no list to read.`);
      return;
    }
    let actual: unknown;
    try { actual = typeof literal === 'string' ? JSON.parse(literal) : undefined; } catch { actual = undefined; }
    if (!isDeepStrictEqual(actual, JSON.parse(JSON.stringify(expected)))) {
      const listed = Array.isArray(actual) ? actual.map((x) => (isObj(x) ? String(x.job) : '?')) : [];
      const want = expected.map((e) => e.job);
      const diff = [...want.filter((x) => !listed.includes(x)).map((x) => `${x} is missing`), ...listed.filter((x) => !want.includes(x)).map((x) => `${x} is extra`)];
      bad('not-gate-readable', `${where}: the gate's job-list is not the list this pipeline needs (${safeText(diff.length > 0 ? diff.join(', ') : 'an entry differs', 200)}), so the gate would read other checks than the pipeline runs.`);
    }
    // final review fix round A (ruling 1): every other input equals gateStepInputs(draft) exactly, none missing, none extra (a skipped,
    // not-proven, service-roots, policy, protected-paths or recorded date the draft never gave would change what the gate decides)
    for (const k of [...new Set([...Object.keys(want), ...Object.keys(withs)])]) {
      if (k === 'job-list') continue;
      const name = show(safeText(k, 40));
      if (!Object.hasOwn(want, k)) bad('not-gate-readable', `${where}: the gate step has the input ${name}, which this pipeline's draft does not give it, so the gate would decide on a setting pipegen never recorded.`);
      else if (!Object.hasOwn(withs, k)) bad('not-gate-readable', `${where}: the gate step has no ${name} input, which this pipeline's draft gives it, so the gate would decide without it.`);
      else if (!sameInput(GATE_JSON_INPUTS, withs[k], want[k] as string, k)) bad('not-gate-readable', `${where}: the gate step's ${name} input is not the value this pipeline's draft gives it, so the gate would decide on another setting.`);
    }
    for (const e of expected) {
      if (!needs.includes(e.job)) bad('not-gate-readable', `${where} does not need the job ${show(e.job)} of its job list, so the gate would not wait for that check (needs must include every listed job).`);
    }
    judgeListedJobs(fc.ex, fc.draft, expected, fileKey(fc.file), bad);
  });
}

/** One step input against its value from gateStepInputs or nightlyStepInputs: JSON literals as parsed JSON (spacing does not count), the others as text. */
function sameInput(json: ReadonlySet<string>, have: unknown, want: string, name: string): boolean {
  if (typeof have !== 'string') return false;
  if (!json.has(name)) return have === want;
  try { return isDeepStrictEqual(JSON.parse(have), JSON.parse(want)); } catch { return false; }
}

/**
 * Each job the gate lists is the job that runs its check, and no other job of the gate's file does (C0b fix rounds 1 and 2): the
 * gate's `needs` and `toJSON(needs)` see only the file the gate is in, so everything here is judged over that file's jobs alone
 * (`file`), never over a job of the same id in another file. The steps pipegen rendered for the check (its tool run or project
 * script, not the shared checkout and installs) sit in `entry.job` only; their base twins only in `base-scan`; a check that is a
 * reviewed ACTION (dependency-review-action) has its action step in `entry.job` and in no other job, unless that job is the listed job
 * of another check of the same action; a findings job holds the scrub and the upload of its artifact and declares exactly the outputs
 * the gate reads (`<artifact>-sha256|-status|-error`). Without this the gate could wait on an empty job, so its `success` would say
 * nothing about the check, which runs (or fails) in a job nobody reads.
 */
function judgeListedJobs(ex: Expectations, draft: PipelineDraft, expected: readonly JobListEntry[], file: string, bad: (check: RefereeCheck, message: string) => void): void {
  const records = ex.jobs.filter((r) => r.file === file);
  const listed = new Set(expected.map((e) => e.job));
  const nb = (m: string): void => bad('not-gate-readable', m);
  // a rendered step of a listed check runs in its own job only
  for (const r of records) {
    for (const x of r.judged) {
      const m = x.match;
      if (m?.need === undefined || m.owner === undefined || !listed.has(m.need) || x.step.run === undefined || x.step.id?.startsWith('pipegen-') === true) continue;
      if (r.id !== m.owner) nb(`The step ${show(x.step.name)} belongs to the job ${show(m.owner)} (the check ${show(m.need)}${m.owner === 'base-scan' ? ', run on the base' : ''}) but sits in the job ${show(r.id)}: the gate reads the job ${show(m.owner)}, so this step's result would not count.`);
    }
  }
  const holds = (jobId: string): readonly Judged[] => records.filter((r) => r.id === jobId).flatMap((r) => r.judged);
  const outputsOf = (jobId: string): Record<string, unknown>[] => records.filter((r) => r.id === jobId).map((r) => (isObj(r.outputs) ? r.outputs : {}));
  const withOf = (x: Judged, k: string): unknown => x.step.with?.[k];
  // the reviewed action entries a listed check is made of (its specs whose tool is an action entry that rendered as reviewed)
  const actionsOf = (job: string): string[] => draft.steps.flatMap((spec, i) => {
    if (!isObj(spec) || !isReviewed(spec.tool) || keyOf(spec.needId, spec.service) !== job) return [];
    const t = ex.byId.get(spec.tool.id);
    return t !== undefined && t.candidate.kind === 'action' && sameCandidate(spec.tool, t.candidate) && reviewedFormatOf(ex)(spec, i) !== undefined ? [t.id] : [];
  });
  for (const e of expected) {
    // 1. the job holds the rendered tool or script of its check
    const sources = [...new Set(ex.runs.filter((r) => r.need === e.job && r.owner === e.job && !r.source.endsWith(':base') && r.step.id?.startsWith('pipegen-') !== true).map((r) => r.source))];
    // G2 (B6): the archive scan of a spec and its registry render are one check rendered two ways: either one counts
    const sameCheck = (a: string | undefined, src: string): boolean => a !== undefined && (a === src || a.replace(/:archive$/, '') === src.replace(/:archive$/, ''));
    // G4b-R1 I1: the check's own FINAL rendered step (the tool run, the project script, the repo tool), not just a shared step of it (the
    // install): a listed job left with its checkout and install only would pass and the gate would read a check that checked nothing
    for (const src of sources) {
      if (!holds(e.job).some((x) => x.match?.final === true && sameCheck(x.match.source, src))) nb(`The job ${show(e.job)} is in the gate's list for the check ${show(e.needId)}, but it holds no step of the check (the rendered ${src.startsWith('script:') ? 'project script' : src.startsWith(`${REPO_TOOL_SOURCE}:`) ? 'repo built-in' : 'tool run'}); the gate would wait on a job that does not run it.`);
    }
    // 1b. an action check: its action step is in the listed job and in no other job of the file
    for (const entryId of new Set(actionsOf(e.job))) {
      if (!holds(e.job).some((x) => x.entryId === entryId)) nb(`The job ${show(e.job)} is in the gate's list for the check ${show(e.needId)}, but it holds no step of the action check ${show(entryId)}; the gate would wait on a job that does not run it.`);
      // an action with a reserved kind (the harden step, the platform actions, the build) is also in other jobs (every job starts with the harden step), so only the other kinds are held to one job
      if (own(ENTRY_KIND, entryId) !== undefined) continue;
      for (const r of records) {
        if (r.id !== e.job && r.judged.some((x) => x.entryId === entryId) && !actionsOf(r.id).includes(entryId)) nb(`The action step of the check ${show(e.needId)} (${show(entryId)}) sits in the job ${show(r.id)}, but the gate reads the job ${show(e.job)}: that step's result would not count.`);
      }
    }
    if (e.artifact === undefined) continue;
    // 2. a findings job holds the scrub and the upload of its artifact, and declares its outputs; no other job touches that artifact
    for (const [artifact, home, label] of [[e.artifact, e.job, 'result'], [e.baseArtifact, 'base-scan', 'base result']] as const) {
      if (artifact === undefined) continue;
      const scrubs = records.flatMap((r) => r.judged.filter((x) => x.kind === 'scrub' && withOf(x, 'artifact') === artifact).map(() => r.id));
      const uploads = records.flatMap((r) => r.judged.filter((x) => x.kind === 'upload-artifact' && withOf(x, 'name') === artifact).map(() => r.id));
      for (const id of new Set([...scrubs, ...uploads])) if (id !== home) nb(`The scrub step of the ${label} ${show(artifact)} sits in the job ${show(id)}, but only the job ${show(home)} may hold the scrub and the upload of it.`);
      if (artifact === e.artifact) {
        if (!scrubs.includes(home)) nb(`The job ${show(home)} holds no scrub step of the ${label} ${show(artifact)}, so the gate would have nothing it can trust to read.`);
        if (!uploads.includes(home)) nb(`The job ${show(home)} does not upload the ${label} ${show(artifact)}, so the gate would have nothing to download.`);
      }
      if (scrubs.includes(home)) {
        for (const n of ['sha256', 'status', 'error']) {
          if (!outputsOf(home).some((o) => Object.hasOwn(o, `${artifact}-${n}`))) nb(`The job ${show(home)} must declare the output ${show(`${artifact}-${n}`)}: the gate reads the scrub's ${n} from the job's outputs (a missing one reads as no result).`);
        }
      }
    }
  }
}

/**
 * An artifact name is uploaded by one step per workflow file (the artifact namespace is per workflow run, so per file: a repo with a
 * pull_request file and a merge_group file has each pipeline's uploads in its own run). A second upload of one name fails at run time or hides the first.
 */
function judgeUploadsPerFile(ex: Expectations, add: Add): void {
  const seen = new Map<string, number>();
  for (const r of ex.jobs) {
    for (const x of r.judged) {
      const name = x.kind === 'upload-artifact' ? x.step.with?.name : undefined;
      if (typeof name === 'string') seen.set(`${r.file}\0${name}`, (seen.get(`${r.file}\0${name}`) ?? 0) + 1);
    }
  }
  for (const [k, n] of seen) {
    if (n > 1) { const [file, name] = k.split('\0') as [string, string]; add(file.slice(file.indexOf(':') + 1), 'not-gate-readable', `The artifact ${show(name)} is uploaded by more than one step (${n}) in this workflow file; one name has one upload, or a later one could replace the scrubbed result.`, undefined, file.slice(0, file.indexOf(':')) as CreatedFile['repo']); }
  }
}

/** The output format of a spec's reviewed tool, only for a spec that rendered and that a parsed file holds a step of (an action spec counts as reviewed): the one rule of the blocking rule and the job list. */
function reviewedFormatOf(ex: Expectations): (spec: StepSpec, index: number) => OutputFormat | undefined {
  return (s, si) => {
    if (!(isObj(s) && isReviewed(s.tool))) return undefined;
    const t = ex.byId.get(s.tool.id);
    if (t === undefined || !sameCandidate(s.tool, t.candidate)) return undefined;
    if (t.candidate.kind !== 'action' && !(ex.rendered.has(`spec:${si}`) && ex.matched.has(`spec:${si}`))) return undefined;
    return t.step.output.format;
  };
}

/**
 * Ruling 1: a job runs only what its power is for. A privileged job must have a row in JOB_STEP_POLICY and hold only the
 * step kinds of its row (never repo code, never an unrecognised step); a job whose id has a row is held to it either way.
 * pipegen's own gate and watcher actions run only in the rows that list them, and never after repo code.
 */
function judgeStepPolicy(fc: FileCtx, id: string, where: string, j: Obj, judged: readonly Judged[]): void {
  const bad = issueFor(fc);
  // the fingerprint key on a recognised scrub step is that step's own power and gives the job none (ruling B1 part 5): a scanner job stays at contents: read; anywhere else the key still makes a job privileged
  // ... but only while the job holds no step that runs code pipegen did not render as harmless (checkJobOrder refuses that too): every step of a job can read the job's secrets
  const mixed = judged.some((x) => x.kind === 'repo-code' || x.kind === 'unrecognised' || x.kind === 'central');
  const secrets = new Set(judged.flatMap((x) => [...x.secrets].filter((n) => mixed || !(x.kind === 'scrub' && n === SCRUB_SECRET))));
  const row = own(JOB_STEP_POLICY, id);
  const power = privileged(j, secrets, fc.ex);
  if (power && row === undefined) bad('permissions', `${where} holds power (a permission beyond contents: read, an environment or pipegen's own secret) but is not one of pipegen's jobs (${Object.keys(JOB_STEP_POLICY).join(', ')}).`);
  if (row !== undefined) {
    judged.forEach((x, i) => {
      if (!row.includes(x.kind)) bad('permissions', `${where}, step ${i + 1}, is ${x.kind === 'repo-code' ? 'code from the repository' : x.kind === 'unrecognised' ? 'a step pipegen does not recognise' : `a ${x.kind} step`}; the job ${id} may run only ${row.join(', ')} steps.`);
    });
  } else {
    judged.forEach((x, i) => {
      if (x.kind === 'gate' || x.kind === 'watcher') bad('permissions', `${where}, step ${i + 1}: pipegen's ${x.kind} action runs only in its own job.`);
      else if (x.kind === 'pr-check') bad('permissions', `${where}, step ${i + 1}: pipegen's pr-check lookup runs only in the job ${PR_CHECK_JOB}.`);
      // G2 (B3 b, d): pipegen signs only in the job sign and verifies only in the job pipegen-verify; an image archive comes only from its own image build (B6)
      else if (x.kind === 'sign') bad('permissions', `${where}, step ${i + 1}: pipegen signs only in the job sign.`);
      else if (x.kind === 'verify') bad('permissions', `${where}, step ${i + 1}: pipegen verifies only in the job pipegen-verify.`);
      else if (x.kind === 'publish-digest') bad('permissions', `${where}, step ${i + 1}: the published image's digest is written only in the job image-publish.`);
      else if (x.kind === 'image-archive' && imageBuildSlugOf(id) !== sourceSlug(x.match?.source ?? '')) bad('permissions', `${where}, step ${i + 1}: the image archive of ${show(sourceSlug(x.match?.source ?? ''))} is made only in its own job ${show(imageBuildJobId(sourceSlug(x.match?.source ?? '')))}.`);
    });
  }
  const firstRepo = judged.findIndex((x) => x.kind === 'repo-code' || x.kind === 'unrecognised' || x.kind === 'central');
  if (firstRepo >= 0) judged.slice(firstRepo + 1).forEach((x) => { if (x.kind === 'gate' || x.kind === 'watcher') bad('injection', `In ${where}: pipegen's ${x.kind} action comes after a step that runs code pipegen did not render.`); });
}

/**
 * No job takes the gate's check name; the gate job (id `gate`) has the name the required check expects (GATE_CHECK_NAME, never a literal).
 * G1-R2 m1: a look-alike is compared normalized (gateNameLike: case, spaces, slashes), and a job id that is `gate` in another case counts too.
 */
function judgeGateName(fc: FileCtx, id: string, j: Obj): void {
  const bad = issueFor(fc);
  if (id === 'gate') {
    if (j.name === GATE_CHECK_NAME) bad('not-gate-readable', `The job ${show(id)} is named like the gate's required check (${GATE_CHECK_NAME}); only the gate may report under that name.`);
    else if (j.name !== undefined && j.name !== GATE_JOB_NAME) bad('not-gate-readable', `The gate job must be named ${show(GATE_JOB_NAME)} so the required check is ${GATE_CHECK_NAME}.`);
    return;
  }
  if (gateNameLike(j.name) || (j.name === undefined && gateNameLike(id))) bad('not-gate-readable', `The job ${show(id)} is named like the gate (${GATE_CHECK_NAME}, compared without case, spaces or doubled slashes); a check under the gate's name could pass for it, so only the gate job may have it.`);
}

/**
 * A reusable-workflow caller: its `uses` pin, its inputs, its explicit secrets. The called workflow must be a file pipegen is
 * writing (local, or the central repo at the commit pipegen recorded, ruling 2), so it is judged too; pipegen's own secrets
 * reach it only then. Returns the called file's job permissions.
 */
function judgeCaller(fc: FileCtx, id: string, j: Obj): Obj[] | undefined {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  const uses = j.uses;
  let called: Parsed | undefined;
  if (typeof uses !== 'string') bad('unpinned', `${where} calls a workflow that is not named by text.`);
  else if (uses.startsWith('./')) {
    const rel = uses.slice(2);
    called = WORKFLOW_PATH_RE.test(rel) && PLAIN_REL_RE.test(rel) ? fc.others.get(`${fc.file.repo}:${rel}`) : undefined;
    if (called === undefined) bad('unknown-pin', `${where} calls ${show(uses)}, which is not a workflow file pipegen is writing.`);
  } else {
    const k = usesKey(uses);
    const central = centralOf(fc.draft);
    if (k === null || !COMMIT_SHA_RE.test(k.ref)) bad('unpinned', `${where} calls ${show(uses)}, which is not pinned to a 40-character commit.`);
    else if (central === null || !k.path.startsWith(central.prefix)) bad('unknown-pin', `${where} calls ${show(uses)}, which is neither the central pipelines repo (at the commit pipegen recorded) nor a reviewed workflow.`);
    else if (k.ref !== central.sha) bad('unknown-pin', `${where} calls the central repo at a commit pipegen did not record.`);
    else {
      const rel = k.path.slice(central.prefix.length);
      called = WORKFLOW_PATH_RE.test(rel) ? fc.others.get(`central:${rel}`) : undefined;
      if (called === undefined) bad('unknown-pin', `${where} calls ${show(uses)}, which is not among the central files pipegen is writing, so it can not be judged.`);
    }
  }
  if (j.secrets === 'inherit') bad('permissions', `${where} passes every secret (secrets: inherit); pipegen maps each secret by name.`);
  else if (j.secrets !== undefined) {
    if (!isObj(j.secrets)) bad('template', `${where} has secrets that are not a map.`);
    else for (const [k, v] of Object.entries(j.secrets)) {
      const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
      if (m === null || m[1] !== k) bad('injection', `${where} passes the secret ${show(k)} as something other than \${{ secrets.${safeText(k, 40)} }}.`);
      else if (!fc.ex.allowed.has(k)) bad('permissions', `${where} passes the secret ${show(k)}, which no step of this pipeline declared.`);
      else if (called === undefined && PIPEGEN_SECRETS.includes(k)) bad('permissions', `${where} passes pipegen's secret ${show(k)} to a workflow pipegen can not judge.`);
    }
  }
  // G3-R2 M2 (ruling S21): the sign workflow takes nothing from its caller (no input, no secret: the key reaches the called job through its
  // own environment), so a caller job of a workflow that holds the job sign passes no `with` and no `secrets`
  if (called !== undefined && isObj(called.js.jobs) && Object.keys(called.js.jobs).some((cid) => cid.toLowerCase() === 'sign') && (j.with !== undefined || j.secrets !== undefined)) {
    bad('injection', `${where} calls the sign workflow, which takes nothing from its caller: no with and no secrets (the mode, the images and the key are the file's and its environment's).`);
  }
  if (called === undefined || !isObj(called.js.jobs)) return undefined;
  return Object.values(called.js.jobs).map((cj) => (isObj(cj) && isObj(cj.permissions) ? cj.permissions : {}));
}

function judgePermissions(fc: FileCtx, id: string, j: Obj, called: Obj[] | undefined): void {
  const bad = issueFor(fc);
  const where = `the job ${show(id)}`;
  const p = j.permissions;
  if (p === undefined || p === null) { bad('permissions', `${where} declares no permissions (it would get the repository's defaults).`); return; }
  if (typeof p === 'string') { bad('permissions', `${where} has permissions ${show(p)}; pipegen lists each permission (never read-all or write-all).`); return; }
  if (!isObj(p)) { bad('permissions', `${where} has permissions that are not a map.`); return; }
  const allowed = ceilingOf(id);
  for (const c of called ?? []) for (const [k, v] of Object.entries(c)) if (typeof v === 'string' && own(LEVEL, v) !== undefined) allowed[k] = Math.max(allowed[k] ?? 0, LEVEL[v] as number);
  for (const [k, v] of Object.entries(p)) {
    const level = typeof v === 'string' ? own(LEVEL, v) : undefined;
    if (level === undefined) bad('permissions', `${where} sets ${show(k)} to ${show(v)}, which is not read, write or none.`);
    else if (level > (own(allowed, k) ?? 0)) bad('permissions', `${where} asks for ${safeText(k, 40)}: ${safeText(String(v), 10)}, more than a job with this id may have.`);
  }
}

function judgeServices(fc: FileCtx, where: string, services: unknown): void {
  if (services === undefined) return;
  const bad = issueFor(fc);
  if (!isObj(services)) { bad('template', `The services of ${where} are not a map.`); return; }
  for (const [name, s] of Object.entries(services)) {
    if (!isObj(s)) { bad('template', `The service ${show(name)} of ${where} is not a map.`); continue; }
    for (const k of Object.keys(s)) if (!['image', 'ports', 'env'].includes(k)) bad('template', `The service ${show(name)} of ${where} has ${show(k)}; pipegen sets only its image, ports and env.`);
    if (hasExpr(s)) bad('injection', `The service ${show(name)} of ${where} holds an expression.`);
    judgeEnv(fc, s.env, `the service ${show(name)}`);
    const image = typeof s.image === 'string' ? s.image : '';
    if (!/@sha256:[0-9a-f]{64}$/.test(image)) bad('unpinned', `The service ${show(name)} of ${where} runs an image that is not pinned by digest.`);
    else if (!fc.ex.images.has(image)) bad('unknown-pin', `The service ${show(name)} of ${where} runs an image that is not a reviewed image at its reviewed digest.`);
  }
}

// ---------- steps ----------

interface Judged {
  step: RenderedStep; match?: Expected; kind: StepKind;
  /** the reviewed entry id of an action step (its `uses` path and pin matched that entry): what binds an action check to its job */
  entryId?: string;
  /** the id may be trusted by the order rule (the step is recognised by content) */
  harmlessId: boolean;
  /** the secrets the step names */
  secrets: Set<string>;
  readsWorkspace: boolean;
}

/**
 * A job's steps, judged where they run: each step (judgeList), then the order rule, the merged npm ci pins and, for a job
 * (`job`), the locked checkout before the first scanner that reads the workspace (ruling 4).
 */
function judgeJobSteps(fc: FileCtx, where: string, steps: unknown[], job: boolean, jobId?: string): Judged[] {
  const judged = judgeList(fc, where, steps);
  // the order rule, on what was parsed: a run step not recognised by content is repo code, whatever id it claims
  const forOrder = judged.map((x) => (x.harmlessId ? x.step : { ...x.step, id: undefined }));
  // the scan steps pipegen rendered (recognised by content, so their ids can be trusted), with their reviewed tool and result format: the scrub steps must equal them
  const scans = new Map<string, ScanFact>();
  for (const x of judged) {
    const m = x.match === undefined || !x.match.final || x.kind !== 'tool' || !x.harmlessId || x.step.id === undefined ? null : /^spec:(\d+)(?::base|:archive)?$/.exec(x.match.source);
    const spec = m === null ? undefined : fc.draft.steps[Number(m[1])];
    const format = spec === undefined || !isObj(spec) || !isObj(spec.tool) ? undefined : fc.ex.byId.get(spec.tool.id)?.step.output.format;
    if (spec !== undefined && x.step.id !== undefined && (format === 'sarif' || format === 'zap-json')) scans.set(x.step.id, { tool: spec.tool.id, format });
    // G4-R1: the hash check of a handed-off DAST result stands for its scan step (the scan ran in the run job)
    const dc = x.match === undefined ? null : new RegExp(`^${DAST_CHECK_SOURCE}:(\\d+)$`).exec(x.match.source);
    const dspec = dc === null ? undefined : fc.draft.steps[Number(dc[1])];
    const dformat = dspec === undefined || !isObj(dspec) || !isObj(dspec.tool) ? undefined : fc.ex.byId.get(dspec.tool.id)?.step.output.format;
    if (dspec !== undefined && x.step.id !== undefined && x.harmlessId && (dformat === 'sarif' || dformat === 'zap-json')) scans.set(x.step.id, { tool: dspec.tool.id, format: dformat });
    // C9: the commit-range scan, recognised by content as the range source's own step
    if (x.match?.source === 'range:secrets' && x.match.final && x.kind === 'tool' && x.harmlessId && x.step.id !== undefined) scans.set(x.step.id, { tool: RANGE_TOOL, format: 'sarif' });
  }
  // D4 M1: compose-up reads the password the runtime-env step generated, so each compose-up has exactly one runtime-env step before it in its job (and a job has one)
  const rtAt = judged.flatMap((x, i) => (x.match?.source === RUNTIME_ENV_SOURCE ? [i] : []));
  if (rtAt.length > 1) fc.add(fc.file.path, 'template', `In ${where}: the job holds ${rtAt.length} runtime-env steps; it holds one, because a second would generate a second password.`);
  judged.forEach((x, i) => {
    if (x.match?.source === 'compose-up' && rtAt.filter((r) => r < i).length !== 1) fc.add(fc.file.path, 'template', `In ${where}, step ${i + 1}: compose-up needs exactly one runtime-env step before it in the same job (it reads the password that step generates).`);
  });
  for (const problem of checkJobOrder(forOrder, { ...(jobId === undefined ? {} : { id: jobId }), scans })) fc.add(fc.file.path, 'injection', `In ${where}: ${problem}`);
  // a merged repo `npm ci` (dedupeJobSteps) carries exactly the pins of the tools of this job that need it
  const sources = new Set(judged.flatMap((x) => (x.match === undefined ? [] : [x.match.source])));
  for (const x of judged) {
    const id = x.step.id;
    if (x.match === undefined || id === undefined || !id.startsWith('pipegen-npm-ci-')) continue;
    const want = new Set([...sources].flatMap((src) => fc.ex.npmPins.get(src)?.get(id) ?? []));
    const got = pinLines(x.step.env?.PIPEGEN_NPM_EXPECT);
    if (got === null || !isDeepStrictEqual(new Set(got), want)) fc.add(fc.file.path, 'template', `In ${where}: the dependency install ${show(id)} does not check exactly the pins of the tools of its job.`);
  }
  if (job) {
    // the stage step (C1c) reads the checkout too: it copies it for the secrets scan
    const reader = judged.findIndex((x) => (x.kind === 'tool' && x.readsWorkspace) || x.kind === 'stage');
    if (reader >= 0) {
      const co = judged.findIndex((x) => x.kind === 'checkout');
      const ok = co >= 0 && co < reader && judged.slice(0, co).every((x) => x.kind === 'harden' || x.kind === 'setup') && judged[co]?.step.if === undefined;
      if (!ok) fc.add(fc.file.path, 'template', `In ${where}: a scanner reads the workspace, so the job must check the repository out first (the locked checkout, right after any harden or setup step, with no condition); otherwise it scans nothing and passes.`);
    }
  }
  return judged;
}

/**
 * Steps in order. A `./` local action is refused outright in v0.2 (fix round 2, ruling 3): GitHub runs it from the job's
 * checked-out workspace, which on a pull request is the author's code (and in a central reusable workflow, the caller's
 * repository), never from the files pipegen judged. A future opt-in would have to treat it as repo code.
 */
function judgeList(fc: FileCtx, where: string, steps: unknown[]): Judged[] {
  return steps.map((raw, i) => {
    const at = `${where}, step ${i + 1}`;
    if (isObj(raw) && typeof raw.uses === 'string' && raw.uses.startsWith('./')) {
      fc.add(fc.file.path, 'unreviewed', `In ${at}: ${show(raw.uses)} is a local action. GitHub runs it from the checked-out workspace, which on a pull request is the author's code, not the file pipegen judged; pipegen does not run local actions.`);
      return { step: { name: '' }, kind: 'unrecognised', harmlessId: false, secrets: new Set<string>(), readsWorkspace: false };
    }
    return judgeStep(fc, at, raw);
  });
}

/** The source name of the runtime-env step among the expected run steps. */
const RUNTIME_ENV_SOURCE = 'runtime-env';
/** The names only the runtime-env step may spell: the generated password and the container copies of the runtime variables (PIPEGEN_APP_*). */
const RESERVED_NAME_RE = /PIPEGEN_(?:DB_PASSWORD|APP_[A-Z0-9_]+)/gi;
const DB_PW_MESSAGE = "A name pipegen reserves for its runtime-env step (PIPEGEN_DB_PASSWORD, the generated database password, or PIPEGEN_APP_*, the container copies of the test variables) appears outside that step. It may be used only there, in exactly the form pipegen writes.";
const dbPwCount = (text: string): number => (text.match(RESERVED_NAME_RE) ?? []).length;

function judgeStep(fc: FileCtx, where: string, raw: unknown): Judged {
  const bad = issueFor(fc);
  const at = (m: string): string => `In ${where}: ${m}`;
  const none = (step: RenderedStep): Judged => ({ step, kind: 'unrecognised', harmlessId: false, secrets: new Set(), readsWorkspace: false });
  if (!isObj(raw)) { bad('template', at('the step is not a map.')); return none({ name: '' }); }
  for (const k of Object.keys(raw)) if (!STEP_KEYS.has(k)) bad('template', at(`the key ${show(k)} is not one pipegen writes on a step.`));
  for (const k of ['id', 'name', 'if', 'uses', 'run', 'shell', 'working-directory']) if (raw[k] !== undefined && typeof raw[k] !== 'string') bad('template', at(`${k} is not text.`));
  for (const k of ['with', 'env']) if (raw[k] !== undefined && !isObj(raw[k])) bad('template', at(`${k} is not a map.`));
  const step = raw as unknown as RenderedStep;
  try {
    checkExpressions(step);
  } catch (e) {
    if (!(e instanceof RenderError)) throw e;
    bad('injection', at(e.message));
  }
  const isUses = typeof raw.uses === 'string';
  const isRun = typeof raw.run === 'string';
  if (isUses === isRun) { bad('template', at('a step must have exactly one of uses and run.')); return none(step); }
  const withs = isObj(raw.with) ? raw.with : {};
  const env = isObj(raw.env) ? raw.env : {};
  // caches: no cache action, no cache input beyond the reviewed locks at their locked value
  for (const [k, v] of Object.entries(withs)) {
    if (CACHE_INPUT_RE.test(k) && own(CACHE_LOCKS, k) !== v) bad('cache', at(`the input ${show(k)} turns on a cache; pipegen uses none.`));
  }
  if (isUses && /^actions\/cache(?:\/|@)/i.test(raw.uses as string)) bad('cache', at('actions/cache restores files a previous run left; pipegen uses no cache.'));
  let appRunning = false;
  let kind: StepKind = 'unrecognised';
  let match: Expected | undefined;
  let harmlessId = true;
  let reads = false;
  let entryId: string | undefined;
  if (isUses) {
    ({ appRunning, kind, entryId } = judgeUses(fc, at, raw.uses as string, withs, env, raw));
    if (raw.shell !== undefined) bad('template', at('an action step takes no shell.'));
  } else {
    const r = matchRun(fc.ex, step);
    if (r === 'near') { bad('template', at(`the step ${show(raw.id)} differs from what pipegen renders for it (an input, its pinned config or its command was changed).`)); harmlessId = false; }
    else if (r === null) { bad('unreviewed', at(`the run step ${show(raw.name ?? raw.id ?? '')} is not a step pipegen renders for this pipeline (a reviewed tool or a project script), so it is not run.`)); harmlessId = false; }
    else {
      match = r;
      // C-MUST-1 (G2): the image or URL a scan step reads, for the base-twin rule (judgeBaseTwins)
      for (const [k, slotKind] of r.slots) if (TWIN_SLOT_KINDS.has(slotKind) && typeof env[k] === 'string') fc.ex.twinInputs.push({ source: r.source, keys: twinKeys(slotKind, env[k] as string), file: fc.file });
      // an archive scan reads the PR's own image with no input a base twin could be compared with (B6)
      if (r.source.endsWith(ARCHIVE_SUFFIX)) fc.ex.twinInputs.push({ source: r.source, keys: [], file: fc.file });
      if (r.source === RUNTIME_ENV_SOURCE) fc.dbPwOk += dbPwCount(JSON.stringify(raw));
      // G2 (B6): an archive scan is the head check itself, read from the archive
      if (r.final) fc.ex.matched.add(r.source.endsWith(ARCHIVE_SUFFIX) ? r.source.slice(0, -ARCHIVE_SUFFIX.length) : r.source);
      appRunning = r.appRunning;
      const id = r.step.id ?? '';
      kind = r.source === PR_CHECK_SOURCE ? 'pr-check'
        : sourceKind(r.source) ?? (r.source.startsWith('script:') || r.source.startsWith(`${REPO_TOOL_SOURCE}:`) || appRunning ? 'repo-code' : /^(?:checker-run|tool-run|tool-install|tool-pull)-/.test(id) ? 'tool' : 'repo-code');
      reads = kind === 'tool' && r.readsWorkspace;
    }
    // trivy keeps a cache between runs unless it runs with pipegen's pinned config (cache.backend: memory, ruling S3), whether
    // or not the step was recognised
    if (TRIVY_LAUNCH_RE.test(raw.run as string)) {
      const cfg = typeof env.PIPEGEN_CONFIG === 'string' ? env.PIPEGEN_CONFIG : '';
      const flag = TRIVY_CONFIG === undefined ? null : `${TRIVY_CONFIG.flag} "$cfg/${TRIVY_CONFIG.fileName}"`;
      if (TRIVY_CONFIG === undefined || cfg !== TRIVY_CONFIG.content || !/backend:\s*memory/.test(cfg) || flag === null || !(raw.run as string).includes(flag)) {
        bad('cache', at('trivy runs without its pinned config (cache.backend: memory), so it could keep a cache between runs.'));
      }
    }
    if (/--cache-dir\b|TRIVY_CACHE/.test(raw.run as string)) bad('cache', at('the step points a tool at a cache folder.'));
  }
  // ruling 4: a step that feeds the gate is never skipped on success and its failure always counts: no continue-on-error,
  // and `if:` only success(), or always() on an upload or a scrub (so a failed job still hands its result to the gate)
  // fix round 1 (ruling 2): except on the gate's baseline and clean-run marker uploads, whose failure is never a gate failure; their job and
  // place (job gate, after the gate step) are the shared order rule's (gateUploadProblems)
  const optionalGateUpload = kind === 'upload-artifact' && typeof withs.name === 'string' && GATE_OPTIONAL_UPLOADS.has(withs.name);
  if (raw['continue-on-error'] !== undefined && raw['continue-on-error'] !== false && !(optionalGateUpload && raw['continue-on-error'] === true)) bad('template', at('continue-on-error would let a failed step pass; pipegen sets it only on the gate\'s baseline and clean-run marker uploads.'));
  // G4 (G21): the base scan's baseline conditions, judged per job (judgeBaselineIfs): the plain form on a tool or stage step, the always() form on a scrub or an upload
  const baselineIf = (raw.if === BASELINE_MISSING_IF && (kind === 'tool' || kind === 'stage')) || (raw.if === BASELINE_MISSING_ALWAYS_IF && (kind === 'upload-artifact' || kind === 'scrub'));
  if (raw.if !== undefined && raw.if !== 'success()' && !baselineIf && !(raw.if === 'always()' && (kind === 'upload-artifact' || kind === 'upload-sarif' || kind === 'scrub'))) {
    bad('template', at(`if: ${safeText(String(raw.if), 20)} could skip this step while the job passes (only success(), or always() on an upload or a scrub).`));
  }
  const secrets = judgeSecrets(fc, at, withs, env, kind, appRunning);
  return { step, ...(match === undefined ? {} : { match }), kind, harmlessId, secrets, readsWorkspace: reads, ...(entryId === undefined ? {} : { entryId }) };
}

/** Which rendered run step this one is: equal to one in every field that runs (name aside), the slots judged by slots.ts. */
function matchRun(ex: Expectations, s: RenderedStep): Expected | 'near' | null {
  const core = coreOf(s);
  for (const e of ex.runs) {
    if (e.slots.size === 0) {
      if (isDeepStrictEqual(core, coreOf(e.step))) return e;
      continue;
    }
    const env = s.env ?? {};
    const masked = Object.fromEntries(Object.entries(env).filter(([k]) => !e.slots.has(k)));
    const want = Object.fromEntries(Object.entries(e.step.env ?? {}).filter(([k]) => !e.slots.has(k)));
    if (!isDeepStrictEqual({ ...core, env: masked }, { ...coreOf(e.step), env: want })) continue;
    if ([...e.slots].every(([k, kind]) => typeof env[k] === 'string' && slotProblem(kind, env[k]) === null)) return e;
  }
  // the repo `npm ci` of a folder: the same step for every tool that asks for it, with the pins merged (dedupeJobSteps)
  if (s.id?.startsWith('pipegen-npm-ci-') === true) {
    const strip = (x: RenderedStep): RenderedStep => ({ ...(coreOf(x) as unknown as RenderedStep), name: '' });
    const e = ex.runs.find((r) => r.step.id === s.id && sameDedupeContent(strip(r.step), strip(s)));
    if (e !== undefined) return e;
  }
  return s.id !== undefined && ex.runIds.has(s.id) ? 'near' : null;
}

/** A `uses:` step: its pin, and as a reviewed action its template. Returns its kind and whether it runs the app (a declared secret may reach it). */
function judgeUses(fc: FileCtx, at: (m: string) => string, uses: string, withs: Obj, env: Obj, raw: Obj): { appRunning: boolean; kind: StepKind; entryId?: string } {
  const bad = issueFor(fc);
  const other = { appRunning: false, kind: 'unrecognised' as StepKind };
  if (uses.startsWith('docker://')) {
    const image = uses.slice('docker://'.length);
    if (!/@sha256:[0-9a-f]{64}$/.test(image)) bad('unpinned', at(`${show(uses)} runs an image by tag; whoever controls the tag controls what runs.`));
    else if (!fc.ex.images.has(image)) bad('unknown-pin', at(`${show(uses)} is not a reviewed image at its reviewed digest.`));
    else bad('template', at('pipegen runs a reviewed image with its own docker step, never as a docker:// action.'));
    return other;
  }
  const k = usesKey(uses);
  if (k === null || !COMMIT_SHA_RE.test(k.ref)) { bad('unpinned', at(`${show(uses)} is not pinned to a 40-character commit.`)); return other; }
  const central = centralOf(fc.draft);
  if (central !== null && k.path.startsWith(central.prefix)) {
    // ruling 2: the central repo only at the commit pipegen recorded, and with every other check (no plain env, no folder)
    if (k.ref !== central.sha) bad('unknown-pin', at(`${show(uses)} is the central repo at a commit pipegen did not record.`));
    // fix round 2, ruling 4: the action file must be a central file pipegen is writing (so it is judged), and the step takes
    // only the inputs that file declares
    const head = uses.slice(0, central.prefix.length);
    const rel = head.toLowerCase() === central.prefix ? uses.slice(central.prefix.length, uses.lastIndexOf('@')) : '';
    const action = PLAIN_REL_RE.test(rel) ? ['action.yml', 'action.yaml'].map((n) => fc.others.get(`central:${rel}/${n}`)).find((x) => x !== undefined) : undefined;
    if (action === undefined) bad('unknown-pin', at(`${show(uses)} is not a central action file pipegen is writing, so what it runs can not be judged.`));
    else {
      const inputs = isObj(action.js.inputs) ? action.js.inputs : {};
      for (const name of Object.keys(withs)) if (!Object.hasOwn(inputs, name)) bad('template', at(`the central action ${show(rel)} declares no input ${show(name)}.`));
    }
    for (const [name, v] of Object.entries(env)) {
      const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
      if (m === null || m[1] !== name) bad('template', at(`a central action step's env may only map a secret under its own name (${show(name)}).`));
    }
    if (raw['working-directory'] !== undefined) bad('template', at('an action step takes no working-directory.'));
    return { appRunning: false, kind: 'central' };
  }
  if (CENTRAL_LIKE_RE.test(k.path) && !fc.ex.actionPaths.has(k.path)) {
    bad('unknown-pin', at(`${show(uses)} looks like a central pipelines repo, but pipegen recorded no central commit for this repository's owner.`));
    return other;
  }
  const t = fc.ex.actions.get(`${k.path}@${k.ref}`);
  if (t === undefined) {
    if (fc.ex.actionPaths.has(k.path)) bad('unknown-pin', at(`${show(uses)} is a reviewed action at another commit than its reviewed pin.`));
    else {
      bad('unknown-pin', at(`${show(uses)} is not a reviewed action (the whole path counts, sub-path included).`));
      bad('unreviewed', at(`${show(uses)} is not on the reviewed list, so pipegen never runs it.`));
    }
    return other;
  }
  const refusal = containerRefusal(t, k.path);
  if (refusal !== null) bad('unpinned', at(`container action: ${refusal}.`));
  judgeTemplate(fc, at, t, k.path, withs);
  for (const [name, v] of Object.entries(env)) {
    const m = typeof v === 'string' ? SECRET_REF_RE.exec(v) : null;
    if (m === null || m[1] !== name) bad('template', at(`an action step's env may only map a secret under its own name (${show(name)}).`));
  }
  if (raw['working-directory'] !== undefined) bad('template', at('an action step takes no working-directory.'));
  const appRunning = t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
  // the gate action in scrub mode under a scrub id is kind scrub; in any other mode (or under another id) it is the gate (ruling B1 part 4)
  // C1c: in stage mode under a stage id it is kind stage (the stage folder of a secrets scan)
  const kind = t.id === PIPEGEN_ACTION_IDS.gate && isScrubStep(raw as unknown as RenderedStep) ? 'scrub'
    : t.id === PIPEGEN_ACTION_IDS.gate && isStageStep(raw as unknown as RenderedStep) ? 'stage'
      : own(ENTRY_KIND, t.id) ?? (appRunning ? 'repo-code' : 'tool');
  return { appRunning, kind, entryId: t.id };
}

/** The template rule (S15): every fixed input at its value, every choice present and inside its list, nothing else but a renderer-filled input that passes its checker and condition. */
function judgeTemplate(fc: FileCtx, at: (m: string) => string, t: ReviewedTool, path: string, withs: Obj): void {
  const bad = issueFor(fc);
  const fixed = t.fixedInputs.with ?? {};
  const all = Object.fromEntries(Object.entries(withs).map(([k, v]) => [k, typeof v === 'string' ? v : String(v)]));
  for (const [k, v] of Object.entries(fixed)) {
    // C5b: an upload's `if-no-files-found` is `error`, except `ignore` on the gate's two optional files (the baseline and the marker)
    const want = path === PLATFORM_USES['upload-artifact'] && k === 'if-no-files-found' ? uploadIfNoFiles(withs.name) : v;
    if (withs[k] !== want) bad('template', at(`${t.id} must have ${safeText(k, 40)}: ${show(want)} (a reviewed fixed input${want === v ? '' : ', for this artifact'}).`));
  }
  // the gate action does one thing per mode and has no default: a step without a mode would run whatever the action's own default is
  if (t.id === PIPEGEN_ACTION_IDS.gate && withs.mode === undefined) bad('template', at(`${t.id} must set its mode (scrub, stage, gate, find-run, nightly or baseline-check); the action has no reviewed default.`));
  for (const [k, values] of Object.entries(t.choices)) {
    const v = withs[k];
    // G4: Bullfrog's allowed-ips may be left out: its default allows no IP at all (block mode lets only the allowed domains through), the tighter
    // setting; the Docker range is written only for a job whose containers talk over the Docker networks (egress.ts renderEgressStep)
    if (v === undefined && path.toLowerCase() === BULLFROG_USES && k === 'allowed-ips') continue;
    if (v === undefined) bad('template', at(`${t.id} must set its choice ${show(k)} (left out, the action's own default would run, which nobody reviewed).`));
    // E9 (ruling B5): Bullfrog's allowed-domains carries the hosts of whole reviewed sets, never a label (the bundled rule)
    else if (path.toLowerCase() === BULLFROG_USES && k === 'allowed-domains') {
      const p = allowedDomainsProblem(v, values);
      if (p !== null) bad('template', at(`${t.id}'s allowed-domains: ${safeText(p, 160)}.`));
    } else if (typeof v !== 'string' || !values.includes(v)) bad('template', at(`${t.id}'s ${safeText(k, 40)} must be one of ${values.join(', ')}.`));
  }
  for (const [k, v] of Object.entries(withs)) {
    if (Object.hasOwn(fixed, k) || Object.hasOwn(t.choices, k)) continue;
    const table = own(RENDERER_INPUTS, path);
    if (table === undefined || own(table, k) === undefined) { bad('template', at(`${t.id} takes no input ${show(k)} from pipegen.`)); continue; }
    const problems = rendererInputProblems(path, { [k]: typeof v === 'string' ? v : String(v) }, all);
    if (problems.length > 0) bad('template', at(problems.map((p) => safeText(p, 160)).join(' ')));
  }
}

/**
 * S9: every secret a step names is in the allowed set; a declared app secret reaches only a step that runs the app;
 * pipegen's own only a reviewed action that does not run the repo's code (never a run step, a central or unknown action).
 * Returns the names, for the job's privilege.
 */
function judgeSecrets(fc: FileCtx, at: (m: string) => string, withs: Obj, env: Obj, kind: StepKind, appRunning: boolean): Set<string> {
  const bad = issueFor(fc);
  const names = new Set<string>();
  for (const v of [...Object.values(withs), ...Object.values(env)]) {
    if (typeof v !== 'string') continue;
    for (const m of v.matchAll(SECRET_USE_RE)) names.add(m[1] as string);
  }
  const ownOk = !appRunning && !['tool', 'scrub', 'stage', 'repo-code', 'unrecognised', 'central'].includes(kind);
  // a recognised scrub step names the fingerprint key and nothing else of pipegen's (ruling B1 part 6)
  const scrubOk = (n: string): boolean => kind === 'scrub' && !appRunning && n === SCRUB_SECRET;
  for (const n of names) {
    if (!fc.ex.allowed.has(n)) { bad('permissions', at(`the secret ${show(n)} is neither declared by a step of this pipeline nor one of pipegen's own.`)); continue; }
    if (SIGNING_KEY_SECRETS.has(n) && kind !== 'sign') { bad('injection', at(`the signing secret ${show(n)} reaches a step that is not pipegen's sign step; only that step names it.`)); continue; }
    if (fc.ex.declared.has(n) && !PIPEGEN_SECRETS.includes(n)) {
      if (!appRunning) bad('injection', at(`the declared secret ${show(n)} reaches a step that does not run the app (a scanner, linter, upload or setup step never gets one).`));
    } else if (!ownOk && !scrubOk(n)) bad('injection', at(`pipegen's own secret ${show(n)} reaches a step that runs code pipegen did not review as harmless.`));
  }
  return names;
}

// ---------- an edited user workflow (the marker, types.ts PipegenInserted) ----------

/** Needs as a list, whatever form they were written in. */
const needsList = (v: unknown): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);


function judgeEdited(fc: FileCtx, parsed: Parsed, mark: PipegenInserted): void {
  const bad = issueFor(fc);
  const existing = fc.draft.profile.existingWorkflows.find((w) => w.path === fc.file.path);
  if (fc.file.repo !== 'app' || existing === undefined || !WORKFLOW_PATH_RE.test(fc.file.path)) {
    bad('template', 'The file is marked as an edited user workflow, but it is not one of the repository\'s existing workflows.');
    return;
  }
  if (!Array.isArray(mark.jobs) || mark.jobs.length === 0 || !Array.isArray(mark.needs) || typeof mark.original !== 'string') { bad('template', 'The edit mark is incomplete.'); return; }
  const orig = parseYaml(mark.original, 'user');
  if (!('parsed' in orig)) { bad('template', `The user's original workflow can not be read (${orig.problems.join('; ')}), so pipegen can not show its edit is only the inserted job.`); return; }
  const jobs = parsed.js.jobs;
  const origJobs = orig.parsed.js.jobs;
  if (!isObj(jobs) || !isObj(origJobs)) { bad('template', 'The workflow has no jobs map.'); return; }
  judgeUserTop(fc, parsed.js, mark);
  // pipegen's own parts: present, new, and free of anchors and aliases
  for (const id of mark.jobs) {
    if (!Object.hasOwn(jobs, id)) bad('template', `The job ${show(id)} pipegen inserted is not in the file.`);
    if (Object.hasOwn(origJobs, id)) bad('template', `The job ${show(id)} is the user's own, not one pipegen inserted.`);
    const p = jobPair(parsed.doc, id);
    if (p !== undefined && hasAnchorOrAlias(p.value)) bad('injection', `The job ${show(id)} pipegen inserted uses a YAML anchor or alias.`);
  }
  for (const id of Object.keys(jobs)) if (!Object.hasOwn(origJobs, id) && !mark.jobs.includes(id)) bad('template', `The job ${show(id)} is new, but not marked as inserted by pipegen.`);
  // the file without pipegen's parts must be the original exactly
  const rest: Obj = structuredClone(parsed.js);
  const restJobs = rest.jobs as Obj;
  for (const id of mark.jobs) delete restJobs[id];
  for (const n of mark.needs) {
    const j = isObj(n) && typeof n.job === 'string' ? restJobs[n.job] : undefined;
    const added: unknown[] = isObj(n) && Array.isArray(n.added) ? n.added : [];
    if (!isObj(j) || !isObj(origJobs[n.job])) { bad('template', `The needs pipegen added are on ${show(n?.job)}, which is not a job of the user's workflow.`); continue; }
    const p = jobPair(parsed.doc, n.job);
    const needsNode = isMap(p?.value) ? p.value.get('needs', true) : undefined;
    if (hasAnchorOrAlias(needsNode)) bad('injection', `The needs of ${show(n.job)} use a YAML anchor or alias.`);
    // a gated job that can run although a job it needs failed is not gated (ruling 5; fix round 2, ruling 1)
    if (!gatedIfAllowed(j.if)) bad('template', `The job ${show(n.job)} has an if: other than success() or success() && <condition without a status function or a top-level ||>, so it could run even when pipegen's check fails; it would not really be gated.`);
    const list = needsList(j.needs);
    for (const a of added) {
      if (typeof a !== 'string' || !mark.jobs.includes(a)) bad('template', `The need ${show(a)} added to ${show(n.job)} is not a job pipegen inserted.`);
      if (!list.includes(a)) bad('template', `The job ${show(n.job)} does not need ${show(a)}, which the edit says pipegen added.`);
    }
    const kept = list.filter((x) => !added.includes(x));
    const before = (origJobs[n.job] as Obj).needs;
    if (before === undefined && kept.length === 0) delete j.needs;
    else if (typeof before === 'string' && kept.length === 1) j.needs = kept[0];
    else j.needs = kept;
  }
  if (!isDeepStrictEqual(rest, orig.parsed.js)) bad('template', 'The edit changes the user\'s workflow beyond the job and needs pipegen inserted.');
  // G1 (C5a, C7s): the jobs pipegen inserts follow the same layout rules under the user's triggers (no gate on a push to another branch, no find-run on schedule)
  judgeLayoutJobs(fc, parsed.js.on, triggersOf(parsed.js.on), jobs, mark.jobs);
  judgeJobs(fc, jobs, mark.jobs);
}

/**
 * Ruling 5: the parts of the user's own file that apply to pipegen's jobs too. Any of these refuses the insert, so Plan G
 * writes a file of its own instead: a trigger that runs with the target's power on outside code (pull_request_target, or
 * workflow_run in a file that checks code out), a workflow env with a dangerous name or an expression, `defaults` other than
 * `run.shell` bash or sh, and top-level permissions beyond what the inserted jobs may have.
 */
function judgeUserTop(fc: FileCtx, js: Obj, mark: PipegenInserted): void {
  const bad = issueFor(fc);
  const triggers = triggersOf(js.on) ?? [];
  if (triggers.includes('pull_request_target')) bad('injection', 'The user\'s workflow runs on pull_request_target (with secrets and a write token for outside pull requests); pipegen will not insert its job there. Plan G writes a separate file.');
  if (triggers.includes('workflow_run')) bad('injection', 'The user\'s workflow runs on workflow_run (with the target\'s power, after another run that may have run outside code); pipegen will not insert its job there. Plan G writes a separate file.');
  judgeEnv(fc, js.env, 'the user\'s workflow');
  const d = js.defaults;
  if (d !== undefined) {
    const run = isObj(d) ? d.run : undefined;
    const ok = isObj(d) && Object.keys(d).every((k) => k === 'run') && isObj(run) && Object.keys(run).every((k) => k === 'shell') && (run.shell === undefined || run.shell === 'bash' || run.shell === 'sh');
    if (!ok) bad('injection', 'The user\'s workflow has defaults that would change pipegen\'s steps (only defaults.run.shell bash or sh is accepted).');
  }
  const p = js.permissions;
  if (p !== undefined) {
    const ceiling: Record<string, number> = {};
    for (const id of mark.jobs) for (const [k, v] of Object.entries(ceilingOf(id))) ceiling[k] = Math.max(ceiling[k] ?? 0, v);
    if (!isObj(p)) bad('permissions', `The user's workflow sets permissions ${show(p)} for every job, more than pipegen's inserted jobs may have.`);
    else for (const [k, v] of Object.entries(p)) {
      const level = typeof v === 'string' ? own(LEVEL, v) : undefined;
      if (level === undefined || level > (own(ceiling, k) ?? 0)) bad('permissions', `The user's workflow sets ${safeText(k, 40)}: ${safeText(String(v), 10)} at the top, more than pipegen's inserted jobs may have.`);
    }
  }
}

function hasAnchorOrAlias(node: unknown): boolean {
  if (node === undefined || node === null) return false;
  let found = false;
  visit(node as YamlNode, {
    Alias() { found = true; return visit.BREAK; },
    Node(_, n) { if (n.anchor !== undefined) { found = true; return visit.BREAK; } return undefined; },
  });
  return found;
}

// ---------- a composite action file ----------

function judgeAction(fc: FileCtx, js: Obj): void {
  const bad = issueFor(fc);
  for (const k of Object.keys(js)) if (!ACTION_KEYS.has(k)) bad('template', `The action key ${show(k)} is not one pipegen writes.`);
  const runs = js.runs;
  if (!isObj(runs) || runs.using !== 'composite' || !Array.isArray(runs.steps)) { bad('template', 'A local action pipegen writes is a composite action with a list of steps.'); return; }
  const judged = judgeJobSteps(fc, 'the action', runs.steps, false);
  // G2-R1 m1: the signing, verification and image hand-off steps are held to their jobs, which a composite action has none of
  judged.forEach((x, i) => {
    if (x.kind === 'sign' || x.kind === 'verify' || x.kind === 'image-archive' || x.kind === 'image-check') bad('permissions', `In the action, step ${i + 1}: a ${x.kind} step runs only in its own job, never in a composite action.`);
  });
}

// ---------- the image base twin (C-MUST-1, ruling B6) ----------

/**
 * A base twin of an image or URL scan must scan the base commit's own image (or app), never the head's: with the same input every head
 * finding would also be a base finding, so every image CVE would look old (a wrong pass). A base-twin step is refused when its image or URL
 * equals one a head step of the same check reads (in any file of the pipeline), when the head reads the PR's image archive (no input to
 * compare with: B6 has no base build yet), or when no head step of the check is there at all (fail closed).
 */
/**
 * Controller ruling G2-R-sec 3: what a twin input is compared on, never its text. An image: its sha256 digest (lower case) and its parsed
 * reference (parseImageRef: registry aliases and docker.io/library folded) with that digest; an unparsable one keeps a key of its own text
 * (the slot check refuses it anyway). A URL: the loopback app on its port (localhost and 127.0.0.1 are one host; the path does not matter).
 * Two inputs are the same when any key is shared.
 */
function twinKeys(kind: SlotKind, value: string): string[] {
  if (kind === 'image-digest') {
    const at = value.lastIndexOf('@');
    const digest = /^sha256:[0-9a-f]{64}$/i.test(value.slice(at + 1)) ? value.slice(at + 1).toLowerCase() : null;
    const ref = at > 0 ? parseImageRef(value.slice(0, at)) : null;
    return [`text:${value.toLowerCase()}`, ...(digest === null ? [] : [`digest:${digest}`]), ...(ref === null || digest === null ? [] : [`ref:${ref.display.toLowerCase()}@${digest}`])];
  }
  try {
    const u = new URL(value);
    const host = u.hostname === '127.0.0.1' || u.hostname.toLowerCase() === 'localhost' ? 'loopback' : u.hostname.toLowerCase();
    return [`text:${value.toLowerCase()}`, `url:${host}:${u.port === '' ? (u.protocol === 'https:' ? '443' : '80') : u.port}`];
  } catch {
    return [`text:${value.toLowerCase()}`];
  }
}

function judgeBaseTwins(ex: Expectations, add: Add): void {
  for (const b of ex.twinInputs) {
    if (!b.source.endsWith(':base')) continue;
    const head = b.source.slice(0, -':base'.length);
    const heads = ex.twinInputs.filter((h) => h.source === head);
    const why = ex.twinInputs.some((h) => h.source === `${head}${ARCHIVE_SUFFIX}`) ? 'the head check reads the pull request\'s own image archive, and pipegen builds no image of the base commit yet'
      : heads.length === 0 ? 'no head step of the same check is there to compare it with'
        : heads.some((h) => h.keys.some((k) => b.keys.includes(k))) ? 'it reads the same input as the head check, so every head finding would look old (a wrong pass)' : null;
    if (why !== null) add(b.file.path, 'not-gate-readable', `A base twin of an image or URL scan is refused: ${why}. The base twin must scan the base commit's own image or app; until pipegen builds one there is no base twin.`, undefined, b.file.repo);
  }
}

// ---------- the blocking rule (B7) ----------

/**
 * Every blocking need (outside pipegen's own jobs and the pre-commit layer) has a reviewed tool step or a project script,
 * else `not-gate-readable` (ruling 7). A findings check (B7) whose tool writes no SARIF the gate reads is demoted with a note.
 */
function blockingRule(draft: PipelineDraft, ex: Expectations, add: Add, notes: string[]): string[] {
  const demoted: string[] = [];
  const formatOf = reviewedFormatOf(ex);
  draft.needs.forEach((need, i) => {
    if (!need.blocking) return;
    const category = Object.hasOwn(NEED_ID_CATEGORY, need.id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[need.id] : undefined;
    // a spec counts only if it rendered and one of its rendered run steps is in a parsed file (an action spec has none: it counts as reviewed); the job list counts the same way
    const formats = draft.steps.flatMap((s, si) => {
      const f = isObj(s) && s.needId === need.id && s.service === need.service ? formatOf(s, si) : undefined;
      return f === undefined ? [] : [f];
    });
    // G4b-R1 I1: a project script or the repo's own tool counts only when a judged file holds its final step (ex.matched), like a reviewed spec
    const script = draft.profile.services.some((s) => (projectScriptFor(need, s) !== null && ex.matched.has(`script:${need.id}:${s.name}`))
      || (repoToolFor(need, s) !== null && ex.rendered.has(`${REPO_TOOL_SOURCE}:${need.id}:${s.name}`) && ex.matched.has(`${REPO_TOOL_SOURCE}:${need.id}:${s.name}`)));
    if (formats.length === 0 && !script && need.layer !== 'pre-commit' && !(category !== undefined && PIPEGEN_JOB_CATEGORIES.has(category))) {
      add(`draft.needs[${i}]`, 'not-gate-readable', `The blocking check ${show(need.id)}${need.service === undefined ? '' : ` for ${show(need.service)}`} has no reviewed tool step, no project script and no repo built-in, so the gate would have nothing to read.`);
      return;
    }
    // the category comes from the need id, never from the tool
    if (category !== undefined && !FINDINGS_CATEGORIES.has(category)) return;
    if (category !== undefined && formats.every((f) => readableFormat(category, f))) return;
    let key = need.id;
    if (need.service !== undefined) {
      try { key = `${need.id}--${slug(need.service)}`; } catch (e) { if (!(e instanceof ArtifactNameError)) throw e; }
    }
    if (demoted.includes(key)) return;
    demoted.push(key);
    notes.push(category === undefined
      ? `The check ${show(need.id)} is not one pipegen knows how the gate reads, so it runs as a warning only (non-blocking).`
      : `The check ${show(need.id)}${need.service === undefined ? '' : ` for ${show(need.service)}`} is judged by its findings, but its tool writes no SARIF the gate can read, so it runs as a warning only (non-blocking).`);
  });
  return demoted;
}

// ---------- the referee ----------

const fileKind = (f: CreatedFile): 'workflow' | 'action' | null => (WORKFLOW_PATH_RE.test(f.path) ? 'workflow' : ACTION_PATH_RE.test(f.path) ? 'action' : null);

/**
 * Judges the files pipegen is about to propose. `platform` from platformActions, `reviewed` from loadReviewed, `linters` from
 * ensureLinters and `ghToken` the read-only token zizmor's online audits use (7b); `deps.runLinters` runs the linters (default:
 * the real runLinters). Never throws for anything in the files.
 */
export function referee(allFiles: CreatedFile[], draft: PipelineDraft, platform: PlatformActions, reviewed: ReviewedTool[], linters: Linters, ghToken: string | null, deps: RefereeDeps = {}): Promise<RefereeReport> {
  // D5 (fix round 3): with a vault, every cutter below scrubs with it before it cuts
  return withActiveVault(deps.vault, () => judgeFiles(allFiles, draft, platform, reviewed, linters, ghToken, deps));
}

async function judgeFiles(allFiles: CreatedFile[], draft: PipelineDraft, platform: PlatformActions, reviewed: ReviewedTool[], linters: Linters, ghToken: string | null, deps: RefereeDeps): Promise<RefereeReport> {
  const issues: RefereeIssue[] = [];
  const notes: string[] = [];
  // D5 (B1): with a vault, everything shown is checked and cleaned AS DISPLAYED (safeText joins a value split by an invisible character back
  // together) and BEFORE any cut: the one place issues and notes are built. Without a vault nothing changes.
  const vault = deps.vault;
  const cleanText = (t: string): string => (vault === undefined ? t : scrubForDisplay(vault, t, (x) => x));
  const add: Add = (file, check, message, line, repo) => { issues.push({ file: vault === undefined ? safeText(file, 200) : scrubForDisplay(vault, file, (x) => safeText(x, 200)), check, message: cleanText(message), ...(line === undefined ? {} : { line }), ...(repo === undefined ? {} : { repo: cleanText(repo) as typeof repo }) }); };

  // D5 (S8, I1, B1): a file whose path, text, reason or repo holds a value the user gave pipegen (in any form, or only once displayed) gets ONE fixed
  // issue, and so does a draft that holds one. The WHOLE draft is then refused and nothing else is judged: no other check reads the text, so no
  // other message can quote a piece of the value.
  // fix round 4 (B6): ESC or a C1 control counts as a value (vaultHolds), whatever the check does
  const holds = (t: unknown): boolean => vault !== undefined && typeof t === 'string' && vaultHolds(vault, t);
  // the text a file shows AFTER it is decoded: YAML escapes in a workflow or action, JSON escapes in a package file (parsed, then every key and string checked)
  const decodedHolds = (f: CreatedFile): boolean => {
    if (vault === undefined || typeof f?.content !== 'string' || typeof f.path !== 'string') return false;
    try {
      if (fileKind(f) !== null) {
        const r = parseYaml(f.content, f.inserted === undefined ? 'strict' : 'user');
        // fix round 4 (B7): a file the strict parse refuses is still decoded, leniently (a linter or a judge may decode it its own way)
        return 'parsed' in r ? anyString(r.parsed.js, holds) : anyYamlScalar(f.content, holds);
      }
      if (/(?:^|\/)package(?:-lock)?\.json$/.test(f.path)) return anyString(JSON.parse(f.content), holds);
      if (/\.ya?ml$/i.test(f.path)) return anyYamlScalar(f.content, holds);
    } catch { /* unreadable text is checked as written only */ }
    return false;
  };
  const holdsValue = (f: CreatedFile): boolean => [f?.path, f?.content, f?.reason, f?.repo].some(holds) || decodedHolds(f);
  const taintedFiles = allFiles.filter(holdsValue);
  const draftHolds = vault !== undefined && anyString(draft, holds);
  if (taintedFiles.length > 0 || draftHolds) {
    for (const f of taintedFiles) add(f.path, 'secret-value', 'The file holds a value you gave pipegen as a secret (or its base64 or URL form); pipegen never writes one into a file.', undefined, f.repo);
    if (draftHolds) add('(draft)', 'secret-value', 'The draft holds a value you gave pipegen as a secret (or its base64 or URL form); pipegen never writes one into a file.');
    return { ok: false, issues, demoted: [], notes: [] };
  }
  const files = allFiles;

  // S18: no secret value in any file (rule names only, never the value)
  for (const f of files) {
    const hits = findSecretLike(f.content);
    if (hits.length > 0) add(f.path, 'secret-value', `The file holds text that looks like a secret value (${hits.join(', ')}); pipegen never writes one into a file.`);
  }

  for (const d of duplicatePathProblems(files)) add(d.file.path, 'template', d.message, undefined, d.file.repo);

  // D4 I1: the compose plan is the one source. Its runtime env counts only when the file it computes is among the files judged together and passes its judge.
  // G2 (S14, D-m4): one vault input. When the created-file inputs carry no check of their own, the referee hands the judges the vault's
  // (vaultHolds: ESC and C1 controls count as a value too), so passing only the vault never refuses PIPEGEN.md
  const given = deps.createdInputs ?? {};
  const inputs = given.containsKnownValue === undefined && vault !== undefined ? { ...given, containsKnownValue: (t: string) => vaultHolds(vault, t) } : given;
  const judgeEnv0 = { reviewed, inputs, files };
  const composeFile = files.find((f) => f.repo === 'app' && f.path === COMPOSE_PATH);
  let composeEnv: RuntimeEnv | null = null;
  const composeVerdict = composeFile === undefined ? null : createdFileProblems(composeFile, draft, deps.createdRules, judgeEnv0);
  // D4 carry C1: claimed AND free of problems (an unclaimed file has no problems, but it is no judged compose file)
  if (composeVerdict !== null && composeVerdict.claimed && composeVerdict.problems.length === 0) {
    const plan = planCompose(draft.profile, loadBaseImages(), dockerfilesOf(files));
    if (plan.text !== null) composeEnv = plan.env;
  }
  const ex = expectations(draft, platform, reviewed, add, notes, composeEnv);
  // C8r1 (G5): a private repository's pipeline runs from its central workflows, pinned to the commit pipegen recorded; without a valid central
  // pin its find-run step and its callers have nothing to be judged against (a public one keeps its workflows in the app and has no pin)
  if (draft.profile.private === true && files.some((f) => f.repo === 'app' && fileKind(f) === 'workflow' && f.inserted === undefined) && centralOf(draft) === null) {
    add('(draft)', 'template', 'A private repository runs its pipeline from its central workflows at the commit pipegen recorded, and the draft has no valid central pin (<owner>/pipelines at a 40-character commit).');
  }
  const parsed = new Map<string, Parsed>();
  const lintable: CreatedFile[] = [];
  for (const f of files) {
    // every created path is judged or refused (final review r1, R1): a path that is not plain and normalized, or that is in
    // .github/ (any letter case) without being exactly a workflow or action file, would otherwise be skipped yet may land in .github/workflows/
    const pathProblem = createdPathProblem(f.path);
    if (pathProblem !== null) { add(f.path, 'template', `The file path is refused: ${pathProblem}; pipegen writes only plain, normalized paths.`, undefined, f.repo); continue; }
    const kind = fileKind(f);
    if (kind === null) {
      // not a workflow or action: a created-file rule (src/engine/created-files.ts) must claim it, else it is refused (D0a, B1)
      const v = createdFileProblems(f, draft, deps.createdRules, judgeEnv0);
      if (!v.claimed) {
        add(f.path, 'template', /^\.github\//i.test(f.path)
          ? 'The file path is in .github/ but is not a workflow (.github/workflows/<name>.yml) or a composite action (.github/actions/<folder>/action.yml) pipegen can judge, so it is not written.'
          : 'pipegen writes no file of this kind (no rule claims this path), so it is not written.', undefined, f.repo);
      }
      for (const m of v.problems) add(f.path, 'template', `pipegen refuses this file: ${m.replace(/\.$/, '')}.`, undefined, f.repo);
      // G9 (B7): PIPEGEN.md is built by a pure function of the draft; the file must be exactly what it builds again (the line judge above is the net)
      if (v.claimed && f.repo === 'app' && f.path === 'PIPEGEN.md') {
        const again = docRecomputeProblem(f, draft, reviewed);
        if (again !== null) add(f.path, 'template', `pipegen refuses this file: ${again}.`, undefined, f.repo);
      }
      continue;
    }
    if (f.edited !== undefined) add(f.path, 'template', 'Only a file of a registered kind can carry the edited marker; an edit to a workflow uses the inserted mark.', undefined, f.repo);
    // `inserted` marks an edited user WORKFLOW only; on a composite action it would relax the strict parse (anchors, aliases), so it is refused before the parse
    if (kind === 'action' && f.inserted !== undefined) { add(f.path, 'template', 'Only a workflow file can carry the mark of an edited user workflow.', undefined, f.repo); continue; }
    const r = parseYaml(f.content, f.inserted === undefined ? 'strict' : 'user');
    // fix round 4 (B7): with a vault, a file pipegen can not parse is not linted (a linter decodes and quotes it its own way); the parse issue says enough
    if (vault === undefined || !('problems' in r)) lintable.push(f);
    if ('problems' in r) {
      for (const p of r.problems) add(f.path, 'injection', `pipegen refuses this file: ${p}.`);
      continue;
    }
    parsed.set(`${f.repo}:${f.path}`, r.parsed);
    // S18 on the parsed values too: an escape (`"\x41…"`) or a folded scalar can hide a value from the raw-text scan
    const raw = findSecretLike(f.content);
    // each value on its own, with a `"` read as a line break: a JSON document held in a value (an npm closure lock) is
    // scanned string by string, as the raw scan sees it, so one URL and the next package name never make a "connection string"
    const hits = uniq(r.parsed.scalars.flatMap((v) => findSecretLike(v.replace(/"/g, '\n')))).filter((h) => !raw.includes(h));
    if (hits.length > 0) add(f.path, 'secret-value', `A value in the file, once parsed, looks like a secret (${hits.join(', ')}); pipegen never writes one into a file.`);
  }
  for (const f of files) {
    const p = parsed.get(`${f.repo}:${f.path}`);
    if (p === undefined) continue;
    const fc: FileCtx = { file: f, add, ex, draft, others: parsed, dbPwOk: 0, js: p.js };
    if (fileKind(f) === 'action') judgeAction(fc, p.js);
    else if (f.inserted !== undefined) judgeEdited(fc, p, f.inserted);
    else {
      judgeTop(fc, p.js);
      judgeJobs(fc, p.js.jobs);
    }
    // D4 (ruling B6): the generated database password's name is allowed only in the runtime-env step pipegen renders (recognised by exact content).
    // A file pipegen wrote whole is counted as a whole (any key, value, name or env of it); in an edited user workflow the user's own text is not judged,
    // so judgeStep checks the steps of the jobs pipegen added.
    if (f.inserted === undefined && dbPwCount(JSON.stringify(p.js)) > fc.dbPwOk) add(f.path, 'injection', DB_PW_MESSAGE, undefined, f.repo);
    else if (f.inserted !== undefined) {
      // an edited user workflow: the user's own text is not judged, but each job pipegen added is counted whole (steps, env, outputs, everything)
      const jobs = isObj(p.js.jobs) ? p.js.jobs : {};
      const total = f.inserted.jobs.reduce((n, id) => n + (Object.hasOwn(jobs, id) ? dbPwCount(JSON.stringify(jobs[id])) : 0), 0);
      if (total > fc.dbPwOk) add(f.path, 'injection', DB_PW_MESSAGE, undefined, f.repo);
    }
  }

  for (const check of ex.deferred) check();
  // GJ-R1 (review sec M1): workflow lint runs zizmor (DECISIONS #122): a draft whose workflow-lint check has no zizmor step, or a job
  // workflow-lint that runs none of the draft's zizmor steps, is refused (poutine never stands in for it)
  const zizmorSpec = (i: number): boolean => { const st = draft.steps[i]; return isObj(st) && st.needId === 'workflow-lint' && isObj(st.tool) && st.tool.id === WORKFLOW_LINT_TOOL; };
  if (draft.needs.some((n) => isObj(n) && n.id === 'workflow-lint') && !draft.steps.some((_st, i) => zizmorSpec(i))) {
    add('(draft)', 'unreviewed', `The draft's workflow lint check has no ${WORKFLOW_LINT_TOOL} step: workflow lint runs ${WORKFLOW_LINT_TOOL} (poutine only next to it), never another tool in its place.`);
  }
  for (const j of ex.jobs) {
    if (j.id !== 'workflow-lint') continue;
    const runs = j.judged.some((x) => { const m = /^spec:(\d+)$/.exec(x.match?.source ?? ''); return m !== null && zizmorSpec(Number(m[1])); });
    if (!runs) add(j.file, 'unreviewed', `The job "workflow-lint" runs no ${WORKFLOW_LINT_TOOL} step: workflow lint runs ${WORKFLOW_LINT_TOOL} (poutine only next to it), never another tool in its place.`);
  }
  // G5-R1 I1, carry G5→G7 1: a repository that signs never publishes an image unsigned: a job that pushes an image (build-push with push)
  // needs a sign job of the judged files holding the plan's sign (or attest) step. The mode is re-derived from the repository and its
  // capabilities (signingMode), never taken from the draft's recorded plan: a stripped plan is no way around it. Mode none is a repository
  // that signs nothing (private Free).
  const signingOwn = signingMode(draft.profile, draft.capabilities);
  if ((draft.signing !== undefined && draft.signing !== null) || signingOwn !== 'none') {
    const publishes = ex.jobs.some((j) => j.judged.some((x) => x.entryId === BUILD_PUSH_ID && x.step.with?.push !== 'false'));
    const signs = ex.jobs.some((j) => j.id === 'sign' && j.judged.some((x) => x.kind === 'sign' || x.kind === 'attest'));
    if (publishes && !signs) add('(draft)', 'permissions', `This repository signs in mode ${show(String(draft.signing?.mode ?? signingOwn))} and a job publishes an image, but the judged files hold no sign job with the plan's sign step: the image would be published unsigned.`);
  }
  judgeBaseTwins(ex, add);
  judgeUploadsPerFile(ex, add);
  const demoted = blockingRule(draft, ex, add, notes);

  // the workflow linters (7b): an issue on pipegen's lines, a note on a user's own
  if (lintable.length > 0) {
    let found: RefereeIssue[];
    try {
      found = await (deps.runLinters ?? runLinters)(lintable, linters, ghToken);
    } catch (e) {
      found = [{ file: lintable[0]?.path ?? '', check: 'actionlint', message: `The workflow linters could not run (${safeText(e instanceof Error ? e.message : String(e), 160)}).` }];
    }
    for (const i of found) {
      // matched by repo and path (ruling 7): a finding that does not name exactly one file is judged as pipegen's own
      const hit = lintable.filter((x) => x.path === i.file && (i.repo === undefined || x.repo === i.repo));
      const f = hit.length === 1 ? hit[0] : undefined;
      const lines = f === undefined ? null : pipegenLines(f);
      if (lines !== null && i.line !== undefined && !lines.has(i.line)) notes.push(`${safeText(cleanText(i.file), 200)}:${i.line}: ${safeText(cleanText(i.message), 300)} (on the user's own lines, not pipegen's)`);
      else add(i.file, i.check, i.message, i.line, i.repo);
    }
  }
  return { ok: issues.length === 0, issues, demoted: demoted.map(cleanText), notes: notes.map(cleanText) };
}
