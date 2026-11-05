// The job rules every layer shares (Plan B final-review fix round, minor 10), in one leaf module: the step shape, the order rule,
// the expression rule, the dangerous names and the workflow/action file paths. The renderer (render-step.ts), the YAML emitter,
// the referee and the linters import them from here, so no second copy can drift. It imports only the leaves render-error.ts,
// tool-flags.ts and types.ts (test/final-fix-b.test.ts and test/module-graph.test.ts check this).
import { EXPR, own, RenderError, show } from './render-error.js';
import { GATE_RESULT_ARTIFACT, resultArtifactName, SECRETS_RANGE_ARTIFACT, slug } from './artifact-names.js';
import { ARGV_POLICIES, BASE_CHECKOUT_REF, GATE_OPTIONAL_UPLOADS, RANGE_STEP_ENV, RANGE_TOOL, rangeScanStepId, isGateUploadName, CHECKER_STEP_ID_RE, GATE_USES_RE, isStagedTool, PLATFORM_USES, rendererInputProblems, RENDERER_INPUTS, scrubStepId, SCRUB_STEP_ID_RE, SETUP_STEP_ID_RE, sha16, stagePath, stageStepId, STAGE_STEP_ID_RE, TOOL_STEP_ID_RE } from './tool-flags.js';

/** One step of a job, as pipegen renders it. `usesComment` becomes the trailing `# <version>` comment on `uses:`. */
export interface RenderedStep {
  id?: string; name: string; if?: string; uses?: string; usesComment?: string; with?: Record<string, string>;
  run?: string; shell?: 'bash'; env?: Record<string, string>; 'working-directory'?: string;
  'continue-on-error'?: boolean; 'timeout-minutes'?: number;
}

/**
 * Env names a mapped secret must never take (ruling S9, widened in 6a fix round 1). One table, by family: each name
 * changes how a shell, a runtime, a package manager, a TLS or proxy setting, the C library, the locale or the runner
 * itself behaves, and 6b passes declared secrets into the tool's environment. Names are matched as a whole (`^…$`).
 * An ordinary application secret (STRIPE_KEY, GOOGLE_API_KEY, DATABASE_URL) is not caught.
 */
const DANGEROUS_NAMES: readonly { family: string; match: RegExp }[] = [
  { family: 'shell and process', match: /^(?:CI|PATH|HOME|BASH_ENV|ENV|SHELLOPTS|PS4|IFS|SHELL|PROMPT_COMMAND|TMPDIR|TMP|TEMP|LANG|LANGUAGE|TZ|TERM[A-Z0-9_]*)$/ },
  { family: 'runner, CI and pipegen', match: /^(?:GITHUB|RUNNER|ACTIONS|PIPEGEN)_/ },
  // an action reads its inputs from INPUT_<name> (the gate action reads every INPUT_* it finds, gate/src/main.ts readInputs), so an env of any
  // level, the job's or the workflow's too, could hand an action an input its `with` never gave (final review r1-1); in any case of the prefix
  { family: 'action inputs', match: /^INPUT_/i },
  { family: 'loader and libc', match: /^(?:LD_|DYLD_|MALLOC_|LC_)|^(?:GCONV_PATH|GLIBC_TUNABLES|HOSTALIASES|RES_OPTIONS|LOCALDOMAIN)$/ },
  { family: 'proxy and TLS', match: /_PROXY$|^(?:SSL_|CURL_|OPENSSL_)|^REQUESTS_CA_BUNDLE$/i },
  { family: 'node, npm, python and package indexes', match: /^(?:NODE_|NPM_CONFIG_|PYTHON|PIP_|UV_)|^npm_config_/ },
  { family: 'java, perl, ruby', match: /^(?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|PERLLIB)$|^(?:PERL5|RUBY|GEM_|BUNDLE_)/ },
  { family: 'rust and go', match: /^(?:CARGO_|RUSTUP_|RUSTFLAGS$)|^GO[A-Z0-9]*$/ },
  { family: 'git, docker, compose, buildx, XDG', match: /^(?:GIT_|DOCKER_|COMPOSE_|BUILDX_|BUILDKIT_|XDG_)/ },
  { family: 'the reviewed tools', match: /^(?:TRIVY_|HADOLINT_|PINACT_|SEMGREP_|COVERAGE_)/ },
  // build toolchains (6b, review R1-7): a compiler, linker, make or package-manager setting changes what a build runs
  { family: 'C, C++ and Go build', match: /^(?:CGO_|PKG_CONFIG_)|^(?:CC|CXX|AR|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|MAKEFLAGS)$/ },
  { family: 'js package managers and runtimes', match: /^(?:YARN_|PNPM_|BUN_|DENO_|COREPACK_)/ },
  // credentials that change what a tool does or where it talks (npm publish auth, the gh CLI's token and host): never mapped from a user-supplied secret
  { family: 'registry and gh CLI credentials', match: /^(?:NPM_TOKEN|GH_TOKEN|GH_HOST|GH_ENTERPRISE_TOKEN|GH_REPO|GH_CONFIG_DIR|GH_DEBUG|GH_PROMPT_DISABLED|GH_NO_UPDATE_NOTIFIER)$/i },
  { family: 'jvm, .NET, php, conda, rust compiler', match: /^(?:COMPOSER_|CONDA_|DOTNET_|NUGET_|RUSTC)|^(?:MAVEN_OPTS|GRADLE_OPTS|GRADLE_USER_HOME|PHPRC|PHP_INI_SCAN_DIR|SSH_ASKPASS)$/ },
];
/** Whether a variable name is one a mapped secret (or a job-level variable) must never take. Shared with the referee. */
export const isDangerousName = (name: string): boolean => DANGEROUS_NAMES.some((d) => d.match.test(name));

/** Why a candidate counts as reviewed: both marks (the type says so, a cast or a JSON copy might not). */
export const isReviewed = (c: unknown): boolean => typeof c === 'object' && c !== null && (c as { source?: unknown }).source === 'reviewed' && (c as { reviewed?: unknown }).reviewed === true;

/** The keys of a step, in the order they are written. */
export const STEP_KEYS = ['id', 'name', 'if', 'uses', 'with', 'run', 'shell', 'env', 'working-directory', 'continue-on-error', 'timeout-minutes'] as const;

// ---------- file paths ----------
// A path segment: plain characters, and never `.` or `..` (so no path climbs out of its folder).
const SEG = '(?!\\.{1,2}(?:/|$))[A-Za-z0-9._-]+';
/** A workflow file pipegen may write or lint. The file name has no `/`, so it can not hold a `..` segment. */
export const WORKFLOW_PATH_RE = /^\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml$/;
/** The Windows device names: a file with one of these as its base name (before the first `.`) can not be created or read there. */
const WINDOWS_RESERVED_RE = /^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$/i;
const MAX_PATH_SEGMENT = 100;
const MAX_PATH_TOTAL = 200;
/**
 * Why a created file's path is not a plain, normalized repo-relative path, or null (final review r1, R1; CF-1 / preflight S1): only
 * `A-Z a-z 0-9 . _ - /` (so no space, `%`, `?`, `#`, `:`, `@`, `+`, `~`, backslash, control character or non-ASCII letter); no leading
 * `/`; no empty, `.` or `..` segment (so `./x`, `a/../b`, `a//b` and a trailing `/` are refused); no segment that starts with `-`
 * (an option for any tool that gets the path as an argument), ends with `.` (Windows drops the dot), is `.git` in any letter case, or
 * has a Windows device name as its base name (`CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9`, any case, any extension); at most 100
 * characters in a segment and 200 in all. One rule for every producer. Joined onto a folder, a path that passes can not land
 * in `.github/workflows/` unless it says so.
 */
export function createdPathProblem(path: string): string | null {
  if (typeof path !== 'string' || path === '') return 'the path is empty';
  if (!/^[\x20-\x7e]+$/.test(path)) return 'the path has a character other than printable ASCII (a control character, NUL or non-ASCII letter)';
  if (path.includes('\\')) return 'the path has a backslash';
  if (path.startsWith('/')) return 'the path is absolute';
  const segs = path.split('/');
  if (segs.some((seg) => seg === '' || seg === '.' || seg === '..')) return 'the path has an empty, . or .. segment';
  if (!/^[A-Za-z0-9._/-]+$/.test(path)) return 'the path has a character other than letters, digits, . _ - and /';
  if (path.length > MAX_PATH_TOTAL) return `the path is longer than ${MAX_PATH_TOTAL} characters`;
  for (const seg of segs) {
    if (seg.length > MAX_PATH_SEGMENT) return `a path segment is longer than ${MAX_PATH_SEGMENT} characters`;
    if (seg.startsWith('-')) return 'a path segment starts with a dash';
    if (seg.endsWith('.')) return 'a path segment ends with a dot';
    if (seg.toLowerCase() === '.git') return 'the path has a .git segment';
    if (WINDOWS_RESERVED_RE.test(seg.split('.')[0] ?? '')) return 'a path segment is a Windows device name';
  }
  return null;
}

/** A composite action file pipegen may write or lint: no empty, `.` or `..` segment anywhere in its path, at most 200 characters between `actions/` and `/action.yml`. */
export const ACTION_PATH_RE = new RegExp(`^\\.github/actions/(?=[^]{1,200}/action\\.ya?ml$)${SEG}(?:/${SEG})*/action\\.ya?ml$`);

// ---------- the order rule ----------

/**
 * The platform actions that run no repo code and no step script of ours: pinned by SHA (the version is a comment).
 * download-artifact is on the list (7a fix round 1, ruling 1): it runs no code, it only writes data another job uploaded;
 * whether that data can be trusted is Plan C's question (the scrub and sha256 chain), not the order rule's. bullfrog (the
 * egress block, reviewed locks: no sudo, allowed domains only) is the harden step a job starts with, before its checkout.
 */
const TRUSTED_PATHS: readonly string[] = [
  ...(['checkout', 'setup-node', 'setup-python', 'upload-artifact', 'download-artifact', 'upload-sarif'] as const).map((k) => PLATFORM_USES[k]),
  'bullfrogsec/bullfrog',
];
export const TRUSTED_ACTION_RE = new RegExp(`^(?:${TRUSTED_PATHS.map((p) => p.replace(/[/.]/g, '\\$&')).join('|')})@[0-9a-f]{40}$`);
/** The `uses` path each setup id belongs to (review-6c-r1 minor 3): `pipegen-checkout` counts only on actions/checkout, and so on. */
const SETUP_ID_ACTION: readonly [RegExp, string][] = [
  [/^pipegen-checkout$/, PLATFORM_USES.checkout], [/^pipegen-setup-node-\d{1,3}$/, PLATFORM_USES['setup-node']], [/^pipegen-setup-python$/, PLATFORM_USES['setup-python']],
];

/**
 * Whether a step is a scrub step (Plan C ruling B1 part 3): a `scrub-<16 hex>` id on a step with no `run`, whose `uses` is the
 * gate action pinned by a commit, in `mode: scrub`. Nothing else is: not a run step with that id, not another action, not the
 * gate in another mode, not the gate action under another id. The shape only; whether the commit is the reviewed pin is the referee's question.
 */
export function isScrubStep(s: RenderedStep): boolean {
  return s.id !== undefined && SCRUB_STEP_ID_RE.test(s.id) && s.run === undefined && s.uses !== undefined && GATE_USES_RE.test(s.uses) && s.with?.mode === 'scrub';
}

/**
 * Whether a step is a stage step (C1c): a `stage-<16 hex>` id on a step with no `run`, whose `uses` is the gate action pinned by a
 * commit, in `mode: stage`. It copies the checkout into the stage folder of a secrets scan and runs no repo code. The shape only, as
 * for a scrub step; stageChainProblems holds it to its scan.
 */
export function isStageStep(s: RenderedStep): boolean {
  return s.id !== undefined && STAGE_STEP_ID_RE.test(s.id) && s.run === undefined && s.uses !== undefined && GATE_USES_RE.test(s.uses) && s.with?.mode === 'stage';
}

/**
 * Whether a step is the gate step that decides (C5b): no id, no `run`, the gate action pinned by a commit, in `mode: gate`. It runs
 * pipegen's own code on the event, the job outputs and the API (the gate job holds no checkout, ruling S21), never the repo's, so the
 * gate's own uploads may follow it. The shape only; the referee holds the pin and the job (mode gate runs only in the job gate).
 */
export function isGateDecideStep(s: RenderedStep): boolean {
  return s.id === undefined && s.run === undefined && s.uses !== undefined && GATE_USES_RE.test(s.uses) && s.with?.mode === 'gate';
}

/**
 * Whether a step is KNOWN not to run the repo's code. Everything else is repo code (fail closed): a step with no id, an
 * unknown or renamed id, `pipegen-npm-ci-…` (the repo's own `npm ci` reads its `.npmrc`), the repo-code run steps, and any
 * action that is not a pinned checkout, setup or upload action. An id counts only on the right kind of step: a script
 * for the run ids, for a setup id the pinned platform action it names (`pipegen-checkout` only on actions/checkout), and for
 * a scrub id the pinned gate action in scrub mode (isScrubStep).
 */
export function isKnownHarmless(s: RenderedStep): boolean {
  if (isPrCheckStep(s)) return true;   // G1 (BP-6): the exact pr-check lookup reads the API with the job's token, never the workspace
  const pinnedAction = s.uses !== undefined && s.run === undefined && TRUSTED_ACTION_RE.test(s.uses);
  if (s.id === undefined) return pinnedAction || isGateDecideStep(s);
  if (SETUP_STEP_ID_RE.test(s.id)) {
    const path = SETUP_ID_ACTION.find(([re]) => re.test(s.id as string))?.[1];
    return pinnedAction && path !== undefined && (s.uses as string).startsWith(`${path}@`);
  }
  if (SCRUB_STEP_ID_RE.test(s.id)) return isScrubStep(s);   // the gate action in scrub mode: no renderer makes a scrub id on a run step
  if (STAGE_STEP_ID_RE.test(s.id)) return isStageStep(s);   // the gate action in stage mode (C1c), likewise
  if (CHECKER_STEP_ID_RE.test(s.id) || TOOL_STEP_ID_RE.test(s.id)) return s.run !== undefined && s.uses === undefined;
  // G2 (B6): the archive's hash check of a scanner job, pipegen's own script (it reads the downloaded archive and the build's output only)
  if (IMAGE_CHECK_ID_RE.test(s.id)) return s.run !== undefined && s.uses === undefined;
  return false;   // an unknown or renamed id
}

/** What a scan step of a findings tool is, for the scrub that follows it: the reviewed entry's id and the format of its result. */
export interface ScanFact { tool: string; format: 'sarif' | 'zap-json' }
/**
 * What the shared job rules know about the job they judge (Plan C C0b):
 * - `id`: the job's id. A checkout `ref` is allowed only in the job `base-scan`; with no id it is refused.
 * - `scans`: the scan steps pipegen rendered or the referee recognised, by step id (`tool-run-…` / `checker-run-…`), each with
 *   its reviewed tool and result format. A scrub step's `tool` and `format` must equal those of its scan step. REQUIRED by
 *   dedupeJobSteps (fix round 1, minor 10): a job built without the facts could not be held to them. A job with no scan passes NO_SCANS.
 *   checkJobOrder itself accepts a context without it (only the unit tests of the order rule do that): the equality is then skipped.
 */
export interface JobContext { id?: string; scans: ReadonlyMap<string, ScanFact> }
/** The scan facts of a job that holds no scan step. */
export const NO_SCANS: ReadonlyMap<string, ScanFact> = new Map();

/** The job a base-commit checkout may sit in (ruling S16). */
export const BASE_SCAN_JOB = 'base-scan';
const HARDEN_USES_RE = /^bullfrogsec\/bullfrog@[0-9a-f]{40}$/;

/**
 * The order rule of the referee (S6 c, Plan 7a), as an allowlist that fails closed (review-6b-r2 C1). A step that runs or
 * loads the repo's code can rewrite what runs after it in the same job (runner temp, the install folders, `$GITHUB_ENV`,
 * the PATH). Every step that is not KNOWN to be harmless (isKnownHarmless) is repo code; once one has run, only repo-code
 * steps may follow. So no checker, release or docker tool, scrub, upload or action may come after one. There is no list of
 * harmless steps that may follow repo code: none can be justified. Returns plain-English problems, empty when the order is
 * fine; `dedupeJobSteps` throws on them and the referee runs it on the final YAML.
 * With a JobContext it also holds the job to the rest of the wiring: the base checkout only in `base-scan`, and every scrub
 * step to its scan (scrubChainProblems).
 * NOTE (C0a review m2): the id shape alone is what this function sees. For a hand-written file, what closes a forged harmless
 * id is the referee's re-render match (a run step that is not exactly a step pipegen renders is unrecognised, and the referee
 * drops its id before calling this), not this function on its own.
 */
export function checkJobOrder(steps: readonly RenderedStep[], job: Partial<JobContext> = {}): string[] {
  const problems: string[] = [];
  let repoCode: string | undefined;
  // A job with a scrub step names PIPEGEN_FP_KEY, and GitHub hands every secret a job names to its runner when the job starts: any
  // step of the job, before or after the scrub, can read it from the runner's memory. So such a job holds only steps known to run
  // no repo code (checkers, installs of pinned tools, the scrub, uploads), whatever their order (C0a fix round 1, finding 1).
  const keyJob = steps.some(isScrubStep);
  const scrubbed = new Set<string>();   // the artifacts a scrub step earlier in this job rebuilt
  // G2 (B6): the exact tail of an image-build job (archive step, then the archive's upload, right after the build) is the one exception
  const tail = imageBuildTailAt(steps, job.id);
  steps.forEach((s, i) => {
    if (tail !== null && i >= tail) return;
    if (isKnownHarmless(s)) {
      if (repoCode !== undefined) problems.push(`Step ${i + 1} (${show(s.name)}) comes after the repo-code step ${show(repoCode)}: code from the repository could have changed what it runs or uploads. Put it before, or in another job.`);
    } else {
      if (repoCode === undefined) repoCode = s.name;
      if (keyJob) problems.push(`Step ${i + 1} (${show(s.name)}) runs code pipegen did not render as harmless, in a job that holds the fingerprint key (it has a scrub step): every step of a job can read the secrets the job names, so this job runs no repo code. Put the step in another job.`);
    }
    if (isScrubStep(s) && typeof s.with?.artifact === 'string') scrubbed.add(s.with.artifact);
    const uploaded = uploadFolder(s);
    if (uploaded === 'raw') problems.push(`Step ${i + 1} (${show(s.name)}) uploads the raw result folder (pipegen-raw), which is never uploaded: only the scrubbed copy in pipegen-out is.`);
    else if (uploaded !== null && !scrubbed.has(uploaded)) problems.push(`Step ${i + 1} (${show(s.name)}) uploads the result folder ${show(uploaded)} of pipegen-out, but no scrub step for that result comes before it in this job: a result the gate's scrub did not rebuild may hold secret text.`);
    if (isCheckout(s) && s.with?.ref !== undefined && !(job.id === BASE_SCAN_JOB && s.with.ref === BASE_CHECKOUT_REF)) {
      problems.push(`Step ${i + 1} (${show(s.name)}) checks out a ref, which only the base commit of the ${BASE_SCAN_JOB} job may be (exactly the event-switched base commit): any other ref would scan code pipegen did not choose, or put the pull request's code where the base is expected.`);
    }
  });
  if (job.id === BASE_SCAN_JOB) problems.push(...baseScanProblems(steps));
  problems.push(...gateUploadProblems(steps, job.id));
  problems.push(...scrubChainProblems(steps, job.scans));
  problems.push(...stageChainProblems(steps, job.scans));
  problems.push(...rangeChainProblems(steps, job.scans));
  return problems;
}

/**
 * The commit-range scan of a job (C9): its step (the id rangeScanStepId) reads the git history, so the job's checkout comes before it and
 * takes the whole history (exactly one checkout, `fetch-depth: '0'`): a shallow checkout has no base commit, and the scan would fail on every
 * run. With `scans`, the step is the range tool's scan. One range scan per job.
 */
export function rangeChainProblems(steps: readonly RenderedStep[], scans?: ReadonlyMap<string, ScanFact>): string[] {
  const at = steps.flatMap((s, i) => (s.id === rangeScanStepId && s.run !== undefined ? [i] : []));
  if (at.length === 0) return [];
  if (at.length > 1) return [`The job holds ${at.length} commit-range scan steps; it has one.`];
  const i = at[0] as number;
  const problems: string[] = [];
  const checkouts = steps.flatMap((s, k) => (isCheckout(s) ? [k] : []));
  if (checkouts.length !== 1 || (checkouts[0] as number) > i || steps[checkouts[0] as number]?.with?.['fetch-depth'] !== '0') {
    problems.push(`Step ${i + 1} (${show(steps[i]?.name ?? '')}) scans the pull request's commits, so the job needs exactly one checkout before it, with fetch-depth: '0' (the whole history): a shallow checkout has no base commit to scan from.`);
  }
  const fact = scans?.get(rangeScanStepId);
  if (scans !== undefined && (fact === undefined || fact.tool !== RANGE_TOOL || fact.format !== 'sarif')) problems.push(`Step ${i + 1} (${show(steps[i]?.name ?? '')}) is the commit-range scan, but its scan fact is not ${RANGE_TOOL} writing SARIF.`);
  return problems;
}

/**
 * The stage steps of a job (C1c). A secrets scan reads only what the stage step of its result put in the stage folder, so:
 * - a stage step names its result (`artifact`), its id is `stage-<sha16(artifact)>`, its `stage` is that result's stage folder and its
 *   `tool` a tool that scans one; there is one per result;
 * - the scan step of that result comes after it in the same job, and (with `scans`) runs that very tool: a stage step is allowed only
 *   in a secrets job and before its scan;
 * - with `scans`: every scan step of a tool that scans a stage folder has the stage step of its result before it.
 */
export function stageChainProblems(steps: readonly RenderedStep[], scans?: ReadonlyMap<string, ScanFact>): string[] {
  const problems: string[] = [];
  const seen = new Map<string, number>();   // artifact → index of its stage step
  steps.forEach((s, i) => {
    if (!isStageStep(s)) return;
    const at = `Step ${i + 1} (${show(s.name)})`;
    const w = s.with ?? {};
    const artifact = w.artifact;
    if (typeof artifact !== 'string' || artifact === '') { problems.push(`${at} is a stage step that names no result.`); return; }
    if (s.id !== stageStepId(artifact)) problems.push(`${at} is a stage step whose id is ${show(s.id ?? '')}, but the stage step of the result ${show(artifact)} is ${stageStepId(artifact)}.`);
    if (w.stage !== stagePath(artifact)) problems.push(`${at} stages into ${show(String(w.stage ?? ''))}, but the stage folder of the result ${show(artifact)} is ${stagePath(artifact)}.`);
    if (!isStagedTool(w.tool)) problems.push(`${at} stages for the tool ${show(String(w.tool ?? ''))}, which does not scan a stage folder.`);
    if (seen.has(artifact)) problems.push(`${at} is a second stage step for the result ${show(artifact)}: a result has exactly one.`);
    else seen.set(artifact, i);
    const scanAt = steps.findIndex((x) => x.run !== undefined && x.id === `tool-run-${sha16(artifact)}`);
    if (scanAt < 0 || scanAt < i) { problems.push(`${at} stages the result ${show(artifact)}, but no scan step of that result comes after it in this job: a stage step belongs to a secrets job, before its scan.`); return; }
    const fact = scans?.get(`tool-run-${sha16(artifact)}`);
    if (scans !== undefined && (fact === undefined || fact.tool !== w.tool)) problems.push(`${at} stages for ${show(String(w.tool ?? ''))}, but the scan step of the result ${show(artifact)} runs ${show(fact?.tool ?? 'no reviewed tool')}.`);
  });
  if (scans !== undefined) {
    steps.forEach((s, i) => {
      if (s.id === undefined || s.run === undefined || s.id === rangeScanStepId || !isStagedTool(scans.get(s.id)?.tool)) return;
      const stageId = s.id.replace(/^tool-run-/, 'stage-');
      const stageAt = steps.findIndex((x) => isStageStep(x) && x.id === stageId);
      if (stageAt < 0 || stageAt > i) problems.push(`Step ${i + 1} (${show(s.name)}) scans for secrets, but the stage step of its result does not come before it in this job: the scanner reads the stage folder, which only the stage step fills (an empty or old folder would read as clean).`);
    });
  }
  return problems;
}

/**
 * The base-scan job scans the base commit and nothing else (C0b fix round 1, C0c CF3a): exactly one checkout, the first step after any
 * harden step, with a `ref` that is exactly BASE_CHECKOUT_REF. That one expression is switched on the event, so it holds in any file
 * (a called workflow included) whatever event starts it, and on any event it can not name gives a commit that does not exist, so the
 * checkout fails ("no base") instead of falling back to the head, where every finding would count as old and nothing new would block.
 */
export function baseScanProblems(steps: readonly RenderedStep[]): string[] {
  const problems: string[] = [];
  const at = steps.flatMap((s, i) => (isCheckout(s) ? [i] : []));
  if (at.length !== 1) return [`The ${BASE_SCAN_JOB} job has ${at.length} checkout steps; it needs exactly one checkout of the base commit (a second one could replace it with the head).`];
  const i = at[0] as number;
  const checkout = steps[i] as RenderedStep;
  if (!steps.slice(0, i).every((s) => s.run === undefined && s.uses !== undefined && HARDEN_USES_RE.test(s.uses))) problems.push(`The checkout of the ${BASE_SCAN_JOB} job must be its first step (after any harden step): a step before it could leave files the base scan would read.`);
  const ref = checkout.with?.ref;
  if (ref === undefined) problems.push(`The checkout of the ${BASE_SCAN_JOB} job needs a ref (the base commit): without one it checks out the head and the scan would call it the base.`);
  else if (ref !== BASE_CHECKOUT_REF) problems.push(`The checkout of the ${BASE_SCAN_JOB} job uses ${show(ref)}, but its ref must be exactly the event-switched base commit ${BASE_CHECKOUT_REF}: any other form is empty on some event, and the checkout then falls back to the head.`);
  return problems;
}

const CHECKOUT_USES_RE = new RegExp(`^${PLATFORM_USES.checkout.replace(/[/.]/g, '\\$&')}@[0-9a-f]{40}$`);
const isCheckout = (s: RenderedStep): boolean => s.run === undefined && s.uses !== undefined && CHECKOUT_USES_RE.test(s.uses);

/** The scrub inputs every scrub step carries (mode is what makes it a scrub step). */
const SCRUB_INPUTS = ['artifact', 'tool', 'format', 'raw', 'out', 'fp-key'] as const;
/** The ids a scan step of a result can have: the tool's run step, named by the hash of its artifact. */
const scanIdsOf = (artifact: string): string[] => [`tool-run-${sha16(artifact)}`, `checker-run-${sha16(artifact)}`];

/**
 * The scrub cross-checks (C0a review finding 3, carried to C0b), for every scrub step of a job:
 * - it names its result (`artifact`), and its id is `scrub-<sha16(artifact)>`;
 * - `tool`, `format`, `raw`, `out` and `fp-key` are all present, and the tool is one pipegen reviewed;
 * - it is the only scrub of that result in the job;
 * - a scan step of that result (`tool-run-<sha16>` / `checker-run-<sha16>`) is in the same job, before it;
 * - with `scans`: that step is a scan step pipegen renders, and the scrub's `tool` and `format` equal its tool and result format.
 * A scrub that does not match its scan could give a result the wrong tool's allowlist or fingerprint rules.
 */
export function scrubChainProblems(steps: readonly RenderedStep[], scans?: ReadonlyMap<string, ScanFact>): string[] {
  const problems: string[] = [];
  const first = new Map<string, number>();   // artifact → index of the first scrub of it
  steps.forEach((s, i) => {
    if (!isScrubStep(s)) return;
    const at = `Step ${i + 1} (${show(s.name)})`;
    const w = s.with ?? {};
    for (const k of SCRUB_INPUTS) if (typeof w[k] !== 'string' || w[k] === '') problems.push(`${at} is a scrub step with no ${k} input.`);
    const artifact = w.artifact;
    if (typeof artifact !== 'string' || artifact === '') return;
    if (s.id !== scrubStepId(artifact)) problems.push(`${at} is a scrub step whose id is ${show(s.id ?? '')}, but a scrub step's id is ${scrubStepId(artifact)} for the result ${show(artifact)}.`);
    if (first.has(artifact)) problems.push(`${at} is a second scrub step for the result ${show(artifact)} in this job: a result has exactly one scrub.`);
    else first.set(artifact, i);
    const tool = w.tool;
    if (typeof tool === 'string' && tool !== '' && !Object.hasOwn(ARGV_POLICIES, tool)) problems.push(`${at} scrubs for the tool ${show(tool)}, which is not a tool pipegen reviewed.`);
    const scanAt = steps.findIndex((x) => x.run !== undefined && x.id !== undefined && scanIdsOf(artifact).includes(x.id));
    if (scanAt < 0 || scanAt > i) {
      problems.push(`${at} scrubs the result ${show(artifact)}, but no scan step of that result comes before it in this job: the scrub must follow the tool run that wrote the raw file.`);
      return;
    }
    const scanTool = scans?.get(steps[scanAt]?.id as string)?.tool ?? (typeof tool === 'string' ? tool : undefined);
    if (artifact === SECRETS_RANGE_ARTIFACT) {
      // C9: the commit-range scan reads the history, never a stage folder; its scrub names none, and it scrubs the range tool's result
      if (w.stage !== undefined) problems.push(`${at} scrubs the commit-range scan, which reads the history and has no stage folder: its scrub names none.`);
      if (typeof tool === 'string' && tool !== RANGE_TOOL) problems.push(`${at} scrubs the commit-range scan as the tool ${show(tool)}, but that scan runs ${RANGE_TOOL}.`);
    } else if (isStagedTool(scanTool) && w.stage !== stagePath(artifact)) problems.push(`${at} scrubs a secrets scan, but does not name its stage folder (stage: ${stagePath(artifact)}): without the manifest the scrub can not map the findings or prove which files were scanned.`);
    if (scans === undefined) return;
    const scan = scans.get(steps[scanAt]?.id as string);
    if (scan === undefined) problems.push(`${at} scrubs the result ${show(artifact)}, but the step before it that carries its scan id is not a scan step pipegen renders for a reviewed tool.`);
    else {
      if (typeof tool === 'string' && tool !== scan.tool) problems.push(`${at} scrubs it as the tool ${show(tool)}, but the scan step ran ${show(scan.tool)}.`);
      if (typeof w.format === 'string' && w.format !== scan.format) problems.push(`${at} scrubs it as the format ${show(w.format)}, but the scan step wrote ${show(scan.format)}.`);
    }
  });
  return problems;
}

/** The job that decides (its uploads are the gate's own, C5b). */
export const GATE_JOB = 'gate';
/** The reserved name an upload step uploads, or undefined (not an upload, or a result upload). */
const gateUploadNameOf = (s: RenderedStep): string | undefined => {
  if (s.uses === undefined || s.run !== undefined || !UPLOAD_USES_RE.test(s.uses)) return undefined;
  const name = s.with?.name;
  return isGateUploadName(name) ? name : undefined;
};
/**
 * The gate's own uploads (C5b ruling 2): `pipegen-gate-result`, `pipegen-baseline` and `pipegen-clean-run` are uploaded only in the job
 * `gate`, each once, with `if: always()` (so the result is there when the gate fails), and only AFTER the gate step (which writes their
 * files); the gate job uploads nothing else. Their paths (each its own file in pipegen-gate) are RENDERER_INPUTS' rule, and their
 * `if-no-files-found` the template rule (uploadIfNoFiles). A job with no id is not the gate job (fail closed).
 */
export function gateUploadProblems(steps: readonly RenderedStep[], jobId: string | undefined): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  let decided = false;
  steps.forEach((s, i) => {
    if (isGateDecideStep(s)) decided = true;
    const name = gateUploadNameOf(s);
    // fix round 1 (ruling 2): continue-on-error only on the baseline and the marker uploads (their failure is never a gate failure, C3);
    // their job and place are the rules below. The result upload and every other step keep it off.
    if (s['continue-on-error'] === true && (name === undefined || !GATE_OPTIONAL_UPLOADS.has(name))) {
      problems.push(`Step ${i + 1} (${show(s.name)}) has continue-on-error, which only the gate's baseline and clean-run marker uploads may have: any other failed step must fail its job.`);
    }
    if (name === undefined) {
      if (jobId === GATE_JOB && s.uses !== undefined && s.run === undefined && UPLOAD_USES_RE.test(s.uses)) problems.push(`Step ${i + 1} (${show(s.name)}): the gate job uploads only its own result, baseline and clean-run marker, nothing else.`);
      return;
    }
    if (jobId !== GATE_JOB) { problems.push(`Step ${i + 1} (${show(s.name)}) uploads ${show(name)}, which only the gate job does (after its gate step).`); return; }
    if (!decided) problems.push(`Step ${i + 1} (${show(s.name)}) uploads ${show(name)} before the gate step has written it: it must come after the gate step.`);
    if (s.if !== 'always()') problems.push(`Step ${i + 1} (${show(s.name)}) uploads ${show(name)} without if: always(), so a failed gate would leave no ${name}.`);
    if (seen.has(name)) problems.push(`Step ${i + 1} (${show(s.name)}) uploads ${show(name)} more than once in the job.`);
    seen.add(name);
  });
  return problems;
}

/**
 * The gate job's result upload (fix round 1, ruling 1): the step right after the gate step uploads `pipegen-gate-result`, with
 * `if: always()` and no continue-on-error, so the job can never succeed without its result file (a gate step that ran nothing would
 * leave none, and the upload then fails the job). Problems, empty when held; for the job `gate` only (the referee: not-gate-readable).
 */
export function gateResultUploadProblems(steps: readonly RenderedStep[], gateIndex?: number): string[] {
  // fix round 2 (review-C5b-r1 r1-1): the referee passes the index of the gate step it judged, so a step this rule's own search would
  // miss (one with an id) can not switch the rule off; the referee also refuses an id on the gate step
  const at = gateIndex ?? steps.findIndex(isGateDecideStep);
  if (at < 0) return [];   // no gate step: judged elsewhere (the job gate runs the gate action exactly once)
  const next = steps[at + 1];
  if (next === undefined || gateUploadNameOf(next) === undefined) return [`The gate job must upload ${GATE_RESULT_ARTIFACT} right after the gate step (if: always()), so it can not succeed without the gate's result.`];
  if (gateUploadNameOf(next) !== GATE_RESULT_ARTIFACT) return [`The upload of ${GATE_RESULT_ARTIFACT} must come right after the gate step, before the other gate uploads.`];
  const out: string[] = [];
  if (next.if !== 'always()') out.push(`The upload of ${GATE_RESULT_ARTIFACT} must have if: always(), so a blocked gate still hands on its result.`);
  if (next['continue-on-error'] === true) out.push(`The upload of ${GATE_RESULT_ARTIFACT} may not have continue-on-error: without its result the gate job must fail.`);
  return out;
}

// ---------- Plan G's workflow shapes (v0.2 Plan G, G1: ruling B1, the referee side of B2; carries C3, C5a, BP-6) ----------
// One exact form each. The renderer writes these values and the referee compares by string (or deep) equality, never by a pattern,
// so neither can accept a near miss the other did not mean. Everything that is not one of them stays refused.

/** The app's caller workflow (ruling B2): push on the default branch only, pull_request, pull_request_review; the merge layer and the deploy jobs. */
export const CALLER_WORKFLOW = '.github/workflows/pipegen.yml';
/** The app's push-layer workflow (ruling B2): push on every branch but the default, pr-check and the push-layer scanners, never a gate. */
export const PUSH_WORKFLOW = '.github/workflows/pipegen-push.yml';
/** The approval re-run (Plan G l. 40): `pull_request_review` with exactly these types, and only in CALLER_WORKFLOW. */
export const PR_REVIEW_TRIGGER: Readonly<{ types: readonly string[] }> = Object.freeze({ types: Object.freeze(['submitted', 'dismissed']) });
/**
 * The one concurrency group expression (ruling G1-R1, with G1-R1b): on the default branch every run gets its own group (`pipegen-<run id>`), so
 * no baseline, signing or deploy run is ever queued behind another or cancelled (GitHub keeps one pending run per group and cancels the older
 * pending one); on any other ref the group is the ref and the event (`pipegen-<ref>-<event>`), so a newer push cancels the older run of the same
 * ref, but a review run never cancels the pull request's pull_request run. `format(...)` is never empty, so the `&& ||` choice is exact.
 */
export const CONCURRENCY_GROUP = "${{ github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && format('pipegen-{0}', github.run_id) || format('pipegen-{0}-{1}', github.ref, github.event_name) }}";
/**
 * The workflow-level `concurrency` of the two app callers (G1-R1): the one form pipegen writes, and the only concurrency the referee accepts at a
 * workflow's top (G1-R2 I2: a plain group is refused too). Never in a called workflow (it would share the group with its caller and deadlock).
 */
export const WORKFLOW_CONCURRENCY: Readonly<{ group: string; 'cancel-in-progress': true }> = Object.freeze({ group: CONCURRENCY_GROUP, 'cancel-in-progress': true });
/** The nightly job's own concurrency (ruling B5, carry C7n: no overlapping nightly runs): the one job-level concurrency, on the job nightly only. */
export const NIGHTLY_CONCURRENCY = 'pipegen-nightly';
/** The app's nightly workflow (ruling B2): schedule only. */
export const NIGHTLY_WORKFLOW = '.github/workflows/pipegen-nightly.yml';
/** The app's local merge workflow of the public layout (G2/G43): called by pipegen.yml, so workflow_call only. */
export const LOCAL_MERGE_WORKFLOW = '.github/workflows/pipegen-merge.yml';
/** CALLER_WORKFLOW's trigger names (ruling B2, G1-R2 I1): nothing else (no workflow_dispatch, workflow_call, merge_group, schedule). */
export const CALLER_TRIGGERS: readonly string[] = Object.freeze(['push', 'pull_request', 'pull_request_review']);

/** The job that looks for an open pull request of the pushed branch, and its one output. */
export const PR_CHECK_JOB = 'pr-check';
export const HAS_PR_OUTPUT = 'has-pr';
/** The push-layer skip (Plan G l. 43): a push-layer job of the push file skips when its branch has an open pull request (the merge layer covers it). */
export const PR_CHECK_IF = "needs.pr-check.outputs.has-pr != 'true'";
/** The deploy jobs of CALLER_WORKFLOW run on its push (the default branch only), never on a pull request or a review. */
export const DEPLOY_PUSH_IF = "github.event_name == 'push'";

/** Characters GitHub's branch filters read as a pattern (or an escape); a default branch holding one has no exact filter, so pipegen writes none. */
const BRANCH_PATTERN_RE = /[*?+[\]!\\]/;
/** The default branch as a filter value: a plain git branch name (printable ASCII, no space, no pattern character, no expression), else a RenderError. */
function branchFilterValue(defaultBranch: string): string {
  if (typeof defaultBranch !== 'string' || defaultBranch.length === 0 || defaultBranch.length > 255 || !/^[\x21-\x7e]+$/.test(defaultBranch)
    || BRANCH_PATTERN_RE.test(defaultBranch) || defaultBranch.includes(EXPR) || defaultBranch.startsWith('-') || /[~^:]|\.\.|@\{|\.lock$|\/$|^\/|\/\/|\.$/.test(defaultBranch)) {
    throw new RenderError(`The default branch ${show(String(defaultBranch))} is not a plain branch name pipegen can write as an exact branch filter (no pattern characters * ? + [ ] ! or \\).`);
  }
  return defaultBranch;
}
/** CALLER_WORKFLOW's push trigger (carry C3): exactly `branches: [<default>]`, so no tag and no other branch starts a run whose head looks trusted. */
export function defaultPushTrigger(defaultBranch: string): { branches: [string] } {
  return { branches: [branchFilterValue(defaultBranch)] };
}
/** PUSH_WORKFLOW's push trigger (ruling B2): every branch but the default (tags never run the pipeline: a push filter on branches alone runs on no tag). */
export function featurePushTrigger(defaultBranch: string): { 'branches-ignore': [string] } {
  return { 'branches-ignore': [branchFilterValue(defaultBranch)] };
}

/** The pr-check lookup step (BP-6): its id, and its one env entry, the job's own token (pull-requests: read, by the pr-check row of the permission table). */
export const PR_CHECK_STEP_ID = 'pipegen-pr-check';
export const PR_CHECK_STEP_ENV: Readonly<Record<string, string>> = Object.freeze({ PIPEGEN_PR_TOKEN: '${{ github.token }}' });
/**
 * The script: the pushed branch and the owner come from the runner's own variables (never an expression), URL-encoded by jq; the API answer
 * must be a list (anything else fails the step); `has-pr` is `true` exactly when the list holds an open pull request of this branch. Any failure
 * (curl, jq, an odd answer) fails the job, so the push-layer jobs that need it do not run and the run is red, never silently green.
 */
const PR_CHECK_RUN = [
  'set -euo pipefail',
  'branch="$(jq -rn --arg v "$GITHUB_REF_NAME" \'$v | @uri\')"',
  'owner="$(jq -rn --arg v "$GITHUB_REPOSITORY_OWNER" \'$v | @uri\')"',
  'count="$(curl -fsS --proto \'=https\' --max-time 60 -H "Authorization: Bearer $PIPEGEN_PR_TOKEN" -H \'Accept: application/vnd.github+json\' "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/pulls?state=open&per_page=1&head=$owner:$branch" | jq -e \'if type == "array" then length else error("not a list") end\')"',
  'if [ "$count" -gt 0 ]; then echo \'has-pr=true\' >> "$GITHUB_OUTPUT"; else echo \'has-pr=false\' >> "$GITHUB_OUTPUT"; fi',
  '',
].join('\n');
/** The one pr-check lookup step pipegen renders (BP-6: a shared renderer, so the referee recognises it by its exact content). */
export function renderPrCheckStep(): RenderedStep {
  return { id: PR_CHECK_STEP_ID, name: 'pipegen: does this branch have an open pull request', run: PR_CHECK_RUN, shell: 'bash', env: { ...PR_CHECK_STEP_ENV } };
}
/** Whether a step is exactly the pr-check lookup step (every field that runs; the name aside). */
export function isPrCheckStep(s: RenderedStep): boolean {
  const want = renderPrCheckStep();
  const runs = (x: RenderedStep): unknown[] => [x.id, x.uses, x.with, x.run, x.shell, x.env, x['working-directory'], x.if, x['continue-on-error'], x['timeout-minutes']];
  return JSON.stringify(runs(s)) === JSON.stringify(runs(want));
}

/** The baseline-check step's id (G22): its `found` output is the job output of the job baseline-check. The renderer (renderBaselineCheckStep) gives it. */
export const BASELINE_CHECK_STEP_ID = 'pipegen-baseline-check';
/** The baseline-check step's shape (the gate action pinned by a commit, in mode baseline-check, with its id); the referee holds the pin. */
export const isBaselineCheckStep = (s: RenderedStep): boolean =>
  s.id === BASELINE_CHECK_STEP_ID && s.run === undefined && s.uses !== undefined && GATE_USES_RE.test(s.uses) && s.with?.mode === 'baseline-check';
/**
 * The verify job's digest step id (G22, B3 a): the run step that reads the trusted run's digest artifact and checks it. Its renderer and its
 * step kind come with the deploy layer (G7); here only its shape: a run step with this id (until G7 the referee does not recognise its content, so
 * the pipegen-verify row refuses it).
 */
export const DIGEST_STEP_ID = 'pipegen-digest';
const isDigestStep = (s: RenderedStep): boolean => s.id === DIGEST_STEP_ID && typeof s.run === 'string' && s.uses === undefined;

/** The one form of a job output taken from a step's output. */
export const stepOutputForm = (stepId: string, output: string): string => `\${{ steps.${stepId}.outputs.${output} }}`;

// ---------- Plan G G2: signing, verification and the image hand-off (rulings B3 b, B6; carries C0c, F-4) ----------
// The exact forms the signing renderer (signing.ts), the image hand-off renderer (image-handoff.ts) and the referee share. As for G1's forms,
// the renderer writes them and the referee compares by equality; a step is recognised by its whole content, these only say which expression
// a step of that id may carry.

/**
 * F2-R11 (DECISIONS #108): the choice values that narrow a scanner, by choice name (true = narrows): a severity list without both HIGH and
 * CRITICAL (the gate's high floor), `ignore-unfixed` on, and an image build that pushes (a check builds, it never publishes). The renderer
 * refuses them for a blocking need (and when it is not told the need is non-blocking); the builder never offers them (debate/builder.ts).
 */
export const NARROWING_CHOICES: Readonly<Record<string, (v: string) => boolean>> = Object.freeze({
  severity: (v: string) => { const s = v.split(','); return !(s.includes('HIGH') && s.includes('CRITICAL')); },
  'ignore-unfixed': (v: string) => v !== 'false',
  push: (v: string) => v !== 'false',
});
/** Why a choice value would narrow a blocking scan, or null. */
export function narrowingChoiceProblem(name: string, value: string): string | null {
  const narrows = Object.hasOwn(NARROWING_CHOICES, name) ? NARROWING_CHOICES[name] : undefined;
  if (narrows === undefined || !narrows(value)) return null;
  return `the choice ${show(name)} = ${show(value)} would narrow a blocking check (DECISIONS #108: no ignore-unfixed, no severity above the gate's high floor, and a check never pushes an image), so pipegen does not render it for a blocking need`;
}

/** The sign step (job sign only) and the verify steps (job pipegen-verify only): their ids, one per image (sha16 of the image repository). */
export const SIGN_STEP_ID_RE = /^pipegen-sign-[0-9a-f]{16}$/;
export const VERIFY_STEP_ID_RE = /^pipegen-verify-[0-9a-f]{16}$/;
export const signStepId = (repo: string): string => `pipegen-sign-${sha16(`sign:${repo}`)}`;
export const verifyStepId = (repo: string): string => `pipegen-verify-${sha16(`verify:${repo}`)}`;
/** The key-env sign step's env (the signing environment's secrets): the only place the cosign key and its password are named. */
export const SIGN_STEP_ENV: Readonly<Record<string, string>> = Object.freeze({ PIPEGEN_COSIGN_KEY: '${{ secrets.PIPEGEN_COSIGN_KEY }}', PIPEGEN_COSIGN_PASSWORD: '${{ secrets.PIPEGEN_COSIGN_PASSWORD }}' });
/**
 * The verify steps' env: the key-env public key, the variable of the signing environment (a writer can change it, so the step checks its
 * sha256 against the literal pipegen recorded before cosign reads it, DECISIONS #76), and the attest-mode token of gh (the job's own token).
 */
export const VERIFY_STEP_ENV: Readonly<Record<string, string>> = Object.freeze({ PIPEGEN_COSIGN_PUB: '${{ vars.PIPEGEN_COSIGN_PUB }}', PIPEGEN_GH_TOKEN: '${{ github.token }}' });

/** The PR's own image (ruling B6): `image-build--<svc>` builds it without pushing and hands it to the scanners as an archive bound by its sha256. */
export const IMAGE_BUILD_NEED = 'image-build';
/** The job id of a service's image build (the same as jobIdFor('image-build', service)). */
export const imageBuildJobId = (service: string): string => `${IMAGE_BUILD_NEED}--${slug(service)}`;
const IMAGE_BUILD_JOB_RE = /^image-build--([a-z0-9][a-z0-9-]{0,39})$/;
/** The service slug of an image-build job id, or null. */
export const imageBuildSlugOf = (jobId: string | undefined): string | null => {
  const m = jobId === undefined ? null : IMAGE_BUILD_JOB_RE.exec(jobId);
  if (m === null) return null;
  try { return slug(m[1] as string) === m[1] ? (m[1] as string) : null; } catch { return null; }
};
/** The archive's artifact (not a check's result: no need is called image-archive, so no result name equals it). */
export const IMAGE_ARCHIVE_ID = 'image-archive';
export const imageArchiveArtifact = (service: string): string => resultArtifactName(IMAGE_ARCHIVE_ID, service);
/** The file inside the archive's artifact folder. */
export const IMAGE_ARCHIVE_FILE = 'image.tar';
/** The archive step of an image-build job (one per job) and its output, the job output the scanners check the archive against. */
export const IMAGE_ARCHIVE_STEP_ID = 'pipegen-image-archive';
export const IMAGE_SHA_OUTPUT = 'image-sha256';
const IMAGE_SHA_VALUE = stepOutputForm(IMAGE_ARCHIVE_STEP_ID, 'sha256');
const isImageArchiveStep = (s: RenderedStep): boolean => s.id === IMAGE_ARCHIVE_STEP_ID && typeof s.run === 'string' && s.uses === undefined;
/** The hash check of a scanner job: its id names the service, and its one expression is that service's image-build output. */
export const imageCheckStepId = (service: string): string => `pipegen-image-check--${slug(service)}`;
const IMAGE_CHECK_ID_RE = /^pipegen-image-check--([a-z0-9][a-z0-9-]{0,39})$/;
export const IMAGE_SHA_ENV = 'PIPEGEN_IMAGE_SHA256';
export const imageShaRef = (slugged: string): string => `\${{ needs.${IMAGE_BUILD_NEED}--${slugged}.outputs.${IMAGE_SHA_OUTPUT} }}`;
const BUILD_PUSH_USES_RE = new RegExp(`^${PLATFORM_USES['build-push'].replace(/[/.]/g, '\\$&')}@[0-9a-f]{40}$`);
const isBuildPushStep = (s: RenderedStep): boolean => s.run === undefined && s.uses !== undefined && BUILD_PUSH_USES_RE.test(s.uses);

/**
 * B6 (and controller ruling G2-R-sec 1): in the job `image-build--<slug>`, every step before the build known harmless, the reviewed build-push step builds the repository's Dockerfile inside BuildKit's own containers
 * (nothing it runs reaches the runner), and right after it, as the job's last two steps, come exactly the archive step and the upload of
 * this service's archive folder (no scrub: it is an image, not a result; the scanners check its sha256). The index where that tail starts,
 * or null when the job is not an image build or its tail is not exactly this. Anything else in the job is held to the order rule as usual.
 */
function imageBuildTailAt(steps: readonly RenderedStep[], jobId: string | undefined): number | null {
  const s = imageBuildSlugOf(jobId);
  const n = steps.length;
  if (s === null || n < 3) return null;
  const [b, a, u] = [steps[n - 3], steps[n - 2], steps[n - 1]] as [RenderedStep, RenderedStep, RenderedStep];
  const artifact = imageArchiveArtifact(s);
  const folder = `\${{ runner.temp }}/pipegen-out/${artifact}`;
  const upload = uploadFolder(u) === artifact && u.with?.name === artifact && u.with?.path === folder && u.if === undefined && u['continue-on-error'] === undefined;
  // controller ruling G2-R-sec 1: only when the build is the job's one step that is not known harmless; repo code anywhere before the tail
  // could rewrite what the archive step saves or uploads, so the tail then follows the order rule like any other step
  const before = steps.slice(0, n - 3).every(isKnownHarmless);
  return before && isBuildPushStep(b) && isImageArchiveStep(a) && upload ? n - 2 : null;
}
/** Plan G's job outputs (G22, three of four; the nested not-proven output is Plan H's): each on its own job only, from its own step only. */
const G_OUTPUTS: Readonly<Record<string, { job: string; step: string; is: (s: RenderedStep) => boolean }>> = Object.freeze({
  found: { job: 'baseline-check', step: BASELINE_CHECK_STEP_ID, is: isBaselineCheckStep },
  [HAS_PR_OUTPUT]: { job: PR_CHECK_JOB, step: PR_CHECK_STEP_ID, is: isPrCheckStep },
  digest: { job: 'pipegen-verify', step: DIGEST_STEP_ID, is: isDigestStep },
});

// ---------- job outputs (Plan C ruling B3) ----------

/** The scrub step's declared outputs the job outputs reference (gate/action.yml declares them; a test keeps them in it). */
export const OUTPUT_NAMES = ['sha256', 'status', 'error'] as const;
/** The id of the base-scan job's one checkout (renderJobPrelude with baseRef), so its `commit` output can be a job output (C5a CF3b). It is the setup id of actions/checkout, which the order rule already knows as harmless. */
export const BASE_CHECKOUT_ID = 'pipegen-checkout';
/** The base-scan job's output naming the commit it checked out: the gate requires it to equal the base of its own event (CF3b). */
export const BASE_SHA_OUTPUT = 'base-sha';
const BASE_SHA_VALUE = `\${{ steps.${BASE_CHECKOUT_ID}.outputs.commit }}`;
/** The steps that are the base checkout: a checkout of exactly BASE_CHECKOUT_REF with the id BASE_CHECKOUT_ID. */
const baseCheckouts = (steps: readonly RenderedStep[]): RenderedStep[] => steps.filter((s) => isCheckout(s) && s.id === BASE_CHECKOUT_ID && s.with?.ref === BASE_CHECKOUT_REF);
/**
 * The `outputs` a job with scrub steps hands the gate: for each scrubbed result `<artifact>-sha256`, `-status` and `-error`, each
 * exactly `${{ steps.<that result's scrub id>.outputs.<sha256|status|error> }}`. The renderer writes them with this function;
 * jobOutputsProblems judges any `outputs` map against the same rule.
 */
export function jobOutputsFor(steps: readonly RenderedStep[]): Record<string, string> {
  const out: Record<string, string> = {};
  if (baseCheckouts(steps).length === 1) out[BASE_SHA_OUTPUT] = BASE_SHA_VALUE;
  // G22: found, has-pr and digest, each from its own step (the renderer puts that step in its own job only; jobOutputsProblems holds the job)
  for (const [name, o] of Object.entries(G_OUTPUTS)) if (steps.filter(o.is).length === 1) out[name] = stepOutputForm(o.step, name);
  // G2 (B6): the archive's sha256 of an image-build job, from its one archive step
  if (steps.filter(isImageArchiveStep).length === 1) out[IMAGE_SHA_OUTPUT] = IMAGE_SHA_VALUE;
  for (const s of steps) {
    if (!isScrubStep(s) || typeof s.with?.artifact !== 'string' || s.id === undefined) continue;
    for (const n of OUTPUT_NAMES) out[`${s.with.artifact}-${n}`] = `\${{ steps.${s.id}.outputs.${n} }}`;
  }
  return out;
}

/**
 * Why a job's `outputs` are not allowed (Plan C ruling B3), as plain-English problems: only `<artifact>-sha256`, `-status` and
 * `-error`, for an artifact whose scrub step is in this job, each exactly `${{ steps.<that scrub's id>.outputs.<same> }}`; and on the
 * base-scan job `base-sha`, exactly `${{ steps.pipegen-checkout.outputs.commit }}` of its one base checkout (C5a CF3b).
 * Plan G (G1, G22): `found` only on the job baseline-check, `has-pr` only on pr-check and `digest` only on pipegen-verify, each exactly
 * `${{ steps.<its step's id>.outputs.<name> }}` of the one step of its kind in that job (G_OUTPUTS). Nothing else is an output of a job.
 * The emitter and the referee both call this, so they allow the same forms.
 */
export function jobOutputsProblems(jobId: string, outputs: unknown, steps: readonly RenderedStep[]): string[] {
  if (outputs === undefined) return [];
  const where = `The outputs of the job ${show(jobId)}`;
  if (typeof outputs !== 'object' || outputs === null || Array.isArray(outputs)) return [`${where} are not a map.`];
  const scrubs = new Map<string, string[]>();   // artifact → ids of its scrub steps in this job
  for (const s of steps) {
    if (isScrubStep(s) && typeof s.with?.artifact === 'string' && s.id !== undefined) scrubs.set(s.with.artifact, [...(scrubs.get(s.with.artifact) ?? []), s.id]);
  }
  const problems: string[] = [];
  for (const [key, value] of Object.entries(outputs)) {
    // G22 (ruling B1): found (baseline-check), has-pr (pr-check), digest (pipegen-verify): on that job only, exactly from that job's one step of its kind
    const g = Object.hasOwn(G_OUTPUTS, key) ? G_OUTPUTS[key] : undefined;
    if (g !== undefined) {
      if (jobId !== g.job) problems.push(`${where} include ${show(key)}, which is not one of the outputs of this job: only the job ${g.job} hands on ${key}, from its own step.`);
      else if (steps.filter(g.is).length !== 1 || steps.filter((s) => s.id === g.step).length !== 1) problems.push(`${where} include ${show(key)}, but the job does not hold exactly one ${g.step} step of its kind: ${key} comes only from its own step.`);
      else if (value !== stepOutputForm(g.step, key)) problems.push(`${where}: ${show(key)} must be exactly ${stepOutputForm(g.step, key)} (the output of its own step), nothing else.`);
      continue;
    }
    if (key === IMAGE_SHA_OUTPUT) {
      // G2 (B6): the sha256 of the image archive, only on the job image-build--<slug>, exactly from its one archive step
      if (imageBuildSlugOf(jobId) === null) problems.push(`${where} include ${show(key)}, which only an image-build--<service> job hands on (the sha256 of its image archive).`);
      else if (steps.filter(isImageArchiveStep).length !== 1 || steps.filter((s) => s.id === IMAGE_ARCHIVE_STEP_ID).length !== 1) problems.push(`${where} include ${show(key)}, but the job does not hold exactly one ${IMAGE_ARCHIVE_STEP_ID} step: the sha256 comes only from its archive step.`);
      else if (value !== IMAGE_SHA_VALUE) problems.push(`${where}: ${show(key)} must be exactly ${IMAGE_SHA_VALUE} (the sha256 its archive step wrote), nothing else.`);
      continue;
    }
    if (key === BASE_SHA_OUTPUT) {
      // C5a CF3b: the commit the base-scan job checked out, from its one base checkout, and nowhere else
      if (jobId !== BASE_SCAN_JOB) problems.push(`${where} include ${show(key)}, which only the ${BASE_SCAN_JOB} job hands the gate (the commit its base checkout checked out).`);
      else if (baseCheckouts(steps).length !== 1) problems.push(`${where} include ${show(key)}, but the job has no single base checkout with the id ${BASE_CHECKOUT_ID} (the checkout of the event's base commit).`);
      else if (value !== BASE_SHA_VALUE) problems.push(`${where}: ${show(key)} must be exactly ${BASE_SHA_VALUE} (the commit of its base checkout), nothing else.`);
      continue;
    }
    const name = OUTPUT_NAMES.find((n) => key.endsWith(`-${n}`));
    const artifact = name === undefined ? undefined : key.slice(0, key.length - name.length - 1);
    if (name === undefined || artifact === undefined || artifact === '') {
      problems.push(`${where} include ${show(key)}, which is not one of <result>-sha256, <result>-status or <result>-error: the gate reads nothing else from a job.`);
      continue;
    }
    const ids = scrubs.get(artifact);
    if (ids === undefined || ids.length !== 1) {
      problems.push(`${where} include ${show(key)}, but this job has ${ids === undefined ? 'no scrub step' : 'more than one scrub step'} for the result ${show(artifact)}.`);
      continue;
    }
    const want = `\${{ steps.${ids[0]}.outputs.${name} }}`;
    if (value !== want) problems.push(`${where}: ${show(key)} must be exactly ${want} (the ${name} of the scrub step of that result), nothing else.`);
  }
  return problems;
}

const UPLOAD_USES_RE = new RegExp(`^${PLATFORM_USES['upload-artifact'].replace(/[/.]/g, '\\$&')}@[0-9a-f]{40}$`);
const OUT_FOLDER_RE = /^\$\{\{ runner\.temp \}\}\/pipegen-out\/([^/]+)(?:\/|$)/;
/**
 * What an upload-artifact step uploads: the artifact folder under `pipegen-out` (the name of its result), `'raw'` for anything
 * in `pipegen-raw` (never uploadable, ruling B1 part 1), or null when the step is no upload or names no pipegen folder (the path rule of RENDERER_INPUTS judges that).
 */
function uploadFolder(s: RenderedStep): string | 'raw' | null {
  if (s.uses === undefined || s.run !== undefined || !UPLOAD_USES_RE.test(s.uses)) return null;
  const path = s.with?.path;
  if (typeof path !== 'string') return null;
  if (path.includes('/pipegen-raw/') || path.endsWith('/pipegen-raw')) return 'raw';
  return OUT_FOLDER_RE.exec(path)?.[1] ?? null;
}

// ---------- the expression rule ----------

/** `if:` values pipegen writes: nothing else is an allowed condition (an `if` is always an expression, with or without `${{`). */
export const IF_VALUES: ReadonlySet<string> = new Set(['always()', 'success()', 'failure()', '!cancelled()']);
export const SECRET_REF_RE = /^\$\{\{ secrets\.([A-Z][A-Z0-9_]{0,99}) \}\}$/;

/**
 * Refuses an expression (`${{`) anywhere but the forms pipegen itself writes (Quoting does not stop Actions from
 * evaluating one, so an expression in a name, run line, id, folder or any key is a bug or an attack, never rendered):
 * - an `env` value that is exactly `${{ secrets.NAME }}` under the same name NAME, which is not a dangerous one (S9);
 * - a `with` value that passes the RENDERER_INPUTS checker of that action together with its `whenWith` condition on the
 *   step's whole `with` (the runner.temp paths, the login actor, the token only with ghcr.io). A `uses` with no `@` has no table.
 * The step's other fields are held to their type too: `if` is one of a fixed set, `continue-on-error` a boolean and
 * `timeout-minutes` a whole number of minutes (a hand-built step may be cast past the types, review R1-2/R1-4).
 * The referee (7a) runs this same function on every step it parses, so the emitter and the judge allow the same forms.
 */
export function checkExpressions(step: RenderedStep): void {
  const bad = (what: string): never => { throw new RenderError(`A step may not contain an expression in its ${what} (${show(step.name)}).`); };
  const odd = (what: string): never => { throw new RenderError(`A step's ${what} is not in a form pipegen writes (${show(step.name)}).`); };
  for (const key of STEP_KEYS) {
    const v: unknown = step[key];
    if (typeof v === 'string' && v.includes(EXPR)) bad(key);
  }
  if (typeof step.usesComment === 'string' && step.usesComment.includes(EXPR)) bad('usesComment');
  if (step.if !== undefined && (typeof step.if !== 'string' || !IF_VALUES.has(step.if))) odd('if');
  const coe: unknown = step['continue-on-error'];
  if (coe !== undefined && typeof coe !== 'boolean') odd('continue-on-error');
  const tm: unknown = step['timeout-minutes'];
  if (tm !== undefined && (typeof tm !== 'number' || !Number.isInteger(tm) || tm < 1 || tm > 360)) odd('timeout-minutes');
  const at = step.uses === undefined ? -1 : step.uses.lastIndexOf('@');
  const usesPath = at < 0 || step.uses === undefined ? undefined : step.uses.slice(0, at);
  const table = usesPath === undefined ? undefined : own(RENDERER_INPUTS, usesPath.toLowerCase());
  for (const [group, values] of [['env', step.env], ['with', step.with]] as const) {
    for (const [k, v] of Object.entries(values ?? {})) {
      if (k.includes(EXPR)) bad(`${group} names`);
      if (typeof v !== 'string') odd(`${group} value ${show(k)}`);
      if (!v.includes(EXPR)) continue;
      if (group === 'env') {
        // C9: the commit-range scan step (its id, a run step) carries this event's base and head commits, each exactly its form
        if (step.id === rangeScanStepId && step.run !== undefined && step.uses === undefined && Object.hasOwn(RANGE_STEP_ENV, k) && RANGE_STEP_ENV[k] === v) continue;
        // G1 (BP-6): the pr-check lookup step, exactly as renderPrCheckStep writes it (every field that runs), carries the job's own token
        if (Object.hasOwn(PR_CHECK_STEP_ENV, k) && PR_CHECK_STEP_ENV[k] === v && isPrCheckStep(step)) continue;
        // G2 (B3 b, B6): a run step with the sign, verify or image-check id carries exactly its own forms (the referee recognises the whole
        // step by content and holds each kind to its job; here only which expression a step of that id may hold)
        if (step.run !== undefined && step.uses === undefined && step.id !== undefined) {
          if (SIGN_STEP_ID_RE.test(step.id) && own(SIGN_STEP_ENV, k) === v) continue;
          if (VERIFY_STEP_ID_RE.test(step.id) && own(VERIFY_STEP_ENV, k) === v) continue;
          const ic = IMAGE_CHECK_ID_RE.exec(step.id);
          if (ic !== null && k === IMAGE_SHA_ENV && v === imageShaRef(ic[1] as string)) continue;
        }
        const m = SECRET_REF_RE.exec(v);
        if (m === null || m[1] !== k || isDangerousName(k)) bad(`env value ${show(k)}`);
      } else if (usesPath === undefined || table === undefined || own(table, k) === undefined || rendererInputProblems(usesPath, { [k]: v }, step.with ?? {}).length > 0) {
        // an input the renderer fills is judged by its own checker and its condition; a with value may carry no other expression
        bad(`with value ${show(k)}`);
      }
    }
  }
}
