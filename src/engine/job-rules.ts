// The job rules every layer shares (Plan B final-review fix round, minor 10), in one leaf module: the step shape, the order rule,
// the expression rule, the dangerous names and the workflow/action file paths. The renderer (render-step.ts), the YAML emitter,
// the referee and the linters import them from here, so no second copy can drift. It imports only the leaves render-error.ts,
// tool-flags.ts and types.ts (test/final-fix-b.test.ts and test/module-graph.test.ts check this).
import { EXPR, own, RenderError, show } from './render-error.js';
import { ARGV_POLICIES, BASE_CHECKOUT_REFS, BASE_REF_FOR_TRIGGER, CHECKER_STEP_ID_RE, GATE_USES_RE, PLATFORM_USES, rendererInputProblems, RENDERER_INPUTS, scrubStepId, SCRUB_STEP_ID_RE, SETUP_STEP_ID_RE, sha16, TOOL_STEP_ID_RE } from './tool-flags.js';

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
  { family: 'loader and libc', match: /^(?:LD_|DYLD_|MALLOC_|LC_)|^(?:GCONV_PATH|GLIBC_TUNABLES|HOSTALIASES|RES_OPTIONS|LOCALDOMAIN)$/ },
  { family: 'proxy and TLS', match: /_PROXY$|^(?:SSL_|CURL_|OPENSSL_)|^REQUESTS_CA_BUNDLE$/i },
  { family: 'node, npm, python and package indexes', match: /^(?:NODE_|NPM_CONFIG_|PYTHON|PIP_|UV_)|^npm_config_/ },
  { family: 'java, perl, ruby', match: /^(?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|PERLLIB)$|^(?:PERL5|RUBY|GEM_|BUNDLE_)/ },
  { family: 'rust and go', match: /^(?:CARGO_|RUSTUP_|RUSTFLAGS$)|^GO[A-Z0-9]*$/ },
  { family: 'git, docker, XDG', match: /^(?:GIT_|DOCKER_|XDG_)/ },
  { family: 'the reviewed tools', match: /^(?:TRIVY_|HADOLINT_|PINACT_|SEMGREP_|COVERAGE_)/ },
  // build toolchains (6b, review R1-7): a compiler, linker, make or package-manager setting changes what a build runs
  { family: 'C, C++ and Go build', match: /^(?:CGO_|PKG_CONFIG_)|^(?:CC|CXX|AR|CFLAGS|CXXFLAGS|CPPFLAGS|LDFLAGS|MAKEFLAGS)$/ },
  { family: 'js package managers and runtimes', match: /^(?:YARN_|PNPM_|BUN_|DENO_|COREPACK_)/ },
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
/**
 * Why a created file's path is not a plain, normalized repo-relative path, or null (final review r1, R1): ASCII only, no
 * backslash or NUL, no leading `/`, and no empty, `.` or `..` segment (so `./x`, `a/../b`, `a//b` and a trailing `/` are all refused).
 * Joined onto a folder, any of those could land in `.github/workflows/` although the text looks like another place.
 */
export function createdPathProblem(path: string): string | null {
  if (typeof path !== 'string' || path === '') return 'the path is empty';
  if (!/^[\x20-\x7e]+$/.test(path)) return 'the path has a character other than printable ASCII (a control character, NUL or non-ASCII letter)';
  if (path.includes('\\')) return 'the path has a backslash';
  if (path.startsWith('/')) return 'the path is absolute';
  if (path.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) return 'the path has an empty, . or .. segment';
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
 * Whether a step is KNOWN not to run the repo's code. Everything else is repo code (fail closed): a step with no id, an
 * unknown or renamed id, `pipegen-npm-ci-…` (the repo's own `npm ci` reads its `.npmrc`), the repo-code run steps, and any
 * action that is not a pinned checkout, setup or upload action. An id counts only on the right kind of step: a script
 * for the run ids, for a setup id the pinned platform action it names (`pipegen-checkout` only on actions/checkout), and for
 * a scrub id the pinned gate action in scrub mode (isScrubStep).
 */
export function isKnownHarmless(s: RenderedStep): boolean {
  const pinnedAction = s.uses !== undefined && s.run === undefined && TRUSTED_ACTION_RE.test(s.uses);
  if (s.id === undefined) return pinnedAction;
  if (SETUP_STEP_ID_RE.test(s.id)) {
    const path = SETUP_ID_ACTION.find(([re]) => re.test(s.id as string))?.[1];
    return pinnedAction && path !== undefined && (s.uses as string).startsWith(`${path}@`);
  }
  if (SCRUB_STEP_ID_RE.test(s.id)) return isScrubStep(s);   // the gate action in scrub mode: no renderer makes a scrub id on a run step
  if (CHECKER_STEP_ID_RE.test(s.id) || TOOL_STEP_ID_RE.test(s.id)) return s.run !== undefined && s.uses === undefined;
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
 * - `triggers`: the event names that start the file, required for `base-scan` (the base commit form depends on the event).
 */
export interface JobContext { id?: string; scans: ReadonlyMap<string, ScanFact>; triggers?: readonly string[] }
/** The scan facts of a job that holds no scan step. */
export const NO_SCANS: ReadonlyMap<string, ScanFact> = new Map();

/** The job a base-commit checkout may sit in (ruling S16). */
export const BASE_SCAN_JOB = 'base-scan';
const BASE_REF_VALUES: readonly string[] = Object.values(BASE_CHECKOUT_REFS);
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
  steps.forEach((s, i) => {
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
    if (isCheckout(s) && s.with?.ref !== undefined && !(job.id === BASE_SCAN_JOB && BASE_REF_VALUES.includes(s.with.ref))) {
      problems.push(`Step ${i + 1} (${show(s.name)}) checks out a ref, which only the base commit of the ${BASE_SCAN_JOB} job may be (${BASE_REF_VALUES.join(' or ')}): any other ref would scan code pipegen did not choose, or put the pull request's code where the base is expected.`);
    }
  });
  if (job.id === BASE_SCAN_JOB) problems.push(...baseScanProblems(steps, job.triggers));
  problems.push(...scrubChainProblems(steps, job.scans));
  return problems;
}

/**
 * The base-scan job scans the base commit and nothing else (C0b fix round 1, ruling 5): exactly one checkout, the first step
 * after any harden step, with a `ref` that is the base commit form of EVERY event that starts the file. An event payload that lacks
 * the field gives an empty ref and the checkout falls back to the head, so every finding would count as old and nothing new would block.
 */
export function baseScanProblems(steps: readonly RenderedStep[], triggers: readonly string[] | undefined): string[] {
  const problems: string[] = [];
  const at = steps.flatMap((s, i) => (isCheckout(s) ? [i] : []));
  if (at.length !== 1) return [`The ${BASE_SCAN_JOB} job has ${at.length} checkout steps; it needs exactly one checkout of the base commit (a second one could replace it with the head).`];
  const i = at[0] as number;
  const checkout = steps[i] as RenderedStep;
  if (!steps.slice(0, i).every((s) => s.run === undefined && s.uses !== undefined && HARDEN_USES_RE.test(s.uses))) problems.push(`The checkout of the ${BASE_SCAN_JOB} job must be its first step (after any harden step): a step before it could leave files the base scan would read.`);
  const ref = checkout.with?.ref;
  if (ref === undefined) problems.push(`The checkout of the ${BASE_SCAN_JOB} job needs a ref (the base commit): without one it checks out the head and the scan would call it the base.`);
  if (triggers === undefined) problems.push(`The ${BASE_SCAN_JOB} job can be judged only with the triggers of its file (the base commit form depends on the event).`);
  else if (triggers.length === 0) problems.push(`The file of the ${BASE_SCAN_JOB} job has no trigger pipegen can read, so no base commit form fits it.`);
  else {
    for (const t of triggers) {
      const form = Object.hasOwn(BASE_REF_FOR_TRIGGER, t) ? (BASE_REF_FOR_TRIGGER as Readonly<Record<string, keyof typeof BASE_CHECKOUT_REFS>>)[t] : undefined;
      if (form === undefined) problems.push(`The ${BASE_SCAN_JOB} job has no base commit form for the trigger ${show(t)} (only ${Object.keys(BASE_REF_FOR_TRIGGER).join(', ')}).`);
      else if (ref !== undefined && ref !== BASE_CHECKOUT_REFS[form]) problems.push(`The checkout of the ${BASE_SCAN_JOB} job uses ${show(ref)}, which does not fit the trigger ${t} (its base is ${BASE_CHECKOUT_REFS[form]}): that event's payload has no such field, so the checkout would fall back to the head. Use one file per form.`);
    }
  }
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

// ---------- job outputs (Plan C ruling B3) ----------

const OUTPUT_NAMES = ['sha256', 'status', 'error'] as const;
/**
 * The `outputs` a job with scrub steps hands the gate: for each scrubbed result `<artifact>-sha256`, `-status` and `-error`, each
 * exactly `${{ steps.<that result's scrub id>.outputs.<sha256|status|error> }}`. The renderer writes them with this function;
 * jobOutputsProblems judges any `outputs` map against the same rule.
 */
export function jobOutputsFor(steps: readonly RenderedStep[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const s of steps) {
    if (!isScrubStep(s) || typeof s.with?.artifact !== 'string' || s.id === undefined) continue;
    for (const n of OUTPUT_NAMES) out[`${s.with.artifact}-${n}`] = `\${{ steps.${s.id}.outputs.${n} }}`;
  }
  return out;
}

/**
 * Why a job's `outputs` are not allowed (Plan C ruling B3), as plain-English problems: only `<artifact>-sha256`, `-status` and
 * `-error`, for an artifact whose scrub step is in this job, each exactly `${{ steps.<that scrub's id>.outputs.<same> }}`.
 * Nothing else is an output of a job that feeds the gate (no `has-pr`, no `digest`: Plan G extends this function when it adds
 * one). The emitter and the referee both call this, so they allow the same forms.
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
        const m = SECRET_REF_RE.exec(v);
        if (m === null || m[1] !== k || isDangerousName(k)) bad(`env value ${show(k)}`);
      } else if (usesPath === undefined || table === undefined || own(table, k) === undefined || rendererInputProblems(usesPath, { [k]: v }, step.with ?? {}).length > 0) {
        // an input the renderer fills is judged by its own checker and its condition; a with value may carry no other expression
        bad(`with value ${show(k)}`);
      }
    }
  }
}
