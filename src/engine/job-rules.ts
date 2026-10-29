// The job rules every layer shares (Plan B final-review fix round, minor 10), in one leaf module: the step shape, the order rule,
// the expression rule, the dangerous names and the workflow/action file paths. The renderer (render-step.ts), the YAML emitter,
// the referee and the linters import them from here, so no second copy can drift. It imports only the leaves render-error.ts,
// tool-flags.ts and types.ts (test/final-fix-b.test.ts and test/module-graph.test.ts check this).
import { EXPR, own, RenderError, show } from './render-error.js';
import { CHECKER_STEP_ID_RE, PLATFORM_USES, rendererInputProblems, RENDERER_INPUTS, SCRUB_STEP_ID_RE, SETUP_STEP_ID_RE, TOOL_STEP_ID_RE } from './tool-flags.js';

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
 * Whether a step is KNOWN not to run the repo's code. Everything else is repo code (fail closed): a step with no id, an
 * unknown or renamed id, `pipegen-npm-ci-…` (the repo's own `npm ci` reads its `.npmrc`), the repo-code run steps, and any
 * action that is not a pinned checkout, setup or upload action. An id counts only on the right kind of step: a script
 * for the run ids, and for a setup id the pinned platform action it names (`pipegen-checkout` only on actions/checkout).
 */
export function isKnownHarmless(s: RenderedStep): boolean {
  const pinnedAction = s.uses !== undefined && s.run === undefined && TRUSTED_ACTION_RE.test(s.uses);
  if (s.id === undefined) return pinnedAction;
  if (SETUP_STEP_ID_RE.test(s.id)) {
    const path = SETUP_ID_ACTION.find(([re]) => re.test(s.id as string))?.[1];
    return pinnedAction && path !== undefined && (s.uses as string).startsWith(`${path}@`);
  }
  if (CHECKER_STEP_ID_RE.test(s.id) || SCRUB_STEP_ID_RE.test(s.id) || TOOL_STEP_ID_RE.test(s.id)) return s.run !== undefined && s.uses === undefined;
  return false;   // an unknown or renamed id
}

/**
 * The order rule of the referee (S6 c, Plan 7a), as an allowlist that fails closed (review-6b-r2 C1). A step that runs or
 * loads the repo's code can rewrite what runs after it in the same job (runner temp, the install folders, `$GITHUB_ENV`,
 * the PATH). Every step that is not KNOWN to be harmless (isKnownHarmless) is repo code; once one has run, only repo-code
 * steps may follow. So no checker, release or docker tool, scrub, upload or action may come after one. There is no list of
 * harmless steps that may follow repo code: none can be justified. Returns plain-English problems, empty when the order is
 * fine; `dedupeJobSteps` throws on them and the referee runs it on the final YAML.
 */
export function checkJobOrder(steps: readonly RenderedStep[]): string[] {
  const problems: string[] = [];
  let repoCode: string | undefined;
  steps.forEach((s, i) => {
    if (isKnownHarmless(s)) {
      if (repoCode !== undefined) problems.push(`Step ${i + 1} (${show(s.name)}) comes after the repo-code step ${show(repoCode)}: code from the repository could have changed what it runs or uploads. Put it before, or in another job.`);
    } else if (repoCode === undefined) repoCode = s.name;
  });
  return problems;
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
