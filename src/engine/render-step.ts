// The step renderer (Plan B Task 6, sub-task 6a: contracts and core). It turns a reviewed tool plus the AI's choices
// into workflow steps that go into users' CI, so every repo-, AI- or memory-derived string is hostile until checked.
// - A step is rendered only from the reviewed entry (`tool.step` + `tool.fixedInputs`) and `spec.choices`. `spec.action`,
//   `spec.cli` and `spec.output` are copies (memory, the AI): they must deep-equal the template or validateSpec reports
//   it; nothing is ever rendered from them (ruling B1). renderStep throws for anything that isn't a reviewed entry.
// - The AI may set only the keys in `tool.choices`, each to one of its listed values. Anything else a step needs at
//   run time (an artifact name, a SARIF file, a Dockerfile) is a renderer-filled input from RENDERER_INPUTS
//   (tool-flags.ts), each with its own checker (ruling S15).
// - renderStep never uploads (ruling B3): the scrub step of Plans C and G sits between the scan and the upload, so
//   renderUpload is a separate helper. Result artifacts are named by artifact-names.ts (ruling B4).
// - Repo-derived values (Service.path, runtimeVersion, dockerfile) are validated or mapped, never copied raw (ruling S8).
//   All YAML is built with the `yaml` Document API (stepsToYaml); no step text is concatenated into YAML.
// - 6a builds the action kind completely; 6b the CLI kinds (github-release, docker, npm, pip) in render-cli.ts; 6c the rule
//   archives, the run-time slots (slots.ts), container actions and renderProjectScript.
import { isDeepStrictEqual } from 'node:util';
import { Scalar, YAMLMap, YAMLSeq } from 'yaml';
import { safeText } from '../util/safe-text.js';
import { DEPENDENCY_KINDS, type OutputFormat, type RepoProfile, type ReviewedTool, type Service, type StepSpec } from '../types.js';
import { COMMIT_SHA_RE } from './names.js';
import { NEED_IDS } from './need-ids.js';
import type { PlatformActions } from './pin.js';
import { projectScriptSteps, renderCliTool, type CliHooks, type RenderOptions } from './render-cli.js';
import { ArtifactNameError, resultArtifactName } from './artifact-names.js';
import type { ProjectScriptStep } from './reviewed.js';
import { EXPR, own, RenderError, show } from './render-error.js';
import { CHECKER_STEP_ID_RE, DOCKER_ACTION_USES, IMAGE_BUILT_ACTION_USES, PLAIN_REL_RE, RENDERER_INPUTS, rendererInputProblems, SCRUB_STEP_ID_RE, SETUP_STEP_ID_RE, TOOL_STEP_ID_RE } from './tool-flags.js';

export { RenderError };
export type { RenderOptions };

/** What a render needs besides the step: the repo facts (services, folders) and, for steps that need them, run-time targets (ruling S2). */
export interface RenderContext {
  profile: RepoProfile;
  /** Values only known at render time (6c slots): an image reference, a local URL, an API spec path. Never from the AI. */
  targets?: { image?: string; url?: string; spec?: string; k8sDir?: string };
}

/** One step of a job, as pipegen renders it. `usesComment` becomes the trailing `# <version>` comment on `uses:`. */
export interface RenderedStep {
  id?: string; name: string; if?: string; uses?: string; usesComment?: string; with?: Record<string, string>;
  run?: string; shell?: 'bash'; env?: Record<string, string>; 'working-directory'?: string;
  'continue-on-error'?: boolean; 'timeout-minutes'?: number;
}

/** `output`: where the tool's result will be, under `${{ runner.temp }}` (ruling S7); null when the step makes none. */
export interface RenderResult {
  steps: RenderedStep[]; output: { path: string; format: OutputFormat } | null;
  /** The job needs the whole git history (a base ref slot, jscpd): its checkout must use fetch-depth 0 (renderJobPrelude `fetchDepth: '0'`). */
  fullHistory?: true;
}

// ---------- shared checks ----------

/** A `with:` value from a template or a choice: plain words only (no expression, no quote, no shell character). */
const WITH_VALUE_RE = /^[A-Za-z0-9_@./:,=+\- ]{0,300}$/;
const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]{0,99}$/;
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

const same = (a: unknown, b: unknown): boolean => isDeepStrictEqual(a, b);

/** Why a candidate counts as reviewed: both marks (the type says so, a cast or a JSON copy might not). */
const isReviewed = (c: { source: string; reviewed: boolean }): boolean => c.source === 'reviewed' && c.reviewed === true;

// ---------- validateSpec ----------

/**
 * Plain-English problems with a spec, each starting with the field path (`choices.fetch-depth: …`), so the builder
 * can show them to the AI once and ask again (ruling S28). Empty = the spec is fine. Nothing here renders anything.
 */
export function validateSpec(spec: StepSpec, tool: ReviewedTool, ctx: RenderContext): string[] {
  const out: string[] = [];
  const problem = (path: string, message: string) => out.push(`${path}: ${message}`);
  const c = tool.candidate;
  const services = ctx.profile.services;

  if (!isReviewed(c)) problem('tool', `${show(tool.id)} isn't a reviewed tool, and pipegen never renders a tool that isn't.`);
  const st = spec.tool;
  if (typeof st !== 'object' || st === null || !isReviewed(st)) problem('tool', 'the step must name a reviewed tool.');
  else if (st.id !== c.id || st.kind !== c.kind || st.repo !== c.repo || st.version !== c.version || !same(st.pin, c.pin)) {
    problem('tool', `the step's tool ${show(st.id)} is not the reviewed entry ${show(c.id)} at its reviewed version and pin.`);
  }

  if (!(NEED_IDS as readonly string[]).includes(spec.needId)) problem('needId', `${show(spec.needId)} isn't a check pipegen knows.`);

  const service = spec.service === undefined ? undefined : services.find((s) => s.name === spec.service);
  if (spec.service !== undefined && service === undefined) problem('service', `${show(spec.service)} isn't a service of this repository.`);

  // choices: only the keys the entry offers, each at one of its listed values
  if (typeof spec.choices !== 'object' || spec.choices === null || Array.isArray(spec.choices)) problem('choices', 'must be a map of choice names to values.');
  else {
    for (const [key, value] of Object.entries(spec.choices)) {
      const path = `choices.${safeText(key, 40)}`;
      const offered = own(tool.choices, key);
      if (offered === undefined) {
        const names = Object.keys(tool.choices);
        problem(path, `this tool has no choice with that name.${names.length === 0 ? ' It offers no choices.' : ` It offers: ${names.join(', ')}.`}`);
      } else if (typeof value !== 'string') problem(path, 'the value must be text.');
      else if (!offered.includes(value)) problem(path, `${show(value)} is not one of the values this tool allows (${offered.join(', ')}).`);
    }
  }

  // copies of the template: never inputs, so they must equal it
  const template = (path: 'action' | 'cli', given: unknown, reviewed: unknown) => {
    if (given !== undefined && !same(given, reviewed)) problem(path, `differs from the reviewed template for ${show(c.id)}. pipegen renders only the reviewed template, so a changed copy is refused.`);
  };
  template('action', spec.action, tool.step.action);
  template('cli', spec.cli, tool.step.cli);
  if (!same(spec.output, tool.step.output)) problem('output', `differs from the reviewed template for ${show(c.id)}. pipegen renders only the reviewed template, so a changed copy is refused.`);

  // workingDir is repo text: it must be a plain folder AND one of the repo's own service folders (ruling S8)
  if (spec.workingDir !== undefined) {
    const wd = spec.workingDir;
    if (typeof wd !== 'string' || !PLAIN_REL_RE.test(wd)) problem('workingDir', `${show(wd)} isn't a plain folder inside the repository (no .., no leading / or -, letters, digits and . _ - / only).`);
    else if (!services.some((s) => s.path === wd)) problem('workingDir', `${show(wd)} isn't the folder of any service pipegen found.`);
    else if (service !== undefined && service.path !== wd) problem('workingDir', `${show(wd)} is not the folder of the service ${show(service.name)} (that is ${show(service.path)}).`);
  }

  if (spec.needsServices !== undefined) {
    if (!Array.isArray(spec.needsServices)) problem('needsServices', 'must be a list of service kinds.');
    else spec.needsServices.forEach((k, i) => { if (!(DEPENDENCY_KINDS as readonly string[]).includes(k)) problem(`needsServices[${i}]`, `${show(k)} isn't a service kind pipegen can start.`); });
  }

  // secrets: names only, a real variable of this service, never one that changes how code runs (ruling S9)
  if (spec.secrets !== undefined) {
    if (!Array.isArray(spec.secrets)) problem('secrets', 'must be a list of names.');
    else {
      // no service on the spec (a repo-wide step): the names any service declares count
      const declared = declaredEnvVars(service === undefined ? services : [service]);
      const seen = new Set<string>();
      spec.secrets.forEach((name, i) => {
        const path = `secrets[${i}]`;
        if (typeof name !== 'string' || !SECRET_NAME_RE.test(name)) problem(path, `${show(name)} isn't a secret name (capital letters, digits and _, starting with a letter, at most 100 characters).`);
        else if (isDangerousName(name)) problem(path, `${name} can't be passed to a step: it changes how code runs or what the runner does.`);
        else if (!declared.has(name)) problem(path, `${name} isn't used by ${service === undefined ? 'any service' : `the service ${show(service.name)}`} (its code or its dependencies), so pipegen won't pass it.`);
        else if (seen.has(name)) problem(path, `${name} is listed twice.`);
        seen.add(String(name));
      });
    }
  }
  return out;
}

/** Env var names the given services read, their own and their dependencies'. */
function declaredEnvVars(services: readonly Service[]): Set<string> {
  return new Set(services.flatMap((s) => [...s.envVars, ...s.dependsOn.flatMap((d) => d.envVars)]));
}

// ---------- node version (ruling S8, controller amendment) ----------

const DEFAULT_NODE = 24;

/**
 * Maps the repo's own Node version text onto the versions pipegen's reviewed setup-node entry offers (`allowed`:
 * 22, 24, 26 today). Only its first run of digits is read, so no repo text is ever rendered or quoted. An exact major
 * in the set is used; otherwise the nearest one that is not older; older than all → the lowest; newer than all → the
 * highest. Every change of major adds a note. No digits at all → 24 with a note; no version known → 24, no note.
 */
export function mapNodeVersion(runtimeVersion: string | undefined, allowed: readonly string[]): { version: string; note?: string } {
  const set = allowed.map(Number).filter((n) => Number.isInteger(n) && n > 0).sort((a, b) => a - b);
  const lowest = set[0];
  const highest = set[set.length - 1];
  if (lowest === undefined || highest === undefined) throw new RenderError('The reviewed setup-node entry offers no Node version.');
  const fallback = set.includes(DEFAULT_NODE) ? DEFAULT_NODE : highest;
  if (runtimeVersion === undefined) return { version: String(fallback) };
  const digits = /\d+/.exec(runtimeVersion)?.[0];
  if (digits === undefined) return { version: String(fallback), note: `pipegen couldn't read a Node version from this repository, so the pipeline uses Node ${fallback}.` };
  const huge = digits.length > 4;
  const major = huge ? Number.POSITIVE_INFINITY : Number(digits);
  if (set.includes(major)) return { version: String(major) };
  const version = set.find((v) => v >= major) ?? highest;
  return { version: String(version), note: `The repository asks for Node ${huge ? 'a far newer version' : major}, which pipegen's pinned setup doesn't offer (${set.join(', ')}), so the pipeline uses Node ${version}.` };
}

// ---------- the action core ----------

/** PlatformActions key → the `uses:` path (owner/repo[/path], lower case) its entry must have; a swapped entry is refused. */
const PLATFORM_USES: Readonly<Record<keyof PlatformActions, string>> = Object.freeze({
  checkout: 'actions/checkout', 'setup-node': 'actions/setup-node', 'setup-python': 'actions/setup-python',
  'upload-artifact': 'actions/upload-artifact', 'download-artifact': 'actions/download-artifact', 'docker-login': 'docker/login-action',
  'setup-buildx': 'docker/setup-buildx-action', 'build-push': 'docker/build-push-action', 'upload-sarif': 'github/codeql-action/upload-sarif', attest: 'actions/attest',
});

/**
 * Inputs a platform action's entry must FIX to these values (by `uses` path). They are checked on every render path
 * (renderStep, renderPlatformStep, the prelude, the upload), not only where an entry is first used, and an input listed
 * here can not also be an AI choice.
 */
const PLATFORM_LOCKS: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  'actions/checkout': { 'persist-credentials': 'false', 'allow-unsafe-pr-checkout': 'false' },
  'actions/setup-node': { 'package-manager-cache': 'false' },
  'actions/upload-artifact': { 'include-hidden-files': 'false', 'if-no-files-found': 'error' },
  // the docker actions' cache and credential locks (6b, review R1-5): checked here, not only by the loader
  'docker/build-push-action': { 'no-cache': 'true', 'github-token': '', context: '.' },
  'docker/setup-buildx-action': { 'cache-binary': 'false' },
  'docker/login-action': { logout: 'true' },
});

/** Actions the renderer fills inputs for through their own helper (renderUpload, renderPlatformStep); renderStep refuses them. */
const HELPER_ONLY: ReadonlySet<string> = new Set(Object.keys(RENDERER_INPUTS).filter((k) => k !== 'docker/login-action' && k !== 'docker/build-push-action'));

/**
 * Container actions (ruling S13), refused by `uses` path (so a renamed copy of an entry is refused too) or because the entry
 * records a `wrappedImage`: one that builds its image at run time can never be pinned; one that runs a docker image renders
 * only when its entry records that image and the image is pinned by the digest it recorded (resolvePin reads it from
 * action.yml at the pinned commit). Returns why not, or null when the action may be rendered.
 */
export function containerRefusal(tool: ReviewedTool, path: string): string | null {
  if (IMAGE_BUILT_ACTION_USES.has(path)) return `${show(tool.id)} builds its image from a Dockerfile at run time, so what it runs can not be pinned; it stays refused (a permanent refusal until a pinned replacement exists)`;
  const w = tool.wrappedImage;
  if (!DOCKER_ACTION_USES.has(path) && w === undefined) return null;
  if (w === undefined) return `${show(tool.id)} is a container action (its action.yml runs a docker image) but its entry has no wrappedImage, so what it runs is not pinned`;
  if (!w.ref.endsWith(`@${w.digest}`)) return `the container action ${show(tool.id)} runs its image by tag (${show(w.ref)}), so whoever controls the tag controls what runs; it stays refused until the image is pinned by digest`;
  return null;
}

/** The entry's `uses:` split into its path (lower case, no `@sha`), checked against the entry's own repo and pin. */
function usesOf(tool: ReviewedTool): { path: string; uses: string } {
  const action = tool.step.action;
  const c = tool.candidate;
  if (action === undefined || c.kind !== 'action') throw new RenderError(`${show(tool.id)} is not an action entry.`);
  const at = action.uses.lastIndexOf('@');
  const path = action.uses.slice(0, at).toLowerCase();
  const repo = c.repo.toLowerCase();
  if (at < 0 || !(path === repo || (path.startsWith(`${repo}/`) && /^[a-z0-9._/-]+$/.test(path.slice(repo.length + 1)) && !path.includes('..')))) {
    throw new RenderError(`The reviewed entry ${show(tool.id)} runs ${show(action.uses)}, which is not ${show(c.repo)}.`);
  }
  const sha = action.uses.slice(at + 1);
  if (!COMMIT_SHA_RE.test(sha) || sha !== c.pin.sha) throw new RenderError(`The reviewed entry ${show(tool.id)} runs a commit that is not its reviewed pin.`);
  return { path, uses: action.uses };
}

/** The values of the entry's choices: the one given (already validated), else the first listed (the reviewed default). */
function chosenInputs(tool: ReviewedTool, given: Readonly<Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, offered] of Object.entries(tool.choices)) {
    const value = own(given, key) ?? offered[0];
    if (value === undefined || !offered.includes(value)) throw new RenderError(`The choice ${show(key)} of ${show(tool.id)} has no allowed value.`);
    out[key] = value;
  }
  return out;
}

/**
 * One `uses:` step: the reviewed `uses` (sub-path kept) with the version as a comment; `with` = the fixed inputs, then
 * the chosen ones, then the renderer-filled ones. A key is set once. Every template or chosen value must be plain
 * words; a filled value passes its own RENDERER_INPUTS checker.
 */
function actionStep(tool: ReviewedTool, name: string, choices: Readonly<Record<string, string>>, filled: Readonly<Record<string, string>>): RenderedStep {
  const { path, uses } = usesOf(tool);
  const fixed = tool.fixedInputs.with ?? {};
  if (!same(tool.step.action?.with ?? {}, fixed)) throw new RenderError(`The reviewed entry ${show(tool.id)} has a step template that disagrees with its fixed inputs.`);
  for (const [input, locked] of Object.entries(own(PLATFORM_LOCKS, path) ?? {})) {
    if (own(fixed, input) !== locked || Object.hasOwn(tool.choices, input)) throw new RenderError(`The reviewed entry ${show(tool.id)} no longer fixes ${input} to ${locked}.`);
  }
  const chosen = chosenInputs(tool, choices);
  const fill = rendererInputProblems(path, filled, { ...fixed, ...chosen, ...filled });
  if (fill.length > 0) throw new RenderError(fill.join(' '));
  const withs: Record<string, string> = {};
  for (const [group, values, checked] of [['fixed', fixed, true], ['chosen', chosen, true], ['filled', filled, false]] as const) {
    for (const [key, value] of Object.entries(values)) {
      if (Object.hasOwn(withs, key)) throw new RenderError(`The input ${show(key)} of ${show(tool.id)} would be set twice (${group}).`);
      if (checked && !WITH_VALUE_RE.test(value)) throw new RenderError(`The input ${show(key)} of ${show(tool.id)} has a value pipegen won't write into a workflow.`);
      withs[key] = value;
    }
  }
  return { name, uses, usesComment: tool.candidate.version, ...(Object.keys(withs).length === 0 ? {} : { with: withs }) };
}

function platformEntry(platform: PlatformActions, key: keyof PlatformActions): ReviewedTool {
  const tool = own(platform, key);
  if (tool === undefined || !isReviewed(tool.candidate)) throw new RenderError(`The platform action ${key} is not a reviewed entry.`);
  if (usesOf(tool).path !== PLATFORM_USES[key]) throw new RenderError(`The platform action ${key} does not run ${PLATFORM_USES[key]}.`);
  return tool;
}

/**
 * A platform action (checkout, setup-node, upload-artifact, upload-sarif, …) from its reviewed entry. `filled` are the
 * renderer inputs for it (RENDERER_INPUTS: an artifact name, a SARIF file, …); `choices` the reviewed choices.
 */
export function renderPlatformStep(key: keyof PlatformActions, platform: PlatformActions, filled: Readonly<Record<string, string>> = {}, choices: Readonly<Record<string, string>> = {}): RenderedStep {
  const tool = platformEntry(platform, key);
  for (const k of Object.keys(choices)) {
    const offered = own(tool.choices, k);
    if (offered === undefined || !offered.includes(choices[k] as string)) throw new RenderError(`${key} has no choice ${show(k)} = ${show(choices[k])}.`);
  }
  return actionStep(tool, `pipegen: ${usesOf(tool).path}`, choices, filled);
}

// ---------- renderStep ----------

/**
 * Renders a reviewed tool's step (never an unreviewed one). Throws a RenderError for a spec with problems, a tool whose
 * id or pin differs from the spec's, or a tool that can't be rendered yet (pip without a closure, cosign, gosec). It
 * never uploads the output (ruling B3). `platform` supplies the setup actions the npm and pip kinds need.
 */
export function renderStep(given: StepSpec, tool: ReviewedTool, platform: PlatformActions, ctx: RenderContext): RenderResult {
  return renderStepWith(given, tool, platform, ctx);
}

/**
 * renderStep with the internal hooks (the argv policies, the pip closures, the npm closure locks). FOR TESTS ONLY: the
 * public renderStep has no such parameter, so Plans F, G and H can't swap a reviewed policy by accident (review finding 8).
 */
export function renderStepWith(given: StepSpec, tool: ReviewedTool, platform: PlatformActions, ctx: RenderContext, options: RenderOptions = {}): RenderResult {
  // render exactly what is validated: one plain copy (a getter or proxy is read once), not the caller's live object
  let spec: StepSpec;
  try {
    spec = structuredClone(given);
  } catch {
    throw new RenderError('The step can not be copied as plain data (it holds a function or another object that is not data).');
  }
  if (!isReviewed(tool.candidate)) throw new RenderError(`${show(tool.id)} is not a reviewed tool, and pipegen never renders a tool that isn't.`);
  const problems = validateSpec(spec, tool, ctx);
  if (problems.length > 0) throw new RenderError(`The step for ${show(spec.needId)} isn't valid: ${problems.join(' ')}`);
  if (tool.candidate.kind !== 'action' || tool.step.action === undefined) {
    if (tool.step.cli === undefined) throw new RenderError(`${show(tool.id)} is neither an action nor a cli entry.`);
    const service = spec.service === undefined ? undefined : ctx.profile.services.find((s) => s.name === spec.service);
    return renderCliTool({ spec, tool, service, ctx, hooks: cliHooks(platform), options });
  }
  const container = containerRefusal(tool, usesOf(tool).path);
  if (container !== null) throw new RenderError(`container action: ${container}.`);
  if (HELPER_ONLY.has(usesOf(tool).path)) throw new RenderError(`${show(tool.id)} is rendered with renderPlatformStep or renderUpload, which supply the inputs it needs.`);
  if (tool.step.output.format !== 'none') throw new RenderError(`not implemented in 6a: an action that writes a result (${show(tool.id)}); its output is moved under runner.temp in 6b.`);

  const { path } = usesOf(tool);
  const service = spec.service === undefined ? undefined : ctx.profile.services.find((s) => s.name === spec.service);
  const step = actionStep(tool, `pipegen: ${path}`, spec.choices, rendererFill(path, service, ctx, spec.choices.registry ?? tool.choices.registry?.[0]));
  const secrets = spec.secrets ?? [];
  if (secrets.length > 0) step.env = Object.fromEntries(secrets.map((n) => [n, `\${{ secrets.${n} }}`]));
  return { steps: [step], output: null };
}

/** What the CLI renderer takes from here: the setup actions (version mapped, no cache) and the secret-name rules. */
function cliHooks(platform: PlatformActions): CliHooks {
  return {
    setupNode(runtimeVersion) {
      const setup = platformEntry(platform, 'setup-node');
      return actionStep(setup, 'Set up Node.js', { 'node-version': mapNodeVersion(runtimeVersion, setup.choices['node-version'] ?? []).version }, {});
    },
    setupPython() {
      const step = actionStep(platformEntry(platform, 'setup-python'), 'Set up Python', {}, {});
      // pipegen uses no caches (spec §19): an entry that grew a cache input is refused
      if (Object.keys(step.with ?? {}).some((k) => k.toLowerCase().startsWith('cache'))) throw new RenderError('The reviewed setup-python entry has a cache input; pipegen uses no caches.');
      return step;
    },
    isDangerousName,
  };
}

/**
 * Keeps the first of every step that has an `id` starting `pipegen-` (the checkout, setup-node and `npm ci` steps, which
 * are the same for every tool of a job) and drops the repeats. Steps without such an id are never dropped. Plan G runs a
 * job's steps through this once, so a job installs its dependencies once (ruling B5). A repeat must be the SAME step
 * (only its display name may differ), or this throws (review-6c-r1 minor 2: a later checkout with fetch-depth 0 must not
 * vanish behind a depth-1 one). The one documented exception is the repo `npm ci` of one folder asked for by several
 * tools: its pin lists are merged, and its scripts may differ only in the tool's own home folder.
 */
export function dedupeJobSteps(steps: readonly RenderedStep[]): RenderedStep[] {
  const seen = new Map<string, number>();
  const kept: RenderedStep[] = [];
  for (const s of steps) {
    if (s.id === undefined || !s.id.startsWith('pipegen-')) { kept.push(s); continue; }
    const at = seen.get(s.id);
    if (at === undefined) {
      seen.set(s.id, kept.length);
      kept.push(s);
      continue;
    }
    const first = kept[at] as RenderedStep;
    if (!sameDedupeContent(first, s)) throw new RenderError(`Two steps of one job have the id ${show(s.id)} but do different things (${show(first.name)} and ${show(s.name)}); pipegen keeps only identical repeats.`);
    // the same repo `npm ci` asked for by several tools: the one that stays must carry EVERY tool's lockfile pins, so its
    // pre-check (before `npm ci`) guards them all, whichever step came first
    if (s.id.startsWith('pipegen-npm-ci-') && first.env?.PIPEGEN_NPM_EXPECT !== s.env?.PIPEGEN_NPM_EXPECT) {
      kept[at] = { ...first, env: { ...first.env, PIPEGEN_NPM_EXPECT: mergePins(first.env?.PIPEGEN_NPM_EXPECT, s.env?.PIPEGEN_NPM_EXPECT) } };
    }
  }
  // one Node version per job: a second major would run a tool on a node it was not set up for (Plan G splits the job)
  const majors = new Set(kept.filter((s) => s.id?.startsWith('pipegen-setup-node-')).map((s) => s.id));
  if (majors.size > 1) throw new RenderError('One job can have only one Node version, but its steps ask for more than one; they belong in separate jobs.');
  // no job is assembled in a bad order (review-6b-r2 C1)
  const order = checkJobOrder(kept);
  if (order.length > 0) throw new RenderError(order.join(' '));
  return kept;
}

/** The tool's own home folder line of a script (`home="$RUNNER_TEMP/pipegen-home/<artifact>"`), the one line two guarded `npm ci` steps of one folder may differ in. */
const HOME_LINE_RE = /^home="\$RUNNER_TEMP\/pipegen-home\/[a-z0-9][a-z0-9-]{0,160}"$/gm;

/** Whether a repeated `pipegen-` step is the same step as the one kept: everything but the name, and for `npm ci` its pins and home folder. */
export function sameDedupeContent(a: RenderedStep, b: RenderedStep): boolean {
  const norm = (s: RenderedStep): unknown => {
    const { name: _name, ...rest } = s;
    if (s.id === undefined || !s.id.startsWith('pipegen-npm-ci-')) return rest;
    const { PIPEGEN_NPM_EXPECT: _pins, ...env } = s.env ?? {};
    return { ...rest, env, run: typeof s.run === 'string' ? s.run.replace(HOME_LINE_RE, 'home=<the tool home>') : s.run };
  };
  return same(norm(a), norm(b));
}

/** The union of two lists of pinned packages (JSON, as in PIPEGEN_NPM_EXPECT); one package at two different pins is refused. */
function mergePins(a: string | undefined, b: string | undefined): string {
  const out = new Map<string, string>();
  for (const text of [a, b]) {
    let list: unknown;
    try { list = JSON.parse(text ?? '[]'); } catch { throw new RenderError('A dependency install step carries a pin list that is not JSON.'); }
    if (!Array.isArray(list)) throw new RenderError('A dependency install step carries a pin list that is not a list.');
    for (const p of list as { name?: unknown }[]) {
      const name = typeof p?.name === 'string' ? p.name : '';
      const line = JSON.stringify(p);
      if (name === '' || (out.has(name) && out.get(name) !== line)) throw new RenderError(`Two steps of one job install ${show(name)} at different pins.`);
      out.set(name, line);
    }
  }
  return `[${[...out.values()].join(',')}]`;
}

/**
 * The platform actions that run no repo code and no step script of ours: pinned by SHA (the version is a comment).
 * download-artifact is on the list (7a fix round 1, ruling 1): it runs no code, it only writes data another job uploaded;
 * whether that data can be trusted is Plan C's question (the scrub and sha256 chain), not the order rule's. bullfrog (the
 * egress block, reviewed locks: no sudo, allowed domains only) is the harden step a job starts with, before its checkout.
 */
const TRUSTED_ACTION_RE = /^(?:actions\/(?:checkout|setup-node|setup-python|upload-artifact|download-artifact)|github\/codeql-action\/upload-sarif|bullfrogsec\/bullfrog)@[0-9a-f]{40}$/;
/** The `uses` path each setup id belongs to (review-6c-r1 minor 3): `pipegen-checkout` counts only on actions/checkout, and so on. */
const SETUP_ID_ACTION: readonly [RegExp, string][] = [
  [/^pipegen-checkout$/, 'actions/checkout'], [/^pipegen-setup-node-\d{1,3}$/, 'actions/setup-node'], [/^pipegen-setup-python$/, 'actions/setup-python'],
];

/**
 * Whether a step is KNOWN not to run the repo's code. Everything else is repo code (fail closed): a step with no id, an
 * unknown or renamed id, `pipegen-npm-ci-…` (the repo's own `npm ci` reads its `.npmrc`), the repo-code run steps, and any
 * action that is not a pinned checkout, setup or upload action. An id counts only on the right kind of step: a script
 * for the run ids, and for a setup id the pinned platform action it names (`pipegen-checkout` only on actions/checkout).
 */
function isKnownHarmless(s: RenderedStep): boolean {
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

/** The renderer-filled inputs of an action for this service and context (the others are set by the helpers that own them). */
function rendererFill(usesPath: string, service: Service | undefined, ctx: RenderContext, registry?: string): Record<string, string> {
  if (usesPath === 'docker/login-action') {
    // the login sends the workflow token: only to ghcr.io (the entry offers nothing else; this holds if it ever does)
    if ((registry ?? 'ghcr.io') !== 'ghcr.io') throw new RenderError('A login to a registry other than ghcr.io would need its own secrets; pipegen does not send the workflow token anywhere else.');
    return { username: '${{ github.actor }}', password: '${{ secrets.GITHUB_TOKEN }}' };
  }
  if (usesPath !== 'docker/build-push-action') return {};
  const out: Record<string, string> = {};
  if (service !== undefined) {
    // the template fixes `context: .`, so a Dockerfile in a sub-folder would be built with the wrong context (ruling S8)
    if (service.path !== '.' && service.path !== '') throw new RenderError(`The service ${show(service.name)} is in a sub-folder, but the image build context is the repository root, so pipegen can't build it yet.`);
    if (service.dockerfile !== undefined) out.file = service.dockerfile;
  }
  if (ctx.targets?.image !== undefined) out.tags = ctx.targets.image;
  return out;
}

// ---------- job prelude, upload, settings ----------

export interface PreludeOptions {
  fetchDepth?: '1' | '0';
  /** Set up Node. `runtimeVersion` is the repo's raw text (Service.runtimeVersion); it is only mapped, never rendered. */
  node?: { runtimeVersion?: string };
}

/**
 * The first steps of a job: checkout (credentials not kept, unsafe PR checkout off: both locks come from the reviewed
 * entry and are checked) and, when asked, setup-node with its package-manager cache off and the version mapped onto the
 * reviewed set. `notes` says what was changed from what the repo asked.
 */
export function renderJobPrelude(opts: PreludeOptions, platform: PlatformActions): { steps: RenderedStep[]; notes: string[] } {
  const steps: RenderedStep[] = [];
  const notes: string[] = [];
  const checkout = platformEntry(platform, 'checkout');
  const depth = opts.fetchDepth ?? '1';
  if (!(checkout.choices['fetch-depth'] ?? []).includes(depth)) throw new RenderError(`The reviewed checkout entry doesn't offer fetch-depth ${show(depth)}.`);
  steps.push(actionStep(checkout, 'Check out the repository', { 'fetch-depth': depth }, {}));
  if (opts.node !== undefined) {
    const setup = platformEntry(platform, 'setup-node');
    const mapped = mapNodeVersion(opts.node.runtimeVersion, setup.choices['node-version'] ?? []);
    if (mapped.note !== undefined) notes.push(mapped.note);
    steps.push(actionStep(setup, 'Set up Node.js', { 'node-version': mapped.version }, {}));
  }
  return { steps, notes };
}

/**
 * The upload of one result (ruling B3: separate from renderStep, so the scrub step can sit before it). Runs even when
 * the job failed, never uploads hidden files, and fails when the file is missing. `artifact` is a result artifact name
 * (artifact-names.ts) and `path` a place under `${{ runner.temp }}/pipegen-out/`.
 */
export function renderUpload(artifact: string, path: string, platform: PlatformActions): RenderedStep {
  // the folder is this artifact's own: another check's unscrubbed file must not go up under this name
  const folder = `\${{ runner.temp }}/pipegen-out/${artifact}`;
  if (path !== folder && !path.startsWith(`${folder}/`)) throw new RenderError('An upload may only take a path inside its own artifact folder.');
  const step = renderPlatformStep('upload-artifact', platform, { name: artifact, path });
  return { ...step, name: 'Upload the result', if: 'always()' };
}

/**
 * The built-in step that runs a service's own `test` or `lint` script (ruling S10, F3): the prelude's checkout and
 * setup-node, the guarded repo `npm ci --ignore-scripts` (the repo-code install of render-cli.ts, same id and marker as the
 * repo-code tools, so a job installs once), then `npm test` / `npm run lint`. npm only: pnpm, yarn and bun are "not
 * supported yet", Python is Plan W's. Every repo-derived value is checked: the script must be one the service has, the
 * folder must be the service's own path, the runtime version is only mapped. The run step is a repo-code step.
 */
export function renderProjectScript(step: ProjectScriptStep, platform: PlatformActions, ctx: RenderContext): RenderResult {
  const svc = ctx.profile.services.find((s) => s.name === step.service);
  if (svc === undefined) throw new RenderError(`The project script is for ${show(step.service)}, which is not a service pipegen found.`);
  if (step.script !== 'test' && step.script !== 'lint') throw new RenderError(`${show(step.script)} is not a script pipegen runs (only test and lint).`);
  if (!svc.scripts.includes(step.script)) throw new RenderError(`The service ${show(svc.name)} has no ${step.script} script, so there is no script to run.`);
  if (svc.language === 'python' || svc.packageManager === 'pip' || svc.packageManager === 'poetry' || svc.packageManager === 'uv') {
    throw new RenderError(`The service ${show(svc.name)} is a Python project; running its scripts is Plan W's work, not supported yet in this version (Plan W).`);
  }
  if (svc.packageManager === 'pnpm' || svc.packageManager === 'yarn' || svc.packageManager === 'bun' || svc.packageManager === 'other') {
    throw new RenderError(`${svc.packageManager} is not supported yet: pipegen runs project scripts with npm only.`);
  }
  if (svc.language !== 'node') throw new RenderError(`The service ${show(svc.name)} is not a Node project; its scripts are not supported yet.`);
  const expected = svc.path === '' || svc.path === '.' ? undefined : svc.path;
  if (step.workingDir !== expected || (expected !== undefined && !PLAIN_REL_RE.test(expected))) throw new RenderError(`The folder ${show(step.workingDir)} is not the plain folder of the service ${show(svc.name)}.`);
  let artifact: string;
  try {
    artifact = resultArtifactName(step.needId, svc.name);
  } catch (e) {
    if (e instanceof ArtifactNameError) throw new RenderError(e.message);
    throw e;
  }
  const prelude = renderJobPrelude({ node: { runtimeVersion: svc.runtimeVersion } }, platform).steps;
  const setup = prelude[1] as RenderedStep;
  const nodeMajor = setup.with?.['node-version'];
  if (nodeMajor === undefined || !/^\d{1,3}$/.test(nodeMajor)) throw new RenderError('The Node setup step has no plain node-version.');
  return { steps: [{ ...(prelude[0] as RenderedStep), id: 'pipegen-checkout' }, { ...setup, id: `pipegen-setup-node-${nodeMajor}` }, ...projectScriptSteps(artifact, step.script, nodeMajor, expected)], output: null };
}

/** Put on every job that feeds the gate, builds, signs or verifies (Plan G): no cache of any kind. */
export function jobSettings(spec: StepSpec): { 'cache-mode': 'none' } {
  return { 'cache-mode': 'none' };
}

// ---------- YAML ----------

const KEY_ORDER = ['id', 'name', 'if', 'uses', 'with', 'run', 'shell', 'env', 'working-directory', 'continue-on-error', 'timeout-minutes'] as const;
const NEEDS_QUOTES = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]|\$\{\{|^\s|\s$|\s#|:\s|^[-?:,[\]{}#&*!|>'"%@`]/;

/** A string scalar that can't be read as anything else: quoted whenever it has control characters, an expression or YAML syntax. */
function str(value: string, block = false): Scalar {
  const s = new Scalar(value);
  if (block && value.includes('\n') && !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]|\s\n|^\s/.test(value)) s.type = Scalar.BLOCK_LITERAL;
  else if (NEEDS_QUOTES.test(value)) s.type = Scalar.QUOTE_DOUBLE;
  return s;
}

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
  for (const key of KEY_ORDER) {
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

/**
 * Steps as a YAML sequence node, built with the `yaml` Document API so no value can break out of its scalar: a name
 * with a newline or `${{` stays one quoted string. The version goes in as the trailing comment on `uses:` (cut to one
 * plain line). Expressions are refused except the forms pipegen writes (checkExpressions). Plan G puts this node into its workflow Document, so the files and the snapshots show the same YAML.
 */
export function stepsToYaml(steps: readonly RenderedStep[]): YAMLSeq {
  const seq = new YAMLSeq();
  for (const step of steps) {
    checkExpressions(step);
    const map = new YAMLMap();
    for (const key of KEY_ORDER) {
      const value = step[key];
      if (value === undefined) continue;
      if (typeof value === 'string') {
        const node = str(value, key === 'run');
        if (key === 'uses' && step.usesComment !== undefined) node.comment = ` ${step.usesComment.replace(/[^\x20-\x7e]+/g, ' ').trim().slice(0, 80)}`;
        map.set(key, node);
      } else if (typeof value === 'object') {
        const inner = new YAMLMap();
        for (const [k, v] of Object.entries(value)) inner.set(new Scalar(k), str(v));
        map.set(key, inner);
      } else map.set(key, new Scalar(value));
    }
    seq.add(map);
  }
  return seq;
}
