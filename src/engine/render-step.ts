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
// - 6a builds the action kind completely. The CLI kinds (github-release, docker, npm, pip) are 6b and throw a
//   RenderError until then; rule archives, slots and project scripts are 6c.
import { isDeepStrictEqual } from 'node:util';
import { Scalar, YAMLMap, YAMLSeq } from 'yaml';
import { safeText } from '../util/safe-text.js';
import type { OutputFormat, RepoProfile, ReviewedTool, Service, StepSpec } from '../types.js';
import { COMMIT_SHA_RE } from './names.js';
import { NEED_IDS } from './need-ids.js';
import type { PlatformActions } from './pin.js';
import { rendererInputProblems } from './tool-flags.js';

export class RenderError extends Error {}

/** What a render needs besides the step: the repo facts (services, folders) and, for steps that need them, run-time targets (ruling S2). */
export interface RenderContext {
  profile: RepoProfile;
  /** Values only known at render time (6c slots): an image reference, a local URL, an API spec path. Never from the AI. */
  targets?: { image?: string; url?: string; spec?: string };
}

/** One step of a job, as pipegen renders it. `usesComment` becomes the trailing `# <version>` comment on `uses:`. */
export interface RenderedStep {
  id?: string; name: string; if?: string; uses?: string; usesComment?: string; with?: Record<string, string>;
  run?: string; shell?: 'bash'; env?: Record<string, string>; 'working-directory'?: string;
  'continue-on-error'?: boolean; 'timeout-minutes'?: number;
}

/** `output`: where the tool's result will be, under `${{ runner.temp }}` (ruling S7); null when the step makes none. */
export interface RenderResult { steps: RenderedStep[]; output: { path: string; format: OutputFormat } | null }

// ---------- shared checks ----------

/** A `with:` value from a template or a choice: plain words only (no expression, no quote, no shell character). */
const WITH_VALUE_RE = /^[A-Za-z0-9_@./:,=+\- ]{0,300}$/;
/** A folder or file that is repo-relative, plain, no `*`, no `..`, not an option (`-x`). */
const PLAIN_REL_RE = /^(?![-/])(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,200}$/;
const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]{0,99}$/;
const DEPENDENCY_KINDS: readonly string[] = ['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq', 'external'];
/** Env names a mapped secret must never take: they change how a shell, runtime, tool or the runner itself behaves (ruling S9). */
const DANGEROUS_EXACT: ReadonlySet<string> = new Set(['CI', 'PATH', 'HOME', 'BASH_ENV', 'ENV', 'SHELLOPTS', 'PS4', 'IFS']);
const DANGEROUS_PREFIX = ['GITHUB_', 'RUNNER_', 'ACTIONS_', 'PIPEGEN_', 'NODE_', 'NPM_CONFIG_', 'npm_config_', 'LD_', 'DYLD_', 'GIT_', 'DOCKER_', 'PYTHON', 'TRIVY_', 'HADOLINT_', 'PINACT_', 'SEMGREP_', 'COVERAGE_'];

/** A value from outside, shown in a message: one clean line, cut short, quoted when it is a string. */
const show = (v: unknown): string => (typeof v === 'string' ? JSON.stringify(safeText(v, 60)) : safeText(String(v), 30));
const same = (a: unknown, b: unknown): boolean => isDeepStrictEqual(a, b);
const own = <T>(o: Readonly<Record<string, T>>, k: string): T | undefined => (Object.hasOwn(o, k) ? o[k] : undefined);

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
    else spec.needsServices.forEach((k, i) => { if (!DEPENDENCY_KINDS.includes(k)) problem(`needsServices[${i}]`, `${show(k)} isn't a service kind pipegen can start.`); });
  }

  // secrets: names only, a real variable of this service, never one that changes how code runs (ruling S9)
  if (spec.secrets !== undefined) {
    if (!Array.isArray(spec.secrets)) problem('secrets', 'must be a list of names.');
    else {
      const declared = declaredEnvVars(service === undefined ? services : [service]);
      const seen = new Set<string>();
      spec.secrets.forEach((name, i) => {
        const path = `secrets[${i}]`;
        if (typeof name !== 'string' || !SECRET_NAME_RE.test(name)) problem(path, `${show(name)} isn't a secret name (capital letters, digits and _, starting with a letter, at most 100 characters).`);
        else if (DANGEROUS_EXACT.has(name) || DANGEROUS_PREFIX.some((p) => name.startsWith(p))) problem(path, `${name} can't be passed to a step: it changes how code runs or what the runner does.`);
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
  const chosen = chosenInputs(tool, choices);
  const fill = rendererInputProblems(path, filled);
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
 * id or pin differs from the spec's, or a kind not built yet. It never uploads the output (ruling B3). `platform` is for
 * the CLI kinds (6b), whose steps need the platform actions; an action step doesn't use it.
 */
export function renderStep(spec: StepSpec, tool: ReviewedTool, platform: PlatformActions, ctx: RenderContext): RenderResult {
  if (!isReviewed(tool.candidate)) throw new RenderError(`${show(tool.id)} is not a reviewed tool, and pipegen never renders a tool that isn't.`);
  const problems = validateSpec(spec, tool, ctx);
  if (problems.length > 0) throw new RenderError(`The step for ${show(spec.needId)} isn't valid: ${problems.join(' ')}`);
  if (tool.candidate.kind !== 'action' || tool.step.action === undefined) {
    throw new RenderError(`not implemented in 6a: ${tool.step.cli?.install.method ?? tool.candidate.kind}`);
  }
  if (tool.step.output.format !== 'none') throw new RenderError(`not implemented in 6a: an action that writes a result (${show(tool.id)}); its output is moved under runner.temp in 6b.`);

  const { path } = usesOf(tool);
  const service = spec.service === undefined ? undefined : ctx.profile.services.find((s) => s.name === spec.service);
  const step = actionStep(tool, `pipegen: ${path}`, spec.choices, rendererFill(path, service, ctx));
  const secrets = spec.secrets ?? [];
  if (secrets.length > 0) step.env = Object.fromEntries(secrets.map((n) => [n, `\${{ secrets.${n} }}`]));
  return { steps: [step], output: null };
}

/** The renderer-filled inputs of an action for this service and context (the others are set by the helpers that own them). */
function rendererFill(usesPath: string, service: Service | undefined, ctx: RenderContext): Record<string, string> {
  if (usesPath === 'docker/login-action') return { username: '${{ github.actor }}', password: '${{ secrets.GITHUB_TOKEN }}' };
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
  for (const lock of ['persist-credentials', 'allow-unsafe-pr-checkout']) {
    if (own(checkout.fixedInputs.with ?? {}, lock) !== 'false') throw new RenderError(`The reviewed checkout entry no longer fixes ${lock} to false.`);
  }
  const depth = opts.fetchDepth ?? '1';
  if (!(checkout.choices['fetch-depth'] ?? []).includes(depth)) throw new RenderError(`The reviewed checkout entry doesn't offer fetch-depth ${show(depth)}.`);
  steps.push(actionStep(checkout, 'Check out the repository', { 'fetch-depth': depth }, {}));
  if (opts.node !== undefined) {
    const setup = platformEntry(platform, 'setup-node');
    if (own(setup.fixedInputs.with ?? {}, 'package-manager-cache') !== 'false') throw new RenderError('The reviewed setup-node entry no longer turns its package-manager cache off.');
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
  const step = renderPlatformStep('upload-artifact', platform, { name: artifact, path });
  return { ...step, name: 'Upload the result', if: 'always()' };
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

/**
 * Steps as a YAML sequence node, built with the `yaml` Document API so no value can break out of its scalar: a name
 * with a newline or `${{` stays one quoted string. The version goes in as the trailing comment on `uses:` (cut to one
 * plain line). Plan G puts this node into its workflow Document, so the files and the snapshots show the same YAML.
 */
export function stepsToYaml(steps: readonly RenderedStep[]): YAMLSeq {
  const seq = new YAMLSeq();
  for (const step of steps) {
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
