// The step renderer (Plan B Task 6, sub-task 6a: contracts and core). It turns a reviewed tool plus the AI's choices
// into workflow steps that go into users' CI, so every repo-, AI- or memory-derived string is hostile until checked.
// - A step is rendered only from the reviewed entry (`tool.step` + `tool.fixedInputs`) and `spec.choices`. `spec.action`,
//   `spec.cli` and `spec.output` are copies (memory, the AI): they must deep-equal the template or validateSpec reports
//   it; nothing is ever rendered from them (ruling B1). renderStep throws for anything that isn't a reviewed entry.
// - The AI may set only the keys in `tool.choices`, each to one of its listed values. Anything else a step needs at
//   run time (an artifact name, a SARIF file, a Dockerfile) is a renderer-filled input from RENDERER_INPUTS
//   (tool-flags.ts), each with its own checker (ruling S15).
// - renderStep never uploads (ruling B3): the scrub step (renderScrub, Plan C ruling B1) sits between the scan and the upload,
//   so renderUpload is a separate helper. A tool's raw result is in `pipegen-raw` and can not be uploaded; the scrub writes
//   the copy in `pipegen-out` that the upload takes. Result artifacts are named by artifact-names.ts (ruling B4).
// - Repo-derived values (Service.path, runtimeVersion, dockerfile) are validated or mapped, never copied raw (ruling S8).
//   All YAML is built with the `yaml` Document API (stepsToYaml); no step text is concatenated into YAML.
// - 6a builds the action kind completely; 6b the CLI kinds (github-release, docker, npm, pip) in render-cli.ts; 6c the rule
//   archives, the run-time slots (slots.ts), container actions and renderProjectScript.
import { isDeepStrictEqual } from 'node:util';
import { Scalar, YAMLMap, YAMLSeq } from 'yaml';
import { safeText } from '../util/safe-text.js';
import { DEPENDENCY_KINDS, type OutputFormat, type RepoProfile, type ReviewedTool, type Service, type StepSpec } from '../types.js';
import { COMMIT_SHA_RE } from './names.js';
import { NEED_IDS, toolCoversNeed } from './need-ids.js';
import type { PlatformActions } from './pin.js';
import { tuningProblems } from './tuning.js';
import { APP_RUNNING_CATEGORIES, projectScriptSteps, renderCliTool, sha16, type CliHooks, type RenderOptions } from './render-cli.js';
import { ArtifactNameError, resultArtifactName } from './artifact-names.js';
import type { ProjectScriptStep } from './reviewed.js';
import { own, RenderError, show } from './render-error.js';
import { checkExpressions, checkJobOrder, isDangerousName, isReviewed, STEP_KEYS, type JobContext, type RenderedStep, type ScanFact } from './job-rules.js';
import { jobListLiteral, type JobListEntry } from './gate-job-list.js';
import { BASE_CHECKOUT_REF, DOCKER_ACTION_USES, IMAGE_BUILT_ACTION_USES, isStagedTool, PIPEGEN_GATE_USES, PLAIN_REL_RE, PLATFORM_LOCKS, PLATFORM_USES, RENDERER_INPUTS, rendererInputProblems, scrubbedResultPath, scrubStepId, stagePath, stageStepId } from './tool-flags.js';

export { RenderError };
// the job rules live in job-rules.ts (one copy for the renderer, the emitter, the referee and the linters); re-exported for the callers that import them here
export { checkExpressions, checkJobOrder, IF_VALUES, isDangerousName, SECRET_REF_RE } from './job-rules.js';
export { NO_SCANS } from './job-rules.js';
export type { JobContext, RenderedStep, ScanFact };
export type { RenderOptions };

/** What a render needs besides the step: the repo facts (services, folders) and, for steps that need them, run-time targets (ruling S2). */
export interface RenderContext {
  profile: RepoProfile;
  /** Values only known at render time (6c slots): an image reference, a local URL, an API spec path. Never from the AI. */
  targets?: { image?: string; url?: string; spec?: string; k8sDir?: string };
  /** Render the target-branch (baseline) variant of the check: its result goes to the `pipegen-out-base-<needId>` artifact (the `base-scan` job). */
  base?: true;
}

/** `output`: where the tool's RAW result will be, `${{ runner.temp }}/pipegen-raw/<artifact>/<file>` (rulings S7 and B1: never uploadable; scrubbedPath gives the copy the scrub writes); null when the step makes none. */
export interface RenderResult {
  steps: RenderedStep[]; output: { path: string; format: OutputFormat } | null;
  /** The job needs the whole git history (a base ref slot, jscpd): its checkout must use fetch-depth 0 (renderJobPrelude `fetchDepth: '0'`). */
  fullHistory?: true;
}

// ---------- shared checks ----------

/** A `with:` value from a template or a choice: plain words only (no expression, no quote, no shell character). */
const WITH_VALUE_RE = /^[A-Za-z0-9_@./:,=+\- ]{0,300}$/;
const SECRET_NAME_RE = /^[A-Z][A-Z0-9_]{0,99}$/;
/** The tool's own choices (text values) of a spec's choices, without the tuning section. */
const textChoices = (c: StepSpec['choices']): Record<string, string> => Object.fromEntries(Object.entries(c).filter((e): e is [string, string] => typeof e[1] === 'string'));

const same = (a: unknown, b: unknown): boolean => isDeepStrictEqual(a, b);

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
  // a platform-only entry (checkout, setup, upload, login, ...) is a step helper, rendered by renderPlatformStep and never a check of a need; the referee refuses any spec that names one
  else if (!(tool.categories.length === 1 && tool.categories[0] === 'platform') && !toolCoversNeed(tool.categories, spec.needId)) problem('tool', `${show(tool.id)} does not cover the check ${show(spec.needId)} (its categories are ${tool.categories.map((c) => show(c)).join(', ')}).`);

  const service = spec.service === undefined ? undefined : services.find((s) => s.name === spec.service);
  if (spec.service !== undefined && service === undefined) problem('service', `${show(spec.service)} isn't a service of this repository.`);

  // choices: only the keys the entry offers, each at one of its listed values
  if (typeof spec.choices !== 'object' || spec.choices === null || Array.isArray(spec.choices)) problem('choices', 'must be a map of choice names to values.');
  else {
    for (const [key, value] of Object.entries(spec.choices)) {
      if (key === 'tuning') continue;   // the per-repo tuning section (6d), checked by tuningProblems below
      const path = `choices.${safeText(key, 40)}`;
      const offered = own(tool.choices, key);
      if (offered === undefined) {
        const names = Object.keys(tool.choices);
        problem(path, `this tool has no choice with that name.${names.length === 0 ? ' It offers no choices.' : ` It offers: ${names.join(', ')}.`}`);
      } else if (typeof value !== 'string') problem(path, 'the value must be text.');
      else if (!offered.includes(value)) problem(path, `${show(value)} is not one of the values this tool allows (${offered.join(', ')}).`);
    }
  }

  // per-repo tuning (6d): every value must be in the enum built for this call from the profile
  if (typeof spec.choices === 'object' && spec.choices !== null && !Array.isArray(spec.choices)) out.push(...tuningProblems(spec, tool, ctx));

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
  if (Array.isArray(spec.secrets) && spec.secrets.length > 0 && !tool.categories.some((cat) => APP_RUNNING_CATEGORIES.has(cat))) {
    problem('secrets', `${show(tool.id)} does not run the app: declared secrets reach only steps that run the app (tests, builds), never a scanner, linter, action or upload step.`);
  }
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

/** Actions the renderer fills inputs for through their own helper (renderUpload, renderPlatformStep); renderStep refuses them. */
const HELPER_ONLY: ReadonlySet<string> = new Set(Object.keys(RENDERER_INPUTS).filter((k) => k !== 'docker/login-action' && k !== 'docker/build-push-action' && k !== 'actions/checkout'));   // checkout's only renderer input (the base ref) is optional: renderStep renders it without

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
  if (tool.step.output.format !== 'none') throw new RenderError(`an action that writes a result (${show(tool.id)}) can't be rendered: its output would have to be moved under runner.temp first, and no reviewed action needs that yet.`);

  const { path } = usesOf(tool);
  const service = spec.service === undefined ? undefined : ctx.profile.services.find((s) => s.name === spec.service);
  const step = actionStep(tool, `pipegen: ${path}`, textChoices(spec.choices), rendererFill(path, service, ctx, typeof spec.choices.registry === 'string' ? spec.choices.registry : tool.choices.registry?.[0]));
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
 * `job` (C0b, required): the job's id and the scan facts of its scrub steps, for the shared job rules (checkJobOrder): the base checkout ref only
 * in `base-scan`, and each scrub step equal to its scan (scanFactOf gives the fact of a rendered tool).
 */
export function dedupeJobSteps(steps: readonly RenderedStep[], job: JobContext): RenderedStep[] {
  if (!(job?.scans instanceof Map)) throw new RenderError('dedupeJobSteps needs the scan facts of the job (JobContext.scans; NO_SCANS for a job with no scan step), or it could not hold a scrub step to its scan.');
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
  const order = checkJobOrder(kept, job);
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
  /** Check out the base commit instead of the event's own (the `base-scan` job only, ruling S16): the one event-switched expression BASE_CHECKOUT_REF. */
  baseRef?: true;
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
  if (opts.baseRef !== undefined && opts.baseRef !== true) throw new RenderError('baseRef is true or absent: the base checkout has one form (BASE_CHECKOUT_REF).');
  const ref = opts.baseRef === true ? BASE_CHECKOUT_REF : undefined;
  steps.push(actionStep(checkout, opts.baseRef === undefined ? 'Check out the repository' : 'Check out the base commit', { 'fetch-depth': depth }, ref === undefined ? {} : { ref }));
  if (opts.node !== undefined) {
    const setup = platformEntry(platform, 'setup-node');
    const mapped = mapNodeVersion(opts.node.runtimeVersion, setup.choices['node-version'] ?? []);
    if (mapped.note !== undefined) notes.push(mapped.note);
    steps.push(actionStep(setup, 'Set up Node.js', { 'node-version': mapped.version }, {}));
  }
  return { steps, notes };
}

/**
 * The scrubbed copy of a raw result path (`${{ runner.temp }}/pipegen-raw/<artifact>/<file>`): the same artifact and file under
 * `${{ runner.temp }}/pipegen-out/`, which `renderUpload` takes. Throws for any other text.
 */
export function scrubbedPath(rawPath: string): string {
  const out = scrubbedResultPath(rawPath);
  if (out === null) throw new RenderError(`${show(rawPath)} is not a raw result path (\${{ runner.temp }}/pipegen-raw/<artifact>/<file>).`);
  return out;
}

/** The gate entry must be the reviewed, pinned gate action with no fixed input and no choice: pipegen sets every input itself. */
function checkGateEntry(gate: ReviewedTool): void {
  if (!isReviewed(gate.candidate)) throw new RenderError('The gate action is not a reviewed entry.');
  if (usesOf(gate).path !== PIPEGEN_GATE_USES) throw new RenderError(`The gate entry does not run ${PIPEGEN_GATE_USES}.`);
  if (Object.keys(gate.fixedInputs.with ?? {}).length > 0 || Object.keys(gate.choices).length > 0) throw new RenderError('The gate entry may fix no input and offer no choice: pipegen sets every input of the gate action itself.');
}

/**
 * The scrub step of one result (Plan C ruling B1, part 7): pipegen's gate action in `scrub` mode rebuilds the raw result
 * from allowlisted fields plus HMAC fingerprints, and writes it to `pipegen-out/<artifact>/<file>`, the only copy that
 * is uploaded. It runs even when the scan step failed (the raw file is then missing and the scrub reports a tool error).
 * `rawPath` is `RenderResult.output.path`; `tool` the reviewed id of the scanner; `gate` the reviewed gate entry (it fixes
 * no input and offers no choice: every input is set here and checked by RENDERER_INPUTS).
 */
export function renderScrub(artifact: string, rawPath: string, tool: string, format: 'sarif' | 'zap-json', gate: ReviewedTool): RenderedStep {
  checkGateEntry(gate);
  const out = scrubbedPath(rawPath);
  // C1c: the scrub of a secrets scan reads the stage folder's manifest, to map the findings back and to prove coverage by the canaries
  const staged: Record<string, string> = isStagedTool(tool) ? { stage: stagePath(artifact) } : {};
  const step = actionStep(gate, 'pipegen: scrub the result', {}, { mode: 'scrub', artifact, tool, format, raw: rawPath, out, 'fp-key': '${{ secrets.PIPEGEN_FP_KEY }}', ...staged });
  return { id: scrubStepId(artifact), ...step, if: 'always()' };
}

/**
 * The stage step of a secrets scan (C1c): pipegen's gate action in `stage` mode copies every regular file of the checkout into
 * `${{ runner.temp }}/pipegen-stage/<artifact>` under neutral names, each ending with a fresh canary line, and writes the manifest
 * (gate/src/stage.ts). It comes after the checkout and before the scanner, in the secrets job only (checkJobOrder,
 * stageChainProblems). No condition: when it fails, the scan does not run and the scrub reports a tool error.
 */
export function renderStage(artifact: string, tool: string, gate: ReviewedTool): RenderedStep {
  checkGateEntry(gate);
  if (!isStagedTool(tool)) throw new RenderError(`${show(tool)} does not scan a stage folder, so it has no stage step.`);
  const step = actionStep(gate, 'pipegen: stage the files for the secrets scan', {}, { mode: 'stage', artifact, tool, stage: stagePath(artifact) });
  return { id: stageStepId(artifact), ...step };
}

/**
 * The steps of one findings check after the job's prelude, as Plan G composes a scanner job (C1c): the stage step for a tool that scans
 * a stage folder (the secrets tools), the tool's own steps (install, run), the scrub and the upload. `scan` is the scan fact for the
 * job rules (dedupeJobSteps). Throws RenderError for a tool that writes no findings file.
 */
export function renderFindingsBlock(spec: StepSpec, tool: ReviewedTool, platform: PlatformActions, ctx: RenderContext, gate: ReviewedTool): { steps: RenderedStep[]; artifact: string; scan: { stepId: string; fact: ScanFact }; result: RenderResult } {
  const result = renderStep(spec, tool, platform, ctx);
  const out = result.output;
  const scan = scanFactOf(result, tool.id);
  if (out === null || scan === null || (out.format !== 'sarif' && out.format !== 'zap-json')) throw new RenderError(`${show(tool.id)} writes no findings file, so it has no scrub and no upload.`);
  const artifact = resultArtifactName(spec.needId, spec.service, ctx.base === true ? { base: true } : undefined);
  const stage = isStagedTool(tool.id) ? [renderStage(artifact, tool.id, gate)] : [];
  const scrub = renderScrub(artifact, out.path, tool.id, out.format, gate);
  return { steps: [...stage, ...result.steps, scrub, renderUpload(artifact, scrubbedPath(out.path), platform)], artifact, scan, result };
}

/**
 * The upload of one result (ruling B3: separate from renderStep, so the scrub step can sit before it). Runs even when
 * the job failed, never uploads hidden files, and fails when the file is missing. `artifact` is a result artifact name
 * (artifact-names.ts) and `path` a place under `${{ runner.temp }}/pipegen-out/<artifact>`: the scrubbed copy
 * (scrubbedPath), never the raw one, and the job must hold the scrub step of that artifact before it (checkJobOrder).
 */
export function renderUpload(artifact: string, path: string, platform: PlatformActions): RenderedStep {
  // the path must sit in this artifact's own folder: the rule is the shared whenWith of RENDERER_INPUTS (tool-flags.ts), which the emitter and the referee also use
  const step = renderPlatformStep('upload-artifact', platform, { name: artifact, path });
  return { ...step, name: 'Upload the result', if: 'always()' };
}

/** The optional literal inputs of the gate step in mode `gate` (each is checked by its schema in RENDERER_INPUTS). */
export interface GateStepOptions {
  /** need ids the user chose not to prove */ notProven?: readonly string[];
  /** need ids skipped with --skip */ skipped?: readonly string[];
  policy?: { block: readonly string[]; warn: readonly string[] };
  /** extra protected path globs */ protectedPaths?: readonly string[];
  /** the date the install recorded for blocking, YYYY-MM-DD */ blockFromRecorded?: string;
}

/**
 * The gate step in mode `gate` (Plan C ruling B3): the job list literal from gateJobList, the needs of the gate job as
 * `${{ toJSON(needs) }}`, the block-from variable, the workflow token and the fingerprint key. The gate job holds this step
 * and no checkout (the gate never reads the workspace, ruling S21), and its `needs` include every job of the list.
 */
export function renderGateStep(gate: ReviewedTool, entries: readonly JobListEntry[], opts: GateStepOptions = {}): RenderedStep {
  checkGateEntry(gate);
  const filled: Record<string, string> = {
    mode: 'gate', jobs: '${{ toJSON(needs) }}', 'job-list': jobListLiteral(entries),
    'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', 'github-token': '${{ secrets.GITHUB_TOKEN }}', 'fp-key': '${{ secrets.PIPEGEN_FP_KEY }}',
  };
  if (opts.notProven !== undefined) filled['not-proven'] = JSON.stringify(opts.notProven);
  if (opts.skipped !== undefined) filled.skipped = JSON.stringify(opts.skipped);
  if (opts.policy !== undefined) filled.policy = JSON.stringify({ block: opts.policy.block, warn: opts.policy.warn });
  if (opts.protectedPaths !== undefined) filled['protected-paths'] = JSON.stringify(opts.protectedPaths);
  if (opts.blockFromRecorded !== undefined) filled['block-from-recorded'] = opts.blockFromRecorded;
  return actionStep(gate, 'pipegen: the merge gate', {}, filled);
}

/**
 * The gate step in mode `baseline-check` (Plan C task C3), for the job `baseline-check`: the workflow token and the fingerprint key,
 * nothing else (the gate checks the stored baseline's signature with the key and reads artifacts with the token). Like the gate job,
 * that job holds no checkout of repo code beyond what its policy row allows, and no other step of the gate action.
 */
export function renderBaselineCheckStep(gate: ReviewedTool): RenderedStep {
  checkGateEntry(gate);
  return actionStep(gate, 'pipegen: check the stored baseline', {}, {
    mode: 'baseline-check', 'github-token': '${{ secrets.GITHUB_TOKEN }}', 'fp-key': '${{ secrets.PIPEGEN_FP_KEY }}',
  });
}

/**
 * The scan fact of a rendered tool: the id of its run step (the last step with a `run`) and the reviewed tool id with the
 * format of its result, for the scrub cross-checks (JobContext.scans). Null when the tool writes no findings file (format none or junit).
 */
export function scanFactOf(result: RenderResult, tool: string): { stepId: string; fact: ScanFact } | null {
  const format = result.output?.format;
  if (format !== 'sarif' && format !== 'zap-json') return null;
  const run = [...result.steps].reverse().find((s) => s.run !== undefined);
  return run?.id === undefined ? null : { stepId: run.id, fact: { tool, format } };
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
 * plain line). Expressions are refused except the forms pipegen writes (checkExpressions). Plan G puts this node into its workflow Document, so the files and the snapshots show the same YAML.
 */
export function stepsToYaml(steps: readonly RenderedStep[]): YAMLSeq {
  const seq = new YAMLSeq();
  for (const step of steps) {
    checkExpressions(step);
    const map = new YAMLMap();
    for (const key of STEP_KEYS) {
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
