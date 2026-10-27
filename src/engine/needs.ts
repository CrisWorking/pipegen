// Needs planner (Plan B Task 1): which checks ("needs") a repo gets, per layer.
// - floorNeeds: the security floor, decided by rules from the RepoProfile and the capabilities. Never removed.
// - planNeeds: the AI may ADD needs (ids, layers, categories and services are schema enums) and propose skipping
//   the deploy layer when nothing runs or deploys. It can't remove or change a floor need (spec §19 "AI", T4).
// Need identity is (layer, id, service) (Plan B ruling S11).
import { z } from 'zod';
import { needsInstructions, NEEDS_SYSTEM } from '../ai/prompts/needs.js';
import { completeValidated, formatAiText } from '../ai/provider.js';
import { bundleText, redact, scrubKnownValues, type CodeBundle } from '../ai/redact.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { signingMode } from '../github/signing-mode.js';
import { SERVER_FRAMEWORKS, SERVICE_NAME_RE } from '../read/project.js';
import { NEEDS_MAX_OUTPUT_TOKENS } from './discovery-limits.js';
import { NEED_ID_CATEGORY, NEED_IDS, REPO_WIDE_CATEGORIES, type NeedId } from './need-ids.js';
import {
  FLOOR_NEEDS, NEED_CATEGORIES, type AiProvider, type AiRequest, type AiUsage, type Capabilities, type Layer, type Need, type NeedCategory,
  type RepoProfile, type Service,
} from '../types.js';

export const LAYERS = ['pre-commit', 'push', 'merge', 'deploy'] as const satisfies readonly Layer[];

export { AI_ONLY_IDS, NEED_ID_CATEGORY, NEED_IDS, REPO_WIDE_CATEGORIES, SCHEDULED_CATEGORIES, type NeedId } from './need-ids.js';

/**
 * Categories whose merge-layer jobs also run in the nightly (ruling S10): the scanners, plus the image build the image
 * scan and DAST need (spike S5's real nightly built the image; final review M8). A merge-layer image build only
 * exists for a runnable service, so the nightly builds an image exactly when the merge layer does.
 */
const NIGHTLY: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'iac', 'image-scan', 'dast', 'image-build', 'scorecard']);
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const RUN_SCRIPTS = ['start', 'dev', 'serve'];
const NEEDS_TIMEOUT_MS = 120_000;

/** Bounds on what is read from one AI answer (in code, not in the schema: Claude's structured outputs don't take maxItems). */
const MAX_AI_SKIPS = 4;
const MAX_AI_ADDS_READ = 48;
const MAX_AI_ADDS_KEPT = 16;

/** Checks that need a running service (an image or a live app). */
const IMAGE_IDS: ReadonlySet<NeedId> = new Set<NeedId>(['image-build', 'image-scan', 'dast']);

const isFloorId = (id: NeedId): id is NeedCategory => (NEED_CATEGORIES as readonly string[]).includes(id);

/** One note per reason an AI addition was dropped; `items` lists "id in layer" (enum values only). */
const REFUSED = {
  gate: (items: string) => `The AI tried to add a gate need (${items}); pipegen ignored it, since it sets up the one merge gate itself.`,
  category: (items: string) => `The AI gave the wrong category to ${items}; pipegen left those needs out.`,
  notInFloor: (items: string) => `The AI suggested ${items}, which this repo's plan doesn't include (for example signing on a private Free repo, or an image scan with nothing to run); pipegen left them out.`,
  layer: (items: string) => `The AI tried to add ${items}, a layer pipegen doesn't add AI checks to here (for example a pull-request-only or scheduled check on push); pipegen left them out.`,
  notRunnable: (items: string) => `The AI suggested ${items}, but image checks only apply to services that run; pipegen left them out.`,
  repoWide: (items: string) => `The AI tried to add ${items} for one service, but that check covers the whole repo; pipegen left them out.`,
  notDeployed: (items: string) => `The AI suggested ${items}, but pipegen's deploy layer doesn't cover that; pipegen left them out.`,
} as const;

function listItems(items: string[]): string {
  const shown = items.slice(0, 5).join(', ');
  return items.length > 5 ? `${shown} and ${items.length - 5} more` : shown;
}

const LINK = /https?:\/\/\S*/gi;
/** AI text for display: links removed (before and after cleaning, so a control character can't hide one), then safeText. Also used by discovery. */
export function cleanAiText(s: string): string {
  const noLinks = (t: string) => t.replace(LINK, '(link removed)');
  return formatAiText(noLinks(formatAiText(noLinks(s), 4000)));
}

/** pipegen's own plain-English reason for the older needs; the Plan P checks' reasons are in the CHECKS table. */
const OLD_WHY: Readonly<Record<string, string>> = {
  secrets: 'Stops passwords, keys and tokens from being committed or merged.',
  sast: 'Scans the source code for common security bugs.',
  deps: 'Checks the dependencies for known vulnerabilities.',
  'unit-tests': 'Runs the unit tests so broken code is caught early.',
  'full-tests': 'Runs the full test suite before anything is merged.',
  lint: 'Runs the linter to catch mistakes and keep the code consistent.',
  'format-lint': 'Checks formatting and lint on changed files before each commit, without blocking it.',
  hooks: 'Sets up the git hook manager that runs the pre-commit checks.',
  'hooks-ci': 'Runs the pre-commit hooks in CI on all files, so skipping them locally is caught.',
  'image-build': 'Builds the container image once, so the same image is scanned and deployed.',
  'image-scan': 'Scans the container image for known vulnerabilities.',
  dast: 'Starts the app and probes it for security problems while it runs.',
  iac: 'Scans the Terraform and Kubernetes files for insecure infrastructure settings.',
  sbom: 'Lists every component in the build (an SBOM), so problems can be traced later.',
  signing: 'Signs the built image, so only gated images can be deployed.',
  attestation: 'Records a GitHub attestation of how the image was built.',
  'deploy-verify': 'Checks before each deploy that the commit passed the pipeline.',
  gate: 'The merge gate: one required check that sums up every blocking result.',
  'migration-check': 'Checks that database migrations apply cleanly.',
};

export interface NeedsPlan {
  needs: Need[];
  notes: string[];
  requireDeployApproval: boolean;
  /** Accepted layer skips (only deploy, when nothing runs and nothing deploys); feeds PipelineDraft.layersSkipped. */
  layersSkipped: { layer: Layer; reason: string }[];
  /** What the AI call cost, summed over every attempt (for the AI cost meter). */
  usage: AiUsage;
}

/**
 * A start, dev or serve script, a server framework, a port, or a Dockerfile. A library with only build/test scripts isn't.
 * Plan U Task 5: a package the repo publishes (Service.publishedPackage) needs a real server entry (a script, a
 * framework or a Dockerfile); a port number in its code alone (Flask's `app.run(port=5000)` default) doesn't make it one.
 */
export function isRunnable(s: Service): boolean {
  return s.scripts.some((n) => RUN_SCRIPTS.includes(n)) || s.frameworks.length > 0 || (s.port !== undefined && s.publishedPackage !== true)
    || (s.dockerfile ?? '') !== '';
}

const deploysExist = (p: RepoProfile) => p.existingWorkflows.some((w) => w.deploys);

/** The rule behind requireDeployApproval (spec §19 "AI"): deploys exist and the repo has at least 2 writers. */
export function deployApprovalRule(p: RepoProfile, writers: number): boolean {
  return deploysExist(p) && writers >= 2;
}

// ---------- the Plan P check table ----------

/** Where a check's needs go: per service, once for the repo, per runnable service, or by the deploy rules (publishing, egress). */
type CheckScope = 'service' | 'repo' | 'runnable' | 'published' | 'deploy-target';

/** The Plan P categories (the table's keys); typing the labels by this makes a missing label a compile error. */
export type CheckCategory = 'format' | 'type-check' | 'coverage' | 'dead-code' | 'duplication' | 'dockerfile-lint' | 'workflow-lint' | 'workflow-pin-check'
  | 'dependency-review' | 'licences' | 'api-dast' | 'publishing' | 'egress' | 'update-config' | 'scorecard' | 'fuzzing';

export interface CheckRule {
  category: CheckCategory;
  layers: readonly Layer[];
  scope: CheckScope;
  /** Whether a failure stops the merge; a function when it depends on the service (dead-code needs a knip config). */
  blocking: boolean | ((s: Service) => boolean);
  label: string;
  why: string;
  /** null when the check applies; otherwise the plain-English reason it doesn't. `s` is the service for service scopes. */
  skip: (p: RepoProfile, caps: Capabilities, s?: Service) => string | null;
}

const NO_SERVICES = 'no services found';
const hasPackageManager = (p: RepoProfile) => p.services.some((s) => s.packageManager !== undefined);
const publishes = (p: RepoProfile) => p.existingWorkflows.some((w) => (w.publishes?.length ?? 0) > 0);
const FORMAT_LANGUAGES: readonly string[] = ['node', 'python', 'go'];
const languageSkip = (s?: Service) => (s !== undefined && FORMAT_LANGUAGES.includes(s.language) ? null : 'only Node, Python and Go code is covered');

/**
 * THE table: for each Plan P check its layers, scope, when it applies, whether it blocks, its label and its why.
 * floorNeeds and skippedChecks both read it (through planChecks), so they can't disagree; the labels and whys feed
 * needLabel (model.ts) and the needs' `why`. SCHEDULED_CATEGORIES and REPO_WIDE_CATEGORIES (need-ids.ts, a leaf module)
 * must match it; a test pins that. The order here is the order of the needs after the older floor.
 */
export const CHECKS: readonly CheckRule[] = [
  { category: 'format', layers: ['push', 'merge'], scope: 'service', blocking: true, skip: (_p, _c, s) => languageSkip(s),
    label: 'Format check', why: 'Checks that the code is formatted one way everywhere, so reviews show real changes.' },
  { category: 'type-check', layers: ['push', 'merge'], scope: 'service', blocking: true,
    skip: (_p, _c, s) => {
      if (s?.language === 'node') return s.quality.tsconfig || s.quality.versions.typescript !== undefined ? null : 'no tsconfig.json or typescript dependency found';
      if (s?.language === 'python') return s.quality.pythonTyped ? null : 'no type checker config or py.typed: add a mypy config to turn this on';
      return 'only Node and Python code is type-checked';
    },
    label: 'Type check', why: 'Runs the type checker, so type errors fail the build instead of reaching users.' },
  { category: 'coverage', layers: ['push', 'merge'], scope: 'service', blocking: true, skip: (_p, _c, s) => (s?.hasTests === true ? null : 'no tests found'),
    label: 'Test coverage minimum', why: "Fails the build when test coverage drops below a minimum, so untested code can't creep in." },
  { category: 'dead-code', layers: ['push', 'merge'], scope: 'service', blocking: (s) => s.quality.configs.includes('knip'), skip: (_p, _c, s) => languageSkip(s),
    label: 'Dead code and unused dependencies', why: 'Finds unused files, exports and dependencies, which hide bugs and slow installs.' },
  { category: 'duplication', layers: ['merge'], scope: 'repo', blocking: false, skip: (p) => (p.services.length > 0 ? null : NO_SERVICES), // DEC #93: on by default, warning only
    label: 'Copy-paste check', why: 'Warns when a pull request adds copy-pasted code, which tends to get fixed in one copy and forgotten in the other.' },
  { category: 'dockerfile-lint', layers: ['push', 'merge'], scope: 'service', blocking: true, skip: (_p, _c, s) => ((s?.dockerfile ?? '') !== '' ? null : 'no Dockerfile found'),
    label: 'Dockerfile lint', why: 'Lints the Dockerfile for risky or broken instructions.' },
  { category: 'workflow-lint', layers: ['push', 'merge'], scope: 'repo', blocking: true, skip: () => null,
    label: 'Workflow lint', why: 'Checks the GitHub Actions workflows for mistakes and risky patterns such as script injection.' },
  { category: 'workflow-pin-check', layers: ['push', 'merge'], scope: 'repo', blocking: true, skip: () => null,
    label: 'Action pin check', why: "Checks that every action is pinned to an exact commit, so a moved tag can't change what runs." },
  { category: 'dependency-review', layers: ['merge'], scope: 'repo', blocking: true, skip: (p) => (hasPackageManager(p) ? null : 'no service with a package manager found'),
    label: 'New-dependency review', why: 'Checks the packages a pull request adds, so a known-vulnerable or malicious package is stopped before merge.' },
  { category: 'licences', layers: ['merge'], scope: 'repo', blocking: true, skip: (p) => (hasPackageManager(p) ? null : 'no service with a package manager found'),
    label: 'Licence check', why: 'Checks dependency licences, so a package the project may not use is caught before merge.' },
  { category: 'api-dast', layers: ['merge'], scope: 'runnable', blocking: true,
    skip: (_p, _c, s) => {
      if (s === undefined || !isRunnable(s)) return "this service doesn't run as a server, so there is nothing to call";
      return s.quality.apiSpec !== null ? null : 'no API spec found: export an OpenAPI file to turn on API testing';
    },
    label: 'API scan against the spec (API DAST)', why: 'Calls every API endpoint with unexpected input, following the API spec, to find crashes and security bugs.' },
  { category: 'publishing', layers: ['deploy'], scope: 'published', blocking: true, skip: (p) => (publishes(p) ? null : 'no workflow publishes a package'),
    label: 'Trusted publishing', why: 'Publishes packages with short-lived credentials, so there is no long-lived token to steal.' },
  { category: 'egress', layers: ['deploy'], scope: 'deploy-target', blocking: true, skip: (p) => (deployTargets(p) !== null ? null : 'no deploy or publish job to lock down'),
    label: 'Network lock for release jobs', why: "Blocks unexpected network traffic in release jobs, so a compromised tool can't send secrets out." },
  { category: 'update-config', layers: ['merge'], scope: 'repo', blocking: false, skip: () => null,
    label: 'Dependency update config', why: 'Opens update pull requests for dependencies, waiting 7 days so brand-new releases are skipped.' },
  { category: 'scorecard', layers: ['merge'], scope: 'repo', blocking: false,
    skip: (p, c) => (!p.private || c.codeScanning ? null : 'Scorecard needs GitHub code scanning on private repos'),
    label: 'OpenSSF Scorecard', why: "Scores the repo's security practices every week, so a weakened setting shows up." },
  { category: 'fuzzing', layers: ['merge'], scope: 'service', blocking: false, skip: (_p, _c, s) => (s?.quality.fuzzTargets === true ? null : 'no fuzz targets found'),
    label: 'Fuzzing (built in v0.3)', why: "Feeds random input to the code's fuzz targets to find crashes." },
];

/** Plain-English label of each Plan P check (model.ts folds these into needLabel). */
export const CHECK_LABELS = Object.freeze(Object.fromEntries(CHECKS.map((c) => [c.category, c.label]))) as Readonly<Record<CheckCategory, string>>;

/** pipegen's own plain-English reason for each need (floor needs, and AI needs that come back with no usable why). */
const WHY: Readonly<Record<string, string>> = Object.freeze({ ...OLD_WHY, ...Object.fromEntries(CHECKS.map((c) => [c.category, c.why])) });

/** The plain-English reason for a need id, or null for an id pipegen doesn't know. */
export function needWhy(id: string): string | null {
  return Object.hasOwn(WHY, id) ? (WHY[id] as string) : null;
}

/** Whether a check of this category blocks, for a service (by name). Categories outside the table: true. */
function checkBlocking(category: string, service: string | null | undefined, p: RepoProfile): boolean {
  const rule = CHECKS.find((c) => c.category === category);
  if (rule === undefined) return true;
  if (typeof rule.blocking === 'boolean') return rule.blocking;
  const s = p.services.find((x) => x.name === service);
  return s !== undefined && rule.blocking(s);
}

/**
 * The CI job a check shares, by category: `lint` for format, type-check and dead-code; `unit-tests` for coverage;
 * `workflow-lint` for the pin check. null = no job of its own (update-config and publishing are repo files and a
 * release step, egress a step inside release jobs, fuzzing waits for v0.3; scorecard runs only in the nightly, see NIGHTLY).
 * A category not listed is its own job. jobCategories and jobCounts both read this.
 */
export const JOB_GROUP: Readonly<Partial<Record<NeedCategory, NeedCategory | null>>> = Object.freeze({
  format: 'lint', 'type-check': 'lint', 'dead-code': 'lint', coverage: 'unit-tests', 'workflow-pin-check': 'workflow-lint',
  'update-config': null, publishing: null, egress: null, fuzzing: null, scorecard: null,
});
const jobGroup = (category: string): string | null => (Object.hasOwn(JOB_GROUP, category) ? (JOB_GROUP as Record<string, string | null>)[category] as string | null : category);

/** A check the plan leaves out for this repo, and why (plain English). `service` absent = the whole repo. */
export interface SkippedCheck { category: NeedCategory; service?: string; why: string }

/** Deploy targets of the older floor (undefined = repo-wide), or null when it has no deploy layer. */
function mainDeployTargets(p: RepoProfile): (string | undefined)[] | null {
  const names = p.services.map((s) => s.name);
  const runnable = p.services.filter(isRunnable).map((s) => s.name);
  if (runnable.length === 0 && !deploysExist(p)) return null;
  return runnable.length > 0 ? runnable : names.length > 0 ? names : [undefined];
}

/** PS7: the service a publishing workflow publishes (publishedPackage), else repo-wide. */
const publishedService = (p: RepoProfile): string | undefined => p.services.find((s) => s.publishedPackage === true)?.name;

/**
 * Where egress goes: the deploy layer's targets; when the layer exists only for publishing (PS7), the published
 * service (or repo-wide). null = no deploy layer at all.
 */
function deployTargets(p: RepoProfile): (string | undefined)[] | null {
  return mainDeployTargets(p) ?? (publishes(p) ? [publishedService(p)] : null);
}

/** Everything the table decides: the Plan P needs (in table order) and the checks left out, from one pass. */
function planChecks(p: RepoProfile, caps: Capabilities): { needs: Need[]; skipped: SkippedCheck[] } {
  const needs: Need[] = [];
  const skipped: SkippedCheck[] = [];
  const seen = new Set<string>();
  const skip = (category: NeedCategory, why: string, service?: string) => skipped.push({ category, ...(service === undefined ? {} : { service }), why });
  const add = (rule: CheckRule, layer: Layer, service?: string) => {
    const blocking = typeof rule.blocking === 'boolean' ? rule.blocking : (() => { const s = p.services.find((x) => x.name === service); return s !== undefined && rule.blocking(s); })();
    const n = makeNeed(layer, rule.category, service, blocking);
    if (seen.has(needKey(n))) return;
    seen.add(needKey(n));
    needs.push(n);
  };
  for (const rule of CHECKS) {
    if (rule.scope === 'repo') {
      const why = rule.skip(p, caps);
      if (why === null) for (const l of rule.layers) add(rule, l);
      else skip(rule.category, why);
    } else if (rule.scope === 'service' || rule.scope === 'runnable') {
      if (p.services.length === 0) { skip(rule.category, NO_SERVICES); continue; }
      for (const s of p.services) {
        const why = rule.skip(p, caps, s);
        if (why === null) for (const l of rule.layers) add(rule, l, s.name);
        else skip(rule.category, why, s.name);
      }
    } else if (rule.scope === 'published') {
      const why = rule.skip(p, caps);
      if (why === null) for (const l of rule.layers) add(rule, l, publishedService(p));
      else skip(rule.category, why);
    } else {
      const why = rule.skip(p, caps);
      const targets = deployTargets(p);
      if (why === null && targets !== null) {
        for (const t of targets) for (const l of rule.layers) add(rule, l, t);
        // A service that isn't a deploy target gets its own skip, so every service is accounted for.
        if (!targets.includes(undefined)) for (const s of p.services) if (!targets.includes(s.name)) skip(rule.category, "this service isn't deployed, so there is no release job to lock down", s.name);
      } else skip(rule.category, why ?? 'no deploy or publish job to lock down');
    }
  }
  return { needs, skipped };
}

/** The checks the plan leaves out, with a plain-English reason each. Decided by the same table as floorNeeds. */
export function skippedChecks(p: RepoProfile, caps: Capabilities): SkippedCheck[] {
  const out = planChecks(p, caps).skipped;
  const iac = iacSkip(p);
  if (iac !== null) out.push({ category: 'iac', why: iac });
  return out;
}

/** iac (an older check) now also applies to Kubernetes manifests. */
const iacSkip = (p: RepoProfile): string | null => (p.terraformDirs.length > 0 || p.repoFiles.kubernetes ? null : 'no Terraform or Kubernetes files found');

/** Need identity (layer, id, service): the key the planner, and the audit's AI step, dedupe needs by. */
export const needKey = (n: Pick<Need, 'layer' | 'id' | 'service'>) => `${n.layer}\u0000${n.id}\u0000${n.service ?? ''}`;

/** `blocking` comes from the CHECKS table for the Plan P checks; the older floor blocks except the format-lint hook. */
function makeNeed(layer: Layer, id: NeedCategory, service?: string, blocking: boolean = id !== 'format-lint'): Need {
  return {
    id, layer, category: id, ...(service === undefined ? {} : { service }), why: needWhy(id) ?? '',
    blocking, floor: FLOOR.has(id),
  };
}

/** The security floor. Per service unless repo-wide (hooks, hooks-ci, secrets, gate, iac). */
export function floorNeeds(p: RepoProfile, caps: Capabilities): Need[] {
  const out: Need[] = [];
  const seen = new Set<string>();
  const add = (layer: Layer, id: NeedCategory, service?: string) => {
    const n = makeNeed(layer, id, service);
    if (seen.has(needKey(n))) return;
    seen.add(needKey(n));
    out.push(n);
  };
  const names = p.services.map((s) => s.name);
  const runnable = p.services.filter(isRunnable).map((s) => s.name);
  /** Per-service needs; sast and deps fall back to repo-wide when no service was found, so the scan floor is never empty. */
  const perService = (layer: Layer, id: NeedCategory) => {
    if (names.length > 0) for (const s of names) add(layer, id, s);
    else if (id === 'sast' || id === 'deps') add(layer, id);
  };
  const pushSet = (layer: Layer) => {
    add(layer, 'hooks-ci');
    add(layer, 'secrets');
    for (const id of ['sast', 'deps', 'unit-tests', 'lint'] as const) perService(layer, id);
  };

  add('pre-commit', 'hooks');
  add('pre-commit', 'secrets');
  perService('pre-commit', 'format-lint');

  pushSet('push');

  pushSet('merge');
  perService('merge', 'full-tests');
  add('merge', 'gate');
  for (const s of runnable) for (const id of ['image-build', 'image-scan', 'dast'] as const) add('merge', id, s);
  if (iacSkip(p) === null) add('merge', 'iac');

  const targets = mainDeployTargets(p);
  if (targets !== null) {
    const mode = signingMode(p, caps);
    for (const s of targets) {
      add('deploy', 'sbom', s);
      // Ruling S8: attest mode → an attestation need only (it is the signing there); keyless or key-env → signing,
      // plus attestation when keyless and the repo has attestations ("attestation where the plan allows").
      if (mode === 'keyless' || mode === 'key-env') add('deploy', 'signing', s);
      if (mode === 'attest' || (mode === 'keyless' && caps.attestations)) add('deploy', 'attestation', s);
      add('deploy', 'deploy-verify', s);
    }
  }
  // The Plan P checks, from the one table (planChecks); skippedChecks reads the same pass.
  for (const n of planChecks(p, caps).needs) {
    if (seen.has(needKey(n))) continue;
    seen.add(needKey(n));
    out.push(n);
  }
  return out;
}

export interface PlanNeedsOptions {
  /** Values the user typed (tokens, passwords): never sent to the AI, in any form scrubKnownValues knows. */
  knownValues?: string[];
}

/**
 * Text for an AI prompt the way bundleCode cleans file content: known values, then redact() (no path hint, so every
 * rule is on), then known values again.
 */
function scrubForPrompt(text: string, knownValues: readonly string[]): string {
  const scrub = (t: string) => (knownValues.length > 0 ? scrubKnownValues(t, [...knownValues]) : t);
  return scrub(redact(scrub(text)));
}

/**
 * Profile service names safe to show the AI and use as the schema enum: valid names, each once, left out when
 * scrubForPrompt would change them (a name that looks like a token, or holds a known value), since the schema is
 * sent to the AI too.
 */
const promptServices = (p: RepoProfile, knownValues: readonly string[] = []) => [...new Set(p.services.map((s) => s.name)
  .filter((n) => SERVICE_NAME_RE.test(n) && scrubForPrompt(n, knownValues) === n))];

type AiNeedsAnswer = {
  add: { id: NeedId; layer: Layer; category: NeedCategory; service: string | null; why: string; blocking: boolean }[];
  skipLayers: { layer: Layer; reason: string }[];
  requireDeployApproval: boolean;
};

/** The answer schema for this profile: ids, layers, categories and services are enums; every object is closed. */
export function needsSchema(p: RepoProfile, opts: PlanNeedsOptions = {}): AiSchema<AiNeedsAnswer> {
  const names = promptServices(p, opts.knownValues);
  const service = names.length > 0 ? z.enum(names as [string, ...string[]]).nullable() : z.null();
  return aiSchema<AiNeedsAnswer>(z.strictObject({
    add: z.array(z.strictObject({
      id: z.enum(NEED_IDS), layer: z.enum(LAYERS), category: z.enum(NEED_CATEGORIES), service, why: z.string(), blocking: z.boolean(),
    })),
    skipLayers: z.array(z.strictObject({ layer: z.enum(LAYERS), reason: z.string() })),
    requireDeployApproval: z.boolean(),
  }));
}

/**
 * The profile as the AI sees it (ruling S29): enum fields, booleans, counts and validated names only, never raw repo
 * text. The whole summary then goes through scrubForPrompt, like the code bundle.
 */
function profileSummary(p: RepoProfile, floor: Need[], knownValues: readonly string[]): string {
  const names = new Set(promptServices(p, knownValues));
  const services = p.services.filter((s) => names.has(s.name)).map((s) => ({
    name: s.name,
    language: s.language,
    packageManager: s.packageManager ?? null,
    hasTests: s.hasTests,
    runnable: isRunnable(s),
    hasDockerfile: (s.dockerfile ?? '') !== '',
    hasPort: s.port !== undefined,
    frameworks: s.frameworks.filter((f) => SERVER_FRAMEWORKS.includes(f)),
    dependencies: [...new Set(s.dependsOn.map((d) => d.kind))],
  }));
  const summary = {
    private: p.private,
    plan: p.plan,
    ownerType: p.ownerType,
    monorepo: p.monorepo,
    hasCompose: p.hasCompose,
    hookManager: p.precommit,
    terraform: p.terraformDirs.length > 0,
    existingWorkflows: p.existingWorkflows.length,
    deployingWorkflows: p.existingWorkflows.filter((w) => w.deploys).length,
    services,
    floorNeeds: floor
      .filter((n) => n.service === undefined || names.has(n.service))
      .map((n) => ({ layer: n.layer, id: n.id, service: n.service ?? null })),
  };
  // One value per line: redact() replaces any line over 4 KB whole, and a compact summary of five or more services is
  // one such line, so the AI would get nothing.
  return scrubForPrompt(`<repo-profile>\n${JSON.stringify(summary, null, 1)}\n</repo-profile>`, knownValues);
}

/** The needs request around `code` (bundleText's output; '' to size the rest of the request). */
function needsRequest(code: string, p: RepoProfile, caps: Capabilities, knownValues: readonly string[]): { req: AiRequest; schema: AiSchema<AiNeedsAnswer> } {
  const schema = needsSchema(p, { knownValues: [...knownValues] });
  return {
    schema,
    req: {
      system: NEEDS_SYSTEM,
      user: `${code}\n${profileSummary(p, floorNeeds(p, caps), knownValues)}\n\n${needsInstructions(NEED_ID_CATEGORY)}`,
      schemaName: 'needs',
      jsonSchema: schema.jsonSchema,
      timeoutMs: NEEDS_TIMEOUT_MS,
      maxOutputTokens: NEEDS_MAX_OUTPUT_TOKENS,
    },
  };
}

/**
 * The needs request's size without the code bundle (UTF-8 bytes of system + user + schema): the needs request is
 * exactly this plus the bundle's `bytes` (bundleText's size). For the `audit --ai` cost cap, before consent (ruling U13).
 */
export function needsPromptBytes(p: RepoProfile, caps: Capabilities, opts: PlanNeedsOptions = {}): number {
  const { req } = needsRequest('', p, caps, opts.knownValues ?? []);
  return Buffer.byteLength(req.system) + Buffer.byteLength(req.user) + Buffer.byteLength(JSON.stringify(req.jsonSchema));
}

/**
 * The floor plus what the AI adds. The bundle goes into the prompt only through bundleText(), which refuses a
 * bundle that skipped the gitleaks pass, so nothing is sent then. `writers` is listWriters(...).length (the audit
 * passes 0). `opts.knownValues` (what the user typed) are scrubbed from the profile summary, and a service name holding
 * one is left out of the prompt and the schema. AiError (with its usage) passes through.
 */
export async function planNeeds(p: RepoProfile, caps: Capabilities, bundle: CodeBundle, ai: AiProvider, writers: number, opts: PlanNeedsOptions = {}): Promise<NeedsPlan> {
  const code = bundleText(bundle); // first: throws GitleaksRequiredError before anything else happens
  const knownValues = opts.knownValues ?? [];
  const floor = floorNeeds(p, caps);
  const { req, schema } = needsRequest(code, p, caps, knownValues);
  const { data, usage } = await completeValidated(ai, req, schema.zod);

  const notes = new Set<string>(); // deduped
  const layersSkipped: { layer: Layer; reason: string }[] = [];
  const deployAllowed = !p.services.some(isRunnable) && !deploysExist(p);
  const refusedSkips = new Set<Layer>();
  for (const skip of data.skipLayers.slice(0, MAX_AI_SKIPS)) {
    const reason = cleanAiText(skip.reason) || 'No reason given.';
    if (skip.layer === 'deploy' && deployAllowed) {
      if (layersSkipped.length === 0) layersSkipped.push({ layer: 'deploy', reason });
      continue;
    }
    if (refusedSkips.has(skip.layer)) continue;
    refusedSkips.add(skip.layer);
    const because = skip.layer === 'deploy'
      ? 'something in this repo runs or deploys'
      : 'only the deploy layer can be skipped, and only when nothing runs or deploys';
    notes.add(`The AI suggested skipping the ${skip.layer} layer ("${reason}"), but pipegen keeps it: ${because}.`);
  }

  // Refused additions, grouped by reason so each reason gives one note. Items hold enum values only.
  const refused = Object.fromEntries(Object.keys(REFUSED).map((k) => [k, new Set<string>()])) as Record<keyof typeof REFUSED, Set<string>>;
  const floorIds = new Set(floor.map((n) => n.id));
  const floorLayers = new Set(floor.map((n) => n.layer));
  const skipped = skippedChecks(p, caps);
  const runnable = new Set(p.services.filter(isRunnable).map((s) => s.name));
  const deployNeedTargets = new Set(floor.filter((n) => n.layer === 'deploy').map((n) => n.service));
  const needs = [...floor];
  const seen = new Set(floor.map(needKey));
  let added = 0;
  const read = data.add.slice(0, MAX_AI_ADDS_READ);
  for (const [i, a] of read.entries()) {
    const item = `${a.id} in ${a.layer}${a.service === null ? '' : ` for ${a.service}`}`; // enum values and checked names only
    if (a.id === 'gate') { refused.gate.add(item); continue; }
    if (NEED_ID_CATEGORY[a.id] !== a.category) { refused.category.add(item); continue; }
    // A floor id only extends what the floor already has (another layer or service): never signing on a repo
    // that can't sign, attestation without the capability, or an image scan for a repo with nothing to run.
    // PS9: and never a check this repo's plan skipped on purpose; the note says why it was skipped.
    const skip = isFloorId(a.id) ? skipped.find((k) => k.category === a.id && (k.service === undefined || k.service === (a.service ?? undefined))) : undefined;
    if (skip !== undefined) { refused.notInFloor.add(`${item} (${skip.why})`); continue; }
    if (isFloorId(a.id) && !floorIds.has(a.id)) { refused.notInFloor.add(item); continue; }
    // A scheduled check runs only in the merge layer; a repo-wide check has no service.
    // A table check goes only on the layers the table gives it (duplication is PR-only, DEC #93; scheduled checks are merge only).
    const rule = CHECKS.find((c) => c.category === a.category);
    if (rule !== undefined && !rule.layers.includes(a.layer)) { refused.layer.add(item); continue; }
    if (REPO_WIDE_CATEGORIES.has(a.category) && a.service !== null) { refused.repoWide.add(item); continue; }
    // Only layers the floor sets up (never pre-commit, never a deploy layer the repo doesn't have).
    if (a.layer === 'pre-commit' || !floorLayers.has(a.layer)) { refused.layer.add(item); continue; }
    // Image checks need something to run: only for a runnable service, never repo-wide.
    if (IMAGE_IDS.has(a.id) && (a.service === null || !runnable.has(a.service))) { refused.notRunnable.add(item); continue; }
    // Deploy additions only for what the floor's deploy layer already covers.
    if (a.layer === 'deploy' && !deployNeedTargets.has(a.service ?? undefined)) { refused.notDeployed.add(item); continue; }
    const need: Need = {
      id: a.id, layer: a.layer, category: a.category, ...(a.service === null ? {} : { service: a.service }),
      why: cleanAiText(a.why) || needWhy(a.id) || '',
      blocking: FLOOR.has(a.category) || (checkBlocking(a.category, a.service, p) && a.blocking), // a floor-category check never runs as warn-only
      floor: false,
    };
    if (seen.has(needKey(need))) continue; // a floor need (or an earlier addition) stays exactly as it is
    seen.add(needKey(need));
    needs.push(need);
    added++;
    if (added === MAX_AI_ADDS_KEPT && i < data.add.length - 1) {
      notes.add(`pipegen kept the first ${MAX_AI_ADDS_KEPT} of ${data.add.length} AI suggestions.`);
      break;
    }
  }
  if (data.add.length > MAX_AI_ADDS_READ && added < MAX_AI_ADDS_KEPT) {
    notes.add(`pipegen read only the first ${MAX_AI_ADDS_READ} of ${data.add.length} AI suggestions.`);
  }
  for (const reason of Object.keys(REFUSED) as (keyof typeof REFUSED)[]) {
    if (refused[reason].size > 0) notes.add(REFUSED[reason](listItems([...refused[reason]])));
  }

  return { needs, notes: [...notes], requireDeployApproval: deployApprovalRule(p, writers) || data.requireDeployApproval, layersSkipped, usage };
}

/**
 * The CI jobs of a need list, in order: one job per (layer, id, service) (ruling S10), except that a check shares the
 * job its JOB_GROUP names (format with lint, ...) and a check with no job (null) adds none. Pre-commit runs on the
 * developer's machine, so no jobs; the gate is one job in merge. The nightly = the nightly job + the merge-layer jobs
 * in NIGHTLY (a check with no job still counts there when it is in NIGHTLY: scorecard). Both exports below read this,
 * so their lengths always agree.
 */
function ciJobs(needs: Need[]): { layer: Layer | 'nightly'; category: string }[] {
  const out: { layer: Layer | 'nightly'; category: string }[] = [{ layer: 'nightly', category: 'nightly' }];
  const seen = new Set<string>();
  const seenNightly = new Set<string>();
  for (const n of needs) {
    if (n.layer === 'pre-commit') continue;
    const group = jobGroup(n.category);
    const jobId = group === null || group === n.category ? n.id : group; // a grouped check is counted under its group's id
    const k = jobId === 'gate' ? needKey({ layer: n.layer, id: 'gate' }) : needKey({ layer: n.layer, id: jobId, service: n.service });
    if (group !== null && !seen.has(k)) {
      seen.add(k);
      out.push({ layer: n.layer, category: group });
    }
    const nightlyCategory = group ?? n.category;
    const nk = needKey({ layer: 'nightly' as Layer, id: group === null ? n.id : jobId, service: n.service });
    if (n.layer === 'merge' && NIGHTLY.has(nightlyCategory) && !seenNightly.has(nk)) {
      seenNightly.add(nk);
      out.push({ layer: 'nightly', category: nightlyCategory });
    }
  }
  return out;
}

/**
 * CI jobs per layer, for Plan A's estimate() (ruling S10): see ciJobs. Nightly = merge-layer scanner and image-build jobs + 1
 * (the nightly job).
 */
export function jobCounts(needs: Need[]): Record<Layer | 'nightly', number> {
  const counts: Record<Layer | 'nightly', number> = { 'pre-commit': 0, push: 0, merge: 0, deploy: 0, nightly: 0 };
  for (const j of ciJobs(needs)) counts[j.layer]++;
  return counts;
}

/**
 * The same CI jobs as jobCounts, listed by need category, so Plan A's estimate() can price each job by its category
 * (S5, DECISIONS #81). `jobCategories(n)[layer].length === jobCounts(n)[layer]` for every layer.
 */
export function jobCategories(needs: Need[]): Record<Layer | 'nightly', string[]> {
  const out: Record<Layer | 'nightly', string[]> = { 'pre-commit': [], push: [], merge: [], deploy: [], nightly: [] };
  for (const j of ciJobs(needs)) out[j.layer].push(j.category);
  return out;
}
