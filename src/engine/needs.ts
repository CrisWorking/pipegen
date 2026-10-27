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
import { NEED_ID_CATEGORY, NEED_IDS, type NeedId } from './need-ids.js';
import {
  FLOOR_NEEDS, NEED_CATEGORIES, type AiProvider, type AiUsage, type Capabilities, type Layer, type Need, type NeedCategory,
  type RepoProfile, type Service,
} from '../types.js';

export const LAYERS = ['pre-commit', 'push', 'merge', 'deploy'] as const satisfies readonly Layer[];

export { NEED_ID_CATEGORY, NEED_IDS, type NeedId } from './need-ids.js';

/**
 * Categories whose merge-layer jobs also run in the nightly (ruling S10): the scanners, plus the image build the image
 * scan and DAST need (spike S5's real nightly built the image; final review M8). A merge-layer image build only
 * exists for a runnable service, so the nightly builds an image exactly when the merge layer does.
 */
const NIGHTLY: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'iac', 'image-scan', 'dast', 'image-build']);
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
  layer: (items: string) => `The AI tried to add ${items}, a layer pipegen doesn't add AI checks to here; pipegen left them out.`,
  notRunnable: (items: string) => `The AI suggested ${items}, but image checks only apply to services that run; pipegen left them out.`,
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

/** pipegen's own plain-English reason for each need (floor needs, and AI needs that come back with no usable why). */
const WHY: Readonly<Record<NeedId, string>> = {
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
  iac: 'Scans the Terraform code for insecure infrastructure settings.',
  sbom: 'Lists every component in the build (an SBOM), so problems can be traced later.',
  signing: 'Signs the built image, so only gated images can be deployed.',
  attestation: 'Records a GitHub attestation of how the image was built.',
  'deploy-verify': 'Checks before each deploy that the commit passed the pipeline.',
  gate: 'The merge gate: one required check that sums up every blocking result.',
  'type-check': 'Runs the type checker to catch type errors.',
  'license-scan': 'Checks dependency licences.',
  'dockerfile-lint': 'Lints the Dockerfile for risky or broken instructions.',
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

/** A start, dev or serve script, a server framework, a port, or a Dockerfile. A library with only build/test scripts isn't. */
export function isRunnable(s: Service): boolean {
  return s.scripts.some((n) => RUN_SCRIPTS.includes(n)) || s.frameworks.length > 0 || s.port !== undefined || (s.dockerfile ?? '') !== '';
}

const deploysExist = (p: RepoProfile) => p.existingWorkflows.some((w) => w.deploys);

/** The rule behind requireDeployApproval (spec §19 "AI"): deploys exist and the repo has at least 2 writers. */
export function deployApprovalRule(p: RepoProfile, writers: number): boolean {
  return deploysExist(p) && writers >= 2;
}

const needKey = (n: Pick<Need, 'layer' | 'id' | 'service'>) => `${n.layer}\u0000${n.id}\u0000${n.service ?? ''}`;

function makeNeed(layer: Layer, id: NeedCategory, service?: string): Need {
  return {
    id, layer, category: id, ...(service === undefined ? {} : { service }), why: WHY[id],
    blocking: id !== 'format-lint', floor: FLOOR.has(id),
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
  if (p.terraformDirs.length > 0) add('merge', 'iac');

  if (runnable.length > 0 || deploysExist(p)) {
    const targets: (string | undefined)[] = runnable.length > 0 ? runnable : names.length > 0 ? names : [undefined];
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
  return scrubForPrompt(`<repo-profile>\n${JSON.stringify(summary)}\n</repo-profile>`, knownValues);
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
  const schema = needsSchema(p, { knownValues });
  const { data, usage } = await completeValidated(ai, {
    system: NEEDS_SYSTEM,
    user: `${code}\n${profileSummary(p, floor, knownValues)}\n\n${needsInstructions(NEED_ID_CATEGORY)}`,
    schemaName: 'needs',
    jsonSchema: schema.jsonSchema,
    timeoutMs: NEEDS_TIMEOUT_MS,
  }, schema.zod);

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
  const runnable = new Set(p.services.filter(isRunnable).map((s) => s.name));
  const deployTargets = new Set(floor.filter((n) => n.layer === 'deploy').map((n) => n.service));
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
    if (isFloorId(a.id) && !floorIds.has(a.id)) { refused.notInFloor.add(item); continue; }
    // Only layers the floor sets up (never pre-commit, never a deploy layer the repo doesn't have).
    if (a.layer === 'pre-commit' || !floorLayers.has(a.layer)) { refused.layer.add(item); continue; }
    // Image checks need something to run: only for a runnable service, never repo-wide.
    if (IMAGE_IDS.has(a.id) && (a.service === null || !runnable.has(a.service))) { refused.notRunnable.add(item); continue; }
    // Deploy additions only for what the floor's deploy layer already covers.
    if (a.layer === 'deploy' && !deployTargets.has(a.service ?? undefined)) { refused.notDeployed.add(item); continue; }
    const need: Need = {
      id: a.id, layer: a.layer, category: a.category, ...(a.service === null ? {} : { service: a.service }),
      why: cleanAiText(a.why) || WHY[a.id],
      blocking: FLOOR.has(a.category) || a.blocking, // a floor-category check never runs as warn-only
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
 * CI jobs per layer, for Plan A's estimate() (ruling S10): one job per (layer, id, service); pre-commit runs on the
 * developer's machine, so 0; the gate is one job in merge; nightly = merge-layer scanner and image-build jobs + 1
 * (the nightly job).
 */
export function jobCounts(needs: Need[]): Record<Layer | 'nightly', number> {
  const counts: Record<Layer | 'nightly', number> = { 'pre-commit': 0, push: 0, merge: 0, deploy: 0, nightly: 1 };
  const seen = new Set<string>();
  for (const n of needs) {
    if (n.layer === 'pre-commit') continue;
    const k = n.id === 'gate' ? needKey({ layer: n.layer, id: 'gate' }) : needKey(n);
    if (seen.has(k)) continue;
    seen.add(k);
    counts[n.layer]++;
    if (n.layer === 'merge' && NIGHTLY.has(n.category)) counts.nightly++;
  }
  return counts;
}

/**
 * The same CI jobs as jobCounts (same rules: one job per (layer, id, service), pre-commit none, one gate job, nightly =
 * the nightly job + merge-layer scanners and image builds), listed by need category, so Plan A's estimate() can price each job by its
 * category (S5, DECISIONS #81). `jobCategories(n)[layer].length === jobCounts(n)[layer]` for every layer.
 */
export function jobCategories(needs: Need[]): Record<Layer | 'nightly', string[]> {
  const out: Record<Layer | 'nightly', string[]> = { 'pre-commit': [], push: [], merge: [], deploy: [], nightly: ['nightly'] };
  const seen = new Set<string>();
  for (const n of needs) {
    if (n.layer === 'pre-commit') continue;
    const k = n.id === 'gate' ? needKey({ layer: n.layer, id: 'gate' }) : needKey(n);
    if (seen.has(k)) continue;
    seen.add(k);
    out[n.layer].push(n.category);
    if (n.layer === 'merge' && NIGHTLY.has(n.category)) out.nightly.push(n.category);
  }
  return out;
}
