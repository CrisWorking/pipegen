// Needs planner (Plan B Task 1): which checks ("needs") a repo gets, per layer.
// - floorNeeds: the security floor, decided by rules from the RepoProfile and the capabilities. Never removed.
// - planNeeds: the AI may ADD needs (ids, layers, categories and services are schema enums) and propose skipping
//   the deploy layer when nothing runs or deploys. It can't remove or change a floor need (spec §19 "AI", T4).
// Need identity is (layer, id, service) (Plan B ruling S11).
import { z } from 'zod';
import { needsInstructions, NEEDS_SYSTEM } from '../ai/prompts/needs.js';
import { completeValidated, formatAiText } from '../ai/provider.js';
import { bundleText, type CodeBundle } from '../ai/redact.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import { signingMode } from '../github/signing-mode.js';
import { SERVER_FRAMEWORKS, SERVICE_NAME_RE } from '../read/project.js';
import {
  FLOOR_NEEDS, NEED_CATEGORIES, type AiProvider, type AiUsage, type Capabilities, type Layer, type Need, type NeedCategory,
  type RepoProfile, type Service,
} from '../types.js';

export const LAYERS = ['pre-commit', 'push', 'merge', 'deploy'] as const satisfies readonly Layer[];

/** Ids only the AI adds (never in the floor). */
const AI_ONLY_IDS = ['type-check', 'license-scan', 'dockerfile-lint', 'migration-check'] as const;

/** Every floor id (each equal to its category) plus the ids the AI may add; the AI schema's id enum. */
export const NEED_IDS = [...NEED_CATEGORIES, ...AI_ONLY_IDS] as const;
export type NeedId = typeof NEED_IDS[number];

/**
 * The category of every need id (Plan B ruling S6). Floor ids map to themselves. The AI must give exactly this
 * category, so it can never change which blocking rules apply to a need. Tool lookup (`reviewedFor`) and memory
 * entries derive the category from this table too.
 */
export const NEED_ID_CATEGORY: Readonly<Record<NeedId, NeedCategory>> = Object.freeze({
  ...(Object.fromEntries(NEED_CATEGORIES.map((c) => [c, c])) as Record<NeedCategory, NeedCategory>),
  'type-check': 'lint',
  'dockerfile-lint': 'lint',
  'license-scan': 'deps',
  'migration-check': 'full-tests',
});

/** Scanner categories (ruling S10): their merge-layer jobs also run in the nightly job. */
const SCANNERS: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'iac', 'image-scan', 'dast']);
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const RUN_SCRIPTS = ['start', 'dev', 'serve'];
const NEEDS_TIMEOUT_MS = 120_000;

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

/** Profile service names safe to show the AI and use as the schema enum: valid names, each once. */
const promptServices = (p: RepoProfile) => [...new Set(p.services.map((s) => s.name).filter((n) => SERVICE_NAME_RE.test(n)))];

type AiNeedsAnswer = {
  add: { id: NeedId; layer: Layer; category: NeedCategory; service: string | null; why: string; blocking: boolean }[];
  skipLayers: { layer: Layer; reason: string }[];
  requireDeployApproval: boolean;
};

/** The answer schema for this profile: ids, layers, categories and services are enums; every object is closed. */
export function needsSchema(p: RepoProfile): AiSchema<AiNeedsAnswer> {
  const names = promptServices(p);
  const service = names.length > 0 ? z.enum(names as [string, ...string[]]).nullable() : z.null();
  return aiSchema<AiNeedsAnswer>(z.strictObject({
    add: z.array(z.strictObject({
      id: z.enum(NEED_IDS), layer: z.enum(LAYERS), category: z.enum(NEED_CATEGORIES), service, why: z.string(), blocking: z.boolean(),
    })),
    skipLayers: z.array(z.strictObject({ layer: z.enum(LAYERS), reason: z.string() })),
    requireDeployApproval: z.boolean(),
  }));
}

/** The profile as the AI sees it (ruling S29): enum fields, booleans, counts and validated names only, never raw repo text. */
function profileSummary(p: RepoProfile, floor: Need[]): string {
  const names = new Set(promptServices(p));
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
  return `<repo-profile>\n${JSON.stringify(summary)}\n</repo-profile>`;
}

/**
 * The floor plus what the AI adds. The bundle goes into the prompt only through bundleText(), which refuses a
 * bundle that skipped the gitleaks pass, so nothing is sent then. `writers` is listWriters(...).length (the audit
 * passes 0). AiError (with its usage) passes through.
 */
export async function planNeeds(p: RepoProfile, caps: Capabilities, bundle: CodeBundle, ai: AiProvider, writers: number): Promise<NeedsPlan> {
  const code = bundleText(bundle); // first: throws GitleaksRequiredError before anything else happens
  const floor = floorNeeds(p, caps);
  const schema = needsSchema(p);
  const { data, usage } = await completeValidated(ai, {
    system: NEEDS_SYSTEM,
    user: `${code}\n${profileSummary(p, floor)}\n\n${needsInstructions(NEED_ID_CATEGORY)}`,
    schemaName: 'needs',
    jsonSchema: schema.jsonSchema,
    timeoutMs: NEEDS_TIMEOUT_MS,
  }, schema.zod);

  const notes: string[] = [];
  const layersSkipped: { layer: Layer; reason: string }[] = [];
  const deployAllowed = !p.services.some(isRunnable) && !deploysExist(p);
  for (const skip of data.skipLayers) {
    const reason = formatAiText(skip.reason) || 'No reason given.';
    if (skip.layer === 'deploy' && deployAllowed) {
      if (layersSkipped.length === 0) layersSkipped.push({ layer: 'deploy', reason });
      continue;
    }
    const because = skip.layer === 'deploy'
      ? 'something in this repo runs or deploys'
      : 'only the deploy layer can be skipped, and only when nothing runs or deploys';
    notes.push(`The AI suggested skipping the ${skip.layer} layer ("${reason}"), but pipegen keeps it: ${because}.`);
  }

  const needs = [...floor];
  const seen = new Set(floor.map(needKey));
  for (const a of data.add) {
    if (a.id === 'gate') {
      notes.push('The AI tried to add a gate need; pipegen ignored it, since it sets up the one merge gate itself.');
      continue;
    }
    if (NEED_ID_CATEGORY[a.id] !== a.category) {
      notes.push(`The AI gave the need ${a.id} the category ${a.category} instead of ${NEED_ID_CATEGORY[a.id]}; pipegen ignored that need.`);
      continue;
    }
    if (a.layer === 'deploy' && layersSkipped.length > 0) {
      notes.push(`The AI added ${a.id} to the deploy layer it also skipped; pipegen left it out.`);
      continue;
    }
    const need: Need = {
      id: a.id, layer: a.layer, category: a.category, ...(a.service === null ? {} : { service: a.service }),
      why: formatAiText(a.why) || WHY[a.id], blocking: a.blocking, floor: false,
    };
    if (seen.has(needKey(need))) continue; // a floor need (or an earlier addition) stays exactly as it is
    seen.add(needKey(need));
    needs.push(need);
  }

  return { needs, notes, requireDeployApproval: deployApprovalRule(p, writers) || data.requireDeployApproval, layersSkipped, usage };
}

/**
 * CI jobs per layer, for Plan A's estimate() (ruling S10): one job per (layer, id, service); pre-commit runs on the
 * developer's machine, so 0; the gate is one job in merge; nightly = merge-layer scanner jobs + 1 (the nightly job).
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
    if (n.layer === 'merge' && SCANNERS.has(n.category)) counts.nightly++;
  }
  return counts;
}
