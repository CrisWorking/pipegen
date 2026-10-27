// Estimates (Plan A Task 9): Actions minutes for setup and per month, the AI cost and its hard cap, and the time it
// takes. Shown at consent (Plan A Task 8) and in the audit report (Plan U). Every assumption goes into `basis`, in
// plain English.
// - Minutes per job come from spike S5 (DECISIONS #81), keyed by need category: measured on a small Node + Postgres app
//   on a private repo, plus about 50% for bigger apps and the egress-control step. Callers pass the jobs of each layer
//   by category: `jobCategories(floorNeeds(p, caps))` (src/engine/needs.ts), since consent comes before the AI adds needs.
// - The setup estimate also counts the proof harness (Plan E Task 2) and the compat copies of the repo's own
//   workflow jobs, per proof variant.
// - AI input and output tokens are priced separately with data/ai-prices.yml, for the chosen provider and model.
// - estimateAuditAi (Plan U ruling B2) prices `audit --ai` alone: one needs call plus the discovery calls. Its cap always
//   has room for the needs call and one discovery call at their worst (ruling U13). requestCeilingUsd and
//   usageCeilingUsd are that worst case and what was used, at the highest price a request could bill at: the audit's
//   spend meter reserves the one before each call and settles with the other. usageCostUsd is the list price.
// - activity30d reads the last 30 days of pushes and pull requests through the caller's Octokit and rate budget.
import { readFileSync } from 'node:fs';
import type { Octokit } from '@octokit/rest';
import { parse } from 'yaml';
import { z } from 'zod';
import {
  CANDIDATES_MAX_OUTPUT_TOKENS, CANDIDATES_REQUEST_MAX_BYTES, MAX_DISCOVERY_NEEDS, NEEDS_MAX_OUTPUT_TOKENS,
} from '../engine/discovery-limits.js';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { DEFAULT_MODEL, type AiRequest, type AiUsage, type Layer, type Plan, type RepoProfile } from '../types.js';
import { fallbackEnabled } from '../util/claude-fallback.js';
import { isOutputLimit } from '../util/output-limit.js';
import { hostPlace } from '../util/local-host.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';

/** How the basis line starts when the activity count is a lower bound (Activity.capped); the audit report reads it. */
export const ACTIVITY_CAPPED_PREFIX = 'Activity: at least';
export type AiStage = 'needs' | 'debate' | 'creators' | 'fix-loop';
/**
 * Pushes and pull requests opened in the last 30 days. `capped`: a list stopped before the start of the 30 days (the
 * event list's 300-event limit, the 1,000 pull requests pipegen reads, or a rate stop on a later page), so the counts
 * are lower bounds.
 */
export interface Activity { pushes: number; prs: number; capped: boolean }
/** The CI jobs of each layer (plus nightly), each named by its need category. Build it with jobCategories() (src/engine/needs.ts). */
export type JobCategories = Record<Layer | 'nightly', string[]>;
export interface AiCost { input: { low: number; high: number }; output: { low: number; high: number }; low: number; high: number }
/**
 * The chosen AI provider and model. Pass the provider itself (makeProvider's result): an Ollama provider carries its
 * `host` (host:port), which says whether Ollama runs on this machine. Without it the basis never claims it does.
 */
export interface AiProviderChoice { name: string; model: string; host?: string }
/**
 * Which provider and model an estimate was priced for (and, for Ollama, its host). consentText refuses an estimate
 * whose pricedFor differs from the provider it shows (final review batch 2, I1).
 */
export interface PricedFor { provider: string; model: string; host?: string }

export interface Estimates {
  setupMinutes: number; setupMinutesCap: number; monthlyMinutes: number;
  /** Actions minutes the plan includes per month for private repos; null for a public repo (minutes are free) or plan 'unknown' (ruling S12). */
  includedMinutes: number | null;
  aiTokens: { stage: AiStage; input: number; output: number }[];   // empty when there's no provider
  aiCostUsd: AiCost | 'local';
  aiCostCapUsd: number | null;                                       // 2 × aiCostUsd.high; null for Ollama (local) or no provider
  durationMinutes: { low: number; high: number }; basis: string[];
  /** The provider and model the AI cost was priced for; null when there is no provider. */
  pricedFor: PricedFor | null;
}

/** `unpriced`: the model has no price, so no hard cap can be kept (ruling U14); capUsd is then 0 and the CLI stops before consent. */
export interface AuditAiEstimate { tokens: { input: number; output: number }; costUsd: AiCost | 'local'; capUsd: number | null; basis: string[]; pricedFor: PricedFor; unpriced: UnpricedModel | null }

// ---------- minutes ----------

/**
 * Billable minutes per job, by need category (spike S5, DECISIONS #81). Measured on a private repo: every job but DAST
 * billed 1 minute (the 1-minute rounding floor), ZAP 2. The table adds about 50% for bigger apps and the egress step
 * (+10–17 s per job), which pushes Semgrep and Trivy (40–55 s measured) over the minute line.
 */
const JOB_MINUTES: Readonly<Record<string, number>> = Object.freeze({
  'hooks-ci': 1, lint: 1, secrets: 1, deps: 1, gate: 1, nightly: 1,
  sast: 2, 'unit-tests': 2, 'full-tests': 2, 'image-build': 2, 'image-scan': 2,
  dast: 3,
});
/** Any other category (iac, sbom, signing, attestation, deploy-verify, anything new): not measured in S5. */
const UNKNOWN_JOB_MINUTES = 2;

/** Billable minutes for one CI job of this need category. */
export function jobMinutes(category: string): number {
  return Object.hasOwn(JOB_MINUTES, category) ? (JOB_MINUTES[category] as number) : UNKNOWN_JOB_MINUTES;
}

/**
 * The proof harness (Plan E Task 2), per variant: app-start 2 (builds and starts the app), hooks 1, tests-repeat 2,
 * sign-roundtrip 2 (image build + local registry), verify-lookup 1. An upper bound: tests-repeat runs only when tests
 * were created, sign-roundtrip only when signing is on, verify-lookup only for the merged `main` variant.
 */
export const HARNESS_MINUTES_PER_VARIANT = 8;
/** Re-runs (fix loop) and slow jobs: setup × 1.3, done as × 13 / 10 so whole numbers stay whole. */
const SETUP_HEADROOM_TENTHS = 13;
const PARALLEL_JOBS = 4;
const QUEUE_MINUTES = 10;
const NIGHTS_PER_MONTH = 30;
const CI_LAYERS = ['push', 'merge', 'deploy', 'nightly'] as const;

const layerMinutes = (cats: readonly string[] | undefined) => (cats ?? []).reduce((sum, c) => sum + jobMinutes(c), 0);
const count = (n: number) => (Number.isFinite(n) && n > 0 ? Math.floor(n) : 0);
const plural = (n: number, one: string, many: string) => `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;

// ---------- AI ----------

/** Tokens per stage of a full run (fixed table, brief). */
const STAGE_TOKENS: readonly { stage: AiStage; input: number; output: number; times: number }[] = [
  { stage: 'needs', input: 30_000, output: 3_000, times: 1 },
  { stage: 'debate', input: 40_000, output: 6_000, times: 3 },          // 3 rounds
  { stage: 'creators', input: 60_000, output: 20_000, times: 1 },
  { stage: 'fix-loop', input: 15_000, output: 4_000, times: 0 },        // times set below
];
/** Fix loop: up to 5 attempts per failing part (Plan E); pipegen expects 2 parts to need fixing. */
const FIX_ATTEMPTS_PER_PART = 5;
const EXPECTED_FAILING_PARTS = 2;
/** One discovery call (Plan B Task 2): an enum-only prompt and up to 6 candidates back, thinking included. */
const CANDIDATE_CALL = { input: 2_000, output: 2_000 };
const LOW = 0.5;
const HIGH = 1.5;
const CAP_FACTOR = 2;

// ---------- data files ----------

/** A real calendar date, YYYY-MM-DD: 2026-13-99 and 2026-02-30 are refused. */
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'must be a date (YYYY-MM-DD)').refine((s) => {
  const [y, m, d] = s.split('-').map(Number) as [number, number, number];
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}, 'must be a date (YYYY-MM-DD)');
const rates = { input: z.number().finite().nonnegative(), output: z.number().finite().nonnegative() };
/** A price tier (ruling U14): above `above_input_tokens` prompt tokens, these prices apply to the whole request. */
const tier = z.strictObject({ above_input_tokens: z.number().int().positive(), ...rates });
const price = z.strictObject({ ...rates, long: tier.optional() }).refine(
  (p) => p.long === undefined || (p.long.input >= p.input && p.long.output >= p.output),
  'a price tier must not be cheaper than the base prices',
);
const paidPrice = z.object({ input: z.number().finite().positive(), output: z.number().finite().positive() });
const providerPrices = z.strictObject({
  source: z.string().min(1),
  local: z.boolean(),
  models: z.record(z.string().min(1), price),
  anyModel: price.optional(),
});
const pricesSchema = z.strictObject({
  checkedAt: isoDate,
  providers: z.strictObject({ claude: providerPrices, openai: providerPrices, ollama: providerPrices }),
}).superRefine((p, ctx) => {
  if (!Object.hasOwn(p.providers.claude.models, DEFAULT_MODEL)) {
    ctx.addIssue({ code: 'custom', path: ['providers', 'claude', 'models'], message: `needs a price for ${DEFAULT_MODEL} (DEFAULT_MODEL)` });
  }
  if (!p.providers.ollama.local || p.providers.ollama.anyModel === undefined) {
    ctx.addIssue({ code: 'custom', path: ['providers', 'ollama'], message: 'must be local with an anyModel price' });
  }
  // Only local Ollama may cost nothing: a 0 anywhere else would understate the cost and its hard cap.
  for (const name of ['claude', 'openai'] as const) {
    const t = p.providers[name];
    const all: [string, unknown][] = [...Object.entries(t.models).map(([m, v]): [string, unknown] => [`models.${m}`, v]), ['anyModel', t.anyModel]];
    for (const [where, v] of all) {
      if (v !== undefined && !paidPrice.safeParse(v).success) {
        ctx.addIssue({ code: 'custom', path: ['providers', name, ...where.split('.')], message: 'input and output prices must be above 0 (only local Ollama is free)' });
      }
    }
  }
});
export type AiPrices = z.infer<typeof pricesSchema>;

const minutes = z.number().int().nonnegative();
const plansSchema = z.strictObject({
  checkedAt: isoDate,
  source: z.string().min(1),
  includedMinutes: z.strictObject({ free: minutes, pro: minutes, team: minutes, enterprise: minutes }),
});
export type GitHubPlans = z.infer<typeof plansSchema>;

function loadYaml<T>(path: string, what: string, schema: z.ZodType<T>): T {
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new Error(`pipegen's ${what} (${path}) could not be read: ${e instanceof Error ? e.message.split('\n')[0] : 'unreadable'}`);
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`pipegen's ${what} (${path}) is not valid: ${issue?.path.join('.') || 'file'}: ${issue?.message ?? 'invalid'}`);
  }
  return parsed.data;
}

/** Reads and checks the AI prices (default: pipegen's own data/ai-prices.yml). Throws on any problem. */
export function loadAiPrices(path: string = packageDataPath('ai-prices.yml')): AiPrices {
  return loadYaml(path, 'AI price list', pricesSchema);
}

/** Reads and checks the GitHub plans' included minutes (default: pipegen's own data/github-plans.yml). Throws on any problem. */
export function loadGitHubPlans(path: string = packageDataPath('github-plans.yml')): GitHubPlans {
  return loadYaml(path, 'GitHub plan list', plansSchema);
}

let defaultPrices: AiPrices | undefined;
let defaultPlans: GitHubPlans | undefined;
const prices = () => (defaultPrices ??= loadAiPrices());
const plans = () => (defaultPlans ??= loadGitHubPlans());

const money = (n: number) => `$${Number.isInteger(n) ? String(n) : n.toFixed(2)}`;
const thousands = (n: number) => `${n / 1000}k`;

type PriceTier = { above_input_tokens: number; input: number; output: number };
/** `known`: the model has its own price in the file (or the provider is local); false when priced like the dearest. */
interface PriceChoice { local: boolean; input: number; output: number; long?: PriceTier; model: string; notes: string[]; known: boolean }

const perMillion = (p: { input: number; output: number }) => `${money(p.input)} per million input tokens and ${money(p.output)} per million output tokens`;

/**
 * The price for this provider and model. An unknown model gets the price of the MOST EXPENSIVE known model of the same
 * provider (input + output price), so the hard cap is never understated; an unknown provider gets the most expensive
 * model in the file. The note names the model used and says the real cost is likely lower.
 */
function priceFor(provider: AiProviderChoice): PriceChoice {
  const list = prices();
  const shown = safeText(provider.model, 80);
  const table = provider.name === 'claude' || provider.name === 'openai' || provider.name === 'ollama' ? list.providers[provider.name] : undefined;
  if (table?.local) return { local: true, input: 0, output: 0, model: shown, notes: [], known: true };
  const found = table !== undefined && Object.hasOwn(table.models, provider.model) ? table.models[provider.model] : undefined;
  if (found) {
    const above = found.long === undefined ? '' : `; above ${found.long.above_input_tokens.toLocaleString('en-US')} prompt tokens, ${perMillion(found.long)}`;
    return { local: false, ...found, model: shown, known: true, notes: [`Prices for ${shown}: ${perMillion(found)}${above} (checked ${list.checkedAt}).`] };
  }
  const pool = table ? [table] : [list.providers.claude, list.providers.openai];
  let top: { name: string; input: number; output: number; long?: PriceTier } | undefined;
  for (const t of pool) {
    for (const [name, m] of Object.entries(t.models)) {
      if (!top || m.input + m.output > top.input + top.output) top = { name, ...m };
    }
  }
  const t = top as { name: string; input: number; output: number; long?: PriceTier }; // the schema guarantees claude has models
  const whose = table ? `the same provider (${safeText(provider.name, 40)})` : 'any provider in its price list';
  return {
    local: false, input: t.input, output: t.output, ...(t.long === undefined ? {} : { long: t.long }), model: t.name, known: false,
    notes: [
      `pipegen has no price for the model "${shown}", so it prices it like ${t.name}, the most expensive model it knows from ${whose}: ${perMillion(t)} (checked ${list.checkedAt}). `
        + "This is the provider's highest price, so the real cost is likely lower.",
    ],
  };
}

function cost(tokens: { input: number; output: number }, p: PriceChoice): AiCost {
  const input = (tokens.input / 1e6) * p.input;
  const output = (tokens.output / 1e6) * p.output;
  return {
    input: { low: input * LOW, high: input * HIGH },
    output: { low: output * LOW, high: output * HIGH },
    low: (input + output) * LOW,
    high: (input + output) * HIGH,
  };
}

const ZERO_COST: AiCost = { input: { low: 0, high: 0 }, output: { low: 0, high: 0 }, low: 0, high: 0 };

/** Only the fields that identify the choice are kept (never a provider object with its key and complete()). */
function pricedFor(provider: AiProviderChoice): PricedFor {
  const host = provider.name === 'ollama' && typeof provider.host === 'string' && provider.host !== '' ? provider.host : undefined;
  return { provider: provider.name, model: provider.model, ...(host === undefined ? {} : { host }) };
}

/** The basis line for a local-model provider: "your machine" only when its host is this computer (hostPlace). */
function noCostLine(provider: AiProviderChoice): string {
  const where = hostPlace(provider.host);
  if (where === 'local') return 'Ollama runs on your machine: no AI cost and no cost cap.';
  if (where === 'remote') {
    return `Ollama runs on the Ollama server at ${safeText(provider.host ?? '', 120)}, which may be another computer. It has no per-token price: no AI cost and no cost cap.`;
  }
  return "pipegen couldn't confirm where the Ollama server runs. Ollama has no per-token price: no AI cost and no cost cap.";
}

// ---------- estimate ----------

/**
 * The estimates for a full run. `jobs`: the CI jobs per layer by need category (jobCategories(floorNeeds(p, caps))).
 * `variants`: proof variants (at least 1; callers pass 2: `main` and `planted`). `activity`: activity30d's answer.
 * `provider`: the chosen AI provider and model (pass the provider itself, see AiProviderChoice), or null when there is
 * none. The result's `pricedFor` records it.
 */
export function estimate(p: RepoProfile, jobs: JobCategories, variants: number, activity: Activity, provider: AiProviderChoice | null): Estimates {
  const basis: string[] = [];
  const v = Math.max(1, count(variants));

  // Setup minutes.
  const ciPerVariant = CI_LAYERS.reduce((sum, l) => sum + layerMinutes(jobs[l]), 0);
  const compatJobs = p.existingWorkflows.reduce((n, w) => n + w.jobs.length, 0);
  const compatMinutes = compatJobs * UNKNOWN_JOB_MINUTES;
  const perVariant = ciPerVariant + HARNESS_MINUTES_PER_VARIANT + compatMinutes;
  const setupMinutes = Math.ceil((perVariant * v * SETUP_HEADROOM_TENTHS) / 10);
  const setupMinutesCap = 2 * setupMinutes;
  basis.push(
    'Actions minutes per job are measured, not guessed: on a small Node + Postgres app on a private repo (spike S5, 2026-10-26) a job billed about 1.1 minutes. '
      + 'pipegen counts 1 min for quick jobs (hooks, lint, secrets, dependency scan, gate, nightly), 2 min for code scans, tests, the image build and image scan (and any job S5 did not measure), '
      + 'and 3 min for the running-app scan (DAST). That is the measured time plus about 50% for bigger apps and the egress-control step; larger apps take longer.',
    `Setup runs the pipeline for ${plural(v, 'proof variant', 'proof variants')} (the real changes, and the same with planted problems), plus 30% for re-runs (× 1.3).`,
    `The setup minutes include the proof harness, ${HARNESS_MINUTES_PER_VARIANT} min per variant (app start, hooks, tests run twice, a signing round trip and the verify-first lookup).`,
    `Copies of your own workflow jobs, run in the proof to compare results, count ${UNKNOWN_JOB_MINUTES} min each per variant (${plural(compatJobs, 'job', 'jobs')} here).`,
    `The hard cap on setup minutes is twice the estimate (${setupMinutesCap} min); the proof stops there. The cap also covers the extra variants that disputes add.`,
    "Pre-commit checks run on the developer's machine, so they use no Actions minutes.",
  );

  // Monthly minutes.
  const pushes = count(activity.pushes);
  const prs = count(activity.prs);
  const prPushes = Math.max(prs, pushes - prs);
  const monthlyMinutes = Math.ceil(
    pushes * layerMinutes(jobs.push) + prPushes * layerMinutes(jobs.merge) + prs * layerMinutes(jobs.deploy) + NIGHTS_PER_MONTH * layerMinutes(jobs.nightly),
  );
  basis.push(
    activity.capped
      ? `${ACTIVITY_CAPPED_PREFIX} ${plural(pushes, 'push', 'pushes')} and at least ${plural(prs, 'pull request', 'pull requests')} in the last 30 days `
        + `(pipegen couldn't read back to the start of the 30 days: GitHub lists only the last ${EVENT_PAGES * PER_PAGE} events, pipegen reads at most `
        + `${(PR_PAGES * PER_PAGE).toLocaleString('en-US')} pull requests, and it stops at GitHub's rate limit).`
      : `Activity: ${plural(pushes, 'push', 'pushes')} and ${plural(prs, 'pull request', 'pull requests')} in the last 30 days.`,
    `Monthly minutes: every push runs the push layer; every push to a branch with an open pull request also runs the merge layer; every merged pull request runs the deploy layer; the nightly scan runs ${NIGHTS_PER_MONTH} times.`,
    "GitHub's event list doesn't say which pushes went to a branch with an open pull request, so pipegen approximates them: every push except one per pull request (its merge into the default branch), "
      + 'and at least one per pull request. Pushes to branches without a pull request count too, so this leans high. Every pull request opened is counted as merged.',
  );

  // Included minutes (S12).
  const included = includedMinutesFor(p.private, p.plan);
  if (!p.private) basis.push('This is a public repo: GitHub Actions minutes on standard GitHub-hosted runners are free.');
  else if (included === null) basis.push("pipegen couldn't tell which GitHub plan this account has, so how many minutes the plan includes isn't known.");
  else basis.push(`Your ${p.plan} plan has ${included.toLocaleString('en-US')} included minutes a month for private repos (docs.github.com, checked ${plans().checkedAt}).`);

  // Duration.
  const low = Math.ceil(setupMinutes / PARALLEL_JOBS) + QUEUE_MINUTES;
  basis.push(`Time: the setup minutes spread over about ${PARALLEL_JOBS} jobs in parallel, plus ${QUEUE_MINUTES} min of queueing; the high end is twice that.`);

  // AI.
  let aiTokens: Estimates['aiTokens'] = [];
  let aiCostUsd: Estimates['aiCostUsd'] = ZERO_COST;
  let aiCostCapUsd: number | null = null;
  if (provider === null) {
    basis.push('No AI provider is set, so there is no AI cost.');
  } else {
    aiTokens = STAGE_TOKENS.map((s) => {
      const times = s.stage === 'fix-loop' ? FIX_ATTEMPTS_PER_PART * EXPECTED_FAILING_PARTS : s.times;
      return { stage: s.stage, input: s.input * times, output: s.output * times };
    });
    basis.push(
      `AI tokens per stage (input / output): needs ${thousands(30_000)} / ${thousands(3_000)}; debate 3 rounds of ${thousands(40_000)} / ${thousands(6_000)}; `
        + `creators ${thousands(60_000)} / ${thousands(20_000)}; fix loop ${FIX_ATTEMPTS_PER_PART} attempts of ${thousands(15_000)} / ${thousands(4_000)} for each of ${EXPECTED_FAILING_PARTS} parts expected to need a fix.`,
    );
    const pr = priceFor(provider);
    if (pr.local) {
      aiCostUsd = 'local';
      basis.push(noCostLine(provider));
    } else {
      const total = aiTokens.reduce((t, s) => ({ input: t.input + s.input, output: t.output + s.output }), { input: 0, output: 0 });
      aiCostUsd = cost(total, pr);
      aiCostCapUsd = CAP_FACTOR * aiCostUsd.high;
      basis.push(
        ...pr.notes,
        'Input and output tokens are priced separately. The AI cost range is half to one and a half times the token estimate.',
        `The AI cost cap is twice the high estimate (${money(aiCostCapUsd)}); pipegen stops calling the AI there.`,
      );
    }
  }

  return {
    setupMinutes, setupMinutesCap, monthlyMinutes, includedMinutes: included, aiTokens, aiCostUsd, aiCostCapUsd, durationMinutes: { low, high: 2 * low }, basis,
    pricedFor: provider === null ? null : pricedFor(provider),
  };
}

function includedMinutesFor(isPrivate: boolean, plan: Plan): number | null {
  if (!isPrivate || plan === 'unknown') return null;
  return plans().includedMinutes[plan];
}

/** A model `audit --ai` can't keep a hard cost limit for: it has no price of its own in data/ai-prices.yml (ruling U14). */
export interface UnpricedModel { model: string; choose: string[]; message: string }

/**
 * The model when it has no price of its own in data/ai-prices.yml, with the priced models of its provider to choose
 * from; null when it is priced (or local: Ollama has no per-token price). The full-run estimate still shows such a
 * model priced like the dearest one, but a hard cap can't rest on a guessed price (ruling U14, review N1).
 */
export function unpricedModel(provider: AiProviderChoice): UnpricedModel | null {
  if (priceFor(provider).known) return null;
  const table = provider.name === 'claude' || provider.name === 'openai' ? prices().providers[provider.name] : undefined;
  const choose = table === undefined ? [] : Object.keys(table.models);
  const model = safeText(provider.model, 80);
  const message = `pipegen doesn't know the price of ${model}, so it can't keep a hard cost limit.${choose.length > 0 ? ` Choose one of: ${choose.join(', ')}.` : ''}`;
  return { model, choose, message };
}

/**
 * The AI cost of `audit --ai` alone (Plan U ruling B2): one needs call plus one candidates call for each need that goes
 * to discovery, at most MAX_DISCOVERY_NEEDS. `needCount`: the needs with no reviewed tool. `needsRequestBytes`: the
 * needs request's size (UTF-8 bytes; the audit model's needsRequestBytes). Priced like estimate() for the chosen
 * provider and model (recorded in `pricedFor`). The cap is 2 × high, and never less than the needs call's and one
 * discovery call's worst case together (requestCeilingUsd, ruling U13), so the needs call always fits the agreed cap.
 * Ollama → 'local', no cap. A model with no price (`unpriced`, ruling U14): capUsd 0, so no call fits; the CLI and the
 * consent screen stop before asking.
 */
export function estimateAuditAi(provider: AiProviderChoice, needCount: number, needsRequestBytes: number): AuditAiEstimate {
  const calls = Math.min(count(needCount), MAX_DISCOVERY_NEEDS);
  const needs = STAGE_TOKENS[0] as { input: number; output: number };
  const tokens = { input: needs.input + calls * CANDIDATE_CALL.input, output: needs.output + calls * CANDIDATE_CALL.output };
  const pr = priceFor(provider);
  const basis = [
    `The AI part of the audit is 1 needs call plus up to ${MAX_DISCOVERY_NEEDS} discovery calls, one for each need with no reviewed tool (${calls} here), at about ${thousands(CANDIDATE_CALL.input)} input / ${thousands(CANDIDATE_CALL.output)} output tokens for each discovery call.`,
    `The cost range is ×${LOW} to ×${HIGH} of the token estimate.`,
  ];
  if (pr.local) return { tokens, costUsd: 'local', capUsd: null, basis: [...basis, noCostLine(provider)], pricedFor: pricedFor(provider), unpriced: null };
  const c = cost(tokens, pr);
  const unpriced = unpricedModel(provider);
  if (unpriced !== null) {
    return { tokens, costUsd: c, capUsd: 0, basis: [unpriced.message, ...basis, ...pr.notes], pricedFor: pricedFor(provider), unpriced };
  }
  const worst = (requestCeilingUsd(provider, count(needsRequestBytes), NEEDS_MAX_OUTPUT_TOKENS) as number)
    + (requestCeilingUsd(provider, CANDIDATES_REQUEST_MAX_BYTES, CANDIDATES_MAX_OUTPUT_TOKENS) as number);
  const capUsd = Math.max(CAP_FACTOR * c.high, worst);
  const fallback = provider.name === 'claude' && fallbackEnabled(provider.model);
  const capLine = `The cap is ${money2(capUsd)}: twice the high end, and never less than the most the needs call and one discovery call could cost together `
    + `(every byte sent counted as a token, the full output limit of ${thousands(NEEDS_MAX_OUTPUT_TOKENS)} and ${thousands(CANDIDATES_MAX_OUTPUT_TOKENS)} tokens, at the highest price the call could be billed at`
    + `${fallback ? ', including a second run on another Claude model if Claude declines and its refusal fallback runs the request again' : ''}). `
    + 'Before each AI call pipegen reserves the most that call could cost, and it makes no call that could take the total past the cap.';
  return { tokens, costUsd: c, capUsd, basis: [...basis, capLine, `Priced with the model ${pr.model}.`, ...pr.notes], pricedFor: pricedFor(provider), unpriced: null };
}

/**
 * Cache tokens have no price in data/ai-prices.yml. So that the cost meter never reads low, a cache read is priced as a
 * full input token (Anthropic bills 0.1×, OpenAI 0.5× and already counts it in its input tokens), and a cache write at
 * 1.25× an input token (Anthropic's price for the 5-minute cache that pipegen's Claude requests use).
 */
const CACHE_WRITE_FACTOR = 1.25;
/** Tokens a provider adds around a request (roles, structured-output scaffolding) on top of its bytes (ruling U13). */
export const FRAMING_MARGIN_TOKENS = 2_000;

const money2 = (n: number) => `$${n.toFixed(2)}`;

/** All the input tokens a request was billed for: its prompt length, which picks the price tier (cache reads and writes count). */
const promptTokens = (usage: AiUsage) => count(usage.inputTokens) + count(usage.cacheReadTokens ?? 0) + count(usage.cacheWriteTokens ?? 0);

/** The prices for a prompt of this many tokens: the `long` tier above its threshold, else the base prices. */
function ratesAt(p: { input: number; output: number; long?: PriceTier }, prompt: number): { input: number; output: number } {
  return p.long !== undefined && prompt > p.long.above_input_tokens ? p.long : p;
}

/**
 * What tokens already used cost (USD) at the list price for this provider and model, in the tier its prompt length
 * falls in (an unknown model at its provider's most expensive price); 'local' for a local model. For showing a cost,
 * not for the cap.
 */
export function usageCostUsd(provider: AiProviderChoice, usage: AiUsage): number | 'local' {
  const pr = priceFor(provider);
  if (pr.local) return 'local';
  return priceUsage(usage, ratesAt(pr, promptTokens(usage)));
}

function priceUsage(usage: AiUsage, rate: { input: number; output: number }): number {
  const input = count(usage.inputTokens) + count(usage.cacheReadTokens ?? 0) + CACHE_WRITE_FACTOR * count(usage.cacheWriteTokens ?? 0);
  return (input / 1e6) * rate.input + (count(usage.outputTokens) / 1e6) * rate.output;
}

/**
 * The highest per-token prices a request with a prompt of `prompt` tokens could be billed at, and how many runs of it
 * one request can bill. null for a local model; 'unpriced' for a model with no price of its own (ruling U14: a hard
 * cap can't rest on a guess, so its requests are unbounded).
 *
 * A Claude model with the server-side refusal fallback (`fallbacks: "default"`) can bill twice: the claude-api skill
 * (shared/model-migration.md, refusal section, "Billing") says an attempt that declines mid-stream bills at normal rates
 * and "fallback attempts bill at the fallback model's rates"; the "default" form "picks Anthropic's recommended
 * fallback" (Migrating to Claude Opus 5, "New API features"), one model, and the hop inherits the top-level max_tokens.
 * The docs don't state "at most one hop" in so many words (review N7); pipegen reads it as one fallback run. Both runs
 * are priced at the top input and output price of any Claude model, any tier. Otherwise: the model's own prices in the
 * tier the prompt falls in, one run.
 */
function ceilingRates(provider: AiProviderChoice, prompt: number): { input: number; output: number; runs: number } | null | 'unpriced' {
  const pr = priceFor(provider);
  if (pr.local) return null;
  if (!pr.known) return 'unpriced';
  if (provider.name === 'claude' && fallbackEnabled(provider.model)) {
    const all = Object.values(prices().providers.claude.models).flatMap((m) => (m.long === undefined ? [m] : [m, m.long]));
    return { input: Math.max(...all.map((m) => m.input)), output: Math.max(...all.map((m) => m.output)), runs: 2 };
  }
  return { ...ratesAt(pr, prompt), runs: 1 };
}

/** A request's size in UTF-8 bytes: system + user + the schema as JSON (byte-level tokenizers give at most 1 token per byte). */
export function aiRequestBytes(req: AiRequest): number {
  return Buffer.byteLength(req.system) + Buffer.byteLength(req.user) + Buffer.byteLength(JSON.stringify(req.jsonSchema));
}

/**
 * The most one request can cost (USD), before it is sent (rulings U13, U14): every byte a token plus
 * FRAMING_MARGIN_TOKENS as input (priced as a cache write, the dearest input), the full `maxOutputTokens` as output, at
 * ceilingRates for that input bound (the higher tier once the bound crosses its threshold), times the runs it can
 * bill. Infinity when the output limit isn't a whole number above 0 (isOutputLimit: nothing bounds it) or the model
 * has no price. 'local' for a local model. A retry is a request of its own.
 */
export function requestCeilingUsd(provider: AiProviderChoice, requestBytes: number, maxOutputTokens: number): number | 'local' {
  const bound = Math.ceil(Math.max(0, requestBytes)) + FRAMING_MARGIN_TOKENS;
  const rate = ceilingRates(provider, bound);
  if (rate === null) return 'local';
  if (rate === 'unpriced' || !isOutputLimit(maxOutputTokens)) return Number.POSITIVE_INFINITY;
  return rate.runs * (((bound * CACHE_WRITE_FACTOR) / 1e6) * rate.input + (maxOutputTokens / 1e6) * rate.output);
}

/**
 * What tokens already used cost at ceilingRates for their real prompt length (usage already holds every run, so no
 * multiplying). Infinity for a model with no price; 'local' for a local model.
 */
export function usageCeilingUsd(provider: AiProviderChoice, usage: AiUsage): number | 'local' {
  const rate = ceilingRates(provider, promptTokens(usage));
  if (rate === null) return 'local';
  return rate === 'unpriced' ? Number.POSITIVE_INFINITY : priceUsage(usage, rate);
}

// ---------- activity30d ----------

const WINDOW_MS = 30 * 86_400_000;
const PER_PAGE = 100;
/**
 * GitHub's repo event list holds at most 300 events from the last 30 days (3 pages of 100), and a page can hold fewer
 * than 100 events while more follow: only the `Link: rel="next"` header says another page exists (Plan U final review
 * I1; https://docs.github.com/en/rest/activity/events, "About GitHub events", checked 2026-10-27).
 */
const EVENT_PAGES = 3;
/** Pull request pages read at most (1,000 pull requests in 30 days). */
const PR_PAGES = 10;
const eventsSchema = z.array(z.object({ type: z.string().nullable(), created_at: z.string().nullable() }));
const pullsSchema = z.array(z.object({ created_at: z.string() }));

/** True when GitHub's Link header (any letter case of the name) points to a next page. */
function hasNextPage(res: unknown): boolean {
  const headers = (res as { headers?: Record<string, unknown> } | null)?.headers;
  if (headers === undefined || headers === null || typeof headers !== 'object') return false;
  const link = Object.entries(headers).find(([k]) => k.toLowerCase() === 'link')?.[1];
  return typeof link === 'string' && /<[^>]*>\s*;\s*rel="?next"?/i.test(link.slice(0, 4096));
}

/**
 * Pushes (PushEvent in GET /repos/{o}/{r}/events) and pull requests opened (GET /repos/{o}/{r}/pulls?state=all, newest
 * first) in the last 30 days. Every call goes through withRateLimit with the caller's clock and run budget (one
 * newRateBudget() per run); `clock.now` also sets the window. Each list is paged by GitHub's `Link: rel="next"` header
 * (never by a full page: GitHub serves short pages that aren't the last), up to its page cap.
 * The counts are lower bounds (`capped`) when a list stopped before the start of the 30 days because:
 * - the event list ended at GitHub's 300-event limit (its last page read; GitHub keeps no more), or the pull request
 *   pages hit pipegen's cap with a next page left;
 * - a rate stop (GitHub's limit or the run's spent wait budget) on a later page: what was counted is kept.
 * A list that ends earlier, without a next page, holds every event or pull request of the 30 days: exact.
 * A rate limit (GitHubRateLimitError) or an unreadable answer on the FIRST page of either list is thrown, never turned
 * into a zero count.
 */
export async function activity30d(gh: Octokit, p: RepoProfile, clock: RateClock): Promise<Activity> {
  const since = (clock.now ?? Date.now)() - WINDOW_MS;
  const { owner, repo } = p;
  const read = <T>(schema: z.ZodType<T>, data: unknown, what: string): T => {
    const parsed = schema.safeParse(data);
    if (!parsed.success) throw new Error(`GitHub's ${what} for ${safeText(`${owner}/${repo}`, 200)} could not be read.`);
    return parsed.data;
  };
  const inWindow = (at: string | null) => {
    const t = Date.parse(at ?? '');
    return Number.isFinite(t) ? t >= since : undefined;
  };
  /**
   * Reads pages 1..maxPages while GitHub says a next page exists and `onPage` hasn't reached the window start. Returns
   * whether the count is a lower bound: the start wasn't reached and the list was cut (a next page left unread, the
   * event list's own limit reached, or a rate stop on a later page).
   */
  const pagesOf = async <T>(call: (page: number) => Promise<unknown>, schema: z.ZodType<T[]>, what: string, maxPages: number,
    endsAtLimit: boolean, onPage: (list: T[]) => boolean): Promise<boolean> => {
    for (let page = 1; page <= maxPages; page++) {
      let res: unknown;
      try {
        res = await withRateLimit(() => call(page), clock);
      } catch (e) {
        if (page > 1 && isRateStop(e)) return true; // keep what was counted, as a lower bound
        throw e;
      }
      const reachedStart = onPage(read(schema, (res as { data?: unknown } | null)?.data, what));
      if (reachedStart) return false;
      if (!hasNextPage(res)) return endsAtLimit && page === maxPages;
    }
    return true; // the page cap, with a next page left
  };

  let pushes = 0;
  const eventsCapped = await pagesOf((page) => gh.rest.activity.listRepoEvents({ owner, repo, per_page: PER_PAGE, page }), eventsSchema, 'event list',
    EVENT_PAGES, true, (list) => {
      let older = false;
      for (const e of list) {
        const inside = inWindow(e.created_at);
        if (inside === false) older = true;
        else if (inside && e.type === 'PushEvent') pushes++;
      }
      return older;
    });

  let prs = 0;
  const prsCapped = await pagesOf((page) => gh.rest.pulls.list({ owner, repo, state: 'all', sort: 'created', direction: 'desc', per_page: PER_PAGE, page }),
    pullsSchema, 'pull request list', PR_PAGES, false, (list) => {
      let older = false;
      for (const pr of list) {
        const inside = inWindow(pr.created_at);
        if (inside === false) older = true;
        else if (inside) prs++;
      }
      return older;
    });

  return { pushes, prs, capped: eventsCapped || prsCapped };
}
