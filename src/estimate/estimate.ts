// Estimates (Plan A Task 9): Actions minutes for setup and per month, the AI cost and its hard cap, and the time it
// takes. Shown at consent (Plan A Task 8) and in the audit report (Plan U). Every assumption goes into `basis`, in
// plain English.
// - Minutes per job come from spike S5 (DECISIONS #81), keyed by need category: measured on a small Node + Postgres app
//   on a private repo, plus about 50% for bigger apps and the egress-control step. Callers pass the jobs of each layer
//   by category: `jobCategories(floorNeeds(p, caps))` (src/engine/needs.ts), since consent comes before the AI adds needs.
// - The setup estimate also counts the proof harness (Plan E Task 2) and the compat copies of the repo's own
//   workflow jobs, per proof variant.
// - AI input and output tokens are priced separately with data/ai-prices.yml, for the chosen provider and model.
// - estimateAuditAi (Plan U ruling B2) prices `audit --ai` alone: one needs call plus the discovery calls.
// - activity30d reads the last 30 days of pushes and pull requests through the caller's Octokit and rate budget.
import { readFileSync } from 'node:fs';
import type { Octokit } from '@octokit/rest';
import { parse } from 'yaml';
import { z } from 'zod';
import { MAX_DISCOVERY_NEEDS } from '../engine/discover.js';
import { withRateLimit, type RateClock } from '../engine/github-rate.js';
import { DEFAULT_MODEL, type Layer, type Plan, type RepoProfile } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';

export type AiStage = 'needs' | 'debate' | 'creators' | 'fix-loop';
/** Pushes and pull requests opened in the last 30 days. `capped`: the event list (300 events) or the pull request pages (1,000) ended inside the window, so the counts are lower bounds. */
export interface Activity { pushes: number; prs: number; capped: boolean }
/** The CI jobs of each layer (plus nightly), each named by its need category. Build it with jobCategories() (src/engine/needs.ts). */
export type JobCategories = Record<Layer | 'nightly', string[]>;
export interface AiCost { input: { low: number; high: number }; output: { low: number; high: number }; low: number; high: number }
export interface AiProviderChoice { name: string; model: string }

export interface Estimates {
  setupMinutes: number; setupMinutesCap: number; monthlyMinutes: number;
  /** Actions minutes the plan includes per month for private repos; null for a public repo (minutes are free) or plan 'unknown' (ruling S12). */
  includedMinutes: number | null;
  aiTokens: { stage: AiStage; input: number; output: number }[];   // empty when there's no provider
  aiCostUsd: AiCost | 'local';
  aiCostCapUsd: number | null;                                       // 2 × aiCostUsd.high; null for Ollama (local) or no provider
  durationMinutes: { low: number; high: number }; basis: string[];
}

export interface AuditAiEstimate { tokens: { input: number; output: number }; costUsd: AiCost | 'local'; capUsd: number | null; basis: string[] }

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
const price = z.strictObject({ input: z.number().finite().nonnegative(), output: z.number().finite().nonnegative() });
const paidPrice = z.strictObject({ input: z.number().finite().positive(), output: z.number().finite().positive() });
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

interface PriceChoice { local: boolean; input: number; output: number; model: string; notes: string[] }

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
  if (table?.local) return { local: true, input: 0, output: 0, model: shown, notes: [] };
  const found = table !== undefined && Object.hasOwn(table.models, provider.model) ? table.models[provider.model] : undefined;
  if (found) {
    return { local: false, ...found, model: shown, notes: [`Prices for ${shown}: ${perMillion(found)} (checked ${list.checkedAt}).`] };
  }
  const pool = table ? [table] : [list.providers.claude, list.providers.openai];
  let top: { name: string; input: number; output: number } | undefined;
  for (const t of pool) {
    for (const [name, m] of Object.entries(t.models)) {
      if (!top || m.input + m.output > top.input + top.output) top = { name, input: m.input, output: m.output };
    }
  }
  const t = top as { name: string; input: number; output: number }; // the schema guarantees claude has models
  const whose = table ? `the same provider (${safeText(provider.name, 40)})` : 'any provider in its price list';
  return {
    local: false, input: t.input, output: t.output, model: t.name,
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

// ---------- estimate ----------

/**
 * The estimates for a full run. `jobs`: the CI jobs per layer by need category (jobCategories(floorNeeds(p, caps))).
 * `variants`: proof variants (at least 1; callers pass 2: `main` and `planted`). `activity`: activity30d's answer.
 * `provider`: the chosen AI provider and model, or null when there is none.
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
      ? `Activity: at least ${plural(pushes, 'push', 'pushes')} and at least ${plural(prs, 'pull request', 'pull requests')} in the last 30 days `
        + `(GitHub lists only the last ${EVENT_PAGES * PER_PAGE} events and pipegen reads at most ${(PR_PAGES * PER_PAGE).toLocaleString('en-US')} pull requests).`
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
      basis.push('Ollama runs on your machine: no AI cost and no cost cap.');
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

  return { setupMinutes, setupMinutesCap, monthlyMinutes, includedMinutes: included, aiTokens, aiCostUsd, aiCostCapUsd, durationMinutes: { low, high: 2 * low }, basis };
}

function includedMinutesFor(isPrivate: boolean, plan: Plan): number | null {
  if (!isPrivate || plan === 'unknown') return null;
  return plans().includedMinutes[plan];
}

/**
 * The AI cost of `audit --ai` alone (Plan U ruling B2): one needs call plus one candidates call for each need that goes
 * to discovery, at most MAX_DISCOVERY_NEEDS. `needCount`: the needs with no reviewed tool. Priced like estimate() for
 * the chosen provider and model; cap = 2 × high; Ollama → 'local', no cap.
 */
export function estimateAuditAi(provider: AiProviderChoice, needCount: number): AuditAiEstimate {
  const calls = Math.min(count(needCount), MAX_DISCOVERY_NEEDS);
  const needs = STAGE_TOKENS[0] as { input: number; output: number };
  const tokens = { input: needs.input + calls * CANDIDATE_CALL.input, output: needs.output + calls * CANDIDATE_CALL.output };
  const pr = priceFor(provider);
  const basis = [
    `The AI part of the audit is 1 needs call plus up to ${MAX_DISCOVERY_NEEDS} discovery calls, one for each need with no reviewed tool (${calls} here), at about ${thousands(CANDIDATE_CALL.input)} input / ${thousands(CANDIDATE_CALL.output)} output tokens for each discovery call.`,
    `The cost range is ×${LOW} to ×${HIGH} of the token estimate, and the cap is twice the high end.`,
  ];
  if (pr.local) return { tokens, costUsd: 'local', capUsd: null, basis: [...basis, 'Ollama runs on your machine: no AI cost and no cost cap.'] };
  const c = cost(tokens, pr);
  return { tokens, costUsd: c, capUsd: CAP_FACTOR * c.high, basis: [...basis, `Priced with the model ${pr.model}.`, ...pr.notes] };
}

// ---------- activity30d ----------

const WINDOW_MS = 30 * 86_400_000;
const PER_PAGE = 100;
/** GitHub's repo event list holds at most 300 events (3 pages of 100). */
const EVENT_PAGES = 3;
/** Pull request pages read at most (1,000 pull requests in 30 days). */
const PR_PAGES = 10;
const eventsSchema = z.array(z.object({ type: z.string().nullable(), created_at: z.string().nullable() }));
const pullsSchema = z.array(z.object({ created_at: z.string() }));

/**
 * Pushes (PushEvent in GET /repos/{o}/{r}/events) and pull requests opened (GET /repos/{o}/{r}/pulls?state=all, newest
 * first) in the last 30 days. Every call goes through withRateLimit with the caller's clock and run budget (one
 * newRateBudget() per run); `clock.now` also sets the window. A rate limit (GitHubRateLimitError) or an unreadable
 * answer is thrown, never turned into a zero count.
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

  let pushes = 0;
  let events = 0;
  let older = false;
  for (let page = 1; page <= EVENT_PAGES && !older; page++) {
    const res = await withRateLimit(() => gh.rest.activity.listRepoEvents({ owner, repo, per_page: PER_PAGE, page }), clock);
    const list = read(eventsSchema, res.data, 'event list');
    events += list.length;
    for (const e of list) {
      const inside = inWindow(e.created_at);
      if (inside === false) older = true;
      else if (inside && e.type === 'PushEvent') pushes++;
    }
    if (list.length < PER_PAGE) break;
  }

  let prs = 0;
  let olderPr = false;
  let prPagesFull = 0;
  for (let page = 1; page <= PR_PAGES && !olderPr; page++) {
    const res = await withRateLimit(() => gh.rest.pulls.list({ owner, repo, state: 'all', sort: 'created', direction: 'desc', per_page: PER_PAGE, page }), clock);
    const list = read(pullsSchema, res.data, 'pull request list');
    for (const pr of list) {
      const inside = inWindow(pr.created_at);
      if (inside === false) olderPr = true;
      else if (inside) prs++;
    }
    if (list.length < PER_PAGE) break;
    prPagesFull++;
  }

  // Capped: a list that ran out of pages (not of data) while everything was still inside the window; the counts are lower bounds.
  const eventsCapped = !older && events >= EVENT_PAGES * PER_PAGE;
  const prsCapped = !olderPr && prPagesFull >= PR_PAGES;
  return { pushes, prs, capped: eventsCapped || prsCapped };
}
