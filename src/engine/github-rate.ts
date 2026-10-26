// GitHub rate limits, shared by discovery, stats and pinning (Plan B ruling S16).
// A rate-limited answer is a 403 or 429 with `x-ratelimit-remaining: 0` (wait until `x-ratelimit-reset`) or with
// `retry-after` (secondary limits). pipegen waits only when that is at most 60 s away, then retries once. Anything
// longer, or a second limit, is a GitHubRateLimitError for the caller to report. Waits also come out of a total
// budget per run (default 120 s): once a wait would go past it, the call fails with
// GitHubRateLimitError("GitHub rate limit: stopped waiting.") (budgetSpent: true) instead of sleeping.
// sleep, now and the budget are injected so tests never really wait.

export const MAX_RATE_WAIT_MS = 60_000;
/** Added to each wait: the reset time is in whole seconds. */
const RESET_MARGIN_MS = 1_000;

export const DEFAULT_RATE_BUDGET_MS = 120_000;
export const BUDGET_SPENT_MESSAGE = 'GitHub rate limit: stopped waiting.';

/** What is left of a run's total wait budget; whoever holds the object shares it. */
export interface RateBudget { remainingMs: number }
/**
 * `budget`: the run's wait budget. When it is not given, one default budget is kept per clock object, so every
 * call made with the same deps object (one run) shares it.
 */
export interface RateClock { sleep?: (ms: number) => Promise<void>; now?: () => number; budget?: RateBudget }

export class GitHubRateLimitError extends Error {
  /** True when the run's total wait budget is spent (rather than one reset being too far away). */
  readonly budgetSpent: boolean;
  constructor(message: string, options?: { cause?: unknown; budgetSpent?: boolean }) {
    super(message, options);
    this.name = 'GitHubRateLimitError';
    this.budgetSpent = options?.budgetSpent ?? false;
  }
}

const defaultBudgets = new WeakMap<object, RateBudget>();
function budgetOf(clock: RateClock): RateBudget {
  if (clock.budget) return clock.budget;
  let budget = defaultBudgets.get(clock);
  if (budget === undefined) {
    budget = { remainingMs: DEFAULT_RATE_BUDGET_MS };
    defaultBudgets.set(clock, budget);
  }
  return budget;
}

const realSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function headerOf(err: unknown, name: string): string | undefined {
  const headers = (err as { response?: { headers?: Record<string, unknown> } } | null)?.response?.headers;
  const v = headers?.[name];
  return typeof v === 'string' || typeof v === 'number' ? String(v) : undefined;
}

/**
 * Milliseconds until GitHub accepts requests again when `err` is a rate-limit answer (Infinity when the reset is
 * not given), else undefined (the error is something else and must not be retried).
 */
export function rateLimitWaitMs(err: unknown, nowMs: number): number | undefined {
  const status = (err as { status?: unknown } | null)?.status;
  if (status !== 403 && status !== 429) return undefined;
  const retryAfter = headerOf(err, 'retry-after');
  if (retryAfter !== undefined && /^\d{1,6}$/.test(retryAfter)) return Number(retryAfter) * 1000;
  if (headerOf(err, 'x-ratelimit-remaining') !== '0') return undefined;
  const reset = headerOf(err, 'x-ratelimit-reset');
  if (reset === undefined || !/^\d{1,12}$/.test(reset)) return Number.POSITIVE_INFINITY;
  return Math.max(0, Number(reset) * 1000 - nowMs);
}

function limitError(waitMs: number, cause: unknown): GitHubRateLimitError {
  const when = Number.isFinite(waitMs) ? `in about ${Math.max(1, Math.ceil(waitMs / 60_000))} minutes` : 'later';
  return new GitHubRateLimitError(`GitHub's rate limit was reached; it resets ${when}.`, { cause });
}

/** Runs one GitHub call; on a rate limit that resets within 60 s (and fits the run's budget), waits and retries it once. */
export async function withRateLimit<T>(call: () => Promise<T>, clock: RateClock = {}): Promise<T> {
  const sleep = clock.sleep ?? realSleep;
  const now = clock.now ?? Date.now;
  try {
    return await call();
  } catch (e) {
    const wait = rateLimitWaitMs(e, now());
    if (wait === undefined) throw e;
    if (wait > MAX_RATE_WAIT_MS) throw limitError(wait, e);
    const budget = budgetOf(clock);
    const cost = wait + RESET_MARGIN_MS;
    if (!(cost <= budget.remainingMs)) throw new GitHubRateLimitError(BUDGET_SPENT_MESSAGE, { cause: e, budgetSpent: true });
    budget.remainingMs -= cost;
    await sleep(cost);
  }
  try {
    return await call();
  } catch (e) {
    const wait = rateLimitWaitMs(e, now());
    if (wait === undefined) throw e;
    throw limitError(wait, e);
  }
}
