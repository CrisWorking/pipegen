// GitHub rate limits, shared by discovery, stats and pinning (Plan B ruling S16).
// A rate-limited answer is a 403 or 429 with `x-ratelimit-remaining: 0` (wait until `x-ratelimit-reset`) or with
// `retry-after` (secondary limits). pipegen waits only when that is at most 60 s away, then retries once. Anything
// longer, or a second limit, is a GitHubRateLimitError for the caller to report. Waits also come out of a total
// budget per run, which the caller creates once per run with newRateBudget() (default 120 s) and passes to every
// call: once a wait would go past it, the call fails with GitHubRateLimitError("GitHub rate limit: stopped
// waiting.") (budgetSpent: true) instead of sleeping. sleep and now are injected so tests never really wait.

export const MAX_RATE_WAIT_MS = 60_000;
/** Added to each wait: the reset time is in whole seconds. */
const RESET_MARGIN_MS = 1_000;

export const DEFAULT_RATE_BUDGET_MS = 120_000;
export const BUDGET_SPENT_MESSAGE = 'GitHub rate limit: stopped waiting.';

/**
 * What is left of a run's total wait budget; whoever holds the object shares it. `stopped` (DoD run 2026-10-29): the
 * run's rate stop (the one with the latest reset), so the caller can say the limit was hit and when it resets, and can
 * skip its own further calls (rateStopOf). withRateLimit itself still sends every call: GitHub's search API has its
 * own limit, so a stop on one call says nothing certain about the next.
 */
export interface RateBudget { remainingMs: number; stopped?: GitHubRateLimitError }
/** `budget`: the run's wait budget, created once per run by the caller (newRateBudget) and shared by every call. */
export interface RateClock { sleep?: (ms: number) => Promise<void>; now?: () => number; budget: RateBudget }

/** A fresh wait budget for one run. */
export function newRateBudget(ms: number = DEFAULT_RATE_BUDGET_MS): RateBudget {
  return { remainingMs: ms };
}

export class GitHubRateLimitError extends Error {
  /** True when the run's total wait budget is spent (rather than one reset being too far away). */
  readonly budgetSpent: boolean;
  /** When GitHub accepts requests again (ms since epoch), from x-ratelimit-reset or retry-after; null when it didn't say. */
  readonly resetAt: number | null;
  constructor(message: string, options?: { cause?: unknown; budgetSpent?: boolean; resetAt?: number | null }) {
    super(message, options);
    this.name = 'GitHubRateLimitError';
    this.budgetSpent = options?.budgetSpent ?? false;
    this.resetAt = options?.resetAt ?? null;
  }
}

/** The run's rate stop, while its reset time hasn't passed (a stop without a reset time lasts for the run). */
export function rateStopOf(budget: RateBudget, nowMs: number = Date.now()): GitHubRateLimitError | null {
  const s = budget.stopped;
  if (s === undefined) return null;
  return s.resetAt === null || nowMs < s.resetAt ? s : null;
}

/**
 * When GitHub's limit resets, in plain words (DoD run 2026-10-29). The time is rounded UP to the next minute and the
 * minutes are rounded up too, so pipegen never says the limit resets sooner than GitHub said. `timeZone`: for tests;
 * default the machine's own time zone.
 */
export function resetText(resetAt: number | null, nowMs: number, timeZone?: string): string {
  if (resetAt === null) return "GitHub didn't say when its limit resets.";
  const mins = Math.max(1, Math.ceil((resetAt - nowMs) / 60_000));
  const shown = new Date(Math.ceil(resetAt / 60_000) * 60_000);
  const parts = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'short', ...(timeZone === undefined ? {} : { timeZone }) }).formatToParts(shown);
  const part = (t: string) => parts.find((x) => x.type === t)?.value ?? '';
  return `GitHub's limit resets by ${part('hour')}:${part('minute')} ${part('timeZoneName')} (your local time), within ${mins} ${mins === 1 ? 'minute' : 'minutes'}.`;
}

/**
 * Is a failure GitHub's rate limit or the run's spent wait budget? True for a GitHubRateLimitError and for any error
 * whose cause chain holds one (a StatsError or PinError raised for a spent budget keeps the GitHubRateLimitError as
 * its cause). Callers stop all further GitHub work then (discovery, pinning, Plan D/U).
 */
export function isRateStop(e: unknown): boolean {
  let cur: unknown = e;
  for (let depth = 0; depth < 8 && cur !== null && cur !== undefined; depth++) {
    if (cur instanceof GitHubRateLimitError) return true;
    cur = (cur as { cause?: unknown }).cause;
  }
  return false;
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

function limitError(waitMs: number, cause: unknown, nowMs: number): GitHubRateLimitError {
  const when = Number.isFinite(waitMs) ? `in about ${Math.max(1, Math.ceil(waitMs / 60_000))} minutes` : 'later';
  return new GitHubRateLimitError(`GitHub's rate limit was reached; it resets ${when}.`, { cause, resetAt: Number.isFinite(waitMs) ? nowMs + waitMs : null });
}

/** Records the run's first rate stop on its budget (rateStopOf), then returns it to throw. */
function stop(budget: RateBudget, e: GitHubRateLimitError): GitHubRateLimitError {
  budget.stopped ??= e;
  if (budget.stopped !== e && (budget.stopped.resetAt ?? Infinity) < (e.resetAt ?? Infinity)) budget.stopped = e; // the later reset wins
  return e;
}

/**
 * Runs one GitHub call; on a rate limit that resets within 60 s (and fits the run's budget), waits and retries it once.
 * Every rate stop it throws is recorded on the budget (`stopped`).
 */
export async function withRateLimit<T>(call: () => Promise<T>, clock: RateClock): Promise<T> {
  const sleep = clock.sleep ?? realSleep;
  const now = clock.now ?? Date.now;
  const budget = clock.budget;
  try {
    return await call();
  } catch (e) {
    const t = now();
    const wait = rateLimitWaitMs(e, t);
    if (wait === undefined) throw e;
    if (wait > MAX_RATE_WAIT_MS) throw stop(budget, limitError(wait, e, t));
    const cost = wait + RESET_MARGIN_MS;
    if (!(cost <= budget.remainingMs)) throw stop(budget, new GitHubRateLimitError(BUDGET_SPENT_MESSAGE, { cause: e, budgetSpent: true, resetAt: t + wait }));
    budget.remainingMs -= cost;
    await sleep(cost);
  }
  try {
    return await call();
  } catch (e) {
    const t = now();
    const wait = rateLimitWaitMs(e, t);
    if (wait === undefined) throw e;
    throw stop(budget, limitError(wait, e, t));
  }
}
