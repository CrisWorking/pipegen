import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_RATE_BUDGET_MS, GitHubRateLimitError, MAX_RATE_WAIT_MS, newRateBudget, rateLimitWaitMs, withRateLimit } from '../src/engine/github-rate.js';
import { fakeOctokit } from './helpers/fake-http.js';

const NOW = Date.parse('2026-10-26T12:00:00Z');
const resetIn = (seconds: number) => String(Math.floor(NOW / 1000) + seconds);
const limited = (seconds: number, status = 403) => ({
  status, body: { message: 'API rate limit exceeded' },
  headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': resetIn(seconds) },
});

/** A clock whose sleep only records the wait and moves time forward, with a fresh run budget (default 120 s). */
function fakeClock() {
  let now = NOW;
  const waits: number[] = [];
  return { waits, now: () => now, sleep: vi.fn(async (ms: number) => { waits.push(ms); now += ms; }), budget: newRateBudget() };
}

describe('github rate limit', () => {
  it('githubRate: waits for a reset within 60 s, then retries once', async () => {
    let n = 0;
    const { gh } = fakeOctokit({ 'GET https://api.github.com/repos/o/r': () => (n++ === 0 ? limited(20) : { body: { full_name: 'o/r' } }) });
    const clock = fakeClock();
    const res = await withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'r' }), clock);
    expect(res.data.full_name).toBe('o/r');
    expect(n).toBe(2);
    expect(clock.waits).toEqual([21_000]); // until the reset, plus one second
  });

  it('githubRate: a 429 secondary limit with retry-after is waited for too', async () => {
    let n = 0;
    const { gh } = fakeOctokit({ 'GET https://api.github.com/repos/o/r': () => (n++ === 0 ? { status: 429, headers: { 'retry-after': '5' } } : { body: {} }) });
    const clock = fakeClock();
    await withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'r' }), clock);
    expect(clock.waits).toEqual([6_000]);
  });

  it('githubRate: reset beyond 60 s → GitHubRateLimitError, no wait', async () => {
    const { gh, calls } = fakeOctokit({ 'GET https://api.github.com/repos/o/r': limited(61) });
    const clock = fakeClock();
    await expect(withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'r' }), clock)).rejects.toThrow(GitHubRateLimitError);
    expect(clock.sleep).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
  });

  it('githubRate: still limited after the wait → GitHubRateLimitError (one retry only)', async () => {
    const { gh, calls } = fakeOctokit({ 'GET https://api.github.com/repos/o/r': limited(10, 429) });
    const clock = fakeClock();
    await expect(withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'r' }), clock)).rejects.toThrow(GitHubRateLimitError);
    expect(calls).toHaveLength(2);
    expect(clock.sleep).toHaveBeenCalledTimes(1);
  });

  it('githubRate: a 403 or 404 that is not a rate limit passes through unchanged', async () => {
    const { gh } = fakeOctokit({
      'GET https://api.github.com/repos/o/denied': { status: 403, body: { message: 'Forbidden' }, headers: { 'x-ratelimit-remaining': '4999' } },
    });
    const clock = fakeClock();
    await expect(withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'denied' }), clock)).rejects.toMatchObject({ status: 403 });
    await expect(withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'gone' }), clock)).rejects.toMatchObject({ status: 404 });
    expect(clock.sleep).not.toHaveBeenCalled();
  });

  it('githubRate: total wait budget per run; once spent, the next limit throws instead of sleeping', async () => {
    let n = 0;
    const clock = fakeClock(); // one run: its budget (120 s) is shared by every call made with it
    // every other call is limited until 40 s after the clock's current time (41 s with the margin)
    const limitedNow = () => ({ status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(clock.now() / 1000) + 40) } });
    const { gh } = fakeOctokit({ 'GET https://api.github.com/repos/o/r': () => (n++ % 2 === 0 ? limitedNow() : { body: {} }) });
    const call = () => withRateLimit(() => gh.rest.repos.get({ owner: 'o', repo: 'r' }), clock);
    await call();
    await call(); // 82 s spent
    const spent = await call().catch((e: unknown) => e); // 41 s more would pass 120 s
    expect(spent).toBeInstanceOf(GitHubRateLimitError);
    expect((spent as GitHubRateLimitError).message).toBe('GitHub rate limit: stopped waiting.');
    expect((spent as GitHubRateLimitError).budgetSpent).toBe(true);
    expect(clock.waits).toEqual([41_000, 41_000]);
    expect(DEFAULT_RATE_BUDGET_MS).toBe(120_000);
    expect(newRateBudget()).toEqual({ remainingMs: 120_000 });
    expect(newRateBudget(5_000)).toEqual({ remainingMs: 5_000 });

    // a smaller budget (shared by whoever holds it)
    const other = fakeOctokit({ 'GET https://api.github.com/repos/o/r': limited(40) });
    const budget = newRateBudget(10_000);
    const small = { ...fakeClock(), budget };
    await expect(withRateLimit(() => other.gh.rest.repos.get({ owner: 'o', repo: 'r' }), small)).rejects.toThrow('GitHub rate limit: stopped waiting.');
    expect(small.sleep).not.toHaveBeenCalled();
    expect(budget.remainingMs).toBe(10_000);
  });

  it('githubRate: rateLimitWaitMs reads the headers; no reset header → never waits', () => {
    const err = (status: number, headers: Record<string, string>) => ({ status, response: { headers } });
    expect(rateLimitWaitMs(err(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': resetIn(30) }), NOW)).toBe(30_000);
    expect(rateLimitWaitMs(err(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': resetIn(-5) }), NOW)).toBe(0);
    expect(rateLimitWaitMs(err(403, { 'x-ratelimit-remaining': '0' }), NOW)).toBe(Number.POSITIVE_INFINITY);
    expect(rateLimitWaitMs(err(403, {}), NOW)).toBeUndefined();
    expect(rateLimitWaitMs(err(500, { 'x-ratelimit-remaining': '0' }), NOW)).toBeUndefined();
    expect(rateLimitWaitMs(new Error('boom'), NOW)).toBeUndefined();
    expect(MAX_RATE_WAIT_MS).toBe(60_000);
  });
});
