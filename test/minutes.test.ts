// Plan E Task 6 / E6 (rulings S12, B4): the Actions minutes meter, the force-cancel after a cancel that didn't take, and the
// "a cap was reached" stop path. A real makeOctokit client over the stateful fakes (proof-github.ts world(), proof-runs.ts);
// the poll clock is fake (no real waiting). interrupting() is mocked. No network.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AiError } from '../src/ai/provider.js';
import { AiSpendMeter } from '../src/ai/spend-meter.js';
import { cancelActiveRuns, capMessage, CapReachedError, capReached, stopAtCap, type CapReached } from '../src/proof/caps.js';
import { MINUTES_SKEW_MARGIN_MS, MINUTES_UNREAD_LIMIT, MinutesMeter, minutesStop, proofStart } from '../src/proof/minutes.js';
import { cancelRuns, findRuns, FORCE_CANCEL_AFTER_MS, waitForRuns, type PollClock } from '../src/proof/run.js';
import { proofTarget, ProofStopError, type ProofTarget } from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest } from '../src/types.js';
import type { Call, Reply } from './helpers/fake-http.js';
import { world } from './helpers/proof-github.js';
import { runsFake, type RunsFake } from './helpers/proof-runs.js';
import { app, OWNER, SCRATCH } from './helpers/scratch-secrets.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); });

const R = `/repos/${OWNER}/${SCRATCH}`;
const SINCE = Date.parse('2026-11-04T10:00:00Z');
const at = (hms: string) => `2026-11-04T${hms}Z`;
const ms = (hms: string) => Date.parse(at(hms));
const target = (): ProofTarget => proofTarget(app(), { runId: '20261104-100000-abcdef' });

interface FakeJob { status: string; started_at: string | null; completed_at: string | null; run_attempt?: number; conclusion?: string | null }
interface MinutesWorld {
  runs: Map<number, FakeJob[]>;
  /** When each run was created (GitHub's clock); default 10:00:00. The list honours `created>=`. */
  created: Map<number, string>;
  /** GitHub's clock: the `date` header of every answer (null: no date header). Default 10:30:00. */
  now: number | null;
  listStatus?: number; jobsBody?: unknown; calls: Call[]; gh: ReturnType<typeof world>['gh'];
}
/** The scratch repo's run list and each run's jobs (filter=all lists every attempt's; filter=latest only the last). */
function minutesWorld(runs: Record<number, FakeJob[]>): MinutesWorld {
  const w: MinutesWorld = { runs: new Map(Object.entries(runs).map(([k, v]) => [Number(k), v])), created: new Map(), now: ms('10:30:00'), calls: [], gh: undefined as never };
  const dated = (r: Reply): Reply => (w.now === null ? r : { ...r, headers: { ...(r.headers ?? {}), date: new Date(w.now).toUTCString() } });
  const extra = (c: Call): Reply | undefined => {
    const path = decodeURIComponent(c.url.pathname);
    if (!path.startsWith(R)) return undefined;
    const rest = path.slice(R.length);
    if (c.method === 'GET' && rest === '/actions/runs') {
      if (w.listStatus !== undefined) return dated({ status: w.listStatus, body: { message: 'Server Error' } });
      const from = /^>=(.+)$/.exec(c.url.searchParams.get('created') ?? '')?.[1];
      const list = [...w.runs.keys()].map((id) => ({ id, status: 'completed', created_at: w.created.get(id) ?? at('10:00:00') }))
        .filter((r) => from === undefined || Date.parse(r.created_at) >= Date.parse(from));
      return dated({ status: 200, body: { total_count: list.length, workflow_runs: list } });
    }
    const m = /^\/actions\/runs\/(\d+)\/jobs$/.exec(rest);
    if (m && c.method === 'GET') {
      if (w.jobsBody !== undefined) return dated({ status: 200, body: w.jobsBody });
      const id = Number(m[1]);
      const all = (w.runs.get(id) ?? []).map((j, i) => ({ id: id * 100 + i, run_id: id, name: `job ${i}`, run_attempt: j.run_attempt ?? 1, ...j }));
      const last = Math.max(1, ...all.map((j) => j.run_attempt));
      const jobs = c.url.searchParams.get('filter') === 'all' ? all : all.filter((j) => j.run_attempt === last);
      return dated({ status: 200, body: { total_count: jobs.length, jobs } });
    }
    return undefined;
  };
  const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra });
  w.gh = g.gh;
  w.calls = g.calls;
  return w;
}
const done = (from: string, to: string, attempt = 1): FakeJob => ({ status: 'completed', started_at: at(from), completed_at: at(to), run_attempt: attempt });
const queued: FakeJob = { status: 'queued', started_at: null, completed_at: null };

function fakeClock(start = 0): PollClock & { t: number; sleeps: number[] } {
  const c = { t: start, sleeps: [] as number[], now: () => c.t, sleep: async (n: number) => { c.sleeps.push(n); c.t += n; } };
  return c;
}

describe('E6 minutes meter (S12)', () => {
  it('meter: each job rounded up to a whole minute', async () => {
    const w = minutesWorld({
      1: [done('10:00:00', '10:00:01'), done('10:01:00', '10:03:00'), done('10:04:00', '10:06:00.5'), queued],
      2: [done('10:10:00', '10:10:00')],   // a finished job that took no time still counts one minute
      // not started on a runner: 0, whatever else GitHub lists (a queued job with a start time, a finished job without one)
      3: [{ status: 'queued', started_at: at('10:00:00'), completed_at: null }, { status: 'completed', started_at: null, completed_at: at('10:20:00') }],
      // ruling E6-R1: a skipped job got no runner, so it counts 0 (GitHub bills none)
      4: [{ status: 'completed', conclusion: 'skipped', started_at: at('10:11:00'), completed_at: at('10:11:00') }],
    });
    const m = new MinutesMeter(100, SINCE);
    w.now = ms('10:30:00'); await m.add(w.gh, target());
    // 1 (1 s) + 2 (exactly 120 s) + 3 (120.5 s) + 0 (queued) + 1 (0 s)
    expect(m.used).toBe(7);
    expect(m.exceeded).toBe(false);
  });

  it('meter: exceeded when the sum passes the cap', async () => {
    const w = minutesWorld({ 1: [done('10:00:00', '10:04:00')] });
    const m = new MinutesMeter(5, SINCE);
    const t = target();
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.used).toBe(4);
    expect(m.exceeded).toBe(false);
    w.runs.set(2, [done('10:05:00', '10:05:30')]);
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.used).toBe(5);
    expect(m.exceeded).toBe(true);   // the limit reached is the stop: no minute past it is started
    w.runs.set(3, [done('10:06:00', '10:08:00')]);
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.used).toBe(7);
    expect(m.exceeded).toBe(true);
    // the count never goes down (a run deleted later still was billed)
    w.runs.clear();
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.used).toBe(7);
    // a cap that isn't a finite number of minutes is refused
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1]) expect(() => new MinutesMeter(bad, SINCE)).toThrow(/cap/);
  });

  it('meter: in-progress jobs counted up to now', async () => {
    const w = minutesWorld({ 1: [{ status: 'in_progress', started_at: at('10:05:00'), completed_at: null }, queued, { status: 'waiting', started_at: null, completed_at: null }] });
    const m = new MinutesMeter(100, SINCE);
    w.now = ms('10:07:30'); await m.add(w.gh, target());
    expect(m.used).toBe(3);   // 150 s so far → 3 minutes; queued and waiting jobs → 0
    w.now = ms('10:12:00'); await m.add(w.gh, target());
    expect(m.used).toBe(7);
    // a job that just started counts one minute
    const w2 = minutesWorld({ 1: [{ status: 'in_progress', started_at: at('10:05:00'), completed_at: null }] });
    const m2 = new MinutesMeter(100, SINCE);
    w2.now = ms('10:05:00'); await m2.add(w2.gh, target());
    expect(m2.used).toBe(1);
  });

  it('meter: counts every scratch run since the proof started, not only tracked handles', async () => {
    // run 2 is no handle of pipegen's (another workflow, or one started late); run 3 was re-run: attempt 1's jobs count too
    const w = minutesWorld({ 1: [done('10:00:00', '10:02:00')], 2: [done('10:00:00', '10:03:00')], 3: [done('10:00:00', '10:01:00', 1), done('10:02:00', '10:04:00', 2)] });
    const m = new MinutesMeter(100, SINCE + 999);   // a start time with milliseconds: GitHub's filter takes whole seconds (rounded down)
    w.now = ms('10:30:00'); await m.add(w.gh, target());
    expect(m.used).toBe(2 + 3 + 1 + 2);
    const list = w.calls.filter((c) => c.method === 'GET' && c.url.pathname === `${R}/actions/runs`);
    expect(list).toHaveLength(1);
    // the proof start, widened by the clock-skew margin (rounded down to the second)
    expect(list[0]?.url.searchParams.get('created')).toBe('>=2026-11-04T09:50:00Z');
    expect(list[0]?.url.searchParams.has('head_sha')).toBe(false);
    expect(list[0]?.url.searchParams.has('event')).toBe(false);
    const jobs = w.calls.filter((c) => /\/actions\/runs\/\d+\/jobs$/.test(c.url.pathname));
    expect(jobs.map((c) => c.url.searchParams.get('filter'))).toEqual(['all', 'all', 'all']);
    // only GET requests: the meter writes nothing
    expect(w.calls.every((c) => c.method === 'GET')).toBe(true);
  });

  it('meter: an unreadable answer keeps the last count; three in a row stop the proof (fail closed)', async () => {
    const w = minutesWorld({ 1: [done('10:00:00', '10:02:00')] });
    const m = new MinutesMeter(100, SINCE);
    const t = target();
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.used).toBe(2);
    w.listStatus = 500;
    for (let i = 1; i < MINUTES_UNREAD_LIMIT; i++) {
      w.now = ms('10:30:00'); await m.add(w.gh, t);
      expect(m.blind).toBe(false);
    }
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.used).toBe(2);
    expect(m.blind).toBe(true);
    expect(m.problem).toMatch(/could not be read/);
    // one good read resets it
    w.listStatus = undefined;
    w.now = ms('10:30:00'); await m.add(w.gh, t);
    expect(m.blind).toBe(false);
    // a job list pipegen can't read, or a start time that isn't GitHub's form, is unreadable too
    for (const body of [{ total_count: 1, jobs: [{ id: 5, run_id: 99, name: 'x', status: 'completed', started_at: at('10:00:00'), completed_at: at('10:01:00') }] },
      { total_count: 1, jobs: [{ id: 5, run_id: 1, name: 'x', status: 'completed', started_at: 'yesterday', completed_at: at('10:01:00') }] }]) {
      w.jobsBody = body;
      w.now = ms('10:30:00'); await m.add(w.gh, t);
      expect(m.problem).toBe('the jobs of run 1 could not be read');
      expect(m.used).toBe(2);
      w.jobsBody = undefined;
      w.now = ms('10:30:00'); await m.add(w.gh, t);
      expect(m.problem).toBeNull();
    }
  });

  it('meter: a local clock ahead of GitHub still counts the proof\'s first runs (the window is widened)', async () => {
    // the proof start came from a clock 5 minutes ahead of GitHub's: run 1 was created at 10:01 by GitHub's clock
    const w = minutesWorld({ 1: [done('10:01:00', '10:03:00')], 2: [done('09:40:00', '09:45:00')] });
    w.created.set(1, at('10:01:00'));
    w.created.set(2, at('09:40:00'));   // well before the proof, outside the margin
    const m = new MinutesMeter(100, ms('10:06:00'));
    await m.add(w.gh, target());
    expect(m.used).toBe(2);
    expect(w.calls.find((c) => c.url.pathname === `${R}/actions/runs`)?.url.searchParams.get('created')).toBe(`>=${at('09:56:00')}`);
    expect(MINUTES_SKEW_MARGIN_MS).toBe(10 * 60_000);
  });

  it('meter: a local clock behind GitHub still counts running jobs up to GitHub\'s now', async () => {
    const local = vi.spyOn(Date, 'now').mockReturnValue(ms('10:00:00'));   // 30 minutes behind GitHub (WSL2 after a sleep)
    try {
      const w = minutesWorld({ 1: [{ status: 'in_progress', started_at: at('10:05:00'), completed_at: null }] });
      w.now = ms('10:30:00');
      const m = new MinutesMeter(100, SINCE);
      await m.add(w.gh, target());
      expect(m.used).toBe(25);
      expect(m.problem).toBeNull();
      // GitHub's later answers move "now" on: the jobs answer is newer than the list answer
      w.now = ms('10:40:00');
      await m.add(w.gh, target());
      expect(m.used).toBe(35);
    } finally {
      local.mockRestore();
    }
  });

  it('meter: no date header from GitHub → never under-counted, and the read counts as unreadable', async () => {
    const local = vi.spyOn(Date, 'now').mockReturnValue(ms('10:00:00'));   // a local clock behind
    try {
      const w = minutesWorld({ 1: [{ status: 'in_progress', started_at: at('10:05:00'), completed_at: null }, done('10:06:00', '10:20:00')] });
      w.now = null;
      const m = new MinutesMeter(100, SINCE);
      await m.add(w.gh, target());
      // "now" is the latest of this machine's clock and every time GitHub's answer shows: 10:20 → 15 + 14
      expect(m.used).toBe(29);
      expect(m.problem).toBe(`GitHub's answer about the runs of ${OWNER}/${SCRATCH} had no date, so its clock is unknown`);
      for (let i = 1; i < MINUTES_UNREAD_LIMIT; i++) await m.add(w.gh, target());
      expect(m.blind).toBe(true);   // GitHub always sends a date: without one, the meter stops the proof
      // a local clock ahead: counted up to it (more, never less)
      local.mockReturnValue(ms('10:40:00'));
      await m.add(w.gh, target());
      expect(m.used).toBe(35 + 14);
    } finally {
      local.mockRestore();
    }
  });

  it('meter: the proof start is GitHub\'s time; without a date header, this machine\'s minus the margin', async () => {
    const local = vi.spyOn(Date, 'now').mockReturnValue(ms('10:05:00'));
    try {
      const w = minutesWorld({});
      w.now = ms('10:00:00');
      expect(await proofStart(w.gh, target())).toEqual({ at: ms('10:00:00'), fromServer: true });
      w.now = null;
      expect(await proofStart(w.gh, target())).toEqual({ at: ms('10:05:00') - MINUTES_SKEW_MARGIN_MS, fromServer: false });
      expect(w.calls.every((c) => c.method === 'GET')).toBe(true);
    } finally {
      local.mockRestore();
    }
  });

  it('meter: restore adds the minutes a resumed run already used', async () => {
    const w = minutesWorld({ 1: [done('10:00:00', '10:02:00')] });
    const m = new MinutesMeter(10, SINCE);
    m.restore(8);
    w.now = ms('10:30:00'); await m.add(w.gh, target());
    expect(m.used).toBe(10);
    expect(m.exceeded).toBe(true);
    for (const bad of [-1, Number.NaN, '3' as unknown as number]) expect(() => m.restore(bad)).toThrow(/minutes/);
  });

  it('meter: minutesStop reads at most once a minute and stops at the cap', async () => {
    const w = minutesWorld({ 1: [{ status: 'in_progress', started_at: at('10:00:00'), completed_at: null }] });
    const m = new MinutesMeter(5, SINCE);
    const clock = fakeClock(ms('10:01:00'));
    const stop = minutesStop(w.gh, target(), m, { clock });
    w.now = ms('10:01:00');
    expect(await stop()).toBe(false);
    clock.t += 30_000;
    w.now = ms('10:04:30');
    expect(await stop()).toBe(false);
    expect(w.calls.filter((c) => c.url.pathname === `${R}/actions/runs`)).toHaveLength(1);   // 30 s later: not read again
    expect(m.used).toBe(1);
    clock.t = ms('10:05:00');
    w.now = ms('10:05:00');
    expect(await stop()).toBe(true);
    expect(m.used).toBe(5);
    // minutes it can't read, three times in a row, stop the proof too (fail closed)
    const blindWorld = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: (c) => (c.url.pathname === `${R}/actions/runs` ? { status: 500, body: {} } : undefined) });
    const blind = new MinutesMeter(5, SINCE);
    const c2 = fakeClock(ms('10:01:00'));
    const stop2 = minutesStop(blindWorld.gh, target(), blind, { clock: c2, everyMs: 1 });
    const said: boolean[] = [];
    for (let i = 0; i < MINUTES_UNREAD_LIMIT; i++) { c2.t += 1; said.push(await stop2()); }
    expect(said).toEqual([...Array.from({ length: MINUTES_UNREAD_LIMIT - 1 }, () => false), true]);
    expect(blind.used).toBe(0);
  });
});

describe('E6 force-cancel (S12)', () => {
  it('run: a run still going 30 s after its cancel is force-cancelled; one that stopped is not', async () => {
    const f = runsFake();
    f.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    f.plans.push['.github/workflows/b.yml'] = { steps: 1_000 };
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f.handler });
    const t = proofTarget(app(), { runId: '20261103-120000-abcdef' });
    f.pushed('proof/20261103-120000-abcdef/main', 'a'.repeat(40));
    const [stuck, ok] = f.runs;
    f.ignoreCancel.add(stuck?.id as number);
    const clock = fakeClock();
    const left: string[] = [];
    const out = await cancelRuns(g.gh, t, [stuck?.id as number, ok?.id as number], { clock, leftover: (x) => left.push(x) });
    expect(f.cancels.sort()).toEqual([stuck?.id, ok?.id].sort());
    expect(clock.sleeps).toEqual([FORCE_CANCEL_AFTER_MS]);
    expect(f.forceCancels).toEqual([stuck?.id]);
    expect([...out.values()]).toEqual([null, null]);
    expect(left).toEqual([]);
    // through the guarded write: the scratch repo only, POST …/force-cancel
    const forced = g.calls.filter((c) => c.url.pathname.endsWith('/force-cancel'));
    expect(forced.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([`POST ${R}/actions/runs/${stuck?.id}/force-cancel`]);
    // a force-cancel GitHub refuses is a leftover the user is told about
    const f2 = runsFake();
    f2.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    const g2 = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f2.handler });
    f2.pushed('proof/20261103-120000-abcdef/main', 'b'.repeat(40));
    const id = f2.runs[0]?.id as number;
    f2.ignoreCancel.add(id);
    f2.forceStatus = 500;
    const left2: string[] = [];
    const out2 = await cancelRuns(g2.gh, t, [id], { clock: fakeClock(), leftover: (x) => left2.push(x) });
    expect(out2.get(id)).toMatch(/HTTP 500/);
    expect(left2).toEqual([`run ${id} of ${OWNER}/${SCRATCH} could not be cancelled (HTTP 500); cancel it there`]);
    // a stop that begins during the 30 s: nothing more is sent (E8's cleanup cancels)
    const f3 = runsFake();
    f3.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    const g3 = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f3.handler });
    f3.pushed('proof/20261103-120000-abcdef/main', 'c'.repeat(40));
    const id3 = f3.runs[0]?.id as number;
    f3.ignoreCancel.add(id3);
    const c3 = fakeClock();
    c3.sleep = async (n: number) => { c3.sleeps.push(n); c3.t += n; vi.mocked(interrupting).mockReturnValue(true); };
    const before3 = g3.calls.length;
    await cancelRuns(g3.gh, t, [id3], { clock: c3 });
    expect(f3.forceCancels).toEqual([]);
    expect(g3.calls.slice(before3).map((c) => `${c.method} ${c.url.pathname}`)).toEqual([`POST ${R}/actions/runs/${id3}/cancel`]);   // nothing after the wait
    vi.mocked(interrupting).mockReturnValue(false);
    // a cancel GitHub refused is followed by the force-cancel all the same (the run may still be billed)
    const f4 = runsFake();
    f4.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    const g4 = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f4.handler });
    f4.pushed('proof/20261103-120000-abcdef/main', 'd'.repeat(40));
    const id4 = f4.runs[0]?.id as number;
    f4.cancelStatus = 500;
    const out4 = await cancelRuns(g4.gh, t, [id4], { clock: fakeClock() });
    expect(f4.forceCancels).toEqual([id4]);
    expect(out4.get(id4)).toBeNull();
  });

  it('run: waitForRuns force-cancels a run its stop could not cancel', async () => {
    const f = runsFake();
    f.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f.handler });
    const t = proofTarget(app(), { runId: '20261103-120000-abcdef' });
    const branch = 'proof/20261103-120000-abcdef/main';
    f.pushed(branch, 'a'.repeat(40));
    f.ignoreCancel.add(f.runs[0]?.id as number);
    const hs = await findRuns(g.gh, t, { headSha: 'a'.repeat(40), event: 'push', workflows: ['.github/workflows/pipegen.yml'], branch });
    const out = await waitForRuns(g.gh, t, hs, { timeoutMs: 60 * 60_000, clock: fakeClock(), shouldStop: async () => true });
    expect(out[0]).toMatchObject({ conclusion: 'cancelled', stopped: true });
    expect(f.forceCancels).toEqual([f.runs[0]?.id]);
  });
});

/** A provider that answers every call with the given usage. */
// "Tokens" in a property name is built at runtime (repo rule: no secret-like literals in test/).
const T = 'Tokens';
const paid = (): AiProvider => ({ name: 'claude', model: DEFAULT_MODEL, complete: async () => ({ data: {}, usage: Object.fromEntries([['input' + T, 1_000], ['output' + T, 100]]) as never }) });
const req = { system: 's', user: 'u', schemaName: 'x', jsonSchema: { type: 'object' }, timeoutMs: 1_000, ['maxOutput' + T]: 1_000 } as unknown as AiRequest;

describe('E6 a cap was reached (B4, S12)', () => {
  it('cap: either cap reached → runs cancelled, state saved, stopped with explanation', async () => {
    // the Actions minutes cap: the meter says so; the running runs of the scratch repo are cancelled, the state is saved
    const f = runsFake();
    f.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    f.plans.push['.github/workflows/other.yml'] = { steps: 1_000 };
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f.handler });
    const t = proofTarget(app(), { runId: '20261103-120000-abcdef' });
    f.pushed('proof/20261103-120000-abcdef/main', 'a'.repeat(40));
    const minutes = new MinutesMeter(120, SINCE);
    minutes.restore(120);
    const ai = new AiSpendMeter(paid(), 10);
    const reached = capReached({ minutes, ai });
    expect(reached).toEqual({ kind: 'actions-minutes', limit: 120 });
    const order: string[] = [];
    const saved: CapReached[] = [];
    const err = await stopAtCap(reached as CapReached, {
      cancelRuns: async () => { order.push('cancel'); return cancelActiveRuns(g.gh, t, SINCE, { clock: fakeClock() }); },
      saveState: async (c) => { order.push('save'); saved.push(c); },
      cleanup: async () => { order.push('cleanup'); },
    }).catch((e: unknown) => e);
    expect(order).toEqual(['cancel', 'save', 'cleanup']);
    expect(f.cancels.sort()).toEqual(f.runs.map((r) => r.id).sort());
    expect(saved).toEqual([{ kind: 'actions-minutes', limit: 120 }]);
    expect(err).toBeInstanceOf(CapReachedError);
    expect(err).toBeInstanceOf(ProofStopError);
    expect((err as CapReachedError).message).toBe('Actions minutes reached the limit of 120');
    expect((err as CapReachedError).problems).toEqual([]);

    // the AI cost cap: the meter's refusal (AiError cost-cap) is the trigger; the limit is the agreed cap
    const meter = new AiSpendMeter(paid(), 0.004);
    const stopped = await meter.provider.complete(req).catch((e: unknown) => e);
    expect(stopped).toBeInstanceOf(AiError);
    const aiCap = capReached({ minutes: new MinutesMeter(120, SINCE), ai: meter, error: stopped });
    expect(aiCap).toEqual({ kind: 'ai-cost', limitUsd: 0.004 });
    expect(capMessage({ kind: 'ai-cost', limitUsd: 12.5 })).toBe('AI cost reached the limit of $12.50, 2 × the estimate');
    const e2 = await stopAtCap(aiCap as CapReached, { cancelRuns: async () => {}, saveState: async () => {}, cleanup: async () => {} }).catch((e: unknown) => e);
    // a cap under a cent is shown with the digits that matter, never as $0.00 (review M4)
    expect((e2 as Error).message).toBe('AI cost reached the limit of $0.0040, 2 × the estimate');
    // no paid AI budget at all (a paid provider with no cap is a cap of 0): said as it is
    expect(capMessage({ kind: 'ai-cost', limitUsd: 0 })).toBe('No paid AI budget was agreed to (the AI cost limit is $0), so pipegen stopped before calling the AI');
    expect(capMessage({ kind: 'ai-cost', limitUsd: 0.0000123 })).toBe('AI cost reached the limit of $0.000012, 2 × the estimate');
    // no cap reached: nothing to stop; another AI error is not a cap
    expect(capReached({ minutes: new MinutesMeter(120, SINCE), ai: new AiSpendMeter(paid(), 10), error: new AiError('timeout', 'x') })).toBeNull();
    // minutes pipegen couldn't read three times in a row stop the proof too, with their own explanation
    const blind = new MinutesMeter(120, SINCE);
    const w = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: (c) => (c.url.pathname === `${R}/actions/runs` ? { status: 500, body: {} } : undefined) });
    for (let i = 0; i < MINUTES_UNREAD_LIMIT; i++) await blind.add(w.gh, t);
    const b = capReached({ minutes: blind, ai: new AiSpendMeter(paid(), 10) });
    expect(b).toMatchObject({ kind: 'actions-minutes', limit: 120, unread: true });
    expect(capMessage(b as CapReached)).toBe(`pipegen stopped before the Actions minutes limit of 120: it couldn't read the minutes used in ${SCRATCH}`);
  });

  it('cap: a cost-cap refusal a caller swallowed still stops the proof (the meter remembers it)', async () => {
    const meter = new AiSpendMeter(paid(), 0.004);
    expect(meter.refused).toBe(false);
    try {
      await meter.provider.complete(req);
    } catch {
      // a caller that turns the refusal into a note (discover.ts with continueWithoutAi)
    }
    expect(meter.exceeded).toBe(false);   // the next worst case didn't fit, but spent + reserved is below the cap
    expect(meter.refused).toBe(true);
    expect(capReached({ minutes: new MinutesMeter(120, SINCE), ai: meter })).toEqual({ kind: 'ai-cost', limitUsd: 0.004 });
    const err = await stopAtCap(capReached({ minutes: new MinutesMeter(120, SINCE), ai: meter }) as CapReached, { cancelRuns: async () => {}, saveState: () => {}, cleanup: () => {} }).catch((e: unknown) => e);
    expect((err as Error).message).toBe('AI cost reached the limit of $0.0040, 2 × the estimate');
    // only the meter's own refusal latches: an answer, a timeout or another AI error does not
    const ok = new AiSpendMeter(paid(), 10);
    await ok.provider.complete(req);
    const failing = new AiSpendMeter({ name: 'claude', model: DEFAULT_MODEL, complete: async () => { throw new AiError('timeout', 'x'); } }, 10);
    await failing.provider.complete(req).catch(() => {});
    expect([ok.refused, failing.refused]).toEqual([false, false]);
    expect(capReached({ minutes: new MinutesMeter(120, SINCE), ai: failing })).toBeNull();
  });

  it('cap: cancelActiveRuns cancels only runs still going, and fails loudly on a run it can\'t stop', async () => {
    const f = runsFake();
    f.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    f.plans.push['.github/workflows/done.yml'] = { steps: 1 };
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f.handler });
    const t = proofTarget(app(), { runId: '20261103-120000-abcdef' });
    f.pushed('proof/20261103-120000-abcdef/main', 'a'.repeat(40));
    const [going, finished] = f.runs;
    if (going === undefined || finished === undefined) throw new Error('two runs expected');
    finished.status = 'completed';
    finished.conclusion = 'success';
    expect(await cancelActiveRuns(g.gh, t, SINCE, { clock: fakeClock() })).toEqual([going.id]);
    expect(f.cancels).toEqual([going.id]);   // a finished run is left alone
    // a run that can't be stopped: a leftover, and an error stopAtCap names
    const f2 = runsFake();
    f2.plans.push['.github/workflows/pipegen.yml'] = { steps: 1_000 };
    const g2 = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: f2.handler });
    f2.pushed('proof/20261103-120000-abcdef/main', 'b'.repeat(40));
    f2.ignoreCancel.add(f2.runs[0]?.id as number);
    f2.forceStatus = 500;
    const left: string[] = [];
    await expect(cancelActiveRuns(g2.gh, t, SINCE, { clock: fakeClock(), leftover: (x) => left.push(x) })).rejects.toThrow(/could not be cancelled/);
    expect(left).toHaveLength(1);
  });

  it('cap: either cap → cleanup still runs', async () => {
    for (const cap of [{ kind: 'ai-cost', limitUsd: 3 }, { kind: 'actions-minutes', limit: 60 }] as CapReached[]) {
      for (const failing of ['cancel', 'save', 'both', 'cleanup']) {
        let cleaned = 0;
        let saved = 0;
        const err = await stopAtCap(cap, {
          cancelRuns: async () => { if (failing === 'cancel' || failing === 'both') throw new Error('cancel failed'); },
          saveState: () => { saved++; if (failing === 'save' || failing === 'both') throw new Error('disk full'); },
          cleanup: () => { cleaned++; if (failing === 'cleanup') throw new Error('cleanup failed'); },
        }).catch((e: unknown) => e);
        expect(cleaned, `${cap.kind} ${failing}`).toBe(1);
        expect(saved, `${cap.kind} ${failing}`).toBe(1);   // the state is saved even when the cancel failed
        expect(err).toBeInstanceOf(CapReachedError);
        expect((err as Error).message).toBe(capMessage(cap));
        const want = { cancel: ['the running runs could not all be cancelled'], save: ['the state could not be saved'], both: ['the running runs could not all be cancelled', 'the state could not be saved'], cleanup: ['the cleanup did not finish'] }[failing];
        expect((err as CapReachedError).problems).toEqual(want);
        expect((err as CapReachedError).causes).toHaveLength(want?.length ?? 0);
      }
    }
  });
});
