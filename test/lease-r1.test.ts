// v0.2 Plan G G-LEASE-R1 (fix round 1 of the lease carry, Plan V V5 security M5): the app lease without the state file (spec I1), kept
// while a stop is under way (sec M1), a stale takeover that checks it is still the holder (sec L1), the stop's way out for a reused
// process id (sec L2), and cleanupLeftovers deciding from the store whether it took the lease (sec I1).
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanupLeftovers } from '../src/proof/cleanup.js';
import { holdAppLease } from '../src/proof/lease.js';
import { StateError, StateStore } from '../src/proof/state.js';
import { quietIo } from './helpers/scratch-secrets.js';

// the stop gate is the test's (a real signal would end the test process)
const h = vi.hoisted(() => ({ stop: { now: false } }));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => h.stop.now,
}));
const { runExitHooks } = await import('../src/util/exit-hooks.js');

const APP = { owner: 'acme', repo: 'web' };
const OTHER = { owner: 'acme', repo: 'api' };
const RUN = '20261109-090000-abc123';
const homes: string[] = [];
const home = (): string => { const d = mkdtempSync(join(tmpdir(), 'pg-lease-r1-')); homes.push(d); return d; };
afterEach(() => {
  h.stop.now = false;
  for (const d of homes.splice(0)) rmSync(d, { recursive: true, force: true });
});
/** An Octokit that records every request and answers none (no network). */
const recordingGh = (calls: string[]) => ({
  request: async (route: string) => { calls.push(route); throw Object.assign(new Error('no network'), { status: 500 }); },
  hook: { wrap: () => {}, before: () => {}, after: () => {}, error: () => {} },
}) as never;
/** A pid that is not alive now. */
const deadPid = (): number => {
  for (let p = 4_000_000; p > 3_000_000; p -= 7919) { try { process.kill(p, 0); } catch (e) { if ((e as { code?: string }).code === 'ESRCH') return p; } }
  throw new Error('no dead pid found');
};
const TK = ['to', 'ken'].join('');
const leaseOf = (dir: string): Record<string, unknown> => JSON.parse(readFileSync(join(dir, 'lease.json'), 'utf8')) as Record<string, unknown>;

describe('G-LEASE-R1: the lease without the proof state (spec I1, sec I3)', () => {
  it('lease: holdAppLease takes the lease with a corrupt, a 0644 or a symlinked state.json beside it; the file is not read or changed', async () => {
    const d = home();
    const st = { home: d, env: {} };
    const s = await StateStore.open(APP, st);
    for (const bad of ['corrupt', '0644', 'symlink'] as const) {
      rmSync(s.path, { force: true });
      if (bad === 'symlink') { writeFileSync(join(d, 'elsewhere'), '{}', { mode: 0o600 }); symlinkSync(join(d, 'elsewhere'), s.path); }
      else writeFileSync(s.path, bad === 'corrupt' ? '{' : '{"version":1}', { mode: bad === '0644' ? 0o644 : 0o600 });
      if (bad === '0644') chmodSync(s.path, 0o644);
      await expect(StateStore.open(APP, st)).rejects.toThrow(StateError);   // what run and uninstall still stop on
      const release = await holdAppLease(APP, 'finish', { state: st });
      expect(leaseOf(s.dir).command).toBe('finish');
      release();
      expect(existsSync(join(s.dir, 'lease.json'))).toBe(false);
    }
    // the stop for another pipegen still names this repo, with no state loaded
    const other = await StateStore.openForLease(APP, st);
    other.acquireLease(RUN, 'uninstall');
    await expect(holdAppLease(APP, 'update', { state: st })).rejects.toThrow(/^Another pipegen \(`pipegen uninstall`, process \d+\) is working on acme\/web on this machine/);
    other.releaseLease();
  });

  it('lease: openForLease keeps the folder checks (a group-writable folder is a stop)', async () => {
    const d = home();
    mkdirSync(join(d, '.cache', 'pipegen'), { recursive: true, mode: 0o700 });
    chmodSync(join(d, '.cache', 'pipegen'), 0o770);
    await expect(holdAppLease(APP, 'finish', { state: { home: d, env: {} } })).rejects.toThrow(StateError);
  });

  it('state: every stop on the state file says what to do', async () => {
    const d = home();
    const st = { home: d, env: {} };
    const s = await StateStore.open(APP, st);
    const stops: string[] = [];
    const tryOpen = async (): Promise<void> => { await StateStore.open(APP, st).then(() => stops.push('(opened)'), (e: unknown) => stops.push((e as Error).message)); };
    writeFileSync(s.path, '{', { mode: 0o600 });
    await tryOpen();
    rmSync(s.path);
    symlinkSync(join(d, 'x'), s.path);
    await tryOpen();
    rmSync(s.path);
    mkdirSync(s.path);
    await tryOpen();
    rmSync(s.path, { recursive: true });
    writeFileSync(s.path, '{"version":1}', { mode: 0o644 });
    chmodSync(s.path, 0o644);
    await tryOpen();
    chmodSync(s.path, 0o600);
    await tryOpen();   // the wrong format
    expect(stops).toHaveLength(5);
    for (const m of stops) expect(m).toMatch(/(then run pipegen again|Delete it to start again|Fix it with: chmod 600)/);
  });
});

describe('G-LEASE-R1: the lease is kept while a stop is under way (sec M1)', () => {
  it('lease: a release while interrupting() is skipped; the exit hook drops the lease at the end of the hook phase', async () => {
    const d = home();
    const st = { home: d, env: {} };
    const release = await holdAppLease(APP, 'finish', { state: st });
    const dir = (await StateStore.openForLease(APP, st)).dir;
    h.stop.now = true;
    release();
    expect(existsSync(join(dir, 'lease.json'))).toBe(true);
    await expect(holdAppLease(APP, 'update', { state: st })).rejects.toThrow(/`pipegen finish`/);
    runExitHooks();
    expect(existsSync(join(dir, 'lease.json'))).toBe(false);
    h.stop.now = false;
    (await holdAppLease(APP, 'update', { state: st }))();
  });

  it('cleanup: cleanupLeftovers keeps the lease it took while a stop is under way', async () => {
    const d = home();
    const s = await StateStore.open(APP, { home: d, env: {} });
    s.begin(RUN, { ...APP, private: true, ownerType: 'User', defaultBranch: 'main' }, { cap: 10, aiCap: null });
    h.stop.now = true;
    await cleanupLeftovers(recordingGh([]), s, { canDeleteRepo: false, clock: { now: () => 0, sleep: async () => {} } as never, io: quietIo }).catch(() => undefined);
    expect(s.holdsLease()).toBe(true);
    runExitHooks();
    expect(existsSync(join(s.dir, 'lease.json'))).toBe(false);
  });
});

describe('G-LEASE-R1: a stale-lease takeover checks it is still the holder (sec L1)', () => {
  it('lease: two takers of one stale lease: only the last writer goes on, the other stops', async () => {
    const d = home();
    const st = { home: d, env: {} };
    const s0 = await StateStore.openForLease(APP, st);
    const file = join(s0.dir, 'lease.json');
    writeFileSync(file, JSON.stringify({ pid: deadPid(), host: hostname(), runId: 'old', [TK]: 'deadbeef', command: 'run' }), { mode: 0o600 });
    // B judged the same stale lease dead (the other process): it replaces A's fresh lease while A waits before its check
    const b = await StateStore.openForLease(APP, { ...st, alive: () => false, leaseSettle: () => {} });
    const a = await StateStore.openForLease(APP, { ...st, leaseSettle: () => { b.acquireLease('b', 'finish'); } });
    expect(() => { a.acquireLease('a', 'uninstall'); }).toThrow(/^Another pipegen took the lease .*lease\.json at the same time\. Wait for it to finish, then run pipegen again\.$/);
    expect(a.holdsLease()).toBe(false);
    expect(b.holdsLease()).toBe(true);
    expect(leaseOf(s0.dir).command).toBe('finish');
    // A's exit hook is not left behind to drop B's lease
    runExitHooks();
    expect(existsSync(file)).toBe(false);   // B's own hook dropped it (B's lease, token-checked)
  });

  it('lease: a stale takeover with no rival holds the lease after its check; a fresh take does not wait', async () => {
    const d = home();
    const st = { home: d, env: {} };
    let settles = 0;
    const a = await StateStore.openForLease(APP, { ...st, leaseSettle: () => { settles++; } });
    a.acquireLease('a', 'finish');
    expect(settles).toBe(0);
    a.releaseLease();
    writeFileSync(join(a.dir, 'lease.json'), JSON.stringify({ pid: deadPid(), host: hostname(), runId: 'old', [TK]: 'deadbeef' }), { mode: 0o600 });
    a.acquireLease('a', 'finish');
    expect(settles).toBe(1);
    expect(a.holdsLease()).toBe(true);
    a.releaseLease();
  });

  it('lease: a stale lease replaced between the read and the unlink is not unlinked', async () => {
    const d = home();
    const st = { home: d, env: {} };
    const s0 = await StateStore.openForLease(APP, st);
    const file = join(s0.dir, 'lease.json');
    const dead = deadPid();
    writeFileSync(file, JSON.stringify({ pid: dead, host: hostname(), runId: 'old', [TK]: 'deadbeef' }), { mode: 0o600 });
    // between this taker's read of the stale lease and its unlink, a live pipegen (this process, another store) takes it over
    const live = await StateStore.openForLease(APP, { ...st, alive: () => false, leaseSettle: () => {} });
    const t = await StateStore.openForLease(APP, { ...st, alive: (pid) => { if (pid === dead) live.acquireLease('live', 'uninstall'); return pid === dead ? false : true; } });
    expect(() => { t.acquireLease('t', 'finish'); }).toThrow(/`pipegen uninstall`/);
    expect(live.holdsLease()).toBe(true);
    expect(leaseOf(s0.dir).command).toBe('uninstall');
    live.releaseLease();
  });
});

describe('G-LEASE-R1: the stop names the way out when the process id was reused (sec L2)', () => {
  it('lease: "If process N is not pipegen, remove <lease file> and run pipegen again"', async () => {
    const d = home();
    const s = await StateStore.openForLease(APP, { home: d, env: {} });
    const file = join(s.dir, 'lease.json');
    writeFileSync(file, JSON.stringify({ pid: process.ppid, host: hostname(), runId: 'x', [TK]: 't', command: 'finish' }), { mode: 0o600 });
    expect(() => { s.acquireLease(RUN, 'update'); }).toThrow(`If process ${process.ppid} is not pipegen, remove ${file} and run pipegen again.`);
  });
});

describe('G-LEASE-R1: cleanupLeftovers decides from the store whether it took the lease (sec I1)', () => {
  it('cleanup: a state file of another app in this folder: the caller\'s lease stays held', async () => {
    const d = home();
    const st = { home: d, env: {} };
    const sb = await StateStore.open(OTHER, st);
    sb.begin(RUN, { ...OTHER, private: true, ownerType: 'User', defaultBranch: 'main' }, { cap: 10, aiCap: null });
    const sa0 = await StateStore.open(APP, st);
    copyFileSync(sb.path, sa0.path);
    chmodSync(sa0.path, 0o600);
    const sa = await StateStore.open(APP, st);
    expect(sa.state?.app.repo).toBe('api');
    sa.acquireLease('uninstall-x', 'uninstall');
    await cleanupLeftovers(recordingGh([]), sa, { canDeleteRepo: false, clock: { now: () => 0, sleep: async () => {} } as never, io: quietIo }).catch(() => undefined);
    expect(sa.holdsLease()).toBe(true);
    expect(existsSync(join(sa.dir, 'lease.json'))).toBe(true);
    sa.releaseLease();
  });
});
