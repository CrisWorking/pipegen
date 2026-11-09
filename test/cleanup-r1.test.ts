// E8 fix round 1 (review-E8.md I-1..I-7, M-1..M-7): the cleanup on every ending, the secrets before any wait, per-item
// failures as leftovers, cleanupDone, a deleted or missing scratch repo, the meters on every ending, case-insensitive
// `secrets`, and the minors. Same fakes as test/cleanup.test.ts. No network.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AiSpendMeter, isCostCap } from '../src/ai/spend-meter.js';
import { cleanupCommand } from '../src/cli/cleanup.js';
import type { CliIO } from '../src/cli/io.js';
import { SecretVault } from '../src/create/secrets.js';
import { CapReachedError, stopAtCap } from '../src/proof/caps.js';
import { cleanupAfterProof, cleanupLeftovers, minutesForResume, proveThenClean, restoreAiSpend, saveStopState, type CleanupOptions } from '../src/proof/cleanup.js';
import { trackWrite } from '../src/proof/inflight.js';
import { ScratchKeys, workflowSecretNames } from '../src/proof/keys.js';
import { MinutesMeter } from '../src/proof/minutes.js';
import { StateError, StateStore } from '../src/proof/state.js';
import { proofTarget, type ProofTarget } from '../src/proof/target.js';
import { makeOctokit } from '../src/github/client.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage } from '../src/types.js';
import { cleanupWorld } from './helpers/cleanup-github.js';
import { app, OWNER, quietIo, SCRATCH } from './helpers/scratch-secrets.js';
import { fake } from './helpers/secret-repo.js';

const RUN = '20261104-090000-abc123';
const R = `/repos/${OWNER}/${SCRATCH}`;
const REAL = ['sk', 'test', '51RealKeyTypedByTheUser0000'].join('_');   // built at runtime (no-secret-literals)
const LIST = ['sec', 'rets'].join('');
const ENV_VAR = 'GITHUB_TOKEN';
const T = 'Tokens';
const dirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const home = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'pg-e8r1-'));
  dirs.push(d);
  return d;
};
const instant = { now: () => 0, sleep: async () => {} };
let nextId = 78_000;

interface Setup { w: ReturnType<typeof cleanupWorld>; t: ProofTarget; store: StateStore; keys: ScratchKeys; vault: SecretVault; h: string; repoId: number }
async function setup(o: { created?: boolean } = {}): Promise<Setup> {
  const repoId = nextId++;
  const w = cleanupWorld({}, Object.fromEntries([['STRIPE_SECRET_KEY', REAL]]), repoId);
  w.f.runs.push({ id: 11, status: 'completed', minutes: 4 }, { id: 12, status: 'in_progress', minutes: 3 });
  w.f.branches.add(`proof/${RUN}/main`);
  w.f.prs.push({ number: 3, head: `proof/${RUN}/main`, state: 'open' });
  const t = proofTarget(app(), { runId: RUN });
  const h = home();
  const store = await StateStore.open(app(), { home: h, env: {} });
  store.begin(RUN, app(), { cap: 100, aiCap: 1 });
  for (const s of ['planned', 'debated', 'created', 'proving'] as const) store.setStage(s);
  store.markArmed(true);
  store.recordSecretNames(['STRIPE_SECRET_KEY']);
  store.recordBranch('scratch', `proof/${RUN}/main`, 'main');
  if (o.created !== false) store.scratchCreated(repoId);
  const vault = new SecretVault();
  vault.set('STRIPE_SECRET_KEY', REAL);
  const keys = new ScratchKeys(w.g.gh, t, vault, { io: quietIo });
  return { w, t, store, keys, vault, h, repoId };
}
const clean = (e: Setup, canDeleteRepo: boolean, extra: Partial<CleanupOptions> = {}) =>
  cleanupAfterProof(e.w.g.gh, e.t, e.store, e.keys, { canDeleteRepo, clock: instant, settleMs: 0, ...extra });
const writes = (e: Setup): string[] => e.w.g.writes().map((c) => `${c.method} ${decodeURIComponent(c.url.pathname).replace(R, '')}`);
const provider = (): AiProvider & { sent: number } => {
  const p = { name: 'claude' as const, model: DEFAULT_MODEL, sent: 0, complete: async () => { p.sent++; return { data: {}, usage: Object.fromEntries([['input' + T, 10], ['output' + T, 10]]) as unknown as AiUsage }; } };
  return p;
};
const request = { system: 's', user: 'u', schemaName: 'x', jsonSchema: { type: 'object' }, timeoutMs: 1_000, ['maxOutput' + T]: 100 } as unknown as AiRequest;

describe('E8 fix round 1: the cleanup runs on every ending (I-1)', () => {
  it('proveThenClean: prove returns while the stage is stopped (a cap stop that returned) → the cleanup still runs, the outcome comes back', async () => {
    const e = await setup();
    const out = await proveThenClean(e.store, async () => { e.store.setStage('stopped', { stoppedBy: 'ai-cost' }); return 'stopped outcome'; }, () => clean(e, false));
    expect(out.outcome).toBe('stopped outcome');
    expect(e.w.s.values.size).toBe(0);
    expect(e.store.load()).toMatchObject({ stage: 'stopped', stoppedBy: 'ai-cost' });
  });

  it('proveThenClean: a state write that fails never skips the cleanup (success and failure paths)', async () => {
    const e = await setup();
    vi.spyOn(e.store, 'update').mockImplementation(() => { throw new StateError('disk full'); });
    const out = await proveThenClean(e.store, async () => 'ok', () => clean(e, false));
    expect(out.outcome).toBe('ok');
    expect(e.w.s.values.size).toBe(0);
    expect([...e.w.f.branches]).toEqual([]);
    const f = await setup();
    vi.spyOn(f.store, 'update').mockImplementation(() => { throw new StateError('disk full'); });
    await expect(proveThenClean(f.store, async () => { throw new Error('the proof failed'); }, () => clean(f, false))).rejects.toThrow('the proof failed');
    expect(f.w.s.values.size).toBe(0);
  });
});

describe('E8 fix round 1: secrets before any wait (I-2)', () => {
  it('cleanup: secrets deleted before waiting on in-flight writes; a store that lands late is deleted by a second pass', async () => {
    const e = await setup();
    let landPush!: () => void;
    const push = trackWrite('push of proof/x', () => new Promise<void>((ok) => { landPush = ok; }));
    let landStore!: () => void;
    const store = trackWrite('store of LATE_KEY', () => new Promise<void>((ok) => { landStore = () => { e.w.s.values.set('LATE_KEY', 'x'); ok(); }; }));
    const p = clean(e, false, { settleMs: 5_000 });
    await new Promise((ok) => setTimeout(ok, 30));
    // the user's key is already deleted while the push is still in flight
    expect(writes(e)).toContain(`DELETE /actions/${LIST}/STRIPE_SECRET_KEY`);
    expect(e.w.s.values.has('STRIPE_SECRET_KEY')).toBe(false);
    landStore();
    landPush();
    await Promise.all([push, store]);
    const res = await p;
    expect(e.w.s.values.size).toBe(0);   // LATE_KEY landed after the first pass: the second pass deleted it
    expect(writes(e)).toContain(`DELETE /actions/${LIST}/LATE_KEY`);
    expect(res.leftovers).toEqual([]);
  });
});

describe('E8 fix round 1: secrets before ScratchKeys\' own stores (I-2)', () => {
  it('cleanup: the first pass doesn\'t wait for a key store in flight; the second deletes what it stored', async () => {
    const e = await setup();
    // a client whose secret PUTs hang until released: a real-key store is in flight when the cleanup starts
    let release!: () => void;
    const gate = new Promise<void>((ok) => { release = ok; });
    let putting = false;
    const gated = (async (input: string | URL | Request, init?: RequestInit) => {
      if ((init?.method ?? 'GET').toUpperCase() === 'PUT' && String(input instanceof Request ? input.url : input).includes(`/actions/${LIST}/`)) { putting = true; await gate; }
      return e.w.g.fetch(input, init);
    }) as typeof fetch;
    const gh2 = makeOctokit(fake.githubPat(), { fetch: gated, log: () => {} });
    const keys2 = new ScratchKeys(gh2, e.t, e.vault, { io: quietIo });
    const storing = keys2.real(['STRIPE_SECRET_KEY']).catch(() => {});
    for (let i = 0; i < 200 && !putting; i++) await new Promise((ok) => setTimeout(ok, 5));
    expect(putting).toBe(true);
    const before = e.w.g.calls.length;
    const p = cleanupAfterProof(e.w.g.gh, e.t, e.store, keys2, { canDeleteRepo: false, clock: instant, settleMs: 0 });
    await new Promise((ok) => setTimeout(ok, 150));
    expect(e.w.g.calls.slice(before).some((c) => c.method === 'DELETE' && c.url.pathname.includes(`/actions/${LIST}/`))).toBe(true);
    release();
    await storing;
    await p;
    expect(e.w.s.values.size).toBe(0);
  });
});

describe('E8 fix round 1: a per-item failure is a leftover, never an abort (I-3)', () => {
  it('cleanup: a listed branch name pipegen won\'t send is a leftover; the rest of the emptying still runs', async () => {
    const e = await setup();
    e.w.f.branches.add('proof/a+b');
    e.store.recordBranch('central', `proof/${RUN}`, 'main');
    e.w.f.central.add(`proof/${RUN}`);
    e.w.s.variables = [{ name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-04' }, { name: 'bad-name', value: 'x' }];   // a listed name the guard won't send either
    const res = await clean(e, false);
    expect(res.leftovers.some((l) => l.includes('proof/a+b') && /won't send|delete it there/.test(l))).toBe(true);
    expect(res.leftovers.some((l) => l.includes('bad-name'))).toBe(true);
    expect(e.w.f.runs).toEqual([]);
    expect(e.w.s.variables).toEqual([{ name: 'bad-name', value: 'x' }]);
    expect(e.w.f.defaultHead).toBe('e'.repeat(40));
    expect(e.w.f.central.size).toBe(0);
    expect(e.store.load()?.leftovers).toEqual(res.leftovers);
  });
});

describe('E8 fix round 1: cleanupDone and a deleted or missing repo (I-4, I-5)', () => {
  it('state: cleanupDone is reset when a resumed proof records again or moves into proving (killed without hooks → begin stops)', async () => {
    const e = await setup();
    e.store.setStage('interrupted');
    await clean(e, false);
    expect(e.store.load()?.cleanupDone).toBe(true);
    // resume: back into proving, then a central branch, then killed without any hook
    e.store.setStage('proving');
    expect(e.store.load()?.cleanupDone).toBe(false);
    e.store.update((s) => { s.cleanupDone = true; });
    e.store.recordBranch('central', `proof/${RUN}`, 'main');
    expect(e.store.load()?.cleanupDone).toBe(false);
    const again = await StateStore.open(app(), { home: e.h, env: {} });
    expect(() => again.begin('20261105-090000-abc124', app(), { cap: 10, aiCap: 1 })).toThrow(/pipegen cleanup first/);
    // each record resets it
    for (const rec of [() => e.store.recordPr(`proof/${RUN}/main`), () => e.store.recordSecretNames(['X']), () => e.store.scratchCreated(e.repoId)]) {
      e.store.update((s) => { s.cleanupDone = true; });
      rec();
      expect(e.store.load()?.cleanupDone, String(rec)).toBe(false);
    }
  });

  it('cleanup: a confirmed repo delete drops that repo\'s leftovers; pipegen cleanup on the deleted repo settles, and says nothing is left', async () => {
    const e = await setup();
    e.w.f.fail.set('POST /actions/runs/12/cancel', 500);
    e.w.f.fail.set('POST /actions/runs/12/force-cancel', 500);
    const res = await clean(e, true);
    expect(res.repoDeleted).toBe(true);
    expect(res.leftovers).toEqual([]);
    expect(e.store.load()).toMatchObject({ leftovers: [], cleanupDone: true, scratchDeleted: true });
    // pipegen cleanup again (another process): the repo is gone (404, id gone): no false leftover, nothing sent to it
    const store2 = await StateStore.open(app(), { home: e.h, env: {} });
    const before = e.w.g.calls.length;
    const r2 = await cleanupLeftovers(e.w.g.gh, store2, { canDeleteRepo: true, clock: instant, io: quietIo });
    expect(r2.leftovers).toEqual([]);
    expect(e.w.g.calls.slice(before).filter((c) => c.method !== 'GET')).toEqual([]);
    expect(store2.load()?.cleanupDone).toBe(true);
    const next = await StateStore.open(app(), { home: e.h, env: {} });
    expect(next.begin('20261105-090000-abc124', app(), { cap: 10, aiCap: 1 }).runId).toBe('20261105-090000-abc124');
  });

  it('cli: cleanup with nothing left says so without touching GitHub', async () => {
    const e = await setup();
    await clean(e, true);
    const repo = home();
    mkdirSync(join(repo, '.git'));
    writeFileSync(join(repo, '.git', 'config'), `[remote "origin"]\n\turl = https://github.com/${OWNER}/shop.git\n`);
    const out: string[] = [];
    const before = e.w.g.calls.length;
    const io: CliIO = { ...quietIo, out: (s) => out.push(s), err: () => {}, env: { [ENV_VAR]: fake.githubPat(), XDG_CACHE_HOME: join(e.h, '.cache') }, cwd: repo, fetch: e.w.g.fetch };
    expect(await cleanupCommand(repo, io, { allowBroad: false })).toBe(0);
    expect(out.join('\n')).toMatch(/Nothing is left behind/);
    expect(e.w.g.calls.length).toBe(before);
  });

  it('cleanup: a scratch repo pipegen can\'t see (404, not deleted by pipegen) is one leftover, no false "copy of your code"; pipegen cleanup asks, Yes settles it', async () => {
    const e = await setup();
    e.w.f.deleted = true;   // gone (by hand), or the token lost access: 404 either way
    const res = await clean(e, false);
    expect(res.scratchMissing).toBe(true);
    expect(res.leftovers).toHaveLength(1);
    expect(res.leftovers[0]).toMatch(/can't see .*pipegen-proof-shop/);
    expect(res.leftovers.join('\n')).not.toMatch(/copy of your code/);
    const repo = home();
    mkdirSync(join(repo, '.git'));
    writeFileSync(join(repo, '.git', 'config'), `[remote "origin"]\n\turl = https://github.com/${OWNER}/shop.git\n`);
    const asked: string[] = [];
    const io: CliIO = { ...quietIo, prompt: { ...quietIo.prompt, confirm: async (q: string, d?: boolean) => { asked.push(`${q} ${String(d)}`); return true; } }, out: () => {}, err: () => {},
      env: { [ENV_VAR]: fake.githubPat(), XDG_CACHE_HOME: join(e.h, '.cache') }, cwd: repo, fetch: e.w.g.fetch };
    expect(await cleanupCommand(repo, io, { allowBroad: false })).toBe(0);
    expect(asked).toHaveLength(1);
    expect(asked[0]).toMatch(/delete .*pipegen-proof-shop.* false$/);   // default No
    const st = (await StateStore.open(app(), { home: e.h, env: {} })).state;
    expect(st).toMatchObject({ leftovers: [], cleanupDone: true, scratchDeleted: true });
    // No: the leftover stays, exit 1
    const f = await setup();
    f.w.f.deleted = true;
    const io2: CliIO = { ...io, env: { ...io.env, XDG_CACHE_HOME: join(f.h, '.cache') }, fetch: f.w.g.fetch, prompt: quietIo.prompt };
    expect(await cleanupCommand(repo, io2, { allowBroad: false })).toBe(1);
    expect((await StateStore.open(app(), { home: f.h, env: {} })).state?.leftovers).toHaveLength(1);
  });
});

describe('E8 fix round 1: the meters on every ending (I-6, M-4)', () => {
  it('cleanup: meters saved before the runs are deleted; cap stop → resume → the restored spend still refuses', async () => {
    const e = await setup();
    const minutes = new MinutesMeter(100, Date.UTC(2026, 10, 4, 9, 0, 0));
    minutes.restore(17);
    const ai = new AiSpendMeter(provider(), 1);
    ai.restore(1);
    const meters = () => ({ minutes, ai, fromServer: true });
    const cap = { kind: 'ai-cost' as const, limitUsd: 1 };
    const cleanup = () => clean(e, false, { meters });
    await expect(proveThenClean(e.store, () => stopAtCap(cap, { cancelRuns: async () => {}, saveState: saveStopState(e.store, meters), cleanup }), cleanup)).rejects.toThrow(CapReachedError);
    const saved = e.store.load();
    expect(saved).toMatchObject({ stage: 'stopped', stoppedBy: 'ai-cost', aiCostUsd: 1, runsDeleted: true, proofStart: { at: Date.UTC(2026, 10, 4, 9, 0, 0), fromServer: true } });
    expect(saved?.minutesUsed).toBeGreaterThanOrEqual(17 + 4 + 3);   // what it had, plus the runs it measured before deleting them
    // resume: the minutes come back (the runs are gone), and the AI spend refuses again
    const m2 = await minutesForResume(e.w.g.gh, e.t, saved as never);
    expect(m2.used).toBe(saved?.minutesUsed);
    const p = provider();
    const ai2 = new AiSpendMeter(p, 1);
    restoreAiSpend(ai2, saved as never);
    expect(isCostCap(await ai2.provider.complete(request).catch((x: unknown) => x))).toBe(true);
    expect(p.sent).toBe(0);
  });

  it('cleanup: with no meter (pipegen cleanup after a kill) the minutes are measured before the runs are deleted; unmeasurable → the cap', async () => {
    const e = await setup();
    e.store.saveMeters({ minutes: { used: 2, since: Date.UTC(2026, 10, 4, 9, 0, 0), fromServer: true } });
    await clean(e, false);
    expect(e.store.load()?.minutesUsed).toBe(4 + 3);
    const f = await setup();
    f.store.saveMeters({ minutes: { used: 2, since: Date.UTC(2026, 10, 4, 9, 0, 0), fromServer: true } });
    f.w.f.unreadable.add('runs');
    await clean(f, false);
    expect(f.store.load()?.minutesUsed).toBe(100);   // unknown spend counts as the whole cap: a resume never gets a fresh budget
  });

  it('cleanup: the meters are on disk before the first GitHub write of the cleanup; a cap stop saves them before its cleanup', async () => {
    const e = await setup();
    const minutes = new MinutesMeter(100, 1_000);
    minutes.restore(9);
    const ai = new AiSpendMeter(provider(), 5);
    ai.restore(0.5);
    let atFirstWrite: unknown = null;
    const orig = e.w.f.handler;
    e.w.f.handler = (c) => { if (atFirstWrite === null && c.method !== 'GET') atFirstWrite = e.store.load(); return orig(c); };
    await clean(e, false, { meters: () => ({ minutes, ai, fromServer: true }) });
    expect(atFirstWrite).toMatchObject({ minutesUsed: 9, aiCostUsd: 0.5, proofStart: { at: 1_000, fromServer: true } });
    // stopAtCap's saveState: the meters, then the stage
    const f = await setup();
    const m2 = new MinutesMeter(100, 1_000);
    m2.restore(9);
    saveStopState(f.store, () => ({ minutes: m2, ai }))({ kind: 'actions-minutes', limit: 100 });
    expect(f.store.load()).toMatchObject({ stage: 'stopped', stoppedBy: 'actions-minutes', minutesUsed: 9, aiCostUsd: 0.5 });
  });

  it('state: saveMeters records a start as from GitHub only when told so (M-4)', async () => {
    const e = await setup();
    e.store.saveMeters({ minutes: { used: 0, since: 5 } });
    expect(e.store.load()?.proofStart).toEqual({ at: 5, fromServer: false });
  });
});

describe('E8 fix round 1: `secrets` in any letter case (I-7)', () => {
  it('keys: workflowSecretNames matches secrets in any letter case; unreadable forms fail closed', () => {
    const up = LIST.toUpperCase();
    const cap = 'S' + LIST.slice(1);
    expect(workflowSecretNames([{ content: `env:\n  K: \${{ ${up}.ORG_KEY }}\n  L: \${{ ${cap}.other_key }}\n  M: \${{ ${cap}["third"] }}\n` }])).toEqual(['ORG_KEY', 'OTHER_KEY', 'THIRD']);
    expect(workflowSecretNames([{ content: `run: echo \${{ ${up}[env.N] }}` }])).toBeNull();
    expect(workflowSecretNames([{ content: `run: echo \${{ toJSON(${cap}) }}` }])).toBeNull();
  });
});

describe('E8 fix round 1: minors', () => {
  it('cli: cleanup refuses a saved state for another repo than the origin (M-1)', async () => {
    const e = await setup();
    e.store.update((s) => { s.app = { ...s.app, repo: 'other' }; });
    const repo = home();
    mkdirSync(join(repo, '.git'));
    writeFileSync(join(repo, '.git', 'config'), `[remote "origin"]\n\turl = https://github.com/${OWNER}/Shop.git\n`);
    const errs: string[] = [];
    const io: CliIO = { ...quietIo, out: () => {}, err: (s) => errs.push(s), env: { [ENV_VAR]: fake.githubPat(), XDG_CACHE_HOME: join(e.h, '.cache') }, cwd: repo, fetch: e.w.g.fetch };
    const before = e.w.g.calls.length;
    expect(await cleanupCommand(repo, io, { allowBroad: false })).toBe(1);
    expect(errs.join('\n')).toMatch(/saved proof state is for CrisWorking\/other, not CrisWorking\/Shop/);
    expect(e.w.g.calls.length).toBe(before);
  });

  it('cleanup: a lease the caller already holds (uninstall\'s run 2) stays held after cleanupLeftovers (Plan V M5: no gap); one it took is given back', async () => {
    const e = await setup();
    const store2 = await StateStore.open(app(), { home: e.h, env: {} });
    store2.acquireLease('uninstall-x', 'uninstall');
    await cleanupLeftovers(e.w.g.gh, store2, { canDeleteRepo: false, clock: instant, io: quietIo });
    expect(store2.holdsLeaseFor(app())).toBe(true);
    const probe = await StateStore.open(app(), { home: e.h, env: {} });
    expect(() => { probe.acquireLease('probe', 'finish'); }).toThrow(/Another pipegen \(`pipegen uninstall`, process \d+\)/);
    store2.releaseLease();
    // a cleanup that took the lease itself gives it back
    const store3 = await StateStore.open(app(), { home: e.h, env: {} });
    await cleanupLeftovers(e.w.g.gh, store3, { canDeleteRepo: false, clock: instant, io: quietIo });
    expect(store3.holdsLeaseFor(app())).toBe(false);
    probe.acquireLease('after', 'finish');
    probe.releaseLease();
  });

  it('state: an unreadable lease is a stop naming the file, never taken over (M-2)', async () => {
    const e = await setup();
    writeFileSync(join(e.store.dir, 'lease.json'), 'not json', { mode: 0o600 });
    const s = await StateStore.open(app(), { home: e.h, env: {}, alive: () => false });
    expect(() => s.acquireLease(RUN)).toThrow(/lease .*lease\.json can't be read/);
  });

  it('state: recordSecretNames needs the cleanup armed (M-3)', async () => {
    const store = await StateStore.open(app(), { home: home(), env: {} });
    store.begin(RUN, app(), { cap: 10, aiCap: 1 });
    expect(() => store.recordSecretNames(['X'])).toThrow(/before its cleanup is registered/);
    store.markArmed(true);
    expect(() => store.requireArmed('create a repo')).not.toThrow();
    store.recordSecretNames(['X']);
    expect(store.state?.secretNames).toEqual(['X']);
  });

  it('cleanup: runs listed again after the deletes; a 409 on a run delete is a leftover (M-5)', async () => {
    const e = await setup();
    e.w.f.fail.set('DELETE /actions/runs/11', 409);
    const res = await clean(e, false);
    expect(res.leftovers).toContain(`run 11 of ${OWNER}/${SCRATCH} could not be deleted (HTTP 409); delete it there (its logs and artifacts go with it)`);
    // a delete GitHub answers OK but doesn't do: found by the second list
    const f = await setup();
    f.w.f.keepRuns.add(11);
    const r2 = await clean(f, false);
    expect(r2.leftovers).toContain(`run 11 of ${OWNER}/${SCRATCH} is still there; delete it there (its logs and artifacts go with it)`);
  });

  it('cleanup: code scanning analyses deleted newest-first along next / confirm urls (M-6)', async () => {
    const e = await setup();
    e.w.f.analyses = [70, 71, 72];   // listed oldest first; only the newest is deletable
    const res = await clean(e, false);
    expect(e.w.f.analyses).toEqual([]);
    expect(res.leftovers).toEqual([]);
    const order = e.w.g.calls.filter((c) => c.method === 'DELETE' && c.url.pathname.includes('/code-scanning/analyses/')).map((c) => Number(c.url.pathname.split('/').pop()));
    expect(order).toEqual([72, 71, 70]);
  });

  it('cleanup: a token refused while deleting the secrets is recorded before the stop (M-7)', async () => {
    const e = await setup();
    e.w.s.listStatus = 401;
    await expect(clean(e, false)).rejects.toThrow();
    expect(e.store.load()?.leftovers.some((l) => /secrets of .*pipegen-proof-shop may still be there/.test(l))).toBe(true);
  });
});
