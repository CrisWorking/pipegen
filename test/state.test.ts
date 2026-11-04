// Plan E Task 7 / E8 (rulings S20, B2, S3; carries E0b, E1-R4, E4-R4, E6, E7-R14): the proof's state file, the stages,
// resume, recording before making, the Ctrl-C hooks and the lease. The state file lives in a temp home. The SIGINT test
// runs a child node process (the child is bundled from test/fixtures/e8-sigint-child.ts with esbuild). No network.
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { build } from 'esbuild';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AiSpendMeter, isCostCap } from '../src/ai/spend-meter.js';
import { SecretVault } from '../src/create/secrets.js';
import { minutesForResume, restoreAiSpend } from '../src/proof/cleanup.js';
import { capReached } from '../src/proof/caps.js';
import { PLACEHOLDER_PREFIX, workflowSecretNames } from '../src/proof/keys.js';
import { MinutesMeter } from '../src/proof/minutes.js';
import { proveVariant } from '../src/proof/run.js';
import {
  loadState, nextStage, proofTransport, prRecorder, recordingTransport, saveState, STAGE_ORDER, StateError, StateStore, type RunState, type Stage,
} from '../src/proof/state.js';
import { assertCentral, assertScratch, proofTarget } from '../src/proof/target.js';
import { writesInFlight } from '../src/proof/inflight.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage, type PipelineDraft } from '../src/types.js';
import { world } from './helpers/proof-github.js';
import { runsFake } from './helpers/proof-runs.js';
import { app, OWNER, SCRATCH } from './helpers/scratch-secrets.js';

const RUN = '20261104-090000-abc123';
const REAL = ['sk', 'test', '51RealKeyTypedByTheUser0000'].join('_');   // built at runtime (no-secret-literals)
const GHP = ['ghp', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('_');
// names kept out of `name: value` shapes (no-secret-literals)
const TOK = ['tok', 'ens'].join('') as 'tokens';
const LIST = ['sec', 'rets'].join('');
const T = 'Tokens';
const dirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const home = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'pg-e8s-'));
  dirs.push(d);
  return d;
};
const open = async (h = home(), deps: Parameters<typeof StateStore.open>[1] = {}) => StateStore.open(app(), { home: h, env: {}, ...deps });
const draft = (): PipelineDraft => ({
  profile: { owner: OWNER, repo: 'shop' }, capabilities: {}, needs: [], steps: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [],
  requireDeployApproval: false, skipped: [], suggestions: [],
  created: [
    { path: 'docker-compose.yml', content: 'services: {}\n', part: 'compose', reason: 'the app', repo: 'app', aiEdited: true },
    { path: 'Dockerfile', content: 'FROM node:24\n', part: 'docker', reason: 'image', repo: 'app' },
  ],
} as unknown as PipelineDraft);

describe('E8 state file', () => {
  it('state: round-trip without secret values', async () => {
    const vault = new SecretVault();
    vault.set('STRIPE_SECRET_KEY', REAL);
    const h = home();
    const store = await open(h, { vault, [TOK]: [GHP] });
    store.begin(RUN, app(), { cap: 140, aiCap: 1.5, draft: draft() });
    store.markArmed(true);
    store.recordBranch('scratch', `proof/${RUN}/main`, 'main');
    store.recordBranch('central', `proof/${RUN}`, 'main');
    store.recordPr(`proof/${RUN}/main`);
    store.recordPr(`proof/${RUN}/main`, 7);
    store.recordSecretNames(['STRIPE_SECRET_KEY', 'DATABASE_URL']);
    store.scratchCreated(4242);
    store.saveMeters({ minutes: { used: 12, since: Date.UTC(2026, 10, 4, 9, 0, 0) }, aiUsedUsd: 0.25 });
    store.record('run 9 of CrisWorking/pipegen-proof-shop could not be cancelled (HTTP 500); cancel it there');
    const saved = await loadState(app(), { home: h, env: {} });
    expect(saved).toEqual(store.state);
    expect(saved).toMatchObject({
      runId: RUN, stage: 'consented', branches: [{ repo: 'scratch', ref: `proof/${RUN}/main` }, { repo: 'central', ref: `proof/${RUN}` }],
      prs: [{ head: `proof/${RUN}/main`, number: 7 }], scratchRepoId: 4242, minutesUsed: 12, aiCostUsd: 0.25,
      proofStart: { at: Date.UTC(2026, 10, 4, 9, 0, 0), fromServer: false },   // not said to be GitHub's clock (fix round 1, M-4)
    });
    expect(saved?.secretNames).toEqual(['DATABASE_URL', 'STRIPE_SECRET_KEY']);
    const text = readFileSync(store.path, 'utf8');
    expect(text).not.toContain(REAL);
    expect(text).not.toContain(PLACEHOLDER_PREFIX);
    // a value the user typed, a placeholder value or a token is never written: the write is refused and the file unchanged
    const before = readFileSync(store.path, 'utf8');
    expect(() => store.update((s) => { s.notes.push(`key ${REAL}`); })).toThrow(StateError);
    expect(() => store.update((s) => { s.notes.push(`${PLACEHOLDER_PREFIX}STRIPE_SECRET_KEY`); })).toThrow(/placeholder/);
    expect(() => store.update((s) => { s.notes.push(GHP); })).toThrow(/token/);
    expect(() => store.update((s) => { s.notes.push(['github', 'pat', '11ABCDEFG0123456789abcdef'].join('_')); })).toThrow(/token/);
    // the vault's base64 form too (containsKnownValue)
    expect(() => store.update((s) => { s.notes.push(Buffer.from(REAL).toString('base64')); })).toThrow(StateError);
    expect(readFileSync(store.path, 'utf8')).toBe(before);
    expect(store.state?.notes).toEqual([]);
    // a leftover that would hold a value goes to stderr instead (never to the file), named as not saved
    const err: string[] = [];
    const s2 = await open(h, { vault, err: (l) => err.push(l) });
    s2.record(`secret value ${REAL}`);
    expect(readFileSync(store.path, 'utf8')).toBe(before);
    expect(err.join('\n')).toMatch(/^Left behind: .* \(pipegen couldn't save this in /);
  });

  it('state: CreatedFile.aiEdited survives the round-trip (E7-R14)', async () => {
    const h = home();
    const store = await open(h);
    store.begin(RUN, app(), { cap: 10, aiCap: null, draft: draft() });
    const back = (await loadState(app(), { home: h, env: {} }))?.draft;
    expect(back?.created.map((f) => [f.path, f.aiEdited])).toEqual([['docker-compose.yml', true], ['Dockerfile', undefined]]);
    // aiEdited is only ever `true` (a `false` written by hand is refused, not read as "not AI-written")
    const raw = JSON.parse(readFileSync(store.path, 'utf8')) as RunState;
    (raw.draft as unknown as { created: { aiEdited?: unknown }[] }).created[0]!.aiEdited = false;
    writeFileSync(store.path, JSON.stringify(raw), { mode: 0o600 });
    await expect(loadState(app(), { home: h, env: {} })).rejects.toThrow(/state format/);
  });

  it('state: written 0600 in a trusted dir; schema-checked on load', async () => {
    const h = home();
    const store = await open(h);
    store.begin(RUN, app(), { cap: 10, aiCap: 1 });
    expect(store.path).toBe(join(h, '.cache', 'pipegen', 'crisworking__shop', 'state.json'));
    expect(statSync(store.path).mode & 0o777).toBe(0o600);
    expect(statSync(store.dir).mode & 0o777).toBe(0o700);
    // XDG_CACHE_HOME when absolute
    const x = home();
    expect((await StateStore.open(app(), { home: h, env: { XDG_CACHE_HOME: x } })).dir).toBe(join(x, 'pipegen', 'crisworking__shop'));
    const good = readFileSync(store.path, 'utf8');
    const reload = () => store.load();
    // mode wider than 0600
    chmodSync(store.path, 0o644);
    expect(reload).toThrow(/chmod 600/);
    chmodSync(store.path, 0o600);
    // not JSON, an unknown key, a wrong type, an interrupted stage without the stage it reached, a bad branch name
    for (const bad of ['{', JSON.stringify({ ...JSON.parse(good), extra: 1 }), JSON.stringify({ ...JSON.parse(good), minutesUsed: -1 }),
      JSON.stringify({ ...JSON.parse(good), stage: 'interrupted' }), JSON.stringify({ ...JSON.parse(good), branches: [{ repo: 'scratch', ref: '../x' }] }),
      JSON.stringify({ ...JSON.parse(good), app: { ...JSON.parse(good).app, owner: 'a/b' } })]) {
      writeFileSync(store.path, bad, { mode: 0o600 });
      expect(reload).toThrow(StateError);
    }
    writeFileSync(store.path, good, { mode: 0o600 });
    expect(reload()).toEqual(store.state);
    // a symbolic link at the state file's place is never followed
    rmSync(store.path);
    writeFileSync(join(h, 'elsewhere.json'), good, { mode: 0o600 });
    symlinkSync(join(h, 'elsewhere.json'), store.path);
    expect(reload).toThrow(/symbolic link/);
    rmSync(store.path);
    // a folder others can write to is refused before anything is kept there
    const g = home();
    mkdirSync(join(g, '.cache', 'pipegen'), { recursive: true });
    chmodSync(join(g, '.cache', 'pipegen'), 0o777);
    await expect(open(g)).rejects.toThrow(/other users can write/);
    // the write goes through a temp file and a rename: no temp file is left
    store.update((s) => { s.notes.push('ok'); });
    expect(lstatSync(store.path).isFile()).toBe(true);
    expect(statSync(store.path).mode & 0o777).toBe(0o600);
  });

  it('stage: order is consented → planned → debated → created → proving → proven → cleaned → delivered', async () => {
    expect([...STAGE_ORDER]).toEqual(['consented', 'planned', 'debated', 'created', 'proving', 'proven', 'cleaned', 'delivered']);
    const store = await open();
    store.begin(RUN, app(), { cap: 10, aiCap: 1 });
    for (const s of STAGE_ORDER.slice(1)) {
      store.setStage(s);
      expect(store.load()?.stage).toBe(s);
    }
    // no skip, no step back
    const s2 = await open();
    s2.begin(RUN, app(), { cap: 10, aiCap: 1 });
    expect(() => s2.setStage('created')).toThrow(/can't go from the stage consented to created/);
    s2.setStage('planned');
    expect(() => s2.setStage('consented')).toThrow(StateError);
    expect(() => s2.setStage('cleaned')).toThrow(StateError);
    // interrupted / stopped keep the stage reached
    s2.setStage('interrupted');
    expect(s2.load()).toMatchObject({ stage: 'interrupted', interruptedAt: 'planned' });
    s2.setStage('stopped', { stoppedBy: 'ai-cost' });
    expect(s2.load()).toMatchObject({ stage: 'stopped', interruptedAt: 'planned', stoppedBy: 'ai-cost' });
  });

  it('resume: nextStage(saved) for every stage', () => {
    const want: Record<Stage, Stage | null> = {
      consented: 'planned', planned: 'debated', debated: 'created', created: 'proving',
      proving: 'proving',   // the proof didn't finish: it runs again (its leftovers cleaned first)
      proven: 'cleaned',    // the cleanup runs before anything is shown
      cleaned: 'delivered', delivered: null, interrupted: null, stopped: null,
    };
    for (const s of STAGE_ORDER) expect(nextStage({ stage: s }), s).toBe(want[s]);
    for (const stop of ['interrupted', 'stopped'] as const) {
      for (const at of STAGE_ORDER) expect(nextStage({ stage: stop, interruptedAt: at }), `${stop} at ${at}`).toBe(want[at]);
      expect(() => nextStage({ stage: stop })).toThrow(StateError);
    }
  });

  it('state: branches and PRs recorded before they are created', async () => {
    const store = await open();
    store.begin(RUN, app(), { cap: 10, aiCap: 1 });
    store.markArmed(true);
    const t = proofTarget(app(), { runId: RUN });
    // a branch is on disk before its push starts; a push whose record can't be written never starts
    const seen: string[] = [];
    const inner = { push: async (_to: unknown, _from: unknown, refs: readonly { branch: string }[]) => { for (const r of refs) seen.push(`${r.branch}: ${JSON.stringify(store.load()?.branches)}`); } };
    const tr = recordingTransport(inner as never, store);
    await tr.push(assertScratch(t, app()), {} as never, [{ branch: `proof/${RUN}/main`, sha: 'a'.repeat(40) }, { branch: 'main', sha: 'b'.repeat(40) }]);
    await tr.push(assertCentral(t, app()), {} as never, [{ branch: `proof/${RUN}`, sha: 'c'.repeat(40) }]);
    expect(seen[0]).toContain(`"ref":"proof/${RUN}/main"`);
    expect(seen[2]).toContain(`{"repo":"central","ref":"proof/${RUN}"}`);
    expect(store.load()?.branches).toEqual([{ repo: 'scratch', ref: `proof/${RUN}/main` }, { repo: 'central', ref: `proof/${RUN}` }]);   // never the default branch
    vi.spyOn(store, 'update').mockImplementationOnce(() => { throw new StateError('disk full'); });
    let pushed = false;
    await expect(recordingTransport({ push: async () => { pushed = true; } } as never, store).push(assertScratch(t, app()), {} as never, [{ branch: `proof/${RUN}/planted`, sha: 'a'.repeat(40) }])).rejects.toThrow('disk full');
    expect(pushed).toBe(false);
    // a PR: its head is on disk when GitHub is asked to open it, its number right after
    const f = runsFake();
    let atCreate: unknown = null;
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: (c) => {
      if (c.method === 'POST' && c.url.pathname.endsWith('/pulls')) atCreate = store.load()?.prs;
      return f.handler(c);
    } });
    const clock = { now: () => 0, sleep: async () => {} };
    const out = await proveVariant(g.gh, t, { branch: { variant: 'main', branch: `proof/${RUN}/main`, sha: 'a'.repeat(40), commits: ['a'.repeat(40)] }, merge: false, workflows: { push: [], pullRequest: [] } },
      { timeoutMs: 60_000, clock, recordPr: prRecorder(store) });
    expect(atCreate).toEqual([{ head: `proof/${RUN}/main` }]);
    expect(store.load()?.prs).toEqual([{ head: `proof/${RUN}/main`, number: out.pr }]);
  });

  it('state: the cleanup hook is registered before the first GitHub write (the save-state hook first)', async () => {
    // a fresh registry (the stop gate is sticky once an interrupt ran), with process.kill stubbed (no real signal here)
    vi.resetModules();
    const eh = await import('../src/util/exit-hooks.js');
    const st = await import('../src/proof/state.js');
    const cl = await import('../src/proof/cleanup.js');
    const tg = await import('../src/proof/target.js');
    const kill = vi.spyOn(process, 'kill').mockImplementation(() => true);
    try {
      const store = await st.StateStore.open(app(), { home: home(), env: {} });
      store.begin(RUN, app(), { cap: 10, aiCap: 1 });
      store.setStage('planned');
      const t = tg.proofTarget(app(), { runId: RUN });
      // before armProofCleanup: nothing is recorded, so nothing is pushed, opened or created
      let pushed = false;
      const tr = st.recordingTransport({ push: async () => { pushed = true; } } as never, store);
      await expect(tr.push(tg.assertScratch(t, app()), {} as never, [{ branch: `proof/${RUN}/main`, sha: 'a'.repeat(40) }])).rejects.toThrow(/before its cleanup is registered/);
      expect(pushed).toBe(false);
      expect(() => st.prRecorder(store).before(`proof/${RUN}/main`)).toThrow(/before its cleanup is registered/);
      expect(() => store.scratchCreated(5)).toThrow(/before its cleanup is registered/);
      // armed: the save-state hook runs first, then the cleanup (which sees the state already saved as interrupted)
      const order: string[] = [];
      const off = cl.armProofCleanup(store, async () => { order.push(`cleanup sees ${store.load()?.stage}`); }, { meters: () => ({ minutes: Object.assign(new MinutesMeter(10, 1_000), {}) }) });
      expect(store.armed).toBe(true);
      await tr.push(tg.assertScratch(t, app()), {} as never, [{ branch: `proof/${RUN}/main`, sha: 'a'.repeat(40) }]);
      expect(pushed).toBe(true);
      await eh.interrupt('SIGINT');
      expect(order).toEqual(['cleanup sees interrupted']);
      expect(store.load()).toMatchObject({ stage: 'interrupted', interruptedAt: 'planned', proofStart: { at: 1_000 } });
      expect(kill).toHaveBeenCalled();
      off();
      expect(store.armed).toBe(false);
    } finally {
      kill.mockRestore();
    }
  });

  it('state: SIGINT cancels, cleans and saves interrupted', async () => {
    const h = home();
    const out = join(h, 'out.txt');
    const cacheDir = resolve(import.meta.dirname, '..', 'node_modules', '.cache', 'pipegen-e8');
    mkdirSync(cacheDir, { recursive: true });
    const file = join(cacheDir, `sigint-child-${process.pid}-${Date.now()}.mjs`);
    await build({ entryPoints: [resolve(import.meta.dirname, 'fixtures', 'e8-sigint-child.ts')], bundle: true, platform: 'node', format: 'esm', target: 'node24', packages: 'external', outfile: file, logLevel: 'silent' });
    try {
      const res = await new Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }>((done, fail) => {
        const p = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH ?? '', E8_OUT: out, E8_HOME: h } });
        let stdout = '';
        let stderr = '';
        let sent = false;
        const guard = setTimeout(() => { p.kill('SIGKILL'); fail(new Error(`child timed out: ${stdout} ${stderr}`)); }, 30_000);
        p.stderr.on('data', (b: Buffer) => { stderr += b.toString(); });
        p.stdout.on('data', (b: Buffer) => {
          stdout += b.toString();
          if (!sent && stdout.includes('READY')) { sent = true; p.kill('SIGINT'); }
        });
        p.on('exit', (code, signal) => { clearTimeout(guard); done({ code, signal, stderr }); });
      });
      expect(res.signal === 'SIGINT' || res.code === 130, res.stderr).toBe(true);
      const lines = readFileSync(out, 'utf8').trim().split('\n');
      // the state was saved as interrupted (at proving) BEFORE the cleanup started
      expect(lines[0]).toBe('stage-at-cleanup interrupted proving');
      const writes = JSON.parse(lines[1]!.slice('writes '.length)) as string[];
      const R = `/repos/${OWNER}/${SCRATCH}`;
      // the secrets first, then the run cancelled, the PR closed, the branch deleted, the repo emptied
      expect(writes[0]).toBe(`DELETE ${R}/actions/secrets/STRIPE_SECRET_KEY`);
      expect(writes).toEqual(expect.arrayContaining([`POST ${R}/actions/runs/21/cancel`, `PATCH ${R}/pulls/5`, `DELETE ${R}/git/refs/heads/proof/${RUN}/main`, `DELETE ${R}/actions/runs/21`]));
      expect(lines[2]).toBe('after stored=0 runs=[] branches=[] open-prs=0 leftovers=0');
      // then the sync hooks: the vault wiped (B2), after the cleanup
      expect(lines[3]).toBe('sync-hooks vault=wiped');
      const saved = JSON.parse(readFileSync(join(h, '.cache', 'pipegen', 'crisworking__shop', 'state.json'), 'utf8')) as RunState;
      expect(saved).toMatchObject({ stage: 'interrupted', interruptedAt: 'proving', leftovers: [], runsDeleted: true });
      expect(nextStage(saved)).toBe('proving');
      expect(res.stderr).toContain('Cleaning up before stopping: saving the proof state');
      expect(res.stderr).toContain('Cleaning up before stopping: removing your keys and the proof from the scratch repo');
    } finally {
      rmSync(file, { force: true });
    }
  }, 60_000);

  it('state: the lease — another live pipegen on this repo is a stop; a dead one\'s lease is taken over', async () => {
    const h = home();
    const a = await open(h);
    a.begin(RUN, app(), { cap: 10, aiCap: 1 });
    a.acquireLease(RUN);
    const leaseFile = join(a.dir, 'lease.json');
    expect(statSync(leaseFile).mode & 0o777).toBe(0o600);
    const b = await open(h);
    expect(() => b.acquireLease(RUN)).toThrow(/Another pipegen \(process \d+\) is working on CrisWorking\/shop/);
    a.releaseLease();
    expect(existsSync(leaseFile)).toBe(false);
    b.acquireLease(RUN);
    // a lease left by a process that is gone is taken over
    const c = await open(h, { alive: () => false });
    c.acquireLease(RUN);
    expect(JSON.parse(readFileSync(leaseFile, 'utf8')).pid).toBe(process.pid);
    // b's release doesn't remove c's lease
    b.releaseLease();
    expect(existsSync(leaseFile)).toBe(true);
    c.releaseLease();
    // a lease taken on another machine is a stop, never taken over
    writeFileSync(leaseFile, JSON.stringify(Object.fromEntries([['pid', 1], ['host', 'other-host'], ['runId', RUN], ['token', 'x']])), { mode: 0o600 });
    const d = await open(h, { alive: () => false });
    expect(() => d.acquireLease(RUN)).toThrow(/another machine/);
  });

  it('state: a new run keeps the scratch repo\'s created id until it is deleted; saveState checks the schema', async () => {
    const h = home();
    const a = await open(h);
    a.begin(RUN, app(), { cap: 10, aiCap: 1 });
    a.markArmed(true);
    a.scratchCreated(4242);
    const b = await open(h);
    b.begin('20261105-090000-abc124', app(), { cap: 10, aiCap: 1 });
    expect(b.state?.scratchRepoId).toBe(4242);
    b.update((s) => { s.scratchDeleted = true; });
    const c = await open(h);
    c.begin('20261106-090000-abc125', app(), { cap: 10, aiCap: 1 });
    expect(c.state?.scratchRepoId).toBeUndefined();
    await expect(saveState(app(), { ...(c.state as RunState), stage: 'nope' as Stage }, { home: h, env: {} })).rejects.toThrow(StateError);
    await saveState(app(), { ...(c.state as RunState), notes: ['saved'] }, { home: h, env: {} });
    expect((await loadState(app(), { home: h, env: {} }))?.notes).toEqual(['saved']);
  });
});

describe('E8 a new run and the transport', () => {
  it('state: a new run over an earlier proof that may have left something is a stop (pipegen cleanup first)', async () => {
    const h = home();
    const a = await open(h);
    a.begin(RUN, app(), { cap: 10, aiCap: 1 });
    a.markArmed(true);
    for (const s of ['planned', 'debated', 'created', 'proving'] as const) a.setStage(s);
    a.recordBranch('scratch', `proof/${RUN}/main`, 'main');
    a.setStage('interrupted');
    const NEXT = '20261105-090000-abc124';
    // interrupted at proving without a finished cleanup: stop, name the scratch repo and the way out
    expect(() => a.begin(NEXT, app(), { cap: 10, aiCap: 1 })).toThrow(/pipegen cleanup first/);
    // a cleanup that finished: a new run may start
    a.update((s) => { s.cleanupDone = true; });
    expect(() => (a.begin(NEXT, app(), { cap: 10, aiCap: 1 }))).not.toThrow();
    // a leftover recorded: stop, whatever the stage
    const b = await open(home());
    b.begin(RUN, app(), { cap: 10, aiCap: 1 });
    b.record('the branch proof/x of CrisWorking/pipegen-proof-shop is still there; delete it there');
    expect(() => b.begin(NEXT, app(), { cap: 10, aiCap: 1 })).toThrow(/pipegen cleanup first/);
    // a run that never reached GitHub's proof stages: replaced
    const c = await open(home());
    c.begin(RUN, app(), { cap: 10, aiCap: 1 });
    c.setStage('planned');
    expect(c.begin(NEXT, app(), { cap: 10, aiCap: 1 }).runId).toBe(NEXT);
  });

  it('state: proofTransport records each branch, then pushes it as a tracked write (E4 carry: setup pushes too)', async () => {
    const store = await open();
    store.begin(RUN, app(), { cap: 10, aiCap: 1 });
    store.markArmed(true);
    let release!: () => void;
    const tr = proofTransport({ push: () => new Promise<void>((ok) => { release = ok; }) } as never, store);
    const p = tr.push(assertScratch(proofTarget(app(), { runId: RUN }), app()), {} as never, [{ branch: `proof/${RUN}/main`, sha: 'a'.repeat(40) }]);
    await new Promise((ok) => setTimeout(ok, 5));
    expect(writesInFlight()).toEqual([`push of proof/${RUN}/main`]);   // the Ctrl-C cleanup would wait for it
    expect(store.load()?.branches).toEqual([{ repo: 'scratch', ref: `proof/${RUN}/main` }]);
    release();
    await p;
    await new Promise((ok) => setTimeout(ok, 0));
    expect(writesInFlight()).toEqual([]);
  });
});

describe('E8 resume meters', () => {
  it('resume: minutes since = the saved server-time proof start, nothing restored; restored only after the runs were deleted', async () => {
    const start = Date.UTC(2026, 10, 4, 9, 0, 0);
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } }, extra: (c) => (c.url.pathname.endsWith('/actions/runs') ? { headers: { date: new Date(start + 3_600_000).toUTCString() }, body: { total_count: 0, workflow_runs: [] } } : undefined) });
    const t = proofTarget(app(), { runId: RUN });
    // runs still there: the original start, no restore (a re-list counts them once)
    const kept = await minutesForResume(g.gh, t, { cap: 100, minutesUsed: 30, proofStart: { at: start, fromServer: true }, runsDeleted: false });
    expect(kept.since).toBe(start);
    expect(kept.used).toBe(0);
    expect(g.calls).toEqual([]);   // no read, no local clock
    // runs deleted by the cleanup: a new start by GitHub's clock, the saved minutes restored
    const gone = await minutesForResume(g.gh, t, { cap: 100, minutesUsed: 30, proofStart: { at: start, fromServer: true }, runsDeleted: true });
    expect(gone.since).toBe(start + 3_600_000);
    expect(gone.used).toBe(30);
  });

  it('resume: a restored AI spend at the cap refuses again (the refused flag is not saved)', async () => {
    let sent = 0;
    const provider: AiProvider = { name: 'claude', model: DEFAULT_MODEL, complete: async () => { sent++; return { data: {}, usage: Object.fromEntries([['input' + T, 10], ['output' + T, 10]]) as unknown as AiUsage }; } };
    const meter = new AiSpendMeter(provider, 1);
    restoreAiSpend(meter, { aiCostUsd: 1 });
    expect(meter.refused).toBe(false);
    const err = await meter.provider.complete({ system: 's', user: 'u', schemaName: 'x', jsonSchema: { type: 'object' }, timeoutMs: 1_000, ['maxOutput' + T]: 100 } as unknown as AiRequest).catch((e: unknown) => e);
    expect(isCostCap(err)).toBe(true);
    expect(sent).toBe(0);
    expect(meter.refused).toBe(true);
    expect(capReached({ minutes: new MinutesMeter(10, 0), ai: meter })).toEqual({ kind: 'ai-cost', limitUsd: 1 });
    // the state holds no `refused` key at all (the schema refuses one)
    const store = await open();
    store.begin(RUN, app(), { cap: 10, aiCap: 1 });
    expect(Object.keys(store.state as object)).not.toContain('refused');
  });
});

describe('E8 readByWorkflows (carry E4-R4 R7)', () => {
  it('keys: readByWorkflows from the proof workflows\' secrets.X refs; dynamic access → every name counts', () => {
    expect(workflowSecretNames([
      { content: 'env:\n  K: ${{ secrets.STRIPE_SECRET_KEY }}\n  D: ${{ secrets[\'database_url\'] }}\n# secrets are fine here\n' },
      { content: `jobs:\n  a:\n    uses: ./.github/workflows/x.yml\n    ${LIST}:\n      T: \${{ ${LIST}.PIPEGEN_FP_KEY }}\n` },
    ])).toEqual(['DATABASE_URL', 'PIPEGEN_FP_KEY', 'STRIPE_SECRET_KEY']);
    expect(workflowSecretNames([{ content: 'run: echo ${{ toJSON(secrets) }}' }])).toBeNull();
    expect(workflowSecretNames([{ content: 'run: echo ${{ secrets[format(\'{0}\', env.N)] }}' }])).toBeNull();
    expect(workflowSecretNames([{ content: `    ${LIST}: inherit\n` }])).toBeNull();
    expect(workflowSecretNames([])).toEqual([]);
  });
});
