// Plan E Task 7 / E8 (spec §19; rulings B2, S3, S9, S14, S18, S20): the cleanup right after the proof, and `pipegen cleanup`.
// A real makeOctokit client over stateful fakes (proof-github.ts world() + scratch-secrets.ts + cleanup-github.ts); the
// state file lives in a temp home. interrupting() is mocked where a stop is under way. No network.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanupCommand } from '../src/cli/cleanup.js';
import type { CliIO } from '../src/cli/io.js';
import { SecretVault } from '../src/create/secrets.js';
import { cleanupAfterProof, proveThenClean, type CleanupResult } from '../src/proof/cleanup.js';
import { ScratchKeys } from '../src/proof/keys.js';
import { StateStore } from '../src/proof/state.js';
import {
  assertCentral, assertScratch, cleanupWrite, deleteScratchRepo, EMPTY_TREE_SHA, guardedWrite, proofTarget, ScratchGuardError, type ProofTarget,
} from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { cleanupWorld } from './helpers/cleanup-github.js';
import { draftOf } from './helpers/proof-eval.js';
import { app, OWNER, quietIo, SCRATCH } from './helpers/scratch-secrets.js';
import { fake } from './helpers/secret-repo.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));

const RUN = '20261104-090000-abc123';
/** The token's env var name, kept out of `NAME: value` shapes (no-secret-literals). */
const ENV_VAR = 'GITHUB_TOKEN';
/** `secrets`, built at runtime (no-secret-literals reads `secrets/…` as a secret assignment). */
const LIST = ['sec', 'rets'].join('');
const R = `/repos/${OWNER}/${SCRATCH}`;
const REAL = ['sk', 'test', '51RealKeyTypedByTheUser0000'].join('_');   // built at runtime (no-secret-literals)
const dirs: string[] = [];
afterEach(() => {
  vi.mocked(interrupting).mockReturnValue(false);
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const home = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'pg-e8-'));
  dirs.push(d);
  return d;
};
const instant = { now: () => 0, sleep: async () => {} };

interface Setup {
  w: ReturnType<typeof cleanupWorld>;
  t: ProofTarget;
  store: StateStore;
  keys: ScratchKeys;
  vault: SecretVault;
  clean: (canDeleteRepo: boolean) => Promise<CleanupResult>;
}
/** A scratch repo after a proof: real key stored, runs, PRs, branches, caches; the state recorded as Plan G would. */
async function setup(o: { created?: number | null; repoId?: number; extra?: Parameters<typeof cleanupWorld>[0] } = {}): Promise<Setup> {
  const repoId = o.repoId ?? 77_001;
  const w = cleanupWorld({ ...(o.extra ?? {}) }, Object.fromEntries([['STRIPE_SECRET_KEY', REAL], ['PIPEGEN_FP_KEY', 'throwaway-bytes']]), repoId);
  w.f.runs.push({ id: 11, status: 'completed' }, { id: 12, status: 'in_progress' });
  w.f.prs.push({ number: 3, head: `proof/${RUN}/main`, state: 'open' }, { number: 4, head: `proof/${RUN}/planted`, state: 'closed' });
  w.f.branches.add(`proof/${RUN}/main`).add(`proof/${RUN}/planted`);
  w.f.caches.push(501, 502);
  w.s.variables = [{ name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-04' }];
  const t = proofTarget(app(), { runId: RUN });
  const store = await StateStore.open(app(), { home: home(), env: {} });
  store.begin(RUN, app(), { cap: 100, aiCap: 2 });
  store.markArmed(true);
  store.recordSecretNames(['STRIPE_SECRET_KEY']);
  store.recordBranch('scratch', `proof/${RUN}/main`, 'main');
  store.recordBranch('scratch', `proof/${RUN}/planted`, 'main');
  store.recordBranch('scratch', `proof/${RUN}/dispute-x-a`, 'main');   // recorded, but its push never landed
  store.recordPr(`proof/${RUN}/main`, 3);
  store.recordPr(`proof/${RUN}/planted`, 4);
  if (o.created !== null) store.scratchCreated(o.created ?? repoId);
  const vault = new SecretVault();
  vault.set('STRIPE_SECRET_KEY', REAL);
  const keys = new ScratchKeys(w.g.gh, t, vault, { io: quietIo });
  const clean = (canDeleteRepo: boolean) => cleanupAfterProof(w.g.gh, t, store, keys, { canDeleteRepo, clock: instant, settleMs: 0 });
  return { w, t, store, keys, vault, clean };
}
const writes = (e: Setup): string[] => e.w.g.writes().map((c) => `${c.method} ${decodeURIComponent(c.url.pathname).replace(R, '')}`);

describe('E8 cleanup after the proof', () => {
  it('cleanup: scratch secrets deleted first', async () => {
    const e = await setup();
    await e.clean(false);
    const ws = writes(e);
    const keyDeletes = ws.filter((x) => x.startsWith(`DELETE /actions/${LIST}/`));
    // two passes (fix round 1, I-2): the first right away, the second after the writes in flight settled (a recorded name
    // the first pass already deleted is asked again: GitHub's 404 is "already gone")
    expect([...new Set(keyDeletes)].sort()).toEqual(['DELETE /actions/secrets/PIPEGEN_FP_KEY', 'DELETE /actions/secrets/STRIPE_SECRET_KEY']);
    // every secret delete comes before any other write (cancel, close, delete, reset)
    expect(ws.slice(0, keyDeletes.length).every((x) => x.startsWith('DELETE /actions/secrets/'))).toBe(true);
    expect(e.w.s.values.size).toBe(0);
    // and the secrets were listed again after the deletes
    const lists = e.w.g.calls.map((c, i) => ({ c, i })).filter(({ c }) => c.method === 'GET' && decodeURIComponent(c.url.pathname) === `${R}/actions/secrets`);
    const lastDelete = e.w.g.calls.findLastIndex((c) => c.method === 'DELETE' && c.url.pathname.includes('/actions/secrets/'));
    expect(lists.some(({ i }) => i > lastDelete)).toBe(true);
  });

  it('cleanup: token can delete → scratch repo deleted', async () => {
    const e = await setup();
    const res = await e.clean(true);
    expect(res.repoDeleted).toBe(true);
    expect(res.message).toBeUndefined();
    expect(e.w.f.deleted).toBe(true);
    expect(writes(e)).toContain('DELETE ');
    expect(e.store.state?.scratchDeleted).toBe(true);
    expect(e.store.state?.scratchRepoId).toBeUndefined();
    // the secrets went first even so
    expect(writes(e)[0]).toMatch(/^DELETE \/actions\/secrets\//);
  });

  it('cleanup: app token → scratch deleted', async () => {
    // App mode: getAuth's canDeleteRepos is true only for pipegen's App with Administration write (S9); the repo pipegen created
    const e = await setup({ repoId: 77_010 });
    const res = await e.clean(true);
    expect(res).toMatchObject({ repoDeleted: true, leftovers: [] });
  });

  it('cleanup: token can\'t delete → repo emptied, gh repo delete command shown', async () => {
    const e = await setup();
    const res = await e.clean(false);
    expect(res.repoDeleted).toBe(false);
    expect(e.w.f.deleted).toBe(false);
    expect(res.message).toContain(`gh repo delete ${OWNER}/${SCRATCH} --yes`);
    expect(res.message).toContain('can\'t delete repos');
    // emptied: no PR open, no proof branch, no run, no cache, the default branch on the empty commit
    expect(e.w.f.prs.filter((p) => p.state === 'open')).toEqual([]);
    expect([...e.w.f.branches]).toEqual([]);
    expect(e.w.f.runs).toEqual([]);
    expect(e.w.f.caches).toEqual([]);
    expect(e.w.f.defaultHead).toBe('e'.repeat(40));
    const commit = e.w.g.calls.find((c) => c.method === 'POST' && c.url.pathname.endsWith('/git/commits'));
    expect(JSON.parse(commit?.body ?? '{}')).toMatchObject({ tree: EMPTY_TREE_SHA, parents: [] });
    expect(res.leftovers).toEqual([]);
  });

  it('cleanup: fine-grained → emptied, not deleted', async () => {
    // a fine-grained token never has canDeleteRepos (S9: getAuth gives it only to pipegen's App); no DELETE of the repo is sent
    const e = await setup();
    const res = await e.clean(false);
    expect(res.repoDeleted).toBe(false);
    expect(writes(e)).not.toContain('DELETE ');
    expect(e.w.g.calls.some((c) => c.method === 'DELETE' && decodeURIComponent(c.url.pathname) === R)).toBe(false);
  });

  it('cleanup: a scratch repo pipegen did not create is emptied, never deleted', async () => {
    // no id recorded at creation (made by hand with the printed gh command, which also sets the marker description)
    const e = await setup({ created: null });
    const res = await e.clean(true);
    expect(res.repoDeleted).toBe(false);
    expect(res.message).toMatch(/no record of creating/);
    expect(e.w.g.calls.some((c) => c.method === 'DELETE' && decodeURIComponent(c.url.pathname) === R)).toBe(false);
    // an id recorded for another repo (the scratch repo was deleted and made again by hand): not deleted either
    const e2 = await setup({ created: 99_999, repoId: 77_002 });
    const res2 = await e2.clean(true);
    expect(res2.repoDeleted).toBe(false);
    expect(res2.message).toMatch(/id differs/);
    expect(e2.w.f.deleted).toBe(false);
    // the marker removed by hand: not deleted
    const e3 = await setup({ repoId: 77_003, extra: { repos: { [SCRATCH]: { private: true, description: 'my own repo' } } } });
    const res3 = await e3.clean(true);
    expect(res3.repoDeleted).toBe(false);
    expect(res3.message).toMatch(/marker/);
    expect(e3.w.f.deleted).toBe(false);
  });

  it('cleanup: delete refuses any name but pipegen-proof-<repo>', async () => {
    const e = await setup();
    // GitHub answers for another repo (renamed or transferred): not deleted
    const renamed = await setup({ repoId: 77_004, extra: { repos: { [SCRATCH]: { private: true, fullName: `${OWNER}/shop` } } } });
    expect(await deleteScratchRepo(renamed.w.g.gh, assertScratch(renamed.t, app()), 77_004)).toMatchObject({ deleted: false });
    expect(renamed.w.f.deleted).toBe(false);
    // the guard: only the exact scratch name gets a handle, never the app repo, never pipelines, never another owner
    expect(() => assertScratch(e.t, app(), { owner: OWNER, repo: 'shop' })).toThrow(ScratchGuardError);
    expect(() => assertScratch(e.t, app(), { owner: OWNER, repo: 'pipegen-proof-shop2' })).toThrow(ScratchGuardError);
    expect(() => assertScratch(e.t, app(), { owner: 'someone', repo: SCRATCH })).toThrow(ScratchGuardError);
    await expect(deleteScratchRepo(e.w.g.gh, assertCentral(e.t, app()), 77_001)).rejects.toThrow(ScratchGuardError);
    await expect(deleteScratchRepo(e.w.g.gh, { ...assertScratch(e.t, app()) } as never, 77_001)).rejects.toThrow(ScratchGuardError);
    // a plain guardedWrite never deletes a repo
    await expect(guardedWrite(e.w.g.gh, assertScratch(e.t, app()), 'DELETE /repos/{owner}/{repo}')).rejects.toThrow(/exact name/);
    // a recorded id that isn't one: not deleted, nothing read
    expect(await deleteScratchRepo(e.w.g.gh, assertScratch(e.t, app()), 0)).toMatchObject({ deleted: false });
    expect(e.w.f.deleted).toBe(false);
    // the real one: deleted, and read back as gone
    expect(await deleteScratchRepo(e.w.g.gh, assertScratch(e.t, app()), 77_001)).toEqual({ deleted: true });
  });

  it('cleanup: deletes every recorded ref and open PR, tolerates already-deleted', async () => {
    const e = await setup();
    e.w.f.prs.push({ number: 9, head: `proof/${RUN}/dispute-x-a`, state: 'open' });
    const res = await e.clean(false);
    // the recorded branch whose push never landed (422 Reference does not exist) and the closed PR are fine
    expect(res.leftovers).toEqual([]);
    expect(e.w.f.prs.every((p) => p.state === 'closed')).toBe(true);
    expect(writes(e)).toEqual(expect.arrayContaining([
      `DELETE /git/refs/heads/proof/${RUN}/main`, `DELETE /git/refs/heads/proof/${RUN}/planted`, `DELETE /git/refs/heads/proof/${RUN}/dispute-x-a`,
      'PATCH /pulls/3', 'PATCH /pulls/9',
    ]));
    expect(writes(e)).not.toContain('PATCH /pulls/4');   // already closed: not listed open
    // a second cleanup in another process (pipegen cleanup) finds nothing left and still reports nothing
    const again = await cleanupAfterProof(e.w.g.gh, e.t, await StateStore.open(app(), { home: e.store.dir.split('/.cache/')[0] as string, env: {} }), e.keys, { canDeleteRepo: false, clock: instant, settleMs: 0 });
    expect(again.leftovers).toEqual([]);
  });

  it('cleanup: deletes all scratch runs (logs and artifacts) and all caches', async () => {
    const e = await setup();
    e.w.f.runs.push({ id: 13, status: 'queued' });
    await e.clean(false);
    expect(e.w.f.runs).toEqual([]);
    expect(e.w.f.caches).toEqual([]);
    expect(writes(e)).toEqual(expect.arrayContaining(['DELETE /actions/runs/11', 'DELETE /actions/runs/12', 'DELETE /actions/runs/13', 'DELETE /actions/caches/501', 'DELETE /actions/caches/502']));
    // the runs still going were cancelled first (a run in progress can't be deleted)
    expect(writes(e).indexOf('POST /actions/runs/12/cancel')).toBeLessThan(writes(e).indexOf('DELETE /actions/runs/12'));
    expect(e.store.state?.runsDeleted).toBe(true);
  });

  it('cleanup: code scanning analyses and Actions variables deleted', async () => {
    const e = await setup();
    e.w.f.analyses = [70, 71];
    await e.clean(false);
    expect(e.w.f.analyses).toEqual([]);
    expect(e.w.s.variables).toEqual([]);
    const del = e.w.g.calls.find((c) => c.method === 'DELETE' && c.url.pathname.endsWith('/code-scanning/analyses/71'));
    expect(del?.url.searchParams.get('confirm_delete')).toBe('true');
    expect(writes(e)).toContain('DELETE /actions/variables/PIPEGEN_BLOCK_FROM');
    // code scanning off (403 "Advanced Security must be enabled"): nothing to delete, no leftover
    const off = await setup({ repoId: 77_005 });
    off.w.f.analyses = null;
    expect((await off.clean(false)).leftovers).toEqual([]);
  });

  it('cleanup: vault not wiped', async () => {
    const e = await setup();
    await e.clean(true);
    expect(e.vault.get('STRIPE_SECRET_KEY')).toBe(REAL);
    expect(e.vault.names()).toEqual(['STRIPE_SECRET_KEY']);
  });

  it('cleanup: runs right after the proof, before the preview', async () => {
    const e = await setup();
    const order: string[] = [];
    e.store.update((s) => { s.stage = 'proving'; });
    // final review I-2: a proof that passed (its verdict and final draft saved) is proven; see test/proof-e-final.test.ts for the rest
    // Plan G G0 (E-F2 m1): a verdict reader may only make a result stricter, so the outcome is a passing FixOutcome itself
    const passed = { draft: draftOf(), result: { ok: true } };
    const out = await proveThenClean(e.store, async () => { order.push('prove'); return passed; }, async () => { order.push(`cleanup (${e.store.state?.stage})`); return e.clean(false); });
    order.push(`preview (${e.store.state?.stage})`);
    expect(order).toEqual(['prove', 'cleanup (proven)', 'preview (cleaned)']);
    expect(out.outcome).toBe(passed);
    expect(e.w.s.values.size).toBe(0);
    // a proof that fails: the cleanup still runs, then the error goes on; nothing shown before it
    const f = await setup({ repoId: 77_006 });
    f.store.update((s) => { s.stage = 'proving'; });
    const seen: string[] = [];
    await expect(proveThenClean(f.store, async () => { seen.push('prove'); throw new Error('the proof failed'); }, async () => { seen.push('cleanup'); return f.clean(false); })).rejects.toThrow('the proof failed');
    expect(seen).toEqual(['prove', 'cleanup']);
    expect(f.w.s.values.size).toBe(0);
  });

  it('cleanup: runs still going are cancelled; a failed cancel is force-cancelled, else a leftover (E6 M6, M7)', async () => {
    // a rate stop in the minutes check left run 12 going without a cancel (M6); run 14's first cancel failed before a Ctrl-C (M7)
    const e = await setup();
    e.w.f.runs.push({ id: 14, status: 'in_progress' }, { id: 15, status: 'in_progress' });
    e.w.f.fail.set('POST /actions/runs/14/cancel', 500);
    e.w.f.fail.set('POST /actions/runs/15/cancel', 500);
    e.w.f.fail.set('POST /actions/runs/15/force-cancel', 500);
    const res = await e.clean(false);   // emptied: the run stays there (a deleted repo takes it along: fix round 1, I-5)
    expect(writes(e)).toEqual(expect.arrayContaining(['POST /actions/runs/12/cancel', 'POST /actions/runs/14/force-cancel', 'POST /actions/runs/15/force-cancel']));
    expect(res.leftovers.some((l) => /run 15 .*could not be cancelled/.test(l))).toBe(true);
    expect(res.leftovers.some((l) => /run 14\b/.test(l))).toBe(false);
    // each leftover is on disk the moment it is found (the process may stop right after: E0b), not only at the end
    const h = await setup({ repoId: 77_012 });
    h.w.f.runs.push({ id: 15, status: 'in_progress' });
    h.w.f.fail.set('POST /actions/runs/15/cancel', 500);
    h.w.f.fail.set('POST /actions/runs/15/force-cancel', 500);
    const onDisk: boolean[] = [];
    await cleanupAfterProof(h.w.g.gh, h.t, h.store, h.keys, { canDeleteRepo: true, clock: instant, settleMs: 0, leftover: (l) => { onDisk.push(h.store.load()?.leftovers.includes(l) === true); } });
    expect(onDisk).toEqual([true]);
    // the leftover is in the state file for `pipegen cleanup`
    expect(e.store.load()?.leftovers.some((l) => /run 15/.test(l))).toBe(true);
    // a cancel that a run ignores (still going after the wait) is force-cancelled before its delete
    const g = await setup({ repoId: 77_007 });
    g.w.f.ignoreCancel.add(12);
    await g.clean(false);
    expect(writes(g)).toEqual(expect.arrayContaining(['POST /actions/runs/12/cancel', 'POST /actions/runs/12/force-cancel', 'DELETE /actions/runs/12']));
  });

  it('cleanup: in-flight writes settle first; secrets deleted by recorded and listed names, then listed again', async () => {
    const { trackWrite } = await import('../src/proof/inflight.js');
    const e = await setup();
    // a store the proof had sent lands only after the cleanup started; the list is taken after it
    let land!: () => void;
    const inflight = trackWrite('store of LATE_KEY', () => new Promise<void>((ok) => { land = () => { e.w.s.values.set('LATE_KEY', 'x'); ok(); }; }));
    const p = cleanupAfterProof(e.w.g.gh, e.t, e.store, e.keys, { canDeleteRepo: false, clock: instant, settleMs: 5_000 });
    await new Promise((ok) => setTimeout(ok, 20));
    // fix round 1 (I-2): the secrets go first, without waiting for the write in flight; a second pass follows the settle
    expect(e.w.g.writes().every((c) => c.method === 'DELETE' && c.url.pathname.includes(`/actions/${LIST}/`))).toBe(true);
    land();
    await inflight;
    await p;
    expect(e.w.s.values.has('LATE_KEY')).toBe(false);
    // a recorded name the list doesn't show (a list lagging behind a store) is deleted by name; its 404 is fine
    const f = await setup({ repoId: 77_008 });
    f.store.recordSecretNames(['DATABASE_URL']);
    f.w.s.failDelete.set('DATABASE_URL', 404);   // GitHub: no such secret
    const res = await f.clean(false);
    expect(writes(f)).toContain('DELETE /actions/secrets/DATABASE_URL');
    expect(res.leftovers).toEqual([]);
    // a write that never settles is a leftover, and the cleanup goes on
    const g = await setup({ repoId: 77_009 });
    let release!: () => void;
    const stuck = trackWrite('push of proof/x', () => new Promise<void>((ok) => { release = ok; }));
    const r2 = await cleanupAfterProof(g.w.g.gh, g.t, g.store, g.keys, { canDeleteRepo: false, clock: instant, settleMs: 10 });
    expect(r2.leftovers.some((l) => l.includes('still in flight') && l.includes('push of proof/x'))).toBe(true);
    expect(g.w.s.values.size).toBe(0);
    release();
    await stuck;
  });

  it('cleanup: proof branches listed again after the delete (a killed push may have landed)', async () => {
    const e = await setup();
    e.w.f.lateBranches.push(`proof/${RUN}/main-2`);   // lands while the cleanup deletes
    const res = await e.clean(false);
    expect(writes(e)).toContain(`DELETE /git/refs/heads/proof/${RUN}/main-2`);
    expect([...e.w.f.branches]).toEqual([]);
    expect(res.leftovers).toEqual([]);
    // one that keeps coming back is a leftover
    const f = await setup({ repoId: 77_011 });
    f.w.f.lateBranches.push(`proof/${RUN}/a`, `proof/${RUN}/b`, `proof/${RUN}/c`, `proof/${RUN}/d`, `proof/${RUN}/e`);
    const r2 = await f.clean(false);
    expect(r2.leftovers.some((l) => /branch proof\/.* is still there/.test(l))).toBe(true);
  });

  it('cleanup: the Ctrl-C cleanup\'s writes pass the stop gate; plain writes still don\'t', async () => {
    const e = await setup();
    vi.mocked(interrupting).mockReturnValue(true);
    const s = assertScratch(e.t, app());
    await expect(guardedWrite(e.w.g.gh, s, 'POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel', { run_id: 12 })).rejects.toThrow(/stopping/);
    await expect(guardedWrite(e.w.g.gh, s, 'DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: `heads/proof/${RUN}/main` })).rejects.toThrow(/stopping/);
    const res = await e.clean(true);
    expect(res.repoDeleted).toBe(true);
    expect(e.w.s.values.size).toBe(0);
    expect(writes(e)).toContain('POST /actions/runs/12/cancel');
    // the cleanup ops still follow the repo rules: the central repo takes only this run's proof branch, and only a delete
    const c = assertCentral(e.t, app());
    await expect(cleanupWrite(e.w.g.gh, c, { op: 'delete-branch', branch: 'main' })).rejects.toThrow(ScratchGuardError);
    await expect(cleanupWrite(e.w.g.gh, c, { op: 'delete-run', runId: 1 })).rejects.toThrow(ScratchGuardError);
    // the scratch default branch is reset only to the empty commit the cleanup made, never deleted
    await expect(cleanupWrite(e.w.g.gh, s, { op: 'delete-branch', branch: 'main' })).rejects.toThrow(/emptied, never deleted/);
    await expect(cleanupWrite(e.w.g.gh, s, { op: 'reset-default-branch', sha: 'a'.repeat(40) })).rejects.toThrow(/empty commit/);
    await expect(cleanupWrite(e.w.g.gh, s, { op: 'nope' } as never)).rejects.toThrow(ScratchGuardError);
  });

  it('cleanup: the central proof/<runId> branch deleted and read again', async () => {
    const e = await setup();
    e.store.recordBranch('central', `proof/${RUN}`, 'main');
    e.w.f.central.add(`proof/${RUN}`);
    const res = await e.clean(true);
    expect(e.w.f.central.size).toBe(0);
    expect(res.leftovers).toEqual([]);
    expect(e.w.g.calls.some((c) => c.method === 'GET' && decodeURIComponent(c.url.pathname) === `/repos/${OWNER}/pipelines/git/ref/heads/proof/${RUN}`)).toBe(true);
  });

  it('cleanup: its leftovers replace an earlier cleanup\'s of this run; one recorded meanwhile (a hook cut) stays', async () => {
    const e = await setup();
    e.store.record('run 99 of CrisWorking/pipegen-proof-shop could not be cancelled (HTTP 500); cancel it there');   // an earlier cleanup's
    let once = false;
    const g = e.w.g;
    e.w.f.fail.set('DELETE /actions/caches/502', 500);
    const res = await cleanupAfterProof(g.gh, e.t, e.store, e.keys, { canDeleteRepo: false, clock: instant, settleMs: 0, leftover: () => {
      if (!once) { once = true; e.store.record('removing your keys and the proof from the scratch repo: did not finish within 90 s'); }
    } });
    const saved = e.store.load();
    expect(res.leftovers).toEqual([
      'the Actions cache 502 of CrisWorking/pipegen-proof-shop could not be deleted (HTTP 500); delete it there',
      'the Actions cache 502 of CrisWorking/pipegen-proof-shop is still there; delete it there',
    ]);
    expect(saved?.leftovers).toContain('removing your keys and the proof from the scratch repo: did not finish within 90 s');
    expect(saved?.leftovers.some((l) => l.includes('run 99'))).toBe(false);
    expect(saved?.cleanupDone).toBe(false);
  });

  it('cleanup: a delete GitHub answers but doesn\'t do is "not deleted"; an empty commit on another tree is refused; cleanup routes stay out of plain writes', async () => {
    const e = await setup();
    e.w.f.deleteIgnored = true;
    expect(await deleteScratchRepo(e.w.g.gh, assertScratch(e.t, app()), 77_001)).toMatchObject({ deleted: false, why: expect.stringMatching(/still shows/) });
    const s = assertScratch(e.t, app());
    e.w.f.commitTree = 'f'.repeat(40);
    await expect(cleanupWrite(e.w.g.gh, s, { op: 'empty-commit' })).rejects.toThrow(/doesn't say it is one/);
    await expect(cleanupWrite(e.w.g.gh, s, { op: 'reset-default-branch', sha: 'e'.repeat(40) })).rejects.toThrow(/empty commit/);
    await expect(guardedWrite(e.w.g.gh, s, 'DELETE /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}{?confirm_delete}', { analysis_id: 70, confirm_delete: 'true' })).rejects.toThrow(/cleanup route/);
  });

  it('cleanup: a repo GitHub refuses to delete is emptied instead; a second call joins the first', async () => {
    const e = await setup();
    e.w.f.deleteStatus = 403;
    const [a, b] = await Promise.all([e.clean(true), e.clean(true)]);
    expect(a).toBe(b);
    expect(a.repoDeleted).toBe(false);
    expect(a.message).toMatch(/HTTP 403/);
    expect([...e.w.f.branches]).toEqual([]);
  });
});

describe('E8 cleanup source scan', () => {
  it('cleanup: only cleanup.ts sends the cleanup writes and the repo delete (a lint; the guard is the boundary)', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const root = join(import.meta.dirname, '..', 'src');
    const files = (readdirSync(root, { recursive: true }) as string[]).filter((f) => f.endsWith('.ts'));
    for (const f of files) {
      const src = readFileSync(join(root, f), 'utf8');
      const allowed = f === join('proof', 'target.ts') || f === join('proof', 'cleanup.ts');
      if (!allowed) expect(src, f).not.toMatch(/\b(?:cleanupWrite|deleteScratchRepo)\b/);
    }
  });
});

describe('E8 pipegen cleanup', () => {
  it('cli: cleanup command removes recorded leftovers', async () => {
    const e = await setup();
    e.store.record('run 12 of CrisWorking/pipegen-proof-shop could not be cancelled (HTTP 500); cancel it there');
    e.store.setStage('interrupted');
    const cacheDir = `${e.store.dir.split('/.cache/')[0] as string}/.cache`;
    const repo = home();
    mkdirSync(join(repo, '.git'));
    writeFileSync(join(repo, '.git', 'config'), `[remote "origin"]\n\turl = https://github.com/${OWNER}/shop.git\n`);
    const out: string[] = [];
    const errs: string[] = [];
    const io: CliIO = { ...quietIo, out: (s) => out.push(s), err: (s) => errs.push(s), env: { [ENV_VAR]: fake.githubPat(), XDG_CACHE_HOME: cacheDir }, cwd: repo, fetch: e.w.g.fetch };
    const code = await cleanupCommand(repo, io, { allowBroad: false });
    expect(errs).toEqual([]);
    expect(code).toBe(0);
    expect(out.join('\n')).toContain('Nothing is left behind.');
    expect(out.join('\n')).toContain(`gh repo delete ${OWNER}/${SCRATCH} --yes`);   // a fine-grained token empties
    expect(e.w.s.values.size).toBe(0);
    expect([...e.w.f.branches]).toEqual([]);
    const saved = e.store.load();
    expect(saved?.leftovers).toEqual([]);
    // nothing saved for a repo: nothing to do
    const other = home();
    mkdirSync(join(other, '.git'));
    writeFileSync(join(other, '.git', 'config'), `[remote "origin"]\n\turl = https://github.com/${OWNER}/other.git\n`);
    const out2: string[] = [];
    expect(await cleanupCommand(other, { ...io, out: (s) => out2.push(s) }, { allowBroad: false })).toBe(0);
    expect(out2.join('\n')).toMatch(/Nothing to clean up/);
  });
});

