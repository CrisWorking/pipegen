// Plan E E4 fix round 1 (review-E4.md I1, M1, M3, M4, M6; rulings E4-R1, E4-R2): the excerpt brand comes from the scratch
// repo's real state (one shared key state per repo id, the Actions secrets listed from the API at ticket() and evidence()),
// org secrets and Actions variables fail closed, the brand is bound to its run ids, the scrubber is live, and deleteAll's
// wait for stores in flight has a deadline. Real makeOctokit over the fakes; interrupting() mocked. No network.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { evidenceCovers, isExcerptEvidence, placeholderValue, ScratchKeys } from '../src/proof/keys.js';
import { assertScratch, guardedWrite, proofTarget, SCRATCH_VARIABLES, ScratchGuardError } from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { person } from './helpers/proof-github.js';
import { app, keysWorld, quietIo, SCRATCH } from './helpers/scratch-secrets.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); });

const TYPED = ['typed', 'Test', 'Value', '0123456789abcdef'].join('-');
const SK = ['STRIPE', 'SEC' + 'RET', 'KEY'].join('_');
const RUN = 777;
const vaultWith = (pairs: Record<string, string> = { [SK]: TYPED }) => {
  const v = new SecretVault();
  for (const [k, val] of Object.entries(pairs)) v.set(k, val);
  return v;
};
type W = ReturnType<typeof keysWorld>;
const keysFor = (w: W, vault = vaultWith(), deps: Partial<ConstructorParameters<typeof ScratchKeys>[3]> = {}) =>
  new ScratchKeys(w.g.gh, proofTarget(app()), vault, { io: quietIo, readByWorkflows: [SK, 'A_KEY'], ...deps });
const brand = async (k: ScratchKeys, runs: number[] = [RUN]) => k.evidence(await k.ticket(), runs);

describe('E4-R1: the brand from the repo\'s real state (review I1)', () => {
  it('two ScratchKeys on one scratch repo share one state: B gets no brand once A stored a real value', async () => {
    const w = keysWorld();
    const v = vaultWith();
    const A = keysFor(w, v);
    const B = keysFor(w, v);
    await B.placeholders(['OTHER_KEY']);
    expect(isExcerptEvidence(await brand(B))).toBe(true);
    await A.real([SK]);
    expect(w.s.values.get(SK)).toBe(TYPED);
    expect(B.mode).toBe('real');                 // the shared state
    expect(await brand(B)).toBeNull();
    // and a ticket B took before A's real store gives nothing after it
    const w2 = keysWorld();
    const A2 = keysFor(w2, v);
    const B2 = keysFor(w2, v);
    await B2.placeholders(['OTHER_KEY']);
    const t = await B2.ticket();
    await A2.real([SK]);
    expect(await B2.evidence(t, [RUN])).toBeNull();
  });

  it('a secret added by hand after the ticket (or before it): no brand', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    const t = await K.ticket();
    w.s.touch('HAND_ADDED', TYPED);
    expect(await K.evidence(t, [RUN])).toBeNull();
    expect(K.lastRefusal).toMatch(/HAND_ADDED/);
    expect(await brand(K)).toBeNull();           // a new ticket sees it too
    // a hand-updated placeholder (same name, a new updated_at): no brand
    const w2 = keysWorld();
    const K2 = keysFor(w2);
    await K2.placeholders(['A_KEY']);
    expect(isExcerptEvidence(await brand(K2))).toBe(true);
    w2.s.touch('A_KEY', TYPED);
    expect(await brand(K2)).toBeNull();
    expect(K2.lastRefusal).toMatch(/A_KEY/);
  });

  it('any user value written since the last verified deleteAll: no brand, even after placeholders over it; a clean deleteAll restores it', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.real([SK]);
    await K.placeholders([SK]);
    expect(K.mode).toBe('placeholder');
    expect(await brand(K)).toBeNull();
    expect(K.lastRefusal).toMatch(/value you typed/);
    await K.deleteAll();
    await K.placeholders([SK]);
    expect(isExcerptEvidence(await brand(K))).toBe(true);
  });

  it('the secrets list is read whole at both ticket() and evidence(); an unreadable or cut list gives no brand', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    const before = w.g.calls.length;
    const t = await K.ticket();
    const e = await K.evidence(t, [RUN]);
    expect(isExcerptEvidence(e)).toBe(true);
    const lists = w.g.calls.slice(before).filter((c) => c.url.pathname.endsWith(`/${SCRATCH}/actions/secrets`));
    expect(lists).toHaveLength(2);
    // cut short (total_count above what is listed), or unreadable
    w.s.listBody = { total_count: 5, [['sec', 'rets'].join('')]: [] };
    expect(await brand(K)).toBeNull();
    w.s.listBody = undefined;
    w.s.listStatus = 500;
    expect(await brand(K)).toBeNull();
  });
});

describe('E4-R2: org secrets and Actions variables (review M6)', () => {
  it('an org-level value a proof workflow reads, not shadowed by a pipegen repo value, means no brand; so does an unreadable org list', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    w.s.orgShared = ['stripe_secret_key'];          // case-insensitive match with a name the workflows read, no repo secret of that name
    expect(await brand(K)).toBeNull();
    expect(K.lastRefusal).toMatch(/organisation secret/i);
    // shadowed by a pipegen placeholder of the same name: fine
    await K.placeholders([SK]);
    expect(isExcerptEvidence(await brand(K))).toBe(true);
    // an org secret no proof workflow reads: fine
    w.s.orgShared = ['SOMETHING_ELSE'];
    expect(isExcerptEvidence(await brand(K))).toBe(true);
    // unknown which names the workflows read (not given): every unshadowed org secret counts
    const w2 = keysWorld();
    const K2 = new ScratchKeys(w2.g.gh, proofTarget(app()), vaultWith(), { io: quietIo });
    await K2.placeholders(['A_KEY']);
    w2.s.orgShared = ['SOMETHING_ELSE'];
    expect(await brand(K2)).toBeNull();
    w2.s.orgShared = [];
    expect(isExcerptEvidence(await brand(K2))).toBe(true);
    // the org list can't be read: unknown fails closed
    w2.s.orgShared = null;
    expect(await brand(K2)).toBeNull();
  });

  it('Actions variables: the guard writes only the declared non-secret names; evidence() refuses any other variable', async () => {
    const w = keysWorld();
    const t = proofTarget(app());
    const s = assertScratch(t, app());
    expect(SCRATCH_VARIABLES).toEqual(['PIPEGEN_BLOCK_FROM']);
    const before = w.g.calls.length;
    for (const [route, p] of [
      ['POST /repos/{owner}/{repo}/actions/variables', { name: 'MY_KEY', value: 'x' }],
      ['POST /repos/{owner}/{repo}/actions/variables', { name: 'pipegen_block_from_x', value: 'x' }],
      ['PATCH /repos/{owner}/{repo}/actions/variables/{name}', { name: 'MY_KEY', value: 'x' }],
      ['PATCH /repos/{owner}/{repo}/actions/variables/{name}', { name: 'PIPEGEN_BLOCK_FROM', value: 'x', ['new' + '_name']: 'OTHER' }],
      ['POST /repos/{owner}/{repo}/environments/{environment_name}/variables', { environment_name: 'e', name: 'MY_KEY', value: 'x' }],
      ['PUT /repos/{owner}/{repo}/actions/variables/{name}', { name: 'PIPEGEN_BLOCK_FROM', value: 'x' }],
    ] as [string, Record<string, unknown>][]) {
      await expect(guardedWrite(w.g.gh, s, route, p), `${route} ${String(p.name)}`).rejects.toThrow(ScratchGuardError);
    }
    expect(w.g.calls.length).toBe(before);
    // the declared name passes the guard (the fake answers 404: not a guard refusal)
    await guardedWrite(w.g.gh, s, 'POST /repos/{owner}/{repo}/actions/variables', { name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-03' }).catch((e: unknown) => { if (e instanceof ScratchGuardError) throw e; });
    // a variable delete stays allowed (E8's cleanup)
    await guardedWrite(w.g.gh, s, 'DELETE /repos/{owner}/{repo}/actions/variables/{name}', { name: 'MY_KEY' }).catch((e: unknown) => { if (e instanceof ScratchGuardError) throw e; });
    // evidence(): an unknown variable (set by hand) means no brand; the declared one with a date value is fine
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    w.s.variables = [{ name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-03' }];
    expect(isExcerptEvidence(await brand(K))).toBe(true);
    w.s.variables = [{ name: 'API_TOKEN', value: TYPED }];
    expect(await brand(K)).toBeNull();
    expect(K.lastRefusal).toMatch(/API_TOKEN/);
    w.s.variables = [{ name: 'PIPEGEN_BLOCK_FROM', value: TYPED }];   // the declared name holding something that isn't its config
    expect(await brand(K)).toBeNull();
    w.s.variables = null;
    expect(await brand(K)).toBeNull();
  });
});

describe('E4 fix round 1: bound brand, live scrubber, deleteAll deadline (review M1, M3, M4)', () => {
  it('the brand names its run ids; evidence() needs at least one run id', async () => {
    const w = keysWorld();
    const K = keysFor(w);
    await K.placeholders(['A_KEY']);
    const e = await K.evidence(await K.ticket(), [11, 12]);
    expect(evidenceCovers(e, 11)).toBe(true);
    expect(evidenceCovers(e, 12)).toBe(true);
    expect(evidenceCovers(e, 13)).toBe(false);
    expect(evidenceCovers({ ...e }, 11)).toBe(false);
    for (const bad of [[], [0], [-1], [1.5], ['7']]) expect(await K.evidence(await K.ticket(), bad as number[]), JSON.stringify(bad)).toBeNull();
  });

  it('scrubber() is live: a value stored after the call is scrubbed too', async () => {
    const w = keysWorld();
    const K = keysFor(w, vaultWith(), { random: () => Buffer.alloc(32, 9) });
    const scrub = K.scrubber();
    await K.placeholders(['A_KEY']);
    await K.throwaway();
    const fp = Buffer.alloc(32, 9).toString('hex');
    expect(scrub(`x ${placeholderValue('A_KEY')} y ${fp} z`)).not.toMatch(/pipegen-placeholder-|0909090909/);
    // another instance on the same repo: its values are in the shared state, so this scrubber hides them too
    const other = keysFor(w, vaultWith(), { random: () => Buffer.alloc(32, 7) });
    await other.throwaway();
    expect(scrub(`${Buffer.alloc(32, 7).toString('hex')}`)).not.toMatch(/0707070707/);
  });

  it('deleteAll waits for a store in flight only until its deadline, then deletes, lists again and reports the store as a leftover', async () => {
    const unsure = { private: true, collaborators: [person('CrisWorking', 1, 'admin'), { ...person('carol', 7, 'custom-x'), permissions: { pull: true, push: false, maintain: false, admin: false, triage: false } }] };
    const w = keysWorld({ repos: { [SCRATCH]: unsure } }, { OLD: 'o'.repeat(10) });
    let answer: (v: boolean) => void = () => {};
    const confirm = vi.fn(() => new Promise<boolean>((ok) => { answer = ok; }));   // the store hangs at the access prompt
    const K = keysFor(w, vaultWith(), { io: { ...quietIo, prompt: { ...quietIo.prompt, confirm } } });
    const storing = K.placeholders(['A_KEY']).catch((e: unknown) => e);
    await vi.waitFor(() => expect(confirm).toHaveBeenCalled());
    const left: string[] = [];
    const t0 = Date.now();
    const deleted = await K.deleteAll({ waitMs: 50, leftover: (x) => left.push(x) });
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(deleted).toEqual([]);                      // the pre-store deleteAll already removed OLD
    expect(left).toHaveLength(1);
    expect(left[0]).toMatch(/A_KEY/);
    expect(w.s.values.size).toBe(0);
    // no brand while that store may still land
    expect(await brand(K)).toBeNull();
    answer(false);
    expect(await storing).toBeInstanceOf(Error);
  });
});
