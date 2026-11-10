// Plan E Task 3 / E4 (rulings S14, B1, E0a-R5 / DECISIONS #113; E1 carries G1 and R5; E0b carry; threat T12): the scratch
// keys. Real makeOctokit client over the stateful fake (test/helpers/proof-github.ts) with the secrets routes of
// test/helpers/scratch-secrets.ts (a real libsodium key pair, so what pipegen sealed can be opened here). interrupting()
// is mocked (a real stop would end the test worker). No network.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateFpKey, SecretVault, storeRepoSecret } from '../src/create/secrets.js';
import { settleWrites, trackWrite, writesInFlight } from '../src/proof/inflight.js';
import { isExcerptEvidence, placeholderValue, ScratchKeys, ScratchKeysError, scratchSecretStore } from '../src/proof/keys.js';
import { checkScratchAccess } from '../src/proof/repos.js';
import {
  ACCESS_CHECK_MAX_AGE_MS, assertCentral, assertScratch, deleteScratchSecret, guardedWrite, proofTarget, ProofStopError, scratchSecretSink, ScratchGuardError,
  takeAccessIssuer,
} from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { person } from './helpers/proof-github.js';
import { app, keysWorld, OWNER, quietIo, SCRATCH } from './helpers/scratch-secrets.js';
import { makeOctokit } from '../src/github/client.js';
import { fakeFetch } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); vi.useRealTimers(); });

// values built at run time (test/no-secret-literals.test.ts)
const TYPED = ['typed', 'Test', 'Value', '0123456789abcdef'].join('-');
const SN = ['sec', 'ret_name'].join('');
// names that look like key = value to redact, built at run time
const SK = ['STRIPE', 'SEC' + 'RET', 'KEY'].join('_');
const OK2 = ['OTHER', 'KEY'].join('_');
const LIST = ['sec', 'rets'].join('');
const vaultWith = (pairs: Record<string, string> = { [SK]: TYPED }) => {
  const v = new SecretVault();
  for (const [k, val] of Object.entries(pairs)) v.set(k, val);
  return v;
};
const keysFor = (g: ReturnType<typeof keysWorld>['g'], vault = vaultWith(), deps: Partial<ConstructorParameters<typeof ScratchKeys>[3]> = {}) =>
  new ScratchKeys(g.gh, proofTarget(app()), vault, { io: quietIo, ...deps });
const path = (c: { method: string; url: URL }) => `${c.method} ${decodeURIComponent(c.url.pathname)}`;
const S_PATH = `/repos/${OWNER}/${SCRATCH}/actions/${LIST}`;

describe('E4 scratch keys: what is stored (S14)', () => {
  it('keys: placeholders are not the vault values', async () => {
    const { g, s } = keysWorld();
    const vault = vaultWith({ [SK]: TYPED, [OK2]: `${TYPED}-2` });
    const keys = keysFor(g, vault);
    await keys.placeholders(['STRIPE_SECRET_KEY', 'other_key']);
    expect(Object.fromEntries(s.values)).toEqual({ [SK]: placeholderValue(SK), [OK2]: placeholderValue(OK2) });
    expect(placeholderValue('STRIPE_SECRET_KEY')).toBe('pipegen-placeholder-STRIPE_SECRET_KEY');
    for (const v of s.values.values()) expect(vault.containsKnownValue(v)).toBe(false);
    // no request carries a vault value, in any form, or a placeholder in clear (sealed only)
    for (const c of g.calls) {
      expect(vault.containsKnownValue(c.body ?? '')).toBe(false);
      expect(c.body ?? '').not.toContain('pipegen-placeholder-');
    }
    expect(keys.mode).toBe('placeholder');
    expect(keys.stored()).toEqual({ [SK]: 'placeholder', [OK2]: 'placeholder' });
    // a placeholder that is a value the user typed is refused before anything is sent
    const odd = keysWorld();
    const before = odd.g.calls.length;
    await expect(keysFor(odd.g, vaultWith({ X_KEY: placeholderValue('X_KEY') })).placeholders(['X_KEY'])).rejects.toThrow(ScratchKeysError);
    expect(odd.g.calls.length).toBe(before);
    // pipegen's own names get no placeholder; bad names are refused
    for (const bad of ['PIPEGEN_FP_KEY', 'GITHUB_TOKEN', 'a b', '']) await expect(keysFor(odd.g).placeholders([bad]), bad).rejects.toThrow(ScratchKeysError);
    await expect(keysFor(odd.g).placeholders(['A', 'a'])).rejects.toThrow(/same after upper-casing/);
    expect(odd.g.writes()).toEqual([]);
  });

  it('keys: scratch FP key is fresh and is not the delivery PIPEGEN_FP_KEY', async () => {
    const { g, s } = keysWorld();
    const vault = vaultWith();
    generateFpKey(vault);
    const delivered = vault.get('PIPEGEN_FP_KEY') as string;
    const keys = keysFor(g, vault);
    await keys.throwaway();
    const first = s.values.get('PIPEGEN_FP_KEY') as string;
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toBe(delivered);
    await keys.throwaway();
    const second = s.values.get('PIPEGEN_FP_KEY') as string;
    expect(second).toMatch(/^[0-9a-f]{64}$/);
    expect(second).not.toBe(first);
    expect(vault.get('PIPEGEN_FP_KEY')).toBe(delivered);   // the vault's delivery key is untouched
    expect(keys.stored()).toEqual({ PIPEGEN_FP_KEY: 'throwaway' });
    expect(keys.mode).toBe('placeholder');
    // the delivered key can never be stored as a "real" value in the scratch repo
    await expect(keys.real(['PIPEGEN_FP_KEY'])).rejects.toThrow(/throwaway key, never the delivered one/);
    // a random source that repeats a value, or gives the delivered key, is refused (nothing sent)
    const fixed = Buffer.alloc(32, 7);
    const rep = keysWorld();
    const k2 = keysFor(rep.g, vaultWith(), { random: () => fixed });
    await k2.throwaway();
    await expect(k2.throwaway()).rejects.toThrow(/not fresh/);
    const v3 = vaultWith();
    generateFpKey(v3);
    const k3 = keysFor(keysWorld().g, v3, { random: () => Buffer.from(v3.get('PIPEGEN_FP_KEY') as string, 'hex') });
    await expect(k3.throwaway()).rejects.toThrow(/equal to the delivered/);
    // the throwaway values join the excerpt scrubber (B1); placeholders too
    await keys.placeholders(['STRIPE_SECRET_KEY']);
    const scrub = keys.scrubber();
    expect(scrub(`a ${first} b ${second} c ${placeholderValue('STRIPE_SECRET_KEY')}`)).not.toMatch(new RegExp(`${first}|${second}|pipegen-placeholder-`));
  });

  it('keys: placeholders and throwaway stored through storeRepoSecret, never the vault', async () => {
    const { g, s } = keysWorld();
    const vault = vaultWith();
    const set = vi.spyOn(vault, 'set');
    const get = vi.spyOn(vault, 'get');
    const keys = keysFor(g, vault);
    await keys.setup(['STRIPE_SECRET_KEY']);
    expect(set).not.toHaveBeenCalled();
    expect(get.mock.calls.map((c) => c[0])).toEqual(['PIPEGEN_FP_KEY']);   // read only to compare, never stored from
    expect(vault.names()).toEqual(['STRIPE_SECRET_KEY']);
    expect([...s.values.keys()].sort()).toEqual(['PIPEGEN_FP_KEY', 'STRIPE_SECRET_KEY']);
    expect(s.values.get('STRIPE_SECRET_KEY')).toBe(placeholderValue('STRIPE_SECRET_KEY'));
    // one public key read and one PUT per value: storeRepoSecret's seal (secrets.ts), through the scratch sink
    expect(g.seen().filter((p) => p.startsWith(`GET ${S_PATH}/public-key`) || p.startsWith(`PUT ${S_PATH}`))).toEqual([
      `GET ${S_PATH}/public-key`, `PUT ${S_PATH}/STRIPE_SECRET_KEY`, `PUT ${S_PATH}/PIPEGEN_FP_KEY`,
    ]);
    // and real values only from the vault, for the names asked
    await keys.real(['STRIPE_SECRET_KEY']);
    expect(s.values.get('STRIPE_SECRET_KEY')).toBe(TYPED);
    expect(keys.mode).toBe('real');
    await expect(keys.real(['NOT_IN_VAULT'])).rejects.toThrow(/no value/);

    // S14: storeRepoSecret is exported for non-vault values, with the same name and value rules (plain Octokit)
    const pk = Buffer.alloc(32, 1).toString('base64');
    const { fetch, calls } = fakeFetch({
      [`GET https://api.github.com/repos/o/r/actions/secrets/public-key`]: { body: { key_id: '1', key: pk } },
      [`PUT https://api.github.com/repos/o/r/actions/secrets/X_KEY`]: { status: 201, body: {} },
    });
    const plain = makeOctokit(fake.githubPat(), { fetch, log: () => {} });
    await storeRepoSecret(plain, { owner: 'o', repo: 'r' }, 'x_key', placeholderValue('X_KEY'));
    expect(calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /repos/o/r/actions/secrets/public-key', 'PUT /repos/o/r/actions/secrets/X_KEY']);
    await expect(storeRepoSecret(plain, { owner: 'o', repo: 'r' }, 'GITHUB_X', placeholderValue('X'))).rejects.toThrow(/GITHUB_/);
    await expect(storeRepoSecret(plain, { owner: 'o', repo: 'r' }, 'X_KEY', 'short')).rejects.toThrow(/too short/);
    await expect(storeRepoSecret(plain, { owner: 'o', repo: '../r' }, 'X_KEY', placeholderValue('X'))).rejects.toThrow(/plain name/);
    expect(calls).toHaveLength(2);
  });
});

describe('E4 scratch keys: deleteAll (S14)', () => {
  it('keys: deleteAll lists secrets from the API and deletes each one', async () => {
    // secrets pipegen never stored in this process (a crashed run's): listed from the API, not from memory
    const { g, s } = keysWorld({}, { OLD_ONE: 'x'.repeat(10), OLD_TWO: 'y'.repeat(10), LEFT_BY_HAND: 'z'.repeat(10) });
    const keys = keysFor(g);
    const deleted = await keys.deleteAll();
    expect(deleted.sort()).toEqual(['LEFT_BY_HAND', 'OLD_ONE', 'OLD_TWO']);
    expect(s.values.size).toBe(0);
    expect(g.seen()).toEqual([
      `GET ${S_PATH}`, `DELETE ${S_PATH}/LEFT_BY_HAND`, `DELETE ${S_PATH}/OLD_ONE`, `DELETE ${S_PATH}/OLD_TWO`, `GET ${S_PATH}`,
      `GET /repos/${OWNER}/${SCRATCH}`,   // then the repo id: the key of the shared key state (E4-R1), read after the deletes (fix round 2, R6)
    ]);
    expect(keys.mode).toBe('none');
    // pages: 150 secrets are read on two pages, all deleted
    const many = Object.fromEntries(Array.from({ length: 150 }, (_, i) => [`K_${i}`, 'v'.repeat(10)]));
    const big = keysWorld({}, many);
    expect(await keysFor(big.g).deleteAll()).toHaveLength(150);
    expect(big.s.values.size).toBe(0);
    // a delete that fails, and one GitHub answers OK but keeps: both named as leftovers; mode counts them as real
    const bad = keysWorld({}, { A_KEY: 'a'.repeat(10), B_KEY: 'b'.repeat(10), C_KEY: 'c'.repeat(10) });
    bad.s.failDelete.set('A_KEY', 500);
    bad.s.sticky.add('B_KEY');
    const kb = keysFor(bad.g);
    const e = await kb.deleteAll().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ScratchKeysError);
    expect((e as ScratchKeysError).leftovers).toEqual(['A_KEY', 'B_KEY']);
    expect(String((e as Error).message)).toMatch(/A_KEY, B_KEY are still there/);
    expect(kb.mode).toBe('real');
    // a list pipegen can't read: an error, never "nothing to delete"
    for (const setup of [(f: typeof bad.s) => { f.listStatus = 403; }, (f: typeof bad.s) => { f.listBody = { [LIST]: [] }; }, (f: typeof bad.s) => { f.listBody = { total_count: 3, [LIST]: [] }; },
      (f: typeof bad.s) => { f.listBody = { total_count: 1, [LIST]: [{ name: '../x' }] }; }]) {
      const w = keysWorld();
      setup(w.s);
      await expect(keysFor(w.g).deleteAll()).rejects.toThrow(/couldn't read the list of secrets/);
      expect(w.g.writes()).toEqual([]);
    }
  });

  it('keys: deleteAll also runs before the first secret is stored', async () => {
    const { g, s } = keysWorld({}, { CRASHED_RUN_KEY: 'q'.repeat(12) });
    const keys = keysFor(g);
    await keys.placeholders(['STRIPE_SECRET_KEY']);
    expect([...s.values.keys()]).toEqual(['STRIPE_SECRET_KEY']);
    const seen = g.seen();
    // the order: list → delete each → list again → the access re-check (reads) → the public key → the store
    expect(seen.slice(0, 4)).toEqual([`GET /repos/${OWNER}/${SCRATCH}`, `GET ${S_PATH}`, `DELETE ${S_PATH}/CRASHED_RUN_KEY`, `GET ${S_PATH}`]);
    expect(seen.indexOf(`GET /repos/${OWNER}/${SCRATCH}/collaborators`)).toBeGreaterThan(2);
    expect(seen.indexOf(`GET ${S_PATH}/public-key`)).toBeGreaterThan(seen.indexOf(`GET /repos/${OWNER}/${SCRATCH}/keys`));
    expect(seen.at(-2)).toBe(`PUT ${S_PATH}/STRIPE_SECRET_KEY`);
    expect(seen.at(-1)).toBe(`GET ${S_PATH}`);   // fix round 1 (E4-R1): GitHub's updated_at recorded right after the store
    // only before the first: the second store lists nothing again
    const n = g.calls.length;
    await keys.placeholders(['OTHER_KEY']);
    expect(g.seen().slice(n).filter((p) => p.startsWith(`DELETE ${S_PATH}`))).toEqual([]);
    expect(g.seen().slice(n).filter((p) => p === `GET ${S_PATH}`)).toHaveLength(1);   // only the updated_at read after the store
    // a pre-store deleteAll that leaves something: nothing is stored
    const w = keysWorld({}, { STUCK: 's'.repeat(10) });
    w.s.failDelete.set('STUCK', 500);
    await expect(keysFor(w.g).placeholders(['STRIPE_SECRET_KEY'])).rejects.toThrow(ScratchKeysError);
    expect(w.g.seen().some((p) => p.startsWith('PUT '))).toBe(false);
  });
});

describe('E4 scratch keys: the access re-check before the store (E1 carries G1, R5)', () => {
  it('every store batch runs checkScratchAccess right before it; a pusher added since E1 stops the store', async () => {
    const { g } = keysWorld();
    const keys = keysFor(g);
    await keys.placeholders(['A_KEY']);
    await keys.real(['STRIPE_SECRET_KEY']);
    const collabReads = g.seen().filter((p) => p === `GET /repos/${OWNER}/${SCRATCH}/collaborators`);
    expect(collabReads).toHaveLength(2);
    // someone got push access after E1: the re-check stops the store, nothing is sent
    const w = keysWorld({ repos: { [SCRATCH]: { private: true, collaborators: [person(OWNER, 1, 'admin'), person('mallory', 66, 'write')] } } });
    await expect(keysFor(w.g).placeholders(['A_KEY'])).rejects.toThrow(/mallory/);
    expect(w.g.seen().some((p) => p.startsWith('PUT '))).toBe(false);
    // the repo was made public since E1: stop
    const pub = keysWorld({ repos: { [SCRATCH]: { private: false } } });
    await expect(keysFor(pub.g).placeholders(['A_KEY'])).rejects.toThrow(ProofStopError);
    expect(pub.g.seen().some((p) => p.startsWith('PUT '))).toBe(false);
  });

  it('the consent set: an answer from E1 is not asked again; a changed set of doubts asks again (default No stops)', async () => {
    const odd = { private: true, collaborators: [person(OWNER, 1, 'admin'), { ...person('carol', 7, 'custom-x'), permissions: { pull: true, push: false, maintain: false, admin: false, triage: false } }] };
    const { g } = keysWorld({ repos: { [SCRATCH]: odd } });
    const t = proofTarget(app());
    const yes = { ...quietIo, prompt: { ...quietIo.prompt, confirm: vi.fn(async () => true) } } as never;
    const e1 = await checkScratchAccess(g.gh, t, yes);
    expect(e1.accepted).toHaveLength(1);
    const confirm = vi.fn(async () => false);
    const keys = new ScratchKeys(g.gh, t, vaultWith(), { io: { ...quietIo, prompt: { ...quietIo.prompt, confirm } } as never, accepted: e1.accepted });
    await keys.placeholders(['A_KEY']);
    expect(confirm).not.toHaveBeenCalled();
    expect(keys.accepted).toEqual(e1.accepted);
    // a second unsure collaborator appears: the key differs, so the prompt comes again; No stops the store
    const two = keysWorld({ repos: { [SCRATCH]: { ...odd, collaborators: [...odd.collaborators, { ...person('dave', 8, 'custom-y'), permissions: { pull: true, push: false, maintain: false, admin: false, triage: false } }] } } });
    const k2 = new ScratchKeys(two.g.gh, proofTarget(app()), vaultWith(), { io: { ...quietIo, prompt: { ...quietIo.prompt, confirm } } as never, accepted: e1.accepted });
    await expect(k2.placeholders(['A_KEY'])).rejects.toThrow(ProofStopError);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(two.g.seen().some((p) => p.startsWith('PUT '))).toBe(false);
  });

  it('scratchSecretSink takes only a fresh, unused checkScratchAccess result (the brand); guardedWrite never writes a secret', async () => {
    const { g } = keysWorld();
    const t = proofTarget(app());
    const s = assertScratch(t, app());
    const access = await checkScratchAccess(g.gh, t, quietIo);
    // look-alikes: a copy, an object made from it, a plain object with the same fields
    for (const fake2 of [{ ...access }, Object.create(access), { scratch: s, warnings: [], accepted: [] }, null, undefined]) {
      expect(() => scratchSecretSink(g.gh, fake2 as never)).toThrow(ScratchGuardError);
    }
    const sink = scratchSecretSink(g.gh, access);
    expect(typeof sink.put).toBe('function');
    // spent: a second store batch needs a new check
    expect(() => scratchSecretSink(g.gh, access)).toThrow(/already used/);
    // too old: a check from more than ACCESS_CHECK_MAX_AGE_MS ago
    vi.useFakeTimers({ toFake: ['Date'] });
    const old = await checkScratchAccess(g.gh, t, quietIo);
    vi.setSystemTime(Date.now() + ACCESS_CHECK_MAX_AGE_MS + 1);
    expect(() => scratchSecretSink(g.gh, old)).toThrow(/too old/);
    const fresh = await checkScratchAccess(g.gh, t, quietIo);
    vi.setSystemTime(Date.now() + ACCESS_CHECK_MAX_AGE_MS);
    expect(() => scratchSecretSink(g.gh, fresh)).not.toThrow();
    vi.useRealTimers();
    // no sink is opened once a stop has begun (and the check is not spent by the refusal)
    const during = await checkScratchAccess(g.gh, t, quietIo);
    vi.mocked(interrupting).mockReturnValue(true);
    expect(() => scratchSecretSink(g.gh, during)).toThrow(/stopping/);
    vi.mocked(interrupting).mockReturnValue(false);
    expect(() => scratchSecretSink(g.gh, during)).not.toThrow();
    // the brand can't be made by anyone else: the issuer was taken by repos.ts at load
    expect(() => takeAccessIssuer()).toThrow(/already taken/);
    // guardedWrite refuses every secret write (repo, environment, Dependabot, Codespaces), on the scratch and central repo
    const c = assertCentral(t, app());
    const before = g.calls.length;
    const writes: [string, Record<string, unknown>][] = [
      ['PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}', { [SN]: 'X', encrypted_value: 'x', key_id: '1' }],
      ['PUT /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { environment_name: 'e', [SN]: 'X', encrypted_value: 'x', key_id: '1' }],
      ['PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}', { [SN]: 'X', encrypted_value: 'x', key_id: '1' }],
      ['PUT /repos/{owner}/{repo}/codespaces/secrets/{secret_name}', { [SN]: 'X', encrypted_value: 'x', key_id: '1' }],
      ['POST /repos/{owner}/{repo}/actions/secrets', {}],
      ['PATCH /repos/{owner}/{repo}/actions/secrets/{secret_name}', { [SN]: 'X' }],
    ];
    for (const r of [s, c]) for (const [route, p] of writes) await expect(guardedWrite(g.gh, r, route, p), `${r.kind} ${route}`).rejects.toThrow(ScratchGuardError);
    // the secret delete only on the scratch repo, only that route
    await expect(deleteScratchSecret(g.gh, c, 'X')).rejects.toThrow(ScratchGuardError);
    expect(g.calls.length).toBe(before);
  });
});

describe('E4 scratch keys: the stop gate and the in-flight writes (E0b carry)', () => {
  it('no store starts once a stop has begun; a stop during a batch sends no further PUT; deleteAll still runs while stopping', async () => {
    const { g, s } = keysWorld();
    const keys = keysFor(g);
    vi.mocked(interrupting).mockReturnValue(true);
    await expect(keys.placeholders(['A_KEY'])).rejects.toThrow(/stopping/);
    expect(g.calls).toEqual([]);
    vi.mocked(interrupting).mockReturnValue(false);
    // the stop begins while the first PUT is answered: the second value is never sent
    s.onPut = () => { vi.mocked(interrupting).mockReturnValue(true); };
    await expect(keys.placeholders(['A_KEY', 'B_KEY'])).rejects.toThrow(ScratchGuardError);
    expect(g.seen().filter((p) => p.startsWith('PUT '))).toEqual([`PUT ${S_PATH}/A_KEY`]);
    // E8's cleanup during the stop: deleteAll still lists and deletes (the one write allowed while stopping)
    expect(interrupting()).toBe(true);
    expect(await keys.deleteAll()).toEqual(['A_KEY']);
    expect(s.values.size).toBe(0);
  });

  it('deleteAll waits for a store of the same keys still in flight (nothing lands after it)', async () => {
    const { g, s } = keysWorld();
    const keys = keysFor(g);
    await keys.placeholders(['A_KEY']);
    const storing = keys.placeholders(['B_KEY']);   // not awaited: the access re-check reads come first, then the PUT
    const deleted = await keys.deleteAll();
    await storing;
    expect(deleted.sort()).toEqual(['A_KEY', 'B_KEY']);
    expect(s.values.size).toBe(0);
    expect(g.seen().lastIndexOf(`PUT ${S_PATH}/B_KEY`)).toBeLessThan(g.seen().lastIndexOf(`DELETE ${S_PATH}/B_KEY`));
  });

  it('every PUT is a tracked write: in flight while it runs, settleWrites waits for it', async () => {
    const { g, s } = keysWorld();
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => { release = r; });
    const seenInFlight: string[][] = [];
    s.onPut = () => { seenInFlight.push(writesInFlight()); };
    const keys = keysFor(g);
    const slow = trackWrite('push of proof/x', () => gate);
    expect(writesInFlight()).toEqual(['push of proof/x']);
    const stored = keys.placeholders(['A_KEY']);
    const settled = settleWrites({ timeoutMs: 5_000 });
    await stored;
    expect(seenInFlight).toEqual([['push of proof/x', 'secret A_KEY']]);
    release();
    await slow;
    expect(await settled).toEqual({ settled: true, pending: [] });
    // a write that never ends: settleWrites gives up at its timeout and names it
    const stuck = trackWrite('merge of PR 3', () => new Promise(() => {}));
    expect(await settleWrites({ timeoutMs: 20 })).toEqual({ settled: false, pending: ['merge of PR 3'] });
    void stuck;
    // no tracked write starts during a stop
    vi.mocked(interrupting).mockReturnValue(true);
    const work = vi.fn(async () => 1);
    await expect(trackWrite('x', work)).rejects.toThrow(ScratchGuardError);
    expect(work).not.toHaveBeenCalled();
  });
});

describe('E4 excerpt evidence (DECISIONS #113)', () => {
  it('minted only for a run window that held placeholders and throwaway keys only; never after a real value', async () => {
    const { g } = keysWorld();
    const keys = keysFor(g);
    // nothing checked yet (no deleteAll): no evidence, the repo may hold a crashed run's real keys
    const early = (await keys.ticket());
    expect((await keys.evidence(early, [1]))).toBeNull();
    await keys.setup(['STRIPE_SECRET_KEY']);
    expect((await keys.evidence(early, [1]))).toBeNull();   // that window began before the repo was known clean
    const t1 = (await keys.ticket());
    const e1 = (await keys.evidence(t1, [1]));
    expect(isExcerptEvidence(e1)).toBe(true);
    expect(isExcerptEvidence({ ...e1 })).toBe(false);
    expect(Object.isFrozen(e1)).toBe(true);
    // a ticket taken before a real store gives no evidence after it, even once placeholders are back
    const t2 = (await keys.ticket());
    await keys.real(['STRIPE_SECRET_KEY']);
    expect((await keys.evidence(t2, [1]))).toBeNull();
    expect((await keys.evidence(await keys.ticket(), [1]))).toBeNull();          // real now
    await keys.placeholders(['STRIPE_SECRET_KEY']);            // switched back (a new AI change, E7)
    expect(keys.mode).toBe('placeholder');
    expect((await keys.evidence(t2, [1]))).toBeNull();                      // that window held the real value
    // E4-R1: a value the user typed was written since the last verified deleteAll, so placeholders over it are not enough
    expect((await keys.evidence(await keys.ticket(), [1]))).toBeNull();
    await keys.deleteAll();
    await keys.placeholders(['STRIPE_SECRET_KEY']);
    const t3 = (await keys.ticket());
    expect(isExcerptEvidence((await keys.evidence(t3, [1])))).toBe(true);   // a window after a verified deleteAll
    // a ticket of another ScratchKeys (both clean, placeholders only, no real store ever), a forged ticket
    const other = keysFor(keysWorld().g);
    await other.placeholders(['A_KEY']);
    expect((await other.evidence(t3, [1]))).toBeNull();
    const third = keysFor(keysWorld().g);
    await third.placeholders(['A_KEY']);
    const tOther = (await other.ticket());
    expect(isExcerptEvidence((await other.evidence(tOther, [1])))).toBe(true);
    expect((await third.evidence(tOther, [1]))).toBeNull();
    expect((await keys.evidence({ ticket: true } as never, [1]))).toBeNull();
    // a deleteAll after the ticket that leaves a secret behind: its value is unknown, no evidence for that window
    const dw = keysWorld();
    const dk = keysFor(dw.g);
    await dk.placeholders(['A_KEY']);
    const td = (await dk.ticket());
    dw.s.failDelete.set('A_KEY', 500);
    await expect(dk.deleteAll()).rejects.toThrow(ScratchKeysError);
    expect((await dk.evidence(td, [1]))).toBeNull();
    // a real batch that fails half-way: the first value may have landed, so the window held it
    const rw = keysWorld();
    const rk = keysFor(rw.g, vaultWith({ A_KEY: TYPED, B_KEY: `${TYPED}-b` }));
    await rk.placeholders(['C_KEY']);
    const tr = (await rk.ticket());
    rw.s.failPut.set('B_KEY', 500);
    await expect(rk.real(['A_KEY', 'B_KEY'])).rejects.toThrow(/Could not store/);
    expect(rw.s.values.get('A_KEY')).toBe(TYPED);
    expect(rk.mode).toBe('real');
    expect((await rk.evidence(tr, [1]))).toBeNull();
    // a placeholder that failed to overwrite a real value: still real, no evidence
    const w = keysWorld();
    const k = keysFor(w.g);
    await k.real(['STRIPE_SECRET_KEY']);
    w.s.failPut.set('STRIPE_SECRET_KEY', 500);
    await expect(k.placeholders(['STRIPE_SECRET_KEY'])).rejects.toThrow(/Could not store/);
    expect(k.mode).toBe('real');
    expect((await k.evidence(await k.ticket(), [1]))).toBeNull();
    // a deleteAll that left something: no evidence until a clean list
    const lw = keysWorld({}, { STUCK: 's'.repeat(10) });
    lw.s.failDelete.set('STUCK', 500);
    const lk = keysFor(lw.g);
    await expect(lk.deleteAll()).rejects.toThrow(ScratchKeysError);
    expect((await lk.evidence(await lk.ticket(), [1]))).toBeNull();
    lw.s.failDelete.clear();
    await lk.deleteAll();
    expect(isExcerptEvidence((await lk.evidence(await lk.ticket(), [1])))).toBe(true);
  });
});

describe('E4 scratch keys: E2 seam and the source', () => {
  it('vault STRIPE_KEY and read stripe_key → one refusal, nothing written', async () => {
    // PL-F2: names that differ only in case are one secret on GitHub; setup refuses before any request, naming both
    const up = ['STRIPE', 'KEY'].join('_');
    const low = up.toLowerCase();
    const { g, s } = keysWorld();
    const keys = keysFor(g, vaultWith({ [up]: TYPED }));
    const before = g.calls.length;
    const err = await keys.setup([up, low]).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(ScratchKeysError);
    expect((err as Error).message).toBe(`${up} and ${low} differ only in case; GitHub keeps one secret for both, so pipegen won't store either.`);
    expect(g.calls.length).toBe(before);
    expect(g.writes()).toEqual([]);
    expect(s.values.size).toBe(0);
    expect(keys.stored()).toEqual({});
  });

  it('the E2 seam (scratchSecretStore) is the real store for pushProofSetup, only for its own scratch repo', async () => {
    const { g, s } = keysWorld();
    const keys = keysFor(g);
    const step = scratchSecretStore(keys, ['STRIPE_SECRET_KEY']);
    await step(keys.scratch, { baseSha: '1'.repeat(40) });
    expect([...s.values.keys()].sort()).toEqual(['PIPEGEN_FP_KEY', 'STRIPE_SECRET_KEY']);
    const otherT = proofTarget(app());
    await expect(step(assertScratch(otherT, app()), { baseSha: '1'.repeat(40) })).rejects.toThrow(ScratchGuardError);
    await expect(step(assertCentral(otherT, app()), { baseSha: '1'.repeat(40) })).rejects.toThrow(ScratchGuardError);
  });

  it('the source: proof code reaches the secret helpers only through the scratch sink; only repos.ts brands an access check', () => {
    const dir = join(import.meta.dirname, '..', 'src', 'proof');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts'))) {
      const src = readFileSync(join(dir, f), 'utf8');
      // the plain-repo helpers of secrets.ts are never imported in src/proof (they take any repo string), nor is the module re-imported under another name
      const imports = [...src.matchAll(/import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*'([^']+)'/g)].filter((m) => (m[2] as string).endsWith('/create/secrets.js'));
      for (const m of imports) expect((m[1] as string).split(',').map((x) => x.trim().replace(/^type\s+/, '')), f).not.toEqual(expect.arrayContaining([expect.stringMatching(/^(?:storeSecrets|storeRepoSecret|storeEnvSecret)\b/)]));
      expect(src, f).not.toMatch(/import\s*\*\s*as\s*\w+\s*from\s*'[^']*create\/secrets\.js'|import\(\s*'[^']*create\/secrets\.js'\s*\)/);
      if (f !== 'keys.ts') expect(src, f).not.toMatch(/\b(?:storeSecretsVia|storeRepoSecretsVia)\s*[(,}]/);
      if (f !== 'keys.ts' && f !== 'target.ts') expect(src, f).not.toMatch(/\bscratchSecretSink\s*\(/);
      if (f !== 'repos.ts' && f !== 'target.ts') expect(src, f).not.toMatch(/\btakeAccessIssuer\b/);
      if (f !== 'keys.ts' && f !== 'target.ts') expect(src, f).not.toMatch(/\bdeleteScratchSecret\b/);
    }
  });
});
