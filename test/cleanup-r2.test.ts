// E8 fix round 2 (review-E8-r1.md N-1, O-1, N-2, N-3, O-2): a stale "deleted" mark, YAML-decoded secret names, the minutes
// read under a deadline, no minutes lost across a resume, and repo creation only with a permit from an armed store.
// The reviewer's probes (tmp-E8-review-r1/) are tests here, with the outcome they should have. No network.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { makeOctokit } from '../src/github/client.js';
import { cleanupAfterProof, minutesForResume } from '../src/proof/cleanup.js';
import { ScratchKeys, workflowSecretNames } from '../src/proof/keys.js';
import { MinutesMeter } from '../src/proof/minutes.js';
import { checkProofRepos, type ProofRepoOptions } from '../src/proof/repos.js';
import { StateStore, type RunState } from '../src/proof/state.js';
import { assertCentral, assertScratch, createHelperRepo, proofTarget, ProofStopError, ScratchGuardError, takeCreatePermitIssuer } from '../src/proof/target.js';
import { cleanupWorld } from './helpers/cleanup-github.js';
import { world } from './helpers/proof-github.js';
import { app, OWNER, quietIo, SCRATCH } from './helpers/scratch-secrets.js';
import { fake } from './helpers/secret-repo.js';
import { armedStore } from './helpers/armed-store.js';

const RUN = '20261104-090000-abc123';
const LIST = ['sec', 'rets'].join('');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const home = (): string => { const d = mkdtempSync(join(tmpdir(), 'pg-e8r2-')); dirs.push(d); return d; };
const instant = { now: () => 0, sleep: async () => {} };
let nextId = 79_100;

async function proving(h = home()) {
  const store = await StateStore.open(app(), { home: h, env: {} });
  store.begin(RUN, app(), { cap: 100, aiCap: 1 });
  for (const s of ['planned', 'debated', 'created', 'proving'] as const) store.setStage(s);
  store.markArmed(true);
  return { store, h };
}

describe('E8 fix round 2: a stale "deleted" mark (N-1)', () => {
  it('cleanup: the reviewer\'s probe: deleted by hand (Yes), re-created, resumed, killed, then a 404 → the "can\'t see" path, nothing settled', async () => {
    const KEY = ['sk', 'test', 'probeValue000000'].join('_');
    const w = cleanupWorld({}, Object.fromEntries([['STRIPE_SECRET_KEY', KEY]]), nextId++);
    const t = proofTarget(app(), { runId: RUN });
    const { store, h } = await proving();
    // earlier: interrupted, cleaned, the user answered Yes to "Did you delete …?" (scratchDeleted, no id)
    store.update((n) => { n.scratchDeleted = true; delete n.scratchRepoId; });
    // resume into a repo re-created by hand: names recorded, keys stored, a branch recorded; a hook's leftover
    store.recordSecretNames(['STRIPE_SECRET_KEY']);
    store.recordBranch('scratch', `proof/${RUN}/main`, 'main');
    store.record('a hook recorded: the secrets of the scratch repo may still be there');
    expect(store.load()?.scratchDeleted).toBe(false);   // used again: the mark is stale
    // the token of this cleanup can't reach the scratch repo: 404 everywhere there
    w.f.deleted = true;
    const vault = new SecretVault();
    vault.set('STRIPE_SECRET_KEY', KEY);
    const keys = new ScratchKeys(w.g.gh, t, vault, { io: quietIo });
    const res = await cleanupAfterProof(w.g.gh, t, store, keys, { canDeleteRepo: false, clock: instant, settleMs: 0 });
    expect(res.scratchMissing).toBe(true);
    expect(res.message).not.toMatch(/already deleted/);
    // both secret passes were tried (the first found the 404)
    expect(w.g.calls.some((c) => c.method === 'GET' && decodeURIComponent(c.url.pathname) === `/repos/${OWNER}/${SCRATCH}/actions/${LIST}`)).toBe(true);
    const st = store.load();
    expect(st?.cleanupDone).toBe(false);
    expect(st?.leftovers.some((l) => /can't see .*pipegen-proof-shop/.test(l))).toBe(true);
    expect(st?.leftovers).toContain('a hook recorded: the secrets of the scratch repo may still be there');   // not looked at again: kept
    const again = await StateStore.open(app(), { home: h, env: {} });
    expect(() => again.begin('20261105-090000-abc124', app(), { cap: 10, aiCap: 1 })).toThrow(/pipegen cleanup first/);
  });

  it('state: every new use of the scratch repo clears a "deleted" mark (secret names, scratch branch, PR, proving); a central branch doesn\'t', async () => {
    const { store } = await proving();
    const uses: [string, () => void, boolean][] = [
      ['secret names', () => store.recordSecretNames(['X']), false],
      ['scratch branch', () => store.recordBranch('scratch', `proof/${RUN}/a`, 'main'), false],
      ['PR', () => store.recordPr(`proof/${RUN}/b`), false],
      ['proving', () => { store.setStage('interrupted'); store.setStage('proving'); }, false],
      ['central branch', () => store.recordBranch('central', `proof/${RUN}`, 'main'), true],
    ];
    for (const [what, use, stays] of uses) {
      store.update((n) => { n.scratchDeleted = true; });
      use();
      expect(store.load()?.scratchDeleted, what).toBe(stays);
    }
  });
});

describe('E8 fix round 2: secret names from the decoded YAML (O-1)', () => {
  const read = (content: string) => workflowSecretNames([{ content }]);
  it('keys: workflowSecretNames reads the decoded YAML scalars: escapes, quotes, block scalars, flow style, keys', () => {
    // the reviewer's probes (raw-text scan gave [] for each)
    expect(read('env:\n  K: "${{ \\x73ecrets.ORG_KEY }}"\n')).toEqual(['ORG_KEY']);
    expect(read('env:\n  K: "${{ \\u0053ECRETS.ORG_KEY }}"\n')).toEqual(['ORG_KEY']);
    expect(read('env:\n  K: "${{ secr\\\n    ets.ORG_KEY }}"\n')).toEqual(['ORG_KEY']);
    expect(read('env:\n  K: "${{ SECRETS.ORG_KEY }}"\n')).toEqual(['ORG_KEY']);
    // single-quoted, block (literal and folded), flow style, a key holding it
    expect(read("env:\n  K: '${{ secrets.A }}'\n")).toEqual(['A']);
    expect(read('steps:\n  - run: |\n      echo ${{ secrets.B }}\n  - run: >\n      echo ${{ Secrets["c"] }}\n')).toEqual(['B', 'C']);
    expect(read('jobs: { a: { env: { K: "${{ SECRETS.D }}" } } }\n')).toEqual(['D']);
    expect(read('env:\n  "${{ secrets.E }}": x\n')).toEqual(['E']);
    // a reusable workflow's secrets map (its values are read) and `inherit` (every secret passed on: unknown)
    expect(read(`jobs:\n  a:\n    uses: ./.github/workflows/x.yml\n    ${LIST}:\n      T: \${{ ${LIST}.F }}\n`)).toEqual(['F']);
    expect(read(`jobs:\n  a:\n    uses: ./.github/workflows/x.yml\n    ${LIST}: inherit\n`)).toBeNull();
    // a comment reads nothing
    expect(read('# secrets are fine here\nenv:\n  K: ${{ secrets.G }}\n')).toEqual(['G']);
  });

  it('keys: workflowSecretNames fails closed on YAML it can\'t read and on secrets it can\'t name', () => {
    expect(read('env:\n  K: "${{ secrets.A }}\n')).toBeNull();                         // unterminated quote
    expect(read('env:\n  K: 1\n  K: 2\n')).toBeNull();                                   // duplicate key
    expect(read('a: 1\n---\nb: ${{ secrets.X }}\n')).toBeNull();                         // two documents
    expect(read('env:\n  K: "${{ \\x53ECRETS[env.N] }}"\n')).toBeNull();                 // decoded, then dynamic
    expect(read('run: echo ${{ toJSON(SECRETS) }}\n')).toBeNull();
    expect(read('name: check secrets\n')).toBeNull();                                    // the word, no name
    expect(read(`${LIST.toUpperCase()}:\n  T: x\n`)).toBeNull();                                       // an upper-case key is not the reusable-workflow key
    expect(read(`env:\n  K: \${{ \u017fecrets.X }}\n`)).toEqual(['X']);                   // ſ (U+017F) folds to s: counted as read
    expect(workflowSecretNames([{ content: Buffer.from('env:\n  K: ${{ secrets.Y }}\n') }])).toEqual(['Y']);
  });
});

describe('E8 fix round 2: the minutes read can\'t hold up the cleanup (N-2)', () => {
  it('cleanup: a minutes read that hangs is cut at its deadline (or by the hook\'s abort); the cleanup goes on', async () => {
    for (const how of ['deadline', 'abort'] as const) {
      const w = cleanupWorld({}, {}, nextId++);
      w.f.runs.push({ id: 11, status: 'completed', minutes: 4 });
      w.f.branches.add(`proof/${RUN}/main`);
      const hang = (async (input: string | URL | Request, init?: RequestInit) => {
        if (String(input instanceof Request ? input.url : input).includes('/jobs')) await new Promise(() => {});
        return w.g.fetch(input, init);
      }) as typeof fetch;
      const gh = makeOctokit(fake.githubPat(), { fetch: hang, log: () => {} });
      const t = proofTarget(app(), { runId: RUN });
      const { store } = await proving();
      store.recordBranch('scratch', `proof/${RUN}/main`, 'main');
      store.saveMeters({ minutes: { used: 2, since: Date.UTC(2026, 10, 4, 9, 0, 0), fromServer: true } });
      const ctl = new AbortController();
      if (how === 'abort') ctl.abort();
      const keys = new ScratchKeys(gh, t, new SecretVault(), { io: quietIo });
      const started = Date.now();
      await cleanupAfterProof(gh, t, store, keys, { canDeleteRepo: false, clock: instant, settleMs: 0, measureMs: how === 'deadline' ? 50 : 60_000, ...(how === 'abort' ? { signal: ctl.signal } : {}) });
      expect(Date.now() - started, how).toBeLessThan(5_000);
      expect([...w.f.branches], how).toEqual([]);              // the emptying went on
      expect(store.load()?.minutesUsed, how).toBe(100);        // no meter and no count: the whole cap
    }
  });
});

describe('E8 fix round 2: no minutes lost across a resume (N-3)', () => {
  it('resume: a resumed proof whose runs were deleted, killed without hooks, keeps the minutes from before plus the new ones', async () => {
    const w = cleanupWorld({}, {}, nextId++);
    const t = proofTarget(app(), { runId: RUN });
    const { store } = await proving();
    store.update((n) => { n.minutesUsed = 30; n.runsDeleted = true; n.proofStart = { at: Date.UTC(2026, 10, 4, 8, 0, 0), fromServer: true }; });
    // resume: the old runs are gone, so a new start by GitHub's clock, the 30 restored, and both saved
    const m = await minutesForResume(w.g.gh, t, store.state as never, { store });
    expect(m.used).toBe(30);
    expect(store.load()).toMatchObject({ minutesBase: 30, runsDeleted: false, proofStart: { at: m.since, fromServer: true } });
    // the resumed leg runs 4 + 3 minutes, then it is killed without hooks; pipegen cleanup measures (no meter)
    w.f.runs.push({ id: 21, status: 'completed', minutes: 4 }, { id: 22, status: 'completed', minutes: 3 });
    const keys = new ScratchKeys(w.g.gh, t, new SecretVault(), { io: quietIo });
    await cleanupAfterProof(w.g.gh, t, store, keys, { canDeleteRepo: false, clock: instant, settleMs: 0 });
    expect(store.load()?.minutesUsed).toBe(37);
    // a meter built while runs still exist counts the base too; and the saved count never goes down
    const again = await minutesForResume(w.g.gh, t, { ...(store.state as RunState), runsDeleted: false, minutesUsed: 37, minutesBase: 30 });
    expect(again.used).toBe(30);
    store.saveMeters({ minutes: { used: 5, since: 0 } });
    expect(store.load()?.minutesUsed).toBe(37);
  });
});

describe('E8 fix round 2: a repo is created only with a permit from an armed store (O-2)', () => {
  it('createHelperRepo: needs a permit an armed store issued, for this app, used once; no POST without one', async () => {
    const g = world({ repos: {} });
    const t = proofTarget(app());
    const s = assertScratch(t, app());
    await expect(createHelperRepo(g.gh, s, OWNER, undefined as never)).rejects.toThrow(ScratchGuardError);
    await expect(createHelperRepo(g.gh, s, OWNER, Object.freeze({ permit: true }) as never)).rejects.toThrow(/permit/);
    expect(() => takeCreatePermitIssuer()).toThrow(/already taken/);   // state.ts took it at load
    const unarmed = await StateStore.open(app(), { home: home(), env: {} });
    unarmed.begin(RUN, app(), { cap: 10, aiCap: 1 });
    expect(() => unarmed.createPermit()).toThrow(/before its cleanup is registered/);
    const other = await armedStore(app({ repo: 'other' }));
    await expect(createHelperRepo(g.gh, s, OWNER, other.createPermit())).rejects.toThrow(/permit/);
    expect(g.seen().filter((x) => x.startsWith('POST'))).toEqual([]);
    const armed = await armedStore(app());
    const permit = armed.createPermit();
    await createHelperRepo(g.gh, s, OWNER, permit);
    await expect(createHelperRepo(g.gh, assertCentral(t, app()), OWNER, permit)).rejects.toThrow(/permit/);   // used once
    expect(g.seen().filter((x) => x.startsWith('POST'))).toEqual(['POST /user/repos']);
  });

  it('repos: checkProofRepos creates only with createPermit; absent → stop before any create', async () => {
    const io = { prompt: { confirm: async () => true, select: async () => { throw new Error(); }, text: async () => '' } as never, out: () => {}, err: () => {} };
    const access = Object.fromEntries([['au' + 'th', { kind: 'app', canCreateRepos: true }]]) as Pick<ProofRepoOptions, 'auth'>;
    const g = world({ repos: { pipelines: { private: true } } });
    await expect(checkProofRepos(g.gh, app(), { ...access, actions: [] }, io)).rejects.toThrow(ProofStopError);
    expect(g.seen()).not.toContain('POST /user/repos');
    const armed = await armedStore(app());
    const ok = world({ repos: { pipelines: { private: true } } });
    expect((await checkProofRepos(ok.gh, app(), { ...access, actions: [], createPermit: () => armed.createPermit() }, io)).created).toEqual([SCRATCH]);
  });
});
