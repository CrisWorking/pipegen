// Plan E E1 (ruling S3): the scratch-only write guard in src/proof/target.ts, the one way src/proof writes to GitHub.
// Octokit is a real makeOctokit client over a fake fetch; the sticky interrupting() gate is mocked (raising a real stop
// would end the test worker). No network.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { pushUrl } from '../src/proof/git.js';
import { checkProofRepos, type ProofRepoOptions } from '../src/proof/repos.js';
import {
  assertCentral, assertScratch, createHelperRepo, guardedWrite, isProofTarget, newRunId, proofTarget, ScratchGuardError, scratchPushUrl,
  ProofStopError, type ProofApp,
} from '../src/proof/target.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { armedStore } from './helpers/armed-store.js';
import { world, SHA_MAIN } from './helpers/proof-github.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));
afterEach(() => { vi.mocked(interrupting).mockReturnValue(false); });

const OWNER = 'CrisWorking';
const SCRATCH = 'pipegen-proof-shop';
const app = (o: Partial<ProofApp> = {}): ProofApp => ({ owner: OWNER, repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main', ...o });
const ARMED = await armedStore(app());   // E8 fix round 2 (O-2): createHelperRepo needs a permit from an armed store
const both = { pipelines: { private: true }, [SCRATCH]: { private: true }, shop: { private: true } };

describe('E1 proof target and runId', () => {
  it('target: frozen, branded, names derived from the app; runId YYYYMMDD-HHMMSS-<6 hex>', () => {
    const t = proofTarget(app({ defaultBranch: 'develop', ownerType: 'Organization', owner: 'AcmeOrg' }), { runId: '20261103-120000-abcdef' });
    expect(t).toEqual({ owner: 'AcmeOrg', appRepo: 'shop', scratch: SCRATCH, central: 'pipelines', defaultBranch: 'develop', ownerType: 'Organization', appPrivate: true, runId: '20261103-120000-abcdef' });
    expect(Object.isFrozen(t)).toBe(true);
    expect(isProofTarget(t)).toBe(true);
    expect(isProofTarget({ ...t })).toBe(false);
    expect(newRunId(new Date(Date.UTC(2026, 10, 3, 7, 5, 9)), Uint8Array.from([0xab, 0x01, 0xff]))).toBe('20261103-070509-ab01ff');
    expect(proofTarget(app()).runId).toMatch(/^\d{8}-\d{6}-[0-9a-f]{6}$/);
    for (const bad of ['2026-1103-120000-abcdef', '20261103-120000-ABCDEF', '20261103-120000-abcde', '../x']) {
      expect(() => proofTarget(app(), { runId: bad }), bad).toThrow(ProofStopError);
    }
    // EMU logins (name_shortcode) stay refused until E9, as in client.ts and git.ts
    expect(() => proofTarget(app({ owner: 'alice_acme' }))).toThrow();
    expect(() => proofTarget(app({ repo: 'a b' }))).toThrow();
  });

  it('push URL: the guarded handle gives git.ts\'s checked URL, scratch or central', () => {
    const t = proofTarget(app());
    expect(scratchPushUrl(assertScratch(t, app()))).toBe(pushUrl(OWNER, 'shop', 'scratch'));
    expect(scratchPushUrl(assertCentral(t, app()))).toBe(pushUrl(OWNER, 'shop', 'central'));
    expect(() => scratchPushUrl({ kind: 'scratch', owner: OWNER, repo: 'shop', fullName: `${OWNER}/shop`, target: t } as never)).toThrow(ScratchGuardError);
  });
});

describe('E1 guardedWrite (S3)', () => {
  it('scratch: writes under /repos/{owner}/{repo} go out with the guarded owner and repo', async () => {
    const g = world({ repos: both });
    const s = assertScratch(proofTarget(app()), app());
    await guardedWrite(g.gh, s, 'POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/proof/x', sha: SHA_MAIN });
    expect(g.seen()).toEqual([`POST /repos/${OWNER}/${SCRATCH}/git/refs`]);
  });

  it('refuses a route outside the repo, a read, reserved params and dot segments, before any call', async () => {
    const g = world({ repos: both });
    const t = proofTarget(app());
    const s = assertScratch(t, app());
    const bad: [string, Record<string, unknown>][] = [
      ['GET /repos/{owner}/{repo}', {}],
      ['POST /user/repos', { name: 'x' }],
      ['DELETE /repos/{owner}/{repo}', {}],                                     // a repo delete is E8's (exact name + created marker)
      ['PATCH /repos/{owner}/{repo}', { private: false }],
      ['PATCH /repos/{owner}/{repo}', { visibility: 'public' }],
      ['PATCH /repos/{owner}/{repo}', { name: 'shop' }],
      ['PATCH /repos/{owner}/{repo}', { private: true, owner: OWNER }],
      ['PATCH /repos/{owner}/{repo}', { private: true, repo: 'shop' }],
      ['PATCH /repos/{owner}/{repo}', { private: true, baseUrl: 'https://example.com' }],
      ['PATCH /repos/{owner}/{repo}', { private: true, headers: { 'x-a': '1' } }],
      ['PATCH /repos/{owner}/{repo}', { private: true, request: {} }],
      ['PATCH /repos/{owner}/{repo}', { private: true, url: '/repos/CrisWorking/shop' }],
      ['PATCH /repos/{owner}/{repo}', { private: true, data: '{}' }],
      ['PATCH /repos/{owner}/{repo}', { private: true, mediaType: {} }],
      ['PATCH /repos/{owner}/{repo}', { private: true, method: 'DELETE' }],
      ['POST /repos/{owner}/{repo}/transfer', { new_owner: 'x' }],
      ['POST /repos/{owner}/{repo}/forks', {}],
      ['PUT /repos/{owner}/{repo}/collaborators/{username}', { username: 'x' }],
      ['POST /repos/{owner}/{repo}/hooks', { config: {} }],
      ['POST /repos/{owner}/{repo}/keys', { key: 'x' }],
      ['POST /repos/{owner}/{repo}/dispatches', { event_type: 'x' }],
      ['POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches', { workflow_id: 'a.yml', ref: 'main' }],
      ['PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'user' }],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: '..' }],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'heads/../../x' }],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', {}],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'heads/a b' }],
      ['DELETE /repos/{owner}/{repo}/../shop/git/refs/x', {}],
      ['DELETE /repos/{owner}/{repo}//git', {}],
      ['DELETE /repos/{owner}/{repo}/git/refs/heads%2Fx', {}],
      ['DELETE /repos/{owner}/shop/git/refs', {}],
      ['delete /repos/{owner}/{repo}/git/refs/x', {}],
    ];
    // reserved Octokit options on a route whose body isn't key-limited
    for (const extra of [{ baseUrl: 'https://example.com' }, { owner: 'Other' }, { repo: 'shop' }, { headers: { 'x-a': '1' } }, { url: '/repos/CrisWorking/shop/git/refs' }, { method: 'DELETE' }, { request: {} }, { mediaType: { format: 'raw' } }, { data: '{}' }]) {
      bad.push(['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/x', sha: SHA_MAIN, ...extra }]);
    }
    for (const [route, params] of bad) {
      await expect(guardedWrite(g.gh, s, route, params), `${route} ${JSON.stringify(params)}`).rejects.toThrow(ScratchGuardError);
    }
    expect(g.calls).toEqual([]);
  });

  it('central (pipelines): only make-private, the Actions access level of this owner type, and refs/heads/proof/<runId>', async () => {
    const g = world({ repos: both });
    const t = proofTarget(app(), { runId: '20261103-120000-abcdef' });
    const c = assertCentral(t, app());
    const allowed: [string, Record<string, unknown>][] = [
      ['PATCH /repos/{owner}/{repo}', { private: true }],
      ['PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'user' }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/proof/20261103-120000-abcdef', sha: SHA_MAIN }],
      ['PATCH /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'heads/proof/20261103-120000-abcdef', sha: SHA_MAIN, force: true }],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'heads/proof/20261103-120000-abcdef' }],
    ];
    for (const [route, params] of allowed) await guardedWrite(g.gh, c, route, params).catch((e: unknown) => { if (e instanceof ScratchGuardError) throw e; });
    expect(g.writes()).toHaveLength(allowed.length);

    const refused: [string, Record<string, unknown>][] = [
      ['PATCH /repos/{owner}/{repo}', { default_branch: 'main' }],
      ['PATCH /repos/{owner}/{repo}', { visibility: 'private' }],   // ruling M1: { private: true } only
      ['PATCH /repos/{owner}/{repo}', { allow_forking: false }],
      ['PATCH /repos/{owner}/{repo}', { description: 'pipegen central workflows and install records' }],
      ['PATCH /repos/{owner}/{repo}', { private: true, default_branch: 'main' }],
      ['PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'organization' }],
      ['PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'none' }],
      ['PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'user', extra: 1 }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/main', sha: SHA_MAIN }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/proof/20261103-120000-abcdeg', sha: SHA_MAIN }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/proof/20261103-120000-abcdef/x', sha: SHA_MAIN }],
      ['PATCH /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'heads/main', sha: SHA_MAIN, force: true }],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'tags/proof/20261103-120000-abcdef' }],
      ['PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}', { ['secret' + '_name']: 'X', encrypted_value: 'x', key_id: '1' }],
      ['PUT /repos/{owner}/{repo}/contents/{path}', { path: 'x', message: 'x', content: 'eA==' }],
      ['PUT /repos/{owner}/{repo}/actions/permissions', { enabled: true }],
    ];
    const before = g.calls.length;
    for (const [route, params] of refused) {
      await expect(guardedWrite(g.gh, c, route, params), `${route} ${JSON.stringify(params)}`).rejects.toThrow(ScratchGuardError);
    }
    expect(g.calls.length).toBe(before);
    // an organisation's central repo takes the organization level only
    const org = proofTarget(app({ owner: 'AcmeOrg', ownerType: 'Organization' }));
    const oc = assertCentral(org, app({ owner: 'AcmeOrg', ownerType: 'Organization' }));
    await expect(guardedWrite(g.gh, oc, 'PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'user' })).rejects.toThrow(ScratchGuardError);
  });

  it('no write starts once a stop has begun (interrupting)', async () => {
    const g = world({ repos: both });
    const t = proofTarget(app());
    vi.mocked(interrupting).mockReturnValue(true);
    await expect(guardedWrite(g.gh, assertScratch(t, app()), 'PATCH /repos/{owner}/{repo}', { private: true })).rejects.toThrow(/stopping/);
    await expect(createHelperRepo(g.gh, assertScratch(t, app()), OWNER, ARMED.createPermit())).rejects.toThrow(/stopping/);
    expect(g.calls).toEqual([]);
  });

  it('the stop is checked before every attempt: a stop that begins during the rate-limit wait sends no retry (I1)', async () => {
    const t = proofTarget(app());
    const clock = () => ({ budget: newRateBudget(), sleep: async () => { vi.mocked(interrupting).mockReturnValue(true); } });
    const g = world({ repos: both, rateLimitOnce: `PATCH /repos/${OWNER}/${SCRATCH}` });
    await expect(guardedWrite(g.gh, assertScratch(t, app()), 'PATCH /repos/{owner}/{repo}', { private: true }, clock())).rejects.toThrow(/refused a GitHub write: pipegen is stopping/);
    expect(g.seen()).toEqual([`PATCH /repos/${OWNER}/${SCRATCH}`]);
    vi.mocked(interrupting).mockReturnValue(false);
    const c = world({ repos: {}, rateLimitOnce: 'POST /user/repos' });
    await expect(createHelperRepo(c.gh, assertScratch(t, app()), OWNER, ARMED.createPermit(), clock())).rejects.toThrow(ScratchGuardError);
    expect(c.seen()).toEqual(['POST /user/repos']);
    // without the stop, the same wait retries once and the write goes through
    vi.mocked(interrupting).mockReturnValue(false);
    const ok = world({ repos: both, rateLimitOnce: `PATCH /repos/${OWNER}/${SCRATCH}` });
    await guardedWrite(ok.gh, assertScratch(t, app()), 'PATCH /repos/{owner}/{repo}', { private: true }, { budget: newRateBudget(), sleep: async () => {} });
    expect(ok.seen()).toEqual([`PATCH /repos/${OWNER}/${SCRATCH}`, `PATCH /repos/${OWNER}/${SCRATCH}`]);
  });

  it('createHelperRepo: only the two helper names, under the owner, checked private in GitHub\'s answer', async () => {
    const g = world({ repos: {} });
    const t = proofTarget(app());
    const made = await createHelperRepo(g.gh, assertScratch(t, app()), OWNER, ARMED.createPermit());
    expect(made).toMatchObject({ full_name: `${OWNER}/${SCRATCH}`, private: true });
    // a personal account: /user/repos makes the repo under the token's login, so it must be the owner
    await expect(createHelperRepo(g.gh, assertCentral(t, app()), 'someone-else', ARMED.createPermit())).rejects.toThrow(ScratchGuardError);
    await expect(createHelperRepo(g.gh, assertCentral(t, app()), null, ARMED.createPermit())).rejects.toThrow(ScratchGuardError);
    expect(g.seen()).toEqual(['POST /user/repos']);
    // GitHub's answer names another repo or says public: a stop
    const pub = world({ repos: {}, createPrivate: false });
    await expect(createHelperRepo(pub.gh, assertScratch(t, app()), OWNER, ARMED.createPermit())).rejects.toThrow(ProofStopError);
  });

  it('a renamed repo GitHub answers for (another full_name) is never used', async () => {
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, fullName: `${OWNER}/shop` } } });
    const io = { prompt: { confirm: async () => true, select: async () => { throw new Error(); }, text: async () => '' } as never, out: () => {}, err: () => {} };
    await expect(checkProofRepos(g.gh, app(), { ...({ ['au' + 'th']: { kind: 'fine-grained', canCreateRepos: false } } as Pick<ProofRepoOptions, 'auth'>), actions: [] }, io)).rejects.toThrow(/renamed or transferred/);
    expect(g.writes()).toEqual([]);
  });
});
