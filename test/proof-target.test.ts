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
    // final review I-1: the one ref the API makes on the scratch repo is its default branch (setScratchDefaultBranch)
    await guardedWrite(g.gh, s, 'POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/main', sha: SHA_MAIN });
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

// Final review I-1 (ruling E-F1): the scratch guard admitted writes that skip checkProofWorkflows (the reviewer's probe,
// tmp-final-review/probe-guard.test.ts). The scratch repo now takes exactly the writes pipegen makes; every workflow reaches
// it only through a git push of a commit buildProofBranch checked. The empty commit and the forced reset of the default
// branch exist only as cleanupWrite ops.
describe('final review I-1: the scratch guard takes only the writes pipegen makes', () => {
  const RUN_ID = '20261103-120000-abcdef';
  const sha = 'a'.repeat(40);

  it('refuses (nothing sent) every write that could put an unchecked workflow or setting in the scratch repo', async () => {
    const g = world({ repos: both });
    const s = assertScratch(proofTarget(app(), { runId: RUN_ID }), app());
    const refused: [string, Record<string, unknown>][] = [
      // the probe's shapes
      ['PUT /repos/{owner}/{repo}/contents/{path}', { path: '.github/workflows/evil.yml', message: 'x', content: 'eA==', branch: 'main' }],
      ['POST /repos/{owner}/{repo}/git/blobs', { content: 'on: push', encoding: 'utf-8' }],
      ['POST /repos/{owner}/{repo}/git/trees', { tree: [] }],
      ['POST /repos/{owner}/{repo}/git/commits', { message: 'x', tree: 'a'.repeat(40), parents: [] }],
      ['PATCH /repos/{owner}/{repo}/git/refs/{ref}', { ref: 'heads/main', sha, force: true }],
      ['PUT /repos/{owner}/{repo}/environments/{environment_name}', { environment_name: 'prod' }],
      ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve', { run_id: 1 }],
      // the same families, other shapes
      ['DELETE /repos/{owner}/{repo}/contents/{path}', { path: 'README.md', message: 'x', sha }],
      ['PUT /repos/{owner}/{repo}/contents/{path}', { path: 'README.md', message: 'x', content: 'eA==' }],
      ['POST /repos/{owner}/{repo}/git/tags', { tag: 'v1', message: 'x', object: sha, type: 'commit' }],
      ['PATCH /repos/{owner}/{repo}/git/refs/{ref}', { ref: `heads/proof/${RUN_ID}/main`, sha }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: `refs/heads/proof/${RUN_ID}/x`, sha }],   // pushes make proof branches, never the API
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/tags/v1', sha }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/main', sha, extra: 1 }],
      ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/main', sha: 'HEAD' }],
      ['DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: `heads/proof/${RUN_ID}/main` }],   // cleanupWrite's
      ['DELETE /repos/{owner}/{repo}/environments/{environment_name}', { environment_name: 'prod' }],
      ['POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', { environment_name: 'prod', name: 'main' }],
      ['PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable', { workflow_id: 7 }],   // would undo the safety net
      ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun', { run_id: 1 }],
      ['POST /repos/{owner}/{repo}/actions/jobs/{job_id}/rerun', { job_id: 1 }],
      ['DELETE /repos/{owner}/{repo}/actions/runs/{run_id}', { run_id: 1 }],                       // cleanupWrite's
      ['DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}', { cache_id: 1 }],                 // cleanupWrite's
      ['PUT /repos/{owner}/{repo}/vulnerability-alerts', {}],
      ['POST /repos/{owner}/{repo}/code-scanning/sarifs', { commit_sha: sha, ref: 'refs/heads/main', sarif: 'x' }],
      ['POST /repos/{owner}/{repo}/pulls', { title: 't', head: 'other', base: 'main', body: 'b' }],
      ['POST /repos/{owner}/{repo}/pulls', { title: 't', head: `proof/${RUN_ID}/main`, base: 'other', body: 'b' }],
      ['POST /repos/{owner}/{repo}/pulls', { title: 't', head: 'proof/20261103-120000-ffffff/main', base: 'main', body: 'b' }],
      ['POST /repos/{owner}/{repo}/pulls', { title: 't', head: `proof/${RUN_ID}/main`, base: 'main', body: 'b', maintainer_can_modify: true }],
      ['DELETE /repos/{owner}/{repo}/actions/variables/{name}', { name: 'MY_KEY', extra: 1 }],
      ['PATCH /repos/{owner}/{repo}/pulls/{pull_number}', { pull_number: 3, base: 'other' }],
      ['PATCH /repos/{owner}/{repo}/pulls/{pull_number}', { pull_number: 3, state: 'open' }],
      ['PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', { pull_number: 3, sha, merge_method: 'merge', commit_message: 'x' }],
      ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel', { run_id: 1, extra: 1 }],
      ['PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable', { workflow_id: 7, extra: 1 }],
      ['DELETE /repos/{owner}/{repo}/automated-security-fixes', { extra: 1 }],
      ['PUT /repos/{owner}/{repo}/automated-security-fixes', {}],
    ];
    for (const [route, params] of refused) {
      await expect(guardedWrite(g.gh, s, route, params), `${route} ${JSON.stringify(params)}`).rejects.toThrow(ScratchGuardError);
    }
    expect(g.calls).toEqual([]);
  });

  /** Every write route src/proof sends through guardedWrite on the scratch repo, with the parameters its caller sends. */
  const used: [string, Record<string, unknown>][] = [
    ['PATCH /repos/{owner}/{repo}', { allow_forking: false }],                                         // repos.ts
    ['PATCH /repos/{owner}/{repo}', { description: 'pipegen proof scratch repo' }],                     // repos.ts (the marker; checked below)
    ['PATCH /repos/{owner}/{repo}', { default_branch: 'main' }],                                       // repos.ts setScratchDefaultBranch
    ['PATCH /repos/{owner}/{repo}', { private: true }],                                                // target.ts makeRepoPrivate
    ['PATCH /repos/{owner}/{repo}', { visibility: 'private' }],
    ['POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/main', sha }],                         // repos.ts setScratchDefaultBranch
    ['POST /repos/{owner}/{repo}/pulls', { title: 't', head: `proof/${RUN_ID}/main`, base: 'main', body: 'b' }],   // run.ts openProofPr
    ['PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge', { pull_number: 3, sha, merge_method: 'merge' }],      // run.ts mergeProofPr
    ['PATCH /repos/{owner}/{repo}/pulls/{pull_number}', { pull_number: 3, state: 'closed' }],                     // run.ts closeProofPr
    ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel', { run_id: 12 }],                                  // run.ts cancelRuns
    ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/force-cancel', { run_id: 12 }],                            // run.ts cancelRuns
    ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs', { run_id: 12 }],                       // run.ts rerunFailedJobs
    ['DELETE /repos/{owner}/{repo}/automated-security-fixes', {}],                                     // snapshot.ts
    ['PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable', { workflow_id: 7 }],         // snapshot.ts disableUserWorkflows
    ['POST /repos/{owner}/{repo}/actions/variables', { name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-03' }],        // E4-R2's declared variable
    ['PATCH /repos/{owner}/{repo}/actions/variables/{name}', { name: 'PIPEGEN_BLOCK_FROM', value: '2026-11-03' }],
    ['DELETE /repos/{owner}/{repo}/actions/variables/{name}', { name: 'MY_KEY' }],
  ];

  it('every write route pipegen calls on the scratch repo still passes the guard', async () => {
    const g = world({ repos: both });
    const s = assertScratch(proofTarget(app(), { runId: RUN_ID }), app());
    const { SCRATCH_MARKER } = await import('../src/proof/target.js');
    for (const [route, params0] of used) {
      const params = params0.description === undefined ? params0 : { description: SCRATCH_MARKER };
      await guardedWrite(g.gh, s, route, params).catch((e: unknown) => { if (e instanceof ScratchGuardError) throw new Error(`${route}: ${e.message}`); });
    }
    expect(g.calls).toHaveLength(used.length);
  });

  it('source scan: every write route src/proof sends through guardedWrite is one the test above covers', async () => {
    const { readFileSync, readdirSync } = await import('node:fs');
    const dir = new URL('../src/proof/', import.meta.url);
    const covered = new Set(used.map(([r]) => r));
    const found = new Set<string>();
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && x !== 'target.ts')) {
      const src = readFileSync(new URL(f, dir), 'utf8');
      for (const m of src.matchAll(/['`]((?:POST|PUT|PATCH|DELETE) \/repos\/\{owner\}\/\{repo\}[^'`]*)['`]/g)) {
        const r = m[1] as string;
        // run.ts cancelRuns: `…/${what}` with what = cancel | force-cancel
        for (const x of r.includes('${what}') ? [r.replace('${what}', 'cancel'), r.replace('${what}', 'force-cancel')] : [r]) found.add(x);
      }
    }
    // the reads and the central repo's writes are not scratch writes
    for (const r of ['PUT /repos/{owner}/{repo}/actions/permissions/access']) found.delete(r);
    expect([...found].filter((r) => !covered.has(r))).toEqual([]);
    expect(found.size).toBeGreaterThanOrEqual(10);
  });

  it('the empty commit and the forced reset of the default branch go only through cleanupWrite (cleanup mode)', async () => {
    const { cleanupWrite } = await import('../src/proof/target.js');
    const g = world({ repos: both, extra: (c) => (c.method === 'POST' && c.url.pathname.endsWith('/git/commits')
      ? { status: 201, body: { sha: 'b'.repeat(40), tree: { sha: '4b825dc642cb6eb9a060e54bf8d69288fbee4904' }, parents: [] } }
      : undefined) });
    const s = assertScratch(proofTarget(app(), { runId: RUN_ID }), app());
    await expect(guardedWrite(g.gh, s, 'POST /repos/{owner}/{repo}/git/commits', { message: 'pipegen: scratch repo emptied after the proof', tree: '4b825dc642cb6eb9a060e54bf8d69288fbee4904', parents: [] })).rejects.toThrow(ScratchGuardError);
    expect(g.calls).toEqual([]);
    const made = await cleanupWrite(g.gh, s, { op: 'empty-commit' });
    await cleanupWrite(g.gh, s, { op: 'reset-default-branch', sha: (made.data as { sha: string }).sha }).catch((e: unknown) => { if (e instanceof ScratchGuardError) throw e; });
    expect(g.seen()).toEqual([`POST /repos/${OWNER}/${SCRATCH}/git/commits`, `PATCH /repos/${OWNER}/${SCRATCH}/git/refs/heads/main`]);
  });
});
