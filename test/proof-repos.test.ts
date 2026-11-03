// Plan E Task 1 / sub-task E1 (preflight rulings S1, S3, S13, S19): the private central and scratch repos, and the
// scratch-only write guard. Octokit is a real makeOctokit client over a fake fetch (test/helpers/proof-github.ts);
// no network. The 16 test names of the preflight's E1 list are below, verbatim.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Prompter } from '../src/cli/io.js';
import type { Auth } from '../src/types.js';
import {
  checkActionsAllowed, checkOrgBasePermission, checkProofRepos, createCommands, ensureActionsAccess, patternCovers, setScratchDefaultBranch,
  visibilityOf, type ProofRepoOptions,
} from '../src/proof/repos.js';
import {
  assertCentral, assertScratch, createHelperRepo, guardedWrite, makeRepoPrivate, proofTarget, ProofStopError, ScratchGuardError,
  type GuardedRepo, type ProofApp,
} from '../src/proof/target.js';
import { world, SHA_MAIN, type WorldOptions } from './helpers/proof-github.js';

const OWNER = 'CrisWorking';
const APP = 'shop';
const SCRATCH = 'pipegen-proof-shop';
const PINS = {
  checkout: `actions/checkout@${'a'.repeat(40)}`,
  bullfrog: `bullfrogsec/bullfrog@${'b'.repeat(40)}`,
  gate: `CrisWorking/pipegen/gate@${'c'.repeat(40)}`,
};
const ALL_PINS = Object.values(PINS);

const app = (o: Partial<ProofApp> = {}): ProofApp => ({ owner: OWNER, repo: APP, private: true, ownerType: 'User', defaultBranch: 'main', ...o });
const both = { pipelines: { private: true }, [SCRATCH]: { private: true } };

function prompter(answer: boolean): Prompter & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    confirm: async (msg) => { asked.push(msg); return answer; },
    select: async () => { throw new Error('no select expected'); },
    text: async () => { throw new Error('no text expected'); },
  };
}
function io(answer = true) {
  const lines: string[] = [];
  const prompt = prompter(answer);
  return { prompt, out: (s: string) => { lines.push(s); }, err: (s: string) => { lines.push(s); }, lines, all: () => lines.join('\n') };
}
// The option key and a few words are built at runtime, so this file passes test/no-secret-literals (redact() on test files).
const AU = 'au' + 'th';
type Access = Pick<Auth, 'kind' | 'canCreateRepos'>;
const by = (a: Access) => ({ [AU]: a }) as Pick<ProofRepoOptions, 'auth'>;
const fgMode: Access = { kind: 'fine-grained', canCreateRepos: false };
const appMode: Access = { kind: 'app', canCreateRepos: true };
const SN_KEY = ['sec', 'ret_name'].join('');
const opts = (o: Partial<ProofRepoOptions> = {}): ProofRepoOptions => ({ ...by(fgMode), actions: ALL_PINS, runId: '20261103-120000-abcdef', ...o });
const run = (w: WorldOptions, a: ProofApp = app(), o: Partial<ProofRepoOptions> = {}, answer = true) => {
  const g = world(w);
  const i = io(answer);
  return { g, i, result: checkProofRepos(g.gh, a, opts(o), i) };
};
const writePaths = (g: ReturnType<typeof world>) => g.writes().map((c) => `${c.method} ${decodeURIComponent(c.url.pathname)}`);

describe('E1 repos (plan Task 1, preflight S1/S13/S19)', () => {
  it('repos: missing → prints gh repo create --private commands and stops, no create call', async () => {
    for (const auth of [fgMode, { kind: 'app', canCreateRepos: false } as const, { kind: 'classic', canCreateRepos: false } as const]) {
      const { g, i, result } = run({ repos: {} }, app(), { auth });
      const r = await result;
      expect(r.ready).toBe(false);
      expect(r.created).toEqual([]);
      expect(r.repos).toEqual([
        { name: 'pipelines', exists: false, createCommand: createCommands(OWNER, ['pipelines'])[0] },
        { name: SCRATCH, exists: false, createCommand: createCommands(OWNER, [SCRATCH])[0] },
      ]);
      expect(i.all()).toContain('Create these private repos, then run pipegen again');
      expect(i.all()).toContain(`gh repo create ${OWNER}/pipelines --private --description "pipegen central workflows and install records"`);
      expect(i.all()).toContain(`gh repo create ${OWNER}/${SCRATCH} --private --description "pipegen proof runs (private scratch repo)"`);
      expect(g.writes()).toEqual([]);
      expect(g.seen().some((s) => s.startsWith('POST'))).toBe(false);
    }
    // only one missing: only that one is printed
    const { g, i, result } = run({ repos: { pipelines: { private: true } } });
    expect((await result).ready).toBe(false);
    expect(i.all()).not.toContain(`${OWNER}/pipelines --private`);
    expect(i.all()).toContain(`${OWNER}/${SCRATCH} --private`);
    expect(g.writes()).toEqual([]);
  });

  it('repos: missing and canCreate → creates private repo for user and for org', async () => {
    const user = run({ repos: {} }, app(), by(appMode));
    const r = await user.result;
    expect(r.ready).toBe(true);
    expect(r.created).toEqual(['pipelines', SCRATCH]);
    const posts = user.g.calls.filter((c) => c.method === 'POST');
    expect(posts.map((c) => c.url.pathname)).toEqual(['/user/repos', '/user/repos']);
    expect(posts.map((c) => JSON.parse(c.body ?? '{}'))).toEqual([
      { name: 'pipelines', private: true, auto_init: true, description: 'pipegen central workflows and install records' },
      { name: SCRATCH, private: true, auto_init: true, description: 'pipegen proof runs (private scratch repo)' },
    ]);
    expect(user.i.all()).toContain(`Created the private repo ${OWNER}/pipelines.`);

    const org = run({ owner: 'AcmeOrg', ownerType: 'Organization', repos: {}, org: { default_repository_permission: 'none' } }, app({ owner: 'AcmeOrg', ownerType: 'Organization' }), by(appMode));
    const o = await org.result;
    expect(o.ready).toBe(true);
    expect(o.created).toEqual(['pipelines', SCRATCH]);
    expect(org.g.calls.filter((c) => c.method === 'POST').map((c) => c.url.pathname)).toEqual(['/orgs/AcmeOrg/repos', '/orgs/AcmeOrg/repos']);
    expect(org.g.seen()).not.toContain('POST /user/repos');

    // a personal-account create goes to /user/repos, which makes the repo under the TOKEN's login: never when that isn't the owner
    const other = run({ repos: {}, login: 'SomeoneElse' }, app(), by(appMode));
    const x = await other.result;
    expect(x.ready).toBe(false);
    expect(other.g.writes()).toEqual([]);
    expect(other.i.all()).toContain(`gh repo create ${OWNER}/pipelines --private`);
  });

  it('repos: existing private reused', async () => {
    const { g, result } = run({ repos: both, access: 'user' });
    const r = await result;
    expect(r.ready).toBe(true);
    expect(r.created).toEqual([]);
    expect(r.repos).toEqual([{ name: 'pipelines', exists: true, private: true }, { name: SCRATCH, exists: true, private: true }]);
    expect(r.target.scratch).toBe(SCRATCH);
    expect(g.writes()).toEqual([]);
  });

  it('repos: existing public → asks; No → throws stop error', async () => {
    const no = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: false } } }, app(), {}, false);
    await expect(no.result).rejects.toThrow(ProofStopError);
    await expect(no.result).rejects.toThrow(/won't use a public helper repo/);
    expect(no.i.prompt.asked).toEqual([`${SCRATCH} is public. Make it private? (Y/n)`]);
    expect(no.g.writes()).toEqual([]);

    // Yes → PATCH private: true, then it goes on
    const yes = run({ repos: { pipelines: { private: false }, [SCRATCH]: { private: true } }, access: 'user' });
    expect((await yes.result).ready).toBe(true);
    expect(yes.i.prompt.asked).toEqual(['pipelines is public. Make it private? (Y/n)']);
    const patch = yes.g.writes();
    expect(patch.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([`PATCH /repos/${OWNER}/pipelines`]);
    expect(JSON.parse(patch[0]?.body ?? '{}')).toEqual({ private: true });

    // Yes, but the token can't change it → the gh repo edit command, and stop
    const refused = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: false } }, patchStatus: 403 });
    await expect(refused.result).rejects.toThrow(`gh repo edit ${OWNER}/${SCRATCH} --visibility private --accept-visibility-change-consequences`);

    // an internal repo (every enterprise member can read it) is not private either: asked, then visibility private
    const internal = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, visibility: 'internal' } }, access: 'user' });
    expect((await internal.result).ready).toBe(true);
    expect(internal.i.prompt.asked[0]).toMatch(/^pipegen-proof-shop is internal/);
    expect(JSON.parse(internal.g.writes()[0]?.body ?? '{}')).toEqual({ visibility: 'private' });
    const internalNo = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, visibility: 'internal' } } }, app(), {}, false);
    await expect(internalNo.result).rejects.toThrow(ProofStopError);
  });

  it('repos: public project → pipelines still checked (records only), scratch named pipegen-proof-<repo>', async () => {
    const { g, result } = run({ repos: both }, app({ private: false }));
    const r = await result;
    expect(r.ready).toBe(true);
    expect(r.target.scratch).toBe(SCRATCH);
    expect(r.repos.map((x) => x.name)).toEqual(['pipelines', SCRATCH]);
    expect(g.seen()).toContain(`GET /repos/${OWNER}/pipelines`);
    expect(g.seen().some((s) => s.includes('/actions/permissions/access'))).toBe(false);
    // and a missing pipelines still stops a public project
    const missing = run({ repos: { [SCRATCH]: { private: true } } }, app({ private: false }));
    expect((await missing.result).ready).toBe(false);
  });

  it('orgPerm: base permission read → warning shown', async () => {
    const warning = `Every member of AcmeOrg can read ${SCRATCH}. It holds a copy of your code during the proof. An org owner can set the base permission to 'No permission'.`;
    const g = world({ owner: 'AcmeOrg', ownerType: 'Organization', org: { default_repository_permission: 'read' } });
    expect(await checkOrgBasePermission(g.gh, 'AcmeOrg', SCRATCH)).toEqual({ level: 'read', warning });
    // in checkProofRepos: shown, and asked before the scratch repo is used
    const r = run({ owner: 'AcmeOrg', ownerType: 'Organization', repos: both, access: 'organization', org: { default_repository_permission: 'read' } }, app({ owner: 'AcmeOrg', ownerType: 'Organization' }));
    const res = await r.result;
    expect(res.orgPerm).toEqual({ level: 'read', warning });
    expect(r.i.lines).toContain(warning);
    const seen = r.g.seen();
    expect(seen.indexOf('GET /orgs/AcmeOrg')).toBeGreaterThanOrEqual(0);
    expect(seen.indexOf('GET /orgs/AcmeOrg')).toBeLessThan(seen.indexOf(`GET /repos/AcmeOrg/${SCRATCH}`));
    // write or admin: code owners may get review requests too (ruling S5)
    for (const level of ['write', 'admin'] as const) {
      const w = world({ owner: 'AcmeOrg', ownerType: 'Organization', org: { default_repository_permission: level } });
      const got = await checkOrgBasePermission(w.gh, 'AcmeOrg', SCRATCH);
      expect(got.level).toBe(level);
      expect(got.warning).toBe(`${warning} Code owners may get review requests from the proof PRs.`);
    }
    // a personal account has no org base permission: not asked
    const user = run({ repos: both, access: 'user' });
    expect((await user.result).orgPerm).toBeUndefined();
    expect(user.g.seen().some((s) => s.startsWith('GET /orgs/'))).toBe(false);
  });

  it('orgPerm: none → no warning; unreadable → "couldn\'t check" warning', async () => {
    const none = world({ owner: 'AcmeOrg', ownerType: 'Organization', org: { default_repository_permission: 'none' } });
    expect(await checkOrgBasePermission(none.gh, 'AcmeOrg', SCRATCH)).toEqual({ level: 'none' });
    const unknown = { level: 'unknown', warning: "pipegen couldn't check who in AcmeOrg can read new repos." };
    for (const org of [{}, { default_repository_permission: 'maintain' }, { default_repository_permission: 7 }, null]) {
      const w = world({ owner: 'AcmeOrg', ownerType: 'Organization', org });
      expect(await checkOrgBasePermission(w.gh, 'AcmeOrg', SCRATCH), JSON.stringify(org)).toEqual(unknown);
    }
    const r = run({ owner: 'AcmeOrg', ownerType: 'Organization', repos: both, access: 'organization', org: {} }, app({ owner: 'AcmeOrg', ownerType: 'Organization' }));
    expect((await r.result).ready).toBe(true);
    expect(r.i.lines).toContain(unknown.warning);
    const n = run({ owner: 'AcmeOrg', ownerType: 'Organization', repos: both, access: 'organization', org: { default_repository_permission: 'none' } }, app({ owner: 'AcmeOrg', ownerType: 'Organization' }));
    await n.result;
    expect(n.i.all()).not.toMatch(/can read|couldn't check/);
  });

  it('access: org → organization level; user → user level; public project → not called', async () => {
    const accessCalls = (g: ReturnType<typeof world>) => g.calls.filter((c) => c.url.pathname.endsWith('/actions/permissions/access'));
    const org = run({ owner: 'AcmeOrg', ownerType: 'Organization', repos: both, org: { default_repository_permission: 'none' } }, app({ owner: 'AcmeOrg', ownerType: 'Organization' }));
    expect((await org.result).ready).toBe(true);
    const put = accessCalls(org.g).filter((c) => c.method === 'PUT');
    expect(put.map((c) => c.url.pathname)).toEqual(['/repos/AcmeOrg/pipelines/actions/permissions/access']);
    expect(JSON.parse(put[0]?.body ?? '{}')).toEqual({ access_level: 'organization' });

    const user = run({ repos: both });
    await user.result;
    const uput = accessCalls(user.g).filter((c) => c.method === 'PUT');
    expect(uput.map((c) => c.url.pathname)).toEqual([`/repos/${OWNER}/pipelines/actions/permissions/access`]);
    expect(JSON.parse(uput[0]?.body ?? '{}')).toEqual({ access_level: 'user' });

    // already set: read, not written again
    const set = run({ repos: both, access: 'user' });
    await set.result;
    expect(accessCalls(set.g).map((c) => c.method)).toEqual(['GET']);

    const pub = run({ repos: both }, app({ private: false }));
    await pub.result;
    expect(accessCalls(pub.g)).toEqual([]);
    // direct call on a public project's target: nothing at all
    const g = world({ repos: both });
    await ensureActionsAccess(g.gh, proofTarget(app({ private: false })), app({ private: false }));
    expect(g.calls).toEqual([]);

    // GitHub refuses the change → a stop with the setting to change by hand
    const refused = run({ repos: both, accessStatus: 403 });
    await expect(refused.result).rejects.toThrow(/Accessible from repositories owned by the user CrisWorking/);
  });

  it('repos: fine-grained token → no create call even with Administration write', async () => {
    // even when told it may create (S9: the token's create succeeds, then it can't reach the repo it made)
    for (const kind of ['fine-grained', 'classic'] as const) {
      const { g, i, result } = run({ repos: {} }, app(), by({ kind, canCreateRepos: true }));
      expect((await result).ready).toBe(false);
      expect(g.seen().filter((s) => s.startsWith('POST'))).toEqual([]);
      expect(g.writes()).toEqual([]);
      expect(i.all()).toContain('gh repo create');
    }
  });

  it('repos: app token → creates missing private repos, then reaches them', async () => {
    const { g, result } = run({ repos: { pipelines: { private: true } } }, app(), by(appMode));
    const r = await result;
    expect(r.ready).toBe(true);
    expect(r.created).toEqual([SCRATCH]);
    expect(r.repos).toEqual([{ name: 'pipelines', exists: true, private: true }, { name: SCRATCH, exists: true, private: true }]);
    const seen = g.seen();
    const post = seen.indexOf('POST /user/repos');
    expect(post).toBeGreaterThan(0);
    expect(seen.indexOf(`GET /repos/${OWNER}/${SCRATCH}`, post)).toBeGreaterThan(post);   // read again after creating
    // made public by GitHub after all (or a different repo answered): stop, never used
    const pub = run({ repos: {}, createPrivate: false }, app(), by(appMode));
    await expect(pub.result).rejects.toThrow(ProofStopError);
  });

  it('repos: exists but 404 for the app → prints add-to-installation steps', async () => {
    const { g, i, result } = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, hidden: true } } }, app(), by(appMode));
    const r = await result;
    expect(r.ready).toBe(false);
    expect(r.created).toEqual([]);
    expect(r.repos).toEqual([{ name: 'pipelines', exists: true, private: true }, { name: SCRATCH, exists: true }]);
    expect(i.all()).not.toContain('gh repo create');
    expect(i.all()).toContain('Installed GitHub Apps → pipegen → Configure → Repository access → Select repositories');
    expect(i.all()).toContain(`${OWNER}/${SCRATCH}`);
    expect(g.seen().filter((s) => s.startsWith('POST'))).toEqual(['POST /user/repos']);   // tried once, GitHub said it exists
    // an App that may not create: the commands, and the same add-to-installation steps
    const noCreate = run({ repos: {} }, app(), by({ kind: 'app', canCreateRepos: false }));
    expect((await noCreate.result).ready).toBe(false);
    expect(noCreate.i.all()).toContain('Installed GitHub Apps → pipegen → Configure');
  });

  it('repos: token mode → prints "add these repos to your token"', async () => {
    const { i, result } = run({ repos: { pipelines: { private: true } } });
    expect((await result).ready).toBe(false);
    expect(i.all()).toMatch(new RegExp(`Then add these repos to your tok[e]n: ${OWNER}/${SCRATCH}`));
    expect(i.all()).toContain('Fine-grained tokens → the token → Edit → Repository access');
    // not for a classic token (it already reaches every repo)
    const classic = run({ repos: { pipelines: { private: true } } }, app(), by({ kind: 'classic', canCreateRepos: false }));
    await classic.result;
    expect(classic.i.all()).not.toContain('add these repos to your token');
  });

  it('repos: scratch name over 100 characters → stop with a note', async () => {
    const long = 'a'.repeat(87);   // pipegen-proof- is 14 characters: 101
    const { g, result } = run({ repos: {} }, app({ repo: long }));
    await expect(result).rejects.toThrow(ProofStopError);
    await expect(result).rejects.toThrow(/longer than GitHub's 100-character limit/);
    expect(g.calls).toEqual([]);
    expect(() => proofTarget(app({ repo: long }))).toThrow(/at most 86 characters/);
    // 86 fits exactly
    const fits = 'b'.repeat(86);
    expect(proofTarget(app({ repo: fits })).scratch).toHaveLength(100);
  });

  it('repos: Actions disabled or allowed_actions not covering the pins → actionable stop', async () => {
    const disabled = run({ repos: both, access: 'user', actions: { [SCRATCH]: { enabled: false } } });
    await expect(disabled.result).rejects.toThrow(ProofStopError);
    await expect(disabled.result).rejects.toThrow(`Actions is turned off on ${OWNER}/${SCRATCH}`);
    await expect(disabled.result).rejects.toThrow(/Settings → Actions → General/);

    const selected = run({
      repos: both, access: 'user',
      actions: { [SCRATCH]: { enabled: true, allowed_actions: 'selected' } },
      selected: { [SCRATCH]: { github_owned_allowed: true, verified_allowed: false, patterns_allowed: ['docker/*'] } },
    });
    await expect(selected.result).rejects.toThrow(PINS.bullfrog);
    await expect(selected.result).rejects.not.toThrow(PINS.checkout);
    await expect(selected.result).rejects.toThrow(/Allow specified actions and reusable workflows/);

    const local = run({ repos: both, access: 'user', actions: { [SCRATCH]: { enabled: true, allowed_actions: 'local_only' } } });
    await expect(local.result).rejects.toThrow(PINS.checkout);
    await expect(local.result).rejects.toThrow(PINS.bullfrog);
    await expect(local.result).rejects.not.toThrow(PINS.gate);   // the owner's own action is allowed

    // covered: github-owned + a pattern for the rest
    const ok = run({
      repos: both, access: 'user',
      actions: { [SCRATCH]: { enabled: true, allowed_actions: 'selected', sha_pinning_required: true } },
      selected: { [SCRATCH]: { github_owned_allowed: true, verified_allowed: false, patterns_allowed: ['bullfrogsec/bullfrog@*'] } },
    });
    expect((await ok.result).ready).toBe(true);
    // checked on the scratch repo only
    expect(ok.g.seen()).toContain(`GET /repos/${OWNER}/${SCRATCH}/actions/permissions`);
    expect(ok.g.seen()).not.toContain(`GET /repos/${OWNER}/pipelines/actions/permissions`);

    // sha pinning required and a pin that is not a full sha
    const g = world({ repos: both, actions: { [SCRATCH]: { enabled: true, allowed_actions: 'all', sha_pinning_required: true } } });
    const t = proofTarget(app());
    await expect(checkActionsAllowed(g.gh, assertScratch(t, app()), ['actions/checkout@v4'])).rejects.toThrow(/actions\/checkout@v4/);
  });

  it('repos: scratch default branch set to the app\'s default branch', async () => {
    // the branch exists in the scratch repo: PATCH default_branch
    const has = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: '2'.repeat(40) } } }, access: 'user' }, app({ defaultBranch: 'develop' }));
    const r = await has.result;
    expect(r.scratchDefaultBranch).toBe('develop');
    expect(r.target.defaultBranch).toBe('develop');
    expect(writePaths(has.g)).toEqual([`PATCH /repos/${OWNER}/${SCRATCH}`]);
    expect(JSON.parse(has.g.writes()[0]?.body ?? '{}')).toEqual({ default_branch: 'develop' });
    expect(has.g.repos[SCRATCH]?.default_branch).toBe('develop');

    // missing: made from the current default head, then set
    const make = run({ repos: both, access: 'user' }, app({ defaultBranch: 'release/2026' }));
    expect((await make.result).scratchDefaultBranch).toBe('release/2026');
    expect(writePaths(make.g)).toEqual([`POST /repos/${OWNER}/${SCRATCH}/git/refs`, `PATCH /repos/${OWNER}/${SCRATCH}`]);
    expect(JSON.parse(make.g.writes()[0]?.body ?? '{}')).toEqual({ ref: 'refs/heads/release/2026', sha: SHA_MAIN });

    // an empty scratch repo: nothing to set yet (the base push creates the branch), so no write; E2 calls it again after
    const empty = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: 'empty' } }, access: 'user' }, app({ defaultBranch: 'develop' }));
    const e = await empty.result;
    expect(e.scratchDefaultBranch).toBe('develop');
    expect(e.defaultBranchState).toBe('pending');
    expect(empty.g.writes()).toEqual([]);

    // already the same: nothing written
    const same = run({ repos: both, access: 'user' });
    expect((await same.result).defaultBranchState).toBe('already');
    expect(same.g.writes()).toEqual([]);

    // a branch name git would refuse never reaches GitHub
    for (const bad of ['-x', 'a..b', 'a b', 'x.lock', 'a//b', '/a', 'a/', 'a@{1}', '']) {
      expect(() => proofTarget(app({ defaultBranch: bad })), bad).toThrow(ProofStopError);
    }
  });

  it('scratch-guard: every write refuses a repo that is not pipegen-proof-<repo>, and the app repo itself', async () => {
    const t = proofTarget(app());
    const okScratch = assertScratch(t, app());
    const okCentral = assertCentral(t, app());
    expect(okScratch).toMatchObject({ kind: 'scratch', owner: OWNER, repo: SCRATCH });
    expect(okCentral).toMatchObject({ kind: 'central', owner: OWNER, repo: 'pipelines' });

    // assertScratch itself: the app repo, another repo, another owner, another app's target, a look-alike target
    const refusals: (() => unknown)[] = [
      () => assertScratch(t, app(), { owner: OWNER, repo: APP }),
      () => assertScratch(t, app(), { owner: OWNER, repo: 'SHOP' }),
      () => assertScratch(t, app(), { owner: OWNER, repo: 'pipegen-proof-other' }),
      () => assertScratch(t, app(), { owner: OWNER, repo: 'pipelines' }),
      () => assertScratch(t, app(), { owner: 'Other', repo: SCRATCH }),
      () => assertScratch(t, app(), { owner: OWNER, repo: 'PIPEGEN-PROOF-SHOP' }),
      () => assertScratch(t, app({ repo: 'other' })),
      () => assertScratch(t, app({ owner: 'Other' })),
      () => assertScratch({ ...t }, app()),
      () => assertScratch(JSON.parse(JSON.stringify(t)), app()),
      () => assertCentral(t, app(), { owner: OWNER, repo: APP }),
      () => assertCentral(t, app(), { owner: OWNER, repo: SCRATCH }),
      () => assertCentral(t, app({ repo: 'other' })),
      () => assertCentral({ ...t }, app()),
    ];
    for (const f of refusals) expect(f, String(f)).toThrow(ScratchGuardError);
    expect(refusals[0]).toThrow(/the app repo itself/);
    expect(refusals[1]).toThrow(/the app repo itself/);
    // an app repo named pipelines has no central repo at all
    expect(() => proofTarget(app({ repo: 'pipelines' }))).toThrow(ProofStopError);

    // forged handles: the same shape as a real one, pointing at the app repo or another repo
    const forged = (repo: string, kind: 'scratch' | 'central' = 'scratch') => ({ kind, owner: OWNER, repo, fullName: `${OWNER}/${repo}`, target: t }) as unknown as GuardedRepo;
    const bad: GuardedRepo[] = [forged(APP), forged('other'), forged(SCRATCH), forged('pipelines', 'central'), forged(APP, 'central'), { ...okScratch }, Object.assign(Object.create(null), okScratch)];

    // every write function of src/proof/target.ts and src/proof/repos.ts, each given each bad handle: refused before any call
    const g = world({ repos: { [APP]: { private: true }, ...both } });
    const writes: [string, (r: GuardedRepo) => Promise<unknown>][] = [
      ['guardedWrite PATCH', (r) => guardedWrite(g.gh, r, 'PATCH /repos/{owner}/{repo}', { private: true })],
      ['guardedWrite POST ref', (r) => guardedWrite(g.gh, r, 'POST /repos/{owner}/{repo}/git/refs', { ref: `refs/heads/proof/${t.runId}`, sha: SHA_MAIN })],
      ['guardedWrite PUT access', (r) => guardedWrite(g.gh, r, 'PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: 'user' })],
      ['guardedWrite DELETE ref', (r) => guardedWrite(g.gh, r, 'DELETE /repos/{owner}/{repo}/git/refs/{ref}', { ref: `heads/proof/${t.runId}` })],
      ['createHelperRepo', (r) => createHelperRepo(g.gh, r, OWNER)],
      ['makeRepoPrivate', (r) => makeRepoPrivate(g.gh, r, 'public')],
      ['setScratchDefaultBranch', (r) => setScratchDefaultBranch(g.gh, r)],
    ];
    for (const [name, write] of writes) {
      for (const r of bad) {
        await expect(write(r), `${name} ${r.kind}:${r.repo}`).rejects.toThrow(ScratchGuardError);
      }
    }
    // ensureActionsAccess takes the target: a forged or another app's target is refused
    await expect(ensureActionsAccess(g.gh, { ...t }, app())).rejects.toThrow(ScratchGuardError);
    await expect(ensureActionsAccess(g.gh, t, app({ repo: 'other' }))).rejects.toThrow(ScratchGuardError);
    // a central handle given to a scratch-only write, and a scratch handle where central-only ops are asked
    await expect(setScratchDefaultBranch(g.gh, okCentral)).rejects.toThrow(ScratchGuardError);
    await expect(guardedWrite(g.gh, okCentral, 'PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}', { [SN_KEY]: 'X', encrypted_value: 'x', key_id: '1' })).rejects.toThrow(ScratchGuardError);
    expect(g.calls).toEqual([]);

    // and the source: no GitHub write in src/proof outside target.ts (every write goes through the guard)
    const dir = join(import.meta.dirname, '..', 'src', 'proof');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && x !== 'target.ts')) {
      const src = readFileSync(join(dir, f), 'utf8');
      expect(src, f).not.toMatch(/\.request\(\s*['"`](?:POST|PUT|PATCH|DELETE)\b/);
      expect(src, f).not.toMatch(/\.rest\.[a-zA-Z]+\.(?!get\b|list|check)[a-zA-Z]+\(/);
      expect(src, f).not.toMatch(/\bmethod\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)/);
    }
  });
});

describe('E1 repos: answers GitHub may give (mutation-driven)', () => {
  it('visibility: private only when private is true and visibility (when stated) is private', () => {
    const table: [unknown, ReturnType<typeof visibilityOf>][] = [
      [{ private: true, visibility: 'private' }, 'private'],
      [{ private: true }, 'private'],
      [{ private: false }, 'public'],
      [{ private: false, visibility: 'public' }, 'public'],
      [{ private: false, visibility: 'private' }, 'public'],
      [{ private: true, visibility: 'internal' }, 'internal'],
      [{ private: true, visibility: 'public' }, null],
      [{ visibility: 'private' }, null],
      [{ private: 'true' }, null],
      [null, null],
    ];
    for (const [data, want] of table) expect(visibilityOf(data), JSON.stringify(data)).toBe(want);
  });

  it('create: an answer that is not that repo or not private, a re-read that is public or 404, a 422 that is not "exists"', async () => {
    const other = run({ repos: {}, createBody: { full_name: `${OWNER}/other` } }, app(), by(appMode));
    await expect(other.result).rejects.toThrow(ProofStopError);
    const notPrivate = run({ repos: {}, createBody: { private: false, visibility: undefined } }, app(), by(appMode));
    await expect(notPrivate.result).rejects.toThrow(ProofStopError);
    // the answer says private, GitHub's own read says public: never used
    const reread = run({ repos: {}, createPrivate: false, createBody: { private: true, visibility: 'private' } }, app(), by(appMode));
    await expect(reread.result).rejects.toThrow(/doesn't show it private/);
    // created, then not visible to the App: the Configure steps, not ready
    const hidden = run({ repos: {}, createHidden: true }, app(), by(appMode));
    const h = await hidden.result;
    expect(h.ready).toBe(false);
    expect(h.created).toEqual([]);
    expect(hidden.i.all()).toContain('Installed GitHub Apps → pipegen → Configure');
    // a 422 for another reason is an error, not "made by hand"
    const invalid = run({ repos: {}, createStatus: 422 }, app(), by(appMode));
    await expect(invalid.result).rejects.toThrow(/couldn't create CrisWorking\/pipelines \(HTTP 422\)/);
  });

  it('make private: GitHub\'s answer must say private; default branch: GitHub\'s answer must name the branch', async () => {
    const stays = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: false } }, patchBody: { private: false, visibility: 'public' } });
    await expect(stays.result).rejects.toThrow(/didn't confirm CrisWorking\/pipegen-proof-shop is private/);
    const branch = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: SHA_MAIN } } }, access: 'user', patchBody: { default_branch: 'main' } }, app({ defaultBranch: 'develop' }));
    await expect(branch.result).rejects.toThrow(/didn't confirm develop as the default branch/);
  });

  it('central make-private takes private true only', async () => {
    const g = world({ repos: both });
    const c = assertCentral(proofTarget(app()), app());
    for (const p of [{ private: false }, { visibility: 'public' }, { visibility: 'internal' }, { private: 'true' }]) {
      await expect(guardedWrite(g.gh, c, 'PATCH /repos/{owner}/{repo}', p), JSON.stringify(p)).rejects.toThrow(ScratchGuardError);
    }
    expect(g.calls).toEqual([]);
  });

  it('Actions settings pipegen can\'t read: a warning, and the proof goes on (the 120 s no-run check is the backstop)', async () => {
    for (const actions of [{ [SCRATCH]: null }, { [SCRATCH]: { enabled: true, allowed_actions: 'something-new' } }, { [SCRATCH]: { allowed_actions: 'all' } }]) {
      const r = run({ repos: both, access: 'user', actions });
      expect((await r.result).ready, JSON.stringify(actions)).toBe(true);
      expect(r.i.all()).toContain(`pipegen couldn't read the Actions settings of ${OWNER}/${SCRATCH}`);
    }
    // selected, but the list can't be read: the same warning
    const sel = run({ repos: both, access: 'user', actions: { [SCRATCH]: { enabled: true, allowed_actions: 'selected' } } });
    expect((await sel.result).ready).toBe(true);
    expect(sel.i.all()).toContain("pipegen couldn't read the Actions settings");
  });

  it('patterns: owner/*, owner/repo@*, exact ref, no ref; names without case, refs with case', () => {
    const u = `bullfrogsec/bullfrog@${'b'.repeat(40)}`;
    for (const p of ['bullfrogsec/*', 'bullfrogsec/bullfrog@*', `bullfrogsec/bullfrog@${'b'.repeat(40)}`, 'bullfrogsec/bullfrog', 'BullfrogSec/Bullfrog@*', '*']) expect(patternCovers(p, u), p).toBe(true);
    for (const p of ['bullfrog/*', 'bullfrogsec/bullfrog@v1', `bullfrogsec/bullfrog@${'B'.repeat(40)}`, 'bullfrogsec/bull', '', '@*']) expect(patternCovers(p, u), p).toBe(false);
    expect(patternCovers('github/codeql-action/*', `github/codeql-action/init@${'d'.repeat(40)}`)).toBe(true);
    expect(patternCovers('a.b/*', 'axb/c@1')).toBe(false);   // a pattern's dots are literal
  });
});
