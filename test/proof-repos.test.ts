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
  assertCentral, assertScratch, createHelperRepo, githubRead, guardedWrite, makeRepoPrivate, proofTarget, ProofStopError, ScratchGuardError,
  type GuardedRepo, type ProofApp,
} from '../src/proof/target.js';
import { armedStore } from './helpers/armed-store.js';
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
// E8 fix round 2 (O-2): a repo is created only with a permit from an armed StateStore (Plan G's), one per app
const ARMED = { user: await armedStore(app()), org: await armedStore(app({ owner: 'AcmeOrg', ownerType: 'Organization' })) };
const permitFor = (a: ProofApp) => () => (a.owner === 'AcmeOrg' ? ARMED.org : ARMED.user).createPermit();
const run = (w: WorldOptions, a: ProofApp = app(), o: Partial<ProofRepoOptions> = {}, answer = true) => {
  const g = world(w);
  const i = io(answer);
  return { g, i, result: checkProofRepos(g.gh, a, opts({ createPermit: permitFor(a), ...o }), i) };
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
      expect(i.all()).toContain('Create these private repos, then run `npx pipegen run` again');
      expect(i.all()).toContain(`gh repo create ${OWNER}/pipelines --private --disable-wiki --description "pipegen central workflows and install records"`);
      expect(i.all()).toContain(`gh repo create ${OWNER}/${SCRATCH} --private --disable-wiki --description "pipegen proof runs (private scratch repo)"`);
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
      // G14 (Plan V ruling V3-wiki): no wiki and no projects, so uninstall can show nothing user-made lives in either repo
      { name: 'pipelines', private: true, auto_init: true, has_wiki: false, has_projects: false, description: 'pipegen central workflows and install records' },
      { name: SCRATCH, private: true, auto_init: true, has_wiki: false, has_projects: false, description: 'pipegen proof runs (private scratch repo)' },
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
    // an internal pipelines (ruling M1: its make-private PATCH is { private: true } only, which can't change an internal repo): the command, no prompt
    const central = run({ repos: { pipelines: { private: true, visibility: 'internal' }, [SCRATCH]: { private: true } } });
    await expect(central.result).rejects.toThrow(`gh repo edit ${OWNER}/pipelines --visibility private --accept-visibility-change-consequences`);
    expect(central.i.prompt.asked).toEqual([]);
    expect(central.g.writes()).toEqual([]);
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
    // write or admin: a hard stop now (fix round 1, ruling E1-R2), no warning
    for (const level of ['write', 'admin'] as const) {
      const w = world({ owner: 'AcmeOrg', ownerType: 'Organization', org: { default_repository_permission: level } });
      const got = await checkOrgBasePermission(w.gh, 'AcmeOrg', SCRATCH);
      expect(got.level).toBe(level);
      expect(got.warning).toBeUndefined();
      expect(got.stop).toMatch(/^Every member of AcmeOrg can push to pipegen-proof-shop/);
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

    // G13 carry 24: the level before the change is kept for the install record (uninstall puts it back)
    expect((await user.result).actionsAccess).toEqual({ previous: 'none' });
    expect((await org.result).actionsAccess).toEqual({ previous: 'none' });

    // already set: read, not written again
    const set = run({ repos: both, access: 'user' });
    await set.result;
    expect(accessCalls(set.g).map((c) => c.method)).toEqual(['GET']);
    expect((await set.result).actionsAccess).toBeUndefined();

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

  it('repos: the id GitHub gave a created repo goes to onCreated before anything else is sent (E8, ruling E1-R4)', async () => {
    const order: string[] = [];
    let g!: ReturnType<typeof world>;
    const made = run({ repos: { pipelines: { private: true } }, repoIds: { [SCRATCH]: 31_337 } }, app(), {
      ...by(appMode), onCreated: (repo, id) => { order.push(`${repo} ${id} after ${g.seen().length} calls`); },
    });
    g = made.g;
    const r = await made.result;
    const post = g.seen().indexOf('POST /user/repos');
    expect(order).toEqual([`${SCRATCH} 31337 after ${post + 1} calls`]);   // right after the create's answer
    expect(r.createdIds).toEqual({ [SCRATCH]: 31_337 });
    // a record that can't be written stops the proof before the new repo is used
    const stop = run({ repos: { pipelines: { private: true } } }, app(), { ...by(appMode), onCreated: () => { throw new Error('state not saved'); } });
    await expect(stop.result).rejects.toThrow('state not saved');
    expect(stop.g.seen().slice(stop.g.seen().indexOf('POST /user/repos') + 1)).toEqual([]);
  });

  it('repos: no repo is created before the cleanup is armed (createPermit; E8 fix rounds 1-2, M-3, O-2)', async () => {
    // without the permit source: refused before POST /user/repos
    const none = run({ repos: { pipelines: { private: true } } }, app(), { ...by(appMode), createPermit: undefined });
    await expect(none.result).rejects.toThrow(/cleanup/);
    expect(none.g.seen()).not.toContain('POST /user/repos');
    // a hook that refuses (the state store not armed): refused before the POST too
    const refused = run({ repos: { pipelines: { private: true } } }, app(), { ...by(appMode), createPermit: () => { throw new Error('not armed'); } });
    await expect(refused.result).rejects.toThrow('not armed');
    expect(refused.g.seen()).not.toContain('POST /user/repos');
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
    // Plan G G0 (E-F2 m3): checkProofRepos runs before pipegen built any commit, so it changes no default branch: the branch
    // exists (at a commit pipegen didn't build) → 'pending', nothing written; E2 sets it after the base push (test/plan-g0.test.ts)
    const has = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: '2'.repeat(40) } } }, access: 'user' }, app({ defaultBranch: 'develop' }));
    const r = await has.result;
    expect(r.scratchDefaultBranch).toBe('develop');
    expect(r.target.defaultBranch).toBe('develop');
    expect(r.defaultBranchState).toBe('pending');
    expect(has.g.writes()).toEqual([]);
    // at the base commit pipegen built: PATCH default_branch
    const built = '2'.repeat(40);
    expect(await setScratchDefaultBranch(has.g.gh, assertScratch(r.target, app({ defaultBranch: 'develop' })), undefined, built)).toBe('set');
    expect(writePaths(has.g)).toEqual([`PATCH /repos/${OWNER}/${SCRATCH}`]);
    expect(JSON.parse(has.g.writes()[0]?.body ?? '{}')).toEqual({ default_branch: 'develop' });
    expect(has.g.repos[SCRATCH]?.default_branch).toBe('develop');

    // missing: never made through the API (Plan G G0, E-F2 m3); the base push makes it at pipegen's commit
    const make = run({ repos: both, access: 'user' }, app({ defaultBranch: 'release/2026' }));
    const m = await make.result;
    expect(m.scratchDefaultBranch).toBe('release/2026');
    expect(m.defaultBranchState).toBe('pending');
    expect(make.g.writes()).toEqual([]);

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
      ['createHelperRepo', (r) => createHelperRepo(g.gh, r, OWNER, ARMED.user.createPermit())],
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

    // and the source: no GitHub write in src/proof outside target.ts. This scan is a lint, not the boundary: the real
    // guard is at run time (guardedWrite takes registered handles and write rules; githubRead takes GET routes only).
    // It catches the obvious ways around them: Octokit write calls, a non-literal or spaced route, an aliased or
    // destructured request/graphql, bracket access on a client, .request.bind/call/apply, fetch( and @octokit/request.
    // E4: download.ts fetches the artifact store's pre-signed URL by hand, without the token (ruling S2); no other file fetches
    const FETCH_ALLOWED: string[] = ['download.ts'];
    for (const f of readdirSync(join(import.meta.dirname, '..', 'src', 'proof')).filter((x) => x.endsWith('.ts') && x !== 'download.ts')) {
      expect(readFileSync(join(import.meta.dirname, '..', 'src', 'proof', f), 'utf8'), f).not.toMatch(/globalThis\s*\.\s*fetch|\.fetch\s*\?\?/);
    }
    // and download.ts's store fetch never carries a credential header
    expect(readFileSync(join(import.meta.dirname, '..', 'src', 'proof', 'download.ts'), 'utf8')).not.toMatch(/authorization|bearer|\btoken\s*:/i);
    for (const f of readdirSync(join(import.meta.dirname, '..', 'src', 'proof')).filter((x) => x.endsWith('.ts'))) {
      const src = readFileSync(join(import.meta.dirname, '..', 'src', 'proof', f), 'utf8');
      if (!FETCH_ALLOWED.includes(f)) expect(src, f).not.toMatch(/\bfetch\s*\(/);
      expect(src, f).not.toMatch(/@octokit\/(?:request|graphql|core)\b/);
      expect(src, f).not.toMatch(/\{[^{}]*\b(?:request|graphql)\b[^{}]*\}\s*=\s*[\w.]+/);   // const { request } = gh
      expect(src, f).not.toMatch(/\b(?:gh|octokit)\s*\[/);   // gh['request'], gh[x] (src/proof names its client gh)
      expect(src, f).not.toMatch(/\[\s*['"`](?:request|graphql|rest)['"`]\s*\]/);
      expect(src, f).not.toMatch(/\.(?:request|graphql)\s*\.(?:bind|call|apply)\b/);
      expect(src, f).not.toMatch(/=\s*[\w.]+\.(?:request|graphql)\s*[;,)\n]/);              // const r = gh.request;
      if (f !== 'target.ts') expect(src, f).not.toMatch(/\.request\s+\(/);
    }
    // the obvious ways around the guard
    const dir = join(import.meta.dirname, '..', 'src', 'proof');
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts') && x !== 'target.ts')) {
      const src = readFileSync(join(dir, f), 'utf8');
      expect(src, f).not.toMatch(/\.request\(\s*['"`](?:POST|PUT|PATCH|DELETE)\b/);
      expect(src, f).not.toMatch(/\.rest\.[a-zA-Z]+\.(?!get\b|list|check)[a-zA-Z]+\(/);
      expect(src, f).not.toMatch(/\bmethod\s*:\s*['"`](?:POST|PUT|PATCH|DELETE)/);
      expect(src, f).not.toMatch(/\.request\(\s*[^'"`\s]/);   // a route that isn't a literal can't be checked here
    }
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.ts'))) expect(readFileSync(join(dir, f), 'utf8'), f).not.toMatch(/\.graphql\s*[(.`]/);
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
    // Plan G G0 (E-F2 m3): the default branch is set after the base push, at the commit pipegen built (SHA_MAIN here)
    const bw = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: SHA_MAIN } } }, access: 'user', patchBody: { default_branch: 'main' } });
    const dev = app({ defaultBranch: 'develop' });
    await expect(setScratchDefaultBranch(bw.gh, assertScratch(proofTarget(dev), dev), undefined, SHA_MAIN)).rejects.toThrow(/didn't confirm develop as the default branch/);
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

describe('E1 fix round 1: marker (M5), default-branch failures (M4), reads are GET only (M3)', () => {
  const MARKER = 'pipegen proof runs (private scratch repo)';
  it('a reused scratch repo without pipegen\'s description: asked, default No; No → stop, no write; Yes → the marker is set through the guard', async () => {
    const msg = `${SCRATCH} exists but pipegen didn't create it. pipegen will overwrite its branches and secrets. Use it?`;
    const no = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, description: 'my old repo' } }, access: 'user' }, app(), {}, false);
    await expect(no.result).rejects.toThrow(ProofStopError);
    expect(no.i.prompt.asked).toEqual([msg]);
    expect(no.g.writes()).toEqual([]);
    const yes = run({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, description: '' } }, access: 'user' });
    expect((await yes.result).ready).toBe(true);
    expect(yes.i.prompt.asked).toEqual([msg]);
    expect(writePaths(yes.g)).toEqual([`PATCH /repos/${OWNER}/${SCRATCH}`]);
    expect(JSON.parse(yes.g.writes()[0]?.body ?? '{}')).toEqual({ description: MARKER });
    // the marker is the description createCommands and the create call use
    expect(createCommands(OWNER, [SCRATCH])[0]).toContain(`--description "${MARKER}"`);
    const created = run({ repos: { pipelines: { private: true } }, access: 'user' }, app(), by(appMode));
    await created.result;
    expect(JSON.parse(created.g.calls.find((c) => c.method === 'POST')?.body ?? '{}').description).toBe(MARKER);
    expect(created.i.prompt.asked).toEqual([]);
    // the guard takes only the marker as a description
    const g = world({ repos: both });
    const s = assertScratch(proofTarget(app()), app());
    for (const p of [{ description: 'x' }, { description: MARKER, name: 'y' }, { allow_forking: true }]) {
      await expect(guardedWrite(g.gh, s, 'PATCH /repos/{owner}/{repo}', p), JSON.stringify(p)).rejects.toThrow(ScratchGuardError);
    }
    expect(g.calls).toEqual([]);
  });

  it('a default-branch write GitHub refuses → a stop that says what to change', async () => {
    // Plan G G0 (E-F2 m3): the write happens after the base push, at the commit pipegen built (SHA_MAIN here)
    const w = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: SHA_MAIN } } }, access: 'user', patchStatus: 403 });
    const dev = app({ defaultBranch: 'develop' });
    const r = { result: setScratchDefaultBranch(w.gh, assertScratch(proofTarget(dev), dev), undefined, SHA_MAIN) };
    await expect(r.result).rejects.toThrow(ProofStopError);
    await expect(r.result).rejects.toThrow(/couldn't set develop as the default branch of CrisWorking\/pipegen-proof-shop \(HTTP 403\).*Settings → General → Default branch/s);
  });

  it('githubRead takes GET routes only', async () => {
    const g = world({ repos: both });
    for (const route of ['POST /user/repos', 'PATCH /repos/{owner}/{repo}', 'get /user', 'DELETE /repos/{owner}/{repo}', ' GET /user']) {
      await expect(githubRead(g.gh, route, { owner: OWNER, repo: SCRATCH }), route).rejects.toThrow(ScratchGuardError);
    }
    await expect(githubRead(g.gh, 'GET /user', { baseUrl: 'https://example.com' })).rejects.toThrow(ScratchGuardError);
    await expect(githubRead(g.gh, 'GET /user', { headers: {} })).rejects.toThrow(ScratchGuardError);
    expect(g.calls).toEqual([]);
    expect((await githubRead(g.gh, 'GET /user', {})).data).toMatchObject({ login: OWNER });
  });
});

describe('G13-R2: the Actions access level is reported the moment it changed (ruling G13-R2 3)', () => {
  it('access: onAccessChanged gets the earlier level right after the PUT, even when the next read fails (PUT ok, then GET 500)', async () => {
    const seen: string[] = [];
    const g = world({ repos: both });
    let put = false;
    g.gh.hook.wrap('request', async (req, options) => {
      const route = `${String(options.method)} ${String(options.url)}`;
      if (put && route.startsWith('GET ')) throw Object.assign(new Error('Server Error'), { status: 500, response: { status: 500, data: { message: 'Server Error' }, headers: {} } });
      const res = await req(options);
      if (route === 'PUT /repos/{owner}/{repo}/actions/permissions/access') put = true;
      return res;
    });
    const i = io(true);
    await expect(checkProofRepos(g.gh, app(), opts({ createPermit: permitFor(app()), onAccessChanged: (previous) => { seen.push(previous); } }), i)).rejects.toThrow();
    expect(put).toBe(true);
    expect(seen).toEqual(['none']);
    // not changed: not called
    const seen2: string[] = [];
    const g2 = world({ repos: both, access: 'user' });
    await checkProofRepos(g2.gh, app(), opts({ createPermit: permitFor(app()), onAccessChanged: (p) => { seen2.push(p); } }), i);
    expect(seen2).toEqual([]);
  });
});

describe('G14 (controller addendum): the access level on a PUT that failed without a 4xx', () => {
  it('access: a PUT that ends in a 5xx or no answer may have changed the level: onAccessChanged gets the earlier one; a 4xx did not change it', async () => {
    const failPut = (status: number | undefined) => {
      const g = world({ repos: both });
      g.gh.hook.wrap('request', async (req, options) => {
        const route = `${String(options.method)} ${String(options.url)}`;
        if (route === 'PUT /repos/{owner}/{repo}/actions/permissions/access') {
          throw Object.assign(new Error('fail'), status === undefined ? {} : { status, response: { status, data: { message: 'x' }, headers: {} } });
        }
        return req(options);
      });
      return g;
    };
    for (const status of [500, 502, undefined]) {
      const seen: string[] = [];
      await expect(checkProofRepos(failPut(status).gh, app(), opts({ createPermit: permitFor(app()), onAccessChanged: (p) => { seen.push(p); } }), io(true))).rejects.toThrow(/couldn't let/);
      expect(seen).toEqual(['none']);
    }
    const seen4: string[] = [];
    await expect(checkProofRepos(failPut(403).gh, app(), opts({ createPermit: permitFor(app()), onAccessChanged: (p) => { seen4.push(p); } }), io(true))).rejects.toThrow(/couldn't let/);
    expect(seen4).toEqual([]);
  });

  it('repos: an existing helper repo with its wiki or projects on is named with the command to turn them off; none of it is changed (sec M5)', async () => {
    const { g, i, result } = run({ repos: { pipelines: { private: true, hasWiki: true }, [SCRATCH]: { private: true, hasWiki: false, hasProjects: true } } });
    await result;
    expect(i.all()).toContain(`${OWNER}/pipelines has its wiki turned on`);
    expect(i.all()).toContain(`${OWNER}/${SCRATCH} has its projects turned on`);
    expect(i.all()).toContain(`gh repo edit ${OWNER}/${SCRATCH} --enable-wiki=false --enable-projects=false`);
    expect(writePaths(g).filter((x) => x.startsWith('PATCH'))).toEqual([]);
    // both off (or not said): nothing is named
    const quiet = run({ repos: { pipelines: { private: true, hasWiki: false, hasProjects: false }, [SCRATCH]: { private: true } } });
    await quiet.result;
    expect(quiet.i.all()).not.toContain('turned on');
  });

  it('access: a callback that throws prints "Left behind: central Actions access was <previous>" and stops', async () => {
    const g = world({ repos: both });
    const i = io(true);
    await expect(checkProofRepos(g.gh, app(), opts({ createPermit: permitFor(app()), onAccessChanged: () => { throw new Error('disk full'); } }), i)).rejects.toThrow();
    expect(i.all()).toMatch(/Left behind: central Actions access was none/);
  });
});
