// Plan E E1 fix round 1 (review I2, ruling E1-R2 with the controller's answers to G1-G6, M2): checkScratchAccess, the
// check that nobody but the user (and the residuals pipegen accepts) can push to the scratch repo that will hold the
// user's real test keys. E1 runs it on a new or reused scratch repo; E4 runs it again right before the first secret store.
// Real makeOctokit client over the stateful fake (test/helpers/proof-github.ts); no network.
import { describe, expect, it } from 'vitest';
import type { Prompter } from '../src/cli/io.js';
import { checkProofRepos, checkScratchAccess, LIST_PAGE_SIZE, MAX_LIST_PAGES, pushUnsurePrompt, type ProofRepoOptions } from '../src/proof/repos.js';
import { helperDescription, proofTarget, ProofStopError, type ProofApp } from '../src/proof/target.js';
import { armedStore } from './helpers/armed-store.js';
import { person, world, type FakeRepo, type WorldOptions } from './helpers/proof-github.js';

const OWNER = 'CrisWorking';
const ORG = 'AcmeOrg';
const SCRATCH = 'pipegen-proof-shop';
const app = (o: Partial<ProofApp> = {}): ProofApp => ({ owner: OWNER, repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main', ...o });
const orgApp = (o: Partial<ProofApp> = {}) => app({ owner: ORG, ownerType: 'Organization', ...o });
const ARMED = await armedStore(app());   // E8 fix round 2 (O-2): repo creation needs a permit from an armed store
const AU = 'au' + 'th';

function answers(...replies: boolean[]): Prompter & { asked: { msg: string; def: boolean }[] } {
  const asked: { msg: string; def: boolean }[] = [];
  return {
    asked,
    confirm: async (msg, def) => { asked.push({ msg, def }); const r = replies.shift(); if (r === undefined) throw new Error(`unexpected prompt: ${msg}`); return r; },
    select: async () => { throw new Error('no select expected'); },
    text: async () => { throw new Error('no text expected'); },
  };
}
function ioWith(...replies: boolean[]) {
  const lines: string[] = [];
  const prompt = answers(...replies);
  return { prompt, out: (s: string) => { lines.push(s); }, err: (s: string) => { lines.push(s); }, lines, all: () => lines.join('\n') };
}
/** One world with a scratch repo (and pipelines), and a check of it. */
function check(scratch: Partial<FakeRepo> = {}, w: WorldOptions = {}, a: ProofApp = app(), replies: boolean[] = [], accepted?: readonly string[]) {
  const org = a.ownerType === 'Organization';
  const g = world({ owner: a.owner, ownerType: a.ownerType, org: org ? { default_repository_permission: 'none' } : undefined, ...w, repos: { pipelines: { private: true }, [SCRATCH]: { private: true, ...scratch }, ...(w.repos ?? {}) } });
  const io = ioWith(...replies);
  return { g, io, result: checkScratchAccess(g.gh, proofTarget(a), io, accepted === undefined ? {} : { accepted }) };
}
const PUSH_PROMPT = `pipegen could not confirm who can push to ${OWNER}/${SCRATCH}. Anyone who can push can read your real test keys stored there. Continue?`;

describe('checkScratchAccess (E1 fix round 1, I2)', () => {
  it('a personal scratch repo only the user can push to: no stop, no prompt, read-only calls in this order', async () => {
    const { g, io, result } = check();
    const r = await result;
    expect(r).toMatchObject({ warnings: [], accepted: [] });
    expect(r.scratch.fullName).toBe(`${OWNER}/${SCRATCH}`);
    expect(io.prompt.asked).toEqual([]);
    expect(g.writes()).toEqual([]);
    expect(g.calls.map((c) => `${c.method} ${c.url.pathname}${c.url.search}`)).toEqual([
      `GET /repos/${OWNER}/${SCRATCH}`,
      'GET /user',
      `GET /repos/${OWNER}/${SCRATCH}/collaborators?affiliation=all&per_page=100&page=1`,
      `GET /repos/${OWNER}/${SCRATCH}/invitations?per_page=100&page=1`,
      `GET /repos/${OWNER}/${SCRATCH}/keys?per_page=100&page=1`,
    ]);
    expect(pushUnsurePrompt(r.scratch)).toBe(PUSH_PROMPT);
  });

  it('an org scratch repo: base permission, owners, teams and the fork flag are read too; cheap to call twice', async () => {
    const g = world({ owner: ORG, ownerType: 'Organization', org: { default_repository_permission: 'none' }, repos: { [SCRATCH]: { private: true } } });
    const t = proofTarget(orgApp());
    const io = ioWith();
    await checkScratchAccess(g.gh, t, io);
    const first = g.calls.length;
    expect(g.calls.map((c) => `${c.method} ${c.url.pathname}${c.url.search}`)).toEqual([
      `GET /repos/${ORG}/${SCRATCH}`,
      `GET /orgs/${ORG}`,
      'GET /user',
      `GET /orgs/${ORG}/members?role=admin&per_page=100&page=1`,
      `GET /repos/${ORG}/${SCRATCH}/collaborators?affiliation=all&per_page=100&page=1`,
      `GET /repos/${ORG}/${SCRATCH}/invitations?per_page=100&page=1`,
      `GET /repos/${ORG}/${SCRATCH}/teams?per_page=100&page=1`,
      `GET /repos/${ORG}/${SCRATCH}/keys?per_page=100&page=1`,
    ]);
    await checkScratchAccess(g.gh, t, io);
    expect(g.calls.length).toBe(2 * first);
    expect(g.writes()).toEqual([]);
  });

  it('visibility is read again each time (M2): public, internal or gone since → stop', async () => {
    for (const [s, why] of [[{ private: false }, /no longer private \(it is public\)/], [{ private: true, visibility: 'internal' as const }, /no longer private \(it is internal\)/], [{ private: true, hidden: true }, /can't see .* any more/]] as const) {
      const { g, result } = check(s);
      await expect(result, JSON.stringify(s)).rejects.toThrow(ProofStopError);
      await expect(result).rejects.toThrow(why);
      expect(g.writes()).toEqual([]);
    }
  });

  it('base permission write or admin → hard stop naming the risk and the fix, also before any create', async () => {
    for (const level of ['write', 'admin']) {
      const { g, result } = check({}, { org: { default_repository_permission: level } }, orgApp());
      await expect(result).rejects.toThrow(ProofStopError);
      await expect(result).rejects.toThrow(`Every member of ${ORG} can push to ${SCRATCH}`);
      await expect(result).rejects.toThrow(/reads its secrets, your real test keys/);
      await expect(result).rejects.toThrow(/"No permission" or "Read"/);
      await expect(result).rejects.toThrow(/personal account/);
      expect(g.writes()).toEqual([]);
      // in checkProofRepos: before the App creates anything
      const w = world({ owner: ORG, ownerType: 'Organization', org: { default_repository_permission: level }, repos: {} });
      await expect(checkProofRepos(w.gh, orgApp(), { ...({ [AU]: { kind: 'app', canCreateRepos: true } } as Pick<ProofRepoOptions, 'auth'>), actions: [] }, ioWith())).rejects.toThrow(ProofStopError);
      expect(w.writes()).toEqual([]);
    }
  });

  it('base permission read → warning, and the check goes on', async () => {
    const { io, result } = check({}, { org: { default_repository_permission: 'read' } }, orgApp());
    const r = await result;
    const warning = `Every member of ${ORG} can read ${SCRATCH}. It holds a copy of your code during the proof. An org owner can set the base permission to 'No permission'.`;
    expect(r.orgPerm).toEqual({ level: 'read', warning });
    expect(r.warnings).toContain(warning);
    expect(io.lines).toContain(warning);
    expect(io.prompt.asked).toEqual([]);
  });

  it('base permission unknown does not decide: a readable, clean push list → no prompt; an unreadable one → the prompt', async () => {
    const clean = check({}, { org: {} }, orgApp());
    expect((await clean.result).orgPerm?.level).toBe('unknown');
    expect(clean.io.prompt.asked).toEqual([]);
    const no = check({ collaborators: null }, { org: {} }, orgApp(), [false]);
    await expect(no.result).rejects.toThrow(ProofStopError);
    expect(no.io.prompt.asked).toEqual([{ msg: `pipegen could not confirm who can push to ${ORG}/${SCRATCH}. Anyone who can push can read your real test keys stored there. Continue?`, def: false }]);
    expect(no.g.writes()).toEqual([]);
    const yes = check({ collaborators: null }, { org: {} }, orgApp(), [true]);
    expect((await yes.result).accepted).toEqual([expect.stringMatching(/^pushers: /)]);
  });

  it('who can push: another user with write, maintain or admin → stop listing them; read and triage do not count; self and org owners excluded', async () => {
    for (const role of ['write', 'maintain', 'admin']) {
      const { g, result } = check({ collaborators: [person(OWNER, 1, 'admin'), person('mallory', 7, role)] });
      await expect(result, role).rejects.toThrow(ProofStopError);
      await expect(result).rejects.toThrow(/mallory/);
      await expect(result).rejects.toThrow(/run a workflow that reads its secrets/);
      expect(g.writes()).toEqual([]);
    }
    const reads = check({ collaborators: [person(OWNER, 1, 'admin'), person('reader', 8, 'read'), person('triager', 9, 'triage')] });
    await expect(reads.result).resolves.toBeDefined();
    // self is matched by id, not login
    const renamed = check({ collaborators: [person('cris-new-name', 1, 'admin')] }, { me: { login: 'cris-new-name', id: 1 } });
    await expect(renamed.result).resolves.toBeDefined();
    const sameLoginOtherId = check({ collaborators: [person('me', 1, 'admin'), person('me', 99, 'write')] }, { me: { login: 'me', id: 1 } }, orgApp());
    await expect(sameLoginOtherId.result).rejects.toThrow(ProofStopError);
    // a personal repo's owner is excluded when someone else (a collaborator) runs pipegen
    const helper = check({ collaborators: [person(OWNER, 1, 'admin'), person('helper', 2, 'write')] }, { me: { login: 'helper', id: 2 } });
    await expect(helper.result).resolves.toBeDefined();
    // org owners (members?role=admin) are excluded; any other admin is a stop
    const org = check({ collaborators: [person('me', 1, 'admin'), person('boss', 5, 'admin')] }, { me: { login: 'me', id: 1 }, owners: [person('boss', 5, 'admin')] }, orgApp());
    await expect(org.result).resolves.toBeDefined();
    const notOwner = check({ collaborators: [person('me', 1, 'admin'), person('boss', 5, 'admin')] }, { me: { login: 'me', id: 1 }, owners: [] }, orgApp());
    await expect(notOwner.result).rejects.toThrow(/boss/);
  });

  it('a personal scratch repo with one collaborator who can push → stop', async () => {
    const { result } = check({ collaborators: [person(OWNER, 1, 'admin'), person('friend', 3, 'write')] });
    await expect(result).rejects.toThrow(/friend/);
  });

  it('the stop lists at most 20 logins, then the count', async () => {
    const many = Array.from({ length: 25 }, (_, i) => person(`user${i}`, 100 + i, 'write'));
    const { result } = check({ collaborators: [person(OWNER, 1, 'admin'), ...many] });
    const e = await result.then(() => null, (x: unknown) => x as Error);
    expect(e).toBeInstanceOf(ProofStopError);
    expect(e?.message).toContain('user19');
    expect(e?.message).not.toContain('user20');
    expect(e?.message).toContain('25 people in all');
  });

  it('caps: 10 pages of 100 at most; a list past the cap → the prompt', async () => {
    expect([MAX_LIST_PAGES, LIST_PAGE_SIZE]).toEqual([10, 100]);
    const crowd = Array.from({ length: 1001 }, (_, i) => person(`r${i}`, 1000 + i, 'read'));
    const { g, io, result } = check({ collaborators: [person(OWNER, 1, 'admin'), ...crowd] }, {}, app(), [true]);
    expect((await result).accepted).toEqual([expect.stringMatching(/^pushers: /)]);
    expect(io.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
    expect(g.calls.filter((c) => c.url.pathname.endsWith('/collaborators')).map((c) => c.url.searchParams.get('page'))).toEqual(['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']);
    // exactly 10 full pages and no more: no prompt
    const full = check({ collaborators: [person(OWNER, 1, 'admin'), ...crowd.slice(0, 999)] });
    await expect(full.result).resolves.toBeDefined();
    expect(full.io.prompt.asked).toEqual([]);
  });

  it('owners list past the cap or unreadable: admins can\'t be told from owners → prompt; a writer is still a stop', async () => {
    const admin = check({ collaborators: [person('me', 1, 'admin'), person('boss', 5, 'admin')] }, { me: { login: 'me', id: 1 }, owners: null }, orgApp(), [true]);
    expect((await admin.result).accepted).toEqual([expect.stringMatching(/^pushers: /)]);
    const writer = check({ collaborators: [person('me', 1, 'admin'), person('dev', 6, 'write')] }, { me: { login: 'me', id: 1 }, owners: null }, orgApp());
    await expect(writer.result).rejects.toThrow(/dev/);
  });

  it('GET /user unreadable: the user can\'t be told apart → prompt', async () => {
    const { io, result } = check({}, { me: null }, app(), [false]);
    await expect(result).rejects.toThrow(ProofStopError);
    expect(io.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
  });

  it('teams: push, maintain or admin → stop listing slug (permission); pull/triage fine; unreadable → prompt', async () => {
    const t = check({ teams: [{ slug: 'devs', permission: 'push' }, { slug: 'ops', permission: 'admin' }, { slug: 'readers', permission: 'pull' }, { slug: 'tri', permission: 'triage' }] }, {}, orgApp());
    await expect(t.result).rejects.toThrow(/devs \(push\), ops \(admin\)/);
    await expect(t.result).rejects.not.toThrow(/readers/);
    const m = check({ teams: [{ slug: 'leads', permission: 'maintain' }] }, {}, orgApp());
    await expect(m.result).rejects.toThrow(/leads \(maintain\)/);
    const ok = check({ teams: [{ slug: 'readers', permission: 'pull' }] }, {}, orgApp());
    await expect(ok.result).resolves.toBeDefined();
    const unread = check({ teams: null }, {}, orgApp(), [false]);
    await expect(unread.result).rejects.toThrow(ProofStopError);
    expect(unread.io.prompt.asked).toHaveLength(1);
  });

  it('a custom role (role_name outside read/triage/write/maintain/admin) → the prompt', async () => {
    const custom = person('auditor', 4, 'read');
    custom.role_name = 'security-manager';
    const yes = check({ collaborators: [person(OWNER, 1, 'admin'), custom] }, {}, app(), [true]);
    expect((await yes.result).accepted).toEqual([expect.stringMatching(/^pushers: /)]);
    expect(yes.io.all()).toMatch(/auditor#4 has the custom role security-manager/);
    const no = check({ collaborators: [person(OWNER, 1, 'admin'), custom] }, {}, app(), [false]);
    await expect(no.result).rejects.toThrow(ProofStopError);
  });

  it('deploy keys: a write key → stop naming its title; read-only keys fine; unreadable → prompt', async () => {
    const w = check({ keys: [{ id: 1, title: 'ci-deploy', read_only: false }, { id: 2, title: 'mirror', read_only: true }] });
    await expect(w.result).rejects.toThrow(/deploy key with write access.*"ci-deploy"/s);
    await expect(w.result).rejects.not.toThrow(/mirror/);
    const ro = check({ keys: [{ id: 2, title: 'mirror', read_only: true }] });
    await expect(ro.result).resolves.toBeDefined();
    const odd = check({ keys: [{ id: 3, title: 'odd' }] });   // read_only missing: not known read-only
    await expect(odd.result).rejects.toThrow(/"odd"/);
    const unread = check({ keys: null }, {}, app(), [true]);
    expect((await unread.result).accepted).toEqual([expect.stringMatching(/^pushers: /)]);
  });

  it('forks (org): allow_forking turned off through the guard and read back; still on → the fork prompt; personal repo untouched', async () => {
    const off = check({ allowForking: true }, {}, orgApp());
    await off.result;
    const w = off.g.writes();
    expect(w.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([`PATCH /repos/${ORG}/${SCRATCH}`]);
    expect(JSON.parse(w[0]?.body ?? '{}')).toEqual({ allow_forking: false });
    expect(off.g.repos[SCRATCH]?.allowForking).toBe(false);
    expect(off.g.seen().filter((s) => s === `GET /repos/${ORG}/${SCRATCH}`)).toHaveLength(2);   // read back
    expect(off.io.prompt.asked).toEqual([]);

    const forced = check({ allowForking: true, forkingForced: true }, {}, orgApp(), [false]);
    await expect(forced.result).rejects.toThrow(ProofStopError);
    expect(forced.io.prompt.asked).toHaveLength(1);
    expect(forced.io.prompt.asked[0]?.def).toBe(false);
    expect(forced.io.prompt.asked[0]?.msg).toMatch(/fork.*secrets.*Continue\?$/s);
    const forcedYes = check({ allowForking: true, forkingForced: true }, {}, orgApp(), [true]);
    expect((await forcedYes.result).accepted).toEqual([`forking: ${ORG}/${SCRATCH}`]);

    const personal = check({ allowForking: true });
    await personal.result;
    expect(personal.g.writes()).toEqual([]);
  });

  it('a second call (E4) with the first call\'s accepted answers asks nothing again, but a new risk is still a stop', async () => {
    const g = world({ owner: ORG, ownerType: 'Organization', org: {}, repos: { [SCRATCH]: { private: true, collaborators: null, allowForking: true, forkingForced: true } } });
    const t = proofTarget(orgApp());
    const first = await checkScratchAccess(g.gh, t, ioWith(true, true));
    expect(first.accepted).toEqual([expect.stringMatching(/^pushers: .*couldn't read the full list of people/), `forking: ${ORG}/${SCRATCH}`]);
    const again = ioWith();
    await checkScratchAccess(g.gh, t, again, { accepted: first.accepted });
    expect(again.prompt.asked).toEqual([]);
    // a pusher added since: a stop, whatever was accepted
    (g.repos[SCRATCH] as FakeRepo).collaborators = [person('me', 1, 'admin'), person('late', 9, 'write')];
    await expect(checkScratchAccess(g.gh, t, ioWith(), { accepted: first.accepted })).rejects.toThrow(/late/);
  });

  it('the stop and warning texts name the residuals pipegen accepts (G6)', async () => {
    const { result } = check({ collaborators: [person(OWNER, 1, 'admin'), person('m', 2, 'write')] });
    await expect(result).rejects.toThrow(/org owners, enterprise owners, GitHub Apps installed on all repos/);
  });

  it('checkProofRepos runs it on a reused and on a newly created scratch repo', async () => {
    const reused = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, collaborators: [person(OWNER, 1, 'admin'), person('x', 2, 'write')] } }, access: 'user' });
    await expect(checkProofRepos(reused.gh, app(), { ...({ [AU]: { kind: 'fine-grained', canCreateRepos: false } } as Pick<ProofRepoOptions, 'auth'>), actions: [] }, ioWith())).rejects.toThrow(/These people can push to CrisWorking\/pipegen-proof-shop: x\./);
    const created = world({ repos: {}, access: 'user' });
    const r = await checkProofRepos(created.gh, app(), { ...({ [AU]: { kind: 'app', canCreateRepos: true } } as Pick<ProofRepoOptions, 'auth'>), actions: [], createPermit: () => ARMED.createPermit() }, ioWith());   // E8 M-3 / O-2: a permit from an armed store
    expect(r.ready).toBe(true);
    expect(created.seen()).toContain(`GET /repos/${OWNER}/${SCRATCH}/collaborators`);
    expect(r.access?.scratch.repo).toBe(SCRATCH);
    expect(helperDescription('scratch')).toBe('pipegen proof runs (private scratch repo)');
  });

  it('push is judged by every flag: maintain or admin alone counts; an org login is never "the owner" of an org repo; an unreadable list shape → prompt', async () => {
    // each flag on its own, under a role that doesn't mean push (read, or a custom one): the flag decides
    for (const [role, permissions] of [
      ['read', { pull: true, push: true, maintain: false, admin: false }], ['read', { pull: true, push: false, maintain: true, admin: false }],
      ['read', { pull: true, push: false, maintain: false, admin: true }], ['custom-x', { pull: true, push: true, maintain: false, admin: false }],
    ] as const) {
      const odd = { login: 'odd', id: 9, type: 'User', role_name: role, permissions };
      const { result } = check({ collaborators: [person(OWNER, 1, 'admin'), odd] });
      await expect(result, JSON.stringify(permissions)).rejects.toThrow(/push to CrisWorking\/pipegen-proof-shop: odd\./);
    }
    const orgNamed = check({ collaborators: [person('me', 1, 'admin'), person(ORG, 3, 'write')] }, { me: { login: 'me', id: 1 } }, orgApp());
    await expect(orgNamed.result).rejects.toThrow(/push to AcmeOrg\/pipegen-proof-shop: AcmeOrg\./);
    const shape = check({ collaboratorsBody: { message: 'not a list' } }, {}, app(), [false]);
    await expect(shape.result).rejects.toThrow(ProofStopError);
    expect(shape.io.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
  });

  it('marker (M5): the prompt defaults to No; a repo pipegen created in this run is never asked about', async () => {
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, description: 'mine' } }, access: 'user' });
    const io = ioWith(false);
    await expect(checkProofRepos(g.gh, app(), { ...({ [AU]: { kind: 'fine-grained', canCreateRepos: false } } as Pick<ProofRepoOptions, 'auth'>), actions: [] }, io)).rejects.toThrow(ProofStopError);
    expect(io.prompt.asked).toEqual([{ msg: `${SCRATCH} exists but pipegen didn't create it. pipegen will overwrite its branches and secrets. Use it?`, def: false }]);
    const made = world({ repos: { pipelines: { private: true } }, access: 'user', createStoredDescription: '' });
    const io2 = ioWith();
    expect((await checkProofRepos(made.gh, app(), { ...({ [AU]: { kind: 'app', canCreateRepos: true } } as Pick<ProofRepoOptions, 'auth'>), actions: [], createPermit: () => ARMED.createPermit() }, io2)).ready).toBe(true);   // E8 M-3 / O-2
    expect(io2.prompt.asked).toEqual([]);
  });

  it('teams fail closed (security scan): a missing or unknown permission → prompt; a permissions object with push, maintain or admin → stop', async () => {
    for (const team of [{ slug: 'ghost' }, { slug: 'custom', permission: 'security-manager' }, { slug: 'nul', permission: null }]) {
      const yes = check({ teams: [team] }, {}, orgApp(), [true]);
      expect((await yes.result).accepted, JSON.stringify(team)).toEqual([expect.stringMatching(new RegExp(`^pushers: \\["the team ${team.slug}#\\? has the permission`))]);
      const no = check({ teams: [team] }, {}, orgApp(), [false]);
      await expect(no.result, JSON.stringify(team)).rejects.toThrow(ProofStopError);
      expect(no.io.prompt.asked.map((a) => a.msg)).toEqual([`pipegen could not confirm who can push to ${ORG}/${SCRATCH}. Anyone who can push can read your real test keys stored there. Continue?`]);
    }
    for (const flag of ['push', 'maintain', 'admin']) {
      const t = check({ teams: [{ slug: 'flagged', permission: 'custom-role', permissions: { pull: true, [flag]: true } }] }, {}, orgApp());
      await expect(t.result, flag).rejects.toThrow(/These teams can push to AcmeOrg\/pipegen-proof-shop: flagged \(custom-role\)/);
    }
    const flagsNoPush = check({ teams: [{ slug: 'readers', permission: 'pull', permissions: { pull: true, push: false, maintain: false, admin: false } }, { slug: 'triagers', permission: 'triage' }] }, {}, orgApp());
    await expect(flagsNoPush.result).resolves.toBeDefined();
    expect(flagsNoPush.io.prompt.asked).toEqual([]);
  });

  it('collaborators fail closed (security scan): no permissions object → prompt', async () => {
    for (const permissions of [undefined, null, 'write']) {
      const p = { login: 'shadow', id: 5, type: 'User', role_name: 'read', permissions } as never;   // role write would be push (N1)
      const no = check({ collaborators: [person(OWNER, 1, 'admin'), p] }, {}, app(), [false]);
      await expect(no.result, String(permissions)).rejects.toThrow(ProofStopError);
      expect(no.io.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
      expect(no.io.all()).toContain("GitHub didn't say what shadow#5 may do");
    }
  });

  it('a Yes covers exactly the doubts it was given (security scan): a new doubt at the second check (E4) asks again', async () => {
    const g = world({ repos: { [SCRATCH]: { private: true, keys: null } } });
    const t = proofTarget(app());
    const first = await checkScratchAccess(g.gh, t, ioWith(true));
    expect(first.accepted).toEqual([`pushers: ${JSON.stringify([`pipegen couldn't read the deploy keys of ${OWNER}/${SCRATCH}`])}`]);
    // the same doubt again: not asked
    const same = ioWith();
    expect((await checkScratchAccess(g.gh, t, same, { accepted: first.accepted })).accepted).toEqual(first.accepted);
    expect(same.prompt.asked).toEqual([]);
    // a new doubt appears (a custom role), on top of the old one: asked again; No stops
    const custom = person('auditor', 4, 'read');
    custom.role_name = 'security-manager';
    (g.repos[SCRATCH] as FakeRepo).collaborators = [person(OWNER, 1, 'admin'), custom];
    const again = ioWith(false);
    await expect(checkScratchAccess(g.gh, t, again, { accepted: first.accepted })).rejects.toThrow(ProofStopError);
    expect(again.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
    // a different doubt in place of the old one: asked again too
    (g.repos[SCRATCH] as FakeRepo).keys = [];
    const other = ioWith(true);
    const r = await checkScratchAccess(g.gh, t, other, { accepted: first.accepted });
    expect(other.prompt.asked).toHaveLength(1);
    expect(r.accepted).toEqual([expect.stringContaining('auditor#4 has the custom role security-manager')]);
    // the key is the sorted reasons, whatever order they were found in
    const two = world({ repos: { [SCRATCH]: { private: true, keys: null } }, me: null });
    const k = await checkScratchAccess(two.gh, proofTarget(app()), ioWith(true));
    expect(k.accepted).toEqual([`pushers: ${JSON.stringify([`pipegen couldn't read the deploy keys of ${OWNER}/${SCRATCH}`, "pipegen couldn't read which GitHub user it acts as"])}`]);
  });

  it('N1: a write, maintain or admin role_name is push whatever the flags; flags that are missing or not booleans are unsure', async () => {
    const shaped = (role: string, permissions: unknown) => ({ login: 'odd', id: 9, type: 'User', role_name: role, permissions }) as never;
    for (const [role, permissions] of [['write', {}], ['maintain', { push: 'true' }], ['admin', { pull: true }], ['write', { push: false, maintain: false, admin: false }]] as const) {
      const { result } = check({ collaborators: [person(OWNER, 1, 'admin'), shaped(role, permissions)] });
      await expect(result, `${role} ${JSON.stringify(permissions)}`).rejects.toThrow(/push to CrisWorking\/pipegen-proof-shop: odd\./);
    }
    for (const permissions of [{}, { pull: true }, { push: 'true', maintain: false, admin: false }, { push: false, maintain: null, admin: false }, { push: false, maintain: false }]) {
      const no = check({ collaborators: [person(OWNER, 1, 'admin'), shaped('read', permissions)] }, {}, app(), [false]);
      await expect(no.result, JSON.stringify(permissions)).rejects.toThrow(ProofStopError);
      expect(no.io.prompt.asked.map((a) => a.msg), JSON.stringify(permissions)).toEqual([PUSH_PROMPT]);
      expect(no.io.all()).toContain("GitHub didn't say what odd#9 may do");
    }
    // an org admin by role name alone, with the owners list unreadable: can't be told from an owner → prompt, not a stop
    const roleAdmin = check({ collaborators: [person('me', 1, 'admin'), shaped('admin', {})] }, { me: { login: 'me', id: 1 }, owners: null }, orgApp(), [true]);
    expect((await roleAdmin.result).accepted[0]).toContain('odd#9 has admin access');
    // flags given as an array: unsure
    const arr = check({ collaborators: [person(OWNER, 1, 'admin'), shaped('read', [true, true])] }, {}, app(), [false]);
    await expect(arr.result).rejects.toThrow(ProofStopError);
    // well-formed read flags with a standard role: fine, no prompt
    const fine = check({ collaborators: [person(OWNER, 1, 'admin'), shaped('read', { pull: true, triage: false, push: false, maintain: false, admin: false })] });
    await expect(fine.result).resolves.toBeDefined();
    expect(fine.io.prompt.asked).toEqual([]);
  });

  it('N2: every reason carries the id; the key is JSON of the sorted, de-duplicated reasons', async () => {
    const nameless = (id: number) => ({ id, type: 'User', role_name: 'custom-x', permissions: { pull: true, triage: false, push: false, maintain: false, admin: false } }) as never;
    const two = check({ collaborators: [person(OWNER, 1, 'admin'), nameless(7), nameless(8)] }, {}, app(), [true]);
    const key = (await two.result).accepted[0] as string;
    expect(key.startsWith('pushers: ')).toBe(true);
    expect(JSON.parse(key.slice('pushers: '.length))).toEqual(['(unnamed)#7 has the custom role custom-x, which may allow pushing', '(unnamed)#8 has the custom role custom-x, which may allow pushing']);
    // a role name holding "; " stays one reason, and can't be mistaken for two
    const semi = person('auditor', 4, 'read');
    semi.role_name = 'a; b';
    const one = check({ collaborators: [person(OWNER, 1, 'admin'), semi] }, {}, app(), [true]);
    const k1 = (await one.result).accepted[0] as string;
    expect(JSON.parse(k1.slice('pushers: '.length))).toEqual(['auditor#4 has the custom role a; b, which may allow pushing']);
    const a = person('auditor', 4, 'read'); a.role_name = 'a';
    const b = person('b', 5, 'read'); b.role_name = 'x';
    const split = check({ collaborators: [person(OWNER, 1, 'admin'), a, b] }, {}, app(), [true]);
    expect((await split.result).accepted[0]).not.toBe(k1);
    // teams carry their id too
    const team = check({ teams: [{ id: 42, slug: 'ghost' }] }, {}, orgApp(), [true]);
    expect((await team.result).accepted[0]).toContain('the team ghost#42 has the permission');
    // the same reason twice counts once
    const dup = check({ collaborators: [person(OWNER, 1, 'admin'), nameless(7), nameless(7)] }, {}, app(), [true]);
    expect(JSON.parse(((await dup.result).accepted[0] as string).slice('pushers: '.length))).toHaveLength(1);
  });

  it('N4: a pending invitation with write, maintain or admin → stop listing the invitee; read/triage fine; unknown value or unreadable → prompt', async () => {
    const invite = (login: string, id: number, permissions: unknown) => ({ id: 100 + id, invitee: { login, id }, permissions });
    for (const level of ['write', 'maintain', 'admin']) {
      const { g, result } = check({ invitations: [invite('newbie', 3, level), invite('watcher', 4, 'read')] });
      await expect(result, level).rejects.toThrow(/invited to push to CrisWorking\/pipegen-proof-shop: newbie\./);
      await expect(result).rejects.not.toThrow(/watcher/);
      expect(g.writes()).toEqual([]);
    }
    const reads = check({ invitations: [invite('watcher', 4, 'read'), invite('tri', 5, 'triage')] });
    await expect(reads.result).resolves.toBeDefined();
    expect(reads.io.prompt.asked).toEqual([]);
    for (const permissions of ['custom-role', undefined, null, 3]) {
      const no = check({ invitations: [invite('who', 6, permissions)] }, {}, app(), [false]);
      await expect(no.result, String(permissions)).rejects.toThrow(ProofStopError);
      expect(no.io.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
      expect(no.io.all()).toContain('who#6');
    }
    const unread = check({ invitations: null }, {}, app(), [true]);
    expect(JSON.parse(((await unread.result).accepted[0] as string).slice('pushers: '.length))).toEqual([`pipegen couldn't read the pending invitations to ${OWNER}/${SCRATCH}`]);
    // an org repo too
    const org = check({ invitations: [invite('newbie', 3, 'admin')] }, {}, orgApp());
    await expect(org.result).rejects.toThrow(/newbie/);
  });
});
