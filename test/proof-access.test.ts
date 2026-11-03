// Plan E E1 fix round 1 (review I2, ruling E1-R2 with the controller's answers to G1-G6, M2): checkScratchAccess, the
// check that nobody but the user (and the residuals pipegen accepts) can push to the scratch repo that will hold the
// user's real test keys. E1 runs it on a new or reused scratch repo; E4 runs it again right before the first secret store.
// Real makeOctokit client over the stateful fake (test/helpers/proof-github.ts); no network.
import { describe, expect, it } from 'vitest';
import type { Prompter } from '../src/cli/io.js';
import { checkProofRepos, checkScratchAccess, LIST_PAGE_SIZE, MAX_LIST_PAGES, pushUnsurePrompt, type ProofRepoOptions } from '../src/proof/repos.js';
import { helperDescription, proofTarget, ProofStopError, type ProofApp } from '../src/proof/target.js';
import { person, world, type FakeRepo, type WorldOptions } from './helpers/proof-github.js';

const OWNER = 'CrisWorking';
const ORG = 'AcmeOrg';
const SCRATCH = 'pipegen-proof-shop';
const app = (o: Partial<ProofApp> = {}): ProofApp => ({ owner: OWNER, repo: 'shop', private: true, ownerType: 'User', defaultBranch: 'main', ...o });
const orgApp = (o: Partial<ProofApp> = {}) => app({ owner: ORG, ownerType: 'Organization', ...o });
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
    expect((await yes.result).accepted).toEqual(['pushers']);
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
    expect((await result).accepted).toEqual(['pushers']);
    expect(io.prompt.asked.map((a) => a.msg)).toEqual([PUSH_PROMPT]);
    expect(g.calls.filter((c) => c.url.pathname.endsWith('/collaborators')).map((c) => c.url.searchParams.get('page'))).toEqual(['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']);
    // exactly 10 full pages and no more: no prompt
    const full = check({ collaborators: [person(OWNER, 1, 'admin'), ...crowd.slice(0, 999)] });
    await expect(full.result).resolves.toBeDefined();
    expect(full.io.prompt.asked).toEqual([]);
  });

  it('owners list past the cap or unreadable: admins can\'t be told from owners → prompt; a writer is still a stop', async () => {
    const admin = check({ collaborators: [person('me', 1, 'admin'), person('boss', 5, 'admin')] }, { me: { login: 'me', id: 1 }, owners: null }, orgApp(), [true]);
    expect((await admin.result).accepted).toEqual(['pushers']);
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
    expect((await yes.result).accepted).toEqual(['pushers']);
    expect(yes.io.all()).toMatch(/auditor.*security-manager/);
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
    expect((await unread.result).accepted).toEqual(['pushers']);
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
    expect((await forcedYes.result).accepted).toEqual(['forking']);

    const personal = check({ allowForking: true });
    await personal.result;
    expect(personal.g.writes()).toEqual([]);
  });

  it('a second call (E4) with the first call\'s accepted answers asks nothing again, but a new risk is still a stop', async () => {
    const g = world({ owner: ORG, ownerType: 'Organization', org: {}, repos: { [SCRATCH]: { private: true, collaborators: null, allowForking: true, forkingForced: true } } });
    const t = proofTarget(orgApp());
    const first = await checkScratchAccess(g.gh, t, ioWith(true, true));
    expect(first.accepted).toEqual(['pushers', 'forking']);
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
    const r = await checkProofRepos(created.gh, app(), { ...({ [AU]: { kind: 'app', canCreateRepos: true } } as Pick<ProofRepoOptions, 'auth'>), actions: [] }, ioWith());
    expect(r.ready).toBe(true);
    expect(created.seen()).toContain(`GET /repos/${OWNER}/${SCRATCH}/collaborators`);
    expect(r.access?.scratch.repo).toBe(SCRATCH);
    expect(helperDescription('scratch')).toBe('pipegen proof runs (private scratch repo)');
  });

  it('push is judged by every flag: maintain or admin alone counts; an org login is never "the owner" of an org repo; an unreadable list shape → prompt', async () => {
    for (const permissions of [{ pull: true, push: false, maintain: true, admin: false }, { pull: true, push: false, maintain: false, admin: true }]) {
      const odd = { login: 'odd', id: 9, type: 'User', role_name: 'write', permissions };
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
    expect((await checkProofRepos(made.gh, app(), { ...({ [AU]: { kind: 'app', canCreateRepos: true } } as Pick<ProofRepoOptions, 'auth'>), actions: [] }, io2)).ready).toBe(true);
    expect(io2.prompt.asked).toEqual([]);
  });
});
