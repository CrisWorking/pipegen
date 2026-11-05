// v0.2 Plan G G8 (ruling S10, S9; carries D0b-2, D0b-r1): the read-only probes the locks need. The org membership role (orgAdmin), the
// sha-pinning setting, the repository ids an org ruleset names, and who can write to the app and the central repo. Every call goes to a
// fake fetch; a probe that can't read its answer says so in a note and gives the answer that plans less, never more.
import { describe, expect, it } from 'vitest';
import { newRateBudget } from '../src/engine/github-rate.js';
import { GitHubAccessError, makeOctokit } from '../src/github/client.js';
import { readOrgAdmin, readRepoId, readShaPinning, readWriters } from '../src/github/lock-probes.js';
import { fakeFetch, type Reply, type Routes } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

const API = 'https://api.github.com';
const MEMBERSHIP = `GET ${API}/user/memberships/orgs/o`;
const PERMS = `GET ${API}/repos/o/r/actions/permissions`;
const clock = () => ({ budget: newRateBudget(), sleep: async () => {} });
const err = (status: number, message: string): Reply => ({ status, body: { message } });
const gh = (routes: Routes) => { const f = fakeFetch(routes); return { gh: makeOctokit(fake.githubPat(), { fetch: f.fetch }), calls: f.calls }; };

describe('G8 probes', () => {
  it('orgAdmin: the token user\'s active admin role in the org (GET /user/memberships/orgs/{org}); a personal account asks nothing', async () => {
    const ask = async (reply: Reply) => { const notes: string[] = []; const g = gh({ [MEMBERSHIP]: reply }); return { v: await readOrgAdmin(g.gh, 'o', 'Organization', notes, clock()), notes, calls: g.calls }; };
    expect((await ask({ body: { state: 'active', role: 'admin' } })).v).toBe(true);
    for (const body of [{ state: 'active', role: 'member' }, { state: 'pending', role: 'admin' }, { state: 'active', role: 'billing_manager' }]) expect((await ask({ body })).v, JSON.stringify(body)).toBe(false);
    // a refusal, a 404 or an odd answer: unknown (null), with a note; never taken as admin
    for (const reply of [err(403, 'Resource not accessible by personal access token'), err(404, 'Not Found'), { body: { state: 'active' } }, { body: [] }]) {
      const r = await ask(reply);
      expect(r.v, JSON.stringify(reply)).toBeNull();
      expect(r.notes.join('\n')).toMatch(/couldn't check whether you're an owner/i);
    }
    const g = gh({});
    const notes: string[] = [];
    expect(await readOrgAdmin(g.gh, 'me', 'User', notes, clock())).toBe(false);
    expect(g.calls.length).toBe(0);
    expect(notes).toEqual([]);
    // a rejected token is an error, not a note
    await expect(readOrgAdmin(gh({ [MEMBERSHIP]: err(401, 'Bad credentials') }).gh, 'o', 'Organization', [], clock())).rejects.toBeInstanceOf(GitHubAccessError);
  });

  it('sha pinning: the Actions permissions read; the setting present, absent, or unreadable', async () => {
    const ask = async (reply: Reply) => { const notes: string[] = []; return { v: await readShaPinning(gh({ [PERMS]: reply }).gh, 'o', 'r', notes, clock()), notes }; };
    expect((await ask({ body: { enabled: true, allowed_actions: 'selected', sha_pinning_required: false } })).v).toEqual({ state: 'read', enabled: true, allowedActions: 'selected', required: false });
    expect((await ask({ body: { enabled: true, allowed_actions: 'all', sha_pinning_required: true } })).v).toEqual({ state: 'read', enabled: true, allowedActions: 'all', required: true });
    // the answer has no such setting (GitHub doesn't offer it here)
    expect((await ask({ body: { enabled: true, allowed_actions: 'all' } })).v).toEqual({ state: 'absent' });
    for (const reply of [err(403, 'Resource not accessible by personal access token'), err(500, 'boom'), { body: { enabled: 'yes', sha_pinning_required: true } }, { body: { enabled: true, allowed_actions: 7, sha_pinning_required: true } }]) {
      const r = await ask(reply);
      expect(r.v, JSON.stringify(reply)).toEqual({ state: 'unknown' });
      expect(r.notes.join('\n')).toMatch(/Actions settings/);
    }
  });

  it('repository id: GET /repos id, or null with a note', async () => {
    const notes: string[] = [];
    expect(await readRepoId(gh({ [`GET ${API}/repos/o/pipelines`]: { body: { id: 42, full_name: 'o/pipelines' } } }).gh, 'o', 'pipelines', notes, clock())).toBe(42);
    expect(await readRepoId(gh({ [`GET ${API}/repos/o/pipelines`]: { body: { id: 'x' } } }).gh, 'o', 'pipelines', notes, clock())).toBeNull();
    expect(await readRepoId(gh({}).gh, 'o', 'pipelines', notes, clock())).toBeNull();
    expect(notes.length).toBe(2);
    expect(notes[0]).toMatch(/o\/pipelines/);
  });

  it('writers: listWriters on the app and on the central repo (effective write access, both repos)', async () => {
    const collab = (list: { login: string; push?: boolean; admin?: boolean; maintain?: boolean; type?: string }[]): Reply => ({ body: list.map((c) => ({ login: c.login, type: c.type ?? 'User', permissions: { push: c.push ?? false, admin: c.admin ?? false, maintain: c.maintain ?? false, pull: true } })) });
    const g = gh({
      [`GET ${API}/repos/o/r/collaborators`]: collab([{ login: 'alice', admin: true }, { login: 'bob', push: true }, { login: 'carol' }, { login: 'ci', push: true, type: 'Bot' }]),
      [`GET ${API}/repos/o/pipelines/collaborators`]: collab([{ login: 'alice', admin: true }, { login: 'dana', maintain: true }]),
    });
    expect(await readWriters(g.gh, 'o', 'r', 'pipelines', clock())).toEqual({ app: ['alice', 'bob'], central: ['alice', 'dana'] });
    expect(g.calls.every((c) => c.url.searchParams.get('affiliation') === 'all')).toBe(true);
    // a list GitHub won't give is an error (the locks are never planned on a guess)
    await expect(readWriters(gh({ [`GET ${API}/repos/o/r/collaborators`]: collab([{ login: 'alice', admin: true }]) }).gh, 'o', 'r', 'pipelines', clock())).rejects.toBeInstanceOf(GitHubAccessError);
    // G8-R2 I1: both lists answer, but one holds nobody who can write (empty, or bots and read-only users only): a stop with a plain reason,
    // never a lock planned as if one person could write
    const ok = collab([{ login: 'alice', admin: true }]);
    for (const [what, appList, centralList] of [
      ['empty app list', collab([]), ok], ['empty central list', ok, collab([])],
      ['bots only', collab([{ login: 'ci', push: true, type: 'Bot' }]), ok], ['read-only users only', ok, collab([{ login: 'carol' }])],
    ] as const) {
      const g2 = gh({ [`GET ${API}/repos/o/r/collaborators`]: appList, [`GET ${API}/repos/o/pipelines/collaborators`]: centralList });
      const e = await readWriters(g2.gh, 'o', 'r', 'pipelines', clock()).catch((x: unknown) => x);
      expect(e, what).toBeInstanceOf(GitHubAccessError);
      expect((e as Error).message, what).toMatch(/found nobody who can write/);
      // both repos were asked: the stop comes from the empty answer, not from an unrouted 404
      expect(g2.calls.every((c) => c.url.pathname.endsWith('/collaborators')), what).toBe(true);
      expect(g2.calls.length, what).toBe(appList === ok ? 2 : 1);
    }
  });

  it('G8-R3: a collaborator list still paging at the 50-page cap stops with a plain reason, never a short list', async () => {
    const page = (n: number, next: boolean): Reply => ({
      body: n === 1 ? [{ login: 'alice', type: 'User', permissions: { admin: true, push: true, pull: true } }]
        : n === 51 ? [{ login: 'bob', type: 'User', permissions: { push: true, pull: true } }]
          : [{ login: `reader${n}`, type: 'User', permissions: { push: false, pull: true } }],
      headers: next ? { link: `<${API}/repos/o/r/collaborators?page=${n + 1}>; rel="next"` } : {},
    });
    const route = (last: number) => (c: { url: URL }) => { const n = Number(c.url.searchParams.get('page') ?? '1'); return page(n, n < last); };
    // 51 pages: the cap is reached while GitHub still has more (bob, the second writer, is on page 51)
    const g = gh({ [`GET ${API}/repos/o/r/collaborators`]: route(51), [`GET ${API}/repos/o/pipelines/collaborators`]: route(1) });
    const e = await readWriters(g.gh, 'o', 'r', 'pipelines', clock()).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect((e as Error).message).toMatch(/more than 5000|too many/);
    expect(g.calls.length).toBe(50);
    // exactly 50 pages, the last with no next link: the whole list is read
    const g2 = gh({ [`GET ${API}/repos/o/r/collaborators`]: route(50), [`GET ${API}/repos/o/pipelines/collaborators`]: route(1) });
    expect(await readWriters(g2.gh, 'o', 'r', 'pipelines', clock())).toEqual({ app: ['alice'], central: ['alice'] });
  });
});
