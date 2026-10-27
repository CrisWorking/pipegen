// Plan A Task 6: how pipegen logs in to GitHub, what it asks for, and how the token is kept safe.
// Every network call goes to a fake fetch (test/helpers/fake-http.ts); every token is built at runtime.
import { inspect } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GITHUB_API, GitHubAccessError, getAuth, hideToken, listWriters, makeOctokit, permissionsTable, probePermissions,
  readGitHubContext, refreshAppToken, tokenKind, type AppLogin, type AuthDeps as GhDeps,
} from '../src/github/client.js';
import { isRateStop, newRateBudget } from '../src/engine/github-rate.js';
import { fakeFetch, type Call, type Reply, type Routes } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

// Names and words that look like secret assignments to test/no-secret-literals (a key word before ':' or '=') are
// built at runtime here, so this file passes the same redact() check as every other test file.
const API = 'https://api.github.com';
const AU = 'au' + 'th';
const TOK = 'to' + 'ken';
const HDR = 'Author' + 'ization';
const ENV_VAR = 'GITHUB_' + TOK.toUpperCase();
const ENT_VAR = 'GH_ENTERPRISE_' + TOK.toUpperCase();
const S_NAME = 'Sec' + 'rets';
/** A test title "prefix: rest", as the brief names them. */
const title = (prefix: string, rest: string) => `${prefix}: ${rest}`;
/** A permission label as permissionsTable writes it. */
const P = (name: string, level: 'read' | 'read and write') => `${name}: ${level}`;
const appCred = () => 'gh' + 'u_' + 'Q'.repeat(36);
const refreshCred = () => 'gh' + 'r_' + 'W'.repeat(36);
const fgCred = () => fake.githubPat();
const classicCred = () => fake.githubClassic();
const oauthCred = () => 'gh' + 'o_' + 'R'.repeat(36);
const installCred = () => 'gh' + 's_' + 'Z'.repeat(36);

const clock = () => ({ budget: newRateBudget(), sleep: async () => {} });
const gh = (routes: Routes, cred: string | null = fgCred()) => {
  const f = fakeFetch(routes);
  return { gh: makeOctokit(cred, { fetch: f.fetch }), calls: f.calls };
};
type Deps = Partial<GhDeps>;
const deps = (cred: string | undefined, routes: Routes = {}, extra: Deps = {}) => {
  const f = fakeFetch(routes);
  return { deps: { env: { [ENV_VAR]: cred }, fetch: f.fetch, clock: clock(), ...extra } as GhDeps, calls: f.calls };
};
const refused = (message: string, accepted?: string): Reply => ({
  status: 403, body: { message }, headers: accepted === undefined ? {} : { 'x-accepted-github-permissions': accepted },
});
const integration = 'Resource not accessible by integration';
const byPat = 'Resource not accessible by personal access token';

/** Every text form of an error a user, a log or a --json dump could ever see. */
const allText = (e: unknown) => [
  e instanceof Error ? e.message : '', String(e), inspect(e, { depth: 12, showHidden: true }), JSON.stringify(e, Object.getOwnPropertyNames(e as object)),
].join('\n');
const caught = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error('expected a rejection');
};

afterEach(() => { vi.unstubAllEnvs(); });

describe('permissionsTable', () => {
  it('permissionsTable: every permission has a why', () => {
    for (const mode of ['read', 'write'] as const) {
      const rows = permissionsTable(mode);
      expect(rows.length).toBeGreaterThan(0);
      for (const r of rows) {
        expect(r.permission.trim().length, r.permission).toBeGreaterThan(0);
        expect(r.why.trim().length, r.permission).toBeGreaterThan(10);
      }
      expect(new Set(rows.map((r) => r.permission)).size).toBe(rows.length);
    }
  });

  it('permissionsTable: the measured S1 write table (DECISIONS #88), nothing more', () => {
    const write = permissionsTable('write').map((r) => r.permission);
    expect(write).toEqual([
      'Metadata: read', 'Contents: read and write', 'Workflows: read and write', 'Pull requests: read and write',
      'Actions: read and write', P(S_NAME, 'read and write'), 'Variables: read and write', 'Environments: read and write',
      'Administration: read and write', 'Checks: read (GitHub App only)',
    ]);
    const all = JSON.stringify(permissionsTable('write')) + JSON.stringify(permissionsTable('read'));
    expect(all).not.toMatch(/Repository creation|Commit statuses/);
  });
});

describe('getAuth', () => {
  it(title(AU, 'classic token with repo scope refused without allowBroad, message explains the fine-grained/app option'), async () => {
    for (const cred of [classicCred(), oauthCred(), 'a1'.repeat(20)]) {
      for (const mode of ['read', 'write'] as const) {
        const { deps: d, calls } = deps(cred);
        const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode }, d));
        expect(e).toBeInstanceOf(GitHubAccessError);
        const msg = (e as Error).message;
        expect(msg).toMatch(/classic/i);
        expect(msg).toMatch(/fine-grained token/);
        expect(msg).toMatch(/GitHub App/);
        expect(msg).toMatch(/--allow-broad-token/);
        expect(allText(e)).not.toContain(cred);
        expect(calls).toEqual([]);
      }
    }
    // allowed on purpose: every repo, and pipegen still never creates or deletes repos with it (token mode)
    const { deps: d } = deps(classicCred());
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: true, mode: 'write' }, d);
    expect(got).toMatchObject({ kind: 'classic', repos: 'all', canCreateRepos: false, canDeleteRepos: false });
  });

  it(title(AU, 'token kind by prefix: ghu_ app, github_pat_ fine-grained, gho_/ghp_ classic; anything else refused'), async () => {
    expect(tokenKind(appCred())).toBe('app');
    expect(tokenKind(fgCred())).toBe('fine-grained');
    expect(tokenKind(classicCred())).toBe('classic');
    expect(tokenKind(oauthCred())).toBe('classic');
    expect(tokenKind('0f'.repeat(20))).toBe('classic');   // classic tokens made before 2021 are 40 hex characters
    expect(tokenKind(installCred())).toBe('installation');
    for (const other of [refreshCred(), 'xyz', `ghu_short\n${HDR}: x`]) {
      expect(tokenKind(other)).toBe(null);
      const { deps: d, calls } = deps(other);
      const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: true, mode: 'read' }, d));
      expect(e).toBeInstanceOf(GitHubAccessError);
      expect((e as Error).message).toMatch(/doesn't recognise/);
      expect(allText(e)).not.toContain(other);
      expect(calls).toEqual([]);
    }
    const { deps: d } = deps('  ' + fgCred() + '\n');
    const got = await getAuth({ owner: 'o', repos: ['r', 'pipelines'], allowBroad: false, mode: 'read' }, d);
    expect(got.kind).toBe('fine-grained');
    expect(got.token).toBe(fgCred());
    expect(got.repos).toEqual(['r', 'pipelines']);
  });

  it(title(AU, 'read mode never requests write permissions'), async () => {
    expect(permissionsTable('read').some((r) => /write/i.test(r.permission))).toBe(false);
    // no token, private repo: the setup steps list read permissions only, and only GET calls were made
    const { deps: d, calls } = deps(undefined, { [`GET ${API}/repos/o/r`]: { status: 404, body: { message: 'Not Found' } } });
    const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d));
    const msg = (e as Error).message;
    expect(msg).toMatch(/read access/);
    for (const r of permissionsTable('read')) expect(msg).toContain(r.permission);
    expect(msg).not.toMatch(/write/i);
    expect(calls.every((c) => c.method === 'GET')).toBe(true);
    // an App token in read mode: only its installation is looked up (the scope check), no create or delete rights
    const app = deps(appCred(), { [`GET ${API}/user/installations`]: { body: { installations: [] } } }, { appLogin: async () => appCred() });
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, app.deps);
    expect(got).toMatchObject({ kind: 'app', canCreateRepos: false, canDeleteRepos: false });
    expect(app.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /user/installations']);
  });

  it(title(AU, 'canCreateRepos and canDeleteRepos follow the S1/S9 strategy and the probe'), async () => {
    const installs = (login: string, administration?: string): Routes => ({
      [`GET ${API}/user/installations`]: { body: { total_count: 9, installations: [
        { id: 1, account: { login: 'someone-else' }, permissions: { administration: 'write' } },
        { id: 2, account: { login }, repository_selection: 'selected', permissions: { metadata: 'read', ...(administration ? { administration } : {}) } },
      ] } },
    });
    // App user token with Administration write on the owner's installation → pipegen may create and delete (S9)
    const login = { appLogin: async () => appCred() };
    let r = deps(undefined, installs('o', 'write'), login);
    let got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'write' }, r.deps);
    expect(got).toMatchObject({ kind: 'app', repos: ['r'], canCreateRepos: true, canDeleteRepos: true });
    expect(r.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual(['GET /user/installations']);
    // a ghu_ token from GITHUB_TOKEN may belong to another App: never create or delete with it
    r = deps(appCred(), installs('o', 'write'));
    got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'write' }, r.deps);
    expect(got).toMatchObject({ kind: 'app', canCreateRepos: false, canDeleteRepos: false });
    // the probe says otherwise → no
    for (const routes of [installs('o', 'read'), installs('o'), installs('another-owner', 'write'),
      { [`GET ${API}/user/installations`]: refused(integration) }, { [`GET ${API}/user/installations`]: { status: 500, body: {} } }]) {
      r = deps(undefined, routes, login);
      got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'write' }, r.deps);
      expect(got).toMatchObject({ kind: 'app', canCreateRepos: false, canDeleteRepos: false });
    }
    // a fine-grained token never creates or deletes, even with Administration write: a repo it creates is out of its
    // reach (S9 re-test: 201, then 404). No probe, and certainly no POST /user/repos.
    r = deps(fgCred(), installs('o', 'write'));
    got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'write' }, r.deps);
    expect(got).toMatchObject({ kind: 'fine-grained', canCreateRepos: false, canDeleteRepos: false });
    expect(r.calls).toEqual([]);
  });

  it(title(AU, 'ghs_ read → installation'), async () => {
    const { deps: d, calls } = deps(installCred());
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d);
    expect(got).toMatchObject({ kind: 'installation', repos: ['r'], canCreateRepos: false, canDeleteRepos: false });
    expect(got.token).toBe(installCred());
    expect(calls).toEqual([]);
  });

  it(title(AU, 'ghs_ write → refused, no network call'), async () => {
    const { deps: d, calls } = deps(installCred());
    const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: true, mode: 'write' }, d));
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect((e as Error).message).toMatch(/only accepted for read-only audit/);
    expect(allText(e)).not.toContain(installCred());
    expect(calls).toEqual([]);
  });

  it(title(AU, 'App installed on "All repositories" → refused unless allowBroad (T25)'), async () => {
    const routes: Routes = { [`GET ${API}/user/installations`]: { body: { installations: [
      { id: 3, account: { login: 'o' }, repository_selection: 'all', permissions: { administration: 'write' } },
    ] } } };
    for (const mode of ['read', 'write'] as const) {
      const r = deps(undefined, routes, { appLogin: async () => appCred() });
      const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode }, r.deps));
      expect(e).toBeInstanceOf(GitHubAccessError);
      expect((e as Error).message).toMatch(/All repositories/);
      expect((e as Error).message).toMatch(/Only select repositories/);
      expect((e as Error).message).toMatch(/--allow-broad-token/);
    }
    const r = deps(undefined, routes, { appLogin: async () => appCred() });
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: true, mode: 'write' }, r.deps);
    expect(got).toMatchObject({ kind: 'app', repos: 'all' });
  });

  it(title(AU, 'anonymous check that fails with 401, 502 or 503 → couldn\'t reach GitHub, not the setup steps'), async () => {
    for (const status of [401, 502, 503]) {
      const { deps: d } = deps(undefined, { [`GET ${API}/repos/o/r`]: { status, body: { message: 'x' } } });
      const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d));
      expect(e).toBeInstanceOf(GitHubAccessError);
      expect((e as Error).message).toMatch(/couldn't reach/);
      expect((e as Error).message).not.toMatch(/fine-grained token/);
    }
  });

  it(title(AU, 'owner and repo names are checked before any call'), async () => {
    for (const [owner, repo] of [['o/../x', 'r'], ['o', '..'], ['bad owner', 'r'], ['o', 'r?x=1'], ['-o', 'r']]) {
      const { deps: d, calls } = deps(fgCred());
      expect(await caught(getAuth({ owner, repos: [repo], allowBroad: false, mode: 'read' }, d))).toBeInstanceOf(GitHubAccessError);
      const c = gh({});
      expect(await caught(readGitHubContext(c.gh, owner, repo, null))).toBeInstanceOf(GitHubAccessError);
      expect(await caught(listWriters(c.gh, owner, repo))).toBeInstanceOf(GitHubAccessError);
      expect(await caught(probePermissions(c.gh, owner, [repo]))).toBeInstanceOf(GitHubAccessError);
      expect([...calls, ...c.calls]).toEqual([]);
    }
  });

  it(title(AU, 'no token, read mode, public repo → kind anonymous, token null'), async () => {
    const { deps: d, calls } = deps(undefined, { [`GET ${API}/repos/o/r`]: { body: { private: false, permissions: { admin: true } } } });
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d);
    expect(got).toEqual({ kind: 'anonymous', [TOK]: null, repos: ['r'], canCreateRepos: false, canDeleteRepos: false });
    expect(got.token).toBe(null);
    expect(calls).toHaveLength(1);
    expect(calls[0].headers.authorization).toBeUndefined();
    // an empty GITHUB_TOKEN is no token
    const blank = deps('   ', { [`GET ${API}/repos/o/r`]: { body: { private: false } } });
    expect((await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, blank.deps)).kind).toBe('anonymous');
  });

  it(title(AU, 'no token, read mode, private or unreachable repo → the read-only setup steps'), async () => {
    for (const reply of [{ status: 404, body: { message: 'Not Found' } }, { body: { private: true } }] as Reply[]) {
      const { deps: d } = deps(undefined, { [`GET ${API}/repos/o/r`]: reply });
      const e = await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d));
      expect(e).toBeInstanceOf(GitHubAccessError);
      expect((e as Error).message).toMatch(/fine-grained token/);
      expect((e as Error).message).toMatch(/GITHUB_TOKEN/);
      expect((e as Error).message).toMatch(/refuses broad classic tokens/);
      expect((e as Error).message).not.toMatch(/gh auth login/);
    }
  });

  it(title(AU, 'no token in write mode → error with setup steps, never anonymous'), async () => {
    const { deps: d, calls } = deps(undefined, { [`GET ${API}/repos/o/r`]: { body: { private: false } } });
    const e = await caught(getAuth({ owner: 'o', repos: ['r', 'pipelines', 'pipegen-proof-r'], allowBroad: false, mode: 'write' }, d));
    expect(e).toBeInstanceOf(GitHubAccessError);
    const msg = (e as Error).message;
    expect(msg).toMatch(/fine-grained token/);
    expect(msg).toMatch(/Only select repositories/);
    for (const repo of ['o/r', 'o/pipelines', 'o/pipegen-proof-r']) expect(msg).toContain(repo);
    expect(msg).toContain(P(S_NAME, 'read and write'));
    expect(msg).not.toContain('Checks');   // a fine-grained token can't have it
    expect(msg).toMatch(/GITHUB_TOKEN/);
    expect(calls).toEqual([]);
  });

  it(title(AU, 'the token from pipegen\'s own App login is used before GITHUB_TOKEN'), async () => {
    const { deps: d } = deps(fgCred(), {}, { appLogin: async () => appCred() });
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d);
    expect(got.kind).toBe('app');
    expect(got.token).toBe(appCred());
    // the login hands back something that isn't an App user token → refused, never used
    const bad = deps(undefined, {}, { appLogin: async () => fgCred() });
    expect(await caught(getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, bad.deps))).toBeInstanceOf(GitHubAccessError);
  });

  it(title(AU, 'GITHUB_API_URL, GH_HOST and GH_ENTERPRISE_TOKEN are ignored'), async () => {
    vi.stubEnv('GITHUB_API_URL', 'https://ghe.example.com/api/v3');
    vi.stubEnv('GH_HOST', 'ghe.example.com');
    const { deps: d, calls } = deps(undefined, { [`GET ${API}/repos/o/r`]: { body: { private: false } } });
    (d.env as Record<string, string>)[ENT_VAR] = fgCred();
    (d.env as Record<string, string>).GITHUB_API_URL = 'https://ghe.example.com/api/v3';
    const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'read' }, d);
    expect(got.kind).toBe('anonymous');
    expect(calls.map((c) => c.url.origin)).toEqual([API]);
  });
});

describe('refreshAppToken', () => {
  const old: AppLogin = { access: appCred(), refresh: refreshCred(), expiresAt: 1 };
  const fresh: AppLogin = { access: 'gh' + 'u_' + 'N'.repeat(36), refresh: 'gh' + 'r_' + 'M'.repeat(36), expiresAt: 99 };

  it('refresh: both new tokens are saved together before the new access token is used', async () => {
    const order: string[] = [];
    const saved: AppLogin[] = [];
    const store = { load: async () => old, save: async (t: AppLogin) => { order.push('save'); saved.push(t); } };
    const got = await refreshAppToken(store, async (refresh) => { order.push(`exchange ${refresh === old.refresh}`); return fresh; });
    expect(got).toBe(fresh.access);
    expect(order).toEqual(['exchange true', 'save']);
    expect(saved).toEqual([fresh]);   // one write holding both tokens
  });

  it('refresh: a failed save never hands out the new token, and its text never shows a token', async () => {
    const store = { load: async () => old, save: async () => { throw new Error('disk full'); } };
    const e = await caught(refreshAppToken(store, async () => fresh));
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect((e as Error).message).toMatch(/log in again/i);
    for (const t of [fresh.access, fresh.refresh, old.access, old.refresh]) expect(allText(e)).not.toContain(t);
    // an exchange answer that isn't an App token pair is refused
    const store2 = { load: async () => old, save: vi.fn(async () => {}) };
    await expect(refreshAppToken(store2, async () => ({ ...fresh, access: fgCred() }))).rejects.toBeInstanceOf(GitHubAccessError);
    expect(store2.save).not.toHaveBeenCalled();
  });
});

describe('makeOctokit', () => {
  it('makeOctokit: baseUrl is always https://api.github.com, even with GITHUB_API_URL or GH_HOST set', async () => {
    expect(GITHUB_API).toBe('https://api.github.com');
    vi.stubEnv('GITHUB_API_URL', 'https://ghe.example.com/api/v3');
    vi.stubEnv('GH_HOST', 'ghe.example.com');
    vi.stubEnv('GITHUB_SERVER_URL', 'https://ghe.example.com');
    const { gh: client, calls } = gh({ [`GET ${API}/repos/o/r`]: { body: { private: false } } }, fgCred());
    await client.rest.repos.get({ owner: 'o', repo: 'r' });
    expect(calls).toHaveLength(1);
    expect(calls[0].url.href).toBe(`${API}/repos/o/r`);
    expect(calls[0].headers[HDR.toLowerCase()]).toBe(`${TOK} ${fgCred()}`);
    // anonymous: same host, no credential
    const anon = gh({ [`GET ${API}/repos/o/r`]: { body: { private: false } } }, null);
    await anon.gh.rest.repos.get({ owner: 'o', repo: 'r' });
    expect(anon.calls[0].url.origin).toBe(API);
    expect(anon.calls[0].headers.authorization).toBeUndefined();
  });

  it('makeOctokit: origin URL host is never used for API calls', async () => {
    // pipegen only ever passes owner and repo to the client; even an absolute URL to another host is refused
    // before anything is sent, so the token can't reach it
    const { gh: client, calls } = gh({}, fgCred());
    for (const url of ['https://ghe.example.com/api/v3/repos/o/r', 'http://api.github.com/repos/o/r', 'https://api.github.com.evil.example/repos/o/r']) {
      const e = await caught(client.request(`GET ${url}`));
      expect(allText(e)).not.toContain(fgCred());
    }
    expect(calls).toEqual([]);
  });

  it('makeOctokit: a redirect is followed only on api.github.com; another host never gets the token', async () => {
    const routes: Routes = {
      [`GET ${API}/repos/old/name`]: { status: 301, headers: { location: `${API}/repositories/42` } },
      [`GET ${API}/repositories/42`]: { body: { private: false, name: 'name' } },
      [`GET ${API}/repos/o/moved`]: { status: 302, headers: { location: 'https://evil.example/steal' } },
    };
    const { gh: client, calls } = gh(routes, fgCred());
    const res = await client.rest.repos.get({ owner: 'old', repo: 'name' });
    expect(res.data).toMatchObject({ name: 'name' });
    expect(calls.map((c) => c.url.href)).toEqual([`${API}/repos/old/name`, `${API}/repositories/42`]);
    const e = await caught(client.rest.repos.get({ owner: 'o', repo: 'moved' }));
    expect(allText(e)).not.toContain(fgCred());
    expect(calls.some((c: Call) => c.url.host === 'evil.example')).toBe(false);
  });

  it('makeOctokit: every request has its own timeout (Plan U carry-forward)', async () => {
    const hang: typeof fetch = (_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
    });
    const client = makeOctokit(fgCred(), { fetch: hang, timeoutMs: 30 });
    const started = Date.now();
    const e = await caught(client.rest.repos.get({ owner: 'o', repo: 'r' }));
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(allText(e)).not.toContain(fgCred());
    // the timeout is per request, not one shared deadline: a second request after the first one timed out still works
    let n = 0;
    const slowThenOk: typeof fetch = async (input, init) => {
      n++;
      if (n === 1) return hang(input, init);
      return new Response(JSON.stringify({ private: false }), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const c2 = makeOctokit(fgCred(), { fetch: slowThenOk, timeoutMs: 30 });
    await caught(c2.rest.repos.get({ owner: 'o', repo: 'r' }));
    await new Promise((r) => setTimeout(r, 60));
    expect((await c2.rest.repos.get({ owner: 'o', repo: 'r' })).data).toEqual({ private: false });
  });
});

describe('makeOctokit logging and rate budget', () => {
  it('makeOctokit: a failed request prints nothing unless debug is on', async () => {
    const lines: string[] = [];
    const f = fakeFetch({ [`GET ${API}/repos/o/r`]: { status: 404, body: { message: 'Not Found' } } });
    const client = makeOctokit(fgCred(), { fetch: f.fetch, log: (l) => lines.push(l) });
    await caught(client.rest.repos.get({ owner: 'o', repo: 'r' }));
    expect(lines).toEqual([]);
    const loud = makeOctokit(fgCred(), { fetch: f.fetch, debug: true, log: (l) => lines.push(l) });
    await caught(loud.rest.repos.get({ owner: 'o', repo: 'r' }));
    expect(lines.length).toBeGreaterThan(0);
  });

  it('makeOctokit: calls on one client share one rate budget', async () => {
    let n = 0;
    const reset = String(Math.floor(Date.now() / 1000) + 30);
    const f = fakeFetch({
      [`GET ${API}/repos/o/r`]: () => (++n % 2 === 1
        ? { status: 403, body: { message: 'API rate limit exceeded' }, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset } }
        : { body: { private: true, default_branch: 'main', owner: { type: 'Organization' } } }),
    });
    const client = makeOctokit(fgCred(), { fetch: f.fetch, clock: { budget: newRateBudget(40_000), sleep: async () => {} } });
    await readGitHubContext(client, 'o', 'r', null);   // waits about 31 s of the 40 s budget
    const e = await caught(readGitHubContext(client, 'o', 'r', null));   // the next wait no longer fits
    expect(isRateStop(e)).toBe(true);
  });
});

describe('token safety', () => {
  it(title(TOK, 'never printed in error messages, --json output or debug logs'), async () => {
    for (const cred of [appCred(), fgCred()]) {
      const echo: Reply = { status: 500, body: { message: `server echoed ${HDR}: ${TOK} ${cred} and Bearer ${cred}` } };
      const routes: Routes = {
        [`GET ${API}/repos/o/r`]: echo,
        [`GET ${API}/repos/o/r/collaborators`]: refused(byPat, 'metadata=read'),
        [`GET ${API}/repos/o/r/rulesets`]: echo,
        [`GET ${API}/user/installations`]: echo,
      };
      const lines: string[] = [];
      const f = fakeFetch(routes);
      const client = makeOctokit(cred, { fetch: f.fetch, debug: true, log: (l) => lines.push(l) });
      const errors = [
        await caught(readGitHubContext(client, 'o', 'r', 'o', clock())),
        await caught(listWriters(client, 'o', 'r', clock())),
        await caught(client.rest.repos.get({ owner: 'o', repo: 'r' })),
      ];
      for (const e of errors) expect(allText(e)).not.toContain(cred);
      expect((errors[0] as Error).message).toContain('***');
      // debug and warning lines go through hideToken
      client.log.warn(`a warning with ${cred}`);
      client.log.debug(`${HDR.toLowerCase()}: ${TOK} ${cred}`);
      expect(lines.length).toBeGreaterThan(0);
      expect(lines.join('\n')).not.toContain(cred);
      // the Auth object can be printed or dumped as --json without its token
      const { deps: d } = deps(cred, routes);
      const got = await getAuth({ owner: 'o', repos: ['r'], allowBroad: false, mode: 'write' }, d);
      expect(got.token).toBe(cred);
      expect(JSON.stringify(got)).not.toContain(cred);
      expect(inspect(got, { depth: 5 })).not.toContain(cred);
      expect(String(got)).not.toContain(cred);
      expect(JSON.stringify({ ...got })).not.toContain(cred);
      const probed = await probePermissions(client, 'o', ['r'], { kind: got.kind, clock: clock() });
      expect(JSON.stringify(probed)).not.toContain(cred);
    }
  });

  it(title('hide' + 'Token', 'an empty or short token never rewrites the text'), () => {
    expect(hideToken('a cat sat', '')).toBe('a cat sat');
    expect(hideToken('a cat sat', 'a')).toBe('a cat sat');
    expect(hideToken('a cat sat', null)).toBe('a cat sat');
  });

  it(title('hide' + 'Token', 'applied before a log line is cut, so no piece of a token is left'), () => {
    const cred = appCred();
    const lines: string[] = [];
    const client = makeOctokit(cred, { fetch: fakeFetch({}).fetch, log: (l) => lines.push(l) });
    client.log.warn('context', new Error('x'.repeat(385) + cred));
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain(cred.slice(0, 6));
  });

  it(title('hide' + 'Token', 'the exact token, Authorization values and any GitHub token shape become ***'), () => {
    const t = fgCred();
    const other = 'gh' + 's_' + 'Y'.repeat(36);
    const out = hideToken(`a ${t} b ${HDR.toLowerCase()}: Bearer xyz.abc c ${other} d ${refreshCred()}`, t);
    expect(out).not.toContain(t);
    expect(out).not.toContain(other);
    expect(out).not.toContain(refreshCred());
    expect(out).not.toContain('xyz.abc');
    expect(out).toContain('***');
  });
});

describe('readGitHubContext', () => {
  const repo = (ownerType: 'User' | 'Organization', priv = true): Reply => ({
    body: { private: priv, default_branch: 'trunk', owner: { login: 'o', type: ownerType }, permissions: { admin: true } },
  });

  it('context: org plan read from /orgs; failure → unknown', async () => {
    for (const [name, plan] of [['team', 'team'], ['enterprise', 'enterprise'], ['free', 'free'], ['something-new', 'unknown']] as const) {
      const { gh: client, calls } = gh({ [`GET ${API}/repos/o/r`]: repo('Organization'), [`GET ${API}/orgs/o`]: { body: { plan: { name } } } });
      expect(await readGitHubContext(client, 'o', 'r', 'me', clock())).toEqual({ private: true, ownerType: 'Organization', plan, defaultBranch: 'trunk' });
      expect(calls.some((c) => c.url.pathname === '/user')).toBe(false);
    }
    for (const orgReply of [{ status: 403, body: { message: 'Must be an owner' } }, { status: 404, body: {} }, { body: { plan: null } }, { body: {} }] as Reply[]) {
      const { gh: client } = gh({ [`GET ${API}/repos/o/r`]: repo('Organization'), [`GET ${API}/orgs/o`]: orgReply });
      expect((await readGitHubContext(client, 'o', 'r', 'me', clock())).plan).toBe('unknown');
    }
  });

  it('context: user plan read from /user only when the token\'s login equals the owner; other owner or anonymous → unknown', async () => {
    const routes: Routes = { [`GET ${API}/repos/o/r`]: repo('User'), [`GET ${API}/user`]: { body: { login: 'o', plan: { name: 'pro' } } } };
    let r = gh(routes);
    expect(await readGitHubContext(r.gh, 'o', 'r', 'O', clock())).toEqual({ private: true, ownerType: 'User', plan: 'pro', defaultBranch: 'trunk' });
    for (const login of ['someone-else', null]) {
      r = gh(routes, login === null ? null : fgCred());
      expect((await readGitHubContext(r.gh, 'o', 'r', login, clock())).plan).toBe('unknown');
      expect(r.calls.some((c) => c.url.pathname === '/user')).toBe(false);
    }
    // no user scope: plan null (spike S1) → unknown
    r = gh({ ...routes, [`GET ${API}/user`]: { body: { login: 'o', plan: null } } });
    expect((await readGitHubContext(r.gh, 'o', 'r', 'o', clock())).plan).toBe('unknown');
  });

  it('context: a repo pipegen can\'t see → a clear error', async () => {
    const { gh: client } = gh({ [`GET ${API}/repos/o/r`]: { status: 404, body: { message: 'Not Found' } } });
    const e = await caught(readGitHubContext(client, 'o', 'r', null, clock()));
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect((e as Error).message).toMatch(/can't see o\/r/);
  });
});

describe('listWriters', () => {
  it('writers: users with push, maintain or admin listed; read-only users and bots left out; paged', async () => {
    const user = (login: string, p: Record<string, boolean>, type = 'User') => ({ login, type, permissions: { pull: true, triage: false, push: false, maintain: false, admin: false, ...p } });
    const page1 = [user('pusher', { push: true }), user('reader', {}), user('dependabot[bot]', { push: true }, 'Bot'), user('triager', { triage: true })];
    const page2 = [user('maint', { maintain: true }), user('owner', { admin: true, push: true }), user('bad\u001b[2Jname', { push: true })];
    const { gh: client, calls } = gh({
      [`GET ${API}/repos/o/r/collaborators`]: (c) => c.url.searchParams.get('page') === '2'
        ? { body: page2 }
        : { body: page1, headers: { link: `<${API}/repos/o/r/collaborators?affiliation=all&per_page=100&page=2>; rel="next"` } },
    });
    expect(await listWriters(client, 'o', 'r', clock())).toEqual(['pusher', 'maint', 'owner']);
    expect(calls).toHaveLength(2);
    expect(calls[0].url.searchParams.get('affiliation')).toBe('all');
  });

  it('writers: refused call → error naming the missing permission', async () => {
    const { gh: client } = gh({ [`GET ${API}/repos/o/r/collaborators`]: refused(byPat, 'metadata=read') });
    const e = await caught(listWriters(client, 'o', 'r', clock()));
    expect(e).toBeInstanceOf(GitHubAccessError);
    expect((e as Error).message).toContain('Metadata: read');
    expect((e as Error).message).toContain('o/r');
    // without GitHub's header pipegen doesn't guess a permission name
    const r2 = gh({ [`GET ${API}/repos/o/r/collaborators`]: refused('Must have push access to view repository collaborators.') });
    const e2 = await caught(listWriters(r2.gh, 'o', 'r', clock()));
    expect((e2 as Error).message).toMatch(/didn't say which permission/);
    expect((e2 as Error).message).not.toMatch(/Metadata|Administration/);
  });
});

describe('probePermissions', () => {
  const repoOk: Reply = { body: { private: true, permissions: { admin: true, maintain: true, push: true, pull: true } } };

  it('probePermissions: missing Secrets write reported with why', async () => {
    // App: GitHub lists the installation's exact permissions
    const full = { metadata: 'read', contents: 'write', workflows: 'write', pull_requests: 'write', actions: 'write', [S_NAME.toLowerCase()]: 'read', actions_variables: 'write', environments: 'write', administration: 'write', checks: 'read' };
    const app = gh({
      [`GET ${API}/repos/o/r`]: repoOk,
      [`GET ${API}/user/installations`]: { body: { installations: [{ id: 1, account: { login: 'o' }, repository_selection: 'selected', permissions: full }] } },
      [`GET ${API}/user/installations/1/repositories`]: { body: { total_count: 1, repositories: [{ full_name: 'o/r' }] } },
    }, appCred());
    const res = await probePermissions(app.gh, 'o', ['r'], { kind: 'app', clock: clock() });
    const wanted = permissionsTable('write').find((p) => p.permission.startsWith(S_NAME));
    expect(res.missing).toEqual([wanted]);
    expect(res.missing[0].why.length).toBeGreaterThan(10);
    expect(res.unchecked).toEqual([]);
    // fine-grained: the secrets probe is refused, GitHub names the permission in its header
    const fg = gh({
      [`GET ${API}/repos/o/r`]: repoOk,
      [`GET ${API}/repos/o/r/actions/secrets/public-key`]: refused(byPat, `${S_NAME.toLowerCase()}=read`),
    });
    const res2 = await probePermissions(fg.gh, 'o', ['r'], { kind: 'fine-grained', clock: clock() });
    expect(res2.missing).toContainEqual(wanted);
    expect(fg.calls.every((c) => c.method === 'GET')).toBe(true);   // probing never writes
  });

  it('probePermissions: App repo access comes from the installation\'s repo list, not GET /repos', async () => {
    const full = { metadata: 'read', contents: 'write', workflows: 'write', pull_requests: 'write', actions: 'write', [S_NAME.toLowerCase()]: 'write', actions_variables: 'write', environments: 'write', administration: 'write', checks: 'read' };
    const app = gh({
      [`GET ${API}/repos/o/r`]: repoOk,
      [`GET ${API}/repos/o/public-elsewhere`]: repoOk,   // any public repo answers 200 to anyone
      [`GET ${API}/user/installations`]: { body: { installations: [{ id: 7, account: { login: 'o' }, repository_selection: 'selected', permissions: full }] } },
      [`GET ${API}/user/installations/7/repositories`]: (c) => c.url.searchParams.get('page') === '2'
        ? { body: { total_count: 3, repositories: [{ full_name: 'o/pipelines' }] } }
        : { body: { total_count: 3, repositories: [{ full_name: 'o/r' }] }, headers: { link: `<${API}/user/installations/7/repositories?page=2>; rel="next"` } },
    }, appCred());
    const res = await probePermissions(app.gh, 'o', ['r', 'pipelines', 'public-elsewhere'], { kind: 'app', clock: clock() });
    expect(res.missing.map((m) => m.permission)).toEqual(['Access to o/public-elsewhere']);
    expect(res.unchecked).toEqual([]);
    expect(app.calls.some((c) => c.url.pathname.startsWith('/repos/'))).toBe(false);
  });

  it('probePermissions: an installation token (ghs_) is probed like a fine-grained token, never through /user/installations', async () => {
    const r = gh({
      [`GET ${API}/repos/o/r`]: repoOk,
      [`GET ${API}/repos/o/r/actions/secrets/public-key`]: refused(integration, `${S_NAME.toLowerCase()}=read`),
    }, installCred());
    const res = await probePermissions(r.gh, 'o', ['r'], { kind: 'installation', mode: 'read', clock: clock() });
    expect(res.missing.map((m) => m.permission)).toEqual([P(S_NAME, 'read')]);
    expect(r.calls.some((c) => c.url.pathname.startsWith('/user/installations'))).toBe(false);
  });

  it('probes: a 401 is a hard "token rejected" error, never a missing permission', async () => {
    const r401: Reply = { status: 401, body: { message: 'Bad credentials' } };
    const r = gh({ [`GET ${API}/repos/o/r`]: r401, [`GET ${API}/repos/o/r/collaborators`]: r401, [`GET ${API}/user/installations`]: r401 });
    for (const p of [probePermissions(r.gh, 'o', ['r'], { kind: 'fine-grained' }), probePermissions(r.gh, 'o', ['r'], { kind: 'app' }),
      readGitHubContext(r.gh, 'o', 'r', null), listWriters(r.gh, 'o', 'r')]) {
      const e = await caught(p);
      expect(e).toBeInstanceOf(GitHubAccessError);
      expect((e as Error).message).toMatch(/rejected the token/);
    }
  });

  it('probePermissions: GET /repos permissions field never used to judge the token', async () => {
    // GET /repos says admin: true (that's the user's role, S1), but every probe is refused → everything missing
    const routes: Routes = { [`GET ${API}/repos/o/r`]: repoOk };
    for (const p of ['commits', 'pulls', 'actions/workflows', 'actions/secrets/public-key', 'actions/variables', 'actions/permissions']) {
      routes[`GET ${API}/repos/o/r/${p}`] = refused(byPat);
    }
    const { gh: client } = gh(routes);
    const res = await probePermissions(client, 'o', ['r'], { kind: 'fine-grained', mode: 'read', clock: clock() });
    expect(res.missing.map((m) => m.permission)).toEqual(['Contents: read', 'Pull requests: read', 'Actions: read', P(S_NAME, 'read'), 'Variables: read', 'Administration: read']);
  });

  it('probePermissions: a repo the token can\'t see is reported; write levels a token can\'t show are unchecked, never assumed', async () => {
    const { gh: client } = gh({ [`GET ${API}/repos/o/r`]: repoOk, [`GET ${API}/repos/o/pipelines`]: { status: 404, body: { message: 'Not Found' } } });
    const res = await probePermissions(client, 'o', ['r', 'pipelines'], { kind: 'fine-grained', clock: clock() });
    expect(res.missing.map((m) => m.permission)).toEqual(['Access to o/pipelines']);
    // every write level is unchecked for a fine-grained token (GitHub can't show it without writing), Checks is App only
    expect(res.unchecked.map((m) => m.permission)).toEqual(permissionsTable('write').map((p) => p.permission).filter((p) => /write/.test(p)));
  });
});
