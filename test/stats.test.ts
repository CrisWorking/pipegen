import { describe, expect, it, vi } from 'vitest';
import { GitHubRateLimitError } from '../src/engine/github-rate.js';
import { fetchStats, StatsError, type StatsDeps } from '../src/engine/stats.js';
import type { Candidate, InstallSpec } from '../src/types.js';
import { fakeFetch, fakeOctokit, type Call, type Routes } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

const GH = 'https://api.github.com';
const SCORECARD = 'https://api.scorecard.dev/projects/github.com';
const OSV = 'https://api.osv.dev/v1/query';
const SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
// Header and option names that hold "auth" are built at runtime (repo rule: no secret-like literals in test/).
const LOGIN_HEADER = 'author' + 'ization';
const LOGIN_OPTION = 'au' + 'th';

const cand = (over: Partial<Candidate> = {}): Candidate => ({
  id: 'tool', name: 'tool', kind: 'action', repo: 'o/r', version: 'v1.2.3', pin: { sha: SHA },
  source: 'discovery', reviewed: false, categories: ['sast'], ...over,
});

/** GitHub answers for a healthy repo o/r owned by a verified organization, latest release v1.2.3. */
const github = (over: Routes = {}): Routes => ({
  [`GET ${GH}/repos/o/r`]: { body: { full_name: 'o/r', stargazers_count: 1234, archived: false, license: { spdx_id: 'MIT' }, owner: { login: 'o', type: 'Organization' } } },
  [`GET ${GH}/repos/o/r/releases/latest`]: { body: { tag_name: 'v1.2.3', published_at: '2026-09-01T10:00:00Z' } },
  [`GET ${GH}/orgs/o`]: { body: { login: 'o', is_verified: true } },
  [`GET ${GH}/advisories`]: { body: [] },
  ...over,
});
const web = (over: Routes = {}): Routes => ({
  [`GET ${SCORECARD}/o/r`]: { body: { score: 7.5, checks: [] } },
  [`POST ${OSV}`]: { body: {} },
  ...over,
});

function setup(gh: Routes = github(), net: Routes = web(), extra: Partial<StatsDeps> = {}) {
  const g = fakeOctokit(gh);
  const f = fakeFetch(net);
  const notes: string[] = [];
  const deps: StatsDeps = { gh: g.gh, fetch: f.fetch, notes, sleep: vi.fn(async () => {}), now: () => Date.parse('2026-10-26T12:00:00Z'), ...extra };
  return { deps, ghCalls: g.calls, netCalls: f.calls, notes };
}
const paths = (calls: Call[]) => calls.map((c) => `${c.method} ${c.url.pathname}`);

describe('stats', () => {
  it('stats: reads stars, archived, licence, latest release, scorecard and verified publisher', async () => {
    const { deps, ghCalls } = setup();
    expect(await fetchStats(cand(), deps)).toEqual({
      repo: 'o/r', stars: 1234, archived: false, lastReleaseAt: '2026-09-01T10:00:00.000Z', scorecard: 7.5,
      verifiedPublisher: true, license: 'MIT', advisories: 0,
    });
    const adv = ghCalls.find((c) => c.url.pathname === '/advisories');
    expect(adv?.url.searchParams.get('ecosystem')).toBe('actions');
    expect(adv?.url.searchParams.get('affects')).toBe('o/r@1.2.3'); // c.version, leading v dropped (S19)
  });

  it('stats: scorecard 404 → null', async () => {
    const { deps, netCalls } = setup(github(), web({ [`GET ${SCORECARD}/o/r`]: { status: 404, body: { message: 'not found' } } }));
    const s = await fetchStats(cand(), deps);
    expect(s.scorecard).toBeNull();
    expect(netCalls.map((c) => c.url.href)).toContain(`${SCORECARD}/o/r`);
  });

  it('stats: a scorecard error or a bad answer is an error, never a guess', async () => {
    for (const reply of [{ status: 500, body: {} }, { body: { score: 'high' } }, { body: { score: 42 } }]) {
      const { deps } = setup(github(), web({ [`GET ${SCORECARD}/o/r`]: reply }));
      await expect(fetchStats(cand(), deps)).rejects.toThrow(StatsError);
    }
  });

  it('stats: osv vuln for npm version → advisories 1', async () => {
    const install: InstallSpec = { method: 'npm', package: '@scope/lint-tool', version: '2.0.1' };
    const { deps, ghCalls, netCalls } = setup(github(), web({ [`POST ${OSV}`]: { body: { vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] } } }));
    const s = await fetchStats(cand({ kind: 'cli', version: '', pin: {} }), deps, install);
    expect(s.advisories).toBe(1);
    const osv = netCalls.filter((c) => c.url.href === OSV);
    expect(osv).toHaveLength(1);
    expect(osv[0].method).toBe('POST');
    expect(JSON.parse(osv[0].body ?? '')).toEqual({ version: '2.0.1', package: { name: '@scope/lint-tool', ecosystem: 'npm' } });
    expect(paths(ghCalls)).not.toContain('GET /advisories'); // npm packages are looked up in OSV only
  });

  it('stats: pip install → OSV PyPI ecosystem; no vulns → 0', async () => {
    const { deps, netCalls } = setup();
    const s = await fetchStats(cand({ kind: 'cli' }), deps, { method: 'pip', package: 'some_tool', version: '1.4.0rc1' });
    expect(s.advisories).toBe(0);
    expect(JSON.parse(netCalls.find((c) => c.url.href === OSV)?.body ?? '')).toEqual({ version: '1.4.0rc1', package: { name: 'some_tool', ecosystem: 'PyPI' } });
  });

  it('stats: osv error → advisories null (unknown), with a note', async () => {
    const { deps, notes } = setup(github(), web({ [`POST ${OSV}`]: { status: 503 } }));
    const s = await fetchStats(cand({ kind: 'cli' }), deps, { method: 'npm', package: 'tool', version: '1.0.0' });
    expect(s.advisories).toBeNull();
    expect(notes.join('\n')).toMatch(/couldn't check o\/r for known vulnerabilities/i);
  });

  it('stats: actions advisories use the tag of the pinned SHA', async () => {
    const tags = [
      { name: 'v5.0.0', commit: { sha: OTHER_SHA } },
      { name: 'v4', commit: { sha: SHA } },
      { name: 'v4.2.2', commit: { sha: SHA } },
    ];
    const { deps, ghCalls } = setup(github({
      [`GET ${GH}/repos/o/r/tags`]: { body: tags },
      [`GET ${GH}/advisories`]: { body: [{ ghsa_id: 'GHSA-1', withdrawn_at: null }, { ghsa_id: 'GHSA-2', withdrawn_at: '2026-01-01T00:00:00Z' }] },
    }));
    const s = await fetchStats(cand({ version: '' }), deps);
    expect(s.advisories).toBe(1); // the withdrawn one doesn't count
    const adv = ghCalls.find((c) => c.url.pathname === '/advisories');
    expect(adv?.url.searchParams.get('affects')).toBe('o/r@4.2.2'); // the most specific tag on that commit
    expect(adv?.url.searchParams.get('ecosystem')).toBe('actions');
  });

  it('stats: pinned SHA with no tag → advisories null and a note', async () => {
    const { deps, ghCalls, notes } = setup(github({ [`GET ${GH}/repos/o/r/tags`]: { body: [{ name: 'v9.0.0', commit: { sha: OTHER_SHA } }] } }));
    const s = await fetchStats(cand({ version: '' }), deps);
    expect(s.advisories).toBeNull();
    expect(paths(ghCalls)).not.toContain('GET /advisories');
    expect(notes.join('\n')).toMatch(/no release tag points at the pinned commit of o\/r/i);
  });

  it('stats: no version and no SHA → the latest release tag is checked', async () => {
    const { deps, ghCalls } = setup();
    await fetchStats(cand({ version: '', pin: {} }), deps);
    expect(ghCalls.find((c) => c.url.pathname === '/advisories')?.url.searchParams.get('affects')).toBe('o/r@1.2.3');
  });

  it('stats: a version that is not a version → advisories null', async () => {
    for (const version of ['main', '1.2.3; rm -rf', 'v1.2.3/../x']) {
      const { deps, ghCalls, notes } = setup();
      const s = await fetchStats(cand({ version }), deps);
      expect(s.advisories, version).toBeNull();
      expect(paths(ghCalls)).not.toContain('GET /advisories');
      expect(notes.join('\n')).toMatch(/isn't a version pipegen can look up/i);
    }
  });

  it('stats: docker and release binaries → advisories null with a note', async () => {
    for (const [c, install] of [
      [cand({ kind: 'docker' }), undefined],
      [cand({ kind: 'cli' }), undefined],
      [cand({ kind: 'cli' }), { method: 'github-release', package: 'o/r', version: '1.2.3' }],
    ] as [Candidate, InstallSpec | undefined][]) {
      const { deps, ghCalls, netCalls, notes } = setup();
      expect((await fetchStats(c, deps, install)).advisories).toBeNull();
      expect(paths(ghCalls)).not.toContain('GET /advisories');
      expect(netCalls.some((x) => x.url.href === OSV)).toBe(false);
      expect(notes.join('\n')).toMatch(/can't look up known vulnerabilities/i);
    }
  });

  it('stats: no release → latest tag commit date; no tags → null', async () => {
    const { deps } = setup(github({
      [`GET ${GH}/repos/o/r/releases/latest`]: { status: 404, body: { message: 'Not Found' } },
      [`GET ${GH}/repos/o/r/tags`]: { body: [{ name: 'v2.0.0', commit: { sha: OTHER_SHA } }] },
      [`GET ${GH}/repos/o/r/git/commits/${OTHER_SHA}`]: { body: { sha: OTHER_SHA, committer: { date: '2026-03-04T05:06:07Z' } } },
    }));
    expect((await fetchStats(cand({ version: '1.0.0' }), deps)).lastReleaseAt).toBe('2026-03-04T05:06:07.000Z');

    const none = setup(github({ [`GET ${GH}/repos/o/r/releases/latest`]: { status: 404 }, [`GET ${GH}/repos/o/r/tags`]: { body: [] } }));
    const s = await fetchStats(cand({ version: '1.0.0' }), none.deps);
    expect(s.lastReleaseAt).toBeNull();
  });

  it('stats: licence NOASSERTION kept; no licence → null; a strange licence id → null', async () => {
    const repo = (license: unknown) => github({ [`GET ${GH}/repos/o/r`]: { body: { stargazers_count: 1, archived: true, license, owner: { login: 'o', type: 'User' } } } });
    const of = async (license: unknown) => fetchStats(cand(), setup(repo(license)).deps);
    expect((await of({ spdx_id: 'NOASSERTION' })).license).toBe('NOASSERTION');
    expect((await of(null)).license).toBeNull();
    expect((await of({ spdx_id: 'MIT\u001b[31m' })).license).toBeNull();
    const s = await of({ spdx_id: 'Apache-2.0' });
    expect(s).toMatchObject({ license: 'Apache-2.0', archived: true, stars: 1 });
  });

  it('stats: verifiedPublisher only for a verified organization', async () => {
    const user = setup(github({ [`GET ${GH}/repos/o/r`]: { body: { stargazers_count: 1, archived: false, license: null, owner: { login: 'o', type: 'User' } } } }));
    expect((await fetchStats(cand(), user.deps)).verifiedPublisher).toBe(false);
    expect(paths(user.ghCalls)).not.toContain('GET /orgs/o'); // a user has no org record to ask for
    const unverified = setup(github({ [`GET ${GH}/orgs/o`]: { body: { login: 'o', is_verified: false } } }));
    expect((await fetchStats(cand(), unverified.deps)).verifiedPublisher).toBe(false);
    const failing = setup(github({ [`GET ${GH}/orgs/o`]: { status: 500 } }));
    expect((await fetchStats(cand(), failing.deps)).verifiedPublisher).toBe(false);
  });

  it('stats: invalid repo or package name → refused before any request', async () => {
    const badRepos = ['o', 'o/r/x', '../r', 'o/..', 'o/.', '-o/r', 'o/r?x=1', 'o/r#x', 'o%2Fr/x', 'o /r', `${'a'.repeat(40)}/r`, 'o/r\n'];
    for (const repo of badRepos) {
      const { deps, ghCalls, netCalls } = setup();
      await expect(fetchStats(cand({ repo }), deps), JSON.stringify(repo)).rejects.toThrow(StatsError);
      expect(ghCalls.length + netCalls.length).toBe(0);
    }
    for (const install of [
      { method: 'npm', package: '../evil', version: '1.0.0' },
      { method: 'npm', package: 'UPPER', version: '1.0.0' },
      { method: 'pip', package: 'bad name', version: '1.0.0' },
    ] as InstallSpec[]) {
      const { deps, ghCalls, netCalls } = setup();
      await expect(fetchStats(cand({ kind: 'cli' }), deps, install), install.package).rejects.toThrow(StatsError);
      expect(ghCalls.length + netCalls.length).toBe(0);
    }
  });

  it('stats: repo not found → StatsError', async () => {
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r`]: { status: 404, body: { message: 'Not Found' } } }));
    await expect(fetchStats(cand(), deps)).rejects.toThrow(StatsError);
  });

  it('stats: only the Octokit carries the credential; deps.fetch never gets an authorization header', async () => {
    const cred = fake.githubClassic();
    const g = fakeOctokit(github({
      [`GET ${GH}/repos/o/r/releases/latest`]: { status: 404 },
      [`GET ${GH}/repos/o/r/tags`]: { body: [{ name: 'v1.2.3', commit: { sha: SHA } }] },
      [`GET ${GH}/repos/o/r/git/commits/${SHA}`]: { body: { committer: { date: '2026-03-04T05:06:07Z' } } },
    }), { [LOGIN_OPTION]: cred });
    const f = fakeFetch(web());
    const deps: StatsDeps = { gh: g.gh, fetch: f.fetch, notes: [] };
    await fetchStats(cand({ version: '' }), deps); // actions: GitHub advisories + scorecard
    await fetchStats(cand({ kind: 'cli' }), deps, { method: 'npm', package: 'tool', version: '1.0.0' }); // + OSV
    // every Octokit request went to api.github.com, with the credential
    expect(g.calls.length).toBeGreaterThan(4);
    for (const c of g.calls) {
      expect(c.url.origin).toBe(GH);
      expect(c.headers[LOGIN_HEADER]).toContain(cred);
    }
    // deps.fetch (scorecard, OSV) never got an auth header, or the credential anywhere
    expect(f.calls.map((c) => c.url.origin).sort()).toEqual(['https://api.osv.dev', 'https://api.scorecard.dev', 'https://api.scorecard.dev']);
    for (const c of f.calls) {
      expect(Object.keys(c.headers).map((k) => k.toLowerCase())).not.toContain(LOGIN_HEADER);
      expect(JSON.stringify(c)).not.toContain(cred);
    }
  });

  it('stats: GitHub rate limits go through the shared helper (injected sleep)', async () => {
    let n = 0;
    const reset = String(Math.floor(Date.parse('2026-10-26T12:00:00Z') / 1000) + 30);
    const repo = github()[`GET ${GH}/repos/o/r`];
    const { deps } = setup(github({
      [`GET ${GH}/repos/o/r`]: () => (n++ === 0 ? { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset } } : repo as { body: unknown }),
    }));
    expect((await fetchStats(cand(), deps)).stars).toBe(1234);
    expect(deps.sleep).toHaveBeenCalledWith(31_000);

    const far = String(Math.floor(Date.parse('2026-10-26T12:00:00Z') / 1000) + 3600);
    const limited = setup(github({ [`GET ${GH}/repos/o/r`]: { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': far } } }));
    await expect(fetchStats(cand(), limited.deps)).rejects.toThrow(GitHubRateLimitError);
    expect(limited.deps.sleep).not.toHaveBeenCalled();
  });
});
