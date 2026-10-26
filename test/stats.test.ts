import { describe, expect, it, vi } from 'vitest';
import { GitHubRateLimitError } from '../src/engine/github-rate.js';
import { fetchStats, StatsError, type StatsDeps } from '../src/engine/stats.js';
import type { Candidate, InstallSpec } from '../src/types.js';
import { fakeFetch, fakeOctokit, type Call, type Reply, type Routes } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

const GH = 'https://api.github.com';
const SCORECARD = 'https://api.scorecard.dev/projects/github.com';
const OSV = 'https://api.osv.dev/v1/query';
const NPM_ATTEST = 'https://registry.npmjs.org/-/npm/v1/attestations';
const PYPI = 'https://pypi.org';
const SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
const THIRD_SHA = 'c'.repeat(40);
const NOW = Date.parse('2026-10-26T12:00:00Z');
// Header and option names that hold "auth" are built at runtime (repo rule: no secret-like literals in test/).
const LOGIN_HEADER = 'author' + 'ization';
const LOGIN_OPTION = 'au' + 'th';

const cand = (over: Partial<Candidate> = {}): Candidate => ({
  id: 'tool', name: 'tool', kind: 'action', repo: 'o/r', version: 'v1.2.3', pin: { sha: SHA },
  source: 'discovery', reviewed: false, categories: ['sast'], ...over,
});
/** An npm or PyPI tool: no git pin, the version is the package's. */
const pkgCand = () => cand({ kind: 'cli', version: '', pin: {} });
const npm = (pkg = 'tool', version = '2.0.1'): InstallSpec => ({ method: 'npm', package: pkg, version });
const pip = (pkg = 'some_tool', version = '1.4.0rc1'): InstallSpec => ({ method: 'pip', package: pkg, version });

const b64 = (text: string) => Buffer.from(text).toString('base64');
/** A file in the repo, as GET /repos/{o}/{r}/contents/{path} returns it. */
const file = (text: string): Reply => ({ body: { type: 'file', encoding: 'base64', content: b64(text) } });
const tag = (name: string, sha: string) => ({ name, commit: { sha } });
const repoBody = (over: Record<string, unknown> = {}) => ({
  full_name: 'o/r', stargazers_count: 1234, archived: false, license: { spdx_id: 'MIT' }, owner: { login: 'o', type: 'Organization' }, ...over,
});

/** GitHub answers for a healthy repo o/r: verified organization, latest release v1.2.3 (tagged on SHA), root manifests naming `tool` / `some_tool`. */
const github = (over: Routes = {}): Routes => ({
  [`GET ${GH}/repos/o/r`]: { body: repoBody() },
  [`GET ${GH}/repos/o/r/releases/latest`]: { body: { tag_name: 'v1.2.3', published_at: '2026-09-01T10:00:00Z' } },
  [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v1.2.3', SHA)] },
  [`GET ${GH}/orgs/o`]: { body: { login: 'o', is_verified: true } },
  [`GET ${GH}/advisories`]: { body: [] },
  [`GET ${GH}/repos/o/r/contents/package.json`]: file(JSON.stringify({ name: 'tool', version: '2.0.1' })),
  [`GET ${GH}/repos/o/r/contents/pyproject.toml`]: file('[project]\nname = "some_tool"\nversion = "1.4.0rc1"\n'),
  ...over,
});
const web = (over: Routes = {}): Routes => ({
  [`GET ${SCORECARD}/o/r`]: { body: { date: '2026-10-01', score: 7.5, checks: [] } },
  [`POST ${OSV}`]: { body: {} },
  ...over,
});

/** npm's provenance answer: one SLSA v1 statement built from `repoUrl`. */
const npmProvenance = (repoUrl: string): Reply => ({
  body: {
    attestations: [{
      predicateType: 'https://slsa.dev/provenance/v1',
      bundle: {
        dsseEnvelope: {
          payloadType: 'application/vnd.in-toto+json',
          payload: b64(JSON.stringify({
            _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'pkg:npm/evil-pkg@2.0.1' }], predicateType: 'https://slsa.dev/provenance/v1',
            predicate: { buildDefinition: { externalParameters: { workflow: { repository: repoUrl, path: '.github/workflows/release.yml', ref: 'refs/heads/main' } } } },
          })),
        },
      },
    }],
  },
});

function setup(gh: Routes = github(), net: Routes = web(), extra: Partial<StatsDeps> = {}) {
  const g = fakeOctokit(gh);
  const f = fakeFetch(net);
  const notes: string[] = [];
  const deps: StatsDeps = { gh: g.gh, fetch: f.fetch, notes, sleep: vi.fn(async () => {}), now: () => NOW, ...extra };
  return { deps, ghCalls: g.calls, netCalls: f.calls, notes };
}
const paths = (calls: Call[]) => calls.map((c) => `${c.method} ${c.url.pathname}`);
const affects = (calls: Call[]) => calls.filter((c) => c.url.pathname === '/advisories').map((c) => c.url.searchParams.get('affects'));

describe('stats', () => {
  it('stats: reads stars, archived, licence, latest release, scorecard and verified publisher', async () => {
    const { deps, ghCalls } = setup();
    expect(await fetchStats(cand(), deps)).toEqual({
      repo: 'o/r', stars: 1234, archived: false, lastReleaseAt: '2026-09-01T10:00:00.000Z', scorecard: 7.5, scorecardAt: '2026-10-01T00:00:00.000Z',
      verifiedPublisher: true, license: 'MIT', advisories: 0,
    });
    const adv = ghCalls.find((c) => c.url.pathname === '/advisories');
    expect(adv?.url.searchParams.get('ecosystem')).toBe('actions');
    expect(affects(ghCalls)).toEqual(['o/r@1.2.3']); // the label v1.2.3 is the tag on the pinned SHA
  });

  it('stats: scorecard 404 → null', async () => {
    const { deps, netCalls } = setup(github(), web({ [`GET ${SCORECARD}/o/r`]: { status: 404, body: { message: 'not found' } } }));
    const s = await fetchStats(cand(), deps);
    expect(s.scorecard).toBeNull();
    expect(s.scorecardAt).toBeNull();
    expect(netCalls.map((c) => c.url.href)).toContain(`${SCORECARD}/o/r`);
  });

  it('stats: a scorecard error or a bad answer is an error, never a guess; a bad date is null', async () => {
    for (const reply of [{ status: 500, body: {} }, { body: { score: 'high' } }, { body: { score: 42 } }]) {
      const { deps } = setup(github(), web({ [`GET ${SCORECARD}/o/r`]: reply }));
      await expect(fetchStats(cand(), deps)).rejects.toThrow(StatsError);
    }
    const { deps } = setup(github(), web({ [`GET ${SCORECARD}/o/r`]: { body: { score: 9, date: 'soon' } } }));
    expect(await fetchStats(cand(), deps)).toMatchObject({ scorecard: 9, scorecardAt: null });
  });

  it('stats: osv vuln for npm version → advisories 1', async () => {
    const { deps, ghCalls, netCalls } = setup(
      github({ [`GET ${GH}/repos/o/r/contents/package.json`]: file(JSON.stringify({ name: '@scope/lint-tool' })) }),
      web({ [`POST ${OSV}`]: { body: { vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] } } }),
    );
    const s = await fetchStats(pkgCand(), deps, npm('@scope/lint-tool'));
    expect(s.advisories).toBe(1);
    const osv = netCalls.filter((c) => c.url.href === OSV);
    expect(osv).toHaveLength(1);
    expect(osv[0].method).toBe('POST');
    expect(JSON.parse(osv[0].body ?? '')).toEqual({ version: '2.0.1', package: { name: '@scope/lint-tool', ecosystem: 'npm' } });
    expect(paths(ghCalls)).not.toContain('GET /advisories'); // npm packages are looked up in OSV only
    // the provenance lookup used the registry's escaped scoped name
    expect(netCalls.some((c) => c.url.href === `${NPM_ATTEST}/@scope%2flint-tool@2.0.1`)).toBe(true);
  });

  it('stats: pip install → OSV PyPI ecosystem; no vulns → 0', async () => {
    const { deps, netCalls } = setup();
    const s = await fetchStats(pkgCand(), deps, pip());
    expect(s.advisories).toBe(0);
    expect(JSON.parse(netCalls.find((c) => c.url.href === OSV)?.body ?? '')).toEqual({ version: '1.4.0rc1', package: { name: 'some_tool', ecosystem: 'PyPI' } });
  });

  it('stats: osv error → advisories null (unknown), with a note', async () => {
    const { deps, notes } = setup(github(), web({ [`POST ${OSV}`]: { status: 503 } }));
    const s = await fetchStats(pkgCand(), deps, npm());
    expect(s.advisories).toBeNull();
    expect(notes.join('\n')).toMatch(/couldn't check o\/r for known vulnerabilities/i);
  });

  it('stats: actions advisories use the tag of the pinned SHA', async () => {
    const { deps, ghCalls } = setup(github({
      [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v5.0.0', OTHER_SHA), tag('v4', SHA), tag('v4.2.2', SHA)] },
      [`GET ${GH}/advisories`]: { body: [{ ghsa_id: 'GHSA-1', withdrawn_at: null }, { ghsa_id: 'GHSA-2', withdrawn_at: '2026-01-01T00:00:00Z' }] },
    }));
    const s = await fetchStats(cand({ version: '' }), deps);
    expect(s.advisories).toBe(1); // the withdrawn one doesn't count
    expect(affects(ghCalls)).toEqual(['o/r@4.2.2']); // the full version on that commit; the partial v4 isn't looked up
    expect(ghCalls.find((c) => c.url.pathname === '/advisories')?.url.searchParams.get('ecosystem')).toBe('actions');
  });

  it('stats: v4-only action label with a SHA → the full tag on that SHA is used', async () => {
    const tags = [tag('v4', SHA), tag('v4.2.2', SHA), tag('v4.3.0', OTHER_SHA)];
    const { deps, ghCalls } = setup(github({ [`GET ${GH}/repos/o/r/tags`]: { body: tags } }));
    expect((await fetchStats(cand({ version: 'v4' }), deps)).advisories).toBe(0);
    expect(affects(ghCalls)).toEqual(['o/r@4.2.2']);
    // only the moving v4 tag on the SHA: no full version to look up
    const only = setup(github({ [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v4', SHA), tag('v4.2.2', OTHER_SHA)] } }));
    expect((await fetchStats(cand({ version: 'v4' }), only.deps)).advisories).toBeNull();
    expect(paths(only.ghCalls)).not.toContain('GET /advisories');
    expect(only.notes.join('\n')).toMatch(/no full version tag/i);
  });

  it('stats: label differs from the tag on the pinned SHA → advisories null', async () => {
    const { deps, ghCalls, notes } = setup(github({ [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v1.2.4', SHA), tag('v1.2.3', OTHER_SHA)] } }));
    expect((await fetchStats(cand({ version: 'v1.2.3' }), deps)).advisories).toBeNull();
    expect(paths(ghCalls)).not.toContain('GET /advisories');
    expect(notes.join('\n')).toMatch(/doesn't match the version tags on the pinned commit/i);
    // a partial label that doesn't fit either
    const partial = setup(github({ [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v5.0.0', SHA)] } }));
    expect((await fetchStats(cand({ version: 'v4' }), partial.deps)).advisories).toBeNull();
  });

  it('stats: two version tags on one SHA → each is checked and the highest count kept', async () => {
    // the highest count is on neither the first nor the last version looked up
    const counts: Record<string, number> = { 'o/r@4.2.2': 0, 'o/r@4.2.2-rc.2': 2, 'o/r@4.2.2-rc.1': 1 };
    const { deps, ghCalls } = setup(github({
      [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v4.2.2-rc.1', SHA), tag('v4.2.2', SHA), tag('v4', SHA), tag('v4.2.2-rc.2', SHA)] },
      [`GET ${GH}/advisories`]: (c) => ({ body: Array.from({ length: counts[c.url.searchParams.get('affects') ?? ''] ?? 99 }, () => ({ withdrawn_at: null })) }),
    }));
    expect((await fetchStats(cand({ version: 'v4' }), deps)).advisories).toBe(2);
    expect(affects(ghCalls).sort()).toEqual(['o/r@4.2.2', 'o/r@4.2.2-rc.1', 'o/r@4.2.2-rc.2']);
  });

  it('stats: pinned SHA with no tag → advisories null and a note', async () => {
    const { deps, ghCalls, notes } = setup(github({ [`GET ${GH}/repos/o/r/tags`]: { body: [tag('v9.0.0', OTHER_SHA)] } }));
    const s = await fetchStats(cand({ version: '' }), deps);
    expect(s.advisories).toBeNull();
    expect(paths(ghCalls)).not.toContain('GET /advisories');
    expect(notes.join('\n')).toMatch(/no release tag points at the pinned commit of o\/r/i);
  });

  it('stats: no version and no SHA → the latest release tag is checked', async () => {
    const { deps, ghCalls } = setup();
    await fetchStats(cand({ version: '', pin: {} }), deps);
    expect(affects(ghCalls)).toEqual(['o/r@1.2.3']);
  });

  it('stats: npm version "4" (partial, no SHA) → advisories null', async () => {
    for (const version of ['4', '4.2', 'v4']) {
      const { deps, netCalls, notes } = setup();
      expect((await fetchStats(pkgCand(), deps, npm('tool', version))).advisories, version).toBeNull();
      expect(netCalls.some((c) => c.url.href === OSV)).toBe(false);
      expect(notes.join('\n')).toMatch(/isn't a full version/i);
    }
    // a partial latest-release tag is refused the same way
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r/releases/latest`]: { body: { tag_name: 'v2', published_at: '2026-09-01T10:00:00Z' } } }));
    expect((await fetchStats(cand({ version: '', pin: {} }), deps)).advisories).toBeNull();
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

  it('stats: no release → commit date of the highest semver tag (not the first listed); no tags → null', async () => {
    const { deps, ghCalls } = setup(github({
      [`GET ${GH}/repos/o/r/releases/latest`]: { status: 404, body: { message: 'Not Found' } },
      [`GET ${GH}/repos/o/r/tags`]: { body: [tag('nightly', SHA), tag('v1.9.0', THIRD_SHA), tag('v1.10.0', OTHER_SHA), tag('v1.10.0-rc.1', SHA)] },
      [`GET ${GH}/repos/o/r/git/commits/${OTHER_SHA}`]: { body: { sha: OTHER_SHA, committer: { date: '2026-03-04T05:06:07Z' } } },
    }));
    expect((await fetchStats(cand({ version: '', pin: {} }), deps)).lastReleaseAt).toBe('2026-03-04T05:06:07.000Z');
    expect(paths(ghCalls)).toContain(`GET /repos/o/r/git/commits/${OTHER_SHA}`);

    const none = setup(github({ [`GET ${GH}/repos/o/r/releases/latest`]: { status: 404 }, [`GET ${GH}/repos/o/r/tags`]: { body: [] } }));
    expect((await fetchStats(cand({ version: '', pin: {} }), none.deps)).lastReleaseAt).toBeNull();
  });

  it('stats: licence NOASSERTION kept; no licence → null; a strange licence id → null', async () => {
    const repo = (license: unknown) => github({ [`GET ${GH}/repos/o/r`]: { body: repoBody({ stargazers_count: 1, archived: true, license, owner: { login: 'o', type: 'User' } }) } });
    const of = async (license: unknown) => fetchStats(cand(), setup(repo(license)).deps);
    expect((await of({ spdx_id: 'NOASSERTION' })).license).toBe('NOASSERTION');
    expect((await of(null)).license).toBeNull();
    expect((await of({ spdx_id: 'MIT\u001b[31m' })).license).toBeNull();
    const s = await of({ spdx_id: 'Apache-2.0' });
    expect(s).toMatchObject({ license: 'Apache-2.0', archived: true, stars: 1 });
  });

  it('stats: verifiedPublisher only for a verified organization', async () => {
    const user = setup(github({ [`GET ${GH}/repos/o/r`]: { body: repoBody({ owner: { login: 'o', type: 'User' } }) } }));
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
    for (const install of [npm('../evil'), npm('UPPER'), pip('bad name')]) {
      const { deps, ghCalls, netCalls } = setup();
      await expect(fetchStats(pkgCand(), deps, install), install.package).rejects.toThrow(StatsError);
      expect(ghCalls.length + netCalls.length).toBe(0);
    }
  });

  it('stats: repo not found → StatsError', async () => {
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r`]: { status: 404, body: { message: 'Not Found' } } }));
    await expect(fetchStats(cand(), deps)).rejects.toThrow(StatsError);
  });

  it('stats: a renamed repo (301 redirect) → StatsError; case differences are fine', async () => {
    const { deps, ghCalls } = setup(github({
      [`GET ${GH}/repos/o/r`]: { status: 301, body: { message: 'Moved Permanently' }, headers: { location: `${GH}/repositories/42` } },
      [`GET ${GH}/repositories/42`]: { body: repoBody({ full_name: 'neworg/r' }) },
    }));
    await expect(fetchStats(cand(), deps)).rejects.toThrow("The repository moved to neworg/r; pipegen checks the exact name only.");
    expect(paths(ghCalls)).toEqual(['GET /repos/o/r', 'GET /repositories/42']); // nothing else is looked up
    const cased = setup(github({ [`GET ${GH}/repos/o/r`]: { body: repoBody({ full_name: 'O/R' }) } }));
    expect((await fetchStats(cand(), cased.deps)).repo).toBe('o/r');
    const odd = setup(github({ [`GET ${GH}/repos/o/r`]: { body: repoBody({ full_name: 'x/y\u001b[2J' }) } }));
    await expect(fetchStats(cand(), odd.deps)).rejects.toThrow(/moved to x\/y;/); // control sequences removed from the shown name
  });

  it('stats: package whose registry points at a popular repo but the root manifest names another package → rejected', async () => {
    // evil-pkg claims o/r; o/r's own package.json is `tool`, and evil-pkg has no provenance
    const { deps, netCalls } = setup();
    await expect(fetchStats(pkgCand(), deps, npm('evil-pkg'))).rejects.toThrow("Couldn't confirm that evil-pkg is published from o/r.");
    expect(netCalls.some((c) => c.url.origin === 'https://api.scorecard.dev' || c.url.href === OSV)).toBe(false); // no stats for it
    // no root manifest at all → rejected too
    const bare = setup(github({ [`GET ${GH}/repos/o/r/contents/package.json`]: { status: 404 } }));
    await expect(fetchStats(pkgCand(), bare.deps, npm('tool'))).rejects.toThrow(StatsError);
    // PyPI the same way
    const py = setup();
    await expect(fetchStats(pkgCand(), py.deps, pip('other-tool'))).rejects.toThrow("Couldn't confirm that other-tool is published from o/r.");
  });

  it('stats: root manifest match → accepted (PyPI names PEP 503-normalised, poetry too)', async () => {
    expect((await fetchStats(pkgCand(), setup().deps, npm('tool'))).repo).toBe('o/r');
    expect((await fetchStats(pkgCand(), setup().deps, pip('Some.Tool'))).repo).toBe('o/r');
    const poetry = setup(github({ [`GET ${GH}/repos/o/r/contents/pyproject.toml`]: file('[tool.poetry]\nname = "some-tool"\n') }));
    expect((await fetchStats(pkgCand(), poetry.deps, pip('some_tool'))).repo).toBe('o/r');
  });

  it('stats: provenance match → accepted', async () => {
    // a monorepo sub-package: the root package.json names the workspace, npm provenance names o/r
    const { deps, netCalls } = setup(github(), web({ [`GET ${NPM_ATTEST}/evil-pkg@2.0.1`]: npmProvenance('https://github.com/o/r') }));
    expect((await fetchStats(pkgCand(), deps, npm('evil-pkg'))).repo).toBe('o/r');
    expect(netCalls.some((c) => c.url.href === `${NPM_ATTEST}/evil-pkg@2.0.1`)).toBe(true);
    // PyPI Trusted Publisher
    const file1 = 'other_tool-1.0.0-py3-none-any.whl';
    const py = setup(github(), web({
      [`GET ${PYPI}/pypi/other-tool/1.0.0/json`]: { body: { urls: [{ filename: file1 }] } },
      [`GET ${PYPI}/integrity/other-tool/1.0.0/${file1}/provenance`]: { body: { version: 1, attestation_bundles: [{ publisher: { kind: 'GitHub', repository: 'O/R', workflow: 'release.yml' }, attestations: [] }] } },
    }));
    expect((await fetchStats(pkgCand(), py.deps, pip('other-tool', '1.0.0'))).repo).toBe('o/r');
  });

  it('stats: provenance naming another repo → rejected', async () => {
    const other = web({ [`GET ${NPM_ATTEST}/evil-pkg@2.0.1`]: npmProvenance('https://github.com/attacker/r') });
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r/contents/package.json`]: { status: 404 } }), other);
    await expect(fetchStats(pkgCand(), deps, npm('evil-pkg'))).rejects.toThrow("Couldn't confirm that evil-pkg is published from o/r.");
    // even when the root manifest names the package: the registry says it was built elsewhere
    const both = setup(github({ [`GET ${GH}/repos/o/r/contents/package.json`]: file(JSON.stringify({ name: 'evil-pkg' })) }), other);
    await expect(fetchStats(pkgCand(), both.deps, npm('evil-pkg'))).rejects.toThrow(StatsError);
  });

  it('stats: only the Octokit carries the credential; deps.fetch never gets an authorization header', async () => {
    const cred = fake.githubClassic();
    const g = fakeOctokit(github({
      [`GET ${GH}/repos/o/r/releases/latest`]: { status: 404 },
      [`GET ${GH}/repos/o/r/git/commits/${SHA}`]: { body: { committer: { date: '2026-03-04T05:06:07Z' } } },
    }), { [LOGIN_OPTION]: cred });
    const f = fakeFetch(web());
    const deps: StatsDeps = { gh: g.gh, fetch: f.fetch, notes: [] };
    await fetchStats(cand({ version: '' }), deps); // actions: GitHub advisories + scorecard
    await fetchStats(pkgCand(), deps, npm()); // + npm provenance, root manifest, OSV
    // every Octokit request went to api.github.com, with the credential
    expect(g.calls.length).toBeGreaterThan(4);
    for (const c of g.calls) {
      expect(c.url.origin).toBe(GH);
      expect(c.headers[LOGIN_HEADER]).toContain(cred);
    }
    // deps.fetch (scorecard, npm, OSV) never got an auth header, or the credential anywhere
    expect(f.calls.map((c) => c.url.origin).sort()).toEqual(['https://api.osv.dev', 'https://api.scorecard.dev', 'https://api.scorecard.dev', 'https://registry.npmjs.org']);
    for (const c of f.calls) {
      expect(Object.keys(c.headers).map((k) => k.toLowerCase())).not.toContain(LOGIN_HEADER);
      expect(JSON.stringify(c)).not.toContain(cred);
    }
  });

  it('stats: GitHub rate limits go through the shared helper (injected sleep)', async () => {
    let n = 0;
    const reset = String(Math.floor(NOW / 1000) + 30);
    const { deps } = setup(github({
      [`GET ${GH}/repos/o/r`]: () => (n++ === 0 ? { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset } } : { body: repoBody() }),
    }));
    expect((await fetchStats(cand(), deps)).stars).toBe(1234);
    expect(deps.sleep).toHaveBeenCalledWith(31_000);

    const far = String(Math.floor(NOW / 1000) + 3600);
    const limited = setup(github({ [`GET ${GH}/repos/o/r`]: { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': far } } }));
    await expect(fetchStats(cand(), limited.deps)).rejects.toThrow(GitHubRateLimitError);
    expect(limited.deps.sleep).not.toHaveBeenCalled();
  });

  it('stats: once the run\'s rate-limit wait budget is spent → StatsError, no more sleeping', async () => {
    const reset = String(Math.floor(NOW / 1000) + 50);
    let n = 0;
    // the repo call is limited on every first try: 51 s per fetchStats
    const { deps } = setup(github({
      [`GET ${GH}/repos/o/r`]: () => (n++ % 2 === 0 ? { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset } } : { body: repoBody() }),
    }));
    await fetchStats(cand(), deps);
    await fetchStats(cand(), deps); // 102 s of the default 120 s spent
    await expect(fetchStats(cand(), deps)).rejects.toThrow(new StatsError('GitHub rate limit: stopped waiting.'));
    expect(deps.sleep).toHaveBeenCalledTimes(2);
    // an injected budget
    const small = setup(github({ [`GET ${GH}/repos/o/r`]: { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset } } }), web(), { budget: { remainingMs: 5_000 } });
    await expect(fetchStats(cand(), small.deps)).rejects.toThrow('GitHub rate limit: stopped waiting.');
    expect(small.deps.sleep).not.toHaveBeenCalled();
  });
});
