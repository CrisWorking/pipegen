import { describe, expect, it } from 'vitest';
import { binaryItems, changedLockEntries, formatReport, prFromEnv, repoPath, runCooldown, type Files } from '../scripts/cooldown.js';

const NOW = new Date('2026-10-27T12:00:00Z');
const daysAgo = (d: number): string => new Date(NOW.getTime() - d * 86_400_000).toISOString().replace('.000Z', 'Z');
const SHA = 'a'.repeat(40);
const SHA2 = 'b'.repeat(40);
const HEX = 'c'.repeat(64);
const HEX2 = 'd'.repeat(64);
const DIGEST = `sha256:${'e'.repeat(64)}`;

const integ = (name: string, v: string): string => `sha512-${name.replace(/\W/g, '')}${v.replace(/\W/g, '')}`;
const tgz = (name: string, v: string): string => `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${v}.tgz`;

interface Pkg { v: string; resolved?: string; integrity?: string; extra?: Record<string, unknown>; at?: string }
function lock(pkgs: Record<string, Pkg | string>, over: Record<string, unknown> = {}): string {
  const packages: Record<string, unknown> = { '': { name: 'x' } };
  for (const [name, p] of Object.entries(pkgs)) {
    const q = typeof p === 'string' ? { v: p } : p;
    packages[`node_modules/${name}`] = { version: q.v, resolved: q.resolved ?? tgz(name, q.v), integrity: q.integrity ?? integ(name, q.v), ...q.extra };
  }
  return JSON.stringify({ lockfileVersion: 3, packages, ...over });
}

/** Routes: URL -> JSON body, or a status number. Anything unlisted is a 404. Every URL asked is recorded. */
type Routes = Record<string, unknown>;
function router(routes: Routes, calls: string[] = []): typeof fetch {
  return (async (url: string) => {
    calls.push(String(url));
    const r = routes[String(url)];
    if (r === undefined) return new Response('{}', { status: 404 });
    if (typeof r === 'number') return new Response('x', { status: r });
    return new Response(JSON.stringify(r), { status: 200 });
  }) as typeof fetch;
}

const npmDoc = (name: string, versions: Record<string, string>) => ({
  [`https://registry.npmjs.org/${name.replace('/', '%2f')}`]: {
    versions: Object.fromEntries(Object.keys(versions).map((v) => [v, { dist: { integrity: integ(name, v) } }])),
    time: { created: daysAgo(900), modified: daysAgo(1), ...versions },
  },
});

const run = (base: Files, head: Files, f: typeof fetch, extra = {}) => runCooldown({ base, head, fetch: f, now: NOW, ...extra });
const problems = (r: { findings: Array<{ problem: string }> }): string => r.findings.map((x) => x.problem).join(' | ');

describe('cooldown: npm lockfile', () => {
  it('fails a new transitive package under 7 days and passes an old one', async () => {
    const base = { 'package-lock.json': lock({ tsup: '9.0.0' }) };
    const head = { 'package-lock.json': lock({ tsup: '9.0.0', rollup: '4.64.12', ms: '2.1.3' }) };
    const r = await run(base, head, router({ ...npmDoc('rollup', { '4.64.12': daysAgo(1) }), ...npmDoc('ms', { '2.1.3': daysAgo(400) }) }));
    expect(r.findings.map((x) => x.name)).toEqual(['rollup']);
    expect(formatReport(r)).toContain('rollup 4.64.12');
  });

  it('ignores a version that did not change and a removed package, with no request', async () => {
    const calls: string[] = [];
    const base = { 'package-lock.json': lock({ tsup: '9.0.0', gone: '1.0.0' }) };
    const r = await run(base, { 'package-lock.json': lock({ tsup: '9.0.0' }) }, router({}, calls));
    expect(r.ok).toBe(true);
    expect(calls).toEqual([]);
  });

  it('exactly 7 days passes, 6.9 days fails', async () => {
    const r = await run({}, { 'package-lock.json': lock({ a: '1.0.0', b: '1.0.0' }) }, router({ ...npmDoc('a', { '1.0.0': daysAgo(7) }), ...npmDoc('b', { '1.0.0': daysAgo(6.9) }) }));
    expect(r.findings.map((x) => x.name)).toEqual(['b']);
  });

  it('fails closed on a registry error (and says how to retry), a network exception and a 404', async () => {
    const head = { 'package-lock.json': lock({ a: '1.0.0' }) };
    const r = await run({}, head, router({ 'https://registry.npmjs.org/a': 500 }));
    expect(r.findings[0]?.lookupFailed).toBe(true);
    expect(formatReport(r)).toContain('Re-run the failed job');
    const boom = (async () => { throw new TypeError('down'); }) as unknown as typeof fetch;
    expect((await run({}, head, boom)).ok).toBe(false);
    expect((await run({}, head, router({}))).ok).toBe(false);
  });

  it('caps the number of lookups', async () => {
    const many: Record<string, string> = {};
    for (let i = 0; i < 5; i++) many[`p${i}`] = '1.0.0';
    const r = await run({}, { 'package-lock.json': lock(many) }, router({}), { maxLookups: 3 });
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('cap of 3');
  });

  it('encodes scoped names', async () => {
    const calls: string[] = [];
    const r = await run({}, { 'package-lock.json': lock({ '@types/node': '26.0.0' }) }, router(npmDoc('@types/node', { '26.0.0': daysAgo(30) }), calls));
    expect(r.ok).toBe(true);
    expect(calls[0]).toBe('https://registry.npmjs.org/@types%2fnode');
  });

  it('probe 1a: same version with a swapped tarball and integrity counts as changed', async () => {
    const base = { 'package-lock.json': lock({ lodash: '4.17.21' }) };
    const head = { 'package-lock.json': lock({ lodash: { v: '4.17.21', resolved: tgz('lodash', '9.9.9'), integrity: 'sha512-B' } }) };
    const r = await run(base, head, router(npmDoc('lodash', { '4.17.21': daysAgo(900), '9.9.9': daysAgo(1) })));
    expect(r.ok).toBe(false);
    expect(changedLockEntries(base['package-lock.json'], head['package-lock.json'])).toHaveLength(1);
  });

  it('probe 1b: entry.name lie with a tarball on another host fails', async () => {
    const head = { 'package-lock.json': lock({ evil: { v: '4.17.21', resolved: 'https://evil.example/x.tgz', extra: { name: 'lodash' } } }) };
    const r = await run({}, head, router(npmDoc('lodash', { '4.17.21': daysAgo(900) })));
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('does not match');
  });

  it('an npm: alias uses the real name from its tarball', async () => {
    const head = { 'package-lock.json': lock({ mine: { v: '4.17.21', resolved: tgz('lodash', '4.17.21'), integrity: integ('lodash', '4.17.21'), extra: { name: 'lodash' } } }) };
    const calls: string[] = [];
    const r = await run({}, head, router(npmDoc('lodash', { '4.17.21': daysAgo(900) }), calls));
    expect(r.ok).toBe(true);
    expect(calls).toEqual(['https://registry.npmjs.org/lodash']);
  });

  it('probe 1c: version "created" (or any non-semver, or a version missing from versions) fails', async () => {
    const docs = npmDoc('lodash', { '4.17.21': daysAgo(900) });
    const r1 = await run({}, { 'package-lock.json': lock({ lodash: { v: 'created', resolved: tgz('lodash', 'created') } }) }, router(docs));
    expect(problems(r1)).toContain('semver');
    const r2 = await run({}, { 'package-lock.json': lock({ lodash: '9.9.9' }) }, router(docs));
    expect(problems(r2)).toContain('does not exist');
  });

  it('a resolved that is not the registry tarball fails', async () => {
    const docs = npmDoc('lodash', { '4.17.21': daysAgo(900) });
    for (const resolved of ['https://registry.npmjs.org/other/-/other-4.17.21.tgz', 'git+ssh://git@github.com/x/y.git#abc', 'http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz']) {
      const r = await run({}, { 'package-lock.json': lock({ lodash: { v: '4.17.21', resolved } }) }, router(docs));
      expect(r.ok, resolved).toBe(false);
    }
  });

  it('integrity must equal the registry dist.integrity', async () => {
    const r = await run({}, { 'package-lock.json': lock({ lodash: { v: '4.17.21', integrity: 'sha512-WRONG' } }) }, router(npmDoc('lodash', { '4.17.21': daysAgo(900) })));
    expect(problems(r)).toContain('integrity');
  });

  it('probe 1d: lockfileVersion 1, no packages, or a removed head lockfile fails', async () => {
    const base = { 'package-lock.json': lock({ lodash: '4.17.21' }) };
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { lodash: { version: '9.9.9' } } });
    expect((await run(base, { 'package-lock.json': v1 }, router({}))).ok).toBe(false);
    expect((await run(base, { 'package-lock.json': JSON.stringify({ lockfileVersion: 3 }) }, router({}))).ok).toBe(false);
    expect((await run(base, {}, router({}))).ok).toBe(false);
    await expect(run(base, { 'package-lock.json': '{ nope SECRET' }, router({}))).rejects.toThrow(/not valid JSON/);
  });

  it('skips a declared workspace and its link without a lookup', async () => {
    const calls: string[] = [];
    const text = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'packages/app': { version: '1.0.0' }, 'node_modules/app': { resolved: 'packages/app', link: true } } });
    const pkg = JSON.stringify({ workspaces: ['packages/*'] });
    expect((await run({}, { 'package-lock.json': text, 'package.json': pkg }, router({}, calls))).ok).toBe(true);
    expect((await run({}, { 'package-lock.json': text, 'package.json': JSON.stringify({ workspaces: { packages: ['packages/app'] } }) }, router({}, calls))).ok).toBe(true);
    expect(calls).toEqual([]);
  });

  it('R-P2: a path key or link that is not a declared workspace, or has a remote resolved or integrity, fails', async () => {
    const mk = (packages: Record<string, unknown>) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...packages } });
    const pkg = JSON.stringify({ workspaces: ['packages/*'] });
    const cases: Record<string, unknown>[] = [
      { 'packages/app': { version: '1.0.0' } }, // declared by pkg, so this one passes
      { 'evil/app': { version: '1.0.0' } },
      { 'node_modules/app': { resolved: 'evil/dir', link: true } },
      { 'node_modules/app': { resolved: '../outside', link: true } },
      { 'packages/app': { version: '1.0.0', resolved: 'https://evil.example/x.tgz', integrity: 'sha512-X' } },
      { 'packages/app': { version: '1.0.0', integrity: 'sha512-X' } },
      { 'node_modules/app': { resolved: 'https://evil.example/x.tgz', link: true } },
    ];
    expect((await run({}, { 'package-lock.json': mk(cases[0] as Record<string, unknown>), 'package.json': pkg }, router({}))).ok).toBe(true);
    for (const c of cases.slice(1)) {
      const r = await run({}, { 'package-lock.json': mk(c), 'package.json': pkg }, router({}));
      expect(r.ok, JSON.stringify(c)).toBe(false);
      expect(problems(r)).toContain('workspace');
    }
    // with no workspaces declared at all, even packages/app fails
    expect((await run({}, { 'package-lock.json': mk(cases[0] as Record<string, unknown>), 'package.json': '{}' }, router({}))).ok).toBe(false);
  });
});

const rtFile = (entries: string, pinnedOn = daysAgo(30)): string => `pinnedOn: "${pinnedOn}"\ntools:\n${entries}`;
const action = (version: string, sha: string, extra = ''): string => `  - id: a
    releasedAt: "${daysAgo(900)}"
    candidate: { id: a, kind: action, repo: o/r, version: "${version}", pin: { sha: "${sha}" } }
    step: { action: { uses: "o/r@${sha}", with: {} } }
${extra}`;
const gh = (path: string): string => `https://api.github.com/repos/${path}`;
const actionRoutes = (tag: string, sha: string, published: string, committed = daysAgo(900)): Routes => ({
  [gh(`o/r/git/ref/tags/${tag}`)]: { object: { type: 'commit', sha } },
  [gh(`o/r/releases/tags/${tag}`)]: { published_at: published, tag_name: tag, target_commitish: 'main' },
  [gh(`o/r/git/commits/${sha}`)]: { committer: { date: committed } },
});

describe('cooldown: reviewed tools', () => {
  it('fails a changed action whose release is young and passes an old one', async () => {
    const base = { 'data/reviewed-tools.yml': rtFile(action('v1', SHA)) };
    const head = { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) };
    expect((await run(base, head, router(actionRoutes('v2', SHA2, daysAgo(2))))).ok).toBe(false);
    expect((await run(base, head, router(actionRoutes('v2', SHA2, daysAgo(30))))).ok).toBe(true);
  });

  it('ignores an unchanged entry and a review-only edit, with no request', async () => {
    const calls: string[] = [];
    const base = { 'data/reviewed-tools.yml': rtFile(action('v1', SHA, '    reviewedBy: PENDING\n    proofs: 0\n')) };
    const head = { 'data/reviewed-tools.yml': rtFile(action('v1', SHA, '    reviewedBy: Cris\n    proofs: 3\n')) };
    expect((await run(base, head, router({}, calls))).ok).toBe(true);
    expect(calls).toEqual([]);
  });

  it('probe 2c: a swapped sha under the same old tag fails (sha is not the tag commit)', async () => {
    const base = { 'data/reviewed-tools.yml': rtFile(action('v1', SHA)) };
    const head = { 'data/reviewed-tools.yml': rtFile(action('v1', SHA2)) };
    const r = await run(base, head, router(actionRoutes('v1', SHA, daysAgo(400))));
    expect(problems(r)).toContain('not the commit of this tag');
  });

  it('follows an annotated tag to its commit', async () => {
    const routes: Routes = {
      [gh('o/r/git/ref/tags/v2')]: { object: { type: 'tag', sha: 'f'.repeat(40) } },
      [gh(`o/r/git/tags/${'f'.repeat(40)}`)]: { object: { type: 'commit', sha: SHA2 } },
      [gh('o/r/releases/tags/v2')]: { published_at: daysAgo(30), tag_name: 'v2' },
      [gh(`o/r/git/commits/${SHA2}`)]: { committer: { date: daysAgo(40) } },
    };
    const head = { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) };
    expect((await run({}, head, router(routes))).ok).toBe(false); // the annotated tag has no tagger date
    routes[gh(`o/r/git/tags/${'f'.repeat(40)}`)] = { object: { type: 'commit', sha: SHA2 }, tagger: { date: daysAgo(35) } };
    expect((await run({}, head, router(routes))).ok).toBe(true);
    routes[gh(`o/r/git/tags/${'f'.repeat(40)}`)] = { object: { type: 'commit', sha: SHA2 }, tagger: { date: daysAgo(1) } };
    expect(problems(await run({}, head, router(routes)))).toContain('days old');
  });

  it('R-P2: an action is dated by the youngest of release, commit and tag dates; a missing date or a mismatching release fails', async () => {
    const head = { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) };
    expect(problems(await run({}, head, router(actionRoutes('v2', SHA2, daysAgo(30), daysAgo(2)))))).toContain('days old'); // young commit, old release
    expect((await run({}, head, router(actionRoutes('v2', SHA2, daysAgo(30), daysAgo(20))))).ok).toBe(true);
    const noCommitDate = { ...actionRoutes('v2', SHA2, daysAgo(30)), [gh(`o/r/git/commits/${SHA2}`)]: { committer: {} } };
    expect(problems(await run({}, head, router(noCommitDate)))).toContain('missing');
    const wrongTag = actionRoutes('v2', SHA2, daysAgo(30));
    wrongTag[gh('o/r/releases/tags/v2')] = { published_at: daysAgo(30), tag_name: 'v3' };
    expect(problems(await run({}, head, router(wrongTag)))).toContain('not for this tag');
    const moved = actionRoutes('v2', SHA2, daysAgo(30));
    moved[gh('o/r/releases/tags/v2')] = { published_at: daysAgo(30), tag_name: 'v2', target_commitish: SHA };
    expect(problems(await run({}, head, router(moved)))).toContain('target commit');
  });

  it('no upstream date fails: a missing release is a 404, never a fallback to the recorded date', async () => {
    const routes: Routes = { [gh('o/r/git/ref/tags/v2')]: { object: { type: 'commit', sha: SHA2 } } };
    const r = await run({}, { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) }, router(routes));
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('404');
  });

  it('uses: must agree with the candidate repo and sha', async () => {
    const bad = action('v2', SHA2).replace(`o/r@${SHA2}`, `x/y@${SHA2}`);
    const r = await run({}, { 'data/reviewed-tools.yml': rtFile(bad) }, router(actionRoutes('v2', SHA2, daysAgo(30))));
    expect(problems(r)).toContain('uses:');
  });

  it('GitHub errors fail closed', async () => {
    const r = await run({}, { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) }, router({ [gh('o/r/git/ref/tags/v2')]: 503 }));
    expect(r.findings[0]?.lookupFailed).toBe(true);
  });

  const cli = (checksum: string, version = 'v1', pkg = 'tool.tar.gz', extra = ''): string => `  - id: t
    releasedAt: "${daysAgo(900)}"
    candidate: { id: t, kind: cli, repo: o/r, version: "${version}", pin: { checksum: "${checksum}" } }
    step: { cli: { install: { method: github-release, package: "${pkg}", version: "${version}" }, command: [] } }
${extra}`;
  const rel = (tag: string, published: string, digest: string | undefined, name = 'tool.tar.gz', created = daysAgo(900), updated = daysAgo(900)) => ({
    [gh(`o/r/releases/tags/${tag}`)]: {
      published_at: published,
      assets: [{ name, created_at: created, updated_at: updated, ...(digest ? { digest: `sha256:${digest}` } : {}), browser_download_url: `https://github.com/o/r/releases/download/${tag}/${name}` }],
    },
  });

  it('a release binary is tied to its release asset digest and the release date', async () => {
    const head = { 'data/reviewed-tools.yml': rtFile(cli(HEX)) };
    expect((await run({}, head, router(rel('v1', daysAgo(30), HEX)))).ok).toBe(true);
    expect((await run({}, head, router(rel('v1', daysAgo(2), HEX)))).ok).toBe(false);
    expect(problems(await run({}, head, router(rel('v1', daysAgo(30), HEX2))))).toContain('differs');
    expect(problems(await run({}, head, router(rel('v1', daysAgo(30), undefined))))).toContain('needs owner review');
    expect(problems(await run({}, head, router(rel('v1', daysAgo(30), HEX, 'other.tar.gz'))))).toContain('not in the GitHub release');
  });

  it('R-P2: a release binary is dated by the youngest of published_at and the asset created_at/updated_at; a missing one fails', async () => {
    const head = { 'data/reviewed-tools.yml': rtFile(cli(HEX)) };
    expect(problems(await run({}, head, router(rel('v1', daysAgo(30), HEX, 'tool.tar.gz', daysAgo(2)))))).toContain('days old');
    expect(problems(await run({}, head, router(rel('v1', daysAgo(30), HEX, 'tool.tar.gz', daysAgo(40), daysAgo(1)))))).toContain('days old');
    expect((await run({}, head, router(rel('v1', daysAgo(30), HEX, 'tool.tar.gz', daysAgo(40), daysAgo(20))))).ok).toBe(true);
    const r = rel('v1', daysAgo(30), HEX);
    delete ((r[gh('o/r/releases/tags/v1')].assets as Array<Record<string, unknown>>)[0] as Record<string, unknown>).updated_at;
    expect(problems(await run({}, head, router(r)))).toContain('missing');
  });

  const docker = (digest: string): string => `  - id: z
    releasedAt: "${daysAgo(900)}"
    candidate: { id: z, kind: docker, repo: zaproxy/zaproxy, version: "2026", pin: { digest: "${digest}" } }
    step: { cli: { install: { method: docker, package: "zaproxy/zap-stable", version: "2026" }, command: [] } }
`;
  const hub = 'https://hub.docker.com/v2/repositories/zaproxy/zap-stable/tags/2026';

  it('probe 2b: a docker digest is tied to the Docker Hub tag and its push date, never the recorded date', async () => {
    const head = { 'data/reviewed-tools.yml': rtFile(docker(DIGEST)) };
    expect((await run({}, head, router({ [hub]: { digest: DIGEST, tag_last_pushed: daysAgo(30) } }))).ok).toBe(true);
    expect((await run({}, head, router({ [hub]: { digest: DIGEST, tag_last_pushed: daysAgo(1) } }))).ok).toBe(false);
    expect(problems(await run({}, head, router({ [hub]: { digest: `sha256:${'1'.repeat(64)}`, tag_last_pushed: daysAgo(30) } })))).toContain('needs owner review');
    expect(problems(await run({}, head, router({})))).toContain('404');
    const other = rtFile(docker(DIGEST).replace('zaproxy/zap-stable', 'ghcr.io/x/y'));
    expect(problems(await run({}, { 'data/reviewed-tools.yml': other }, router({})))).toContain('needs owner review');
  });

  const plugin = (v: string, integrity: string): string => `  - id: n
    candidate: { id: n, kind: cli, repo: o/r, version: "1.0.0", pin: { checksum: "${integ('tool', '1.0.0')}" } }
    step: { cli: { install: { method: npm, package: tool, version: "1.0.0", checksum: "${integ('tool', '1.0.0')}" }, plugins: [{ method: npm, package: plug, version: "${v}", checksum: "${integrity}" }], command: [] } }
`;

  it('probe 2a: a plugin bump is seen and date-checked on its registry', async () => {
    const base = { 'data/reviewed-tools.yml': rtFile(plugin('1.0.0', integ('plug', '1.0.0'))) };
    const head = { 'data/reviewed-tools.yml': rtFile(plugin('9.9.9', integ('plug', '9.9.9'))) };
    const routes = { ...npmDoc('tool', { '1.0.0': daysAgo(90) }), ...npmDoc('plug', { '1.0.0': daysAgo(90), '9.9.9': daysAgo(1) }) };
    const r = await run(base, head, router(routes));
    expect(r.ok).toBe(false);
    expect(r.findings.some((f) => f.name.includes('plugin 1 plug'))).toBe(true);
    const wrong = { 'data/reviewed-tools.yml': rtFile(plugin('9.9.9', 'sha512-WRONG')) };
    expect(problems(await run(base, wrong, router({ ...routes, ...npmDoc('plug', { '9.9.9': daysAgo(90) }) })))).toContain('integrity');
  });

  it('an unknown kind fails closed', async () => {
    const odd = `  - id: q\n    candidate: { id: q, kind: weird, repo: o/r, version: "1" }\n`;
    expect(problems(await run({}, { 'data/reviewed-tools.yml': rtFile(odd) }, router({})))).toContain('needs owner review');
  });

  it('a malformed yaml file fails without echoing its content', async () => {
    await expect(run({}, { 'data/reviewed-tools.yml': 'a: [SECRET' }, router({}))).rejects.toThrow('data/reviewed-tools.yml is not valid YAML');
  });
});

describe('cooldown: pinned binaries', () => {
  const bin = (over: { version?: string; repo?: string; url?: string; sha?: string; by?: string } = {}): string => `g:
  version: "${over.version ?? '1'}"
  repo: ${over.repo ?? 'o/r'}
  releasedAt: "${daysAgo(900)}"
  pinnedOn: "${daysAgo(5)}"
  reviewedBy: ${over.by ?? 'PENDING'}
  platforms:
    linux-x64:
      url: ${over.url ?? 'https://github.com/o/r/releases/download/v1/g.tgz'}
      archiveSha256: ${over.sha ?? HEX}
`;
  const rel = (published: string, digest = HEX) => ({
    [gh('o/r/releases/tags/v1')]: { published_at: published, assets: [{ name: 'g.tgz', created_at: daysAgo(900), updated_at: daysAgo(900), digest: `sha256:${digest}`, browser_download_url: 'https://github.com/o/r/releases/download/v1/g.tgz' }] },
  });

  it('checks a changed pinned binary against its GitHub release; a review-only edit is ignored', async () => {
    const calls: string[] = [];
    expect((await run({ 'data/pinned-binaries.yml': bin() }, { 'data/pinned-binaries.yml': bin({ by: 'Cris' }) }, router({}, calls))).ok).toBe(true);
    expect(calls).toEqual([]);
    expect((await run({}, { 'data/pinned-binaries.yml': bin() }, router(rel(daysAgo(30))))).ok).toBe(true);
    expect((await run({}, { 'data/pinned-binaries.yml': bin() }, router(rel(daysAgo(3))))).ok).toBe(false);
    expect(problems(await run({}, { 'data/pinned-binaries.yml': bin() }, router(rel(daysAgo(30), HEX2))))).toContain('differs');
  });

  it('probe 3a: repo "../.." is refused and never put in a URL', async () => {
    const calls: string[] = [];
    const r = await run({}, { 'data/pinned-binaries.yml': bin({ repo: '../..', url: 'https://github.com/o/r/releases/download/v1/g.tgz' }) }, router({}, calls));
    expect(r.ok).toBe(false);
    expect(calls).toEqual([]);
    expect(repoPath('..')).toBeUndefined();
    expect(repoPath('a/..')).toBeUndefined();
    expect(repoPath('a/b/c')).toBeUndefined();
    expect(repoPath('a/b')).toBe('a/b');
  });

  it('probe 3b: repo must match the repo in the asset url', async () => {
    const head = { 'data/pinned-binaries.yml': bin({ repo: 'old/repo', url: 'https://github.com/young/repo/releases/download/v1/g.tgz' }) };
    const r = await run({}, head, router({ [gh('old/repo/releases/tags/v1')]: { published_at: daysAgo(900), assets: [] } }));
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('not a release asset of old/repo');
  });

  it('a url for another tag than the version fails; a 404 release fails', async () => {
    expect(problems(await run({}, { 'data/pinned-binaries.yml': bin({ url: 'https://github.com/o/r/releases/download/v0/g.tgz' }) }, router({})))).toContain('tag v0');
    expect(problems(await run({}, { 'data/pinned-binaries.yml': bin() }, router({})))).toContain('404');
  });

  it('with no platforms nothing can be tied, so it fails', () => {
    const items = binaryItems(null, 'g:\n  version: "1"\n  repo: o/r\n');
    expect(items).toHaveLength(1);
  });
});

describe('cooldown: general', () => {
  it('no change at all passes', async () => {
    expect((await run({}, {}, router({}))).ok).toBe(true);
  });

  it('a response over the byte cap fails closed', async () => {
    const big = (async () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(40 * 1024 * 1024)); c.close(); } }), { status: 200 })) as unknown as typeof fetch;
    const r = await run({}, { 'package-lock.json': lock({ a: '1.0.0' }) }, big);
    expect(problems(r)).toContain('too large');
  });
});

// --- the security-fix emergency path (DECISIONS #103, Plan R Task 4 / ruling R-E1) ---------------------------------

const PR = { repo: 'o/p', number: 7, headSha: SHA };
const OWNERS1 = '# owners\n/data/ @CrisWorking\n/gate/ @CrisWorking\n/scripts/ @CrisWorking\n';
const OWNERS2 = '/data/ @CrisWorking @Second\n/scripts/ @CrisWorking @Second\n';
const REASON = 'Security-fix-reason: CVE-2026-0001 in rollup, fixed upstream yesterday';
const young = { 'package-lock.json': lock({ rollup: '4.64.12' }) };
const youngDocs = npmDoc('rollup', { '4.64.12': daysAgo(1) });
const labeled = (login: string, event = 'labeled', name = 'security-fix') => ({ event, actor: { login }, label: { name } });
const review = (login: string, state: string, commit = SHA) => ({ user: { login }, state, commit_id: commit });
const prRoutes = (o: { body?: string | null; labels?: string[]; author?: string; head?: string; events?: unknown; reviews?: unknown } = {}): Routes => ({
  [gh('o/p/pulls/7')]: {
    number: 7, head: { sha: o.head ?? SHA }, user: { login: o.author ?? 'contributor' },
    body: o.body === undefined ? `Fixes the CVE.\n\n${REASON}\n` : o.body, labels: (o.labels ?? ['security-fix']).map((name) => ({ name })),
  },
  [gh('o/p/issues/7/events?per_page=100&page=1')]: o.events ?? [labeled('someone', 'labeled', 'bug'), labeled('CrisWorking')],
  [gh('o/p/pulls/7/reviews?per_page=100&page=1')]: o.reviews ?? [],
});
const emergency = (owners: string | null, routes: Routes, head: Files = young, calls: string[] = []) =>
  run(owners === null ? {} : { '.github/CODEOWNERS': owners }, head, router({ ...youngDocs, ...routes }, calls), { pr: PR });

describe('cooldown: security-fix emergency path', () => {
  it('cooldown: security-fix label with 2 approvals → pass', async () => {
    const reviews = [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED')];
    const r = await emergency(OWNERS2, prRoutes({ reviews }));
    expect(r.ok).toBe(true);
    expect(r.findings).toEqual([]);
    expect(r.waived.map((f) => f.name)).toEqual(['rollup']);
    const out = formatReport(r);
    expect(out).toContain('security-fix');
    expect(out).toContain('rollup 4.64.12');
    expect(out).toContain('CrisWorking, Second');
  });

  it('cooldown: security-fix label, one maintainer, reason given → pass and reason in summary', async () => {
    const r = await emergency(OWNERS1, prRoutes());
    expect(r.ok).toBe(true);
    const out = formatReport(r);
    expect(out).toContain('CVE-2026-0001 in rollup, fixed upstream yesterday');
    expect(out).toContain('rollup 4.64.12'); // the young item stays visible
    expect(out).toContain('CrisWorking');
  });

  it('cooldown: security-fix label without reason or approvals → fail', async () => {
    for (const body of [null, 'no reason line here', 'Security-fix-reason:   ', `Security-fix-reason:\n${REASON}`]) {
      const r = await emergency(OWNERS1, prRoutes({ body }));
      expect(r.ok, String(body)).toBe(false);
      expect(problems(r)).toContain('Security-fix-reason');
    }
    // two owners: a reason alone is not enough, and approvals do not replace the reason
    const noApprovals = await emergency(OWNERS2, prRoutes());
    expect(noApprovals.ok).toBe(false);
    expect(problems(noApprovals)).toContain('2 code owners');
    const approvedNoReason = await emergency(OWNERS2, prRoutes({ body: '', reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED')] }));
    expect(approvedNoReason.ok).toBe(false);
    // and the young item is still listed
    expect(noApprovals.findings.map((f) => f.name)).toContain('rollup');
  });

  it('a label applied by a non-owner fails, and the latest labeled event counts', async () => {
    const r = await emergency(OWNERS1, prRoutes({ events: [labeled('contributor')] }));
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('not a code owner');
    const relabeled = [labeled('CrisWorking'), labeled('contributor', 'unlabeled'), labeled('contributor')];
    expect(problems(await emergency(OWNERS1, prRoutes({ events: relabeled })))).toContain('not a code owner');
    const bot = [labeled('github-actions[bot]')];
    expect((await emergency(OWNERS1, prRoutes({ events: bot }))).ok).toBe(false);
  });

  it('the label must really be on the PR (API labels and events agree)', async () => {
    // not in the PR's labels: no emergency, the young item fails as usual, no event lookup
    const calls: string[] = [];
    const r = await emergency(OWNERS1, prRoutes({ labels: ['bug'] }), young, calls);
    expect(r.ok).toBe(false);
    expect(calls.some((c) => c.includes('/events'))).toBe(false);
    // on the PR but the latest event removed it, or no event at all
    expect((await emergency(OWNERS1, prRoutes({ events: [labeled('CrisWorking'), labeled('CrisWorking', 'unlabeled')] }))).ok).toBe(false);
    expect((await emergency(OWNERS1, prRoutes({ events: [] }))).ok).toBe(false);
  });

  it('owners come from the BASE CODEOWNERS, never the PR copy', async () => {
    const hostile = '/data/ @contributor\n/scripts/ @contributor\n';
    const head = { ...young, '.github/CODEOWNERS': hostile };
    const r = await run({ '.github/CODEOWNERS': OWNERS1 }, head, router({ ...youngDocs, ...prRoutes({ events: [labeled('contributor')] }) }), { pr: PR });
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('not a code owner');
    // no base CODEOWNERS at all: fails even if the PR adds one
    expect((await run({}, head, router({ ...youngDocs, ...prRoutes({ events: [labeled('contributor')] }) }), { pr: PR })).ok).toBe(false);
  });

  it('an unusable base CODEOWNERS fails closed', async () => {
    for (const owners of [null, '/data/ @CrisWorking\n', '/data/ @CrisWorking\n/scripts/ @Other\n', '/data/ @org/team\n/scripts/ @org/team\n', '/data/ a@b.com\n/scripts/ a@b.com\n', '/data/\n/scripts/\n']) {
      const r = await emergency(owners, prRoutes());
      expect(r.ok, String(owners)).toBe(false);
      expect(problems(r)).toContain('CODEOWNERS');
    }
    // the last line for a pattern wins (as on GitHub), and logins compare without case
    expect((await emergency('/data/ @Old\n/scripts/ @crisworking\n/data/ @CRISWORKING\n', prRoutes())).ok).toBe(true);
  });

  it('two owners: one approval, self-approval, an old head SHA, a later change request or comment, a non-owner all fail', async () => {
    const ok = [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED')];
    expect((await emergency(OWNERS2, prRoutes({ reviews: ok }))).ok).toBe(true);
    const cases: Record<string, { reviews: unknown[]; author?: string }> = {
      one: { reviews: [review('CrisWorking', 'APPROVED')] },
      self: { reviews: ok, author: 'Second' },
      oldSha: { reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED', SHA2)] },
      changes: { reviews: [...ok, review('Second', 'CHANGES_REQUESTED')] },
      dismissed: { reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'DISMISSED')] },
      comment: { reviews: [...ok, review('Second', 'COMMENTED')] },
      nonOwner: { reviews: [review('CrisWorking', 'APPROVED'), review('contributor', 'APPROVED')] },
      sameTwice: { reviews: [review('CrisWorking', 'APPROVED'), review('crisworking', 'APPROVED')] },
    };
    for (const [name, c] of Object.entries(cases)) {
      const r = await emergency(OWNERS2, prRoutes({ reviews: c.reviews, ...(c.author ? { author: c.author } : {}) }));
      expect(r.ok, name).toBe(false);
      expect(problems(r), name).toContain('2 code owners');
    }
    // a later approval after a change request counts again
    expect((await emergency(OWNERS2, prRoutes({ reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'CHANGES_REQUESTED'), review('Second', 'APPROVED')] }))).ok).toBe(true);
  });

  it('an API error reading the PR, events or reviews fails closed (not "no label")', async () => {
    for (const path of ['o/p/pulls/7', 'o/p/issues/7/events?per_page=100&page=1', 'o/p/pulls/7/reviews?per_page=100&page=1']) {
      const r = await emergency(OWNERS2, { ...prRoutes({ reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED')] }), [gh(path)]: 502 });
      expect(r.ok, path).toBe(false);
      expect(r.findings.some((f) => f.kind === 'security-fix' && f.lookupFailed), path).toBe(true);
    }
    // an unreadable answer (not a list, no labels) fails too
    expect((await emergency(OWNERS1, { ...prRoutes(), [gh('o/p/issues/7/events?per_page=100&page=1')]: { message: 'odd' } })).ok).toBe(false);
    expect((await emergency(OWNERS1, { ...prRoutes(), [gh('o/p/pulls/7')]: { head: { sha: SHA }, body: REASON } })).ok).toBe(false);
  });

  it('a PR head that moved since the run started fails', async () => {
    const r = await emergency(OWNERS1, prRoutes({ head: SHA2 }));
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('head');
  });

  it('reads every page of events', async () => {
    const filler = Array.from({ length: 100 }, () => labeled('someone', 'labeled', 'bug'));
    const routes = { ...prRoutes(), [gh('o/p/issues/7/events?per_page=100&page=1')]: filler, [gh('o/p/issues/7/events?per_page=100&page=2')]: [labeled('CrisWorking')] };
    expect((await emergency(OWNERS1, routes)).ok).toBe(true);
    const unlabeledLater = { ...routes, [gh('o/p/issues/7/events?per_page=100&page=2')]: [labeled('CrisWorking'), labeled('x', 'unlabeled')] };
    expect((await emergency(OWNERS1, unlabeledLater)).ok).toBe(false);
  });

  it('a hostile reason is printed as one inert line', async () => {
    const evil = 'Security-fix-reason: \u001b[31mred\u001b[0m \u202eevil\u2066 \u200b@everyone see https://evil.example/x and [click](http://y.example) www.z.example ::error::boom' + ' long'.repeat(2000);
    const r = await emergency(OWNERS1, prRoutes({ body: `${evil}\r\n::warning::second line` }));
    expect(r.ok).toBe(true);
    const out = formatReport(r);
    const line = out.split('\n').find((l) => l.startsWith('Security-fix-reason:')) ?? '';
    expect(line).toContain('red');
    expect(out).not.toMatch(/[\u001b\u202e\u2066\u200b]/);
    expect(line).not.toContain('@');
    expect(line).not.toContain('://');
    expect(line).not.toContain('](');
    expect(line).not.toContain('www.');
    expect(out).not.toContain('second line');
    expect(out.split('\n').some((l) => l.trimStart().startsWith('::'))).toBe(false);
    expect(line).not.toContain('::');
    expect([...line.slice('Security-fix-reason: '.length)].length).toBeLessThanOrEqual(301);
  });

  it('the label only lifts the age rule: a bad integrity, a future date or a wrong sha still fails', async () => {
    const head = { 'package-lock.json': lock({ rollup: '4.64.12', lodash: { v: '4.17.21', integrity: 'sha512-WRONG' } }) };
    const calls: string[] = [];
    const r = await run({ '.github/CODEOWNERS': OWNERS1 }, head, router({ ...youngDocs, ...npmDoc('lodash', { '4.17.21': daysAgo(1) }), ...prRoutes() }, calls), { pr: PR });
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain('integrity');
    expect(formatReport(r)).toContain('only lifts the age rule');
    const future = await emergency(OWNERS1, { ...prRoutes(), ...npmDoc('rollup', { '4.64.12': daysAgo(-2) }) });
    expect(future.ok).toBe(false);
    expect(problems(future)).toContain('future');
    const sha = await run({ '.github/CODEOWNERS': OWNERS1 }, { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) }, router({ ...actionRoutes('v2', SHA, daysAgo(1)), ...prRoutes() }), { pr: PR });
    expect(problems(sha)).toContain('not the commit of this tag');
  });

  it('nothing young: no GitHub PR lookups; no PR context: young still fails', async () => {
    const calls: string[] = [];
    const old = { 'package-lock.json': lock({ ms: '2.1.3' }) };
    expect((await run({ '.github/CODEOWNERS': OWNERS1 }, old, router({ ...npmDoc('ms', { '2.1.3': daysAgo(400) }), ...prRoutes() }, calls), { pr: PR })).ok).toBe(true);
    expect(calls.some((c) => c.includes('/repos/o/p/'))).toBe(false);
    expect((await run({ '.github/CODEOWNERS': OWNERS1 }, young, router({ ...youngDocs, ...prRoutes() }))).ok).toBe(false);
  });

  it('reads the PR context from env and refuses a malformed one', () => {
    expect(prFromEnv({})).toBeUndefined();
    expect(prFromEnv({ PR_REPO: 'o/p', PR_NUMBER: '7', PR_HEAD_SHA: SHA })).toEqual(PR);
    for (const env of [{ PR_REPO: 'o/p' }, { PR_REPO: '../x', PR_NUMBER: '7', PR_HEAD_SHA: SHA }, { PR_REPO: 'o/p', PR_NUMBER: '7a', PR_HEAD_SHA: SHA }, { PR_REPO: 'o/p', PR_NUMBER: '7', PR_HEAD_SHA: 'main' }]) {
      expect(() => prFromEnv(env), JSON.stringify(env)).toThrow(/PR_/);
    }
  });

  it('plain text output strips escapes from file-supplied names too', async () => {
    const head = { 'package-lock.json': lock({ 'x\u001b[2J\n::error::y': '1.0.0' }) };
    const out = formatReport(await run({}, head, router({})));
    expect(out).not.toContain('\u001b');
    expect(out.split('\n').some((l) => l.trimStart().startsWith('::'))).toBe(false);
  });
});
