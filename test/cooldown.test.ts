import { createHash } from 'node:crypto';
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

/**
 * Routes: URL -> JSON body, a status number, or a function making the Response (it gets the request init, so it can
 * see a HEAD). Anything unlisted is a 404. Every URL asked is recorded (a HEAD as `HEAD <url>`).
 */
type Routes = Record<string, unknown>;
function router(routes: Routes, calls: string[] = []): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    calls.push(init?.method === 'HEAD' ? `HEAD ${String(url)}` : String(url));
    const r = routes[String(url)];
    if (r === undefined) return new Response('{}', { status: 404 });
    if (typeof r === 'number') return new Response('x', { status: r });
    if (typeof r === 'function') return (r as (i?: RequestInit) => Response)(init);
    return new Response(JSON.stringify(r), { status: 200 });
  }) as typeof fetch;
}

/** A body over the 32 MB cap, as a stream with no content-length (like the registry's gzip answer). */
const tooBig = (): Response => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(33 * 1024 * 1024)); c.close(); } }), { status: 200 });
const httpDate = (iso: string): string => new Date(iso).toUTCString();

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

  describe('a packument over the byte cap (vite): the version document and the tarball date, never a bigger cap', () => {
    const name = 'vite';
    const v = '8.3.4';
    const tarball = tgz(name, v);
    const routes = (o: { integrity?: string; lastModified?: string | null; doc?: unknown; tarballUrl?: string } = {}): Routes => ({
      [`https://registry.npmjs.org/${name}`]: tooBig,
      [`https://registry.npmjs.org/${name}/${v}`]: o.doc ?? { name, version: v, dist: { integrity: o.integrity ?? integ(name, v), tarball: o.tarballUrl ?? tarball } },
      [tarball]: (init?: RequestInit) => {
        if (init?.method !== 'HEAD') return new Response('tarball bytes', { status: 200 });
        const lm = o.lastModified === undefined ? httpDate(daysAgo(21)) : o.lastModified;
        return new Response(null, { status: 200, headers: lm === null ? {} : { 'last-modified': lm } });
      },
    });
    const head = { 'package-lock.json': lock({ vite: v }) };

    it('an old version passes: integrity from /<name>/<version>, date from a HEAD of the registry tarball', async () => {
      const calls: string[] = [];
      const r = await run({}, head, router(routes(), calls));
      expect(problems(r)).toBe('');
      expect(r.ok).toBe(true);
      expect(calls).toEqual(['https://registry.npmjs.org/vite', 'https://registry.npmjs.org/vite/8.3.4', `HEAD ${tarball}`]);
    });

    it('a young tarball, a wrong integrity, a missing or odd Last-Modified, another tarball url or a doc for another version fail', async () => {
      const young = await run({}, head, router(routes({ lastModified: httpDate(daysAgo(2)) })));
      expect(young.findings[0]?.young).toBe(true);
      expect(problems(await run({}, head, router(routes({ integrity: 'sha512-WRONG' }))))).toContain('integrity');
      expect(problems(await run({}, head, router(routes({ lastModified: null }))))).toContain('Last-Modified');
      expect(problems(await run({}, head, router(routes({ lastModified: 'yesterday' }))))).toContain('Last-Modified');
      expect(problems(await run({}, head, router(routes({ tarballUrl: 'https://evil.example/vite.tgz' }))))).toContain('tarball');
      expect(problems(await run({}, head, router(routes({ doc: { name, version: '8.3.5', dist: { integrity: integ(name, v), tarball } } }))))).toContain('not for this package version');
      const future = await run({}, head, router(routes({ lastModified: httpDate(daysAgo(-2)) })));
      expect(problems(future)).toContain('future');
    });

    it('a 404 version document or a failed HEAD fails closed', async () => {
      const r1 = routes();
      delete r1[`https://registry.npmjs.org/${name}/${v}`];
      expect(problems(await run({}, head, router(r1)))).toContain('404');
      const r2 = { ...routes(), [tarball]: 503 };
      const r = await run({}, head, router(r2));
      expect(r.ok).toBe(false);
      expect(r.findings[0]?.lookupFailed).toBe(true);
    });

    it('P43: the date is the LATER of the tarball Last-Modified and the version document publish stamp', async () => {
      const stamped = (at: string, lm: string) => routes({
        lastModified: httpDate(lm),
        doc: { name, version: v, dist: { integrity: integ(name, v), tarball }, _npmOperationalInternal: { tmp: `tmp/${name}_${v}_${Date.parse(at)}_0.6120386617728939`, host: 's3://npm-registry-packages' } },
      });
      // a young publish stamp with an old Last-Modified: young
      const young = await run({}, head, router(stamped(daysAgo(2), daysAgo(30))));
      expect(young.findings[0]?.young).toBe(true);
      expect(Date.parse(young.findings[0]?.date ?? '')).toBe(Date.parse(daysAgo(2)));
      // an old stamp with a young Last-Modified (a re-stored tarball): still young, never the older stamp
      expect((await run({}, head, router(stamped(daysAgo(30), daysAgo(2))))).findings[0]?.young).toBe(true);
      expect((await run({}, head, router(stamped(daysAgo(30), daysAgo(20))))).ok).toBe(true);
      // an unreadable stamp is ignored (Last-Modified still decides; it can only be stricter)
      const odd = routes({ doc: { name, version: v, dist: { integrity: integ(name, v), tarball }, _npmOperationalInternal: { tmp: 'tmp/garbage' } } });
      expect((await run({}, head, router(odd))).ok).toBe(true);
    });

    it('a reviewed npm tool whose packument is too big is checked the same way', async () => {
      const entry = `  - id: v
    candidate: { id: v, kind: cli, repo: vitejs/vite, version: "${v}", pin: { checksum: "${integ(name, v)}" } }
    step: { cli: { install: { method: npm, package: ${name}, version: "${v}" }, command: [] } }
`;
      expect((await run({}, { 'data/reviewed-tools.yml': rtFile(entry) }, router(routes()))).ok).toBe(true);
      expect((await run({}, { 'data/reviewed-tools.yml': rtFile(entry) }, router(routes({ integrity: 'sha512-WRONG' })))).ok).toBe(false);
    });
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

  // The data's shape since Plan P: the main package's hash is candidate.pin.checksum (step.cli.install has none), and
  // each plugin carries its own checksum. candidate.id is pipegen's id, never the package name.
  const npmTool = (o: { install?: string; plugins?: string; pinned?: string; version?: string } = {}): string => `  - id: lint-ts
    candidate: { id: lint-ts, kind: cli, repo: o/r, version: "${o.version ?? '1.0.0'}", pin: { checksum: "${o.pinned ?? integ('tool', '1.0.0')}" } }
    step: { cli: { install: ${o.install ?? '{ method: npm, package: tool, version: "1.0.0" }'}, plugins: ${o.plugins ?? `[{ method: npm, package: "@s/plug", version: "2.0.0", checksum: "${integ('@s/plug', '2.0.0')}" }]`}, command: [] } }
`;
  const npmRoutes = (toolAt = daysAgo(90), plugAt = daysAgo(90)) => ({ ...npmDoc('tool', { '1.0.0': toolAt }), ...npmDoc('@s/plug', { '2.0.0': plugAt }) });

  it('an npm tool: the main package is tied to candidate.pin.checksum, each plugin to its own checksum', async () => {
    const calls: string[] = [];
    const head = { 'data/reviewed-tools.yml': rtFile(npmTool()) };
    const r = await run({}, head, router(npmRoutes(), calls));
    expect(problems(r)).toBe('');
    expect(r.checked).toBe(2);
    expect(calls.sort()).toEqual(['https://registry.npmjs.org/@s%2fplug', 'https://registry.npmjs.org/tool']);
    // never looked up by candidate.id
    expect(calls.some((c) => c.includes('lint-ts'))).toBe(false);
    const young = await run({}, head, router(npmRoutes(daysAgo(90), daysAgo(1))));
    expect(young.findings.map((f) => f.name)).toEqual(['lint-ts (plugin 1 @s/plug)']);
    const wrongMain = { 'data/reviewed-tools.yml': rtFile(npmTool({ pinned: 'sha512-WRONG' })) };
    expect((await run({}, wrongMain, router(npmRoutes()))).findings.map((f) => `${f.name}: ${f.problem}`)).toEqual(['lint-ts (tool tool): integrity does not match the registry dist.integrity']);
  });

  it('an install checksum or version that differs from the candidate pin fails, never picks one', async () => {
    const own = { 'data/reviewed-tools.yml': rtFile(npmTool({ install: `{ method: npm, package: tool, version: "1.0.0", checksum: "${integ('other', '1')}" }` })) };
    expect(problems(await run({}, own, router(npmRoutes())))).toContain('candidate.pin.checksum');
    const same = { 'data/reviewed-tools.yml': rtFile(npmTool({ install: `{ method: npm, package: tool, version: "1.0.0", checksum: "${integ('tool', '1.0.0')}" }` })) };
    expect((await run({}, same, router(npmRoutes()))).ok).toBe(true);
    const ver = { 'data/reviewed-tools.yml': rtFile(npmTool({ version: '9.9.9' })) };
    expect(problems(await run({}, ver, router(npmRoutes())))).toContain('candidate version');
  });

  it('a plugin with a method this check can not tie, or a plugins value that is not a list, fails closed', async () => {
    const gh1 = { 'data/reviewed-tools.yml': rtFile(npmTool({ plugins: `[{ method: github-release, package: x.tgz, version: "1", checksum: "${HEX}" }]` })) };
    const r = await run({}, gh1, router(npmRoutes()));
    expect(r.findings.map((f) => `${f.name}: ${f.problem}`)).toEqual(['lint-ts (plugin 1 x.tgz): install method "github-release" is not one this check can tie to an upstream date; needs owner review']);
    const notList = { 'data/reviewed-tools.yml': rtFile(npmTool({ plugins: '{ method: npm }' })) };
    expect(problems(await run({}, notList, router(npmRoutes())))).toContain('plugins');
  });

  const pipTool = (pinned: string, plugin = HEX2): string => `  - id: lint-py
    candidate: { id: lint-py, kind: cli, repo: o/r, version: "1.9.4", pin: { checksum: "${pinned}" } }
    step: { cli: { install: { method: pip, package: bandit, version: "1.9.4" }, plugins: [{ method: pip, package: sarif-om, version: "1.0.4", checksum: "${plugin}" }], command: [] } }
`;
  const pypi = (name: string, v: string, sha: string, at: string) => ({
    [`https://pypi.org/pypi/${name}/${v}/json`]: { urls: [{ filename: `${name}-${v}.tar.gz`, digests: { sha256: '0'.repeat(64) }, upload_time_iso_8601: daysAgo(900) }, { filename: `${name}-${v}-py3-none-any.whl`, digests: { sha256: sha }, upload_time_iso_8601: at }] },
  });

  it('a pip tool: the main package is tied to the wheel sha256 in candidate.pin.checksum, the plugin to its own', async () => {
    const routes = { ...pypi('bandit', '1.9.4', HEX, daysAgo(60)), ...pypi('sarif-om', '1.0.4', HEX2, daysAgo(600)) };
    const head = { 'data/reviewed-tools.yml': rtFile(pipTool(HEX)) };
    const r = await run({}, head, router(routes));
    expect(problems(r)).toBe('');
    expect(r.checked).toBe(2);
    expect(problems(await run({}, { 'data/reviewed-tools.yml': rtFile(pipTool('1'.repeat(64))) }, router(routes)))).toContain('pinned sha256');
    expect(problems(await run({}, { 'data/reviewed-tools.yml': rtFile(pipTool(HEX, '1'.repeat(64))) }, router(routes)))).toContain('pinned sha256');
    const young = await run({}, head, router({ ...routes, ...pypi('bandit', '1.9.4', HEX, daysAgo(3)) }));
    expect(young.findings.map((f) => f.name)).toEqual(['lint-py (tool bandit)']);
  });

  // built at runtime so no committed test line looks like a credential assignment (test/no-secret-literals.test.ts)
  const HAND_RUN_HINT = ['GITHUB_TOK', 'EN=$(gh auth token)'].join('');
  const GH_OPTS = Object.fromEntries([[['github', 'Tok', 'en'].join(''), 'x'.repeat(8)]]);
  it('a GitHub 403 or 429 says to set GITHUB_TOKEN (gh auth token by hand) and still fails closed', async () => {
    const limited = (status: number) => () => new Response('{}', { status, headers: { 'x-ratelimit-remaining': '0' } });
    const head = { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2)) };
    for (const status of [403, 429]) {
      const r = await run({}, head, router({ [gh('o/r/git/ref/tags/v2')]: limited(status) }));
      expect(r.ok).toBe(false);
      expect(r.findings[0]?.lookupFailed).toBe(true);
      expect(problems(r)).toContain('rate limit');
      expect(problems(r)).toContain(HAND_RUN_HINT);
    }
    const given = await run({}, head, router({ [gh('o/r/git/ref/tags/v2')]: 403 }), GH_OPTS);
    expect(problems(given)).toContain('GITHUB_TOKEN');
    expect(problems(given)).not.toContain('gh auth token');
    // a 403 from the npm registry is just an HTTP error
    const npm403 = await run({}, { 'package-lock.json': lock({ a: '1.0.0' }) }, router({ 'https://registry.npmjs.org/a': 403 }));
    expect(problems(npm403)).toBe('lookup failed: HTTP 403');
  });

  // P41: archives a tool downloads at run time, pinned in step.cli.env (and fixedInputs.env), are pins too.
  const sha256 = (t: string): string => createHash('sha256').update(t).digest('hex');
  const NT = 'projectdiscovery/nuclei-templates';
  const ntArchive = `https://github.com/${NT}/archive/refs/tags/v10.5.0.tar.gz`;
  const ntSumsUrl = `https://github.com/${NT}/releases/download/v10.5.0/nuclei-templates-10.5.0_checksums.txt`;
  const nuclei = (o: { url?: string; sha?: string; fixedUrl?: string } = {}): string => `  - id: nu
    candidate: { id: nu, kind: cli, repo: o/r, version: "v1", pin: { checksum: "${HEX}" } }
    step: { cli: { install: { method: github-release, package: "tool.tar.gz", version: "v1" }, command: [], env: { PIPEGEN_NUCLEI_TEMPLATES_URL: "${o.url ?? ntArchive}", PIPEGEN_NUCLEI_TEMPLATES_SHA256: "${o.sha ?? HEX2}" } } }
    fixedInputs: { env: { PIPEGEN_NUCLEI_TEMPLATES_URL: "${o.fixedUrl ?? o.url ?? ntArchive}", PIPEGEN_NUCLEI_TEMPLATES_SHA256: "${o.sha ?? HEX2}" } }
`;
  const ntRoutes = (o: { published?: string; listed?: string; text?: string; badDigest?: boolean; assetAt?: string; noAsset?: boolean; tarball?: string } = {}): Routes => {
    const text = o.text ?? `${'9'.repeat(64)}  nuclei-templates-10.5.0.zip\n${o.listed ?? HEX2}  nuclei-templates-10.5.0.tar.gz\n`;
    const at = o.assetAt ?? daysAgo(30);
    const assets: unknown[] = o.noAsset ? [] : [{ name: 'nuclei-templates-10.5.0_checksums.txt', browser_download_url: ntSumsUrl, digest: `sha256:${o.badDigest ? HEX : sha256(text)}`, created_at: at, updated_at: at }];
    if (o.tarball) assets.push({ name: 'nuclei-templates-10.5.0.tar.gz', browser_download_url: `https://github.com/${NT}/releases/download/v10.5.0/nuclei-templates-10.5.0.tar.gz`, digest: `sha256:${o.tarball}`, created_at: at, updated_at: at });
    return {
      ...rel('v1', daysAgo(400), HEX),
      [gh(`${NT}/releases/tags/v10.5.0`)]: { tag_name: 'v10.5.0', published_at: o.published ?? daysAgo(30), assets },
      [ntSumsUrl]: () => new Response(text, { status: 200 }),
    };
  };

  it('P41: nuclei templates (tag archive) are tied to the release checksums file and dated by the release', async () => {
    const head = { 'data/reviewed-tools.yml': rtFile(nuclei()) };
    const calls: string[] = [];
    const ok = await run({}, head, router(ntRoutes(), calls));
    expect(problems(ok)).toBe('');
    expect(ok.checked).toBe(2);
    expect(calls).toContain(ntSumsUrl);
    const young = await run({}, head, router(ntRoutes({ published: daysAgo(1) })));
    expect(young.findings.map((f) => `${f.name}: ${f.young}`)).toEqual(['nu (nuclei templates): true']);
    expect((await run({}, head, router(ntRoutes({ assetAt: daysAgo(2) })))).findings[0]?.young).toBe(true);
    expect(problems(await run({}, head, router(ntRoutes({ listed: HEX }))))).toContain('does not list the pinned sha256');
    expect(problems(await run({}, head, router(ntRoutes({ badDigest: true }))))).toContain('digest');
    expect(problems(await run({}, head, router(ntRoutes({ noAsset: true }))))).toContain('needs owner review');
    expect(problems(await run({}, head, router({ ...rel('v1', daysAgo(400), HEX) })))).toContain('404');
  });

  it('P41: nuclei templates as a release asset are tied to its digest; odd URLs or env copies that disagree fail', async () => {
    const asset = `https://github.com/${NT}/releases/download/v10.5.0/nuclei-templates-10.5.0.tar.gz`;
    const head = { 'data/reviewed-tools.yml': rtFile(nuclei({ url: asset })) };
    expect(problems(await run({}, head, router(ntRoutes({ tarball: HEX2 }))))).toBe('');
    expect(problems(await run({}, head, router(ntRoutes({ tarball: HEX }))))).toContain('differs');
    const odd = { 'data/reviewed-tools.yml': rtFile(nuclei({ url: 'https://evil.example/t.tar.gz' })) };
    expect(problems(await run({}, odd, router(ntRoutes())))).toContain('nuclei-templates');
    const split = { 'data/reviewed-tools.yml': rtFile(nuclei({ fixedUrl: asset })) };
    expect(problems(await run({}, split, router(ntRoutes({ tarball: HEX2 }))))).toContain('fixedInputs.env');
  });

  const RULES_COMMIT = 'f'.repeat(40);
  const semgrep = (o: { url?: string; tree?: string } = {}): string => `  - id: sg
    candidate: { id: sg, kind: docker, repo: semgrep/semgrep, version: "2026", pin: { digest: "${DIGEST}" } }
    step: { cli: { install: { method: docker, package: "semgrep/semgrep", version: "2026" }, command: [], env: { PIPEGEN_RULES_URL: "${o.url ?? `https://github.com/semgrep/semgrep-rules/archive/${RULES_COMMIT}.tar.gz`}", PIPEGEN_RULES_SHA256: "${HEX}", PIPEGEN_RULES_TREE: "${o.tree ?? SHA2}" } } }
`;
  const sgRoutes = (verification: unknown, committed = daysAgo(400)): Routes => ({
    'https://hub.docker.com/v2/repositories/semgrep/semgrep/tags/2026': { digest: DIGEST, tag_last_pushed: daysAgo(400) },
    [gh(`semgrep/semgrep-rules/git/commits/${RULES_COMMIT}`)]: { sha: RULES_COMMIT, tree: { sha: SHA2 }, committer: { date: committed }, verification },
  });
  const verified = (at: string) => ({ verified: true, reason: 'valid', verified_at: at });

  it('P41: semgrep rules: the commit tree must be PIPEGEN_RULES_TREE, dated by GitHub verified_at, never the committer date', async () => {
    const head = { 'data/reviewed-tools.yml': rtFile(semgrep()) };
    const ok = await run({}, head, router(sgRoutes(verified(daysAgo(30)))));
    expect(problems(ok)).toBe('');
    expect(ok.checked).toBe(2);
    // a backdated committer date does not help: verified_at decides
    const young = await run({}, head, router(sgRoutes(verified(daysAgo(1)), daysAgo(900))));
    expect(young.findings.map((f) => `${f.name}: ${f.young}`)).toEqual(['sg (semgrep rules): true']);
    expect((await run({}, head, router(sgRoutes(verified(daysAgo(30)), daysAgo(1))))).ok).toBe(true);
    expect(problems(await run({}, { 'data/reviewed-tools.yml': rtFile(semgrep({ tree: SHA })) }, router(sgRoutes(verified(daysAgo(30))))))).toContain('PIPEGEN_RULES_TREE');
    for (const v of [{ verified: false, reason: 'unsigned', verified_at: null }, { verified: true, reason: 'valid' }, undefined]) {
      expect(problems(await run({}, head, router(sgRoutes(v)))), JSON.stringify(v)).toContain('needs owner review');
    }
    const odd = { 'data/reviewed-tools.yml': rtFile(semgrep({ url: 'https://evil.example/rules.tar.gz' })) };
    expect(problems(await run({}, odd, router(sgRoutes(verified(daysAgo(30))))))).toContain('PIPEGEN_RULES_URL');
  });

  it('P41: a hash- or URL-shaped value at a field this check does not know fails; verifiedWith is known', async () => {
    const base = cli(HEX);
    const routes = rel('v1', daysAgo(30), HEX);
    expect((await run({}, { 'data/reviewed-tools.yml': rtFile(base) }, router(routes))).ok).toBe(true);
    const withEnv = base.replace('command: [] }', `command: [], env: { EXTRA_SHA256: "${HEX2}" } }`);
    const r1 = await run({}, { 'data/reviewed-tools.yml': rtFile(withEnv) }, router(routes));
    expect(problems(r1)).toContain('step.cli.env.EXTRA_SHA256');
    expect(problems(r1)).toContain('needs owner review');
    for (const extra of [
      '    fixedInputs: { config: { content: "rules: https://evil.example/r.yml" } }\n',
      `    fixedInputs: { args: ["--sha", "${SHA}"] }\n`,
      `    extra: { sri: "sha512-${'A'.repeat(20)}" }\n`,
      `    wrappedImage: { ref: "x", digest: "${DIGEST}", mirror: "https://m.example" }\n`,
    ]) {
      expect((await run({}, { 'data/reviewed-tools.yml': rtFile(cli(HEX, 'v1', 'tool.tar.gz', extra)) }, router(routes))).ok, extra).toBe(false);
    }
    const known = `    verifiedWith: { method: cosign-key, keyUrl: "https://raw.example/k.pub", keySha256: "${HEX2}", identity: "https://github.com/o/r/.github/workflows/r.yml@refs/tags/v1" }\n    wrappedImage: { ref: "ghcr.io/o/r:v1", digest: "${DIGEST}" }\n`;
    expect(problems(await run({}, { 'data/reviewed-tools.yml': rtFile(cli(HEX, 'v1', 'tool.tar.gz', known)) }, router(routes)))).toBe('');
  });

  it('P42: tools that is not a list, an entry with no id, or a duplicate id fails', async () => {
    const routes = actionRoutes('v1', SHA, daysAgo(400));
    const base = { 'data/reviewed-tools.yml': rtFile(action('v1', SHA)) };
    expect(problems(await run(base, { 'data/reviewed-tools.yml': 'pinnedOn: "x"\ntools: { a: 1 }\n' }, router(routes)))).toContain('not a list');
    const noId = `  - candidate: { kind: action, repo: o/r, version: "v9", pin: { sha: "${SHA2}" } }\n`;
    expect(problems(await run(base, { 'data/reviewed-tools.yml': rtFile(action('v1', SHA) + noId) }, router(routes)))).toContain('no id');
    // a changed copy placed BEFORE the unchanged original is not hidden by it
    const dup = await run(base, { 'data/reviewed-tools.yml': rtFile(action('v2', SHA2) + action('v1', SHA)) }, router(routes));
    expect(problems(dup)).toContain('more than once');
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

  it('P41/P42: an unknown hash- or URL-shaped field, a non-tool value or a duplicate tool key fails', async () => {
    const extra = bin().replace('      archiveSha256:', '      mirror: https://m.example/g.tgz\n      archiveSha256:');
    expect(problems(await run({}, { 'data/pinned-binaries.yml': extra }, router(rel(daysAgo(30)))))).toContain('mirror');
    expect(problems(await run({}, { 'data/pinned-binaries.yml': `${bin()}h: "1.0"\n` }, router(rel(daysAgo(30)))))).toContain('not a tool entry');
    await expect(run({}, { 'data/pinned-binaries.yml': bin() + bin() }, router(rel(daysAgo(30))))).rejects.toThrow('data/pinned-binaries.yml is not valid YAML');
    const known = bin().replace('      archiveSha256:', `      binarySha256: ${HEX2}\n      archiveSha256:`);
    expect((await run({}, { 'data/pinned-binaries.yml': known }, router(rel(daysAgo(30))))).ok).toBe(true);
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
const review = (login: string, state: string, commit = SHA, body = '') => ({ user: { login }, state, commit_id: commit, body });
/** One-owner mode (R-E5): the owner's review on the head with the `Security-fix-approved` line. */
const confirm = (login = 'CrisWorking', commit = SHA, state = 'COMMENTED') => review(login, state, commit, 'Checked the diff.\r\n  Security-fix-approved  \n');
const prRoutes = (o: { body?: string | null; labels?: string[]; author?: string; head?: string; events?: unknown; reviews?: unknown } = {}): Routes => ({
  [gh('o/p/pulls/7')]: {
    number: 7, head: { sha: o.head ?? SHA }, user: { login: o.author ?? 'contributor' },
    body: o.body === undefined ? `Fixes the CVE.\n\n${REASON}\n` : o.body, labels: (o.labels ?? ['security-fix']).map((name) => ({ name })),
  },
  [gh('o/p/issues/7/events?per_page=100&page=1')]: o.events ?? [labeled('someone', 'labeled', 'bug'), labeled('CrisWorking')],
  [gh('o/p/pulls/7/reviews?per_page=100&page=1')]: o.reviews ?? [confirm()],
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
    expect(problems(noApprovals)).toContain('approving review');
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
      self: { reviews: [review('Second', 'APPROVED')], author: 'Second' },
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
      expect(problems(r), name).toContain('approving review');
    }
    // a later approval after a change request counts again
    expect((await emergency(OWNERS2, prRoutes({ reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'CHANGES_REQUESTED'), review('Second', 'APPROVED')] }))).ok).toBe(true);
  });

  it('an API error reading the PR, events or reviews fails closed (not "no label")', async () => {
    for (const path of ['o/p/pulls/7', 'o/p/issues/7/events?per_page=100&page=1', 'o/p/pulls/7/reviews?per_page=100&page=1']) {
      const r = await emergency(OWNERS2, { ...prRoutes({ reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED')] }), [gh(path)]: 502 });
      expect(r.ok, path).toBe(false);
      expect(r.findings.some((f) => f.kind === 'security-fix' && f.lookupFailed), path).toBe(true);
      const one = await emergency(OWNERS1, { ...prRoutes(), [gh(path)]: 502 });
      expect(one.findings.some((f) => f.kind === 'security-fix' && f.lookupFailed), `one owner: ${path}`).toBe(true);
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

  it('R-E5: one owner: an owner COMMENTED review with the Security-fix-approved line on the head → pass', async () => {
    // the owner may confirm on their own PR; an APPROVED review with the line counts too
    const own = await emergency(OWNERS1, prRoutes({ author: 'CrisWorking', reviews: [confirm()] }));
    expect(own.ok).toBe(true);
    expect(formatReport(own)).toContain('Security-fix-approved');
    expect((await emergency(OWNERS1, prRoutes({ reviews: [confirm('crisworking', SHA, 'APPROVED')] }))).ok).toBe(true);
  });

  it('R-E5: one owner: the confirming review on an older commit, from a non-owner, without the line, or missing → fail', async () => {
    const cases: Record<string, unknown[]> = {
      olderCommit: [confirm('CrisWorking', SHA2)],
      nonOwner: [confirm('contributor')],
      noLine: [review('CrisWorking', 'COMMENTED', SHA, 'looks fine'), review('CrisWorking', 'APPROVED', SHA, '')],
      lineNotAlone: [review('CrisWorking', 'COMMENTED', SHA, 'Security-fix-approved, I think'), review('CrisWorking', 'COMMENTED', SHA, '> Security-fix-approved')],
      wrongState: [confirm('CrisWorking', SHA, 'CHANGES_REQUESTED'), confirm('CrisWorking', SHA, 'PENDING')],
      noReview: [],
      dismissedItself: [confirm('CrisWorking', SHA, 'DISMISSED')],
      laterDismissal: [confirm(), review('CrisWorking', 'DISMISSED', SHA)],
      laterChangeRequest: [confirm(), review('CrisWorking', 'CHANGES_REQUESTED', SHA)],
    };
    for (const [name, reviews] of Object.entries(cases)) {
      const r = await emergency(OWNERS1, prRoutes({ reviews }));
      expect(r.ok, name).toBe(false);
      expect(problems(r), name).toContain('Security-fix-approved');
    }
    // a confirmation after a dismissal counts again; a later plain comment does not cancel one
    expect((await emergency(OWNERS1, prRoutes({ reviews: [confirm(), review('CrisWorking', 'DISMISSED', SHA), confirm()] }))).ok).toBe(true);
    expect((await emergency(OWNERS1, prRoutes({ reviews: [confirm(), review('CrisWorking', 'COMMENTED', SHA, 'thanks')] }))).ok).toBe(true);
  });

  it('R-E5 regression: a label and confirmation given for commit B do not carry over to a commit C pushed later', async () => {
    // The owner labelled the PR and confirmed B (SHA2). C (SHA) was pushed afterwards; C may even be an old commit
    // with its own earlier CI runs. Nothing ties the owner to C, so it fails, until the owner confirms C itself.
    const reviews = [confirm('CrisWorking', SHA2)];
    const r = await emergency(OWNERS1, prRoutes({ head: SHA, reviews }));
    expect(r.ok).toBe(false);
    expect(problems(r)).toContain(SHA.slice(0, 12));
    expect((await emergency(OWNERS1, prRoutes({ head: SHA, reviews: [...reviews, confirm('CrisWorking', SHA)] }))).ok).toBe(true);
  });

  it('R-E3: approvals needed = min(2, owners other than the author), at least 1', async () => {
    // 2 owners, the author is one of them: one approval from the other owner is enough
    expect((await emergency(OWNERS2, prRoutes({ author: 'Second', reviews: [review('CrisWorking', 'APPROVED')] }))).ok).toBe(true);
    expect((await emergency(OWNERS2, prRoutes({ author: 'Second', reviews: [review('Second', 'APPROVED')] }))).ok).toBe(false);
    expect((await emergency(OWNERS2, prRoutes({ author: 'Second', reviews: [review('CrisWorking', 'APPROVED', SHA2)] }))).ok).toBe(false);
    // 3 owners: 2 needed, whether or not the author is an owner
    const OWNERS3 = '/data/ @CrisWorking @Second @Third\n/scripts/ @CrisWorking @Second @Third\n';
    expect((await emergency(OWNERS3, prRoutes({ author: 'Third', reviews: [review('CrisWorking', 'APPROVED')] }))).ok).toBe(false);
    expect((await emergency(OWNERS3, prRoutes({ author: 'Third', reviews: [review('CrisWorking', 'APPROVED'), review('Second', 'APPROVED')] }))).ok).toBe(true);
    expect((await emergency(OWNERS3, prRoutes({ reviews: [review('Third', 'APPROVED')] }))).ok).toBe(false);
    expect((await emergency(OWNERS3, prRoutes({ reviews: [review('Third', 'APPROVED'), review('Second', 'APPROVED')] }))).ok).toBe(true);
  });

  it('plain text output strips escapes from file-supplied names too', async () => {
    const head = { 'package-lock.json': lock({ 'x\u001b[2J\n::error::y': '1.0.0' }) };
    const out = formatReport(await run({}, head, router({})));
    expect(out).not.toContain('\u001b');
    expect(out.split('\n').some((l) => l.trimStart().startsWith('::'))).toBe(false);
  });
});
