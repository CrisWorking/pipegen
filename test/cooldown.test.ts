import { describe, expect, it } from 'vitest';
import { formatReport, runCooldown, type Files } from '../scripts/cooldown.js';

const NOW = new Date('2026-10-27T12:00:00Z');
const daysAgo = (d: number): string => new Date(NOW.getTime() - d * 86_400_000).toISOString().replace('.000Z', 'Z');

function lock(pkgs: Record<string, string>): string {
  const packages: Record<string, unknown> = { '': { name: 'x' } };
  for (const [name, version] of Object.entries(pkgs)) packages[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz` };
  return JSON.stringify({ lockfileVersion: 3, packages });
}

/** A fake fetch: npm time maps and GitHub releases by URL; anything unlisted is a 500. */
function fakeFetch(npm: Record<string, Record<string, string>>, releases: Record<string, string> = {}, calls: string[] = []): typeof fetch {
  return (async (url: string) => {
    calls.push(String(url));
    const u = String(url);
    let body: unknown;
    if (u.startsWith('https://registry.npmjs.org/')) {
      const name = decodeURIComponent(u.slice('https://registry.npmjs.org/'.length));
      if (!npm[name]) return new Response('no', { status: 500 });
      body = { time: npm[name] };
    } else {
      const m = /repos\/(.+)\/releases\/tags\/(.+)$/.exec(u);
      const when = m ? releases[`${m[1]}@${decodeURIComponent(m[2] as string)}`] : undefined;
      if (!when) return new Response('nf', { status: 404 });
      body = { published_at: when };
    }
    return new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
}

const run = (base: Files, head: Files, f: typeof fetch, extra = {}) => runCooldown({ base, head, fetch: f, now: NOW, ...extra });

const reviewed = (version: string, sha: string, releasedAt: string): string => `pinnedOn: "${daysAgo(30)}"
tools:
  - id: actions-checkout
    releasedAt: "${releasedAt}"
    candidate: { id: actions-checkout, kind: action, repo: actions/checkout, version: "${version}", pin: { sha: "${sha}" } }
`;

describe('cooldown: npm lockfile', () => {
  it('fails a new transitive package under 7 days and passes an old one', async () => {
    const base = { 'package-lock.json': lock({ tsup: '9.0.0' }) };
    const head = { 'package-lock.json': lock({ tsup: '9.0.0', rollup: '4.64.12', ms: '2.1.3' }) };
    const f = fakeFetch({ rollup: { '4.64.12': daysAgo(1) }, ms: { '2.1.3': daysAgo(400) } });
    const r = await run(base, head, f);
    expect(r.ok).toBe(false);
    expect(r.findings.map((x) => x.name)).toEqual(['rollup']);
    expect(formatReport(r)).toContain('rollup 4.64.12');
  });

  it('ignores a version that did not change, and a removed package, without any request', async () => {
    const calls: string[] = [];
    const base = { 'package-lock.json': lock({ tsup: '9.0.0', gone: '1.0.0' }) };
    const head = { 'package-lock.json': lock({ tsup: '9.0.0' }) };
    const r = await run(base, head, fakeFetch({}, {}, calls));
    expect(r.ok).toBe(true);
    expect(calls).toEqual([]);
  });

  it('exactly 7 days passes, 6.9 days fails', async () => {
    const head = { 'package-lock.json': lock({ a: '1.0.0', b: '1.0.0' }) };
    const f = fakeFetch({ a: { '1.0.0': daysAgo(7) }, b: { '1.0.0': daysAgo(6.9) } });
    const r = await run({}, head, f);
    expect(r.findings.map((x) => x.name)).toEqual(['b']);
  });

  it('fails closed on a registry error and says how to retry', async () => {
    const r = await run({}, { 'package-lock.json': lock({ a: '1.0.0' }) }, fakeFetch({}));
    expect(r.ok).toBe(false);
    expect(r.findings[0]?.lookupFailed).toBe(true);
    expect(formatReport(r)).toContain('Re-run the failed job');
  });

  it('fails closed on a network exception and on a missing publish time', async () => {
    const boom = (async () => { throw new TypeError('down'); }) as unknown as typeof fetch;
    expect((await run({}, { 'package-lock.json': lock({ a: '1.0.0' }) }, boom)).ok).toBe(false);
    const r = await run({}, { 'package-lock.json': lock({ a: '1.0.0' }) }, fakeFetch({ a: { '0.9.0': daysAgo(90) } }));
    expect(r.ok).toBe(false);
  });

  it('caps the number of lookups', async () => {
    const many: Record<string, string> = {};
    for (let i = 0; i < 5; i++) many[`p${i}`] = '1.0.0';
    const r = await run({}, { 'package-lock.json': lock(many) }, fakeFetch({}), { maxLookups: 3 });
    expect(r.ok).toBe(false);
    expect(r.findings[0]?.problem).toContain('cap is 3');
  });

  it('encodes scoped names', async () => {
    const calls: string[] = [];
    await run({}, { 'package-lock.json': lock({ '@types/node': '26.0.0' }) }, fakeFetch({ '@types/node': { '26.0.0': daysAgo(30) } }, {}, calls));
    expect(calls[0]).toBe('https://registry.npmjs.org/@types%2fnode');
  });
});

describe('cooldown: reviewed tools and pinned binaries', () => {
  const sha1 = 'a'.repeat(40);
  const sha2 = 'b'.repeat(40);

  it('fails a changed reviewed pin whose upstream release is young, even if the file claims it is old', async () => {
    const base = { 'data/reviewed-tools.yml': reviewed('v7.0.1', sha1, daysAgo(60)) };
    const head = { 'data/reviewed-tools.yml': reviewed('v7.0.2', sha2, daysAgo(60)) };
    const r = await run(base, head, fakeFetch({}, { 'actions/checkout@v7.0.2': daysAgo(2) }));
    expect(r.ok).toBe(false);
    expect(r.findings[0]?.problem).toContain('2.0 days');
  });

  it('passes a changed reviewed pin that is old enough, and ignores an unchanged one', async () => {
    const base = { 'data/reviewed-tools.yml': reviewed('v7.0.1', sha1, daysAgo(60)) };
    const head = { 'data/reviewed-tools.yml': reviewed('v7.0.2', sha2, daysAgo(60)) };
    expect((await run(base, head, fakeFetch({}, { 'actions/checkout@v7.0.2': daysAgo(30) }))).ok).toBe(true);
    const calls: string[] = [];
    const same = await run(base, base, fakeFetch({}, {}, calls));
    expect(same.ok).toBe(true);
    expect(calls).toEqual([]);
  });

  it('falls back to the recorded date when GitHub has no release, with a note', async () => {
    const head = { 'data/reviewed-tools.yml': reviewed('v7.0.2', sha2, daysAgo(2)) };
    const r = await run({}, head, fakeFetch({}));
    expect(r.ok).toBe(false);
    expect(r.notes[0]).toContain('no GitHub release found');
  });

  it('fails closed when GitHub errors', async () => {
    const head = { 'data/reviewed-tools.yml': reviewed('v7.0.2', sha2, daysAgo(60)) };
    const f = (async () => new Response('x', { status: 503 })) as unknown as typeof fetch;
    const r = await run({}, head, f);
    expect(r.ok).toBe(false);
    expect(r.findings[0]?.lookupFailed).toBe(true);
  });

  it('checks a changed pinned binary, and ignores a review-only edit', async () => {
    const bin = (v: string, rel: string, by: string): string =>
      `gitleaks:\n  version: ${v}\n  repo: gitleaks/gitleaks\n  releasedAt: "${rel}"\n  pinnedOn: "${daysAgo(1)}"\n  reviewedBy: ${by}\n`;
    const base = { 'data/pinned-binaries.yml': bin('8.30.1', daysAgo(90), 'PENDING') };
    const calls: string[] = [];
    const reviewOnly = await run(base, { 'data/pinned-binaries.yml': bin('8.30.1', daysAgo(90), 'Cris') }, fakeFetch({}, {}, calls));
    expect(reviewOnly.ok).toBe(true);
    expect(calls).toEqual([]);
    const bumped = await run(base, { 'data/pinned-binaries.yml': bin('8.31.0', daysAgo(3), 'PENDING') }, fakeFetch({}, { 'gitleaks/gitleaks@v8.31.0': daysAgo(3) }));
    expect(bumped.ok).toBe(false);
    expect(bumped.findings[0]?.kind).toBe('pinned-binary');
  });

  it('no changes at all passes', async () => {
    expect((await run({}, {}, fakeFetch({}))).ok).toBe(true);
  });
});
