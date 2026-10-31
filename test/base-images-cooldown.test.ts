// D2: scripts/cooldown.ts also covers data/base-images.yml: a changed entry's digest must be the Docker Hub tag's digest,
// and the tag's push date (from Docker Hub, never from the file) must be at least 7 days old.
import { describe, expect, it } from 'vitest';
import { runCooldown, WATCHED_FILES, type Files } from '../scripts/cooldown.js';

const NOW = new Date('2026-10-31T12:00:00Z');
const daysAgo = (d: number): string => new Date(NOW.getTime() - d * 86_400_000).toISOString();
const D1 = `sha256:${'a'.repeat(64)}`;
const D2 = `sha256:${'b'.repeat(64)}`;
const file = (rows: { id: string; image: string; tag: string; digest: string; by?: string }[]): string => `images:\n${rows.map((r) => `  - id: ${r.id}\n    image: ${r.image}\n    tag: ${r.tag}\n    digest: ${r.digest}\n    releasedAt: 2026-10-01T00:00:00Z\n    pinnedOn: 2026-10-31T00:00:00Z\n    reviewedBy: ${r.by ?? 'Claude delegated DECISIONS 105'}\n    reviewedAt: 2026-10-31\n`).join('')}`;
const hub = (image: string, tag: string): string => `https://hub.docker.com/v2/repositories/library/${image}/tags/${tag}`;
function fetchFor(routes: Record<string, unknown>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const body = routes[String(input)];
    return body === undefined ? new Response('{}', { status: 404 }) : new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
}
const run = (base: Files, head: Files, f: typeof fetch) => runCooldown({ base, head, fetch: f, now: NOW });
const problems = (r: Awaited<ReturnType<typeof run>>): string => r.findings.map((f) => `${f.kind} ${f.name}: ${f.problem}`).join('\n');
const row = { id: 'redis-7', image: 'redis', tag: '7.4.5', digest: D1 };

describe('cooldown: data/base-images.yml', () => {
  it('is a watched file', () => {
    expect(WATCHED_FILES).toContain('data/base-images.yml');
  });

  it('a new or changed entry passes when its digest is the Docker Hub tag digest and the tag is at least 7 days old', async () => {
    const head = { 'data/base-images.yml': file([row]) };
    expect((await run({}, head, fetchFor({ [hub('redis', '7.4.5')]: { digest: D1, tag_last_pushed: daysAgo(10) } }))).ok).toBe(true);
  });

  it('fails when the tag is younger than 7 days, the digest differs, the lookup fails, or the image is not a bare official name', async () => {
    const head = { 'data/base-images.yml': file([row]) };
    const young = await run({}, head, fetchFor({ [hub('redis', '7.4.5')]: { digest: D1, tag_last_pushed: daysAgo(2) } }));
    expect(young.ok).toBe(false);
    expect(young.findings[0]?.kind).toBe('base-image');
    expect(problems(await run({}, head, fetchFor({ [hub('redis', '7.4.5')]: { digest: D2, tag_last_pushed: daysAgo(30) } })))).toContain('needs owner review');
    expect(problems(await run({}, head, fetchFor({})))).toContain('404');
    for (const image of ['ghcr.io/x/redis', 'someone/redis', 'docker.io/library/redis']) {
      expect(problems(await run({}, { 'data/base-images.yml': file([{ ...row, image }]) }, fetchFor({})))).toContain('needs owner review');
    }
  });

  it('an unchanged entry is not looked up again; a change of reviewedBy alone is not a change; a new digest is', async () => {
    const base = { 'data/base-images.yml': file([row]) };
    expect((await run(base, { 'data/base-images.yml': file([{ ...row, by: 'Someone Else' }]) }, fetchFor({}))).ok).toBe(true);
    const bumped = { 'data/base-images.yml': file([{ ...row, digest: D2 }]) };
    expect((await run(base, bumped, fetchFor({}))).ok).toBe(false);
  });

  it('a file that is not a list of entries, or has a duplicate id, fails', async () => {
    expect((await run({}, { 'data/base-images.yml': 'images: nope\n' }, fetchFor({}))).ok).toBe(false);
    expect((await run({}, { 'data/base-images.yml': file([row, row]) }, fetchFor({ [hub('redis', '7.4.5')]: { digest: D1, tag_last_pushed: daysAgo(10) } }))).ok).toBe(false);
  });
});
