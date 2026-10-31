// D2 (ruling B3): the reviewed base-image list. The AI names only a list id; pipegen writes <image>:<tag>@sha256:<digest>.
// Offline: the loader is tested on fixtures and on the real data file; the refresh script on a faked Docker Hub and a faked resolvePin.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { BASE_IMAGE_LINES, baseImageIds, baseImageRef, BaseImageError, loadBaseImages, nodeBaseImageId, parseBaseImages } from '../src/engine/base-images.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { PinError } from '../src/engine/pin.js';
import { mapNodeVersion } from '../src/engine/render-step.js';
import { refreshBaseImages, renderBaseImagesYaml } from '../scripts/base-images.js';
import { fakeFetch } from './helpers/fake-http.js';

const DAY = 86_400_000;
const PINNED = '2026-10-31T10:00:00Z';
const digestOf = (n: number): string => `sha256:${n.toString(16).padStart(64, '0')}`;
const TAGS: Record<string, string> = {
  'node-22-bookworm-slim': '22.20.1-bookworm-slim', 'node-24-bookworm-slim': '24.10.2-bookworm-slim', 'node-26-bookworm-slim': '26.0.3-bookworm-slim',
  'postgres-17': '17.6', 'mysql-8.4': '8.4.6', 'redis-7': '7.4.5', 'mongo-8.0': '8.0.12', 'rabbitmq-4-management': '4.1.3-management',
};
function entryFor(id: string, n: number): Record<string, unknown> {
  return {
    id, image: BASE_IMAGE_LINES[id]?.image, tag: TAGS[id], digest: digestOf(n), releasedAt: '2026-10-10T08:00:00Z', pinnedOn: PINNED,
    reviewedBy: 'Claude delegated DECISIONS 105', reviewedAt: '2026-10-31', platforms: ['linux/amd64', 'linux/arm64'],
  };
}
const goodList = (): Record<string, unknown>[] => Object.keys(BASE_IMAGE_LINES).map((id, i) => entryFor(id, i + 1));
const edited = (id: string, change: Record<string, unknown>): unknown => goodList().map((e) => (e.id === id ? { ...e, ...change } : e));
const refusal = (raw: unknown): string => { try { parseBaseImages(raw); } catch (e) { return (e as Error).message; } return ''; };

describe('base-images (loader)', () => {
  it('base-images: loader refuses a GHCR entry, a rolling tag, a missing digest', () => {
    expect(parseBaseImages(goodList())).toHaveLength(8);
    expect(refusal(edited('node-22-bookworm-slim', { image: 'ghcr.io/library/node' }))).toMatch(/official Docker Hub image/);
    expect(refusal(edited('node-22-bookworm-slim', { image: 'docker.io/library/node' }))).toMatch(/official Docker Hub image/);
    expect(refusal(edited('node-22-bookworm-slim', { image: 'someone/node' }))).toMatch(/official Docker Hub image/);
    expect(refusal(edited('node-22-bookworm-slim', { image: 'evil' }))).toMatch(/official Docker Hub image|image/);
    for (const tag of ['22-bookworm-slim', '22.20-bookworm-slim', 'latest', 'lts-bookworm-slim', '22.20.1', '22.20.1-bookworm-slim\n', '22.20.1-bookworm-slim latest']) expect(refusal(edited('node-22-bookworm-slim', { tag })), tag).toMatch(/tag/);
    expect(refusal(edited('postgres-17', { tag: '17' }))).toMatch(/tag/);
    // mongo 8: the stable 8.0 line only; 8.1+ are rapid releases
    for (const tag of ['8.3.11', '8.1.0', '8.0', '8']) expect(refusal(edited('mongo-8.0', { tag })), tag).toMatch(/tag/);
    expect(refusal(edited('postgres-17', { tag: 'latest' }))).toMatch(/tag/);
    for (const digest of [undefined, '', 'sha256:abc', `sha256:${'a'.repeat(63)}`, `sha256:${'A'.repeat(64)}`, 'a'.repeat(64), `sha512:${'a'.repeat(64)}`]) expect(refusal(edited('redis-7', { digest })), String(digest)).toMatch(/digest/);
  });

  it('refuses a duplicate id, an unknown id, an id whose image differs, an unknown key and a non-list', () => {
    expect(refusal([...goodList(), entryFor('redis-7', 99)])).toMatch(/duplicate/);
    expect(refusal([...goodList(), { ...entryFor('redis-7', 99), id: 'redis-8' }])).toMatch(/id/);
    for (const id of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      expect(() => parseBaseImages([...goodList(), { ...entryFor('redis-7', 99), id }]), id).toThrow(BaseImageError);
      expect(refusal([...goodList(), { ...entryFor('redis-7', 99), id }]), id).toMatch(/base-image ids/);
    }
    for (const image of ['Node', 'node_', 'node image', 'node\n', '-node', 'no/de', 'node:22']) expect(refusal(edited('node-22-bookworm-slim', { image })), image).toMatch(/image/);
    expect(refusal(edited('redis-7', { image: 'mongo' }))).toMatch(/image/);
    expect(refusal(goodList().map((e) => ({ ...e, extra: 1 })))).not.toBe('');
    expect(refusal({ images: 'x' })).not.toBe('');
    expect(refusal(null)).not.toBe('');
  });

  it('refuses releasedAt less than 7 days before pinnedOn, and an unreadable date', () => {
    expect(refusal(edited('mongo-8.0', { releasedAt: '2026-10-25T10:00:01Z' }))).toMatch(/7 days/);
    expect(parseBaseImages(edited('mongo-8.0', { releasedAt: '2026-10-24T10:00:00Z' }))).toHaveLength(8);
    expect(refusal(edited('mongo-8.0', { releasedAt: '2026-11-30T10:00:00Z' }))).toMatch(/7 days/);
    expect(refusal(edited('mongo-8.0', { releasedAt: 'yesterday' }))).not.toBe('');
  });

  it('refuses a bad reviewedBy: REVIEWER_RE plus the shared marker rules', () => {
    for (const reviewedBy of ['', 'x', 'Claude\u200b delegated', 'Claude; rm -rf', 'a'.repeat(81), 'PENDlNG']) expect(refusal(edited('redis-7', { reviewedBy })), reviewedBy).toMatch(/reviewedBy/);
    expect(refusal(edited('redis-7', { reviewedAt: '2026-10-30' }))).toMatch(/reviewedAt/);   // before pinnedOn
    expect(refusal(edited('redis-7', { reviewedAt: '2026-02-31' }))).toMatch(/reviewedAt/);
  });

  it('a refreshed entry (reviewedBy PENDING) is refused by the loader until reviewed', () => {
    const msg = refusal(edited('redis-7', { reviewedBy: 'PENDING', reviewedAt: 'PENDING' }));
    expect(msg).toMatch(/review/);
    expect(msg).toContain('redis-7');
    expect(() => parseBaseImages(edited('redis-7', { reviewedBy: 'PENDING', reviewedAt: 'PENDING' }))).toThrow(BaseImageError);
  });

  it('baseImageRef: exact format; an unknown id throws and never falls back', () => {
    const list = parseBaseImages(goodList());
    expect(baseImageRef('postgres-17', list)).toBe(`postgres:17.6@${digestOf(Object.keys(BASE_IMAGE_LINES).indexOf('postgres-17') + 1)}`);
    for (const id of ['', 'postgres', 'postgres-18', 'latest', 'node:22', '../node', 'POSTGRES-17', 'constructor', '__proto__', 'toString']) expect(() => baseImageRef(id, list), id).toThrow(BaseImageError);
  });

  it('M1: an unquoted YAML number tag (17.10 is the number 17.1) is refused, never loaded as 17.1', () => {
    const text = readFileSync(new URL('../data/base-images.yml', import.meta.url), 'utf8');
    expect(text).toContain('tag: "17.10"');
    const unquoted = text.replace('tag: "17.10"', 'tag: 17.10');
    expect(unquoted).not.toBe(text);
    expect(refusal((parse(unquoted) as { images: unknown }).images)).toMatch(/tag/);
    expect(() => parseBaseImages(parse(unquoted))).toThrow(BaseImageError);
  });

  it('M6: platforms must hold linux/amd64 and linux/arm64 (an amd64 + 386 index, a lone amd64, an empty or a missing list is refused)', () => {
    for (const platforms of [['linux/amd64', 'linux/386'], ['linux/amd64'], ['linux/arm64'], [], undefined, 'linux/amd64', ['linux/amd64', 'linux/arm64\n'], ['windows/amd64', 'linux/arm64'], [1, 2]]) {
      expect(refusal(edited('redis-7', { platforms })), JSON.stringify(platforms)).toMatch(/platforms/);
    }
    expect(parseBaseImages(edited('redis-7', { platforms: ['linux/386', 'linux/amd64', 'linux/arm', 'linux/arm64'] }))).toHaveLength(8);
  });

  it('M5: the mongo id is mongo-8.0 (upstream mongo:8 is 8.3.x, a different line); no mongo-8 id', () => {
    expect(Object.keys(BASE_IMAGE_LINES)).toContain('mongo-8.0');
    expect(Object.keys(BASE_IMAGE_LINES)).not.toContain('mongo-8');
    expect(() => baseImageRef('mongo-8', parseBaseImages(goodList()))).toThrow(BaseImageError);
    expect(baseImageIds()).toContain('mongo-8.0');
  });

  it('M2: every id refuses a rolling tag, a missing variant, an extra suffix and a prefix', () => {
    for (const [id, good] of Object.entries(TAGS)) {
      const m = /^(\d+)\.(\d+)(?:\.(\d+))?(-.+)?$/.exec(good) as RegExpExecArray;
      const [, major, minor, patch, variant = ''] = m;
      const bad = new Set<string>([
        major as string, `${major}.`, `${major}.x`, `${major}${variant}`, `${major}.${minor}${variant}`, `${major}.${minor}.${patch ?? '0'}.1${variant}`,
        `${major}.${minor}.${patch ?? '0'}${variant}-alpine`, `${good}-alpine`, `${good} x`, `${good}x`, `x${good}`, ` ${good}`, `${good}\n`, `v${good}`, `latest`,
        ...(variant === '' ? [] : [`${major}.${minor}${patch === undefined ? '' : `.${patch}`}`, variant.slice(1)]),
      ]);
      bad.delete(good);
      for (const tag of bad) expect(refusal(edited(id, { tag })), `${id} ${JSON.stringify(tag)}`).toMatch(/tag/);
      expect(parseBaseImages(edited(id, { tag: good })), id).toHaveLength(8);
    }
  });

  it('M3: the 7 day rule at 7 d (accepted), 7 d minus one second, 6 d 23 h and 6 d (refused)', () => {
    expect(parseBaseImages(edited('mongo-8.0', { releasedAt: '2026-10-24T10:00:00Z' }))).toHaveLength(8);
    for (const releasedAt of ['2026-10-24T10:00:01Z', '2026-10-24T11:00:00Z', '2026-10-25T10:00:00Z']) expect(refusal(edited('mongo-8.0', { releasedAt })), releasedAt).toMatch(/7 days/);
  });

  it('M9: the loaded entries, the list, BASE_IMAGE_LINES and its lines are frozen; a mutation throws and baseImageRef is unchanged', () => {
    const list = parseBaseImages(goodList());
    const before = baseImageRef('redis-7', list);
    expect(Object.isFrozen(list)).toBe(true);
    for (const e of list) expect(Object.isFrozen(e), e.id).toBe(true);
    expect(() => { (list.find((e) => e.id === 'redis-7') as { tag: string }).tag = 'latest'; }).toThrow(TypeError);
    expect(() => { (list as unknown as unknown[]).push({}); }).toThrow(TypeError);
    expect(() => { (list as unknown as unknown[]).length = 0; }).toThrow(TypeError);
    expect(baseImageRef('redis-7', list)).toBe(before);
    expect(Object.isFrozen(BASE_IMAGE_LINES)).toBe(true);
    for (const l of Object.values(BASE_IMAGE_LINES)) expect(Object.isFrozen(l)).toBe(true);
    expect(() => { (BASE_IMAGE_LINES as Record<string, unknown>).evil = { image: 'evil', tagRe: /./ }; }).toThrow(TypeError);
    expect(() => { (BASE_IMAGE_LINES['redis-7'] as { image: string }).image = 'evil'; }).toThrow(TypeError);
    expect(() => parseBaseImages(goodList().concat([entryFor('redis-7', 5)]))).toThrow(/duplicate/);
    const real = loadBaseImages();
    expect(Object.isFrozen(real)).toBe(true);
    for (const e of real) expect(Object.isFrozen(e), e.id).toBe(true);
    expect(() => { (real[0] as { digest: string }).digest = 'x'; }).toThrow(TypeError);
  });
});

describe('base-images (node)', () => {
  it('base-images: node major chosen by mapNodeVersion over {22,24,26}', () => {
    const list = parseBaseImages(goodList());
    for (const [rv, id, note] of [
      ['22', 'node-22-bookworm-slim', false], ['24', 'node-24-bookworm-slim', false], ['26', 'node-26-bookworm-slim', false],
      ['>=22.1.0', 'node-22-bookworm-slim', false], ['v24.3.0', 'node-24-bookworm-slim', false], [undefined, 'node-24-bookworm-slim', false],
      ['20', 'node-22-bookworm-slim', true], ['23', 'node-24-bookworm-slim', true], ['28', 'node-26-bookworm-slim', true], ['lts/*', 'node-24-bookworm-slim', true],
    ] as const) {
      const r = nodeBaseImageId(rv, list);
      expect(r.id, String(rv)).toBe(id);
      expect(r.note !== undefined, String(rv)).toBe(note);
      expect(r.note, String(rv)).toBe(mapNodeVersion(rv, ['22', '24', '26']).note);
    }
  });

  it('hostile runtimeVersion values never reach a tag: you get a list id or a note', () => {
    const list = parseBaseImages(goodList());
    const ids = new Set(baseImageIds(list));
    for (const rv of ['22; rm -rf /', '../', '${{ secrets.X }}', '22\n- run: evil', 'latest', '99', '', '1'.repeat(40), '24\u202e', '$(id)', "22'; curl x | sh"]) {
      const r = nodeBaseImageId(rv, list);
      expect(ids.has(r.id), rv).toBe(true);
      const ref = baseImageRef(r.id, list);
      expect(ref, rv).toMatch(/^node:\d+\.\d+\.\d+-bookworm-slim@sha256:[0-9a-f]{64}$/);
      expect(ref, rv).not.toMatch(/[;$\n\\'"{}]|\.\./);
      if (r.id !== 'node-24-bookworm-slim' || rv === '99') expect(r.note !== undefined || /^(?:\D*)(22|24|26)/.test(rv), rv).toBe(true);
    }
  });

  it('the majors come from the list itself: without node 26 a repo asking for 26 gets 24 and a note', () => {
    const list = parseBaseImages(goodList().filter((e) => e.id !== 'node-26-bookworm-slim'));
    const r = nodeBaseImageId('26', list);
    expect(r.id).toBe('node-24-bookworm-slim');
    expect(r.note).toContain('22, 24');
  });

  it('nodeBaseImageId throws when the list has no node entry (no fallback to a made-up tag)', () => {
    const noNode = parseBaseImages(goodList().filter((e) => !String(e.id).startsWith('node-')));
    expect(() => nodeBaseImageId('22', noNode)).toThrow(BaseImageError);
  });
});

// ---------- refresh ----------

const NOW = Date.parse('2026-10-31T10:00:00Z');
const HUB = 'https://hub.docker.com/v2/repositories/library';
interface HubTag { name: string; tag_last_pushed: string; images: { architecture: string; os: string }[] }
const multi = [{ architecture: 'amd64', os: 'linux' }, { architecture: 'arm64', os: 'linux' }];
const ago = (days: number): string => new Date(NOW - days * DAY).toISOString();
const tagRow = (name: string, days: number, images = multi): HubTag => ({ name, tag_last_pushed: ago(days), images });
const hubFor = (image: string): HubTag[] => {
  switch (image) {
    case 'node': return [tagRow('26.1.0-bookworm-slim', 2), tagRow('26.0.3-bookworm-slim', 9), tagRow('26.0.3-alpine', 9), tagRow('26.0.2-bookworm-slim', 30), tagRow('26-bookworm-slim', 9), tagRow('24.11.0-bookworm-slim', 1), tagRow('24.10.2-bookworm-slim', 8), tagRow('24.10.1-bookworm-slim', 40), tagRow('22.20.1-bookworm-slim', 20), tagRow('22.20.1-bookworm', 20), tagRow('latest', 1), tagRow('lts-bookworm-slim', 20)];
    case 'postgres': return [tagRow('17.7', 3), tagRow('17.6', 12), tagRow('17.6-bookworm', 12), tagRow('17', 12), tagRow('17.5', 60)];
    case 'mysql': return [tagRow('8.4.7', 1), tagRow('8.4.6', 15), tagRow('8.4', 15), tagRow('8.4.6-oraclelinux9', 15), tagRow('8.0.43', 15)];
    case 'redis': return [tagRow('7.4.6', 4), tagRow('7.4.5', 10), tagRow('7.4.5-alpine', 10), tagRow('7.2.10', 40), tagRow('8.0.3', 10)];
    case 'mongo': return [tagRow('8.0.13', 2), tagRow('8.0.12', 9, [{ architecture: 'amd64', os: 'linux' }]), tagRow('8.0.11', 22), tagRow('8.0', 22), tagRow('8.3.2', 20), tagRow('8.1.0', 25)];
    default: return [tagRow('4.1.4-management', 3), tagRow('4.1.3-management', 11), tagRow('4.1.3', 11), tagRow('4-management', 11), tagRow('3.13.7-management', 50)];
  }
}
function hubRoutes(rows: (image: string) => HubTag[] = hubFor) {
  const routes: Record<string, (c: { url: URL }) => { body: unknown }> = {};
  for (const image of ['node', 'postgres', 'mysql', 'redis', 'mongo', 'rabbitmq']) {
    routes[`GET ${HUB}/${image}/tags`] = (c) => {
      const all = rows(image);
      const size = Number(c.url.searchParams.get('page_size') ?? '100');
      const page = Number(c.url.searchParams.get('page') ?? '1');
      const results = all.slice((page - 1) * size, page * size);
      return { body: { count: all.length, next: page * size < all.length ? `${HUB}/${image}/tags?page=${page + 1}&page_size=${size}` : null, results } };
    };
  }
  return routes;
}
function harness(over: { rows?: (image: string) => HubTag[]; reject?: (version: string) => boolean } = {}) {
  const { fetch, calls } = fakeFetch(hubRoutes(over.rows));
  const budgets: unknown[] = [];
  const resolved: { image: string; tag: string }[] = [];
  let budgetsMade = 0;
  const deps = {
    fetch, now: () => NOW,
    newBudget: () => { budgetsMade++; return newRateBudget(); },
    gh: undefined as never,
    resolvePin: async (c: { version: string }, d: { budget: unknown; notes: string[] }, install?: { package: string; version: string }) => {
      budgets.push(d.budget);
      resolved.push({ image: install?.package ?? '', tag: install?.version ?? c.version });
      if (over.reject?.(`${install?.package}:${install?.version}`)) throw new PinError('Docker Hub says that moved less than 7 days ago');
      d.notes.push(`New pin for ${install?.package}:${install?.version}`);
      return { ...c, version: install?.version ?? c.version, pin: { digest: digestOf(resolved.length + 100) } };
    },
  };
  return { deps, calls, budgets, resolved, made: () => budgetsMade };
}

describe('base-images (refresh)', () => {
  it('base-images: refresh uses one newRateBudget', async () => {
    const h = harness();
    await refreshBaseImages(h.deps as never);
    expect(h.made()).toBe(1);
    expect(h.budgets).toHaveLength(8);
    expect(new Set(h.budgets).size).toBe(1);
    expect(h.budgets[0]).toMatchObject({ remainingMs: expect.any(Number) });
    // and the script text creates it exactly once, outside any loop body of the per-entry work
    const text = readFileSync(new URL('../scripts/base-images.ts', import.meta.url), 'utf8');
    expect(text.match(/newRateBudget\(/g)?.length ?? 0).toBe(1);
  });

  it('picks, per line, the newest exact patch tag at least 7 days old with a multi-platform list, and sends it through resolvePin', async () => {
    const h = harness();
    const out = await refreshBaseImages(h.deps as never);
    const tags = Object.fromEntries(out.entries.map((e) => [e.id, e.tag]));
    expect(tags).toEqual({
      'node-22-bookworm-slim': '22.20.1-bookworm-slim', 'node-24-bookworm-slim': '24.10.2-bookworm-slim', 'node-26-bookworm-slim': '26.0.3-bookworm-slim',
      'postgres-17': '17.6', 'mysql-8.4': '8.4.6', 'redis-7': '7.4.5', 'mongo-8.0': '8.0.11', 'rabbitmq-4-management': '4.1.3-management',
    });
    expect(out.entries.map((e) => e.id)).toEqual(Object.keys(BASE_IMAGE_LINES));
    // every pin went through resolvePin with the image name and the exact tag; nothing else decides the digest
    expect(h.resolved).toContainEqual({ image: 'node', tag: '24.10.2-bookworm-slim' });
    for (const e of out.entries) {
      expect(e.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(e.pinnedOn).toBe('2026-10-31T10:00:00.000Z');
      expect(Date.parse(e.pinnedOn) - Date.parse(e.releasedAt)).toBeGreaterThanOrEqual(7 * DAY);
    }
    expect(out.platforms['mongo-8.0']).toEqual(['linux/amd64', 'linux/arm64']);
    for (const e of out.entries) expect(e.platforms, e.id).toEqual(out.platforms[e.id]);   // recorded in each entry, so the reviewer sees them
    for (const call of h.calls) expect(call.url.hostname).toBe('hub.docker.com');
  });

  it('never changes reviewedBy: a refreshed entry is PENDING and the loader refuses it', async () => {
    const h = harness();
    const out = await refreshBaseImages(h.deps as never);
    for (const e of out.entries) { expect(e.reviewedBy).toBe('PENDING'); expect(e.reviewedAt).toBe('PENDING'); }
    const text = renderBaseImagesYaml(out.entries);
    expect(text).not.toMatch(/delegated/);
    expect(() => parseBaseImages(parse(text).images)).toThrow(/review/);
  });

  it('falls to the next older tag when resolvePin refuses one; stops with an error when none is left (no rolling fallback)', async () => {
    const h = harness({ reject: (r) => r === 'node:24.10.2-bookworm-slim' });
    const out = await refreshBaseImages(h.deps as never);
    expect(out.entries.find((e) => e.id === 'node-24-bookworm-slim')?.tag).toBe('24.10.1-bookworm-slim');
    const none = harness({ reject: (r) => r.startsWith('redis:') });
    await expect(refreshBaseImages(none.deps as never)).rejects.toThrow(/redis-7/);
    const young = harness({ rows: (image) => (image === 'mysql' ? [tagRow('8.4.7', 1), tagRow('8.4', 30)] : hubFor(image)) });
    await expect(refreshBaseImages(young.deps as never)).rejects.toThrow(/mysql-8\.4/);
  });

  it('an error that is not a pin refusal (rate limit, network) stops the run at once and is not swallowed', async () => {
    const h = harness();
    let calls = 0;
    const deps = { ...h.deps, resolvePin: async () => { calls++; throw new Error('GitHub rate limit: stopped waiting.'); } };
    await expect(refreshBaseImages(deps as never)).rejects.toThrow(/^GitHub rate limit/);
    expect(calls).toBe(1);
    const down = fakeFetch({});
    await expect(refreshBaseImages({ ...h.deps, fetch: down.fetch } as never)).rejects.toThrow(/Docker Hub's tag list for node answered 404/);
  });

  it('M6: a tag listed for linux/amd64 and linux/386 (or amd64 and arm/v7 only) is skipped: both amd64 and arm64 are required', async () => {
    const odd = (image: string): HubTag[] => (image === 'redis'
      ? [tagRow('7.4.5', 10, [{ architecture: 'amd64', os: 'linux' }, { architecture: '386', os: 'linux' }]), tagRow('7.4.4', 10, [{ architecture: 'amd64', os: 'linux' }, { architecture: 'arm', os: 'linux' }]), tagRow('7.4.3', 10, [{ architecture: 'arm64', os: 'linux' }, { architecture: 'amd64', os: 'windows' }]), tagRow('7.4.2', 10, [{ architecture: 'arm64', os: 'linux' }, { architecture: 'amd64', os: 'linux' }, { architecture: '386', os: 'linux' }])]
      : hubFor(image));
    const out = await refreshBaseImages(harness({ rows: odd }).deps as never);
    const redis = out.entries.find((e) => e.id === 'redis-7');
    expect(redis?.tag).toBe('7.4.2');
    expect(redis?.platforms).toEqual(['linux/386', 'linux/amd64', 'linux/arm64']);
  });

  it('pages through the Docker Hub list and ignores a tag whose list is single-platform or absent', async () => {
    const many = (image: string): HubTag[] => (image === 'redis' ? [...Array.from({ length: 150 }, (_, i) => tagRow(`7.4.${200 - i}-alpine`, 20)), tagRow('7.4.5', 10, [{ architecture: 'amd64', os: 'linux' }]), tagRow('7.4.4', 20)] : hubFor(image));
    const h = harness({ rows: many });
    const out = await refreshBaseImages(h.deps as never);
    expect(out.entries.find((e) => e.id === 'redis-7')?.tag).toBe('7.4.4');
    expect(h.calls.filter((c) => c.url.pathname.endsWith('/redis/tags')).length).toBeGreaterThan(1);
  });

  it('M4: the newest tag wins whatever order Docker Hub lists the tags in (the version sort is asserted)', async () => {
    const expected = { 'node-22-bookworm-slim': '22.20.1-bookworm-slim', 'node-24-bookworm-slim': '24.10.2-bookworm-slim', 'node-26-bookworm-slim': '26.0.3-bookworm-slim', 'postgres-17': '17.6', 'mysql-8.4': '8.4.6', 'redis-7': '7.4.5', 'mongo-8.0': '8.0.11', 'rabbitmq-4-management': '4.1.3-management' };
    const orders: ((r: HubTag[]) => HubTag[])[] = [(r) => [...r].reverse(), (r) => [...r].sort((a, b) => a.name.localeCompare(b.name))];
    for (const order of orders) {
      const out = await refreshBaseImages(harness({ rows: (image) => order(hubFor(image)) }).deps as never);
      expect(Object.fromEntries(out.entries.map((e) => [e.id, e.tag]))).toEqual(expected);
    }
    // 10 sorts after 9 as a number, not as text
    const ten = (image: string): HubTag[] => (image === 'redis' ? [tagRow('7.4.9', 10), tagRow('7.4.10', 10), tagRow('7.4.2', 10)] : hubFor(image));
    expect((await refreshBaseImages(harness({ rows: ten }).deps as never)).entries.find((e) => e.id === 'redis-7')?.tag).toBe('7.4.10');
  });

  it('M4: every skipped tag and its reason goes into the notes (main prints them)', async () => {
    const h = harness({ reject: (r) => r === 'node:24.10.2-bookworm-slim' });
    const out = await refreshBaseImages(h.deps as never);
    expect(out.entries.find((e) => e.id === 'node-24-bookworm-slim')?.tag).toBe('24.10.1-bookworm-slim');
    expect(out.notes.some((n) => n.includes('24.10.2-bookworm-slim: Docker Hub says that moved less than 7 days ago'))).toBe(true);
    const text = readFileSync(new URL('../scripts/base-images.ts', import.meta.url), 'utf8');
    expect(text).toMatch(/for \(const n of out\.notes\) console\.log/);
  });
});
