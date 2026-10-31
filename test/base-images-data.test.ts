// D2 (ruling B3): the REAL data/base-images.yml passes the loader and the pre-flight shape tests.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { BASE_IMAGE_LINES, baseImageIds, baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { REVIEWER_RE } from '../src/engine/review-marker.js';
import { packageDataPath } from '../src/util/package-data.js';

const DAY = 86_400_000;

describe('base-images (data file)', () => {
  const real = loadBaseImages();
  it('base-images: every entry an exact patch tag + multi-platform index digest, pinnedOn, releasedAt ≥ 7 days before pinnedOn, reviewedBy REVIEWER_RE', () => {
    expect(real.length).toBeGreaterThanOrEqual(8);
    for (const e of real) {
      expect(e.tag, e.id).toMatch(BASE_IMAGE_LINES[e.id]!.tagRe);
      expect(e.tag, e.id).not.toMatch(/latest/);
      expect(e.digest, e.id).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(Date.parse(e.pinnedOn) - Date.parse(e.releasedAt), e.id).toBeGreaterThanOrEqual(7 * DAY);
      expect(e.reviewedBy, e.id).toMatch(REVIEWER_RE);
      expect(e.reviewedBy, e.id).toBe('Claude delegated DECISIONS 105');
      expect(e.reviewedAt >= e.pinnedOn.slice(0, 10), e.id).toBe(true);
      expect(e.platforms, e.id).toEqual(expect.arrayContaining(['linux/amd64', 'linux/arm64']));
    }
    // the raw file: no unknown keys, ids unique, and the data file is the one the loader reads
    const raw = parse(readFileSync(packageDataPath('base-images.yml'), 'utf8')) as { images: Record<string, unknown>[] };
    expect(raw.images.map((e) => e.id)).toEqual(real.map((e) => e.id));
    expect(new Set(real.map((e) => e.id)).size).toBe(real.length);
  });

  it('base-images: postgres/mysql/redis/mongo/rabbitmq rows present', () => {
    const byId = new Map(real.map((e) => [e.id, e]));
    for (const [id, image, re] of [
      ['postgres-17', 'postgres', /^17\.\d+$/], ['mysql-8.4', 'mysql', /^8\.4\.\d+$/], ['redis-7', 'redis', /^7\.\d+\.\d+$/],
      ['mongo-8.0', 'mongo', /^8\.0\.\d+$/], ['rabbitmq-4-management', 'rabbitmq', /^4\.\d+\.\d+-management$/],
    ] as const) {
      expect(byId.get(id)?.image, id).toBe(image);
      expect(byId.get(id)?.tag, id).toMatch(re);
    }
    for (const v of [22, 24, 26]) expect(byId.get(`node-${v}-bookworm-slim`)?.tag).toMatch(new RegExp(`^${v}\\.\\d+\\.\\d+-bookworm-slim$`));
    expect(baseImageIds().sort()).toEqual(Object.keys(BASE_IMAGE_LINES).sort());
  });

  it('the live data file passes the loader and every ref has the exact <image>:<tag>@sha256:<digest> form', () => {
    for (const e of real) expect(baseImageRef(e.id)).toBe(`${e.image}:${e.tag}@${e.digest}`);
  });
});

