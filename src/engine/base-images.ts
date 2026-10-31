// pipegen's reviewed base-image list (v0.2 Plan D, D2, ruling B3), read from data/base-images.yml.
//
// A created Dockerfile or compose file needs base images. An image the AI names is an unreviewed tool by another name,
// and a rolling tag (`node:24`, `postgres:17`) is re-pushed so often that pinning it live fails on most days. So the AI
// chooses only a list id (baseImageIds(): an enum for its schema), and pipegen writes every `FROM` / `image:` itself as
// `<image>:<tag>@sha256:<digest>` from this list (baseImageRef). Nothing is pinned live during a run.
//
// One entry per (image, major/variant), with an exact patch tag and the digest of its multi-platform index, filled by
// scripts/base-images.ts through resolvePin (cooldown and GHCR refusal intact). Like the other trust-root data files,
// each entry carries a human-review marker (review-marker.ts). Unlike them, a PENDING entry is refused in dev and test
// builds too: a refreshed list is never usable until somebody has reviewed it.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { z } from 'zod';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { DIGEST_RE } from './names.js';
import { COOLDOWN_DAYS } from './pin.js';
import { mapNodeVersion } from './render-step.js';
import { PENDING, reviewMarkerProblems } from './review-marker.js';

export class BaseImageError extends Error {
  constructor(message: string) {
    super(safeText(message, 600));
    this.name = 'BaseImageError';
  }
}

/** What each list id stands for: its official Docker Hub image and the exact shape of its tag (the major/variant is part of the shape). */
export interface BaseImageLine { image: string; tagRe: RegExp }
/**
 * The ids pipegen offers, in file order. `tagRe` demands a fully specified version for the id's major (X.Y.Z; PostgreSQL
 * numbers its releases X.Y) and the variant suffix, so a rolling tag (`22-bookworm-slim`, `latest`) never matches.
 */
const LINES: Record<string, BaseImageLine> = {
  'node-22-bookworm-slim': { image: 'node', tagRe: /^22\.\d+\.\d+-bookworm-slim$/ },
  'node-24-bookworm-slim': { image: 'node', tagRe: /^24\.\d+\.\d+-bookworm-slim$/ },
  'node-26-bookworm-slim': { image: 'node', tagRe: /^26\.\d+\.\d+-bookworm-slim$/ },
  'postgres-17': { image: 'postgres', tagRe: /^17\.\d+$/ },
  'mysql-8.4': { image: 'mysql', tagRe: /^8\.4\.\d+$/ },
  'redis-7': { image: 'redis', tagRe: /^7\.\d+\.\d+$/ },
  // 8.0.x only: 8.1 and later minors are MongoDB rapid releases, not the stable line
  'mongo-8': { image: 'mongo', tagRe: /^8\.0\.\d+$/ },
  'rabbitmq-4-management': { image: 'rabbitmq', tagRe: /^4\.\d+\.\d+-management$/ },
};
for (const line of Object.values(LINES)) Object.freeze(line);
export const BASE_IMAGE_LINES: Readonly<Record<string, BaseImageLine>> = Object.freeze(LINES);

const DAY_MS = 86_400_000;
/** A bare official Docker Hub image name: lower case words joined by `.`, `_` or `-`; no registry, namespace, tag or digest. */
const BARE_NAME_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const lineOf = (id: string): BaseImageLine | undefined => (Object.hasOwn(BASE_IMAGE_LINES, id) ? BASE_IMAGE_LINES[id] : undefined);

const entrySchema = z.object({
  id: z.string(),
  /** A bare official Docker Hub image name (`node`): never a registry, a namespace, a tag or a digest. */
  image: z.string(),
  tag: z.string().max(128),
  /** The digest of the tag's multi-platform index. */
  digest: z.string().regex(DIGEST_RE, 'digest must be sha256:<64 lower-case hex>'),
  releasedAt: z.string().regex(ISO_DATE_RE),
  /** When the entry was pinned; releasedAt must be at least the cooldown before it (ruling S26). */
  pinnedOn: z.string().regex(ISO_DATE_RE),
  reviewedBy: z.string().max(100),
  reviewedAt: z.string().max(20),
}).strict().superRefine((e, ctx) => {
  const line = lineOf(e.id);
  if (line === undefined) { ctx.addIssue({ code: 'custom', path: ['id'], message: `id isn't one of pipegen's base-image ids (${Object.keys(BASE_IMAGE_LINES).join(', ')})` }); return; }
  if (!BARE_NAME_RE.test(e.image)) ctx.addIssue({ code: 'custom', path: ['image'], message: 'image must be an official Docker Hub image (a bare name such as node; no registry, namespace, tag or digest)' });
  else if (e.image !== line.image) ctx.addIssue({ code: 'custom', path: ['image'], message: `image must be ${line.image} for id ${e.id}` });
  if (!line.tagRe.test(e.tag)) ctx.addIssue({ code: 'custom', path: ['tag'], message: `tag must be an exact patch tag matching ${line.tagRe.source} (no rolling tag, no latest)` });
  if (!(Date.parse(e.pinnedOn) - Date.parse(e.releasedAt) >= COOLDOWN_DAYS * DAY_MS)) {
    ctx.addIssue({ code: 'custom', path: ['pinnedOn'], message: `releasedAt must be at least ${COOLDOWN_DAYS} days before pinnedOn (cooldown, ruling S26)` });
  }
  if (e.reviewedBy === PENDING || e.reviewedAt === PENDING) {
    ctx.addIssue({ code: 'custom', path: ['reviewedBy'], message: 'the entry is PENDING: a refreshed entry needs a review (reviewedBy, reviewedAt) before it can be used' });
  } else {
    for (const p of reviewMarkerProblems(e.reviewedBy, e.reviewedAt, e.pinnedOn.slice(0, 10))) ctx.addIssue({ code: 'custom', path: [p.field], message: p.message });
  }
});

export type BaseImage = z.infer<typeof entrySchema>;
const fileSchema = z.object({ images: z.array(entrySchema).min(1).max(64) }).strict();

/** Checks a parsed `images` list (or the whole file object) and returns the entries; throws BaseImageError listing every problem. */
export function parseBaseImages(raw: unknown): BaseImage[] {
  const doc = Array.isArray(raw) ? { images: raw } : raw;
  const res = fileSchema.safeParse(doc);
  if (!res.success) {
    const items = Array.isArray((doc as { images?: unknown } | null)?.images) ? ((doc as { images: unknown[] }).images) : [];
    const problems = res.error.issues.map((i) => {
      const at = i.path[0] === 'images' && typeof i.path[1] === 'number' ? items[i.path[1]] : undefined;
      const id = typeof (at as { id?: unknown } | undefined)?.id === 'string' ? (at as { id: string }).id : String(i.path[1] ?? '?');
      return `${id}: ${i.path.slice(2).join('.') || 'entry'}: ${i.message}`;
    });
    throw new BaseImageError(`data/base-images.yml is not valid: ${problems.slice(0, 8).join('; ')}${problems.length > 8 ? ` and ${problems.length - 8} more` : ''}`);
  }
  const seen = new Set<string>();
  for (const e of res.data.images) {
    if (seen.has(e.id)) throw new BaseImageError(`data/base-images.yml has a duplicate id: ${e.id}`);
    seen.add(e.id);
  }
  return Object.freeze(res.data.images.map((e) => Object.freeze(e))) as BaseImage[];   // frozen: a holder of an entry can not change what baseImageRef returns (D2 review M9)
}

let cached: { path: string; list: BaseImage[] } | undefined;

/** Reads and validates data/base-images.yml (found through packageDataPath, ruling S2). */
export function loadBaseImages(path: string = packageDataPath('base-images.yml')): BaseImage[] {
  if (cached?.path === path) return cached.list;
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new BaseImageError(`Couldn't read pipegen's base-image list: ${(e as Error).message}`);
  }
  const list = parseBaseImages(raw);
  cached = { path, list };
  return list;
}

/** The ids the AI may choose from (the enum for its schema). */
export function baseImageIds(list: readonly BaseImage[] = loadBaseImages()): string[] {
  return list.map((e) => e.id);
}

/** `<image>:<tag>@sha256:<digest>` for a list id. An unknown id is an error, never a fallback. */
export function baseImageRef(id: string, list: readonly BaseImage[] = loadBaseImages()): string {
  const e = typeof id === 'string' ? list.find((x) => x.id === id) : undefined;
  if (e === undefined) throw new BaseImageError(`"${safeText(String(id), 60)}" isn't a base-image id in pipegen's reviewed list.`);
  return `${e.image}:${e.tag}@${e.digest}`;
}

/**
 * The list id of the Node image for a repo's own Node version text. The text is never copied anywhere: mapNodeVersion
 * reads its first run of digits and picks one of the majors the list offers (#109), and the answer is a list id. The note
 * (a change of major, or no readable version) is the one mapNodeVersion gives.
 */
export function nodeBaseImageId(runtimeVersion: string | undefined, list: readonly BaseImage[] = loadBaseImages()): { id: string; note?: string } {
  const majors = list.flatMap((e) => /^node-(\d+)-bookworm-slim$/.exec(e.id)?.[1] ?? []);
  if (majors.length === 0) throw new BaseImageError('pipegen\'s base-image list has no Node image.');
  const { version, note } = mapNodeVersion(runtimeVersion, majors);
  const id = `node-${version}-bookworm-slim`;   // version is one of `majors`, so the id is in the list
  return note === undefined ? { id } : { id, note };
}
