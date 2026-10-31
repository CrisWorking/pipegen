// Refreshes data/base-images.yml (v0.2 Plan D, D2, ruling B3). USES THE NETWORK; run it by hand:
//
//   npm run base-images
//
// (the script imports pipegen's engine, whose files use `.js` import names, so it is bundled first, like the build does).
// For each id in BASE_IMAGE_LINES it reads the image's tag list from Docker Hub, keeps the tags that are an exact patch
// tag of that major/variant (the id's tagRe), pushed at least 7 days ago and listed for more than one platform, takes the
// newest by version, and pins it with resolvePin (the multi-platform index digest, the cooldown on Docker Hub's
// tag_last_pushed, the GHCR refusal). If resolvePin refuses a tag, the next older one is tried (at most 5); if none passes,
// the run fails. It never falls back to a rolling tag. The whole run shares ONE newRateBudget().
//
// It never reviews anything: every written entry says `reviewedBy: PENDING`, and the loader (src/engine/base-images.ts)
// refuses PENDING entries until a human (or the delegated reviewer, DECISIONS 105) replaces the marker in a PR.
// Keep the write path small: the file is written only after every entry resolved.
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Octokit } from '@octokit/rest';
import { stringify } from 'yaml';
import { z } from 'zod';
import { BASE_IMAGE_LINES, type BaseImage } from '../src/engine/base-images.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { COOLDOWN_DAYS, PinError, resolvePin, type PinDeps } from '../src/engine/pin.js';
import { PENDING } from '../src/engine/review-marker.js';
import type { Candidate, InstallSpec } from '../src/types.js';

const DAY_MS = 86_400_000;
const HUB = 'https://hub.docker.com/v2/repositories/library/';
const PAGE_SIZE = 100;
const MAX_PAGES = 30;
const MAX_BODY_BYTES = 8 * 1024 * 1024;
const TIMEOUT_MS = 20_000;
/** How many tags (newest first) resolvePin may refuse before the run gives up on an id. */
const MAX_TRIES = 5;

/** The substring Docker Hub's tag search is asked for; the exact shape is still judged locally by the id's tagRe. */
const HUB_SEARCH: Readonly<Record<string, string>> = {
  'node-22-bookworm-slim': '22.', 'node-24-bookworm-slim': '24.', 'node-26-bookworm-slim': '26.',
  'postgres-17': '17.', 'mysql-8.4': '8.4.', 'redis-7': '7.', 'mongo-8': '8.0.', 'rabbitmq-4-management': '4.',
};

const pageSchema = z.object({
  next: z.string().nullish(),
  results: z.array(z.object({
    name: z.string(),
    tag_last_pushed: z.string().nullish(),
    images: z.array(z.object({ architecture: z.string().nullish(), os: z.string().nullish() })).nullish(),
  })),
});

export interface RefreshDeps {
  fetch: typeof fetch;
  now?: () => number;
  /** Test hook: makes the run's budget. The run calls it exactly once. */
  newBudget?: typeof newRateBudget;
  gh: PinDeps['gh'];
  resolvePin?: typeof resolvePin;
  sleep?: PinDeps['sleep'];
}
export interface RefreshResult { entries: BaseImage[]; platforms: Record<string, string[]>; notes: string[] }

interface Row { tag: string; pushed: number; platforms: string[] }

async function hubTags(f: typeof fetch, image: string, search: string): Promise<{ name: string; tag_last_pushed?: string | null; images?: { architecture?: string | null; os?: string | null }[] | null }[]> {
  const all: z.infer<typeof pageSchema>['results'] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const url = `${HUB}${encodeURIComponent(image)}/tags?${new URLSearchParams({ page_size: String(PAGE_SIZE), ordering: 'last_updated', name: search, page: String(page) })}`;
    const res = await f(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS), redirect: 'error' });
    if (!res.ok) throw new Error(`Docker Hub's tag list for ${image} answered ${res.status}.`);
    const text = await res.text();
    if (text.length > MAX_BODY_BYTES) throw new Error(`Docker Hub's tag list for ${image} is larger than ${MAX_BODY_BYTES} bytes.`);
    const parsed = pageSchema.safeParse(JSON.parse(text));
    if (!parsed.success) throw new Error(`Docker Hub's tag list for ${image} has an unexpected shape.`);
    all.push(...parsed.data.results);
    if (parsed.data.next === null || parsed.data.next === undefined || parsed.data.results.length === 0) break;
  }
  return all;
}

const versionKey = (tag: string): number[] => (/^\d+(?:\.\d+)*/.exec(tag)?.[0] ?? '').split('.').map(Number);
function newerFirst(a: Row, b: Row): number {
  const x = versionKey(a.tag);
  const y = versionKey(b.tag);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (y[i] ?? 0) - (x[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** The refreshed entries (all PENDING), in the order of BASE_IMAGE_LINES. Throws when an id has no tag that passes. */
export async function refreshBaseImages(deps: RefreshDeps): Promise<RefreshResult> {
  const now = deps.now ?? Date.now;
  const pin = deps.resolvePin ?? resolvePin;
  const budget = (deps.newBudget ?? newRateBudget)();   // the one budget of this run, shared by every pin
  const notes: string[] = [];
  const pinDeps: PinDeps = { gh: deps.gh, fetch: deps.fetch, alert: (w) => { notes.push(w.message); }, notes, budget, now, ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }) };
  const pinnedOn = new Date(now()).toISOString();
  const entries: BaseImage[] = [];
  const platforms: Record<string, string[]> = {};
  for (const [id, line] of Object.entries(BASE_IMAGE_LINES)) {
    const rows: Row[] = [];
    for (const r of await hubTags(deps.fetch, line.image, HUB_SEARCH[id] ?? '')) {
      if (!line.tagRe.test(r.name)) continue;
      const pushed = Date.parse(r.tag_last_pushed ?? '');
      if (!Number.isFinite(pushed) || now() - pushed < COOLDOWN_DAYS * DAY_MS) continue;
      const set = [...new Set((r.images ?? []).filter((i) => i.os === 'linux' && typeof i.architecture === 'string' && i.architecture !== 'unknown').map((i) => `linux/${i.architecture as string}`))].sort();
      if (set.length < 2) continue;   // not a multi-platform list (resolvePin checks the registry's own answer as well)
      rows.push({ tag: r.name, pushed, platforms: set });
    }
    rows.sort(newerFirst);
    let done = false;
    const refused: string[] = [];
    for (const row of rows.slice(0, MAX_TRIES)) {
      const install: InstallSpec = { method: 'docker', package: line.image, version: row.tag };
      const cand: Candidate = { id, name: line.image, kind: 'docker', repo: `library/${line.image}`, version: row.tag, pin: {}, source: 'discovery', reviewed: false, categories: [] };
      try {
        const pinned = await pin(cand, pinDeps, install);
        const digest = pinned.pin.digest;
        if (digest === undefined) throw new PinError(`resolvePin gave no digest for ${line.image}:${row.tag}.`);
        entries.push({ id, image: line.image, tag: row.tag, digest, releasedAt: new Date(row.pushed).toISOString(), pinnedOn, reviewedBy: PENDING, reviewedAt: PENDING });
        platforms[id] = row.platforms;
        done = true;
        break;
      } catch (e) {
        if (!(e instanceof PinError)) throw e;
        refused.push(`${row.tag}: ${e.message}`);
      }
    }
    if (!done) throw new Error(`${id}: no exact patch tag of ${line.image} could be pinned (needs a tag matching ${line.tagRe.source}, pushed at least ${COOLDOWN_DAYS} days ago, multi-platform). ${refused.join(' | ')}`.trim());
  }
  return { entries, platforms, notes };
}

const HEADER = `# pipegen's reviewed base-image list (v0.2 Plan D, D2, ruling B3), read by loadBaseImages (src/engine/base-images.ts).
# This file is a trust root, like reviewed-tools.yml: created Dockerfiles and compose files take their base images only
# from here. The AI picks an \`id\`; pipegen writes \`<image>:<tag>@<digest>\`. Nothing is pinned live during a run.
#
#   id          one of BASE_IMAGE_LINES (base-images.ts): an image and its major/variant
#   image       the official Docker Hub image (a bare name; never a registry or namespace)
#   tag         an exact patch tag of that major/variant (never a rolling tag or latest)
#   digest      the digest of that tag's multi-platform index (resolvePin)
#   releasedAt  Docker Hub's tag_last_pushed; at least 7 days before pinnedOn (ruling S26)
#   pinnedOn    when scripts/base-images.ts pinned it
#   reviewedBy / reviewedAt  the human review (review-marker.ts). The refresh script writes PENDING and the loader
#               refuses PENDING in every build, so a refreshed list always needs a review before it is used.
#
# Refresh: see scripts/base-images.ts. Then review every tag and digest and set reviewedBy and reviewedAt in a PR.
`;

/** The text of data/base-images.yml for a list of entries. */
export function renderBaseImagesYaml(entries: readonly BaseImage[]): string {
  return `${HEADER}\n${stringify({ images: entries }, { lineWidth: 0 })}`;
}

async function main(): Promise<number> {
  const gh = new Octokit({ request: { fetch } });   // no credential: image pins use the registries' anonymous tokens
  const out = await refreshBaseImages({ fetch, gh });
  writeFileSync(resolve('data/base-images.yml'), renderBaseImagesYaml(out.entries));
  for (const e of out.entries) console.log(`${e.id}\t${e.image}:${e.tag}\t${e.digest}\treleasedAt ${e.releasedAt}\t${out.platforms[e.id]?.join(',')}`);
  for (const n of out.notes) console.log(`note: ${n}`);
  return 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; }, (e: unknown) => { console.error(e instanceof Error ? e.message : String(e)); process.exitCode = 1; });
}
