// The cooldown against the REAL data/reviewed-tools.yml and data/pinned-binaries.yml (as on a first release, where
// everything is new). The test walks the data by itself (not through scripts/cooldown.ts), builds a fake upstream from
// it (registry, PyPI, GitHub, Docker Hub) that agrees with every pin and is old, then proves that:
//   - the whole real data passes against that upstream;
//   - every pinned artifact is looked at: with every upstream date young, each one is reported;
//   - every pinned artifact is tied to its own exact hash and its own date: changing that one artifact's upstream hash,
//     or making only its date young, fails the check and names its entry.
// So a field the script misreads (a checksum read from the wrong place, a plugin or platform skipped) fails here.
// A data shape this walker doesn't know throws, so new kinds of pins have to be added here (and to the script).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { runCooldown, type CooldownResult } from '../scripts/cooldown.js';

const NOW = new Date('2026-10-29T12:00:00Z');
const daysAgo = (d: number): string => new Date(NOW.getTime() - d * 86_400_000).toISOString();
const OLD = daysAgo(400);
const YOUNG = daysAgo(1);
const FILES = {
  'data/reviewed-tools.yml': readFileSync(new URL('../data/reviewed-tools.yml', import.meta.url), 'utf8'),
  'data/pinned-binaries.yml': readFileSync(new URL('../data/pinned-binaries.yml', import.meta.url), 'utf8'),
};

type Obj = Record<string, any>;
type Artifact =
  | { type: 'npm'; owner: string; name: string; version: string; integrity: string }
  | { type: 'pypi'; owner: string; name: string; version: string; sha256: string }
  | { type: 'action'; owner: string; repo: string; tag: string; sha: string }
  | { type: 'asset'; owner: string; repo: string; tag: string; asset: string; sha256: string }
  | { type: 'docker'; owner: string; image: string; tag: string; digest: string };

/** Every pinned artifact of the two files, read straight from the data. */
function artifacts(): Artifact[] {
  const out: Artifact[] = [];
  const pkg = (owner: string, i: Obj, checksum: string): Artifact => {
    if (i.method === 'npm') return { type: 'npm', owner, name: i.package, version: i.version, integrity: checksum };
    if (i.method === 'pip') return { type: 'pypi', owner, name: i.package, version: i.version, sha256: checksum };
    throw new Error(`${owner}: a package installed by ${i.method} is not known to this test`);
  };
  for (const t of (parse(FILES['data/reviewed-tools.yml']) as Obj).tools as Obj[]) {
    const c = t.candidate;
    const inst = t.step?.cli?.install;
    const before = out.length;
    if (c.kind === 'action') out.push({ type: 'action', owner: t.id, repo: c.repo, tag: c.version, sha: c.pin.sha });
    else if (c.kind === 'docker') out.push({ type: 'docker', owner: t.id, image: inst.package, tag: inst.version, digest: c.pin.digest });
    else if (c.kind === 'cli' && inst.method === 'github-release') out.push({ type: 'asset', owner: t.id, repo: c.repo, tag: inst.version, asset: inst.package, sha256: c.pin.checksum });
    else if (c.kind === 'cli') out.push(pkg(t.id, inst, c.pin.checksum));
    else throw new Error(`${t.id}: kind ${c.kind} is not known to this test`);
    for (const p of (t.step?.cli?.plugins ?? []) as Obj[]) out.push(pkg(t.id, p, p.checksum));
    // wrappedImage (scorecard-action) records the image the action's own action.yml runs; it is not a pin pipegen
    // installs, and the action itself is tied by its commit SHA above.
    expect(out.length, t.id).toBeGreaterThan(before);
  }
  for (const [tool, b] of Object.entries(parse(FILES['data/pinned-binaries.yml']) as Obj)) {
    const plats = Object.entries(b.platforms as Obj);
    expect(plats.length, tool).toBeGreaterThan(0);
    for (const [, p] of plats) {
      const m = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/([^/]+)\/([^/]+)$/.exec(p.url);
      if (!m) throw new Error(`${tool}: url is not a GitHub release asset`);
      out.push({ type: 'asset', owner: tool, repo: m[1] as string, tag: m[2] as string, asset: m[3] as string, sha256: p.archiveSha256 });
    }
  }
  return out;
}

const ALL = artifacts();
const label = (a: Artifact): string => {
  if (a.type === 'npm' || a.type === 'pypi') return `${a.owner}: ${a.type} ${a.name}@${a.version}`;
  if (a.type === 'action') return `${a.owner}: action ${a.repo}@${a.tag}`;
  if (a.type === 'asset') return `${a.owner}: asset ${a.repo}@${a.tag}/${a.asset}`;
  return `${a.owner}: image ${a.image}:${a.tag}`;
};

/** The fake upstream for the artifacts: each one agrees with its pin, dated `dateOf(a)`, hashed `hashOf(a)`. */
function upstream(dateOf: (a: Artifact) => string, hashOf: (a: Artifact, pinned: string) => string): { fetch: typeof fetch; calls: string[] } {
  const routes = new Map<string, unknown>();
  const merge = (url: string, make: () => Obj, add: (doc: Obj) => void): void => {
    if (!routes.has(url)) routes.set(url, make());
    add(routes.get(url) as Obj);
  };
  const gh = (p: string): string => `https://api.github.com/repos/${p}`;
  /** Several artifacts can share one upstream object (trivy's three entries); the youngest date and any changed hash win. */
  const younger = (a: string | undefined, b: string): string => (a === undefined || Date.parse(b) > Date.parse(a) ? b : a);
  for (const a of ALL) {
    const at = dateOf(a);
    if (a.type === 'npm') {
      merge(`https://registry.npmjs.org/${a.name.replace('/', '%2f')}`, () => ({ versions: {}, time: { created: daysAgo(2000) } }), (doc) => {
        const prev = doc.versions[a.version]?.dist.integrity;
        const mine = hashOf(a, a.integrity);
        doc.versions[a.version] = { dist: { integrity: prev !== undefined && prev !== a.integrity ? prev : mine } };
        doc.time[a.version] = younger(doc.time[a.version], at);
      });
    } else if (a.type === 'pypi') {
      merge(`https://pypi.org/pypi/${a.name}/${a.version}/json`, () => ({ urls: [] }), (doc) => {
        const filename = `${a.name}-${a.version}-py3-none-any.whl`;
        const sha = hashOf(a, a.sha256);
        const hit = doc.urls.find((x: Obj) => x.filename === filename);
        if (!hit) doc.urls.push({ filename, digests: { sha256: sha }, upload_time_iso_8601: at });
        else {
          if (sha !== a.sha256) hit.digests.sha256 = sha;
          hit.upload_time_iso_8601 = younger(hit.upload_time_iso_8601, at);
        }
      });
    } else if (a.type === 'action') {
      merge(gh(`${a.repo}/git/ref/tags/${a.tag}`), () => ({ object: { type: 'commit', sha: a.sha } }), (ref) => {
        if (hashOf(a, a.sha) !== a.sha) ref.object.sha = hashOf(a, a.sha);
      });
      merge(gh(`${a.repo}/releases/tags/${a.tag}`), () => ({ tag_name: a.tag, target_commitish: a.sha }), (rel) => {
        rel.published_at = younger(rel.published_at, at);
      });
      routes.set(gh(`${a.repo}/git/commits/${a.sha}`), { committer: { date: OLD } });
    } else if (a.type === 'asset') {
      merge(gh(`${a.repo}/releases/tags/${a.tag}`), () => ({ tag_name: a.tag, published_at: OLD, assets: [] }), (rel) => {
        const url = `https://github.com/${a.repo}/releases/download/${a.tag}/${a.asset}`;
        const hit = rel.assets.find((x: Obj) => x.name === a.asset);
        const digest = `sha256:${hashOf(a, a.sha256)}`;
        if (!hit) rel.assets.push({ name: a.asset, browser_download_url: url, digest, created_at: at, updated_at: at });
        else {
          if (digest !== `sha256:${a.sha256}`) hit.digest = digest;
          hit.updated_at = younger(hit.updated_at, at);
        }
      });
    } else {
      const [ns, name] = a.image.includes('/') ? a.image.split('/') : ['library', a.image];
      merge(`https://hub.docker.com/v2/repositories/${ns}/${name}/tags/${a.tag}`, () => ({ digest: a.digest }), (doc) => {
        if (hashOf(a, a.digest) !== a.digest) doc.digest = hashOf(a, a.digest);
        doc.tag_last_pushed = younger(doc.tag_last_pushed, at);
      });
    }
  }
  const calls: string[] = [];
  const f = (async (url: string) => {
    calls.push(String(url));
    const body = routes.get(String(url));
    return body === undefined ? new Response('{}', { status: 404 }) : new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
  return { fetch: f, calls };
}

const same = (_a: Artifact, pinned: string): string => pinned;
/** A different value of the same shape (so only the value, not the format, is wrong). */
const flip = (pinned: string): string => pinned.replace(/[0-9a-f](?=[^0-9a-f]*$)/i, (c) => (c === '0' ? '1' : '0'));
// The first release: everything is new, so the cap is raised as release-check does.
const check = (f: typeof fetch): Promise<CooldownResult> => runCooldown({ base: {}, head: FILES, fetch: f, now: NOW, maxLookups: 3000 });
const lines = (r: CooldownResult): string => r.findings.map((f) => `${f.name}: ${f.problem}`).join('\n');

describe('cooldown: the real data', () => {
  it('walks every entry and finds pins of every kind', () => {
    const kinds = new Set(ALL.map((a) => a.type));
    expect([...kinds].sort()).toEqual(['action', 'asset', 'docker', 'npm', 'pypi']);
    // each plugin is its own artifact (biome's binary, oxlint's three, bandit's two)
    expect(ALL.filter((a) => a.owner === 'oxlint-typeaware').map((a) => (a.type === 'npm' ? a.name : '')).sort()).toEqual(['@oxlint-tsgolint/linux-x64', '@oxlint/binding-linux-x64-gnu', 'oxlint', 'oxlint-tsgolint']);
  });

  it('passes against an old upstream that agrees with every pin, and asks about every artifact', async () => {
    const up = upstream(() => OLD, same);
    const r = await check(up.fetch);
    expect(lines(r)).toBe('');
    expect(r.ok).toBe(true);
    for (const a of ALL) {
      const want = a.type === 'npm' ? `https://registry.npmjs.org/${a.name.replace('/', '%2f')}`
        : a.type === 'pypi' ? `https://pypi.org/pypi/${a.name}/${a.version}/json`
        : a.type === 'docker' ? `/tags/${a.tag}`
        : `https://api.github.com/repos/${a.repo}/releases/tags/${a.tag}`;
      expect(up.calls.some((c) => c.includes(want)), label(a)).toBe(true);
    }
  });

  it('with every upstream date young, every entry and every package is reported young', async () => {
    const r = await check(upstream(() => YOUNG, same).fetch);
    expect(r.ok).toBe(false);
    expect(r.findings.every((f) => f.young), lines(r)).toBe(true);
    for (const a of ALL) {
      const hit = r.findings.some((f) => (f.name === a.owner || f.name.startsWith(`${a.owner} (`)) && (a.type !== 'npm' && a.type !== 'pypi' ? true : f.name.endsWith(` ${a.name})`)));
      expect(hit, label(a)).toBe(true);
    }
  });

  it('each artifact is tied to its own exact hash: changing only its upstream hash fails and names it', async () => {
    for (const target of ALL) {
      const r = await check(upstream(() => OLD, (a, pinned) => (a === target ? flip(pinned) : pinned)).fetch);
      expect(r.ok, label(target)).toBe(false);
      expect(r.findings.some((f) => f.name === target.owner || f.name.startsWith(`${target.owner} (`)), `${label(target)}\n${lines(r)}`).toBe(true);
      expect(r.findings.every((f) => !f.young), label(target)).toBe(true);
    }
  });

  it('each artifact is tied to its own date: making only its date young fails and names it', async () => {
    for (const target of ALL) {
      const r = await check(upstream((a) => (a === target ? YOUNG : OLD), same).fetch);
      expect(r.ok, label(target)).toBe(false);
      expect(r.findings.some((f) => f.young && (f.name === target.owner || f.name.startsWith(`${target.owner} (`))), `${label(target)}\n${lines(r)}`).toBe(true);
    }
  });
});
