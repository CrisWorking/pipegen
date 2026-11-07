// The cooldown against the REAL data/reviewed-tools.yml and data/pinned-binaries.yml (as on a first release, where
// everything is new). The test walks the data by itself (not through scripts/cooldown.ts), builds a fake upstream from
// it (registry, PyPI, GitHub, Docker Hub) that agrees with every pin and is old, then proves that:
//   - the whole real data passes against that upstream;
//   - every pinned artifact is looked at: with every upstream date young, each one is reported;
//   - every pinned artifact is tied to its own exact hash and its own date: changing that one artifact's upstream hash,
//     or making only its date young, fails the check and names its entry.
// So a field the script misreads (a checksum read from the wrong place, a plugin or platform skipped) fails here.
// The walker itself could miss a new pin field, so it is not trusted alone (review M1): the artifact count is fixed,
// and a scan of the RAW YAML text (not the parsed walk) finds every hash- or URL-shaped value outside comments and
// requires each to be one of the walked artifacts or on a short, explained allowlist. A new pin field fails here
// until it is walked (and the script checks it) or deliberately allowlisted.
import { createHash } from 'node:crypto';
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
  | { type: 'docker'; owner: string; image: string; tag: string; digest: string }
  /** An archive a tool downloads at run time, pinned in step.cli.env (nuclei templates: a release tag's tarball). */
  | { type: 'templates'; owner: string; url: string; tag: string; sha256: string; commit: string; tree: string }
  /** semgrep rules: a repo archive at a commit, tied by the commit's tree. */
  | { type: 'rules'; owner: string; url: string; repo: string; commit: string; tree: string };

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
    // pipegen's own gate action is not dated or tied to a release (C6: the cooldown skips the exact repo crisworking/pipegen); tested in gate-entry.test.ts
    if (c.kind === 'action' && c.repo === 'crisworking/pipegen') continue;
    if (c.kind === 'action') out.push({ type: 'action', owner: t.id, repo: c.repo, tag: c.version, sha: c.pin.sha });
    else if (c.kind === 'docker') out.push({ type: 'docker', owner: t.id, image: inst.package, tag: inst.version, digest: c.pin.digest });
    else if (c.kind === 'cli' && inst.method === 'github-release') out.push({ type: 'asset', owner: t.id, repo: c.repo, tag: inst.version, asset: inst.package, sha256: c.pin.checksum });
    else if (c.kind === 'cli') out.push(pkg(t.id, inst, c.pin.checksum));
    else throw new Error(`${t.id}: kind ${c.kind} is not known to this test`);
    for (const p of (t.step?.cli?.plugins ?? []) as Obj[]) out.push(pkg(t.id, p, p.checksum));
    const env = (t.step?.cli?.env ?? {}) as Obj;
    if (env.PIPEGEN_NUCLEI_TEMPLATES_URL) {
      const m = /\/(v\d+\.\d+\.\d+)\.tar\.gz$/.exec(env.PIPEGEN_NUCLEI_TEMPLATES_URL);
      out.push({ type: 'templates', owner: t.id, url: env.PIPEGEN_NUCLEI_TEMPLATES_URL, tag: m?.[1] as string, sha256: env.PIPEGEN_NUCLEI_TEMPLATES_SHA256, commit: env.PIPEGEN_NUCLEI_TEMPLATES_COMMIT, tree: env.PIPEGEN_NUCLEI_TEMPLATES_TREE });
    }
    if (env.PIPEGEN_RULES_URL) {
      const m = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/archive\/([0-9a-f]{40})\.tar\.gz$/.exec(env.PIPEGEN_RULES_URL);
      out.push({ type: 'rules', owner: t.id, url: env.PIPEGEN_RULES_URL, repo: m?.[1] as string, commit: m?.[2] as string, tree: env.PIPEGEN_RULES_TREE });
    }
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
  if (a.type === 'templates') return `${a.owner}: nuclei templates ${a.tag}`;
  if (a.type === 'rules') return `${a.owner}: semgrep rules ${a.commit}`;
  return `${a.owner}: image ${a.image}:${a.tag}`;
};
/** The finding that must name this artifact: its own package or archive item, or its entry's main item. */
const names = (a: Artifact, name: string): boolean => {
  if (a.type === 'npm' || a.type === 'pypi') return name.startsWith(`${a.owner} (`) && name.endsWith(` ${a.name})`);
  if (a.type === 'templates') return name === `${a.owner} (nuclei templates)`;
  if (a.type === 'rules') return name === `${a.owner} (semgrep rules)`;
  return name === a.owner;
};
const sha256 = (t: string): string => createHash('sha256').update(t).digest('hex');
const NT = 'projectdiscovery/nuclei-templates';

/** The fake upstream for the artifacts: each one agrees with its pin, dated `dateOf(a)`, hashed `hashOf(a)`. */
function upstream(dateOf: (a: Artifact) => string, hashOf: (a: Artifact, pinned: string) => string, extra: Record<string, unknown> = {}): { fetch: typeof fetch; calls: string[] } {
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
    } else if (a.type === 'templates') {
      // the release's checksums file lists the tag archive's sha256 (as on pin day); GitHub records the file's digest
      const ver = a.tag.slice(1);
      const sumsName = `nuclei-templates-${ver}_checksums.txt`;
      const sumsUrl = `https://github.com/${NT}/releases/download/${a.tag}/${sumsName}`;
      const text = `${hashOf(a, a.sha256)}  nuclei-templates-${ver}.tar.gz\n`;
      routes.set(sumsUrl, { text });
      // the tag's commit, on the repo's default branch (P44)
      const tagCommit = a.commit;
      routes.set(gh(`${NT}/git/commits/${tagCommit}`), { sha: tagCommit, tree: { sha: hashOf(a, a.tree) } });
      routes.set(gh(`${NT}/git/ref/tags/${a.tag}`), { object: { type: 'commit', sha: tagCommit } });
      routes.set(gh(NT), { default_branch: 'main' });
      routes.set(gh(`${NT}/compare/${tagCommit}...main?per_page=1`), { status: 'ahead', behind_by: 0, merge_base_commit: { sha: tagCommit } });
      routes.set(gh(`${NT}/releases/tags/${a.tag}`), { tag_name: a.tag, published_at: at, assets: [{ name: sumsName, browser_download_url: sumsUrl, digest: `sha256:${sha256(text)}`, created_at: OLD, updated_at: OLD }] });
    } else if (a.type === 'rules') {
      routes.set(gh(`${a.repo}/git/commits/${a.commit}`), { sha: a.commit, tree: { sha: hashOf(a, a.tree) }, committer: { date: OLD }, verification: { verified: true, reason: 'valid', verified_at: at } });
      routes.set(gh(a.repo), { default_branch: 'develop' });
      routes.set(gh(`${a.repo}/compare/${a.commit}...develop?per_page=1`), { status: 'ahead', behind_by: 0, merge_base_commit: { sha: a.commit } });
    } else {
      const [ns, name] = a.image.includes('/') ? a.image.split('/') : ['library', a.image];
      merge(`https://hub.docker.com/v2/repositories/${ns}/${name}/tags/${a.tag}`, () => ({ digest: a.digest }), (doc) => {
        if (hashOf(a, a.digest) !== a.digest) doc.digest = hashOf(a, a.digest);
        doc.tag_last_pushed = younger(doc.tag_last_pushed, at);
      });
    }
  }
  // pipegen's own gate action: no age, but its pin is tied to the tag gate-v<version> of the repo (C6 fix round 1)
  for (const t of (parse(FILES['data/reviewed-tools.yml']) as Obj).tools as Obj[]) {
    if (t.candidate.kind === 'action' && t.candidate.repo === 'crisworking/pipegen') routes.set(gh(`${t.candidate.repo}/git/ref/tags/gate-v${t.candidate.version}`), { ref: `refs/tags/gate-v${t.candidate.version}`, object: { type: 'commit', sha: t.candidate.pin.sha } });
  }
  for (const [k, v] of Object.entries(extra)) routes.set(k, v);
  const calls: string[] = [];
  const f = (async (url: string) => {
    calls.push(String(url));
    const body = routes.get(String(url)) as Obj | undefined;
    if (body === undefined) return new Response('{}', { status: 404 });
    return new Response(typeof body.text === 'string' && Object.keys(body).length === 1 ? body.text : JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
  return { fetch: f, calls };
}

const same = (_a: Artifact, pinned: string): string => pinned;
/** A different value of the same shape (so only the value, not the format, is wrong). */
const flip = (pinned: string): string => pinned.replace(/[0-9a-f](?=[^0-9a-f]*$)/i, (c) => (c === '0' ? '1' : '0'));
// The first release: everything is new, so the cap is raised as release-check does.
const check = (f: typeof fetch, head: Record<string, string> = FILES, base: Record<string, string> = {}): Promise<CooldownResult> =>
  runCooldown({ base, head, fetch: f, now: NOW, maxLookups: 3000 });
const lines = (r: CooldownResult): string => r.findings.map((f) => `${f.name}: ${f.problem}`).join('\n');

describe('cooldown: the real data', () => {
  it('walks every entry and finds pins of every kind; the count is fixed, so a change to it is deliberate', () => {
    const kinds = new Set(ALL.map((a) => a.type));
    expect([...kinds].sort()).toEqual(['action', 'asset', 'docker', 'npm', 'pypi', 'rules', 'templates']);
    // 14 actions, 4 images (G15a round 6: zap-af-active, the same pinned image as zap-baseline), 21 release assets (G15a: gh), 8 npm tools + 6 npm plugins, 6 pip tools + 2 pip plugins,
    // 20 pinned-binary platforms, the nuclei templates archive and the semgrep rules archive
    const count = (t: Artifact['type']) => ALL.filter((a) => a.type === t).length;
    expect({ action: count('action'), docker: count('docker'), asset: count('asset'), npm: count('npm'), pypi: count('pypi'), templates: count('templates'), rules: count('rules') })
      .toEqual({ action: 14, docker: 4, asset: 41, npm: 16, pypi: 8, templates: 1, rules: 1 });
    expect(ALL).toHaveLength(85);
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
        : a.type === 'templates' ? `https://api.github.com/repos/${NT}/releases/tags/${a.tag}`
        : a.type === 'rules' ? `https://api.github.com/repos/${a.repo}/git/commits/${a.commit}`
        : `https://api.github.com/repos/${a.repo}/releases/tags/${a.tag}`;
      expect(up.calls.some((c) => c.includes(want)), label(a)).toBe(true);
    }
  });

  it('with every upstream date young, every entry and every package is reported young', async () => {
    const r = await check(upstream(() => YOUNG, same).fetch);
    expect(r.ok).toBe(false);
    expect(r.findings.every((f) => f.young), lines(r)).toBe(true);
    for (const a of ALL) {
      expect(r.findings.some((f) => names(a, f.name)), label(a)).toBe(true);
    }
  });

  it('each artifact is tied to its own exact hash: changing only its upstream hash fails and names it', async () => {
    for (const target of ALL) {
      const r = await check(upstream(() => OLD, (a, pinned) => (a === target ? flip(pinned) : pinned)).fetch);
      expect(r.ok, label(target)).toBe(false);
      expect(r.findings.some((f) => names(target, f.name)), `${label(target)}\n${lines(r)}`).toBe(true);
      expect(r.findings.every((f) => !f.young), label(target)).toBe(true);
    }
  });

  it('each artifact is tied to its own date: making only its date young fails and names it', async () => {
    for (const target of ALL) {
      const r = await check(upstream((a) => (a === target ? YOUNG : OLD), same).fetch);
      expect(r.ok, label(target)).toBe(false);
      expect(r.findings.some((f) => f.young && names(target, f.name)), `${label(target)}\n${lines(r)}`).toBe(true);
    }
  });

  it('every hash- or URL-shaped value in the raw YAML (outside comments) is a walked artifact or explicitly allowed', () => {
    const covered = new Set<string>();
    for (const a of ALL) {
      if (a.type === 'npm') covered.add(a.integrity);
      else if (a.type === 'pypi' || a.type === 'asset') covered.add(a.sha256);
      else if (a.type === 'action') covered.add(a.sha);
      else if (a.type === 'docker') covered.add(a.digest);
      else if (a.type === 'templates') covered.add(a.url).add(a.sha256).add(a.commit).add(a.tree);
      else covered.add(a.url).add(a.commit).add(a.tree);
    }
    for (const [, b] of Object.entries(parse(FILES['data/pinned-binaries.yml']) as Obj)) for (const p of Object.values(b.platforms as Obj)) covered.add(p.url);
    // Allowed, not pins this check dates (each explained in docs/cooldown.md):
    const allowed = new Set<string>();
    for (const t of (parse(FILES['data/reviewed-tools.yml']) as Obj).tools as Obj[]) {
      // pipegen's own gate action: its pin is a commit of this repository (not dated by the cooldown, see gate-entry.test.ts)
      if (t.candidate.repo === 'crisworking/pipegen') allowed.add(t.candidate.pin.sha);
      // pin-time verification inputs (cosign identity/issuer, key URL and its sha256), never installed
      for (const v of Object.values((t.verifiedWith ?? {}) as Obj)) if (typeof v === 'string') allowed.add(v);
      // a record of the image an action's own action.yml runs; the action is tied by its commit SHA
      if (t.wrappedImage?.digest) allowed.add(t.wrappedImage.digest);
      // the sha256 of GitHub's archive of the pinned rules commit. The commit (upstream's, on its default branch) and its
      // tree are tied and dated, so these bytes can't hold other rules; checking them on download is a requirement on
      // the renderer (v0.2, not written yet: docs/cooldown.md), not something this check or today's code does
      if (t.step?.cli?.env?.PIPEGEN_RULES_SHA256) allowed.add(t.step.cli.env.PIPEGEN_RULES_SHA256);
    }
    // the hash of the binary inside a pinned archive; the archive's own sha256 is tied above
    for (const [, b] of Object.entries(parse(FILES['data/pinned-binaries.yml']) as Obj)) for (const p of Object.values(b.platforms as Obj)) allowed.add(p.binarySha256);
    // a scheme, `://` and the rest of a URL; built from parts so this line itself does not read as a URL
    const URL_LIKE = ['[a-z][a-z0-9+.-]*', ':', '\\/\\/', `[^\\s"',)}\\]]+`].join('');
    const PIN_LIKE = new RegExp(['sha512-[A-Za-z0-9+/]+=*', 'sha256:[0-9a-f]{64}', URL_LIKE, '\\b[0-9a-f]{64}\\b', '\\b[0-9a-f]{40}\\b'].join('|'), 'gi');
    let seen = 0;
    for (const [file, text] of Object.entries(FILES)) {
      text.split('\n').forEach((raw, i) => {
        if (/^\s*#/.test(raw)) return;
        // drop a trailing comment (a ` #` outside quotes)
        let line = raw;
        let quote = '';
        for (let k = 0; k < raw.length; k++) {
          const c = raw[k] as string;
          if (quote) { if (c === '\\') k++; else if (c === quote) quote = ''; }
          else if (c === '"' || c === "'") quote = c;
          else if (c === '#' && (k === 0 || /\s/.test(raw[k - 1] as string))) { line = raw.slice(0, k); break; }
        }
        for (const m of line.matchAll(PIN_LIKE)) {
          seen++;
          const v = m[0].replace(/\.$/, '');
          // a hex40 inside a covered URL (the rules commit) or a pinned uses: owner/repo@sha is that value itself
          expect(covered.has(v) || allowed.has(v), `${file}:${i + 1}: ${v}`).toBe(true);
        }
      });
    }
    expect(seen).toBeGreaterThan(ALL.length);
  });

  // The reviewer's probes (review I1, M2), on the real data.
  const realBase = { 'data/reviewed-tools.yml': FILES['data/reviewed-tools.yml'] };
  it('probe I1: moving the nuclei templates to a new tag and sha256 fails (nothing else changed)', async () => {
    const t = FILES['data/reviewed-tools.yml'];
    const head = t.replaceAll('nuclei-templates/archive/refs/tags/v10.5.0.tar.gz', 'nuclei-templates/archive/refs/tags/v10.9.9.tar.gz')
      .replaceAll('80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41', '0'.repeat(64));
    expect(head).not.toBe(t);
    const r = await check(upstream(() => OLD, same).fetch, { 'data/reviewed-tools.yml': head }, realBase);
    expect(r.ok).toBe(false);
    expect(r.findings.map((f) => f.name)).toEqual(['nuclei (nuclei templates)']);
  });

  it('probe I1b: moving the semgrep rules to another commit fails', async () => {
    const t = FILES['data/reviewed-tools.yml'];
    const head = t.replaceAll('semgrep-rules/archive/17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9', `semgrep-rules/archive/${'a'.repeat(40)}`);
    expect(head).not.toBe(t);
    const r = await check(upstream(() => OLD, same).fetch, { 'data/reviewed-tools.yml': head }, realBase);
    expect(r.findings.map((f) => f.name)).toEqual(['semgrep (semgrep rules)']);
  });

  // The re-review's probe2 (P44): a signed commit of the attacker's, verified long ago, with its own tree and sha256.
  const UP_SHA = '17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9';
  const UP_TREE = 'dd3179667faf14717e05c33b1916b0d2c349673d';
  const UP_SUM = '9dfe6866fbecd557f507078cb79721a9eb8f4764fc2f6163648ea1320be25933';
  const EVIL_SHA = 'e'.repeat(40);
  const EVIL_TREE = 'f'.repeat(40);
  const evilCommit = { sha: EVIL_SHA, tree: { sha: EVIL_TREE }, verification: { verified: true, reason: 'valid', verified_at: OLD } };
  const gh = (p: string): string => `https://api.github.com/repos/${p}`;

  it('probe2 C: the rules moved to the attacker\'s own repo (own signed commit, tree and sha256) fail', async () => {
    const t = FILES['data/reviewed-tools.yml'];
    const head = t.replaceAll(`semgrep/semgrep-rules/archive/${UP_SHA}`, `attacker/rules/archive/${EVIL_SHA}`).replaceAll(UP_TREE, EVIL_TREE).replaceAll(UP_SUM, '2'.repeat(64));
    expect(head).not.toBe(t);
    const extra = { [gh(`attacker/rules/git/commits/${EVIL_SHA}`)]: evilCommit, [gh('attacker/rules')]: { default_branch: 'main' }, [gh(`attacker/rules/compare/${EVIL_SHA}...main?per_page=1`)]: { status: 'ahead', behind_by: 0, merge_base_commit: { sha: EVIL_SHA } } };
    const r = await check(upstream(() => OLD, same, extra).fetch, { 'data/reviewed-tools.yml': head }, realBase);
    expect(r.findings.map((f) => `${f.name}: ${f.problem}`)).toEqual(['semgrep (semgrep rules): PIPEGEN_RULES_URL is not https://github.com/semgrep/semgrep-rules/archive/<40-character commit SHA>.tar.gz; needs owner review']);
  });

  it('probe2 D: a fork\'s commit served under the upstream URL (forks share objects) fails', async () => {
    const t = FILES['data/reviewed-tools.yml'];
    const head = t.replaceAll(UP_SHA, EVIL_SHA).replaceAll(UP_TREE, EVIL_TREE).replaceAll(UP_SUM, '3'.repeat(64));
    expect(head).not.toBe(t);
    // GitHub answers for the fork's commit under semgrep/semgrep-rules; only the compare with develop tells it apart
    for (const cmp of [{ status: 'diverged', behind_by: 4, merge_base_commit: { sha: UP_SHA } }, 404]) {
      const extra = { [gh(`semgrep/semgrep-rules/git/commits/${EVIL_SHA}`)]: evilCommit, ...(typeof cmp === 'object' ? { [gh(`semgrep/semgrep-rules/compare/${EVIL_SHA}...develop?per_page=1`)]: cmp } : {}) };
      const r = await check(upstream(() => OLD, same, extra).fetch, { 'data/reviewed-tools.yml': head }, realBase);
      expect(r.ok, JSON.stringify(cmp)).toBe(false);
      expect(r.findings.map((f) => f.name)).toEqual(['semgrep (semgrep rules)']);
      // a diverged compare says why; a 404 compare is a failed lookup (it proves nothing either way)
      expect(lines(r)).toContain(typeof cmp === 'object' ? 'not on the default branch' : 'lookup failed');
    }
  });

  it('probe M2: a changed duplicate of an entry placed before the unchanged original fails', async () => {
    const t = FILES['data/reviewed-tools.yml'];
    const start = t.indexOf('  - id: nuclei\n');
    const end = t.indexOf('\n  - id: ', start + 10);
    const evil = t.slice(start, end + 1).replaceAll('v3.11.1', 'v3.99.0').replaceAll('nuclei_3.11.1', 'nuclei_3.99.0');
    const head = t.slice(0, start) + evil + t.slice(start);
    const r = await check(upstream(() => OLD, same).fetch, { 'data/reviewed-tools.yml': head }, realBase);
    expect(r.ok).toBe(false);
    expect(lines(r)).toContain('more than once');
  });
});
