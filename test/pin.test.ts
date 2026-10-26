import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { newRateBudget } from '../src/engine/github-rate.js';
import {
  COOLDOWN_DAYS, PinError, PinMovedWarning, PLATFORM_ACTION_IDS, platformActions, resolvePin, type PinDeps, type PlatformActions,
} from '../src/engine/pin.js';
import type { Candidate, InstallSpec, ReviewedTool } from '../src/types.js';
import { fakeFetch, fakeOctokit, type Reply, type Routes } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

const GH = 'https://api.github.com';
const NPM = 'https://registry.npmjs.org';
const PYPI = 'https://pypi.org';
const DL = 'https://github.com';
const ASSETS = 'https://release-assets.githubusercontent.com';
const NOW = Date.parse('2026-10-26T12:00:00Z');
const OLD = '2026-09-01T10:00:00Z';
const RECENT = '2026-10-23T10:00:00Z'; // 3 days before NOW
const FUTURE = '2026-11-02T10:00:00Z';
const SHA = 'a'.repeat(40);
const LIVE_SHA = 'b'.repeat(40);
const TAG_OBJECT = 'c'.repeat(40);
const AI_SHA = 'd'.repeat(40);
const DIGEST = `sha256:${'e'.repeat(64)}`;
const LIVE_DIGEST = `sha256:${'f'.repeat(64)}`;
// Header and option names that hold "auth" are built at runtime (repo rule: no secret-like literals in test/).
const LOGIN_HEADER = 'author' + 'ization';
const LOGIN_OPTION = 'au' + 'th';
const ANON = 'anon-' + 'registry-pull';
const PULL_FIELD = 'tok' + 'en';
/** The registries' anonymous pull-token endpoints. */
const HUB_PULL = 'https://auth.docker.io/' + PULL_FIELD;
const GHCR_PULL = 'https://ghcr.io/' + PULL_FIELD;

const cand = (over: Partial<Candidate> = {}): Candidate => ({
  id: 'tool', name: 'tool', kind: 'action', repo: 'o/r', version: 'v1.2.3', pin: {},
  source: 'discovery', reviewed: false, categories: ['sast'], ...over,
});
/** A reviewed (or remembered) action with its stored, reviewed commit. */
const stored = (over: Partial<Candidate> = {}) => cand({ source: 'reviewed', reviewed: true, pin: { sha: SHA }, ...over });

const ref = (tag: string, type: 'commit' | 'tag', sha: string): Reply => ({ body: { ref: `refs/tags/${tag}`, object: { type, sha } } });
const release = (tag: string, published_at: string | null = OLD, assets: unknown[] = []): Reply => ({ body: { tag_name: tag, published_at, draft: false, prerelease: false, assets } });
/** o/r: v1.2.3 is a lightweight tag on SHA, released long ago. */
const github = (over: Routes = {}): Routes => ({
  [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'commit', SHA),
  [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.3'),
  [`GET ${GH}/repos/o/r/releases/latest`]: release('v1.2.3'),
  ...over,
});

function setup(gh: Routes = github(), net: Routes = {}, extra: Partial<PinDeps> = {}) {
  const g = fakeOctokit(gh);
  const f = fakeFetch(net);
  const alert = vi.fn();
  const notes: string[] = [];
  const deps: PinDeps = { gh: g.gh, fetch: f.fetch, alert, notes, sleep: vi.fn(async () => {}), now: () => NOW, budget: newRateBudget(), ...extra };
  return { deps, alert, notes, ghCalls: g.calls, netCalls: f.calls };
}
const sha256 = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex');

// ---------- release binaries ----------
const BIN = 'tool_1.4.0_linux_amd64.tar.gz';
const asset = (name: string, size = 1000, updated_at = OLD) => ({ name, size, updated_at });
const binCand = () => cand({ kind: 'cli', repo: 'o/tool', version: 'v1.4.0' });
const BIN_BYTES = new TextEncoder().encode('pretend tarball');
const OTHER_HASH = '1'.repeat(64);

// ---------- npm, pip, docker ----------
const INTEGRITY = 'sha512-' + Buffer.alloc(64, 7).toString('base64');
const npm = (pkg = 'tool', version = '2.0.1'): InstallSpec => ({ method: 'npm', package: pkg, version });
const npmRoutes = (over: Routes = {}): Routes => ({
  [`GET ${NPM}/tool/2.0.1`]: { body: { name: 'tool', version: '2.0.1', dist: { integrity: INTEGRITY, shasum: '0'.repeat(40) } } },
  [`GET ${NPM}/tool`]: { body: { name: 'tool', time: { created: '2020-01-01T00:00:00Z', '2.0.1': OLD } } },
  ...over,
});
const pip = (pkg = 'Some_Tool', version = '1.4.0'): InstallSpec => ({ method: 'pip', package: pkg, version });
const pypiFile = (filename: string, packagetype: string, hex: string, upload = OLD, yanked = false) => ({
  filename, packagetype, digests: { sha256: hex, md5: '0'.repeat(32) }, upload_time_iso_8601: upload, yanked,
});
const docker = (pkg = 'alpine', version = '3.20'): InstallSpec => ({ method: 'docker', package: pkg, version });
const dockerCand = () => cand({ kind: 'docker', repo: 'alpinelinux/docker-alpine', version: '' });
const INDEX = 'application/vnd.oci.image.index.v1+json';
const LIST = 'application/vnd.docker.distribution.manifest.list.v2+json';
const manifest = (digest = DIGEST, type = INDEX): Reply => ({ headers: { 'docker-content-digest': digest, 'content-type': type } });
const hubRoutes = (over: Routes = {}): Routes => ({
  [`GET ${HUB_PULL}`]: { body: { [PULL_FIELD]: ANON } },
  [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: manifest(),
  [`GET https://hub.docker.com/v2/repositories/library/alpine/tags/3.20`]: { body: { name: '3.20', digest: DIGEST, tag_last_pushed: OLD, last_updated: OLD } },
  ...over,
});

describe('pin: actions', () => {
  it('pin: annotated tag dereferenced to commit sha', async () => {
    const { deps, ghCalls } = setup(github({
      [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'tag', TAG_OBJECT),
      [`GET ${GH}/repos/o/r/git/tags/${TAG_OBJECT}`]: { body: { sha: TAG_OBJECT, tag: 'v1.2.3', object: { type: 'commit', sha: SHA } } },
    }));
    const out = await resolvePin(cand(), deps);
    expect(out.pin).toEqual({ sha: SHA });
    expect(out.version).toBe('v1.2.3');
    expect(JSON.stringify(out)).not.toContain(TAG_OBJECT); // the tag object's own SHA is never the pin
    expect(ghCalls.map((c) => c.url.pathname)).toContain(`/repos/o/r/git/tags/${TAG_OBJECT}`);
  });

  it('pin: lightweight tag of the latest release when no version is set', async () => {
    const { deps } = setup(github({
      [`GET ${GH}/repos/o/r/releases/latest`]: release('v2.0.0'),
      [`GET ${GH}/repos/o/r/git/ref/tags/v2.0.0`]: ref('v2.0.0', 'commit', LIVE_SHA),
    }));
    const out = await resolvePin(cand({ version: '' }), deps);
    expect(out).toMatchObject({ version: 'v2.0.0', pin: { sha: LIVE_SHA } });
  });

  it('pin: a SHA from the AI is never used; the tag is resolved from the upstream refs', async () => {
    const { deps, alert } = setup();
    const out = await resolvePin(cand({ pin: { sha: AI_SHA } }), deps);
    expect(out.pin).toEqual({ sha: SHA });
    expect(alert).not.toHaveBeenCalled(); // a discovery candidate has no reviewed pin to defend
  });

  it('pin: a ref answer for another tag, a non-commit target or a bad SHA is refused', async () => {
    for (const reply of [ref('v1.2.30', 'commit', SHA), ref('v1.2.3', 'tree' as 'commit', SHA), ref('v1.2.3', 'commit', 'A'.repeat(40)), ref('v1.2.3', 'commit', 'abc')]) {
      const { deps } = setup(github({ [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: reply }));
      await expect(resolvePin(cand(), deps)).rejects.toThrow(PinError);
    }
    // a tag that points at another tag that never reaches a commit
    const loop: Routes = {
      [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'tag', TAG_OBJECT),
      [`GET ${GH}/repos/o/r/git/tags/${TAG_OBJECT}`]: { body: { sha: TAG_OBJECT, object: { type: 'tag', sha: TAG_OBJECT } } },
    };
    const { deps } = setup(github(loop));
    await expect(resolvePin(cand(), deps)).rejects.toThrow(PinError);
  });

  it('pin: a tag that does not exist is an error', async () => {
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: { status: 404, body: { message: 'Not Found' } } }));
    await expect(resolvePin(cand(), deps)).rejects.toThrow(/v1\.2\.3/);
  });
});

describe('pin: cooldown', () => {
  it(`pin: a release younger than ${COOLDOWN_DAYS} days is not pinned`, async () => {
    expect(COOLDOWN_DAYS).toBe(7);
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.3', RECENT) }));
    await expect(resolvePin(cand(), deps)).rejects.toThrow(/7 days/);
  });

  it('pin: a release dated in the future, a draft or an unreadable date is refused (fail closed)', async () => {
    const future = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.3', FUTURE) }));
    await expect(resolvePin(cand(), future.deps)).rejects.toThrow(/in the future/);
    for (const reply of [release('v1.2.3', FUTURE), release('v1.2.3', null), release('v1.2.3', 'last week'), { body: { tag_name: 'v1.2.3', published_at: OLD, draft: true } }]) {
      const { deps } = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: reply }));
      await expect(resolvePin(cand(), deps)).rejects.toThrow(PinError);
    }
  });

  it('pin: no release for the tag → the age is unknown → not pinned (commit dates are not trusted)', async () => {
    const { deps, ghCalls } = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: { status: 404, body: { message: 'Not Found' } } }));
    await expect(resolvePin(cand(), deps)).rejects.toThrow(/age/);
    expect(ghCalls.some((c) => c.url.pathname.includes('/git/commits/'))).toBe(false);
  });

  it('pin: a release for another tag does not count', async () => {
    const { deps } = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.4') }));
    await expect(resolvePin(cand(), deps)).rejects.toThrow(PinError);
  });
});

describe('pin: moved tags', () => {
  it('pin: moved tag → PinMovedWarning, stored sha kept, new sha never used', async () => {
    const { deps, alert } = setup(github({ [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'commit', LIVE_SHA) }));
    const out = await resolvePin(stored(), deps);
    expect(alert).toHaveBeenCalledTimes(1);
    const w = alert.mock.calls[0][0] as PinMovedWarning;
    expect(w).toBeInstanceOf(PinMovedWarning);
    expect(w).toMatchObject({ repo: 'o/r', tag: 'v1.2.3', storedSha: SHA, liveSha: LIVE_SHA });
    expect(w.message).toBe(`Possible supply-chain attack: tag v1.2.3 of o/r moved. pipegen keeps the reviewed commit ${SHA}.`);
    expect(out.pin).toEqual({ sha: SHA });
    expect(out.version).toBe('v1.2.3');
    expect(JSON.stringify(out)).not.toContain(LIVE_SHA);
  });

  it('pin: an annotated tag moved to another commit is caught after dereferencing', async () => {
    const { deps, alert } = setup(github({
      [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'tag', TAG_OBJECT),
      [`GET ${GH}/repos/o/r/git/tags/${TAG_OBJECT}`]: { body: { sha: TAG_OBJECT, object: { type: 'commit', sha: LIVE_SHA } } },
    }));
    const out = await resolvePin(stored(), deps);
    expect(alert).toHaveBeenCalledTimes(1);
    expect(out.pin.sha).toBe(SHA);
  });

  it('pin: memory pins are verified the same way', async () => {
    const { deps, alert } = setup(github({ [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'commit', LIVE_SHA) }));
    const out = await resolvePin(stored({ source: 'memory', reviewed: false }), deps);
    expect(alert).toHaveBeenCalledTimes(1);
    expect(out.pin.sha).toBe(SHA);
  });

  it('pin: an unmoved stored pin is returned as is, with no alert and no cooldown lookup', async () => {
    const { deps, alert, ghCalls } = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.3', RECENT) }));
    const c = stored();
    expect(await resolvePin(c, deps)).toEqual(c);
    expect(alert).not.toHaveBeenCalled();
    expect(ghCalls.map((x) => x.url.pathname)).toEqual(['/repos/o/r/git/ref/tags/v1.2.3']);
  });

  it('pin: a deleted tag keeps the stored sha and says so in a note', async () => {
    const { deps, alert, notes } = setup(github({ [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: { status: 404, body: { message: 'Not Found' } } }));
    const out = await resolvePin(stored(), deps);
    expect(out.pin).toEqual({ sha: SHA });
    expect(alert).not.toHaveBeenCalled();
    expect(notes.join(' ')).toMatch(/v1\.2\.3.*no longer exists/);
  });

  it('pin: a stored pin that is not a full SHA, or has no tag to check, is an error', async () => {
    for (const c of [stored({ pin: { sha: 'abc123' } }), stored({ version: '' })]) {
      const { deps } = setup();
      await expect(resolvePin(c, deps)).rejects.toThrow(PinError);
    }
  });

  it('pin: stored package and binary checksums are kept as is (the install checks the hash); a malformed one is an error', async () => {
    const hex = '4'.repeat(64);
    const cases: [Candidate, InstallSpec | undefined][] = [
      [stored({ kind: 'cli', version: '2.0.1', pin: { checksum: INTEGRITY } }), npm()],
      [stored({ kind: 'cli', version: '1.4.0', pin: { checksum: hex } }), pip()],
      [stored({ kind: 'cli', repo: 'o/tool', version: 'v1.4.0', pin: { checksum: hex } }), undefined],
    ];
    for (const [c, spec] of cases) {
      const { deps, ghCalls, netCalls } = setup();
      expect(await resolvePin(c, deps, spec)).toEqual(c);
      expect([...ghCalls, ...netCalls]).toHaveLength(0);
    }
    for (const [c, spec] of [[stored({ kind: 'cli', version: '2.0.1', pin: { checksum: hex } }), npm()], [stored({ kind: 'cli', repo: 'o/tool', pin: { checksum: 'md5:abc' } }), undefined]] as const) {
      const { deps } = setup();
      await expect(resolvePin(c, deps, spec)).rejects.toThrow(PinError);
    }
  });

  it('pin: a moved image tag → warning, stored digest kept', async () => {
    const { deps, alert } = setup(github(), hubRoutes({ [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: manifest(LIVE_DIGEST) }));
    const c = { ...dockerCand(), source: 'reviewed' as const, reviewed: true, version: '3.20', pin: { digest: DIGEST } };
    const out = await resolvePin(c, deps, docker());
    expect(out.pin).toEqual({ digest: DIGEST });
    expect(alert).toHaveBeenCalledTimes(1);
    const w = alert.mock.calls[0][0] as PinMovedWarning;
    expect(w).toMatchObject({ repo: 'docker.io/library/alpine', tag: '3.20', storedSha: DIGEST, liveSha: LIVE_DIGEST });
    expect(w.message).toContain(`keeps the reviewed image ${DIGEST}`);
  });
});

describe('pin: release binaries', () => {
  const binGithub = (assets: unknown[], over: Routes = {}) => ({
    [`GET ${GH}/repos/o/tool/releases/tags/v1.4.0`]: release('v1.4.0', OLD, assets),
    ...over,
  });

  it('pin: release binary sha256 from checksums.txt', async () => {
    const want = sha256('the real archive');
    const sums = `${'9'.repeat(64)}  tool_1.4.0_darwin_arm64.tar.gz\n${want}  ${BIN}\n`;
    const { deps, netCalls } = setup(
      binGithub([asset('tool_1.4.0_darwin_arm64.tar.gz'), asset(BIN), asset('tool_1.4.0_linux_amd64.tar.gz.sig'), asset('tool_1.4.0_checksums.txt', 200)]),
      {
        // GitHub redirects release downloads to its asset host
        [`GET ${DL}/o/tool/releases/download/v1.4.0/tool_1.4.0_checksums.txt`]: { status: 302, headers: { location: `${ASSETS}/sums` } },
        [`GET ${ASSETS}/sums`]: { raw: sums },
      },
    );
    const out = await resolvePin(binCand(), deps);
    expect(out).toMatchObject({ version: 'v1.4.0', pin: { checksum: want } });
    expect(netCalls.some((c) => c.url.pathname.endsWith(BIN))).toBe(false); // the archive itself was not downloaded
  });

  it('pin: a per-asset .sha256 file and an x86_64-unknown-linux asset name are understood', async () => {
    const name = 'tool-v1.4.0-x86_64-unknown-linux-musl.tar.gz';
    const want = sha256('x');
    const { deps } = setup(binGithub([asset(name), asset(`${name}.sha256`, 100)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/${name}.sha256`]: { raw: `${want}\n` },
    });
    expect((await resolvePin(binCand(), deps)).pin).toEqual({ checksum: want });
  });

  it('pin: a checksums file that does not list the asset is an error', async () => {
    const { deps } = setup(binGithub([asset(BIN), asset('checksums.txt', 100)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/checksums.txt`]: { raw: `${OTHER_HASH}  something-else.tar.gz\n` },
    });
    await expect(resolvePin(binCand(), deps)).rejects.toThrow(PinError);
  });

  it('pin: no checksums file → the archive is downloaded and hashed, marked checksumSource computed', async () => {
    const { deps, notes } = setup(binGithub([asset(BIN, BIN_BYTES.length)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/${BIN}`]: { status: 302, headers: { location: `${ASSETS}/bin` } },
      [`GET ${ASSETS}/bin`]: { raw: BIN_BYTES },
    });
    const out = await resolvePin(binCand(), deps);
    expect(out.pin).toEqual({ checksum: sha256(BIN_BYTES) });
    expect(notes.join('\n')).toContain('checksumSource: computed');
  });

  it('pin: a checksums file and GitHub\'s asset digest must agree', async () => {
    const want = sha256('the real archive');
    const routes = (digest: string) => setup(binGithub([{ ...asset(BIN), digest }, asset('checksums.txt', 100)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/checksums.txt`]: { raw: `${want}  ${BIN}\n` },
    });
    expect((await resolvePin(binCand(), routes(`sha256:${want}`).deps)).pin).toEqual({ checksum: want });
    await expect(resolvePin(binCand(), routes(`sha256:${'7'.repeat(64)}`).deps)).rejects.toThrow(/disagree/);
  });

  it("pin: no checksums file but GitHub's own asset digest → that digest, marked checksumSource github-asset-digest, nothing downloaded", async () => {
    const hex = sha256(BIN_BYTES);
    const immutable = (assets: unknown[]): Routes => ({
      [`GET ${GH}/repos/o/tool/releases/tags/v1.4.0`]: { body: { tag_name: 'v1.4.0', published_at: OLD, draft: false, prerelease: false, immutable: true, assets } },
    });
    const { deps, notes, netCalls } = setup(immutable([{ ...asset(BIN, BIN_BYTES.length), digest: `sha256:${hex}` }]));
    const out = await resolvePin(binCand(), deps);
    expect(out.pin).toEqual({ checksum: hex });
    expect(notes.join('\n')).toContain('checksumSource: github-asset-digest');
    expect(notes.join('\n')).toMatch(/immutable release: yes/);
    expect(notes.join('\n')).not.toContain('checksumSource: computed');
    expect(netCalls).toEqual([]); // nothing downloaded
    // a digest that isn't a sha256 is not used: back to downloading and hashing (computed)
    const odd = setup(binGithub([{ ...asset(BIN, BIN_BYTES.length), digest: 'md5:abc' }]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/${BIN}`]: { raw: BIN_BYTES },
    });
    expect((await resolvePin(binCand(), odd.deps)).pin).toEqual({ checksum: hex });
    expect(odd.notes.join('\n')).toContain('checksumSource: computed');
  });

  it('pin: downloads only follow redirects to allow-listed https hosts, and are size-bounded', async () => {
    const evil = setup(binGithub([asset(BIN, BIN_BYTES.length)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/${BIN}`]: { status: 302, headers: { location: 'https://evil.example/bin' } },
      ['GET https://evil.example/bin']: { raw: BIN_BYTES },
    });
    await expect(resolvePin(binCand(), evil.deps)).rejects.toThrow(PinError);
    expect(evil.netCalls.some((c) => c.url.host === 'evil.example')).toBe(false);

    const plain = setup(binGithub([asset(BIN, BIN_BYTES.length)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/${BIN}`]: { status: 302, headers: { location: 'http://objects.githubusercontent.com/bin' } },
    });
    await expect(resolvePin(binCand(), plain.deps)).rejects.toThrow(/not an allowed https host/);
    expect(plain.netCalls.some((c) => c.url.protocol === 'http:')).toBe(false);

    // the API says the asset is huge: refused before any download
    const huge = setup(binGithub([asset(BIN, 2 * 1024 ** 3)]));
    await expect(resolvePin(binCand(), huge.deps)).rejects.toThrow(/too large/);
    expect(huge.netCalls).toHaveLength(0);

    // the API under-reports: the body itself is cut off at the cap
    const lying = setup(binGithub([asset(BIN, 10)]), { [`GET ${DL}/o/tool/releases/download/v1.4.0/${BIN}`]: { raw: new Uint8Array(1024 * 1024 + 1) } }, { maxDownloadBytes: 1024 * 1024 });
    await expect(resolvePin(binCand(), lying.deps)).rejects.toThrow(/too large/);
  });

  it('pin: an asset or checksums file changed within the cooldown is not pinned', async () => {
    const want = sha256('y');
    const { deps } = setup(binGithub([asset(BIN, 1000, RECENT), asset('checksums.txt', 100)]), {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/checksums.txt`]: { raw: `${want}  ${BIN}\n` },
    });
    await expect(resolvePin(binCand(), deps)).rejects.toThrow(/7 days/);
  });

  it('pin: several matching linux assets → the install spec names one, else an error', async () => {
    const gz = 'tool_1.4.0_linux_amd64.tar.gz';
    const deb = 'tool_1.4.0_linux_amd64.deb';
    const zip = 'tool_1.4.0_linux_amd64.zip';
    const want = sha256('z');
    const routes = { [`GET ${DL}/o/tool/releases/download/v1.4.0/checksums.txt`]: { raw: `${want}  ${zip}\n${OTHER_HASH}  ${gz}\n` } };
    const assets = [asset(gz), asset(deb), asset(zip), asset('checksums.txt', 100)];
    const ambiguous = setup(binGithub(assets), routes);
    await expect(resolvePin(binCand(), ambiguous.deps)).rejects.toThrow(/several/);
    const named = setup(binGithub(assets), routes);
    expect((await resolvePin(binCand(), named.deps, { method: 'github-release', package: zip, version: 'v1.4.0' })).pin).toEqual({ checksum: want });
  });

  it('pin: the latest release is used when no version is set', async () => {
    const want = sha256('w');
    const { deps } = setup({ [`GET ${GH}/repos/o/tool/releases/latest`]: release('v1.4.0', OLD, [asset(BIN), asset('checksums.txt', 100)]) }, {
      [`GET ${DL}/o/tool/releases/download/v1.4.0/checksums.txt`]: { raw: `${want} *${BIN}\n` },
    });
    expect(await resolvePin(cand({ kind: 'cli', repo: 'o/tool', version: '' }), deps)).toMatchObject({ version: 'v1.4.0', pin: { checksum: want } });
  });
});

describe('pin: packages', () => {
  it('pin: npm integrity recorded', async () => {
    const { deps, netCalls } = setup({}, npmRoutes());
    const out = await resolvePin(cand({ kind: 'cli', version: '' }), deps, npm());
    expect(out).toMatchObject({ version: '2.0.1', pin: { checksum: INTEGRITY } });
    expect(netCalls.map((c) => c.url.href)).toContain(`${NPM}/tool/2.0.1`);
  });

  it('pin: npm scoped names are escaped; a weak or missing integrity, or a young version, is refused', async () => {
    const scoped = setup({}, {
      [`GET ${NPM}/@scope%2ftool/2.0.1`]: { body: { name: '@scope/tool', version: '2.0.1', dist: { integrity: INTEGRITY } } },
      [`GET ${NPM}/@scope%2ftool`]: { body: { time: { '2.0.1': OLD } } },
    });
    expect((await resolvePin(cand({ kind: 'cli' }), scoped.deps, npm('@scope/tool'))).pin).toEqual({ checksum: INTEGRITY });
    for (const over of <Routes[]>[
      { [`GET ${NPM}/tool/2.0.1`]: { body: { name: 'tool', version: '2.0.1', dist: { integrity: 'sha1-' + Buffer.alloc(20).toString('base64') } } } },
      { [`GET ${NPM}/tool/2.0.1`]: { body: { name: 'tool', version: '2.0.1', dist: {} } } },
      { [`GET ${NPM}/tool/2.0.1`]: { body: { name: 'tool', version: '2.0.2', dist: { integrity: INTEGRITY } } } },
      { [`GET ${NPM}/tool`]: { body: { time: { '2.0.1': RECENT } } } },
      { [`GET ${NPM}/tool`]: { body: { time: { '2.0.1': FUTURE } } } },
      { [`GET ${NPM}/tool`]: { body: { time: {} } } },
    ]) {
      const { deps } = setup({}, npmRoutes(over));
      await expect(resolvePin(cand({ kind: 'cli' }), deps, npm())).rejects.toThrow(PinError);
    }
  });

  it('pin: an npm or pip version must be exact', async () => {
    for (const spec of [npm('tool', '^2.0.0'), npm('tool', '2'), npm('tool', ''), pip('Some_Tool', '>=1.0'), pip('Some_Tool', '')]) {
      const { deps, netCalls } = setup({}, npmRoutes());
      await expect(resolvePin(cand({ kind: 'cli', version: '' }), deps, spec)).rejects.toThrow(PinError);
      expect(netCalls).toHaveLength(0);
    }
  });

  it('pin: pip records the sha256 of the py3-none-any wheel', async () => {
    const wheel = '1'.repeat(64);
    const { deps, netCalls } = setup({}, {
      [`GET ${PYPI}/pypi/some-tool/1.4.0/json`]: { body: { info: { version: '1.4.0' }, urls: [
        pypiFile('some_tool-1.4.0.tar.gz', 'sdist', '2'.repeat(64)),
        pypiFile('some_tool-1.4.0-cp312-cp312-manylinux_2_17_x86_64.whl', 'bdist_wheel', '3'.repeat(64)),
        pypiFile('some_tool-1.4.0-py3-none-any.whl', 'bdist_wheel', wheel),
      ] } },
    });
    expect(await resolvePin(cand({ kind: 'cli' }), deps, pip())).toMatchObject({ version: '1.4.0', pin: { checksum: wheel } });
    expect(netCalls.map((c) => c.url.href)).toEqual([`${PYPI}/pypi/some-tool/1.4.0/json`]);
  });

  it('pin: pip falls back to the sdist; yanked, young or unreadable files are refused', async () => {
    const sdist = '2'.repeat(64);
    const page = (urls: unknown[]): Routes => ({ [`GET ${PYPI}/pypi/some-tool/1.4.0/json`]: { body: { info: { version: '1.4.0' }, urls } } });
    const ok = setup({}, page([pypiFile('some_tool-1.4.0-cp312-cp312-win_amd64.whl', 'bdist_wheel', '3'.repeat(64)), pypiFile('some_tool-1.4.0.tar.gz', 'sdist', sdist)]));
    expect((await resolvePin(cand({ kind: 'cli' }), ok.deps, pip())).pin).toEqual({ checksum: sdist });
    for (const urls of [
      [pypiFile('some_tool-1.4.0-py3-none-any.whl', 'bdist_wheel', '1'.repeat(64), OLD, true)],
      [pypiFile('some_tool-1.4.0-py3-none-any.whl', 'bdist_wheel', '1'.repeat(64), RECENT)],
      [pypiFile('some_tool-1.4.0-py3-none-any.whl', 'bdist_wheel', 'XYZ')],
      [pypiFile('some_tool-1.4.0-cp312-cp312-win_amd64.whl', 'bdist_wheel', '3'.repeat(64))],
    ]) {
      const { deps } = setup({}, page(urls));
      await expect(resolvePin(cand({ kind: 'cli' }), deps, pip())).rejects.toThrow(PinError);
    }
  });
});

describe('pin: images', () => {
  it('pin: docker digest from manifest HEAD', async () => {
    const { deps, netCalls } = setup({}, hubRoutes());
    const out = await resolvePin(dockerCand(), deps, docker());
    expect(out).toMatchObject({ version: '3.20', pin: { digest: DIGEST } });
    const head = netCalls.find((c) => c.method === 'HEAD');
    expect(head?.url.href).toBe('https://registry-1.docker.io/v2/library/alpine/manifests/3.20');
    expect(head?.headers.accept).toContain(INDEX);
    expect(head?.headers.accept).toContain(LIST);
    expect(head?.headers[LOGIN_HEADER]).toBe(`Bearer ${ANON}`);
    const pull = netCalls.find((c) => c.url.host === 'auth.docker.io');
    expect(pull?.url.searchParams.get('scope')).toBe('repository:library/alpine:pull');
    expect(pull?.url.searchParams.get('service')).toBe('registry.docker.io');
    expect(pull?.headers[LOGIN_HEADER]).toBeUndefined();
  });

  it('pin: a single-platform manifest, a bad digest or a hub digest that differs is refused', async () => {
    for (const over of <Routes[]>[
      { [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: manifest(DIGEST, 'application/vnd.oci.image.manifest.v1+json') },
      { [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: manifest('sha256:abc') },
      { [`GET https://hub.docker.com/v2/repositories/library/alpine/tags/3.20`]: { body: { digest: LIVE_DIGEST, tag_last_pushed: OLD } } },
      { [`GET https://hub.docker.com/v2/repositories/library/alpine/tags/3.20`]: { body: { digest: DIGEST, tag_last_pushed: RECENT } } },
      { [`GET ${HUB_PULL}`]: { body: { [PULL_FIELD]: 'bad value\r\nx-injected: 1' } } },
    ]) {
      const { deps } = setup({}, hubRoutes(over));
      await expect(resolvePin(dockerCand(), deps, docker())).rejects.toThrow(PinError);
    }
  });

  it('pin: a manifest-list digest from Docker Hub is accepted', async () => {
    const { deps } = setup({}, hubRoutes({ [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: manifest(DIGEST, LIST) }));
    expect((await resolvePin(dockerCand(), deps, docker('docker.io/library/alpine'))).pin).toEqual({ digest: DIGEST });
  });

  it('pin: GHCR uses its anonymous token; a stored digest is verified there, a new pin is refused (no server-side age)', async () => {
    const routes: Routes = {
      [`GET ${GHCR_PULL}`]: { body: { [PULL_FIELD]: ANON } },
      ['HEAD https://ghcr.io/v2/zaproxy/zaproxy/manifests/2.16.1']: manifest(),
    };
    const c = { ...dockerCand(), source: 'reviewed' as const, reviewed: true, version: '2.16.1', pin: { digest: DIGEST } };
    const verify = setup({}, routes);
    expect(await resolvePin(c, verify.deps, docker('ghcr.io/zaproxy/zaproxy', '2.16.1'))).toEqual(c);
    expect(verify.alert).not.toHaveBeenCalled();
    const head = verify.netCalls.find((x) => x.method === 'HEAD');
    expect(head?.headers[LOGIN_HEADER]).toBe(`Bearer ${ANON}`);
    expect(verify.netCalls.find((x) => x.url.pathname === '/token')?.url.searchParams.get('scope')).toBe('repository:zaproxy/zaproxy:pull');

    const fresh = setup({}, routes);
    await expect(resolvePin(dockerCand(), fresh.deps, docker('ghcr.io/zaproxy/zaproxy', '2.16.1'))).rejects.toThrow(/age/);
  });

  it('pin: an image without an install spec, from another registry, or with a bad name is refused before any request', async () => {
    for (const spec of [undefined, docker('quay.io/org/img'), docker('Alpine'), docker('alpine', 'bad tag'), docker('../etc', '1'), docker('alpine', '')]) {
      const { deps, netCalls } = setup({}, hubRoutes());
      await expect(resolvePin(dockerCand(), deps, spec)).rejects.toThrow(PinError);
      expect(netCalls).toHaveLength(0);
    }
  });
});

describe('pin: fix round 1', () => {
  const DAY = 86_400_000;
  const iso = (ms: number) => new Date(ms).toISOString();
  const blobRef: Routes = {
    [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'tag', TAG_OBJECT),
    [`GET ${GH}/repos/o/r/git/tags/${TAG_OBJECT}`]: { body: { sha: TAG_OBJECT, object: { type: 'blob', sha: LIVE_SHA } } },
  };
  const deepChain: Routes = Object.fromEntries([
    [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`, ref('v1.2.3', 'tag', '1'.repeat(40))],
    ...[1, 2, 3, 4].map((i) => [`GET ${GH}/repos/o/r/git/tags/${String(i).repeat(40)}`, { body: { object: { type: 'tag', sha: String(i + 1).repeat(40) } } }]),
  ]);

  it('pin: a stored pin whose tag now leads to a tree, a blob or a deep tag chain → alert, stored sha kept', async () => {
    for (const routes of [{ [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'tree' as 'commit', LIVE_SHA) }, blobRef, deepChain]) {
      const { deps, alert } = setup(github(routes));
      const c = stored();
      expect(await resolvePin(c, deps)).toEqual(c);
      expect(alert).toHaveBeenCalledTimes(1);
      expect(alert.mock.calls[0][0]).toMatchObject({ storedSha: SHA, liveSha: '<not a commit>' });
    }
    // a new pin still refuses them
    const { deps } = setup(github(blobRef));
    await expect(resolvePin(cand(), deps)).rejects.toThrow(PinError);
  });

  it('pin: a nested annotated tag chain (tag → tag → commit) resolves to the commit', async () => {
    const { deps } = setup(github({
      [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: ref('v1.2.3', 'tag', TAG_OBJECT),
      [`GET ${GH}/repos/o/r/git/tags/${TAG_OBJECT}`]: { body: { object: { type: 'tag', sha: AI_SHA } } },
      [`GET ${GH}/repos/o/r/git/tags/${AI_SHA}`]: { body: { object: { type: 'commit', sha: SHA } } },
    }));
    expect((await resolvePin(cand(), deps)).pin).toEqual({ sha: SHA });
  });

  const storedImage = () => ({ ...dockerCand(), source: 'reviewed' as const, reviewed: true, version: '3.20', pin: { digest: DIGEST } });

  it('pin: a stored image tag that no longer serves an index → alert, stored digest kept', async () => {
    const { deps, alert } = setup({}, hubRoutes({ [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: manifest(LIVE_DIGEST, 'application/vnd.oci.image.manifest.v1+json') }));
    const c = storedImage();
    expect(await resolvePin(c, deps, docker())).toEqual(c);
    expect(alert).toHaveBeenCalledTimes(1);
    expect(alert.mock.calls[0][0]).toMatchObject({ storedSha: DIGEST, liveSha: '<not an index>' });
  });

  it('pin: a stored image tag that is gone (404) → note, stored digest kept', async () => {
    const { deps, alert, notes } = setup({}, hubRoutes({ [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: { status: 404 } }));
    const c = storedImage();
    expect(await resolvePin(c, deps, docker())).toEqual(c);
    expect(alert).not.toHaveBeenCalled();
    expect(notes.join(' ')).toMatch(/3\.20.*no longer exists/);
    // a new pin of a missing tag is an error
    const fresh = setup({}, hubRoutes({ [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: { status: 404 } }));
    await expect(resolvePin(dockerCand(), fresh.deps, docker())).rejects.toThrow(PinError);
  });

  it('pin: notes are required in PinDeps', () => {
    const { deps } = setup();
    const { notes: _notes, ...rest } = deps;
    // @ts-expect-error notes is required, so the computed-checksum marker can't be lost
    const missing: PinDeps = rest;
    expect(missing.notes).toBeUndefined();
  });

  it('pin: a release whose target_commitish is another commit → new pin refused (tag moved after release)', async () => {
    const moved = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: { body: { tag_name: 'v1.2.3', published_at: OLD, draft: false, target_commitish: LIVE_SHA } } }));
    await expect(resolvePin(cand(), moved.deps)).rejects.toThrow('The tag v1.2.3 was moved after its release was published.');
    for (const target of [SHA, 'main', null]) {
      const ok = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: { body: { tag_name: 'v1.2.3', published_at: OLD, draft: false, target_commitish: target } } }));
      expect((await resolvePin(cand(), ok.deps)).pin).toEqual({ sha: SHA });
    }
  });

  it('pin: every new pin adds a human-review note; a verified stored pin does not', async () => {
    const a = setup();
    await resolvePin(cand(), a.deps);
    expect(a.notes).toEqual([`New pin for o/r v1.2.3 → ${SHA}: needs human review before release (reviewed-tools Step 6).`]);
    const n = setup({}, npmRoutes());
    await resolvePin(cand({ kind: 'cli' }), n.deps, npm());
    expect(n.notes).toEqual([`New pin for tool@2.0.1 → ${INTEGRITY}: needs human review before release (reviewed-tools Step 6).`]);
    const d = setup({}, hubRoutes());
    await resolvePin(dockerCand(), d.deps, docker());
    expect(d.notes.join(' ')).toContain(`New pin for docker.io/library/alpine:3.20 → ${DIGEST}`);
    const s = setup();
    await resolvePin(stored(), s.deps);
    expect(s.notes).toEqual([]);
  });

  it('pin: the 7-day boundary: exactly 7 days old is accepted, 1 ms less is refused', async () => {
    const at = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.3', iso(NOW - 7 * DAY)) }));
    expect((await resolvePin(cand(), at.deps)).pin).toEqual({ sha: SHA });
    const under = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: release('v1.2.3', iso(NOW - 7 * DAY + 1)) }));
    await expect(resolvePin(cand(), under.deps)).rejects.toThrow(/7 days/);
  });

  it('pin: a registry HEAD redirect to another host is refused and the pull token is not sent there', async () => {
    const { deps, netCalls } = setup({}, hubRoutes({
      [`HEAD https://registry-1.docker.io/v2/library/alpine/manifests/3.20`]: { status: 307, headers: { location: 'https://evil.example/v2/x' } },
      ['HEAD https://evil.example/v2/x']: manifest(),
    }));
    await expect(resolvePin(dockerCand(), deps, docker())).rejects.toThrow(/not an allowed https host/);
    expect(netCalls.some((c) => c.url.host === 'evil.example')).toBe(false);
  });

  it('pin: more checksums files than pipegen reads → refused, never silently cut', async () => {
    const files = ['checksums.txt', 'SHA256SUMS', 'tool_checksums.txt', 'sha256sums.txt', `${BIN}.sha256`];
    const { deps } = setup({ [`GET ${GH}/repos/o/tool/releases/tags/v1.4.0`]: release('v1.4.0', OLD, [asset(BIN), ...files.map((f) => asset(f, 100))]) });
    await expect(resolvePin(binCand(), deps)).rejects.toThrow(/checksums files/);
  });

  it('pin: an install spec hash that disagrees with the candidate pin is refused', async () => {
    const hex = '4'.repeat(64);
    const cases: [Candidate, InstallSpec][] = [
      [stored({ kind: 'cli', version: '1.4.0', pin: { checksum: hex } }), { ...pip(), checksum: OTHER_HASH }],
      [stored({ kind: 'cli', version: '1.4.0', pin: {} }), { ...pip(), checksum: hex }],
      [{ ...storedImage() }, { ...docker(), digest: LIVE_DIGEST }],
      [{ ...storedImage(), pin: {} }, { ...docker(), digest: DIGEST }],
    ];
    for (const [c, spec] of cases) {
      const { deps, ghCalls, netCalls } = setup({}, hubRoutes());
      await expect(resolvePin(c, deps, spec)).rejects.toThrow(/stored hash .* and its pin disagree/);
      expect([...ghCalls, ...netCalls]).toHaveLength(0);
    }
    const same = setup();
    const c = stored({ kind: 'cli', version: '1.4.0', pin: { checksum: hex } });
    expect(await resolvePin(c, same.deps, { ...pip(), checksum: hex })).toEqual(c);
  });

  it('pin: a prerelease is never newly pinned', async () => {
    const pre = (assets: unknown[] = []): Reply => ({ body: { tag_name: 'v1.2.3', published_at: OLD, draft: false, prerelease: true, assets } });
    const action = setup(github({ [`GET ${GH}/repos/o/r/releases/tags/v1.2.3`]: pre() }));
    await expect(resolvePin(cand(), action.deps)).rejects.toThrow(/pre-release/);
    const bin = setup({ [`GET ${GH}/repos/o/tool/releases/tags/v1.2.3`]: pre([asset(BIN)]) });
    await expect(resolvePin(binCand(), bin.deps, { method: 'github-release', package: BIN, version: 'v1.2.3' })).rejects.toThrow(/pre-release/);
  });
});

describe('pin: inputs, credentials, rate limits', () => {
  it('pin: bad repo, tag or package names are refused before any request (S14), and errors are cleaned', async () => {
    const bad: [Candidate, InstallSpec?][] = [
      [cand({ repo: 'o/r/../x' })], [cand({ repo: '../r' })], [cand({ repo: 'o/..' })],
      [cand({ version: 'v1/../../x' })], [cand({ version: 'v1\u001b[31m' })], [cand({ version: '-v1' })],
      [cand({ kind: 'cli' }), npm('Bad Name')], [cand({ kind: 'cli' }), pip('-bad')],
      [cand({ kind: 'cli', version: 'v1?x=1' })],
    ];
    for (const [c, spec] of bad) {
      const { deps, ghCalls, netCalls } = setup();
      const err = await resolvePin(c, deps, spec).then(() => null, (e: unknown) => e as Error);
      expect(err).toBeInstanceOf(PinError);
      expect(err?.message).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
      expect(ghCalls).toHaveLength(0);
      expect(netCalls).toHaveLength(0);
    }
  });

  it('pin: only the Octokit carries the credential; deps.fetch gets no authorization except the anonymous registry token on its own registry', async () => {
    const cred = fake.githubClassic();
    const want = sha256('v');
    const g = fakeOctokit({
      ...github(),
      [`GET ${GH}/repos/o/tool/releases/tags/v1.4.0`]: release('v1.4.0', OLD, [asset(BIN), asset('checksums.txt', 100)]),
    }, { [LOGIN_OPTION]: cred });
    const f = fakeFetch({
      ...npmRoutes(), ...hubRoutes(),
      [`GET ${DL}/o/tool/releases/download/v1.4.0/checksums.txt`]: { raw: `${want}  ${BIN}\n` },
      [`GET ${PYPI}/pypi/some-tool/1.4.0/json`]: { body: { info: { version: '1.4.0' }, urls: [pypiFile('some_tool-1.4.0-py3-none-any.whl', 'bdist_wheel', want)] } },
    });
    const deps: PinDeps = { gh: g.gh, fetch: f.fetch, alert: vi.fn(), notes: [], sleep: async () => {}, now: () => NOW, budget: newRateBudget() };
    await resolvePin(cand(), deps);
    await resolvePin(binCand(), deps);
    await resolvePin(cand({ kind: 'cli' }), deps, npm());
    await resolvePin(cand({ kind: 'cli' }), deps, pip());
    await resolvePin(dockerCand(), deps, docker());
    expect(g.calls.length).toBeGreaterThan(0);
    for (const c of g.calls) expect(c.headers[LOGIN_HEADER]).toContain(cred);
    expect(f.calls.length).toBeGreaterThan(4);
    for (const c of f.calls) {
      expect(JSON.stringify(c)).not.toContain(cred);
      const sent = c.headers[LOGIN_HEADER];
      if (c.url.origin === 'https://registry-1.docker.io') expect(sent).toBe(`Bearer ${ANON}`);
      else expect(sent).toBeUndefined();
    }
  });

  it('pin: GitHub calls go through the shared rate-limit helper with the run budget (S16)', async () => {
    let first = true;
    const limited: Routes = github({
      [`GET ${GH}/repos/o/r/git/ref/tags/v1.2.3`]: () => {
        if (!first) return ref('v1.2.3', 'commit', SHA);
        first = false;
        return { status: 403, body: { message: 'rate limited' }, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(NOW / 1000) + 10) } };
      },
    });
    const budget = newRateBudget(60_000);
    const { deps } = setup(limited, {}, { budget });
    expect((await resolvePin(cand(), deps)).pin).toEqual({ sha: SHA });
    expect(deps.sleep).toHaveBeenCalledTimes(1);
    expect(budget.remainingMs).toBeLessThan(60_000);

    first = true;
    const spent = setup(limited, {}, { budget: newRateBudget(0) });
    await expect(resolvePin(cand(), spent.deps)).rejects.toThrow(/stopped waiting/);
  });
});

describe('platformActions', () => {
  const reviewedTool = (id: string, repo: string, tag: string, sha: string): ReviewedTool => ({
    id, categories: ['platform'], languages: ['any'],
    candidate: { id, name: id, kind: 'action', repo, version: tag, pin: { sha }, source: 'reviewed', reviewed: true, categories: ['platform'] },
    step: { output: { path: '', format: 'none' } }, fixedInputs: {}, choices: {}, configFiles: [], reviewedBy: 'maintainer', reviewedAt: '2026-09-01', proofs: 0,
  });
  const repoOf = (id: string) => `owner-${id}/action`;
  const shaOf = (i: number) => i.toString(16).padStart(40, '0');
  const list = () => Object.values(PLATFORM_ACTION_IDS).map((id, i) => reviewedTool(id, repoOf(id), 'v4.1.0', shaOf(i + 1)));
  const refs = (moved?: string): Routes => Object.fromEntries(Object.values(PLATFORM_ACTION_IDS).map((id, i) => [
    `GET ${GH}/repos/${repoOf(id)}/git/ref/tags/v4.1.0`, ref('v4.1.0', 'commit', id === moved ? LIVE_SHA : shaOf(i + 1)),
  ]));

  it('platformActions: ids match the reviewed list', () => {
    expect(PLATFORM_ACTION_IDS).toEqual({
      checkout: 'actions-checkout', 'setup-node': 'actions-setup-node', 'setup-python': 'actions-setup-python',
      'upload-artifact': 'actions-upload-artifact', 'download-artifact': 'actions-download-artifact',
      'docker-login': 'docker-login-action', 'setup-buildx': 'docker-setup-buildx-action', 'build-push': 'docker-build-push-action',
      'upload-sarif': 'codeql-upload-sarif', attest: 'actions-attest',
    });
  });

  it('platformActions: no cache entry; moved platform tag → warning, stored sha kept', async () => {
    const { deps, alert } = setup(refs('actions-checkout'));
    const out: PlatformActions = await platformActions(list(), deps);
    expect(Object.keys(out).sort()).toEqual(Object.keys(PLATFORM_ACTION_IDS).sort());
    expect(Object.keys(out)).not.toContain('cache');
    expect(Object.values(out).some((c) => /cache/i.test(c.id) || /actions\/cache/i.test(c.repo))).toBe(false);
    expect(alert).toHaveBeenCalledTimes(1);
    expect(alert.mock.calls[0][0]).toMatchObject({ repo: repoOf('actions-checkout'), storedSha: shaOf(1), liveSha: LIVE_SHA });
    expect(out.checkout.pin).toEqual({ sha: shaOf(1) });
    expect(JSON.stringify(out)).not.toContain(LIVE_SHA);
    Object.values(PLATFORM_ACTION_IDS).forEach((id, i) => {
      const key = (Object.keys(PLATFORM_ACTION_IDS) as (keyof PlatformActions)[])[i];
      expect(out[key].id).toBe(id);
      expect(out[key].pin.sha).toBe(shaOf(i + 1));
    });
  });

  it('platformActions: a missing, duplicated or unpinned entry is an error', async () => {
    const missing = list().filter((t) => t.id !== 'actions-attest');
    const dup = [...list(), list()[0]];
    const unpinned = list().map((t) => (t.id === 'actions-setup-node' ? { ...t, candidate: { ...t.candidate, pin: {} } } : t));
    const notReviewed = list().map((t) => (t.id === 'actions-setup-node' ? { ...t, candidate: { ...t.candidate, reviewed: false, source: 'discovery' as const } } : t));
    for (const l of [missing, dup, unpinned, notReviewed]) {
      const { deps } = setup(refs());
      await expect(platformActions(l, deps)).rejects.toThrow(PinError);
    }
  });
});

describe('PinMovedWarning', () => {
  it('PinMovedWarning: the message is cleaned', () => {
    const w = new PinMovedWarning('o/r', 'v1\u001b[2J', SHA, LIVE_SHA);
    expect(w.message).not.toContain('\u001b');
    expect(w.tag).toBe('v1\u001b[2J'); // the field stays raw; only display text is cleaned
  });
});
