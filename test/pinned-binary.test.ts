import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lutimesSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  checkPinnedAgainstReviewed, ensurePinnedBinary, loadPinnedBinaries, PinnedBinaryError, pinnedBinariesSchema,
  type PinnedBinaries, type PinnedBinaryDeps,
} from '../src/engine/linters.js';
import { COOLDOWN_DAYS } from '../src/engine/pin.js';
import type { Candidate, ReviewedTool } from '../src/types.js';
import { fakeFetch, type Routes } from './helpers/fake-http.js';
import { makeTarGz, type TarEntry } from './helpers/fake-tar.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

// Every child-process entry point is a spy: unpacking must happen in-process (ruling B3), never through `tar`.
const spawned = vi.hoisted(() => [] as string[]);
vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>();
  const spy = (name: string) => (...args: unknown[]) => {
    spawned.push(`${name} ${String(args[0])}`);
    return (real as unknown as Record<string, (...a: unknown[]) => unknown>)[name]?.(...args);
  };
  const names = ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'];
  return { ...real, ...Object.fromEntries(names.map((n) => [n, spy(n)])) };
});

afterEach(() => {
  cleanupRepos();
  spawned.length = 0;
});

const NOW = Date.parse('2026-10-26T12:00:00Z');
const DAY = 86_400_000;
const OLD = '2026-09-01T10:00:00Z';
const DL = 'https://github.com';
const ASSETS = 'https://release-assets.githubusercontent.com';
// Header name that holds "auth", built at runtime (repo rule: no secret-like literals in test/).
const LOGIN_HEADER = 'author' + 'ization';
const VERSION = '9.9.9';
const ASSET = `gitleaks_${VERSION}_linux_x64.tar.gz`;
const URL_PATH = `/gitleaks/gitleaks/releases/download/v${VERSION}/${ASSET}`;
const ASSET_PATH = '/github-production-release-asset/1/gitleaks-asset';

const sha256 = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex');

interface Setup {
  dir: string;
  cache: string;
  marker: string;
  binary: Buffer;
  archive: Buffer;
  pins: PinnedBinaries;
  routes: Routes;
  deps: (over?: PinnedBinaryDeps) => PinnedBinaryDeps & { calls: ReturnType<typeof fakeFetch>['calls'] };
}

/** A fake binary that would leave a marker file if it were ever run. */
function fakeBinary(marker: string): Buffer {
  return Buffer.from(`#!/bin/sh\necho ran > '${marker}'\n`);
}

/**
 * A fake gitleaks release: a tar.gz built at runtime, served by a fake fetch through a GitHub-style redirect, and
 * a pins table whose hashes match it (unless `over` changes them).
 */
function setup(opts: {
  entries?: (bin: Buffer) => TarEntry[];
  archive?: (bin: Buffer) => Buffer;
  asset?: (pins: PinnedBinaries['gitleaks']['platforms']['linux-x64'], archive: Buffer, bin: Buffer) => Partial<PinnedBinaries['gitleaks']['platforms']['linux-x64']>;
  releasedAt?: string;
} = {}): Setup {
  const dir = makeTempDir();
  const cache = join(dir, 'tools');
  const marker = join(dir, 'ran');
  const binary = fakeBinary(marker);
  const entries = opts.entries?.(binary) ?? [{ name: 'LICENSE', content: 'MIT' }, { name: 'README.md', content: '# gitleaks' }, { name: 'gitleaks', content: binary }];
  const archive = opts.archive?.(binary) ?? makeTarGz(entries);
  const base = {
    url: `${DL}${URL_PATH}`, archive: 'tar.gz' as const,
    archiveSize: archive.length, archiveSha256: sha256(archive), binarySize: binary.length, binarySha256: sha256(binary),
  };
  const asset = { ...base, ...opts.asset?.(base, archive, binary) };
  const platforms = { 'linux-x64': asset, 'linux-arm64': asset, 'darwin-x64': asset, 'darwin-arm64': asset };
  const entry = { version: VERSION, repo: 'gitleaks/gitleaks', releasedAt: opts.releasedAt ?? OLD, member: 'gitleaks', platforms };
  const pins = {
    gitleaks: entry,
    actionlint: { ...entry, repo: 'rhysd/actionlint', member: 'actionlint', platforms: rehost(platforms, 'rhysd/actionlint', 'actionlint') },
    cosign: { ...entry, repo: 'sigstore/cosign', member: 'cosign', platforms: rehost(platforms, 'sigstore/cosign', 'cosign') },
  } as PinnedBinaries;
  const routes: Routes = {
    [`GET ${DL}${URL_PATH}`]: { status: 302, headers: { location: `${ASSETS}${ASSET_PATH}?sig=x` } },
    [`GET ${ASSETS}${ASSET_PATH}`]: { raw: archive, headers: { 'content-type': 'application/octet-stream' } },
  };
  return {
    dir, cache, marker, binary, archive, pins, routes,
    deps: (over = {}) => {
      const f = fakeFetch(routes);
      return { fetch: f.fetch, calls: f.calls, pins, platform: 'linux', arch: 'x64', now: () => NOW, env: {}, ...over };
    },
  };
}

function rehost<T extends { url: string }>(platforms: Record<string, T>, repo: string, tool: string): Record<string, T> {
  return Object.fromEntries(Object.entries(platforms).map(([k, v]) => [k, { ...v, url: `${DL}/${repo}/releases/download/v${VERSION}/${tool}_${VERSION}_${k}.tar.gz` }]));
}

const modeOf = (p: string) => statSync(p).mode & 0o777;
const filesIn = (p: string) => (existsSync(p) ? readdirSync(p) : []);

describe('ensurePinnedBinary', () => {
  it('ensurePinnedBinary: gitleaks downloaded and checksum-verified', async () => {
    const s = setup();
    const deps = s.deps();
    const path = await ensurePinnedBinary('gitleaks', s.cache, deps);
    expect(path).toBe(join(s.cache, `gitleaks-${VERSION}`, 'gitleaks'));
    expect(readFileSync(path).equals(s.binary)).toBe(true);
    expect(modeOf(path)).toBe(0o700);
    expect(modeOf(join(s.cache, `gitleaks-${VERSION}`))).toBe(0o700);
    expect(filesIn(join(s.cache, `gitleaks-${VERSION}`))).toEqual(['gitleaks']); // no temp file left behind
    // github.com, then its release-asset host; https only, no credential on any request (ruling S15)
    expect(deps.calls.map((c) => c.url.origin)).toEqual([DL, ASSETS]);
    for (const c of deps.calls) expect(Object.keys(c.headers)).not.toContain(LOGIN_HEADER);
    expect(existsSync(s.marker)).toBe(false); // never run
    expect(spawned).toEqual([]); // unpacked in-process: no tar, no child process at all
  });

  it('ensurePinnedBinary: checksum mismatch → error, file deleted, never run', async () => {
    const s = setup({ asset: () => ({ binarySha256: sha256('something else') }) });
    const err = await ensurePinnedBinary('gitleaks', s.cache, s.deps()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PinnedBinaryError);
    // refused at the binary check, before anything is written (not later, by the re-check of the written file)
    expect(String((err as Error).message)).toMatch(/gitleaks.*binary.*doesn't match its pinned checksum.*Nothing was written/i);
    expect(filesIn(join(s.cache, `gitleaks-${VERSION}`))).toEqual([]); // nothing written, no temp file
    expect(existsSync(s.marker)).toBe(false);
    expect(spawned).toEqual([]);
  });

  it('ensurePinnedBinary: cached binary re-checked before use', async () => {
    const s = setup();
    const first = s.deps();
    const path = await ensurePinnedBinary('gitleaks', s.cache, first);
    // a good cached copy: re-hashed and returned, nothing downloaded
    const second = s.deps();
    expect(await ensurePinnedBinary('gitleaks', s.cache, second)).toBe(path);
    expect(second.calls).toEqual([]);
    // tampered after caching: refused, deleted, never run, and not silently replaced by a new download
    writeFileSync(path, Buffer.concat([s.binary, Buffer.from('# tampered\n')]));
    const third = s.deps();
    const err = await ensurePinnedBinary('gitleaks', s.cache, third).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PinnedBinaryError);
    expect(String((err as Error).message)).toMatch(/cached.*gitleaks.*(changed|checksum).*deleted/i);
    expect(existsSync(path)).toBe(false);
    expect(third.calls).toEqual([]);
    expect(existsSync(s.marker)).toBe(false);
    // the next call downloads a fresh, verified copy
    expect(await ensurePinnedBinary('gitleaks', s.cache, s.deps())).toBe(path);
    expect(readFileSync(path).equals(s.binary)).toBe(true);
  });

  it('ensurePinnedBinary: archive checksum checked before unpacking (a bad archive is never parsed)', async () => {
    // not even gzip: if it were unpacked first, the error would be about the format, not the checksum
    const s = setup({ asset: () => ({ archiveSha256: sha256('the real archive') }), archive: () => Buffer.from('not a gzip stream at all') });
    const err = await ensurePinnedBinary('gitleaks', s.cache, s.deps()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PinnedBinaryError);
    expect(String((err as Error).message)).toMatch(/download.*checksum/i);
    expect(filesIn(join(s.cache, `gitleaks-${VERSION}`))).toEqual([]);
  });

  it('ensurePinnedBinary: a cached file that is a symlink is removed (not followed) and refused', async () => {
    const s = setup();
    const toolDir = join(s.cache, `gitleaks-${VERSION}`);
    mkdirSync(toolDir, { recursive: true, mode: 0o700 });
    chmodSync(s.cache, 0o700);
    const elsewhere = join(s.dir, 'elsewhere');
    writeFileSync(elsewhere, s.binary);
    symlinkSync(elsewhere, join(toolDir, 'gitleaks'));
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).rejects.toThrow(/cached gitleaks.*symbolic link.*deleted/i);
    expect(existsSync(join(toolDir, 'gitleaks'))).toBe(false);
    expect(readFileSync(elsewhere).equals(s.binary)).toBe(true); // the link target is untouched
  });
});

describe('ensurePinnedBinary: tar reader', () => {
  const refused: [string, (bin: Buffer) => TarEntry[], RegExp][] = [
    ['path traversal (..)', (bin) => [{ name: '../gitleaks', content: bin }], /unsafe path/i],
    ['traversal through the prefix field', (bin) => [{ name: 'gitleaks', prefix: '..', content: bin }], /unsafe path/i],
    ['absolute path', (bin) => [{ name: '/gitleaks', content: bin }], /unsafe path/i],
    ['backslash path', (bin) => [{ name: 'a\\..\\gitleaks', content: bin }, { name: 'gitleaks', content: bin }], /unsafe path/i],
    ['symlink as the binary', () => [{ name: 'gitleaks', type: '2', linkname: '/bin/sh' }], /link/i],
    ['symlink elsewhere in the archive', (bin) => [{ name: 'README.md', type: '2', linkname: '/etc/passwd' }, { name: 'gitleaks', content: bin }], /link/i],
    ['hardlink', (bin) => [{ name: 'LICENSE', content: 'x' }, { name: 'gitleaks', type: '1', linkname: 'LICENSE' }, { name: 'other', content: bin }], /link/i],
    ['character device', (bin) => [{ name: 'tty', type: '3' }, { name: 'gitleaks', content: bin }], /device/i],
    ['block device', (bin) => [{ name: 'disk', type: '4' }, { name: 'gitleaks', content: bin }], /device/i],
    ['pax header (could rename an entry)', (bin) => [{ name: 'PaxHeader', type: 'x', content: '30 path=../../escape\n' }, { name: 'gitleaks', content: bin }], /entry type/i],
    ['the binary twice', (bin) => [{ name: 'gitleaks', content: bin }, { name: 'gitleaks', content: bin }], /more than once/i],
    ['the binary missing', () => [{ name: 'LICENSE', content: 'x' }], /no gitleaks/i],
    ['a corrupt header checksum', (bin) => [{ name: 'gitleaks', content: bin, badChecksum: true }], /corrupt|checksum/i],
    ['a non-ustar header', (bin) => [{ name: 'gitleaks', content: bin, magic: 'xxxxx\u000000' }], /ustar|format/i],
    ['a size beyond the data', (bin) => [{ name: 'gitleaks', content: bin, size: 999_999 }], /truncated|corrupt/i],
  ];
  for (const [what, entries, message] of refused) {
    it(`ensurePinnedBinary: tar with ${what} → refused, nothing written`, async () => {
      // the archive hash is honest (it is "upstream's"), so these checks are the tar reader's own
      const s = setup({ entries });
      const err = await ensurePinnedBinary('gitleaks', s.cache, s.deps()).catch((e: unknown) => e);
      expect(err, what).toBeInstanceOf(PinnedBinaryError);
      expect(String((err as Error).message)).toMatch(message);
      expect(filesIn(join(s.cache, `gitleaks-${VERSION}`))).toEqual([]);
      expect(existsSync(join(s.dir, 'escape'))).toBe(false);
    });
  }

  it('ensurePinnedBinary: GNU-format tar: the prefix field (GNU keeps times there) is ignored', async () => {
    const s = setup({ entries: (bin) => [{ name: 'gitleaks', content: bin, magic: 'ustar  \u0000', prefix: '14567123456' }] });
    expect(readFileSync(await ensurePinnedBinary('gitleaks', s.cache, s.deps())).equals(s.binary)).toBe(true);
  });

  it('ensurePinnedBinary: tar member bigger than the pinned binary size → refused before it is copied out', async () => {
    const s = setup({ asset: (a) => ({ binarySize: a.binarySize - 1 }) });
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).rejects.toThrow(/gitleaks.*larger than/i);
    expect(filesIn(join(s.cache, `gitleaks-${VERSION}`))).toEqual([]);
  });

  it('ensurePinnedBinary: unpacked archive size is bounded (a gzip bomb is refused)', async () => {
    const bomb = Buffer.alloc(17 * 1024 * 1024); // compresses to a few KB, unpacks past the bound
    const s = setup({ entries: (bin) => [{ name: 'filler', content: bomb }, { name: 'gitleaks', content: bin }] });
    expect(s.archive.length).toBeLessThan(100_000);
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).rejects.toThrow(/unpack.*too large/i);
  });
});

describe('ensurePinnedBinary: download', () => {
  it('ensurePinnedBinary: a download bigger than the pinned archive size → refused', async () => {
    const s = setup({ asset: (a) => ({ archiveSize: a.archiveSize - 1 }) });
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).rejects.toThrow(/too large/i);
    expect(filesIn(join(s.cache, `gitleaks-${VERSION}`))).toEqual([]);
  });

  it('ensurePinnedBinary: a redirect to a host outside GitHub release downloads → refused', async () => {
    const s = setup();
    s.routes[`GET ${DL}${URL_PATH}`] = { status: 302, headers: { location: 'https://evil.example.com/gitleaks.tar.gz' } };
    const deps = s.deps();
    await expect(ensurePinnedBinary('gitleaks', s.cache, deps)).rejects.toThrow(/not an allowed https host/i);
    expect(deps.calls.map((c) => c.url.hostname)).toEqual(['github.com']);
  });

  it('ensurePinnedBinary: a redirect to plain http → refused', async () => {
    const s = setup();
    s.routes[`GET ${DL}${URL_PATH}`] = { status: 302, headers: { location: `http://release-assets.githubusercontent.com${ASSET_PATH}` } };
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).rejects.toThrow(/not an allowed https host/i);
  });

  it('ensurePinnedBinary: a raw binary asset (cosign: archive none) is verified and written as is', async () => {
    const s = setup();
    const binary = s.binary;
    const url = `${DL}/sigstore/cosign/releases/download/v${VERSION}/cosign-linux-amd64`;
    const raw = { url, archive: 'none' as const, archiveSize: binary.length, archiveSha256: sha256(binary), binarySize: binary.length, binarySha256: sha256(binary) };
    s.pins.cosign = { ...s.pins.cosign, platforms: { 'linux-x64': raw, 'linux-arm64': raw, 'darwin-x64': raw, 'darwin-arm64': raw } };
    s.routes[`GET ${url}`] = { raw: binary };
    const path = await ensurePinnedBinary('cosign', s.cache, s.deps());
    expect(path).toBe(join(s.cache, `cosign-${VERSION}`, 'cosign'));
    expect(readFileSync(path).equals(binary)).toBe(true);
    expect(modeOf(path)).toBe(0o700);
  });
});

describe('ensurePinnedBinary: cache directory', () => {
  /** A home dir (0700) under the test dir; `.cache` inside it when `cacheMode` is given. */
  function homeWith(s: Setup, cacheMode?: number): string {
    const home = join(s.dir, 'home');
    mkdirSync(home, { mode: 0o700 });
    if (cacheMode !== undefined) {
      mkdirSync(join(home, '.cache'));
      chmodSync(join(home, '.cache'), cacheMode);
    }
    return home;
  }

  it('ensurePinnedBinary: default cache is ~/.cache/pipegen/tools/<name>-<version>, every level created 0700', async () => {
    const s = setup();
    const home = homeWith(s);
    const path = await ensurePinnedBinary('gitleaks', undefined, s.deps({ home }));
    expect(path).toBe(join(home, '.cache', 'pipegen', 'tools', `gitleaks-${VERSION}`, 'gitleaks'));
    for (const level of ['.cache', '.cache/pipegen', '.cache/pipegen/tools', `.cache/pipegen/tools/gitleaks-${VERSION}`]) {
      expect(modeOf(join(home, level)), level).toBe(0o700);
    }
  });

  it('ensurePinnedBinary: XDG_CACHE_HOME is honoured when absolute, ignored when relative', async () => {
    const s = setup();
    const home = homeWith(s);
    const xdg = join(s.dir, 'xdg', 'cache');
    const path = await ensurePinnedBinary('gitleaks', undefined, s.deps({ home, env: { XDG_CACHE_HOME: xdg } }));
    expect(path).toBe(join(xdg, 'pipegen', 'tools', `gitleaks-${VERSION}`, 'gitleaks'));
    const relative = await ensurePinnedBinary('gitleaks', undefined, s.deps({ home, env: { XDG_CACHE_HOME: 'rel/cache' } }));
    expect(relative).toBe(join(home, '.cache', 'pipegen', 'tools', `gitleaks-${VERSION}`, 'gitleaks'));
  });

  it('ensurePinnedBinary: a group-writable ~/.cache (0775) → refused, naming the folder and the fix', async () => {
    const s = setup();
    const home = homeWith(s, 0o775);
    const deps = s.deps({ home });
    const err = await ensurePinnedBinary('gitleaks', undefined, deps).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PinnedBinaryError);
    expect(String((err as Error).message)).toContain(join(home, '.cache'));
    expect(String((err as Error).message)).toMatch(/other users can write to it.*chmod g-w,o-w/i);
    expect(deps.calls).toEqual([]);
  });

  it('ensurePinnedBinary: a world-writable home (0777) → refused (the path above the cache counts too)', async () => {
    const s = setup();
    const home = homeWith(s);
    chmodSync(home, 0o777);
    await expect(ensurePinnedBinary('gitleaks', undefined, s.deps({ home }))).rejects.toThrow(new RegExp(`${home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.*other users can write`));
  });

  it('ensurePinnedBinary: a sticky world-writable folder not owned by root (1777) → refused', async () => {
    const s = setup();
    const home = homeWith(s, 0o1777);
    await expect(ensurePinnedBinary('gitleaks', undefined, s.deps({ home }))).rejects.toThrow(/other users can write/i);
  });

  it.runIf(statSync(tmpdir()).uid === 0 && (statSync(tmpdir()).mode & 0o1000) !== 0)('ensurePinnedBinary: a root-owned sticky ancestor (the system temp dir) is accepted', async () => {
    const s = setup();
    expect(s.dir.startsWith(tmpdir())).toBe(true);
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).resolves.toBe(join(s.cache, `gitleaks-${VERSION}`, 'gitleaks'));
  });

  it("ensurePinnedBinary: group write on pipegen's own level (~/.cache/pipegen 0770) → refused", async () => {
    const s = setup();
    const home = homeWith(s, 0o700);
    mkdirSync(join(home, '.cache', 'pipegen'));
    chmodSync(join(home, '.cache', 'pipegen'), 0o770);
    await expect(ensurePinnedBinary('gitleaks', undefined, s.deps({ home }))).rejects.toThrow(/pipegen.*other users can write/i);
  });

  it('ensurePinnedBinary: a symlinked ~/.cache pointing to a safe real folder is accepted (checked on its real path)', async () => {
    const s = setup();
    const home = homeWith(s);
    const real = join(s.dir, 'real-cache');
    mkdirSync(real, { mode: 0o700 });
    symlinkSync(real, join(home, '.cache'));
    const path = await ensurePinnedBinary('gitleaks', undefined, s.deps({ home }));
    expect(path).toBe(join(real, 'pipegen', 'tools', `gitleaks-${VERSION}`, 'gitleaks'));
  });

  it('ensurePinnedBinary: a symlinked ~/.cache pointing to an unsafe folder → refused', async () => {
    const s = setup();
    const home = homeWith(s);
    const real = join(s.dir, 'real-cache');
    mkdirSync(real);
    chmodSync(real, 0o777);
    symlinkSync(real, join(home, '.cache'));
    await expect(ensurePinnedBinary('gitleaks', undefined, s.deps({ home }))).rejects.toThrow(/other users can write/i);
  });

  it("ensurePinnedBinary: a symlink at pipegen's own levels (pipegen/, the tool dir) → refused", async () => {
    const s = setup();
    const home = homeWith(s, 0o700);
    const other = join(s.dir, 'attacker');
    mkdirSync(other, { mode: 0o700 });
    symlinkSync(other, join(home, '.cache', 'pipegen'));
    await expect(ensurePinnedBinary('gitleaks', undefined, s.deps({ home }))).rejects.toThrow(/symbolic link/i);
    const s2 = setup();
    mkdirSync(s2.cache, { mode: 0o700 });
    symlinkSync(other, join(s2.cache, `gitleaks-${VERSION}`));
    await expect(ensurePinnedBinary('gitleaks', s2.cache, s2.deps())).rejects.toThrow(/symbolic link/i);
    expect(readdirSync(other)).toEqual([]);
  });

  it('ensurePinnedBinary: a given cache dir that is a symlink to a safe folder is used on its real path', async () => {
    const s = setup();
    const real = join(s.dir, 'real-tools');
    mkdirSync(real, { mode: 0o700 });
    symlinkSync(real, s.cache);
    expect(await ensurePinnedBinary('gitleaks', s.cache, s.deps())).toBe(join(real, `gitleaks-${VERSION}`, 'gitleaks'));
  });

  it('ensurePinnedBinary: a cache dir owned by another user → refused before any download', async () => {
    const s = setup();
    const uid = (process.getuid?.() ?? 0) + 1;
    const deps = s.deps({ uid });
    await expect(ensurePinnedBinary('gitleaks', s.cache, deps)).rejects.toThrow(/is not owned by you/i);
    expect(deps.calls).toEqual([]);
  });

  it('ensurePinnedBinary: a cache dir others can write to → refused', async () => {
    const s = setup();
    mkdirSync(s.cache, { mode: 0o700 });
    chmodSync(s.cache, 0o777);
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).rejects.toThrow(/other users can write/i);
  });

  it('ensurePinnedBinary: stale temp files (over 1 hour old) are removed; fresh ones, links and other files are kept', async () => {
    const s = setup();
    const toolDir = join(s.cache, `gitleaks-${VERSION}`);
    mkdirSync(toolDir, { recursive: true, mode: 0o700 });
    const old = (NOW - 2 * 3_600_000) / 1000;
    const stale = join(toolDir, '.gitleaks-aaaaaaaaaaaaaaaa.tmp');
    const fresh = join(toolDir, '.gitleaks-bbbbbbbbbbbbbbbb.tmp');
    const link = join(toolDir, '.gitleaks-cccccccccccccccc.tmp');
    const other = join(toolDir, 'notes.txt');
    for (const f of [stale, fresh, other]) writeFileSync(f, 'x');
    symlinkSync(join(s.dir, 'nowhere'), link);
    utimesSync(stale, old, old);
    utimesSync(other, old, old);
    lutimesSync(link, old, old);
    utimesSync(fresh, (NOW - 60_000) / 1000, (NOW - 60_000) / 1000);
    await ensurePinnedBinary('gitleaks', s.cache, s.deps());
    expect(filesIn(toolDir).sort()).toEqual(['.gitleaks-bbbbbbbbbbbbbbbb.tmp', '.gitleaks-cccccccccccccccc.tmp', 'gitleaks', 'notes.txt']);
  });
});

describe('ensurePinnedBinary: parallel first runs', () => {
  it('ensurePinnedBinary: 8 parallel first-run calls all succeed and never delete the good binary (5 rounds)', async () => {
    const s = setup();
    const home = join(s.dir, 'home');
    mkdirSync(home, { mode: 0o700 });
    for (let round = 0; round < 5; round++) {
      rmSync(join(home, '.cache'), { recursive: true, force: true });
      const results = await Promise.allSettled(Array.from({ length: 8 }, () => ensurePinnedBinary('gitleaks', undefined, s.deps({ home }))));
      const failed = results.filter((r) => r.status === 'rejected').map((r) => String((r as PromiseRejectedResult).reason));
      expect(failed, `round ${round}`).toEqual([]);
      const path = join(home, '.cache', 'pipegen', 'tools', `gitleaks-${VERSION}`, 'gitleaks');
      expect(readFileSync(path).equals(s.binary), `round ${round}`).toBe(true);
      expect(filesIn(dirname(path)), `round ${round}`).toEqual(['gitleaks']);
    }
  });

  it('ensurePinnedBinary: a cached copy removed by another run is downloaded again (not reported as tampering)', async () => {
    const s = setup();
    const path = await ensurePinnedBinary('gitleaks', s.cache, s.deps());
    rmSync(path);
    expect(await ensurePinnedBinary('gitleaks', s.cache, s.deps())).toBe(path);
  });
});

describe('ensurePinnedBinary: platforms', () => {
  it('ensurePinnedBinary: linux and darwin on x64 and arm64 each use their own asset', async () => {
    const s = setup();
    for (const [platform, arch] of [['linux', 'x64'], ['linux', 'arm64'], ['darwin', 'x64'], ['darwin', 'arm64']] as const) {
      const key = `${platform}-${arch}` as const;
      const url = `${DL}/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_${key}.tar.gz`;
      s.pins.gitleaks.platforms[key] = { ...s.pins.gitleaks.platforms[key], url };
      s.routes[`GET ${url}`] = { raw: s.archive };
      const deps = s.deps({ platform, arch });
      const path = await ensurePinnedBinary('gitleaks', join(s.dir, key), deps);
      expect(readFileSync(path).equals(s.binary)).toBe(true);
      expect(deps.calls[0]?.url.href).toBe(url);
    }
  });

  for (const [platform, arch] of [['win32', 'x64'], ['freebsd', 'x64'], ['linux', 'ia32'], ['darwin', 'ppc64']]) {
    it(`ensurePinnedBinary: ${platform}-${arch} → a clear, tool-neutral "Linux or macOS" error, nothing downloaded`, async () => {
      const s = setup();
      const deps = s.deps({ platform, arch });
      await expect(ensurePinnedBinary('cosign', s.cache, deps)).rejects.toThrow(/pipegen's cosign download needs Linux or macOS for now \(WSL works\)/);
      expect(deps.calls).toEqual([]);
    });
  }

  it('ensurePinnedBinary: the release date is not re-checked at run time (the data-file test holds the cooldown)', async () => {
    const s = setup({ releasedAt: new Date(NOW - 3 * DAY).toISOString() });
    await expect(ensurePinnedBinary('gitleaks', s.cache, s.deps())).resolves.toContain('gitleaks');
  });

  it('ensurePinnedBinary: an unknown tool name → refused', async () => {
    const s = setup();
    await expect(ensurePinnedBinary('curl' as 'gitleaks', s.cache, s.deps())).rejects.toThrow(/no pinned binary/i);
  });
});

describe('pinned-binaries.yml', () => {
  const HEX = /^[0-9a-f]{64}$/;

  it('pinned-binaries.yml: gitleaks, actionlint and cosign pinned for linux and darwin, x64 and arm64, with both hashes', () => {
    const pins = loadPinnedBinaries();
    expect(Object.keys(pins).sort()).toEqual(['actionlint', 'cosign', 'gitleaks']);
    for (const [name, entry] of Object.entries(pins)) {
      expect(Object.keys(entry.platforms).sort(), name).toEqual(['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64']);
      for (const [key, a] of Object.entries(entry.platforms)) {
        expect(a.archiveSha256, `${name} ${key}`).toMatch(HEX);
        expect(a.binarySha256, `${name} ${key}`).toMatch(HEX);
        expect(a.url.startsWith(`https://github.com/${entry.repo}/releases/download/v${entry.version}/`), `${name} ${key}`).toBe(true);
        if (name === 'cosign') {
          expect(a.archive).toBe('none');
          expect(a.archiveSha256).toBe(a.binarySha256);
        } else {
          expect(a.archive).toBe('tar.gz');
          expect(a.archiveSha256).not.toBe(a.binarySha256);
        }
      }
    }
  });

  it(`pinned-binaries.yml: every release was at least ${COOLDOWN_DAYS} days old when pinned (ruling S26)`, () => {
    const pinnedOn = Date.parse('2026-10-26T00:00:00Z');
    for (const [name, entry] of Object.entries(loadPinnedBinaries())) {
      expect(pinnedOn - Date.parse(entry.releasedAt), name).toBeGreaterThanOrEqual(COOLDOWN_DAYS * DAY);
    }
  });

  it('pinned-binaries.yml: the loader refuses non-https, non-GitHub, mismatched or malformed entries', () => {
    const good = loadPinnedBinaries();
    const asset = good.gitleaks.platforms['linux-x64'];
    const withAsset = (over: Record<string, unknown>) => ({ ...good, gitleaks: { ...good.gitleaks, platforms: { ...good.gitleaks.platforms, 'linux-x64': { ...asset, ...over } } } });
    expect(pinnedBinariesSchema.safeParse(good).success).toBe(true);
    const bad: [string, unknown][] = [
      ['http', withAsset({ url: asset.url.replace('https:', 'http:') })],
      ['other host', withAsset({ url: asset.url.replace('github.com', 'evil.example.com') })],
      ['other repo', withAsset({ url: asset.url.replace('gitleaks/gitleaks', 'gitIeaks/gitleaks') })],
      ['other version', withAsset({ url: asset.url.replace(`v${good.gitleaks.version}`, 'v0.0.1') })],
      ['url with a query', withAsset({ url: `${asset.url}?x=1` })],
      ['bad sha256', withAsset({ archiveSha256: 'abc' })],
      ['zero size', withAsset({ binarySize: 0 })],
      ['raw binary with two hashes', withAsset({ archive: 'none' })],
      ['unknown field', withAsset({ extra: 1 })],
      ['missing platform', { ...good, gitleaks: { ...good.gitleaks, platforms: { 'linux-x64': asset } } }],
      ['member with a slash', { ...good, gitleaks: { ...good.gitleaks, member: '../gitleaks' } }],
      ['missing tool', { gitleaks: good.gitleaks, actionlint: good.actionlint }],
    ];
    for (const [what, value] of bad) expect(pinnedBinariesSchema.safeParse(value).success, what).toBe(false);
  });
});

describe('checkPinnedAgainstReviewed (ruling S25)', () => {
  /** `asset`: the release asset the entry installs (S25 compares the hash to that platform's). */
  const reviewedCli = (repo: string, version: string, checksum?: string, asset?: string): ReviewedTool => {
    const candidate: Candidate = {
      id: repo.split('/')[1] ?? repo, name: repo, kind: 'cli', repo, version, pin: checksum === undefined ? {} : { checksum },
      source: 'reviewed', reviewed: true, categories: ['workflow-lint'],
    };
    return {
      id: candidate.id, categories: candidate.categories, languages: ['any'], candidate,
      step: {
        ...(asset === undefined ? {} : { cli: { install: { method: 'github-release', package: asset, version }, command: ['tool'] } }),
        output: { path: 'out', format: 'none' },
      },
      fixedInputs: {}, choices: {}, configFiles: [],
      reviewedBy: 'reviewer', reviewedAt: '2026-10-01', proofs: 0,
    };
  };

  it('checkPinnedAgainstReviewed: same version and hash → no problem; a tool only in one file is ignored', () => {
    const pins = loadPinnedBinaries();
    const a = pins.actionlint;
    const assetOf = (k: 'linux-x64' | 'linux-arm64') => a.platforms[k].url.split('/').pop() as string;
    const list = [
      reviewedCli('rhysd/actionlint', `v${a.version}`, a.platforms['linux-x64'].archiveSha256, assetOf('linux-x64')),
      reviewedCli('zizmorcore/zizmor', 'v1.0.0', 'f'.repeat(64)),
    ];
    expect(checkPinnedAgainstReviewed(pins, list)).toEqual([]);
    // the extracted binary's hash is the same tool too
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', a.version, a.platforms['linux-arm64'].binarySha256, assetOf('linux-arm64'))])).toEqual([]);
  });

  it('checkPinnedAgainstReviewed: the hash must be the one of the platform the install names (M5)', () => {
    const pins = loadPinnedBinaries();
    const a = pins.actionlint;
    const x64 = a.platforms['linux-x64'].url.split('/').pop() as string;
    // another platform's hash (a real actionlint hash, but not of the asset the entry installs)
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', `v${a.version}`, a.platforms['darwin-arm64'].archiveSha256, x64)]).join('\n'))
      .toMatch(/actionlint.*linux-x64/i);
    // an asset pinned-binaries.yml doesn't list, or no asset at all
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', `v${a.version}`, a.platforms['linux-x64'].archiveSha256, 'actionlint_other.tar.gz')]).join('\n'))
      .toMatch(/actionlint.*asset/i);
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', `v${a.version}`, a.platforms['linux-x64'].archiveSha256)]).join('\n'))
      .toMatch(/actionlint.*asset/i);
  });

  it('checkPinnedAgainstReviewed: another version, another hash, or no hash → a problem naming the tool', () => {
    const pins = loadPinnedBinaries();
    const a = pins.actionlint;
    const sum = a.platforms['linux-x64'].archiveSha256;
    const x64 = a.platforms['linux-x64'].url.split('/').pop() as string;
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', 'v1.0.0', sum, x64)]).join('\n')).toMatch(/actionlint.*version/i);
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', `v${a.version}`, 'e'.repeat(64), x64)]).join('\n')).toMatch(/actionlint.*hash/i);
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('rhysd/actionlint', `v${a.version}`, undefined, x64)]).join('\n')).toMatch(/actionlint.*no hash/i);
    expect(checkPinnedAgainstReviewed(pins, [reviewedCli('Sigstore/Cosign', 'v0.1.0', sum)]).join('\n')).toMatch(/cosign/i);
  });
});
