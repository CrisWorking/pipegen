// Live check of every platform's archiveSha256 in data/pinned-binaries.yml (Plan P final review m4). The scanners and
// cosign run on users' Macs and arm64 Linux too, but only linux-x64 was ever checked against upstream's signed checksums
// (reviewed-verify-live, and the live scanner tests that run on ubuntu). Here every platform of every pinned tool must
// be listed, with its exact sha256 and asset name, in the release's own checksums file, and that file must verify with
// pipegen's pinned cosign where upstream signs it:
//   - betterleaks: checksums.txt, keyless, signed by its release workflow at the pinned tag;
//   - cosign: cosign_checksums.txt, keyless, signed by the Sigstore project's release identity;
//   - gitleaks and actionlint: upstream publishes no signature for the checksums file, so it is only checked to list
//     every pin (download over https from github.com). The per-PR cooldown ties each archive to GitHub's asset digest.
// Network: the pinned cosign (once, into ~/.cache/pipegen/tools) and the checksums files and bundles from github.com.
// Nothing downloaded runs but cosign. Skipped unless PIPEGEN_LIVE_TESTS=1, so `npm test` stays offline.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { downloadRelease } from '../src/engine/pin.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const MAX = 1024 * 1024;
const GH_ISSUER = 'https://token.actions.githubusercontent.com';

interface Platform { url: string; archiveSha256: string }
interface Tool { version: string; repo: string; platforms: Record<string, Platform> }
const TOOLS = parse(readFileSync(new URL('../data/pinned-binaries.yml', import.meta.url), 'utf8')) as Record<string, Tool>;

/** Where each tool's checksums file is, and who must have signed it (null: upstream does not sign it). */
const SUMS: Record<string, (v: string) => { file: string; signer: { identity: string; issuer: string } | null }> = {
  betterleaks: (v) => ({ file: 'checksums.txt', signer: { identity: `https://github.com/betterleaks/betterleaks/.github/workflows/release.yml@refs/tags/v${v}`, issuer: GH_ISSUER } }),
  cosign: () => ({ file: 'cosign_checksums.txt', signer: { identity: 'keyless@projectsigstore.iam.gserviceaccount.com', issuer: 'https://accounts.google.com' } }),
  gitleaks: (v) => ({ file: `gitleaks_${v}_checksums.txt`, signer: null }),
  actionlint: (v) => ({ file: `actionlint_${v}_checksums.txt`, signer: null }),
};

let cosign = '';

/** A release file of `tool`, saved in `dir`; returns its text. */
async function releaseFile(tool: Tool, name: string, dir: string): Promise<string> {
  const url = `https://github.com/${tool.repo}/releases/download/v${encodeURIComponent(tool.version)}/${encodeURIComponent(name)}`;
  const bytes = Buffer.from(await downloadRelease(fetch, url, MAX));
  writeFileSync(join(dir, name), bytes);
  return bytes.toString('utf8');
}

function verifyBlob(file: string, signer: { identity: string; issuer: string }, cwd: string): { code: number; out: string } {
  const r = spawnSync(cosign, ['verify-blob', '--bundle', `${file}.sigstore.json`, '--certificate-identity', signer.identity, '--certificate-oidc-issuer', signer.issuer, file], { cwd, encoding: 'utf8', timeout: 120_000 });
  if (r.error !== undefined || typeof r.status !== 'number') throw r.error ?? new Error('cosign did not exit');
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

/** `<sha256>  <name>` lines of a checksums file (a `*` before the name, binary mode, is allowed). */
const listed = (text: string): Set<string> => new Set(text.split(/\r?\n/).map((l) => l.trim().split(/\s+\*?/).join(' ')).filter((l) => l !== ''));
const assetOf = (url: string): string => decodeURIComponent(url.slice(url.lastIndexOf('/') + 1));

describe.skipIf(!live)('pinned binaries: every platform hash against the release checksums (live, pinned cosign)', () => {
  beforeAll(async () => {
    cosign = await ensurePinnedBinary('cosign');
  }, 600_000);
  afterAll(cleanupRepos);

  it('live: every pinned tool has a known checksums file; the scanners and cosign are signed upstream', () => {
    expect(Object.keys(TOOLS).sort()).toEqual(Object.keys(SUMS).sort());
    for (const name of ['betterleaks', 'cosign']) expect(SUMS[name]?.(TOOLS[name]?.version as string).signer, name).not.toBeNull();
  });

  it('live: each checksums file verifies (where signed) and lists every platform\'s archiveSha256 for its asset', async () => {
    for (const [name, tool] of Object.entries(TOOLS)) {
      const { file, signer } = (SUMS[name] as (v: string) => { file: string; signer: { identity: string; issuer: string } | null })(tool.version);
      const dir = makeTempDir();
      const sums = listed(await releaseFile(tool, file, dir));
      if (signer !== null) {
        await releaseFile(tool, `${file}.sigstore.json`, dir);
        const r = verifyBlob(file, signer, dir);
        console.log(`${name} ${tool.version}: cosign verify-blob --certificate-identity ${signer.identity} ${file} → exit ${r.code} ${r.out.trim()}`);
        expect(r.code, `${name}: ${r.out}`).toBe(0);
      } else {
        console.log(`${name} ${tool.version}: ${file} is not signed upstream; checked for every pin only`);
      }
      const platforms = Object.entries(tool.platforms);
      expect(platforms.length, name).toBe(4);
      for (const [platform, p] of platforms) {
        expect(sums.has(`${p.archiveSha256} ${assetOf(p.url)}`), `${name} ${platform}: ${assetOf(p.url)} with the pinned sha256 is not in ${file}`).toBe(true);
      }
    }
  }, 900_000);

  it('live: negative controls (a changed hash is not listed; another identity does not verify)', async () => {
    const tool = TOOLS.betterleaks as Tool;
    const dir = makeTempDir();
    const sums = listed(await releaseFile(tool, 'checksums.txt', dir));
    const p = tool.platforms['darwin-arm64'] as Platform;
    const flipped = (p.archiveSha256[0] === '0' ? '1' : '0') + p.archiveSha256.slice(1);
    expect(sums.has(`${flipped} ${assetOf(p.url)}`)).toBe(false);
    await releaseFile(tool, 'checksums.txt.sigstore.json', dir);
    const wrongTag = verifyBlob('checksums.txt', { identity: `https://github.com/betterleaks/betterleaks/.github/workflows/release.yml@refs/tags/v1.8.0`, issuer: GH_ISSUER }, dir);
    expect(wrongTag.code).not.toBe(0);
    const cdir = makeTempDir();
    await releaseFile(TOOLS.cosign as Tool, 'cosign_checksums.txt', cdir);
    await releaseFile(TOOLS.cosign as Tool, 'cosign_checksums.txt.sigstore.json', cdir);
    expect(verifyBlob('cosign_checksums.txt', { identity: 'someone@example.com', issuer: 'https://accounts.google.com' }, cdir).code).not.toBe(0);
  }, 600_000);
});
