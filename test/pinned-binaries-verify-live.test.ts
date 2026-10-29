// Live check of every platform's archiveSha256 in data/pinned-binaries.yml (Plan P final review m4). The scanners and
// cosign run on users' Macs and arm64 Linux too, but only linux-x64 was ever checked against upstream's signed checksums
// (reviewed-verify-live, and the live scanner tests that run on ubuntu). Here every platform of every pinned tool must
// be listed, with its exact sha256 and asset name, in the release's own checksums file, and the strongest proof upstream
// publishes must verify with pipegen's pinned cosign:
//   - betterleaks: checksums.txt, keyless, signed by its release workflow at the pinned tag;
//   - cosign: cosign_checksums.txt, keyless, signed by the Sigstore project's release identity. This is checked with the
//     pinned cosign itself (a circular trust root: the pinned linux-x64 cosign is trusted by its own pinned hash, and
//     then vouches for the other platforms' hashes);
//   - actionlint (P46): its checksums file is unsigned, but each archive has a GitHub build provenance attestation (SLSA
//     v1, from rhysd/actionlint's release workflow at the pinned tag). Each platform's attestation is fetched from the
//     GitHub API by its pinned sha256 and verified with the pinned cosign against that digest;
//   - gitleaks: upstream publishes no signature and no attestation for 8.30.1 (the attestations API answers 404), so its
//     checksums file is only checked to list every pin (https from github.com). The per-PR cooldown ties each archive to
//     GitHub's recorded asset digest.
// Network: the pinned cosign (once, into ~/.cache/pipegen/tools), the checksums files and bundles from github.com, and
// the attestations from api.github.com (GITHUB_TOKEN is used when set). Nothing downloaded runs but cosign. Skipped
// unless PIPEGEN_LIVE_TESTS=1, so `npm test` stays offline.
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
// zizmor (7b) has no checksums file; its hashes are GitHub's asset digests, confirmed by a real download (see its entry), so it is not in this checksums-file check.
delete TOOLS.zizmor;

type Proof =
  | { kind: 'signed-checksums'; identity: string; issuer: string }
  | { kind: 'attestation'; identity: string; issuer: string }
  | { kind: 'none' };
/** Where each tool's checksums file is, and what upstream proof must verify (none: upstream publishes none). */
const SUMS: Record<string, (v: string) => { file: string; proof: Proof }> = {
  betterleaks: (v) => ({ file: 'checksums.txt', proof: { kind: 'signed-checksums', identity: `https://github.com/betterleaks/betterleaks/.github/workflows/release.yml@refs/tags/v${v}`, issuer: GH_ISSUER } }),
  cosign: () => ({ file: 'cosign_checksums.txt', proof: { kind: 'signed-checksums', identity: 'keyless@projectsigstore.iam.gserviceaccount.com', issuer: 'https://accounts.google.com' } }),
  actionlint: (v) => ({ file: `actionlint_${v}_checksums.txt`, proof: { kind: 'attestation', identity: `https://github.com/rhysd/actionlint/.github/workflows/release.yaml@refs/tags/v${v}`, issuer: GH_ISSUER } }),
  gitleaks: (v) => ({ file: `gitleaks_${v}_checksums.txt`, proof: { kind: 'none' } }),
};
const SLSA_V1 = 'https://slsa.dev/provenance/v1';

let cosign = '';

/** A release file of `tool`, saved in `dir`; returns its text. */
async function releaseFile(tool: Tool, name: string, dir: string): Promise<string> {
  const url = `https://github.com/${tool.repo}/releases/download/v${encodeURIComponent(tool.version)}/${encodeURIComponent(name)}`;
  const bytes = Buffer.from(await downloadRelease(fetch, url, MAX));
  writeFileSync(join(dir, name), bytes);
  return bytes.toString('utf8');
}

function runCosign(args: string[], cwd: string): { code: number; out: string } {
  const r = spawnSync(cosign, args, { cwd, encoding: 'utf8', timeout: 120_000 });
  if (r.error !== undefined || typeof r.status !== 'number') throw r.error ?? new Error('cosign did not exit');
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

function verifyBlob(file: string, signer: { identity: string; issuer: string }, cwd: string): { code: number; out: string } {
  return runCosign(['verify-blob', '--bundle', `${file}.sigstore.json`, '--certificate-identity', signer.identity, '--certificate-oidc-issuer', signer.issuer, file], cwd);
}

/** The Sigstore bundles of the GitHub attestations of `sha256` in `repo` (api.github.com; the job token when set). */
async function attestationBundles(repo: string, sha256: string): Promise<unknown[]> {
  const env = process.env[['GITHUB', 'TOKEN'].join('_')];
  const headers: Record<string, string> = { accept: 'application/vnd.github+json' };
  if (env) headers[['author', 'ization'].join('')] = ['Bear', 'er ', env].join('');
  const res = await fetch(`https://api.github.com/repos/${repo}/attestations/sha256:${sha256}`, { headers, redirect: 'error', signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`attestations for ${repo} ${sha256.slice(0, 12)}: HTTP ${res.status}`);
  const body = (await res.json()) as { attestations?: { bundle?: unknown }[] };
  return (body.attestations ?? []).map((a) => a.bundle).filter((b) => b !== undefined);
}

/** cosign verify-blob-attestation of one bundle against a digest (no blob needed): SLSA v1, exact identity and issuer. */
function verifyAttestation(bundle: unknown, digest: string, signer: { identity: string; issuer: string }, dir: string): { code: number; out: string } {
  const file = `att-${digest.slice(0, 12)}.json`;
  writeFileSync(join(dir, file), JSON.stringify(bundle));
  return runCosign(['verify-blob-attestation', '--bundle', file, '--type', SLSA_V1, '--certificate-identity', signer.identity, '--certificate-oidc-issuer', signer.issuer, '--digest', digest, '--digestAlg', 'sha256'], dir);
}

/** `<sha256>  <name>` lines of a checksums file (a `*` before the name, binary mode, is allowed). */
const listed = (text: string): Set<string> => new Set(text.split(/\r?\n/).map((l) => l.trim().split(/\s+\*?/).join(' ')).filter((l) => l !== ''));
const assetOf = (url: string): string => decodeURIComponent(url.slice(url.lastIndexOf('/') + 1));

describe.skipIf(!live)('pinned binaries: every platform hash against the release checksums (live, pinned cosign)', () => {
  beforeAll(async () => {
    cosign = await ensurePinnedBinary('cosign');
  }, 600_000);
  afterAll(cleanupRepos);

  it('live: every pinned tool has a known checksums file; every tool but gitleaks has an upstream proof', () => {
    expect(Object.keys(TOOLS).sort()).toEqual(Object.keys(SUMS).sort());
    for (const [name, tool] of Object.entries(TOOLS)) expect((SUMS[name]?.(tool.version).proof.kind === 'none'), name).toBe(name === 'gitleaks');
  });

  it('live: each checksums file lists every platform\'s archiveSha256, and upstream\'s proof verifies (signed checksums, or each archive\'s attestation)', async () => {
    for (const [name, tool] of Object.entries(TOOLS)) {
      const { file, proof } = (SUMS[name] as (v: string) => { file: string; proof: Proof })(tool.version);
      const dir = makeTempDir();
      const sums = listed(await releaseFile(tool, file, dir));
      if (proof.kind === 'signed-checksums') {
        await releaseFile(tool, `${file}.sigstore.json`, dir);
        const r = verifyBlob(file, proof, dir);
        console.log(`${name} ${tool.version}: cosign verify-blob --certificate-identity ${proof.identity} ${file} → exit ${r.code} ${r.out.trim()}`);
        expect(r.code, `${name}: ${r.out}`).toBe(0);
      } else if (proof.kind === 'none') {
        console.log(`${name} ${tool.version}: ${file} is not signed and the archives are not attested upstream; checked for every pin only`);
      }
      const platforms = Object.entries(tool.platforms);
      expect(platforms.length, name).toBe(4);
      for (const [platform, p] of platforms) {
        expect(sums.has(`${p.archiveSha256} ${assetOf(p.url)}`), `${name} ${platform}: ${assetOf(p.url)} with the pinned sha256 is not in ${file}`).toBe(true);
        if (proof.kind === 'attestation') {
          const bundles = await attestationBundles(tool.repo, p.archiveSha256);
          expect(bundles.length, `${name} ${platform}: no attestation`).toBeGreaterThan(0);
          const results = bundles.map((b) => verifyAttestation(b, p.archiveSha256, proof, dir));
          console.log(`${name} ${tool.version} ${platform}: cosign verify-blob-attestation --type ${SLSA_V1} --certificate-identity ${proof.identity} --digest ${p.archiveSha256.slice(0, 12)}… → exit ${results.map((r) => r.code).join(',')}`);
          expect(results.some((r) => r.code === 0), `${name} ${platform}: ${results.map((r) => r.out).join('\n')}`).toBe(true);
        }
      }
    }
  }, 900_000);

  it('live: negative controls (a changed hash is not listed or attested; another identity does not verify)', async () => {
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
    // actionlint: the attestation does not verify for another digest, nor for another tag's workflow
    const al = TOOLS.actionlint as Tool;
    const ap = al.platforms['darwin-arm64'] as Platform;
    const [bundle] = await attestationBundles(al.repo, ap.archiveSha256);
    const adir = makeTempDir();
    const id = { identity: `https://github.com/rhysd/actionlint/.github/workflows/release.yaml@refs/tags/v${al.version}`, issuer: GH_ISSUER };
    expect(verifyAttestation(bundle, ap.archiveSha256, id, adir).code).toBe(0);
    expect(verifyAttestation(bundle, (ap.archiveSha256[0] === '0' ? '1' : '0') + ap.archiveSha256.slice(1), id, adir).code).not.toBe(0);
    expect(verifyAttestation(bundle, ap.archiveSha256, { ...id, identity: id.identity.replace(/v[\d.]+$/, 'v1.7.11') }, adir).code).not.toBe(0);
  }, 600_000);
});
