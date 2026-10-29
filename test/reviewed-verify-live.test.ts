// Live check of the reviewed list's recorded signature checks (Plan P Task 6): every entry whose verifiedWith is a
// cosign check is verified again, now, with pipegen's pinned cosign (ensurePinnedBinary('cosign')), against the
// upstream release files. Network: the pinned cosign (once, into ~/.cache/pipegen/tools), the signed files and their
// bundles from github.com, and repo-held keys from raw.githubusercontent.com. Nothing downloaded is run but cosign.
// Skipped unless PIPEGEN_LIVE_TESTS=1, so `npm test` stays offline.
//
// - Keyless (cosign-bundle): `<asset>` and `<asset>.sigstore.json` from the entry's release; cosign verify-blob with
//   the exact recorded identity and issuer. The verified file must list the entry's pinned sha256 for its asset.
// - Key-based (cosign-key, ruling P10): the key from keyUrl, whose sha256 must be keySha256; the entry's own pinned
//   asset (its sha256 must be the pin) and `<asset>.sigstore.json`; cosign verify-blob --key.
// - Negative controls: the same check with another tag's identity, or with another entry's key, fails.
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { fetchAllowed, readBody } from '../src/engine/http.js';
import { downloadRelease } from '../src/engine/pin.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import type { ReviewedTool } from '../src/types.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const MAX = 256 * 1024 * 1024;
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');

let cosign = '';

/** Runs the pinned cosign; returns its exit code and output (stdout + stderr). */
function verifyBlob(args: string[], cwd: string): { code: number; out: string } {
  const r = spawnSync(cosign, ['verify-blob', ...args], { cwd, encoding: 'utf8', timeout: 120_000 });
  if (r.error !== undefined || typeof r.status !== 'number') throw r.error ?? new Error('cosign did not exit');
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

/** A release file of the entry, saved in `dir`; returns its bytes. */
async function releaseFile(t: ReviewedTool, name: string, dir: string): Promise<Buffer> {
  const url = `https://github.com/${t.candidate.repo}/releases/download/${encodeURIComponent(t.candidate.version)}/${encodeURIComponent(name)}`;
  const bytes = Buffer.from(await downloadRelease(fetch, url, MAX));
  writeFileSync(join(dir, name), bytes);
  return bytes;
}

/** The repo-held key at keyUrl (raw.githubusercontent.com only, no redirect to elsewhere). */
async function keyFile(url: string): Promise<Buffer> {
  const res = await fetchAllowed(fetch, url, { method: 'GET', timeoutMs: 20_000, hosts: ['raw.githubusercontent.com'] });
  const chunks: Uint8Array[] = [];
  await readBody(res, 64 * 1024, (b) => chunks.push(b), 'the key file');
  return Buffer.concat(chunks);
}

const cosignEntries = (): ReviewedTool[] => loadReviewed().filter((t) => t.verifiedWith !== undefined
  && ('kind' in t.verifiedWith ? t.verifiedWith.kind === 'cosign-key' : t.verifiedWith.method === 'cosign-bundle'));

describe.skipIf(!live)('reviewed list signature checks (live, pinned cosign)', () => {
  beforeAll(async () => {
    cosign = await ensurePinnedBinary('cosign');
    console.log(`pinned cosign: ${execFileSync(cosign, ['version'], { encoding: 'utf8' }).split('\n').find((l) => l.startsWith('GitVersion'))?.trim()}`);
  }, 600_000);
  afterAll(cleanupRepos);

  it('live: the list has cosign checks to re-verify (MUST_VERIFY: betterleaks, the trivy entries, kube-linter, gosec)', () => {
    expect(cosignEntries().map((t) => t.id).sort()).toEqual(['betterleaks', 'gosec', 'kube-linter', 'trivy-config', 'trivy-image', 'trivy-licence']);
  });

  it('live: every verifiedWith cosign entry re-verifies with the pinned cosign', async () => {
    for (const t of cosignEntries()) {
      const v = t.verifiedWith;
      const dir = makeTempDir();
      const asset = t.step.cli?.install.package as string;
      if (v !== undefined && 'kind' in v) {
        const key = await keyFile(v.keyUrl);
        expect(sha256(key), `${t.id} key`).toBe(v.keySha256);
        writeFileSync(join(dir, 'cosign.pub'), key);
        const bytes = await releaseFile(t, asset, dir);
        expect(sha256(bytes), `${t.id} asset`).toBe(t.candidate.pin.checksum);
        await releaseFile(t, `${asset}.sigstore.json`, dir);
        const r = verifyBlob(['--key', 'cosign.pub', '--bundle', `${asset}.sigstore.json`, asset], dir);
        console.log(`${t.id}: cosign verify-blob --key <${v.keyUrl}> --bundle ${asset}.sigstore.json ${asset} → exit ${r.code} ${r.out.trim()}`);
        expect(r.code, `${t.id}: ${r.out}`).toBe(0);
      } else if (v !== undefined) {
        const sums = (await releaseFile(t, v.asset, dir)).toString('utf8');
        await releaseFile(t, `${v.asset}.sigstore.json`, dir);
        const r = verifyBlob(['--bundle', `${v.asset}.sigstore.json`, '--certificate-identity', v.identity, '--certificate-oidc-issuer', v.issuer, v.asset], dir);
        console.log(`${t.id}: cosign verify-blob --bundle ${v.asset}.sigstore.json --certificate-identity ${v.identity} --certificate-oidc-issuer ${v.issuer} ${v.asset} → exit ${r.code} ${r.out.trim()}`);
        expect(r.code, `${t.id}: ${r.out}`).toBe(0);
        // the signed checksums file lists the pinned sha256 for the pinned asset
        expect(sums.split(/\r?\n/).some((l) => l.trim().split(/\s+\*?/).join(' ') === `${t.candidate.pin.checksum} ${asset}`), `${t.id} listed`).toBe(true);
      }
    }
  }, 900_000);

  it('live: negative controls fail (another tag in the identity; another entry\'s key)', async () => {
    const list = cosignEntries();
    const bl = list.find((t) => t.id === 'betterleaks') as ReviewedTool;
    const v = bl.verifiedWith as { asset: string; identity: string; issuer: string };
    const dir = makeTempDir();
    await releaseFile(bl, v.asset, dir);
    await releaseFile(bl, `${v.asset}.sigstore.json`, dir);
    const wrongTag = verifyBlob(['--bundle', `${v.asset}.sigstore.json`, '--certificate-identity', v.identity.replace(/v1\.9\.0$/, 'v1.8.0'), '--certificate-oidc-issuer', v.issuer, v.asset], dir);
    expect(wrongTag.code).not.toBe(0);

    const kl = list.find((t) => t.id === 'kube-linter') as ReviewedTool;
    const gosec = list.find((t) => t.id === 'gosec') as ReviewedTool;
    const kdir = makeTempDir();
    writeFileSync(join(kdir, 'other.pub'), await keyFile((gosec.verifiedWith as { keyUrl: string }).keyUrl));
    const asset = kl.step.cli?.install.package as string;
    await releaseFile(kl, asset, kdir);
    await releaseFile(kl, `${asset}.sigstore.json`, kdir);
    const wrongKey = verifyBlob(['--key', 'other.pub', '--bundle', `${asset}.sigstore.json`, asset], kdir);
    expect(wrongKey.code).not.toBe(0);
  }, 600_000);
});
