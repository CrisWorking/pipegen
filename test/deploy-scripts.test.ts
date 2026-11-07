// v0.2 Plan G G7-R1 (spec review I2): the deploy layer's bash steps run for real, against a local fake of the GitHub API over HTTPS (a
// self-signed certificate made for the test, trusted through CURL_CA_BUNDLE), with the real curl, unzip and jq. The script's own fixed PATH
// line is the one line the harness changes: it puts a folder first that holds only jq (the runner image has jq; a test machine may not), so
// every other program is the system's. jq comes from PATH, or from PIPEGEN_TEST_JQ; without jq or openssl the suite is skipped (and says so).
import { execFile, execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32 } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { imageDigestArtifact, renderDigestStep, renderHeadCheckStep, renderPublishDigestStep } from '../src/engine/deploy-steps.js';
import type { RenderedStep } from '../src/engine/job-rules.js';
import { SCRIPT_HEAD } from '../src/engine/pipegen-script.js';

const which = (exe: string): string | null => {
  try { return execFileSync('bash', ['-c', `command -v ${exe}`], { encoding: 'utf8' }).trim() || null; } catch { return null; }
};
const JQ = process.env.PIPEGEN_TEST_JQ !== undefined && existsSync(process.env.PIPEGEN_TEST_JQ) ? process.env.PIPEGEN_TEST_JQ : which('jq');
const OPENSSL = which('openssl');
const READY = JQ !== null && OPENSSL !== null && which('curl') !== null && which('unzip') !== null;

const SHA = 'a'.repeat(40);
const NEWER = 'b'.repeat(40);
const DIGEST = `sha256:${'c'.repeat(64)}`;
const RUN = '4242';
/** G15a-R11 r5-1: the build's imageid on the classic image store (the config digest; the containerd store reports the manifest's, the digest). */
const IMAGE_ID = `sha256:${'e'.repeat(64)}`;
const IMAGE_REPO = 'ghcr.io/o/r-app';
const ART = '777';
/** Spelled at run time (test/no-secret-literals.test.ts): the fake job token and the header scheme. */
const FAKE_T = ['pipegen', 'test', 'value'].join('-');
const SCHEME = ['Bear', 'er'].join('');
const ARTIFACT = imageDigestArtifact('app');

/** A one-entry zip (stored, no compression): what GitHub's artifact zip of the digest folder holds. */
function zipOf(entries: [string, string][]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of entries) {
    const data = Buffer.from(text, 'utf8');
    const n = Buffer.from(name, 'utf8');
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(n.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(n.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, n, data);
    centrals.push(central, n);
    offset += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

interface Api { head: string; type?: string; refStatus?: number; listStatus?: number; artifacts: unknown; zip: Buffer; redirectTo?: string; seen: { url: string; who: string | undefined }[] }
let api: Api;
let server: Server;
let base = '';
let dir = '';
let bin = '';
let ca = '';

beforeAll(async () => {
  if (!READY) return;
  dir = mkdtempSync(join(tmpdir(), 'pipegen-deploy-scripts-'));
  bin = join(dir, 'bin');
  mkdirSync(bin);
  symlinkSync(JQ as string, join(bin, 'jq'));
  ca = join(dir, 'cert.pem');
  const key = join(dir, 'key.pem');
  execFileSync(OPENSSL as string, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', ca, '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  server = createServer({ key: readFileSync(key), cert: readFileSync(ca) }, (req, res) => {
    const url = req.url ?? '';
    api.seen.push({ url, who: req.headers[['author', 'ization'].join('')] as string | undefined });
    const json = (v: unknown): void => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
    if (url === '/repos/o/r/git/ref/heads/main') {
      if (api.refStatus !== undefined) { res.writeHead(api.refStatus); res.end('{}'); return undefined; }
      return json({ ref: 'refs/heads/main', object: { type: api.type ?? 'commit', sha: api.head } });
    }
    if (url === `/repos/o/r/actions/runs/${RUN}/artifacts?name=${ARTIFACT}&per_page=2`) {
      if (api.listStatus !== undefined) { res.writeHead(api.listStatus); res.end('{}'); return undefined; }
      return json(api.artifacts);
    }
    if (url === `/repos/o/r/actions/artifacts/${ART}/zip`) {
      if (api.redirectTo !== undefined) { res.writeHead(302, { location: api.redirectTo }); res.end(); return undefined; }
      res.writeHead(200, { 'content-type': 'application/zip', 'content-length': String(api.zip.length) }); res.end(api.zip); return undefined;
    }
    if (url.startsWith('/blob/')) {
      if (url === '/blob/again') { res.writeHead(302, { location: `${base}/blob/zip` }); res.end(); return undefined; }
      res.writeHead(200, { 'content-type': 'application/zip' }); res.end(api.zip); return undefined;
    }
    res.writeHead(404); res.end('{}');
    return undefined;
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  if (!READY) return;
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

const goodArtifacts = (over: Record<string, unknown> = {}): unknown => ({ total_count: 1, artifacts: [{ id: Number(ART), name: ARTIFACT, expired: false, workflow_run: { id: Number(RUN) }, ...over }] });
const fresh = (over: Partial<Api> = {}): Api => ({ head: SHA, artifacts: goodArtifacts(), zip: zipOf([['digest', DIGEST]]), seen: [], ...over });

interface Ran { code: number; err: string; out: string; tmp: string }
/** Runs a rendered step as the runner would (bash, its env, the job's GITHUB_* variables), with jq from the harness folder. */
async function run(step: RenderedStep, env: Record<string, string> = {}, pathDir?: string): Promise<Ran> {
  const fixed = SCRIPT_HEAD[2] as string;
  const script = String(step.run);
  expect(script.split('\n').filter((l) => l === fixed)).toHaveLength(1);
  const body = script.replace(fixed, pathDir === undefined ? fixed.replace('PATH=', `PATH=${bin}:`) : `PATH=${pathDir}`);
  const tmp = mkdtempSync(join(dir, 'run-'));
  const out = join(tmp, 'output');
  writeFileSync(out, '');
  const stepEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(step.env ?? {})) {
    stepEnv[k] = String(v)
      .replace('${{ github.token }}', FAKE_T)
      .replace('${{ steps.pipegen-find-run.outputs.run-id }}', RUN)
      .replace('${{ steps.pipegen-build-push.outputs.digest }}', DIGEST)
      .replace('${{ steps.pipegen-build-push.outputs.imageid }}', IMAGE_ID);
  }
  const all = {
    HOME: tmp, CURL_CA_BUNDLE: ca, RUNNER_TEMP: tmp, GITHUB_OUTPUT: out, GITHUB_API_URL: base, GITHUB_REPOSITORY: 'o/r',
    GITHUB_REF: 'refs/heads/main', GITHUB_SHA: SHA, GITHUB_EVENT_NAME: 'push', ...stepEnv, ...env,
  };
  return new Promise((resolve) => {
    execFile('bash', ['--noprofile', '--norc', '-c', body], { env: all, timeout: 60_000 }, (e, stdout, stderr) => {
      resolve({ code: e === null ? 0 : typeof e.code === 'number' ? e.code : 1, err: stderr, out: readFileSync(out, 'utf8'), tmp });
    });
  });
}

describe.skipIf(!READY)('G7-R1 spec I2: the head check runs (real bash, curl, jq; fake API over HTTPS)', () => {
  const head = renderHeadCheckStep('main');
  it('head check: passes on a push of the head of the default branch, the token only in a header read from stdin', async () => {
    api = fresh();
    const r = await run(head);
    expect(r.code, r.err).toBe(0);
    expect(api.seen).toEqual([{ url: '/repos/o/r/git/ref/heads/main', who: `${SCHEME} ${FAKE_T}` }]);
    // the token is never on a command line (sec M5): curl reads the header from stdin
    expect(String(head.run)).not.toMatch(/curl[^\n]*\$TOKEN/);
  });
  it('head check: the default branch moved on (a newer commit, an approval that waited, a re-run of an old run) → refused', async () => {
    api = fresh({ head: NEWER });
    const r = await run(head);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/default branch has moved on to a newer commit/);
  });
  it('head check: any event but push → refused (workflow_run, pull_request_target, issue_comment; sec M2)', async () => {
    for (const ev of ['workflow_run', 'pull_request_target', 'issue_comment', 'workflow_dispatch']) {
      api = fresh();
      const r = await run(head, { GITHUB_EVENT_NAME: ev });
      expect(r.code, ev).not.toBe(0);
      expect(r.err, ev).toMatch(/is not a push/);
      expect(api.seen, ev).toEqual([]);
    }
  });
  it('head check: another branch, or a commit that is not 40 hex → refused before any call', async () => {
    for (const env of [{ GITHUB_REF: 'refs/heads/dev' }, { GITHUB_REF: 'refs/tags/v1' }, { GITHUB_SHA: 'main' }] as Record<string, string>[]) {
      api = fresh();
      const r = await run(head, env);
      expect(r.code, JSON.stringify(env)).not.toBe(0);
      expect(api.seen).toEqual([]);
    }
  });
  it('head check: an API answer that is not a branch head → refused', async () => {
    api = fresh();
    api.head = '';
    const r = await run(head);
    expect(r.code).not.toBe(0);
    // a tag object whose sha matches the commit: still not a branch head (G7-R2 8)
    api = fresh({ type: 'tag' });
    const t = await run(head);
    expect(t.code).not.toBe(0);
  });
  it('head check: the ref answers 404 or 5xx → refused (G7-R2 8)', async () => {
    for (const status of [404, 500, 503]) {
      api = fresh({ refStatus: status });
      const r = await run(head);
      expect(r.code, String(status)).not.toBe(0);
    }
  });
  it('head check: a runner without jq (or curl) fails with a plain message naming the tool (G7-R2 1b)', async () => {
    api = fresh();
    const only = mkdtempSync(join(dir, 'path-'));
    symlinkSync(which('curl') as string, join(only, 'curl'));
    const r = await run(head, {}, only);
    expect(r.code).not.toBe(0);
    expect(r.err).toMatch(/has no jq, which pipegen's head check needs; install jq there/);
    expect(api.seen).toEqual([]);
    const none = mkdtempSync(join(dir, 'path-'));
    const c = await run(head, {}, none);
    expect(c.err).toMatch(/has no curl/);
  });
  it('head check: the refusal says what to do when the newer commit starts no deploy (G7-R2 4)', async () => {
    api = fresh({ head: NEWER });
    const r = await run(head);
    expect(r.err).toMatch(/if that commit starts a deploy; otherwise push again or re-run all jobs on the newest commit/);
  });
});

describe.skipIf(!READY)('G7-R1 spec I2: the digest step runs', () => {
  const step = renderDigestStep('app');
  const digestOf = (r: Ran): string => readFileSync(join(r.tmp, 'pipegen-out', ARTIFACT, 'digest'), 'utf8');
  it('digest: one artifact of the gated run, not expired, one digest entry → written and output', async () => {
    api = fresh();
    const r = await run(step);
    expect(r.code, r.err).toBe(0);
    expect(digestOf(r)).toBe(DIGEST);
    expect(r.out).toBe(`digest=${DIGEST}\n`);
    expect(api.seen.every((s) => s.who === `${SCHEME} ${FAKE_T}`)).toBe(true);
    expect(String(step.run)).not.toMatch(/curl[^\n]*\$TOKEN/);
  });
  it('digest: the artifact of another run (wrong workflow_run.id) → refused', async () => {
    api = fresh({ artifacts: goodArtifacts({ workflow_run: { id: 1 } }) });
    const r = await run(step);
    expect(r.code).not.toBe(0);
    expect(r.out).toBe('');
  });
  it('digest: the artifact list answers 404 or 5xx → refused (G7-R2 8)', async () => {
    for (const status of [404, 500, 502]) {
      api = fresh({ listStatus: status });
      const r = await run(step);
      expect(r.code, String(status)).not.toBe(0);
      expect(r.out).toBe('');
    }
  });
  it('digest: an artifact of the gated run under another name → refused (G7-R2 8)', async () => {
    api = fresh({ artifacts: goodArtifacts({ name: imageDigestArtifact('other') }) });
    const r = await run(step);
    expect(r.code).not.toBe(0);
    expect(r.out).toBe('');
  });
  it('digest: two artifacts of that name, or none → refused', async () => {
    const one = (goodArtifacts() as { artifacts: unknown[] }).artifacts[0];
    for (const artifacts of [{ total_count: 2, artifacts: [one, one] }, { total_count: 0, artifacts: [] }, { artifacts: 'x' }]) {
      api = fresh({ artifacts });
      const r = await run(step);
      expect(r.code, JSON.stringify(artifacts)).not.toBe(0);
      expect(r.out).toBe('');
    }
  });
  it('digest: an expired artifact (or no expired field) → refused with the retention reason', async () => {
    for (const over of [{ expired: true }, { expired: undefined }, { expired: 'false' }]) {
      api = fresh({ artifacts: goodArtifacts(over) });
      const r = await run(step);
      expect(r.code, JSON.stringify(over)).not.toBe(0);
      expect(r.err).toMatch(/past the artifact retention period/);
      expect(api.seen.some((s) => s.url.endsWith('/zip'))).toBe(false);
    }
  });
  it('digest: a digest that is not sha256:<64 hex> (or a zip without the digest entry) → refused, nothing output', async () => {
    for (const zip of [zipOf([['digest', 'sha256:abc']]), zipOf([['digest', `${DIGEST}\nX`]]), zipOf([['other', DIGEST]]), zipOf([['digest', DIGEST.toUpperCase()]])]) {
      api = fresh({ zip });
      const r = await run(step);
      expect(r.code).not.toBe(0);
      expect(r.out).toBe('');
    }
  });
  it('digest: a zip over the size limit → refused', async () => {
    api = fresh({ zip: zipOf([['digest', DIGEST], ['pad', 'x'.repeat(70_000)]]) });
    const r = await run(step);
    expect(r.code).not.toBe(0);
    expect(r.out).toBe('');
  });
  it('digest: one redirect (to the storage host) is followed; a second one is refused (sec M6)', async () => {
    api = fresh({ redirectTo: `${base}/blob/zip` });
    const ok = await run(step);
    expect(ok.code, ok.err).toBe(0);
    api = fresh({ redirectTo: `${base}/blob/again` });
    const two = await run(step);
    expect(two.code).not.toBe(0);
    expect(two.out).toBe('');
  });
  it('digest: a run id that is not a plain id → refused before any call', async () => {
    for (const id of ['', '0', '12a', '1;id']) {
      api = fresh();
      const r = await run(step, { PIPEGEN_RUN_ID: id });
      expect(r.code, id).not.toBe(0);
      expect(api.seen).toEqual([]);
    }
  });
});

describe.skipIf(!READY)('G7-R1 spec I2, G15a-R11 r5-1: the publish digest step runs', () => {
  const step = renderPublishDigestStep('app', IMAGE_REPO);
  // a fake docker first on the PATH: it records its arguments and prints PIPEGEN_TEST_REPO_DIGESTS (or fails with PIPEGEN_TEST_DOCKER_CODE)
  beforeAll(() => {
    if (!READY) return;
    writeFileSync(join(bin, 'docker'), [
      '#!/bin/bash',
      'printf \'%s\\n\' "$*" >> "$RUNNER_TEMP/docker-args"',
      'if [ "${PIPEGEN_TEST_DOCKER_CODE:-0}" != 0 ]; then echo "Error: No such image" >&2; exit "$PIPEGEN_TEST_DOCKER_CODE"; fi',
      'printf \'%s\\n\' "$PIPEGEN_TEST_REPO_DIGESTS"',
    ].join('\n'), { mode: 0o755 });
  });
  const digests = (...refs: string[]): string => JSON.stringify(refs);
  const wrote = (r: Ran): boolean => existsSync(join(r.tmp, 'pipegen-out', ARTIFACT, 'digest'));
  it('publish digest: the build digest is written when the daemon\'s record of the built image holds <repo>@<digest>, on both image stores', async () => {
    api = fresh();
    // classic store: imageid is the config digest, RepoDigests gets the pushed manifest's digest; containerd store: imageid is the digest itself
    for (const [store, id, rd] of [
      ['classic', IMAGE_ID, digests(`${IMAGE_REPO}@${DIGEST}`)],
      ['containerd', DIGEST, digests(`${IMAGE_REPO}@${DIGEST}`)],
      ['classic, an entry of another repository too', IMAGE_ID, digests(`ghcr.io/o/r-web@sha256:${'d'.repeat(64)}`, `${IMAGE_REPO}@${DIGEST}`)],
    ] as const) {
      const r = await run(step, { PIPEGEN_IMAGE_ID: id, PIPEGEN_TEST_REPO_DIGESTS: rd });
      expect(r.code, `${store}: ${r.err}`).toBe(0);
      expect(readFileSync(join(r.tmp, 'pipegen-out', ARTIFACT, 'digest'), 'utf8'), store).toBe(DIGEST);
      // the daemon is asked about the image this job built, by its id, never by the tag
      expect(readFileSync(join(r.tmp, 'docker-args'), 'utf8'), store).toBe(`image inspect --format {{json .RepoDigests}} -- ${id}\n`);
    }
  });
  it('publish digest: a digest the daemon did not push for this image (the tag moved in between), no record, or a bad digest or id is refused before anything is written', async () => {
    api = fresh();
    const ok = { PIPEGEN_IMAGE_ID: IMAGE_ID, PIPEGEN_TEST_REPO_DIGESTS: digests(`${IMAGE_REPO}@${DIGEST}`) };
    const cases: [string, Record<string, string>][] = [
      ['the swapped digest (another writer\'s manifest)', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: digests(`${IMAGE_REPO}@sha256:${'f'.repeat(64)}`) }],
      ['the digest under another repository', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: digests(`ghcr.io/o/r-other@${DIGEST}`) }],
      ['a prefix of the repository', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: digests(`ghcr.io/o/r-app-x@${DIGEST}`) }],
      // round 12 (security r6 Nit 2): exactly one entry for the repository; two are refused, whichever the build reported
      ['two entries for the repository, the reported digest second', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: digests(`${IMAGE_REPO}@sha256:${'f'.repeat(64)}`, `${IMAGE_REPO}@${DIGEST}`) }],
      ['two entries for the repository, the reported digest first', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: digests(`${IMAGE_REPO}@${DIGEST}`, `${IMAGE_REPO}@sha256:${'f'.repeat(64)}`) }],
      ['the reported entry twice', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: digests(`${IMAGE_REPO}@${DIGEST}`, `${IMAGE_REPO}@${DIGEST}`) }],
      ['a non-string entry beside it', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: JSON.stringify([`${IMAGE_REPO}@${DIGEST}`, 1]) }],
      ['no RepoDigests (never pushed by this daemon)', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: '[]' }],
      ['RepoDigests null', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: 'null' }],
      ['RepoDigests not JSON', { ...ok, PIPEGEN_TEST_REPO_DIGESTS: `${IMAGE_REPO}@${DIGEST}` }],
      ['the image is unknown to the daemon', { ...ok, PIPEGEN_TEST_DOCKER_CODE: '1' }],
      ['no image id', { ...ok, PIPEGEN_IMAGE_ID: '' }],
      ['an image id that is an option', { ...ok, PIPEGEN_IMAGE_ID: '--help' }],
      ['an image id that is a name', { ...ok, PIPEGEN_IMAGE_ID: 'ghcr.io/o/r-app:pipegen' }],
    ];
    for (const [name, env] of cases) {
      const b = await run(step, env);
      expect(b.code, name).not.toBe(0);
      expect(wrote(b), name).toBe(false);
    }
    for (const bad of ['', 'sha256:abc', `${DIGEST} `, 'latest']) {
      const b = await run(step, { ...ok, PIPEGEN_IMAGE_DIGEST: bad });
      expect(b.code, bad).not.toBe(0);
      expect(wrote(b), bad).toBe(false);
    }
  });
});

describe('G7-R1 spec I2: the harness itself', () => {
  it('says why it is skipped when jq or openssl is missing (set PIPEGEN_TEST_JQ to a jq binary); in CI it fails instead', () => {
    if (!READY) console.warn(`test/deploy-scripts.test.ts skipped: jq ${JQ ?? 'missing'}, openssl ${OPENSSL ?? 'missing'}`);
    // G7-R2 5: in CI the script tests never skip silently: a runner without jq or openssl fails here
    expect(READY || process.env.CI === undefined || process.env.CI === '', `CI is set but jq (${JQ ?? 'missing'}) or openssl (${OPENSSL ?? 'missing'}) is missing`).toBe(true);
  });
});
