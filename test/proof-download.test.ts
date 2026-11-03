// Plan E E4 (ruling S2; DECISIONS #64): artifact and job-log downloads from the scratch repo. The API call (with the token) is
// a real makeOctokit client over a fake fetch; the artifact store's URL comes back unfollowed and is fetched by hand, once,
// WITHOUT the token, only on the store hosts the gate allows (STORE_HOST_RE). Artifacts are size-capped from the listing
// before any download, capped while they stream, and must be a single-entry zip (the gate's pickArtifact / readZipEntry).
// Job logs are fetched per job as text, the most recent 8 MiB kept. No network.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { makeOctokit } from '../src/github/client.js';
import { downloadJobLog, downloadRunArtifacts, MAX_ARTIFACT_ZIP_BYTES, MAX_LOG_BYTES, MAX_LOG_READ_BYTES, STORE_HOST_RE } from '../src/proof/download.js';
import { assertScratch, proofTarget } from '../src/proof/target.js';
import { countingStream, fakeFetch, type Call, type Reply, type Routes } from './helpers/fake-http.js';
import { app, OWNER, SCRATCH } from './helpers/scratch-secrets.js';
import { fake } from './helpers/secret-repo.js';
import { makeZip } from './helpers/zip.js';

const API = 'https://api.github.com';
const STORE = 'https://pipelinesghubeus22.actions.githubusercontent.com';
const BLOB = 'https://productionresultssa3.blob.core.windows.net';
const RUN = 4242;
const R = `/repos/${OWNER}/${SCRATCH}`;
const art = (id: number, name: string, size: number, o: Record<string, unknown> = {}) => ({ id, name, size_in_bytes: size, expired: false, workflow_run: { id: RUN }, ...o });

function setup(routes: Routes) {
  const cred = fake.githubPat();
  const f = fakeFetch(routes);
  const gh = makeOctokit(cred, { fetch: f.fetch, log: () => {} });
  const scratch = assertScratch(proofTarget(app()), app());
  return { gh, scratch, calls: f.calls, cred, deps: { fetch: f.fetch } };
}
const listing = (artifacts: unknown[], extra: Record<string, unknown> = {}): Reply => ({ body: { total_count: artifacts.length, artifacts, ...extra } });
const redirect = (to: string): Reply => ({ status: 302, headers: { location: to } });
const zipOf = (name: string, data: string) => Buffer.from(makeZip({ entries: [{ name, data }] }));
const storeCalls = (calls: Call[]) => calls.filter((c) => c.url.origin !== API);

describe('E4 downloads (S2)', () => {
  it('run: artifact download follows one redirect to the store host without the token, size-capped, single-entry zip', async () => {
    const result = '{"version":1,"blocking":[]}';
    const zip = zipOf('result.json', result);
    const { gh, scratch, calls, cred, deps } = setup({
      [`GET ${API}${R}/actions/runs/${RUN}/artifacts`]: listing([
        art(1, 'pipegen-gate-result', zip.length),
        art(2, 'pipegen-out-sast--api', zip.length),
        art(3, 'some-user-artifact', 10),                 // not asked for: never downloaded
        art(4, 'pipegen-out-big', MAX_ARTIFACT_ZIP_BYTES + 1),   // over the cap in the listing: never downloaded
        art(5, 'pipegen-out-two', 300),
        art(6, 'pipegen-out-evil', 300),
        art(7, 'pipegen-out-again', 300),
        art(8, 'pipegen-out-api200', 300),
      ]),
      [`GET ${API}${R}/actions/artifacts/1/zip`]: redirect(`${STORE}/a/1?sig=x`),
      [`GET ${API}${R}/actions/artifacts/2/zip`]: redirect(`${BLOB}/a/2?sig=y`),
      [`GET ${API}${R}/actions/artifacts/5/zip`]: redirect(`${STORE}/a/5`),
      [`GET ${API}${R}/actions/artifacts/6/zip`]: redirect('https://evil.example/a/6'),
      [`GET ${API}${R}/actions/artifacts/7/zip`]: redirect(`${STORE}/a/7`),
      [`GET ${API}${R}/actions/artifacts/8/zip`]: { raw: zip, headers: { 'content-type': 'application/zip' } },
      [`GET ${STORE}/a/1`]: { raw: zip, headers: { 'content-type': 'application/zip' } },
      [`GET ${BLOB}/a/2`]: { raw: zip, headers: { 'content-type': 'application/zip' } },
      [`GET ${STORE}/a/5`]: { raw: Buffer.from(makeZip({ entries: [{ name: 'a.json', data: '1' }, { name: 'b.json', data: '2' }] })) },
      [`GET ${STORE}/a/7`]: redirect(`${STORE}/a/7b`),       // a second redirect is never followed
      [`GET ${STORE}/a/7b`]: { raw: zip },
      [`GET https://evil.example/a/6`]: { raw: zip },
    });
    const out = await downloadRunArtifacts(gh, scratch, RUN, (n) => n.startsWith('pipegen-out-') || n === 'pipegen-gate-result', deps);
    expect([...out.files.keys()].sort()).toEqual(['pipegen-gate-result', 'pipegen-out-sast--api']);
    const f = out.files.get('pipegen-gate-result');
    expect(f?.file).toBe('result.json');
    expect(f?.bytes.toString('utf8')).toBe(result);
    expect(f?.sha256).toBe(createHash('sha256').update(result).digest('hex'));
    expect([...out.problems.keys()].sort()).toEqual(['pipegen-out-again', 'pipegen-out-api200', 'pipegen-out-big', 'pipegen-out-evil', 'pipegen-out-two']);
    expect(out.problems.get('pipegen-out-big')).toMatch(/size cap/);
    expect(out.problems.get('pipegen-out-two')).toMatch(/exactly one/);
    expect(out.problems.get('pipegen-out-evil')).toMatch(/host/);
    expect(out.problems.get('pipegen-out-again')).toMatch(/redirect/);
    expect(out.problems.get('pipegen-out-api200')).toMatch(/redirect/);
    // the token went to the API only; the store calls carry no authorization at all; the evil host and the 2nd hop were never called
    for (const c of calls) {
      if (c.url.origin === API) expect(c.headers.authorization).toContain(cred);
      else expect(c.headers.authorization, c.url.href).toBeUndefined();
      expect(JSON.stringify(c.headers), c.url.href).toSatisfy((h: string) => c.url.origin === API || !h.includes(cred));
    }
    expect(storeCalls(calls).map((c) => c.url.href).sort()).toEqual([`${BLOB}/a/2?sig=y`, `${STORE}/a/1?sig=x`, `${STORE}/a/5`, `${STORE}/a/7`].sort());
    expect(calls.some((c) => c.url.pathname.endsWith('/artifacts/4/zip') || c.url.pathname.endsWith('/artifacts/3/zip'))).toBe(false);
  });

  it('downloads: store URLs that are not plain https on a store host are refused; a body over the cap stops reading', async () => {
    const bad = ['http://pipelinesghubeus22.actions.githubusercontent.com/x', `https://${['u', 'p'].join(':')}@pipelinesghubeus22.actions.githubusercontent.com/x`,
      'https://pipelinesghubeus22.actions.githubusercontent.com:8443/x', 'https://api.github.com/repos/x', 'https://x.blob.core.windows.net.evil.example/x',
      'https://a.b.blob.core.windows.net/x', 'not a url', ''];
    for (const loc of bad) {
      const { gh, scratch, calls, deps } = setup({
        [`GET ${API}${R}/actions/runs/${RUN}/artifacts`]: listing([art(1, 'pipegen-out-x', 100)]),
        [`GET ${API}${R}/actions/artifacts/1/zip`]: redirect(loc),
      });
      const out = await downloadRunArtifacts(gh, scratch, RUN, () => true, deps);
      expect(out.problems.get('pipegen-out-x'), loc).toMatch(/redirect|host/);
      expect(calls.filter((c) => c.url.pathname !== `${R}/actions/runs/${RUN}/artifacts` && c.url.pathname !== `${R}/actions/artifacts/1/zip`), loc).toEqual([]);
    }
    // the listing says small, the store sends more: reading stops at the listed size cap
    const s = countingStream(4 * 1024 * 1024);
    const { gh, scratch, deps } = setup({
      [`GET ${API}${R}/actions/runs/${RUN}/artifacts`]: listing([art(1, 'pipegen-out-x', 1000)]),
      [`GET ${API}${R}/actions/artifacts/1/zip`]: redirect(`${STORE}/z`),
      [`GET ${STORE}/z`]: { stream: s.stream },
    });
    const out = await downloadRunArtifacts(gh, scratch, RUN, () => true, deps);
    expect(out.problems.get('pipegen-out-x')).toMatch(/size cap/);
    expect(s.pulled()).toBeLessThan(256 * 1024);
    // a listing that is cut short, or of another run: refused before any download
    for (const l of [listing([art(1, 'pipegen-out-x', 10)], { total_count: 9 }), listing([art(1, 'pipegen-out-x', 10, { workflow_run: { id: 1 } })]), { body: { nope: 1 } }]) {
      const w = setup({ [`GET ${API}${R}/actions/runs/${RUN}/artifacts`]: l });
      const o = await downloadRunArtifacts(w.gh, w.scratch, RUN, () => true, w.deps);
      expect(o.files.size).toBe(0);
      expect(o.problems.size).toBeGreaterThan(0);
      expect(w.calls.filter((c) => c.url.pathname.endsWith('/zip'))).toEqual([]);
    }
  });

  it('run: job logs fetched per job as text, capped', async () => {
    const text = '2026-11-03T10:00:00.0000000Z ##[group]Run npm test\n2026-11-03T10:00:01.0000000Z Error: boom\n';
    const { gh, scratch, calls, cred, deps } = setup({
      [`GET ${API}${R}/actions/jobs/11/logs`]: redirect(`${BLOB}/logs/11.txt?sig=z`),
      [`GET ${BLOB}/logs/11.txt`]: { raw: text, headers: { 'content-type': 'text/plain' } },
    });
    expect(await downloadJobLog(gh, scratch, 11, deps)).toEqual({ log: text, cut: false });
    expect(calls.map((c) => c.url.href)).toEqual([`${API}${R}/actions/jobs/11/logs`, `${BLOB}/logs/11.txt?sig=z`]);
    expect(calls[0]?.headers.authorization).toContain(cred);
    expect(calls[1]?.headers.authorization).toBeUndefined();
    // a long log: the most recent MAX_LOG_BYTES are kept (the error is at the end)
    const big = Buffer.concat([Buffer.alloc(MAX_LOG_BYTES + 1000, 0x61), Buffer.from('\nError: at the end\n')]);
    const w = setup({ [`GET ${API}${R}/actions/jobs/12/logs`]: redirect(`${STORE}/l/12`), [`GET ${STORE}/l/12`]: { raw: big } });
    const long = await downloadJobLog(w.gh, w.scratch, 12, w.deps);
    expect(long.cut).toBe(true);
    expect(Buffer.byteLength(long.log ?? '')).toBeLessThanOrEqual(MAX_LOG_BYTES);
    expect(long.log?.endsWith('Error: at the end\n')).toBe(true);
    // past the hard read cap: reading stops there, nothing kept
    const huge = countingStream(MAX_LOG_READ_BYTES + 4 * 1024 * 1024, 1024 * 1024);
    const h = setup({ [`GET ${API}${R}/actions/jobs/13/logs`]: redirect(`${STORE}/l/13`), [`GET ${STORE}/l/13`]: { stream: huge.stream } });
    const hr = await downloadJobLog(h.gh, h.scratch, 13, h.deps);
    expect(hr.log).toBeUndefined();
    expect(hr.problem).toMatch(/over/);
    expect(huge.pulled()).toBeLessThanOrEqual(MAX_LOG_READ_BYTES + 1024 * 1024);
    // a store host pipegen doesn't fetch from: no log, nothing sent there
    const e = setup({ [`GET ${API}${R}/actions/jobs/14/logs`]: redirect('https://evil.example/l') });
    expect((await downloadJobLog(e.gh, e.scratch, 14, e.deps)).problem).toMatch(/host/);
    expect(e.calls.map((c) => c.url.host)).toEqual(['api.github.com']);
  });

  it('STORE_HOST_RE is the gate\'s (a copy: gate/src is bundled and left unchanged until E9)', () => {
    const gate = readFileSync(join(import.meta.dirname, '..', 'gate', 'src', 'github-adapter.ts'), 'utf8');
    const m = /const STORE_HOST_RE = (\/.*\/);/.exec(gate);
    expect(m?.[1]).toBe(String(STORE_HOST_RE));
  });
});
