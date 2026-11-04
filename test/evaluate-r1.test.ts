// E5 mutation round: tests that pin the messages and branches the first mutation run showed were only covered by a neighbouring check.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseJunit } from '../src/create/junit.js';
import { readJunitBytes } from '../src/create/junit-worker.js';
import { evaluate, evaluateProof, type EvalContext, type VariantRuns } from '../src/proof/evaluate.js';
import { gateResultOf } from '../src/proof/gate-result.js';
import type { PartResult, ProofResult } from '../src/types.js';
import {
  c1b, COMPAT_PREFIX, ctxOf, draftOf, file, gateDoc, gateFinding, GATE_RESULT_ARTIFACT, greenMain, HARNESS_PATH, harnessJob, job, MERGE, needOf, PIPEGEN, plantedRuns, resultArtifactName, run, spec,
} from './helpers/proof-eval.js';

const part = (r: ProofResult, p: PartResult['part']): PartResult | undefined => r.parts.find((x) => x.part === p && x.needId === undefined);
const D = () => draftOf();
const both = (d = D(), main: VariantRuns = greenMain(d), planted: VariantRuns = plantedRuns(d)): VariantRuns[] => [main, planted];
type O = VariantRuns['outcomes'][number];
const prRun = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.event === 'pull_request') as O;
const mergeRun = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === PIPEGEN && o.handle.headSha === MERGE) as O;
const harnessPr = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === HARNESS_PATH && o.handle.event === 'pull_request') as O;
const harnessMerge = (m: VariantRuns): O => m.outcomes.find((o) => o.handle.workflow === HARNESS_PATH && o.handle.event === 'push') as O;
const set = (o: O, name: string, conclusion: string | null, log?: string): void => {
  const j = o.jobs.find((x) => x.name === name);
  if (j === undefined) throw new Error(`no job ${name}`);
  j.conclusion = conclusion; j.status = conclusion === null ? 'in_progress' : 'completed';
  if (log !== undefined) j.log = log;
};
const setGate = (o: O, d: ReturnType<typeof draftOf>, opts: Omit<Parameters<typeof gateDoc>[0], 'runId'>): void => { o.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ ...opts, runId: o.handle.runId }, d)); };
const xml = (cases: [string, 'pass' | 'fail' | 'skip'][]): string =>
  `<testsuites><testsuite name="s">${cases.map(([n, s]) => `<testcase classname="a.test.ts" name="${n}">${s === 'fail' ? '<failure message="x"/>' : s === 'skip' ? '<skipped/>' : ''}</testcase>`).join('')}</testsuite></testsuites>`;
const readJunit: NonNullable<EvalContext['readJunit']> = async (bytes) => { try { return { ok: true, cases: parseJunit(Buffer.from(bytes).toString('utf8')) }; } catch (e) { return { ok: false, reason: `report unreadable: ${(e as Error).message}` }; } };
const MOUNT = 'docker: Error response from daemon: bullfrog: mounting the host path /w is not allowed while sudo is disabled';
const EXACT = 'required check semgrep (sast--api) did not succeed (failure)';
const refused = (m: VariantRuns, d: ReturnType<typeof draftOf>, over: Record<string, unknown> = {}): void => {
  const o = prRun(m);
  set(o, 'sast--api', 'failure', MOUNT); set(o, 'gate', 'failure'); o.conclusion = 'failure';
  o.artifacts.delete(resultArtifactName('sast', 'api'));
  setGate(o, d, { result: 'block', failedJobs: [{ needId: 'sast', job: 'sast--api' }], blockReasons: [EXACT], ...over });
};

describe('messages and branches pinned by the mutation round', () => {
  it('a job skipped in another layer does not fail an owned check; the latest attempt of a job decides', async () => {
    const d = D();
    const m = greenMain(d);
    mergeRun(m).jobs.push(job('unit-tests--api', 'skipped'));
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'tests')?.status).toBe('proven');
    const a = greenMain(d);
    prRun(a).jobs.push(job('sast--api', 'failure', { attempt: 1 }));
    prRun(a).jobs.find((j) => j.name === 'sast--api' && j.attempt === 1)!.attempt = 1;
    prRun(a).jobs.find((j) => j.name === 'sast--api' && j.conclusion === 'success')!.attempt = 2;
    expect(part(await evaluate(d, both(d, a), ctxOf()), 'pipeline')?.status).toBe('proven');
    const b = greenMain(d);
    prRun(b).jobs.find((j) => j.name === 'sast--api')!.attempt = 1;
    prRun(b).jobs.push(job('sast--api', 'failure', { attempt: 2 }));
    expect(part(await evaluate(d, both(d, b), ctxOf()), 'pipeline')?.status).toBe('failed');
  });

  it('pipeline reasons are named: no PR run, not merged, no merge run, no harness, egress failed open, gate unfinished', async () => {
    const d = D();
    const detail = async (m: VariantRuns): Promise<string> => part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.detail ?? '';
    const a = greenMain(d); a.outcomes = a.outcomes.filter((o) => o !== prRun(a));
    expect(await detail(a)).toMatch(/did not run on the pull request/);
    const b = greenMain(d); delete (b as { mergeSha?: string }).mergeSha; b.notMerged = 'the merge was refused'; b.outcomes = b.outcomes.filter((o) => o.handle.headSha !== MERGE);
    expect(await detail(b)).toMatch(/was not merged.*the merge was refused/);
    expect(part(await evaluate(d, both(d, b), ctxOf()), 'deploy-verify')?.detail).toMatch(/was not merged.*the merge was refused/);
    const c = greenMain(d); c.outcomes = c.outcomes.filter((o) => !(o.handle.workflow === PIPEGEN && o.handle.headSha === MERGE));
    expect(await detail(c)).toMatch(/did not run on the merge/);
    const e = greenMain(d); e.outcomes = e.outcomes.filter((o) => !(o.handle.workflow === HARNESS_PATH && o.handle.event === 'pull_request'));
    expect(await detail(e)).toMatch(/proof harness did not run on the pull request/);
    const f = greenMain(d); set(harnessPr(f), 'pipegen proof: egress-check', 'failure');
    expect(await detail(f)).toMatch(/egress control failed open/);
    for (const conclusion of ['skipped', null, 'cancelled']) {
      const g = greenMain(d); set(prRun(g), 'gate', conclusion);
      expect(await detail(g), String(conclusion)).toMatch(/gate job did not run to a result|gate blocked/);
    }
    const h = greenMain(d); set(prRun(h), 'sast--api', 'success'); prRun(h).jobs = prRun(h).jobs.filter((j) => j.name !== 'sast--api');
    expect(await detail(h)).toMatch(/sast--api did not run on the pull request/);
    const i = greenMain(d); i.outcomes = i.outcomes.filter((o) => o !== prRun(i) && o !== harnessPr(i));
    expect(await detail(i)).toMatch(/gate job did not run|did not run on the pull request/);
  });

  it('a gate that passed with an unreadable report is named', async () => {
    const d = D();
    const m = greenMain(d);
    prRun(m).artifacts.delete(GATE_RESULT_ARTIFACT);
    expect(part(await evaluate(d, both(d, m), ctxOf()), 'pipeline')?.detail).toMatch(/gate passed but its result\.json is not usable/);
    const m2 = greenMain(d);
    setGate(prRun(m2), d, { result: 'block', blocking: [gateFinding('sast', 'semgrep')] });
    expect(part(await evaluate(d, both(d, m2), ctxOf()), 'pipeline')?.detail).toMatch(/the two disagree/);
  });

  it('a gate report under another file name, or with a download problem, is unreadable even when its content is valid', () => {
    const d = D();
    const o = run({ runId: 55, jobs: [] });
    o.artifacts.set(GATE_RESULT_ARTIFACT, { ...gateDoc({ runId: 55 }, d), file: 'other.json' });
    const r = gateResultOf(o);
    expect(r.ok).toBe(false);
    const o2 = run({ runId: 56, jobs: [] });
    o2.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: 56 }, d));
    expect(gateResultOf(o2).ok).toBe(true);
    o2.artifactProblems.set(GATE_RESULT_ARTIFACT, 'too big');
    const r2 = gateResultOf(o2);
    expect(r2.ok).toBe(false);
    expect(r2.ok === false && r2.reason).toMatch(/too big/);
  });

  it('exact attribution: an inconsistent report, a not-run entry, an unexplained job entry and a non-blocking tool error', async () => {
    const d = D();
    const a = greenMain(d); refused(a, d, { result: 'warn', pass: true });
    expect(part(await evaluate(d, both(d, a), ctxOf()), 'pipeline')?.status).toBe('failed');
    const b = greenMain(d); refused(b, d, { notRun: [{ needId: 'sast', job: 'sast--api' }] });
    expect(part(await evaluate(d, both(d, b), ctxOf()), 'pipeline')?.status).toBe('failed');
    const c = greenMain(d);
    refused(c, d, { failedJobs: [{ needId: 'sast', job: 'sast--api' }, { needId: 'deps', job: 'deps--api' }], blockReasons: [EXACT, 'required check osv-scanner (deps--api) did not succeed (failure)'] });
    expect(part(await evaluate(d, both(d, c), ctxOf()), 'pipeline')?.status).toBe('failed');
    const e = greenMain(d);
    refused(e, d, { toolErrors: [{ needId: 'deps', job: 'deps--api', tool: 'osv-scanner', base: false, blocks: true, reason: 'x' }], blockReasons: [EXACT, 'tool error in osv-scanner (deps--api): re-run the job'] });
    expect(part(await evaluate(d, both(d, e), ctxOf()), 'pipeline')?.status).toBe('failed');
    const f = greenMain(d);
    refused(f, d, { toolErrors: [{ needId: 'deps', job: 'deps--api', tool: 'osv-scanner', base: false, blocks: false, reason: 'x' }] });
    expect(part(await evaluate(d, both(d, f), ctxOf()), 'pipeline')?.status).toBe('not-proven');
  });

  it('a scanner log that only contains the Bullfrog line on a GREEN job is not a refusal', async () => {
    const d = D();
    const m = greenMain(d);
    prRun(m).jobs.find((j) => j.name === 'sast--api')!.log = MOUNT;
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(part(r, 'pipeline')?.status).toBe('proven');
    expect(r.parts.some((p) => p.status === 'not-proven')).toBe(false);
  });

  it('result artifacts come only from the run of the need\'s job', async () => {
    const d = D();
    const m = greenMain(d);
    prRun(m).artifacts.delete(resultArtifactName('sast', 'api'));
    const other = run({ workflow: '.github/workflows/pipegen-merge.yml', event: 'pull_request', jobs: [job('x')], artifacts: [file(resultArtifactName('sast', 'api'), 'results.sarif', '{}')] });
    m.outcomes.push(other);
    const r = await evaluate(d, both(d, m), ctxOf());
    expect(r.parts.find((p) => p.part === 'pipeline' && p.needId === 'sast')?.status).toBe('failed');
    // the first-run JUnit counts only from a pipegen PR run, not from a compat run (the repeat is legitimate)
    const GOOD = xml([['s > a', 'pass'], ['s > b', 'pass']]);
    const t = greenMain(d);
    t.outcomes.push(run({ workflow: `${COMPAT_PREFIX}ci.yml`, event: 'pull_request', jobs: [job('b')], artifacts: [file('pipegen-out-junit-api', 'junit.xml', GOOD)] }));
    harnessPr(t).jobs.push(harnessJob('tests-repeat'));
    harnessPr(t).artifacts.set('pipegen-out-junit-repeat-api', file('pipegen-out-junit-repeat-api', 'junit.xml', GOOD));
    const rt = await evaluate(d, both(d, t), ctxOf({ createdTests: [{ service: 'api', staticCount: 2 }], readJunit, harnessJobs: ['egress-check', 'app-start', 'verify-lookup', 'tests-repeat'] }));
    expect(part(rt, 'tests')?.detail).toMatch(/first-run JUnit.*not uploaded/);
  });

  it('a compat run that failed without a failed job (startup failure) is a failure when the user\'s main passes', async () => {
    const d = D();
    const m = greenMain(d);
    m.outcomes.push(run({ workflow: `${COMPAT_PREFIX}ci.yml`, event: 'pull_request', conclusion: 'startup_failure', jobs: [] }));
    const r = await evaluate(d, both(d, m), ctxOf({ userMain: new Map([['.github/workflows/ci.yml', 'success']]) }));
    expect(part(r, 'pipeline')?.detail).toContain('pipegen broke .github/workflows/ci.yml');
  });

  it('planted: gate report says block while the job passed; unreadable report; unfinished gate; missing parts; matcher edge cases', async () => {
    const d = D();
    const detail = async (p: VariantRuns | undefined, ctx = ctxOf()): Promise<string> => part(await evaluate(d, p === undefined ? [greenMain(d)] : both(d, greenMain(d), p), ctx), 'pipeline')?.detail ?? '';
    // gate job passed, report says block
    expect(await detail(plantedRuns(d, { gateConclusion: 'success', result: 'block' }))).toMatch(/it passed on the planted pull request/);
    // gate job blocked but the report is missing
    expect(await detail(plantedRuns(d, { omitResult: true }))).toMatch(/planted pull request's gate report is not usable/);
    // gate did not finish
    for (const gateConclusion of ['skipped', 'cancelled']) expect(await detail(plantedRuns(d, { gateConclusion })), gateConclusion).toMatch(/did not finish on the planted/);
    // no planted variant, no PR run, no gate job
    expect(await detail(undefined)).toMatch(/planted variant was not proven/);
    const noPr: VariantRuns = { variant: 'planted', outcomes: [] };
    expect(await detail(noPr)).toMatch(/did not run on the planted pull request/);
    const noGate = plantedRuns(d); noGate.outcomes[0]!.jobs = noGate.outcomes[0]!.jobs.filter((j) => j.name !== 'gate');
    expect(await detail(noGate)).toMatch(/gate job did not run on the planted/);
    // the matcher: no matcher; and an item neither caught nor missed is not caught
    expect(await detail(plantedRuns(d), ctxOf({ matchPlanted: undefined }))).toMatch(/no matcher/);
    expect(await detail(plantedRuns(d), ctxOf({ matchPlanted: () => ({ caught: [], missed: [] }) }))).toMatch(/didn't catch the planted/);
    expect(await detail(plantedRuns(d), ctxOf({ matchPlanted: () => ({ caught: PLANTED_IDS, missed: [] }) }))).not.toMatch(/didn't catch/);
    // a near-miss file name (an extra non-ASCII character) is not the planted placement
    const near = plantedRuns(d, { skip: (f) => f.file === 'node_modules/x.js' });
    const doc = near.outcomes[0]!;
    const blocking = [
      ...c1b().filter((p) => p.kind === 'secret' && p.path !== 'node_modules/x.js').map((p) => gateFinding('secrets', 'gitleaks', { file: p.path, secret: true })),
      gateFinding('secrets', 'gitleaks', { file: 'node_modules/x.jés', secret: true }),
      gateFinding('sast', 'semgrep', { file: 'pipegen-planted/sast.js', job: 'sast--api' }), gateFinding('deps', 'osv-scanner', { file: 'pipegen-planted/package.json', job: 'deps--api' }), gateFinding('image-scan', 'trivy', { file: 'pipegen-planted/Dockerfile', job: 'image-scan--api' }),
    ];
    setGate(doc, d, { result: 'block', blocking });
    expect(await detail(near)).toContain("didn't catch the planted secret in node_modules/x.js");
  });

  it('nuclei and ZAP', async () => {
    const mk = (tool: string) => draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('dast', { service: 'api' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec(tool, 'dast', 'api')],
    });
    const z = mk('zap-baseline');
    const m = greenMain(z);
    prRun(m).artifacts.delete(resultArtifactName('dast', 'api'));
    const r = await evaluate(z, [m, plantedRuns(z)], ctxOf());
    expect(r.parts.some((p) => p.status === 'failed' && p.needId === 'dast')).toBe(false);
    const n = mk('nuclei');
    const rn = await evaluate(n, [greenMain(n), plantedRuns(n)], ctxOf());
    expect(rn.parts.some((p) => p.needId === 'dast' && p.status === 'not-proven' && /deferred/.test(p.detail))).toBe(true);
  });

  it('created tests: each rule is named', async () => {
    const d = D();
    const GOOD = xml([['s > a', 'pass'], ['s > b', 'pass']]);
    const withJ = (first: string, repeat: string): VariantRuns => {
      const m = greenMain(d);
      prRun(m).artifacts.set('pipegen-out-junit-api', file('pipegen-out-junit-api', 'junit.xml', first));
      harnessPr(m).artifacts.set('pipegen-out-junit-repeat-api', file('pipegen-out-junit-repeat-api', 'junit.xml', repeat));
      harnessPr(m).jobs.push(harnessJob('tests-repeat'));
      return m;
    };
    const cx = (over: Partial<EvalContext> = {}, n = 2): EvalContext => ctxOf({ createdTests: [{ service: 'api', staticCount: n }], readJunit, harnessJobs: ['egress-check', 'app-start', 'verify-lookup', 'tests-repeat'], ...over });
    const detail = async (m: VariantRuns, ctx = cx()): Promise<string> => part(await evaluate(d, both(d, m), ctx), 'tests')?.detail ?? '';
    const sk = xml([['s > a', 'pass'], ['s > b', 'skip']]);
    expect(await detail(withJ(sk, sk))).toMatch(/were skipped/);
    const bad = xml([['s > a', 'pass'], ['s > b', 'fail']]);
    expect(await detail(withJ(bad, bad))).toMatch(/created tests of api failed/);
    const zero = '<testsuites><testsuite name="s"></testsuite></testsuites>';
    expect(await detail(withJ(zero, zero), cx({}, 0))).toMatch(/has no test/);
    const red = withJ(GOOD, GOOD); set(harnessPr(red), 'pipegen proof: tests-repeat', 'failure');
    expect(await detail(red)).toMatch(/repeat run of the created tests failed/);
    const gone = withJ(GOOD, GOOD); gone.outcomes.forEach((o) => { o.jobs = o.jobs.filter((j) => !/tests-repeat/.test(j.name)); });
    expect(await detail(gone)).toMatch(/repeat run of the created tests did not run|not uploaded/);
    const gone2 = withJ(GOOD, GOOD); harnessPr(gone2).jobs = harnessPr(gone2).jobs.filter((j) => !/tests-repeat/.test(j.name));
    harnessPr(gone2).artifacts.clear(); harnessPr(gone2).jobs.push(harnessJob('tests-repeat', 'skipped'));
    expect(await detail(gone2)).toMatch(/did not run/);
    expect(await detail(withJ(GOOD, GOOD), cx({ readJunit: async () => { throw new Error('boom'); } }))).toMatch(/report unreadable: boom/);
    expect(await detail(withJ(GOOD, GOOD), cx({ readJunit: async () => ({ ok: true, cases: 'x' } as never) }))).toMatch(/report unreadable/);
    expect(await detail(withJ(GOOD, GOOD), cx({ readJunit: async () => ({ ok: true } as never) }))).toMatch(/report unreadable/);
    expect(await detail(withJ(GOOD, GOOD), cx({ readJunit: async () => null as never }))).toMatch(/report unreadable/);
  });

  it('docker, deploy-verify and sign-roundtrip reasons are named', async () => {
    const d = D();
    const a = greenMain(d); prRun(a).jobs = prRun(a).jobs.filter((j) => j.name !== 'image-build--api');
    expect(part(await evaluate(d, both(d, a), ctxOf()), 'docker')?.detail).toMatch(/image build job image-build--api did not run/);
    const s = greenMain(d);
    const sc = (rendered: boolean) => ctxOf({ harnessJobs: rendered ? ['egress-check', 'app-start', 'verify-lookup', 'sign-roundtrip'] : ['egress-check', 'app-start', 'verify-lookup'] });
    expect(part(await evaluate(d, both(d, s), sc(true)), 'deploy-verify')?.detail).toMatch(/sign-roundtrip did not run/);
    harnessPr(s).jobs.push(harnessJob('sign-roundtrip', 'failure'));
    expect(part(await evaluate(d, both(d, s), sc(true)), 'deploy-verify')?.detail).toMatch(/sign-roundtrip: pipegen proof: sign-roundtrip failed/);
    const v = greenMain(d); set(harnessMerge(v), 'pipegen proof: verify-lookup', 'skipped');
    expect(part(await evaluate(d, both(d, v), ctxOf()), 'deploy-verify')?.detail).toMatch(/verify-lookup did not run on the push run/);
    const f = greenMain(d); set(harnessPr(f), 'pipegen proof: app-start', 'failure', 'boom');
    expect(part(await evaluate(d, both(d, f), ctxOf()), 'compose')?.detail).toMatch(/app-start: pipegen proof: app-start failed/);
    const g = greenMain(d); set(harnessPr(g), 'pipegen proof: app-start', 'skipped');
    expect(part(await evaluate(d, both(d, g), ctxOf()), 'compose')?.detail).toMatch(/app-start did not run/);
  });

  it('coverage: several services give the lowest; only the green jobs are read', async () => {
    const d = draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('coverage', { service: 'api' }), needOf('coverage', { service: 'web' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api')],
    });
    const tbl = (n: string) => `All files |  ${n} |  1 |  1 |  ${n} |`;
    const m = greenMain(d);
    prRun(m).jobs.push(job('coverage--api', 'success', { log: tbl('83.5') }), job('coverage--web', 'success', { log: tbl('61') }));
    const full = await evaluateProof(d, both(d, m), ctxOf());
    expect(full.coverage.measured).toBe(61);
    // a skipped matrix entry has no table: it is not read and does not make the measurement unreadable
    const m2 = greenMain(d);
    prRun(m2).jobs.push(job('coverage--api', 'success', { log: tbl('83.5') }), job('coverage--api (b)', 'skipped', { log: 'nothing' }), job('coverage--web', 'success', { log: tbl('90') }));
    expect((await evaluateProof(d, both(d, m2), ctxOf())).coverage.measured).toBe(83.5);
  });
});
const PLANTED_IDS = ['sast-eval', 'deps-vuln', 'image-cve'];

describe('junit worker: remaining limits', () => {
  let dir: string; let thread: URL;
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'junit-r1-'));
    const out = join(dir, 'junit-thread.mjs');
    await build({ entryPoints: [new URL('../src/create/junit-thread.ts', import.meta.url).pathname], bundle: true, platform: 'node', format: 'esm', outfile: out, logLevel: 'silent' });
    thread = pathToFileURL(out);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const script = (name: string, body: string): URL => { const p = join(dir, name); writeFileSync(p, body); return pathToFileURL(p); };

  it('more cases than the cap, an oversize report with a raised cap, invalid UTF-8 and the parser\'s own refusal', async () => {
    const many = script('many.mjs', `import { parentPort } from 'node:worker_threads'; parentPort.postMessage({ ok: true, cases: Array.from({ length: 50001 }, (_, i) => ({ id: 'a' + i, status: 'pass' })) });`);
    expect((await readJunitBytes(new Uint8Array(1), { workerUrl: many })).ok).toBe(false);
    const good = script('good2.mjs', `import { parentPort } from 'node:worker_threads'; parentPort.postMessage({ ok: true, cases: [{ id: 'a', status: 'pass' }] });`);
    expect((await readJunitBytes(new Uint8Array(17 * 1024 * 1024), { workerUrl: good, maxBytes: Number.MAX_SAFE_INTEGER })).ok).toBe(false);
    const xmlBytes = Buffer.concat([Buffer.from('<testsuites><testsuite name="s"><testcase classname="a.test.ts" name="'), Buffer.from([0xff]), Buffer.from('"/></testsuite></testsuites>')]);
    expect((await readJunitBytes(xmlBytes, { workerUrl: thread })).ok).toBe(false);
    const doctype = await readJunitBytes(Buffer.from('<!DOCTYPE x><testsuites/>'), { workerUrl: thread });
    expect(doctype.ok === false && doctype.reason).toMatch(/DOCTYPE|ENTITY|<!/i);
    const dirRead = await (await import('../src/create/junit-worker.js')).readJunitFile(dir, { workerUrl: thread });
    expect(dirRead.ok === false && dirRead.reason).toMatch(/not a regular file/);
  });
});
