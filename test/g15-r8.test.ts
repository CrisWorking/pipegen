// v0.2 Plan G, sub-task G15a, ruling G15a-R8 (re-review r2: security APPROVED with Minors, spec CHANGES REQUIRED). Each item as a failing
// test first. sec m1: every download-artifact step names its artifact and folder. sec m2: the raw hand-off pattern is anchored on the two
// lanes (a service may be called api-raw). sec m3: the attest sign job of two images delivers. sec m4: the sign job needs image-publish, in
// every mode. spec 1: the ZAP AF scan is counted at 5 minutes a night, its 45-minute ceiling shown beside it. spec 2: the cost line keeps
// its unit. spec 5: readableFormat and isResultFormat read a raw output format themselves.
import { parse, parseDocument, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { estimate, jobMinutes } from '../src/estimate/estimate.js';
import { floorNeeds, jobCategories } from '../src/engine/needs.js';
import { DAST_UPLOAD_JOB, DEPLOY_PUSH_IF, NIGHTLY_WORKFLOW } from '../src/engine/job-rules.js';
import { referee } from '../src/engine/referee.js';
import { renderPlatformStep } from '../src/engine/render-step.js';
import { sharedWorkflows, signCallerJob, SIGN_JOB_ID } from '../src/layers/central.js';
import { draftOf, imageProf, jobsOf, p as GP, workflow } from './helpers/gate-pipeline.js';
import { reviewedList } from './helpers/render.js';
import { isResultFormat, readableFormat } from '../src/engine/gate-job-list.js';
import { ZAP_ACTIVE_CEILING_MINUTES, ZAP_ACTIVE_PASSIVE_MINUTES, ZAP_ACTIVE_PLAN, ZAP_ACTIVE_POLICY, ZAP_ACTIVE_SPIDER_MINUTES, ZAP_ACTIVE_START_MINUTES } from '../src/engine/zap-active.js';
import { assemble as assembleFiles, judgeAssembled } from '../src/layers/assemble.js';
import { releaseJobs } from '../src/layers/deploy.js';
import { buildShortDoc } from '../src/audit/render-short.js';
import { ctxFor } from '../src/audit/render.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool } from '../src/types.js';
import { assemble, CAPS, editJob, files, judge, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { freePrivateReport } from './fixtures/audit-report.js';

const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
const web = (name = 'app', port = 3000, path = '.') => node({ name, dockerfile: path === '.' ? 'Dockerfile' : `${path}/Dockerfile`, port, path });
const world = (name = 'app') => { const a = assemble(planned(profileOf([web(name)]), { caps: CAPS, over: SKIP_DEPLOY })); return { a, fs: files(a) }; };
const withFile = (fs: CreatedFile[], f: CreatedFile): CreatedFile[] => fs.map((x) => (x.path === f.path ? f : x));
const nightlyOf = (fs: CreatedFile[]): CreatedFile => fs.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
const DL = 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333';

describe('G15a-R8 sec m1, m2: downloads', () => {
  it('referee: a download-artifact step without a name and a path (with: {} or no with) is refused in any job', async () => {
    const { a, fs } = world();
    for (const w of [{}, undefined, { name: 'pipegen-out-dast--app' }]) {
      const step: Obj = { name: 'Download everything', uses: DL, ...(w === undefined ? {} : { with: w }) };
      const f = editJob(nightlyOf(fs), DAST_UPLOAD_JOB, (j: Obj) => { (j.steps as Obj[]).splice(1, 0, step); });
      expect(shown(await judge(withFile(fs, f), a.draft)), JSON.stringify(w)).toMatch(/download-artifact step that names no artifact and folder/);
    }
  });

  it('referee: a service named api-raw gets its pipeline; its raw hand-off is still refused outside dast--api-raw', async () => {
    const { a, fs } = world('api-raw');
    expect(shown(await judge(fs, a.draft))).toBe('');
    const name = 'pipegen-out-dast-raw--api-raw';
    const f = editJob(nightlyOf(fs), DAST_UPLOAD_JOB, (j: Obj) => { (j.steps as Obj[]).splice(1, 0, { name: 'raw', uses: DL, with: { name, path: `\${{ runner.temp }}/pipegen-out/${name}` } }); });
    expect(shown(await judge(withFile(fs, f), a.draft))).toMatch(/raw hand-off "pipegen-out-dast-raw--api-raw"/);
  });
});

// ---------- sec m3, m4: the delivered sign jobs ----------

const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const PIN = { repo: 'o/pipelines', sha: 'c'.repeat(40) };
type Mode = 'attest' | 'key-env' | 'keyless';
function signWorld(mode: Mode, services: string[] = ['app']) {
  const priv = mode !== 'keyless';
  const caps: Capabilities = mode === 'attest' ? { ...CAPS, attestations: true, environments: true }
    : mode === 'key-env' ? { ...CAPS, environments: true, deploymentBranchPolicies: true, envRequiredReviewers: true } : { ...CAPS, keylessSigningAllowed: true };
  const svcs = services.map((s, i) => web(s, 3000 + i, i === 0 ? '.' : s));
  const images = services.map((s) => ({ service: s, repo: `ghcr.io/o/r/pipegen-${s}` }));
  const signing = mode === 'key-env' ? { mode, images, cosignPubSha256: 'b'.repeat(64) } : { mode, images };
  const x = planned(profileOf(svcs, { private: priv }), { caps, over: { ...(priv ? { centralPin: PIN } : {}), signing } as Partial<PipelineDraft> });
  const a = assembleFiles(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode, layout: priv ? 'central' : 'local', plan: x.plan, deploy: releaseJobs(x.draft, { platform: p }) } as Parameters<typeof assembleFiles>[1]);
  return a;
}
const APP = '.github/workflows/pipegen.yml';
function editSignNeeds(a: ReturnType<typeof signWorld>, needs: string[]): ReturnType<typeof signWorld> {
  const f = a.files.find((x) => x.repo === 'app' && x.path === APP) as CreatedFile;
  const doc = parseDocument(f.content);
  expect(doc.getIn(['jobs', 'sign'])).toBeDefined();
  doc.setIn(['jobs', 'sign', 'needs'], doc.createNode(needs));
  const changed = { ...f, content: doc.toString({ lineWidth: 0 }) };
  return { ...a, files: a.files.map((x) => (x === f ? changed : x)) };
}

describe('G15a-R8 sec m3, m4: the sign job', () => {
  it('central: the attest sign job of two images holds every download first, then each image\'s digest and attest; the referee passes it, and one image\'s attest removed is published unsigned', async () => {
    // (v0.2 publishes one image per repository, publishedImageServices: the two-image job is the central file and its caller, as the reviewer's probe B0/B1)
    const d = draftOf({ profile: { ...imageProf, private: true }, capabilities: { ...CAPS, attestations: true, environments: true }, centralPin: PIN, signing: { mode: 'attest', images: [{ service: 'app', repo: 'ghcr.io/o/r/pipegen-app' }, { service: 'web', repo: 'ghcr.io/o/r/pipegen-web' }] } });
    const central = sharedWorkflows(d, 'attest', { reviewed: reviewedList(), platform: GP })[0] as CreatedFile;
    const steps = ((parse(central.content) as Obj).jobs.sign as Obj).steps as Obj[];
    const kinds = steps.map((s) => (/download-artifact/.test(String(s.uses)) ? 'download' : /actions\/attest/.test(String(s.uses)) ? 'attest' : 'digest'));
    expect(kinds).toEqual(['download', 'download', 'digest', 'attest', 'digest', 'attest']);
    const app = (): CreatedFile => {
      const base = workflow(jobsOf(d), { on: { push: { branches: ['main'] }, pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } } });
      const doc = parseDocument(base.content);
      doc.setIn(['jobs', SIGN_JOB_ID], doc.createNode(signCallerJob(d, 'attest', ['gate', 'image-publish'])));
      doc.setIn(['jobs', 'image-publish'], doc.createNode({ 'runs-on': 'ubuntu-24.04', 'timeout-minutes': 30, permissions: { contents: 'read', packages: 'write' }, 'cache-mode': 'none', if: DEPLOY_PUSH_IF, needs: ['gate'],
        steps: [renderPlatformStep('build-push', GP, { file: 'Dockerfile', tags: 'ghcr.io/o/r/pipegen-app:pipegen' }, { push: 'true' })] }));
      return { ...base, content: doc.toString({ lineWidth: 0 }) };
    };
    const run = (files: CreatedFile[]) => referee(files, d, GP, reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
    const r = (await run([central, app()])).issues.map((i) => i.message).join('\n');
    expect(r).not.toMatch(/comes after the repo-code step|In the job "sign"|the job "sign" /);
    expect(r).not.toMatch(/published unsigned/);
    const js = parse(central.content) as Obj;
    const sj = js.jobs.sign as Obj;
    const last = (sj.steps as Obj[]).map((x) => /actions\/attest/.test(String(x.uses))).lastIndexOf(true);
    (sj.steps as Obj[]).splice(last, 1);
    const cut = { ...central, content: stringify(js, { lineWidth: 0 }) };
    expect((await run([cut, app()])).issues.map((i) => i.message).join('\n')).toMatch(/published unsigned/);
  });

  it('referee: the sign job must need image-publish, in every signing mode', async () => {
    for (const mode of ['attest', 'key-env', 'keyless'] as const) {
      const a = signWorld(mode);
      expect(shown(await judgeAssembled(a, JD)), mode).toBe('');
      const r = shown(await judgeAssembled(editSignNeeds(a, ['gate']), JD));
      expect(r, mode).toMatch(/the sign job must need image-publish/);
    }
  });
});

// ---------- spec 1, 2, 5 ----------

describe('G15a-R8 spec 1: the ZAP AF scan at 5 minutes a night, its ceiling beside it', () => {
  const needs = () => floorNeeds(profileOf([web()]), CAPS);
  const prof = profileOf([web()], { private: true, plan: 'free' });
  const act = { pushes: 40, prs: 10, capped: false };
  it('estimate: the headline is 5 a night; the ceiling (the plan\'s own limits and the start) is 45, shown in a basis line; the monthly figure uses the headline', () => {
    expect(jobMinutes('zap-active')).toBe(5);
    expect(ZAP_ACTIVE_CEILING_MINUTES).toBe(ZAP_ACTIVE_SPIDER_MINUTES + ZAP_ACTIVE_PASSIVE_MINUTES + ZAP_ACTIVE_POLICY.maxScanDurationInMins + ZAP_ACTIVE_START_MINUTES);
    expect(ZAP_ACTIVE_CEILING_MINUTES).toBe(45);
    // the plan's own limits are those constants
    const plan = parse(ZAP_ACTIVE_PLAN) as { jobs: { type: string; parameters?: Obj }[] };
    expect(plan.jobs.find((j) => j.type === 'spider')?.parameters?.maxDuration).toBe(ZAP_ACTIVE_SPIDER_MINUTES);
    expect(plan.jobs.find((j) => j.type === 'passiveScan-wait')?.parameters?.maxDuration).toBe(ZAP_ACTIVE_PASSIVE_MINUTES);
    const jobs = jobCategories(needs(), { codeSecurity: true });
    const without = { ...jobs, nightly: jobs.nightly.filter((c) => c !== 'zap-active') };
    const est = estimate(prof, jobs, 1, act, null);
    const less = estimate(prof, without, 1, act, null);
    expect(est.monthlyMinutes - less.monthlyMinutes).toBe(30 * 5);
    expect(est.basis.join('\n')).toMatch(/ZAP active scan[^\n]*about 5 min[^\n]*up to 45 min[^\n]*up to 1,200 more minutes a month/);
  });

  it('estimate: setup minutes and the proof\'s cap grow by the headline only, never the ceiling', () => {
    const jobs = jobCategories(needs(), { codeSecurity: true });
    const without = { ...jobs, nightly: jobs.nightly.filter((c) => c !== 'zap-active') };
    const est = estimate(prof, jobs, 2, act, null);
    const less = estimate(prof, without, 2, act, null);
    expect(est.setupMinutes - less.setupMinutes).toBeLessThanOrEqual(Math.ceil(2 * 5 * 1.3) + 1);
    expect(est.setupMinutes - less.setupMinutes).toBeGreaterThanOrEqual(Math.floor(2 * 5 * 1.3));
    expect(est.setupMinutesCap).toBe(2 * est.setupMinutes);
    expect(est.setupMinutesCap - less.setupMinutesCap).toBeLessThan(2 * 2 * 45);
  });
});

describe('G15a-R8 spec 2, 5', () => {
  it('render-short: the cost line says "then N minutes a month"', () => {
    const r = freePrivateReport([]);
    const doc = buildShortDoc(r, ctxFor('terminal', { knownValues: [], now: () => Date.parse('2026-10-27T12:00:00Z') }, false, r.profile.services));
    const line = (doc.terminal ?? []).join('\n').replace(/\n {2,}/g, ' ').split('\n').find((l) => l.startsWith('Full setup cost:')) as string;
    expect(line).toMatch(/then [\d,]+( or more)? minutes a month/);
  });

  it('gate-job-list: readableFormat and isResultFormat read a raw output format themselves (json is a SARIF result)', () => {
    expect(isResultFormat('json')).toBe(true);
    expect(readableFormat('licences', 'json')).toBe(true);
    expect(isResultFormat('junit')).toBe(false);
    expect(readableFormat('licences', 'zap-json')).toBe(false);
  });
});
