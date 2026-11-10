// v0.2 Plan G, sub-task G15a, ruling G15a-R7 (whole-G15a review r1): the security and spec findings, each as a failing test first.
// sec 1: code scanning is sent only the scrubbed output of a scrub step in a needed job; a raw DAST hand-off is downloaded only by its own
// scrub job. sec 2: "never published unsigned" holds per image (the plan's final cosign sign step, or a fully checked actions/attest step).
// sec 3: the weekly Scorecard job holds no key. sec 4: the ZAP AF context is tied to the target's origin. spec 1: the estimate counts the
// new nightly jobs. spec 2: no Monday double run. spec 3, 6, 7: dead switches gone, pinnedOn documented, the licence scan's raw output json.
import { readFileSync } from 'node:fs';
import { Document, parse, parseDocument, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import * as egress from '../src/engine/egress.js';
import { estimate, jobMinutes } from '../src/estimate/estimate.js';
import { floorNeeds, jobCategories, jobCounts } from '../src/engine/needs.js';
import { DAST_UPLOAD_JOB, DEPLOY_PUSH_IF, HISTORY_UPLOAD_JOB, NIGHTLY_IF, NIGHTLY_WORKFLOW, SCORECARD_JOB, SIGN_STEP_ID_RE } from '../src/engine/job-rules.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { renderPlatformStep, renderScorecardBlock } from '../src/engine/render-step.js';
import { scrubChainProblems } from '../src/engine/job-rules.js';
import { renderEgressStep } from '../src/engine/egress.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { ZAP_ACTIVE_JOB_MINUTES } from '../src/engine/dast-handoff.js';
import { ZAP_ACTIVE_PLAN } from '../src/engine/zap-active.js';
import { gateJobList } from '../src/engine/gate-job-list.js';
import { sharedWorkflows, signCallerJob, SIGN_JOB_ID } from '../src/layers/central.js';
import { assemble as assembleFiles, judgeAssembled, NIGHTLY_CRON, SCORECARD_CRON, SCORECARD_IF } from '../src/layers/assemble.js';
import { scrubBytes } from '../gate/src/scrub.js';
import type { Capabilities, CreatedFile, PipelineDraft, ReviewedTool, SigningPlan } from '../src/types.js';
import { draftOf, imageProf, jobsOf, p as GP, workflow } from './helpers/gate-pipeline.js';
import { reviewedList } from './helpers/render.js';
import { assemble, CAPS, editJob, files, judge, LINTERS as A_LINTERS, node, p as AP, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { makeTempDir, writeIn } from './helpers/make-repo.js';

const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
const web = (name = 'app', port = 3000) => node({ name, dockerfile: 'Dockerfile', port });
/** The reviewer's world: one Dockerised web app, public, code scanning on, the deploy part skipped (every nightly job is written). */
const world = () => { const a = assemble(planned(profileOf([web()]), { caps: CAPS, over: SKIP_DEPLOY })); return { a, fs: files(a) }; };
const withFile = (fs: CreatedFile[], f: CreatedFile): CreatedFile[] => fs.map((x) => (x.path === f.path ? f : x));
const nightlyOf = (fs: CreatedFile[]): CreatedFile => fs.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
const isDownload = (s: Obj): boolean => /download-artifact/.test(String(s.uses));
const isSarif = (s: Obj): boolean => /upload-sarif/.test(String(s.uses));
const NOT_SCRUBBED = /not the scrubbed output of a scrub step/;
const RAW_ELSEWHERE = /raw hand-off/;

describe('G15a-R7 sec 1: code scanning gets only a scrubbed result', () => {
  it('referee: the assembled nightly file, with its three upload jobs, passes', async () => {
    const { a, fs } = world();
    const doc = parse(nightlyOf(fs).content) as Obj;
    for (const id of ['code-scanning', HISTORY_UPLOAD_JOB, DAST_UPLOAD_JOB]) expect(Object.keys(doc.jobs), id).toContain(id);
    const r = await judge(fs, a.draft);
    expect(shown(r)).toBe('');
  });

  it('referee: code-scanning-dast uploading the raw nuclei or ZAP AF hand-off in place of the scrubbed result is refused (the reviewer\'s probe)', async () => {
    const { a, fs } = world();
    for (const lane of ['dast', 'zap-active'] as const) {
      const file = lane === 'dast' ? 'nuclei.sarif' : 'zap-active.json';
      const raw = editJob(nightlyOf(fs), DAST_UPLOAD_JOB, (j: Obj) => {
        for (const s of j.steps as Obj[]) {
          if (isDownload(s) && s.with?.name === `pipegen-out-${lane}--app`) { s.with.name = `pipegen-out-${lane}-raw--app`; s.with.path = `\${{ runner.temp }}/pipegen-out/pipegen-out-${lane}-raw--app`; }
          if (isSarif(s) && String(s.with?.sarif_file).includes(`pipegen-out-${lane}--app/`)) s.with.sarif_file = `\${{ runner.temp }}/pipegen-out/pipegen-out-${lane}-raw--app/${file}`;
        }
      });
      const r = await judge(withFile(fs, raw), a.draft);
      expect(r.ok, lane).toBe(false);
      expect(shown(r), lane).toMatch(NOT_SCRUBBED);
      expect(shown(r), lane).toMatch(RAW_ELSEWHERE);
    }
  });

  it('referee: in each upload job (code-scanning, code-scanning-history, code-scanning-dast), a sarif_file no scrub step of a needed job wrote, a dropped need, or a missing download is refused', async () => {
    const { a, fs } = world();
    for (const id of ['code-scanning', HISTORY_UPLOAD_JOB, DAST_UPLOAD_JOB]) {
      // another file of the downloaded folder: the scrub wrote only its own out file
      const other = editJob(nightlyOf(fs), id, (j: Obj) => { const s = (j.steps as Obj[]).find(isSarif) as Obj; s.with.sarif_file = String(s.with.sarif_file).replace(/[^/]+$/, 'other.sarif'); });
      const r1 = await judge(withFile(fs, other), a.draft);
      expect(shown(r1), `${id} other file`).toMatch(NOT_SCRUBBED);
      // the scrub job dropped from needs: the upload could run before (or without) the scrub
      const unneeded = editJob(nightlyOf(fs), id, (j: Obj) => { j.needs = (j.needs as string[]).slice(1); if ((j.needs as string[]).length === 0) delete j.needs; });
      const r2 = await judge(withFile(fs, unneeded), a.draft);
      expect(shown(r2), `${id} need dropped`).toMatch(NOT_SCRUBBED);
      // the download of the scrubbed artifact removed: the file would be whatever else is in the folder
      const undownloaded = editJob(nightlyOf(fs), id, (j: Obj) => { const k = (j.steps as Obj[]).findIndex(isDownload); (j.steps as Obj[]).splice(k, 1); });
      const r3 = await judge(withFile(fs, undownloaded), a.draft);
      expect(shown(r3), `${id} no download`).toMatch(NOT_SCRUBBED);
    }
  });

  it('referee: a raw hand-off artifact is downloaded only by its own <lane>--<svc> scrub job', async () => {
    const { a, fs } = world();
    const extra = (name: string): Obj => { const { usesComment: _u, ...s } = renderPlatformStep('download-artifact', AP, { name, path: `\${{ runner.temp }}/pipegen-out/${name}` }) as Obj; return { ...s, name: 'Download a raw hand-off' }; };
    // in the upload job (no upload of it) and in the other lane's scrub job
    const inUpload = editJob(nightlyOf(fs), DAST_UPLOAD_JOB, (j: Obj) => { (j.steps as Obj[]).splice(1, 0, extra('pipegen-out-dast-raw--app')); });
    expect(shown(await judge(withFile(fs, inUpload), a.draft))).toMatch(RAW_ELSEWHERE);
    const inOtherLane = editJob(nightlyOf(fs), 'zap-active--app', (j: Obj) => { (j.steps as Obj[]).splice(1, 0, extra('pipegen-out-dast-raw--app')); });
    expect(shown(await judge(withFile(fs, inOtherLane), a.draft))).toMatch(RAW_ELSEWHERE);
    // the merge file's own pair is untouched by the rule
    expect(shown(await judge(fs, a.draft))).toBe('');
  });
});

// ---------- sec 2 ----------

const LINTERS: Linters = { actionlint: async () => '/stub', zizmor: async () => '/stub' };
const deps = { reviewed: reviewedList(), platform: GP };
const SHA = 'a'.repeat(40);
const IMG = { service: 'app', repo: 'ghcr.io/o/r/pipegen-app' };
const IMG2 = { service: 'web', repo: 'ghcr.io/o/r/pipegen-web' };
const NEEDS = ['gate', 'image-publish'];
const CAPS_BASE: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: false };
const ATTEST_CAPS: Capabilities = { ...CAPS_BASE, attestations: true, environments: true };
const KE_CAPS: Capabilities = { ...CAPS_BASE, environments: true, deploymentBranchPolicies: true };
const DEPLOY_ON = { push: { branches: ['main'] }, pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
const PUB_SHA = 'b'.repeat(64);
const privProf = { ...imageProf, private: true };
const sjudge = (fs: CreatedFile[], d: PipelineDraft, reviewed: ReviewedTool[] = reviewedList()) => referee(fs, d, GP, reviewed, LINTERS, 'tok', { runLinters: async () => [] });
const sshow = (r: { issues: { check: string; message: string }[] }): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const UNSIGNED = /published unsigned/;
const publishJob = { 'runs-on': 'ubuntu-24.04', 'timeout-minutes': 30, permissions: { contents: 'read', packages: 'write' }, 'cache-mode': 'none', if: DEPLOY_PUSH_IF, needs: ['gate'],
  steps: [renderPlatformStep('build-push', GP, { file: 'Dockerfile', tags: 'ghcr.io/o/r/pipegen-app:pipegen' }, { push: 'true' })] };
/** The app's pipegen.yml with the sign caller and an image-publish job. */
function appWith(d: PipelineDraft, mode: 'attest' | 'key-env', perms?: Obj): CreatedFile {
  const base = workflow(jobsOf(d), { on: DEPLOY_ON });
  const doc = parseDocument(base.content);
  const caller = signCallerJob(d, mode, NEEDS) as Obj;
  doc.setIn(['jobs', SIGN_JOB_ID], doc.createNode(perms === undefined ? caller : { ...caller, permissions: perms }));
  doc.setIn(['jobs', 'image-publish'], doc.createNode(publishJob));
  return { ...base, content: doc.toString({ lineWidth: 0 }) };
}
function editCentral(f: CreatedFile, edit: (j: Obj) => void): CreatedFile {
  const js = parse(f.content) as Obj;
  edit(js.jobs[SIGN_JOB_ID]);
  const doc = new Document();
  doc.contents = doc.createNode(js);
  return { ...f, content: doc.toString({ lineWidth: 0 }) };
}

describe('G15a-R7 sec 2: never published unsigned, per image', () => {
  it('referee: attest mode, a sign job with the digest step but no actions/attest, and an image publish → refused (the reviewer\'s probe)', async () => {
    const d = draftOf({ profile: privProf, capabilities: ATTEST_CAPS, centralPin: { repo: 'o/pipelines', sha: SHA }, signing: { mode: 'attest', images: [IMG] } });
    const shared = sharedWorkflows(d, 'attest', deps)[0] as CreatedFile;
    const perms = { contents: 'read', packages: 'write' };
    const central = editCentral(shared, (sj) => {
      const { usesComment: _u, ...eg } = renderEgressStep(['ghcr'], { dockerNetworks: false }) as Obj;
      sj.steps = [eg, sj.steps[0], sj.steps[1]];
      sj.permissions = perms;
    });
    const r = await sjudge([central, appWith(d, 'attest', perms)], d);
    expect(sshow(r)).toMatch(UNSIGNED);
    expect(sshow(r)).toMatch(/digest step of .* with no actions\/attest of that image after it/);
    // the full attest set: the rule holds
    const r0 = await sjudge([shared, appWith(d, 'attest')], d);
    expect(sshow(r0)).not.toMatch(UNSIGNED);
  });

  it('referee: attest mode, an actions/attest step that does not pass its checks does not count as signing the image', async () => {
    const d = draftOf({ profile: privProf, capabilities: ATTEST_CAPS, centralPin: { repo: 'o/pipelines', sha: SHA }, signing: { mode: 'attest', images: [IMG] } });
    const shared = sharedWorkflows(d, 'attest', deps)[0] as CreatedFile;
    const central = editCentral(shared, (sj) => {
      const k = (sj.steps as Obj[]).findIndex((s) => /actions\/attest/.test(String(s.uses)));
      sj.steps[k].with['subject-name'] = 'ghcr.io/o/other';
    });
    const r = await sjudge([central, appWith(d, 'attest')], d);
    expect(sshow(r)).toMatch(UNSIGNED);
  });

  it('referee: cosign modes, a sign job without the plan\'s final sign step of an image (only the install, or one image of two) → published unsigned', async () => {
    const plan = (images: SigningPlan['images']): SigningPlan => ({ mode: 'key-env', images, cosignPubSha256: PUB_SHA });
    const d = draftOf({ profile: privProf, capabilities: KE_CAPS, centralPin: { repo: 'o/pipelines', sha: SHA }, signing: plan([IMG]) });
    const shared = sharedWorkflows(d, 'key-env', deps)[0] as CreatedFile;
    const r0 = await sjudge([shared, appWith(d, 'key-env')], d);
    expect(sshow(r0)).not.toMatch(UNSIGNED);
    const installOnly = editCentral(shared, (sj) => { sj.steps = (sj.steps as Obj[]).filter((s) => !SIGN_STEP_ID_RE.test(String(s.id))); });
    expect(sshow(await sjudge([installOnly, appWith(d, 'key-env')], d))).toMatch(UNSIGNED);
    // two images, the second one's sign step gone
    const d2 = draftOf({ profile: privProf, capabilities: KE_CAPS, centralPin: { repo: 'o/pipelines', sha: SHA }, signing: plan([IMG, IMG2]) });
    const shared2 = sharedWorkflows(d2, 'key-env', deps)[0] as CreatedFile;
    expect(sshow(await sjudge([shared2, appWith(d2, 'key-env')], d2))).not.toMatch(UNSIGNED);
    const oneOfTwo = editCentral(shared2, (sj) => {
      const last = (sj.steps as Obj[]).map((s) => SIGN_STEP_ID_RE.test(String(s.id))).lastIndexOf(true);
      (sj.steps as Obj[]).splice(last, 1);
    });
    expect(sshow(await sjudge([oneOfTwo, appWith(d2, 'key-env')], d2))).toMatch(UNSIGNED);
  });
});

// ---------- sec 3, spec 2 (the assembled files) ----------

const GATE_T = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const JDEPS = { platform: AP, reviewed: REVIEWED, linters: A_LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
function fullWorld() {
  const x = planned(profileOf([web()]), { caps: CAPS, over: SKIP_DEPLOY });
  const a = assembleFiles(x.draft, { gate: GATE_T, reviewed: REVIEWED, platform: AP, mode: 'none', layout: 'local', plan: x.plan } as Parameters<typeof assembleFiles>[1]);
  const file = a.files.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
  return { a, file, doc: parse(file.content) as Obj };
}
async function judgeEdited(path: string, edit: (doc: Obj) => void): Promise<string> {
  const w = fullWorld();
  const f = w.a.files.find((x) => x.path === path) as CreatedFile;
  const doc = structuredClone(parse(f.content) as Obj);
  edit(doc);
  const changed = { ...f, content: stringify(doc, { lineWidth: 0 }) };
  return shown(await judgeAssembled({ ...w.a, files: w.a.files.map((x) => (x === f ? changed : x)) }, JDEPS));
}
const KEY_NAME = ['PIPEGEN_FP', 'KEY'].join('_');

describe('G15a-R7 sec 3: the weekly Scorecard job holds no key', () => {
  it('render: the scorecard job names no secret and no key (its scrub runs without the fingerprint key); the referee passes', async () => {
    const w = fullWorld();
    const card = (w.doc.jobs as Obj)[SCORECARD_JOB] as Obj;
    const text = JSON.stringify(card);
    expect(text).not.toMatch(/secrets\./);
    expect(text).not.toContain(KEY_NAME);
    const scrub = (card.steps as Obj[]).find((s) => s.with?.mode === 'scrub') as Obj;
    expect(Object.keys(scrub.with)).not.toContain('fp-key');
    // every other scrub still carries it
    for (const [id, j] of Object.entries(w.doc.jobs as Record<string, Obj>)) {
      if (id === SCORECARD_JOB) continue;
      for (const s of (j.steps ?? []) as Obj[]) if (s.with?.mode === 'scrub') expect(Object.keys(s.with), id).toContain('fp-key');
    }
    expect(shown(await judgeAssembled(w.a, JDEPS))).toBe('');
  });

  it('referee: the key back in the scorecard scrub, or a scrub of another tool without it → refused', async () => {
    const back = await judgeEdited(NIGHTLY_WORKFLOW, (doc) => {
      const s = ((doc.jobs[SCORECARD_JOB] as Obj).steps as Obj[]).find((x) => x.with?.mode === 'scrub') as Obj;
      s.with['fp-key'] = `\${{ secrets.${KEY_NAME} }}`;
    });
    expect(back).toMatch(/Scorecard/);
    const missing = await judgeEdited(NIGHTLY_WORKFLOW, (doc) => {
      const s = ((doc.jobs['dast--app'] as Obj).steps as Obj[]).find((x) => x.with?.mode === 'scrub') as Obj;
      delete s.with['fp-key'];
    });
    expect(missing).toMatch(/no fp-key input/);
  });

  it('job rules: each guard holds on its own: the scrub chain refuses the key in the Scorecard scrub, and the job rule refuses any secret in the scorecard job (mutant S3b)', async () => {
    const card = REVIEWED.find((t) => t.id === 'scorecard-action') as ReviewedTool;
    const steps = renderScorecardBlock(card, AP, GATE_T);
    expect(scrubChainProblems(steps)).toEqual([]);
    const keyed = steps.map((s) => (s.with?.mode === 'scrub' ? { ...s, with: { ...s.with, 'fp-key': `\${{ secrets.${KEY_NAME} }}` } } : s));
    expect(scrubChainProblems(keyed).join('\n')).toMatch(/Scorecard result with the fingerprint key/);
    // a secret on another step of the job (not the scrub): the job rule alone
    const other = await judgeEdited(NIGHTLY_WORKFLOW, (doc) => {
      const move = ((doc.jobs[SCORECARD_JOB] as Obj).steps as Obj[]).find((x) => typeof x.run === 'string') as Obj;
      move.env = { ...(move.env ?? {}), X: `\${{ secrets.${KEY_NAME} }}` };
    });
    expect(other).toMatch(/weekly Scorecard job, which runs Scorecard's container and a scrub that needs no key: it names no secret/);
  });

  it('gate: the Scorecard scrub runs with no key at all', () => {
    const sarif = readFileSync('test/fixtures/scorecard/scorecard-action.sarif');
    const out = scrubBytes(sarif, { tool: 'scorecard-action', format: 'sarif', eventText: JSON.stringify({ after: 'c'.repeat(40) }), workspace: '/home/runner/work/r/r' });
    expect(out.status).toBe('ok');
  });
});

describe('G15a-R7 spec 2: no Monday double run', () => {
  it('assemble: every nightly job runs only on the nightly cron, Scorecard (and its upload, through needs) only on the weekly one; the referee passes', async () => {
    const w = fullWorld();
    expect((w.doc.on as Obj).schedule).toEqual([{ cron: NIGHTLY_CRON }, { cron: SCORECARD_CRON }]);
    expect(NIGHTLY_IF).toBe(`github.event.schedule == '${NIGHTLY_CRON}'`);
    const jobs = w.doc.jobs as Record<string, Obj>;
    for (const id of ['nightly', 'secrets-history', HISTORY_UPLOAD_JOB, 'workflow-lint-online', 'image-build--app', 'dast-run--app', 'dast--app', 'zap-active-run--app', 'zap-active--app', DAST_UPLOAD_JOB]) {
      expect(jobs[id]?.if, id).toBe(NIGHTLY_IF);
    }
    expect(jobs[SCORECARD_JOB]?.if).toBe(SCORECARD_IF);
    expect(jobs['code-scanning']?.needs).toEqual([SCORECARD_JOB]);
    expect(jobs['code-scanning']?.if).toBeUndefined();
    expect(shown(await judgeAssembled(w.a, JDEPS))).toBe('');
  });

  it('referee: the nightly condition only on a job of the nightly file, never on the scorecard job', async () => {
    const merge = await judgeEdited('.github/workflows/pipegen-merge.yml', (doc) => { (doc.jobs['sast--app'] as Obj).if = NIGHTLY_IF; });
    expect(merge).toMatch(/nightly condition/);
    const card = await judgeEdited(NIGHTLY_WORKFLOW, (doc) => { (doc.jobs[SCORECARD_JOB] as Obj).if = NIGHTLY_IF; });
    expect(card).toMatch(/weekly Scorecard job/);
  });
});

// ---------- sec 4 ----------

/** The AF context as ZAP evaluates it, with the target substituted: each include and exclude a whole-URL Java regex (\Q…\E quoted). */
function inContext(target: string, url: string): boolean {
  const ctx = (parse(ZAP_ACTIVE_PLAN) as Obj).env.contexts[0] as { urls: string[]; includePaths: string[]; excludePaths?: string[] };
  const java = (re: string): RegExp => new RegExp(`^(?:${re.replaceAll('${PIPEGEN_ZAP_TARGET}', target).replace(/\\Q([\s\S]*?)\\E/g, (_m, lit: string) => lit.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))})$`);
  // measured on the pinned image (G15a-R7): the AF adds each context URL as an include of its own, `<url>.*` unquoted
  const includes = [...ctx.urls.map((u) => `${u}.*`), ...ctx.includePaths].map(java);
  const excludes = (ctx.excludePaths ?? []).map(java);
  return includes.some((r) => r.test(url)) && !excludes.some((r) => r.test(url));
}

describe('G15a-R7 sec 4: the ZAP AF context is the target\'s origin only', () => {
  it('zap-active: the include is the quoted target, then nothing or a path; everything else is excluded; the plan is the one re-measured on the pinned image', () => {
    const ctx = (parse(ZAP_ACTIVE_PLAN) as Obj).env.contexts[0] as Obj;
    expect(ctx.includePaths).toEqual(['\\Q${PIPEGEN_ZAP_TARGET}\\E(?:/.*)?']);
    expect(ctx.excludePaths).toEqual(['(?!\\Q${PIPEGEN_ZAP_TARGET}\\E(?:/.*)?$).*']);
    expect(ZAP_ACTIVE_PLAN).toBe(readFileSync('test/fixtures/zap/plans/af-active-origin.yaml', 'utf8'));
    const af = loadReviewed().find((t) => t.id === 'zap-af-active') as ReviewedTool;
    expect(af.fixedInputs.config?.content).toBe(ZAP_ACTIVE_PLAN);
  });

  it('zap-active: http://127.0.0.1:3000 keeps its own paths in scope, never :30001, an @host, or a longer host name', () => {
    const t = 'http://127.0.0.1:3000';
    for (const u of [t, `${t}/`, `${t}/search?q=1`, `${t}/a/b.html`]) expect(inContext(t, u), u).toBe(true);
    for (const u of ['http://127.0.0.1:30001/', 'http://127.0.0.1:30001', `${t}@registry-1.docker.io/`, `${t}@127.0.0.1:5432/`, `${t}.evil.example/`, 'http://127.0.0.1:3000x/', 'http://127.0.0.1:8080/']) {
      expect(inContext(t, u), u).toBe(false);
    }
    // the dots of the target are literal: 127a0a0a1 is not 127.0.0.1
    expect(inContext(t, 'http://127a0a0a1:3000/')).toBe(false);
  });
});

// ---------- spec 1 ----------

describe('G15a-R7 spec 1: the monthly-minutes estimate counts the new nightly jobs', () => {
  const needs = () => floorNeeds(profileOf([web()]), CAPS);
  it('estimate: the nightly history scan, workflow-lint-online, the ZAP AF pair, the scrub and upload jobs and the weekly Scorecard are counted; without code scanning only the online lint is', () => {
    const on = jobCategories(needs(), { codeSecurity: true }).nightly;
    for (const c of ['secrets-history', 'workflow-lint-online', 'zap-active', 'dast-scrub', 'code-scanning', 'scorecard']) expect(on, c).toContain(c);
    expect(on.filter((c) => c === 'code-scanning')).toHaveLength(3);
    expect(on.filter((c) => c === 'dast-scrub')).toHaveLength(2);
    // (G15a-R8 spec 1: the headline is 5 a night; the job's 60-minute timeout only guards a hang: test/g15-r8.test.ts)
    expect(jobMinutes('zap-active')).toBe(5);
    expect(ZAP_ACTIVE_JOB_MINUTES).toBe(60);
    expect(jobCounts(needs(), { codeSecurity: true }).nightly).toBe(on.length);
    const off = jobCategories(needs(), { codeSecurity: false }).nightly;
    for (const c of ['secrets-history', 'zap-active', 'dast-scrub', 'code-scanning']) expect(off, c).not.toContain(c);
    expect(off).toContain('workflow-lint-online');
    // leans high when not told
    expect(jobCategories(needs()).nightly).toEqual(on);
  });

  // (G15a-R8 spec 1 replaced the AF lane's pricing test: test/g15-r8.test.ts "the headline is 5 a night …")
});

// ---------- spec 3, 6, 7 ----------

describe('G15a-R7 spec 3, 6, 7', () => {
  it('egress: the attest verify set is a set, with no refusal text left behind it', () => {
    expect(egress.ATTEST_VERIFY_SETS).toEqual(['github-attest']);
    expect(Object.keys(egress)).not.toContain('ATTEST_VERIFY_REFUSAL');
  });

  it('reviewed: pinnedOn of an entry is documented in the list header and docs/cooldown.md; the cli/cli branch signer cites ruling G15a-R7', () => {
    const header = readFileSync('data/reviewed-tools.yml', 'utf8').split('\npinnedOn:')[0] as string;
    expect(header).toMatch(/pinnedOn \(/);
    expect(readFileSync('docs/cooldown.md', 'utf8')).toMatch(/pinnedOn/);
    const src = readFileSync('src/engine/reviewed.ts', 'utf8');
    const at = src.indexOf('BRANCH_SIGNERS');
    expect(src.slice(Math.max(0, at - 1200), at + 400)).toMatch(/G15a-R7/);
  });

  it('reviewed: the licence scan declares its raw output as json; the loader refuses sarif there and json on any other entry', () => {
    const lic = loadReviewed().find((t) => t.id === 'trivy-licence') as ReviewedTool;
    expect(lic.step.output).toEqual({ path: 'trivy-licence.json', format: 'json' });
    const raw = parse(readFileSync('data/reviewed-tools.yml', 'utf8')) as { pinnedOn: string; tools: Obj[] };
    const entryOf = (id: string): Obj => structuredClone(raw.tools.find((t) => t.id === id) as Obj);
    const tryLoad = (e: Obj): (() => unknown) => {
      const dir = makeTempDir();
      writeIn(dir, 'reviewed-tools.yml', stringify({ pinnedOn: raw.pinnedOn, tools: [e] }));
      return () => loadReviewed(`${dir}/reviewed-tools.yml`);
    };
    expect(tryLoad(entryOf('trivy-licence'))).not.toThrow();
    const asSarif = entryOf('trivy-licence'); (asSarif.step as Obj).output.format = 'sarif';
    expect(tryLoad(asSarif)).toThrow(/licence/);
    const other = entryOf('trivy-config'); (other.step as Obj).output.format = 'json';
    expect(tryLoad(other)).toThrow(/json/);
  });

  it('render: the licence job still scrubs Trivy\'s JSON into SARIF, and the gate\'s job list reads it as SARIF', async () => {
    const { a, fs } = world();
    const merge = parse((fs.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile).content) as Obj;
    const scrub = ((merge.jobs.licences as Obj).steps as Obj[]).find((s) => s.with?.mode === 'scrub') as Obj;
    expect(scrub.with).toMatchObject({ tool: 'trivy-licence', format: 'sarif' });
    expect(String(scrub.with.raw)).toMatch(/trivy-licence\.json$/);
    const entry = gateJobList(a.draft).find((e) => e.tool === 'trivy-licence');
    expect(entry?.format).toBe('sarif');
    expect(shown(await judge(fs, a.draft))).toBe('');
  });
});
