// v0.2 Plan G G4 fix round 1 (rulings G4-R1): DAST split into a key-free run job and a scrub job (the reviewer's design A), the referee's
// egress backstop (E0d on every delivered job, E3-R3 in the referee), and the starter-test job's Node major by step identity.
// The run job `dast-run--<svc>` holds neither the key nor any other credential; it starts the app in containers only (pipegen's compose file, or the image archive
// checked by its sha256 and bound to 127.0.0.1), runs the reviewed DAST step, and hands the raw result on with its sha256 (the one new
// order-rule exception, after harmless steps only). `dast--<svc>` (the gate's job) downloads it, checks the sha256, scrubs and uploads.
import { describe, expect, it } from 'vitest';
import { composeText } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { EGRESS_DOMAIN_SETS } from '../src/engine/egress-sets.js';
import { SHARED_CDN_SETS } from '../src/engine/egress.js';
import { gateJobList } from '../src/engine/gate-job-list.js';
import {
  checkJobOrder, jobOutputsProblems, scrubChainProblems, DAST_HANDOFF_STEP_ID, DAST_RAW_SHA_ENV, DAST_RAW_SHA_OUTPUT, dastAppStepId, dastCheckStepId, dastRawArtifact, dastRunJobId, NO_SCANS,
} from '../src/engine/job-rules.js';
import { keyOffers, specFor } from '../src/debate/builder.js';
import { floorNeeds } from '../src/engine/needs.js';
import { renderComposeUp, renderJobPrelude, renderProjectScript, renderStep, stepsToYaml } from '../src/engine/render-step.js';
import { egressDomains } from '../src/engine/tool-flags.js';
import { AssembleError, starterTestJob, type Job } from '../src/layers/jobs.js';
import type { CreatedFile, Need, StepSpec } from '../src/types.js';
import { APP_KEY, allJobs, assemble, CAPS, domainsOf, editJob, files, judge, node, p, planned, profileOf, SEC, shown, wf, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
/** A runnable service with a Dockerfile and a port: its image is built, scanned and run for DAST. */
const web = () => node({ dockerfile: 'Dockerfile', port: 3000 });
const KEY_RE = new RegExp(`${SEC}\\.|github\\.token|fp-key|PIPEGEN_FP_KEY`);
const SHARED_HOSTS = [...SHARED_CDN_SETS].flatMap((s) => EGRESS_DOMAIN_SETS[s]);

describe('G4 fix round 1: DAST in two jobs (G4-R1, design A)', () => {
  it('assemble: dast runs in dast-run--<svc> with no key and no secret; dast--<svc> checks the raw sha256, scrubs and gives the three outputs', async () => {
    const a = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    expect(dastRunJobId('app')).toBe('dast-run--app');
    const run = a.merge['dast-run--app'] as Job;
    const scrub = a.merge['dast--app'] as Job;
    expect(run, 'the run job').toBeDefined();
    expect(scrub, 'the scrub job').toBeDefined();
    // the run job: no key, no secret, no scrub; contents read only; the reviewed ZAP step at the local URL; the hand-off tail last
    expect(JSON.stringify(run)).not.toMatch(KEY_RE);
    expect(run.steps.some((s) => s.with?.mode === 'scrub')).toBe(false);
    expect(run.permissions).toEqual({ contents: 'read' });
    expect(run.steps[0]?.uses).toMatch(/^bullfrogsec\/bullfrog@/);
    const zap = run.steps.find((s) => /zap-baseline/.test(s.name) && s.run !== undefined && s.id?.startsWith('tool-run-') === true);
    expect(zap?.env?.PIPEGEN_ARG_0).toBe('http://127.0.0.1:3000');
    const n = run.steps.length;
    expect(run.steps[n - 2]?.id).toBe(DAST_HANDOFF_STEP_ID);
    expect(run.steps[n - 1]?.with?.name).toBe(dastRawArtifact('app'));
    expect(run.outputs).toEqual({ [DAST_RAW_SHA_OUTPUT]: `\${{ steps.${DAST_HANDOFF_STEP_ID}.outputs.sha256 }}` });
    // the scrub job: the gate's job id; the download, the sha256 check against the run job's output, the scrub, the upload; no checkout
    expect(scrub.needs).toEqual(['dast-run--app']);
    expect(JSON.stringify(scrub.steps)).not.toMatch(/actions\/checkout@|zap-baseline\.py|docker run/);
    const check = scrub.steps.find((s) => s.id === dastCheckStepId('app'));
    expect(check?.env?.[DAST_RAW_SHA_ENV]).toBe('${{ needs.dast-run--app.outputs.raw-sha256 }}');
    expect(check?.run).toMatch(/sha256sum --check --strict -/);
    const sc = scrub.steps.find((s) => s.with?.mode === 'scrub');
    expect(sc?.with).toMatchObject({ artifact: 'pipegen-out-dast--app', tool: 'zap-baseline', format: 'zap-json', raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-dast--app/zap.json' });
    expect(scrub.steps.indexOf(check as never)).toBeLessThan(scrub.steps.indexOf(sc as never));
    for (const k of ['sha256', 'status', 'error']) expect(scrub.outputs?.[`pipegen-out-dast--app-${k}`]).toBe(`\${{ steps.${sc?.id}.outputs.${k} }}`);
    // the gate reads it as a blocking findings check (G0-R1: never warn-only, never dropped); no base twin of it anywhere
    const entry = gateJobList(a.draft).find((e) => e.needId === 'dast');
    expect(entry).toMatchObject({ job: 'dast--app', blocking: true, format: 'zap-json' });
    expect(a.merge.gate?.needs).toContain('dast--app');
    expect(JSON.stringify(a.merge['base-scan'])).not.toMatch(/zap|dast/);
    expect(a.notes.join('\n')).not.toMatch(/scan of the running app/);
    expect(shown(await judge(files(a), a.draft))).toBe('');
  });

  it('assemble: the app starts in containers only: pipegen\'s compose file when the draft holds it, else the checked image archive bound to 127.0.0.1', async () => {
    // the archive: downloaded, checked against the image build's sha256, loaded and run with no capabilities, published on 127.0.0.1 only
    const a = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    const run = a.merge['dast-run--app'] as Job;
    expect(run.needs).toEqual(['image-build--app']);
    const start = run.steps.find((s) => s.id === dastAppStepId('app'));
    expect(start?.run).toMatch(/docker load/);
    expect(start?.run).toContain('127.0.0.1:3000:3000');
    expect(start?.run).toMatch(/--cap-drop ALL/);
    expect(start?.run).toMatch(/no-new-privileges/);
    expect(start?.run).not.toMatch(/ -v |--volume|--mount|--env-file|--privileged|--network host/);
    const ids = run.steps.map((s) => s.id ?? s.uses?.split('@')[0]);
    expect(ids.indexOf('pipegen-image-check--app')).toBeLessThan(ids.indexOf(dastAppStepId('app')));
    // nothing of the repository runs on the runner itself: no npm, no project script, no start script
    expect(JSON.stringify(run.steps)).not.toMatch(/npm" (?:ci|test|run)|pipegen-npm-ci-/);
    // pipegen's compose file: runtime env, compose up (its app published on 127.0.0.1), then the scan
    const dep = { kind: 'postgres' as const, name: 'postgres', evidence: 'x', envVars: ['DATABASE_URL'] };
    const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], dependsOn: [dep] })]);
    const compose: CreatedFile = { path: 'docker-compose.pipegen.yml', content: composeText(prof, loadBaseImages()) as string, part: 'compose', reason: 't', repo: 'app' };
    const b = assemble(planned(prof, { over: { created: [compose], ...SKIP_DEPLOY } }));
    const crun = b.merge['dast-run--app'] as Job;
    const cids = crun.steps.map((s) => s.id ?? '');
    expect(cids.some((x) => x.startsWith('runtime-env-'))).toBe(true);
    expect(crun.steps.some((s) => s.id === renderComposeUp().id && s.run === renderComposeUp().run)).toBe(true);
    expect(crun.steps.find((s) => s.id?.startsWith('tool-run-') === true)?.env?.PIPEGEN_ARG_0).toBe('http://127.0.0.1:3000');
    expect(crun.steps[0]?.with?.['allowed-ips']).toBe('172.16.0.0/12');
    expect(shown(await judge([...files(b), compose], b.draft))).toBe('');
  });

  it('assemble: a blocking dast need with no container image stops assembly with a plain reason', () => {
    // runnable (an express server) but no Dockerfile and no compose file: nothing pipegen can start in a container
    const x = planned(profileOf([node({ frameworks: ['express'], port: 3000, scripts: ['test', 'lint', 'start'] })]), { over: SKIP_DEPLOY });
    expect(x.draft.needs.some((n) => n.id === 'dast' && n.blocking)).toBe(true);
    expect(() => assemble(x)).toThrow(AssembleError);
    expect(() => assemble(x)).toThrow(/"dast" for "app".*no container image/);
    // a Dockerfile but no port to scan: refused the same way, never dropped
    const noPort = planned(profileOf([node({ dockerfile: 'Dockerfile' })]), { over: SKIP_DEPLOY });
    expect(() => assemble(noPort)).toThrow(/"dast" for "app".*port/);
  });

  it('assemble: nuclei runs the same split where it is offered', async () => {
    // nuclei is advisory (ADVISORY_TOOLS): offered only for a non-blocking dast need
    const prof = profileOf([web()]);
    const needs: Need[] = floorNeeds(prof, CAPS).map((n) => (n.id === 'dast' ? { ...n, blocking: false } : n));
    const nuc = planned(prof, { needs, over: SKIP_DEPLOY, edit: (s) => s.filter((st) => st.needId !== 'dast') });
    const o = keyOffers(needs, nuc.plan.candidates, prof, { reviewed: REVIEWED });
    const ref = o.refs.find((r) => r.key === 'dast--app');
    const offer = o.offers.get('dast--app')?.find((of) => of.entry.id === 'nuclei');
    expect(offer, 'nuclei is offered for a non-blocking dast need').toBeDefined();
    const withNuclei = specFor(ref as NonNullable<typeof ref>, offer as NonNullable<typeof offer>, prof);
    const a = assemble({ ...nuc, draft: { ...nuc.draft, steps: [...nuc.draft.steps, withNuclei] } });
    const run = a.merge['dast-run--app'] as Job;
    expect(run.steps.some((s) => /nuclei/.test(s.name) && s.id?.startsWith('tool-run-') === true)).toBe(true);
    expect(JSON.stringify(run)).not.toMatch(KEY_RE);
    const sc = (a.merge['dast--app'] as Job).steps.find((s) => s.with?.mode === 'scrub');
    expect(sc?.with).toMatchObject({ tool: 'nuclei', format: 'sarif', raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-dast--app/nuclei.sarif' });
    // C1a: the hand-off checks the app still answers after the scan (nuclei exits 0 on an unreachable target)
    expect(run.steps.find((s) => s.id === DAST_HANDOFF_STEP_ID)?.run).toMatch(/curl[^\n]*http:\/\/127\.0\.0\.1:3000\/[^\n]*\n[^\n]*\[1-4\]\[0-9\]\[0-9\]\) ;; \*\) pg_fail/);
    expect(shown(await judge(files(a), a.draft))).toBe('');
  });

  it('job-rules: the dast-run tail is the one exception (container start, the DAST step, the hand-off, its upload), after harmless steps only', () => {
    const a = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    const run = (a.merge['dast-run--app'] as Job).steps;
    expect(checkJobOrder(run, { id: 'dast-run--app', scans: NO_SCANS })).toEqual([]);
    // the same steps in a job of another id: the scanner after the app start is refused
    expect(checkJobOrder(run, { id: 'dast--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    expect(checkJobOrder(run, { id: 'dast-run--web', scans: NO_SCANS }).length).toBeGreaterThan(0);
    // repo code on the runner before the start (a project script's npm ci): refused
    const ps = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, { profile: a.draft.profile }).steps;
    const at = run.findIndex((s) => s.id === dastAppStepId('app'));
    expect(checkJobOrder([...run.slice(0, at), ...ps.slice(2), ...run.slice(at)], { id: 'dast-run--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    // anything between the parts of the tail, or after the upload: refused
    expect(checkJobOrder([...run, ps[3] as never], { id: 'dast-run--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    const h = run.findIndex((s) => s.id === DAST_HANDOFF_STEP_ID);
    expect(checkJobOrder([...run.slice(0, h), ps[3] as never, ...run.slice(h)], { id: 'dast-run--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    // without the hand-off step, or with the upload of another folder: refused
    expect(checkJobOrder([...run.slice(0, h), ...run.slice(h + 1)], { id: 'dast-run--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    const up = run[run.length - 1] as unknown as Obj;
    expect(checkJobOrder([...run.slice(0, -1), { ...up, with: { ...up.with, name: 'pipegen-out-dast--app', path: '${{ runner.temp }}/pipegen-out/pipegen-out-dast--app' } } as never], { id: 'dast-run--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    // a credential anywhere in the run job: the exception does not apply (the scan after the app start is refused)
    const tok = run.map((x) => (x.id?.startsWith('tool-run-') === true ? { ...x, env: { ...x.env, PIPEGEN_T: '${{ github.token }}' } } : x));
    expect(checkJobOrder(tok, { id: 'dast-run--app', scans: NO_SCANS }).length).toBeGreaterThan(0);
    // the hash check's expression only on its own id; the raw sha256 output only on a dast-run job; a check stands only for its own service's result
    const chk = (a.merge['dast--app'] as Job).steps.find((x) => x.id === dastCheckStepId('app')) as never as Obj;
    expect(() => stepsToYaml([{ ...chk, id: 'pipegen-image-check--app' } as never])).toThrow(/expression/);
    expect(() => stepsToYaml([{ ...chk, env: { ...chk.env, [DAST_RAW_SHA_ENV]: '${{ needs.dast-run--web.outputs.raw-sha256 }}' } } as never])).toThrow(/expression/);
    expect(jobOutputsProblems('sast--app', { [DAST_RAW_SHA_OUTPUT]: `\${{ steps.${DAST_HANDOFF_STEP_ID}.outputs.sha256 }}` }, run).join(' ')).toMatch(/only a dast-run--<service> job/);
    expect(jobOutputsProblems('dast-run--app', { [DAST_RAW_SHA_OUTPUT]: `\${{ steps.${DAST_HANDOFF_STEP_ID}.outputs.sha256 }}` }, run)).toEqual([]);
    const sj = (a.merge['dast--app'] as Job).steps;
    expect(scrubChainProblems(sj)).toEqual([]);
    expect(scrubChainProblems(sj.map((x) => (x.id === dastCheckStepId('app') ? { ...x, id: dastCheckStepId('web') } : x))).join(' ')).toMatch(/no scan step of that result comes before it/);
    // with a scrub (the key) in the job: the exception does not apply, and the key job rule refuses the app start
    const scrub = (a.merge['dast--app'] as Job).steps.find((s) => s.with?.mode === 'scrub') as never;
    expect(checkJobOrder([...run.slice(0, 1), scrub, ...run.slice(1)], { id: 'dast-run--app', scans: NO_SCANS }).join(' ')).toMatch(/fingerprint key/);
  });

  it('referee: the DAST step only in dast-run--<svc>, the key never there, no DAST base twin, the hand-off checked by its sha256', async () => {
    const a = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    const f = files(a)[0] as CreatedFile;
    const bad = async (edit: (js: Obj) => void, re?: RegExp): Promise<void> => {
      const { parse } = await import('yaml');
      const { Document } = await import('yaml');
      const js = parse(f.content) as Obj;
      edit(js.jobs);
      const doc = new Document();
      doc.contents = doc.createNode(js);
      const r = await judge([{ ...f, content: doc.toString({ lineWidth: 0 }) }], a.draft);
      expect(r.ok, shown(r)).toBe(false);
      if (re !== undefined) expect(shown(r)).toMatch(re);
    };
    const runOf = (jobs: Obj): Obj[] => jobs["dast-run--app"].steps as Obj[];
    // the key: a scrub step, the fingerprint key in a step's env, or any secret in the run job
    await bad((jobs) => { const sc = (jobs['dast--app'].steps as Obj[]).find((s) => s.with?.mode === 'scrub'); runOf(jobs).splice(1, 0, structuredClone(sc) as Obj); });
    await bad((jobs) => { (runOf(jobs)[1] as Obj).env = { ...(runOf(jobs)[1] as Obj).env, X: `\${{ ${SEC}.PIPEGEN_FP_KEY }}` }; });
    await bad((jobs) => { const z = runOf(jobs).find((s) => String(s.id).startsWith('tool-run-')) as Obj; z.env = { ...z.env, [APP_KEY]: `\${{ ${SEC}.${APP_KEY} }}` }; }, /runs the app for its DAST scan, so it names no secret/);
    await bad((jobs) => { jobs['dast-run--app'].permissions = { contents: 'read', actions: 'read' }; });
    // the DAST step in the scrub job (beside the key), or in any other job
    await bad((jobs) => { const z = runOf(jobs).find((s) => String(s.id).startsWith('tool-run-')); (jobs["dast--app"].steps as Obj[]).splice(1, 0, structuredClone(z) as Obj); });
    await bad((jobs) => { const z = runOf(jobs).find((s) => String(s.id).startsWith('tool-run-')); (jobs["sast--app"].steps as Obj[]).push(structuredClone(z) as Obj); });
    // a DAST base twin in base-scan: there is none to recognise
    await bad((jobs) => { const z = runOf(jobs).find((s) => String(s.id).startsWith('tool-run-')) as Obj; (jobs['base-scan'].steps as Obj[]).push({ ...structuredClone(z), if: undefined }); });
    // the base render of the DAST spec itself is not a step pipegen renders either (no base twin is recorded)
    {
      const spec = a.draft.steps.find((st) => st.needId === 'dast') as StepSpec;
      const base = renderStep(spec, REVIEWED.find((t) => t.id === spec.tool.id) as never, p, { profile: a.draft.profile, targets: { url: 'http://127.0.0.1:3000' }, base: true }).steps;
      await bad((jobs) => { (jobs['base-scan'].steps as Obj[]).push(...base.map(({ usesComment: _u, ...rest }) => rest)); }, /is not a step pipegen renders for this pipeline/);
    }
    // the scan in a job of a file without the gate (no job list to hold it): its own rule refuses it
    {
      const push = files(a)[1] as CreatedFile;
      const { parse, Document } = await import('yaml');
      const js = parse(push.content) as Obj;
      const z = runOf(parse(f.content).jobs as Obj).filter((s) => String(s.id).startsWith('tool-'));
      js.jobs['lint--app'].steps.splice(1, 0, ...structuredClone(z));
      const doc = new Document();
      doc.contents = doc.createNode(js);
      expect(shown(await judge([{ ...push, content: doc.toString({ lineWidth: 0 }) }], a.draft))).toMatch(/runs only in its own job "dast-run--app"/);
    }
    // the hand-off check: another expression, or none; the raw sha256 output on another job
    await bad((jobs) => { const c = (jobs['dast--app'].steps as Obj[]).find((s) => s.id === dastCheckStepId('app')) as Obj; c.env[DAST_RAW_SHA_ENV] = '${{ needs.image-build--app.outputs.image-sha256 }}'; });
    await bad((jobs) => { jobs['dast--app'].steps = (jobs['dast--app'].steps as Obj[]).filter((s) => s.id !== dastCheckStepId('app')); });
    await bad((jobs) => { jobs['sast--app'].outputs = { ...jobs['sast--app'].outputs, [DAST_RAW_SHA_OUTPUT]: `\${{ steps.${DAST_HANDOFF_STEP_ID}.outputs.sha256 }}` }; });
    // the scrub job without the need of its run job (it would read nothing, or an old artifact)
    await bad((jobs) => { delete jobs['dast--app'].needs; }, /does not need that job/);
    // the app started on the runner (a project script) in the run job
    await bad((jobs) => {
      const ps = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, { profile: a.draft.profile }).steps;
      const at = runOf(jobs).findIndex((s) => s.id === dastAppStepId('app'));
      runOf(jobs).splice(at, 0, ...ps.slice(2).map(({ usesComment: _u, ...rest }) => rest));
    });
  });
});

describe('G4 fix round 1: the referee egress backstop (G4-R1)', () => {
  it('referee: every delivered job starts with the egress step (the keyless sign job aside)', async () => {
    const a = assemble(planned());
    const f = files(a)[0] as CreatedFile;
    for (const id of ['sast--app', 'gate', 'base-scan', 'baseline-check', 'lint--app']) {
      const none = editJob(f, id, (j) => { (j.steps as Obj[]).shift(); });
      expect((await judge([none], a.draft)).issues.some((i) => i.message.includes(id) && /egress step/.test(i.message)), id).toBe(true);
      // the egress step not first: refused too
      const twice = editJob(f, id, (j) => { (j.steps as Obj[]).splice(1, 0, structuredClone((j.steps as Obj[])[0])); });
      expect((await judge([twice], a.draft)).issues.some((i) => /egress step \(the reviewed Bullfrog block, once, first\)/.test(i.message)), `${id} twice`).toBe(true);
      const moved = editJob(f, id, (j) => { const [e] = (j.steps as Obj[]).splice(0, 1); (j.steps as Obj[]).push(e); });
      expect((await judge([moved], a.draft)).issues.some((i) => /egress step/.test(i.message)), `${id} moved`).toBe(true);
    }
    // the keyless sign job runs without one (documented: its Sigstore and OIDC hosts are in no reviewed set)
    const pub = planned(profileOf([web()]), { caps: { ...CAPS, keylessSigningAllowed: true }, over: { signing: { mode: 'keyless', images: [{ service: 'app', repo: 'ghcr.io/o/r/app' }] } } });
    const k = assemble(pub, 'keyless');
    const sign = { ...(k.sign as Obj), if: "github.event_name == 'push'", needs: ['gate'] };
    const r = await judge([wf({ ...k.merge, sign }, '.github/workflows/pipegen.yml', { push: { branches: ['main'] }, pull_request: null })], k.draft);
    expect(r.issues.filter((i) => /egress step/.test(i.message)).map((i) => i.message)).toEqual([]);
  });

  it('referee: no shared-CDN egress set in a job that holds a user secret', async () => {
    const x = planned(profileOf([node({ envVars: [APP_KEY] })]), { edit: (s) => s.map((st) => (st.needId === 'coverage' ? { ...st, [SEC]: [APP_KEY] } : st)) });
    const a = assemble(x);
    const f = files(a)[0] as CreatedFile;
    expect(shown(await judge([f], a.draft))).toBe('');
    for (const set of ['osv', 'trivy-db', 'github-releases'] as const) {
      const wide = editJob(f, 'coverage--app', (j) => { (j.steps as Obj[])[0].with['allowed-domains'] = egressDomains(['npm', set]); });
      expect((await judge([wide], a.draft)).issues.some((i) => /shared-CDN/.test(i.message) && i.message.includes('coverage--app')), set).toBe(true);
    }
    // the same set in a job with only pipegen's own secret (the fingerprint key of a scrub) is fine
    expect(domainsOf(a.merge['deps--app'] as Job)).toEqual(expect.arrayContaining(SHARED_HOSTS.filter((h) => h === 'api.osv.dev')));
    expect(allJobs(a).length).toBeGreaterThan(0);
  });
});

describe('G4 fix round 1: the starter-test job (G4-R1)', () => {
  it('starterTestJob: the Node major comes from the setup-node step itself, not its position', () => {
    for (const v of ['22', '26']) {
      const { job } = starterTestJob(node({ runtimeVersion: v }), { reviewed: REVIEWED, platform: p });
      const setup = job.steps.find((s) => s.uses?.startsWith('actions/setup-node@') === true);
      expect(setup?.with?.['node-version']).toBe(v);
      // the run uses that major's node and the Node base image of that major
      expect(job.steps.find((s) => s.id?.startsWith('pipegen-npm-ci-') === true)?.run).toMatch(new RegExp(`v${v}\\.`));
      expect(JSON.stringify(job.steps)).toMatch(new RegExp(`node:${v}[-.]`));
    }
    // the prelude's checkout is found by its action, wherever it stands
    expect(renderJobPrelude({ node: { runtimeVersion: '24' } }, p).steps.map((s) => s.uses?.split('@')[0])).toEqual(['actions/checkout', 'actions/setup-node']);
  });
});
