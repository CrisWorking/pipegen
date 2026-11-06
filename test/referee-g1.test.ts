// v0.2 Plan G, sub-task G1 (rulings B1, B2 referee side, B4; carries C3, C5a, C7s, G22, BP-6 pr-check): the referee and job rules for the
// workflow shapes Plan G itself writes, each in ONE exact form shared with its renderer (string equality, never a pattern), and the
// created-file rules for appending pipegen's reviewed hooks to pre-commit, husky and lefthook. Everything else stays refused.
import { describe, expect, it } from 'vitest';
import {
  BASELINE_CHECK_STEP_ID, CALLER_WORKFLOW, defaultPushTrigger, DEPLOY_PUSH_IF, DIGEST_STEP_ID, featurePushTrigger, jobOutputsFor, jobOutputsProblems, PR_CHECK_IF,
  checkExpressions, PR_CHECK_STEP_ID, PR_REVIEW_TRIGGER, PUSH_WORKFLOW, renderPrCheckStep, stepOutputForm, CONCURRENCY_GROUP, NIGHTLY_CONCURRENCY, WORKFLOW_CONCURRENCY, type RenderedStep,
} from '../src/engine/job-rules.js';
import { Document } from 'yaml';
import { renderBaselineCheckStep, renderFindRunStep, renderJobPrelude, renderNightlyStep, stepsToYaml } from '../src/engine/render-step.js';
import { createdFileProblems, CREATED_RULES } from '../src/engine/created-files.js';
import { HOOK_FILES, hookBlock, hookCommands, hookDataProblem, hookFile } from '../src/engine/created-builders.js';
import { GATE_CHECK_NAME, type CreatedFile, type ExistingWorkflow, type Need, type PipelineDraft } from '../src/types.js';
import { draftOf, GATE, job, jobsOf, p, prof, run, show, workflow as stepsWorkflow, type Job } from './helpers/gate-pipeline.js';
import { entry, reviewedList, specFor } from './helpers/render.js';
import { withEgress } from './helpers/egress-step.js';
import { noImages, verifyTail, VERIFY_LIMIT } from './helpers/verify-tail.js';

const d = draftOf();
/** The helper's workflow, also with reusable-workflow caller jobs (a job with `uses` and no steps). */
function workflow(jobs: Record<string, Job>, top: Record<string, unknown> = {}): CreatedFile {
  if (Object.values(jobs).every((j) => Array.isArray(j.steps))) return stepsWorkflow(jobs, top);
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, ...top, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) if (Array.isArray(j.steps)) doc.setIn(['jobs', id, 'steps'], id === 'gate' ? doc.createNode(withEgress(j.steps as RenderedStep[]).map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(withEgress(j.steps as RenderedStep[])));
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
const has = (r: { issues: { check: string; message: string }[] }, check: string, re: RegExp): boolean => r.issues.some((i) => i.check === check && re.test(i.message));
/** A workflow file at another path or repo. */
const at = (f: CreatedFile, path: string, repo: CreatedFile['repo'] = 'app'): CreatedFile => ({ ...f, path, repo });
const PR = { 'pull-requests': 'read' } as const;
const prCheckJob = (over: Job = {}): Job => job([renderPrCheckStep()], { permissions: PR, outputs: jobOutputsFor([renderPrCheckStep()]), ...over });
/** The push-layer file: pr-check and one scanner job that skips when the branch has an open pull request (no gate). */
function pushFile(scannerOver: Job = {}, top: Record<string, unknown> = {}, extraJobs: Record<string, Job> = {}): CreatedFile {
  const j = jobsOf(d);
  const scanner = { ...(j['sast--app'] as Job), needs: ['pr-check'], if: PR_CHECK_IF, ...scannerOver };
  return at(workflow({ 'pr-check': prCheckJob(), 'sast--app': scanner, ...extraJobs }, { on: { push: featurePushTrigger('main') }, ...top }), PUSH_WORKFLOW);
}
/** A user's deploy workflow with pipegen's inserted job (the Plan B marker), under the user's own triggers. */
function editedUser(on: string, insertedId: string, steps: RenderedStep[], perms: Record<string, string>, extra: Record<string, unknown> = {}): { f: CreatedFile; draft: PipelineDraft } {
  const original = `on:\n${on}jobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh\n`;
  const doc = new Document();
  doc.contents = doc.createNode({ on: null, jobs: {} });
  const text0 = original.replace('  deploy:\n    runs-on', `  deploy:\n    needs: [${insertedId}]\n    runs-on`);
  const ins = new Document();
  ins.contents = ins.createNode({ [insertedId]: { 'runs-on': 'ubuntu-latest', ...extra, permissions: perms, 'cache-mode': 'none' } });
  ins.setIn([insertedId, 'steps'], stepsToYaml(withEgress(steps)));
  const text = `${text0}${ins.toString({ lineWidth: 0 }).split('\n').map((l) => (l === '' ? l : `  ${l}`)).join('\n')}`;
  const f: CreatedFile = { path: '.github/workflows/deploy.yml', content: text, part: 'deploy-verify', reason: 't', repo: 'app', inserted: { original, jobs: [insertedId], needs: [{ job: 'deploy', added: [insertedId] }] } };
  const draft = draftOf({ profile: { ...prof, existingWorkflows: [{ path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [SEC_USED]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow] } });
  return { f, draft };
}
/** Spelled at run time (test/no-secret-literals.test.ts): the field name and the token variable name. */
const SEC_USED = ['secrets', 'Used'].join('');
const envName = Object.keys(renderPrCheckStep().env ?? {})[0] as string;
const VERIFY_PERMS = { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' };
const gateFile = (top: Record<string, unknown> = {}, extra: Record<string, Job> = {}): CreatedFile => workflow({ ...jobsOf(d), ...extra }, top);

describe('G1: the triggers of Plan G\'s layout (B1, B2, C3)', () => {
  it('referee: pull_request_review [submitted, dismissed] accepted only in pipegen.yml', async () => {
    const on = { pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
    expect(show(await run([gateFile({ on })], d))).toBe('');
    expect(PR_REVIEW_TRIGGER).toEqual({ types: ['submitted', 'dismissed'] });
    // any other spelling of the trigger is refused, even in pipegen.yml
    for (const prr of [null, { types: ['submitted'] }, { types: ['dismissed', 'submitted'] }, { types: ['submitted', 'dismissed', 'edited'] }, { types: ['submitted', 'dismissed'], branches: ['main'] }, { types: 'submitted' }]) {
      const r = await run([gateFile({ on: { pull_request: null, pull_request_review: prr } })], d);
      expect(has(r, 'template', /pull_request_review/), `${JSON.stringify(prr)}: ${show(r)}`).toBe(true);
    }
    const listed = await run([gateFile({ on: ['pull_request', 'pull_request_review'] })], d);
    expect(has(listed, 'template', /pull_request_review/), show(listed)).toBe(true);
    // the exact form in any other file (another app workflow, or the central repo) is refused
    for (const f of [at(gateFile({ on }), '.github/workflows/pipegen-merge.yml'), at(gateFile({ on }), PUSH_WORKFLOW), at(gateFile({ on }), CALLER_WORKFLOW, 'central')]) {
      const r = await run([f], d);
      expect(has(r, 'template', /pull_request_review/), `${f.repo}:${f.path}: ${show(r)}`).toBe(true);
    }
  });

  it('referee: pipegen.yml push trigger must be branches [<default>] with no tags', async () => {
    expect(defaultPushTrigger('main')).toEqual({ branches: ['main'] });
    expect(show(await run([gateFile({ on: { push: { branches: ['main'] }, pull_request: null } })], d))).toBe('');
    const trunk: PipelineDraft = { ...d, profile: { ...prof, defaultBranch: 'trunk' } };
    expect(show(await run([workflow(jobsOf(trunk), { on: { push: { branches: ['trunk'] }, pull_request: null } })], trunk))).toBe('');
    for (const on of [
      'push', ['push', 'pull_request'], { push: null, pull_request: null }, { push: { branches: ['main'], tags: ['*'] } }, { push: { tags: ['v*'] } },
      { push: { branches: ['main', 'dev'] } }, { push: { branches: ['ma*'] } }, { push: { branches: ['main'], paths: ['src/**'] } },
      { push: { 'branches-ignore': ['dev'] } }, { push: { branches: 'main' } }, { push: { branches: ['trunk'] } }, { push: { branches: ['Main'] } },
    ]) {
      const r = await run([gateFile({ on })], d);
      expect(has(r, 'template', /push trigger must be exactly branches/), `${JSON.stringify(on)}: ${show(r)}`).toBe(true);
    }
    // a default branch whose name is a filter pattern (*, ?, +, [, ], !, \) has no exact form: the shared builder refuses it, so does the referee
    for (const b of ['ma*n', 'rel+1', '!main', 'a[b]', 'x?', 'a\\b', '', ' main', 'main\n']) expect(() => defaultPushTrigger(b), JSON.stringify(b)).toThrow();
    const odd: PipelineDraft = { ...d, profile: { ...prof, defaultBranch: 'rel+1' } };
    const r = await run([workflow(jobsOf(odd), { on: { push: { branches: ['rel+1'] }, pull_request: null } })], odd);
    expect(has(r, 'template', /push trigger must be exactly branches/), show(r)).toBe(true);
  });

  it('referee: a workflow with push on a non-default branch holds no gate job and no job named like the gate', async () => {
    const offDefault = [{ push: null, pull_request: null }, 'push', ['push', 'pull_request'], { push: featurePushTrigger('main') }, { push: { branches: ['**'] } }, { push: { tags: ['v*'] } }, { pull_request: null, push: { branches: ['main', 'dev'] } }];
    for (const on of offDefault) {
      for (const path of ['.github/workflows/ci.yml', PUSH_WORKFLOW]) {
        const r = await run([at(gateFile({ on }), path)], d);
        expect(has(r, 'not-gate-readable', /pushes to a branch other than the default/), `${path} ${JSON.stringify(on)}: ${show(r)}`).toBe(true);
      }
    }
    // triggers pipegen can not read count as a push that may run anywhere (fail closed)
    const unreadable = await run([gateFile({ on: 5 })], d);
    expect(has(unreadable, 'not-gate-readable', /pushes to a branch other than the default/), show(unreadable)).toBe(true);
    // a job named like the gate (its id need not be gate) is refused there too, and so is a caller of a workflow that holds the gate
    const named = pushFile({}, {}, { lookalike: job(renderJobPrelude({}, p).steps, { name: 'gate' }) });
    expect(has(await run([named], d), 'not-gate-readable', /pushes to a branch other than the default/)).toBe(true);
    const named2 = pushFile({}, {}, { lookalike: job(renderJobPrelude({}, p).steps, { name: GATE_CHECK_NAME }) });
    expect(has(await run([named2], d), 'not-gate-readable', /pushes to a branch other than the default/)).toBe(true);
    const merge = at(gateFile({ on: { workflow_call: null } }), '.github/workflows/pipegen-merge.yml');
    const caller = (on: unknown, path: string): CreatedFile => at(workflow({ pipegen: { name: 'pipegen', uses: './.github/workflows/pipegen-merge.yml', permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } } }, { on }), path);
    const bad = await run([merge, caller({ push: featurePushTrigger('main') }, PUSH_WORKFLOW)], d);
    expect(has(bad, 'not-gate-readable', /pushes to a branch other than the default/), show(bad)).toBe(true);
    // the control: the same caller in pipegen.yml, whose push runs only on the default branch, may call it
    const good = await run([merge, caller({ push: defaultPushTrigger('main'), pull_request: null }, CALLER_WORKFLOW)], d);
    expect(has(good, 'not-gate-readable', /pushes to a branch other than the default/), show(good)).toBe(false);
    // a call chain deeper than GitHub runs is read as holding the gate (fail closed)
    const chain = Array.from({ length: 12 }, (_, i) => at(workflow({ next: { uses: `./.github/workflows/c${i + 1}.yml`, permissions: { contents: 'read' } } }, { on: { workflow_call: null } }), `.github/workflows/c${i}.yml`));
    const deep = await run([...chain, at(workflow({ c: { uses: './.github/workflows/c0.yml', permissions: { contents: 'read' } } }, { on: { push: featurePushTrigger('main') } }), '.github/workflows/deep.yml')], d);
    // G1-R2 m3: refused as too deep, never read as holding the gate
    expect(has(deep, 'template', /deeper than/), show(deep)).toBe(true);
    expect(has(deep, 'not-gate-readable', /pushes to a branch other than the default/), show(deep)).toBe(false);
    // and a push-layer file without a gate passes
    expect(show(await run([gateFile(), pushFile()], d))).toBe('');
    // a job pipegen inserts into a user's workflow that pushes on any branch may not be named like the gate either
    const ed = editedUser('  push:\n', 'pipegen-verify', [renderFindRunStep(GATE, {})], VERIFY_PERMS);
    const named3 = { ...ed.f, content: ed.f.content.replace('  pipegen-verify:\n', '  pipegen-verify:\n    name: gate\n') };
    expect(named3.content).not.toBe(ed.f.content);
    expect(has(await run([named3], ed.draft), 'not-gate-readable', /pushes to a branch other than the default/)).toBe(true);
    expect(has(await run([ed.f], ed.draft), 'not-gate-readable', /pushes to a branch other than the default/)).toBe(false);
  });

  it('referee: baseline-check and find-run never in a workflow with schedule', async () => {
    const schedule = { schedule: [{ cron: '17 3 * * *' }] };
    const bc = job([renderBaselineCheckStep(GATE)], { permissions: { contents: 'read', actions: 'read' }, outputs: jobOutputsFor([renderBaselineCheckStep(GATE)]) });
    const verify = job([renderFindRunStep(GATE, {})], { permissions: { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' } });
    const nightly = job([renderNightlyStep(GATE, d)], { permissions: { contents: 'read', actions: 'read', issues: 'write' }, concurrency: NIGHTLY_CONCURRENCY });
    const nightlyFile = (jobs: Record<string, Job>, on: unknown = schedule): CreatedFile => at(workflow(jobs, { on }), '.github/workflows/pipegen-nightly.yml');
    // the nightly job alone (mode nightly) is the scheduled gate mode
    const ok = await run([gateFile(), nightlyFile({ nightly })], d);
    expect(has(ok, 'template', /runs on schedule/), show(ok)).toBe(false);
    for (const [name, jobs] of [['baseline-check', { nightly, 'baseline-check': bc }], ['find-run', { nightly, 'pipegen-verify': verify }], ['the gate', jobsOf(d)]] as const) {
      for (const on of [schedule, { ...schedule, pull_request: null }]) {
        const r = await run([gateFile(), nightlyFile(jobs as Record<string, Job>, on)], d);
        expect(has(r, 'template', /runs on schedule/), `${name} ${JSON.stringify(on)}: ${show(r)}`).toBe(true);
      }
    }
    // each sign alone: a job id baseline-check with no gate step, and a baseline-check step under another job id
    const idOnly = await run([gateFile(), nightlyFile({ nightly, 'baseline-check': job(renderJobPrelude({}, p).steps) })], d);
    expect(has(idOnly, 'template', /runs on schedule/), show(idOnly)).toBe(true);
    const modeOnly = await run([gateFile(), nightlyFile({ nightly, other: job([renderBaselineCheckStep(GATE)], { permissions: { contents: 'read', actions: 'read' } }) })], d);
    expect(has(modeOnly, 'template', /runs on schedule/), show(modeOnly)).toBe(true);
    // the same jobs without schedule: no schedule issue (baseline-check in the merge file is how it is meant to run)
    const plain = await run([workflow({ ...jobsOf(d), 'baseline-check': bc })], d);
    expect(has(plain, 'template', /runs on schedule/), show(plain)).toBe(false);
    // a scheduled caller of a workflow that holds baseline-check is refused too
    const merge = at(workflow({ ...jobsOf(d), 'baseline-check': bc }, { on: { workflow_call: null } }), '.github/workflows/pipegen-merge.yml');
    const sched = nightlyFile({ pipegen: { name: 'pipegen', uses: './.github/workflows/pipegen-merge.yml', permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } } });
    expect(has(await run([merge, sched], d), 'template', /runs on schedule/)).toBe(true);
    // pipegen's inserted verify job (find-run) in a user's scheduled deploy workflow is refused; under a push to the default branch it is not
    const sch = editedUser("  schedule:\n    - cron: '0 3 * * *'\n", 'pipegen-verify', [renderFindRunStep(GATE, {})], VERIFY_PERMS);
    const rs = await run([sch.f], sch.draft);
    expect(has(rs, 'template', /runs on schedule/), show(rs)).toBe(true);
    // (G7: the verify job as the referee holds it, find-run under its id then the head check, longer than the wait, for a profile that
    // publishes no image: no digest step or signature check)
    const psh = editedUser('  push:\n    branches: [main]\n', 'pipegen-verify', verifyTail(renderFindRunStep(GATE, {})), VERIFY_PERMS, { 'timeout-minutes': VERIFY_LIMIT });
    psh.draft = { ...psh.draft, profile: noImages(psh.draft.profile) };
    const rp = await run([psh.f], psh.draft);
    expect(has(rp, 'template', /runs on schedule/), show(rp)).toBe(false);
    expect(rp.issues.filter((i) => i.file === psh.f.path), show(rp)).toEqual([]);
  });
});

describe('G1: workflow concurrency, job conditions and job outputs (B1, G22, BP-6)', () => {
  it('referee: workflow concurrency only in the exact per-ref form (cancel except the default branch); any other expression refused', async () => {
    // ruling G1-R1 / G1-R1b: one exact form (it replaced B1's). Its meaning per event is in the G1-R2 describe below
    expect(WORKFLOW_CONCURRENCY).toEqual({ group: CONCURRENCY_GROUP, 'cancel-in-progress': true });
    const exact = { ...WORKFLOW_CONCURRENCY };
    expect(show(await run([gateFile({ concurrency: exact })], d))).toBe('');
    expect(show(await run([gateFile(), pushFile({}, { concurrency: exact })], d))).toBe('');
    // G1-R2 I2: a plain value is refused too (a shared plain group cancels other refs' runs); so is B1's earlier form
    const B1_FORM = { group: 'pipegen-${{ github.ref }}', 'cancel-in-progress': "${{ github.ref != format('refs/heads/{0}', github.event.repository.default_branch) }}" };
    for (const c of [
      'pipegen', { group: 'pipegen', 'cancel-in-progress': true }, { group: 'pipegen', 'cancel-in-progress': false }, B1_FORM,
      { group: CONCURRENCY_GROUP.replace('github.run_id', 'github.sha'), 'cancel-in-progress': true },
      { group: CONCURRENCY_GROUP.replace(", github.event_name", ''), 'cancel-in-progress': true },
      { group: CONCURRENCY_GROUP, 'cancel-in-progress': 'true' },
      { group: CONCURRENCY_GROUP, 'cancel-in-progress': false },
      { group: CONCURRENCY_GROUP },
      { group: `${CONCURRENCY_GROUP} `, 'cancel-in-progress': true },
      { ...exact, extra: 'x' },
      CONCURRENCY_GROUP,
    ]) {
      const r = await run([gateFile({ concurrency: c })], d);
      expect(has(r, 'injection', /concurrency/), `${JSON.stringify(c)}: ${show(r)}`).toBe(true);
    }
    // the exact form in a called workflow (it would share the group with its caller and deadlock) or another file is refused
    const merge = at(gateFile({ on: { workflow_call: null }, concurrency: exact }), '.github/workflows/pipegen-merge.yml');
    expect(has(await run([merge], d), 'injection', /concurrency/)).toBe(true);
    expect(has(await run([at(gateFile({ concurrency: exact }), '.github/workflows/ci.yml')], d), 'injection', /concurrency/)).toBe(true);
    expect(has(await run([at(gateFile({ concurrency: exact }), CALLER_WORKFLOW, 'central')], d), 'injection', /concurrency/)).toBe(true);
    expect(has(await run([gateFile({ on: { pull_request: null, workflow_call: null }, concurrency: exact })], d), 'injection', /concurrency/)).toBe(true);
  });

  it('referee: pr-check if form exact; any other if on a gate-feeding job refused', async () => {
    expect(PR_CHECK_IF).toBe("needs.pr-check.outputs.has-pr != 'true'");
    expect(show(await run([gateFile(), pushFile()], d))).toBe('');
    // any other spelling of the condition is refused
    for (const cond of [`\${{ ${PR_CHECK_IF} }}`, "needs.pr-check.outputs.has-pr != 'false'", "needs.pr-check.outputs.has-pr == 'false'", `${PR_CHECK_IF} || always()`, `always() && ${PR_CHECK_IF}`, `${PR_CHECK_IF} `, "needs.pr-check.outputs.has-pr!='true'"]) {
      const r = await run([gateFile(), pushFile({ if: cond })], d);
      expect(r.ok, `${cond}: ${show(r)}`).toBe(false);
      expect(has(r, 'injection', /if: pipegen does not write/), `${cond}: ${show(r)}`).toBe(true);
    }
    // the exact form on a gate-feeding job (in the file that holds the gate) is refused
    const j = jobsOf(d);
    const inGate = workflow({ ...j, 'pr-check': prCheckJob(), 'sast--app': { ...(j['sast--app'] as Job), needs: ['pr-check'], if: PR_CHECK_IF } });
    expect(has(await run([inGate], d), 'template', /pr-check skip/), show(await run([inGate], d))).toBe(true);
    // ... or anywhere but a push-layer job of the push file: without needs pr-check, on pr-check itself, in a file whose push runs on the default branch
    expect(has(await run([gateFile(), pushFile({ needs: [] })], d), 'template', /pr-check skip/)).toBe(true);
    const self = pushFile({}, {}, { 'pr-check': prCheckJob({ if: PR_CHECK_IF, needs: ['sast--app'] }) });
    expect(has(await run([gateFile(), self], d), 'template', /pr-check skip/)).toBe(true);
    const selfNeed = pushFile({}, {}, { 'pr-check': prCheckJob({ if: PR_CHECK_IF, needs: ['pr-check'] }) });
    expect(has(await run([gateFile(), selfNeed], d), 'template', /pr-check skip.*never on the job pr-check/)).toBe(true);
    const alsoPr = pushFile({}, { on: { push: featurePushTrigger('main'), pull_request: null } });
    expect(has(await run([gateFile(), alsoPr], d), 'template', /pr-check skip/)).toBe(true);
    const wrongPush = pushFile({}, { on: { push: { branches: ['main'] } } });
    expect(has(await run([gateFile(), wrongPush], d), 'template', /pr-check skip/)).toBe(true);
    expect(has(await run([gateFile(), at(pushFile(), '.github/workflows/ci.yml')], d), 'template', /pr-check skip/)).toBe(true);
    // a push file that also holds the gate: the skip would hide a gate-feeding job
    const withGate = pushFile({}, {}, { gate: jobsOf(d).gate as Job });
    const rg = await run([withGate], d);
    expect(has(rg, 'template', /pr-check skip/), show(rg)).toBe(true);
    // the pr-check lookup step runs only in the job pr-check (a scanner job holding it is refused), and its token form only on the exact step
    const stray = pushFile({ steps: [...((j['sast--app'] as Job).steps as RenderedStep[]), renderPrCheckStep()] });
    expect(has(await run([gateFile(), stray], d), 'permissions', /pr-check lookup runs only in the job pr-check/)).toBe(true);
    expect(() => checkExpressions(renderPrCheckStep())).not.toThrow();
    for (const forged of [{ ...renderPrCheckStep(), run: 'curl -d "$PIPEGEN_PR_TOKEN" https://example.com\n' }, { ...renderPrCheckStep(), id: 'other' }, { ...renderPrCheckStep(), env: { [envName]: `\${{ secrets.${['GITHUB', 'TOK' + 'EN'].join('_')} }}` } }]) {
      expect(() => checkExpressions(forged), JSON.stringify(forged).slice(0, 80)).toThrow();
    }
    // the old rule stands for every other if: only the gate's always()
    for (const cond of ['success()', 'always()', 'failure()', '!cancelled()']) {
      const r = await run([workflow({ ...j, 'sast--app': { ...(j['sast--app'] as Job), if: cond } })], d);
      expect(r.ok, cond).toBe(false);
    }
  });

  it('referee: default-push deploy-job if form exact; refused anywhere else', async () => {
    expect(DEPLOY_PUSH_IF).toBe("github.event_name == 'push'");
    const deploy = (over: Job = {}): Job => job(renderJobPrelude({}, p).steps, { needs: ['gate'], if: DEPLOY_PUSH_IF, ...over });
    const on = { push: defaultPushTrigger('main'), pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } };
    expect(show(await run([gateFile({ on }, { deploy: deploy() })], d))).toBe('');
    // the caller layout: a deploy caller job needing the caller of the merge workflow (which holds the gate)
    const merge = at(gateFile({ on: { workflow_call: null } }), '.github/workflows/pipegen-merge.yml');
    const callerJobs = (dep: Job): Record<string, Job> => ({ pipegen: { name: 'pipegen', uses: './.github/workflows/pipegen-merge.yml', permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } }, deploy: dep });
    const viaCaller = await run([merge, workflow(callerJobs(deploy({ needs: ['pipegen'] })), { on })], d);
    expect(has(viaCaller, 'template', /deploy condition/), show(viaCaller)).toBe(false);
    // other spellings are refused
    for (const cond of [`\${{ ${DEPLOY_PUSH_IF} }}`, "github.event_name != 'pull_request'", "github.event_name == 'push' || always()", "github.ref == 'refs/heads/main'", "github.event_name=='push'"]) {
      const r = await run([gateFile({ on }, { deploy: deploy({ if: cond }) })], d);
      expect(has(r, 'injection', /if: pipegen does not write/), `${cond}: ${show(r)}`).toBe(true);
    }
    // the exact form anywhere else: another file, a file whose push is not default-only, a job that does not need the gate, the gate itself, a gate-feeding job
    const elsewhere = [
      ['another file', [at(gateFile({ on: { push: defaultPushTrigger('main'), pull_request: null } }, { deploy: deploy() }), '.github/workflows/ci.yml')]],
      ['the push file', [gateFile(), pushFile({}, {}, { deploy: deploy({ needs: ['pr-check'] }) })]],
      ['no gate needed', [gateFile({ on }, { deploy: deploy({ needs: [] }) })]],
      ['needs a scanner only', [gateFile({ on }, { deploy: deploy({ needs: ['sast--app'] }) })]],
      ['on pull_request only', [gateFile({ on: { pull_request: null } }, { deploy: deploy() })]],
      ['the gate itself', [workflow({ ...jobsOf(d), gate: { ...(jobsOf(d).gate as Job), if: DEPLOY_PUSH_IF } }, { on })]],
      ['a gate-feeding job', [workflow({ ...jobsOf(d), 'sast--app': { ...(jobsOf(d)['sast--app'] as Job), if: DEPLOY_PUSH_IF } }, { on })]],
      ['the gate caller', [merge, workflow({ ...callerJobs(deploy({ needs: ['pipegen'] })), pipegen: { ...(callerJobs(deploy()).pipegen as Job), if: DEPLOY_PUSH_IF } }, { on })]],
    ] as const;
    // the gate itself, even when it lists itself among its needs
    const selfGate = await run([workflow({ ...jobsOf(d), gate: { ...(jobsOf(d).gate as Job), if: DEPLOY_PUSH_IF, needs: [...((jobsOf(d).gate as Job).needs as string[]), 'gate'] } }, { on })], d);
    expect(has(selfGate, 'template', /deploy condition.*never on the gate/), show(selfGate)).toBe(true);
    for (const [name, files] of elsewhere) {
      const r = await run([...files], d);
      expect(r.ok, `${name}: ${show(r)}`).toBe(false);
      expect(has(r, 'template', /deploy condition/) || (name === 'the gate itself' && has(r, 'not-gate-readable', /always\(\)/)), `${name}: ${show(r)}`).toBe(true);
    }
  });

  it('referee: outputs found, has-pr, digest only on their own job and from their own step', async () => {
    const pr = renderPrCheckStep();
    const bc = renderBaselineCheckStep(GATE);
    const dig: RenderedStep = { id: DIGEST_STEP_ID, name: 'pipegen: the verified image digest', run: 'true\n', shell: 'bash' };
    expect(pr.id).toBe(PR_CHECK_STEP_ID);
    expect(bc.id).toBe(BASELINE_CHECK_STEP_ID);
    const form = { 'has-pr': stepOutputForm(PR_CHECK_STEP_ID, 'has-pr'), found: stepOutputForm(BASELINE_CHECK_STEP_ID, 'found'), digest: stepOutputForm(DIGEST_STEP_ID, 'digest') };
    expect(form['has-pr']).toBe('${{ steps.pipegen-pr-check.outputs.has-pr }}');
    // the renderer's outputs and the rule agree
    expect(jobOutputsFor([pr])).toEqual({ 'has-pr': form['has-pr'] });
    expect(jobOutputsFor([bc])).toEqual({ found: form.found });
    expect(jobOutputsFor([dig])).toEqual({ digest: form.digest });
    for (const [jobId, key, steps] of [['pr-check', 'has-pr', [pr]], ['baseline-check', 'found', [bc]], ['pipegen-verify', 'digest', [dig]]] as const) {
      const want = form[key];
      expect(jobOutputsProblems(jobId, { [key]: want }, steps), `${jobId} ${key}`).toEqual([]);
      // on any other job of the table, or a scanner job: refused
      for (const other of ['pr-check', 'baseline-check', 'pipegen-verify', 'gate', 'sast--app', 'base-scan']) {
        if (other === jobId) continue;
        expect(jobOutputsProblems(other, { [key]: want }, steps).join('\n'), `${key} on ${other}`).toMatch(/not one of/);
      }
      // any other value: another step, another output name, spacing, a literal, an extra expression
      for (const v of [want.replace('outputs.', 'outputs.x'), want.replace(/steps\.[^.]+\./, 'steps.other.'), `${want} `, want.replace('${{ ', '${{'), 'true', `${want}\${{ secrets.GITHUB_TOKEN }}`, 1, null]) {
        expect(jobOutputsProblems(jobId, { [key]: v }, steps).join('\n'), `${key}=${String(v)}`).toMatch(/must be exactly/);
      }
      // not from its own step: the step missing, twice, or another step under its id
      expect(jobOutputsProblems(jobId, { [key]: want }, []).join('\n')).toMatch(/its own step/);
      expect(jobOutputsProblems(jobId, { [key]: want }, [...steps, ...steps]).join('\n')).toMatch(/its own step/);
      const impostor: RenderedStep = key === 'digest' ? { id: DIGEST_STEP_ID, name: 'x', uses: `actions/checkout@${'a'.repeat(40)}` } : { ...(steps[0] as RenderedStep), run: 'echo has-pr=true >> "$GITHUB_OUTPUT"\n', uses: undefined, with: undefined };
      expect(jobOutputsProblems(jobId, { [key]: want }, [impostor]).join('\n'), `${key} impostor`).toMatch(/its own step/);
    }
    // a found step whose gate mode is not baseline-check is not its step
    expect(jobOutputsProblems('baseline-check', { found: form.found }, [{ ...bc, with: { ...bc.with, mode: 'gate' } }]).join('\n')).toMatch(/its own step/);
    // the referee: the outputs on their own jobs pass; on another job they are injection
    const bcJob = job([bc], { permissions: { contents: 'read', actions: 'read' }, outputs: { found: form.found } });
    expect(show(await run([workflow({ ...jobsOf(d), 'baseline-check': bcJob })], d))).toBe('');
    expect(show(await run([gateFile(), pushFile()], d))).toBe('');
    const j = jobsOf(d);
    for (const [id, key] of [['sast--app', 'has-pr'], ['gate', 'found'], ['base-scan', 'digest'], ['baseline-check', 'has-pr']] as const) {
      const base = id === 'baseline-check' ? bcJob : (j[id] as Job);
      const r = await run([workflow({ ...j, 'baseline-check': bcJob, [id]: { ...base, outputs: { ...(base.outputs as object), [key]: form[key] } } })], d);
      expect(has(r, 'injection', /not one of/), `${key} on ${id}: ${show(r)}`).toBe(true);
    }
    // a pr-check step that is not exactly the rendered one is not recognised (and its has-pr is not from its own step)
    // (the emitter refuses to write it: the token form is allowed only on the exact step, so the forged file is edited as text)
    expect(() => stepsToYaml([{ ...pr, run: `${pr.run as string}echo has-pr=true >> "$GITHUB_OUTPUT"\n` }])).toThrow();
    const good = pushFile();
    const forged = { ...good, content: good.content.replace(/\n( +)if \[ "\$count"/, '\n$1echo has-pr=true >> "$GITHUB_OUTPUT"\n$1if [ "$count"') };
    expect(forged.content).not.toBe(good.content);
    const rf = await run([gateFile(), forged], d);
    expect(rf.ok, show(rf)).toBe(false);
    expect(has(rf, 'injection', /has-pr.*its own step/), show(rf)).toBe(true);
  });
});

// ---------- controller ruling G1-R-sec: the push workflow is called only by the push caller ----------

const CSHA = 'c'.repeat(40);
const cd = draftOf({ centralPin: { repo: 'o/pipelines', sha: CSHA } });
const CENTRAL_PUSH = '.github/workflows/r--push.yml';
const CALL_PERMS = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
/** The central push workflow (pr-check and a scanner with the skip), called by workflow_call only. */
const centralPush = (extra: Record<string, Job> = {}): CreatedFile => at(pushFile({}, { on: { workflow_call: null } }, extra), CENTRAL_PUSH, 'central');
const callerOf = (uses: string, on: unknown, path: string, repo: CreatedFile['repo'] = 'app', extra: Record<string, Job> = {}): CreatedFile =>
  at(workflow({ push: { uses, permissions: CALL_PERMS }, ...extra }, { on }), path, repo);
const CENTRAL_PUSH_USES = `o/pipelines/${CENTRAL_PUSH}@${CSHA}`;

describe('G1-R-sec: the pr-check skip never runs under a gate', () => {
  it('referee: only the push caller may call the push workflow; pipegen.yml calling it → refused', async () => {
    const onPush = { push: featurePushTrigger('main') };
    const onCaller = { push: defaultPushTrigger('main'), pull_request: null };
    // the push caller may call it
    const ok = await run([gateFile(), centralPush(), callerOf(CENTRAL_PUSH_USES, onPush, PUSH_WORKFLOW)], cd);
    expect(has(ok, 'not-gate-readable', /push workflow/), show(ok)).toBe(false);
    // pipegen.yml (it holds or calls the gate, and runs on pull requests) calling it: refused, alone or next to the gate
    for (const extra of [{}, jobsOf(cd)]) {
      const r = await run([centralPush(), callerOf(CENTRAL_PUSH_USES, onCaller, CALLER_WORKFLOW, 'app', extra)], cd);
      expect(has(r, 'not-gate-readable', /only the push caller .* may call the push workflow/), show(r)).toBe(true);
    }
    // the central merge workflow calling it; the push file under another path or with other triggers calling it; another app file
    const merge = at(workflow({ ...jobsOf(cd), push: { uses: `./${CENTRAL_PUSH}`, permissions: CALL_PERMS } }, { on: { workflow_call: null } }), '.github/workflows/r--merge.yml', 'central');
    expect(has(await run([centralPush(), merge], cd), 'not-gate-readable', /only the push caller/)).toBe(true);
    for (const [on, path] of [[{ push: featurePushTrigger('main'), pull_request: null }, PUSH_WORKFLOW], [onPush, '.github/workflows/ci.yml'], [{ pull_request: null }, PUSH_WORKFLOW], [onPush, PUSH_WORKFLOW]] as const) {
      const repo = path === PUSH_WORKFLOW && on === onPush ? 'central' : 'app';
      const r = await run([centralPush(), callerOf(CENTRAL_PUSH_USES, on, path, repo)], cd);
      expect(has(r, 'not-gate-readable', /only the push caller/), `${repo}:${path} ${JSON.stringify(on)}: ${show(r)}`).toBe(true);
    }
    // the push file that holds the gate is no push caller either
    const gated = await run([centralPush(), callerOf(CENTRAL_PUSH_USES, onPush, PUSH_WORKFLOW, 'app', { gate: jobsOf(cd).gate as Job })], cd);
    expect(has(gated, 'not-gate-readable', /only the push caller/), show(gated)).toBe(true);
    // the app push file itself (the public form) called from pipegen.yml: refused too
    const r2 = await run([gateFile(), pushFile({}, { on: { workflow_call: null } }), callerOf('./.github/workflows/pipegen-push.yml', onCaller, CALLER_WORKFLOW)], d);
    expect(has(r2, 'not-gate-readable', /only the push caller/), show(r2)).toBe(true);
  });

  it('referee: a pr-check skip job in a workflow that holds or calls the gate → refused', async () => {
    const merge = at(gateFile({ on: { workflow_call: null } }), '.github/workflows/pipegen-merge.yml');
    const callMerge = { pipegen: { name: 'pipegen', uses: './.github/workflows/pipegen-merge.yml', permissions: CALL_PERMS } };
    // the push file holding the gate, calling the merge workflow, or the central push file holding the gate
    for (const [name, files, draft] of [
      ['holds', [pushFile({}, {}, { gate: jobsOf(d).gate as Job })], d],
      ['calls', [merge, pushFile({}, {}, callMerge as unknown as Record<string, Job>)], d],
      ['central holds', [gateFile(), centralPush({ gate: jobsOf(cd).gate as Job }), callerOf(CENTRAL_PUSH_USES, { push: featurePushTrigger('main') }, PUSH_WORKFLOW)], cd],
      ['central calls', [at(merge, '.github/workflows/r--merge.yml', 'central'), centralPush({ pipegen: { name: 'pipegen', uses: './.github/workflows/r--merge.yml', permissions: CALL_PERMS } } as unknown as Record<string, Job>)], cd],
    ] as const) {
      const r = await run([...files], draft);
      expect(has(r, 'template', /pr-check skip.*holds or calls the gate/), `${name}: ${show(r)}`).toBe(true);
    }
  });
});

// ---------- B4: the hook managers' files ----------

const fmtNeed: Need = { id: 'format-lint', layer: 'pre-commit', category: 'format-lint', service: 'app', why: 't', blocking: true, floor: false };
/** G6: the biome hook is added only when the root service's lockfile holds the reviewed @biomejs/biome, so the fixture installs it. */
const biomeInstalled = prof.services.map((s, i) => (i !== 0 ? s : { ...s, quality: { ...s.quality, versions: { ...s.quality.versions, '@biomejs/biome': entry('biome').step.cli?.install.version as string }, fromRange: [] } }));
const hookDraft = (precommit: PipelineDraft['profile']['precommit'], over: Partial<PipelineDraft> = {}): PipelineDraft =>
  draftOf({ profile: { ...prof, precommit, services: biomeInstalled }, needs: [...d.needs, fmtNeed], steps: [...d.steps, specFor(entry('biome'), { needId: 'format-lint', service: 'app' })], ...over });
const hookCreated = (path: string, original: string, content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'precommit', reason: 't', repo: 'app', edited: { original }, ...over });
const judge = (f: CreatedFile, draft: PipelineDraft): string[] => createdFileProblems(f, draft, CREATED_RULES, { reviewed: reviewedList(), inputs: {} }).problems;
const built = (manager: keyof typeof HOOK_FILES, original: string, draft: PipelineDraft): string => {
  const b = hookFile(manager, original, draft, reviewedList());
  if (!('content' in b)) throw new Error(b.note);
  return b.content;
};
const PRE_COMMIT = 'repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: 2c9f875913ee60ca25ce70243dc24d5b6415598c   # v6.0.0\n    hooks:\n      - id: trailing-whitespace\n';
const HUSKY = 'npm test\n';
const LEFTHOOK = 'commit-msg:\n  commands:\n    lint:\n      run: npx --no -- commitlint --edit {1}\n';

describe('G1: pre-commit, husky and lefthook appends (B4)', () => {
  it('referee: pre-commit, husky and lefthook edits judged byte-exact as appends of reviewed hook text', async () => {
    expect(HOOK_FILES).toEqual({ 'pre-commit': '.pre-commit-config.yaml', husky: '.husky/pre-commit', lefthook: 'lefthook.yml' });
    // the reviewed command: the root service's pinned biome, from its own lockfile install (npx --no never downloads)
    expect(hookCommands(hookDraft('husky'), reviewedList())).toEqual([{ id: 'pipegen-biome', run: `npx --no --package=@biomejs/biome@${entry('biome').step.cli?.install.version as string} -- biome check --staged --no-errors-on-unmatched --vcs-enabled=true --vcs-client-kind=git` }]);
    const cases = [
      ['pre-commit', PRE_COMMIT, hookDraft('pre-commit')], ['pre-commit', PRE_COMMIT.replace(/^ {2}/gm, ''), hookDraft('pre-commit')],
      ['husky', HUSKY, hookDraft('husky')], ['husky', '', hookDraft('husky')], ['husky', 'npm test', hookDraft('husky')],
      ['lefthook', LEFTHOOK, hookDraft('lefthook')], ['lefthook', '', hookDraft(null)],
    ] as const;
    for (const [manager, original, draft] of cases) {
      const path = HOOK_FILES[manager];
      const content = built(manager, original, draft);
      const label = `${manager} ${JSON.stringify(original.slice(0, 20))}`;
      expect(content.startsWith(original), label).toBe(true);
      expect(content).toContain('pipegen:hooks');
      expect(judge(hookCreated(path, original, content), draft), label).toEqual([]);
      const r = await run([gateFile(), hookCreated(path, original, content)], draft);
      expect(show(r), label).toBe('');
      // one byte changed anywhere in pipegen's block, the user's text changed, the block placed before the user's text: refused
      const block = content.slice(original.length);
      for (const bad of [
        original + block.replace('--staged', '--staged '), original + block.replace('biome check', 'biome format --write'), original + block + 'echo extra\n',
        original + block.replace('\n', '\n\n'), `${block}${original}`, original.replace(/test|repo|commit-msg/, 'x') + block, original + block.slice(0, -1),
      ]) {
        if (bad === content) continue;
        expect(judge(hookCreated(path, original, bad), draft), `${label}: ${JSON.stringify(bad.slice(-60))}`).not.toEqual([]);
      }
    }
    const precommitFile = hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, built('pre-commit', PRE_COMMIT, hookDraft('pre-commit')));
    // the wrong manager, a skipped part, the wrong part, no edited marker, an empty original for an existing config: refused
    expect(judge(precommitFile, hookDraft('husky')).join('\n')).toMatch(/hook manager is husky/);
    expect(judge(precommitFile, hookDraft(null)).join('\n')).toMatch(/sets up only lefthook/);
    expect(judge(hookCreated(HOOK_FILES.husky, '', built('husky', '', hookDraft('husky'))), hookDraft(null)).join('\n')).toMatch(/sets up only lefthook/);
    expect(judge(precommitFile, hookDraft('pre-commit', { skipped: [{ part: 'precommit', reason: 'x' }] })).join('\n')).toMatch(/skipped/);
    expect(judge({ ...precommitFile, part: 'pipeline' }, hookDraft('pre-commit')).join('\n')).toMatch(/does not belong to the part/);
    expect(judge({ ...precommitFile, edited: undefined }, hookDraft('pre-commit')).join('\n')).toMatch(/edited marker/);
    expect(judge(hookCreated(HOOK_FILES['pre-commit'], '', built('pre-commit', '', hookDraft('pre-commit'))), hookDraft('pre-commit')).join('\n')).toMatch(/original text given is empty/);
    expect(judge(hookCreated('lefthook.yml', '', built('lefthook', '', hookDraft(null))), hookDraft(null, { profile: { ...prof, precommit: null, otherHookManagers: ['simple-git-hooks'] } })).join('\n')).toMatch(/another hook manager/);
    // a re-run (the file already holds pipegen's block) and a shape pipegen can not append to give no file: the builder gives a note, the judge refuses
    expect('note' in hookFile('husky', built('husky', HUSKY, hookDraft('husky')), hookDraft('husky'), reviewedList())).toBe(true);
    for (const [manager, original] of [['pre-commit', 'repos: []\n'], ['pre-commit', 'repos:\n    - repo: local\n      hooks: []\n'], ['pre-commit', 'repos:\n- repo: local\n  hooks: []\nfail_fast: true\n'], ['lefthook', 'pre-commit:\n  commands: {}\n'], ['husky', 'npm test \\\n'], ['husky', 'cat <<EOF\n'], ['husky', 'npm test\r\n']] as const) {
      expect('note' in hookFile(manager, original, hookDraft(manager), reviewedList()), `${manager} ${JSON.stringify(original)}`).toBe(true);
    }
    // only the root npm service's pre-commit format-lint need, with the entry at its reviewed pin: a sub-folder service, another layer, another pin give no hook
    const api = { ...(prof.services[1] as PipelineDraft['profile']['services'][number]), name: 'api' };
    const sub = hookDraft('husky', { profile: { ...prof, precommit: 'husky', services: [...prof.services, api] }, needs: [...d.needs, { ...fmtNeed, service: 'api' }], steps: [...d.steps, specFor(entry('biome'), { needId: 'format-lint', service: 'api' })] });
    expect(hookCommands(sub, reviewedList())).toEqual([]);
    expect(hookCommands(hookDraft('husky', { needs: [...d.needs, { ...fmtNeed, layer: 'merge' }] }), reviewedList())).toEqual([]);
    const biome = entry('biome');
    const notNpm = reviewedList().map((t) => (t.id !== 'biome' || t.step.cli === undefined ? t : { ...t, step: { ...t.step, cli: { ...t.step.cli, install: { ...t.step.cli.install, method: 'github-release' as const } } } }));
    expect(hookCommands(hookDraft('husky'), notNpm)).toEqual([]);
    const otherPin = specFor(biome, { needId: 'format-lint', service: 'app', tool: { ...biome.candidate, version: '0.0.1' } });
    expect(hookCommands(hookDraft('husky', { steps: [...d.steps, otherPin] }), reviewedList())).toEqual([]);
    // no reviewed hook command for the repository (no biome spec for the root service): no block at all
    expect(hookCommands(draftOf({ profile: { ...prof, precommit: 'husky' }, needs: [...d.needs, fmtNeed] }), reviewedList())).toEqual([]);
    expect('note' in hookFile('husky', HUSKY, draftOf({ profile: { ...prof, precommit: 'husky' } }), reviewedList())).toBe(true);
    // only those three exact paths are claimed (the hidden() exception is for them alone), in the app repo
    for (const path of ['.husky/pre-push', '.husky/_/pre-commit', 'api/.pre-commit-config.yaml', '.pre-commit-config.yml', 'lefthook.yaml', '.lefthook.yml', 'api/lefthook.yml']) {
      expect(CREATED_RULES.filter((r) => r.match(path, hookDraft('lefthook'))).map((r) => r.id), path).toEqual([]);
    }
    expect((await run([gateFile(), { ...precommitFile, repo: 'central' }], hookDraft('pre-commit'))).ok).toBe(false);
  });

  it('referee: a new remote hook repo (repos: url + rev) refused', async () => {
    const draft = hookDraft('pre-commit');
    const ours = built('pre-commit', PRE_COMMIT, draft);
    const remote = '  - repo: https://github.com/gitleaks/gitleaks\n    rev: 4e43d1109ef5c1e9cb2a2b47fb8d4a2b7d1e0f5a\n    hooks:\n      - id: gitleaks\n';
    for (const content of [PRE_COMMIT + remote, ours + remote, PRE_COMMIT + remote.replace(/https:[^\n]+/, '"https://example.com/x.git"'), ours.replace('repo: local', 'repo: https://github.com/x/y')]) {
      const problems = judge(hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, content), draft);
      expect(problems.join('\n'), content).toMatch(/remote hook repo/);
      expect((await run([gateFile(), hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, content)], draft)).ok).toBe(false);
    }
    // the text check and the parsed check each catch what the other can not read: an unparsable remote entry, and a flow-style one
    expect(judge(hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, `${ours}  - repo: https://github.com/x/y\n    rev: [\n`), draft).join('\n')).toMatch(/remote hook repo/);
    expect(judge(hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, `${ours}  - {repo: "https://github.com/x/y", rev: abc, hooks: []}\n`), draft).join('\n')).toMatch(/remote hook repo/);
    // a rev added to pipegen's local repo is refused too (a local repo has no rev; one would mean a remote fetch)
    expect(judge(hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, ours.replace('- repo: local\n', `- repo: local\n    rev: ${'a'.repeat(40)}\n`)), draft).join('\n')).toMatch(/remote hook repo/);
    // lefthook's remote configs (remotes, extends) are refused the same way
    const lh = hookDraft('lefthook');
    const lhOurs = built('lefthook', LEFTHOOK, lh);
    for (const extra of ['remotes:\n  - git_url: https://github.com/x/hooks\n    ref: v1\n', 'extends:\n  - /tmp/x.yml\n']) {
      expect(judge(hookCreated('lefthook.yml', LEFTHOOK, lhOurs + extra), lh).join('\n'), extra).toMatch(/remote hook/);
    }
    // the user's own remote repos are theirs: kept untouched, and pipegen's append next to them passes
    expect(judge(hookCreated(HOOK_FILES['pre-commit'], PRE_COMMIT, ours), draft)).toEqual([]);
  });
});

// ---------- fix round 1 (review-G1, controller ruling G1-R2) ----------

/** CONCURRENCY_GROUP evaluated for one event, the way Actions would (format, ==, && and || on strings): the test translates it to JS. */
function groupFor(ev: { ref: string; defaultBranch: string; runId: string; name: string }): string {
  const body = CONCURRENCY_GROUP.slice(3, -2).trim();
  const js = body.replace(/github\.event\.repository\.default_branch/g, 'e.defaultBranch').replace(/github\.run_id/g, 'e.runId').replace(/github\.event_name/g, 'e.name').replace(/github\.ref/g, 'e.ref').replace(/==/g, '===');
  const format = (f: string, ...a: string[]): string => f.replace(/\{(\d)\}/g, (_m, i: string) => a[Number(i)] as string);
  return new Function('e', 'format', `return (${js});`)(ev, format) as string;
}

describe('G1 fix round 1 (ruling G1-R2)', () => {
  it('I1: pipegen.yml takes only push [<default>], pull_request and pull_request_review; the push, nightly and called files only their own triggers', async () => {
    const full = { push: defaultPushTrigger('main'), pull_request: null, pull_request_review: { ...PR_REVIEW_TRIGGER, types: [...PR_REVIEW_TRIGGER.types] } };
    expect(show(await run([gateFile({ on: full })], d))).toBe('');
    const deploy = job(renderJobPrelude({}, p).steps, { needs: ['gate'], if: DEPLOY_PUSH_IF });
    for (const extra of [{ workflow_dispatch: null }, { workflow_call: null }, { merge_group: null }, { schedule: [{ cron: '0 3 * * *' }] }]) {
      const r = await run([gateFile({ on: { ...full, ...extra } }, { deploy })], d);
      expect(has(r, 'template', /pipegen\.yml runs only on/), `${JSON.stringify(extra)}: ${show(r)}`).toBe(true);
    }
    for (const pr of [{}, { branches: ['main'] }, { types: ['opened'] }]) {
      expect(has(await run([gateFile({ on: { ...full, pull_request: pr } })], d), 'template', /pipegen\.yml runs only on/), JSON.stringify(pr)).toBe(true);
    }
    // the push file: exactly the feature push; the nightly file: schedule only; a called file: workflow_call only
    for (const on of [{ push: featurePushTrigger('main'), pull_request: null }, { push: featurePushTrigger('main'), workflow_dispatch: null }, { pull_request: null }]) {
      expect(has(await run([gateFile(), at(workflow({ 'sast--app': jobsOf(d)['sast--app'] as Job }, { on }), PUSH_WORKFLOW)], d), 'template', /pipegen-push\.yml runs only on/), JSON.stringify(on)).toBe(true);
    }
    const nightly = job([renderNightlyStep(GATE, d)], { permissions: { contents: 'read', actions: 'read', issues: 'write' }, concurrency: NIGHTLY_CONCURRENCY });
    const nf = (on: unknown): CreatedFile => at(workflow({ nightly }, { on }), '.github/workflows/pipegen-nightly.yml');
    expect(has(await run([gateFile(), nf({ schedule: [{ cron: '17 3 * * *' }] })], d), 'template', /runs only on/)).toBe(false);
    for (const on of [{ schedule: [{ cron: '17 3 * * *' }], workflow_dispatch: null }, { schedule: [{ cron: '17 3 * * *' }], push: defaultPushTrigger('main') }, { pull_request: null }]) {
      expect(has(await run([gateFile(), nf(on)], d), 'template', /pipegen-nightly\.yml runs only on/), JSON.stringify(on)).toBe(true);
    }
    const called = (on: unknown, path: string, repo: CreatedFile['repo']): CreatedFile => at(workflow({ 'sast--app': jobsOf(d)['sast--app'] as Job }, { on }), path, repo);
    for (const [path, repo] of [['.github/workflows/pipegen-merge.yml', 'app'], ['.github/workflows/r--merge.yml', 'central'], ['.github/workflows/x.yml', 'central'], ['.github/workflows/ci.yml', 'app']] as const) {
      expect(has(await run([gateFile(), called({ workflow_call: null, pull_request: null }, path, repo)], d), 'template', /called workflow runs only on workflow_call/), `${repo}:${path}`).toBe(true);
    }
    expect(has(await run([gateFile(), called({ pull_request: null }, '.github/workflows/r--merge.yml', 'central')], d), 'template', /called workflow runs only on workflow_call/)).toBe(true);
    expect(has(await run([gateFile(), called({ workflow_call: null }, '.github/workflows/r--merge.yml', 'central')], d), 'template', /runs only on/)).toBe(false);
  });

  it('I2: one concurrency form (G1-R1, G1-R1b): default-branch runs each their own group, PR and review runs apart; no other concurrency anywhere', async () => {
    const base = { defaultBranch: 'main', runId: '' };
    // the default branch: a unique group per run (nothing queued, nothing cancelled), whatever the event
    expect(groupFor({ ...base, ref: 'refs/heads/main', runId: '11', name: 'push' })).toBe('pipegen-11');
    expect(groupFor({ ...base, ref: 'refs/heads/main', runId: '12', name: 'push' })).toBe('pipegen-12');
    // a pull request: one group per ref and event, so the review run never cancels the pull_request run (G1-R1b)
    const pr = groupFor({ ...base, ref: 'refs/pull/7/merge', runId: '13', name: 'pull_request' });
    const review = groupFor({ ...base, ref: 'refs/pull/7/merge', runId: '14', name: 'pull_request_review' });
    expect(pr).toBe('pipegen-refs/pull/7/merge-pull_request');
    expect(review).toBe('pipegen-refs/pull/7/merge-pull_request_review');
    expect(pr).not.toBe(review);
    expect(groupFor({ ...base, ref: 'refs/pull/7/merge', runId: '15', name: 'pull_request' })).toBe(pr);   // a new push to the PR cancels its old run
    // a feature-branch push and a branch named like the default in another repo shape: grouped per ref, never the unique default arm
    expect(groupFor({ ...base, ref: 'refs/heads/feature', runId: '16', name: 'push' })).toBe('pipegen-refs/heads/feature-push');
    expect(groupFor({ ...base, ref: 'refs/tags/main', runId: '17', name: 'push' })).toBe('pipegen-refs/tags/main-push');
    // job-level concurrency: only the nightly job's own form, on the job nightly
    const j = jobsOf(d);
    for (const [id, c] of [['sast--app', 'x'], ['sast--app', { group: 'x', 'cancel-in-progress': true }], ['gate', NIGHTLY_CONCURRENCY], ['base-scan', { ...WORKFLOW_CONCURRENCY }]] as const) {
      const r = await run([workflow({ ...j, [id]: { ...(j[id] as Job), concurrency: c } })], d);
      expect(has(r, 'injection', /concurrency/), `${id} ${JSON.stringify(c)}: ${show(r)}`).toBe(true);
    }
    const nightly = (c: unknown): Job => job([renderNightlyStep(GATE, d)], { permissions: { contents: 'read', actions: 'read', issues: 'write' }, concurrency: c });
    const nf = (c: unknown): CreatedFile => at(workflow({ nightly: nightly(c) }, { on: { schedule: [{ cron: '17 3 * * *' }] } }), '.github/workflows/pipegen-nightly.yml');
    expect(has(await run([gateFile(), nf(NIGHTLY_CONCURRENCY)], d), 'injection', /concurrency/)).toBe(false);
    for (const c of ['pipegen-nightly-x', { group: NIGHTLY_CONCURRENCY, 'cancel-in-progress': true }, { group: NIGHTLY_CONCURRENCY }]) {
      expect(has(await run([gateFile(), nf(c)], d), 'injection', /concurrency/), JSON.stringify(c)).toBe(true);
    }
    // a called workflow's job may not carry the workflow form either
    const merge = at(workflow({ ...j, 'sast--app': { ...(j['sast--app'] as Job), concurrency: { ...WORKFLOW_CONCURRENCY } } }, { on: { workflow_call: null } }), '.github/workflows/pipegen-merge.yml');
    expect(has(await run([merge], d), 'injection', /concurrency/)).toBe(true);
  });

  it('I3: the hook command names the reviewed package at its reviewed version', async () => {
    const biome = entry('biome');
    const install = biome.step.cli?.install as { package: string; version: string };
    const [hook] = hookCommands(hookDraft('husky'), reviewedList());
    expect(hook?.run).toBe(`npx --no --package=${install.package}@${install.version} -- biome check --staged --no-errors-on-unmatched --vcs-enabled=true --vcs-client-kind=git`);
    // the version comes from the reviewed entry, never a bare name: another reviewed version gives another command
    const bumped = reviewedList().map((t) => (t.id !== 'biome' || t.step.cli === undefined ? t : { ...t, step: { ...t.step, cli: { ...t.step.cli, install: { ...t.step.cli.install, version: '9.9.9' } } } }));
    // (G6: and only when the lockfile holds that version, so the bumped entry's draft installs 9.9.9)
    const at999 = hookDraft('husky', { profile: { ...prof, precommit: 'husky', services: biomeInstalled.map((s, i) => (i !== 0 ? s : { ...s, quality: { ...s.quality, versions: { '@biomejs/biome': '9.9.9' } } })) } });
    expect(hookCommands(at999, bumped)[0]?.run).toContain(`--package=${install.package}@9.9.9 `);
    expect(hookCommands(hookDraft('husky'), bumped)).toEqual([]);
    // a bare-name hook (no --package pin) is refused by the judge
    const draft = hookDraft('husky');
    const ok = built('husky', HUSKY, draft);
    const bare = ok.replace(` --package=${install.package}@${install.version}`, '');
    expect(bare).not.toBe(ok);
    expect(judge(hookCreated(HOOK_FILES.husky, HUSKY, bare), draft)).not.toEqual([]);
  });

  it('I4: the hook builder parses its result; an original it can not append to safely gives no edit and a note', async () => {
    const lh = hookDraft('lefthook');
    const pc = hookDraft('pre-commit');
    for (const [manager, original, draft] of [
      ['lefthook', '{colors: false}\n', lh], ['lefthook', 'colors: false\n...\n', lh], ['lefthook', 'colors: false\n---\nx: 1\n', lh], ['lefthook', 'colors: false\n# a comment\n...\n', lh],
      ['pre-commit', 'repos:\n- {repo: local, hooks: []}\n...\n', pc], ['pre-commit', '{repos: [{repo: local, hooks: []}]}\n', pc], ['pre-commit', 'repos:\n- repo: local\n  hooks: []\n---\nx: 1\n', pc],
    ] as const) {
      const b = hookFile(manager, original, draft, reviewedList());
      expect('note' in b, `${manager} ${JSON.stringify(original)}`).toBe(true);
      // and the judge refuses what a naive append would give
      const naive = `${original}${hookBlock(manager, hookCommands(draft, reviewedList()))}`;
      expect(judge(hookCreated(HOOK_FILES[manager], original, naive), draft), `${manager} ${JSON.stringify(original)}`).not.toEqual([]);
    }
    // the data rule itself: a result that parses but changes the user's data, or adds other hooks, is a problem
    const cmds = hookCommands(lh, reviewedList());
    const lhBlock = hookBlock('lefthook', cmds);
    expect(hookDataProblem('lefthook', 'colors: false\n', `colors: false\n${lhBlock}`, cmds)).toBeNull();
    expect(hookDataProblem('lefthook', 'colors: false\n', `colors: true\n${lhBlock}`, cmds)).toMatch(/exactly pipegen's hooks/);
    expect(hookDataProblem('lefthook', 'colors: false\n', `colors: false\n${lhBlock}    extra:\n      run: "x"\n`, cmds)).toMatch(/exactly pipegen's hooks/);
    expect(hookDataProblem('pre-commit', 'repos: []\nfail_fast: true\n', `fail_fast: false\nrepos:\n${hookBlock('pre-commit', cmds)}`, cmds)).toMatch(/exactly pipegen's hooks/);
    // every file the builder does write parses as one document holding the user's data plus exactly pipegen's hooks
    for (const [manager, original, draft] of [['lefthook', LEFTHOOK, lh], ['lefthook', '', hookDraft(null)], ['pre-commit', PRE_COMMIT, pc], ['pre-commit', PRE_COMMIT.replace(/^ {2}/gm, ''), pc]] as const) {
      const content = built(manager, original, draft);
      expect(judge(hookCreated(HOOK_FILES[manager], original, content), draft)).toEqual([]);
    }
  });

  it('m1: gate look-alike names are compared normalized (case, spaces, slashes)', async () => {
    for (const name of ['Gate', 'GATE', 'gate ', ' gate', 'pipegen / Gate', 'pipegen /gate', 'Pipegen//gate', 'pipegen  /  gate', 'pipegen/gate']) {
      const r = await run([gateFile(), pushFile({}, {}, { lookalike: job(renderJobPrelude({}, p).steps, { name }) })], d);
      expect(has(r, 'not-gate-readable', /pushes to a branch other than the default/), `${JSON.stringify(name)}: ${show(r)}`).toBe(true);
      const r2 = await run([workflow({ ...jobsOf(d), other: job(renderJobPrelude({}, p).steps, { name }) })], d);
      expect(has(r2, 'not-gate-readable', /named like the gate/), `${JSON.stringify(name)}: ${show(r2)}`).toBe(true);
    }
    const byId = await run([gateFile(), pushFile({}, {}, { Gate: job(renderJobPrelude({}, p).steps) })], d);
    expect(has(byId, 'not-gate-readable', /pushes to a branch other than the default/), show(byId)).toBe(true);
    const byIdHere = await run([workflow({ ...jobsOf(d), Gate: job(renderJobPrelude({}, p).steps) })], d);
    expect(has(byIdHere, 'not-gate-readable', /named like the gate/), show(byIdHere)).toBe(true);
    // a name that merely contains the word is not a look-alike
    expect(has(await run([gateFile(), pushFile({}, {}, { lookalike: job(renderJobPrelude({}, p).steps, { name: 'gate keeper' }) })], d), 'not-gate-readable', /pushes to a branch/)).toBe(false);
  });

  it('m2: unreadable triggers fail closed in the schedule rule too', async () => {
    const ed = editedUser('  push:\n', 'pipegen-verify', [renderFindRunStep(GATE, {})], VERIFY_PERMS);
    const odd = { ...ed.f, content: ed.f.content.replace('on:\n  push:\n', 'on: 5\n'), inserted: { ...(ed.f.inserted as NonNullable<CreatedFile['inserted']>), original: (ed.f.inserted?.original as string).replace('on:\n  push:\n', 'on: 5\n') } };
    expect(odd.content).not.toBe(ed.f.content);
    const r = await run([odd], ed.draft);
    expect(has(r, 'template', /runs on schedule/), show(r)).toBe(true);
  });

  it('m3: a call chain deeper than the limit is refused, never read as holding the gate', async () => {
    const chain = Array.from({ length: 12 }, (_, i) => at(workflow({ next: { uses: `./.github/workflows/c${i + 1}.yml`, permissions: { contents: 'read' } } }, { on: { workflow_call: null } }), `.github/workflows/c${i}.yml`));
    const on = { push: defaultPushTrigger('main'), pull_request: null };
    // a deploy job needing a job whose chain is too deep: the deep job is no gate holder, so the deploy condition is refused too
    const f = workflow({ ...jobsOf(d), deep: { uses: './.github/workflows/c0.yml', permissions: { contents: 'read' } }, deploy: job(renderJobPrelude({}, p).steps, { needs: ['deep'], if: DEPLOY_PUSH_IF }) }, { on });
    const r = await run([...chain, f], d);
    expect(has(r, 'template', /deeper than/), show(r)).toBe(true);
    expect(has(r, 'template', /deploy condition/), show(r)).toBe(true);
    // a shallow chain is fine
    const short = await run([...chain.slice(0, 3).map((c, i) => (i === 2 ? at(workflow({ x: job(renderJobPrelude({}, p).steps) }, { on: { workflow_call: null } }), c.path) : c)), at(workflow({ c: { uses: './.github/workflows/c0.yml', permissions: { contents: 'read' } } }, { on: { push: featurePushTrigger('main') } }), PUSH_WORKFLOW)], d);
    expect(has(short, 'template', /deeper than/), show(short)).toBe(false);
  });

  it('m4: a husky original with exit, exec, a heredoc or an unclosed construct gets no append, only a note', () => {
    const draft = hookDraft('husky');
    for (const original of ['npm test\nexit 0\n', 'exec npm test\n', 'if [ -n "$CI" ]; then\n  npm test\n', 'case "$x" in\n  a) npm test ;;\n', 'case "$x" in\n  (a) npm test ;;\n', 'for f in a b; do\n  echo $f\n', 'while true; do\n', 'cat <<1\n', 'cat <<\\EOF\n', "cat <<'EOF'\n", 'echo "unclosed\n', "echo 'unclosed\n", 'npm test || exit 1\n', '{\n  npm test\n', '(\n  npm test\n']) {
      const b = hookFile('husky', original, draft, reviewedList());
      expect('note' in b, JSON.stringify(original)).toBe(true);
      const naive = `${original}${hookBlock('husky', hookCommands(draft, reviewedList()))}`;
      expect(judge(hookCreated(HOOK_FILES.husky, original, naive), draft), JSON.stringify(original)).not.toEqual([]);
    }
    // closed constructs and plain lines are fine
    for (const original of ['npm test\n', 'if [ -n "$CI" ]; then\n  npm test\nfi\n', 'for f in a b; do\n  echo "$f"\ndone\n', "echo 'ok' \"ok\"\n", '# exit early? no\nnpm run lint\n']) {
      expect('content' in hookFile('husky', original, draft, reviewedList()), JSON.stringify(original)).toBe(true);
    }
  });
});
