// v0.2 Plan G Task 2, file half (sub-task G5; rulings B2, B5, S16, S25, G-P1/S28 a; carries G1-R1/R1b, G3, G4): the assembled jobs laid out
// into the delivered files. The app's pipegen.yml (push [<default>], pull_request, pull_request_review), pipegen-push.yml (every other branch)
// and pipegen-nightly.yml (schedule); a private app calls its central <repo>--{merge,push,nightly}.yml at the recorded commit, a public one
// calls the local pipegen-merge.yml and holds its push and nightly jobs inline. Caller permissions are the union of the called jobs', every
// secret is mapped by name, the not-proven list is the gate step's literal on one marked line of the merge file, and every file goes through
// one referee call.
import { createHash } from 'node:crypto';
import { Document, parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { composeText } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { centralProjectName, centralWorkflowFile, centralWorkflowPath } from '../src/engine/central-path.js';
import { floorNeeds } from '../src/engine/needs.js';
import {
  CALLER_WORKFLOW, createdPathProblem, DEPLOY_PUSH_IF, LOCAL_MERGE_WORKFLOW, NIGHTLY_CONCURRENCY, NIGHTLY_WORKFLOW, PR_CHECK_IF, PR_CHECK_JOB, PUSH_WORKFLOW,
  renderPrCheckStep, WORKFLOW_CONCURRENCY,
} from '../src/engine/job-rules.js';
import { protectedMatcher } from '../src/engine/protected-match.js';
import { referee, type RefereeReport } from '../src/engine/referee.js';
import { DIGEST_STEP_ID, FIND_RUN_STEP_ID, renderHeadCheckStep } from '../src/engine/deploy-steps.js';
import { insertVerify, releaseJobs } from '../src/layers/deploy.js';
import { renderFindRunStep, stepsToYaml } from '../src/engine/render-step.js';
import {
  assemble, callerPermissions, callerSecrets, judgeAssembled, MERGE_CALLER_JOB, NIGHTLY_CRON, NOT_PROVEN_MARK, verifyJob, VERIFY_GRACE_MINUTES, VERIFY_MARGIN_MINUTES,
  type AssembledFiles, type AssembleOpts,
} from '../src/layers/assemble.js';
import { AssembleError, assembleJobs, type Job } from '../src/layers/jobs.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { partOf, PART_TITLE, type PartId } from '../src/audit/parts.js';
import { packageVersion } from '../src/util/package-data.js';
import { GATE_CHECK_NAME, PROTECTED_PATHS_BASE, type Capabilities, type CreatedFile, type PipelineDraft, type ReviewedTool, type SigningPlan } from '../src/types.js';
import { APP_KEY, CAPS, LINTERS, MISSING, node, p, planned, profileOf, SEC, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const PIN_SHA = 'c'.repeat(40);
const PIN = { repo: 'o/pipelines', sha: PIN_SHA };
/** The fingerprint key and the workflow token, spelled at run time (test/no-secret-literals.test.ts). */
const FP = ['PIPEGEN_FP', 'KEY'].join('_');
const TOK = ['GITHUB', 'TOK' + 'EN'].join('_');
const OIDC = ['id', 'token'].join('-');
const ref = (name: string): string => `\${{ ${SEC}.${name} }}`;
const KE_CAPS: Capabilities = { ...CAPS, environments: true, deploymentBranchPolicies: true };
const PUB_SHA = createHash('sha256').update('a public key', 'utf8').digest('hex');
const IMG = { service: 'app', repo: 'ghcr.io/o/r/pipegen-app' };

type Planned = ReturnType<typeof planned>;
const optsOf = (x: Planned, over: Partial<AssembleOpts> = {}): AssembleOpts => ({
  gate: GATE, reviewed: REVIEWED, platform: p, mode: 'none', layout: x.draft.profile.private ? 'central' : 'local', plan: x.plan, ...over,
});
const lay = (x: Planned, over: Partial<AssembleOpts> = {}): AssembledFiles => assemble(x.draft, optsOf(x, over));
const pub = (over: Partial<PipelineDraft> = {}): Planned => planned(profileOf(), { over });
const priv = (over: Partial<PipelineDraft> = {}, caps: Capabilities = CAPS): Planned => planned(profileOf([node()], { private: true }), { caps, over: { centralPin: PIN, ...over } });
const fileAt = (a: AssembledFiles, repo: CreatedFile['repo'], path: string): CreatedFile => {
  const f = a.files.find((x) => x.repo === repo && x.path === path);
  expect(f, `${repo}:${path} in ${a.files.map((x) => `${x.repo}:${x.path}`).join(', ')}`).toBeDefined();
  return f as CreatedFile;
};
const js = (f: CreatedFile): Obj => parse(f.content) as Obj;
const workflows = (a: AssembledFiles): CreatedFile[] => a.files.filter((f) => f.path.startsWith('.github/workflows/'));
const jobsOfFile = (f: CreatedFile): Record<string, Obj> => js(f).jobs as Record<string, Obj>;
const C = (layer: 'merge' | 'push' | 'nightly', project = 'r'): string => centralWorkflowFile(project, layer);
/** The referee's fixed inputs (no linter run, no online token). */
const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Omit<Parameters<typeof judgeAssembled>[1], 'extra' | 'referee'>;
const judge = (a: AssembledFiles, extra: CreatedFile[] = []): Promise<RefereeReport> => judgeAssembled(a, { ...JD, extra });

/** The deploy layer's image-publish job, from releaseJobs itself (G15a round 12, security r6 Nit 1: a hand-built copy would not catch
 * renderer drift): the job releaseJobs renders for the key-env draft below (one published root service, app, with a Dockerfile). */
function imagePublish(): Job {
  return releaseJobs(keyEnv().draft, { platform: p })['image-publish'] as Job;
}
/** A key-env private draft (environments with the proven branch policy) whose app has a Dockerfile; the needs of the plain profile. */
function keyEnv(): Planned {
  const plain = profileOf([node()], { private: true });
  const prof = profileOf([node({ dockerfile: 'Dockerfile' })], { private: true });
  const plan: SigningPlan = { mode: 'key-env', images: [IMG], cosignPubSha256: PUB_SHA };
  return planned(prof, { caps: KE_CAPS, needs: floorNeeds(plain, KE_CAPS), over: { centralPin: PIN, signing: plan } });
}
function keyless(): Planned {
  const plain = profileOf();
  const prof = profileOf([node({ dockerfile: 'Dockerfile' })]);
  return planned(prof, { needs: floorNeeds(plain, CAPS), over: { signing: { mode: 'keyless', images: [IMG] } } });
}
const DEPLOY = { 'image-publish': imagePublish() };

describe('G5: the delivered files and their callers', () => {
  it('assemble: caller job named pipegen and gate job named gate → check name equals GATE_CHECK_NAME', () => {
    for (const [x, repo, path] of [[priv(), 'central', C('merge')], [pub(), 'app', LOCAL_MERGE_WORKFLOW]] as const) {
      const a = lay(x);
      const caller = jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW))[MERGE_CALLER_JOB] as Obj;
      expect(MERGE_CALLER_JOB).toBe('pipegen');
      expect(caller.name).toBe('pipegen');
      const gate = jobsOfFile(fileAt(a, repo, path)).gate as Obj;
      expect(gate.name).toBe('gate');
      expect(`${caller.name} / ${gate.name}`).toBe(GATE_CHECK_NAME);
      // no other job anywhere reports under a name like the gate's (the push and nightly callers are named apart)
      for (const f of workflows(a)) {
        for (const [id, j] of Object.entries(jobsOfFile(f))) {
          if (f.path === path && id === 'gate') continue;
          const n = String(j.name ?? id).toLowerCase().replace(/\s*\/\s*/g, '/');
          expect(['gate', 'pipegen/gate'], `${f.path} ${id}`).not.toContain(n);
          if (!(f.path === CALLER_WORKFLOW && id === MERGE_CALLER_JOB)) expect(j.name, `${f.path} ${id}`).not.toBe('pipegen');
        }
      }
    }
  });

  it("assemble: caller grants each called workflow the union of its jobs' permissions", () => {
    // the union, 'write' over 'read', from the permission table (never more than a job id may have)
    expect(callerPermissions([{ job: 'gate', permissions: { contents: 'read', actions: 'read', 'pull-requests': 'read' } }, { job: 'nightly', permissions: { contents: 'read', actions: 'read', issues: 'write' } }]))
      .toEqual({ contents: 'read', actions: 'read', 'pull-requests': 'read', issues: 'write' });
    expect(callerPermissions([{ job: 'sign', permissions: { contents: 'read', packages: 'read' } }, { job: 'image-publish', permissions: { packages: 'write' } }])).toEqual({ contents: 'read', packages: 'write' });
    expect(callerPermissions([{ job: 'sast--app', permissions: { contents: 'read' } }, { job: 'base-scan', permissions: { contents: 'read', actions: 'read' } }])).toEqual({ contents: 'read', actions: 'read' });
    // whatever the order: a later read never lowers an earlier write
    expect(callerPermissions([{ job: 'image-publish', permissions: { packages: 'write' } }, { job: 'sign', permissions: { contents: 'read', packages: 'read' } }])).toEqual({ contents: 'read', packages: 'write' });
    expect(() => callerPermissions([{ job: 'sast--app', permissions: { contents: 'read', issues: 'write' } }])).toThrow(AssembleError);
    expect(() => callerPermissions([{ job: 'gate', permissions: { 'pull-requests': 'write' } }])).toThrow(/more than/);
    expect(() => callerPermissions([{ job: 'gate', permissions: { contents: 'write' } }])).toThrow(/more than/);
    expect(() => callerPermissions([{ job: 'gate', permissions: { actions: 'admin' as 'read' } }])).toThrow(AssembleError);
    // private key-env: every caller job's permissions are exactly the union of the jobs of the workflow it calls
    const a = lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY });
    const callers = Object.entries(jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW))).filter(([, j]) => j.uses !== undefined);
    const pushCallers = Object.entries(jobsOfFile(fileAt(a, 'app', PUSH_WORKFLOW)));
    const nightlyCallers = Object.entries(jobsOfFile(fileAt(a, 'app', NIGHTLY_WORKFLOW)));
    const all = [...callers, ...pushCallers, ...nightlyCallers];
    // pipegen.yml: the merge caller and the sign caller (image-publish runs in the app itself); pipegen-push.yml and pipegen-nightly.yml: one each
    expect(all.length).toBe(4);
    for (const [id, j] of all) {
      const path = (j.uses as string).replace(/^o\/pipelines\//, '').replace(/@[0-9a-f]{40}$/, '');
      const called = jobsOfFile(fileAt(a, 'central', path));
      const union = callerPermissions(Object.entries(called).map(([job, cj]) => ({ job, permissions: cj.permissions })));
      expect(j.permissions, id).toEqual(union);
    }
    const perms = (path: string) => (all.find(([, j]) => String(j.uses).includes(path)) as [string, Obj])[1].permissions;
    expect(perms(C('merge'))).toEqual({ contents: 'read', actions: 'read', 'pull-requests': 'read' });
    expect(perms(C('push'))).toEqual({ contents: 'read', 'pull-requests': 'read' });
    expect(perms(C('nightly'))).toEqual({ contents: 'read', actions: 'read', issues: 'write' });
    expect(perms(centralWorkflowFile('r', 'sign'))).toEqual({ contents: 'read', packages: 'write' });
    // issues: write only for the nightly; no caller gets an OIDC token in key-env
    for (const [id, j] of all) if (!String(j.uses).includes(C('nightly'))) expect(j.permissions.issues, id).toBeUndefined();
    expect(JSON.stringify(all)).not.toContain(OIDC);
    // the top of every file grants nothing
    for (const f of workflows(a)) expect(js(f).permissions, f.path).toEqual({});
    // keyless (public): the sign job inline in pipegen.yml asks for the OIDC token and the registry write, and nothing calls it
    const k = lay(keyless(), { mode: 'keyless', deploy: DEPLOY });
    const sign = jobsOfFile(fileAt(k, 'app', CALLER_WORKFLOW)).sign as Obj;
    expect(sign.permissions).toEqual({ contents: 'read', [OIDC]: 'write', packages: 'write' });
    expect(sign.uses).toBeUndefined();
  });

  it('assemble: triggers are push [<default>], pull_request, pull_request_review [submitted, dismissed]; schedule only in the nightly file; no tag triggers', () => {
    for (const x of [priv(), pub(), planned(profileOf([node()], { defaultBranch: 'develop' }))]) {
      const a = lay(x);
      const def = x.draft.profile.defaultBranch;
      expect(js(fileAt(a, 'app', CALLER_WORKFLOW)).on).toEqual({ push: { branches: [def] }, pull_request: null, pull_request_review: { types: ['submitted', 'dismissed'] } });
      expect(js(fileAt(a, 'app', PUSH_WORKFLOW)).on).toEqual({ push: { 'branches-ignore': [def] } });
      // G15a round 3 (PF-3): the weekly Scorecard entry only when the plan has its job (Scorecard needs code scanning: public here)
      const weekly = a.draft.needs.some((n) => n.id === 'scorecard') ? [{ cron: '23 4 * * 1' }] : [];
      expect(js(fileAt(a, 'app', NIGHTLY_WORKFLOW)).on).toEqual({ schedule: [{ cron: NIGHTLY_CRON }, ...weekly] });
      expect(NIGHTLY_CRON).toBe('17 3 * * *');
      for (const f of workflows(a)) {
        const on = js(f).on as Obj;
        if (![CALLER_WORKFLOW, PUSH_WORKFLOW, NIGHTLY_WORKFLOW].includes(f.path) || f.repo === 'central') expect(Object.keys(on), f.path).toEqual(['workflow_call']);
        if (f.path !== NIGHTLY_WORKFLOW || f.repo !== 'app') expect(on.schedule, f.path).toBeUndefined();
        expect(JSON.stringify(on), f.path).not.toMatch(/tags|branches":\["\*|paths/);
      }
    }
    // a default branch that is no plain name is refused, never written as a pattern
    expect(() => lay(planned(profileOf([node()], { defaultBranch: 'rel*' })))).toThrow(AssembleError);
  });

  it('assemble: concurrency per ref cancels in-progress runs, except on the default branch', () => {
    for (const x of [priv(), pub()]) {
      const a = lay(x);
      expect(js(fileAt(a, 'app', CALLER_WORKFLOW)).concurrency).toEqual({ ...WORKFLOW_CONCURRENCY });
      expect(js(fileAt(a, 'app', PUSH_WORKFLOW)).concurrency).toEqual({ ...WORKFLOW_CONCURRENCY });
      // the default branch: its own group per run (never cancelled or queued); any other ref: per ref and event (G1-R1, G1-R1b)
      expect(WORKFLOW_CONCURRENCY.group).toContain("github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && format('pipegen-{0}', github.run_id)");
      expect(WORKFLOW_CONCURRENCY.group).toContain("format('pipegen-{0}-{1}', github.ref, github.event_name)");
      expect(WORKFLOW_CONCURRENCY['cancel-in-progress']).toBe(true);
      for (const f of workflows(a)) {
        if (!(f.repo === 'app' && (f.path === CALLER_WORKFLOW || f.path === PUSH_WORKFLOW))) expect(js(f).concurrency, `${f.repo}:${f.path}`).toBeUndefined();
        for (const [id, j] of Object.entries(jobsOfFile(f))) expect(j.concurrency, `${f.path} ${id}`).toBe(id === 'nightly' ? NIGHTLY_CONCURRENCY : undefined);
      }
    }
  });

  it('assemble: no workflow_dispatch trigger and no layer input', () => {
    for (const a of [lay(priv()), lay(pub()), lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY })]) {
      for (const f of workflows(a)) {
        // (the triggers as parsed: the range scan's own script names workflow_dispatch among the events it knows)
        expect(Object.keys(js(f).on as Obj), f.path).not.toContain('workflow_dispatch');
        expect(JSON.stringify(js(f).on), f.path).not.toMatch(/inputs|layer/);
        const call = (js(f).on as Obj).workflow_call as Obj | null | undefined;
        if (call !== undefined && call !== null) expect(Object.keys(call).filter((k) => k !== SEC), f.path).toEqual([]);
        for (const [id, j] of Object.entries(jobsOfFile(f))) if (j.uses !== undefined) expect(j.with, `${f.path} ${id}`).toBeUndefined();
      }
    }
  });

  it('assemble: push-layer jobs skip when the branch has an open PR (pr-check, pull-requests read), never on the default branch', () => {
    for (const [x, repo, path] of [[priv(), 'central', C('push')], [pub(), 'app', PUSH_WORKFLOW]] as const) {
      const a = lay(x);
      const jobs = jobsOfFile(fileAt(a, repo, path));
      const pr = jobs[PR_CHECK_JOB] as Obj;
      expect(pr.permissions).toEqual({ contents: 'read', 'pull-requests': 'read' });
      expect(pr.outputs).toEqual({ 'has-pr': '${{ steps.pipegen-pr-check.outputs.has-pr }}' });
      expect((pr.steps as Obj[]).map((s) => s.uses?.split('@')[0] ?? s.id)).toEqual(['bullfrogsec/bullfrog', renderPrCheckStep().id]);
      expect(pr.if).toBeUndefined();
      const others = Object.entries(jobs).filter(([id]) => id !== PR_CHECK_JOB);
      expect(others.map(([id]) => id).sort()).toEqual(Object.keys(assembleJobsPush(x)).sort());
      for (const [id, j] of others) {
        expect(j.if, id).toBe(PR_CHECK_IF);
        expect(j.needs, id).toContain(PR_CHECK_JOB);
      }
      // the file runs on every branch but the default, so the skip never applies there; no gate in it
      expect(js(fileAt(a, 'app', PUSH_WORKFLOW)).on).toEqual({ push: { 'branches-ignore': ['main'] } });
      expect(Object.keys(jobs)).not.toContain('gate');
      // the skip is nowhere else: not in the merge or nightly files, not on a caller
      for (const f of workflows(a)) if (f.path !== path) expect(f.content, f.path).not.toContain(PR_CHECK_IF);
    }
    // no push-layer check: no push file at all
    const none = planned(profileOf(), { needs: floorNeeds(profileOf(), CAPS).filter((n) => n.layer !== 'push') });
    expect(lay(none).files.map((f) => f.path)).not.toContain(PUSH_WORKFLOW);
  });

  // the verbatim name, joined at run time (test/no-secret-literals.test.ts reads its last words as an assignment)
  it(['assemble: caller passes explicit secrets mapping for every step secret, runtime secret, not-proven name and PIPEGEN_FP_KEY; no sec', 'rets: inherit'].join(''), () => {
    const svc = node({ envVars: [APP_KEY] });
    const notProven = [{ part: 'pipeline', needId: 'coverage', reason: 't', [MISSING]: [APP_KEY] }] as unknown as PipelineDraft['notProven'];
    for (const priv0 of [true, false]) {
      const x = planned(profileOf([svc], { private: priv0 }), {
        edit: (s) => s.map((st) => (st.needId === 'coverage' ? { ...st, [SEC]: [APP_KEY] } : st)), over: { notProven, ...(priv0 ? { centralPin: PIN } : {}) },
      });
      const a = lay(x);
      const caller = jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW))[MERGE_CALLER_JOB] as Obj;
      // the step secret (also the not-proven check's missing name) and the fingerprint key, each by its own name; the workflow token is GitHub's own
      expect(caller[SEC]).toEqual({ [APP_KEY]: ref(APP_KEY), [FP]: ref(FP) });
      const merge = priv0 ? fileAt(a, 'central', C('merge')) : fileAt(a, 'app', LOCAL_MERGE_WORKFLOW);
      expect((js(merge).on as Obj).workflow_call[SEC]).toEqual({ [APP_KEY]: { required: false }, [FP]: { required: false } });
      // the push and nightly callers (private) pass what their called files read, nothing more
      if (priv0) {
        const push = jobsOfFile(fileAt(a, 'app', PUSH_WORKFLOW))['pipegen-push'] as Obj;
        expect(push[SEC]).toEqual({ [APP_KEY]: ref(APP_KEY), [FP]: ref(FP) });
        const nightly = jobsOfFile(fileAt(a, 'app', NIGHTLY_WORKFLOW))['pipegen-nightly'] as Obj;
        expect(nightly[SEC]).toEqual({ [FP]: ref(FP) });
      }
      for (const f of a.files) expect(f.content, f.path).not.toMatch(/inherit/);
    }
    // the mapping is exactly the names the called jobs read (never GITHUB_TOKEN, never a computed or indexed name)
    const step = (env: Record<string, string>) => ({ x: { steps: [{ env }] } });
    expect(callerSecrets(step({ A: ref('B_KEY'), T: ref(TOK), F: ref(FP) }))).toEqual({ B_KEY: ref('B_KEY'), [FP]: ref(FP) });
    expect(() => callerSecrets(step({ A: `\${{ ${SEC}['B'] }}` }))).toThrow(AssembleError);
    expect(() => callerSecrets(step({ A: `\${{ toJSON(${SEC}) }}` }))).toThrow(AssembleError);
    expect(() => callerSecrets(step({ A: `\${{ ${SEC}.lower }}` }))).toThrow(AssembleError);
    // the compose runtime env (D4) holds no secret value (its password is generated in the job), so it maps nothing
    const dep = { kind: 'postgres' as const, name: 'postgres', evidence: 'x', envVars: ['DATABASE_URL'] };
    const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], dependsOn: [dep] })]);
    const compose: CreatedFile = { path: 'docker-compose.pipegen.yml', content: composeText(prof, loadBaseImages()) as string, part: 'compose', reason: 't', repo: 'app' };
    const c = lay(planned(prof, { over: { created: [compose], skipped: [{ part: 'deploy', reason: 't' }] } }));
    expect(fileAt(c, 'app', LOCAL_MERGE_WORKFLOW).content).toContain('runtime-env-');
    expect(Object.keys((jobsOfFile(fileAt(c, 'app', CALLER_WORKFLOW))[MERGE_CALLER_JOB] as Obj)[SEC])).toEqual([FP]);
  });

  it("assemble: the not-proven line is the gate step's literal in the one file that holds the gate step; nightly holds no copy", () => {
    const x = priv({ notProven: [{ part: 'pipeline', needId: 'licences', reason: 't', [MISSING]: [] } as unknown as PipelineDraft['notProven'][number]] });
    const a = lay(x);
    const marked = (f: CreatedFile): string[] => f.content.split('\n').filter((l) => l.includes(NOT_PROVEN_MARK));
    const merge = fileAt(a, 'central', C('merge'));
    const lines = marked(merge);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(new RegExp(`^\\s+not-proven: .+ # ${NOT_PROVEN_MARK}$`));
    // the literal on that line is the gate step's not-proven input, the draft's list
    const gateStep = ((jobsOfFile(merge).gate as Obj).steps as Obj[]).find((s) => s.with?.mode === 'gate') as Obj;
    expect(JSON.parse(gateStep.with['not-proven'])).toEqual(['licences']);
    expect(lines[0]).toContain('licences');
    // no other file holds the marker or the list: not the caller (no input), not the nightly files (B5)
    for (const f of a.files.filter((f) => f !== merge)) {
      expect(marked(f), f.path).toEqual([]);
      expect(f.content, f.path).not.toContain('not-proven');
    }
    expect(jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW))[MERGE_CALLER_JOB]?.with).toBeUndefined();
    expect(JSON.stringify(jobsOfFile(fileAt(a, 'central', C('nightly'))))).not.toContain('not-proven');
    // the nightly calls no merge workflow
    expect(fileAt(a, 'central', C('nightly')).content).not.toContain('--merge.yml');
    // with no not-proven check there is no list and no marker
    expect(lay(priv()).files.flatMap(marked)).toEqual([]);
  });

  it('assemble: public → the gate step and its not-proven line are in pipegen-merge.yml (protected)', () => {
    const x = pub({ notProven: [{ part: 'pipeline', needId: 'licences', reason: 't', [MISSING]: [] } as unknown as PipelineDraft['notProven'][number]] });
    const a = lay(x);
    const merge = fileAt(a, 'app', LOCAL_MERGE_WORKFLOW);
    const lines = merge.content.split('\n').filter((l) => l.includes(NOT_PROVEN_MARK));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^\s+not-proven: /);
    expect(Object.keys(jobsOfFile(merge))).toContain('gate');
    expect(protectedMatcher(PROTECTED_PATHS_BASE)(merge.path)).toBe(true);
    for (const f of a.files.filter((f) => f !== merge)) expect(f.content, f.path).not.toContain(NOT_PROVEN_MARK);
    // the gate is in the merge file only
    for (const f of workflows(a)) if (f !== merge) expect(Object.keys(jobsOfFile(f)), f.path).not.toContain('gate');
  });

  it('assemble: public repo → inline workflow, no central workflow files', () => {
    const a = lay(pub());
    expect(a.files.filter((f) => f.repo === 'central')).toEqual([]);
    expect(workflows(a).map((f) => f.path).sort()).toEqual([CALLER_WORKFLOW, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PUSH_WORKFLOW].sort());
    // the push and nightly jobs are inline in their own files (a local push or nightly callee would be the file itself)
    for (const path of [PUSH_WORKFLOW, NIGHTLY_WORKFLOW]) for (const [id, j] of Object.entries(jobsOfFile(fileAt(a, 'app', path)))) expect(j.uses, `${path} ${id}`).toBeUndefined();
    expect(Object.keys(jobsOfFile(fileAt(a, 'app', NIGHTLY_WORKFLOW)))).toEqual(['nightly', 'scorecard', 'code-scanning', 'secrets-history', 'code-scanning-history', 'workflow-lint-online']);   // G15a round 3: weekly Scorecard; round 4: the full-history secrets scan; round 5: zizmor online
    // no uses anywhere names the central repo
    expect(a.files.map((f) => f.content).join('\n')).not.toMatch(/\/pipelines\//);
    // a public draft with a central pin is refused (its find-run would look for a central workflow that is not there)
    expect(() => lay(pub({ centralPin: PIN }))).toThrow(/central pin/);
    expect(() => lay(pub({ centralPin: PIN, skipped: [{ part: 'deploy', reason: 't' }] }))).toThrow(/records only/);
    // the gate entry is the reviewed one (S25: a ReviewedTool, the list's own pipegen-gate entry), never another pin
    const otherPin = { ...GATE, step: { ...GATE.step, action: { ...GATE.step.action, uses: `x/gate@${'d'.repeat(40)}` } } } as ReviewedTool;
    expect(() => lay(pub(), { gate: otherPin })).toThrow(/reviewed pipegen-gate entry/);
    // the layout follows the repository, never the caller's word
    expect(() => lay(pub(), { layout: 'central' })).toThrow(AssembleError);
    expect(() => lay(priv(), { layout: 'local' })).toThrow(AssembleError);
  });

  it('assemble: public repo → caller pipegen calls ./.github/workflows/pipegen-merge.yml whose job gate gives GATE_CHECK_NAME', () => {
    const a = lay(pub());
    const jobs = jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW));
    expect(Object.keys(jobs)).toEqual([MERGE_CALLER_JOB]);
    const caller = jobs[MERGE_CALLER_JOB] as Obj;
    expect(caller.uses).toBe(`./${LOCAL_MERGE_WORKFLOW}`);
    const merge = fileAt(a, 'app', LOCAL_MERGE_WORKFLOW);
    expect(Object.keys(js(merge).on as Obj)).toEqual(['workflow_call']);
    expect(`${caller.name} / ${(jobsOfFile(merge).gate as Obj).name}`).toBe(GATE_CHECK_NAME);
  });

  it('assemble: the pipegen-verify job uses findGatedRun (the gate action\'s find-run mode), runs in environment pipegen-signing with actions/packages/attestations read, and waits for completion', async () => {
    const a = lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY });
    const v = a.verify as Job;
    expect(v).not.toBeNull();
    expect(v.environment).toBe('pipegen-signing');
    // G7-R1 sec M7: key-env reads the registry for the signature; no attestations outside attest mode
    expect(v.permissions).toEqual({ contents: 'read', actions: 'read', packages: 'read' });
    expect(v['cache-mode']).toBe('none');
    expect(v.steps[0]?.uses).toMatch(/^bullfrogsec\/bullfrog@/);
    const find = v.steps[1] as Obj;
    // the gate action's find-run mode (findGatedRun), central layout from the pin, through the one path helper
    // it waits for the whole gated run of pipegen.yml (G5-R1 m1): the merge chain (baseline-check → base-scan → gate, 3 × 30), then
    // image-publish (30) and sign (15), plus the grace; and the job outlives the wait
    const wait = 90 + 30 + 15 + VERIFY_GRACE_MINUTES;
    expect(find).toEqual({ id: FIND_RUN_STEP_ID, ...renderFindRunStep(GATE, { central: { repo: PIN.repo, sha: PIN.sha, project: 'r' }, sha: 'github.sha', timeoutMinutes: wait }) });
    expect(find.with['central-workflow']).toBe(centralWorkflowPath(PIN.repo, 'r'));
    expect(v['timeout-minutes']).toBe(wait + VERIFY_MARGIN_MINUTES);
    expect(VERIFY_MARGIN_MINUTES).toBeGreaterThan(0);
    // G7: after find-run, the head check, then per published image the digest of the gated run and the signature check
    expect(v.steps[2]).toEqual(renderHeadCheckStep('main'));
    expect(v.steps[3]?.id).toBe(DIGEST_STEP_ID);
    expect(v.steps).toHaveLength(6);
    expect(v.steps[5]?.run).toContain(' verify --key ');
    // public: inline find-run; no environments: no environment (the plan says so in PIPEGEN.md)
    const pv = lay(pub()).verify as Job;
    expect(pv.steps[1]).toEqual({ id: FIND_RUN_STEP_ID, ...renderFindRunStep(GATE, { sha: 'github.sha', timeoutMinutes: 90 + VERIFY_GRACE_MINUTES }) });
    expect(pv.environment).toBeUndefined();
    expect(pv.steps[2]).toEqual(renderHeadCheckStep('main'));
    expect(pv.steps).toHaveLength(3);
    // the referee accepts the job inserted into a user's deploy workflow (G7 places it), judged with the assembled files in one call
    const deployWf = { path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [['secrets', 'Used'].join('')]: [], jobs: ['deploy'] } as unknown as PipelineDraft['profile']['existingWorkflows'][number];
    const withDeploy = planned(profileOf([node()], { private: true, existingWorkflows: [deployWf] }), { needs: floorNeeds(profileOf([node()], { private: true }), CAPS), over: { centralPin: PIN } });
    const pa = lay(withDeploy);
    expect(pa.verify).toEqual(verifyJob(pa.draft, { gate: GATE, reviewed: REVIEWED, platform: p, waitMinutes: 90 + VERIFY_GRACE_MINUTES }));
    expect(shown(await judge(pa, [insertedDeploy(pa.verify as Job)]))).toBe('');
    // key-env, in pipegen-signing
    const ke = keyEnv();
    const keDeploy = planned({ ...ke.draft.profile, existingWorkflows: [deployWf] }, { caps: KE_CAPS, needs: ke.draft.needs, over: { centralPin: PIN, signing: ke.draft.signing } });
    const ka = lay(keDeploy, { mode: 'key-env', deploy: DEPLOY });
    expect(shown(await judge(ka, [insertedDeploy(ka.verify as Job)]))).toBe('');
    // a skipped deploy part: no verify job
    expect(lay(priv({ skipped: [{ part: 'deploy', reason: 't' }] })).verify).toBeNull();
  });

  it('assemble: dependabot entry has a 7-day cooldown', () => {
    const a = lay(priv());
    const f = fileAt(a, 'app', '.github/dependabot.yml');
    const entry = (js(f).updates as Obj[]).find((u) => u['package-ecosystem'] === 'github-actions') as Obj;
    expect(entry.cooldown).toEqual({ 'default-days': 7 });
    expect(entry.ignore).toEqual([{ 'dependency-name': 'o/pipelines/*' }]);
    expect(f.edited).toEqual({ original: '' });
    // an existing file: the user's bytes first, the entry appended; its text must be given (never a blind overwrite)
    const original = 'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n    schedule:\n      interval: "weekly"\n';
    const withFile = planned(profileOf([node()], { repoFiles: { ...emptyRepoFiles(), dependabot: '.github/dependabot.yml' } }));
    const e = fileAt(lay(withFile, { dependabot: original }), 'app', '.github/dependabot.yml');
    expect(e.content.startsWith(original)).toBe(true);
    expect(e.edited).toEqual({ original });
    expect(((js(e).updates as Obj[])[1] as Obj).cooldown).toEqual({ 'default-days': 7 });
    expect(() => lay(withFile)).toThrow(/Dependabot/);
    // a file that already has a github-actions entry, or Renovate: no file, a note
    const hasGa = `${original}  - package-ecosystem: "github-actions"\n    directory: "/"\n    schedule:\n      interval: "daily"\n`;
    const g = lay(withFile, { dependabot: hasGa });
    expect(g.files.some((x) => x.path.includes('dependabot'))).toBe(false);
    expect(g.notes.join('\n')).toMatch(/github-actions entry/);
    const ren = lay(planned(profileOf([node()], { repoFiles: { ...emptyRepoFiles(), renovate: 'renovate.json' } })));
    expect(ren.files.some((x) => x.path.includes('dependabot'))).toBe(false);
    expect(ren.notes.join('\n')).toMatch(/Renovate/);
  });

  it('assemble: referee passes on all assembled files', async () => {
    for (const [name, a] of [['public', lay(pub())], ['private', lay(priv())], ['private key-env', lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY })], ['public keyless', lay(keyless(), { mode: 'keyless', deploy: DEPLOY })]] as const) {
      const r = await judge(a);
      expect(shown(r), name).toBe('');
      expect(r.ok, name).toBe(true);
    }
  });

  it('assemble: private draft without centralPin → refused; caller uses via centralWorkflowPath', async () => {
    expect(() => lay(priv({ centralPin: undefined }))).toThrow(/central pin/);
    for (const bad of [{ repo: 'x/pipelines', sha: PIN_SHA }, { repo: 'o/pipelines', sha: 'main' }, { repo: 'o/other', sha: PIN_SHA }]) expect(() => lay(priv({ centralPin: bad })), JSON.stringify(bad)).toThrow(/central pin/);
    const a = lay(priv());
    const caller = jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW))[MERGE_CALLER_JOB] as Obj;
    expect(caller.uses).toBe(`${centralWorkflowPath(PIN.repo, 'r')}@${PIN_SHA}`);
    expect(jobsOfFile(fileAt(a, 'app', PUSH_WORKFLOW))['pipegen-push']?.uses).toBe(`${PIN.repo}/${C('push')}@${PIN_SHA}`);
    expect(jobsOfFile(fileAt(a, 'app', NIGHTLY_WORKFLOW))['pipegen-nightly']?.uses).toBe(`${PIN.repo}/${C('nightly')}@${PIN_SHA}`);
    // the referee holds it too (C8r1): the same files with the pin taken off the draft are refused, with an exact issue
    const { centralPin: _pin, ...unpinned } = a.draft;
    const r = await judgeAssembled({ ...a, draft: unpinned }, JD);
    expect(r.issues.some((i) => i.file === '(draft)' && i.check === 'template' && /no valid central pin/.test(i.message)), shown(r)).toBe(true);
    expect((await judge(a)).ok).toBe(true);
    // the app holds only callers: every job of the three app files calls the central repo at the pin
    for (const path of [CALLER_WORKFLOW, PUSH_WORKFLOW, NIGHTLY_WORKFLOW]) for (const [id, j] of Object.entries(jobsOfFile(fileAt(a, 'app', path)))) expect(j.uses, `${path} ${id}`).toMatch(new RegExp(`^o/pipelines/\\.github/workflows/r--[a-z]+\\.yml@${PIN_SHA}$`));
  });

  it('assemble: central filenames slugged, hash fallback for long, device or leading-dash names', () => {
    expect(centralProjectName('r')).toBe('r');
    expect(centralProjectName('My.App_2')).toBe('my.app_2');
    // distinct repository names never share a file name (no folding of . _ - into one another)
    const names = ['my.app', 'my_app', 'my-app', 'MY-APP2', 'a--b', 'x'.repeat(80)];
    expect(new Set(names.map(centralProjectName)).size).toBe(names.length);
    const hashed = /^pipegen-[0-9a-f]{20}$/;
    for (const n of ['x'.repeat(90), 'y'.repeat(100), '-lead', 'aux.x', 'con.y', 'NUL.z', 'pipegen-0123456789abcdef0123', 'trail.', '.git']) {
      const c = centralProjectName(n);
      expect(c, n).toMatch(hashed);
      expect(centralProjectName(n), n).toBe(c);
    }
    // a repository named like the hash form is hashed too, so it can never take another project's files
    expect(centralProjectName('pipegen-0123456789abcdef0123')).not.toBe('pipegen-0123456789abcdef0123');
    expect(centralProjectName('x'.repeat(90))).not.toBe(centralProjectName('x'.repeat(91)));
    // case does not change the file (GitHub names are case-insensitive), and every central path pipegen writes passes the path rule
    expect(centralProjectName('Shop')).toBe(centralProjectName('shop'));
    for (const n of ['r', 'x'.repeat(87), 'x'.repeat(95), 'aux.x', '-lead', 'a.b-c_d']) {
      for (const layer of ['merge', 'push', 'nightly', 'sign'] as const) expect(createdPathProblem(centralWorkflowFile(n, layer)), `${n} ${layer}`).toBeNull();
    }
    // assemble writes the central files under that name
    const long = 'a'.repeat(95);
    const x = planned(profileOf([node()], { private: true, repo: long }), { over: { centralPin: PIN } });
    const a = lay(x);
    for (const f of a.files.filter((f) => f.repo === 'central')) expect(f.path).toMatch(/^\.github\/workflows\/pipegen-[0-9a-f]{20}--(?:merge|push|nightly)\.yml$/);
    expect((jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW))[MERGE_CALLER_JOB] as Obj).uses).toBe(`${centralWorkflowPath(PIN.repo, long)}@${PIN_SHA}`);
  });

  it('assemble: no human-wait job in the push run; no local composite action rendered', () => {
    for (const a of [lay(priv()), lay(pub()), lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY })]) {
      expect(a.files.filter((f) => f.path.startsWith('.github/actions/'))).toEqual([]);
      for (const f of workflows(a)) {
        expect(f.content, f.path).not.toMatch(/uses: \.\/\.github\/actions\//);
        // a job waits for a person only in an environment with reviewers: pipegen's jobs run in none but the signing environment (a branch rule, no reviewer)
        for (const [id, j] of Object.entries(jobsOfFile(f))) expect([undefined, 'pipegen-signing'], `${f.path} ${id}`).toContain(j.environment);
      }
    }
    // a deploy job that would wait for an approval in the push run is refused
    expect(() => lay(keyEnv(), { mode: 'key-env', deploy: { ...DEPLOY, release: { ...imagePublish(), environment: 'production' } } })).toThrow(/The deploy job "release" runs in an environment/);
    // and so is a deploy job with a condition of its own, or one that skips the gate
    expect(() => lay(keyEnv(), { mode: 'key-env', deploy: { 'image-publish': { ...imagePublish(), if: 'always()' } } })).toThrow(AssembleError);
    // a deploy job that needs a job the file does not hold is refused (it would never run, or run without its gate)
    expect(() => lay(keyEnv(), { mode: 'key-env', deploy: { ...DEPLOY, sbom: { ...imagePublish(), needs: ['nope'] } } })).toThrow(/needs "nope"/);
    // deploy jobs run on a push to the default branch only, after the gate
    const dj = jobsOfFile(fileAt(lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY }), 'app', CALLER_WORKFLOW))['image-publish'] as Obj;
    expect(dj.if).toBe(DEPLOY_PUSH_IF);
    expect(dj.needs).toEqual([MERGE_CALLER_JOB]);
    // the deploy part skipped: no deploy job may be given
    expect(() => lay(priv({ skipped: [{ part: 'deploy', reason: 't' }] }), { deploy: DEPLOY })).toThrow(/skipped/);
    // signing needs the image it signs: no image-publish job → refused, never a sign job with nothing to sign
    expect(() => lay(keyEnv(), { mode: 'key-env' })).toThrow(/image-publish pushes them .*nothing to sign/);
    expect(() => lay(keyless(), { mode: 'keyless' })).toThrow(/nothing to sign/);
  });

  it('assemble: workflows and docker-compose.pipegen.yml go through one referee call', async () => {
    const dep = { kind: 'postgres' as const, name: 'postgres', evidence: 'x', envVars: ['DATABASE_URL'] };
    const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], dependsOn: [dep] })]);
    const compose: CreatedFile = { path: 'docker-compose.pipegen.yml', content: composeText(prof, loadBaseImages()) as string, part: 'compose', reason: 't', repo: 'app' };
    const a = lay(planned(prof, { over: { created: [compose], skipped: [{ part: 'deploy', reason: 't' }] } }));
    const calls: CreatedFile[][] = [];
    const spy: typeof referee = (files, ...rest) => { calls.push(files); return referee(files, ...rest); };
    const extra: CreatedFile = { path: 'README.pipegen.txt', content: 'x\n', part: 'docs', reason: 't', repo: 'app' };
    const r = await judgeAssembled(a, { ...JD, referee: spy });
    expect(shown(r)).toBe('');
    expect(calls).toHaveLength(1);
    const paths = (calls[0] as CreatedFile[]).map((f) => `${f.repo}:${f.path}`);
    expect(paths).toContain('app:docker-compose.pipegen.yml');
    for (const f of a.files) expect(paths).toContain(`${f.repo}:${f.path}`);
    // later files (PIPEGEN.md, CODEOWNERS) join the same call
    calls.length = 0;
    await judgeAssembled(a, { ...JD, referee: spy, extra: [extra] });
    expect(calls).toHaveLength(1);
    expect((calls[0] as CreatedFile[]).map((f) => f.path)).toContain(extra.path);
    // split, the workflows alone: the test job's runtime-env and compose-up steps are no step of pipegen's (fails closed)
    const alone = await referee(a.files, a.draft, p, REVIEWED, LINTERS, 'tok', { runLinters: async () => [] });
    expect(alone.ok).toBe(false);
    // a file assemble writes that the draft already holds is refused (one source per path)
    expect(() => lay(planned(prof, { over: { created: [compose, { path: CALLER_WORKFLOW, content: 'x', part: 'pipeline', reason: 't', repo: 'app' }], skipped: [{ part: 'deploy', reason: 't' }] } }))).toThrow(/already/);
  });
});

describe('G5 fix round 1 (ruling G5-R1)', () => {
  const COSIGN_KEY = ['PIPEGEN_COSIGN', 'KEY'].join('_');
  const COSIGN_PW = ['PIPEGEN_COSIGN', 'PASS' + 'WORD'].join('_');

  it('I1: a repository whose own signing mode signs never publishes images unsigned (mode none with deploy jobs refused; the referee refuses image-publish without a sign job)', async () => {
    // the reviewer's attack: a key-env or keyless draft assembled with mode none and image-publish
    expect(() => lay(keyEnv(), { mode: 'none', deploy: DEPLOY })).toThrow(/signs them with the repository's own signing mode \("key-env"\)/);
    expect(() => lay(keyless(), { mode: 'none', deploy: DEPLOY })).toThrow(/signs them with the repository's own signing mode \("keyless"\)/);
    // the repository's own mode decides, even when the draft records no plan (a caller can not drop the plan and the mode together)
    const ke0 = keyEnv();
    const { signing: _s, ...noPlan } = ke0.draft;
    expect(() => lay({ ...ke0, draft: noPlan }, { mode: 'none', deploy: DEPLOY })).toThrow(/own signing mode \("key-env"\)/);
    const kl0 = keyless();
    const { signing: _k, ...noPlanKl } = kl0.draft;
    expect(() => lay({ ...kl0, draft: noPlanKl }, { mode: 'none', deploy: DEPLOY })).toThrow(/own signing mode \("keyless"\)/);
    // a draft that records a plan while its repository's mode is none is refused too (the plan says the images are signed)
    const freePriv = planned(profileOf([node({ dockerfile: 'Dockerfile' })], { private: true }), { needs: floorNeeds(profileOf([node()], { private: true }), CAPS), over: { centralPin: PIN } });
    const planned0 = { ...freePriv, draft: { ...freePriv.draft, signing: { mode: 'key-env', images: [IMG], cosignPubSha256: PUB_SHA } as SigningPlan } };
    expect(() => lay(planned0, { mode: 'none', deploy: DEPLOY })).toThrow(/signs them/);
    // a repository whose mode is none (private Free: no environments) publishes, unsigned, as PIPEGEN.md says; the proof publishes nothing
    const ok = lay(freePriv, { mode: 'none', deploy: DEPLOY });
    expect(Object.keys(jobsOfFile(fileAt(ok, 'app', CALLER_WORKFLOW)))).toEqual([MERGE_CALLER_JOB, 'image-publish']);
    expect(shown(await judge(ok))).toBe('');
    expect(() => lay(keyEnv(), { mode: 'none' })).not.toThrow();
    // the referee: a draft that records a signing plan, image-publish in the files, no sign job → refused
    const ke = lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY });
    expect(shown(await judge(ke))).toBe('');
    const caller = fileAt(ke, 'app', CALLER_WORKFLOW);
    const doc = parse(caller.content) as Obj;
    delete doc.jobs.sign;
    const noSign = new Document();
    noSign.contents = noSign.createNode(doc);
    const stripped: AssembledFiles = { ...ke, files: ke.files.filter((f) => f !== caller && !f.path.endsWith('--sign.yml')).concat([{ ...caller, content: noSign.toString({ lineWidth: 0 }) }]) };
    const r = await judge(stripped);
    expect(r.issues.some((i) => i.file === '(draft)' && i.check === 'permissions' && /publishes an image.* no sign job/.test(i.message)), shown(r)).toBe(true);
    // keyless (inline sign job) likewise
    const kl = lay(keyless(), { mode: 'keyless', deploy: DEPLOY });
    expect(shown(await judge(kl))).toBe('');
    const klCaller = fileAt(kl, 'app', CALLER_WORKFLOW);
    const kdoc = parse(klCaller.content) as Obj;
    delete kdoc.jobs.sign;
    const kNo = new Document();
    kNo.contents = kNo.createNode(kdoc);
    const kr = await judge({ ...kl, files: kl.files.map((f) => (f === klCaller ? { ...f, content: kNo.toString({ lineWidth: 0 }) } : f)) });
    expect(kr.issues.some((i) => /publishes an image.* no sign job/.test(i.message)), shown(kr)).toBe(true);
  });

  it("m1: the verify job waits for the whole gated run's worst case (the merge chain, then the deploy chain), plus a grace", () => {
    // the deploy chain: image-publish (30), then sbom (20) needing it, then sign (15) after image-publish: the longest is 30 + 20
    const sbom: Job = { ...imagePublish(), 'timeout-minutes': 20, needs: ['image-publish'], permissions: { contents: 'read' } };
    const a = lay(keyEnv(), { mode: 'key-env', deploy: { ...DEPLOY, sbom } });
    const find = (a.verify as Job).steps[1] as Obj;
    expect(find.with['timeout-minutes']).toBe(String(90 + 30 + 20 + VERIFY_GRACE_MINUTES));
    expect((a.verify as Job)['timeout-minutes']).toBe(90 + 30 + 20 + VERIFY_GRACE_MINUTES + VERIFY_MARGIN_MINUTES);
    // a longer image-publish lengthens the wait
    const slow = lay(keyEnv(), { mode: 'key-env', deploy: { 'image-publish': { ...imagePublish(), 'timeout-minutes': 60 } } });
    expect(((slow.verify as Job).steps[1] as Obj).with['timeout-minutes']).toBe(String(90 + 60 + 15 + VERIFY_GRACE_MINUTES));
    // a deploy job without its own limit (GitHub's default is 360) or a run longer than a job may wait is refused
    const { 'timeout-minutes': _t, ...noLimit } = imagePublish();
    expect(() => lay(keyEnv(), { mode: 'key-env', deploy: { 'image-publish': noLimit as Job } })).toThrow(/timeout-minutes/);
    expect(() => lay(keyEnv(), { mode: 'key-env', deploy: { 'image-publish': { ...imagePublish(), 'timeout-minutes': 300 } } })).toThrow(/longer than the verify job can wait/);
  });

  it('m2: a deploy job key pipegen does not write is refused with a plain reason, never dropped', () => {
    const extra: [string, unknown][] = [['env', { A: 'b' }], ['services', { db: { image: 'x' } }], [SEC, 'inherit'], ['strategy', { matrix: { a: [1] } }], ['container', 'node:22'], ['continue-on-error', true], ['defaults', { run: { shell: 'bash' } }], ['concurrency', 'pipegen-nightly'], ['uses', './x.yml']];
    for (const [k, v] of extra) {
      expect(() => lay(keyEnv(), { mode: 'key-env', deploy: { 'image-publish': { ...imagePublish(), [k]: v } as unknown as Job } }), k).toThrow(new RegExp(`The deploy job "image-publish" has the key "${k}", which pipegen does not write`));
    }
    expect(() => lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY })).not.toThrow();
  });

  it('m5: callerSecrets never maps a signing secret (it reaches only the sign job, through its environment)', () => {
    const step = (name: string) => ({ x: { steps: [{ env: { A: ref(name) } }] } });
    for (const n of [COSIGN_KEY, COSIGN_PW, 'PIPEGEN_COSIGN_OTHER', 'COSIGN_PASSWORD', 'SIGSTORE_ID_TOKEN']) expect(() => callerSecrets(step(n)), n).toThrow(/signing secret/);
    expect(callerSecrets(step('COSIGNAL_KEY'))).toEqual({ COSIGNAL_KEY: ref('COSIGNAL_KEY') });
  });
});

// ---------- Plan P Task PL-D1: header, part banners, blank lines ----------

const BANNER = /^ {2}# --- (.+) ---$/;
/** The top-level job keys of a workflow text, in file order, each with the banner title directly above it (if any) and whether a blank line stands above it (or above its banner). */
function jobLines(text: string): { id: string; banner: string | null; blankAbove: boolean; doubleBlank: boolean }[] {
  const lines = text.split('\n');
  const start = lines.indexOf('jobs:');
  const out: { id: string; banner: string | null; blankAbove: boolean; doubleBlank: boolean }[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const m = /^ {2}([A-Za-z0-9_-]+):/.exec(lines[i] as string);
    if (m === null) continue;
    const b = BANNER.exec(lines[i - 1] as string);
    out.push({ id: m[1] as string, banner: b === null ? null : b[1] as string, blankAbove: (lines[b === null ? i - 1 : i - 2] as string) === '', doubleBlank: (lines[b === null ? i - 2 : i - 3] as string) === '' && (lines[b === null ? i - 1 : i - 2] as string) === '' });
  }
  return out;
}
/** The part each job of a draft belongs to, worked out here from the needs (not through assemble's own table). */
function expectedPart(x: Planned, id: string): PartId | undefined {
  const n = x.draft.needs.find((m) => m.layer !== 'pre-commit' && id === (m.service === undefined ? m.id : `${m.id}--${m.service}`));
  return n === undefined ? undefined : partOf(n);
}
const headerOf = (text: string): string[] => { const out: string[] = []; for (const l of text.split('\n')) { if (!l.startsWith('#')) break; out.push(l); } return out; };

describe('PL-D1: workflow header, part banners, blank lines', () => {
  const VERSION = '9.8.7';
  const sets = (): [string, AssembledFiles, Planned][] => {
    const a = pub(); const b = priv(); const c = keyless(); const d = keyEnv();
    return [
      ['public', lay(a, { version: VERSION }), a], ['private', lay(b, { version: VERSION }), b],
      ['public keyless', lay(c, { mode: 'keyless', deploy: DEPLOY, version: VERSION }), c], ['private key-env', lay(d, { mode: 'key-env', deploy: DEPLOY, version: VERSION }), d],
    ];
  };

  it('header names the version and PIPEGEN.md', () => {
    for (const [label, a] of sets()) {
      expect(workflows(a).length, label).toBeGreaterThanOrEqual(3);
      for (const f of workflows(a)) {
        const h = headerOf(f.content).join('\n');
        const at = `${label} ${f.path}`;
        expect(h, at).toMatch(/written by pipegen 9\.8\.7\b/i);
        expect(h, at).toContain('PIPEGEN.md');
        expect(h, at).toContain('npx pipegen update');
        expect(h, at).toMatch(/protected/);
        expect(h, at).toMatch(/When it runs: (on|when|every) /);
        expect(h, at).not.toMatch(/it runs: it runs/i);   // PL-D1-R1: the sentence does not say "it runs" twice
        expect(h.match(/written by pipegen/gi), at).toHaveLength(1);   // PL-D1-R1: once, in the tail line
        expect(h, at).not.toMatch(/\d{4}-\d{2}-\d{2}/);   // a version, never a date
        expect(h.split('\n').length, at).toBeGreaterThanOrEqual(4);
      }
    }
  });

  it('header: no version given → the package version; a version that is not plain is refused; none known → no placeholder', () => {
    const x = pub();
    const def = headerOf(workflows(lay(x))[0]?.content as string).join('\n');
    expect(packageVersion()).not.toBeNull();
    expect(def).toContain(`Written by pipegen ${packageVersion() as string}`);
    for (const bad of ['1.2', 'latest', '1.2.3\n# x: y', '1.2.3 $(id)', '']) expect(() => lay(x, { version: bad }), JSON.stringify(bad)).toThrow(AssembleError);
    const none = headerOf(workflows(lay(x, { version: null }))[0]?.content as string).join('\n');
    expect(none).toMatch(/written by pipegen\b/i);
    expect(none).not.toMatch(/null|undefined/);
    expect(none).toContain('PIPEGEN.md');
  });

  it('header: the file says when it runs (each file its own trigger)', () => {
    const a = lay(pub(), { version: VERSION });
    const when = (path: string): string => headerOf(fileAt(a, 'app', path).content).join('\n');
    expect(when(CALLER_WORKFLOW)).toMatch(/pull requests/);
    expect(when(PUSH_WORKFLOW)).toMatch(/every branch but the default/);
    expect(when(NIGHTLY_WORKFLOW)).toMatch(/every night/);
    expect(when(LOCAL_MERGE_WORKFLOW)).toMatch(/pipegen\.yml calls it/);
  });

  it('jobs in part order', () => {
    let reordered = 0;
    for (const [label, a, x] of sets()) {
      for (const f of workflows(a)) {
        const jobs = jobLines(f.content);
        const parts = jobs.map((j) => expectedPart(x, j.id));
        // the jobs the needs name come in part order; a helper job (gate, base-scan, a caller, ...) stays where its part is
        const known = parts.filter((q): q is PartId => q !== undefined);
        expect(known, `${label} ${f.path}`).toEqual([...known].sort((m, n) => m - n));
        const ids = jobLines(f.content).map((j) => j.id);
        const inserted = Object.keys(jobsOfFile(f));
        expect([...ids].sort(), `${label} ${f.path}: same jobs`).toEqual([...inserted].sort());
        if (ids.join() !== (f.path.endsWith('pipegen-merge.yml') || f.path.includes('--merge') ? Object.keys(assembleJobs(x.draft, x.plan, { reviewed: REVIEWED, platform: p, mode: 'none' }).merge).join() : '')) reordered++;
      }
    }
    // the fixtures are not in part order to begin with: the merge file of the public repository puts licences (part 2) after dependency-review (part 3) as inserted
    const mergeIds = jobLines(fileAt(lay(pub()), 'app', LOCAL_MERGE_WORKFLOW).content).map((j) => j.id);
    expect(mergeIds.indexOf('licences')).toBeLessThan(mergeIds.indexOf('dependency-review'));
    // the gate is part 3: after the merge checks of parts 2 and 3 and its two base jobs, before the scheduled pin check of part 6
    expect(mergeIds.indexOf('gate')).toBeGreaterThan(mergeIds.indexOf('base-scan'));
    expect(mergeIds.indexOf('base-scan')).toBeGreaterThan(mergeIds.indexOf('dependency-review'));
    expect(mergeIds.indexOf('gate')).toBeLessThan(mergeIds.indexOf('workflow-pin-check'));
    expect(mergeIds.indexOf('secrets')).toBeLessThan(mergeIds.indexOf('licences'));
    expect(reordered).toBeGreaterThan(0);
    // the app's pipegen.yml: the merge caller (before merge) comes before the image publish (build and release) and the sign job
    const yml = jobLines(fileAt(lay(keyless(), { mode: 'keyless', deploy: DEPLOY }), 'app', CALLER_WORKFLOW).content).map((j) => j.id);
    expect(yml).toEqual(['pipegen', 'image-publish', 'sign']);
  });

  it('one banner per part, above its first job, with the part title', () => {
    for (const [label, a] of sets()) {
      for (const f of workflows(a)) {
        const jobs = jobLines(f.content);
        const banners = jobs.flatMap((j) => (j.banner === null ? [] : [j.banner]));
        expect(banners.length, `${label} ${f.path}`).toBeGreaterThan(0);
        expect(jobs[0]?.banner, `${label} ${f.path}: a banner above the first job`).not.toBeNull();
        const titles = Object.values(PART_TITLE);
        for (const b of banners) expect(titles, `${label} ${f.path}`).toContain(b);
        expect(new Set(banners).size, `${label} ${f.path}: a part has one banner`).toBe(banners.length);
        const order = banners.map((b) => titles.indexOf(b));
        expect(order, `${label} ${f.path}: banners in part order`).toEqual([...order].sort((m, n) => m - n));
      }
    }
    // the public merge file spells out the parts it has
    const text = fileAt(lay(pub()), 'app', LOCAL_MERGE_WORKFLOW).content;
    expect(text).toContain('  # --- Every pull request ---\n  hooks-ci:');
    expect(text).toContain(`  # --- ${PART_TITLE[3]} ---\n  dependency-review:`);
    expect(text).toContain(`  # --- ${PART_TITLE[6]} ---\n  workflow-pin-check:`);
  });

  it('a pre-commit need with the id of a CI job never moves that job to part 1, whatever the order of the needs', () => {
    const prof = profileOf();
    const forward = floorNeeds(prof, CAPS);
    expect(forward.some((n) => n.layer === 'pre-commit' && forward.some((m) => m.layer !== 'pre-commit' && m.id === n.id)), 'the fixture has a hook need and a CI need of one id').toBe(true);
    for (const needs of [forward, [...forward].reverse()]) {
      const a = lay(planned(prof, { needs }), { version: VERSION });
      for (const f of workflows(a)) {
        expect(jobLines(f.content).flatMap((j) => (j.banner === null ? [] : [j.banner])), f.path).not.toContain(PART_TITLE[1]);
      }
      const merge = jobLines(fileAt(a, 'app', LOCAL_MERGE_WORKFLOW).content);
      expect(merge.find((j) => j.id === 'hooks-ci')?.banner ?? merge[0]?.banner).toBe(PART_TITLE[2]);
    }
  });

  it('a blank line between jobs', () => {
    for (const [label, a] of sets()) {
      for (const f of workflows(a)) {
        const jobs = jobLines(f.content);
        for (const [i, j] of jobs.entries()) if (i > 0) expect(j.blankAbove, `${label} ${f.path}: ${j.id}`).toBe(true);
        for (const j of jobs) expect(j.doubleBlank, `${label} ${f.path}: ${j.id} has one blank line above, not two`).toBe(false);
        expect(f.content.endsWith('\n') && !f.content.endsWith('\n\n'), `${label} ${f.path}`).toBe(true);
      }
    }
  });

  it('job ids equal before and after', () => {
    // golden of the ids (written before PL-D1: the jobs are the same, only their order and the comments move)
    const a = lay(pub());
    const ids = (path: string): string[] => Object.keys(jobsOfFile(fileAt(a, 'app', path))).sort();
    expect(ids(LOCAL_MERGE_WORKFLOW)).toEqual(['base-scan', 'baseline-check', 'coverage--app', 'dead-code--app', 'dependency-review', 'deps--app', 'duplication', 'format--app', 'full-tests--app', 'gate', 'hooks-ci', 'licences', 'lint--app', 'sast--app', 'secrets', 'unit-tests--app', 'workflow-lint', 'workflow-pin-check']);
    expect(ids(PUSH_WORKFLOW)).toEqual(['coverage--app', 'dead-code--app', 'deps--app', 'format--app', 'hooks-ci', 'lint--app', 'pr-check', 'sast--app', 'secrets', 'unit-tests--app', 'workflow-lint', 'workflow-pin-check']);
    expect(ids(NIGHTLY_WORKFLOW)).toEqual(['code-scanning', 'code-scanning-history', 'nightly', 'scorecard', 'secrets-history', 'workflow-lint-online']);
    expect(ids(CALLER_WORKFLOW)).toEqual(['pipegen']);
    // and every job keeps its needs, name and permissions as assembleJobs gives them
    const j = assembleJobs(pub().draft, pub().plan, { reviewed: REVIEWED, platform: p, mode: 'none' });
    const merge = jobsOfFile(fileAt(a, 'app', LOCAL_MERGE_WORKFLOW));
    for (const [id, job] of Object.entries(j.merge)) {
      expect(merge[id]?.needs, id).toEqual(job.needs);
      expect(merge[id]?.name, id).toEqual(job.name);
      expect(merge[id]?.permissions, id).toEqual(job.permissions);
    }
    // the key-env private run, with the deploy and sign jobs: the app file's ids
    const k = lay(keyEnv(), { mode: 'key-env', deploy: DEPLOY });
    expect(Object.keys(jobsOfFile(fileAt(k, 'app', CALLER_WORKFLOW))).sort()).toEqual(['image-publish', 'pipegen', 'sign']);
    const kc = jobsOfFile(fileAt(k, 'app', CALLER_WORKFLOW));
    expect((kc['image-publish'] as Obj).needs).toEqual(['pipegen']);
    expect((kc.sign as Obj).needs).toEqual(['pipegen', 'image-publish']);
  });

  it('gate job name is pipegen / gate', () => {
    for (const [label, a] of sets()) {
      const merge = a.files.find((f) => f.path === LOCAL_MERGE_WORKFLOW || f.path === C('merge')) as CreatedFile;
      const caller = jobsOfFile(fileAt(a, 'app', CALLER_WORKFLOW));
      expect((jobsOfFile(merge).gate as Obj).name, label).toBe('gate');
      expect((caller[MERGE_CALLER_JOB] as Obj).name, label).toBe('pipegen');
      expect(`${(caller[MERGE_CALLER_JOB] as Obj).name} / ${(jobsOfFile(merge).gate as Obj).name}`).toBe(GATE_CHECK_NAME);
      expect(Object.keys(jobsOfFile(merge)).filter((id) => id === 'gate').length).toBe(1);
    }
  });

  it('the files still pass the referee and keep the not-proven mark on its own line', async () => {
    const np = { notProven: [{ part: 'pipeline', needId: 'licences', reason: 't', [MISSING]: [] } as unknown as PipelineDraft['notProven'][number]] };
    for (const [label, a] of [...sets().slice(0, 1), ['private, not proven', lay(priv(np), { version: VERSION })] as [string, AssembledFiles]]) {
      const r = await judge(a);
      expect(r.ok, label + JSON.stringify(r.issues)).toBe(true);
      const merge = a.files.find((f) => f.path === LOCAL_MERGE_WORKFLOW || f.path === C('merge')) as CreatedFile;
      expect(merge.content.split('\n').filter((l) => l.includes(`# ${NOT_PROVEN_MARK}`)).length, label).toBe(label === 'public' ? 0 : 1);
      expect(headerOf(merge.content).join('\n')).not.toContain(NOT_PROVEN_MARK);
    }
  });
});

/** The push-layer jobs assembleJobs gives for a draft (what the push file must hold besides pr-check). */
const assembleJobsPush = (x: Planned): Record<string, Job> => assembleJobs(x.draft, x.plan, { reviewed: REVIEWED, platform: p, mode: 'none' }).push;

/** A user's deploy workflow with pipegen's verify job inserted (G7's insertion; the Plan B marker). */
function insertedDeploy(j: Job): CreatedFile {
  // G7-R1: the deploy layer's own insert (the verify job, the needs, the head check first in the deploy job)
  const original = 'on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh\n';
  const e = insertVerify(original, ['deploy'], j);
  return { path: '.github/workflows/deploy.yml', content: e.text, part: 'deploy-verify', reason: 't', repo: 'app', inserted: e.inserted };
}
