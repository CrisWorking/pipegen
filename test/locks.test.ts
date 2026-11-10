// v0.2 Plan G Task 5 (sub-task G8; rulings S9, S10, S13; carries S-1, S-2, C8, G42, D0b-2, D0b-r1, D1-r1, D1-r2): the locks pipegen plans
// for the default branch (two rulesets, or classic protection), the central repo's ruleset and CODEOWNERS, the org required workflow, the
// sha-pinning setting and the app's CODEOWNERS block. planLocks is pure: it returns the exact API requests, which finish (G11) sends.
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { centralWorkflowFile } from '../src/engine/central-path.js';
import { CENTRAL_PROTECTED_PATHS, codeownersBlock, codeownersFile, codeownersProtectedPaths, codeownersReplace } from '../src/engine/created-builders.js';
import { createdFileProblems, type CreatedEnv } from '../src/engine/created-files.js';
import { assemble, judgeAssembled, MERGE_CALLER_JOB } from '../src/layers/assemble.js';
import { CENTRAL_RULESET, GATE_RULESET, LockError, planLocks, REVIEWS_RULESET, type ApiRequest, type LockInputs, type LockPlan } from '../src/layers/locks.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { GATE_CHECK_INTEGRATION_ID, GATE_CHECK_NAME, type CreatedFile, type PipelineDraft, type RepoProfile, type ReviewedTool } from '../src/types.js';
import { CAPS, LINTERS, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const SHA = 'c'.repeat(40);
const OWNERS = ['@alice', '@bob'];
const GATE = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const orgPriv = (over: Partial<RepoProfile> = {}): RepoProfile => profileOf([node()], { private: true, ownerType: 'Organization', plan: 'team', ...over });
const noCo = { path: null, original: '', isSymlink: false, inserted: null };

function inputs(over: Partial<LockInputs> = {}): LockInputs {
  const profile = over.profile ?? orgPriv();
  const draft = { profile, gateSettings: undefined } as unknown as PipelineDraft;
  return {
    profile, caps: CAPS,
    central: { repo: 'o/pipelines', sha: SHA, branchProtection: true, codeowners: noCo },
    writers: { app: ['alice', 'bob'], central: ['alice', 'bob'] },
    owners: OWNERS, orgAdmin: false, shaPinning: { state: 'absent' },
    protectedPaths: codeownersProtectedPaths(draft, REVIEWED), appCodeowners: { original: '', isSymlink: false, inserted: null },
    files: [],
    ...over,
  };
}
const rule = (r: ApiRequest | undefined, type: string): Obj => {
  const found = ((r?.body.rules ?? []) as Obj[]).find((x) => x.type === type);
  expect(found, `${type} in ${JSON.stringify(r?.body.rules)}`).toBeDefined();
  return found as Obj;
};
const prRule = (r: ApiRequest | undefined): Obj => rule(r, 'pull_request').parameters as Obj;
const allRulesets = (plan: LockPlan): ApiRequest[] => [plan.rulesets?.gate, plan.rulesets?.reviews, plan.centralRuleset, plan.orgRequiredWorkflow?.rule].filter((x): x is ApiRequest => x !== undefined);
/** The private org app assembled by G5 (its files hold the merge caller the required workflow reuses). */
function assembledPrivate() {
  const x = planned(orgPriv(), { over: { centralPin: { repo: 'o/pipelines', sha: SHA } } });
  return { x, a: assemble(x.draft, { gate: GATE, reviewed: REVIEWED, platform: p, mode: 'none', layout: 'central', plan: x.plan }) };
}
/** A user workflow with `n` actions used by tag (the secret-name list's key is spelled at run time: test/no-secret-literals.test.ts). */
const tagPinnedWorkflow = (n: number): RepoProfile['existingWorkflows'][number] =>
  Object.assign({ path: '.github/workflows/ci.yml', triggers: ['push'], deploys: false, jobs: ['b'], tagPinned: n }, Object.fromEntries([['secrets' + 'Used', []]])) as unknown as RepoProfile['existingWorkflows'][number];
const envOf = (inputs: CreatedEnv['inputs']): CreatedEnv => ({ reviewed: REVIEWED, inputs });

describe('G8: merge locks, central locks, required workflow, CODEOWNERS', () => {
  it('locks: required check bound to GATE_CHECK_INTEGRATION_ID', () => {
    const plan = planLocks(inputs());
    const gate = plan.rulesets?.gate as ApiRequest;
    expect(gate.method).toBe('POST');
    expect(gate.route).toBe('/repos/{owner}/{repo}/rulesets');
    expect(gate.params).toEqual({ owner: 'o', repo: 'r' });
    const checks = (rule(gate, 'required_status_checks').parameters as Obj).required_status_checks;
    // bound to the GitHub Actions app: a commit status posted through the API under the same context does not satisfy it (Review Focus 6)
    expect(checks).toEqual([{ context: GATE_CHECK_NAME, integration_id: GATE_CHECK_INTEGRATION_ID }]);
    expect(GATE_CHECK_INTEGRATION_ID).toBe(15368);
    // whatever the writers and owners, the binding never changes
    for (const over of [{ writers: { app: ['alice'], central: ['alice'] }, owners: ['@alice'] }, { writers: { app: ['alice', 'bob', 'carol'], central: ['alice'] }, owners: ['@alice'] }]) {
      expect((rule(planLocks(inputs(over)).rulesets?.gate, 'required_status_checks').parameters as Obj).required_status_checks).toEqual([{ context: GATE_CHECK_NAME, integration_id: 15368 }]);
    }
  });

  it('locks: ruleset uses GATE_CHECK_NAME, codeowner review with ≥ 2 writers', () => {
    const plan = planLocks(inputs());
    const gate = plan.rulesets?.gate as ApiRequest;
    expect(gate.body).toMatchObject({ target: 'branch', enforcement: 'active', conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } } });
    expect((rule(gate, 'required_status_checks').parameters as Obj).required_status_checks[0].context).toBe(GATE_CHECK_NAME);
    expect((rule(gate, 'required_status_checks').parameters as Obj).strict_required_status_checks_policy).toBe(false);
    rule(gate, 'deletion'); rule(gate, 'non_fast_forward');
    expect(prRule(plan.rulesets?.reviews)).toMatchObject({ required_approving_review_count: 1, require_code_owner_review: true });
    expect(plan.codeOwners).toEqual({ owners: OWNERS, writers: 2 });
    expect(plan.owners).toEqual({ app: OWNERS, central: OWNERS });
    expect(plan.writers).toEqual({ app: ['alice', 'bob'], central: ['alice', 'bob'] });
    // logins are matched as GitHub does (case-insensitive); the owners keep the spelling the user picked
    expect(planLocks(inputs({ writers: { app: ['Alice', 'BOB'], central: ['alice', 'Bob'] } })).codeOwners?.owners).toEqual(OWNERS);
  });

  it('locks: dismiss_stale_reviews_on_push and require_last_push_approval set', () => {
    const plan = planLocks(inputs());
    expect(prRule(plan.rulesets?.reviews)).toMatchObject({ dismiss_stale_reviews_on_push: true, require_last_push_approval: true });
    expect(prRule(plan.centralRuleset)).toMatchObject({ dismiss_stale_reviews_on_push: true, require_last_push_approval: true });
    expect((plan.classic?.body.required_pull_request_reviews as Obj)).toMatchObject({ dismiss_stale_reviews: true, require_last_push_approval: true });
    // also when the code-owner rule is off (fewer than two qualified owners): a second writer's approval is still dismissed on a new push
    const few = planLocks(inputs({ writers: { app: ['alice', 'bob'], central: ['alice'] }, owners: ['@alice'] }));
    expect(prRule(few.rulesets?.reviews)).toMatchObject({ required_approving_review_count: 1, dismiss_stale_reviews_on_push: true, require_last_push_approval: true });
  });

  // *replaces* (G42, S9): `locks: ≥ 2 writers but one code owner → admin role bypass in pull_request mode`
  it('locks: ≥ 2 writers needs ≥ 2 code owners with write on both repos, else no code-owner rule and a plain note; never a bypass', () => {
    // three can write to the app, but only alice can also write to the central repo: fewer than two qualify
    const few = planLocks(inputs({ writers: { app: ['alice', 'bob', 'carol'], central: ['alice'] }, owners: ['@alice'] }));
    expect(prRule(few.rulesets?.reviews).require_code_owner_review).toBe(false);
    expect(prRule(few.rulesets?.reviews).required_approving_review_count).toBe(1);
    expect((few.classic?.body.required_pull_request_reviews as Obj).require_code_owner_reviews).toBe(false);
    expect(few.codeowners).toBeUndefined();
    expect(few.centralCodeowners).toBeUndefined();
    expect(few.codeOwners).toBeUndefined();
    const note = few.notes.join('\n');
    expect(note).toMatch(/code-owner review/);
    expect(note).toContain('o/pipelines');
    expect(note).toMatch(/3 people can write/);
    // nobody qualifies with the app's two writers either
    expect(prRule(planLocks(inputs({ writers: { app: ['alice', 'bob'], central: ['carol'] }, owners: [] })).rulesets?.reviews).require_code_owner_review).toBe(false);
    // two qualify: the user must pick both (one owner could not approve their own pull request)
    expect(() => planLocks(inputs({ owners: ['@alice'] }))).toThrow(LockError);
    expect(() => planLocks(inputs({ owners: ['@alice'] }))).toThrow(/at least two/);
    // an owner who can't write to both repos is refused, never silently kept (GitHub ignores a code owner without write access)
    expect(() => planLocks(inputs({ writers: { app: ['alice', 'bob', 'carol'], central: ['alice', 'bob'] }, owners: ['@alice', '@carol'] }))).toThrow(/carol/);
    expect(() => planLocks(inputs({ writers: { app: ['alice'], central: ['alice', 'bob'] }, owners: ['@alice', '@bob'] }))).toThrow(/bob/);
    // never a bypass, for anyone, in any case
    const cases = [inputs(), inputs({ writers: { app: ['alice', 'bob', 'carol'], central: ['alice'] }, owners: ['@alice'] }), inputs({ writers: { app: ['alice'], central: ['alice'] }, owners: ['@alice'] }),
      inputs({ orgAdmin: true, ids: { app: 1, central: 2 }, files: assembledPrivate().a.files })];
    for (const i of cases) {
      const plan = planLocks(i);
      expect(allRulesets(plan).length).toBeGreaterThanOrEqual(3);
      for (const r of allRulesets(plan)) expect(r.body.bypass_actors, r.body.name as string).toEqual([]);
      expect(plan.classic?.body.enforce_admins).toBe(true);
      expect(JSON.stringify(plan)).not.toMatch(/bypass_mode|actor_type|RepositoryRole/);
    }
  });

  // *added* (controller ruling G8-R0)
  it('locks: every planned ruleset has an empty bypass_actors list in every mode', () => {
    const { a } = assembledPrivate();
    const modes: [string, Partial<LockInputs>][] = [
      ['two writers, two owners', {}],
      ['one writer', { writers: { app: ['alice'], central: ['alice'] }, owners: ['@alice'] }],
      ['three writers, one qualified owner', { writers: { app: ['alice', 'bob', 'carol'], central: ['alice'] }, owners: ['@alice'] }],
      ['no owner qualifies', { writers: { app: ['alice', 'bob'], central: ['carol'] }, owners: [] }],
      ['solo app, two central writers', { writers: { app: ['alice'], central: ['alice', 'bob'] }, owners: ['@alice'] }],
      ['org admin, required workflow', { orgAdmin: true, ids: { app: 1, central: 2 }, files: a.files }],
      ['public app', { profile: profileOf([node()], { ownerType: 'Organization', plan: 'team' }) }],
      ['personal pro', { profile: orgPriv({ ownerType: 'User', plan: 'pro' }) }],
      ['enterprise org admin', { profile: orgPriv({ plan: 'enterprise' }), orgAdmin: true, ids: { app: 1, central: 2 }, files: a.files }],
    ];
    for (const [mode, over] of modes) {
      const plan = planLocks(inputs(over));
      const rs = allRulesets(plan);
      expect(rs.length, mode).toBeGreaterThanOrEqual(3);
      for (const r of rs) {
        expect(Object.hasOwn(r.body, 'bypass_actors'), `${mode}: ${String(r.body.name)}`).toBe(true);
        expect(r.body.bypass_actors, `${mode}: ${String(r.body.name)}`).toEqual([]);
      }
      // classic protection: admins included, no restriction list that could name who may push past it
      expect(plan.classic?.body.enforce_admins, mode).toBe(true);
      expect(plan.classic?.body.restrictions, mode).toBeNull();
      expect(JSON.stringify(plan), mode).not.toMatch(/bypass_mode|actor_id|actor_type|bypass_pull_request_allowances/);
    }
    // the names Plan V reads are fixed
    expect([GATE_RULESET, REVIEWS_RULESET, CENTRAL_RULESET]).toEqual(['pipegen', 'pipegen-reviews', 'pipegen']);
  });

  it('locks: single writer → zero approvals, no codeowner review, note', () => {
    const plan = planLocks(inputs({ writers: { app: ['alice'], central: ['alice'] }, owners: ['@alice'] }));
    expect(prRule(plan.rulesets?.reviews)).toMatchObject({ required_approving_review_count: 0, require_code_owner_review: false, require_last_push_approval: false, dismiss_stale_reviews_on_push: true });
    expect(plan.classic?.body.required_pull_request_reviews).toMatchObject({ required_approving_review_count: 0, require_code_owner_reviews: false, require_last_push_approval: false });
    expect(prRule(plan.centralRuleset)).toMatchObject({ required_approving_review_count: 0, require_code_owner_review: false });
    // the required check stays
    expect((rule(plan.rulesets?.gate, 'required_status_checks').parameters as Obj).required_status_checks).toEqual([{ context: GATE_CHECK_NAME, integration_id: 15368 }]);
    // the remaining risk (T17) and pipegen verify, in plain words (Review Focus 1)
    const note = plan.notes.join('\n');
    expect(note).toMatch(/only one person can write/i);
    expect(note).toContain('npx pipegen verify');
    // the one owner still owns the protected paths (the gate reads the block)
    expect(plan.codeOwners).toEqual({ owners: ['@alice'], writers: 1 });
    expect(plan.codeowners?.file.content).toContain('/.github/workflows/ @alice');
  });

  it('locks: central ruleset and CODEOWNERS cover .github/workflows/** and installs/**', () => {
    const plan = planLocks(inputs());
    const c = plan.centralRuleset as ApiRequest;
    expect(c.route).toBe('/repos/{owner}/{repo}/rulesets');
    expect(c.params).toEqual({ owner: 'o', repo: 'pipelines' });
    expect(c.body).toMatchObject({ name: 'pipegen', target: 'branch', enforcement: 'active', bypass_actors: [], conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] } } });
    expect(prRule(c)).toMatchObject({ required_approving_review_count: 1, require_code_owner_review: true });
    rule(c, 'deletion'); rule(c, 'non_fast_forward');
    const file = plan.centralCodeowners?.file as CreatedFile;
    expect(file).toMatchObject({ path: '.github/CODEOWNERS', repo: 'central', part: 'codeowners', edited: { original: '' } });
    expect(file.content).toBe(codeownersBlock(CENTRAL_PROTECTED_PATHS, OWNERS));
    expect(file.content).toContain('/.github/workflows/ @alice @bob\n');
    expect(file.content).toContain('/installs/ @alice @bob\n');
    // the D0b central judge accepts exactly this file for the plan's owners
    const d = planned(orgPriv(), { over: { codeOwners: plan.codeOwners } }).draft;
    expect(createdFileProblems(file, d, undefined, envOf({ centralCodeowners: null, codeownersFacts: {} })).problems).toEqual([]);
    // the records-only central repo of a public app is locked the same way
    const pub = planLocks(inputs({ profile: profileOf([node()], { ownerType: 'Organization', plan: 'team' }) }));
    expect(pub.centralRuleset?.params).toEqual({ owner: 'o', repo: 'pipelines' });
    expect(pub.centralCodeowners?.file.content).toContain('/installs/ @alice @bob\n');
    // the central approvals follow the central repo's own writers (its second writer approves), the code-owner rule needs two owners
    const soloApp = planLocks(inputs({ writers: { app: ['alice'], central: ['alice', 'bob'] }, owners: ['@alice'] }));
    expect(prRule(soloApp.centralRuleset)).toMatchObject({ required_approving_review_count: 1, require_code_owner_review: false, require_last_push_approval: true });
    expect(prRule(soloApp.rulesets?.reviews)).toMatchObject({ required_approving_review_count: 0 });
  });

  it('locks: org admin on team, private app → required workflow pinned by sha, runs its own scans', async () => {
    const { x, a } = assembledPrivate();
    for (const plan of ['team', 'enterprise'] as const) {
      const lp = planLocks(inputs({ profile: orgPriv({ plan }), orgAdmin: true, ids: { app: 11, central: 22 }, files: a.files }));
      const rw = lp.orgRequiredWorkflow;
      expect(rw, plan).toBeDefined();
      const path = centralWorkflowFile('r', 'required');
      expect(rw?.rule.method).toBe('POST');
      expect(rw?.rule.route).toBe('/orgs/{org}/rulesets');
      expect(rw?.rule.params).toEqual({ org: 'o' });
      expect(rw?.rule.body).toMatchObject({ target: 'branch', enforcement: 'active', bypass_actors: [], conditions: { ref_name: { include: ['~DEFAULT_BRANCH'], exclude: [] }, repository_id: { repository_ids: [11] } } });
      // pinned by the central commit's sha, never by a branch or a tag
      expect(rule(rw?.rule, 'workflows').parameters).toEqual({ do_not_enforce_on_create: false, workflows: [{ path, repository_id: 22, sha: SHA }] });
      expect(JSON.stringify(rw?.rule)).not.toMatch(/"ref"/);
      // the file: a central workflow on pull requests that calls the merge workflow (every check and the gate) at the same commit
      expect(rw?.file).toMatchObject({ path, repo: 'central', part: 'pipeline' });
      const wf = parse(rw?.file.content as string) as Obj;
      expect(Object.keys(wf.on)).toEqual(['pull_request']);
      expect(wf.permissions).toEqual({});
      const jobs = Object.values(wf.jobs) as Obj[];
      expect(jobs.length).toBe(1);
      const caller = (parse((a.files.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile).content) as Obj).jobs[MERGE_CALLER_JOB] as Obj;
      expect(jobs[0]?.uses).toBe(`o/pipelines/${centralWorkflowFile('r', 'merge')}@${SHA}`);
      expect(jobs[0]?.permissions).toEqual(caller.permissions);
      expect(jobs[0]?.secrets).toEqual(caller.secrets);
      expect(jobs[0]?.name).not.toBe('pipegen');
      // its own scans: the called merge workflow holds the floor scanners and the gate, which reads only that run's results
      const merge = parse((a.files.find((f) => f.repo === 'central' && f.path === centralWorkflowFile('r', 'merge')) as CreatedFile).content) as Obj;
      const ids = Object.keys(merge.jobs);
      expect(ids).toContain('gate');
      for (const floor of ['secrets', 'sast', 'deps']) expect(ids.some((id) => id === floor || id.startsWith(`${floor}--`)), `${floor} in ${ids.join(',')}`).toBe(true);
    }
    // the referee judges it with the other delivered files
    const lp = planLocks(inputs({ orgAdmin: true, ids: { app: 11, central: 22 }, files: a.files }));
    const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
    expect(shown(await judgeAssembled(a, { ...JD, extra: [lp.orgRequiredWorkflow?.file as CreatedFile] }))).toBe('');
    void x;
    // the referee holds the required workflow to its one form: another trigger, a filter, a second job, another commit or file is refused
    const rf = lp.orgRequiredWorkflow?.file as CreatedFile;
    const pin = `@${SHA}`;
    for (const [what, content] of [
      ['push trigger', rf.content.replace('pull_request: null', 'pull_request: null\n  push: null')],
      ['filtered pull_request', rf.content.replace('pull_request: null', 'pull_request:\n    branches: [main]')],
      ['workflow_dispatch', rf.content.replace('pull_request: null', 'workflow_dispatch: null')],
      ['another commit', rf.content.replace(pin, `@${'d'.repeat(40)}`)],
      ['another central file', rf.content.replace('r--merge.yml', 'r--push.yml')],
      ['another project\'s merge workflow', rf.content.replace('r--merge.yml', 'other--merge.yml')],
      ['the nightly workflow', rf.content.replace('r--merge.yml', 'r--nightly.yml')],
      ['a second job', `${rf.content}  extra:\n    uses: o/pipelines/${centralWorkflowFile('r', 'merge')}${pin}\n    permissions: {}\n`],
    ] as const) {
      expect(content, what).not.toBe(rf.content);
      expect(shown(await judgeAssembled(a, { ...JD, extra: [{ ...rf, content }] })), what).not.toBe('');
    }
    // the form is accepted only at the project's own required path in the central repo
    expect(shown(await judgeAssembled(a, { ...JD, extra: [{ ...rf, path: centralWorkflowFile('other', 'required') }] }))).not.toBe('');
    // without the repository ids GitHub's rule needs: not planned, said plainly
    const noIds = planLocks(inputs({ orgAdmin: true, files: a.files }));
    expect(noIds.orgRequiredWorkflow).toBeUndefined();
    expect(noIds.notes.join('\n')).toMatch(/required workflow/);
    // a merge caller that is not at the recorded central commit is refused
    const moved = a.files.map((f) => (f.path === '.github/workflows/pipegen.yml' ? { ...f, content: f.content.replace(SHA, 'd'.repeat(40)) } : f));
    expect(() => planLocks(inputs({ orgAdmin: true, ids: { app: 11, central: 22 }, files: moved }))).toThrow(LockError);
  });

  it('locks: public app repo or personal account → no required workflow', () => {
    const { a } = assembledPrivate();
    const base = { orgAdmin: true, ids: { app: 11, central: 22 }, files: a.files } as const;
    const none = [
      inputs({ ...base, profile: profileOf([node()], { ownerType: 'Organization', plan: 'team' }) }),          // a public app
      inputs({ ...base, profile: orgPriv({ ownerType: 'User', plan: 'pro' }) }),                              // a personal account
      inputs({ ...base, profile: orgPriv({ ownerType: 'User', plan: 'enterprise' }) }),                       // a personal account, whatever its plan reads
      inputs({ ...base, profile: orgPriv({ plan: 'free' }) }), inputs({ ...base, profile: orgPriv({ plan: 'pro' }) }), inputs({ ...base, profile: orgPriv({ plan: 'unknown' }) }),
      inputs({ ...base, orgAdmin: false }),
    ];
    for (const i of none) {
      const plan = planLocks(i);
      expect(plan.orgRequiredWorkflow, JSON.stringify([i.profile.private, i.profile.ownerType, i.profile.plan, i.orgAdmin])).toBeUndefined();
      expect(plan.notes.join('\n')).toMatch(/required workflow/);
    }
    // an org membership pipegen couldn't read: not planned, and the note says it couldn't check
    const unread = planLocks(inputs({ ...base, orgAdmin: null }));
    expect(unread.orgRequiredWorkflow).toBeUndefined();
    expect(unread.notes.join('\n')).toMatch(/couldn't check/i);
  });

  it('locks: sha_pinning_required planned only when available', () => {
    const on = planLocks(inputs({ shaPinning: { state: 'read', enabled: true, allowedActions: 'selected', required: false } }));
    expect(on.shaPinning).toEqual({
      previous: false,
      request: { method: 'PUT', route: '/repos/{owner}/{repo}/actions/permissions', params: { owner: 'o', repo: 'r' }, body: { enabled: true, allowed_actions: 'selected', sha_pinning_required: true } },
    });
    // already on: planned again (idempotent), the previous value kept for uninstall
    expect(planLocks(inputs({ shaPinning: { state: 'read', enabled: true, allowedActions: 'all', required: true } })).shaPinning?.previous).toBe(true);
    // Free private too, when the read answers (S10, Plan P)
    const free = planLocks(inputs({ profile: orgPriv({ plan: 'free' }), caps: { ...CAPS, branchProtection: false }, shaPinning: { state: 'read', enabled: true, allowedActions: 'all', required: false } }));
    expect(free.shaPinning?.request.body).toMatchObject({ sha_pinning_required: true });
    // not offered by GitHub, or not readable: not planned, with a note
    for (const [s, said] of [[{ state: 'absent' }, /doesn't offer/], [{ state: 'unknown' }, /couldn't read/]] as const) {
      const plan = planLocks(inputs({ shaPinning: s }));
      expect(plan.shaPinning, s.state).toBeUndefined();
      expect(plan.notes.join('\n'), s.state).toMatch(/full-length commit SHA/);
      expect(plan.notes.join('\n'), s.state).toMatch(said);
    }
    // Actions turned off (or an unknown allowed_actions value): pipegen would rewrite a setting it doesn't understand, so not planned
    expect(planLocks(inputs({ shaPinning: { state: 'read', enabled: false, allowedActions: 'all', required: false } })).shaPinning).toBeUndefined();
    // the user's own workflows still use actions by tag: turning the setting on would stop them, so not planned, and the note says why
    const tagged = planLocks(inputs({ profile: orgPriv({ existingWorkflows: [tagPinnedWorkflow(3)] }), shaPinning: { state: 'read', enabled: true, allowedActions: 'all', required: false } }));
    expect(tagged.shaPinning).toBeUndefined();
    expect(tagged.notes.join('\n')).toMatch(/3 action references/);
  });

  it('locks: free private → no ruleset, Pro/Team suggestion, no /public/i wording', () => {
    for (const ownerType of ['User', 'Organization'] as const) {
      const plan = planLocks(inputs({ profile: orgPriv({ plan: 'free', ownerType }), caps: { ...CAPS, branchProtection: false }, central: { repo: 'o/pipelines', sha: SHA, branchProtection: false, codeowners: noCo } }));
      expect(plan.rulesets).toBeUndefined();
      expect(plan.classic).toBeUndefined();
      expect(plan.centralRuleset).toBeUndefined();
      expect(plan.orgRequiredWorkflow).toBeUndefined();
      const note = plan.notes.join('\n');
      expect(note).toMatch(/GitHub Pro/);
      expect(note).toMatch(/Team/);
      expect(note).toMatch(/can't lock merges/);
      expect(note).not.toMatch(/public/i);
      // the CODEOWNERS files are still written (the gate reads the owners)
      expect(plan.codeowners?.file.content).toContain('/.github/workflows/ @alice @bob');
    }
    // no note anywhere suggests making a repo public
    for (const i of [inputs(), inputs({ profile: profileOf([node()], { ownerType: 'Organization', plan: 'team' }) }), inputs({ writers: { app: ['a', 'b', 'c'], central: ['a'] }, owners: ['@a'] })]) {
      expect(planLocks(i).notes.join('\n')).not.toMatch(/public/i);
    }
  });

  it('codeowners: appends effective protected paths, edit recorded', () => {
    const original = '* @carol\n/docs/ @dana\n';
    const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
    const i = inputs({ profile: prof, appCodeowners: { original, isSymlink: false, inserted: null } });
    const plan = planLocks(i);
    const block = codeownersBlock(i.protectedPaths, OWNERS);
    expect(plan.codeowners?.file).toEqual({ path: '.github/CODEOWNERS', content: codeownersFile(original, block), part: 'codeowners', reason: expect.any(String), repo: 'app', edited: { original } });
    expect(plan.codeowners?.file.content.startsWith(original)).toBe(true);
    // every effective protected path is in the block (the reviewed tools' config files too)
    for (const pth of ['/.github/workflows/', '/.husky/', 'lefthook.yml', '.gitleaksignore']) expect(block).toContain(`${pth} @alice @bob`);
    expect(plan.codeowners?.edit).toEqual({ path: '.github/CODEOWNERS', kind: 'codeowners', inserted: block, anchor: '/docs/ @dana\n' });
    // the app judge accepts it
    const d = planned(prof, { over: { codeOwners: plan.codeOwners } }).draft;
    const facts = { app: { isSymlink: false, inserted: null }, central: { isSymlink: false, inserted: null } };
    expect(createdFileProblems(plan.codeowners?.file as CreatedFile, d, undefined, envOf({ codeownersFacts: facts, centralCodeowners: null })).problems).toEqual([]);
    // a CODEOWNERS file at another place GitHub reads is edited there
    expect(planLocks(inputs({ profile: orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: 'docs/CODEOWNERS' } }), appCodeowners: { original, isSymlink: false, inserted: null } })).codeowners?.file.path).toBe('docs/CODEOWNERS');
    // a new file: no edit to record (the file itself is pipegen's)
    const fresh = planLocks(inputs());
    expect(fresh.codeowners?.file).toMatchObject({ path: '.github/CODEOWNERS', content: block, edited: { original: '' } });
    expect(fresh.codeowners?.edit).toBeUndefined();
    // a re-run: the block the record owns is replaced in place, the rest stays
    const OLD = codeownersBlock(['lefthook.yml'], OWNERS);
    const before = `* @carol\n\n${OLD}tail @x\n`;
    const rerun = planLocks(inputs({ profile: prof, appCodeowners: { original: before, isSymlink: false, inserted: OLD } }));
    expect(rerun.codeowners?.file.content).toBe(codeownersReplace(before, OLD, block));
    expect(rerun.codeowners?.edit).toEqual({ path: '.github/CODEOWNERS', kind: 'codeowners', inserted: block, anchor: '\n' });
    // a symbolic link is never written through: no file, a note
    const link = planLocks(inputs({ profile: prof, appCodeowners: { original, isSymlink: true, inserted: null } }));
    expect(link.codeowners).toBeUndefined();
    expect(link.notes.join('\n')).toMatch(/symbolic link/);
  });

  it('CODEOWNERS line of 4,097 characters → note', () => {
    const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
    const long = (n: number): string => `/docs/ ${'@x'.repeat(Math.ceil((n - 7) / 2))}`.slice(0, n);
    const run = (original: string, over: Partial<LockInputs> = {}) => planLocks(inputs({ profile: prof, appCodeowners: { original, isSymlink: false, inserted: null }, ...over }));
    const over = run(`* @carol\n${long(4097)}\n`);
    expect(over.notes.join('\n')).toContain('Line 2 of .github/CODEOWNERS is over 4,096 characters; the gate does not read it, so nobody can approve changes to the paths it covers. Shorten or split it.');
    // the file is still planned
    expect(over.codeowners).toBeDefined();
    // CRLF endings do not count toward the length
    expect(run(`${long(4096)}\r\n`).notes.join('\n')).not.toMatch(/over 4,096/);
    // a comment line is not a rule: the gate ignores it
    expect(run(`# ${'x'.repeat(4100)}\n`).notes.join('\n')).not.toMatch(/over 4,096/);
    // the central repo's own file too
    const central = planLocks(inputs({ central: { repo: 'o/pipelines', sha: SHA, branchProtection: true, codeowners: { path: '.github/CODEOWNERS', original: `\n\n${long(4100)}\n`, isSymlink: false, inserted: null } } }));
    expect(central.notes.join('\n')).toMatch(/Line 3 of \.github\/CODEOWNERS is over 4,096/);
  });

  it('CODEOWNERS line of 4,096 characters → no note', () => {
    const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
    const line = `/docs/ ${'@x'.repeat(2045)}`.slice(0, 4096);
    expect(line.length).toBe(4096);
    const plan = planLocks(inputs({ profile: prof, appCodeowners: { original: `${line}\n`, isSymlink: false, inserted: null } }));
    expect(plan.notes.join('\n')).not.toMatch(/over 4,096/);
  });

  it('codeowners: team names refused, user logins only', () => {
    for (const bad of [['@o/team', '@bob'], ['alice', '@bob'], ['@alice', 'a@b.example'], ['@alice', '@dependabot[bot]'], ['@alice', '']]) {
      expect(() => planLocks(inputs({ owners: bad })), bad.join(' ')).toThrow(LockError);
      // refused as not a user login, before any write-access check
      expect(() => planLocks(inputs({ owners: bad })), bad.join(' ')).toThrow(/not a user login/);
    }
    expect(() => planLocks(inputs({ owners: ['@alice', '@Alice'] }))).toThrow(/listed twice/);
    expect(() => planLocks(inputs({ owners: ['@o/team', '@bob'] }))).toThrow(/team/);
    // never a team in any file or request
    expect(JSON.stringify(planLocks(inputs()))).not.toMatch(/@o\//);
  });

  it('locks: two rulesets: gate-only with no bypass, PR rules with no bypass', () => {
    const plan = planLocks(inputs());
    const gate = plan.rulesets?.gate as ApiRequest;
    const reviews = plan.rulesets?.reviews as ApiRequest;
    expect(gate.body.name).toBe('pipegen');
    expect(reviews.body.name).toBe('pipegen-reviews');
    expect((gate.body.rules as Obj[]).map((r) => r.type)).toEqual(['deletion', 'non_fast_forward', 'required_status_checks']);
    expect((reviews.body.rules as Obj[]).map((r) => r.type)).toEqual(['pull_request']);
    for (const r of [gate, reviews]) {
      expect(r.body.bypass_actors).toEqual([]);
      expect(r.body.enforcement).toBe('active');
      expect(r.route).toBe('/repos/{owner}/{repo}/rulesets');
    }
  });

  it('locks: classic protection binds the check to app 15368 with the same review settings', () => {
    for (const over of [{}, { writers: { app: ['alice'], central: ['alice'] }, owners: ['@alice'] }, { writers: { app: ['alice', 'bob', 'carol'], central: ['alice'] }, owners: ['@alice'] }]) {
      const plan = planLocks(inputs(over));
      const c = plan.classic as ApiRequest;
      expect(c.method).toBe('PUT');
      expect(c.route).toBe('/repos/{owner}/{repo}/branches/{branch}/protection');
      expect(c.params).toEqual({ owner: 'o', repo: 'r', branch: 'main' });
      expect(c.body.required_status_checks).toEqual({ strict: false, checks: [{ context: GATE_CHECK_NAME, app_id: 15368 }] });
      const pr = prRule(plan.rulesets?.reviews);
      expect(c.body.required_pull_request_reviews).toEqual({
        required_approving_review_count: pr.required_approving_review_count, require_code_owner_reviews: pr.require_code_owner_review,
        dismiss_stale_reviews: pr.dismiss_stale_reviews_on_push, require_last_push_approval: pr.require_last_push_approval,
      });
      expect(c.body).toMatchObject({ enforce_admins: true, restrictions: null, allow_force_pushes: false, allow_deletions: false });
    }
  });

  it('codeowners: re-run keeps only names the block owns; central re-run uses the central file list', async () => {
    const { codeownersJudge, codeownersCentralJudge } = await import('../src/engine/created-judges/codeowners.js');
    const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
    const d = planned(prof, { over: { codeOwners: { owners: OWNERS, writers: 2 }, created: [{ path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 't', repo: 'app' }] } }).draft;
    const paths = codeownersProtectedPaths(d, REVIEWED);
    const block = codeownersBlock(paths, OWNERS);
    const OLD = codeownersBlock(['lefthook.yml'], OWNERS);
    const facts = (repo: 'app' | 'central', inserted: string) => ({ app: { isSymlink: false, inserted: repo === 'app' ? inserted : null }, central: { isSymlink: false, inserted: repo === 'central' ? inserted : null } });
    const appRun = (line: string) => {
      const original = `${OLD}${line}\n`;
      const f: CreatedFile = { path: '.github/CODEOWNERS', content: codeownersReplace(original, OLD, block) as string, part: 'codeowners', reason: 't', repo: 'app', edited: { original } };
      return codeownersJudge(f, { draft: d, ...envOf({ codeownersFacts: facts('app', OLD), centralCodeowners: '.github/CODEOWNERS' }) }).join(' | ');
    };
    // names the block does not own (PIPEGEN.md, a created Dockerfile, a source folder) are the user's to assign: a re-run keeps them
    for (const line of ['PIPEGEN.md @docs', '/api/ @backend', 'Dockerfile @dev', '/src/*.md @docs']) expect(appRun(line), line).toBe('');
    // names the block owns are still refused, and so is a bare wildcard that reaches into a protected folder (`*.md` owns .github/workflows/x.md)
    for (const line of ['pipegen.yml @dev', 'CODEOWNERS @dev', 'lefthook.yml @dev', '*.md @docs']) expect(appRun(line), line).toMatch(/after the pipegen block/);
    // the central re-run: the central repo's own files (its workflows, the install records), never the app's
    const cpaths = [...CENTRAL_PROTECTED_PATHS];
    const cblock = codeownersBlock(cpaths, OWNERS);
    const cOLD = codeownersBlock(['installs/**'], OWNERS);
    const centralFiles: CreatedFile[] = [{ path: centralWorkflowFile('r', 'merge'), content: 'x', part: 'pipeline', reason: 't', repo: 'central' }];
    const centralRun = (line: string, files: readonly CreatedFile[] = centralFiles, centralTree?: string[]) => {
      const original = `${cOLD}${line}\n`;
      const f: CreatedFile = { path: '.github/CODEOWNERS', content: codeownersReplace(original, cOLD, cblock) as string, part: 'codeowners', reason: 't', repo: 'central', edited: { original } };
      return codeownersCentralJudge(f, { draft: d, files, ...envOf({ codeownersFacts: facts('central', cOLD), centralCodeowners: '.github/CODEOWNERS', ...(centralTree === undefined ? {} : { centralFiles: centralTree }) }) }).join(' | ');
    };
    expect(centralRun('r--merge.yml @dev', [], ['.github/workflows/r--merge.yml'])).toMatch(/after the pipegen block/);
    expect(centralRun('r--merge.yml @dev', centralFiles, ['installs/r.json'])).toMatch(/after the pipegen block/);
    // G8-R2 m3: a central re-run needs the central repo's file list; without it the file is refused, never judged on a shorter list
    expect(centralRun('README.md @docs')).toMatch(/central repository's file list/);
    expect(centralRun('README.md @docs', centralFiles, ['README.md'])).toBe('');
    expect(centralRun('other--nightly.yml @dev', [], ['.github/workflows/other--nightly.yml', 'installs/other.json', 'README.md'])).toMatch(/after the pipegen block/);
    expect(centralRun('other.json @dev', [], ['installs/other.json'])).toMatch(/after the pipegen block/);
    // the app's names mean nothing in the central repo: an app workflow's or PIPEGEN.md's name there is not refused
    // (the app's own delivered files, judged in the same referee call, are not the central repo's)
    const withApp: CreatedFile[] = [...centralFiles, { path: '.github/workflows/pipegen.yml', content: 'x', part: 'pipeline', reason: 't', repo: 'app' }];
    for (const line of ['pipegen.yml @dev', 'PIPEGEN.md @docs', 'README.md @docs']) expect(centralRun(line, withApp, ['README.md']), line).toBe('');
  });

  describe('G8 fix round 1 (controller ruling G8-R2)', () => {
    it('I1: an empty writer list (either repo) stops with a plain reason, never a weaker lock or a one-writer note', () => {
      for (const writers of [{ app: [], central: ['alice'] }, { app: ['alice'], central: [] }, { app: [], central: [] }]) {
        expect(() => planLocks(inputs({ writers, owners: [] })), JSON.stringify(writers)).toThrow(LockError);
        expect(() => planLocks(inputs({ writers, owners: [] })), JSON.stringify(writers)).toThrow(/found nobody who can write/);
      }
    });

    it('PL-F1: the stops and notes that say to run again name the caller command (default `npx pipegen run`, finish passes its own)', () => {
      const none = { writers: { app: [], central: [] }, owners: [] };
      expect(() => planLocks(inputs(none))).toThrow(/then run `npx pipegen run` again\./);
      expect(() => planLocks(inputs({ ...none, command: 'finish' }))).toThrow(/then run `npx pipegen finish` again\./);
      const one = { writers: { app: ['alice', 'bob'], central: ['alice'] }, owners: [] };
      expect(planLocks(inputs(one)).notes.join('\n')).toMatch(/then run `npx pipegen run` again\./);
      expect(planLocks(inputs({ ...one, command: 'finish' })).notes.join('\n')).toMatch(/then run `npx pipegen finish` again\./);
    });

    it('PL-D1-R1: the org required workflow has the pipegen header and the part banner (version injected, default, or refused)', () => {
      const { a } = assembledPrivate();
      const base = { orgAdmin: true, ids: { app: 11, central: 22 }, files: a.files };
      const text = planLocks(inputs({ ...base, version: '9.8.7' })).orgRequiredWorkflow?.file.content as string;
      const head = text.split('\n').filter((l, i, all) => all.slice(0, i + 1).every((x) => x.startsWith('#'))).join('\n');
      expect(head).toMatch(/written by pipegen 9\.8\.7\./i);
      expect(head.match(/written by pipegen/gi)).toHaveLength(1);
      expect(head).toContain('PIPEGEN.md');
      expect(head).toContain('npx pipegen update');
      expect(head).toMatch(/When it runs: on every pull request/);
      expect(head).not.toMatch(/\d{4}-\d{2}-\d{2}/);
      expect(text).toContain('  # --- Before merge ---\n  pipegen-required:\n');
      // comments only: the data is the exact form the referee holds the file to
      expect(parse(text)).toEqual(parse(planLocks(inputs({ ...base, version: null })).orgRequiredWorkflow?.file.content as string));
      expect((planLocks(inputs({ ...base, version: null })).orgRequiredWorkflow?.file.content as string)).toMatch(/Written by pipegen\.\n/);
      expect((planLocks(inputs(base)).orgRequiredWorkflow?.file.content as string)).toMatch(/Written by pipegen \d+\.\d+\.\d+/);
      for (const bad of ['1.2', 'latest', '1.2.3\n# x: y', '1.2.3 $(id)', '']) expect(() => planLocks(inputs({ ...base, version: bad })), JSON.stringify(bad)).toThrow(LockError);
    });

    it('I2 + m7: a planned org required workflow comes with the re-run note and the minutes note', () => {
      const { a } = assembledPrivate();
      const plan = planLocks(inputs({ orgAdmin: true, ids: { app: 11, central: 22 }, files: a.files }));
      expect(plan.orgRequiredWorkflow).toBeDefined();
      const note = plan.notes.join('\n');
      expect(note).toMatch(/after a code owner approves/);
      expect(note).toContain('re-run the `pipegen required` run');
      expect(note).toMatch(/roughly doubles/);
      expect(note).toMatch(/minutes/);
      // without it, neither note
      const none = planLocks(inputs()).notes.join('\n');
      expect(none).not.toMatch(/roughly doubles|re-run the `pipegen required`/);
    });

    it('m1: the referee holds the required workflow to its exact form (with, needs, the name pipegen, missing or other secrets, other permissions refused)', async () => {
      const { a } = assembledPrivate();
      const lp = planLocks(inputs({ orgAdmin: true, ids: { app: 11, central: 22 }, files: a.files }));
      const rf = lp.orgRequiredWorkflow?.file as CreatedFile;
      const JD = { platform: p, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];
      const SEC_KEY = ['sec', 'rets'].join('');
      const MAPPING_BLOCK = new RegExp(`\\n {4}${SEC_KEY}:\\n(?: {6}.*\\n)+`);
      expect(rf.content).toMatch(MAPPING_BLOCK);
      const job = '  pipegen-required:\n';
      for (const [what, content] of [
        ['a literal with', rf.content.replace(job, `${job}    with:\n      mode: none\n`)],
        ['needs', rf.content.replace(job, `${job}    needs: [x]\n`)],
        ['named pipegen', rf.content.replace('    name: pipegen required\n', '    name: pipegen\n')],
        ['no secrets', rf.content.replace(MAPPING_BLOCK, '\n')],
        ['another secret', rf.content.replace(new RegExp(`(\\n {4}${SEC_KEY}:\\n)`), `$1      OTHER: \${{ ${SEC_KEY}.OTHER }}\n`)],
        ['fewer permissions', rf.content.replace('      actions: read\n', '')],
        ['a run-name', rf.content.replace('on:\n', 'run-name: x\non:\n')],
      ] as const) {
        expect(content, what).not.toBe(rf.content);
        expect(shown(await judgeAssembled(a, { ...JD, extra: [{ ...rf, content }] })), what).toMatch(/org required workflow/);
      }
      // without the app's pipegen.yml in the same call there is nothing to compare with: refused
      const { judge } = await import('./helpers/assemble.js');
      const central = a.files.filter((f) => f.repo === 'central');
      expect(shown(await judge([...central, rf], (await import('./helpers/assemble.js')).planned(orgPriv(), { over: { centralPin: { repo: 'o/pipelines', sha: SHA } } }).draft))).toMatch(/org required workflow/);
    });

    it('m2: an unknown plan and branch rules not confirmed → the locks are planned anyway (finish re-probes), never "no lock"', () => {
      const plan = planLocks(inputs({ profile: orgPriv({ plan: 'unknown' }), caps: { ...CAPS, branchProtection: false }, central: { repo: 'o/pipelines', sha: SHA, branchProtection: false, codeowners: noCo } }));
      expect(plan.rulesets?.gate).toBeDefined();
      expect(plan.classic).toBeDefined();
      expect(plan.centralRuleset).toBeDefined();
      const note = plan.notes.join('\n');
      expect(note).toMatch(/couldn't confirm/);
      expect(note).not.toMatch(/can't lock merges/);
      expect(note).not.toMatch(/public/i);
      // a known Free plan stays "no lock" (GitHub offers no branch rules there)
      expect(planLocks(inputs({ profile: orgPriv({ plan: 'free' }), caps: { ...CAPS, branchProtection: false } })).rulesets).toBeUndefined();
    });

    it('m5: a re-run with fewer than two qualifying owners says the old block stays', () => {
      const OLD = codeownersBlock(['lefthook.yml'], OWNERS);
      const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
      const plan = planLocks(inputs({ profile: prof, writers: { app: ['alice', 'bob'], central: ['alice'] }, owners: ['@alice'], appCodeowners: { original: OLD, isSymlink: false, inserted: OLD } }));
      expect(plan.codeowners).toBeUndefined();
      expect(plan.notes.join('\n')).toMatch(/block pipegen wrote before .*stays/);
      expect(plan.notes.join('\n')).toContain('o/r');
      // the same for the central repo's recorded block
      const c = planLocks(inputs({ writers: { app: ['alice', 'bob'], central: ['alice'] }, owners: ['@alice'], central: { repo: 'o/pipelines', sha: SHA, branchProtection: true, codeowners: { path: '.github/CODEOWNERS', original: OLD, isSymlink: false, inserted: OLD } } }));
      expect(c.notes.join('\n')).toMatch(/block pipegen wrote before in o\/pipelines .*stays/);
      // no recorded block: no such note
      expect(planLocks(inputs({ writers: { app: ['alice', 'bob'], central: ['alice'] }, owners: ['@alice'] })).notes.join('\n')).not.toMatch(/wrote before/);
    });

    it('m6: a CODEOWNERS that is a symbolic link (or not a plain file) → no code-owner rule on that repo, the note names the fake-gate risk', () => {
      const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
      const app = planLocks(inputs({ profile: prof, appCodeowners: { original: '* @x\n', isSymlink: true, inserted: null } }));
      expect(app.codeowners).toBeUndefined();
      expect(prRule(app.rulesets?.reviews).require_code_owner_review).toBe(false);
      expect((app.classic?.body.required_pull_request_reviews as Obj).require_code_owner_reviews).toBe(false);
      expect(prRule(app.rulesets?.reviews).required_approving_review_count).toBe(1);
      expect(prRule(app.centralRuleset).require_code_owner_review).toBe(true);
      expect(app.notes.join('\n')).toMatch(/not a plain file/);
      expect(app.notes.join('\n')).toContain(GATE_CHECK_NAME);
      const central = planLocks(inputs({ central: { repo: 'o/pipelines', sha: SHA, branchProtection: true, codeowners: { path: '.github/CODEOWNERS', original: '* @x\n', isSymlink: true, inserted: null } } }));
      expect(central.centralCodeowners).toBeUndefined();
      expect(prRule(central.centralRuleset).require_code_owner_review).toBe(false);
      expect(prRule(central.rulesets?.reviews).require_code_owner_review).toBe(true);
    });
  });

  describe('G8 fix round 2 (controller ruling G8-R3)', () => {
    it('both CODEOWNERS files symbolic links (no block, no code-owner rule) → the plan lists no code owners', () => {
      const prof = orgPriv({ repoFiles: { ...emptyRepoFiles(), codeowners: '.github/CODEOWNERS' } });
      const link = { original: '* @x\n', isSymlink: true, inserted: null };
      const plan = planLocks(inputs({ profile: prof, appCodeowners: link, central: { repo: 'o/pipelines', sha: SHA, branchProtection: true, codeowners: { path: '.github/CODEOWNERS', ...link } } }));
      expect(plan.codeowners).toBeUndefined();
      expect(plan.centralCodeowners).toBeUndefined();
      expect(plan.codeOwners).toBeUndefined();
      expect(plan.owners).toEqual({ app: [], central: [] });
      // one repo linked: only the other lists its owners
      const appOnly = planLocks(inputs({ profile: prof, appCodeowners: link }));
      expect(appOnly.owners).toEqual({ app: [], central: OWNERS });
      expect(appOnly.codeOwners).toEqual({ owners: OWNERS, writers: 2 });
      const centralOnly = planLocks(inputs({ central: { repo: 'o/pipelines', sha: SHA, branchProtection: true, codeowners: { path: '.github/CODEOWNERS', ...link } } }));
      expect(centralOnly.owners).toEqual({ app: OWNERS, central: [] });
    });

    it('central layout: an empty central file list is refused on a central re-run, like a missing one', async () => {
      const { codeownersCentralJudge } = await import('../src/engine/created-judges/codeowners.js');
      const cblock = codeownersBlock([...CENTRAL_PROTECTED_PATHS], OWNERS);
      const cOLD = codeownersBlock(['installs/**'], OWNERS);
      const original = `${cOLD}README.md @docs\n`;
      const f: CreatedFile = { path: '.github/CODEOWNERS', content: codeownersReplace(original, cOLD, cblock) as string, part: 'codeowners', reason: 't', repo: 'central', edited: { original } };
      const facts = { app: { isSymlink: false, inserted: null }, central: { isSymlink: false, inserted: cOLD } };
      const run = (prof: RepoProfile, centralFiles?: string[]) => codeownersCentralJudge(f, { draft: planned(prof, { over: { codeOwners: { owners: OWNERS, writers: 2 } } }).draft, files: [], ...envOf({ codeownersFacts: facts, centralCodeowners: '.github/CODEOWNERS', ...(centralFiles === undefined ? {} : { centralFiles }) }) }).join(' | ');
      // a private app (central layout): the central repo holds its workflows, so an empty list can't be its tree
      expect(run(orgPriv(), [])).toMatch(/central repository's file list/);
      expect(run(orgPriv())).toMatch(/central repository's file list/);
      expect(run(orgPriv(), ['.github/workflows/r--merge.yml', 'installs/r.json'])).toBe('');
    });
  });
});
