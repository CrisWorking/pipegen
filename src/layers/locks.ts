// v0.2 Plan G Task 5 (sub-task G8; rulings S9, S10, S13; carries S-1, S-2, C8, G42, D0b-2, D0b-r1, D1-r1): the locks on the default
// branch, planned as data. planLocks is pure: it returns the exact API requests (route, path parameters, body) that `finish` (G11) sends
// after the setup PR is merged, and the CODEOWNERS files the delivery (G10) writes. Nothing here talks to GitHub; the probes it needs
// are in src/github/lock-probes.ts.
//
// The app repo (when GitHub offers branch rules, caps.branchProtection):
// - ruleset `pipegen` (gate only, S-1 / DEC #74): the required check GATE_CHECK_NAME bound to GATE_CHECK_INTEGRATION_ID (the GitHub
//   Actions app), so a commit status posted through the API under the same name doesn't satisfy it (Review Focus 6); no deletion, no
//   force-push. No bypass.
// - ruleset `pipegen-reviews` (the PR rules): with two or more writers, one approval, stale approvals dismissed on a new push and the last
//   push approved by someone else (Review Focus 7), and code-owner review when at least two code owners can write to both repos (S9). With
//   one writer: no approval (nobody else could give it), no code-owner review, a plain note (Review Focus 1, T17). No bypass (G42, C8): the
//   plan's admin-role bypass for a single code owner is struck.
// - classic branch protection, the fallback `finish` uses only where rulesets can't be created: the same check bound to the same app
//   (`checks[{ context, app_id }]`), the same review settings, admins included (enforce_admins), no force-push, no deletion.
// The central repo `<owner>/pipelines` (also the records-only one of a public app): ruleset `pipegen` (pull request required with the
// approvals its own writers allow, code-owner review under the same rule, no deletion, no force-push, no bypass) and a CODEOWNERS block for
// CENTRAL_PROTECTED_PATHS (.github/workflows/**, installs/** and the CODEOWNERS files themselves).
// The app's CODEOWNERS: the effective protected paths (given: codeownersProtectedPaths) owned by the code owners, appended to the file GitHub
// reads (or replacing the block the install record owns, on a re-run), the edit recorded.
// The org required workflow: only for a private app of a Team or Enterprise organisation whose owner (admin) runs pipegen. It is the central
// `<name>--required.yml`, run by GitHub on every pull request from the central repo (a pull request can't change it), pinned in the org
// ruleset by the central commit's sha; it calls the merge workflow at that commit, so every check and the gate run again on their own results.
// The sha-pinning setting: planned where the read answered (Free private too, S10), never where it couldn't be read.
//
// Code owners (S9, D0b-2, D0b-r1, D1-r1): user logins (`@login`, never a team, e-mail or bot) the user picked among the users who can write
// to the app AND the central repo (two listWriters lists, effective access). An owner outside that set is refused. With two or more app
// writers, at least two owners are required when two qualify; when fewer than two qualify there is no code-owner rule and no CODEOWNERS
// block, and the notes say so (DEC #75). Never a bypass.
import { Document, parse } from 'yaml';
import { centralProjectName, centralWorkflowFile } from '../engine/central-path.js';
import { CENTRAL_PROTECTED_PATHS, codeownersBlock, codeownersFile, codeownersOwnerProblem, codeownersReplace } from '../engine/created-builders.js';
import { CALLER_WORKFLOW } from '../engine/job-rules.js';
import { COMMIT_SHA_RE, isGitHubRepo } from '../engine/names.js';
import type { ShaPinningRead } from '../github/lock-probes.js';
import { GATE_CHECK_INTEGRATION_ID, GATE_CHECK_NAME, type Capabilities, type CreatedFile, type InstallRecord, type RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { MERGE_CALLER_JOB } from './assemble.js';

/** A plan pipegen refuses to make (an owner that is not a user login or can't write to both repos, an inconsistent input). */
export class LockError extends Error {
  constructor(message: string) { super(message); this.name = 'LockError'; }
}

/** The app's gate-only ruleset and its PR-rules ruleset (S13); the central repo's ruleset (another repo, so the same name). */
export const GATE_RULESET = 'pipegen';
export const REVIEWS_RULESET = 'pipegen-reviews';
export const CENTRAL_RULESET = 'pipegen';
/** The org ruleset that requires the project's central required workflow. */
export const requiredRulesetName = (project: string): string => `pipegen-required--${centralProjectName(project)}`;
/** The job of the required workflow: named apart from the gate's check (its own check is `pipegen required / gate`). */
export const REQUIRED_JOB = 'pipegen-required';
const REQUIRED_NAME = 'pipegen required';
/** GitHub's name for the default branch in a ruleset condition: the rule follows a renamed default branch. */
const DEFAULT_BRANCH = '~DEFAULT_BRANCH';
const CO_PLACES: readonly string[] = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
const NEW_CODEOWNERS = '.github/CODEOWNERS';
const ALLOWED_ACTIONS: ReadonlySet<string> = new Set(['all', 'local_only', 'selected']);
const MARKER_RE = /pipegen:(?:begin|end)/;

/** One GitHub API call: `gh.request(\`${method} ${route}\`, { ...params, ...body })`. */
export interface ApiRequest { method: 'POST' | 'PUT'; route: string; params: Readonly<Record<string, string>>; body: Record<string, unknown> }
/** An existing CODEOWNERS file's text (`original`, '' when there is none), whether it is a symbolic link, and the block the install record owns in it. */
export interface ExistingCodeowners { original: string; isSymlink: boolean; inserted: string | null }
export type CodeownersEdit = InstallRecord['edits'][number];

export interface LockInputs {
  /** owner, repo, private, ownerType, plan (readGitHubContext), defaultBranch, repoFiles.codeowners (the app's CODEOWNERS path GitHub reads). */
  profile: RepoProfile;
  /** The app repo's capabilities (probeCapabilities): branchProtection decides the rulesets and the classic fallback. */
  caps: Capabilities;
  /** The central repo (`<owner>/pipelines`), the commit pipegen delivered there, whether GitHub offers it branch rules, its CODEOWNERS. */
  central: { repo: string; sha: string; branchProtection: boolean; codeowners: ExistingCodeowners & { path: string | null } };
  /** listWriters of the app and of the central repo (readWriters). */
  writers: { app: readonly string[]; central: readonly string[] };
  /** The code owners the user picked (`@login`). */
  owners: readonly string[];
  /** readOrgAdmin: null when it couldn't be read. */
  orgAdmin: boolean | null;
  /** readShaPinning of the app repo. */
  shaPinning: ShaPinningRead;
  /** The paths the app's block owns: codeownersProtectedPaths(draft, reviewed). */
  protectedPaths: readonly string[];
  /** The app's existing CODEOWNERS (at profile.repoFiles.codeowners). */
  appCodeowners: ExistingCodeowners;
  /** The repository ids an org ruleset names (readRepoId); without them no org required workflow is planned. */
  ids?: { app: number; central: number };
  /** The delivered files (assemble's AssembledFiles.files): the required workflow calls the merge workflow pipegen.yml calls. */
  files: readonly CreatedFile[];
}

export interface LockPlan {
  /** The app's two rulesets (POST /repos/{owner}/{repo}/rulesets). */
  rulesets?: { gate: ApiRequest; reviews: ApiRequest };
  /** Classic branch protection (PUT …/branches/{branch}/protection), only where rulesets can't be created. */
  classic?: ApiRequest;
  centralRuleset?: ApiRequest;
  codeowners?: { file: CreatedFile; edit?: CodeownersEdit };
  centralCodeowners?: { file: CreatedFile; edit?: CodeownersEdit };
  orgRequiredWorkflow?: { file: CreatedFile; rule: ApiRequest };
  /** The setting turned on (PUT …/actions/permissions, the other two values sent back as read); `previous` for uninstall. */
  shaPinning?: { request: ApiRequest; previous: boolean };
  /** PipelineDraft.codeOwners for the CODEOWNERS judges; absent when no block is written. */
  codeOwners?: { owners: string[]; writers: number };
  /** S13: the code owners of each repo (the same users: they can write to both). */
  owners: { app: string[]; central: string[] };
  /** D0b-r1: who can write to each repo, as read. */
  writers: { app: string[]; central: string[] };
  /** Plain lines for PIPEGEN.md (fixed text and validated names only). */
  notes: string[];
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const show = (s: string): string => safeText(s, 140);

// ---------- the requests ----------

function ruleset(params: Readonly<Record<string, string>>, name: string, rules: Obj[]): ApiRequest {
  return {
    method: 'POST', route: '/repos/{owner}/{repo}/rulesets', params,
    body: { name, target: 'branch', enforcement: 'active', bypass_actors: [], conditions: { ref_name: { include: [DEFAULT_BRANCH], exclude: [] } }, rules },
  };
}
const NO_DELETE: readonly Obj[] = [{ type: 'deletion' }, { type: 'non_fast_forward' }];
interface Reviews { approvals: 0 | 1; codeOwners: boolean; lastPush: boolean }
const prRule = (r: Reviews): Obj => ({
  type: 'pull_request',
  parameters: { required_approving_review_count: r.approvals, dismiss_stale_reviews_on_push: true, require_code_owner_review: r.codeOwners, require_last_push_approval: r.lastPush, required_review_thread_resolution: false },
});
const gateCheckRule = (): Obj => ({
  type: 'required_status_checks',
  parameters: { strict_required_status_checks_policy: false, do_not_enforce_on_create: false, required_status_checks: [{ context: GATE_CHECK_NAME, integration_id: GATE_CHECK_INTEGRATION_ID }] },
});
function classic(params: Readonly<Record<string, string>>, r: Reviews): ApiRequest {
  return {
    method: 'PUT', route: '/repos/{owner}/{repo}/branches/{branch}/protection', params,
    body: {
      required_status_checks: { strict: false, checks: [{ context: GATE_CHECK_NAME, app_id: GATE_CHECK_INTEGRATION_ID }] },
      enforce_admins: true,
      required_pull_request_reviews: { required_approving_review_count: r.approvals, require_code_owner_reviews: r.codeOwners, dismiss_stale_reviews: true, require_last_push_approval: r.lastPush },
      restrictions: null, allow_force_pushes: false, allow_deletions: false,
    },
  };
}

// ---------- CODEOWNERS ----------

/** The last line of `before` ('' when empty): where the block starts, for the install record's edit. */
function lineBefore(before: string): string {
  if (before === '') return '';
  const body = before.endsWith('\n') ? before.slice(0, -1) : before;
  return before.slice(body.lastIndexOf('\n') + 1);
}

function codeownersPlan(repo: CreatedFile['repo'], found: string | null, existing: ExistingCodeowners, paths: readonly string[], owners: readonly string[], where: string, notes: string[]): { file: CreatedFile; edit?: CodeownersEdit } | undefined {
  if (found !== null && !CO_PLACES.includes(found)) throw new LockError(`The CODEOWNERS path ${JSON.stringify(show(found))} of ${where} is not one GitHub reads.`);
  if (found === null && existing.original !== '') throw new LockError(`${where} has no CODEOWNERS file, but an original text was given.`);
  const path = found ?? NEW_CODEOWNERS;
  if (existing.isSymlink) {
    notes.push(`The CODEOWNERS file of ${where} (${path}) is a symbolic link, which pipegen won't write through, so it adds no code owners there. Replace the link with a plain file and run pipegen again.`);
    return undefined;
  }
  let block: string;
  try { block = codeownersBlock(paths, owners); } catch (e) { throw new LockError(`The CODEOWNERS block of ${where} can't be written: ${e instanceof Error ? e.message : 'unknown error'}.`); }
  const { original, inserted } = existing;
  let content: string;
  let at: number;
  if (inserted !== null && inserted !== '') {
    const replaced = codeownersReplace(original, inserted, block);
    if (replaced === null || MARKER_RE.test(original.replace(inserted, ''))) throw new LockError(`The CODEOWNERS file of ${where} doesn't hold the block the install record owns exactly once, so pipegen can't replace it.`);
    content = replaced;
    at = original.indexOf(inserted);
  } else {
    if (MARKER_RE.test(original)) throw new LockError(`The CODEOWNERS file of ${where} already holds a pipegen block that the install record doesn't own, so a second block would be ambiguous.`);
    content = codeownersFile(original, block);
    at = original.length;
  }
  const file: CreatedFile = { path, content, part: 'codeowners', reason: `The code owners of the files that decide the checks (${repo === 'app' ? 'the protected paths' : 'the workflows and install records'}).`, repo, edited: { original } };
  return found === null ? { file } : { file, edit: { path, kind: 'codeowners', inserted: block, anchor: lineBefore(original.slice(0, at)) } };
}

// ---------- the required workflow ----------

function requiredWorkflow(i: LockInputs, ids: { app: number; central: number }): { file: CreatedFile; rule: ApiRequest } {
  const { profile: p, central } = i;
  const merge = centralWorkflowFile(p.repo, 'merge');
  const uses = `${central.repo}/${merge}@${central.sha}`;
  const app = i.files.find((f) => f.repo === 'app' && f.path === CALLER_WORKFLOW);
  if (app === undefined || !i.files.some((f) => f.repo === 'central' && f.path === merge)) throw new LockError(`The required workflow calls the merge workflow ${CALLER_WORKFLOW} calls, and the delivered files don't hold both.`);
  let caller: unknown;
  try { caller = (parse(app.content) as { jobs?: Obj } | null)?.jobs?.[MERGE_CALLER_JOB]; } catch { caller = undefined; }
  if (!isObj(caller) || caller.uses !== uses || !isObj(caller.permissions) || (caller.secrets !== undefined && !isObj(caller.secrets))) {
    throw new LockError(`The merge caller of ${CALLER_WORKFLOW} doesn't call ${show(merge)} at the recorded central commit, so the required workflow can't be pinned to it.`);
  }
  const path = centralWorkflowFile(p.repo, 'required');
  const doc = new Document();
  doc.contents = doc.createNode({
    name: REQUIRED_NAME, on: { pull_request: null }, permissions: {},
    jobs: { [REQUIRED_JOB]: { name: REQUIRED_NAME, uses, permissions: caller.permissions, ...(caller.secrets === undefined ? {} : { secrets: caller.secrets }) } },
  });
  doc.commentBefore = ` pipegen: the org required workflow of ${p.repo}; GitHub runs it from this repo on every pull request to the default branch, so a pull request can't change it. It calls the merge workflow at the same commit: every check and the gate run again on their own results. Written by pipegen.`;
  const file: CreatedFile = { path, content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 'The org required workflow: the checks and the gate, run from the central repo on every pull request.', repo: 'central' };
  const rule: ApiRequest = {
    method: 'POST', route: '/orgs/{org}/rulesets', params: { org: p.owner },
    body: {
      name: requiredRulesetName(p.repo), target: 'branch', enforcement: 'active', bypass_actors: [],
      conditions: { ref_name: { include: [DEFAULT_BRANCH], exclude: [] }, repository_id: { repository_ids: [ids.app] } },
      rules: [{ type: 'workflows', parameters: { do_not_enforce_on_create: false, workflows: [{ path, repository_id: ids.central, sha: central.sha }] } }],
    },
  };
  return { file, rule };
}

// ---------- the plan ----------

/** Logins as GitHub compares them (case-insensitive), each once. */
const loginSet = (xs: readonly string[], what: string): Set<string> => {
  if (!Array.isArray(xs) || xs.some((x) => typeof x !== 'string' || x === '')) throw new LockError(`The list of who can write to ${what} is not a list of logins.`);
  return new Set(xs.map((x) => x.toLowerCase()));
};

/** The locks of one project (see the file header). Throws LockError for what it refuses. */
export function planLocks(i: LockInputs): LockPlan {
  const p = i.profile;
  if (typeof p.owner !== 'string' || typeof p.repo !== 'string' || !isGitHubRepo(`${p.owner}/${p.repo}`)) throw new LockError('The repository is not a plain GitHub owner/name.');
  if (typeof i.central.repo !== 'string' || i.central.repo.toLowerCase() !== `${p.owner.toLowerCase()}/pipelines` || !isGitHubRepo(i.central.repo)) throw new LockError('The central repository is not <owner>/pipelines.');
  if (typeof i.central.sha !== 'string' || !COMMIT_SHA_RE.test(i.central.sha)) throw new LockError('The central commit is not a 40-character commit sha.');
  if (typeof p.defaultBranch !== 'string' || p.defaultBranch === '') throw new LockError('The default branch is not known.');
  const app = `${p.owner}/${p.repo}`;
  const centralName = i.central.repo;
  const centralRepo = centralName.slice(centralName.indexOf('/') + 1);
  const notes: string[] = [];

  // 1. the code owners: user logins who can write to both repos (S9, D0b-2)
  const owners = [...i.owners];
  if (owners.length > 0) {
    const bad = codeownersOwnerProblem(owners);
    if (bad !== null) throw new LockError(`The code owners can't be used: ${bad}. pipegen needs user logins (@name), because GitHub's own token can't read a team's members.`);
  }
  const appW = loginSet(i.writers.app, app);
  const centralW = loginSet(i.writers.central, centralName);
  for (const o of owners) {
    const login = o.slice(1).toLowerCase();
    if (!appW.has(login)) throw new LockError(`${show(o)} can't write to ${show(app)}, so GitHub would ignore their approval as a code owner. Pick code owners who can write to both ${show(app)} and ${show(centralName)}.`);
    if (!centralW.has(login)) throw new LockError(`${show(o)} can't write to ${show(centralName)}, so GitHub would ignore their approval there as a code owner. Pick code owners who can write to both ${show(app)} and ${show(centralName)}.`);
  }
  const qualified = [...appW].filter((w) => centralW.has(w)).length;
  const writers = appW.size;
  let codeOwnerRule = false;
  let blocks = owners.length > 0;
  if (writers >= 2) {
    if (qualified >= 2) {
      if (owners.length < 2) throw new LockError(`${writers} people can write to ${show(app)}, so pick at least two code owners (one owner couldn't approve their own pull request).`);
      codeOwnerRule = true;
    } else {
      blocks = false;
      notes.push(`${writers} people can write to ${show(app)}, but fewer than two of them can also write to ${show(centralName)}, so pipegen sets no code-owner review and writes no CODEOWNERS block (one code owner couldn't approve their own pull request). A pull request still needs an approval from another writer, but any writer can approve a change to the pipeline files, even a job that reports under the gate's name (${GATE_CHECK_NAME}). Give a second person write access to both repos, then run pipegen again.`);
    }
  } else {
    notes.push(`Only one person can write to ${show(app)}, so pull requests need no approval: the required check must still pass, but whoever merges can also change the pipeline that judges them, and pipegen can't prevent that on a one-person repo. Run \`npx pipegen verify\` to see whether the pipeline still matches what pipegen set up.`);
  }
  if (owners.length === 0 && (writers < 2 || qualified >= 2)) notes.push('No code owner was picked, so pipegen writes no CODEOWNERS block.');

  // 2. the app's locks
  const appParams = { owner: p.owner, repo: p.repo };
  const appReviews: Reviews = { approvals: writers >= 2 ? 1 : 0, codeOwners: codeOwnerRule, lastPush: writers >= 2 };
  const plan: LockPlan = { owners: { app: blocks ? owners : [], central: blocks ? owners : [] }, writers: { app: [...i.writers.app], central: [...i.writers.central] }, notes };
  if (i.caps.branchProtection === true) {
    plan.rulesets = {
      gate: ruleset(appParams, GATE_RULESET, [...NO_DELETE, gateCheckRule()]),
      reviews: ruleset(appParams, REVIEWS_RULESET, [prRule(appReviews)]),
    };
    plan.classic = classic({ ...appParams, branch: p.defaultBranch }, appReviews);
  } else {
    notes.push(p.private
      ? `Your GitHub plan can't lock merges on this private repo. Checks still run and show as failed, and pipegen warns about unreviewed pipeline changes, but nothing stops a merge, and a pull request could add a job that reports under the gate's name (${GATE_CHECK_NAME}). GitHub Pro (personal) or Team (organisation) adds the real lock.`
      : `GitHub didn't offer branch rules on ${show(app)}, so pipegen can't lock merges there. Checks still run and show as failed, but nothing stops a merge.`);
  }

  // 3. the central repo's locks: its own writers set the approvals; the code-owner rule follows the owners
  const centralCount = centralW.size;
  const centralReviews: Reviews = { approvals: centralCount >= 2 ? 1 : 0, codeOwners: codeOwnerRule, lastPush: centralCount >= 2 };
  if (i.central.branchProtection === true) plan.centralRuleset = ruleset({ owner: p.owner, repo: centralRepo }, CENTRAL_RULESET, [...NO_DELETE, prRule(centralReviews)]);
  else notes.push(`Your GitHub plan can't lock merges on the private ${show(centralName)} repo, which holds the central workflows and the install records, so pipegen can't require a review there. GitHub Pro (personal) or Team (organisation) adds the real lock.`);
  if (centralCount >= 2 && !codeOwnerRule && writers < 2) notes.push(`${centralCount} people can write to ${show(centralName)}: a change there needs an approval from another of them, without code-owner review (one code owner couldn't approve their own pull request).`);

  // 4. CODEOWNERS (D0b builders; the judges re-check them)
  if (blocks) {
    plan.codeOwners = { owners, writers };
    const appCo = codeownersPlan('app', p.repoFiles.codeowners, i.appCodeowners, i.protectedPaths, owners, show(app), notes);
    if (appCo !== undefined) plan.codeowners = appCo;
    const cCo = codeownersPlan('central', i.central.codeowners.path, i.central.codeowners, CENTRAL_PROTECTED_PATHS, owners, show(centralName), notes);
    if (cCo !== undefined) plan.centralCodeowners = cCo;
  }

  // 5. the org required workflow: a private app of a Team or Enterprise organisation, planned by one of its owners
  const allowed = p.private === true && p.ownerType === 'Organization' && (p.plan === 'team' || p.plan === 'enterprise');
  if (!allowed) notes.push('An org required workflow (the checks and the gate run from the central repo, which a pull request can\'t change) is planned only for a private repo of a GitHub Team or Enterprise organisation, so here the code-owner review is the guard.');
  else if (i.orgAdmin === null) notes.push('pipegen couldn\'t check whether you\'re an owner of the organisation, so it plans no org required workflow (the checks and the gate run from the central repo); the code-owner review is the guard.');
  else if (i.orgAdmin !== true) notes.push('Only an owner of the organisation can add an org required workflow (the checks and the gate run from the central repo), so pipegen plans none; an owner can run pipegen again to add it.');
  else if (i.ids === undefined || !Number.isSafeInteger(i.ids.app) || !Number.isSafeInteger(i.ids.central) || i.ids.app <= 0 || i.ids.central <= 0) notes.push('pipegen couldn\'t read the repository ids GitHub\'s org rule names, so it plans no org required workflow this time; run pipegen again to add it.');
  else plan.orgRequiredWorkflow = requiredWorkflow(i, i.ids);

  // 6. sha pinning (S10): where the read answered, the user's own workflows pin by sha, and the other values are known
  const SETTING = '"Require actions to be pinned to a full-length commit SHA"';
  const s = i.shaPinning;
  const tagged = p.existingWorkflows.reduce((n, w) => n + (w.tagPinned ?? 0), 0);
  const unchecked = p.existingWorkflows.some((w) => w.usesUnchecked === true);
  if (s.state === 'absent') notes.push(`GitHub doesn't offer the Actions setting ${SETTING} on this repo, so pipegen leaves it as it is.`);
  else if (s.state !== 'read') notes.push(`pipegen couldn't read the Actions setting ${SETTING} on this repo, so it leaves it as it is.`);
  else if (s.enabled !== true || !ALLOWED_ACTIONS.has(s.allowedActions)) notes.push(`Actions is off on this repo, or its allowed-actions setting is one pipegen doesn't know, so pipegen doesn't change the setting ${SETTING}.`);
  else if (tagged > 0 || unchecked) notes.push(`${tagged > 0 ? `${tagged} action reference${tagged === 1 ? '' : 's'} in your own workflows point${tagged === 1 ? 's' : ''} at a tag or a branch` : 'Some action references in your own workflows could not be checked'}, and the Actions setting ${SETTING} would stop those workflows, so pipegen leaves it off. Pin them by commit SHA, then turn the setting on.`);
  else plan.shaPinning = { previous: s.required, request: { method: 'PUT', route: '/repos/{owner}/{repo}/actions/permissions', params: appParams, body: { enabled: true, allowed_actions: s.allowedActions, sha_pinning_required: true } } };

  return plan;
}
