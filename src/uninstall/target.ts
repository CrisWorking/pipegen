// v0.2 Plan V V3 (rulings V-B5, V-B6, V-S11, V-S13, V-S16, V-N2, V-N7; fix rounds: V3-R1, V3-R2, V3-R2b): the one module of src/uninstall that
// sends a GitHub write.
//
// - UNINSTALL_WRITE_ROUTES is the fixed list of settings writes uninstall sends (the allow-list pattern of FINISH_WRITE_ROUTES, G11 carry).
//   UninstallApi checks every call before it is sent: the route is listed, the owner is the app's, the repo is the app or its central repo
//   `<owner>/pipelines` (each route names which), the org is the app's owner, every path part is a plain name or a whole id, and the body
//   holds only the keys that route takes, with the values it takes. Reads take path parts and a few query keys only, so no Octokit option
//   (`baseUrl`, `headers`, …) reaches any request. Before the first write to a repo, GitHub's id of it must be the recorded one (the app's
//   `repoId`; central's `central.repoId` when recorded). A 401 stops the run (githubTokenRejected); a rate stop is rethrown; no write
//   starts once a stop has begun (interrupting()).
// - A settings write (fix round 2, ruling V3-R2) reads the setting first and puts back only what is still as pipegen set it, never a
//   setting that needs the one turned off (V3-R2b: Dependabot security updates, the other secret_scanning switches) and never with a
//   value it didn't read (the live allowed_actions go back with the pin); reads never hold a `.` or `..` segment. The classic
//   protection, the central CODEOWNERS (its sha in the parent tree too) and the central repo delete each look at every field, path or
//   object GitHub holds that pipegen's own form would not show (signed commits, Discussions, Dependabot and Codespaces secrets, other
//   refs, commit comments) and keep what pipegen didn't make.
// - The deletes that remove an object pipegen created (rulesets, the org rule, secrets, variables, environments) are not open through
//   `write`: deleteIfPipegens reads the object from GitHub right before the DELETE and sends it only when isPipegens says `yes` (GitHub's id,
//   name, source and created_at equal the recorded ones), or `ask` with a typed name for that very object. An environment is deleted only
//   while it holds nothing but pipegen's own secrets and variables. `no` keeps the object, whatever the hash or a typed name says.
// - Typed names: `confirm(object)` builds the question here from the object as GitHub knows it and asks it through the injected `askName`
//   (V1's askTypedName in the run: the interactive terminal only). The answer is a token bound to that object (kind, repo, scope, id) of
//   this UninstallApi, used up by the first call it is passed to.
// - Restores (V-B3, V-N10, V-S6): restoreClassic puts `previous` back, or DELETEs (previous null), only while GitHub's protection is still
//   exactly what pipegen set; restoreEnvironment puts back the fields pipegen changed, only while the environment is as the preview showed;
//   restoreVariable only while the variable holds pipegen's value; deleteBranchPolicy only an id the record holds. Else kept + manual.
// - PR closes and branch deletes only touch pipegen's own branches by exact name (`pipegen/setup`, `pipegen/update`, `pipegen/uninstall` on
//   the app; this project's `pipegen/update-<name>` and `pipegen/uninstall-<name>` on central); a PR's head (branch and repo id) is read
//   from GitHub, never taken from the caller.
// - The uninstall PRs' files go through the git data API of src/deliver/git-data.ts (ghWrite, setBranch, openOrUpdatePr), on the one branch
//   each: `pipegen/uninstall` (app), `pipegen/uninstall-<name>` (central, and only this project's central files, record and CODEOWNERS).
// - goneOr (V-S11): a 404 is "gone" only after a read of the parent succeeds (GitHub answers 404 for "no access" on a private repo); a 403 is
//   a leftover with the exact manual step; a 401 stops.
// - deleteCentralRepo (V-B5, scan §4.5): the one repo delete of uninstall. The scratch repo goes only through E's own scratch delete (src/proof).
// No other file of src/uninstall sends a GitHub write (a source scan in test/uninstall-target.test.ts keeps it so).
import type { Octokit } from '@octokit/rest';
import { gitBlobSha } from '../create/guard.js';
import { readEnv, SETUP_BRANCH } from '../deliver/deliver.js';
import { checkBranch, ghWrite, isoAt, openOrUpdatePr, readTree, setBranch, statusOf, type RepoRef, type TreeEntry } from '../deliver/git-data.js';
import { centralUpdateBranch, recordPath } from '../deliver/record.js';
import { centralFilesOf, UPDATE_BRANCH } from '../deliver/update.js';
import { centralProjectName, centralWorkflowFile } from '../engine/central-path.js';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { CENTRAL_RULESET, GATE_RULESET, REVIEWS_RULESET, requiredRulesetName } from '../layers/locks.js';
import { CENTRAL_REPO, helperDescription } from '../proof/target.js';
import { classicPutForm, isObj } from '../deliver/settings-api.js';
import type { EnvSettings, InstallRecord, RecordApiRequest } from '../types.js';
import { interrupting } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';

/** A call uninstall refuses to send (a route, a target or a value it doesn't take). Nothing was sent. */
export class UninstallRefusal extends Error {
  constructor(message: string) { super(message); this.name = 'UninstallRefusal'; }
}
const refuse = (msg: string): never => { throw new UninstallRefusal(msg); };

/** The app as the record names it (its repo id binds every app write and the org rule's conditions). */
export interface UninstallApp { owner: string; repo: string; repoId: number }
export type Where = 'app' | 'central';
/**
 * The typed-name question of the run: true only when the user typed `expected` at the interactive terminal after `question` (V1's
 * askTypedName, `src/uninstall/record.ts`, bound to the run's terminal). target.ts never prompts by itself.
 */
export type AskName = (expected: string, question: string) => Promise<boolean>;
export interface UninstallApiOptions {
  clock?: RateClock;
  /** The terminal's typed-name question; without it nothing that needs a typed name is done. */
  askName?: AskName;
  /** The record's `central.repoId`: GitHub's id of `<owner>/pipelines` must equal it before any central write (when recorded). */
  centralRepoId?: number;
  /** V-S2 / V1-R1: a typed-trust record or a PR-body marker that differs: every delete and restore needs a typed name, `yes` too. */
  typedNames?: boolean;
}

// ---------- the routes ----------

const ROUTES = {
  repoRuleset: 'DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}',
  orgRuleset: 'DELETE /orgs/{org}/rulesets/{ruleset_id}',
  classicPut: 'PUT /repos/{owner}/{repo}/branches/{branch}/protection',
  classicDelete: 'DELETE /repos/{owner}/{repo}/branches/{branch}/protection',
  secret: 'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}',
  envSecret: 'DELETE /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}',
  variable: 'DELETE /repos/{owner}/{repo}/actions/variables/{name}',
  variablePatch: 'PATCH /repos/{owner}/{repo}/actions/variables/{name}',
  envVariable: 'DELETE /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}',
  environment: 'DELETE /repos/{owner}/{repo}/environments/{environment_name}',
  environmentPut: 'PUT /repos/{owner}/{repo}/environments/{environment_name}',
  branchPolicy: 'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}',
  actionsPermissions: 'PUT /repos/{owner}/{repo}/actions/permissions',
  vulnerabilityAlerts: 'DELETE /repos/{owner}/{repo}/vulnerability-alerts',
  repoPatch: 'PATCH /repos/{owner}/{repo}',
  actionsAccess: 'PUT /repos/{owner}/{repo}/actions/permissions/access',
  prPatch: 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}',
  refDelete: 'DELETE /repos/{owner}/{repo}/git/refs/{ref}',
} as const;
const REPO_DELETE_ROUTE = 'DELETE /repos/{owner}/{repo}';

function frozenSet(xs: readonly string[]): ReadonlySet<string> {
  const s = new Set(xs);
  const fixed = (): never => { throw new TypeError('UNINSTALL_WRITE_ROUTES is fixed.'); };
  Object.defineProperties(s, { add: { value: fixed }, delete: { value: fixed }, clear: { value: fixed } });
  return Object.freeze(s);
}
/** Every write uninstall sends besides the git data API of its PRs and the repo deletes. Nothing else is sent. */
export const UNINSTALL_WRITE_ROUTES: ReadonlySet<string> = frozenSet(Object.values(ROUTES));
/** The routes only their own function sends (an identity read, a typed name or a branch rule comes first). */
const DEDICATED: ReadonlySet<string> = new Set<string>([ROUTES.repoRuleset, ROUTES.orgRuleset, ROUTES.classicPut, ROUTES.classicDelete, ROUTES.secret, ROUTES.envSecret, ROUTES.variable, ROUTES.variablePatch, ROUTES.envVariable, ROUTES.environment, ROUTES.environmentPut, ROUTES.branchPolicy, ROUTES.prPatch, ROUTES.refDelete]);

type Body = Record<string, unknown>;
/** null when the body is one the route takes, else why not. */
type BodyCheck = (b: Body) => string | null;
const keysIn = (b: Body, allowed: readonly string[]): boolean => Object.keys(b).every((k) => allowed.includes(k));
const none: BodyCheck = (b) => (Object.keys(b).length === 0 ? null : 'it takes no body');
const bool = (v: unknown): boolean => typeof v === 'boolean';
const posId = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;

/** The keys of the classic protection PUT (classicPutForm's output). */
const CLASSIC_KEYS = ['required_status_checks', 'enforce_admins', 'required_pull_request_reviews', 'restrictions', 'allow_force_pushes', 'allow_deletions', 'required_linear_history', 'required_conversation_resolution', 'block_creations', 'lock_branch', 'allow_fork_syncing'] as const;
const classicBody: BodyCheck = (b) => {
  if (!keysIn(b, CLASSIC_KEYS)) return 'it holds a key the protection PUT doesn\'t take';
  for (const k of ['required_status_checks', 'enforce_admins', 'required_pull_request_reviews', 'restrictions']) if (!(k in b)) return `it lacks ${k}`;
  if (!bool(b.enforce_admins)) return 'enforce_admins is not true or false';
  for (const k of ['required_status_checks', 'required_pull_request_reviews', 'restrictions']) if (b[k] !== null && !isObj(b[k])) return `${k} is not an object or null`;
  for (const k of CLASSIC_KEYS.slice(4)) if (k in b && !bool(b[k])) return `${k} is not true or false`;
  return null;
};
const ENV_KEYS = ['wait_timer', 'prevent_self_review', 'reviewers', 'deployment_branch_policy', 'can_admins_bypass'] as const;
const envBody: BodyCheck = (b) => {
  if (!keysIn(b, ENV_KEYS)) return 'it holds a key the environment PUT doesn\'t take';
  if ('wait_timer' in b && !(Number.isSafeInteger(b.wait_timer) && (b.wait_timer as number) >= 0 && (b.wait_timer as number) <= 43_200)) return 'wait_timer is not 0 to 43200';
  for (const k of ['prevent_self_review', 'can_admins_bypass']) if (k in b && !bool(b[k])) return `${k} is not true or false`;
  if ('reviewers' in b && !(Array.isArray(b.reviewers) && b.reviewers.length <= 6 && b.reviewers.every((r) => isObj(r) && keysIn(r, ['type', 'id']) && (r.type === 'User' || r.type === 'Team') && posId(r.id)))) return 'reviewers is not a list of users and teams';
  if ('deployment_branch_policy' in b) {
    const p = b.deployment_branch_policy;
    if (p !== null && !(isObj(p) && keysIn(p, ['protected_branches', 'custom_branch_policies']) && bool(p.protected_branches) && bool(p.custom_branch_policies))) return 'deployment_branch_policy is not null or the two switches';
  }
  return null;
};
/** The values of GitHub's `allowed_actions` the actions-permissions PUT takes. */
const ALLOWED_ACTIONS: readonly string[] = ['all', 'local_only', 'selected'];
const STATUS = (v: unknown): boolean => isObj(v) && keysIn(v, ['status']) && (v.status === 'enabled' || v.status === 'disabled');
const BODIES: Readonly<Record<string, { repos: readonly Where[] | 'org'; body: BodyCheck }>> = {
  [ROUTES.repoRuleset]: { repos: ['app', 'central'], body: none },
  [ROUTES.orgRuleset]: { repos: 'org', body: none },
  [ROUTES.classicPut]: { repos: ['app'], body: classicBody },
  [ROUTES.classicDelete]: { repos: ['app'], body: none },
  [ROUTES.secret]: { repos: ['app', 'central'], body: none },
  [ROUTES.envSecret]: { repos: ['app'], body: none },
  [ROUTES.variable]: { repos: ['app'], body: none },
  [ROUTES.variablePatch]: { repos: ['app'], body: (b) => (keysIn(b, ['value']) && typeof b.value === 'string' && b.value.length <= 48 * 1024 ? null : 'it takes only the value, as text') },
  [ROUTES.envVariable]: { repos: ['app'], body: none },
  [ROUTES.environment]: { repos: ['app'], body: none },
  [ROUTES.environmentPut]: { repos: ['app'], body: envBody },
  [ROUTES.branchPolicy]: { repos: ['app'], body: none },
  [ROUTES.actionsPermissions]: {
    repos: ['app'],
    body: (b) => (keysIn(b, ['enabled', 'allowed_actions', 'sha_pinning_required']) && b.enabled === true && bool(b.sha_pinning_required)
      && (!('allowed_actions' in b) || ALLOWED_ACTIONS.includes(b.allowed_actions as string)) ? null : 'it takes only enabled (true), allowed_actions and sha_pinning_required'),
  },
  [ROUTES.vulnerabilityAlerts]: { repos: ['app'], body: none },
  [ROUTES.repoPatch]: {
    repos: ['app'],
    body: (b) => {
      const sa = b.security_and_analysis;
      return keysIn(b, ['security_and_analysis']) && isObj(sa) && Object.keys(sa).length > 0 && keysIn(sa, ['secret_scanning', 'secret_scanning_push_protection']) && Object.values(sa).every(STATUS)
        ? null : 'it takes only security_and_analysis (secret scanning and push protection)';
    },
  },
  [ROUTES.actionsAccess]: { repos: ['central'], body: (b) => (keysIn(b, ['access_level']) && ['none', 'user', 'organization', 'enterprise'].includes(b.access_level as string) ? null : 'it takes only access_level') },
  [ROUTES.prPatch]: { repos: ['app', 'central'], body: (b) => (keysIn(b, ['state']) && b.state === 'closed' ? null : 'it only closes the pull request') },
  [ROUTES.refDelete]: { repos: ['app', 'central'], body: none },
};


const NAME_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,199}$/;
/** A path segment that is only dots (`/./`, `/../`, at the end too): URL resolution would move the read elsewhere (sec N-M4). */
const DOT_SEGMENT_RE = /\/\.{1,2}(?=\/|$)/;
const READ_RE = /^GET (?:\/repos\/\{owner\}\/\{repo\}(?:\/[A-Za-z0-9_{}/.-]*)?|\/orgs\/\{org\}\/rulesets(?:\/\{ruleset_id\})?)$/;
/** The query keys a read takes besides its path parts (sec M1): never an Octokit option (`baseUrl`, `headers`, `request`, …). */
const QUERY_KEYS: readonly string[] = ['per_page', 'page', 'state', 'head', 'base', 'sort', 'direction', 'recursive'];
const PATH_KEYS = (route: string): string[] => [...route.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1] as string);
const lower = (v: unknown): string => String(v).toLowerCase();
const show = (s: string, n = 120): string => safeText(s, n);
const SHA_RE = /^[0-9a-f]{40}$/;
/** Where GitHub reads a CODEOWNERS file: the one central file besides this project's own that the central uninstall PR may change. */
const CODEOWNERS_PATHS: readonly string[] = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];
/** The app branches pipegen makes (deliver, update, uninstall): nothing else on the app is closed or deleted (sec I6). */
const APP_BRANCHES: readonly string[] = [SETUP_BRANCH, UPDATE_BRANCH, 'pipegen/uninstall'];
/** A central PR branch of some project of pipegen (its update or uninstall PR). */
const CENTRAL_PR_BRANCH_RE = /^pipegen\/(?:update|uninstall)-[a-z0-9][a-z0-9._-]{0,99}$/;

const validBranch = (b: unknown): b is string => { if (typeof b !== 'string') return false; try { checkBranch(b); return true; } catch { return false; } };
/** The branches of a repo uninstall may close a PR of, or delete: pipegen's own, by exact name. */
export function pipegenBranch(app: UninstallApp, where: Where, branch: unknown): boolean {
  if (!validBranch(branch)) return false;
  if (where === 'central') return branch === centralUpdateBranch(app.repo) || branch === `pipegen/uninstall-${centralProjectName(app.repo)}`;
  return APP_BRANCHES.includes(branch);
}
/** The one branch each uninstall PR comes from. */
export const uninstallBranch = (app: UninstallApp, where: Where): string => (where === 'app' ? 'pipegen/uninstall' : `pipegen/uninstall-${centralProjectName(app.repo)}`);

// ---------- identity (V-B6, V-N2, V-N7, V-S16) ----------

type RulesetEntry = InstallRecord['rulesets'][number];
type OrgEntry = NonNullable<InstallRecord['orgRuleset']>;
type SecretEntry = InstallRecord['secrets'][number];
type VariableEntry = InstallRecord['variables'][number];
type EnvEntry = InstallRecord['environments'][number];
type CodeownersEdit = Extract<InstallRecord['edits'][number], { kind: 'codeowners' | 'hooks' | 'dependabot' }>;
/** An environment's settings in the PUT form, as GitHub reports them now (readEnv) and as the preview showed them. */
export type EnvForm = Omit<EnvSettings, 'branch_policies'>;

/** One object the record says pipegen created, as uninstall would delete it. */
export type Owned =
  | { kind: 'ruleset'; entry: RulesetEntry }                       // the app's pipegen / pipegen-reviews
  | { kind: 'central-ruleset'; id: number; createdAt?: string }    // record.central.rulesetId / rulesetCreatedAt
  | { kind: 'org-ruleset'; entry: OrgEntry; centralRepoId?: number } // GitHub's id of <owner>/pipelines; deleteIfPipegens reads it itself (sec M8)
  | { kind: 'secret'; entry: SecretEntry }
  | { kind: 'variable'; entry: VariableEntry }
  /** `held`: the record's secrets and variables of that environment (environmentOwned); anything else in it keeps it (V-S5). */
  | { kind: 'environment'; entry: EnvEntry; held?: { secrets: readonly SecretEntry[]; variables: readonly VariableEntry[] } };
/** yes: pipegen's (GitHub agrees on every recorded fact); ask: can't be proved (a typed name decides); no: not the one pipegen created. */
export interface Verdict { is: 'yes' | 'ask' | 'no'; why: string }

/** An environment of the record as uninstall deletes it: with the record's own secrets and variables of that environment. */
export function environmentOwned(rec: Pick<InstallRecord, 'secrets' | 'variables'>, entry: EnvEntry): Owned {
  const scope = lower(`env:${entry.name}`);
  return { kind: 'environment', entry, held: { secrets: rec.secrets.filter((x) => lower(x.scope) === scope), variables: rec.variables.filter((x) => lower(x.scope) === scope) } };
}

const no = (why: string): Verdict => ({ is: 'no', why });
/** The recorded created_at against GitHub's (the same instant; `…Z` and `….000Z` alike). */
function dateVerdict(recorded: string | undefined, unconfirmed: true | undefined, live: unknown, what: string): Verdict {
  if (unconfirmed === true || recorded === undefined || !isoAt(recorded)) return { is: 'ask', why: `GitHub never confirmed when pipegen created ${what}, so pipegen can't prove it is the one it made` };
  const at = typeof live === 'string' ? Date.parse(live) : Number.NaN;
  if (!Number.isFinite(at)) return { is: 'ask', why: `GitHub doesn't say when ${what} was created, so pipegen can't prove it is the one it made` };
  if (at !== Date.parse(recorded)) return no(`${what} is not the one pipegen created (GitHub says it was created at another time)`);
  return { is: 'yes', why: `${what} is the one pipegen created` };
}

/** The name an object is known by (what the user types for an `ask`). */
export function ownedName(o: Owned): string {
  switch (o.kind) {
    case 'ruleset': case 'org-ruleset': case 'secret': case 'variable': case 'environment': return o.entry.name;
    case 'central-ruleset': return CENTRAL_RULESET;
  }
}

/**
 * Whether the object GitHub holds now (`live`, its GET answer) is the one the record says pipegen created. Every recorded identity fact must
 * match first (else `no`, never asked about); then the created_at decides: equal → yes, different → no, unknown on either side → ask.
 * A secret pipegen stored under the user's own key name (not PIPEGEN_) is at most `ask` (V-S12).
 */
export function isPipegens(o: Owned, live: unknown, app: UninstallApp): Verdict {
  if (!isObj(live)) return no('GitHub\'s answer about it could not be read');
  const repoName = `${app.owner}/${app.repo}`;
  switch (o.kind) {
    case 'ruleset': {
      const e = o.entry;
      const want = e.kind === 'gate' ? GATE_RULESET : e.kind === 'reviews' ? REVIEWS_RULESET : null;
      const what = `the ruleset ${show(String(e.name), 100)}`;
      if (want === null || e.name !== want) return no(`${what} is not a ruleset pipegen makes`);
      if (live.id !== e.id || live.name !== e.name) return no(`${what} (id ${e.id}) is not the one pipegen created (GitHub names another ruleset)`);
      if (live.source_type !== 'Repository' || typeof live.source !== 'string' || lower(live.source) !== lower(repoName)) return no(`${what} doesn't belong to ${show(repoName)}`);
      return dateVerdict(e.githubCreatedAt, e.unconfirmed, live.created_at, what);
    }
    case 'central-ruleset': {
      const what = `the central ruleset ${CENTRAL_RULESET}`;
      if (!posId(o.id) || live.id !== o.id || live.name !== CENTRAL_RULESET) return no(`${what} (id ${o.id}) is not the one pipegen created (GitHub names another ruleset)`);
      if (live.source_type !== 'Repository' || typeof live.source !== 'string' || lower(live.source) !== lower(`${app.owner}/${CENTRAL_REPO}`)) return no(`${what} doesn't belong to ${show(`${app.owner}/${CENTRAL_REPO}`)}`);
      return dateVerdict(o.createdAt, undefined, live.created_at, what);
    }
    case 'org-ruleset': {
      const e = o.entry;
      const what = `the org ruleset ${show(String(e.name), 100)}`;
      if (lower(e.org) !== lower(app.owner) || e.name !== requiredRulesetName(app.repo)) return no(`${what} is not this project's required-workflow rule`);
      if (live.id !== e.id || live.name !== e.name) return no(`${what} (id ${e.id}) is not the one pipegen created (GitHub names another ruleset)`);
      if (live.source_type !== 'Organization' || typeof live.source !== 'string' || lower(live.source) !== lower(app.owner)) return no(`${what} doesn't belong to the organisation ${show(app.owner)}`);
      const c = live.conditions;
      if (!isObj(c) || !keysIn(c, ['ref_name', 'repository_id'])) return no(`${what} targets repositories by more than their id`);
      const rid = c.repository_id;
      if (!isObj(rid) || !keysIn(rid, ['repository_ids']) || !Array.isArray(rid.repository_ids) || rid.repository_ids.length !== 1 || rid.repository_ids[0] !== app.repoId) return no(`${what} doesn't target exactly ${show(repoName)}`);
      const path = centralWorkflowFile(app.repo, 'required');
      const rules = Array.isArray(live.rules) ? live.rules : null;
      if (rules === null || rules.length === 0) return no(`${what} holds no required workflow`);
      for (const r of rules) {
        if (!isObj(r) || r.type !== 'workflows' || !isObj(r.parameters)) return no(`${what} holds a rule pipegen didn't add`);
        const wfs = r.parameters.workflows;
        if (!Array.isArray(wfs) || wfs.length === 0) return no(`${what} holds no required workflow`);
        if (!SHA_RE.test(e.pinnedSha)) return no(`${what}'s recorded commit is not a full sha`);
        for (const w of wfs) if (!isObj(w) || w.path !== path || w.sha !== e.pinnedSha || !posId(o.centralRepoId) || w.repository_id !== o.centralRepoId) return no(`${what} requires a workflow other than ${show(path)} at the commit pipegen pinned`);
      }
      return dateVerdict(e.githubCreatedAt, e.unconfirmed, live.created_at, what);
    }
    case 'secret': {
      const e = o.entry;
      const what = `the secret ${show(String(e.name), 100)}`;
      if (e.created !== true || e.overwritten === true) return no(`pipegen didn't create ${what}`);
      if (typeof live.name !== 'string' || lower(live.name) !== lower(e.name)) return no(`GitHub's answer names another secret than ${show(String(e.name), 100)}`);
      const v = dateVerdict(e.githubCreatedAt, e.unconfirmed, live.created_at, what);
      if (v.is === 'yes' && !e.name.startsWith('PIPEGEN_')) return { is: 'ask', why: `${what} has your own key name, so pipegen asks before deleting it` };
      return v;
    }
    case 'variable': {
      const e = o.entry;
      const what = `the variable ${show(String(e.name), 100)}`;
      if (e.created !== true) return no(`pipegen didn't create ${what}`);
      if (typeof live.name !== 'string' || lower(live.name) !== lower(e.name)) return no(`GitHub's answer names another variable than ${show(String(e.name), 100)}`);
      return dateVerdict(e.githubCreatedAt, e.unconfirmed, live.created_at, what);
    }
    case 'environment': {
      const e = o.entry;
      const what = `the environment ${show(String(e.name), 100)}`;
      if (e.created !== true) return no(`pipegen didn't create ${what}`);
      if (typeof live.name !== 'string' || lower(live.name) !== lower(e.name)) return no(`GitHub's answer names another environment than ${show(String(e.name), 100)}`);
      return dateVerdict(e.githubCreatedAt, e.unconfirmed, live.created_at, what);
    }
  }
}

// ---------- typed names (V-S13; sec I3) ----------

/** What a typed name confirms: one object to delete, or one restore. */
export type Confirmable =
  | Owned
  | { kind: 'classic'; branch: string }
  | { kind: 'environment-restore'; entry: EnvEntry }
  | { kind: 'variable-restore'; entry: VariableEntry }
  | { kind: 'branch-policy'; entry: EnvEntry; id: number };
/** A name the user typed at the terminal for one object of one UninstallApi, used up by the first call it is passed to. confirm() makes it. */
export interface TypedName { readonly name: string }
const tokens = new WeakMap<object, { api: object; key: string; used: boolean }>();

/** The object's identity (kind, repo, scope, id or name), the name the user types, and the question, built here, never by the caller. */
function askedFor(c: Confirmable, app: UninstallApp): { key: string; name: string; question: string } {
  const repo = `${app.owner}/${app.repo}`;
  const central = `${app.owner}/${CENTRAL_REPO}`;
  const str = (v: unknown, what: string): string => (typeof v === 'string' && v.length > 0 ? v : refuse(`${what} is not a name.`));
  const scoped = (scope: unknown): { key: string; text: string } => {
    const s = str(scope, 'a scope');
    if (s === 'repo') return { key: 'repo', text: `of ${repo}` };
    if (s === 'central') return { key: 'central', text: `of ${central}` };
    const env = /^env:(.+)$/.exec(s)?.[1];
    return env === undefined ? refuse('a scope is not repo, central or env:<name>.') : { key: `env:${lower(env)}`, text: `of the environment ${show(env, 100)} in ${repo}` };
  };
  const id = (v: unknown): number => (posId(v) ? v : refuse('an id is not a whole number above 0.'));
  switch (c.kind) {
    case 'ruleset': return { key: `ruleset:app:${id(c.entry.id)}`, name: str(c.entry.name, 'a ruleset'), question: `Delete the ruleset ${show(c.entry.name, 100)} (id ${c.entry.id}) of ${repo}?` };
    case 'central-ruleset': return { key: `ruleset:central:${id(c.id)}`, name: CENTRAL_RULESET, question: `Delete the ruleset ${CENTRAL_RULESET} (id ${c.id}) of ${central}? It guards the central files of every project there.` };
    case 'org-ruleset': return { key: `org-ruleset:${lower(str(c.entry.org, 'an organisation'))}:${id(c.entry.id)}`, name: str(c.entry.name, 'a ruleset'), question: `Delete the organisation ruleset ${show(c.entry.name, 100)} (id ${c.entry.id}) of ${show(c.entry.org, 40)}?` };
    case 'secret': { const s = scoped(c.entry.scope); return { key: `secret:${s.key}:${str(c.entry.name, 'a secret').toUpperCase()}`, name: c.entry.name, question: `Delete the secret ${show(c.entry.name, 100)} ${s.text}?` }; }
    case 'variable': { const s = scoped(c.entry.scope); return { key: `variable:${s.key}:${str(c.entry.name, 'a variable').toUpperCase()}`, name: c.entry.name, question: `Delete the variable ${show(c.entry.name, 100)} ${s.text}?` }; }
    case 'environment': return { key: `environment:${lower(str(c.entry.name, 'an environment'))}`, name: c.entry.name, question: `Delete the environment ${show(c.entry.name, 100)} of ${repo}, with every secret and variable in it?` };
    case 'classic': return { key: `classic:${str(c.branch, 'a branch')}`, name: c.branch, question: `Put the branch protection of ${show(c.branch, 100)} in ${repo} back as it was before pipegen?` };
    case 'environment-restore': return { key: `environment-restore:${lower(str(c.entry.name, 'an environment'))}`, name: c.entry.name, question: `Put the settings pipegen changed on the environment ${show(c.entry.name, 100)} of ${repo} back as they were before pipegen?` };
    case 'variable-restore': { const s = scoped(c.entry.scope); return { key: `variable-restore:${s.key}:${str(c.entry.name, 'a variable').toUpperCase()}`, name: c.entry.name, question: `Put the variable ${show(c.entry.name, 100)} ${s.text} back to the value it had before pipegen?` }; }
    case 'branch-policy': return { key: `branch-policy:${lower(str(c.entry.name, 'an environment'))}:${id(c.id)}`, name: c.entry.name, question: `Delete the deployment branch rule ${c.id} pipegen added to the environment ${show(c.entry.name, 100)} of ${repo}?` };
  }
}

// ---------- HTTP answers (V-S11) ----------

export type Gone = { gone: true } | { gone: false; leftover: string; manual: string };
/** A 401 or a rate stop ends the run; anything with no HTTP status is a bug or a refusal and passes through. */
function hardStop(e: unknown): void {
  if (isRateStop(e)) throw e;
  if (statusOf(e) === 401) throw (e instanceof Error && e.name === 'GitHubAccessError' ? e : githubTokenRejected());
}
/**
 * What a failed read or delete of `what` means: 404 → gone, only when `parentRead` (the parent repo, or the org's ruleset list) then
 * succeeds; else, and on a 403 or any other HTTP answer, a leftover with the exact `manual` step. 401 and rate stops are thrown.
 */
export async function goneOr(e: unknown, parentRead: () => Promise<unknown>, what: string, manual: string): Promise<Gone> {
  hardStop(e);
  const s = statusOf(e);
  if (s === undefined) throw e;
  if (s === 404) {
    try { await parentRead(); return { gone: true }; } catch (p) {
      if (p instanceof UninstallRefusal) throw p;
      hardStop(p);
      return { gone: false, leftover: `GitHub answered 404 for ${what} and pipegen couldn't read where it lives, so it can't tell "gone" from "no access"`, manual };
    }
  }
  if (s === 403) return { gone: false, leftover: `GitHub refused to change ${what} (HTTP 403): the token lacks the permission`, manual };
  return { gone: false, leftover: `GitHub refused to change ${what} (HTTP ${s})`, manual };
}

export type DeleteOutcome =
  | { status: 'deleted' } | { status: 'gone' } | { status: 'restored'; manual?: string } | { status: 'done' } | { status: 'closed' } | { status: 'not-open' }
  | { status: 'kept'; why: string; manual?: string } | { status: 'ask'; why: string } | { status: 'leftover'; why: string; manual: string };

/** A value GitHub reports when a switch or a list is off (null, false, 0, empty), at any depth. */
const isDefault = (v: unknown): boolean => v === undefined || v === null || v === false || v === 0 || v === ''
  || (Array.isArray(v) && v.length === 0) || (isObj(v) && Object.values(v).every(isDefault));
/**
 * Whether `got` (GitHub's protection now, in the PUT form) is exactly what pipegen set (`want`, its planned body): every key of `want`
 * equal, lists matched element by element, and every other key of `got` off (sec I2, M6: a rule the owner added since keeps it).
 */
export function exactlyAsSet(want: unknown, got: unknown): boolean {
  if (Array.isArray(want)) {
    if (!Array.isArray(got) || got.length !== want.length) return false;
    const used = new Set<number>();
    return want.every((w) => {
      const i = got.findIndex((g, j) => !used.has(j) && exactlyAsSet(w, g));
      if (i < 0) return false;
      used.add(i);
      return true;
    });
  }
  if (isObj(want)) return isObj(got) && Object.keys(want).every((k) => exactlyAsSet(want[k], got[k])) && Object.keys(got).every((k) => k in want || isDefault(got[k]));
  return want === got;
}
/** GitHub's link fields (`url`, `contexts_url`, …): not settings. */
const isLink = (k: string): boolean => k === 'url' || k.endsWith('_url');
/** `v` without its link fields, at any depth. */
const noLinks = (v: unknown): unknown => (Array.isArray(v) ? v.map(noLinks) : isObj(v) ? Object.fromEntries(Object.entries(v).filter(([k]) => !isLink(k)).map(([k, x]) => [k, noLinks(x)])) : v);
/** The fields of GitHub's protection answer that classicPutForm carries into the PUT form (the rest it drops). */
const CLASSIC_LIVE: Readonly<Record<string, readonly string[]>> = {
  required_status_checks: ['strict', 'contexts', 'checks'],
  required_pull_request_reviews: ['dismiss_stale_reviews', 'require_code_owner_reviews', 'required_approving_review_count', 'require_last_push_approval', 'dismissal_restrictions'],
  restrictions: ['users', 'teams', 'apps'],
  ...Object.fromEntries(['enforce_admins', ...CLASSIC_KEYS.slice(4)].map((k) => [k, ['enabled']])),
};
/**
 * The first field of GitHub's protection answer (`live`, the GET) that is on but that classicPutForm drops, so exactlyAsSet can't see it
 * (sec N-M1: `required_signatures`, `bypass_pull_request_allowances`, an app in `dismissal_restrictions`, a rule GitHub adds later); null
 * when there is none. A protection holding one is not exactly what pipegen set.
 */
export function droppedLiveField(live: unknown): string | null {
  if (!isObj(live)) return null;
  for (const [k, v] of Object.entries(live)) {
    if (isLink(k)) continue;
    const known = CLASSIC_LIVE[k];
    if (known === undefined) { if (!isDefault(noLinks(v))) return k; continue; }
    if (!isObj(v)) continue;
    for (const [f, x] of Object.entries(v)) if (!isLink(f) && !known.includes(f) && !isDefault(noLinks(x))) return `${k}.${f}`;
  }
  const rpr = live.required_pull_request_reviews;
  const dr = isObj(rpr) ? rpr.dismissal_restrictions : undefined;
  if (isObj(dr)) for (const [f, x] of Object.entries(dr)) if (!isLink(f) && f !== 'users' && f !== 'teams' && !isDefault(noLinks(x))) return `required_pull_request_reviews.dismissal_restrictions.${f}`;
  return null;
}
/** JSON with sorted keys: two answers compared by content, not key order. */
const canon = (v: unknown): string => JSON.stringify(v, (_k, x: unknown) => (isObj(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));

// ---------- the API ----------

interface Located { where: Where | 'org'; params: Record<string, unknown>; get: string; del: string; what: string; manual: string }
const ghPath = (route: string, params: Record<string, unknown>): string => route.replace(/^[A-Z]+ \//, '').replace(/\{([a-z_]+)\}/g, (_m, k: string) => String(params[k]));

/** The uninstall calls of one app (and its central repo `<owner>/pipelines` and its organisation). */
export class UninstallApi {
  readonly central: RepoRef;
  readonly clock: RateClock;
  readonly #askName: AskName | undefined;
  readonly #centralRepoId: number | undefined;
  readonly #typedNames: boolean;
  readonly #ids = new Map<Where, number>();

  constructor(readonly gh: Octokit, readonly app: UninstallApp, opts: UninstallApiOptions = {}) {
    if (!NAME_RE.test(String(app?.owner)) || !NAME_RE.test(String(app?.repo)) || !posId(app?.repoId)) refuse('the app is not a plain owner, repo and id.');
    if (lower(app.repo) === CENTRAL_REPO) refuse(`the app can't be named ${CENTRAL_REPO}: that is the name of its central repo.`);
    if (opts.centralRepoId !== undefined && !posId(opts.centralRepoId)) refuse('the recorded central repo id is not a whole number above 0.');
    this.central = { owner: app.owner, repo: CENTRAL_REPO };
    this.clock = opts.clock ?? clockOf(gh);
    this.#askName = opts.askName;
    this.#centralRepoId = opts.centralRepoId;
    this.#typedNames = opts.typedNames === true;
  }

  repoOf(where: Where): RepoRef { return where === 'app' ? { owner: this.app.owner, repo: this.app.repo } : this.central; }

  #whereOf(params: Record<string, unknown>): Where | null {
    if (lower(params.repo) === lower(this.app.repo)) return 'app';
    if (lower(params.repo) === CENTRAL_REPO) return 'central';
    return null;
  }

  /** Owner, repo, org and every path part: the app's, plain, whole ids. */
  #target(route: string, params: Record<string, unknown>, repos: readonly Where[] | 'org' | 'any'): void {
    const reading = route.startsWith('GET ');
    const keys = PATH_KEYS(route);
    if (keys.includes('owner') && lower(params.owner) !== lower(this.app.owner)) refuse(`"${show(route)}" names another owner than ${show(this.app.owner, 40)}.`);
    if (keys.includes('repo')) {
      const w = this.#whereOf(params);
      if (w === null || (repos !== 'any' && (repos === 'org' || !repos.includes(w)))) refuse(`"${show(route)}" names a repo uninstall doesn't change that way.`);
    }
    if (keys.includes('org') && (repos === 'org' || repos === 'any') && lower(params.org) !== lower(this.app.owner)) refuse(`"${show(route)}" names another organisation than ${show(this.app.owner, 40)}.`);
    if (keys.includes('org') && repos !== 'org' && repos !== 'any') refuse(`"${show(route)}" is not an org route.`);
    for (const k of keys) {
      const v = params[k];
      const ok = k === 'ruleset_id' || k === 'pull_number' || k === 'branch_policy_id' ? posId(v)
        : k === 'branch' ? validBranch(v)
          : k === 'ref' ? typeof v === 'string' && (reading ? v === 'tags' || (v === '' && route.endsWith('/git/matching-refs/{ref}')) || (v.startsWith('heads/') && validBranch(v.slice(6))) : v.startsWith('heads/') && pipegenBranch(this.app, this.#whereOf(params) ?? 'app', v.slice(6)))
            : k === 'secret_name' ? typeof v === 'string' && SECRET_NAME_RE.test(v)
              : typeof v === 'string' && NAME_RE.test(v);
      if (!ok) refuse(`"${show(route)}" has a path part that is not a plain name.`);
    }
  }

  async #send(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown }> {
    if (!route.startsWith('GET ') && interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
    try {
      const res = await withRateLimit(() => this.gh.request(route, params), this.clock);
      return { status: res.status, data: res.data };
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (statusOf(e) === 401 && !isAnonymousClient(this.gh)) throw githubTokenRejected();
      throw e;
    }
  }

  #checked(route: string, params: Record<string, unknown>): void {
    const rule = BODIES[route];
    if (!UNINSTALL_WRITE_ROUTES.has(route) || rule === undefined) refuse(`"${show(route)}" is not a write uninstall makes.`);
    const r = rule as (typeof BODIES)[string];
    this.#target(route, params, r.repos);
    const pathKeys = PATH_KEYS(route);
    const body: Body = Object.fromEntries(Object.entries(params).filter(([k]) => !pathKeys.includes(k)));
    const why = r.body(body);
    if (why !== null) refuse(`"${show(route)}" was given a body uninstall doesn't send: ${why}.`);
  }

  /** GitHub's id of the repo must be the recorded one (sec M3): the app's repoId; central's, when the record holds it. */
  #idOk(where: Where, d: unknown): number {
    const id = isObj(d) ? d.id : undefined;
    const want = where === 'app' ? this.app.repoId : this.#centralRepoId;
    const r = this.repoOf(where);
    const full = show(`${r.owner}/${r.repo}`);
    if (!posId(id)) return refuse(`GitHub's answer about ${full} holds no id, so pipegen changes nothing there.`);
    if (want !== undefined && id !== want) return refuse(`${full} is not the repo pipegen installed in (GitHub's id is ${id}, the record's ${want}), so pipegen changes nothing there.`);
    this.#ids.set(where, id);
    return id;
  }
  /** GitHub's id of `where`, read once (before the first write there) and checked against the record. */
  async #verify(where: Where): Promise<number> {
    const known = this.#ids.get(where);
    if (known !== undefined) return known;
    return this.#idOk(where, (await this.#send('GET /repos/{owner}/{repo}', { ...this.repoOf(where) })).data);
  }

  /** A GET under the app or central repo, or the org's rulesets; never the contents API; path parts and QUERY_KEYS only. Errors pass through. */
  async read(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown }> {
    if (!READ_RE.test(route) || route.includes('/contents')) refuse(`"${show(route)}" is not a read uninstall makes.`);
    // sec N-M4: a `.` or `..` segment would leave the app or central repo once the URL is resolved
    if (DOT_SEGMENT_RE.test(route)) refuse(`"${show(route)}" holds a . or .. segment.`);
    const pathKeys = PATH_KEYS(route);
    for (const [k, v] of Object.entries(params)) {
      if (pathKeys.includes(k)) continue;
      if (!QUERY_KEYS.includes(k) || !(typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) refuse(`"${show(route)}" was given ${show(k, 40)}, which is not a part of the read.`);
    }
    this.#target(route, params, 'any');
    return this.#send(route, params);
  }

  /** What a failure means (goneOr), as an outcome; a refusal passes through. */
  async #outcome(e: unknown, where: Where | 'org', what: string, manual: string): Promise<DeleteOutcome> {
    if (e instanceof UninstallRefusal) throw e;
    const g = await this.goneOr(e, where, what, manual);
    return g.gone ? { status: 'gone' } : { status: 'leftover', why: g.leftover, manual: g.manual };
  }

  /**
   * One of the settings writes of UNINSTALL_WRITE_ROUTES (actions permissions, vulnerability alerts, secret scanning, central actions
   * access); every other route is refused before it is sent. Right before it, the setting is read from GitHub, and only what is still as
   * pipegen set it is put back (sec N-M5; #settingNow); anything else is kept with the manual step. `pipegenSet` is the central Actions
   * access level finish set (`organization` for an organisation's app, `user` for a user's). A failure is mapped through goneOr (spec M3).
   */
  async write(route: string, params: Record<string, unknown>, opts: { pipegenSet?: string } = {}): Promise<DeleteOutcome> {
    if (DEDICATED.has(route)) refuse(`"${show(route)}" goes only through its own uninstall function (an identity read, a typed name or a branch rule first).`);
    this.#checked(route, params);
    const where = this.#whereOf(params) as Where;
    const pathKeys = PATH_KEYS(route);
    const path = Object.fromEntries(Object.entries(params).filter(([k]) => pathKeys.includes(k)));
    const body = Object.fromEntries(Object.entries(params).filter(([k]) => !pathKeys.includes(k)));
    const method = route.split(' ')[0] as string;
    const manual = `gh api -X ${method} ${ghPath(route, params)}${Object.keys(body).length > 0 ? ` --input - <<< '${JSON.stringify(body)}'` : ''}`;
    const what = `the setting ${show(ghPath(route, params))}`;
    try {
      await this.#verify(where);
      const now = await this.#settingNow(route, path, body, opts.pipegenSet, manual);
      if ('keep' in now) return { status: 'kept', why: `${what}: ${now.keep}, so pipegen leaves it`, ...(now.manual === null ? {} : { manual: now.manual }) };
      await this.#send(route, { ...now.send, ...path });
    } catch (e) { return this.#outcome(e, where, what, manual); }
    return { status: 'done' };
  }

  /**
   * Sec N-M5: GitHub's setting now, against what pipegen set; the body to send, or why nothing is sent with the manual step (`manual`, the
   * command of this very write, unless said otherwise; null: none). Pipegen only turns these on (the sha pin, Dependabot alerts, secret
   * scanning and push protection) or sets the central Actions access, so each is put back only while it is still that: never Actions
   * turned back on, its allowed actions changed, a switch the owner changed since, a setting that needs the one turned off, or an access
   * level another project set.
   */
  async #settingNow(route: string, path: Record<string, unknown>, body: Body, pipegenSet: string | undefined, manual: string): Promise<{ send: Body } | { keep: string; manual: string | null }> {
    const keep = (why: string, m: string | null = manual) => ({ keep: why, manual: m });
    switch (route) {
      case ROUTES.actionsPermissions: {
        const d = (await this.read('GET /repos/{owner}/{repo}/actions/permissions', path)).data;
        // sec M-r2-3: no manual step either: the command would turn Actions back on
        if (!isObj(d) || d.enabled !== true) return keep('Actions is off now (or GitHub doesn\'t say), and pipegen doesn\'t turn it back on', null);
        if ('allowed_actions' in body && body.allowed_actions !== d.allowed_actions) return keep('its allowed actions are not what pipegen read at install (changed since), and pipegen never changes them');
        // sec M-r2-2: the PUT carries GitHub's own allowed_actions (an omitted one may be reset to `all`); one pipegen doesn't know keeps it
        if (!ALLOWED_ACTIONS.includes(d.allowed_actions as string)) return keep('GitHub doesn\'t say which actions are allowed (or names a value pipegen doesn\'t know), and pipegen never changes them');
        if (d.sha_pinning_required !== true) return keep('the full-length sha pin is not on as pipegen set it (changed since, or GitHub doesn\'t say)');
        if (body.sha_pinning_required === true) return keep('already as it was before pipegen', null);
        return { send: { enabled: true, allowed_actions: d.allowed_actions, sha_pinning_required: body.sha_pinning_required } };
      }
      case ROUTES.vulnerabilityAlerts: {
        try { await this.read('GET /repos/{owner}/{repo}/vulnerability-alerts', path); } catch (e) {
          if (!(e instanceof UninstallRefusal) && statusOf(e) === 404) return keep('already off', null);
          throw e;
        }
        // sec M-r2-1: Dependabot security updates need the alerts, and GitHub turns them off with the alerts
        const both = `Dependabot security updates need Dependabot alerts: to turn both off, turn off Dependabot security updates first, then Dependabot alerts, in the repo's settings (Code security), or gh api -X DELETE ${ghPath('DELETE /repos/{owner}/{repo}/automated-security-fixes', path)}, then ${manual}`;
        let fixes: unknown;
        try { fixes = (await this.read('GET /repos/{owner}/{repo}/automated-security-fixes', path)).data; } catch (e) {
          if (e instanceof UninstallRefusal) throw e;
          hardStop(e);
          return keep('GitHub doesn\'t say whether Dependabot security updates are on (they need the alerts)', both);
        }
        if (!isObj(fixes) || fixes.enabled !== false) return keep('Dependabot security updates are on (or GitHub doesn\'t say), and turning the alerts off would turn them off too', both);
        return { send: {} };
      }
      case ROUTES.repoPatch: {
        const d = (await this.read('GET /repos/{owner}/{repo}', path)).data;
        this.#idOk('app', d);
        const sa = isObj(d) && isObj(d.security_and_analysis) ? d.security_and_analysis : {};
        const want = body.security_and_analysis as Record<string, { status: string }>;
        const send: Record<string, { status: string }> = {};
        for (const [k, v] of Object.entries(want)) {
          if (v.status !== 'disabled') return keep(`pipegen only turns ${k} on, so it never turns it on again`);
          const live = isObj(sa[k]) ? (sa[k] as { status?: unknown }).status : undefined;
          if (live !== 'enabled' && live !== 'disabled') return keep(`GitHub doesn't say whether ${k} is on`);
          if (live === 'enabled') send[k] = v;
        }
        // sec M-r2-1: every other secret_scanning switch (push protection, validity checks, non-provider patterns, …) needs secret scanning
        if ('secret_scanning' in send) {
          const on = Object.entries(sa).filter(([k, v]) => k.startsWith('secret_scanning_') && !(k in want) && isObj(v) && v.status === 'enabled')
            .map(([k]) => (/^secret_scanning_[a-z0-9_]{1,60}$/.test(k) ? k : 'another secret_scanning switch'));
          if (on.length > 0) {
            const names = on.slice(0, MAX_LISTED).join(', ');
            return keep(`${names} ${on.length === 1 ? 'is' : 'are'} on and need secret scanning`, `${names} need secret scanning: to turn secret scanning off too, turn ${on.length === 1 ? 'it' : 'them'} off first in the repo's settings (Code security), then: ${manual}`);
          }
        }
        return Object.keys(send).length === 0 ? keep('already as it was before pipegen', null) : { send: { security_and_analysis: send } };
      }
      case ROUTES.actionsAccess: {
        // sec M-r2-3: the access level is shared by every project of the central repo: the step is advice, after a check
        const shared = `Check first that no other project of ${this.app.owner}/${CENTRAL_REPO} relies on this access level, then: ${manual}`;
        if (pipegenSet !== 'organization' && pipegenSet !== 'user') return keep('pipegen doesn\'t know the access level it set', shared);
        const d = (await this.read('GET /repos/{owner}/{repo}/actions/permissions/access', path)).data;
        const live = isObj(d) ? d.access_level : undefined;
        if (live !== pipegenSet) return keep(`the access level is not the one pipegen set (${pipegenSet}): another project or the owner may rely on it`, shared);
        if (body.access_level === pipegenSet) return keep('already as it was before pipegen', null);
        return { send: body };
      }
      default: return refuse(`"${show(route)}" is not a settings write uninstall makes.`);
    }
  }

  async #dedicated(route: string, params: Record<string, unknown>): Promise<unknown> {
    this.#checked(route, params);
    const where = PATH_KEYS(route).includes('repo') ? this.#whereOf(params) : null;
    if (where !== null) await this.#verify(where);
    return (await this.#send(route, params)).data;
  }

  /** What failed means for an object of `where` (its parent: the repo, its id checked, or the org's ruleset list). */
  goneOr(e: unknown, where: Where | 'org', what: string, manual: string): Promise<Gone> {
    const parent = where === 'org'
      ? () => this.read('GET /orgs/{org}/rulesets', { org: this.app.owner, per_page: 1 })
      : async () => this.#idOk(where, (await this.read('GET /repos/{owner}/{repo}', { ...this.repoOf(where) })).data);
    return goneOr(e, parent, what, manual);
  }

  /** A typed name for `c`: the question is built here from the object and asked through the run's askName; null for another answer. */
  async confirm(c: Confirmable): Promise<TypedName | null> {
    const q = askedFor(c, this.app);
    if (this.#askName === undefined) return refuse(`${q.question} needs its name typed at the terminal, and this run has none.`);
    const ok = await this.#askName(q.name, safeText(q.question, 400));
    if (ok !== true) return null;
    const t: TypedName = Object.freeze({ name: q.name });
    tokens.set(t, { api: this, key: q.key, used: false });
    return t;
  }
  /** Uses up `t` (whatever comes next) and checks it was typed for `c` at this API's terminal; false when none was passed. */
  #take(t: TypedName | undefined, c: Confirmable): boolean {
    if (t === undefined) return false;
    const r = tokens.get(t);
    if (r === undefined || r.api !== this) return refuse('that typed name was not given at this run\'s terminal.');
    if (r.used) return refuse('a typed name counts once.');
    r.used = true;
    if (r.key !== askedFor(c, this.app).key) return refuse('the name typed was for another object.');
    return true;
  }

  #locate(o: Owned): Located {
    const app = { owner: this.app.owner, repo: this.app.repo };
    const api = (method: string, route: string, p: Record<string, unknown>) => `gh api -X ${method} ${ghPath(route, p)}`;
    switch (o.kind) {
      case 'ruleset': case 'central-ruleset': {
        const where: Where = o.kind === 'ruleset' ? 'app' : 'central';
        const params = { ...this.repoOf(where), ruleset_id: o.kind === 'ruleset' ? o.entry.id : o.id };
        return { where, params, get: 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', del: ROUTES.repoRuleset, what: `the ruleset ${show(ownedName(o), 100)}`, manual: api('DELETE', ROUTES.repoRuleset, params) };
      }
      case 'org-ruleset': {
        const params = { org: o.entry.org, ruleset_id: o.entry.id };
        if (lower(o.entry.org) !== lower(this.app.owner)) refuse('the org rule names another organisation than the app\'s owner.');
        return { where: 'org', params, get: 'GET /orgs/{org}/rulesets/{ruleset_id}', del: ROUTES.orgRuleset, what: `the org ruleset ${show(o.entry.name, 100)}`, manual: api('DELETE', ROUTES.orgRuleset, params) };
      }
      case 'secret': {
        const s = String(o.entry.scope);
        if (s === 'repo' || s === 'central') {
          const where: Where = s === 'repo' ? 'app' : 'central';
          const params = { ...this.repoOf(where), secret_name: o.entry.name };
          return { where, params, get: 'GET /repos/{owner}/{repo}/actions/secrets/{secret_name}', del: ROUTES.secret, what: `the secret ${show(o.entry.name, 100)}`, manual: `gh secret delete ${show(o.entry.name, 100)} --repo ${params.owner}/${params.repo}` };
        }
        const env = /^env:(.+)$/.exec(s)?.[1];
        if (env === undefined) refuse('a secret scope is not repo, central or env:<name>.');
        const params = { ...app, environment_name: env, secret_name: o.entry.name };
        return { where: 'app', params, get: 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', del: ROUTES.envSecret, what: `the secret ${show(o.entry.name, 100)} of ${show(String(env), 100)}`, manual: `gh secret delete ${show(o.entry.name, 100)} --env ${show(String(env), 100)} --repo ${app.owner}/${app.repo}` };
      }
      case 'variable': {
        const s = String(o.entry.scope);
        if (s === 'repo') {
          const params = { ...app, name: o.entry.name };
          return { where: 'app', params, get: 'GET /repos/{owner}/{repo}/actions/variables/{name}', del: ROUTES.variable, what: `the variable ${show(o.entry.name, 100)}`, manual: `gh variable delete ${show(o.entry.name, 100)} --repo ${app.owner}/${app.repo}` };
        }
        const env = /^env:(.+)$/.exec(s)?.[1];
        if (env === undefined) refuse('a variable scope is not repo or env:<name>.');
        const params = { ...app, environment_name: env, name: o.entry.name };
        return { where: 'app', params, get: 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}', del: ROUTES.envVariable, what: `the variable ${show(o.entry.name, 100)} of ${show(String(env), 100)}`, manual: `gh variable delete ${show(o.entry.name, 100)} --env ${show(String(env), 100)} --repo ${app.owner}/${app.repo}` };
      }
      case 'environment': {
        const params = { ...app, environment_name: o.entry.name };
        return { where: 'app', params, get: 'GET /repos/{owner}/{repo}/environments/{environment_name}', del: ROUTES.environment, what: `the environment ${show(o.entry.name, 100)}`, manual: api('DELETE', ROUTES.environment, params) };
      }
    }
  }

  /** V-S5 (sec I5), right before the DELETE: the environment holds only secrets and variables the record proves pipegen added; else kept. */
  async #foreignInEnv(o: Extract<Owned, { kind: 'environment' }>, l: Located): Promise<DeleteOutcome | null> {
    const held = o.held ?? { secrets: [], variables: [] };
    const params = { ...this.repoOf('app'), environment_name: o.entry.name, per_page: 100 };
    const foreign: string[] = [];
    const lists = [
      { kind: 'secret' as const, route: 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets', key: 'secrets', entries: held.secrets },
      { kind: 'variable' as const, route: 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables', key: 'variables', entries: held.variables },
    ];
    for (const x of lists) {
      let d: unknown;
      try { d = (await this.read(x.route, params)).data; } catch (e) { return this.#outcome(e, 'app', `the ${x.kind}s of ${l.what}`, l.manual); }
      const list = isObj(d) && Array.isArray(d[x.key]) ? (d[x.key] as unknown[]).filter(isObj) : null;
      if (list === null || !isObj(d) || typeof d.total_count !== 'number' || d.total_count > list.length) return { status: 'kept', why: `pipegen couldn't list every ${x.kind} of ${l.what}, so it doesn't delete it`, manual: l.manual };
      for (const item of list) {
        const name = typeof item.name === 'string' ? item.name : '';
        const e = (x.entries as readonly (SecretEntry | VariableEntry)[]).find((y) => y.name.toUpperCase() === name.toUpperCase());
        const ok = e !== undefined && isPipegens(x.kind === 'secret' ? { kind: 'secret', entry: e as SecretEntry } : { kind: 'variable', entry: e as VariableEntry }, item, this.app).is === 'yes';
        if (!ok) foreign.push(show(name || '(no name)', 100));
      }
    }
    if (foreign.length === 0) return null;
    return { status: 'kept', why: `${l.what} holds ${foreign.slice(0, MAX_LISTED).join(', ')}${foreign.length > MAX_LISTED ? ', …' : ''}, which pipegen didn't add (or can't prove it did); deleting the environment would delete them too, so pipegen leaves it`, manual: l.manual };
  }

  /**
   * Deletes one object the record says pipegen created, only when GitHub's answer right before the DELETE says it is (isPipegens `yes`), or
   * `ask` with `typed` (confirm() for this very object; a typed-names run asks for `yes` too). `no` → kept; `ask` without a typed name → ask
   * (nothing sent). A token passed is used up whatever the answer. An environment holding anything pipegen didn't add is kept. A 404 or 403
   * on the read or the DELETE goes through goneOr; a 404 on the DELETE is gone only when the object then reads 404 too (sec M2).
   */
  async deleteIfPipegens(o: Owned, opts: { typed?: TypedName } = {}): Promise<DeleteOutcome> {
    const l = this.#locate(o);
    this.#checked(l.del, l.params);
    const typed = this.#take(opts.typed, o);
    let live: unknown;
    try { live = (await this.read(l.get, l.params)).data; } catch (e) { return this.#outcome(e, l.where, l.what, l.manual); }
    let subject: Owned = o;
    if (o.kind === 'org-ruleset') {
      // sec M8: the pinned central repo is GitHub's (checked against the record's id), never the caller's
      try { await this.#verify('app'); subject = { ...o, centralRepoId: await this.#verify('central') }; } catch (e) { return this.#outcome(e, 'central', l.what, l.manual); }
    }
    const v = isPipegens(subject, live, this.app);
    if (v.is === 'no') return { status: 'kept', why: v.why };
    if ((v.is === 'ask' || this.#typedNames) && !typed) return { status: 'ask', why: v.is === 'ask' ? v.why : `this run asks a typed name before every delete (the record was trusted by typing, or its marker differs): ${v.why}` };
    if (o.kind === 'environment') { const k = await this.#foreignInEnv(o, l); if (k !== null) return k; }
    try { await this.#dedicated(l.del, l.params); } catch (e) {
      if (e instanceof UninstallRefusal || statusOf(e) !== 404) return this.#outcome(e, l.where, l.what, l.manual);
      try { await this.read(l.get, l.params); } catch (again) { return this.#outcome(again, l.where, l.what, l.manual); }
      return { status: 'leftover', why: `GitHub answered 404 to the delete of ${l.what} but still shows it (the token may not be allowed to delete it)`, manual: l.manual };
    }
    return { status: 'deleted' };
  }

  /**
   * Classic protection back as it was (V-B3), after the typed branch name, and only while GitHub's protection is still exactly what pipegen
   * set (`planned`, the record's planned.classic; sec I2, M6): `previous` PUT back on the recorded branch (a previous naming a path part is
   * refused, sec I1); `previous: null` (none before) → DELETE. Changed since, no plan, or gone with a previous → kept with the manual step.
   */
  async restoreClassic(cp: { branch: string; previous: Record<string, unknown> | null } | undefined, planned: RecordApiRequest | undefined, typed?: TypedName): Promise<DeleteOutcome> {
    if (cp === undefined || !isObj(cp)) return refuse('the record holds no classic protection to restore.');
    const params = { owner: this.app.owner, repo: this.app.repo, branch: cp.branch };
    const putManual = `gh api -X PUT ${ghPath(ROUTES.classicPut, params)} --input <the protection before pipegen, from the install record>`;
    const manual = cp.previous === null ? `gh api -X DELETE ${ghPath(ROUTES.classicDelete, params)}` : putManual;
    if (cp.previous === null) this.#checked(ROUTES.classicDelete, params);
    else {
      if (!isObj(cp.previous)) refuse('the recorded protection is not an object.');
      const bad = classicBody(cp.previous);
      if (bad !== null) refuse(`the recorded protection is not a body the protection PUT takes: ${bad}.`);
      this.#checked(ROUTES.classicPut, { ...cp.previous, ...params });
    }
    if (!this.#take(typed, { kind: 'classic', branch: cp.branch })) refuse(`putting the branch protection of ${show(String(cp.branch), 100)} back needs the branch name typed at the terminal.`);
    const what = `the branch protection of ${show(cp.branch, 100)}`;
    let live: unknown;
    try { live = (await this.read('GET /repos/{owner}/{repo}/branches/{branch}/protection', params)).data; } catch (e) {
      const g = await this.#outcome(e, 'app', what, manual);
      if (g.status !== 'gone' || cp.previous === null) return g;
      return { status: 'kept', why: `${what} is gone (removed since pipegen set it), so pipegen doesn't create it again`, manual: putManual };
    }
    if (planned === undefined || !isObj(planned.body) || !isObj(planned.params) || planned.params.branch !== cp.branch || !exactlyAsSet(planned.body, classicPutForm(live))) {
      return { status: 'kept', why: `${what} is not exactly as pipegen set it (changed since, or pipegen's plan is not in the record), so pipegen leaves it`, manual };
    }
    const extra = droppedLiveField(live);
    if (extra !== null) return { status: 'kept', why: `${what} holds ${show(extra, 100)}, which pipegen never sets (added since), so pipegen leaves it`, manual };
    try {
      if (cp.previous === null) { await this.#dedicated(ROUTES.classicDelete, params); return { status: 'deleted' }; }
      await this.#dedicated(ROUTES.classicPut, { ...cp.previous, ...params });
      return { status: 'restored' };
    } catch (e) { return this.#outcome(e, 'app', what, manual); }
  }

  /**
   * V-N10 (sec M7): the fields pipegen changed on an environment that was there before, back to `previous`, after the typed environment
   * name and only while GitHub's settings are exactly `shown` (what the preview's diff showed) and the environment is the recorded one.
   * The other fields are sent as GitHub holds them now. Branch and tag rules have no route here: a manual step.
   */
  async restoreEnvironment(entry: EnvEntry, shown: EnvForm, typed?: TypedName): Promise<DeleteOutcome> {
    if (!isObj(entry) || typeof entry.name !== 'string' || !NAME_RE.test(entry.name)) return refuse('an environment name is not a plain name.');
    const params = { ...this.repoOf('app'), environment_name: entry.name };
    const manual = `gh api -X PUT ${ghPath(ROUTES.environmentPut, params)} --input <the settings before pipegen, from the install record>`;
    if (!this.#take(typed, { kind: 'environment-restore', entry })) refuse(`putting the environment ${show(entry.name, 100)} back needs its name typed at the terminal.`);
    const what = `the environment ${show(entry.name, 100)}`;
    if (entry.created !== false || !isObj(entry.previous) || !Array.isArray(entry.changed) || entry.changed.length === 0) return { status: 'kept', why: `pipegen has no earlier settings of ${what} to put back` };
    let cur: Awaited<ReturnType<typeof readEnv>>;
    try { cur = await readEnv(this.gh, this.repoOf('app'), this.clock, entry.name); } catch (e) {
      const cause = isObj(e) ? (e as { cause?: unknown }).cause : undefined;
      if (cause !== undefined) return this.#outcome(cause, 'app', what, manual);
      return { status: 'kept', why: `GitHub's answer about ${what} could not be read, so pipegen leaves it`, manual };
    }
    if (cur === null) return this.#outcome(Object.assign(new Error('HTTP 404'), { status: 404 }), 'app', what, manual);
    if (isoAt(entry.githubCreatedAt) && (cur.createdAt === null || Date.parse(cur.createdAt) !== Date.parse(entry.githubCreatedAt))) return { status: 'kept', why: `${what} is not the one pipegen changed (GitHub says it was created at another time)`, manual };
    if (canon(cur.settings) !== canon(shown)) return { status: 'kept', why: `${what} changed since the preview showed it, so pipegen leaves it; run pipegen uninstall again to see it`, manual };
    const body: Record<string, unknown> = { ...cur.settings };
    const previous = entry.previous as EnvSettings;
    for (const k of ENV_KEYS) if (entry.changed.includes(k)) body[k] = previous[k];
    try { await this.#dedicated(ROUTES.environmentPut, { ...body, ...params }); } catch (e) { return this.#outcome(e, 'app', what, manual); }
    return entry.changed.includes('branch_policies')
      ? { status: 'restored', manual: `the branch and tag rules ${what} had before pipegen are in the install record; add them back in the environment's settings` }
      : { status: 'restored' };
  }

  /**
   * A repo variable pipegen changed, back to `previous` (sec M7), only while GitHub holds `pipegenValue` (the value pipegen set; unknown →
   * kept). An environment's variable has no restore route: a manual step. A typed-names run needs the typed variable name.
   */
  async restoreVariable(entry: VariableEntry, pipegenValue: string | undefined, typed?: TypedName): Promise<DeleteOutcome> {
    if (!isObj(entry) || typeof entry.name !== 'string' || !SECRET_NAME_RE.test(entry.name)) return refuse('a variable name is not a plain name.');
    const had = this.#take(typed, { kind: 'variable-restore', entry });
    if (this.#typedNames && !had) refuse(`putting the variable ${show(entry.name, 100)} back needs its name typed at the terminal in this run.`);
    const what = `the variable ${show(entry.name, 100)}`;
    if (entry.created !== false || typeof entry.previous !== 'string') return { status: 'kept', why: `pipegen has no earlier value of ${what} to put back` };
    const s = String(entry.scope);
    const env = /^env:(.+)$/.exec(s)?.[1];
    if (s !== 'repo') {
      return { status: 'leftover', why: `uninstall has no route to put back a variable of an environment (${what})`, manual: `gh variable set ${show(entry.name, 100)} --env ${show(String(env), 100)} --repo ${this.app.owner}/${this.app.repo} --body <the value before pipegen, from the install record>` };
    }
    const params = { ...this.repoOf('app'), name: entry.name };
    const manual = `gh variable set ${show(entry.name, 100)} --repo ${this.app.owner}/${this.app.repo} --body <the value before pipegen, from the install record>`;
    if (typeof pipegenValue !== 'string') return { status: 'kept', why: `pipegen doesn't know the value it set on ${what}, so it can't tell whether you changed it since`, manual };
    let live: unknown;
    try { live = (await this.read('GET /repos/{owner}/{repo}/actions/variables/{name}', params)).data; } catch (e) { return this.#outcome(e, 'app', what, manual); }
    if (!isObj(live) || live.value !== pipegenValue) return { status: 'kept', why: `${what} no longer holds the value pipegen set (changed since), so pipegen leaves it`, manual };
    try { await this.#dedicated(ROUTES.variablePatch, { value: entry.previous, ...params }); } catch (e) { return this.#outcome(e, 'app', what, manual); }
    return { status: 'restored' };
  }

  /** A deployment branch rule pipegen added to an environment (an id of the record's `branchPolicyIds` for it; sec M7). */
  async deleteBranchPolicy(entry: EnvEntry, id: number, typed?: TypedName): Promise<DeleteOutcome> {
    if (!isObj(entry) || !posId(id) || !Array.isArray(entry.branchPolicyIds) || !entry.branchPolicyIds.includes(id)) return refuse(`the branch rule ${String(id)} is not one the record says pipegen added to that environment.`);
    const had = this.#take(typed, { kind: 'branch-policy', entry, id });
    if (this.#typedNames && !had) refuse(`deleting a branch rule of ${show(String(entry.name), 100)} needs the environment name typed at the terminal in this run.`);
    const params = { ...this.repoOf('app'), environment_name: entry.name, branch_policy_id: id };
    const manual = `gh api -X DELETE ${ghPath(ROUTES.branchPolicy, params)}`;
    try { await this.#dedicated(ROUTES.branchPolicy, params); } catch (e) { return this.#outcome(e, 'app', `the branch rule ${id} of ${show(String(entry.name), 100)}`, manual); }
    return { status: 'deleted' };
  }

  /** Closes a pipegen PR: its head (read from GitHub) is a pipegen branch, by exact name, of this very repo (GitHub's id). */
  async closePr(where: Where, pr: number): Promise<DeleteOutcome> {
    if (!posId(pr)) refuse('a pull request number is not a whole number above 0.');
    const params = { ...this.repoOf(where), pull_number: pr };
    this.#checked(ROUTES.prPatch, { ...params, state: 'closed' });
    const r = this.repoOf(where);
    const what = `pull request #${pr} of ${show(`${r.owner}/${r.repo}`)}`;
    const manual = `gh pr close ${pr} --repo ${r.owner}/${r.repo}`;
    let d: unknown;
    let id: number;
    try { d = (await this.read('GET /repos/{owner}/{repo}/pulls/{pull_number}', params)).data; id = await this.#verify(where); } catch (e) { return this.#outcome(e, where, what, manual); }
    const head = isObj(d) && isObj(d.head) ? d.head : {};
    const hr = isObj(head.repo) ? head.repo : {};
    if (!isObj(d) || d.number !== pr || !pipegenBranch(this.app, where, head.ref) || hr.id !== id || typeof hr.full_name !== 'string' || lower(hr.full_name) !== lower(`${r.owner}/${r.repo}`)) {
      refuse(`${what} doesn't come from a pipegen branch of that repo, so pipegen doesn't close it.`);
    }
    if ((d as Body).state !== 'open') return { status: 'not-open' };
    try { await this.#dedicated(ROUTES.prPatch, { ...params, state: 'closed' }); } catch (e) { return this.#outcome(e, where, what, manual); }
    return { status: 'closed' };
  }

  /** Deletes a pipegen branch (pipegenBranch: exact names). */
  async deleteBranch(where: Where, branch: string): Promise<DeleteOutcome> {
    if (!pipegenBranch(this.app, where, branch)) refuse(`${show(String(branch), 100)} is not a pipegen branch uninstall may delete.`);
    const params = { ...this.repoOf(where), ref: `heads/${branch}` };
    const manual = `gh api -X DELETE ${ghPath(ROUTES.refDelete, params)}`;
    try { await this.#dedicated(ROUTES.refDelete, params); } catch (e) { return this.#outcome(e, where, `the branch ${show(branch, 100)}`, manual); }
    return { status: 'deleted' };
  }

  // ---------- the uninstall PRs ----------

  /**
   * One commit on `parent`: `files` written, `deletes` removed (a tree entry with `sha: null`). Paths are plain relative paths, each in one
   * list once; modes 100644 / 100755. On central only this project's files and record are removed (sec M5, V-B4), and the one CODEOWNERS
   * the record's central `codeowners` edit names (`recordEdits`: the record's `edits`) is the only file written, and is removed only when
   * pipegen created it and the owner didn't edit it (sec N-M3). `baseTree` must be `parent`'s tree. The branch and the PR come next
   * (setUninstallBranch, openUninstallPr).
   */
  async commitUninstall(where: Where, c: { parent: string; baseTree: string; files: readonly { path: string; content: string; mode: string }[]; deletes: readonly string[]; message: string; recordEdits?: InstallRecord['edits'] }): Promise<{ commit: string; tree: string }> {
    if (!SHA_RE.test(String(c.parent)) || !SHA_RE.test(String(c.baseTree))) refuse('a commit id is not a full sha.');
    if (c.files.length + c.deletes.length === 0) refuse('an uninstall commit changes no file.');
    const seen = new Set<string>();
    const plain = (p: unknown): string => {
      if (typeof p !== 'string' || p.length > 1024 || p.startsWith('/') || p.includes('\\') || p.split('/').some((s) => s === '' || s === '.' || s === '..' || lower(s) === '.git') || /[\0-\x1f\x7f]/.test(p)) refuse(`${show(String(p), 100)} is not a plain file path.`);
      if (seen.has(p as string)) refuse(`${show(p as string, 100)} is named twice in one commit.`);
      seen.add(p as string);
      return p as string;
    };
    let codeownersEdit: CodeownersEdit | undefined;
    const tree = [
      ...c.files.map((f) => {
        if (f.mode !== '100644' && f.mode !== '100755') refuse(`${show(String(f.path), 100)} has a mode uninstall doesn't write.`);
        if (typeof f.content !== 'string') refuse('a file\'s content is not text.');
        return { path: plain(f.path), mode: f.mode, type: 'blob', content: f.content };
      }),
      ...c.deletes.map((p) => ({ path: plain(p), mode: '100644', type: 'blob', sha: null })),
    ];
    if (where === 'central') {
      const removable = new Set([...centralFilesOf(this.app.repo), recordPath(this.app.repo)]);
      const owners = [...c.files.map((f) => f.path), ...c.deletes].filter((p) => CODEOWNERS_PATHS.includes(p));
      const eds = (Array.isArray(c.recordEdits) ? c.recordEdits : []).filter((x): x is CodeownersEdit => isObj(x) && x.repo === 'central' && x.kind === 'codeowners');
      const edit: CodeownersEdit | undefined = owners.length === 0 ? undefined
        : eds.length === 1 ? eds[0] : refuse('the record doesn\'t name exactly one central CODEOWNERS pipegen edited, so uninstall changes none.');
      codeownersEdit = edit;
      for (const f of c.files) {
        if (!CODEOWNERS_PATHS.includes(f.path)) refuse(`${show(f.path, 100)} is not a central file uninstall writes (it only puts the central CODEOWNERS back).`);
        if (f.path !== edit?.path) refuse(`${show(f.path, 100)} is not the CODEOWNERS the record says pipegen edited.`);
      }
      for (const p of c.deletes) {
        if (CODEOWNERS_PATHS.includes(p)) {
          if (p !== edit?.path) refuse(`${show(p, 100)} is not the CODEOWNERS the record says pipegen edited.`);
          if (edit === undefined || edit.originalSha !== null || edit.ownerEdited === true) refuse(`${show(p, 100)} was there before pipegen (or the owner edited it), so uninstall doesn't remove it.`);
        } else if (!removable.has(p)) refuse(`${show(p, 100)} is not a central file of this project, so uninstall doesn't remove it.`);
      }
    }
    if (typeof c.message !== 'string' || c.message.length === 0 || c.message.length > 2000) refuse('a commit message is empty or too long.');
    if (interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
    const r = this.repoOf(where);
    await this.#verify(where);
    const pc = (await this.read('GET /repos/{owner}/{repo}/git/commits/{commit_sha}', { ...r, commit_sha: c.parent })).data;
    if (!isObj(pc) || !isObj(pc.tree) || pc.tree.sha !== c.baseTree) refuse('the base tree is not the tree of the parent commit, so the commit would undo other changes.');
    const ownersGone = where === 'central' ? c.deletes.find((p) => CODEOWNERS_PATHS.includes(p)) : undefined;
    if (ownersGone !== undefined) {
      // sec M-r2-5: the record's flags are not proof: the file in the parent tree must be a version pipegen wrote (its sha in writtenShas)
      const t = (await this.read('GET /repos/{owner}/{repo}/git/trees/{tree_sha}', { ...r, tree_sha: c.baseTree, recursive: '1' })).data;
      const entries = isObj(t) && t.truncated === false && Array.isArray(t.tree) ? t.tree : [];
      const e = entries.find((x) => isObj(x) && x.path === ownersGone);
      const written = codeownersEdit !== undefined && Array.isArray(codeownersEdit.writtenShas) ? codeownersEdit.writtenShas : [];
      if (!isObj(e) || e.type !== 'blob' || typeof e.sha !== 'string' || !written.includes(e.sha)) refuse(`${show(ownersGone, 100)} on ${show(`${r.owner}/${r.repo}`)} is not a version pipegen wrote (changed since, or GitHub's file list could not be read), so uninstall doesn't remove it.`);
    }
    const t = (await ghWrite(this.gh, 'POST /repos/{owner}/{repo}/git/trees', r, { base_tree: c.baseTree, tree }, this.clock) as Body | null)?.sha;
    if (typeof t !== 'string' || !SHA_RE.test(t)) throw new UninstallRefusal('GitHub\'s answer to the new file tree could not be read.');
    const commit = (await ghWrite(this.gh, 'POST /repos/{owner}/{repo}/git/commits', r, { message: c.message, tree: t, parents: [c.parent] }, this.clock) as Body | null)?.sha;
    if (typeof commit !== 'string' || !SHA_RE.test(commit)) throw new UninstallRefusal('GitHub\'s answer to the new commit could not be read.');
    return { commit, tree: t };
  }

  /** Points the uninstall branch of `where` at `sha` (created, or moved: pipegen's own branch). */
  async setUninstallBranch(where: Where, sha: string): Promise<'created' | 'moved'> {
    if (interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
    await this.#verify(where);
    return setBranch(this.gh, this.repoOf(where), uninstallBranch(this.app, where), sha, true, this.clock);
  }

  /** Opens the uninstall PR of `where` from its branch, or updates the open one. */
  async openUninstallPr(where: Where, pr: { base: string; title: string; body: string }): Promise<{ number: number; url: string; opened: boolean }> {
    if (interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
    await this.#verify(where);
    return openOrUpdatePr(this.gh, this.repoOf(where), { head: uninstallBranch(this.app, where), base: checkBranch(pr.base), title: pr.title, body: pr.body }, this.clock);
  }

  /** The repo delete; only deleteCentralRepo calls it, after its checks. */
  async sendRepoDelete(guard: object, r: RepoRef): Promise<void> {
    if (guard !== REPO_DELETE_GUARD || r.repo !== CENTRAL_REPO || lower(r.owner) !== lower(this.app.owner)) refuse('a repo is deleted only by deleteCentralRepo.');
    await this.#send(REPO_DELETE_ROUTE, { owner: this.app.owner, repo: CENTRAL_REPO });
  }
}
const REPO_DELETE_GUARD: object = Object.freeze({});

// ---------- the central repo delete (V-B5, scan §4.5) ----------

/** `unchecked`: what pipegen couldn't read before the delete (the token's permission), named in the typed-name question (sec N-M2). */
export interface CentralDeleteResult { deleted: boolean; why?: string; command?: string; unchecked?: string[] }
/** The README GitHub's `auto_init` writes for the repo pipegen creates (`# pipelines` and its description): nothing of the user's. */
const AUTO_README = (desc: string): Set<string> => new Set([
  `# ${CENTRAL_REPO}\n${desc}`, `# ${CENTRAL_REPO}\n${desc}\n`, `# ${CENTRAL_REPO}\n\n${desc}`, `# ${CENTRAL_REPO}\n\n${desc}\n`, `# ${CENTRAL_REPO}\n`, `# ${CENTRAL_REPO}`,
].map(gitBlobSha));
const MAX_LISTED = 5;
const listed = (xs: readonly unknown[]): string => `${xs.slice(0, MAX_LISTED).map((x) => show(String(x), 100)).join(', ')}${xs.length > MAX_LISTED ? ', …' : ''}`;

/**
 * Deletes `<owner>/pipelines`, only when every one of these holds, read from GitHub right before the DELETE (and again after the typed name):
 * the exact name under the app's owner; pipegen's central marker as its description; the id the record says pipegen created it with
 * (`central.repoId`, `createdByPipegen`); no fork, the wiki and Discussions off; its default branch is its only branch; no ref but that
 * branch and pipegen's own PR refs (and the list holds that branch); no tag, no release, no commit comment, no issue, and no pull request but pipegen's own (a central pipegen branch of this
 * repo); no Actions secret but pipegen's (created_at equal), no Dependabot or Codespaces secret (a list the token can't read is named in
 * the question and in `unchecked`), no variable, no environment; no `installs/` file left (this project's record or another's); every file left is one pipegen wrote there (a
 * central file of this record at a sha it wrote, not adopted or owner-edited; the central CODEOWNERS pipegen created; GitHub's own first
 * README); the user typed `pipelines` at the terminal (`askName`). After the DELETE a read must answer 404. Else `{ deleted: false, why,
 * command }` with the `gh repo delete` command. The caller decides the token may delete repos.
 */
export async function deleteCentralRepo(gh: Octokit, central: RepoRef, rec: InstallRecord, io: { askName: AskName; clock?: RateClock }): Promise<CentralDeleteResult> {
  const owner = rec?.app?.owner;
  if (central?.repo !== CENTRAL_REPO || typeof owner !== 'string' || central.owner !== owner) refuse(`${show(`${central?.owner}/${central?.repo}`)} is not the central repo of ${show(String(owner))}.`);
  const c = rec.central;
  const api = new UninstallApi(gh, { owner: rec.app.owner, repo: rec.app.repo, repoId: rec.app.repoId }, { clock: io.clock ?? clockOf(gh), centralRepoId: posId(c?.repoId) ? c.repoId : undefined });
  const full = `${owner}/${CENTRAL_REPO}`;
  const command = `gh repo delete ${full}`;
  const notDeleted = (why: string): CentralDeleteResult => ({ deleted: false, why, command });
  if (c === undefined || c.createdByPipegen !== true || !posId(c.repoId)) return notDeleted(`pipegen has no record of creating ${full}, so it doesn't delete it`);
  const repoId = c.repoId;
  const cr = { ...api.central };

  /** One read of central, or why it can't be checked. */
  const get = async (route: string, params: Record<string, unknown>, what: string): Promise<{ data: unknown } | { why: string }> => {
    try { return { data: (await api.read(route, { ...cr, ...params })).data }; } catch (e) {
      if (e instanceof UninstallRefusal) throw e;
      hardStop(e);
      return { why: `pipegen couldn't read ${what} of ${full}` };
    }
  };
  /** Sec N-M2: the Dependabot or Codespaces secrets: none, or the list can't be read with this token (named, then asked). */
  const noSecrets = async (route: string, label: string, unread: string[]): Promise<string | null> => {
    let d: unknown;
    try { d = (await api.read(route, { ...cr, per_page: 100 })).data; } catch (e) {
      if (e instanceof UninstallRefusal) throw e;
      hardStop(e);
      const s = statusOf(e);
      if (s === 403 || s === 404) { unread.push(`its ${label} secrets`); return null; }
      return `pipegen couldn't read the ${label} secrets of ${full}, so it doesn't delete it`;
    }
    const list = isObj(d) && Array.isArray(d.secrets) ? d.secrets : null;
    if (list === null || !isObj(d) || d.total_count !== 0 || list.length > 0) return `${full} holds ${label} secrets${list !== null && list.length > 0 ? ` (${listed(list.map((x) => (isObj(x) ? x.name : '?')))})` : ' (or they could not be read)'}, so pipegen doesn't delete it`;
    return null;
  };
  /** Sec I4, N-M2: nothing else of the user's goes with the repo (tags, refs, releases, issues, PRs, secrets, variables, environments). */
  const others = async (def: string, head: string | null, unread: string[]): Promise<string | null> => {
    const tags = await get('GET /repos/{owner}/{repo}/git/matching-refs/{ref}', { ref: 'tags', per_page: 100 }, 'the tags');
    if ('why' in tags) return tags.why;
    if (!Array.isArray(tags.data) || tags.data.length > 0) return `${full} has tags, so pipegen doesn't delete it`;
    const rel = await get('GET /repos/{owner}/{repo}/releases', { per_page: 1 }, 'the releases');
    if ('why' in rel) return rel.why;
    if (!Array.isArray(rel.data) || rel.data.length > 0) return `${full} has releases, so pipegen doesn't delete it`;
    // sec M-r2-8: commit comments are the user's too, and go with the repo
    const com = await get('GET /repos/{owner}/{repo}/comments', { per_page: 1 }, 'the commit comments');
    if ('why' in com) return com.why;
    if (!Array.isArray(com.data) || com.data.length > 0) return `${full} has commit comments (or they could not be read), so pipegen doesn't delete it`;
    const iss = await get('GET /repos/{owner}/{repo}/issues', { state: 'all', per_page: 100 }, 'the issues');
    if ('why' in iss) return iss.why;
    if (!Array.isArray(iss.data) || iss.data.length >= 100) return `${full} has 100 or more issues and pull requests (or they could not be read); pipegen can't check them all, so it doesn't delete it`;
    const issues = iss.data.filter((x) => !(isObj(x) && isObj(x.pull_request)));
    if (issues.length > 0) return `${full} has issues (${listed(issues.map((x) => `#${isObj(x) ? String(x.number) : '?'}`))}), so pipegen doesn't delete it`;
    const prs = await get('GET /repos/{owner}/{repo}/pulls', { state: 'all', per_page: 100 }, 'the pull requests');
    if ('why' in prs) return prs.why;
    if (!Array.isArray(prs.data) || prs.data.length >= 100) return `${full} has 100 or more pull requests (or they could not be read); pipegen can't check them all, so it doesn't delete it`;
    const theirs = prs.data.filter((p) => !(isObj(p) && isObj(p.head) && typeof p.head.ref === 'string' && CENTRAL_PR_BRANCH_RE.test(p.head.ref) && isObj(p.head.repo) && p.head.repo.id === repoId));
    if (theirs.length > 0) return `${full} has pull requests pipegen didn't open (${listed(theirs.map((p) => `#${isObj(p) ? String(p.number) : '?'}`))}), so pipegen doesn't delete it`;
    // sec N-M2: every ref (notes, custom refs, …) is the default branch or a PR ref of pipegen's own PRs
    const ours = new Set(prs.data.map((p) => (isObj(p) && posId(p.number) ? p.number : -1)));
    const refs = await get('GET /repos/{owner}/{repo}/git/matching-refs/{ref}', { ref: '' }, 'the refs');
    if ('why' in refs) return refs.why;
    if (!Array.isArray(refs.data)) return `GitHub's list of the refs of ${full} could not be read, so pipegen doesn't delete it`;
    // sec M-r2-7: a list without the default branch (which has a commit) is not the list of every ref
    if (head !== null && !refs.data.some((r) => isObj(r) && r.ref === `refs/heads/${def}`)) return `GitHub's list of the refs of ${full} doesn't hold refs/heads/${show(def, 100)}, so pipegen can't tell it is whole and doesn't delete it`;
    const foreignRefs = refs.data.map((r) => (isObj(r) && typeof r.ref === 'string' ? r.ref : '(unreadable ref)')).filter((r) => {
      if (r === `refs/heads/${def}`) return false;
      const n = /^refs\/pull\/([1-9][0-9]{0,9})\/(?:head|merge)$/.exec(r)?.[1];
      return n === undefined || !ours.has(Number(n));
    });
    if (foreignRefs.length > 0) return `${full} holds refs pipegen didn't make (${listed(foreignRefs)}), so pipegen doesn't delete it`;
    const sec = await get('GET /repos/{owner}/{repo}/actions/secrets', { per_page: 100 }, 'the secrets');
    if ('why' in sec) return sec.why;
    const sl = isObj(sec.data) && Array.isArray(sec.data.secrets) ? sec.data.secrets.filter(isObj) : null;
    if (sl === null || !isObj(sec.data) || typeof sec.data.total_count !== 'number' || sec.data.total_count > sl.length) return `pipegen couldn't list every secret of ${full}, so it doesn't delete it`;
    const foreign = sl.filter((s) => {
      const e = rec.secrets.find((x) => x.scope === 'central' && typeof s.name === 'string' && x.name.toUpperCase() === s.name.toUpperCase());
      return e === undefined || isPipegens({ kind: 'secret', entry: e }, s, api.app).is !== 'yes';
    }).map((s) => s.name);
    if (foreign.length > 0) return `${full} holds secrets pipegen didn't add or can't prove it added (${listed(foreign)}), so pipegen doesn't delete it`;
    for (const [route, label] of [['GET /repos/{owner}/{repo}/dependabot/secrets', 'Dependabot'], ['GET /repos/{owner}/{repo}/codespaces/secrets', 'Codespaces']] as const) {
      const why = await noSecrets(route, label, unread);
      if (why !== null) return why;
    }
    const vars = await get('GET /repos/{owner}/{repo}/actions/variables', { per_page: 100 }, 'the variables');
    if ('why' in vars) return vars.why;
    if (!isObj(vars.data) || vars.data.total_count !== 0) return `${full} holds Actions variables (or they could not be read), so pipegen doesn't delete it`;
    const envs = await get('GET /repos/{owner}/{repo}/environments', { per_page: 100 }, 'the environments');
    if ('why' in envs) return envs.why;
    if (!isObj(envs.data) || envs.data.total_count !== 0) return `${full} has environments (or they could not be read), so pipegen doesn't delete it`;
    return null;
  };

  const check = async (): Promise<{ head: string | null; unread: string[] } | { why: string }> => {
    const repo = await get('GET /repos/{owner}/{repo}', {}, 'the repo itself');
    if ('why' in repo) return { why: `pipegen couldn't read ${full} before deleting it` };
    const d = repo.data;
    if (!isObj(d)) return { why: `GitHub's answer about ${full} could not be read` };
    if (d.full_name !== full || d.name !== CENTRAL_REPO || !isObj(d.owner) || d.owner.login !== owner) return { why: `GitHub's answer for ${full} names another repo, so pipegen doesn't delete it` };
    if (d.description !== helperDescription('central')) return { why: `${full} doesn't carry pipegen's marker (its description), so pipegen doesn't delete it` };
    if (d.id !== repoId) return { why: `${full} is not the repo pipegen created (its id differs from the one recorded), so pipegen doesn't delete it` };
    if (d.forks_count !== 0) return { why: `${full} has forks (or GitHub doesn't say), and they belong to whoever made them, so pipegen doesn't delete it` };
    if (d.has_wiki !== false) return { why: `${full} has its wiki turned on, and pipegen can't see whether it holds pages: check the wiki, turn it off in the repo's settings, then run pipegen again (or delete the repo yourself)` };
    if (d.has_discussions !== false) return { why: `${full} has Discussions turned on (or GitHub doesn't say), and they would go with the repo: check them, turn Discussions off in the repo's settings, then run pipegen again (or delete the repo yourself)` };
    if (typeof d.default_branch !== 'string') return { why: `GitHub doesn't say which is the default branch of ${full}` };
    const def = d.default_branch;
    const br = await get('GET /repos/{owner}/{repo}/branches', { per_page: 100 }, 'the branches');
    if ('why' in br) return { why: `pipegen couldn't list the branches of ${full}` };
    if (!Array.isArray(br.data)) return { why: `GitHub's list of the branches of ${full} could not be read` };
    const branches = br.data.map((b) => (isObj(b) ? b.name : undefined)).filter((n) => n !== def);
    if (branches.length > 0) return { why: `${full} has other branches than ${show(def, 100)} (${listed(branches)}), so pipegen doesn't delete it` };
    let head: string | null = null;
    try {
      const ref = (await api.read('GET /repos/{owner}/{repo}/git/ref/{ref}', { ...cr, ref: `heads/${def}` })).data;
      const sha = isObj(ref) && isObj(ref.object) ? ref.object.sha : undefined;
      if (typeof sha !== 'string' || !SHA_RE.test(sha)) return { why: `GitHub's answer about the branch ${show(def, 100)} of ${full} could not be read` };
      head = sha;
    } catch (e) {
      hardStop(e);
      const s = statusOf(e);
      if (s !== 404 && s !== 409) return { why: `pipegen couldn't read the branch ${show(def, 100)} of ${full}` };   // 404 / 409: no commit yet
    }
    if (head !== null) {
      let entries: Map<string, TreeEntry>;
      try { entries = (await readTree(gh, cr, head, api.clock)).entries; } catch (e) { hardStop(e); return { why: `pipegen couldn't read the files of ${full}` }; }
      const records = [...entries.keys()].filter((p) => p.startsWith('installs/'));
      if (records.length > 0) return { why: `${full} still holds an install record (${listed(records)}), so pipegen doesn't delete it` };
      const readme = AUTO_README(helperDescription('central'));
      const own = (path: string, e: TreeEntry): boolean => {
        if (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755')) return false;
        if (path === 'README.md' && readme.has(e.sha)) return true;
        if (rec.files.some((f) => f.repo === 'central' && f.path === path && f.adopted !== true && f.ownerEdited !== true && f.shas.includes(e.sha))) return true;
        return rec.edits.some((x) => x.repo === 'central' && x.kind === 'codeowners' && x.path === path && x.originalSha === null && x.ownerEdited !== true && x.writtenShas.includes(e.sha));
      };
      const foreign = [...entries].filter(([p, e]) => !own(p, e)).map(([p]) => p);
      if (foreign.length > 0) return { why: `${full} holds files pipegen didn't write (${listed(foreign)}), so pipegen doesn't delete it` };
    }
    const unread: string[] = [];
    const why = await others(def, head, unread);
    return why === null ? { head, unread } : { why };
  };

  const first = await check();
  if ('why' in first) return notDeleted(first.why);
  // sec M-r2-6: a line of its own (askTypedName cuts each line of the question at 300 characters)
  const unread = first.unread.length > 0 ? `\npipegen couldn't read ${first.unread.join(' or ')} (the token has no permission for them): whatever is there goes with it too.` : '';
  const yes = await io.askName(CENTRAL_REPO, `Delete the repo ${show(full)} (id ${repoId})? Its workflows, its history, its pull requests and everything else in it go with it, and GitHub can't undo it.${unread}`);
  if (yes !== true) return notDeleted(`the name typed was not ${CENTRAL_REPO}`);
  const again = await check();
  if ('why' in again) return notDeleted(again.why);
  if (again.head !== first.head) return notDeleted(`${full} changed while pipegen asked, so it doesn't delete it; run pipegen again`);
  if (again.unread.some((x) => !first.unread.includes(x))) return notDeleted(`pipegen could read less of ${full} than when it asked, so it doesn't delete it; run pipegen again`);
  try { await api.sendRepoDelete(REPO_DELETE_GUARD, api.central); } catch (e) {
    if (e instanceof UninstallRefusal) throw e;
    hardStop(e);
    const s = statusOf(e);
    return notDeleted(`GitHub refused to delete ${full}${s === undefined ? '' : ` (HTTP ${s})`}`);
  }
  try { await api.read('GET /repos/{owner}/{repo}', { ...cr }); } catch (e) {
    hardStop(e);
    const s = statusOf(e);
    if (s === 404) return first.unread.length > 0 ? { deleted: true, unchecked: first.unread.map((x) => `${x} of ${full} (not read before the delete)`) } : { deleted: true };
    return notDeleted(`pipegen could not confirm that ${full} is gone after the delete (GitHub answered ${s === undefined ? 'nothing' : `HTTP ${s}`}); check it`);
  }
  return notDeleted(`GitHub still shows ${full} after the delete`);
}
