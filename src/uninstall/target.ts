// v0.2 Plan V V3 (rulings V-B5, V-B6, V-S11, V-S13, V-S16, V-N2, V-N7): the one module of src/uninstall that sends a GitHub write.
//
// - UNINSTALL_WRITE_ROUTES is the fixed list of settings writes uninstall sends (the allow-list pattern of FINISH_WRITE_ROUTES, G11 carry).
//   UninstallApi checks every call before it is sent: the route is listed, the owner is the app's, the repo is the app or its central repo
//   `<owner>/pipelines` (each route names which), the org is the app's owner, every path part is a plain name or a whole id, and the body
//   holds only the keys that route takes, with the values it takes (so no Octokit option, `baseUrl`, `headers`, …, ever reaches a request).
//   A 401 stops the run (githubTokenRejected); a rate stop is rethrown; no write starts once a stop has begun (interrupting()).
// - The deletes that remove an object pipegen created (rulesets, the org rule, secrets, variables, environments) are not open through
//   `write`: deleteIfPipegens reads the object from GitHub right before the DELETE and sends it only when isPipegens says `yes` (GitHub's id,
//   name, source and created_at equal the recorded ones), or `ask` with the object's own name typed at the terminal (askTypedName: a branded,
//   single-use answer; no flag, no env var, no TTY gives one). `no` keeps the object, whatever the hash or a typed name says.
// - Classic protection is restored, never deleted blind (V-B3): restoreClassic PUTs `previous` back, or, when `previous` is null, DELETEs only
//   a protection that still holds pipegen's planned rules; both after the typed branch name.
// - PR closes and branch deletes only touch pipegen's own branches (`pipegen/*` on the app, this project's `pipegen/update-<name>` and
//   `pipegen/uninstall-<name>` on central); a PR's head is read from GitHub, never taken from the caller.
// - The uninstall PRs' files go through the git data API of src/deliver/git-data.ts (ghWrite, setBranch, openOrUpdatePr), on the one branch
//   each: `pipegen/uninstall` (app), `pipegen/uninstall-<name>` (central).
// - goneOr (V-S11): a 404 is "gone" only after a read of the parent succeeds (GitHub answers 404 for "no access" on a private repo); a 403 is
//   a leftover with the exact manual step; a 401 stops.
// - deleteCentralRepo (V-B5, scan §4.5): the one repo delete of uninstall. The scratch repo goes only through E's own scratch delete (src/proof).
// No other file of src/uninstall sends a GitHub write (a source scan in test/uninstall-target.test.ts keeps it so).
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../cli/io.js';
import { gitBlobSha } from '../create/guard.js';
import { checkBranch, ghWrite, isoAt, openOrUpdatePr, readTree, setBranch, statusOf, type RepoRef, type TreeEntry } from '../deliver/git-data.js';
import { centralProjectName, centralWorkflowFile } from '../engine/central-path.js';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { CENTRAL_RULESET, GATE_RULESET, REVIEWS_RULESET, requiredRulesetName } from '../layers/locks.js';
import { CENTRAL_REPO, helperDescription } from '../proof/target.js';
import { classicPutForm, holdsWanted, isObj } from '../deliver/settings-api.js';
import type { InstallRecord, RecordApiRequest } from '../types.js';
import { interrupting } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';

/** A call uninstall refuses to send (a route, a target or a value it doesn't take). Nothing was sent. */
export class UninstallRefusal extends Error {
  constructor(message: string) { super(message); this.name = 'UninstallRefusal'; }
}
const refuse = (msg: string): never => { throw new UninstallRefusal(msg); };

/** The app as the record names it (its repo id binds the org rule's conditions). */
export interface UninstallApp { owner: string; repo: string; repoId: number }
export type Where = 'app' | 'central';

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
const DEDICATED: ReadonlySet<string> = new Set<string>([ROUTES.repoRuleset, ROUTES.orgRuleset, ROUTES.classicPut, ROUTES.classicDelete, ROUTES.secret, ROUTES.envSecret, ROUTES.variable, ROUTES.envVariable, ROUTES.environment, ROUTES.prPatch, ROUTES.refDelete]);

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
      && (!('allowed_actions' in b) || ['all', 'local_only', 'selected'].includes(b.allowed_actions as string)) ? null : 'it takes only enabled (true), allowed_actions and sha_pinning_required'),
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
const READ_RE = /^GET (?:\/repos\/\{owner\}\/\{repo\}(?:\/[A-Za-z0-9_{}/.-]*)?|\/orgs\/\{org\}\/rulesets(?:\/\{ruleset_id\})?)$/;
const PATH_KEYS = (route: string): string[] => [...route.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1] as string);
const lower = (v: unknown): string => String(v).toLowerCase();
const show = (s: string, n = 120): string => safeText(s, n);

const validBranch = (b: unknown): b is string => { if (typeof b !== 'string') return false; try { checkBranch(b); return true; } catch { return false; } };
/** The branches of a repo uninstall may close a PR of, or delete. */
export function pipegenBranch(app: UninstallApp, where: Where, branch: unknown): boolean {
  if (!validBranch(branch)) return false;
  if (where === 'central') { const n = centralProjectName(app.repo); return branch === `pipegen/update-${n}` || branch === `pipegen/uninstall-${n}`; }
  return /^pipegen\/[A-Za-z0-9._/-]+$/.test(branch);
}
/** The one branch each uninstall PR comes from. */
export const uninstallBranch = (app: UninstallApp, where: Where): string => (where === 'app' ? 'pipegen/uninstall' : `pipegen/uninstall-${centralProjectName(app.repo)}`);

// ---------- typed names (V-S13) ----------

/** A name the user typed at the terminal, for one object, used once. Only askTypedName makes one. */
export interface TypedName { readonly name: string }
const typedNames = new WeakMap<object, { name: string; used: boolean }>();

/**
 * Asks the user to type `name`; a TypedName only for the exact name (letter case and surrounding spaces ignored) on an interactive terminal
 * (`interactive === true`). No terminal, a --yes run or another answer: null, and nothing is deleted on its strength.
 */
export async function askTypedName(io: { prompt: Prompter; interactive: boolean }, name: string, question: string): Promise<TypedName | null> {
  if (io.interactive !== true) return null;
  const got = await io.prompt.text(safeText(question, 400));
  if (typeof got !== 'string' || lower(got.trim()) !== lower(name)) return null;
  const t: TypedName = Object.freeze({ name });
  typedNames.set(t, { name, used: false });
  return t;
}
function takeTyped(t: TypedName | undefined, name: string): void {
  const rec = t === undefined ? undefined : typedNames.get(t);
  if (rec === undefined) refuse(`a delete of ${show(name)} needs its name typed at the terminal.`);
  const r = rec as { name: string; used: boolean };
  if (r.used) refuse('a typed name counts once.');
  if (lower(r.name) !== lower(name)) refuse(`the name typed was for ${show(r.name)}, not ${show(name)}.`);
  r.used = true;
}

// ---------- identity (V-B6, V-N2, V-N7, V-S16) ----------

/** One object the record says pipegen created, as uninstall would delete it. */
export type Owned =
  | { kind: 'ruleset'; entry: InstallRecord['rulesets'][number] }                                  // the app's pipegen / pipegen-reviews
  | { kind: 'central-ruleset'; id: number; createdAt?: string }                                     // record.central.rulesetId / rulesetCreatedAt
  | { kind: 'org-ruleset'; entry: NonNullable<InstallRecord['orgRuleset']>; centralRepoId: number } // centralRepoId: the live id of <owner>/pipelines
  | { kind: 'secret'; entry: InstallRecord['secrets'][number] }
  | { kind: 'variable'; entry: InstallRecord['variables'][number] }
  | { kind: 'environment'; entry: InstallRecord['environments'][number] };
/** yes: pipegen's (GitHub agrees on every recorded fact); ask: can't be proved (a typed name decides); no: not the one pipegen created. */
export interface Verdict { is: 'yes' | 'ask' | 'no'; why: string }

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
        if (!/^[0-9a-f]{40}$/.test(e.pinnedSha)) return no(`${what}'s recorded commit is not a full sha`);
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
      hardStop(p);
      return { gone: false, leftover: `GitHub answered 404 for ${what} and pipegen couldn't read where it lives, so it can't tell "gone" from "no access"`, manual };
    }
  }
  if (s === 403) return { gone: false, leftover: `GitHub refused to change ${what} (HTTP 403): the token lacks the permission`, manual };
  return { gone: false, leftover: `GitHub refused to change ${what} (HTTP ${s})`, manual };
}

export type DeleteOutcome =
  | { status: 'deleted' } | { status: 'gone' } | { status: 'restored' }
  | { status: 'kept'; why: string } | { status: 'ask'; why: string } | { status: 'leftover'; why: string; manual: string };

// ---------- the API ----------

interface Located { where: Where | 'org'; params: Record<string, unknown>; get: string; del: string; what: string; manual: string }
const ghPath = (route: string, params: Record<string, unknown>): string => route.replace(/^[A-Z]+ \//, '').replace(/\{([a-z_]+)\}/g, (_m, k: string) => String(params[k]));

/** The uninstall calls of one app (and its central repo `<owner>/pipelines` and its organisation). */
export class UninstallApi {
  readonly central: RepoRef;
  constructor(readonly gh: Octokit, readonly app: UninstallApp, readonly clock: RateClock = clockOf(gh)) {
    if (!NAME_RE.test(String(app?.owner)) || !NAME_RE.test(String(app?.repo)) || !posId(app?.repoId)) refuse('the app is not a plain owner, repo and id.');
    this.central = { owner: app.owner, repo: CENTRAL_REPO };
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
          : k === 'ref' ? typeof v === 'string' && v.startsWith('heads/') && (reading ? validBranch(v.slice(6)) : pipegenBranch(this.app, this.#whereOf(params) ?? 'app', v.slice(6)))
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

  /** A GET under the app or central repo, or the org's rulesets; never the contents API. Errors pass through. */
  async read(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown }> {
    if (!READ_RE.test(route) || route.includes('/contents')) refuse(`"${show(route)}" is not a read uninstall makes.`);
    this.#target(route, params, 'any');
    return this.#send(route, params);
  }

  /** One of UNINSTALL_WRITE_ROUTES, but those only their own function sends; anything else is refused before it is sent. */
  async write(route: string, params: Record<string, unknown>): Promise<unknown> {
    if (DEDICATED.has(route)) refuse(`"${show(route)}" goes only through its own uninstall function (an identity read, a typed name or a branch rule first).`);
    this.#checked(route, params);
    return (await this.#send(route, params)).data;
  }

  async #dedicated(route: string, params: Record<string, unknown>): Promise<unknown> {
    this.#checked(route, params);
    return (await this.#send(route, params)).data;
  }

  /** What failed means for an object of `where` (its parent: the repo, or the org's ruleset list). */
  goneOr(e: unknown, where: Where | 'org', what: string, manual: string): Promise<Gone> {
    const parent = where === 'org'
      ? () => this.read('GET /orgs/{org}/rulesets', { org: this.app.owner, per_page: 1 })
      : () => this.read('GET /repos/{owner}/{repo}', { ...this.repoOf(where) });
    return goneOr(e, parent, what, manual);
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

  /**
   * Deletes one object the record says pipegen created, only when GitHub's answer right before the DELETE says it is (isPipegens `yes`), or
   * `ask` with `typed` (askTypedName for this object's name). `no` → kept; `ask` without a typed name → ask (nothing sent). A 404 or 403 on
   * the read or the DELETE goes through goneOr. Path parts are checked before anything is sent.
   */
  async deleteIfPipegens(o: Owned, opts: { typed?: TypedName } = {}): Promise<DeleteOutcome> {
    const l = this.#locate(o);
    this.#checked(l.del, l.params);
    let live: unknown;
    try { live = (await this.read(l.get, l.params)).data; } catch (e) {
      const g = await this.goneOr(e, l.where, l.what, l.manual);
      return g.gone ? { status: 'gone' } : { status: 'leftover', why: g.leftover, manual: g.manual };
    }
    const v = isPipegens(o, live, this.app);
    if (v.is === 'no') return { status: 'kept', why: v.why };
    if (v.is === 'ask') {
      if (opts.typed === undefined) return { status: 'ask', why: v.why };
      takeTyped(opts.typed, ownedName(o));
    }
    try { await this.#dedicated(l.del, l.params); } catch (e) {
      if (e instanceof UninstallRefusal) throw e;
      const g = await this.goneOr(e, l.where, l.what, l.manual);
      return g.gone ? { status: 'gone' } : { status: 'leftover', why: g.leftover, manual: g.manual };
    }
    return { status: 'deleted' };
  }

  /**
   * Classic protection back as it was (V-B3), after the typed branch name: `previous` PUT back as recorded; `previous: null` (none before)
   * → DELETE, only when GitHub's protection still holds pipegen's planned rules (`planned`, the record's planned.classic), else kept.
   */
  async restoreClassic(cp: { branch: string; previous: Record<string, unknown> | null } | undefined, planned: RecordApiRequest | undefined, typed?: TypedName): Promise<DeleteOutcome> {
    if (cp === undefined || !isObj(cp)) return refuse('the record holds no classic protection to restore.');
    const params = { owner: this.app.owner, repo: this.app.repo, branch: cp.branch };
    const manual = cp.previous === null ? `gh api -X DELETE ${ghPath(ROUTES.classicDelete, params)}` : `gh api -X PUT ${ghPath(ROUTES.classicPut, params)} --input <the previous protection>`;
    if (cp.previous === null) this.#checked(ROUTES.classicDelete, params);
    else { if (!isObj(cp.previous)) refuse('the recorded protection is not an object.'); this.#checked(ROUTES.classicPut, { ...params, ...cp.previous }); }
    takeTyped(typed, cp.branch);
    const what = `the branch protection of ${show(cp.branch, 100)}`;
    let live: unknown = null;
    try { live = (await this.read('GET /repos/{owner}/{repo}/branches/{branch}/protection', params)).data; } catch (e) {
      const g = await this.goneOr(e, 'app', what, manual);
      if (!g.gone) return { status: 'leftover', why: g.leftover, manual: g.manual };
      if (cp.previous === null) return { status: 'gone' };
      live = null;
    }
    try {
      if (cp.previous === null) {
        if (planned === undefined || !isObj(planned.body) || !holdsWanted(planned.body, classicPutForm(live))) return { status: 'kept', why: `${what} is not as pipegen set it, so pipegen leaves it` };
        await this.#dedicated(ROUTES.classicDelete, params);
        return { status: 'deleted' };
      }
      await this.#dedicated(ROUTES.classicPut, { ...params, ...cp.previous });
      return { status: 'restored' };
    } catch (e) {
      if (e instanceof UninstallRefusal) throw e;
      const g = await this.goneOr(e, 'app', what, manual);
      return g.gone ? { status: 'gone' } : { status: 'leftover', why: g.leftover, manual: g.manual };
    }
  }

  /** Closes a pipegen PR: its head (read from GitHub) is a pipegen branch of this very repo. Already closed → nothing sent. */
  async closePr(where: Where, pr: number): Promise<{ closed: boolean }> {
    if (!posId(pr)) refuse('a pull request number is not a whole number above 0.');
    const params = { ...this.repoOf(where), pull_number: pr };
    this.#checked(ROUTES.prPatch, { ...params, state: 'closed' });
    const d = (await this.read('GET /repos/{owner}/{repo}/pulls/{pull_number}', params)).data;
    const head = isObj(d) && isObj(d.head) ? d.head : {};
    const full = isObj(head.repo) ? head.repo.full_name : undefined;
    const r = this.repoOf(where);
    if (!isObj(d) || d.number !== pr || !pipegenBranch(this.app, where, head.ref) || typeof full !== 'string' || lower(full) !== lower(`${r.owner}/${r.repo}`)) {
      refuse(`pull request #${pr} of ${show(`${r.owner}/${r.repo}`)} doesn't come from a pipegen branch of that repo, so pipegen doesn't close it.`);
    }
    if ((d as Body).state !== 'open') return { closed: false };
    await this.#dedicated(ROUTES.prPatch, { ...params, state: 'closed' });
    return { closed: true };
  }

  /** Deletes a pipegen branch (pipegenBranch). */
  async deleteBranch(where: Where, branch: string): Promise<void> {
    if (!pipegenBranch(this.app, where, branch)) refuse(`${show(String(branch), 100)} is not a pipegen branch uninstall may delete.`);
    await this.#dedicated(ROUTES.refDelete, { ...this.repoOf(where), ref: `heads/${branch}` });
  }

  // ---------- the uninstall PRs ----------

  /**
   * One commit on `parent`: `files` written, `deletes` removed (a tree entry with `sha: null`). Paths are plain relative paths, each in one
   * list once; modes 100644 / 100755. The branch and the PR come next (setUninstallBranch, openUninstallPr).
   */
  async commitUninstall(where: Where, c: { parent: string; baseTree: string; files: readonly { path: string; content: string; mode: string }[]; deletes: readonly string[]; message: string }): Promise<{ commit: string; tree: string }> {
    const SHA = /^[0-9a-f]{40}$/;
    if (!SHA.test(String(c.parent)) || !SHA.test(String(c.baseTree))) refuse('a commit id is not a full sha.');
    if (c.files.length + c.deletes.length === 0) refuse('an uninstall commit changes no file.');
    const seen = new Set<string>();
    const plain = (p: unknown): string => {
      if (typeof p !== 'string' || p.length > 1024 || p.startsWith('/') || p.includes('\\') || p.split('/').some((s) => s === '' || s === '.' || s === '..' || lower(s) === '.git') || /[\0-\x1f\x7f]/.test(p)) refuse(`${show(String(p), 100)} is not a plain file path.`);
      if (seen.has(p as string)) refuse(`${show(p as string, 100)} is named twice in one commit.`);
      seen.add(p as string);
      return p as string;
    };
    const tree = [
      ...c.files.map((f) => {
        if (f.mode !== '100644' && f.mode !== '100755') refuse(`${show(String(f.path), 100)} has a mode uninstall doesn't write.`);
        if (typeof f.content !== 'string') refuse('a file\'s content is not text.');
        return { path: plain(f.path), mode: f.mode, type: 'blob', content: f.content };
      }),
      ...c.deletes.map((p) => ({ path: plain(p), mode: '100644', type: 'blob', sha: null })),
    ];
    if (typeof c.message !== 'string' || c.message.length === 0 || c.message.length > 2000) refuse('a commit message is empty or too long.');
    if (interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
    const r = this.repoOf(where);
    const t = (await ghWrite(this.gh, 'POST /repos/{owner}/{repo}/git/trees', r, { base_tree: c.baseTree, tree }, this.clock) as Body | null)?.sha;
    if (typeof t !== 'string' || !SHA.test(t)) throw new UninstallRefusal('GitHub\'s answer to the new file tree could not be read.');
    const commit = (await ghWrite(this.gh, 'POST /repos/{owner}/{repo}/git/commits', r, { message: c.message, tree: t, parents: [c.parent] }, this.clock) as Body | null)?.sha;
    if (typeof commit !== 'string' || !SHA.test(commit)) throw new UninstallRefusal('GitHub\'s answer to the new commit could not be read.');
    return { commit, tree: t };
  }

  /** Points the uninstall branch of `where` at `sha` (created, or moved: pipegen's own branch). */
  async setUninstallBranch(where: Where, sha: string): Promise<'created' | 'moved'> {
    if (interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
    return setBranch(this.gh, this.repoOf(where), uninstallBranch(this.app, where), sha, true, this.clock);
  }

  /** Opens the uninstall PR of `where` from its branch, or updates the open one. */
  async openUninstallPr(where: Where, pr: { base: string; title: string; body: string }): Promise<{ number: number; url: string; opened: boolean }> {
    if (interrupting()) refuse('a stop has begun; uninstall sends nothing more.');
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

export interface CentralDeleteResult { deleted: boolean; why?: string; command?: string }
/** The README GitHub's `auto_init` writes for the repo pipegen creates (`# pipelines` and its description): nothing of the user's. */
const AUTO_README = (desc: string): Set<string> => new Set([`# ${CENTRAL_REPO}\n${desc}`, `# ${CENTRAL_REPO}\n${desc}\n`, `# ${CENTRAL_REPO}\n`, `# ${CENTRAL_REPO}`].map(gitBlobSha));
const MAX_LISTED = 5;

/**
 * Deletes `<owner>/pipelines`, only when every one of these holds, read from GitHub right before the DELETE (and again after the typed name):
 * the exact name under the app's owner; pipegen's central marker as its description; the id the record says pipegen created it with
 * (`central.repoId`, `createdByPipegen`); its default branch is its only branch; no `installs/` file is left (this project's record or
 * another's); every file left is one pipegen wrote there (a central file of this record at a sha it wrote, not adopted or owner-edited; the
 * central CODEOWNERS pipegen created; GitHub's own first README); the user typed `pipelines` at the terminal. After the DELETE a read must
 * answer 404. Else `{ deleted: false, why, command }` with the `gh repo delete` command. The caller decides the token may delete repos.
 */
export async function deleteCentralRepo(gh: Octokit, central: RepoRef, rec: InstallRecord, io: { prompt: Prompter; interactive: boolean; clock?: RateClock }): Promise<CentralDeleteResult> {
  const owner = rec?.app?.owner;
  if (central?.repo !== CENTRAL_REPO || typeof owner !== 'string' || central.owner !== owner) refuse(`${show(`${central?.owner}/${central?.repo}`)} is not the central repo of ${show(String(owner))}.`);
  const api = new UninstallApi(gh, { owner: rec.app.owner, repo: rec.app.repo, repoId: rec.app.repoId }, io.clock ?? clockOf(gh));
  const full = `${owner}/${CENTRAL_REPO}`;
  const command = `gh repo delete ${full}`;
  const notDeleted = (why: string): CentralDeleteResult => ({ deleted: false, why, command });
  const c = rec.central;
  if (c === undefined || c.createdByPipegen !== true || !posId(c.repoId)) return notDeleted(`pipegen has no record of creating ${full}, so it doesn't delete it`);
  const repoId = c.repoId;

  const check = async (): Promise<{ head: string | null } | { why: string }> => {
    let d: unknown;
    try { d = (await api.read('GET /repos/{owner}/{repo}', { ...api.central })).data; } catch (e) { hardStop(e); return { why: `pipegen couldn't read ${full} before deleting it` }; }
    if (!isObj(d)) return { why: `GitHub's answer about ${full} could not be read` };
    if (d.full_name !== full || d.name !== CENTRAL_REPO || !isObj(d.owner) || d.owner.login !== owner) return { why: `GitHub's answer for ${full} names another repo, so pipegen doesn't delete it` };
    if (d.description !== helperDescription('central')) return { why: `${full} doesn't carry pipegen's marker (its description), so pipegen doesn't delete it` };
    if (d.id !== repoId) return { why: `${full} is not the repo pipegen created (its id differs from the one recorded), so pipegen doesn't delete it` };
    if (typeof d.default_branch !== 'string') return { why: `GitHub doesn't say which is the default branch of ${full}` };
    const def = d.default_branch;
    let branches: unknown;
    try { branches = (await api.read('GET /repos/{owner}/{repo}/branches', { ...api.central, per_page: 100 })).data; } catch (e) { hardStop(e); return { why: `pipegen couldn't list the branches of ${full}` }; }
    if (!Array.isArray(branches)) return { why: `GitHub's list of the branches of ${full} could not be read` };
    const others = branches.map((b) => (isObj(b) ? b.name : undefined)).filter((n) => n !== def);
    if (others.length > 0) return { why: `${full} has other branches than ${show(def, 100)} (${others.slice(0, MAX_LISTED).map((n) => show(String(n), 100)).join(', ')}), so pipegen doesn't delete it` };
    let head: string | null = null;
    try {
      const ref = (await api.read('GET /repos/{owner}/{repo}/git/ref/{ref}', { ...api.central, ref: `heads/${def}` })).data;
      const sha = isObj(ref) && isObj(ref.object) ? ref.object.sha : undefined;
      if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) return { why: `GitHub's answer about the branch ${show(def, 100)} of ${full} could not be read` };
      head = sha;
    } catch (e) {
      hardStop(e);
      const s = statusOf(e);
      if (s !== 404 && s !== 409) return { why: `pipegen couldn't read the branch ${show(def, 100)} of ${full}` };   // 404 / 409: no commit yet
    }
    if (head === null) return { head };
    let entries: Map<string, TreeEntry>;
    try { entries = (await readTree(gh, api.central, head, api.clock)).entries; } catch (e) { hardStop(e); return { why: `pipegen couldn't read the files of ${full}` }; }
    const records = [...entries.keys()].filter((p) => p.startsWith('installs/'));
    if (records.length > 0) return { why: `${full} still holds an install record (${records.slice(0, MAX_LISTED).map((p) => show(p, 100)).join(', ')}), so pipegen doesn't delete it` };
    const readme = AUTO_README(helperDescription('central'));
    const own = (path: string, e: TreeEntry): boolean => {
      if (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755')) return false;
      if (path === 'README.md' && readme.has(e.sha)) return true;
      if (rec.files.some((f) => f.repo === 'central' && f.path === path && f.adopted !== true && f.ownerEdited !== true && f.shas.includes(e.sha))) return true;
      return rec.edits.some((x) => x.repo === 'central' && x.kind === 'codeowners' && x.path === path && x.originalSha === null && x.ownerEdited !== true && x.writtenShas.includes(e.sha));
    };
    const foreign = [...entries].filter(([p, e]) => !own(p, e)).map(([p]) => p);
    if (foreign.length > 0) return { why: `${full} holds files pipegen didn't write (${foreign.slice(0, MAX_LISTED).map((p) => show(p, 100)).join(', ')}${foreign.length > MAX_LISTED ? ', …' : ''}), so pipegen doesn't delete it` };
    return { head };
  };

  const first = await check();
  if ('why' in first) return notDeleted(first.why);
  const typed = await askTypedName(io, CENTRAL_REPO, `Type ${CENTRAL_REPO} to delete the repo ${show(full)} (its workflows and its history go with it)`);
  if (typed === null) return notDeleted(io.interactive === true ? `the name typed was not ${CENTRAL_REPO}` : `deleting ${full} needs its name typed at an interactive terminal`);
  takeTyped(typed, CENTRAL_REPO);
  const again = await check();
  if ('why' in again) return notDeleted(again.why);
  if (again.head !== first.head) return notDeleted(`${full} changed while pipegen asked, so it doesn't delete it; run pipegen again`);
  try { await api.sendRepoDelete(REPO_DELETE_GUARD, api.central); } catch (e) {
    if (e instanceof UninstallRefusal) throw e;
    hardStop(e);
    const s = statusOf(e);
    return notDeleted(`GitHub refused to delete ${full}${s === undefined ? '' : ` (HTTP ${s})`}`);
  }
  try { await api.read('GET /repos/{owner}/{repo}', { ...api.central }); } catch (e) {
    hardStop(e);
    if (statusOf(e) === 404) return { deleted: true };
  }
  return notDeleted(`GitHub still shows ${full} after the delete`);
}
