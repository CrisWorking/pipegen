// Plan E E1 (ruling S3; threats T12, T21): the proof's target and the scratch-only write guard. The proof writes to
// exactly two repos of the app's owner: the private scratch repo `pipegen-proof-<repo>`, which holds the user's real test
// keys during the proof, and, for a few listed operations, the private central repo `pipelines`. Never to the app repo,
// never to any other repo. Every GitHub write in src/proof goes through this module, now and in E2-E8:
//
// - proofTarget(app) builds the run's ProofTarget: the names come from the app's owner and repo (validated like
//   client.ts and git.ts: EMU `_` logins stay refused until E9), the scratch name fits GitHub's 100-character limit, the
//   app's default branch is a branch name git accepts, and runId is YYYYMMDD-HHMMSS-<6 hex>. The object is frozen and
//   registered: a copy or a look-alike with the same fields is not a ProofTarget.
// - assertScratch(t, app) / assertCentral(t, app) give a GuardedRepo, the only thing a write takes. They refuse a target
//   this module didn't make, a target made for another app, the app repo itself, and any repo but the exact scratch or
//   central name under the app's owner. A GuardedRepo is frozen and registered too, so it can't be forged or edited.
// - guardedWrite(gh, repo, route, params) is the one choke point: it checks the handle again, refuses to start once a
//   stop has begun (the sticky interrupting() gate, E0b), takes only a write route under /repos/{owner}/{repo} whose
//   owner and repo it fills in itself, refuses Octokit's reserved options (baseUrl, headers, request, url, …) and path
//   values with dot segments, and then applies the per-repo rules:
//     scratch: the sections in SCRATCH_SECTIONS; never the repo delete (E8 adds it with the exact name and the
//       "pipegen created it" marker, ruling S3), never a visibility change but to private, never a transfer, fork,
//       collaborator, webhook, deploy key, dispatch (no workflow_dispatch, plan Global Constraints) or Actions access change;
//     central: make it private (the literal { private: true }, ruling M1), set its Actions access level to this owner
//       type's (the plan's ensureActionsAccess; ruling E1-R1), and create, move or delete refs/heads/proof/<runId>
//       (S3, S21). Nothing else.
//   The stop gate is checked again inside the call withRateLimit retries (review I1), so a stop that begins during a
//   rate-limit wait sends nothing more.
// - githubRead is the one generic read (GET routes only, review M3).
// - createHelperRepo(gh, repo, login) is the one repo create (App mode only, decided by the caller; ruling S19): the
//   name is the guarded one, a personal account's create needs the token's login to be the owner (POST /user/repos
//   makes the repo under the login), and GitHub's answer must name that repo and say private.
// - Secrets (E4; threat T12; carries G1 and E1-R5): guardedWrite refuses every secret write (any non-DELETE route with a
//   /secrets path part). The ONE way a secret value reaches the scratch repo is scratchSecretSink(gh, access), which takes
//   the result of checkScratchAccess (repos.ts) as a branded argument: only that function brands a result (it takes the
//   issuer below once, at load), a brand is used for one store batch only, and it is good for ACCESS_CHECK_MAX_AGE_MS. So
//   the pre-store re-check can't be skipped or reused. deleteScratchSecret is the one write allowed while stopping: it
//   only removes a key (E8's Ctrl-C cleanup).
// Later tasks extend SCRATCH_SECTIONS (or add a dedicated function here) under review; they never call Octokit writes
// themselves (a source scan in test/proof-repos.test.ts checks src/proof).
import { randomBytes } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { checkRepoNames, clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import type { RepoProfile } from '../types.js';
import { interrupting } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import type { SecretSink } from '../create/secrets.js';
import { pushUrl } from './git.js';

export const SCRATCH_PREFIX = 'pipegen-proof-';
export const CENTRAL_REPO = 'pipelines';
/** GitHub's limit for a repo name (S9). */
export const MAX_REPO_NAME = 100;
/** The longest app repo name whose scratch name still fits. */
export const MAX_APP_REPO_NAME = MAX_REPO_NAME - SCRATCH_PREFIX.length;
const RUN_ID_RE = /^\d{8}-\d{6}-[0-9a-f]{6}$/;

/** A stop the CLI shows as it is (plain text, built from validated names). The proof does not go on. */
export class ProofStopError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProofStopError';
  }
}

/** A write the guard refused. Always a bug or an attack, never a user mistake: nothing was sent. */
export class ScratchGuardError extends Error {
  constructor(message: string) {
    super(`pipegen refused a GitHub write: ${message}`);
    this.name = 'ScratchGuardError';
  }
}

/** What the proof needs to know about the app repo. */
export type ProofApp = Pick<RepoProfile, 'owner' | 'repo' | 'private' | 'ownerType' | 'defaultBranch'>;
export interface AppRef { owner: string; repo: string }
export interface RepoRef { owner: string; repo: string }

/** The run's proof target. Only proofTarget makes one (isProofTarget). */
export interface ProofTarget {
  readonly owner: string;
  readonly appRepo: string;
  /** `pipegen-proof-<appRepo>`. */
  readonly scratch: string;
  readonly central: typeof CENTRAL_REPO;
  /** Always the app's default branch (ruling S1): the scratch repo's default branch is set to it. */
  readonly defaultBranch: string;
  readonly ownerType: RepoProfile['ownerType'];
  readonly appPrivate: boolean;
  /** YYYYMMDD-HHMMSS-<6 hex> (S3); central writes are limited to refs/heads/proof/<runId>. */
  readonly runId: string;
}

/** A repo the guard checked for this target. Only assertScratch / assertCentral make one. */
export interface GuardedRepo {
  readonly kind: 'scratch' | 'central';
  readonly owner: string;
  readonly repo: string;
  readonly fullName: string;
  readonly target: ProofTarget;
}

const targets = new WeakSet<object>();
const guarded = new WeakSet<object>();

/** A branch name git accepts (git check-ref-format, the parts that matter here), at most 255 characters. */
export function validBranchName(b: string): boolean {
  return /^[A-Za-z0-9._/-]{1,255}$/.test(b) && !b.startsWith('-') && !b.startsWith('/') && !b.endsWith('/') && !b.endsWith('.')
    && !b.includes('..') && !b.includes('//') && !b.split('/').some((p) => p.startsWith('.') || p.endsWith('.lock'));
}

/** YYYYMMDD-HHMMSS-<6 hex>, in UTC. */
export function newRunId(now: Date = new Date(), bytes: Uint8Array = randomBytes(3)): string {
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  const hex = Buffer.from(bytes.subarray(0, 3)).toString('hex');
  return `${p(now.getUTCFullYear(), 4)}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}-${p(now.getUTCHours())}${p(now.getUTCMinutes())}${p(now.getUTCSeconds())}-${hex}`;
}

/**
 * The run's target. Throws ProofStopError when the scratch name would pass GitHub's 100-character limit, when the app
 * repo is named `pipelines` (the central repo's name), when the default branch isn't a branch name git accepts, or when
 * `opts.runId` isn't one of newRunId's; GitHubAccessError when the owner or repo isn't a GitHub name.
 */
export function proofTarget(app: ProofApp, opts: { runId?: string } = {}): ProofTarget {
  const scratch = `${SCRATCH_PREFIX}${app.repo}`;
  if (scratch.length > MAX_REPO_NAME) {
    throw new ProofStopError(`The scratch repo name ${SCRATCH_PREFIX}${safeText(app.repo, 120)} is longer than GitHub's 100-character limit, `
      + `so pipegen can't prove this repo. A repo name of at most ${MAX_APP_REPO_NAME} characters fits.`);
  }
  checkRepoNames(app.owner, [app.repo, scratch, CENTRAL_REPO]);
  if (app.repo.toLowerCase() === CENTRAL_REPO) {
    throw new ProofStopError(`The app repo is named ${CENTRAL_REPO}, which is the name of pipegen's central repo, so pipegen can't prove it.`);
  }
  if (!validBranchName(app.defaultBranch)) {
    throw new ProofStopError(`The default branch "${safeText(app.defaultBranch, 100)}" isn't a branch name pipegen can use.`);
  }
  const runId = opts.runId ?? newRunId();
  if (!RUN_ID_RE.test(runId)) throw new ProofStopError('The proof run id is not of the form YYYYMMDD-HHMMSS-<6 hex>.');
  const t: ProofTarget = Object.freeze({
    owner: app.owner, appRepo: app.repo, scratch, central: CENTRAL_REPO, defaultBranch: app.defaultBranch,
    ownerType: app.ownerType, appPrivate: app.private, runId,
  });
  targets.add(t);
  return t;
}

export const isProofTarget = (x: unknown): x is ProofTarget => typeof x === 'object' && x !== null && targets.has(x);
const isGuarded = (x: unknown): x is GuardedRepo => typeof x === 'object' && x !== null && guarded.has(x);

/** Throws ScratchGuardError unless `r` is a handle assertScratch / assertCentral made (of `kind`, when given). For reads before a write. */
export function requireGuarded(r: GuardedRepo, kind?: GuardedRepo['kind']): void {
  if (!isGuarded(r)) refuse('the repo handle was not made by assertScratch or assertCentral.');
  if (kind !== undefined && r.kind !== kind) refuse(`this write is for the ${kind} repo only, not ${r.fullName}.`);
}

function checkTarget(t: ProofTarget, app: AppRef): void {
  if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
  if (typeof app?.owner !== 'string' || typeof app.repo !== 'string' || app.owner !== t.owner || app.repo !== t.appRepo) {
    throw new ScratchGuardError('the proof target was made for another repo.');
  }
}

function guard(kind: GuardedRepo['kind'], t: ProofTarget, app: AppRef, repo?: RepoRef): GuardedRepo {
  checkTarget(t, app);
  const name = kind === 'scratch' ? t.scratch : t.central;
  const want = repo ?? { owner: t.owner, repo: name };
  if (typeof want.owner !== 'string' || typeof want.repo !== 'string') throw new ScratchGuardError('the repo is not named.');
  const isApp = want.repo.toLowerCase() === t.appRepo.toLowerCase();
  if (isApp || want.owner !== t.owner || want.repo !== name) {
    throw new ScratchGuardError(isApp ? 'the app repo itself is never a proof write target.'
      : `only ${t.owner}/${name} is allowed here, not ${safeText(`${want.owner}/${want.repo}`, 160)}.`);
  }
  const g: GuardedRepo = Object.freeze({ kind, owner: t.owner, repo: name, fullName: `${t.owner}/${name}`, target: t });
  guarded.add(g);
  return g;
}

/**
 * The scratch repo of this target, checked (ruling S3): exactly `<owner>/pipegen-proof-<app.repo>`, never the app repo.
 * `repo`, when given, must name exactly that repo. The result is what every scratch write takes.
 */
export function assertScratch(t: ProofTarget, app: AppRef, repo?: RepoRef): GuardedRepo {
  return guard('scratch', t, app, repo);
}

/** The central repo `<owner>/pipelines` of this target, checked. Only the operations guardedWrite lists for it pass. */
export function assertCentral(t: ProofTarget, app: AppRef, repo?: RepoRef): GuardedRepo {
  return guard('central', t, app, repo);
}

/** The checked git push URL of a guarded repo (git.ts's pushUrl), for E2's pushes. */
export function scratchPushUrl(r: GuardedRepo): string {
  requireGuarded(r);
  return pushUrl(r.owner, r.target.appRepo, r.kind);
}

// ---------- the write choke point ----------

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/** Octokit request options (and the two names the guard fills in): never taken from a caller. */
const RESERVED = new Set(['owner', 'repo', 'baseUrl', 'headers', 'request', 'method', 'url', 'mediaType', 'data']);
const ROUTE_RE = /^(POST|PUT|PATCH|DELETE) \/repos\/\{owner\}\/\{repo\}((?:\/(?:[a-z0-9_-]+|\{[a-z_]+\}))*)$/;
const PATH_VALUE_RE = /^[A-Za-z0-9._/-]{1,255}$/;
/**
 * The scratch repo's write sections (the first path part after /repos/{owner}/{repo}). E2-E8 need git data and refs,
 * PRs and merges, secrets and variables, workflow disable/enable, run cancel/re-run/delete, caches, code scanning
 * analyses (S18), Dependabot security fixes off (S5) and environments. `actions` sub-paths in SCRATCH_ACTIONS_DENIED are refused.
 */
const SCRATCH_SECTIONS = new Set(['git', 'pulls', 'actions', 'code-scanning', 'automated-security-fixes', 'vulnerability-alerts', 'environments', 'contents']);
const SCRATCH_ACTIONS_DENIED = /\/dispatches$|^\/actions\/permissions(?:\/|$)|^\/actions\/runners|^\/actions\/oidc/;
/**
 * PATCH /repos/{owner}/{repo} on the scratch repo: only these keys; visibility only towards private, forking only off
 * (fix round 1, G4), and the description only pipegen's marker (M5).
 */
const SCRATCH_REPO_PATCH = new Set(['private', 'visibility', 'default_branch', 'allow_forking', 'description']);

type Params = Record<string, unknown>;

function refuse(why: string): never {
  throw new ScratchGuardError(why);
}

/** The sticky stop gate (E0b): no GitHub write starts, or is retried, once a stop has begun. */
function notStopping(): void {
  if (interrupting()) refuse('pipegen is stopping; no new GitHub write starts.');
}

const onlyKeys = (p: Params, keys: readonly string[]) => Object.keys(p).every((k) => keys.includes(k));
const towardsPrivate = (p: Params) => (p.private === undefined || p.private === true) && (p.visibility === undefined || p.visibility === 'private')
  && (p.allow_forking === undefined || p.allow_forking === false) && (p.description === undefined || p.description === SCRATCH_MARKER);

function checkCentral(r: GuardedRepo, method: string, path: string, p: Params): void {
  const t = r.target;
  const proofRef = `heads/proof/${t.runId}`;
  if (method === 'PATCH' && path === '') {
    if (onlyKeys(p, ['private']) && p.private === true) return;   // ruling M1: the literal { private: true } only
    refuse(`${r.fullName} may only be made private ({ private: true }).`);
  }
  if (method === 'PUT' && path === '/actions/permissions/access') {
    const level = t.ownerType === 'Organization' ? 'organization' : 'user';
    if (onlyKeys(p, ['access_level']) && p.access_level === level) return;
    refuse(`the Actions access level of ${r.fullName} may only be set to "${level}".`);
  }
  if (method === 'POST' && path === '/git/refs') {
    if (p.ref === `refs/${proofRef}`) return;
    refuse(`${r.fullName} takes only the branch proof/${t.runId}.`);
  }
  if ((method === 'PATCH' || method === 'DELETE') && path === '/git/refs/{ref}') {
    if (p.ref === proofRef) return;
    refuse(`${r.fullName} takes only the branch proof/${t.runId}.`);
  }
  refuse(`${method} ${path || '/'} is not a write pipegen makes to ${r.fullName}.`);
}

/** How a write is sent: a plain guardedWrite, the secret sink's store, or the secret delete (allowed while stopping). */
type WriteMode = 'plain' | 'secret-store' | 'secret-delete';
const SECRET_STORE_ROUTE = 'PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}';
const SECRET_DELETE_ROUTE = 'DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}';
/** Any path with a `secrets` part (repo, environment, Dependabot, Codespaces secrets). */
const SECRETS_PATH_RE = /(?:^|\/)secrets(?:\/|$)/;

function checkScratch(r: GuardedRepo, method: string, path: string, p: Params): void {
  // E4 (T12): no secret is written through a plain guardedWrite; scratchSecretSink is the one way (after checkScratchAccess)
  if (method !== 'DELETE' && SECRETS_PATH_RE.test(path)) refuse(`a secret of ${r.fullName} is stored only through scratchSecretSink, right after checkScratchAccess.`);
  if (path === '') {
    if (method === 'PATCH' && Object.keys(p).length > 0 && onlyKeys(p, [...SCRATCH_REPO_PATCH]) && towardsPrivate(p)) return;
    refuse(method === 'DELETE' ? `deleting ${r.fullName} needs the exact name and pipegen's created marker (cleanup).`
      : `${method} on ${r.fullName} may only make it private, turn forking off, set its default branch or pipegen's marker.`);
  }
  const section = path.split('/')[1] ?? '';
  if (!SCRATCH_SECTIONS.has(section)) refuse(`${method} ${path} is not a write pipegen makes to ${r.fullName}.`);
  if (section === 'actions' && SCRATCH_ACTIONS_DENIED.test(path)) refuse(`${method} ${path} is never called on ${r.fullName}.`);
}

/**
 * The one way src/proof writes to GitHub. `route` is "METHOD /repos/{owner}/{repo}/…" (owner and repo come from the
 * guarded handle, never from `params`); `params` fills the other {placeholders} and the body. Refuses (ScratchGuardError,
 * nothing sent) a handle it didn't make, a stop in progress, a read, any other route shape, a reserved Octokit option,
 * a path value with a dot segment, and every write the repo's rules above don't list. Rate stops and GitHub's errors
 * pass through (a 401 as githubTokenRejected).
 */
export async function guardedWrite(gh: Octokit, r: GuardedRepo, route: string, params: Params = {}, clock: RateClock = clockOf(gh)): Promise<{ status: number; data: unknown }> {
  return writeChecked(gh, r, route, params, clock, 'plain');
}

/**
 * guardedWrite's body. `mode` 'secret-store' takes only SECRET_STORE_ROUTE on the scratch repo (scratchSecretSink, after
 * the access check); 'secret-delete' takes only SECRET_DELETE_ROUTE on the scratch repo and is the one write sent while a
 * stop is under way (it only removes a key). Neither is exported.
 */
async function writeChecked(gh: Octokit, r: GuardedRepo, route: string, params: Params, clock: RateClock, mode: WriteMode): Promise<{ status: number; data: unknown }> {
  requireGuarded(r);
  checkTarget(r.target, { owner: r.target.owner, repo: r.target.appRepo });
  const stopGate = mode === 'secret-delete' ? () => {} : notStopping;
  stopGate();
  if (mode !== 'plain') {
    const want = mode === 'secret-store' ? SECRET_STORE_ROUTE : SECRET_DELETE_ROUTE;
    if (r.kind !== 'scratch' || route !== want) refuse(`only ${want} on the scratch repo goes this way.`);
  }
  const m = ROUTE_RE.exec(route);
  if (m === null) refuse(`"${safeText(route, 120)}" is not a write under /repos/{owner}/{repo}.`);
  const method = m[1] as string;
  const path = m[2] as string;
  if (!WRITE_METHODS.has(method)) refuse(`${method} is not a write.`);
  if (params === null || typeof params !== 'object' || Array.isArray(params)) refuse('the request parameters are not an object.');
  for (const k of Object.keys(params)) if (RESERVED.has(k)) refuse(`the parameter "${safeText(k, 40)}" is not taken from a caller.`);
  for (const [, name] of path.matchAll(/\{([a-z_]+)\}/g)) {
    const v = params[name as string];
    const s = typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? String(v) : v;
    if (typeof s !== 'string' || !PATH_VALUE_RE.test(s) || s.split('/').some((part) => part === '' || part === '.' || part === '..')) {
      refuse(`the path value {${name}} is missing or not a plain name.`);
    }
  }
  if (r.kind === 'central') checkCentral(r, method, path, params);
  else if (mode === 'secret-store') {
    if (!onlyKeys(params, ['secret_name', 'encrypted_value', 'key_id'])) refuse('a secret store takes only secret_name, encrypted_value and key_id.');
  } else if (mode === 'secret-delete') {
    if (!onlyKeys(params, ['secret_name'])) refuse('a secret delete takes only secret_name.');
  } else checkScratch(r, method, path, params);
  try {
    // checked again before every attempt (review I1): withRateLimit may wait up to 60 s, then send the call again
    const res = await withRateLimit(() => { stopGate(); return gh.request(route, { ...params, owner: r.owner, repo: r.repo }); }, clock);
    return { status: res.status, data: res.data };
  } catch (e) {
    if (isRateStop(e)) throw e;
    if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    throw e;
  }
}

// ---------- reads ----------

const READ_ROUTE_RE = /^GET \/[A-Za-z0-9_./{}-]*$/;
/**
 * The one generic GitHub read of src/proof (review M3): GET routes only, no Octokit option from the caller (owner and
 * repo are path values here). Errors pass through; the caller decides what a refusal means.
 */
export async function githubRead(gh: Octokit, route: string, params: Params = {}, clock: RateClock = clockOf(gh)): Promise<{ data: unknown; headers: Record<string, unknown> }> {
  if (typeof route !== 'string' || !READ_ROUTE_RE.test(route)) refuse(`"${safeText(String(route), 120)}" is not a GET route; reads take GET only.`);
  for (const k of Object.keys(params)) if (RESERVED.has(k) && k !== 'owner' && k !== 'repo') refuse(`the parameter "${safeText(k, 40)}" is not taken from a caller.`);
  const res = await withRateLimit(() => gh.request(route, params), clock);
  return { data: res.data, headers: res.headers as Record<string, unknown> };
}

// ---------- creating a helper repo (App mode only, S19) ----------

/**
 * The marker that pipegen made (or adopted) the scratch repo (ruling M5): its description, set by the create call and by
 * the printed `gh repo create` command alike. A reused scratch repo without it is asked about; E8's delete requires it.
 */
export const SCRATCH_MARKER = 'pipegen proof runs (private scratch repo)';
const DESCRIPTIONS: Record<GuardedRepo['kind'], string> = {
  central: 'pipegen central workflows and install records',
  scratch: SCRATCH_MARKER,
};
export const helperDescription = (kind: GuardedRepo['kind']): string => DESCRIPTIONS[kind];

/**
 * Creates the guarded helper repo, private, with a first commit (plan Task 1: `private: true`, `auto_init: true`):
 * POST /orgs/{org}/repos for an organisation, POST /user/repos for a personal account, only when `login` (the token's
 * user) is the owner. The caller decides App mode (ruling S19: never in token mode). GitHub's answer must name that
 * repo and say private, else ProofStopError. GitHub's errors pass through (a 422 "name already exists" included).
 */
export async function createHelperRepo(gh: Octokit, r: GuardedRepo, login: string | null, clock: RateClock = clockOf(gh)): Promise<Record<string, unknown>> {
  requireGuarded(r);
  const t = r.target;
  checkTarget(t, { owner: t.owner, repo: t.appRepo });
  notStopping();
  const org = t.ownerType === 'Organization';
  if (!org && (login === null || login.toLowerCase() !== t.owner.toLowerCase())) {
    refuse(`a repo for ${t.owner} can only be created by ${t.owner} (the token belongs to ${safeText(login ?? 'nobody known', 40)}).`);
  }
  const body = { name: r.repo, private: true, auto_init: true, description: DESCRIPTIONS[r.kind] };
  let data: unknown;
  try {
    data = (await withRateLimit(() => {
      notStopping();
      return org ? gh.request('POST /orgs/{org}/repos', { org: t.owner, ...body }) : gh.request('POST /user/repos', body);
    }, clock)).data;
  } catch (e) {
    if (isRateStop(e)) throw e;
    if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    throw e;
  }
  const d = (data ?? {}) as Record<string, unknown>;
  const visibility = d.visibility;
  if (typeof d.full_name !== 'string' || d.full_name.toLowerCase() !== r.fullName.toLowerCase() || d.private !== true
    || (visibility !== undefined && visibility !== 'private')) {
    throw new ProofStopError(`GitHub's answer to creating ${r.fullName} doesn't say it is that repo and private, so pipegen won't use it. `
      + `Check ${r.fullName} on GitHub (make it private, or delete it if pipegen made it public), then run pipegen again.`);
  }
  return d;
}

/**
 * Makes the guarded repo private (plan Task 1, after the user said yes): `{ private: true }` for a public repo,
 * `{ visibility: 'private' }` for an internal one (scratch only: ruling M1 allows the central repo `{ private: true }`
 * only, so an internal `pipelines` is a stop with the `gh repo edit` command). GitHub's answer must say private, else ProofStopError.
 */
export async function makeRepoPrivate(gh: Octokit, r: GuardedRepo, from: 'public' | 'internal', clock: RateClock = clockOf(gh)): Promise<void> {
  const res = await guardedWrite(gh, r, 'PATCH /repos/{owner}/{repo}', from === 'internal' ? { visibility: 'private' } : { private: true }, clock);
  const d = (res.data ?? {}) as { private?: unknown; visibility?: unknown };
  if (d.private !== true || (d.visibility !== undefined && d.visibility !== 'private')) {
    throw new ProofStopError(`GitHub didn't confirm ${r.fullName} is private now, so pipegen won't use it.`);
  }
}

// ---------- secrets: the store after the access check, the delete (E4) ----------

/** How long checkScratchAccess's result stays good for a store (the re-check must come right before it). */
export const ACCESS_CHECK_MAX_AGE_MS = 60_000;
interface AccessRecord { scratch: GuardedRepo; at: number; used: boolean }
/** checkScratchAccess results, branded when made (by repos.ts, through the issuer). Module-private. */
const accessChecks = new WeakMap<object, AccessRecord>();
type AccessIssuer = (result: object, scratch: GuardedRepo) => void;
let accessIssuer: AccessIssuer | null = (result, scratch) => {
  requireGuarded(scratch, 'scratch');
  accessChecks.set(result, { scratch, at: Date.now(), used: false });
};

/**
 * The brand maker for checkScratchAccess's result, handed out ONCE: repos.ts takes it when it loads (it imports this module,
 * so it loads right after it). Any later call throws, so nothing else can brand an object as an access check.
 */
export function takeAccessIssuer(): AccessIssuer {
  const f = accessIssuer;
  if (f === null) throw new ScratchGuardError('the access-check issuer was already taken.');
  accessIssuer = null;
  return f;
}

/**
 * The one way a secret value reaches the scratch repo (E4; T12). `access` must be a result checkScratchAccess made (the
 * brand), not used for a store before, at most ACCESS_CHECK_MAX_AGE_MS old, for a scratch repo; the brand is spent here, so
 * every store batch needs a fresh check. The sink reads the scratch repo's public key and PUTs sealed values only
 * (secrets.ts storeSecretsVia / storeRepoSecretsVia seal them); nothing is sent once a stop has begun.
 */
export function scratchSecretSink(gh: Octokit, access: object, clock: RateClock = clockOf(gh)): SecretSink {
  const rec = typeof access === 'object' && access !== null ? accessChecks.get(access) : undefined;
  if (rec === undefined) refuse('a secret is stored only with the result of checkScratchAccess, made right before the store.');
  if (rec.used) refuse('that access check was already used for a store; pipegen checks again before each store.');
  const age = Date.now() - rec.at;
  if (!(age >= 0 && age <= ACCESS_CHECK_MAX_AGE_MS)) refuse('the access check is too old for a store; pipegen checks again right before it.');
  const r = rec.scratch;
  requireGuarded(r, 'scratch');
  checkTarget(r.target, { owner: r.target.owner, repo: r.target.appRepo });
  notStopping();
  rec.used = true;
  return Object.freeze({
    publicKey: async () => {
      notStopping();
      return githubRead(gh, 'GET /repos/{owner}/{repo}/actions/secrets/public-key', { owner: r.owner, repo: r.repo }, clock);
    },
    put: (name: string, encrypted: string, keyId: string) =>
      writeChecked(gh, r, SECRET_STORE_ROUTE, { secret_name: name, encrypted_value: encrypted, key_id: keyId }, clock, 'secret-store'),
  });
}

/** Deletes one repo secret of the scratch repo. The one write sent while a stop is under way (it only removes a key; E8). */
export async function deleteScratchSecret(gh: Octokit, scratch: GuardedRepo, name: string, clock: RateClock = clockOf(gh)): Promise<void> {
  requireGuarded(scratch, 'scratch');
  await writeChecked(gh, scratch, SECRET_DELETE_ROUTE, { secret_name: name }, clock, 'secret-delete');
}
