// How pipegen talks to GitHub: which token it uses, what that token may do, and the repo's GitHub context.
// Plan A Task 6, following spikes S1 and S9 (DECISIONS #64, #87, #88).
//
// - Strategy (S1, #87): pipegen's own GitHub App first (device flow, user-to-server token `ghu_`, installed on
//   "Only select repositories"). Fallback: a fine-grained token (`github_pat_`) on exactly the involved repos.
//   Classic tokens (`ghp_`, `gho_`, or the old 40-hex form) reach every repo of the user and are refused unless
//   --allow-broad-token. The kind comes from the prefix; nothing else is trusted to say what a token is.
// - Where the token comes from: the App login (AuthDeps.appLogin) when there is one, else GITHUB_TOKEN. v0.1 ships
//   no login command, so the App path is an interface only (see AppLoginStore / refreshAppToken). GH_TOKEN,
//   GH_ENTERPRISE_TOKEN, GH_HOST and GITHUB_API_URL are never read.
// - Repo creation (S9): only the App may create and delete pipegen's helper repos (a repo it creates joins the
//   installation at once). A fine-grained token can create a repo too, but then can't reach it (404), so in token
//   mode pipegen never creates or deletes repos (canCreateRepos/canDeleteRepos false).
// - What a token may do is found by real calls or GitHub's x-accepted-github-permissions header, never by the
//   `permissions` field of GET /repos: that is the USER's role (S1 saw admin: true for a read-only token).
// - The token only ever goes to https://api.github.com (hard-coded): makeOctokit's fetch refuses any other origin,
//   follows redirects only on that origin, and gives every request its own timeout. It is never printed: errors
//   pipegen raises, debug lines and error bodies GitHub sends back pass through hideToken(), and Auth keeps its
//   token in a non-enumerable property, so JSON.stringify and util.inspect leave it out.
import { Octokit } from '@octokit/rest';
import type { Auth, Plan, RepoProfile } from '../types.js';
import { isRateStop, newRateBudget, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { readBytes } from '../engine/http.js';
import { safeText } from '../util/safe-text.js';

/** Hard-coded: the only host that ever gets the token. */
export const GITHUB_API = 'https://api.github.com';
/** Per-request timeout for every GitHub call (a hanging request can't stall discovery or the audit). */
export const GITHUB_TIMEOUT_MS = 30_000;
const API_ORIGIN = new URL(GITHUB_API).origin;
const MAX_API_REDIRECTS = 3;
/** Error bodies are scrubbed of the token before Octokit sees them; larger ones are refused. */
const MAX_ERROR_BODY_BYTES = 1_000_000;

// ---------- keeping the token out of every output ----------

/** Tokens seen by makeOctokit / getAuth in this process, so hideToken can find them anywhere. */
const knownTokens = new Set<string>();
const remember = (t: string) => { if (/^[A-Za-z0-9_]{20,255}$/.test(t)) knownTokens.add(t); };

// Any GitHub token shape, and the value after an Authorization header or a token/Bearer scheme.
const TOKEN_SHAPES = /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})/g;
const AUTH_VALUES = /\b(authorization["']?\s*[:=]\s*["']?)(?:(?:token|bearer|basic)\s+)?[^\s"',;]+/gi;
const SCHEME_VALUES = /\b((?:token|bearer)\s+)[A-Za-z0-9_.~+/=-]{16,}/gi;

/**
 * `text` with the token (the one given and every token pipegen has seen), any GitHub token shape and any
 * Authorization value replaced by ***. Every error message, debug line and --json field that could hold one passes here.
 */
export function hideToken(text: string, token?: string | null): string {
  let out = text;
  for (const t of token ? [token, ...knownTokens] : knownTokens) out = out.split(t).join('***');
  return out.replace(TOKEN_SHAPES, '***').replace(AUTH_VALUES, '$1***').replace(SCHEME_VALUES, '$1***');
}

/** An access problem pipegen explains to the user. Its message never holds a token. */
export class GitHubAccessError extends Error {
  /** The HTTP status GitHub answered, when there was one. */
  readonly status?: number;
  constructor(message: string, options?: { status?: number; cause?: unknown }) {
    // Only a rate stop is kept as the cause (callers check isRateStop); other causes could carry request details.
    super(hideToken(message), options?.cause !== undefined && isRateStop(options.cause) ? { cause: options.cause } : undefined);
    this.name = 'GitHubAccessError';
    if (options?.status !== undefined) this.status = options.status;
  }
}

/** Status and GitHub's message of a failed Octokit call (both may be missing). */
function failure(e: unknown): { status?: number; message: string; accepted?: string } {
  const err = e as { status?: unknown; message?: unknown; response?: { data?: unknown; headers?: Record<string, unknown> } } | null;
  const status = typeof err?.status === 'number' ? err.status : undefined;
  const data = err?.response?.data as { message?: unknown } | undefined;
  const message = typeof data?.message === 'string' ? data.message : typeof err?.message === 'string' ? err.message : '';
  const acc = err?.response?.headers?.['x-accepted-github-permissions'];
  return { status, message, accepted: typeof acc === 'string' ? acc : undefined };
}
/** GitHub's answer in a form safe to show: no token, no control characters, short. */
const said = (e: unknown) => {
  const f = failure(e);
  const msg = safeText(hideToken(f.message), 160);
  return `HTTP ${f.status ?? 'error'}${msg === '' ? '' : `: ${msg}`}`;
};
const repoName = (owner: string, repo: string) => safeText(`${owner}/${repo}`, 200);

// ---------- the client ----------

export interface MakeOctokitOptions {
  /** The fetch the client sends through (tests pass a fake). Default: globalThis.fetch. */
  fetch?: typeof fetch;
  /** Per-request timeout. Default GITHUB_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Also write Octokit's debug and info lines (request log) to `log`. */
  debug?: boolean;
  /** Where log lines go, already passed through hideToken. Default: stderr. */
  log?: (line: string) => void;
}

/**
 * The fetch every pipegen Octokit uses: https://api.github.com only, its own timeout per request, redirects followed
 * by hand on that origin only (GET/HEAD), and error bodies scrubbed of the token before Octokit turns them into errors.
 */
function guardedFetch(base: typeof fetch, timeoutMs: number, token: string | null): typeof fetch {
  return async (input, init) => {
    let url = new URL(input instanceof Request ? input.url : String(input));
    const method = (init?.method ?? 'GET').toUpperCase();
    for (let hop = 0; ; hop++) {
      if (url.origin !== API_ORIGIN || url.username !== '' || url.password !== '') {
        throw new Error(`pipegen only sends GitHub requests to ${GITHUB_API}, not to ${safeText(url.origin, 100)}.`);
      }
      const timeout = AbortSignal.timeout(timeoutMs);
      const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
      const res = await base(url.href, { ...init, redirect: 'manual', signal });
      if (res.status >= 300 && res.status < 400 && res.status !== 304) {
        const location = res.headers.get('location');
        await res.body?.cancel().catch(() => {});
        if (location === null || hop >= MAX_API_REDIRECTS || (method !== 'GET' && method !== 'HEAD')) {
          throw new Error(`GitHub redirected ${method} ${safeText(url.pathname, 120)} and pipegen won't follow it.`);
        }
        url = new URL(location, url);
        continue;
      }
      if (res.status < 400) return res;
      const body = hideToken((await readBytes(res, MAX_ERROR_BODY_BYTES, 'GitHub\'s error answer')).toString('utf8'), token);
      const headers = new Headers(res.headers);
      headers.delete('content-length');
      headers.delete('content-encoding');
      return new Response(body, { status: res.status, statusText: res.statusText, headers });
    }
  };
}

/** An Octokit for https://api.github.com (always; no env var or origin URL changes it). null → anonymous client. */
export function makeOctokit(token: string | null, opts: MakeOctokitOptions = {}): Octokit {
  if (token !== null) remember(token);
  const sink = opts.log ?? ((line: string) => { process.stderr.write(line + '\n'); });
  const write = (level: string) => (message: unknown, ...rest: unknown[]) => {
    sink(hideToken([`[github ${level}]`, message, ...rest].map((x) => (typeof x === 'string' ? x : safeText(String(x), 400))).join(' '), token));
  };
  const quiet = () => {};
  return new Octokit({
    ...(token === null ? {} : { auth: token }),
    baseUrl: GITHUB_API,
    userAgent: 'pipegen',
    request: { fetch: guardedFetch(opts.fetch ?? globalThis.fetch, opts.timeoutMs ?? GITHUB_TIMEOUT_MS, token) },
    log: { debug: opts.debug ? write('debug') : quiet, info: opts.debug ? write('info') : quiet, warn: write('warn'), error: write('error') },
  });
}

// ---------- permissions (spike S1, DECISIONS #88) ----------

type Level = 'read' | 'write';
interface PermissionRow {
  /** GitHub's API key (installation permissions, x-accepted-github-permissions). */
  key: string;
  name: string;
  write: Level;
  read?: Level;
  why: string;
  readWhy?: string;
  /** Only a GitHub App can hold it (a fine-grained token has no Checks permission). */
  appOnly?: boolean;
  /** A GET that needs this permission at read level (S1's header evidence), `{r}` = /repos/{owner}/{repo}. */
  probe?: string;
}

// The order is the consent screen's order. Not requested: Repository creation (Administration write already allows
// POST /user/repos, S9), Commit statuses (no pipegen call reads them), and every account or organization permission.
const PERMISSIONS: readonly PermissionRow[] = [
  { key: 'metadata', name: 'Metadata', write: 'read', read: 'read', why: 'Always required. Read repo details and rulesets.', readWhy: 'Repo details, the rulesets list and collaborators.', probe: '' },
  { key: 'contents', name: 'Contents', write: 'write', read: 'read', why: 'Read your code, push the setup branch and the proof branches.', readWhy: 'Read the code and the workflow files.', probe: '/commits?per_page=1' },
  { key: 'workflows', name: 'Workflows', write: 'write', why: 'Add and change files in .github/workflows.' },
  { key: 'pull_requests', name: 'Pull requests', write: 'write', read: 'read', why: 'Open the setup PR and the proof PR, and close them.', readWhy: 'See open pull requests.', probe: '/pulls?per_page=1' },
  { key: 'actions', name: 'Actions', write: 'write', read: 'read', why: 'Watch proof runs, disable or enable workflows, delete proof runs and logs. Also needed to list environments.', readWhy: 'Workflows, runs, jobs and the environments list.', probe: '/actions/workflows?per_page=1' },
  { key: 'secrets', name: 'Secrets', write: 'write', read: 'read', why: 'Set the repo secrets the pipeline needs (values encrypted on your machine).', readWhy: 'Secret names only (values can never be read).', probe: '/actions/secrets/public-key' },
  { key: 'actions_variables', name: 'Variables', write: 'write', read: 'read', why: 'Set Actions variables such as PIPEGEN_BLOCK_FROM.', readWhy: 'Actions variable names and values.', probe: '/actions/variables?per_page=1' },
  { key: 'environments', name: 'Environments', write: 'write', read: 'read', why: 'Set environment secrets and variables (for example the signing key).', readWhy: 'Environment secret names and variables.' },
  { key: 'administration', name: 'Administration', write: 'write', read: 'read', why: 'Apply the merge rules (rulesets), create environments and their branch rules, change Actions settings, create the private helper repos and delete the scratch repo.', readWhy: 'Actions settings (access level, SHA pinning).', probe: '/actions/permissions' },
  { key: 'checks', name: 'Checks', write: 'read', why: 'Read the gate check result. A fine-grained token can\'t have it, so in token mode pipegen reads workflow runs and jobs instead.', appOnly: true },
];

const levelText = (l: Level) => (l === 'write' ? 'read and write' : 'read');
const label = (p: PermissionRow, mode: Level): string =>
  `${p.name}: ${levelText(mode === 'write' ? p.write : (p.read as Level))}${p.appOnly ? ' (GitHub App only)' : ''}`;
const rowsFor = (mode: Level) => PERMISSIONS.filter((p) => mode === 'write' || p.read !== undefined);
const entry = (p: PermissionRow, mode: Level) => ({ permission: label(p, mode), why: mode === 'write' ? p.why : (p.readWhy as string) });

/** The permissions pipegen asks for, each with a one-line reason (README and consent screen). */
export function permissionsTable(mode: 'read' | 'write'): { permission: string; why: string }[] {
  return rowsFor(mode).map((p) => entry(p, mode));
}

/** "metadata=read; contents=write,workflows=write" → the table's names, e.g. "Metadata: read". */
function acceptedNames(header: string | undefined): string[] {
  if (header === undefined) return [];
  const names: string[] = [];
  for (const alt of header.split(';')) {
    for (const pair of alt.split(',')) {
      const [key, level] = pair.trim().split('=');
      const row = PERMISSIONS.find((p) => p.key === key);
      const lvl = level === 'write' ? 'write' : level === 'read' ? 'read' : undefined;
      const name = row !== undefined && lvl !== undefined ? `${row.name}: ${levelText(lvl)}` : safeText(pair.trim(), 60);
      if (name !== '' && !names.includes(name)) names.push(name);
    }
  }
  return names;
}

// ---------- token kind and setup steps ----------

const TOKEN_CHARS = /^[A-Za-z0-9_]{20,255}$/;

/** What a token is, by its prefix (S1): ghu_ App user token, github_pat_ fine-grained, ghp_/gho_/40-hex classic. Else null. */
export function tokenKind(token: string): Exclude<Auth['kind'], 'anonymous'> | null {
  if (!TOKEN_CHARS.test(token)) return null;
  if (token.startsWith('ghu_')) return 'app';
  if (token.startsWith('github_pat_')) return 'fine-grained';
  if (token.startsWith('ghp_') || token.startsWith('gho_') || /^[0-9a-f]{40}$/.test(token)) return 'classic';
  return null;
}

const FG_PAGE = 'GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token';

function readSetup(owner: string, repo: string): string {
  const perms = permissionsTable('read').map((p) => p.permission).join(', ');
  return `pipegen needs read access to ${repoName(owner, repo)}. Create a fine-grained token for this one repo (${FG_PAGE}; `
    + `Repository access: Only select repositories → ${safeText(repo, 100)}) with ${perms}, and set it as GITHUB_TOKEN `
    + '(or install the pipegen GitHub App on this repo). pipegen refuses broad classic tokens.';
}

function writeSetup(owner: string, repos: string[]): string {
  const perms = PERMISSIONS.filter((p) => !p.appOnly).map((p) => label(p, 'write')).join(', ');
  const list = repos.map((r) => repoName(owner, r)).join(', ');
  return `pipegen needs a GitHub token to change ${list}. Create a fine-grained token (${FG_PAGE}; Resource owner: `
    + `${safeText(owner, 100)}; Repository access: Only select repositories → ${list}) with ${perms}, and set it as GITHUB_TOKEN. `
    + 'Repos that don\'t exist yet must be created first (gh repo create <owner>/<name> --private) and added to the token. '
    + 'pipegen refuses broad classic tokens unless --allow-broad-token.';
}

const CLASSIC_REFUSED = 'pipegen won\'t use this token: it is a classic token, which reaches every repo you have. '
  + 'Use a fine-grained token limited to the repos pipegen works on, or pipegen\'s GitHub App installed on "Only select repositories". '
  + 'To use the classic token anyway, run again with --allow-broad-token.';
const UNKNOWN_TOKEN = 'pipegen doesn\'t recognise this kind of GitHub token. Use a fine-grained token (it starts with github_pat_) '
  + 'limited to the repos pipegen works on, or pipegen\'s GitHub App.';

// ---------- the App login (interface only in v0.1) ----------

/** An App user-to-server login: the access token (`ghu_`, 8 hours) and the refresh token (`ghr_`, about 6 months), S1. */
export interface AppLogin { access: string; refresh: string; /** ms since epoch */ expiresAt: number }
/**
 * Where pipegen's App login keeps its tokens. NOT built in v0.1 (no login command in Plan A). An implementation must
 * keep them in one 0600 file in the trusted config folder ($XDG_CONFIG_HOME/pipegen or ~/.config/pipegen, checked
 * with src/util/trusted-dir.ts), opened with O_NOFOLLOW, and `save` must write both tokens in one temp-file-then-rename,
 * under a lock so two processes never refresh at once (the old tokens die at the first refresh).
 */
export interface AppLoginStore { load(): Promise<AppLogin | null>; save(login: AppLogin): Promise<void> }

/**
 * Refreshes the App login: `exchange` trades the refresh token for a new pair (POST https://github.com/login/oauth/
 * access_token with the client ID only, no secret, S1). Both new tokens are saved together BEFORE the new access token
 * is handed out, because the old access token stops working at once (S1). A failed save never returns the new token.
 */
export async function refreshAppToken(store: AppLoginStore, exchange: (refreshToken: string) => Promise<AppLogin>): Promise<string> {
  const current = await store.load();
  if (current === null) throw new GitHubAccessError('pipegen has no GitHub App login to refresh. Log in again.');
  remember(current.access);
  remember(current.refresh);
  let next: AppLogin;
  try {
    next = await exchange(current.refresh);
  } catch (e) {
    throw new GitHubAccessError('GitHub didn\'t refresh pipegen\'s App login. Log in again.', { cause: e });
  }
  remember(next.access);
  remember(next.refresh);
  if (tokenKind(next.access) !== 'app' || !/^ghr_[A-Za-z0-9_]{16,255}$/.test(next.refresh)) {
    throw new GitHubAccessError('GitHub\'s answer to the App login refresh wasn\'t an App token pair. Log in again.');
  }
  try {
    await store.save(next);
  } catch {
    throw new GitHubAccessError('pipegen couldn\'t save the refreshed GitHub App login, so it won\'t use it. Log in again.');
  }
  return next.access;
}

// ---------- getAuth ----------

export interface AuthDeps {
  /** Read for GITHUB_TOKEN only. Default: process.env. */
  env?: Record<string, string | undefined>;
  /** The App login's current access token (pipegen's device-flow login; not shipped in v0.1). Tried first. */
  appLogin?: () => Promise<string | null>;
  /** The fetch for every call getAuth makes (tests pass a fake). */
  fetch?: typeof fetch;
  clock?: RateClock;
}
type AuthOpts = { owner: string; repos: string[]; allowBroad: boolean };

/** An Auth whose token is non-enumerable: JSON.stringify, util.inspect and spreads leave it out. */
function authWith(token: string, rest: Omit<Auth, 'token'>): Auth & { token: string } {
  const auth = { ...rest } as Auth & { token: string };
  Object.defineProperty(auth, 'token', { value: token, enumerable: false, writable: false });
  return auth;
}

/** Does the App installation on `owner` hold Administration write? (S9: then pipegen may create and delete repos.) */
async function appAdministers(gh: Octokit, owner: string, clock: RateClock): Promise<boolean> {
  const inst = await installationFor(gh, owner, clock);
  return inst?.permissions.administration === 'write';
}

interface Installation { login: string; permissions: Record<string, string> }
/** The App installation on `owner` (case-insensitive), null when there is none or GitHub won't say. Rate stops are thrown. */
async function installationFor(gh: Octokit, owner: string, clock: RateClock): Promise<Installation | null> {
  for (let page = 1; page <= 10; page++) {
    let data: unknown;
    try {
      data = (await withRateLimit(() => gh.request('GET /user/installations', { per_page: 100, page }), clock)).data;
    } catch (e) {
      if (isRateStop(e)) throw e;
      return null;
    }
    // S9: count the list, never total_count (it lagged behind after a delete)
    const list = (data as { installations?: unknown } | null)?.installations;
    if (!Array.isArray(list)) return null;
    for (const i of list as { account?: { login?: unknown }; permissions?: unknown }[]) {
      const login = i?.account?.login;
      if (typeof login === 'string' && login.toLowerCase() === owner.toLowerCase()) {
        const perms = i.permissions !== null && typeof i.permissions === 'object' ? i.permissions as Record<string, unknown> : {};
        return { login, permissions: Object.fromEntries(Object.entries(perms).filter(([, v]) => typeof v === 'string')) as Record<string, string> };
      }
    }
    if (list.length < 100) return null;
  }
  return null;
}

/**
 * How pipegen logs in to GitHub (S1 strategy). `repos`: the repo names (under `owner`) pipegen works on.
 * - write mode needs a token (no token → the setup steps); read mode without a token works for a public repo only
 *   (checked with an anonymous GET /repos/{owner}/{repos[0]}) and gives kind 'anonymous';
 * - classic tokens are refused unless allowBroad; unknown token kinds are refused;
 * - canCreateRepos/canDeleteRepos: write mode, App token, and the installation on `owner` holds Administration write.
 */
export function getAuth(opts: AuthOpts & { mode: 'write' }, deps?: AuthDeps): Promise<Auth & { token: string }>;
export function getAuth(opts: AuthOpts & { mode: 'read' }, deps?: AuthDeps): Promise<Auth>;
export function getAuth(opts: AuthOpts & { mode: 'read' | 'write' }, deps?: AuthDeps): Promise<Auth>;
export async function getAuth(opts: AuthOpts & { mode: 'read' | 'write' }, deps: AuthDeps = {}): Promise<Auth> {
  const { owner, repos, allowBroad, mode } = opts;
  const clock = deps.clock ?? { budget: newRateBudget() };
  const env = deps.env ?? process.env;

  let token: string | null = null;
  let fromApp = false;
  let appTok: string | null = null;
  try {
    appTok = deps.appLogin ? await deps.appLogin() : null;
  } catch {
    throw new GitHubAccessError('pipegen couldn\'t read its GitHub App login. Log in again, or set GITHUB_TOKEN to a fine-grained token.');
  }
  if (appTok !== null && appTok.trim() !== '') {
    token = appTok.trim();
    fromApp = true;
  } else {
    const t = env.GITHUB_TOKEN?.trim();
    if (t !== undefined && t !== '') token = t;
  }

  if (token === null) {
    if (mode === 'write') throw new GitHubAccessError(writeSetup(owner, repos));
    const repo = repos[0];
    if (repo === undefined) throw new GitHubAccessError('pipegen was given no repo to read.');
    const anon = makeOctokit(null, { fetch: deps.fetch });
    let isPublic = false;
    try {
      const res = await withRateLimit(() => anon.rest.repos.get({ owner, repo }), clock);
      isPublic = (res.data as { private?: unknown }).private === false;
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (failure(e).status === undefined || failure(e).status === 500) {
        throw new GitHubAccessError(`pipegen couldn't reach ${GITHUB_API} to check ${repoName(owner, repo)} (${said(e)}).`);
      }
    }
    if (!isPublic) throw new GitHubAccessError(readSetup(owner, repo));
    return { kind: 'anonymous', token: null, repos: [repo], canCreateRepos: false, canDeleteRepos: false };
  }

  remember(token);
  const kind = tokenKind(token);
  if (kind === null || (fromApp && kind !== 'app')) throw new GitHubAccessError(UNKNOWN_TOKEN);
  if (kind === 'classic' && !allowBroad) throw new GitHubAccessError(CLASSIC_REFUSED);

  let manage = false;
  if (mode === 'write' && kind === 'app') manage = await appAdministers(makeOctokit(token, { fetch: deps.fetch }), owner, clock);
  return authWith(token, { kind, repos: kind === 'classic' ? 'all' : [...repos], canCreateRepos: manage, canDeleteRepos: manage });
}

// ---------- the repo's GitHub context ----------

const PLANS: Record<string, Plan> = { free: 'free', pro: 'pro', team: 'team', enterprise: 'enterprise' };
const planOf = (data: unknown): Plan => {
  const name = (data as { plan?: { name?: unknown } | null } | null)?.plan?.name;
  return typeof name === 'string' ? PLANS[name.toLowerCase()] ?? 'unknown' : 'unknown';
};

/**
 * Visibility, owner type, plan and default branch. Plan: GET /orgs/{org} for orgs; GET /user only when the token's own
 * `login` is the owner (else it would describe the wrong account); anything else, or any failure → 'unknown'.
 * The `permissions` field of GET /repos is never read (it is the user's role, not the token's rights).
 */
export async function readGitHubContext(gh: Octokit, owner: string, repo: string, login: string | null, clock: RateClock = { budget: newRateBudget() }): Promise<Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>> {
  let data: { private?: unknown; default_branch?: unknown; owner?: { type?: unknown } };
  try {
    data = (await withRateLimit(() => gh.rest.repos.get({ owner, repo }), clock)).data as typeof data;
  } catch (e) {
    if (isRateStop(e)) throw new GitHubAccessError(`GitHub's rate limit stopped pipegen reading ${repoName(owner, repo)}.`, { cause: e });
    const { status } = failure(e);
    if (status === 404 || status === 403) {
      throw new GitHubAccessError(`pipegen can't see ${repoName(owner, repo)} with this token (${said(e)}). Check the repo name and that the token (or the App installation) includes this repo.`, { status });
    }
    throw new GitHubAccessError(`pipegen couldn't read ${repoName(owner, repo)} from GitHub (${said(e)}).`, { status });
  }
  const ownerType = data.owner?.type === 'Organization' ? 'Organization' : data.owner?.type === 'User' ? 'User' : undefined;
  if (typeof data.private !== 'boolean' || ownerType === undefined || typeof data.default_branch !== 'string' || data.default_branch === '') {
    throw new GitHubAccessError(`GitHub's answer about ${repoName(owner, repo)} could not be read.`);
  }
  let plan: Plan = 'unknown';
  const readPlan = async (call: () => Promise<{ data: unknown }>) => {
    try {
      plan = planOf((await withRateLimit(call, clock)).data);
    } catch (e) {
      if (isRateStop(e)) throw e;
      plan = 'unknown';
    }
  };
  if (ownerType === 'Organization') await readPlan(() => gh.rest.orgs.get({ org: owner }));
  else if (login !== null && login.toLowerCase() === owner.toLowerCase()) await readPlan(() => gh.rest.users.getAuthenticated());
  return { private: data.private, ownerType, plan, defaultBranch: data.default_branch };
}

// ---------- probing the token's permissions ----------

type Row = { permission: string; why: string };
const PERMISSION_REFUSAL = /resource not accessible by (?:integration|personal access token)/i;

/**
 * What the token can't do on `repos` (under `owner`), found by real calls (never by GET /repos `permissions`).
 * - App token (`kind: 'app'`): the installation on `owner` lists its exact permissions (GET /user/installations).
 * - Other tokens: one read-only GET per permission that has one (S1's header evidence). A 403 "Resource not
 *   accessible…" is a missing permission (named by GitHub's x-accepted-github-permissions header when it sends one).
 *   GitHub can't show a write level without a write, so in write mode those are listed as `unchecked`, never assumed.
 * A repo the token can't see (403/404 on GET /repos) is missing as "Access to owner/repo". Probing never writes.
 */
export async function probePermissions(gh: Octokit, owner: string, repos: string[], opts: { kind?: Auth['kind']; mode?: 'read' | 'write'; clock?: RateClock } = {}): Promise<{ missing: Row[]; unchecked: Row[] }> {
  const mode = opts.mode ?? 'write';
  const clock = opts.clock ?? { budget: newRateBudget() };
  const missing: Row[] = [];
  const unchecked: Row[] = [];
  const add = (list: Row[], r: Row) => { if (!list.some((x) => x.permission === r.permission)) list.push(r); };
  const rows = rowsFor(mode).filter((p) => opts.kind === 'app' || !p.appOnly);

  const visible: string[] = [];
  for (const repo of repos) {
    try {
      await withRateLimit(() => gh.rest.repos.get({ owner, repo }), clock);
      visible.push(repo);
    } catch (e) {
      if (isRateStop(e)) throw e;
      const { status } = failure(e);
      const access = `Access to ${repoName(owner, repo)}`;
      if (status === 403 || status === 404) add(missing, { permission: access, why: 'pipegen can\'t see this repo with this token: it doesn\'t exist yet, or it isn\'t in the token\'s (or the App installation\'s) repository list.' });
      else add(unchecked, { permission: access, why: `GitHub didn't answer (${said(e)}), so pipegen couldn't check this repo.` });
    }
  }

  if (opts.kind === 'app') {
    let inst: Installation | null;
    try {
      inst = await installationFor(gh, owner, clock);
    } catch (e) {
      if (isRateStop(e)) throw e;
      inst = null;
    }
    if (inst === null) {
      for (const p of rows) add(unchecked, entry(p, mode));
      return { missing, unchecked };
    }
    for (const p of rows) {
      const need = mode === 'write' ? p.write : (p.read as Level);
      const have = inst.permissions[p.key];
      if (!(have === 'write' || (have === 'read' && need === 'read'))) add(missing, entry(p, mode));
    }
    return { missing, unchecked };
  }

  for (const p of rows) {
    let confirmed = p.key === 'metadata' && visible.length > 0;   // repos it can't see are already reported
    let refused = false;
    if (p.probe !== undefined && p.key !== 'metadata') {
      confirmed = visible.length > 0;
      for (const repo of visible) {
        try {
          await withRateLimit(() => gh.request(`GET /repos/{owner}/{repo}${p.probe}`, { owner, repo }), clock);
        } catch (e) {
          if (isRateStop(e)) throw e;
          confirmed = false;
          const f = failure(e);
          if (f.status === 403 && PERMISSION_REFUSAL.test(f.message)) {
            const named = acceptedNames(f.accepted);
            // GitHub's header names what the call needed; when it names another permission, that one is missing
            const other = named.length > 0 && !named.some((n) => n.startsWith(`${p.name}:`));
            if (other) for (const n of named) add(missing, { permission: n, why: `GitHub refused a ${p.name} call and asked for it.` });
            else refused = true;
          }
        }
      }
    }
    if (refused) add(missing, entry(p, mode));
    else if (!confirmed || (mode === 'write' && p.write === 'write')) add(unchecked, entry(p, mode));
  }
  // keep `unchecked` free of what is already known to be missing
  return { missing, unchecked: unchecked.filter((u) => !missing.some((m) => m.permission === u.permission)) };
}

// ---------- writers ----------

const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const WRITERS_PAGES = 50;

/**
 * User logins with write, maintain or admin access (GET /repos/{o}/{r}/collaborators?affiliation=all, paged). Bots and
 * logins that aren't valid GitHub logins are left out. A refused call is an error naming the permission GitHub asked
 * for (its x-accepted-github-permissions header); pipegen doesn't guess one when GitHub doesn't say.
 */
export async function listWriters(gh: Octokit, owner: string, repo: string, clock: RateClock = { budget: newRateBudget() }): Promise<string[]> {
  const writers: string[] = [];
  for (let page = 1; page <= WRITERS_PAGES; page++) {
    let data: unknown;
    let more = false;
    try {
      const res = await withRateLimit(() => gh.rest.repos.listCollaborators({ owner, repo, affiliation: 'all', per_page: 100, page }), clock);
      data = res.data;
      more = /rel="next"/.test(String(res.headers.link ?? ''));
    } catch (e) {
      if (isRateStop(e)) throw new GitHubAccessError(`GitHub's rate limit stopped pipegen listing who can write to ${repoName(owner, repo)}.`, { cause: e });
      const f = failure(e);
      const named = acceptedNames(f.accepted);
      const which = named.length > 0
        ? `the token lacks ${named.join(' or ')}`
        : 'GitHub didn\'t say which permission is missing';
      throw new GitHubAccessError(`pipegen couldn't list who can write to ${repoName(owner, repo)}: ${which} (${said(e)}).`, { status: f.status });
    }
    if (!Array.isArray(data)) throw new GitHubAccessError(`GitHub's collaborator list for ${repoName(owner, repo)} could not be read.`);
    for (const c of data as { login?: unknown; type?: unknown; permissions?: Record<string, unknown> }[]) {
      if (c?.type === 'Bot' || typeof c?.login !== 'string' || !LOGIN_RE.test(c.login)) continue;
      const p = c.permissions ?? {};
      if ((p.push === true || p.maintain === true || p.admin === true) && !writers.includes(c.login)) writers.push(c.login);
    }
    if (!more) break;
  }
  return writers;
}
