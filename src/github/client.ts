// How pipegen talks to GitHub: which token it uses, what that token may do, and the repo's GitHub context.
// Plan A Task 6, following spikes S1 and S9 (DECISIONS #64, #87, #88).
//
// - Strategy (S1, #87): pipegen's own GitHub App first (device flow, user-to-server token `ghu_`, installed on
//   "Only select repositories"). Fallback: a fine-grained token (`github_pat_`) on exactly the involved repos.
//   Classic tokens (`ghp_`, `gho_`, or the old 40-hex form) reach every repo of the user and are refused unless
//   --allow-broad-token. An Actions GITHUB_TOKEN (`ghs_`, an installation token) is accepted for the read-only
//   audit only (kind 'installation'). The kind comes from the prefix; nothing else is trusted to say what a token is.
// - An App installed on "All repositories" is refused like a classic token, unless --allow-broad-token (T25). Which
//   repos an App may touch comes from the installation's own repo list, never from GET /repos (a public repo answers
//   200 to anyone).
// - Where the token comes from: the App login (AuthDeps.appLogin) when there is one, else GITHUB_TOKEN. v0.1 ships
//   no login command, so the App path is an interface only (see AppLoginStore / refreshAppToken). GH_TOKEN,
//   GH_ENTERPRISE_TOKEN, GH_HOST and GITHUB_API_URL are never read.
// - Repo creation (S9): only the App may create and delete pipegen's helper repos (a repo it creates joins the
//   installation at once). A fine-grained token can create a repo too, but then can't reach it (404), so in token
//   mode pipegen never creates or deletes repos (canCreateRepos/canDeleteRepos false). A `ghu_` token from
//   GITHUB_TOKEN may belong to another App, so only pipegen's own App login may create or delete.
// - What a token may do is found by real calls or GitHub's x-accepted-github-permissions header, never by the
//   `permissions` field of GET /repos: that is the USER's role (S1 saw admin: true for a read-only token).
// - The token only ever goes to https://api.github.com (hard-coded): makeOctokit's fetch refuses any other origin,
//   follows redirects only on that origin, and gives every request its own timeout. It is never printed: errors
//   pipegen raises, debug lines and error bodies GitHub sends back pass through hideToken(), and Auth keeps its
//   token in a non-enumerable property, so JSON.stringify and util.inspect leave it out.
// - Every call on one client draws from one rate budget: makeOctokit takes the run's RateClock (or makes one), and
//   every function here uses it unless it is given another. A 401 is never read as a missing permission: it is a
//   hard "GitHub rejected the token" error.
import { Octokit } from '@octokit/rest';
import type { Auth, Plan, RepoProfile } from '../types.js';
import { isRateStop, newRateBudget, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { readBytes } from '../engine/http.js';
import { safeText } from '../util/safe-text.js';
import { API_LOGIN_RE } from '../../gate/src/login.js';

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
/** Only token-shaped values are hidden by value (an empty or short string would rewrite ordinary text). */
const tokenLike = (t: string) => /^[A-Za-z0-9_]{20,255}$/.test(t);
const remember = (t: string) => { if (tokenLike(t)) knownTokens.add(t); };

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
  for (const t of token && tokenLike(token) ? [token, ...knownTokens] : knownTokens) out = out.split(t).join('***');
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

/**
 * True when a request got no HTTP answer at all: a DNS, connection or TLS failure, a timeout, or pipegen's own fetch
 * refusing the request. @octokit/request reports all of these as status 500 with no `response`, which must never be
 * shown as GitHub answering HTTP 500 (final review batch 2, M1).
 */
export function isNoAnswer(e: unknown): boolean {
  const err = e as { status?: unknown; response?: unknown } | null;
  return typeof err === 'object' && err !== null && err.status === 500 && err.response === undefined;
}

/** Status and GitHub's message of a failed Octokit call (both may be missing; no status when GitHub never answered). */
function failure(e: unknown): { status?: number; message: string; accepted?: string; noAnswer: boolean } {
  const err = e as { status?: unknown; message?: unknown; response?: { data?: unknown; headers?: Record<string, unknown> } } | null;
  const noAnswer = isNoAnswer(e);
  const status = !noAnswer && typeof err?.status === 'number' ? err.status : undefined;
  const data = err?.response?.data as { message?: unknown } | undefined;
  const message = typeof data?.message === 'string' ? data.message : typeof err?.message === 'string' ? err.message : '';
  const acc = err?.response?.headers?.['x-accepted-github-permissions'];
  return { status, message, accepted: typeof acc === 'string' ? acc : undefined, noAnswer };
}
/** GitHub's answer (or that there was none) in a form safe to show: no token, no control characters, short. */
const said = (e: unknown) => {
  const f = failure(e);
  const msg = safeText(hideToken(f.message), 160);
  const head = f.noAnswer ? 'no answer from GitHub (network problem)' : `HTTP ${f.status ?? 'error'}`;
  return `${head}${msg === '' ? '' : `: ${msg}`}`;
};
const repoName = (owner: string, repo: string) => safeText(`${owner}/${repo}`, 200);

/** GitHub said 401: the token is wrong, expired or revoked. Never read as a missing permission. */
const isRejected = (e: unknown) => failure(e).status === 401;
/** Clients made without a token (makeOctokit(null)). On them a 401 only means "this needs a token": inconclusive. */
const anonymousClients = new WeakSet<Octokit>();
export const isAnonymousClient = (gh: Octokit): boolean => anonymousClients.has(gh);
/** A 401 on a client that sent a token: that token was rejected. */
const rejectedOn = (gh: Octokit, e: unknown) => isRejected(e) && !anonymousClients.has(gh);
const tokenRejected = () => new GitHubAccessError('GitHub rejected the token (HTTP 401): it is wrong, expired or revoked. Make a new one, or log in again.', { status: 401 });
export { tokenRejected as githubTokenRejected };

// Defence in depth: owner and repo are checked here too, before they go into any API path.
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
/** Throws unless every name is a valid GitHub owner / repo name. */
export function checkRepoNames(owner: string, repos: readonly string[]): void {
  const bad = !OWNER_RE.test(owner) ? owner : repos.find((r) => !REPO_RE.test(r) || r === '.' || r === '..');
  if (bad !== undefined) throw new GitHubAccessError(`"${safeText(bad, 100)}" isn't a valid GitHub owner or repo name.`);
}

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
  /** The run's rate budget, shared by every call made through this client (default: a fresh newRateBudget()). */
  clock?: RateClock;
}

const clocks = new WeakMap<Octokit, RateClock>();
/** The rate clock of a client: the one given to makeOctokit, else one made on first use and kept for that client. */
export function clockOf(gh: Octokit): RateClock {
  let c = clocks.get(gh);
  if (c === undefined) {
    c = { budget: newRateBudget() };
    clocks.set(gh, c);
  }
  return c;
}

/**
 * The fetch every pipegen Octokit uses: https://api.github.com only, its own timeout per request, redirects followed
 * by hand on that origin only (GET/HEAD), and error bodies scrubbed of the token before Octokit turns them into errors.
 */
function guardedFetch(base: typeof fetch, timeoutMs: number, token: string | null): typeof fetch {
  return async (input, init) => {
    let url = new URL(input instanceof Request ? input.url : String(input));
    const method = (init?.method ?? 'GET').toUpperCase();
    // E4 (ruling S2): a GET whose caller asked `redirect: 'manual'` gets the redirect back unfollowed, so src/proof/download.ts
    // can fetch the artifact store's URL WITHOUT the token. Nothing is ever sent to another origin from here.
    const handBack = init?.redirect === 'manual' && method === 'GET';
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
        if (handBack) return new Response(null, { status: res.status, statusText: res.statusText, headers: res.headers });
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
  // the token is hidden BEFORE the line is cut, so a cut can never leave part of a token behind
  const write = (level: string) => (message: unknown, ...rest: unknown[]) => {
    sink(safeText(hideToken([`[github ${level}]`, message, ...rest].map((x) => String(x)).join(' '), token), 1000));
  };
  const quiet = () => {};
  // Octokit's request log reports every failed request through log.error; pipegen explains failures itself, so
  // that line is printed only with debug on.
  const gh = new Octokit({
    ...(token === null ? {} : { auth: token }),
    baseUrl: GITHUB_API,
    userAgent: 'pipegen',
    request: { fetch: guardedFetch(opts.fetch ?? globalThis.fetch, opts.timeoutMs ?? GITHUB_TIMEOUT_MS, token) },
    log: { debug: opts.debug ? write('debug') : quiet, info: opts.debug ? write('info') : quiet, warn: write('warn'), error: opts.debug ? write('error') : quiet },
  });
  clocks.set(gh, opts.clock ?? { budget: newRateBudget() });
  if (token === null) anonymousClients.add(gh);
  return gh;
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
  /** The write-mode why in token mode, when it differs (DECISIONS #87: with a token pipegen never creates or deletes repos). */
  tokenWhy?: string;
  /** Only a GitHub App can hold it (a fine-grained token has no Checks permission). */
  appOnly?: boolean;
  /** G13 (S12): an optional organisation permission. Never required: probePermissions never reports it missing, and pipegen works without it. */
  org?: boolean;
  /** A GET that needs this permission at read level (S1's header evidence), `{r}` = /repos/{owner}/{repo}. */
  probe?: string;
}

// The FULL RUN's table (write mode; spike S1, DECISIONS #88). The order is the consent screen's order. Not requested:
// Repository creation (Administration write already allows POST /user/repos, S9), Commit statuses (no pipegen call
// reads them), and every account or organization permission. Read mode uses READ_PERMISSIONS below, not these rows.
const PERMISSIONS: readonly PermissionRow[] = [
  { key: 'metadata', name: 'Metadata', write: 'read', read: 'read', why: 'Always required. Read repo details and rulesets.', readWhy: 'Repo details, the rulesets list and collaborators.', probe: '' },
  { key: 'contents', name: 'Contents', write: 'write', read: 'read', why: 'Read your code, push the setup branch and the proof branches.', readWhy: 'Read the code and the workflow files.', probe: '/commits?per_page=1' },
  { key: 'workflows', name: 'Workflows', write: 'write', why: 'Add and change files in .github/workflows.' },
  { key: 'pull_requests', name: 'Pull requests', write: 'write', read: 'read', why: 'Open the setup PR and the proof PR, and close them.', readWhy: 'See open pull requests.', probe: '/pulls?per_page=1' },
  { key: 'actions', name: 'Actions', write: 'write', read: 'read', why: 'Watch proof runs, disable or enable workflows, delete proof runs and logs. Also needed to list environments.', readWhy: 'Workflows, runs, jobs and the environments list.', probe: '/actions/workflows?per_page=1' },
  { key: 'secrets', name: 'Secrets', write: 'write', read: 'read', why: 'Set the repo secrets the pipeline needs (values encrypted on your machine).', readWhy: 'Secret names only (values can never be read).', probe: '/actions/secrets/public-key' },
  { key: 'actions_variables', name: 'Variables', write: 'write', read: 'read', why: 'Set Actions variables such as PIPEGEN_BLOCK_FROM.', readWhy: 'Actions variable names and values.', probe: '/actions/variables?per_page=1' },
  { key: 'environments', name: 'Environments', write: 'write', read: 'read', why: 'Set environment secrets and variables (for example the signing key).', readWhy: 'Environment secret names and variables.' },
  {
    key: 'administration', name: 'Administration', write: 'write', read: 'read',
    why: 'Apply the merge rules (rulesets), create the deploy and signing environments and their branch rules, change Actions settings, create the private helper repos, and delete the scratch repo after the proof if you allow it.',
    tokenWhy: 'Apply the merge rules (rulesets), create the deploy and signing environments and their branch rules, and change Actions settings. With a token pipegen never creates or deletes repos; it empties the scratch repo instead.',
    readWhy: 'Actions settings (access level, SHA pinning).', probe: '/actions/permissions',
  },
  { key: 'checks', name: 'Checks', write: 'read', why: 'Read the gate check result. A fine-grained token can\'t have it, so in token mode pipegen reads workflow runs and jobs instead.', appOnly: true },
  // G13 (rulings S12, E-b2): `pipegen update` reads the update issues; the two organisation rows are optional (an organisation-owned repo only):
  // without them pipegen plans no organisation required workflow and asks the owners itself
  { key: 'issues', name: 'Issues', write: 'read', why: 'Read the update issues pipegen\'s nightly check opens (pipegen update). pipegen never writes an issue.', probe: '/issues?per_page=1' },
  {
    key: 'organization_administration', name: 'Organization administration', write: 'write', org: true,
    why: 'Optional, organisation repos only: add the organisation rule that makes pipegen\'s required workflow run on every pull request.',
  },
  {
    key: 'members', name: 'Organization members', write: 'read', org: true,
    why: 'Optional, organisation repos only: read whether you own the organisation and who can write, to suggest code owners.',
  },
];

/**
 * The READ-ONLY table: exactly what `pipegen audit` and `pipegen inspect` call on the audited repo (Plan U final review
 * I3; spec §7 "only read access to the one repo", §12 least privilege). Every GitHub call those two commands make on
 * it, and the fine-grained token permission GitHub's docs list for it
 * (https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens and
 * https://docs.github.com/en/rest/authentication/endpoints-available-for-fine-grained-personal-access-tokens, both
 * checked 2026-10-27):
 * - GET /repos/{o}/{r} (visibility, owner, default branch)            → Metadata: read
 * - GET /repos/{o}/{r}/rulesets (is a merge lock possible)            → Metadata: read
 * - GET /repos/{o}/{r}/events (pushes, last 30 days)                   → Metadata: read
 * - GET /repos/{o}/{r}/pulls?state=all (pull requests, last 30 days)  → Pull requests: read
 * - GET /repos/{o}/{r}/environments                                    → Actions: read
 * - GET /repos/{o}/{r}/environments/{env}/deployment-branch-policies  → Actions: read
 * - GET /repos/{o}/{r}/code-scanning/analyses                          → Code scanning alerts: read (without it, code
 *   scanning on a private repo reads "not available", with a note that pipegen couldn't check)
 * - GET /repos/{o}/{r}/code-scanning/default-setup (with a token only)  → Administration: read, which this table does
 *   NOT ask for: a refusal is expected and pipegen falls back to the workflow list below (P55)
 * - GET /repos/{o}/{r}/actions/workflows, …/actions/workflows/{id}/runs, …/actions/runs/{id}/jobs → Actions: read
 *   (CodeQL default setup's dynamic workflow and its languages; the last run of each workflow that covers a check, P55)
 * - GET /user (the token's login, for a personal account's plan), GET /orgs/{org} (an organisation's plan),
 *   GET /user/installations and /user/installations/{id}/repositories (pipegen's App: which repos it reaches): no
 *   repository permission.
 * `audit --ai` also reads OTHER public repos for its tool search (search, releases, contents, advisories): a
 * fine-grained token can always read public repos, so that needs nothing here. The audit reads the code from the clone
 * on disk, never through the API, so Contents isn't asked for. No Secrets, Variables, Environments or Administration
 * call is made. `key`: the GitHub App permission name; `probe`: a GET probePermissions uses to confirm it.
 */
const READ_PERMISSIONS: readonly PermissionRow[] = [
  { key: 'metadata', name: 'Metadata', write: 'read', read: 'read', why: '', readWhy: 'Repo details (visibility, default branch), the rulesets list and recent pushes.', probe: '' },
  { key: 'pull_requests', name: 'Pull requests', write: 'read', read: 'read', why: '', readWhy: 'Count the pull requests opened in the last 30 days.', probe: '/pulls?per_page=1' },
  { key: 'actions', name: 'Actions', write: 'read', read: 'read', why: '', readWhy: 'The environments list, the signing environment\'s branch rule, whether CodeQL default setup is on, and the last run of each workflow that covers a check.', probe: '/environments?per_page=1' },
  {
    key: 'security_events', name: 'Code scanning alerts', write: 'read', read: 'read', why: '',
    readWhy: 'Whether code scanning has run here (optional: without it pipegen can\'t confirm code scanning on a private repo). pipegen reads no alerts.',
    probe: '/code-scanning/analyses?per_page=1',
  },
];

const levelText = (l: Level) => (l === 'write' ? 'read and write' : 'read');
const label = (p: PermissionRow, mode: Level): string =>
  `${p.name}: ${levelText(mode === 'write' ? p.write : (p.read as Level))}${p.appOnly ? ' (GitHub App only)' : ''}${p.org ? ' (organisation, optional)' : ''}`;
const rowsFor = (mode: Level) => (mode === 'write' ? PERMISSIONS : READ_PERMISSIONS);
/** `app`: pipegen's own GitHub App login, which creates and deletes the helper repos (#87); else token mode, which never does. */
const entry = (p: PermissionRow, mode: Level, app: boolean) => ({
  permission: label(p, mode),
  why: mode === 'read' ? (p.readWhy as string) : app ? p.why : p.tokenWhy ?? p.why,
});

/**
 * The permissions pipegen asks for, each with a one-line reason (README, --help, the access steps and the consent
 * screen). Read mode is READ_PERMISSIONS: what the audit and inspect call, nothing more. Write mode needs to know
 * whether pipegen's App creates and deletes the helper repos (Auth.canCreateRepos, DECISIONS #87): in token mode no
 * row says pipegen creates or deletes a repo.
 */
export function permissionsTable(mode: 'read'): { permission: string; why: string }[];
export function permissionsTable(mode: 'write', opts: { appCreatesRepos: boolean }): { permission: string; why: string }[];
export function permissionsTable(mode: 'read' | 'write', opts?: { appCreatesRepos: boolean }): { permission: string; why: string }[] {
  return rowsFor(mode).map((p) => entry(p, mode, opts?.appCreatesRepos === true));
}

/** "metadata=read; contents=write,workflows=write" → the table's names, e.g. "Metadata: read". */
function acceptedNames(header: string | undefined): string[] {
  if (header === undefined) return [];
  const names: string[] = [];
  for (const alt of header.split(';')) {
    for (const pair of alt.split(',')) {
      const [key, level] = pair.trim().split('=');
      const row = PERMISSIONS.find((p) => p.key === key) ?? READ_PERMISSIONS.find((p) => p.key === key);
      const lvl = level === 'write' ? 'write' : level === 'read' ? 'read' : undefined;
      const name = row !== undefined && lvl !== undefined ? `${row.name}: ${levelText(lvl)}` : safeText(pair.trim(), 60);
      if (name !== '' && !names.includes(name)) names.push(name);
    }
  }
  return names;
}

// ---------- token kind and setup steps ----------

const TOKEN_CHARS = /^[A-Za-z0-9_]{20,255}$/;

/**
 * What a token is, by its prefix (S1): ghu_ App user token, github_pat_ fine-grained, ghp_/gho_/40-hex classic,
 * ghs_ installation token (the Actions GITHUB_TOKEN). Else null.
 */
export function tokenKind(token: string): Exclude<Auth['kind'], 'anonymous'> | null {
  if (!TOKEN_CHARS.test(token)) return null;
  if (token.startsWith('ghu_')) return 'app';
  if (token.startsWith('ghs_')) return 'installation';
  if (token.startsWith('github_pat_')) return 'fine-grained';
  if (token.startsWith('ghp_') || token.startsWith('gho_') || /^[0-9a-f]{40}$/.test(token)) return 'classic';
  return null;
}

const FG_PAGE = 'GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token';

/**
 * How to give pipegen read access to one repo (spike S1): a fine-grained token for that repo only, with the read-only
 * permissions, or pipegen's GitHub App. Never `gh auth login` (its token reaches every repo of the account).
 */
export function readAccessSteps(owner: string, repo: string): string {
  const perms = permissionsTable('read').map((p) => p.permission).join(', ');
  return `pipegen needs read access to ${repoName(owner, repo)}. Create a fine-grained token for this one repo (${FG_PAGE}; `
    + `Repository access: Only select repositories → ${safeText(repo, 100)}) with ${perms}, and set it as GITHUB_TOKEN `
    + '(or install the pipegen GitHub App on this repo). pipegen refuses broad classic tokens.';
}

/**
 * DoD run 2026-10-29: the read-only token that lifts the anonymous rate limit (60 requests an hour; 5,000 with a
 * token), with exactly the permissions the audit reads with (permissionsTable('read')).
 */
export function readOnlyTokenHint(repo: string): string {
  const perms = permissionsTable('read').map((p) => p.permission).join(', ');
  return `set GITHUB_TOKEN to a read-only fine-grained token for this one repo (${FG_PAGE}; Repository access: Only select repositories → `
    + `${safeText(repo, 100)}) with ${perms}. Every one of them is read-only; GitHub then allows 5,000 requests an hour.`;
}

/**
 * No token, and GitHub doesn't show the repo to anonymous callers (Plan U ruling S22): a 404 can't tell a private repo
 * from a missing one, so the message says both, then how to give read access.
 */
function anonymousCantSee(owner: string, repo: string): string {
  return `pipegen can't see ${repoName(owner, repo)}: it's private or doesn't exist. If it's private, ${readAccessSteps(owner, repo)}`;
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
const INSTALLATION_WRITE = 'The Actions GITHUB_TOKEN is only accepted for read-only audit. To change a repo, use pipegen\'s GitHub App '
  + 'or a fine-grained token limited to the repos pipegen works on.';
const ALL_REPOS = 'pipegen won\'t use this GitHub App login: the App is installed on "All repositories", so it reaches every repo of '
  + 'the account. Change the installation to "Only select repositories" (GitHub → Settings → Applications → Installed GitHub Apps → '
  + 'Configure), or run again with --allow-broad-token.';
const SCOPE_UNCONFIRMED = 'pipegen couldn\'t confirm which repos its GitHub App installation reaches, so it treats it as "All repositories" '
  + 'and won\'t use it. Check the installation is on "Only select repositories" (GitHub → Settings → Applications → Installed GitHub Apps → '
  + 'Configure) and try again, or run again with --allow-broad-token.';
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
  /** Plain-English lines about choices getAuth made (for example a scope it couldn't confirm, allowed by --allow-broad-token). */
  notes?: string[];
  /**
   * Filled with the body of the anonymous GET /repos/{owner}/{repos[0]} getAuth makes without a token, so the caller can
   * hand it to readGitHubContext (`opts.known`) instead of asking GitHub again (review M6: one request less per run).
   */
  repoAnswer?: { data?: unknown };
}
type AuthOpts = { owner: string; repos: string[]; allowBroad: boolean };

/** An Auth whose token is non-enumerable: JSON.stringify, util.inspect and spreads leave it out. */
function authWith(token: string, rest: Omit<Auth, 'token'>): Auth & { token: string } {
  const auth = { ...rest } as Auth & { token: string };
  Object.defineProperty(auth, 'token', { value: token, enumerable: false, writable: false });
  return auth;
}

interface Installation { id: number; login: string; selection: 'all' | 'selected' | 'unknown'; permissions: Record<string, string> }
/**
 * The App installation on `owner` (case-insensitive); 'none' when GitHub's list has none for `owner`; 'error' when
 * GitHub wouldn't say (a refusal, an error, an unreadable answer, too many pages). Rate stops and 401s are thrown.
 */
async function installationFor(gh: Octokit, owner: string, clock: RateClock): Promise<Installation | 'none' | 'error'> {
  for (let page = 1; page <= 10; page++) {
    let data: unknown;
    try {
      data = (await withRateLimit(() => gh.request('GET /user/installations', { per_page: 100, page }), clock)).data;
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (rejectedOn(gh, e)) throw tokenRejected();
      return 'error';
    }
    // S9: count the list, never total_count (it lagged behind after a delete)
    const list = (data as { installations?: unknown } | null)?.installations;
    if (!Array.isArray(list)) return 'error';
    for (const i of list as { id?: unknown; account?: { login?: unknown }; repository_selection?: unknown; permissions?: unknown }[]) {
      const login = i?.account?.login;
      if (typeof login === 'string' && login.toLowerCase() === owner.toLowerCase()) {
        const perms = i.permissions !== null && typeof i.permissions === 'object' ? i.permissions as Record<string, unknown> : {};
        const selection = i.repository_selection === 'all' || i.repository_selection === 'selected' ? i.repository_selection : 'unknown';
        return {
          id: typeof i.id === 'number' ? i.id : -1, login, selection,
          permissions: Object.fromEntries(Object.entries(perms).filter(([, v]) => typeof v === 'string')) as Record<string, string>,
        };
      }
    }
    if (list.length < 100) return 'none';
  }
  return 'error';
}

const INSTALLATION_REPO_PAGES = 50;
/**
 * The repos (lower-case "owner/name") an App installation may touch: GET /user/installations/{id}/repositories, paged
 * by its Link header, counting the items (S9: total_count lagged). null when GitHub won't say. Rate stops are thrown.
 */
async function installationRepos(gh: Octokit, id: number, clock: RateClock): Promise<Set<string> | null> {
  const names = new Set<string>();
  for (let page = 1; page <= INSTALLATION_REPO_PAGES; page++) {
    let res: { data: unknown; headers: Record<string, unknown> };
    try {
      res = await withRateLimit(() => gh.request('GET /user/installations/{installation_id}/repositories', { installation_id: id, per_page: 100, page }), clock);
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (rejectedOn(gh, e)) throw tokenRejected();
      return null;
    }
    const list = (res.data as { repositories?: unknown } | null)?.repositories;
    if (!Array.isArray(list)) return null;
    for (const r of list as { full_name?: unknown }[]) if (typeof r?.full_name === 'string') names.add(r.full_name.toLowerCase());
    if (!/rel="next"/.test(String(res.headers.link ?? ''))) return names;
  }
  return null;   // more pages than pipegen reads: it won't claim to know
}

/**
 * How pipegen logs in to GitHub (S1 strategy). `repos`: the repo names (under `owner`) pipegen works on.
 * - write mode needs a token (no token → the setup steps); read mode without a token works for a public repo only
 *   (checked with an anonymous GET /repos/{owner}/{repos[0]}) and gives kind 'anonymous';
 * - classic tokens, and an App installed on "All repositories", are refused unless allowBroad; unknown kinds are refused;
 * - an Actions GITHUB_TOKEN (ghs_) works in read mode only (kind 'installation');
 * - canCreateRepos/canDeleteRepos: write mode, pipegen's own App login (not a ghu_ token from GITHUB_TOKEN), and the
 *   installation on `owner` holds Administration write.
 */
export function getAuth(opts: AuthOpts & { mode: 'write' }, deps?: AuthDeps): Promise<Auth & { token: string }>;
export function getAuth(opts: AuthOpts & { mode: 'read' }, deps?: AuthDeps): Promise<Auth>;
export function getAuth(opts: AuthOpts & { mode: 'read' | 'write' }, deps?: AuthDeps): Promise<Auth>;
export async function getAuth(opts: AuthOpts & { mode: 'read' | 'write' }, deps: AuthDeps = {}): Promise<Auth> {
  const { owner, repos, allowBroad, mode } = opts;
  checkRepoNames(owner, repos);
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
      if (deps.repoAnswer !== undefined) deps.repoAnswer.data = res.data;
    } catch (e) {
      if (isRateStop(e)) throw e;
      const status = failure(e).status;
      // no answer, a server error or a 401 on an anonymous call: GitHub itself is the problem, not the user's access
      if (status === undefined || status === 401 || status >= 500) {
        throw new GitHubAccessError(`pipegen couldn't reach ${GITHUB_API} to check ${repoName(owner, repo)} (${said(e)}).`);
      }
    }
    if (!isPublic) throw new GitHubAccessError(anonymousCantSee(owner, repo));
    return { kind: 'anonymous', token: null, repos: [repo], canCreateRepos: false, canDeleteRepos: false };
  }

  remember(token);
  const kind = tokenKind(token);
  if (kind === null || (fromApp && kind !== 'app')) throw new GitHubAccessError(UNKNOWN_TOKEN);
  if (kind === 'classic' && !allowBroad) throw new GitHubAccessError(CLASSIC_REFUSED);
  if (kind === 'installation') {
    if (mode === 'write') throw new GitHubAccessError(INSTALLATION_WRITE);
    return authWith(token, { kind, repos: [...repos], canCreateRepos: false, canDeleteRepos: false });
  }

  let manage = false;
  let broad = kind === 'classic';
  if (kind === 'app') {
    const inst = await installationFor(makeOctokit(token, { fetch: deps.fetch, clock }), owner, clock);
    // fail closed (fix round 2, N2): a lookup GitHub wouldn't answer, or a scope it didn't state, counts as "All repositories"
    const unconfirmed = inst === 'error' || (typeof inst === 'object' && inst.selection === 'unknown');
    if (unconfirmed || (typeof inst === 'object' && inst.selection === 'all')) {
      if (!allowBroad) throw new GitHubAccessError(unconfirmed ? SCOPE_UNCONFIRMED : ALL_REPOS);
      if (unconfirmed) deps.notes?.push('pipegen couldn\'t confirm which repos the GitHub App installation reaches; treated it as "All repositories" (--allow-broad-token).');
      broad = true;
    }
    // never create or delete through an installation whose scope pipegen couldn't confirm
    manage = mode === 'write' && fromApp && !unconfirmed && typeof inst === 'object' && inst.permissions.administration === 'write';
  }
  return authWith(token, { kind, repos: broad ? 'all' : [...repos], canCreateRepos: manage, canDeleteRepos: manage });
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
 * `login` is null for anonymous access and for an installation token (ghs_, which has no user).
 * `notes`: when given, gets a line when GitHub's full_name isn't owner/repo (any letter case): the repo was renamed or
 * transferred and GitHub answered for the new one.
 * `opts.known`: the body of a GET /repos/{owner}/{repo} already made in this run (getAuth's `repoAnswer`), read with the
 * same checks instead of asking again (review M6). An anonymous client never asks GET /orgs: GitHub shows an
 * organisation's plan only to its members, so the answer would be 'unknown' anyway (one request less per run).
 */
export async function readGitHubContext(
  gh: Octokit, owner: string, repo: string, login: string | null, clock: RateClock = clockOf(gh), notes?: string[],
  opts: { known?: unknown; planRateStop?: 'unknown' } = {},
): Promise<Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>> {
  checkRepoNames(owner, [repo]);
  let data: { private?: unknown; default_branch?: unknown; owner?: { type?: unknown }; full_name?: unknown };
  try {
    data = (opts.known !== undefined && opts.known !== null && typeof opts.known === 'object' ? opts.known
      : (await withRateLimit(() => gh.rest.repos.get({ owner, repo }), clock)).data) as typeof data;
  } catch (e) {
    if (isRateStop(e)) throw new GitHubAccessError(`GitHub's rate limit stopped pipegen reading ${repoName(owner, repo)}.`, { cause: e });
    if (rejectedOn(gh, e)) throw tokenRejected();
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
  // GitHub follows a renamed or transferred repo to its new name (review M12): say so, and go on with that repo's facts
  const fullName = typeof data.full_name === 'string' ? data.full_name : null;
  if (notes !== undefined && fullName !== null && fullName.toLowerCase() !== `${owner}/${repo}`.toLowerCase()) {
    const shown = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/.test(fullName) ? fullName : safeText(fullName, 160);
    notes.push(`GitHub says this repo is now ${shown} (renamed or transferred); the facts below are for that repo.`);
  }
  let plan: Plan = 'unknown';
  const readPlan = async (call: () => Promise<{ data: unknown }>) => {
    try {
      plan = planOf((await withRateLimit(call, clock)).data);
    } catch (e) {
      // DoD run 2026-10-29: the audit asks for planRateStop 'unknown': the repo's facts are read, so a rate stop on
      // the plan alone leaves the plan unknown (as for any other failure) and the run goes on
      if (isRateStop(e) && opts.planRateStop === undefined) throw e;
      if (isRateStop(e)) notes?.push("Couldn't check the account's GitHub plan: GitHub's rate limit was reached.");
      else if (rejectedOn(gh, e)) throw tokenRejected();
      plan = 'unknown';
    }
  };
  if (ownerType === 'Organization' && !anonymousClients.has(gh)) await readPlan(() => gh.rest.orgs.get({ org: owner }));
  else if (login !== null && login.toLowerCase() === owner.toLowerCase()) await readPlan(() => gh.rest.users.getAuthenticated());
  return { private: data.private, ownerType, plan, defaultBranch: data.default_branch };
}

// ---------- probing the token's permissions ----------

type Row = { permission: string; why: string };
const PERMISSION_REFUSAL = /resource not accessible by (?:integration|personal access token)/i;

/**
 * What the token can't do on `repos` (under `owner`), found by real calls (never by GET /repos `permissions`).
 * - App token (`kind: 'app'`): the installation on `owner` lists its exact permissions (GET /user/installations), and
 *   which repos it may touch comes from the installation's repo list (GET /user/installations/{id}/repositories),
 *   not from GET /repos, which answers 200 for any public repo.
 * - Other tokens (fine-grained, classic, an installation token `ghs_`): GET /repos for each repo, then one read-only
 *   GET per permission that has one (S1's header evidence). A 403 "Resource not accessible…" is a missing permission
 *   (named by GitHub's x-accepted-github-permissions header when it sends one). GitHub can't show a write level without
 *   a write, so in write mode those are listed as `unchecked`, never assumed. (A fine-grained token answers 200 for a
 *   public repo outside its selection too; there the per-permission probes are what find the gap.)
 * A repo the token can't reach is missing as "Access to owner/repo". A 401 is a GitHubAccessError ("token rejected").
 * Probing never writes.
 */
export async function probePermissions(gh: Octokit, owner: string, repos: string[], opts: { kind?: Auth['kind']; mode?: 'read' | 'write'; clock?: RateClock } = {}): Promise<{ missing: Row[]; unchecked: Row[] }> {
  checkRepoNames(owner, repos);
  const mode = opts.mode ?? 'write';
  const clock = opts.clock ?? clockOf(gh);
  const missing: Row[] = [];
  const unchecked: Row[] = [];
  const add = (list: Row[], r: Row) => { if (!list.some((x) => x.permission === r.permission)) list.push(r); };
  // G13 (S12): the optional organisation rows are never required, so never checked here
  const rows = rowsFor(mode).filter((p) => (opts.kind === 'app' || !p.appOnly) && p.org !== true);
  const access = (repo: string) => `Access to ${repoName(owner, repo)}`;
  const NO_ACCESS = 'pipegen can\'t reach this repo with this token: it doesn\'t exist yet, or it isn\'t in the token\'s (or the App installation\'s) repository list.';
  const done = () => ({ missing, unchecked: unchecked.filter((u) => !missing.some((m) => m.permission === u.permission)) });

  if (opts.kind === 'app') {
    const inst = await installationFor(gh, owner, clock);
    if (inst === 'none' || inst === 'error') {
      for (const repo of repos) add(unchecked, { permission: access(repo), why: 'GitHub didn\'t list pipegen\'s App installation on this account, so pipegen couldn\'t check it.' });
      for (const p of rows) add(unchecked, entry(p, mode, opts.kind === 'app'));
      return done();
    }
    const reach = await installationRepos(gh, inst.id, clock);
    for (const repo of repos) {
      if (reach === null) add(unchecked, { permission: access(repo), why: 'GitHub didn\'t list the App installation\'s repos, so pipegen couldn\'t check this one.' });
      else if (!reach.has(`${owner}/${repo}`.toLowerCase())) add(missing, { permission: access(repo), why: NO_ACCESS });
    }
    for (const p of rows) {
      const need = mode === 'write' ? p.write : (p.read as Level);
      const have = inst.permissions[p.key];
      if (!(have === 'write' || (have === 'read' && need === 'read'))) add(missing, entry(p, mode, opts.kind === 'app'));
    }
    return done();
  }

  const visible: string[] = [];
  for (const repo of repos) {
    try {
      await withRateLimit(() => gh.rest.repos.get({ owner, repo }), clock);
      visible.push(repo);
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (rejectedOn(gh, e)) throw tokenRejected();
      const { status } = failure(e);
      if (status === 403 || status === 404) add(missing, { permission: access(repo), why: NO_ACCESS });
      else add(unchecked, { permission: access(repo), why: `GitHub didn't answer (${said(e)}), so pipegen couldn't check this repo.` });
    }
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
          if (rejectedOn(gh, e)) throw tokenRejected();
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
    if (refused) add(missing, entry(p, mode, false));
    else if (!confirmed || (mode === 'write' && p.write === 'write')) add(unchecked, entry(p, mode, false));
  }
  return done();
}

// ---------- writers ----------

const LOGIN_RE = API_LOGIN_RE;   // E9: EMU logins too (gate/src/login.ts)
const WRITERS_PAGES = 50;

/**
 * User logins with write, maintain or admin access (GET /repos/{o}/{r}/collaborators?affiliation=all, paged). Bots and
 * logins that aren't valid GitHub logins are left out. A refused call is an error naming the permission GitHub asked
 * for (its x-accepted-github-permissions header); pipegen doesn't guess one when GitHub doesn't say.
 */
export async function listWriters(gh: Octokit, owner: string, repo: string, clock: RateClock = clockOf(gh)): Promise<string[]> {
  checkRepoNames(owner, [repo]);
  const writers: string[] = [];
  let more = false;
  // G17 row 52 (G8-r2): a full page with no Link header (a proxy that strips it) can't tell whether more follow: ask for the next page; an
  // empty or short page ends the list. A short list would plan the one-writer locks for a repo a second writer can push to.
  let full = false;
  for (let page = 1; page <= WRITERS_PAGES; page++) {
    let data: unknown;
    try {
      const res = await withRateLimit(() => gh.rest.repos.listCollaborators({ owner, repo, affiliation: 'all', per_page: 100, page }), clock);
      data = res.data;
      more = /rel="next"/.test(String(res.headers.link ?? ''));
    } catch (e) {
      if (isRateStop(e)) throw new GitHubAccessError(`GitHub's rate limit stopped pipegen listing who can write to ${repoName(owner, repo)}.`, { cause: e });
      if (rejectedOn(gh, e)) throw tokenRejected();
      const f = failure(e);
      if (anonymousClients.has(gh) && (f.status === 401 || f.status === 403)) {
        throw new GitHubAccessError(`pipegen needs a token to list who can write to ${repoName(owner, repo)} (${said(e)}).`, { status: f.status });
      }
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
    full = data.length >= 100;
    if (!more && !full) break;
  }
  // G8-R3: GitHub still has pages at the cap; a short list would plan the locks as if fewer people could write, so stop instead
  if (more || full) throw new GitHubAccessError(`${repoName(owner, repo)} has more than ${WRITERS_PAGES * 100} collaborators (${more ? `GitHub still had more pages after ${WRITERS_PAGES}` : `page ${WRITERS_PAGES} was full and GitHub didn't say whether more follow`}), too many for pipegen to read who can write; it can't plan who approves changes there.`);
  return writers;
}
