// Plan E Task 1 / sub-task E1 (spec §11, §12, §19; spikes S1, S9; preflight rulings S1, S3, S13, S19): before a proof,
// pipegen checks the two private helper repos of the app's owner:
// - `pipelines`, the central reusable workflows and install records (checked for every project; a public project keeps
//   only its install records there);
// - `pipegen-proof-<repo>`, the scratch repo where the proof runs with the user's real test keys as repo secrets.
// Both must be private (a public or internal one is asked about, made private only on Yes, never used otherwise).
//
// Repo creation (S9, S19): only pipegen's own GitHub App login creates them (Auth kind 'app' AND canCreateRepos). A
// fine-grained token never calls POST /user/repos, even with Administration write: the create succeeds, then the token
// gets 404 on the repo it made. In token mode pipegen prints the `gh repo create … --private` commands, then "add these
// repos to your token", and stops. An App that gets 422 "name already exists" for a repo it can't see (made by hand,
// so not in the installation) prints the installation's Configure steps. Org creation (POST /orgs/{org}/repos) is built
// but not live-tested (S19).
//
// Then (each a stop with the exact setting to change when it fails): the org base permission warning (orgs only, before
// the scratch repo is used), the scratch repo's Actions settings against the pins the proof uses (S13), the central
// repo's Actions access level (private projects only), and the scratch repo's default branch = the app's (S1).
// Every write goes through src/proof/target.ts (assertScratch / assertCentral, guardedWrite, createHelperRepo).
import type { Octokit } from '@octokit/rest';
import type { CliIO } from '../cli/io.js';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { checkRepoNames, clockOf, GitHubAccessError, githubTokenRejected, hideToken, isAnonymousClient, isNoAnswer } from '../github/client.js';
import type { Auth } from '../types.js';
import { safeText } from '../util/safe-text.js';
import {
  assertCentral, assertScratch, CENTRAL_REPO, createHelperRepo, guardedWrite, helperDescription, makeRepoPrivate, proofTarget, ProofStopError,
  requireGuarded, ScratchGuardError, type GuardedRepo, type ProofApp, type ProofTarget,
} from './target.js';

export interface RepoCheck { name: string; exists: boolean; private?: boolean; createCommand?: string }
export interface OrgPermission { level: 'none' | 'read' | 'write' | 'admin' | 'unknown'; warning?: string }

export interface ProofRepoOptions {
  /** From getAuth: only kind 'app' with canCreateRepos creates repos (S9, S19). */
  auth: Pick<Auth, 'kind' | 'canCreateRepos'>;
  /** Every `uses:` the proof runs in the scratch repo (owner/repo[/path]@ref), checked against its Actions settings (S13). */
  actions: readonly string[];
  /** The run id (default: a new one). */
  runId?: string;
  clock?: RateClock;
}

export interface ProofRepos {
  /** False: something the user must do first was printed (create the repos, add them to the token or the App). */
  ready: boolean;
  target: ProofTarget;
  repos: RepoCheck[];
  /** Repos pipegen created in this call (App mode). */
  created: string[];
  /** When ready: always the app's default branch (S1). */
  scratchDefaultBranch?: string;
  /** 'pending': the scratch repo has no commit yet; E2 calls setScratchDefaultBranch again after the base push. */
  defaultBranchState?: DefaultBranchState;
  /** Organisations only. */
  orgPerm?: OrgPermission;
}

export type DefaultBranchState = 'already' | 'set' | 'pending';
type ProofIO = Pick<CliIO, 'prompt' | 'out' | 'err'>;

const FG_EDIT = 'GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → the token → Edit → Repository access → add them → Update';
const APP_CONFIGURE = 'GitHub → Settings → Applications → Installed GitHub Apps → pipegen → Configure → Repository access → Select repositories → add them → Save';

/** `gh repo create <owner>/<name> --private --description "…"` for each name (validated GitHub names, a fixed description). */
export function createCommands(owner: string, names: string[]): string[] {
  checkRepoNames(owner, names);
  return names.map((n) => `gh repo create ${owner}/${n} --private --description "${helperDescription(n === CENTRAL_REPO ? 'central' : 'scratch')}"`);
}

// ---------- GitHub reads ----------

const statusOf = (e: unknown): number | undefined => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' && !isNoAnswer(e) ? s : undefined;
};
const saidOf = (e: unknown): string => {
  const s = statusOf(e);
  return s === undefined ? 'no answer from GitHub' : `HTTP ${s}`;
};
function rethrowHard(gh: Octokit, e: unknown): void {
  if (isRateStop(e)) throw e;
  if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
}
async function read(gh: Octokit, clock: RateClock, route: string, params: Record<string, unknown>): Promise<unknown> {
  return (await withRateLimit(() => gh.request(route, params), clock)).data;
}

type Seen = { exists: false } | { exists: true; visibility: 'private' | 'public' | 'internal'; defaultBranch: string };

/**
 * The visibility decision: private only when GitHub says `private: true` and, when it states one, `visibility: private`
 * (an internal repo is `private: true` too, and every enterprise member can read it).
 */
export function visibilityOf(data: unknown): 'private' | 'public' | 'internal' | null {
  const d = (data ?? {}) as { private?: unknown; visibility?: unknown };
  if (typeof d.private !== 'boolean') return null;
  if (d.visibility === 'internal') return 'internal';
  if (d.private && (d.visibility === undefined || d.visibility === 'private')) return 'private';
  return d.private ? null : 'public';
}

/** GET /repos/{owner}/{name}: 404 = not there for this token. The answer must be for that repo (no rename followed). */
async function readHelper(gh: Octokit, owner: string, name: string, clock: RateClock): Promise<Seen> {
  let data: unknown;
  try {
    data = await read(gh, clock, 'GET /repos/{owner}/{repo}', { owner, repo: name });
  } catch (e) {
    rethrowHard(gh, e);
    if (statusOf(e) === 404) return { exists: false };
    throw new GitHubAccessError(`pipegen couldn't read ${owner}/${name} (${saidOf(e)}).`, { status: statusOf(e) });
  }
  const d = (data ?? {}) as { full_name?: unknown; default_branch?: unknown };
  if (typeof d.full_name !== 'string' || d.full_name.toLowerCase() !== `${owner}/${name}`.toLowerCase()) {
    throw new ProofStopError(`GitHub answered for ${safeText(String(d.full_name), 160)} when pipegen asked for ${owner}/${name} (renamed or transferred), `
      + `so pipegen won't use it. Rename or move that repo away from ${owner}/${name}, then run pipegen again.`);
  }
  const visibility = visibilityOf(data);
  if (visibility === null || typeof d.default_branch !== 'string') throw new GitHubAccessError(`GitHub's answer about ${owner}/${name} could not be read.`);
  return { exists: true, visibility, defaultBranch: d.default_branch };
}

// ---------- org base permission ----------

/**
 * GET /orgs/{org} → default_repository_permission (plan Task 1; Review Focus 7). read, write or admin: every member can
 * read the scratch repo, which holds a copy of the code during the proof (write or admin: code owners may also get
 * review requests from the proof PRs, ruling S5). A field GitHub doesn't show (it is visible to org owners) or any
 * failure: 'unknown' with a "couldn't check" warning.
 */
export async function checkOrgBasePermission(gh: Octokit, org: string, scratch: string, clock: RateClock = clockOf(gh)): Promise<OrgPermission> {
  checkRepoNames(org, [scratch]);
  let data: unknown;
  try {
    data = await read(gh, clock, 'GET /orgs/{org}', { org });
  } catch (e) {
    rethrowHard(gh, e);
    data = null;
  }
  const level = (data as { default_repository_permission?: unknown } | null)?.default_repository_permission;
  if (level === 'none') return { level };
  if (level === 'read' || level === 'write' || level === 'admin') {
    const warning = `Every member of ${org} can read ${scratch}. It holds a copy of your code during the proof. An org owner can set the base permission to 'No permission'.`;
    return { level, warning: level === 'read' ? warning : `${warning} Code owners may get review requests from the proof PRs.` };
  }
  return { level: 'unknown', warning: `pipegen couldn't check who in ${org} can read new repos.` };
}

// ---------- Actions settings of the scratch repo (S13) ----------

const USES_RE = /^([A-Za-z0-9-]{1,39})\/[A-Za-z0-9._-]{1,100}(?:\/[A-Za-z0-9._/-]+)?@([A-Za-z0-9._/-]{1,255})$/;
const GITHUB_OWNED = new Set(['actions', 'github']);

const glob = (pattern: string, text: string, flags: string) =>
  new RegExp(`^${pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\/-]/g, '\\$&')).join('.*')}$`, flags).test(text);

/**
 * Does a GitHub "allowed actions" pattern cover `uses`? `owner/name[@ref]`, `*` anywhere; no `@` = any ref. Names are
 * matched without case, refs with case.
 */
export function patternCovers(pattern: string, uses: string): boolean {
  const at = (s: string) => { const i = s.lastIndexOf('@'); return i < 0 ? [s, undefined] as const : [s.slice(0, i), s.slice(i + 1)] as const; };
  const [pName, pRef] = at(pattern.trim());
  const [uName, uRef] = at(uses);
  if (pName === '' || uRef === undefined) return false;
  return glob(pName, uName, 'i') && (pRef === undefined || glob(pRef, uRef, ''));
}

/**
 * GET /repos/{owner}/pipegen-proof-<repo>/actions/permissions (and …/selected-actions when only some are allowed): a
 * ProofStopError with the setting to change when Actions is off, or when an action the proof uses isn't allowed
 * ('local_only': only the owner's own; 'selected': the owner's own, GitHub's own when allowed, and the patterns;
 * verified creators can't be checked here, so they don't count; sha_pinning_required: a ref that isn't a full sha).
 * A setting pipegen can't read is a warning only: the 120 s no-run check (E4) stays the backstop.
 */
export async function checkActionsAllowed(gh: Octokit, scratch: GuardedRepo, actions: readonly string[], warn: (s: string) => void = () => {}, clock: RateClock = clockOf(gh)): Promise<void> {
  requireGuarded(scratch, 'scratch');
  for (const a of actions) if (!USES_RE.test(a)) throw new ProofStopError(`"${safeText(a, 120)}" is not an action reference pipegen can check.`);
  const where = `${scratch.fullName} → Settings → Actions → General → Actions permissions`;
  const couldnt = `pipegen couldn't read the Actions settings of ${scratch.fullName}; if no proof run starts, check that Actions is on there (${where}).`;
  let perms: { enabled?: unknown; allowed_actions?: unknown; sha_pinning_required?: unknown };
  try {
    perms = (await read(gh, clock, 'GET /repos/{owner}/{repo}/actions/permissions', { owner: scratch.owner, repo: scratch.repo }) ?? {}) as typeof perms;
  } catch (e) {
    rethrowHard(gh, e);
    warn(couldnt);
    return;
  }
  if (perms.enabled === false) {
    throw new ProofStopError(`Actions is turned off on ${scratch.fullName}, so no proof run can start. Enable Actions on ${scratch.repo}: ${where} → "Allow all actions and reusable workflows", then run pipegen again.`);
  }
  if (perms.enabled !== true) { warn(couldnt); return; }
  const owner = scratch.owner.toLowerCase();
  const ownerOf = (u: string) => (USES_RE.exec(u)?.[1] ?? '').toLowerCase();
  const refOf = (u: string) => USES_RE.exec(u)?.[2] ?? '';
  let allowed: (u: string) => boolean;
  if (perms.allowed_actions === 'all') allowed = () => true;
  else if (perms.allowed_actions === 'local_only') allowed = (u) => ownerOf(u) === owner;
  else if (perms.allowed_actions === 'selected') {
    let sel: { github_owned_allowed?: unknown; patterns_allowed?: unknown };
    try {
      sel = (await read(gh, clock, 'GET /repos/{owner}/{repo}/actions/permissions/selected-actions', { owner: scratch.owner, repo: scratch.repo }) ?? {}) as typeof sel;
    } catch (e) {
      rethrowHard(gh, e);
      warn(couldnt);
      return;
    }
    const patterns = Array.isArray(sel.patterns_allowed) ? sel.patterns_allowed.filter((p): p is string => typeof p === 'string') : [];
    const githubOwned = sel.github_owned_allowed === true;
    allowed = (u) => ownerOf(u) === owner || (githubOwned && GITHUB_OWNED.has(ownerOf(u))) || patterns.some((p) => patternCovers(p, u));
  } else { warn(couldnt); return; }
  const shaOnly = perms.sha_pinning_required === true;
  const blocked = actions.filter((u) => !allowed(u) || (shaOnly && !/^[0-9a-f]{40}$/.test(refOf(u))));
  if (blocked.length > 0) {
    throw new ProofStopError(`${scratch.fullName} doesn't allow these actions the proof uses: ${blocked.join(', ')}. Change it: ${where} → `
      + `add them to "Allow specified actions and reusable workflows" (or choose "Allow all actions and reusable workflows")`
      + `${shaOnly ? '; with "Require actions to be pinned to a full-length commit SHA" on, every action needs a full sha' : ''}, then run pipegen again.`);
  }
}

// ---------- central repo Actions access (private projects) ----------

/**
 * The scratch repo must be able to call the private reusable workflows in `pipelines`: its Actions access level is set to
 * 'organization' (orgs) or 'user' (personal accounts), plan Task 1. Private projects only (a public project's
 * `pipelines` holds install records only): otherwise nothing is called. Read first; written only when different
 * ('enterprise' already covers an organisation). A refusal is a ProofStopError with the setting to change by hand.
 */
export async function ensureActionsAccess(gh: Octokit, t: ProofTarget, app: ProofApp, clock: RateClock = clockOf(gh)): Promise<void> {
  const central = assertCentral(t, app);
  if (!t.appPrivate) return;
  const org = t.ownerType === 'Organization';
  const level = org ? 'organization' : 'user';
  let current: unknown;
  try {
    current = ((await read(gh, clock, 'GET /repos/{owner}/{repo}/actions/permissions/access', { owner: central.owner, repo: central.repo })) as { access_level?: unknown } | null)?.access_level;
  } catch (e) {
    rethrowHard(gh, e);
  }
  if (current === level || (org && current === 'enterprise')) return;
  try {
    await guardedWrite(gh, central, 'PUT /repos/{owner}/{repo}/actions/permissions/access', { access_level: level }, clock);
  } catch (e) {
    if (e instanceof ScratchGuardError) throw e;
    rethrowHard(gh, e);
    const choice = org ? `Accessible from repositories in the ${t.owner} organization` : `Accessible from repositories owned by the user ${t.owner}`;
    throw new ProofStopError(`pipegen couldn't let ${t.scratch} use the workflows in ${central.fullName} (${saidOf(e)}). `
      + `Set it by hand: ${central.fullName} → Settings → Actions → General → Access → "${choice}", then run pipegen again.`);
  }
}

// ---------- default branch (S1) ----------

/**
 * Sets the scratch repo's default branch to the app's (ruling S1), so the gate's default-branch trust and the deploy
 * layer behave as in the app repo. Already equal: nothing. The branch exists: PATCH default_branch. It doesn't: made from
 * the current default head (POST git/refs), then PATCH. An empty repo (no commit): 'pending', nothing written: the base
 * push creates the branch, and E2 calls this again after it.
 */
export async function setScratchDefaultBranch(gh: Octokit, scratch: GuardedRepo, clock: RateClock = clockOf(gh)): Promise<DefaultBranchState> {
  requireGuarded(scratch, 'scratch');
  const branch = scratch.target.defaultBranch;
  const seen = await readHelper(gh, scratch.owner, scratch.repo, clock);
  if (!seen.exists) throw new GitHubAccessError(`pipegen can't see ${scratch.fullName} any more.`);
  if (seen.defaultBranch === branch) return 'already';
  const head = async (b: string): Promise<string | 'missing' | 'empty'> => {
    try {
      const d = await read(gh, clock, 'GET /repos/{owner}/{repo}/git/ref/{ref}', { owner: scratch.owner, repo: scratch.repo, ref: `heads/${b}` }) as { object?: { sha?: unknown } } | null;
      const sha = d?.object?.sha;
      if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) throw new GitHubAccessError(`GitHub's answer about the branch ${safeText(b, 100)} of ${scratch.fullName} could not be read.`);
      return sha;
    } catch (e) {
      if (e instanceof GitHubAccessError) throw e;
      rethrowHard(gh, e);
      if (statusOf(e) === 409) return 'empty';
      if (statusOf(e) === 404) return 'missing';
      throw new GitHubAccessError(`pipegen couldn't read the branches of ${scratch.fullName} (${saidOf(e)}).`, { status: statusOf(e) });
    }
  };
  const want = await head(branch);
  if (want === 'empty') return 'pending';
  if (want === 'missing') {
    const from = await head(seen.defaultBranch);
    if (from === 'empty' || from === 'missing') return 'pending';
    await guardedWrite(gh, scratch, 'POST /repos/{owner}/{repo}/git/refs', { ref: `refs/heads/${branch}`, sha: from }, clock);
  }
  const res = await guardedWrite(gh, scratch, 'PATCH /repos/{owner}/{repo}', { default_branch: branch }, clock);
  if ((res.data as { default_branch?: unknown } | null)?.default_branch !== branch) {
    throw new ProofStopError(`GitHub didn't confirm ${branch} as the default branch of ${scratch.fullName}. Set it by hand (Settings → General → Default branch), then run pipegen again.`);
  }
  return 'set';
}

// ---------- the check ----------

/**
 * Checks (and in App mode creates) the private helper repos for a proof of `app` (plan Task 1, rulings S1, S3, S13, S19).
 * Returns ready: false after printing what the user must do (create the repos, add them to the token or the App);
 * throws ProofStopError for a stop with a note (a scratch name over 100 characters, a public repo the user keeps public,
 * Actions off or not allowing the proof's actions, an access level GitHub refused). See the file comment for the order.
 */
export async function checkProofRepos(gh: Octokit, app: ProofApp, opts: ProofRepoOptions, io: ProofIO): Promise<ProofRepos> {
  const clock = opts.clock ?? clockOf(gh);
  const t = proofTarget(app, opts.runId === undefined ? {} : { runId: opts.runId });
  const central = assertCentral(t, app);
  const scratch = assertScratch(t, app);
  const result: ProofRepos = { ready: false, target: t, repos: [], created: [] };

  // the org base permission, before the scratch repo is used (Review Focus 7)
  if (t.ownerType === 'Organization') {
    result.orgPerm = await checkOrgBasePermission(gh, t.owner, t.scratch, clock);
    if (result.orgPerm.warning !== undefined) io.err(result.orgPerm.warning);
  }

  const helpers = [central, scratch];
  const seen = new Map<GuardedRepo, Seen>();
  for (const r of helpers) seen.set(r, await readHelper(gh, r.owner, r.repo, clock));

  // public or internal → ask; only Yes makes it private, and nothing public is ever used
  for (const r of helpers) {
    const s = seen.get(r) as Seen;
    if (!s.exists || s.visibility === 'private') continue;
    const msg = s.visibility === 'internal'
      ? `${r.repo} is internal (every member of the enterprise can read it). Make it private? (Y/n)`
      : `${r.repo} is public. Make it private? (Y/n)`;
    if (!(await io.prompt.confirm(msg, true))) {
      throw new ProofStopError(`pipegen won't use a public helper repo. Make ${r.fullName} private, then run pipegen again.`);
    }
    try {
      await makeRepoPrivate(gh, r, s.visibility, clock);
    } catch (e) {
      if (e instanceof ScratchGuardError || e instanceof ProofStopError) throw e;
      rethrowHard(gh, e);
      throw new ProofStopError(`pipegen couldn't make ${r.fullName} private (${saidOf(e)}). Run this, then run pipegen again:\n`
        + `  gh repo edit ${r.fullName} --visibility private --accept-visibility-change-consequences`);
    }
    seen.set(r, { ...s, visibility: 'private' });
  }

  // missing repos: created only by pipegen's own App login (S9, S19)
  const missing = helpers.filter((r) => !(seen.get(r) as Seen).exists);
  const appMode = opts.auth.kind === 'app';
  const unreachable: GuardedRepo[] = [];
  let toPrint: GuardedRepo[] = missing;
  if (missing.length > 0 && appMode && opts.auth.canCreateRepos) {
    let login: string | null = null;
    if (t.ownerType === 'User') {
      try {
        const d = await read(gh, clock, 'GET /user', {}) as { login?: unknown } | null;
        login = typeof d?.login === 'string' ? d.login : null;
      } catch (e) {
        rethrowHard(gh, e);
      }
    }
    if (t.ownerType === 'Organization' || (login !== null && login.toLowerCase() === t.owner.toLowerCase())) {
      toPrint = [];
      for (const r of missing) {
        try {
          await createHelperRepo(gh, r, login, clock);
        } catch (e) {
          if (e instanceof ScratchGuardError || e instanceof ProofStopError) throw e;
          rethrowHard(gh, e);
          const body = hideToken(JSON.stringify((e as { response?: { data?: unknown } } | null)?.response?.data ?? ''));
          if (statusOf(e) === 422 && /already exists/i.test(body)) { unreachable.push(r); continue; }
          throw new GitHubAccessError(`pipegen couldn't create ${r.fullName} (${saidOf(e)}).`, { status: statusOf(e) });
        }
        // the App reaches what it creates at once (S9): read it again, and use it only when GitHub shows it private
        const again = await readHelper(gh, r.owner, r.repo, clock);
        if (!again.exists) { unreachable.push(r); continue; }
        if (again.visibility !== 'private') throw new ProofStopError(`${r.fullName} was created but GitHub doesn't show it private, so pipegen won't use it.`);
        seen.set(r, again);
        result.created.push(r.repo);
        io.out(`Created the private repo ${r.fullName}.`);
      }
    }
  }

  result.repos = helpers.map((r) => {
    const s = seen.get(r) as Seen;
    if (s.exists) return { name: r.repo, exists: true, private: s.visibility === 'private' };
    // GitHub said it exists, but this App login can't see it: no create command for it
    return unreachable.includes(r) ? { name: r.repo, exists: true } : { name: r.repo, exists: false, createCommand: createCommands(t.owner, [r.repo])[0] as string };
  });

  if (toPrint.length > 0 || unreachable.length > 0) {
    if (toPrint.length > 0) {
      io.err(['Create these private repos, then run pipegen again:', ...createCommands(t.owner, toPrint.map((r) => r.repo)).map((c) => `  ${c}`)].join('\n'));
    }
    const names = [...toPrint, ...unreachable].map((r) => r.fullName).join(', ');
    if (appMode) {
      io.err(`pipegen's GitHub App can't reach ${names}: a repo made by hand isn't added to the App by itself. Add it: ${APP_CONFIGURE}. Then run pipegen again.`);
    } else if (opts.auth.kind === 'fine-grained') {
      io.err(`Then add these repos to your token: ${names} (${FG_EDIT}). If a repo already exists, only add it.`);
    }
    return result;
  }

  // the proof's actions are allowed in the scratch repo (S13); the central workflows are callable (private projects)
  await checkActionsAllowed(gh, scratch, opts.actions, (s) => io.err(s), clock);
  await ensureActionsAccess(gh, t, app, clock);
  result.defaultBranchState = await setScratchDefaultBranch(gh, scratch, clock);
  result.scratchDefaultBranch = t.defaultBranch;
  result.ready = true;
  return result;
}

