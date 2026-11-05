// The read-only probes the merge locks need (v0.2 Plan G G8; ruling S10, S9; carries D0b-2, D0b-r1). Each one is a GET through `gh`
// (api.github.com only). The plan (Free, Pro, Team, Enterprise) comes from readGitHubContext, never from here.
//
// What a probe that can't read its answer gives: the answer that makes planLocks plan less, never more, and a plain note.
// - readOrgAdmin: null (unknown). planLocks then plans no org required workflow and says it couldn't check.
// - readShaPinning: { state: 'unknown' }. planLocks then leaves the setting as it is and says so.
// - readRepoId: null. planLocks then plans no org required workflow (GitHub's rule names repositories by id).
// - readWriters: an error (listWriters', or a list with nobody who can write). Who can approve is never guessed.
// A rate stop is thrown, and so is a 401 on a client that sent a token (the token was rejected).
import type { Octokit } from '@octokit/rest';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import type { RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { checkRepoNames, clockOf, GitHubAccessError, githubTokenRejected, isAnonymousClient, isNoAnswer, listWriters } from './client.js';

/**
 * The repo's Actions setting "Require actions to be pinned to a full-length commit SHA" (GET /repos/{o}/{r}/actions/permissions):
 * `read` with the two values a PUT must send back unchanged (`enabled`, `allowedActions`), `absent` when GitHub's answer has no such
 * setting, `unknown` when the answer couldn't be read.
 */
export type ShaPinningRead =
  | { state: 'read'; enabled: boolean; allowedActions: string; required: boolean }
  | { state: 'absent' }
  | { state: 'unknown' };

const statusOf = (e: unknown): number | undefined => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' ? s : undefined;
};
/** One GET: its data, or undefined when it failed (rate stops and a rejected token are thrown). */
async function get(gh: Octokit, clock: RateClock, call: () => Promise<{ data: unknown }>): Promise<{ data: unknown } | { failed: 'network' | 'other' }> {
  try {
    return { data: (await withRateLimit(call, clock)).data };
  } catch (e) {
    if (isRateStop(e)) throw e;
    if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    return { failed: isNoAnswer(e) ? 'network' : 'other' };
  }
}
const why = (failed: 'network' | 'other' | 'odd'): string => (failed === 'network' ? "GitHub didn't answer (a network problem)" : failed === 'odd' ? "GitHub's answer could not be read" : "the token can't read it");

/**
 * Whether the token's user is an active owner (admin) of the organisation `org` (GET /user/memberships/orgs/{org}; a fine-grained token
 * needs the organisation's Members: read). A personal account (ownerType 'User') has no org: false, without a request. Anything other than
 * an active admin membership is false; an answer that couldn't be read is null, with a note.
 */
export async function readOrgAdmin(gh: Octokit, org: string, ownerType: RepoProfile['ownerType'], notes: string[], clock: RateClock = clockOf(gh)): Promise<boolean | null> {
  if (ownerType !== 'Organization') return false;
  checkRepoNames(org, []);
  const r = await get(gh, clock, () => gh.rest.orgs.getMembershipForAuthenticatedUser({ org }));
  const d = 'data' in r ? (r.data as { state?: unknown; role?: unknown } | null) : null;
  if (!('data' in r) || d === null || typeof d !== 'object' || typeof d.state !== 'string' || typeof d.role !== 'string') {
    notes.push(`pipegen couldn't check whether you're an owner of the ${safeText(org, 40)} organisation (${why('data' in r ? 'odd' : r.failed)}), so it plans no org required workflow.`);
    return null;
  }
  return d.state === 'active' && d.role === 'admin';
}

/** The sha-pinning setting of owner/repo (see ShaPinningRead). */
export async function readShaPinning(gh: Octokit, owner: string, repo: string, notes: string[], clock: RateClock = clockOf(gh)): Promise<ShaPinningRead> {
  checkRepoNames(owner, [repo]);
  const r = await get(gh, clock, () => gh.request('GET /repos/{owner}/{repo}/actions/permissions', { owner, repo }));
  const d = 'data' in r ? (r.data as { enabled?: unknown; allowed_actions?: unknown; sha_pinning_required?: unknown } | null) : null;
  const readable = d !== null && typeof d === 'object' && typeof d.enabled === 'boolean' && (d.allowed_actions === undefined || typeof d.allowed_actions === 'string');
  if (!readable) {
    notes.push(`pipegen couldn't read the Actions settings of ${safeText(`${owner}/${repo}`, 140)} (${why('data' in r ? 'odd' : r.failed)}).`);
    return { state: 'unknown' };
  }
  if (d.sha_pinning_required === undefined) return { state: 'absent' };
  if (typeof d.sha_pinning_required !== 'boolean' || typeof d.allowed_actions !== 'string') {
    notes.push(`pipegen couldn't read the Actions settings of ${safeText(`${owner}/${repo}`, 140)} (${why('odd')}).`);
    return { state: 'unknown' };
  }
  return { state: 'read', enabled: d.enabled as boolean, allowedActions: d.allowed_actions, required: d.sha_pinning_required };
}

/** The numeric id of owner/repo (GET /repos), which an org ruleset names repositories by; null with a note when it can't be read. */
export async function readRepoId(gh: Octokit, owner: string, repo: string, notes: string[], clock: RateClock = clockOf(gh)): Promise<number | null> {
  checkRepoNames(owner, [repo]);
  const r = await get(gh, clock, () => gh.rest.repos.get({ owner, repo }));
  const id = 'data' in r ? (r.data as { id?: unknown } | null)?.id : undefined;
  if (typeof id === 'number' && Number.isSafeInteger(id) && id > 0) return id;
  notes.push(`pipegen couldn't read the id of ${safeText(`${owner}/${repo}`, 140)} (${why('data' in r ? 'odd' : r.failed)}).`);
  return null;
}

/**
 * Who can write to the app repo and to the central repo (ruling S9: the code owners are picked from users who can write to both; D0b-r1:
 * listWriters reads every collaborator with `affiliation=all`, so direct, team and organisation-base access all count, with GitHub's
 * effective permission). Throws listWriters' error when either list can't be read.
 */
export async function readWriters(gh: Octokit, owner: string, app: string, central: string, clock: RateClock = clockOf(gh)): Promise<{ app: string[]; central: string[] }> {
  // G8-R2 I1: an answer with nobody who can write (empty, or only bots and read-only users) is a stop, never "one writer"
  const nobody = (repo: string) => new GitHubAccessError(`pipegen found nobody who can write to ${safeText(`${owner}/${repo}`, 140)} in GitHub's collaborator list (it held no user with write access), so it can't plan who approves changes. Check that the token can read the repo's collaborators, then run pipegen again.`);
  const a = await listWriters(gh, owner, app, clock);
  if (a.length === 0) throw nobody(app);
  const c = await listWriters(gh, owner, central, clock);
  if (c.length === 0) throw nobody(central);
  return { app: a, central: c };
}
