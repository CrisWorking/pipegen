// v0.2 Plan G G10 (carry CF-1, D1-r1): the GitHub calls the delivery makes, and only those. Files reach a repo only through the git
// data API (a tree built on the base tree, a commit with one parent, a ref moved), never through the contents API with a path built
// into a URL. Every call goes through the run's rate clock (withRateLimit); a rejected token stops the run. The write routes are a
// fixed list: anything else is refused before it is sent. Secrets go through src/create/secrets.ts (sealed), never through here.
import type { Octokit } from '@octokit/rest';
import { isRateStop, withRateLimit, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { validDate } from '../../gate/src/date.js';
import { safeText } from '../util/safe-text.js';

/** A delivery that stops: a plain reason, never a secret value or a server message. */
export class DeliverError extends Error {
  /** What pipegen had already stored when it stopped (names only, never a value; also in the local leftovers file). */
  leftovers: string[] = [];
  constructor(message: string, options?: { cause?: unknown; leftovers?: string[] }) { super(message, options); this.name = 'DeliverError'; this.leftovers = [...(options?.leftovers ?? [])]; }
}

/** GitHub's created_at form, the one the record keeps. */
export const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
/**
 * G11-R3 N3-2: a created_at in GitHub's form that names a real instant. The form alone is not enough: JS Date rolls `2026-02-30` over to
 * March 2 and rejects `25:61`, so an impossible one would read as a known date that differs from the recorded one (the previous value lost).
 * The day is held to the gate's one date definition, the time to 00:00:00 to 23:59:59.
 */
export function isoAt(s: unknown): s is string {
  if (typeof s !== 'string' || !ISO_RE.test(s) || validDate(s.slice(0, 10)) === undefined) return false;
  const [h, m, sec] = s.slice(11, 19).split(':').map(Number) as [number, number, number];
  return h < 24 && m < 60 && sec < 60;
}

/** G17 row 35: two created_at values that name the same real instant (GitHub writes `…03Z` and `…03.000Z` alike); anything unreadable: false. */
export const sameInstant = (a: unknown, b: unknown): boolean => isoAt(a) && isoAt(b) && Date.parse(a) === Date.parse(b);

export interface RepoRef { owner: string; repo: string }
export interface TreeEntry { sha: string; mode: string; type: string }

const PART_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
/** A branch name pipegen sends: plain, no `..`, no leading or trailing `/` or `.`, no `@{`. */
const BRANCH_RE = /^(?![/.])(?!.*(?:\.\.|\/\/|@\{|\.lock(?:\/|$)))[A-Za-z0-9._/-]{1,200}(?<![/.])$/;
const MAX_TREE_ENTRIES = 100_000;

/** The only writes the delivery sends through here (the git data API, the setup and central pull requests, the N4 signing environment). */
const WRITE_ROUTES: ReadonlySet<string> = new Set([
  'POST /repos/{owner}/{repo}/git/trees',
  'POST /repos/{owner}/{repo}/git/commits',
  'POST /repos/{owner}/{repo}/git/refs',
  'PATCH /repos/{owner}/{repo}/git/refs/{ref}',
  'POST /repos/{owner}/{repo}/pulls',
  'PATCH /repos/{owner}/{repo}/pulls/{pull_number}',
  'PUT /repos/{owner}/{repo}/environments/{environment_name}',
  'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies',
  // ruling G-SIGN1-R1: only dropRunSigningEnvironment (deliver.ts), for the pipegen-signing environment the same run made
  'DELETE /repos/{owner}/{repo}/environments/{environment_name}',
]);
const READ_RE = /^GET \/repos\/\{owner\}\/\{repo\}(?:\/[A-Za-z0-9_{}/.-]*)?$/;

export const statusOf = (e: unknown): number | undefined => {
  const s = typeof e === 'object' && e !== null ? (e as { status?: unknown }).status : undefined;
  return typeof s === 'number' ? s : undefined;
};
/** A ref move the branch refused (its rules, not a fast forward): the caller goes through a pull request instead. */
export const refusedMove = (e: unknown): boolean => { const s = statusOf(e); return s === 422 || s === 409 || s === 403; };
const said = (e: unknown): string => { const s = statusOf(e); return s === undefined ? 'no answer' : `HTTP ${s}`; };

function checkRepo(r: RepoRef): void {
  if (!PART_RE.test(String(r?.owner)) || !PART_RE.test(String(r?.repo))) throw new DeliverError('The repository owner or name is not a plain name.');
}
export function checkBranch(b: string): string {
  if (typeof b !== 'string' || !BRANCH_RE.test(b)) throw new DeliverError(`"${safeText(String(b), 100)}" is not a branch name pipegen uses.`);
  return b;
}

async function send(gh: Octokit, route: string, r: RepoRef, params: Record<string, unknown>, clock: RateClock): Promise<{ status: number; data: unknown }> {
  checkRepo(r);
  try {
    const res = await withRateLimit(() => gh.request(route, { ...params, owner: r.owner, repo: r.repo }), clock);
    return { status: res.status, data: res.data };
  } catch (e) {
    if (isRateStop(e)) throw e;
    if (statusOf(e) === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
    throw e;
  }
}

/** A GET under /repos/{owner}/{repo}; never the contents API. Errors pass through (the caller decides what a 404 means). */
export async function ghRead(gh: Octokit, route: string, r: RepoRef, params: Record<string, unknown> = {}, clock: RateClock = clockOf(gh)): Promise<unknown> {
  if (!READ_RE.test(route) || route.includes('/contents')) throw new DeliverError(`"${safeText(route, 120)}" is not a read the delivery makes.`);
  return (await send(gh, route, r, params, clock)).data;
}

/** One of WRITE_ROUTES; anything else is refused before it is sent. */
export async function ghWrite(gh: Octokit, route: string, r: RepoRef, params: Record<string, unknown>, clock: RateClock = clockOf(gh)): Promise<unknown> {
  if (!WRITE_ROUTES.has(route)) throw new DeliverError(`"${safeText(route, 120)}" is not a write the delivery makes.`);
  return (await send(gh, route, r, params, clock)).data;
}

const obj = (v: unknown): Record<string, unknown> => (typeof v === 'object' && v !== null && !Array.isArray(v) ? v as Record<string, unknown> : {});

/** The repo as GitHub reports it, or null when it is not there (404). */
export async function readRepo(gh: Octokit, r: RepoRef, clock: RateClock): Promise<{ id: number; private: boolean; defaultBranch: string; ownerType: 'User' | 'Organization' } | null> {
  let d: Record<string, unknown>;
  try { d = obj(await ghRead(gh, 'GET /repos/{owner}/{repo}', r, {}, clock)); } catch (e) {
    if (statusOf(e) === 404) return null;
    if (e instanceof DeliverError || isRateStop(e) || statusOf(e) === undefined) throw e;
    throw new DeliverError(`pipegen couldn't read ${safeText(`${r.owner}/${r.repo}`, 120)} (${said(e)}).`, { cause: e });
  }
  const type = obj(d.owner).type;
  if (!Number.isSafeInteger(d.id) || (d.id as number) <= 0 || typeof d.private !== 'boolean' || typeof d.default_branch !== 'string' || (type !== 'User' && type !== 'Organization')) {
    throw new DeliverError(`GitHub's answer about ${safeText(`${r.owner}/${r.repo}`, 120)} could not be read.`);
  }
  return { id: d.id as number, private: d.private, defaultBranch: checkBranch(d.default_branch), ownerType: type };
}

/** The commit a branch points at, or null when the branch is not there. */
export async function readHead(gh: Octokit, r: RepoRef, branch: string, clock: RateClock): Promise<string | null> {
  let d: unknown;
  try { d = await ghRead(gh, 'GET /repos/{owner}/{repo}/git/ref/{ref}', r, { ref: `heads/${checkBranch(branch)}` }, clock); } catch (e) {
    if (statusOf(e) === 404) return null;
    throw e;
  }
  const sha = obj(obj(d).object).sha;
  if (typeof sha !== 'string' || !SHA_RE.test(sha)) throw new DeliverError(`GitHub's answer about the branch ${safeText(branch, 100)} could not be read.`);
  return sha;
}

/** A commit's whole tree (recursive), blobs and links only. A truncated answer is refused: an edit is never checked against a part of a tree. */
export async function readTree(gh: Octokit, r: RepoRef, commit: string, clock: RateClock): Promise<{ tree: string; entries: Map<string, TreeEntry>; parents: string[] }> {
  if (!SHA_RE.test(commit)) throw new DeliverError('A commit id is not a full sha.');
  const c = obj(await ghRead(gh, 'GET /repos/{owner}/{repo}/git/commits/{commit_sha}', r, { commit_sha: commit }, clock));
  const tree = obj(c.tree).sha;
  const parents = (Array.isArray(c.parents) ? c.parents : []).map((x) => obj(x).sha).filter((x): x is string => typeof x === 'string' && SHA_RE.test(x));
  if (typeof tree !== 'string' || !SHA_RE.test(tree)) throw new DeliverError('GitHub\'s answer about a commit could not be read.');
  const d = obj(await ghRead(gh, 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}', r, { tree_sha: tree, recursive: '1' }, clock));
  if (d.truncated !== false || !Array.isArray(d.tree) || d.tree.length > MAX_TREE_ENTRIES) throw new DeliverError(`The file list of ${safeText(`${r.owner}/${r.repo}`, 120)} is too large for GitHub to give whole, so pipegen can't check what it changes there.`);
  const entries = new Map<string, TreeEntry>();
  for (const e of d.tree.map(obj)) {
    if (typeof e.path !== 'string' || typeof e.sha !== 'string' || typeof e.mode !== 'string' || typeof e.type !== 'string') throw new DeliverError('GitHub\'s file list could not be read.');
    if (e.type !== 'tree') entries.set(e.path, { sha: e.sha, mode: e.mode, type: e.type });
  }
  return { tree, entries, parents };
}

/** A blob's text (UTF-8), at most `maxBytes`. */
export async function readBlobText(gh: Octokit, r: RepoRef, sha: string, maxBytes: number, clock: RateClock): Promise<string> {
  if (!SHA_RE.test(sha)) throw new DeliverError('A blob id is not a full sha.');
  const d = obj(await ghRead(gh, 'GET /repos/{owner}/{repo}/git/blobs/{file_sha}', r, { file_sha: sha }, clock));
  if (d.encoding !== 'base64' || typeof d.content !== 'string' || d.content.length > Math.ceil(maxBytes / 3) * 4 + Math.ceil(maxBytes / 30) + 8) {
    throw new DeliverError('A file GitHub gave is too large or could not be read.');
  }
  const buf = Buffer.from(d.content.replace(/\n/g, ''), 'base64');
  if (buf.length > maxBytes) throw new DeliverError('A file GitHub gave is too large.');
  return buf.toString('utf8');
}

/** One commit: the files on top of `baseTree`, one parent. Returns the commit and its tree. */
export async function commitFiles(gh: Octokit, r: RepoRef, c: { parent: string; baseTree: string; files: readonly { path: string; content: string; mode: string }[]; message: string }, clock: RateClock): Promise<{ commit: string; tree: string }> {
  if (!SHA_RE.test(c.parent) || !SHA_RE.test(c.baseTree)) throw new DeliverError('A commit id is not a full sha.');
  if (c.files.length === 0) throw new DeliverError('A delivery commit holds no file.');
  const t = obj(await ghWrite(gh, 'POST /repos/{owner}/{repo}/git/trees', r, { base_tree: c.baseTree, tree: c.files.map((f) => ({ path: f.path, mode: f.mode, type: 'blob', content: f.content })) }, clock)).sha;
  if (typeof t !== 'string' || !SHA_RE.test(t)) throw new DeliverError('GitHub\'s answer to a new file tree could not be read.');
  const commit = obj(await ghWrite(gh, 'POST /repos/{owner}/{repo}/git/commits', r, { message: c.message, tree: t, parents: [c.parent] }, clock)).sha;
  if (typeof commit !== 'string' || !SHA_RE.test(commit)) throw new DeliverError('GitHub\'s answer to a new commit could not be read.');
  return { commit, tree: t };
}

/** Points `branch` at `sha`: created when missing, else moved (`force` only for pipegen's own branches). */
export async function setBranch(gh: Octokit, r: RepoRef, branch: string, sha: string, force: boolean, clock: RateClock): Promise<'created' | 'moved'> {
  checkBranch(branch);
  if (!SHA_RE.test(sha)) throw new DeliverError('A commit id is not a full sha.');
  if (await readHead(gh, r, branch, clock) === null) {
    await ghWrite(gh, 'POST /repos/{owner}/{repo}/git/refs', r, { ref: `refs/heads/${branch}`, sha }, clock);
    return 'created';
  }
  await ghWrite(gh, 'PATCH /repos/{owner}/{repo}/git/refs/{ref}', r, { ref: `heads/${branch}`, sha, force }, clock);
  return 'moved';
}

/** GitHub's compare status of `head` against `base` (identical, behind: head is in base's history; ahead, diverged). */
export async function compareStatus(gh: Octokit, r: RepoRef, base: string, head: string, clock: RateClock): Promise<string> {
  const s = obj(await ghRead(gh, 'GET /repos/{owner}/{repo}/compare/{basehead}', r, { basehead: `${checkBranch(base)}...${head}` }, clock)).status;
  if (typeof s !== 'string') throw new DeliverError('GitHub\'s compare answer could not be read.');
  return s;
}

/** The open pull request from `branch` (this repo), or null. */
export async function findOpenPr(gh: Octokit, r: RepoRef, branch: string, clock: RateClock): Promise<{ number: number; url: string } | null> {
  const d = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls', r, { head: `${r.owner}:${checkBranch(branch)}`, state: 'open', per_page: 10 }, clock);
  if (!Array.isArray(d)) throw new DeliverError('GitHub\'s list of pull requests could not be read.');
  const mine = d.map(obj).filter((p) => obj(p.head).ref === branch && Number.isSafeInteger(p.number));
  if (mine.length > 1) throw new DeliverError(`More than one pull request is open from ${safeText(branch, 100)}; close the extra ones, then run pipegen again.`);
  const p = mine[0];
  return p === undefined ? null : { number: p.number as number, url: typeof p.html_url === 'string' ? p.html_url : '' };
}

/** Opens the pull request from `head`, or updates the open one (title and body): never a second one. */
export async function openOrUpdatePr(gh: Octokit, r: RepoRef, pr: { head: string; base: string; title: string; body: string }, clock: RateClock): Promise<{ number: number; url: string; opened: boolean }> {
  const open = await findOpenPr(gh, r, pr.head, clock);
  if (open !== null) {
    await ghWrite(gh, 'PATCH /repos/{owner}/{repo}/pulls/{pull_number}', r, { pull_number: open.number, title: pr.title, body: pr.body }, clock);
    return { ...open, opened: false };
  }
  const d = obj(await ghWrite(gh, 'POST /repos/{owner}/{repo}/pulls', r, { head: pr.head, base: checkBranch(pr.base), title: pr.title, body: pr.body }, clock));
  if (!Number.isSafeInteger(d.number)) throw new DeliverError('GitHub\'s answer to the new pull request could not be read.');
  return { number: d.number as number, url: typeof d.html_url === 'string' ? d.html_url : '', opened: true };
}


