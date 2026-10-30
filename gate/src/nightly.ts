// Plan C Task C7: the gate action's `nightly` mode. It runs on a schedule and opens or updates ISSUES, nothing else:
//   - `warn-ending-<date>` warn mode ends in 1 or 2 days and old findings exist (counted from the TRUSTED, MAC-verified baseline, S13) or are unknown;
//   - `finish-missing-<merge commit sha>` the setup pull request merged more than 24 hours ago and the PIPEGEN_BLOCK_FROM variable is still unset;
//   - `update-<ver>`   a newer pipegen gate is out (released at least 7 days ago), with the exact patch for the pin line(s) in pipegen.yml;
//   - `warn-first-<need>-<date>` a warn-first check's warn period ended (WARN_FIRST_DAYS after the later of its start and the setup merge,
//                      #96, S12; final review fix round A): make it blocking with `pipegen update` (a reviewed pull request; CI never edits a workflow).
// It NEVER writes a file or a workflow (the job has `contents: read`, `actions: read`, `issues: write`): the only calls that are not reads
// are createIssue and updateIssue, and the adapter has no other write method (test/gate-nightly.test.ts spies on all of it).
//
// Premises that must not move:
//   - A clean-run marker can only make the gate stricter (C3). Nightly never asks for one, and a marker never suppresses an issue or a warning.
//   - Everything it reads is hostile: repo data (the payload, the pull requests, the workflow file, the baseline) and release data (tags,
//     release lists). Every repo or release string that reaches an issue goes through safeMarkdown ONCE; values that matched a strict
//     pattern (x.y.z, 40-hex, an ISO date) are the only ones put raw, and only where the pattern leaves no way to inject markup.
//   - ADVISORY ONLY. A patch issue is a prompt, not authority: any job with `issues: write`, and anyone with issue rights in a public repo,
//     can open an issue that looks exactly like pipegen's, even as github-actions[bot]. So `pipegen update` (Plan G) must re-derive the patch
//     itself, from the reviewed list bundled with the CLI, and use the issue only as a prompt to do so. The issue text says this too.
//
// Update trust chain: the releases list gives candidate versions (tags `gate-v<x.y.z>` only, never the CLI's `v*` tags, never drafts, prereleases
// or releases that are not IMMUTABLE: a mutable tag could be moved after the cooldown) and their dates; the new SHA comes ONLY from resolving that tag through the git refs API (annotated tags followed, a limited
// depth), and must be a commit with a 40-hex sha. A release body is never read. The pipegen repository is private until v0.4, so any API
// error or 404 is "no update", with a note; nothing is faked.
import { createHash } from 'node:crypto';
import { safeMarkdown } from '../../src/util/safe-text.js';
import { loadBaseline, resolveTip, WORKFLOW_PATH, type LoadResult, type RepoRef, type VerifyContext } from './baseline.js';
import { validDate } from './date.js';
import { GATE_VERSION } from './generated/gate-view.js';
import type { GateGithubAdapter } from './github-adapter.js';
import { PatchRefused, pinnedShas, updatePatch } from './pin-patch.js';

// ---------- the client ----------

/** The reads and the two issue writes nightly needs on top of GateGithub. Every answer is parsed JSON and hostile (validated here). */
export interface NightlyGithub {
  /** `GET /repos/{o}/{r}` → `{ id, full_name, default_branch, ... }` (the repository's identity: a `schedule` event payload has none). */
  getRepo(owner: string, name: string): Promise<unknown>;
  /** `POST /repos/{o}/{r}/issues/{n}/labels` (adds labels; an issue endpoint). */
  addLabels(owner: string, name: string, number: number, labels: readonly string[]): Promise<unknown>;
  /** `GET /repos/{o}/{r}/pulls?state=closed&head={o}:pipegen/setup&sort=updated&direction=desc&per_page&page` → an array. */
  listSetupPulls(owner: string, name: string, page: number, perPage: number): Promise<unknown>;
  /** `GET /repos/{o}/{r}/releases?per_page&page` → an array (newest first). */
  listReleases(owner: string, name: string, page: number, perPage: number): Promise<unknown>;
  /** `GET /repos/{o}/{r}/git/ref/tags/{tag}` → `{ ref, object: { type, sha } }`; a 404 or any error is thrown. */
  tagRef(owner: string, name: string, tag: string): Promise<unknown>;
  /** `GET /repos/{o}/{r}/git/tags/{sha}` → an annotated tag object `{ sha, object: { type, sha } }`. */
  gitTag(owner: string, name: string, sha: string): Promise<unknown>;
  /** `GET /repos/{o}/{r}/issues?state=all&labels=pipegen&creator=github-actions[bot]&sort=created&direction=desc&per_page&page` → an array (pull requests included). `labelled: false` drops the label filter (the fallback page). */
  listIssues(owner: string, name: string, page: number, perPage: number, labelled?: boolean): Promise<unknown>;
  /** `GET /repos/{o}/{r}/issues/{n}` (for `closed_by`). */
  getIssue(owner: string, name: string, number: number): Promise<unknown>;
  /** `POST /repos/{o}/{r}/issues` → `{ number }`. */
  createIssue(owner: string, name: string, issue: { title: string; body: string; labels?: readonly string[] }): Promise<unknown>;
  /** `PATCH /repos/{o}/{r}/issues/{n}` (title and body only) → `{ number }`. */
  updateIssue(owner: string, name: string, number: number, issue: { title: string; body: string }): Promise<unknown>;
}
export type NightlyAdapter = GateGithubAdapter & NightlyGithub;

// ---------- reading hostile data ----------

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const SHA_RE = /^[0-9a-f]{40}$/;
/** x.y.z with no leading zeros and at most 6 digits a part (no overflow, no `1e3`, no prerelease). */
const SEMVER_RE = /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/;
const GATE_TAG_RE = /^gate-v((?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5}))$/;
const ISO_RE = /^(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const DAY_MS = 86_400_000;

/** The time of an ISO UTC timestamp as GitHub writes it, or undefined. */
function isoTime(v: unknown): number | undefined {
  if (typeof v !== 'string') return undefined;
  const m = ISO_RE.exec(v);
  if (m === null || validDate(m[1]) === undefined) return undefined;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : undefined;
}
const clockOf = (d: Date): number | undefined => (d instanceof Date && Number.isFinite(d.getTime()) ? d.getTime() : undefined);
function semver(v: string): [number, number, number] | undefined {
  const m = SEMVER_RE.exec(v);
  return m === null ? undefined : [Number(m[1]), Number(m[2]), Number(m[3])];
}
const newer = (a: [number, number, number], b: [number, number, number]): boolean => (a[0] !== b[0] ? a[0] > b[0] : a[1] !== b[1] ? a[1] > b[1] : a[2] > b[2]);

// ---------- the rules ----------

/** The block date that counts: the EARLIER of the variable and the date recorded at setup, each only if it is a real date (S13, mode.ts). */
export function effectiveBlockFrom(blockFrom: string | undefined, recorded: string | undefined): string | undefined {
  const dates = [validDate(blockFrom), validDate(recorded)].filter((x): x is string => x !== undefined).sort();
  return dates[0];
}

/**
 * Whether warn mode is about to end. `blockFrom` is the effective date (effectiveBlockFrom). `oldFindings` is the count from the trusted
 * baseline, or 'unknown' when there is none. Null when there is no valid date, the date has come (block mode runs from 00:00 UTC of it), or
 * there are no old findings (0). Otherwise `open` is true when 1 or 2 days are left; the issue for 'unknown' is the softer variant.
 */
export function warnEnding(blockFrom: string | undefined, today: Date, oldFindings: number | 'unknown'): { open: boolean; daysLeft: number; unknown: boolean } | null {
  const date = validDate(blockFrom);
  const now = clockOf(today);
  if (date === undefined || now === undefined) return null;
  const startOfToday = Math.floor(now / DAY_MS) * DAY_MS;
  const daysLeft = Math.round((Date.parse(`${date}T00:00:00Z`) - startOfToday) / DAY_MS);
  if (daysLeft <= 0) return null;
  const unknown = typeof oldFindings !== 'number' || !Number.isSafeInteger(oldFindings) || oldFindings < 0;
  if (!unknown && oldFindings === 0) return null;
  return { open: daysLeft <= 2, daysLeft, unknown };
}

/**
 * The setup PR merged more than 24 hours ago and PIPEGEN_BLOCK_FROM is not set. A value that is not a real date counts as unset (a writer
 * can not silence the issue with junk). Without a proven merge time (undefined, not a timestamp, in the future) it is false.
 */
export function finishMissing(blockFrom: string | undefined, setupMergedAt: string | undefined, now: Date): boolean {
  if (validDate(blockFrom) !== undefined) return false;
  const merged = isoTime(setupMergedAt);
  const clock = clockOf(now);
  if (merged === undefined || clock === undefined) return false;
  return clock - merged > DAY_MS;
}

/** How long a warn-first check only warns (DECISIONS #96): 14 days. */
export const WARN_FIRST_DAYS = 14;
const NEED_ID_RE = /^(?!base-)(?!.*--)[a-z0-9][a-z0-9-]{0,63}$/;
/**
 * The day a warn-first check's warn period ends (YYYY-MM-DD): WARN_FIRST_DAYS after the later of `since` (the day it became warn-first) and the
 * day the setup pull request merged (a check can not leave warn mode before pipegen is installed). Undefined without a real `since` or a proven
 * merge time (nothing is opened on a doubt).
 */
export function warnFirstEnd(since: string, setupMergedAt: string | undefined): string | undefined {
  const start = validDate(since);
  const merged = isoTime(setupMergedAt);
  if (start === undefined || merged === undefined) return undefined;
  const from = Math.max(Date.parse(`${start}T00:00:00Z`), Math.floor(merged / DAY_MS) * DAY_MS);
  return new Date(from + WARN_FIRST_DAYS * DAY_MS).toISOString().slice(0, 10);
}

/** The cooldown before a release counts: 7 days (the same rule as for every pinned action). */
export const UPDATE_COOLDOWN_DAYS = 7;
/** A newer version (x.y.z), released at least UPDATE_COOLDOWN_DAYS ago. */
export function updateAvailable(current: string, latest: { version: string; publishedAt: string } | null, now: Date): boolean {
  if (latest === null) return false;
  const cur = semver(current);
  const next = semver(latest.version);
  const published = isoTime(latest.publishedAt);
  const clock = clockOf(now);
  if (cur === undefined || next === undefined || published === undefined || clock === undefined) return false;
  return newer(next, cur) && clock - published >= UPDATE_COOLDOWN_DAYS * DAY_MS;
}

// ---------- updatePatch (gate/src/pin-patch.ts) ----------

export { PatchRefused, pinnedShas, updatePatch } from './pin-patch.js';   // re-exported: nightly's interface

// ---------- the repository ----------

const FULL_RE = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/;
/**
 * The repository nightly works on, from GITHUB_REPOSITORY and GITHUB_REPOSITORY_ID plus one read, `GET /repos/{o}/{r}`: the answer's id must equal
 * the runner's id and its full_name must equal GITHUB_REPOSITORY (any case); the default branch is the answer's. The event payload is never read:
 * a `schedule` run's payload is only `{"schedule": "<cron>"}`. A string is the reason it could not be established (fail closed).
 */
export async function resolveRepo(gh: NightlyGithub, full: string | undefined, idText: string | undefined): Promise<RepoRef | string> {
  const m = typeof full === 'string' ? FULL_RE.exec(full) : null;
  if (m === null || m[2] === '.' || m[2] === '..') return 'GITHUB_REPOSITORY is not an owner/name';
  if (typeof idText !== 'string' || !/^[1-9][0-9]{0,15}$/.test(idText) || !Number.isSafeInteger(Number(idText))) return 'GITHUB_REPOSITORY_ID is not a repository id';
  const [owner, name] = [m[1] as string, m[2] as string];
  let a: unknown;
  try { a = await gh.getRepo(owner, name); } catch { return 'the repository could not be read (GET /repos/{owner}/{name})'; }
  if (!isPlain(a)) return 'the repository answer is not an object';
  const id = own(a, 'id');
  const fullName = own(a, 'full_name');
  const branch = own(a, 'default_branch');
  if (id !== Number(idText)) return 'the repository id does not equal GITHUB_REPOSITORY_ID';
  if (typeof fullName !== 'string' || fullName.toLowerCase() !== (full as string).toLowerCase()) return 'the repository name does not equal GITHUB_REPOSITORY';
  if (typeof branch !== 'string' || branch === '' || branch.length > 255) return 'the repository answer has no default branch';
  return { owner, name, id: Number(idText), defaultBranch: branch };
}

// ---------- issues ----------

/** The author of every issue nightly opens: the workflow token's own bot. The key marker is looked for only in issues by this account. */
export const BOT_LOGIN = 'github-actions[bot]';
export const ISSUE_PAGE_CAP = 5;
const ISSUE_PER_PAGE = 100;
const KEY_RE = /^[a-z0-9][a-z0-9.-]{0,99}$/;
const MAX_TITLE = 256;
const MAX_BODY = 60_000;
const markerOf = (key: string): string => `<!-- pipegen:key=${key} -->`;

/** The label every nightly issue carries; the issue search asks for it. */
export const ISSUE_LABEL = 'pipegen';
export interface UpsertOptions { labels?: readonly string[] }
export type IssueAction = 'created' | 'updated' | 'unchanged' | 'left-closed';
export interface IssueOutcome { key: string; number: number; action: IssueAction }

/**
 * Opens the issue with this key, or updates the one that has it. The key marker must be the FIRST line of the body, and only issues by
* github-actions[bot] (type Bot) count: an issue by a person, or by any other account, is never edited and never blocks ours. A closed
 * issue is left alone only when a PERSON closed it (closed_by); one closed by a bot is treated as missing and a new one is opened. Pull requests in the list are skipped. The list is paged up to ISSUE_PAGE_CAP pages; running
 * into the cap, a failed or malformed list all FAIL CLOSED (they throw, nothing is created: no blind duplicate).
 * The caller's title and body are already escaped; the marker line is added here. Every issue carries the label `pipegen`, and the search asks for it (the
 * bot's pull requests and unrelated issues then never fill the page cap; a removed label can only cause one duplicate, never a suppression).
 */
export async function upsertIssueDetailed(gh: NightlyGithub, repo: RepoRef, key: string, title: string, body: string, opts: UpsertOptions = {}): Promise<IssueOutcome> {
  if (typeof key !== 'string' || !KEY_RE.test(key)) throw new Error('nightly: the issue key is not a plain key');
  if (typeof title !== 'string' || title === '' || title.length > MAX_TITLE) throw new Error('nightly: the issue title is empty or too long');
  if (typeof body !== 'string' || markerOf(key).length + 1 + body.length > MAX_BODY) throw new Error('nightly: the issue body is too long');
  const marker = markerOf(key);
  const wanted = opts.labels ?? [];
  // Our issues: github-actions[bot] of type Bot, first line the key marker, never a pull request. `strict` (the labelled search) throws on an entry
  // that is not an issue; the fallback page is best effort and skips such entries.
  const hitOf = (raw: unknown, strict: boolean): { number: number; state: string; title: string; body: string; labels: string[] } | undefined => {
    if (!isPlain(raw)) { if (strict) throw new Error('nightly: the issue list holds an entry that is not an issue, so no issue is written'); return undefined; }
    const number = own(raw, 'number');
    if (typeof number !== 'number' || !Number.isSafeInteger(number) || number <= 0) { if (strict) throw new Error('nightly: the issue list holds an entry with no issue number, so no issue is written'); return undefined; }
    if (own(raw, 'pull_request') !== undefined) return undefined;
    const user = own(raw, 'user');
    if (!isPlain(user) || own(user, 'login') !== BOT_LOGIN || own(user, 'type') !== 'Bot') return undefined;
    const b = own(raw, 'body');
    if (typeof b !== 'string' || (b.split('\n')[0] as string).replace(/\r$/, '') !== marker) return undefined;
    const ls = own(raw, 'labels');
    const names = Array.isArray(ls) ? ls.map((l) => (isPlain(l) ? own(l, 'name') : undefined)).filter((n): n is string => typeof n === 'string') : [];
    return { number, state: String(own(raw, 'state')), title: String(own(raw, 'title') ?? ''), body: b, labels: names };
  };
  let open: ReturnType<typeof hitOf>;
  const closed: number[] = [];
  let complete = false;
  for (let page = 1; page <= ISSUE_PAGE_CAP; page++) {
    const list = await gh.listIssues(repo.owner, repo.name, page, ISSUE_PER_PAGE);
    if (!Array.isArray(list)) throw new Error('nightly: the issue list is not a list, so no issue is written');
    for (const raw of list) {
      const h = hitOf(raw, true);
      if (h === undefined) continue;
      if (h.state === 'open') { open = h; break; }
      if (closed.length < MAX_CLOSED_CHECKS) closed.push(h.number);
    }
    if (open !== undefined) break;
    if (list.length < ISSUE_PER_PAGE) { complete = true; break; }
  }
  // The label may have been dropped (GitHub drops labels for a token without push access): one page of the bot's newest issues, with no label
  // filter, so a dropped label can not turn into a duplicate every night. Best effort: a full page does not fail closed; an API error does.
  let adopted = false;
  if (open === undefined && closed.length === 0) {
    if (!complete) throw new Error(`nightly: the issue list reaches its cap of ${ISSUE_PAGE_CAP} pages without ending, so no issue is created (it might be a duplicate)`);
    const list = await gh.listIssues(repo.owner, repo.name, 1, ISSUE_PER_PAGE, false);
    if (!Array.isArray(list)) throw new Error('nightly: the unlabelled issue list is not a list, so no issue is written');
    for (const raw of list) {
      const h = hitOf(raw, false);
      if (h === undefined) continue;
      adopted = true;
      if (h.state === 'open') { open = h; break; }
      if (closed.length < MAX_CLOSED_CHECKS) closed.push(h.number);
    }
  }
  const want = adopted ? [ISSUE_LABEL, ...wanted] : wanted;
  if (open !== undefined) {
    // a line that says the issue was re-opened after a bot closed one stays on OUR (labelled) issue; on an adopted one it is never kept (any job
    // with issues: write could have planted it: review-C7-r2 c2), so it is derived again: none. A patch label is added when the issue gains a patch, never removed
    const second = open.body.replace(/\r\n/g, '\n').split('\n')[1] ?? '';
    const kept = !adopted && /^> Reopened after a bot closed #[0-9]+\.$/.test(second) ? `${second}\n\n` : '';
    const text = `${marker}\n${kept}${body}`;
    const missing = want.filter((l) => !(open as { labels: string[] }).labels.includes(l));
    const same = open.title === title && open.body.replace(/\r\n/g, '\n') === text;
    if (!same) await gh.updateIssue(repo.owner, repo.name, open.number, { title, body: text });
    if (missing.length > 0) await ensureLabels(gh, repo, open.number, missing);
    return { key, number: open.number, action: same ? 'unchanged' : 'updated' };
  }
  // A closed issue dismisses the key only when a PERSON closed it. One closed by a bot (any workflow with issues: write can do that) counts as missing.
  let botClosed: number | undefined;
  for (const n of closed) {
    const full = await gh.getIssue(repo.owner, repo.name, n);
    if (!isPlain(full)) throw new Error(`nightly: issue #${n} could not be read, so no issue is written`);
    if (isPerson(own(full, 'closed_by'))) {
      if (adopted) await ensureLabels(gh, repo, n, [ISSUE_LABEL]);
      return { key, number: n, action: 'left-closed' };
    }
    botClosed ??= n;
  }
  // never a create without a complete search (review-C7-r2 c3): the cap may hide our open issue, whatever the search did find
  if (!complete) throw new Error(`nightly: the issue list reaches its cap of ${ISSUE_PAGE_CAP} pages without ending, so no issue is created (it might be a duplicate)`);
  const reopened = botClosed === undefined ? '' : `> Reopened after a bot closed #${botClosed}.\n\n`;
  const made = await gh.createIssue(repo.owner, repo.name, { title, body: `${marker}\n${reopened}${body}` });
  const n = isPlain(made) ? own(made, 'number') : undefined;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n <= 0) throw new Error('nightly: GitHub did not answer with the number of the new issue');
  // never trust the create call for labels: set them and check the answer (a dropped label would turn into a duplicate issue every night)
  await ensureLabels(gh, repo, n, [ISSUE_LABEL, ...wanted]);
  return { key, number: n, action: 'created' };
}

const MAX_CLOSED_CHECKS = 3;
/** A person: a user account that is not a bot (the login of a bot ends in [bot], and github-actions[bot] is one). */
function isPerson(closedBy: unknown): boolean {
  if (!isPlain(closedBy)) return false;
  const login = own(closedBy, 'login');
  return own(closedBy, 'type') === 'User' && typeof login === 'string' && login !== '' && login !== BOT_LOGIN && !login.endsWith('[bot]');
}
/** Sets labels and checks the answer: every one must be in the list GitHub returns, or this throws (a token without push access drops labels silently). */
async function ensureLabels(gh: NightlyGithub, repo: RepoRef, number: number, labels: readonly string[]): Promise<void> {
  const answer = await gh.addLabels(repo.owner, repo.name, number, labels);
  const names = Array.isArray(answer) ? answer.map((l) => (typeof l === 'string' ? l : isPlain(l) ? own(l, 'name') : undefined)) : [];
  const missing = labels.filter((l) => !names.includes(l));
  if (missing.length > 0) throw new Error(`nightly: the label ${missing.join(', ')} could not be set on issue #${number} (a token without push access drops labels), so nightly stops instead of risking a duplicate issue every night`);
}

// ---------- the setup merge ----------

const SETUP_BRANCH = 'pipegen/setup';
const PULL_PAGES = 3;
/**
 * The merge time of the latest merged PR from `pipegen/setup` in THIS repository: the head branch is exactly that name, the head repository
 * id equals the base repository id and this repository's id (a fork is ignored), the base is the default branch, and `merged_at` is a
 * timestamp not in the future and `merge_commit_sha` a 40-hex commit (it keys the issue: one instance per setup merge). Any API error or malformed answer is "no proof".
 */
export async function setupMergedAt(gh: NightlyGithub, repo: RepoRef, now: Date): Promise<{ at?: string; sha?: string; note?: string }> {
  const clock = clockOf(now);
  if (clock === undefined) return { note: 'the clock is not a date, so the setup merge is not proven' };
  let best: { t: number; at: string; sha: string } | undefined;
  try {
    for (let page = 1; page <= PULL_PAGES; page++) {
      const list = await gh.listSetupPulls(repo.owner, repo.name, page, 100);
      if (!Array.isArray(list)) return { note: 'the list of closed setup pull requests could not be read (not a list), so the setup merge is not proven' };
      for (const pr of list) {
        if (!isPlain(pr)) continue;
        const head = own(pr, 'head');
        const base = own(pr, 'base');
        if (!isPlain(head) || !isPlain(base) || own(head, 'ref') !== SETUP_BRANCH || own(base, 'ref') !== repo.defaultBranch) continue;
        const hr = own(head, 'repo');
        const br = own(base, 'repo');
        const hid = isPlain(hr) ? own(hr, 'id') : undefined;
        const bid = isPlain(br) ? own(br, 'id') : undefined;
        if (typeof hid !== 'number' || hid !== bid || hid !== repo.id) continue;
        const merged = own(pr, 'merged_at');
        const t = isoTime(merged);
        const mergeSha = own(pr, 'merge_commit_sha');
        if (t === undefined || t > clock || typeof mergeSha !== 'string' || !SHA_RE.test(mergeSha)) continue;
        if (best === undefined || t > best.t) best = { t, at: merged as string, sha: mergeSha };
      }
      if (list.length < 100) break;
    }
  } catch {
    return { note: 'the list of closed setup pull requests could not be read, so the setup merge is not proven' };
  }
  return best === undefined ? {} : { at: best.at, sha: best.sha };
}

// ---------- the update ----------

export interface GateRelease { version: string; publishedAt: string; tag: string; sha: string }
const PIPEGEN_OWNER = 'crisworking';
const PIPEGEN_NAME = 'pipegen';
const RELEASE_PAGES = 3;
const MAX_TAG_CHAIN = 4;

/** Resolves `refs/tags/<tag>` of pipegen to a commit: annotated tags are followed (at most MAX_TAG_CHAIN of them); anything but a commit with a 40-hex sha is an error. */
async function resolveGateTag(gh: NightlyGithub, tag: string): Promise<string> {
  const ref = await gh.tagRef(PIPEGEN_OWNER, PIPEGEN_NAME, tag);
  if (!isPlain(ref) || own(ref, 'ref') !== `refs/tags/${tag}`) throw new Error('the tag ref is not the tag asked for');
  let obj = own(ref, 'object');
  const seen = new Set<string>();
  for (let depth = 0; depth <= MAX_TAG_CHAIN; depth++) {
    if (!isPlain(obj)) throw new Error('the tag has no object');
    const type = own(obj, 'type');
    const sha = own(obj, 'sha');
    if (typeof sha !== 'string' || !SHA_RE.test(sha)) throw new Error('the tag points at something that is not a 40-hex sha');
    if (type === 'commit') return sha;
    if (type !== 'tag') throw new Error(`the tag points at a ${typeof type === 'string' && /^[a-z]{1,10}$/.test(type) ? type : 'thing'}, not a commit`);
    if (seen.has(sha) || depth === MAX_TAG_CHAIN) throw new Error('the annotated tag chain loops or is too long');
    seen.add(sha);
    const tagObject = await gh.gitTag(PIPEGEN_OWNER, PIPEGEN_NAME, sha);
    if (!isPlain(tagObject) || own(tagObject, 'sha') !== sha) throw new Error('the annotated tag object is not the one asked for');
    obj = own(tagObject, 'object');
  }
  throw new Error('the annotated tag chain is too long');
}

/**
 * The newest gate release that is newer than `current` and past the cooldown, with its commit resolved from the TAG (never from a release
 * body). The tag scheme is C6's `gate-v<x.y.z>`; the CLI's `v*` tags, drafts, prereleases and releases that are not immutable are ignored. Any API error, a malformed list
 * or an unresolvable tag is "no update" with a note.
 */
export async function latestGateRelease(gh: NightlyGithub, current: string, now: Date): Promise<{ release?: GateRelease; note?: string }> {
  const found: { version: string; ver: [number, number, number]; publishedAt: string; tag: string; immutable: boolean }[] = [];
  try {
    for (let page = 1; page <= RELEASE_PAGES; page++) {
      const list = await gh.listReleases(PIPEGEN_OWNER, PIPEGEN_NAME, page, 100);
      if (!Array.isArray(list)) return { note: 'no update check: the release list of pipegen could not be read (not a list)' };
      for (const r of list) {
        if (!isPlain(r)) continue;
        const tag = own(r, 'tag_name');
        const m = typeof tag === 'string' ? GATE_TAG_RE.exec(tag) : null;
        const published = own(r, 'published_at');
        if (m === null || own(r, 'draft') !== false || own(r, 'prerelease') !== false || isoTime(published) === undefined) continue;
        const ver = semver(m[1] as string);
        if (ver !== undefined) found.push({ version: m[1] as string, ver, publishedAt: published as string, tag: tag as string, immutable: own(r, 'immutable') === true });
      }
      if (list.length < 100) break;
    }
  } catch {
    return { note: 'no update check: the release list of pipegen could not be read (the repository is private until v0.4, so this is expected)' };
  }
  const eligible = found.filter((f) => updateAvailable(current, { version: f.version, publishedAt: f.publishedAt }, now)).sort((a, b) => (newer(a.ver, b.ver) ? -1 : newer(b.ver, a.ver) ? 1 : 0));
  // an immutable release locks its tag: without it the tag could be moved to another commit after the cooldown, and the commit resolved now
  // would never have waited the 7 days
  const top = eligible.find((f) => f.immutable);
  if (top === undefined) return eligible.length === 0 ? {} : { note: `no update: ${eligible[0]?.tag ?? 'the newest release'} is not an immutable release, so its tag could be moved after the cooldown` };
  try {
    const sha = await resolveGateTag(gh, top.tag);
    return { release: { version: top.version, publishedAt: top.publishedAt, tag: top.tag, sha } };
  } catch (e) {
    return { note: `no update: the tag ${top.tag} could not be resolved to a commit (${e instanceof Error ? e.message : 'unknown'})` };
  }
}

/** The blob hash git gives these bytes, computed here from the text the patch is made from (not taken from the API). */
export function blobSha(bytes: Uint8Array): string {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

const MAX_WORKFLOW_BYTES = 1024 * 1024;
/** The caller workflow at the default branch's tip: text and blob sha; or why not (a private repository has the pin in the central repository). */
async function readWorkflow(gh: NightlyAdapter, repo: RepoRef): Promise<{ text: string; baseSha: string } | { why: string }> {
  const tip = await resolveTip(gh, repo);
  if (tip === undefined) return { why: 'the default branch could not be resolved' };
  let a: unknown;
  try { a = await gh.fileAt(repo.owner, repo.name, WORKFLOW_PATH, tip); } catch { return { why: 'the workflow file could not be read' }; }
  if (a === null) return { why: 'there is no pipegen.yml in this repository (a private repository keeps the pin in the central repository)' };
  if (!isPlain(a) || own(a, 'type') !== 'file' || own(a, 'encoding') !== 'base64' || typeof own(a, 'content') !== 'string') return { why: 'the workflow file answer is not a readable file' };
  const size = own(a, 'size');
  if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0 || size > MAX_WORKFLOW_BYTES) return { why: 'the workflow file is over the size cap' };
  const bytes = Buffer.from((own(a, 'content') as string).replace(/\s+/g, ''), 'base64');
  if (bytes.length > MAX_WORKFLOW_BYTES) return { why: 'the workflow file is over the size cap' };
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return { why: 'the workflow file is not UTF-8 text' }; }
  return { text, baseSha: blobSha(bytes) };
}

// ---------- the issue texts ----------

/** The issue's repository name, escaped once. */
const repoName = (repo: RepoRef): string => safeMarkdown(`${repo.owner}/${repo.name}`, 200);
const branchName = (repo: RepoRef): string => safeMarkdown(repo.defaultBranch, 100);
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

function warnEndingIssue(repo: RepoRef, date: string, w: { daysLeft: number; unknown: boolean }, old: number | 'unknown', note: string | undefined): { title: string; body: string } {
  const days = plural(w.daysLeft, 'day', 'days');
  const count = typeof old === 'number'
    ? `There are ${plural(old, 'existing finding', 'existing findings')} on ${branchName(repo)} in the trusted baseline (signed by this repository's own pipegen run). In block mode they follow the policy and can block merges.`
    : `Old findings unknown: pipegen found no trusted baseline for ${branchName(repo)}${note === undefined ? '' : ` (${safeMarkdown(note, 300)})`}, so it can not count the findings that block mode would start to judge. Do not read this as "none".`;
  return {
    title: `pipegen: warn mode ends in ${days}${w.unknown ? '; old findings unknown' : ''}`,
    body: [
      `## Warn mode ends in ${days}`, '',
      `In ${repoName(repo)}, old findings only warn until \`${date}\` (00:00 UTC). From that day the pipegen gate runs in block mode.`, '',
      count, '',
      'What to do: fix the old findings, or accept them knowingly before that day. The date is the earlier of the repository variable `PIPEGEN_BLOCK_FROM` and the date recorded at setup; moving the variable later does not postpone a recorded date.',
      '', 'This issue is opened by pipegen\'s nightly job and updated in place every night. pipegen does not close it.',
    ].join('\n'),
  };
}

function finishMissingIssue(repo: RepoRef, mergedAt: string): { title: string; body: string } {
  return {
    title: 'pipegen: setup was merged but finish has not run',
    body: [
      '## `pipegen finish` has not run', '',
      `The pipegen setup pull request for ${repoName(repo)} was merged at \`${mergedAt}\`, more than 24 hours ago, but the repository variable \`PIPEGEN_BLOCK_FROM\` is still not set. That variable is set by \`finish\`, which also applies the repository settings.`, '',
      'Run it from a machine where you are signed in to GitHub:', '', '`npx pipegen finish`', '',
      'This issue is opened by pipegen\'s nightly job and updated in place every night. pipegen does not close it.',
    ].join('\n'),
  };
}

function warnFirstIssue(repo: RepoRef, needId: string, since: string, end: string): { title: string; body: string } {
  return {
    title: `pipegen: make the ${needId} check blocking (its warn-first period ended ${end})`,
    body: [
      `## The \`${needId}\` check can block now`, '',
      `In ${repoName(repo)}, the pipegen gate has run the \`${needId}\` check as warn-first since \`${since}\`: its failures and its old or medium findings only warn. A new critical, high or secret finding already blocks. The warn period (${WARN_FIRST_DAYS} days after setup) ended on \`${end}\`.`, '',
      'To make the check blocking, run:', '', '`npx pipegen update`', '',
      'It removes warn-first from this check in a pull request you review: `pipegen.yml` is a protected file, and CI never edits a workflow. To keep the check warn-first, close this issue: pipegen does not open it again for this check and date.', '',
      '> **This issue is advisory.** Anyone with issue rights in a public repository, and any job with `issues: write`, can open an issue that looks like this one. `pipegen update` reads the checks from your pipeline, not from this issue.',
      '', 'This issue is opened by pipegen\'s nightly job and updated in place every night. pipegen does not close it.',
    ].join('\n'),
  };
}

/** A fence longer than any run of backticks in the text. */
function fenceFor(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((r) => r.length));
  return '`'.repeat(Math.max(3, longest + 1));
}

const ADVISORY = [
  '> **This issue is advisory.** Anyone with issue rights in a public repository, and any job with `issues: write`, can open an issue that looks exactly like this one, even as `github-actions[bot]`.',
  '> So `pipegen update` does not apply a patch from an issue: it re-derives the patch itself, from the reviewed list bundled with the pipegen version you run, and uses this issue only as a prompt.',
  '> If you apply anything by hand, compare the commit with the pin in the reviewed list of `pipegen@{VERSION}` (the list `pipegen update` uses), not with the tag: a tag is not authority.',
].join('\n');

function updateIssue(repo: RepoRef, rel: GateRelease, patch: { diff: string; baseSha: string } | undefined, notes: readonly string[]): { title: string; body: string; labels: string[] } {
  const v = safeMarkdown(`v${rel.version}`, 40);
  const cur = safeMarkdown(`v${GATE_VERSION}`, 40);
  const lines = [
    `## pipegen gate ${v} is available`, '',
    `${repoName(repo)} runs pipegen gate ${cur}. Version ${v} was released at \`${rel.publishedAt}\`, at least ${UPDATE_COOLDOWN_DAYS} days ago.`, '',
    `- release tag: \`${rel.tag}\``,
    `- the commit that tag resolves to (the new pin): \`${rel.sha}\``, '',
    'The commit comes from resolving the tag through the git refs API, never from the release text.', '',
    'To update, run:', '', `\`npx pipegen@${rel.version} update\``, '',
  ];
  if (patch !== undefined) {
    const fence = fenceFor(patch.diff);
    lines.push(
      'The patch below swaps only the pinned gate line or lines in `.github/workflows/pipegen.yml`; every other byte stays the same.', '',
      `${fence}diff`, patch.diff.replace(/\n$/, ''), fence,
      `<!-- pipegen:patch ${JSON.stringify({ repo: 'app', path: WORKFLOW_PATH, baseSha: patch.baseSha })} -->`, '',
    );
  } else {
    lines.push('There is no patch in this issue: pipegen could not read a pin line to swap here (a private repository keeps the pin in the central repository, which `pipegen update` changes with your token).', '');
  }
  for (const n of notes) lines.push(`Note: ${safeMarkdown(n, 300)}`, '');
  lines.push(ADVISORY.replace('{VERSION}', rel.version), '', 'This issue is opened by pipegen\'s nightly job. pipegen does not close it.');
  return { title: `pipegen: gate v${rel.version} is available`, body: lines.join('\n'), labels: patch === undefined ? [] : ['pipegen:patch'] };
}

const MAX_PATCH_CHARS = 30_000;

// ---------- older update issues ----------

const UPDATE_KEY_RE = /^update-((?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5}))$/;
const SUPERSEDED_RE = /^> Superseded by #/;
/**
 * Marks each older OPEN update issue of ours (bot, type Bot, key update-<older version>) as superseded: a line under the key marker,
 * "> Superseded by #N", replaced if it names an older issue. Never closes anything and never touches a closed issue, a person's issue,
 * another key or a newer version. Idempotent: an issue that already says it is not written again.
 */
async function supersedeOlder(gh: NightlyGithub, repo: RepoRef, version: string, newNumber: number): Promise<void> {
  const cur = semver(version) as [number, number, number];
  for (let page = 1; page <= ISSUE_PAGE_CAP; page++) {
    const list = await gh.listIssues(repo.owner, repo.name, page, ISSUE_PER_PAGE);
    if (!Array.isArray(list)) throw new Error('the issue list is not a list');
    for (const raw of list) {
      if (!isPlain(raw) || own(raw, 'pull_request') !== undefined || own(raw, 'state') !== 'open') continue;
      const number = own(raw, 'number');
      const user = own(raw, 'user');
      const body = own(raw, 'body');
      const title = own(raw, 'title');
      if (typeof number !== 'number' || !Number.isSafeInteger(number) || number <= 0 || number === newNumber || typeof body !== 'string' || typeof title !== 'string' || title === '') continue;
      if (!isPlain(user) || own(user, 'login') !== BOT_LOGIN || own(user, 'type') !== 'Bot') continue;
      const lines = body.replace(/\r\n/g, '\n').split('\n');
      const k = UPDATE_KEY_RE.exec((/^<!-- pipegen:key=([^ ]+) -->$/.exec(lines[0] as string) ?? [])[1] ?? '');
      const old = k === null ? undefined : semver(k[1] as string);
      if (old === undefined || !newer(cur, old)) continue;
      const rest = lines.slice(1);
      if (SUPERSEDED_RE.test(rest[0] ?? '')) rest.shift();
      const next = [lines[0] as string, `> Superseded by #${newNumber}: pipegen gate v${version} is out.`, ...rest].join('\n');
      if (next !== lines.join('\n')) await gh.updateIssue(repo.owner, repo.name, number, { title, body: next });
    }
    if (list.length < ISSUE_PER_PAGE) return;
  }
}

// ---------- the mode ----------

export interface NightlyCtx {
  repo: RepoRef; now: Date;
  /** The PIPEGEN_BLOCK_FROM variable (unset: undefined or ""). */
  blockFrom?: string | undefined;
  /** The date `finish` recorded at setup (the `block-from-recorded` input). */
  recorded?: string | undefined;
  /** PIPEGEN_FP_KEY, to verify the baseline (absent: the baseline can not be trusted). */
  key?: string | undefined;
  /** The warn-first checks and the day each became warn-first (the `warn-first` input, fix round A). */
  warnFirst?: readonly { needId: string; since: string }[] | undefined;
}
export interface NightlyDeps { loadBaseline?: (gh: NightlyAdapter, repo: RepoRef, ctx: VerifyContext) => Promise<LoadResult> }
export interface NightlyResult { issues: IssueOutcome[]; /** Why something was not done (reads that failed, a patch left out): logged, never an error. */ notes: string[]; /** Writes that failed or could not be made safe: the step fails. */ errors: string[] }

/**
 * Runs the four checks, each on its own: one failing never hides another. Read failures are notes (nothing is opened on a doubt); a failed
 * issue write, or an issue list that can not be searched to its end, is an error.
 */
export async function runNightly(gh: NightlyAdapter, ctx: NightlyCtx, deps: NightlyDeps = {}): Promise<NightlyResult> {
  const result: NightlyResult = { issues: [], notes: [], errors: [] };
  const { repo, now } = ctx;
  const upsert = async (key: string, issue: { title: string; body: string; labels?: string[] }): Promise<IssueOutcome | undefined> => {
    try {
      const out = await upsertIssueDetailed(gh, repo, key, issue.title, issue.body, { labels: issue.labels ?? [] });
      result.issues.push(out);
      return out;
    } catch (e) { result.errors.push(`the issue ${key} was not written: ${e instanceof Error ? e.message : 'unknown error'}`); return undefined; }
  };

  // 1. warn mode ends. A clean-run marker is NOT consulted: it can only move the gate toward block and never suppresses a warning.
  const effective = effectiveBlockFrom(ctx.blockFrom, ctx.recorded);
  if (effective !== undefined && warnEnding(effective, now, 'unknown')?.open === true) {
    let old: number | 'unknown' = 'unknown';
    let note: string | undefined;
    try {
      const loaded = await (deps.loadBaseline ?? loadBaseline)(gh, repo, { key: ctx.key, now });
      if (loaded.baseline !== null) {
        old = 0;
        for (const n of loaded.baseline.counts.values()) old += n;
      } else note = loaded.note;
    } catch { note = 'the baseline lookup failed'; }
    const w = warnEnding(effective, now, old);
    if (w?.open === true) await upsert(`warn-ending-${effective}`, warnEndingIssue(repo, effective, w, old, note));
  }

  // 2. the setup PR merged and `finish` has not run (the merge is read once, for 2 and 4)
  let mergedOnce: Promise<Awaited<ReturnType<typeof setupMergedAt>>> | undefined;
  const merge = (): Promise<Awaited<ReturnType<typeof setupMergedAt>>> => {
    mergedOnce ??= setupMergedAt(gh, repo, now).then((m) => { if (m.note !== undefined) result.notes.push(m.note); return m; });
    return mergedOnce;
  };
  if (validDate(ctx.blockFrom) === undefined) {
    const merged = await merge();
    if (merged.at !== undefined && merged.sha !== undefined && finishMissing(ctx.blockFrom, merged.at, now)) await upsert(`finish-missing-${merged.sha as string}`, finishMissingIssue(repo, merged.at));
  }

  // 4 (read here, written after the update): warn-first checks whose warn period has ended (#96, S12). One issue per check and end date.
  const switches: { needId: string; since: string; end: string }[] = [];
  const clock = clockOf(now);
  for (const w of ctx.warnFirst ?? []) {
    if (typeof w?.needId !== 'string' || !NEED_ID_RE.test(w.needId) || validDate(w.since) !== w.since) { result.notes.push('a warn-first entry is not in the form pipegen writes, so it was skipped'); continue; }
    const merged = await merge();
    const end = warnFirstEnd(w.since, merged.at);
    if (end === undefined) { result.notes.push(`warn-first ${w.needId}: the setup merge is not proven, so its warn period can not be counted and no switch issue is opened`); continue; }
    if (clock !== undefined && clock >= Date.parse(`${end}T00:00:00Z`)) switches.push({ needId: w.needId, since: w.since, end });
  }

  // 3. a pipegen update
  const latest = await latestGateRelease(gh, GATE_VERSION, now);
  if (latest.note !== undefined) result.notes.push(latest.note);
  if (latest.release !== undefined) {
    const rel = latest.release;
    const notes: string[] = [];
    let patch: { diff: string; baseSha: string } | undefined;
    try {
      const file = await readWorkflow(gh, repo);
      if ('why' in file) notes.push(`no patch: ${file.why}`);
      else {
        const pinned = new Set(pinnedShas(file.text, GATE_VERSION));
        if (pinned.size === 0) notes.push(`no patch: pipegen.yml has no gate pin line for v${GATE_VERSION}`);
        else if (pinned.size > 1) notes.push('no patch: pipegen.yml pins the gate at more than one commit for this version, so the swap is ambiguous');
        else {
          const diff = updatePatch([{ path: WORKFLOW_PATH, text: file.text }], { sha: [...pinned][0] as string, version: GATE_VERSION }, { sha: rel.sha, version: rel.version });
          if (diff === '') notes.push('no patch: nothing to swap');
          else if (diff.length > MAX_PATCH_CHARS) notes.push('no patch: the patch is too large for an issue');
          else patch = { diff, baseSha: file.baseSha };
        }
      }
    } catch (e) {
      notes.push(e instanceof PatchRefused ? `the patch was left out: ${e.message}` : 'no patch: the workflow file could not be read');
    }
    result.notes.push(...notes);
    const made = await upsert(`update-${rel.version}`, updateIssue(repo, rel, patch, notes));
    if (made !== undefined && made.action !== 'left-closed') {
      try { await supersedeOlder(gh, repo, rel.version, made.number); } catch (e) { result.notes.push(`older update issues were not marked as superseded: ${e instanceof Error ? e.message : 'unknown error'}`); }
    }
  }

  // 4. the "switch to blocking" issues
  for (const s of switches) await upsert(`warn-first-${s.needId}-${s.end}`, warnFirstIssue(repo, s.needId, s.since, s.end));
  return result;
}
