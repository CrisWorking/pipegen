// v0.2 Plan G G10 fix round 1 (controller ruling G10-R2; narrows G10-R-sec / G10-R-sec2): which earlier install record pipegen builds on.
// The record decides what pipegen calls its own (files it may replace, secrets it created, first originals uninstall restores), and both
// the central default branch (before `finish` adds its rule) and the central pull request branch can be written by anyone with write on
// the central repo. One trust order, for deliverCentral and deliver alike:
//   1. the record whose hash equals this machine's local record file's hash, from either branch, wins (the newest one pipegen vouched for);
//      a local file that matches neither is a hard "untrusted" (G10-R-sec3): no fall-through to step 2;
//   2. with no local file: the record on the central default branch, only when pipegen's central ruleset exists now, live-read to require an
//      approving review and code-owner review with no bypass, the central CODEOWNERS owns installs/<name>.json (G10-R3 N1), AND the last commit that changed installs/<name>.json belongs to a merged pull request
//      (GET commits/{sha}/pulls), approved by someone other than its author, whose merged_at (GitHub's server time) is after the ruleset's created_at (G10-R-sec3: a record planted
//      before `finish` is not covered by a ruleset added later; git author and committer dates are client-set and never used);
//   3. otherwise none: pipegen claims nothing (prev = null for ownership) and says so in a plain note. Anything unreadable is untrusted.
// The setup PR body's marker is never a trust source (any app writer can edit it), and an unverified record is never vouched for: with
// prev = null the record pipegen writes next holds only what this run proves.
import type { Octokit } from '@octokit/rest';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { CENTRAL_RULESET } from '../layers/locks.js';
import type { InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { codeOwners, MAX_CODEOWNERS_BYTES, ownersOf } from '../../gate/src/integrity.js';
import { DeliverError, ghRead, ISO_RE, readBlobText, readHead, readTree, statusOf, type RepoRef } from './git-data.js';
import { readLocalRecord, readRecord, recordPath, RecordError, type LocalRecordDeps, type ReadRecordResult } from './record.js';

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

const CODEOWNERS_PLACES = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'] as const;

/**
 * pipegen's central lock on the central default branch, read live now (G10-R-sec3, G10-R3 N1): an active `pull_request` rule on the branch
 * that requires at least one approving review AND code-owner review, from a ruleset named CENTRAL_RULESET, enforced, with no bypass actor;
 * and the central CODEOWNERS GitHub reads (the first of .github/, the root, docs/) gives `recordPath` at least one owner. Returns the
 * ruleset's GitHub created_at, or null when any part is missing or unreadable (a rate stop stops).
 */
export async function centralLockSince(gh: Octokit, central: RepoRef, branch: string, recordFile: string, clock: RateClock): Promise<string | null> {
  try {
    const rules = await ghRead(gh, 'GET /repos/{owner}/{repo}/rules/branches/{branch}', central, { branch }, clock);
    if (!Array.isArray(rules)) return null;
    const reviewed = (r: Record<string, unknown>): boolean => isObj(r.parameters) && typeof r.parameters.required_approving_review_count === 'number' && r.parameters.required_approving_review_count >= 1 && r.parameters.require_code_owner_review === true;
    const ids = [...new Set(rules.filter(isObj).filter((r) => r.type === 'pull_request' && Number.isSafeInteger(r.ruleset_id) && reviewed(r)).map((r) => r.ruleset_id as number))];
    let since: string | null = null;
    for (const id of ids) {
      const rs = await ghRead(gh, 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', central, { ruleset_id: id }, clock);
      if (isObj(rs) && rs.name === CENTRAL_RULESET && rs.enforcement === 'active' && Array.isArray(rs.bypass_actors) && rs.bypass_actors.length === 0 && typeof rs.created_at === 'string' && ISO_RE.test(rs.created_at)) { since = rs.created_at; break; }
    }
    if (since === null) return null;
    // the code-owner review covers the record only when CODEOWNERS gives it an owner (the last matching line wins, as GitHub reads it)
    const head = await readHead(gh, central, branch, clock);
    if (head === null) return null;
    const { entries } = await readTree(gh, central, head, clock);
    const place = CODEOWNERS_PLACES.find((x) => entries.has(x));
    const e = place === undefined ? undefined : entries.get(place);
    if (e === undefined || e.type !== 'blob' || e.mode !== '100644') return null;
    const owners = ownersOf(codeOwners(await readBlobText(gh, central, e.sha, MAX_CODEOWNERS_BYTES, clock)), recordFile);
    return owners !== undefined && owners.length > 0 ? since : null;
  } catch (e) {
    if (isRateStop(e) || e instanceof DeliverError || statusOf(e) === undefined) throw e;
    return null;
  }
}

/**
 * Whether the last commit that changed `path` on `branch` belongs to a pull request into `branch` that GitHub merged after `after` (server
 * times only) and that someone other than its author approved (G10-R3 N1: GET pulls/{n}/reviews, state APPROVED). Anything unreadable is false.
 */
export async function mergedThroughPrAfter(gh: Octokit, central: RepoRef, branch: string, path: string, after: string, clock: RateClock): Promise<boolean> {
  try {
    const list = await ghRead(gh, 'GET /repos/{owner}/{repo}/commits', central, { sha: branch, path, per_page: 1 }, clock);
    const sha = Array.isArray(list) && isObj(list[0]) ? list[0].sha : undefined;
    if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) return false;
    const pulls = await ghRead(gh, 'GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls', central, { commit_sha: sha }, clock);
    if (!Array.isArray(pulls)) return false;
    const limit = Date.parse(after);
    for (const pr of pulls.filter(isObj)) {
      if (!(typeof pr.merged_at === 'string' && ISO_RE.test(pr.merged_at) && Date.parse(pr.merged_at) > limit && isObj(pr.base) && pr.base.ref === branch)) continue;
      const author = isObj(pr.user) && typeof pr.user.login === 'string' ? pr.user.login.toLowerCase() : null;
      if (author === null || !Number.isSafeInteger(pr.number)) continue;
      const reviews = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews', central, { pull_number: pr.number, per_page: 100 }, clock);
      if (Array.isArray(reviews) && reviews.filter(isObj).some((r) => r.state === 'APPROVED' && isObj(r.user) && typeof r.user.login === 'string' && r.user.login.toLowerCase() !== author)) return true;
    }
    return false;
  } catch (e) {
    if (isRateStop(e) || e instanceof DeliverError || statusOf(e) === undefined) throw e;
    return false;
  }
}

export interface TrustedRecord {
  /** The record pipegen builds on, or null (it claims nothing). */
  record: InstallRecord | null;
  /** Whether any record (trusted or not, readable or not) exists on either branch: a later run then writes through a pull request. */
  exists: boolean;
  /** Why a record that exists isn't trusted: no local record file, or one that matches neither record (N5: then removing it is the way on). */
  why?: 'no-local' | 'mismatch';
}

/** A record read for the trust decision: an unreadable one counts as present and untrusted; a rate stop or another failure stops. */
async function readFor(gh: Octokit, central: RepoRef, appRepo: string, branch: string, clock: RateClock): Promise<ReadRecordResult | 'unreadable' | null> {
  try { return await readRecord(gh, central, appRepo, { branch, clock }); } catch (e) {
    if (e instanceof RecordError) return 'unreadable';
    throw e;
  }
}

/** The earlier record, in the trust order of the header. `notes` gets a plain line when a record exists that pipegen doesn't trust. */
export async function trustedPrevious(gh: Octokit, app: RepoRef, central: RepoRef, centralBranch: string, updateBranch: string | null, local: LocalRecordDeps, clock: RateClock, notes: string[]): Promise<TrustedRecord> {
  const onDefault = await readFor(gh, central, app.repo, centralBranch, clock);
  const onBranch = updateBranch === null ? null : await readFor(gh, central, app.repo, updateBranch, clock);
  const exists = onDefault !== null || onBranch !== null;
  if (!exists) return { record: null, exists };
  const file = await readLocalRecord(app, local).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  // 1. vouched by this machine's local record file: the newest such record, the central PR branch first (it was built on the default one)
  for (const r of [onBranch, onDefault]) if (file !== null && r !== null && r !== 'unreadable' && r.hash === file.recordHash) return { record: r.record, exists };
  // 2. no local file: the default branch's record, merged through a pull request after pipegen's central ruleset existed
  if (file === null && onDefault !== null && onDefault !== 'unreadable') {
    const since = await centralLockSince(gh, central, centralBranch, recordPath(app.repo), clock);
    if (since !== null && await mergedThroughPrAfter(gh, central, centralBranch, recordPath(app.repo), since, clock)) return { record: onDefault.record, exists };
  }
  // 3. nothing: say which record, and why
  const where = [onDefault === null ? null : `the default branch ${safeText(centralBranch, 100)}`, onBranch === null || updateBranch === null ? null : `the central pull request branch ${safeText(updateBranch, 100)}`].filter((x) => x !== null).join(' and ');
  const why = file === null
    ? "can't be checked from this machine (no local record file holds its hash), and pipegen can't show it was merged through a reviewed pull request under its central merge rule (which `finish` adds)"
    : "doesn't match the hash in this machine's local record file";
  notes.push(`The install record on ${where} of ${safeText(`${central.owner}/${central.repo}`, 120)} ${why}, so pipegen claims nothing from it: it writes a new record, and treats every existing file and secret as not its own.`);
  return { record: null, exists, why: file === null ? 'no-local' : 'mismatch' };
}
