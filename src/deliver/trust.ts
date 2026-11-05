// v0.2 Plan G G10 fix round 1 (controller ruling G10-R2; narrows G10-R-sec / G10-R-sec2): which earlier install record pipegen builds on.
// The record decides what pipegen calls its own (files it may replace, secrets it created, first originals uninstall restores), and both
// the central default branch (before `finish` adds its rule) and the central pull request branch can be written by anyone with write on
// the central repo. One trust order, for deliverCentral and deliver alike:
//   1. the record whose hash equals this machine's local record file's hash, from either branch, wins (the newest one pipegen vouched for);
//      a local file that matches neither is a hard "untrusted" (G10-R-sec3): no fall-through to step 2;
//   2. with no local file: the record on the central default branch, only when pipegen's central ruleset (which guards installs/** with a
//      pull request rule and no bypass) exists now AND the last commit that changed installs/<name>.json belongs to a merged pull request
//      (GET commits/{sha}/pulls) whose merged_at (GitHub's server time) is after the ruleset's created_at (G10-R-sec3: a record planted
//      before `finish` is not covered by a ruleset added later; git author and committer dates are client-set and never used);
//   3. otherwise none: pipegen claims nothing (prev = null for ownership) and says so in a plain note. Anything unreadable is untrusted.
// The setup PR body's marker is never a trust source (any app writer can edit it), and an unverified record is never vouched for: with
// prev = null the record pipegen writes next holds only what this run proves.
import type { Octokit } from '@octokit/rest';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { CENTRAL_RULESET } from '../layers/locks.js';
import type { InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { DeliverError, ghRead, ISO_RE, statusOf, type RepoRef } from './git-data.js';
import { readLocalRecord, readRecord, recordPath, RecordError, type LocalRecordDeps, type ReadRecordResult } from './record.js';

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * pipegen's central ruleset on the central default branch now: an active `pull_request` rule on the branch whose ruleset is named
 * CENTRAL_RULESET, enforced, with no bypass actor; returns its GitHub created_at. Anything unreadable is null (a rate stop stops).
 */
export async function centralRulesetCreatedAt(gh: Octokit, central: RepoRef, branch: string, clock: RateClock): Promise<string | null> {
  try {
    const rules = await ghRead(gh, 'GET /repos/{owner}/{repo}/rules/branches/{branch}', central, { branch }, clock);
    if (!Array.isArray(rules)) return null;
    const ids = [...new Set(rules.filter(isObj).filter((r) => r.type === 'pull_request' && Number.isSafeInteger(r.ruleset_id)).map((r) => r.ruleset_id as number))];
    for (const id of ids) {
      const rs = await ghRead(gh, 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', central, { ruleset_id: id }, clock);
      if (isObj(rs) && rs.name === CENTRAL_RULESET && rs.enforcement === 'active' && Array.isArray(rs.bypass_actors) && rs.bypass_actors.length === 0 && typeof rs.created_at === 'string' && ISO_RE.test(rs.created_at)) return rs.created_at;
    }
    return null;
  } catch (e) {
    if (isRateStop(e) || e instanceof DeliverError || statusOf(e) === undefined) throw e;
    return null;
  }
}

/**
 * Whether the last commit that changed `path` on `branch` belongs to a pull request into `branch` that GitHub merged after `after`
 * (server times only). Anything unreadable is false.
 */
export async function mergedThroughPrAfter(gh: Octokit, central: RepoRef, branch: string, path: string, after: string, clock: RateClock): Promise<boolean> {
  try {
    const list = await ghRead(gh, 'GET /repos/{owner}/{repo}/commits', central, { sha: branch, path, per_page: 1 }, clock);
    const sha = Array.isArray(list) && isObj(list[0]) ? list[0].sha : undefined;
    if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) return false;
    const pulls = await ghRead(gh, 'GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls', central, { commit_sha: sha }, clock);
    if (!Array.isArray(pulls)) return false;
    const limit = Date.parse(after);
    return pulls.filter(isObj).some((pr) => typeof pr.merged_at === 'string' && ISO_RE.test(pr.merged_at) && Date.parse(pr.merged_at) > limit && isObj(pr.base) && pr.base.ref === branch);
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
    const since = await centralRulesetCreatedAt(gh, central, centralBranch, clock);
    if (since !== null && await mergedThroughPrAfter(gh, central, centralBranch, recordPath(app.repo), since, clock)) return { record: onDefault.record, exists };
  }
  // 3. nothing: say which record, and why
  const where = [onDefault === null ? null : `the default branch ${safeText(centralBranch, 100)}`, onBranch === null || updateBranch === null ? null : `the central pull request branch ${safeText(updateBranch, 100)}`].filter((x) => x !== null).join(' and ');
  const why = file === null
    ? "can't be checked from this machine (no local record file holds its hash), and pipegen can't show it was merged through a pull request under its central merge rule (which `finish` adds)"
    : "doesn't match the hash in this machine's local record file";
  notes.push(`The install record on ${where} of ${safeText(`${central.owner}/${central.repo}`, 120)} ${why}, so pipegen claims nothing from it: it writes a new record, and treats every existing file and secret as not its own.`);
  return { record: null, exists };
}
