// v0.2 Plan G G10 (controller rulings G10-R2, G10-R-sec2/sec3/sec5/sec6): which earlier install record pipegen builds on.
// The record decides what pipegen calls its own (files it may replace, secrets it created, first originals uninstall restores), and both
// the central default branch and the central pull request branch can be written by anyone with write on the central repo. One trust order,
// for deliverCentral and deliver alike:
//   1. the record whose hash equals this machine's local record file's hash, from either branch, wins (the newest one pipegen vouched for);
//      a local file that matches neither is a hard "untrusted": no question, no fall-through;
//   2. with no local file, no automatic trust (G10-R-sec6: every proof built from GitHub state, a ruleset, a merged and reviewed pull
//      request, CODEOWNERS at the head, opened another door, so that fallback is gone). Instead, an interactive run that finds a record on
//      the central default branch shows what it claims as pipegen's (names only) and asks the user to type the app repo (`owner/repo`):
//      typed correctly, the record is trusted and vouched into the local record file; anything else, a non-interactive run (--yes, CI), no
//      terminal, or an unreadable record is untrusted;
//   3. untrusted: pipegen claims nothing (prev = null for ownership) and says so in a plain note.
// The setup PR body's marker is never a trust source (any app writer can edit it), and an unverified record is never vouched for: with
// prev = null the record pipegen writes next holds only what this run proves.
import type { Octokit } from '@octokit/rest';
import { PromptCancelledError, type Prompter } from '../cli/io.js';
import type { RateClock } from '../engine/github-rate.js';
import type { InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { RepoRef } from './git-data.js';
import { readLocalRecord, readRecord, RecordError, writeLocalRecord, type LocalRecordDeps, type ReadRecordResult } from './record.js';

export interface TrustedRecord {
  /** The record pipegen builds on, or null (it claims nothing). */
  record: InstallRecord | null;
  /** Whether any record (trusted or not, readable or not) exists on either branch: a later run then writes through a pull request. */
  exists: boolean;
  /** Why a record that exists isn't trusted: no local record file, or one that matches neither record (N5: then removing it is the way on). */
  why?: 'no-local' | 'mismatch';
}

/** The question step 2 asks (G10-R-sec6): only when `interactive`; never in a --yes or CI run. */
export interface RecordConfirm { io: Prompter; interactive: boolean }

/** A record read for the trust decision: an unreadable one counts as present and untrusted; a rate stop or another failure stops. */
async function readFor(gh: Octokit, central: RepoRef, appRepo: string, branch: string, clock: RateClock): Promise<ReadRecordResult | 'unreadable' | null> {
  try { return await readRecord(gh, central, appRepo, { branch, clock }); } catch (e) {
    if (e instanceof RecordError) return 'unreadable';
    throw e;
  }
}

/** The most entries the typed question lists (G10-R-sec7): a record that claims more is never trusted by typing (never a partial list). */
export const MAX_CONFIRM_ENTRIES = 200;

/**
 * Every entry of a record that pipegen's ownership checks act on (G10-R-sec7: the same entries, nothing filtered, nothing cut), one name per
 * line group, each through safeText: the files (adopted ones tagged), the edits, the secrets and variables (created or not), the environments
 * and the rulesets. Returns null when there are more than MAX_CONFIRM_ENTRIES.
 */
export function recordClaims(r: InstallRecord): string[] | null {
  const repo = (x: { repo: string }): string => (x.repo === 'central' ? 'central ' : '');
  const groups: [string, string[]][] = [
    ['files', r.files.map((f) => `${repo(f)}${f.path}${f.adopted === true ? ' (adopted)' : ''}`)],
    ['edits', r.edits.map((e) => `${repo(e)}${e.path} (${e.kind})`)],
    ['secrets', r.secrets.map((x) => `${x.name} (${x.scope}${x.created ? ', created' : ', not created'})`)],
    ['variables', r.variables.map((x) => `${x.name} (${x.scope}${x.created ? ', created' : ', not created'})`)],
    ['environments', r.environments.map((x) => `${x.name}${x.created ? ' (created)' : ' (not created)'}`)],
    ['rulesets', r.rulesets.map((x) => `${x.name} (${x.kind})`)],
  ];
  if (groups.reduce((n, [, xs]) => n + xs.length, 0) > MAX_CONFIRM_ENTRIES) return null;
  return groups.filter(([, xs]) => xs.length > 0).map(([label, xs]) => `  ${label}: ${xs.map((x) => safeText(x, 300)).join(', ')}`);
}

/** Step 2's question; true only for the exact app repo name (letter case and surrounding spaces ignored). No terminal is a no. */
async function askToTrust(confirm: RecordConfirm | undefined, app: RepoRef, central: RepoRef, branch: string, r: InstallRecord, notes: string[]): Promise<boolean> {
  if (confirm === undefined || confirm.interactive !== true) return false;
  const name = `${app.owner}/${app.repo}`;
  const claims = recordClaims(r);
  if (claims === null) {
    notes.push(`The install record for ${safeText(name, 140)} lists more than ${MAX_CONFIRM_ENTRIES} entries, too many to confirm by typing, so pipegen doesn't ask about it.`);
    return false;
  }
  const msg = [
    `pipegen found an install record for ${safeText(name, 140)} on the default branch ${safeText(branch, 100)} of ${safeText(`${central.owner}/${central.repo}`, 120)}, and this machine can't check it (it has no local record file for it). If you trust it, pipegen treats these as its own: it may replace them, and uninstalling pipegen may delete them.`,
    ...(claims.length === 0 ? ['  (it claims nothing as created)'] : claims),
    `Type ${safeText(name, 140)} to trust it; anything else, and pipegen claims nothing from it.`,
  ].join('\n');
  let typed: string;
  try { typed = await confirm.io.text(msg); } catch (e) {
    if (e instanceof PromptCancelledError) return false;
    throw e;
  }
  return typeof typed === 'string' && typed.trim().toLowerCase() === name.toLowerCase();
}

/** The earlier record, in the trust order of the header. `notes` gets a plain line when a record exists that pipegen doesn't trust. */
export async function trustedPrevious(gh: Octokit, app: RepoRef, central: RepoRef, centralBranch: string, updateBranch: string | null, local: LocalRecordDeps, clock: RateClock, notes: string[], confirm?: RecordConfirm): Promise<TrustedRecord> {
  const onDefault = await readFor(gh, central, app.repo, centralBranch, clock);
  const onBranch = updateBranch === null ? null : await readFor(gh, central, app.repo, updateBranch, clock);
  const exists = onDefault !== null || onBranch !== null;
  if (!exists) return { record: null, exists };
  const file = await readLocalRecord(app, local).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  // 1. vouched by this machine's local record file: the newest such record, the central PR branch first (it was built on the default one)
  for (const r of [onBranch, onDefault]) if (file !== null && r !== null && r !== 'unreadable' && r.hash === file.recordHash) return { record: r.record, exists };
  // 2. no local file: the user confirms the default branch's record by typing the repo name; it is then vouched into the local file
  if (file === null && onDefault !== null && onDefault !== 'unreadable' && await askToTrust(confirm, app, central, centralBranch, onDefault.record, notes)) {
    await writeLocalRecord(app, { recordHash: onDefault.hash, updatedAt: new Date().toISOString() }, local);
    return { record: onDefault.record, exists };
  }
  // 3. nothing: say which record, and why
  const where = [onDefault === null ? null : `the default branch ${safeText(centralBranch, 100)}`, onBranch === null || updateBranch === null ? null : `the central pull request branch ${safeText(updateBranch, 100)}`].filter((x) => x !== null).join(' and ');
  const why = file === null
    ? `can't be checked from this machine (no local record file holds its hash)${confirm?.interactive === true ? ' and you didn\'t confirm it' : '; run pipegen interactively to confirm it by typing the repo name'}`
    : "doesn't match the hash in this machine's local record file";
  notes.push(`The install record on ${where} of ${safeText(`${central.owner}/${central.repo}`, 120)} ${why}, so pipegen claims nothing from it: it writes a new record, and treats every existing file and secret as not its own.`);
  return { record: null, exists, why: file === null ? 'no-local' : 'mismatch' };
}
