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

const MAX_LISTED = 15;
const list = (label: string, names: readonly string[]): string | null => {
  if (names.length === 0) return null;
  const shown = names.slice(0, MAX_LISTED).map((n) => safeText(n, 120)).join(', ');
  return `  ${label}: ${shown}${names.length > MAX_LISTED ? ` and ${names.length - MAX_LISTED} more` : ''}`;
};

/** What a record claims as pipegen's own, names only: the files and edits it lists, and the secrets, environments and rulesets it says pipegen created. */
export function recordClaims(r: InstallRecord): string[] {
  return [
    list('files', [...r.files.filter((f) => f.adopted !== true).map((f) => `${f.repo === 'central' ? 'central ' : ''}${f.path}`), ...r.edits.map((e) => `${e.repo === 'central' ? 'central ' : ''}${e.path} (edit)`)]),
    list('secrets', r.secrets.filter((s) => s.created).map((s) => `${s.name}${s.scope === 'repo' ? '' : ` (${s.scope})`}`)),
    list('environments', r.environments.filter((e) => e.created).map((e) => e.name)),
    list('rulesets', r.rulesets.map((x) => x.name)),
  ].filter((x): x is string => x !== null);
}

/** Step 2's question; true only for the exact app repo name (letter case and surrounding spaces ignored). No terminal is a no. */
async function askToTrust(confirm: RecordConfirm | undefined, app: RepoRef, central: RepoRef, branch: string, r: InstallRecord): Promise<boolean> {
  if (confirm === undefined || confirm.interactive !== true) return false;
  const name = `${app.owner}/${app.repo}`;
  const claims = recordClaims(r);
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
  if (file === null && onDefault !== null && onDefault !== 'unreadable' && await askToTrust(confirm, app, central, centralBranch, onDefault.record)) {
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
