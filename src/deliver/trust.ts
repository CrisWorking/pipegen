// v0.2 Plan G G10 (controller rulings G10-R2, G10-R-sec2/sec3/sec5/sec6): which earlier install record pipegen builds on.
// The record decides what pipegen calls its own (files it may replace, secrets it created, first originals uninstall restores), and both
// the central default branch and the central pull request branch can be written by anyone with write on the central repo. One trust order,
// for deliverCentral and deliver alike:
//   1. the record whose hash equals this machine's local record file's hash, from either branch, wins (the newest one pipegen vouched for);
//      a local file that matches neither is a hard "untrusted": no question, no fall-through;
//   2. with no local file, no automatic trust (G10-R-sec6: every proof built from GitHub state, a ruleset, a merged and reviewed pull
//      request, CODEOWNERS at the head, opened another door, so that fallback is gone). Instead, an interactive run that finds a record on
//      the central default branch shows what it claims as pipegen's (names only) and asks the user to type the app repo (`owner/repo`):
//      typed correctly, the record is trusted (only the entries the question listed, G10-R-sec8: confirmView) and vouched into the local
//      record file with `typed: true`, so a later run grants the same view and no more; anything else, a non-interactive run (--yes, CI), no
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
import { localRecordPath, readLocalRecord, readRecord, RecordError, writeLocalRecord, type LocalRecordDeps, type ReadRecordResult } from './record.js';

export interface TrustedRecord {
  /** The record pipegen builds on, or null (it claims nothing). */
  record: InstallRecord | null;
  /** Whether any record (trusted or not, readable or not) exists on either branch: a later run then writes through a pull request. */
  exists: boolean;
  /** Why a record that exists isn't trusted: no local record file, or one that matches neither record (N5: then removing it is the way on). */
  why?: 'no-local' | 'mismatch';
  /**
   * G11-R3 (R2-6): for a record trusted by typing, the blockFrom of the full record behind the view (the view drops it: typing never
   * vouched it). finish may only take it as an earlier date, never a later one.
   */
  unvouchedBlockFrom?: string;
  /** G12-R2 N5: the record is confirmView's view (trusted by typing, now or earlier): a caller that writes a record must not build on it. */
  typed?: true;
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

/** The longest entry the typed question shows; a longer one refuses the typed path (G10-R-sec8: never a cut entry). */
export const MAX_CONFIRM_TEXT = 200;

/**
 * The typed-trusted view's allow-list (G10-R5): for the record and each entry kind, the fields kept (shown in the question, or proven
 * harmless by the review: shas, githubCreatedAt, unconfirmed, part, aiEdited, overwritten, createdAt, centralSha), the fields written fresh
 * (present, but never taken from the record), and the fields dropped. A test holds this list to InstallRecordSchema's keys, so a field the
 * schema gains later is absent from the view until someone classifies it on purpose.
 */
export const TYPED_VIEW_FIELDS = {
  record: {
    keep: ['schema', 'pipegenVersion', 'createdAt', 'centralSha', 'app', 'name', 'files', 'secrets', 'variables', 'environments', 'rulesets'],
    fresh: ['edits', 'planned', 'serviceRoots', 'protectedPaths'],
    drop: ['mergedAt', 'blockFrom', 'cosignPubSha256', 'cosignPub', 'central', 'scratch', 'orgRuleset', 'classicProtection', 'repoSettings'],
  },
  // ownerEdited (G12) is kept: it only makes a file the owner's (dropping it would make a merged file look like pipegen's own)
  files: { keep: ['repo', 'path', 'part', 'shas', 'aiEdited', 'adopted', 'ownerEdited'] },
  secrets: { keep: ['name', 'scope', 'created', 'overwritten', 'githubCreatedAt', 'unconfirmed'] },
  variables: { keep: ['name', 'scope', 'created', 'githubCreatedAt', 'unconfirmed'], drop: ['previous'] },
  environments: { keep: ['name', 'created', 'githubCreatedAt', 'unconfirmed'], fresh: ['changed', 'branchPolicyIds'], drop: ['previous'] },
  rulesets: { keep: ['kind', 'id', 'name', 'githubCreatedAt', 'unconfirmed'] },
  // G17 row 30: the app's plain facts, key by key (a key the schema gains is absent from the view until classified)
  app: { keep: ['owner', 'repo', 'repoId', 'defaultBranch', 'private', 'ownerType'] },
  // the record drops orgRuleset whole (record.drop); its fields are listed so a field it gains is classified on purpose (G11-R-sec1 pinnedSha)
  orgRuleset: { keep: [], drop: ['org', 'id', 'name', 'githubCreatedAt', 'unconfirmed', 'pinnedSha'] },
} as const satisfies Record<string, { keep: readonly string[]; fresh?: readonly string[]; drop?: readonly string[] }>;

/** A copy of exactly the listed own fields that are present (deep-copied). */
function pick<T extends object>(o: T, keys: readonly string[]): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const k of keys) if (Object.hasOwn(o, k) && (o as Record<string, unknown>)[k] !== undefined) out[k] = structuredClone((o as Record<string, unknown>)[k]);
  return out as Partial<T>;
}

/**
 * The typed question's entries and the view of the record that typing grants, made by ONE function so they can't drift (G10-R-sec7, sec8).
 * The lines list every entry the view keeps, nothing filtered or cut: all files (adopted ones tagged), the secrets and variables (created or
 * not), the environments (created or not) and the rulesets (with their ids). The view holds exactly those names and the record's plain facts
 * (TYPED_VIEW_FIELDS, an allow-list, G10-R5). G10-R4: no edits, no variable `previous` values and no `planned` requests (payloads the
 * question never showed; pipegen re-derives its edits and re-plans this run); no mergedAt, blockFrom or cosignPubSha256. Every other ownership-bearing field (central
 * and scratch repo ids and createdByPipegen, the central ruleset/CODEOWNERS/actions access, the org ruleset, classic protection, repo
 * settings, an environment's previous settings, changes and branch policy ids) is dropped: typing proves nothing about them.
 * Refused (never a partial or altered list): more than MAX_CONFIRM_ENTRIES entries, or an entry safeText would change or that is longer than
 * MAX_CONFIRM_TEXT.
 */
export function confirmView(r: InstallRecord): { lines: string[]; view: InstallRecord } | { refused: string } {
  const repo = (x: { repo: string }): string => (x.repo === 'central' ? 'central ' : '');
  const groups: [string, string[]][] = [
    ['files', r.files.map((f) => `${repo(f)}${f.path}${f.adopted === true ? ' (adopted)' : ''}`)],
    ['secrets', r.secrets.map((x) => `${x.name} (${x.scope}${x.created ? ', created' : ', not created'})`)],
    ['variables', r.variables.map((x) => `${x.name} (${x.scope}${x.created ? ', created' : ', not created'})`)],
    ['environments', r.environments.map((x) => `${x.name}${x.created ? ' (created)' : ' (not created)'}`)],
    ['rulesets', r.rulesets.map((x) => `${x.name} (${x.kind}, id ${x.id})`)],
  ];
  const all = groups.flatMap(([, xs]) => xs);
  if (all.length > MAX_CONFIRM_ENTRIES) return { refused: `it lists more than ${MAX_CONFIRM_ENTRIES} entries, too many to confirm by typing` };
  if (all.some((x) => x.length > MAX_CONFIRM_TEXT || safeText(x, MAX_CONFIRM_TEXT) !== x)) return { refused: 'one of its entries can\'t be shown exactly (too long, or holding characters a terminal would hide or change)' };
  const lines = groups.filter(([, xs]) => xs.length > 0).map(([label, xs]) => `  ${label}: ${xs.join(', ')}`);
  const f = TYPED_VIEW_FIELDS;
  // G10-R5: the view is built field by field from the allow-list; a field not listed there (a new schema key included) is absent
  const view = {
    ...pick(r, f.record.keep),
    // written fresh: this run re-derives its edits, re-plans, and writes the roots and protected paths from the draft
    edits: [], planned: { signingMode: 'none', environments: [], owners: { app: [], central: [] }, codeOwners: [] }, serviceRoots: [], protectedPaths: [],
    app: pick(r.app, f.app.keep),
    files: r.files.map((x) => pick(x, f.files.keep)),
    secrets: r.secrets.map((x) => pick(x, f.secrets.keep)),
    variables: r.variables.map((x) => pick(x, f.variables.keep)),
    environments: r.environments.map((x) => ({ ...pick(x, f.environments.keep), changed: [], branchPolicyIds: [] })),
    rulesets: r.rulesets.map((x) => pick(x, f.rulesets.keep)),
  } as InstallRecord;
  return { lines, view };
}

/** Step 2's question; true only for the exact app repo name (letter case and surrounding spaces ignored). No terminal is a no. */
async function askToTrust(confirm: RecordConfirm | undefined, app: RepoRef, central: RepoRef, branch: string, r: InstallRecord, notes: string[]): Promise<InstallRecord | null> {
  if (confirm === undefined || confirm.interactive !== true) return null;
  const name = `${app.owner}/${app.repo}`;
  const cv = confirmView(r);
  if ('refused' in cv) {
    notes.push(`The install record for ${safeText(name, 140)} can't be confirmed by typing: ${cv.refused}. pipegen doesn't ask about it.`);
    return null;
  }
  const claims = cv.lines;
  const msg = [
    `pipegen found an install record for ${safeText(name, 140)} on the default branch ${safeText(branch, 100)} of ${safeText(`${central.owner}/${central.repo}`, 120)}, and this machine can't check it (it has no local record file for it). If you trust it, pipegen treats these as its own: it may replace them, and uninstalling pipegen may delete them.`,
    ...(claims.length === 0 ? ['  (it claims nothing as created)'] : claims),
    `Type ${safeText(name, 140)} to trust exactly these entries; anything else, and pipegen claims nothing from it.`,
  ].join('\n');
  let typed: string;
  try { typed = await confirm.io.text(msg); } catch (e) {
    if (e instanceof PromptCancelledError) return null;
    throw e;
  }
  return typeof typed === 'string' && typed.trim().toLowerCase() === name.toLowerCase() ? cv.view : null;
}

const unvouched = (r: InstallRecord): { unvouchedBlockFrom?: string } => (r.blockFrom === undefined ? {} : { unvouchedBlockFrom: r.blockFrom });

/** The earlier record, in the trust order of the header. `notes` gets a plain line when a record exists that pipegen doesn't trust. */
export async function trustedPrevious(gh: Octokit, app: RepoRef, central: RepoRef, centralBranch: string, updateBranch: string | null, local: LocalRecordDeps, clock: RateClock, notes: string[], confirm?: RecordConfirm): Promise<TrustedRecord> {
  const onDefault = await readFor(gh, central, app.repo, centralBranch, clock);
  const onBranch = updateBranch === null ? null : await readFor(gh, central, app.repo, updateBranch, clock);
  const exists = onDefault !== null || onBranch !== null;
  if (!exists) return { record: null, exists };
  // G17 row 31 (open question 10, as G10-R-sec3): a local record file that can't be read (a link, a folder, not pipegen's form, a records
  // folder pipegen won't use) is a hard "untrusted", like a hash that matches neither record: no question, nothing vouched over it
  const file = await readLocalRecord(app, local).catch((e: unknown) => { if (e instanceof RecordError) return 'unreadable' as const; throw e; });
  if (file === 'unreadable') {
    let where = 'this machine\'s local record file';
    try { where = `this machine's local record file ${localRecordPath(app, local)}`; } catch { /* no path for this name */ }
    notes.push(`The install record of ${safeText(`${central.owner}/${central.repo}`, 120)} can't be checked: ${where} can't be read (it is a link, a folder, or not in the form pipegen writes), so pipegen claims nothing from any install record and treats every existing file and secret as not its own. Remove that file, then run \`npx pipegen run\` again (pipegen then asks you to confirm the record).`);
    return { record: null, exists, why: 'mismatch' };
  }
  // 1. vouched by this machine's local record file: the newest such record, the central PR branch first (it was built on the default one)
  for (const r of [onBranch, onDefault]) {
    if (file === null || r === null || r === 'unreadable' || r.hash !== file.recordHash) continue;
    // a hash the user vouched for by typing grants only the view they were shown (G10-R-sec8)
    if (file.typed !== true) return { record: r.record, exists };
    const cv = confirmView(r.record);
    if ('view' in cv) return { record: cv.view, exists, typed: true, ...unvouched(r.record) };
  }
  // 2. no local file: the user confirms the default branch's record by typing the repo name; it is then vouched into the local file
  const typed = file === null && onDefault !== null && onDefault !== 'unreadable' ? await askToTrust(confirm, app, central, centralBranch, onDefault.record, notes) : null;
  if (typed !== null && onDefault !== null && onDefault !== 'unreadable') {
    await writeLocalRecord(app, { recordHash: onDefault.hash, typed: true, updatedAt: new Date().toISOString() }, local);
    return { record: typed, exists, typed: true, ...unvouched(onDefault.record) };
  }
  // 3. nothing: say which record, and why
  const where = [onDefault === null ? null : `the default branch ${safeText(centralBranch, 100)}`, onBranch === null || updateBranch === null ? null : `the central pull request branch ${safeText(updateBranch, 100)}`].filter((x) => x !== null).join(' and ');
  const why = file === null
    ? `can't be checked from this machine (no local record file holds its hash)${confirm?.interactive === true ? ' and you didn\'t confirm it' : '; run pipegen interactively to confirm it by typing the repo name'}`
    : "doesn't match the hash in this machine's local record file";
  notes.push(`The install record on ${where} of ${safeText(`${central.owner}/${central.repo}`, 120)} ${why}, so pipegen claims nothing from it: it writes a new record, and treats every existing file and secret as not its own.`);
  return { record: null, exists, why: file === null ? 'no-local' : 'mismatch' };
}
