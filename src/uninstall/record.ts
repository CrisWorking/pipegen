// v0.2 Plan V V1 (rulings V-B1, V-B6, V-S1, V-S2, V-S13, V-N2, V-N4, V-N13, V-N14): the install record uninstall works from, and only that.
// Uninstall may delete only what the record proves pipegen created, so the record is read through the one trust order every pipegen
// command uses (trustedPrevious, src/deliver/trust.ts), never through a second parser:
//   - full trust: this machine's local record file holds the record's hash;
//   - typed trust: the user typed the app repo's name after seeing the record's names (now, or on an earlier run): only confirmView's view
//     is granted, and every field it drops (edits, previous settings, classic protection, the org rule, central and scratch facts) becomes
//     a manual step for the plan (TYPED_DROPPED);
//   - anything else (no record, a record that doesn't match the local file, an unreadable one, no terminal to ask at): stop.
// The app's facts (id, visibility, default branch, owner type) are GitHub's, never the record's; a record of another repo id stops. An open
// central pull request on pipegen/update-<name> can still change the record: stop until it is merged or closed. The setup pull request's
// record marker is never trust (any app writer can edit it): it is compared for a warning only. Fix round 1 (V1-R1): `typedNames` is true
// for a typed trust or a marker that isn't a match, and then the plan asks for a typed name before every API delete and restore (a typed
// trust has no hash anchor, and the created_at values it keeps were never shown). A created entry that doesn't hold exactly one of
// githubCreatedAt / unconfirmed counts as unconfirmed. Typed names come only from the user's terminal (askTypedName).
import type { Octokit } from '@octokit/rest';
import { PromptCancelledError, type Prompter } from '../cli/io.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { clockOf, GitHubAccessError } from '../github/client.js';
import { SETUP_BRANCH } from '../deliver/deliver.js';
import { gitBlobSha } from '../create/guard.js';
import { DeliverError, ghRead, readBlobText, readHead, readRepo, statusOf, type RepoRef } from '../deliver/git-data.js';
import {
  canonicalRecordJson, centralOf, centralUpdateBranch, localRecordPath, MAX_RECORD_BYTES, parseRecord, readLocalRecord, readRecord, RecordError,
  recordHash, recordMarkerOf, recordPath, type LocalRecordDeps, type ReadRecordResult,
} from '../deliver/record.js';
import { centralProjectName } from '../engine/central-path.js';
import { confirmView, TYPED_VIEW_FIELDS, trustedPrevious } from '../deliver/trust.js';
import type { InstallRecord } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { UninstallError } from './errors.js';
import { ProgressFile } from './progress.js';

/** The app repo as GitHub reports it now (readRepo), never as the record says. */
export interface UninstallApp extends RepoRef { repoId: number; private: boolean; defaultBranch: string; ownerType: 'User' | 'Organization' }

export interface LoadedRecord {
  app: UninstallApp;
  /** The trusted record (full trust), or confirmView's view of it (typed trust). */
  record: InstallRecord;
  /**
   * typed: the record is confirmView's view. The fields in `dropped` are not the record's: the `drop` ones are absent (mergedAt, central,
   * scratch, orgRuleset, classicProtection, repoSettings, …), and the `fresh` ones are present but EMPTY (edits: [], planned: none,
   * serviceRoots: [], protectedPaths: [], environments[].changed: [] and .branchPolicyIds: []). The plan must consult `dropped` before it
   * reads any of them: an empty `edits` or an absent `mergedAt` there means "not granted", never "none" or "unfinished" (V-N4).
   */
  trust: 'full' | 'typed';
  /**
   * V1-R1 (sec I1): every API delete and restore needs the object's name typed (askTypedName): trust === 'typed' || marker !== 'match'.
   */
  typedNames: boolean;
  /** The record file's blob sha and the central default head it was read at: V4/V5 re-check both before they act (V-S9). */
  blobSha: string; centralHead: string;
  /** GitHub's id of the central repo now (sec M7): V6 compares it with record.central.repoId before any central delete. */
  centralRepoId: number;
  /** The setup pull request body's marker against the record's hash. Never a trust source (V-S2): differs/absent → typed names downstream. */
  marker: 'match' | 'differs' | 'absent';
  /** The local record file's setup PR, else the newest pull request on pipegen/setup (V-N14); never a number from the record. */
  setupPr: number | null;
  /** typed trust: the record fields (and `<kind>.<field>` entry fields) the view doesn't grant, absent or empty (TYPED_DROPPED); full trust: []. */
  dropped: readonly string[];
  /** Plain lines for the preview (names only). */
  warnings: string[];
}

export interface UninstallDeps {
  /** The user's terminal; typed names are asked only through it, and only when `interactive` is true (V-S13). */
  io?: Prompter; interactive?: boolean;
  local?: LocalRecordDeps; clock?: RateClock;
}

/**
 * What a typed trust never grants (TYPED_VIEW_FIELDS, G10-R5): the record fields it drops or writes fresh, and each entry kind's dropped or
 * fresh fields as `<kind>.<field>`. Built from the allow-list itself, so a field it classifies later shows up here without an edit.
 */
export const TYPED_DROPPED: readonly string[] = Object.freeze((() => {
  const f = TYPED_VIEW_FIELDS;
  const out: string[] = [...f.record.drop, ...f.record.fresh];
  for (const [kind, v] of Object.entries(f)) {
    if (kind === 'record' || kind === 'orgRuleset') continue;   // orgRuleset is dropped whole (in record.drop)
    const x = v as { drop?: readonly string[]; fresh?: readonly string[] };
    for (const k of [...(x.drop ?? []), ...(x.fresh ?? [])]) out.push(`${kind}.${k}`);
  }
  return out;
})());

const show = (s: string, n = 140): string => safeText(s, n);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The user's terminal, or a stop: typed names are never taken from a flag, an env variable or a run without a terminal (V-S13). */
function terminalOf(deps: Pick<UninstallDeps, 'io' | 'interactive'>, what: string): Prompter {
  if (deps.interactive !== true || deps.io === undefined) {
    throw new UninstallError(`pipegen needs you to ${what} at a terminal, and this run has none (no terminal, --yes, or CI), so it stopped here: nothing more was changed. Run \`npx pipegen uninstall\` at a terminal.`);
  }
  return deps.io;
}

/** The longest name askTypedName asks for; a longer one can't be shown whole, so it is never asked for. */
const MAX_TYPED_NAME = 120;

/**
 * Asks the user to type `expected` (exactly, surrounding spaces ignored) after `question`. True only for that name; a wrong name or a
 * cancelled question is false. No terminal: UninstallError, nothing asked. A blank `expected` is a caller's bug: Error, nothing asked.
 * A name that can't be shown exactly (safeText would change it, or it is longer than MAX_TYPED_NAME): false, nothing asked; the caller
 * keeps the object and lists it. Each line of `question` is shown through safeText.
 */
export async function askTypedName(deps: Pick<UninstallDeps, 'io' | 'interactive'>, expected: string, question: string): Promise<boolean> {
  if (typeof expected !== 'string' || expected.trim() === '') throw new UninstallError('pipegen asked for a typed confirmation with no name to type; it stopped here: nothing more was changed.');
  if (safeText(expected, MAX_TYPED_NAME) !== expected) return false;   // safeText cuts a longer one, so it differs then
  const io = terminalOf(deps, `type ${expected} to confirm`);
  const q = String(question).split('\n').map((l) => safeText(l, 300)).join('\n');
  let typed: string;
  try { typed = await io.text(`${q}\nType ${expected} to go on; anything else, and pipegen leaves it.`); } catch (e) {
    if (e instanceof PromptCancelledError) return false;
    throw e;
  }
  return typeof typed === 'string' && typed.trim() === expected;
}

/** A pull request of `r` by number, or null (404 after the repo itself was read). */
async function readPull(gh: Octokit, r: RepoRef, n: number, clock: RateClock): Promise<Record<string, unknown> | null> {
  try {
    const d = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls/{pull_number}', r, { pull_number: n }, clock);
    return isObj(d) ? d : null;
  } catch (e) {
    if (statusOf(e) === 404) return null;
    throw e;
  }
}

/** Whether a pull request's head is `branch` of the repo with id `repoId` (sec M2: never a fork's branch of the same name). */
const headIs = (p: Record<string, unknown>, branch: string, repoId: number): boolean => isObj(p.head) && p.head.ref === branch && isObj(p.head.repo) && p.head.repo.id === repoId;

/**
 * The pull requests of `r` whose head is `owner:branch`, in `state`, numbers newest first. With `headRepoId`, only those whose head repo is
 * that repo; without it (a stop check: more stops, never fewer) any head repo.
 */
async function pullsOn(gh: Octokit, r: RepoRef, branch: string, state: 'open' | 'all', clock: RateClock, headRepoId?: number): Promise<number[]> {
  const d = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls', r, { head: `${r.owner}:${branch}`, state, per_page: 100 }, clock);
  const list = Array.isArray(d) ? d.filter(isObj) : [];
  return list
    .filter((p) => isObj(p.head) && p.head.ref === branch && (headRepoId === undefined || headIs(p, branch, headRepoId)) && Number.isSafeInteger(p.number) && (p.number as number) > 0 && (state === 'all' || p.state === 'open'))
    .map((p) => p.number as number)
    .sort((a, b) => b - a);
}

/** V-N14: the local record file's setup PR when it is one on pipegen/setup, else the newest pull request on pipegen/setup. */
async function setupPrOf(gh: Octokit, app: RepoRef, appId: number, localPr: number | undefined, clock: RateClock, warnings: string[]): Promise<{ number: number; body: string } | null> {
  const asSetup = (d: Record<string, unknown> | null): string | null => (d !== null && headIs(d, SETUP_BRANCH, appId) ? (typeof d.body === 'string' ? d.body : '') : null);
  if (localPr !== undefined) {
    const body = asSetup(await readPull(gh, app, localPr, clock));
    if (body !== null) return { number: localPr, body };
    warnings.push(`This machine's local record file names pull request #${localPr}, which is not pipegen's setup pull request (branch ${SETUP_BRANCH} of ${show(`${app.owner}/${app.repo}`)} itself); pipegen looked for it by its branch instead.`);
  }
  for (const n of await pullsOn(gh, app, SETUP_BRANCH, 'all', clock, appId)) {
    const body = asSetup(await readPull(gh, app, n, clock));
    if (body !== null) return { number: n, body };
  }
  return null;
}

/** The record on `branch`, or null (none there), or the reason it can't be read (sec M6: told to the user as it is). */
async function reread(gh: Octokit, central: RepoRef, appRepo: string, branch: string, clock: RateClock): Promise<ReadRecordResult | { unreadable: string } | null> {
  try { return await readRecord(gh, central, appRepo, { branch, clock }); } catch (e) {
    if (e instanceof RecordError || e instanceof DeliverError) return { unreadable: e.message };
    throw e;
  }
}
const readable = (x: ReadRecordResult | { unreadable: string } | null): x is ReadRecordResult => x !== null && !('unreadable' in x);

/**
 * Whether `found` is the record behind `trusted`: its hash is the one this machine's local record file vouches for (sec M8, both trusts),
 * and it is the same record (full) or the record whose view `trusted` is (typed).
 */
function behind(found: ReadRecordResult | { unreadable: string } | null, vouched: string | null, trusted: InstallRecord, typed: boolean): found is ReadRecordResult {
  if (!readable(found) || vouched === null || found.hash !== vouched) return false;
  if (!typed) return canonicalRecordJson(found.record) === canonicalRecordJson(trusted);
  const cv = confirmView(found.record);
  return 'view' in cv && canonicalRecordJson(cv.view) === canonicalRecordJson(trusted);
}

/** Whether the record names this repository (its id, owner and name): a re-created or renamed repo has another id. */
const isThisRepo = (r: InstallRecord, appId: number, app: RepoRef): boolean => r.app.repoId === appId && r.app.owner.toLowerCase() === app.owner.toLowerCase() && r.app.repo.toLowerCase() === app.repo.toLowerCase();

/**
 * V1-R1 (sec M4): a created secret, variable or environment that doesn't hold exactly one of githubCreatedAt / unconfirmed (deliver always
 * writes one, so only an edited record lacks it or holds both) counts as unconfirmed: its githubCreatedAt is dropped, so the plan can only
 * delete it after a typed name (V-N2). Returns the record with those entries changed, and their names.
 */
function normalizeCreated(r: InstallRecord): { record: InstallRecord; names: string[] } {
  const names: string[] = [];
  const fix = <T extends { name: string; created: boolean; githubCreatedAt?: string; unconfirmed?: true }>(e: T): T => {
    if (!e.created || (e.githubCreatedAt !== undefined) !== (e.unconfirmed === true)) return e;
    names.push(e.name);
    const { githubCreatedAt: _drop, ...rest } = e;
    return { ...rest, unconfirmed: true } as T;
  };
  const record = { ...r, secrets: r.secrets.map(fix), variables: r.variables.map(fix), environments: r.environments.map(fix) };
  return { record, names };
}

/**
 * V6-R1 spec I1: the record for a second run 2, when the record file is gone from central's default branch. Only when the progress file
 * is at `B` and GitHub shows this project's central uninstall PR merged (exact branch, from the central repo itself, onto its default
 * branch): the record is rebuilt from the blob run 2 read before (the progress file's `anchors.recordBlobSha`), and used only when its git
 * blob sha is that anchor AND its hash is the one this machine's local record file vouches for (a typed vouch grants confirmView's view, as
 * trustedPrevious does). Anything else that doesn't match stops; null: not this case (the usual "no install record" follows).
 */
async function fromRun2Blob(
  gh: Octokit, app: RepoRef, uapp: UninstallApp, central: RepoRef, c: { id: number; defaultBranch: string }, deps: UninstallDeps, clock: RateClock, otherRepo: string,
): Promise<LoadedRecord | null> {
  const progress = await ProgressFile.open(app, uapp.repoId, deps.local ?? {});
  const st = progress.state;
  if (st === null || st.phase !== 'B') return null;
  const branch = `pipegen/uninstall-${centralProjectName(app.repo)}`;
  const prs = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls', central, { head: `${central.owner}:${branch}`, state: 'closed', per_page: 100 }, clock);
  const merged = (Array.isArray(prs) ? prs.filter(isObj) : [])
    // V6-R2 sec M1: this uninstall's PR only: its head the one pipegen set the branch to (the progress file); an earlier cycle's doesn't count
    .filter((p) => headIs(p, branch, c.id) && isObj(p.base) && p.base.ref === c.defaultBranch && typeof p.merged_at === 'string' && p.merged_at !== ''
      && st.centralUninstallHead !== undefined && isObj(p.head) && p.head.sha === st.centralUninstallHead)
    .map((p) => p.number).filter((n): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n > 0).sort((x, y) => y - x);
  if (merged.length === 0) return null;
  const centralName = show(`${central.owner}/${central.repo}`);
  const stop = (why: string): never => {
    throw new UninstallError(`The install record of ${show(`${app.owner}/${app.repo}`)} is gone from ${centralName} (your central uninstall pull request #${merged[0]} merged), and ${why}, so pipegen removes nothing more. Finish the steps it listed by hand. Nothing was changed.`);
  };
  const vouched = await readLocalRecord(app, deps.local ?? {}).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  if (vouched === null) stop('this machine has no local record file to check the copy pipegen read before');
  const anchor = st.anchors.recordBlobSha;
  let text = '';
  try { text = await readBlobText(gh, central, anchor, MAX_RECORD_BYTES, clock); } catch (e) {
    if (isRateStop(e) || e instanceof GitHubAccessError) throw e;
    if (e instanceof DeliverError || statusOf(e) === 404) stop(`pipegen can't read the copy of it it read before (blob ${anchor.slice(0, 12)})`);
    throw e;
  }
  if (gitBlobSha(text) !== anchor) stop(`GitHub's copy of it is not the blob pipegen read before (${anchor.slice(0, 12)})`);
  let found: InstallRecord;
  try { found = parseRecord(text); } catch (e) {
    if (e instanceof RecordError) stop(`the copy pipegen read before can't be read as a record (${show(e.message, 200)})`);
    throw e;
  }
  const hash = recordHash(found);
  if (hash !== vouched?.recordHash) stop('the copy pipegen read before is not the record this machine\'s local record file vouches for');
  if (!isThisRepo(found, uapp.repoId, app)) throw new UninstallError(otherRepo);
  const typed = vouched?.typed === true;
  let trustedRec = found;
  if (typed) {
    const cv = confirmView(found);
    if (!('view' in cv)) stop('its view (the names you confirmed by typing) can\'t be built');
    trustedRec = (cv as { view: InstallRecord }).view;
  }
  const warnings: string[] = [`The install record is gone from ${centralName}: your central uninstall pull request #${merged[0]} removed it. pipegen uses the copy it read before (blob ${anchor.slice(0, 12)}), checked against this machine's local record file.`];
  const { record, names } = normalizeCreated(trustedRec);
  if (names.length > 0) warnings.push(`The install record says pipegen created ${names.map((x) => show(x, 120)).join(', ')} without the one creation date pipegen records, so pipegen can't compare it with GitHub's: it deletes each only after you type its name (typed name).`);
  const pr = await setupPrOf(gh, app, uapp.repoId, vouched?.setupPr, clock, warnings);
  const m = pr === null ? null : recordMarkerOf(pr.body);
  const marker: LoadedRecord['marker'] = m === null ? 'absent' : m === hash ? 'match' : 'differs';
  if (marker !== 'match') warnings.push('The setup pull request\'s record marker doesn\'t match the install record (or there is none), so pipegen will ask you to type each name before it deletes or restores anything on GitHub.');
  const head = await readHead(gh, central, c.defaultBranch, clock);
  if (head === null) stop(`pipegen can't read the default branch of ${centralName}`);
  return {
    app: uapp, record, trust: typed ? 'typed' : 'full', typedNames: typed || marker !== 'match', blobSha: anchor, centralHead: head as string, centralRepoId: c.id,
    marker, setupPr: pr?.number ?? null, dropped: typed ? TYPED_DROPPED : [], warnings,
  };
}

/** trustedPrevious's note, without the clause meant for deliver (uninstall writes no new record). */
const uninstallNote = (n: string): string => n.replace(/: it writes a new record, and treats every existing file and secret as not its own\./, '.');

/**
 * The install record of `app` that uninstall may act on (see the header). Throws UninstallError, with nothing changed on GitHub, when there
 * is none, it isn't trusted, it is another repo's, or an open central pull request can still change it. A rate stop or a rejected token
 * passes through as is.
 */
export async function loadUninstallRecord(gh: Octokit, app: RepoRef, deps: UninstallDeps = {}): Promise<LoadedRecord> {
  try { return await load(gh, app, deps); } catch (e) {
    if (e instanceof UninstallError || isRateStop(e) || e instanceof GitHubAccessError) throw e;
    if (e instanceof DeliverError || e instanceof RecordError) throw new UninstallError(`${e.message} Nothing was changed.`, { cause: e });
    throw e;
  }
}

async function load(gh: Octokit, app: RepoRef, deps: UninstallDeps): Promise<LoadedRecord> {
  const clock = deps.clock ?? clockOf(gh);
  const name = show(`${app.owner}/${app.repo}`);
  const none = `No install record for ${name}. pipegen only removes what it recorded installing.`;
  const warnings: string[] = [];

  // 1. the app, as GitHub reports it
  const a = await readRepo(gh, app, clock);
  if (a === null) throw new UninstallError(`pipegen can't see ${name} (it isn't there, or this login has no access to it), so it removes nothing.`);
  // sec M7: GitHub's own name for it (a renamed or transferred repo is served through a redirect for the old name)
  const canonical = await ghRead(gh, 'GET /repos/{owner}/{repo}', app, {}, clock);
  const fullName = isObj(canonical) ? canonical.full_name : undefined;
  if (typeof fullName !== 'string' || fullName.toLowerCase() !== `${app.owner}/${app.repo}`.toLowerCase()) {
    throw new UninstallError(`GitHub now calls it ${show(String(fullName), 140)}, not ${name} (renamed or transferred). Run \`npx pipegen uninstall\` with its current name; pipegen removes nothing under the old one. Nothing was changed.`);
  }
  const uapp: UninstallApp = { owner: app.owner, repo: app.repo, repoId: a.id, private: a.private, defaultBranch: a.defaultBranch, ownerType: a.ownerType };

  // the private central repo the record lives in (records-only for a public app, V-N13)
  const central = centralOf(app);
  const centralName = show(`${central.owner}/${central.repo}`);
  const c = await readRepo(gh, central, clock);
  if (c === null) throw new UninstallError(`${none} (pipegen can't see ${centralName}, where it keeps its install records.)`);
  if (!c.private) throw new UninstallError(`${centralName} is public; pipegen keeps install records only in a private one, so it won't act on a record there. Nothing was changed.`);

  // 4. an open central pull request on pipegen/update-<name> can still change the record: stop before anything is asked
  const update = centralUpdateBranch(app.repo);
  const open = await pullsOn(gh, central, update, 'open', clock);
  if (open.length > 0) {
    throw new UninstallError(`pipegen's central pull request #${open[0]} (branch ${show(update, 120)}) in ${centralName} is still open, and it can change the install record. Merge or close it first, then run \`npx pipegen uninstall\` again. Nothing was changed.`);
  }
  const updateExists = await readHead(gh, central, update, clock) !== null;

  // sec M1 / M6, spec M1 / M3 (V1-R1): the default branch's record, read once before the trust question. An unreadable one stops with its
  // own reason, and one of another repo stops, before anything is asked or vouched into the local record file.
  const recordName = show(recordPath(app.repo), 200);
  const otherRepo = `The install record ${recordName} names another repo id or name: ${name} is not the repository pipegen was installed in (re-created or renamed?), so pipegen removes nothing.`;
  const first = await reread(gh, central, app.repo, c.defaultBranch, clock);
  if (first !== null && !readable(first)) {
    throw new UninstallError(`pipegen can't read the install record ${recordName} in ${centralName}: ${show(first.unreadable, 300)} pipegen removes nothing. Nothing was changed.`);
  }
  if (readable(first) && !isThisRepo(first.record, a.id, app)) throw new UninstallError(otherRepo);

  // V6-R1 spec I1: run 2 again after this project's central uninstall PR merged (the record is gone from central by design)
  if (first === null) {
    const again = await fromRun2Blob(gh, app, uapp, central, c, deps, clock, otherRepo);
    if (again !== null) return again;
  }

  // 2. the one trust order; a typed confirmation only from the user's terminal (V-S13)
  const notes: string[] = [];
  const confirm = deps.io !== undefined && deps.interactive === true ? { io: deps.io, interactive: true } : undefined;
  const trusted = await trustedPrevious(gh, app, central, c.defaultBranch, updateExists ? update : null, deps.local ?? {}, clock, notes, confirm);
  if (trusted.record === null) {
    if (!trusted.exists) throw new UninstallError(none);
    // sec M-r1 (V1-R2): nothing on the default branch, so the record is only on the central update branch. trustedPrevious offers only the
    // default branch's record for typing, so no run at a terminal can confirm it, and its note ("you didn't confirm it") would be false.
    if (first === null) {
      throw new UninstallError(`pipegen found no install record for ${name} on the default branch of ${centralName}: it is only on the central branch ${show(update, 120)}, which pipegen can't confirm. Merge that change (or delete the branch), then run \`npx pipegen uninstall\` again. Nothing was changed.`);
    }
    const file = localRecordPath(app, deps.local ?? {});
    const wayOn = trusted.why === 'mismatch'
      ? `This machine's local record file ${show(file, 300)} holds another record's hash. If you set pipegen up from another machine, move that file away and run \`npx pipegen uninstall\` again at a terminal: pipegen then shows what the record claims and asks you to type the repo name.`
      : confirm === undefined
        ? 'This machine has no local record file for it. Run `npx pipegen uninstall` at a terminal: pipegen then shows what the record claims and asks you to type the repo name.'
        : 'It was not confirmed by typing the repo name.';
    throw new UninstallError(`pipegen found no install record for ${name} that it trusts, so it removes nothing. ${wayOn}${notes.length > 0 ? ` ${notes.map(uninstallNote).join(' ')}` : ''}`);
  }
  const typed = trusted.typed === true;

  // the record's file and the central head it was read at, for the re-checks before any change (the trusted one must be the default
  // branch's, and its hash the one this machine's local record file vouches for: sec I2, M8)
  const vouched = await readLocalRecord(app, deps.local ?? {}).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  const vouchedHash = vouched?.recordHash ?? null;
  const onDefault = await reread(gh, central, app.repo, c.defaultBranch, clock);
  if (!behind(onDefault, vouchedHash, trusted.record, typed)) {
    const onBranch = updateExists ? await reread(gh, central, app.repo, update, clock) : null;
    throw new UninstallError(behind(onBranch, vouchedHash, trusted.record, typed)
      ? `The install record pipegen trusts is on the central branch ${show(update, 120)} and not on the default branch of ${centralName}. Merge that change (or delete the branch), then run \`npx pipegen uninstall\` again. Nothing was changed.`
      : `The install record in ${centralName} changed while pipegen read it. Run \`npx pipegen uninstall\` again. Nothing was changed.`);
  }
  const found = onDefault;

  // 3. the record must be this repository's (checked again on the record that is trusted)
  if (!isThisRepo(trusted.record, a.id, app)) throw new UninstallError(otherRepo);
  const { record, names: unconfirmedNames } = normalizeCreated(trusted.record);
  if (record.app.private !== a.private) warnings.push(`${name} is ${a.private ? 'private' : 'public'} now; it was ${record.app.private ? 'private' : 'public'} when pipegen set it up.`);
  if (record.app.defaultBranch !== a.defaultBranch) warnings.push(`The default branch of ${name} is ${show(a.defaultBranch, 100)} now; pipegen set it up on ${show(record.app.defaultBranch, 100)}.`);
  const owned = (t: 'User' | 'Organization'): string => (t === 'User' ? 'a user account' : 'an organization');
  if (record.app.ownerType !== a.ownerType) warnings.push(`${name} is owned by ${owned(a.ownerType)} now; it was owned by ${owned(record.app.ownerType)} when pipegen set it up.`);
  if (record.central?.repoId !== undefined && record.central.repoId !== c.id) warnings.push(`${centralName} has the id ${c.id} now; the install record names ${record.central.repoId} (re-created?), so pipegen treats it as not the one it created.`);
  if (unconfirmedNames.length > 0) warnings.push(`The install record says pipegen created ${unconfirmedNames.map((x) => show(x, 120)).join(', ')} without the one creation date pipegen records, so pipegen can't compare it with GitHub's: it deletes each only after you type its name (typed name).`);

  // 5. the setup pull request's marker: a warning, never trust
  const pr = await setupPrOf(gh, app, a.id, vouched?.setupPr, clock, warnings);
  const m = pr === null ? null : recordMarkerOf(pr.body);
  const marker: LoadedRecord['marker'] = m === null ? 'absent' : m === found.hash ? 'match' : 'differs';
  const ask = 'pipegen will ask you to type each name before it deletes or restores anything on GitHub.';
  if (pr === null) warnings.push(`pipegen found no setup pull request (branch ${SETUP_BRANCH}) in ${name} to compare the record's hash with, so ${ask}`);
  else if (marker === 'absent') warnings.push(`The setup pull request #${pr.number} holds no record marker on its last line, so ${ask}`);
  else if (marker === 'differs') warnings.push(`The record marker in the setup pull request #${pr.number} doesn't match the install record (someone edited one of them), so ${ask}`);

  // V-N4: what a typed trust doesn't grant
  if (typed) warnings.push(`The install record was trusted by typing the repo name, so pipegen uses only the names you confirmed, and it will ask you to type each name, one by one, before it deletes or restores anything on GitHub. It deletes the app's rulesets only after each name is typed. It doesn't undo its edits, restore earlier settings or the branch protection, remove the org rule or the central locks, or delete repos: those are manual steps it lists.`);

  return {
    app: uapp, record, trust: typed ? 'typed' : 'full', typedNames: typed || marker !== 'match', blobSha: found.blobSha, centralHead: found.commit, centralRepoId: c.id,
    marker, setupPr: pr?.number ?? null, dropped: typed ? TYPED_DROPPED : [], warnings,
  };
}
