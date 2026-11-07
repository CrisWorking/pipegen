// v0.2 Plan V V4 (rulings V-B3, V-B4, V-B6, V-S1, V-S2, V-S4, V-S5, V-S6, V-S8, V-S12, V-S13, V-N1…V-N14): the uninstall plan and its preview.
// The plan decides what uninstall removes, reverts, restores, asks about or keeps; the preview is what the user agrees to (V5 asks the one
// confirmation). Nothing here writes: every read goes through the API (the app's default-branch tree and blobs, UninstallApi reads), never
// the local folder.
//
// - Files the record says pipegen wrote whole: each path must pass createdPathProblem and be claimed by exactly one created-file rule of
//   its part (with the record's service roots), or be one of pipegen's own app workflows; else manual review. Unchanged (its blob sha is one
//   pipegen wrote) → removed in the uninstall PR. Changed since, adopted (V-N1), or a file the team may want (Dockerfile + .dockerignore
//   together, docker-compose, the starter tests) → asked, default keep; ownerEdited (V-N3) → manual review, never asked or removed. Kept
//   starter tests keep the package.json/lock edits (V-S8).
// - Edits: revertEdits (V2) on the whole app record, with the app's LIVE default branch; a typed trust drops them (V-N4): manual steps.
// - GitHub objects: each is read now and classified by isPipegens (V3: GitHub's id, name, source and created_at against the record).
//   `no` → kept and listed, never asked about. A typed name (V1's askTypedName, the interactive terminal only; no terminal → stop) for an
//   `ask`, a name without PIPEGEN_ (secrets, variables) or pipegen- (environments), every restore, and every API delete and restore of a
//   run with `typedNames` (typed trust or a marker that isn't a match). The typed name is minted by UninstallApi.confirm as a token for that
//   very object; V5 passes it back to the same `api`.
// - Secrets: created:false never; overwritten never (the old value is gone, V-N6). A created environment holding anything this plan doesn't
//   delete is kept (V-S5). Restores touch only `changed` fields and need `previous` (absent → left as it is); an environment's variable has
//   no restore route (a manual step); a variable restore needs the value pipegen set (blockFrom, cosignPub).
// - Settings pipegen turned on (previous false): "Turn off <setting>? (y/N)", default keep (V-S6); with typedNames also the key typed.
// - An unfinished install (the setup PR never merged, V-S4): its open PR closed, pipegen/setup deleted only when every change on it is a file
//   pipegen recorded writing (else manual), the N4 environment and the deliver-time secrets (record entries) as above.
// - The local leftovers file (V-N5): each entry for this repo is identity-checked and always asked by name; never deleted blind.
// - Central: the exact list (record `repo: 'central'` ∩ centralFilesOf + the record, V-B4); lastProject from the records AND the files on the
//   central default branch, and no open central PR but this project's own (exact branch and GitHub's id of the recorded central repo).
// - Fix round 1 (V4-R1), two runs: `phase` A (run 1: the uninstall PR, pipegen's open PRs (app and the central update PR), the merge
//   locks) asks typed names only for its own items; run 2's items (secrets, variables, environments, settings, central) are planned and
//   previewed with no question and no token (`needsName`). Phase B (run 2, a fresh plan and confirmation) asks those names, asks no file
//   question, and sees run 1's work as done (`done`: files gone, a file back to its original or without pipegen's part, a ruleset gone,
//   the protection as before), or as still to do by hand, never as a new action. A leftover secret or environment with no creation date is
//   never deleted (it may be one pipegen only overwrote). "Unfinished" (no PR to wait for) only when none of pipegen's own workflows is on
//   the default branch (and, under full trust, the record has no mergedAt).
// - V6 (M-r1-9, V5-R1 carry): phase B's preview also names the scratch repo cleanup (the scratch repo as GitHub shows it now, with
//   pipegen's marker; a saved proof state's leftovers) and, with --delete-repos, each repo to be deleted (App mode: after its typed name;
//   the central repo only after its pull request merged) or the `gh repo delete` command printed instead (token mode). Nothing of either is
//   done without being in that preview.
import type { Octokit } from '@octokit/rest';
import { PromptCancelledError, type Prompter } from '../cli/io.js';
import { readEnv, SETUP_BRANCH } from '../deliver/deliver.js';
import { DeliverError, ghRead, isoAt, readBlobText, readHead, readTree, statusOf, type RepoRef, type TreeEntry } from '../deliver/git-data.js';
import { centralUpdateBranch, readLocalLeftovers, recordPath, RecordError, type Leftover } from '../deliver/record.js';
import { classicPutForm } from '../deliver/settings-api.js';
import { centralFilesOf, UPDATE_BRANCH } from '../deliver/update.js';
import { HOOK_FILES, HOOKS_MARKER } from '../engine/created-builders.js';
import { CREATED_RULES } from '../engine/created-files.js';
import { HEAD_CHECK_STEP_ID } from '../engine/deploy-steps.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { CALLER_WORKFLOW, createdPathProblem, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PUSH_WORKFLOW } from '../engine/job-rules.js';
import { clockOf, GitHubAccessError } from '../github/client.js';
import { VERIFY_JOB_ID } from '../layers/assemble.js';
import { CENTRAL_REPO, githubRead, SCRATCH_MARKER, SCRATCH_PREFIX } from '../proof/target.js';
import type { EnvSettings, InstallEdit, InstallRecord, PipelineDraft, RecordApiRequest } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { UninstallError } from './errors.js';
import { askTypedName, type LoadedRecord, type UninstallDeps } from './record.js';
import { revertEdits, type CurrentFile, type RevertResult } from './revert.js';
import {
  droppedLiveField, environmentOwned, exactlyAsSet, isPipegens, ownedName, uninstallBranch, UninstallApi, UninstallRefusal,
  type Confirmable, type EnvForm, type Owned, type TypedName, type UninstallApp as TargetApp,
} from './target.js';

type FileEntry = InstallRecord['files'][number];
type SecretEntry = InstallRecord['secrets'][number];
type VariableEntry = InstallRecord['variables'][number];
type EnvEntry = InstallRecord['environments'][number];
type RulesetEntry = InstallRecord['rulesets'][number];
type OrgEntry = NonNullable<InstallRecord['orgRuleset']>;
type SettingKey = 'shaPinningRequired' | 'vulnerabilityAlerts' | 'secretScanning' | 'pushProtection';

/**
 * A typed name the user gave for one object (confirmedByName), with the token V3 takes for it when the object has one. `needsName`: the
 * item belongs to the other run, which asks its name (no question here, no token).
 */
interface Named { confirmedByName: boolean; typed?: TypedName; needsName?: true }
/** A: run 1 (the uninstall PR, pipegen's PRs, the merge locks). B: run 2, after the uninstall PR merged (secrets … central). */
export type UninstallPhase = 'A' | 'B';

export interface UninstallPlan {
  /** The run this plan is for; only its own items carry typed names and tokens (V4-R1). */
  phase: UninstallPhase;
  /** Phase B: run 1's work found done on GitHub (names only). */
  done: string[];
  /** The app as GitHub reports it now (LoadedRecord.app). */
  app: { owner: string; repo: string; repoId: number; defaultBranch: string };
  /**
   * The write API of this plan; the typed-name tokens below are bound to it. Never used directly: apply.ts's takeApi takes it off the
   * confirmed plan and hands the phase runner a PhaseApi bound to the plan's phase (V5-R1 I2); V5/V6 send every write through that.
   */
  api: UninstallApi;
  trust: LoadedRecord['trust'];
  typedNames: boolean;
  /** TOCTOU anchors (V-S9): V5 re-checks them before anything is sent. */
  base: { appHead: string; appTree: string; centralHead: string; recordBlobSha: string };
  warnings: string[];
  /** Every file the app's uninstall PR deletes: pipegen's own, unchanged; and those the user chose not to keep. */
  removeFiles: { repo: 'app'; path: string }[];
  /** The questions asked about files (default keep) and the answers. `pair`: asked together (Dockerfile and .dockerignore). */
  keepAsk: { path: string; pair?: string; keep: boolean; why: string }[];
  /** V2's result per app edit; `manual` ones are listed with their exact text in the preview. */
  reverts: { edit: InstallEdit; result: RevertResult }[];
  manual: { what: string; why: string; step?: string }[];
  deleteRulesets: ({ kind: 'gate' | 'reviews'; id: number; entry: RulesetEntry } & Named)[];
  restoreClassic?: { branch: string; previous: Record<string, unknown> | null; diff: string; planned: RecordApiRequest } & Named;
  deleteOrgRuleset?: { org: string; id: number; entry: OrgEntry } & Named;
  deleteSecrets: ({ secret: SecretEntry; fromLeftovers?: true } & Named)[];
  deleteVariables: ({ name: string; scope: 'repo' | `env:${string}`; entry: VariableEntry } & Named)[];
  /** `previous` is a value: never printed. `pipegenValue`: the value pipegen set (restoreVariable restores only while GitHub holds it). */
  restoreVariables: ({ name: string; scope: string; previous: string; pipegenValue: string; entry: VariableEntry } & Named)[];
  /** `owned`: the environment as V3 deletes it (with the record's own secrets and variables of it, V-S5). */
  deleteEnvironments: ({ name: string; entry: EnvEntry; owned: Owned } & Named)[];
  /**
   * `changed`: the fields to put back (only those); `shown`: GitHub's settings the diff was made from (restoreEnvironment needs them
   * unchanged); `current`: the same with the branch rules; `deleteBranchPolicies`: the rule ids pipegen added that GitHub still holds.
   */
  restoreEnvironments: ({ name: string; previous: EnvSettings; changed: (keyof EnvSettings)[]; current: EnvSettings; shown: EnvForm; diff: string; entry: EnvEntry; deleteBranchPolicies: { id: number; typed?: TypedName }[] } & Named)[];
  settings: { key: SettingKey; previous: boolean; turnOff: boolean; confirmedByName: boolean }[];
  closePrs: { repo: 'app' | 'central'; number: number; branch: string; confirmedByName: boolean }[];
  /** pipegen/setup of an unfinished install, only when every change on it is pipegen's; `head`: the commit checked (V5 deletes only that). */
  deleteBranches: { repo: 'app'; branch: string; head: string; confirmedByName: boolean }[];
  /** This project's exact central files (V-B4), the record last; V6 reads them again before the central PR. */
  centralFiles: string[];
  lastProject: boolean;
  centralLocks?: InstallRecord['central'];
  /** None of pipegen's own workflows is on the default branch (and, full trust, no mergedAt): no uninstall PR to wait for (V-S4). */
  unfinished: boolean;
  /** Phase B (M-r1-9): the scratch repo `<owner>/pipegen-proof-<repo>` GitHub shows now with pipegen's marker (its id): run 2 empties it. */
  scratch?: { repo: string; id: number };
  /** Phase B: a saved proof state is there; run 2 cleans what it left first (E's cleanupLeftovers, the scratch repo never deleted there). */
  proofCleanup: boolean;
  /**
   * Phase B with --delete-repos (V-S3): `delete` (App mode: its name typed then; `afterCentralPr`: only once the central pull request
   * removing the record merged) or `command` (token mode: `gh repo delete` printed, nothing deleted). Any other repo is in skipped/manual.
   */
  deleteRepos: { repo: string; kind: 'scratch' | 'central'; how: 'delete' | 'command'; afterCentralPr?: true }[];
  skipped: { what: string; why: string }[];
}

/** `phase`: A (run 1, the default) or B (run 2). */
export type PlanDeps = Omit<UninstallDeps, 'io'> & {
  phase?: UninstallPhase;
  /** --delete-repos (V-S3): run 2 deletes the scratch repo and, last project, the central repo. */
  deleteRepos?: boolean;
  /** Auth.canDeleteRepos: the App's consented Administration write. Without it (token mode) nothing is deleted; the commands are printed. */
  canDeleteRepos?: boolean;
  /** A saved proof state is there (StateStore): run 2 cleans what it left first. */
  proofState?: boolean;
};

const show = (s: unknown, n = 120): string => safeText(String(s), n);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const lower = (s: unknown): string => String(s).toLowerCase();
/** JSON with sorted keys: two settings compared by content, not key order. */
const canon = (v: unknown): string => JSON.stringify(v, (_k, x: unknown) => (isObj(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x)) ?? 'undefined';
const fmt = (v: unknown): string => safeText(canon(v), 160);
const SHA_RE = /^[0-9a-f]{40}$/;
/** The largest file uninstall reads to revert (a package-lock can be large); a larger one is manual. */
const MAX_BLOB = 8 * 1024 * 1024;
/** The most pages of open central pull requests read (100 each); more → not provably the last project. */
const MAX_PR_PAGES = 10;
/** The most workflows of the app read for pipegen's leftovers (V-N11); more → one manual step. */
const MAX_SCANNED = 200;
const NOT_TYPED = 'kept: its name was not typed';
const GONE = 'GitHub doesn\'t show it (already gone, or this login can\'t see it): nothing to do';
const ORG_GONE = 'GitHub answers 404 for it: it is gone, or this login can\'t read the organisation\'s rulesets (pipegen can\'t tell which); check it in the organisation\'s settings';
const CANT_ASK = 'its name has characters (or a length) the terminal can\'t show exactly, so it can\'t be asked safely; pipegen leaves it';
/** A name askTypedName can ask for exactly (V1: it refuses any name safeText would change or cut). */
const askable = (name: unknown): boolean => typeof name === 'string' && name.trim() !== '' && safeText(name, 120) === name;

/** pipegen's own app workflows (assemble.ts): claimed by their exact path, part `pipeline`. */
const APP_WORKFLOWS: readonly string[] = [CALLER_WORKFLOW, PUSH_WORKFLOW, NIGHTLY_WORKFLOW, LOCAL_MERGE_WORKFLOW];
/** Created files the team may want to keep: asked, default keep. */
const KEEP_KINDS: ReadonlySet<string> = new Set(['dockerfile', 'dockerignore', 'compose', 'starter-tests']);
const ENV_FIELDS: readonly (keyof EnvSettings)[] = ['wait_timer', 'prevent_self_review', 'reviewers', 'can_admins_bypass', 'deployment_branch_policy', 'branch_policies'];
const SETTING_KEYS: readonly SettingKey[] = ['shaPinningRequired', 'vulnerabilityAlerts', 'secretScanning', 'pushProtection'];
const SETTING_LABEL: Readonly<Record<SettingKey, string>> = {
  shaPinningRequired: 'the full-length commit sha pin for actions', vulnerabilityAlerts: 'Dependabot alerts', secretScanning: 'secret scanning', pushProtection: 'push protection',
};
/** The central workflow of some project: `<project>--<layer>.yml`. */
const CENTRAL_LAYER_RE = /^\.github\/workflows\/.+--(?:merge|push|nightly|sign|required)\.ya?ml$/;
const WORKFLOW_RE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
/** The classic protection keys a diff compares (classicPutForm's output). */
const CLASSIC_DIFF_KEYS = ['required_status_checks', 'enforce_admins', 'required_pull_request_reviews', 'restrictions', 'allow_force_pushes', 'allow_deletions', 'required_linear_history', 'required_conversation_resolution', 'block_creations', 'lock_branch', 'allow_fork_syncing'];

const CENTRAL_MANUAL = 'the central repo\'s ruleset, CODEOWNERS block and Actions access';
/** V-N4: what a typed trust doesn't grant (TYPED_DROPPED field → the manual step). */
const TYPED_MANUAL: readonly { fields: readonly string[]; what: string; step: string }[] = [
  { fields: ['edits'], what: 'pipegen\'s changes inside your files', step: 'Review by hand the pipegen-verify job and the head checks in your deploy workflows, pipegen\'s hook block, its CODEOWNERS block, its Dependabot entry and the test changes in package.json and its lock file.' },
  { fields: ['variables.previous', 'environments.previous'], what: 'settings pipegen changed on existing variables and environments', step: 'Check your repo variables and environments (Settings → Environments) and put back what you want.' },
  { fields: ['classicProtection'], what: 'the branch protection pipegen set (if it set one)', step: 'Check Settings → Branches and put the protection back as you want it.' },
  { fields: ['orgRuleset'], what: 'the organisation required-workflow rule (if pipegen made one)', step: 'Check the organisation\'s rulesets and delete pipegen\'s required-workflow rule for this repo if it is there.' },
  { fields: ['central'], what: CENTRAL_MANUAL, step: 'Check the ruleset, CODEOWNERS and Actions access settings of your pipelines repo by hand.' },
  { fields: ['scratch'], what: 'the scratch repo (if pipegen made one)', step: 'Check for a pipegen-proof-<repo> repo and delete it by hand if you don\'t need it.' },
  { fields: ['repoSettings'], what: 'repo security settings pipegen turned on', step: 'Check Settings → Code security (secret scanning, push protection, Dependabot alerts) and Settings → Actions (the sha pin).' },
];

/**
 * The uninstall plan of `loaded` (V1's trusted record) for one run (`deps.phase`, default A). Asks the keep questions (run 1; default keep;
 * none without a terminal) and the typed names of this run's items only (at the interactive terminal: without one, a needed name stops with
 * UninstallError). Sends no write. Run 2 (B) is a fresh plan: it never reuses run 1's answers or tokens.
 */
export async function planUninstall(gh: Octokit, loaded: LoadedRecord, io: Prompter | undefined, deps: PlanDeps = {}): Promise<UninstallPlan> {
  try { return await build(gh, loaded, io, deps); } catch (e) {
    if (e instanceof UninstallError || isRateStop(e) || e instanceof GitHubAccessError) throw e;
    if (e instanceof DeliverError || e instanceof RecordError) throw new UninstallError(`${e.message} pipegen plans nothing. Nothing was changed.`, { cause: e });
    throw e;
  }
}

async function build(gh: Octokit, loaded: LoadedRecord, io: Prompter | undefined, deps: PlanDeps): Promise<UninstallPlan> {
  const clock: RateClock = deps.clock ?? clockOf(gh);
  const rec = loaded.record;
  const appRef: RepoRef = { owner: loaded.app.owner, repo: loaded.app.repo };
  const full = `${appRef.owner}/${appRef.repo}`;
  const typedTrust = loaded.trust === 'typed';
  const phase: UninstallPhase = deps.phase === 'B' ? 'B' : 'A';
  const inA = phase === 'A';
  const interactive = deps.interactive === true && io !== undefined;
  const askDeps = { ...(io === undefined ? {} : { io }), ...(deps.interactive === undefined ? {} : { interactive: deps.interactive }) };
  // the typed-name question of this run: target.ts builds it; `context` (the diff, the reason) is shown above it once
  let context = '';
  const askName = (expected: string, question: string): Promise<boolean> => {
    const q = context === '' ? question : `${context}\n${question}`;
    context = '';
    return askTypedName(askDeps, expected, q);
  };
  const targetApp: TargetApp = { owner: appRef.owner, repo: appRef.repo, repoId: loaded.app.repoId };
  const centralRepoId = rec.central?.repoId;
  const api = new UninstallApi(gh, targetApp, { clock, askName, typedNames: loaded.typedNames, ...(centralRepoId === undefined ? {} : { centralRepoId }) });
  const central: RepoRef = { owner: appRef.owner, repo: CENTRAL_REPO };

  const u: UninstallPlan = {
    phase, done: [],
    app: { owner: appRef.owner, repo: appRef.repo, repoId: loaded.app.repoId, defaultBranch: loaded.app.defaultBranch },
    api, trust: loaded.trust, typedNames: loaded.typedNames,
    base: { appHead: '', appTree: '', centralHead: loaded.centralHead, recordBlobSha: loaded.blobSha },
    warnings: [...loaded.warnings], removeFiles: [], keepAsk: [], reverts: [], manual: [], deleteRulesets: [], deleteSecrets: [], deleteVariables: [],
    restoreVariables: [], deleteEnvironments: [], restoreEnvironments: [], settings: [], closePrs: [], deleteBranches: [], centralFiles: [], lastProject: false,
    unfinished: false, skipped: [], proofCleanup: !inA && deps.proofState === true, deleteRepos: [],
  };
  const skip = (what: string, why: string): void => { u.skipped.push({ what, why }); };
  const manual = (what: string, why: string, step?: string): void => { u.manual.push({ what, why, ...(step === undefined ? {} : { step }) }); };
  /** Phase B: run 1's work found done on GitHub. */
  const markDone = (what: string): void => { u.done.push(what); };

  /** A yes/no question (the default when there is no terminal, or the question is cancelled). */
  const ask = async (q: string, def: boolean): Promise<boolean> => {
    if (!interactive) return def;
    try { return (await (io as Prompter).confirm(q, def)) === true; } catch (e) {
      if (e instanceof PromptCancelledError) return def;
      throw e;
    }
  };
  /** A typed name minted for `c` by the API (its token), with `ctx` shown above the question. */
  const confirm = async (c: Confirmable, ctx = ''): Promise<TypedName | null> => {
    context = ctx;
    try { return await api.confirm(c); } finally { context = ''; }
  };
  /** A typed name for something with no token (a setting, a pull request, a branch): V1's askTypedName directly. */
  const typedPlain = (expected: string, question: string): Promise<boolean> => askTypedName(askDeps, expected, question);

  /** A GET through the API: the answer, or why it isn't there (404: gone or no access; 403 or another status: a manual step). */
  const live = async (route: string, params: Record<string, unknown>, gone = GONE): Promise<{ data: unknown } | { missing: string; manual: boolean }> => {
    try { return { data: (await api.read(route, params)).data }; } catch (e) {
      if (e instanceof UninstallRefusal) return { missing: `pipegen won't read it (${show(e.message, 200)})`, manual: true };
      const s = statusOf(e);
      if (isRateStop(e) || e instanceof GitHubAccessError || s === undefined || s === 401) throw e;
      if (s === 404) return { missing: gone, manual: false };
      return { missing: `GitHub refused to show it (HTTP ${s}), so pipegen can't tell whether it is the one it created`, manual: true };
    }
  };

  /**
   * One object pipegen may delete: read now, judged by isPipegens, then (when a name is needed) its typed name. null: kept, and listed.
   * `extra`: a name is needed besides the verdict (not pipegen-shaped, or a leftover); `check`: a reason to keep it found right before asking;
   * `when`: the run that sends it (V4-R1): another run's name is not asked here (`needsName`, no token); `gone`: the words for a 404.
   */
  const classify = async (o: Owned, what: string, read: { route: string; params: Record<string, unknown> }, extra: boolean, opts: { why?: string; check?: () => Promise<string | null>; when: UninstallPhase; gone?: string }): Promise<Named | null> => {
    const l = await live(read.route, read.params, opts.gone);
    if ('missing' in l) {
      if (l.manual) manual(what, l.missing, 'Check it on GitHub and remove it by hand if it is pipegen\'s.');
      else skip(what, l.missing);
      return null;
    }
    const v = isPipegens(o, l.data, targetApp);
    if (v.is === 'no') { skip(what, v.why); return null; }
    const kept = opts.check === undefined ? null : await opts.check();
    if (kept !== null) { skip(what, kept); return null; }
    const need = v.is === 'ask' || loaded.typedNames || extra;
    if (!need) return { confirmedByName: false };
    if (!askable(ownedName(o))) { manual(what, CANT_ASK, 'Check it on GitHub and remove it by hand if it is pipegen\'s.'); return null; }
    if (opts.when !== phase) return { confirmedByName: false, needsName: true };
    const reason = [opts.why, v.is === 'ask' ? `${v.why}.` : null, loaded.typedNames ? 'This run asks each name: the install record was trusted by typing, or its marker in the setup pull request differs.' : null].filter((x): x is string => x !== null && x !== undefined).join(' ');
    const t = await confirm(o, reason);
    if (t === null) { skip(what, NOT_TYPED); return null; }
    return { confirmedByName: true, typed: t };
  };

  // ---------- the base: the app's default branch now (the API, never the local folder) ----------
  const appHead = await readHead(gh, appRef, loaded.app.defaultBranch, clock);
  if (appHead === null) throw new UninstallError(`pipegen can't read the default branch ${show(loaded.app.defaultBranch, 100)} of ${show(full)}, so it plans nothing. Nothing was changed.`);
  const appTree = await readTree(gh, appRef, appHead, clock);
  u.base.appHead = appHead;
  u.base.appTree = appTree.tree;
  const entries = appTree.entries;
  const blobs = new Map<string, string | null>();
  /** A blob of the app by sha (cached), or null when it can't be read (gone, too large, refused). */
  const readBlob = async (sha: string | null | undefined): Promise<string | null> => {
    if (typeof sha !== 'string' || !SHA_RE.test(sha)) return null;
    if (blobs.has(sha)) return blobs.get(sha) ?? null;
    let t: string | null = null;
    try { t = await readBlobText(gh, appRef, sha, MAX_BLOB, clock); } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401 || (!(e instanceof DeliverError) && statusOf(e) === undefined)) throw e;
      t = null;
    }
    blobs.set(sha, t);
    return t;
  };
  const plainFile = (e: TreeEntry | undefined): e is TreeEntry => e !== undefined && e.type === 'blob' && (e.mode === '100644' || e.mode === '100755');

  // ---------- V-N4: what a typed trust doesn't grant ----------
  if (typedTrust) {
    for (const m of TYPED_MANUAL) {
      if (m.fields.some((f) => loaded.dropped.includes(f))) manual(m.what, 'the install record was trusted by typing the repo name, which doesn\'t vouch for this part of it, so pipegen doesn\'t undo it', m.step);
    }
  }
  if (rec.app.defaultBranch !== loaded.app.defaultBranch) {
    manual('default branch', `the default branch was renamed since install (${show(rec.app.defaultBranch, 100)} → ${show(loaded.app.defaultBranch, 100)}): pipegen's head checks name the old one, so their reverts come back as manual review`);
  }

  // ---------- 1. files pipegen wrote whole ----------
  const draft = { profile: { services: rec.serviceRoots.map((path) => ({ path })) } } as unknown as PipelineDraft;
  const claimOf = (f: FileEntry): string | null => {
    if (createdPathProblem(f.path) !== null) return null;
    if (APP_WORKFLOWS.includes(f.path)) return f.part === 'pipeline' ? 'workflow' : null;
    let rules;
    try { rules = CREATED_RULES.filter((r) => r.repo === 'app' && r.match(f.path, draft)); } catch { return null; }
    const r = rules.length === 1 ? rules[0] : undefined;
    return r !== undefined && r.mode === 'new' && r.parts.includes(f.part) ? r.id : null;
  };
  type Judged = { f: FileEntry; claim: string; state: 'remove' | 'ask' | 'held'; changed: boolean };
  const judged: Judged[] = [];
  for (const f of rec.files) {
    if (f.repo !== 'app') continue;
    const claim = claimOf(f);
    if (claim === null) {
      const roots = typedTrust ? '; the record was trusted by typing, which doesn\'t vouch for its service folders' : '';
      manual(f.path, `not a file pipegen creates there (no created-file rule of its part claims the path, and it isn't one of pipegen's workflows${roots}), so pipegen never removes it`, 'Review it and remove it by hand if you don\'t want it.');
      continue;
    }
    const e = entries.get(f.path);
    if (e === undefined) {
      if (inA) skip(f.path, 'it is no longer on the default branch: nothing to remove');
      else markDone(`${show(f.path, 200)}: not on the default branch`);
      continue;
    }
    if (!plainFile(e)) { manual(f.path, 'it is not a plain file now (a link or a submodule), so pipegen leaves it'); judged.push({ f, claim, state: 'held', changed: true }); continue; }
    if (f.ownerEdited === true) {
      manual(f.path, '`pipegen update` merged its change into your edits, so the file is yours now; pipegen never removes it', 'Review it and take out pipegen\'s parts by hand if you don\'t want them.');
      judged.push({ f, claim, state: 'held', changed: true });
      continue;
    }
    if (!inA) {
      // run 2 asks no file question: the file is still there (kept in run 1, or the uninstall PR isn't merged)
      skip(f.path, 'it is still on the default branch (you kept it in the first run, or the uninstall pull request is not merged yet), so pipegen leaves it');
      judged.push({ f, claim, state: 'held', changed: false });
      continue;
    }
    const changed = !f.shas.includes(e.sha);
    judged.push({ f, claim, state: f.adopted === true || changed || KEEP_KINDS.has(claim) ? 'ask' : 'remove', changed });
  }
  const remove = (path: string): void => { u.removeFiles.push({ repo: 'app', path }); };
  const answer = (j: Judged, keep: boolean, why: string, pair?: string): void => {
    u.keepAsk.push({ path: j.f.path, ...(pair === undefined ? {} : { pair }), keep, why });
    if (!keep) remove(j.f.path);
  };
  const whyOf = (j: Judged): string => (j.f.adopted === true ? 'pipegen found it as it is (adopted), so it never proved it created it' : j.changed ? 'it changed since pipegen wrote it' : 'the team may want to keep it');
  const done = new Set<Judged>();
  // the Dockerfile and its .dockerignore: one question; one held by anything else keeps the other
  const dirOf = (p: string): string => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  for (const df of judged.filter((j) => j.claim === 'dockerfile')) {
    const di = judged.find((j) => j.claim === 'dockerignore' && dirOf(j.f.path) === dirOf(df.f.path));
    if (di === undefined) continue;
    done.add(df);
    done.add(di);
    if (df.state === 'held' || di.state === 'held') {
      for (const [a, b] of [[df, di], [di, df]] as const) if (a.state !== 'held') skip(a.f.path, `kept with ${b.f.path}, which pipegen leaves (they go together)`);
      continue;
    }
    const notes = [df, di].filter((j) => j.changed || j.f.adopted === true).map((j) => `${j.f.path}: ${whyOf(j)}`);
    const keep = await ask(`Keep ${show(df.f.path)} and ${show(di.f.path)}? They go together.${notes.length > 0 ? ` (${show(notes.join('; '), 300)})` : ''} (Y/n)`, true);
    answer(df, keep, whyOf(df), di.f.path);
    answer(di, keep, whyOf(di), df.f.path);
  }
  // the starter tests: one question (an adopted one is asked on its own)
  const tests = judged.filter((j) => j.claim === 'starter-tests' && j.state === 'ask' && j.f.adopted !== true && !done.has(j));
  if (tests.length > 0) {
    for (const j of tests) done.add(j);
    const names = tests.map((j) => j.f.path);
    const changedNames = tests.filter((j) => j.changed).map((j) => j.f.path);
    const keep = await ask(`Keep the starter tests (${show(names.slice(0, 10).join(', '), 400)}${names.length > 10 ? `, and ${names.length - 10} more` : ''})?${changedNames.length > 0 ? ` ${show(changedNames.join(', '), 200)} changed since pipegen wrote ${changedNames.length === 1 ? 'it' : 'them'}.` : ''} Their package.json and lock changes stay with them. (Y/n)`, true);
    for (const j of tests) answer(j, keep, whyOf(j));
  }
  for (const j of judged) {
    if (done.has(j) || j.state === 'held') continue;
    if (j.state === 'remove') { remove(j.f.path); continue; }
    if (j.f.adopted === true) {
      const del = await ask(`pipegen found ${show(j.f.path)} as it is; delete it? (y/N)`, false);
      answer(j, !del, whyOf(j));
    } else {
      answer(j, await ask(`Keep ${show(j.f.path)}?${j.changed ? ' It changed since pipegen wrote it.' : ''} (Y/n)`, true), whyOf(j));
    }
  }
  const testsKept = judged.some((j) => j.claim === 'starter-tests' && (j.state === 'held' || u.keepAsk.some((k) => k.path === j.f.path && k.keep)));

  // ---------- 2. pipegen's edits inside files it didn't write whole (V2) ----------
  const appEdits = typedTrust ? [] : rec.edits.filter((e) => e.repo === 'app');
  const keptPkg: InstallEdit[] = testsKept ? appEdits.filter((e) => e.kind === 'package-json' || e.kind === 'package-lock') : [];
  for (const e of keptPkg) skip(e.path, 'kept with the starter tests you keep (they need its change)');
  const toRevert = appEdits.filter((e) => !keptPkg.includes(e));
  if (!inA) await doneEdits(toRevert);
  else if (toRevert.length > 0) {
    const current = new Map<string, CurrentFile | null>();
    for (const e of toRevert) {
      const t = entries.get(e.path);
      const text = plainFile(t) ? await readBlob(t.sha) : null;
      current.set(e.path, text === null || t === undefined ? null : { text, sha: t.sha });
      await readBlob(e.originalSha);
      await readBlob(e.writtenShas[e.writtenShas.length - 1]);
    }
    u.reverts = revertEdits(toRevert, (e) => current.get(e.path) ?? null, (sha) => blobs.get(sha) ?? null, { defaultBranch: loaded.app.defaultBranch });
  }
  // V-N12: a hook block the record has no entry for
  for (const path of Object.values(HOOK_FILES)) {
    const t = entries.get(path);
    if (!plainFile(t) || appEdits.some((e) => e.kind === 'hooks' && e.path === path)) continue;
    const text = await readBlob(t.sha);
    if (text !== null && text.includes(HOOKS_MARKER)) manual(path, `pipegen's hook block may still be in ${show(path)} (the install record has no entry for it)`, `Remove the lines between pipegen's ${HOOKS_MARKER} markers by hand if you don't want them.`);
  }
  // V-N11: pipegen's verify job or head check in a workflow the record doesn't list
  const listed = new Set([...rec.files.filter((f) => f.repo === 'app').map((f) => f.path), ...appEdits.filter((e) => e.kind === 'verify-job').map((e) => e.path)]);
  const others = [...entries].filter(([p, t]) => WORKFLOW_RE.test(p) && !listed.has(p) && plainFile(t));
  if (others.length > MAX_SCANNED) manual('.github/workflows', `there are more than ${MAX_SCANNED} workflows, too many for pipegen to check for its verify job (${VERIFY_JOB_ID}) and head check (${HEAD_CHECK_STEP_ID})`, 'Search your workflows for them and take them out by hand.');
  else {
    for (const [p, t] of others) {
      const text = await readBlob(t.sha);
      if (text !== null && (text.includes(VERIFY_JOB_ID) || text.includes(HEAD_CHECK_STEP_ID))) {
        manual(p, `it holds ${VERIFY_JOB_ID} or pipegen's head check (${HEAD_CHECK_STEP_ID}), which the install record doesn't list there`, `Review it and take pipegen's job and step out by hand.`);
      }
    }
  }

  // ---------- 3. central: the exact file list and whether this is the last project ----------
  const centralTree = await readTree(gh, central, loaded.centralHead, clock);
  const own = centralFilesOf(appRef.repo);
  const rp = recordPath(appRef.repo);
  const claimed = new Set<string>();
  for (const f of rec.files) {
    if (f.repo !== 'central') continue;
    const what = `central ${show(f.path, 200)}`;
    if (rec.centralSha === null) manual(what, `a public app keeps no workflow in ${CENTRAL_REPO} (records only), so it is not one of this project's central files; pipegen leaves it`);
    else if (!own.includes(f.path) || createdPathProblem(f.path) !== null) manual(what, 'it is not one of this project\'s central files (the exact list), so pipegen leaves it');
    else if (!centralTree.entries.has(f.path)) skip(what, `it is no longer in ${CENTRAL_REPO}: nothing to remove`);
    else claimed.add(f.path);
  }
  u.centralFiles = [...own.filter((p) => claimed.has(p)), rp];
  const otherRecords = [...centralTree.entries.keys()].filter((p) => /^installs\/[^/]+\.json$/.test(p) && p !== rp);
  const otherFiles = [...centralTree.entries.keys()].filter((p) => CENTRAL_LAYER_RE.test(p) && !own.includes(p));
  // a central PR is this project's only on its exact branch, from the recorded central repo itself (never a fork's PR of the same name)
  const updateBranch = centralUpdateBranch(appRef.repo);
  const mine = new Set([updateBranch, uninstallBranch(targetApp, 'central')]);
  const ownHead = (p: Record<string, unknown>, branches: ReadonlySet<string>): boolean => isObj(p.head) && typeof p.head.ref === 'string' && branches.has(p.head.ref) && isObj(p.head.repo) && p.head.repo.id === loaded.centralRepoId;
  // every open central PR, page by page (M-r1-3): a page that can't be read, or more pages than pipegen reads → null (not the last project)
  const centralPrs = await (async (): Promise<unknown[] | null> => {
    const all: unknown[] = [];
    for (let page = 1; page <= MAX_PR_PAGES; page += 1) {
      const l = await live('GET /repos/{owner}/{repo}/pulls', { ...central, state: 'open', per_page: 100, page });
      if (!('data' in l) || !Array.isArray(l.data)) return null;
      all.push(...l.data);
      if (l.data.length < 100) return all;
    }
    return null;
  })();
  const otherPrs = centralPrs === null ? null : centralPrs.filter((p) => !(isObj(p) && ownHead(p, mine)));
  u.lastProject = otherRecords.length === 0 && otherFiles.length === 0 && otherPrs !== null && otherPrs.length === 0;
  if (u.lastProject && !typedTrust && rec.central !== undefined) u.centralLocks = rec.central;
  if (!inA) await planRepos();

  // ---------- 4. the merge locks: rulesets, the org rule, classic protection (run 1; run 2 checks them done) ----------
  if (!inA) await doneLocks();
  else for (const r of rec.rulesets) {
    const what = `ruleset ${show(r.name, 100)} (id ${r.id})`;
    const n = await classify({ kind: 'ruleset', entry: r }, what, { route: 'GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', params: { ...appRef, ruleset_id: r.id } }, false, { when: 'A' });
    if (n !== null) u.deleteRulesets.push({ kind: r.kind, id: r.id, entry: r, ...n });
  }
  if (inA && !typedTrust && rec.orgRuleset !== undefined) {
    const e = rec.orgRuleset;
    const what = `org ruleset ${show(e.name, 100)} (id ${e.id})`;
    // the pinned central repo is GitHub's, and only when it is the recorded one (V3 checks it again before the delete)
    const cid = centralRepoId === undefined || centralRepoId === loaded.centralRepoId ? loaded.centralRepoId : undefined;
    const n = lower(e.org) !== lower(appRef.owner)
      ? (skip(what, `it names the organisation ${show(e.org, 40)}, not ${show(appRef.owner, 40)}`), null)
      : await classify({ kind: 'org-ruleset', entry: e, ...(cid === undefined ? {} : { centralRepoId: cid }) }, what, { route: 'GET /orgs/{org}/rulesets/{ruleset_id}', params: { org: e.org, ruleset_id: e.id } }, false, { when: 'A', gone: ORG_GONE });
    if (n !== null) u.deleteOrgRuleset = { org: e.org, id: e.id, entry: e, ...n };
  }
  if (inA && !typedTrust && rec.classicProtection !== undefined) await planClassic(rec.classicProtection, rec.planned.classic);

  // ---------- 5. secrets (the record's, then the leftovers'), variables, environments ----------
  const secretWhat = (s: { name: string; scope: string }): string => `secret ${show(s.name, 100)}${s.scope === 'repo' ? '' : s.scope === 'central' ? ` (${CENTRAL_REPO})` : ` (environment ${show(s.scope.slice(4), 100)})`}`;
  const secretRead = (s: SecretEntry): { route: string; params: Record<string, unknown> } => {
    if (s.scope === 'repo' || s.scope === 'central') return { route: 'GET /repos/{owner}/{repo}/actions/secrets/{secret_name}', params: { ...(s.scope === 'repo' ? appRef : central), secret_name: s.name } };
    return { route: 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', params: { ...appRef, environment_name: s.scope.slice(4), secret_name: s.name } };
  };
  const planSecret = async (s: SecretEntry, leftover: boolean): Promise<void> => {
    const what = secretWhat(s);
    if (s.overwritten === true) { skip(what, 'pipegen replaced its value; the old value is gone, and the secret was there before pipegen, so pipegen never deletes it'); return; }
    if (s.created !== true) { skip(what, 'pipegen didn\'t create it, so it never deletes it'); return; }
    if (s.scope === 'central' && !u.lastProject) { skip(what, `other projects of ${CENTRAL_REPO} may use it; pipegen deletes a central secret only with the last project`); return; }
    const why = leftover ? 'pipegen stored it before a delivery stopped (this machine\'s leftovers file lists it); pipegen can\'t tell whether it created it or only replaced the value of one that was there.' : undefined;
    const n = await classify({ kind: 'secret', entry: s }, what, secretRead(s), leftover || !s.name.startsWith('PIPEGEN_'), { when: 'B', ...(why === undefined ? {} : { why }) });
    if (n !== null) u.deleteSecrets.push({ secret: s, ...(leftover ? { fromLeftovers: true as const } : {}), ...n });
  };
  for (const s of rec.secrets) await planSecret(s, false);
  let leftovers: Leftover[];
  try { leftovers = await readLocalLeftovers(appRef, deps.local ?? {}); } catch (e) {
    if (e instanceof RecordError) throw new UninstallError(`${e.message} pipegen won't guess what it lists: move it away (or fix it), then run \`npx pipegen uninstall\` again. Nothing was changed.`, { cause: e });
    throw e;
  }
  const ours = leftovers.filter((x) => {
    if (lower(x.repo) === lower(full)) return true;
    skip(`${x.kind === 'secret' ? secretWhat({ name: x.name, scope: x.scope ?? 'repo' }) : `${x.kind} ${show(x.name, 100)}`} (leftovers file)`, `it is listed for another repo (${show(x.repo, 140)}), so pipegen leaves it`);
    return false;
  });
  const leftSecrets: SecretEntry[] = [];
  for (const x of ours.filter((y) => y.kind === 'secret')) {
    const scope = x.scope ?? 'repo';
    if (rec.secrets.some((s) => s.name === x.name && s.scope === scope)) continue;   // the record's entry decides
    if (scope !== 'repo' && !/^env:.+$/.test(scope)) { skip(`${secretWhat({ name: x.name, scope })} (leftovers file)`, 'its scope is not one pipegen stores secrets in'); continue; }
    if (!isoAt(x.githubCreatedAt)) {
      // deliver records a secret whose value it replaced with no creation date: it may be the user's own (V4-R1 sec I1)
      manual(`${secretWhat({ name: x.name, scope })} (leftovers file)`, 'pipegen may only have replaced the value of a secret you already had: the leftovers file holds no creation date to prove pipegen made it, so pipegen never deletes it', 'Check it, and delete it by hand if pipegen created it.');
      continue;
    }
    const entry = { name: x.name, scope: scope as SecretEntry['scope'], created: true, githubCreatedAt: x.githubCreatedAt } as SecretEntry;
    leftSecrets.push(entry);
    await planSecret(entry, true);
  }

  for (const v of rec.variables) {
    const scopeText = v.scope === 'repo' ? '' : ` (environment ${show(v.scope.slice(4), 100)})`;
    const what = `variable ${show(v.name, 100)}${scopeText}`;
    if (v.created) {
      const read = v.scope === 'repo'
        ? { route: 'GET /repos/{owner}/{repo}/actions/variables/{name}', params: { ...appRef, name: v.name } }
        : { route: 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables/{name}', params: { ...appRef, environment_name: v.scope.slice(4), name: v.name } };
      const n = await classify({ kind: 'variable', entry: v }, what, read, !v.name.startsWith('PIPEGEN_'), { when: 'B' });
      if (n !== null) u.deleteVariables.push({ name: v.name, scope: v.scope, entry: v, ...n });
      continue;
    }
    if (typedTrust || typeof v.previous !== 'string') { skip(what, 'pipegen didn\'t create it and has no earlier value of it, so it leaves it as it is'); continue; }
    if (v.scope !== 'repo') {
      manual(what, 'pipegen changed its value, and uninstall has no way to put an environment\'s variable back', `gh variable set ${show(v.name, 100)} --env ${show(v.scope.slice(4), 100)} --repo ${show(full)} --body <the value before pipegen, from the install record>`);
      continue;
    }
    const pipegenValue = v.name === 'PIPEGEN_BLOCK_FROM' ? rec.blockFrom : v.name === 'PIPEGEN_COSIGN_PUB' ? rec.cosignPub : undefined;
    if (typeof pipegenValue !== 'string') { skip(what, 'pipegen doesn\'t know the value it set, so it can\'t tell whether you changed it since; it leaves it as it is'); continue; }
    const l = await live('GET /repos/{owner}/{repo}/actions/variables/{name}', { ...appRef, name: v.name });
    if ('missing' in l) { if (l.manual) manual(what, l.missing); else skip(what, l.missing); continue; }
    if (!isObj(l.data) || l.data.value !== pipegenValue) { skip(what, 'it no longer holds the value pipegen set (changed since), so pipegen leaves it'); continue; }
    if (!askable(v.name)) { manual(what, CANT_ASK); continue; }
    if (inA) { u.restoreVariables.push({ name: v.name, scope: v.scope, previous: v.previous, pipegenValue, entry: v, confirmedByName: false, needsName: true }); continue; }
    const t = await confirm({ kind: 'variable-restore', entry: v }, `pipegen would put the variable ${show(v.name, 100)} back to the value it had before pipegen (the value is not shown).`);
    if (t === null) { skip(what, NOT_TYPED); continue; }
    u.restoreVariables.push({ name: v.name, scope: v.scope, previous: v.previous, pipegenValue, entry: v, confirmedByName: true, typed: t });
  }

  /** V-S5: an environment holds nothing this plan doesn't delete (its secrets and variables, listed now); else the reason to keep it. */
  const foreignIn = async (name: string): Promise<string | null> => {
    const scope = lower(`env:${name}`);
    const foreign: string[] = [];
    for (const x of [{ kind: 'secret', route: 'GET /repos/{owner}/{repo}/environments/{environment_name}/secrets', key: 'secrets' }, { kind: 'variable', route: 'GET /repos/{owner}/{repo}/environments/{environment_name}/variables', key: 'variables' }] as const) {
      const l = await live(x.route, { ...appRef, environment_name: name, per_page: 100 });
      const d = 'data' in l ? l.data : null;
      const list = isObj(d) && Array.isArray(d[x.key]) ? (d[x.key] as unknown[]).filter(isObj) : null;
      if (list === null || !isObj(d) || typeof d.total_count !== 'number' || d.total_count > list.length) return `pipegen couldn't list every ${x.kind} in it, so it doesn't delete it (deleting an environment deletes what is in it)`;
      for (const item of list) {
        const n = typeof item.name === 'string' ? item.name : '';
        const planned = x.kind === 'secret'
          ? u.deleteSecrets.some((s) => lower(s.secret.scope) === scope && lower(s.secret.name) === lower(n))
          : u.deleteVariables.some((v) => lower(v.scope) === scope && lower(v.name) === lower(n));
        if (!planned) foreign.push(show(n === '' ? '(no name)' : n, 100));
      }
    }
    return foreign.length === 0 ? null : `it holds ${foreign.slice(0, 20).join(', ')}${foreign.length > 20 ? ', …' : ''}, which pipegen doesn't delete (it didn't add them, or can't prove it did); deleting the environment would delete them too, so pipegen leaves it`;
  };
  const planEnvDelete = async (e: EnvEntry, leftover: boolean): Promise<void> => {
    const what = `environment ${show(e.name, 100)}`;
    const held = environmentOwned({ secrets: [...rec.secrets, ...leftSecrets], variables: rec.variables }, e);
    const why = leftover ? 'pipegen made it before a delivery stopped (this machine\'s leftovers file lists it).' : undefined;
    const n = await classify(held, what, { route: 'GET /repos/{owner}/{repo}/environments/{environment_name}', params: { ...appRef, environment_name: e.name } }, leftover || !e.name.startsWith('pipegen-'), { when: 'B', ...(why === undefined ? {} : { why }), check: () => foreignIn(e.name) });
    if (n !== null) u.deleteEnvironments.push({ name: e.name, entry: e, owned: held, ...n });
  };
  for (const e of rec.environments) {
    if (e.created) await planEnvDelete(e, false);
    else if (typedTrust) skip(`environment ${show(e.name, 100)}`, 'pipegen didn\'t create it, so it never deletes it');
    else await planEnvRestore(e);
  }
  for (const x of ours.filter((y) => y.kind === 'environment')) {
    if (rec.environments.some((e) => e.name === x.name)) continue;   // the record's entry decides
    if (x.previous === undefined) {
      if (!isoAt(x.githubCreatedAt)) {
        manual(`environment ${show(x.name, 100)} (leftovers file)`, 'the leftovers file holds no creation date for it, so pipegen can\'t prove it made it (it may be one you already had); pipegen never deletes it', 'Check it, and delete it by hand if pipegen created it.');
        continue;
      }
      await planEnvDelete({ name: x.name, created: true, changed: [], branchPolicyIds: [], githubCreatedAt: x.githubCreatedAt }, true);
      continue;
    }
    // G10-R3 N3: an existing environment pipegen narrowed; the same data as a record entry, to confirm
    const changed = Array.isArray(x.changed) ? x.changed : [];
    await planEnvRestore({ name: x.name, created: false, previous: x.previous as unknown as EnvSettings, changed: changed as (keyof EnvSettings)[], branchPolicyIds: [], ...(isoAt(x.githubCreatedAt) ? { githubCreatedAt: x.githubCreatedAt } : {}) });
  }
  for (const x of ours.filter((y) => y.kind === 'branch' || y.kind === 'pull-request')) {
    const handled = x.kind === 'branch' ? u.deleteBranches.some((b) => b.branch === x.name) : u.closePrs.some((p) => `#${p.number}` === x.name);
    if (!handled) skip(`${x.kind === 'branch' ? 'branch' : 'pull request'} ${show(x.name, 100)} (leftovers file)`, 'pipegen looks at its own branch and pull requests on GitHub (below), not at this list');
  }

  // ---------- 6. settings pipegen turned on (V-S6): asked, default keep ----------
  if (!typedTrust && rec.repoSettings !== undefined) {
    for (const key of SETTING_KEYS) {
      const s = rec.repoSettings[key];
      if (s === undefined) continue;
      if (s.previous === true) { skip(`setting ${SETTING_LABEL[key]}`, 'it was on before pipegen: nothing to turn back'); continue; }
      if (s.previous !== false) continue;
      // run 1 asks nothing about settings: the preview says run 2 will
      if (inA) { u.settings.push({ key, previous: false, turnOff: false, confirmedByName: false }); continue; }
      let turnOff = await ask(`Turn off ${SETTING_LABEL[key]}? (y/N)`, false);
      let named = false;
      if (turnOff && loaded.typedNames) {
        named = await typedPlain(key, `pipegen would turn off ${SETTING_LABEL[key]} in ${show(full)}. This run asks each name: the install record was trusted by typing, or its marker in the setup pull request differs.`);
        if (!named) { turnOff = false; skip(`setting ${SETTING_LABEL[key]}`, NOT_TYPED); }
      }
      u.settings.push({ key, previous: false, turnOff, confirmedByName: named });
    }
  }

  // ---------- 7. pipegen's open pull requests, and an unfinished install (V-S4) ----------
  let setupMerged: boolean | null = null;
  let setupClosed = false;
  if (loaded.setupPr !== null) {
    const l = await live('GET /repos/{owner}/{repo}/pulls/{pull_number}', { ...appRef, pull_number: loaded.setupPr });
    if ('data' in l && isObj(l.data)) {
      setupMerged = typeof l.data.merged_at === 'string' && l.data.merged_at !== '';
      setupClosed = l.data.state === 'closed';
    }
  }
  // V4-R1: unfinished (nothing to wait for) only when none of pipegen's own workflows is on the default branch, and (full trust) the
  // record has no mergedAt; a setup PR closed unmerged with the workflows live (copied over by hand) still takes two runs
  let workflowsLive = rec.files.some((f) => f.repo === 'app' && APP_WORKFLOWS.includes(f.path) && f.adopted !== true && plainFile(entries.get(f.path)));
  // M-r1-4: pipegen's verify job or head check still in a workflow it edited runs too (pipegen.yml may have been removed by hand);
  // a blob that can't be read counts as live (two runs, the safe side)
  for (const e of rec.edits) {
    if (workflowsLive) break;
    if (e.repo !== 'app' || e.kind !== 'verify-job') continue;
    const t = entries.get(e.path);
    if (!plainFile(t)) continue;
    const text = await readBlob(t.sha);
    if (text === null || text.includes(VERIFY_JOB_ID) || text.includes(HEAD_CHECK_STEP_ID)) workflowsLive = true;
  }
  u.unfinished = !workflowsLive && (typedTrust || rec.mergedAt === undefined) && setupMerged !== true;
  if (setupMerged === false && setupClosed && workflowsLive) {
    u.warnings.push(`The setup pull request #${loaded.setupPr} was closed without merging, but pipegen's workflows are on ${show(loaded.app.defaultBranch, 100)}: pipegen uninstalls them through the uninstall pull request, in two runs.`);
  }
  for (const branch of [SETUP_BRANCH, UPDATE_BRANCH]) {
    const l = await live('GET /repos/{owner}/{repo}/pulls', { ...appRef, head: `${appRef.owner}:${branch}`, state: 'open', per_page: 100 });
    const prs = 'data' in l && Array.isArray(l.data) ? l.data.filter(isObj) : [];
    for (const p of prs) {
      const n = p.number;
      if (!(typeof n === 'number' && Number.isSafeInteger(n) && n > 0) || p.state !== 'open' || !isObj(p.head) || p.head.ref !== branch || !isObj(p.head.repo) || p.head.repo.id !== loaded.app.repoId) continue;
      if (u.closePrs.some((x) => x.number === n)) continue;
      if (!inA) { manual(`pull request #${n} (${branch})`, 'it is still open: the first run didn\'t close it', 'Close it on GitHub if you don\'t need it.'); continue; }
      let named = false;
      if (loaded.typedNames) {
        named = await typedPlain(branch, `pipegen would close its pull request #${n} (branch ${branch}) in ${show(full)}. This run asks each name: the install record was trusted by typing, or its marker in the setup pull request differs.`);
        if (!named) { skip(`pull request #${n} (${branch})`, NOT_TYPED); continue; }
      }
      u.closePrs.push({ repo: 'app', number: n, branch, confirmedByName: named });
    }
  }
  // the central update PR of this project (spec I2): exact branch, opened from the recorded central repo itself; the record names no author,
  // so its number is always typed
  const recordedCentral = centralRepoId === undefined || centralRepoId === loaded.centralRepoId;
  for (const p of centralPrs ?? []) {
    if (!recordedCentral || !isObj(p) || p.state !== 'open' || !ownHead(p, new Set([updateBranch]))) continue;
    const n = p.number;
    if (!(typeof n === 'number' && Number.isSafeInteger(n) && n > 0)) continue;
    const what = `pull request #${n} (${updateBranch}) in ${show(`${central.owner}/${central.repo}`)}`;
    if (!inA) { manual(what, 'it is still open: the first run didn\'t close it', 'Close it on GitHub if you don\'t need it.'); continue; }
    const named = await typedPlain(String(n), `pipegen would close its pull request #${n} (branch ${updateBranch}) in ${show(`${central.owner}/${central.repo}`)}. The install record doesn't say who opened it, so pipegen asks for its number.`);
    if (!named) { skip(what, NOT_TYPED); continue; }
    u.closePrs.push({ repo: 'central', number: n, branch: updateBranch, confirmedByName: true });
  }
  if (inA && u.unfinished) {
    const head = await readHead(gh, appRef, SETUP_BRANCH, clock);
    if (head !== null) {
      const foreign = await foreignOnSetup(head);
      if (foreign.length > 0) {
        manual(`branch ${SETUP_BRANCH}`, `it holds changes pipegen didn't make (${show(foreign.slice(0, 10).join(', '), 300)}${foreign.length > 10 ? ', …' : ''}), so pipegen keeps it`, 'Look at the branch, keep what you need, then delete it by hand.');
      } else {
        let named = false;
        if (loaded.typedNames) {
          named = await typedPlain(SETUP_BRANCH, `pipegen would delete its branch ${SETUP_BRANCH} in ${show(full)} (it holds only pipegen's files). This run asks each name: the install record was trusted by typing, or its marker in the setup pull request differs.`);
          if (!named) skip(`branch ${SETUP_BRANCH}`, NOT_TYPED);
        }
        if (named || !loaded.typedNames) u.deleteBranches.push({ repo: 'app', branch: SETUP_BRANCH, head, confirmedByName: named });
      }
    }
  }
  return u;

  /** The paths pipegen/setup (at `head`) changes that are not a version pipegen recorded writing (an empty list: all pipegen's). */
  async function foreignOnSetup(head: string): Promise<string[]> {
    let d: unknown;
    try { d = await ghRead(gh, 'GET /repos/{owner}/{repo}/compare/{basehead}', appRef, { basehead: `${loaded.app.defaultBranch}...${head}` }, clock); } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      return ['(GitHub couldn\'t compare it with the default branch)'];
    }
    const files = isObj(d) && Array.isArray(d.files) ? d.files.filter(isObj) : null;
    if (files === null || files.length >= 300) return ['(GitHub didn\'t list every change on it)'];
    const tree = await readTree(gh, appRef, head, clock);
    const out: string[] = [];
    for (const f of files) {
      const p = typeof f.filename === 'string' ? f.filename : '';
      const e = tree.entries.get(p);
      // only a path pipegen creates (a created-file rule claims it) or edits (full trust) counts as pipegen's (sec M5)
      const shas = [...rec.files.filter((x) => x.repo === 'app' && x.path === p && claimOf(x) !== null).flatMap((x) => x.shas), ...(typedTrust ? [] : rec.edits.filter((x) => x.repo === 'app' && x.path === p).flatMap((x) => x.writtenShas))];
      if (p === '' || typeof f.previous_filename === 'string' || e === undefined || !shas.includes(e.sha)) out.push(p === '' ? '(a change with no name)' : p);
    }
    return out;
  }

  /**
   * Phase B (M-r1-9, V-S3): the scratch repo run 2 empties (GitHub's answer now: the exact name and pipegen's marker; a typed trust doesn't
   * vouch for the scratch facts, a manual step then) and, with --delete-repos, the repos it deletes or the commands it prints.
   */
  async function planRepos(): Promise<void> {
    const scratchName = `${SCRATCH_PREFIX}${appRef.repo}`;
    const scratchFull = `${appRef.owner}/${scratchName}`;
    const app = deps.canDeleteRepos === true;
    if (!typedTrust) {
      let d: unknown = null;
      try { d = (await githubRead(gh, 'GET /repos/{owner}/{repo}', { owner: appRef.owner, repo: scratchName }, clock)).data; } catch (e) {
        if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401 || statusOf(e) === undefined) throw e;
        if (statusOf(e) !== 404) manual(`scratch repo ${scratchFull}`, `GitHub refused to show it (HTTP ${statusOf(e)}), so pipegen can't tell it is the one it made`, 'Check it on GitHub and delete it by hand if pipegen made it.');
      }
      if (isObj(d)) {
        const id = d.id;
        if (d.full_name !== scratchFull || !isObj(d.owner) || d.owner.login !== appRef.owner || d.description !== SCRATCH_MARKER || !(typeof id === 'number' && Number.isSafeInteger(id) && id > 0)) {
          skip(`scratch repo ${scratchFull}`, 'it doesn\'t carry pipegen\'s marker (its description), so pipegen leaves it');
        } else u.scratch = { repo: scratchFull, id };
      }
    }
    if (deps.deleteRepos !== true) return;
    const sc = rec.scratch;
    // V6-R1 sec I1: token mode (the command only) passes the same gates as the App's delete
    const how = app ? 'delete' as const : 'command' as const;
    const check = 'Check it on GitHub; delete it by hand only if it is the one pipegen made.';
    if (u.scratch !== undefined) {
      if (sc?.createdByPipegen === true && sc.repoId === u.scratch.id) u.deleteRepos.push({ repo: scratchFull, kind: 'scratch', how });
      else manual(`repo ${scratchFull}`, sc?.repoId === undefined ? 'the install record holds no id of the scratch repo pipegen created, so pipegen only empties it' : 'it is not the scratch repo pipegen created (GitHub\'s id differs from the recorded one), so pipegen only empties it', check);
    }
    const centralFull = `${appRef.owner}/${CENTRAL_REPO}`;
    const c = rec.central;
    if (!u.lastProject) { skip(`repo ${centralFull}`, 'other projects use it (or pipegen can\'t tell none does), so pipegen keeps it'); return; }
    if (typedTrust) return;   // TYPED_MANUAL: central facts are not granted
    if (c?.createdByPipegen !== true) { skip(`repo ${centralFull}`, 'the install record doesn\'t say pipegen created it, so pipegen never deletes it'); return; }
    if (c.repoId === undefined) { manual(`repo ${centralFull}`, 'the install record holds no id of it, so pipegen can\'t prove it is the repo it created; it keeps it', check); return; }
    if (c.repoId !== loaded.centralRepoId) { skip(`repo ${centralFull}`, 'it is not the repo pipegen created (GitHub\'s id differs from the recorded one), so pipegen keeps it'); return; }
    u.deleteRepos.push({ repo: centralFull, kind: 'central', how, afterCentralPr: true });
  }

  /**
   * Phase B: each edit as run 1 left it. Done: the file is its original version (or gone, when pipegen made it), or pipegen's text is out
   * of it. Anything else is a manual step (pipegen never reverts in run 2), never a new action.
   */
  async function doneEdits(list: InstallEdit[]): Promise<void> {
    for (const e of list) {
      const p = show(e.path, 200);
      const t = entries.get(e.path);
      if (t === undefined) {
        if (e.originalSha === null) markDone(`${p}: removed`);
        else manual(e.path, 'it is gone from the default branch, but it was there before pipegen, so pipegen can\'t put it back', 'Restore it from your history if you need it.');
        continue;
      }
      if (!plainFile(t)) { manual(e.path, 'it is not a plain file now (a link or a submodule), so pipegen leaves it'); continue; }
      if (t.sha === e.originalSha) { markDone(`${p}: back to its version before pipegen`); continue; }
      const text = await readBlob(t.sha);
      let still: boolean | null = null;
      if (text === null) still = null;
      else if (e.kind === 'codeowners' || e.kind === 'hooks' || e.kind === 'dependabot') still = e.inserted === '' ? null : text.includes(e.inserted);
      else if (e.kind === 'verify-job') still = text.includes(VERIFY_JOB_ID) || text.includes(HEAD_CHECK_STEP_ID);
      if (still === false) { markDone(`${p}: pipegen's exact text is no longer in it`); continue; }
      manual(e.path, still === true ? 'pipegen\'s change is still in it (the first run didn\'t take it out, or the uninstall pull request is not merged yet)' : 'pipegen can\'t tell whether its change is still in it', 'Take pipegen\'s change out by hand, or merge the uninstall pull request and run `pipegen uninstall` again.');
    }
  }

  /** Phase B: the merge locks as run 1 left them: gone (done), still pipegen's (manual), or changed since (left). */
  async function doneLocks(): Promise<void> {
    const step = 'Delete it by hand, or run `pipegen uninstall` again from the first run.';
    for (const r of rec.rulesets) {
      const what = `ruleset ${show(r.name, 100)} (id ${r.id})`;
      const l = await live('GET /repos/{owner}/{repo}/rulesets/{ruleset_id}', { ...appRef, ruleset_id: r.id });
      if ('missing' in l) { if (l.manual) manual(what, l.missing); else markDone(`${what}: ${GONE}`); continue; }
      const v = isPipegens({ kind: 'ruleset', entry: r }, l.data, targetApp);
      if (v.is === 'no') skip(what, v.why);
      else manual(what, 'it is still there: the first run didn\'t delete it', step);
    }
    if (!typedTrust && rec.orgRuleset !== undefined) {
      const e = rec.orgRuleset;
      const what = `org ruleset ${show(e.name, 100)} (id ${e.id})`;
      if (lower(e.org) !== lower(appRef.owner)) skip(what, `it names the organisation ${show(e.org, 40)}, not ${show(appRef.owner, 40)}`);
      else {
        const l = await live('GET /orgs/{org}/rulesets/{ruleset_id}', { org: e.org, ruleset_id: e.id }, ORG_GONE);
        if ('missing' in l) { if (l.manual) manual(what, l.missing); else skip(what, l.missing); }
        else {
          const v = isPipegens({ kind: 'org-ruleset', entry: e }, l.data, targetApp);
          if (v.is === 'no') skip(what, v.why);
          else manual(what, 'it is still there: the first run didn\'t delete it', step);
        }
      }
    }
    const cp = typedTrust ? undefined : rec.classicProtection;
    if (cp === undefined) return;
    const what = `branch protection of ${show(cp.branch, 100)}`;
    const back = `Check Settings → Branches of ${show(full)} and put the protection of ${show(cp.branch, 100)} back as you want it (the install record holds what it was before pipegen).`;
    const l = await live('GET /repos/{owner}/{repo}/branches/{branch}/protection', { ...appRef, branch: cp.branch });
    if ('missing' in l) {
      if (l.manual) manual(what, l.missing, back);
      else if (cp.previous === null) markDone(`${what}: taken off (there was none before pipegen)`);
      else manual(what, 'GitHub shows no protection on it now, but there was one before pipegen', back);
      return;
    }
    const now = classicPutForm(l.data);
    const extra = droppedLiveField(l.data);
    const planned = rec.planned.classic;
    if (extra === null && cp.previous !== null && exactlyAsSet(cp.previous, now)) { markDone(`${what}: back as it was before pipegen`); return; }
    if (extra === null && planned !== undefined && isObj(planned.body) && exactlyAsSet(planned.body, now)) { manual(what, 'it is still as pipegen set it: the first run didn\'t put it back', back); return; }
    skip(what, 'it changed since pipegen set it, so pipegen leaves it as it is');
  }

  /** V-B3: classic protection put back from `previous` (null: taken off), only while it is exactly as pipegen set it; the typed branch name. */
  async function planClassic(cp: NonNullable<InstallRecord['classicProtection']>, planned: RecordApiRequest | undefined): Promise<void> {
    const what = `branch protection of ${show(cp.branch, 100)}`;
    const step = `Check Settings → Branches of ${show(full)} and put the protection of ${show(cp.branch, 100)} back as you want it (the install record holds what it was before pipegen).`;
    const l = await live('GET /repos/{owner}/{repo}/branches/{branch}/protection', { ...appRef, branch: cp.branch });
    if ('missing' in l) {
      if (!l.manual && cp.previous === null) { skip(what, 'GitHub shows no protection on it now (taken off since), so there is nothing to take off'); return; }
      manual(what, l.manual ? l.missing : 'it is gone (taken off since pipegen set it), and pipegen doesn\'t create it again', step);
      return;
    }
    const now = classicPutForm(l.data);
    const extra = droppedLiveField(l.data);
    if (planned === undefined || !isObj(planned.body) || !isObj(planned.params) || planned.params.branch !== cp.branch || !exactlyAsSet(planned.body, now) || extra !== null) {
      manual(what, `it is not exactly as pipegen set it (${extra !== null ? `it holds ${show(extra, 100)}, which pipegen never sets` : 'changed since, or pipegen\'s plan is not in the record'}), so pipegen leaves it`, step);
      return;
    }
    const diff = cp.previous === null
      ? '  (there was no protection before pipegen: pipegen takes off the one it added)'
      : CLASSIC_DIFF_KEYS.filter((k) => canon(now[k] ?? null) !== canon((cp.previous as Record<string, unknown>)[k] ?? null)).map((k) => `  ${k}: ${fmt(now[k] ?? null)} → ${fmt((cp.previous as Record<string, unknown>)[k] ?? null)}`).join('\n');
    const t = await confirm({ kind: 'classic', branch: cp.branch }, `pipegen would put the branch protection of ${show(cp.branch, 100)} back as it was before pipegen:\n${diff === '' ? '  (no field differs)' : diff}`);
    if (t === null) { skip(what, NOT_TYPED); return; }
    u.restoreClassic = { branch: cp.branch, previous: cp.previous, diff, planned, confirmedByName: true, typed: t };
  }

  /** V-N10: an environment pipegen changed, back to `previous` in the `changed` fields only, after the diff and its typed name. */
  async function planEnvRestore(e: EnvEntry): Promise<void> {
    const what = `environment ${show(e.name, 100)}`;
    if (!isObj(e.previous) || !Array.isArray(e.changed) || e.changed.length === 0) { skip(what, 'pipegen has no earlier settings of it, so it leaves it as it is'); return; }
    const odd = e.changed.filter((k) => !ENV_FIELDS.includes(k));
    if (odd.length > 0) { manual(what, `its record names a field pipegen never changes (${show(odd.join(', '), 100)}), so pipegen puts nothing back there`, 'Check the environment\'s settings by hand.'); return; }
    let cur: Awaited<ReturnType<typeof readEnv>>;
    try { cur = await readEnv(gh, appRef, clock, e.name); } catch (x) {
      if (isRateStop(x) || x instanceof GitHubAccessError || statusOf(x) === 401) throw x;
      manual(what, 'GitHub\'s answer about it could not be read, so pipegen puts nothing back', 'Check the environment\'s settings by hand.');
      return;
    }
    if (cur === null) { skip(what, GONE); return; }
    if (isoAt(e.githubCreatedAt) && (cur.createdAt === null || Date.parse(cur.createdAt) !== Date.parse(e.githubCreatedAt))) { skip(what, 'it is not the one pipegen changed (GitHub says it was created at another time), so pipegen leaves it'); return; }
    const previous = e.previous;
    const settings = cur.settings as unknown as Record<string, unknown>;
    const lines = e.changed.filter((k) => k !== 'branch_policies' && canon(settings[k] ?? null) !== canon(previous[k] ?? null)).map((k) => `  ${k}: ${fmt(settings[k] ?? null)} → ${fmt(previous[k] ?? null)}`);
    const live = new Set(cur.policies.map((p) => p.id));
    const policyIds = e.changed.includes('branch_policies') ? e.branchPolicyIds.filter((id) => live.has(id)) : [];
    if (e.changed.includes('branch_policies')) manual(what, 'pipegen changed its branch and tag rules; the ones it had before pipegen are in the install record, and uninstall only takes off the rules pipegen added', 'Add the earlier branch and tag rules back in the environment\'s settings (Deployment branches and tags).');
    if (lines.length === 0 && policyIds.length === 0) { skip(what, 'its settings are already as they were before pipegen'); return; }
    const diff = lines.join('\n');
    const current: EnvSettings = { ...cur.settings, branch_policies: cur.policies.map((p) => ({ name: p.name, type: p.type })) };
    if (!askable(e.name)) { manual(what, CANT_ASK, 'Check the environment\'s settings by hand.'); return; }
    if (inA) {
      u.restoreEnvironments.push({ name: e.name, previous, changed: [...e.changed], current, shown: cur.settings, diff, entry: e, deleteBranchPolicies: policyIds.map((id) => ({ id })), confirmedByName: false, needsName: true });
      return;
    }
    // the question names every change it covers, the branch rules too (sec M2)
    const rules = policyIds.length === 0 ? '' : `${diff === '' ? '' : '\n'}  and takes off the branch rules pipegen added (ids ${policyIds.join(', ')})`;
    const t = await confirm({ kind: 'environment-restore', entry: e }, `pipegen would put back the settings it changed on the environment ${show(e.name, 100)} (only these):\n${diff}${rules}`);
    if (t === null) { skip(what, NOT_TYPED); return; }
    const deleteBranchPolicies: { id: number; typed?: TypedName }[] = [];
    for (const id of policyIds) {
      if (!loaded.typedNames) { deleteBranchPolicies.push({ id }); continue; }
      const pt = await confirm({ kind: 'branch-policy', entry: e, id });
      if (pt === null) skip(`branch rule ${id} of ${what}`, NOT_TYPED);
      else deleteBranchPolicies.push({ id, typed: pt });
    }
    u.restoreEnvironments.push({ name: e.name, previous, changed: [...e.changed], current, shown: cur.settings, diff, entry: e, deleteBranchPolicies, confirmedByName: true, typed: t });
  }
}

// ---------- the preview ----------

const TWO_RUNS = 'the uninstall PR removes the gate, so the merge lock is removed now; until you merge it, run `pipegen finish` to lock again';
/** How the name of an item is (or will be) confirmed. */
const by = (x: { confirmedByName: boolean; needsName?: true }): string => (x.confirmedByName ? ' (you typed its name)' : x.needsName === true ? ' (you type its name then)' : '');
/** `text` line by line, each line escaped (safeText: no control character reaches the terminal), indented. */
const block = (text: string, indent: string): string[] => text.replace(/\n$/, '').split('\n').map((l) => `${indent}| ${safeText(l, 200)}`);

/**
 * What this run of uninstall will do, for its one confirmation (V5): names only, never a secret or variable value; every manual step.
 * Run 1 also lists what the next run will do (named, nothing asked yet); run 2 lists what it found done.
 */
export function previewUninstall(u: UninstallPlan): string {
  const repo = show(`${u.app.owner}/${u.app.repo}`);
  const inA = u.phase === 'A';
  const out: string[] = [`pipegen uninstall: what it will do in ${repo} (${u.unfinished ? 'part' : 'run'} ${inA ? 1 : 2} of 2)`];
  const list = (title: string, items: string[]): void => { if (items.length > 0) out.push('', title, ...items); };
  if (u.trust === 'typed') out.push('', 'The install record was trusted by typing the repo name: pipegen uses only the names you confirmed, and lists the rest as manual steps.');
  list('Warnings:', u.warnings.map((w) => `  - ${show(w, 400)}`));
  out.push('');
  if (!inA) {
    out.push(u.unfinished
      ? 'This is the second part: pipegen deletes the secrets, variables and environments below, turns off the settings you choose, and opens the central pull request.'
      : 'This is the second run, after the uninstall pull request: pipegen deletes the secrets, variables and environments below, turns off the settings you choose, and opens the central pull request.');
  } else if (u.unfinished) {
    out.push(`The setup pull request was never merged, so pipegen's workflows are not on ${show(u.app.defaultBranch, 100)}: there is no uninstall pull request to wait for. Right after this part, pipegen goes on to the next part, with its own questions and confirmation.`);
  } else {
    out.push(`This takes two runs. Now: pipegen opens the uninstall pull request (branch pipegen/uninstall), closes its own open pull requests and takes off the merge locks: ${TWO_RUNS}.`);
    out.push('Then, after you merge the uninstall pull request, run `pipegen uninstall` again: it asks the names below, deletes the secrets, variables and environments, turns off the settings you choose, and opens the central pull request.');
  }
  list('Done in the first run:', u.done.map((d) => `  - ${show(d, 300)}`));
  // run 1: the uninstall PR, pipegen's pull requests, the merge locks
  const pr: string[] = [];
  for (const f of u.removeFiles) pr.push(`  - remove ${show(f.path, 200)}`);
  for (const r of u.reverts) {
    const p = show(r.edit.path, 200);
    if (r.result.kind === 'restore') pr.push(`  - ${p}: put back to the version before pipegen's first change (the first original the install record names; anything changed in it since is pipegen's)`);
    else if (r.result.kind === 'strip') pr.push(`  - ${p}: pipegen's part taken out, the rest kept as it is`);
    else if (r.result.kind === 'delete') pr.push(`  - remove ${p} (pipegen made it, and it holds only pipegen's text)`);
  }
  list(`Uninstall pull request in ${repo}:`, pr);
  list('Kept (asked; the default keeps):', u.keepAsk.filter((k) => k.keep).map((k) => `  - ${show(k.path, 200)}${k.pair === undefined ? '' : ` (with ${show(k.pair, 200)})`}: ${show(k.why, 200)}`));
  list('Pull requests closed:', u.closePrs.map((p) => `  - #${p.number}${p.repo === 'central' ? ` in ${show(`${u.app.owner}/${CENTRAL_REPO}`)}` : ''} (${show(p.branch, 100)})${by(p)}`));
  list('Branches deleted:', u.deleteBranches.map((b) => `  - ${show(b.branch, 100)}${by(b)}`));
  const locks: string[] = [];
  for (const r of u.deleteRulesets) locks.push(`  - ruleset ${show(r.entry.name, 100)} (id ${r.id}): deleted${by(r)}`);
  if (u.deleteOrgRuleset !== undefined) locks.push(`  - org ruleset ${show(u.deleteOrgRuleset.entry.name, 100)} (id ${u.deleteOrgRuleset.id}) of ${show(u.deleteOrgRuleset.org, 40)}: deleted${by(u.deleteOrgRuleset)}`);
  if (u.restoreClassic !== undefined) {
    const c = u.restoreClassic;
    locks.push(c.previous === null
      ? `  - branch protection of ${show(c.branch, 100)}: pipegen's own taken off (there was none before pipegen)${by(c)}`
      : `  - branch protection of ${show(c.branch, 100)}: put back as it was before pipegen${by(c)}`, ...c.diff.split('\n').map((l) => `    ${safeText(l, 300)}`));
  }
  list(u.unfinished ? 'Merge locks:' : 'Merge locks taken off now:', locks);
  // run 2's items: named in run 1 (nothing asked yet), done in run 2
  const later: string[] = [];
  for (const s of u.deleteSecrets) later.push(`  - delete the secret ${show(s.secret.name, 100)}${s.secret.scope === 'repo' ? '' : ` (${show(s.secret.scope, 120)})`}${s.fromLeftovers === true ? ' (from the leftovers file)' : ''}${by(s)}`);
  for (const v of u.deleteVariables) later.push(`  - delete the variable ${show(v.name, 100)}${v.scope === 'repo' ? '' : ` (${show(v.scope, 120)})`}${by(v)}`);
  for (const v of u.restoreVariables) later.push(`  - put the variable ${show(v.name, 100)} back to its value before pipegen (not shown)${by(v)}`);
  for (const e of u.deleteEnvironments) later.push(`  - delete the environment ${show(e.name, 100)}, with what is in it (only pipegen's items)${by(e)}`);
  for (const e of u.restoreEnvironments) {
    later.push(`  - put back the settings pipegen changed on the environment ${show(e.name, 100)} (only these)${by(e)}:`, ...(e.diff === '' ? [] : e.diff.split('\n').map((l) => `    ${safeText(l, 300)}`)));
    if (e.deleteBranchPolicies.length > 0) later.push(`    and take off the branch rules pipegen added (ids ${e.deleteBranchPolicies.map((p) => p.id).join(', ')})`);
  }
  if (inA) {
    if (u.settings.length > 0) later.push(`  - asks whether to turn off: ${u.settings.map((s) => SETTING_LABEL[s.key]).join(', ')} (pipegen turned them on; the default keeps them on)`);
  } else {
    const off = u.settings.filter((s) => s.turnOff);
    if (off.length > 0) later.push('  - Settings pipegen turns off (you said yes):', ...off.map((s) => `      ${SETTING_LABEL[s.key]}${by(s)}`));
    const on = u.settings.filter((s) => !s.turnOff);
    if (on.length > 0) later.push(`  - settings pipegen turned on and leaves on (you can turn them off yourself): ${on.map((s) => SETTING_LABEL[s.key]).join(', ')}`);
  }
  later.push(`  - a central pull request in ${show(`${u.app.owner}/${CENTRAL_REPO}`)} removes this project's files: ${u.centralFiles.map((p) => show(p, 200)).join(', ')} (the install record last)`);
  // sec M1: the central locks go only when the plan holds them (full trust, last project)
  later.push(u.centralLocks !== undefined
    ? `  - this is the last project in ${CENTRAL_REPO}: its central ruleset, CODEOWNERS and Actions access go too, as recorded`
    : u.lastProject
      ? u.manual.some((m) => m.what === CENTRAL_MANUAL)
        ? `  - this is the last project in ${CENTRAL_REPO}, but the install record doesn't vouch for its central ruleset, CODEOWNERS and Actions access: pipegen doesn't touch them (see the manual steps)`
        : `  - this is the last project in ${CENTRAL_REPO}; the install record lists no central ruleset, CODEOWNERS or Actions access of pipegen's, so pipegen doesn't touch them`
      : `  - other projects use ${CENTRAL_REPO}: its central ruleset, CODEOWNERS and Actions access stay`);
  if (!inA) {
    if (u.proofCleanup) later.push('  - clean up what the saved proof left in GitHub (as `pipegen cleanup` does; the scratch repo is not deleted there)');
    if (u.scratch !== undefined) later.push(`  - empty the scratch repo ${show(u.scratch.repo, 140)} (it carries pipegen's marker): its proof/ branches, secrets, variables, workflow runs and caches`);
    for (const d of u.deleteRepos) {
      later.push(d.how === 'delete'
        ? `  - delete the repo ${show(d.repo, 140)} (--delete-repos; you type its name then${d.afterCentralPr === true ? '; only once the central pull request removing the install record merged' : ''})`
        : `  - print \`gh repo delete ${show(d.repo, 140)}\` (--delete-repos: this token can't delete repos, so pipegen deletes nothing)${d.afterCentralPr === true ? ': only once the central pull request removing the install record merged, the org rule is gone and pipegen\'s checks find nothing but its own there' : ': only while it still carries pipegen\'s marker and the recorded id'}`);
    }
  }
  list(!inA ? 'This run:' : u.unfinished ? 'Next part (right after this one), pipegen will:' : 'Next run (after you merge the uninstall PR), pipegen will:', later);
  list('Not done (kept):', u.skipped.map((s) => `  - ${show(s.what, 200)}: ${show(s.why, 400)}`));
  const man: string[] = [];
  for (const m of u.manual) man.push(`  - ${show(m.what, 200)}: ${show(m.why, 400)}`, ...(m.step === undefined ? [] : [`    ${show(m.step, 400)}`]));
  for (const r of u.reverts) {
    if (r.result.kind !== 'manual') continue;
    man.push(`  - ${show(r.edit.path, 200)}: ${show(r.result.why, 400)}`);
    if (r.result.remove !== undefined) man.push('    Take out exactly this text pipegen added:', ...block(r.result.remove, '      '));
  }
  list('Manual steps (pipegen doesn\'t do these):', man);
  return out.join('\n');
}
