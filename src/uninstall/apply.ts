// v0.2 Plan V V5 (rulings V-B2, V-B3, V-S9, V-S10, V-S11, V-S14, V-S16; V4-R1, V4-R1b M-r1-1 and M-r1-2): run 1 of uninstall (phase A)
// sends the writes, and the dispatcher decides which run this is.
//
// - The four conditions of the V4 security review. (1) Nothing is sent before the one confirmation of that phase's plan (confirmPlan: the
//   preview, then one yes; no terminal → stop). (2) A no, a cancel, a re-plan or an apply drops the plan and its api: a dropped plan is
//   never applied again (its tokens are bound to its api and die with it). (3) Run 2 is a fresh planUninstall(…, { phase: 'B' }): nothing of
//   run 1's answers or tokens is kept, the progress file holds names and ids only. (4) Writes use the plan's own objects (the items, their
//   entries, restoreClassic.previous / planned, the typed tokens), never one rebuilt from the record or a fresh read.
// - M-r1-1: every write goes through a PhaseApi bound to the plan's own phase; a phase-A api refuses run 2's writes (secrets, variables,
//   environments, restores, branch rules, settings, central) and a phase-B api refuses run 1's (app rulesets, the org rule, classic
//   protection, PR closes, the app branch and PR).
// - V-S9: right before the first write, the anchors are read again: the central default head and the record's blob there (changed → stop,
//   nothing sent), the app's default head (moved → a new plan, preview and yes). The uninstall PR is built on the preview's commit and tree,
//   never rebased silently.
// - Phase A, in order: the uninstall PR (one commit per removal kind, one per revert), pipegen's open PRs closed, pipegen/setup deleted (only
//   while it still points at the commit the plan checked, and only when its PRs closed), then the merge locks (app rulesets, the org rule,
//   classic protection restored), each identity-read again right before its write (V3). No lock comes off unless the PR is open (or none was
//   needed). A failed step is reported and the later independent steps still run; anything not done leaves run 1 to do again (re-planned).
// - V-S10: the app's lease (StateStore) is held for the whole run; after Ctrl-C (interrupting()) no new step starts, the write in flight
//   settles, the progress is saved; the install record is never written in phase A.
// - M-r1-2: run 2 goes to phase B only when GitHub's merged_at on the recorded uninstall PR is set. No PR: an unfinished install goes on to
//   phase B in the same process; a run 1 with nothing to remove goes to phase B only when no workflow of pipegen's is live on the default
//   branch (else phase A again); a PR GitHub no longer shows (or not pipegen's) → stop with a manual step.
// - V5-R1: a progress file past run 1 counts only for the record it was made for (its anchors' record blob sha); `B` reads merged_at again;
//   the uninstall PR must target the default branch. The phase runner gets the plan without its api, and only takeApi makes a PhaseApi.
//   pipegen/setup stays while a PR into it is open; pipegen/uninstall moves only while it points where pipegen set it (saved in the progress
//   file); a run 1 with no PR remembers the workflows the user kept, so the next run goes on to run 2 (with the warning) instead of run 1.
// - V6: run 2's runner is phase-b.ts's applyPhaseB. The phase-B api adds its own routes: a typed name at apply time (the central ruleset
//   with no creation date; a repo delete), the central repo delete (deleteCentralRepo, called here only), and the scratch repo's cleanup
//   writes (E's cleanupWrite, deleteScratchSecret, deleteScratchRepo and cleanupLeftovers, called here only).
import { randomBytes } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { PromptCancelledError, type Prompter } from '../cli/io.js';
import { SETUP_BRANCH } from '../deliver/deliver.js';
import { DeliverError, ghRead, readBlobText, readHead, readRepo, readTree, statusOf, type RepoRef, type TreeEntry } from '../deliver/git-data.js';
import { centralOf, recordPath } from '../deliver/record.js';
import { HEAD_CHECK_STEP_ID } from '../engine/deploy-steps.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { CALLER_WORKFLOW, LOCAL_MERGE_WORKFLOW, NIGHTLY_WORKFLOW, PUSH_WORKFLOW } from '../engine/job-rules.js';
import { clockOf, GitHubAccessError } from '../github/client.js';
import { VERIFY_JOB_ID } from '../layers/assemble.js';
import { cleanupLeftovers, type CleanupResult } from '../proof/cleanup.js';
import { StateError, StateStore, type StateDeps } from '../proof/state.js';
import { CENTRAL_REPO, cleanupWrite, deleteScratchRepo, deleteScratchSecret, ProofStopError, type CleanupOp, type GuardedRepo, type RepoDeleteResult } from '../proof/target.js';
import type { InstallRecord, RecordApiRequest } from '../types.js';
import { interrupting, onInterrupt } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { UninstallError } from './errors.js';
import { applyPhaseB } from './phase-b.js';
import { planUninstall, previewUninstall, type PlanDeps, type UninstallPhase, type UninstallPlan } from './plan.js';
import { ProgressFile, type ProgressItem } from './progress.js';
import type { LoadedRecord } from './record.js';
import {
  deleteCentralRepo, UninstallRefusal, type CentralDeleteResult, type Confirmable, type DeleteOutcome, type EnvForm, type Owned, type TypedName, type UninstallApi, type Where,
} from './target.js';

type EnvEntry = InstallRecord['environments'][number];
type VariableEntry = InstallRecord['variables'][number];

export type StepStatus =
  | 'declined' | 'a-done' | 'failed' | 'interrupted' | 'waiting' | 'closed-unmerged' | 'stopped' | 'replan' | `b-${string}`;
export interface StepResult {
  status: StepStatus;
  /** The phase of the plan that ran (null: none ran). */
  phase: UninstallPhase | null;
  /** The uninstall PR this run opened or updated. */
  pr?: { number: number; url: string };
  done: string[];
  /** Steps that didn't happen: the next run does them again (a fresh plan). */
  failed: ProgressItem[];
  skipped: { what: string; why: string }[];
  manual: { what: string; why: string; step?: string }[];
  /**
   * V9a (V8 sec i6, M2): what needs nothing from pipegen and no step from the user to finish the uninstall (the scratch repo's default
   * branch kept, a repo the user created that holds nothing of pipegen's now). Never a leftover: a run with only notes is a clean exit 0.
   */
  notes?: string[];
  /** The final message (names only). */
  lines: string[];
}
/**
 * What phase B gets besides its confirmed plan and its phase-bound api (V6): the loaded (trusted) record the plan was made from, the
 * terminal (the record's yes, typed names at apply time), and the app's lease store (a saved proof state; cleanupLeftovers).
 */
export interface PhaseBContext {
  progress: ProgressFile; workflowsLive: boolean; out: (line: string) => void; deps: StepDeps;
  loaded: LoadedRecord; io: Prompter | undefined; store: StateStore;
}
/** A confirmed plan as a phase runner gets it: without its unbound `api` (V5-R1 I2); every write goes through the PhaseApi beside it. */
export type PhasePlan = Omit<UninstallPlan, 'api'>;
export type PhaseBRunner = (gh: Octokit, plan: PhasePlan, api: PhaseApi, ctx: PhaseBContext) => Promise<StepResult>;
export interface StepDeps extends PlanDeps {
  /** Where the preview and notes go (default: stdout). */
  out?: (line: string) => void;
  /** The lease's state folder (tests). */
  state?: StateDeps;
  /**
   * V9a (V8 sec M4): the app's lease the caller took before it loaded the record (src/cli/uninstall.ts, holdUninstallLease): used, never
   * taken a second time, and given back by the caller. Absent: uninstallStep takes the lease itself.
   */
  lease?: StateStore;
  /** Phase B (V6). Absent: phase-b.ts's applyPhaseB. */
  phaseB?: PhaseBRunner;
}

const show = (s: unknown, n = 200): string => safeText(String(s), n);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
/** How many times the default branch may move under a plan before pipegen stops asking. */
const MAX_REPLANS = 3;
/** pipegen's own app workflows (assemble.ts). */
const APP_WORKFLOWS: readonly string[] = [CALLER_WORKFLOW, PUSH_WORKFLOW, NIGHTLY_WORKFLOW, LOCAL_MERGE_WORKFLOW];
const WORKFLOW_RE = /^\.github\/workflows\/[^/]+\.ya?ml$/;
const MAX_SCANNED = 200;
const MAX_WORKFLOW_BYTES = 1024 * 1024;
const UNINSTALL_PR_BRANCH = 'pipegen/uninstall';
const PR_TITLE = 'pipegen: uninstall';
const LIVE_WARNING = 'pipegen\'s workflows or its verify job are still on the default branch: the uninstall pull request\'s changes aren\'t on the default branch, so this run removes nothing the gate still needs.';
const plainFile = (e: TreeEntry | undefined): e is TreeEntry => e !== undefined && e.type === 'blob' && (e.mode === '100644' || e.mode === '100755');

// ---------- the plan's life: confirmed once, used once (conditions 1 and 2) ----------

const confirmed = new WeakSet<UninstallPlan>();
const dropped = new WeakSet<UninstallPlan>();

/** Drops a plan: it is never confirmed or applied again (its api and tokens go with it). */
export function dropPlan(plan: UninstallPlan): void {
  dropped.add(plan);
  confirmed.delete(plan);
}

/**
 * The one confirmation of a plan: the preview, then one yes (default no). A no or a cancel drops the plan. No terminal: the preview, then an
 * UninstallError (nothing sent). Nothing is sent here.
 */
export async function confirmPlan(plan: UninstallPlan, io: Prompter | undefined, deps: { interactive?: boolean; out?: (line: string) => void }): Promise<boolean> {
  if (dropped.has(plan)) throw new UninstallError('pipegen asks about each plan once; this one was already answered. Nothing more was changed.');
  const out = deps.out ?? printLine;
  out(previewUninstall(plan));
  if (deps.interactive !== true || io === undefined) {
    dropPlan(plan);
    throw new UninstallError('pipegen shows what it will do and asks for one yes before it changes anything, and this run has no terminal (no terminal, --yes, or CI). Nothing was changed. Run `npx pipegen uninstall` at a terminal.');
  }
  const part = plan.phase === 'A' ? (plan.unfinished ? 'part 1' : 'run 1') : (plan.unfinished ? 'part 2' : 'run 2');
  let yes = false;
  try { yes = (await io.confirm(`Go ahead with ${part} of pipegen uninstall in ${show(`${plan.app.owner}/${plan.app.repo}`, 140)}? (y/N)`, false)) === true; } catch (e) {
    if (!(e instanceof PromptCancelledError)) throw e;
    yes = false;
  }
  if (!yes) { dropPlan(plan); return false; }
  confirmed.add(plan);
  return true;
}

/**
 * The phase-bound api of a confirmed plan, once: the plan is dropped as it is taken (an apply uses its plan once). The only maker of a
 * PhaseApi (V5-R1 I2). The plan comes back without its `api`, so a runner can't reach the unbound UninstallApi; the typed-name tokens in its
 * items still work through the PhaseApi, which sends to that same api.
 */
export function takeApi(plan: UninstallPlan, phase: UninstallPhase): { api: PhaseApi; plan: PhasePlan } {
  if (!confirmed.has(plan) || dropped.has(plan)) throw new UninstallError('pipegen sends nothing without the confirmed plan of this run (each plan is confirmed once and used once). Nothing more was changed.');
  if (plan.phase !== phase) throw new UninstallError(`This plan is for phase ${plan.phase}, not phase ${phase}. Nothing more was changed.`);
  dropPlan(plan);
  const { api, ...rest } = plan;
  return { api: new PhaseApi(PHASE_API_GUARD, api, phase), plan: rest };
}
/** Held by this module only: a PhaseApi is made by takeApi, never by a caller with an UninstallApi in hand. */
const PHASE_API_GUARD: object = Object.freeze({});

// ---------- the phase-bound api (M-r1-1) ----------

const A_KINDS: ReadonlySet<string> = new Set(['ruleset', 'org-ruleset']);
const B_KINDS: ReadonlySet<string> = new Set(['secret', 'variable', 'environment', 'central-ruleset']);

/**
 * The writes of one run, on the plan's UninstallApi: phase A (run 1) only the app's uninstall PR, the app rulesets, the org rule, classic
 * protection, PR closes and pipegen/setup; phase B (run 2) only secrets, variables, environments, their restores and branch rules, the
 * settings and the central PR and branches. Anything else is refused before anything is read or sent.
 */
export class PhaseApi {
  readonly #phase: UninstallPhase;
  readonly #api: UninstallApi;

  constructor(guard: object, api: UninstallApi, phase: UninstallPhase) {
    if (guard !== PHASE_API_GUARD) throw new UninstallRefusal('an uninstall api bound to a phase is made only from the confirmed plan of this run.');
    if (phase !== 'A' && phase !== 'B') throw new UninstallRefusal('an uninstall api is bound to phase A or B.');
    this.#api = api;
    this.#phase = phase;
    Object.freeze(this);
  }

  /** Read-only: a runner can't turn its phase-B api into a phase-A one. */
  get phase(): UninstallPhase { return this.#phase; }

  get clock(): RateClock { return this.#api.clock; }

  #only(phase: UninstallPhase, what: string): void {
    if (this.phase !== phase) throw new UninstallRefusal(`${what} belongs to ${phase === 'A' ? 'the first run (phase A)' : 'the second run (phase B)'}; this run doesn't send it.`);
  }
  /** The repo a phase's files, branches and PRs are in: the app in A, central in B. */
  #where(where: Where, what: string): void {
    if (where !== (this.phase === 'A' ? 'app' : 'central')) throw new UninstallRefusal(`${what} in the ${where} repo doesn't belong to this run.`);
  }

  read(route: string, params: Record<string, unknown>): Promise<{ status: number; data: unknown }> { return this.#api.read(route, params); }

  async deleteIfPipegens(o: Owned, opts: { typed?: TypedName } = {}): Promise<DeleteOutcome> {
    if (!(this.phase === 'A' ? A_KINDS : B_KINDS).has(String(o?.kind))) throw new UninstallRefusal(`a ${show(o?.kind, 40)} delete doesn't belong to this run.`);
    return this.#api.deleteIfPipegens(o, opts);
  }
  async restoreClassic(cp: { branch: string; previous: Record<string, unknown> | null }, planned: RecordApiRequest | undefined, typed?: TypedName): Promise<DeleteOutcome> {
    this.#only('A', 'the branch protection restore');
    return this.#api.restoreClassic(cp, planned, typed);
  }
  async closePr(where: Where, pr: number): Promise<DeleteOutcome> {
    this.#only('A', 'closing pipegen\'s pull requests');
    return this.#api.closePr(where, pr);
  }
  async deleteBranch(where: Where, branch: string): Promise<DeleteOutcome> {
    this.#where(where, 'a branch delete');
    if (this.phase === 'A' && branch !== SETUP_BRANCH) throw new UninstallRefusal(`run 1 deletes only ${SETUP_BRANCH}.`);
    return this.#api.deleteBranch(where, branch);
  }
  async commitUninstall(where: Where, c: Parameters<UninstallApi['commitUninstall']>[1]): Promise<{ commit: string; tree: string }> {
    this.#where(where, 'an uninstall commit');
    return this.#api.commitUninstall(where, c);
  }
  async setUninstallBranch(where: Where, sha: string): Promise<'created' | 'moved'> {
    this.#where(where, 'the uninstall branch');
    return this.#api.setUninstallBranch(where, sha);
  }
  async openUninstallPr(where: Where, pr: { base: string; title: string; body: string }): Promise<{ number: number; url: string; opened: boolean }> {
    this.#where(where, 'the uninstall pull request');
    return this.#api.openUninstallPr(where, pr);
  }
  async restoreEnvironment(entry: EnvEntry, shown: EnvForm, secrets: readonly { name: string }[], typed?: TypedName): Promise<DeleteOutcome> {
    this.#only('B', 'an environment restore');
    return this.#api.restoreEnvironment(entry, shown, secrets, typed);
  }
  async restoreVariable(entry: VariableEntry, pipegenValue: string | undefined, typed?: TypedName): Promise<DeleteOutcome> {
    this.#only('B', 'a variable restore');
    return this.#api.restoreVariable(entry, pipegenValue, typed);
  }
  async deleteBranchPolicy(entry: EnvEntry, id: number, typed?: TypedName): Promise<DeleteOutcome> {
    this.#only('B', 'a deployment branch rule delete');
    return this.#api.deleteBranchPolicy(entry, id, typed);
  }
  async write(route: string, params: Record<string, unknown>, opts: { pipegenSet?: string; typed?: TypedName } = {}): Promise<DeleteOutcome> {
    this.#only('B', 'a settings write');
    return this.#api.write(route, params, opts);
  }

  // ---------- phase B's own routes (V6, V5-R1 carry) ----------

  /**
   * A typed name at apply time for an object the plan couldn't ask about (the central ruleset with no creation date; V9a: the central
   * Actions access of a typed-names run, asked only once central is known to be the last project's): its token.
   */
  async confirm(c: Confirmable): Promise<TypedName | null> {
    this.#only('B', 'a typed name at apply time');
    if (String(c?.kind) !== 'central-ruleset' && String(c?.kind) !== 'central-access') throw new UninstallRefusal('run 2 asks a typed name at apply time only for the central ruleset and the central Actions access; the plan asked the others.');
    return this.#api.confirm(c);
  }
  /**
   * PL-F5 (V9a R2-i3): after `pipelines` was not typed for the central Actions access, whether the owner types `keep` (the level pipegen
   * set stays, as the owner's choice). The question is built here; it sends nothing.
   */
  async keepCentralAccess(): Promise<boolean> {
    this.#only('B', 'a typed keep at apply time');
    return this.#api.ask('keep', `Keep the Actions access level of ${this.#api.app.owner}/${CENTRAL_REPO} as pipegen set it? It is shared by every project there, and pipegen won't call it a leftover again.`);
  }
  /**
   * The central repo delete (deleteCentralRepo's every check, the typed numbers and `pipelines` typed at this run's terminal). The caller
   * decides the token may delete repos (App mode) and that the central PR removing the record merged; sendRepoDelete is reached only here.
   */
  async removeCentralRepo(rec: InstallRecord, knownHeads: Readonly<Record<string, string>>, marker?: { beforeDelete: () => void; deleteAccepted: () => void }): Promise<CentralDeleteResult> {
    this.#only('B', 'the central repo delete');
    const api = this.#api;
    return deleteCentralRepo(api.gh, api.central, rec, { askName: (expected, question) => api.ask(expected, question), clock: api.clock, knownHeads, ...(marker ?? {}) });
  }
  /** V6-R1 sec I1: deleteCentralRepo's checks, read only (token mode: whether pipegen may tell the user to delete it); nothing asked or sent. */
  async checkCentralRepo(rec: InstallRecord, knownHeads: Readonly<Record<string, string>>): Promise<CentralDeleteResult> {
    this.#only('B', 'the central repo check');
    const api = this.#api;
    return deleteCentralRepo(api.gh, api.central, rec, { askName: async () => { throw new UninstallRefusal('the central repo check asks nothing.'); }, clock: api.clock, dryRun: true, knownHeads });
  }
  /** One of E's cleanup writes on the scratch repo (cleanupWrite: its own guard and op list). */
  async scratchCleanup(r: GuardedRepo, op: CleanupOp): Promise<{ status: number; data: unknown }> {
    this.#only('B', 'the scratch repo cleanup');
    return cleanupWrite(this.#api.gh, r, op, this.#api.clock);
  }
  /** One repo secret of the scratch repo, deleted through E's deleteScratchSecret. */
  async scratchSecretDelete(r: GuardedRepo, name: string): Promise<void> {
    this.#only('B', 'the scratch repo cleanup');
    return deleteScratchSecret(this.#api.gh, r, name, this.#api.clock);
  }
  /** The scratch repo delete: its exact name typed at this run's terminal first, then E's deleteScratchRepo (name, marker, recorded id). */
  async scratchRepoDelete(r: GuardedRepo, recordedId: number | undefined): Promise<RepoDeleteResult> {
    this.#only('B', 'the scratch repo delete');
    const typed = await this.#api.ask(r.repo, `Delete the repo ${show(r.fullName, 140)} (pipegen's scratch repo, id ${String(recordedId)})? Its history, runs and everything else in it go with it, and GitHub can't undo it.`);
    if (!typed) return { deleted: false, why: `the name typed was not ${r.repo}` };
    return deleteScratchRepo(this.#api.gh, r, recordedId, this.#api.clock);
  }
  /** What a saved proof state left (E's cleanupLeftovers); the scratch repo is never deleted there (that needs its typed name). */
  async proofLeftovers(store: StateStore, io: Parameters<typeof cleanupLeftovers>[2]['io']): Promise<CleanupResult> {
    this.#only('B', 'the proof cleanup');
    return cleanupLeftovers(this.#api.gh, store, { canDeleteRepo: false, io });
  }
}

// ---------- the dispatcher ----------

/**
 * One run of `pipegen uninstall` for a loaded (trusted) record: the app's lease for the whole run, then by the progress file: none (or run 1
 * not done) → run 1 (plan A, preview, one yes, phase A); run 1 done → the uninstall PR from GitHub: merged (merged_at) → run 2 (a fresh
 * phase-B plan, preview, one yes, phase B); open → merge it first; closed unmerged → nothing more (finish locks again), the progress file
 * goes. Returns the run's result; its `lines` are the final message.
 */
export async function uninstallStep(gh: Octokit, loaded: LoadedRecord, io: Prompter | undefined, deps: StepDeps = {}): Promise<StepResult> {
  const app: RepoRef = { owner: loaded.app.owner, repo: loaded.app.repo };
  const out = deps.out ?? printLine;
  const { out: _out, state: _state, phaseB: _phaseB, lease: _lease, ...planDeps } = deps;
  const clock = deps.clock ?? clockOf(gh);
  // V9a (V8 sec M4): the caller's lease, taken before the record was loaded; it must be this app's, and the caller gives it back
  if (deps.lease !== undefined && !deps.lease.holdsLeaseFor(app)) throw new UninstallError(`pipegen uninstall was handed a lease it doesn't hold for ${show(`${app.owner}/${app.repo}`, 140)}, so it changes nothing. Nothing was changed.`);
  const own = deps.lease === undefined;
  const lease = deps.lease ?? await takeLease(app, deps.state);
  try {
    const progress = await ProgressFile.open(app, loaded.app.repoId, deps.local ?? {});
    const ctx: Ctx = { gh, loaded, io, deps, planDeps, out, clock, progress, store: lease };
    const p = progress.state;
    if (p === null || p.phase === 'A') return await runA(ctx);
    // I1: past run 1, the file counts only for the record it was made for (phase A never writes the record; phase B removes it last)
    if (p.anchors.recordBlobSha !== loaded.blobSha) {
      const why = `the uninstall progress file ${progress.path} was made for another install record (pipegen was installed again, or the record changed since)`;
      const step = `Check ${show(`${app.owner}/${app.repo}`, 140)}, move ${progress.path} away, then run \`pipegen uninstall\` again: it starts with the first run.`;
      const r = result('stopped', null, [`pipegen stopped: ${why}. Nothing was changed.`, `Manual step: ${step}`]);
      r.manual.push({ what: 'uninstall progress file', why, step });
      return r;
    }
    if (p.phase === 'B' && p.prNumber === undefined) return await runB(ctx, (await liveWorkflow(gh, loaded, clock)) !== null);
    // run 1 is done: what next depends on GitHub, never on the progress file alone
    if (p.prNumber === undefined || p.unfinished === true) {
      const kept = new Set((p.keptWorkflows ?? []).filter((k) => loaded.record.files.some((f) => f.repo === 'app' && f.path === k)));
      const live = await liveWorkflow(gh, loaded, clock, kept);
      if (live !== null) {
        out(`pipegen's workflow ${show(live, 200)} (or its verify job in it) is still on ${show(loaded.app.defaultBranch, 100)}, and the first run needed no uninstall pull request: pipegen runs the first run again, so it is removed before anything it needs. If pipegen can't remove it, take pipegen's part out of ${show(live, 200)} on ${show(loaded.app.defaultBranch, 100)} by hand, then run \`pipegen uninstall\` again.`);
        return await runA(ctx);
      }
      return await runB(ctx, kept.size > 0 && (await liveWorkflow(gh, loaded, clock)) !== null);
    }
    const pr = await prState(gh, app, loaded.app.repoId, loaded.app.defaultBranch, p.prNumber, clock);
    const num = `#${p.prNumber}`;
    const url = p.prUrl === undefined ? '' : ` (${show(p.prUrl, 300)})`;
    if (p.phase === 'B' && pr !== 'merged' && pr !== 'gone' && pr !== 'foreign' && pr !== 'other-base') {
      // B: the second run began, so its PR merged; GitHub showing it unmerged now is not something pipegen goes on from
      const why = `the progress file says the second run began, but GitHub shows the uninstall pull request ${num} as not merged`;
      const step = `Check ${show(`${app.owner}/${app.repo}`, 140)}: if pipegen's uninstall pull request merged, move ${progress.path} away and run \`pipegen uninstall\` again; if not, run \`pipegen finish\` to lock again.`;
      const r = result('stopped', null, [`pipegen stopped: ${why}. Nothing was changed.`, `Manual step: ${step}`]);
      r.manual.push({ what: `uninstall pull request ${num}`, why, step });
      return r;
    }
    switch (pr) {
      case 'merged': return await runB(ctx, (await liveWorkflow(gh, loaded, clock)) !== null);
      case 'open': return result('waiting', 'A', [`The uninstall pull request ${num}${url} is still open. Merge it, then run \`pipegen uninstall\` again for the second run. Until you merge it, run \`pipegen finish\` to lock again.`]);
      case 'closed':
        progress.remove();
        return result('closed-unmerged', 'A', [`The uninstall pull request ${num}${url} was closed without merging: pipegen does nothing more. The merge locks are off since the first run: run \`pipegen finish\` to lock again.`]);
      default: {
        const why = pr === 'gone'
          ? `GitHub doesn't show the uninstall pull request ${num} any more (deleted, or this login can't see it), so pipegen can't tell whether it merged`
          : pr === 'other-base'
            ? `the uninstall pull request ${num} targets another branch than the default branch ${show(loaded.app.defaultBranch, 100)}, so its changes are not where pipegen's gate runs`
            : `the pull request ${num} the progress file names is not pipegen's uninstall pull request (branch ${UNINSTALL_PR_BRANCH} of this repo)`;
        const step = `Check ${show(`${app.owner}/${app.repo}`, 140)}: if pipegen's uninstall pull request merged, move ${progress.path} away and run \`pipegen uninstall\` again; if not, run \`pipegen finish\` to lock again.`;
        const r = result('stopped', null, [`pipegen stopped: ${why}. Nothing was changed.`, `Manual step: ${step}`]);
        r.manual.push({ what: `uninstall pull request ${num}`, why, step });
        return r;
      }
    }
  } finally {
    // G-LEASE-R1 (sec M1): kept while a stop is under way; the exit hook drops it after the interrupt hooks. A caller's lease is the caller's.
    if (own && !interrupting()) lease.releaseLease();
  }
}

interface Ctx {
  gh: Octokit; loaded: LoadedRecord; io: Prompter | undefined; deps: StepDeps; planDeps: PlanDeps; out: (line: string) => void; clock: RateClock;
  progress: ProgressFile; store: StateStore;
}

/** Run 1: plan A, preview, one yes, phase A (again on a moved default branch); an unfinished install goes on to run 2 in the same process. */
async function runA(c: Ctx): Promise<StepResult> {
  for (let n = 0; ; n += 1) {
    const plan = await planUninstall(c.gh, c.loaded, c.io, { ...c.planDeps, phase: 'A' });
    if (!(await confirmPlan(plan, c.io, c.deps))) return declined(plan.phase);
    const r = await dispatch(c, plan, false);
    if (r.status === 'replan') {
      if (n + 1 >= MAX_REPLANS) return result('stopped', 'A', [`The default branch of ${show(`${plan.app.owner}/${plan.app.repo}`, 140)} kept moving while pipegen planned (${MAX_REPLANS} times). Nothing was changed. Run \`pipegen uninstall\` again when it is quiet.`]);
      c.out(`The default branch ${show(plan.app.defaultBranch, 100)} moved since the preview: nothing was sent. pipegen plans again, with a new preview and question.`);
      continue;
    }
    if (r.status === 'a-done' && plan.unfinished) {
      for (const l of r.lines) c.out(l);
      const b = await runB(c, (await liveWorkflow(c.gh, c.loaded, c.clock)) !== null);
      return { ...b, done: [...r.done, ...b.done], skipped: [...r.skipped, ...b.skipped], manual: [...r.manual, ...b.manual], notes: [...(r.notes ?? []), ...(b.notes ?? [])] };
    }
    return r;
  }
}

/** Run 2: a fresh phase-B plan (never run 1's answers or tokens), its preview and one yes, then phase B (V6). */
async function runB(c: Ctx, live: boolean): Promise<StepResult> {
  const plan = await planUninstall(c.gh, c.loaded, c.io, { ...c.planDeps, phase: 'B', proofState: c.store.state !== null });
  if (live) plan.warnings.push(LIVE_WARNING);
  if (!(await confirmPlan(plan, c.io, c.deps))) return declined(plan.phase);
  return dispatch(c, plan, live);
}

/** M-r1-1: by the plan's own phase, with an api bound to it. */
async function dispatch(c: Ctx, plan: UninstallPlan, live: boolean): Promise<StepResult> {
  if (plan.phase === 'A') return applyPhaseA(c.gh, plan, c.progress, { out: c.out, clock: c.clock });
  const taken = takeApi(plan, 'B');
  const runner: PhaseBRunner = c.deps.phaseB ?? applyPhaseB;
  return runner(c.gh, taken.plan, taken.api, { progress: c.progress, workflowsLive: live, out: c.out, deps: c.deps, loaded: c.loaded, io: c.io, store: c.store });
}

// ---------- phase A ----------

/**
 * Phase A of a confirmed plan (run 1): the anchors read again (V-S9), then the uninstall PR, pipegen's open PRs, pipegen/setup, and the merge
 * locks, through the plan's phase-A api, with the progress saved before the first write, after the PR, on a failure and on Ctrl-C. Secrets,
 * variables, environments and settings are never sent here (run 2's). The install record is never written.
 */
export async function applyPhaseA(gh: Octokit, confirmedPlan: UninstallPlan, progress: ProgressFile, deps: { out?: (line: string) => void; clock?: RateClock } = {}): Promise<StepResult> {
  const { api, plan } = takeApi(confirmedPlan, 'A');
  // M2: the head pipegen set pipegen/uninstall to in an earlier try of run 1 (read before this run saves over the file)
  const prior = progress.state;
  let uninstallHead = prior !== null && prior.phase === 'A' ? prior.uninstallHead : undefined;
  let keptWorkflows: string[] = [];
  const clock = deps.clock ?? api.clock;
  const appRef: RepoRef = { owner: plan.app.owner, repo: plan.app.repo };
  const full = show(`${appRef.owner}/${appRef.repo}`, 140);
  if ((await recheck(gh, plan, clock)) === 'moved') return result('replan', 'A', []);

  const r = result('a-done', 'A', []);
  let pr: { number: number; url: string } | undefined;
  const save = (phase: 'A' | 'A-done'): void => {
    progress.save({
      phase, anchors: { ...plan.base }, ...(pr === undefined ? {} : { prNumber: pr.number, prUrl: pr.url }), ...(plan.unfinished ? { unfinished: true as const } : {}),
      ...(uninstallHead === undefined ? {} : { uninstallHead }), keptWorkflows,
      done: [...r.done], leftovers: [...r.failed, ...r.manual.map((m) => ({ what: m.what, why: m.why, ...(m.step === undefined ? {} : { manual: m.step }) }))],
    });
  };
  save('A');   // before the first write: a stop from here on is resumed as run 1

  /** One step; false when it didn't happen (listed in `failed`). A 401 or a rate stop ends the run (progress saved by the caller). */
  const attempt = async (what: string, manual: string | undefined, fn: () => Promise<DeleteOutcome | 'ok'>): Promise<boolean> => {
    let o: DeleteOutcome | 'ok';
    try { o = await fn(); } catch (e) {
      if (isRateStop(e) || e instanceof GitHubAccessError || statusOf(e) === 401) throw e;
      r.failed.push({ what, why: interrupting() ? 'not done: pipegen was stopped (Ctrl-C)' : reasonOf(e), ...(manual === undefined ? {} : { manual }) });
      return false;
    }
    if (o === 'ok') return true;
    switch (o.status) {
      case 'deleted': case 'gone': case 'restored': case 'closed': case 'not-open': case 'done':
        r.done.push(`${what}: ${DONE_WORDS[o.status]}`);
        if (o.status === 'restored' && o.manual !== undefined) r.manual.push({ what, why: 'put back, but one part needs your hand', step: o.manual });
        return true;
      case 'kept':
        r.skipped.push({ what, why: o.why });
        if (o.manual !== undefined) r.manual.push({ what, why: o.why, step: o.manual });
        return true;
      case 'ask':
        r.failed.push({ what, why: `not done: GitHub's answer changed since the preview (${o.why}); run \`pipegen uninstall\` again and type its name when asked` });
        return false;
      case 'leftover':
        r.failed.push({ what, why: o.why, manual: o.manual });
        return false;
    }
  };

  // the steps, in order; each starts only while no stop has begun (V-S10)
  let prOk = false;
  const closed = new Map<string, boolean>();   // branch → every PR of it closed
  const steps: (() => Promise<void>)[] = [];
  steps.push(async () => {
    prOk = await attempt('uninstall pull request', undefined, async () => {
      let opened: Awaited<ReturnType<typeof uninstallPr>>;
      try {
        opened = await uninstallPr(gh, plan, api, clock, {
          head: uninstallHead,
          set: (sha) => { uninstallHead = sha; save('A'); },
        });
      } catch (e) {
        // spec M3 (V-S11): a 403 while building the PR names the exact step
        if (statusOf(e) !== 403) throw e;
        return { status: 'leftover', why: 'GitHub refused a write for the uninstall pull request (HTTP 403)', manual: `Give the token Contents: write and Pull requests: write on ${full} (or open the uninstall pull request by hand), then run \`pipegen uninstall\` again.` };
      }
      if (opened === null) {
        r.done.push(`${full} needed no uninstall pull request: nothing of pipegen's to remove there`);
        // M4: the workflows the user kept stay; the next run's live-workflow check passes them over (the run-2 preview still warns)
        keptWorkflows = plan.keepAsk.filter((k) => k.keep && WORKFLOW_RE.test(k.path)).map((k) => k.path);
        return 'ok';
      }
      if ('status' in opened) return opened;
      pr = opened.pr;
      r.pr = opened.pr;
      r.done.push(`uninstall pull request #${opened.pr.number}: ${opened.opened ? 'opened' : 'updated'}`);
      save('A');
      return 'ok';
    });
  });
  for (const c of plan.closePrs) {
    steps.push(async () => {
      const what = `pull request #${c.number} (${show(c.branch, 100)})${c.repo === 'central' ? ` in ${show(`${appRef.owner}/pipelines`, 140)}` : ''}`;
      const key = `${c.repo}:${c.branch}`;
      // a name the plan should have asked (typed names; the central PR always): without it nothing is sent
      if ((plan.typedNames || c.repo === 'central') && c.confirmedByName !== true) { r.skipped.push({ what, why: 'kept: its name was not typed' }); closed.set(key, false); return; }
      const ok = await attempt(what, `gh pr close ${c.number} --repo ${c.repo === 'app' ? `${appRef.owner}/${appRef.repo}` : `${appRef.owner}/pipelines`}`, () => api.closePr(c.repo, c.number));
      closed.set(key, (closed.get(key) ?? true) && ok);
    });
  }
  for (const b of plan.deleteBranches) {
    steps.push(async () => {
      const what = `branch ${show(b.branch, 100)}`;
      if (plan.typedNames && b.confirmedByName !== true) { r.skipped.push({ what, why: 'kept: its name was not typed' }); return; }
      if (closed.get(`app:${b.branch}`) === false) { r.failed.push({ what, why: 'not done: its pull request was not closed' }); return; }
      await attempt(what, `gh api -X DELETE repos/${appRef.owner}/${appRef.repo}/git/refs/heads/${b.branch}`, async () => {
        const now = await branchHead(api, appRef, b.branch);
        if (now === null) return { status: 'gone' };
        if (now !== b.head) return { status: 'kept', why: 'it moved since the preview (a new commit on it), so pipegen leaves it', manual: `Look at ${b.branch}, keep what you need, then delete it by hand.` };
        // a branch delete closes any pull request still open on it: only when none is (one pipegen didn't close is the user's)
        const open = (await api.read('GET /repos/{owner}/{repo}/pulls', { ...appRef, head: `${appRef.owner}:${b.branch}`, state: 'open', per_page: 100 })).data;
        if (!Array.isArray(open) || open.some((p) => !isObj(p) || (p.state === 'open' && isObj(p.head) && p.head.ref === b.branch))) {
          return { status: 'kept', why: 'a pull request is still open on it (deleting the branch would close it), so pipegen leaves it', manual: `Close the pull request on ${b.branch} if you don't need it, then delete the branch by hand.` };
        }
        // sec M1: GitHub also closes the open pull requests INTO a deleted branch (the setup PR was closed unmerged, so none is retargeted)
        const into = (await api.read('GET /repos/{owner}/{repo}/pulls', { ...appRef, base: b.branch, state: 'open', per_page: 100 })).data;
        if (!Array.isArray(into) || into.some((p) => !isObj(p) || (p.state === 'open' && isObj(p.base) && p.base.ref === b.branch))) {
          return { status: 'kept', why: 'a pull request into it is still open (deleting the branch would close it), so pipegen leaves it', manual: `Retarget or close the pull request into ${b.branch}, then delete the branch by hand.` };
        }
        return api.deleteBranch('app', b.branch);
      });
    });
  }
  // the merge locks: only once the uninstall PR is open (or none was needed), each re-read right before its write (V3)
  const lock = (what: string, manual: string | undefined, fn: () => Promise<DeleteOutcome>) => async (): Promise<void> => {
    if (!prOk) { r.failed.push({ what, why: 'not done: the uninstall pull request was not opened, so the merge locks stay' }); return; }
    await attempt(what, manual, fn);
  };
  for (const x of plan.deleteRulesets) steps.push(lock(`ruleset ${show(x.entry.name, 100)} (id ${x.id})`, undefined, () => api.deleteIfPipegens({ kind: 'ruleset', entry: x.entry }, x.typed === undefined ? {} : { typed: x.typed })));
  const org = plan.deleteOrgRuleset;
  if (org !== undefined) steps.push(lock(`org ruleset ${show(org.entry.name, 100)} (id ${org.id})`, undefined, () => api.deleteIfPipegens({ kind: 'org-ruleset', entry: org.entry }, org.typed === undefined ? {} : { typed: org.typed })));
  const cp = plan.restoreClassic;
  if (cp !== undefined) steps.push(lock(`branch protection of ${show(cp.branch, 100)}`, undefined, () => api.restoreClassic({ branch: cp.branch, previous: cp.previous }, cp.planned, cp.typed)));

  // Ctrl-C: no new step; the one in flight settles, then the progress is saved
  let current: Promise<void> = Promise.resolve();
  let stopped = false;
  const off = onInterrupt(async (ictx) => {
    await current.catch(() => undefined);
    try { save('A'); } catch { ictx.leftover('the uninstall progress (not saved)'); }
  }, { label: 'saving the uninstall progress', deadlineMs: 60_000 });
  try {
    for (const s of steps) {
      if (interrupting()) { stopped = true; break; }
      current = s();
      await current;
    }
    if (interrupting()) stopped = true;
  } catch (e) {
    try { save('A'); } catch { /* the error that stopped the run is the one to report */ }
    throw e;
  } finally {
    off();
  }
  for (const s of plan.skipped) r.skipped.push(s);
  for (const m of plan.manual) r.manual.push(m);
  for (const x of plan.reverts) if (x.result.kind === 'manual') r.manual.push({ what: x.edit.path, why: x.result.why, ...(x.result.remove === undefined ? {} : { step: 'Take out pipegen\'s text by hand (shown in the preview).' }) });
  if (stopped) {
    save('A');
    r.status = 'interrupted';
    r.lines = [`pipegen stopped (Ctrl-C). What it did is saved in ${progress.path}; run \`pipegen uninstall\` again to finish the first run.`, ...summary(r)];
    return r;
  }
  const finished = r.failed.length === 0;
  save(finished ? 'A-done' : 'A');
  r.status = finished ? 'a-done' : 'failed';
  r.lines = [...summary(r), ...nextOf(plan, r, finished, keptWorkflows, progress.path)];
  return r;
}

const DONE_WORDS: Readonly<Record<string, string>> = { deleted: 'deleted', gone: 'already gone', restored: 'put back as it was before pipegen', closed: 'closed', 'not-open': 'already closed', done: 'done' };

/** What to do next after run 1 (the final message's end). */
function nextOf(plan: PhasePlan, r: StepResult, finished: boolean, kept: readonly string[], progressPath: string): string[] {
  if (!finished) return ['Some steps were not done (above). Run `pipegen uninstall` again: it plans the first run again and does what is left.'];
  if (plan.unfinished) return ['The first part is done.'];
  // V9a (V8 sec i1): the merge locks are off from now on, while the environments the record stores secrets in keep them until run 2
  const envs = plan.secretEnvs.map((e) => show(e, 100));
  const open = envs.length === 0 ? [] : [`Do the second run soon: until the second run, anyone who can push to ${show(plan.app.defaultBranch, 100)} can use pipegen's environment${envs.length === 1 ? '' : 's'} ${envs.join(', ')} and the secrets pipegen stored there (the merge locks are off now; the second run deletes them).`];
  if (r.pr === undefined && kept.length > 0) {
    return [`${show(`${plan.app.owner}/${plan.app.repo}`, 140)} needed no uninstall pull request. You kept ${kept.map((k) => show(k, 200)).join(', ')} on ${show(plan.app.defaultBranch, 100)}: pipegen leaves ${kept.length === 1 ? 'it' : 'them'} as ${kept.length === 1 ? 'it is' : 'they are'}, and its merge locks are off now. Run \`pipegen uninstall\` again for the second run (secrets, variables, environments, settings, central); its preview warns that pipegen's workflow is still there. What this run did is saved in ${progressPath}.`, ...open];
  }
  if (r.pr === undefined) return [`${show(`${plan.app.owner}/${plan.app.repo}`, 140)} needed no uninstall pull request. Run \`pipegen uninstall\` again for the second run (secrets, variables, environments, settings, central).`, ...open];
  return [`Merge the uninstall pull request #${r.pr.number} (${show(r.pr.url, 300)}), then run \`pipegen uninstall\` again for the second run (secrets, variables, environments, settings, central). The merge locks are off now: until you merge it, run \`pipegen finish\` to lock again.`, ...open];
}

/** Done, not done, kept and manual steps, as lines (names only). */
function summary(r: StepResult): string[] {
  const out: string[] = [];
  const list = (title: string, items: string[]): void => { if (items.length > 0) out.push(title, ...items); };
  list('Done:', r.done.map((d) => `  - ${show(d, 300)}`));
  list('Not done (the next run tries again):', r.failed.map((f) => `  - ${show(f.what, 200)}: ${show(f.why, 400)}${f.manual === undefined ? '' : `\n    ${show(f.manual, 300)}`}`));
  list('Kept:', r.skipped.map((s) => `  - ${show(s.what, 200)}: ${show(s.why, 400)}`));
  list('Manual steps (pipegen doesn\'t do these):', r.manual.map((m) => `  - ${show(m.what, 200)}: ${show(m.why, 400)}${m.step === undefined ? '' : `\n    ${show(m.step, 400)}`}`));
  list('Notes:', (r.notes ?? []).map((n) => `  - ${show(n, 600)}`));
  return out;
}

/** Why a step failed, for the message (names only; an unknown error's text is cut and made safe). */
function reasonOf(e: unknown): string {
  if (e instanceof UninstallRefusal || e instanceof UninstallError || e instanceof DeliverError) return show(e.message, 300);
  const s = statusOf(e);
  if (s !== undefined) return `GitHub answered HTTP ${s}`;
  return `an unexpected error (${show(e instanceof Error ? e.name : typeof e, 60)})`;
}

/**
 * V-S9, right before the first write: the central default head and the record's blob at it as the preview read them (else a stop: nothing
 * sent), and the app's default head (moved → 'moved': plan again). The app's default branch gone → a stop.
 */
async function recheck(gh: Octokit, plan: PhasePlan, clock: RateClock): Promise<'ok' | 'moved'> {
  const central = centralOf({ owner: plan.app.owner, repo: plan.app.repo });
  const changed = (what: string): never => {
    throw new UninstallError(`${what} changed since the preview, so pipegen sent nothing. Run \`pipegen uninstall\` again to see the new plan. Nothing was changed.`);
  };
  const c = await readRepo(gh, central, clock);
  if (c === null) changed(`The central repo ${show(`${central.owner}/${central.repo}`, 140)}`);
  const head = await readHead(gh, central, (c as { defaultBranch: string }).defaultBranch, clock);
  if (head === null) changed(`The default branch of ${show(`${central.owner}/${central.repo}`, 140)}`);
  const at = (await readTree(gh, central, head as string, clock)).entries.get(recordPath(plan.app.repo));
  if (at === undefined || at.sha !== plan.base.recordBlobSha) changed(`The install record ${recordPath(plan.app.repo)} in ${show(`${central.owner}/${central.repo}`, 140)}`);
  if (head !== plan.base.centralHead) changed(`The default branch of ${show(`${central.owner}/${central.repo}`, 140)}`);
  const appHead = await readHead(gh, { owner: plan.app.owner, repo: plan.app.repo }, plan.app.defaultBranch, clock);
  if (appHead === null) throw new UninstallError(`pipegen can't read the default branch ${show(plan.app.defaultBranch, 100)} of ${show(`${plan.app.owner}/${plan.app.repo}`, 140)} any more, so it sent nothing. Nothing was changed.`);
  return appHead === plan.base.appHead ? 'ok' : 'moved';
}

/**
 * The uninstall PR of run 1, built on the preview's commit and tree (plan.base): one commit removing pipegen's workflows, one removing the
 * other files pipegen created, one per revert (restore, strip, delete). null when there is nothing to change.
 */
async function uninstallPr(
  gh: Octokit, plan: PhasePlan, api: PhaseApi, clock: RateClock, branch: { head: string | undefined; set: (sha: string) => void },
): Promise<{ pr: { number: number; url: string }; opened: boolean } | DeleteOutcome | null> {
  const workflows = plan.removeFiles.filter((f) => f.repo === 'app' && f.path.startsWith('.github/workflows/')).map((f) => f.path);
  const files = plan.removeFiles.filter((f) => f.repo === 'app' && !f.path.startsWith('.github/workflows/')).map((f) => f.path);
  const reverts = plan.reverts.filter((x) => x.result.kind !== 'manual');
  if (workflows.length + files.length + reverts.length === 0) return null;
  const appRef: RepoRef = { owner: plan.app.owner, repo: plan.app.repo };
  // sec M2: pipegen/uninstall is moved only while it points where pipegen set it (absent: created); anything else is someone's work
  const now = await branchHead(api, appRef, UNINSTALL_PR_BRANCH);
  if (now !== null && now !== branch.head) {
    const full = `${appRef.owner}/${appRef.repo}`;
    return {
      status: 'leftover',
      why: `the branch ${UNINSTALL_PR_BRANCH} has commits pipegen didn't make (or this uninstall didn't set it), so pipegen doesn't move it`,
      manual: `Look at ${UNINSTALL_PR_BRANCH} in ${show(full, 140)}, keep what you need, then delete it (gh api -X DELETE repos/${full}/git/refs/heads/${UNINSTALL_PR_BRANCH}) and run \`pipegen uninstall\` again.`,
    };
  }
  const tree = await readTree(gh, appRef, plan.base.appHead, clock);
  if (tree.tree !== plan.base.appTree) throw new UninstallError('GitHub gives another file tree for the commit the preview read, so pipegen builds no uninstall pull request on it.');
  let parent = plan.base.appHead;
  let baseTree = plan.base.appTree;
  const commit = async (c: { files: { path: string; content: string; mode: string }[]; deletes: string[]; message: string }): Promise<void> => {
    const made = await api.commitUninstall('app', { parent, baseTree, ...c });
    parent = made.commit;
    baseTree = made.tree;
  };
  const lines: string[] = [];
  if (workflows.length > 0) {
    await commit({ files: [], deletes: workflows, message: 'pipegen uninstall: remove pipegen\'s workflows' });
    for (const p of workflows) lines.push(`- removes ${show(p, 200)}`);
  }
  if (files.length > 0) {
    await commit({ files: [], deletes: files, message: 'pipegen uninstall: remove the files pipegen created' });
    for (const p of files) lines.push(`- removes ${show(p, 200)}`);
  }
  for (const x of reverts) {
    const path = x.edit.path;
    const p = show(path, 200);
    if (x.result.kind === 'delete') {
      await commit({ files: [], deletes: [path], message: `pipegen uninstall: remove ${p} (pipegen made it)` });
      lines.push(`- removes ${p} (pipegen made it, and it held only pipegen's text)`);
      continue;
    }
    if (x.result.kind !== 'restore' && x.result.kind !== 'strip') continue;
    const e = tree.entries.get(path);
    if (!plainFile(e)) throw new UninstallError(`${p} is not a plain file in the commit the preview read, so pipegen doesn't change it.`);
    const restore = x.result.kind === 'restore';
    await commit({ files: [{ path, content: x.result.text, mode: e.mode }], deletes: [], message: restore ? `pipegen uninstall: put ${p} back to its version before pipegen` : `pipegen uninstall: take pipegen's part out of ${p}` });
    lines.push(restore ? `- ${p}: put back to the version before pipegen's first change` : `- ${p}: pipegen's part taken out, the rest kept as it is`);
  }
  await api.setUninstallBranch('app', parent);
  branch.set(parent);
  const shown = lines.length > 300 ? [...lines.slice(0, 300), `- and ${lines.length - 300} more`] : lines;
  const body = [
    `pipegen uninstall: this pull request removes pipegen from ${show(`${appRef.owner}/${appRef.repo}`, 140)}.`, '', ...shown, '',
    'pipegen took off its merge locks when it opened this pull request: it can\'t pass the gate it removes. Until you merge it, run `pipegen finish` to lock again.',
    'After you merge it, run `pipegen uninstall` again for the second run (secrets, variables, environments, settings, central).',
  ].join('\n');
  const o = await api.openUninstallPr('app', { base: plan.app.defaultBranch, title: PR_TITLE, body });
  return { pr: { number: o.number, url: o.url }, opened: o.opened };
}

/** The commit a branch of the app points at now (null: gone), read through the api. */
async function branchHead(api: PhaseApi, app: RepoRef, branch: string): Promise<string | null> {
  try {
    const d = (await api.read('GET /repos/{owner}/{repo}/git/ref/{ref}', { ...app, ref: `heads/${branch}` })).data;
    const sha = isObj(d) && isObj(d.object) ? d.object.sha : undefined;
    if (typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) throw new UninstallError(`GitHub's answer about the branch ${show(branch, 100)} could not be read.`);
    return sha;
  } catch (e) {
    if (statusOf(e) === 404) return null;
    throw e;
  }
}

/** The recorded uninstall PR on GitHub: merged (merged_at set), open, closed (unmerged), gone (404), or foreign (not pipegen's). */
async function prState(gh: Octokit, app: RepoRef, repoId: number, defaultBranch: string, n: number, clock: RateClock): Promise<'merged' | 'open' | 'closed' | 'gone' | 'foreign' | 'other-base'> {
  let d: unknown;
  try { d = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls/{pull_number}', app, { pull_number: n }, clock); } catch (e) {
    if (statusOf(e) === 404) return 'gone';
    throw e;
  }
  if (!isObj(d) || d.number !== n || !isObj(d.head) || d.head.ref !== UNINSTALL_PR_BRANCH || !isObj(d.head.repo) || d.head.repo.id !== repoId) return 'foreign';
  // sec M6: merged into another branch, its changes are not on the default branch
  if (!isObj(d.base) || d.base.ref !== defaultBranch) return 'other-base';
  if (typeof d.merged_at === 'string' && d.merged_at !== '') return 'merged';
  if (d.state === 'open') return 'open';
  if (d.state === 'closed') return 'closed';
  return 'foreign';
}

/**
 * The first workflow of pipegen's that still runs on the app's default branch (null: none): one of its four workflow paths, or any workflow
 * holding its verify job or head check. `kept` (workflows the user chose to keep in a run 1 that needed no PR) are passed over. Anything
 * pipegen can't read (the branch, too many workflows, a blob) counts as live (the safe side).
 */
async function liveWorkflow(gh: Octokit, loaded: LoadedRecord, clock: RateClock, kept: ReadonlySet<string> = new Set()): Promise<string | null> {
  const app: RepoRef = { owner: loaded.app.owner, repo: loaded.app.repo };
  const head = await readHead(gh, app, loaded.app.defaultBranch, clock);
  if (head === null) return loaded.app.defaultBranch;
  const { entries } = await readTree(gh, app, head, clock);
  const own = APP_WORKFLOWS.find((p) => entries.has(p) && !kept.has(p));
  if (own !== undefined) return own;
  const wf = [...entries].filter(([p, e]) => WORKFLOW_RE.test(p) && plainFile(e) && !kept.has(p));
  if (wf.length > MAX_SCANNED) return '.github/workflows';
  for (const [p, e] of wf) {
    let text: string;
    try { text = await readBlobText(gh, app, e.sha, MAX_WORKFLOW_BYTES, clock); } catch (x) {
      if (isRateStop(x) || x instanceof GitHubAccessError || statusOf(x) === 401) throw x;
      return p;
    }
    if (text.includes(VERIFY_JOB_ID) || text.includes(HEAD_CHECK_STEP_ID)) return p;
  }
  return null;
}

/**
 * V9a (V8 sec M4): the app's lease for `pipegen uninstall` (src/cli/uninstall.ts), taken before the record is loaded (the loader may write
 * this machine's local record file), and handed to uninstallStep (`deps.lease`). `release` gives it back, unless a stop is under way (the
 * exit hook drops it then, after the interrupt hooks). Another pipegen holding it → UninstallError, nothing read or sent.
 */
export async function holdUninstallLease(app: RepoRef, state: StateDeps | undefined): Promise<{ lease: StateStore; release: () => void }> {
  const lease = await takeLease({ owner: app.owner, repo: app.repo }, state);
  return { lease, release: () => { if (!interrupting()) lease.releaseLease(); } };
}

/** The app's lease (the proof's state folder): another pipegen run on this repo → a stop, nothing read or sent. */
async function takeLease(app: RepoRef, deps: StateDeps | undefined): Promise<StateStore> {
  try {
    const store = await StateStore.open(app, { ...deps, command: 'uninstall' });
    store.acquireLease(`uninstall-${randomBytes(6).toString('hex')}`, 'uninstall');
    return store;
  } catch (e) {
    if (e instanceof ProofStopError || e instanceof StateError) throw new UninstallError(`${(e as Error).message} Nothing was changed.`, { cause: e });
    throw e;
  }
}

function result(status: StepStatus, phase: UninstallPhase | null, lines: string[]): StepResult {
  return { status, phase, done: [], failed: [], skipped: [], manual: [], lines };
}
const declined = (phase: UninstallPhase): StepResult => result('declined', phase, ['pipegen uninstall stopped at your answer. Nothing was changed by this run.']);
function printLine(line: string): void { process.stdout.write(`${line}\n`); }
