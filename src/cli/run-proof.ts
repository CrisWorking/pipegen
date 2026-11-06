// v0.2 Plan G G14 (plan Task 8 stages 16-17, l. 504-505 and 511; contracts "Proof contracts" §4-§6 and "Debate contracts" §5-§8;
// rulings S2, S3, S20, B8, E-b21; ruling G14-R0): the production proof seam of `pipegen run` (RunDeps.proof) and its cleanup.
//
// The order (contracts §6):
//   1. the target (proofTarget, the saved run id), the scratch keys (readByWorkflows from the assembled proof workflows), the cleanup
//      closure (cleanupAfterProof with the token's canDeleteRepos, the signal and the meters); armed through the run's `arm`
//      (armProofCleanup) before the first GitHub write.
//   2. proveThenClean(store, prove, cleanup) with the default verdict. `prove` wraps everything from the first GitHub write:
//      checkProofRepos (createPermit from the armed store, has_wiki/has_projects off in target.ts), the minutes meter (proofStart, or
//      minutesForResume on a resume), pushProofSetup ONCE with scratchSecretStore (the only store outside the fix loop), the disputes
//      (after the setup, before the main merge; a judge win pushes main and planted again with the winners' files), then
//      proveWithFixes. The cleanup (secrets first, then branches, runs, artifacts, caches; the repo deleted only when the token may)
//      runs right after, on every path, before anything is shown (the run shows the preview only after this returns).
//   3. a stopped proof → { ok: false, stopped } (the run exits 2 with the reason). The returned draft is the fix loop's final
//      pre-assembly draft; the run builds and judges it again before delivery and delivers only the one saved with the pass.
// Never here: a clack spinner (it adds signal handlers; E-b1), a second assembler or meter (ProofInput's), isolatedTestJob, a flag that
// answers the mid-run confirmation.
import type { Octokit } from '@octokit/rest';
import { parseDocument } from 'yaml';
import type { CodeBundle } from '../ai/redact.js';
import type { SecretScanner } from '../ai/secret-scan-config.js';
import type { AiSpendMeter } from '../ai/spend-meter.js';
import { createDockerfile } from '../create/dockerfile.js';
import type { GuardResult } from '../create/guard.js';
import type { SecretVault } from '../create/secrets.js';
import { keyOffers, specFor, type Choice } from '../debate/builder.js';
import type { DebateResult } from '../debate/debate.js';
import { decideDisputes, optionRunOf, toolsByKey, type Decision } from '../debate/decide.js';
import { matchPlanted, plantedFiles } from '../debate/planted.js';
import type { PlatformActions } from '../engine/pin.js';
import type { RefereeReport } from '../engine/referee.js';
import { jobIdFor } from '../engine/gate-job-list.js';
import { CapReachedError, cancelActiveRuns, stopAtCap, type CapReached } from '../proof/caps.js';
import { cleanupAfterProof, minutesForResume, proveThenClean, saveStopState, type CleanupResult, type ProofMeters } from '../proof/cleanup.js';
import { evaluateProof, jobNameMatches, userMainStatuses, type EvalContext, type Evaluation, type VariantRuns } from '../proof/evaluate.js';
import { proveWithFixes, type FixDeps, type FixKeys, type FixOutcome, type ProofRun, type PushedWorkflow } from '../proof/fix.js';
import { readSnapshot } from '../proof/git.js';
import { HARNESS_PATH, proofAppFiles, type ProofAssemble } from '../proof/harness.js';
import { SCRATCH_FP_KEY, ScratchKeys, scratchSecretStore, workflowSecretNames } from '../proof/keys.js';
import { MinutesMeter, minutesStop, proofStart } from '../proof/minutes.js';
import { checkProofRepos, type ProofRepoOptions, type ProofRepos } from '../proof/repos.js';
import { proveVariant, rerunFailedJobs, resetBase, type ProofWorkflows, type RunOutcome, type VariantProof, type WaitOptions } from '../proof/run.js';
import { gitTransport, plantedSecretPlacements, pushProofBranch, pushProofSetup, type BaseSnapshot, type PlantedPlacement, type ProofBranch, type ProofFile, type ProofSession, type ProofSetup, type ProofSetupDeps, type ProofSetupInput, type ProofTransport, type SecretStoreStep, type Variant } from '../proof/snapshot.js';
import { prRecorder, proofTransport, type StateStore } from '../proof/state.js';
import { ProofStopError, proofTarget, type ProofTarget } from '../proof/target.js';
import type { Auth, CreatedFile, PipelineDraft, RepoProfile, ReviewedTool, StepSpec } from '../types.js';
import { interrupting, type InterruptContext } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import type { CliIO } from './io.js';

/** Each wait of a proof (the push runs, the PR runs, the merge runs). */
export const PROOF_WAIT_MS = 45 * 60_000;
export const REPOS_NOT_READY = 'pipegen stopped: the helper repositories above must exist first (see the commands). exit code 2.';
/** Plan l. 504: the mid-run screen, before AI-written code runs with the user's keys. */
export const CONFIRM_TITLE = 'pipegen\'s AI wrote or changed these files to make the proof pass. They ran with placeholder keys only so far:';
export const CONFIRM_QUESTION = 'Run them with your real test keys now? (No: pipegen drops these AI changes from what runs with your keys; the parts that need your keys end not proven.)';
/** A private app's proof pushes its central workflows once per proof (snapshot.ts: one central draft per session). */
export const CENTRAL_CHANGED = 'pipegen stopped the proof: a change would need pipegen\'s central workflows pushed again, which one proof can\'t do. Nothing was delivered. Run `npx pipegen run` again. exit code 2.';

/** The delivery build of one pre-assembly draft (the run's buildFiles with the facts it read), and the fix loop's referee and guard over it. */
export interface ProofBuild {
  /** buildFiles of `d` with the run's facts: the delivered files and AssembledFiles.draft. */
  rebuild(d: PipelineDraft): Promise<{ files: CreatedFile[]; assembled: PipelineDraft }>;
  /** makeFixReferee (seven arguments, AssembledFiles.draft) AND the guard on the same batch (D-m1): either one refusing is an issue. */
  referee: (d: PipelineDraft) => Promise<RefereeReport>;
  /** makeFixGuard: the guard on a part's files (the vault, the reviewed closure, the install record, the delivery base tree). */
  guard(files: CreatedFile[]): Promise<GuardResult>;
}

/** What the run gives the proof (RunDeps.proof). */
export interface ProofInput {
  /** The draft before assembly: what the proof's fix loop changes and returns. `assembled`: AssembledFiles.draft of `files`. */
  draft: PipelineDraft; assembled: PipelineDraft; files: readonly CreatedFile[];
  /** G13's proofAssembler for the pre-proof build (signing none, the proof layout). */
  assemble: ProofAssemble;
  /** G14: the proof assembler for any draft of the run (the security review's carry: the fix loop's draft, not only the pre-proof one). */
  assembleFor: (d: PipelineDraft) => Promise<ProofAssemble>;
  /** The run's delivery build for the fix loop (absent: the proof refuses to start, fail closed). */
  build?: ProofBuild;
  store: StateStore; auth: Auth & { token?: string | null }; gh: Octokit; vault: SecretVault;
  /** The run's one meter (carry 47): every AI closure goes through `meter.provider`. */
  ai: { meter: AiSpendMeter };
  io: CliIO;
  /** The debate (disputes, choices, needs, candidates); absent on a resume (the winners are already in the saved draft). */
  debate?: DebateResult;
  /** Decision.winners applied by key over DebateResult.choices, through draftFromDebate (carry 22). */
  withWinners?: (winners: ReadonlyMap<string, Choice>) => PipelineDraft;
  reviewed: ReviewedTool[]; platform: PlatformActions; dir: string;
  /** The checked code bundle (absent on a resume: then no Dockerfile is made again). */
  bundle?: CodeBundle;
  /** The pinned secret scanner errorExcerpt runs. */
  scanner: () => Promise<SecretScanner>;
  /** The run's arm (armProofCleanup through RunDeps.arm): before the first GitHub write. */
  arm: (cleanup: (ctx: InterruptContext) => Promise<unknown>, meters: () => ProofMeters | undefined) => void;
  /** About how many Actions minutes one variant's runs take (the consent's setup minutes over its two variants): disputes fit the cap. */
  variantMinutes: number;
  /** A resume (S20): the minutes come from minutesForResume, the AI meter is already restored, no dispute runs. */
  resume?: boolean;
  /** Stage 8, checkProofRepos as the run wires it (createPermit from the armed store, onCreated, onAccessChanged); default: ops.checkRepos. */
  checkRepos?: () => Promise<ProofRepos>;
}
export interface ProofReturn { ok: boolean; draft?: PipelineDraft; stopped?: string; repos?: ProofRepos; cleanup?: CleanupResult; notes?: string[] }
export type RunProof = (i: ProofInput) => Promise<ProofReturn>;

/** Every GitHub-touching call of the proof, one seam each (tests inject fakes; the defaults are the real Plan E modules). */
export interface ProofOps {
  checkRepos: (gh: Octokit, app: Parameters<typeof checkProofRepos>[1], opts: ProofRepoOptions, io: CliIO) => Promise<ProofRepos>;
  start: (gh: Octokit, t: ProofTarget) => Promise<{ at: number; fromServer: boolean }>;
  resumeMinutes: typeof minutesForResume;
  minutesStop: (gh: Octokit, t: ProofTarget, m: MinutesMeter) => () => Promise<boolean>;
  basePaths: (dir: string) => Promise<ReadonlySet<string>>;
  keys: (gh: Octokit, t: ProofTarget, vault: SecretVault, deps: ConstructorParameters<typeof ScratchKeys>[3]) => FixKeys & { readonly mode: FixKeys['mode'] };
  secretStore: (keys: FixKeys, names: readonly string[]) => SecretStoreStep;
  transport: (token: string) => ProofTransport;
  setup: (input: ProofSetupInput, deps: ProofSetupDeps) => Promise<ProofSetup>;
  pushBranch: (s: ProofSession, variant: Variant, commits: readonly (readonly ProofFile[])[], deps: { transport: ProofTransport; pipegenWorkflows: ReadonlySet<string>; parent?: string; round?: number }) => Promise<ProofBranch>;
  resetBase: (s: ProofSession, base: BaseSnapshot, transport: ProofTransport) => Promise<void>;
  variant: (gh: Octokit, t: ProofTarget, v: { branch: ProofBranch; merge: boolean; workflows: ProofWorkflows; pr?: number; keepOpen?: boolean }, opts: WaitOptions) => Promise<VariantProof>;
  rerunFailed: (gh: Octokit, t: ProofTarget, runs: readonly { handle: RunOutcome['handle']; attempt: number }[], opts: WaitOptions) => Promise<RunOutcome[]>;
  evaluate: (d: PipelineDraft, runs: readonly VariantRuns[], ctx: EvalContext) => Promise<Evaluation>;
  userMain: (gh: Octokit, p: RepoProfile) => Promise<ReadonlyMap<string, 'success' | 'failure' | 'none'>>;
  cancelActive: (gh: Octokit, t: ProofTarget, since: number) => Promise<unknown>;
  cleanup: typeof cleanupAfterProof;
  placements: (basePaths: ReadonlySet<string>, ignore: Uint8Array | null) => { files: ProofFile[]; expected: PlantedPlacement[] };
  fixLoop: typeof proveWithFixes;
  decide: typeof decideDisputes;
  /** proofAppFiles (the assembled files at signing none, the harness, the compat copies of HEAD). */
  appFiles: typeof proofAppFiles;
}

export const realProofOps: ProofOps = {
  checkRepos: (gh, app, opts, io) => checkProofRepos(gh, app, opts, io),
  start: (gh, t) => proofStart(gh, t),
  resumeMinutes: minutesForResume,
  minutesStop: (gh, t, m) => minutesStop(gh, t, m),
  basePaths: async (dir) => new Set((await readSnapshot(dir)).files.map((f) => f.path)),
  keys: (gh, t, vault, deps) => new ScratchKeys(gh, t, vault, deps),
  secretStore: (keys, names) => scratchSecretStore(keys as ScratchKeys, names),
  transport: (token) => gitTransport(token),
  setup: pushProofSetup,
  pushBranch: pushProofBranch,
  resetBase,
  variant: (gh, t, v, opts) => proveVariant(gh, t, v, opts),
  rerunFailed: rerunFailedJobs,
  evaluate: evaluateProof,
  userMain: userMainStatuses,
  cancelActive: (gh, t, since) => cancelActiveRuns(gh, t, since),
  cleanup: cleanupAfterProof,
  placements: (basePaths, ignore) => plantedSecretPlacements(basePaths, { existingIgnore: ignore }),
  fixLoop: proveWithFixes,
  decide: decideDisputes,
  appFiles: proofAppFiles,
};

const isWorkflow = (path: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path);

/**
 * The ProofWorkflows of a file set (sec I1): which workflow files run on a push of the proof branch `at.branch`, which on its PR (to the
 * default branch), and which on the merge commit's push to `at.defaultBranch`. Each event's `branches` / `branches-ignore` and
 * `paths` / `paths-ignore` filters are applied (GitHub's filter patterns: `*`, `**`, `?`, a leading `!`); the changed paths are the
 * set's own files. `on:` is read as YAML.
 */
export function proofWorkflowsOf(files: readonly { path: string; content: string | Uint8Array }[], at: { branch: string; defaultBranch: string }): ProofWorkflows {
  const push: string[] = [];
  const pullRequest: string[] = [];
  const merge: string[] = [];
  const changed = files.map((f) => f.path);
  for (const f of files) {
    if (!isWorkflow(f.path)) continue;
    const text = typeof f.content === 'string' ? f.content : Buffer.from(f.content).toString('utf8');
    const on: unknown = parseDocument(text).toJS()?.on;
    const events: Record<string, unknown> = typeof on === 'string' ? { [on]: null } : Array.isArray(on) ? Object.fromEntries(on.map((e) => [String(e), null])) : typeof on === 'object' && on !== null ? on as Record<string, unknown> : {};
    if (Object.hasOwn(events, 'push') && runsOn(events.push, at.branch, changed)) push.push(f.path);
    if (Object.hasOwn(events, 'pull_request') && runsOn(events.pull_request, at.defaultBranch, changed)) pullRequest.push(f.path);
    if (Object.hasOwn(events, 'push') && runsOn(events.push, at.defaultBranch, changed)) merge.push(f.path);
  }
  return { push, pullRequest, merge };
}

/** One event's filters against a branch and the changed paths (GitHub's rules: a filter it can't read means no run, fail closed). */
function runsOn(cfg: unknown, branch: string, changed: readonly string[]): boolean {
  if (cfg === null || cfg === undefined) return true;
  if (typeof cfg !== 'object' || Array.isArray(cfg)) return false;
  const c = cfg as Record<string, unknown>;
  const list = (k: string): string[] | null | undefined => (c[k] === undefined ? undefined : Array.isArray(c[k]) ? (c[k] as unknown[]).map(String) : typeof c[k] === 'string' ? [c[k] as string] : null);
  const br = list('branches'), brIgnore = list('branches-ignore'), paths = list('paths'), pathsIgnore = list('paths-ignore');
  if (br === null || brIgnore === null || paths === null || pathsIgnore === null) return false;
  if (br !== undefined && !filterMatches(br, branch)) return false;
  if (brIgnore !== undefined && brIgnore.some((x) => globMatch(x, branch))) return false;
  if (paths !== undefined && !changed.some((x) => filterMatches(paths, x))) return false;
  if (pathsIgnore !== undefined && changed.every((x) => pathsIgnore.some((g) => globMatch(g, x)))) return false;
  return true;
}
/** A filter list with `!` negations: the last pattern that matches decides. */
function filterMatches(patterns: readonly string[], value: string): boolean {
  let hit = false;
  for (const raw of patterns) {
    const neg = raw.startsWith('!');
    if (globMatch(neg ? raw.slice(1) : raw, value)) hit = !neg;
  }
  return hit;
}
/** GitHub's filter pattern: `**` any characters, `*` any but `/`, `?` one character; the rest literal. */
function globMatch(pattern: string, value: string): boolean {
  let re = '';
  for (let k = 0; k < pattern.length; k++) {
    const ch = pattern[k] as string;
    if (ch === '*' && pattern[k + 1] === '*') { re += '.*'; k++; } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '.';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`).test(value);
}

/** One proof's files of a draft: the central draft (private apps) and the app branch's files (assembled at signing none, the created app files, the harness, the compat copies). */
interface DraftFiles { central: CreatedFile[]; app: CreatedFile[]; last: ReturnType<ReturnType<typeof proofAppFiles>['last']> }
const fileKey = (fs: readonly { path: string; content: string | Uint8Array }[]): string =>
  JSON.stringify([...fs].map((f) => [f.path, typeof f.content === 'string' ? f.content : Buffer.from(f.content).toString('base64')]).sort());

/**
 * The production RunProof (see the file header). `ops` replaces the GitHub-touching calls (tests); a real run passes none.
 */
export function makeRunProof(over: Partial<ProofOps> = {}): RunProof {
  const o: ProofOps = { ...realProofOps, ...over };
  return async (i) => {
    const { store, gh, vault, io, auth } = i;
    const token = typeof auth.token === 'string' ? auth.token : '';
    const st0 = store.state;
    if (st0 === null) throw new Error('The proof needs the run\'s state.');
    if (i.build === undefined) throw new Error('pipegen has no referee for the proof\'s fix loop in this run, so nothing was proven.');
    const build = i.build;
    const p = i.draft.profile;
    const t = proofTarget(st0.app, { runId: st0.runId });
    const meter = i.ai.meter;
    let minutes: MinutesMeter | null = null;
    let fromServer: boolean | undefined;
    const meters = (): ProofMeters => ({ ai: meter, ...(minutes === null ? {} : { minutes }), ...(fromServer === undefined ? {} : { fromServer }) });
    const notes: string[] = [];
    const say = (l: string): void => { notes.push(l); io.err(safeText(l, 600)); };

    // the files of a draft for the proof: the run's proof assembler for it (signing none, the proof layout), split by repo
    const created = async (d: PipelineDraft): Promise<CreatedFile[]> => (await build.rebuild(d)).assembled.created.filter((f) => f.repo === 'app');
    const filesOf = async (d: PipelineDraft, centralSha: string | undefined): Promise<DraftFiles> => {
      const asm = await i.assembleFor(d);
      const own = await created(d);
      const appOnly: ProofAssemble = async (mode, sha) => [...own, ...(await asm(mode, sha)).filter((f) => f.repo === 'app')];
      const paf = o.appFiles(d, { assemble: appOnly, harness: { platform: i.platform, reviewed: i.reviewed, createdTests: false, signing: d.signing?.mode ?? 'none' }, dir: i.dir });
      const central = d.centralPin === undefined ? [] : (await asm('none', undefined)).filter((f) => f.repo === 'central');
      const app = await paf.appFiles(centralSha);
      return { central, app, last: paf.last() };
    };
    // C1 (G14-R1): one computation per draft and central sha, so a proof never runs files other than the draft's own (no stale set)
    const cache = new WeakMap<PipelineDraft, Map<string, Promise<DraftFiles>>>();
    const filesAt = (d: PipelineDraft, centralSha: string | undefined): Promise<DraftFiles> => {
      let byKey = cache.get(d);
      if (byKey === undefined) { byKey = new Map(); cache.set(d, byKey); }
      const k = centralSha ?? '';
      let f = byKey.get(k);
      if (f === undefined) { f = filesOf(d, centralSha); byKey.set(k, f); }
      return f;
    };
    const pushed = (f: DraftFiles): PushedWorkflow[] => [...f.app.filter((x) => isWorkflow(x.path)), ...f.central.filter((x) => isWorkflow(x.path))].map((x) => ({ path: x.path, content: x.content }));
    const pipegenWorkflows = (f: DraftFiles): Set<string> => new Set(f.app.filter((x) => isWorkflow(x.path)).map((x) => x.path));
    // sec M3: the workflows a proof's evaluation reads (the main proof and every dispute option alike): never the harness or a compat copy
    const evalWorkflows = (f: DraftFiles): string[] => [...pipegenWorkflows(f)].filter((x) => x !== HARNESS_PATH && !x.startsWith('.github/workflows/pipegen-compat-'));
    const workflowsAt = (f: DraftFiles, br: ProofBranch): ProofWorkflows => proofWorkflowsOf(f.app, { branch: br.branch, defaultBranch: t.defaultBranch });

    // C1 (G14-R1): a private app proves ONE central draft per session (Plan E), so its disputes are decided before the setup, without a
    // proof run, and the setup pushes (and the proof runs) the winners' central workflows
    const debate = i.debate;
    const disputes = i.resume !== true && debate !== undefined && debate.disputes.length > 0 ? debate : undefined;
    let startDraft = i.draft;
    if (disputes !== undefined && p.private) {
      const planted0 = plantedFiles(p, { basePaths: await o.basePaths(i.dir) });
      const decision = await o.decide(disputes.disputes, {
        expected: planted0.expected, placements: [], choices: disputes.choices, canProve: () => false,
        prove: async () => { throw new ProofStopError('pipegen proves no dispute of a private app.'); },
      });
      startDraft = winnersDraft(i, decision, startDraft, (l) => l.replace(MINUTES_REASON, PRIVATE_REASON));
    }

    // E-b11: the scratch keys read the names of the assembled proof workflows
    const first = await filesAt(startDraft, undefined);
    const readBy = workflowSecretNames(pushed(first));
    const raw = o.keys(gh, t, vault, { io, leftover: (x) => store.record(x), ...(readBy === null ? {} : { readByWorkflows: readBy }) });
    const keys = guardedKeys(raw, store);
    const cleanup = (signal?: AbortSignal): Promise<CleanupResult> => o.cleanup(gh, t, store, raw as unknown as ScratchKeys, {
      canDeleteRepo: auth.canDeleteRepos === true, meters, ...(signal === undefined ? {} : { signal }),
    });
    // contracts §6 step 4: arm before the first GitHub write (only through armProofCleanup, the run's `arm`)
    i.arm((ctx) => cleanup(ctx.signal), meters);
    // the draft the proof starts from, saved for a resume (S20), then the stage (S3: 16 proving)
    if (i.resume !== true) {
      store.update((n) => { n.draft = structuredClone(startDraft); });
      store.setStage('proving');
    }

    let repos: ProofRepos | undefined;
    const declined = new Set<string>();
    // spec M2: the draft the latest proof ran (the fix loop's), saved with a stop's verdict
    let latest = startDraft;
    const prove = async (): Promise<FixOutcome> => {
      // 8. the helper repos, inside prove (E-a7, ruling G14-R0 1): a throw here is cleaned up too
      repos = i.checkRepos !== undefined ? await i.checkRepos() : await o.checkRepos(gh, st0.app, {
        auth, actions: proofActionsOf(i.reviewed), runId: t.runId,
        onCreated: (name, id) => { if (name === t.scratch) store.scratchCreated(id); },
        onAccessChanged: (previous) => { store.recordActionsAccess(previous); },
        createPermit: () => store.createPermit(),
      }, io);
      if (!repos.ready) throw new ProofStopError(REPOS_NOT_READY);
      // contracts §6 step 6 (and step 2 on a resume): the minutes meter from GitHub's clock
      if (i.resume === true) {
        minutes = await o.resumeMinutes(gh, t, store.state as NonNullable<typeof store.state>, { store });
      } else {
        const start = await o.start(gh, t);
        fromServer = start.fromServer;
        minutes = new MinutesMeter((store.state as NonNullable<typeof store.state>).cap, start.at);
        store.saveMeters({ minutes: { used: 0, since: start.at, fromServer: start.fromServer }, aiUsedUsd: meter.usedUsd });
      }
      const m = minutes;
      const transport = stoppable(proofTransport(o.transport(token), store));
      const wait: WaitOptions = {
        timeoutMs: PROOF_WAIT_MS, shouldStop: o.minutesStop(gh, t, m), recordPr: prRecorder(store), leftover: (x) => store.record(x),
        onTick: () => { store.saveMeters({ minutes: { used: m.used, since: m.since }, aiUsedUsd: meter.usedUsd }); },
      };
      // the planted files (F-8): basePaths from HEAD; the names every proof workflow reads get placeholders (E-a2: stored here, once)
      const basePaths = await o.basePaths(i.dir);
      const planted = plantedFiles(p, { basePaths });
      const names = [...new Set([...vault.names(), ...(readBy ?? [])])];
      let stores = 0;
      const storeStep: SecretStoreStep = async (scratch, ctx) => {
        if (++stores > 1) throw new ProofStopError('pipegen stores the scratch secrets once before the proof; nothing was stored again.');
        if (interrupting()) throw new ProofStopError('pipegen is stopping; no secret is stored.');
        store.recordSecretNames([...names, SCRATCH_FP_KEY]);
        await o.secretStore(raw, names)(scratch, ctx);
      };
      const setup = await o.setup({
        target: t, dir: i.dir, ...(repos.defaultBranchState === undefined ? {} : { defaultBranchState: repos.defaultBranchState }),
        ...(first.central.length === 0 ? {} : { central: { files: first.central } }),
        appFiles: async (sha) => (await filesAt(startDraft, sha)).app, plantedFiles: planted.files,
        dockerServices: p.services.filter((s) => s.dockerfile !== undefined || startDraft.created.some((f) => f.path === dockerfileAt(s))),
      }, { gh, transport, io, storeSecrets: storeStep });
      const centralSha = setup.centralSha;
      const centralKey = fileKey(first.central);
      const ctxOf = (f: DraftFiles, placements: readonly PlantedPlacement[]): EvalContext => ({
        userMain: userMainMap, notCompared: f.last?.compat.notCompared ?? [], planted: placements, plantedItems: planted.expected, matchPlanted,
        keys: raw.mode, harnessJobs: f.last?.harness.jobs.map((j) => j.id) ?? [], harnessNotes: f.last?.harness.notes ?? [], carried: setup.notProven,
        pipegenWorkflows: evalWorkflows(f), minutesUsed: m.used,
      });
      const userMainMap = await o.userMain(gh, p);

      // the current branches: main and planted as the setup pushed them
      let cur: { d: PipelineDraft; files: DraftFiles; main: ProofBranch; planted: ProofBranch; placements: readonly PlantedPlacement[] } = {
        d: startDraft, files: await filesAt(startDraft, centralSha), main: setup.branches.main, planted: setup.branches.planted, placements: setup.planted,
      };
      // C1: the files the setup pushed are the start draft's, central included (anything else stops the proof)
      if (fileKey(cur.files.central) !== centralKey) throw new ProofStopError(CENTRAL_CHANGED);
      let round = 1;
      let merged = false;
      // sec M2: main and planted of a draft as a fresh round off the base, with fresh C1b placements
      const freshRound = async (d: PipelineDraft, f: DraftFiles): Promise<typeof cur> => {
        round++;
        if (merged) { await o.resetBase(setup.session, setup.base, transport); merged = false; }
        const c1b = o.placements(setup.base.paths, setup.base.gitleaksIgnore);
        const main = await o.pushBranch(setup.session, 'main', [f.app], { transport, pipegenWorkflows: pipegenWorkflows(f), round });
        const pl = await o.pushBranch(setup.session, 'planted', [[...f.app, ...planted.files, ...c1b.files]], { transport, pipegenWorkflows: pipegenWorkflows(f), round });
        return { d, files: f, main, planted: pl, placements: c1b.expected };
      };

      // F-7: a public app's disputes, after pushProofSetup and before the main merge
      if (disputes !== undefined && !p.private) {
        const decision: Decision = await o.decide(disputes.disputes, {
          expected: planted.expected, placements: setup.planted, choices: disputes.choices,
          // the minutes meter: the next dispute's runs must fit what is left of the cap
          canProve: (runs) => m.cap - m.used >= runs * Math.max(1, i.variantMinutes),
          prove: async (variant, choices) => {
            const od = withSteps(cur.d, choices);
            const f = await filesAt(od, centralSha);
            if (fileKey(f.central) !== centralKey) throw new ProofStopError(CENTRAL_CHANGED);
            const c1b = o.placements(setup.base.paths, setup.base.gitleaksIgnore);
            const br = await o.pushBranch(setup.session, variant, [[...f.app, ...planted.files, ...c1b.files]], { transport, pipegenWorkflows: pipegenWorkflows(f) });
            const vp = await o.variant(gh, t, { branch: br, merge: false, workflows: workflowsAt(f, br), keepOpen: false }, wait);
            return { run: optionRunOf({ variant, ...vp }, { optionLabel: variant, expected: planted.expected, placements: c1b.expected, toolOfKey: toolsByKey(choices), pipegenWorkflows: evalWorkflows(f) }) };
          },
        });
        // carry 22: the winners by key over the debate's choices, through draftFromDebate; the scoreboard as it is
        const draft = winnersDraft(i, decision, cur.d);
        // a judge win: main and planted again with the winners' files (a fresh round off the base), before the main merge
        const f = await filesAt(draft, centralSha);
        if (fileKey(f.central) !== centralKey) throw new ProofStopError(CENTRAL_CHANGED);
        cur = fileKey(f.app) !== fileKey(cur.files.app) ? await freshRound(draft, f) : { ...cur, d: draft, files: f };
      }

      // FixDeps.prove: the first call runs the branches as pushed; every later one a fresh round off the base (B3)
      let calls = 0;
      let last: { d: PipelineDraft; files: DraftFiles; runs: VariantRuns[]; placements: readonly PlantedPlacement[] } | null = null;
      const proveDraft = async (d: PipelineDraft, scope: 'pr' | 'full'): Promise<ProofRun> => {
        // C1: the draft's own files, every call; a central change after the setup can't be pushed again (one central draft per session)
        const f = await filesAt(d, centralSha);
        if (fileKey(f.central) !== centralKey) throw new ProofStopError(CENTRAL_CHANGED);
        latest = d;
        let { main, planted: pl, placements } = cur;
        if (calls > 0 || fileKey(f.app) !== fileKey(cur.files.app)) {
          const r = await freshRound(d, f);
          main = r.main; pl = r.planted; placements = r.placements;
        }
        calls++;
        const mv = await o.variant(gh, t, { branch: main, merge: scope === 'full', workflows: workflowsAt(f, main) }, wait);
        if (mv.mergeSha !== undefined) merged = true;
        const pv = await o.variant(gh, t, { branch: pl, merge: false, workflows: workflowsAt(f, pl), keepOpen: false }, wait);
        const runs: VariantRuns[] = [{ variant: 'main', ...mv }, { variant: 'planted', ...pv }];
        last = { d, files: f, runs, placements };
        const ev = await o.evaluate((await build.rebuild(d)).assembled, runs, ctxOf(f, placements));
        // E-a3, E-a4: the evidence only from evaluateProof; the full pushed set of workflows
        return { result: ev.result, evidence: ev.evidence, workflows: pushed(f) };
      };
      // FixDeps.rerun: the failed jobs again, then the WHOLE latest proof evaluated with those attempts put in (E-a3, E-b14)
      const rerun = async (runIds: readonly number[]): Promise<ProofRun> => {
        const l = last;
        if (l === null) throw new ProofStopError('pipegen has no proof to re-run.');
        const outs = l.runs.flatMap((r) => r.outcomes);
        const picked = outs.filter((x) => runIds.includes(x.handle.runId)).map((x) => ({ handle: x.handle, attempt: x.attempt }));
        const again = await o.rerunFailed(gh, t, picked, wait);
        const runs = l.runs.map((r) => ({ ...r, outcomes: r.outcomes.map((x) => again.find((a) => a.handle.runId === x.handle.runId) ?? x) }));
        last = { ...l, runs };
        const ev = await o.evaluate((await build.rebuild(l.d)).assembled, runs, ctxOf(l.files, l.placements));
        return { result: ev.result, evidence: ev.evidence, workflows: pushed(l.files) };
      };

      const fix: FixDeps = {
        ai: meter.provider,
        prove: proveDraft, rerun,
        nextCandidate: nextCandidateFrom(i.resume === true ? undefined : i.debate, p, i.reviewed, () => last?.runs ?? []),
        ...(i.bundle === undefined ? {} : { dockerfileFor: dockerfileFrom(i.bundle, meter) }),
        referee: (d) => build.referee(d),
        guard: (files) => build.guard(files),
        keys, vault, scanner: await i.scanner(), secretNames: names,
        workflowsOf: async (d) => pushed(await filesAt(d, centralSha)),
        confirm: async (files) => {
          const yes = await midRunConfirm(io)(files);
          if (!yes) for (const f of files) declined.add(f.path);
          return yes;
        },
        meters: { minutes: m, ai: meter },
        // E-b18, G0-R1 I2: stopAtCap with saveStopState; its CapReachedError is the loop's stop (it returns `stopped` with its draft)
        onCap: async (cap: CapReached) => {
          try {
            await stopAtCap(cap, { cancelRuns: () => o.cancelActive(gh, t, m.since), saveState: saveStopState(store, meters), cleanup: () => cleanup() });
          } catch (e) {
            if (!(e instanceof CapReachedError)) throw e;
          }
        },
        log: say,
      };
      const out = await o.fixLoop(cur.d, fix);
      return declined.size === 0 ? out : dropDeclined(out, declined);
    };

    let res: { outcome: FixOutcome; cleanup: CleanupResult };
    try {
      res = await proveThenClean(store, prove, () => cleanup(), undefined, { stopDraft: () => latest });
    } catch (e) {
      if (e instanceof ProofStopError) {
        // spec M2: proveThenClean saved the latest draft the proof ran with a failed verdict (stopDraft)
        return { ok: false, stopped: stopLine(e.message), ...(repos === undefined ? {} : { repos }), notes };
      }
      throw e;
    }
    const out = res.outcome;
    if (res.cleanup.message !== undefined) say(res.cleanup.message);
    for (const l of res.cleanup.leftovers) say(`Left behind: ${l}`);
    const saved = store.state;
    const ok = saved?.stage === 'cleaned' && saved.proofOk === true;
    if (!ok) {
      const why = out.stopped ?? out.result.parts.filter((x) => x.status === 'failed').map((x) => `${x.part}${x.needId === undefined ? '' : ` (${x.needId})`}: ${x.detail}`).join('; ');
      return { ok: false, draft: out.draft, stopped: stopLine(why === '' ? 'the proof did not pass' : why), ...(repos === undefined ? {} : { repos }), cleanup: res.cleanup, notes };
    }
    return { ok: true, draft: out.draft, ...(repos === undefined ? {} : { repos }), cleanup: res.cleanup, notes };
  };
}

/** The fix loop's words for a part whose AI-written files the user declined to run with the keys. */
export const DECLINED_REASON = 'you chose not to run AI-written code with your keys, so pipegen left those files out';
const FLOOR_PARTS: ReadonlySet<string> = new Set(['pipeline', 'deploy-verify']);
/**
 * Plan l. 504 (carry 29): a declined mid-run confirmation drops those AI-written files from the draft (they never run with the real keys and
 * are never delivered); their parts end not proven. A pipeline, deploy-verify or a tests part the floor needs can't end not proven: no pass.
 */
export function dropDeclined(out: FixOutcome, declined: ReadonlySet<string>): FixOutcome {
  const gone = out.draft.created.filter((f) => f.repo === 'app' && declined.has(f.path));
  if (gone.length === 0) return out;
  const parts = [...new Set(gone.map((f) => f.part))];
  const testsFloor = out.draft.needs.some((n) => n.floor === true && /tests$/.test(n.category ?? n.id)) && !out.draft.skipped.some((x) => x.part === 'tests');
  // sec M1: every part whose jobs read a dropped path ran with a file that is not delivered: not proven either. A job reads the paths of
  // its service (the service's folder; a service at the root reads every path). Repo-wide jobs (no service) only scan text, and a file
  // less never adds a finding, so they keep their result.
  const owners = new Set(out.draft.profile.services.filter((sv) => gone.some((f) => owns(sv.path, f.path))).map((sv) => sv.name));
  const readers = out.draft.steps.filter((st) => st.service !== undefined && owners.has(st.service)).map((st) => st.needId);
  const hit = out.result.parts.filter((x) => x.needId !== undefined && readers.includes(x.needId) && x.status === 'proven');
  const floorNeed = hit.some((x) => out.draft.needs.some((n) => n.id === x.needId && n.floor === true));
  const floorHit = floorNeed || parts.some((x) => FLOOR_PARTS.has(x) || (x === 'tests' && testsFloor));
  const add = [
    ...parts.map((part) => ({ part, missingSecrets: [], reason: DECLINED_REASON })),
    ...hit.map((x) => ({ part: x.part, needId: x.needId as string, missingSecrets: [], reason: `${DECLINED_REASON} (this job read them)` })),
  ].filter((n) => !out.draft.notProven.some((o) => o.part === n.part && o.reason === n.reason && o.needId === (n as { needId?: string }).needId));
  const notProven = [...out.draft.notProven, ...add];
  const draft: PipelineDraft = { ...out.draft, created: out.draft.created.filter((f) => !gone.includes(f)), notProven } as PipelineDraft;
  const result = { ...out.result, parts: out.result.parts.map((x) => (hit.includes(x) ? { ...x, status: 'not-proven' as const, detail: DECLINED_REASON } : x)) };
  return floorHit
    ? { ...out, draft, result: { ...result, ok: false }, stopped: `${out.stopped === undefined ? '' : `${out.stopped}; `}${DECLINED_REASON}, and the ${[...parts, ...hit.map((x) => x.needId as string)].join(', ')} part must be proven` }
    : { ...out, draft, result };
}
const owns = (servicePath: string, path: string): boolean => {
  const sp = servicePath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '');
  return sp === '' || sp === '.' || path === sp || path.startsWith(`${sp}/`);
};

/**
 * A resumed run whose proof passed but whose cleanup didn't finish (stage proven): the same cleanup (cleanupAfterProof with the token's
 * canDeleteRepos), then the stage cleaned.
 */
export function makeCleanupOnly(over: Partial<ProofOps> = {}) {
  const o: ProofOps = { ...realProofOps, ...over };
  return async (i: Pick<ProofInput, 'store' | 'gh' | 'vault' | 'io' | 'auth' | 'ai'>): Promise<CleanupResult> => {
    const st0 = i.store.state;
    if (st0 === null) throw new Error('The cleanup needs the run\'s state.');
    const t = proofTarget(st0.app, { runId: st0.runId });
    const keys = o.keys(i.gh, t, i.vault, { io: i.io, leftover: (x) => i.store.record(x) });
    // carry 14: the meters reach the cleanup (the AI spend restored on the resume's meter)
    const r = await o.cleanup(i.gh, t, i.store, keys as unknown as ScratchKeys, { canDeleteRepo: i.auth.canDeleteRepos === true, meters: () => ({ ai: i.ai.meter }) });
    i.store.setStage('cleaned');
    return r;
  };
}

/** decide.ts's words for a dispute it decided without a run for lack of minutes; a private app's real reason replaces them (C1). */
const MINUTES_REASON = 'not enough Actions minutes are left for it';
export const PRIVATE_REASON = 'a private app proves one central draft per session, so no option ran on its own';
/** Carry 22: the winners by key over the debate's choices (through draftFromDebate), with the scoreboard as decide wrote it. */
function winnersDraft(i: Pick<ProofInput, 'withWinners'>, decision: Decision, d: PipelineDraft, line: (l: string) => string = (l) => l): PipelineDraft {
  const won = i.withWinners === undefined ? withSteps(d, [...decision.winners.values()]) : i.withWinners(decision.winners);
  return { ...won, scoreboard: decision.scoreboard.map(line) };
}

const stopLine = (why: string): string => `pipegen stopped: the proof did not pass (${safeText(why, 900)}), so nothing was delivered. exit code 2.`;

/** The actions the proof runs: every pinned reviewed action (checkProofRepos checks the scratch repo's Actions settings against them). */
const proofActionsOf = (reviewed: readonly ReviewedTool[]): string[] =>
  reviewed.filter((x) => x.candidate.kind === 'action' && typeof x.candidate.pin.sha === 'string').map((x) => `${x.candidate.repo}@${x.candidate.pin.sha as string}`);

/** E-ledger: no push starts once a stop has begun (interrupting(), checked before each push). */
function stoppable(tr: ProofTransport): ProofTransport {
  return { push: (to, from, refs, opts) => { if (interrupting()) throw new ProofStopError('pipegen is stopping; no push starts.'); return tr.push(to, from, refs, opts); } };
}

/**
 * The fix loop's keys (E-b17, E-ledger): store.recordSecretNames before every store; interrupting() checked before the real keys (and
 * every store). The loop itself decides when the real keys go in (after the mid-run confirmation).
 */
export function guardedKeys(keys: FixKeys, store: Pick<StateStore, 'recordSecretNames'>): FixKeys {
  const before = (names: readonly string[], real: boolean): void => {
    if (interrupting()) throw new ProofStopError(real ? 'pipegen is stopping; your real test keys are not stored.' : 'pipegen is stopping; no secret is stored.');
    store.recordSecretNames(real ? [...names] : [...names, SCRATCH_FP_KEY]);
  };
  return {
    get mode() { return keys.mode; },
    get lastRefusal() { return keys.lastRefusal; },
    setup: async (n) => { before(n, false); await keys.setup(n); },
    placeholders: async (n) => { before(n, false); await keys.placeholders(n); },
    real: async (n) => { before(n, true); await keys.real(n); },
    deleteAll: (opts) => keys.deleteAll(opts),
    ticket: (opts) => keys.ticket(opts),
    evidence: (tk, ids, opts) => keys.evidence(tk, ids, opts),
    scrubber: () => keys.scrubber(),
  } as FixKeys;
}

/**
 * Plan l. 504 (carry 29): the mid-run screen. Lists the AI-written files and asks once; no terminal (CI) is a no (ruling G14-R0 Q5),
 * and no flag answers it.
 */
export function midRunConfirm(io: CliIO): (files: CreatedFile[]) => Promise<boolean> {
  return async (files) => {
    if (io.interactive !== true || io.env.CI === 'true') return false;
    const list = files.map((f) => `  - ${safeText(f.path, 200)} (AI-written)`).join('\n');
    try {
      return (await io.prompt.confirm(`${CONFIRM_TITLE}\n${list}\n${CONFIRM_QUESTION}`, false)) === true;
    } catch {
      return false;
    }
  };
}

/** The draft with the steps of `choices` (by need and service) in place of its own (a dispute option, or the winners). */
function withSteps(d: PipelineDraft, choices: readonly Choice[]): PipelineDraft {
  const same = (a: StepSpec, b: StepSpec): boolean => a.needId === b.needId && (a.service ?? null) === (b.service ?? null);
  let steps = [...d.steps];
  for (const c of choices) steps = steps.some((x) => same(x, c.chosen)) ? steps.map((x) => (same(x, c.chosen) ? c.chosen : x)) : steps;
  return { ...d, steps };
}

/**
 * F-5, S2 (carry 19): the next candidate of the failing key, from Choice.ranked[1…] through specFor with template defaults. One key for
 * the need: its next ranked tool. More: each key whose job failed in the latest proof, in the order of the failed jobs; no failed job
 * named: null. Never another service's key. No debate (a resume) or a private app (its central workflows can't be pushed again): null.
 */
export function nextCandidateFrom(debate: DebateResult | undefined, p: RepoProfile, reviewed: readonly ReviewedTool[], runs: () => readonly VariantRuns[]): FixDeps['nextCandidate'] {
  const used = new Map<string, number>();
  return async (needId) => {
    if (debate === undefined || p.private) return null;
    const keys = debate.choices.filter((c) => c.needId === needId);
    if (keys.length === 0) return null;
    let order: Choice[];
    if (keys.length === 1) order = keys;
    else {
      const failed = runs().flatMap((r) => r.outcomes).flatMap((o) => o.jobs).filter((j) => j.conclusion === 'failure').map((j) => j.name);
      order = [];
      for (const name of failed) for (const c of keys) if (!order.includes(c) && jobNameMatches(name, c.key)) order.push(c);
    }
    const offers = keyOffers(debate.needs, debate.candidates, p, { reviewed });
    for (const c of order) {
      const at = used.get(c.key) ?? 1;
      const next = c.ranked[at];
      if (next === undefined) continue;
      used.set(c.key, at + 1);
      const ref = offers.refs.find((r) => r.key === c.key);
      const offer = offers.offers.get(c.key)?.find((x) => x.entry.candidate.id === next.id);
      if (ref === undefined || offer === undefined) continue;
      return specFor(ref, offer, p);
    }
    return null;
  };
}

const dockerfileAt = (s: { path: string }): string => { const r = s.path.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, ''); return r === '' ? 'Dockerfile' : `${r}/Dockerfile`; };

/** S10: the created Dockerfile at `path` made again from base image `baseId`, through the run's metered provider (E-a5), with its .dockerignore. */
function dockerfileFrom(bundle: CodeBundle, meter: AiSpendMeter): NonNullable<FixDeps['dockerfileFor']> {
  return async (path, baseId, d) => {
    const svc = d.profile.services.find((s) => dockerfileAt(s) === path);
    if (svc === undefined) return [];
    return (await createDockerfile(svc, d.profile, bundle, meter.provider, undefined, { baseId })).files;
  };
}

/** The need key of a step (the gate job id), for tests and the report. */
export const stepKey = (s: Pick<StepSpec, 'needId' | 'service'>): string => jobIdFor(s.needId, s.service);
