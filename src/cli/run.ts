// v0.2 Plan G G13 (plan Task 8, stages 1-15 and 18-21; rulings S1, S3, S20, S28, B7; ruling G13-R0): `pipegen run`, the full setup.
//
// The order (each stage saved with StateStore per S3 from consent on: 7 consented, 9-10 planned, 11 debated, 12-13 and 15 created; 16-17 the
// proof (G14) moves it to proving/proven/cleaned; 19 delivered):
//   0. (main.ts) unsafeFolderStop, exit 4. Then: the flags (--skip, --strictness), the v0.2 scope line, the Windows refusal (no GitHub write
//      happens before it).
//   1. the origin remote, the services on disk, the --type values and (at a terminal) the type question: all before any GitHub call; a
//      cancel exits 0 with nothing read from GitHub.
//   2. getAuth (write mode, exactly the app, pipelines and pipegen-proof-<repo>).   3. readProject's GitHub half: context, capabilities,
//      writers (listWriters and readWriters), the org and sha-pinning reads.   4. supportLevel.   5-6. the provider and the code bundle.
//   7. the consent (estimate from the floor needs, needKeys, 2 variants, nightly; one AI meter), assertBootstrapAllowed first.
//   7b. (ruling G-SIGN1, a first run) firstRunSigning: the run's own pipegen-signing, made new and read back, then the signing mode again.
//   8. checkProofRepos.   9. planNeeds.   10. discover + pin.   11. debate.   12. the creators.   13. the secrets, PIPEGEN_FP_KEY.
//   14. nothing (Slack: --skip slack is accepted and does nothing in v0.2).   15. assemble, the deploy layer, pre-commit, locks, PIPEGEN.md,
//      one referee call (seven arguments) and the guard on the same batch.   16-17. the proof (G14, run-proof.ts: the helper repos,
//      the setup, the disputes, the fix loop, the cleanup). Delivery only from the stage `cleaned` with a passed proof.   18. deliverCentral, the re-pin, readCentralFileList once, assemble and judge again, the preview
//      (asked again when the minutes went up), one confirmation.   19. deliver.   20. the merge wait, then finish.   21. the summary.
// Exit codes: 0 done; 1 a refusal, a declined question or an error; 2 a stopped run (the proof, the central PR, a refused batch, audit-only);
// 4 the unsafe folder (main.ts). The vault is wiped on every exit.
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { join, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import type { Octokit } from '@octokit/rest';
import { makeProvider } from '../ai/provider.js';
import { bundleCode, chooseSecretScanner, type CodeBundle } from '../ai/redact.js';
import { ConsentToken, CountingSummary, countingSummary, isSpent, spend } from '../audit/consent-token.js';
import { ollamaHostOf } from '../ai/ollama.js';
import { AiSpendMeter, meteredProvider } from '../ai/spend-meter.js';
import { mapCoverage } from '../audit/coverage.js';
import { noImageCheck } from '../audit/model.js';
import { readWorkflows, skippedWorkflowCount } from '../read/workflows.js';
import { readOrigin, readProject } from '../read/project.js';
import { applyTypeOverrides, type TypeOverride } from '../read/project-type.js';
import { supportLevel } from '../read/support.js';
import { createCompose } from '../create/compose.js';
import { createDockerfile } from '../create/dockerfile.js';
import { gitBlobSha, guardCreatedFiles, type BaseTree, type GuardInstallRecord } from '../create/guard.js';
import { loadReviewedClosure } from '../create/reviewed-closure.js';
import { askSecrets, coveredNames, generateFpKey, secretRequests, SecretVault } from '../create/secrets.js';
import { debate as runDebate, type DebateResult } from '../debate/debate.js';
import { needKeyOf } from '../debate/need-ref.js';
import { decideTests } from '../debate/tests.js';
import type { StarterDeps } from '../create/tests.js';
import { deliver, deliverCentral, DeliverError, dropRunSigningEnvironment, makeRunSigningEnvironment, planDelivery, previewText, readCentralFileList, type DeliverResult, type DeliveryInput, type SigningKey, type CentralPr, type CentralResult } from '../deliver/deliver.js';
import { pipegenDoc } from '../deliver/docs.js';
import { coCaseProblem, coFacts, type CoFacts } from '../deliver/finish.js';
import { readBlobText, readHead, readRepo, readTree } from '../deliver/git-data.js';
import type { CreatedInputs } from '../engine/created-files.js';
import { discover } from '../engine/discover.js';
import { resolvePin } from '../engine/pin.js';
import { openMemory } from '../engine/memory.js';
import type { LocalRecordDeps } from '../deliver/record.js';
import { trustedPrevious, UNREADABLE_RUN_WAY_ON } from '../deliver/trust.js';
import { codeownersProtectedPaths } from '../engine/created-builders.js';
import { newRateBudget, type RateClock } from '../engine/github-rate.js';
import { ensureLinters, ensurePinnedBinary, loadPinnedBinaries } from '../engine/linters.js';
import { floorNeeds, isRunnable, planNeeds, publishedImageServices, type NeedsPlan } from '../engine/needs.js';
import { platformActions, type PlatformActions } from '../engine/pin.js';
import type { RefereeReport, RunLinters } from '../engine/referee.js';
import { assertBootstrapAllowed, bootstrapProofsNote, loadReviewed } from '../engine/reviewed.js';
import { loadQualityBar } from '../engine/quality-bar.js';
import { loadBaseImages } from '../engine/base-images.js';
import { activity30d, estimate, needKeyCount, type Activity, type Estimates } from '../estimate/estimate.js';
import { probeCapabilities, SIGNING_ENVIRONMENT } from '../github/capabilities.js';
import { getAuth, GITHUB_TIMEOUT_MS, hideToken, listWriters, makeOctokit, permissionsTable, readGitHubContext } from '../github/client.js';
import { readOrgAdmin, readRepoId, readShaPinning, readWriters, type ShaPinningRead } from '../github/lock-probes.js';
import { assemble, judgeAssembled, type AssembledFiles } from '../layers/assemble.js';
import { environmentPlan, generateCosignKeys, isMemoryFolder, MEMORY_DIR, planVerifyInserts, releaseJobs, type EnvironmentPlan, type VerifyPlan } from '../layers/deploy.js';
import { AssembleError, assembleJobs } from '../layers/jobs.js';
import { planLocks, type LockPlan } from '../layers/locks.js';
import { precommitFiles, type PrecommitResult } from '../layers/precommit.js';
import { checkProofRepos, createCommands, type ProofRepos } from '../proof/repos.js';
import { armProofCleanup, type ProofMeters } from '../proof/cleanup.js';
import { makeFixGuard, makeFixReferee } from '../proof/fix.js';
import { COMPAT_PREFIX, HARNESS_PATH } from '../proof/harness.js';
import { isPlantedPath } from '../debate/planted.js';
import { interrupting, onInterrupt, type InterruptContext, type InterruptOptions } from '../util/exit-hooks.js';
import { makeCleanupOnly, makeRunProof, type ProofBuild, type ProofInput, type ProofReturn, type RunProof } from './run-proof.js';
import { keyOffers, type Choice } from '../debate/builder.js';
import { restoreAiSpend } from '../proof/cleanup.js';
import { nextStage, STAGE_ORDER } from '../proof/state.js';
import { StateStore, type AgreedTerms, type RunState, type StateDeps } from '../proof/state.js';
import { CENTRAL_REPO } from '../proof/target.js';
import type { AiProvider, Auth, Capabilities, Candidate, CreatedFile, KnownValueCheck, PipelineDraft, RepoProfile, ReviewedTool, SkippablePart } from '../types.js';
import { signingMode, type SigningMode } from '../github/signing-mode.js';
import { safeText } from '../util/safe-text.js';
import { pubKeySha256 } from '../engine/signing.js';
import type { InstallRecord } from '../types.js';
import { withActiveVault } from '../util/known-values.js';
import { TYPE_CANCELLED } from './audit.js';
import { askConsent, consentScreen } from './consent.js';
import { tokenLogin } from './inspect.js';
import { finishCommand, interactiveRun } from './commands.js';
export { interactiveRun };
import type { CliIO, Prompter } from './io.js';
import {
  assembledJobs, consentJobs, docFor, draftFromDebate, isAiNote, parseStrictness, pickOwners, proofAssembler, prWaitMinutes,
  signingFor, strictNeeds, warnFirstFor, type Strictness,
} from './run-parts.js';
import { typeStep } from './type-confirm.js';

// ---------- --skip ----------

/** The parts --skip names (SkippablePart): never secrets scanning or the gate. */
export const SKIPPABLE_PARTS: readonly SkippablePart[] = Object.freeze(['tests', 'precommit', 'docker', 'compose', 'deploy', 'locks', 'slack', 'test-migration']);
export const NEVER_SKIPPED = 'Secrets scanning and the gate can never be skipped.';

/**
 * `--skip <part,…>` (plan Task 8): the comma list, spaces and duplicates removed, into draft.skipped with the reason "skipped with --skip
 * on <date>". `secrets` or `gate` throws NEVER_SKIPPED; an unknown part throws a message listing the valid parts. `slack` is accepted and
 * does nothing (S3). Absent or empty: nothing skipped.
 */
export function parseSkip(value: string | undefined, today: string): PipelineDraft['skipped'] {
  if (value === undefined) return [];
  const parts = [...new Set(value.split(',').map((s) => s.trim().toLowerCase()).filter((s) => s !== ''))];
  if (parts.some((s) => s === 'secrets' || s === 'gate')) throw new Error(NEVER_SKIPPED);
  const bad = parts.filter((s) => !(SKIPPABLE_PARTS as readonly string[]).includes(s));
  if (bad.length > 0) throw new Error(`Unknown --skip part ${bad.map((b) => `"${safeText(b, 40)}"`).join(', ')}. The parts you can skip are: ${SKIPPABLE_PARTS.join(', ')}.`);
  return parts.map((part) => ({ part: part as SkippablePart, reason: `skipped with --skip on ${today}` }));
}

// ---------- the seams ----------

/** S28 / plan l. 722 (G11/E23): said at the start of every run. */
export const SCOPE_LINE = 'pipegen v0.2 sets up repositories owned by CrisWorking only; anything else is refused before any change.';
/** Carry 56 (E-b16): the proof needs `pipegen cleanup`, which can't run on native Windows. */
export const WINDOWS_REFUSAL = 'pipegen run needs Linux or macOS (WSL works): on native Windows pipegen can\'t clean up after its proof, so it changes nothing. exit code 1.';
/** Ruling G13-R0 12 (carry 58, S28 b). */
export const GATE_UNREACHABLE = 'pipegen stopped before the proof: this repository is public, and the pipegen gate its pull requests would load can\'t be read at its pinned commit, so every pull request would be blocked. Nothing was changed. exit code 2.';
/** The stand-in central commit of a private draft before deliverCentral (never delivered: the run re-pins before it judges for delivery). */
export const UNPINNED = '0'.repeat(40);
/** G13-R1 (sec M2): the one owner v0.2 sets up (SCOPE_LINE), compared without case. */
export const V02_OWNER = 'CrisWorking';
export const NOT_IN_SCOPE = (owner: string): string => `pipegen v0.2 sets up repositories owned by ${V02_OWNER} only, and this folder's origin is owned by ${safeText(owner, 100)}; nothing was read from GitHub or changed. exit code 1.`;
/** G13-R1 (sec I1): the pinned scanner found a secret in the files consent counted. */
export const SECRET_FOUND = 'pipegen stopped: the secret scan found what looks like a secret in the files it would send to the AI, so nothing was sent and nothing was created. Remove it (or add the file to .gitignore), then run `npx pipegen run` again. exit code 2.';
/** G13-R1 (sec M4): key-env makes its key pair only in a memory folder. */
export const NO_MEMORY_FOLDER = `pipegen stopped before anything was spent: this repository's images are signed with a key pair, which pipegen makes only in memory (${MEMORY_DIR}), and this machine has no such folder. Run pipegen on Linux (WSL or a Linux container works too). exit code 2.`;
/** Plan l. 507-508 (stage 20). */
export const MERGE_POLL_MS = 30_000;
export const MERGE_WAIT_MS = 30 * 60_000;

export type { ProofInput, RunProof };
/** G14: the production proof (run-proof.ts); no RunDeps path skips it (ruling G14-R0 2 replaces G13-R0 1). */
export const defaultProof: RunProof = makeRunProof();
/** G14 (carries 8, 33): the production arm, only through armProofCleanup (S4: never StateStore.markArmed from Plan G code). */
export const defaultArm = (store: StateStore, cleanup: (ctx: InterruptContext) => Promise<unknown>, meters: () => ProofMeters | undefined): (() => void) =>
  armProofCleanup(store, cleanup, { meters });
/** G14 (controller addendum): a public app's app files changed between the build of the proven draft and the one delivered. */
export const PUBLIC_FILES_CHANGED = 'pipegen stopped: the files it would deliver are not the ones it built from the proven draft, so nothing was delivered. exit code 2.';
export const NOTHING_TO_RESUME = 'pipegen has no stopped run of this repository to resume. Run `npx pipegen run`. exit code 1.';
export const ALREADY_DELIVERED = 'The saved run of this repository was already delivered; there is nothing to resume. exit code 1.';
export const NOT_PROVING_YET = 'The saved run stopped before its proof, so there is nothing to resume: run `npx pipegen run` again (it starts over). exit code 1.';
/** G14-R1 (sec I2): a saved run with no agreed terms (an older state): a resume can't tell which AI the user agreed to. */
export const NO_AGREED_TERMS = 'pipegen stopped: the saved run does not say which AI you agreed to, so it can\'t go on with it. Run `npx pipegen cleanup`, then `npx pipegen run`. exit code 2.';
/** G14-R1 (sec I2): a resume whose AI (provider, model or Ollama host) is not the one agreed to: nothing is sent. */
export const AI_NOT_AGREED = (agreed: AgreedTerms, now: Pick<AgreedTerms, 'provider' | 'model' | 'host'>): string =>
  `pipegen stopped: you agreed to ${aiLabel(agreed)}, but this shell sets up ${aiLabel(now)}. Nothing was sent to an AI. Set the same AI as before (the API key and --model), or run \`npx pipegen cleanup\` and start again. exit code 2.`;
const aiLabel = (t: Pick<AgreedTerms, 'provider' | 'model' | 'host'>): string => safeText(`${t.provider} (${t.model}${t.host === undefined ? '' : ` at ${t.host}`})`, 300);
/** The agreed AI of a provider: its name, model and Ollama host (never a key). */
export const aiTermsOf = (p: AiProvider): Pick<AgreedTerms, 'provider' | 'model' | 'host'> => {
  const host = ollamaHostOf(p);
  return { provider: p.name, model: p.model, ...(host === null ? {} : { host }) };
};
export const KEY_PAIR_GONE = 'pipegen stopped: the saved draft signs with a key pair that lived only in memory during the stopped run, so it can\'t be delivered. Run `npx pipegen cleanup`, then `npx pipegen run`. exit code 2.';
/**
 * S20 (resume): the plan of a saved draft. Its steps are the tools the stopped run chose (reviewed entries only); assemble checks them against
 * these offers, and the referee and the guard judge the whole build again before any push. No debate runs again.
 */
export function planOfSaved(d: PipelineDraft, reviewed: readonly ReviewedTool[]): DebateDraftPlan {
  const candidates = new Map<string, Candidate[]>();
  for (const s of d.steps) candidates.set(needKeyOf({ id: s.needId, ...(s.service === undefined ? {} : { service: s.service }) } as never), [s.tool as Candidate]);
  const uncovered = keyOffers(d.needs, candidates, d.profile, { reviewed }).uncovered;
  return { needs: d.needs, candidates, uncovered } as DebateDraftPlan;
}
/** Carries 23, 31: a planted file, the proof harness or a compat copy in the delivered batch. */
export const PROOF_FILE_IN_DELIVERY = 'pipegen stopped: a file of the proof (a planted test problem, the proof harness or a compat copy) is in what it would deliver, so nothing was delivered. exit code 2.';

/** What stage 3 reads from GitHub. */
export interface GitHubFacts {
  gh: Octokit; clock: RateClock; login: string | null;
  context: Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>; caps: Capabilities;
  /** listWriters of the app (planNeeds' count). */
  writers: string[];
  /** readWriters: users who can write to the app and to the central repo. */
  lockWriters: { app: string[]; central: string[] };
  orgAdmin: boolean | null; shaPinning: ShaPinningRead; ids: { app: number | null; central: number | null };
}

/** The result of stage 15 (and of the re-build after the central pin). */
export interface Built {
  assembled: AssembledFiles; verify: VerifyPlan; locks: LockPlan; precommit: PrecommitResult; doc: CreatedFile;
  /** Every file of the delivery, as judged and guarded together. */
  files: CreatedFile[];
  report: RefereeReport; guardProblems: string[];
  environments: { name: string; reviewers: boolean }[];
  /** spec I7: what environmentPlan could not do (also in doc.notes); shown at the preview. */
  envNotes: string[];
  /** G13-R2 7: hooks already in place that the trusted install record does not hold (uninstall would leave them); also in doc.notes, shown at the preview. */
  hookNotes: string[];
  /**
   * G17 row 29 (G10-r2 P3): files an earlier run adopted (they were in the repository, identical to pipegen's text) that this run rewrites;
   * also in doc.notes, shown at the preview. Absent: none.
   */
  adoptedNotes?: string[];
  /** The files judged besides AssembledFiles (PIPEGEN.md, the inserted verify jobs, CODEOWNERS, the org required workflow): judgeAssembled's `extra`. */
  extra: CreatedFile[];
  /** G14: the same build for another draft, with the fix loop's referee and guard over it (the real stage sets it; absent: the proof refuses). */
  proof?: ProofBuild;
  /** The jobs as assembled, for the preview estimate (carry 43) and the PR wait. */
  minutes: { jobs: ReturnType<typeof assembledJobs>; prWait: number };
}
export interface BuildInput {
  /** The known-value check: the user's vault and (key-env) the in-memory key pair (sec M4). */
  dir: string; draft: PipelineDraft; plan: DebateDraftPlan; facts: GitHubFacts; vault: KnownValueCheck; reviewed: ReviewedTool[]; platform: PlatformActions;
  owners: string[]; strictness: Strictness; transcript: string[]; testNotes: string[]; est: Estimates; auth: Auth;
  /** readCentralFileList, after deliverCentral (carry 15); absent before it. */
  centralFiles?: readonly string[];
  /** The audit's credits (ruling G13-R0 13), for doc.credits. */
  credits: NonNullable<PipelineDraft['doc']>['credits'];
  /** The earlier install record pipegen trusts (trustedPrevious), or null. */
  prev: InstallRecord | null;
}
type DebateDraftPlan = ReturnType<typeof draftFromDebate>['plan'];

/** Every outside call of the run, one seam each (tests inject fakes; the defaults are the real modules). */
export interface RunStages {
  readOrigin(dir: string): Promise<{ owner: string; repo: string }>;
  /** The services on disk (no network), for the type question. */
  localProject(dir: string): Promise<Omit<RepoProfile, 'private' | 'ownerType' | 'plan'>>;
  getAuth(o: { owner: string; repos: string[]; allowBroad: boolean }): Promise<Auth & { token: string }>;
  /** Stage 3: readProject's GitHub half. */
  readProject(auth: Auth, local: Omit<RepoProfile, 'private' | 'ownerType' | 'plan'>): Promise<GitHubFacts>;
  provider(): ReturnType<typeof makeProvider>;
  /** The counting bundle consent shows (no secret scan yet: ruling S21). */
  bundle(dir: string, knownValues: string[]): Promise<CodeBundle>;
  /** G13-R1 (sec I1): after the yes, the pinned scanner the consent named over exactly the counted files; refuses when it can't. */
  scan(dir: string, consent: ConsentToken, knownValues: string[], agreed: Agreed): Promise<CodeBundle>;
  activity(f: GitHubFacts, p: RepoProfile): Promise<Activity>;
  /** `opts.signingEnv` (ruling G-SIGN1-R1): the screen says pipegen creates pipegen-signing before the proof (only when that path can run). */
  consent(f: GitHubFacts, p: RepoProfile, ai: ReturnType<typeof makeProvider>, est: Estimates, bundle: CodeBundle, auth: Auth, extra: string[], opts?: { signingEnv: boolean }): Promise<ConsentToken | null>;
  /** G13-R2 4 (sec m3): `guard` is the run's known-value check (the vault and the key vault, read live) and its tokens: never written. */
  state(p: RepoProfile, guard: { vault: KnownValueCheck; tokens: readonly string[] }): Promise<StateStore>;
  /** Carry 58 (ruling G13-R0 12): a public app's gate, at its pinned commit, can be read. */
  gateReachable(f: GitHubFacts, reviewed: readonly ReviewedTool[]): Promise<boolean>;
  proofRepos(f: GitHubFacts, p: RepoProfile, auth: Auth, store: StateStore, runId: string, actions: readonly string[]): Promise<ProofRepos>;
  /** Stage 8, read only (ruling G14-R0 1): the helper repos that don't exist yet (names). */
  helperRepos(f: GitHubFacts, p: RepoProfile): Promise<string[]>;
  /** G-COCASE-R1, read only: the stop message when the app or central repo holds a CODEOWNERS case variant (coCaseOfRepos), or null. */
  coCase(f: GitHubFacts, p: RepoProfile): Promise<string | null>;
  needs(p: RepoProfile, caps: Capabilities, bundle: CodeBundle, ai: ReturnType<typeof makeProvider>, writers: number, knownValues: string[]): Promise<NeedsPlan>;
  /** `ai` is the run's metered provider (sec I2); `onUsage` saves the meter after each call. */
  discover(needs: NeedsPlan['needs'], p: RepoProfile, f: GitHubFacts, reviewed: ReviewedTool[], ai: ReturnType<typeof makeProvider>, onUsage: () => void): Promise<Map<string, readonly Candidate[]>>;
  debate(needs: NeedsPlan['needs'], candidates: ReadonlyMap<string, readonly Candidate[]>, p: RepoProfile, caps: Capabilities, bundle: CodeBundle, ai: ReturnType<typeof makeProvider>, rule: { requireDeployApproval: boolean }, reviewed: ReviewedTool[]): Promise<DebateResult>;
  creators(draft: PipelineDraft, bundle: CodeBundle, ai: ReturnType<typeof makeProvider>, dir: string, vault: SecretVault, reviewed: ReviewedTool[]): Promise<Creators>;
  secrets(p: RepoProfile, created: readonly CreatedFile[], vault: SecretVault, io: CliIO): Promise<{ names: string[]; missing: string[]; notes: string[] }>;
  credits(p: RepoProfile, draft: PipelineDraft, dir: string): Promise<NonNullable<PipelineDraft['doc']>['credits']>;
  build(i: BuildInput): Promise<Built>;
  /** trustedPrevious on the central default branch: the earlier record pipegen builds on (carries 21, 60). */
  trusted(f: GitHubFacts, p: RepoProfile, io: CliIO): Promise<{ record: InstallRecord | null; notes: string[] }>;
  /** previewText(planDelivery(input)): what the one confirmation shows. */
  preview(input: DeliveryInput): string;
  /** `pr` (G17C-R1, F5): the central pull request an earlier run opened, from the run state. */
  /** `lease` (Plan V M5): run's own lease of the app, passed down (deliver takes no second one: that would stop on this process). */
  deliverCentral(f: GitHubFacts, p: RepoProfile, files: readonly CreatedFile[], io: CliIO, pr: CentralPr | undefined, lease: StateStore): Promise<CentralResult>;
  readCentralFileList(f: GitHubFacts, p: RepoProfile): Promise<string[]>;
  signingKey(): Promise<SigningKey>;
  /** Ruling G-SIGN1: makeRunSigningEnvironment (the run's own pipegen-signing, made new and read back), or why signing is off. */
  signingEnv(f: GitHubFacts, p: RepoProfile): Promise<{ env: SigningEnvEntry } | { off: string }>;
  /** Ruling G-SIGN1-R1: dropRunSigningEnvironment (the run stops before delivery: the environment it made is deleted), or why it stays. */
  dropSigningEnv(f: GitHubFacts, p: RepoProfile, env: SigningEnvEntry): Promise<{ dropped: true } | { left: string }>;
  deliver(f: GitHubFacts, p: RepoProfile, input: DeliveryInput, vault: SecretVault, io: CliIO, signingKey: (() => Promise<SigningKey>) | undefined, lease: StateStore): Promise<DeliverResult>;
  /** The setup PR: merged, closed (unmerged) or still open. */
  prState(f: GitHubFacts, p: RepoProfile, pr: number): Promise<'merged' | 'closed' | 'open'>;
  finish(f: GitHubFacts, p: RepoProfile, io: CliIO, lease: StateStore): Promise<number>;
}
export interface Creators { files: CreatedFile[]; notes: string[]; testNotes: string[]; testDecisions: PipelineDraft['testDecisions']; notProven: PipelineDraft['notProven'] }

export interface RunFlags { skip?: string; types?: readonly TypeOverride[]; strictness?: string; allowBroad?: boolean }
export interface RunDeps {
  flags?: RunFlags;
  /** Carry 56: the platform (CliIO has none). Default process.platform. */
  platform?: NodeJS.Platform;
  today?: () => string;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  stages?: Partial<RunStages>;
  proof?: RunProof;
  local?: LocalRecordDeps;
  state?: StateDeps;
  /** The reviewed list (default loadReviewed()). */
  reviewed?: () => ReviewedTool[];
  /** The platform actions (default platformActions over the reviewed list). */
  platformActions?: (reviewed: ReviewedTool[], f: GitHubFacts) => Promise<PlatformActions>;
  runId?: () => string;
  /** G14: armProofCleanup(store, cleanupAfterProof, meters); returns the disarm (default defaultArm). The proof arms before its first GitHub write. */
  arm?: (store: StateStore, cleanup: (ctx: InterruptContext) => Promise<unknown>, meters: () => ProofMeters | undefined) => () => void;
  /** G14: `pipegen resume` (contracts §6 step 2, S20): the saved run, at nextStage. */
  resume?: boolean;
  /** G14: the cleanup of a resumed run whose proof passed but whose cleanup didn't finish (default makeCleanupOnly()). */
  cleanupOnly?: ReturnType<typeof makeCleanupOnly>;
  /** Ruling G-SIGN1-R1: arms the deletion of the run's own signing environment on an interrupt; returns the disarm (default onInterrupt). */
  armSigningEnv?: (cleanup: () => Promise<void>, opts: InterruptOptions) => () => void;
  /** Ruling G-SIGN1-R2 (sec M4): whether a stop has begun (default exit-hooks' interrupting()), read at the delivery hand-off. */
  interrupting?: () => boolean;
  /** sec M4: whether the memory folder is one (default isMemoryFolder). */
  isMemory?: (dir: string) => boolean;
  /** sec I1: the pinned secret scanner (default ensurePinnedBinary with the pins). */
  secretScanner?: (name: 'gitleaks' | 'betterleaks') => Promise<{ name: 'gitleaks' | 'betterleaks'; path: string; version: string }>;
}

const isoDay = (ms: number): string => new Date(ms).toISOString().slice(0, 10);
const newRunId = (now: number): string => {
  const d = new Date(now).toISOString();
  return `${d.slice(0, 10).replace(/-/g, '')}-${d.slice(11, 19).replace(/:/g, '')}-${Math.floor(Math.random() * 0x1000000).toString(16).padStart(6, '0')}`;
};

/**
 * `pipegen run` (see the file header). `deps` are the seams; a real run passes only `flags`.
 */
export async function fullRun(dir: string, io: CliIO, deps: RunDeps = {}): Promise<number> {
  const now = deps.now ?? Date.now;
  const today = (deps.today ?? (() => isoDay(now())))();
  let token: string | null = null;
  const out = (s: string): void => { io.out(hideToken(s, token)); };
  const err = (s: string): void => { io.err(hideToken(s, token)); };
  let vault: SecretVault | null = null;
  let keyVault: SecretVault | null = null;
  let store: StateStore | null = null;
  let disarm: (() => void) | null = null;
  // ruling G-SIGN1-R1: the deletion of the signing environment this run made, until delivery takes it (and its interrupt disarm)
  let dropEnv: (() => Promise<void>) | null = null;
  let disarmEnv: (() => void) | null = null;
  /** The services a workflow, compose or bake file builds an image from (containerHint): carry 13's way past. */
  let hinted: readonly { name: string; containerHint?: string }[] = [];
  try {
    return await go();
  } catch (e) {
    if (e instanceof DeliverError) {
      err(`pipegen stopped: ${safeText(e.message, 1000)}`);
      for (const l of (e as DeliverError & { leftovers?: string[] }).leftovers ?? []) err(`  left: ${safeText(l, 300)}`);
      return 1;
    }
    err(`pipegen run failed: ${safeText(e instanceof Error ? e.message : String(e), 600)}`);
    if (e instanceof AssembleError) for (const t of dastWayPast(e.message, hinted)) err(t);
    return 1;
  } finally {
    // ruling G-SIGN1-R1: a run that stops before delivery (any exit path) deletes the environment it made. G-SIGN1-R3 (sec r2-L1): while a
    // stop is under way the hook stays armed, so the registry runs it inside its awaited hook phase (deadline, state record)
    const drop = dropEnv as (() => Promise<void>) | null;
    dropEnv = null;
    if (drop !== null && (deps.interrupting ?? interrupting)()) {
      disarmEnv = null;
    } else {
      try { (disarmEnv as (() => void) | null)?.(); } catch { /* the hook only deletes what this run made */ }
      disarmEnv = null;
      if (drop !== null) await drop().catch(() => undefined);
    }
    (vault as SecretVault | null)?.wipe();
    (keyVault as SecretVault | null)?.wipe();
    try { (disarm as (() => void) | null)?.(); } catch { /* the state file keeps what was done */ }
    // G-LEASE-R1 (sec M1): while a stop is under way, the interrupt hooks (the env drop, the proof cleanup) still write to GitHub after this
    // finally; the lease stays until the exit hook acquireLease registered drops it, at the end of the hook phase
    if (!(deps.interrupting ?? interrupting)()) try { (store as StateStore | null)?.releaseLease(); } catch { /* released at exit anyway */ }
  }

  async function go(): Promise<number> {
    const flags = deps.flags ?? {};
    // the flags first: nothing is read yet
    let skipped: PipelineDraft['skipped'];
    let level: Strictness;
    try {
      skipped = parseSkip(flags.skip, today);
      level = parseStrictness(flags.strictness);
    } catch (e) {
      err(e instanceof Error ? e.message : String(e));
      return 1;
    }
    // ruling G14-R0 Q3: a resume uses the saved draft only; a new value could loosen what the user agreed to
    if (deps.resume === true && (flags.skip !== undefined || (flags.types ?? []).length > 0 || flags.strictness !== undefined)) {
      err('pipegen resume takes no --skip, --type or --strictness: it goes on with the saved draft as it was agreed. exit code 1.');
      return 1;
    }
    err(SCOPE_LINE);
    // carry 56: before any GitHub call (and so before any write)
    if ((deps.platform ?? process.platform) === 'win32') { err(WINDOWS_REFUSAL); return 1; }
    const st = { ...realStages(io, deps), ...deps.stages } as RunStages;

    // 1. the origin, the services on disk and the types: no GitHub call yet (carry 2)
    const origin = await st.readOrigin(dir);
    // G13-R1 (sec M2): what SCOPE_LINE says, enforced from the folder's own origin, before any GitHub call
    if (origin.owner.toLowerCase() !== V02_OWNER.toLowerCase()) { err(NOT_IN_SCOPE(origin.owner)); return 1; }
    const read = await st.localProject(dir);
    if (read.owner.toLowerCase() !== origin.owner.toLowerCase() || read.repo.toLowerCase() !== origin.repo.toLowerCase()) throw new Error('The folder\'s origin remote changed while pipegen read it.');
    // the audit's own type step (carry 2): --type checked and applied, else the question at a terminal; a cancel reads nothing from GitHub
    const typed = deps.resume === true ? { overrides: [] } : await typeStep(io.prompt, io.interactive === true, read, flags.types ?? []);
    if ('error' in typed) { err(safeText(typed.error, 500)); return 1; }
    if ('cancel' in typed) { err(TYPE_CANCELLED); return 0; }
    // carry 6: an override never drops the minimum (floorNeeds keeps MINIMUM_CATEGORIES whatever the type)
    const local = applyTypeOverrides(read, typed.overrides);
    hinted = local.services.filter((x) => x.containerHint !== undefined);

    // 2. auth (least privilege, exact repos)
    const auth = await st.getAuth({ owner: origin.owner, repos: [origin.repo, CENTRAL_REPO, `pipegen-proof-${origin.repo}`], allowBroad: flags.allowBroad === true });
    token = auth.token;
    // 3. readProject's GitHub half
    // `let`: ruling G-SIGN1 re-derives the capabilities once the run's own signing environment has read back (after consent)
    let facts = await st.readProject(auth, local);
    const p: RepoProfile = { ...local, ...facts.context };
    // 4. support level (no --skip changes it)
    const support = supportLevel(p, 'v0.2');
    if (support.level === 'audit-only') {
      err(`pipegen v0.2 can't set this repository up: ${support.reasons.map((r) => safeText(r, 300)).join(' ')} Run \`pipegen audit\` for the report. exit code 2.`);
      return 2;
    }
    // carry 39 (G8-R2 I1, spec M7): the code owners from both writer lists, before anything costs money
    const pick = pickOwners(facts.lockWriters, facts.login);
    if ('stop' in pick) { err(pick.stop); return 2; }
    if (pick.note !== undefined) err(pick.note);
    const reviewed = (deps.reviewed ?? (() => loadReviewed()))();
    // 5-6: the counting bundle (no secret scan yet: the scanner runs only after the yes, ruling S21, G13-R1 sec I1). A resume (S20) sends no
    // code to an AI again (no debate, no creators): no bundle and no new consent; its AI spend goes on under the saved cap
    const resume = deps.resume === true;
    const provider = st.provider();
    const knownValues = [auth.token];
    const counted = resume ? undefined : await st.bundle(dir, knownValues);

    // 7. consent: the bootstrap switch first (carry 46), then the services the proof can't prove, the estimate, the screen
    assertBootstrapAllowed(io.env);
    // G13-R1 (sec M4): key-env makes its key pair only in memory; a host without a memory folder is refused before anything costs money
    const hasMemory = (): boolean => (deps.isMemory ?? isMemoryFolder)(MEMORY_DIR);
    // G17-F1 (sec M1): with the deploy part skipped nothing is signed (assembly drops the signing plan), so no key pair, no memory folder,
    // no signing environment and no "this run signs" note
    let keyEnvApplies = keyEnvFor(p, facts.caps, skipped);
    if (keyEnvApplies && !hasMemory()) { err(NO_MEMORY_FOLDER); return 2; }
    // 8, read only (ruling G14-R0 1): helper repos this token can't create are named before anything costs money. The writing check
    // (checkProofRepos: create, Actions access, default branch) runs inside the proof, where a throw is cleaned up
    const missing = await st.helperRepos(facts, p).catch(() => null);
    if (missing !== null && missing.length > 0 && !(auth.kind === 'app' && auth.canCreateRepos)) {
      err(['Create these private repos, then run `npx pipegen run` again:', ...createCommands(p.owner, missing).map((c) => `  ${c}`)].join('\n'));
      err('pipegen stopped before anything was spent: the helper repositories above must exist first. exit code 2.');
      return 2;
    }
    // G-COCASE-R1, read only: a CODEOWNERS case variant stops setup before consent and any write
    const coStop = await st.coCase(facts, p);
    if (coStop !== null) { err(safeText(coStop, 1500)); return 2; }
    const extra = notProvableNotes(p);
    const floor = floorNeeds(p, facts.caps);
    const activity = await st.activity(facts, p);
    const est = estimate(p, consentJobs(p, facts.caps), 2, activity, provider, { needKeys: needKeyCount(floor) });
    let bundle: CodeBundle | undefined;
    let scannerName: 'gitleaks' | 'betterleaks' = chooseSecretScanner(io.env);
    let agreedMinutes = est.monthlyMinutes;
    // G-SIGN1-R2 (sec N1): whether the consent the user gave named the signing environment (the token's terms, not a recomputation)
    let agreedSigningEnv = false;
    if (counted !== undefined) {
      // ruling G-SIGN1-R1: the screen names the signing environment the run creates before the proof, only when that path can run
      const consent = await st.consent(facts, p, provider, est, counted, auth, extra, { signingEnv: firstRunSigningCan(p, facts.caps, skipped) && hasMemory() });
      if (consent === null) { err('No consent: nothing was created, nothing was sent to an AI and no secret was asked for. exit code 1.'); return 1; }
      scannerName = (consent as { terms?: { secretScanner?: { name: 'gitleaks' | 'betterleaks' } } }).terms?.secretScanner?.name ?? scannerName;
      agreedSigningEnv = (consent as { terms?: { signingEnv?: unknown } }).terms?.signingEnv === true;
      // the secret scan of the counted files only; a finding stops the run before anything is sent to an AI
      bundle = await st.scan(dir, consent, knownValues, { ai: provider, capUsd: est.aiCostCapUsd });
      if (bundle.found.names.length > 0 || bundle.found.values.length > 0) { err(SECRET_FOUND); return 2; }
    }
    // sec m3: the vaults exist from here (empty), so the state store checks every write against what is typed later
    vault = new SecretVault();
    keyVault = new SecretVault();
    // G14 (controller addendum): the AI keys from the environment are tokens the state file must never hold, like the GitHub one
    store = await st.state(p, { vault: knownChecks(vault, keyVault), tokens: [auth.token, ...aiKeysOf(io.env)] });
    let runId: string;
    let saved0: RunState | null = null;
    let next: ReturnType<typeof nextStage> = 'proving';
    if (resume) {
      // contracts §6 step 2: the saved run of this app, at the stage nextStage gives (a proof that didn't pass proves again)
      saved0 = store.load();
      if (saved0 === null || saved0.app.owner.toLowerCase() !== p.owner.toLowerCase() || saved0.app.repo.toLowerCase() !== p.repo.toLowerCase()) { err(NOTHING_TO_RESUME); return 1; }
      next = nextStage(saved0);
      if (next === null) { err(ALREADY_DELIVERED); return 1; }
      if (STAGE_ORDER.indexOf(next) < STAGE_ORDER.indexOf('proving')) { err(NOT_PROVING_YET); return 1; }
      if (saved0.draft === undefined) { err('pipegen stopped: the saved run holds no draft to go on with. Run `npx pipegen cleanup`, then `npx pipegen run`. exit code 2.'); return 2; }
      // G14-R1 (sec I2, M6): the AI, strictness, scanner and minutes the user agreed to; a resume never sends code to another AI
      const agreed = saved0.agreed;
      if (agreed === undefined) { err(NO_AGREED_TERMS); return 2; }
      const now0 = aiTermsOf(provider);
      if (now0.provider !== agreed.provider || now0.model !== agreed.model || (now0.host ?? '') !== (agreed.host ?? '')) { err(AI_NOT_AGREED(agreed, now0)); return 2; }
      if (agreed.strictness !== undefined) level = parseStrictness(agreed.strictness);
      if (agreed.scanner !== undefined) scannerName = agreed.scanner;
      if (agreed.monthlyMinutes !== undefined) agreedMinutes = agreed.monthlyMinutes;
      runId = saved0.runId;
      store.acquireLease(runId, 'resume');
    } else {
      runId = (deps.runId ?? (() => newRunId(now())))();
      // S20: one pipegen per app repo on this machine (Plan V M5: deliver and finish below use this lease, passed down)
      store.acquireLease(runId, 'run');
      store.begin(runId, { owner: p.owner, repo: p.repo, private: p.private, ownerType: p.ownerType, defaultBranch: p.defaultBranch }, {
        cap: est.setupMinutesCap, aiCap: est.aiCostCapUsd,
        // G14-R1 (sec I2, M6): the consent's terms, for a resume (names only)
        agreed: { ...aiTermsOf(provider), strictness: level, scanner: scannerName, monthlyMinutes: est.monthlyMinutes },
      });
    }
    // carry 47: one meter per consent token; every AI closure goes through it. E-a6: a resume builds it on the SAVED aiCap, then restores
    // the spend so far (restoreAiSpend)
    const meter = new AiSpendMeter(provider, saved0 === null ? est.aiCostCapUsd : saved0.aiCap);
    if (saved0 !== null) restoreAiSpend(meter, saved0);
    const ai = meteredProvider(provider, meter);
    const runStore = store;
    const onUsage = (): void => { runStore.saveMeters({ aiUsedUsd: meter.usedUsd }); };

    // carry 58: a public app whose gate can't load stops before the proof (and before any repo is made)
    if (!p.private && !(await st.gateReachable(facts, reviewed))) { err(GATE_UNREACHABLE); return 2; }

    // the draft: from the debate (F-6), the strictness level (carry 44), the trusted record's block date (carry 21), the owners (carry 39);
    // on a resume, the saved one (S20: built, re-refereed and re-guarded below before any push)
    let debated: DebateResult | undefined;
    let base: PipelineDraft | undefined;
    let draft: PipelineDraft;
    let plan: DebateDraftPlan;
    let trusted: Awaited<ReturnType<RunStages['trusted']>>;
    let made: Creators = { files: [], notes: [], testNotes: [], testDecisions: [], notProven: [] };
    let runSigningEnv: SigningEnvEntry | undefined;
    /** G-SIGN1-R3 (spec r2-L1): the delivery happened (an environment it didn't use is deleted with another message). */
    let deliveredRun = false;
    /** G-SIGN1-R2 sec M3: (re-)arms the environment's interrupt hook; the proof's arm calls it again, so it runs after the proof's hooks. */
    let armEnvHook: (() => void) | null = null;
    if (saved0 !== null) {
      trusted = await st.trusted(facts, p, io);
      for (const n of trusted.notes) err(n);
      draft = saved0.draft as PipelineDraft;
      plan = planOfSaved(draft, reviewed);
    } else {
      // ruling G-SIGN1: the first run on a private repo signs when the plan allows. After the yes (a GitHub write) and before the needs, the
      // debate, assembly and the referee: the run's own pipegen-signing, made new and read back with the default-branch rule, and only
      // then the signing mode re-derived from the proven capabilities. Anything else stays unsigned, with the reason said (fail closed)
      const first = await firstRunSigning(p, facts.caps, () => st.signingEnv(facts, p), hasMemory, agreedSigningEnv, skipped);
      for (const n of first.notes) err(n);
      if (first.env !== undefined) {
        facts = { ...facts, caps: first.caps };
        runSigningEnv = first.env;
        // ruling G-SIGN1-R1: from here until delivery takes it, a stop (any exit path, or an interrupt) deletes it again
        const made = first.env;
        let ran = false;
        const once = async (): Promise<void> => {
          if (ran) return;
          ran = true;
          const r = await st.dropSigningEnv(facts, p, made).catch(() => ({ left: 'an error' }));
          if ('dropped' in r) err(deliveredRun ? SIGNING_ENV_UNUSED : SIGNING_ENV_DELETED);
          else err(`pipegen couldn't delete the environment ${SIGNING_ENVIRONMENT} it made earlier in this run (${safeText(r.left, 600)}). Remove it by hand in the repository settings.`);
        };
        dropEnv = once;
        armEnvHook = () => {
          try { (disarmEnv as (() => void) | null)?.(); } catch { /* re-armed below */ }
          // G-SIGN1-R2 sec M3: a label, a short deadline, and a line in the run's state file if it doesn't finish (to be seen; the local
          // leftovers file is what keeps the environment for uninstall)
          disarmEnv = (deps.armSigningEnv ?? defaultArmSigningEnv)(once, { label: SIGNING_ENV_HOOK_LABEL, deadlineMs: SIGNING_ENV_HOOK_DEADLINE_MS, record: (item) => { runStore.record(item); } });
        };
        armEnvHook();
        keyEnvApplies = keyEnvFor(p, facts.caps, skipped);
      }
      // 9-10
      const needsPlan = await st.needs(p, facts.caps, bundle as CodeBundle, ai, facts.writers.length, knownValues);
      const candidates = await st.discover(needsPlan.needs, p, facts, reviewed, ai, onUsage);
      store.setStage('planned');
      // 11
      debated = await st.debate(needsPlan.needs, candidates, p, facts.caps, bundle as CodeBundle, ai, { requireDeployApproval: needsPlan.requireDeployApproval }, reviewed);
      store.setStage('debated');
      trusted = await st.trusted(facts, p, io);
      for (const n of trusted.notes) err(n);
      const typeNeedIds = new Set(floor.map((n) => n.id));
      base = {
        profile: p, capabilities: facts.caps, needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: needsPlan.layersSkipped, scoreboard: [],
        requireDeployApproval: false, skipped, suggestions: [],
        ...(pick.owners.length >= 2 ? { codeOwners: { owners: pick.owners, writers: pick.writers } } : {}),
        // carry 21 (ruling G13-R0 2): only an earlier record's blockFrom; a first run leaves it out
        ...(trusted.record?.blockFrom === undefined ? {} : { gateSettings: { blockFromRecorded: trusted.record.blockFrom } }),
      };
      const dd = draftFromDebate(base, debated);
      const levelNeeds = strictNeeds(dd.draft.needs, level, { steps: dd.draft.steps, uncovered: dd.plan.uncovered });
      draft = { ...dd.draft, needs: levelNeeds, warnFirst: warnFirstFor(levelNeeds, level, typeNeedIds, today) };
      plan = { ...dd.plan, needs: levelNeeds };
      // a private app is assembled at a stand-in central commit until deliverCentral gives the real one (carry 14); the proof pins its own
      if (p.private) draft.centralPin = { repo: `${p.owner}/${CENTRAL_REPO}`, sha: UNPINNED };
    }
    // carry 10: the signing plan from the probed mode, only for services that build an image. key-env (carries 16, 28, 60): a record that
    // already names a public key (a finish --rotate-key) keeps it and makes no pair; otherwise one pair, in memory, before the verify literal
    let pair: SigningKey | undefined;
    let pubSha: string | undefined;
    if (saved0 !== null) {
      // the pair of the stopped run lived only in memory: a saved key-env draft whose key no record holds can't be delivered (fail closed)
      if (draft.signing?.mode === 'key-env' && (trusted.record?.cosignPubSha256 === undefined || trusted.record.cosignPubSha256 !== (draft.signing as { cosignPubSha256?: string }).cosignPubSha256)) {
        err(KEY_PAIR_GONE);
        return 2;
      }
    } else {
      if (keyEnvApplies) {
        // G-SIGN1-R2 sec I1: an environment this run made holds no key, so a recorded public key is never reused for it (a fresh pair)
        pubSha = runSigningEnv === undefined ? trusted.record?.cosignPubSha256 : undefined;
        if (pubSha === undefined) {
          pair = await st.signingKey();
          pubSha = pubKeySha256(pair.pub);
          // sec M4: the pair is a known value for the run's lifetime (the referee, the guard, the state file and the doc refuse or scrub it)
          rememberKey(keyVault, pair);
        }
      }
      // G17-F1 (sec M1): a skipped deploy part signs nothing (assembly would drop the plan anyway; a key-env plan here would have no key)
      const signing = deploySkipped(skipped) ? undefined : signingFor(p, facts.caps, pubSha);
      if (signing !== undefined) draft.signing = signing;
    }
    const known = knownChecks(vault, keyVault);

    // 12. the creators (a resume keeps the saved draft's files)
    if (saved0 === null) {
      made = await st.creators(draft, bundle as CodeBundle, ai, dir, vault, reviewed);
      draft = { ...draft, created: [...draft.created, ...made.files], notProven: [...draft.notProven, ...made.notProven], testDecisions: made.testDecisions };
    }
    // 13. the secrets (asked again on a resume: the vault is wiped at every exit), then the fingerprint key (only through generateFpKey, carry 23)
    const sec = await st.secrets(p, draft.created, vault, io);
    for (const n of sec.notes) err(n);
    generateFpKey(vault);
    // S3: stages 12-13 are `created`
    if (saved0 === null) store.setStage('created');
    // 14. Slack: nothing in v0.2

    // 15. assemble, judge, guard (on a resume: the saved draft re-refereed and re-guarded before any push, S20)
    const plat = await (deps.platformActions ?? ((r, f) => platformActions(r, { gh: f.gh, fetch: io.fetch ?? globalThis.fetch, alert: () => {}, notes: [], ...f.clock })))(reviewed, facts);
    const testNotes = made.testNotes.filter((n) => !isAiNote(n));
    const credits = await st.credits(p, draft, dir) ?? [];
    const transcript = debated?.transcript ?? [];
    const inputs = (d: PipelineDraft, centralFiles?: readonly string[]): BuildInput => ({
      dir, draft: d, plan: { ...plan, needs: d.needs }, facts, vault: known, reviewed, platform: plat, owners: pick.owners, strictness: level, transcript, testNotes, est, auth,
      credits, prev: trusted.record, ...(centralFiles === undefined ? {} : { centralFiles }),
    });
    let built = await st.build(inputs(draft));
    if (!judgedClean(built)) return 2;

    // 16-17. the proof (G14, run-proof.ts); delivery only from `cleaned` with a passed proof (Plan E carry (a)1)
    const assembleIn = (d: PipelineDraft, mode: 'none') => assemble(d, { gate: gateOf(reviewed), reviewed, platform: plat, mode, layout: d.profile.private ? 'central' : 'local', plan: { ...plan, needs: d.needs } });
    const proofAssemble = proofAssembler(built.assembled.draft, assembleIn);
    const proofBuild = built.proof;
    const pre = built;
    // a resume whose proof passed (proven: its cleanup didn't finish; cleaned: delivery is next) proves nothing again
    let proof: ProofReturn;
    if (resume && next !== 'proving') {
      if (next === 'cleaned') {
        const c = await (deps.cleanupOnly ?? makeCleanupOnly())({ store, gh: facts.gh, vault, io, auth, ai: { meter } });
        for (const l of c.leftovers) err(`Left behind: ${safeText(l, 300)}`);
      }
      proof = { ok: true };
    } else {
    // a resume proves the saved draft again from `proving` (nextStage), and never delivers what didn't pass
    if (resume) store.setStage('proving');
    proof = await (deps.proof ?? defaultProof)({
      draft, assembled: built.assembled.draft, files: built.files, assemble: proofAssemble,
      // the security review's carry: the proof assembles the draft it is given (the fix loop's), never only the pre-proof one
      assembleFor: async (d) => proofAssembler(d === draft ? pre.assembled.draft : proofBuild === undefined ? d : (await proofBuild.rebuild(d)).assembled, assembleIn),
      ...(proofBuild === undefined ? {} : { build: proofBuild }),
      store, auth, gh: facts.gh, vault, ai: { meter }, io,
      ...(debated === undefined || base === undefined ? {} : { debate: debated, withWinners: ((b: PipelineDraft, d: DebateResult, d0: PipelineDraft) => (w: ReadonlyMap<string, Choice>) => ({ ...d0, steps: draftFromDebate(b, d, w).draft.steps }))(base, debated, draft) }),
      reviewed, platform: plat, dir, ...(bundle === undefined ? {} : { bundle }),
      scanner: () => (deps.secretScanner ?? pinnedScanner)(scannerName),
      arm: (cleanup, meters) => { disarm = (deps.arm ?? defaultArm)(runStore, cleanup, meters); if (dropEnv !== null) armEnvHook?.(); },
      variantMinutes: Math.max(1, Math.ceil(est.setupMinutes / 2)),
      checkRepos: async () => {
        const r = await st.proofRepos(facts, p, auth, runStore, runId, proofActions(reviewed));
        // sec M3: the central Actions access level before the change, saved at once
        if (r.actionsAccess !== undefined) runStore.recordActionsAccess(r.actionsAccess.previous);
        return r;
      },
      ...(resume ? { resume: true } : {}),
    });
    }
    const repos: Pick<ProofRepos, 'created' | 'createdIds' | 'actionsAccess'> = proof.repos ?? { created: [] };
    if (!proof.ok) { err(safeText(proof.stopped ?? 'pipegen stopped: the proof did not pass, so nothing was delivered. exit code 2.', 1200)); return 2; }
    const saved = store.load();
    // sec M4: a Ctrl-C after the cleanup (the preview, the delivery) leaves it interrupted or stopped AT cleaned: still cleaned, with its verdict
    const cleanedNow = saved !== null && (saved.stage === 'cleaned' || ((saved.stage === 'interrupted' || saved.stage === 'stopped') && saved.interruptedAt === 'cleaned'));
    if (saved === null || !cleanedNow || saved.proofOk !== true) { err('pipegen stopped: the proof did not end cleaned up with a passed verdict, so nothing was delivered. exit code 2.'); return 2; }
    // G13-R1 (sec I3): deliver only the draft saved with the passing verdict of THIS run
    const proven = provenDraft(saved, runId, proof.draft);
    if ('stop' in proven) { err(proven.stop); return 2; }
    // sec I4 / spec I3: a draft the proof changed is built and judged again (a private app at the stand-in commit) before anything leaves
    if (!sameDraft(proven.draft, draft)) {
      draft = { ...proven.draft, ...(p.private ? { centralPin: { repo: `${p.owner}/${CENTRAL_REPO}`, sha: UNPINNED } } : {}) };
      built = await st.build(inputs(draft));
      if (!judgedClean(built)) return 2;
    }
    const provenBuild = built;

    // 18. two-step delivery (carries 14, 15): deliverCentral (the central files of the last judged build), the re-pin, the central file list
    // once, assemble and judge again
    let centralFileList: string[] | undefined;
    let centralCommitted: string | undefined;
    if (p.private) {
      const centralFiles = built.files.filter((f) => f.repo === 'central' && !f.path.endsWith('--required.yml') && /^\.github\/workflows\/[^/]+--[^/]+\.ya?ml$/.test(f.path));
      const c = await st.deliverCentral(facts, p, centralFiles, io, saved.centralPr, runStore);
      // G17C-R1 (F5): the PR and pipegen's commit on it are kept, so the next run can prove its merge put pipegen's files there
      if (c.kind === 'central-pr' && c.pr !== undefined) store.centralPrOpened(c.pr.number, c.pr.commit);
      if (c.kind === 'central-pr') { out(safeText(c.message, 600)); err('exit code 2: merge the central pull request, then run `npx pipegen run` again.'); return 2; }
      for (const d of c.done) out(`done: ${safeText(d, 200)}`);
      // G17 row 28: only the commit deliverCentral made in this run (or, G17C-R1, the merge of pipegen's own central PR) proves pipegen added a new central file
      if (c.committed === true) centralCommitted = c.sha;
      draft = { ...draft, centralPin: { repo: `${p.owner}/${CENTRAL_REPO}`, sha: c.sha } };
      centralFileList = await st.readCentralFileList(facts, p);
      built = await st.build(inputs(draft, centralFileList));
      if (!judgedClean(built)) return 2;
    } else if (built.files.some((f) => f.repo === 'central')) {
      // G13-R2: a public app's batch holds the record repo's CODEOWNERS (the central lock): judged against the central file list, and
      // delivered with it (deliver refuses central files without one)
      centralFileList = await st.readCentralFileList(facts, p);
      built = await st.build(inputs(draft, centralFileList));
      if (!judgedClean(built)) return 2;
      // G14 (controller addendum): the central file list may change a public app's central CODEOWNERS only, never what the app gets
      if (!sameFiles(appFilesOf(built.files), appFilesOf(provenBuild.files))) { err(PUBLIC_FILES_CHANGED); return 2; }
    }
    // carries 23, 31: no planted file, no proof harness and no compat copy is ever delivered
    if (built.files.some((f) => isPlantedPath(f.path) || f.path === HARNESS_PATH || f.path.startsWith(COMPAT_PREFIX))) { err(PROOF_FILE_IN_DELIVERY); return 2; }
    // ruling G13-R0 3: the preview estimate from the assembled jobs; asked again when it is higher than what was agreed
    const est2 = estimate(p, built.minutes.jobs, 2, activity, provider, { needKeys: needKeyCount(built.assembled.draft.needs) });
    if (est2.monthlyMinutes > agreedMinutes) {
      const again = await ask(`The pipeline as built needs about ${est2.monthlyMinutes} Actions minutes a month, more than the ${agreedMinutes} you agreed to. Go on?`);
      if (!again) { err('Nothing was delivered: you said no to the higher minutes. The secrets you typed were wiped.'); return 1; }
    }
    // 19's inputs (key-env: the key pair made in memory, carry 16 and 28). G-SIGN1-R2 sec I1: delivery gets the run's environment only
    // when it will set it up (it stores the new key in it); otherwise the run keeps it and deletes it when it ends
    const keyEnv = built.assembled.draft.signing?.mode === 'key-env';
    const key = pair;
    const handOver = runSigningEnv !== undefined && keyEnv && key !== undefined;
    const input: DeliveryInput = {
      draft: built.assembled.draft, files: built.files, locks: built.locks, secretNames: sec.names,
      protectedPaths: codeownersProtectedPaths(built.assembled.draft, reviewed), environments: built.environments,
      proofRepos: proofReposFor(repos, saved),
      ...(centralFileList === undefined ? {} : { centralFileList }),
      ...(centralCommitted === undefined ? {} : { centralCommitted }),
      ...(handOver && runSigningEnv !== undefined ? { signingEnv: runSigningEnv } : {}),
    };
    if (built.assembled.draft.centralPin?.sha === UNPINNED) throw new Error('pipegen would deliver a draft with no central commit pinned; nothing was delivered.');
    const note = bootstrapProofsNote(io.env);
    const preview = [
      st.preview(input), ...(note === null ? [] : ['', note]),
      // spec I7: what the environment plan couldn't do (an approval with no environment to put it on), said before the yes
      ...(built.envNotes.length === 0 ? [] : ['', ...built.envNotes.map((n) => safeText(n, 600))]),
      ...(built.hookNotes.length === 0 ? [] : ['', ...built.hookNotes.map((n) => safeText(n, 600))]),
      ...((built.adoptedNotes ?? []).length === 0 ? [] : ['', ...(built.adoptedNotes ?? []).map((n) => safeText(n, 600))]),
      '', `A pull request waits about ${built.minutes.prWait} minutes at most for the checks; about ${est2.monthlyMinutes} Actions minutes a month.`,
    ].join('\n');
    if (!(await ask(`${preview}\n\nOpen the setup pull request with these changes?`))) { err('Nothing was delivered: you said no. The secrets you typed were wiped. exit code 1.'); return 1; }
    // 19. deliver. G-SIGN1-R2 sec M4, one synchronous step (no signal handler runs in between): a stop already under way ends the run
    // here (its hook deletes the environment); else delivery takes the run's signing environment (the record or its leftovers name it)
    if ((deps.interrupting ?? interrupting)()) { err(STOP_AT_HAND_OFF); return 1; }
    if (handOver) { try { (disarmEnv as (() => void) | null)?.(); } finally { disarmEnv = null; dropEnv = null; } }
    const res = await st.deliver(facts, p, input, vault, io, keyEnv && key !== undefined ? async () => key : undefined, runStore);
    deliveredRun = true;
    store.setStage('delivered');
    // carry 19 (spec I4): everything delivery says
    for (const d of res.done) out(`done: ${safeText(d, 300)}`);
    for (const s of res.skipped) out(`skipped: ${safeText(s.what, 200)} (${safeText(s.why, 600)})`);
    for (const n of res.notes) out(safeText(n, 600));
    out(`The setup pull request: ${safeText(res.prUrl, 300)}`);
    if (res.centralPrUrl !== undefined) out(`The central pull request (merge it too): ${safeText(res.centralPrUrl, 300)}`);

    // 20. wait for the merge, then finish in this process
    const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => { setTimeout(r, ms); }));
    const until = now() + MERGE_WAIT_MS;
    let state = await st.prState(facts, p, res.prNumber);
    while (state === 'open' && now() < until) { await sleep(MERGE_POLL_MS); state = await st.prState(facts, p, res.prNumber); }
    if (state === 'closed') { out('The setup pull request was closed without merging: nothing was applied.'); return 0; }
    if (state === 'open') {
      out('After merging, run `npx pipegen finish`.');
      out('A team that applies settings itself: `npx pipegen finish --print` prints the commands instead.');
      return 0;
    }
    const code = await st.finish(facts, p, io, runStore);
    // 21. the summary
    out(code === 0 ? 'pipegen set up this repository.' : 'pipegen delivered the setup; finish did not complete (see above).');
    return code;
  }

  async function ask(q: string): Promise<boolean> {
    try { return (await io.prompt.confirm(q, false)) === true; } catch { return false; }
  }
  function judgedClean(b: Built): boolean {
    if (b.report.issues.length === 0 && b.guardProblems.length === 0) return true;
    err('pipegen stopped: the files it built did not pass its own checks, so nothing was changed. exit code 2.');
    for (const i of b.report.issues.slice(0, 40)) err(`  ${safeText(i.file, 120)}: ${safeText(i.message, 400)}`);
    for (const g of b.guardProblems.slice(0, 40)) err(`  ${safeText(g, 400)}`);
    return false;
  }
}

/**
 * Carries 16 and 24: what deliver records of the helper repos: the central repo pipegen created (with GitHub's id) and the Actions access
 * level it changed there (checkProofRepos), the scratch repo pipegen created (the state file's id).
 */
type SigningEnvEntry = InstallRecord['environments'][number];
/** Ruling G-SIGN1: why a first run that could sign with a key pair doesn't, when the machine has no memory folder for the pair. */
export const NO_MEMORY_SIGNING_OFF = `Signing is off (mode none): this repository's images would be signed with a key pair, which pipegen makes only in memory (${MEMORY_DIR}), and this machine has no such folder, so pipegen made no signing environment. Run pipegen on Linux (WSL or a Linux container works too) to sign.`;
export const RUN_SIGNS_NOTE = `pipegen made the environment ${SIGNING_ENVIRONMENT} (default branch only) and read it back, so this run signs its images with a key pair (key-env).`;

/** Ruling G-SIGN1-R1: the deletion notice of a run that stopped before delivery. */
export const SIGNING_ENV_DELETED = `pipegen deleted the environment ${SIGNING_ENVIRONMENT} it made earlier in this run: nothing was delivered.`;
/** G-SIGN1-R3 (spec r2-L1): the delivered pipeline didn't use the environment the run made. */
export const SIGNING_ENV_UNUSED = `pipegen deleted the environment ${SIGNING_ENVIRONMENT} it made earlier in this run: the delivered pipeline doesn't sign with it.`;
/** Ruling G-SIGN1-R1: the production arm (an interrupt hook, like the proof's keys). */
export const defaultArmSigningEnv = (cleanup: () => Promise<void>, opts: InterruptOptions): (() => void) => onInterrupt(async () => { await cleanup(); }, opts);
/** G-SIGN1-R2 sec M3: the environment hook's label (a constant) and its deadline (short: the environment holds no secret yet). */
export const SIGNING_ENV_HOOK_LABEL = `deleting the signing environment ${SIGNING_ENVIRONMENT} this run made`;
export const SIGNING_ENV_HOOK_DEADLINE_MS = 30_000;
/** G-SIGN1-R2 sec M4: a stop began before the hand-off to delivery. */
export const STOP_AT_HAND_OFF = 'pipegen stopped: a stop began before the delivery, so nothing was delivered. exit code 1.';
/** G-SIGN1-R2 sec N1: the path could run, but the consent the user answered didn't name the signing environment. */
export const NOT_AGREED_SIGNING_OFF = `Signing is off (mode none): the consent screen you answered didn't say pipegen creates the environment ${SIGNING_ENVIRONMENT}, so it makes none.`;

/** G17-F1 (sec M1): the deploy part is skipped (`--skip deploy`): no image is published or signed (jobs.ts drops the signing plan). */
export const deploySkipped = (skipped: PipelineDraft['skipped']): boolean => skipped.some((x) => x.part === 'deploy');
/** Whether this run signs with a key pair it makes (key-env with a published image, the deploy part not skipped). */
export function keyEnvFor(p: RepoProfile, caps: Capabilities, skipped: PipelineDraft['skipped']): boolean {
  return !deploySkipped(skipped) && signingMode(p, caps) === 'key-env' && publishedImageServices(p, caps).length > 0;
}

/**
 * Whether firstRunSigning would make the run's own environment (the memory folder aside): a private repo with environments, the rule not
 * proven yet, and key-env with a published image once it is (attestations, no image, a public repo: never).
 */
export function firstRunSigningCan(p: RepoProfile, caps: Capabilities, skipped: PipelineDraft['skipped']): boolean {
  if (deploySkipped(skipped)) return false;   // G17-F1 (sec M1): nothing is signed with the deploy part skipped
  if (!p.private || !caps.environments || caps.deploymentBranchPolicies) return false;
  const proven: Capabilities = { ...caps, deploymentBranchPolicies: true };
  return signingMode(p, proven) === 'key-env' && publishedImageServices(p, proven).length > 0;
}

/**
 * Ruling G-SIGN1 (G16 review F6): the first run on a private repo signs when the plan allows. Asked only when key-env is what the proven
 * rule would give (a private repo, environments, no attestations, a published image) and the probe could not prove the rule (no
 * pipegen-signing yet). `make` is the run's own environment (makeRunSigningEnvironment: made new, read back default-branch only); only a
 * fresh environment of that name with its branch rule turns deploymentBranchPolicies on. Fail closed: any other answer keeps `caps` as
 * probed (signing mode none) with the reason in `notes`; nothing claims signing that the read-back didn't prove.
 */
export async function firstRunSigning(p: RepoProfile, caps: Capabilities, make: () => Promise<{ env: SigningEnvEntry } | { off: string }>, memory: () => boolean, agreed: boolean, skipped: PipelineDraft['skipped']): Promise<{ caps: Capabilities; env?: SigningEnvEntry; notes: string[] }> {
  if (!firstRunSigningCan(p, caps, skipped)) return { caps, notes: [] };
  const proven: Capabilities = { ...caps, deploymentBranchPolicies: true };
  if (!memory()) return { caps, notes: [NO_MEMORY_SIGNING_OFF] };
  // G-SIGN1-R2 (sec N1): only when the consent the user answered named the environment
  if (!agreed) return { caps, notes: [NOT_AGREED_SIGNING_OFF] };
  const made = await make();
  if ('off' in made) return { caps, notes: [`Signing is off (mode none): ${made.off}`] };
  const e = made.env;
  if (e?.name !== SIGNING_ENVIRONMENT || e.created !== true || !Array.isArray(e.branchPolicyIds) || e.branchPolicyIds.length === 0) {
    return { caps, notes: [`Signing is off (mode none): the environment ${SIGNING_ENVIRONMENT} didn't read back as one this run made with its default-branch rule.`] };
  }
  return { caps: proven, env: e, notes: [RUN_SIGNS_NOTE] };
}

export function proofReposFor(repos: Pick<ProofRepos, 'created' | 'createdIds' | 'actionsAccess'>, saved: { scratchRepoId?: number; actionsAccessPrevious?: string; centralCreated?: boolean; centralRepoId?: number }): NonNullable<DeliveryInput['proofRepos']> {
  // G17 row 27: this run's id of the repo it created, else the one the state saved when an earlier (interrupted) run of it created the repo
  const id = repos.createdIds?.[CENTRAL_REPO] ?? (saved.centralCreated === true ? saved.centralRepoId : undefined);
  // sec M3: the level saved the moment it changed (an earlier, interrupted run's included) wins over this run's read
  const previous = saved.actionsAccessPrevious ?? repos.actionsAccess?.previous;
  return {
    central: {
      ...(id === undefined ? { createdByPipegen: repos.created.includes(CENTRAL_REPO) || saved.centralCreated === true } : { repoId: id, createdByPipegen: true }),
      ...(previous === undefined ? {} : { actionsAccess: { previous } }),
    },
    scratch: { ...(saved.scratchRepoId === undefined ? {} : { repoId: saved.scratchRepoId }), createdByPipegen: saved.scratchRepoId !== undefined },
  };
}

/** The run's trust step (the stage `trusted`): the earlier record pipegen builds on, with its notes and (G17C-R1, F6/m2) the run's own way on. */
export async function trustedForRun(f: Pick<GitHubFacts, 'gh' | 'clock'>, p: { owner: string; repo: string }, local: LocalRecordDeps, prompt: Prompter, interactive: boolean): Promise<{ record: InstallRecord | null; notes: string[] }> {
  const notes: string[] = [];
  const central = { owner: p.owner, repo: CENTRAL_REPO };
  const c = await readRepo(f.gh, central, f.clock);
  if (c === null) return { record: null, notes };
  const t = await trustedPrevious(f.gh, { owner: p.owner, repo: p.repo }, central, c.defaultBranch, null, local, f.clock, notes, { io: prompt, interactive });
  if (t.why === 'unreadable') notes.push(UNREADABLE_RUN_WAY_ON);
  return { record: t.record, notes };
}

/** The pinned scanner, downloaded and checked against its pin; the version from the same pins table (the audit's defaultSecretScanner). */
async function pinnedScanner(name: 'gitleaks' | 'betterleaks'): Promise<{ name: 'gitleaks' | 'betterleaks'; path: string; version: string }> {
  const pins = loadPinnedBinaries();
  const path = await ensurePinnedBinary(name, undefined, { pins });
  return { name, path, version: pins[name].version };
}

/** What the run agreed to at consent: the provider (name, model, Ollama host) and the AI cost cap of the estimate. */
export interface Agreed { ai: ReturnType<typeof makeProvider>; capUsd: number | null }
/**
 * G13-R1 (sec I1), the audit's pattern: after the yes, the scanner the consent screen named (name and version) over exactly the files it
 * counted. A token that is not askConsent's 'full' one, a spent one, another folder, provider, model or cap (G13-R2 5), another scanner, or a
 * bundle with a file that was not counted is refused (thrown).
 */
export async function scanCounted(dir: string, consent: ConsentToken, knownValues: string[], ensure: NonNullable<RunDeps['secretScanner']>, agreed: Agreed): Promise<CodeBundle> {
  const c: unknown = consent;
  if (!ConsentToken.isToken(c) || c.terms.mode !== 'full') throw new Error('pipegen run needs the consent askConsent gives for its own screen; nothing was sent.');
  // G13-R2 5 (the audit's checkConsent): spent before the first await, so two scans started at once can't both pass; a token refused below is
  // spent too (the safe side)
  if (isSpent(c)) throw new Error('This consent was already used; each run needs its own yes. Nothing was sent.');
  spend(c);
  const t = c.terms;
  const host = agreed.ai.name === 'ollama' ? ollamaHostOf(agreed.ai) ?? undefined : undefined;
  if (t.pricedFor.provider !== agreed.ai.name || t.pricedFor.model !== agreed.ai.model || t.pricedFor.host !== host || t.capUsd !== agreed.capUsd) {
    throw new Error('The scan was given another AI provider, model or cost cap than the one you agreed to; nothing was sent.');
  }
  const counted = t.files;
  const here = await realpath(dir).catch(() => null);
  if (!CountingSummary.isSummary(counted) || t.dir === null || counted.dir !== t.dir || here !== t.dir) throw new Error('This consent was given for the files counted in another folder; nothing was sent.');
  const named = c.terms.secretScanner;
  if (named === undefined) throw new Error('The consent named no secret scanner; nothing was sent.');
  const scanner = await ensure(named.name);
  if (scanner.name !== named.name || scanner.version !== named.version) {
    throw new Error(`pipegen was given ${safeText(scanner.name, 20)} ${safeText(scanner.version, 20)}, not the ${named.name} ${named.version} the consent screen named, and ran neither.`);
  }
  const bundle = await bundleCode(dir, { secretScanner: scanner, knownValues, onlyPaths: counted.paths() });
  if (!counted.covers(bundle)) throw new Error('The scanned files are not the ones you agreed to send; nothing was sent.');
  return bundle;
}

/** The AI provider keys set in the environment (makeProvider reads these names), for the state store's token check. */
export const aiKeysOf = (env: NodeJS.ProcessEnv): string[] =>
  ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY'].map((n) => env[n]).filter((v): v is string => typeof v === 'string' && v !== '');

const appFilesOf = (files: readonly CreatedFile[]): CreatedFile[] => files.filter((f) => f.repo === 'app');
/** The same files (path, repo, content) in any order. */
const sameFiles = (a: readonly CreatedFile[], b: readonly CreatedFile[]): boolean => {
  const k = (fs: readonly CreatedFile[]) => fs.map((f) => JSON.stringify([f.repo, f.path, f.content])).sort();
  return isDeepStrictEqual(k(a), k(b));
};

/** sec I5: only the scratch repo (pipegen-proof-<repo>) is the state's scratch repo; the central repo checkProofRepos also creates is not. */
export const onCreatedFor = (store: Pick<StateStore, 'scratchCreated' | 'update'> & Partial<Pick<StateStore, 'centralCreatedWith'>>, repo: string) => (name: string, id: number): void => {
  if (name === `pipegen-proof-${repo}`) store.scratchCreated(id);
  // G14-R1 (spec M1): a resume's delivery record still says pipegen made the central repo; G17 row 27: with GitHub's id of it
  if (name === CENTRAL_REPO) {
    if (store.centralCreatedWith !== undefined && Number.isSafeInteger(id) && id > 0) store.centralCreatedWith(id);
    else store.update((n) => { n.centralCreated = true; });
  }
};

/** sec M4: the key-env pair's secret parts (the password and each line of the private key's body) as known values. */
export function rememberKey(keyVault: SecretVault, pair: SigningKey): void {
  keyVault.set('COSIGN_PASSWORD', pair.password);
  let n = 0;
  for (const line of pair.key.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length < 8 || /^-----(BEGIN|END) /.test(t)) continue;
    keyVault.set(`COSIGN_KEY_${n++}`, t);
  }
}

/** The run's one known-value check: the user's vault and the key vault (the key vault never reaches deliver's secret names). */
export function knownChecks(...vaults: KnownValueCheck[]): KnownValueCheck {
  return {
    containsKnownValue: (t) => vaults.some((v) => v.containsKnownValue(t)),
    scrubber: () => { const fns = vaults.map((v) => v.scrubber()); return (t) => fns.reduce((acc, fn) => fn(acc), t); },
  };
}

const jsonCopy = (x: unknown): unknown => JSON.parse(JSON.stringify(x)) as unknown;
/** Two drafts are the same after a JSON round trip (the state file's form). */
export const sameDraft = (a: PipelineDraft, b: PipelineDraft): boolean => isDeepStrictEqual(jsonCopy(a), jsonCopy(b));

/**
 * sec I3: the draft delivery builds from is the one the state saved with the passing verdict, of this run only; a proof that hands back
 * another draft than the one it saved is refused.
 */
export function provenDraft(saved: Pick<RunState, 'runId' | 'draft'>, runId: string, returned: PipelineDraft | undefined): { draft: PipelineDraft } | { stop: string } {
  if (saved.runId !== runId) return { stop: 'pipegen stopped: the saved proof verdict belongs to another run, so nothing was delivered. exit code 2.' };
  if (saved.draft === undefined) return { stop: 'pipegen stopped: the proof saved no draft with its verdict, so nothing was delivered. exit code 2.' };
  if (returned !== undefined && !sameDraft(returned, saved.draft)) return { stop: 'pipegen stopped: the proof returned another draft than the one it saved with its verdict, so nothing was delivered. exit code 2.' };
  return { draft: saved.draft };
}

/**
 * Carry 46: the services the proof can't prove, named before consent. Only Node and Python services get planted items (src/debate/planted.ts);
 * any other service's checks end not proven. (In v0.2 supportLevel already stops a repo with such a service; the line stays for v0.4.)
 */
export function notProvableNotes(p: Pick<RepoProfile, 'services'>): string[] {
  return p.services.filter((s) => s.language !== 'node' && s.language !== 'python').map((s) =>
    `The service "${safeText(s.name, 60)}" is neither Node nor Python: pipegen has no planted template for it, so its checks will end not proven (the proof can't show they catch anything).`);
}

/**
 * Carry 13 (review-GJ-r3 N8, ruling G13-R0 6): a blocking DAST check of a hinted service that can't start stops the run (jobs.ts never
 * makes it warn-only or drops it); the stop names the way past: the --type flag, or a Dockerfile pipegen can see. Nothing skips DAST.
 */
export function dastWayPast(message: string, services: readonly { name: string; containerHint?: string }[]): string[] {
  // spec M3: the service named exactly as jobs.ts writes it (`The blocking check "dast" for "<name>" can not run`), never a substring
  const named = (name: string): boolean => message.includes(`The blocking check ${JSON.stringify('dast')} for ${JSON.stringify(safeText(name, 60))} can not run`);
  return services.filter((s) => s.containerHint !== undefined && named(s.name)).map((s) =>
    `The service ${safeText(s.name, 60)} is built into an image elsewhere (${safeText(s.containerHint as string, 200)}), but pipegen sees no Dockerfile of its own to start it for the DAST check. Either add a Dockerfile in its folder, or, if it is a static site, run again with --type ${safeText(s.name, 60)}=static-site (at a terminal, the type question asks the same). pipegen never skips the DAST check.`);
}

/** The actions the proof runs (checkProofRepos checks them against the scratch repo's Actions settings): every pinned reviewed action, a superset. */
export const proofActions = (reviewed: readonly ReviewedTool[]): string[] =>
  reviewed.filter((t) => t.candidate.kind === 'action' && typeof t.candidate.pin.sha === 'string').map((t) => `${t.candidate.repo}@${t.candidate.pin.sha as string}`);

const gateOf = (reviewed: readonly ReviewedTool[]): ReviewedTool => {
  const g = reviewed.find((t) => t.id === 'pipegen-gate');
  if (g === undefined) throw new Error('pipegen\'s reviewed list has no gate entry in this build.');
  return g;
};

// ---------- the real stages ----------

const MAX_WORKFLOW_TEXT = 512 * 1024;
const MAX_BLOB = 512 * 1024;

/** The user's workflow texts (regular files only, never a link, with a size cap; deliver re-checks the base tree): carry 25. */
export async function workflowTexts(dir: string, paths: readonly string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const path of paths) {
    if (!/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(path)) continue;
    const full = join(dir, path);
    const st = await lstat(full).catch(() => null);
    if (st === null || !st.isFile() || st.size > MAX_WORKFLOW_TEXT) continue;
    out.set(path, await readFile(full, 'utf8'));
  }
  return out;
}

/** What stage 15 reads besides the draft: the user's workflow texts, the app's base tree and both CODEOWNERS (pipegen's earlier block only when the trusted record names it). */
export interface BuildFacts {
  texts: ReadonlyMap<string, string>;
  baseTree: BaseTree;
  appCo: CoFacts & { inserted: string | null };
  centralCo: CoFacts & { inserted: string | null };
  centralBranchProtection: boolean;
  pipegenDoc: { baseSha: string | null; recordSha: string | null };
  serviceTypes: Record<string, 'module' | 'commonjs'>;
  /**
   * G14 (controller addendum, BINDING): the central repo's file list (its default-branch tree), for the referee's central CODEOWNERS re-run check.
   * A re-run after a complete install has a central CODEOWNERS holding pipegen's block, and without the list the first build is refused.
   */
  centralFiles?: readonly string[];
}

/** The block pipegen wrote before: the trusted record's codeowners edit, when the file still holds it exactly once (else none: fail closed). */
export function insertedBlock(prev: InstallRecord | null, repo: 'app' | 'central', co: CoFacts): string | null {
  if (prev === null || co.path === null) return null;
  const e = prev.edits.find((x) => x.repo === repo && x.kind === 'codeowners' && x.path === co.path) as { inserted?: string } | undefined;
  return e?.inserted !== undefined && co.text.split(e.inserted).length === 2 ? e.inserted : null;
}

/** The pure part of stage 15 (no GitHub read): pre-commit files, assemble (twice: the verify plan's not-proven entries are rendered), locks, PIPEGEN.md. */
export type EnvPlanFn = (requireApproval: boolean, inserted: readonly string[]) => Promise<{ envs: readonly EnvironmentPlan[]; notes: string[] }>;
const NO_ENV_PLAN: EnvPlanFn = async () => ({ envs: [], notes: [] });
export async function buildFiles(i: BuildInput, f: Pick<BuildFacts, 'texts' | 'appCo' | 'centralCo' | 'centralBranchProtection'>, envPlan: EnvPlanFn = NO_ENV_PLAN): Promise<Omit<Built, 'report' | 'guardProblems'>> {
  const { draft: d0, reviewed, platform } = i;
  const p = d0.profile;
  const skip = (part: SkippablePart): boolean => d0.skipped.some((s) => s.part === part);
  // carry 25: releaseJobs into AssembleOpts.deploy
  const deploy = skip('deploy') ? undefined : releaseJobs(d0, { platform });
  // carry 37: the hook files go into draft.created (G9 reads them), through the guard and the referee with everything else
  const precommit: PrecommitResult = skip('precommit') ? { files: [], edits: [], setupCommand: '', notes: [] } as unknown as PrecommitResult : await precommitFiles(d0, reviewed, i.dir, (i.prev?.edits ?? []).filter((e) => e.repo === 'app' && e.kind === 'hooks').map((e) => ({ path: e.path, inserted: (e as { inserted: string }).inserted })));
  const withHooks: PipelineDraft = { ...d0, created: [...d0.created, ...precommit.files] };
  // G13-R2 7: hooks in place that the trusted record holds no hooks edit for are not removed by an uninstall: said in the doc and the preview
  const hookNotes = (precommit.inPlace ?? []).filter((h) => !(i.prev?.edits ?? []).some((e) => e.repo === 'app' && e.kind === 'hooks' && e.path === h.path)).map((h) =>
    `pipegen's hooks are already in ${h.path}, but the install record pipegen trusts does not list them, so an uninstall would leave them: remove pipegen's lines from ${h.path} by hand (the block that starts with the pipegen:hooks comment) if you uninstall.`);
  const opts = { gate: gateOf(reviewed), reviewed, platform, mode: (d0.signing?.mode ?? 'none') as SigningMode, layout: p.private ? 'central' as const : 'local' as const, plan: i.plan, ...(deploy === undefined ? {} : { deploy }) };
  const first = assemble(withHooks, opts);
  // carry 26: the verify plan's not-proven entries are rendered, so assemble runs again with them
  const verify = planVerifyInserts(first.draft, f.texts, first.verify);
  const withVerify: PipelineDraft = { ...withHooks, notProven: [...withHooks.notProven, ...verify.notProven] };
  const a0 = assemble(withVerify, opts);
  const jobs = assembleJobs(withVerify, i.plan, { reviewed, platform, mode: opts.mode });
  const inserted = verify.inserts.map((x) => x.file);
  const protectedPaths = codeownersProtectedPaths(a0.draft, reviewed);
  const locks: LockPlan = skip('locks')
    ? { owners: { app: [], central: [] }, writers: { app: [...i.facts.lockWriters.app], central: [...i.facts.lockWriters.central] }, notes: ['Merge locks were skipped with --skip locks: nothing requires the gate to pass before a merge.'] } as unknown as LockPlan
    : planLocks({
      profile: { ...p, repoFiles: { ...p.repoFiles, codeowners: f.appCo.path } }, caps: i.facts.caps,
      central: { repo: `${p.owner}/${CENTRAL_REPO}`, sha: d0.centralPin?.sha ?? '0'.repeat(40), branchProtection: f.centralBranchProtection, codeowners: { path: f.centralCo.path, original: f.centralCo.text, isSymlink: f.centralCo.isSymlink, inserted: f.centralCo.inserted } },
      writers: i.facts.lockWriters, owners: i.owners, orgAdmin: i.facts.orgAdmin, shaPinning: i.facts.shaPinning, protectedPaths,
      appCodeowners: { original: f.appCo.text, isSymlink: f.appCo.isSymlink, inserted: f.appCo.inserted },
      ...(i.facts.ids.app === null || i.facts.ids.central === null ? {} : { ids: { app: i.facts.ids.app, central: i.facts.ids.central } }),
      files: a0.files,
    });
  const prWait = prWaitMinutes(jobs.merge);
  // G17 row 29 (G10-r2 P3): a whole file an earlier run adopted whose text this run changes is said in PIPEGEN.md and at the preview
  const lockFiles = [locks.codeowners?.file, locks.centralCodeowners?.file, locks.orgRequiredWorkflow?.file].filter((x): x is CreatedFile => x !== undefined);
  const adoptedNotes = [...new Set([...a0.draft.created, ...a0.files, ...inserted, ...lockFiles].filter((x) => x.edited === undefined && x.inserted === undefined).flatMap((x) => {
    const was = i.prev?.files.find((r) => r.repo === x.repo && r.path === x.path);
    if (was?.adopted !== true || was.shas.includes(gitBlobSha(x.content))) return [];
    // G17C-R1 (F5): only what the record says (an earlier run found the file identical to pipegen's text and couldn't prove pipegen wrote it)
    return [`pipegen rewrites ${x.path}${x.repo === 'central' ? ` in ${CENTRAL_REPO}` : ''}: the install record lists it as adopted, not created (an earlier run found it identical to pipegen's text and couldn't prove pipegen wrote it), and this run changes it. Uninstall still asks before it deletes it.`];
  }))];
  // spec I7: what the environment plan can't do lands in doc.notes (and the preview) before the judge
  const env = await envPlan(a0.draft.requireDeployApproval, verify.inserts.map((x) => x.path));
  const envNotes = [...new Set(env.notes)];
  // carries 31-34: the doc is filled before the judge
  const doc = docFor({
    transcript: i.transcript, verify, locks: { notes: locks.notes, gateRequired: locks.rulesets !== undefined || locks.classic !== undefined }, precommit,
    jobs: { notes: jobs.notes, uncoveredMinimum: jobs.uncoveredMinimum }, assembledNotes: [...a0.notes, ...envNotes, ...hookNotes, ...adoptedNotes], testNotes: i.testNotes, credits: i.credits ?? [],
    estimates: i.est, prWaitMinutes: prWait, strictness: i.strictness,
  });
  const finalDraft: PipelineDraft = { ...a0.draft, doc };
  const assembled: AssembledFiles = { ...a0, draft: finalDraft };
  // carry 31: pipegenDoc under the active vault (the scrub before any cut, F4-R14), the same as docs.ts's own vault wrapper
  const pipegenMd = withActiveVault(i.vault, () => pipegenDoc(finalDraft, reviewed));
  // carries 20, 26: the inserted verify jobs, the CODEOWNERS files and the org required workflow travel in the one judged batch
  const extra = [pipegenMd, ...inserted, ...(locks.codeowners === undefined ? [] : [locks.codeowners.file]), ...(locks.centralCodeowners === undefined ? [] : [locks.centralCodeowners.file]), ...(locks.orgRequiredWorkflow === undefined ? [] : [locks.orgRequiredWorkflow.file])];
  return {
    assembled, verify, locks, precommit, doc: pipegenMd, extra, files: [...finalDraft.created, ...a0.files, ...extra],
    environments: env.envs.map((e) => ({ name: e.name, reviewers: e.reviewers })), envNotes, hookNotes, adoptedNotes,
    minutes: { jobs: assembledJobs(jobs, a0.draft.needs, p), prWait },
  };
}

/** The referee's delivery inputs (carry 50): seven arguments, the vault's check, the central file list (carry 15); never isolatedTestJob (carry 54). */
export function createdInputsFor(i: Pick<BuildInput, 'vault' | 'centralFiles'>, f: Pick<BuildFacts, 'appCo' | 'centralCo' | 'pipegenDoc' | 'serviceTypes' | 'centralFiles'>): CreatedInputs {
  const vault = i.vault;
  // readCentralFileList after deliverCentral (carry 15) wins; before it, the central tree readBuildFacts read (G14 addendum)
  const centralFiles = i.centralFiles ?? f.centralFiles;
  return {
    centralCodeowners: f.centralCo.path,
    pipegenDoc: f.pipegenDoc,
    codeownersFacts: { app: { isSymlink: f.appCo.isSymlink, inserted: f.appCo.inserted }, central: { isSymlink: f.centralCo.isSymlink, inserted: f.centralCo.inserted } },
    serviceTypes: f.serviceTypes,
    containsKnownValue: (t: string) => vault.containsKnownValue(t),
    ...(centralFiles === undefined ? {} : { centralFiles }),
  };
}

/** The guard's view of the trusted record: the app files pipegen wrote whole (not adopted, not the owner's since). */
export const guardRecord = (prev: InstallRecord | null): GuardInstallRecord | null => (prev === null ? null : {
  files: prev.files.filter((x) => x.repo === 'app' && x.shas.length > 0).map((x) => ({ path: x.path, part: x.part, sha: x.shas[x.shas.length - 1] as string, created: x.adopted !== true && x.ownerEdited !== true })),
});

/** G-COCASE-R1, read only: coCaseProblem over the default-branch trees of the app and its central repo (a missing branch or repo: no paths). */
export async function coCaseOfRepos(f: GitHubFacts, p: RepoProfile): Promise<string | null> {
  const app = { owner: p.owner, repo: p.repo };
  const central = { owner: p.owner, repo: CENTRAL_REPO };
  const head = await readHead(f.gh, app, p.defaultBranch, f.clock);
  const appPaths = head === null ? [] : [...(await readTree(f.gh, app, head, f.clock)).entries.keys()];
  const centralRepo = await readRepo(f.gh, central, f.clock);
  const cHead = centralRepo === null ? null : await readHead(f.gh, central, centralRepo.defaultBranch, f.clock);
  const centralPaths = cHead === null ? [] : [...(await readTree(f.gh, central, cHead, f.clock)).entries.keys()];
  return coCaseProblem([{ label: `${p.owner}/${p.repo}`, paths: appPaths }, { label: `${p.owner}/${CENTRAL_REPO}`, paths: centralPaths }], 'npx pipegen run');
}

export async function readBuildFacts(i: BuildInput): Promise<BuildFacts> {
  const { gh, clock } = i.facts;
  const p = i.draft.profile;
  const app = { owner: p.owner, repo: p.repo };
  const central = { owner: p.owner, repo: CENTRAL_REPO };
  const texts = await workflowTexts(i.dir, p.existingWorkflows.map((w) => w.path));
  const head = await readHead(gh, app, p.defaultBranch, clock);
  if (head === null) throw new DeliverError(`${p.owner}/${p.repo} has no default branch to build on.`);
  const tree = await readTree(gh, app, head, clock);
  const baseTree: BaseTree = {
    complete: true,
    entries: new Map([...tree.entries].map(([path, e]) => [path, { sha: e.sha, mode: e.mode, read: async () => (e.type === 'blob' && e.mode !== '120000' ? readBlobText(gh, app, e.sha, MAX_BLOB, clock) : null) }])),
  };
  const centralRepo = await readRepo(gh, central, clock);
  if (centralRepo === null) throw new DeliverError(`pipegen can't see ${p.owner}/${CENTRAL_REPO}.`);
  const cHead = await readHead(gh, central, centralRepo.defaultBranch, clock);
  const cTree = cHead === null ? new Map() : (await readTree(gh, central, cHead, clock)).entries;
  // G-COCASE-R1: the same refusal as the early check (a variant that appeared since), before anything is built
  const caseStop = coCaseProblem([{ label: `${p.owner}/${p.repo}`, paths: tree.entries.keys() }, { label: `${p.owner}/${CENTRAL_REPO}`, paths: cTree.keys() }], 'npx pipegen run');
  if (caseStop !== null) throw new DeliverError(caseStop);
  const appCo0 = await coFacts(gh, app, tree.entries, clock);
  const centralCo0 = await coFacts(gh, central, cTree, clock);
  const centralCaps = await probeCapabilities(gh, p.owner, CENTRAL_REPO, { plan: p.plan, ownerType: p.ownerType, private: centralRepo.private, defaultBranch: centralRepo.defaultBranch }, [], clock).catch(() => null);
  const doc = i.prev?.files.find((x) => x.repo === 'app' && x.path === 'PIPEGEN.md');
  const serviceTypes: Record<string, 'module' | 'commonjs'> = {};
  for (const s of p.services) {
    if (s.language !== 'node') continue;
    const root = s.path.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
    const text = await readRegular(i.dir, root === '' ? 'package.json' : `${root}/package.json`, MAX_PACKAGE_JSON);
    const pj = text === null ? null : (() => { try { return JSON.parse(text) as { type?: unknown } | null; } catch { return null; } })();
    serviceTypes[root] = pj?.type === 'module' ? 'module' : 'commonjs';
  }
  return {
    texts, baseTree,
    appCo: { ...appCo0, inserted: insertedBlock(i.prev, 'app', appCo0) },
    centralCo: { ...centralCo0, inserted: insertedBlock(i.prev, 'central', centralCo0) },
    centralBranchProtection: centralCaps?.branchProtection ?? false,
    pipegenDoc: { baseSha: tree.entries.get('PIPEGEN.md')?.sha ?? null, recordSha: doc?.shas[doc.shas.length - 1] ?? null },
    serviceTypes,
    // G14 addendum: the central tree's files (blobs and links: every path the CODEOWNERS block could own)
    centralFiles: [...cTree.entries()].filter(([, e]) => (e as { type?: string }).type !== 'tree').map(([path]) => path as string),
  };
}

function realStages(io: CliIO, deps: RunDeps): RunStages {
  const interactive = interactiveRun(io);
  const local = deps.local ?? {};
  return {
    readOrigin: (dir) => readOrigin(dir),
    localProject: (dir) => readProject(dir),
    getAuth: (o) => getAuth({ ...o, mode: 'write' }, { env: io.env, fetch: io.fetch, clock: { budget: newRateBudget() } }),
    async readProject(auth, l) {
      const clock: RateClock = { budget: newRateBudget() };
      const notes: string[] = [];
      const gh = makeOctokit(auth.token, { fetch: io.fetch, clock, timeoutMs: GITHUB_TIMEOUT_MS, log: (s) => { io.err(s); } });
      const login = await tokenLogin(gh, auth, clock, notes);
      const context = await readGitHubContext(gh, l.owner, l.repo, login, clock, notes);
      const caps = await probeCapabilities(gh, l.owner, l.repo, { ...l, ...context }, notes, clock);
      const writers = await listWriters(gh, l.owner, l.repo, clock);
      const lockWriters = await readWriters(gh, l.owner, l.repo, CENTRAL_REPO, clock);
      const orgAdmin = await readOrgAdmin(gh, l.owner, context.ownerType, notes, clock);
      const shaPinning = await readShaPinning(gh, l.owner, l.repo, notes, clock);
      const ids = { app: await readRepoId(gh, l.owner, l.repo, notes, clock), central: await readRepoId(gh, l.owner, CENTRAL_REPO, notes, clock) };
      for (const n of notes) io.err(n);
      return { gh, clock, login, context, caps, writers, lockWriters, orgAdmin, shaPinning, ids };
    },
    provider: () => makeProvider({ env: io.env, fetch: io.fetch, log: (l) => { io.err(l); } }),
    bundle: (dir, knownValues) => bundleCode(dir, { knownValues }),
    activity: (f, p) => activity30d(f.gh, p, f.clock),
    async consent(f, p, ai, est, bundle, auth, extra, opts) {
      const scanner = chooseSecretScanner(io.env);
      const repos = [];
      for (const name of [CENTRAL_REPO, `pipegen-proof-${p.repo}`]) repos.push({ name, exists: (await readRepo(f.gh, { owner: p.owner, repo: name }, f.clock).catch(() => null)) !== null });
      // sec I1: the counting summary (an upper bound); the pinned scanner runs only after the yes (the scan stage)
      const screen = consentScreen(p, ai, est, countingSummary(bundle), permissionsTable('write', { appCreatesRepos: auth.canCreateRepos }), repos, 'full', { appCreatesRepos: auth.canCreateRepos, secretScanner: { name: scanner, version: loadPinnedBinaries()[scanner].version }, signingEnv: opts?.signingEnv === true });
      for (const l of extra) io.err(l);
      return askConsent(io.prompt, screen, (s) => { io.err(s); });
    },
    scan: (dir, consent, knownValues, agreed) => scanCounted(dir, consent, knownValues, deps.secretScanner ?? pinnedScanner, agreed),
    state: (p, guard) => StateStore.open(p, { ...deps.state, vault: guard.vault, tokens: guard.tokens }),
    async gateReachable(f, reviewed) {
      // ruling G13-R0 12: the gate action's pinned commit, read through the API; any failure is "unreachable"
      const g = gateOf(reviewed);
      const [owner = '', repo = ''] = g.candidate.repo.split('/');
      const sha = g.candidate.pin.sha;
      if (sha === undefined) return false;
      try { await f.gh.request('GET /repos/{owner}/{repo}/commits/{ref}', { owner, repo, ref: sha }); return true; } catch { return false; }
    },
    coCase: (f, p) => coCaseOfRepos(f, p),
    async helperRepos(f, p) {
      const out: string[] = [];
      for (const name of [CENTRAL_REPO, `pipegen-proof-${p.repo}`]) if ((await readRepo(f.gh, { owner: p.owner, repo: name }, f.clock)) === null) out.push(name);
      return out;
    },
    proofRepos: (f, p, auth, store, runId, actions) => checkProofRepos(f.gh, p, { auth, actions, runId, clock: f.clock, onCreated: onCreatedFor(store, p.repo), onAccessChanged: (previous) => { store.recordActionsAccess(previous); }, createPermit: () => store.createPermit() }, io),
    needs: (p, caps, bundle, ai, writers, knownValues) => planNeeds(p, caps, bundle, ai, writers, { knownValues }),
    async discover(needs, p, f, reviewed, ai, onUsage) {
      // stage 10 (carry 48): discover per need; an unreviewed action candidate is pinned with its image read, or dropped
      const notes: string[] = [];
      const memory = await openMemory();
      const fetchFn = io.fetch ?? globalThis.fetch;
      const m = new Map<string, readonly Candidate[]>();
      for (const n of needs) {
        const key = needKeyOf(n);
        if (m.has(key)) continue;
        // sec I2: the run's metered provider (the consent's cap holds here too), the meter saved after each need
        const found = await discover(n, p, { ai, gh: f.gh, memory, fetch: fetchFn, reviewed, mode: 'full', notes, ...f.clock });
        onUsage();
        const kept: Candidate[] = [];
        for (const c of found) {
          if (c.reviewed || c.kind !== 'action') { kept.push(c); continue; }
          try { kept.push(await resolvePin(c, { gh: f.gh, fetch: fetchFn, alert: (w) => { notes.push(safeText(String((w as { message?: string }).message ?? w), 300)); }, notes, ...f.clock }, undefined, { readActionImage: true })); } catch { /* dropped: not pinnable */ }
        }
        m.set(key, kept);
      }
      for (const l of [...new Set(notes)]) io.err(l);
      return m;
    },
    debate: (needs, candidates, p, caps, bundle, ai, rule, reviewed) => runDebate(needs, candidates, p, caps, bundle, ai, rule, { reviewed, bar: loadQualityBar(), now: new Date() }),
    creators: (draft, bundle, ai, dir, vault, reviewed) => runCreators(draft, bundle, ai, dir, vault, reviewed),
    async secrets(p, created, vault, io2) {
      const reqs = secretRequests(p, { covered: coveredNames(p, created) });
      const { missing } = await askSecrets(io2.prompt, reqs.requests, vault);
      return { names: vault.names(), missing, notes: reqs.notes };
    },
    credits: (p, draft, dir) => auditCredits(p, draft, dir),
    async build(i) {
      const facts = await readBuildFacts(i);
      // spec I7: the environment plan runs inside buildFiles, before the doc, so its notes reach doc.notes and the preview
      const envPlan: EnvPlanFn = async (requireApproval, inserted) => {
        const notes: string[] = [];
        const envs = await environmentPlan(i.facts.gh, i.draft.profile, i.facts.caps, requireApproval, { texts: facts.texts, inserted, clock: i.facts.clock, notes });
        return { envs, notes };
      };
      const files = await buildFiles(i, facts, envPlan);
      return { ...files, ...(await judgeBuilt(i, files, facts)), proof: proofBuildFor(i, facts, envPlan) };
    },
    trusted: (f, p, io2) => trustedForRun(f, p, local, io2.prompt, interactive),
    deliverCentral: (f, p, files, io2, pr, lease) => deliverCentral(f.gh, p, files, { clock: f.clock, local, io: io2.prompt, interactive, lease, ...(pr === undefined ? {} : { pr }) }),
    readCentralFileList: (f, p) => readCentralFileList(f.gh, p, f.clock),
    preview: (input) => previewText(planDelivery(input)),
    dropSigningEnv: (f, p, env) => dropRunSigningEnvironment(f.gh, { owner: p.owner, repo: p.repo }, env, { clock: f.clock, local, now: new Date((deps.now ?? Date.now)()) }),
    signingEnv: (f, p) => makeRunSigningEnvironment(f.gh, { owner: p.owner, repo: p.repo }, p.defaultBranch, { clock: f.clock, local, now: new Date((deps.now ?? Date.now)()) }),
    async signingKey() {
      // carry 28: the one in-memory key maker (finish uses it too)
      const k = await generateCosignKeys(() => ensurePinnedBinary('cosign'));
      return { key: k.privateKey, password: k.password, pub: k.publicKey };
    },
    deliver: (f, p, input, v, io2, signingKey, lease) => deliver(f.gh, p, planDelivery(input), v, { io: io2.prompt, clock: f.clock, local, interactive, lease, ...(signingKey === undefined ? {} : { signingKey }) }),
    async prState(f, p, pr) {
      const d = (await f.gh.request('GET /repos/{owner}/{repo}/pulls/{pull_number}', { owner: p.owner, repo: p.repo, pull_number: pr })).data as { merged_at?: string | null; state?: string };
      return typeof d.merged_at === 'string' ? 'merged' : d.state === 'closed' ? 'closed' : 'open';
    },
    finish: (f, p, io2, lease) => finishCommand(io2, { owner: p.owner, repo: p.repo }, {}, { gh: f.gh, login: f.login, local, clock: f.clock, lease }),
  };
}

/**
 * The referee (seven arguments, against AssembledFiles.draft: carries 11, 50) and the guard on the same batch (carry 51). Never
 * isolatedTestJob (carry 54). The guard's refusals and the referee's issues both stop the run.
 */
export async function judgeBuilt(i: BuildInput, files: Pick<Built, 'assembled' | 'files' | 'verify' | 'extra'>, facts: Pick<BuildFacts, 'appCo' | 'centralCo' | 'pipegenDoc' | 'serviceTypes' | 'baseTree' | 'centralFiles' | 'texts'>, deps: { linters?: () => ReturnType<typeof ensureLinters>; judge?: typeof judgeAssembled; guard?: typeof guardCreatedFiles } = {}): Promise<{ report: RefereeReport; guardProblems: string[] }> {
  const report = await (deps.judge ?? judgeAssembled)(files.assembled, {
    platform: i.platform, reviewed: i.reviewed, linters: (deps.linters ?? ensureLinters)(), ghToken: i.auth.token ?? '',
    // G17A-R1 sec M2: the workflow texts the verify plan was built from, so the referee re-derives the called-file head checks
    refereeDeps: { vault: i.vault, createdInputs: createdInputsFor(i, facts), workflowTexts: facts.texts }, extra: files.extra,
  });
  const g = await (deps.guard ?? guardCreatedFiles)(files.files.filter((x) => x.repo === 'app'), {
    root: i.dir, baseTree: facts.baseTree, installRecord: guardRecord(i.prev), profile: files.assembled.draft.profile, repo: 'app',
    allowWorkflowInsert: files.verify.inserts.map((x) => x.path), closure: loadReviewedClosure(i.reviewed), vault: i.vault,
  });
  return { report, guardProblems: g.refused.map((r) => `${r.path}: ${r.reason}`) };
}

/**
 * G14 (carries 25, 26; D-I3, D-m1): the fix loop's build of a draft with the facts this build read: buildFiles again, the referee through
 * makeFixReferee (seven arguments, judging AssembledFiles.draft), and the guard on the same batch (a Dockerfile with its .dockerignore);
 * either one refusing is an issue. Never isolatedTestJob.
 */
export function proofBuildFor(i: BuildInput, facts: BuildFacts, envPlan: EnvPlanFn = NO_ENV_PLAN, deps: { linters?: () => ReturnType<typeof ensureLinters>; guard?: typeof guardCreatedFiles; runLinters?: RunLinters } = {}): ProofBuild {
  const cache = new WeakMap<PipelineDraft, ReturnType<typeof buildFiles>>();
  const rebuild = (d: PipelineDraft): ReturnType<typeof buildFiles> => {
    let b = cache.get(d);
    if (b === undefined) { b = buildFiles({ ...i, draft: d }, facts, envPlan); cache.set(d, b); }
    return b;
  };
  const judge = makeFixReferee({
    assemble: async (d) => { const b = await rebuild(d); return { files: b.files, draft: b.assembled.draft }; },
    platform: i.platform, reviewed: i.reviewed, linters: (deps.linters ?? ensureLinters)(), ghToken: i.auth.token ?? null,
    deps: { vault: i.vault, createdInputs: createdInputsFor(i, facts), workflowTexts: facts.texts, ...(deps.runLinters === undefined ? {} : { runLinters: deps.runLinters }) },
  });
  const ctx = { root: i.dir, baseTree: facts.baseTree, installRecord: guardRecord(i.prev), repo: 'app' as const, closure: loadReviewedClosure(i.reviewed), vault: i.vault };
  const guard = deps.guard ?? guardCreatedFiles;
  return {
    rebuild: async (d) => { const b = await rebuild(d); return { files: b.files, assembled: b.assembled.draft }; },
    referee: async (d) => {
      const report = await judge(d);
      const b = await rebuild(d);
      const g = await guard(b.files.filter((x) => x.repo === 'app'), { ...ctx, profile: b.assembled.draft.profile, allowWorkflowInsert: b.verify.inserts.map((x) => x.path) });
      const issues = [...report.issues, ...g.refused.map((r) => ({ file: r.path, check: 'template' as const, message: `the guard refused it: ${r.reason}`, repo: 'app' as const }))];
      return { ...report, ok: report.ok && g.refused.length === 0, issues };
    },
    guard: (files) => makeFixGuard({ ...ctx, profile: i.draft.profile })(files),
  };
}

/** Ruling G13-R0 13: the credits from the audit's coverage map (local files only: no child process, no AI). */
export async function auditCredits(p: RepoProfile, draft: Pick<PipelineDraft, 'capabilities'>, dir: string, map: typeof mapCoverage = mapCoverage): Promise<NonNullable<NonNullable<PipelineDraft['doc']>['credits']>> {
  // spec M4: the options buildAudit passes (src/audit/model.ts coverageOf): the skipped workflow count from the workflow reader's notes,
  // buildsNoImage, the capabilities; no branchGuess (the GitHub context is read, so the branch is known)
  const readerNotes: string[] = [];
  await readWorkflows(dir, undefined, readerNotes);
  const rows = await map(p, floorNeeds(p, draft.capabilities), dir, { skippedWorkflows: skippedWorkflowCount(readerNotes), noImage: noImageCheck(p), capabilities: draft.capabilities });
  const out: { text: string; kind: 'push-default' | 'hooks-ci' | 'signing' | 'deploy-gate' }[] = [];
  for (const r of rows) if (r.credit !== undefined && r.creditKind !== undefined && !out.some((o) => o.text === r.credit)) out.push({ text: r.credit, kind: r.creditKind });
  return out;
}

/**
 * Stage 12, the creators. Carry 12: no Dockerfile for a service a workflow, compose or bake file already builds an image from (containerHint),
 * nor for one that isn't runnable; carry 54: isolatedTestJob is never passed; carry 52: planNpmDeps runs under withActiveVault (inside the
 * test creator). The creators' own "The AI explained" notes stay out of the doc (isAiNote).
 */
export async function runCreators(draft: PipelineDraft, bundle: CodeBundle, ai: ReturnType<typeof makeProvider>, dir: string, vault: SecretVault, reviewed: ReviewedTool[], c: { dockerfile?: typeof createDockerfile; tests?: typeof decideTests; compose?: typeof createCompose } = {}): Promise<Creators> {
  const p = draft.profile;
  const skip = (part: SkippablePart): boolean => draft.skipped.some((s) => s.part === part);
  const files: CreatedFile[] = [];
  const notes: string[] = [];
  const testNotes: string[] = [];
  const testDecisions: PipelineDraft['testDecisions'] = [];
  const notProven: PipelineDraft['notProven'] = [];
  const repoPaths = await listFiles(dir);
  // carry 52 (fail closed): with npm workspaces at the root, every service below the root counts as a member (its lockfile isn't edited)
  const rootPj = await readRegular(dir, 'package.json', MAX_PACKAGE_JSON);
  const rootWorkspaces = rootPj !== null && (() => { try { return (JSON.parse(rootPj) as { workspaces?: unknown }).workspaces !== undefined; } catch { return false; } })();
  return withActiveVault(vault, async () => {
    if (!skip('docker')) {
      for (const s of p.services) {
        // the C2 extension: a service set to `container` with --type (or the question) but no Dockerfile is not given a created one
        const overriddenContainer = s.projectType?.overridden === true && s.projectType.types.includes('container');
        if (s.dockerfile !== undefined || s.containerHint !== undefined || overriddenContainer || !isRunnable(s)) continue;
        const r = await (c.dockerfile ?? createDockerfile)(s, p, bundle, ai, { repoPaths });
        files.push(...r.files);
        testNotes.push(...r.notes);
      }
    }
    for (const s of p.services) {
      // carries 52, 54: the service's package.json and lock as on disk, workspaceMember, the reviewed list; never isolatedTestJob
      const root = s.path.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');
      const at = (name: string): string => (root === '' ? name : `${root}/${name}`);
      // sec M6: regular files only (listFiles holds no link), under a size cap
      const packageJson = s.language === 'node' && repoPaths.includes(at('package.json')) ? await readRegular(dir, at('package.json'), MAX_PACKAGE_JSON) ?? '' : '';
      const packageLock = s.language === 'node' && repoPaths.includes(at('package-lock.json')) ? await readRegular(dir, at('package-lock.json'), MAX_PACKAGE_LOCK) : null;
      const starter: StarterDeps = { fileExists: (path: string) => repoPaths.includes(path), packageJson, packageLock, reviewed, ...(root !== '' && rootWorkspaces ? { workspaceMember: true } : {}) };
      const r = await (c.tests ?? decideTests)(s, p, bundle, { ai, skip: skip('tests'), starter });
      testDecisions.push(r.decision);
      files.push(...r.files);
      if (r.notProven !== undefined) notProven.push(r.notProven);
      if (r.note !== undefined) testNotes.push(r.note);
    }
    if (!skip('compose')) {
      const created = files.filter((f) => /(^|\/)Dockerfile$/.test(f.path)).map((f) => f.path);
      const r = (c.compose ?? createCompose)(p, { repoPaths, baseImages: loadBaseImages(), createdDockerfiles: created });
      if (r.file !== null) files.push(r.file);
      notes.push(...r.notes);
    }
    return { files, notes, testNotes, testDecisions, notProven };
  });
}

const MAX_PACKAGE_JSON = 1024 * 1024;
const MAX_PACKAGE_LOCK = 32 * 1024 * 1024;
/** sec M6: a file of the folder read only when it is a regular file (never a link, a folder or a device) no larger than `max`; else null. */
export async function readRegular(dir: string, rel: string, max: number): Promise<string | null> {
  const full = join(dir, rel);
  const st = await lstat(full).catch(() => null);
  if (st === null || !st.isFile() || st.size > max) return null;
  // a linked folder on the way (svc -> /elsewhere) is outside the folder too
  const [real, root] = await Promise.all([realpath(full).catch(() => null), realpath(dir).catch(() => null)]);
  if (real === null || root === null || !real.startsWith(root.endsWith(sep) ? root : root + sep)) return null;
  return readFile(full, 'utf8').catch(() => null);
}

async function listFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (rel: string, depth: number): Promise<void> => {
    if (depth > 8 || out.length > 20_000) return;
    for (const e of await readdir(join(dir, rel), { withFileTypes: true }).catch(() => [])) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      const path = rel === '' ? e.name : `${rel}/${e.name}`;
      if (e.isDirectory()) await walk(path, depth + 1);
      else if (e.isFile()) out.push(path);
    }
  };
  await walk('', 0);
  return out;
}
