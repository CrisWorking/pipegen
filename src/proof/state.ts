// Plan E Task 7 / E8 (rulings S20, B2, S3; carries E0b, E1-R4, E4-R4, E6, E7-R14; threats T12, T38): the proof's state file.
// `~/.cache/pipegen/<owner>__<repo>/state.json` ($XDG_CACHE_HOME when it is absolute) holds what `pipegen resume` (Plan G)
// needs to continue and what `pipegen cleanup` needs to remove what a proof left in GitHub:
// - the stage (consented → planned → debated → created → proving → proven → cleaned → delivered; or interrupted / stopped,
//   with the stage it was at), nextStage() says where a resumed run goes on;
// - the app (owner, repo, visibility, owner type, default branch) and the run id, so the proof target can be made again;
// - every branch and PR pipegen makes, recorded BEFORE it is made (recordingTransport, prRecorder), the secret NAMES it
//   stores, the scratch repo's id when pipegen created it (the only proof that a later delete may remove it), the meters
//   (minutes used, the proof start by GitHub's clock, AI spend), the leftovers the cleanup couldn't remove, the draft.
// It never holds a secret value: no vault value, no placeholder value (pipegen-placeholder-…), no token. Every write checks
// the whole text first (the vault's known values when the store has the vault, GitHub and AI token shapes, the placeholder
// prefix) and refuses to write rather than write one.
// The folder is a trusted directory (util/trusted-dir.ts: every level up to / owned by you or root, no group or other write,
// no symlink), created 0700; the file is written 0600 through a fresh temp file (exclusive, no-follow), fsynced, renamed.
// A load opens it no-follow and refuses a file that isn't a regular file of yours with mode 0600, is larger than
// MAX_STATE_BYTES, isn't JSON, or doesn't match the schema (zod, strict at the top level).
// Every write is synchronous (writeFileSync-style), so a leftover recorded from an interrupt hook (E0b: "must write
// synchronously") is on disk before the process can stop. When a write fails, the leftover is printed to stderr instead
// ("Left behind: …"), the registry's own fallback: it is never lost silently.
// The lease (S20; E4-R4 R3): one pipegen process at a time per app repo on this machine. `lease.json` is made exclusively
// next to the state; another live process's lease is a stop; a dead one's (this host) is taken over; one from another host, or
// one that can't be read, is a stop naming the file (never taken over). Two machines are not covered (a
// recorded residual: the scratch repo's key state is shared per repo id inside one process only, E4).
import { closeSync, constants, fstatSync, fsyncSync, linkSync, openSync, readSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { basename, isAbsolute, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { KnownValueCheck, PipelineDraft } from '../types.js';
import { onExit } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { trackedTransport } from './inflight.js';
import { PLACEHOLDER_PREFIX } from './keys.js';
import { ProofStopError, takeCreatePermitIssuer, validBranchName, type CreatePermit, type GuardedRepo, type ProofApp } from './target.js';

/** The create-permit maker, taken once when this module loads (target.ts hands it out once). */
const issuePermit = takeCreatePermitIssuer();
import { pipegenCmd } from '../util/next-step.js';
import type { ProofTransport } from './snapshot.js';

export type Stage = 'consented' | 'planned' | 'debated' | 'created' | 'proving' | 'proven' | 'cleaned' | 'delivered' | 'interrupted' | 'stopped';
/** The stages of a run that goes well, in order (the design flow: debate before create, cleanup before the preview). */
export const STAGE_ORDER = Object.freeze(['consented', 'planned', 'debated', 'created', 'proving', 'proven', 'cleaned', 'delivered'] as const);
export type WorkStage = typeof STAGE_ORDER[number];
export const STATE_VERSION = 1;
/** The largest state file pipegen reads (a draft with its created files fits well below it). */
export const MAX_STATE_BYTES = 16 * 1024 * 1024;
const STATE_FILE = 'state.json';
const LEASE_FILE = 'lease.json';
/** G-LEASE-R1 (sec L1), r2-L1: how long every take of the lease waits before it checks that the lease it wrote is still there. */
export const LEASE_SETTLE_MS = 75;
/** The commands that take the app's lease (Plan V M5): a stop names the one holding it. */
export const LEASE_COMMANDS = ['run', 'resume', 'cleanup', 'uninstall', 'finish', 'update'] as const;
export type LeaseCommand = (typeof LEASE_COMMANDS)[number];

/** A problem with the state file or a refused write. The message never holds a value. */
export class StateError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'StateError';
  }
}

export interface RecordedBranch { repo: 'scratch' | 'central'; ref: string }
export interface RecordedPr { head: string; number?: number }
/** G14-R1: the consent's terms a resume goes on with (names only: never a key). */
export interface AgreedTerms {
  provider: 'claude' | 'openai' | 'ollama';
  model: string;
  host?: string;
  strictness?: string;
  scanner?: 'gitleaks' | 'betterleaks';
  monthlyMinutes?: number;
}

export interface RunState {
  version: typeof STATE_VERSION;
  runId: string;
  app: ProofApp;
  stage: Stage;
  /** interrupted / stopped: the stage the run had reached when it stopped (nextStage goes on from it). */
  interruptedAt?: WorkStage;
  /** stopped: which cap stopped it, or 'proof-failed' (final review I-2: the proof ended without a pass). */
  stoppedBy?: 'ai-cost' | 'actions-minutes' | 'proof-failed';
  /**
   * The draft (CreatedFile.aiEdited kept: a resumed draft treats those files as AI-written; E7-R14). Plan G re-referees it.
   * begin() saves the draft the proof starts from; recordVerdict() replaces it with the proof's final (fixed) draft.
   */
  draft?: PipelineDraft;
  /**
   * Final review I-2: the verdict of the proof of this run (FixOutcome: result.ok, and no stop or cap), saved with the final
   * draft before the stage moves. Only `true` lets the stage reach proven, cleaned and delivered (setStage, nextStage);
   * absent while a proof runs (setStage('proving') clears it) and in a state saved before this field existed.
   */
  proofOk?: boolean;
  /** Why the proof stopped before it could pass (FixOutcome.stopped, plain text). */
  proofStopped?: string;
  /** Branch names (no `refs/heads/`), recorded before each push. The scratch default branch is never one (it is emptied). */
  branches: RecordedBranch[];
  /** Scratch PRs by head branch, recorded before each is opened; the number once GitHub gave it. */
  prs: RecordedPr[];
  /** Secret NAMES pipegen stores in the scratch repo (values never). */
  secretNames: string[];
  /** The Actions minutes the proof used, and the cap. */
  minutesUsed: number;
  cap: number;
  /** When the proof started, by GitHub's clock (minutes.ts proofStart), in ms; `fromServer` false: this machine's minus the margin. */
  proofStart?: { at: number; fromServer: boolean };
  /**
   * Fix round 2 (N-3): the minutes used before `proofStart`, by runs that no longer exist (a resume after the cleanup deleted
   * them restores them and starts a new window). The count is `minutesBase` + the runs since `proofStart`.
   */
  minutesBase?: number;
  /** The cleanup deleted scratch runs (or the whole repo): a resumed meter can't count them again and restores minutesUsed. */
  runsDeleted?: boolean;
  /** The AI spend (AiSpendMeter.usedUsd: spent plus reserved), and the cap (null: Ollama, no cap). */
  aiCostUsd: number;
  aiCap: number | null;
  /** GitHub's id of the scratch repo, recorded when pipegen created it: a delete needs it (rulings S3, E1-R4). */
  scratchRepoId?: number;
  scratchDeleted?: boolean;
  /**
   * G13-R1 (sec M3): the central repo's Actions access level before pipegen first changed it (checkProofRepos), saved the moment it
   * changes and carried into the next run's state, so a stop before delivery doesn't lose it (uninstall puts it back).
   */
  actionsAccessPrevious?: 'none' | 'user' | 'organization' | 'enterprise';
  /**
   * G14-R1 (sec I2, sec M6): what the user agreed to at the consent screen, saved at begin(): the AI provider, its model and (Ollama)
   * host, the strictness, the secret scanner and the monthly Actions minutes estimate. A resume uses these, and refuses an AI that
   * isn't the agreed one (no key is ever saved).
   */
  agreed?: AgreedTerms;
  /** G14-R1 (spec M1): pipegen created the central `pipelines` repo in this run (kept for a resume's delivery record). */
  centralCreated?: boolean;
  /** G17 row 27: GitHub's id of the central repo pipegen created (centralCreated): the record names it, and uninstall deletes only that id. */
  centralRepoId?: number;
  /**
   * G17C-R1 (F5): the central pull request pipegen opened (or updated) and the commit it put on its branch. Carried into the next run of
   * the same app: once that PR is merged, its merge proves pipegen added the central files it holds (deliverCentral checks it on GitHub).
   */
  centralPr?: { number: number; commit: string };
  /** The cleanup of this run finished with nothing left behind (cleanupAfterProof). */
  cleanupDone?: boolean;
  /** What the cleanup couldn't remove (plain text, names only), for `pipegen cleanup`. */
  leftovers: string[];
  notes: string[];
  /** ISO time of the last write. */
  updatedAt: string;
}

// ---------- the schema (zod; strict at the top level, so an unknown key is refused) ----------

const NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const RUN_ID_RE = /^\d{8}-\d{6}-[0-9a-f]{6}$/;
const SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,199}$/;
const TEXT_MAX = 2000;
const finite = z.number().refine(Number.isFinite, 'a finite number');
const nonNeg = finite.refine((n) => n >= 0, '0 or more');
const branchName = z.string().max(255).refine(validBranchName, 'a branch name');
const text = z.string().max(TEXT_MAX);
const workStage = z.enum(STAGE_ORDER as unknown as [WorkStage, ...WorkStage[]]);
const createdFile = z.looseObject({
  path: z.string().min(1).max(4096),
  content: z.string(),
  part: z.string(),
  reason: z.string(),
  repo: z.enum(['app', 'central']),
  needsConfirm: z.boolean().optional(),
  aiEdited: z.literal(true).optional(),
});
/** The draft: its created files are checked field by field (aiEdited kept); the rest is Plan G's, re-refereed on resume (S20). */
const draft = z.looseObject({
  profile: z.looseObject({ owner: z.string(), repo: z.string() }),
  created: z.array(createdFile),
  needs: z.array(z.unknown()),
  steps: z.array(z.unknown()),
});
const stateSchema = z.strictObject({
  version: z.literal(STATE_VERSION),
  runId: z.string().regex(RUN_ID_RE),
  app: z.strictObject({
    owner: z.string().regex(OWNER_RE),
    repo: z.string().regex(NAME_RE).refine((r) => r !== '.' && r !== '..', 'a repo name'),
    private: z.boolean(),
    ownerType: z.enum(['User', 'Organization']),
    defaultBranch: branchName,
  }),
  stage: z.enum(['consented', 'planned', 'debated', 'created', 'proving', 'proven', 'cleaned', 'delivered', 'interrupted', 'stopped']),
  interruptedAt: workStage.optional(),
  stoppedBy: z.enum(['ai-cost', 'actions-minutes', 'proof-failed']).optional(),
  draft: draft.optional(),
  proofOk: z.boolean().optional(),
  proofStopped: text.optional(),
  branches: z.array(z.strictObject({ repo: z.enum(['scratch', 'central']), ref: branchName })).max(1000),
  prs: z.array(z.strictObject({ head: branchName, number: z.number().int().positive().optional() })).max(1000),
  secretNames: z.array(z.string().regex(SECRET_NAME_RE)).max(1000),
  minutesUsed: nonNeg,
  cap: nonNeg,
  proofStart: z.strictObject({ at: finite, fromServer: z.boolean() }).optional(),
  runsDeleted: z.boolean().optional(),
  minutesBase: nonNeg.optional(),
  aiCostUsd: nonNeg,
  aiCap: nonNeg.nullable(),
  scratchRepoId: z.number().int().positive().optional(),
  scratchDeleted: z.boolean().optional(),
  actionsAccessPrevious: z.enum(['none', 'user', 'organization', 'enterprise']).optional(),
  agreed: z.strictObject({
    provider: z.enum(['claude', 'openai', 'ollama']), model: z.string().max(200), host: z.string().max(300).optional(),
    strictness: z.string().max(40).optional(), scanner: z.enum(['gitleaks', 'betterleaks']).optional(), monthlyMinutes: nonNeg.optional(),
  }).optional(),
  centralCreated: z.boolean().optional(),
  centralRepoId: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
  centralPr: z.strictObject({ number: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), commit: z.string().regex(/^[0-9a-f]{40}$/) }).optional(),
  cleanupDone: z.boolean().optional(),
  leftovers: z.array(text).max(1000),
  notes: z.array(text).max(1000),
  updatedAt: z.string().max(40),
}).refine((s) => (s.stage === 'interrupted' || s.stage === 'stopped') === (s.interruptedAt !== undefined), 'interruptedAt goes with an interrupted or stopped stage');

// ---------- stages ----------

const isWork = (s: Stage | undefined): s is WorkStage => s !== undefined && (STAGE_ORDER as readonly string[]).includes(s);

/** Final review I-2: the stages only a proof that passed (a saved proofOk true) reaches. */
const PASSED_STAGES: ReadonlySet<Stage> = new Set<Stage>(['proven', 'cleaned', 'delivered']);

/**
 * The stage a resumed run goes on with (S20: Plan G's `resume` uses it), or null when the run is done (delivered). The next
 * stage in order, except: `proving` → `proving` (the proof didn't finish: it runs again, after its leftovers are cleaned) and
 * `proven` → `cleaned` (the cleanup runs before anything is shown). interrupted / stopped go on from the stage they had reached.
 * Final review I-2: `proven` and `cleaned` go on only with a saved passing verdict (proofOk true); without one (a proof that
 * failed, or a state saved before the verdict was), the proof runs again: a resume never delivers what didn't pass.
 */
export function nextStage(s: Pick<RunState, 'stage' | 'interruptedAt'> & { proofOk?: boolean }): WorkStage | null {
  const at: Stage | undefined = s.stage === 'interrupted' || s.stage === 'stopped' ? s.interruptedAt : s.stage;
  if (!isWork(at)) throw new StateError('The saved state was interrupted without the stage it had reached, so pipegen can\'t tell where to go on.');
  if (at === 'proving') return 'proving';
  if ((at === 'proven' || at === 'cleaned') && s.proofOk !== true) return 'proving';
  const i = STAGE_ORDER.indexOf(at);
  return i === STAGE_ORDER.length - 1 ? null : STAGE_ORDER[i + 1] as WorkStage;
}

// ---------- what may never be written ----------

/** Token shapes (GitHub's, Anthropic's and OpenAI's) that must never reach the state file. */
const TOKEN_RE = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}|\bgithub_pat_[A-Za-z0-9_]{16,}|\bsk-ant-[A-Za-z0-9_-]{16,}|\bsk-(?:proj-)?[A-Za-z0-9]{20,}/;

/** Why `json` can't be written (names no value), or null. */
function secretProblem(json: string, vault: KnownValueCheck | undefined, tokens: readonly string[]): string | null {
  if (vault !== undefined && vault.containsKnownValue(json)) return 'it would hold a value you typed';
  if (json.includes(PLACEHOLDER_PREFIX)) return 'it would hold a placeholder secret value';
  if (TOKEN_RE.test(json) || tokens.some((t) => t.length >= 8 && json.includes(t))) return 'it would hold a token';
  return null;
}

/**
 * A saved run whose state may be replaced by a new one: nothing left behind, and either it never reached GitHub's proof
 * stages (before `proving`), or it was delivered or cleaned, or its cleanup finished.
 */
function settled(s: RunState): boolean {
  if (s.leftovers.length > 0) return false;
  if (s.cleanupDone === true || s.stage === 'cleaned' || s.stage === 'delivered') return true;
  const at = s.stage === 'interrupted' || s.stage === 'stopped' ? s.interruptedAt : s.stage;
  return at !== undefined && STAGE_ORDER.indexOf(at) < STAGE_ORDER.indexOf('proving') && s.branches.length === 0 && s.prs.length === 0 && s.secretNames.length === 0;
}

// ---------- the store ----------

export interface StateDeps {
  /** The home directory the default ~/.cache is under (default os.homedir()). */
  home?: string;
  /** Read for XDG_CACHE_HOME (default process.env). */
  env?: NodeJS.ProcessEnv;
  /** The user the folders and the file must belong to (default process.getuid()). */
  uid?: number;
  /** The run's vault: no text it knows a value of is ever written. */
  vault?: KnownValueCheck;
  /** Tokens of this run (the GitHub token, AI keys): never written. */
  tokens?: readonly string[];
  /** Where a leftover goes when the state file can't take it (default: stderr). */
  err?: (line: string) => void;
  /** For tests: the clock of updatedAt. */
  now?: () => number;
  /** For tests: whether a process is alive (default process.kill(pid, 0)). */
  alive?: (pid: number) => boolean;
  /**
   * For tests: the pause after every take of the lease, before it is read again to check it is still this process's (G-LEASE-R1 sec L1,
   * r2-L1). Default: LEASE_SETTLE_MS, slept synchronously.
   */
  leaseSettle?: () => void;
  /** PL-F1: the command that opened the store; its stops say `npx pipegen <command>` where they tell the user to run it again (default: the setup run). */
  command?: LeaseCommand;
}

const KIND: TrustedDirKind = {
  noun: 'state', keeping: 'its proof state', risk: 'change what pipegen deletes or resumes',
  error: (message, cause) => new StateError(message, cause === undefined ? undefined : { cause }),
};

/** A short synchronous pause (the lease is taken synchronously). */
function sleepSettle(): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, LEASE_SETTLE_MS);
}

/** The folder name of an app repo: `<owner>__<repo>`, lower-case (GitHub's names are case-insensitive). */
export function stateFolderName(app: Pick<ProofApp, 'owner' | 'repo'>): string {
  if (!OWNER_RE.test(app.owner) || !NAME_RE.test(app.repo) || app.repo === '.' || app.repo === '..') throw new StateError('The repo name is not one pipegen can keep a state file for.');
  return `${app.owner}__${app.repo}`.toLowerCase();
}

/**
 * The proof's state file of one app repo, and its lease. open() prepares the trusted folder; every write after that is
 * synchronous. Mutations go through the methods below, each of which writes the file before it returns.
 */
export class StateStore {
  readonly dir: string;
  readonly path: string;
  readonly #deps: StateDeps;
  #state: RunState | null = null;
  #armed = false;
  #lease: { token: string; off: () => void } | null = null;
  /** The app repo the store was opened for (`owner/repo`), for messages. */
  #app = '';
  /** G-LEASE r2-I2: opened for the lease only (openForLease): every state write is refused. */
  #leaseOnly = false;

  private constructor(dir: string, deps: StateDeps) {
    this.dir = dir;
    this.path = join(dir, STATE_FILE);
    this.#deps = deps;
  }

  /** Prepares `<cache>/pipegen/<owner>__<repo>` (0700, trusted chain) and loads the saved state, if any. */
  static async open(app: Pick<ProofApp, 'owner' | 'repo'>, deps: StateDeps = {}): Promise<StateStore> {
    const store = await StateStore.#prepare(app, deps, 'keep its proof state');
    store.#state = store.load();
    return store;
  }

  /** G-LEASE r2-I2: the one folder preparation of open() and openForLease() (the user, the cache base, the trusted chain). */
  static async #prepare(app: Pick<ProofApp, 'owner' | 'repo'>, deps: StateDeps, what: string): Promise<StateStore> {
    const uid = deps.uid ?? process.getuid?.();
    if (uid === undefined) throw new StateError(`pipegen could not tell which user it runs as, so it will not ${what}.`);
    const env = deps.env ?? process.env;
    const xdg = env.XDG_CACHE_HOME;
    const base = xdg !== undefined && isAbsolute(xdg) ? xdg : join(deps.home ?? homedir(), '.cache');
    const dir = await prepareTrustedDir(base, ['pipegen', stateFolderName(app)], false, uid, KIND);
    const store = new StateStore(dir, { ...deps, uid });
    store.#app = `${app.owner}/${app.repo}`;
    return store;
  }

  /**
   * G-LEASE-R1 (spec I1, sec I3): the same trusted folder, for the lease only. The saved proof state is not read: finish and update
   * never use it, so a state file they can't trust doesn't stop them. The store holds no state (state is null); use it only for the lease.
   */
  static async openForLease(app: Pick<ProofApp, 'owner' | 'repo'>, deps: StateDeps = {}): Promise<StateStore> {
    const store = await StateStore.#prepare(app, deps, 'take the repo\'s lease');
    // G-LEASE r2-I2: it never loaded the saved state, so it must never replace it (begin() would skip the unsettled-proof stop)
    store.#leaseOnly = true;
    return store;
  }

  /** The state in memory (null before begin() or a load that found none). Read-only: change it through the methods. */
  get state(): Readonly<RunState> | null {
    return this.#state;
  }

  /** Reads and checks the saved state (null when there is none). Throws StateError for any file it won't trust. */
  load(): RunState | null {
    let fd: number;
    try {
      fd = openSync(this.path, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch (e) {
      const code = (e as { code?: unknown } | null)?.code;
      if (code === 'ENOENT') return null;
      throw new StateError(code === 'ELOOP' ? `${this.path} is a symbolic link; pipegen won't read it. Remove the link, then run ${pipegenCmd(this.#deps.command)} again.` : `pipegen couldn't open its state file ${this.path}. Check that you can read it (or delete it), then run ${pipegenCmd(this.#deps.command)} again.`, { cause: e });
    }
    let raw: string;
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) throw new StateError(`${this.path} is not a regular file; pipegen won't read it. Remove it, then run ${pipegenCmd(this.#deps.command)} again.`);
      if (st.uid !== this.#deps.uid) throw new StateError(`${this.path} is not owned by you; pipegen won't read it. Check who wrote it; delete it (or make it yours with chown), then run ${pipegenCmd(this.#deps.command)} again.`);
      if ((st.mode & 0o077) !== 0) throw new StateError(`${this.path} can be read or changed by other users (mode ${(st.mode & 0o777).toString(8)}); pipegen won't trust it. Fix it with: chmod 600 '${this.path}'`);
      if (st.size > MAX_STATE_BYTES) throw new StateError(`${this.path} is larger than pipegen's limit; pipegen won't read it. Delete it to start again (run pipegen cleanup first if a proof left anything behind).`);
      const buf = Buffer.alloc(st.size + 1);
      let got = 0;
      for (;;) {
        const n = readSync(fd, buf, got, buf.length - got, null);
        if (n === 0) break;
        got += n;
        if (got > st.size) throw new StateError(`${this.path} grew while pipegen read it; pipegen won't trust it. Run ${pipegenCmd(this.#deps.command)} again once no other pipegen works on this repo.`);
      }
      raw = buf.subarray(0, got).toString('utf8');
    } finally {
      closeSync(fd);
    }
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      throw new StateError(`${this.path} is not a state file pipegen can read (not JSON). Delete it to start again (run pipegen cleanup first if a proof left anything behind).`, { cause: e });
    }
    const parsed = stateSchema.safeParse(data);
    if (!parsed.success) {
      const where = parsed.error.issues.slice(0, 3).map((i) => i.path.map(String).join('.') || '(top)').map((p) => safeText(p, 80)).join(', ');
      throw new StateError(`${this.path} doesn't match pipegen's state format (at ${where}); pipegen won't use it. Delete it to start again (run pipegen cleanup first if a proof left anything behind).`);
    }
    return parsed.data as RunState;
  }

  /**
   * Starts the state of a new run (the stage `consented`). The scratch repo's created id carries over from the saved state
   * when that repo wasn't deleted since: the repo is still the one pipegen made. A saved run that may have left something in
   * GitHub (leftovers recorded, or a proof that reached GitHub and wasn't cleaned up to the end) is a stop: `pipegen cleanup`
   * first (or `pipegen resume`), so nothing an earlier run left is forgotten when its state is replaced.
   */
  begin(runId: string, app: ProofApp, init: { cap: number; aiCap: number | null; draft?: PipelineDraft; agreed?: AgreedTerms }): RunState {
    if (!RUN_ID_RE.test(runId)) throw new StateError('The run id is not of the form YYYYMMDD-HHMMSS-<6 hex>.');
    const old = this.#state;
    if (old !== null && old.runId !== runId && !settled(old)) {
      throw new ProofStopError(`An earlier proof of ${old.app.owner}/${old.app.repo} (${old.runId}) may have left your keys or its branches in `
        + `${old.app.owner}/pipegen-proof-${old.app.repo}. Run pipegen cleanup first (or pipegen resume to go on with it).`);
    }
    const keepId = old !== null && old.scratchRepoId !== undefined && old.scratchDeleted !== true
      && old.app.owner.toLowerCase() === app.owner.toLowerCase() && old.app.repo.toLowerCase() === app.repo.toLowerCase();
    const s: RunState = {
      version: STATE_VERSION, runId,
      app: { owner: app.owner, repo: app.repo, private: app.private, ownerType: app.ownerType, defaultBranch: app.defaultBranch },
      stage: 'consented', branches: [], prs: [], secretNames: [], minutesUsed: 0, cap: init.cap, aiCostUsd: 0, aiCap: init.aiCap,
      ...(keepId ? { scratchRepoId: old.scratchRepoId } : {}),
      ...(old !== null && old.actionsAccessPrevious !== undefined && old.app.owner.toLowerCase() === app.owner.toLowerCase() && old.app.repo.toLowerCase() === app.repo.toLowerCase() ? { actionsAccessPrevious: old.actionsAccessPrevious } : {}),
      // G14-R2 (spec minor): pipegen made the central repo in an earlier run of this app (kept like the Actions access level)
      ...(old !== null && old.centralCreated === true && old.app.owner.toLowerCase() === app.owner.toLowerCase() && old.app.repo.toLowerCase() === app.repo.toLowerCase() ? { centralCreated: true, ...(old.centralRepoId === undefined ? {} : { centralRepoId: old.centralRepoId }) } : {}),
      // G17C-R1 (F5): the central PR an earlier run of this app opened (merged since, it proves pipegen's central files)
      ...(old !== null && old.centralPr !== undefined && old.app.owner.toLowerCase() === app.owner.toLowerCase() && old.app.repo.toLowerCase() === app.repo.toLowerCase() ? { centralPr: { ...old.centralPr } } : {}),
      ...(init.draft === undefined ? {} : { draft: init.draft }),
      ...(init.agreed === undefined ? {} : { agreed: structuredClone(init.agreed) }),
      leftovers: [], notes: [], updatedAt: '',
    };
    this.#write(s);
    this.#state = s;
    return s;
  }

  #need(): RunState {
    if (this.#state === null) throw new StateError('No proof state was started or loaded.');
    return this.#state;
  }

  /** Replaces the whole state with `s`, after the same schema check as a load (saveState). */
  replace(s: RunState): void {
    const parsed = stateSchema.safeParse(structuredClone(s));
    if (!parsed.success) throw new StateError('pipegen didn\'t save its proof state: it doesn\'t match the state format.');
    const next = parsed.data as RunState;
    this.#write(next);
    this.#state = next;
  }

  /** Applies `change` to a copy, writes it, then keeps it. A refused or failed write changes nothing. */
  update(change: (s: RunState) => void): void {
    const next = structuredClone(this.#need());
    change(next);
    this.#write(next);
    this.#state = next;
  }

  /**
   * Moves the stage: one step forward in STAGE_ORDER, the stage nextStage() gives (resume), or interrupted / stopped (the
   * stage reached is kept in interruptedAt). Anything else (a skip, a step back) is refused.
   */
  setStage(to: Stage, extra: { stoppedBy?: RunState['stoppedBy'] } = {}): void {
    const s = this.#need();
    if (to === 'interrupted' || to === 'stopped') {
      const at = isWork(s.stage) ? s.stage : s.interruptedAt;
      this.update((n) => {
        n.stage = to;
        n.interruptedAt = at;
        if (to === 'stopped' && extra.stoppedBy !== undefined) n.stoppedBy = extra.stoppedBy;
      });
      return;
    }
    const ok = (isWork(s.stage) && STAGE_ORDER.indexOf(to as WorkStage) === STAGE_ORDER.indexOf(s.stage) + 1) || nextStage(s) === to;
    if (!ok) throw new StateError(`The proof can't go from the stage ${s.stage} to ${to}.`);
    // final review I-2: proven, cleaned and delivered only after a proof that passed, its verdict saved first (recordVerdict)
    if (PASSED_STAGES.has(to) && s.proofOk !== true) throw new StateError(`The proof can't go to the stage ${to}: only a proof that passed (its verdict saved) does.`);
    this.update((n) => {
      n.stage = to;
      delete n.interruptedAt;
      delete n.stoppedBy;
      // review I-4: a proof that starts (again) may leave things behind; only a finished cleanup sets it back
      if (to === 'proving') {
        n.cleanupDone = false;
        n.scratchDeleted = false;   // fix round 2 (N-1): the scratch repo is used again, so a "deleted" mark is stale
        // final review I-2: a proof that runs again has no verdict until it ends
        delete n.proofOk;
        delete n.proofStopped;
      }
    });
  }

  /**
   * Final review I-2: the verdict of the proof that just ended and its final draft (CreatedFile.aiEdited kept), saved together
   * before the stage moves (proveThenClean). The draft is checked against the state format first, and the write refuses any
   * secret value (#write): a StateError, and nothing is written. Without a draft, the saved one stays and the verdict is
   * not a pass. Plan G G0 (E-F2 m1, G0-R1 I2): accepted at the stage `proving`, the moment proveThenClean (its only caller,
   * test/plan-g0.test.ts scans src for it) records the proof that just ended, and, for a verdict that is NOT a pass, at `stopped`
   * reached from `proving` (a cap stop saved before the proof returned). Anywhere else (proven, cleaned, interrupted, delivered,
   * stopped before the proof) it is a StateError and nothing is written.
   */
  recordVerdict(v: { ok: boolean; draft?: PipelineDraft; stopped?: string }): void {
    const cur = this.#need();
    // G0-R1 I2: a cap stop saves `stopped` (from proving) before the proof returns; its FAILED verdict and its AI-fixed draft are
    // still saved there, so a resume starts from that draft. A pass is accepted only at proving.
    const stoppedFromProving = cur.stage === 'stopped' && cur.interruptedAt === 'proving';
    if (cur.stage !== 'proving' && !(stoppedFromProving && v.ok !== true)) {
      throw new StateError(`pipegen records a proof's verdict only while it proves, or a failed one when it stopped while proving (the stage is ${cur.stage}).`);
    }
    let checked: PipelineDraft | undefined;
    if (v.draft !== undefined) {
      const parsed = draft.safeParse(structuredClone(v.draft));
      if (!parsed.success) throw new StateError('pipegen didn\'t save the proof\'s draft: it doesn\'t match the state format.');
      checked = parsed.data as unknown as PipelineDraft;
    }
    this.update((n) => {
      n.proofOk = v.ok === true && checked !== undefined;   // a pass needs its draft saved (a resume delivers only that)
      if (typeof v.stopped === 'string' && v.stopped !== '') n.proofStopped = safeText(v.stopped, TEXT_MAX);
      else delete n.proofStopped;
      if (checked !== undefined) n.draft = checked;
    });
  }

  /** The cleanup hook is registered (armProofCleanup): branches, PRs and repos may be recorded (and so made) from now on. */
  get armed(): boolean {
    return this.#armed;
  }
  /** Set by armProofCleanup only. */
  markArmed(on: boolean): void {
    this.#armed = on;
  }

  /** Throws unless armProofCleanup has run (Plan G passes `() => store.requireArmed('create a repo')` as checkProofRepos' beforeCreate). */
  requireArmed(what: string): void {
    if (!this.#armed) throw new StateError(`pipegen won't ${what} before its cleanup is registered for Ctrl-C (armProofCleanup).`);
  }

  /** Records a branch before it is pushed (S20). The scratch default branch is not recorded (it is emptied, never deleted). */
  recordBranch(repo: 'scratch' | 'central', ref: string, defaultBranch: string): void {
    this.requireArmed('push a branch');
    if (!validBranchName(ref)) throw new StateError('The branch to record is not a branch name.');
    if (repo === 'scratch' && ref === defaultBranch) return;
    const cur = this.#need();
    if (cur.branches.some((b) => b.repo === repo && b.ref === ref) && cur.cleanupDone !== true && !(repo === 'scratch' && cur.scratchDeleted === true)) return;
    this.update((n) => {
      if (!n.branches.some((b) => b.repo === repo && b.ref === ref)) n.branches.push({ repo, ref });
      n.cleanupDone = false;   // review I-4: something new may be left behind
      if (repo === 'scratch') n.scratchDeleted = false;   // fix round 2 (N-1)
    });
  }

  /** Records a PR before it is opened (by its head branch), then its number. */
  recordPr(head: string, number?: number): void {
    this.requireArmed('open a PR');
    if (!validBranchName(head)) throw new StateError('The PR head to record is not a branch name.');
    this.update((n) => {
      const have = n.prs.find((p) => p.head === head && (p.number === undefined || p.number === number));
      if (have === undefined) n.prs.push(number === undefined ? { head } : { head, number });
      else if (number !== undefined) have.number = number;
      n.cleanupDone = false;
      n.scratchDeleted = false;   // fix round 2 (N-1): PRs live in the scratch repo
    });
  }

  /** Records the secret names about to be stored in the scratch repo (names only). */
  recordSecretNames(names: readonly string[]): void {
    this.requireArmed('store a secret');   // review M-3
    for (const n of names) if (typeof n !== 'string' || !SECRET_NAME_RE.test(n)) throw new StateError('A secret name to record is not a secret name.');
    this.update((s) => { s.secretNames = [...new Set([...s.secretNames, ...names.map((n) => n.toUpperCase())])].sort(); s.cleanupDone = false; s.scratchDeleted = false; });
  }

  /**
   * Fix round 2 (O-2): a single-use permit to create a helper repo of this app (checkProofRepos' createPermit), only while
   * the cleanup is armed. createHelperRepo refuses to send anything without one.
   */
  createPermit(): CreatePermit {
    this.requireArmed('create a repo');
    const s = this.#need();
    return issuePermit({ owner: s.app.owner, repo: s.app.repo });
  }

  /** G13-R1 (sec M3): the central Actions access level before pipegen changed it; the first one saved stays. */
  recordActionsAccess(previous: string): void {
    if (previous !== 'none' && previous !== 'user' && previous !== 'organization' && previous !== 'enterprise') throw new StateError('The Actions access level to record is not one GitHub has.');
    if (this.#need().actionsAccessPrevious !== undefined) return;
    this.update((s) => { s.actionsAccessPrevious = previous; });
  }

  /** G17 row 27: pipegen just created the central repo (checkProofRepos' onCreated); its GitHub id is kept with the flag, never apart. */
  centralCreatedWith(id: number): void {
    if (!Number.isSafeInteger(id) || id <= 0) throw new StateError('The repo id to record is not one.');
    this.update((s) => { s.centralCreated = true; s.centralRepoId = id; });
  }

  /** G17C-R1 (F5): deliverCentral opened (or updated) the central pull request `number` with pipegen's commit `commit` on its branch. */
  centralPrOpened(number: number, commit: string): void {
    if (!Number.isSafeInteger(number) || number <= 0 || !/^[0-9a-f]{40}$/.test(commit)) throw new StateError('The central pull request to record is not one.');
    this.update((s) => { s.centralPr = { number, commit }; });
  }

  /** The id GitHub gave the scratch repo pipegen just created (checkProofRepos' onCreated). */
  scratchCreated(id: number): void {
    this.requireArmed('create a repo');
    if (!Number.isSafeInteger(id) || id <= 0) throw new StateError('The repo id to record is not one.');
    this.update((s) => { s.scratchRepoId = id; s.scratchDeleted = false; s.cleanupDone = false; });
  }

  /** The meters (minutes used, the proof start by GitHub's clock, AI spend) as they are now. */
  saveMeters(m: { minutes?: { used: number; since: number; fromServer?: boolean }; aiUsedUsd?: number }): void {
    this.update((s) => {
      if (m.minutes !== undefined) {
        s.minutesUsed = Math.max(s.minutesUsed, m.minutes.used);
        s.proofStart ??= { at: m.minutes.since, fromServer: m.minutes.fromServer ?? false };   // review M-4: only what the caller says
      }
      if (m.aiUsedUsd !== undefined) s.aiCostUsd = Math.max(s.aiCostUsd, m.aiUsedUsd);
    });
  }

  /**
   * Records one leftover (E0b's `record`): synchronous, so it is on disk before the process may stop. If the state file
   * can't take it, it is printed to stderr instead ("Left behind: …"), never lost silently.
   */
  record(item: string): void {
    const line = safeText(String(item), 500);
    try {
      if (this.#state === null) throw new StateError('no state');
      if (!this.#state.leftovers.includes(line)) this.update((s) => { s.leftovers.push(line); });
    } catch {
      const err = this.#deps.err ?? ((l: string) => { try { process.stderr.write(`${l}\n`); } catch { /* stderr gone */ } });
      err(`Left behind: ${line} (pipegen couldn't save this in ${this.path})`);
    }
  }

  /** Writes `s` (secret check, temp file 0600 exclusive no-follow, fsync, rename). Throws StateError; nothing is written then. */
  #write(s: RunState): void {
    if (this.#leaseOnly) throw new StateError('pipegen opened this state folder for the lease only; it writes no proof state through it.');
    s.updatedAt = new Date((this.#deps.now ?? Date.now)()).toISOString();
    const json = `${JSON.stringify(s, null, 1)}\n`;
    const why = secretProblem(json, this.#deps.vault, this.#deps.tokens ?? []);
    if (why !== null) throw new StateError(`pipegen didn't save its proof state: ${why}.`);
    if (Buffer.byteLength(json) > MAX_STATE_BYTES) throw new StateError('pipegen didn\'t save its proof state: it is larger than pipegen\'s limit.');
    const tmp = join(this.dir, `.${STATE_FILE}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
    let fd: number | null = null;
    try {
      fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const buf = Buffer.from(json, 'utf8');
      let off = 0;
      while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
      fsyncSync(fd);
      closeSync(fd);
      fd = null;
      renameSync(tmp, this.path);
    } catch (e) {
      if (fd !== null) try { closeSync(fd); } catch { /* closed */ }
      try { unlinkSync(tmp); } catch { /* gone */ }
      throw new StateError(`pipegen couldn't save its proof state in ${this.path}.`, { cause: e });
    }
  }

  // ---------- the lease ----------

  /**
   * Takes the lease of this app repo for this process (S20): a stop when another live pipegen process holds it on this
   * machine; a lease left by a process that is gone is taken over. Released by releaseLease() or when the process exits.
   */
  acquireLease(runId: string, command?: LeaseCommand): void {
    if (this.#lease !== null) return;
    const token = randomBytes(8).toString('hex');
    const body = JSON.stringify({ pid: process.pid, host: hostname(), runId, token, at: new Date((this.#deps.now ?? Date.now)()).toISOString(), ...(command === undefined ? {} : { command }) });
    const file = join(this.dir, LEASE_FILE);
    for (let tries = 0; tries < 2; tries++) {
      // G-LEASE r2-I3: the lease is written whole to a temp file first, then linked into place (atomic, EEXIST when there is one), so no
      // other pipegen ever sees a half-written lease, and a failed write never removes anything by the lease's path
      const tmp = join(this.dir, `.${LEASE_FILE}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
      let linked = false;
      try {
        const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try { writeSync(fd, body); fsyncSync(fd); } finally { closeSync(fd); }
        linkSync(tmp, file);
        linked = true;
      } catch (e) {
        if ((e as { code?: unknown } | null)?.code !== 'EEXIST') throw new StateError(`pipegen couldn't take the lease ${file}.`, { cause: e });
      } finally {
        try { unlinkSync(tmp); } catch { /* gone */ }
      }
      if (linked) {
        // G-LEASE-R1 (sec L1), r2-L1: another pipegen that judged a stale lease dead may unlink this one and write its own, whether this take
        // was a takeover or a fresh one. After every take, wait a moment and read the lease again: only the last writer goes on
        (this.#deps.leaseSettle ?? sleepSettle)();
        if (this.#readLease(file)?.token !== token) {
          throw new ProofStopError(`Another pipegen took the lease ${file} at the same time. Wait for it to finish, then run ${pipegenCmd(command ?? this.#deps.command)} again.`);
        }
        this.#lease = { token, off: onExit(() => this.#dropLease(token)) };
        return;
      }
      const held = this.#readLease(file);
      if (held !== null && held.host === hostname() && this.#alive(held.pid)) {
        const which = this.#state !== null ? `${this.#state.app.owner}/${this.#state.app.repo}` : this.#app !== '' ? this.#app : 'this repo';
        // Plan V M5: the message names the command that holds the lease (a lease written before then names none). G-LEASE-R1 (sec L2): the
        // process id may have been reused by another program since a pipegen died without giving the lease back
        const who = held.command === undefined ? `process ${held.pid}` : `\`pipegen ${held.command}\`, process ${held.pid}`;
        throw new ProofStopError(`Another pipegen (${who}) is working on ${which} on this machine. Wait for it to finish, or stop it, then run ${pipegenCmd(command ?? this.#deps.command)} again. If process ${held.pid} is not pipegen, remove ${file} and run ${pipegenCmd(command ?? this.#deps.command)} again.`);
      }
      // an unreadable lease (review M-2): never taken over (it can't be shown to be this machine's, or dead), a stop naming it
      if (held !== null && held.host === '') {
        throw new ProofStopError(`The lease ${file} can't be read, so pipegen can't tell whether another pipegen works on this repo. If none runs, remove that file and run ${pipegenCmd(command ?? this.#deps.command)} again.`);
      }
      if (held !== null && held.host !== hostname()) {
        throw new ProofStopError(`The lease ${file} was taken on another machine (${safeText(held.host, 80)}); pipegen won't share the scratch repo with it. Remove that file only if no pipegen runs there.`);
      }
      // G-LEASE-R1 (sec L1): unlink only the lease judged stale (read it again: another pipegen may have just replaced it)
      // r2-L1: also when the first read found no lease (it was given back, then another pipegen took it)
      const again = this.#readLease(file);
      if (again !== null && again.token !== held?.token) continue;
      try { unlinkSync(file); } catch { /* raced: try once more */ }
    }
    throw new ProofStopError(`Another pipegen took the lease ${file} at the same time. Run ${pipegenCmd(command ?? this.#deps.command)} again.`);
  }

  #alive(pid: number): boolean {
    if (this.#deps.alive !== undefined) return this.#deps.alive(pid);
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return (e as { code?: unknown } | null)?.code === 'EPERM';
    }
  }

  #readLease(file: string): { pid: number; host: string; token: string; command?: LeaseCommand } | null {
    let fd: number;
    try {
      fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch {
      return null;
    }
    try {
      const buf = Buffer.alloc(4096);
      const n = readSync(fd, buf, 0, buf.length, 0);
      const d = JSON.parse(buf.subarray(0, n).toString('utf8')) as { pid?: unknown; host?: unknown; token?: unknown; command?: unknown };
      if (typeof d.pid !== 'number' || !Number.isSafeInteger(d.pid) || d.pid <= 0 || typeof d.host !== 'string' || typeof d.token !== 'string') return { pid: 0, host: '', token: '' };
      // only a known command name is shown (the file is the user's own, but its text never reaches the terminal unchecked)
      const command = (LEASE_COMMANDS as readonly unknown[]).includes(d.command) ? d.command as LeaseCommand : undefined;
      return { pid: d.pid, host: d.host, token: d.token, ...(command === undefined ? {} : { command }) };
    } catch {
      return { pid: 0, host: '', token: '' };   // unreadable (a crash while it was written, or edited): acquireLease stops on it
    } finally {
      closeSync(fd);
    }
  }

  #dropLease(token: string): void {
    const file = join(this.dir, LEASE_FILE);
    const held = this.#readLease(file);
    if (held !== null && held.token === token) try { unlinkSync(file); } catch { /* gone */ }
  }

  /** Whether this store holds a lease (this process took it and has not given it back). */
  holdsLease(): boolean {
    return this.#lease !== null;
  }

  /** Whether this store holds the lease (this process took it and has not given it back) of the app repo `app`. */
  holdsLeaseFor(app: Pick<ProofApp, 'owner' | 'repo'>): boolean {
    if (this.#lease === null) return false;
    try {
      return basename(this.dir) === stateFolderName(app);
    } catch {
      return false;
    }
  }

  /** Gives the lease back (only this process's own). */
  releaseLease(): void {
    const l = this.#lease;
    if (l === null) return;
    this.#lease = null;
    l.off();
    this.#dropLease(l.token);
  }
}

/** Plan E Task 7's interface: writes `s` as the saved state of the app repo (a store opened for this one write). */
export async function saveState(p: Pick<ProofApp, 'owner' | 'repo'>, s: RunState, deps: StateDeps = {}): Promise<void> {
  (await StateStore.open(p, deps)).replace(s);
}

/** Plan E Task 7's interface: the saved state of the app repo, checked, or null when there is none. */
export async function loadState(p: Pick<ProofApp, 'owner' | 'repo'>, deps: StateDeps = {}): Promise<RunState | null> {
  return (await StateStore.open(p, deps)).state as RunState | null;
}

// ---------- recording before making (S20) ----------

/**
 * A transport that records every branch in the state file before it is pushed (S20: branches recorded before they are
 * created), then pushes through `transport`. A record that can't be written (or a store not armed) stops the push.
 */
export function recordingTransport(transport: ProofTransport, store: StateStore): ProofTransport {
  return Object.freeze({
    push: async (to: GuardedRepo, from: Parameters<ProofTransport['push']>[1], refs: Parameters<ProofTransport['push']>[2], opts?: { force?: boolean }) => {
      for (const r of refs) store.recordBranch(to.kind, String(r?.branch), to.target.defaultBranch);
      await transport.push(to, from, refs, opts);
    },
  } satisfies ProofTransport);
}

/**
 * The transport for every proof push (E4 carry: pushProofSetup's pushes too): each branch recorded first (recordingTransport),
 * and each push a tracked write (inflight.ts), so the Ctrl-C cleanup waits for it before it lists the branches.
 */
export function proofTransport(transport: ProofTransport, store: StateStore): ProofTransport {
  return trackedTransport(recordingTransport(transport, store));
}

/** WaitOptions.recordPr for proveVariant: the PR's head recorded before it is opened, its number after. */
export function prRecorder(store: StateStore): { before(head: string): void; opened(head: string, pr: number): void } {
  return Object.freeze({
    before: (head: string) => store.recordPr(head),
    opened: (head: string, pr: number) => store.recordPr(head, pr),
  });
}
