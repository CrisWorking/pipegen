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
// next to the state; another live process's lease is a stop; a dead one's is taken over. Two machines are not covered (a
// recorded residual: the scratch repo's key state is shared per repo id inside one process only, E4).
import { closeSync, constants, fstatSync, fsyncSync, openSync, readSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { KnownValueCheck, PipelineDraft } from '../types.js';
import { onExit } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { prepareTrustedDir, type TrustedDirKind } from '../util/trusted-dir.js';
import { trackedTransport } from './inflight.js';
import { PLACEHOLDER_PREFIX } from './keys.js';
import { ProofStopError, validBranchName, type GuardedRepo, type ProofApp } from './target.js';
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

/** A problem with the state file or a refused write. The message never holds a value. */
export class StateError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'StateError';
  }
}

export interface RecordedBranch { repo: 'scratch' | 'central'; ref: string }
export interface RecordedPr { head: string; number?: number }
export interface RunState {
  version: typeof STATE_VERSION;
  runId: string;
  app: ProofApp;
  stage: Stage;
  /** interrupted / stopped: the stage the run had reached when it stopped (nextStage goes on from it). */
  interruptedAt?: WorkStage;
  /** stopped: which cap stopped it. */
  stoppedBy?: 'ai-cost' | 'actions-minutes';
  /** The draft (CreatedFile.aiEdited kept: a resumed draft treats those files as AI-written; E7-R14). Plan G re-referees it. */
  draft?: PipelineDraft;
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
  /** The cleanup deleted scratch runs (or the whole repo): a resumed meter can't count them again and restores minutesUsed. */
  runsDeleted?: boolean;
  /** The AI spend (AiSpendMeter.usedUsd: spent plus reserved), and the cap (null: Ollama, no cap). */
  aiCostUsd: number;
  aiCap: number | null;
  /** GitHub's id of the scratch repo, recorded when pipegen created it: a delete needs it (rulings S3, E1-R4). */
  scratchRepoId?: number;
  scratchDeleted?: boolean;
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
  stoppedBy: z.enum(['ai-cost', 'actions-minutes']).optional(),
  draft: draft.optional(),
  branches: z.array(z.strictObject({ repo: z.enum(['scratch', 'central']), ref: branchName })).max(1000),
  prs: z.array(z.strictObject({ head: branchName, number: z.number().int().positive().optional() })).max(1000),
  secretNames: z.array(z.string().regex(SECRET_NAME_RE)).max(1000),
  minutesUsed: nonNeg,
  cap: nonNeg,
  proofStart: z.strictObject({ at: finite, fromServer: z.boolean() }).optional(),
  runsDeleted: z.boolean().optional(),
  aiCostUsd: nonNeg,
  aiCap: nonNeg.nullable(),
  scratchRepoId: z.number().int().positive().optional(),
  scratchDeleted: z.boolean().optional(),
  cleanupDone: z.boolean().optional(),
  leftovers: z.array(text).max(1000),
  notes: z.array(text).max(1000),
  updatedAt: z.string().max(40),
}).refine((s) => (s.stage === 'interrupted' || s.stage === 'stopped') === (s.interruptedAt !== undefined), 'interruptedAt goes with an interrupted or stopped stage');

// ---------- stages ----------

const isWork = (s: Stage | undefined): s is WorkStage => s !== undefined && (STAGE_ORDER as readonly string[]).includes(s);

/**
 * The stage a resumed run goes on with (S20: Plan G's `resume` uses it), or null when the run is done (delivered). The next
 * stage in order, except: `proving` → `proving` (the proof didn't finish: it runs again, after its leftovers are cleaned) and
 * `proven` → `cleaned` (the cleanup runs before anything is shown). interrupted / stopped go on from the stage they had reached.
 */
export function nextStage(s: Pick<RunState, 'stage' | 'interruptedAt'>): WorkStage | null {
  const at: Stage | undefined = s.stage === 'interrupted' || s.stage === 'stopped' ? s.interruptedAt : s.stage;
  if (!isWork(at)) throw new StateError('The saved state was interrupted without the stage it had reached, so pipegen can\'t tell where to go on.');
  if (at === 'proving') return 'proving';
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
}

const KIND: TrustedDirKind = {
  noun: 'state', keeping: 'its proof state', risk: 'change what pipegen deletes or resumes',
  error: (message, cause) => new StateError(message, cause === undefined ? undefined : { cause }),
};

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

  private constructor(dir: string, deps: StateDeps) {
    this.dir = dir;
    this.path = join(dir, STATE_FILE);
    this.#deps = deps;
  }

  /** Prepares `<cache>/pipegen/<owner>__<repo>` (0700, trusted chain) and loads the saved state, if any. */
  static async open(app: Pick<ProofApp, 'owner' | 'repo'>, deps: StateDeps = {}): Promise<StateStore> {
    const uid = deps.uid ?? process.getuid?.();
    if (uid === undefined) throw new StateError('pipegen could not tell which user it runs as, so it will not keep its proof state.');
    const env = deps.env ?? process.env;
    const xdg = env.XDG_CACHE_HOME;
    const base = xdg !== undefined && isAbsolute(xdg) ? xdg : join(deps.home ?? homedir(), '.cache');
    const dir = await prepareTrustedDir(base, ['pipegen', stateFolderName(app)], false, uid, KIND);
    const store = new StateStore(dir, { ...deps, uid });
    store.#state = store.load();
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
      throw new StateError(code === 'ELOOP' ? `${this.path} is a symbolic link; pipegen won't read it.` : `pipegen couldn't open its state file ${this.path}.`, { cause: e });
    }
    let raw: string;
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) throw new StateError(`${this.path} is not a regular file; pipegen won't read it.`);
      if (st.uid !== this.#deps.uid) throw new StateError(`${this.path} is not owned by you; pipegen won't read it.`);
      if ((st.mode & 0o077) !== 0) throw new StateError(`${this.path} can be read or changed by other users (mode ${(st.mode & 0o777).toString(8)}); pipegen won't trust it. Fix it with: chmod 600 '${this.path}'`);
      if (st.size > MAX_STATE_BYTES) throw new StateError(`${this.path} is larger than pipegen's limit; pipegen won't read it.`);
      const buf = Buffer.alloc(st.size + 1);
      let got = 0;
      for (;;) {
        const n = readSync(fd, buf, got, buf.length - got, null);
        if (n === 0) break;
        got += n;
        if (got > st.size) throw new StateError(`${this.path} grew while pipegen read it; pipegen won't trust it.`);
      }
      raw = buf.subarray(0, got).toString('utf8');
    } finally {
      closeSync(fd);
    }
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      throw new StateError(`${this.path} is not a state file pipegen can read (not JSON).`, { cause: e });
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
  begin(runId: string, app: ProofApp, init: { cap: number; aiCap: number | null; draft?: PipelineDraft }): RunState {
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
      ...(init.draft === undefined ? {} : { draft: init.draft }),
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
    this.update((n) => {
      n.stage = to;
      delete n.interruptedAt;
      delete n.stoppedBy;
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

  #requireArmed(what: string): void {
    if (!this.#armed) throw new StateError(`pipegen won't ${what} before its cleanup is registered for Ctrl-C (armProofCleanup).`);
  }

  /** Records a branch before it is pushed (S20). The scratch default branch is not recorded (it is emptied, never deleted). */
  recordBranch(repo: 'scratch' | 'central', ref: string, defaultBranch: string): void {
    this.#requireArmed('push a branch');
    if (!validBranchName(ref)) throw new StateError('The branch to record is not a branch name.');
    if (repo === 'scratch' && ref === defaultBranch) return;
    if (this.#need().branches.some((b) => b.repo === repo && b.ref === ref)) return;
    this.update((n) => { n.branches.push({ repo, ref }); });
  }

  /** Records a PR before it is opened (by its head branch), then its number. */
  recordPr(head: string, number?: number): void {
    this.#requireArmed('open a PR');
    if (!validBranchName(head)) throw new StateError('The PR head to record is not a branch name.');
    this.update((n) => {
      const have = n.prs.find((p) => p.head === head && (p.number === undefined || p.number === number));
      if (have === undefined) n.prs.push(number === undefined ? { head } : { head, number });
      else if (number !== undefined) have.number = number;
    });
  }

  /** Records the secret names about to be stored in the scratch repo (names only). */
  recordSecretNames(names: readonly string[]): void {
    for (const n of names) if (typeof n !== 'string' || !SECRET_NAME_RE.test(n)) throw new StateError('A secret name to record is not a secret name.');
    this.update((s) => { s.secretNames = [...new Set([...s.secretNames, ...names.map((n) => n.toUpperCase())])].sort(); });
  }

  /** The id GitHub gave the scratch repo pipegen just created (checkProofRepos' onCreated). */
  scratchCreated(id: number): void {
    this.#requireArmed('create a repo');
    if (!Number.isSafeInteger(id) || id <= 0) throw new StateError('The repo id to record is not one.');
    this.update((s) => { s.scratchRepoId = id; s.scratchDeleted = false; });
  }

  /** The meters (minutes used, the proof start by GitHub's clock, AI spend) as they are now. */
  saveMeters(m: { minutes?: { used: number; since: number; fromServer?: boolean }; aiUsedUsd?: number }): void {
    this.update((s) => {
      if (m.minutes !== undefined) {
        s.minutesUsed = Math.max(s.minutesUsed, m.minutes.used);
        s.proofStart ??= { at: m.minutes.since, fromServer: m.minutes.fromServer ?? true };
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
  acquireLease(runId: string): void {
    if (this.#lease !== null) return;
    const token = randomBytes(8).toString('hex');
    const body = JSON.stringify({ pid: process.pid, host: hostname(), runId, token, at: new Date((this.#deps.now ?? Date.now)()).toISOString() });
    const file = join(this.dir, LEASE_FILE);
    for (let tries = 0; tries < 2; tries++) {
      try {
        const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try { writeSync(fd, body); fsyncSync(fd); } finally { closeSync(fd); }
        this.#lease = { token, off: onExit(() => this.#dropLease(token)) };
        return;
      } catch (e) {
        if ((e as { code?: unknown } | null)?.code !== 'EEXIST') throw new StateError(`pipegen couldn't take the lease ${file}.`, { cause: e });
      }
      const held = this.#readLease(file);
      if (held !== null && held.host === hostname() && this.#alive(held.pid)) {
        const which = this.#state === null ? 'this repo' : `${this.#state.app.owner}/${this.#state.app.repo}`;
        throw new ProofStopError(`Another pipegen (process ${held.pid}) is working on ${which} on this machine. Wait for it to finish, or stop it, then run pipegen again.`);
      }
      if (held !== null && held.host !== hostname()) {
        throw new ProofStopError(`The lease ${file} was taken on another machine (${safeText(held.host, 80)}); pipegen won't share the scratch repo with it. Remove that file only if no pipegen runs there.`);
      }
      try { unlinkSync(file); } catch { /* raced: try once more */ }
    }
    throw new ProofStopError(`Another pipegen took the lease ${file} at the same time. Run pipegen again.`);
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

  #readLease(file: string): { pid: number; host: string; token: string } | null {
    let fd: number;
    try {
      fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    } catch {
      return null;
    }
    try {
      const buf = Buffer.alloc(4096);
      const n = readSync(fd, buf, 0, buf.length, 0);
      const d = JSON.parse(buf.subarray(0, n).toString('utf8')) as { pid?: unknown; host?: unknown; token?: unknown };
      if (typeof d.pid !== 'number' || !Number.isSafeInteger(d.pid) || d.pid <= 0 || typeof d.host !== 'string' || typeof d.token !== 'string') return { pid: 0, host: '', token: '' };
      return { pid: d.pid, host: d.host, token: d.token };
    } catch {
      return { pid: 0, host: '', token: '' };   // unreadable: an empty lease (a crash while it was written) is taken over
    } finally {
      closeSync(fd);
    }
  }

  #dropLease(token: string): void {
    const file = join(this.dir, LEASE_FILE);
    const held = this.#readLease(file);
    if (held !== null && held.token === token) try { unlinkSync(file); } catch { /* gone */ }
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
