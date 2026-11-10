// PL-E1: split out of finish.ts (a pure move, by step); see finish.ts for the whole story.
import type { Octokit } from '@octokit/rest';
import type { Prompter } from '../cli/io.js';
import { SecretStoreError } from '../create/secrets.js';
import { validDate } from '../../gate/src/date.js';
import { CODEOWNERS_BEGIN, CODEOWNERS_END } from '../engine/created-builders.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { GitHubAccessError } from '../github/client.js';
import { type ShaPinningRead } from '../github/lock-probes.js';
import { CO_PLACES, LockError, type LockPlan } from '../layers/locks.js';
import { type Capabilities, type InstallEdit, type InstallPlanned, type InstallRecord, type Plan, type RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { CosignExec, CosignResolver } from './cosign-keys.js';
import { DeliverError, isoAt, readBlobText, statusOf, type RepoRef, type TreeEntry } from './git-data.js';
import type { StateStore } from '../proof/state.js';
import { localFinishPendingPath, RecordError, writeFinishPending, type FinishPending, type LocalRecordDeps } from './record.js';
import { SettingsApi } from './settings-api.js';

export const BLOCK_FROM_VAR = 'PIPEGEN_BLOCK_FROM';
export const COSIGN_PUB_VAR = 'PIPEGEN_COSIGN_PUB';
export const PASSWORD_SECRET = ['PIPEGEN_COSIGN', 'PASSWORD'].join('_');
export const SIGNING_SCOPE = `env:${SIGNING_ENVIRONMENT}` as const;
export const SHA_WHAT = 'the Actions setting that requires actions pinned by commit sha';
export const DAY_MS = 86_400_000;
export const MAX_TEXT = 512 * 1024;
export const show = (s: string, n = 140): string => safeText(s, n);

/** finish stops: a plain reason, and nothing was applied (or, after the first write, what was is named). */
export class FinishError extends Error {
  constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = 'FinishError'; }
}
/** G-COCASE-R1: a CODEOWNERS case variant is there; finish stops before its first write (the command exits 2). */
export class CoCaseError extends FinishError {
  readonly exitCode = 2;
  constructor(message: string) { super(message); this.name = 'CoCaseError'; }
}
/** G-COCASE-R1/R2: shared with setup and deliver (co-case.ts, no import cycle). */
/** One step's own refusal (a read-back that doesn't match, an answer that can't be read): reported, the step not applied. */
export class StepError extends Error {}

export interface FinishOpts { print?: boolean; rotateKey?: boolean }
/** What the re-probe answers (readGitHubContext and probeCapabilities, githubFinishProbe). */
export interface FinishProbeResult {
  plan: Plan; caps: Capabilities; centralBranchProtection: boolean;
  /** The app's own workflows on its default branch: action references by tag or branch (planLocks leaves sha pinning off then). */
  workflowPins: { tagPinned: number; unchecked: boolean };
}
export type FinishProbe = (gh: Octokit, app: RepoRef, facts: { private: boolean; ownerType: 'User' | 'Organization'; defaultBranch: string; centralDefaultBranch: string }, notes: string[], clock: RateClock) => Promise<FinishProbeResult>;
export interface FinishDeps {
  /** The user's output, one line per call (never a secret value). */
  out: (line: string) => void;
  probe: FinishProbe;
  /** S24: the pinned cosign binary, resolved right before each exec (`() => ensurePinnedBinary('cosign')`); the path is never kept. */
  cosignBin: CosignResolver;
  exec?: CosignExec;
  clock?: RateClock; now?: () => Date; local?: LocalRecordDeps;
  /** The trust question (G10-R-sec6): only an interactive run (a terminal, no --yes, not CI) may ask it. */
  io?: Prompter; interactive?: boolean;
  /**
   * G13 (carry 28, BINDING): where the key pair is made, a fresh 0700 folder in it, removed after (generateCosignKeys). It must be a memory
   * folder (tmpfs or ramfs), so the key never reaches a disk; anything else is refused before cosign runs. Default: /dev/shm.
   */
  keyBase?: string;
  /** Test seam: whether a folder is a memory folder (default: the statfs check, isMemoryFolder). */
  isMemory?: (dir: string) => boolean;
  /** Plan V M5: the app's lease the caller already holds (run): finish takes no second one, and leaves it held. */
  lease?: StateStore;
}
export interface FinishResult {
  applied: string[]; skipped: { what: string; why: string }[]; notes: string[];
  /** --print: the commands, in order. */
  commands?: string[];
  recordHash?: string; centralPrUrl?: string;
}

export type EnvEntry = InstallRecord['environments'][number];
export type VarEntry = InstallRecord['variables'][number];
export type SecretEntry = InstallRecord['secrets'][number];
/** sha: the blob read (G-FINREC-R1 sec M2: the text must hash back to it, else the read was lossy and proves no base). */
export interface CoFacts { path: string | null; text: string; isSymlink: boolean; block: string | null; sha?: string }
export interface Ctx {
  gh: Octokit; api: SettingsApi; app: RepoRef; central: RepoRef; clock: RateClock; deps: FinishDeps; print: boolean; rotate: boolean;
  rec: InstallRecord; typed: boolean; planned: InstallPlanned; fresh: LockPlan; profile: RepoProfile; caps: Capabilities; shaRead: ShaPinningRead;
  /** I1: what earlier runs saved before their writes (the local pending file), and the app's repo id it belongs to. */
  pending: FinishPending; repoId: number;
  branch: string; ownerType: 'User' | 'Organization'; private: boolean;
  centralHead: string; centralBranch: string; centralTree: Map<string, TreeEntry>; centralCo: CoFacts;
  applied: string[]; skipped: { what: string; why: string }[]; notes: string[]; commands: string[];
  rulesets: Map<'gate' | 'reviews', InstallRecord['rulesets'][number]>; classic?: InstallRecord['classicProtection']; orgRuleset?: InstallRecord['orgRuleset'];
  repoSettings: NonNullable<InstallRecord['repoSettings']>; centralRec: Partial<NonNullable<InstallRecord['central']>>;
  environments: Map<string, EnvEntry>; variables: VarEntry[]; secrets: SecretEntry[]; cosign?: { pub: string; sha: string };
  centralFiles: { path: string; content: string }[]; files: InstallRecord['files']; edits: InstallEdit[];
  activate?: { id: number; body: Record<string, unknown>; what: string };
  /** m4: the new central ruleset is in the record but couldn't be switched on (its id, and why). */
  activationFailed?: { id: number; why: string };
  /** m1: a new key pair was stored this run (the note about verify depends on how the record is written). */
  newKey?: boolean;
  /** m2: the new private key is stored but its password is not (signing is broken until a new rotation). */
  halfKey?: boolean;
}

// ---------- small helpers ----------

/** A stop of the whole run (rate limit, a rejected or insufficient token): passed through, never turned into one skipped step. */
export const isStop = (e: unknown): boolean => isRateStop(e) || e instanceof GitHubAccessError;
export function whyOf(e: unknown): string {
  if (e instanceof StepError || e instanceof DeliverError || e instanceof SecretStoreError || e instanceof RecordError || e instanceof LockError) return e.message;
  const s = statusOf(e);
  return s === undefined ? 'pipegen got no answer from GitHub.' : `GitHub refused it (HTTP ${s}).`;
}
/** Runs one step; a failure is named (not applied, not recorded) and the next step runs. Returns whether it went through. */
export async function step(x: Ctx, what: string, fn: () => Promise<void>): Promise<boolean> {
  try { await fn(); return true; } catch (e) {
    if (isStop(e)) throw e;
    x.skipped.push({ what, why: whyOf(e) });
    return false;
  }
}
export const noteAbout = (l: LockPlan, re: RegExp): string | undefined => l.notes.find((n) => re.test(n));
/**
 * G11-R2 d (replaces m3's broad match): an earlier entry found by name is the same object only when both created_at are known and equal.
 * Unknown on either side: it is not adopted (its `created` mark never moves to an object pipegen can't show it made, so uninstall never
 * deletes a same-name object of the user's), but its `previous` value is kept (see `priorOf`), never replaced by pipegen's own settings.
 */
export const sameObject = (priorAt: string | undefined, at: string | null): boolean => priorAt !== undefined && at !== null && sameInstant(priorAt, at);
/** G11-R3 (R2-4): two created_at strings name the same instant (GitHub may write `…00Z` or `…00.000Z`); an unparsable one names none. */
export const sameInstant = (a: string, b: string): boolean => { const x = Date.parse(a); return Number.isFinite(x) && x === Date.parse(b); };
/**
 * A ruleset is found by its id, which GitHub never reuses: the same object unless both created_at are known and name other instants (an
 * unconfirmed ruleset pipegen made stays recorded on a re-run). G17 row 42: compared as instants (GitHub may write `…03Z` or `…03.000Z`).
 */
export const sameRuleset = (priorAt: string | undefined, at: string | null): boolean => priorAt === undefined || at === null || sameInstant(priorAt, at);
/**
 * The earlier entry (the record's first, then the pending file's) for the object GitHub holds now: `same` (adopted whole) or `maybe` (a
 * created_at unknown on either side: only its `previous` is kept). A known, different created_at: another object, no entry.
 */
export function priorOf<T extends { githubCreatedAt?: string; previous?: unknown }>(lists: readonly (readonly T[])[], match: (e: T) => boolean, at: string | null): { kind: 'same' | 'maybe'; entry: T } | undefined {
  for (const l of lists) { const e = l.find((p) => match(p) && sameObject(p.githubCreatedAt, at)); if (e !== undefined) return { kind: 'same', entry: e }; }
  for (const l of lists) { const e = l.find((p) => match(p) && (p.githubCreatedAt === undefined || at === null) && p.previous !== undefined); if (e !== undefined) return { kind: 'maybe', entry: e }; }
  return undefined;
}
/**
 * A real calendar day written YYYY-MM-DD (2026-02-30 is not one), by the gate's one date definition (G11-R3 N3-1): JS Date takes year 0000,
 * which the gate reads as no date (warn mode), so a day the gate refuses is never kept, recorded or set.
 */
export const realDay = (d: string): boolean => validDate(d) === d;
/**
 * I2 (S18: never looser), G17C-R1 (F4): the block date is the earliest of the merge day + 7 and every other day given that is a real day
 * (the record's, the unvouched one behind a typed view, the variable's). A day the gate can't read (impossible, year 0000) never counts:
 * the record schema refuses such a day now, and this keeps older records and the variable to the same rule.
 */
export function earliestBlockFrom(mergeDay: string, days: readonly (string | undefined)[]): string {
  let out = mergeDay;
  for (const d of days) if (d !== undefined && realDay(d) && d < out) out = d;
  return out;
}
export const atOf = (at: string | null): { githubCreatedAt: string } | { unconfirmed: true } => (at !== null && isoAt(at) ? { githubCreatedAt: at } : { unconfirmed: true as const });
export const pendingPath = (x: Ctx): string => localFinishPendingPath(x.app, x.deps.local ?? {});
/** I1: the pending file saved with `change` applied, BEFORE the write it guards; a file that can't be saved: that write isn't made. */
export async function keepPending(x: Ctx, change: (p: FinishPending) => void): Promise<void> {
  const next = structuredClone(x.pending);
  change(next);
  try { await writeFinishPending(x.app, x.repoId, next, (x.deps.now ?? (() => new Date()))(), x.deps.local ?? {}); } catch (e) {
    throw new StepError(`pipegen couldn't save locally what it was before (${e instanceof RecordError ? e.message : 'an error'}), so it doesn't change it.`);
  }
  x.pending = next;
}
/** I1: an object pipegen just made, saved to the pending file after its read-back (best effort: only its `created` mark is at stake). */
export async function keepMade(x: Ctx, change: (p: FinishPending) => void): Promise<void> {
  try { await keepPending(x, change); } catch { x.notes.push(`pipegen couldn't save locally that it made an object (${show(pendingPath(x))}); if this run stops before the install record is written, uninstall won't know pipegen made it.`); }
}
/**
 * G11-R2 a: a write GitHub refused (HTTP 4xx) changed nothing, so the value `keepPending` saved for it is dropped again (`unsave`): a
 * later run never takes it for what a setting the user changed themselves was before. Any other failure keeps it (the write may have
 * gone through). The refusal is passed on.
 */
export async function guardedWrite(x: Ctx, unsave: ((p: FinishPending) => void) | undefined, write: () => Promise<unknown>): Promise<void> {
  try { await write(); } catch (e) {
    const s = statusOf(e);
    if (unsave !== undefined && s !== undefined && s >= 400 && s < 500) {
      const next = structuredClone(x.pending);
      unsave(next);
      try { await writeFinishPending(x.app, x.repoId, next, (x.deps.now ?? (() => new Date()))(), x.deps.local ?? {}); x.pending = next; } catch {
        x.notes.push(`pipegen couldn't take back from its pending file (${show(pendingPath(x))}) a value it saved for a write GitHub refused; remove the file before the next \`npx pipegen finish\`.`);
      }
    }
    throw e;
  }
}
export const pendEnv = (p: FinishPending, e: EnvEntry): void => { p.environments = [...p.environments.filter((v) => v.name !== e.name), e]; };
export const pendVar = (p: FinishPending, v: VarEntry): void => { p.variables = [...p.variables.filter((w) => !(w.name === v.name && w.scope === v.scope)), v]; };
export const pathOf = (route: string, params: Readonly<Record<string, unknown>>): string => route.replace(/\{([a-z_]+)\}/g, (_, k: string) => String(params[k]));
/** One `gh api` command; a JSON body goes on stdin through a quoted heredoc (no shell expansion). */
export function apiCmd(method: string, route: string, params: Readonly<Record<string, unknown>>, body?: Record<string, unknown>): string {
  return `gh api --method ${method} ${pathOf(route, params)}${body === undefined ? '' : ` --input - <<'PIPEGEN_JSON'\n${JSON.stringify(body)}\nPIPEGEN_JSON`}`;
}
export const appParams = (x: Ctx): { owner: string; repo: string } => ({ owner: x.app.owner, repo: x.app.repo });
export const centralParams = (x: Ctx): { owner: string; repo: string } => ({ owner: x.central.owner, repo: x.central.repo });

/** pipegen's one CODEOWNERS block in `text` (exactly once), or null. */
export function blockOf(text: string): string | null {
  const re = new RegExp(`(?:^|(?<=\\n))${CODEOWNERS_BEGIN}\\n[\\s\\S]*?\\n${CODEOWNERS_END}(?:\\n|$)`, 'g');
  const m = text.match(re);
  return m !== null && m.length === 1 ? m[0] as string : null;
}
/** The code owners a pipegen block names (the same on every line), in order. */
export function ownersOf(block: string | null): string[] {
  if (block === null) return [];
  const out: string[] = [];
  for (const line of block.split('\n').slice(1, -1)) for (const t of line.trim().split(/\s+/).slice(1)) if (/^@[A-Za-z0-9-]+$/.test(t) && !out.includes(t)) out.push(t);
  return out;
}
export async function coFacts(gh: Octokit, r: RepoRef, entries: ReadonlyMap<string, TreeEntry>, clock: RateClock): Promise<CoFacts> {
  for (const path of CO_PLACES) {
    const e = entries.get(path);
    if (e === undefined) continue;
    if (e.type !== 'blob' || e.mode === '120000') return { path, text: '', isSymlink: true, block: null };
    const text = await readBlobText(gh, r, e.sha, MAX_TEXT, clock);
    return { path, text, isSymlink: false, block: blockOf(text), sha: e.sha };
  }
  return { path: null, text: '', isSymlink: false, block: null };
}
