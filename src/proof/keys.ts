// Plan E Task 3 / sub-task E4 (spec §19; rulings S14, B1, E0a-R5 / DECISIONS #113; threats T12, T32): the scratch keys, the
// repo secrets of the private scratch repo `pipegen-proof-<repo>` while a proof runs. Three kinds of value go there:
// - placeholders, `pipegen-placeholder-<NAME>` (not secret, safe if they leak): AI-written code runs with them first;
// - the proof's throwaway PIPEGEN_FP_KEY: fresh random bytes for this scratch repo only, never the delivered key the vault holds;
// - the user's real test keys (the vault's values), only after the user confirmed the AI-written changes (E7's confirm).
// Placeholders and the throwaway key never go through the vault (S14): they are sealed and stored by secrets.ts
// storeRepoSecretsVia; real values by storeSecretsVia. Both only through target.ts scratchSecretSink.
//
// Every store batch, in this order:
//   1. no stop has begun (interrupting(), E0b), checked again by every guarded write and before every rate-limit retry;
//   2. before the FIRST store, deleteAll (S14): secrets a crashed run left behind are listed from the API and deleted;
//   3. checkScratchAccess again, right before the store (E1 carry G1/R5): the repo is still private and nobody else can push.
//      Its branded result is what scratchSecretSink takes (spent there), so this re-check can't be skipped or reused. The
//      answers the user already gave (keyed on the exact doubts) are passed back, so the same doubt isn't asked twice;
//   4. each PUT is a tracked write (inflight.ts), so E8's Ctrl-C cleanup waits for it before it lists and deletes.
//
// deleteAll lists every secret from the API (never from memory), deletes each one (deleteScratchSecret, the one write sent
// while a stop is under way), and lists again: anything still there is a leftover, named in the error.
//
// One key state per scratch repo (fix round 1, ruling E4-R1): every ScratchKeys on the same repo (by GitHub's repo id, read
// once per instance) shares one record in a module-level registry: what pipegen stored under each name (its kind and the
// updated_at GitHub listed right after the store), whether a deleteAll listed the repo empty, the store batches in flight,
// and whether a value the user typed was written since that verified deleteAll.
//
// The excerpt evidence (ruling E0a-R5, DECISIONS #113): errorExcerpt (excerpt.ts) builds a log excerpt for the AI only with
// evidence that the run the log comes from held no value the user typed. ScratchKeys alone mints it, as an unforgeable brand
// (a frozen object in a module-private WeakSet) bound to the run ids it was minted for (fix round 1, M1), through a ticket
// that brackets the runs:
//   const t = await keys.ticket();             // BEFORE the push (or re-run) that starts the runs
//   ... the runs start and finish ...
//   const ev = await keys.evidence(t, runIds); // AFTER their outcomes are complete: the brand, or null (keys.lastRefusal says why)
// At BOTH ticket() and evidence() the repo's real state is read from the API (E4-R1, E4-R2), and the brand is refused when:
//   - the shared state isn't verified clean, a store is in flight, or a value the user typed was written (or began to be)
//     since the last verified deleteAll; at evidence(), also when one was written since the ticket;
//   - the repo's Actions secrets (listed whole, every page) hold a name pipegen didn't write in this state, a value the user
//     typed, or a secret whose updated_at differs from pipegen's own record (changed by hand);
//   - an organisation secret visible to the repo, whose name a proof workflow reads (case-insensitive; every name when
//     `readByWorkflows` isn't given), isn't shadowed by a placeholder or throwaway pipegen wrote under that name;
//   - a repo Actions variable isn't one of the declared non-secret names (target.ts SCRATCH_VARIABLES) holding its config;
//   - any of those lists can't be read (unknown fails closed).
// Recorded residuals: environment secrets and variables, and organisation variables, are not listed (no proof job takes an
// environment's secrets, and E1's guard refuses environment writes of both); a value changed by hand in the instant between
// pipegen's PUT and its own list would be recorded as pipegen's.
import { randomBytes } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { knownValueScrubber } from '../ai/redact.js';
import type { CliIO } from '../cli/io.js';
import { SecretVault, storeRepoSecretsVia, storeSecretsVia, type SecretSink } from '../create/secrets.js';
import { validDate } from '../../gate/src/date.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { interrupting } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { trackWrite } from './inflight.js';
import { checkScratchAccess } from './repos.js';
import type { SecretStoreStep } from './snapshot.js';
import {
  assertScratch, deleteScratchSecret, githubRead, isProofTarget, requireGuarded, SCRATCH_VARIABLES, scratchSecretSink, ScratchGuardError,
  type GuardedRepo, type ProofTarget,
} from './target.js';

export const PLACEHOLDER_PREFIX = 'pipegen-placeholder-';
/** The throwaway fingerprint key's name in the scratch repo (the same name the delivered pipeline reads). */
export const SCRATCH_FP_KEY = 'PIPEGEN_FP_KEY';
/** Secrets listed per page, and the most pages deleteAll reads (1,000 secrets; GitHub allows 100 per repo). */
export const SECRET_LIST_PAGES = 10;
const NAME_RE = /^[A-Z_][A-Z0-9_]{0,199}$/;

type ProofIO = Pick<CliIO, 'prompt' | 'out' | 'err'>;
type Kind = 'placeholder' | 'throwaway' | 'real';

/** A store or delete that failed. Names only, never a value. `leftovers`: secrets still in the scratch repo. */
export class ScratchKeysError extends Error {
  readonly leftovers: readonly string[];
  constructor(message: string, leftovers: readonly string[] = []) {
    super(message);
    this.name = 'ScratchKeysError';
    this.leftovers = Object.freeze([...leftovers]);
  }
}

// ---------- the excerpt evidence (DECISIONS #113) ----------

declare const EVIDENCE: unique symbol;
/** Proof that a run held only placeholders and throwaway keys. Only ScratchKeys.evidence makes one (errorExcerpt checks). */
export interface ExcerptEvidence { readonly [EVIDENCE]: true }
const minted = new WeakSet<object>();
/** True only for an object ScratchKeys.evidence made. A copy, a look-alike or an object made from one is not evidence. */
export const isExcerptEvidence = (x: unknown): x is ExcerptEvidence => typeof x === 'object' && x !== null && minted.has(x);

/** The run ids each brand was minted for (M1): errorExcerpt takes a log only of one of them. */
const coveredRuns = new WeakMap<object, ReadonlySet<number>>();
/** True only when `e` is evidence ScratchKeys minted for a set of runs that holds `runId`. */
export const evidenceCovers = (e: unknown, runId: unknown): boolean =>
  isExcerptEvidence(e) && typeof runId === 'number' && (coveredRuns.get(e)?.has(runId) ?? false);

/** An opaque ticket (see the file comment). */
export interface RunTicket { readonly ticket: true }

/** What pipegen wrote under one name: its kind, and the updated_at GitHub listed right after (null: unknown). */
interface StoredRec { kind: Kind; updatedAt: string | null }
/** The one key state of a scratch repo (E4-R1), shared by every ScratchKeys on it. */
interface KeyState {
  id: number;
  stored: Map<string, StoredRec>;
  /** A deleteAll listed the repo empty, with no store in flight, and nothing failed since. */
  clean: boolean;
  /** Bumped when a store of a value the user typed begins. */
  realSeq: number;
  /** A value the user typed was written (or began to be) since the last verified deleteAll. */
  realSinceClean: boolean;
  /** Store batches in flight: the names each writes, and whether any is a user value. */
  busy: Map<Promise<unknown>, { names: string[]; real: boolean }>;
  /** Every placeholder and throwaway value stored in this repo (the excerpt scrubber, B1). */
  ours: Set<string>;
  /** Bumped whenever `ours` grows (the live scrubber, M3). */
  version: number;
}
/** The registry, by GitHub's repo id. */
const states = new Map<number, KeyState>();
interface TicketRec { state: KeyState | null; seq: number; refusal: string | null }
const tickets = new WeakMap<object, TicketRec>();
/** How long deleteAll waits for stores in flight before it deletes anyway (M4). */
export const DELETE_WAIT_MS = 30_000;

/** The placeholder value of a secret name (not secret; safe if it leaks). */
export const placeholderValue = (name: string): string => `${PLACEHOLDER_PREFIX}${name.toUpperCase()}`;

export interface ScratchKeysDeps {
  io: ProofIO;
  /** checkScratchAccess answers already given in this run (E1's ScratchAccess.accepted). */
  accepted?: readonly string[];
  clock?: RateClock;
  /** For tests: the random source of the throwaway key. */
  random?: (n: number) => Uint8Array;
  /** The secret names the proof's workflows read (`secrets.NAME`). Absent: every organisation secret counts as read (fails closed). */
  readByWorkflows?: readonly string[];
  /** deleteAll's wait for stores in flight (default DELETE_WAIT_MS). */
  deleteWaitMs?: number;
  /** Where a leftover goes (E0b's leftover callback; default: printed through io.err). */
  leftover?: (item: string) => void;
}
type Entry = { name: string; kind: 'placeholder' | 'throwaway'; value: string } | { name: string; kind: 'real'; from: string };

export class ScratchKeys {
  readonly #gh: Octokit;
  readonly #scratch: GuardedRepo;
  readonly #vault: SecretVault;
  readonly #io: ProofIO;
  readonly #clock: RateClock;
  readonly #random: (n: number) => Uint8Array;
  readonly #accepted = new Set<string>();
  readonly #readByWorkflows: ReadonlySet<string> | null;
  readonly #deleteWaitMs: number;
  readonly #leftover: (item: string) => void;
  /** The shared state of this repo, once its id is read. */
  #st: KeyState | null = null;
  #scrub: { version: number; fn: (text: string) => string } | null = null;
  #why: string | undefined;

  constructor(gh: Octokit, t: ProofTarget, vault: SecretVault, deps: ScratchKeysDeps) {
    if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
    if (!(vault instanceof SecretVault)) throw new ScratchGuardError('ScratchKeys takes the run\'s SecretVault.');
    this.#gh = gh;
    this.#scratch = assertScratch(t, { owner: t.owner, repo: t.appRepo });
    this.#vault = vault;
    this.#io = deps.io;
    this.#clock = deps.clock ?? clockOf(gh);
    this.#random = deps.random ?? ((n) => randomBytes(n));
    for (const a of deps.accepted ?? []) this.#accepted.add(a);
    this.#readByWorkflows = deps.readByWorkflows === undefined ? null : new Set(deps.readByWorkflows.map((n) => String(n).toUpperCase()));
    this.#deleteWaitMs = deps.deleteWaitMs ?? DELETE_WAIT_MS;
    this.#leftover = deps.leftover ?? ((item) => this.#io.err(`Left behind: ${item}`));
  }

  /** The scratch repo these keys go to. */
  get scratch(): GuardedRepo { return this.#scratch; }
  /** For the repo's shared state: 'real' once any user value is (or may be) stored; 'placeholder' with only placeholders or throwaway keys; else 'none'. */
  get mode(): 'none' | 'placeholder' | 'real' {
    const kinds = [...(this.#st?.stored.values() ?? [])].map((r) => r.kind);
    return kinds.includes('real') ? 'real' : kinds.length > 0 ? 'placeholder' : 'none';
  }
  /** Every checkScratchAccess answer given so far (pass it on to the next ScratchKeys or check). */
  get accepted(): string[] { return [...this.#accepted]; }
  /** Why the last ticket or evidence gave no brand (names only, never a value). */
  get lastRefusal(): string | undefined { return this.#why; }
  /** The upper-case names stored, each with its kind (no value). */
  stored(): Record<string, Kind> { return Object.fromEntries([...(this.#st?.stored ?? new Map<string, StoredRec>())].map(([k, r]) => [k, r.kind])); }

  /** Stores `pipegen-placeholder-<NAME>` for each name (never a vault value). */
  async placeholders(names: readonly string[]): Promise<void> {
    await this.#store(this.#placeholderEntries(names));
  }

  /** Stores a fresh random PIPEGEN_FP_KEY, for the scratch repo only: never the delivered key the vault holds. */
  async throwaway(): Promise<void> {
    await this.#store([await this.#throwawayEntry()]);
  }

  /** E2's first store (pushProofSetup's seam): the placeholders and the throwaway key in one batch, so one access check. */
  async setup(names: readonly string[]): Promise<void> {
    const ph = this.#placeholderEntries(names);
    await this.#store([...ph, await this.#throwawayEntry()]);
  }

  /** Stores the vault's values for `names` (only after the user's confirm, E7). PIPEGEN_* and GITHUB_* are refused. */
  async real(names: readonly string[]): Promise<void> {
    const entries = names.map((n) => {
      const up = this.#name(n);
      if (/^PIPEGEN_/.test(up)) throw new ScratchKeysError(`${up} is pipegen's own; the scratch repo gets the throwaway key, never the delivered one.`);
      if (typeof n !== 'string' || !this.#vault.has(n)) throw new ScratchKeysError(`there is no value for ${safeText(up, 80)} in the vault.`);
      return { name: up, kind: 'real' as const, from: n };
    });
    await this.#store(entries);
  }

  /**
   * Every secret of the scratch repo, listed from the API, deleted one by one, then listed again (S14). Runs before the first
   * store and in E8's cleanup (also while a stop is under way). It first waits for the repo's stores in flight, at most
   * `waitMs` (default deps.deleteWaitMs, DELETE_WAIT_MS; M4), then deletes anyway; a store still in flight is reported
   * through `leftover` (E0b's callback) and keeps the state unverified. Returns the names deleted; throws ScratchKeysError
   * naming the leftovers when the list can't be read or a secret stays.
   */
  async deleteAll(opts: { waitMs?: number; leftover?: (item: string) => void } = {}): Promise<string[]> {
    const st = await this.#state();
    const waitMs = opts.waitMs ?? this.#deleteWaitMs;
    if (st.busy.size > 0) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([Promise.allSettled([...st.busy.keys()]), new Promise((ok) => { timer = setTimeout(ok, Math.max(0, waitMs)); })]);
      clearTimeout(timer);
    }
    const still = [...st.busy.values()];
    try {
      return await this.#deleteAll(st);
    } finally {
      if (still.length > 0) {
        st.clean = false;
        if (still.some((b) => b.real)) st.realSinceClean = true;
        const report = opts.leftover ?? this.#leftover;
        for (const b of still) {
          report(`a store of ${b.names.map((n) => safeText(n, 80)).join(', ')} to ${this.#scratch.fullName} was still in flight when its secrets were deleted; `
            + `it may have landed after (check ${this.#scratch.fullName} → Settings → Secrets and variables → Actions)`);
        }
      }
    }
  }

  async #deleteAll(st: KeyState): Promise<string[]> {
    st.clean = false;
    const first = (await this.#list()).map((e) => e.name);
    const deleted: string[] = [];
    const failed: string[] = [];
    for (const name of first) {
      try {
        await deleteScratchSecret(this.#gh, this.#scratch, name, this.#clock);
        deleted.push(name);
      } catch (e) {
        if (e instanceof ScratchGuardError) throw e;
        failed.push(name);
      }
    }
    const left = (await this.#list()).map((e) => e.name);
    const leftovers = [...new Set([...failed, ...left])];
    if (leftovers.length > 0) {
      // a leftover's value is unknown to pipegen: it counts as a user value (no evidence while it is there)
      for (const n of leftovers) st.stored.set(n, { kind: 'real', updatedAt: null });
      st.realSinceClean = true;
      throw new ScratchKeysError(`pipegen couldn't delete every secret of ${this.#scratch.fullName}: ${leftovers.map((n) => safeText(n, 80)).join(', ')} `
        + `${leftovers.length === 1 ? 'is' : 'are'} still there. Delete ${leftovers.length === 1 ? 'it' : 'them'} in ${this.#scratch.fullName} → Settings → Secrets and variables → Actions.`, leftovers);
    }
    st.stored.clear();
    st.clean = true;
    st.realSinceClean = false;
    return deleted;
  }

  /**
   * The composed scrubber's second half (ruling B1, S14): every placeholder and throwaway value stored in this repo, read
   * live at each call (M3), so values stored after this call are scrubbed too. The caller composes it after vault.scrubber().
   */
  scrubber(): (text: string) => string {
    return (text) => this.#currentScrub()(text);
  }

  #currentScrub(): (text: string) => string {
    const st = this.#st;
    if (st === null) return (text) => text;
    if (this.#scrub === null || this.#scrub.version !== st.version) this.#scrub = { version: st.version, fn: knownValueScrubber([...st.ours]) };
    return this.#scrub.fn;
  }

  /** Take BEFORE the push or re-run that starts the runs (see the file comment). Reads the repo's secrets, org secrets and variables. */
  async ticket(): Promise<RunTicket> {
    const t = Object.freeze({ ticket: true as const });
    let rec: TicketRec;
    try {
      const st = await this.#state();
      const seq = st.realSeq;
      rec = { state: st, seq, refusal: await this.#verify(st) };
    } catch (e) {
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      rec = { state: null, seq: -1, refusal: `pipegen couldn't read ${this.#scratch.fullName}` };
    }
    tickets.set(t, rec);
    if (rec.refusal !== null) this.#why = rec.refusal;
    return t;
  }

  /**
   * The excerpt evidence for `runIds`, the runs `ticket` brackets, taken AFTER they finished: the brand when the scratch repo
   * held only placeholders and throwaway keys for the whole window (read from the API again now), else null; `lastRefusal`
   * says why (DECISIONS #113, E4-R1, E4-R2).
   */
  async evidence(ticket: RunTicket, runIds: readonly number[]): Promise<ExcerptEvidence | null> {
    const refuse = (why: string): null => { this.#why = why; return null; };
    const rec = typeof ticket === 'object' && ticket !== null ? tickets.get(ticket) : undefined;
    if (rec === undefined) return refuse('the ticket was not taken by ScratchKeys');
    if (rec.refusal !== null) return refuse(rec.refusal);
    if (!Array.isArray(runIds) || runIds.length === 0 || !runIds.every((r) => typeof r === 'number' && Number.isSafeInteger(r) && r > 0)) {
      return refuse('the evidence names no run (a run id is a positive whole number)');
    }
    let st: KeyState;
    try {
      st = await this.#state();
    } catch (e) {
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      return refuse(`pipegen couldn't read ${this.#scratch.fullName}`);
    }
    if (rec.state !== st) return refuse('the ticket is for another scratch repo');
    if (rec.seq !== st.realSeq) return refuse(`a value you typed was stored in ${this.#scratch.fullName} after the ticket`);
    const now = await this.#verify(st);
    if (now !== null) return refuse(now);
    const e = Object.freeze(Object.create(null) as object) as ExcerptEvidence;
    minted.add(e);
    coveredRuns.set(e, new Set(runIds));
    this.#why = undefined;
    return e;
  }

  // ---------- inside ----------

  /** The repo's shared state (E4-R1), by its GitHub id, read once per instance. */
  async #state(): Promise<KeyState> {
    if (this.#st !== null) return this.#st;
    let d: { id?: unknown; full_name?: unknown } | null;
    try {
      d = (await githubRead(this.#gh, 'GET /repos/{owner}/{repo}', { owner: this.#scratch.owner, repo: this.#scratch.repo }, this.#clock)).data as typeof d;
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      throw new ScratchKeysError(`pipegen couldn't read ${this.#scratch.fullName}, so it stores and deletes nothing there.`);
    }
    const id = d?.id;
    if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0 || typeof d?.full_name !== 'string' || d.full_name.toLowerCase() !== this.#scratch.fullName.toLowerCase()) {
      throw new ScratchKeysError(`GitHub's answer about ${this.#scratch.fullName} could not be read.`);
    }
    let st = states.get(id);
    if (st === undefined) {
      st = { id, stored: new Map(), clean: false, realSeq: 0, realSinceClean: false, busy: new Map(), ours: new Set(), version: 0 };
      states.set(id, st);
    }
    this.#st = st;
    return st;
  }

  /** null when the repo's real state allows the brand, else why not (see the file comment). Never throws but for a rejected token. */
  async #verify(st: KeyState): Promise<string | null> {
    const repo = this.#scratch.fullName;
    if (!st.clean) return `${repo} has not been listed empty by pipegen's deleteAll since its last change it can't account for`;
    if (st.busy.size > 0) return `a store to ${repo} is in flight`;
    if (st.realSinceClean) return `a value you typed was stored in ${repo} since its secrets were last deleted`;
    let secrets: { name: string; updatedAt: string | null }[];
    try {
      secrets = await this.#list();
    } catch (e) {
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      return `pipegen couldn't read the secrets of ${repo}`;
    }
    const shadowing = new Set<string>();
    for (const s of secrets) {
      const rec = st.stored.get(s.name.toUpperCase());
      if (rec === undefined) return `the secret ${safeText(s.name, 80)} of ${repo} was not written by pipegen`;
      if (rec.kind === 'real') return `the secret ${safeText(s.name, 80)} of ${repo} holds a value you typed`;
      if (rec.updatedAt === null || s.updatedAt !== rec.updatedAt) return `the secret ${safeText(s.name, 80)} of ${repo} was changed outside pipegen`;
      shadowing.add(s.name.toUpperCase());
    }
    let org: { name: string }[];
    try {
      org = await this.#listOf('GET /repos/{owner}/{repo}/actions/organization-secrets', 'secrets');
    } catch (e) {
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      return `pipegen couldn't read the organisation secrets visible to ${repo}`;
    }
    for (const o of org) {
      const up = o.name.toUpperCase();
      const read = this.#readByWorkflows === null || this.#readByWorkflows.has(up);
      if (read && !shadowing.has(up)) return `the organisation secret ${safeText(o.name, 80)} reaches the proof's workflows in ${repo}`;
    }
    let vars: { name: string; value?: unknown }[];
    try {
      vars = await this.#listOf('GET /repos/{owner}/{repo}/actions/variables', 'variables');
    } catch (e) {
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      return `pipegen couldn't read the Actions variables of ${repo}`;
    }
    for (const v of vars) {
      if (!SCRATCH_VARIABLES.includes(v.name)) return `the Actions variable ${safeText(v.name, 80)} of ${repo} is not one pipegen declares`;
      if (typeof v.value !== 'string' || validDate(v.value) === undefined) return `the Actions variable ${safeText(v.name, 80)} of ${repo} doesn't hold its date`;
    }
    return null;
  }

  #name(n: unknown): string {
    const up = typeof n === 'string' ? n.toUpperCase() : '';
    if (!NAME_RE.test(up) || up.startsWith('GITHUB_')) throw new ScratchKeysError(`${safeText(String(n), 80)} is not a secret name pipegen stores.`);
    return up;
  }

  #placeholderEntries(names: readonly string[]): { name: string; kind: 'placeholder'; value: string }[] {
    return names.map((n) => {
      const up = this.#name(n);
      if (/^PIPEGEN_/.test(up)) throw new ScratchKeysError(`${up} is pipegen's own; it gets no placeholder.`);
      const value = placeholderValue(up);
      if (this.#vault.containsKnownValue(value)) throw new ScratchKeysError(`the placeholder for ${up} is a value you typed; pipegen won't store it.`);
      return { name: up, kind: 'placeholder' as const, value };
    });
  }

  async #throwawayEntry(): Promise<{ name: string; kind: 'throwaway'; value: string }> {
    const bytes = this.#random(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new ScratchKeysError('the throwaway key needs 32 random bytes.');
    const value = Buffer.from(bytes).toString('hex');
    const delivered = this.#vault.get(SCRATCH_FP_KEY);
    if (delivered !== undefined && delivered === value) throw new ScratchKeysError('the throwaway key came out equal to the delivered PIPEGEN_FP_KEY; not stored.');
    const st = await this.#state();
    if (st.ours.has(value)) throw new ScratchKeysError('the throwaway key is not fresh; not stored.');
    return { name: SCRATCH_FP_KEY, kind: 'throwaway', value };
  }

  async #store(entries: readonly Entry[]): Promise<void> {
    if (entries.length === 0) return;
    if (new Set(entries.map((e) => e.name)).size !== entries.length) throw new ScratchKeysError('two of the secret names are the same after upper-casing.');
    if (interrupting()) throw new ScratchGuardError('pipegen is stopping; no secret is stored.');
    const st = await this.#state();
    if (interrupting()) throw new ScratchGuardError('pipegen is stopping; no secret is stored.');
    const run = this.#storeBatch(st, entries);
    st.busy.set(run, { names: entries.map((e) => e.name), real: entries.some((e) => e.kind === 'real') });
    try {
      await run;
    } finally {
      st.busy.delete(run);
    }
  }

  async #storeBatch(st: KeyState, entries: readonly Entry[]): Promise<void> {
    // 2. the first store: what a crashed run left goes first
    if (!st.clean) await this.#deleteAll(st);
    // 3. the access check, right before the store; its branded result opens the sink (spent there)
    const access = await checkScratchAccess(this.#gh, this.#scratch.target, this.#io, { accepted: [...this.#accepted], clock: this.#clock });
    for (const a of access.accepted) this.#accepted.add(a);
    requireGuarded(access.scratch, 'scratch');
    if (access.scratch.fullName !== this.#scratch.fullName) throw new ScratchGuardError('the access check was for another repo.');
    const inner = scratchSecretSink(this.#gh, access, this.#clock);
    let cause: unknown;
    const landed = new Set<string>();
    const sink: SecretSink = {
      publicKey: () => inner.publicKey(),
      // 4. each PUT a tracked write; the guard's own error is kept (secrets.ts reports a name and a status only)
      put: (name, encrypted, keyId) => trackWrite(`secret ${name}`, () => inner.put(name, encrypted, keyId))
        .then((r) => { landed.add(name); return r; }, (e: unknown) => { cause = e; throw e; }),
    };
    const real = entries.filter((e) => e.kind === 'real');
    const ours = entries.filter((e): e is { name: string; kind: 'placeholder' | 'throwaway'; value: string } => e.kind !== 'real');
    try {
      if (real.length > 0) {
        // counted before it is sent: from here on, no ticket taken earlier gives evidence, nor any until a verified deleteAll
        st.realSeq++;
        st.realSinceClean = true;
        for (const e of real) st.stored.set(e.name, { kind: 'real', updatedAt: null });
        await storeSecretsVia(sink, this.#vault, real.map((e) => e.from));
      }
      if (ours.length > 0) {
        for (const e of ours) st.ours.add(e.value);
        st.version++;
        await storeRepoSecretsVia(sink, ours.map((e) => ({ name: e.name, value: e.value })));
      }
    } catch (e) {
      if (cause instanceof ScratchGuardError || isRateStop(cause)) throw cause;
      if (isTokenRejected(this.#gh, cause)) throw githubTokenRejected();
      throw e;
    } finally {
      // a placeholder over a real value counts as real until GitHub took it; then GitHub's updated_at is recorded
      for (const e of ours) if (landed.has(e.name)) st.stored.set(e.name, { kind: e.kind, updatedAt: null });
      if (landed.size > 0) await this.#recordStamps(st, landed);
    }
  }

  /** The updated_at GitHub lists for the names just written (E4-R1): a later change by anyone else shows as a different one. */
  async #recordStamps(st: KeyState, names: ReadonlySet<string>): Promise<void> {
    let listed: { name: string; updatedAt: string | null }[];
    try {
      listed = await this.#list();
    } catch {
      return;   // left unknown (null): no brand until a verified deleteAll
    }
    for (const n of names) {
      const rec = st.stored.get(n);
      const seen = listed.find((x) => x.name.toUpperCase() === n);
      if (rec !== undefined) rec.updatedAt = seen?.updatedAt ?? null;
    }
  }

  async #list(): Promise<{ name: string; updatedAt: string | null }[]> {
    try {
      const all = await this.#listOf('GET /repos/{owner}/{repo}/actions/secrets', 'secrets');
      return all.map((x) => ({ name: x.name, updatedAt: typeof x.updated_at === 'string' ? x.updated_at : null }));
    } catch (e) {
      if (isRateStop(e)) throw e;
      if (isTokenRejected(this.#gh, e)) throw githubTokenRejected();
      throw new ScratchKeysError(`pipegen couldn't read the list of secrets of ${this.#scratch.fullName}, so it can't confirm they are deleted. `
        + `Check ${this.#scratch.fullName} → Settings → Secrets and variables → Actions, and delete any secret there.`);
    }
  }

  /** One whole list (every page up to its total_count, no skip), each item with a plain name; throws when it can't be read. */
  async #listOf(route: string, key: 'secrets' | 'variables'): Promise<{ name: string; updated_at?: unknown; value?: unknown }[]> {
    const items: { name: string; updated_at?: unknown; value?: unknown }[] = [];
    const bad = () => new ScratchKeysError(`the list ${route} could not be read`);
    for (let page = 1; ; page++) {
      if (page > SECRET_LIST_PAGES) throw bad();
      const d = (await githubRead(this.#gh, route, { owner: this.#scratch.owner, repo: this.#scratch.repo, per_page: 100, page }, this.#clock)).data as Record<string, unknown> | null;
      const list = d?.[key];
      if (typeof d?.total_count !== 'number' || !Number.isSafeInteger(d.total_count) || d.total_count < 0 || !Array.isArray(list)) throw bad();
      for (const x of list as unknown[]) {
        const n = (x as { name?: unknown } | null)?.name;
        if (typeof n !== 'string' || !/^[A-Za-z0-9_]{1,200}$/.test(n)) throw bad();
        items.push({ ...(x as object), name: n });
      }
      if (items.length >= d.total_count) break;
      if (list.length === 0) throw bad();
    }
    return items;
  }
}

const isTokenRejected = (gh: Octokit, e: unknown): boolean => (e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh);

/**
 * E2's secret-store seam (pushProofSetup's `storeSecrets`): the real ScratchKeys store, wired. It runs after the no-run
 * check and before the proof branch push (E2's order); `placeholderNames` are the secrets the proof's workflows read.
 */
export function scratchSecretStore(keys: ScratchKeys, placeholderNames: readonly string[]): SecretStoreStep {
  if (!(keys instanceof ScratchKeys)) throw new ScratchGuardError('the secret store takes a ScratchKeys.');
  return async (scratch) => {
    requireGuarded(scratch, 'scratch');
    if (scratch.target !== keys.scratch.target || scratch.fullName !== keys.scratch.fullName) throw new ScratchGuardError('the secret store was made for another scratch repo.');
    await keys.setup(placeholderNames);
  };
}
