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
// The excerpt evidence (ruling E0a-R5, DECISIONS #113): errorExcerpt (excerpt.ts) builds a log excerpt for the AI only with
// evidence that the run the log comes from held no value the user typed. ScratchKeys alone mints it, as an unforgeable brand
// (a frozen object in a module-private WeakSet), through a ticket that brackets the run:
//   const t = keys.ticket();          // BEFORE the push (or re-run) that starts the run
//   ... the run starts and finishes ...
//   const ev = keys.evidence(t);      // AFTER the run's outcome is complete: the brand, or null
// The ticket is good only when, at the ticket, the scratch repo was known clean (a deleteAll listed it empty) and held only
// placeholders and throwaway keys, with no store in flight; evidence() also needs that no real value was stored, or began
// to be stored, since the ticket. A run that held any user-typed value never gets the brand. Recorded residuals: secrets
// someone with admin rights adds to the scratch repo by hand, and organisation secrets shared with it, are not pipegen's
// to see (the excerpt's redact, scrub and secret scan stay as defence in depth).
import { randomBytes } from 'node:crypto';
import type { Octokit } from '@octokit/rest';
import { knownValueScrubber } from '../ai/redact.js';
import type { CliIO } from '../cli/io.js';
import { SecretVault, storeRepoSecretsVia, storeSecretsVia, type SecretSink } from '../create/secrets.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import { interrupting } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { trackWrite } from './inflight.js';
import { checkScratchAccess } from './repos.js';
import type { SecretStoreStep } from './snapshot.js';
import {
  assertScratch, deleteScratchSecret, githubRead, isProofTarget, requireGuarded, scratchSecretSink, ScratchGuardError,
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

/** An opaque ticket (see the file comment). */
export interface RunTicket { readonly ticket: true }
interface TicketRec { keys: ScratchKeys; seq: number; ok: boolean }
const tickets = new WeakMap<object, TicketRec>();

/** The placeholder value of a secret name (not secret; safe if it leaks). */
export const placeholderValue = (name: string): string => `${PLACEHOLDER_PREFIX}${name.toUpperCase()}`;

export interface ScratchKeysDeps {
  io: ProofIO;
  /** checkScratchAccess answers already given in this run (E1's ScratchAccess.accepted). */
  accepted?: readonly string[];
  clock?: RateClock;
  /** For tests: the random source of the throwaway key. */
  random?: (n: number) => Uint8Array;
}

export class ScratchKeys {
  readonly #gh: Octokit;
  readonly #scratch: GuardedRepo;
  readonly #vault: SecretVault;
  readonly #io: ProofIO;
  readonly #clock: RateClock;
  readonly #random: (n: number) => Uint8Array;
  readonly #accepted = new Set<string>();
  /** Upper-case name → what it holds. A real store is counted before it is sent. */
  readonly #stored = new Map<string, Kind>();
  /** A deleteAll listed the scratch repo empty, and no delete failed since. */
  #clean = false;
  /** Counts real stores begun: a ticket is good only while it doesn't change. */
  #realSeq = 0;
  /** Store batches in flight. */
  readonly #busy = new Set<Promise<unknown>>();
  /** Every placeholder and throwaway value stored (for the excerpt scrubber, B1). */
  readonly #ours = new Set<string>();
  #scrub: ((text: string) => string) | null = null;

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
  }

  /** The scratch repo these keys go to. */
  get scratch(): GuardedRepo { return this.#scratch; }
  /** 'real' once any real value is (or may be) stored; 'placeholder' with only placeholders or throwaway keys; else 'none'. */
  get mode(): 'none' | 'placeholder' | 'real' {
    const kinds = [...this.#stored.values()];
    return kinds.includes('real') ? 'real' : kinds.length > 0 ? 'placeholder' : 'none';
  }
  /** Every checkScratchAccess answer given so far (pass it on to the next ScratchKeys or check). */
  get accepted(): string[] { return [...this.#accepted]; }
  /** The upper-case names stored, each with its kind (no value). */
  stored(): Record<string, Kind> { return Object.fromEntries(this.#stored); }

  /** Stores `pipegen-placeholder-<NAME>` for each name (never a vault value). */
  async placeholders(names: readonly string[]): Promise<void> {
    await this.#store(this.#placeholderEntries(names));
  }

  /** Stores a fresh random PIPEGEN_FP_KEY, for the scratch repo only: never the delivered key the vault holds. */
  async throwaway(): Promise<void> {
    await this.#store([this.#throwawayEntry()]);
  }

  /** E2's first store (pushProofSetup's seam): the placeholders and the throwaway key in one batch, so one access check. */
  async setup(names: readonly string[]): Promise<void> {
    await this.#store([...this.#placeholderEntries(names), this.#throwawayEntry()]);
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
   * store and in E8's cleanup (also while a stop is under way). Waits for this instance's stores in flight first. Returns
   * the names deleted; throws ScratchKeysError naming the leftovers when the list can't be read or a secret stays.
   */
  async deleteAll(): Promise<string[]> {
    await Promise.allSettled([...this.#busy]);
    return this.#deleteAll();
  }

  async #deleteAll(): Promise<string[]> {
    this.#clean = false;
    const first = await this.#list();
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
    const left = await this.#list();
    const leftovers = [...new Set([...failed, ...left])];
    if (leftovers.length > 0) {
      // a leftover's value is unknown to pipegen: it counts as real (no evidence while it is there)
      for (const n of leftovers) this.#stored.set(n, 'real');
      throw new ScratchKeysError(`pipegen couldn't delete every secret of ${this.#scratch.fullName}: ${leftovers.map((n) => safeText(n, 80)).join(', ')} `
        + `${leftovers.length === 1 ? 'is' : 'are'} still there. Delete ${leftovers.length === 1 ? 'it' : 'them'} in ${this.#scratch.fullName} → Settings → Secrets and variables → Actions.`, leftovers);
    }
    this.#stored.clear();
    this.#clean = true;
    return deleted;
  }

  /**
   * The composed scrubber's second half (ruling B1, S14): every placeholder and throwaway value this instance stored. The
   * caller composes it after vault.scrubber().
   */
  scrubber(): (text: string) => string {
    this.#scrub ??= knownValueScrubber([...this.#ours]);
    return this.#scrub;
  }

  /** Take BEFORE the push or re-run that starts a run (see the file comment). */
  ticket(): RunTicket {
    const t = Object.freeze({ ticket: true as const });
    tickets.set(t, { keys: this, seq: this.#realSeq, ok: this.#placeholdersOnly() });
    return t;
  }

  /**
   * The excerpt evidence for the run `ticket` brackets, taken AFTER the run finished: the brand when the scratch repo held
   * only placeholders and throwaway keys for the whole window, else null (DECISIONS #113).
   */
  evidence(ticket: RunTicket): ExcerptEvidence | null {
    const rec = typeof ticket === 'object' && ticket !== null ? tickets.get(ticket) : undefined;
    if (rec === undefined || rec.keys !== this || !rec.ok || rec.seq !== this.#realSeq || !this.#placeholdersOnly()) return null;
    const e = Object.freeze(Object.create(null) as object) as ExcerptEvidence;
    minted.add(e);
    return e;
  }

  // ---------- inside ----------

  #placeholdersOnly(): boolean {
    return this.#clean && this.#busy.size === 0 && ![...this.#stored.values()].includes('real');
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

  #throwawayEntry(): { name: string; kind: 'throwaway'; value: string } {
    const bytes = this.#random(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new ScratchKeysError('the throwaway key needs 32 random bytes.');
    const value = Buffer.from(bytes).toString('hex');
    const delivered = this.#vault.get(SCRATCH_FP_KEY);
    if (delivered !== undefined && delivered === value) throw new ScratchKeysError('the throwaway key came out equal to the delivered PIPEGEN_FP_KEY; not stored.');
    if (this.#ours.has(value)) throw new ScratchKeysError('the throwaway key is not fresh; not stored.');
    return { name: SCRATCH_FP_KEY, kind: 'throwaway', value };
  }

  async #store(entries: readonly ({ name: string; kind: 'placeholder' | 'throwaway'; value: string } | { name: string; kind: 'real'; from: string })[]): Promise<void> {
    if (entries.length === 0) return;
    if (new Set(entries.map((e) => e.name)).size !== entries.length) throw new ScratchKeysError('two of the secret names are the same after upper-casing.');
    if (interrupting()) throw new ScratchGuardError('pipegen is stopping; no secret is stored.');
    const run = this.#storeBatch(entries);
    this.#busy.add(run);
    try {
      await run;
    } finally {
      this.#busy.delete(run);
    }
  }

  async #storeBatch(entries: readonly ({ name: string; kind: 'placeholder' | 'throwaway'; value: string } | { name: string; kind: 'real'; from: string })[]): Promise<void> {
    // 2. the first store: what a crashed run left goes first
    if (!this.#clean) await this.#deleteAll();
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
        // counted before it is sent: from here on, no ticket taken earlier gives evidence
        this.#realSeq++;
        for (const e of real) this.#stored.set(e.name, 'real');
        await storeSecretsVia(sink, this.#vault, real.map((e) => e.from));
      }
      if (ours.length > 0) {
        for (const e of ours) this.#ours.add(e.value);
        this.#scrub = null;
        await storeRepoSecretsVia(sink, ours.map((e) => ({ name: e.name, value: e.value })));
      }
    } catch (e) {
      if (cause instanceof ScratchGuardError || isRateStop(cause)) throw cause;
      if ((cause as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(this.#gh)) throw githubTokenRejected();
      throw e;
    } finally {
      // a placeholder over a real value counts as real until GitHub took it
      for (const e of ours) if (landed.has(e.name)) this.#stored.set(e.name, e.kind);
    }
  }

  async #list(): Promise<string[]> {
    const names: string[] = [];
    const unreadable = () => new ScratchKeysError(`pipegen couldn't read the list of secrets of ${this.#scratch.fullName}, so it can't confirm they are deleted. `
      + `Check ${this.#scratch.fullName} → Settings → Secrets and variables → Actions, and delete any secret there.`);
    for (let page = 1; ; page++) {
      if (page > SECRET_LIST_PAGES) throw unreadable();
      let d: { total_count?: unknown; secrets?: unknown } | null;
      try {
        d = (await githubRead(this.#gh, 'GET /repos/{owner}/{repo}/actions/secrets', { owner: this.#scratch.owner, repo: this.#scratch.repo, per_page: 100, page }, this.#clock)).data as typeof d;
      } catch (e) {
        if (isRateStop(e)) throw e;
        if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(this.#gh)) throw githubTokenRejected();
        throw unreadable();
      }
      if (typeof d?.total_count !== 'number' || !Number.isSafeInteger(d.total_count) || d.total_count < 0 || !Array.isArray(d.secrets)) throw unreadable();
      for (const s of d.secrets as unknown[]) {
        const n = (s as { name?: unknown } | null)?.name;
        if (typeof n !== 'string' || !/^[A-Za-z0-9_]{1,200}$/.test(n)) throw unreadable();
        names.push(n);
      }
      if (names.length >= d.total_count) break;
      if (d.secrets.length === 0) throw unreadable();
    }
    return [...new Set(names)];
  }
}

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
