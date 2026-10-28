// The consent token and the counting summary (Plan U Task 4b; review M1, M2, M11). They live here, not in src/cli/, so
// the audit model can require them without depending on the CLI; the CLI's consent screen (src/cli/consent.ts) makes them.
//
// - CountingSummary: what a COUNTING-ONLY bundle (bundleCode without the secret scan) holds, for the `audit --ai` consent
//   screen (ruling S21: the secret scanner is downloaded and run only after consent). It keeps the folder it was counted in (its
//   real path) and the exact file list; the AI step reads only those files (bundleCode `onlyPaths`, review I1), and
//   covers() is the backstop. It binds paths, not content: a file can change between the count and the send (a local
//   writer, a `git pull` while the question waits); the AI cost cap still holds then, since the meter prices what is
//   really sent (review M3, accepted residual).
// - ConsentToken: the user said yes to a consent screen. askConsent() is the only maker: the minter is claimed once, by
//   the consent module (claimTokenMinter), and a second claim throws. addAiSuggestions requires a token, checks its terms
//   (provider, model, Ollama host, cap, folder) and spends it: a token is good for one AI step only.
// Runtime forgery: `private constructor` is TypeScript only, so `new (X as any)()` or a subclass would make an object
// with the private brand. Each class therefore also keeps a module-private WeakSet of the objects it really issued, and
// isSummary()/isToken() check it (the same idea as redact.ts's CHECKED bundles).
import { bundleTopFolders, countedBundleRoot, type BundleSummary, type CodeBundle } from '../ai/redact.js';
import type { PricedFor } from '../estimate/estimate.js';

export type ConsentMode = 'full' | 'audit-ai';

// ---------- the counting summary ----------

const ISSUED_SUMMARIES = new WeakSet<object>();
let makeCounting: (bundle: CodeBundle, dir: string) => CountingSummary;

/**
 * The consent facts of a counting-only bundle: an upper bound of what `audit --ai` sends (the secret scan only hides
 * values and leaves files out). Only countingSummary() makes one.
 */
export class CountingSummary {
  readonly #paths: ReadonlySet<string>;

  private constructor(readonly files: number, readonly bytes: number, readonly topFolders: readonly string[], readonly dir: string, paths: ReadonlySet<string>) {
    this.#paths = paths;
    Object.freeze(this);
  }

  /** True only for an object countingSummary() made. */
  static isSummary(x: unknown): x is CountingSummary {
    return typeof x === 'object' && x !== null && #paths in x && ISSUED_SUMMARIES.has(x);
  }

  /** True when every file of `bundle` is one of the files counted here (the user agreed to send at most these). */
  covers(bundle: CodeBundle): boolean {
    return bundle.files.every((f) => this.#paths.has(f.path));
  }

  /** The counted repo paths (a copy): bundleCode's `onlyPaths` for the secret-scanned bundle. */
  paths(): Set<string> {
    return new Set(this.#paths);
  }

  static {
    makeCounting = (bundle, dir) => {
      const made = new CountingSummary(bundle.files.length, bundle.bytes, Object.freeze(bundleTopFolders(bundle)), dir, new Set(bundle.files.map((f) => f.path)));
      ISSUED_SUMMARIES.add(made);
      return made;
    };
  }
}

/** The consent facts of bundleCode's own counting-only bundle; anything else (a checked bundle, a copy) is refused. */
export function countingSummary(bundle: CodeBundle): CountingSummary {
  const dir = countedBundleRoot(bundle);
  if (dir === null || bundle.secretScanChecked !== false) {
    throw new Error('countingSummary needs bundleCode\'s own counting-only bundle (built without the secret scan).');
  }
  return makeCounting(bundle, dir);
}

// ---------- the consent token ----------

/** What a yes agrees to. */
export interface ConsentTerms {
  readonly mode: ConsentMode;
  readonly pricedFor: PricedFor;
  /** The hard AI cost cap the screen showed (null: none, a local model). */
  readonly capUsd: number | null;
  /** The file facts the screen showed, this exact object: the checked bundle's summary, or ('audit-ai') the counted one's. */
  readonly files: BundleSummary | CountingSummary;
  /** The real path of the folder the counted files are in (a CountingSummary's dir); null for a checked summary. */
  readonly dir: string | null;
}

const ISSUED_TOKENS = new WeakSet<object>();
const SPENT_TOKENS = new WeakSet<object>();
let mintToken: ((terms: ConsentTerms) => ConsentToken) | null = null;

/** The user's yes to a consent screen. Only the consent module's askConsent() makes one (see claimTokenMinter). */
export class ConsentToken {
  readonly #granted = true;
  private constructor(readonly terms: ConsentTerms) {
    Object.freeze(this);
  }
  /** True only for a token askConsent() made (not one made with `new` through a cast, nor a subclass's). */
  static isToken(x: unknown): x is ConsentToken {
    return typeof x === 'object' && x !== null && #granted in x && ISSUED_TOKENS.has(x);
  }
  static {
    mintToken = (terms) => {
      const made = new ConsentToken(Object.freeze({ ...terms }));
      ISSUED_TOKENS.add(made);
      return made;
    };
  }
}

/**
 * The token minter, handed out ONCE: src/cli/consent.ts claims it when it loads, so askConsent is the only code that can
 * make a token. Any later claim throws (a second claimer is a bug, and loud).
 */
export function claimTokenMinter(): (terms: ConsentTerms) => ConsentToken {
  const m = mintToken;
  if (m === null) throw new Error('The consent token minter was already claimed by the consent module.');
  mintToken = null;
  return m;
}

/** True when `token` was already used for an AI step. */
export function isSpent(token: ConsentToken): boolean {
  return SPENT_TOKENS.has(token);
}

/** Marks `token` used: the next AI step needs a new yes (review M2). */
export function spend(token: ConsentToken): void {
  SPENT_TOKENS.add(token);
}
