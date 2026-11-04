// The AI spend meter: the one hard cap on AI cost (Plan U ruling U13; moved here from src/audit/model.ts by Plan E ruling B4,
// so the audit's AI step and the whole proof run share it). One meter covers a whole run: the CLI wraps the provider once
// (meteredProvider), and every call (needs, debate, creators, fix loop, completeValidated's retries) goes through it.
// - Before an attempt is sent, its worst case is reserved (requestCeilingUsd: every byte a token, the full output limit,
//   the highest price it could bill at, the refusal fallback's second run included). An attempt that doesn't fit
//   (spent + reserved + its worst case > cap) is refused with AiError('cost-cap') and never sent. A request without
//   maxOutputTokens has no bound, so under a cap it is always refused.
// - After the attempt, the reservation is swapped for its usage at the same ceiling prices (usageCeilingUsd); an error
//   without usage (a timeout, a dropped connection) keeps the whole reservation, since the provider may still bill it.
// - The REPORTED cost (attempts, costUsd) is the list price, each model run at its own model's price when the provider
//   names them (AiUsage.attempts, Plan E S22: the refusal fallback's run). The cap never uses it.
// - restore(spentUsd): a resumed run starts from what the saved state says was used (Plan E Task 6).
import type { AiProvider, AiRequest, AiTokenCounts, AiUsage, AiUsageAttempt } from '../types.js';
import { aiRequestBytes, requestCeilingUsd, usageCeilingUsd, usageCostUsd } from '../estimate/estimate.js';
import { AiError, COST_CAP_MESSAGE, count, outputLimit } from './errors.js';

/** One model run inside an attempt (AiUsage.attempts) with its own list cost. */
export interface AiModelRun extends AiUsageAttempt { listUsd: number }

/** One settled AI attempt and its list cost. */
export interface AiAttempt {
  model: string;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  /** The attempt's list cost: the sum of `runs` when the provider named them, else its counts at `model`'s price. */
  listUsd: number;
  /** Each model run the attempt billed (Claude's usage.iterations: the refusal fallback's run at its own model), when known. */
  runs?: AiModelRun[];
}

/** The most model runs one attempt's report lists (a longer list is reported as one run at the provider's model). */
export const MAX_RUNS_PER_ATTEMPT = 16;

const validCap = (c: unknown): boolean => c === null || (typeof c === 'number' && Number.isFinite(c) && c >= 0);

/**
 * The spend meter. capUsd null: nothing is refused for a local model (Ollama); for a paid provider null counts as 0, so
 * everything is refused (review H1). Any other cap must be a finite number ≥ 0 (an Infinity cap would be no cap at all).
 */
export class AiSpendMeter {
  /** USD settled so far (usage priced at the ceiling rates, the reservations of attempts that ended without usage, and what restore() added). */
  spentUsd = 0;
  /** USD reserved for attempts in flight. */
  reservedUsd = 0;
  /** USD restore() added from a saved state (already in spentUsd; not in attempts or costUsd). */
  restoredUsd = 0;
  /** Every attempt's usage, summed (failed attempts that reported usage included). */
  readonly usage: AiTokenCounts = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
  /** Each settled attempt with its own list cost (tier by its own prompt length); costUsd is their sum. */
  readonly attempts: AiAttempt[] = [];
  /** The cap in force: capUsd, except that null means 0 for a paid provider. null only for Ollama (no cap). */
  readonly effectiveCapUsd: number | null;
  /** The metered provider: the same name and model, every call metered (no other field is copied). */
  readonly provider: AiProvider;
  readonly #inner: AiProvider;
  #refused = false;
  constructor(inner: AiProvider, readonly capUsd: number | null) {
    if (!validCap(capUsd)) throw new Error('The AI cost cap must be a finite number of US dollars (0 or more), or null for a local model.');
    this.#inner = inner;
    this.effectiveCapUsd = capUsd === null && inner.name !== 'ollama' ? 0 : capUsd;
    this.provider = { name: inner.name, model: inner.model, complete: (req) => this.#complete(req) };
  }

  /** What counts against the cap now: settled plus reserved (USD). This is what a saved state keeps (resume restores it). */
  get usedUsd(): number {
    return this.spentUsd + this.reservedUsd;
  }

  /** True when the cap is reached: spent + reserved ≥ cap (never for no cap). No attempt fits then. */
  get exceeded(): boolean {
    const cap = this.effectiveCapUsd;
    return cap !== null && this.spentUsd + this.reservedUsd >= cap;
  }

  /**
   * Sticky (review I2): true once the meter refused a request (AiError('cost-cap')), whatever the caller did with the
   * error. After a refusal `exceeded` is usually still false (the next worst case didn't fit, the spend is below the cap),
   * so the proof's stop (capReached) reads this, not the error a caller may have turned into a note.
   */
  get refused(): boolean {
    return this.#refused;
  }

  #refuse(): never {
    this.#refused = true;
    throw new AiError('cost-cap', COST_CAP_MESSAGE);
  }

  /** Resume: adds what the saved state says the run already used. Anything but a number ≥ 0 is refused (thrown). */
  restore(spentUsd: number): void {
    if (typeof spentUsd !== 'number' || !(spentUsd >= 0)) throw new Error('The AI cost restored from the saved state must be a number of US dollars, 0 or more.');
    this.spentUsd += spentUsd;
    this.restoredUsd += spentUsd;
  }

  /** True when `ai` is the provider this meter wraps (or its metered provider). */
  wraps(ai: AiProvider): boolean {
    return ai === this.#inner || ai === this.provider;
  }

  /** Total list cost of the attempts (USD). */
  get costUsd(): number {
    return this.attempts.reduce((sum, a) => sum + a.listUsd, 0);
  }

  async #complete(req: AiRequest): Promise<{ data: unknown; usage: AiUsage }> {
    let reserved = 0;
    const cap = this.effectiveCapUsd;
    if (cap !== null) {
      // one validator for the output limit (review N3): anything set but not a whole number above 0 is refused here
      const limit = outputLimit(req.maxOutputTokens);
      const worst = requestCeilingUsd(this.#inner, aiRequestBytes(req), limit ?? Number.POSITIVE_INFINITY);
      if (worst !== 'local') {
        // B4: no output limit means no bound, so the attempt can't fit any cap
        if (limit === undefined) this.#refuse();
        if (!(this.spentUsd + this.reservedUsd + worst <= cap)) this.#refuse();
        reserved = worst;
        this.reservedUsd += worst;
      }
    }
    let r: { data: unknown; usage: AiUsage };
    try {
      r = await this.#inner.complete(req);
    } catch (e) {
      if (e instanceof AiError && e.usage !== undefined) this.#settle(reserved, e.usage);
      else this.#keep(reserved);
      throw e;
    }
    this.#settle(reserved, r.usage);
    return r;
  }

  #settle(reserved: number, u: AiUsage | undefined): void {
    // The cost is spent BEFORE the reservation is released, and only then is the usage recorded for the report (review
    // M5): a failure while recording can never release a reservation without spending.
    // An answer that reports no prompt tokens can't be priced: keep the full reservation (review N5).
    if (u === undefined || u === null || count(u.inputTokens) + count(u.cacheReadTokens) + count(u.cacheWriteTokens) === 0) {
      this.#keep(reserved);
      if (u !== undefined && u !== null) this.#addUsage(u);
      return;
    }
    const c = usageCeilingUsd(this.#inner, u);
    if (c !== 'local') this.spentUsd += c;
    this.reservedUsd -= reserved;
    this.#addUsage(u);
  }

  #addUsage(u: AiUsage): void {
    const runs = this.#runsOf(u);
    const listUsd = runs !== null ? runs.reduce((sum, x) => sum + x.listUsd, 0) : listCost(this.#inner.name, this.#inner.model, u);
    this.attempts.push({
      model: this.#inner.model, input: count(u.inputTokens), output: count(u.outputTokens),
      cacheRead: count(u.cacheReadTokens), cacheWrite: count(u.cacheWriteTokens), listUsd, ...(runs === null ? {} : { runs }),
    });
    this.usage.inputTokens += count(u.inputTokens);
    this.usage.outputTokens += count(u.outputTokens);
    this.usage.cacheReadTokens += count(u.cacheReadTokens);
    this.usage.cacheWriteTokens += count(u.cacheWriteTokens);
  }

  /** S22: each model run of the attempt at its own model's list price, or null when the provider named none (or too many). */
  #runsOf(u: AiUsage): AiModelRun[] | null {
    const list: unknown = u.attempts;
    if (!Array.isArray(list) || list.length === 0 || list.length > MAX_RUNS_PER_ATTEMPT) return null;
    return list.map((a: Partial<AiUsageAttempt> | null) => {
      const model = typeof a?.model === 'string' && a.model !== '' ? a.model : this.#inner.model;
      const run = { model, input: count(a?.input), output: count(a?.output), cacheRead: count(a?.cacheRead), cacheWrite: count(a?.cacheWrite) };
      const tokens: AiUsage = { inputTokens: run.input, outputTokens: run.output, cacheReadTokens: run.cacheRead, cacheWriteTokens: run.cacheWrite };
      return { ...run, listUsd: listCost(this.#inner.name, model, tokens) };
    });
  }

  #keep(reserved: number): void {
    this.spentUsd += reserved;
    this.reservedUsd -= reserved;
  }
}

/** The list price of `u` at `model` (0 for a local model). */
function listCost(name: string, model: string, u: AiUsage): number {
  const c = usageCostUsd({ name, model }, u);
  return c === 'local' ? 0 : c;
}

/**
 * The provider every AI call of a run goes through (Plan E Task 6, ruling B4): `meter.provider`. `ai` must be the
 * provider the meter wraps (anything else would be an unmetered side door, so it is refused, thrown).
 */
export function meteredProvider(ai: AiProvider, meter: AiSpendMeter): AiProvider {
  if (!(meter instanceof AiSpendMeter) || !meter.wraps(ai)) throw new Error('meteredProvider needs the spend meter made for this AI provider.');
  return meter.provider;
}

/** True for the meter's refusal: AiError('cost-cap'). */
export const isCostCap = (e: unknown): e is AiError => e instanceof AiError && e.kind === 'cost-cap';
