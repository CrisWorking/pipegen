// Plan E Task 6 / E6 (rulings B4, S12; threats T16, T39): the proof's two hard caps, both 2× the estimate the consent
// screen showed (plan Global Constraints), and what happens when one is reached.
// - proofAiMeter(ai, est, consent): the run's one AI spend meter. Its cap is Estimates.aiCostCapUsd, and it must be the cap
//   the user said yes to (the consent token's capUsd), for this provider and model; anything else refuses to start
//   (thrown, nothing sent). One meter per consent: a second meter on the same yes would double the agreed cap.
// - capReached({ minutes, ai, error }): which cap, if any, stops the proof now. The AI cap is reached when the meter
//   refuses a call (AiError('cost-cap'), before anything is sent) or `exceeded`; the minutes cap when the minutes meter is
//   `exceeded` or `blind` (its minutes couldn't be read, fail closed).
// - stopAtCap(cap, steps): cancels the running runs, saves the state, and runs the cleanup even when the cancel or the
//   save failed; then throws CapReachedError (a ProofStopError) whose message is the explanation. The state file and the
//   full cleanup are E8's; they are injected here.
// - cancelActiveRuns(gh, t, since): the scratch repo's runs still going (any run since the proof started, not only the
//   ones pipegen tracks) cancelled through cancelRuns (guardedWrite; force-cancel after 30 s).
import type { Octokit } from '@octokit/rest';
import { ollamaHostOf } from '../ai/ollama.js';
import { AiSpendMeter, isCostCap } from '../ai/spend-meter.js';
import { ConsentToken } from '../audit/consent-token.js';
import type { RateClock } from '../engine/github-rate.js';
import type { Estimates } from '../estimate/estimate.js';
import { clockOf } from '../github/client.js';
import type { AiProvider } from '../types.js';
import { num, usd } from '../util/format.js';
import { listScratchRuns, type MinutesMeter } from './minutes.js';
import { cancelRuns, type PollClock } from './run.js';
import { assertScratch, isProofTarget, ProofStopError, ScratchGuardError, type ProofTarget } from './target.js';

/** The cap that stops the proof. `unread`: the minutes couldn't be read (the minutes meter is blind). */
export type CapReached = { kind: 'ai-cost'; limitUsd: number } | { kind: 'actions-minutes'; limit: number; unread?: true; scratch?: string };

/** The explanation the user sees (the plan's wording). */
export function capMessage(cap: CapReached): string {
  if (cap.kind === 'ai-cost') return `AI cost reached the limit of ${usd(cap.limitUsd)}, 2 × the estimate`;
  if (cap.unread === true) return `pipegen stopped before the Actions minutes limit of ${num(cap.limit)}: it couldn't read the minutes used in ${cap.scratch ?? 'the scratch repo'}`;
  return `Actions minutes reached the limit of ${num(cap.limit)}`;
}

/** The proof stopped at a cap. `problems`: what didn't work on the way out (fixed texts); `causes`: the errors behind them. */
export class CapReachedError extends ProofStopError {
  constructor(readonly cap: CapReached, readonly problems: readonly string[], readonly causes: readonly unknown[]) {
    super(capMessage(cap));
    this.name = 'CapReachedError';
  }
}

const METERED = new WeakSet<object>();

/**
 * The proof run's AI spend meter (B4): cap = est.aiCostCapUsd, which must equal the consent token's capUsd, given by
 * askConsent for the full run ('full') with this provider, model (and Ollama host). Anything else is thrown before any
 * AI call. A consent gives one meter only.
 */
export function proofAiMeter(ai: AiProvider, est: Estimates, consent: ConsentToken): AiSpendMeter {
  const c: unknown = consent;
  if (!ConsentToken.isToken(c) || c.terms.mode !== 'full') {
    throw new Error('The proof needs the consent token askConsent() gives for the full run; nothing was sent.');
  }
  const t = c.terms;
  if (t.capUsd !== est.aiCostCapUsd) {
    throw new Error('The AI cost cap differs from the one the user agreed to on the consent screen; the proof does not start.');
  }
  const host = ai.name === 'ollama' ? ollamaHostOf(ai) ?? undefined : undefined;
  const same = (p: { provider: string; model: string; host?: string } | null) => p !== null && p.provider === ai.name && p.model === ai.model && p.host === host;
  if (!same(t.pricedFor) || !same(est.pricedFor)) {
    throw new Error('The AI provider or model differs from the one the user agreed to on the consent screen; the proof does not start.');
  }
  if (METERED.has(c)) throw new Error('This consent already has its AI spend meter; one yes covers one meter. Nothing was sent.');
  METERED.add(c);
  return new AiSpendMeter(ai, est.aiCostCapUsd);
}

/** Which cap stops the proof now, or null. `error`: an error an AI call threw (the meter's cost-cap refusal). */
export function capReached(m: { minutes: MinutesMeter; ai: AiSpendMeter; error?: unknown }): CapReached | null {
  const aiCap = m.ai.effectiveCapUsd;
  if (aiCap !== null && (isCostCap(m.error) || m.ai.exceeded)) return { kind: 'ai-cost', limitUsd: aiCap };
  if (m.minutes.exceeded) return { kind: 'actions-minutes', limit: m.minutes.cap };
  if (m.minutes.blind) return { kind: 'actions-minutes', limit: m.minutes.cap, unread: true, ...(m.minutes.scratch === null ? {} : { scratch: m.minutes.scratch }) };
  return null;
}

export interface CapStopSteps {
  /** Cancels the runs still going (cancelActiveRuns, bound to the proof's gh, target and start). */
  cancelRuns: () => Promise<unknown>;
  /** Saves the proof state (E8), with the cap that stopped it. */
  saveState: (cap: CapReached) => unknown;
  /** The cleanup after the proof (E8): it runs whatever happened before it. */
  cleanup: () => unknown;
}

/**
 * On either cap (plan Global Constraints): (a) cancel the running runs, (b) save the state, (c) the cleanup, which runs
 * even when (a) or (b) threw; then (d) throws CapReachedError with the explanation. A step that failed is named in
 * `problems` (its error in `causes`); it never hides the stop.
 */
export async function stopAtCap(cap: CapReached, steps: CapStopSteps): Promise<never> {
  const problems: string[] = [];
  const causes: unknown[] = [];
  const step = async (run: () => unknown, problem: string): Promise<void> => {
    try {
      await run();
    } catch (e) {
      problems.push(problem);
      causes.push(e);
    }
  };
  await step(steps.cancelRuns, 'the running runs could not all be cancelled');
  await step(() => steps.saveState(cap), 'the state could not be saved');
  await step(steps.cleanup, 'the cleanup did not finish');
  throw new CapReachedError(cap, problems, causes);
}

/**
 * Cancels every run of the scratch repo created since `since` that is still going (S12: not only the runs pipegen holds
 * handles for), through cancelRuns (guardedWrite; force-cancel after 30 s). Throws when the list can't be read, or when a
 * run couldn't be stopped (each one also goes to `leftover`), so stopAtCap names the problem.
 */
export async function cancelActiveRuns(gh: Octokit, t: ProofTarget, since: number, opts: { clock?: PollClock; rateClock?: RateClock; leftover?: (item: string) => void } = {}): Promise<number[]> {
  if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
  const s = assertScratch(t, { owner: t.owner, repo: t.appRepo });
  const rate = opts.rateClock ?? clockOf(gh);
  let active: number[];
  try {
    active = (await listScratchRuns(gh, s, since, rate)).filter((r) => r.status !== 'completed').map((r) => r.id);
  } catch (e) {
    opts.leftover?.(`the runs of ${s.fullName} could not be listed after the stop; cancel any still running there`);
    throw e;
  }
  const out = await cancelRuns(gh, t, active, { ...opts, rateClock: rate });
  const failed = [...out].filter(([, why]) => why !== null);
  if (failed.length > 0) throw new ProofStopError(`${failed.length} run(s) of ${s.fullName} could not be cancelled; cancel them there.`);
  return active;
}
