// Shared by the provider adapters and provider.ts (kept apart so the adapters and provider.ts don't import each other).
// Error messages here and in the adapters are pipegen's own fixed text: never an API response body, an SDK error
// message or the AI's words, so neither a key echoed by a server nor hostile AI text can end up in one.
import type { AiUsage } from '../types.js';

/** `cost-cap`: pipegen itself refused to send the request, since it could take the spend past the agreed AI cost cap. */
export type AiErrorKind = 'timeout' | 'invalid' | 'http' | 'missing' | 'refusal' | 'truncated' | 'cost-cap';

/** The message of an AiError('cost-cap'). */
export const COST_CAP_MESSAGE = 'Stopped before the AI cost limit you agreed to.';

export class AiError extends Error {
  kind: AiErrorKind;
  /** Set when the provider answered (the call was billed): invalid, refusal, truncated. */
  usage?: AiUsage;

  constructor(kind: AiErrorKind, message: string, usage?: AiUsage) {
    super(message);
    this.name = 'AiError';
    this.kind = kind;
    if (usage) this.usage = usage;
  }
}

/** A token count from a provider answer: a finite number >= 0, else 0 (a missing or odd field never breaks the meter). */
export function count(n: unknown): number {
  return typeof n === 'number' && Number.isFinite(n) && n >= 0 ? n : 0;
}

/**
 * Runs `run` with an AbortSignal that fires after `ms`. If it fires, the call ends in AiError('timeout'),
 * whatever the transport threw. The timer is always cleared, so nothing is left running.
 */
export async function withTimeout<T>(ms: number, label: string, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    return await run(ctl.signal);
  } catch (e) {
    if (ctl.signal.aborted) throw new AiError('timeout', `${label} did not answer within ${Math.max(1, Math.round(ms / 1000))} s.`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** A request's output limit (AiRequest.maxOutputTokens) when it is a whole number above 0, else undefined (no limit set). */
export function outputLimit(n: unknown): number | undefined {
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

/** An enumerated error code from a provider body (e.g. `invalid_api_key`) when it is a plain identifier, else ''. */
export function safeCode(v: unknown): string {
  return typeof v === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(v) ? v : '';
}
