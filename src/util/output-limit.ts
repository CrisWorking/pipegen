// What counts as a request's output limit (AiRequest.maxOutputTokens), in a leaf module (no imports): the providers, the
// audit's spend meter and the estimator all use this one rule (review N3).

/** A valid output limit: a whole number above 0 (a safe integer). Anything else is refused before a request is made. */
export function isOutputLimit(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0;
}
