// Which Claude models turn on the server-side refusal fallback, in a leaf module (no imports): the Claude adapter sends
// the fallback parameter for them, and the estimator prices a possible fallback run for them (the estimator must not
// pull in any AI code). src/ai/claude.ts re-exports both.

/**
 * Models the claude-api skill lists for server-side `fallbacks` (SKILL.md: Claude Fable 5.1 / Mythos 5.1, Opus 5.5,
 * Opus 5, Sonnet 5.5; model-migration.md: "work as on Claude Fable 5"). Not Claude Haiku 5.5 ("no server-side
 * fallback"), and not older models. Any other --model gets neither the parameter nor the beta header.
 */
export const FALLBACK_MODELS: readonly string[] = Object.freeze([
  'claude-fable-5-1', 'claude-mythos-5-1', 'claude-fable-5', 'claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5',
]);

/** True when requests for this model turn on the server-side refusal fallback (and REFUSAL_FALLBACK_NOTE applies). */
export function fallbackEnabled(model: string): boolean {
  return FALLBACK_MODELS.includes(model);
}
