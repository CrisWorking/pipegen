// Limits of the `audit --ai` AI calls, in a leaf module (no imports): the estimator prices the needs and discovery calls
// with them and must not pull in discovery's AI and network code (final review batch 2, M5). discover.ts re-exports
// MAX_DISCOVERY_NEEDS.

/** Needs discovery runs for in one run (distinct need id + language). */
export const MAX_DISCOVERY_NEEDS = 5;

/**
 * Output limits per request (Plan U ruling U13): the needs call and one discovery (candidates) call. Thinking counts as
 * output on claude-opus-5-5, which can't turn it off, so smaller limits would cut answers off too often. A cut-off
 * answer fails safe (a note; nothing is used).
 */
export const NEEDS_MAX_OUTPUT_TOKENS = 32_000;
export const CANDIDATES_MAX_OUTPUT_TOKENS = 16_000;
/** An upper bound on one candidates request's size (system + user + schema, UTF-8 bytes); a test checks the real one. */
export const CANDIDATES_REQUEST_MAX_BYTES = 8_000;
