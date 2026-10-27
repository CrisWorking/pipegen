// How many needs one run sends to discovery, in a leaf module (no imports): the estimator prices the discovery calls
// with it and must not pull in discovery's AI and network code (final review batch 2, M5). discover.ts re-exports it.

/** Needs discovery runs for in one run (distinct need id + language). */
export const MAX_DISCOVERY_NEEDS = 5;
