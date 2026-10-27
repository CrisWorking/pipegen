// Tool flags pipegen never passes, in one leaf module (no imports) so every rule that checks them uses the same list
// (Plan P ruling PS34): the reviewed-list loader (reviewed.ts) and the local secret scan's own argv (Task 7).

/**
 * betterleaks flags pipegen never passes (catalogue §3 PC2): --validate and --analyze send candidate secrets to
 * provider APIs, and --unsafe-auto-load-config loads a config from the scanned repo.
 */
export const BETTERLEAKS_FORBIDDEN_FLAGS = ['--validate', '--analyze', '--unsafe-auto-load-config'] as const;
