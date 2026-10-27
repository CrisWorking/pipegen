// Need ids and their categories (Plan B ruling S6), in a leaf module: it imports only src/types.ts, which imports
// nothing. The reviewed list loader and the memory read these without pulling in the needs planner or any AI code
// (final review M6); needs.ts re-exports them.
import { NEED_CATEGORIES, type NeedCategory } from '../types.js';

/** Ids only the AI adds (never in the floor). */
export const AI_ONLY_IDS = ['type-check', 'license-scan', 'dockerfile-lint', 'migration-check'] as const;

/** Every floor id (each equal to its category) plus the ids the AI may add; the AI schema's id enum. */
export const NEED_IDS = [...NEED_CATEGORIES, ...AI_ONLY_IDS] as const;
export type NeedId = typeof NEED_IDS[number];

/**
 * The category of every need id (Plan B ruling S6). Floor ids map to themselves. The AI must give exactly this
 * category, so it can never change which blocking rules apply to a need. Tool lookup (`reviewedFor`) and memory
 * entries derive the category from this table too.
 */
export const NEED_ID_CATEGORY: Readonly<Record<NeedId, NeedCategory>> = Object.freeze({
  ...(Object.fromEntries(NEED_CATEGORIES.map((c) => [c, c])) as Record<NeedCategory, NeedCategory>),
  'type-check': 'lint',
  'dockerfile-lint': 'lint',
  'license-scan': 'deps',
  'migration-check': 'full-tests',
});
