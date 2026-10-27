// Need ids and their categories (Plan B ruling S6), in a leaf module: it imports only src/types.ts, which imports
// nothing. The reviewed list loader and the memory read these without pulling in the needs planner or any AI code
// (final review M6); needs.ts re-exports them.
import { NEED_CATEGORIES, type NeedCategory } from '../types.js';

/** Ids only the AI adds (never in the floor). Plan P Task 2: type-check and dockerfile-lint became categories, license-scan became `licences`. */
export const AI_ONLY_IDS = ['migration-check'] as const;

/**
 * Checks that run on a schedule (merge layer; the CI schedule, not each pull request). The AI can't put one on another
 * layer. Kept equal to the layers in the check table (src/engine/needs.ts CHECKS); a test pins that.
 */
export const SCHEDULED_CATEGORIES: ReadonlySet<NeedCategory> = new Set<NeedCategory>(['update-config', 'scorecard', 'fuzzing']);

/** Checks about the whole repo: a need for one never has a service. Also pinned against the check table by a test. */
export const REPO_WIDE_CATEGORIES: ReadonlySet<NeedCategory> = new Set<NeedCategory>([
  'hooks', 'hooks-ci', 'secrets', 'gate', 'iac', 'duplication', 'workflow-lint', 'workflow-pin-check', 'dependency-review', 'licences', 'update-config', 'scorecard',
]);

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
  'migration-check': 'full-tests',
});
