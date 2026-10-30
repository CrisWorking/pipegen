// Plan C Task C2: the gate's severity policy, and the ONE definition of what a policy may be. Two places check a policy:
// the engine, when it renders or judges the gate step's `policy` literal (src/engine/tool-flags.ts, C0b), and the gate itself
// (decide.ts), which refuses a bad one as a settings error. Both call policyProblem here, so they can never disagree.
// A leaf: it imports only the import-free types.ts.
import type { Severity } from '../../src/types.js';

export interface Policy { block: Severity[]; warn: Severity[] }

export const SEVERITIES: readonly Severity[] = Object.freeze(['critical', 'high', 'medium', 'low', 'info'] as const);
/** Decision 13: these always block when new, and a policy can never take them out of its block list. */
export const POLICY_FLOOR: readonly Severity[] = Object.freeze(['critical', 'high'] as const);
/** The documented default: block critical and high, warn on medium; low and info are only counted. */
export const DEFAULT_POLICY: Readonly<Policy> = Object.freeze({
  block: Object.freeze(['critical', 'high']) as unknown as Severity[],
  warn: Object.freeze(['medium']) as unknown as Severity[],
});

const isPlain = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

/**
 * Why a value is not a policy the gate accepts, or null. Exactly the keys `block` and `warn`, each a list of at most five
 * known severities; the block list holds critical and high (the floor); no severity twice or in both lists.
 */
export function policyProblem(v: unknown): string | null {
  if (!isPlain(v) || Object.keys(v).sort().join() !== 'block,warn') return 'a JSON object with exactly block and warn';
  const lists = [v.block, v.warn];
  if (!lists.every((l) => Array.isArray(l) && l.length <= SEVERITIES.length && l.every((x) => typeof x === 'string' && (SEVERITIES as readonly string[]).includes(x)))) return 'block and warn lists of severities';
  const block = v.block as string[];
  const warn = v.warn as string[];
  if (!POLICY_FLOOR.every((s) => block.includes(s))) return 'a policy whose block list includes at least critical and high';
  if (new Set(block).size !== block.length || new Set(warn).size !== warn.length || warn.some((x) => block.includes(x))) return 'a policy with no duplicate and no severity in both lists';
  return null;
}
