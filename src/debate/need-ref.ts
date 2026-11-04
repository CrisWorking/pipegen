// The debate's unit (v0.2 Plan F, ruling B1): a need key = jobIdFor(need.id, need.service), the key the gate and the job
// list already use. Need ids repeat per layer and per service (floorNeeds), and a StepSpec has no layer, so the builder
// makes one choice per (id, service) pair and that choice covers every layer of the pair. The candidates map, the
// disputes and the decided winners are keyed by it, and the AI schemas' need enum is the list of offered keys.
// Two pairs that would share a key (two services whose names slug the same) are refused, never merged: one choice would
// otherwise be applied to the other service (gateJobList refuses the same collision later; this refuses it first).
import { GateJobListError, jobIdFor } from '../engine/gate-job-list.js';
import { promptServiceNames, promptText } from '../engine/needs.js';
import type { Layer, Need, RepoProfile } from '../types.js';

export class NeedKeyError extends Error {}

const COLLISION = "Two services have names that give the same id once cleaned, so pipegen can't tell their checks apart. Rename one of them.";
const NO_KEY = 'A service name has no letters or digits, so pipegen has no id for its checks. Rename it.';

/** The need key of a need: its job id (need id, then `--` and the service slug). Throws NeedKeyError when the name has no slug. */
export function needKeyOf(n: Pick<Need, 'id' | 'service'>): string {
  try {
    return jobIdFor(n.id, n.service);
  } catch (e) {
    if (e instanceof GateJobListError) throw new NeedKeyError(NO_KEY);
    throw e;
  }
}

/** Every need of one (id, service) pair, under its key. */
export interface NeedRef {
  key: string;
  id: string;
  category: string;
  /** The profile's service name; absent for a repo-wide need. */
  service?: string;
  /** The layers the pair has, in the order of the need list, each once. */
  layers: Layer[];
  /** The needs of the pair, in the order of the need list. */
  needs: Need[];
  /** True when any layer of the pair blocks (the choice covers them all, so the strictest wins). */
  blocking: boolean;
  /** True when any layer of the pair is a floor need. */
  floor: boolean;
  /**
   * Whether the AI may see this key: the key passes promptText unchanged and its service (if any) is one of the names the
   * profile summary shows (promptServiceNames). false → code decides the pair (ruling B1), the key is never in a prompt or schema.
   */
  offered: boolean;
}

/**
 * The needs grouped by need key, in the order of first appearance. `p` and `knownValues` decide `offered` exactly as the
 * profile summary decides which service names it shows. Throws NeedKeyError when two pairs share a key or a service name
 * has no key; the message holds no repo text.
 */
export function needRefs(needs: readonly Need[], p: RepoProfile, knownValues: readonly string[] = []): NeedRef[] {
  const shown = new Set(promptServiceNames(p, knownValues));
  const byKey = new Map<string, NeedRef>();
  for (const n of needs) {
    const key = needKeyOf(n);
    const ref = byKey.get(key);
    if (ref === undefined) {
      byKey.set(key, {
        key, id: n.id, category: n.category, ...(n.service === undefined ? {} : { service: n.service }),
        layers: [n.layer], needs: [n], blocking: n.blocking, floor: n.floor,
        offered: promptText(key, knownValues) === key && (n.service === undefined || shown.has(n.service)),
      });
      continue;
    }
    if (ref.id !== n.id || ref.service !== n.service) throw new NeedKeyError(COLLISION);
    if (ref.category !== n.category) throw new NeedKeyError('One need id has two categories in the plan, so pipegen stopped before the AI saw it.');
    if (!ref.layers.includes(n.layer)) ref.layers.push(n.layer);
    ref.needs.push(n);
    ref.blocking ||= n.blocking;
    ref.floor ||= n.floor;
  }
  return [...byKey.values()];
}

/** The refs the AI may see (their keys are the schema's need enum); the rest are decided by code. */
export function offeredRefs(refs: readonly NeedRef[]): NeedRef[] {
  return refs.filter((r) => r.offered);
}
