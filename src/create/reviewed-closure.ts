// The reviewed lock entries a lock edit may add (D1 fix round 1, B2): the closure of the pinned repo-code packages (vitest + @vitest/coverage-v8,
// and c8), made and reviewed like the checker closures in data/npm-closures/ (#107): a complete npm lockfile v3 for one fixed package.json, dated
// and cooldown-checked once. The guard checks MEMBERSHIP: every entry a lock edit adds must equal one reviewed entry (name@version), so the added
// code is a subset of the reviewed code. D6 generates the data files (`npm install` is needed); until they exist `loadReviewedClosure` gives null and
// the guard refuses every lock edit (fail closed).
import { readFileSync } from 'node:fs';
import { closureProblems, expectedPins, NpmClosureError, type NpmPin } from '../engine/npm-closure.js';
import { packageDataPath } from '../util/package-data.js';
import type { ReviewedTool } from '../types.js';

/** The reviewed entries by name@version and the reviewed pins (the packages pipegen adds to devDependencies). */
export interface ReviewedClosure {
  pins: Readonly<Record<string, { version: string; integrity: string }>>;
  entries: ReadonlyMap<string, Record<string, unknown>>;
}
/** npm's placement flags: they say where and why an entry sits in a user's tree, not what code it is. */
export const PLACEMENT_FLAGS: readonly string[] = ['dev', 'optional', 'devOptional', 'peer'];
/** The reviewed-list entries whose closures D6 makes for the guard. */
export const B2_CLOSURE_IDS: readonly string[] = ['vitest-coverage', 'c8'];

/** The lock key's package name (the last `node_modules/` segment). */
export const nameOfLockKey = (key: string): string | null => /^node_modules\/(?:.*\/node_modules\/)?((?:@[^/]+\/)?[^/]+)$/.exec(key)?.[1] ?? null;
/** An entry without its placement flags (a copy). */
export function withoutPlacement(e: Record<string, unknown>): Record<string, unknown> {
  const c = { ...e };
  for (const f of PLACEMENT_FLAGS) delete c[f];
  return c;
}

/** Builds a ReviewedClosure from judged closure lock texts and the pins they hold. Throws NpmClosureError for a lock that does not pass the closure judge. */
export function closureFromLocks(locks: readonly { text: string; pins: readonly NpmPin[] }[]): ReviewedClosure {
  const pins: Record<string, { version: string; integrity: string }> = {};
  const entries = new Map<string, Record<string, unknown>>();
  const banned = new Set<string>();
  for (const { text, pins: p } of locks) {
    const bad = closureProblems(text, p);
    if (bad.length > 0) throw new NpmClosureError(`a reviewed closure is refused: ${bad[0]}`);
    for (const x of p) pins[x.name] = { version: x.version, integrity: x.integrity };
    const packages = (JSON.parse(text) as { packages: Record<string, Record<string, unknown>> }).packages;
    for (const [key, e] of Object.entries(packages)) {
      const name = nameOfLockKey(key);
      if (key === '' || name === null || typeof e.version !== 'string') continue;
      const id = `${name}@${e.version}`;
      const have = entries.get(id);
      if (have !== undefined && JSON.stringify(sorted(withoutPlacement(have))) !== JSON.stringify(sorted(withoutPlacement(e)))) banned.add(id);
      else if (have === undefined) entries.set(id, e);
    }
  }
  for (const id of banned) entries.delete(id);
  return { pins, entries };
}
const sorted = (o: Record<string, unknown>): unknown => JSON.parse(JSON.stringify(o, (_k, v: unknown) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v))) as unknown;

/**
 * The reviewed closure for the B2 pins, or null when the data is not there (D6 has not made it): then every lock edit is refused.
 * `read` returns the closure lock text of an entry id (default: data/npm-closures/<id>.json); a missing or refused one is skipped, so its pin is never offered.
 */
export function loadReviewedClosure(reviewed: readonly ReviewedTool[], read: (id: string) => string = (id) => readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8')): ReviewedClosure | null {
  const locks: { text: string; pins: NpmPin[] }[] = [];
  for (const id of B2_CLOSURE_IDS) {
    const tool = reviewed.find((t) => t.id === id);
    if (tool === undefined) continue;
    try { locks.push({ text: read(id), pins: expectedPins(tool) }); } catch { /* not made yet */ }
  }
  if (locks.length === 0) return null;
  try { return closureFromLocks(locks); } catch { return null; }
}
