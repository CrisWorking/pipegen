// One matcher for "does the gate protect this path?", shared by the CODEOWNERS judge and the starter-test rule (v0.2 Plan D, D7; D0a/D0b m1).
// It is the gate's own matching (gate/src/integrity.ts pathMatcher): a name without a slash matches at any depth, a leading `/` the root only,
// case-insensitive, dot files included. Not part of the gate bundle (the gate does not import this file).
import picomatch from 'picomatch';
import type { ReviewedTool } from '../types.js';
import { effectiveProtectedPaths } from './protected-paths.js';
import { loadReviewed } from './reviewed.js';

/** The gate's matching of a protected path list: a name without a slash at any depth, a leading `/` the root only, case-insensitive. */
export const protectedMatcher = (paths: readonly string[]): ((p: string) => boolean) => {
  const m = picomatch(paths.map((p) => (p.startsWith('/') ? p.slice(1) : p.includes('/') ? p : `**/${p}`)), { nocase: true, dot: true });
  return (p) => paths.length > 0 && m(p);
};

let builtIn: readonly ReviewedTool[] | null | undefined;
const matchers = new Map<string, (p: string) => boolean>();

/**
 * Whether the gate treats `path` as protected, given the service roots (the root-scoped names are protected at each service root too).
 * The list is the whole built-in reviewed list, as the gate has it. If that list can not be read the answer is `true` (fail closed: nothing is claimed).
 */
export function isProtectedPath(path: string, serviceRoots: readonly string[], reviewed?: readonly ReviewedTool[]): boolean {
  let list = reviewed;
  if (list === undefined) {
    if (builtIn === undefined) { try { builtIn = loadReviewed(); } catch { builtIn = null; } }
    if (builtIn === null) return true;
    list = builtIn;
  }
  if (reviewed !== undefined) return protectedMatcher(effectiveProtectedPaths(list, serviceRoots))(path);   // a given list is compiled each time (tests, rare)
  const key = [...serviceRoots].sort().join('\0');
  let m = matchers.get(key);
  if (m === undefined) { m = protectedMatcher(effectiveProtectedPaths(list, serviceRoots)); if (matchers.size > 200) matchers.clear(); matchers.set(key, m); }
  return m(path);
}
