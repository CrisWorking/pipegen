// The gate's protected paths (Plan C Task 4, C4 fix round 2, C5a CF3), in a leaf module: it imports only types.ts, so the gate action
// bundles it without the reviewed-list loader (which reads files and the network).
import { PROTECTED_PATHS_BASE, type ReviewedTool } from '../types.js';

/**
 * PROTECTED_PATHS_BASE, then every configFiles entry of the tools in use (a name without a slash is protected at any depth by the gate), then
 * every rootConfigFiles name as `/name` (the repository root) and `/<service>/name` for each service root other than `.`, each once, in order.
 * A leading `/` tells the gate to match the root only. `serviceRoots` is required (C5a CF3): a forgotten list would silently drop the
 * service-root copies of the root-scoped names (`services/web/.prettierignore`, which prettier reads in that folder).
 */
export function effectiveProtectedPaths(inUse: readonly Pick<ReviewedTool, 'configFiles' | 'rootConfigFiles'>[], serviceRoots: readonly string[]): string[] {
  const roots = [...new Set(serviceRoots.map((r) => r.replace(/^(?:\.\/)+|\/+$/g, '')).filter((r) => r !== '' && r !== '.'))];
  const rooted = inUse.flatMap((t) => (t.rootConfigFiles ?? []).flatMap((n) => (n.includes('/') ? [n] : [`/${n}`, ...roots.map((r) => `/${r}/${n}`)])));
  return [...new Set([...PROTECTED_PATHS_BASE, ...inUse.flatMap((t) => t.configFiles), ...rooted])];
}
