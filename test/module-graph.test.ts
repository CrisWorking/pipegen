// The reviewed list loader is the trust root's reader: it must not pull in the AI code (prompts, providers, the
// code bundle). The module graph is read from esbuild's metafile, the same bundler tsup uses.
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..');

/** Every source file `entry` pulls in (relative to the repo), npm packages left out. */
async function graph(entry: string): Promise<string[]> {
  const r = await build({
    entryPoints: [resolve(root, entry)], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent',
  });
  return Object.keys(r.metafile.inputs).sort();
}

describe('module graph (final review M6)', () => {
  it('module graph: reviewed.ts and memory.ts pull in nothing from src/ai/ (nor the needs planner)', async () => {
    for (const entry of ['src/engine/reviewed.ts', 'src/engine/memory.ts']) {
      const files = await graph(entry);
      expect(files, entry).toContain(entry);
      expect(files.filter((f) => f.startsWith('src/ai/')), entry).toEqual([]);
      expect(files, entry).not.toContain('src/engine/needs.ts');
    }
  });

  it('module graph: local-host.ts and discovery-limits.ts are leaves (no imports)', async () => {
    expect(await graph('src/util/local-host.ts')).toEqual(['src/util/local-host.ts']);
    expect(await graph('src/engine/discovery-limits.ts')).toEqual(['src/engine/discovery-limits.ts']);
  });

  it('module graph: need-ids.ts is a leaf (only the import-free types.ts)', async () => {
    expect(await graph('src/engine/need-ids.ts')).toEqual(['src/engine/need-ids.ts', 'src/types.ts']);
  });

  it('module graph: the estimator pulls in no AI, GitHub client or network code (final review batch 2, M5)', async () => {
    const files = await graph('src/estimate/estimate.ts');
    expect(files.filter((f) => f.startsWith('src/ai/') || f.startsWith('src/github/'))).toEqual([]);
    for (const net of ['src/engine/discover.ts', 'src/engine/http.ts', 'src/engine/stats.ts']) expect(files).not.toContain(net);
    expect(files).toEqual([
      'src/engine/discovery-limits.ts', 'src/engine/github-rate.ts', 'src/estimate/estimate.ts', 'src/types.ts',
      'src/util/local-host.ts', 'src/util/package-data.ts', 'src/util/safe-text.ts',
    ]);
  });
});
