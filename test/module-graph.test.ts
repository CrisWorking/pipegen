// The reviewed list loader is the trust root's reader: it must not pull in the AI code (prompts, providers, the
// code bundle). The module graph is read from esbuild's metafile, the same bundler tsup uses.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
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

  it('module graph: local-host.ts, claude-fallback.ts, output-limit.ts and discovery-limits.ts are leaves (no imports)', async () => {
    expect(await graph('src/util/local-host.ts')).toEqual(['src/util/local-host.ts']);
    expect(await graph('src/util/claude-fallback.ts')).toEqual(['src/util/claude-fallback.ts']);
    expect(await graph('src/util/output-limit.ts')).toEqual(['src/util/output-limit.ts']);
    expect(await graph('src/engine/discovery-limits.ts')).toEqual(['src/engine/discovery-limits.ts']);
  });

  it('module graph: need-ids.ts is a leaf (only the import-free types.ts)', async () => {
    expect(await graph('src/engine/need-ids.ts')).toEqual(['src/engine/need-ids.ts', 'src/types.ts']);
  });

  it('module graph (Plan B 6a, ruling B4): artifact-names.ts is a leaf (only the import-free types.ts); render-step.ts pulls in no AI or GitHub client code', async () => {
    expect(await graph('src/engine/artifact-names.ts')).toEqual(['src/engine/artifact-names.ts', 'src/types.ts']);
    const files = await graph('src/engine/render-step.ts');
    expect(files.filter((f) => f.startsWith('src/ai/') || f.startsWith('src/github/'))).toEqual([]);
  });

  it('module graph: the estimator pulls in no AI, GitHub client or network code (final review batch 2, M5)', async () => {
    const files = await graph('src/estimate/estimate.ts');
    expect(files.filter((f) => f.startsWith('src/ai/') || f.startsWith('src/github/'))).toEqual([]);
    for (const net of ['src/engine/discover.ts', 'src/engine/http.ts', 'src/engine/stats.ts']) expect(files).not.toContain(net);
    expect(files).toEqual([
      'src/engine/discovery-limits.ts', 'src/engine/github-rate.ts', 'src/engine/zap-active.ts', 'src/estimate/estimate.ts', 'src/types.ts',
      'src/util/claude-fallback.ts', 'src/util/local-host.ts', 'src/util/output-limit.ts', 'src/util/package-data.ts', 'src/util/safe-text.ts',
    ]);
  });

  it('module graph (T4b review M11): the audit model pulls in nothing from src/cli/ (the consent token lives in src/audit/)', async () => {
    for (const entry of ['src/audit/model.ts', 'src/audit/render.ts', 'src/audit/consent-token.ts']) {
      const files = await graph(entry);
      expect(files.filter((f) => f.startsWith('src/cli/')), entry).toEqual([]);
    }
  });

  it('module graph (Plan P Task 0, ruling PB1): no runtime import cycle among src/audit/coverage*; tokenize.ts is a leaf, types.ts types only', async () => {
    const isCoverage = (f: string) => f === 'src/audit/coverage.ts' || f.startsWith('src/audit/coverage/');
    const r = await build({
      entryPoints: [resolve(root, 'src/audit/coverage.ts')], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent',
    });
    // esbuild drops `import type`, so these edges are the runtime imports only
    const edges = new Map(Object.entries(r.metafile.inputs).filter(([f]) => isCoverage(f))
      .map(([f, input]) => [f, [...new Set(input.imports.map((i) => i.path).filter(isCoverage))]]));
    const onDisk = readdirSync(resolve(root, 'src/audit/coverage')).filter((f) => f !== 'types.ts').map((f) => `src/audit/coverage/${f}`);
    expect([...edges.keys()].sort()).toEqual(['src/audit/coverage.ts', ...onDisk].sort());

    const cycles: string[] = [];
    const state = new Map<string, 'open' | 'done'>();
    const visit = (f: string, path: string[]): void => {
      state.set(f, 'open');
      for (const next of edges.get(f) ?? []) {
        if (state.get(next) === 'open') cycles.push([...path, f, next].join(' → '));
        else if (!state.has(next)) visit(next, [...path, f]);
      }
      state.set(f, 'done');
    };
    for (const f of edges.keys()) if (!state.has(f)) visit(f, []);
    expect(cycles).toEqual([]);

    expect(edges.get('src/audit/coverage/tokenize.ts')).toEqual([]);
    expect(await graph('src/audit/coverage/types.ts')).toEqual(['src/audit/coverage/types.ts']);
  });

  it('module graph (Plan P Task 0 review, minor): every import of src/audit/coverage/types.ts in the source text is `import type`', () => {
    // esbuild drops an unused plain import, so the bundle check above can't see one; this reads the source instead
    const target = resolve(root, 'src/audit/coverage/types.ts');
    const sources = readdirSync(resolve(root, 'src'), { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith('.ts')).map((f) => resolve(root, 'src', f));
    const STATIC = /^[ \t]*(import|export)[ \t]+(type[ \t]+)?(?:[^;'"]*?[ \t\n]from[ \t]+)?['"]([^'"\n]+)['"]/gm;
    const DYNAMIC = /\bimport\(\s*['"]([^'"\n]+)['"]\s*\)/g;
    const toTarget = (file: string, spec: string) => spec.startsWith('.') && resolve(dirname(file), spec.replace(/\.js$/, '.ts')) === target;
    const typeOnly: string[] = [];
    const plain: string[] = [];
    for (const file of sources) {
      const text = readFileSync(file, 'utf8');
      for (const m of text.matchAll(STATIC)) if (toTarget(file, m[3] ?? '')) (m[2] === undefined ? plain : typeOnly).push(file);
      for (const m of text.matchAll(DYNAMIC)) if (toTarget(file, m[1] ?? '')) plain.push(file);
    }
    expect(typeOnly.length).toBeGreaterThanOrEqual(9); // coverage.ts and the coverage/ modules that use its types
    expect(plain).toEqual([]);
  });
});
