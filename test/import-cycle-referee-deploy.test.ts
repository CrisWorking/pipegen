// PL-E5: the referee <-> deploy layer import cycle is gone. A source scan of the import lines (the cycle was a static import in both
// directions), and a check that the deployGating derivation lives in the engine, not the layer.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (p: string): string => readFileSync(resolve(__dirname, '..', p), 'utf8');
/** Every module specifier an import or export-from statement names (multi-line statements included). */
const specifiers = (src: string): string[] => [...src.matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+'([^']+)'/gms)].map((m) => m[1] as string);
const named = (src: string, from: RegExp): string[] => [...src.matchAll(/^\s*import\b([^;]*?)\bfrom\s+'([^']+)'/gms)].filter((m) => from.test(m[2] as string)).map((m) => m[1] as string);

describe('PL-E5 referee <-> deploy cycle', () => {
  it('src/layers/deploy.ts imports no referee module that imports it back (not referee.ts)', () => {
    const s = specifiers(read('src/layers/deploy.ts'));
    expect(s.filter((x) => /(^|\/)referee\.js$/.test(x))).toEqual([]);
  });
  it('src/engine/deploy-gating.ts does not import referee.ts or the deploy layer', () => {
    const s = specifiers(read('src/engine/deploy-gating.ts'));
    expect(s.filter((x) => /(^|\/)referee\.js$/.test(x))).toEqual([]);
    expect(s.filter((x) => /layers\/deploy\.js$/.test(x))).toEqual([]);
  });
  it('the leaf referee-shared.ts imports neither referee.ts nor the deploy layer', () => {
    const s = specifiers(read('src/engine/referee-shared.ts'));
    expect(s.filter((x) => /(^|\/)referee\.js$|layers\//.test(x))).toEqual([]);
  });
  it('referee.ts no longer imports deployGating from layers/deploy.ts, but from engine/deploy-gating.ts', () => {
    const src = read('src/engine/referee.ts');
    expect(named(src, /layers\/deploy\.js$/).join(' ')).not.toMatch(/\bdeployGating\b/);
    expect(named(src, /(^|\/)deploy-gating\.js$/).join(' ')).toMatch(/\bdeployGating\b/);
  });
  it('deployGating is defined in engine/deploy-gating.ts, not in layers/deploy.ts', () => {
    expect(read('src/engine/deploy-gating.ts')).toMatch(/export function deployGating\(/);
    expect(read('src/layers/deploy.ts')).not.toMatch(/function deployGating\(/);
  });
});

// PL-E5 R1: the whole static value-import graph, not only the direct edges. Type-only imports are erased at build, so they are no edge.
import { existsSync } from 'node:fs';
import { dirname } from 'node:path';

const SRC = resolve(__dirname, '..', 'src');
const valueImports = (file: string): string[] => {
  const src = readFileSync(file, 'utf8');
  const out: string[] = [];
  for (const m of src.matchAll(/^\s*(import|export)\b(\s+type\b)?([^;]*?)\bfrom\s+'(\.[^']*)'/gms)) {
    if (m[2]) continue;
    const to = resolve(dirname(file), (m[4] as string).replace(/\.js$/, '.ts'));
    if (existsSync(to)) out.push(to);
  }
  return out;
};
/** A value-import path from `from` to `to` (file names relative to src), or null. */
const pathBetween = (from: string, to: string): string[] | null => {
  const seen = new Set<string>();
  const walk = (f: string, trail: string[]): string[] | null => {
    if (f === to) return trail;
    if (seen.has(f)) return null;
    seen.add(f);
    for (const n of valueImports(f)) { const r = walk(n, [...trail, n.slice(SRC.length + 1)]); if (r) return r; }
    return null;
  };
  return walk(resolve(SRC, from), [from]);
};

describe('PL-E5 R1 no transitive cycle through referee.ts', () => {
  it('referee.ts reaches the deploy layer, but no path leads from the deploy layer back to referee.ts', () => {
    expect(pathBetween('engine/referee.ts', resolve(SRC, 'layers/deploy.ts'))).not.toBeNull();
    expect(pathBetween('layers/deploy.ts', resolve(SRC, 'engine/referee.ts'))).toBeNull();
  });
  it('deliver.ts and central.ts take SIGNING_ENVIRONMENT from referee-shared.ts, not referee.ts', () => {
    for (const f of ['src/deliver/deliver.ts', 'src/layers/central.ts']) {
      expect(specifiers(read(f)).filter((x) => /(^|\/)referee\.js$/.test(x)), f).toEqual([]);
    }
  });
});
