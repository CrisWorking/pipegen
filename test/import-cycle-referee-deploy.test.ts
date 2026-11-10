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
