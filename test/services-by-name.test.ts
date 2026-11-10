import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { servicesByName } from '../src/engine/names.js';
import type { Service } from '../src/types.js';

const svc = (name: string, path: string) => ({ name, path }) as unknown as Service;

describe('servicesByName', () => {
  it('duplicate names → first wins, as find() did', () => {
    const map = servicesByName({ services: [svc('web', 'a'), svc('api', 'b'), svc('web', 'c')] });
    expect(map.get('web')?.path).toBe('a');
    expect(map.get('api')?.path).toBe('b');
    expect(map.size).toBe(2);
  });
  it('unknown name → undefined', () => {
    expect(servicesByName({ services: [svc('web', 'a')] }).get('nope')).toBeUndefined();
  });
});

describe('name lookups use servicesByName (PL-E2 fold R1)', () => {
  const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
  const scan = /\b(services|all)\.(find|filter)\(\((\w+)\) => \3.name === /;
  it.each(['src/layers/jobs.ts', 'src/engine/tuning.ts'])('%s has no services.find/filter by name', (p) => {
    expect(read(p).split('\n').filter((l) => scan.test(l))).toEqual([]);
  });
  it('jobs.ts builds no map inside a map callback or per-iteration lookup', () => {
    const src = read('src/layers/jobs.ts');
    expect(src).not.toMatch(/\.map\(\(a\) => servicesByName/);
  });
});
