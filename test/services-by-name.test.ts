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
