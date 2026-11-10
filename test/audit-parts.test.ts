// Plan P Task PL-A1: the six report parts. partOf puts every need in exactly one part.
import { describe, expect, it } from 'vitest';
import { NEED_CATEGORIES, type Layer, type NeedCategory } from '../src/types.js';
import { PART_TITLE, partOf, type PartId } from '../src/audit/parts.js';

const LAYERS: Layer[] = ['pre-commit', 'push', 'merge', 'deploy'];
const part = (category: NeedCategory, layer: Layer = 'push'): PartId => partOf({ category, layer });

describe('audit parts', () => {
  it('every NEED_CATEGORY has a part', () => {
    for (const c of NEED_CATEGORIES) {
      for (const l of LAYERS.filter((x) => x !== 'pre-commit')) {
        expect([1, 2, 3, 4, 5, 6], `${c}/${l}`).toContain(partOf({ category: c, layer: l }));
      }
    }
  });

  it('has the six titles', () => {
    expect(PART_TITLE).toEqual({
      1: 'On your computer', 2: 'Every pull request', 3: 'Before merge',
      4: 'Build and release', 5: 'Deploy', 6: 'Scheduled and repo settings',
    });
  });

  it('pre-commit layer → part 1 for any category', () => {
    for (const c of NEED_CATEGORIES) expect(part(c, 'pre-commit'), c).toBe(1);
  });

  it('part 1: hooks and a push-layer hooks need', () => { expect(part('hooks')).toBe(1); });
  it('part 2: secrets and lint', () => { expect(part('secrets')).toBe(2); expect(part('lint')).toBe(2); });
  it('part 3: gate and dependency-review', () => { expect(part('gate', 'merge')).toBe(3); expect(part('dependency-review', 'merge')).toBe(3); });
  it('part 4: image-scan and signing', () => { expect(part('image-scan')).toBe(4); expect(part('signing')).toBe(4); });
  it('part 5: deploy-verify and dast', () => { expect(part('deploy-verify', 'deploy')).toBe(5); expect(part('dast', 'deploy')).toBe(5); });
  it('part 6: scorecard and update-config', () => { expect(part('scorecard')).toBe(6); expect(part('update-config')).toBe(6); });
  it('workflow-pin-check → part 6', () => { expect(part('workflow-pin-check')).toBe(6); });
  it('dependency-review → part 3', () => { expect(part('dependency-review')).toBe(3); });
  it('an unknown category falls back to part 2, never dropped', () => {
    expect(partOf({ category: 'not-a-category', layer: 'push' })).toBe(2);
  });
});
