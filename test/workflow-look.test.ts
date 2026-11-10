// Plan P Task PL-D1: the look helpers of a pipegen workflow (src/layers/workflow-look.ts): order by part, header, banners.
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import type { PartId } from '../src/audit/parts.js';
import { byPart, lookOf, workflowHeader } from '../src/layers/workflow-look.js';

const partsOf = (m: Record<string, PartId>) => (id: string): PartId | undefined => m[id];

describe('PL-D1: workflow look helpers', () => {
  it('byPart: a stable sort by part', () => {
    expect(byPart(['d', 'a', 'c', 'b'], partsOf({ a: 3, b: 2, c: 3, d: 6 }))).toEqual([{ id: 'b', part: 2 }, { id: 'a', part: 3 }, { id: 'c', part: 3 }, { id: 'd', part: 6 }]);
  });

  it('byPart: a job with no known part stays with the job before it; the first such job is part 2', () => {
    const ids = ['x', 'a', 'helper', 'b'];
    expect(byPart(ids, partsOf({ a: 5, b: 3 }))).toEqual([{ id: 'x', part: 2 }, { id: 'b', part: 3 }, { id: 'a', part: 5 }, { id: 'helper', part: 5 }]);
  });

  it('lookOf: a banner at each change of part, a blank line between jobs, the header above', () => {
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'n', jobs: { one: { 'runs-on': 'x' }, two: { 'runs-on': 'x' }, three: { 'runs-on': 'x' } } });
    lookOf(doc, [{ id: 'one', part: 2 }, { id: 'two', part: 2 }, { id: 'three', part: 4 }], ' top');
    expect(doc.toString({ lineWidth: 0 })).toBe([
      '# top', '', 'name: n', 'jobs:', '  # --- Every pull request ---', '  one:', '    runs-on: x', '', '  two:', '    runs-on: x', '', '  # --- Build and release ---', '  three:', '    runs-on: x', '',
    ].join('\n'));
  });

  it('workflowHeader: what it does, when it runs, how to change it, PIPEGEN.md, the version (or none)', () => {
    const lines = workflowHeader({ comment: 'pipegen: c', runs: 'on a push', version: '1.2.3' }).split('\n');
    expect(lines).toEqual([
      ' pipegen: c', ' ', ' When it runs: on a push.',
      ' How to change it: through `npx pipegen update`. Edit it through pipegen; pipegen\'s locks protect it once they are on (see PIPEGEN.md).',
      ' See PIPEGEN.md for what each check does and what is not covered.', ' Written by pipegen 1.2.3.',
    ]);
    expect(workflowHeader({ comment: 'c', runs: 'r', version: null }).split('\n').at(-1)).toBe(' Written by pipegen.');
  });

  it('workflowHeader: no "It runs" after "When it runs:", and "written by pipegen" once (the tail line only)', () => {
    const h = workflowHeader({ comment: 'pipegen: c', runs: 'on a push', version: '1.2.3' });
    expect(h).not.toMatch(/when it runs: it runs/i);
    expect(h.match(/written by pipegen/gi)).toHaveLength(1);
  });

  // PL-D1 Fold R2 (security M1): the header checks its own version; no control or line-break character reaches a comment line
  for (const [name, v] of [['LF', '1.2.3\non: push'], ['CR', '1.2.3\ron: push'], ['NEL U+0085', '1.2.3\u0085on: push'], ['LS U+2028', '1.2.3\u2028on: push'],
    ['PS U+2029', '1.2.3\u2029on: push'], ['NUL', '1.2.3\u0000'], ['TAB', '1.2.3\t'], ['DEL', '1.2.3\u007f'], ['C1 U+009B', '1.2.3\u009b'], ['not plain', '1.2.3 # x']] as const) {
    it(`workflowHeader: refuses a version with ${name}`, () => {
      expect(() => workflowHeader({ comment: 'c', runs: 'r', version: v })).toThrow(/not a plain pipegen version/);
    });
  }

  it('workflowHeader: refuses a control or line-break character in comment or runs', () => {
    for (const bad of ['a\nb', 'a\rb', 'a\u0085b', 'a\u2028b', 'a\u2029b', 'a\u0007b']) {
      expect(() => workflowHeader({ comment: bad, runs: 'r', version: null })).toThrow(/control or line-break/);
      expect(() => workflowHeader({ comment: 'c', runs: bad, version: null })).toThrow(/control or line-break/);
    }
  });

  it('workflowHeader: the protection line stays true when locks are skipped (no unconditional claim)', () => {
    const h = workflowHeader({ comment: 'c', runs: 'r', version: '1.2.3' });
    expect(h).toContain('once they are on');
    expect(h).not.toMatch(/The file is protected/);
  });
});
