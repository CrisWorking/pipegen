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
    const lines = workflowHeader({ comment: 'pipegen: c', runs: 'It runs on a push', version: '1.2.3' }).split('\n');
    expect(lines).toEqual([
      ' pipegen: c', ' ', ' When it runs: It runs on a push.',
      ' How to change it: through `npx pipegen update`. The file is protected (a code owner reviews every change), so edits by hand are refused or undone.',
      ' See PIPEGEN.md for what each check does and what is not covered.', ' Written by pipegen 1.2.3.',
    ]);
    expect(workflowHeader({ comment: 'c', runs: 'r', version: null }).split('\n').at(-1)).toBe(' Written by pipegen.');
  });
});
