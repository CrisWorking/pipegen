// PL-E1: finish.ts is split by step; the new modules never import finish.ts back, and finish.ts still exports what others use.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import * as finish from '../src/deliver/finish.js';

const NEW = ['finish-base', 'finish-rulesets', 'finish-settings', 'finish-signing', 'finish-central', 'finish-probe'];
const importsOf = (name: string): string[] =>
  [...readFileSync(new URL(`../src/deliver/${name}.ts`, import.meta.url), 'utf8').matchAll(/from '([^']+)'/g)].map((m) => m[1] as string);

describe('finish split (PL-E1)', () => {
  it.each(NEW)('%s does not import finish.ts back', (name) => {
    expect(importsOf(name).filter((s) => /(^|\/)finish(\.js)?$/.test(s))).toEqual([]);
  });
  it('finish.ts still exports the names other modules use', () => {
    for (const n of ['finish', 'FinishError', 'CoCaseError', 'coCaseProblem', 'coFacts', 'earliestBlockFrom', 'githubFinishProbe', 'FINISH_WRITE_ROUTES']) {
      expect(typeof (finish as Record<string, unknown>)[n], n).not.toBe('undefined');
    }
  });
  it('finish.ts is under 800 lines', () => {
    expect(readFileSync(new URL('../src/deliver/finish.ts', import.meta.url), 'utf8').split('\n').length).toBeLessThan(800);
  });
});
