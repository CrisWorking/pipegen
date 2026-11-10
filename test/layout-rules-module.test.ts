// PL-E3: the layout rules (G1) live in src/engine/layout-rules.ts, and moving them added no import cycle. Source scans of the import lines;
// type-only imports are erased at build, so they are no edge.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const SRC = resolve(__dirname, '..', 'src');
const read = (p: string): string => readFileSync(resolve(__dirname, '..', p), 'utf8');
const stmts = (src: string): { type: boolean; names: string; from: string }[] =>
  [...src.matchAll(/^\s*(?:import|export)\b(\s+type\b)?([^;]*?)\bfrom\s+'([^']+)'/gms)].map((m) => ({ type: Boolean(m[1]), names: m[2] as string, from: m[3] as string }));
const valueEdges = (file: string): string[] => {
  const out: string[] = [];
  for (const s of stmts(readFileSync(file, 'utf8'))) {
    if (s.type || !s.from.startsWith('.')) continue;
    const to = resolve(dirname(file), s.from.replace(/\.js$/, '.ts'));
    if (existsSync(to)) out.push(to);
  }
  return out;
};
const reaches = (from: string, target: string): boolean => {
  const seen = new Set<string>();
  const go = (f: string): boolean => { if (f === target) return true; if (seen.has(f)) return false; seen.add(f); return valueEdges(f).some(go); };
  return valueEdges(from).some(go);
};
const LAYOUT = resolve(SRC, 'engine/layout-rules.ts');
const REFEREE = resolve(SRC, 'engine/referee.ts');
const MOVED = ['judgeLayout', 'judgeLayoutJobs', 'judgeTriggerSet', 'judgeJobIf', 'reaches', 'holdsGate', 'isPushFile', 'isPushCaller', 'callsPushFile', 'calledFileOf', 'gateLayoutFile', 'pushOffDefault', 'concurrencyFormOk', 'prReviewFormOk', 'prCheckIfProblem', 'deployIfProblem', 'isNightlyFile'];

describe('PL-E3 layout rules in their own module', () => {
  it('src/engine/layout-rules.ts defines the layout rules; referee.ts no longer does', () => {
    expect(existsSync(LAYOUT)).toBe(true);
    const lay = read('src/engine/layout-rules.ts');
    const ref = read('src/engine/referee.ts');
    for (const f of MOVED) {
      expect(lay, f).toMatch(new RegExp(`(?:function ${f}\\(|const ${f} =)`));
      expect(ref, f).not.toMatch(new RegExp(`(?:function ${f}\\(|const ${f} =)`));
    }
  });
  it('referee.ts imports the layout rules from layout-rules.js', () => {
    const names = stmts(read('src/engine/referee.ts')).filter((s) => /(^|\/)layout-rules\.js$/.test(s.from)).map((s) => s.names).join(' ');
    for (const f of ['judgeLayout', 'judgeJobIf']) expect(names, f).toMatch(new RegExp(`\\b${f}\\b`));
  });
  it('no import cycle: layout-rules.ts reaches referee.ts by no value import, and referee.ts reaches layout-rules.ts', () => {
    expect(reaches(LAYOUT, REFEREE)).toBe(false);
    expect(reaches(REFEREE, LAYOUT)).toBe(true);
  });
});
