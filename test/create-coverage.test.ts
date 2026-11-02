// v0.2 Plan D, D6 (ruling B5): the coverage minimum is computed by code. (Written after the code; fix round 1 added its cases first.)
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { aiChoiceNames, CODE_FILLED_CHOICES, coverageChoice, coverageNotes, measuredLines, readExistingMinimum } from '../src/create/coverage.js';
import { COVERAGE_MINIMUMS } from '../src/engine/tool-flags.js';
import { entry } from './helpers/render.js';

// the real `All files` row of vitest 5.0.5 --coverage (v8), from the D6 live run
const VITEST_TABLE = ['----------|---------|----------|---------|---------|-------------------', 'File      | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s ', '----------|---------|----------|---------|---------|-------------------', 'All files |      50 |        0 |   33.33 |      60 |                   ', ' a.js     |      50 |        0 |   33.33 |      60 | 3-4               '].join('\n');

describe('coverageChoice (B5)', () => {
  it('coverage: choice = max enum ≤ min(floor(measured)−1, existing); none → coverage non-blocking with a note', () => {
    const t: [number, number | null, string | null][] = [
      [100, null, '90'], [91, null, '90'], [90.9, null, '80'], [90, null, '80'], [81, null, '80'], [80.99, null, '70'], [71, null, '70'], [70, null, '60'], [61, null, '60'], [60.99, null, null], [60, null, null], [0, null, null], [100, 75, '70'], [100, 70, '70'], [100, 69.9, '60'], [100, 60, '60'], [100, 59, null], [100, 0, null], [75, 100, '70'], [62, 85, '60'], [61.5, 90, '60'],
    ];
    for (const [m, e, want] of t) expect(coverageChoice(m, e), `measured ${m}, existing ${String(e)}`).toBe(want);
    // never a value outside the enum, never 0
    for (let m = 0; m <= 100; m += 0.5) for (const e of [null, 0, 55, 65, 75, 85, 95, 100]) { const c = coverageChoice(m, e); if (c !== null) { expect(COVERAGE_MINIMUMS).toContain(c); expect(Number(c)).toBeLessThanOrEqual(Math.floor(m) - 1); if (e !== null) expect(Number(c)).toBeLessThanOrEqual(e); } }
    // hostile numbers fit nothing
    for (const m of [Number.NaN, Number.POSITIVE_INFINITY, -5, 101, Number('x')]) expect(coverageChoice(m, null)).toBeNull();
    expect(coverageChoice(90, Number.NaN)).toBeNull();
    // non-blocking, with the B5 note
    const low = coverageNotes(42.5, null);
    expect(low).toEqual({ choice: null, blocking: false, notes: ["coverage is 42.5%, below pipegen's lowest minimum (60%), so the coverage check is not blocking"] });
    expect(coverageNotes(60, null).blocking).toBe(false);
    expect(coverageNotes(61, null)).toEqual({ choice: '60', blocking: true, notes: [] });
    // the repo's own higher minimum: the lower enum value, with a note; an equal one needs none
    expect(coverageNotes(100, 65)).toEqual({ choice: '60', blocking: true, notes: ["your own config still requires 65% in your test job; pipegen's check uses 60% and never edits your config"] });
    expect(coverageNotes(100, 70).notes).toEqual([]);
    expect(coverageNotes(100, 50).blocking).toBe(false);
    expect(coverageNotes(100, 50).notes[0]).toBe("your own config asks for only 50%, below pipegen's lowest minimum (60%), so the coverage check is not blocking");
    expect(coverageNotes(95, 50).notes.join(' ')).not.toMatch(/coverage is 95%/);
    for (const m of [Number.NaN, Number.POSITIVE_INFINITY, -1, 100.5]) {
      const r = coverageNotes(m, null);
      expect(r).toEqual({ choice: null, blocking: false, notes: ['the measured coverage could not be read, so the coverage check is not blocking'] });
    }
    expect(coverageNotes(42.5, 50).notes[0]).toMatch(/coverage is 42\.5%, below pipegen's lowest minimum \(60%\)/);
  });

  it('coverage: existing minimum read from vitest/vite config (bounded regex), .c8rc*, package.json c8 (smol JSON parse); unreadable → note', () => {
    const v = (text: string, path = 'vitest.config.ts') => readExistingMinimum({ vitestConfigs: [{ path, text }] });
    expect(v('export default { test: { coverage: { thresholds: { lines: 80, branches: 70 } } } }')).toEqual({ minimum: 80, notes: [] });
    expect(v('thresholds: {\n  statements: 50,\n  lines: 72.5,\n}', 'vite.config.js').minimum).toBe(72.5);
    expect(v('export default {}')).toEqual({ minimum: null, notes: [] });
    expect(v('thresholds: { branches: 70 }')).toEqual({ minimum: null, notes: [] });
    // several that disagree: none is chosen, and a note says so (fix round 1, m2); equal ones are fine
    const dis = v('a = { thresholds: { lines: 90 } }; b = { thresholds: { lines: 75 } }');
    expect(dis.minimum).toBeNull();
    expect(dis.notes[0]).toMatch(/disagree/);
    expect(v('a = { thresholds: { lines: 75 } }; b = { thresholds: { lines: 75 } }').minimum).toBe(75);
    // quoted keys are read; comments are not; a spread beside a number gives no minimum (not both a value and "assumes none")
    expect(v("thresholds: { 'lines': 80 }").minimum).toBe(80);
    expect(v('thresholds: { "lines": 81 }').minimum).toBe(81);
    expect(v('// thresholds: { lines: 0 }\nexport default { test: { coverage: { thresholds: { lines: 80 } } } }')).toEqual({ minimum: 80, notes: [] });
    expect(v('/* thresholds: { lines: 0 } */ thresholds: { lines: 80 }').minimum).toBe(80);
    const spread = v('thresholds: { ...base, lines: 80 }');
    expect(spread.minimum).toBeNull();
    expect(spread.notes).toHaveLength(1);
    // unreadable: a variable, a nested object, a spread, a huge number, a huge file
    for (const bad of ['thresholds: { lines: MIN }', 'thresholds: { lines: 80 + 5 }', 'thresholds: { lines: 101 }', 'thresholds: { lines: -1 }', 'thresholds: { lines: 0x50 }', 'thresholds: base', 'thresholds: { ...base }', 'thresholds: { perFile: { lines: 80 }, lines: 90 }', 'thresholds: { lines: "80" }']) {
      const r = v(bad);
      expect(r.minimum, bad).toBeNull();
      expect(r.notes.length, bad).toBe(1);
      expect(r.notes[0]).toMatch(/could not read the coverage minimum in vitest\.config\.ts/);
    }
    // a block longer than the bound is not read (and says so)
    const long = v(`thresholds: { ${'branches: 1, '.repeat(60)}lines: 80 }`);
    expect(long.minimum).toBeNull();
    expect(long.notes).toHaveLength(1);
    const big = v(`thresholds: { lines: 80 }${' '.repeat(300 * 1024)}`);
    expect(big.minimum).toBeNull();
    expect(big.notes[0]).toMatch(/too large/);
    // the regexes are bounded: a long hostile text is read in linear time
    const t0 = Date.now();
    v(`thresholds: {${'a:1,'.repeat(60000)}`);
    v(`${'thresholds:{'.repeat(20000)}`);
    v(`thresholds:${' '.repeat(200000)}{ lines: 1`);
    expect(Date.now() - t0).toBeLessThan(2000);

    const c = (text: string, path = '.c8rc.json') => readExistingMinimum({ c8rcs: [{ path, text }] });
    expect(c('{ "lines": 85, "check-coverage": true }')).toEqual({ minimum: 85, notes: [] });
    expect(c('{ "reporter": ["text"] }')).toEqual({ minimum: null, notes: [] });
    for (const bad of ['{ lines: 85 }', '# yaml\nlines: 85', '{"lines": "85"}', '{"lines": 150}', '{"lines": 1, "lines": 2}', '[1]', 'module.exports = { lines: 85 }']) {
      const r = c(bad, '.c8rc');
      expect(r.minimum, bad).toBeNull();
      expect(r.notes, bad).toHaveLength(1);
    }
    expect(c(`{"lines": 85}${' '.repeat(300 * 1024)}`).notes[0]).toMatch(/too large/);
    const p = (text: string) => readExistingMinimum({ packageJson: text });
    expect(p('{"name":"x","c8":{"lines":90}}')).toEqual({ minimum: 90, notes: [] });
    expect(p('{"name":"x"}')).toEqual({ minimum: null, notes: [] });
    expect(p('{"name":"x","c8":[]}').notes).toHaveLength(1);
    expect(p('{"name":"x","c8":{"lines":"a"}}').notes[0]).toMatch(/package\.json/);
    expect(p('{"name":').notes).toHaveLength(1);
    // all three sources together: equal -> that value; different -> none, with a note
    expect(readExistingMinimum({ vitestConfigs: [{ path: 'vitest.config.ts', text: 'thresholds: { lines: 85 }' }], c8rcs: [{ path: '.c8rc.json', text: '{"lines": 85}' }], packageJson: '{"c8":{"lines":85}}' })).toEqual({ minimum: 85, notes: [] });
    expect(readExistingMinimum({ vitestConfigs: [{ path: 'vitest.config.ts', text: 'thresholds: { lines: 95 }' }], c8rcs: [{ path: '.c8rc.json', text: '{"lines": 85}' }], packageJson: '{"c8":{"lines":88}}' }).minimum).toBeNull();
    // a path the repo chose is shown cut and on one line
    expect(readExistingMinimum({ c8rcs: [{ path: `.c8rc\nx${'y'.repeat(300)}`, text: 'nope' }] }).notes[0]).not.toMatch(/\n/);
  });

  it('coverage: measured lines are read by code from the `All files` row of the text summary', () => {
    expect(measuredLines(VITEST_TABLE)).toBe(60);
    expect(measuredLines(VITEST_TABLE.replace(/\n/g, '\r\n'))).toBe(60);   // CRLF logs
    expect(measuredLines('noise\nAll files  |   92.3 |   85.7 |   100 |   91.25 |\n')).toBe(91.25);
    for (const bad of ['', 'no table', 'All files | a | b | c | d |', 'All files | 1 | 2 | 3 |', 'All files | 1 | 2 | 3 | 101 |', ' a.js | 1 | 2 | 3 | 4 |', `All files |${' 1 |'.repeat(200)}`]) expect(measuredLines(bad), bad).toBeNull();
    expect(measuredLines(`${'x'.repeat(2_000_000)}\nAll files | 1 | 2 | 3 | 90 |`)).toBeNull();   // only the first MiB is read
  });

  it('coverage: the AI never chooses coverage-thresholds-lines or c8 lines (Plan F schema has no such choice)', () => {
    expect(CODE_FILLED_CHOICES).toEqual({ 'vitest-coverage': 'coverage-thresholds-lines', c8: 'lines' });
    const vit = entry('vitest-coverage');
    expect(Object.keys(vit.choices)).toEqual(['coverage-thresholds-lines']);
    expect(aiChoiceNames('vitest-coverage', vit.choices)).toEqual([]);
    expect(aiChoiceNames('c8', { lines: ['60'], other: ['x'] })).toEqual(['other']);
    expect(aiChoiceNames('eslint', { 'coverage-thresholds-lines': ['60'] })).toEqual(['coverage-thresholds-lines']);   // only the two coverage entries are special
  });
});

// the live check (network: npm registry only; PIPEGEN_LIVE_TESTS=1): the CLI flag overrides the config's thresholds, in pipegen's job only
describe.skipIf(process.env.PIPEGEN_LIVE_TESTS !== '1')('vitest flag overrides config thresholds (live, vitest 5.0.5)', () => {
  it('vitest flag overrides config thresholds: config lines 100 fails at 60% measured, --coverage.thresholds.lines=60 passes, 70 fails', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-d6-live-'));
    try {
      const w = (f: string, t: string): void => { mkdirSync(dir, { recursive: true }); writeFileSync(join(dir, f), t); };
      w('package.json', JSON.stringify({ name: 't', version: '1.0.0', type: 'module', private: true, devDependencies: { vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } }));
      w('a.js', 'export const used = (x) => x + 1;\nexport const unused = (x) => {\n  if (x > 1) return "big";\n  return "small";\n};\nexport const unused2 = (x) => x * 2;\n');
      w('a.test.js', "import { it, expect } from 'vitest';\nimport { used } from './a.js';\nit('used', () => expect(used(1)).toBe(2));\n");
      w('vitest.config.js', "import { defineConfig } from 'vitest/config';\nexport default defineConfig({ test: { coverage: { include: ['a.js'], thresholds: { lines: 100 } } } });\n");
      const home = join(dir, 'home'); mkdirSync(home);
      const env = { PATH: process.env.PATH ?? '', HOME: home };
      execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/'], { cwd: dir, env, stdio: 'pipe' });
      const run = (...flags: string[]) => spawnSync('npx', ['vitest', 'run', '--coverage', ...flags], { cwd: dir, env, encoding: 'utf8' });
      const config = run();
      expect(config.status).toBe(1);
      expect(measuredLines(config.stdout)).toBe(60);
      expect(run('--coverage.thresholds.lines=60').status).toBe(0);
      expect(run('--coverage.thresholds.lines=70').status).toBe(1);
      expect(run('--coverage.thresholds.lines=100').status).toBe(1);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 300_000);
});
