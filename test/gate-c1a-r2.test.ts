// Part 0 of C1b: the notes of review-C1a-r1.md (m1, m3, m4) as tests.
import { describe, expect, it } from 'vitest';
import { parseSarif } from '../gate/src/sarif.js';

type Obj = Record<string, unknown>;
const WS = '/home/runner/work/fixture/fixture';
function doc(driver: string, results: unknown[] = [], extra: { rules?: unknown[]; runs?: number } = {}): Obj {
  const run = { tool: { driver: { name: driver, rules: extra.rules ?? [] } }, results };
  return { version: '2.1.0', runs: Array.from({ length: extra.runs ?? 1 }, () => run) };
}
function result(ruleId: string, over: Obj = {}): Obj {
  return { ruleId, message: { text: `message of ${ruleId}` }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/a.js' }, region: { startLine: 3 } } }], ...over };
}
const parse = (json: unknown, tool: string) => parseSarif(json, tool, { workspace: WS });

describe('m1: ruff writes `panic` for a file its linter crashed on; `io-error` is not a ruff id', () => {
  it('a ruff result with id panic is a tool error (the checks of that file were skipped)', () => {
    const out = parse(doc('ruff', [result('C901', { level: 'error' }), result('panic', { level: 'error' })]), 'ruff');
    expect(out.toolError).toMatch(/could not read 1 target\(s\) \(panic\).*covered less/);
    expect(out.findings).toEqual([]);
  });
  it('io-error is an ordinary rule id again (ruff never writes it)', () => {
    const out = parse(doc('ruff', [result('io-error', { level: 'error' })]), 'ruff');
    expect(out.toolError).toBeUndefined();
    expect(out.findings).toHaveLength(1);
  });
  it('the ids that stay: invalid-syntax, E999, E902', () => {
    for (const id of ['invalid-syntax', 'E999', 'E902']) expect(parse(doc('ruff', [result(id, { level: 'error' })]), 'ruff').toolError, id).toMatch(/could not read/);
  });
});

describe('m3: a real nuclei run with no result is accepted only as "nothing reported"', () => {
  it('driver Nuclei with results [] gives no findings and the note, never a silent clean', () => {
    const out = parse(doc('Nuclei', []), 'nuclei');
    expect(out.toolError).toBeUndefined();
    expect(out.findings).toEqual([]);
    expect(out.notes).toEqual(['nothing reported (nuclei run with no result)']);
  });
  it('several runs, all empty: one note', () => {
    expect(parse(doc('Nuclei', [], { runs: 2 }), 'nuclei').notes).toEqual(['nothing reported (nuclei run with no result)']);
  });
  it('a run with a result has no such note; another tool with no result has none either', () => {
    expect(parse(doc('Nuclei', [result('git-config')]), 'nuclei').notes.join()).not.toMatch(/nothing reported/);
    expect(parse(doc('ruff', []), 'ruff').notes).toEqual([]);
  });
});

describe('m4: survivors of the C1a re-review mutation pass', () => {
  const marked = (): { version: string; runs: { tool: { driver: Obj }; results: unknown[]; properties: Obj }[] } =>
    ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'pipegen-empty-nuclei' } }, results: [], properties: { pipegenSynthesized: 'nuclei-no-file' } }] });
  it('the marked file has exactly the keys of properties, tool and driver (one extra key in any of them is refused)', () => {
    const a = marked(); a.runs[0].properties.extra = 'x';
    const b = marked(); (b.runs[0].tool as Obj).extra = 'x';
    const c = marked(); c.runs[0].tool.driver.version = '1';
    expect(parse(marked(), 'nuclei').toolError).toBeUndefined();
    for (const [name, v] of [['properties', a], ['tool', b], ['driver', c]] as const) expect(parse(v, 'nuclei').toolError, name).toBeDefined();
  });
  it('two rules with one id that differ only in their tags are a tool error (a secret tag must not be dropped)', () => {
    const rules = [{ id: 'R1', properties: { tags: [] } }, { id: 'R1', properties: { tags: ['secret'] } }];
    expect(parse(doc('Semgrep OSS', [result('R1', { level: 'error' })], { rules }), 'semgrep').toolError).toMatch(/same id/);
    expect(parse(doc('Semgrep OSS', [result('R1', { level: 'error' })], { rules: [rules[0], rules[0]] }), 'semgrep').toolError).toBeUndefined();
  });
  it('gosec: the highest severity word wins whatever the order of the tags', () => {
    for (const tags of [['LOW', 'HIGH'], ['HIGH', 'LOW'], ['MEDIUM', 'HIGH', 'LOW']]) {
      const out = parse(doc('gosec', [result('G1')], { rules: [{ id: 'G1', properties: { tags } }] }), 'gosec');
      expect(out.findings[0].severity, tags.join()).toBe('high');
    }
    expect(parse(doc('gosec', [result('G1', { properties: { tags: ['LOW', 'MEDIUM'] } })], { rules: [{ id: 'G1' }] }), 'gosec').findings[0].severity).toBe('medium');
  });
});
