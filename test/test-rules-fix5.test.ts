// v0.2 Plan D, D7 fix round 5 (exception, ruling D7-R5): repros e1-e3, e5-e9 of review-D7-r4.md, copied verbatim and written red first.
// (1) vi.spyOn and expect.poll are dropped from the allowlists (R1: spyOn by a built string reached the Function constructor; R3: poll binds its
// callback to the running test's Assertion); (2) R2: an asymmetric matcher's result is only an argument of the matcher call that ends an expect
// chain, or of another asymmetric call, directly or nested in literals there; (3)/(4) the prompt and the header say so.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testsInstructions } from '../src/ai/prompts/tests.js';
import { analyzeTestFile } from '../src/create/test-rules.js';

const probs = (src: string, rel = 'test/a.test.ts'): string[] => analyzeTestFile(rel, src).problems;
const refused = (src: string, re: RegExp, rel = 'test/a.test.ts'): void => {
  const p = probs(src, rel);
  expect(p.length, src).toBeGreaterThan(0);
  expect(p.join(' | '), src).toMatch(re);
};
const HEAD = "import { describe, it, test, expect, vi, beforeEach, afterEach } from 'vitest';\nconst f = (...a) => a;\n";
const TAIL = "\nit('tail', () => { expect(f()).toBe(1); });\n";
const E1 = "import { it, expect, vi } from 'vitest';\nit('a', async () => {\n  const s = vi.spyOn(expect.any(Number), 'getMatcherContext');\n  const ctx = s.call({});\n  const st = Object.values(ctx).find((v) => v !== null && typeof v === 'object' && 'environment' in v && 'snapshotPath' in v);\n  const env = st.environment;\n  const host = await env.readSnapshotFile(['', 'etc', 'hostname'].join('/'));\n  await env.saveSnapshotFile(['..', 'pwned-e1.txt'].join('/'), 'PWNED-E1 ' + host);\n  expect(1 + 1).toBe(2);\n});\n";
const E2 = "import { it, expect, vi } from 'vitest';\nconst h = (m) => vi.spyOn(m, 'getMatcher' + 'Context').call({});\nit('a', async () => {\n  const ctx = h(expect.objectContaining({}));\n  const st = Object.values(ctx).find((v) => v !== null && typeof v === 'object' && 'environment' in v);\n  await st.environment.saveSnapshotFile(['..', 'pwned-e2.txt'].join('/'), 'PWNED-E2');\n  expect(1 + 1).toBe(2);\n});\n";
const E3 = "import { it, expect, vi } from 'vitest';\nconst f = () => 1;\nit('a', () => {\n  const F = vi.spyOn(f, 'constr' + 'uctor');\n  const out = F('return process.getBuilt' + 'inModule(\"child' + '_process\").execSync(\"id\").toString()')();\n  console.log('E3', out);\n  expect(f()).toBe(1);\n});\n";
const E5 = "import { it, expect } from 'vitest';\nconst h = (m) => Object.assign(m.getPrototype(m), { asymmetricMatch: () => true });\nit('first', () => { h(expect.objectContaining({})); expect({ a: 1 }).toEqual(expect.objectContaining({ a: 2 })); });\n";
const E6 = "import { it, expect } from 'vitest';\nclass K { grab() { K.got = this; return 1; } }\nit('first', async () => {\n  await expect.poll(new K().grab).toBe(1);\n  const flags = Object.values(K.got)[0];\n  const t = Object.entries(flags).find(([k]) => k === 'vitest-test')[1];\n  t.file.tasks.forEach((x) => { if (x !== t) Object.assign(x, JSON.parse('{\"fai' + 'ls\":true}')); });\n  expect(K.got).toBeDefined();\n});\nit('second', () => { expect(1 + 1).toBe(3); });\n";
const E7 = "import { it, expect, vi } from \"vitest\";\nit(\"a\", async () => {\n  const m = Array.of(expect.anything())[0];\n  const ctx = vi.spyOn(m, \"getMatcherContext\").call({});\n  const st = Object.values(ctx).find((v) => v !== null && typeof v === \"object\" && \"environment\" in v);\n  await st.environment.saveSnapshotFile([\"..\", \"pwned-e7.txt\"].join(\"/\"), \"PWNED-E7\");\n  expect(1 + 1).toBe(2);\n});\n";
const E8 = "import { it, expect } from \"vitest\";\nit(\"a\", () => {\n  expect(expect.objectContaining({})).toSatisfy((m) => Object.assign(m.getPrototype(m), { asymmetricMatch: () => true }) !== null);\n  expect({ a: 1 }).toEqual(expect.objectContaining({ a: 2 }));\n});\n";
const E9 = "import { it, expect, vi } from \"vitest\";\nit(\"first\", async () => {\n  const p = vi.fn(() => 1);\n  await expect.poll(p).toBe(1);\n  const t = Object.entries(Object.values(p.mock.contexts[0])[0]).find(([k]) => k === \"vitest-test\")[1];\n  t.file.tasks.forEach((x) => { if (x !== t) Object.assign(x, JSON.parse(\"{\\\"fai\\\" + \\\"ls\\\":true}\".replace(\"\\\" + \\\"\", \"\"))); });\n  expect(p).toHaveBeenCalled();\n});\nit(\"second\", () => { expect(1 + 1).toBe(3); });\n";

describe('the review-D7-r4 repros are refused', () => {
  it('R1 e3: vi.spyOn(f, built string) returned the Function constructor and ran a shell', () => { refused(E3, /vi\.spyOn/); });
  it('R2 e1, e2, e7: an asymmetric matcher handed back by vi.spyOn, a helper or Array.of wrote files', () => {
    refused(E1, /asymmetric matcher|vi\.spyOn/);
    refused(E2, /asymmetric matcher|vi\.spyOn/);
    refused(E7, /asymmetric matcher|vi\.spyOn/);
    // the asymmetric rule alone refuses them, whatever the spyOn rule says
    for (const p of [E1, E2, E7]) expect(probs(p).join(' | '), p).toMatch(/asymmetric matcher/);
  });
  it('R2 e5, e8: an asymmetric matcher given to a helper or to expect() itself (toSatisfy) faked a pass', () => {
    refused(E5, /asymmetric matcher/);
    refused(E8, /asymmetric matcher/);
  });
  it('R3 e6, e9: expect.poll bound its callback to the running test', () => {
    refused(E6, /expect\.poll|expect \(from vitest\)/);
    refused(E9, /expect\.poll|expect \(from vitest\)/);
  });
});

describe('(1) vi.spyOn and expect.poll are gone, in every form', () => {
  it('vi.spyOn: dot, computed, kept or as a statement', () => {
    for (const code of ["vi.spyOn(f, 'x');", "const s = vi.spyOn(f, 'x');", "vi['spyOn'](f, 'x');", "vi['spy' + 'On'](f, 'x');", 'const { spyOn } = vi;', "vi.spyOn?.(f, 'x');"]) refused(`${HEAD}${code}${TAIL}`, /vi\.spyOn|vi \(from vitest\)|spyOn|computed/);
  });
  it('expect.poll: awaited, in place, stored, computed', () => {
    for (const code of ['await expect.poll(() => f()).toBe(1);', 'expect.poll(() => f()).toBe(1);', 'const p = expect.poll;', "await expect['poll'](() => f()).toBe(1);", 'const { poll } = expect;']) {
      refused(`${HEAD}it('a', async () => { ${code} expect(f()).toBe(1); });\n`, /expect \(from vitest\)|poll|computed/);
    }
  });
  it('positive control: vi.fn and vi.mock still work', () => {
    expect(probs(`${HEAD}vi.mock('../src/a.js', () => ({ run: vi.fn(() => 1) }));\nit('a', () => { const cb = vi.fn(); cb(1); expect(cb).toHaveBeenCalledWith(expect.anything()); expect(cb).toHaveBeenCalledTimes(1); });\n`)).toEqual([]);
  });
});

describe('(2) R2: an asymmetric matcher only inside the matcher call of an expect chain, or inside another asymmetric matcher', () => {
  it('refused as an argument of expect() itself, of vi.*, of a built-in, of a helper or of a chain member that is not the matcher', () => {
    for (const code of ['expect(expect.any(Number)).toBeDefined();', 'expect.soft(expect.anything()).toBeDefined();', 'expect(expect.objectContaining({})).toSatisfy((m) => m !== null);', 'const m = vi.fn(expect.anything());',
      'f(expect.any(Number));', 'f([expect.any(Number)]);', 'f({ a: expect.any(Number) });', 'Array.of(expect.anything());', 'Promise.resolve(expect.anything());', 'Object.assign({}, { a: expect.anything() });', 'Object.values({ a: expect.anything() });',
      'JSON.stringify(expect.anything());', 'console.log(expect.anything());', 'expect(f()).toBe.call(expect.anything(), 1);', 'expect(f()).toBe.apply(null, [expect.anything()]);', 'expect(f()).toBe.bind(null)(expect.anything());',
      'expect(f()).to.equal(expect.anything());', 'expect(f()).toEqual(f(expect.any(Number)));', 'expect(f()).toEqual([f(expect.any(Number))]);', 'expect(f(expect.any(Number))).toBe(1);', 'f(1).toEqual(expect.any(Number));', 'f().toEqual(expect.any(Number));',
      'expect(f()).call(expect.anything(), 1);', 'expect(f()).not.apply(expect.anything(), [1]);', 'expect(f()).bind(expect.anything());', 'expect(f()).not(expect.anything());', 'await expect(f()).resolves(expect.anything());', 'expect(f()).rejects(expect.anything());', "expect(f())['toEqual'](expect.anything());", 'expect(f())[`toEqual`](expect.anything());']) {
      refused(`${HEAD}it('a', async () => { ${code} expect(f()).toBe(1); });\n`, /asymmetric matcher/);
    }
  });
  it('positive control: the normal forms, nested in literals and in other asymmetric matchers, with .not/.resolves/.rejects and expect.soft', () => {
    expect(probs(`${HEAD}it('a', async () => {\n  const x = f();\n  const arr = f();\n  const fn = vi.fn();\n  expect(x).toEqual(expect.objectContaining({ a: expect.any(Number) }));\n  expect(arr).toEqual([expect.any(String)]);\n  expect(fn).toHaveBeenCalledWith(expect.anything());\n  expect(x).not.toEqual(expect.not.objectContaining({ b: [expect.stringMatching(/y/), { c: expect.closeTo(1, 2) }] }));\n  await expect(Promise.resolve(x)).resolves.toEqual(expect.arrayContaining([expect.anything()]));\n  await expect(Promise.reject(x)).rejects.toThrow(expect.objectContaining({ message: expect.stringContaining('x') }));\n  expect.soft(x).toMatchObject({ a: expect.any(Number) });\n});\n`)).toEqual([]);
  });
});

describe('(3) and (4) wording', () => {
  it('the prompt: no spyOn or poll, vi.fn / vi.mock instead, the asymmetric rule, expect.not as a use, and the complete refused-name list', () => {
    const p = testsInstructions({ ext: 'ts' });
    expect(p).toMatch(/no spyOn/);
    expect(p).toMatch(/no expect\.poll/);
    expect(p).toMatch(/use vi\.fn\(\) or vi\.mock/);
    expect(p).not.toMatch(/From vi use only fn, spyOn/);
    expect(p).toMatch(/only as an argument of the matcher call that ends an expect chain/);
    expect(p).toMatch(/never as the value given to expect\(\.\.\.\)/);
    expect(p).toMatch(/and not, as in expect\.not\.objectContaining/);
    expect(p).not.toMatch(/and not as expect\.not/);
    for (const n of ['importActual', 'importMock', 'doMock', 'doUnmock', 'stubGlobal', 'stubEnv', 'unstubAllGlobals', 'unstubAllEnvs', 'hoisted', 'dynamicImportSettled', 'mocked', 'setConfig', 'resetConfig', 'getMatcherContext', 'snapshotState', 'getState', 'setState', 'extend', 'addSnapshotSerializer', 'addEqualityTesters']) {
      expect(p, n).toMatch(new RegExp(`Members named [^.]*\\b${n}\\b`));
    }
  });
  it('the header calls the any-object name ban defence in depth, not a boundary', () => {
    const src = readFileSync(join(import.meta.dirname, '..', 'src', 'create', 'test-rules.ts'), 'utf8');
    expect(src).toMatch(/defence in depth[^\n]*\n?[^\n]*not a boundary/);
    expect(src).not.toMatch(/vi\.fn, vi\.spyOn, vi\.mock/);
  });
});
