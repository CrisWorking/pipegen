// v0.2 Plan D, D7 fix round 3 (exception, ruling D7-R3): repros a1, a2, a4, a5, a6, a6b of review-D7-r2.md, written red first.
// (1) no computed member on a vitest binding; (3) the value of expect(...) is only the head of a matcher chain that ends in a call, and the results of
// describe/it/test only stand as statements; (4) the service's own dependencies are NOT importable (S9 amended); (5) no http wording.
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
const HEAD = "import { describe, it, test, expect, vi, beforeEach } from 'vitest';\nconst f = (...a) => a;\n";

describe('(1) computed member access on a vitest binding is refused', () => {
  it('the review repros a6 and a6b', () => {
    refused("import { it, expect } from 'vitest';\nit('counted', () => { expect(1 + 1).toBe(2); });\nit['concurrent']('hidden', function () {\n  Object.entries(arguments[0]).find(([k]) => k === 'sk' + 'ip')[1]();\n  expect(1 + 1).toBe(3);\n});\n", /computed|can only be called/);
    refused("import { describe, it, expect } from 'vitest';\ndescribe[`concurrent`]('group', function () {\n  it('inner', () => { expect(1 + 1).toBe(2); });\n});\n", /computed|can only be called/);
  });
  it('every computed form, on every vitest name, even a literal key', () => {
    for (const code of ["it['concurrent']('a', () => { expect(f()).toBe(1); });", "test['concurrent']('a', () => { expect(f()).toBe(1); });", "describe['concurrent']('g', () => { it('a', () => { expect(f()).toBe(1); }); });", "it[`concurrent`]('a', () => { expect(f()).toBe(1); });", "it['conc' + 'urrent']('a', () => { expect(f()).toBe(1); });", "expect['soft'](1).toBe(1);", "expect['any'](Number);", "vi['fn']();", "vi['mock']('./a.js');", "it.concurrent['x']();"]) {
      refused(`${HEAD}${code}\nit('b', () => { expect(f()).toBe(1); });\n`, /computed|can only be called|member/);
    }
    expect(probs(`${HEAD}it.concurrent('a', () => { expect(f()).toBe(1); });\ntest.concurrent('b', () => { expect.soft(f()).toBe(1); });\ndescribe.concurrent('g', () => { it('c', () => { expect(f()).toBe(1); }); });\n`)).toEqual([]);
  });
});

describe('(3) the result of expect(...) is only the head of a matcher chain that ends in a call; results of describe/it/test are only statements', () => {
  it('the review repros a1, a2 (the value of expect(...) read for its flags) and a4 (the describe collector)', () => {
    refused("import { it, expect } from 'vitest';\nit('a', () => {\n  const flags = Object.values(expect(1 + 1))[0];\n  const t = Object.entries(flags).find(([k]) => k === 'vitest-test')[1];\n  Object.entries(t.context).find(([k]) => k === 'sk' + 'ip')[1]();\n  expect(1 + 1).toBe(3);\n  expect(1 + 1).toBe(2);\n});\n", /expect\(/);
    refused("import { it, expect } from 'vitest';\nit('first', () => {\n  const t = Object.entries(Object.values(expect(1 + 1))[0]).find(([k]) => k === 'vitest-test')[1];\n  t.file.tasks.forEach((x) => { if (x !== t) x.mode = 'skip'; });\n  expect(1 + 1).toBe(2);\n});\nit('second', () => { expect(1 + 1).toBe(3); });\n", /expect\(/);
    refused("import { describe, it, expect } from 'vitest';\nconst c = describe('setup', () => {});\nc.test('prepare', () => { c.file.tasks.forEach((x) => { if (x.name !== 'setup') x.mode = 'skip'; }); });\nit('second', () => { expect(1 + 1).toBe(3); });\n", /result of describe/);
  });
  it('expect(...) may not be stored, passed, spread, read, or used without a matcher call', () => {
    for (const code of ['const e = expect(f());', 'let e; e = expect(f());', 'g(expect(f()));', 'const l = [expect(f())];', 'const m = { ...expect(f()) };', 'const k = Object.keys(expect(f()));', 'expect(f());', 'expect(f()).toBe;', 'const t = expect(f()).toBe;', 'expect(f()).resolves;', 'const v = expect(f()).not;', 'const r = expect(f()).toBe(1);', 'g(expect(f()).toBe(1));', 'const [a] = [expect(f()).toBe(1)];', 'expect(f()).toBe(1).x;', 'expect.soft(f());', 'const s = expect.soft(f());', 'const s = expect.poll(() => f());', "expect(f())['toBe'](1);", 'const w = f() || expect(f()).toBe(1);', 'f() ? expect(f()).toBe(1) : 0;', '(0, expect)(f()).toBe(1);']) {
      refused(`${HEAD}const g = f;\nit('a', async () => { ${code} expect(f()).toBe(1); });\n`, /expect\(|expect \(from vitest\)|computed|matcher/);
    }
  });
  it('the normal shapes still pass: statement, awaited, returned, a concise arrow body, .not/.resolves/.rejects chains, asymmetric matchers as arguments', () => {
    expect(probs(`${HEAD}it('a', async () => {\n  expect(f()).toBe(1);\n  expect(f()).not.toBe(2);\n  await expect(f()).resolves.toBe(1);\n  await expect(f()).rejects.toThrow('x');\n  expect.soft(f()).toBe(1);\n  expect(f()).toEqual(expect.objectContaining({}));\n  expect(f()).toEqual([expect.any(Number), expect.anything()]);\n  expect.assertions(6);\n  return expect(f()).toBe(1);\n});\nit('b', () => expect(f()).toBe(1));\nit('c', async () => await expect(f()).resolves.toBe(1));\nit('d', () => { return expect(f()).toBe(1); });\n`)).toEqual([]);
  });
  it('describe(...), it(...) and test(...) and their .concurrent forms may only stand as statements', () => {
    for (const code of ["const c = describe('g', () => {});", "const c = it('a', () => { expect(f()).toBe(1); });", "const c = test('a', () => { expect(f()).toBe(1); });", "const c = describe.concurrent('g', () => {});", "const c = it.concurrent('a', () => { expect(f()).toBe(1); });", "f(describe('g', () => {}));", "describe('g', () => {}).test('x', () => {});", "describe('g', () => {}).file;", "void describe('g', () => {});", "(describe('g', () => {}));".replace(/^\((.*)\);$/, '[$1];')]) {
      refused(`${HEAD}${code}\nit('b', () => { expect(f()).toBe(1); });\n`, /result of|own in the file|statement/);
    }
  });
});

describe('(4) the service\'s own dependencies are not importable', () => {
  it('the review repro a5 (execa) and every package, whatever the dependency list says', () => {
    refused("import { it, expect } from 'vitest';\nimport { execaSync } from 'execa';\nit('runs', () => {\n  const r = execaSync('sh', ['-c', 'echo x']);\n  expect(r.exitCode).toBe(0);\n});\n", /execa/, 'test/a.test.mjs');
    for (const spec of ['execa', 'express', 'lodash/template', '@scope/pkg', '@scope/pkg/sub', 'axios']) {
      refused(`${HEAD}import x from '${spec}';\nit('b', () => { expect(x).toBe(f()); });\n`, new RegExp(spec.replace('/', '\\/')), 'test/a.test.ts');
      refused(`${HEAD}export * from '${spec}';\nit('b', () => { expect(f()).toBe(1); });\n`, /may not export|allowlist|imports/, 'test/a.test.ts');
    }
    refused("const { it, expect } = require('vitest');\nconst x = require('express');\nconst f = () => 1;\nit('a', () => { expect(x).toBe(f()); });\n", /express/, 'test/a.test.cjs');
  });
  it('the allowed modules and relative paths inside the service still pass; the message lists them without dependencies', () => {
    expect(probs(`${HEAD}import path from 'node:path';\nimport { fileURLToPath } from 'node:url';\nimport util from 'node:util';\nimport assert from 'node:assert/strict';\nimport { sub } from '../src/add.js';\nit('b', () => { assert.equal(path.sep, f()); expect(util.format('a') + fileURLToPath(import.meta.url) + sub(1)).toBe(1); });\n`)).toEqual([]);
    const m = probs(`${HEAD}import x from 'lodash';\nit('b', () => { expect(x).toBe(f()); });\n`).join(' ');
    expect(m).toMatch(/not on the allowlist/);
    expect(m).not.toMatch(/dependenc/);
  });
});

describe('(5) no stale http wording', () => {
  it('the prompt and the leaf do not mention http options objects, http routes, node:http re-exports or dependencies as importable', () => {
    const prompt = testsInstructions({ ext: 'ts' });
    expect(prompt).not.toMatch(/HTTP routes|http options|dependencies:/i);
    expect(prompt).not.toMatch(/packages from the service's dependencies/);
    const src = readFileSync(join(import.meta.dirname, '..', 'src', 'create', 'test-rules.ts'), 'utf8');
    expect(src).not.toMatch(/http options object|carry node:http/);
  });
});
