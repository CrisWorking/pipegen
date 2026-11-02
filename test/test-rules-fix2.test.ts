// v0.2 Plan D, D7 fix round 2 (ruling D7-R2, structural): every repro of review-D7-r1.md is a test here (written red first).
// (a) no dynamic import() at all; (b) vi and expect have member ALLOWLISTS; (c) node:http is not importable; (d) test, describe and hook callbacks are arrow
// functions; (e) every member of a chain rooted at a vitest binding is checked (only it/test/describe.concurrent chains).
// The it/describe shape rules, SKIP_PROP (.skip .only .each ...) and the assertion rules are kept.
import { describe, expect, it } from 'vitest';
import { testsInstructions } from '../src/ai/prompts/tests.js';
import { analyzeTestFile } from '../src/create/test-rules.js';

const probs = (src: string, rel = 'test/a.test.ts'): string[] => analyzeTestFile(rel, src, []).problems;
const refused = (src: string, re: RegExp, rel = 'test/a.test.ts'): void => {
  const p = probs(src, rel);
  expect(p.length, src).toBeGreaterThan(0);
  expect(p.join(' | '), src).toMatch(re);
};
const HEAD = "import { describe, it, test, expect, vi, beforeEach, afterEach } from 'vitest';\nconst f = (...a) => a;\n";
const body = (code: string): string => `${HEAD}it('a', async () => { const o = {}; ${code}; expect(1 + f()).toBe(2); });\n`;

describe('(d) callbacks of test, describe and hooks are arrow functions (closes the arguments[0] context)', () => {
  it('the review repros: a function expression as the test, the hook and the describe body is refused', () => {
    refused("import { it, expect } from 'vitest';\nconst v = 1;\nit('b', function () {\n  (Object.entries(arguments[0]).find((e) => e[0] === 'skip'))[1]();\n  expect(v).toBe(2);\n});\n", /arrow function/);
    refused("import { it, expect, beforeEach } from 'vitest';\nconst v = 1;\nbeforeEach(function () {\n  (Object.entries(arguments[0]).find((e) => e[0] === 'skip'))[1]();\n});\nit('b', () => {\n  expect(v).toBe(2);\n});\n", /arrow function/);
    refused("import { describe, it, expect } from 'vitest';\nconst v = 1;\ndescribe('s', function () {\n  console.log('DESC-ARGS', arguments.length, typeof arguments[0]);\n  it('t', () => { expect(v).toBe(v); });\n});\n", /arrow function/);
  });
  it('every function-expression form is refused for each kind of callback; arrows (async too) pass', () => {
    for (const code of ["it('a', function () { expect(f()).toBe(1); });", "it('a', async function () { expect(f()).toBe(1); });", "test('a', function named() { expect(f()).toBe(1); });", "it.concurrent('a', function () { expect(f()).toBe(1); });", "describe('g', function () { it('a', () => { expect(f()).toBe(1); }); });", "describe.concurrent('g', async function () { it('a', () => { expect(f()).toBe(1); }); });", 'beforeEach(function () {});', 'afterEach(async function () {}, 5);']) {
      refused(`${HEAD}${code}\nit('b', () => { expect(f()).toBe(1); });\n`, /arrow function/);
    }
    expect(probs(`${HEAD}beforeEach(async () => { f(); }, 5);\ndescribe('g', async () => { it('a', async () => { expect(f()).toBe(1); }); });\ndescribe.concurrent('h', () => { it.concurrent('b', () => expect(f()).toBe(1)); });\n`)).toEqual([]);
  });
});

describe('(a) every dynamic import() is refused', () => {
  it('the review repros and every form', () => {
    refused("import { it, expect } from 'vitest';\nconst v = 1;\nit('b', async () => {\n  const cp = await (await import('vitest')).vi.importActual('node:child' + '_process');\n  cp.execSync('id');\n  expect(v).toBe(v);\n});\n", /import\(\)/);
    refused("const { it, expect } = require('vitest');\nconst v = 1;\nit('b', async () => {\n  const m = await import('vitest');\n  m.vi.hoisted(() => 1);\n  expect(v).toBe(v);\n});\n", /import\(\)/, 'test/a.test.js');
    for (const spec of ["import('vitest')", "import('node:path')", "import('../src/a.js')", "import('./helpers/h.js')", 'import(`node:path`)', 'import(name)', "import('node:' + 'path')", "import('x', { with: {} })", "import('lodash')"]) {
      refused(body(`const m = await ${spec}`), /import\(\)/);
      refused(`${HEAD}const m = ${spec};\nit('b', () => { expect(f()).toBe(1); });\n`, /import\(\)/, 'test/a.test.mjs');
    }
  });
  it('a static import is still fine', () => {
    expect(probs("import { it, expect } from 'vitest';\nimport path from 'node:path';\nit('b', () => { expect(path.sep).toBe('/'); });\n")).toEqual([]);
  });
});

describe('(b) vi has a member allowlist, and so does expect', () => {
  it('the listed vi members pass; every other member is refused (importActual, importMock, doMock, stubGlobal, stubEnv, hoisted ...)', () => {
    for (const n of ['fn', 'spyOn', 'clearAllMocks', 'resetAllMocks', 'restoreAllMocks', 'useFakeTimers', 'useRealTimers', 'advanceTimersByTime', 'runAllTimers']) expect(probs(body(`vi.${n}()`)), n).toEqual([]);
    expect(probs(body("vi.mock('../src/add.js'); vi.mock('./x.js', () => ({ x: vi.fn() }))"))).toEqual([]);
    for (const n of ['importActual', 'importMock', 'doMock', 'doUnmock', 'unmock', 'stubGlobal', 'stubEnv', 'unstubAllEnvs', 'unstubAllGlobals', 'hoisted', 'resetModules', 'waitFor', 'waitUntil', 'mocked', 'advanceTimersToNextTimer', 'runOnlyPendingTimers', 'setSystemTime', 'getMockedSystemTime', 'isMockFunction', 'isFakeTimers', 'getTimerCount', 'dynamicImportSettled', 'setConfig']) {
      refused(body(`vi.${n}()`), new RegExp(`vi\\.${n} is refused`));
      refused(body(`vi['${n}']()`), new RegExp(`vi\\.${n} is refused`));
    }
    refused(body("vi.mock('node:fs')"), /relative path/);
    refused(body("vi.mock('./a.js', () => { eval('1'); return {}; })"), /eval/);   // the factory body is judged by the same rules
  });
  it('the listed expect members pass; extend, addSnapshotSerializer and the rest are refused', () => {
    for (const n of ['soft', 'poll']) expect(probs(body(`expect.${n}(f()).toBe(1)`)), n).toEqual([]);
    // D7-R4: an asymmetric matcher only as a call argument, expect.assertions/hasAssertions only as statements
    for (const n of ['any', 'anything', 'objectContaining', 'arrayContaining', 'stringContaining', 'stringMatching', 'closeTo']) expect(probs(body(`expect(f()).toEqual(expect.${n}(1))`)), n).toEqual([]);
    for (const n of ['assertions', 'hasAssertions']) expect(probs(body(`expect.${n}(1)`)), n).toEqual([]);
    for (const n of ['extend', 'addSnapshotSerializer', 'unreachable', 'getState', 'setState', 'addEqualityTesters', 'toBe', 'fail']) refused(body(`expect.${n}({})`), /expect \(from vitest\)/);
  });
});

describe('(c) node:http is not importable, and no http machinery is left', () => {
  it('the review repro and every import form', () => {
    refused("import { it, expect } from 'vitest';\nimport http from 'node:http';\nit('egress', async () => {\n  const req = http.get({ port: 1, path: '/' }, (res) => { res.resume(); });\n  expect(req.agent.createConnection({ host: 'h', port: 1 }, () => 1)).toBeTruthy();\n});\n", /node:http/);
    for (const spec of ["import http from 'node:http';", "import * as http from 'node:http';", "import { get } from 'node:http';", "import { createServer } from 'node:http';", "import 'node:http';", "export * from 'node:http';", "export { get } from 'node:http';"]) refused(`${HEAD}${spec}\nit('b', () => { expect(f()).toBe(1); });\n`, /node:http|may not export/);
    refused("const { it, expect } = require('vitest');\nconst http = require('node:http');\nconst f = () => 1;\nit('a', () => { expect(f()).toBe(1); });\n", /node:http/, 'test/a.test.cjs');
    refused(`${HEAD}import https from 'node:https';\nit('b', () => { expect(f()).toBe(1); });\n`, /node:https/);
    refused(`${HEAD}import x from 'http';\nit('b', () => { expect(f()).toBe(1); });\n`, /"http"/);
  });
  it('the texts do not offer http', () => {
    expect(testsInstructions({ ext: 'ts' })).not.toMatch(/http\.get|http\.request|createServer|sockets? .*port/);
  });
});

describe('(e) every member of a chain rooted at a vitest binding is checked', () => {
  it('only it/test/describe.concurrent chains pass, and they must be called', () => {
    for (const code of ["it.concurrent.foo('a', () => { expect(f()).toBe(1); });", "it.concurrent.skip('a', () => { expect(f()).toBe(1); });", "it.concurrent.concurrent('a', () => { expect(f()).toBe(1); });", "test.concurrent.only('a', () => { expect(f()).toBe(1); });", "describe.concurrent.x('g', () => {});", "describe.concurrent['skip']('g', () => {});", 'const g = it.concurrent;', 'f(test.concurrent);', 'const k = Object.keys(it.concurrent);', "expect.soft.x(1);", "expect.any.constructor", 'expect.poll.call', 'vi.fn.x()', 'vi.fn.call()', 'const g = vi.fn;', 'const g = expect.soft;', "it.concurrent.each([1])('a', () => {});", "it.concurrent['sk' + 'ip']('a', () => {});"]) {
      refused(`${HEAD}${code}\nit('b', () => { expect(f()).toBe(1); });\n`, /can only be called|skips, focuses|is refused|can not count/);
    }
    expect(probs(`${HEAD}it.concurrent('a', () => { expect(f()).toBe(1); });\ntest.concurrent('b', () => { expect(f()).toBe(1); });\ndescribe.concurrent('g', () => { it('c', () => { expect.soft(f()).toBe(1); expect(f()).toEqual(expect.any(Array)); vi.fn().mockReturnValue(1); }); });\n`)).toEqual([]);
  });
});
