// v0.2 Plan D, D7 fix round 4 (exception, ruling D7-R4): repros b1, b2, b6, b7, o1, o2 of review-D7-r3.md and the S3 scan repro, written red first.
// (1) an expect chain is returned (or is a concise arrow body) only from the arrow written in place as a test or hook callback; (2) expect has a member
// allowlist, asymmetric-matcher results are only call arguments, expect.assertions/hasAssertions only statements; (3) vi.* results other than fn/spyOn
// only statements; (4) vitest's escape members are refused on any object; (5) the vitest bindings are never values; (6) no stale "dependencies"
// wording; (7) the prompt states the new limits.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testsInstructions } from '../src/ai/prompts/tests.js';
import { analyzeTestFile } from '../src/create/test-rules.js';

const probs = (src: string, rel = 'test/a.test.ts'): string[] => analyzeTestFile(rel, src, []).problems;
const refused = (src: string, re: RegExp, rel = 'test/a.test.ts'): void => {
  const p = probs(src, rel);
  expect(p.length, src).toBeGreaterThan(0);
  expect(p.join(' | '), src).toMatch(re);
};
const HEAD = "import { describe, it, test, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';\nconst f = (...a) => a;\nconst g = f;\n";
const TAIL = "\nit('tail', () => { expect(f()).toBe(1); });\n";
const SKIP_SELF = "  const t = Object.entries(Object.values(r)[0]).find(([k]) => k === 'vitest-test')[1];\n  Object.entries(t.context).find(([k]) => k === 'sk' + 'ip')[1]();\n  expect(1 + 1).toBe(3);\n";
const VI = "import { describe, it, test, expect, vi, beforeEach } from 'vitest';\n";

describe('(1) B1/S4: an expect chain leaves a function only from the test or hook callback itself', () => {
  it('the review repros b1, b2, b6 and b7 are refused', () => {
    refused(`${VI}const grab = (v) => expect(v).toBeDefined();\nit('a', () => {\n  const r = grab(1);\n${SKIP_SELF}});\n`, /expect\(/);
    refused(`${VI}function grab(v) { return expect(v).toBeDefined(); }\nit('a', () => {\n  const r = grab(1);\n${SKIP_SELF}});\n`, /expect\(/);
    refused(`${VI}class K { get r() { return expect(1).toBe(1); } }\nit('a', () => {\n  const r = new K().r;\n${SKIP_SELF}});\n`, /expect\(/);
    refused("import { it, expect } from 'vitest';\nconst grab = (v) => expect(v).toBeDefined();\nit('first', () => {\n  const t = Object.entries(Object.values(grab(1))[0]).find(([k]) => k === 'vitest-test')[1];\n  t.file.tasks.forEach((x) => { if (x !== t) Object.assign(x, JSON.parse('{\"fai' + 'ls\":true}')); });\n  expect(grab(1)).toBeDefined();\n});\nit('second', () => { expect(1 + 1).toBe(3); });\nit('third', () => { expect(2 + 2).toBe(5); });\n", /expect\(/);
  });
  it('the other review shapes (b3 .not, b4 awaited .resolves, b5 soft) and the helper forms are refused', () => {
    for (const code of ['const h = (v) => expect(v).not.toBe(2);', 'const h = async (v) => await expect(Promise.resolve(v)).resolves.toBe(v);', 'const h = (v) => expect.soft(v).toBe(v);',
      'const h = (v) => expect.poll(() => v).toBe(v);', 'const h = async (v) => { return await expect(v).resolves.toBe(1); };', 'const h = function (v) { return expect(v).toBe(1); };',
      'const o = { m(v) { return expect(v).toBe(1); } };', 'class C { m(v) { return expect(v).toBe(1); } }']) {
      refused(`${HEAD}${code}${TAIL}`, /expect\(/);
    }
    // inside a test, a nested function still may not hand the result out
    for (const code of ['const h = () => expect(f()).toBe(1); h();', '[1].forEach((x) => expect(x).toBe(1));', 'const h = () => { return expect(f()).toBe(1); }; h();', 'f(() => expect(f()).toBe(1));',
      'function h() { return expect(f()).toBe(1); } h();', 'const h = function () { return expect(f()).toBe(1); }; h();', 'class C { m() { return expect(f()).toBe(1); } }', 'const h = () => () => expect(f()).toBe(1); h();']) {
      refused(`${HEAD}it('a', () => { ${code} expect(f()).toBe(1); });\n`, /expect\(/);
    }
    // only the callback itself: an arrow, in its own argument position (the shapes below are refused by the test and hook rules too; the chain rule must also hold)
    for (const code of ["it('a', () => { expect(f()).toBe(1); }, () => expect(f()).toBe(1));", "test('a', () => { expect(f()).toBe(1); }, () => { return expect(f()).toBe(1); });", 'beforeEach(f, () => expect(f()).toBe(1));', 'afterAll(f, () => { return expect(f()).toBe(1); });',
      "it('a', function () { return expect(f()).toBe(1); });", 'beforeAll(function () { return expect(f()).toBe(1); });']) {
      refused(`${HEAD}${code}${TAIL}`, /only from the test or hook function itself/);
    }
    // a hook name that is not imported from vitest is not a hook
    refused("import { it, expect } from 'vitest';\nconst f = (...a) => a;\nbeforeEach(() => expect(f()).toBe(1));\nit('a', () => { expect(f()).toBe(1); });\n", /only from the test or hook function itself/);
    // a describe callback is not a test or hook callback
    refused(`${HEAD}describe('g', () => expect(f()).toBe(1));${TAIL}`, /expect\(|describe/);
    // a helper file may not return one either
    refused("import { expect } from 'vitest';\nexport const check = (v) => expect(v).toBe(1);\nexport function check2(v) { return expect(v).toBe(1); }\n", /expect\(/, 'test/helpers/h.ts');
  });
  it('positive control: the return and concise forms in the test or hook callback, and statements anywhere', () => {
    expect(probs(`${HEAD}it('a', () => expect(f()).toBe(1));\nit('b', async () => await expect(f()).resolves.toBe(1));\nit('c', () => { return expect(f()).not.toBe(2); });\ntest('d', async () => { if (f()) { return await expect(f()).resolves.toBe(1); } expect(f()).toBe(1); });\nit.concurrent('e', () => expect.soft(f()).toBe(1));\ntest.concurrent('e2', () => expect(f()).toBe(1));\nbeforeEach(() => expect(f()).toBe(1));\nafterAll(() => { return expect(f()).toBe(1); });\nconst h = (v) => { expect(v).toBe(1); };\nconst h2 = async (v) => { await expect(v).resolves.toBe(1); };\nit('f', () => { [1].forEach((x) => { expect(x).toBe(1); }); h(1); expect(f()).toBe(1); });\n`)).toEqual([]);
    // the brief's literal control: the chain rule has nothing to say about it (an expect on a literal does not count as an assertion, an older rule)
    const lit = probs("import { it, expect } from 'vitest';\nit('x', () => expect(1).toBe(1))\n");
    expect(lit.join(' | ')).not.toMatch(/value of expect/);
    expect(probs("import { expect } from 'vitest';\nexport const check = (v) => { expect(v).toBe(1); };\n", 'test/helpers/h.ts')).toEqual([]);
  });
});

describe('(2) OOS-1: expect has a member allowlist; asymmetric-matcher results are only call arguments', () => {
  it('the review repros o1 and o2 are refused', () => {
    refused("import { it, expect } from 'vitest';\nit('a', () => {\n  const s = expect.any(Number).getMatcherContext().snapshotState;\n  s.match({ testId: 'x', testName: 'pwn', received: 'PWNED-O1', isInline: false });\n  s.save();\n  expect(1 + 1).toBe(2);\n});\n", /getMatcherContext|snapshotState|asymmetric/);
    refused("import { it, expect } from 'vitest';\nit('a', async () => {\n  const env = expect.any(Number).getMatcherContext().snapshotState.environment;\n  const host = await env.readSnapshotFile(['', 'etc', 'hostname'].join('/'));\n  await env.saveSnapshotFile(['..', 'pwned-o2.txt'].join('/'), 'PWNED-O2 ' + host);\n  expect(1 + 1).toBe(2);\n});\n", /getMatcherContext|snapshotState|asymmetric/);
  });
  it('members of expect outside the allowlist are refused', () => {
    for (const code of ['expect.extend({});', 'expect.getState();', 'expect.setState({});', 'expect.addSnapshotSerializer(f);', 'expect.addEqualityTesters([]);', 'expect.unreachable();', 'f(expect.schemaMatching(f()));', 'expect.not;', 'expect.not.toBe(1);', 'f(expect.not.schemaMatching(f()));', 'f(expect.not.not.any(Number));', 'f(expect.any.call(null, Number));', "f(expect.not['any'](Number));", 'expect.not(1);', 'const q = expect.not.objectContaining;', 'f(expect.not.objectContaining);', 'f(expect.not.any.call(null, Number));']) {
      refused(`${HEAD}it('a', () => { ${code} expect(f()).toBe(1); });\n`, /expect|refused|computed/);
    }
  });
  it('an asymmetric-matcher result may not be a member object, stored, spread, returned or otherwise used', () => {
    for (const code of ['const m = expect.any(Number);', 'let m; m = expect.anything();', 'const o = { a: expect.any(Number) };', 'const l = [expect.stringContaining(\'x\')];', 'expect.any(Number).sample;', 'expect.objectContaining({}).asymmetricMatch({});',
      'f(...[expect.any(Number)]);', 'f({ ...expect.objectContaining({}) });', 'f([...expect.arrayContaining([])]);', 'const h = () => expect.anything();', 'const h = () => { return expect.closeTo(1, 2); };', 'f(f() ? expect.any(Number) : 1);',
      'f((0, expect.any(Number)));', 'f(await expect.any(Number));', 'f(expect.any(Number) || 1);', 'f({ a: [expect.any(Number)] }.a);', 'f(`${expect.any(Number)}`);', 'f(new Map([[1, expect.any(Number)]]));', 'const { sample } = expect.stringMatching(/x/);', 'expect.any(Number)();', 'expect.anything();', 'f(expect.not.objectContaining({}).sample);']) {
      refused(`${HEAD}it('a', async () => { ${code} expect(f()).toBe(1); });\n`, /asymmetric|expect/);
    }
    refused(`${HEAD}const m = expect.objectContaining({});${TAIL}`, /asymmetric/);
  });
  it('expect.assertions(n) and expect.hasAssertions() may only be statements', () => {
    for (const code of ['const n = expect.assertions(1);', 'f(expect.hasAssertions());', 'await expect.assertions(1);', 'void expect.hasAssertions();', 'expect.assertions(1).x;', 'const h = () => expect.assertions(1);']) {
      refused(`${HEAD}it('a', async () => { ${code} expect(f()).toBe(1); });\n`, /assertions|hasAssertions|expect/);
    }
  });
  it('positive control: asymmetric matchers as arguments, nested in literals, expect.not.<asymmetric>, and the statements', () => {
    expect(probs(`${HEAD}const spy = vi.fn();\nit('a', async () => {\n  expect.assertions(4);\n  expect.hasAssertions();\n  expect(f()).toEqual(expect.objectContaining({ a: expect.any(Number), b: [expect.stringContaining('x'), { c: expect.anything() }] }));\n  expect(f()).toEqual(expect.arrayContaining([expect.closeTo(1, 2)]));\n  expect(spy).toHaveBeenCalledWith(expect.anything(), expect.not.stringMatching(/x/), expect.not.objectContaining({ a: 1 }));\n  expect(f()).toEqual(expect.not.arrayContaining([expect.stringMatching(/y/)]));\n});\n`)).toEqual([]);
  });
});

describe('(3) S3: the results of vi.* calls other than vi.fn and vi.spyOn may only be statements', () => {
  it('the scan repro: vi.useFakeTimers() returns vi, which reaches importActual', () => {
    refused(`${VI}it('a', async () => {\n  const v = vi.useFakeTimers();\n  const cp = await v.importActual('node:child' + '_process');\n  expect(cp).toBeDefined();\n});\n`, /vi\.useFakeTimers|statement|importActual/);
  });
  it('every vi result other than fn and spyOn, used as anything but a statement, is refused', () => {
    for (const code of ['const v = vi.useFakeTimers();', 'vi.useFakeTimers().advanceTimersByTime(1);', 'f(vi.clearAllMocks());', 'await vi.runAllTimers();', 'const h = () => vi.useRealTimers();', 'const r = [vi.resetAllMocks()];', 'f(vi.restoreAllMocks() || 1);', 'const x = vi.advanceTimersByTime(1).fn;', "const m = vi.mock('../src/a.js');"]) {
      refused(`${HEAD}it('a', async () => { ${code} expect(f()).toBe(1); });\n`, /vi\.|statement/);
    }
    refused(`${HEAD}afterEach(() => vi.restoreAllMocks());${TAIL}`, /vi\.restoreAllMocks|statement/);
  });
  it('positive control: vi calls as statements, and vi.fn / vi.spyOn results used freely', () => {
    expect(probs(`${HEAD}import * as mod from '../src/a.js';\nvi.mock('../src/a.js');\nbeforeEach(() => { vi.useFakeTimers(); });\nafterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });\nit('a', () => {\n  vi.useFakeTimers();\n  vi.advanceTimersByTime(10);\n  vi.runAllTimers();\n  vi.clearAllMocks();\n  vi.resetAllMocks();\n  const m = vi.fn().mockReturnValue(1);\n  const s = vi.spyOn(mod, 'run');\n  f(vi.fn());\n  expect(m()).toBe(1);\n  expect(s).not.toHaveBeenCalled();\n});\n`)).toEqual([]);
  });
});

describe('(4) defense in depth: vitest escape members are refused on any object', () => {
  const NAMES = ['importActual', 'importMock', 'doMock', 'doUnmock', 'stubGlobal', 'stubEnv', 'unstubAllGlobals', 'unstubAllEnvs', 'hoisted', 'dynamicImportSettled', 'mocked', 'setConfig', 'resetConfig', 'getMatcherContext', 'snapshotState', 'getState', 'setState', 'extend', 'addSnapshotSerializer', 'addEqualityTesters'];
  it('in dot form, in a statically visible computed form, and destructured', () => {
    for (const name of NAMES) {
      const half = Math.ceil(name.length / 2);
      for (const code of [`f().${name};`, `f().${name}(1);`, `const o = f(); o.${name}(1);`, `f()['${name}'];`, `f()[\`${name}\`];`, `f()['${name.slice(0, half)}' + '${name.slice(half)}'](1);`, `const { ${name}: q } = f();`, `const { ['${name}']: q } = f();`]) {
        refused(`${HEAD}it('a', () => { ${code} expect(f()).toBe(1); });\n`, new RegExp(`${name}|computed`));
      }
    }
  });
  it('positive control: the same words as plain names that are not members are still accepted', () => {
    expect(probs(`${HEAD}import { getState, extend } from '../src/store.js';\nit('a', () => { const mocked = getState(); expect(extend(mocked)).toBe(1); });\n`)).toEqual([]);
  });
});

describe('(5) the vitest bindings are only callees or the object of an allowed member', () => {
  it('never stored, passed, spread, returned, destructured, aliased or exported', () => {
    for (const name of ['vi', 'expect', 'it', 'test', 'describe', 'beforeAll', 'afterAll', 'beforeEach', 'afterEach']) {
      for (const code of [`const x = ${name};`, `let x; x = ${name};`, `f(${name});`, `f(...[${name}]);`, `const l = [${name}];`, `const o = { ${name} };`, `const o = { k: ${name} };`, `const h = () => ${name};`, `const h = () => { return ${name}; };`, `const { length } = ${name};`, `const [x] = [${name}];`,
        `const h = (a = ${name}) => a;`, `typeof ${name};`, `f(${name} ?? 1);`, `new ${name}();`, `${name}\`x\`;`, `class C extends ${name} {}`]) {
        refused(`${HEAD}${code}${TAIL}`, new RegExp(`${name} \\(from vitest\\)`));
      }
    }
    refused(`import { expect } from 'vitest';\nexport { expect };\n`, /may not export|from an import/, 'test/helpers/h.ts');
    refused(`import { expect } from 'vitest';\nexport default expect;\n`, /expect/, 'test/helpers/h.ts');
    refused(`import { expect as e, it } from 'vitest';\nit('a', () => { e(f()).toBe(1); });\n`, /another name|plain name/);
    refused(`import * as v from 'vitest';\nv.it('a', () => { v.expect(1).toBe(1); });\n`, /named imports/);
    refused(`const { expect: e, it } = require('vitest');\nit('a', () => { e(1).toBe(1); });\n`, /require\('vitest'\)/, 'test/a.test.cjs');
    refused(`const v = require('vitest');\nv.it('a', () => { v.expect(1).toBe(1); });\n`, /require\('vitest'\)/, 'test/a.test.cjs');
  });
});

describe('(6) and (7) wording', () => {
  it('the leaf no longer says a dependency is importable', () => {
    const src = readFileSync(join(import.meta.dirname, '..', 'src', 'create', 'test-rules.ts'), 'utf8');
    expect(src).not.toMatch(/a name in the service's own `dependencies`/);
    expect(src).not.toMatch(/that service's own dependency names/);
  });
  it('the prompt states the new limits: no helper returning an expect chain, the asymmetric-matcher rule, no expect.extend, vi results as statements', () => {
    const prompt = testsInstructions({ ext: 'ts' });
    expect(prompt).toMatch(/helper/i);
    expect(prompt).toMatch(/never return an expect/i);
    expect(prompt).toMatch(/expect\.any\(\.\.\.\).*only .*argument/i);
    expect(prompt).toMatch(/no extend/);
    expect(prompt).toMatch(/closeTo/);
    expect(prompt).toMatch(/expect\.assertions\(n\) and expect\.hasAssertions\(\) only as statements/);
    expect(prompt).toMatch(/vi\.useFakeTimers\(\); as a statement/);
    expect(prompt).not.toMatch(/only as a statement \(or awaited or returned\)/);
  });
});
