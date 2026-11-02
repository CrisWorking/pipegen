// v0.2 Plan D, D7 (preflight S9, item 9): the rules for AI-written starter tests are a real parse and a tree walk, not a denylist of words.
import { describe, expect, it } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { analyzeTestFile, dependencyNames, packageModuleType, fileStats, starterOwner, starterTestFileProblems, starterTestPathProblem } from '../src/create/test-rules.js';
import { withActiveVault } from '../src/util/known-values.js';

const HEAD = "import { describe, it, expect } from 'vitest';\nconst f = (...a) => a, h = f, add = f, p = f;\n";
const ok = (body: string, head = HEAD): string => `${head}${body}\n`;
const CJS = "const { describe, it, expect } = require('vitest');\nconst f = (...a) => a, h = f, add = f, p = f;\n";
const T = "it('works', () => { expect(add(1, 2)).toBe(3); });";
const probs = (src: string, rel = 'test/a.test.ts', deps: string[] = []): string[] => analyzeTestFile(rel, src, deps).problems;
const refused = (src: string, re: RegExp, rel = 'test/a.test.ts', deps: string[] = []): void => {
  const p = probs(src, rel, deps);
  expect(p.length, src).toBeGreaterThan(0);
  expect(p.join(' | '), src).toMatch(re);
};

describe('paths (S9)', () => {
  it('only {test,tests,__tests__}/**/*.test.{ts,js,mjs,cjs} and test/helpers/** pass', () => {
    for (const p of ['test/a.test.ts', 'tests/a.test.js', '__tests__/x/a.test.mjs', 'test/a.b.test.cjs', 'test/helpers/h.ts', 'test/helpers/deep/h.mjs']) expect(starterTestPathProblem(p), p).toBeNull();
    for (const p of ['a.test.ts', 'src/a.test.ts', 'test/a.spec.ts', 'test/a.test.tsx', 'test/a.test.jsx', 'test/a.test.mts', 'test/a.test.d.ts', 'test/a.ts', 'test/helpers/h.json', 'tests/helpers/h.ts', '__tests__/helpers/h.ts', 'Test/a.test.ts', 'test/.hidden/a.test.ts', 'test/node_modules/a.test.ts', 'test/../a.test.ts', 'test//a.test.ts', 'test/a b.test.ts', 'test/.test.ts']) expect(starterTestPathProblem(p), p).not.toBeNull();
  });
  it('a vitest or vite config file is refused by name', () => {
    for (const p of ['test/vitest.config.test.ts', 'tests/vite.config.test.js', 'test/helpers/vitest.config.ts', 'test/helpers/vite.config.mjs', 'test/helpers/vitest.workspace.js']) expect(starterTestPathProblem(p), p).toMatch(/config|protected/);
  });
  it('the owner is the deepest service that holds the path', () => {
    expect(starterOwner('api/test/a.test.ts', ['', 'api'])).toEqual({ root: 'api', rel: 'test/a.test.ts' });
    expect(starterOwner('test/a.test.ts', ['', 'api'])).toEqual({ root: '', rel: 'test/a.test.ts' });
    expect(starterOwner('api/test/a.test.ts', ['', 'web'])).toBeNull();
    expect(starterOwner('web/src/test/a.test.ts', ['web'])).toBeNull();
    expect(starterOwner('x/tests/a.test.ts', ['api'])).toBeNull();
  });
  it('dependencyNames reads only valid names under dependencies, never devDependencies', () => {
    expect(dependencyNames('{"dependencies":{"express":"^4","@a/b":"1","BAD NAME":"1","../x":"1"},"devDependencies":{"vitest":"5"}}')).toEqual(['express', '@a/b']);
    expect(dependencyNames('not json')).toEqual([]);
    expect(dependencyNames('{"dependencies":[1]}')).toEqual([]);
  });
});

describe('a good file passes, with its counts', () => {
  it('counts tests and the assertions written directly in them', () => {
    const r = analyzeTestFile('test/a.test.ts', ok(`const x = f, y = f;\n${T}\ndescribe('g', () => {\n  it('a', async () => { await expect(p()).resolves.toBe(1); expect(2).toBe(2); expect(x).not.toBe(2); });\n  it.concurrent('b', () => expect(y()).toEqual({ a: 1 }));\n});`), []);
    expect(r).toEqual({ problems: [], tests: 3, assertions: 4, parsed: true });   // expect(2).toBe(2) is on a literal and does not count
  });
  it('TypeScript syntax (types, as, !, generics, interfaces) is read', () => {
    const src = ok("import type { Foo } from '../src/foo.js';\ninterface I { a: number }\ntype K = keyof I;\nconst x: Foo = { a: 1 } as Foo;\nfunction id<T extends object>(v: T, w?: string): T { return v; }\nit('t', () => { expect(id<I>(x!).a as number).toBe(1); });");
    expect(probs(src, 'test/a.test.ts', [])).toEqual([]);
  });
  it('node:assert and node:test files count assert calls', () => {
    const src = "import assert from 'node:assert/strict';\nimport { strictEqual } from 'node:assert';\nimport { test } from 'node:test';\nconst f = () => 1;\ntest('a', () => { assert.equal(f(), 1); });\ntest('b', () => { strictEqual(f(), 2); assert(f()); });\n";
    expect(analyzeTestFile('test/a.test.js', src, [])).toMatchObject({ problems: [], tests: 2, assertions: 3 });
  });
  it('a CommonJS file with require of an allowed module passes', () => {
    const src = "const assert = require('node:assert');\nconst { it } = require('vitest');\nconst f = () => 1;\nit('a', () => { assert.strictEqual(f(), 1); });\n";
    expect(probs(src, 'test/a.test.cjs')).toEqual([]);
  });
  it('relative imports inside the service, the service\'s own dependencies and the allowed built-ins pass', () => {
    const src = ok("import path from 'node:path';\nimport { fileURLToPath } from 'node:url';\nimport util from 'node:util';\nimport http from 'node:http';\nimport express from 'express';\nimport request from 'supertest/lib/x';\nimport { sub } from '../src/add.js';\nimport hh from './helpers/h.js';\nimport { s } from '@scope/pkg/sub';\nit('a', () => { expect(sub(1, 1)).toBe(2); });");
    expect(probs(src, 'test/a.test.ts', ['express', 'supertest', '@scope/pkg'])).toEqual([]);
  });
  it('helpers need no test; a helper with an import outside the allowlist is still refused', () => {
    expect(probs("export const make = (n) => ({ n });\n", 'test/helpers/h.js')).toEqual([]);
    refused("import fs from 'node:fs';\nexport const x = fs;\n", /node:fs/, 'test/helpers/h.js');
  });
  it('urls to localhost, 127.0.0.1 and example.com pass (with a literal port)', () => {
    expect(probs(ok("it('u', () => { const port = 3000; expect(f('http://localhost:3000/x')).toBe(f('http://127.0.0.1:8080/a?b=https://example.com', 'http://[::1]:1/')); expect('https://example.com/a').toBeTruthy(); });"))).toEqual([]);
  });
});

describe('validate: imports are an allowlist with string-literal specifiers', () => {
  it('require/import with a non-literal specifier is refused', () => {
    refused(ok("const m = 'child' + '_process';\nit('a', async () => { const x = await import(m); expect(x).toBe(1); });"), /not a plain string/);
    refused(`${CJS}const r = require('chi' + 'ld_process');\nit('a', () => { expect(r).toBe(1); });`, /not a plain string/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { const x = require(name); expect(x).toBe(1); });`, /not a plain string/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { const x = require(\`\${y}\`); expect(x).toBe(1); });`, /not a plain string/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { const x = require(); expect(x).toBe(1); });`, /require\(\) takes one/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { const r = require; expect(r('x')).toBe(1); });`, /require can only be called/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { const g = (function () { return this; })(); expect(g['ev' + 'al']).toBe(1); });`, /this is not accepted|eval/, 'test/a.test.cjs');
    refused(ok("it('a', async () => { const x = await import('node:path', { with: { type: 'json' } }); expect(x).toBe(1); });"), /options/);
  });
  it('an import outside the allowlist is refused, whatever the form', () => {
    for (const spec of ['node:fs', 'fs', 'child_process', 'node:child_process', 'node:vm', 'worker_threads', 'node:worker_threads', 'node:net', 'node:module', 'node:os', 'http', 'node:https', 'lodash', 'file:///etc/passwd', '/etc/passwd', 'data:text/javascript,1', 'vitest/config', 'vitest/node', '../../outside.js', '../../../x', './a?worker', './a?raw', '../node_modules/x/index.js', './.hidden/x.js', '..\\x']) {
      refused(ok(`import x from ${JSON.stringify(spec)};\n${T}`), /imports|allowlist|dependencies/, 'test/a.test.ts', []);
      refused(ok(`export * from ${JSON.stringify(spec)};\n${T}`), /imports|may not export/, 'test/a.test.ts', []);
      refused(ok(`it('a', async () => { const m = await import(${JSON.stringify(spec)}); expect(m).toBe(1); });`), /imports/, 'test/a.test.ts', []);
      refused(`${CJS}it('a', () => { const m = require(${JSON.stringify(spec)}); expect(m).toBe(1); });`, /imports/, 'test/a.test.cjs', []);
    }
  });
  it('a package that is not in the service\'s dependencies is refused; a builtin name in dependencies does not help', () => {
    refused(ok(`import x from 'lodash';\n${T}`), /lodash.*allowlist/, 'test/a.test.ts', ['express']);
    refused(ok(`import x from 'fs';\n${T}`), /"fs"/, 'test/a.test.ts', ['fs']);
    refused(ok(`import x from 'express-evil';\n${T}`), /express-evil/, 'test/a.test.ts', ['express']);
    refused(ok(`import x from 'express/../../x';\n${T}`), /imports/, 'test/a.test.ts', ['express']);
  });
  it('no re-export at all in a test file', () => {
    refused(ok(`export { join } from 'node:path';\n${T}`), /may not export/);
    refused(ok(`export * from './helpers/h.js';\n${T}`), /may not export/);
  });
  it('named imports of vitest are a fixed set, with no alias, no namespace and no default', () => {
    refused(`import { it, expect, onTestFinished } from 'vitest';\nit('a', () => { expect(f()).toBe(1); });`, /vitest/);
    refused(`import * as v from 'vitest';\nv.it('a', () => { v.expect(f()).toBe(1); });`, /vitest/);
    refused(`import v from 'vitest';\nv.it('a', () => {});`, /vitest/);
    refused(`import { it as t, expect } from 'vitest';\nt('a', () => { expect(f()).toBe(1); });`, /another name/);
    refused(`import { it, expect } from 'node:test';\nit('a', () => { expect(f()).toBe(1); });`, /node:test/);
  });
  it('a specifier must be one string literal: a + of two literals is not accepted, even when it names an allowed module', () => {
    refused(ok(`import x from 'node:' + 'path';\n${T}`), /read as TypeScript/);
    refused(`${CJS}const pp = require('node:' + 'path');\nit('a', () => { expect(pp.sep).toBe('/'); });`, /not a plain string/, 'test/a.test.cjs');
    refused(ok("it('a', async () => { const p = await import('node:' + 'path'); expect(p.sep).toBe('/'); });"), /not a plain string/);
    expect(probs(ok("it('a', async () => { const p = await import(`node:path`); expect(p.sep).toBe('/'); });"))).toEqual([]);
  });
  it('import attributes are refused', () => {
    refused(ok(`import d from './d.json' with { type: 'json' };\n${T}`), /attributes/);
  });
});

describe('validate: eval, new Function, node:vm, worker_threads, process.binding, process.dlopen, module.createRequire', () => {
  const body = (code: string): string => ok(`it('a', async () => { ${code} expect(1 + f()).toBe(2); });`);
  it('eval and Function in every form', () => {
    for (const code of ['eval("1");', 'new Function("return 1")();', 'Function("return 1")();', '(0, eval)("1");', 'const e = eval; e("1");', 'x instanceof Function;', 'const { eval: ev } = { eval: 1 };']) refused(body(code), /eval|Function/);
  });
  it('globalThis and friends, also with computed keys (globalThis[\'ev\'+\'al\'])', () => {
    for (const code of ["globalThis['ev' + 'al']('1');", 'globalThis.eval("1");', 'global.process.binding("fs");', 'window.x;', 'self.x;', "const g = globalThis; g['ev' + 'al']('1');", 'Reflect.get(a, "b");']) refused(body(code), /globalThis|global|window|self|Reflect|eval/);
  });
  it('process other than a few reads, in every form (process.binding, process["binding"], dlopen, mainModule)', () => {
    for (const code of ['process.binding("fs");', "process['binding']('fs');", "process['bin' + 'ding']('fs');", 'process.dlopen(m, "x");', 'process.mainModule.require("fs");', 'process.getBuiltinModule("child_process");', 'process.exit(1);', 'process.kill(1);', 'const p = process;', 'process.chdir("/");', 'process.emit("x");']) refused(body(code), /process/);
    expect(probs(body('const a = process.env.X; const b = process.cwd(); const c = process.platform; process.nextTick(() => {});'))).toEqual([]);
  });
  it('module.createRequire, module, require.resolve and the constructor chains', () => {
    for (const code of ["module.createRequire('x');", 'module.require("fs");', 'const r = require.resolve("x");', '(() => {}).constructor("return 1")();', "[]['constructor']['constructor']('1')();", "({})['con' + 'structor'];", '({}).__proto__;', "Object.getOwnPropertyDescriptor(a, 'constructor');", 'const { constructor: C } = {};', 'arguments.callee.caller;']) refused(body(code), /module|require|constructor|__proto__|process|callee|caller/);
  });
  it('a computed key that can not be read statically is refused; a literal or arithmetic key is fine', () => {
    refused(body('const a = {}; const k = f(); a[k];'), /computed property/);
    refused(body('const a = {}; const k = f(); const { [k]: v } = a;'), /destructured key/);
    expect(probs(body("const a = {}; const k = f(); a['x']; a[0]; a[1 + 2]; a[-1]; a[`k`]; const o = { [k]: 1 };"))).toEqual([]);
  });
  it('node:vm, worker_threads, child_process, snapshots, import.meta other than url, vi.mock', () => {
    refused(ok(`import vm from 'node:vm';\n${T}`), /node:vm/);
    refused(ok(`import { Worker } from 'worker_threads';\n${T}`), /worker_threads/);
    refused(body("expect(x).toMatchSnapshot();"), /toMatchSnapshot/);
    refused(body("expect(x).toMatchFileSnapshot('/tmp/x');"), /toMatchFileSnapshot/);
    refused(body("import.meta.resolve('fs');"), /import\.meta/);
    refused(body("import.meta.glob('./*');"), /import\.meta/);
    refused(body("const m = import.meta;"), /import\.meta/);
    expect(probs(body('const u = import.meta.url; const d = import.meta.dirname;'))).toEqual([]);
    expect(probs(body("vi.mock('../src/add.js'); vi.mock('./x.js', () => ({}));"))).toEqual([]);
    for (const c of ["vi.mock('child_process');", "vi.mock('node:fs');", "vi.mock(name);", "vi.mock('../../outside');", "vi.mock();", "vi.doMock('x');", "await vi.importActual('child_process');", "vi.resetModules();", 'const v = vi;', "vi['mock']('x');"]) refused(body(c), /vi/);
    expect(probs(body('const fn = vi.fn(); vi.spyOn(a, "b"); vi.useFakeTimers(); vi.advanceTimersByTime(5); vi.useRealTimers(); vi.stubEnv("A", "b");'))).toEqual([]);
  });
  it('setTimeout with a string, new Worker, WebAssembly, XMLHttpRequest are refused or harmless', () => {
    refused(body('new Worker("x");'), /Worker/);
    refused(body('WebAssembly.compile(b);'), /WebAssembly/);
  });
  it('a banned name as a string is refused', () => {
    refused(body("const n = 'constructor';"), /constructor/);
    refused(body('const n = `eval`;'), /eval/);
    refused(body("const n = 'child_process';"), /child_process/);
  });
});

describe('validate: urls', () => {
  const t = (s: string): string => ok(`it('u', () => { const port = 1; expect(f(${s})).toBeTruthy(); });`);
  it('an external URL is refused, localhost allowed', () => {
    refused(t("'https://evil.example/x'"), /evil\.example/);
    refused(t("'http://example.com.evil.net/x'"), /example\.com\.evil\.net/);
    refused(t("'http://localhost@evil.net/'"), /user name/);
    refused(t("'http://localhost.evil.net/'"), /localhost\.evil\.net/);
    refused(t("'//evil.net/x'"), /evil\.net/);
    refused(t("'ftp://evil.net/x'"), /evil\.net/);
    refused(t("'file:///etc/passwd'"), /URL host/);
    refused(t("'http://' + host"), /URL host|bare URL scheme|built at run time/);
    refused(t('`http://${host}/x`'), /built at run time/);
    refused(t("'h\\x74tp://evil.net'"), /evil\.net/);
        expect(probs(t("'http://localhost:3000/x'"))).toEqual([]);
    expect(probs(t("'http://127.0.0.1/x'"))).toEqual([]);
    refused(t('`http://localhost:${port}/x`'), /built at run time/);   // a run-time port can not be proven to be the test's own server
    expect(probs(t("'http://[::1]:3000/x'"))).toEqual([]);
  });
  it('a url in a comment is not code and does not count', () => {
    expect(probs(ok(`// see https://evil.example/doc\n${T}`))).toEqual([]);
  });
});

describe('validate: .skip, .only and the other ways not to run a test', () => {
  const t = (code: string): string => ok(`${code}\n${T}`);
  it('skip, only, todo, skipIf, runIf, fails, each, for and the x/f forms, also computed and destructured', () => {
    for (const code of ["it.skip('a', () => { expect(1 + f()).toBe(1); });", "it.only('a', () => { expect(f()).toBe(1); });", "it.todo('a');", "describe.skip('g', () => {});", "describe.only('g', () => {});", "it.skipIf(x)('a', () => { expect(f()).toBe(1); });", "it.runIf(x)('a', () => { expect(f()).toBe(1); });", "it.fails('a', () => { expect(f()).toBe(1); });", "it.each([1])('a', (n) => { expect(f(n)).toBe(1); });", "test.for([1])('a', () => {});",
      "xit('a', () => {});", 'xdescribe("a", () => {});', 'fit("a", () => {});', 'fdescribe("a", () => {});', 'xtest("a", () => {});',
      "it['sk' + 'ip']('a', () => {});", "it['only']('a', () => {});", "const { skip } = it;", "const { skip: s } = it;",
      "it('a', { skip: true }, () => { expect(f()).toBe(1); });", "it('a', { only: true }, () => { expect(f()).toBe(1); });", "it('a', { retry: 3 }, () => { expect(f()).toBe(1); });", "it('a', { todo: true }, () => {});", "it('a', () => { ctx.skip(); expect(f()).toBe(1); });"]) {
      refused(t(code), /skip|only|todo|focus|retry|repeat|x[a-z]+|f[a-z]+|each|fails|for|test form|plain string|written as|assertion/i);
    }
    expect(probs(t("it['sk' + 'ip']('a', () => {});")).join(' ')).toMatch(/skip/);
    expect(probs(t('it.skip("a", () => {});')).join(' ')).toMatch(/\.skip/);
  });
  it('a pytest skip in a python file is not a starter-test path at all', () => {
    expect(starterTestPathProblem('tests/test_a.py')).not.toBeNull();
    expect(starterTestPathProblem('tests/conftest.py')).not.toBeNull();
    expect(starterTestPathProblem('tests/fixtures/data.py')).not.toBeNull();
  });
});

describe('validate: assertions and the shape of a test', () => {
  it('a test with no expect/assert is refused', () => {
    refused(ok("it('a', () => { const x = f(); });"), /no assertion/);
    refused(ok("it('a', () => { expect(f()); });"), /no assertion/);
    refused(ok("it('a', () => { expect(f()).toBe; });"), /no assertion/);
    refused(ok("it('a', () => {});"), /no assertion/);
    refused(ok("it('a', () => { expect(1).toBe(1); });"), /no assertion/);
    refused(ok("it('a', () => { expect('x').toBe('x'); });"), /no assertion/);
    refused(ok("it('a', () => { if (x) { expect(f()).toBe(1); } });"), /no assertion/);
    refused(ok("it('a', () => { check(f()); });"), /no assertion/);
    refused(ok("it('a', () => { helper.expect(f()).toBe(1); });"), /no assertion/);
    refused("import assert from 'node:assert';\nimport { it } from 'vitest';\nit('a', () => { assert(true); });\n", /no assertion/);
    refused("import assert from 'node:assert';\nimport { it } from 'vitest';\nit('a', () => { assert.ok(1); });\n", /no assertion/);
  });
  it('every test of a file needs its own assertion', () => {
    const p = probs(ok(`${T}\nit('second', () => { const y = 1; });`));
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/"second"/);
  });
  it('a file with no test is refused, but only a .test. file', () => {
    refused(ok("describe('g', () => { const x = 1; });"), /no test/);
    refused(HEAD, /no test/);
    expect(probs('export const x = 1;\n', 'test/helpers/h.ts')).toEqual([]);
  });
  it('a test inside a loop, a condition, a function or a hook is refused (its count is not static)', () => {
    refused(ok(`for (const n of [1, 2]) { ${T} }`), /own in the file or directly inside describe/);
    refused(ok(`if (x) { ${T} }`), /own in the file/);
    refused(ok(`function ff() { ${T} }`), /own in the file/);
    refused(ok(`[1].forEach(() => { ${T} });`), /own in the file/);
    refused(ok(`describe('g', () => { for (;;) { ${T} } });`), /own in the file/);
    refused(ok(`it('a', () => { ${T} expect(f()).toBe(1); });`), /own in the file/);
    expect(probs(ok(`describe('g', () => { describe('h', () => { ${T}\n}); });`))).toEqual([]);
  });
  it('the test is it(name, () => {...}) with a plain name', () => {
    refused(ok("const body = () => { expect(f()).toBe(1); };\nit('a', body);"), /written as it/);
    refused(ok("it(name, () => { expect(f()).toBe(1); });"), /plain string as its name/);
    refused(ok("it('', () => { expect(f()).toBe(1); });"), /plain string as its name/);
    refused(ok("it('a', () => { expect(f()).toBe(1); }, 'slow');"), /written as it/);
    expect(probs(ok("it('a', () => { expect(f()).toBe(1); }, 5000);"))).toEqual([]);
    expect(probs(ok("it(`a`, async function () { await expect(f()).resolves.toBe(1); });"))).toEqual([]);
  });
  it('an unknown member of it or test is a form pipegen can not count', () => {
    refused(ok("it.extend({})('a', () => {});"), /can not count|extend/);
  });
});

describe('validate: unreadable input', () => {
  it('a file that does not parse is refused, with the line', () => {
    expect(probs('const = ;\n', 'test/a.test.js').join(' ')).toMatch(/does not parse as JavaScript near line 1/);
    expect(probs('it("a", () => {\n', 'test/a.test.ts').join(' ')).toMatch(/can not be read as TypeScript|does not parse/);
    expect(probs('import x from "a"\nwith (x) {}', 'test/a.test.mjs').join(' ')).toMatch(/parse/);
    expect(probs('import x from "vitest";', 'test/a.test.cjs').join(' ')).toMatch(/parse/);
  });
  it('a file over 50 KB, with a NUL byte, or not text is refused unparsed', () => {
    expect(probs(`${'//x\n'.repeat(20_000)}`)).toEqual([expect.stringMatching(/over 50 KB/)]);
    expect(probs(ok(`${T}\n// \0`))).toEqual([expect.stringMatching(/NUL/)]);
    expect(probs(5 as unknown as string)).toEqual([expect.stringMatching(/not text/)]);
  });
  it('a deeply nested file is refused, never a crash', () => {
    expect(probs(`${HEAD}it('a', () => { expect(${'['.repeat(500)}${']'.repeat(500)}).toBe(1); });`)).toEqual([expect.stringMatching(/nested too deeply/)]);
    expect(probs(`${HEAD}it('a', () => { expect(${'['.repeat(30_000)}${']'.repeat(30_000)}).toBe(1); });`).length).toBeGreaterThan(0);
  });
  it('a TypeScript namespace (which sucrase would drop silently) is refused', () => {
    refused(ok("namespace A { export const x = eval('1'); }\n" + T), /namespace/);
    refused(ok("declare module 'x' { }\n" + T), /namespace or module/);
    refused(ok("enum E { A }\n" + T), /enum/);
    refused(ok("export const enum E { A }\n" + T), /enum/);
    refused(ok("export namespace A { }\n" + T), /namespace/);
    expect(probs(ok(`const namespace = 1;\nconst enumerate = 2;\n${T}`)).join(' ')).not.toMatch(/namespace or module|enum/);
  });
  it('TypeScript import-equals is read as a require', () => {
    refused(ok("import cp = require('child_process');\n" + T), /child_process/);
  });
  it('an unused import of a banned module is still refused (sucrase keeps unused imports)', () => {
    refused(ok("import { execSync } from 'node:child_process';\n" + T), /node:child_process/);
  });
  it('the stats are null for a file that does not parse and counted for one that does', () => {
    expect(fileStats('test/a.test.js', 'const =;')).toBeNull();
    expect(fileStats('test/a.test.ts', ok(T))).toEqual({ tests: 1, assertions: 1 });
  });
});

describe('what the rules show goes through the vault', () => {
  it('a vault value in a specifier, a test name, a URL host or a property name is never shown', () => {
    const value = 'zzvaultvalue98765qwerty';
    const vault = new SecretVault();
    vault.set('K_TEST', value);
    const shown = withActiveVault(vault, () => [
      ...probs(ok(`import x from '${value}-pkg';\n${T}`)),
      ...probs(ok(`it('${value}', () => { const a = 1; });`)),
      ...probs(ok(`it('u', () => { expect('http://${value}.evil.net/').toBeTruthy(); });`)),
      ...probs(ok(`it('u', () => { expect(a['${value}']).toBeTruthy(); a.${value}.skip; });`)),
      ...probs(ok(`it('u', () => { const o = { ${value}: 1, skip: 2 }; expect(o).toBe(1); });`)),
      ...probs(ok(`import x from '../${value}/../../x.js';\n${T}`)),
      ...starterTestFileProblems(`api/test/${value}.js`, 'x', { roots: ['api'], depsOf: () => [] }),
    ].join(' | '));
    expect(shown.length).toBeGreaterThan(0);
    expect(shown).not.toContain(value);
    expect(shown).not.toContain(value.slice(0, 10));
  });
});

describe('starterTestFileProblems (judge and guard share it)', () => {
  const o = { roots: ['', 'api'], depsOf: (r: string) => (r === 'api' ? ['express'] : []) };
  it('refuses a path that is not a starter-test path and uses the owning service\'s dependencies', () => {
    expect(starterTestFileProblems('src/a.test.ts', ok(T), o)[0]).toMatch(/not a path starter tests may use/);
    expect(starterTestFileProblems('api/test/a.test.ts', ok(`import e from 'express';\n${T}`), o)).toEqual([]);
    expect(starterTestFileProblems('test/a.test.ts', ok(`import e from 'express';\n${T}`), o).join(' ')).toMatch(/express/);
  });
});

// ---- security scan findings (coordinator ruling): globals are an allowlist, no network of its own, parse by module type ----
describe('security scan 1: calls and members on globals are an allowlist (reflection can not rebuild a banned name)', () => {
  const body = (code: string): string => ok(`it('a', async () => { const o = {}; ${code}; expect(1 + f()).toBe(2); });`);
  it('Object reflection, Reflect, Symbol, String.fromCharCode and friends are refused, also through an alias, a destructuring or a computed name', () => {
    for (const code of ["Object.getOwnPropertyDescriptor(o, 'x')", 'Object.getOwnPropertyDescriptors(o)', 'Object.getOwnPropertyNames(o)', 'Object.getOwnPropertySymbols(o)', 'Object.getPrototypeOf(o)', 'Object.setPrototypeOf(o, null)', "Object.defineProperty(o, 'x', {})", 'Object.defineProperties(o, {})',
      'Reflect.ownKeys(o)', 'Reflect.get(o, "x")', 'String.fromCharCode(99)', 'String.fromCodePoint(99)', 'Symbol.iterator', 'Symbol("x")', 'new Proxy(o, {})',
      'Object.entries(Object.getPrototypeOf(f))', 'const O = Object; O.getPrototypeOf(1)', 'const { getPrototypeOf } = Object', "Object['get' + 'PrototypeOf'](o)", 'const O = Object', 'const keys = [Object]', 'Object.create(null)', 'Object.groupBy(o, f)', 'JSON.foo', 'Number.foo', 'Date.prototype', 'Array.prototype', 'Promise.foo', 'URL.createObjectURL(o)', 'Boolean.x']) {
      refused(body(code), /Object|Reflect|Symbol|String|Proxy|JSON|Number|Date|Array|Promise|URL|Boolean|getPrototypeOf|getOwn|define|fromChar|list/);
    }
  });
  it('the pure globals tests need still work', () => {
    const code = "JSON.parse(JSON.stringify({ a: 1 })); Math.max(1, 2); Math.floor(1.5); Number.isInteger(1); Number(1); String(1); Boolean(1); Array.isArray([]); Array.from([1]); Object.keys({}); Object.entries({}); Object.values({}); Object.assign({}, {}); Object.freeze({}); Object.hasOwn({}, 'a'); Object.fromEntries([]); await Promise.all([]); Promise.resolve(1); Date.now(); new Date(); new URL('http://localhost/x'); setTimeout(() => {}, 1); console.log(1); new Map(); new Set(); new Error('x'); JSON['parse']('1'); Buffer.from('a'); structuredClone({}); [1] instanceof Array; expect(1 + f()).toBeInstanceOf(Date); parseInt('1'); encodeURIComponent('a')";
    expect(probs(ok(`it('a', async () => { ${code}; expect(f()).toBe(1); });`))).toEqual([]);
  });
  it('a free name that is declared nowhere in the file and not listed is refused; a declared one is fine', () => {
    for (const n of ['Deno', 'Bun', 'navigator', 'document', 'foo', 'Atomics', 'Intl', 'exports', 'SharedArrayBuffer', 'it2']) refused(ok(`it('a', () => { ${n}.x; expect(f()).toBe(1); });`), new RegExp(n));
    expect(probs(ok("function foo() { return 1; }\nclass K {}\nconst { q, ...rest } = { q: 1 };\nconst [r1, [r2]] = [1, [2]];\ntry { f(); } catch (err) { err.x; }\nit('a', (ctx) => { expect(foo() + q + r1 + r2 + rest.length + ctx.x + new K().x).toBe(1); });"))).toEqual([]);
    refused("import { it, expect } from 'vitest';\nit('a', () => { expect(f()).toBe(1); });\n", /f is a global/);
    refused("it('a', () => { expect(1 + 1 + f).toBe(1); });", /it is a global|expect is a global/);   // vitest names are imported, not free
  });
  it('vi may only fn, spyOn, the timer helpers, stubEnv and mock of a relative path', () => {
    refused(body("vi.stubGlobal('x', 1)"), /vi\.stubGlobal/);
    refused(body("vi.hoisted(() => 1)"), /vi\.hoisted/);
  });
});

describe('security scan 2: no network of its own', () => {
  const body = (code: string, head = "import http from 'node:http';\n"): string => `${HEAD}${head}it('a', async () => { const u = f(); const hh = f(); const o = {}; ${code}; expect(1 + f()).toBe(2); });\n`;
  it('fetch, WebSocket, EventSource and XMLHttpRequest are refused, also through globalThis', () => {
    for (const code of ["await fetch('http://localhost:1/')", "new WebSocket('ws://localhost:1')", "new EventSource('http://localhost:1')", 'new XMLHttpRequest()', "globalThis.fetch('http://localhost:1')", 'const g = fetch']) refused(body(code), /fetch|WebSocket|EventSource|XMLHttpRequest|globalThis/);
  });
  it('node:http: a server and requests to a literal local address pass', () => {
    const code = "const s = http.createServer((req, res) => { res.end('x'); }); s.listen(0); http.get('http://127.0.0.1:1/x'); http.get(`http://localhost:${1}/x`); http.get({ port: 1, path: '/' }); http.request({ hostname: 'localhost', port: 1, method: 'POST', headers: {} }); http.request({ host: '127.0.0.1', port: 1 }); http.request({ hostname: '::1' })";
    expect(probs(body(code))).toEqual([]);
  });
  it('node:http: any other target, an unreadable one, or any other member is refused', () => {
    for (const code of ["http.get('http://evil.net/x')", "http.get({ hostname: 'evil.net' })", 'http.get(u)', 'http.get({ hostname: hh })', 'http.get({ ...o })', "http.request({ socketPath: '/var/run/x' })", "http.request({ hostname: 'localhost', agent: o })", "http.get('/x')", "http.get('http://' + hh)", "http.get('http://localhost@evil.net/')", 'http.get()', 'http.get(new URL(u))', 'http.Agent', 'http.globalAgent', 'http.ClientRequest', 'const g = http.get', 'http[`get`](u)', 'http.get', 'http.request(`${u}/x`)']) {
      refused(body(code), /http|URL|literal|user name|built/);
    }
  });
  it('node:http by name and by require follows the same rule', () => {
    expect(probs(body("get('http://127.0.0.1:1/'); request({ port: 1 });", "import { get, request, createServer } from 'node:http';\n"))).toEqual([]);
    refused(body("get('http://evil.net/')", "import { get } from 'node:http';\n"), /evil\.net/);
    refused(body("get(u)", "import { get } from 'node:http';\n"), /literal local address/);
    refused(body("const r = get", "import { get } from 'node:http';\n"), /can only be called/);
    refused(body("", "import { Agent } from 'node:http';\n"), /node:http/);
    refused(`${CJS}const http = require('node:http');\nit('a', () => { http.get(u); expect(f()).toBe(1); });`, /literal local address/, 'test/a.test.cjs');
    expect(probs(`${CJS}const http = require('node:http');\nit('a', () => { http.get({ port: 1 }); expect(f()).toBe(1); });`, 'test/a.test.cjs')).toEqual([]);
    refused(`${CJS}const { get } = require('node:http');\nit('a', () => { get(u); expect(f()).toBe(1); });`, /literal local address/, 'test/a.test.cjs');
  });
  it('joined strings are read whole before the URL check', () => {
    const t = (e: string): string => ok(`it('u', () => { const hh = f(); expect(f(${e})).toBeTruthy(); });`);
    for (const e of ["'ht' + 'tp://evil.net/x'", "'http:' + '//evil.net'", "'https' + '://' + hh", "'ws' + '://evil.net'", "`ht${'tp'}://evil.net`", "'a' + 'https://evil.net/x' + 'b'", "'https:'", "'wss://evil.net'", "'http://localhost' + '@evil.net'"]) refused(t(e), /URL|scheme|host|user name/);
    expect(probs(t("'http://127.0.0.1' + ':3000' + '/x'"))).toEqual([]);
    expect(probs(t("'http://localhost:' + 3000 + '/x'"))).toEqual([]);
  });
});

describe('security scan 3: parse by the package type, and no `this` in plain functions', () => {
  const body = (code: string): string => ok(`it('a', () => { ${code}; expect(f()).toBe(1); });`);
  it('this in a plain function is refused in every extension; arrows, class members and a module top level are fine', () => {
    for (const rel of ['test/a.test.ts', 'test/a.test.js', 'test/a.test.mjs']) {
      refused(body('const g = (function () { return this; })()'), /this inside a plain function/, rel);
      refused(`${HEAD}function t() { return this; }\nit('a', () => { expect(t()).toBe(1); });`, /this inside a plain function/, rel);
      refused(body('const o = { m() { return this; } }'), /this inside a plain function/, rel);
      refused(body('const o = { m: function () { return this; } }'), /this inside a plain function/, rel);
    }
    refused(`${CJS}const t = this;\nit('a', () => { expect(t).toBe(1); });`, /this at the top of a script/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { const g = (() => this)(); expect(g).toBe(1); });`, /top of a script/, 'test/a.test.cjs');
    expect(probs(body('const g = () => this; class K { m() { return this; } static s = this; x = this; static { this.q = 1; } }'), 'test/a.test.mjs')).toEqual([]);
  });
  it('.js follows the package.json type: a module, or both readings (a script-only reading is not trusted alone)', () => {
    const hidden = `${HEAD}const a = 1, b = 1;\na <!-- globalThis\nit('a', () => { expect(f()).toBe(1); });\n`;
    const r = (src: string, type: 'module' | 'commonjs') => analyzeTestFile('test/a.test.js', src, [], type);
    expect(r(hidden, 'module').problems.join(' ')).toMatch(/globalThis/);
    expect(r(hidden, 'commonjs').problems.join(' ')).toMatch(/globalThis/);   // the module reading sees what the script reading hides
    const sloppy = `${CJS}var o = 010;\nit('a', () => { expect(f()).toBe(o); });\n`;
    expect(r(sloppy, 'module').problems.join(' ')).toMatch(/does not parse/);
    expect(r(sloppy, 'commonjs').problems).toEqual([]);
    expect(r(HEAD + "it('a', () => { expect(f()).toBe(1); });\n", 'commonjs')).toMatchObject({ problems: [], tests: 1, assertions: 1 });
    expect(analyzeTestFile('test/a.test.cjs', `${CJS}const a = 1, b = 1;\na <!-- globalThis\nit('a', () => { expect(f()).toBe(1); });\n`, [], 'module').problems).toEqual([]);   // .cjs is a script by its name
  });
  it('packageModuleType reads "type" exactly', () => {
    expect(packageModuleType('{"type":"module"}')).toBe('module');
    for (const t of ['{"type":"commonjs"}', '{}', '{"type":"Module"}', 'x', 'null', '[]']) expect(packageModuleType(t), t).toBe('commonjs');
  });
  it('starterTestFileProblems passes the service type to the parse', () => {
    const sloppy = `${CJS}var o = 010;\nit('a', () => { expect(f()).toBe(o); });\n`;
    const o = { roots: ['api'], depsOf: () => [] as string[] };
    expect(starterTestFileProblems('api/test/a.test.js', sloppy, { ...o, typeOf: () => 'module' }).join(' ')).toMatch(/parse/);
    expect(starterTestFileProblems('api/test/a.test.js', sloppy, { ...o, typeOf: () => 'commonjs' })).toEqual([]);
    expect(starterTestFileProblems('api/test/a.test.js', sloppy, o)).toEqual([]);
  });
});

// ---- security scan, round 2 ----
describe('security scan round 2 / 1: the http binding is only ever the object of a member call', () => {
  const body = (code: string, head = "import http from 'node:http';\n"): string => `${HEAD}${head}it('a', async () => { const o = {}; ${code}; expect(1 + f()).toBe(2); });\n`;
  it('as a value, alias, argument, element, spread, destructuring, computed member or bare statement it is refused', () => {
    for (const code of ['const h2 = http', 'f(http)', 'const l = [http]', 'const m = { ...http }', 'const m = { http }', 'const { get } = http', "http['get']('http://127.0.0.1:1/')", "(0, http.get)('http://127.0.0.1:1/')", 'http', "const g = http.get", "http.get.call(o, 'http://127.0.0.1:1/')", 'f(http.get)', 'const e = http.createServer', 'return http', 'new http.Agent()', 'http.get ? 1 : 2']) {
      refused(body(code), /node:http|http\./);
    }
    expect(probs(body("http.get('http://127.0.0.1:1/', () => 1); http.request({ port: 1 }); const srv = http.createServer(() => {}); srv.listen(0)"))).toEqual([]);
    expect(probs(body("ns.get('http://127.0.0.1:1/')", "import * as ns from 'node:http';\n"))).toEqual([]);
    refused(body('f(ns)', "import * as ns from 'node:http';\n"), /never as a value/);
  });
  it('named imports and require destructuring can only be called directly', () => {
    for (const code of ['const g = get', 'f(get)', 'const l = [request]', 'createServer']) refused(body(code, "import { get, request, createServer } from 'node:http';\n"), /only be called|node:http/);
    refused(`${CJS}const { get: g } = require('node:http');\nit('a', () => { f(g); expect(f()).toBe(1); });`, /only be called/, 'test/a.test.cjs');
    refused(`${CJS}const { get: g } = require('node:http');\nit('a', () => { g(u); expect(f()).toBe(1); });`, /local address/, 'test/a.test.cjs');
  });
  it('require is only the init of a top-level const, and import() never takes node:http', () => {
    refused(`${CJS}it('a', () => { const h = require('node:path'); expect(h.sep).toBe('/'); });`, /top of the file/, 'test/a.test.cjs');
    refused(`${CJS}it('a', () => { expect(require('node:path').sep).toBe('/'); });`, /top of the file/, 'test/a.test.cjs');
    refused(`${CJS}const x = f() || require('node:path');\nit('a', () => { expect(x).toBe(1); });`, /top of the file/, 'test/a.test.cjs');
    refused(`${CJS}if (f()) { var q = require('node:path'); }\nit('a', () => { expect(q).toBe(1); });`, /top of the file/, 'test/a.test.cjs');
    refused(body("const m = await import('node:http'); m.get(u)", ''), /import\(\)/);
    refused(body("const m = await import(`node:http`)", ''), /import\(\)/);
    expect(probs(`${CJS}const pth = require('node:path');\nit('a', () => { expect(pth.sep).toBe('/'); });`, 'test/a.test.cjs')).toEqual([]);
    expect(probs(body("const m = await import('node:path'); expect(m.sep).toBe('/')", ''))).toEqual([]);
  });
});

describe('security scan round 2 / 2: the other arguments of an http call', () => {
  const body = (code: string): string => `${HEAD}import http from 'node:http';\nit('a', async () => { const o = {}; const args = []; ${code}; expect(1 + f()).toBe(2); });\n`;
  const L = "'http://127.0.0.1:1/'";
  it('after a URL only options (with the same rules) and a callback may follow', () => {
    for (const code of [`http.get(${L}, () => 1)`, `http.get(${L}, (res) => { res.resume(); })`, `http.get(${L}, { headers: {}, method: 'GET' }, () => 1)`, `http.get(${L}, { hostname: 'localhost' })`, 'http.get({ port: 1 }, () => 1)', 'http.get({ port: 1 })']) expect(probs(body(code)), code).toEqual([]);
    for (const code of [`http.get(${L}, { hostname: 'evil.net' })`, `http.get(${L}, { host: 'evil.net' }, () => 1)`, `http.get(${L}, { agent: o })`, `http.get(${L}, { ...o })`, `http.get(${L}, o)`, `http.get(${L}, 5)`, `http.get(${L}, 'http://evil.net/')`, `http.get(${L}, () => 1, 1)`, `http.get(${L}, () => 1, () => 1)`, `http.get(${L}, ...args)`, `http.get(${L}, {}, {})`,
      'http.get({ port: 1 }, { host: "evil.net" })', 'http.get({ port: 1 }, o)', 'http.get({ port: 1 }, () => 1, 1)', 'http.get({ port: 1 }, 5)', 'http.get({ port: 1 }, ...args)', "http.get('http://example.com/')"]) refused(body(code), /local address|http/);
  });
});

describe('security scan round 2 / 3: reserved names can not be declared, so no scope can shadow a listed global', () => {
  const body = (code: string, head = ''): string => `${HEAD}${head}it('a', async () => { const o = {}; ${code}; expect(1 + f()).toBe(2); });\n`;
  it('a nested variable, function, class, parameter, catch or destructured name that is listed is refused', () => {
    for (const code of ['function g(fetch) { return fetch(1); } g(f)', 'const g = (Object) => Object.getPrototypeOf(1); g(f)', 'try { f(); } catch (Reflect) { Reflect.ownKeys(o); }', '{ const Object = o; Object.getPrototypeOf(1); }', 'class Map {}', 'const { JSON } = o', 'let process = 1', 'function Math() {}', 'const [Symbol] = [1]', 'const { a: Date = 1 } = o', 'function g(...Buffer) {} g()', 'const __dirname = 1', 'const __x = 1', 'const Function = 1', 'const globalThis = 1', 'const fetch = f', 'const require = f', 'const vi = f', 'const expect = f', 'const it = f', 'const describe = f', 'const test = f', 'const module = 1', 'const exports = 1', 'const constructor = 1', 'const undefined = 1', 'const console = f', 'const URL = f', 'const Promise = f', 'const parseInt = f']) {
      refused(body(code), /reserves|declares/);
    }
    refused(body('', "import Object from 'express';\n"), /reserves/, 'test/a.test.ts', ['express']);
    refused(body('', "import { Map } from 'express';\n"), /reserves/, 'test/a.test.ts', ['express']);
  });
  it('an API name is bound once, by importing it; declaring it again anywhere is refused', () => {
    refused(body('function g(expect) { return expect; } g(f)'), /declared again/);
    refused(body('const http = f', "import http from 'node:http';\n"), /declared again/);
    refused(body('function g(http) { return http; } g(f)', "import http from 'node:http';\n"), /declared again/);
    refused(`import assert from 'node:assert';\nimport { it, expect } from 'vitest';\nconst f = () => 1;\nit('a', () => { const assert = f; assert(f()); expect(f()).toBe(1); });\n`, /declared again|reserves/);
    refused(`${CJS}const { it: it2 } = require('vitest');\nfunction g(describe) { return describe; }\nit('a', () => { expect(f()).toBe(1); });`, /declared again|reserves/, 'test/a.test.cjs');
    expect(probs(`import assert, { strictEqual } from 'node:assert';\nimport { it } from 'vitest';\nconst f = () => 1;\nit('a', () => { assert.equal(f(), 1); strictEqual(f(), 1); });\n`)).toEqual([]);
  });
  it('an ordinary name is fine, in any scope', () => {
    expect(probs(body('const name = 1, status = 2, items = [3]; function helper(count, ...rest) { return count; } try { f(); } catch (err) { err.x; } class Box { m(v) { return v; } } helper(name + status + items.length + new Box().m(1))'))).toEqual([]);
  });
});

describe('security scan round 2 / 4: scheme, host and port are written out, and parsed as a URL', () => {
  const t = (e: string): string => ok(`it('u', () => { const port = f(), host = f(), scheme = f(), p = f(); expect(f(${e})).toBeTruthy(); });`);
  it('a run-time piece in the scheme, the host or the port is refused; in the path it is fine', () => {
    for (const e of ['`http://localhost:${port}/x`', '`http://${host}/x`', '`http://localhost${port}/x`', '`${scheme}://localhost/x`', '`http://127.0.0.1:${port}`', "'http://localhost:' + port", "'http://localhost' + ':' + port + '/x'", "'http://' + host + '/x'", '`http://[::1]:${port}/`', '`http://localhost:80${port}/`']) refused(t(e), /built at run time|URL host|can not read|bare URL/);
    for (const e of ['`http://localhost:3000/${p}`', "'http://localhost:3000/' + p", '`http://127.0.0.1/a?b=${p}#${p}`']) expect(probs(t(e)), e).toEqual([]);
  });
  it('the host is what the URL parser reads: localhost, 127.0.0.1, [::1] (and example.com in a plain string), nothing else', () => {
    for (const e of ["'http://localhost:3000/x'", "'http://LOCALHOST/x'", "'http://[::1]:80/x'", "'https://127.0.0.1:8443/x'", "'http://127.1/x'", "'http://0x7f.0.0.1/x'", "'http://example.com/x'"]) expect(probs(t(e)), e).toEqual([]);
    for (const e of ["'http://localhost%2eevil.net/x'", "'http://localhost.evil.net/x'", "'http://localhost:abc/x'", "'http://localhost:99999/x'", "'http://[::2]/x'", "'http://10.0.0.1/x'", "'http://169.254.169.254/'", "'http://evil.net:80" + "@localhost/x'", "'http://localhost@evil.net/x'", "'http://u" + ":p@localhost/x'", "'http://localhost\\\\@evil.net/x'", "'http://2130706434/x'", "'http://[::ffff:10.0.0.1]/x'", "'http:///evil.net'", "'http://'"]) refused(t(e), /URL|scheme/);
  });
  it('an http call takes only a local host, example.com included is not local', () => {
    const body = (a: string): string => `${HEAD}import http from 'node:http';\nit('a', () => { http.get(${a}); expect(f()).toBe(1); });\n`;
    for (const a of ["'http://localhost:1/x'", "'http://[::1]:1/x'", "'https://127.0.0.1:1/x'", "'http://LOCALHOST:1'"]) expect(probs(body(a)), a).toEqual([]);
    for (const a of ["'http://example.com/x'", "'http://localhost.evil.net/'", "'http://localhost%2eevil.net/'", "`http://localhost:${f()}/x`", "'//localhost/x'", "'localhost'", "'ftp://localhost/'"]) refused(body(a), /local address|URL|built/);
  });
});

// ---- every entry of every rule table is probed (written out here, not read from the module, so a deleted entry is caught) ----
describe('rule tables: every name', () => {
  const body = (code: string): string => ok(`it('a', () => { const o = {}; ${code}; expect(1 + f()).toBe(2); });`);
  const IDENTS = ['eval', 'Function', 'globalThis', 'global', 'window', 'self', 'Reflect', 'WebAssembly', 'Worker', 'SharedWorker', 'module', 'XMLHttpRequest', 'importScripts', 'fetch', 'WebSocket', 'EventSource', 'Symbol', 'Proxy'];
  const SKIP_IDENTS = ['xit', 'xtest', 'xdescribe', 'fit', 'ftest', 'fdescribe'];
  const SKIP_PROPS = ['skip', 'only', 'todo', 'skipIf', 'runIf', 'fails', 'each', 'for', 'fixme', 'retry', 'repeats'];
  const BAD_PROPS = ['constructor', '__proto__', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__', 'caller', 'callee', 'mainModule', 'binding', 'dlopen', '_load', '_linkedBinding', 'createRequire', 'require', 'getBuiltinModule', 'eval', 'Function',
    'toMatchSnapshot', 'toMatchInlineSnapshot', 'toMatchFileSnapshot', 'toThrowErrorMatchingSnapshot', 'toThrowErrorMatchingInlineSnapshot', 'getOwnPropertyDescriptor', 'getOwnPropertyDescriptors', 'getOwnPropertyNames', 'getOwnPropertySymbols', 'getPrototypeOf', 'setPrototypeOf', 'defineProperty', 'defineProperties', 'fromCharCode', 'fromCodePoint'];
  const BAD_STRINGS = ['constructor', '__proto__', 'eval', 'Function', 'binding', 'dlopen', 'mainModule', 'createRequire', 'getBuiltinModule', 'child_process'];
  it('banned identifiers are refused by name', () => { for (const n of IDENTS) refused(body(`${n};`), /can run code or reach what the checks cover/); });
  it('skip and focus identifiers are refused by name', () => { for (const n of SKIP_IDENTS) refused(body(`${n}('a', () => {});`), /skips or focuses tests/); });
  it('skip members are refused as a member, as a computed key and as an option', () => {
    for (const n of SKIP_PROPS) {
      refused(body(`o.${n};`), new RegExp(`\\.${n} skips, focuses or repeats`));
      refused(body(`o['${n}'];`), new RegExp(`\\.${n} skips, focuses or repeats`));
      refused(body(`const w = { ${n}: 1 };`), new RegExp(`the name "${n}" is refused`));
      refused(body(`const w = { '${n}': 1 };`), new RegExp(`the name "${n}" is refused`));
    }
  });
  it('banned members are refused as a member, as a computed key and as an object key', () => {
    for (const n of BAD_PROPS) {
      refused(body(`o.${n};`), new RegExp(`\\.${n} is refused`));
      refused(body(`o['${n}'];`), new RegExp(`\\.${n} is refused`));
      refused(body(`const w = { ${n}: 1 };`), new RegExp(`the name "${n}" is refused`));
    }
  });
  it('banned strings are refused as a literal and as a template', () => {
    for (const n of BAD_STRINGS) { refused(body(`const w = '${n}';`), new RegExp(`the string "${n}" is refused`)); refused(body(`const w = \`${n}\`;`), new RegExp(`the string "${n}" is refused`)); }
  });
  it('process: exactly six members', () => {
    for (const n of ['env', 'cwd', 'platform', 'nextTick', 'hrtime', 'uptime']) expect(probs(body(`process.${n};`)), n).toEqual([]);
    for (const n of ['exit', 'argv', 'version', 'versions', 'pid', 'stdout', 'kill', 'binding', 'dlopen', 'emit', 'on', 'chdir', 'umask', 'memoryUsage']) refused(body(`process.${n};`), new RegExp(`process\\.${n} is refused`));
  });
  it('vi: exactly the listed helpers', () => {
    for (const n of ['fn', 'spyOn', 'useFakeTimers', 'useRealTimers', 'advanceTimersByTime', 'advanceTimersToNextTimer', 'runAllTimers', 'runOnlyPendingTimers', 'setSystemTime', 'getMockedSystemTime', 'clearAllMocks', 'resetAllMocks', 'restoreAllMocks', 'isMockFunction', 'stubEnv', 'unstubAllEnvs']) expect(probs(body(`vi.${n};`)), n).toEqual([]);
    for (const n of ['stubGlobal', 'unstubAllGlobals', 'doMock', 'importActual', 'importMock', 'hoisted', 'resetModules', 'unmock', 'doUnmock', 'waitFor', 'dynamicImportSettled', 'mocked']) refused(body(`vi.${n};`), new RegExp(`vi\\.${n} is refused`));
  });
  it('import.meta: url, dirname and filename only', () => {
    for (const n of ['url', 'dirname', 'filename']) expect(probs(body(`import.meta.${n};`)), n).toEqual([]);
    for (const n of ['resolve', 'glob', 'env', 'hot', 'main']) refused(body(`import.meta.${n};`), /import\.meta can only/);
    refused(body('import.meta;'), /import\.meta can only/);
    expect(probs(body('const u = new.target;'))).not.toEqual(expect.arrayContaining([expect.stringMatching(/import\.meta/)]));
  });
  it('the members of each global: the allowed ones pass, the rest are refused', () => {
    const OK: Record<string, string[]> = {
      JSON: ['parse', 'stringify'], Math: ['max', 'min', 'floor', 'random', 'PI', 'abs'],
      Number: ['isInteger', 'isFinite', 'isNaN', 'isSafeInteger', 'parseFloat', 'parseInt', 'MAX_SAFE_INTEGER', 'MIN_SAFE_INTEGER', 'EPSILON', 'MAX_VALUE', 'MIN_VALUE', 'POSITIVE_INFINITY', 'NEGATIVE_INFINITY', 'NaN'],
      String: ['raw'], Boolean: [], Array: ['isArray', 'from', 'of'], Object: ['keys', 'values', 'entries', 'assign', 'freeze', 'fromEntries', 'is', 'hasOwn'],
      Promise: ['resolve', 'reject', 'all', 'allSettled', 'race', 'any', 'withResolvers'], Date: ['now', 'UTC', 'parse'], URL: [],
    };
    for (const [g, names] of Object.entries(OK)) {
      for (const n of names) expect(probs(body(`${g}.${n};`)), `${g}.${n}`).toEqual([]);
      if (g !== 'Math') refused(body(`${g}.zzNotListed;`), new RegExp(`${g}\\.zzNotListed is not on the list`));
    }
  });
  it('every listed free global is accepted, and an unlisted one is refused', () => {
    for (const n of ['undefined', 'NaN', 'Infinity', 'console', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'setImmediate', 'clearImmediate', 'queueMicrotask', 'structuredClone', 'Buffer', 'URLSearchParams', 'TextEncoder', 'TextDecoder', 'AbortController', 'AbortSignal', 'Headers', 'Request', 'Response', 'FormData', 'Blob', 'Map', 'Set', 'WeakMap', 'WeakSet', 'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError', 'AggregateError', 'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI', 'BigInt', 'Uint8Array', 'Uint16Array', 'Uint32Array', 'Int8Array', 'Int16Array', 'Int32Array', 'Float32Array', 'Float64Array', 'ArrayBuffer', 'DataView', 'performance', '__dirname', '__filename']) {
      expect(probs(body(`const w = ${n};`)), n).toEqual([]);
    }
    for (const n of ['Atomics', 'Intl', 'Iterator', 'Deno', 'Bun', 'navigator', 'crypto', 'SharedArrayBuffer', 'FinalizationRegistry', 'WeakRef', 'MessageChannel', 'BroadcastChannel', 'Worker2', 'zzz']) refused(body(`const w = ${n};`), new RegExp(`${n} is a global pipegen does not list`));
  });
  it('a global used as a bare value (not as an object, a callee, an argument or an instanceof operand) is refused', () => {
    for (const g of ['Object', 'Math', 'JSON', 'Number', 'String', 'Boolean', 'Array', 'Promise', 'Date', 'URL']) {
      refused(body(`const w = ${g};`), new RegExp(`${g} can only be used as`));
      refused(body(`const w = [${g}];`), new RegExp(`${g} can only be used as`));
      expect(probs(body(`f(${g}); const q = o instanceof ${g}; new ${g}(); ${g}(1);`)), g).toEqual([]);
    }
  });
  it('the size cap is exact: 50 KB passes, one byte more does not', () => {
    const pad = (n: number): string => `${ok(T)}//${'x'.repeat(Math.max(0, n - Buffer.byteLength(`${ok(T)}//`)))}`;
    const exact = pad(50 * 1024);
    expect(Buffer.byteLength(exact)).toBe(50 * 1024);
    expect(analyzeTestFile('test/a.test.ts', exact, []).parsed).toBe(true);
    expect(probs(`${exact}x`)).toEqual([expect.stringMatching(/over 50 KB/)]);
  });
  it('a builtin name in dependencies never allows a bare import, and .. at the service root leaves it', () => {
    refused(ok(`import x from 'punycode';\n${T}`), /punycode/, 'test/a.test.ts', ['punycode']);
    refused(ok(`import x from 'assert';\n${T}`), /"assert"/, 'test/a.test.ts', ['assert']);
    expect(analyzeTestFile('a.test.js', ok("import x from '..';\nit('a', () => { expect(x).toBe(1); });").replace(HEAD, "import { it, expect } from 'vitest';\n"), []).problems.join(' ')).toMatch(/leaves the service folder/);
    expect(analyzeTestFile('a.test.js', "import { it, expect } from 'vitest';\nimport x from '../x.js';\nit('a', () => { expect(x).toBe(1); });\n", [], 'module').problems.join(' ')).toMatch(/leaves the service folder/);
  });
  it('a with statement is refused in a script', () => {
    refused(`${CJS}const o = {};\nwith (o) { f(); }\nit('a', () => { expect(f()).toBe(1); });`, /with statement/, 'test/a.test.cjs');
  });
});

// ---- security scan, round 3 ----
describe('security scan round 3 / 1: exports', () => {
  const T2 = "it('a', () => { expect(f()).toBe(1); });\n";
  const test = (code: string, head = "import http from 'node:http';\nimport { get } from 'node:http';\nimport express from 'express';\n"): string => `${HEAD}${head}${code}\n${T2}`;
  it('a test file may not contain any export statement', () => {
    for (const code of ['export { http };', 'export { get };', 'export { http as default };', 'export default http;', 'export const x = 1;', 'export default 1;', "export * from './x.js';", "export { a } from './x.js';", 'export function g() {}', 'export class K {}', 'export default function () {}', 'export { f as default };', 'export {};']) {
      refused(test(code), /may not export anything/, 'test/a.test.ts', ['express']);
      refused(test(code), /may not export anything/, 'test/a.test.mjs', ['express']);
    }
  });
  it('a helper may export its own bindings but never an import, nor re-export', () => {
    const helper = (code: string, head = "import http from 'node:http';\nimport { get } from 'node:http';\nimport express from 'express';\n"): string[] => probs(`${head}const own = 1;\n${code}\n`, 'test/helpers/h.js', ['express']);
    for (const code of ['export const x = 1;', 'export { own };', 'export { own as default };', 'export default own;', 'export function g() { return 1; }', 'export default function () {}', 'export default 1;']) expect(helper(code), code).toEqual([]);
    for (const code of ['export { http };', 'export { get };', 'export { http as default };', 'export { get as g };', 'export default http;', 'export default get;', 'export { express };', "export * from './x.js';", "export { a } from './x.js';", "export * as ns from './x.js';", "export { default } from './x.js';"]) {
      expect(helper(code).join(' '), code).toMatch(/may not export|may not re-export/);
    }
  });
});

describe('security scan round 3 / 2: the API exemption is keyed on module and name together', () => {
  const T2 = "it('a', () => { expect(f()).toBe(1); });\n";
  it('a vitest, node:test or assert name imported from the wrong module, or under another name, is a reserved declaration', () => {
    for (const head of ["import { expect as fetch } from 'vitest';", "import { expect as e } from 'vitest';\nimport { it as describe } from 'vitest';", "import { describe } from 'node:assert';", "import { it } from 'node:assert';", "import { strictEqual as expect } from 'node:assert';", "import { get as describe } from 'node:http';", "import describe from 'node:http';", "import * as Map from 'node:assert';", "import * as expect from 'node:assert';", "import expect from 'node:assert';", "import { test as it } from 'node:test';", "import { it as Object } from 'node:test';", "import { describe } from 'express';", "import vi from 'express';", "import { expect } from 'express';"]) {
      refused(`const f = () => 1;\n${head}\n${T2}`, /reserves|declared again|vitest|another name/, 'test/a.test.ts', ['express']);
    }
    refused(`${CJS}const { expect: fetch } = require('vitest');\n${T2}`, /reserves|declared again/, 'test/a.test.cjs');
    refused(`const { it, expect } = require('vitest');\nconst { describe } = require('node:assert');\nconst f = () => 1;\n${T2}`, /reserves|declared again/, 'test/a.test.cjs');
    refused(`const { it, expect } = require('vitest');\nconst { get: describe } = require('node:http');\nconst f = () => 1;\n${T2}`, /reserves|declared again/, 'test/a.test.cjs');
    refused(`const { it, expect } = require('vitest');\nconst expect2 = require('node:assert');\nconst { vi } = require('node:test');\nconst f = () => 1;\n${T2}`, /reserves|declared again|vi/, 'test/a.test.cjs');
  });
  it('the real forms still pass: own names from their own module, default and namespace imports of node:assert and node:http with plain names', () => {
    expect(probs(`import { it, expect, describe, vi, beforeAll } from 'vitest';\nimport assert, { strictEqual } from 'node:assert';\nimport * as http from 'node:http';\nimport { test } from 'node:test';\nconst f = () => 1;\n${T2}`)).toEqual([]);
    expect(probs(`import { describe, it, test, before, after, beforeEach, afterEach } from 'node:test';\nimport { expect } from 'vitest';\nconst f = () => 1;\n${T2}`)).toEqual([]);
    expect(probs(`const { it, expect } = require('vitest');\nconst { test } = require('node:test');\nconst assert = require('node:assert');\nconst f = () => 1;\n${T2}`, 'test/a.test.cjs')).toEqual([]);
  });
});

// ---- mutation survivors: shape of a test, assertion forms, placement, union of readings ----
describe('mutation survivors: tests and assertions', () => {
  it('a test call must be an expression statement of its own', () => {
    refused(ok("const r = it('a', () => { expect(f()).toBe(1); });"), /own in the file/);
    refused(ok("f(it('a', () => { expect(f()).toBe(1); }));"), /own in the file/);
    refused(ok("void it('a', () => { expect(f()).toBe(1); });"), /own in the file/);
    expect(probs(ok("describe('g', () => { it('a', () => { expect(f()).toBe(1); }); });"))).toEqual([]);
  });
  it('the timeout is at most one number: a fourth argument is refused', () => {
    refused(ok("it('a', () => { expect(f()).toBe(1); }, 5, 6);"), /written as it/);
    refused(ok("it('a', () => { expect(f()).toBe(1); }, 5, () => {});"), /written as it/);
  });
  it('assertion forms that count: return, await, expect.soft, expect.poll, assert calls on real values; assert.fail and bare literals do not', () => {
    const one = (code: string, head = ''): number => analyzeTestFile('test/a.test.js', `${head}import { it, expect } from 'vitest';\nimport assert, { ok as okk } from 'node:assert';\nconst f = () => 1;\nit('a', async () => { ${code} });\n`, []).assertions;
    expect(one('return expect(f()).toBe(1);')).toBe(1);
    expect(one('await expect(f()).resolves.toBe(1);')).toBe(1);
    expect(one('expect.soft(f()).toBe(1);')).toBe(1);
    expect(one('await expect.poll(() => f()).toBe(1);')).toBe(1);
    expect(one('assert.equal(f(), 1);')).toBe(1);
    expect(one('okk(f());')).toBe(1);
    expect(one('assert(f());')).toBe(1);
    expect(one('assert.fail(f());')).toBe(0);
    expect(one("assert.equal(1, 1);")).toBe(0);
    expect(one("okk(true);")).toBe(0);
    expect(one("assert(1);")).toBe(0);
    expect(one('expect.assertions(1); expect.hasAssertions();')).toBe(0);
    expect(one('expect(f()).toBe(1); expect(f()).not.toBe(2); await expect(f()).resolves.toBe(1);')).toBe(3);
  });
  it('a CommonJS destructured require of node:assert binds its names', () => {
    const src = "const { it, expect } = require('vitest');\nconst { strictEqual: eq, ok } = require('node:assert');\nconst f = () => 1;\nit('a', () => { eq(f(), 1); ok(f()); });\n";
    expect(analyzeTestFile('test/a.test.cjs', src, [])).toMatchObject({ problems: [], tests: 1, assertions: 2 });
  });
  it('a TypeScript class with a private field is read, and its name is not a skip', () => {
    expect(probs(ok("class K { #skip = 1; m() { return this.#skip; } }\nit('a', () => { expect(new K().m()).toBe(1); });"))).toEqual([]);
  });
  it('a computed template key with a hole is not statically readable; arithmetic keys fold', () => {
    refused(ok("it('a', () => { const o = {}; o[`a${f()}`]; expect(f()).toBe(1); });"), /computed property access whose key can not be read/);
    expect(probs(ok("it('a', () => { const o = {}; o[2 * 3]; o[5 - 1]; o[-2 * -3]; expect(f()).toBe(1); });"))).toEqual([]);
  });
  it('new.target is not import.meta', () => {
    expect(probs(ok("function g() { return new.target; }\nit('a', () => { expect(g()).toBe(1); });")).join(' ')).not.toMatch(/import\.meta/);
  });
  it('a member call that http does not offer is refused by its name', () => {
    refused(`${HEAD}import http from 'node:http';\nit('a', () => { http.foo(1); expect(f()).toBe(1); });\n`, /http\.foo is refused/);
  });
  it('the owner of a path is the deepest service that holds it', () => {
    expect(starterOwner('api/test/test/a.test.ts', ['api', 'api/test'])).toEqual({ root: 'api/test', rel: 'test/a.test.ts' });
    expect(starterOwner('api/test/test/a.test.ts', ['api/test', 'api'])).toEqual({ root: 'api/test', rel: 'test/a.test.ts' });
  });
  it('the union of the script and the module reading: counts are the smaller, problems are all', () => {
    const hidden = `${CJS}const a = 1, b = 1;\na <!-- b; it('x', () => { expect(f()).toBe(1); });\n${T}\n`;
    const r = analyzeTestFile('test/a.test.js', hidden, [], 'commonjs');
    expect(r).toMatchObject({ problems: [], tests: 1, assertions: 1, parsed: true });   // the script reading hides one test
    const evil = `${CJS}const a = 1, b = 1;\na <!-- b; globalThis;\n${T}\n`;
    expect(analyzeTestFile('test/a.test.js', evil, [], 'commonjs').problems.join(' ')).toMatch(/globalThis/);
    expect(analyzeTestFile('test/a.test.js', evil, [], 'module').problems.join(' ')).toMatch(/does not parse|globalThis/);
  });
});
