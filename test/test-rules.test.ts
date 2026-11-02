// v0.2 Plan D, D7 (preflight S9, item 9): the rules for AI-written starter tests are a real parse and a tree walk, not a denylist of words.
import { describe, expect, it } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { analyzeTestFile, dependencyNames, fileStats, starterOwner, starterTestFileProblems, starterTestPathProblem } from '../src/create/test-rules.js';
import { withActiveVault } from '../src/util/known-values.js';

const HEAD = "import { describe, it, expect } from 'vitest';\n";
const ok = (body: string, head = HEAD): string => `${head}${body}\n`;
const CJS = "const { describe, it, expect } = require('vitest');\n";
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
    const r = analyzeTestFile('test/a.test.ts', ok(`${T}\ndescribe('g', () => {\n  it('a', async () => { await expect(p()).resolves.toBe(1); expect(2).toBe(2); expect(x).not.toBe(2); });\n  it.concurrent('b', () => expect(y()).toEqual({ a: 1 }));\n});`), []);
    expect(r).toEqual({ problems: [], tests: 3, assertions: 4, parsed: true });   // expect(2).toBe(2) is on a literal and does not count
  });
  it('TypeScript syntax (types, as, !, generics, interfaces) is read', () => {
    const src = ok("import type { Foo } from '../src/foo.js';\ninterface I { a: number }\ntype K = keyof I;\nconst x: Foo = { a: 1 } as Foo;\nfunction g<T extends object>(v: T, w?: string): T { return v; }\nit('t', () => { expect(g<I>(x!).a as number).toBe(1); });");
    expect(probs(src, 'test/a.test.ts', [])).toEqual([]);
  });
  it('node:assert and node:test files count assert calls', () => {
    const src = "import assert from 'node:assert/strict';\nimport { strictEqual } from 'node:assert';\nimport { test } from 'node:test';\ntest('a', () => { assert.equal(f(), 1); });\ntest('b', () => { strictEqual(f(), 2); assert(f()); });\n";
    expect(analyzeTestFile('test/a.test.js', src, [])).toMatchObject({ problems: [], tests: 2, assertions: 3 });
  });
  it('a CommonJS file with require of an allowed module passes', () => {
    const src = "const assert = require('node:assert');\nconst { it } = require('vitest');\nit('a', () => { assert.strictEqual(f(), 1); });\n";
    expect(probs(src, 'test/a.test.cjs')).toEqual([]);
  });
  it('relative imports inside the service, the service\'s own dependencies and the allowed built-ins pass', () => {
    const src = ok("import path from 'node:path';\nimport { fileURLToPath } from 'node:url';\nimport util from 'node:util';\nimport http from 'node:http';\nimport express from 'express';\nimport request from 'supertest/lib/x';\nimport { add } from '../src/add.js';\nimport h from './helpers/h.js';\nimport { s } from '@scope/pkg/sub';\nit('a', () => { expect(add(1, 1)).toBe(2); });");
    expect(probs(src, 'test/a.test.ts', ['express', 'supertest', '@scope/pkg'])).toEqual([]);
  });
  it('helpers need no test; a helper with an import outside the allowlist is still refused', () => {
    expect(probs("export const make = (n) => ({ n });\n", 'test/helpers/h.js')).toEqual([]);
    refused("import fs from 'node:fs';\nexport const x = fs;\n", /node:fs/, 'test/helpers/h.js');
  });
  it('urls to localhost, 127.0.0.1 and example.com pass (with ports and templates with a port)', () => {
    expect(probs(ok("it('u', () => { const port = 3000; expect(`http://localhost:${port}/x`).toBe('http://127.0.0.1:8080/a?b=https://example.com'.length ? 'a' : 'b'); expect('https://example.com/a').toBeTruthy(); });"))).toEqual([]);
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
      refused(ok(`export * from ${JSON.stringify(spec)};\n${T}`), /imports|re-exports/, 'test/a.test.ts', []);
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
  it('re-exports of a package are refused; relative re-exports pass', () => {
    refused(ok(`export { join } from 'node:path';\n${T}`), /re-exports/);
    expect(probs(ok(`export * from './helpers/h.js';\n${T}`))).toEqual([]);
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
    refused(`${CJS}const p = require('node:' + 'path');\nit('a', () => { expect(p.sep).toBe('/'); });`, /not a plain string/, 'test/a.test.cjs');
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
    refused(body('const k = f(); a[k];'), /computed property/);
    refused(body('const { [k]: v } = a;'), /destructured key/);
    expect(probs(body("a['x']; a[0]; a[1 + 2]; a[-1]; a[`k`]; const o = { [k]: 1 };"))).toEqual([]);
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
    for (const c of ["vi.mock('child_process');", "vi.doMock('x');", "await vi.importActual('child_process');", "vi.resetModules();", 'const v = vi;', "vi['mock']('x');"]) refused(body(c), /vi/);
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
  const t = (s: string): string => ok(`it('u', () => { expect(f(${s})).toBeTruthy(); });`);
  it('an external URL is refused, localhost allowed', () => {
    refused(t("'https://evil.example/x'"), /evil\.example/);
    refused(t("'http://example.com.evil.net/x'"), /example\.com\.evil\.net/);
    refused(t("'http://localhost@evil.net/'"), /user name/);
    refused(t("'http://localhost.evil.net/'"), /localhost\.evil\.net/);
    refused(t("'//evil.net/x'"), /evil\.net/);
    refused(t("'ftp://evil.net/x'"), /evil\.net/);
    refused(t("'file:///etc/passwd'"), /URL host/);
    refused(t("'http://' + host"), /URL host/);
    refused(t('`http://${host}/x`'), /built at run time/);
    refused(t("'h\\x74tp://evil.net'"), /evil\.net/);
    refused(t("'http://[::1]:3000/'"), /URL host/);
    expect(probs(t("'http://localhost:3000/x'"))).toEqual([]);
    expect(probs(t("'http://127.0.0.1/x'"))).toEqual([]);
    expect(probs(t('`http://localhost:${port}/x`'))).toEqual([]);
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
    refused(ok(`function f() { ${T} }`), /own in the file/);
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
