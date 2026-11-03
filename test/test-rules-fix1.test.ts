// v0.2 Plan D, D7 fix round 1: every repro of review-D7.md is a test here (written red first). C1 node:test is not allowed and vitest bindings have a fixed
// member list; C2 the words namespace and module in a .ts file; I1 connect and _members; I2 describe shape and no-parameter callbacks; M2-M6.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testsInstructions } from '../src/ai/prompts/tests.js';
import { SecretVault } from '../src/create/secrets.js';
import { analyzeTestFile } from '../src/create/test-rules.js';
import { withActiveVault } from '../src/util/known-values.js';

const probs = (src: string, rel = 'test/a.test.ts'): string[] => analyzeTestFile(rel, src).problems;
const refused = (src: string, re: RegExp, rel = 'test/a.test.ts'): void => {
  const p = probs(src, rel);
  expect(p.length, src).toBeGreaterThan(0);
  expect(p.join(' | '), src).toMatch(re);
};
const HEAD = "import { describe, it, expect, beforeEach } from 'vitest';\nconst f = (...a) => a;\n";
const body = (code: string): string => `${HEAD}it('a', async () => { const o = {}; ${code}; expect(1 + f()).toBe(2); });\n`;

describe('C1: node:test is not allowed, and a vitest binding has a fixed member list', () => {
  it('the review repros are refused (node:test run by import and by require)', () => {
    refused("import { it, expect } from 'vitest';\nimport { test } from 'node:test';\nconst go = test.run;\nit('runs a process', async () => { await go({ files: ['x'] }).toArray(); expect(go).toBeTruthy(); });\n", /node:test/);
    refused("import { it, expect } from 'vitest';\nconst nt = require('node:test');\nit('runs', async () => { await nt.run({}).toArray(); expect(nt).toBeTruthy(); });\n", /node:test|require/, 'test/a.test.js');
    for (const spec of ["import { run } from 'node:test';", "import test from 'node:test';", "import * as nt from 'node:test';", "import { it as t } from 'node:test';", "import 'node:test';", "export * from 'node:test';"]) refused(`${HEAD}${spec}\nit('b', () => { expect(f()).toBe(1); });\n`, /node:test|may not export/);
    refused("const { it, expect } = require('vitest');\nconst { run } = require('node:test');\nconst f = () => 1;\nit('a', () => { expect(f()).toBe(1); });\n", /node:test/, 'test/a.test.cjs');
    refused(body("await import('node:test')"), /node:test|import\(\)/);
  });
  it('a vitest binding can only be called, or used with a listed member', () => {
    for (const code of ['it.run', 'test.run', 'it.mock', 'it.extend({})', 'it.scoped', "it['run']", "it['ru' + 'n']", 'expect.extend({})', 'expect.unreachable()', 'expect.getState()', 'expect.addSnapshotSerializer', 'describe.runIf(1)', 'beforeEach.run', 'const go = it', 'const go = expect', 'const go = describe', 'const t = [test]', 'f(it)', 'const { run } = it', 'const { extend } = expect', 'const { importActual } = vi', 'const v = vi', "vi['importActual']"]) {
      refused(body(code).replace("const f = (...a) => a;", "const f = (...a) => a; const test = 1;").replace("const test = 1;", ""), /vitest|vi\b|it\b|expect|describe|test|beforeEach|run|importActual|extend/);
    }
    expect(probs(`${HEAD}describe.concurrent('g', () => { it.concurrent('b', () => { expect.soft(f()).toBe(1); }); });\nit('a', async () => { expect(f()).toEqual(expect.any(Array)); expect(f()).toEqual(expect.objectContaining({})); expect(f()).toEqual(expect.arrayContaining([])); expect(f()).toEqual(expect.stringContaining('')); expect(f()).toEqual(expect.stringMatching(/a/)); expect(f()).toEqual(expect.anything()); expect.assertions(1); expect.hasAssertions(); });\n`)).toEqual([]);
  });
  it('require of vitest follows the named-import rule: own names, no alias, no whole object', () => {
    const t = "\nconst f = () => 1;\nit('a', () => { expect(f()).toBe(1); });\n";
    expect(probs(`const { it, expect, describe, vi, beforeAll, afterAll, beforeEach, afterEach, test } = require('vitest');${t}`, 'test/a.test.cjs')).toEqual([]);
    for (const head of ["const vt = require('vitest');\nconst { it, expect } = vt;", "const { it, expect: e } = require('vitest');", "const { it, expect, run } = require('vitest');", "const { it, expect, ...rest } = require('vitest');", "const { vi: v, it, expect } = require('vitest');", "const [it] = require('vitest');", "const { it, expect, ['vi']: vi } = require('vitest');"]) refused(`${head}${t}`, /vitest|reserves|require/, 'test/a.test.cjs');
  });
});

describe('C2: a .ts file may not contain the words namespace or module anywhere', () => {
  it('the review repro and its forms (a comment between the keyword and the name) are refused', () => {
    const t = "\nit('t', () => { expect(v).toBe(v); });\n";
    for (const ns of ["namespace/**/N { export const x = 1; require('node:fs').writeFileSync('pwned.txt', 'x'); }", 'namespace /**/ N { }', 'module/**/N { }', 'export namespace/*x*/N { }', 'namespace\n/**/N { }', 'declare namespace N { }', 'declare module "x" { }', 'declare global { }'.replace('global', 'module')]) {
      refused(`import { it, expect } from 'vitest';\nconst v = 1;\n${ns}${t}`, /namespace|module/);
    }
  });
  it('prose in a comment or a string is refused too, in .ts only', () => {
    const t = "import { it, expect } from 'vitest';\nconst v = 1;\n";
    refused(`${t}// this module is tested\nit('t', () => { expect(v).toBe(v); });\n`, /namespace|module/);
    refused(`${t}it('t', () => { expect('a namespace').toBe(v + 'x'); });\n`, /namespace|module/);
    refused(`${t}/* module */\nit('t', () => { expect(v).toBe(v); });\n`, /namespace|module/);
    for (const rel of ['test/a.test.js', 'test/a.test.mjs']) expect(probs(`${t}// this module is tested\nit('t', () => { expect(v).toBe(v); });\n`, rel), rel).toEqual([]);
    expect(probs(`${t}const modules = 1, namespaces = 2, nomodule = 3;\nit('t', () => { expect(v + modules + namespaces + nomodule).toBe(v); });\n`)).toEqual([]);
  });
  it('the enum rule stays', () => {
    refused("import { it, expect } from 'vitest';\nenum E { A }\nit('t', () => { expect(E.A).toBe(1 - 1 + E.A); });\n", /enum/);
  });
});

describe('I1: connect and members that start with _ are refused', () => {
  it('the review repro (a node:http socket re-connected to any host)', () => {
    const src = readFileSync(join(import.meta.dirname, 'fixtures', 'fix1-socket-reconnect.txt'), 'utf8');
    refused(src, /\.connect is refused/);
  });
  it('connect, _handle and every _member, as a member, a computed key, a pattern key; not as an object literal key', () => {
    for (const code of ['o.connect(1, "h")', "o['connect']()", "o['con' + 'nect']()", 'o._handle.connect()', "o['_handle']", 'o._x', 'o._', 'const { _handle } = o', 'const { connect } = o', "const { ['_x']: y } = o", 'o.a._b.c']) refused(body(code), /connect|_|reaches/);
    expect(probs(body('const w = { _id: 1 }; w;'))).toEqual([]);
  });
});

describe('I2: describe has the shape of it, and callbacks take no parameters', () => {
  it('the review repros (a skip through a run-time options object, a skip through the test context)', () => {
    refused("import { describe, it, expect } from 'vitest';\nconst v = 1;\ndescribe('suite', JSON.parse('{\"skip\":true}'), () => {\n  it('a', () => { expect(v).toBe(2); });\n});\n", /describe is written as/);
    refused("import { it, expect } from 'vitest';\nconst v = 1;\nit('b', (ctx) => {\n  (Object.entries(ctx).find((e) => e[0] === 'skip'))[1]();\n  expect(v).toBe(2);\n});\n", /no parameters/);
  });
  it('describe: a plain name, an inline function, at most a number; no parameters', () => {
    for (const d of ["describe('g', {}, () => { it('a', () => { expect(f()).toBe(1); }); });", "describe(name, () => { it('a', () => { expect(f()).toBe(1); }); });", "describe('g', handler);", "describe('g', (ctx) => { it('a', () => { expect(f()).toBe(1); }); });", "describe('g', () => { it('a', () => { expect(f()).toBe(1); }); }, 5, 6);", "describe('g', () => { it('a', () => { expect(f()).toBe(1); }); }, 'x');", "describe();", "describe.concurrent('g', {}, () => { it('a', () => { expect(f()).toBe(1); }); });", "describe('', () => { it('a', () => { expect(f()).toBe(1); }); });"]) {
      refused(`${HEAD}const name = 'x', handler = () => 1;\n${d}\n`, /describe is written as|no parameters|plain string/);
    }
    expect(probs(`${HEAD}describe('g', () => { it('a', () => { expect(f()).toBe(1); }); });\ndescribe.concurrent('h', async () => { it('b', () => { expect(f()).toBe(1); }); }, 5000);\n`)).toEqual([]);
  });
  it('test and hook callbacks take no parameters, and a hook is an inline function', () => {
    for (const code of ["it('a', (ctx) => { expect(f()).toBe(1); });", "it('a', async function (done) { expect(f()).toBe(1); });", "it('a', ({ skip }) => { expect(f()).toBe(1); });", "it('a', (...r) => { expect(f()).toBe(1); });", "beforeEach((ctx) => {});", "beforeEach(handler);", "beforeEach(() => {}, 1, 2);", "beforeEach();", "beforeEach(() => {}, 'x');"]) {
      refused(`${HEAD}const handler = () => 1;\n${code}\nit('b', () => { expect(f()).toBe(1); });\n`, /no parameters|hook is written as|test is written as/);
    }
    expect(probs(`${HEAD}beforeEach(() => { f(); });\nbeforeEach(async () => { f(); }, 5000);\nit('b', () => { expect(f()).toBe(1); });\n`)).toEqual([]);
  });
});

describe('M2: messages carry no raw text of the file', () => {
  it('a long or secret identifier is cut and scrubbed in the test-form and the free-global messages', () => {
    const value = 'zzvaultvalue98765qwerty';
    const vault = new SecretVault();
    vault.set('K_M2', value);
    const long = `SECRETVALUE_${'x'.repeat(120)}`;
    const shown = withActiveVault(vault, () => [
      ...probs(`${HEAD}it.${value}('x', () => {});\nit('b', () => { expect(f()).toBe(1); });\n`),
      ...probs(`${HEAD}it('b', () => { expect(${value}).toBe(1); });\n`),
      ...probs(`${HEAD}it('b', () => { expect(${long}).toBe(1); });\n`),
      ...probs(`${HEAD}it.${long}('x', () => {});\nit('b', () => { expect(f()).toBe(1); });\n`),
    ].join(' | '));
    expect(shown).not.toContain(value);
    expect(shown).not.toContain('x'.repeat(100));
    expect(shown).toMatch(/is a global pipegen does not list/);
  });
});

describe('M3: .cjs is read both ways', () => {
  it('import in a .cjs file is read (vitest runs it as a module); a hidden-comment differential is reported', () => {
    expect(probs(`${HEAD}it('b', () => { expect(f()).toBe(1); });\n`, 'test/a.test.cjs')).toEqual([]);
    refused("const { it, expect } = require('vitest');\nconst f = () => 1;\nconst a = 1, b = 1;\na <!-- globalThis\nit('t', () => { expect(f()).toBe(1); });\n", /globalThis/, 'test/a.test.cjs');
  });
});

describe('M4: arguments only inside a non-arrow function', () => {
  it('the top of a file and an arrow at the top are refused; a plain function is fine', () => {
    refused("import { it, expect } from 'vitest';\nconst a = typeof arguments === 'undefined' ? 'none' : String(arguments.length);\nit('f', () => { expect(a).toBe('none'); });\n", /arguments/);
    refused(`${HEAD}it('f', () => { const g = () => arguments; expect(g()).toBe(1); });\n`, /arguments/);
    expect(probs(`${HEAD}function g() { return arguments.length; }\nfunction h() { return () => arguments[0]; }\nit('f', () => { expect(g(1) + h(2)()).toBe(3); });\n`)).toEqual([]);
  });
});

describe('M5: assertions after an early return or throw do not count', () => {
  it('the review repro (0 assertions run, 1 counted)', () => {
    const r = analyzeTestFile('test/a.test.ts', "import { it, expect } from 'vitest';\nconst v = 1;\nit('c', () => {\n  return;\n  expect(v).toBe(2);\n});\n");
    expect(r.assertions).toBe(0);
    expect(r.problems.join(' ')).toMatch(/no assertion/);
    const t = analyzeTestFile('test/a.test.ts', "import { it, expect } from 'vitest';\nconst v = 1;\nit('c', () => {\n  throw new Error('x');\n  expect(v).toBe(2);\n});\n");
    expect(t.assertions).toBe(0);
    expect(analyzeTestFile('test/a.test.ts', "import { it, expect } from 'vitest';\nconst v = 1;\nit('c', () => {\n  expect(v).toBe(1);\n  return expect(v).toBe(1);\n  expect(v).toBe(2);\n});\n").assertions).toBe(2);
  });
});

describe('M6: no text offers STATUS_CODES or METHODS', () => {
  it('the prompt, the leaf header and the messages', () => {
    expect(testsInstructions({ ext: 'ts' })).not.toMatch(/STATUS_CODES|METHODS/);
    expect(readFileSync(join(import.meta.dirname, '..', 'src', 'create', 'test-rules.ts'), 'utf8')).not.toMatch(/STATUS_CODES|METHODS/);
    expect(probs(`${HEAD}import http from 'node:http';\nit('a', () => { http.foo(1); expect(f()).toBe(1); });\n`).join(' ')).not.toMatch(/STATUS_CODES|METHODS/);
  });
});

describe('D7-C1: acorn and sucrase are declared, exact', () => {
  it('package.json devDependencies and the lock root say acorn 8.19.0 and sucrase 3.35.1', () => {
    const root = join(import.meta.dirname, '..');
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { devDependencies: Record<string, string> };
    expect(pkg.devDependencies.acorn).toBe('8.19.0');
    expect(pkg.devDependencies.sucrase).toBe('3.35.1');
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')) as { packages: Record<string, { version?: string; devDependencies?: Record<string, string> }> };
    expect(lock.packages[''].devDependencies?.acorn).toBe('8.19.0');
    expect(lock.packages[''].devDependencies?.sucrase).toBe('3.35.1');
    expect(lock.packages['node_modules/acorn']?.version).toBe('8.19.0');
    expect(lock.packages['node_modules/sucrase']?.version).toBe('3.35.1');
  });
});
