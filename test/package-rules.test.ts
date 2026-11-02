// v0.2 Plan D, D1: the package.json and package-lock.json rules of ruling B2, as pure functions (the guard, and D6's judges, call them).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { B2_DEVDEPS, lockProblems, packageJsonProblems, parseJsonStrict } from '../src/create/package-rules.js';
import { closureFromLocks, type ReviewedClosure } from '../src/create/reviewed-closure.js';
import { satisfies } from '../src/create/semver-min.js';
import { packageDataPath } from '../src/util/package-data.js';

const pj = (o: object): string => JSON.stringify(o, null, 2);
const BASE = { name: 'app', version: '1.0.0', scripts: { build: 'tsc', start: 'node index.js' }, dependencies: { express: '4.21.0' }, devDependencies: { typescript: '5.6.0' } };
const withTest = { ...BASE, scripts: { ...BASE.scripts, test: 'vitest run' }, devDependencies: { ...BASE.devDependencies, vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } };
const p = (a: object, b: object): string => packageJsonProblems(pj(a), pj(b)).join(' | ');

describe('B2 table', () => {
  it('is exactly vitest 5.0.5, @vitest/coverage-v8 5.0.5, c8 12.0.0, and frozen', () => {
    expect(B2_DEVDEPS).toEqual({ vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5', c8: '12.0.0' });
    expect(Object.isFrozen(B2_DEVDEPS)).toBe(true);
  });
});

describe('parseJsonStrict', () => {
  it('refuses a repeated key at any depth, a __proto__ key as a repeated one, and bad JSON', () => {
    expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow(/repeated/);
    expect(() => parseJsonStrict('{"a":{"b":1,"b":1}}')).toThrow(/repeated/);
    expect(() => parseJsonStrict('{"a":[{"b":1,"b":1}]}')).toThrow(/repeated/);
    expect(() => parseJsonStrict('{"a":1,')).toThrow();
    expect(() => parseJsonStrict('')).toThrow();
  });
  it('reads a normal document, and a __proto__ key stays a plain own property', () => {
    const v = parseJsonStrict('{"a":[1,{"b":null}],"__proto__":{"x":1}}') as Record<string, unknown>;
    expect(v.a).toEqual([1, { b: null }]);
    expect(Object.keys(v)).toContain('__proto__');
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
});

describe('packageJsonProblems (B2)', () => {
  it('an identical file passes; the B2 additions with scripts.test pass', () => {
    expect(p(BASE, BASE)).toBe('');
    expect(p(BASE, withTest)).toBe('');
  });
  it('formatting is not a change (key order is: fix round 1)', () => {
    expect(packageJsonProblems(JSON.stringify(BASE), pj({ name: 'app', version: '1.0.0', scripts: BASE.scripts, dependencies: BASE.dependencies, devDependencies: BASE.devDependencies }).replace(/\n\s*/g, ' '))).toEqual([]);
  });
  it('scripts.build changed, added or removed is refused', () => {
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, build: 'tsc && curl x' } })).toMatch(/scripts\.build/);
    expect(p({ ...BASE, scripts: { start: 'node i.js' } }, { ...BASE, scripts: { start: 'node i.js', build: 'x' } })).toMatch(/scripts\.build/);
    expect(p(BASE, { ...BASE, scripts: { start: 'node index.js' } })).toMatch(/scripts\.build/);
  });
  it('any lifecycle script, new or changed, is refused', () => {
    for (const k of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack', 'pretest', 'posttest', 'prebuild', 'postbuild', 'prestart', 'poststart', 'preversion', 'postversion', 'dependencies', 'prerestart', 'prestop']) {
      expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, [k]: 'node evil.js' } }), k).toMatch(/lifecycle|scripts\./);
    }
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, postinstall: 'x' } })).toMatch(/lifecycle script/);
    expect(p({ ...BASE, scripts: { ...BASE.scripts, prepare: 'husky' } }, { ...BASE, scripts: { ...BASE.scripts, prepare: 'evil' } })).toMatch(/lifecycle script/);
  });
  it('any other script (lint, start) added or changed is refused', () => {
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, lint: 'x' } })).toMatch(/scripts\.lint/);
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, start: 'node evil.js' } })).toMatch(/scripts\.start/);
  });
  it('scripts.test is added only when absent or npm\'s default; the value is vitest run', () => {
    const dflt = 'echo "Error: no test specified" && exit 1';
    expect(p({ ...BASE, scripts: { ...BASE.scripts, test: dflt } }, { ...BASE, scripts: { ...BASE.scripts, test: 'vitest run' } })).toBe('');
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, test: 'vitest run' } })).toBe('');
    expect(p({ ...BASE, scripts: { ...BASE.scripts, test: 'jest' } }, { ...BASE, scripts: { ...BASE.scripts, test: 'vitest run' } })).toMatch(/scripts\.test/);
    expect(p({ ...BASE, scripts: { ...BASE.scripts, test: dflt + ' ' } }, { ...BASE, scripts: { ...BASE.scripts, test: 'vitest run' } })).toMatch(/scripts\.test/);
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, test: 'curl x | sh' } })).toMatch(/scripts\.test/);
    expect(p(BASE, { ...BASE, scripts: { ...BASE.scripts, test: 'vitest run && node evil.js' } })).toMatch(/scripts\.test/);
    expect(p({ ...BASE, scripts: { ...BASE.scripts, test: 'jest' } }, { ...BASE, scripts: { ...BASE.scripts, test: 'jest' } })).toBe('');   // untouched
    expect(p({ ...BASE, scripts: { ...BASE.scripts, test: 'jest' } }, BASE)).toMatch(/scripts\.test/);   // removed
  });
  it('a package.json with no scripts object may gain {test}', () => {
    const { scripts: _s, ...noScripts } = BASE;
    expect(p(noScripts, { ...noScripts, scripts: { test: 'vitest run' } })).toBe('');
    expect(p(noScripts, { ...noScripts, scripts: { test: 'vitest run', build: 'x' } })).toMatch(/scripts\.build/);
    expect(p(BASE, { ...BASE, scripts: 'x' })).toMatch(/scripts/);
  });
  it('dependencies (and every other key) changed, added or removed is refused', () => {
    expect(p(BASE, { ...BASE, dependencies: { ...BASE.dependencies, evil: '1.0.0' } })).toMatch(/dependencies/);
    expect(p(BASE, { ...BASE, dependencies: { express: '4.99.0' } })).toMatch(/dependencies/);
    const { dependencies: _d, ...none } = BASE;
    expect(p(none, { ...none, dependencies: { x: '1.0.0' } })).toMatch(/dependencies/);
    for (const [k, v] of [['optionalDependencies', { x: '1.0.0' }], ['peerDependencies', { x: '1' }], ['overrides', { x: '1' }], ['resolutions', { x: '1' }], ['bundleDependencies', ['x']], ['workspaces', ['a']], ['packageManager', 'npm@10'], ['main', 'evil.js'], ['bin', { x: 'evil.js' }], ['engines', { node: '99' }], ['name', 'other'], ['type', 'module'], ['publishConfig', { registry: 'https://evil.example' }]] as const) {
      expect(p(BASE, { ...BASE, [k]: v }), k).toMatch(/changes `/);
    }
  });
  it('the c8, prettier and renovate keys are the gate\'s sections: added or changed is refused, by name', () => {
    for (const k of ['c8', 'prettier', 'renovate']) {
      expect(p(BASE, { ...BASE, [k]: { x: 1 } }), k).toMatch(new RegExp(`\`${k}\``));
      expect(p({ ...BASE, [k]: { a: 1 } }, { ...BASE, [k]: { a: 2 } }), k).toMatch(new RegExp(`\`${k}\``));
      expect(p({ ...BASE, [k]: { a: 1 } }, BASE), k).toMatch(new RegExp(`\`${k}\``));
    }
  });
  it('devDependencies: only the B2 table, at the exact version, only when absent', () => {
    const dd = (x: object) => ({ ...BASE, devDependencies: { ...BASE.devDependencies, ...x } });
    expect(p(BASE, dd({ vitest: '5.0.5' }))).toBe('');
    expect(p(BASE, dd({ c8: '12.0.0' }))).toBe('');
    expect(p(BASE, dd({ vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5', c8: '12.0.0' }))).toBe('');
    expect(p(BASE, dd({ eslint: '9.0.0' }))).toMatch(/not one of pipegen's reviewed packages/);
    for (const bad of [{ vitest: '^5.0.5' }, { vitest: '5.0.4' }, { vitest: '5.0.5 ' }, { vitest: 'latest' }, { vitest: 'npm:evil@1.0.0' }, { vitest: 'github:evil/x' }, { c8: '12.0.1' }, { '@vitest/coverage-v8': '5.0.6' }, { eslint: '9.0.0' }, { prettier: '3.0.0' }, { 'left-pad': '1.3.0' }, { biome: '1.0.0' }, { vitest: 5 }]) {
      expect(p(BASE, dd(bad)), JSON.stringify(bad)).toMatch(/adds devDependencies/);
    }
  });
  it('an existing devDependency is never changed, removed or re-pinned, even to the B2 version', () => {
    const had = { ...BASE, devDependencies: { ...BASE.devDependencies, vitest: '4.0.0' } };
    expect(p(had, { ...had, devDependencies: { ...had.devDependencies, vitest: '5.0.5' } })).toMatch(/vitest/);
    expect(p(had, { ...had, devDependencies: { typescript: '5.6.0' } })).toMatch(/removes devDependencies\.vitest/);
    expect(p(BASE, { ...BASE, devDependencies: { typescript: '5.7.0' } })).toMatch(/typescript/);
    expect(p(had, { ...had, devDependencies: { ...had.devDependencies, c8: '12.0.0' } })).toBe('');
  });
  it('a B2 package that the repo already has in dependencies, optionalDependencies or peerDependencies is not added again', () => {
    for (const k of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      const had = { ...BASE, [k]: { ...(BASE as unknown as Record<string, object>)[k], vitest: '5.0.5' } };
      expect(p(had, { ...had, devDependencies: { ...BASE.devDependencies, vitest: '5.0.5' } }), k).toMatch(/vitest/);
    }
  });
  it('a package.json with no devDependencies may gain the B2 ones; devDependencies must stay an object of strings', () => {
    const { devDependencies: _x, ...none } = BASE;
    expect(p(none, { ...none, devDependencies: { vitest: '5.0.5' } })).toBe('');
    expect(p(BASE, { ...BASE, devDependencies: ['vitest'] })).toMatch(/devDependencies/);
    expect(p(BASE, { ...BASE, devDependencies: null })).toMatch(/devDependencies/);
  });
  it('fix round 1 (2): key order is semantic in exports, imports and typesVersions; a reorder is a change', () => {
    const o = { ...BASE, exports: { '.': { import: './a.mjs', require: './a.cjs', default: './evil.js' } }, typesVersions: { '>=5': { '*': ['a'] }, '*': { '*': ['b'] } } };
    expect(p(o, o)).toBe('');
    expect(p(o, { ...o, exports: { '.': { default: './evil.js', import: './a.mjs', require: './a.cjs' } } })).toMatch(/changes `exports`/);
    expect(p(o, { ...o, typesVersions: { '*': { '*': ['b'] }, '>=5': { '*': ['a'] } } })).toMatch(/changes `typesVersions`/);
    expect(p({ ...BASE, files: ['a', 'b'] }, { ...BASE, files: ['b', 'a'] })).toMatch(/changes `files`/);
  });
  it('fix round 1 (2): a reorder of the top-level keys, of scripts or of existing devDependencies is a change; additions may sit anywhere', () => {
    const rev = (x: Record<string, unknown>): Record<string, unknown> => Object.fromEntries(Object.entries(x).reverse());
    expect(p(BASE, rev(BASE))).toMatch(/order/);
    const two = { ...BASE, scripts: { build: 'tsc', start: 'node i.js' }, devDependencies: { typescript: '5.6.0', eslint: '9.0.0' } };
    expect(p(two, { ...two, scripts: { start: 'node i.js', build: 'tsc' } })).toMatch(/order of scripts/);
    expect(p(two, { ...two, devDependencies: { eslint: '9.0.0', typescript: '5.6.0' } })).toMatch(/order of devDependencies/);
    // the test slot and the added devDependencies may sit anywhere
    expect(p(two, { ...two, scripts: { test: 'vitest run', build: 'tsc', start: 'node i.js' } })).toBe('');
    expect(p(two, { ...two, scripts: { build: 'tsc', test: 'vitest run', start: 'node i.js' }, devDependencies: { vitest: '5.0.5', typescript: '5.6.0', eslint: '9.0.0' } })).toBe('');
  });
  it('fix round 1 (8): B2 scope in package.json: workspaces and a non-npm packageManager are refused; coverage-v8 only with vitest 5.0.5', () => {
    expect(p({ ...BASE, workspaces: ['a'] }, { ...BASE, workspaces: ['a'], devDependencies: { ...BASE.devDependencies, vitest: '5.0.5' } })).toMatch(/workspaces/);
    expect(p({ ...BASE, packageManager: 'pnpm@9.0.0' }, { ...BASE, packageManager: 'pnpm@9.0.0', devDependencies: { ...BASE.devDependencies, vitest: '5.0.5' } })).toMatch(/packageManager/);
    expect(p({ ...BASE, packageManager: 'npm@10.8.0' }, { ...BASE, packageManager: 'npm@10.8.0', devDependencies: { ...BASE.devDependencies, vitest: '5.0.5' } })).toBe('');
    const v4 = { ...BASE, devDependencies: { ...BASE.devDependencies, vitest: '4.0.0' } };
    expect(p(v4, { ...v4, devDependencies: { ...v4.devDependencies, '@vitest/coverage-v8': '5.0.5' } })).toMatch(/coverage-v8.*vitest 5\.0\.5/);
    expect(p(BASE, { ...BASE, devDependencies: { ...BASE.devDependencies, '@vitest/coverage-v8': '5.0.5' } })).toMatch(/coverage-v8.*vitest 5\.0\.5/);
    expect(p(BASE, withTest)).toBe('');
  });
  it('bad text: not JSON, not an object, a repeated key (in either file), a prototype key trick', () => {
    expect(packageJsonProblems('{', pj(BASE)).join(' ')).toMatch(/original/);
    expect(packageJsonProblems(pj(BASE), '[1]').join(' ')).toMatch(/object|new/);
    expect(packageJsonProblems(pj(BASE), '{"name":"app","name":"x"}').join(' ')).toMatch(/repeated/);
    expect(packageJsonProblems('{"scripts":{"build":"a","build":"b"}}', pj(BASE)).join(' ')).toMatch(/repeated/);
    const dup = `${pj(BASE).slice(0, -2)},\n"dependencies":{"evil":"1.0.0"}\n}`;
    expect(packageJsonProblems(pj(BASE), dup).join(' ')).toMatch(/repeated/);
  });
});

// ---------- the lock ----------

const sri = (seed: string): string => `sha512-${createHash('sha512').update(seed).digest('base64')}`;
const ent = (name: string, version: string, extra: object = {}): Record<string, unknown> => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name.slice(name.indexOf('/') + 1)}-${version}.tgz`, integrity: sri(`${name}@${version}`), ...extra });
const lockOf = (root: object, pkgs: Record<string, object>, top: object = {}): string => pj({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'app', version: '1.0.0', ...root }, ...pkgs }, ...top });
const OLD_PKGS = { 'node_modules/express': ent('express', '4.21.0', { dependencies: { accepts: '~1.3.8' } }), 'node_modules/accepts': ent('accepts', '1.3.8'), 'node_modules/typescript': ent('typescript', '5.6.0', { dev: true }) };
const OLD_ROOT = { dependencies: { express: '4.21.0' }, devDependencies: { typescript: '5.6.0' } };
const OLD = lockOf(OLD_ROOT, OLD_PKGS);
/** The reviewed entries (as D6's closure lock would hold them, hoisted in an empty folder). */
const VITEST = ent('vitest', '5.0.5', { dev: true, dependencies: { tinyspy: '^3.0.0' }, optionalDependencies: { fsevents: '^2.3.0' }, peerDependencies: { jsdom: '*' }, peerDependenciesMeta: { jsdom: { optional: true } } });
const COV = ent('@vitest/coverage-v8', '5.0.5', { dev: true, peerDependencies: { vitest: '5.0.5' } });
const TINYSPY = ent('tinyspy', '3.0.2', { dev: true });
const C8 = ent('c8', '12.0.0', { dev: true });
const NEW_PKGS = { 'node_modules/vitest': VITEST, 'node_modules/@vitest/coverage-v8': COV, 'node_modules/tinyspy': TINYSPY };
const closureLock = (root: Record<string, string>, pkgs: Record<string, object>): string => pj({ name: 'closure', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'closure', version: '1.0.0', dependencies: root }, ...pkgs } });
const pin = (name: string, version: string) => ({ name, version, integrity: sri(`${name}@${version}`) });
const CLOSURE: ReviewedClosure = closureFromLocks([
  { text: closureLock({ vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' }, { ...NEW_PKGS }), pins: [pin('vitest', '5.0.5'), pin('@vitest/coverage-v8', '5.0.5')] },
  { text: closureLock({ c8: '12.0.0' }, { 'node_modules/c8': C8 }), pins: [pin('c8', '12.0.0')] },
]);
const NEW_ROOT = { ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } };
const GOOD = lockOf(NEW_ROOT, { ...OLD_PKGS, ...NEW_PKGS });
const lp = (o: string, n: string, opts: Parameters<typeof lockProblems>[2] = { closure: CLOSURE }): string => lockProblems(o, n, opts).join(' | ');
const edit = (mut: (l: { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>) => void, from: string = GOOD): string => {
  const l = JSON.parse(from) as { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>;
  mut(l);
  return pj(l);
};

describe('semver-min (allowlist grammar, fix round 2)', () => {
  it('accepted forms: [op]X.Y.Z, x-ranges, hyphen ranges, sets joined by " || "', () => {
    const t: [string, string, boolean][] = [['1.2.3', '1.2.3', true], ['1.2.4', '1.2.3', false], ['1.2.3', '=1.2.3', true], ['1.4.0', '^1.2.3', true], ['2.0.0', '^1.2.3', false], ['1.2.2', '^1.2.3', false], ['0.2.5', '^0.2.3', true], ['0.3.0', '^0.2.3', false], ['0.0.3', '^0.0.3', true], ['0.0.4', '^0.0.3', false],
      ['1.2.9', '~1.2.3', true], ['1.3.0', '~1.2.3', false], ['1.2.2', '~1.2.3', false], ['5.0.5', '>=5.0.0', true], ['4.9.9', '>=5.0.0', false], ['5.0.0', '>5.0.0', false], ['5.0.1', '>5.0.0', true], ['1.2.3', '<=1.2.3', true], ['1.2.4', '<=1.2.3', false], ['1.2.2', '<1.2.3', true], ['1.2.3', '<1.2.3', false],
      ['3.1.0', '*', true], ['3.1.0', 'x', true], ['3.1.0', 'X', true], ['3.1.0', '', true], ['1.9.0', '1', true], ['2.0.0', '1', false], ['1.9.0', '1.x', true], ['2.0.0', '1.x', false], ['1.9.0', '1.*', true], ['1.2.9', '1.2.x', true], ['1.3.0', '1.2.x', false], ['1.2.9', '1.2.*', true],
      ['18.0.0', '^16.0.0 || ^18.0.0', true], ['17.0.0', '^16.0.0 || ^18.0.0', false], ['1.5.0', '1.2.3 - 2.0.0', true], ['2.0.0', '1.2.3 - 2.0.0', true], ['2.0.1', '1.2.3 - 2.0.0', false], ['1.2.2', '1.2.3 - 2.0.0', false], ['1.9.9', '>=1.0.0 <2.0.0', true], ['2.0.0', '>=1.0.0 <2.0.0', false], ['1.0.0', '>=1.0.0 <2.0.0 || 3.x', true], ['3.4.5', '>=1.0.0 <2.0.0 || 3.x', true]];
    for (const [v, r, want] of t) expect(satisfies(v, r), `${v} in ${JSON.stringify(r)}`).toBe(want);
  });
  it('anything outside the grammar gives null: partial versions with an operator, tags, build tags, stray text, odd spacing, unknown schemes', () => {
    for (const r of ['>=5', '>1.2', '<=1.2', '>=1.2', '1.2', '>=1', '<2', 'npm:evil@1', 'github:a/b', '^^1.0.0', 'latest', 'a.b.c', '>=1.0.0 <=x.y.z', '>= 1.0.0', '1.0.0  2.0.0', '^1.0.0||^2.0.0', '^1.0.0 ||', '|| ^1.0.0', '1.0.0 -2.0.0', '1.0.0 - 2', '1 - 2', '01.2.3', '1.2.3.4', 'v1.2.3', '<*', '^*', '~*', '>*', '1.x.3', '^1.x.3', '~1.x.3', '<=1.x.3', '>=1.x.3', '>1.x.3', '<1.x.3', '*-0', 'x-0', '1.x-0', '1.2.x-0', '*.1', 'x.2.3', '1.2.3-beta', '1.2.3+build', '^1.2.3-beta.1', '>=1.2.3-beta.1', '>1.2.3-beta', '<1.2.3-beta', '~1.2.3-beta', '=1.2.3-beta', '1.2.3-beta || 1.2.3', '1.2.x3', '1.2.*0', '^1.x', '~1.x', '^1.2.x3', '^1.2.', '~', '^', '^1.', '^01', '~1.02', '^1.2 - 2', '>=^1', '^~1', '~>1', '^1.2.3.4', '1.0.0-ab || 1.0.0-a', '1.2.3-0 - 2.0.0', '1.2.3 - 2.0.0-0', '1.x - 2.0.0', '', ]) {
      if (r === '') continue;   // the empty range is the x-range "any"
      expect(satisfies('1.2.3', r), JSON.stringify(r)).toBeNull();
    }
  });
  it('a version that is not plain MAJOR.MINOR.PATCH gives null: prerelease, build tag, v prefix, leading zero, stray text', () => {
    for (const v of ['1.0.0-a', '1.2.3-beta', '1.2.3-beta.1', '1.0.0+build', '1.0.0-a+b', 'v1.2.3', '01.2.3', '1.2', '1', 'x', 'not-a-version', '1.2.3 ', '']) {
      for (const r of ['*', '1.2.3', '^1.0.0', '', '1.x']) expect(satisfies(v, r), `${JSON.stringify(v)} in ${JSON.stringify(r)}`).toBeNull();
    }
  });
  it('the 37 differential cases of review-D1-r1 (tmp-D1-review/r1/semver.txt): npm says false or invalid, so the answer is never true', () => {
    const cases: [string, string][] = [];
    for (const v of ['1.0.5', '1.2.0', '1.2.3', '1.2.4', '1.3.0', '1.5.0', '1.9.9']) cases.push([v, '>1.x.3']);
    for (const v of ['1.0.0', '1.0.1']) cases.push([v, '<1.x.3']);
    cases.push(['1.2.3-beta', '>=1.2.3-beta.1'], ['1.2.3', '1.2.3-beta'], ['1.2.3-beta', '^1.2.3-beta.1'], ['1.0.0-a', '>=1.0.0-ab'], ['1.0.0', '1.0.0-ab || 1.0.0-a']);
    for (const v of ['0.0.0', '0.0.1', '0.0.3', '0.0.4', '0.1.0', '0.2.3', '0.2.9', '0.3.0', '1.0.0', '1.0.1', '1.0.3', '1.0.5', '1.2.0', '1.2.3', '1.2.4', '1.3.0', '1.5.0', '1.9.9', '2.0.0', '2.3.4', '2.4.0', '3.0.0', '10.0.0']) cases.push([v, '*-0']);
    expect(cases.length).toBe(37);
    for (const [v, r] of cases) expect(satisfies(v, r), `${v} in ${JSON.stringify(r)}`).not.toBe(true);
    for (const [v, r] of cases) expect(satisfies(v, r), `${v} in ${JSON.stringify(r)}`).toBeNull();
  });
});

describe('semver-min: partial versions with ^ or ~ (D6-B1)', () => {
  // generated with npm 11.9.0's own `semver` (semver.satisfies over these versions); the live differential below re-checks it when that package is found
  const VERSIONS = ["0.0.0", "0.0.1", "0.0.3", "0.0.4", "0.1.0", "0.1.5", "0.2.3", "0.2.9", "0.3.0", "0.9.9", "1.0.0", "1.2.0", "1.2.3", "1.9.9", "2.0.0", "2.3.4", "3.0.0", "3.9.9", "4.0.0", "4.0.7", "10.0.0"];
  const TABLE: [string, string[]][] = [
      ["^0", ["0.0.0", "0.0.1", "0.0.3", "0.0.4", "0.1.0", "0.1.5", "0.2.3", "0.2.9", "0.3.0", "0.9.9"]],
      ["^0.0", ["0.0.0", "0.0.1", "0.0.3", "0.0.4"]],
      ["^0.1", ["0.1.0", "0.1.5"]],
      ["^0.2", ["0.2.3", "0.2.9"]],
      ["^0.3", ["0.3.0"]],
      ["^1", ["1.0.0", "1.2.0", "1.2.3", "1.9.9"]],
      ["^1.0", ["1.0.0", "1.2.0", "1.2.3", "1.9.9"]],
      ["^1.2", ["1.2.0", "1.2.3", "1.9.9"]],
      ["^3", ["3.0.0", "3.9.9"]],
      ["^4", ["4.0.0", "4.0.7"]],
      ["^10", ["10.0.0"]],
      ["~0", ["0.0.0", "0.0.1", "0.0.3", "0.0.4", "0.1.0", "0.1.5", "0.2.3", "0.2.9", "0.3.0", "0.9.9"]],
      ["~0.0", ["0.0.0", "0.0.1", "0.0.3", "0.0.4"]],
      ["~0.1", ["0.1.0", "0.1.5"]],
      ["~0.2", ["0.2.3", "0.2.9"]],
      ["~1", ["1.0.0", "1.2.0", "1.2.3", "1.9.9"]],
      ["~1.0", ["1.0.0"]],
      ["~1.2", ["1.2.0", "1.2.3"]],
      ["~3", ["3.0.0", "3.9.9"]],
      ["~4", ["4.0.0", "4.0.7"]],
      ["^3 || ^4", ["3.0.0", "3.9.9", "4.0.0", "4.0.7"]],
      ["~1 || ^4", ["1.0.0", "1.2.0", "1.2.3", "1.9.9", "4.0.0", "4.0.7"]],
      ["^0.0 || ^2", ["0.0.0", "0.0.1", "0.0.3", "0.0.4", "2.0.0", "2.3.4"]],
      [">=1.0.0 <2.0.0 || ~0.2", ["0.2.3", "0.2.9", "1.0.0", "1.2.0", "1.2.3", "1.9.9"]],
      ["^1.2 ^1.0", ["1.2.0", "1.2.3", "1.9.9"]],
      ["~1.2 >=1.2.3", ["1.2.3"]],
      ["^1 <1.5.0", ["1.0.0", "1.2.0", "1.2.3"]],
  ];
  it('^N, ^N.M, ~N and ~N.M (also inside || sets and beside other comparators) give what the semver package gives, 0.x cases included', () => {
    for (const [range, yes] of TABLE) for (const v of VERSIONS) expect(satisfies(v, range), `${v} in ${range}`).toBe(yes.includes(v));
  });
  it('nothing else is partial: >=5, >1.2, 1.2.x3, 1.2.*0 and a tail after a wildcard stay null', () => {
    for (const r of ['>=5', '>1.2', '<=1', '1.2.x3', '1.2.*0', '^1.x', '~1.x', '^1.2.x3', '^1.2.', '^1.', '~', '^', '^01', '~1.02', '^1.2.3.4', '^1 - 2']) expect(satisfies('1.2.3', r), r).toBeNull();
  });
  it('live differential against the semver package (when npm\'s copy is found): 20000 random ^/~ partial ranges, never a different answer', () => {
    let semver: { satisfies: (v: string, r: string) => boolean } | undefined;
    for (const dir of [join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'node_modules', 'semver'), '/usr/lib/node_modules/npm/node_modules/semver']) {
      try { semver = createRequire(import.meta.url)(dir) as typeof semver; break; } catch { /* try the next place */ }
    }
    if (semver === undefined) return;
    const pick = (a: string[]): string => a[Math.floor(Math.random() * a.length)] as string;
    const num = ['0', '1', '2', '3', '10'];
    const bad: string[] = [];
    for (let i = 0; i < 20000; i++) {
      const one = (): string => `${pick(['^', '~', ''])}${pick(num)}${Math.random() < 0.5 ? `.${pick(num)}` : ''}`;
      const range = Array.from({ length: 1 + Math.floor(Math.random() * 2) }, () => Array.from({ length: 1 + Math.floor(Math.random() * 2) }, one).join(' ')).join(' || ');
      for (const v of VERSIONS) {
        const mine = satisfies(v, range);
        if (mine !== null && mine !== semver.satisfies(v, range)) bad.push(`${v} in ${range}`);
      }
    }
    expect(bad.slice(0, 5)).toEqual([]);
  });
});

describe('lockProblems (B2, fix round 1): added entries must be reviewed code', () => {
  it('unchanged passes; the B2 additions with their reviewed closure pass', () => {
    expect(lp(OLD, OLD)).toBe('');
    expect(lp(OLD, GOOD)).toBe('');
  });
  it('without a reviewed closure every lock edit is refused (the safe default until D6 makes the data)', () => {
    expect(lp(OLD, GOOD, {})).toMatch(/no reviewed closure/);
    expect(lp(OLD, GOOD, { closure: null })).toMatch(/no reviewed closure/);
    expect(lp(OLD, OLD, {})).toMatch(/no reviewed closure/);
  });
  it('a pin the closure does not hold (c8 before D6 adds it) is refused', () => {
    const only: ReviewedClosure = closureFromLocks([{ text: closureLock({ vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' }, { ...NEW_PKGS }), pins: [pin('vitest', '5.0.5'), pin('@vitest/coverage-v8', '5.0.5')] }]);
    const withC8 = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', c8: '12.0.0' } }, { ...OLD_PKGS, 'node_modules/c8': C8 });
    expect(lp(OLD, withC8, { closure: only })).toMatch(/c8.*no reviewed/);
    expect(lp(OLD, withC8)).toBe('');
  });
  it('a pretty-printing or key-order change alone is no change', () => {
    expect(lp(OLD, JSON.stringify(JSON.parse(GOOD)))).toBe('');
  });
  it('P14: an added entry whose dependency map differs from the reviewed one (a forged edge to an arbitrary package) is refused', () => {
    const forged = edit((l) => {
      l.packages['node_modules/vitest'] = { ...VITEST, dependencies: { tinyspy: '^3.0.0', 'evil-pkg': '^1.0.0' } };
      l.packages['node_modules/evil-pkg'] = ent('evil-pkg', '1.0.0', { dev: true, hasInstallScript: true });
    });
    const out = lp(OLD, forged);
    expect(out).toMatch(/node_modules\/vitest.*reviewed/);
    expect(out).toMatch(/evil-pkg.*not in the reviewed/);
  });
  it('D6 (live npm 11.9): a dev entry that npm also marks peer (reached through vite, a peer of vitest) is accepted; devOptional stays refused', () => {
    expect(lp(OLD, edit((l) => { l.packages['node_modules/tinyspy'].peer = true; }))).toBe('');
    expect(lp(OLD, edit((l) => { l.packages['node_modules/tinyspy'].peer = true; l.packages['node_modules/tinyspy'].optional = true; }))).toBe('');
    expect(lp(OLD, edit((l) => { l.packages['node_modules/tinyspy'].devOptional = true; l.packages['node_modules/tinyspy'].peer = true; }))).toMatch(/tinyspy.*dev/);
    // m5 (D6 fix round 1): npm writes `peer` and `optional` only as true; any other value is refused
    for (const v of [false, 'x', 1, null, {}]) {
      expect(lp(OLD, edit((l) => { l.packages['node_modules/tinyspy'].peer = v; })), `peer ${JSON.stringify(v)}`).toMatch(/tinyspy.*(placement|flag)/);
      expect(lp(OLD, edit((l) => { l.packages['node_modules/tinyspy'].optional = v; })), `optional ${JSON.stringify(v)}`).toMatch(/tinyspy.*(placement|flag)/);
    }
  });
  it('P15: an entry with another version, no dev flag, devOptional, an install script the reviewed entry lacks, or another integrity is refused', () => {
    const cases: [string, (l: { packages: Record<string, Record<string, unknown>> }) => void, RegExp][] = [
      ['another version', (l) => { l.packages['node_modules/tinyspy'] = ent('tinyspy', '3.0.9', { dev: true }); }, /tinyspy.*not in the reviewed/],
      ['no dev flag', (l) => { delete l.packages['node_modules/tinyspy'].dev; }, /tinyspy.*dev/],
      ['devOptional', (l) => { delete l.packages['node_modules/tinyspy'].dev; l.packages['node_modules/tinyspy'].devOptional = true; }, /tinyspy.*dev/],
      ['dev beside devOptional', (l) => { l.packages['node_modules/tinyspy'].devOptional = true; }, /tinyspy.*dev/],
      ['peer flag without dev', (l) => { delete l.packages['node_modules/tinyspy'].dev; l.packages['node_modules/tinyspy'].peer = true; }, /tinyspy.*dev/],
      ['install script', (l) => { l.packages['node_modules/tinyspy'].hasInstallScript = true; }, /tinyspy.*reviewed/],
      ['integrity', (l) => { l.packages['node_modules/tinyspy'].integrity = sri('other'); }, /tinyspy.*reviewed/],
      ['bin added', (l) => { l.packages['node_modules/tinyspy'].bin = { x: 'evil.js' }; }, /tinyspy.*reviewed/],
      ['os', (l) => { l.packages['node_modules/tinyspy'].os = ['linux']; }, /tinyspy.*reviewed/],
    ];
    for (const [what, mut, re] of cases) expect(lp(OLD, edit(mut)), what).toMatch(re);
  });
  it('the placement flags may differ from the reviewed entry: optional beside dev, and a nested placement', () => {
    expect(lp(OLD, edit((l) => { l.packages['node_modules/tinyspy'].optional = true; }))).toBe('');
    const nested = edit((l) => { l.packages['node_modules/vitest/node_modules/tinyspy'] = l.packages['node_modules/tinyspy']; delete l.packages['node_modules/tinyspy']; });
    expect(lp(OLD, nested)).toBe('');
  });
  it('the reviewed entry is matched by name@version, not by where it sits', () => {
    const hoistedElsewhere = edit((l) => { l.packages['node_modules/vitest/node_modules/tinyspy'] = ent('tinyspy', '3.0.2', { dev: true }); delete l.packages['node_modules/tinyspy']; });
    expect(lp(OLD, hoistedElsewhere)).toBe('');
  });
  it('a pre-existing entry that changes is refused: version, resolved, integrity, dev flag, a dependency range, a new field', () => {
    for (const [what, mut] of [
      ['version', (l) => { l.packages['node_modules/express'].version = '4.21.1'; }],
      ['resolved', (l) => { l.packages['node_modules/express'].resolved = 'https://evil.example/express.tgz'; }],
      ['integrity', (l) => { l.packages['node_modules/accepts'].integrity = sri('other'); }],
      ['dev flag', (l) => { delete l.packages['node_modules/typescript'].dev; }],
      ['dependencies', (l) => { l.packages['node_modules/express'].dependencies = { accepts: '~1.3.8', evil: '1' }; }],
      ['new field', (l) => { l.packages['node_modules/accepts'].hasInstallScript = true; }],
    ] as [string, Parameters<typeof edit>[0]][]) expect(lp(OLD, edit(mut)), what).toMatch(/node_modules\/(express|accepts|typescript)/);
  });
  it('a pre-existing entry removed is refused', () => {
    expect(lp(OLD, edit((l) => { delete l.packages['node_modules/accepts']; }))).toMatch(/removes node_modules\/accepts/);
  });
  it('a new entry that is not a reviewed one is refused, wherever it sits', () => {
    expect(lp(OLD, edit((l) => { l.packages['node_modules/left-pad'] = ent('left-pad', '1.3.0', { dev: true }); }))).toMatch(/left-pad.*not in the reviewed/);
    expect(lp(OLD, edit((l) => { l.packages['node_modules/vitest/node_modules/evil'] = ent('evil', '1.0.0', { dev: true }); }))).toMatch(/evil.*not in the reviewed/);
  });
  it('a reviewed entry nested under an existing package, where no added package reaches it, is refused (it would shadow)', () => {
    expect(lp(OLD, edit((l) => { l.packages['node_modules/express/node_modules/tinyspy'] = TINYSPY; }))).toMatch(/express\/node_modules\/tinyspy.*not reached/);
  });
  it('edge completeness: an edge of an added entry that the lock does not hold is refused (optional edges and optional peers are not needed)', () => {
    expect(lp(OLD, edit((l) => { delete l.packages['node_modules/tinyspy']; }))).toMatch(/tinyspy/);
    expect(lp(OLD, GOOD)).toBe('');   // fsevents (optional) and jsdom (optional peer) are absent: fine
    const hard = closureFromLocks([{ text: closureLock({ vitest: '5.0.5' }, { 'node_modules/vitest': { ...VITEST, peerDependenciesMeta: undefined }, 'node_modules/tinyspy': TINYSPY }), pins: [pin('vitest', '5.0.5')] }]);
    const next = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }, { ...OLD_PKGS, 'node_modules/vitest': { ...VITEST, peerDependenciesMeta: undefined }, 'node_modules/tinyspy': TINYSPY });
    expect(lp(OLD, next, { closure: hard })).toMatch(/jsdom/);
  });
  it('an edge may land on an entry the user already has, when its version satisfies the range', () => {
    const user = lockOf({ ...OLD_ROOT }, { ...OLD_PKGS, 'node_modules/tinyspy': ent('tinyspy', '3.0.2', { dev: true }) });
    const next = edit((l) => { l.packages['node_modules/tinyspy'] = ent('tinyspy', '3.0.2', { dev: true }); }, GOOD);
    expect(lp(user, next)).toBe('');
    const old2 = lockOf({ ...OLD_ROOT }, { ...OLD_PKGS, 'node_modules/tinyspy': ent('tinyspy', '2.0.0', { dev: true }) });
    const next2 = edit((l) => { l.packages['node_modules/tinyspy'] = ent('tinyspy', '2.0.0', { dev: true }); });
    expect(lp(old2, next2)).toMatch(/resolves .* to 2\.0\.0, which does not satisfy \^3\.0\.0/);
  });
  it('an edge range it can not read is refused (fail closed)', () => {
    const odd = { ...VITEST, dependencies: { tinyspy: 'latest' } };
    const c = closureFromLocks([{ text: closureLock({ vitest: '5.0.5' }, { 'node_modules/vitest': odd, 'node_modules/tinyspy': TINYSPY }), pins: [pin('vitest', '5.0.5')] }]);
    const next = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }, { ...OLD_PKGS, 'node_modules/vitest': odd, 'node_modules/tinyspy': TINYSPY });
    expect(lp(OLD, next, { closure: c })).toMatch(/range/);
  });
  it('resolution takes the nearest node_modules: an edge from a nested entry lands on a sibling at an intermediate level, not on the user\'s top-level package', () => {
    const v = { ...VITEST, dependencies: { b: '^1.0.0', c: '^2.0.0' }, optionalDependencies: undefined, peerDependencies: undefined, peerDependenciesMeta: undefined };
    const b = ent('b', '1.0.0', { dev: true, dependencies: { c: '^2.0.0' } });
    const c2 = ent('c', '2.0.0', { dev: true });
    const closure = closureFromLocks([{ text: closureLock({ vitest: '5.0.5' }, { 'node_modules/vitest': v, 'node_modules/b': b, 'node_modules/c': c2 }), pins: [pin('vitest', '5.0.5')] }]);
    const user = lockOf(OLD_ROOT, { ...OLD_PKGS, 'node_modules/c': ent('c', '9.0.0', { dev: true }) });
    const next = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }, { ...OLD_PKGS, 'node_modules/c': ent('c', '9.0.0', { dev: true }), 'node_modules/vitest': v, 'node_modules/vitest/node_modules/b': b, 'node_modules/vitest/node_modules/c': c2 });
    expect(lp(user, next, { closure })).toBe('');
  });
  it('the root devDependencies gain exactly the reviewed pins at exact versions; a range, another name or a changed root field is refused', () => {
    expect(lp(OLD, edit((l) => { (l.packages[''].devDependencies as Record<string, string>).vitest = '^5.0.5'; }))).toMatch(/devDependencies/);
    expect(lp(OLD, edit((l) => { (l.packages[''].devDependencies as Record<string, string>)['left-pad'] = '1.3.0'; l.packages['node_modules/left-pad'] = ent('left-pad', '1.3.0', { dev: true }); }))).toMatch(/left-pad/);
    expect(lp(OLD, edit((l) => { l.packages[''].dependencies = { express: '4.21.0', evil: '1' }; }))).toMatch(/root/);
    expect(lp(OLD, edit((l) => { l.packages[''].name = 'other'; }))).toMatch(/root/);
    expect(lp(OLD, edit((l) => { l.packages[''].scripts = { x: 'y' }; }))).toMatch(/root/);
    expect(lp(OLD, edit((l) => { (l.packages[''].devDependencies as Record<string, string>).typescript = '5.7.0'; }))).toMatch(/typescript/);
    expect(lp(OLD, edit((l) => { delete (l.packages[''].devDependencies as Record<string, string>).typescript; }))).toMatch(/typescript/);
  });
  it('each added package sits at node_modules/<name> at the reviewed version; a root addition with no entry is refused', () => {
    expect(lp(OLD, edit((l) => { delete l.packages['node_modules/vitest']; }))).toMatch(/vitest/);
  });
  it('a new entry that is not a plain registry package is refused (shape): link, bundle, another registry, a foreign dependency', () => {
    for (const [what, mut] of [
      ['resolved elsewhere', (e) => { e.resolved = 'https://evil.example/tinyspy/-/tinyspy-3.0.2.tgz'; }],
      ['no integrity', (e) => { delete e.integrity; }],
      ['link', (e) => { e.link = true; }],
      ['inBundle', (e) => { e.inBundle = true; }],
      ['hasShrinkwrap', (e) => { e.hasShrinkwrap = true; }],
      ['alias dependency', (e) => { e.dependencies = { x: 'npm:evil@1.0.0' }; }],
    ] as [string, (e: Record<string, unknown>) => void][]) expect(lp(OLD, edit((l) => { mut(l.packages['node_modules/tinyspy'] as Record<string, unknown>); })), what).toMatch(/tinyspy/);
  });
  it('a key that is not node_modules/<name>[/node_modules/<name>]... is refused', () => {
    for (const key of ['packages/evil', 'node_modules/../x', 'node_modules/a/b', '../x', 'node_modules/vitest/../../x', 'node_modules/', 'node_modules/Evil', 'evil']) {
      expect(lp(OLD, edit((l) => { l.packages[key] = ent('evil', '1.0.0', { dev: true }); })), key).toMatch(/not a package under node_modules/);
    }
  });
  it('lockfileVersion must be 3 on both sides; any top-level key but packages must be unchanged', () => {
    expect(lp(OLD, edit((l) => { l.lockfileVersion = 2; }))).toMatch(/lockfileVersion/);
    expect(lp(OLD, edit((l) => { l.dependencies = {}; }))).toMatch(/top level/);
    expect(lp(OLD, edit((l) => { l.name = 'other'; }))).toMatch(/top level/);
    expect(lp(edit((l) => { l.lockfileVersion = 2; }, OLD), GOOD)).toMatch(/lockfileVersion/);
    const v2 = (t: string): string => edit((l) => { l.lockfileVersion = 2; }, t);
    expect(lp(v2(OLD), v2(OLD))).toMatch(/not lockfileVersion 3/);
    expect(lp(v2(OLD), v2(GOOD))).toMatch(/not lockfileVersion 3/);
  });
  it('bad text: not JSON, packages missing, a repeated key', () => {
    expect(lp('{', GOOD)).toMatch(/original/);
    expect(lp(OLD, 'x')).toMatch(/new/);
    expect(lp(OLD, '{"lockfileVersion":3}')).toMatch(/packages/);
    const dup = GOOD.replace('"node_modules/tinyspy": {', '"node_modules/tinyspy": {"version":"3.0.2","version":"9.9.9"},\n"node_modules/tinyspy": {');
    expect(lp(OLD, dup)).toMatch(/repeated/);
  });
  it('an added package that is already in the lock at the reviewed version, with no change to existing entries, passes', () => {
    const old = lockOf(OLD_ROOT, { ...OLD_PKGS, 'node_modules/c8': C8 });
    const next = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', c8: '12.0.0' } }, { ...OLD_PKGS, 'node_modules/c8': C8 });
    expect(lp(old, next)).toBe('');
  });
  it('fix round 2 (m1): an EXISTING entry of an added pin with another integrity than the reviewed one is refused (the entry deep-equal never runs on it)', () => {
    const mirror = { ...VITEST, integrity: sri('a mirror tarball') };
    const old = lockOf(OLD_ROOT, { ...OLD_PKGS, 'node_modules/vitest': mirror });
    const next = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }, { ...OLD_PKGS, 'node_modules/vitest': mirror, 'node_modules/tinyspy': TINYSPY });
    expect(lp(old, next)).toMatch(/vitest with another integrity than the reviewed one/);
    const same = lockOf(OLD_ROOT, { ...OLD_PKGS, 'node_modules/vitest': VITEST, 'node_modules/tinyspy': TINYSPY });
    expect(lp(same, lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }, { ...OLD_PKGS, 'node_modules/vitest': VITEST, 'node_modules/tinyspy': TINYSPY }))).toBe('');
  });
  it('with the new package.json given, the lock root devDependencies must equal it', () => {
    const pkg = pj({ ...BASE, devDependencies: { typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } });
    expect(lp(OLD, GOOD, { closure: CLOSURE, packageJson: pkg })).toBe('');
    expect(lp(OLD, GOOD, { closure: CLOSURE, packageJson: pj({ ...BASE, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }) })).toMatch(/package\.json/);
    expect(lp(OLD, GOOD, { closure: CLOSURE, packageJson: '{' })).toMatch(/package\.json/);
  });
});

describe('reviewed closure loader', () => {
  it('loads the real closure data (D6): the three reviewed pins at the reviewed integrity, and every closure edge that resolves is readable and satisfied; of all 180 declared edges exactly one is null (D6-I1)', async () => {
    const { loadReviewedClosure } = await import('../src/create/reviewed-closure.js');
    const { reviewedList } = await import('./helpers/render.js');
    const c = loadReviewedClosure(reviewedList());
    expect(c).not.toBeNull();
    expect(Object.keys(c?.pins ?? {}).sort()).toEqual(['@vitest/coverage-v8', 'c8', 'vitest']);
    // every edge the lock judge would check (a dependency the lock holds, found by npm's nearest-folder rule) has a range semver-min reads, and the resolved version satisfies it
    let edges = 0;
    for (const id of ['vitest-coverage', 'c8']) {
      const pk = (JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8')) as { packages: Record<string, Record<string, Record<string, string> | string>> }).packages;
      for (const [key, e] of Object.entries(pk)) {
        for (const f of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
          for (const [d, r] of Object.entries((e[f] ?? {}) as Record<string, string>)) {
            let scope = key; let at: string | null = null;
            for (;;) { const cand = `${scope === '' ? '' : `${scope}/`}node_modules/${d}`; if (pk[cand] !== undefined) { at = cand; break; } if (scope === '') break; const m = /^(.*)\/node_modules\/(?:@[^/]+\/)?[^/]+$/.exec(scope); scope = m === null ? '' : (m[1] as string); }
            if (at === null) continue;
            edges++;
            expect(satisfies(String(pk[at]?.version), r), `${key} ${d} ${r}`).toBe(true);
          }
        }
      }
    }
    expect(edges).toBe(155);   // 180 declared edges, 25 of them optional peers the lock does not hold
    // ALL 180 declared edges, resolved or not: exactly one is outside the grammar (ruling D6-I1: a prerelease range stays null; the lock judge checks that
    // optional peer only when the user's lock holds @vitest/browser-webdriverio, which means a repo with its own vitest, so it is refused: fail closed)
    const nulls: string[] = []; let declared = 0;
    for (const id of ['vitest-coverage', 'c8']) {
      const pk = (JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8')) as { packages: Record<string, Record<string, Record<string, string> | string>> }).packages;
      for (const [key, e] of Object.entries(pk)) for (const f of ['dependencies', 'optionalDependencies', 'peerDependencies']) for (const [d, r] of Object.entries((e[f] ?? {}) as Record<string, string>)) { declared++; if (satisfies('1.0.0', r) === null) nulls.push(`${id} ${key} ${f} ${d} ${r}`); }
    }
    expect(declared).toBe(180);
    expect(nulls).toEqual(['vitest-coverage node_modules/vitest peerDependencies @vitest/browser-webdriverio ^5.0.0-beta.5 || >=5.0.0']);
  });
  it('gives null when the data is not there: every lock edit stays refused', async () => {
    const { loadReviewedClosure } = await import('../src/create/reviewed-closure.js');
    const { reviewedList } = await import('./helpers/render.js');
    expect(loadReviewedClosure(reviewedList(), () => { throw new Error('missing'); })).toBeNull();
  });
  it('reads closure locks through an injected reader, and refuses a lock that fails the closure judge', async () => {
    const { loadReviewedClosure } = await import('../src/create/reviewed-closure.js');
    const { reviewedList } = await import('./helpers/render.js');
    expect(loadReviewedClosure(reviewedList(), () => { throw new Error('missing'); })).toBeNull();
    expect(loadReviewedClosure(reviewedList(), () => '{"not":"a lock"}')).toBeNull();
  });
});

describe('closureFromLocks', () => {
  const lockA = closureLockFor({ x: '1.0.0' }, { 'node_modules/x': ent('x', '1.0.0', { dev: true }) });
  function closureLockFor(root: Record<string, string>, pkgs: Record<string, object>): string { return pj({ name: 'c', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'c', version: '1.0.0', dependencies: root }, ...pkgs } }); }
  it('throws for a lock that fails the closure judge (a wrong pin, a bad entry)', () => {
    expect(() => closureFromLocks([{ text: lockA, pins: [pin('x', '2.0.0')] }])).toThrow(/refused/);
    expect(() => closureFromLocks([{ text: closureLockFor({ x: '1.0.0' }, { 'node_modules/x': { ...ent('x', '1.0.0'), link: true } }), pins: [pin('x', '1.0.0')] }])).toThrow(/refused/);
    expect(closureFromLocks([{ text: lockA, pins: [pin('x', '1.0.0')] }]).entries.has('x@1.0.0')).toBe(true);
  });
  it('two locks that define the same name@version differently leave it out (it is not reviewed)', () => {
    const other = closureLockFor({ x: '1.0.0' }, { 'node_modules/x': ent('x', '1.0.0', { dev: true, hasInstallScript: true }) });
    const c = closureFromLocks([{ text: lockA, pins: [pin('x', '1.0.0')] }, { text: other, pins: [pin('x', '1.0.0')] }]);
    expect(c.entries.has('x@1.0.0')).toBe(false);
    // the same entry twice, or differing only in placement flags, is kept
    const same = closureLockFor({ x: '1.0.0' }, { 'node_modules/x': ent('x', '1.0.0', { dev: true, optional: true }) });
    expect(closureFromLocks([{ text: lockA, pins: [pin('x', '1.0.0')] }, { text: same, pins: [pin('x', '1.0.0')] }]).entries.has('x@1.0.0')).toBe(true);
  });
});
