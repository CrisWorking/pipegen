// v0.2 Plan D, D1: the package.json and package-lock.json rules of ruling B2, as pure functions (the guard, and D6's judges, call them).
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { B2_DEVDEPS, lockProblems, packageJsonProblems, parseJsonStrict } from '../src/create/package-rules.js';

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
  it('formatting and key order are not changes (semantic diff)', () => {
    expect(packageJsonProblems(JSON.stringify(BASE), pj({ devDependencies: BASE.devDependencies, scripts: BASE.scripts, dependencies: BASE.dependencies, version: '1.0.0', name: 'app' }))).toEqual([]);
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
const NEW_PKGS = {
  'node_modules/vitest': ent('vitest', '5.0.5', { dev: true, dependencies: { tinyspy: '^3.0.0' } }),
  'node_modules/@vitest/coverage-v8': ent('@vitest/coverage-v8', '5.0.5', { dev: true, peerDependencies: { vitest: '5.0.5' } }),
  'node_modules/tinyspy': ent('tinyspy', '3.0.2', { dev: true }),
};
const NEW_ROOT = { ...OLD_ROOT, devDependencies: { typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } };
const GOOD = lockOf(NEW_ROOT, { ...OLD_PKGS, ...NEW_PKGS });
const lp = (o: string, n: string, opts?: Parameters<typeof lockProblems>[2]): string => lockProblems(o, n, opts).join(' | ');
const edit = (mut: (l: { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>) => void, from: string = GOOD): string => {
  const l = JSON.parse(from) as { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>;
  mut(l);
  return pj(l);
};

describe('lockProblems (B2): every change is explained by the added devDependencies and their closure', () => {
  it('unchanged passes; the B2 additions with their closure pass', () => {
    expect(lp(OLD, OLD)).toBe('');
    expect(lp(OLD, GOOD)).toBe('');
  });
  it('a pretty-printing or key-order change alone is no change', () => {
    expect(lp(OLD, JSON.stringify(JSON.parse(GOOD)))).toBe('');
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
  it('a new entry that is not part of the closure of the added packages is refused', () => {
    expect(lp(OLD, edit((l) => { l.packages['node_modules/left-pad'] = ent('left-pad', '1.3.0'); }))).toMatch(/left-pad.*closure/);
    expect(lp(OLD, edit((l) => { l.packages['node_modules/vitest/node_modules/evil'] = ent('evil', '1.0.0'); }))).toMatch(/evil.*closure/);
  });
  it('a dependency of an added package that the lock does not hold is refused (an incomplete closure)', () => {
    expect(lp(OLD, edit((l) => { delete l.packages['node_modules/tinyspy']; }))).toMatch(/tinyspy/);
  });
  it('a missing optional or optional-peer dependency is fine', () => {
    const g = edit((l) => { l.packages['node_modules/vitest'].optionalDependencies = { fsevents: '^2' }; l.packages['node_modules/vitest'].peerDependencies = { jsdom: '*' }; l.packages['node_modules/vitest'].peerDependenciesMeta = { jsdom: { optional: true } }; });
    expect(lp(OLD, g)).toBe('');
  });
  it('a nested entry that is in the closure is fine', () => {
    const g = edit((l) => {
      l.packages['node_modules/vitest'].dependencies = { tinyspy: '^3.0.0', ms: '^2' };
      l.packages['node_modules/vitest/node_modules/ms'] = ent('ms', '2.1.3', { dev: true });
    });
    expect(lp(OLD, g)).toBe('');
  });
  it('the root devDependencies gain exactly the B2 names at exact versions; a range, another name or a changed root field is refused', () => {
    expect(lp(OLD, edit((l) => { (l.packages[''].devDependencies as Record<string, string>).vitest = '^5.0.5'; }))).toMatch(/devDependencies/);
    expect(lp(OLD, edit((l) => { (l.packages[''].devDependencies as Record<string, string>)['left-pad'] = '1.3.0'; l.packages['node_modules/left-pad'] = ent('left-pad', '1.3.0'); }))).toMatch(/left-pad/);
    expect(lp(OLD, edit((l) => { l.packages[''].dependencies = { express: '4.21.0', evil: '1' }; }))).toMatch(/root/);
    expect(lp(OLD, edit((l) => { l.packages[''].name = 'other'; }))).toMatch(/root/);
    expect(lp(OLD, edit((l) => { l.packages[''].scripts = { x: 'y' }; }))).toMatch(/root/);
    expect(lp(OLD, edit((l) => { (l.packages[''].devDependencies as Record<string, string>).typescript = '5.7.0'; }))).toMatch(/typescript/);
    expect(lp(OLD, edit((l) => { delete (l.packages[''].devDependencies as Record<string, string>).typescript; }))).toMatch(/typescript/);
  });
  it('each added package sits at node_modules/<name> at the B2 version; a root addition with no entry, or another version, is refused', () => {
    expect(lp(OLD, edit((l) => { delete l.packages['node_modules/vitest']; }))).toMatch(/vitest/);
    expect(lp(OLD, edit((l) => { l.packages['node_modules/vitest'].version = '5.0.4'; l.packages['node_modules/vitest'].resolved = 'https://registry.npmjs.org/vitest/-/vitest-5.0.4.tgz'; }))).toMatch(/vitest/);
  });
  it('a new entry is a plain registry package: exact version, the registry tarball, sha512, no link/inBundle/hasShrinkwrap/bundled', () => {
    for (const [what, mut] of [
      ['version range', (e) => { e.version = '^3.0.2'; }],
      ['resolved elsewhere', (e) => { e.resolved = 'https://evil.example/tinyspy/-/tinyspy-3.0.2.tgz'; }],
      ['resolved http', (e) => { e.resolved = 'http://registry.npmjs.org/tinyspy/-/tinyspy-3.0.2.tgz'; }],
      ['resolved git', (e) => { e.resolved = 'git+ssh://git@github.com/x/tinyspy.git'; }],
      ['resolved other file', (e) => { e.resolved = 'https://registry.npmjs.org/tinyspy/-/evil-3.0.2.tgz'; }],
      ['no integrity', (e) => { delete e.integrity; }],
      ['sha1', (e) => { e.integrity = 'sha1-2jmsmO3Jpi3F+xWR2LJ5GBN5/qs='; }],
      ['link', (e) => { e.link = true; }],
      ['inBundle', (e) => { e.inBundle = true; }],
      ['hasShrinkwrap', (e) => { e.hasShrinkwrap = true; }],
      ['bundled', (e) => { e.bundleDependencies = ['x']; }],
      ['alias dependency', (e) => { e.dependencies = { x: 'npm:evil@1.0.0' }; }],
      ['git dependency', (e) => { e.dependencies = { x: 'github:evil/x' }; }],
      ['url dependency', (e) => { e.dependencies = { x: 'https://evil.example/x.tgz' }; }],
      ['file dependency', (e) => { e.dependencies = { x: 'file:../x' }; }],
    ] as [string, (e: Record<string, unknown>) => void][]) expect(lp(OLD, edit((l) => { mut(l.packages['node_modules/tinyspy'] as Record<string, unknown>); })), what).toMatch(/tinyspy/);
  });
  it('a key that is not node_modules/<name>[/node_modules/<name>]... is refused (no path, link target, dot segment, other folder)', () => {
    for (const key of ['packages/evil', 'node_modules/../x', 'node_modules/a/b', '../x', 'node_modules/vitest/../../x', 'node_modules/', 'node_modules/Evil', 'evil']) {
      expect(lp(OLD, edit((l) => { l.packages[key] = ent('evil', '1.0.0'); })), key).toMatch(/not a package under node_modules|closure/);
    }
  });
  it('lockfileVersion must be 3; any top-level key but packages must be unchanged; the old file must be v3 too', () => {
    expect(lp(OLD, edit((l) => { l.lockfileVersion = 2; }))).toMatch(/lockfileVersion/);
    expect(lp(OLD, edit((l) => { l.dependencies = {}; }))).toMatch(/dependencies|top level/);
    expect(lp(OLD, edit((l) => { l.name = 'other'; }))).toMatch(/top level|name/);
    expect(lp(edit((l) => { l.lockfileVersion = 2; }, OLD), GOOD)).toMatch(/lockfileVersion/);
    const v2 = (t: string): string => edit((l) => { l.lockfileVersion = 2; }, t);
    expect(lp(v2(OLD), v2(OLD))).toMatch(/not lockfileVersion 3/);
    expect(lp(v2(OLD), v2(GOOD))).toMatch(/not lockfileVersion 3/);
  });
  it('bad text: not JSON, packages missing, a repeated key, a repeated entry key', () => {
    expect(lp('{', GOOD)).toMatch(/original/);
    expect(lp(OLD, 'x')).toMatch(/new/);
    expect(lp(OLD, '{"lockfileVersion":3}')).toMatch(/packages/);
    const dup = GOOD.replace('"node_modules/tinyspy": {', '"node_modules/tinyspy": {"version":"3.0.2","version":"9.9.9"},\n"node_modules/tinyspy": {');
    expect(lp(OLD, dup)).toMatch(/repeated/);
  });
  it('an added package that is already in the lock at the B2 version, with no change to existing entries, passes', () => {
    const old = lockOf(OLD_ROOT, { ...OLD_PKGS, 'node_modules/c8': ent('c8', '12.0.0', { dev: true }) });
    const next = lockOf({ ...OLD_ROOT, devDependencies: { typescript: '5.6.0', c8: '12.0.0' } }, { ...OLD_PKGS, 'node_modules/c8': ent('c8', '12.0.0', { dev: true }) });
    expect(lp(old, next)).toBe('');
  });
  it('the reviewed integrity of a pin, when given, must match', () => {
    const integrity = { vitest: sri('vitest@5.0.5'), '@vitest/coverage-v8': sri('@vitest/coverage-v8@5.0.5') };
    expect(lp(OLD, GOOD, { integrity })).toBe('');
    expect(lp(OLD, GOOD, { integrity: { ...integrity, vitest: sri('other') } })).toMatch(/vitest.*reviewed/);
  });
  it('with the new package.json given, the lock root devDependencies must equal it', () => {
    const pkg = pj({ ...BASE, devDependencies: { typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } });
    expect(lp(OLD, GOOD, { packageJson: pkg })).toBe('');
    expect(lp(OLD, GOOD, { packageJson: pj({ ...BASE, devDependencies: { typescript: '5.6.0', vitest: '5.0.5' } }) })).toMatch(/package\.json/);
    expect(lp(OLD, GOOD, { packageJson: '{' })).toMatch(/package\.json/);
  });
});
