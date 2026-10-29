// Plan B 6b fix round 1 (R-A, DECISIONS #107): the npm closure locks of the checker tools, and the code that refuses a
// malformed one. Offline: the files are read from data/npm-closures/.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CLOSURES } from '../scripts/npm-closure.js';
import { closureProblems, closureRootDependencies, expectedPins, loadNpmClosure, NpmClosureError } from '../src/engine/npm-closure.js';
import { loadReviewed, ReviewedListError } from '../src/engine/reviewed.js';
import { ARGV_POLICIES, runsRepoCode } from '../src/engine/tool-flags.js';
import { packageDataPath } from '../src/util/package-data.js';
import { entry, reviewedList } from './helpers/render.js';

// a checker is installed from a closure: every npm entry that does not need the repo's own dependency tree (prettier and knip are checkers by install, but load repo config: runsRepoCode(id) is true for them too)
const checkerIds = (): string[] => reviewedList().filter((t) => t.step.cli?.install.method === 'npm' && ARGV_POLICIES[t.id]?.runsRepoCode !== true).map((t) => t.id);
const closureText = (id: string): string => readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8');
const metaOf = (id: string): Record<string, unknown> => JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.meta.json`), 'utf8')) as Record<string, unknown>;
const edit = (id: string, change: (lock: { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>) => void): string => {
  const lock = JSON.parse(closureText(id)) as { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>;
  change(lock);
  return JSON.stringify(lock);
};
const firstDep = (lock: { packages: Record<string, Record<string, unknown>> }): string => Object.keys(lock.packages).find((k) => k !== '' && !k.includes('/node_modules/') && k !== 'node_modules/eslint') as string;

describe('npm closures (data)', () => {
  it('npm class: biome, eslint, eslint-typescript, oxlint-typeaware, prettier and knip are checkers; vitest-coverage and c8 run repo code; the generator script lists exactly the checkers', () => {
    expect(checkerIds().sort()).toEqual(['biome', 'eslint', 'eslint-typescript', 'knip', 'oxlint-typeaware', 'prettier']);
    expect(Object.keys(CLOSURES).sort()).toEqual(checkerIds().sort());
    for (const id of ['vitest-coverage', 'c8', 'lefthook', 'prettier', 'knip']) expect(runsRepoCode(id), id).toBe(true);
    for (const id of ['eslint', 'eslint-typescript', 'biome', 'oxlint-typeaware']) expect(runsRepoCode(id), id).toBe(false);
    // every npm policy names the reviewed bin file of its package (a constant: it is never read from a repo-influenced file)
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) if (pol.method === 'npm') expect(pol.npmBin, id).toMatch(/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/);
  });

  it('every checker has a closure lock that passes the strict check, with the reviewed top-level versions and integrities, and a meta file', () => {
    for (const id of checkerIds()) {
      const t = entry(id);
      expect(closureProblems(closureText(id), expectedPins(t)), id).toEqual([]);
      const meta = metaOf(id);
      expect(typeof meta.generatedAt, id).toBe('string');
      expect(Date.parse(meta.before as string), id).toBeLessThan(Date.parse(meta.generatedAt as string));
      expect(meta.before, id).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('eslint-typescript\'s closure pins one typescript that typescript-eslint accepts; every closure root depends on exactly the pinned packages', () => {
    const lock = JSON.parse(closureText('eslint-typescript')) as { packages: Record<string, { version?: string }> };
    expect(lock.packages['node_modules/typescript']?.version).toBe('6.0.3');
    for (const id of checkerIds()) {
      const t = entry(id);
      const names = expectedPins(t).map((p) => p.name);
      const extra = Object.keys(CLOSURES[id]?.extra ?? {});
      expect(Object.keys(closureRootDependencies(closureText(id))).sort(), id).toEqual([...names, ...extra].sort());
    }
  });
});

describe('npm closures (validation)', () => {
  const t = entry('eslint');
  const pins = expectedPins(t);

  it('a good closure is accepted', () => {
    expect(closureProblems(closureText('eslint'), pins)).toEqual([]);
  });

  it('malformed closures are refused, each for its own reason', () => {
    const dep = (lock: { packages: Record<string, Record<string, unknown>> }) => lock.packages[firstDep(lock)] as Record<string, unknown>;
    const bad: [string, string][] = [
      ['not json', '{'],
      ['lockfile v2', edit('eslint', (l) => { l.lockfileVersion = 2; })],
      ['a link', edit('eslint', (l) => { dep(l).link = true; })],
      ['a resolved outside the registry', edit('eslint', (l) => { dep(l).resolved = 'https://evil.example/x/-/x-1.0.0.tgz'; })],
      ['a file: resolved', edit('eslint', (l) => { dep(l).resolved = 'file:../vendor/x'; })],
      ['a git resolved', edit('eslint', (l) => { dep(l).resolved = 'git+https://github.com/a/b.git#abc'; })],
      ['a registry url of another package (an alias)', edit('eslint', (l) => { dep(l).resolved = 'https://registry.npmjs.org/evil/-/evil-1.0.0.tgz'; })],
      ['a http registry url', edit('eslint', (l) => { dep(l).resolved = String(dep(l).resolved).replace('https:', 'http:'); })],
      ['a missing integrity', edit('eslint', (l) => { delete dep(l).integrity; })],
      ['a sha1 integrity', edit('eslint', (l) => { dep(l).integrity = 'sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA='; })],
      ['inBundle', edit('eslint', (l) => { dep(l).inBundle = true; })],
      ['bundleDependencies', edit('eslint', (l) => { dep(l).bundleDependencies = ['x']; })],
      ['an alias dependency spec', edit('eslint', (l) => { dep(l).dependencies = { x: 'npm:evil@1.0.0' }; })],
      ['a file dependency spec', edit('eslint', (l) => { dep(l).dependencies = { x: 'file:../x' }; })],
      ['a github dependency spec', edit('eslint', (l) => { dep(l).dependencies = { x: 'github:a/b' }; })],
      ['a key outside node_modules', edit('eslint', (l) => { l.packages['vendor/evil'] = { version: '1.0.0' }; })],
      ['a root dependency that is a range', edit('eslint', (l) => { (l.packages[''] as { dependencies: Record<string, string> }).dependencies.eslint = '^10.13.0'; })],
      ['the tool at another version', edit('eslint', (l) => { l.packages['node_modules/eslint'] = { ...l.packages['node_modules/eslint'], version: '10.13.1' }; })],
      ['the tool with another integrity', edit('eslint', (l) => { (l.packages['node_modules/eslint'] as Record<string, unknown>).integrity = `sha512-${'A'.repeat(86)}==`; })],
      ['the tool missing', edit('eslint', (l) => { delete l.packages['node_modules/eslint']; })],
    ];
    for (const [why, text] of bad) expect(closureProblems(text, pins), why).not.toEqual([]);
  });

  it('a plugin missing from the closure is refused', () => {
    const b = entry('biome');
    const text = edit('biome', (l) => { delete l.packages['node_modules/@biomejs/cli-linux-x64']; });
    expect(closureProblems(text, expectedPins(b)).join(' ')).toMatch(/cli-linux-x64/);
  });

  it('loadNpmClosure: returns the text, and throws NpmClosureError for a missing or malformed file', () => {
    expect(loadNpmClosure('eslint', pins)).toBe(closureText('eslint'));
    expect(() => loadNpmClosure('eslint', pins, () => '{}')).toThrow(NpmClosureError);
    expect(() => loadNpmClosure('eslint', pins, () => { throw new Error('ENOENT'); })).toThrow(NpmClosureError);
    expect(() => loadNpmClosure('../x', pins)).toThrow(NpmClosureError);
  });

  it('the loader refuses a checker entry whose closure is missing or malformed', () => {
    const path = packageDataPath('reviewed-tools.yml');
    expect(() => loadReviewed(path, { closureReader: () => '{}' })).toThrow(ReviewedListError);
    expect(() => loadReviewed(path, { closureReader: (id) => { if (id === 'prettier') throw new Error('ENOENT'); return closureText(id); } })).toThrow(/prettier/);
    expect(loadReviewed(path).length).toBeGreaterThan(40);
  });

  it('keys with .. or . segments, absolute keys and keys outside node_modules/ are refused', () => {
    const base = (key: string): string => edit('eslint', (l) => { l.packages[key] = { ...l.packages['node_modules/eslint'], version: '1.0.0', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz' }; });
    for (const key of ['node_modules/a/../../../../evil/node_modules/x', 'node_modules/./node_modules/x', '/node_modules/x', 'node_modules/../x', 'vendor/node_modules/x', 'node_modules/x/y/node_modules/z', 'node_modules//x']) {
      expect(closureProblems(base(key), pins), key).not.toEqual([]);
    }
    // a nested dependency under its parent is fine
    expect(closureProblems(edit('eslint', (l) => { l.packages['node_modules/eslint/node_modules/ms'] = { ...l.packages[firstDep(l)] as Record<string, unknown>, resolved: 'https://registry.npmjs.org/ms/-/ms-1.0.0.tgz', version: '1.0.0' }; }), pins)).toEqual([]);
  });

  it('the root package may hold only name, version and dependencies', () => {
    for (const extra of [{ devDependencies: { x: 'file:../x' } }, { optionalDependencies: { x: 'github:a/b' } }, { scripts: { postinstall: 'x' } }]) {
      expect(closureProblems(edit('eslint', (l) => { Object.assign(l.packages[''] as object, extra); }), pins), JSON.stringify(extra)).not.toEqual([]);
    }
  });

  it('the root must depend on each pin at exactly its version, not only hold it somewhere in the lock', () => {
    const text = edit('eslint', (l) => { (l.packages[''] as { dependencies: Record<string, string> }).dependencies.eslint = '10.13.1'; });
    expect(closureProblems(text, pins).join(' ')).toMatch(/root does not depend on eslint at exactly 10\.13\.0/);
  });

  it('every dependency a closure package needs is in the closure, so nothing is looked up above the install folder (a planted node_modules in a parent can not be resolved)', () => {
    for (const id of checkerIds()) {
      const lock = JSON.parse(closureText(id)) as { packages: Record<string, { dependencies?: Record<string, string>; peerDependencies?: Record<string, string>; peerDependenciesMeta?: Record<string, { optional?: boolean }> }> };
      const keys = new Set(Object.keys(lock.packages));
      const unresolved: string[] = [];
      for (const [key, e] of Object.entries(lock.packages)) {
        const needs = [...Object.keys(e.dependencies ?? {}), ...Object.keys(e.peerDependencies ?? {}).filter((d) => e.peerDependenciesMeta?.[d]?.optional !== true)];
        for (const d of needs) {
          // node's lookup: <key>/node_modules/<d>, then each parent node_modules, then the root
          let base = key;
          let found = false;
          for (;;) {
            if (keys.has(`${base === '' ? '' : `${base}/`}node_modules/${d}`)) { found = true; break; }
            if (base === '') break;
            const cut = base.lastIndexOf('/node_modules/');
            base = cut < 0 ? '' : base.slice(0, cut);
          }
          if (!found) unresolved.push(`${key} -> ${d}`);
        }
      }
      expect(unresolved, id).toEqual([]);
    }
  });
});
