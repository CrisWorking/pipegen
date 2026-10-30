// Plan P Task 1: the per-service quality facts and the repo files the new checks read (src/read/quality.ts), with the
// rulings PS3 (empty builders), PS4 (bounded reads) and PS5 (no unused facts).
import { closeSync, ftruncateSync, mkdirSync, openSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as limits from '../src/read/limits.js';
import { readProject } from '../src/read/project.js';
import { emptyRepoFiles, emptyServiceQuality, K8S_FOLDERS, lockfileVersions, MAX_K8S_YAML_FILES, newQualityRun, QUALITY_PACKAGES, readRepoFiles, readServiceQuality } from '../src/read/quality.js';
import type { Service } from '../src/types.js';
import { hostileNames } from './fixtures/hostile-names.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

// Wrap the bounded line reader so a test can count how often each lockfile is read (PS4: once per run).
vi.mock('../src/read/limits.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/read/limits.js')>();
  return { ...actual, readLinesLimited: vi.fn(actual.readLinesLimited), readTextLimitedWithReason: vi.fn(actual.readTextLimitedWithReason) };
});

const GH = 'https://github.com/o/r.git';
const FIX = resolve(import.meta.dirname, 'fixtures/quality');
const fixture = (name: string) => readFileSync(join(FIX, name), 'utf8');
const MB = 1024 * 1024;
// Built at runtime: the redact patterns (rightly) hide any value next to a key named after a secret.
const BASELINE = ['.sec', 'rets.baseline'].join('');
const BASELINE_FACT = ['sec', 'retsBaseline'].join('');

/** A temp repo with an `origin` remote (read as text by readProject; no git needed) and these files. */
function repo(files: Record<string, string>): string {
  const dir = makeTempDir();
  writeIn(dir, '.git/config', `[remote "origin"]\n\turl = ${GH}\n`);
  for (const [rel, content] of Object.entries(files)) writeIn(dir, rel, content);
  return dir;
}

/** A sparse file of `bytes` (no disk used): its size is what the read limits look at first. */
function sparse(dir: string, rel: string, bytes: number): void {
  mkdirSync(join(dir, rel, '..'), { recursive: true });
  const fd = openSync(join(dir, rel), 'w');
  ftruncateSync(fd, bytes);
  closeSync(fd);
}

const pkg = (o: object) => JSON.stringify(o, null, 2);
const nodeSvc = (path = '.', frameworks: string[] = []): Pick<Service, 'path' | 'language' | 'frameworks'> => ({ path, language: 'node', frameworks });
const pySvc = (path = '.', frameworks: string[] = []): Pick<Service, 'path' | 'language' | 'frameworks'> => ({ path, language: 'python', frameworks });
const TS_ESLINT = { devDependencies: { eslint: '^9.0.0', typescript: '^5.4.0' } };

afterEach(() => {
  vi.mocked(limits.readLinesLimited).mockClear();
  cleanupRepos();
});

describe('quality: lockfile versions', () => {
  it('quality: package-lock v3, pnpm v9, yarn berry and bun.lock give the same typescript and eslint versions', async () => {
    const cases: [string, string][] = [
      ['package-lock.json', 'package-lock.v3.json'],
      ['package-lock.json', 'package-lock.v1.json'],
      ['npm-shrinkwrap.json', 'package-lock.v3.json'],
      ['pnpm-lock.yaml', 'pnpm-lock.v9.yaml'],
      ['yarn.lock', 'yarn.berry.lock'],
      ['yarn.lock', 'yarn.classic.lock'],
      ['bun.lock', 'bun.v1.lock'],
    ];
    for (const [name, source] of cases) {
      const dir = repo({ 'package.json': pkg(TS_ESLINT), [name]: fixture(source) });
      const r = await lockfileVersions(dir, '.', QUALITY_PACKAGES);
      // the nested eslint 8.57.0 (under old-plugin) is never the service's own eslint
      expect(r, source).toEqual({ versions: { typescript: '5.4.5', eslint: '9.1.1' }, fromRange: [] });
    }
  });

  it('quality: lockfile over 64 MB → versions from package.json ranges, listed in fromRange, with a note', async () => {
    const dir = repo({ 'package.json': pkg(TS_ESLINT) });
    sparse(dir, 'package-lock.json', 65 * MB);
    const r = await lockfileVersions(dir, '.', QUALITY_PACKAGES);
    expect(r.versions).toEqual({ typescript: '5.4.0', eslint: '9.0.0' });
    expect([...r.fromRange].sort()).toEqual(['eslint', 'typescript']);
    expect(r.note).toMatch(/package-lock\.json is larger than 64 MB/);
    expect(r.note).toMatch(/package\.json ranges/);
    expect(limits.readLinesLimited).not.toHaveBeenCalled(); // refused on its size, never opened for reading
  });

  it('quality (PS4): one 128 MB lockfile budget per run; a lockfile past it falls back to ranges with a note', async () => {
    const files: Record<string, string> = {};
    for (const s of ['a', 'b', 'c']) Object.assign(files, { [`${s}/package.json`]: pkg({ name: s, scripts: { start: 'node .' }, ...TS_ESLINT }), [`${s}/Dockerfile`]: 'FROM scratch\n' });
    const dir = repo(files);
    for (const s of ['a', 'b', 'c']) sparse(dir, `${s}/package-lock.json`, 60 * MB);
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(p.services.map((s) => s.path)).toEqual(['a', 'b', 'c']);
    for (const s of p.services) expect([...s.quality.fromRange].sort()).toEqual(['eslint', 'typescript']);
    expect(notes.join('\n')).toMatch(/c\/package-lock\.json.*128 MB/);
    expect(limits.readLinesLimited).toHaveBeenCalledTimes(2); // a and b (binary: a sparse file is all zeros); c never opened
  });

  it('quality: bun.lockb is binary → an unknown lockfile version, the range as fromRange, never a crash', async () => {
    const dir = repo({ 'package.json': pkg(TS_ESLINT) });
    writeFileSync(join(dir, 'bun.lockb'), Buffer.from([0x23, 0x21, 0x2f, 0x00, 0x01, 0x02, 0xff, 0x00]));
    const r = await lockfileVersions(dir, '.', QUALITY_PACKAGES);
    expect(r.versions).toEqual({ typescript: '5.4.0', eslint: '9.0.0' });
    expect([...r.fromRange].sort()).toEqual(['eslint', 'typescript']);
    expect(r.note).toMatch(/bun\.lockb is a binary file/);
  });

  it('quality: a version range vs an exact version: only versions not read from the lockfile are in fromRange', async () => {
    const declared = { devDependencies: { typescript: '5.4.5', eslint: '^9.1.0', prettier: '>=3.0.0', vitest: '~1.6.0', jest: '^29 || ^30', knip: 'latest', c8: '^10' } };
    const none = await lockfileVersions(repo({ 'package.json': pkg(declared) }), '.', QUALITY_PACKAGES);
    // an exact pin in package.json is still not the lockfile; complex ranges and tags are dropped, never guessed
    expect(none.versions).toEqual({ typescript: '5.4.5', eslint: '9.1.0', prettier: '3.0.0', vitest: '1.6.0', c8: '10.0.0' });
    expect([...none.fromRange].sort()).toEqual(['c8', 'eslint', 'prettier', 'typescript', 'vitest']);
    expect(none.note).toMatch(/no lockfile/);

    // the lockfile pins typescript only: typescript leaves fromRange, eslint stays in it
    const lock = ['lockfileVersion: \'9.0\'', '', 'importers:', '', '  .:', '    devDependencies:', '      typescript:', '        specifier: 5.4.5', '        version: 5.4.5', ''].join('\n');
    const some = await lockfileVersions(repo({ 'package.json': pkg({ devDependencies: { typescript: '5.4.5', eslint: '^9.1.0' } }), 'pnpm-lock.yaml': lock }), '.', QUALITY_PACKAGES);
    expect(some).toEqual({ versions: { typescript: '5.4.5', eslint: '9.1.0' }, fromRange: ['eslint'], note: expect.stringMatching(/eslint/) });
    expect(some.note).not.toMatch(/typescript/);
  });

  it('quality: a lockfile version that fails the version pattern is dropped (secret-like or hostile text is never kept)', async () => {
    const lock = (v: string) => ['lockfileVersion: \'9.0\'', 'importers:', '  .:', '    devDependencies:', '      typescript:', '        specifier: ^5.4.0', `        version: ${v}`, ''].join('\n');
    for (const bad of [fake.githubClassic(), `5.4.5-${hostileNames.bidiOverride}`, 'link:../ts', `5.4.5-${'a'.repeat(41)}`]) {
      const r = await lockfileVersions(repo({ 'package.json': pkg({ devDependencies: { typescript: '^5.4.0' } }), 'pnpm-lock.yaml': lock(bad) }), '.', QUALITY_PACKAGES);
      expect(r.versions, bad.slice(0, 8)).toEqual({ typescript: '5.4.0' });
      expect(r.fromRange).toEqual(['typescript']);
      expect(JSON.stringify(r)).not.toContain(bad);
    }
    const ok = await lockfileVersions(repo({ 'package.json': pkg({ devDependencies: { typescript: '^7.0.0-beta' } }), 'pnpm-lock.yaml': lock('7.0.0-dev.20261020.1') }), '.', QUALITY_PACKAGES);
    expect(ok).toEqual({ versions: { typescript: '7.0.0-dev.20261020.1' }, fromRange: [] });
  });

  it('quality: workspace packages read their own importer / nested entry, else the root\'s hoisted one', async () => {
    const root = { name: 'mono', private: true, workspaces: ['packages/*'], devDependencies: { typescript: '^5.4.0' } };
    const web = { name: 'web', scripts: { start: 'next start' }, dependencies: { next: '^15.0.0' }, devDependencies: { eslint: '^9.0.0' } };
    const lock = pkg({
      name: 'mono', lockfileVersion: 3, requires: true,
      packages: {
        '': { name: 'mono', workspaces: ['packages/*'], devDependencies: { typescript: '^5.4.0' } },
        'node_modules/eslint': { version: '8.57.0' },
        'node_modules/typescript': { version: '5.4.5' },
        'node_modules/web': { resolved: 'packages/web', link: true },
        'packages/web': { name: 'web', devDependencies: { eslint: '^9.0.0' } },
        'packages/web/node_modules/eslint': { version: '9.1.1' },
      },
    });
    const dir = repo({ 'package.json': pkg(root), 'package-lock.json': lock, 'packages/web/package.json': pkg(web) });
    const p = await readProject(dir);
    expect(p.services.map((s) => s.path)).toEqual(['packages/web']);
    expect(p.services[0]?.quality).toMatchObject({ versions: { typescript: '5.4.5', eslint: '9.1.1' }, fromRange: [], uiFrameworks: ['next'] });
  });
});

describe('quality: configs and frameworks', () => {
  it('quality: eslint.config.mjs → flat; .eslintrc.json only → eslintrc; both → both', async () => {
    const kind = async (files: Record<string, string>) => (await readServiceQuality(repo({ 'package.json': pkg({}), ...files }), nodeSvc(), [])).eslintConfig;
    expect(await kind({ 'eslint.config.mjs': 'export default [];\n' })).toBe('flat');
    expect(await kind({ 'eslint.config.cts': 'module.exports = [];\n' })).toBe('flat');
    expect(await kind({ '.eslintrc.json': '{}\n' })).toBe('eslintrc');
    expect(await kind({ '.eslintrc': '{}\n' })).toBe('eslintrc');
    expect(await kind({ 'package.json': pkg({ eslintConfig: { root: true } }) })).toBe('eslintrc');
    expect(await kind({ 'eslint.config.js': 'export default [];\n', '.eslintrc.yml': 'root: true\n' })).toBe('both');
    expect(await kind({})).toBe('none');
  });

  it('quality (T1 review I1): a root setup.cfg/tox.ini is read once per run, not once per Python service', async () => {
    const files: Record<string, string> = { 'setup.cfg': '[mypy]\nstrict = true\n', 'tox.ini': '[tox]\nenv_list = py\n' };
    for (let i = 0; i < 30; i++) files[`svc${i}/pyproject.toml`] = `[project]\nname = "svc${i}"\n`;
    const dir = repo(files);
    const dirs = Array.from({ length: 30 }, (_, i) => `svc${i}`);
    const run = newQualityRun(dir, Object.keys(files), dirs);
    vi.mocked(limits.readTextLimitedWithReason).mockClear();
    const out = [];
    for (const d of dirs) out.push(await readServiceQuality(dir, pySvc(d), [], run));
    const reads = vi.mocked(limits.readTextLimitedWithReason).mock.calls.map((c) => String(c[0]));
    expect(reads.filter((f) => f.endsWith('setup.cfg'))).toHaveLength(1);
    expect(reads.filter((f) => f.endsWith('tox.ini'))).toHaveLength(1);
    expect(out.every((q) => q.configs.includes('mypy'))).toBe(true);
  });

  it('quality: tool configs found in the service or a folder above it, per language; tsconfig in the service only', async () => {
    const dir = repo({
      'biome.json': '{}\n', '.prettierrc': '{}\n', 'ruff.toml': '\n',
      'web/package.json': pkg({ knip: {} }), 'web/.oxlintrc.json': '{}\n', 'web/tsconfig.json': '{}\n',
      'api/pyproject.toml': '[project]\nname = "api"\n\n[tool.black]\nline-length = 100\n\n[tool.pylint.main]\njobs = 1\n',
      'api/.flake8': '[flake8]\n', 'api/mypy.ini': '[mypy]\n',
    });
    const web = await readServiceQuality(dir, nodeSvc('web'), []);
    expect(web.configs).toEqual(['biome', 'prettier', 'knip', 'oxlint']);
    expect(web.tsconfig).toBe(true);
    const api = await readServiceQuality(dir, pySvc('api'), []);
    expect(api.configs).toEqual(['ruff', 'black', 'flake8', 'pylint', 'mypy']);
    expect(api.tsconfig).toBe(false);
    expect((await readServiceQuality(dir, nodeSvc('.'), [])).tsconfig).toBe(false); // web/tsconfig.json belongs to web
    expect((await readServiceQuality(repo({ 'package.json': '{}', 'oxlint.config.ts': 'export default {};\n' }), nodeSvc(), [])).configs).toEqual(['oxlint']);
  });

  it('quality (P55): XO is configured by the `xo` key in package.json or an xo.config.* file, and its version is read', async () => {
    expect((await readServiceQuality(repo({ 'package.json': pkg({ xo: { rules: {} } }) }), nodeSvc(), [])).configs).toEqual(['xo']);
    expect((await readServiceQuality(repo({ 'package.json': pkg({}), 'xo.config.js': 'export default [];\n' }), nodeSvc(), [])).configs).toEqual(['xo']);
    expect((await readServiceQuality(repo({ 'package.json': pkg({ devDependencies: { xo: '^1.2.0' } }), 'package-lock.json': '{}' }), nodeSvc(), [])).configs).toEqual([]);
    const q = await readServiceQuality(repo({ 'package.json': pkg({ devDependencies: { xo: '^1.2.0' }, xo: {} }) }), nodeSvc(), []);
    expect(q.versions.xo).toBe('1.2.0');
  });

  it('quality: next / vue / svelte / astro / react-native detected from dependencies', async () => {
    const dir = repo({
      'package.json': pkg({ dependencies: { next: '15.0.0', vue: '^3.5.0', svelte: '^5.0.0', astro: '^5.0.0', 'react-native': '0.76.0', nuxt: '^3.0.0' } }),
      'own/package.json': pkg({ name: 'vue', dependencies: { vue: '^3.5.0' } }), // the vue repo itself doesn't USE vue
      'plain/package.json': pkg({ dependencies: { express: '^5.0.0' } }),
    });
    expect((await readServiceQuality(dir, nodeSvc(), [])).uiFrameworks).toEqual(['next', 'nuxt', 'vue', 'svelte', 'astro', 'react-native']);
    expect((await readServiceQuality(dir, nodeSvc('own'), [])).uiFrameworks).toEqual([]);
    expect((await readServiceQuality(dir, nodeSvc('plain'), [])).uiFrameworks).toEqual([]);
  });

  it('quality: python typed by [tool.mypy], pyrightconfig.json or py.typed; untyped otherwise', async () => {
    const typed = async (files: Record<string, string>) => (await readServiceQuality(repo({ 'pyproject.toml': '[project]\nname = "x"\n', ...files }), pySvc(), [])).pythonTyped;
    expect(await typed({ 'pyproject.toml': '[project]\nname = "x"\n\n[tool.mypy]\nstrict = true\n' })).toBe(true);
    expect(await typed({ 'pyproject.toml': '[tool.basedpyright]\n' })).toBe(true);
    expect(await typed({ 'pyrightconfig.json': '{}\n' })).toBe(true);
    expect(await typed({ 'src/x/py.typed': '' })).toBe(true);
    expect(await typed({ 'setup.cfg': '[metadata]\nname = x\n\n[mypy]\nstrict = True\n' })).toBe(true);
    expect(await typed({ 'tox.ini': '[tox]\n[mypy]\n' })).toBe(true);
    expect(await typed({ '.mypy.ini': '[mypy]\n' })).toBe(true);
    expect(await typed({ 'requirements-dev.txt': 'pytest\nmypy==1.13.0\n' })).toBe(true);
    expect(await typed({ 'pyproject.toml': '[project]\nname = "x"\n[dependency-groups]\ndev = ["pyright>=1.1"]\n' })).toBe(true);
    expect(await typed({})).toBe(false);
    expect(await typed({ 'setup.cfg': '[metadata]\nname = mypy-tools\n# [mypy]\n' })).toBe(false);
  });

  it('quality: openapi.yaml → apiSpec file; fastapi without a spec file → served', async () => {
    const dir = repo({ 'pyproject.toml': '[project]\nname = "x"\n', 'docs/api/openapi.yaml': 'openapi: 3.1.0\n' });
    expect((await readServiceQuality(dir, pySvc('.', ['fastapi']), [])).apiSpec).toEqual({ kind: 'file', path: 'docs/api/openapi.yaml' });
    expect((await readServiceQuality(repo({ 'pyproject.toml': '' }), pySvc('.', ['fastapi']), [])).apiSpec).toEqual({ kind: 'served', by: 'fastapi' });
    expect((await readServiceQuality(repo({ 'package.json': pkg({ dependencies: { '@nestjs/swagger': '^8.0.0' } }) }), nodeSvc(), [])).apiSpec).toEqual({ kind: 'served', by: '@nestjs/swagger' });
    for (const name of ['swagger.json', 'v1.openapi.yml', 'schema.graphql']) {
      expect((await readServiceQuality(repo({ 'package.json': '{}', [`spec/${name}`]: '{}' }), nodeSvc(), [])).apiSpec, name).toEqual({ kind: 'file', path: `spec/${name}` });
    }
    // deeper than 4 folders inside the service: not looked at
    expect((await readServiceQuality(repo({ 'package.json': '{}', 'a/b/c/d/e/openapi.json': '{}' }), nodeSvc(), [])).apiSpec).toBeNull();
    expect((await readServiceQuality(repo({ 'package.json': '{}' }), nodeSvc(), [])).apiSpec).toBeNull();
  });

  it('quality (PS4): a root service never claims another service\'s spec file; the path is relative to the repo', async () => {
    const dir = repo({
      'package.json': pkg({ scripts: { start: 'node .' } }), Dockerfile: 'FROM scratch\n',
      'packages/api/package.json': pkg({ name: 'api', scripts: { start: 'node .' } }), 'packages/api/Dockerfile': 'FROM scratch\n', 'packages/api/openapi.yaml': 'openapi: 3.1.0\n',
    });
    const p = await readProject(dir);
    expect(p.services.map((s) => [s.path, s.quality.apiSpec])).toEqual([['.', null], ['packages/api', { kind: 'file', path: 'packages/api/openapi.yaml' }]]);
  });

  it('quality: Go Fuzz function, @jazzer.js/core or atheris → fuzzTargets', async () => {
    const fuzz = async (files: Record<string, string>, svc = nodeSvc()) => (await readServiceQuality(repo(files), svc, [])).fuzzTargets;
    expect(await fuzz({ 'go.mod': 'module x\n', 'parse/parse_test.go': 'package parse\n\nimport "testing"\n\nfunc FuzzParse(f *testing.F) {\n}\n' }, { path: '.', language: 'other', frameworks: [] })).toBe(true);
    expect(await fuzz({ 'parse/parse_test.go': 'package parse\n\n// func FuzzParse is planned\nfunc TestParse(t *testing.T) {}\n' }, { path: '.', language: 'other', frameworks: [] })).toBe(false);
    expect(await fuzz({ 'parse/parse.go': 'package parse\n\nfunc FuzzParse(f *testing.F) {}\n' }, { path: '.', language: 'other', frameworks: [] })).toBe(false); // not a test file
    expect(await fuzz({ 'package.json': pkg({ devDependencies: { '@jazzer.js/core': '^2.1.0' } }) })).toBe(true);
    expect(await fuzz({ 'requirements-dev.txt': 'atheris==2.3.0\n' }, pySvc())).toBe(true);
    expect(await fuzz({ 'pyproject.toml': '[project]\nname = "x"\n[project.optional-dependencies]\nfuzz = ["atheris"]\n' }, pySvc())).toBe(true);
    expect(await fuzz({ 'package.json': pkg({ dependencies: { express: '^5.0.0' } }) })).toBe(false);
  });

  it('quality (PS4): Go fuzz detection reads at most 1 MB per test file', async () => {
    const big = `package x\n${'// filler line\n'.repeat(80_000)}func FuzzX(f *testing.F) {}\n`;
    expect(big.length).toBeGreaterThan(1_000_000);
    const notes: string[] = [];
    expect((await readServiceQuality(repo({ 'x_test.go': big }), { path: '.', language: 'other', frameworks: [] }, notes)).fuzzTargets).toBe(false);
    expect(notes).toContain('Skipped x_test.go: it is larger than 1 MB.');
  });
});

describe('repoFiles', () => {
  it('repoFiles: dependabot, each renovate spelling, Chart.yaml, deny.toml, .secrets.baseline', async () => {
    expect(await readRepoFiles(repo({}), [])).toEqual(emptyRepoFiles());
    const all = await readRepoFiles(repo({
      '.github/dependabot.yml': 'version: 2\n', 'renovate.json': '{}\n', '.github/actions.lock': '\n',
      'charts/app/Chart.yaml': 'apiVersion: v2\nname: app\n', 'deny.toml': '\n', [BASELINE]: '{}\n',
    }), []);
    expect(all).toEqual({ dependabot: '.github/dependabot.yml', codeowners: null, renovate: 'renovate.json', actionsLock: true, kubernetes: true, licenceConfig: 'deny.toml', [BASELINE_FACT]: true });
    expect('rego' in all).toBe(false); // PS5: no task reads it

    expect((await readRepoFiles(repo({ '.github/dependabot.yaml': 'version: 2\n' }), [])).dependabot).toBe('.github/dependabot.yaml');
    for (const spelling of ['renovate.json', 'renovate.json5', '.github/renovate.json', '.github/renovate.json5', '.gitlab/renovate.json', '.gitlab/renovate.json5', '.renovaterc', '.renovaterc.json', '.renovaterc.json5']) {
      expect((await readRepoFiles(repo({ [spelling]: '{}\n' }), [])).renovate, spelling).toBe(spelling);
    }
    expect((await readRepoFiles(repo({ '.renovaterc': '{}\n', '.github/renovate.json': '{}\n' }), [])).renovate).toBe('.github/renovate.json'); // the first spelling wins
    expect((await readRepoFiles(repo({ 'package.json': pkg({ renovate: { extends: ['config:recommended'] } }) }), [])).renovate).toBe('package.json');
    expect((await readRepoFiles(repo({ 'package.json': pkg({ name: 'x' }) }), [])).renovate).toBeNull();

    expect((await readRepoFiles(repo({ '.grant.yaml': 'rules: []\n' }), [])).licenceConfig).toBe('.grant.yaml');
    expect((await readRepoFiles(repo({ '.fossa.yml': 'version: 3\n' }), [])).licenceConfig).toBe('.fossa.yml');
    expect((await readRepoFiles(repo({ '.github/workflows/actions.lock': '\n' }), [])).actionsLock).toBe(true);
    expect((await readRepoFiles(repo({ 'actions.lock': '\n' }), [])).actionsLock).toBe(false);
  });

  it('repoFiles: codeowners is the first of .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS (the gate\'s order), else null', async () => {
    const co = async (files: Record<string, string>) => (await readRepoFiles(repo(files), [])).codeowners;
    expect(await co({})).toBeNull();
    expect(await co({ 'docs/CODEOWNERS': '* @a\n' })).toBe('docs/CODEOWNERS');
    expect(await co({ 'docs/CODEOWNERS': '* @a\n', CODEOWNERS: '* @a\n' })).toBe('CODEOWNERS');
    expect(await co({ 'docs/CODEOWNERS': '* @a\n', CODEOWNERS: '* @a\n', '.github/CODEOWNERS': '* @a\n' })).toBe('.github/CODEOWNERS');
    expect(await co({ 'src/CODEOWNERS': '* @a\n', 'codeowners': '* @a\n' })).toBeNull();
  });

  it('repoFiles: Kubernetes from YAML with top-level apiVersion and kind under a manifests folder only', async () => {
    const k8s = async (files: Record<string, string>) => (await readRepoFiles(repo(files), [])).kubernetes;
    const manifest = '# app\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n';
    for (const folder of ['k8s', 'kubernetes', 'manifests', 'deploy', 'helm', 'charts', 'ops/k8s/base']) expect(await k8s({ [`${folder}/app.yaml`]: manifest }), folder).toBe(true);
    expect(await k8s({ 'k8s/app.yml': `---\n${manifest}` })).toBe(true);
    expect(await k8s({ 'config/app.yaml': manifest })).toBe(false); // not a manifests folder
    expect(await k8s({ 'k8s/values.yaml': 'replicas: 2\n  apiVersion: v1\n  kind: x\n' })).toBe(false); // indented: not top-level
    expect(await k8s({ 'k8s/notes.txt': manifest })).toBe(false);
  });

  it('repoFiles: past the cap of YAML files read for Kubernetes, a "not found" says so in a note (final review m1)', async () => {
    const manifest = 'apiVersion: apps/v1\nkind: Deployment\n';
    const filler = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k8s/a${String(i).padStart(4, '0')}.yaml`, 'replicas: 2\n']));
    const capNote = `Only the first ${MAX_K8S_YAML_FILES} YAML files in Kubernetes folders (${K8S_FOLDERS.join(', ')}) were checked for Kubernetes manifests.`;
    // the manifest sorts after the cap: not seen, and the note says why
    const notes: string[] = [];
    expect((await readRepoFiles(repo({ ...filler(MAX_K8S_YAML_FILES), 'k8s/z.yaml': manifest }), notes)).kubernetes).toBe(false);
    expect(notes).toContain(capNote);
    // exactly at the cap: everything was read, no note
    const atCap: string[] = [];
    expect((await readRepoFiles(repo(filler(MAX_K8S_YAML_FILES)), atCap)).kubernetes).toBe(false);
    expect(atCap.join('\n')).not.toContain('Kubernetes');
    // found within the cap: no note either
    const found: string[] = [];
    expect((await readRepoFiles(repo({ ...filler(MAX_K8S_YAML_FILES), 'k8s/0.yaml': manifest }), found)).kubernetes).toBe(true);
    expect(found.join('\n')).not.toContain('Kubernetes');
  });
});

describe('quality: hostile repos', () => {
  it('quality: a symlinked lockfile or config is not followed', async () => {
    const outside = makeTempDir();
    writeIn(outside, 'package-lock.json', fixture('package-lock.v3.json'));
    writeIn(outside, 'eslint.config.mjs', 'export default [];\n');
    writeIn(outside, 'dependabot.yml', 'version: 2\n');
    writeIn(outside, 'tsconfig.json', '{}\n');
    writeIn(outside, 'pyproject.toml', '[tool.mypy]\n');
    const dir = repo({ 'package.json': pkg({ ...TS_ESLINT, scripts: { start: 'node .' } }) });
    for (const f of ['package-lock.json', 'eslint.config.mjs', 'tsconfig.json']) symlinkSync(join(outside, f), join(dir, f));
    mkdirSync(join(dir, '.github'));
    symlinkSync(join(outside, 'dependabot.yml'), join(dir, '.github/dependabot.yml'));
    symlinkSync(outside, join(dir, '.gitlab')); // a linked folder: .gitlab/renovate.json would be outside the repo
    writeIn(outside, 'renovate.json', '{}\n');

    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    const q = p.services[0]?.quality;
    expect(q).toMatchObject({ versions: { typescript: '5.4.0', eslint: '9.0.0' }, eslintConfig: 'none', tsconfig: false });
    expect([...(q?.fromRange ?? [])].sort()).toEqual(['eslint', 'typescript']);
    expect(p.repoFiles).toMatchObject({ dependabot: null, renovate: null });
    expect(notes).toContain('Skipped .github/dependabot.yml: it is a symbolic link.');
    expect(notes).toContain('Skipped .gitlab: it is a symbolic link.');
    expect(notes.filter((n) => /package-lock\.json is a symbolic link/.test(n))).toHaveLength(1);

    const py = repo({});
    symlinkSync(join(outside, 'pyproject.toml'), join(py, 'pyproject.toml'));
    expect((await readServiceQuality(py, pySvc(), [])).pythonTyped).toBe(false);
  });

  it('quality: hostile paths are never kept; notes name them cleaned', async () => {
    const bad = `docs${hostileNames.bidiOverride}`;
    const esc = `spec${hostileNames.ansiColour}`;
    const dir = repo({ 'package.json': '{}', [`${bad}/openapi.yaml`]: 'openapi: 3.1.0\n', [`${esc}/swagger.json`]: '{}' });
    const notes: string[] = [];
    const q = await readServiceQuality(dir, nodeSvc(), notes);
    expect(q.apiSpec).toBeNull();
    expect(notes.length).toBeGreaterThan(0);
    for (const n of notes) {
      expect(n).toMatch(/control or invisible characters/);
      expect(n).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/);
    }
    // a valid spec next to the hostile ones is still found
    writeIn(dir, 'api/openapi.yaml', 'openapi: 3.1.0\n');
    expect((await readServiceQuality(dir, nodeSvc(), [])).apiSpec).toEqual({ kind: 'file', path: 'api/openapi.yaml' });
  });

  it('quality: malformed JSON, YAML and TOML give empty facts with a note, never a crash', async () => {
    const notes: string[] = [];
    const node = await readServiceQuality(repo({ 'package.json': '{ "devDependencies": ', 'eslint.config.js': 'export default [];\n' }), nodeSvc(), notes);
    expect(node).toEqual({ ...emptyServiceQuality(), eslintConfig: 'flat' });
    expect(notes).toContain('Skipped package.json: it could not be parsed.');

    const pyNotes: string[] = [];
    const py = await readServiceQuality(repo({ 'pyproject.toml': '[tool.mypy\nstrict = ', 'pyrightconfig.json': '{ not json' }), pySvc(), pyNotes);
    expect(py.pythonTyped).toBe(true); // pyrightconfig.json counts by its presence; its text is never needed
    expect(pyNotes).toContain('Skipped pyproject.toml: it could not be parsed.');

    const yaml = '{{{ [unclosed\n  - : :\n';
    const r = await lockfileVersions(repo({ 'package.json': pkg(TS_ESLINT), 'pnpm-lock.yaml': yaml }), '.', QUALITY_PACKAGES);
    expect(r.versions).toEqual({ typescript: '5.4.0', eslint: '9.0.0' });
    expect(r.note).toMatch(/not listed in pnpm-lock\.yaml/);
    expect((await readRepoFiles(repo({ 'k8s/a.yaml': yaml, 'package.json': '{ "renovate": ' }), [])).kubernetes).toBe(false);
  });

  it('quality: lockfile lines over 4 KB are skipped (a minified lockfile gives ranges, not a crash)', async () => {
    const minified = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/typescript': { version: '5.4.5' }, pad: { x: 'y'.repeat(5000) } } });
    const r = await lockfileVersions(repo({ 'package.json': pkg({ devDependencies: { typescript: '^5.4.0' } }), 'package-lock.json': minified }), '.', QUALITY_PACKAGES);
    expect(r).toMatchObject({ versions: { typescript: '5.4.0' }, fromRange: ['typescript'] });
  });
});

describe('profile', () => {
  it('profile: readProject fills quality for every service and repoFiles once', async () => {
    const p = await readProject(makeRepo('node-pnpm-workspaces', GH));
    expect(p.services.length).toBeGreaterThan(1);
    for (const s of p.services) expect(Object.keys(s.quality).sort()).toEqual(Object.keys(emptyServiceQuality()).sort());
    expect(Object.keys(p.repoFiles).sort()).toEqual(Object.keys(emptyRepoFiles()).sort());
  });

  it('profile (PS4): a shared root lockfile is read once for all services', async () => {
    const svc = (name: string, devDependencies: object) => pkg({ name, scripts: { start: 'node .' }, devDependencies });
    const lock = [
      'lockfileVersion: \'9.0\'', '', 'importers:', '',
      '  .: {}', '',
      '  packages/a:', '    devDependencies:', '      typescript:', '        specifier: ^5.4.0', '        version: 5.4.5', '',
      '  \'packages/b\':', '    devDependencies:', '      \'@biomejs/biome\':', '        specifier: ^1.9.0', '        version: 1.9.4', '      typescript:', '        specifier: ^5.6.0', '        version: 5.6.3', '',
    ].join('\n');
    const dir = repo({
      'package.json': pkg({ name: 'mono', private: true }), 'pnpm-workspace.yaml': 'packages:\n  - packages/*\n', 'pnpm-lock.yaml': lock,
      'packages/a/package.json': svc('a', { typescript: '^5.4.0' }), 'packages/b/package.json': svc('b', { typescript: '^5.6.0', '@biomejs/biome': '^1.9.0' }),
    });
    const p = await readProject(dir);
    expect(p.services.map((s) => [s.path, s.quality.versions, s.quality.fromRange])).toEqual([
      ['packages/a', { typescript: '5.4.5' }, []],
      ['packages/b', { typescript: '5.6.3', '@biomejs/biome': '1.9.4' }, []],
    ]);
    expect(limits.readLinesLimited).toHaveBeenCalledTimes(1);
  });

  it('profile: a monorepo with mixed languages keeps each service\'s facts to its own language and folder', async () => {
    const dir = repo({
      'web/package.json': pkg({ name: 'web', scripts: { start: 'next start' }, dependencies: { next: '^15.0.0' }, devDependencies: { typescript: '^5.4.0', eslint: '^9.0.0' } }),
      'web/package-lock.json': fixture('package-lock.v3.json'), 'web/Dockerfile': 'FROM scratch\n', 'web/eslint.config.mjs': 'export default [];\n', 'web/tsconfig.json': '{}\n',
      'api/pyproject.toml': '[project]\nname = "api"\ndependencies = ["fastapi"]\n\n[tool.mypy]\nstrict = true\n\n[tool.ruff]\nline-length = 100\n',
      'api/Dockerfile': 'FROM scratch\n', 'api/docs/openapi.json': '{}\n',
      'fuzz/Dockerfile': 'FROM scratch\n', 'fuzz/go.mod': 'module fuzz\n', 'fuzz/x_test.go': 'package x\nfunc FuzzX(f *testing.F) {}\n',
      '.github/dependabot.yml': 'version: 2\n',
    });
    const p = await readProject(dir);
    const by = Object.fromEntries(p.services.map((s) => [s.path, s.quality]));
    expect(Object.keys(by).sort()).toEqual(['api', 'fuzz', 'web']);
    expect(by.web).toEqual({ ...emptyServiceQuality(), tsconfig: true, versions: { typescript: '5.4.5', eslint: '9.1.1' }, eslintConfig: 'flat', uiFrameworks: ['next'] });
    expect(by.api).toEqual({ ...emptyServiceQuality(), configs: ['ruff', 'mypy'], pythonTyped: true, apiSpec: { kind: 'file', path: 'api/docs/openapi.json' } });
    expect(by.fuzz).toEqual({ ...emptyServiceQuality(), fuzzTargets: true });
    expect(p.repoFiles.dependabot).toBe('.github/dependabot.yml');
  });
});
