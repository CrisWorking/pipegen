import * as childProcess from 'node:child_process';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import fg from 'fast-glob';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NotGitHubRepoError, readProject } from '../src/read/project.js';
import { cleanupRepos, makeRepo, writeIn } from './helpers/make-repo.js';

const CP_FNS = ['spawn', 'exec', 'execFile', 'fork', 'spawnSync', 'execSync', 'execFileSync'] as const;

// Wrap every child_process function and every execa entry point so the test can see whether pipegen's code calls any.
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  const wrapped: Record<string, unknown> = { ...actual };
  for (const name of ['spawn', 'exec', 'execFile', 'fork', 'spawnSync', 'execSync', 'execFileSync'] as const) {
    wrapped[name] = vi.fn(actual[name] as (...args: unknown[]) => unknown);
  }
  return { ...wrapped, default: wrapped };
});
vi.mock('execa', () => ({ execa: vi.fn(), execaSync: vi.fn(), execaCommand: vi.fn(), execaCommandSync: vi.fn(), execaNode: vi.fn(), $: vi.fn() }));

const GH = 'https://github.com/o/r.git';
const repo = (fixture: string) => makeRepo(fixture, GH);

afterEach(() => {
  vi.restoreAllMocks();
  cleanupRepos();
});

describe('read', () => {
  it('node-npm → 1 service, packageManager npm, runtimeVersion from .nvmrc', async () => {
    const p = await readProject(repo('node-npm'));
    expect(p.services).toHaveLength(1);
    expect(p.services[0]).toMatchObject({ path: '.', language: 'node', packageManager: 'npm', runtimeVersion: '20' });
    expect(p.monorepo).toBe('none');
  });

  it('pnpm workspaces → one service per package', async () => {
    const p = await readProject(repo('node-pnpm-workspaces'));
    expect(p.monorepo).toBe('pnpm-workspaces');
    expect(p.services.map((s) => s.path).sort()).toEqual(['packages/api', 'packages/web']); // packages/lib has no start/dev script and no Dockerfile
    expect(p.services.map((s) => s.name).sort()).toEqual(['@mono/api', '@mono/web']);
    expect(p.services.every((s) => s.packageManager === 'pnpm')).toBe(true);
    expect(p.services.find((s) => s.path === 'packages/api')?.dockerfile).toBe('packages/api/Dockerfile');
  });

  it('python-poetry → language python, packageManager poetry, testFramework pytest', async () => {
    const p = await readProject(repo('python-poetry'));
    expect(p.services[0]).toMatchObject({ language: 'python', packageManager: 'poetry', testFramework: 'pytest', hasTests: true, runtimeVersion: '^3.11' });
    const uv = await readProject(repo('python-uv'));
    expect(uv.services[0]).toMatchObject({ language: 'python', packageManager: 'uv', runtimeVersion: '3.12' });
  });

  it('port from Dockerfile EXPOSE, else from code default', async () => {
    const ws = await readProject(repo('node-pnpm-workspaces'));
    expect(ws.services.find((s) => s.path === 'packages/api')?.port).toBe(4000);
    expect((await readProject(repo('node-express'))).services[0]?.port).toBe(3000);
    expect((await readProject(repo('python-uv'))).services[0]?.port).toBe(8000);
    expect((await readProject(repo('node-npm'))).services[0]?.port).toBeUndefined();
    const both = repo('node-express');
    writeIn(both, 'Dockerfile', 'FROM node:20\nEXPOSE 8080/tcp\n');
    expect((await readProject(both)).services[0]?.port).toBe(8080);
  });

  it('jest detected from devDependencies', async () => {
    const dir = repo('node-npm');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'x', devDependencies: { jest: '^29.0.0' } }));
    expect((await readProject(dir)).services[0]?.testFramework).toBe('jest');
    for (const fw of ['vitest', 'mocha', 'ava']) {
      writeIn(dir, 'package.json', JSON.stringify({ name: 'x', devDependencies: { [fw]: '1.0.0' } }));
      expect((await readProject(dir)).services[0]?.testFramework).toBe(fw);
    }
    writeIn(dir, 'package.json', JSON.stringify({ name: 'x', scripts: { test: 'node --test' } }));
    expect((await readProject(dir)).services[0]?.testFramework).toBe('node:test');
  });

  it('gitlab remote → NotGitHubRepoError', async () => {
    await expect(readProject(makeRepo('node-npm', 'https://gitlab.com/o/r.git'))).rejects.toBeInstanceOf(NotGitHubRepoError);
    await expect(readProject(makeRepo('node-npm', 'git@gitlab.com:o/r.git'))).rejects.toBeInstanceOf(NotGitHubRepoError);
  });

  it('no remote → NotGitHubRepoError', async () => {
    await expect(readProject(makeRepo('node-npm'))).rejects.toBeInstanceOf(NotGitHubRepoError);
    await expect(readProject(makeRepo('node-npm').replace(/.$/, 'missing'))).rejects.toBeInstanceOf(NotGitHubRepoError);
  });

  it('owner/repo parsed from .git/config text; no child process started', async () => {
    const urls = ['git@github.com:octo/hello.git', 'https://github.com/octo/hello.git', 'https://github.com/octo/hello', 'https://github.com/octo/hello/'];
    const dirs = urls.map((u) => makeRepo('node-npm', u)); // makeRepo itself runs git: allowed
    const spies = [...CP_FNS.map((n) => vi.mocked(childProcess[n])), vi.mocked((await import('execa')).execa)];
    spies.forEach((s) => s.mockClear());
    for (const dir of dirs) {
      const p = await readProject(dir);
      expect([p.owner, p.repo]).toEqual(['octo', 'hello']);
    }
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it('hasTests true for test folders and test file patterns (*.test.*, *.spec.*, test_*.py, *_test.py)', async () => {
    const base = repo('node-library');
    expect((await readProject(base)).services[0]?.hasTests).toBe(false);
    const cases = ['test/a.js', 'tests/a.js', '__tests__/a.js', 'src/a.test.js', 'src/b.spec.ts', 'pkg/test_foo.py', 'pkg/foo_test.py'];
    for (const file of cases) {
      const dir = repo('node-library');
      writeIn(dir, file, '');
      expect((await readProject(dir)).services[0]?.hasTests, file).toBe(true);
    }
    const near = repo('node-library');
    writeIn(near, 'src/contest.js', '');
    writeIn(near, 'src/latest/a.js', '');
    expect((await readProject(near)).services[0]?.hasTests).toBe(false);
  });

  it('hasTests false when scripts.test is npm\'s default "no test specified"; true for a real scripts.test', async () => {
    const dir = repo('node-library');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'x', scripts: { test: 'echo "Error: no test specified" && exit 1' } }));
    expect((await readProject(dir)).services[0]?.hasTests).toBe(false);
    writeIn(dir, 'package.json', JSON.stringify({ name: 'x', scripts: { test: 'node check.js' } }));
    expect((await readProject(dir)).services[0]?.hasTests).toBe(true);
  });

  it('scripts names from package.json and pyproject', async () => {
    expect((await readProject(repo('node-npm'))).services[0]?.scripts).toEqual(['start', 'build']);
    expect((await readProject(repo('python-poetry'))).services[0]?.scripts).toEqual(['serve']);
    expect((await readProject(repo('python-uv'))).services[0]?.scripts).toEqual(['uv-app']);
  });

  it('frameworks detected (express, fastify, @nestjs/core, next, koa, hapi, flask, fastapi, django)', async () => {
    const node: [string, string][] = [['express', 'express'], ['fastify', 'fastify'], ['@nestjs/core', '@nestjs/core'], ['next', 'next'], ['koa', 'koa'], ['@hapi/hapi', 'hapi'], ['hapi', 'hapi']];
    for (const [dep, name] of node) {
      const dir = repo('node-library');
      writeIn(dir, 'package.json', JSON.stringify({ name: 'x', dependencies: { [dep]: '1.0.0', lodash: '4.0.0' } }));
      expect((await readProject(dir)).services[0]?.frameworks, dep).toEqual([name]);
    }
    for (const name of ['flask', 'fastapi', 'django']) {
      const dir = repo('python-uv');
      writeIn(dir, 'pyproject.toml', `[project]\nname = "x"\ndependencies = ["${name}>=1.0", "requests"]\n`);
      expect((await readProject(dir)).services[0]?.frameworks, name).toEqual([name]);
    }
    const req = repo('mixed-folders');
    expect((await readProject(req)).services.find((s) => s.path === 'api')?.frameworks).toEqual(['flask']);
    expect((await readProject(repo('node-npm'))).services[0]?.frameworks).toEqual([]);
  });

  it('later fields start as stubs (existingWorkflows [], precommit null, envVars [], dependsOn [], defaultBranch \'main\')', async () => {
    const p = await readProject(repo('node-pnpm-workspaces'));
    expect(p.existingWorkflows).toEqual([]);
    expect(p.precommit).toBeNull();
    expect(p.defaultBranch).toBe('main');
    expect(p.services.length).toBeGreaterThan(0);
    for (const s of p.services) {
      expect(s.envVars).toEqual([]);
      expect(s.dependsOn).toEqual([]);
    }
  });

  it('mixed folders → folders monorepo; library without start script or Dockerfile → root service', async () => {
    const mixed = await readProject(repo('mixed-folders'));
    expect(mixed.monorepo).toBe('folders');
    expect(mixed.services.map((s) => [s.path, s.language, s.port])).toEqual([['api', 'python', 5000], ['web', 'node', 3000]]);
    const lib = await readProject(repo('node-library'));
    expect(lib.services.map((s) => s.path)).toEqual(['.']);
    expect(lib.services[0]?.name).toBe('tiny-lib');
  });

  it('monorepo markers: turbo.json, nx.json, npm/yarn workspaces', async () => {
    const turbo = repo('node-library');
    writeIn(turbo, 'turbo.json', '{}');
    expect((await readProject(turbo)).monorepo).toBe('turbo');
    const nx = repo('node-library');
    writeIn(nx, 'nx.json', '{}');
    expect((await readProject(nx)).monorepo).toBe('nx');
    for (const [lock, expected] of [['package-lock.json', 'npm-workspaces'], ['yarn.lock', 'yarn-workspaces']] as const) {
      const dir = repo('node-library');
      writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: ['apps/*'] }));
      writeIn(dir, lock, '');
      writeIn(dir, 'apps/one/package.json', JSON.stringify({ name: 'one', scripts: { dev: 'x' } }));
      const p = await readProject(dir);
      expect(p.monorepo).toBe(expected);
      expect(p.services.map((s) => s.path)).toEqual(['apps/one']);
    }
  });

  it('read limits: oversized package.json skipped with a note; hostile files do not crash', async () => {
    const dir = repo('node-npm');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}' + ' '.repeat(1_000_001));
    writeIn(dir, 'pnpm-workspace.yaml', 'a: &a [1]\nb:\n' + Array.from({ length: 60 }, () => '  - *a').join('\n'));
    mkdirSync(join(dir, 'node_modules/dep'), { recursive: true });
    writeFileSync(join(dir, 'node_modules/dep/package.json'), '{"scripts":{"start":"x"}}');
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(notes.some((n) => n.includes('package.json') && /skipped/i.test(n))).toBe(true);
    expect(notes.some((n) => n.includes('pnpm-workspace.yaml'))).toBe(true);
    expect(p.services.map((s) => s.path)).toEqual(['.']);
  });

  it('read limits: note when more than 20,000 files', async () => {
    const dir = repo('node-npm');
    for (let d = 0; d < 100; d++) {
      mkdirSync(join(dir, `bulk${d}`));
      for (let f = 0; f < 201; f++) writeFileSync(join(dir, `bulk${d}`, `f${f}.txt`), '');
    }
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(notes).toContain('Only the first 20,000 files were read. Results may be incomplete.');
    // root manifests are read by direct path, so the 20k cap cannot hide them
    expect(p.services[0]).toMatchObject({ path: '.', packageManager: 'npm', runtimeVersion: '20' });
  });

  it('read limits: port regex ignores lines longer than 4 KB', async () => {
    const dir = repo('node-library');
    writeIn(dir, 'server.js', `app.listen(process.env.PORT || 7777); // ${'x'.repeat(5000)}\n`);
    expect((await readProject(dir)).services[0]?.port).toBeUndefined();
    writeIn(dir, 'server.js', 'app.listen(process.env.PORT || 7777);\n');
    expect((await readProject(dir)).services[0]?.port).toBe(7777);
  });

  it('read: hostile workspace globs (\'../**\', \'/**\', \'C:/x\') are refused with a note and no out-of-repo service', async () => {
    const outside = makeRepo('node-library'); // a sibling directory with a package.json that would match '../**'
    const dir = repo('node-library');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: ['../**', '/**', 'C:/x', '~/x', 'a/../../b', 'apps/*'] }));
    writeIn(dir, 'apps/one/package.json', JSON.stringify({ name: 'one', scripts: { dev: 'x' } }));
    const spy = vi.spyOn(fg, 'stream');
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(spy).toHaveBeenCalledTimes(1); // only the one capped listing; workspace globs match in memory
    expect(p.services.map((s) => s.path)).toEqual(['apps/one']);
    expect(notes.filter((n) => /workspace pattern/i.test(n))).toHaveLength(5);
    expect(outside).not.toBe(dir);
  });

  it('read: at most 100 workspace patterns are used, with a note', async () => {
    const dir = repo('node-library');
    const patterns = Array.from({ length: 101 }, (_, i) => `apps/a${i}`);
    writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: patterns }));
    writeIn(dir, 'apps/a0/package.json', JSON.stringify({ name: 'a0', scripts: { dev: 'x' } }));
    writeIn(dir, 'apps/a100/package.json', JSON.stringify({ name: 'a100', scripts: { dev: 'x' } }));
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(p.services.map((s) => s.name)).toEqual(['a0']);
    expect(notes.some((n) => /100 workspace patterns/.test(n))).toBe(true);
  });

  it('read: a 5 KB script value containing node --test does not set node:test', async () => {
    const dir = repo('node-library');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'x', scripts: { test: `${'x'.repeat(5000)} node --test` } }));
    expect((await readProject(dir)).services[0]?.testFramework).toBeUndefined();
  });

  it('read: .git that is a symlink, a file (worktree) or has a non-regular config is refused', async () => {
    const link = makeRepo('node-npm', GH);
    rmSync(join(link, '.git'), { recursive: true });
    symlinkSync(join(link, 'package.json'), join(link, '.git'));
    await expect(readProject(link)).rejects.toThrow(/symbolic link; refusing to follow it/);

    const wt = makeRepo('node-npm', GH);
    rmSync(join(wt, '.git'), { recursive: true });
    writeIn(wt, '.git', 'gitdir: /elsewhere/.git/worktrees/x\n');
    await expect(readProject(wt)).rejects.toThrow(/worktree or submodule; run pipegen from the main checkout/);

    const cfg = makeRepo('node-npm', GH);
    rmSync(join(cfg, '.git/config'));
    symlinkSync(join(cfg, 'package.json'), join(cfg, '.git/config'));
    await expect(readProject(cfg)).rejects.toBeInstanceOf(NotGitHubRepoError);
  });

  it('read: git config section and key names are case-insensitive, "origin" is not', async () => {
    const ok = makeRepo('node-npm');
    writeIn(ok, '.git/config', '[Core]\n\tbare = false\n[Remote "origin"]\n\tURL = git@github.com:octo/hello.git\n');
    expect(await readProject(ok)).toMatchObject({ owner: 'octo', repo: 'hello' });
    const upper = makeRepo('node-npm');
    writeIn(upper, '.git/config', '[remote "Origin"]\n\turl = https://github.com/octo/hello.git\n');
    await expect(readProject(upper)).rejects.toBeInstanceOf(NotGitHubRepoError);
  });

  it('read: owner and repo names are validated', async () => {
    const bad = [
      'https://github.com/-bad/repo.git', 'https://github.com/a_b/repo.git', `https://github.com/${'a'.repeat(40)}/repo`,
      'https://github.com/o/..', 'https://github.com/o/.', 'https://github.com/o/..git', `https://github.com/o/${'r'.repeat(101)}`,
    ];
    for (const url of bad) await expect(readProject(makeRepo('node-npm', url)), url).rejects.toBeInstanceOf(NotGitHubRepoError);
    expect(await readProject(makeRepo('node-npm', 'https://github.com/o-1/my.repo_x-y.git'))).toMatchObject({ owner: 'o-1', repo: 'my.repo_x-y' });
  });

  it('read: Dockerfiles under .devcontainer, test, fixtures, examples, docs are not services', async () => {
    const dir = repo('node-npm');
    writeIn(dir, 'Dockerfile', 'FROM node:20\n');
    for (const d of ['.devcontainer', 'test/e2e', 'tests', '__tests__', 'fixtures/a', 'examples/demo', 'docs']) writeIn(dir, `${d}/Dockerfile`, 'FROM node:20\n');
    const p = await readProject(dir);
    expect(p.services.map((s) => s.path)).toEqual(['.']);
    expect(p.monorepo).toBe('none');
  });

  it('read: skip notes give the real reason', async () => {
    const dir = repo('node-npm');
    writeFileSync(join(dir, 'package.json'), '{"name":"x"}' + ' '.repeat(1_000_001));
    writeIn(dir, 'pyproject.toml', 'not [valid');
    const notes: string[] = [];
    await readProject(dir, { notes });
    expect(notes).toContain('Skipped package.json: it is larger than 1 MB.');
    expect(notes).toContain('Skipped pyproject.toml: it could not be parsed.');
  });
});
