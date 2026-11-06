import * as childProcess from 'node:child_process';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import fg from 'fast-glob';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isRunnable } from '../src/engine/needs.js';
import { NotGitHubRepoError, readProject } from '../src/read/project.js';
import { cleanupRepos, makeRepo, writeIn } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';
import { expectScaling } from './helpers/scaling.js';

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

  it('defaultBranch is still a stub (\'main\') until the GitHub step', async () => {
    const p = await readProject(repo('node-pnpm-workspaces'));
    expect(p.defaultBranch).toBe('main');
    expect(p.services.length).toBeGreaterThan(0);
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

  it('read: https remotes with user and token, and ssh:// remotes, are accepted; the user info is never kept or shown', async () => {
    const cred = fake.githubClassic();
    const https = (userInfo: string, rest: string) => 'https' + '://' + userInfo + '@' + rest; // built at runtime: no URL with a password in this file
    const urls = [
      https('user:' + cred, 'github.com/octo/hello.git'), https('x-access-' + 'tok' + 'en:' + cred, 'github.com/octo/hello'), https(cred, 'github.com/octo/hello/'),
      'ssh://git@github.com/octo/hello.git', 'ssh://git@github.com/octo/hello', 'ssh://git@github.com:22/octo/hello.git',
    ];
    for (const url of urls) {
      const notes: string[] = [];
      const p = await readProject(makeRepo('node-npm', url), { notes });
      expect([p.owner, p.repo], url.replace(cred, '(hidden)')).toEqual(['octo', 'hello']);
      expect(JSON.stringify(p) + notes.join('\n')).not.toContain(cred);
    }
    for (const url of [https('user:' + cred, 'gitlab.com/octo/hello.git'), https('user:' + cred, 'github.com.evil.example/octo/hello'), https('github.com', 'evil.example/octo/hello'), 'ssh://git@github.com:2222/octo/hello', 'ssh://root@github.com/octo/hello']) {
      const err = await readProject(makeRepo('node-npm', url)).catch((e: unknown) => e);
      expect(err, url.replace(cred, '(hidden)')).toBeInstanceOf(NotGitHubRepoError);
      expect(String((err as Error).message)).not.toContain(cred);
    }
  });

  it('read: https remotes whose user info hides another host are refused', async () => {
    const bad = ['https://evil.com\\@github.com/o/r', 'https://evil.com?@github.com/o/r', 'https://evil.com#@github.com/o/r'];
    for (const url of bad) await expect(readProject(makeRepo('node-npm', url)), url).rejects.toBeInstanceOf(NotGitHubRepoError);
  });

  it('read: owner and repo names are validated', async () => {
    const bad = [
      'https://github.com/-bad/repo.git', 'https://github.com/a_b/repo.git', `https://github.com/${'a'.repeat(40)}/repo`,
      'https://github.com/o/..', 'https://github.com/o/.', 'https://github.com/o/..git', `https://github.com/o/${'r'.repeat(101)}`,
    ];
    for (const url of bad) await expect(readProject(makeRepo('node-npm', url)), url).rejects.toBeInstanceOf(NotGitHubRepoError);
    expect(await readProject(makeRepo('node-npm', 'https://github.com/o-1/my.repo_x-y.git'))).toMatchObject({ owner: 'o-1', repo: 'my.repo_x-y' });
  });

  // G17: bounded as a ratio (expectScaling), not a wall-clock budget, so a loaded machine doesn't fail it
  it('read: finding Dockerfile services next to Node workspaces is linear (P50 I3: Dockerfile folders next to a workspace)', async () => {
    // the reviewer's probe: before the fix, each Dockerfile folder scanned every file for a requirements file
    const repoOf = (folders: number) => {
      const dir = repo('node-library');
      writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: ['frontend'] }));
      writeIn(dir, 'frontend/package.json', JSON.stringify({ name: 'frontend', scripts: { dev: 'vite' } }));
      for (let i = 0; i < folders; i++) {
        writeIn(dir, `s/d${i}/Dockerfile`, 'FROM nginx\n');
        writeIn(dir, `s/d${i}/a.txt`, 'x\n');
      }
      writeIn(dir, 's/d5/requirements.txt', 'flask\n');
      return dir;
    };
    const dirs = { small: repoOf(1000), big: repoOf(8000) };
    expect((await readProject(dirs.big)).services.map((s) => s.path)).toEqual(['frontend', 's/d5']);
    // 8 times the folders: linear is at most about 8 times the time, a scan of every file per folder about 64 times
    await expectScaling('Dockerfile folders', async (size) => {
      const t = performance.now();
      await readProject(dirs[size]);
      return performance.now() - t;
    }, 16);
  }, 180_000);

  it('read: a go.mod makes a Go service, and *_test.go files are its tests (DoD cobra)', async () => {
    const p = await readProject(repo('go-module'));
    expect(p.services.map((s) => [s.path, s.language, s.hasTests])).toEqual([['.', 'go', true]]);
  });

  it('read: a Python folder with a Dockerfile is a service next to Node workspace packages (DoD fastapi)', async () => {
    // fastapi/full-stack-fastapi-template: the root package.json lists Node workspaces (frontend), and backend/ is a
    // Python app with its own Dockerfile. The workspace list names Node packages only, so it must not hide backend/.
    const p = await readProject(repo('workspaces-python-backend'));
    expect(p.services.map((s) => [s.path, s.language])).toEqual([['frontend', 'node'], ['backend', 'python']]);
    expect(p.services.find((s) => s.path === 'backend')?.hasTests).toBe(true);
    // a Dockerfile folder without a Python or Go manifest (an nginx or database image) stays out
    const infra = repo('workspaces-python-backend');
    writeIn(infra, 'nginx/Dockerfile', 'FROM nginx\n');
    expect((await readProject(infra)).services.map((s) => s.path)).toEqual(['frontend', 'backend']);
  });

  it('read: Dockerfiles under .devcontainer, test, fixtures, examples, docs are not services', async () => {
    const dir = repo('node-npm');
    writeIn(dir, 'Dockerfile', 'FROM node:20\n');
    for (const d of ['.devcontainer', 'test/e2e', 'tests', '__tests__', 'fixtures/a', 'examples/demo', 'docs']) writeIn(dir, `${d}/Dockerfile`, 'FROM node:20\n');
    const p = await readProject(dir);
    expect(p.services.map((s) => s.path)).toEqual(['.']);
    expect(p.monorepo).toBe('none');
  });

  it('read: service names are kept raw when valid, else the folder name, else "app"', async () => {
    const dir = repo('node-library');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: ['apps/*'] }));
    const svc = (name: string | undefined, folder: string) => writeIn(dir, `apps/${folder}/package.json`, JSON.stringify({ ...(name === undefined ? {} : { name }), scripts: { dev: 'x' } }));
    svc('@scope/good.name_1-x', 'a1');      // valid: kept exactly
    svc('bad\u001b[31mname', 'a2');        // control characters: folder name instead
    svc('has space', 'a3');                 // not a valid package name: folder name instead
    svc('x'.repeat(215), 'a4');             // too long: folder name instead
    svc('also bad\u202e', 'bad folder');    // invalid name and invalid folder: 'app'
    svc(undefined, 'a6');                   // no name: folder name
    const p = await readProject(dir);
    expect(p.services.map((s) => [s.path, s.name])).toEqual([
      ['apps/a1', '@scope/good.name_1-x'], ['apps/a2', 'a2'], ['apps/a3', 'a3'], ['apps/a4', 'a4'], ['apps/a6', 'a6'], ['apps/bad folder', 'app'],
    ]);
    const root = repo('node-library');
    writeIn(root, 'package.json', JSON.stringify({ name: 'bad\u0007name' }));
    expect((await readProject(root)).services[0]?.name).toBe('r'); // the root folder's name is the repo name
  });

  it('read: two packages with the same package.json name → the later one (by path) is renamed <name>-2, with a note', async () => {
    const dir = repo('node-library');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: ['apps/*'] }));
    for (const folder of ['b', 'a', 'c']) writeIn(dir, `apps/${folder}/package.json`, JSON.stringify({ name: 'web', scripts: { start: 'x' } }));
    writeIn(dir, 'apps/d/package.json', JSON.stringify({ name: 'web-2', scripts: { start: 'x' } })); // already taken: the suffix keeps counting
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(p.services.map((s) => [s.path, s.name])).toEqual([['apps/a', 'web'], ['apps/b', 'web-3'], ['apps/c', 'web-4'], ['apps/d', 'web-2']]);
    expect(new Set(p.services.map((s) => s.name)).size).toBe(p.services.length);
    expect(notes).toContain('Two services were both named web; the second is called web-3 here.');
    expect(notes).toContain('Two services were both named web; the second is called web-4 here.');
  });

  it('read: two invalid-name folders that both fall back to "app" → app and app-2; a renamed long name still matches the pattern', async () => {
    const dir = repo('node-library');
    writeIn(dir, 'package.json', JSON.stringify({ name: 'root', workspaces: ['apps/*'] }));
    writeIn(dir, 'apps/bad one/package.json', JSON.stringify({ name: 'bad\u202e', scripts: { dev: 'x' } }));
    writeIn(dir, 'apps/bad two/package.json', JSON.stringify({ scripts: { dev: 'x' } }));
    const long = 'n'.repeat(214);
    writeIn(dir, 'apps/l1/package.json', JSON.stringify({ name: long, scripts: { dev: 'x' } }));
    writeIn(dir, 'apps/l2/package.json', JSON.stringify({ name: long, scripts: { dev: 'x' } }));
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(p.services.map((s) => [s.path, s.name])).toEqual([
      ['apps/bad one', 'app'], ['apps/bad two', 'app-2'], ['apps/l1', long], ['apps/l2', `${'n'.repeat(212)}-2`],
    ]);
    for (const s of p.services) expect(s.name).toMatch(/^[A-Za-z0-9._@/-]{1,214}$/);
    expect(notes).toContain('Two services were both named app; the second is called app-2 here.');
  });

  it('read: code port default found in .tsx, .mts and .cts files too', async () => {
    for (const ext of ['tsx', 'mts', 'cts']) {
      const dir = repo('node-library');
      writeIn(dir, `server.${ext}`, 'app.listen(process.env.PORT || 4321);\n');
      expect((await readProject(dir)).services[0]?.port, ext).toBe(4321);
    }
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

// Task 5, item 4: packages vs apps (express and flask shapes, minimal hand-written files).
describe('read (Task 5: packages vs apps)', () => {
  const PYPI_PUBLISH = "on:\n  push:\n    tags: ['*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: pypa/gh-action-pypi-publish@v1.14.2\n";
  const NPM_PUBLISH = 'on:\n  release:\n    types: [published]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish --provenance\n';

  it('packages: a repo whose own package is a framework does not count as using it (express, flask)', async () => {
    const node = repo('node-library');
    writeIn(node, 'package.json', JSON.stringify({ name: 'express', version: '5.0.0', dependencies: { express: 'file:.', debug: '4.0.0' } }));
    expect((await readProject(node)).services[0]?.frameworks).toEqual([]);
    const py = repo('python-uv');
    writeIn(py, 'pyproject.toml', '[project]\nname = "Flask"\ndependencies = ["flask", "werkzeug>=3"]\n');
    expect((await readProject(py)).services[0]?.frameworks).toEqual([]);
  });

  it('packages: a published package whose only server sign is a port in its code is not runnable (flask shape, npm too)', async () => {
    const py = repo('python-uv');
    writeIn(py, 'pyproject.toml', '[project]\nname = "Flask"\ndependencies = ["werkzeug>=3"]\n[project.scripts]\nflask = "flask.cli:main"\n');
    writeIn(py, 'app.py', 'def run(port=5000):\n    pass\n');
    writeIn(py, '.github/workflows/publish.yaml', PYPI_PUBLISH);
    const flask = (await readProject(py)).services[0];
    expect(flask?.port).toBe(5000);
    expect(isRunnable(flask!)).toBe(false);
    const node = repo('node-library');
    writeIn(node, 'index.js', 'module.exports = (port = 3000) => port;\nconst PORT = process.env.PORT || 3000;\n');
    writeIn(node, '.github/workflows/npm-publish.yml', NPM_PUBLISH);
    expect(isRunnable((await readProject(node)).services[0]!)).toBe(false);
  });

  it('packages (adversarial): a package named like a framework that also has a real server entry stays runnable', async () => {
    const withStart = repo('node-library');
    writeIn(withStart, 'package.json', JSON.stringify({ name: 'express', scripts: { start: 'node server.js' }, dependencies: { express: 'file:.' } }));
    writeIn(withStart, '.github/workflows/npm-publish.yml', NPM_PUBLISH);
    expect(isRunnable((await readProject(withStart)).services[0]!)).toBe(true);
    const withFramework = repo('node-library');
    writeIn(withFramework, 'package.json', JSON.stringify({ name: 'express', dependencies: { express: 'file:.', fastify: '5.0.0' } }));
    writeIn(withFramework, '.github/workflows/npm-publish.yml', NPM_PUBLISH);
    const s = (await readProject(withFramework)).services[0]!;
    expect(s.frameworks).toEqual(['fastify']);
    expect(isRunnable(s)).toBe(true);
    const withDocker = repo('python-uv');
    writeIn(withDocker, 'pyproject.toml', '[project]\nname = "Flask"\ndependencies = ["flask"]\n');
    writeIn(withDocker, 'Dockerfile', 'FROM python:3.12\n');
    writeIn(withDocker, '.github/workflows/publish.yaml', PYPI_PUBLISH);
    expect(isRunnable((await readProject(withDocker)).services[0]!)).toBe(true);
    // a port with no publishing workflow: still an app, as before
    const app = repo('node-library');
    writeIn(app, 'index.js', 'const PORT = process.env.PORT || 3000;\n');
    expect(isRunnable((await readProject(app)).services[0]!)).toBe(true);
    // publishing words only in an echo or a comment are not publishing
    const echo = repo('node-library');
    writeIn(echo, 'index.js', 'const PORT = process.env.PORT || 3000;\n');
    writeIn(echo, '.github/workflows/ci.yml', 'on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo "npm publish later"  # npm publish\n');
    expect(isRunnable((await readProject(echo)).services[0]!)).toBe(true);
  });
});

// Task 5 fix round 1 (I5): a real server must not look like a published package.
describe('read (Task 5 fix round 1: packages vs apps)', () => {
  it('I5: npm publish --dry-run, a publish only on pull requests, or NPM_CONFIG_DRY_RUN is not publishing', async () => {
    const wfOf = (on: string, steps: string) => `on:\n${on}jobs:\n  a:\n    runs-on: x\n    steps:\n${steps}`;
    for (const workflow of [
      wfOf('  pull_request:\n', '      - run: npm publish --dry-run\n'),
      wfOf('  release:\n    types: [published]\n', '      - run: npm publish --dry-run --provenance\n'),
      wfOf('  pull_request:\n', '      - run: npm publish --provenance\n'),
      wfOf('  - pull_request\n  - pull_request_target\n', '      - run: npm publish\n'),
      wfOf('  release:\n    types: [published]\n', '      - run: npm publish\n        env:\n          NPM_CONFIG_DRY_RUN: "true"\n'),
      wfOf('  release:\n    types: [published]\n', '      - run: npm_config_dry_run=true npm publish\n'),
    ]) {
      const dir = repo('node-library');
      writeIn(dir, 'index.js', 'require("http").createServer(h).listen(process.env.PORT || 8080);\n');
      writeIn(dir, 'package.json', JSON.stringify({ name: 'my-server', bin: { 'my-server': 'index.js' } }));
      writeIn(dir, '.github/workflows/ci.yml', workflow);
      const s = (await readProject(dir)).services[0]!;
      expect(s.publishedPackage, workflow).toBeUndefined();
      expect(isRunnable(s), workflow).toBe(true);
    }
  });

  it('I5: aiohttp, tornado, starlette, sanic, quart, litestar and falcon are server frameworks (a published server stays runnable)', async () => {
    for (const fw of ['aiohttp', 'tornado', 'starlette', 'sanic', 'quart', 'litestar', 'falcon']) {
      const dir = repo('python-uv');
      writeIn(dir, 'pyproject.toml', `[project]\nname = "mysrv"\ndependencies = ["${fw}>=1"]\n`);
      writeIn(dir, '.github/workflows/publish.yaml', "on:\n  push:\n    tags: ['*']\njobs:\n  p:\n    runs-on: x\n    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n");
      const s = (await readProject(dir)).services[0]!;
      expect(s.frameworks, fw).toEqual([fw]);
      expect(isRunnable(s), fw).toBe(true);
    }
    // each framework's own repo is still not an app of itself
    const own = repo('python-uv');
    writeIn(own, 'pyproject.toml', '[project]\nname = "aiohttp"\ndependencies = ["aiohttp"]\n');
    expect((await readProject(own)).services[0]?.frameworks).toEqual([]);
  });
});

// P55 batch B (hand checks 2026-10-29): packages that run by a script's name but are not services of their own.
describe('read (P55 batch B: not a standalone service)', () => {
  const files = (f: Record<string, string>) => {
    const dir = repo('node-library');
    for (const [rel, text] of Object.entries(f)) writeIn(dir, rel, text);
    return dir;
  };
  const one = async (f: Record<string, string>, path = '.') => {
    const p = await readProject(files(f));
    return p.services.find((s) => s.path === path)!;
  };
  const pkgOf = (scripts: Record<string, string>, extra: Record<string, unknown> = {}) => JSON.stringify({ name: 'x', version: '1.0.0', type: 'module', scripts, ...extra });

  it('a start script that runs a one-shot script (prints and exits, imports only repo files and quiet built-ins) is not runnable', async () => {
    const s = await one({
      'package.json': pkgOf({ start: 'node src/index.js' }), 'src/index.js': 'import config from "../config.js";\nimport { buildReport } from "./report.js";\nconsole.log(buildReport(config.name));\n',
      'config.js': 'export default { name: "x" };\n', 'src/report.js': 'import { readFileSync } from "node:fs";\nexport const buildReport = (n) => `report ${n}`;\n',
    });
    expect(s.notStandalone).toBe('one-shot');
    expect(isRunnable(s)).toBe(false);
  });

  it('a start script stays runnable when the script can\'t be shown to exit: a listener, a timer, a package, a computed import, a missing file, an unknown command', async () => {
    const base = { 'package.json': pkgOf({ start: 'node src/index.js' }) };
    const cases: Record<string, Record<string, string>> = {
      listen: { ...base, 'src/index.js': 'import http from "node:http";\nhttp.createServer(() => {}).listen(3000);\n' },
      'listen in an import': { ...base, 'src/index.js': 'import "./server.js";\n', 'src/server.js': 'const s = createServer();\ns.listen(8080);\n' },
      timer: { ...base, 'src/index.js': 'setInterval(() => console.log("tick"), 1000);\n' },
      'event handler': { ...base, 'src/index.js': 'process.on("SIGTERM", () => {});\n' },
      package: { ...base, 'src/index.js': 'import ws from "ws";\nconsole.log(ws);\n' },
      'bare require': { ...base, 'src/index.js': 'const m = require("some-queue-client");\n' },
      'child process': { ...base, 'src/index.js': 'import { spawn } from "node:child_process";\n' },
      computed: { ...base, 'src/index.js': 'const m = await import(name);\n' },
      'missing import': { ...base, 'src/index.js': 'import "./gone.js";\n' },
      'file missing': base,
      'long line hides an import': { ...base, 'src/index.js': `console.log(1);${' '.repeat(5000)}import "./x.js";\n` },
      'not node': { 'package.json': pkgOf({ start: 'nodemon src/index.js' }), 'src/index.js': 'console.log(1);\n' },
      'two commands': { 'package.json': pkgOf({ start: 'node src/index.js && node src/other.js' }), 'src/index.js': 'console.log(1);\n' },
      'dev starts a server': { 'package.json': pkgOf({ start: 'node src/index.js', dev: 'vite' }), 'src/index.js': 'console.log(1);\n' },
      'dot dot path': { 'package.json': pkgOf({ start: 'node ../x.js' }) },
    };
    for (const [name, f] of Object.entries(cases)) {
      const s = await one(f);
      expect(s.notStandalone, name).toBeUndefined();
      expect(isRunnable(s), name).toBe(true);
    }
  });

  it('a one-shot start script with a Dockerfile, a framework or a port is still a service', async () => {
    const f = { 'package.json': pkgOf({ start: 'node src/index.js' }), 'src/index.js': 'console.log(1);\n' };
    expect((await one({ ...f, Dockerfile: 'FROM node:22\n' })).notStandalone).toBeUndefined();
    expect((await one({ ...f, 'package.json': pkgOf({ start: 'node src/index.js' }, { dependencies: { express: '5.0.0' } }) })).notStandalone).toBeUndefined();
    expect((await one({ ...f, 'src/index.js': 'const port = 8080;\nconsole.log(port);\n' })).notStandalone).toBeUndefined();
  });

  it('a frontend another service\'s Dockerfile copies into its image is part of that service', async () => {
    const f = {
      'package.json': JSON.stringify({ name: 'root', private: true, workspaces: ['frontend'] }),
      'frontend/package.json': pkgOf({ dev: 'vite', build: 'vite build' }), 'frontend/src/main.ts': 'console.log(1);\n',
      'backend/pyproject.toml': '[project]\nname = "backend"\ndependencies = ["fastapi"]\n', 'backend/app/main.py': 'x = 1\n',
      'backend/Dockerfile': 'FROM oven/bun:1 AS build\nCOPY frontend/package.json /app/frontend/\nCOPY ./frontend /app/frontend\nRUN bun run build\nFROM python:3.14\nCOPY --from=build /app/dist /app/dist\nCOPY ./backend/app /app/backend/app\n',
    };
    const p = await readProject(files(f));
    const fe = p.services.find((s) => s.path === 'frontend')!;
    expect(fe.notStandalone).toBe('built-in-image');
    expect(isRunnable(fe)).toBe(false);
    const be = p.services.find((s) => s.path === 'backend')!;
    expect(be.notStandalone).toBeUndefined();
    expect(isRunnable(be)).toBe(true);
    // a --from copy, a copy of an unrelated folder, or a folder that has its own Dockerfile does not count
    const other = await readProject(files({ ...f, 'backend/Dockerfile': 'FROM python:3.14\nCOPY --from=build /app/frontend /app/frontend\nCOPY ./docs /app/docs\n', 'docs/a.md': 'x\n' }));
    expect(other.services.find((s) => s.path === 'frontend')!.notStandalone).toBeUndefined();
    const own = await readProject(files({ ...f, 'frontend/Dockerfile': 'FROM node:22\nCOPY . .\n' }));
    expect(own.services.find((s) => s.path === 'frontend')!.notStandalone).toBeUndefined();
    // a Dockerfile in the folder's own context holding its own `frontend` folder is not the repo's frontend
    const nested = await readProject(files({ ...f, 'backend/frontend/x.txt': 'x\n' }));
    expect(nested.services.find((s) => s.path === 'frontend')!.notStandalone).toBeUndefined();
  });

  it('an email-template package (react-email, mjml, maizzle) is a design-time tool, not a service', async () => {
    for (const dep of ['react-email', '@react-email/components', 'mjml', '@maizzle/framework']) {
      const s = await one({ 'package.json': pkgOf({ dev: 'email dev --port 3333', export: 'email export' }, { dependencies: { [dep]: '1.0.0' } }) });
      expect(s.notStandalone, dep).toBe('email-templates');
      expect(isRunnable(s), dep).toBe(false);
    }
    // an email package that also is a server (a framework or a Dockerfile) stays a service
    expect((await one({ 'package.json': pkgOf({ start: 'node a.js' }, { dependencies: { 'react-email': '1.0.0', express: '5.0.0' } }) })).notStandalone).toBeUndefined();
    expect((await one({ 'package.json': pkgOf({ dev: 'email dev' }, { dependencies: { mjml: '4.0.0' } }), Dockerfile: 'FROM node:22\n' })).notStandalone).toBeUndefined();
  });

  // P57 (I1): hiding a package needs strong proof; by default it is runnable. The svc probe's four reproductions.
  describe('P57 I1: a package is hidden only with strong proof', () => {
    const ws = (f: Record<string, string>) => files({ 'package.json': JSON.stringify({ name: 'root', private: true, workspaces: ['apps/*'] }), ...f });
    const svcAt = async (f: Record<string, string>, path: string) => (await readProject(ws(f))).services.find((s) => s.path === path)!;
    const HONO = 'import { Hono } from "hono";\nimport { serve } from "@hono/node-server";\nconst app = new Hono();\nserve({ fetch: app.fetch, port: 8787 });\n';

    it('a Hono or h3 server that sends mail with react-email or mjml is a server, not an email-template package', async () => {
      const api = await svcAt({
        'apps/api/package.json': pkgOf({ dev: 'tsx watch src/index.ts', start: 'node dist/index.js' }, { dependencies: { hono: '4.0.0', '@hono/node-server': '1.0.0', '@react-email/components': '0.1.0' } }),
        'apps/api/src/index.ts': HONO,
      }, 'apps/api');
      expect(api.notStandalone).toBeUndefined();
      expect(isRunnable(api)).toBe(true);
      const mailer = await svcAt({
        'apps/mailer/package.json': pkgOf({ start: 'node src/server.js' }, { dependencies: { h3: '1.0.0', mjml: '4.0.0' } }),
        'apps/mailer/src/server.js': 'import http from "node:http";\nimport { createApp, toNodeListener } from "h3";\nhttp.createServer(toNodeListener(createApp())).listen(3000);\n',
      }, 'apps/mailer');
      expect(mailer.notStandalone).toBeUndefined();
      // an email package whose run script isn't the email tool's own CLI, even without a port found, stays runnable
      const plain = await svcAt({ 'apps/m/package.json': pkgOf({ start: 'node src/x.js' }, { dependencies: { mjml: '4.0.0' } }), 'apps/m/src/x.js': 'console.log(1);\n' }, 'apps/m');
      expect(plain.notStandalone).not.toBe('email-templates');
    });

    it('a Dockerfile that copies one file out of a folder, or one that belongs to no service (docker/api.Dockerfile), doesn\'t hide it', async () => {
      const api = { 'apps/api/package.json': pkgOf({ dev: 'tsx watch src/index.ts', start: 'node dist/index.js' }), 'apps/api/src/index.ts': 'console.log(1);\n', 'apps/api/openapi.json': '{}\n' };
      const web = { 'apps/web/package.json': pkgOf({ dev: 'vite', start: 'vite preview' }, { dependencies: { vite: '7.0.0' } }), 'apps/web/src/main.ts': 'x\n' };
      const oneFile = await svcAt({ ...api, ...web, 'apps/web/Dockerfile': 'FROM node:22\nCOPY apps/api/openapi.json /app/openapi.json\nCOPY apps/web /app\n' }, 'apps/api');
      expect(oneFile.notStandalone).toBeUndefined();
      const dockerDir = await svcAt({ ...api, ...web, 'docker/api.Dockerfile': 'FROM node:22\nCOPY apps/api /app\n' }, 'apps/api');
      expect(dockerDir.notStandalone).toBeUndefined();
    });

    it('a poller (while (!stop) with timers/promises), a recursive loop or any loop is not provably one-shot', async () => {
      const worker = (code: string) => svcAt({ 'apps/worker/package.json': pkgOf({ start: 'node src/worker.js' }), 'apps/worker/src/worker.js': code }, 'apps/worker');
      for (const code of [
        'import { scheduler } from "node:timers/promises";\nlet stop = false;\nwhile (!stop) {\n  await fetch("https://x.test/jobs");\n  await scheduler.wait(5000);\n}\n',
        'while (1) { await fetch("https://x.test"); }\n',
        'async function poll() {\n  await fetch("https://x.test");\n  return poll();\n}\nawait poll();\n',
        'async function poll() { await fetch("https://x.test"); setImmediate; return poll(); }\n',
        'function tick() { console.log(1); tick(); }\n',
        'do { await fetch("https://x.test"); } while (Date.now() > 0);\n',
        'for (const x of jobs()) console.log(x);\n',
      ]) expect((await worker(code)).notStandalone, code).toBeUndefined();
      // a plain script still is one-shot
      expect((await worker('console.log("hello");\n')).notStandalone).toBe('one-shot');
    });
  });
});
