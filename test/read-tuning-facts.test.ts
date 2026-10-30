// Plan B Task 6d: the profile facts per-repo tuning reads. Written first (strict test-first).
// - RepoProfile.generatedDirs: the folders pipegen itself detects as vendored or generated (DECISIONS #108), by a fixed list of
//   names that exist as real folders (never a link), at the root or in a service folder.
import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readProject } from '../src/read/project.js';
import { cleanupRepos, makeRepo, writeIn } from './helpers/make-repo.js';

afterEach(() => cleanupRepos());
const GH = 'https://github.com/o/r.git';

describe('read: RepoProfile.generatedDirs (6d, DECISIONS #108)', () => {
  it('only folders that exist as real folders, at the root or in a service folder', async () => {
    const dir = makeRepo('node-npm', GH);
    mkdirSync(join(dir, 'dist'));
    writeIn(dir, 'dist/app.js', 'x');
    mkdirSync(join(dir, 'vendor'));
    writeIn(dir, 'vendor/lib.js', 'x');
    mkdirSync(join(dir, 'src/generated'), { recursive: true });
    writeIn(dir, 'src/generated/api.ts', 'x');
    const p = await readProject(dir);
    expect(p.generatedDirs).toEqual(['dist', 'src/generated', 'vendor']);
  });

  it('a name on the list that is a file or a symlink is not a folder; a source folder name is never on the list', async () => {
    const dir = makeRepo('node-npm', GH);
    writeIn(dir, 'dist', 'a file called dist');
    mkdirSync(join(dir, 'real'));
    symlinkSync(join(dir, 'real'), join(dir, 'vendor'));
    mkdirSync(join(dir, 'src'));
    mkdirSync(join(dir, 'lib'));
    mkdirSync(join(dir, 'build'));   // ambiguous (build scripts live there too): not detected
    mkdirSync(join(dir, 'tests'));
    const p = await readProject(dir);
    expect(p.generatedDirs).toBeUndefined();
  });

  it('a service folder\'s own generated folder is reported repo-relative', async () => {
    const dir = makeRepo('node-npm', GH);
    writeIn(dir, 'api/package.json', '{"name":"api","scripts":{"start":"node i.js"}}');
    writeIn(dir, 'api/Dockerfile', 'FROM node:22\n');
    writeIn(dir, 'web/package.json', '{"name":"web","scripts":{"start":"node i.js"}}');
    writeIn(dir, 'web/Dockerfile', 'FROM node:22\n');
    mkdirSync(join(dir, 'api/dist'));
    mkdirSync(join(dir, 'web/.next'));
    const p = await readProject(dir);
    expect(p.generatedDirs).toEqual(['api/dist', 'web/.next']);
  });

  it('a folder name with characters outside the plain set is dropped', async () => {
    const dir = makeRepo('node-npm', GH);
    mkdirSync(join(dir, 'a b'));   // not on the list anyway; the list is fixed names only
    expect((await readProject(dir)).generatedDirs).toBeUndefined();
  });

  it('a generated folder that is a service folder, or holds one, is dropped (never a whole service), with a note', async () => {
    const dir = makeRepo('node-npm', GH);
    for (const d of ['packages/generated', 'gen/generated/app']) {
      writeIn(dir, `${d}/package.json`, '{"name":"s-' + d.replace(/\W/g, '') + '","scripts":{"start":"node i.js"}}');
      writeIn(dir, `${d}/Dockerfile`, 'FROM node:22\n');
    }
    mkdirSync(join(dir, 'dist'));   // a real generated folder at the root stays
    const notes: string[] = [];
    const p = await readProject(dir, { notes });
    expect(p.services.map((s) => s.path).sort()).toEqual(['gen/generated/app', 'packages/generated']);
    expect(p.generatedDirs).toEqual(['dist']);
    expect(notes.join('\n')).toMatch(/packages\/generated.*service/s);
    expect(notes.join('\n')).toMatch(/gen\/generated.*service/s);
  });
});

describe('read: RepoProfile.otherHookManagers (6d fix round 1)', () => {
  const managers = async (files: Record<string, string>, config = ''): Promise<string[] | undefined> => {
    const dir = makeRepo('node-npm', GH);
    for (const [f, c] of Object.entries(files)) writeIn(dir, f, c);
    if (config !== '') writeIn(dir, '.git/config', `[remote "origin"]\n\turl = ${GH}\n${config}`);
    return (await readProject(dir)).otherHookManagers;
  };
  it('none by default', async () => { expect(await managers({})).toBeUndefined(); });
  it('simple-git-hooks: a config file or a package.json key', async () => {
    expect(await managers({ '.simple-git-hooks.json': '{}' })).toEqual(['simple-git-hooks']);
    expect(await managers({ '.simple-git-hooks.cjs': 'module.exports={}' })).toEqual(['simple-git-hooks']);
    expect(await managers({ 'simple-git-hooks.js': 'module.exports={}' })).toEqual(['simple-git-hooks']);
    expect(await managers({ 'package.json': '{"name":"x","simple-git-hooks":{"pre-commit":"npm test"}}' })).toEqual(['simple-git-hooks']);
  });
  it('a .githooks folder, or core.hooksPath in .git/config', async () => {
    expect(await managers({ '.githooks/pre-commit': '#!/bin/sh\n' })).toEqual(['githooks']);
    expect(await managers({}, '[core]\n\thooksPath = .githooks\n')).toEqual(['githooks']);
  });
  it('husky v4 (a husky key or a .huskyrc / husky.config file), yorkie (gitHooks), the npm pre-commit package (a key or a dependency), overcommit', async () => {
    expect(await managers({ 'package.json': '{"name":"x","husky":{"hooks":{"pre-commit":"npm test"}}}' })).toEqual(['husky-v4']);
    expect(await managers({ '.huskyrc': '{}' })).toEqual(['husky-v4']);
    expect(await managers({ '.huskyrc.json': '{}' })).toEqual(['husky-v4']);
    expect(await managers({ 'husky.config.js': 'module.exports={}' })).toEqual(['husky-v4']);
    expect(await managers({ 'package.json': '{"name":"x","gitHooks":{"pre-commit":"lint-staged"}}' })).toEqual(['yorkie']);
    expect(await managers({ 'package.json': '{"name":"x","pre-commit":["lint"]}' })).toEqual(['pre-commit-npm']);
    expect(await managers({ 'package.json': '{"name":"x","devDependencies":{"pre-commit":"^1.2.2"}}' })).toEqual(['pre-commit-npm']);
    expect(await managers({ 'package.json': '{"name":"x","dependencies":{"pre-commit":"^1.2.2"}}' })).toEqual(['pre-commit-npm']);
    expect(await managers({ '.overcommit.yml': 'PreCommit: {}\n' })).toEqual(['overcommit']);
    // a package that merely mentions the words is not a manager
    expect(await managers({ 'package.json': '{"name":"x","devDependencies":{"husky":"^9.0.0","precommit-hook-x":"1"}}' })).toBeUndefined();
  });

  it('a symlink at any hook-manager config name counts as a hook manager (never followed; even a dangling one)', async () => {
    for (const name of ['lefthook.yml', '.lefthook.toml', '.config/lefthook.json', 'lefthook-local.yml', '.pre-commit-config.yaml', '.husky', '.simple-git-hooks.json', '.overcommit.yml', '.huskyrc']) {
      const dir = makeRepo('node-npm', GH);
      const outside = join(makeRepo('node-npm', GH), 'target');
      mkdirSync(join(dir, name, '..'), { recursive: true });
      symlinkSync(outside, join(dir, name));
      expect((await readProject(dir)).otherHookManagers, name).toContain('linked-config');
    }
  });
});
