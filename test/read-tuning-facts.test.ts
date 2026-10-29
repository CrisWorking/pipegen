// Plan B Task 6d: the two profile facts per-repo tuning reads. Written first (strict test-first).
// - Service.lockfile: the repo-relative path of the lockfile the reader found for the service (its own folder's, else the root's).
// - RepoProfile.generatedDirs: the folders pipegen itself detects as vendored or generated (DECISIONS #108), by a fixed list of
//   names that exist as real folders (never a link), at the root or in a service folder.
import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readProject } from '../src/read/project.js';
import { cleanupRepos, makeRepo, writeIn } from './helpers/make-repo.js';

afterEach(() => cleanupRepos());
const GH = 'https://github.com/o/r.git';

describe('read: Service.lockfile (6d)', () => {
  it('a node service has its own lockfile path; python has poetry.lock, uv.lock or requirements.txt', async () => {
    expect((await readProject(makeRepo('node-npm', GH))).services[0]?.lockfile).toBe('package-lock.json');
    expect((await readProject(makeRepo('python-poetry', GH))).services[0]?.lockfile).toBe('poetry.lock');
    expect((await readProject(makeRepo('python-uv', GH))).services[0]?.lockfile).toBe('uv.lock');
    const pnpm = await readProject(makeRepo('node-pnpm-workspaces', GH));
    expect(pnpm.services.map((s) => s.lockfile)).toEqual(pnpm.services.map(() => 'pnpm-lock.yaml'));
  });

  it('a service folder\'s own lockfile wins over the root\'s, and a service folder with none has the root\'s', async () => {
    const dir = makeRepo('node-npm', GH);
    writeIn(dir, 'api/package.json', '{"name":"api","scripts":{"start":"node i.js"}}');
    writeIn(dir, 'api/yarn.lock', '# yarn\n');
    writeIn(dir, 'web/package.json', '{"name":"web","scripts":{"start":"node i.js"}}');
    writeIn(dir, 'api/Dockerfile', 'FROM node:22\n');
    writeIn(dir, 'web/Dockerfile', 'FROM node:22\n');
    const p = await readProject(dir);
    const by = Object.fromEntries(p.services.map((s) => [s.path, s.lockfile]));
    expect(by.api).toBe('api/yarn.lock');
    expect(by.web).toBe('package-lock.json');
  });
});

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
});
