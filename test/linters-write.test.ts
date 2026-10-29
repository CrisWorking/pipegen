// Plan B Task 6d Part 0 (7b re-review notes): the temp copy is written with O_EXCL | O_NOFOLLOW. node:fs/promises.mkdtemp is
// wrapped here so a hostile file or symlink is planted at the target path right after the temp folder is made (the only
// moment an attacker on the same machine could do it). Kept in its own file because the module mock is file-wide.
import { existsSync, lstatSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Linters } from '../src/engine/referee.js';
import type { CreatedFile } from '../src/types.js';
import { stub } from './helpers/linter-stub.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const plant = vi.hoisted(() => ({ fn: null as null | ((dir: string) => void) }));
vi.mock('node:fs/promises', async (orig) => {
  const real = await orig<typeof import('node:fs/promises')>();
  return { ...real, mkdtemp: async (...args: Parameters<typeof real.mkdtemp>) => { const d = await real.mkdtemp(...args); plant.fn?.(d); return d; } };
});
const { runLinters } = await import('../src/engine/linters.js');

afterEach(() => { plant.fn = null; cleanupRepos(); });

const WF = '.github/workflows/pipegen.yml';
const file = (path: string): CreatedFile => ({ path, content: 'name: from-pipegen\n', part: 'pipeline', reason: 'test', repo: 'app' });
const closures = (a: ReturnType<typeof stub>, z: ReturnType<typeof stub>): Linters => ({ actionlint: async () => a.bin, zizmor: async () => z.bin });

describe('runLinters: the temp copy is written exclusively and without following links', () => {
  it('a file already at the target path (O_EXCL) is not overwritten: issue, no linter run', async () => {
    let seen = '';
    const a = stub(); const z = stub();
    const base = makeTempDir();
    plant.fn = (dir) => { mkdirSync(join(dir, dirname(WF)), { recursive: true }); writeFileSync(join(dir, WF), 'PLANTED\n'); seen = dir; };
    const issues = await runLinters([file(WF)], closures(a, z), 'tok', { tmp: base });
    expect(seen).not.toBe('');
    expect(issues.filter((i) => /could not be copied/.test(i.message)), JSON.stringify(issues)).toHaveLength(1);
    expect(a.records()).toEqual([]);
    expect(z.records()).toEqual([]);
  });

  it('a symlink at the target path is not followed: nothing is written through it', async () => {
    const outside = join(makeTempDir(), 'victim.txt');
    writeFileSync(outside, 'ORIGINAL\n');
    plant.fn = (dir) => { mkdirSync(join(dir, dirname(WF)), { recursive: true }); symlinkSync(outside, join(dir, WF)); };
    const a = stub(); const z = stub();
    const issues = await runLinters([file(WF)], closures(a, z), 'tok', { tmp: makeTempDir() });
    expect(readFileSync(outside, 'utf8')).toBe('ORIGINAL\n');
    expect(issues.filter((i) => /could not be copied/.test(i.message)), JSON.stringify(issues)).toHaveLength(1);
    expect(a.records()).toEqual([]);
  });

  it('a dangling symlink at the target path is not followed either (nothing is created at its destination)', async () => {
    const gone = join(makeTempDir(), 'not-yet.txt');
    plant.fn = (dir) => { mkdirSync(join(dir, dirname(WF)), { recursive: true }); symlinkSync(gone, join(dir, WF)); };
    const a = stub(); const z = stub();
    const issues = await runLinters([file(WF)], closures(a, z), 'tok', { tmp: makeTempDir() });
    expect(existsSync(gone), 'the link target was created through the link').toBe(false);
    expect(lstatSync(dirname(gone)).isDirectory()).toBe(true);
    expect(issues.filter((i) => /could not be copied/.test(i.message))).toHaveLength(1);
  });
});
