// Plan E E0c (ruling S4): the snapshot read. HEAD's files come from `git ls-tree` + `git cat-file --batch` in the hardened
// environment, never `git archive` (whose export-ignore / export-subst would hide or change files); symlinks and submodules
// are dropped and listed; the dirty check runs `git --no-optional-locks status` with fsmonitor off.
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { GitTransportError, HARDENED_CONFIG, isDirty, readSnapshot } from '../src/proof/git.js';
import { makeGitRecorder, REAL_GIT } from './helpers/git-recorder.js';

const root = mkdtempSync(join(tmpdir(), 'pg-e0c-snap-'));
const recorder = makeGitRecorder(root);
const savedEnv = { ...process.env };
let n = 0;

const ENV = { ...savedEnv, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };
const git = (cwd: string, ...args: string[]) => execFileSync(REAL_GIT, args, { cwd, encoding: 'utf8', env: ENV }).trim();
const fresh = () => {
  const d = join(root, `repo-${++n}`);
  mkdirSync(d, { recursive: true });
  git(d, 'init', '-q');
  return d;
};
const put = (dir: string, rel: string, content: string | Buffer) => {
  mkdirSync(join(dir, rel, '..'), { recursive: true });
  writeFileSync(join(dir, rel), content);
};
const commitAll = (dir: string) => {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', 'c');
};
const filesOf = (s: Awaited<ReturnType<typeof readSnapshot>>) => Object.fromEntries(s.files.map((f) => [f.path, Buffer.from(f.content).toString('utf8')]));

beforeEach(() => {
  recorder.clear();
  process.env.PATH = `${recorder.bin}:${savedEnv.PATH ?? ''}`;
});
afterEach(() => {
  for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
  Object.assign(process.env, savedEnv);
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('snapshot read (E0c, S4)', () => {
  it('snapshot read: ls-tree + cat-file; export-ignore and export-subst ignored', async () => {
    const d = fresh();
    put(d, '.gitattributes', 'ignored.txt export-ignore\nver.txt export-subst\nhidden/** export-ignore\n');
    put(d, 'ignored.txt', 'kept\n');
    put(d, 'ver.txt', 'commit $Format:%H$\n');
    put(d, 'hidden/deep/a.txt', 'deep\n');
    put(d, 'bin.dat', Buffer.from([0, 1, 2, 255, 10, 13, 0]));
    put(d, 'run.sh', '#!/bin/sh\n');
    chmodSync(join(d, 'run.sh'), 0o755);
    put(d, '.github/workflows/ci.yml', 'on: push\n');
    put(d, 'empty.txt', '');
    commitAll(d);
    const head = git(d, 'rev-parse', 'HEAD');
    // HEAD only: an uncommitted change and an untracked file are not part of the snapshot.
    put(d, 'ignored.txt', 'changed\n');
    put(d, 'untracked.txt', 'x\n');

    const s = await readSnapshot(d);
    expect(s.commit).toBe(head);
    expect(filesOf(s)).toEqual({
      '.gitattributes': 'ignored.txt export-ignore\nver.txt export-subst\nhidden/** export-ignore\n',
      '.github/workflows/ci.yml': 'on: push\n',
      'bin.dat': Buffer.from([0, 1, 2, 255, 10, 13, 0]).toString('utf8'),
      'empty.txt': '',
      'hidden/deep/a.txt': 'deep\n',
      'run.sh': '#!/bin/sh\n',
      'ignored.txt': 'kept\n',
      'ver.txt': 'commit $Format:%H$\n',
    });
    expect(Buffer.from(s.files.find((f) => f.path === 'bin.dat')!.content)).toEqual(Buffer.from([0, 1, 2, 255, 10, 13, 0]));
    expect(s.files.find((f) => f.path === 'run.sh')!.mode).toBe('100755');
    expect(s.files.find((f) => f.path === 'ignored.txt')!.mode).toBe('100644');
    expect(s.files.map((f) => f.path)).toEqual([...s.files.map((f) => f.path)].sort());
    expect(s.dropped).toEqual([]);

    const calls = recorder.calls();
    const cmds = calls.map((c) => c.argv[c.argv.indexOf(d) + 1]);
    expect(cmds).toEqual(['rev-parse', 'ls-tree', 'cat-file']);
    for (const c of calls) {
      expect(c.argv.slice(0, HARDENED_CONFIG.length)).toEqual([...HARDENED_CONFIG]);
      expect(c.argv).toContain('--no-replace-objects');
      expect(c.argv).not.toContain('archive');
      expect(c.env.GIT_CEILING_DIRECTORIES).toBe(join(d, '..'));
    }
    expect(calls[1].argv.slice(-5)).toEqual(['ls-tree', '-r', '-z', '-l', '--full-tree', head].slice(-5));
    expect(calls[2].argv.slice(-2)).toEqual(['cat-file', '--batch']);
  });

  it('snapshot read: symlinks and submodules dropped and listed', async () => {
    const sub = fresh();
    put(sub, 'x.txt', 'x\n');
    commitAll(sub);
    const subSha = git(sub, 'rev-parse', 'HEAD');
    const d = fresh();
    put(d, 'svc/app.js', 'app\n');
    symlinkSync('app.js', join(d, 'svc', 'link.js'));
    symlinkSync('/etc/passwd', join(d, 'abs-link'));
    git(d, 'add', '-A');
    git(d, 'update-index', '--add', '--cacheinfo', `160000,${subSha},vendor/lib`);
    git(d, 'commit', '-qm', 'c');
    const s = await readSnapshot(d);
    expect(filesOf(s)).toEqual({ 'svc/app.js': 'app\n' });
    expect(s.dropped).toEqual([
      { path: 'abs-link', why: 'symlink' },
      { path: 'svc/link.js', why: 'symlink' },
      { path: 'vendor/lib', why: 'submodule' },
    ]);
  });

  it('snapshot read: a name that is not UTF-8 or not a safe path is dropped and listed', async () => {
    const d = fresh();
    put(d, 'ok.txt', 'ok\n');
    commitAll(d);
    // Trees written by hand: a non-UTF-8 name, and names a checkout would refuse.
    const blob = git(d, 'hash-object', '-w', 'ok.txt');
    const entries = [
      Buffer.from(`100644 blob ${blob}\t`), Buffer.from([0x62, 0xff, 0x2e, 0x74]), Buffer.from('\0'),
      Buffer.from(`100644 blob ${blob}\tok.txt\0`),
      Buffer.from(`100644 blob ${blob}\tb\\c.txt\0`),
      Buffer.from(`100644 blob ${blob}\t.GIT\0`),
    ];
    const sub = execFileSync(REAL_GIT, ['mktree', '-z', '--missing'], { cwd: d, env: ENV, input: Buffer.from(`100644 blob ${blob}\tconfig\0`) }).toString().trim();
    entries.push(Buffer.from(`040000 tree ${sub}\t.git\0`));
    const tree = execFileSync(REAL_GIT, ['mktree', '-z'], { cwd: d, env: ENV, input: Buffer.concat(entries) }).toString().trim();
    const commit = execFileSync(REAL_GIT, ['commit-tree', tree, '-m', 'odd'], { cwd: d, env: ENV }).toString().trim();
    git(d, 'update-ref', 'HEAD', commit);
    const s = await readSnapshot(d);
    expect(filesOf(s)).toEqual({ 'ok.txt': 'ok\n' });
    expect(s.dropped.map((x) => x.why).sort()).toEqual(['non-utf8-name', 'unsafe-path', 'unsafe-path', 'unsafe-path']);
    expect(s.dropped.find((x) => x.why === 'non-utf8-name')!.path).toBe('b�.t');
  });

  it('snapshot read: no commit, a folder that is not a repo root, or over the size cap → error', async () => {
    const empty = fresh();
    await expect(readSnapshot(empty)).rejects.toThrow(GitTransportError);
    const d = fresh();
    put(d, 'a/b.txt', 'b\n');
    commitAll(d);
    // A sub-folder of a repo is not a repo: git is not allowed to look above the folder it is given.
    await expect(readSnapshot(join(d, 'a'))).rejects.toThrow(GitTransportError);
    await expect(isDirty(join(d, 'a'))).rejects.toThrow(GitTransportError);
    await expect(readSnapshot('relative')).rejects.toThrow(GitTransportError);
    put(d, 'big.txt', 'x'.repeat(1000));
    commitAll(d);
    await expect(readSnapshot(d, { maxBytes: 999 })).rejects.toThrow(/more than/);
    expect((await readSnapshot(d, { maxBytes: 1002 })).files).toHaveLength(2);
  });

  it('snapshot read: dirty check with --no-optional-locks and fsmonitor off', async () => {
    const d = fresh();
    put(d, 'a.txt', 'a\n');
    commitAll(d);
    const marker = join(root, `fsmonitor-${n}`);
    put(d, '.fsm.sh', `#!/bin/sh\necho ran >> '${marker}'\n`);
    chmodSync(join(d, '.fsm.sh'), 0o755);
    git(d, 'config', 'core.fsmonitor', join(d, '.fsm.sh'));
    put(d, '.gitignore', '.fsm.sh\n.gitignore\n');
    expect(await isDirty(d)).toBe(false);
    // A touched file (same content, new mtime) would make status refresh and rewrite the index; with the optional locks off it doesn't.
    const index = join(d, '.git', 'index');
    const before = readFileSync(index);
    const mtime = statSync(index).mtimeMs;
    writeFileSync(join(d, 'a.txt'), 'a\n');
    const later = new Date(Date.now() + 5000);
    execFileSync('touch', ['-d', later.toISOString(), join(d, 'a.txt')]);
    expect(await isDirty(d)).toBe(false);
    expect(readFileSync(index)).toEqual(before);
    expect(statSync(index).mtimeMs).toBe(mtime);
    expect(existsSync(join(d, '.git', 'index.lock'))).toBe(false);
    put(d, 'a.txt', 'changed\n');
    expect(await isDirty(d)).toBe(true);
    put(d, 'a.txt', 'a\n');
    put(d, 'new.txt', 'n\n');
    expect(await isDirty(d)).toBe(true);
    expect(existsSync(marker)).toBe(false);

    const calls = recorder.calls();
    expect(calls).toHaveLength(4);
    for (const c of calls) {
      expect(c.argv.slice(0, HARDENED_CONFIG.length)).toEqual([...HARDENED_CONFIG]);
      expect(c.argv).toContain('core.fsmonitor=false');
      const i = c.argv.indexOf('status');
      expect(c.argv.indexOf('--no-optional-locks')).toBeGreaterThan(-1);
      expect(c.argv.indexOf('--no-optional-locks')).toBeLessThan(i);
      expect(c.argv.slice(i)).toEqual(['status', '--porcelain=v1', '-z', '--ignore-submodules=all', '--untracked-files=normal']);
    }
  });
});
