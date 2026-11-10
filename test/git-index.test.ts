// Plan J sub-task J1 (DECISIONS #126, ruling S11): the paths in the git index, read in-process (pipegen never runs git).
// Real index files are written by `git` at test setup only (a test-only child process).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, renameSync, symlinkSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GIT_INDEX_LIMITS, parseGitIndex, readGitIndexPaths } from '../src/read/git-index.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

/** git with no user or system config (no index.version, feature.manyFiles or skipHash from the machine). */
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', HOME: '/nonexistent' };
const git = (dir: string, ...args: string[]) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', env: GIT_ENV }).toString();

const FILES = ['README.md', 'src/index.ts', 'src/lib/a.ts', 'src/lib/b.ts', 'src/lib/deeper/c.ts', 'docs/guide.md', 'a b/with space.txt'];

/** A repo whose index git wrote (git init, then git add of FILES). */
function gitRepo(init: string[] = []): string {
  const dir = makeTempDir();
  git(dir, 'init', '-q', ...init);
  for (const f of FILES) writeIn(dir, f, `${f}\n`);
  git(dir, 'add', '--', ...FILES);
  return dir;
}
const indexOf = (dir: string) => readFileSync(join(dir, '.git/index'));
const versionOf = (buf: Buffer) => buf.readUInt32BE(4);
/** The index with its SHA-1 trailer recomputed, so only the change under test is wrong. */
const resign = (body: Buffer) => Buffer.concat([body, createHash('sha1').update(body).digest()]);

/** A hand-built index (version 2 or 4) of plain entries; v4 paths are prefix-compressed against the previous one. */
function handIndex(version: 2 | 4, paths: string[], opts: { strip?: (i: number, prev: string) => number } = {}): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('DIRC', 0, 'latin1');
  head.writeUInt32BE(version, 4);
  head.writeUInt32BE(paths.length, 8);
  parts.push(head);
  let prev = '';
  paths.forEach((p, i) => {
    const fixed = Buffer.alloc(62);
    fixed.writeUInt32BE(0o100644, 24); // mode
    fixed.fill(0xab, 40, 60); // object id
    const name = Buffer.from(p);
    fixed.writeUInt16BE(Math.min(name.length, 0xfff), 60);
    if (version === 2) {
      const len = 62 + name.length;
      const padded = Math.ceil((len + 1) / 8) * 8;
      parts.push(fixed, name, Buffer.alloc(padded - len));
    } else {
      let common = 0;
      while (common < prev.length && common < p.length && prev[common] === p[common]) common++;
      const strip = opts.strip ? opts.strip(i, prev) : prev.length - common;
      parts.push(fixed, varint(strip), Buffer.from(p.slice(prev.length - strip)), Buffer.alloc(1));
    }
    prev = p;
  });
  return resign(Buffer.concat(parts));
}
/** git's offset varint (the one index v4 uses for the strip count). */
function varint(n: number): Buffer {
  const bytes = [n & 0x7f];
  while ((n >>= 7) > 0) bytes.unshift(0x80 | (--n & 0x7f));
  return Buffer.from(bytes);
}

describe('readGitIndexPaths', () => {
  it('git-index: v2, v3 and v4 written by git at setup; truncated → null; 600,000-entry header → null', async () => {
    const v2 = gitRepo();
    git(v2, 'update-index', '--index-version', '2');
    expect(versionOf(indexOf(v2))).toBe(2);
    expect([...((await readGitIndexPaths(v2)) ?? [])].sort()).toEqual([...FILES].sort());

    // git writes version 3 only when an entry has extended flags (skip-worktree here)
    const v3 = gitRepo();
    git(v3, 'update-index', '--index-version', '3');
    git(v3, 'update-index', '--skip-worktree', 'src/lib/a.ts');
    expect(versionOf(indexOf(v3))).toBe(3);
    expect([...((await readGitIndexPaths(v3)) ?? [])].sort()).toEqual([...FILES].sort());

    const v4 = gitRepo();
    git(v4, 'update-index', '--index-version', '4');
    expect(versionOf(indexOf(v4))).toBe(4);
    expect([...((await readGitIndexPaths(v4)) ?? [])].sort()).toEqual([...FILES].sort());

    for (const cut of [8, 12, 40, indexOf(v2).length - 21, indexOf(v2).length - 1]) {
      const dir = gitRepo();
      writeFileSync(join(dir, '.git/index'), indexOf(dir).subarray(0, cut));
      expect(await readGitIndexPaths(dir), `cut at ${cut}`).toBeNull();
    }

    const many = gitRepo();
    const body = Buffer.from(indexOf(many).subarray(0, -20));
    body.writeUInt32BE(600_000, 8);
    writeFileSync(join(many, '.git/index'), resign(body));
    expect(await readGitIndexPaths(many)).toBeNull();
    expect(GIT_INDEX_LIMITS).toEqual({ maxBytes: 64 * 1024 * 1024, maxEntries: 500_000, maxPathBytes: 4096 });
  });

  it('git-index: link (split index) or sdir (sparse) extension → null', async () => {
    const split = gitRepo();
    git(split, 'update-index', '--split-index');
    expect(indexOf(split).includes(Buffer.from('link'))).toBe(true);
    expect(await readGitIndexPaths(split)).toBeNull();

    const sparse = gitRepo();
    git(sparse, '-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '--no-verify', '-m', 'init');
    git(sparse, 'sparse-checkout', 'init', '--cone', '--sparse-index');
    git(sparse, 'sparse-checkout', 'set', 'docs');
    expect(indexOf(sparse).includes(Buffer.from('sdir'))).toBe(true);
    expect(await readGitIndexPaths(sparse)).toBeNull();
  });

  it('git-index: sha256 object format or zero checksum → null', async () => {
    const sha256 = gitRepo(['--object-format=sha256']);
    expect(readFileSync(join(sha256, '.git/config'), 'utf8')).toMatch(/objectformat = sha256/);
    expect(await readGitIndexPaths(sha256)).toBeNull();

    const skip = makeTempDir();
    git(skip, 'init', '-q');
    git(skip, 'config', 'index.skipHash', 'true');
    writeIn(skip, 'a.txt', 'a\n');
    git(skip, 'add', 'a.txt');
    expect(indexOf(skip).subarray(-20).equals(Buffer.alloc(20))).toBe(true);
    expect(await readGitIndexPaths(skip)).toBeNull();

    // a wrong checksum (one byte of a path changed after git wrote it)
    const wrong = gitRepo();
    const buf = Buffer.from(indexOf(wrong));
    const at = buf.indexOf(Buffer.from('README.md'));
    buf[at] = 'X'.charCodeAt(0);
    writeFileSync(join(wrong, '.git/index'), buf);
    expect(await readGitIndexPaths(wrong)).toBeNull();
  });

  it('git-index: .git/index a symbolic link → null', async () => {
    const dir = gitRepo();
    const outside = makeTempDir();
    renameSync(join(dir, '.git/index'), join(outside, 'index'));
    symlinkSync(join(outside, 'index'), join(dir, '.git/index'));
    expect(await readGitIndexPaths(dir)).toBeNull();

    // .git itself a link to a real git folder
    const real = gitRepo();
    const linked = makeTempDir();
    symlinkSync(join(real, '.git'), join(linked, '.git'));
    expect(await readGitIndexPaths(linked)).toBeNull();
  });

  it('git-index: .git a file (gitdir:), no .git, no index, or an index over 64 MB → null', async () => {
    const real = gitRepo();
    const worktree = makeTempDir();
    writeIn(worktree, '.git', `gitdir: ${join(real, '.git')}\n`);
    expect(await readGitIndexPaths(worktree)).toBeNull();
    expect(await readGitIndexPaths(makeTempDir())).toBeNull();
    const empty = makeTempDir();
    git(empty, 'init', '-q');
    expect(await readGitIndexPaths(empty)).toBeNull();
    const big = gitRepo();
    truncateSync(join(big, '.git/index'), GIT_INDEX_LIMITS.maxBytes + 1);
    expect(await readGitIndexPaths(big)).toBeNull();
  });

  it('git-index: an unreadable .git/config (a link) → null; a config without sha256 is fine', async () => {
    const dir = gitRepo();
    const outside = makeTempDir();
    renameSync(join(dir, '.git/config'), join(outside, 'config'));
    symlinkSync(join(outside, 'config'), join(dir, '.git/config'));
    expect(await readGitIndexPaths(dir)).toBeNull();
  });
});

describe('parseGitIndex (hand-built indexes)', () => {
  const PATHS = ['a/b/c.ts', 'a/b/d.ts', 'a/e.ts', 'z.txt'];

  it('v2 and v4 hand-built → the paths', () => {
    for (const v of [2, 4] as const) {
      const got = parseGitIndex(handIndex(v, PATHS));
      expect(got && [...got]).toEqual(PATHS);
    }
  });

  it('500,000 entries → the paths; 500,001 (enough bytes for all of them) → null, by the entry limit alone', () => {
    const index = (count: number) => {
      const entry = Buffer.alloc(64); // 62 fixed bytes, the name "a", one NUL: a multiple of 8
      entry.writeUInt32BE(0o100644, 24);
      entry.writeUInt16BE(1, 60);
      entry.write('a', 62, 'latin1');
      const head = Buffer.alloc(12);
      head.write('DIRC', 0, 'latin1');
      head.writeUInt32BE(2, 4);
      head.writeUInt32BE(count, 8);
      const body = Buffer.alloc(12 + count * 64);
      head.copy(body, 0);
      for (let i = 0; i < count; i++) entry.copy(body, 12 + i * 64);
      return resign(body);
    };
    expect([...(parseGitIndex(index(GIT_INDEX_LIMITS.maxEntries)) ?? [])]).toEqual(['a']);
    expect(parseGitIndex(index(GIT_INDEX_LIMITS.maxEntries + 1))).toBeNull();
  });

  it('a v4 strip count over the previous path → null', () => {
    expect(parseGitIndex(handIndex(4, PATHS, { strip: (i, prev) => (i === 2 ? prev.length + 1 : 0) }))).toBeNull();
  });

  it('a path over 4,096 bytes, or one with .., ., an empty part or a leading / → null', () => {
    expect(parseGitIndex(handIndex(2, [`a/${'x'.repeat(4094)}`]))).not.toBeNull(); // 4,096 bytes: fine
    expect(parseGitIndex(handIndex(2, [`a/${'x'.repeat(4095)}`]))).toBeNull();
    expect(parseGitIndex(handIndex(4, [`a/${'x'.repeat(4095)}`]))).toBeNull();
    for (const bad of ['../x', 'a/../x', './x', 'a//x', '/x', 'a/.', '.git/config', 'a/.git/x']) expect(parseGitIndex(handIndex(2, [bad])), bad).toBeNull();
  });

  it('version 1 or 5, a wrong signature, or bytes after the last extension → null', () => {
    for (const v of [1, 5]) {
      const body = Buffer.from(handIndex(2, PATHS).subarray(0, -20));
      body.writeUInt32BE(v, 4);
      expect(parseGitIndex(resign(body)), `version ${v}`).toBeNull();
    }
    const sig = Buffer.from(handIndex(2, PATHS).subarray(0, -20));
    sig.write('DIRX', 0, 'latin1');
    expect(parseGitIndex(resign(sig))).toBeNull();
    const extra = Buffer.concat([handIndex(2, PATHS).subarray(0, -20), Buffer.from('TRE')]);
    expect(parseGitIndex(resign(extra))).toBeNull();
  });

  it('an unknown required extension (lowercase first letter) → null; an unknown optional one is skipped', () => {
    const ext = (sig: string, data: Buffer) => {
      const h = Buffer.alloc(8);
      h.write(sig, 0, 'latin1');
      h.writeUInt32BE(data.length, 4);
      return Buffer.concat([h, data]);
    };
    const base = handIndex(2, PATHS).subarray(0, -20);
    expect(parseGitIndex(resign(Buffer.concat([base, ext('ABCD', Buffer.from('xyz'))])))).not.toBeNull();
    expect(parseGitIndex(resign(Buffer.concat([base, ext('abcd', Buffer.from('xyz'))])))).toBeNull();
    // an extension whose size runs past the end
    const h = Buffer.alloc(8);
    h.write('TREE', 0, 'latin1');
    h.writeUInt32BE(1000, 4);
    expect(parseGitIndex(resign(Buffer.concat([base, h])))).toBeNull();
  });

  it('a directory entry (mode 040000, a sparse index) → null', () => {
    const buf = Buffer.from(handIndex(2, PATHS).subarray(0, -20));
    buf.writeUInt32BE(0o040000, 12 + 24);
    expect(parseGitIndex(resign(buf))).toBeNull();
  });
});

/** A main repo with one commit (FILES) and a linked worktree made by `git worktree add`; returns both folders. */
function worktree(extra: Record<string, string> = {}): { main: string; wt: string } {
  const main = gitRepo();
  for (const [f, body] of Object.entries(extra)) writeIn(main, f, body);
  git(main, 'add', '-f', '--', '.');
  git(main, '-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '--no-verify', '-m', 'init');
  const wt = join(makeTempDir(), 'wt');
  git(main, 'worktree', 'add', '-q', wt);
  return { main, wt };
}

describe('readGitIndexPaths: linked worktrees (PL-B3)', () => {
  it('worktree → index read through gitdir', async () => {
    const { wt } = worktree();
    expect([...((await readGitIndexPaths(wt)) ?? [])].sort()).toEqual([...FILES].sort());
  });

  it('gitdir whose back-pointer names another folder → null', async () => {
    const { main, wt } = worktree();
    const gitdir = /^gitdir: (.+)$/m.exec(readFileSync(join(wt, '.git'), 'utf8'))?.[1] as string;
    // a second checkout points its .git file at the first worktree's git folder: the back-pointer names wt, not it
    const other = makeTempDir();
    writeIn(other, '.git', `gitdir: ${gitdir}\n`);
    expect(await readGitIndexPaths(other)).toBeNull();
    // a relative back-pointer that resolves elsewhere is refused too
    writeFileSync(join(gitdir, 'gitdir'), '../../../../elsewhere/.git\n');
    expect(await readGitIndexPaths(wt)).toBeNull();
    expect(main).toBeTruthy();
  });

  it('submodule .git file → null', async () => {
    // a submodule's git folder (modules/<name>) is a full git folder: an index, no commondir
    const main = gitRepo();
    const mod = join(main, '.git/modules/sub');
    mkdirSync(mod, { recursive: true });
    const sub = join(main, 'sub');
    mkdirSync(sub);
    for (const f of ['index', 'config', 'HEAD']) writeFileSync(join(mod, f), f === 'index' ? indexOf(main) : '\n');
    writeFileSync(join(mod, 'gitdir'), `${join(sub, '.git')}\n`);
    writeIn(sub, '.git', 'gitdir: ../.git/modules/sub\n');
    expect(await readGitIndexPaths(sub)).toBeNull();
  });

  it('.git file is a symlink → null', async () => {
    const { wt } = worktree();
    const body = readFileSync(join(wt, '.git'));
    const elsewhere = join(makeTempDir(), 'dotgit');
    writeFileSync(elsewhere, body);
    rmIn(wt, '.git');
    symlinkSync(elsewhere, join(wt, '.git'));
    expect(await readGitIndexPaths(wt)).toBeNull();
  });

  it('worktree gitdir reached through a symlinked folder → null', async () => {
    const { wt } = worktree();
    const gitdir = /^gitdir: (.+)$/m.exec(readFileSync(join(wt, '.git'), 'utf8'))?.[1] as string;
    const link = join(makeTempDir(), 'link');
    symlinkSync(gitdir, link);
    writeFileSync(join(wt, '.git'), `gitdir: ${link}\n`);
    expect(await readGitIndexPaths(wt)).toBeNull();
    // a link higher up: the main repo's .git reached through a linked folder, the worktree's git folder under it
    const up = join(makeTempDir(), 'up');
    symlinkSync(join(gitdir, '../..'), up);
    writeFileSync(join(wt, '.git'), `gitdir: ${join(up, 'worktrees/wt')}\n`);
    expect(await readGitIndexPaths(wt)).toBeNull();
  });
});

function rmIn(dir: string, f: string): void {
  rmSync(join(dir, f));
}

