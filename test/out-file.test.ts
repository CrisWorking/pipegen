// Plan U Task 4a: `--out` file writing (threat T42: a hostile repo plants symlinks so pipegen overwrites another
// file). Ruling S20: no-follow + exclusive create, `--force` only for an existing regular file, lstat before and
// fstat after (same dev/ino), relative paths from the current folder, never create folders, no symlinked folder
// inside `--dir`, no write into `--dir` without `--force`, and a Windows branch without O_NOFOLLOW.
// Real temp folders and real symlinks; the platform constants and `open` are injected, never module-mocked.
import { execFileSync } from 'node:child_process';
import { constants, link, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { open as fsOpen } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { OutFileError, writeOutFile, type OpenFn, type OutFileConstants } from '../src/audit/out-file.js';

const POSIX = process.platform !== 'win32';
const { O_WRONLY, O_CREAT, O_EXCL, O_TRUNC, O_NOFOLLOW, O_NONBLOCK } = constants;
/** What Node reports on Windows: no O_NOFOLLOW (and no O_NONBLOCK). */
const WINDOWS_CONSTANTS: OutFileConstants = { O_WRONLY, O_CREAT, O_EXCL };

let root: string;
let repo: string; // the audited repo (--dir)
let work: string; // the current folder
let outside: string; // a folder outside the repo

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'pipegen-out-'));
  repo = join(root, 'repo');
  work = join(root, 'work');
  outside = join(root, 'outside');
  await Promise.all([mkdir(repo), mkdir(work), mkdir(outside)]);
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

/** Runs writeOutFile and returns the OutFileError it throws (fails the test when it doesn't throw one). */
async function refusal(p: Promise<void>): Promise<OutFileError> {
  const e = await p.then(
    () => undefined,
    (err: unknown) => err,
  );
  expect(e).toBeInstanceOf(OutFileError);
  return e as OutFileError;
}

/** An `open` spy that records each call and then opens for real (optionally doing `before` first, to race). */
function spyOpen(before?: () => Promise<void>) {
  const calls: { path: string; flags: string | number; mode: number | undefined }[] = [];
  const open: OpenFn = async (path, flags, mode) => {
    calls.push({ path, flags, mode });
    if (before) await before();
    return fsOpen(path, flags, mode);
  };
  return { open, calls };
}

const exists = (p: string) =>
  stat(p).then(
    () => true,
    () => false,
  );

describe.runIf(POSIX)('writeOutFile (POSIX)', () => {
  it('out: existing file refused without --force', async () => {
    const target = join(outside, 'report.md');
    await writeFile(target, 'old');
    const e = await refusal(writeOutFile(target, 'new', { force: false, dir: repo, cwd: work }));
    expect(e.message).toMatch(/already exists/);
    expect(e.message).toMatch(/--force/);
    expect(await readFile(target, 'utf8')).toBe('old');
  });

  it('out: symlink refused, even with --force', async () => {
    const victim = join(outside, 'victim.txt');
    await writeFile(victim, 'precious');
    const target = join(outside, 'report.md');
    await symlink(victim, target);
    for (const force of [false, true]) {
      const e = await refusal(writeOutFile(target, 'evil', { force, dir: repo, cwd: work }));
      expect(e.message).toMatch(/symbolic link/);
    }
    expect(await readFile(victim, 'utf8')).toBe('precious');
  });

  it('out: --force replaces an existing regular file', async () => {
    const target = join(outside, 'report.md');
    await writeFile(target, 'a much longer old report that must not leave a tail behind');
    await writeOutFile(target, 'new', { force: true, dir: repo, cwd: work });
    expect(await readFile(target, 'utf8')).toBe('new');
  });

  it('out: opened with no-follow and exclusive create (flags checked)', async () => {
    const fresh = spyOpen();
    await writeOutFile(join(outside, 'a.md'), 'x', { force: false, dir: repo, cwd: work, open: fresh.open });
    expect(fresh.calls).toHaveLength(1);
    expect(fresh.calls[0]!.flags).toBe(O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW);
    expect(fresh.calls[0]!.mode).toBe(0o600);

    // --force: no O_EXCL; still no-follow; O_NONBLOCK so a FIFO swapped in can't hang the open; no O_TRUNC
    // (the file is emptied only after fstat proved it is the same regular file lstat saw).
    await writeFile(join(outside, 'b.md'), 'old');
    const forced = spyOpen();
    await writeOutFile(join(outside, 'b.md'), 'x', { force: true, dir: repo, cwd: work, open: forced.open });
    expect(forced.calls).toHaveLength(1);
    expect(forced.calls[0]!.flags).toBe(O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK);
    expect((forced.calls[0]!.flags as number) & O_TRUNC).toBe(0);
    expect(forced.calls[0]!.mode).toBe(0o600);
    expect(await readFile(join(outside, 'b.md'), 'utf8')).toBe('x');
  });

  it('out: relative path resolved from the current folder, not from --dir', async () => {
    const spy = spyOpen();
    await writeOutFile('report.md', 'r', { force: false, dir: repo, cwd: work, open: spy.open });
    expect(spy.calls[0]!.path).toBe(join(work, 'report.md'));
    expect(await readFile(join(work, 'report.md'), 'utf8')).toBe('r');
    expect(await exists(join(repo, 'report.md'))).toBe(false);

    // A relative --dir is also read from the current folder.
    await writeOutFile('../outside/r2.md', 'r2', { force: false, dir: '../repo', cwd: work });
    expect(await readFile(join(outside, 'r2.md'), 'utf8')).toBe('r2');
  });

  it('dangling symlink refused, with and without --force, and its target is not created', async () => {
    const target = join(outside, 'report.md');
    const nowhere = join(outside, 'created-through-link.txt');
    await symlink(nowhere, target);
    for (const force of [false, true]) {
      const e = await refusal(writeOutFile(target, 'evil', { force, dir: repo, cwd: work }));
      expect(e.message).toMatch(/symbolic link/);
    }
    expect(await exists(nowhere)).toBe(false);
  });

  it('a symlink planted in the repo, pointing to a file outside it, is refused with and without --force', async () => {
    const victim = join(outside, '.bashrc');
    await writeFile(victim, 'precious');
    await symlink(victim, join(repo, 'pipegen-report.md'));
    for (const force of [false, true]) {
      const e = await refusal(writeOutFile(join(repo, 'pipegen-report.md'), 'evil', { force, dir: repo, cwd: work }));
      expect(e.message).toMatch(/symbolic link/);
    }
    expect(await readFile(victim, 'utf8')).toBe('precious');
  });

  it('a symlinked folder inside --dir is refused, with and without --force', async () => {
    await mkdir(join(repo, 'real'));
    await symlink(outside, join(repo, 'real', 'docs'));
    for (const force of [false, true]) {
      const e = await refusal(writeOutFile(join(repo, 'real', 'docs', 'report.md'), 'evil', { force, dir: repo, cwd: work }));
      expect(e.message).toMatch(/symbolic link/);
      expect(e.message).toMatch(/docs/);
    }
    expect(await exists(join(outside, 'report.md'))).toBe(false);
    // Same with a relative path from inside the repo.
    const e = await refusal(writeOutFile('real/docs/report.md', 'evil', { force: true, dir: '.', cwd: repo }));
    expect(e.message).toMatch(/symbolic link/);
    expect(await exists(join(outside, 'report.md'))).toBe(false);
  });

  it('a FIFO target is refused with --force (and the call does not hang)', async () => {
    const fifo = join(outside, 'report.md');
    execFileSync('mkfifo', [fifo]);
    const e = await refusal(writeOutFile(fifo, 'x', { force: true, dir: repo, cwd: work }));
    expect(e.message).toMatch(/not a regular file/);
  });

  it('a folder target is refused with --force', async () => {
    await mkdir(join(outside, 'report.md'));
    const e = await refusal(writeOutFile(join(outside, 'report.md'), 'x', { force: true, dir: repo, cwd: work }));
    expect(e.message).toMatch(/not a regular file/);
  });

  it('a target inside --dir is refused without --force and says why; --force allows a new regular file there', async () => {
    const target = join(repo, 'sub', 'report.md');
    await mkdir(join(repo, 'sub'));
    const e = await refusal(writeOutFile(target, 'x', { force: false, dir: repo, cwd: work }));
    expect(e.message).toMatch(/don't write the report into the repo you're auditing/i);
    expect(await exists(target)).toBe(false);
    // The default --dir is the current folder: a bare file name lands in the repo, so it is refused too.
    await refusal(writeOutFile('report.md', 'x', { force: false, dir: '.', cwd: repo }));
    expect(await exists(join(repo, 'report.md'))).toBe(false);

    await writeOutFile(target, 'x', { force: true, dir: repo, cwd: work });
    expect(await readFile(target, 'utf8')).toBe('x');
  });

  it('a path outside --dir that leads into it through your own symlink still counts as inside', async () => {
    await symlink(repo, join(work, 'repo-link'));
    const e = await refusal(writeOutFile('repo-link/report.md', 'x', { force: false, dir: repo, cwd: work }));
    expect(e.message).toMatch(/repo you're auditing/);
    expect(await exists(join(repo, 'report.md'))).toBe(false);
  });

  it('a new file gets mode 0600', async () => {
    const target = join(outside, 'report.md');
    await writeOutFile(target, 'x', { force: false, dir: repo, cwd: work });
    expect((await stat(target)).mode & 0o777).toBe(0o600);
    await writeOutFile(join(outside, 'forced-new.md'), 'x', { force: true, dir: repo, cwd: work });
    expect((await stat(join(outside, 'forced-new.md'))).mode & 0o777).toBe(0o600);
  });

  it('a missing folder is not created', async () => {
    const e = await refusal(writeOutFile(join(outside, 'nope', 'report.md'), 'x', { force: true, dir: repo, cwd: work }));
    expect(e.message).toMatch(/doesn't exist/);
    expect(e.message).toMatch(/doesn't create folders/);
    expect(await exists(join(outside, 'nope'))).toBe(false);
  });

  it('--force refuses a file with other hard links (replacing it would change the other file too)', async () => {
    const victim = join(outside, 'victim.txt');
    await writeFile(victim, 'precious');
    await link(victim, join(outside, 'report.md'));
    const e = await refusal(writeOutFile(join(outside, 'report.md'), 'evil', { force: true, dir: repo, cwd: work }));
    expect(e.message).toMatch(/hard link/);
    expect(await readFile(victim, 'utf8')).toBe('precious');
  });

  it('a symlink swapped in after the checks is still refused by no-follow', async () => {
    const victim = join(outside, 'victim.txt');
    await writeFile(victim, 'precious');
    const target = join(outside, 'report.md');
    for (const force of [false, true]) {
      if (force) await writeFile(target, 'old');
      const race = spyOpen(async () => {
        await rm(target, { force: true });
        await symlink(victim, target);
      });
      const e = await refusal(writeOutFile(target, 'evil', { force, dir: repo, cwd: work, open: race.open }));
      expect(e.message).toMatch(/symbolic link/);
      await rm(target);
    }
    expect(await readFile(victim, 'utf8')).toBe('precious');
  });

  it('--force: a different file swapped in after lstat is refused (dev/ino check) and left untouched', async () => {
    const target = join(outside, 'report.md');
    await writeFile(target, 'old');
    await writeFile(join(outside, 'other.txt'), 'other content');
    const race = spyOpen(() => rename(join(outside, 'other.txt'), target));
    const e = await refusal(writeOutFile(target, 'evil', { force: true, dir: repo, cwd: work, open: race.open }));
    expect(e.message).toMatch(/changed while pipegen was writing/);
    expect(await readFile(target, 'utf8')).toBe('other content');
  });

  it('messages are plain: no stack trace, path cleaned with safeText', async () => {
    const hostile = join(outside, 'r\u001b[31m\nep\u202eort.md');
    await writeFile(hostile, 'old');
    const e = await refusal(writeOutFile(hostile, 'x', { force: false, dir: repo, cwd: work }));
    expect(e.message).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/);
    expect(e.message).not.toMatch(/\n\s+at /);
    expect(e.message).toContain('rep');
    expect(e.cause).toBeUndefined();
  });

  it('an empty path is refused', async () => {
    const e = await refusal(writeOutFile('', 'x', { force: true, dir: repo, cwd: work }));
    expect(e.message).toMatch(/file name/);
  });

  describe('Windows branch (no O_NOFOLLOW), simulated by injected constants', () => {
    it('--force is refused with a clear message, before anything is opened', async () => {
      const target = join(outside, 'report.md');
      await writeFile(target, 'old');
      const spy = spyOpen();
      const e = await refusal(
        writeOutFile(target, 'x', { force: true, dir: repo, cwd: work, constants: WINDOWS_CONSTANTS, open: spy.open }),
      );
      expect(e.message).toMatch(/--force isn't available on this system/);
      expect(spy.calls).toHaveLength(0);
      expect(await readFile(target, 'utf8')).toBe('old');
    });

    it('a symlink is refused', async () => {
      const victim = join(outside, 'victim.txt');
      await writeFile(victim, 'precious');
      await symlink(victim, join(outside, 'report.md'));
      const spy = spyOpen();
      const e = await refusal(
        writeOutFile(join(outside, 'report.md'), 'x', { force: false, dir: repo, cwd: work, constants: WINDOWS_CONSTANTS, open: spy.open }),
      );
      expect(e.message).toMatch(/symbolic link/);
      expect(spy.calls).toHaveLength(0);
      expect(await readFile(victim, 'utf8')).toBe('precious');
    });

    it('a new file is opened with wx (exclusive create)', async () => {
      const spy = spyOpen();
      await writeOutFile('report.md', 'x', { force: false, dir: repo, cwd: work, constants: WINDOWS_CONSTANTS, open: spy.open });
      expect(spy.calls).toEqual([{ path: join(work, 'report.md'), flags: 'wx', mode: 0o600 }]);
      expect(await readFile(join(work, 'report.md'), 'utf8')).toBe('x');
    });

    it('an existing file is refused, and a symlinked folder inside --dir too', async () => {
      await writeFile(join(outside, 'report.md'), 'old');
      await refusal(writeOutFile(join(outside, 'report.md'), 'x', { force: false, dir: repo, cwd: work, constants: WINDOWS_CONSTANTS }));
      expect(await readFile(join(outside, 'report.md'), 'utf8')).toBe('old');
      await symlink(outside, join(repo, 'docs'));
      const e = await refusal(writeOutFile(join(repo, 'docs', 'new.md'), 'x', { force: false, dir: repo, cwd: work, constants: WINDOWS_CONSTANTS }));
      expect(e.message).toMatch(/symbolic link/);
      expect(await exists(join(outside, 'new.md'))).toBe(false);
    });
  });
});
