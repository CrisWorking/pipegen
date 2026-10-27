// Plan U Task 4a: `--out` file writing (threat T42: a hostile repo plants symlinks so pipegen overwrites another
// file). Ruling S20: no-follow + exclusive create, `--force` only for an existing regular file, lstat before and
// fstat after (same dev/ino), relative paths from the current folder, never create folders, no symlinked folder
// inside `--dir`, no write into `--dir` without `--force`, and a Windows branch without O_NOFOLLOW.
// Fix round 1: the repo check is by identity (dev/ino), not by how `--dir` and `--out` spell the path (C1);
// exclusive create whenever the target doesn't exist, no O_CREAT when it does (I1, M2); minors M1-M9.
// Real temp folders and real symlinks; the platform constants and `open` are injected, never module-mocked.
// CI runs on Ubuntu only: the simulated Windows block runs on every host, using junctions for folder links there.
import { execFileSync } from 'node:child_process';
import {
  chmod, constants, link, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, stat, symlink, writeFile,
} from 'node:fs/promises';
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
  root = await realpath(await mkdtemp(join(tmpdir(), 'pipegen-out-')));
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

/** A folder link: a junction on Windows (no admin rights needed); the type is ignored elsewhere. */
const dirLink = (to: string, at: string) => symlink(to, at, 'junction');

/** A file symlink; false when the system doesn't allow it (Windows without the right). */
async function tryFileLink(to: string, at: string): Promise<boolean> {
  try {
    await symlink(to, at, 'file');
    return true;
  } catch (e) {
    if ((e as { code?: string }).code === 'EPERM') return false;
    throw e;
  }
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
    expect(fresh.calls[0]!.flags).toBe(O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK);
    expect(fresh.calls[0]!.mode).toBe(0o600);

    // --force on a target that doesn't exist: still exclusive create (a parent swapped after the checks can't
    // make pipegen overwrite another file).
    const forcedNew = spyOpen();
    await writeOutFile(join(outside, 'c.md'), 'x', { force: true, dir: repo, cwd: work, open: forcedNew.open });
    expect(forcedNew.calls[0]!.flags).toBe(O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK);

    // --force on an existing file: no O_CREAT, no O_EXCL, no O_TRUNC; still no-follow; O_NONBLOCK so a FIFO
    // swapped in can't hang the open. The file is emptied only after fstat proved it is the file lstat saw.
    await writeFile(join(outside, 'b.md'), 'old');
    const forced = spyOpen();
    await writeOutFile(join(outside, 'b.md'), 'x', { force: true, dir: repo, cwd: work, open: forced.open });
    expect(forced.calls).toHaveLength(1);
    expect(forced.calls[0]!.flags).toBe(O_WRONLY | O_NOFOLLOW | O_NONBLOCK);
    expect((forced.calls[0]!.flags as number) & (O_TRUNC | O_CREAT | O_EXCL)).toBe(0);
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

  describe('C1: the repo check does not depend on how --dir and --out spell the path', () => {
    let victimDir: string;
    beforeEach(async () => {
      victimDir = join(root, 'home', '.bashrc.d');
      await mkdir(victimDir, { recursive: true });
      await writeFile(join(victimDir, 'report.md'), 'precious');
      await symlink(victimDir, join(repo, 'docs')); // planted by the repo
      await symlink(repo, join(root, 'repo-link')); // your own link to the repo
    });
    const victimSafe = async () => {
      expect(await readdir(victimDir)).toEqual(['report.md']);
      expect(await readFile(join(victimDir, 'report.md'), 'utf8')).toBe('precious');
    };
    const PLANTED = /inside the repo is a symbolic link/;

    it('--dir through your own link, --out through the real path (and the reverse)', async () => {
      for (const force of [false, true]) {
        let e = await refusal(writeOutFile(join(repo, 'docs', 'report.md'), 'evil', { force, dir: join(root, 'repo-link'), cwd: work }));
        expect(e.message).toMatch(PLANTED);
        e = await refusal(writeOutFile(join(root, 'repo-link', 'docs', 'report.md'), 'evil', { force, dir: repo, cwd: work }));
        expect(e.message).toMatch(PLANTED);
      }
      await victimSafe();
    });

    it('cd through a symlinked folder with a relative --out (logical --dir, physical current folder, and the reverse)', async () => {
      for (const force of [false, true]) {
        let e = await refusal(writeOutFile('docs/report.md', 'evil', { force, dir: join(root, 'repo-link'), cwd: repo }));
        expect(e.message).toMatch(PLANTED);
        e = await refusal(writeOutFile('docs/report.md', 'evil', { force, dir: repo, cwd: join(root, 'repo-link') }));
        expect(e.message).toMatch(PLANTED);
        e = await refusal(writeOutFile('docs/new.md', 'evil', { force, dir: '.', cwd: join(root, 'repo-link') }));
        expect(e.message).toMatch(PLANTED);
      }
      await victimSafe();
    });

    it('a symlinked tmp prefix (like macOS /tmp -> /private/tmp)', async () => {
      await mkdir(join(root, 'private', 'tmp'), { recursive: true });
      await symlink(join(root, 'private', 'tmp'), join(root, 'tmp'));
      const realRepo = join(root, 'private', 'tmp', 'repo');
      await mkdir(realRepo);
      await symlink(victimDir, join(realRepo, 'docs'));
      for (const force of [false, true]) {
        let e = await refusal(writeOutFile(join(realRepo, 'docs', 'report.md'), 'evil', { force, dir: join(root, 'tmp', 'repo'), cwd: work }));
        expect(e.message).toMatch(PLANTED);
        e = await refusal(writeOutFile(join(root, 'tmp', 'repo', 'docs', 'report.md'), 'evil', { force, dir: realRepo, cwd: work }));
        expect(e.message).toMatch(PLANTED);
      }
      await victimSafe();
    });

    it.runIf(process.platform === 'linux')('--dir /proc/self/cwd', async (ctx) => {
      const old = process.cwd();
      try {
        process.chdir(repo);
      } catch {
        return ctx.skip(); // a worker thread can't change folder
      }
      try {
        for (const force of [false, true]) {
          const e = await refusal(writeOutFile(join(repo, 'docs', 'report.md'), 'evil', { force, dir: '/proc/self/cwd', cwd: work }));
          expect(e.message).toMatch(PLANTED);
        }
      } finally {
        process.chdir(old);
      }
      await victimSafe();
    });

    it('your own link that points at the planted link is refused too', async () => {
      await symlink(join(repo, 'docs'), join(root, 'via-planted'));
      for (const force of [false, true]) {
        const e = await refusal(writeOutFile(join(root, 'via-planted', 'report.md'), 'evil', { force, dir: repo, cwd: work }));
        expect(e.message).toMatch(PLANTED);
      }
      await victimSafe();
    });

    it('"inside the repo" is judged by identity too: refused without --force, allowed with it', async () => {
      const e = await refusal(writeOutFile('report.md', 'x', { force: false, dir: join(root, 'repo-link'), cwd: repo }));
      expect(e.message).toMatch(/don't write the report into the repo you're auditing/i);
      await refusal(writeOutFile(join(root, 'repo-link', 'report.md'), 'x', { force: false, dir: repo, cwd: work }));
      expect(await exists(join(repo, 'report.md'))).toBe(false);
      await writeOutFile('report.md', 'x', { force: true, dir: join(root, 'repo-link'), cwd: repo });
      expect(await readFile(join(repo, 'report.md'), 'utf8')).toBe('x');
    });

    it('your own symlinked folders outside the repo still work', async () => {
      await symlink(outside, join(root, 'out-link'));
      await writeOutFile(join(root, 'out-link', 'report.md'), 'x', { force: false, dir: join(root, 'repo-link'), cwd: work });
      expect(await readFile(join(outside, 'report.md'), 'utf8')).toBe('x');
    });
  });

  it('I1: a repo folder swapped for a symlink after the checks never overwrites a file there (missing target)', async () => {
    const victimDir = join(root, 'home');
    await mkdir(victimDir);
    await writeFile(join(victimDir, 'report.md'), 'precious');
    for (const force of [false, true]) {
      await rm(join(repo, 'sub'), { recursive: true, force: true });
      await mkdir(join(repo, 'sub'));
      const race = spyOpen(async () => {
        await rm(join(repo, 'sub'), { recursive: true });
        await symlink(victimDir, join(repo, 'sub'));
      });
      const e = await refusal(writeOutFile(join(repo, 'sub', 'report.md'), 'PIPEGEN', { force, dir: repo, cwd: work, open: race.open }));
      // Without --force the inside-repo rule refuses first; with it, the exclusive create meets the other file.
      expect(e.message).toMatch(force ? /changed while pipegen was writing the report\. Nothing was written/ : /inside the repo you are auditing/);
      expect(await readFile(join(victimDir, 'report.md'), 'utf8')).toBe('precious');
    }
  });

  it('I1: same race with an existing target: refused by the dev/ino check, the other file untouched', async () => {
    const victimDir = join(root, 'home');
    await mkdir(victimDir);
    await writeFile(join(victimDir, 'report.md'), 'precious');
    await mkdir(join(repo, 'sub'));
    await writeFile(join(repo, 'sub', 'report.md'), 'old');
    const race = spyOpen(async () => {
      await rename(join(repo, 'sub'), join(repo, 'sub-old'));
      await symlink(victimDir, join(repo, 'sub'));
    });
    const e = await refusal(writeOutFile(join(repo, 'sub', 'report.md'), 'PIPEGEN', { force: true, dir: repo, cwd: work, open: race.open }));
    expect(e.message).toMatch(/changed while pipegen was writing/);
    expect(await readFile(join(victimDir, 'report.md'), 'utf8')).toBe('precious');
  });

  it.runIf(process.platform === 'linux')('I1: a folder swapped after the checks, no file there yet: nothing is written into it', async () => {
    const victimDir = join(root, 'home');
    await mkdir(victimDir);
    await mkdir(join(repo, 'sub'));
    const race = spyOpen(async () => {
      await rename(join(repo, 'sub'), join(repo, 'sub-old'));
      await symlink(victimDir, join(repo, 'sub'));
    });
    const e = await refusal(writeOutFile(join(repo, 'sub', 'report.md'), 'PIPEGEN', { force: true, dir: repo, cwd: work, open: race.open }));
    expect(e.message).toMatch(/a folder on its path changed while pipegen was writing the report\. Nothing was written/);
    expect(e.message).toMatch(/an empty file may have been left at/);
    expect(await readFile(join(victimDir, 'report.md'), 'utf8')).toBe('');
  });

  it('M1: --force over a 0666 file leaves it 0600', async () => {
    const target = join(outside, 'report.md');
    await writeFile(target, 'old');
    await chmod(target, 0o666);
    await writeOutFile(target, 'new', { force: true, dir: repo, cwd: work });
    expect((await stat(target)).mode & 0o777).toBe(0o600);
    expect(await readFile(target, 'utf8')).toBe('new');
  });

  it('M2: --force on a file removed after lstat: no new file is created', async () => {
    const target = join(outside, 'report.md');
    await writeFile(target, 'old');
    const race = spyOpen(() => rm(target));
    const e = await refusal(writeOutFile(target, 'x', { force: true, dir: repo, cwd: work, open: race.open }));
    expect(e.message).toMatch(/changed while pipegen was writing/);
    expect(await exists(target)).toBe(false);
  });

  it.runIf(typeof process.getuid === 'function' && process.getuid() !== 0)('M3: an error while resolving the folders refuses', async () => {
    await mkdir(join(outside, 'locked', 'inner'), { recursive: true });
    await chmod(join(outside, 'locked'), 0o000);
    try {
      const e = await refusal(writeOutFile(join(outside, 'locked', 'inner', 'report.md'), 'x', { force: true, dir: repo, cwd: work }));
      expect(e.message).toMatch(/permission denied/);
    } finally {
      await chmod(join(outside, 'locked'), 0o700);
    }
  });

  it("M4: Node's own ERR_* errors are rethrown as they are, not shown as a refusal", async () => {
    const bug = Object.assign(new TypeError('bad argument'), { code: 'ERR_INVALID_ARG_TYPE' });
    const open: OpenFn = async () => {
      throw bug;
    };
    await expect(writeOutFile(join(outside, 'r.md'), 'x', { force: false, dir: repo, cwd: work, open })).rejects.toBe(bug);
  });

  it('M5: a failed write says the file may be empty or incomplete', async () => {
    const target = join(outside, 'report.md');
    await writeFile(target, 'old');
    const open: OpenFn = async (p, flags, mode) => {
      const fh = await fsOpen(p, flags, mode);
      fh.writeFile = async () => {
        throw Object.assign(new Error('no space'), { code: 'ENOSPC' });
      };
      return fh;
    };
    const e = await refusal(writeOutFile(target, 'x', { force: true, dir: repo, cwd: work, open }));
    expect(e.message).toMatch(/the disk is full\. The file may be empty or incomplete\./);
  });

  it('M7: a path ending with a folder separator is refused', async () => {
    const e = await refusal(writeOutFile('report.md/', 'x', { force: false, dir: repo, cwd: work }));
    expect(e.message).toMatch(/ends with a folder separator/);
    expect(await exists(join(work, 'report.md'))).toBe(false);
  });

  it('M8: a symlink loop in a parent folder is reported as a loop', async () => {
    await symlink(join(outside, 'loop'), join(outside, 'loop'));
    for (const force of [false, true]) {
      const e = await refusal(writeOutFile(join(outside, 'loop', 'report.md'), 'x', { force, dir: repo, cwd: work }));
      expect(e.message).toMatch(/too many symbolic links in a row \(probably a loop\)/);
    }
  });

  it('an unreadable --dir refuses', async () => {
    const e = await refusal(writeOutFile(join(outside, 'r.md'), 'x', { force: false, dir: join(root, 'missing'), cwd: work }));
    expect(e.message).toMatch(/can't read the repo folder/);
    expect(await exists(join(outside, 'r.md'))).toBe(false);
  });
});

// Runs on every host: the constants are injected. On a Windows host, folder links are junctions.
describe('writeOutFile, Windows branch (no O_NOFOLLOW), simulated by injected constants', () => {
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

  it('a symlink is refused', async (ctx) => {
    const victim = join(outside, 'victim.txt');
    await writeFile(victim, 'precious');
    if (!(await tryFileLink(victim, join(outside, 'report.md')))) return ctx.skip();
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
    await dirLink(outside, join(repo, 'docs'));
    const e = await refusal(writeOutFile(join(repo, 'docs', 'new.md'), 'x', { force: false, dir: repo, cwd: work, constants: WINDOWS_CONSTANTS }));
    expect(e.message).toMatch(/symbolic link/);
    expect(await exists(join(outside, 'new.md'))).toBe(false);
  });
});
