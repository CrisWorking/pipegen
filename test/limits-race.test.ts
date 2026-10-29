// The swap race in the limited readers (Plan A final review, optional hardening): a file checked with lstat can be
// replaced before it is read (by a FIFO, which blocks a plain open or read forever; by a symlink, which a path read
// follows; or by a bigger file). The swap is simulated by an lstat that still describes the file as it was checked: a
// small regular file. What is read must be judged on the opened descriptor, so none of these is read as text.
import { execFileSync } from 'node:child_process';
import { symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { READ_LIMITS, readLinesLimited, readTextLimitedWithReason } from '../src/read/limits.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

const swapped = vi.hoisted(() => ({ paths: new Map<string, string>() }));
vi.mock('node:fs/promises', async (importOriginal) => {
  const a = await importOriginal<typeof import('node:fs/promises')>();
  // lstat of a swapped path answers for the small regular file that was there when it was checked
  const lstat = vi.fn(async (p: Parameters<typeof a.lstat>[0]) => a.lstat(swapped.paths.get(String(p)) ?? p));
  return { ...a, lstat, default: { ...a, lstat } };
});

afterEach(() => {
  swapped.paths.clear();
  cleanupRepos();
});

/** A small regular file standing for the file as it was checked, and `path` reported as that file by lstat. */
function swappedIn(dir: string, path: string): void {
  const before = join(dir, 'checked.txt');
  writeFileSync(before, 'small\n');
  swapped.paths.set(path, before);
}

/** Fails the test instead of hanging when a reader blocks (a FIFO opened or read without O_NONBLOCK). */
function within<T>(p: Promise<T>, ms = 3000): Promise<T> {
  return Promise.race([p, new Promise<T>((_, reject) => setTimeout(() => reject(new Error('the read blocked')), ms))]);
}

describe.skipIf(process.platform === 'win32')('limited readers: a file swapped after the lstat check', () => {
  it('a FIFO swapped in is not a file, and the read never blocks', async () => {
    const dir = makeTempDir();
    const fifo = join(dir, 'pipe');
    execFileSync('mkfifo', [fifo]);
    swappedIn(dir, fifo);
    expect(await within(readTextLimitedWithReason(fifo))).toEqual({ skipped: 'not-a-file' });
    const lines: string[] = [];
    expect(await within(readLinesLimited(fifo, { maxBytes: 1000, maxLineBytes: 100 }, (l) => lines.push(l)))).toEqual({ skipped: 'not-a-file' });
    expect(lines).toEqual([]);
  });

  it('a symlink swapped in is a link, never followed', async () => {
    const dir = makeTempDir();
    const target = join(dir, 'outside.txt');
    writeFileSync(target, 'not for the reader\n');
    const link = join(dir, 'link.txt');
    symlinkSync(target, link);
    swappedIn(dir, link);
    expect(await readTextLimitedWithReason(link)).toEqual({ skipped: 'link' });
  });

  it('a file that is bigger than the limit when opened is too large, whatever lstat said', async () => {
    const dir = makeTempDir();
    const big = join(dir, 'big.txt');
    writeFileSync(big, 'a'.repeat(READ_LIMITS.maxFileBytes + 1));
    swappedIn(dir, big);
    expect(await readTextLimitedWithReason(big)).toEqual({ skipped: 'too-large' });
  });

  it('a regular file not swapped reads as before', async () => {
    const dir = makeTempDir();
    const ok = join(dir, 'ok.txt');
    writeFileSync(ok, 'hello\n');
    expect(await readTextLimitedWithReason(ok)).toEqual({ text: 'hello\n' });
    writeFileSync(join(dir, 'nul.bin'), Buffer.from([0x61, 0, 0x62]));
    expect(await readTextLimitedWithReason(join(dir, 'nul.bin'))).toEqual({ skipped: 'binary' });
    expect(await readTextLimitedWithReason(join(dir, 'missing.txt'))).toEqual({ skipped: 'unreadable' });
    expect(await readTextLimitedWithReason(dir)).toEqual({ skipped: 'not-a-file' });
  });
});
