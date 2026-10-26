import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import fg from 'fast-glob';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { READ_LIMITS, isBinary, listFiles, parseYamlLimited, readTextLimited, readTextLimitedWithReason, regexLines, regexSafe } from '../src/read/limits.js';
import { cleanupRepos, makeTempDir } from './helpers/make-repo.js';

afterEach(() => {
  vi.restoreAllMocks();
  cleanupRepos();
});

describe('limits', () => {
  it('file over 1 MB skipped', async () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, 'big.txt'), 'a'.repeat(READ_LIMITS.maxFileBytes + 1));
    writeFileSync(join(dir, 'ok.txt'), 'a'.repeat(READ_LIMITS.maxFileBytes));
    expect(await readTextLimited(join(dir, 'big.txt'))).toBeNull();
    expect((await readTextLimited(join(dir, 'ok.txt')))?.length).toBe(READ_LIMITS.maxFileBytes);
  });

  it('stops at 20,000 files with a note', async () => {
    const dir = makeTempDir();
    for (let d = 0; d < 100; d++) {
      mkdirSync(join(dir, `d${d}`));
      for (let f = 0; f < 201; f++) writeFileSync(join(dir, `d${d}`, `f${f}.txt`), '');
    }
    const result = await listFiles(dir, ['**/*'], []);
    expect(result.files).toHaveLength(20_000);
    expect(result.truncated).toBe(true);
    const small = await listFiles(dir, ['d0/*'], []);
    expect(small.truncated).toBe(false);
    expect(small.files).toHaveLength(201);
  });

  it('binary file skipped', async () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, 'a.bin'), Buffer.from([0x41, 0x00, 0x42]));
    expect(isBinary(Buffer.from([0x41, 0x00]))).toBe(true);
    expect(isBinary(Buffer.from('plain text'))).toBe(false);
    expect(await readTextLimitedWithReason(join(dir, 'a.bin'))).toEqual({ skipped: 'binary' });
    expect(await readTextLimited(join(dir, 'a.bin'))).toBeNull();
  });

  it('symlinks are never read', async () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, 'real.txt'), 'secret-ish');
    symlinkSync(join(dir, 'real.txt'), join(dir, 'link.txt'));
    expect(await readTextLimited(join(dir, 'link.txt'))).toBeNull();
    expect(await readTextLimited(join(dir, 'real.txt'))).toBe('secret-ish');
    expect(await listFiles(dir, ['**/*'], [])).toMatchObject({ files: ['real.txt'] });
  });

  it('fast-glob called with followSymbolicLinks false', async () => {
    const spy = vi.spyOn(fg, 'stream');
    await listFiles(makeTempDir(), ['**/*'], []);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[1]).toMatchObject({ followSymbolicLinks: false });
  });

  it('yaml with more than 50 aliases refused', () => {
    const refs = (n: number) => Array.from({ length: n }, () => '  - *a').join('\n');
    expect(parseYamlLimited('base: &a [1]\nlist:\n' + refs(10))).toEqual({ base: [1], list: Array(10).fill([1]) });
    expect(() => parseYamlLimited('base: &a [1]\nlist:\n' + refs(60))).toThrow(/alias/i);
  });

  it('regex rules skip lines longer than 4 KB', () => {
    const long = 'x'.repeat(READ_LIMITS.maxRegexLineBytes + 1);
    const exact = 'y'.repeat(READ_LIMITS.maxRegexLineBytes);
    expect(regexLines(`short\r\n${long}\n${exact}\nend`)).toEqual(['short', exact, 'end']);
  });

  it('symlinked directory not walked', async () => {
    const dir = makeTempDir();
    const outside = makeTempDir();
    writeFileSync(join(outside, 'secret.txt'), 'x');
    mkdirSync(join(dir, 'real'));
    writeFileSync(join(dir, 'real', 'a.txt'), '');
    symlinkSync(outside, join(dir, 'linked'), 'dir');
    expect((await listFiles(dir, ['**/*'], [])).files).toEqual(['real/a.txt']);
  });

  it('a pattern whose fixed base goes through a symlink lists nothing and the link is recorded', async () => {
    const dir = makeTempDir();
    const outside = makeTempDir();
    mkdirSync(join(outside, 'workflows'));
    writeFileSync(join(outside, 'workflows', 'a.yml'), 'on: push\n');
    symlinkSync(outside, join(dir, '.github'), 'dir');
    mkdirSync(join(dir, 'real'));
    writeFileSync(join(dir, 'real', 'b.yml'), '');
    const result = await listFiles(dir, ['.github/workflows/*.yml', 'real/*.yml'], []);
    expect(result.files).toEqual(['real/b.yml']);
    expect(result.links).toEqual(['.github']);
    const found = { links: [] as string[] };
    expect((await listFiles(dir, ['.github/workflows/*.yml'], [], found)).files).toEqual([]);
    expect(found.links).toEqual(['.github']);
    // a symlink deeper in the fixed base counts too; a plain listing has no links field
    const deep = makeTempDir();
    mkdirSync(join(deep, '.github'));
    symlinkSync(join(outside, 'workflows'), join(deep, '.github', 'workflows'), 'dir');
    expect(await listFiles(deep, ['.github/workflows/*.yml'], [])).toEqual({ files: [], truncated: false, links: ['.github/workflows'] });
    // a brace in a folder part expands to several fixed bases; each one is checked
    const braces = makeTempDir();
    mkdirSync(join(braces, 'outside'));
    writeFileSync(join(braces, 'outside', 'secret.txt'), 'x');
    symlinkSync(join(braces, 'outside'), join(braces, 'lnk'));
    expect((await listFiles(braces, ['l{n,x}k/*'], [])).files).toEqual([]);
    expect(await listFiles(dir, ['real/*.yml'], [])).toEqual({ files: ['real/b.yml'], truncated: false });
  });

  it('regexSafe refuses strings over 4 KB', () => {
    expect(regexSafe('a'.repeat(READ_LIMITS.maxRegexLineBytes))).toBe(true);
    expect(regexSafe('a'.repeat(READ_LIMITS.maxRegexLineBytes + 1))).toBe(false);
    expect(regexSafe('é'.repeat(READ_LIMITS.maxRegexLineBytes / 2 + 1))).toBe(false); // counted in bytes
  });

  it('readTextLimitedWithReason tells why a file was skipped', async () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, 'ok.txt'), 'hi');
    writeFileSync(join(dir, 'big.txt'), 'a'.repeat(READ_LIMITS.maxFileBytes + 1));
    writeFileSync(join(dir, 'bin'), Buffer.from([0, 1]));
    symlinkSync(join(dir, 'ok.txt'), join(dir, 'link'));
    mkdirSync(join(dir, 'folder'));
    expect(await readTextLimitedWithReason(join(dir, 'ok.txt'))).toEqual({ text: 'hi' });
    expect(await readTextLimitedWithReason(join(dir, 'big.txt'))).toEqual({ skipped: 'too-large' });
    expect(await readTextLimitedWithReason(join(dir, 'bin'))).toEqual({ skipped: 'binary' });
    expect(await readTextLimitedWithReason(join(dir, 'link'))).toEqual({ skipped: 'link' });
    expect(await readTextLimitedWithReason(join(dir, 'folder'))).toEqual({ skipped: 'not-a-file' });
    expect(await readTextLimitedWithReason(join(dir, 'missing'))).toEqual({ skipped: 'unreadable' });
  });

  it.skipIf(process.getuid?.() === 0)('readTextLimitedWithReason: unreadable file', async () => {
    const dir = makeTempDir();
    const file = join(dir, 'locked.txt');
    writeFileSync(file, 'x');
    chmodSync(file, 0o000);
    expect(await readTextLimitedWithReason(file)).toEqual({ skipped: 'unreadable' });
    expect(await readTextLimited(file)).toBeNull();
  });
});
