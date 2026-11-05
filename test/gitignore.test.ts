// Plan J sub-task J1 (DECISIONS #126, ruling S11): the audit reads .gitignore itself, in-process, never by running git.
// The differential test runs `git check-ignore` at setup only (test-only child process); pipegen never runs git.
import { execFileSync } from 'node:child_process';
import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { IGNORE_BUDGET_NOTE, IGNORE_GUARDS, IGNORE_LIMITS, ignoreSkippedNote, loadIgnore } from '../src/read/gitignore.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

/** git with no user or system config (no core.excludesFile, no global ignore file). */
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', HOME: '/nonexistent' };
const git = (dir: string, args: string[]) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', env: GIT_ENV }).toString();

describe('loadIgnore', () => {
  it('gitignore: root /out/, nested src/.gitignore *.gen.ts, negation !keep.log, .git/info/exclude, symlinked .gitignore ignored', async () => {
    const dir = makeTempDir();
    mkdirSync(join(dir, '.git/info'), { recursive: true });
    writeIn(dir, '.gitignore', '/out/\n*.log\n!keep.log\n');
    writeIn(dir, 'src/.gitignore', '*.gen.ts\n');
    writeIn(dir, '.git/info/exclude', 'local-notes.txt\n');
    // a symbolic link named .gitignore is never followed: its target's rules add nothing
    const outside = makeTempDir();
    writeIn(outside, 'rules', '*.ts\n');
    mkdirSync(join(dir, 'lib'));
    symlinkSync(join(outside, 'rules'), join(dir, 'lib/.gitignore'));
    const m = await loadIgnore(dir);
    expect(m.ignored('out/index.html')).toBe(true);
    expect(m.ignored('out/_next/static/a.js')).toBe(true);
    expect(m.ignored('docs/out/index.html')).toBe(false); // `/out/` is anchored to the root
    expect(m.ignored('src/api.gen.ts')).toBe(true);
    expect(m.ignored('src/deep/x.gen.ts')).toBe(true);
    expect(m.ignored('api.gen.ts')).toBe(false); // src/.gitignore applies under src/ only
    expect(m.ignored('debug.log')).toBe(true);
    expect(m.ignored('keep.log')).toBe(false);
    expect(m.ignored('src/keep.log')).toBe(false);
    expect(m.ignored('local-notes.txt')).toBe(true);
    expect(m.ignored('lib/index.ts')).toBe(false);
    expect(m.ignored('src/index.ts')).toBe(false);
    expect(m.notes).toEqual([]);
  });

  it('gitignore: over 1,000 files or 10,000 patterns → the rest add no rules, one note', async () => {
    expect(IGNORE_LIMITS).toEqual({ maxFiles: 1000, maxPatterns: 10_000, maxPatternChars: 1000 });
    const NOTE = 'pipegen read only the first 1,000 .gitignore files and 10,000 patterns; the rest were not used, so some files git ignores were treated as not ignored.';
    // files: 1,001 .gitignore files, read shallowest first (then by path): d1000/.gitignore is the one left out
    const many = makeTempDir();
    for (let i = 0; i <= 1000; i++) writeIn(many, `d${String(i).padStart(4, '0')}/.gitignore`, 'x.txt\n');
    const m1 = await loadIgnore(many);
    expect(m1.ignored('d0000/x.txt')).toBe(true);
    expect(m1.ignored('d0999/x.txt')).toBe(true);
    expect(m1.ignored('d1000/x.txt')).toBe(false);
    expect(m1.notes).toEqual([NOTE]);
    // patterns: the root file's 10,000 patterns are used, a nested file's pattern after them is not; comments and blank lines don't count
    const big = makeTempDir();
    writeIn(big, '.gitignore', `# a comment\n\n${Array.from({ length: 10_000 }, (_, i) => `p${i}.txt`).join('\n')}\n`);
    writeIn(big, 'sub/.gitignore', 'late.txt\n');
    const m2 = await loadIgnore(big);
    expect(m2.ignored('p0.txt')).toBe(true);
    expect(m2.ignored('p9999.txt')).toBe(true);
    expect(m2.ignored('sub/late.txt')).toBe(false);
    expect(m2.notes).toEqual([NOTE]);
    // a pattern over 1,000 characters adds nothing (its own note); the next one still counts
    const long = makeTempDir();
    writeIn(long, '.gitignore', `${'a'.repeat(1001)}*\nshort.txt\n`);
    const m3 = await loadIgnore(long);
    expect(m3.ignored(`${'a'.repeat(1001)}b`)).toBe(false);
    expect(m3.ignored('short.txt')).toBe(true);
    expect(m3.notes).toEqual([ignoreSkippedNote(1)]);
  });

  it('gitignore: .git a file (a worktree or submodule) → no .git/info/exclude; .gitignore files still apply', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.git', 'gitdir: /somewhere/else\n');
    writeIn(dir, '.gitignore', 'out/\n');
    const m = await loadIgnore(dir);
    expect(m.ignored('out/a.js')).toBe(true);
    expect(m.ignored('src/a.js')).toBe(false);
  });

  it('gitignore: .git/info/exclude through a symbolic link, or an unreadable .gitignore, adds no rules', async () => {
    const dir = makeTempDir();
    const outside = makeTempDir();
    writeIn(outside, 'exclude', '*.js\n');
    mkdirSync(join(dir, '.git'));
    symlinkSync(outside, join(dir, '.git/info'));
    writeIn(dir, '.gitignore', `${'#'.repeat(1_000_001)}\n`); // over 1 MB: unreadable
    const m = await loadIgnore(dir);
    expect(m.ignored('a.js')).toBe(false);
  });

  it('gitignore: folder names with glob characters are matched literally', async () => {
    const dir = makeTempDir();
    writeIn(dir, '[ab]/.gitignore', 'x.txt\n');
    writeIn(dir, 'st*r/.gitignore', '/y.txt\n');
    const m = await loadIgnore(dir);
    expect(m.ignored('[ab]/x.txt')).toBe(true);
    expect(m.ignored('a/x.txt')).toBe(false);
    expect(m.ignored('st*r/y.txt')).toBe(true);
    expect(m.ignored('stXr/y.txt')).toBe(false);
  });

  it('gitignore: a path the matcher cannot take (empty, absolute, ..) is not ignored and never throws', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', '*\n');
    const m = await loadIgnore(dir);
    for (const p of ['', '/etc/passwd', '../x', './x']) expect(m.ignored(p), p).toBe(false);
  });

  it('gitignore: the same answers as `git check-ignore` (run at setup) on nested rules, re-includes and folder rules', async () => {
    const dir = makeTempDir();
    git(dir, ['init', '-q']);
    writeIn(dir, '.git/info/exclude', 'scratch/\n');
    writeIn(dir, '.gitignore', [
      'build-out/', '*.tmp', '!important.tmp', '/root-only.txt', 'logs/**/*.log', 'docs/*.html', '\\#hash.txt', 'trailing.txt   ',
      'cache', 'vendor-x/', '!vendor-x/keep.js', 'a/**/b.txt', '**/deep.txt', 'reinc/', '',
    ].join('\n'));
    writeIn(dir, 'pkg/.gitignore', ['*.gen.ts', '/local.txt', 'sub/only.txt', '!*.tmp', 'cache', '!reinc/'].join('\n'));
    writeIn(dir, 'pkg/sub/.gitignore', ['!keep.gen.ts', 'z*'].join('\n'));
    const paths = [
      'build-out/a.js', 'pkg/build-out/a.js', 'x.tmp', 'important.tmp', 'pkg/x.tmp', 'root-only.txt', 'pkg/root-only.txt',
      'logs/a.log', 'logs/x/y/a.log', 'logs/a.txt', 'docs/a.html', 'docs/x/a.html', '#hash.txt', 'trailing.txt', 'cache',
      'other/cache/x.js', 'pkg/cache', 'vendor-x/keep.js', 'vendor-x/other.js', 'a/b.txt', 'a/x/y/b.txt', 'q/deep.txt', 'deep.txt',
      'pkg/a.gen.ts', 'pkg/sub/a.gen.ts', 'pkg/sub/keep.gen.ts', 'pkg/local.txt', 'pkg/x/local.txt', 'pkg/sub/only.txt',
      'pkg/sub/zed.js', 'pkg/zed.js', 'scratch/a', 'pkg/scratch/a', 'reinc/a.js', 'pkg/reinc/a.js', 'src/index.ts',
    ];
    for (const p of paths) writeIn(dir, p, '');
    let byGit: Set<string>;
    try {
      byGit = new Set(git(dir, ['check-ignore', '--no-index', ...paths]).split('\n').filter((l) => l !== ''));
    } catch (e) {
      // check-ignore exits 1 when nothing is ignored
      byGit = new Set(String((e as { stdout?: Buffer }).stdout ?? '').split('\n').filter((l) => l !== ''));
    }
    expect(byGit.size).toBeGreaterThan(10); // the setup itself worked
    const m = await loadIgnore(dir);
    for (const p of paths) expect(m.ignored(p), p).toBe(byGit.has(p));
  });

  it('gitignore: a rule with two `**` (a trailing /** aside), or past 500,000 characters in all, adds nothing, with a note', async () => {
    expect(IGNORE_GUARDS).toEqual({ maxTotalChars: 500_000, maxDoubleStars: 1, maxMatchWork: 2_000_000_000 });
    const dir = makeTempDir();
    // `a/**/a/**/b` runs for minutes on a deep path with ignore 7.0.14 (J1 report); it is never used
    writeIn(dir, '.gitignore', ['a/**/a/**/b', '**/keep/**', '**/one/**/x.js', 'one/**/x.js', 'two**x'].join('\n'));
    writeIn(dir, 'pkg/.gitignore', ['deep/**/y.js', '**/z.js', 'w*.js'].join('\n'));
    const m = await loadIgnore(dir);
    expect(m.ignored('a/q/a/r/b')).toBe(false);
    expect(m.ignored(`${'a/'.repeat(1000)}b`)).toBe(false); // and it returns at once
    expect(m.ignored('x/keep/y.txt')).toBe(true);
    expect(m.ignored('one/q/x.js')).toBe(true);
    expect(m.ignored('two-and-x')).toBe(true); // `**` inside a name is one `**`
    expect(m.ignored('pkg/deep/q/y.js')).toBe(true); // pkg/deep/**/y.js
    expect(m.ignored('pkg/q/z.js')).toBe(true); // `**/z.js` has a slash, so it becomes pkg/**/z.js: one
    expect(m.ignored('pkg/q/w1.js')).toBe(true); // pkg/**/w*.js: one
    expect(m.ignored('two/one/q/x.js')).toBe(false); // only `**/one/**/x.js` (two, not used) would match it
    expect(m.notes).toEqual([ignoreSkippedNote(2)]);

    const total = makeTempDir();
    // 600 patterns of 900 characters: the first 555 fit in 500,000 characters, the rest add nothing
    writeIn(total, '.gitignore', Array.from({ length: 600 }, (_, i) => `${String(i).padStart(3, '0')}${'q'.repeat(897)}`).join('\n'));
    const t = await loadIgnore(total);
    expect(t.ignored(`000${'q'.repeat(897)}`)).toBe(true);
    expect(t.ignored(`554${'q'.repeat(897)}`)).toBe(true);
    expect(t.ignored(`555${'q'.repeat(897)}`)).toBe(false);
    expect(t.notes).toEqual([ignoreSkippedNote(45)]);
  });

  it('gitignore: past the matching work budget every later path is not ignored, one note, the same answers on a second run', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', 'out/\n');
    // budget: one rule × (characters of the path and each folder above it not tested yet, +1 each)
    const paths = ['out/a.js', 'out/b.js', 'out/c.js', 'out/d.js'];
    const answers = async () => {
      const m = await loadIgnore(dir, { maxMatchWork: 30 });
      return { got: paths.map((p) => m.ignored(p)), notes: m.notes };
    };
    // out/a.js: 9 + "out/" 5 = 14; out/b.js: 9 (out/ already tested) = 23; out/c.js: 32 > 30 → stop
    const first = await answers();
    expect(first.got).toEqual([true, true, false, false]);
    expect(first.notes).toEqual([IGNORE_BUDGET_NOTE]);
    expect(await answers()).toEqual(first);
    // the real budget is not reached by an ordinary repo
    const m = await loadIgnore(dir);
    for (let i = 0; i < 1000; i++) expect(m.ignored(`out/f${i}.js`)).toBe(true);
    expect(m.notes).toEqual([]);
  });

  it('gitignore: no .gitignore anywhere → nothing ignored', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'a.js', '');
    const m = await loadIgnore(dir);
    expect(m.ignored('a.js')).toBe(false);
    expect(m.notes).toEqual([]);
  });
});
