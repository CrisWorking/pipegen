// Plan J sub-task J1 (DECISIONS #126, ruling S11): the audit reads .gitignore itself, in-process, never by running git.
// The differential test runs `git check-ignore` at setup only (test-only child process); pipegen never runs git.
// Fix round 1 (review J1, I1): where a limit leaves the answer unsure, the caller's safe side is used: 'ignored' for the
// AI bundle (never send a file git may ignore), 'not-ignored' for the quick secret check (never skip one it may not).
import { execFileSync } from 'node:child_process';
import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  IGNORE_GUARDS, IGNORE_LIMITS, ignoreBudgetNote, ignoreLimitNote, ignoreSkippedNote, ignoreUnreadableNote, loadIgnore, type WhenUnsure,
} from '../src/read/gitignore.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

/** git with no user or system config (no core.excludesFile, no global ignore file). */
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', HOME: '/nonexistent' };
const git = (dir: string, args: string[]) => execFileSync('git', args, { cwd: dir, stdio: 'pipe', env: GIT_ENV }).toString();

const BUNDLE = { whenUnsure: 'ignored' } as const; // the AI bundle's side
const SCAN = { whenUnsure: 'not-ignored' } as const; // the quick secret check's side
const BOTH: WhenUnsure[] = ['ignored', 'not-ignored'];

describe('loadIgnore', () => {
  it('gitignore: root /out/, nested src/.gitignore *.gen.ts, negation !keep.log, .git/info/exclude, symlinked .gitignore ignored', async () => {
    const dir = makeTempDir();
    mkdirSync(join(dir, '.git/info'), { recursive: true });
    writeIn(dir, '.gitignore', '/out/\n*.log\n!keep.log\n');
    writeIn(dir, 'src/.gitignore', '*.gen.ts\n');
    writeIn(dir, '.git/info/exclude', 'local-notes.txt\n');
    // a symbolic link named .gitignore is never followed (git doesn't either): its target's rules add nothing
    const outside = makeTempDir();
    writeIn(outside, 'rules', '*.ts\n');
    mkdirSync(join(dir, 'lib'));
    symlinkSync(join(outside, 'rules'), join(dir, 'lib/.gitignore'));
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
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
      expect(m.ignored('lib/index.ts'), whenUnsure).toBe(false); // the link adds nothing and leaves nothing unsure
      expect(m.ignored('src/index.ts')).toBe(false);
      expect(m.notes).toEqual([]);
    }
  });

  it('gitignore: over 1,000 files or 10,000 patterns → the rest add no rules, one note', async () => {
    expect(IGNORE_LIMITS).toEqual({ maxFiles: 1000, maxPatterns: 10_000, maxPatternChars: 1000 });
    // files: 1,001 .gitignore files, read shallowest first (then by path): d1000/.gitignore is the one left out
    const many = makeTempDir();
    for (let i = 0; i <= 1000; i++) writeIn(many, `d${String(i).padStart(4, '0')}/.gitignore`, 'x.txt\n');
    // patterns: the root file's 10,000 patterns are used, a nested file's pattern after them is not; comments and blank lines don't count
    const big = makeTempDir();
    writeIn(big, '.gitignore', `# a comment\n\n${Array.from({ length: 10_000 }, (_, i) => `p${i}.txt`).join('\n')}\n`);
    writeIn(big, 'sub/.gitignore', 'late.txt\n');
    for (const whenUnsure of BOTH) {
      const m1 = await loadIgnore(many, { whenUnsure });
      expect(m1.ignored('d0000/x.txt')).toBe(true);
      expect(m1.ignored('d0999/x.txt')).toBe(true);
      expect(m1.ignored('d0999/y.txt')).toBe(false);
      // the left-out file adds no rule; what it might say is unsure: its folder takes the caller's safe answer
      expect(m1.ignored('d1000/x.txt')).toBe(whenUnsure === 'ignored');
      expect(m1.ignored('d1000/y.txt')).toBe(whenUnsure === 'ignored');
      expect(m1.notes).toEqual([ignoreLimitNote(whenUnsure)]);
      const m2 = await loadIgnore(big, { whenUnsure });
      expect(m2.ignored('p0.txt')).toBe(true);
      expect(m2.ignored('p9999.txt')).toBe(true);
      expect(m2.ignored('q.txt')).toBe(false);
      expect(m2.ignored('sub/late.txt')).toBe(whenUnsure === 'ignored');
      expect(m2.ignored('sub/other.txt')).toBe(whenUnsure === 'ignored');
      expect(m2.notes).toEqual([ignoreLimitNote(whenUnsure)]);
    }
  });

  it('gitignore: a pattern over 1,000 characters: the secret check drops it, the bundle treats its folder as ignored', async () => {
    const long = makeTempDir();
    writeIn(long, '.gitignore', 'short.txt\n');
    writeIn(long, 'tools/.gitignore', `${'a'.repeat(1001)}*\nkept.txt\n`);
    const scan = await loadIgnore(long, SCAN);
    expect(scan.ignored(`tools/${'a'.repeat(1001)}b`)).toBe(false);
    expect(scan.ignored('tools/kept.txt')).toBe(true); // the next pattern still counts
    expect(scan.ignored('tools/other.js')).toBe(false);
    expect(scan.notes).toEqual([ignoreSkippedNote(1, 'not-ignored')]);
    const bundle = await loadIgnore(long, BUNDLE);
    expect(bundle.ignored(`tools/${'a'.repeat(1001)}b`)).toBe(true);
    expect(bundle.ignored('tools/other.js')).toBe(true); // everything under tools/ may be what it lists
    expect(bundle.ignored('src/app.js')).toBe(false); // outside its folder: unaffected
    expect(bundle.ignored('short.txt')).toBe(true);
    expect(bundle.notes).toEqual([ignoreSkippedNote(1, 'ignored')]);
    // a long negation is the mirror image: the bundle drops it, the secret check treats its folder as not ignored
    const neg = makeTempDir();
    writeIn(neg, 'gen/.gitignore', `*.js\n!${'b'.repeat(1001)}.js\n`);
    expect((await loadIgnore(neg, BUNDLE)).ignored('gen/a.js')).toBe(true);
    expect((await loadIgnore(neg, SCAN)).ignored('gen/a.js')).toBe(false);
  });

  it('gitignore: a rule with two `**` (a trailing /** aside): the bundle uses a broader one-`**` rule, the secret check drops it', async () => {
    expect(IGNORE_GUARDS).toEqual({ maxTotalChars: 500_000, maxDoubleStars: 1, maxMatchWork: 2_000_000_000 });
    const dir = makeTempDir();
    // `a/**/a/**/b` runs for minutes on a deep path with ignore 7.0.14 (J1 report); it is never used as written
    writeIn(dir, '.gitignore', ['a/**/a/**/b', '**/keep/**', '**/one/**/x.js', 'two**x', '*.log', '!**/save/**/last.log'].join('\n'));
    writeIn(dir, 'pkg/.gitignore', ['deep/**/y.js', '**/z.js', 'w*.js'].join('\n'));
    // a two-`**` rule whose joins are not folder boundaries has no broader rule: its folder is unsure
    writeIn(dir, 'odd/.gitignore', 'q**/r/**s\n');
    const both = async (whenUnsure: WhenUnsure) => loadIgnore(dir, { whenUnsure });
    for (const whenUnsure of BOTH) {
      const m = await both(whenUnsure);
      expect(m.ignored(`${'a/'.repeat(1000)}b`)).toBe(whenUnsure === 'ignored'); // and it returns at once
      expect(m.ignored('x/keep/y.txt')).toBe(true); // leading and trailing: one
      expect(m.ignored('two-and-x')).toBe(true); // `**` inside a name is one `**`
      expect(m.ignored('pkg/deep/q/y.js')).toBe(true); // pkg/deep/**/y.js
      expect(m.ignored('pkg/q/z.js')).toBe(true); // `**/z.js` has a slash, so it becomes pkg/**/z.js: one
      expect(m.ignored('pkg/q/w1.js')).toBe(true); // pkg/**/w*.js: one
      expect(m.ignored('src/app.ts')).toBe(false);
      expect(m.notes).toEqual([ignoreSkippedNote(4, whenUnsure)]);
    }
    const bundle = await both('ignored');
    expect(bundle.ignored('a/q/a/r/b')).toBe(true); // a/**/b
    expect(bundle.ignored('a/q/b')).toBe(true); // the broader rule also takes this one
    expect(bundle.ignored('two/one/q/x.js')).toBe(true); // **/x.js
    expect(bundle.ignored('m/save/n/last.log')).toBe(true); // the negation is dropped: still ignored by *.log
    expect(bundle.ignored('odd/anything.js')).toBe(true);
    const scan = await both('not-ignored');
    expect(scan.ignored('a/q/a/r/b')).toBe(false); // dropped
    expect(scan.ignored('two/one/q/x.js')).toBe(false);
    expect(scan.ignored('m/save/n/last.log')).toBe(false); // the negation becomes !**/last.log
    expect(scan.ignored('m/last.log')).toBe(false); // broader: more files checked
    expect(scan.ignored('m/other.log')).toBe(true);
    expect(scan.ignored('odd/anything.js')).toBe(false);
  });

  it('gitignore: past 500,000 characters in all, the rest of the rules are unsure', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', 'x.tmp\n');
    // 600 patterns of 900 characters in big/: the first 555 fit with the root rule, then the rest of the file is unsure
    writeIn(dir, 'big/.gitignore', Array.from({ length: 600 }, (_, i) => `${String(i).padStart(3, '0')}${'q'.repeat(897)}`).join('\n'));
    writeIn(dir, 'later/.gitignore', 'later.txt\n');
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
      expect(m.ignored('x.tmp')).toBe(true);
      expect(m.ignored('other.js')).toBe(false);
      expect(m.ignored(`big/599${'q'.repeat(897)}`)).toBe(whenUnsure === 'ignored');
      expect(m.ignored('big/other.js')).toBe(whenUnsure === 'ignored');
      expect(m.ignored('later/other.js')).toBe(whenUnsure === 'ignored'); // files after the limit are unsure too
      expect(m.notes).toEqual([ignoreLimitNote(whenUnsure)]);
    }
  });

  it('gitignore: past the matching work budget every later path takes the caller\'s side, one note, the same answers on a second run', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', 'out/\n');
    // budget: one rule × (characters of the path and each folder above it not tested yet, +1 each)
    const paths = ['out/a.js', 'out/b.js', 'out/c.js', 'src/d.js'];
    for (const whenUnsure of BOTH) {
      const answers = async () => {
        const m = await loadIgnore(dir, { whenUnsure, guards: { maxMatchWork: 30 } });
        return { got: paths.map((p) => m.ignored(p)), notes: m.notes };
      };
      // out/a.js: 9 + "out/" 5 = 14; out/b.js: 9 (out/ already tested) = 23; out/c.js: 32 > 30 → stop
      const first = await answers();
      const after = whenUnsure === 'ignored';
      expect(first.got).toEqual([true, true, after, after]);
      expect(first.notes).toEqual([ignoreBudgetNote(whenUnsure)]);
      expect(await answers()).toEqual(first);
    }
    // the real budget is not reached by an ordinary repo
    const m = await loadIgnore(dir, BUNDLE);
    for (let i = 0; i < 1000; i++) expect(m.ignored(`out/f${i}.js`)).toBe(true);
    expect(m.ignored('src/app.js')).toBe(false);
    expect(m.notes).toEqual([]);
  });

  it('gitignore: .git a file (a worktree or submodule) → no .git/info/exclude; .gitignore files still apply', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.git', 'gitdir: /somewhere/else\n');
    writeIn(dir, '.gitignore', 'out/\n');
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
      expect(m.ignored('out/a.js')).toBe(true);
      expect(m.ignored('src/a.js')).toBe(false);
      expect(m.notes).toEqual([]);
    }
  });

  it('gitignore: .git/info/exclude through a symbolic link, or a .gitignore over 1 MB, adds no rules and leaves its folder unsure', async () => {
    const dir = makeTempDir();
    const outside = makeTempDir();
    writeIn(outside, 'exclude', '*.js\n');
    mkdirSync(join(dir, '.git'));
    symlinkSync(outside, join(dir, '.git/info'));
    const scan = await loadIgnore(dir, SCAN);
    expect(scan.ignored('a.js')).toBe(false);
    expect(scan.notes).toEqual([ignoreUnreadableNote(1, 'not-ignored')]);
    const bundle = await loadIgnore(dir, BUNDLE);
    expect(bundle.ignored('a.js')).toBe(true); // info/exclude covers the whole repo
    expect(bundle.notes).toEqual([ignoreUnreadableNote(1, 'ignored')]);

    const big = makeTempDir();
    writeIn(big, '.gitignore', 'x.tmp\n');
    writeIn(big, 'vendored/.gitignore', `${'#'.repeat(1_000_001)}\n`); // over 1 MB: unreadable
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(big, { whenUnsure });
      expect(m.ignored('vendored/a.js')).toBe(whenUnsure === 'ignored');
      expect(m.ignored('src/a.js')).toBe(false);
      expect(m.ignored('x.tmp')).toBe(true);
      expect(m.notes).toEqual([ignoreUnreadableNote(1, whenUnsure)]);
    }
  });

  it('gitignore: a leading UTF-8 byte order mark is skipped, in the root and in a nested .gitignore', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', '\uFEFFout/\n');
    writeIn(dir, 'src/.gitignore', '\uFEFF*.gen.ts\n');
    writeIn(dir, 'docs/.gitignore', '\uFEFF# a comment\n*.draft.md\n');
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
      expect(m.ignored('out/index.html')).toBe(true);
      expect(m.ignored('src/a.gen.ts')).toBe(true);
      expect(m.ignored('docs/a.draft.md')).toBe(true);
      expect(m.ignored('docs/# a comment')).toBe(false); // the first line stays a comment
      expect(m.notes).toEqual([]);
    }
  });

  it('gitignore: matching is case-sensitive unless .git/config sets ignorecase = true', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', 'out/\n');
    writeIn(dir, '.git/config', '[core]\n\tbare = false\n');
    expect((await loadIgnore(dir, BUNDLE)).ignored('Out/a.js')).toBe(false);
    writeIn(dir, '.git/config', '[core]\n\tignorecase = true\n');
    expect((await loadIgnore(dir, BUNDLE)).ignored('Out/a.js')).toBe(true);
    expect((await loadIgnore(dir, SCAN)).ignored('OUT/a.js')).toBe(true);
  });

  it('gitignore: folder names with glob characters are matched literally', async () => {
    const dir = makeTempDir();
    writeIn(dir, '[ab]/.gitignore', 'x.txt\n');
    writeIn(dir, 'st*r/.gitignore', '/y.txt\n');
    writeIn(dir, '!bang/.gitignore', 'z.txt\n');
    const m = await loadIgnore(dir, BUNDLE);
    expect(m.ignored('[ab]/x.txt')).toBe(true);
    expect(m.ignored('a/x.txt')).toBe(false);
    expect(m.ignored('st*r/y.txt')).toBe(true);
    expect(m.ignored('stXr/y.txt')).toBe(false);
    expect(m.ignored('!bang/z.txt')).toBe(true);
    expect(m.ignored('bang/z.txt')).toBe(false);
  });

  it('gitignore: a path the matcher cannot take (empty, absolute, ..) is not ignored and never throws', async () => {
    const dir = makeTempDir();
    writeIn(dir, '.gitignore', '*\n');
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
      for (const p of ['', '/etc/passwd', '../x', './x']) expect(m.ignored(p), p).toBe(false);
    }
  });

  it('gitignore: the same answers as `git check-ignore` (run at setup) on nested rules, re-includes, folder rules and a byte order mark', async () => {
    const dir = makeTempDir();
    git(dir, ['init', '-q']);
    writeIn(dir, '.git/info/exclude', 'scratch/\n');
    writeIn(dir, '.gitignore', [
      'build-out/', '*.tmp', '!important.tmp', '/root-only.txt', 'logs/**/*.log', 'docs/*.html', '\\#hash.txt', 'trailing.txt   ',
      'cache', 'vendor-x/', '!vendor-x/keep.js', 'a/**/b.txt', '**/deep.txt', 'reinc/', '',
    ].join('\n'));
    writeIn(dir, 'pkg/.gitignore', ['*.gen.ts', '/local.txt', 'sub/only.txt', '!*.tmp', 'cache', '!reinc/', '\\#nested.txt'].join('\n'));
    writeIn(dir, 'pkg/sub/.gitignore', ['!keep.gen.ts', 'z*'].join('\n'));
    writeIn(dir, 'bom/.gitignore', '\uFEFF*.gen.ts\n/top.txt\n');
    const paths = [
      'build-out/a.js', 'pkg/build-out/a.js', 'x.tmp', 'important.tmp', 'pkg/x.tmp', 'root-only.txt', 'pkg/root-only.txt',
      'logs/a.log', 'logs/x/y/a.log', 'logs/a.txt', 'docs/a.html', 'docs/x/a.html', '#hash.txt', 'trailing.txt', 'cache',
      'other/cache/x.js', 'pkg/cache', 'vendor-x/keep.js', 'vendor-x/other.js', 'a/b.txt', 'a/x/y/b.txt', 'q/deep.txt', 'deep.txt',
      'pkg/a.gen.ts', 'pkg/sub/a.gen.ts', 'pkg/sub/keep.gen.ts', 'pkg/local.txt', 'pkg/x/local.txt', 'pkg/sub/only.txt',
      'pkg/sub/zed.js', 'pkg/zed.js', 'scratch/a', 'pkg/scratch/a', 'reinc/a.js', 'pkg/reinc/a.js', 'src/index.ts',
      'pkg/#nested.txt', 'bom/a.gen.ts', 'bom/x/b.gen.ts', 'bom/top.txt', 'bom/x/top.txt',
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
    expect(byGit.has('bom/a.gen.ts')).toBe(true);
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
      for (const p of paths) expect(m.ignored(p), p).toBe(byGit.has(p));
      expect(m.notes).toEqual([]);
    }
  });

  it('gitignore: no .gitignore anywhere → nothing ignored', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'a.js', '');
    for (const whenUnsure of BOTH) {
      const m = await loadIgnore(dir, { whenUnsure });
      expect(m.ignored('a.js')).toBe(false);
      expect(m.notes).toEqual([]);
    }
  });
});
