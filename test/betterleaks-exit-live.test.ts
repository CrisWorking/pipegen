// LIVE (PIPEGEN_LIVE_TESTS=1; downloads the pinned betterleaks once, like betterleaks-live.test.ts): C0a fix round 1.
// The reviewed argv (`--exit-code 10`) against the REAL betterleaks 1.9.0: a clean tree exits 0, a planted leak exits 10 (a finding).
// The reviewed entry scans in `dir` mode (C1b fix round 1), which never reads git objects, so the "partial scan" case runs the same flags in
// `git` mode: the commit-range scan of the PR's own commits (Plan C final review Important 2, sub-task C9) is a `git` scan. There a history
// that cannot be read to the end (a deleted object: "partial scan completed") exits 1, the error exit, never 0 and never the finding exit 10
// (final review minor 4: in `dir` mode this case could not fail).
import { execFileSync, spawnSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { entry } from './helpers/render.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1' && process.platform !== 'win32';
const shopify = (): string => 'shp' + 'at_' + '0123456789abcdef'.repeat(2);   // built at run time (no secret-like literal in test/)

const LABEL = 'shopify_value';
let bin = '';
const git = (dir: string, ...args: string[]): string => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' }).trim();
function repo(files: string[]): string {
  const dir = makeTempDir();
  git(dir, 'init', '-q');
  files.forEach((content, i) => { writeIn(dir, `f${i}.txt`, content); git(dir, 'add', '.'); git(dir, 'commit', '-q', '-m', `c${i}`); });
  return dir;
}
/** The reviewed command of the entry (everything after the exe), with the pinned config written next to the repo; `git` swaps the subcommand (the range scan's mode). */
function scan(dir: string, mode: 'dir' | 'git' = 'dir'): number {
  const t = entry('betterleaks');
  const cfg = join(makeTempDir(), 'betterleaks.toml');
  writeFileSync(cfg, t.fixedInputs.config?.content ?? '');
  const reviewed = (t.step.cli?.command ?? []).slice(1, -1);
  expect(reviewed[0]).toBe('dir');
  const argv = [mode, ...reviewed.slice(1), '--config', cfg, '.'];
  return spawnSync(bin, argv, { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' } }).status ?? -1;
}

describe.skipIf(!live)('live: betterleaks with --exit-code 10 (C0a fix round 1)', () => {
  beforeAll(async () => { bin = await ensurePinnedBinary('betterleaks'); }, 600_000);
  afterEach(cleanupRepos);

  it('live: a clean tree exits 0, a planted leak exits 10 (the policy\'s findingsExit); in git mode (the range scan) a partial scan exits 1', () => {
    expect(ARGV_POLICIES.betterleaks?.findingsExit).toEqual([10]);
    expect(scan(repo(['one\n', 'two\n', 'three\n']))).toBe(0);
    expect(scan(repo(['one\n', 'two\n', `${LABEL} = "${shopify()}"\n`]))).toBe(10);
    // git mode reads the history: the same clean and leaking repos, then one with a deleted object
    expect(scan(repo(['one\n', 'two\n', 'three\n']), 'git')).toBe(0);
    expect(scan(repo(['one\n', `${LABEL} = "${shopify()}"\n`, 'three\n']), 'git')).toBe(10);
    const broken = repo(['one\n', 'two\n', 'three\n']);
    const blob = git(broken, 'rev-parse', 'HEAD~1:f1.txt');
    rmSync(join(broken, '.git', 'objects', blob.slice(0, 2), blob.slice(2)));
    expect(scan(broken, 'git')).toBe(1);
    expect(scan(broken), 'dir mode never reads the object').toBe(0);
  }, 120_000);
});
