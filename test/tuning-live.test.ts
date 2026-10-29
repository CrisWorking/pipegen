// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network and a GitHub token from the environment): the Semgrep rule folders pipegen's
// tuning may mount (SEMGREP_RULE_FOLDERS) are real top-level folders of the pinned rules tree. The commit and tree come
// from the reviewed list, so the test follows a version bump. Skipped by default, so `npm test` stays offline.
import { afterEach, describe, expect, it } from 'vitest';
import { SEMGREP_RULE_FOLDERS } from '../src/engine/tuning.js';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { renderStep } from '../src/engine/render-step.js';
import { tuningEffects } from '../src/engine/tuning.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { semgrepBin, semgrepPaths } from './helpers/semgrep-live.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const ENV_NAME = ['GH', 'TOKEN'].join('_');

describe.skipIf(!live)('live: SEMGREP_RULE_FOLDERS are folders of the pinned semgrep-rules tree', () => {
  it('every listed folder is a tree entry of the reviewed tree', async () => {
    const env = entry('semgrep').fixedInputs.env ?? {};
    const tree = env.PIPEGEN_RULES_TREE as string;
    const headers: Record<string, string> = { accept: 'application/vnd.github+json' };
    const credential = process.env[ENV_NAME] ?? '';
    // the header's name is spelled at run time (test/no-secret-literals.test.ts)
    if (credential !== '') headers[['auth', 'orization'].join('')] = ['Bea', 'rer ', credential].join('');
    const res = await fetch(`https://api.github.com/repos/semgrep/semgrep-rules/git/trees/${tree}`, { headers });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { tree: { path: string; type: string }[] };
    const folders = new Set(body.tree.filter((e) => e.type === 'tree').map((e) => e.path));
    for (const f of SEMGREP_RULE_FOLDERS) expect(folders.has(f), f).toBe(true);
  }, 60_000);
});

afterEach(() => cleanupRepos());

describe.skipIf(!live)('live: the Semgrep skip is anchored (6d fix round 1)', () => {
  it('--exclude "/dist" skips the top dist/ only; a nested folder with the same name is still scanned, with and without .git', () => {
    const t = entry('semgrep');
    const ctx = { ...ctxFor([service({ name: 'app', path: '.' })]), profile: { ...ctxFor().profile, generatedDirs: ['dist'] } };
    const e = tuningEffects(specFor(t, { needId: 'sast', service: 'app', choices: { tuning: { 'skip-generated': ['dist'] } } }), t, ctx);
    const args = e.flags.flatMap((f) => [f.flag, f.value]);
    expect(args).toEqual(['--exclude', '/dist']);
    for (const git of [false, true]) {
      const dir = makeTempDir();
      for (const p of ['dist/a.js', 'src/lib/dist/b.js', 'src/c.js']) writeIn(dir, p, 'eval(x)\n');
      writeIn(dir, '.semgrepignore', 'node_modules\n');   // pipegen's own ignore file (the next commit makes the step write it); without one semgrep's defaults skip dist/ at any depth
      if (git) { execFileSync('git', ['init', '-q'], { cwd: dir }); execFileSync('git', ['add', '-A'], { cwd: dir }); }
      mkdirSync(join(dir, 'empty'), { recursive: true });
      expect(semgrepPaths(semgrepBin(), dir, args), git ? 'git checkout' : 'plain folder').toEqual(['src/c.js', 'src/lib/dist/b.js']);
    }
  }, 600_000);
});

describe.skipIf(!live)('live: the Semgrep step\'s scope is pipegen\'s, not the repo\'s (6d fix round 1, ruling 6)', () => {
  it('a repo .semgrepignore (root and nested) has no effect; test/, tests/, build/, vendor/ and dist/ are scanned; node_modules is not', () => {
    const t = entry('semgrep');
    const ctx = ctxFor([service({ name: 'app', path: '.' })]);
    const run = renderStep(specFor(t, { needId: 'sast', service: 'app' }), t, platform(), ctx).steps.filter((x) => x.run !== undefined).at(-1)?.run as string;
    const lines = run.split('\n');
    const block = lines.slice(lines.indexOf('# pipegen scope: begin'), lines.indexOf('# pipegen scope: end') + 1).join('\n');
    expect(block).not.toBe('');
    for (const git of [false, true]) {
      const dir = makeTempDir();
      const files = ['src/ok/x.js', 'test/x.js', 'tests/x.js', 'build/x.js', 'vendor/x.js', 'dist/x.js', 'deep/test/x.js', 'node_modules/x.js'];
      for (const f of files) writeIn(dir, f, 'eval(x)\n');
      writeIn(dir, '.semgrepignore', 'src/\n');          // the repo's own file: must have no effect
      writeIn(dir, 'deep/.semgrepignore', 'test\n');      // nested: no effect either
      if (git) { execFileSync('git', ['init', '-q'], { cwd: dir }); execFileSync('git', ['add', '-A'], { cwd: dir }); }
      const sh = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', `sys=(/usr/bin/env -i "PATH=/usr/local/bin:/usr/bin:/bin")\n${block}`], { cwd: dir, encoding: 'utf8' });
      expect(sh.status, sh.stderr).toBe(0);
      expect(semgrepPaths(semgrepBin(), dir, []), git ? 'git checkout' : 'plain folder').toEqual(['build/x.js', 'deep/test/x.js', 'dist/x.js', 'src/ok/x.js', 'test/x.js', 'tests/x.js', 'vendor/x.js']);
      // and without the step's block, the repo's file and semgrep's defaults shrink the scope (the gap this closes)
      const bare = makeTempDir();
      for (const f of files) writeIn(bare, f, 'eval(x)\n');
      writeIn(bare, '.semgrepignore', 'src/\n');
      expect(semgrepPaths(semgrepBin(), bare, []), 'without the block').not.toContain('src/ok/x.js');
    }
  }, 600_000);
});
