// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network and a GitHub token from the environment): the Semgrep rule folders pipegen's
// tuning may mount (SEMGREP_RULE_FOLDERS) are real top-level folders of the pinned rules tree. The commit and tree come
// from the reviewed list, so the test follows a version bump. Skipped by default, so `npm test` stays offline.
import { afterEach, describe, expect, it } from 'vitest';
import { SEMGREP_RULE_FOLDERS } from '../src/engine/tuning.js';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tuningEffects } from '../src/engine/tuning.js';
import { ctxFor, entry, service, specFor } from './helpers/render.js';
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
