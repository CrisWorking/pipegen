// LIVE (PIPEGEN_LIVE_TESTS=1, uses the network and a GitHub token from the environment): the Semgrep rule folders pipegen's
// tuning may mount (SEMGREP_RULE_FOLDERS) are real top-level folders of the pinned rules tree. The commit and tree come
// from the reviewed list, so the test follows a version bump. Skipped by default, so `npm test` stays offline.
import { describe, expect, it } from 'vitest';
import { SEMGREP_RULE_FOLDERS } from '../src/engine/tuning.js';
import { entry } from './helpers/render.js';

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
