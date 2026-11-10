// PL-E6: commitFiles takes deletes (a tree entry with sha null); a delete of a path the base tree doesn't hold is refused.
import type { Octokit } from '@octokit/rest';
import { describe, expect, it } from 'vitest';
import { commitFiles, DeliverError } from '../src/deliver/git-data.js';
import { newRateBudget } from '../src/engine/github-rate.js';

const SHA = 'a'.repeat(40);
const sha = (n: number) => String(n).repeat(40).slice(0, 40);
const R = { owner: 'acme', repo: 'shop' };
const clock = () => ({ budget: newRateBudget(), sleep: async () => {}, now: () => 0 });
const fake = (tree: { path: string; type?: string }[], over: Record<string, unknown> = {}) => {
  const calls: { route: string; params: Record<string, unknown> }[] = [];
  const gh = { request: async (route: string, params: Record<string, unknown>) => {
    calls.push({ route, params });
    if (route === 'GET /repos/{owner}/{repo}/git/trees/{tree_sha}') return { status: 200, data: { truncated: false, tree: tree.map((e) => ({ path: e.path, sha: SHA, mode: '100644', type: e.type ?? 'blob' })), ...over }, headers: {} };
    if (route === 'POST /repos/{owner}/{repo}/git/trees') return { status: 201, data: { sha: sha(1) }, headers: {} };
    if (route === 'POST /repos/{owner}/{repo}/git/commits') return { status: 201, data: { sha: sha(2) }, headers: {} };
    throw new Error(`unexpected ${route}`);
  } } as unknown as Octokit;
  return { gh, calls };
};
const writes = (calls: { route: string }[]) => calls.filter((c) => c.route.startsWith('POST'));

describe('PL-E6 commitFiles takes deletes', () => {
  it('commitFiles: delete → tree entry sha null', async () => {
    const f = fake([{ path: 'old.yml' }, { path: 'keep.md' }]);
    const out = await commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: 'a.txt', content: 'x\n', mode: '100644' }, { path: 'old.yml', sha: null }], message: 'm' }, clock());
    expect(out).toEqual({ commit: sha(2), tree: sha(1) });
    expect(f.calls.find((c) => c.route === 'POST /repos/{owner}/{repo}/git/trees')?.params).toEqual({ owner: 'acme', repo: 'shop', base_tree: SHA, tree: [
      { path: 'a.txt', mode: '100644', type: 'blob', content: 'x\n' },
      { path: 'old.yml', mode: '100644', type: 'blob', sha: null },
    ] });
  });

  it('commitFiles: delete of a missing path → refused', async () => {
    const f = fake([{ path: 'keep.md' }, { path: 'dir', type: 'tree' }]);
    for (const p of ['old.yml', 'dir']) {
      await expect(commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: p, sha: null }], message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
    }
    expect(writes(f.calls)).toEqual([]);
    // a truncated file list is not proof the path is there
    const t = fake([{ path: 'old.yml' }], { truncated: true });
    await expect(commitFiles(t.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: 'old.yml', sha: null }], message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
    expect(writes(t.calls)).toEqual([]);
  });

  it('commitFiles: an empty list → refused, nothing sent', async () => {
    const f = fake([]);
    await expect(commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [], message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
    expect(f.calls).toEqual([]);
  });

  it('commitFiles: writes only → no tree read (deliver callers unchanged)', async () => {
    const f = fake([]);
    await commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: 'a.txt', content: 'x', mode: '100644' }], message: 'm' }, clock());
    expect(f.calls.map((c) => c.route)).toEqual(['POST /repos/{owner}/{repo}/git/trees', 'POST /repos/{owner}/{repo}/git/commits']);
  });
  it('commitFiles: two deletes, the second missing → refused, nothing sent', async () => {
    const f = fake([{ path: 'a.yml' }]);
    await expect(commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: 'a.yml', sha: null }, { path: 'b.yml', sha: null }], message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
    expect(writes(f.calls)).toEqual([]);
  });

  it('commitFiles: a delete matches the path exactly (case too) → refused, nothing sent', async () => {
    const f = fake([{ path: '.github/workflows/pipegen.yml' }]);
    await expect(commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: '.github/workflows/Pipegen.yml', sha: null }], message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
    expect(writes(f.calls)).toEqual([]);
  });

  it('commitFiles: only a file (blob) is removed, never a submodule (commit) → refused, nothing sent', async () => {
    const f = fake([{ path: 'vendor/x', type: 'commit' }]);
    await expect(commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files: [{ path: 'vendor/x', sha: null }], message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
    expect(writes(f.calls)).toEqual([]);
  });

  it('commitFiles: a path twice (written and removed, or written twice) → refused, nothing sent', async () => {
    for (const files of [
      [{ path: 'a.yml', content: 'x', mode: '100644' }, { path: 'a.yml', sha: null }],
      [{ path: 'a.yml', content: 'x', mode: '100644' }, { path: 'a.yml', content: 'y', mode: '100644' }],
    ] as const) {
      const f = fake([{ path: 'a.yml' }]);
      await expect(commitFiles(f.gh, R, { parent: SHA, baseTree: SHA, files, message: 'm' }, clock())).rejects.toBeInstanceOf(DeliverError);
      expect(f.calls).toEqual([]);
    }
  });
});
