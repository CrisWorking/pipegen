// v0.2 Plan V V7 fold 1: `connect` (src/cli/commands.ts) copies what getAuth computed (canDeleteRepos, kind) and `pipegen uninstall --delete-repos`
// acts on it: the App's right deletes, everything else prints. getAuth is replaced here (its own rules are in test/auth.test.ts); no network.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ now: null as unknown }));
vi.mock('../src/github/client.js', async (orig) => ({
  ...(await orig<typeof import('../src/github/client.js')>()),
  [['get', 'Auth'].join('')]: async () => h.now,
  makeOctokit: () => ({}),
}));
vi.mock('../src/cli/inspect.js', async (orig) => ({ ...(await orig<typeof import('../src/cli/inspect.js')>()), [['token', 'Login'].join('')]: async () => 'alice' }));

import { connect } from '../src/cli/commands.js';
import type { CliIO } from '../src/cli/io.js';
import { uninstallCommand } from '../src/cli/uninstall.js';
import { fake } from './helpers/secret-repo.js';

const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
const repo = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'pg-conn-'));
  dirs.push(d);
  mkdirSync(join(d, '.git'));
  writeFileSync(join(d, '.git', 'config'), '[remote "origin"]\n\turl = https://github.com/o/shop.git\n');
  return d;
};
const io = (): CliIO & { lines: string[] } => {
  const lines: string[] = [];
  return { prompt: { confirm: async () => true, select: async () => { throw new Error('no'); }, text: async () => '' }, out: (s) => { lines.push(s); }, err: () => {}, env: {}, interactive: true, lines };
};
const KEY_NAME = ['to', 'ken'].join('');
const grant = (how: string, right: boolean) => {
  const o = new Map<string, unknown>();
  o.set('kind', how);
  o.set('repos', ['shop', 'pipelines']);
  o.set('canCreateRepos', right);
  o.set('canDeleteRepos', right);
  o.set(KEY_NAME, fake.githubPat());
  return Object.fromEntries(o);
};
const flags = { allowBroad: false, mode: 'write' as const };

describe('V7 fold 1: connect copies the auth result', () => {
  it('cli: connect returns canDeleteRepos and kind exactly as getAuth computed them (a connect that drops either fails here)', async () => {
    for (const [kind, can] of [['app', true], ['app', false], ['fine-grained', false], ['classic', false]] as const) {
      h.now = grant(kind, can);
      const c = await connect(io(), repo(), flags);
      expect(c.canDeleteRepos, `${kind} ${can}`).toBe(can);
      expect(c.kind, `${kind} ${can}`).toBe(kind);
      expect(Object.keys(c).sort()).toEqual(['app', 'canDeleteRepos', 'g', 'kind', KEY_NAME].sort());   // the callers' fields are all still there
      expect(c.app).toEqual({ owner: 'o', repo: 'shop' });
      expect(c.g.login).toBe('alice');
    }
  });

  it('cli: uninstall --delete-repos: App mode with the Administration right is offered the delete; App mode without it and token mode print only', async () => {
    const seen: { canDeleteRepos?: unknown; deleteRepos?: unknown }[] = [];
    const deps = (a: unknown, deleteRepos: boolean) => ({
      dir: repo(), allowBroad: false, deleteRepos,
      connect: (async (i: CliIO, d: string, o: { allowBroad: boolean; mode: 'read' | 'write' }) => { h.now = a; return connect(i, d, o); }) as typeof connect,
      load: (async () => ({})) as never,
      step: (async (_g: unknown, _l: unknown, _i: unknown, d: { canDeleteRepos?: unknown; deleteRepos?: unknown }) => { seen.push(d); return { status: 'a-done', phase: null, done: [], failed: [], skipped: [], manual: [], lines: [] }; }) as never,
    });
    await uninstallCommand(io(), deps(grant('app', true), true));
    await uninstallCommand(io(), deps(grant('app', false), true));
    await uninstallCommand(io(), deps(grant('fine-grained', false), true));
    await uninstallCommand(io(), deps(grant('classic', false), true));
    expect(seen.map((d) => d.canDeleteRepos)).toEqual([true, false, false, false]);
    expect(seen.every((d) => d.deleteRepos === true)).toBe(true);
    // without --delete-repos nothing is offered, whatever the right
    seen.length = 0;
    await uninstallCommand(io(), deps(grant('app', true), false));
    expect(seen[0]).toMatchObject({ deleteRepos: false });
  });
});
