// v0.2 Plan P PL-F1: every stop that says "run pipegen again" names the command that raised it (setup run -> `npx pipegen run`, finish ->
// `npx pipegen finish`, update, uninstall, cleanup, resume). deliver.ts and cli/run.ts already say it their own way (G17C row 36).
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cleanupCommand } from '../src/cli/cleanup.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { makeOctokit } from '../src/github/client.js';
import { readWriters } from '../src/github/lock-probes.js';
import { StateStore } from '../src/proof/state.js';
import { pipegenCmd } from '../src/util/next-step.js';
import type { CliIO } from '../src/cli/io.js';
import { quietIo } from './helpers/scratch-secrets.js';
import { fakeFetch, type Reply } from './helpers/fake-http.js';
import { fake } from './helpers/secret-repo.js';

const TK = ['to', 'ken'].join('');
const SRC = join(__dirname, '..', 'src');
const SKIP = new Set(['deliver/deliver.ts', 'cli/run.ts']);
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? sources(p) : p.endsWith('.ts') ? [p] : [];
  });
}

describe('PL-F1: no bare "run pipegen again"', () => {
  it('source scan: no "run pipegen again" outside deliver.ts and cli/run.ts', () => {
    const bad: string[] = [];
    for (const f of sources(SRC)) {
      const rel = relative(SRC, f).split('\\').join('/');
      if (SKIP.has(rel)) continue;
      readFileSync(f, 'utf8').split('\n').forEach((line, n) => { if (/run\s+pipegen\s+again/i.test(line)) bad.push(`${rel}:${n + 1}`); });
    }
    expect(bad).toEqual([]);
  });

  it('pipegenCmd: setup run and no command name `npx pipegen run`; any other command is named', () => {
    expect(pipegenCmd()).toBe('`npx pipegen run`');
    expect(pipegenCmd('run')).toBe('`npx pipegen run`');
    expect(pipegenCmd('finish')).toBe('`npx pipegen finish`');
    expect(pipegenCmd('uninstall')).toBe('`npx pipegen uninstall`');
  });
});

describe('PL-F1: shared code takes the command from its caller', () => {
  const APP = { owner: 'o', repo: 'r' };
  const lease = async (command: 'run' | 'update' | 'cleanup') => {
    const home = mkdtempSync(join(tmpdir(), 'pl-f1-'));
    const s = await StateStore.openForLease(APP, { home, env: {} });
    writeFileSync(join(s.dir, 'lease.json'), JSON.stringify({ pid: process.ppid, host: hostname(), runId: 'x', [TK]: 't', command: 'finish' }), { mode: 0o600 });
    try { s.acquireLease('r', command); } catch (e) { return (e as Error).message; }
    return '';
  };
  it('lease stop: names the command that tried to take it', async () => {
    expect(await lease('update')).toContain('then run `npx pipegen update` again.');
    expect(await lease('cleanup')).toContain('then run `npx pipegen cleanup` again.');
    expect(await lease('run')).toContain('then run `npx pipegen run` again.');
  });

  const empty: Reply = { body: [] };
  it('readWriters: nobody who can write -> the stop names the caller command', async () => {
    const f = fakeFetch({ 'GET https://api.github.com/repos/o/r/collaborators': empty });
    const gh = makeOctokit(fake.githubPat(), { fetch: f.fetch });
    const clock = { budget: newRateBudget(), sleep: async () => {} };
    await expect(readWriters(gh, 'o', 'r', 'pipelines', clock)).rejects.toThrow(/then run `npx pipegen run` again\./);
    await expect(readWriters(gh, 'o', 'r', 'pipelines', clock, 'finish')).rejects.toThrow(/then run `npx pipegen finish` again\./);
  });

  it('cleanup: a state file that is a symbolic link stops with `npx pipegen cleanup`, not the setup run', async () => {
    const home = mkdtempSync(join(tmpdir(), 'pl-f1-'));
    const s = await StateStore.openForLease(APP, { home, env: {} });
    symlinkSync(join(home, 'nowhere'), s.path);
    const repo = mkdtempSync(join(tmpdir(), 'pl-f1-'));
    mkdirSync(join(repo, '.git'));
    writeFileSync(join(repo, '.git', 'config'), '[remote "origin"]\n\turl = https://github.com/o/r.git\n');
    const errs: string[] = [];
    const io = { ...quietIo, out: () => {}, err: (x: string) => errs.push(x), env: { XDG_CACHE_HOME: join(home, '.cache') }, cwd: repo } as CliIO;
    expect(await cleanupCommand(repo, io, { allowBroad: false }, { home })).toBe(1);
    expect(errs.join('\n')).toContain('then run `npx pipegen cleanup` again.');
  });
});
