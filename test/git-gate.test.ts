// Plan E E0c, E0b carry: the transport checks the sticky interrupting() gate before every push, again right before git
// starts, and kills a push in flight once a stop begins. interrupting() is replaced here (a real stop would end the worker).
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPushRepo, gitPush, GitTransportError, runGit, type PushRequest } from '../src/proof/git.js';
import { startGitHttp } from './helpers/git-http.js';
import { makeGitRecorder, REAL_GIT } from './helpers/git-recorder.js';

const gate = vi.hoisted(() => ({ on: false, calls: 0, onAfter: Infinity }));
vi.mock('../src/util/exit-hooks.js', async (orig) => ({
  ...(await orig<typeof import('../src/util/exit-hooks.js')>()),
  interrupting: () => ++gate.calls > gate.onAfter || gate.on,
}));

// The token is built at run time (no-secret-literals): token-shaped, but no GitHub prefix, so only hidden when it is passed.
const cred = (value: string) => ({ ['tok' + 'en']: value }) as Pick<PushRequest, 'token'>;
const { token } = cred(['pipegenE0cTest', 'Token_0123456789', 'abcdefXYZ'].join(''));
const root = mkdtempSync(join(tmpdir(), 'pg-e0c-gate-'));
const recorder = makeGitRecorder(root);
const savedEnv = { ...process.env };
let tmp: string;
let n = 0;

const text = (b: Uint8Array) => Buffer.from(b).toString('utf8').trim();
async function pushRepoWithCommit() {
  const handle = await createPushRepo();
  const blob = text(await runGit(handle, ['hash-object', '-w', '--stdin'], { input: 'hello\n' }));
  const tree = text(await runGit(handle, ['mktree'], { input: `100644 blob ${blob}\thello.txt\n` }));
  const sha = text(await runGit(handle, ['commit-tree', tree, '-m', 'base'], { identity: { name: 'pipegen', email: 'pipegen@example.invalid' } }));
  return { handle, sha, remove: handle.remove };
}
const req = (m: Awaited<ReturnType<typeof pushRepoWithCommit>>): PushRequest =>
  ({ repo: m.handle, url: 'https://github.com/acme/pipegen-proof-shop.git', owner: 'acme', appRepo: 'shop', ...cred(token), refs: [{ sha: m.sha, branch: 'main' }] });
function serverRoot(): string {
  const srv = join(root, `srv-${++n}`);
  mkdirSync(srv);
  execFileSync(REAL_GIT, ['init', '-q', '--bare', 'app.git'], { cwd: srv });
  return srv;
}
const routed = (port: number, m: Awaited<ReturnType<typeof pushRepoWithCommit>>) => {
  recorder.route(port);
  return gitPush(req(m));
};
const pushes = () => recorder.calls().filter((c) => c.argv.includes('push'));

beforeEach(() => {
  recorder.clear();
  gate.on = false;
  gate.calls = 0;
  gate.onAfter = Infinity;
  tmp = join(root, `tmp-${++n}`);
  mkdirSync(tmp);
  process.env.PATH = `${recorder.bin}:${savedEnv.PATH ?? ''}`;
  process.env.TMPDIR = tmp;
});
afterEach(() => {
  for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
  Object.assign(process.env, savedEnv);
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('git transport and the interrupt gate (E0c, E0b carry)', () => {
  it('git: no push starts once interrupting() is set (sticky gate)', async () => {
    const repo = await pushRepoWithCommit();
    recorder.clear();
    gate.on = true;
    await expect(gitPush(req(repo))).rejects.toThrow(/stopping/);
    expect(recorder.calls()).toEqual([]);
    gate.on = false;
    await repo.remove();
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('git: the gate is checked again right before git push starts', async () => {
    const srv = serverRoot();
    const s = await startGitHttp(srv, { token });
    const repo = await pushRepoWithCommit();
    recorder.clear();
    gate.calls = 0;
    gate.onAfter = 1;   // the entry check passes; the check right before the push sees the stop
    const err = await routed(s.port, repo).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GitTransportError);
    expect((err as Error).message).toMatch(/stopping/);
    expect(gate.calls).toBeGreaterThanOrEqual(2);
    expect(pushes()).toEqual([]);
    expect(s.requests).toEqual([]);
    gate.onAfter = Infinity;
    await repo.remove();
    await s.close();
    expect(readdirSync(tmp)).toEqual([]);
  });

  it('git: a push in flight is killed when a stop begins', async () => {
    const srv = serverRoot();
    const s = await startGitHttp(srv, { token, holdPushMs: 3000 });
    const repo = await pushRepoWithCommit();
    const started = Date.now();
    const p = routed(s.port, repo).catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 500));
    expect(pushes()).toHaveLength(1);
    gate.on = true;
    const err = await p;
    expect(err).toBeInstanceOf(GitTransportError);
    expect((err as Error).message).toMatch(/stopping/);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(readdirSync(tmp).filter((f) => f.startsWith('pipegen-git-'))).toEqual([]);
    gate.on = false;
    await repo.remove();
    await s.close();
  });
});
