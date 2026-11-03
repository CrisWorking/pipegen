// Plan E E0c (rulings B6 and S4; DECISIONS #111): the git transport. Every push is the real gitPush to a github.com URL.
// A `git` wrapper first on PATH (test/helpers/git-recorder.ts) records each call's argv, environment and working dir as
// pipegen started it, then either refuses (exit 97: nothing reaches github.com) or, when a test routes it, swaps the
// github.com URL for a loopback smart-HTTP server (test/helpers/git-http.ts) serving local bare repos, and maps git's
// 127.0.0.1 prompts back to the github.com ones for pipegen's own askpass script. Nothing touches the network.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  checkPushUrl, createPushRepo, gitEnv, gitPush, GitTransportError, HARDENED_CONFIG, isDirty, pushUrl, runGit, shownGitOutput,
  type PushRepoHandle, type PushRequest,
} from '../src/proof/git.js';
import { runExitHooks } from '../src/util/exit-hooks.js';
import { startGitHttp, type GitHttpServer } from './helpers/git-http.js';
import { makeGitRecorder, REAL_GIT } from './helpers/git-recorder.js';

// The token is built at run time (no-secret-literals): token-shaped, but no GitHub prefix, so only hidden when it is passed.
const cred = (value: string) => ({ ['tok' + 'en']: value }) as Pick<PushRequest, 'token'>;
const { token } = cred(['pipegenE0cTest', 'Token_0123456789', 'abcdefXYZ'].join(''));
const HARDENED = ['-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'http.followRedirects=false'];
const SHA = 'a'.repeat(40);
const ASKPASS_VARS = ['GIT_ASKPASS', 'PIPEGEN_GIT_TOKEN'];
const poisonValue = ['not', 'inherited'].join('-');

const root = mkdtempSync(join(tmpdir(), 'pg-e0c-'));
const recorder = makeGitRecorder(root);
const savedEnv = { ...process.env };
let tmp: string;
let servers: GitHttpServer[] = [];
let n = 0;

const git = (cwd: string, ...args: string[]) => execFileSync(REAL_GIT, args, { cwd, encoding: 'utf8', env: { ...savedEnv, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } }).trim();
const text = (b: Uint8Array) => Buffer.from(b).toString('utf8').trim();
const fresh = (name: string) => {
  const d = join(root, `${name}-${++n}`);
  mkdirSync(d, { recursive: true });
  return d;
};
/** A server root with one empty bare repo, app.git. */
function serverRoot(): string {
  const srv = fresh('srv');
  git(srv, 'init', '-q', '--bare', 'app.git');
  return srv;
}
async function serve(srv: string, opts: Parameters<typeof startGitHttp>[1] = {}): Promise<GitHttpServer> {
  const s = await startGitHttp(srv, opts);
  servers.push(s);
  return s;
}
interface Made { handle: PushRepoHandle; gitDir: string; sha: string; remove: () => Promise<void> }
/** A push repo holding one commit with hello.txt. */
async function pushRepoWithCommit(): Promise<Made> {
  const handle = await createPushRepo();
  const blob = text(await runGit(handle, ['hash-object', '-w', '--stdin'], { input: 'hello\n' }));
  const tree = text(await runGit(handle, ['mktree'], { input: `100644 blob ${blob}\thello.txt\n` }));
  const sha = text(await runGit(handle, ['commit-tree', tree, '-m', 'base'], { identity: { name: 'pipegen', email: 'pipegen@example.invalid' } }));
  return { handle, gitDir: handle.gitDir, sha, remove: handle.remove };
}
const SCRATCH_URL = 'https://github.com/acme/pipegen-proof-shop.git';
/** A scratch push of `m`'s commit to main, changed by `extra`. */
const req = (m: Made, extra: Partial<PushRequest> = {}): PushRequest => ({ repo: m.handle, url: SCRATCH_URL, owner: 'acme', appRepo: 'shop', ...cred(token), refs: [{ sha: m.sha, branch: 'main' }], ...extra });
/** gitPush with the recorder routing github.com to the loopback server on `port`. */
const routedPush = (port: number, r: PushRequest) => {
  recorder.route(port);
  return gitPush(r);
};
const leftovers = () => readdirSync(tmp);

beforeEach(() => {
  recorder.clear();
  tmp = fresh('tmp');
  process.env.PATH = `${recorder.bin}:${savedEnv.PATH ?? ''}`;
  process.env.TMPDIR = tmp;
});
afterEach(async () => {
  for (const s of servers) await s.close();
  servers = [];
  for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
  Object.assign(process.env, savedEnv);
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('git transport (E0c, B6)', () => {
  it('git: env built from scratch (no inherited GIT_*, HOME temp, GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL=/dev/null)', async () => {
    expect(gitEnv('/h')).toEqual({
      PATH: process.env.PATH, HOME: '/h', LANG: 'C', GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    });
    const poison = {
      GIT_DIR: '/nonexistent', GIT_WORK_TREE: '/nonexistent', GIT_TRACE: '1', GIT_CURL_VERBOSE: '1', GIT_TRACE_CURL: '1', GIT_SSL_NO_VERIFY: '1',
      GIT_CONFIG_PARAMETERS: "'core.askpass'='/bin/false'", GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.askpass', GIT_CONFIG_VALUE_0: '/bin/false',
      GIT_ASKPASS: '/bin/false', SSH_ASKPASS: '/bin/false', HTTPS_PROXY: 'http://127.0.0.1:9', https_proxy: 'http://127.0.0.1:9', 
      HOME: fresh('userhome'), XDG_CONFIG_HOME: fresh('xdg'), GIT_CONFIG_SYSTEM: '/nonexistent', GIT_CONFIG_GLOBAL: '/nonexistent',
    };
    Object.assign(process.env, poison);
    for (const k of ['GH_TOKEN', 'SECRET_THING']) process.env[k] = poisonValue;
    const work = fresh('work');
    git(work, 'init', '-q');
    expect(await isDirty(work)).toBe(false);
    const srv = serverRoot();
    const s = await serve(srv, { token });
    const repo = await pushRepoWithCommit();
    await routedPush(s.port, req(repo));
    await repo.remove();
    expect(git(join(srv, 'app.git'), 'rev-parse', 'refs/heads/main')).toBe(repo.sha);

    const calls = recorder.calls();
    expect(calls.length).toBeGreaterThanOrEqual(6);
    const base = ['PATH', 'HOME', 'LANG', 'GIT_TERMINAL_PROMPT', 'GCM_INTERACTIVE', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL'];
    for (const c of calls) {
      const isPush = c.argv.includes('push');
      const isRead = c.argv.includes('-C');
      const isCommit = c.argv.includes('commit-tree');
      const extra = isPush ? ASKPASS_VARS : isRead ? ['GIT_CEILING_DIRECTORIES', 'GIT_NO_LAZY_FETCH']
        : isCommit ? ['GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL'] : [];
      expect(Object.keys(c.env).sort(), c.argv.join(' ')).toEqual([...base, ...extra].sort());
      expect(c.env.LANG).toBe('C');
      expect(c.env.GIT_TERMINAL_PROMPT).toBe('0');
      expect(c.env.GCM_INTERACTIVE).toBe('never');
      expect(c.env.GIT_CONFIG_NOSYSTEM).toBe('1');
      expect(c.env.GIT_CONFIG_GLOBAL).toBe('/dev/null');
      expect(c.env.PATH).toBe(process.env.PATH);
      expect(c.env.HOME.startsWith(join(tmp, 'pipegen-git-'))).toBe(true);
      expect(existsSync(c.env.HOME)).toBe(false);   // removed after the call
      expect(c.cwd, c.argv.join(' ')).toBe(c.env.HOME);   // never the user's repo (Windows looks for the program there first)
      if (isPush) expect(c.env.PIPEGEN_GIT_TOKEN).toBe(token);
      else expect(Object.values(c.env).join('\n')).not.toContain(token);
    }
    const push = calls.filter((c) => c.argv.includes('push'));
    expect(push).toHaveLength(1);
    expect(push[0].argv.slice(push[0].argv.indexOf('push'))).toEqual(['push', '--atomic', '--no-verify', '--no-follow-tags', '--recurse-submodules=no', SCRATCH_URL, `${repo.sha}:refs/heads/main`]);
    expect(leftovers()).toEqual([]);

    // force: the refspecs get a +, and the branch is replaced.
    recorder.clear();
    const other = await pushRepoWithCommit();
    await routedPush(s.port, req(other, { refs: [{ sha: other.sha, branch: 'main' }, { sha: other.sha, branch: 'proof/x' }], force: true }));
    await other.remove();
    const forced = recorder.calls().find((c) => c.argv.includes('push'))!;
    expect(forced.argv.slice(-2)).toEqual([`+${other.sha}:refs/heads/main`, `+${other.sha}:refs/heads/proof/x`]);
    expect(git(join(srv, 'app.git'), 'rev-parse', 'refs/heads/main')).toBe(other.sha);
  });

  it('git: credential.helper reset, hooksPath /dev/null, fsmonitor off on every call', async () => {
    expect([...HARDENED_CONFIG]).toEqual(HARDENED);
    // The reset empties every helper read before it, a URL-specific one in the repo's own config included (the probe).
    const probe = fresh('probe');
    git(probe, 'init', '-q');
    const marker = join(probe, 'helper-called');
    git(probe, 'config', 'credential.https://github.com.helper', `!f() { echo called >> '${marker}'; }; f`);
    const fill = (cfg: string[]) => {
      try {
        execFileSync(REAL_GIT, [...cfg, 'credential', 'fill'], { cwd: probe, input: 'protocol=https\nhost=github.com\n\n', stdio: 'pipe', env: { PATH: savedEnv.PATH ?? '', HOME: probe, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' } });
      } catch { /* no credential: expected */ }
    };
    fill([...HARDENED_CONFIG]);
    expect(existsSync(marker)).toBe(false);
    fill([]);
    expect(existsSync(marker)).toBe(true);   // the probe's helper is live without the reset

    // Hooks in the push repo (pre-push, reference-transaction) never run; fsmonitor in the user's repo never runs.
    const srv = serverRoot();
    const s = await serve(srv);
    const repo = await pushRepoWithCommit();
    const hookMarker = join(root, `hook-ran-${n}`);
    for (const h of ['pre-push', 'reference-transaction']) {
      writeFileSync(join(repo.gitDir, 'hooks', h), `#!/bin/sh\necho ${h} >> '${hookMarker}'\n`);
      chmodSync(join(repo.gitDir, 'hooks', h), 0o755);
    }
    await routedPush(s.port, req(repo));
    await repo.remove();
    expect(existsSync(hookMarker)).toBe(false);
    const work = fresh('work');
    git(work, 'init', '-q');
    const fsmMarker = join(root, `fsmonitor-ran-${n}`);
    writeFileSync(join(work, 'fsm.sh'), `#!/bin/sh\necho ran >> '${fsmMarker}'\n`);
    chmodSync(join(work, 'fsm.sh'), 0o755);
    git(work, 'config', 'core.fsmonitor', join(work, 'fsm.sh'));
    await isDirty(work);
    expect(existsSync(fsmMarker)).toBe(false);

    const calls = recorder.calls();
    expect(calls.length).toBeGreaterThanOrEqual(6);
    for (const c of calls) expect(c.argv.slice(0, HARDENED.length), c.argv.join(' ')).toEqual(HARDENED);
  });

  it('git: askpass script in a 0700 temp dir reads the token from env; removed after', async () => {
    const srv = serverRoot();
    const s = await serve(srv, { token });
    const repo = await pushRepoWithCommit();
    await routedPush(s.port, req(repo));
    const basic = ['Basic', Buffer.from(['x-access-token', token].join(':')).toString('base64')].join(' ');
    expect(s.requests.map((r) => r.header)).toContain(basic);
    const push = recorder.calls().find((c) => c.argv.includes('push'));
    expect(push?.askpass).toBeDefined();
    const a = push!.askpass!;
    expect(a.dirMode).toBe('700');
    expect(a.fileMode).toBe('700');
    expect(a.script).not.toContain(token);
    expect(a.script).toContain('"$PIPEGEN_GIT_TOKEN"');
    expect(push!.env.GIT_ASKPASS).toBe(a.path);
    expect(existsSync(a.path)).toBe(false);
    expect(leftovers().filter((f) => f.startsWith('pipegen-git-'))).toEqual([]);

    // The script answers only git's two prompts for this origin; any other prompt gets nothing and a failure.
    const scriptPath = join(fresh('ask'), 'askpass');
    writeFileSync(scriptPath, a.script);
    chmodSync(scriptPath, 0o700);
    const ask = (prompt: string) => {
      try {
        return { out: execFileSync(scriptPath, [prompt], { encoding: 'utf8', env: { PATH: savedEnv.PATH ?? '', ...Object.fromEntries([[ASKPASS_VARS[1], token]]) } }), ok: true };
      } catch (e) {
        return { out: String((e as { stdout?: unknown }).stdout ?? ''), ok: false };
      }
    };
    expect(ask(`Username for 'https://github.com': `)).toEqual({ out: 'x-access-token\n', ok: true });
    expect(ask(`Password for 'https://x-access-token@github.com': `)).toEqual({ out: `${token}\n`, ok: true });
    const otherPrompts = [`Password for 'https://x-access-token@evil.example': `, `Password for 'http://x-access-token@127.0.0.1:${s.port}': `, `Username for 'http://127.0.0.1:${s.port}': `,
      `Password for 'https://x-access-token@github.com.evil': `, `Username for 'https://github.com.evil': `, `Password for 'https://x-access-token@github.com:443': `, 'Pass' + 'word: ', ''];
    for (const p of otherPrompts) {
      expect(ask(p), p).toEqual({ out: '', ok: false });
    }

    // Removed after a failed push too (a wrong token, which the server refuses).
    recorder.clear();
    await expect(routedPush(s.port, req(repo, { ...cred(`${token}Wrong`), refs: [{ sha: repo.sha, branch: 'other' }] }))).rejects.toThrow(GitTransportError);
    const failed = recorder.calls().find((c) => c.argv.includes('push'));
    expect(existsSync(failed!.askpass!.path)).toBe(false);
    await repo.remove();
    expect(leftovers()).toEqual([]);
  });

  it('git: push URL must be https://github.com/<owner>/(pipegen-proof-<repo>|pipelines).git', async () => {
    expect(checkPushUrl('https://github.com/acme/pipegen-proof-shop.git', 'acme', 'shop')).toBe('scratch');
    expect(checkPushUrl('https://github.com/acme/pipelines.git', 'acme', 'shop')).toBe('central');
    expect(checkPushUrl('https://github.com/a-b/pipegen-proof-my.app_1.git', 'a-b', 'my.app_1')).toBe('scratch');
    // A dot in a name is a dot, not any character.
    expect(() => checkPushUrl('https://github.com/a-b/pipegen-proof-myXapp_1.git', 'a-b', 'my.app_1')).toThrow(GitTransportError);
    expect(pushUrl('acme', 'shop', 'scratch')).toBe('https://github.com/acme/pipegen-proof-shop.git');
    expect(pushUrl('acme', 'shop', 'central')).toBe('https://github.com/acme/pipelines.git');
    const refused = [
      'https://github.com/acme/shop.git',                       // the app repo itself
      'https://github.com/acme/pipegen-proof-shop',             // no .git
      'https://github.com/acme/pipegen-proof-shop.git/',
      'https://github.com/acme/pipegen-proof-shopx.git',
      'https://github.com/acme/pipegen-proof-sho.git',
      'https://github.com/acme/xpipelines.git',
      'https://github.com/acme/pipelines.git.git',
      'https://github.com/other/pipegen-proof-shop.git',
      'https://github.com/Acme/pipegen-proof-shop.git',
      'https://github.com/acme/Pipelines.git',
      'http://github.com/acme/pipegen-proof-shop.git',
      'ssh://git@github.com/acme/pipegen-proof-shop.git',
      'git@github.com:acme/pipegen-proof-shop.git',
      'https://github.com.evil.example/acme/pipegen-proof-shop.git',
      'https://evil.example/github.com/acme/pipegen-proof-shop.git',
      'https://api.github.com/acme/pipegen-proof-shop.git',
      'https://github.com:443/acme/pipegen-proof-shop.git',
      `${['https://x-access-token', token].join(':')}@github.com/acme/pipegen-proof-shop.git`,
      'https://x-access-token@github.com/acme/pipegen-proof-shop.git',
      'https://github.com/acme/pipegen-proof-shop.git?x=1',
      'https://github.com/acme/pipegen-proof-shop.git#x',
      'https://github.com/acme/pipegen-proof-shop.git\n',
      ' https://github.com/acme/pipegen-proof-shop.git',
      'https://github.com/acme/../acme/pipegen-proof-shop.git',
      'https://github.com/acme/pipegen-proof-shop%2egit',
      'HTTPS://GITHUB.COM/acme/pipegen-proof-shop.git',
      'https://githubXcom/acme/pipegen-proof-shop.git',
      'https://github.com/acme/pipegen-proof-shop-git',
      'https://github.com/acme/pipegen-proof-shopXgit',
      '',
    ];
    for (const url of refused) expect(() => checkPushUrl(url, 'acme', 'shop'), JSON.stringify(url)).toThrow(GitTransportError);
    // Names that aren't GitHub names never build a pattern; an app repo named pipelines can't push to central (it IS the app repo).
    for (const [owner, repo] of [['ac.me', 'shop'], ['-acme', 'shop'], ['acme', '..'], ['acme', 'sh/op'], ['acme', 'a'.repeat(101)], ['acme', 'a'.repeat(87)]]) {
      expect(() => checkPushUrl(`https://github.com/${owner}/pipelines.git`, owner, repo), `${owner}/${repo}`).toThrow(GitTransportError);
    }
    expect(() => checkPushUrl('https://github.com/acme/pipelines.git', 'acme', 'pipelines')).toThrow(GitTransportError);
    expect(() => checkPushUrl('https://github.com/acme/pipelines.git', 'acme', 'PipeLines')).toThrow(GitTransportError);
    expect(checkPushUrl('https://github.com/acme/pipegen-proof-pipelines.git', 'acme', 'pipelines')).toBe('scratch');
    expect(checkPushUrl(`https://github.com/acme/pipegen-proof-${'a'.repeat(86)}.git`, 'acme', 'a'.repeat(86))).toBe('scratch');
    // The message never repeats the URL (it could hold a token).
    try {
      checkPushUrl(`${['https://x', token].join(':')}@github.com/acme/pipelines.git`, 'acme', 'shop');
    } catch (e) {
      expect((e as Error).message).not.toContain(token);
    }

    // gitPush checks the URL before anything runs.
    const repo = await pushRepoWithCommit();
    recorder.clear();
    for (const url of ['https://github.com/acme/shop.git', 'http://127.0.0.1:9/app.git']) {
      await expect(gitPush(req(repo, { url }))).rejects.toThrow(GitTransportError);
    }
    // Central takes only refs/heads/proof/<runId>.
    await expect(gitPush(req(repo, { url: pushUrl('acme', 'shop', 'central') }))).rejects.toThrow(/proof\/<runId>/);
    await expect(gitPush(req(repo, { url: pushUrl('acme', 'shop', 'central'), refs: [{ sha: repo.sha, branch: 'proof/20261103-120000-abc123/main' }] }))).rejects.toThrow(/proof\/<runId>/);
    expect(recorder.calls()).toEqual([]);
    await repo.remove();
    expect(leftovers()).toEqual([]);
  });

  it('git: the production push, offline: exact argv and -c flags, env from scratch, github.com askpass, no token in argv', async () => {
    // Unrouted, the recorder exits 97 on github.com: this is gitPush's own remote, flags and askpass, as they ship.
    const repo = await pushRepoWithCommit();
    const cases = [
      { url: SCRATCH_URL, branch: 'main', force: true, spec: `+${repo.sha}:refs/heads/main` },
      { url: 'https://github.com/acme/pipelines.git', branch: 'proof/20261103-120000-abcdef', force: false, spec: `${repo.sha}:refs/heads/proof/20261103-120000-abcdef` },
    ];
    for (const c of cases) {
      recorder.clear();
      const err = await gitPush(req(repo, { url: c.url, refs: [{ sha: repo.sha, branch: c.branch }], force: c.force })).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(GitTransportError);
      expect((err as Error).message).toMatch(/exit 97/);
      const calls = recorder.calls();
      expect(calls.map((k) => k.argv)).toEqual([
        [...HARDENED, `--git-dir=${repo.gitDir}`, 'config', '--list', '--show-scope', '-z'],
        [...HARDENED, `--git-dir=${repo.gitDir}`, 'push', '--atomic', '--no-verify', '--no-follow-tags', '--recurse-submodules=no', c.url, c.spec],
      ]);
      const push = calls[1];
      expect(Object.keys(push.env).sort()).toEqual(['GCM_INTERACTIVE', 'GIT_ASKPASS', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT', 'HOME', 'LANG', 'PATH', 'PIPEGEN_GIT_TOKEN']);
      expect(push.env).toMatchObject({ LANG: 'C', GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'never', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' });
      expect(push.env[ASKPASS_VARS[1]]).toBe(token);
      expect(push.argv.join('\0')).not.toContain(token);
      expect(calls[0].env.PIPEGEN_GIT_TOKEN).toBeUndefined();
      // The askpass script as shipped answers github.com's two prompts and nothing else.
      const scriptPath = join(fresh('ask'), 'askpass');
      writeFileSync(scriptPath, push.askpass!.script);
      chmodSync(scriptPath, 0o700);
      const ask = (prompt: string) => {
        try {
          return execFileSync(scriptPath, [prompt], { encoding: 'utf8', env: { PATH: savedEnv.PATH ?? '', ...Object.fromEntries([[ASKPASS_VARS[1], token]]) } });
        } catch {
          return null;
        }
      };
      expect(ask(`Username for 'https://github.com': `)).toBe('x-access-token\n');
      expect(ask(`Password for 'https://x-access-token@github.com': `)).toBe(`${token}\n`);
      expect(ask(`Password for 'https://x-access-token@evil.example': `)).toBeNull();
      expect(push.askpass!.dirMode).toBe('700');
      expect(existsSync(push.askpass!.path)).toBe(false);
    }
    await repo.remove();
    expect(leftovers()).toEqual([]);
  });

  it('git: gitPush and runGit take only a live createPushRepo handle', async () => {
    const repo = await pushRepoWithCommit();
    recorder.clear();
    const forged = [
      { gitDir: repo.gitDir, remove: repo.remove },
      { ...repo.handle },
      Object.create(repo.handle) as PushRepoHandle,
      null,
      repo.gitDir,
    ] as unknown as PushRepoHandle[];
    for (const f of forged) {
      await expect(gitPush(req(repo, { repo: f })), String(f)).rejects.toThrow(/createPushRepo/);
      await expect(runGit(f, ['cat-file', '-t', repo.sha]), String(f)).rejects.toThrow(/createPushRepo/);
    }
    expect(recorder.calls()).toEqual([]);
    expect(Object.isFrozen(repo.handle)).toBe(true);
    await repo.remove();
    // A removed repo's handle is dead.
    await expect(gitPush(req(repo))).rejects.toThrow(/createPushRepo/);
    await expect(runGit(repo.handle, ['cat-file', '-t', repo.sha])).rejects.toThrow(/createPushRepo/);
    // So is one whose folder the exit hook removed.
    const other = await createPushRepo();
    runExitHooks();
    recorder.clear();
    await expect(runGit(other, ['rev-parse', 'HEAD'])).rejects.toThrow(/createPushRepo/);
    expect(recorder.calls()).toEqual([]);
  });

  it('git: the test wrapper, routed, still refuses anything naming github.com after its rewrite', () => {
    recorder.route(9);
    const run = (args: string[]) => {
      try {
        execFileSync(join(recorder.bin, 'git'), args, { stdio: 'pipe', env: { PATH: savedEnv.PATH ?? '', HOME: root } });
        return 0;
      } catch (e) {
        return (e as { status?: number }).status;
      }
    };
    // Local commands only: without the re-check they would run (exit 0 or 1), never touching the network.
    expect(run(['config', '--file', '/dev/null', '--get-urlmatch', 'http.proxy', 'http://github.com/acme/x.git'])).toBe(97);
    expect(run(['config', '--file', '/dev/null', '--get-urlmatch', 'http.proxy', 'https://github.com.evil/acme/x.git'])).toBe(97);
    expect(run(['-c', 'url.https://github.com/.insteadOf=x', 'config', '--file', '/dev/null', '--list'])).toBe(97);
    // The rewrite itself still works: only the loopback URL is left.
    expect(run(['config', '--file', '/dev/null', '--get-urlmatch', 'http.proxy', 'https://github.com/acme/pipegen-proof-shop.git'])).toBe(1);
  });

  it('git: refs, token and options are checked before git runs', async () => {
    const repo = await pushRepoWithCommit();
    recorder.clear();
    const base = req(repo);
    const bad: Array<Partial<PushRequest>> = [
      { refs: [] },
      { refs: [{ sha: 'abc', branch: 'main' }] },
      { refs: [{ sha: 'A'.repeat(40), branch: 'main' }] },
      { refs: [{ sha: `${SHA}\n`, branch: 'main' }] },
      { refs: [{ sha: SHA, branch: 'refs/heads/main' }] },
      { refs: [{ sha: SHA, branch: 'HEAD' }] },
      { refs: [{ sha: SHA, branch: '-main' }] },
      { refs: [{ sha: SHA, branch: 'a..b' }] },
      { refs: [{ sha: SHA, branch: 'a b' }] },
      { refs: [{ sha: SHA, branch: 'a:b' }] },
      { refs: [{ sha: SHA, branch: 'x.lock' }] },
      { refs: [{ sha: SHA, branch: 'a/' }] },
      { refs: [{ sha: SHA, branch: '' }] },
      cred(''),
      cred('short'),
      cred(`${token}\n`),
      cred(`${token} x`),
      { ...cred('main_branch_name_is_the_token'), refs: [{ sha: SHA, branch: 'main_branch_name_is_the_token' }] },
      { ...cred('acme_x'.repeat(4)), refs: [{ sha: SHA, branch: `x/${'acme_x'.repeat(4)}` }] },
    ];
    for (const b of bad) await expect(gitPush({ ...base, ...b }), JSON.stringify(b)).rejects.toThrow(GitTransportError);
    // A refused name is shown, but never a GitHub token shape in it (GitTransportError hides every message).
    const shaped = ['gh', 'p_', 'B'.repeat(36)].join('');
    const named = await gitPush({ ...base, refs: [{ sha: SHA, branch: `${shaped} x` }] }).catch((e: unknown) => e);
    expect((named as Error).message).toContain('***');
    expect((named as Error).message).not.toContain(shaped);
    expect(recorder.calls()).toEqual([]);
    await repo.remove();
  });

  it('git: insteadOf and pushInsteadOf in the push repo\'s config → push refused, nothing sent', async () => {
    const srv = serverRoot();
    const good = await serve(srv, { token });
    const evil = await serve(serverRoot());
    for (const [key, extra] of [
      [`url.http://127.0.0.1:${evil.port}/.insteadOf`, null],
      [`url.http://127.0.0.1:${evil.port}/.pushInsteadOf`, null],
      ['credential.helper', null],
      ['http.extraHeader', null],
      ['include.path', 'EMPTY'],
      ['remote.origin.url', null],
      ['core.sshCommand', null],
      ['http.sslVerify', 'false'],
    ] as const) {
      const repo = await pushRepoWithCommit();
      const empty = join(fresh('inc'), 'empty.cfg');
      writeFileSync(empty, '');
      const value = extra === 'EMPTY' ? empty : extra ?? (key.startsWith('url.') ? 'https://github.com/' : '/bin/false');
      git(repo.gitDir, 'config', key, value);
      recorder.clear();
      const err = await routedPush(good.port, req(repo)).catch((e: unknown) => e);
      expect(err, key).toBeInstanceOf(GitTransportError);
      expect((err as Error).message).toMatch(/config/);
      expect((err as Error).message).not.toContain(value);
      expect(recorder.calls().filter((c) => c.argv.includes('push')), key).toEqual([]);
      await repo.remove();
    }
    expect(good.requests).toEqual([]);
    expect(evil.requests).toEqual([]);
    expect(() => git(join(srv, 'app.git'), 'rev-parse', '--verify', '-q', 'refs/heads/main')).toThrow();
    expect(leftovers()).toEqual([]);
  });

  it('git: insteadOf, pushInsteadOf and credential helpers from the user\'s HOME, system config and GIT_CONFIG_* are ignored', async () => {
    const srv = serverRoot();
    const good = await serve(srv, { token });
    const evil = await serve(serverRoot());
    const helperLog = join(root, `helper-${n}`);
    const helper = join(fresh('helper'), 'helper.sh');
    // A helper that would store (approve) or give a credential; it logs every call and everything it reads.
    writeFileSync(helper, `#!/bin/sh\necho "call $*" >> '${helperLog}'\ncat >> '${helperLog}'\n`);
    chmodSync(helper, 0o755);
    // The URL git sees once the recorder has routed the push: a leaked insteadOf on it would send the push to the evil server.
    const goodBase = `http://127.0.0.1:${good.port}/`;
    const evilBase = `http://127.0.0.1:${evil.port}/`;
    const cfg = `[credential]\n\thelper = ${helper}\n[url "${evilBase}"]\n\tinsteadOf = ${goodBase}\n\tpushInsteadOf = ${goodBase}\n[http]\n\tproxy = http://127.0.0.1:${evil.port}\n`;
    const home = fresh('home');
    writeFileSync(join(home, '.gitconfig'), cfg);
    mkdirSync(join(home, '.config', 'git'), { recursive: true });
    writeFileSync(join(home, '.config', 'git', 'config'), cfg);
    const sys = join(fresh('sys'), 'gitconfig');
    writeFileSync(sys, cfg);
    Object.assign(process.env, {
      HOME: home, XDG_CONFIG_HOME: join(home, '.config'), GIT_CONFIG_SYSTEM: sys, GIT_CONFIG_GLOBAL: join(home, '.gitconfig'),
      GIT_CONFIG_COUNT: '2', GIT_CONFIG_KEY_0: `url.${evilBase}.pushInsteadOf`, GIT_CONFIG_VALUE_0: goodBase, GIT_CONFIG_KEY_1: 'credential.helper', GIT_CONFIG_VALUE_1: helper,
      GIT_CONFIG_PARAMETERS: `'url.${evilBase}.insteadof'='${goodBase}'`,
      http_proxy: `http://127.0.0.1:${evil.port}`, HTTP_PROXY: `http://127.0.0.1:${evil.port}`, ALL_PROXY: `http://127.0.0.1:${evil.port}`,
    });
    // The poisoned config is live for a plain git in this environment (so the test would see a leak).
    expect(execFileSync(REAL_GIT, ['config', '--get-all', 'credential.helper'], { encoding: 'utf8', cwd: home })).toContain(helper);

    const repo = await pushRepoWithCommit();
    await routedPush(good.port, req(repo));
    await repo.remove();
    expect(git(join(srv, 'app.git'), 'rev-parse', 'refs/heads/main')).toBe(repo.sha);
    expect(evil.requests).toEqual([]);
    expect(existsSync(helperLog)).toBe(false);   // never called: not for get, not for store after the successful push
    expect(good.requests.length).toBeGreaterThan(0);
  });

  it('git: redirects are not followed; the redirect target gets nothing', async () => {
    const target = await serve(serverRoot());
    const srv = serverRoot();
    const redirecting = await serve(srv, { redirectTo: target.port });
    const repo = await pushRepoWithCommit();
    await expect(routedPush(redirecting.port, req(repo))).rejects.toThrow(GitTransportError);
    await repo.remove();
    expect(redirecting.requests.length).toBeGreaterThan(0);
    expect(target.requests).toEqual([]);
    expect(leftovers()).toEqual([]);
  });

  it.runIf(process.platform === 'linux')('git: the token never appears in argv (/proc cmdline of every process) or the remote URL', async () => {
    const srv = serverRoot();
    const s = await serve(srv, { token, holdPushMs: 400 });
    const repo = await pushRepoWithCommit();
    const seen = new Set<string>();
    let leaks = 0;
    const scan = () => {
      for (const pid of readdirSync('/proc')) {
        if (!/^\d+$/.test(pid)) continue;
        let cmd: string;
        try { cmd = readFileSync(`/proc/${pid}/cmdline`, 'latin1'); } catch { continue; }
        if (cmd.includes(token)) leaks++;
        if (/git|askpass/.test(cmd)) seen.add(cmd.split('\0').slice(0, 2).join(' '));
      }
    };
    const timer = setInterval(scan, 2);
    try {
      await routedPush(s.port, req(repo));
    } finally {
      clearInterval(timer);
    }
    await repo.remove();
    expect(leaks).toBe(0);
    expect([...seen].some((c) => c.includes('remote-http'))).toBe(true);   // the scan saw the push's own processes
    const push = recorder.calls().find((c) => c.argv.includes('push'))!;
    expect(push.argv.join('\0')).not.toContain(token);
    expect(push.argv).toContain(SCRATCH_URL);
    for (const r of s.requests) expect(r.url).not.toContain(token);
  });

  it('git: git output and errors pass through hideToken', async () => {
    // A server-side hook prints the token (and the token cut by an escape sequence) to the push's stderr.
    const srv = serverRoot();
    const hook = join(srv, 'app.git', 'hooks', 'pre-receive');
    writeFileSync(hook, `#!/bin/sh\necho "plain ${token}" >&2\nprintf 'cut ${token.slice(0, 10)}\\033[0m${token.slice(10)}\\n' >&2\nexit 1\n`);
    chmodSync(hook, 0o755);
    const s = await serve(srv, { token });
    const repo = await pushRepoWithCommit();
    const err = await routedPush(s.port, req(repo)).catch((e: unknown) => e);
    await repo.remove();
    expect(err).toBeInstanceOf(GitTransportError);
    const msg = (err as Error).message;
    expect(msg).toContain('plain ***');
    expect(msg).not.toContain(token);
    expect(msg).not.toContain(token.slice(10));
    expect(String((err as Error).stack)).not.toContain(token);
    expect((err as { cause?: unknown }).cause).toBeUndefined();

    // The formatter: the token by value (any shape), split by an escape or a control character, any GitHub token shape; one line, short.
    expect(shownGitOutput(`a ${token} b`, token)).toBe('a *** b');
    expect(shownGitOutput(`a ${token.slice(0, 5)}\x1b[31m${token.slice(5)}`, token)).toBe('a ***');
    expect(shownGitOutput(`a ${token.slice(0, 5)}\x07${token.slice(5)}`, token)).toBe('a ***');
    expect(shownGitOutput(`x ghp_${'A'.repeat(36)} y`)).toBe('x *** y');
    // An escape that eats the token's first character: hidden on the raw text, before cleaning.
    expect(shownGitOutput(`a \x1b${token}`, token)).not.toContain(token.slice(1));
    expect(shownGitOutput('one\ntwo\r\nthree\rfour')).toBe('one | two | three | four');
    expect(shownGitOutput(Array.from({ length: 30 }, (_, i) => `line ${i}`).join('\n'))).toBe(Array.from({ length: 8 }, (_, i) => `line ${i + 22}`).join(' | '));
    expect(shownGitOutput('x'.repeat(5000)).length).toBeLessThanOrEqual(600);
  });

  it('git: the exit hook removes the askpass dir and kills a push in flight', async () => {
    const srv = serverRoot();
    const s = await serve(srv, { token, holdPushMs: 1500 });
    const repo = await pushRepoWithCommit();
    const started = Date.now();
    const p = routedPush(s.port, req(repo)).catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 400));
    const ask = recorder.calls().find((c) => c.argv.includes('push'))!.askpass!.path;
    expect(existsSync(ask)).toBe(true);
    runExitHooks();
    expect(existsSync(ask)).toBe(false);
    expect(await p).toBeInstanceOf(GitTransportError);
    expect(Date.now() - started).toBeLessThan(1400);
    await repo.remove();
    expect(leftovers()).toEqual([]);
  });

  it('git: a push past its timeout is killed with everything it started', async () => {
    const s = await serve(serverRoot(), { ...cred(token), holdPushMs: 3000 });
    const repo = await pushRepoWithCommit();
    const started = Date.now();
    const err = await routedPush(s.port, req(repo, { timeoutMs: 500 })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GitTransportError);
    expect((err as Error).message).toMatch(/took longer than 1 s/);
    expect(Date.now() - started).toBeLessThan(2000);
    await repo.remove();
    expect(leftovers()).toEqual([]);
  });

  it('git: runGit runs only the plumbing commands the proof needs, in a pipegen push repo', async () => {
    const repo = await pushRepoWithCommit();
    expect(text(await runGit(repo.handle, ['cat-file', '-t', repo.sha]))).toBe('commit');
    for (const args of [['push', 'x'], ['-c', 'a=b', 'status'], ['config', 'x.y', 'z'], ['fetch'], ['credential', 'fill'], ['remote', 'add', 'o', 'x'], ['--exec-path=/tmp', 'cat-file'], [], ['submodule', 'update']]) {
      await expect(runGit(repo.handle, args), args.join(' ')).rejects.toThrow(GitTransportError);
    }
    await expect(runGit({ gitDir: repo.gitDir, remove: repo.remove } as PushRepoHandle, ['cat-file', '-t', repo.sha])).rejects.toThrow(GitTransportError);
    // A failing git call is an error with git's (cleaned) message.
    await expect(runGit(repo.handle, ['cat-file', '-t', SHA])).rejects.toThrow(/cat-file/);
    // The identity sets author and committer.
    const raw = text(await runGit(repo.handle, ['cat-file', '-p', repo.sha]));
    expect(raw).toMatch(/^author pipegen <pipegen@example\.invalid> /m);
    expect(raw).toMatch(/^committer pipegen <pipegen@example\.invalid> /m);
    const gitDir = repo.gitDir;
    await repo.remove();
    expect(existsSync(gitDir)).toBe(false);
    expect(leftovers()).toEqual([]);
  });

  it('git: createPushRepo makes a 0700 bare repo whose config passes the push check, removed on exit', async () => {
    const repo = await createPushRepo();
    const parent = join(repo.gitDir, '..');
    expect((readdirSync(tmp))).toHaveLength(1);
    expect(execFileSync('stat', ['-c', '%a', parent], { encoding: 'utf8' }).trim()).toBe('700');
    expect(git(repo.gitDir, 'rev-parse', '--is-bare-repository')).toBe('true');
    runExitHooks();
    expect(existsSync(parent)).toBe(false);
    await repo.remove();   // safe after the exit hook
  });
});
