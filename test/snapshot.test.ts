// Plan E E2 (Task 2, first half; rulings S1, S4, S5, S9, S21, S24, B3, B6): the base snapshot, the central draft and the
// proof branches. Every push is the real gitPush (src/proof/git.ts) through gitTransport: a `git` wrapper first on PATH
// (test/helpers/git-recorder.ts) records each call, and routes github.com by repo name to a loopback smart-HTTP server
// (test/helpers/git-http.ts) that serves local bare repos named pipegen-proof-shop.git and pipelines.git. Octokit is a real
// makeOctokit client over a fake fetch whose answers are read from those bare repos. interrupting() is mocked (raising a
// real stop would end the test worker). Nothing touches the network.
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Octokit } from '@octokit/rest';
import { makeOctokit } from '../src/github/client.js';
import type { PushRef, PushRepoHandle } from '../src/proof/git.js';
import {
  checkCentralTriggers, disableUserWorkflows, gitTransport, openProofSession, plantedSecretPlacements, pushBase, pushProofBranch,
  pushProofSetup, symlinkNotProven, type ProofFile, type ProofSetupInput, type ProofTransport,
} from '../src/proof/snapshot.js';
import { assertCentral, assertScratch, proofTarget, ProofStopError, ScratchGuardError, type GuardedRepo, type ProofTarget } from '../src/proof/target.js';
import type { CreatedFile } from '../src/types.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { fakeFetch, type Call, type Reply } from './helpers/fake-http.js';
import { startGitHttp, type GitHttpServer } from './helpers/git-http.js';
import { makeGitRecorder, REAL_GIT } from './helpers/git-recorder.js';
import { fake } from './helpers/secret-repo.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));

// The token is built at run time (no-secret-literals): token-shaped, so the transport takes it.
const TOKEN = ['pipegenE2Test', 'Token_0123456789', 'abcdefXYZ'].join('');
const OWNER = 'CrisWorking';
const SCRATCH = 'pipegen-proof-shop';
const RUN_ID = '20261103-120000-abcdef';
const ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' };
const savedEnv = { ...process.env };

const root = mkdtempSync(join(tmpdir(), 'pg-e2-'));
const recorder = makeGitRecorder(root);
let n = 0;
let servers: GitHttpServer[] = [];

const git = (cwd: string, ...args: string[]) => execFileSync(REAL_GIT, args, { cwd, encoding: 'utf8', env: ENV }).trim();
const gitBuf = (cwd: string, ...args: string[]) => execFileSync(REAL_GIT, args, { cwd, env: ENV });
const fresh = (name: string) => {
  const d = join(root, `${name}-${++n}`);
  mkdirSync(d, { recursive: true });
  return d;
};
const put = (dir: string, rel: string, content: string | Buffer) => {
  mkdirSync(join(dir, rel, '..'), { recursive: true });
  writeFileSync(join(dir, rel), content);
};
const commitAll = (dir: string, msg = 'c') => {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-qm', msg);
};

const USER_CI = 'on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "$" && env\n';
const SHARED_SIGN = 'on:\n  workflow_call: {}\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n';
const CENTRAL_MERGE = 'on:\n  workflow_call: {}\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n';

/** The user's repo: three commits of history; HEAD holds workflows, Dependabot and Renovate configs, an export-ignore file. */
function userRepo(): string {
  const d = fresh('app');
  git(d, 'init', '-q', '-b', 'main');
  put(d, 'old-secret.txt', 'history only\n');
  commitAll(d, 'one');
  rmSync(join(d, 'old-secret.txt'));
  put(d, 'src/app.js', 'console.log(1);\n');
  commitAll(d, 'two');
  put(d, '.github/workflows/ci.yml', USER_CI);
  put(d, '.github/workflows/nested/deep.yaml', USER_CI);
  put(d, '.github/dependabot.yml', 'version: 2\nupdates: []\n');
  put(d, '.github/CODEOWNERS', '* @CrisWorking\n');
  put(d, 'renovate.json', '{}\n');
  put(d, '.github/renovate.json5', '{}\n');
  put(d, '.renovaterc', '{}\n');
  put(d, '.gitattributes', 'docs/ignored.md export-ignore\nversion.txt export-subst\n');
  put(d, 'docs/ignored.md', 'kept even though export-ignore\n');
  put(d, 'version.txt', '$Format:%H$\n');
  put(d, 'run.sh', '#!/bin/sh\necho hi\n');
  chmodSync(join(d, 'run.sh'), 0o755);
  commitAll(d, 'three');
  return d;
}

interface Fixture {
  app: string;
  srv: string;
  scratchGit: string;
  pipelinesGit: string;
  gh: Octokit;
  calls: Call[];
  /** Every event in order: API writes, reads of runs, transport pushes, the secret store. */
  events: string[];
  /** GET …/actions/runs answer for the base sha. */
  runs: { count: number };
  workflows: { id: number; path: string; state: string }[];
  target: ProofTarget;
  transport: ProofTransport;
  stored: GuardedRepo[];
  close(): Promise<void>;
}

const json = (status: number, body: unknown): Reply => ({ status, body });

/** A bare repo's branch heads. */
const heads = (bare: string): Record<string, string> => {
  const out = git(bare, 'for-each-ref', '--format=%(refname:short) %(objectname)', 'refs/heads');
  return Object.fromEntries(out === '' ? [] : out.split('\n').map((l) => l.split(' ') as [string, string]));
};
const treeOf = (bare: string, rev: string): Record<string, string> => {
  const out = gitBuf(bare, 'ls-tree', '-r', '-z', '--full-tree', rev).toString('latin1');
  return Object.fromEntries(out.split('\0').filter((l) => l !== '').map((l) => {
    const [meta, path] = l.split('\t') as [string, string];
    return [Buffer.from(path, 'latin1').toString('utf8'), meta.split(' ')[0] as string];
  }));
};
const show = (bare: string, rev: string, path: string) => git(bare, 'show', `${rev}:${path}`);
/** Blob contents by raw path bytes (latin1 key): argv can't carry a name that is not UTF-8. */
const blobsByRawPath = (bare: string, rev: string): Map<string, Buffer> => {
  const out = gitBuf(bare, 'ls-tree', '-r', '-z', '--full-tree', rev).toString('latin1');
  return new Map(out.split('\0').filter((l) => l !== '').map((l) => {
    const [meta, path] = l.split('\t') as [string, string];
    return [path, gitBuf(bare, 'cat-file', 'blob', meta.split(' ')[2] as string)];
  }));
};
const parents = (bare: string, sha: string) => git(bare, 'rev-list', '--parents', '-n', '1', sha).split(' ').slice(1);

async function fixture(o: { appDefault?: string; scratchEmpty?: boolean; runs?: number; pipelinesFiles?: Record<string, string>; token?: string } = {}): Promise<Fixture> {
  const app = userRepo();
  const srv = fresh('srv');
  const scratchGit = join(srv, `${SCRATCH}.git`);
  const pipelinesGit = join(srv, 'pipelines.git');
  git(srv, 'init', '-q', '--bare', '-b', 'main', scratchGit);
  git(srv, 'init', '-q', '--bare', '-b', 'main', pipelinesGit);
  // the scratch repo as auto_init leaves it (a README on main), unless empty
  const seed = (bare: string, files: Record<string, string>) => {
    const w = fresh('seed');
    git(w, 'init', '-q', '-b', 'main');
    for (const [p, c] of Object.entries(files)) put(w, p, c);
    commitAll(w, 'seed');
    git(w, 'push', '-q', bare, 'main');
  };
  if (o.scratchEmpty !== true) seed(scratchGit, { 'README.md': '# scratch\n' });
  seed(pipelinesGit, o.pipelinesFiles ?? { '.github/workflows/pipegen--sign.yml': SHARED_SIGN, 'records/other.json': '{"repo":"other"}\n', 'run.sh': '#!/bin/sh\n' });
  const server = await startGitHttp(srv, { token: o.token ?? TOKEN });
  servers.push(server);
  recorder.route(server.port, { byName: true });

  const events: string[] = [];
  const runs = { count: o.runs ?? 0 };
  const workflows: Fixture['workflows'] = [];
  const bareOf = (name: string) => (name === SCRATCH ? scratchGit : name === 'pipelines' ? pipelinesGit : null);
  const defaultOf = (bare: string) => {
    const h = heads(bare);
    const head = git(bare, 'symbolic-ref', '--short', 'HEAD');
    if (h[head] !== undefined) return head;
    const names = Object.keys(h);
    return names.length === 1 ? names[0] as string : head;   // GitHub: the first branch pushed to an empty repo becomes the default
  };
  const route = (c: Call): Reply => {
    const path = decodeURIComponent(c.url.pathname);
    const parts = path.split('/').filter((p) => p !== '');
    if (parts[0] !== 'repos' || parts[1] !== OWNER) return json(404, { message: 'Not Found' });
    const name = parts[2] as string;
    const bare = bareOf(name);
    if (bare === null) return json(404, { message: 'Not Found' });
    const rest = parts.slice(3).join('/');
    const m = c.method;
    if (m !== 'GET' || rest === 'actions/runs') events.push(`${m} ${name}/${rest}`);
    if (m === 'GET' && rest === '') return json(200, { name, full_name: `${OWNER}/${name}`, private: true, visibility: 'private', default_branch: defaultOf(bare), description: name === SCRATCH ? 'pipegen proof runs (private scratch repo)' : '' });
    if (m === 'PATCH' && rest === '') {
      const b = JSON.parse(c.body ?? '{}') as { default_branch?: string };
      if (b.default_branch !== undefined) {
        if (heads(bare)[b.default_branch] === undefined) return json(422, { message: 'Validation Failed' });
        git(bare, 'symbolic-ref', 'HEAD', `refs/heads/${b.default_branch}`);
      }
      return json(200, { name, default_branch: defaultOf(bare), private: true });
    }
    if (m === 'GET' && parts[3] === 'git' && parts[4] === 'ref' && parts[5] === 'heads') {
      const h = heads(bare);
      if (Object.keys(h).length === 0) return json(409, { message: 'Git Repository is empty.' });
      const sha = h[parts.slice(6).join('/')];
      return sha === undefined ? json(404, { message: 'Not Found' }) : json(200, { object: { sha, type: 'commit' } });
    }
    if (m === 'GET' && parts[3] === 'git' && parts[4] === 'commits') {
      const sha = parts[5] as string;
      return json(200, { sha, tree: { sha: git(bare, 'rev-parse', `${sha}^{tree}`) } });
    }
    if (m === 'GET' && parts[3] === 'git' && parts[4] === 'trees') {
      const sha = parts[5] as string;
      const out = gitBuf(bare, 'ls-tree', '-r', '-t', '-l', '-z', sha).toString('utf8');
      const tree = out.split('\0').filter((l) => l !== '').map((l) => {
        const [meta, p] = l.split('\t') as [string, string];
        const [mode, type, s, size] = meta.trim().split(/ +/) as [string, string, string, string];
        return { path: p, mode, type, sha: s, ...(type === 'blob' ? { size: Number(size) } : {}) };
      });
      return json(200, { sha, tree, truncated: false });
    }
    if (m === 'GET' && parts[3] === 'git' && parts[4] === 'blobs') {
      const content = gitBuf(bare, 'cat-file', 'blob', parts[5] as string);
      return json(200, { sha: parts[5], size: content.length, encoding: 'base64', content: content.toString('base64').replace(/(.{60})/g, '$1\n') });
    }
    if (m === 'DELETE' && rest === 'automated-security-fixes') return json(200, {});
    if (m === 'GET' && rest === 'actions/workflows') return json(200, { total_count: workflows.length, workflows });
    if (m === 'PUT' && /^actions\/workflows\/\d+\/disable$/.test(rest)) {
      const w = workflows.find((x) => String(x.id) === parts[6]);
      if (w !== undefined) w.state = 'disabled_manually';
      return json(200, {});
    }
    if (m === 'GET' && rest === 'actions/runs') return json(200, { total_count: runs.count, workflow_runs: [] });
    return json(404, { message: 'Not Found' });
  };
  const { fetch, calls } = fakeFetch(new Proxy({}, { get: (_t, key) => (typeof key === 'string' ? route : undefined) }) as never);
  const gh = makeOctokit(fake.githubPat(), { fetch, log: () => {} });
  const target = proofTarget({ owner: OWNER, repo: 'shop', private: true, ownerType: 'User', defaultBranch: o.appDefault ?? 'main' }, { runId: RUN_ID });
  const real = gitTransport(TOKEN);
  const transport: ProofTransport = {
    push: async (to: GuardedRepo, from: PushRepoHandle, refs: readonly PushRef[], opts?: { force?: boolean }) => {
      events.push(`push ${to.repo} ${refs.map((r) => `${opts?.force === true ? '+' : ''}${r.branch}`).join(',')}`);
      await real.push(to, from, refs, opts);
    },
  };
  const stored: GuardedRepo[] = [];
  return {
    app, srv, scratchGit, pipelinesGit, gh, calls, events, runs, workflows, target, transport, stored,
    close: async () => {
      await server.close();
      servers = servers.filter((s) => s !== server);
    },
  };
}

const created = (path: string, content: string, o: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'pipeline', reason: 'test', repo: 'app', ...o });
/** The assembled proof files of a central layout: the caller pinned to the central commit and a non-workflow file. */
const centralCaller = (sha: string | undefined, o: { sha?: string } = {}): CreatedFile[] => [
  created('.github/workflows/pipegen.yml', `on:\n  push: {}\n  pull_request: {}\njobs:\n  pipegen:\n    uses: ${OWNER}/pipelines/.github/workflows/shop--merge.yml@${o.sha ?? sha ?? 'none'}\n`),
  created('Dockerfile', 'FROM scratch\n', { part: 'docker' }),
];
const localLayout = (): CreatedFile[] => [
  created('.github/workflows/pipegen.yml', 'on:\n  push: {}\n  pull_request: {}\njobs:\n  pipegen:\n    uses: ./.github/workflows/pipegen-merge.yml\n'),
  created('.github/workflows/pipegen-merge.yml', CENTRAL_MERGE),
];
const centralDraft = () => ({ files: [created('.github/workflows/shop--merge.yml', CENTRAL_MERGE, { repo: 'central' })] });
const PLANTED: ProofFile[] = [{ path: 'pipegen-planted/sql.js', content: 'db.query("SELECT * FROM t WHERE id=" + id);\n' }];

function input(f: Fixture, o: Partial<ProofSetupInput> = {}): ProofSetupInput {
  return {
    target: f.target, dir: f.app, central: centralDraft(), appFiles: (sha) => centralCaller(sha), plantedFiles: PLANTED,
    ...o,
  };
}
function deps(f: Fixture, o: { settleMs?: number } = {}) {
  const err: string[] = [];
  return {
    err,
    d: {
      gh: f.gh, transport: f.transport, io: { out: () => {}, err: (s: string) => err.push(s) }, settleMs: o.settleMs ?? 0,
      storeSecrets: async (scratch: GuardedRepo) => { f.events.push('store-secrets'); f.stored.push(scratch); },
    },
  };
}

const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
const USER_WORKFLOWS = ['.github/workflows/ci.yml', '.github/workflows/nested/deep.yaml'];
const BOTS = ['.github/dependabot.yml', 'renovate.json', '.github/renovate.json5', '.renovaterc'];

beforeEach(() => {
  recorder.clear();
  process.env.PATH = `${recorder.bin}:${savedEnv.PATH ?? ''}`;
  vi.mocked(interrupting).mockReturnValue(false);
});
afterEach(async () => {
  for (const s of servers) await s.close();
  servers = [];
  process.env.PATH = savedEnv.PATH;
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('E2 base snapshot, central draft, proof branches (Task 2 first half)', () => {
  it('snapshot: base = HEAD files without .github/workflows, pushed to the default branch', async () => {
    const f = await fixture();
    const { d } = deps(f);
    const r = await pushProofSetup(input(f), d);
    const head = git(f.app, 'rev-parse', 'HEAD');
    const want = Object.keys(treeOf(f.app, 'HEAD')).filter((p) => !p.startsWith('.github/workflows/') && !BOTS.includes(p)).sort();
    expect(Object.keys(treeOf(f.scratchGit, 'main')).sort()).toEqual(want);
    expect(heads(f.scratchGit).main).toBe(r.base.sha);
    expect(r.base.head).toBe(head);
    // every byte and mode as in HEAD (the executable bit included); the README of auto_init is gone (force-pushed)
    for (const p of want) expect(show(f.scratchGit, 'main', p), p).toBe(show(f.app, 'HEAD', p));
    expect(treeOf(f.scratchGit, 'main')['run.sh']).toBe('100755');
    expect(treeOf(f.scratchGit, 'main')['README.md']).toBeUndefined();
    expect(r.base.leftOut.map((l) => l.path).sort()).toEqual([...USER_WORKFLOWS, ...BOTS].sort());
    expect(f.events).toContain('push pipegen-proof-shop +main');
    await f.close();
  });

  it('snapshot: base commit has no parent (no history)', async () => {
    const f = await fixture();
    const r = await pushProofSetup(input(f), deps(f).d);
    expect(Number(git(f.app, 'rev-list', '--count', 'HEAD'))).toBe(3);
    expect(parents(f.scratchGit, r.base.sha)).toEqual([]);
    expect(git(f.scratchGit, 'rev-list', '--count', 'main')).toBe('1');
    // nothing of the history reached the scratch repo
    expect(() => git(f.scratchGit, 'cat-file', '-e', git(f.app, 'rev-parse', 'HEAD~2:old-secret.txt'))).toThrow();
    expect(git(f.scratchGit, 'cat-file', '-p', r.base.sha)).not.toMatch(/^parent /m);
    await f.close();
  });

  it('snapshot: proof branch = base + changes, only parent is the base commit', async () => {
    const f = await fixture();
    const r = await pushProofSetup(input(f), deps(f).d);
    const main = r.branches.main;
    expect(main.branch).toBe(`proof/${RUN_ID}/main`);
    expect(heads(f.scratchGit)[main.branch]).toBe(main.sha);
    expect(parents(f.scratchGit, main.sha)).toEqual([r.base.sha]);
    const base = treeOf(f.scratchGit, r.base.sha);
    const proof = treeOf(f.scratchGit, main.sha);
    expect(Object.keys(proof).sort()).toEqual([...Object.keys(base), '.github/workflows/pipegen.yml', 'Dockerfile'].sort());
    expect(show(f.scratchGit, main.sha, 'Dockerfile')).toBe('FROM scratch');
    for (const p of Object.keys(base)) expect(show(f.scratchGit, main.sha, p)).toBe(show(f.scratchGit, r.base.sha, p));
    // the proof branches are never force-pushed (B3)
    expect(f.events.filter((e) => e.startsWith('push pipegen-proof-shop proof/'))).toEqual([`push pipegen-proof-shop proof/${RUN_ID}/main`, `push pipegen-proof-shop proof/${RUN_ID}/planted`]);
    await f.close();
  });

  it('snapshot: dirty tree warns and uses HEAD', async () => {
    const f = await fixture();
    put(f.app, 'src/app.js', 'console.log("uncommitted");\n');
    const { d, err } = deps(f);
    const r = await pushProofSetup(input(f), d);
    expect(r.base.dirtyWarning).toBe(true);
    expect(err.join('\n')).toMatch(/uncommitted changes are not part of the proof/);
    expect(show(f.scratchGit, 'main', 'src/app.js')).toBe('console.log(1);');
    // an untracked file alone also counts as dirty, and is not in the base
    const g = await fixture();
    put(g.app, 'untracked.txt', 'u\n');
    const two = deps(g);
    const r2 = await pushProofSetup(input(g), two.d);
    expect(r2.base.dirtyWarning).toBe(true);
    expect(two.err.join('\n')).toMatch(/uncommitted changes are not part of the proof/);
    expect(treeOf(g.scratchGit, 'main')['untracked.txt']).toBeUndefined();
    // a clean tree: no warning
    const h = await fixture();
    const three = deps(h);
    expect((await pushProofSetup(input(h), three.d)).base.dirtyWarning).toBe(false);
    expect(three.err.join('\n')).not.toMatch(/uncommitted/);
    for (const x of [f, g, h]) await x.close();
  });

  it('snapshot: token never appears in git argv or remote url', async () => {
    const f = await fixture();
    await pushProofSetup(input(f), deps(f).d);
    const calls = recorder.calls();
    const pushes = calls.filter((c) => c.argv.includes('push'));
    expect(pushes).toHaveLength(4);   // central, base, main, planted
    for (const c of calls) {
      expect(c.argv.join(' '), c.argv.join(' ')).not.toContain(TOKEN);
      for (const a of c.argv) if (/^[a-z]+:\/\//i.test(a)) expect(a).toMatch(new RegExp(`^https://github\\.com/${OWNER}/(${SCRATCH}|pipelines)\\.git$`));
      expect(c.argv.join(' ')).not.toMatch(/@github\.com|x-access-token/);
      // the token is in the environment of a push only (for its askpass), never of a plumbing call
      if (!c.argv.includes('push')) expect(Object.values(c.env).join('\n')).not.toContain(TOKEN);
    }
    for (const c of pushes) expect(c.env.PIPEGEN_GIT_TOKEN).toBe(TOKEN);
    // the server saw the token as Basic auth (the askpass answered), so the pushes were authenticated
    expect(servers[0]?.requests.some((q) => q.header !== undefined)).toBe(true);
    // and the transport refuses a value that is not token-shaped, or a target the guard didn't make
    await expect(gitTransport('not a token').push(assertScratch(f.target, { owner: OWNER, repo: 'shop' }), (await openProofSession(f.target)).repo, [{ sha: 'a'.repeat(40), branch: 'main' }], { force: true })).rejects.toThrow(/token/);
    await f.close();
  });

  it('snapshot: user workflow files are not in any pushed tree', async () => {
    const f = await fixture();
    // pipegen's own edit of a user workflow (Plan G insertVerify) and a pipegen file at a user workflow's path are left out
    const files = (sha: string | undefined) => [
      ...centralCaller(sha),
      created('.github/workflows/ci.yml', `${USER_CI}  verify:\n    runs-on: ubuntu-latest\n`, { inserted: { original: USER_CI, jobs: ['verify'], needs: [] } }),
      created('.github/workflows/deploy.yml', USER_CI, { inserted: { original: USER_CI, jobs: [], needs: [] } }),
      created('.github/workflows/Nested/DEEP.yaml', USER_CI),
    ];
    const r = await pushProofSetup(input(f, { appFiles: files }), deps(f).d);
    const pushedTrees: Record<string, string>[] = [];
    for (const bare of [f.scratchGit, f.pipelinesGit]) {
      for (const sha of Object.values(heads(bare))) {
        for (const c of git(bare, 'rev-list', sha).split('\n')) pushedTrees.push(treeOf(bare, c));
      }
    }
    const pipegenOwn = new Set(['.github/workflows/pipegen.yml']);
    for (const t of pushedTrees) {
      for (const p of USER_WORKFLOWS) expect(t[p]).toBeUndefined();
      expect(t['.github/workflows/deploy.yml']).toBeUndefined();
      for (const p of Object.keys(t).filter((x) => x.toLowerCase().startsWith('.github/workflows/'))) {
        // scratch trees: only pipegen's files; the central tree: pipelines' own and this project's central files
        expect(pipegenOwn.has(p) || ['.github/workflows/pipegen--sign.yml', '.github/workflows/shop--merge.yml'].includes(p), p).toBe(true);
      }
    }
    expect(r.leftOut.map((l) => l.path)).toEqual(expect.arrayContaining(['.github/workflows/ci.yml', '.github/workflows/deploy.yml', '.github/workflows/Nested/DEEP.yaml']));
    // the last line: pushProofBranch itself refuses a tree with a workflow pipegen didn't list
    const s = r.session;
    await expect(pushProofBranch(s, 'main', [[{ path: '.github/workflows/ci.yml', content: USER_CI }]], { transport: f.transport, pipegenWorkflows: new Set(['.github/workflows/pipegen.yml']) }))
      .rejects.toThrow(/workflow/);
    await expect(pushProofBranch(s, 'planted', [[{ path: '.GitHub/Workflows/x.yml', content: USER_CI }]], { transport: f.transport, pipegenWorkflows: new Set() }))
      .rejects.toThrow(/workflow/);
    // a workflow inherited from the parent commit that pipegen no longer lists is refused too (the tree check, not only added files)
    await expect(pushProofBranch(s, 'main', [[{ path: 'x.txt', content: 'x' }]], { transport: f.transport, pipegenWorkflows: new Set(), parent: r.branches.main.sha }))
      .rejects.toThrow(/pipegen\.yml is a workflow/);
    // a user workflow path given as pipegen's own is refused even when no file is added there
    await expect(pushProofBranch(s, 'planted', [[{ path: 'x.txt', content: 'x' }]], { transport: f.transport, pipegenWorkflows: new Set(['.github/workflows/CI.yml']), parent: r.branches.planted.sha }))
      .rejects.toThrow(/one of your workflows/);
    await s.remove();
    await f.close();
  });

  it('private: caller pinned to pipelines@centralSha', async () => {
    const f = await fixture();
    let asked: string | undefined = 'never';
    const r = await pushProofSetup(input(f, { appFiles: (sha) => { asked = sha; return centralCaller(sha); } }), deps(f).d);
    const central = heads(f.pipelinesGit)[`proof/${RUN_ID}`];
    expect(r.centralSha).toBe(central);
    expect(asked).toBe(central);
    expect(show(f.scratchGit, r.branches.main.sha, '.github/workflows/pipegen.yml')).toContain(`${OWNER}/pipelines/.github/workflows/shop--merge.yml@${central}`);
    // a caller pinned to another commit, or to a file the central commit doesn't hold, is refused before any proof branch
    for (const bad of [
      (sha: string | undefined) => centralCaller(sha, { sha: 'b'.repeat(40) }),
      () => [created('.github/workflows/pipegen.yml', 'jobs:\n  p:\n    uses: CrisWorking/pipelines/.github/workflows/missing.yml@SHA\n')],
      () => localLayout(),
    ]) {
      const g = await fixture();
      const files = (sha: string | undefined) => bad(sha).map((x) => ({ ...x, content: x.content.replace('@SHA', `@${sha ?? ''}`) }));
      await expect(pushProofSetup(input(g, { appFiles: files }), deps(g).d)).rejects.toThrow(ProofStopError);
      expect(Object.keys(heads(g.scratchGit)).filter((b) => b.startsWith('proof/'))).toEqual([]);
      expect(g.events).not.toContain('store-secrets');
      await g.close();
    }
    await f.close();
  });

  it('layout: no centralPin → no central push; caller + local merge workflow in the proof branch', async () => {
    const f = await fixture();
    const before = heads(f.pipelinesGit);
    let asked: string | undefined = 'never';
    const r = await pushProofSetup(input(f, { central: undefined, appFiles: (sha) => { asked = sha; return localLayout(); } }), deps(f).d);
    expect(asked).toBeUndefined();
    expect(r.centralSha).toBeUndefined();
    expect(heads(f.pipelinesGit)).toEqual(before);
    expect(f.calls.filter((c) => c.url.pathname.includes('/pipelines'))).toEqual([]);
    expect(recorder.calls().filter((c) => c.argv.some((a) => a.includes('/pipelines.git')))).toEqual([]);
    const tree = treeOf(f.scratchGit, r.branches.main.sha);
    expect(tree['.github/workflows/pipegen.yml']).toBe('100644');
    expect(tree['.github/workflows/pipegen-merge.yml']).toBe('100644');
    expect(show(f.scratchGit, r.branches.main.sha, '.github/workflows/pipegen.yml')).toContain('uses: ./.github/workflows/pipegen-merge.yml');
    // a central `uses` without a central layout is refused
    const g = await fixture();
    await expect(pushProofSetup(input(g, { central: undefined, appFiles: () => centralCaller('c'.repeat(40)) }), deps(g).d)).rejects.toThrow(/no central pin/);
    await g.close();
    await f.close();
  });

  it('planted: every proof pushes a main and a planted branch; planted files only on planted', async () => {
    const f = await fixture();
    const r = await pushProofSetup(input(f), deps(f).d);
    const b = heads(f.scratchGit);
    expect(Object.keys(b).filter((x) => x.startsWith('proof/')).sort()).toEqual([`proof/${RUN_ID}/main`, `proof/${RUN_ID}/planted`]);
    const main = treeOf(f.scratchGit, r.branches.main.sha);
    const planted = treeOf(f.scratchGit, r.branches.planted.sha);
    expect(parents(f.scratchGit, r.branches.planted.sha)).toEqual([r.base.sha]);
    const plantedOnly = Object.keys(planted).filter((p) => !(p in main));
    expect(plantedOnly).toContain('pipegen-planted/sql.js');
    for (const e of r.planted.filter((x) => x.kind === 'secret')) expect(Object.keys(planted)).toContain(e.path);
    // main holds no planted file, and planted holds every main file with the same content
    for (const p of plantedOnly) expect(main[p]).toBeUndefined();
    for (const p of Object.keys(main)) expect(planted[p]).toBe(main[p]);
    for (const p of Object.keys(main)) if (p !== '.gitleaksignore') expect(show(f.scratchGit, r.branches.planted.sha, p)).toBe(show(f.scratchGit, r.branches.main.sha, p));
    // a planted file may not be a workflow (it would run), nor be missing
    const g = await fixture();
    await expect(pushProofSetup(input(g, { plantedFiles: [{ path: '.github/workflows/evil.yml', content: USER_CI }] }), deps(g).d)).rejects.toThrow(/workflow/);
    // refused before anything is written: no secret stored, nothing pushed
    expect(g.events).toEqual([]);
    await g.close();
    await f.close();
  });

  it('order: secrets stored only after the no-user-run check, before the proof branch push', async () => {
    const f = await fixture({ appDefault: 'develop', scratchEmpty: true });
    f.workflows.push({ id: 7, path: '.github/workflows/old-user.yml', state: 'active' });
    const r = await pushProofSetup(input(f, { defaultBranchState: 'pending' }), deps(f).d);
    const at = (pred: (e: string) => boolean) => f.events.findIndex(pred);
    const order = [
      at((e) => e === 'DELETE pipegen-proof-shop/automated-security-fixes'),
      at((e) => e.startsWith('push pipelines proof/')),
      at((e) => e === 'push pipegen-proof-shop +develop'),
      at((e) => e.startsWith('PUT pipegen-proof-shop/actions/workflows/7/disable')),
      at((e) => e === 'GET pipegen-proof-shop/actions/runs'),
      at((e) => e === 'store-secrets'),
      at((e) => e === `push pipegen-proof-shop proof/${RUN_ID}/main`),
      at((e) => e === `push pipegen-proof-shop proof/${RUN_ID}/planted`),
    ];
    expect(order.every((i) => i >= 0), f.events.join('\n')).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(f.events.filter((e) => e === 'store-secrets')).toHaveLength(1);
    expect(f.stored[0]?.repo).toBe(SCRATCH);
    // the runs check asked about the base sha
    const runsCall = f.calls.find((c) => c.url.pathname.endsWith('/actions/runs'));
    expect(runsCall?.url.searchParams.get('head_sha')).toBe(r.base.sha);
    // E1 carry: the scratch repo was empty, so its default branch is set again after the base push (S1)
    expect(r.defaultBranchState).toBe('already');
    const repoRead = f.calls.findIndex((c, i) => i > 0 && c.method === 'GET' && c.url.pathname === `/repos/${OWNER}/${SCRATCH}`);
    expect(repoRead).toBeGreaterThanOrEqual(0);
    expect(git(f.scratchGit, 'symbolic-ref', '--short', 'HEAD')).toBe('main');   // the fake keeps HEAD; GitHub's default is the only branch
    expect(Object.keys(heads(f.scratchGit))).toContain('develop');

    // a run for the base sha → stop with an alert: no secret stored, no proof branch pushed
    const g = await fixture({ runs: 1 });
    await expect(pushProofSetup(input(g), deps(g).d)).rejects.toThrow(/workflow run started/);
    expect(g.events).not.toContain('store-secrets');
    expect(g.events.some((e) => e.includes(`proof/${RUN_ID}/`))).toBe(false);
    // the secret store fails → no proof branch pushed
    const h = await fixture();
    const dh = deps(h).d;
    await expect(pushProofSetup(input(h), { ...dh, storeSecrets: async () => { h.events.push('store-secrets'); throw new Error('store failed'); } })).rejects.toThrow(/store failed/);
    expect(h.events.some((e) => e.includes(`proof/${RUN_ID}/`))).toBe(false);
    // a stop begun during the store: no push after it
    const k = await fixture();
    const dk = deps(k).d;
    await expect(pushProofSetup(input(k), { ...dk, storeSecrets: async () => { k.events.push('store-secrets'); vi.mocked(interrupting).mockReturnValue(true); } })).rejects.toThrow(/stopping/);
    expect(k.events.some((e) => e.includes(`proof/${RUN_ID}/`))).toBe(false);
    vi.mocked(interrupting).mockReturnValue(false);
    for (const x of [f, g, h, k]) await x.close();
  });

  it('disable: every user workflow disabled, pipegen ones untouched', async () => {
    const f = await fixture();
    f.workflows.push(
      { id: 1, path: '.github/workflows/ci.yml', state: 'active' },
      { id: 2, path: '.github/workflows/pipegen.yml', state: 'active' },
      { id: 3, path: '.github/workflows/release.yml', state: 'disabled_manually' },
      { id: 4, path: 'dynamic/dependabot/dependabot-updates', state: 'active' },
      { id: 5, path: '.github/workflows/pipegen-merge.yml', state: 'active' },
    );
    const r = await pushProofSetup(input(f), deps(f).d);
    expect(r.disabled.sort()).toEqual(['.github/workflows/ci.yml', '.github/workflows/pipegen-merge.yml', 'dynamic/dependabot/dependabot-updates']);
    const puts = f.calls.filter((c) => c.method === 'PUT').map((c) => c.url.pathname);
    expect(puts.sort()).toEqual([1, 4, 5].map((id) => `/repos/${OWNER}/${SCRATCH}/actions/workflows/${id}/disable`));
    // the direct call: pipegen's paths are exactly what it is given; the write goes through the guard
    const g = await fixture();
    g.workflows.push({ id: 9, path: '.github/workflows/x.yml', state: 'active' });
    const scratch = assertScratch(g.target, { owner: OWNER, repo: 'shop' });
    expect(await disableUserWorkflows(g.gh, scratch, new Set(['.github/workflows/x.yml']))).toEqual([]);
    await expect(disableUserWorkflows(g.gh, assertCentral(g.target, { owner: OWNER, repo: 'shop' }), new Set())).rejects.toThrow(ScratchGuardError);
    await expect(disableUserWorkflows(g.gh, { ...scratch }, new Set())).rejects.toThrow(ScratchGuardError);
    for (const x of [f, g]) await x.close();
  });

  it('snapshot: export-ignore files are in the base', async () => {
    const f = await fixture();
    const r = await pushProofSetup(input(f), deps(f).d);
    expect(show(f.scratchGit, r.base.sha, 'docs/ignored.md')).toBe('kept even though export-ignore');
    expect(show(f.scratchGit, r.base.sha, 'version.txt')).toBe('$Format:%H$');   // export-subst not applied
    expect(show(f.scratchGit, r.base.sha, '.gitattributes')).toContain('export-ignore');
    await f.close();
  });

  it('snapshot: .github/dependabot.yml and renovate configs left out of base and proof trees', async () => {
    const f = await fixture();
    const files = (sha: string | undefined) => [...centralCaller(sha), created('.github/dependabot.yml', 'version: 2\nupdates: []\n'), created('.github/DEPENDABOT.YAML', 'version: 2\n'), created('.renovaterc.json5', '{}\n')];
    const r = await pushProofSetup(input(f, { appFiles: files }), deps(f).d);
    const bots = [...BOTS, '.github/DEPENDABOT.YAML', '.renovaterc.json5'];
    for (const sha of [r.base.sha, r.branches.main.sha, r.branches.planted.sha]) {
      const t = treeOf(f.scratchGit, sha);
      for (const p of bots) expect(t[p], `${p} in ${sha}`).toBeUndefined();
      expect(t['.github/CODEOWNERS']).toBe('100644');   // the gate reads it (S5)
    }
    expect(r.leftOut.map((l) => l.path)).toEqual(expect.arrayContaining(['.github/dependabot.yml', '.github/DEPENDABOT.YAML', '.renovaterc.json5']));
    // S5: Dependabot security updates turned off on the scratch repo, through the guard
    expect(f.calls.filter((c) => c.method === 'DELETE').map((c) => c.url.pathname)).toEqual([`/repos/${OWNER}/${SCRATCH}/automated-security-fixes`]);
    await f.close();
  });

  it('snapshot: a symlink inside a service with a docker part → docker not-proven', async () => {
    const f = await fixture();
    put(f.app, 'api/server.js', 'x\n');
    put(f.app, 'web/index.js', 'y\n');
    symlinkSync('/etc', join(f.app, 'api', 'etc-link'));
    symlinkSync('../api', join(f.app, 'web', 'up'));
    commitAll(f.app, 'links');
    const r = await pushProofSetup(input(f, { dockerServices: [{ name: 'api', path: 'api' }, { name: 'other', path: 'other' }] }), deps(f).d);
    const docker = r.notProven.filter((x) => x.part === 'docker');
    expect(docker).toHaveLength(1);
    expect(docker[0]?.reason).toMatch(/api.*symlink.*api\/etc-link/s);
    expect(treeOf(f.scratchGit, r.base.sha)['api/etc-link']).toBeUndefined();
    // the rule itself: a root service ('.') holds every symlink; a service without a docker part is not named
    const dropped = [{ path: 'api/etc-link', why: 'symlink' as const }, { path: 'web/up', why: 'symlink' as const }, { path: 'sub', why: 'submodule' as const }];
    expect(symlinkNotProven(dropped, [{ name: 'root', path: '.' }]).map((x) => x.reason)[0]).toMatch(/api\/etc-link.*web\/up/s);
    expect(symlinkNotProven(dropped, [{ name: 'web', path: 'web' }])).toHaveLength(1);
    expect(symlinkNotProven(dropped, [{ name: 'apix', path: 'apix' }, { name: 'ap', path: 'ap' }])).toEqual([]);
    expect(symlinkNotProven(dropped, [])).toEqual([]);
    await f.close();
  });

  it('central: proof/<runId> = pipelines default head + this project\'s central files; no other ref touched', async () => {
    const f = await fixture();
    const before = heads(f.pipelinesGit);
    const r = await pushProofSetup(input(f), deps(f).d);
    const after = heads(f.pipelinesGit);
    expect(Object.keys(after).sort()).toEqual(['main', `proof/${RUN_ID}`]);
    expect(after.main).toBe(before.main);
    const sha = after[`proof/${RUN_ID}`] as string;
    expect(r.centralSha).toBe(sha);
    const head = treeOf(f.pipelinesGit, 'main');
    const proof = treeOf(f.pipelinesGit, sha);
    expect(proof).toEqual({ ...head, '.github/workflows/shop--merge.yml': '100644' });
    for (const p of Object.keys(head)) expect(show(f.pipelinesGit, sha, p)).toBe(show(f.pipelinesGit, 'main', p));
    expect(show(f.pipelinesGit, sha, '.github/workflows/shop--merge.yml')).toBe(CENTRAL_MERGE.trim());
    // a central file replaces the head's file of the same path
    const g = await fixture({ pipelinesFiles: { '.github/workflows/shop--merge.yml': SHARED_SIGN, 'a.txt': 'a\n' } });
    const r2 = await pushProofSetup(input(g), deps(g).d);
    expect(show(g.pipelinesGit, r2.centralSha as string, '.github/workflows/shop--merge.yml')).toBe(CENTRAL_MERGE.trim());
    expect(show(g.pipelinesGit, r2.centralSha as string, 'a.txt')).toBe('a');
    // the transport pushes to pipelines only refs/heads/proof/<runId>, never forced
    const s = await openProofSession(f.target);
    const central = assertCentral(f.target, { owner: OWNER, repo: 'shop' });
    for (const [refs, force] of [[[{ sha, branch: 'main' }], false], [[{ sha, branch: `proof/20261103-120000-000000` }], false], [[{ sha, branch: `proof/${RUN_ID}` }], true]] as const) {
      await expect(gitTransport(TOKEN).push(central, s.repo, refs, { force })).rejects.toThrow(ScratchGuardError);
    }
    // nor to the scratch repo any branch but its default and proof/<runId>/…; the default branch only forced, proof branches never
    const scratch = assertScratch(f.target, { owner: OWNER, repo: 'shop' });
    for (const [branch, force] of [['other', false], [`proof/20261103-120000-000000/main`, false], [`proof/${RUN_ID}/main`, true], [`proof/${RUN_ID}`, false]] as const) {
      await expect(gitTransport(TOKEN).push(scratch, s.repo, [{ sha, branch }], { force }), branch).rejects.toThrow(ScratchGuardError);
    }
    await s.remove();
    for (const x of [f, g]) await x.close();
  });

  it('central: no central workflow has a push or pull_request trigger', async () => {
    const yml = (on: string) => `on: ${on}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n`;
    const bad = ['push', '[push]', '{ pull_request: {} }', '[workflow_call, pull_request_target]', '{ create: {} }', '{ workflow_run: { workflows: [x] } }', '{ merge_group: {} }', 'issues', '"not yaml'];
    for (const on of bad) {
      expect(checkCentralTriggers([{ path: '.github/workflows/x.yml', content: yml(on) }]), on).not.toEqual([]);
    }
    for (const on of ['workflow_call', '[workflow_call]', '{ workflow_call: { inputs: {} } }', '{ workflow_dispatch: {}, schedule: [{ cron: "0 0 * * *" }] }']) {
      expect(checkCentralTriggers([{ path: '.github/workflows/x.yml', content: yml(on) }]), on).toEqual([]);
    }
    // only workflow files are judged
    expect(checkCentralTriggers([{ path: 'records/x.yml', content: yml('push') }])).toEqual([]);
    // this project's central file with a push trigger, or one in pipelines' default head: refused before anything is pushed
    const f = await fixture();
    const draft = { files: [created('.github/workflows/shop--merge.yml', yml('{ workflow_call: {}, push: {} }'), { repo: 'central' })] };
    await expect(pushProofSetup(input(f, { central: draft }), deps(f).d)).rejects.toThrow(/shop--merge\.yml.*push/s);
    expect(heads(f.pipelinesGit)[`proof/${RUN_ID}`]).toBeUndefined();
    const g = await fixture({ pipelinesFiles: { '.github/workflows/ci.yml': yml('push') } });
    await expect(pushProofSetup(input(g), deps(g).d)).rejects.toThrow(/ci\.yml/);
    expect(heads(g.pipelinesGit)[`proof/${RUN_ID}`]).toBeUndefined();
    expect(g.events.some((e) => e.startsWith('push'))).toBe(false);
    // a central draft file that is not central, or an app file marked central, is refused
    const h = await fixture();
    await expect(pushProofSetup(input(h, { central: { files: [created('.github/workflows/shop--merge.yml', CENTRAL_MERGE)] } }), deps(h).d)).rejects.toThrow(/central/);
    for (const x of [f, g, h]) await x.close();
  });

  it('planted: C1b placements outside pipegen-planted/, each listed as expected', async () => {
    const f = await fixture();
    put(f.app, 'package-lock.json', '{"lockfileVersion":3}\n');
    put(f.app, '.gitleaksignore', 'user/own:generic-api-key:1\n');
    commitAll(f.app, 'lock');
    const r = await pushProofSetup(input(f), deps(f).d);
    const secrets = r.planted.filter((x) => x.kind === 'secret');
    const wanted = ['gitleaks.toml/app.js', 'src.gitleaks.toml.js', 'node_modules/x.js', 'vendor/bundle/x.rb', 'env/lib/x.py', 'docs/x.svg', 'docs/x.pdf', 'go.sum', 'pipegen-c1b/package-lock.json'];
    for (const w of wanted) expect(secrets.map((x) => x.path), w).toContain(w);
    // a non-UTF-8 file name, pushed as its bytes
    const raw = secrets.find((x) => x.nonUtf8 === true);
    expect(raw).toBeDefined();
    const plantedTree = gitBuf(f.scratchGit, 'ls-tree', '-r', '-z', '--name-only', r.branches.planted.sha).toString('latin1').split('\0');
    expect(plantedTree).toContain(Buffer.from(raw?.pathBytes as Uint8Array).toString('latin1'));
    const plantedBlobs = blobsByRawPath(f.scratchGit, r.branches.planted.sha);
    for (const x of secrets) {
      expect(x.path.startsWith('pipegen-planted/'), x.path).toBe(false);
      expect(x.rule).toBe('generic-api-key');
      // the expected line holds the planted value, a generic high-entropy value of no provider format
      const text = (plantedBlobs.get(Buffer.from(x.pathBytes).toString('latin1')) as Buffer).toString('utf8');
      const line = text.split('\n')[x.line - 1] as string;
      expect(line, x.path).toMatch(/api_key"?\s*[:=]\s*"[A-Za-z0-9]{32}"/);
      const value = /"([A-Za-z0-9]{32})"/.exec(line)?.[1] as string;
      expect(value).toMatch(/[0-9]/);
      expect(value).toMatch(/[A-Z]/);
      expect(value).toMatch(/[a-z]/);
    }
    // the user's own package-lock.json is untouched; the .gitleaksignore keeps the user's lines and names every placement
    expect(show(f.scratchGit, r.branches.planted.sha, 'package-lock.json')).toBe('{"lockfileVersion":3}');
    const ignore = (plantedBlobs.get('.gitleaksignore') as Buffer).toString('latin1');
    expect(ignore.startsWith('user/own:generic-api-key:1\n')).toBe(true);
    for (const x of secrets) expect(ignore).toContain(`${Buffer.from(x.pathBytes).toString('latin1')}:generic-api-key:${x.line}`);
    expect(r.planted.find((x) => x.path === '.gitleaksignore')?.kind).toBe('integrity-warning');
    // nothing of it on main
    expect(show(f.scratchGit, r.branches.main.sha, '.gitleaksignore')).toBe('user/own:generic-api-key:1');
    for (const x of secrets) expect(treeOf(f.scratchGit, r.branches.main.sha)[x.path]).toBeUndefined();
    // fresh values each call; a path the base already holds (or a folder of it) moves under pipegen-c1b/
    const a = plantedSecretPlacements(new Set());
    const b = plantedSecretPlacements(new Set(['go.sum', 'docs/x.svg/inner', 'node_modules']));
    expect(a.expected.map((x) => x.path)).toContain('go.sum');
    expect(b.expected.map((x) => x.path)).toEqual(expect.arrayContaining(['pipegen-c1b/go.sum', 'pipegen-c1b/docs/x.svg', 'pipegen-c1b/node_modules/x.js']));
    const valueOf = (s: ReturnType<typeof plantedSecretPlacements>) => Buffer.from(s.files.find((x) => x.path === 'go.sum' || x.path === 'pipegen-c1b/go.sum')?.content as Uint8Array).toString();
    expect(valueOf(a)).not.toBe(valueOf(b));
    await f.close();
  });

  it('planted: variant may carry more than one commit (fast-forward)', async () => {
    const f = await fixture();
    const r = await pushProofSetup(input(f), deps(f).d);
    const s = r.session;
    const own = new Set(['.github/workflows/pipegen.yml']);
    // two commits in one push: the first on the planted tip, the second on the first
    const two = await pushProofBranch(s, 'planted', [[{ path: 'pipegen-planted/step1.txt', content: 'one\n' }], [{ path: 'pipegen-planted/step2.txt', content: 'two\n' }]], { transport: f.transport, pipegenWorkflows: own, parent: r.branches.planted.sha });
    expect(two.commits).toHaveLength(2);
    expect(parents(f.scratchGit, two.commits[0] as string)).toEqual([r.branches.planted.sha]);
    expect(parents(f.scratchGit, two.commits[1] as string)).toEqual([two.commits[0]]);
    expect(heads(f.scratchGit)[`proof/${RUN_ID}/planted`]).toBe(two.sha);
    const t = treeOf(f.scratchGit, two.sha);
    expect(t['pipegen-planted/step1.txt']).toBe('100644');
    expect(t['pipegen-planted/sql.js']).toBe('100644');
    // a branch that doesn't fast-forward is refused by GitHub (no force): nothing changes
    await expect(pushProofBranch(s, 'planted', [[{ path: 'x.txt', content: 'x\n' }]], { transport: f.transport, pipegenWorkflows: own })).rejects.toThrow();
    expect(heads(f.scratchGit)[`proof/${RUN_ID}/planted`]).toBe(two.sha);
    // the recorder: no proof branch refspec was ever forced
    for (const c of recorder.calls().filter((x) => x.argv.includes('push'))) {
      for (const a of c.argv.filter((x) => x.includes(':refs/heads/proof/'))) expect(a.startsWith('+'), a).toBe(false);
    }
    // a parent pipegen didn't make in this session is refused before any git push
    await expect(pushProofBranch(s, 'planted', [[{ path: 'y', content: 'y' }]], { transport: f.transport, pipegenWorkflows: own, parent: 'd'.repeat(40) })).rejects.toThrow(/parent/);
    // the central commit (made in this session, in pipelines) is never a scratch parent
    await expect(pushProofBranch(s, 'planted', [[{ path: 'y', content: 'y' }]], { transport: f.transport, pipegenWorkflows: own, parent: r.centralSha as string })).rejects.toThrow(/parent/);
    // a dispute variant name is checked
    await expect(pushProofBranch(s, 'dispute-../x-a' as never, [[]], { transport: f.transport, pipegenWorkflows: own })).rejects.toThrow(/variant/);
    await s.remove();
    await f.close();
  });

  it('planted: push protection rejection (GH013) → clear stop', async () => {
    const f = await fixture();
    // the scratch repo's pre-receive answers like GitHub push protection for the planted branch
    const hook = join(f.scratchGit, 'hooks', 'pre-receive');
    writeFileSync(hook, [
      '#!/bin/sh',
      'while read old new ref; do',
      '  case "$ref" in */planted)',
      '    echo "error: GH013: Repository rule violations found for $ref." >&2',
      '    echo "- GITHUB PUSH PROTECTION" >&2',
      '    echo "  Push cannot contain secrets" >&2',
      '    exit 1 ;;',
      '  esac',
      'done',
      'exit 0',
      '',
    ].join('\n'));
    chmodSync(hook, 0o755);
    const err = await pushProofSetup(input(f), deps(f).d).then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(ProofStopError);
    expect(String((err as Error).message)).toMatch(/push protection/i);
    expect(String((err as Error).message)).toMatch(/planted/);
    expect(String((err as Error).message)).toMatch(/GH013/);
    expect(String((err as Error).message)).not.toContain(TOKEN);
    expect(heads(f.scratchGit)[`proof/${RUN_ID}/planted`]).toBeUndefined();
    // the same refusal of the base push names the user's own code
    const g = await fixture();
    const hook2 = join(g.scratchGit, 'hooks', 'pre-receive');
    writeFileSync(hook2, '#!/bin/sh\necho "error: GH013: Repository rule violations found for refs/heads/main." >&2\nexit 1\n');
    chmodSync(hook2, 0o755);
    const err2 = await pushProofSetup(input(g), deps(g).d).then(() => null, (e: unknown) => e);
    expect(err2).toBeInstanceOf(ProofStopError);
    expect(String((err2 as Error).message)).toMatch(/your HEAD|your code/);
    expect(g.events).not.toContain('store-secrets');
    for (const x of [f, g]) await x.close();
  });
});

describe('E2 more (carries and edges)', () => {
  it('snapshot: filter=lfs → a docker service holding LFS pointer files is not-proven; others warned', async () => {
    const f = await fixture();
    put(f.app, '.gitattributes', '*.bin filter=lfs diff=lfs merge=lfs -text\n');
    put(f.app, 'api/model.bin', 'version https://git-lfs.github.com/spec/v1\noid sha256:' + '0'.repeat(64) + '\nsize 12\n');
    put(f.app, 'web/x.bin', 'version https://git-lfs.github.com/spec/v1\noid sha256:' + '1'.repeat(64) + '\nsize 3\n');
    commitAll(f.app, 'lfs');
    const { d, err } = deps(f);
    const r = await pushProofSetup(input(f, { dockerServices: [{ name: 'api', path: 'api' }] }), d);
    expect(r.base.lfs?.pointers.sort()).toEqual(['api/model.bin', 'web/x.bin']);
    const lfs = r.notProven.filter((x) => /LFS/.test(x.reason));
    expect(lfs.map((x) => x.part)).toEqual(['docker']);
    expect(lfs[0]?.reason).toMatch(/api/);
    expect(err.join('\n')).toMatch(/Git LFS/);
    // no filter=lfs: no LFS facts even with a pointer-looking file
    const g = await fixture();
    expect((await pushProofSetup(input(g), deps(g).d)).base.lfs).toBeNull();
    for (const x of [f, g]) await x.close();
  });

  it('stop gate: no push or write starts once a stop has begun', async () => {
    const f = await fixture();
    vi.mocked(interrupting).mockReturnValue(true);
    await expect(pushProofSetup(input(f), deps(f).d)).rejects.toThrow(/stopping/);
    expect(f.events).toEqual([]);
    expect(f.calls.filter((c) => c.method !== 'GET')).toEqual([]);
    expect(recorder.calls().filter((c) => c.argv.includes('push'))).toEqual([]);
    vi.mocked(interrupting).mockReturnValue(false);
    await f.close();
  });

  it('session: pushBase twice and a session of another target are refused; a removed session pushes nothing', async () => {
    const f = await fixture();
    const s = await openProofSession(f.target);
    const io = { out: () => {}, err: () => {} };
    await pushBase(s, f.app, { transport: f.transport, io });
    await expect(pushBase(s, f.app, { transport: f.transport, io })).rejects.toThrow(/once/);
    await expect(openProofSession({ ...f.target } as ProofTarget)).rejects.toThrow(ScratchGuardError);
    await s.remove();
    await expect(pushProofBranch(s, 'main', [[]], { transport: f.transport, pipegenWorkflows: new Set() })).rejects.toThrow();
    // a proof branch before the base is refused
    const s2 = await openProofSession(f.target);
    await expect(pushProofBranch(s2, 'main', [[]], { transport: f.transport, pipegenWorkflows: new Set() })).rejects.toThrow(/base/);
    await s2.remove();
    await f.close();
  });

  it('paths: a created or planted path that is not a plain repo path is refused', async () => {
    const f = await fixture();
    const r = await pushProofSetup(input(f), deps(f).d);
    const own = new Set(['.github/workflows/pipegen.yml']);
    for (const p of ['../x', '/abs', 'a//b', 'a/./b', '.git/config', 'a/.GIT/x', 'x/.git. /y', '', 'a/', 'nul\0x']) {
      await expect(pushProofBranch(r.session, 'main', [[{ path: p, content: 'x' }]], { transport: f.transport, pipegenWorkflows: own, parent: r.branches.main.sha }), JSON.stringify(p)).rejects.toThrow(/path/);
    }
    // a file where the tree has a folder (and the other way round)
    await expect(pushProofBranch(r.session, 'main', [[{ path: 'src', content: 'x' }]], { transport: f.transport, pipegenWorkflows: own, parent: r.branches.main.sha })).rejects.toThrow(/folder/);
    await expect(pushProofBranch(r.session, 'main', [[{ path: 'run.sh/x', content: 'x' }]], { transport: f.transport, pipegenWorkflows: own, parent: r.branches.main.sha })).rejects.toThrow(/folder/);
    await r.session.remove();
    await f.close();
  });

  it('dependabot off: GitHub refusing it is a warning, not a stop', async () => {
    const f = await fixture();
    const { d, err } = deps(f);
    // the same fixture, but DELETE automated-security-fixes answers 403
    const gh = f.gh;
    const wrapped = new Proxy(gh, {
      get(target, key, recv) {
        if (key !== 'request') return Reflect.get(target, key, recv);
        return (route: string, params: Record<string, unknown>) => {
          if (route === 'DELETE /repos/{owner}/{repo}/automated-security-fixes') {
            f.events.push('DELETE refused');
            return Promise.reject(Object.assign(new Error('Resource not accessible by personal access token'), { status: 403 }));
          }
          return target.request(route as never, params as never);
        };
      },
    });
    const r = await pushProofSetup(input(f), { ...d, gh: wrapped });
    expect(err.join('\n')).toMatch(/Dependabot security updates/);
    expect(r.warnings.join('\n')).toMatch(/Dependabot security updates/);
    expect(r.branches.planted.sha).toMatch(/^[0-9a-f]{40}$/);
    await f.close();
  });
});

describe('E2 central default head read (S21)', () => {
  it('central: a default head pipegen can\'t copy exactly (truncated, a blob that does not hash back) → stop, nothing pushed', async () => {
    const f = await fixture();
    const { fetch } = fakeFetch(new Proxy({}, {
      get: () => (c: Call): Reply => {
        const p = decodeURIComponent(c.url.pathname);
        if (p === `/repos/${OWNER}/pipelines`) return json(200, { default_branch: 'main' });
        if (p.endsWith('/git/ref/heads/main')) return json(200, { object: { sha: '1'.repeat(40) } });
        // a list that is consistent (the empty tree) but cut short: only the truncated flag can stop it
        if (p.includes('/git/commits/')) return json(200, { tree: { sha: EMPTY_TREE } });
        if (p.includes('/git/trees/')) return json(200, { sha: EMPTY_TREE, truncated: true, tree: [] });
        return json(404, {});
      },
    }) as never);
    const gh = makeOctokit(fake.githubPat(), { fetch, log: () => {} });
    await expect(pushProofSetup(input(f), { ...deps(f).d, gh })).rejects.toThrow(/pipelines/);
    expect(f.events.some((e) => e.startsWith('push'))).toBe(false);
    const g = await fixture();
    const { fetch: fetch2 } = fakeFetch(new Proxy({}, {
      get: () => (c: Call): Reply => {
        const p = decodeURIComponent(c.url.pathname);
        if (p === `/repos/${OWNER}/pipelines`) return json(200, { default_branch: 'main' });
        if (p.endsWith('/git/ref/heads/main')) return json(200, { object: { sha: '1'.repeat(40) } });
        if (p.includes('/git/commits/')) return json(200, { tree: { sha: '2'.repeat(40) } });
        if (p.includes('/git/trees/')) return json(200, { sha: '2'.repeat(40), truncated: false, tree: [{ path: 'a.txt', mode: '100644', type: 'blob', sha: '3'.repeat(40), size: 2 }] });
        if (p.includes('/git/blobs/')) return json(200, { encoding: 'base64', content: Buffer.from('a\n').toString('base64'), size: 2 });
        return json(404, {});
      },
    }) as never);
    const gh2 = makeOctokit(fake.githubPat(), { fetch: fetch2, log: () => {} });
    await expect(pushProofSetup(input(g), { ...deps(g).d, gh: gh2 })).rejects.toThrow(/pipelines/);
    expect(g.events.some((e) => e.startsWith('push'))).toBe(false);
    // every blob hashes back, but the files don't rebuild the head's tree (an entry left out of the list): stop
    const h = await fixture();
    const blobA = execFileSync(REAL_GIT, ['hash-object', '--stdin'], { input: 'a\n', encoding: 'utf8' }).trim();
    const { fetch: fetch3 } = fakeFetch(new Proxy({}, {
      get: () => (c: Call): Reply => {
        const p = decodeURIComponent(c.url.pathname);
        if (p === `/repos/${OWNER}/pipelines`) return json(200, { default_branch: 'main' });
        if (p.endsWith('/git/ref/heads/main')) return json(200, { object: { sha: '1'.repeat(40) } });
        if (p.includes('/git/commits/')) return json(200, { tree: { sha: '2'.repeat(40) } });
        if (p.includes('/git/trees/')) return json(200, { sha: '2'.repeat(40), truncated: false, tree: [{ path: 'a.txt', mode: '100644', type: 'blob', sha: blobA, size: 2 }] });
        if (p.includes('/git/blobs/')) return json(200, { encoding: 'base64', content: Buffer.from('a\n').toString('base64'), size: 2 });
        return json(404, {});
      },
    }) as never);
    const gh3 = makeOctokit(fake.githubPat(), { fetch: fetch3, log: () => {} });
    await expect(pushProofSetup(input(h), { ...deps(h).d, gh: gh3 })).rejects.toThrow(/rebuild its head tree exactly/);
    expect(h.events.some((e) => e.startsWith('push'))).toBe(false);
    for (const x of [f, g, h]) await x.close();
  });
});
