// Plan E E0c (rulings B6 and S4; DECISIONS #111): the git transport. The proof pushes the base snapshot and the proof
// branches to the private scratch repo, and the draft central workflows to `pipelines`, with the git CLI; and it reads the
// user's HEAD with git plumbing. Every git call here:
//
// - runs through execa with an argv (no shell) and an environment built from scratch (gitEnv): PATH, a temp HOME, LANG=C,
//   no terminal or credential-manager prompts, no system config, global config = /dev/null. Nothing else is inherited:
//   no GIT_* variable of the user's (GIT_DIR, GIT_CONFIG_*, GIT_TRACE, GIT_SSL_NO_VERIFY, …), no proxy, no other token;
// - starts with HARDENED_CONFIG: `credential.helper=` empties the helper list (git reads `-c` last, so every helper from
//   any config file, a URL-specific one included, is dropped: the token is never stored in a keychain or a file, and no
//   helper ever sees it), hooks and fsmonitor off, only https allowed, redirects never followed;
// - runs with its working directory in pipegen's own 0700 temp dir (never in the user's repo: on Windows the program
//   lookup searches the working directory first), the user's repo reached with `-C`;
// - shows git's output only through shownGitOutput (hideToken, before and after control characters are removed).
//
// Pushes (gitPush) go only to https://github.com/<owner>/pipegen-proof-<repo>.git or https://github.com/<owner>/pipelines.git
// (checkPushUrl, an exact pattern), and only from a repo made by createPushRepo (an unforgeable handle: the check of its
// config and the push are two processes, which is safe only because nobody else can write pipegen's 0700 temp dir). This is the one exception to "the token goes only to api.github.com" (DECISIONS #64,
// #111). The token never goes into argv, a URL, a file or the output: it is in the git child's environment only
// (PIPEGEN_GIT_TOKEN), and GIT_ASKPASS points at a script in a fresh 0700 temp dir that prints `x-access-token` or that
// variable, and only for git's two prompts for https://github.com. The dir is removed after the push, and by a sync exit
// hook when the process stops first. The push repo's own config may hold only the keys `git init` writes
// (PUSH_REPO_KEYS): an `insteadOf`, `pushInsteadOf`, `include.path`, helper, proxy or extra header there refuses the push,
// and the environment leaves no other config file. No push starts once a stop has begun (the sticky interrupting() gate,
// checked on entry and again right before git starts), and a push in flight is killed when one begins.
//
// The snapshot read (ruling S4, a recorded exception to P55 "never run git"): readSnapshot lists HEAD with
// `ls-tree -r -z -l --full-tree` and reads the blobs with `cat-file --batch`, never `git archive` (export-ignore and
// export-subst would hide or change files there). Replace refs are ignored. Symlinks (120000) and submodules (160000) are
// dropped and listed, as are names that are not UTF-8 or not safe paths (.git and its Windows/macOS look-alikes included).
// isDirty runs `git --no-optional-locks status` (it never rewrites the index). Reads never fetch: every transport is turned
// off by name on the command line and GIT_NO_LAZY_FETCH is set, so a partial clone's missing blobs are an error, not a download. The folder
// must be the top of its repo: GIT_CEILING_DIRECTORIES stops git from looking above it, and `rev-parse --show-toplevel` is
// compared with it anyway (the ceiling is a list split at ':', so a parent path holding one escapes it). A repo configured
// as a partial clone (extensions.partialclone, remote.<name>.promisor) is refused before the read (E0c-R2, E2).
// Git LFS: the files read are the pointer files (no filter runs).
import { mkdtempSync, rmSync, chmodSync, lstatSync, realpathSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { execa, type ResultPromise } from 'execa';
import { hideToken } from '../github/client.js';
import { interrupting, onExit } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import { API_LOGIN_RE } from '../../gate/src/login.js';

/** Ruling B6: on every git call, before the command. Read last by git, so these win over every config file. */
export const HARDENED_CONFIG: readonly string[] = Object.freeze([
  '-c', 'credential.helper=',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.fsmonitor=false',
  '-c', 'protocol.allow=never',
  '-c', 'protocol.https.allow=always',
  '-c', 'http.followRedirects=false',
]);

/** The only origin a push goes to. */
export const GITHUB_ORIGIN = 'https://github.com';
/** HEAD's files are read into memory; past this the snapshot is refused. */
export const MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024;
/** GitHub refuses a pushed file over 100 MiB. */
export const MAX_SNAPSHOT_FILE_BYTES = 100 * 1024 * 1024;
const PUSH_TIMEOUT_MS = 10 * 60_000;
const READ_TIMEOUT_MS = 5 * 60_000;
const GATE_POLL_MS = 100;

/** A git call failed or was refused. The message never holds the token (hideToken) and is one clean line. */
export class GitTransportError extends Error {
  constructor(message: string) {
    super(hideToken(message));
    this.name = 'GitTransportError';
  }
}

// ---------- environment and output ----------

/** Ruling B6: the whole environment of a git child (nothing inherited but PATH). `extra` adds the call's own variables. */
export function gitEnv(home: string, extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    HOME: home,
    LANG: 'C',
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'never',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
  };
  // Windows: git's https transport can't start its sockets without SystemRoot (not a secret, not a config source).
  if (process.platform === 'win32' && process.env.SystemRoot !== undefined) env.SystemRoot = process.env.SystemRoot;
  return { ...env, ...extra };
}

const NO_CUT = Number.MAX_SAFE_INTEGER;
/**
 * git's output as one short line: the token hidden by value and by shape, before and after control characters and escape
 * sequences are removed (a token cut by an escape would join again), the last 8 non-empty lines kept, at most 600 characters.
 */
export function shownGitOutput(raw: string, token?: string): string {
  const lines = hideToken(raw, token)
    .split(/\r\n|\n|\r/)
    .map((l) => hideToken(safeText(l, NO_CUT), token).trim())
    .filter((l) => l !== '');
  return safeText(lines.slice(-8).join(' | '), 600);
}

// ---------- the private temp dir of one call ----------

interface Session {
  dir: string;
  /** The git child running now, killed by the exit hook. */
  child: ResultPromise | null;
}

/** A fresh 0700 dir for one call (HOME, working directory, askpass), removed after it and by a sync exit hook on a stop. */
async function inSession<T>(prefix: string, fn: (s: Session) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const s: Session = { dir, child: null };
  const off = onExit(() => {
    if (s.child !== null) killTree(s.child);
    rmSync(dir, { recursive: true, force: true });
  });
  try {
    privateDir(dir);
    return await fn(s);
  } finally {
    off();
    await rm(dir, { recursive: true, force: true });
  }
}

/** The dir must be a real directory of ours that nobody else can enter (POSIX). */
function privateDir(dir: string): void {
  chmodSync(dir, 0o700);
  const st = lstatSync(dir);
  const mine = process.getuid === undefined || st.uid === process.getuid();
  if (!st.isDirectory() || !mine || (process.platform !== 'win32' && (st.mode & 0o077) !== 0)) {
    throw new GitTransportError(`pipegen's temp folder ${safeText(dir)} is not private; not running git.`);
  }
}

/**
 * Kills git and everything it started: the push itself runs in git's child (git-remote-https), which keeps going when only
 * git dies. POSIX: git leads its own process group (spawned detached), so the group is killed. Windows: only git itself
 * (a recorded limit; the live session checks it).
 */
function killTree(child: ResultPromise): void {
  try {
    if (process.platform !== 'win32' && child.pid !== undefined) process.kill(-child.pid, 'SIGKILL');
    else child.kill('SIGKILL');
  } catch {
    try { child.kill('SIGKILL'); } catch { /* already gone */ }
  }
}

interface Spawned { stdout: Uint8Array; stderr: string }
interface SpawnOpts {
  env: Record<string, string>;
  input?: string | Uint8Array;
  maxBuffer?: number;
  timeoutMs?: number;
  token?: string;
  /** Kill the child when a stop begins (pushes). */
  watchGate?: boolean;
  /** maxBuffer reached is a result (stdout so far), not an error. */
  overflowOk?: boolean;
}

/** One hardened git call in the session dir. A failure is a GitTransportError naming the command, with git's cleaned output. */
async function spawnGit(s: Session, args: readonly string[], what: string, o: SpawnOpts): Promise<Spawned & { overflow: boolean }> {
  const child = execa('git', [...HARDENED_CONFIG, ...args], {
    cwd: s.dir,
    env: o.env,
    extendEnv: false,
    shell: false,
    ...(o.input === undefined ? { stdin: 'ignore' as const } : { input: o.input }),
    encoding: 'buffer',
    maxBuffer: o.maxBuffer ?? 64 * 1024 * 1024,
    killSignal: 'SIGKILL',
    windowsHide: true,
    detached: process.platform !== 'win32',
    reject: false,
    stripFinalNewline: false,
  });
  s.child = child;
  let stopped = false;
  // Our own timeout, so the whole process group goes (execa's would kill git alone, and wait for git-remote-https).
  const limitMs = o.timeoutMs ?? READ_TIMEOUT_MS;
  let timedOut = false;
  const deadline = setTimeout(() => {
    timedOut = true;
    killTree(child);
  }, limitMs);
  const timer = o.watchGate === true
    ? setInterval(() => {
      if (interrupting()) {
        stopped = true;
        killTree(child);
      }
    }, GATE_POLL_MS)
    : null;
  try {
    const r = await child;
    const stderr = Buffer.from(r.stderr).toString('utf8');
    if (stopped) throw new GitTransportError(`git ${what} was stopped: pipegen is stopping (what it sent may still have reached GitHub).`);
    if (r.isMaxBuffer && o.overflowOk === true) return { stdout: r.stdout, stderr, overflow: true };
    if (r.failed) {
      const why = timedOut ? `took longer than ${Math.round(limitMs / 1000)} s`
        : r.isMaxBuffer ? 'printed more than pipegen reads'
        : r.exitCode !== undefined ? `exit ${r.exitCode}` : 'could not run git (is git installed?)';
      const said = shownGitOutput(stderr, o.token);
      throw new GitTransportError(`git ${what} failed (${why})${said === '' ? '' : `: ${said}`}`);
    }
    return { stdout: r.stdout, stderr, overflow: false };
  } finally {
    if (timer !== null) clearInterval(timer);
    clearTimeout(deadline);
    s.child = null;
  }
}

const absolute = (dir: string, what: string): string => {
  if (typeof dir !== 'string' || !isAbsolute(dir)) throw new GitTransportError(`${what} must be an absolute path.`);
  return resolve(dir);
};

// ---------- push URL and refs ----------

// carry E0c (E9): an EMU user's own repos have the EMU login as owner (gate/src/login.ts)
const OWNER_RE = API_LOGIN_RE;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
export type PushRepo = 'scratch' | 'central';

/**
 * The push URL rule (ruling B6): exactly https://github.com/<owner>/pipegen-proof-<appRepo>.git (scratch) or
 * https://github.com/<owner>/pipelines.git (central). Anything else throws, without repeating the URL. An app repo named
 * `pipelines` has no central push (that name is the app repo itself).
 */
export function checkPushUrl(url: string, owner: string, appRepo: string): PushRepo {
  const scratch = `pipegen-proof-${appRepo}`;
  if (!OWNER_RE.test(owner) || !REPO_RE.test(appRepo) || appRepo === '.' || appRepo === '..' || !REPO_RE.test(scratch)) {
    throw new GitTransportError('The owner or repo is not a plain GitHub name; pipegen pushes nowhere.');
  }
  const m = new RegExp(`^https://github\\.com/${escapeRe(owner)}/(${escapeRe(scratch)}|pipelines)\\.git$`).exec(String(url));
  if (m === null) {
    throw new GitTransportError(`pipegen pushes only to https://github.com/${owner}/${scratch}.git and https://github.com/${owner}/pipelines.git; another URL was refused.`);
  }
  if (m[1] === 'pipelines') {
    if (appRepo.toLowerCase() === 'pipelines') throw new GitTransportError('The app repo is named pipelines, which is the central repo name; pipegen does not push there.');
    return 'central';
  }
  return 'scratch';
}

/** The push URL of the scratch or central repo, checked. */
export function pushUrl(owner: string, appRepo: string, repo: PushRepo): string {
  const url = `${GITHUB_ORIGIN}/${owner}/${repo === 'central' ? 'pipelines' : `pipegen-proof-${appRepo}`}.git`;
  checkPushUrl(url, owner, appRepo);
  return url;
}

export interface PushRef { sha: string; branch: string }
export interface PushRequest {
  /** The repo pushed from: only a live createPushRepo handle is accepted. */
  repo: PushRepoHandle;
  url: string;
  owner: string;
  appRepo: string;
  token: string;
  refs: readonly PushRef[];
  /** Force the update (the base snapshot replaces the default branch). */
  force?: boolean;
  timeoutMs?: number;
}

const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const BRANCH_RE = /^(?!.*\.\.)(?!.*\/\/)(?!.*\/\.)(?!.*\.lock(?:\/|$))[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}(?<![./])$/;
const CENTRAL_BRANCH_RE = /^proof\/\d{8}-\d{6}-[0-9a-f]{6}$/;
/** Only token-shaped values (as hideToken's own rule): no space, newline or quote reaches the askpass output. */
const TOKEN_RE = /^[A-Za-z0-9_]{20,255}$/;

function refspecs(refs: readonly PushRef[], repo: PushRepo, force: boolean): string[] {
  if (!Array.isArray(refs) || refs.length === 0) throw new GitTransportError('Nothing to push.');
  return refs.map((r) => {
    if (typeof r?.sha !== 'string' || !SHA_RE.test(r.sha)) throw new GitTransportError('A pushed commit is not a full lowercase sha.');
    if (typeof r.branch !== 'string' || !BRANCH_RE.test(r.branch) || r.branch.startsWith('refs/') || r.branch === 'HEAD') throw new GitTransportError(`"${safeText(String(r.branch), 100)}" is not a branch name pipegen pushes.`);
    if (repo === 'central' && !CENTRAL_BRANCH_RE.test(r.branch)) throw new GitTransportError('pipegen pushes to pipelines only refs/heads/proof/<runId>.');
    return `${force ? '+' : ''}${r.sha}:refs/heads/${r.branch}`;
  });
}

// ---------- the push ----------

/** The keys `git init` writes. Any other key in the push repo's own config (or a system/global one) refuses the push. */
const PUSH_REPO_KEYS: ReadonlySet<string> = new Set([
  'core.repositoryformatversion', 'core.filemode', 'core.bare', 'core.logallrefupdates', 'core.ignorecase', 'core.precomposeunicode',
  'core.symlinks', 'extensions.objectformat',
]);

/** `git config --list --show-scope -z`: every key not given on our command line must be one `git init` writes. */
async function checkPushRepoConfig(s: Session, gitDir: string): Promise<void> {
  const r = await spawnGit(s, [`--git-dir=${gitDir}`, 'config', '--list', '--show-scope', '-z'], 'config', { env: gitEnv(s.dir), maxBuffer: 1024 * 1024 });
  const parts = Buffer.from(r.stdout).toString('utf8').split('\0');
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const scope = parts[i];
    const key = parts[i + 1].split('\n')[0].toLowerCase();
    if (scope === 'command') continue;
    if (!PUSH_REPO_KEYS.has(key)) {
      // The section and name only: a subsection (a URL) could hold a credential.
      const shown = `${key.split('.')[0]}.${key.split('.').pop()}`;
      throw new GitTransportError(`The push repo's git config sets ${safeText(shown, 80)} (${safeText(scope, 20)}); pipegen pushes only from a repo with git init's config.`);
    }
  }
}

/** The askpass script: answers git's two prompts for `origin` only, the password from the child's environment. */
function askpassScript(origin: string): string {
  const withUser = origin.replace('://', '://x-access-token@');
  return [
    '#!/bin/sh',
    'case "$1" in',
    `"Username for '${origin}': ") printf '%s\\n' x-access-token ;;`,
    `"Password for '${withUser}': ") printf '%s\\n' "$PIPEGEN_GIT_TOKEN" ;;`,
    '*) exit 1 ;;',
    'esac',
    '',
  ].join('\n');
}

const stopping = () => new GitTransportError('Not pushing: pipegen is stopping.');

/**
 * Pushes commits of a pipegen push repo to the scratch repo or to `pipelines` (ruling B6, DECISIONS #111). Checks the gate,
 * the URL (checkPushUrl), the repo handle, the token's shape and the refs (central: only proof/<runId>) before anything runs.
 */
export async function gitPush(req: PushRequest): Promise<void> {
  if (interrupting()) throw stopping();
  const target = checkPushUrl(req.url, req.owner, req.appRepo);
  const gitDir = liveGitDir(req.repo);
  if (typeof req.token !== 'string' || !TOKEN_RE.test(req.token)) throw new GitTransportError('The token is not token-shaped; not pushing.');
  const specs = refspecs(req.refs, target, req.force === true);
  // The token is never in argv, even when a branch or path happens to hold it: /proc and ps show argv to every user.
  if ([gitDir, req.url, ...specs].some((a) => a.includes(req.token))) throw new GitTransportError('Not pushing: the token would be on git\'s command line.');
  await inSession('pipegen-git-', async (s) => {
    const askpass = join(s.dir, 'askpass');
    writeFileSync(askpass, askpassScript(GITHUB_ORIGIN), { mode: 0o700, flag: 'wx' });
    await checkPushRepoConfig(s, gitDir);
    if (interrupting()) throw stopping();
    const env = gitEnv(s.dir, { GIT_ASKPASS: askpass, PIPEGEN_GIT_TOKEN: req.token });
    await spawnGit(s, [`--git-dir=${gitDir}`, 'push', '--atomic', '--no-verify', '--no-follow-tags', '--recurse-submodules=no', req.url, ...specs], 'push', {
      env, token: req.token, watchGate: true, timeoutMs: req.timeoutMs ?? PUSH_TIMEOUT_MS, maxBuffer: 1024 * 1024,
    });
  });
}

// ---------- the push repo and its plumbing ----------

/** A repo made by createPushRepo. Only the object createPushRepo returned is accepted (not a copy), until it is removed. */
export interface PushRepoHandle {
  readonly gitDir: string;
  remove(): Promise<void>;
}
/** The live handles: a path can't be forged into one, and remove() or the exit hook ends one. */
const liveRepos = new WeakSet<object>();

function liveGitDir(h: unknown): string {
  if (typeof h !== 'object' || h === null || !liveRepos.has(h)) {
    throw new GitTransportError('pipegen pushes from and runs plumbing in a repo made by createPushRepo only (this one was not, or was removed).');
  }
  return (h as PushRepoHandle).gitDir;
}

/** A fresh bare repo in its own 0700 temp dir, with git init's config only; removed by remove() or a sync exit hook. */
export async function createPushRepo(): Promise<PushRepoHandle> {
  const parent = mkdtempSync(join(tmpdir(), 'pipegen-push-'));
  const gitDir = join(parent, 'repo.git');
  let handle: PushRepoHandle | null = null;
  const off = onExit(() => {
    if (handle !== null) liveRepos.delete(handle);
    rmSync(parent, { recursive: true, force: true });
  });
  try {
    privateDir(parent);
    await inSession('pipegen-git-', (s) => spawnGit(s, ['init', '-q', '--bare', gitDir], 'init', { env: gitEnv(s.dir) }));
  } catch (e) {
    off();
    rmSync(parent, { recursive: true, force: true });
    throw e;
  }
  const made: PushRepoHandle = Object.freeze({
    gitDir,
    remove: async () => {
      liveRepos.delete(made);
      off();
      await rm(parent, { recursive: true, force: true });
    },
  });
  handle = made;
  liveRepos.add(made);
  return made;
}

/** The plumbing E2 builds commits with. Nothing that talks to a remote, changes config or runs other programs. */
const PLUMBING: ReadonlySet<string> = new Set(['hash-object', 'mktree', 'commit-tree', 'update-ref', 'rev-parse', 'cat-file', 'ls-tree']);

export interface Identity { name: string; email: string; date?: string }

/** Runs one plumbing command in a createPushRepo repo (hardened, no token). Returns its stdout. */
export async function runGit(repo: PushRepoHandle, args: readonly string[], opts: { input?: string | Uint8Array; identity?: Identity; maxBuffer?: number } = {}): Promise<Uint8Array> {
  const dir = liveGitDir(repo);
  if (!Array.isArray(args) || !PLUMBING.has(args[0])) throw new GitTransportError(`runGit runs only ${[...PLUMBING].join(', ')}.`);
  const id: Record<string, string> = {};
  if (opts.identity !== undefined) {
    const { name, email, date } = opts.identity;
    Object.assign(id, { GIT_AUTHOR_NAME: name, GIT_AUTHOR_EMAIL: email, GIT_COMMITTER_NAME: name, GIT_COMMITTER_EMAIL: email });
    if (date !== undefined) Object.assign(id, { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date });
  }
  return inSession('pipegen-git-', async (s) => (await spawnGit(s, [`--git-dir=${dir}`, ...args], args[0], {
    env: gitEnv(s.dir, id), ...(opts.input === undefined ? {} : { input: opts.input }), ...(opts.maxBuffer === undefined ? {} : { maxBuffer: opts.maxBuffer }),
  })).stdout);
}

// ---------- the snapshot read (ruling S4) ----------

export interface SnapshotFile { path: string; mode: '100644' | '100755'; content: Uint8Array }
/** Left out of the snapshot. `path` is repo data: pass it through safeText before showing it. */
export interface DroppedEntry { path: string; why: 'symlink' | 'submodule' | 'non-utf8-name' | 'unsafe-path' | 'other' }
export interface Snapshot { commit: string; files: SnapshotFile[]; dropped: DroppedEntry[] }

/**
 * Reads never talk to a remote. Every transport is turned off by name: a per-protocol key in the user's repo config
 * (protocol.file.allow=always, say) beats HARDENED_CONFIG's protocol.allow=never, but the command line beats the repo config
 * key by key. GIT_NO_LAZY_FETCH (git 2.44+ and the 2024 security backports) also stops a partial clone's lazy fetch; the
 * flags close it on a git without that variable.
 */
const READ_CONFIG: readonly string[] = Object.freeze(['file', 'git', 'ssh', 'http', 'https', 'ext'].flatMap((p) => ['-c', `protocol.${p}.allow=never`]));

/**
 * A read in the user's repo: `-C <dir>`, no transport, replace refs off, and git may not look above <dir> for a repo. A
 * failure for a missing object of a partial clone gets a message naming the cause.
 */
async function readGit(s: Session, dir: string, args: readonly string[], o: Omit<SpawnOpts, 'env'> & { pre?: readonly string[] } = {}): Promise<Spawned & { overflow: boolean }> {
  const env = gitEnv(s.dir, { GIT_CEILING_DIRECTORIES: dirname(dir), GIT_NO_LAZY_FETCH: '1' });
  try {
    return await spawnGit(s, [...READ_CONFIG, '--no-replace-objects', ...(o.pre ?? []), '-C', dir, ...args], args[0], { ...o, env });
  } catch (e) {
    if (e instanceof GitTransportError && /promisor|lazy fetch|transport '[a-z]+' not allowed/i.test(e.message)) {
      throw new GitTransportError(`HEAD's files are not all in this clone (a partial clone): pipegen reads only what is on disk and fetches nothing. Fetch the missing objects (git fetch --refetch) or use a full clone. (${e.message})`);
    }
    throw e;
  }
}

/**
 * E0c-R2 (carried to E2): a partial clone is refused before anything is read. Its missing objects can't be read without
 * a fetch, which pipegen never makes, and an old git with the user's own `protocol.<helper>.allow=always` could still
 * fetch through a custom remote helper. So `extensions.partialclone` or any `remote.<name>.promisor` (whatever its value)
 * in the repo's config is a stop that asks for a full clone.
 */
async function refusePartialClone(s: Session, dir: string): Promise<void> {
  const out = Buffer.from((await readGit(s, dir, ['config', '--list', '-z'], { maxBuffer: 4 * 1024 * 1024 })).stdout).toString('utf8');
  const keys = out.split('\0').map((kv) => kv.split('\n')[0]?.toLowerCase() ?? '');
  if (keys.some((k) => k === 'extensions.partialclone' || /^remote\..+\.promisor$/.test(k))) {
    throw new GitTransportError('This folder is a partial clone (extensions.partialclone or a remote.<name>.promisor is set): pipegen reads only what is on disk and fetches nothing. Run the proof from a full clone of the repo.');
  }
}

/** The folder must be its repo's top: git may have found a repo above it when the ceiling list was split at a ':'. */
function checkTopLevel(dir: string, top: string): void {
  let real: string;
  try {
    real = realpathSync(dir);
  } catch {
    throw new GitTransportError(`${safeText(dir)} can't be resolved.`);
  }
  if (top === '' || resolve(top) !== resolve(real)) throw new GitTransportError(`${safeText(dir)} is not the top of a git repo; pipegen reads only the project's own repo.`);
}

// ignoreBOM: a name that starts with U+FEFF keeps it (by default TextDecoder drops a leading BOM, renaming the file).
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const lossy = new TextDecoder('utf-8', { ignoreBOM: true });
const IGNORABLE = /[\p{Default_Ignorable_Code_Point}]/gu;
/**
 * A name a checkout must never write: empty, `.`, `..`, a backslash, and `.git` the way Windows and macOS read names. The
 * check runs on the part before the first colon (NTFS names the file there and puts a stream after it: `.git::$DATA`,
 * `.GIT:stream`), with invisible characters ignored (HFS+), any case, trailing dots and spaces dropped, and the 8.3 short
 * name `git~1`; an empty result is refused too. Other names with a colon (`a:b`, `urn:x`) are legal on Linux, macOS and the
 * runner, and kept, so the proof tree stays HEAD's.
 */
function unsafeName(c: string): boolean {
  if (c === '' || c === '.' || c === '..' || c.includes('\\')) return true;
  const n = c.split(':')[0].replace(IGNORABLE, '').toLowerCase().replace(/[. ]+$/, '');
  return n === '' || n === '.git' || n === 'git~1';
}
const unsafePath = (p: string) => p.split('/').some(unsafeName);

/**
 * HEAD's files (ruling S4): `ls-tree -r -z -l --full-tree` then `cat-file --batch`, in the hardened environment. No filter,
 * no export attribute, no replace ref applies. Symlinks, submodules, names that are not UTF-8 and unsafe paths are dropped
 * and listed. Over `maxBytes` (default MAX_SNAPSHOT_BYTES) in all, or a file over MAX_SNAPSHOT_FILE_BYTES, it throws.
 */
export async function readSnapshot(dir: string, opts: { maxBytes?: number; maxFileBytes?: number } = {}): Promise<Snapshot> {
  const repo = absolute(dir, 'The project folder');
  const maxBytes = opts.maxBytes ?? MAX_SNAPSHOT_BYTES;
  const maxFileBytes = opts.maxFileBytes ?? MAX_SNAPSHOT_FILE_BYTES;
  return inSession('pipegen-git-', async (s) => {
    const [top = '', commit = ''] = Buffer.from((await readGit(s, repo, ['rev-parse', '--show-toplevel', '--verify', '--end-of-options', 'HEAD^{commit}'])).stdout).toString('utf8').split('\n');
    checkTopLevel(repo, top);
    await refusePartialClone(s, repo);
    if (!SHA_RE.test(commit)) throw new GitTransportError('HEAD is not a commit pipegen can read.');
    const listing = Buffer.from((await readGit(s, repo, ['ls-tree', '-r', '-z', '-l', '--full-tree', commit], { maxBuffer: 256 * 1024 * 1024 })).stdout);
    const wanted: { path: string; mode: SnapshotFile['mode']; sha: string; size: number }[] = [];
    const dropped: DroppedEntry[] = [];
    let total = 0;
    let start = 0;
    while (start < listing.length) {
      let end = listing.indexOf(0, start);
      if (end === -1) end = listing.length;
      const rec = listing.subarray(start, end);
      start = end + 1;
      const tab = rec.indexOf(9);
      const m = /^(\d{6}) (\w+) ([0-9a-f]{40,64}) +(-|\d+)$/.exec(rec.subarray(0, tab).toString('latin1'));
      if (tab === -1 || m === null) throw new GitTransportError('git ls-tree printed a line pipegen does not understand.');
      const raw = rec.subarray(tab + 1);
      let path: string;
      try {
        path = utf8.decode(raw);
      } catch {
        dropped.push({ path: lossy.decode(raw), why: 'non-utf8-name' });
        continue;
      }
      const [, mode, type, sha, size] = m;
      if (mode === '120000') dropped.push({ path, why: 'symlink' });
      else if (mode === '160000') dropped.push({ path, why: 'submodule' });
      else if (unsafePath(path)) dropped.push({ path, why: 'unsafe-path' });
      else if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) dropped.push({ path, why: 'other' });
      else {
        const bytes = Number(size);
        if (bytes > maxFileBytes) throw new GitTransportError(`${safeText(path)} is over ${maxFileBytes} bytes; GitHub refuses a pushed file over 100 MiB.`);
        total += bytes;
        if (total > maxBytes) throw new GitTransportError(`HEAD's files add up to more than ${maxBytes} bytes; pipegen can't copy them to the scratch repo.`);
        wanted.push({ path, mode, sha, size: bytes });
      }
    }
    const shas = [...new Set(wanted.map((w) => w.sha))];
    const blobs = new Map<string, Uint8Array>();
    if (shas.length > 0) {
      const out = Buffer.from((await readGit(s, repo, ['cat-file', '--batch'], { input: `${shas.join('\n')}\n`, maxBuffer: total + shas.length * 200 + 1024 })).stdout);
      let at = 0;
      for (const sha of shas) {
        const nl = out.indexOf(10, at);
        const head = nl === -1 ? '' : out.subarray(at, nl).toString('latin1');
        const hm = /^([0-9a-f]{40,64}) blob (\d+)$/.exec(head);
        if (hm === null || hm[1] !== sha) throw new GitTransportError('git cat-file did not return a blob pipegen asked for.');
        const len = Number(hm[2]);
        blobs.set(sha, out.subarray(nl + 1, nl + 1 + len));
        at = nl + 1 + len + 1;
      }
    }
    const files = wanted
      .map((w) => ({ path: w.path, mode: w.mode, content: blobs.get(w.sha) as Uint8Array }))
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    dropped.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return { commit, files, dropped };
  });
}

/**
 * Whether the working tree differs from HEAD (tracked changes or untracked files not ignored), for the "uncommitted
 * changes are not part of the proof" warning. `git --no-optional-locks status` with fsmonitor off; submodules ignored
 * (they are dropped from the snapshot anyway).
 */
export async function isDirty(dir: string): Promise<boolean> {
  const repo = absolute(dir, 'The project folder');
  return inSession('pipegen-git-', async (s) => {
    checkTopLevel(repo, Buffer.from((await readGit(s, repo, ['rev-parse', '--show-toplevel'])).stdout).toString('utf8').split('\n')[0]);
    const r = await readGit(s, repo, ['status', '--porcelain=v1', '-z', '--ignore-submodules=all', '--untracked-files=normal'], {
      pre: ['--no-optional-locks'], maxBuffer: 1024 * 1024, overflowOk: true,
    });
    return r.overflow || r.stdout.length > 0;
  });
}
