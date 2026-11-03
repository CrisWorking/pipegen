// Plan E Task 2, first half / sub-task E2 (spec §19; rulings S1, S4, S5, S9, S21, S24, B3, B6, E2-R1..R5; threats T12,
// T21): what a proof pushes. The scratch repo `pipegen-proof-<repo>` holds the user's real test keys during the proof, so
// a user workflow in any pushed tree would run next to them, and a push to the wrong repo or ref would touch the user's
// project.
//
// - The base snapshot (buildBase): HEAD's files as readSnapshot reads them (ruling S4: ls-tree + cat-file, never
//   `git archive`, so export-ignore / export-subst change nothing; symlinks and submodules dropped and listed), without
//   anything under .github/workflows/ (every workflow of HEAD, pipegen's own earlier files included: the user may have
//   edited them, E2-R5) and without the Dependabot and Renovate configs (S5). One commit, no parent, no history, for the
//   scratch repo's default branch (= the app's, S1). It holds no workflow, so pushing it starts nothing. The working tree
//   is never read: uncommitted changes (untracked files included) only give the warning.
// - The central draft (buildCentralDraft, the central layout only: draft.centralPin set, S24): proof/<runId> of
//   `pipelines` = its default head + this project's central files (S21). The head is read through the API (GET only; the
//   transport never fetches) and rebuilt locally; each blob must hash back and the tree must equal the head's tree sha, so
//   the copy is exact (E2-R2: the commit has no parent). Every workflow in that tree may start only on workflow_call,
//   workflow_dispatch or schedule (E2-R3, one `on` key spelled exactly so); a `.github` or `.github/workflows` that is a
//   symlink or a submodule there is a stop.
// - The proof branches (buildProofBranch): proof/<runId>/<variant> = the base (or an earlier proof commit of this session)
//   + one commit per file set, each with exactly one parent, pushed without force (B3). The tree's workflow files must be
//   exactly the draft's own pipegen workflows (E2-R5: with the draft's content, also at a path HEAD holds).
// - Every commit is a ProofCommit record (kind, sha, the one branch it may go to) that only this module makes. pushCommit,
//   and gitTransport itself, push only such a commit of a live session, to its own repo and branch, after checking its
//   whole tree (and its parents') again (review M2). The session's push repo is never exposed.
// - pushProofSetup builds every commit first (central, base, main, planted: every tree, path and mode check), then writes,
//   in the plan's order: Dependabot security updates off (S5) → central → base → the scratch default branch again when
//   the repo was empty (E1 carry) → every listed workflow that isn't pipegen's disabled → no run for the base sha (else a
//   stop naming the run) → the injected secret store (E4: it must call checkScratchAccess again first) → main, planted.
//   A refusal of any build or check comes before any write, store or push (review M1).
//
// Pushes go only through the ProofTransport (gitTransport: E0c's gitPush with the token in a closure, never in argv, a URL
// or output) and only to a GuardedRepo (target.ts). Every API write is guardedWrite. No push and no write starts once a
// stop has begun (interrupting(), checked before each step; gitPush and guardedWrite check again). Commits are built in a
// createPushRepo repo with hash-object, mktree and commit-tree only (runGit).
//
// Known limits (recorded in the E2 report): Windows-reserved names such as `CON` or `a:b` are kept (the runner is Linux);
// only the pointer files of Git LFS objects are copied, so a docker service holding them is not-proven (filter=lfs);
// Renovate's deprecated `renovate` key in package.json is not removed.
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import type { CliIO } from '../cli/io.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { isObj, parseYaml } from '../engine/yaml-parse.js';
import { clockOf, githubTokenRejected, isAnonymousClient } from '../github/client.js';
import type { CreatedFile, NotProven, Service } from '../types.js';
import { interrupting, onExit } from '../util/exit-hooks.js';
import { safeText } from '../util/safe-text.js';
import {
  createPushRepo, gitPush, GitTransportError, isDirty, readSnapshot, runGit, type DroppedEntry, type PushRef, type PushRepoHandle,
} from './git.js';
import { setScratchDefaultBranch, type DefaultBranchState } from './repos.js';
import {
  assertCentral, assertScratch, githubRead, guardedWrite, isProofTarget, ProofStopError, requireGuarded, ScratchGuardError, scratchPushUrl,
  validBranchName, type GuardedRepo, type ProofTarget,
} from './target.js';

export type Variant = 'main' | 'planted' | `dispute-${string}-${'a' | 'b'}`;
/** This project's central files (every one `repo: 'central'`), pushed to proof/<runId> of `pipelines`. */
export interface CentralDraft { files: CreatedFile[] }
/** A file of a proof tree. `path` as bytes for a name that is not UTF-8 (a planted placement). */
export interface ProofFile { path: string | Uint8Array; content: string | Uint8Array; mode?: '100644' | '100755' }
/** A file kept out of a pushed tree, and why. `path` is repo data: show it through safeText. */
export interface LeftOut { path: string; why: string }

/**
 * The only way src/proof pushes (B6). gitTransport is the production one; a test or E8 may wrap it. `from` is a proof
 * session's own push repo (never exposed): gitTransport refuses any other, and any commit that session didn't build.
 */
export interface ProofTransport {
  push(to: GuardedRepo, from: PushRepoHandle, refs: readonly PushRef[], opts?: { force?: boolean }): Promise<void>;
}

/** E4's seam: stores the scratch secrets. The real store must call checkScratchAccess again before its first write. */
export type SecretStoreStep = (scratch: GuardedRepo, ctx: { baseSha: string }) => Promise<void>;

/**
 * A commit this module built and checked (review M2). Only it makes one (registered, frozen); pushCommit takes nothing
 * else. `branch` is the one branch it may be pushed to: base → the scratch default branch (forced), central →
 * proof/<runId> of pipelines, proof → proof/<runId>/<variant> (never forced).
 */
export interface ProofCommit {
  readonly kind: 'base' | 'central' | 'proof';
  readonly sha: string;
  readonly branch: string;
  readonly variant?: Variant;
  /** Every commit built for this record, oldest first (the last is `sha`). */
  readonly commits: readonly string[];
}

const IDENTITY = Object.freeze({ name: 'pipegen', email: 'proof@pipegen.invalid' });
const SHA_RE = /^[0-9a-f]{40}$/;
const TOKEN_RE = /^[A-Za-z0-9_]{20,255}$/;
const PROOF_NAME_RE = /^[a-z0-9][a-z0-9-]{0,80}$/;
const VARIANT_RE = /^(?:main|planted|dispute-[a-z0-9][a-z0-9-]{0,40}-[ab])$/;
const TREE_CONCURRENCY = 8;
const BLOB_READ_CONCURRENCY = 4;
/** The central default head copied through the API: past these it is a stop (it is pipegen's helper repo, normally small). */
export const MAX_CENTRAL_ENTRIES = 5000;
export const MAX_CENTRAL_BYTES = 64 * 1024 * 1024;
/** Triggers a pushed central workflow may have: none of them starts on a branch push. */
const CENTRAL_TRIGGERS: ReadonlySet<string> = new Set(['workflow_call', 'workflow_dispatch', 'schedule']);
/** Ruling S5: left out of base and proof trees (lower-case paths). */
const BOT_CONFIGS: ReadonlySet<string> = new Set([
  '.github/dependabot.yml', '.github/dependabot.yaml',
  'renovate.json', 'renovate.json5', '.github/renovate.json', '.github/renovate.json5', '.gitlab/renovate.json', '.gitlab/renovate.json5',
  '.renovaterc', '.renovaterc.json', '.renovaterc.json5',
]);
const GH013_RE = /GH013|push declined due to repository rule violations|push protection/i;
const LFS_POINTER = 'version https://git-lfs.github.com/spec/v1\n';

const text = (b: Uint8Array): string => Buffer.from(b).toString('utf8').trim();
const lossy = new TextDecoder('utf-8', { ignoreBOM: true });
const shown = (b: Uint8Array): string => lossy.decode(b);
const keyOf = (b: Uint8Array): string => Buffer.from(b).toString('latin1');
const bytesOfKey = (k: string): Buffer => Buffer.from(k, 'latin1');

function notStopping(): void {
  if (interrupting()) throw new ScratchGuardError('pipegen is stopping; no new push or GitHub write starts.');
}

function hard(gh: Octokit, e: unknown): void {
  if (e instanceof ScratchGuardError || e instanceof ProofStopError) throw e;
  if (isRateStop(e)) throw e;
  if ((e as { status?: unknown } | null)?.status === 401 && !isAnonymousClient(gh)) throw githubTokenRejected();
}
const saidOf = (e: unknown): string => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' ? `GitHub answered ${s}` : safeText(e instanceof Error ? e.message : String(e), 160);
};

// ---------- paths ----------

const IGNORABLE = /[\p{Default_Ignorable_Code_Point}]/gu;
/** As git.ts's unsafeName: `.git` the way Windows and macOS read a name is never written. */
function unsafeSegment(seg: string): boolean {
  if (seg === '' || seg === '.' || seg === '..' || seg.includes('\\')) return true;
  const n = seg.split(':')[0]?.replace(IGNORABLE, '').toLowerCase().replace(/[. ]+$/, '') ?? '';
  return n === '' || n === '.git' || n === 'git~1';
}

/** A plain repo path as bytes, or an Error naming it. */
function pathBytes(p: string | Uint8Array): Buffer {
  const b = typeof p === 'string' ? Buffer.from(p, 'utf8') : Buffer.from(p);
  const s = shown(b);
  if (b.length === 0 || b.length > 4096 || b.includes(0) || s.split('/').some(unsafeSegment)) {
    throw new GitTransportError(`"${safeText(s, 120)}" is not a plain repo path; pipegen doesn't write it.`);
  }
  return b;
}

/** Anything under .github/workflows/ (any case, any depth): a workflow GitHub could run, or a folder of them. */
export const isWorkflowPath = (p: string): boolean => p.toLowerCase().startsWith('.github/workflows/');
const isBotConfig = (p: string): boolean => BOT_CONFIGS.has(p.toLowerCase());

// ---------- the session: one push repo, the commits pipegen built in it ----------

interface Entry { name: Buffer; mode: string; type: 'blob' | 'commit'; sha: string }
type Entries = Map<string, Entry>;

export interface BaseSnapshot {
  /** The base commit (no parent), for the scratch repo's default branch. */
  sha: string;
  tree: string;
  /** Its ProofCommit record (pushCommit takes it). */
  commit: ProofCommit;
  /** The user's HEAD commit it copies. */
  head: string;
  dirtyWarning: boolean;
  /** readSnapshot's dropped entries (symlinks, submodules, names that are not UTF-8 or not safe). */
  dropped: DroppedEntry[];
  /** HEAD files left out: every workflow of HEAD and the bot configs (S5). */
  leftOut: LeftOut[];
  /** Lower-case paths of HEAD's workflow files (dropped ones included). */
  userWorkflows: string[];
  /** Every path in the base (UTF-8). */
  paths: ReadonlySet<string>;
  /** The base's own .gitleaksignore, if any (the planted one extends it). */
  gitleaksIgnore: Uint8Array | null;
  /** Set when a .gitattributes holds filter=lfs: the LFS pointer files copied instead of their objects. */
  lfs: { pointers: string[] } | null;
  /** docker not-proven: a symlink (S4) or LFS pointer files inside a docker service's folder. */
  notProven: NotProven[];
  warnings: string[];
}

/** What the session knows of a commit it built: checked again, with its parents, right before every push (M2). */
interface CommitRec {
  kind: ProofCommit['kind'];
  branch: string;
  parent: string | null;
  entries: Entries;
  /** Lower-case workflow paths this commit's tree may hold (base: none). */
  allowed: ReadonlySet<string>;
  /** Central only: the tree's workflow files, judged by checkCentralTriggers again before the push. */
  centralWorkflows?: readonly { path: string; content: string }[];
}

interface SessionState {
  target: ProofTarget;
  repo: PushRepoHandle;
  removed: boolean;
  base: BaseSnapshot | null;
  commits: Map<string, CommitRec>;
  /** mktree input digest → tree sha (identical folders are written once). */
  treeCache: Map<string, string>;
  /** The central commit and its paths (central layout only). */
  central: { sha: string; paths: ReadonlySet<string> } | null;
}

/** One proof's local push repo and the commits built in it. Only openProofSession makes one; remove() ends it. */
export interface ProofSession {
  readonly target: ProofTarget;
  remove(): Promise<void>;
}
const sessions = new WeakMap<object, SessionState>();
/** The live session of a push repo (gitTransport takes no other `from`). */
const repoSessions = new WeakMap<object, SessionState>();
/** Each ProofCommit record → the session that built it. */
const commitOwners = new WeakMap<object, SessionState>();

function live(s: ProofSession): SessionState {
  const st = typeof s === 'object' && s !== null ? sessions.get(s) : undefined;
  if (st === undefined || st.removed) throw new GitTransportError('This proof session was not made by openProofSession, or was removed.');
  return st;
}

export async function openProofSession(t: ProofTarget): Promise<ProofSession> {
  if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
  const repo = await createPushRepo();
  const st: SessionState = { target: t, repo, removed: false, base: null, commits: new Map(), treeCache: new Map(), central: null };
  const s: ProofSession = Object.freeze({
    target: t,
    remove: async () => {
      st.removed = true;
      st.commits.clear();
      await repo.remove();
    },
  });
  sessions.set(s, st);
  repoSessions.set(repo, st);
  return s;
}

function record(st: SessionState, sha: string, rec: CommitRec): void {
  st.commits.set(sha, rec);
}

function proofCommit(st: SessionState, c: ProofCommit): ProofCommit {
  const frozen = Object.freeze({ ...c, commits: Object.freeze([...c.commits]) });
  commitOwners.set(frozen, st);
  return frozen;
}

// ---------- objects ----------

/** Writes each content as a blob (hash-object -w --no-filters --stdin-paths over files in a fresh 0700 dir). */
async function hashBlobs(repo: PushRepoHandle, contents: readonly Uint8Array[]): Promise<string[]> {
  if (contents.length === 0) return [];
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-blobs-'));
  const off = onExit(() => rmSync(dir, { recursive: true, force: true }));
  try {
    chmodSync(dir, 0o700);
    if (/[\n\r]/.test(dir)) throw new GitTransportError('The temp folder name holds a line break; pipegen can\'t list files in it for git.');
    const paths = contents.map((c, i) => {
      const p = join(dir, String(i));
      writeFileSync(p, c, { mode: 0o600, flag: 'wx' });
      return p;
    });
    const out = text(await runGit(repo, ['hash-object', '-w', '--no-filters', '--stdin-paths'], { input: `${paths.join('\n')}\n` })).split('\n');
    if (out.length !== contents.length || !out.every((x) => SHA_RE.test(x))) throw new GitTransportError('git hash-object did not return one sha per file.');
    return out;
  } finally {
    off();
    await rm(dir, { recursive: true, force: true });
  }
}

/** Blobs for files: each content written once. Returns the entries in the order of `files`. */
async function blobEntries(repo: PushRepoHandle, files: readonly { name: Buffer; content: Uint8Array; mode: string }[]): Promise<Entry[]> {
  const unique = new Map<string, number>();
  const contents: Uint8Array[] = [];
  const idx = files.map((f) => {
    const k = createHash('sha256').update(f.content).digest('hex');
    let i = unique.get(k);
    if (i === undefined) {
      i = contents.length;
      unique.set(k, i);
      contents.push(f.content);
    }
    return i;
  });
  const shas = await hashBlobs(repo, contents);
  return files.map((f, i) => ({ name: f.name, mode: f.mode, type: 'blob' as const, sha: shas[idx[i] as number] as string }));
}

interface Dir { kind: 'dir'; name: Buffer; children: Map<string, Dir | (Entry & { kind: 'leaf'; leaf: Buffer })>; depth: number; sha?: string }

/** The root tree of `entries` (mktree per folder, deepest first; identical folders written once). */
async function writeTree(st: SessionState, entries: Iterable<Entry>): Promise<string> {
  const root: Dir = { kind: 'dir', name: Buffer.alloc(0), children: new Map(), depth: 0 };
  const dirs: Dir[] = [root];
  for (const e of entries) {
    const parts: Buffer[] = [];
    let start = 0;
    for (let i = 0; i <= e.name.length; i++) {
      if (i === e.name.length || e.name[i] === 0x2f) {
        parts.push(e.name.subarray(start, i));
        start = i + 1;
      }
    }
    let d = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const k = keyOf(parts[i] as Buffer);
      let c = d.children.get(k);
      if (c === undefined) {
        c = { kind: 'dir', name: parts[i] as Buffer, children: new Map(), depth: d.depth + 1 };
        d.children.set(k, c);
        dirs.push(c);
      } else if (c.kind !== 'dir') {
        throw new GitTransportError(`"${safeText(shown(e.name), 120)}" needs a folder where the tree has a file.`);
      }
      d = c;
    }
    const leaf = parts[parts.length - 1] as Buffer;
    const k = keyOf(leaf);
    if (d.children.get(k)?.kind === 'dir') throw new GitTransportError(`"${safeText(shown(e.name), 120)}" is a file where the tree has a folder.`);
    d.children.set(k, { ...e, kind: 'leaf', leaf });
  }
  const maxDepth = Math.max(...dirs.map((d) => d.depth));
  for (let depth = maxDepth; depth >= 0; depth--) {
    const level = dirs.filter((d) => d.depth === depth);
    for (let i = 0; i < level.length; i += TREE_CONCURRENCY) {
      await Promise.all(level.slice(i, i + TREE_CONCURRENCY).map(async (d) => {
        const input = Buffer.concat([...d.children.values()].map((c) => (c.kind === 'dir'
          ? Buffer.concat([Buffer.from(`040000 tree ${c.sha as string}\t`), c.name, Buffer.from([0])])
          : Buffer.concat([Buffer.from(`${c.mode} ${c.type} ${c.sha}\t`), c.leaf, Buffer.from([0])]))));
        const k = createHash('sha256').update(input).digest('hex');
        let sha = st.treeCache.get(k);
        if (sha === undefined) {
          sha = text(await runGit(st.repo, ['mktree', '-z'], { input }));
          if (!SHA_RE.test(sha)) throw new GitTransportError('git mktree did not return a tree sha.');
          st.treeCache.set(k, sha);
        }
        d.sha = sha;
      }));
    }
  }
  return root.sha as string;
}

async function commitTree(st: SessionState, tree: string, parent: string | null, message: string): Promise<string> {
  const sha = text(await runGit(st.repo, ['commit-tree', tree, ...(parent === null ? [] : ['-p', parent]), '-m', message], { identity: IDENTITY }));
  if (!SHA_RE.test(sha)) throw new GitTransportError('git commit-tree did not return a commit sha.');
  return sha;
}

// ---------- the transport and the push choke point ----------

/** The refs a guarded repo takes (S3, S21, B3). Throws ScratchGuardError before anything runs. */
function checkPushRefs(to: GuardedRepo, refs: readonly PushRef[], force: boolean): void {
  requireGuarded(to);
  const t = to.target;
  if (!Array.isArray(refs) || refs.length === 0) throw new ScratchGuardError('nothing to push.');
  for (const r of refs) {
    const b = r?.branch;
    if (typeof b !== 'string') throw new ScratchGuardError('a pushed branch is not named.');
    if (to.kind === 'central') {
      if (b !== `proof/${t.runId}`) throw new ScratchGuardError(`${to.fullName} takes only the branch proof/${t.runId}.`);
      if (force) throw new ScratchGuardError(`proof/${t.runId} of ${to.fullName} is never force-pushed.`);
      continue;
    }
    if (b === t.defaultBranch) continue;
    const prefix = `proof/${t.runId}/`;
    if (!b.startsWith(prefix) || !PROOF_NAME_RE.test(b.slice(prefix.length))) {
      throw new ScratchGuardError(`${to.fullName} takes only its default branch and proof/${t.runId}/<name>, not "${safeText(b, 100)}".`);
    }
    if (force) throw new ScratchGuardError(`the proof branch ${b} is never force-pushed (B3).`);
  }
}

/**
 * Review M2: the commit `sha` of this session may go to `to` on `branch` (its kind's repo, its own branch, forced only for
 * the base), and its whole tree, and each parent's, passes the workflow check again: a scratch commit holds no workflow
 * but the ones it was built to hold (the base none), and the central commit's workflows start on no push.
 */
function checkCommitFor(st: SessionState, to: GuardedRepo, sha: string, branch: string, force: boolean): void {
  const t = st.target;
  const rec = st.commits.get(sha);
  if (rec === undefined) throw new ScratchGuardError('pipegen pushes only a commit its proof session built and checked.');
  if (rec.kind === 'central') {
    if (to.kind !== 'central' || branch !== `proof/${t.runId}` || force) throw new ScratchGuardError(`the central draft commit goes only to proof/${t.runId} of ${t.central}, never forced.`);
  } else if (to.kind !== 'scratch') {
    throw new ScratchGuardError(`a scratch commit never goes to ${to.fullName}.`);
  } else if (rec.kind === 'base') {
    if (branch !== t.defaultBranch || !force) throw new ScratchGuardError(`the base snapshot goes only to the default branch ${t.defaultBranch} of ${to.fullName}.`);
  } else if (branch !== rec.branch || force) {
    throw new ScratchGuardError(`this proof commit goes only to ${rec.branch}, never forced.`);
  }
  for (let r: CommitRec | undefined = rec, n = 0; r !== undefined; r = r.parent === null ? undefined : st.commits.get(r.parent), n++) {
    if (n > 10_000) throw new ScratchGuardError('the commit chain is too long to check.');
    if (r.kind === 'central') {
      const problems = checkCentralTriggers(r.centralWorkflows ?? []);
      if (problems.length > 0) throw new ScratchGuardError(`the central draft commit holds a workflow that could start: ${problems[0] as string}.`);
      continue;
    }
    for (const k of r.entries.keys()) {
      const p = shown(bytesOfKey(k));
      if (isWorkflowPath(p) && !r.allowed.has(p.toLowerCase())) throw new ScratchGuardError(`${safeText(p, 120)} is a workflow this commit was not built to hold; not pushing.`);
    }
    if (r.parent !== null && !st.commits.has(r.parent)) throw new ScratchGuardError('a parent of this commit was not built by its proof session.');
  }
}

/**
 * The production transport (B6): gitPush to the guarded repo's checked URL, the token held here only. It pushes only from a
 * live proof session's repo, and only commits that session built, each to its own repo and branch after the tree check.
 */
export function gitTransport(token: string): ProofTransport {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) throw new GitTransportError('The token is not token-shaped; pipegen makes no git transport with it.');
  return Object.freeze({
    push: async (to: GuardedRepo, from: PushRepoHandle, refs: readonly PushRef[], opts: { force?: boolean } = {}) => {
      const force = opts.force === true;
      checkPushRefs(to, refs, force);
      const st = typeof from === 'object' && from !== null ? repoSessions.get(from) : undefined;
      if (st === undefined || st.removed) throw new ScratchGuardError('pipegen pushes only from a live proof session\'s own repo.');
      if (st.target !== to.target) throw new ScratchGuardError('the proof session was made for another target.');
      for (const r of refs) checkCommitFor(st, to, r.sha, r.branch, force);
      notStopping();
      await gitPush({ repo: from, url: scratchPushUrl(to), owner: to.owner, appRepo: to.target.appRepo, token, refs, force });
    },
  });
}

type PushWhat = 'base' | 'central' | 'planted' | 'proof';

/** A push whose GH013 refusal (push protection, a ruleset) is a clear stop. */
async function pushOrStop(transport: ProofTransport, to: GuardedRepo, from: PushRepoHandle, refs: readonly PushRef[], force: boolean, what: PushWhat): Promise<void> {
  notStopping();
  try {
    await transport.push(to, from, refs, { force });
  } catch (e) {
    if (!(e instanceof GitTransportError) || !GH013_RE.test(e.message)) throw e;
    const said = `(git said: ${safeText(e.message, 300)})`;
    const branch = refs.map((r) => r.branch).join(', ');
    const never = 'pipegen never bypasses push protection or a ruleset; the proof stops.';
    if (what === 'base') {
      throw new ProofStopError(`GitHub refused the push of your HEAD to ${to.fullName} (GH013: push protection or a repository rule). Push protection may have `
        + `found a secret in your code. Remove it from HEAD (and rotate it), or check the rulesets of ${to.fullName}, then run pipegen again. ${never} ${said}`);
    }
    if (what === 'central') {
      throw new ProofStopError(`GitHub refused ${branch} in ${to.fullName} (GH013: a repository rule or push protection). A ruleset on ${to.fullName} must `
        + `target only its default branch (or exclude proof/**) for a proof to run. ${never} ${said}`);
    }
    if (what === 'planted') {
      throw new ProofStopError(`GitHub refused the planted branch ${branch} of ${to.fullName} (GH013: push protection or a repository rule). The planted `
        + `keys are random generic values of no provider format, so check the push protection and rulesets of ${to.fullName}. ${never} ${said}`);
    }
    throw new ProofStopError(`GitHub refused the proof branch ${branch} of ${to.fullName} (GH013: push protection or a repository rule). `
      + `Check the push protection and rulesets of ${to.fullName}. ${never} ${said}`);
  }
}

/**
 * Pushes a commit this session built (review M2): the base forced to the scratch default branch, the central commit to
 * proof/<runId> of pipelines, a proof commit (and its new parents) to its own branch without force. Any other record, or
 * one of another session, is refused (ScratchGuardError) before anything runs; the tree is checked again first.
 */
export async function pushCommit(s: ProofSession, c: ProofCommit, transport: ProofTransport): Promise<void> {
  const st = live(s);
  if (typeof c !== 'object' || c === null || commitOwners.get(c) !== st) throw new ScratchGuardError('the commit was not built by this proof session.');
  notStopping();
  const t = st.target;
  const app = { owner: t.owner, repo: t.appRepo };
  const to = c.kind === 'central' ? assertCentral(t, app) : assertScratch(t, app);
  const force = c.kind === 'base';
  checkCommitFor(st, to, c.sha, c.branch, force);
  const what: PushWhat = c.kind === 'proof' ? (c.variant === 'planted' ? 'planted' : 'proof') : c.kind;
  await pushOrStop(transport, to, st.repo, [{ sha: c.sha, branch: c.branch }], force, what);
}

// ---------- base snapshot ----------

/**
 * Builds the base snapshot of `dir`'s HEAD (see the file comment). Once per session. Warns (io.err) on a dirty tree and on
 * Git LFS. `dockerServices`: the services whose docker part runs (the symlink and LFS rules). Nothing is pushed.
 */
export async function buildBase(s: ProofSession, dir: string, deps: { io: Pick<CliIO, 'err'>; dockerServices?: readonly Pick<Service, 'name' | 'path'>[] }): Promise<BaseSnapshot> {
  const st = live(s);
  if (st.base !== null) throw new GitTransportError('The base snapshot is built once per proof session.');
  notStopping();
  const t = st.target;
  const warnings: string[] = [];
  const warn = (w: string) => { warnings.push(w); deps.io.err(w); };

  // the read first: a partial clone is refused before anything else runs in the user's repo (E0c-R2)
  const snap = await readSnapshot(dir);
  const dirtyWarning = await isDirty(dir);
  if (dirtyWarning) warn(`Your working tree has uncommitted changes: uncommitted changes are not part of the proof. pipegen copies HEAD (${snap.commit.slice(0, 12)}) only.`);

  const leftOut: LeftOut[] = [];
  const userWorkflows = new Set<string>();
  for (const d of snap.dropped) if (isWorkflowPath(d.path)) userWorkflows.add(d.path.toLowerCase());
  const kept: { name: Buffer; content: Uint8Array; mode: string }[] = [];
  const paths = new Set<string>();
  let gitleaksIgnore: Uint8Array | null = null;
  for (const f of snap.files) {
    if (isWorkflowPath(f.path)) {
      userWorkflows.add(f.path.toLowerCase());
      leftOut.push({ path: f.path, why: 'a workflow of your HEAD: never pushed to the scratch repo (pipegen\'s own files come from the draft)' });
      continue;
    }
    if (isBotConfig(f.path)) {
      leftOut.push({ path: f.path, why: 'a Dependabot or Renovate config: left out so the bots open no pull requests in the scratch repo' });
      continue;
    }
    kept.push({ name: pathBytes(f.path), content: f.content, mode: f.mode });
    paths.add(f.path);
    if (f.path === '.gitleaksignore') gitleaksIgnore = f.content;
  }

  // Git LFS: only the pointer files are copied
  let lfs: BaseSnapshot['lfs'] = null;
  const notProven: NotProven[] = symlinkNotProven(snap.dropped, deps.dockerServices ?? []);
  const lfsAttr = snap.files.some((f) => (f.path === '.gitattributes' || f.path.endsWith('/.gitattributes')) && /(^|\s)filter=lfs(\s|$)/m.test(Buffer.from(f.content).toString('utf8')));
  if (lfsAttr) {
    const pointers = kept.filter((f) => f.content.length < 1024 && Buffer.from(f.content).subarray(0, LFS_POINTER.length).toString('latin1') === LFS_POINTER)
      .map((f) => shown(f.name)).sort();
    lfs = { pointers };
    warn(`This repo uses Git LFS (filter=lfs): the proof copies only the pointer files of ${pointers.length} file(s), not their contents, so a build or test that reads them can't be proven.`);
    for (const svc of deps.dockerServices ?? []) {
      const mine = pointers.filter((p) => inside(p, svc.path));
      if (mine.length > 0) {
        notProven.push({
          part: 'docker', missingSecrets: [],
          reason: `${safeText(svc.name, 60)} holds Git LFS files (${mine.length}, e.g. ${mine.slice(0, 3).map((p) => safeText(p, 80)).join(', ')}): the proof copies only their pointer files, so its image build can't be proven.`,
        });
      }
    }
  }

  const entries: Entries = new Map();
  for (const e of await blobEntries(st.repo, kept)) entries.set(keyOf(e.name), e);
  // the last line: nothing under .github/workflows/ in the base, whatever the filters above did
  for (const k of entries.keys()) if (isWorkflowPath(shown(bytesOfKey(k)))) throw new GitTransportError('A workflow file reached the base snapshot; not pushing.');
  const tree = await writeTree(st, entries.values());
  const sha = await commitTree(st, tree, null, `pipegen proof ${t.runId}: base snapshot of HEAD ${snap.commit}`);
  record(st, sha, { kind: 'base', branch: t.defaultBranch, parent: null, entries, allowed: new Set() });
  const commit = proofCommit(st, { kind: 'base', sha, branch: t.defaultBranch, commits: [sha] });
  const base: BaseSnapshot = {
    sha, tree, commit, head: snap.commit, dirtyWarning, dropped: snap.dropped, leftOut, userWorkflows: [...userWorkflows].sort(), paths, gitleaksIgnore, lfs, notProven, warnings,
  };
  st.base = base;
  return base;
}

/** buildBase, then the force-push to the scratch repo's default branch. */
export async function pushBase(s: ProofSession, dir: string, deps: { transport: ProofTransport; io: Pick<CliIO, 'err'>; dockerServices?: readonly Pick<Service, 'name' | 'path'>[] }): Promise<BaseSnapshot> {
  const base = await buildBase(s, dir, deps);
  await pushCommit(s, base.commit, deps.transport);
  return base;
}

const inside = (p: string, folder: string): boolean => {
  const f = folder.replace(/\/+$/, '');
  return f === '' || f === '.' || p === f || p.startsWith(`${f}/`);
};

/**
 * Ruling S4 / the D3 r3 carry: a symlink inside a service whose docker part runs makes that part not-proven (the proof
 * drops symlinks, but a delivered image build would follow them). One note per service, naming the links.
 */
export function symlinkNotProven(dropped: readonly DroppedEntry[], dockerServices: readonly Pick<Service, 'name' | 'path'>[]): NotProven[] {
  const out: NotProven[] = [];
  for (const svc of dockerServices) {
    const links = dropped.filter((d) => d.why === 'symlink' && inside(d.path, svc.path)).map((d) => d.path);
    if (links.length === 0) continue;
    out.push({
      part: 'docker', missingSecrets: [],
      reason: `The build folder of ${safeText(svc.name, 60)} (${safeText(svc.path, 80)}) holds a symlink (${links.slice(0, 5).map((p) => safeText(p, 80)).join(', ')}`
        + `${links.length > 5 ? `, and ${links.length - 5} more` : ''}). The proof doesn't copy symlinks, and a delivered image build would follow them, so docker is not proven for ${safeText(svc.name, 60)}.`,
    });
  }
  return out;
}

// ---------- central draft (S21) ----------

/**
 * The problems of the workflow files among `files` that could start on a push of proof/<runId> (E2-R3, review M4): one
 * top-level trigger key, spelled exactly `on` (no `On`, `ON` or other spelling beside or instead of it), and every trigger
 * workflow_call, workflow_dispatch or schedule. A file pipegen can't read is a problem too.
 */
export function checkCentralTriggers(files: readonly { path: string; content: string }[]): string[] {
  const problems: string[] = [];
  for (const f of files) {
    if (!isWorkflowPath(f.path) || !/\.ya?ml$/i.test(f.path)) continue;
    const name = safeText(f.path, 120);
    const r = parseYaml(f.content, 'user');
    if ('problems' in r) { problems.push(`${name}: pipegen can't read it (${r.problems[0] ?? 'not YAML'})`); continue; }
    const onKeys = Object.keys(r.parsed.js).filter((k) => k.trim().toLowerCase() === 'on');
    if (onKeys.length !== 1 || onKeys[0] !== 'on') {
      problems.push(`${name}: its trigger key must be exactly one \`on\` (found ${onKeys.length === 0 ? 'none' : onKeys.map((k) => JSON.stringify(safeText(k, 20))).join(', ')})`);
      continue;
    }
    const on = r.parsed.js.on;
    const triggers = typeof on === 'string' ? [on] : Array.isArray(on) ? on : isObj(on) ? Object.keys(on) : null;
    if (triggers === null || triggers.length === 0 || !triggers.every((x) => typeof x === 'string')) { problems.push(`${name}: pipegen can't read its triggers`); continue; }
    const bad = (triggers as string[]).filter((x) => !CENTRAL_TRIGGERS.has(x));
    if (bad.length > 0) problems.push(`${name} runs on ${bad.map((x) => safeText(x, 40)).join(', ')}, so pushing proof/<runId> could start it`);
  }
  return problems;
}

export interface CentralLimits { entries?: number; bytes?: number }

/** The default head of `pipelines`, read through the API and checked to rebuild exactly (null: an empty repo). */
async function readCentralHead(gh: Octokit, st: SessionState, central: GuardedRepo, clock: RateClock, limits: CentralLimits): Promise<{ branch: string; commit: string; entries: Entries; workflows: { path: string; content: string }[] } | null> {
  const maxEntries = limits.entries ?? MAX_CENTRAL_ENTRIES;
  const maxBytes = limits.bytes ?? MAX_CENTRAL_BYTES;
  const where = { owner: central.owner, repo: central.repo };
  const cannot = (why: string) => new ProofStopError(`pipegen couldn't copy the default branch of ${central.fullName} for the proof (${why}). Check ${central.fullName}, then run pipegen again.`);
  const get = async (route: string, params: Record<string, unknown>): Promise<unknown> => {
    try {
      return (await githubRead(gh, route, { ...where, ...params }, clock)).data;
    } catch (e) {
      hard(gh, e);
      if ((e as { status?: unknown } | null)?.status === 409) return 'empty';
      throw cannot(saidOf(e));
    }
  };
  const repo = await get('GET /repos/{owner}/{repo}', {}) as { default_branch?: unknown } | null;
  const branch = repo?.default_branch;
  if (typeof branch !== 'string' || !validBranchName(branch)) throw cannot('its default branch could not be read');
  const ref = await get('GET /repos/{owner}/{repo}/git/ref/{ref}', { ref: `heads/${branch}` });
  if (ref === 'empty') return null;
  const commit = (ref as { object?: { sha?: unknown } } | null)?.object?.sha;
  if (typeof commit !== 'string' || !SHA_RE.test(commit)) throw cannot('its head commit could not be read');
  const c = await get('GET /repos/{owner}/{repo}/git/commits/{commit_sha}', { commit_sha: commit }) as { tree?: { sha?: unknown } } | null;
  const treeSha = c?.tree?.sha;
  if (typeof treeSha !== 'string' || !SHA_RE.test(treeSha)) throw cannot('its head tree could not be read');
  const tr = await get('GET /repos/{owner}/{repo}/git/trees/{tree_sha}', { tree_sha: treeSha, recursive: '1' }) as { truncated?: unknown; tree?: unknown } | null;
  if (tr?.truncated !== false || !Array.isArray(tr.tree)) throw cannot('GitHub gave its file list cut short or not at all');
  if (tr.tree.length > maxEntries) throw cannot(`it holds more than ${maxEntries} entries`);
  const blobs: { path: string; mode: string; sha: string }[] = [];
  const entries: Entries = new Map();
  let reported = 0;
  for (const raw of tr.tree as unknown[]) {
    const e = raw as { path?: unknown; mode?: unknown; type?: unknown; sha?: unknown; size?: unknown };
    if (typeof e.path !== 'string' || typeof e.sha !== 'string' || !SHA_RE.test(e.sha)) throw cannot('an entry could not be read');
    // review M3: the workflow folder (or .github) as a symlink or a submodule would hide what the trigger check reads
    const low = e.path.toLowerCase();
    if ((e.mode === '120000' || e.mode === '160000') && (low === '.github' || low === '.github/workflows')) {
      throw cannot(`${safeText(e.path, 80)} is a ${e.mode === '120000' ? 'symlink' : 'submodule'}, so pipegen can't check the workflows behind it`);
    }
    if (e.type === 'tree' && e.mode === '040000') continue;
    const name = pathBytes(e.path);
    if (e.type === 'commit' && e.mode === '160000') { entries.set(keyOf(name), { name, mode: '160000', type: 'commit', sha: e.sha }); continue; }
    if (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755' && e.mode !== '120000')) throw cannot(`${safeText(e.path, 80)} is of a kind pipegen doesn't copy`);
    // review M6: a size GitHub doesn't give is unknown (not 0); the cap holds on the bytes read below
    if (typeof e.size === 'number' && Number.isFinite(e.size) && e.size >= 0) reported += e.size;
    if (reported > maxBytes) throw cannot(`its files add up to more than ${maxBytes} bytes`);
    blobs.push({ path: e.path, mode: e.mode, sha: e.sha });
  }
  const contents = new Map<string, Uint8Array>();
  const shas = [...new Set(blobs.map((b) => b.sha))];
  let read = 0;
  for (let i = 0; i < shas.length; i += BLOB_READ_CONCURRENCY) {
    await Promise.all(shas.slice(i, i + BLOB_READ_CONCURRENCY).map(async (sha) => {
      notStopping();
      const b = await get('GET /repos/{owner}/{repo}/git/blobs/{file_sha}', { file_sha: sha }) as { encoding?: unknown; content?: unknown } | null;
      if (b?.encoding !== 'base64' || typeof b.content !== 'string') throw cannot('a file could not be read');
      const bytes = Buffer.from(b.content.replace(/\s+/g, ''), 'base64');
      read += bytes.length;
      if (read > maxBytes) throw cannot(`its files add up to more than ${maxBytes} bytes`);
      contents.set(sha, bytes);
    }));
  }
  const back = await hashBlobs(st.repo, shas.map((x) => contents.get(x) as Uint8Array));
  if (back.some((x, i) => x !== shas[i])) throw cannot('a file GitHub gave does not hash back to its sha');
  for (const b of blobs) {
    const name = pathBytes(b.path);
    entries.set(keyOf(name), { name, mode: b.mode, type: 'blob', sha: b.sha });
  }
  if (await writeTree(st, entries.values()) !== treeSha) throw cannot('the copy does not rebuild its head tree exactly');
  // a symlink file among the workflows is judged by its target text (not a map: a problem), so it fails closed
  const workflows = blobs.filter((b) => isWorkflowPath(b.path)).map((b) => ({ path: b.path, content: Buffer.from(contents.get(b.sha) as Uint8Array).toString('utf8') }));
  return { branch, commit, entries, workflows };
}

/**
 * Builds proof/<runId> of `pipelines` = its default head + this project's central files (S21; the central layout only).
 * Its sha is what the caller's `uses:` must pin. ProofStopError when a file isn't central, when a workflow of the tree
 * could start on the push, or when the head can't be copied exactly. Nothing is pushed.
 */
export async function buildCentralDraft(s: ProofSession, gh: Octokit, draft: CentralDraft, deps: { clock?: RateClock; limits?: CentralLimits } = {}): Promise<ProofCommit> {
  const st = live(s);
  notStopping();
  if (st.central !== null) throw new GitTransportError('The central draft is built once per proof session.');
  const t = st.target;
  const central = assertCentral(t, { owner: t.owner, repo: t.appRepo });
  checkCentralDraft(draft);
  const own = draft.files.map((f) => ({ name: pathBytes(f.path), path: f.path, content: f.content }));
  const ownProblems = checkCentralTriggers(own);
  if (ownProblems.length > 0) throw new ProofStopError(`pipegen won't push this central draft: ${ownProblems.join('; ')}.`);
  const head = await readCentralHead(gh, st, central, deps.clock ?? clockOf(gh), deps.limits ?? {});
  const entries: Entries = new Map(head?.entries ?? []);
  for (const e of await blobEntries(st.repo, own.map((f) => ({ name: f.name, content: Buffer.from(f.content, 'utf8'), mode: '100644' })))) entries.set(keyOf(e.name), e);
  const ownKeys = new Set(own.map((f) => keyOf(f.name)));
  const inherited = (head?.workflows ?? []).filter((w) => !ownKeys.has(keyOf(Buffer.from(w.path, 'utf8'))));
  const problems = checkCentralTriggers(inherited);
  if (problems.length > 0) throw new ProofStopError(`pipegen won't push proof/${t.runId} to ${central.fullName}: ${problems.join('; ')}. Change that workflow's triggers in ${central.fullName}, then run pipegen again.`);
  const tree = await writeTree(st, entries.values());
  const sha = await commitTree(st, tree, null, `pipegen proof ${t.runId}: central draft for ${t.appRepo}${head === null ? '' : ` on ${head.branch} ${head.commit}`}`);
  const branch = `proof/${t.runId}`;
  record(st, sha, { kind: 'central', branch, parent: null, entries, allowed: new Set(), centralWorkflows: [...inherited, ...own.map((f) => ({ path: f.path, content: f.content }))] });
  st.central = { sha, paths: new Set([...entries.values()].map((e) => shown(e.name))) };
  return proofCommit(st, { kind: 'central', sha, branch, commits: [sha] });
}

/** buildCentralDraft, then the push to proof/<runId> of pipelines. Returns the commit sha. */
export async function pushCentralDraft(s: ProofSession, gh: Octokit, draft: CentralDraft, deps: { transport: ProofTransport; clock?: RateClock; limits?: CentralLimits }): Promise<string> {
  const c = await buildCentralDraft(s, gh, draft, deps);
  await pushCommit(s, c, deps.transport);
  return c.sha;
}

function checkCentralDraft(draft: CentralDraft): void {
  if (!Array.isArray(draft?.files) || draft.files.length === 0) throw new ProofStopError('The central draft holds no file, so there is nothing to prove in pipelines.');
  for (const f of draft.files) {
    if (f.repo !== 'central' || f.inserted !== undefined) throw new ProofStopError(`${safeText(String(f.path), 120)} is not a central file of this project; pipegen pushes only central files to pipelines.`);
    pathBytes(f.path);
  }
}

// ---------- proof branches ----------

/**
 * Builds proof/<runId>/<variant>: one commit per file set, the first on `parent` (default: the base; else a scratch commit
 * of this session), each with exactly that one parent. `pipegenWorkflows` lists the draft's own pipegen workflow files
 * (E2-R5: also at a path HEAD holds; their content is the draft's): the tree may hold no other file under
 * .github/workflows/. Every path, mode and file/folder clash is checked here. Nothing is pushed.
 */
export async function buildProofBranch(s: ProofSession, variant: Variant, commits: readonly (readonly ProofFile[])[], deps: { pipegenWorkflows: ReadonlySet<string>; parent?: string }): Promise<ProofCommit> {
  const st = live(s);
  notStopping();
  if (st.base === null) throw new GitTransportError('A proof branch needs the base snapshot first (buildBase).');
  if (typeof variant !== 'string' || !VARIANT_RE.test(variant)) throw new GitTransportError(`"${safeText(String(variant), 60)}" is not a proof variant.`);
  const t = st.target;
  const parent = deps.parent ?? st.base.sha;
  const start = st.commits.get(parent);
  if (start === undefined || start.kind === 'central') throw new GitTransportError('The parent commit is not a scratch commit pipegen made in this proof session.');
  // review r1-m2: main never builds on planted (or dispute) commits; planted on base, main or planted; a dispute on base,
  // main or its own branch
  const branch = `proof/${t.runId}/${variant}`;
  const mainBranch = `proof/${t.runId}/main`;
  const okParent = start.kind === 'base' || start.branch === branch || (variant !== 'main' && start.branch === mainBranch);
  if (!okParent) throw new GitTransportError(`The parent commit is on ${start.branch}; a ${variant} commit builds only on the base${variant === 'main' ? ' or main' : `, main or ${variant}`}.`);
  const allowed = new Set([...deps.pipegenWorkflows].map((p) => p.toLowerCase()));
  for (const p of allowed) if (!isWorkflowPath(p)) throw new GitTransportError(`${safeText(p, 120)} is not a workflow path.`);
  let cur = parent;
  let entries = start.entries;
  const made: string[] = [];
  for (const [i, files] of commits.entries()) {
    const next: Entries = new Map(entries);
    const add = files.map((f) => {
      const name = pathBytes(f.path);
      const p = shown(name);
      if (isWorkflowPath(p) && !allowed.has(p.toLowerCase())) throw new GitTransportError(`${safeText(p, 120)} is a workflow pipegen didn't list as its own; not pushing it.`);
      if (isBotConfig(p)) throw new GitTransportError(`${safeText(p, 120)} is a Dependabot or Renovate config; it stays out of the scratch repo.`);
      const mode = f.mode ?? '100644';
      if (mode !== '100644' && mode !== '100755') throw new GitTransportError(`${safeText(p, 120)} has a mode pipegen doesn't write.`);
      return { name, content: typeof f.content === 'string' ? Buffer.from(f.content, 'utf8') : f.content, mode };
    });
    for (const e of await blobEntries(st.repo, add)) next.set(keyOf(e.name), e);
    // the tree's workflow files are exactly pipegen's own (checked again right before the push)
    for (const k of next.keys()) {
      const p = shown(bytesOfKey(k));
      if (isWorkflowPath(p) && !allowed.has(p.toLowerCase())) throw new GitTransportError(`${safeText(p, 120)} is a workflow pipegen didn't list as its own; not pushing.`);
    }
    const tree = await writeTree(st, next.values());
    const sha = await commitTree(st, tree, cur, `pipegen proof ${t.runId}: ${variant} (${i + 1}/${commits.length})`);
    record(st, sha, { kind: 'proof', branch, parent: cur, entries: next, allowed });
    cur = sha;
    made.push(sha);
    entries = next;
  }
  if (made.length === 0) throw new GitTransportError('A proof branch needs at least one commit.');
  return proofCommit(st, { kind: 'proof', sha: cur, branch, variant, commits: made });
}

/** buildProofBranch, then one push without force (B3: GitHub refuses a push that doesn't fast-forward). */
export async function pushProofBranch(s: ProofSession, variant: Variant, commits: readonly (readonly ProofFile[])[], deps: { transport: ProofTransport; pipegenWorkflows: ReadonlySet<string>; parent?: string }): Promise<ProofBranch> {
  const c = await buildProofBranch(s, variant, commits, deps);
  await pushCommit(s, c, deps.transport);
  return { variant, branch: c.branch, sha: c.sha, commits: [...c.commits] };
}

// ---------- planted secrets (C1b, ruling S9) ----------

export interface PlantedPlacement {
  /** secret: the gate must block on it; integrity-warning: the repo .gitleaksignore (a warning on the installing PR). */
  kind: 'secret' | 'integrity-warning';
  /** As shown (a name that is not UTF-8 shows U+FFFD); match by `pathBytes`. */
  path: string;
  pathBytes: Uint8Array;
  rule?: 'generic-api-key';
  /** 1-based line of the planted value (0 for the ignore file). */
  line: number;
  nonUtf8?: boolean;
}

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
/** 32 base62 characters with a digit, an upper and a lower letter: gitleaks' generic rule, no provider format. */
function plantedValue(random: (n: number) => Uint8Array): string {
  for (;;) {
    let v = '';
    while (v.length < 32) for (const b of random(48)) if (b < 248 && v.length < 32) v += B62[b % 62];
    if (/[0-9]/.test(v) && /[A-Z]/.test(v) && /[a-z]/.test(v)) return v;
  }
}

const NON_UTF8_NAME = Buffer.concat([Buffer.from('pipegen-c1b/k'), Buffer.from([0xe9]), Buffer.from('y.txt')]);
/** The C1b placements (plan carry E:457): paths outside pipegen-planted/ that path allowlists commonly skip. */
const PLACEMENTS: readonly { path: string | Buffer; body: (v: string) => string; line: number }[] = [
  { path: 'gitleaks.toml/app.js', body: (v) => `const api_key = "${v}";\n`, line: 1 },
  { path: 'src.gitleaks.toml.js', body: (v) => `const api_key = "${v}";\n`, line: 1 },
  { path: 'node_modules/x.js', body: (v) => `const api_key = "${v}";\n`, line: 1 },
  { path: 'vendor/bundle/x.rb', body: (v) => `api_key = "${v}"\n`, line: 1 },
  { path: 'env/lib/x.py', body: (v) => `api_key = "${v}"\n`, line: 1 },
  { path: 'docs/x.svg', body: (v) => `<svg xmlns="http://www.w3.org/2000/svg">\n<desc>api_key = "${v}"</desc>\n</svg>\n`, line: 2 },
  { path: 'docs/x.pdf', body: (v) => `%PDF-1.4\n% api_key = "${v}"\n%%EOF\n`, line: 2 },
  { path: 'go.sum', body: (v) => `api_key = "${v}"\n`, line: 1 },
  { path: 'package-lock.json', body: (v) => `{\n  "api_key": "${v}"\n}\n`, line: 2 },
  { path: NON_UTF8_NAME, body: (v) => `api_key = "${v}"\n`, line: 1 },
];
const C1B_DIR = 'pipegen-c1b';

/**
 * The E-owned planted secrets (C1b, S9): each placement a fresh generic value at a path outside pipegen-planted/ (moved
 * under pipegen-c1b/ when the base already holds that path, a file at one of its folders, or a folder at it), plus a
 * .gitleaksignore that keeps the base's lines and names every placement. Each is its own expected item. The `.gz`/zip
 * member of the carry is left out: the reviewed secrets scanners run with max-archive-depth 0 (plan carry E7).
 */
export function plantedSecretPlacements(basePaths: ReadonlySet<string>, opts: { random?: (n: number) => Uint8Array; existingIgnore?: Uint8Array | null } = {}): { files: ProofFile[]; expected: PlantedPlacement[] } {
  const random = opts.random ?? ((n: number) => randomBytes(n));
  const dirs = new Set<string>();
  for (const p of basePaths) {
    const parts = p.split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  const taken = (p: string) => {
    const parts = p.split('/');
    for (let i = 1; i < parts.length; i++) if (basePaths.has(parts.slice(0, i).join('/'))) return true;
    return basePaths.has(p) || dirs.has(p);
  };
  const files: ProofFile[] = [];
  const expected: PlantedPlacement[] = [];
  const ignore: Buffer[] = [];
  if (opts.existingIgnore !== undefined && opts.existingIgnore !== null && opts.existingIgnore.length > 0) {
    ignore.push(Buffer.from(opts.existingIgnore));
    if (opts.existingIgnore[opts.existingIgnore.length - 1] !== 0x0a) ignore.push(Buffer.from('\n'));
  }
  for (const pl of PLACEMENTS) {
    let bytes = Buffer.isBuffer(pl.path) ? pl.path : Buffer.from(pl.path, 'utf8');
    const s = shown(bytes);
    if (taken(s)) bytes = Buffer.concat([Buffer.from(`${C1B_DIR}/`), bytes]);
    if (taken(shown(bytes))) throw new GitTransportError(`The planted path ${safeText(shown(bytes), 80)} is taken in the base.`);
    const nonUtf8 = Buffer.isBuffer(pl.path);
    files.push({ path: nonUtf8 ? bytes : shown(bytes), content: pl.body(plantedValue(random)) });
    expected.push({ kind: 'secret', path: shown(bytes), pathBytes: bytes, rule: 'generic-api-key', line: pl.line, ...(nonUtf8 ? { nonUtf8: true } : {}) });
    ignore.push(Buffer.concat([bytes, Buffer.from(`:generic-api-key:${pl.line}\n`)]));
  }
  files.push({ path: '.gitleaksignore', content: Buffer.concat(ignore) });
  expected.push({ kind: 'integrity-warning', path: '.gitleaksignore', pathBytes: Buffer.from('.gitleaksignore'), line: 0 });
  return { files, expected };
}

// ---------- GitHub steps of the order ----------

/** Ruling S5: Dependabot security updates off on the scratch repo (guarded DELETE). GitHub refusing it is a warning. */
async function turnOffDependabotUpdates(gh: Octokit, scratch: GuardedRepo, warn: (s: string) => void, clock: RateClock): Promise<void> {
  try {
    await guardedWrite(gh, scratch, 'DELETE /repos/{owner}/{repo}/automated-security-fixes', {}, clock);
  } catch (e) {
    hard(gh, e);
    warn(`pipegen couldn't turn off Dependabot security updates on ${scratch.fullName} (${saidOf(e)}): Dependabot may open pull requests there during the proof. `
      + `Turn them off in ${scratch.fullName} → Settings → Code security.`);
  }
}

const WORKFLOW_PAGES = 10;
/**
 * The safety net (plan Task 2): every workflow GitHub lists for the scratch repo whose path isn't one of pipegen's is
 * disabled (guarded PUT …/disable). Already disabled ones are left. Returns the paths disabled. A list pipegen can't read,
 * or a user workflow GitHub won't disable, is a stop; a dynamic one (not under .github/workflows/) is a warning.
 */
export async function disableUserWorkflows(gh: Octokit, scratch: GuardedRepo, pipegenPaths: ReadonlySet<string>, clock: RateClock = clockOf(gh), warn: (s: string) => void = () => {}): Promise<string[]> {
  requireGuarded(scratch, 'scratch');
  const all: { id: number; path: string; state: string }[] = [];
  for (let page = 1; ; page++) {
    if (page > WORKFLOW_PAGES) throw new ProofStopError(`${scratch.fullName} lists more than ${WORKFLOW_PAGES * 100} workflows; pipegen can't check them all.`);
    let d: { total_count?: unknown; workflows?: unknown } | null;
    try {
      d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/workflows', { owner: scratch.owner, repo: scratch.repo, per_page: 100, page }, clock)).data as typeof d;
    } catch (e) {
      hard(gh, e);
      throw new ProofStopError(`pipegen couldn't list the workflows of ${scratch.fullName} (${saidOf(e)}), so it can't make sure none of yours runs there.`);
    }
    if (!Array.isArray(d?.workflows) || typeof d.total_count !== 'number') throw new ProofStopError(`GitHub's list of the workflows of ${scratch.fullName} could not be read.`);
    for (const w of d.workflows as unknown[]) {
      const x = w as { id?: unknown; path?: unknown; state?: unknown };
      if (typeof x.id !== 'number' || !Number.isSafeInteger(x.id) || typeof x.path !== 'string' || typeof x.state !== 'string') throw new ProofStopError(`GitHub's list of the workflows of ${scratch.fullName} could not be read.`);
      all.push({ id: x.id, path: x.path, state: x.state });
    }
    if (d.workflows.length < 100 || all.length >= d.total_count) break;
  }
  const disabled: string[] = [];
  for (const w of all) {
    if (pipegenPaths.has(w.path) || w.state.startsWith('disabled')) continue;
    try {
      await guardedWrite(gh, scratch, 'PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable', { workflow_id: w.id }, clock);
    } catch (e) {
      hard(gh, e);
      if (!isWorkflowPath(w.path)) { warn(`pipegen couldn't disable ${safeText(w.path, 120)} in ${scratch.fullName} (${saidOf(e)}).`); continue; }
      throw new ProofStopError(`pipegen couldn't disable the workflow ${safeText(w.path, 120)} in ${scratch.fullName} (${saidOf(e)}). Disable it there (Actions → the workflow → Disable workflow), then run pipegen again.`);
    }
    disabled.push(w.path);
  }
  return disabled;
}

const RUNS_NAMED = 3;
/**
 * No workflow run may exist for the base sha (it holds no workflow): one that does is a stop before any secret is stored,
 * naming the runs (id, name, event, path, head branch: review M7) and what to do.
 */
async function checkNoRunForBase(gh: Octokit, scratch: GuardedRepo, baseSha: string, clock: RateClock): Promise<void> {
  let d: { total_count?: unknown; workflow_runs?: unknown } | null;
  try {
    d = (await githubRead(gh, 'GET /repos/{owner}/{repo}/actions/runs', { owner: scratch.owner, repo: scratch.repo, head_sha: baseSha, per_page: 5 }, clock)).data as typeof d;
  } catch (e) {
    hard(gh, e);
    throw new ProofStopError(`pipegen couldn't check the workflow runs of ${scratch.fullName} (${saidOf(e)}), so it stores no secret there.`);
  }
  if (typeof d?.total_count !== 'number') throw new ProofStopError(`GitHub's list of the workflow runs of ${scratch.fullName} could not be read, so pipegen stores no secret there.`);
  if (d.total_count === 0) return;
  const runs = (Array.isArray(d.workflow_runs) ? d.workflow_runs : []).slice(0, RUNS_NAMED).map((x) => {
    const r = (x ?? {}) as { id?: unknown; name?: unknown; event?: unknown; path?: unknown; head_branch?: unknown };
    const f = (v: unknown, n = 80) => (typeof v === 'string' || typeof v === 'number' ? safeText(String(v), n) : '?');
    return `run ${f(r.id, 20)} "${f(r.name)}" (event ${f(r.event, 40)}, workflow ${f(r.path, 120)}, branch ${f(r.head_branch, 100)})`;
  });
  const named = runs.length > 0 ? `: ${runs.join('; ')}${d.total_count > runs.length ? `; and ${d.total_count - runs.length} more` : ''}` : '';
  throw new ProofStopError(`ALERT: a workflow run started in ${scratch.fullName} for the base snapshot (${baseSha.slice(0, 12)}), which holds none of your workflows${named}. `
    + `pipegen stopped before storing any secret there. Disable or remove that workflow in ${scratch.fullName} (Actions → the workflow → Disable workflow; `
    + `for a dynamic one such as CodeQL default setup, turn it off in Settings → Code security), check its rulesets and installed apps, then run pipegen again.`);
}

// ---------- the caller's pins (S24, review M5) ----------

/**
 * The central layout: in every pipegen workflow (parsed), each `uses:` of a job or a step that names `<owner>/pipelines`
 * must be exactly `<owner>/pipelines/<a file of the central commit>@<centralSha>`, the owner the app's, and at least one
 * must exist (the caller). The local layout (no centralSha): none may name pipelines. A workflow pipegen can't read, or a
 * `uses` that isn't text, is a stop.
 */
export function checkCentralPins(files: readonly ProofFile[], t: ProofTarget, centralSha: string | undefined, centralPaths: ReadonlySet<string> | undefined): void {
  let seen = 0;
  for (const f of files) {
    const p = shown(pathBytes(f.path));
    if (!isWorkflowPath(p) || !/\.ya?ml$/i.test(p)) continue;
    const content = typeof f.content === 'string' ? f.content : Buffer.from(f.content).toString('utf8');
    const r = parseYaml(content, 'user');
    if ('problems' in r) throw new ProofStopError(`pipegen can't read its own workflow ${safeText(p, 120)} (${r.problems[0] ?? 'not YAML'}); it won't prove it.`);
    const uses: unknown[] = [];
    const jobs = r.parsed.js.jobs;
    if (isObj(jobs)) {
      for (const job of Object.values(jobs)) {
        if (!isObj(job)) continue;
        if ('uses' in job) uses.push(job.uses);
        if (Array.isArray(job.steps)) for (const step of job.steps) if (isObj(step) && 'uses' in step) uses.push(step.uses);
      }
    }
    for (const u of uses) {
      if (typeof u !== 'string') throw new ProofStopError(`${safeText(p, 120)} has a \`uses:\` that isn't text; pipegen won't prove it.`);
      const at = u.lastIndexOf('@');
      const target = (at === -1 ? u : u.slice(0, at)).trim();
      const parts = target.split('/');
      if (parts.length < 2 || (parts[1] ?? '').toLowerCase() !== 'pipelines' || parts[0] === '.' || parts[0] === '..' || /^[a-z]+:/i.test(target)) continue;
      const where = `${safeText(p, 120)} (uses ${safeText(u, 160)})`;
      const owner = parts[0] ?? '';
      const file = parts.slice(2).join('/');
      const ref = at === -1 ? '' : u.slice(at + 1);
      if (owner.toLowerCase() !== t.owner.toLowerCase()) throw new ProofStopError(`${where} names another owner's central repo; pipegen won't prove it.`);
      if (centralSha === undefined) throw new ProofStopError(`${where} references the central repo, but this draft has no central pin (the local layout); pipegen won't prove it.`);
      if (ref !== centralSha) throw new ProofStopError(`${where} is not pinned to the central draft commit ${centralSha}; pipegen won't prove it.`);
      if (file === '' || !(centralPaths ?? new Set()).has(file)) throw new ProofStopError(`${where} names no file of the central draft commit.`);
      seen++;
    }
  }
  if (centralSha !== undefined && seen === 0) throw new ProofStopError(`No workflow of the proof calls the central draft at ${centralSha}; the central layout needs the caller pinned to it.`);
}

/**
 * E2-R7 (allowlist): the CreatedFile keys of a workflow pipegen rendered whole and fresh. Any other key on a workflow
 * file (`inserted`, `edited`, a merge marker, any marker added later) means it may hold the user's content: it is left
 * out of every proof tree and its part is not-proven.
 */
const RENDERED_WORKFLOW_KEYS: ReadonlySet<string> = new Set(['path', 'content', 'part', 'reason', 'repo', 'needsConfirm']);
const isFreshlyRendered = (f: CreatedFile): boolean => Object.keys(f).every((k) => RENDERED_WORKFLOW_KEYS.has(k) || (f as unknown as Record<string, unknown>)[k] === undefined);

/**
 * The proof branch's files from the assembled ones (E2-R5, E2-R7): a draft workflow pipegen rendered whole and fresh (no
 * marker beyond RENDERED_WORKFLOW_KEYS) goes in with the draft's content, also at a path HEAD holds (HEAD's copy, maybe
 * edited by the user, stays out of every tree). A workflow with any other marker (`inserted`, `edited`, merged, unknown)
 * is left out and reported not-proven; bot configs are left out; central files are refused.
 */
function prepareAppFiles(files: readonly CreatedFile[]): { proof: ProofFile[]; leftOut: LeftOut[]; workflows: Set<string>; notProven: NotProven[] } {
  if (!Array.isArray(files)) throw new ProofStopError('The assembled proof files are not a list.');
  const proof: ProofFile[] = [];
  const leftOut: LeftOut[] = [];
  const notProven: NotProven[] = [];
  const workflows = new Set<string>();
  for (const f of files) {
    if (f.repo !== 'app') throw new ProofStopError(`${safeText(String(f.path), 120)} is a central file; the proof branch takes only the app's files (central files go to pipelines).`);
    pathBytes(f.path);
    if (isBotConfig(f.path)) { leftOut.push({ path: f.path, why: 'a Dependabot or Renovate config: left out of the proof (S5)' }); continue; }
    if (isWorkflowPath(f.path)) {
      if (!isFreshlyRendered(f)) {
        const why = `pipegen's change to ${safeText(f.path, 120)} edits or merges a workflow that may hold your content, so it isn't run in the scratch repo (your workflows never run next to your test keys)`;
        leftOut.push({ path: f.path, why });
        notProven.push({ part: f.part, missingSecrets: [], reason: `${why}; not proven.` });
        continue;
      }
      workflows.add(f.path);
    }
    proof.push({ path: f.path, content: f.content });
  }
  return { proof, leftOut, workflows, notProven };
}

// ---------- the order (plan Task 2) ----------

export interface ProofSetupInput {
  target: ProofTarget;
  /** The app repo folder (its top). */
  dir: string;
  /** checkProofRepos' defaultBranchState: 'pending' (an empty scratch repo) → set again after the base push (E1 carry, S1). */
  defaultBranchState?: DefaultBranchState;
  /** draft.centralPin set: the central layout, these files pushed to proof/<runId> of pipelines. Absent: the local layout. */
  central?: CentralDraft;
  /** The proof branch's files for the central sha (Plan G assemble, signing mode none; E3's harness and compat copies). */
  appFiles: (centralSha: string | undefined) => CreatedFile[] | Promise<CreatedFile[]>;
  /** Plan F's plantedFiles(p) (injected): on the planted branch only. */
  plantedFiles: readonly ProofFile[];
  /** Services whose docker part runs (the symlink and LFS rules). */
  dockerServices?: readonly Pick<Service, 'name' | 'path'>[];
}

export interface ProofSetupDeps {
  gh: Octokit;
  transport: ProofTransport;
  io: Pick<CliIO, 'out' | 'err'>;
  storeSecrets: SecretStoreStep;
  clock?: RateClock;
  /** Wait before the no-run check (default 5000 ms), so a run the base push started can show up. */
  settleMs?: number;
  random?: (n: number) => Uint8Array;
  /** The central head copy's caps (default MAX_CENTRAL_ENTRIES, MAX_CENTRAL_BYTES). */
  centralLimits?: CentralLimits;
}

export interface ProofBranch { variant: Variant; branch: string; sha: string; commits: string[] }
export interface ProofSetup {
  /** Kept for later fast-forward pushes (fix loop, disputes); the caller removes it. */
  session: ProofSession;
  centralSha?: string;
  base: BaseSnapshot;
  branches: { main: ProofBranch; planted: ProofBranch };
  /** The planted items E owns (C1b), each expected by file. Plan F's own are matched by Plan F. */
  planted: PlantedPlacement[];
  disabled: string[];
  notProven: NotProven[];
  leftOut: LeftOut[];
  warnings: string[];
  defaultBranchState?: DefaultBranchState;
}

const branchOf = (c: ProofCommit): ProofBranch => ({ variant: c.variant as Variant, branch: c.branch, sha: c.sha, commits: [...c.commits] });

/**
 * The plan's order for one proof (see the file comment): every commit is built and checked first (review M1), then the
 * writes. Any failure removes the session and passes through.
 */
export async function pushProofSetup(input: ProofSetupInput, deps: ProofSetupDeps): Promise<ProofSetup> {
  const t = input.target;
  if (!isProofTarget(t)) throw new ScratchGuardError('the proof target was not made by proofTarget.');
  notStopping();
  const scratch = assertScratch(t, { owner: t.owner, repo: t.appRepo });
  const clock = deps.clock ?? clockOf(deps.gh);
  const warnings: string[] = [];
  const warn = (w: string) => { warnings.push(w); deps.io.err(w); };
  if (input.central !== undefined) checkCentralDraft(input.central);
  for (const f of input.plantedFiles) {
    const p = shown(pathBytes(f.path));
    if (isWorkflowPath(p) || isBotConfig(p)) throw new ProofStopError(`The planted file ${safeText(p, 120)} is a workflow or bot config; planted files never are.`);
  }
  const s = await openProofSession(t);
  try {
    // 1. build and check every commit (reads only)
    const central = input.central === undefined ? undefined : await buildCentralDraft(s, deps.gh, input.central, { clock, ...(deps.centralLimits === undefined ? {} : { limits: deps.centralLimits }) });
    const centralSha = central?.sha;
    const base = await buildBase(s, input.dir, { io: deps.io, ...(input.dockerServices === undefined ? {} : { dockerServices: input.dockerServices }) });
    warnings.push(...base.warnings);
    const prepared = prepareAppFiles(await input.appFiles(centralSha));
    checkCentralPins(prepared.proof, t, centralSha, live(s).central?.paths);
    const c1b = plantedSecretPlacements(base.paths, { existingIgnore: base.gitleaksIgnore, ...(deps.random === undefined ? {} : { random: deps.random }) });
    const branchDeps = { pipegenWorkflows: prepared.workflows };
    const main = await buildProofBranch(s, 'main', [prepared.proof], branchDeps);
    const planted = await buildProofBranch(s, 'planted', [[...prepared.proof, ...input.plantedFiles, ...c1b.files]], branchDeps);

    // 2. the writes, in the plan's order
    await turnOffDependabotUpdates(deps.gh, scratch, warn, clock);
    if (central !== undefined) await pushCommit(s, central, deps.transport);
    await pushCommit(s, base.commit, deps.transport);
    let defaultBranchState = input.defaultBranchState;
    if (defaultBranchState === 'pending') {
      notStopping();
      defaultBranchState = await setScratchDefaultBranch(deps.gh, scratch, clock);
      if (defaultBranchState === 'pending') throw new ProofStopError(`${scratch.fullName} still shows no branch after the base push; check it on GitHub, then run pipegen again.`);
    }
    notStopping();
    const disabled = await disableUserWorkflows(deps.gh, scratch, prepared.workflows, clock, warn);
    const settle = deps.settleMs ?? 5000;
    if (settle > 0) await new Promise((ok) => setTimeout(ok, settle));
    notStopping();
    await checkNoRunForBase(deps.gh, scratch, base.sha, clock);
    notStopping();
    await deps.storeSecrets(scratch, { baseSha: base.sha });
    notStopping();
    await pushCommit(s, main, deps.transport);
    await pushCommit(s, planted, deps.transport);
    return {
      session: s, ...(centralSha === undefined ? {} : { centralSha }), base, branches: { main: branchOf(main), planted: branchOf(planted) }, planted: c1b.expected, disabled,
      notProven: [...base.notProven, ...prepared.notProven], leftOut: [...base.leftOut, ...prepared.leftOut], warnings, ...(defaultBranchState === undefined ? {} : { defaultBranchState }),
    };
  } catch (e) {
    await s.remove();
    throw e;
  }
}
