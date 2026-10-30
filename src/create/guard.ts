// The created-file guard (v0.2 Plan D, D1; preflight S3 and the path part of S4; ruling B2). Before pipegen writes or proposes a file, the
// guard checks WHERE and OVER WHAT it lands in the user's repository (the referee judges what the file says). The repository tree is hostile:
// the guard never follows a link, never opens a special file, never trusts a name, and it never writes anything. It only decides.
//
// Rules, per file (the first that fires refuses it):
//   repo         the file belongs to the repository the guard was given (`ctx.repo`, default the app repo);
//   path         createdPathProblem (the one path rule for every producer);
//   batch        two files of one batch may not share a path ignoring case, nor may one be the folder of the other;
//   v0.2 edits   no file named pyproject.toml or requirements-dev.txt (Python creators are v0.4);
//   service      a created file under a service folder outside the plain set is refused (S4: that service gets a note only);
//   symlinks     every component under the root is lstat'ed; any symbolic link (a parent, or the file itself, even dangling) is refused;
//   case         a name that equals an existing one ignoring letter case (a macOS or Windows checkout would merge them) is refused,
//                checked against the local folder AND the delivery base tree;
//   file/folder  a path under an existing file, or equal to an existing folder, is refused; a FIFO, device or socket is never opened;
//   create-only  a path that exists locally or in the base tree is refused (#97), unless
//                (a) the file carries `edited` (or `inserted`, for an allowed workflow) whose `original` equals BOTH the disk and the base
//                    tree text, and a registry rule works as an edit on that path; the package.json and package-lock.json edits are
//                    then judged by package-rules.ts (B2); or
//                (b) the install record owns it (`created`) at a blob sha equal to what is now on the disk and in the base tree: it is
//                    replaced (with a note). If the user changed it, it is KEPT with a note (neither ok nor refused);
//   new files    package.json and package-lock.json must already exist; new app source (a code file inside a service folder that is not
//                a test and that no registry rule claims) is refused.
// The guard checks a moment in time. Delivery (Plan G) writes through the Git Data API and repeats the create-only check against the base
// tree it writes onto; the local check here is advice for the person running pipegen, not a lock.
import { createHash } from 'node:crypto';
import { lstat, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { CREATED_RULES } from '../engine/created-files.js';
import { createdPathProblem } from '../engine/job-rules.js';
import { CODE_FILE_RE, isTestFile } from '../read/manifest.js';
import { readTextLimitedWithReason, SKIP_REASON, READ_LIMITS } from '../read/limits.js';
import type { CreatedFile, InstallRecord, PipelineDraft, RepoProfile } from '../types.js';
import { lockProblems, packageJsonProblems } from './package-rules.js';

/** One file of the delivery base tree (the default branch head): its blob sha and its text (null: not readable as text). */
export interface BaseEntry { sha: string; read(): Promise<string | null> }
/** The delivery base tree: blob path to entry. Plan G builds it from `GET /git/trees/<head>?recursive=1`; a submodule counts as a path too. */
export type BaseTree = ReadonlyMap<string, BaseEntry>;

export interface GuardCtx {
  /** The repository folder on disk. */
  root: string;
  baseTree: BaseTree;
  /** What pipegen wrote before (a re-run, #97); null when it never installed here. */
  installRecord: Pick<InstallRecord, 'files'> | null;
  profile: RepoProfile;
  /** Which repository `root` is; files of the other repo are refused. Default `app`. */
  repo?: 'app' | 'central';
  /** Existing workflow paths pipegen may edit through `inserted`. */
  allowWorkflowInsert?: readonly string[];
  /** The reviewed integrity of the B2 pins (name to `sha512-...`), checked in a lock edit when given. */
  integrity?: Readonly<Record<string, string>>;
}
export interface GuardResult {
  ok: CreatedFile[];
  refused: { path: string; reason: string }[];
  notes: string[];
}

const LOCK_MAX_BYTES = 8 * 1024 * 1024;
const PYTHON_NAMES: readonly string[] = ['pyproject.toml', 'requirements-dev.txt'];

/** git's blob sha of a text (what the install record and the trees API hold). */
export function gitBlobSha(text: string): string {
  const body = Buffer.from(text, 'utf8');
  return createHash('sha1').update(`blob ${body.length}\0`).update(body).digest('hex');
}

const baseName = (p: string): string => p.slice(p.lastIndexOf('/') + 1);
/** A repo-derived string made safe for a message: printable ASCII only, short. */
const safe = (s: unknown): string => String(s).replace(/[^\x20-\x7e]/g, '?').slice(0, 80);
const q = (p: string): string => `\`${safe(p)}\``;
const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

type Verdict = { kind: 'ok'; note?: string } | { kind: 'refuse'; reason: string } | { kind: 'keep'; note: string };
const refuse = (reason: string): Verdict => ({ kind: 'refuse', reason });

// ---------- the local tree ----------

type Local = { kind: 'absent' } | { kind: 'file' } | { kind: 'dir' } | { kind: 'refuse'; reason: string };

/** Walks `segs` down from `root` with readdir and lstat on every level (no realpath, nothing followed, nothing opened). */
async function probeLocal(root: string, segs: readonly string[]): Promise<Local> {
  let dir = root;
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i] as string;
    const rel = segs.slice(0, i + 1).join('/');
    const last = i === segs.length - 1;
    let names: string[];
    try { names = await readdir(dir); } catch { return { kind: 'refuse', reason: `the folder of ${q(rel)} could not be listed, so pipegen can not tell what is there` }; }
    if (!names.includes(seg)) {
      const clash = names.find((n) => n.toLowerCase() === seg.toLowerCase());
      return clash === undefined ? { kind: 'absent' } : { kind: 'refuse', reason: `${q(rel)} equals the existing ${q(clash)} ignoring letter case (a macOS or Windows checkout would merge them)` };
    }
    const path = join(dir, seg);
    let st;
    try { st = await lstat(path); } catch { return { kind: 'refuse', reason: `${q(rel)} could not be inspected` }; }
    if (st.isSymbolicLink()) return { kind: 'refuse', reason: `${q(rel)} is a symbolic link, and pipegen never writes through or over one` };
    if (st.isDirectory()) { if (last) return { kind: 'dir' }; dir = path; continue; }
    if (!st.isFile()) return { kind: 'refuse', reason: `${q(rel)} is not a regular file or folder (a pipe, device or socket), and pipegen never opens one` };
    return last ? { kind: 'file' } : { kind: 'refuse', reason: `a file can not be created under ${q(rel)}, which is an existing file` };
  }
  return { kind: 'absent' };
}

// ---------- the base tree ----------

interface BaseIndex { files: ReadonlyMap<string, BaseEntry>; lowerFiles: Map<string, string>; dirs: Set<string>; lowerDirs: Map<string, string> }
function indexBase(tree: BaseTree): BaseIndex {
  const lowerFiles = new Map<string, string>();
  const dirs = new Set<string>();
  const lowerDirs = new Map<string, string>();
  for (const p of tree.keys()) {
    lowerFiles.set(p.toLowerCase(), p);
    for (let i = p.indexOf('/'); i >= 0; i = p.indexOf('/', i + 1)) { const d = p.slice(0, i); dirs.add(d); lowerDirs.set(d.toLowerCase(), d); }
  }
  return { files: tree, lowerFiles, dirs, lowerDirs };
}

type Remote = { kind: 'absent' } | { kind: 'file'; entry: BaseEntry } | { kind: 'refuse'; reason: string };
function probeBase(ix: BaseIndex, segs: readonly string[]): Remote {
  for (let i = 1; i <= segs.length; i++) {
    const x = segs.slice(0, i).join('/');
    const last = i === segs.length;
    const entry = ix.files.get(x);
    if (entry !== undefined) return last ? { kind: 'file', entry } : { kind: 'refuse', reason: `a file can not be created under ${q(x)}, which is an existing file on the default branch` };
    if (ix.dirs.has(x)) { if (last) return { kind: 'refuse', reason: `${q(x)} is an existing folder on the default branch, so a file can not be created at that path` }; continue; }
    const other = ix.lowerFiles.get(x.toLowerCase()) ?? ix.lowerDirs.get(x.toLowerCase());
    if (other !== undefined) return { kind: 'refuse', reason: `${q(x)} equals ${q(other)} on the default branch ignoring letter case (a macOS or Windows checkout would merge them)` };
    return { kind: 'absent' };
  }
  return { kind: 'absent' };
}

// ---------- the guard ----------

/** Rules of the registry that claim `path` for `repo` (only `match` is used, which reads the services of the profile). */
function claimingRules(path: string, repo: 'app' | 'central', profile: RepoProfile) {
  const draft = { profile } as PipelineDraft;
  return CREATED_RULES.filter((r) => { try { return r.repo === repo && r.match(path, draft); } catch { return false; } });
}

/** Whether a service folder is in the plain set (S4): its normalised path passes the path rule. */
const planeService = (raw: string): boolean => { const n = rootPrefix(raw); return n === '' || createdPathProblem(n) === null; };

/** Created files in one batch that share a path ignoring case, or where one is the folder of another: all of them. */
function batchClashes(files: readonly CreatedFile[]): Set<number> {
  const bad = new Set<number>();
  const byLower = new Map<string, number[]>();
  files.forEach((f, i) => { if (typeof f?.path === 'string') { const k = f.path.toLowerCase(); byLower.set(k, [...(byLower.get(k) ?? []), i]); } });
  for (const idx of byLower.values()) if (idx.length > 1) idx.forEach((i) => bad.add(i));
  files.forEach((f, i) => {
    if (typeof f?.path !== 'string') return;
    const segs = f.path.toLowerCase().split('/');
    for (let k = 1; k < segs.length; k++) for (const j of byLower.get(segs.slice(0, k).join('/')) ?? []) { bad.add(i); bad.add(j); }
  });
  return bad;
}

export async function guardCreatedFiles(files: readonly CreatedFile[], ctx: GuardCtx): Promise<GuardResult> {
  const result: GuardResult = { ok: [], refused: [], notes: [] };
  const repo = ctx.repo ?? 'app';
  const ix = indexBase(ctx.baseTree);
  const clashes = batchClashes(files);
  const badServices = ctx.profile.services.map((s) => s.path).filter((p) => !planeService(p));
  for (const raw of badServices) result.notes.push(`The service folder ${JSON.stringify(safe(raw))} has characters or a shape pipegen does not write into (letters, digits, . _ - and / only), so pipegen creates no file there; add what that service needs by hand.`);
  const lenient = badServices.map((p) => p.split('/').filter((s) => s !== '' && s !== '.').join('/').toLowerCase()).filter((p) => p !== '');
  let rootOk = true;
  try { rootOk = (await stat(ctx.root)).isDirectory(); } catch { rootOk = false; }

  const siblingPackageJson = (lockPath: string): string | undefined => {
    const dir = lockPath.includes('/') ? lockPath.slice(0, lockPath.lastIndexOf('/') + 1) : '';
    return files.find((f) => f?.repo === repo && f.path === `${dir}package.json`)?.content;
  };

  async function judge(f: CreatedFile, i: number): Promise<Verdict> {
    if (typeof f !== 'object' || f === null) return refuse('this is not a file description');
    if (typeof f.path !== 'string') return refuse('the path is empty');
    if (f.repo !== repo) return refuse(`this file belongs to the ${safe(f.repo)} repository, but the guard checks the ${repo} repository`);
    const pathProblem = createdPathProblem(f.path);
    if (pathProblem !== null) return refuse(`The file path is refused: ${pathProblem}; pipegen writes only plain, normalized paths.`);
    if (typeof f.content !== 'string') return refuse('the file has no text');
    if (clashes.has(i)) return refuse('another created file has the same path ignoring letter case, or is the folder of this one, and a path can not be both');
    if (PYTHON_NAMES.includes(baseName(f.path).toLowerCase())) return refuse('pipegen does not create or edit pyproject.toml or requirements-dev.txt in this version (Python support comes later)');
    const lower = f.path.toLowerCase();
    if (lenient.some((p) => lower === p || lower.startsWith(`${p}/`))) return refuse('this file is inside a service folder whose name is outside the plain set of characters pipegen writes into, so it gets a note instead of a file');
    if (!rootOk) return refuse('the repository folder could not be read, so pipegen can not check the file against it');

    const segs = f.path.split('/');
    const local = await probeLocal(ctx.root, segs);
    if (local.kind === 'refuse') return refuse(local.reason);
    if (local.kind === 'dir') return refuse(`${q(f.path)} is an existing folder, so a file can not be created at that path`);
    const remote = probeBase(ix, segs);
    if (remote.kind === 'refuse') return refuse(remote.reason);

    if (f.edited !== undefined && f.inserted !== undefined) return refuse('the file carries both the edit marker and the workflow insert marker; it can be only one');
    const marker = f.edited ?? f.inserted;
    if (marker !== undefined && (typeof marker !== 'object' || marker === null || typeof marker.original !== 'string')) return refuse('the edit marker is malformed (it needs the original text)');
    const original = marker?.original;
    const name = baseName(f.path);
    const isPkg = name === 'package.json' || name === 'package-lock.json';
    const onDisk = local.kind === 'file';
    const onBase = remote.kind === 'file';

    if (!onDisk && !onBase) {
      if (f.inserted !== undefined) return refuse('the file marks an edit of an existing workflow, but that workflow does not exist');
      if (original !== undefined && original !== '') return refuse(`the file claims to edit an original text, but ${q(f.path)} does not exist`);
      if (isPkg) return refuse(`${q(f.path)} must already exist: pipegen edits a package.json or package-lock.json and never creates one`);
      if (marker === undefined) {
        const prefix = (r: string): boolean => r === '' || f.path.startsWith(`${r}/`);
        const inService = ctx.profile.services.map((s) => rootPrefix(s.path)).filter(prefix).some((r) => {
          const rel = r === '' ? f.path : f.path.slice(r.length + 1);
          return CODE_FILE_RE.test(rel) && !isTestFile(rel);
        });
        if (inService && claimingRules(f.path, repo, ctx.profile).length === 0) return refuse(`${q(f.path)} would be new source code of your service, and pipegen writes tests, Docker files and pipeline files, never your application's source`);
      }
      return { kind: 'ok' };
    }

    // the path exists somewhere
    const where = onDisk ? 'in your repository' : 'on the default branch (the delivery base)';
    if (marker === undefined) {
      const rec = isPkg ? undefined : ctx.installRecord?.files.find((r) => r.path === f.path && r.created === true);
      if (rec === undefined) return refuse(`${q(f.path)} already exists ${where}; pipegen never overwrites your files`);
      const same: boolean[] = [];
      if (onDisk) {
        const r = await readTextLimitedWithReason(join(ctx.root, ...segs), ctx.root, LOCK_MAX_BYTES);
        same.push('text' in r && gitBlobSha(r.text) === rec.sha);
      }
      if (onBase) same.push((remote as { entry: BaseEntry }).entry.sha === rec.sha);
      if (same.every(Boolean)) return { kind: 'ok', note: `${q(f.path)} is a file pipegen wrote earlier and nobody has changed, so it is replaced.` };
      return { kind: 'keep', note: `${q(f.path)} was written by pipegen earlier but has been changed since, so pipegen keeps your version and writes nothing there.` };
    }

    // an edit of an existing file
    if (f.inserted !== undefined) {
      if (!(ctx.allowWorkflowInsert ?? []).includes(f.path)) return refuse(`the workflow ${q(f.path)} already exists, and pipegen edits an existing workflow only where it was allowed to insert a job`);
    } else if (!claimingRules(f.path, repo, ctx.profile).some((r) => r.mode === 'edit')) return refuse(`pipegen does not edit ${q(f.path)}: it edits only the files it has a rule for (package.json, package-lock.json, CODEOWNERS, dependabot)`);
    if (!onDisk) return refuse(`${q(f.path)} is on the default branch but not in your local folder, so its original can not be checked against your disk`);
    if (!onBase) return refuse(`${q(f.path)} is in your local folder but not on the default branch (the delivery base), so it can not be edited there`);
    const max = name === 'package-lock.json' ? LOCK_MAX_BYTES : READ_LIMITS.maxFileBytes;
    const disk = await readTextLimitedWithReason(join(ctx.root, ...segs), ctx.root, max);
    if ('skipped' in disk) return refuse(`${q(f.path)} on your disk could not be read to compare it with its original: ${SKIP_REASON[disk.skipped]}`);
    if (disk.text.includes('\uFFFD')) return refuse(`${q(f.path)} on your disk is not valid UTF-8 text, so its bytes can not be proven equal to the original`);
    if (disk.text !== original) return refuse(`the original text pipegen worked from differs from ${q(f.path)} on your disk (it changed in the meantime)`);
    let baseText: string | null;
    try { baseText = await (remote as { entry: BaseEntry }).entry.read(); } catch { baseText = null; }
    if (baseText === null) return refuse(`${q(f.path)} on the default branch could not be read to compare it with its original`);
    if (baseText !== original) return refuse(`the original text pipegen worked from differs from ${q(f.path)} on the default branch`);

    if (name === 'package.json') {
      const p = packageJsonProblems(original as string, f.content);
      if (p.length > 0) return refuse(p.join('; '));
    } else if (name === 'package-lock.json') {
      if (f.content.length > LOCK_MAX_BYTES) return refuse('the new package-lock.json is over 8 MiB');
      const pkg = siblingPackageJson(f.path);
      const p = lockProblems(original as string, f.content, { ...(pkg === undefined ? {} : { packageJson: pkg }), ...(ctx.integrity === undefined ? {} : { integrity: ctx.integrity }) });
      if (p.length > 0) return refuse(p.slice(0, 5).join('; '));
    }
    return { kind: 'ok' };
  }

  for (let i = 0; i < files.length; i++) {
    const f = files[i] as CreatedFile;
    let v: Verdict;
    try { v = await judge(f, i); } catch { v = refuse('the file could not be checked, so pipegen does not write it'); }
    if (v.kind === 'ok') { result.ok.push(f); if (v.note !== undefined) result.notes.push(v.note); }
    else if (v.kind === 'refuse') result.refused.push({ path: typeof f?.path === 'string' ? safe(f.path) : '', reason: v.reason });
    else result.notes.push(v.note);
  }
  return result;
}
