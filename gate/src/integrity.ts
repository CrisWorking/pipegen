// Plan C Task C4: pipeline integrity. A pull request can attack the gate by changing the pipeline itself: a workflow, a tool config, an
// ignore file, a suppression comment, or by hiding its changes from the file list. Those changes block unless a code owner approved the
// EXACT head commit. Every GitHub answer and every patch here is hostile: answers are `unknown` and validated, a list that cannot be
// shown complete fails closed (no approval waives that), and the repository's own text never reaches a finding's message.
//
// The pieces: readPrContext (pull, files, reviews), loadCodeowners/codeOwners/ownersOf (CODEOWNERS of the BASE commit, GitHub's
// semantics), integrityFindings (the rule), readConfigSections (a change inside a section of a shared file), baseHasInstall (the
// installing exemption, decided by the base commit's files), addedLinesOf/buildPrDiff (the diff the gate judges "new" by).
import { createHash } from 'node:crypto';
import picomatch from 'picomatch';
import { parse as parseToml } from 'smol-toml';
import type { Finding } from '../../src/types.js';
import { WORKFLOW_PATH, type GateGithub } from './baseline.js';
import type { PrDiff } from './decide.js';
import { STRICT_LOGIN_SOURCE } from './login.js';

// ---------- reading hostile data ----------

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
const posInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
const natInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const SHA_RE = /^[0-9a-f]{40}$/;

export interface RepoId { owner: string; name: string; id: number }

/** The pull files API caps at 3,000 files, 100 per page. */
export const API_FILE_CAP = 3000;
export const PER_PAGE = 100;
/** A patch longer than this is not parsed (the API omits huge ones; a longer one is hostile). */
/** The compare API lists at most this many files, on its first page only. */
export const COMPARE_FILE_CAP = 300;
export const MAX_PATCH_CHARS = 2 * 1024 * 1024;
/** A file read through the contents API (CODEOWNERS, a shared config file) over this size is not read. */
export const MAX_FILE_BYTES = 1024 * 1024;
/** GitHub's own limit for a CODEOWNERS file; 1 to 3 MiB is read through the raw media type. */
export const MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024;
/** At most this many approvers get a permission check. */
const MAX_APPROVERS = 30;

// ---------- types ----------

export interface PrFile { filename: string; previous_filename?: string; status: string; changes: number; patch?: string }
export interface PrContext {
  number: number; headSha: string; baseSha: string;
  isFork: boolean;                     // head.repo.id !== repository.id, or the head repository is gone
  files: PrFile[]; filesComplete: boolean;   // false: fewer or more files than pull.changed_files, the 3,000 cap, or any read problem
  approvals: string[];                 // lower-case logins whose latest non-COMMENTED review is APPROVED on exactly headSha
  approvalsComplete: boolean;          // false: the reviews could not be read in full; approvals is then empty
  problems: string[];                  // fixed texts about what could not be read (never repository text)
}
/**
 * One CODEOWNERS rule. `unreadable` (G15b-R1 S5) marks the place of a line the parser could not keep (over MAX_LINE characters) or of the
 * lines past MAX_RULES: such a place could hold the deciding rule, so a lookup that reaches it is unresolved (it owns nothing itself).
 */
export interface CodeownersRule { pattern: string; owners: string[]; unreadable?: 'line' | 'count' }
export interface SectionChange { file: string; section: string; problem?: string }

// ---------- paths ----------

/**
 * A slashless protected name is protected at ANY depth (`**\/` prefix): tools find configs in sub-folders (bandit's `.bandit` anywhere in
 * the tree, `mypy.ini` in the service folder). An entry with a slash is anchored as written, and a leading `/` scopes a name to the
 * root (`/ruff.toml`: a tool with a pinned config that reads nothing below it; see `rootConfigFiles` in the reviewed list). Case-insensitive, dot files included.
 */
const anyDepth = (p: string): string => (p.startsWith('/') ? p.slice(1) : p.includes('/') ? p : `**/${p}`);
function pathMatcher(patterns: readonly string[]): (path: string) => boolean {
  if (patterns.length === 0) return () => false;
  return picomatch(patterns.map(anyDepth), { nocase: true, dot: true });
}

// ---------- files and markers ----------

const LOCKFILES = new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'poetry.lock', 'uv.lock', 'cargo.lock', 'go.sum', 'composer.lock', 'gemfile.lock']);
const BINARY_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'bmp', 'tif', 'tiff', 'avif', 'heic', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'zip', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar', 'tar', 'jar', 'war',
  'pdf', 'mp3', 'mp4', 'mov', 'webm', 'wav', 'ogg', 'flac', 'avi', 'wasm', 'so', 'dll', 'exe', 'dylib', 'bin', 'class', 'pyc', 'o', 'a', 'sqlite', 'sqlite3', 'psd',
]);
const baseName = (path: string): string => path.slice(path.lastIndexOf('/') + 1);
const isLockfile = (path: string): boolean => LOCKFILES.has(baseName(path).toLowerCase());
const isBinary = (path: string): boolean => { const n = baseName(path).toLowerCase(); const i = n.lastIndexOf('.'); return i > 0 && BINARY_EXT.has(n.slice(i + 1)); };
/**
 * Extensions the scanners pick files by (semgrep's languages, oxlint's file list, ruff, bandit, the IaC and workflow scanners). A file whose
 * extension is one of these in another letter case (`B.JS`, `c.Py`) is skipped by them (semgrep 1.181.0 and oxlint 1.89.0, checked live
 * in review-C4-r2), while a runtime may still load it (Node's `require('./B.JS')` runs it as JavaScript): C5a CF2.
 */
const SCANNED_EXTENSIONS: ReadonlySet<string> = new Set([
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte', 'astro', 'py', 'pyi', 'pyw', 'go', 'java', 'kt', 'kts', 'scala', 'rb', 'php', 'cs', 'swift', 'rs',
  'c', 'h', 'cc', 'cpp', 'cxx', 'hpp', 'm', 'sh', 'bash', 'ex', 'exs', 'lua', 'dart', 'tf', 'hcl', 'yaml', 'yml', 'json', 'html', 'erb', 'sol',
]);
/** The extension of a path when it is a scanned one in another letter case (`JS` for `.js`), else undefined. */
function caseVariantExtension(path: string): string | undefined {
  const n = baseName(path);
  const i = n.lastIndexOf('.');
  if (i <= 0) return undefined;
  const ext = n.slice(i + 1);
  return ext !== ext.toLowerCase() && SCANNED_EXTENSIONS.has(ext.toLowerCase()) ? ext : undefined;
}
/** `.gitleaksignore`, `.semgrepignore`, `.trivyignore`, `.trivyignore.yaml`, `.prettierignore`: any ADDED line is a suppression. */
const IGNORE_FILE_RE = /^\.[^/]*ignore[^/]*$/i;

/** The suppression markers (preflight ruling S14: the plan's list plus Plan P M13). Case-insensitive; fixed names only reach a message. */
const MARKERS: { name: string; re: RegExp }[] = [
  { name: 'nosemgrep', re: /nosem/i },
  { name: 'gitleaks:allow', re: /gitleaks:allow/i },
  { name: 'trivy:ignore', re: /trivy:ignore/i },
  { name: 'noqa', re: /\bnoqa\b/i },   // bare, or with codes; `# noqa: E501` alone is not a security suppression (see MARKER_EXEMPT)
  { name: 'eslint-disable', re: /eslint-disable/i },
  { name: 'eslint config comment', re: /\/\*\s*eslint\s/i },
  { name: 'hadolint ignore', re: /#\s*hadolint\s+(?:global\s+)?ignore/i },
  { name: 'kube-linter ignore', re: /ignore-check\.kube-linter\.io/i },
  { name: 'mypy ignore-errors', re: /#\s*mypy:\s*ignore-errors/i },
  { name: 'nosec', re: /\bnosec\b/i },
  { name: 'checkov:skip', re: /checkov:skip/i },
  { name: 'tfsec:ignore', re: /tfsec:ignore/i },
  { name: 'betterleaks:allow', re: /betterleaks:allow/i },
  { name: 'biome-ignore', re: /biome-ignore/i },
  { name: 'oxlint-disable', re: /oxlint-disable/i },
  { name: 'ruff suppression', re: /#\s*ruff:\s*(?:noqa|disable)/i },
  { name: 'coverage ignore', re: /(?:istanbul|c8|v8)\s+ignore|pragma:\s*no\s*cover/i },
  { name: 'type ignore', re: /#\s*type:\s*ignore|@ts-(?:ignore|expect-error|nocheck)/i },
  { name: 'zizmor ignore', re: /zizmor:\s*ignore/i },
];
/** Markers that apply to the NEXT line (or block): an existing one directly above a changed line suppresses that line too. */
const NEXT_LINE_RE = /nosem|eslint-disable-next-line|oxlint-disable-next-line|hadolint\s+ignore|trivy:ignore|@ts-ignore|@ts-expect-error|biome-ignore|(?:istanbul|c8|v8)\s+ignore\s+next|checkov:skip|tfsec:ignore/i;
/** `noqa: E501, W291` (codes none of which starts with S) is a style suppression, not a security one. */
function noqaIsSecurity(line: string): boolean {
  for (const m of line.matchAll(/\bnoqa\b(?:\s*:\s*([A-Za-z0-9, \t]*))?/gi)) {
    if (m[1] === undefined || m[1].trim() === '') return true;   // blanket noqa suppresses the security rules too
    if (/(^|[\s,])S\d/i.test(m[1])) return true;
  }
  return false;
}
function markersOf(line: string): string[] {
  const out: string[] = [];
  for (const m of MARKERS) {
    if (!m.re.test(line)) continue;
    if (m.name === 'noqa' && !noqaIsSecurity(line)) continue;
    out.push(m.name);
  }
  return out;
}

// ---------- patches ----------

const HUNK_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;
interface ParsedPatch { added: { no: number; text: string }[]; context: Map<number, string> }

/**
 * Parse a unified-diff body (GitHub's `patch`, hunks only). The hunk header's counts decide where a hunk ends, so a line in a hunk body
 * that looks like a header (`+@@ ...`, `+++ b/x`) is content. Anything that does not fit the counts is malformed: null.
 */
function parsePatch(patch: string): ParsedPatch | null {
  if (patch.length > MAX_PATCH_CHARS) return null;
  const lines = patch.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const added: { no: number; text: string }[] = [];
  const context = new Map<number, string>();
  let i = 0;
  while (i < lines.length) {
    const m = HUNK_RE.exec(lines[i] as string);
    if (m === null) return null;
    let oldLeft = m[2] === undefined ? 1 : Number(m[2]);
    let newLeft = m[4] === undefined ? 1 : Number(m[4]);
    let newNo = Number(m[3]);
    i++;
    while (oldLeft > 0 || newLeft > 0) {
      if (i >= lines.length) return null;
      const l = lines[i++] as string;
      const c = l[0];
      if (c === '+') { if (newLeft <= 0) return null; added.push({ no: newNo, text: l.slice(1) }); newNo++; newLeft--; }
      else if (c === '-') { if (oldLeft <= 0) return null; oldLeft--; }
      else if (c === ' ') { if (oldLeft <= 0 || newLeft <= 0) return null; context.set(newNo, l.slice(1)); oldLeft--; newLeft--; newNo++; }
      else if (c === '\\') continue;   // "\ No newline at end of file"
      else return null;
    }
    while (i < lines.length && (lines[i] as string)[0] === '\\') i++;
  }
  return { added, context };
}

/** The `+` lines of a patch by plain prefix: in a well-formed patch these are exactly the added lines. Used when the patch does not parse. */
function plusLines(patch: string): string[] {
  const out: string[] = [];
  for (const l of patch.split('\n')) if (l[0] === '+') out.push(l.slice(1));
  return out;
}

/** Integrity: a text file whose changes could hide a marker. A deletion adds nothing; a binary-looking name is exempt. */
const needsPatch = (f: PrFile): boolean => f.changes > 0 && f.status !== 'removed' && !isBinary(f.filename);
/** The diff: the name is the author's choice, so any file with added content needs its patch. */
const needsPatchForDiff = (f: PrFile): boolean => f.changes > 0 && f.status !== 'removed';

/**
 * The added lines of each file as new-file line numbers. `complete` is false when a patch is missing (a text file with changes) or
 * malformed or too long: the caller then treats every position-form finding as new. Keyed by the file's (new) name.
 */
export function addedLinesOf(files: readonly PrFile[]): { added: Map<string, Set<number>>; complete: boolean; problems: string[] } {
  const added = new Map<string, Set<number>>();
  const problems: string[] = [];
  let complete = true;
  for (const f of files) {
    if (typeof f.patch !== 'string' || f.patch === '') {
      if (needsPatchForDiff(f)) { complete = false; problems.push('a changed file has no patch'); }
      continue;
    }
    const parsed = parsePatch(f.patch);
    if (parsed === null) { complete = false; problems.push('a patch could not be read'); continue; }
    if (parsed.added.length === 0) continue;
    let set = added.get(f.filename);
    if (set === undefined) { set = new Set(); added.set(f.filename, set); }
    for (const a of parsed.added) set.add(a.no);
  }
  return { added, complete, problems: [...new Set(problems)] };
}

// ---------- the pull request ----------

function readFile(entry: unknown): PrFile | undefined {
  if (!isPlain(entry)) return undefined;
  const filename = own(entry, 'filename');
  const status = own(entry, 'status');
  const changes = own(entry, 'changes');
  const prev = own(entry, 'previous_filename');
  const patch = own(entry, 'patch');
  if (typeof filename !== 'string' || filename === '' || typeof status !== 'string' || !natInt(changes)) return undefined;
  if (prev !== undefined && (typeof prev !== 'string' || prev === '')) return undefined;
  return { filename, status, changes, ...(prev === undefined ? {} : { previous_filename: prev as string }), ...(typeof patch === 'string' ? { patch } : {}) };
}

const REVIEW_STATES_IGNORED = new Set(['COMMENTED', 'PENDING']);

/**
 * GET the pull, all its files and all its reviews. Fail closed on everything: the file list is complete only when it has exactly
 * `changed_files` entries and is below the 3,000 cap; approvals are the logins whose latest review that is neither COMMENTED nor
 * PENDING is APPROVED on exactly the head commit (DISMISSED, CHANGES_REQUESTED and any unknown state revoke), and an incomplete review
 * list gives none. `expectHeadSha` (the commit the event is about): when the pull's head has moved, nothing is approved. `codeowners` (the
 * base commit's rules, loaded first) is required: only a login it names as a user is an approver candidate (C4 r1, C5a CF3).
 */
export async function readPrContext(gh: GateGithub, repo: RepoId, prNumber: number, opts: { expectHeadSha?: string; codeowners: readonly CodeownersRule[] }): Promise<PrContext> {
  const pr: PrContext = { number: prNumber, headSha: '', baseSha: '', isFork: true, files: [], filesComplete: false, approvals: [], approvalsComplete: false, problems: [] };
  let pull: unknown;
  try { pull = await gh.getPull(repo.owner, repo.name, prNumber); } catch { pr.problems.push('the pull request could not be read'); return pr; }
  if (!isPlain(pull)) { pr.problems.push('the pull request answer is not an object'); return pr; }
  const head = own(pull, 'head');
  const base = own(pull, 'base');
  const headSha = isPlain(head) ? own(head, 'sha') : undefined;
  const baseSha = isPlain(base) ? own(base, 'sha') : undefined;
  const changed = own(pull, 'changed_files');
  if (own(pull, 'number') !== prNumber || typeof headSha !== 'string' || !SHA_RE.test(headSha) || typeof baseSha !== 'string' || !SHA_RE.test(baseSha) || !natInt(changed)) {
    pr.problems.push('the pull request answer is malformed'); return pr;
  }
  pr.headSha = headSha; pr.baseSha = baseSha;
  const headRepo = isPlain(head) ? own(head, 'repo') : undefined;
  pr.isFork = !(isPlain(headRepo) && own(headRepo, 'id') === repo.id);
  const author = isPlain(own(pull, 'user')) ? own(own(pull, 'user') as Record<string, unknown>, 'login') : undefined;

  // files
  let filesOk = true;
  for (let page = 1; page <= API_FILE_CAP / PER_PAGE; page++) {
    let answer: unknown;
    try { answer = await gh.listPullFiles(repo.owner, repo.name, prNumber, page, PER_PAGE); } catch { filesOk = false; pr.problems.push('the list of changed files could not be read'); break; }
    if (!Array.isArray(answer)) { filesOk = false; pr.problems.push('the list of changed files is not a list'); break; }
    for (const e of answer) {
      const f = readFile(e);
      if (f === undefined) { filesOk = false; pr.problems.push('a changed file entry is malformed'); } else pr.files.push(f);
    }
    if (answer.length < PER_PAGE) break;
  }
  if (filesOk && pr.files.length >= API_FILE_CAP) { filesOk = false; pr.problems.push(`the pull request has ${API_FILE_CAP} files or more, the most the API lists`); }
  if (filesOk && pr.files.length !== changed) { filesOk = false; pr.problems.push(`the list has ${pr.files.length} files, the pull request says ${changed}`); }
  // the files are the pull's CURRENT head; if the event was about another commit they are not the files of that commit
  if (opts.expectHeadSha !== undefined && opts.expectHeadSha !== headSha) { filesOk = false; pr.problems.push('the pull request head moved since the event; re-run the gate'); }
  pr.filesComplete = filesOk;
  pr.problems = [...new Set(pr.problems)];

  // reviews
  const reviews: { id: number; login: string; state: string; commit: unknown }[] = [];
  let reviewsOk = true;
  for (let page = 1; page <= API_FILE_CAP / PER_PAGE + 1; page++) {
    let answer: unknown;
    try { answer = await gh.listPullReviews(repo.owner, repo.name, prNumber, page, PER_PAGE); } catch { reviewsOk = false; pr.problems.push('the reviews could not be read'); break; }
    if (!Array.isArray(answer)) { reviewsOk = false; pr.problems.push('the reviews are not a list'); break; }
    for (const r of answer) {
      if (!isPlain(r) || !posInt(own(r, 'id'))) continue;
      const user = own(r, 'user');
      const login = isPlain(user) ? own(user, 'login') : undefined;
      const state = own(r, 'state');
      if (typeof login !== 'string' || login === '' || typeof state !== 'string') continue;
      reviews.push({ id: own(r, 'id') as number, login: login.toLowerCase(), state, commit: own(r, 'commit_id') });
    }
    if (answer.length < PER_PAGE) break;
    if (page === API_FILE_CAP / PER_PAGE + 1) { reviewsOk = false; pr.problems.push('the reviews were cut at the page cap'); }
  }
  pr.approvalsComplete = reviewsOk;
  if (!reviewsOk) return pr;
  if (opts.expectHeadSha !== undefined && opts.expectHeadSha !== headSha) return pr;   // nothing is approved
  const latest = new Map<string, { id: number; state: string; commit: unknown }>();
  for (const r of reviews) {
    if (REVIEW_STATES_IGNORED.has(r.state)) continue;
    const cur = latest.get(r.login);
    if (cur === undefined || r.id > cur.id) latest.set(r.login, r);
  }
  // Owners first: only a login that CODEOWNERS names as a user gets a permission check (so throwaway approvers cost nothing and cannot
  // crowd the real owner out), then the cap, then the permission itself.
  // required (C5a CF3): without the owner filter the approver flood is back; a list missing at run time counts as no owner at all
  const ownerLogins = new Set((Array.isArray(opts.codeowners) ? opts.codeowners : []).flatMap((r) => r.owners));
  const authorLogin = typeof author === 'string' ? author.toLowerCase() : '';
  const candidates = [...latest]
    .filter(([login, r]) => r.state === 'APPROVED' && r.commit === headSha && login !== authorLogin && ownerLogins.has(login))
    .map(([login]) => login).sort();
  if (candidates.length > MAX_APPROVERS) pr.problems.push(`more than ${MAX_APPROVERS} code-owner approvers; only the first ${MAX_APPROVERS} were checked`);
  // an approval counts only from a user with write, maintain or admin permission (GitHub's own rule for code owners); any error means no
  for (const login of candidates.slice(0, MAX_APPROVERS)) {
    try {
      const a = await gh.collaboratorPermission(repo.owner, repo.name, login);
      const perm = isPlain(a) ? own(a, 'permission') : undefined;
      const role = isPlain(a) ? own(a, 'role_name') : undefined;
      if (perm === 'admin' || perm === 'write' || role === 'maintain' || role === 'admin' || role === 'write') pr.approvals.push(login);
    } catch { pr.problems.push(`approval by ${login.replace(/[^a-z0-9-]/g, '?').slice(0, 39)} not counted: could not read their permission`); }
  }
  return pr;
}

// ---------- reading a file at a commit ----------

type Read = { kind: 'missing' } | { kind: 'text'; text: string } | { kind: 'problem'; why: string };
async function readTextAt(gh: GateGithub, repo: RepoId, path: string, ref: string, opts: { max?: number; raw?: boolean } = {}): Promise<Read> {
  const max = opts.max ?? MAX_FILE_BYTES;
  if (!SHA_RE.test(ref)) return { kind: 'problem', why: 'the commit is not a commit sha' };
  let a: unknown;
  try { a = await gh.fileAt(repo.owner, repo.name, path, ref); } catch { return { kind: 'problem', why: 'the file could not be read' }; }
  if (a === null) return { kind: 'missing' };
  if (!isPlain(a) || own(a, 'type') !== 'file') return { kind: 'problem', why: 'the answer is not a file' };
  const size = own(a, 'size');
  const content = own(a, 'content');
  if (!natInt(size) || size > max) return { kind: 'problem', why: 'the file is over the size cap' };
  if (own(a, 'encoding') === 'none' && opts.raw === true && size > MAX_FILE_BYTES) {
    let raw: unknown;
    try { raw = await gh.rawFileAt(repo.owner, repo.name, path, ref); } catch { return { kind: 'problem', why: 'the file could not be read' }; }
    const bytes = typeof raw === 'string' ? Buffer.from(raw, 'utf8') : raw instanceof Uint8Array ? raw : undefined;
    if (bytes === undefined) return { kind: 'problem', why: 'the file content is not readable' };
    if (bytes.length > max) return { kind: 'problem', why: 'the file is over the size cap' };
    return { kind: 'text', text: Buffer.from(bytes).toString('utf8') };
  }
  if (own(a, 'encoding') !== 'base64' || typeof content !== 'string' || size > MAX_FILE_BYTES) return { kind: 'problem', why: size > MAX_FILE_BYTES ? 'the file is over the size cap' : 'the file content is not readable' };
  const bytes = Buffer.from(content.replace(/\s+/g, ''), 'base64');
  if (bytes.length > MAX_FILE_BYTES) return { kind: 'problem', why: 'the file is over the size cap' };
  return { kind: 'text', text: bytes.toString('utf8') };
}

/** The installing exemption's input: does the BASE commit have the pipegen workflow? 404 → false; any other error or answer → true (fail closed). */
export async function baseHasInstall(gh: GateGithub, repo: RepoId, baseSha: string): Promise<boolean> {
  if (typeof baseSha !== 'string' || !SHA_RE.test(baseSha)) return true;
  try { return (await gh.fileAt(repo.owner, repo.name, WORKFLOW_PATH, baseSha)) !== null; } catch { return true; }
}

// ---------- CODEOWNERS ----------

export const MAX_RULES = 100_000;
export const MAX_LINE = 4096;
const TEAM_RE = /^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** `@login` of a user, EMU logins included (E9, gate/src/login.ts); group 1 is the login. */
export const LOGIN_RE = new RegExp(`^@(${STRICT_LOGIN_SOURCE})$`);

/** Split a line into tokens on unescaped whitespace; `\ ` is a space inside a token. Stops at a token that starts with `#`. */
function tokens(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let started = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i] as string;
    if (c === '\\' && line[i + 1] === ' ') { cur += ' '; started = true; i++; continue; }
    if (c === ' ' || c === '\t') { if (started) { out.push(cur); cur = ''; started = false; } continue; }
    if (!started && c === '#') break;
    cur += c; started = true;
  }
  if (started) out.push(cur);
  return out;
}

/**
 * Parse CODEOWNERS text: one rule per line, `pattern owner...`. Owners are user logins only (`@name`): `@org/team` and e-mail owners are
 * dropped (a team-only rule still owns its paths, with no user who can approve). Lines GitHub rejects are skipped: a pattern starting
 * with `!` or `\#`, or containing `[` `]`. G15b-R1 S5: a line over MAX_LINE characters, and the lines past MAX_RULES, are not dropped
 * silently (that could hand their paths to an earlier rule's owners): each leaves an `unreadable` place that a lookup reaching it can not
 * pass (fail closed). A blank or comment line can own nothing, so it never leaves one.
 */
export function codeOwners(text: string | null): CodeownersRule[] {
  if (typeof text !== 'string') return [];
  const rules: CodeownersRule[] = [];
  const canOwn = (raw: string): boolean => { const t = raw.trim(); return t !== '' && !t.startsWith('#'); };
  for (const raw of text.split(/\r?\n/)) {
    if (rules.length >= MAX_RULES) {
      if (canOwn(raw)) { rules.push({ pattern: '', owners: [], unreadable: 'count' }); break; }
      continue;
    }
    if (raw.length > MAX_LINE) { if (canOwn(raw)) rules.push({ pattern: '', owners: [], unreadable: 'line' }); continue; }
    const t = tokens(raw.trim());
    const pattern = t[0];
    if (pattern === undefined) continue;
    if (pattern.startsWith('!') || pattern.startsWith('\\#') || /[[\]]/.test(pattern)) continue;
    if (pattern.replace(/\//g, '') === '' || pattern.includes('//')) continue;
    const owners: string[] = [];
    let valid = true;
    for (const o of t.slice(1)) {
      const m = LOGIN_RE.exec(o);
      if (m !== null) owners.push((m[1] as string).toLowerCase());
      else if (!TEAM_RE.test(o) && !EMAIL_RE.test(o)) { valid = false; break; }   // a team or an e-mail is valid but has no user to count
    }
    if (valid) rules.push({ pattern, owners });   // GitHub skips a line with an invalid owner whole
  }
  return rules;
}

/** A glob token: STAR (`*`), ANY (`?`), or one literal character (G15b-R1 S2: an escaped `\*` or `\?` is the literal character). */
const STAR = 0;
const ANY = 1;
type Tok = typeof STAR | typeof ANY | string;
type Seg = { kind: 'globstar' } | { kind: 'globstar+' } | { kind: 'glob'; toks: Tok[] };
interface Compiled { segs: Seg[]; dirOnly: boolean; ancestors: boolean; tooLong: boolean }
const compiled = new WeakMap<CodeownersRule, Compiled>();

/**
 * G15b (review-G17G-r1 F7): a rule has at most this many path segments (an unanchored rule's leading `**` counts). A longer rule is kept
 * (skipping it could hand its paths to an earlier rule's owners), but a lookup that reaches it before any later rule matches is
 * unresolved: the gate fails closed on that path and says why.
 */
export const MAX_RULE_SEGMENTS = 64;
/**
 * G15b (F7): the steps (DP positions visited, characters compared, and RULE_VISIT_STEPS per rule visited) one gate run may spend on
 * CODEOWNERS lookups, shared by every path of the run; a standalone ownersLookup/ownersOf call gets its own. Measured (G15b-R1 S4, this
 * machine): spending the whole budget takes 1.7 s with a 100,000-rule base file of plain rules, 2.7 s with the reviewer's 46-rule file
 * against 256-part paths, 3.1 s with a 4,000-character part against `*a*a...b`, 3.6 s with a glob-heavy rule (4 to 9 ns a step): about
 * 4 s at most. A 256-part path under the 46-rule file costs about 20,000 steps (a plain 3-part path about 1,000), so 3,000 such files
 * spend about 6e7. Past the budget every remaining lookup is unresolved (fail closed).
 */
export const OWNERS_STEP_BUDGET = 400_000_000;
/** The steps left; ownersLookup spends from it. */
export interface OwnerSteps { left: number }
/** A CODEOWNERS lookup: the owners (undefined when no rule matches), or why the gate could not work them out (it then waives nothing). */
export type OwnersLookup = { owners: string[] | undefined } | { unresolved: Unresolved };
/**
 * Why a lookup is unresolved: a deciding rule over MAX_RULE_SEGMENTS; the step budget spent; the path has more than 256 parts or an empty
 * part (G15b-R1 S1); an unreadable CODEOWNERS line, or rules past MAX_RULES (S5).
 */
export type Unresolved = 'segments' | 'budget' | 'path' | 'unreadable';
/** G15b-R1 S4: the steps one rule visit costs (measured: a visit whose first segment fails takes about as long as 16 DP steps). */
export const RULE_VISIT_STEPS = 16;
/** ownersOf's failure: the lookup is unresolved (fail closed; the caller treats the path as owned by nobody it can count). */
export class OwnersUnresolvedError extends Error {
  constructor(readonly why: Unresolved) { super(`CODEOWNERS lookup unresolved (${why})`); this.name = 'OwnersUnresolvedError'; }
}

function compile(rule: CodeownersRule): Compiled {
  const got = compiled.get(rule);
  if (got !== undefined) return got;
  let p = rule.pattern;
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith('/') || p.includes('/');
  if (p.startsWith('/')) p = p.slice(1);
  let parts = p.split('/');
  if (!anchored) parts = ['**', ...parts];
  if (parts.length > MAX_RULE_SEGMENTS) {
    const c = { segs: [], dirOnly, ancestors: false, tooLong: true };
    compiled.set(rule, c);
    return c;
  }
  const segs: Seg[] = parts.map((part, idx) => {
    if (part === '**') return idx === parts.length - 1 ? { kind: 'globstar+' } : { kind: 'globstar' };
    const toks: Tok[] = [];
    for (let i = 0; i < part.length; i++) {
      const c = part[i] as string;
      if (c === '\\' && i + 1 < part.length) { toks.push(part[++i] as string); continue; }   // an escaped character is literal (gitignore)
      if (c === '*') { if (toks[toks.length - 1] !== STAR) toks.push(STAR); continue; }
      toks.push(c === '?' ? ANY : c);
    }
    return { kind: 'glob', toks };
  });
  const lastSeg = segs[segs.length - 1] as Seg;
  // a final segment with a wildcard (or a final `**`) names files (`docs/*` is not the whole docs tree); a literal one names a file or a directory
  const ancestors = dirOnly || (lastSeg.kind === 'glob' && !lastSeg.toks.some((t) => t === STAR || t === ANY));
  const c = { segs, dirOnly, ancestors, tooLong: false };
  compiled.set(rule, c);
  return c;
}

/**
 * `*` and `?` never cross a `/` (the segment is already split). Two-pointer match with backtracking on the last star. Spends one step per
 * loop turn from `steps`; returns null when they run out.
 */
function segMatch(toks: readonly Tok[], s: string, steps: OwnerSteps): boolean | null {
  let t = 0; let i = 0; let star = -1; let mark = 0; let n = 0;
  let r: boolean | undefined;
  while (i < s.length) {
    n++;
    const k = toks[t];
    if (k === STAR) { star = t++; mark = i; }
    else if (k !== undefined && (k === ANY || k === s[i])) { t++; i++; }
    else if (star >= 0) { t = star + 1; i = ++mark; }
    else { r = false; break; }
  }
  if (r === undefined) { while (toks[t] === STAR) { t++; n++; } r = t === toks.length; }
  steps.left -= n + 1;
  return steps.left < 0 ? null : r;
}

/**
 * G15b (F7): one DP over every prefix of the path at once. `reach` holds, in ascending order, the positions j (0..n) such that the
 * segments so far match parts[0..j); a rule matches the prefix of k parts when the last row holds k. O(segments x parts) per rule (the
 * old matcher ran a fresh DP per prefix and was about n^2.8 in the path length). Same answers as before: `**` matches zero or more whole
 * parts, a final `**` one or more, a glob exactly one; the full path counts unless the rule is dir-only, a shorter prefix only when the
 * rule names its descendants (`ancestors`). Returns null when the steps run out.
 */
function ruleMatches(c: Compiled, parts: readonly string[], steps: OwnerSteps): boolean | null {
  const n = parts.length;
  let reach: number[] = [0];
  for (const seg of c.segs) {
    let next: number[] = [];
    if (seg.kind === 'glob') {
      for (const j of reach) {
        if (j >= n) continue;
        const m = segMatch(seg.toks, parts[j] as string, steps);
        if (m === null) return null;
        if (m) next.push(j + 1);
      }
    } else {
      const from = (reach[0] as number) + (seg.kind === 'globstar+' ? 1 : 0);   // reach is never empty here, and ascending
      if ((steps.left -= n + 1 - from) < 0) return null;
      next = [];
      for (let j = from; j <= n; j++) next.push(j);
    }
    if (next.length === 0) return false;
    reach = next;
  }
  for (const k of reach) {
    if (k === n ? !c.dirOnly : k >= 1 && c.ancestors) return true;
  }
  return false;
}

/**
 * The owners (users) of `path` by the LAST matching rule: `[]` when that rule has no user owner (it clears ownership), undefined when no
 * rule matches. Case sensitive. Rules are tried from the last one back, so the first match decides. Fail closed (G15b, F7): reaching a
 * rule over MAX_RULE_SEGMENTS before any match, or running out of `steps`, gives `unresolved`. G15b-R1: so do a path of more than 256 parts
 * or with an empty part (S1: never "no owner", which would let pipegen's block owners waive), and reaching an unreadable place (S5).
 * Every rule visited costs RULE_VISIT_STEPS (S4), so the budget tracks time with a huge base CODEOWNERS too.
 */
export function ownersLookup(rules: readonly CodeownersRule[], path: string, steps: OwnerSteps = { left: OWNERS_STEP_BUDGET }): OwnersLookup {
  const parts = path.split('/');
  if (parts.length > 256 || parts.includes('')) return { unresolved: 'path' };
  for (let i = rules.length - 1; i >= 0; i--) {
    const r = rules[i] as CodeownersRule;
    if ((steps.left -= RULE_VISIT_STEPS) < 0) return { unresolved: 'budget' };
    if (r.unreadable !== undefined) return { unresolved: 'unreadable' };
    const c = compile(r);
    if (c.tooLong) return { unresolved: 'segments' };
    const m = ruleMatches(c, parts, steps);
    if (m === null) return { unresolved: 'budget' };
    if (m) return { owners: r.owners };
  }
  return { owners: undefined };
}

/** ownersLookup's owners; throws OwnersUnresolvedError when the lookup is unresolved (fail closed). */
export function ownersOf(rules: readonly CodeownersRule[], path: string): string[] | undefined {
  const r = ownersLookup(rules, path);
  if ('unresolved' in r) throw new OwnersUnresolvedError(r.unresolved);
  return r.owners;
}

/** The lines that open and close pipegen's own block in a CODEOWNERS file (the builder, src/engine/created-builders.ts, writes these). */
export const PIPEGEN_BLOCK_BEGIN = '# pipegen:begin';
export const PIPEGEN_BLOCK_END = '# pipegen:end';

/**
 * gate-v0.2.1 (Plan C MUST-DO, Plan D D0b review important 5): the user owners listed in pipegen's own CODEOWNERS block, lower-cased, sorted,
 * once each. The block is the lines between a line that is exactly PIPEGEN_BLOCK_BEGIN and one that is exactly PIPEGEN_BLOCK_END (a CR
 * before the newline is allowed), read with the same parser as the whole file. Fail closed: no block, more than one begin or end line, or
 * an end before the begin gives nobody.
 */
export function pipegenBlockOwners(text: string | null): string[] {
  if (typeof text !== 'string') return [];
  const lines = text.split(/\r?\n/);
  const begins = lines.flatMap((l, i) => (l === PIPEGEN_BLOCK_BEGIN ? [i] : []));
  const ends = lines.flatMap((l, i) => (l === PIPEGEN_BLOCK_END ? [i] : []));
  if (begins.length !== 1 || ends.length !== 1 || (ends[0] as number) < (begins[0] as number)) return [];
  const inside = codeOwners(lines.slice((begins[0] as number) + 1, ends[0] as number).join('\n'));
  return [...new Set(inside.flatMap((r) => r.owners))].sort();
}

/**
 * CODEOWNERS of the BASE commit: `.github/CODEOWNERS`, then `CODEOWNERS`, then `docs/CODEOWNERS`; the first that exists is the file. Never the head.
 * `blockOwners`: the owners of pipegen's own block in that file (pipegenBlockOwners); none when there is no file or it can not be read.
 */
export async function loadCodeowners(gh: GateGithub, repo: RepoId, baseSha: string): Promise<{ rules: CodeownersRule[]; found: string | null; blockOwners: string[]; problem?: string }> {
  for (const path of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
    const r = await readTextAt(gh, repo, path, baseSha, { max: MAX_CODEOWNERS_BYTES, raw: true });
    if (r.kind === 'missing') continue;
    if (r.kind === 'problem') return { rules: [], found: null, blockOwners: [], problem: `CODEOWNERS of the base commit could not be read (${r.why}); nobody can approve` };
    return { rules: codeOwners(r.text), found: path, blockOwners: pipegenBlockOwners(r.text) };
  }
  return { rules: [], found: null, blockOwners: [] };
}

// ---------- configSections ----------


/** A non-finite TOML number (nan, inf, -inf). A class, so no document can produce one by spelling a key or a table. */
export class NonFinite { constructor(readonly kind: 'nan' | 'inf' | '-inf') {} }
/** A TOML integer, by its digits (C5a CF4: always this class, so `1` and `1.0` stay different values, and a 64-bit integer is read exactly). */
export class BigInteger { constructor(readonly digits: string) {} }

const isTable = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && !(v instanceof NonFinite) && !(v instanceof BigInteger) && !(v instanceof Date);

/** A document as plain data: non-finite numbers and big integers become typed tags, never a string or an object a document could write. */
function norm(v: unknown): unknown {
  if (typeof v === 'number') return Number.isFinite(v) ? v : new NonFinite(Number.isNaN(v) ? 'nan' : v > 0 ? 'inf' : '-inf');
  if (typeof v === 'bigint') return new BigInteger(String(v));
  if (Array.isArray(v)) return v.map(norm);
  if (isTable(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])]));
  return v;
}
/** An injective text form: every value is typed, so no value of one type can equal another's text. */
function canon(v: unknown): string {
  if (v instanceof NonFinite) return `F:${v.kind}`;
  if (v instanceof BigInteger) return `I:${v.digits}`;
  if (v instanceof Date) return `D:${v.toISOString()}`;
  if (typeof v === 'number') return `n:${Object.is(v, -0) ? '-0' : String(v)}`;
  if (typeof v === 'string') return `s:${JSON.stringify(v)}`;
  if (typeof v === 'boolean') return `b:${v}`;
  if (v === null || v === undefined) return 'z';
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (isTable(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}=${canon(v[k])}`).join(',')}}`;
  return `?:${String(v)}`;
}

/**
 * Python configparser (`RawConfigParser`, strict), ported: a header is `^\[(.+)\]` (greedy) on the stripped line and the rest of the line
 * is ignored; an indented line after an option continues it; `#` and `;` lines are comments (not inline ones); blank lines inside a value
 * are kept; `[DEFAULT]` is merged into every section; keys are lower-cased; values are kept as written (`""` is two characters); a duplicate section or option, an option before a header, a
 * line without `=` or `:` and an empty key are errors (undefined).
 */
/**
 * Python reads a file with universal newlines and `str.strip`/`\S` over its own whitespace set; JavaScript's differ (`\x1c`-`\x1f`, `\x85`,
 * `\ufeff`, a lone `\r`, `\v`, `\f`, U+2028/9). A file with any of them, or any other C0/C1 control character, is not read at all.
 */
const INI_UNSAFE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufeff]|\r(?!\n)/;
function parseIni(text: string): Record<string, Record<string, string>> | undefined {
  if (INI_UNSAFE.test(text)) return undefined;
  const sections = new Map<string, Map<string, string[]>>();
  const defaults = new Map<string, string[]>();
  let cur: Map<string, string[]> | undefined;
  let curName = '';
  let opt: string | undefined;
  let indentLevel = 0;
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const stripped = line.trim();
    const comment = stripped.startsWith('#') || stripped.startsWith(';');
    const value = comment ? '' : stripped;
    if (value === '') {
      if (!comment && cur !== undefined && opt !== undefined) cur.get(opt)?.push('');
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (cur !== undefined && opt !== undefined && indent > indentLevel) { cur.get(opt)?.push(value); continue; }
    indentLevel = indent;
    const h = /^\[(.+)\]/.exec(value);
    if (h !== null) {
      const name = h[1] as string;
      if (name === 'DEFAULT') { cur = defaults; curName = name; }
      else { if (sections.has(name)) return undefined; cur = new Map(); sections.set(name, cur); curName = name; }
      opt = undefined;
      continue;
    }
    if (cur === undefined) return undefined;
    const o = /^(.*?)\s*[=:]\s*(.*)$/.exec(value);
    if (o === null) return undefined;
    const key = (o[1] as string).trimEnd().toLowerCase();
    if (key === '') return undefined;
    const id = `${curName}\0${key}`;
    if (seen.has(id)) return undefined;
    seen.add(id);
    const first = (o[2] as string).trim();
    cur.set(key, [first]);   // `k = ""` keeps its two quote characters, as Python's RawConfigParser does (C5a CF4)
    opt = key;
  }
  const done = (lines: string[]): string => lines.join('\n').trimEnd();
  const out: Record<string, Record<string, string>> = {};
  for (const [name, entries] of sections) {
    const merged: Record<string, string> = {};
    for (const [k, v] of defaults) merged[k] = done(v);
    for (const [k, v] of entries) merged[k] = done(v);
    out[name] = merged;
  }
  return out;
}

/** A shared config file as plain data (JSON, TOML or INI by extension); undefined when it does not parse as the tool's parser would. */
export function parseConfigDoc(path: string, text: string): Record<string, unknown> | undefined {   // tables, TOML non-finite numbers as NonFinite
  const lower = path.toLowerCase();
  try {
    if (lower.endsWith('.json')) { const v: unknown = JSON.parse(text); return isTable(v) ? (norm(v) as Record<string, unknown>) : undefined; }
    if (lower.endsWith('.toml')) return norm(parseToml(text, { integersAsBigInt: true })) as Record<string, unknown>;   // integers typed apart from floats (CF4)
    if (lower.endsWith('.cfg') || lower.endsWith('.ini')) return parseIni(text);
  } catch { return undefined; }
  return undefined;
}

interface Section { segs: string[]; value: unknown }
/**
 * The sections of a parsed document, keyed by their key path: INI sections and JSON top-level keys are one segment (the whole name);
 * TOML tables are the list of keys from the root (`["tool.mypy"]` is ONE segment and is not `tool` + `mypy`). Dotted literal keys are
 * fine: they are one segment, never equal to a table path.
 */
function sectionTree(path: string, doc: Record<string, unknown>): Map<string, Section> {
  const t = new Map<string, Section>();
  if (!path.toLowerCase().endsWith('.toml')) { for (const k of Object.keys(doc)) t.set(JSON.stringify([k]), { segs: [k], value: doc[k] }); return t; }
  const walk = (v: unknown, prefix: string[], depth: number): void => {
    if (!isTable(v) || depth > 16) return;
    for (const k of Object.keys(v)) {
      const segs = [...prefix, k];
      t.set(JSON.stringify(segs), { segs, value: v[k] });
      walk(v[k], segs, depth + 1);
    }
  };
  walk(doc, [], 0);
  return t;
}

const sectionRe = (section: string): RegExp => new RegExp(`^${section.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
const safeName = (s: string): string => s.replace(/[^A-Za-z0-9._:*/() -]/g, '?').slice(0, 80);
const MAX_SECTION_FILES = 20;

/**
 * For each changed file that is a shared file of a reviewed tool (`<file>:<section>`, see ReviewedTool.configSections): read it at the
 * base and at the head (≤ 1 MiB), parse (JSON, TOML, INI as the tools' parsers do) and deep-compare each matching section. A change inside
 * a matching section, or to the section itself, is a SectionChange; a change elsewhere in the file is not. An unreadable, unparsable or
 * ambiguous file is a change with a `problem`. A file already protected as a whole is skipped. A rename is the removal of the old path
 * plus the addition of the new one: moving the file out of the place the tool reads it from is a `(file moved)` change on the old path
 * even when the content is the same, and the new path is compared as an added file; each path is waived by its own owners.
 */
export async function readConfigSections(gh: GateGithub, repo: RepoId, pr: PrContext, sections: readonly string[], protectedPaths: readonly string[]): Promise<SectionChange[]> {
  const specs = sections.flatMap((s) => { const i = s.indexOf(':'); return i > 0 ? [{ glob: pathMatcher([s.slice(0, i)]), section: s.slice(i + 1) }] : []; });
  if (specs.length === 0) return [];
  const whole = pathMatcher(protectedPaths);
  const out: SectionChange[] = [];
  let checked = 0;
  const compare = async (path: string, skipBase: boolean, skipHead: boolean): Promise<void> => {
    const relevant = specs.filter((s) => s.glob(path));
    if (relevant.length === 0 || whole(path)) return;
    if (++checked > MAX_SECTION_FILES) { out.push({ file: path, section: '*', problem: 'too many shared config files changed to compare' }); return; }
    const fail = (): void => { out.push({ file: path, section: safeName(relevant.map((r) => r.section).join(',')), problem: 'the file could not be read, parsed or told apart at the base or the head' }); };
    const side = async (ref: string, skip: boolean): Promise<Map<string, Section> | 'fail'> => {
      if (skip) return new Map();
      const r = await readTextAt(gh, repo, path, ref);
      if (r.kind === 'missing') return new Map();
      if (r.kind === 'problem') return 'fail';
      const doc = parseConfigDoc(path, r.text);
      return doc === undefined ? 'fail' : sectionTree(path, doc);
    };
    const base = await side(pr.baseSha, skipBase);
    const head = await side(pr.headSha, skipHead);
    if (base === 'fail' || head === 'fail') { fail(); return; }
    const toml = path.toLowerCase().endsWith('.toml');
    const changed = new Map<string, string[]>();
    for (const r of relevant) {
      const want = (toml ? r.section.split('.') : [r.section]).map(sectionRe);
      const fits = (segs: readonly string[]): boolean => segs.length === want.length && segs.every((x, i) => (want[i] as RegExp).test(x));
      for (const key of new Set([...base.keys(), ...head.keys()])) {
        const segs = (base.get(key) ?? head.get(key) as Section).segs;
        if (!fits(segs)) continue;
        const a = base.has(key) ? canon((base.get(key) as Section).value) : undefined;
        const b = head.has(key) ? canon((head.get(key) as Section).value) : undefined;
        if (a !== b) changed.set(key, segs);
      }
    }
    // report the shallowest changed section of a nested family once
    for (const [key, segs] of changed) {
      const nested = [...changed].some(([k, o]) => k !== key && o.length < segs.length && o.every((x, i) => x === segs[i]));
      if (!nested) out.push({ file: path, section: safeName(segs.join('.')) });
    }
  };
  for (const f of pr.files) {
    const prev = f.previous_filename;
    if (prev !== undefined && prev !== f.filename && f.status !== 'copied') {   // a copy leaves the original where it is
      if (specs.some((s) => s.glob(prev)) && !whole(prev)) out.push({ file: prev, section: '(file moved)' });
      await compare(f.filename, true, f.status === 'removed');
    } else {
      await compare(f.filename, f.status === 'added' || f.status === 'copied', f.status === 'removed');
    }
  }
  return out;
}

// ---------- the diff the gate judges by ----------

/**
 * The PR's added lines of the SCANNED tree: the compare API's patches for `base...head` where head is the scanned commit (github.sha;
 * for merge_group `base_sha...head_sha`), never the PR files API's patches (that numbering is the PR head's). `commit` is the head.
 * An incomplete compare (an error, a status other than ahead/identical, 300 files or more, a missing or malformed patch) is
 * `complete: false`, and the gate then treats every position-form finding as new.
 */
export async function buildPrDiff(gh: GateGithub, repo: RepoId, baseSha: string, headSha: string): Promise<PrDiff> {
  const bad = (): PrDiff => ({ added: new Map(), complete: false, commit: headSha });
  if (typeof baseSha !== 'string' || !SHA_RE.test(baseSha) || typeof headSha !== 'string' || !SHA_RE.test(headSha)) return bad();
  let a: unknown;
  try { a = await gh.compareFiles(repo.owner, repo.name, baseSha, headSha); } catch { return bad(); }
  const status = isPlain(a) ? own(a, 'status') : undefined;
  const list = isPlain(a) ? own(a, 'files') : undefined;
  if ((status !== 'ahead' && status !== 'identical') || !Array.isArray(list)) return bad();
  let ok = list.length < COMPARE_FILE_CAP;   // 300 files is the most the API lists; at the cap a truncation cannot be told from a full list
  const files: PrFile[] = [];
  for (const e of list) { const f = readFile(e); if (f === undefined) ok = false; else files.push(f); }
  const r = addedLinesOf(files);
  return { added: r.added, complete: ok && r.complete, commit: headSha };
}

// ---------- the rule ----------

/** The fixed reason a finding gives when its path's owners are unresolved (G15b, G15b-R1): nobody can approve. */
const UNRESOLVED_HOW: Record<Unresolved, string> = {
  segments: ` The gate could not work out the code owners of this path: a CODEOWNERS rule of the base commit that could decide it has over ${MAX_RULE_SEGMENTS} segments, so nobody can approve: shorten that rule, or merge with an administrator bypass.`,
  budget: ' The gate could not work out the code owners of this path within its step budget (the paths are too deep for the CODEOWNERS rules of the base commit), so nobody can approve: shorten the paths, or merge with an administrator bypass.',
  path: ' The gate could not work out the code owners of this path: it has more than 256 parts or an empty part, so nobody can approve: shorten the path, or merge with an administrator bypass.',
  unreadable: ` The gate could not work out the code owners of this path: the CODEOWNERS file of the base commit has a line over 4,096 characters or over 100,000 rules, which the gate does not read, so nobody can approve: shorten or split the file, or merge with an administrator bypass.`,
};

const fp = (...parts: string[]): string => createHash('sha256').update(parts.join('\0')).digest('hex');

/**
 * Pipeline-integrity findings of a pull request. Critical `integrity:incomplete-list` (no approval waives it), critical
 * `integrity:protected-path` (a changed file or rename source that matches `protectedPaths` case-insensitively, or a changed section of a
 * shared file), critical `integrity:no-patch` (a text file with changes and no readable patch; lockfiles and known binary types are
 * exempt), high `integrity:suppression` (an added suppression marker, or any added line in a declared ignore file), high
 * `integrity:case-extension` (a new file name whose extension is a scanned one in another letter case, C5a CF2). All but the first are
 * waived by an approval, on the head commit, of a code owner (a user) of the path (last matching CODEOWNERS rule of the base commit).
 * gate-v0.2.1: a suppression, no-patch or case-extension finding in a file whose last matching rule names no USER owner is also waived by an
 * approval from any owner listed in pipegen's own block (`codeowners.blockOwners`, from loadCodeowners): no rule matches (ownersOf is
 * undefined), or the rule names only teams or e-mails, or clears ownership (ownersOf is [], ruling D9-4; the gate can not count a team's
 * approval). Without it nobody could waive one. A file whose rule names a user, every protected path and every shared-config section keep
 * their own owners only. The approvals are readPrContext's: on exactly the head commit, never the author's, only from a user with write access.
 */
export function integrityFindings(
  pr: PrContext, protectedPaths: readonly string[], rules: readonly CodeownersRule[],
  extra: { sectionChanges?: readonly SectionChange[]; codeowners?: { found: string | null; problem?: string; blockOwners?: readonly string[] }; ownerSteps?: number } = {},
): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const approvals = new Set(pr.approvals.map((a) => a.toLowerCase()));
  const isProtected = pathMatcher(protectedPaths);
  const blockOwners = extra.codeowners?.problem === undefined && Array.isArray(extra.codeowners?.blockOwners) ? extra.codeowners.blockOwners.map((o) => String(o).toLowerCase()) : [];
  // G15b (F7): one step budget for every CODEOWNERS lookup of this run, and each path looked up once
  const steps: OwnerSteps = { left: typeof extra.ownerSteps === 'number' ? extra.ownerSteps : OWNERS_STEP_BUDGET };
  const lookups = new Map<string, OwnersLookup>();
  const lookup = (path: string): OwnersLookup => {
    let r = lookups.get(path);
    if (r === undefined) { r = ownersLookup(rules, path, steps); lookups.set(path, r); }
    return r;
  };
  /** An unresolved lookup waives nothing, not even by pipegen's block owners (fail closed). */
  const waived = (path: string): boolean => { const r = lookup(path); return 'owners' in r && (r.owners ?? []).some((o) => approvals.has(o)); };
  /** For the file findings only (suppression, no-patch, case-extension): a file no rule gives a user owner is waived by an owner in pipegen's block. */
  const waivedFile = (path: string): boolean => {
    const r = lookup(path);
    if (!('owners' in r)) return false;
    const o = r.owners;   // user owners only (codeOwners drops teams and e-mails)
    return (o === undefined || o.length === 0 ? blockOwners : o).some((x) => approvals.has(x));
  };
  const push = (ruleId: string, severity: Finding['severity'], file: string | undefined, message: string, key: string, line?: number): void => {
    const k = `${ruleId}\0${file ?? ''}\0${key}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ tool: 'pipegen', ruleId, severity, ...(file === undefined ? {} : { file }), ...(line === undefined ? {} : { line }), message, fingerprint: fp(ruleId, file ?? '', key) });
  };
  /** How the author gets this path approved, by why nobody can. Fixed texts only. `file`: a file finding, where pipegen's block owners count. */
  const how = (path: string, file = false): string => {
    if (extra.codeowners?.problem !== undefined) return ' CODEOWNERS of the base commit could not be read, so nobody can approve: re-run the gate, or merge with an administrator bypass.';
    if (rules.length === 0) {
      return extra.codeowners?.found != null
        ? ' CODEOWNERS of the base commit has no rule that names a user, so nobody can approve: add one, or merge with an administrator bypass.'
        : ' The base commit has no CODEOWNERS, so nobody can approve: add one (user owners, not only teams), or merge with an administrator bypass.';
    }
    const r = lookup(path);
    if ('unresolved' in r) return UNRESOLVED_HOW[r.unresolved];
    const o = r.owners;
    if ((o === undefined || o.length === 0) && file && blockOwners.length > 0) {
      return ' No CODEOWNERS rule names a user owner of this file, so an owner listed in pipegen\'s CODEOWNERS block (a user with write access, not the author) must approve the pull request on its current head commit.';
    }
    if (o === undefined || o.length === 0) {
      return ' No user is a code owner of this path (a team-only entry cannot approve: the gate cannot read team membership, so name a user as an owner in CODEOWNERS), or merge with an administrator bypass.';
    }
    return ' A code owner of this path (a user, not only a team) with write access must approve the pull request on its current head commit.';
  };

  if (!pr.filesComplete) push('integrity:incomplete-list', 'critical', undefined, 'The list of changed files is incomplete (or is not the list of the commit being checked), so the gate cannot see every change and blocks. Split the pull request into smaller ones, or re-run if the branch moved.', 'list');

  for (const f of pr.files) {
    for (const path of f.previous_filename === undefined || f.status === 'copied' ? [f.filename] : [f.filename, f.previous_filename]) {
      if (isProtected(path) && !waived(path)) push('integrity:protected-path', 'critical', path, `This file is part of the pipeline (a workflow, a tool config or an ignore file).${how(path)}`, 'path');
    }
    // a new name (added, renamed, copied) with a scanned extension in another letter case: the scanners skip it (CF2)
    if ((f.status === 'added' || f.status === 'renamed' || f.status === 'copied') && caseVariantExtension(f.filename) !== undefined && !waivedFile(f.filename)) {
      push('integrity:case-extension', 'high', f.filename, `This new file name has a scanned language's extension written in another letter case, so the scanners skip the file while a runtime may still load it. Rename it to the lower-case extension.${how(f.filename, true)}`, 'case-extension');
    }
    const hasPatch = typeof f.patch === 'string' && f.patch !== '';
    const parsed = hasPatch ? parsePatch(f.patch as string) : undefined;
    if (!hasPatch ? needsPatch(f) && !isLockfile(f.filename) : parsed === null) {
      if (!waivedFile(f.filename)) push('integrity:no-patch', 'critical', f.filename, `The gate cannot read this file's changes (no patch, or a patch it cannot parse), so it cannot check them for suppressions.${how(f.filename, true)}`, 'patch');
    }
    if (!hasPatch) continue;
    const ignoreFile = isProtected(f.filename) && IGNORE_FILE_RE.test(baseName(f.filename));
    const texts: { no: number | undefined; text: string; above?: string }[] = parsed === undefined || parsed === null
      ? plusLines(f.patch as string).map((text) => ({ no: undefined, text }))
      : parsed.added.map((a) => ({ no: a.no, text: a.text, ...(parsed.context.has(a.no - 1) ? { above: parsed.context.get(a.no - 1) as string } : {}) }));
    const kinds = new Set<string>();
    let first: number | undefined;
    let hits = 0;
    for (const a of texts) {
      let m = ignoreFile ? ['ignore file entry'] : markersOf(a.text);
      if (m.length === 0 && a.above !== undefined && NEXT_LINE_RE.test(a.above)) m = ['existing marker above a changed line'];
      if (m.length === 0) continue;
      hits++;
      for (const k of m) kinds.add(k);
      if (first === undefined && a.no !== undefined) first = a.no;
    }
    if (hits > 0 && !waivedFile(f.filename)) {
      push('integrity:suppression', 'high', f.filename, `${hits} added line${hits === 1 ? '' : 's'} suppress${hits === 1 ? 'es' : ''} a check (${[...kinds].sort().join(', ')}).${how(f.filename, true)}`, 'suppression', first);
    }
  }

  for (const c of extra.sectionChanges ?? []) {
    if (waived(c.file)) continue;
    push('integrity:protected-path', 'critical', c.file,
      c.problem === undefined
        ? (c.section === '(file moved)' ? `This shared config file was renamed or moved away from where its tool reads it.${how(c.file)}` : `The section ${safeName(c.section)} of this shared config file changed.${how(c.file)}`)
        : `This shared config file (section ${safeName(c.section)}) could not be compared: ${c.problem}.${how(c.file)}`, `section:${c.section}`);
  }
  return out;
}
