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
export interface CodeownersRule { pattern: string; owners: string[] }
export interface SectionChange { file: string; section: string; problem?: string }

// ---------- paths ----------

/**
 * A slashless protected name is protected at ANY depth (`**\/` prefix): tools find configs in sub-folders (bandit's `.bandit` anywhere in
 * the tree, `mypy.ini` in the service folder). An entry with a slash is anchored as written. Case-insensitive, dot files included.
 */
const anyDepth = (p: string): string => (p.includes('/') ? p : `**/${p}`);
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
 * list gives none. `expectHeadSha` (the commit the event is about): when the pull's head has moved, nothing is approved.
 */
export async function readPrContext(gh: GateGithub, repo: RepoId, prNumber: number, opts: { expectHeadSha?: string } = {}): Promise<PrContext> {
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
  const candidates = [...latest].filter(([login, r]) => r.state === 'APPROVED' && r.commit === headSha && login !== (typeof author === 'string' ? author.toLowerCase() : '')).map(([login]) => login).sort();
  if (candidates.length > MAX_APPROVERS) pr.problems.push(`more than ${MAX_APPROVERS} approvers; only the first ${MAX_APPROVERS} were checked`);
  // an approval counts only from a user with write, maintain or admin permission (GitHub's own rule for code owners); any error means no
  for (const login of candidates.slice(0, MAX_APPROVERS)) {
    try {
      const a = await gh.collaboratorPermission(repo.owner, repo.name, login);
      const perm = isPlain(a) ? own(a, 'permission') : undefined;
      const role = isPlain(a) ? own(a, 'role_name') : undefined;
      if (perm === 'admin' || perm === 'write' || role === 'maintain' || role === 'admin' || role === 'write') pr.approvals.push(login);
    } catch { /* not approved */ }
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

const MAX_RULES = 100_000;
const MAX_LINE = 4096;
const TEAM_RE = /^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LOGIN_RE = /^@([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)$/;

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
 * with `!` or `\#`, or containing `[` `]`.
 */
export function codeOwners(text: string | null): CodeownersRule[] {
  if (typeof text !== 'string') return [];
  const rules: CodeownersRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if (rules.length >= MAX_RULES) break;
    if (raw.length > MAX_LINE) continue;
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

type Seg = { kind: 'globstar' } | { kind: 'globstar+' } | { kind: 'glob'; toks: ('*' | '?' | string)[] };
interface Compiled { segs: Seg[]; dirOnly: boolean; ancestors: boolean }
const compiled = new WeakMap<CodeownersRule, Compiled>();

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
  const segs: Seg[] = parts.map((part, idx) => {
    if (part === '**') return idx === parts.length - 1 ? { kind: 'globstar+' } : { kind: 'globstar' };
    const toks: ('*' | '?' | string)[] = [];
    for (let i = 0; i < part.length; i++) {
      const c = part[i] as string;
      if (c === '\\' && i + 1 < part.length) { toks.push(part[++i] as string); continue; }
      if (c === '*') { if (toks[toks.length - 1] !== '*') toks.push('*'); continue; }
      toks.push(c === '?' ? '?' : c);
    }
    return { kind: 'glob', toks };
  });
  const last = parts[parts.length - 1] as string;
  // a final segment with a wildcard names files (`docs/*` is not the whole docs tree); a literal one names a file or a directory
  const ancestors = dirOnly || !/[*?]/.test(last);
  const c = { segs, dirOnly, ancestors };
  compiled.set(rule, c);
  return c;
}

/** `*` and `?` never cross a `/` (the segment is already split). Two-pointer match with backtracking on the last star. */
function segMatch(toks: readonly ('*' | '?' | string)[], s: string): boolean {
  let t = 0; let i = 0; let star = -1; let mark = 0;
  while (i < s.length) {
    const k = toks[t];
    if (k === '*') { star = t++; mark = i; }
    else if (k !== undefined && (k === '?' || k === s[i])) { t++; i++; }
    else if (star >= 0) { t = star + 1; i = ++mark; }
    else return false;
  }
  while (toks[t] === '*') t++;
  return t === toks.length;
}

function matchesPrefix(c: Compiled, parts: readonly string[], end: number): boolean {
  const memo = new Map<number, boolean>();
  const go = (pi: number, si: number): boolean => {
    const key = pi * (end + 1) + si;
    const hit = memo.get(key);
    if (hit !== undefined) return hit;
    let r: boolean;
    const seg = c.segs[pi];
    if (seg === undefined) r = si === end;
    else if (seg.kind === 'globstar+') r = si < end;
    else if (seg.kind === 'globstar') { r = false; for (let j = si; j <= end && !r; j++) r = go(pi + 1, j); }
    else r = si < end && segMatch(seg.toks, parts[si] as string) && go(pi + 1, si + 1);
    memo.set(key, r);
    return r;
  };
  return go(0, 0);
}

function ruleMatches(rule: CodeownersRule, parts: readonly string[]): boolean {
  const c = compile(rule);
  for (let k = 1; k <= parts.length; k++) {
    if (k === parts.length) { if (!c.dirOnly && matchesPrefix(c, parts, k)) return true; }
    else if (c.ancestors && matchesPrefix(c, parts, k)) return true;
  }
  return false;
}

/** The owners (users) of `path` by the LAST matching rule; `[]` when that rule has no user owner (it clears ownership); undefined when no rule matches. Case sensitive. */
export function ownersOf(rules: readonly CodeownersRule[], path: string): string[] | undefined {
  const parts = path.split('/');
  if (parts.length > 256 || parts.includes('')) return undefined;
  let owners: string[] | undefined;
  for (const r of rules) if (ruleMatches(r, parts)) owners = r.owners;
  return owners;
}

/** CODEOWNERS of the BASE commit: `.github/CODEOWNERS`, then `CODEOWNERS`, then `docs/CODEOWNERS`; the first that exists is the file. Never the head. */
export async function loadCodeowners(gh: GateGithub, repo: RepoId, baseSha: string): Promise<{ rules: CodeownersRule[]; found: string | null; problem?: string }> {
  for (const path of ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS']) {
    const r = await readTextAt(gh, repo, path, baseSha, { max: MAX_CODEOWNERS_BYTES, raw: true });
    if (r.kind === 'missing') continue;
    if (r.kind === 'problem') return { rules: [], found: null, problem: `CODEOWNERS of the base commit could not be read (${r.why}); nobody can approve` };
    return { rules: codeOwners(r.text), found: path };
  }
  return { rules: [], found: null };
}

// ---------- configSections ----------

type Tree = Map<string, unknown>;

/** A document as plain data, comparable by text: non-finite numbers, big integers and dates get distinct forms (JSON would make them null). */
function norm(v: unknown): unknown {
  if (typeof v === 'number') return Number.isFinite(v) ? v : { $num: Number.isNaN(v) ? 'nan' : v > 0 ? 'inf' : '-inf' };
  if (typeof v === 'bigint') return Number.isSafeInteger(Number(v)) ? Number(v) : { $int: String(v) };
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map(norm);
  if (isPlain(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])]));
  return v;
}
const canon = (v: unknown): string => JSON.stringify(norm(v));

/**
 * Python configparser (`RawConfigParser`, strict), ported: a header is `^\[(.+)\]` (greedy) on the stripped line and the rest of the line
 * is ignored; an indented line after an option continues it; `#` and `;` lines are comments (not inline ones); blank lines inside a value
 * are kept; `[DEFAULT]` is merged into every section; keys are lower-cased; a duplicate section or option, an option before a header, a
 * line without `=` or `:` and an empty key are errors (undefined).
 */
function parseIni(text: string): Record<string, Record<string, string>> | undefined {
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
    cur.set(key, [first === '""' ? '' : first]);
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
export function parseConfigDoc(path: string, text: string): Record<string, unknown> | undefined {
  const lower = path.toLowerCase();
  try {
    if (lower.endsWith('.json')) { const v: unknown = JSON.parse(text); return isPlain(v) ? (norm(v) as Record<string, unknown>) : undefined; }
    if (lower.endsWith('.toml')) return norm(parseToml(text)) as Record<string, unknown>;
    if (lower.endsWith('.cfg') || lower.endsWith('.ini')) return parseIni(text);
  } catch { return undefined; }
  return undefined;
}

/**
 * The sections of a parsed document by name: INI sections and JSON top-level keys as they are; TOML tables by their dotted path built from
 * the parsed segments. A literal key that contains a dot and joins to the same name as another path (`"tool.mypy"` beside `[tool.mypy]`)
 * is ambiguous: undefined, so the caller fails closed.
 */
function sectionTree(path: string, doc: Record<string, unknown>): Tree | undefined {
  const t: Tree = new Map();
  if (!path.toLowerCase().endsWith('.toml')) { for (const k of Object.keys(doc)) t.set(k, doc[k]); return t; }
  const segsOf = new Map<string, string>();
  const walk = (v: unknown, prefix: string[], depth: number): boolean => {
    if (!isPlain(v) || depth > 16 || '$num' in v || '$int' in v) return true;
    for (const k of Object.keys(v)) {
      const segs = [...prefix, k];
      const joined = segs.join('.');
      const id = JSON.stringify(segs);
      const prev = segsOf.get(joined);
      if (prev !== undefined && prev !== id) return false;
      segsOf.set(joined, id);
      t.set(joined, v[k]);
      if (!walk(v[k], segs, depth + 1)) return false;
    }
    return true;
  };
  return walk(doc, [], 0) ? t : undefined;
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
    const side = async (ref: string, skip: boolean): Promise<Tree | 'fail'> => {
      if (skip) return new Map();
      const r = await readTextAt(gh, repo, path, ref);
      if (r.kind === 'missing') return new Map();
      if (r.kind === 'problem') return 'fail';
      const doc = parseConfigDoc(path, r.text);
      const tree = doc === undefined ? undefined : sectionTree(path, doc);
      return tree ?? 'fail';
    };
    const base = await side(pr.baseSha, skipBase);
    const head = await side(pr.headSha, skipHead);
    if (base === 'fail' || head === 'fail') { fail(); return; }
    const changed = new Set<string>();
    for (const r of relevant) {
      const re = sectionRe(r.section);
      for (const n of new Set([...base.keys(), ...head.keys()].filter((k) => re.test(k)))) {
        const a = base.has(n) ? canon(base.get(n)) : undefined;
        const b = head.has(n) ? canon(head.get(n)) : undefined;
        if (a !== b) changed.add(n);
      }
    }
    // report the shallowest changed section of a nested family once
    for (const n of changed) if (![...changed].some((o) => o !== n && n.startsWith(`${o}.`))) out.push({ file: path, section: safeName(n) });
  };
  for (const f of pr.files) {
    const prev = f.previous_filename;
    if (prev !== undefined && prev !== f.filename) {
      if (specs.some((s) => s.glob(prev)) && !whole(prev)) out.push({ file: prev, section: '(file moved)' });
      await compare(f.filename, true, f.status === 'removed');
    } else {
      await compare(f.filename, f.status === 'added', f.status === 'removed');
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

const fp = (...parts: string[]): string => createHash('sha256').update(parts.join('\0')).digest('hex');

/**
 * Pipeline-integrity findings of a pull request. Critical `integrity:incomplete-list` (no approval waives it), critical
 * `integrity:protected-path` (a changed file or rename source that matches `protectedPaths` case-insensitively, or a changed section of a
 * shared file), critical `integrity:no-patch` (a text file with changes and no readable patch; lockfiles and known binary types are
 * exempt), high `integrity:suppression` (an added suppression marker, or any added line in a declared ignore file). All but the first are
 * waived by an approval, on the head commit, of a code owner (a user) of the path (last matching CODEOWNERS rule of the base commit).
 */
export function integrityFindings(
  pr: PrContext, protectedPaths: readonly string[], rules: readonly CodeownersRule[],
  extra: { sectionChanges?: readonly SectionChange[]; codeowners?: { found: string | null; problem?: string } } = {},
): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const approvals = new Set(pr.approvals.map((a) => a.toLowerCase()));
  const isProtected = pathMatcher(protectedPaths);
  const waived = (path: string): boolean => (ownersOf(rules, path) ?? []).some((o) => approvals.has(o));
  const push = (ruleId: string, severity: Finding['severity'], file: string | undefined, message: string, key: string, line?: number): void => {
    const k = `${ruleId}\0${file ?? ''}\0${key}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ tool: 'pipegen', ruleId, severity, ...(file === undefined ? {} : { file }), ...(line === undefined ? {} : { line }), message, fingerprint: fp(ruleId, file ?? '', key) });
  };
  /** How the author gets this path approved, by why nobody can. Fixed texts only. */
  const how = (path: string): string => {
    if (extra.codeowners?.problem !== undefined) return ' CODEOWNERS of the base commit could not be read, so nobody can approve: re-run the gate, or merge with an administrator bypass.';
    if (rules.length === 0) {
      return extra.codeowners?.found != null
        ? ' CODEOWNERS of the base commit has no rule that names a user, so nobody can approve: add one, or merge with an administrator bypass.'
        : ' The base commit has no CODEOWNERS, so nobody can approve: add one (user owners, not only teams), or merge with an administrator bypass.';
    }
    const o = ownersOf(rules, path);
    if (o === undefined || o.length === 0) {
      return ' No user is a code owner of this path (a team-only entry cannot approve: the gate cannot read team membership, so name a user as an owner in CODEOWNERS), or merge with an administrator bypass.';
    }
    return ' A code owner of this path (a user, not only a team) with write access must approve the pull request on its current head commit.';
  };

  if (!pr.filesComplete) push('integrity:incomplete-list', 'critical', undefined, 'The list of changed files is incomplete (or is not the list of the commit being checked), so the gate cannot see every change and blocks. Split the pull request into smaller ones, or re-run if the branch moved.', 'list');

  for (const f of pr.files) {
    for (const path of f.previous_filename === undefined ? [f.filename] : [f.filename, f.previous_filename]) {
      if (isProtected(path) && !waived(path)) push('integrity:protected-path', 'critical', path, `This file is part of the pipeline (a workflow, a tool config or an ignore file).${how(path)}`, 'path');
    }
    const hasPatch = typeof f.patch === 'string' && f.patch !== '';
    const parsed = hasPatch ? parsePatch(f.patch as string) : undefined;
    if (!hasPatch ? needsPatch(f) && !isLockfile(f.filename) : parsed === null) {
      if (!waived(f.filename)) push('integrity:no-patch', 'critical', f.filename, `The gate cannot read this file's changes (no patch, or a patch it cannot parse), so it cannot check them for suppressions.${how(f.filename)}`, 'patch');
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
    if (hits > 0 && !waived(f.filename)) {
      push('integrity:suppression', 'high', f.filename, `${hits} added line${hits === 1 ? '' : 's'} suppress${hits === 1 ? 'es' : ''} a check (${[...kinds].sort().join(', ')}).${how(f.filename)}`, 'suppression', first);
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
