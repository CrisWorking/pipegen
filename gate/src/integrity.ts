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

/** The API caps the pull files and the compare files at 3,000; 100 per page. */
export const API_FILE_CAP = 3000;
export const PER_PAGE = 100;
/** A patch longer than this is not parsed (the API omits huge ones; a longer one is hostile). */
export const MAX_PATCH_CHARS = 2 * 1024 * 1024;
/** A file read through the contents API (CODEOWNERS, a shared config file) over this size is not read. */
export const MAX_FILE_BYTES = 1024 * 1024;

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
];
/** `noqa: E501, W291` (codes none of which starts with S) is a style suppression, not a security one. */
function noqaIsSecurity(line: string): boolean {
  const m = /\bnoqa\b(?:\s*:\s*([A-Za-z0-9, \t]*))?/i.exec(line);
  if (m === null) return false;
  if (m[1] === undefined || m[1].trim() === '') return true;   // blanket noqa suppresses the security rules too
  return /(^|[\s,])S\d/i.test(m[1]);
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
interface ParsedPatch { added: { no: number; text: string }[] }

/**
 * Parse a unified-diff body (GitHub's `patch`, hunks only). The hunk header's counts decide where a hunk ends, so a line in a hunk body
 * that looks like a header (`+@@ ...`, `+++ b/x`) is content. Anything that does not fit the counts is malformed: null.
 */
function parsePatch(patch: string): ParsedPatch | null {
  if (patch.length > MAX_PATCH_CHARS) return null;
  const lines = patch.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const added: { no: number; text: string }[] = [];
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
      else if (c === ' ') { if (oldLeft <= 0 || newLeft <= 0) return null; oldLeft--; newLeft--; newNo++; }
      else if (c === '\\') continue;   // "\ No newline at end of file"
      else return null;
    }
    while (i < lines.length && (lines[i] as string)[0] === '\\') i++;
  }
  return { added };
}

/** The `+` lines of a patch by plain prefix: in a well-formed patch these are exactly the added lines. Used when the patch does not parse. */
function plusLines(patch: string): string[] {
  const out: string[] = [];
  for (const l of patch.split('\n')) if (l[0] === '+') out.push(l.slice(1));
  return out;
}

const needsPatch = (f: PrFile): boolean => f.changes > 0 && !isBinary(f.filename);

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
      if (needsPatch(f)) { complete = false; problems.push('a changed text file has no patch'); }
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
  if (opts.expectHeadSha !== undefined && opts.expectHeadSha !== headSha) { pr.problems.push('the pull request head moved since the event; nothing is approved'); return pr; }
  const latest = new Map<string, { id: number; state: string; commit: unknown }>();
  for (const r of reviews) {
    if (REVIEW_STATES_IGNORED.has(r.state)) continue;
    const cur = latest.get(r.login);
    if (cur === undefined || r.id > cur.id) latest.set(r.login, r);
  }
  pr.approvals = [...latest].filter(([, r]) => r.state === 'APPROVED' && r.commit === headSha).map(([login]) => login).sort();
  return pr;
}

// ---------- reading a file at a commit ----------

type Read = { kind: 'missing' } | { kind: 'text'; text: string } | { kind: 'problem'; why: string };
async function readTextAt(gh: GateGithub, repo: RepoId, path: string, ref: string): Promise<Read> {
  if (!SHA_RE.test(ref)) return { kind: 'problem', why: 'the commit is not a commit sha' };
  let a: unknown;
  try { a = await gh.fileAt(repo.owner, repo.name, path, ref); } catch { return { kind: 'problem', why: 'the file could not be read' }; }
  if (a === null) return { kind: 'missing' };
  if (!isPlain(a) || own(a, 'type') !== 'file') return { kind: 'problem', why: 'the answer is not a file' };
  const size = own(a, 'size');
  const content = own(a, 'content');
  if (!natInt(size) || size > MAX_FILE_BYTES) return { kind: 'problem', why: 'the file is over the size cap' };
  if (own(a, 'encoding') !== 'base64' || typeof content !== 'string') return { kind: 'problem', why: 'the file content is not readable' };
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
    for (const o of t.slice(1)) { const m = LOGIN_RE.exec(o); if (m !== null) owners.push((m[1] as string).toLowerCase()); }
    rules.push({ pattern, owners });
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
    const r = await readTextAt(gh, repo, path, baseSha);
    if (r.kind === 'missing') continue;
    if (r.kind === 'problem') return { rules: [], found: null, problem: `CODEOWNERS of the base commit could not be read (${r.why}); nobody can approve` };
    return { rules: codeOwners(r.text), found: path };
  }
  return { rules: [], found: null };
}

// ---------- configSections ----------

type Tree = Map<string, unknown>;
const canon = (v: unknown): string => JSON.stringify(v, (_k, x: unknown) => {
  if (typeof x === 'bigint') return `${x}n`;
  if (isPlain(x) && !(x instanceof Date)) return Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]]));
  return x;
});

function flattenTables(v: unknown, prefix: string, out: Tree, depth: number): void {
  if (!isPlain(v) || v instanceof Date || depth > 16) return;
  for (const k of Object.keys(v)) {
    const path = prefix === '' ? k : `${prefix}.${k}`;
    out.set(path, v[k]);
    flattenTables(v[k], path, out, depth + 1);
  }
}

function parseIni(text: string): Tree | undefined {
  const tree = new Map<string, [string, string][]>();
  let cur: [string, string][] | undefined;
  let last: [string, string] | undefined;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '' || /^\s*[#;]/.test(line)) continue;
    const sec = /^\[(.+)\]\s*$/.exec(line.trim());
    if (sec !== null && !/^\s/.test(line)) { const name = sec[1] as string; cur = tree.get(name) ?? []; tree.set(name, cur); last = undefined; continue; }
    if (/^\s/.test(line) && last !== undefined) { last[1] += `\n${line.trim()}`; continue; }
    const kv = /^([^=:\s][^=:]*?)\s*[=:]\s*(.*)$/.exec(line);
    if (kv === null || cur === undefined) return undefined;
    last = [kv[1] as string, kv[2] as string];
    cur.push(last);
  }
  return tree;
}

function parseShared(path: string, text: string): Tree | undefined {
  const lower = path.toLowerCase();
  try {
    if (lower.endsWith('.json')) {
      const v: unknown = JSON.parse(text);
      if (!isPlain(v)) return undefined;
      const t: Tree = new Map();
      for (const k of Object.keys(v)) t.set(k, v[k]);
      return t;
    }
    if (lower.endsWith('.toml')) { const t: Tree = new Map(); flattenTables(parseToml(text), '', t, 0); return t; }
    if (lower.endsWith('.cfg') || lower.endsWith('.ini')) return parseIni(text);
  } catch { return undefined; }
  return undefined;
}

const sectionRe = (section: string): RegExp => new RegExp(`^${section.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
const safeName = (s: string): string => s.replace(/[^A-Za-z0-9._:*/-]/g, '?').slice(0, 80);
const MAX_SECTION_FILES = 20;

/**
 * For each changed file that is a shared file of a reviewed tool (`<file>:<section>`, see ReviewedTool.configSections): read it at the
 * base and at the head (≤ 1 MiB), parse (JSON, TOML, INI) and deep-compare each matching section. A change inside a matching section, or to
 * the section itself, is a SectionChange; a change elsewhere in the file is not. An unreadable or unparsable file is a change with a
 * `problem`. A file already protected as a whole is skipped.
 */
export async function readConfigSections(gh: GateGithub, repo: RepoId, pr: PrContext, sections: readonly string[], protectedPaths: readonly string[]): Promise<SectionChange[]> {
  const specs = sections.flatMap((s) => { const i = s.indexOf(':'); return i > 0 ? [{ glob: picomatch(s.slice(0, i), { nocase: true, dot: true }), section: s.slice(i + 1) }] : []; });
  if (specs.length === 0) return [];
  const whole = protectedPaths.length === 0 ? () => false : picomatch([...protectedPaths], { nocase: true, dot: true });
  const out: SectionChange[] = [];
  let checked = 0;
  for (const f of pr.files) {
    const basePath = f.previous_filename ?? f.filename;
    const headPath = f.filename;
    if (whole(headPath) || whole(basePath)) continue;
    const relevant = specs.filter((s) => s.glob(headPath) || s.glob(basePath));
    if (relevant.length === 0) continue;
    if (++checked > MAX_SECTION_FILES) { out.push({ file: headPath, section: '*', problem: 'too many shared config files changed to compare' }); continue; }
    const fail = (why: string): void => { out.push({ file: headPath, section: safeName(relevant.map((r) => r.section).join(',')), problem: why }); };
    const side = async (path: string, ref: string, skip: boolean): Promise<Tree | undefined | 'fail'> => {
      if (skip) return new Map();
      const r = await readTextAt(gh, repo, path, ref);
      if (r.kind === 'missing') return new Map();
      if (r.kind === 'problem') return 'fail';
      return parseShared(path, r.text) ?? 'fail';
    };
    const base = await side(basePath, pr.baseSha, f.status === 'added');
    const head = await side(headPath, pr.headSha, f.status === 'removed');
    if (base === 'fail' || head === 'fail' || base === undefined || head === undefined) { fail('the file could not be read or parsed at the base or the head'); continue; }
    const changed = new Set<string>();
    for (const r of relevant) {
      const re = sectionRe(r.section);
      const names = new Set([...base.keys(), ...head.keys()].filter((k) => re.test(k)));
      for (const n of names) {
        const a = base.has(n) ? canon(base.get(n)) : undefined;
        const b = head.has(n) ? canon(head.get(n)) : undefined;
        if (a !== b) changed.add(n);
      }
    }
    // report the shallowest changed section of a nested family once
    for (const n of changed) if (![...changed].some((o) => o !== n && n.startsWith(`${o}.`))) out.push({ file: headPath, section: safeName(n) });
  }
  return out;
}

// ---------- the diff the gate judges by ----------

/**
 * The PR's added lines of the SCANNED tree: the compare API's patches for `base...head` where head is the scanned commit (github.sha;
 * for merge_group `base_sha...head_sha`), never the PR files API's patches (that numbering is the PR head's). `commit` is the head.
 * An incomplete compare (an error, a status other than ahead/identical, the 3,000-file cap, a missing or malformed patch) is
 * `complete: false`, and the gate then treats every position-form finding as new.
 */
export async function buildPrDiff(gh: GateGithub, repo: RepoId, baseSha: string, headSha: string): Promise<PrDiff> {
  const bad = (added = new Map<string, Set<number>>()): PrDiff => ({ added, complete: false, commit: headSha });
  if (typeof baseSha !== 'string' || !SHA_RE.test(baseSha) || typeof headSha !== 'string' || !SHA_RE.test(headSha)) return bad();
  const files: PrFile[] = [];
  let ok = true;
  const pages = API_FILE_CAP / PER_PAGE;
  for (let page = 1; page <= pages; page++) {
    let a: unknown;
    try { a = await gh.compareFiles(repo.owner, repo.name, baseSha, headSha, page, PER_PAGE); } catch { ok = false; break; }
    const status = isPlain(a) ? own(a, 'status') : undefined;
    const list = isPlain(a) ? own(a, 'files') : undefined;
    if ((status !== 'ahead' && status !== 'identical') || !Array.isArray(list)) { ok = false; break; }
    for (const e of list) { const f = readFile(e); if (f === undefined) ok = false; else files.push(f); }
    if (list.length < PER_PAGE) break;
    if (page === pages) ok = false;   // the cap: more files may exist
  }
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
export function integrityFindings(pr: PrContext, protectedPaths: readonly string[], rules: readonly CodeownersRule[], extra: { sectionChanges?: readonly SectionChange[] } = {}): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const approvals = new Set(pr.approvals.map((a) => a.toLowerCase()));
  const isProtected = protectedPaths.length === 0 ? (): boolean => false : picomatch([...protectedPaths], { nocase: true, dot: true });
  const waived = (path: string): boolean => (ownersOf(rules, path) ?? []).some((o) => approvals.has(o));
  const push = (ruleId: string, severity: Finding['severity'], file: string | undefined, message: string, key: string, line?: number): void => {
    const k = `${ruleId}\0${file ?? ''}\0${key}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ tool: 'pipegen', ruleId, severity, ...(file === undefined ? {} : { file }), ...(line === undefined ? {} : { line }), message, fingerprint: fp(ruleId, file ?? '', key) });
  };
  const how = rules.length === 0
    ? ' The base commit has no CODEOWNERS, so nobody can approve: add one (user owners, not only teams), or merge with an administrator bypass.'
    : ' A code owner of this path (a user, not only a team) must approve the pull request on its current head commit.';

  if (!pr.filesComplete) push('integrity:incomplete-list', 'critical', undefined, 'The list of changed files is incomplete, so the gate cannot see every change and blocks. Split the pull request into smaller ones.', 'list');

  for (const f of pr.files) {
    for (const path of f.previous_filename === undefined ? [f.filename] : [f.filename, f.previous_filename]) {
      if (isProtected(path) && !waived(path)) push('integrity:protected-path', 'critical', path, `This file is part of the pipeline (a workflow, a tool config or an ignore file).${how}`, 'path');
    }
    const hasPatch = typeof f.patch === 'string' && f.patch !== '';
    const parsed = hasPatch ? parsePatch(f.patch as string) : undefined;
    if (!hasPatch ? needsPatch(f) && !isLockfile(f.filename) : parsed === null) {
      if (!waived(f.filename)) push('integrity:no-patch', 'critical', f.filename, `The gate cannot read this file's changes (no patch, or a patch it cannot parse), so it cannot check them for suppressions.${how}`, 'patch');
    }
    if (!hasPatch) continue;
    const ignoreFile = isProtected(f.filename) && IGNORE_FILE_RE.test(baseName(f.filename));
    const texts = parsed === undefined || parsed === null ? plusLines(f.patch as string).map((text) => ({ no: undefined as number | undefined, text })) : parsed.added;
    const kinds = new Set<string>();
    let first: number | undefined;
    let hits = 0;
    for (const a of texts) {
      const m = ignoreFile ? ['ignore file entry'] : markersOf(a.text);
      if (m.length === 0) continue;
      hits++;
      for (const k of m) kinds.add(k);
      if (first === undefined && a.no !== undefined) first = a.no;
    }
    if (hits > 0 && !waived(f.filename)) {
      push('integrity:suppression', 'high', f.filename, `${hits} added line${hits === 1 ? '' : 's'} suppress${hits === 1 ? 'es' : ''} a check (${[...kinds].sort().join(', ')}).${how}`, 'suppression', first);
    }
  }

  for (const c of extra.sectionChanges ?? []) {
    if (waived(c.file)) continue;
    push('integrity:protected-path', 'critical', c.file,
      c.problem === undefined ? `The section ${safeName(c.section)} of this shared config file changed.${how}` : `This shared config file (section ${safeName(c.section)}) could not be compared: ${c.problem}.${how}`, `section:${c.section}`);
  }
  return out;
}
