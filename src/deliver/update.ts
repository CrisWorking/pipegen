// v0.2 Plan G G12 (plan Task 7 "update"; rulings S27, CTO-2 (DECISIONS #97), E-b4 (E2-R7), G-C7, G37; Plan V pre-flight §5 G12, binding):
// `pipegen update`, run by the user with the user's token, keeps an installed pipeline on the gate pin of the reviewed list bundled with this
// CLI.
//
// - Issues are PROMPTS, never authority (G-C7). Anyone with issue rights in a public repo, and any job with `issues: write`, can open an issue
//   that looks exactly like the nightly's, even as github-actions[bot]. So an issue counts only when it was opened by github-actions[bot] (type
//   Bot) and its FIRST line is the pipegen key marker of an update issue (`update-<x.y.z>`); every other one is listed as ignored, with why.
//   The patch is never taken from an issue: pipegen derives the change itself (from the reviewed pin; a movable tag or a release is never
//   authority) and only COMPARES an issue's patch with it: a patch that touches a file outside the install record, doesn't match the file's
//   blob (baseSha), doesn't apply cleanly, or gives another result than pipegen's own derivation is refused and shown. An issue that names a
//   version other than the reviewed pin is refused ("not in the reviewed list").
// - Only files the install record lists are touched (this project's workflows written whole, and its verify-job edits), read through the one
//   trust order (trust.ts); with no trusted record nothing is touched. The only change derived is a pin swap: pipegen's gate `uses:` lines to
//   the reviewed pin, and (private apps, once the central change is merged) the app's calls of its central workflows to the central default
//   commit that holds them (S26). Every change is held to changeProblem before it goes out: only `uses:` / `central-sha:` values that a swap
//   allows change, the YAML is otherwise identical, and the `# pipegen:not-proven` line is never touched by a pin swap (a not-proven change,
//   Plan H, may edit that one line and nothing else: notProvenProblem).
// - A file the owner edited since pipegen wrote it (its blob is not one of the recorded shas) is never overwritten (CTO-2): pipegen's change is
//   made on its own last written text and merged 3-way into the owner's file; overlapping edits go to the conflict list (shown in the preview
//   and the pull request), and that file is not written. A merged file is marked `ownerEdited` in the record (E2-R7, Plan V §5): from then on it
//   is the owner's (never pipegen's own for a replace, the guard or uninstall).
// - Central files go to the central pull request pipegen/update-<name> (with the record, through writeRecord); the app's own change waits
//   until it is merged. App files go to the pull request pipegen/update, which closes the update issues it answers.
// - Every diff is shown before anything is written, and one question (default no) opens the pull requests; no answer, no write. Every blob
//   sha pipegen writes is appended to the record (files[].shas / edits[].writtenShas) through writeRecord (Plan V §5).
import { isDeepStrictEqual } from 'node:util';
import type { Octokit } from '@octokit/rest';
import { isScalar, parseDocument, visit } from 'yaml';
import { PromptCancelledError, type Prompter } from '../cli/io.js';
import { gitBlobSha } from '../create/guard.js';
import { isRateStop, type RateClock } from '../engine/github-rate.js';
import { centralWorkflowFile, type CentralLayer } from '../engine/central-path.js';
import { GATE_USES_RE, PIPEGEN_GATE_USES } from '../engine/tool-flags.js';
import { clockOf } from '../github/client.js';
import { NOT_PROVEN_MARK } from '../layers/assemble.js';
import { CENTRAL_REPO } from '../proof/target.js';
import { FLOOR_NEEDS, type InstallRecord, type RecordRepo, type ReviewedTool } from '../types.js';
import { safeMarkdown, safeText } from '../util/safe-text.js';
import { commitFiles, DeliverError, ghRead, statusOf, openOrUpdatePr, readBlobText, readHead, readRepo, readTree, setBranch, type RepoRef, type TreeEntry } from './git-data.js';
import { centralOf, centralUpdateBranch, localRecordPath, readLocalRecord, RecordError, recordWriteReached, writeRecord, type LocalRecordDeps } from './record.js';
import { trustedPrevious } from './trust.js';

// ---------- constants ----------

/** The app pull request branch of `pipegen update`. */
export const UPDATE_BRANCH = 'pipegen/update';
/** The setup pull request's branch (deliver.ts SETUP_BRANCH; spelled here so update doesn't load the delivery). */
const SETUP_BRANCH = 'pipegen/setup';
/** The only author an update issue may have (and its account type must be Bot). */
export const ISSUE_AUTHOR = 'github-actions[bot]';
const KEY_LINE_RE = /^<!-- pipegen:key=([a-z0-9][a-z0-9.-]{0,99}) -->$/;
const SEMVER = '(?:0|[1-9][0-9]{0,5})\\.(?:0|[1-9][0-9]{0,5})\\.(?:0|[1-9][0-9]{0,5})';
const UPDATE_KEY_RE = new RegExp(`^update-(${SEMVER})$`);
const SEMVER_RE = new RegExp(`^${SEMVER}$`);
const PATCH_LINE_RE = /^<!-- pipegen:patch (\{.{0,600}\}) -->$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const WORKFLOW_RE = /^\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml$/;
const MAX_BODY = 65_536;
const MAX_PATCHES = 20;
const MAX_ISSUE_PAGES = 5;
const MAX_FILE_BYTES = 1024 * 1024;
/** The largest middle part (after the common start and end are taken off) the line matcher compares: rows × columns. */
const MAX_CELLS = 4_000_000;
/** The most diff lines one preview section shows for one file. */
const MAX_SHOWN_LINES = 200;

/** `pipegen update` stops: a plain reason, nothing written. */
export class UpdateError extends Error {
  constructor(message: string, options?: { cause?: unknown }) { super(message, options); this.name = 'UpdateError'; }
}

// ---------- types ----------

export interface GatePin { sha: string; version: string }
/** One patch block of an issue (only ever compared, never applied as it is). */
export interface IssuePatch { repo: RecordRepo; path: string; baseSha: string; diff: string | null }
/** An issue that counts as a prompt: github-actions[bot], the update key marker first. */
export interface UpdatePrompt { issue: number; in: RecordRepo; key: string; version: string; patches: IssuePatch[]; malformed?: string }
export interface IgnoredIssue { issue: number; in: RecordRepo; why: string }
/** A prompt pipegen doesn't act on: why, and (for a differing patch) both sides shown. */
export interface RefusedIssue { issue: number; in: RecordRepo; why: string; shown?: string }
/** One file pipegen writes: its text now, what pipegen writes, and whether it was merged into the owner's edits. */
export interface FileChange { repo: RecordRepo; path: string; entry: 'file' | 'edit'; currentSha: string; mode: string; current: string; after: string; ownerEdited: boolean }
export interface Conflict { repo: RecordRepo; path: string; why: string }

/** A swap of one kind of pinned value (see gateSwaps, centralSwaps). */
export interface Swap {
  /** The YAML key whose plain scalar value the swap changes. */
  key: 'uses' | 'central-sha';
  /** Whether a value is one this swap changes. */
  test: (v: string) => boolean;
  /** The value it becomes. */
  to: (v: string) => string;
  /** The version comment the line must carry and gets (pipegen's gate: ` # gate-v<x.y.z>`); `version` is the one it swaps to (a newer one on the line is never moved back, G12-R1 I2). */
  comment?: { re: RegExp; text: string; version: string };
}

export interface UpdateDeps {
  io: Prompter;
  /** The reviewed list bundled with this CLI (loadReviewed()); the gate pin is read from its pipegen-gate entry. */
  reviewed: readonly ReviewedTool[];
  /** Only an interactive run may ask the record trust question (trust.ts). */
  interactive?: boolean;
  local?: LocalRecordDeps; clock?: RateClock; now?: () => Date;
}
export interface UpdateResult {
  /** Whether pull requests were opened or updated. */
  done: boolean;
  preview: string;
  prompts: UpdatePrompt[]; ignored: IgnoredIssue[]; refused: RefusedIssue[]; conflicts: Conflict[]; notes: string[];
  prUrl?: string; centralPrUrl?: string; recordHash?: string;
}

const obj = (v: unknown): Record<string, unknown> => (typeof v === 'object' && v !== null && !Array.isArray(v) ? v as Record<string, unknown> : {});
const show = (s: string, max = 200): string => safeText(s, max);
const label = (repo: RecordRepo, path: string): string => `${repo === 'central' ? 'central ' : ''}${path}`;

// ---------- the reviewed pin ----------

/** The gate pin of the reviewed list bundled with this CLI (its `pipegen-gate` entry). No such entry: an UpdateError. */
export function reviewedGatePin(reviewed: readonly ReviewedTool[]): GatePin {
  const e = reviewed.find((t) => t.id === 'pipegen-gate');
  const c = e?.candidate;
  const sha = c?.pin?.sha;
  if (c === undefined || c.repo !== 'crisworking/pipegen' || typeof sha !== 'string' || !SHA_RE.test(sha) || typeof c.version !== 'string' || !SEMVER_RE.test(c.version)) {
    throw new UpdateError('pipegen\'s reviewed tool list has no pinned gate entry, so `pipegen update` has nothing to update to.');
  }
  return { sha, version: c.version };
}

// ---------- issues → prompts ----------

/** The patch blocks of an issue body: each machine block with the fenced diff right above it (null when there is none). */
function patchesOf(body: string): { patches: IssuePatch[]; malformed?: string } {
  const lines = body.split('\n').map((l) => l.replace(/\r$/, ''));
  const patches: IssuePatch[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!(lines[i] as string).startsWith('<!-- pipegen:patch')) continue;
    const m = PATCH_LINE_RE.exec(lines[i] as string);
    if (m === null) return { patches, malformed: 'a patch block is malformed' };
    let data: unknown;
    try { data = JSON.parse(m[1] as string); } catch { return { patches, malformed: 'a patch block is malformed (not JSON)' }; }
    const d = obj(data);
    const keys = Object.keys(d).sort();
    if (!isDeepStrictEqual(keys, ['baseSha', 'path', 'repo']) || (d.repo !== 'app' && d.repo !== 'central') || typeof d.path !== 'string' || d.path.length > 200 || typeof d.baseSha !== 'string' || !SHA_RE.test(d.baseSha)) {
      return { patches, malformed: 'a patch block is malformed (not pipegen\'s {repo, path, baseSha})' };
    }
    let diff: string | null = null;
    const fence = /^(`{3,})$/.exec(lines[i - 1] ?? '')?.[1];
    if (fence !== undefined) {
      for (let j = i - 2; j >= 0; j--) {
        if (lines[j] === `${fence}diff`) { diff = `${lines.slice(j + 1, i - 1).join('\n')}\n`; break; }
        if (lines[j] === fence) break;
      }
    }
    patches.push({ repo: d.repo, path: d.path, baseSha: d.baseSha, diff });
    if (patches.length > MAX_PATCHES) return { patches, malformed: `the issue holds more than ${MAX_PATCHES} patch blocks` };
  }
  return { patches };
}

/**
 * One issue (GitHub's issues list form) as a prompt, or why it is ignored. null: a pull request (the issues list holds them too). Pure.
 * A prompt needs the author github-actions[bot] of type Bot AND the update key marker as the body's first line.
 */
export function promptOf(issue: unknown, where: RecordRepo): UpdatePrompt | IgnoredIssue | null {
  const o = obj(issue);
  if (o.pull_request !== undefined) return null;
  const number = Number.isSafeInteger(o.number) && (o.number as number) > 0 ? o.number as number : 0;
  const user = obj(o.user);
  if (user.login !== ISSUE_AUTHOR || user.type !== 'Bot') {
    return { issue: number, in: where, why: `it was opened by ${typeof user.login === 'string' ? show(user.login, 60) : 'someone'}${user.login === ISSUE_AUTHOR ? ' (not a bot account)' : ''}, not by ${ISSUE_AUTHOR}` };
  }
  const body = typeof o.body === 'string' ? o.body : '';
  if (body.length > MAX_BODY) return { issue: number, in: where, why: 'its text is longer than any issue pipegen opens' };
  const key = KEY_LINE_RE.exec((body.split('\n')[0] ?? '').replace(/\r$/, ''))?.[1];
  if (key === undefined) return { issue: number, in: where, why: 'its first line is not the pipegen key marker' };
  const v = UPDATE_KEY_RE.exec(key)?.[1];
  if (v === undefined) return { issue: number, in: where, why: `it is pipegen's ${show(key, 100)} issue, not an update issue (pipegen update doesn't act on it)` };
  const p = patchesOf(body);
  return { issue: number, in: where, key, version: v, patches: p.patches, ...(p.malformed === undefined ? {} : { malformed: p.malformed }) };
}

async function listIssues(gh: Octokit, r: RepoRef, clock: RateClock): Promise<unknown[]> {
  const out: unknown[] = [];
  for (let page = 1; page <= MAX_ISSUE_PAGES; page++) {
    const d = await ghRead(gh, 'GET /repos/{owner}/{repo}/issues', r, { state: 'open', labels: 'pipegen', per_page: 100, page }, clock);
    if (!Array.isArray(d)) throw new UpdateError(`GitHub's list of issues of ${show(`${r.owner}/${r.repo}`, 120)} could not be read.`);
    out.push(...d);
    if (d.length < 100) break;
  }
  return out;
}

/** The open pipegen issues of the app repo and of the central repo, as prompts and ignored ones (patches are only parsed, never applied). */
export async function findUpdates(gh: Octokit, app: RepoRef, clock: RateClock = clockOf(gh)): Promise<{ prompts: UpdatePrompt[]; ignored: IgnoredIssue[] }> {
  const prompts: UpdatePrompt[] = [];
  const ignored: IgnoredIssue[] = [];
  for (const [where, r] of [['app', app], ['central', centralOf(app)]] as const) {
    let list: unknown[];
    try { list = await listIssues(gh, r, clock); } catch (e) {
      if (where === 'central' && obj(e).status === 404) continue;
      throw e;
    }
    for (const i of list) {
      const p = promptOf(i, where);
      if (p === null) continue;
      if ('why' in p) ignored.push(p); else prompts.push(p);
    }
  }
  return { prompts, ignored };
}

// ---------- lines, diffs and the 3-way merge (pure) ----------

const splitEol = (text: string): { lines: string[]; eol: boolean } => {
  if (text === '') return { lines: [], eol: false };
  const eol = text.endsWith('\n');
  return { lines: (eol ? text.slice(0, -1) : text).split('\n'), eol };
};
const joinEol = (lines: readonly string[], eol: boolean): string => (lines.length === 0 ? '' : `${lines.join('\n')}${eol ? '\n' : ''}`);

/** For each line of `a`, the line of `b` it is matched to in a longest common subsequence (-1: not matched); null when too large to compare. */
function matchLines(a: readonly string[], b: readonly string[]): Int32Array | null {
  const m = new Int32Array(a.length).fill(-1);
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) { m[p] = p; p++; }
  let s = 0;
  while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) { m[a.length - 1 - s] = b.length - 1 - s; s++; }
  const n = a.length - p - s;
  const k = b.length - p - s;
  if (n === 0 || k === 0) return m;
  if (n * k > MAX_CELLS) return null;
  const w = k + 1;
  const L = new Uint32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) for (let j = k - 1; j >= 0; j--) L[i * w + j] = a[p + i] === b[p + j] ? (L[(i + 1) * w + j + 1] as number) + 1 : Math.max(L[(i + 1) * w + j] as number, L[i * w + j + 1] as number);
  let i = 0;
  let j = 0;
  while (i < n && j < k) {
    if (a[p + i] === b[p + j]) { m[p + i] = p + j; i++; j++; } else if ((L[(i + 1) * w + j] as number) >= (L[i * w + j + 1] as number)) i++; else j++;
  }
  return m;
}

const sameLines = (x: readonly string[], y: readonly string[]): boolean => x.length === y.length && x.every((l, i) => l === y[i]);

/**
 * A 3-way line merge: the changes from `base` to `ours` (the owner's file) and from `base` to `theirs` (pipegen's change on its own last
 * text). Changes to different lines merge; a region both changed differently is a conflict (nothing merged, nothing overwritten). Pure.
 */
export function merge3(base: string, ours: string, theirs: string): { text: string } | { conflict: string } {
  const B = base.split('\n');
  const O = ours.split('\n');
  const T = theirs.split('\n');
  const mo = matchLines(B, O);
  const mt = matchLines(B, T);
  if (mo === null || mt === null) return { conflict: 'the file is too different from what pipegen wrote to merge safely' };
  const out: string[] = [];
  const at: number[] = [];
  let i = 0;
  let j = 0;
  let k = 0;
  for (;;) {
    let s = i;
    while (s < B.length && ((mo[s] as number) < 0 || (mt[s] as number) < 0)) s++;
    const oe = s < B.length ? mo[s] as number : O.length;
    const te = s < B.length ? mt[s] as number : T.length;
    const b = B.slice(i, s);
    const o = O.slice(j, oe);
    const t = T.slice(k, te);
    if (sameLines(o, b)) out.push(...t);
    else if (sameLines(t, b) || sameLines(o, t)) out.push(...o);
    else at.push(j + 1);
    if (s >= B.length) break;
    out.push(B[s] as string);
    i = s + 1; j = oe + 1; k = te + 1;
  }
  if (at.length > 0) return { conflict: `pipegen's change and your edit touch the same lines (near line ${at.slice(0, 5).join(', ')} of your file)` };
  return { text: out.join('\n') };
}

/** A unified diff of `a` → `b` (three lines of context), for the preview and the refused issues. Pure. */
export function unifiedDiff(path: string, a: string, b: string): string {
  const A = splitEol(a).lines;
  const B = splitEol(b).lines;
  const m = matchLines(A, B);
  if (m === null) return `--- a/${path}\n+++ b/${path}\n(the file changes too much to show here)\n`;
  const ops: { t: ' ' | '-' | '+'; line: string; ai: number; bi: number }[] = [];
  let j = 0;
  for (let i = 0; i < A.length; i++) {
    const to = m[i] as number;
    if (to < 0) { ops.push({ t: '-', line: A[i] as string, ai: i, bi: j }); continue; }
    while (j < to) { ops.push({ t: '+', line: B[j] as string, ai: i, bi: j }); j++; }
    ops.push({ t: ' ', line: A[i] as string, ai: i, bi: j }); j++;
  }
  while (j < B.length) { ops.push({ t: '+', line: B[j] as string, ai: A.length, bi: j }); j++; }
  const changed = ops.map((o, x) => (o.t === ' ' ? -1 : x)).filter((x) => x >= 0);
  if (changed.length === 0) return '';
  const out = [`--- a/${path}`, `+++ b/${path}`];
  let x = 0;
  while (x < changed.length) {
    const start = Math.max(0, (changed[x] as number) - 3);
    let end = Math.min(ops.length - 1, (changed[x] as number) + 3);
    while (x + 1 < changed.length && (changed[x + 1] as number) - 3 <= end + 1) { x++; end = Math.min(ops.length - 1, (changed[x] as number) + 3); }
    const h = ops.slice(start, end + 1);
    const aCount = h.filter((o) => o.t !== '+').length;
    const bCount = h.filter((o) => o.t !== '-').length;
    out.push(`@@ -${(h[0] as { ai: number }).ai + (aCount === 0 ? 0 : 1)},${aCount} +${(h[0] as { bi: number }).bi + (bCount === 0 ? 0 : 1)},${bCount} @@`, ...h.map((o) => `${o.t}${o.line}`));
    x++;
  }
  return `${out.join('\n')}\n`;
}

/**
 * Applies a one-file unified diff to `text` strictly (every context and removed line must match at the hunk's own position; no fuzz). The
 * diff must name `path` (`--- a/<path>`, `+++ b/<path>`). null when it doesn't apply cleanly. Pure.
 */
export function applyUnifiedDiff(text: string, diff: string, path: string): string | null {
  const d = diff.split('\n');
  if (d.at(-1) === '') d.pop();
  if (d[0] !== `--- a/${path}` || d[1] !== `+++ b/${path}`) return null;
  const src = splitEol(text);
  const out: string[] = [];
  let eol = src.eol;
  let pos = 0;
  let i = 2;
  if (i >= d.length) return null;
  while (i < d.length) {
    const h = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(d[i] as string);
    if (h === null) return null;
    const oldStart = Number(h[1]);
    const oldCount = h[2] === undefined ? 1 : Number(h[2]);
    const newCount = h[4] === undefined ? 1 : Number(h[4]);
    const start = oldCount === 0 ? oldStart : oldStart - 1;
    if (start < pos || start > src.lines.length) return null;
    out.push(...src.lines.slice(pos, start));
    pos = start;
    i++;
    let seenOld = 0;
    let seenNew = 0;
    let last: string | undefined;
    while (i < d.length && !(d[i] as string).startsWith('@@')) {
      const l = d[i] as string;
      i++;
      if (l === '\\ No newline at end of file') {
        if (last === '+' || last === ' ') eol = false; else if (last === '-') eol = true; else return null;
        continue;
      }
      const t = l[0];
      const body = l.slice(1);
      if (t === ' ' || t === '-') {
        if (src.lines[pos] !== body) return null;
        pos++; seenOld++;
        if (t === ' ') { out.push(body); seenNew++; }
      } else if (t === '+') { out.push(body); seenNew++; } else return null;
      last = t;
    }
    if (seenOld !== oldCount || seenNew !== newCount) return null;
  }
  out.push(...src.lines.slice(pos));
  return joinEol(out, eol);
}

// ---------- the swaps (pure) ----------

const GATE_COMMENT_RE = new RegExp(` # gate-v${SEMVER}(\\s*)$`);
/** pipegen's gate `uses:` (any other pin) → the reviewed pin, with its ` # gate-v<version>` comment. */
export function gateSwaps(pin: GatePin): Swap[] {
  const to = `${PIPEGEN_GATE_USES}@${pin.sha}`;
  return [{ key: 'uses', test: (v) => GATE_USES_RE.test(v) && v !== to, to: () => to, comment: { re: GATE_COMMENT_RE, text: ` # gate-v${pin.version}`, version: pin.version } }];
}
const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
/** The central layers a project's files are named for (central-path.ts CentralLayer). */
const CENTRAL_LAYERS: readonly CentralLayer[] = ['merge', 'push', 'nightly', 'sign', 'required'];
/** This project's central workflow files, exactly (G12-R1 m5: never a prefix match, which another project's name could share). */
export const centralFilesOf = (appRepo: string): string[] => CENTRAL_LAYERS.map((l) => centralWorkflowFile(appRepo, l));
/** `<owner>/pipelines/<one of this project's central files>@<sha>`: group 1 the file, group 2 the sha. */
/** The owner matched in any letter case (GitHub names are case-insensitive); the path matched exactly (git paths are not; G12-R2 N6). */
const anyCase = (s: string): string => [...s].map((c) => (/[A-Za-z]/.test(c) ? `[${c.toLowerCase()}${c.toUpperCase()}]` : esc(c))).join('');
const centralCallRe = (owner: string, appRepo: string): RegExp => new RegExp(`^${anyCase(owner)}/${esc(CENTRAL_REPO)}/(${centralFilesOf(appRepo).map(esc).join('|')})@([0-9a-f]{40})$`);
/** The app's calls of this project's central workflows at commit `from` → `to` (the `uses:` and the find-run step's `central-sha`). */
export function centralSwaps(owner: string, appRepo: string, from: string, to: string): Swap[] {
  const call = centralCallRe(owner, appRepo);
  const re = { test: (v: string): boolean => call.exec(v)?.[2] === from };
  return [
    { key: 'uses', test: (v) => re.test(v), to: (v) => `${v.slice(0, -40)}${to}` },
    { key: 'central-sha', test: (v) => v === from, to: () => to },
  ];
}

const parseYaml = (text: string): { ok: true; js: unknown } | { ok: false } => {
  try {
    const doc = parseDocument(text, { uniqueKeys: true });
    if (doc.errors.length > 0) return { ok: false };
    return { ok: true, js: doc.toJS({ maxAliasCount: 100 }) };
  } catch { return { ok: false }; }
};
const lineStart = (text: string, at: number): number => text.lastIndexOf('\n', at - 1) + 1;
const lineEnd = (text: string, at: number): number => { const e = text.indexOf('\n', at); return e < 0 ? text.length : e; };

/**
 * Swaps the values `swaps` name in `text` (plain YAML scalars of real `key: value` pairs, never text inside a block scalar), keeping every other
 * byte. The result is held to changeProblem. `refused` when a value to swap is not in pipegen's form (quoted, no version comment) or the file
 * is not YAML. Pure.
 */
export function swapPins(text: string, swaps: readonly Swap[]): { text: string } | { refused: string; newer?: string } {
  let doc;
  try { doc = parseDocument(text, { uniqueKeys: true }); } catch { return { refused: 'it is not valid YAML' }; }
  if (doc.errors.length > 0) return { refused: 'it is not valid YAML' };
  const edits: { start: number; end: number; value: string; swap: Swap }[] = [];
  let problem: string | null = null;
  let newerSeen: string | null = null;
  visit(doc, {
    Pair(_, pair) {
      if (!isScalar(pair.key) || !isScalar(pair.value)) return;
      const k = pair.key.value;
      const v = pair.value.value;
      if (typeof k !== 'string' || typeof v !== 'string') return;
      const s = swaps.find((x) => x.key === k && x.test(v));
      if (s === undefined) return;
      const range = pair.value.range;
      if (pair.value.type !== 'PLAIN' || range === undefined || range === null || text.slice(range[0], range[1]) !== v) { problem = `a pinned \`${k}\` value is not written in pipegen's plain form`; return; }
      if (s.comment !== undefined) {
        // G12-R1 I2: a line pinned at a NEWER gate than this pipegen's is never moved back (no silent downgrade)
        const was = new RegExp(`^ # gate-v(${SEMVER})(?:\\s|$)`).exec(text.slice(range[1], lineEnd(text, range[1])))?.[1];
        if (was !== undefined && newer(was, s.comment.version)) { newerSeen = was; return; }
      }
      edits.push({ start: range[0], end: range[1], value: s.to(v), swap: s });
    },
  });
  if (newerSeen !== null) return { refused: `it pins pipegen's gate at v${newerSeen}, newer than this pipegen's reviewed pin`, newer: newerSeen };
  if (problem !== null) return { refused: problem };
  let out = text;
  const lines = new Set<number>();
  for (const e of [...edits].sort((a, b) => b.start - a.start)) {
    const ls = lineStart(out, e.start);
    if (lines.has(ls)) return { refused: 'two pinned values share one line' };
    lines.add(ls);
    let next = `${out.slice(0, e.start)}${e.value}${out.slice(e.end)}`;
    if (e.swap.comment !== undefined) {
      const le = lineEnd(next, e.start);
      const tail = next.slice(e.start + e.value.length, le);
      const m = e.swap.comment.re.exec(tail);
      if (m === null || m.index !== 0) return { refused: 'a pinned gate line has no version comment in pipegen\'s form' };
      next = `${next.slice(0, e.start + e.value.length)}${e.swap.comment.text}${m[1] as string}${next.slice(le)}`;
    }
    out = next;
  }
  const problemAfter = changeProblem(text, out, swaps);
  return problemAfter === null ? { text: out } : { refused: problemAfter };
}

/** Whether `a` → `b` changes only values a swap allows (at the key it names), and nothing else of the YAML's data. */
function onlySwapped(a: unknown, b: unknown, swaps: readonly Swap[], key: string | null): boolean {
  if (typeof a === 'string' && typeof b === 'string') return a === b || (key !== null && swaps.some((s) => s.key === key && s.test(a) && s.to(a) === b));
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => onlySwapped(x, b[i], swaps, null));
  if (a !== null && b !== null && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    const ka = Object.keys(a);
    if (!isDeepStrictEqual(ka, Object.keys(b))) return false;
    return ka.every((k) => onlySwapped((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], swaps, k));
  }
  return isDeepStrictEqual(a, b);
}
const SWAP_LINE_RE = /^\s*(?:-\s+)?(?:uses|central-sha):\s/;

/**
 * The final check on every change pipegen writes (a pin swap, merged or not), or null: the same number of lines; each changed line a
 * `uses:` / `central-sha:` line before and after, never the `# pipegen:not-proven` line; both texts YAML; and the data equal except for values
 * a swap allows (so a pin outside the reviewed list, or any other edit, is refused). Pure.
 */
export function changeProblem(before: string, after: string, swaps: readonly Swap[]): string | null {
  const a = before.split('\n');
  const b = after.split('\n');
  if (a.length !== b.length) return 'the change adds or removes lines; a pin swap only changes pin lines';
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) continue;
    if ((a[i] as string).includes(NOT_PROVEN_MARK) || (b[i] as string).includes(NOT_PROVEN_MARK)) return 'the change touches the not-proven line';
    if (!SWAP_LINE_RE.test(a[i] as string) || !SWAP_LINE_RE.test(b[i] as string)) return `the change edits line ${i + 1}, which is not a pin line`;
  }
  const pa = parseYaml(before);
  const pb = parseYaml(after);
  if (!pa.ok || !pb.ok) return 'the file is not valid YAML before or after the change';
  if (!onlySwapped(pa.js, pb.js, swaps, null)) return 'the change sets a value that is not a pin of the reviewed list (or changes more than the pins)';
  return null;
}

// ---------- the not-proven line (Plan H promotions; pure) ----------

const NP_LINE_RE = new RegExp(`^(\\s*not-proven:\\s+)'(\\[[^']*\\])'( # ${esc(NOT_PROVEN_MARK)})\\s*$`);
const npList = (line: string): string[] | null => {
  const m = NP_LINE_RE.exec(line);
  if (m === null) return null;
  try {
    const v: unknown = JSON.parse(m[2] as string);
    return Array.isArray(v) && v.every((x) => typeof x === 'string') ? v as string[] : null;
  } catch { return null; }
};

/**
 * Why `before` → `after` is not a not-proven promotion, or null: only the one line marked `# pipegen:not-proven` changes (the line count,
 * every other byte and the mark stay), its list only loses checks (adding one, or naming a floor check, is refused) and the file stays YAML.
 */
export function notProvenProblem(before: string, after: string): string | null {
  const a = before.split('\n');
  const b = after.split('\n');
  const marked = a.flatMap((l, i) => (l.includes(NOT_PROVEN_MARK) ? [i] : []));
  if (marked.length !== 1) return 'the file has no single not-proven line';
  const at = marked[0] as number;
  if (a.length !== b.length || a.some((l, i) => i !== at && l !== b[i])) return 'a not-proven change may edit only the # pipegen:not-proven line, and this one edits more';
  const was = npList(a[at] as string);
  const now = npList(b[at] as string);
  if (was === null || now === null) return 'the not-proven line is not in pipegen\'s form before or after the change';
  if (now.some((n) => (FLOOR_NEEDS as readonly string[]).includes(n))) return 'the change names a floor check as not proven';
  if (now.some((n) => !was.includes(n)) || new Set(now).size !== now.length) return 'the change adds a check to the not-proven list (a promotion only removes)';
  return parseYaml(after).ok ? null : 'the file is not valid YAML after the change';
}

/** The not-proven line without the `promote` checks (held to notProvenProblem). `refused` when no listed check is promoted. Pure. */
export function deriveNotProven(text: string, promote: readonly string[]): { text: string } | { refused: string } {
  const lines = text.split('\n');
  const at = lines.findIndex((l) => l.includes(NOT_PROVEN_MARK));
  const m = at < 0 ? null : NP_LINE_RE.exec(lines[at] as string);
  const was = at < 0 ? null : npList(lines[at] as string);
  if (m === null || was === null) return { refused: 'the file has no not-proven line in pipegen\'s form' };
  const now = was.filter((n) => !promote.includes(n));
  if (now.length === was.length) return { refused: 'none of these checks is on the not-proven list' };
  lines[at] = `${m[1] as string}'${JSON.stringify(now)}'${m[3] as string}`;
  const out = lines.join('\n');
  const p = notProvenProblem(text, out);
  return p === null ? { text: out } : { refused: p };
}

// ---------- planning (reads only) ----------

/** ownerEdited: the record's marker (a file `pipegen update` merged into the owner's text, or any verify-job edit: the owner's file). */
interface Touchable { repo: RecordRepo; path: string; entry: 'file' | 'edit'; shas: readonly string[]; ownerEdited: boolean }
/** The record entries update may touch: this project's workflows written whole (app, and central `<name>--*`), and its verify-job edits. */
function touchable(r: InstallRecord): Touchable[] {
  const out: Touchable[] = [];
  for (const f of r.files) {
    if (!WORKFLOW_RE.test(f.path)) continue;
    if (f.repo === 'central' && !centralFilesOf(r.app.repo).includes(f.path)) continue;
    out.push({ repo: f.repo, path: f.path, entry: 'file', shas: f.shas, ownerEdited: f.ownerEdited === true });
  }
  for (const e of r.edits) if (e.kind === 'verify-job' && WORKFLOW_RE.test(e.path)) out.push({ repo: e.repo, path: e.path, entry: 'edit', shas: e.writtenShas, ownerEdited: true });
  return out;
}

interface RepoState { ref: RepoRef; defaultBranch: string; head: string; tree: string; entries: Map<string, TreeEntry> }
async function repoState(gh: Octokit, ref: RepoRef, clock: RateClock): Promise<RepoState> {
  const repo = await readRepo(gh, ref, clock);
  if (repo === null) throw new UpdateError(`pipegen can't see ${show(`${ref.owner}/${ref.repo}`, 120)}.`);
  const head = await readHead(gh, ref, repo.defaultBranch, clock);
  if (head === null) throw new UpdateError(`${show(`${ref.owner}/${ref.repo}`, 120)} has no default branch.`);
  const t = await readTree(gh, ref, head, clock);
  return { ref, defaultBranch: repo.defaultBranch, head, tree: t.tree, entries: t.entries };
}

/** held (G12-R2 N2): why a file was left on an old pin on purpose; the run then answers no issue whole (no `Closes #N`) and says so. */
interface Derived { changes: FileChange[]; conflicts: Conflict[]; notes: string[]; held: string[]; current: Map<string, { sha: string; text: string }> }
const keyOf = (repo: RecordRepo, path: string): string => `${repo}:${path}`;

/** A blob GitHub doesn't give (gone, too large, an answer pipegen can't read): never a rate stop or a rejected token. */
const unreadable = (e: unknown): boolean => !isRateStop(e) && (e instanceof DeliverError || [404, 409, 422].includes(statusOf(e) ?? 0));

/** pipegen's change to each touchable file of `repo` (owner edits merged 3-way), the conflicts, and each file's text now (for the issue checks). */
async function derive(gh: Octokit, st: RepoState, items: readonly Touchable[], swaps: readonly Swap[], clock: RateClock, out: Derived): Promise<void> {
  for (const t of items) {
    const e = st.entries.get(t.path);
    if (e === undefined) { out.notes.push(`${label(t.repo, show(t.path))} is not in the repository any more, so pipegen doesn't change it.`); continue; }
    if (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755')) { out.conflicts.push({ repo: t.repo, path: t.path, why: 'it is a link or not a plain file' }); continue; }
    const current = await readBlobText(gh, st.ref, e.sha, MAX_FILE_BYTES, clock);
    // m2: a file that isn't UTF-8 would be decoded lossily and written back changed outside its pin lines
    if (gitBlobSha(current) !== e.sha) { out.conflicts.push({ repo: t.repo, path: t.path, why: 'it is not UTF-8 text, so pipegen can\'t change it byte-exactly' }); continue; }
    out.current.set(keyOf(t.repo, t.path), { sha: e.sha, text: current });
    const ownerEdited = !t.shas.includes(e.sha);
    // I2: a file a newer pipegen pinned is left alone (never moved back to an older gate). G12-R2 N1: only a file pipegen wrote (its blob is a
    // recorded sha) is believed; anyone's `# gate-v99` on an unvouched file goes through the merge, where it is a conflict
    // G12-R3 H1: a recorded sha proves pipegen wrote every line only for a whole file pipegen alone wrote (ownWholeFile: not a merged
    // ownerEdited file, never a verify-job edit, which is the owner's file); anywhere else a newer comment is a conflict, never merged around
    const probe = swapPins(current, swaps);
    if ('newer' in probe && probe.newer !== undefined) {
      if (t.entry === 'file' && !t.ownerEdited && !ownerEdited) {
        const why = `${label(t.repo, show(t.path))}: a newer pipegen wrote this (gate v${probe.newer}); pipegen leaves it as it is. Run \`npx pipegen@latest update\`.`;
        out.notes.push(why); out.held.push(why); continue;
      }
      out.conflicts.push({ repo: t.repo, path: t.path, why: `a gate line pipegen can't vouch for carries a version comment newer than this pipegen's (v${probe.newer}); check that line and merge by hand` });
      continue;
    }
    let base = current;
    if (ownerEdited) {
      const last = t.shas.at(-1);
      try { base = await readBlobText(gh, st.ref, last as string, MAX_FILE_BYTES, clock); } catch (err) {
        // Spec M1: only an unreadable blob is that conflict; a rate stop, a rejected token or a network error stops the run
        if (!unreadable(err)) throw err;
        out.conflicts.push({ repo: t.repo, path: t.path, why: 'you edited it and pipegen can\'t read the version it wrote last, so it can\'t merge its change' }); continue;
      }
      if (gitBlobSha(base) !== last) { out.conflicts.push({ repo: t.repo, path: t.path, why: 'the version pipegen wrote last could not be read exactly' }); continue; }
    }
    const theirs = swapPins(base, swaps);
    if ('refused' in theirs) { out.conflicts.push({ repo: t.repo, path: t.path, why: `pipegen can't change it: ${theirs.refused}` }); continue; }
    if (theirs.text === base) {
      // m3 (N7): pipegen's own last text is current, but the owner's file pins something else: say what (never a silent "nothing to change")
      let why: string | null = null;
      if ('refused' in probe) why = `${label(t.repo, show(t.path))}: your edit pins a value pipegen can't update (${probe.refused}); pipegen didn't change it.`;
      else if (probe.text !== current) {
        const gateOnly = swapPins(current, swaps.filter((x) => x.comment !== undefined));
        const what = 'text' in gateOnly && gateOnly.text !== current ? 'pipegen\'s gate at a commit other than the reviewed one' : 'a central workflow at another central commit';
        why = `${label(t.repo, show(t.path))} pins ${what} (an edit of yours); pipegen didn't change it.`;
      }
      if (why !== null) { out.notes.push(why); out.held.push(why); }
      continue;
    }
    let after = theirs.text;
    if (ownerEdited) {
      const m = merge3(base, current, theirs.text);
      if ('conflict' in m) { out.conflicts.push({ repo: t.repo, path: t.path, why: m.conflict }); continue; }
      after = m.text;
    }
    if (after === current) continue;
    const p = changeProblem(current, after, swaps);
    if (p !== null) { out.conflicts.push({ repo: t.repo, path: t.path, why: p }); continue; }
    out.changes.push({ repo: t.repo, path: t.path, entry: t.entry, currentSha: e.sha, mode: e.mode, current, after, ownerEdited });
  }
}

/** The central workflows this project's app calls, per file, with the commits it calls them at (its own text, never the record's centralSha: m4). */
function centralCallsIn(texts: readonly string[], owner: string, appRepo: string): Map<string, Set<string>> {
  const re = centralCallRe(owner, appRepo);
  const calls = new Map<string, Set<string>>();
  for (const text of texts) {
    let doc;
    try { doc = parseDocument(text, { uniqueKeys: true }); } catch { continue; }
    visit(doc, {
      Pair(_, pair) {
        if (!isScalar(pair.key) || pair.key.value !== 'uses' || !isScalar(pair.value) || typeof pair.value.value !== 'string') return;
        const m = re.exec(pair.value.value);
        if (m === null) return;
        const file = m[1] as string;
        calls.set(file, (calls.get(file) ?? new Set()).add(m[2] as string));
      },
    });
  }
  return calls;
}

/**
 * The central re-pin of a private app (G12-R1 I1, proven from content, never from the record's shas): the app calls its central files at one
 * commit `from`; every file it calls must, at the central default head, be exactly pipegen's update of that file at `from`
 * (swapPins(blob at from, gate swaps)), and at least one of them must change. Anything that can't be checked, or differs, is no re-pin and a
 * plain note. null: no re-pin.
 */
async function repinTarget(gh: Octokit, app: RepoRef, appTexts: readonly string[], central: RepoState, gate: readonly Swap[], clock: RateClock, notes: string[]): Promise<{ from: string; to: string } | { refused: string } | null> {
  const calls = centralCallsIn(appTexts, app.owner, app.repo);
  if (calls.size === 0) return null;
  const shas = new Set([...calls.values()].flatMap((x) => [...x]));
  if (shas.size !== 1) { const why = 'The app calls its central workflows at more than one central commit, so pipegen doesn\'t re-pin it.'; notes.push(why); return { refused: why }; }
  const from = [...shas][0] as string;
  if (from === central.head) return null;
  const refuse = (why: string): { refused: string } => { const text = `pipegen doesn't re-pin the app to the central default branch: ${why}.`; notes.push(text); return { refused: text }; };
  let at;
  try { at = await readTree(gh, central.ref, from, clock); } catch (e) { if (!unreadable(e)) throw e; return refuse('it can\'t read the central commit the app calls'); }
  let needed = false;
  for (const file of calls.keys()) {
    const was = at.entries.get(file);
    const now = central.entries.get(file);
    if (was === undefined || now === undefined || was.type !== 'blob' || now.type !== 'blob') return refuse(`it can't check ${show(file)} in both commits`);
    let wasText: string;
    let nowText: string;
    try { wasText = await readBlobText(gh, central.ref, was.sha, MAX_FILE_BYTES, clock); nowText = await readBlobText(gh, central.ref, now.sha, MAX_FILE_BYTES, clock); } catch (e) { if (!unreadable(e)) throw e; return refuse(`it can't read ${show(file)}`); }
    if (gitBlobSha(wasText) !== was.sha || gitBlobSha(nowText) !== now.sha) return refuse(`${show(file)} is not UTF-8 text`);
    const s = swapPins(wasText, gate);
    if ('refused' in s) return refuse(`it can't update ${show(file)} (${s.refused})`);
    if (nowText !== s.text) return refuse(`${show(file)} on the central default branch is not pipegen's update of the file the app calls`);
    if (s.text !== wasText) needed = true;
  }
  return needed ? { from, to: central.head } : null;
}

/** Each prompt held to pipegen's own derivation: refused (with why, and both sides for a differing patch) or acted on. */
function checkPrompts(prompts: readonly UpdatePrompt[], gate: GatePin, record: InstallRecord, d: Derived): { acted: UpdatePrompt[]; refused: RefusedIssue[] } {
  const allowed = new Set(touchable(record).map((t) => keyOf(t.repo, t.path)));
  const acted: UpdatePrompt[] = [];
  const refused: RefusedIssue[] = [];
  const refuse = (p: UpdatePrompt, why: string, shown?: string): void => { refused.push({ issue: p.issue, in: p.in, why, ...(shown === undefined ? {} : { shown }) }); };
  next: for (const p of prompts) {
    if (p.malformed !== undefined) { refuse(p, `its patch is malformed: ${p.malformed}`); continue; }
    if (p.version !== gate.version) {
      refuse(p, `it asks for gate v${p.version}, which is not in the reviewed list of this pipegen (it pins gate v${gate.version}); ${newer(p.version, gate.version) ? 'a newer pipegen may carry it: run `npx pipegen@latest update`' : 'pipegen updates only to its reviewed pin'}`);
      continue;
    }
    for (const x of p.patches) {
      if (!allowed.has(keyOf(x.repo, x.path))) { refuse(p, `its patch touches ${label(x.repo, show(x.path))}, a file not in the install record`); continue next; }
      const cur = d.current.get(keyOf(x.repo, x.path));
      if (cur === undefined) { refuse(p, `its patch touches ${label(x.repo, show(x.path))}, which pipegen can't read now`); continue next; }
      if (x.baseSha !== cur.sha) { refuse(p, `its patch doesn't match baseSha: it was made for another version of ${show(x.path)}`); continue next; }
      if (x.diff === null) { refuse(p, `its patch for ${show(x.path)} has no diff (malformed)`); continue next; }
      const applied = applyUnifiedDiff(cur.text, x.diff, x.path);
      if (applied === null) { refuse(p, `its patch for ${show(x.path)} doesn't apply cleanly to the file as it is now`); continue next; }
      const expected = d.changes.find((c) => c.repo === x.repo && c.path === x.path)?.after ?? cur.text;
      if (applied !== expected) {
        refuse(p, `its patch for ${show(x.path)} differs from the change pipegen derived itself from its reviewed list`, [
          'The issue\'s patch:', ...shownLines(x.diff), 'pipegen\'s own change:', ...shownLines(unifiedDiff(x.path, cur.text, expected) || '(no change)\n'),
        ].join('\n'));
        continue next;
      }
    }
    acted.push(p);
  }
  return { acted, refused };
}
const newer = (a: string, b: string): boolean => {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((x[i] as number) !== (y[i] as number)) return (x[i] as number) > (y[i] as number);
  return false;
};
/** Diff text for the terminal: each line made safe, at most MAX_SHOWN_LINES. */
function shownLines(diff: string): string[] {
  const lines = diff.replace(/\n$/, '').split('\n');
  const kept = lines.slice(0, MAX_SHOWN_LINES).map((l) => `    ${show(l, 400)}`);
  return lines.length > MAX_SHOWN_LINES ? [...kept, `    (${lines.length - MAX_SHOWN_LINES} more lines)`] : kept;
}

// ---------- the preview ----------

interface Plan { held: string[]; appRepo: string; gate: GatePin; app: FileChange[]; central: FileChange[]; conflicts: Conflict[]; acted: UpdatePrompt[]; ignored: IgnoredIssue[]; refused: RefusedIssue[]; notes: string[]; repin: string | null; name: string }

function previewOf(p: Plan): string {
  const out = [`pipegen update: the gate pin of this pipegen's reviewed list is v${p.gate.version} (${p.gate.sha}). Issues are only prompts: pipegen derived every change below itself.`];
  const issues = [
    ...p.acted.map((x) => `  #${x.issue} acted on (${x.in === 'central' ? 'central repo, ' : ''}${show(x.key, 100)})`),
    ...p.ignored.map((x) => `  #${x.issue} ignored: ${x.why}`),
    ...p.refused.flatMap((x) => [`  #${x.issue} refused: ${x.why}`, ...(x.shown === undefined ? [] : [x.shown])]),
  ];
  if (issues.length > 0) out.push('', 'Issues:', ...issues);
  const section = (title: string, changes: readonly FileChange[]): void => {
    if (changes.length === 0) return;
    out.push('', title);
    for (const c of changes) out.push(`  ${show(c.path)}${c.ownerEdited ? ' (merged with your edits: pipegen changed only its pin lines)' : ''}`, ...shownLines(unifiedDiff(c.path, c.current, c.after)));
  };
  section(`Central repo (${CENTRAL_REPO}), pull request ${centralUpdateBranch(p.appRepo)}:`, p.central);
  section(`App repo, pull request ${UPDATE_BRANCH}:`, p.app);
  if (p.conflicts.length > 0) out.push('', 'Not changed (merge by hand; pipegen never overwrites your edits):', ...p.conflicts.map((c) => `  ${label(c.repo, show(c.path))}: ${c.why}`));
  if (p.notes.length > 0) out.push('', ...p.notes);
  if (p.app.length === 0 && p.central.length === 0) out.push('', 'Nothing to change.');
  return out.join('\n');
}

function appPrBody(p: Plan): string {
  const lines = [
    `pipegen moves its pins to gate v${safeMarkdown(p.gate.version, 20)} (\`${p.gate.sha}\`), the pin of the reviewed list bundled with the pipegen version that opened this pull request. Review it like any other change: it goes through the gate and code-owner review.`,
    '', 'Files:', ...p.app.map((c) => `- \`${safeMarkdown(c.path, 200)}\`${c.ownerEdited ? ' (merged with your edits)' : ''}`),
  ];
  if (p.repin !== null) lines.push('', `The calls of the central workflows now pin \`${p.repin}\`, the central commit that holds the updated files.`);
  const conflicts = p.conflicts.filter((c) => c.repo === 'app');
  if (conflicts.length > 0) lines.push('', 'Not changed (merge by hand; pipegen never overwrites your edits):', ...conflicts.map((c) => `- \`${safeMarkdown(c.path, 200)}\`: ${safeMarkdown(c.why, 300)}`));
  if (p.held.length > 0) lines.push('', 'Left on its old pin on purpose (this pull request doesn\'t finish the update; what to do is on each line):', ...p.held.map((h) => `- ${safeMarkdown(h, 400)}`));
  const closes = p.acted.filter((x) => x.in === 'app' && answers(x, p));
  if (closes.length > 0) lines.push('', ...closes.map((x) => `Closes #${x.issue}`));
  return lines.join('\n');
}
/**
 * Spec M4: a pull request closes an issue only when it answers it whole: every file the issue's patches name is changed in this run, and an
 * issue that names no file (a private repo's) is closed only when no file is left in the conflict list.
 */
function answers(x: UpdatePrompt, p: Plan): boolean {
  if (p.held.length > 0) return false;   // G12-R2 N2: a file left on an old pin on purpose: the update is not done
  const changed = new Set([...p.app, ...p.central].map((c) => keyOf(c.repo, c.path)));
  return x.patches.length > 0 ? x.patches.every((y) => changed.has(keyOf(y.repo, y.path))) : p.conflicts.length === 0;
}
function centralPrBody(p: Plan): string {
  const lines = [
    `pipegen moves the gate pin of the central workflows of ${safeMarkdown(p.name, 100)} to v${safeMarkdown(p.gate.version, 20)} (\`${p.gate.sha}\`), the pin of its reviewed list, and records what it wrote in the install record. After this pull request is merged, run \`pipegen update\` again: it then pins the app to the merged commit.`,
    '', 'Files:', ...p.central.map((c) => `- \`${safeMarkdown(c.path, 200)}\`${c.ownerEdited ? ' (merged with your edits)' : ''}`),
  ];
  if (p.held.length > 0) lines.push('', 'Left on its old pin on purpose (what to do is on each line):', ...p.held.map((h) => `- ${safeMarkdown(h, 400)}`));
  const conflicts = p.conflicts.filter((c) => c.repo === 'central');
  if (conflicts.length > 0) lines.push('', 'Not changed (merge by hand):', ...conflicts.map((c) => `- \`${safeMarkdown(c.path, 200)}\`: ${safeMarkdown(c.why, 300)}`));
  const closes = p.acted.filter((x) => x.in === 'central' && answers(x, p));
  if (closes.length > 0) lines.push('', ...closes.map((x) => `Closes #${x.issue}`));
  return lines.join('\n');
}

// ---------- the record ----------

/** The record with every written blob sha appended (newest last) and the merged files marked ownerEdited; the new central pin when re-pinned. */
export function recordAfter(record: InstallRecord, changes: readonly FileChange[], repin: string | null): InstallRecord {
  const r = structuredClone(record);
  for (const c of changes) {
    const sha = gitBlobSha(c.after);
    if (c.entry === 'file') {
      const f = r.files.find((x) => x.repo === c.repo && x.path === c.path);
      if (f === undefined) throw new UpdateError(`${show(c.path)} is not in the install record.`);
      if (f.shas.at(-1) !== sha) f.shas.push(sha);
      if (c.ownerEdited) f.ownerEdited = true;
    } else {
      const e = r.edits.find((x) => x.repo === c.repo && x.path === c.path);
      if (e === undefined) throw new UpdateError(`${show(c.path)} is not in the install record.`);
      if (e.writtenShas.at(-1) !== sha) e.writtenShas.push(sha);
      if (c.ownerEdited) e.ownerEdited = true;
    }
  }
  if (repin !== null) r.centralSha = repin;
  return r;
}

async function setupPrNumber(gh: Octokit, app: RepoRef, local: number | undefined, clock: RateClock): Promise<number> {
  if (local !== undefined) return local;
  const d = await ghRead(gh, 'GET /repos/{owner}/{repo}/pulls', app, { head: `${app.owner}:${SETUP_BRANCH}`, state: 'all', per_page: 100 }, clock);
  const n = (Array.isArray(d) ? d : []).map(obj).filter((p) => obj(p.head).ref === SETUP_BRANCH && Number.isSafeInteger(p.number)).map((p) => p.number as number).sort((a, b) => b - a)[0];
  if (n === undefined) throw new UpdateError(`pipegen can't find its setup pull request (branch ${SETUP_BRANCH}) in ${show(`${app.owner}/${app.repo}`, 120)}, where the record hash goes; run pipegen first.`);
  return n;
}

// ---------- the command ----------

/**
 * `pipegen update` for the app `app` (see the header): trust the record, read the prompts, derive, show everything, ask once, then open the
 * pull requests and write the record. Throws UpdateError (nothing written) without a trusted record or a reviewed gate pin.
 */
export async function update(gh: Octokit, app: RepoRef, deps: UpdateDeps): Promise<UpdateResult> {
  const clock = deps.clock ?? clockOf(gh);
  const gate = reviewedGatePin(deps.reviewed);
  const appSt = await repoState(gh, app, clock);
  const centralRef = centralOf(app);
  const centralRepo = await readRepo(gh, centralRef, clock);
  if (centralRepo === null) throw new UpdateError(`pipegen can't see ${show(`${centralRef.owner}/${centralRef.repo}`, 120)}, where its install record is, so it changes nothing.`);
  const notes: string[] = [];
  // G12-R2 N4: update never asks the typed trust question (its answer would stand for deliver and uninstall, and update can't use a view)
  const trusted = await trustedPrevious(gh, app, centralRef, centralRepo.defaultBranch, centralUpdateBranch(app.repo), deps.local ?? {}, clock, notes, { io: deps.io, interactive: false });
  if (trusted.record === null && trusted.why === 'no-local') {
    throw new UpdateError(`This machine has no local record file for ${show(`${app.owner}/${app.repo}`, 140)}, so pipegen can't check its install record. Run \`npx pipegen\` in this repo first (it re-checks the full setup), then run update again.`);
  }
  if (trusted.record === null) {
    throw new UpdateError(`pipegen found no install record for ${show(`${app.owner}/${app.repo}`, 140)} that it trusts, so it changes nothing: update touches only the files the record lists.${notes.length > 0 ? ` ${notes.join(' ')}` : ''}`);
  }
  const record = trusted.record;
  // G12-R1 C1: a record trusted by typing is a view (edits, plans and settings dropped); update never writes it back as the record
  // N5: from what the trust decision returned, never a second read of the file
  if (trusted.typed === true) throw new UpdateError('pipegen can\'t update from a record you only confirmed by name. Run `npx pipegen run` in this repo first (it re-checks the full setup), then run update again.');
  const appRepo = await readRepo(gh, app, clock);
  if (appRepo === null || appRepo.id !== record.app.repoId) throw new UpdateError(`The install record is for another repository than ${show(`${app.owner}/${app.repo}`, 140)} (its id differs), so pipegen changes nothing.`);
  const centralSt = await repoState(gh, centralRef, clock);

  const { prompts, ignored } = await findUpdates(gh, app, clock);
  const items = touchable(record);
  const gateSw = gateSwaps(gate);
  const d: Derived = { changes: [], conflicts: [], notes, held: [], current: new Map() };
  const centralItems = items.filter((t) => t.repo === 'central');
  await derive(gh, centralSt, centralItems, gateSw, clock, d);
  const central = d.changes.filter((c) => c.repo === 'central');
  const appItems = items.filter((t) => t.repo === 'app');
  let repin: { from: string; to: string } | { refused: string } | null = null;
  if (central.length === 0 && record.centralSha !== null) {
    const texts: string[] = [];
    for (const t of appItems) {
      const e = appSt.entries.get(t.path);
      if (e?.type === 'blob') texts.push(await readBlobText(gh, app, e.sha, MAX_FILE_BYTES, clock));
    }
    repin = await repinTarget(gh, app, texts, centralSt, gateSw, clock, notes);
  }
  const moved = repin !== null && 'from' in repin ? repin : null;
  const appSwaps = moved === null ? gateSw : [...gateSw, ...centralSwaps(app.owner, app.repo, moved.from, moved.to)];
  await derive(gh, appSt, appItems, appSwaps, clock, d);
  let appChanges = d.changes.filter((c) => c.repo === 'app');
  if (repin !== null && 'refused' in repin) {
    // G12-R2 N2: the app is never half-updated (its verify job on the new gate, its calls on the old central commit): nothing of the app goes out
    // G12-R3 M1: npx pipegen can't help here (a merged central file is the owner's); the way on is the central file itself
    const wayOn = 'Bring the central file back to pipegen\'s text, or merge the change by hand; then run `pipegen update` again.';
    notes.push(appChanges.length > 0 ? `pipegen holds back the app's own pin changes too, so the app is never half-updated. ${wayOn}` : wayOn);
    d.held.push(`${repin.refused} ${wayOn}`);
    appChanges = [];
  }
  if (moved !== null && appChanges.length > 0) {
    // G13 (m7, ruling G13-R0 8): a verify job names the central commit inside a run line too (attest's --signer-digest), which no pin swap
    // reaches; update has no draft to render the job again (renewVerifyJob), so a verify job that would keep the old commit is not re-pinned,
    // and, as in N2, nothing of the app moves (never a verify job on one central commit and the calls on another)
    const stale = appItems.filter((t) => t.entry === 'edit').filter((t) => {
      const key = keyOf(t.repo, t.path);
      const text = appChanges.find((c) => keyOf(c.repo, c.path) === key)?.after ?? d.current.get(key)?.text;
      return text?.includes(moved.from) === true;
    });
    if (stale.length > 0) {
      for (const t of stale) {
        const why = `${label(t.repo, show(t.path))}: its pipegen-verify job names the central commit in a run line that \`pipegen update\` can't rebuild, so pipegen doesn't re-pin this verify job or the rest of the app (a verify job on an old central commit fails closed). Run \`npx pipegen run\` again to re-pin it.`;
        notes.push(why);
        d.held.push(why);
      }
      appChanges = [];
    }
  }
  if (central.length > 0) {
    // the app pins only a commit on the central default branch (S26): its change waits until the central pull request is merged
    notes.push('Merge the central pull request first, then run `pipegen update` again: it then updates the app and pins it to the merged central commit.');
    appChanges = [];
  }
  const { acted, refused } = checkPrompts(prompts, gate, record, d);
  const plan: Plan = { gate, app: appChanges, central, conflicts: d.conflicts, acted, ignored, refused, notes, repin: appChanges.length > 0 ? moved?.to ?? null : null, name: record.name, appRepo: record.app.repo, held: d.held };
  const preview = previewOf(plan);
  const base = { preview, prompts: acted, ignored, refused, conflicts: d.conflicts, notes };
  if (appChanges.length === 0 && central.length === 0) return { done: false, ...base };

  const local = await readLocalRecord(app, deps.local ?? {}).catch((e: unknown) => { if (e instanceof RecordError) return null; throw e; });
  const setupPr = await setupPrNumber(gh, app, local?.setupPr, clock);
  let yes = false;
  try { yes = await deps.io.confirm(`${preview}\n\nOpen the pull request${appChanges.length > 0 && central.length > 0 ? 's' : ''} with these changes?`, false); } catch (e) { if (!(e instanceof PromptCancelledError)) throw e; }
  if (!yes) return { done: false, ...base, notes: [...notes, 'Nothing was opened or written.'] };

  // the app pull request: one commit on the default head pipegen read the files at (never onto a moved head), pipegen's own branch moved there
  let prUrl: string | undefined;
  if (appChanges.length > 0) {
    const c = await commitFiles(gh, app, { parent: appSt.head, baseTree: appSt.tree, files: appChanges.map((x) => ({ path: x.path, content: x.after, mode: x.mode })), message: `pipegen: update the gate to v${gate.version}` }, clock);
    await setBranch(gh, app, UPDATE_BRANCH, c.commit, true, clock);
    const pr = await openOrUpdatePr(gh, app, { head: UPDATE_BRANCH, base: appSt.defaultBranch, title: `pipegen: update the gate to v${gate.version}`, body: appPrBody(plan) }, clock);
    prUrl = pr.url;
  }
  // the record (and the central files, in the same central pull request commit): every blob sha written appended, through writeRecord
  const next = recordAfter(record, [...central, ...appChanges], plan.repin);
  let written;
  try {
    written = await writeRecord(gh, {
    record: next, setupPr, via: central.length > 0 ? 'pr' : 'direct',
    ...(central.length > 0 ? { files: central.map((x) => ({ path: x.path, content: x.after })), base: centralSt.head, pr: { title: `pipegen: update the gate of ${record.name} to v${gate.version}`, body: centralPrBody(plan) } } : {}),
    clock, ...(deps.now === undefined ? {} : { now: deps.now }), ...(deps.local === undefined ? {} : { local: deps.local }),
    });
  } catch (e) {
    // Spec M3: the app pull request is open; say so, and that the record was not written (its sha is missing: the safe side for uninstall)
    if (prUrl === undefined) throw e;
    const why = show(e instanceof DeliverError || e instanceof RecordError || e instanceof UpdateError ? e.message : 'GitHub refused or did not answer', 300);
    // G12-R2 N3: the note says exactly how far the record got
    const at = recordWriteReached(e);
    const file = localRecordPath(app, deps.local ?? {});
    const note = at?.at === 'local'
      ? `The pull request ${prUrl} is open and the install record is written (central repo and this machine), but the setup pull request's record marker was not updated (${why}); \`pipegen verify\` reports that until pipegen writes the record again.`
      : at?.at === 'central' && at.via === 'direct'
        // G12-R3 M2: the central default branch holds the new record and this machine's file the old hash: they no longer match
        ? `The pull request ${prUrl} is open and the install record is written on the central default branch, but this machine's local record file was not updated (${why}), so the two no longer match. Remove ${show(file, 300)}, then run \`npx pipegen\` in this repo (it re-checks the setup and writes a record this machine vouches for); then run update again.`
        : at?.at === 'central'
          ? `The pull request ${prUrl} is open and the install record went to the central pull request, but this machine's local record file was not updated (${why}). The record this machine trusts is unchanged, so run \`pipegen update\` again: it rebuilds the central pull request.`
          : `The pull request ${prUrl} is open, but the install record was not written (${why}); run \`pipegen update\` again to record it.`;
    return { done: true, ...base, notes: [...notes, note], prUrl };
  }
  return { done: true, ...base, notes: [...notes, ...written.notes], ...(prUrl === undefined ? {} : { prUrl }), ...(written.centralPr === undefined ? {} : { centralPrUrl: written.centralPr.url }), recordHash: written.recordHash };
}
