// v0.2 Plan V, Task V2: the revert engine (rulings V-B1 edit forms, V-B6, V-S7, V-S8, V-N3, V-N11, V-N12; plan m6). It decides which bytes
// the uninstall PR takes out of a file pipegen edited but didn't write whole. Pure: the caller passes the current text and sha and a blob
// reader; nothing here calls GitHub. It never forces anything: what it can't prove is pipegen's comes back as `manual`, with the exact text
// to take out by hand where pipegen knows it.
//
// - Unchanged (the current sha is the last one pipegen wrote, not ownerEdited): the original blob back, byte for byte, but only after the
//   current text is shown to be that original plus pipegen's part (a record whose originalSha names another blob restores nothing).
//   A new file (originalSha null) unchanged is deleted; changed, it is manual.
// - codeowners / hooks / dependabot changed since: pipegen's `inserted` text is removed only when it is in pipegen's builder form, occurs
//   exactly once, and starts a line (or, beginning with its own newline, ends the file: removing it then joins no two of the owner's lines).
// - verify-job changed since: a structural strip on the record form with the YAML Document API, cutting bytes by node ranges (the owner's
//   comments and spacing stay): the `pipegen-verify` job (byte-equal to the job in the last version pipegen wrote), each recorded needs entry
//   in the form pipegen added it, the first step of each recorded `headCheck` job when it is pipegen's rendered head check exactly. Then the
//   result must parse to exactly the current file without those parts, and name neither `pipegen-verify` nor pipegen's head check.
// - package.json + package-lock.json: a pair (m6). Both restored when both are unchanged, else both manual. Never one alone.
// referee.ts judgeEdited is not reused (V-S7: it is private, needs the original, and src/engine is G15a's); carry to G17: dedupe if wanted.
import { isDeepStrictEqual } from 'node:util';
import { Document, isAlias, isMap, isScalar, isSeq, parseDocument, visit, type Node as YamlNode, type Pair, type YAMLMap, type YAMLSeq } from 'yaml';
import { gitBlobSha } from '../create/guard.js';
import { editOf } from '../create/package-edit.js';
import { CODEOWNERS_BEGIN, CODEOWNERS_END, dependabotEntryText, HOOK_FILES, HOOKS_MARKER, hookBlock, type HookCommand, type HookManager } from '../engine/created-builders.js';
import { HEAD_CHECK_STEP_ID, renderHeadCheckStep } from '../engine/deploy-steps.js';
import { stepsToYaml } from '../engine/render-step.js';
import { VERIFY_JOB_ID } from '../layers/assemble.js';
import type { InstallEdit, PipelineDraft } from '../types.js';
import { safeText } from '../util/safe-text.js';

/**
 * What to do with one edited file. `restore`: write `text` (the original blob, byte-exact). `delete`: pipegen made the file and it is
 * unchanged. `strip`: write `text` (the current file with pipegen's part taken out). `manual`: change nothing; `why` says what to review and
 * `remove`, when present, is the exact text pipegen added, to take out by hand.
 */
export type RevertResult =
  | { kind: 'restore'; text: string }
  | { kind: 'delete' }
  | { kind: 'strip'; text: string }
  | { kind: 'manual'; why: string; remove?: string };
/** The file as it is now on the default branch: its text and git blob sha. */
export interface CurrentFile { text: string; sha: string }
/** A git blob by sha (the original pipegen recorded, a version pipegen wrote), or null when it can't be read. Its text must hash to the sha. */
export type BlobReader = (sha: string) => string | null;
/** What the verify-job strip needs besides the texts: the app's default branch, which pipegen's head check names. */
export interface RevertContext { defaultBranch?: string }

type TextEdit = Extract<InstallEdit, { kind: 'codeowners' | 'hooks' | 'dependabot' }>;
type VerifyEdit = Extract<InstallEdit, { kind: 'verify-job' }>;
type JsonEdit = Extract<InstallEdit, { kind: 'package-json' }>;
type LockEdit = Extract<InstallEdit, { kind: 'package-lock' }>;
type Obj = Record<string, unknown>;

const show = (s: string): string => JSON.stringify(safeText(String(s), 200));
const manual = (why: string, remove?: string): RevertResult => (remove === undefined ? { kind: 'manual', why } : { kind: 'manual', why, remove });
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
/** The blob of `sha`, only when the reader gives one that hashes to it. */
function readBlob(blob: BlobReader, sha: string | null | undefined): string | null {
  if (typeof sha !== 'string') return null;
  let t: string | null;
  try { t = blob(sha); } catch { return null; }
  return typeof t === 'string' && gitBlobSha(t) === sha ? t : null;
}
/** Unchanged: the current sha is the last one pipegen wrote, and update never merged the owner's edits into it. */
const unchanged = (e: InstallEdit, current: CurrentFile): boolean => e.ownerEdited !== true && e.writtenShas.length > 0 && current.sha === e.writtenShas[e.writtenShas.length - 1];
const OWNER_EDITED = (path: string): string => `${show(path)}: \`pipegen update\` merged its change into the owner's edits, so the file is the owner's now; review pipegen's part by hand.`;

/**
 * The revert of one edit (not a package.json that has a lock in the record, nor a lock: those go through revertPair). `current` is the file
 * on the default branch now; `blob` reads the original and the versions pipegen wrote; `ctx.defaultBranch` is needed for a head check.
 */
export function revertEdit(e: InstallEdit, current: CurrentFile, blob: BlobReader, ctx: RevertContext = {}): RevertResult {
  if (e.kind === 'package-lock') return manual(`${show(e.path)} is reverted only together with its package.json (${show(e.json)}), never alone.`);
  if (e.kind === 'package-json') {
    if (e.lock !== undefined) return manual(`${show(e.path)} is reverted only together with its lock file (${show(e.lock)}), never alone.`);
    return revertPair({ edit: e, current }, null, blob).json;
  }
  if (e.ownerEdited === true) return manual(OWNER_EDITED(e.path), e.kind === 'verify-job' ? undefined : e.inserted);
  if (gitBlobSha(current.text) !== current.sha) return manual(`${show(e.path)}: the text read is not the blob of its sha, so pipegen changes nothing there.`);
  return e.kind === 'verify-job' ? revertVerify(e, current, blob, ctx) : revertText(e, current, blob);
}

// ---------- codeowners, hooks, dependabot ----------

const WHAT: Readonly<Record<TextEdit['kind'], string>> = { codeowners: 'a CODEOWNERS block', hooks: "a hooks block", dependabot: 'a Dependabot entry' };

function revertText(e: TextEdit, current: CurrentFile, blob: BlobReader): RevertResult {
  const where = show(e.path);
  const form = textFormProblem(e);
  // not pipegen's builder form: nothing proves the text is pipegen's, so it is neither removed nor offered as the text to remove
  if (form !== null) return manual(`${where}: the recorded text is not ${WHAT[e.kind]} as pipegen writes it (${form}), so pipegen removes nothing there; review the file by hand.`);
  const same = unchanged(e, current);
  if (e.originalSha === null) {
    if (same && current.text === e.inserted) return { kind: 'delete' };
    return manual(`${where} is a file pipegen created and it has changed since; delete it, or take pipegen's part out by hand.`, e.inserted);
  }
  if (same) {
    const original = readBlob(blob, e.originalSha);
    if (original !== null && current.text === original + e.inserted) return { kind: 'restore', text: original };
  }
  const s = stripOnce(current.text, e.inserted);
  if (typeof s === 'string') return { kind: 'strip', text: s };
  return manual(`${where}: ${s.why}; take pipegen's text out by hand.`, e.inserted);
}

/** `text` without `ins`, when `ins` occurs exactly once and starts a line (or starts with its own newline and ends the text). */
function stripOnce(text: string, ins: string): string | { why: string } {
  const i = ins === '' ? -1 : text.indexOf(ins);
  if (i < 0) return { why: "pipegen's text is no longer in the file as pipegen wrote it" };
  if (text.indexOf(ins, i + 1) >= 0) return { why: "pipegen's text is in the file more than once" };
  const lineStart = i === 0 || text[i - 1] === '\n';
  // an insert that starts with its own newline (the original had no newline at its end) comes out mid-line only at the end of the file:
  // anywhere else removing it would join the owner's line before it with the owner's text after it
  if (!lineStart && !(ins.startsWith('\n') && i + ins.length === text.length)) return { why: "pipegen's text no longer starts a line" };
  return text.slice(0, i) + text.slice(i + ins.length);
}

/** Why the recorded `inserted` is not what pipegen's builder writes for its kind and path, or null. */
function textFormProblem(e: TextEdit): string | null {
  const ins = e.inserted;
  if (typeof ins !== 'string' || ins === '' || !ins.endsWith('\n') || ins.includes('\r')) return 'not whole lines';
  if (e.kind === 'codeowners') {
    if (!['CODEOWNERS', 'docs/CODEOWNERS', '.github/CODEOWNERS'].includes(e.path)) return 'not a CODEOWNERS path';
    const sep = /^\n{0,2}/.exec(ins)?.[0] ?? '';
    if (e.originalSha === null && sep !== '') return 'a new file starts with the block';
    const lines = ins.slice(sep.length).split('\n');
    lines.pop();   // the empty piece after the last newline
    const inner = lines.slice(1, -1);
    if (lines[0] !== CODEOWNERS_BEGIN || lines[lines.length - 1] !== CODEOWNERS_END || inner.length === 0) return 'not between the gate markers';
    if (inner.some((l) => l.trim() === '' || l.startsWith('#') || l.includes(CODEOWNERS_BEGIN) || l.includes(CODEOWNERS_END))) return 'not rules only between the markers';
    return null;
  }
  if (e.repo !== 'app') return 'not in the app repository';
  if (e.kind === 'hooks') return hooksFormProblem(e.path, ins, e.originalSha === null);
  return dependabotFormProblem(e.path, ins, e.originalSha === null);
}

/** The husky shebang hookFile writes at the top of a new script (created-builders.ts HUSKY_SHEBANG, not exported). */
const HUSKY_SHEBANG = '#!/usr/bin/env sh\n';
const MANAGERS: readonly HookManager[] = ['pre-commit', 'husky', 'lefthook'];
const parseJson = (s: string | undefined): string | null => { if (s === undefined) return null; try { const v: unknown = JSON.parse(s); return typeof v === 'string' ? v : null; } catch { return null; } };

/** Why `ins` is not hookFile's insert for the hook file at `path` (the block hookBlock writes, after the prefixes hookFile adds), or null. */
function hooksFormProblem(path: string, ins: string, isNew: boolean): string | null {
  const manager = MANAGERS.find((m) => HOOK_FILES[m] === path);
  if (manager === undefined) return 'not a hook file pipegen edits';
  const prefixes = isNew ? [manager === 'husky' ? HUSKY_SHEBANG : manager === 'pre-commit' ? 'repos:\n' : ''] : ['', '\n'];
  for (const pre of prefixes) {
    if (!ins.startsWith(pre)) continue;
    const body = ins.slice(pre.length);
    const indents = manager === 'pre-commit' ? (isNew ? [''] : ['', '  ']) : [''];
    for (const indent of indents) {
      const commands = hookCommandsOf(manager, body, indent);
      if (commands !== null && commands.length > 0 && hookBlock(manager, commands, indent) === body) return null;
    }
  }
  return `not the ${HOOKS_MARKER} block pipegen writes`;
}

/** The commands a hook block names, read loosely (the caller rebuilds the block from them and compares it byte for byte), or null. */
function hookCommandsOf(manager: HookManager, body: string, i: string): HookCommand[] | null {
  const lines = body.split('\n');
  if (manager === 'husky') {
    const runs = lines.slice(1, -2);
    if (runs.some((l) => !l.endsWith(' || exit 1'))) return null;
    return runs.map((l) => { const run = l.slice(0, -' || exit 1'.length); return { id: run, run }; });
  }
  const out: HookCommand[] = [];
  if (manager === 'lefthook') {
    const rest = lines.slice(3, -1);
    if (rest.length % 2 !== 0) return null;
    for (let k = 0; k < rest.length; k += 2) {
      const id = /^ {4}(.+):$/.exec(rest[k] ?? '')?.[1];
      const run = parseJson(/^ {6}run: (.*)$/.exec(rest[k + 1] ?? '')?.[1]);
      if (id === undefined || run === null) return null;
      out.push({ id, run });
    }
    return out;
  }
  const rest = lines.slice(3, -1);
  if (rest.length % 6 !== 0) return null;
  for (let k = 0; k < rest.length; k += 6) {
    const id = parseJson(new RegExp(`^${i} {4}- id: (.*)$`).exec(rest[k] ?? '')?.[1]);
    const run = parseJson(new RegExp(`^${i} {6}entry: (.*)$`).exec(rest[k + 2] ?? '')?.[1]);
    if (id === null || run === null) return null;
    out.push({ id, run });
  }
  return out;
}

/** Why `ins` is not dependabotFile's insert (its one github-actions entry, after the prefixes dependabotFile adds), or null. */
function dependabotFormProblem(path: string, ins: string, isNew: boolean): string | null {
  if (path !== '.github/dependabot.yml' && path !== '.github/dependabot.yaml') return 'not the Dependabot file';
  const prefixes = isNew ? ['version: 2\nupdates:\n'] : ['', '\n', 'updates:\n', '\nupdates:\n'];
  const ignored = /\n {6}- dependency-name: ("[^"\n]*")\n$/.exec(ins)?.[1];
  const repo = parseJson(ignored)?.replace(/\/\*$/, '');
  const entries: string[] = [];
  const draftOf = (d: unknown): PipelineDraft => d as PipelineDraft;
  entries.push(dependabotEntryText(draftOf({ profile: { private: false } })));
  if (repo !== undefined) { try { entries.push(dependabotEntryText(draftOf({ profile: { private: true }, centralPin: { repo } }))); } catch { /* no valid central repo: only the public form */ } }
  return prefixes.some((p) => entries.some((x) => ins === p + x)) ? null : 'not the github-actions entry pipegen writes';
}

// ---------- verify-job ----------

const WORKFLOW_RE = /^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/;

/** Why the record form is not pipegen's insert (only the job `pipegen-verify`, needs entries adding only it), or null (V-B6). */
function verifyFormProblem(e: VerifyEdit): string | null {
  if (!WORKFLOW_RE.test(e.path)) return 'not a workflow file';
  if (e.jobs.length > 1 || e.jobs.some((j) => j !== VERIFY_JOB_ID)) return `a job other than ${VERIFY_JOB_ID}`;
  if (e.needs.some((n) => n.added.length !== 1 || n.added[0] !== VERIFY_JOB_ID || n.job === VERIFY_JOB_ID)) return `a needs entry other than ${VERIFY_JOB_ID}`;
  if (new Set(e.needs.map((n) => n.job)).size !== e.needs.length) return 'a job listed twice';
  const heads = e.headCheck ?? [];
  if (heads.includes(VERIFY_JOB_ID) || new Set(heads).size !== heads.length) return 'a head-check job listed twice or the verify job';
  if (e.jobs.length === 0 && (e.needs.length > 0 || heads.length === 0)) return 'a called workflow holds only head checks';
  return null;
}

function revertVerify(e: VerifyEdit, current: CurrentFile, blob: BlobReader, ctx: RevertContext): RevertResult {
  const where = show(e.path);
  const form = verifyFormProblem(e);
  if (form !== null) return manual(`${where}: the recorded edit is not pipegen's verify-job insert (${form}), so pipegen removes nothing there; review the file by hand.`);
  const original = readBlob(blob, e.originalSha);
  const s = stripVerify(e, current.text, blob, ctx, original);
  if (typeof s !== 'string') return manual(`${where}: ${s.why}. ${byHand(e)}`);
  // unchanged, and the strip reads exactly as the original: the original's own bytes come back
  if (unchanged(e, current) && original !== null && isDeepStrictEqual(jsOf(s), jsOf(original))) return { kind: 'restore', text: original };
  return { kind: 'strip', text: s };
}

/** The manual step for a verify-job edit: what pipegen added, by name. */
function byHand(e: VerifyEdit): string {
  const parts: string[] = [];
  if (e.jobs.length > 0) parts.push(`the ${VERIFY_JOB_ID} job`);
  if (e.needs.length > 0) parts.push(`${VERIFY_JOB_ID} from the needs of ${e.needs.map((n) => show(n.job)).join(', ')}`);
  if ((e.headCheck ?? []).length > 0) parts.push(`the first step ${HEAD_CHECK_STEP_ID} of ${(e.headCheck ?? []).map(show).join(', ')}`);
  return `Take out by hand: ${parts.join('; ')}.`;
}

const jsOf = (text: string): unknown => { try { const d = parseDocument(text, { uniqueKeys: true }); return d.errors.length > 0 ? Symbol('unreadable') : d.toJS(); } catch { return Symbol('unreadable'); } };
const lineStartOf = (text: string, at: number): number => text.lastIndexOf('\n', at - 1) + 1;
/** The end of the line holding `at`, after its newline (or the end of the text). */
const lineEndOf = (text: string, at: number): number => { const n = text.indexOf('\n', at); return n < 0 ? text.length : n + 1; };
const spacesBefore = (text: string, at: number): number | null => { const from = lineStartOf(text, at); return /^ *$/.test(text.slice(from, at)) ? at - from : null; };
const pairOf = (map: YAMLMap, key: string): Pair<YamlNode, YamlNode> | undefined => (map.items as Pair<YamlNode, YamlNode>[]).find((p) => isScalar(p.key) && p.key.value === key);
/** Whether a node holds an anchor or an alias anywhere (a touched node with one is manual: a cut could change what an alias reads). */
function hasAnchor(node: unknown): boolean {
  let found = false;
  visit(node as YamlNode, (_k, n) => { if (isAlias(n) || ((n as { anchor?: string }).anchor ?? '') !== '') { found = true; return visit.BREAK; } return undefined; });
  return found;
}
/** One step as pipegen writes it: a block list item at indent 0, no trailing newline (deploy.ts stepItemYaml). */
function stepItemYaml(step: Parameters<typeof stepsToYaml>[0][number]): string {
  const doc = new Document();
  doc.contents = stepsToYaml([step]);
  return doc.toString({ lineWidth: 0 }).replace(/\n+$/, '');
}
const indentLines = (text: string, n: number): string => text.split('\n').map((l) => (l === '' ? l : `${' '.repeat(n)}${l}`)).join('\n');

/** A job's bytes: from the start of its key's line to the end of its value (block maps end after their last line's newline). */
function jobSlice(text: string, p: Pair<YamlNode, YamlNode>): { from: number; to: number } | null {
  const k = p.key?.range?.[0];
  const to = p.value?.range?.[1];
  if (k === undefined || to === undefined || !isMap(p.value) || p.value.flow === true) return null;
  if (spacesBefore(text, k) === null || (to < text.length && text[to - 1] !== '\n')) return null;
  return { from: lineStartOf(text, k), to };
}
/** The block `jobs:` map of a workflow document, or null. */
function jobsOf(doc: Document): YAMLMap | null {
  const jobs = doc.get('jobs', true);
  return isMap(jobs) && jobs.flow !== true ? jobs : null;
}

interface Cut { from: number; to: number; text: string }

/**
 * The current workflow without pipegen's recorded part, or why it can't be taken out exactly. `original` (may be null) chooses the needs form
 * to give back (a plain job name, an empty list, no needs line), as the referee reads it; without it the list form stays (the same jobs).
 */
function stripVerify(e: VerifyEdit, text: string, blob: BlobReader, ctx: RevertContext, original: string | null): string | { why: string } {
  let doc: Document;
  try { doc = parseDocument(text, { uniqueKeys: true }); } catch { return { why: 'it is not YAML pipegen can read' }; }
  if (doc.errors.length > 0 || doc.warnings.length > 0) return { why: 'it is not YAML pipegen can read' };
  const jobs = jobsOf(doc);
  if (jobs === null || (jobs.anchor ?? '') !== '') return { why: 'its jobs are not a block map pipegen can read' };
  const want = doc.toJS() as Obj;
  const wantJobs = isObj(want.jobs) ? want.jobs : {};
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const cuts: Cut[] = [];
  const origJobs: Obj | null = (() => { if (original === null) return null; const js = jsOf(original); return isObj(js) && isObj(js.jobs) ? js.jobs : null; })();

  // the verify job: byte-equal to the job in the version pipegen wrote last
  for (const id of e.jobs) {
    const p = pairOf(jobs, id);
    if (p === undefined) continue;   // the owner removed it: nothing of pipegen's left there
    if (hasAnchor(p)) return { why: `its ${VERIFY_JOB_ID} job holds a YAML anchor or alias` };
    const at = jobSlice(text, p);
    const lastText = readBlob(blob, e.writtenShas[e.writtenShas.length - 1]);
    if (at === null || lastText === null) return { why: `pipegen can't read the ${VERIFY_JOB_ID} job it wrote to compare it` };
    const lastDoc = parseDocument(lastText, { uniqueKeys: true });
    const lastJobs = lastDoc.errors.length > 0 ? null : jobsOf(lastDoc);
    const lp = lastJobs === null ? undefined : pairOf(lastJobs, id);
    const lat = lp === undefined ? null : jobSlice(lastText, lp);
    if (lat === null || text.slice(at.from, at.to) !== lastText.slice(lat.from, lat.to)) return { why: `its ${VERIFY_JOB_ID} job is not the one pipegen wrote (it was changed)` };
    cuts.push({ from: at.from, to: at.to, text: '' });
    delete wantJobs[id];
  }

  // the needs entries, in the form pipegen added each
  for (const n of e.needs) {
    const p = pairOf(jobs, n.job);
    if (p === undefined || !isMap(p.value)) continue;
    const np = pairOf(p.value, 'needs');
    const v = np?.value;
    if (np === undefined || !isSeq(v)) continue;   // no list: pipegen's entry is not there (a leftover name is caught below)
    const items = v.items as YamlNode[];
    const idx = items.findIndex((x) => isScalar(x) && x.value === VERIFY_JOB_ID);
    if (idx < 0) continue;
    if (hasAnchor(p)) return { why: `its job ${show(n.job)} holds a YAML anchor or alias` };
    const item = items[idx] as YamlNode;
    const wj = wantJobs[n.job] as Obj;
    const rest = (wj.needs as unknown[]).filter((_x, k) => k !== idx);
    if (!isScalar(item) || item.type !== 'PLAIN' || item.range === undefined || item.range === null || v.range === undefined || v.range === null) return { why: `the ${VERIFY_JOB_ID} need of ${show(n.job)} is not written as pipegen wrote it` };
    const before = origJobs !== null && isObj(origJobs[n.job]) ? (origJobs[n.job] as Obj).needs : undefined;
    const origKnown = origJobs !== null && isObj(origJobs[n.job]);
    if (v.flow === true) {
      const [r0, r1] = v.range;
      const flow = text.slice(r0, r1);
      if (idx !== items.length - 1) return { why: `the ${VERIFY_JOB_ID} need of ${show(n.job)} is not last in its list, where pipegen put it` };
      if (items.length === 1) {
        if (flow !== `[${VERIFY_JOB_ID}]`) return { why: `the needs of ${show(n.job)} are not written as pipegen wrote them` };
        const ls = lineStartOf(text, np.key?.range?.[0] ?? r0);
        const le = lineEndOf(text, r1);
        const wholeLine = new RegExp(`^ *needs: \\[${VERIFY_JOB_ID}\\]${eol === '\r\n' ? '\\r\\n' : '\\n'}$`).test(text.slice(ls, le));
        if (wholeLine && (!origKnown || before === undefined)) { cuts.push({ from: ls, to: le, text: '' }); delete wj.needs; }
        else { cuts.push({ from: r0, to: r1, text: '[]' }); wj.needs = []; }
      } else {
        const prev = items[idx - 1] as YamlNode;
        const pe = prev.range?.[1];
        if (pe === undefined || text.slice(pe, item.range[1]) !== `, ${VERIFY_JOB_ID}`) return { why: `the ${VERIFY_JOB_ID} need of ${show(n.job)} is not written as pipegen wrote it` };
        const only = rest.length === 1 ? rest[0] : undefined;
        if (origKnown && typeof before === 'string' && only === before && isScalar(prev) && prev.type === 'PLAIN' && flow === `[${before}, ${VERIFY_JOB_ID}]`) { cuts.push({ from: r0, to: r1, text: before }); wj.needs = before; }
        else { cuts.push({ from: pe, to: item.range[1], text: '' }); wj.needs = rest; }
      }
    } else {
      if (items.length === 1) return { why: `${show(n.job)} would be left with an empty needs list` };
      const dash = text.lastIndexOf('-', item.range[0] - 1);
      const col = dash < 0 ? null : spacesBefore(text, dash);
      const ls = lineStartOf(text, item.range[0]);
      const le = lineEndOf(text, item.range[0]);
      if (col === null || text.slice(ls, le) !== `${' '.repeat(col)}- ${VERIFY_JOB_ID}${eol}`) return { why: `the ${VERIFY_JOB_ID} need of ${show(n.job)} is not on its own line as pipegen wrote it` };
      cuts.push({ from: ls, to: le, text: '' });
      wj.needs = rest;
    }
  }

  // the head checks: the first step of each recorded job, only when it is pipegen's step for this default branch, byte for byte
  const heads = e.headCheck ?? [];
  if (heads.length > 0) {
    if (typeof ctx.defaultBranch !== 'string' || ctx.defaultBranch === '') return { why: "pipegen needs the default branch to recognise its head check" };
    let headText: string;
    let headJs: unknown;
    try {
      const step = renderHeadCheckStep(ctx.defaultBranch);
      headText = stepItemYaml(step);
      headJs = (parseDocument(headText).toJS() as unknown[])[0];
    } catch { return { why: "pipegen can't render its head check for this default branch" }; }
    for (const id of heads) {
      const p = pairOf(jobs, id);
      if (p === undefined) continue;   // the owner removed the job
      if (!isMap(p.value)) return { why: `its job ${show(id)} is not a block map` };
      if (hasAnchor(p)) return { why: `its job ${show(id)} holds a YAML anchor or alias` };
      const sv = pairOf(p.value, 'steps')?.value;
      const items = isSeq(sv) && sv.flow !== true ? (sv as YAMLSeq).items as YamlNode[] : [];
      const wsteps = (wantJobs[id] as Obj).steps;
      if (items.length < 2 || !Array.isArray(wsteps)) return { why: `the job ${show(id)} has no step of the owner's after pipegen's head check` };
      if (!isDeepStrictEqual(wsteps[0], headJs)) return { why: `the job ${show(id)} doesn't start with pipegen's head check as pipegen writes it` };
      const i0 = items[0]?.range?.[0];
      const i1 = items[1]?.range?.[0];
      const d0 = i0 === undefined ? -1 : text.lastIndexOf('-', i0 - 1);
      const d1 = i1 === undefined ? -1 : text.lastIndexOf('-', i1 - 1);
      const col = d0 < 0 ? null : spacesBefore(text, d0);
      if (col === null || d1 < 0 || spacesBefore(text, d1) !== col) return { why: `the steps of ${show(id)} are not a list pipegen can cut` };
      const from = lineStartOf(text, d0);
      const to = lineStartOf(text, d1);
      if (text.slice(from, to) !== `${indentLines(headText, col).replace(/\n/g, eol)}${eol}`) return { why: `the job ${show(id)} doesn't start with pipegen's head check as pipegen writes it` };
      cuts.push({ from, to, text: '' });
      wsteps.shift();
    }
  }

  cuts.sort((a, b) => a.from - b.from);
  for (let k = 1; k < cuts.length; k++) if ((cuts[k] as Cut).from < (cuts[k - 1] as Cut).to) return { why: "pipegen's parts overlap in the file" };
  let out = text;
  for (const c of [...cuts].reverse()) out = out.slice(0, c.from) + c.text + out.slice(c.to);
  // the result is exactly the current file without pipegen's parts, and nothing of pipegen's is left (V-N11: a head check the record lacks)
  if (!isDeepStrictEqual(jsOf(out), want)) return { why: "taking pipegen's part out would change more of the file" };
  if (out.includes(VERIFY_JOB_ID)) return { why: `the file still names ${VERIFY_JOB_ID} besides what pipegen recorded adding` };
  if (out.includes(HEAD_CHECK_STEP_ID)) return { why: `the file still holds pipegen's head check (${HEAD_CHECK_STEP_ID}) in a job the record doesn't list` };
  return out;
}

// ---------- package.json + package-lock.json (m6) ----------

/**
 * The package.json edit and its lock edit, reverted together or not at all (m6, V-S8): both restored from their original blobs only when
 * both are unchanged (each current sha the last pipegen wrote), the package.json reads as the recorded edit, and both originals can be read.
 * Anything else: both manual. `lock` is null only for a package.json whose record names no lock. `current: null` = the file is gone.
 */
export function revertPair(json: { edit: JsonEdit; current: CurrentFile | null }, lock: { edit: LockEdit; current: CurrentFile | null } | null, blob: BlobReader): { json: RevertResult; lock: RevertResult | null } {
  const pj = json.edit;
  const both = (why: string): { json: RevertResult; lock: RevertResult | null } => {
    const pair = lock === null ? `${show(pj.path)}` : `${show(pj.path)} and ${show(lock.edit.path)}`;
    const m = manual(`${pair} go back together or not at all: ${why}. Review pipegen's change to both by hand.`);
    return { json: m, lock: lock === null ? null : m };
  };
  if (pj.lock !== undefined && lock === null) return both(`the record pairs it with ${show(pj.lock)}, which was not given`);
  if (pj.lock === undefined && lock !== null) return both('the record names no lock file for it');
  if (lock !== null && (pj.lock !== lock.edit.path || lock.edit.json !== pj.path)) return both('the two edits are not each other\'s pair in the record');
  if (pj.ownerEdited === true || lock?.edit.ownerEdited === true) return both('`pipegen update` merged a change into the owner\'s edits');
  const restoreOf = (e: JsonEdit | LockEdit, c: CurrentFile | null): string | { why: string } => {
    if (c === null) return { why: `${show(e.path)} is no longer there` };
    if (gitBlobSha(c.text) !== c.sha) return { why: `the text read for ${show(e.path)} is not the blob of its sha` };
    if (!unchanged(e, c)) return { why: `${show(e.path)} changed since pipegen wrote it` };
    const o = readBlob(blob, e.originalSha);
    return o === null ? { why: `pipegen can't read the original ${show(e.path)}` } : o;
  };
  const jo = restoreOf(pj, json.current);
  if (typeof jo !== 'string') return both(jo.why);
  // the package.json reads as the recorded edit of its original (the same devDependencies added, the same test-script change)
  let readsAsRecorded = false;
  try {
    const before: unknown = JSON.parse(jo);
    const after: unknown = JSON.parse((json.current as CurrentFile).text);
    if (isObj(before) && isObj(after)) { const d = editOf(before, after); readsAsRecorded = isDeepStrictEqual({ ...d.add }, { ...pj.add }) && d.setTest === pj.setTest; }
  } catch { readsAsRecorded = false; }
  if (!readsAsRecorded) return both(`${show(pj.path)} doesn't read as the original with pipegen's recorded change`);
  if (lock === null) return { json: { kind: 'restore', text: jo }, lock: null };
  const lo = restoreOf(lock.edit, lock.current);
  if (typeof lo !== 'string') return both(lo.why);
  return { json: { kind: 'restore', text: jo }, lock: { kind: 'restore', text: lo } };
}

/**
 * Every edit of a record reverted, in the record's order, pairs together: a package.json and the lock the record pairs it with are judged
 * as one (revertPair). `read` gives the current file of an edit (null: it is gone). A gone file is manual: nothing is forced.
 */
export function revertEdits(edits: readonly InstallEdit[], read: (e: InstallEdit) => CurrentFile | null, blob: BlobReader, ctx: RevertContext = {}): { edit: InstallEdit; result: RevertResult }[] {
  const pairs = new Map<InstallEdit, RevertResult>();
  for (const e of edits) {
    if (e.kind !== 'package-json') continue;
    const lk = e.lock === undefined ? undefined : edits.find((x): x is LockEdit => x.kind === 'package-lock' && x.repo === e.repo && x.path === e.lock);
    const r = revertPair({ edit: e, current: read(e) }, lk === undefined ? null : { edit: lk, current: read(lk) }, blob);
    pairs.set(e, r.json);
    if (lk !== undefined && r.lock !== null) pairs.set(lk, r.lock);
  }
  return edits.map((e) => {
    const paired = pairs.get(e);
    if (paired !== undefined) return { edit: e, result: paired };
    if (e.kind === 'package-lock') return { edit: e, result: manual(`${show(e.path)} has no package.json edit in the record to go back with, so pipegen leaves it; review it by hand.`) };
    const c = read(e);
    if (c === null) return { edit: e, result: manual(`${show(e.path)} is no longer there; nothing of pipegen's is left to take out, but check it was not moved.`) };
    return { edit: e, result: revertEdit(e, c, blob, ctx) };
  });
}
