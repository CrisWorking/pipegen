// Coverage mapper (see ../coverage.ts for the rules): DECISIONS #122 credit 3 (J3b), the deploy gate the repo already
// has. The property: every deploying job runs only after CI passed, on the default branch, for the exact commit CI
// tested, from this repo (never a fork's run). Ruling B3 and pre-flight §4 item 2 (a)-(h) are the rule text; a false
// "covered" is the worst error pipegen can make (U23), so anything outside the two accepted forms stays missing.
//
// Form (a), a `workflow_run` deploy file:
// - its only trigger is `workflow_run` (f), naming exactly one workflow by its `name:` (no pattern), and exactly one
//   workflow of the repo has that name (letter case ignored, so two that differ only in case are two; never a path); it is not this
//   file, runs on a push that takes the default branch (fitOf's pushDefault) and runs at least one check that blocks
//   (a run pipegen recognises, reason null) (d);
// - every job of the file (a stray one too) has, on its needs chain (the job and every job it needs, transitively), the
//   three guards as top-level `&&` terms of some job-level `if:`: `github.event.workflow_run.conclusion == 'success'`,
//   `github.event.workflow_run.event == 'push'` and `github.event.workflow_run.head_repository.full_name ==
//   github.repository` (or this repo's own `owner/name`) (g). GitHub skips a job whose needed job was skipped, so a
//   guard on the root job guards the chain, but only when no job's `if:` on it uses a status function other than a
//   plain `success()` term, `||` or a lone `!` (a `!=` comparison only narrows, fix round 1), and none has job-level
//   continue-on-error (a). An `if:` pipegen can't
//   parse to the end is none of these;
// - for every deploying job (jobDeploys or a deploy/release/publish name; every job when none is), the tested commit is
//   tied to what deploys, in one of two ways (b, c):
//   - a commit check step on the chain: a `run:` step with no `if:` and no continue-on-error, in a job that every other
//     job of the chain needs, after nothing but checkout steps in that job, that compares the run's own commit
//     (`$GITHUB_SHA`, `${{ github.sha }}`, or `$(git rev-parse HEAD)` after exactly one plain checkout) with
//     `github.event.workflow_run.head_sha` (inline, or an env var set to exactly that expression, the step's env over
//     the job's over the workflow's) and stops on a mismatch (`exit <non-zero>` or the shell's -e); every later step of
//     that job has no status function in its `if:`; the shell is the default bash/sh (never on Windows), `bash` or
//     `sh`; nothing sets GITHUB_SHA. Every checkout on the chain takes no `ref`, `github.sha` or the head_sha;
//   - or the ref form: `workflow_run.branches` is exactly `[<default>]` (no branches-ignore) and every checkout on the
//     chain (at least one) has `ref:` exactly `${{ github.event.workflow_run.head_sha }}`;
// - no job of the file is a reusable call (e): what it builds or deploys can't be seen; no checkout names another
//   repository.
// Form (b), a deploy job inside the CI workflow: triggers only `push` (taking the default branch) and `pull_request`;
// at least one deploying job and at least one other (CI) job, the CI jobs running a check that blocks; every deploying
// job needs every CI job (transitively), is not a reusable call, and runs only on a push to the default branch: the
// push trigger has `branches:` exactly `[<default>]` and no tag filter (fix round 1, S-b: an `if:` comparison ignores
// letter case, so it never proves the branch), and with `pull_request` too a `github.ref == 'refs/heads/<default>'`
// or `github.event_name == 'push'` term on its chain keeps it off pull-request runs. A `!=` term anywhere only narrows
// (fix round 1, I1). The chain's `if:`s and continue-on-error as in form (a); every checkout on the chain
// takes no `ref` or `github.sha`, and no other repository.
// Per service (h): the deploy-verify rows are covered only when the repo has a deploying workflow, every workflow with
// `deploys: true` passes, and no listed workflow was unreadable (or past the budget). Under a rate stop only the widest
// world may credit, so the two worlds differ and the audit says unknown (as J3a's push credit).
//
// Hostile input: the workflow files are attacker-controlled. Expressions are read by a small tokenizer (no regex over
// the whole text, at most MAX_EXPR characters) and a recursive-descent parser with a depth bound; shell text only by
// line, each line at most MAX_LINE characters and matched by anchored, linear patterns; jobs are capped at MAX_GATE_JOBS.
// Nothing from the files is printed: the evidence names only workflow paths (already checked against safeText by the
// mapper) and the default branch through safeText.
import { regexSafe } from '../../read/limits.js';
import { asObj } from '../../read/manifest.js';
import { JOB_ID_RE, MAX_WORKFLOWS, WORKFLOW_FILE, jobDeploys, namesDeploy } from '../../read/workflows.js';
import type { RepoProfile } from '../../types.js';
import { safeText } from '../../util/safe-text.js';
import { nonZeroExit } from './settings.js';
import { fitOf, parseOn, type BranchGuess } from './triggers.js';
import type { Ctx, Hit, Obj } from './types.js';

const MAX_GATE_JOBS = 100;
const MAX_EXPR = 2_000;
const MAX_DEPTH = 20;
const MAX_LINE = 1_000;
const MAX_LINES = 200;

/** A listed workflow and its parsed file; `doc` null when it couldn't be read. */
export interface GateWorkflow { path: string; doc: Obj | null }

// ---------- expressions ----------

type Operand = { path: string } | { lit: string };
type Term = { kind: 'success' } | { kind: 'eq'; a: Operand; b: Operand } | { kind: 'other' };
type Tok = { t: 'id'; v: string } | { t: 'str'; v: string } | { t: 'num'; v: string } | { t: 'op'; v: '&&' | '==' | '!=' | '(' | ')' };
type Node = { n: 'and'; parts: Node[] } | { n: 'eq'; a: Node; b: Node } | { n: 'ne'; a: Node; b: Node } | { n: 'success' } | { n: 'path'; v: string } | { n: 'lit'; v: string } | { n: 'group'; e: Node };

/** Tokens of a GitHub expression, or null for anything outside this small grammar (a lone `!`, `||`, `<`, `[`, `,`, a double quote …). */
function tokens(s: string): Tok[] | null {
  const out: Tok[] = [];
  let i = 0;
  while (i < s.length) {
    const c = s[i] as string;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
    if (c === "'") {
      let v = '';
      i++;
      for (;;) {
        if (i >= s.length) return null;
        if (s[i] === "'") {
          if (s[i + 1] === "'") { v += "'"; i += 2; continue; }
          i++;
          break;
        }
        v += s[i];
        i++;
      }
      out.push({ t: 'str', v });
      continue;
    }
    if (s.startsWith('&&', i)) { out.push({ t: 'op', v: '&&' }); i += 2; continue; }
    if (s.startsWith('==', i)) { out.push({ t: 'op', v: '==' }); i += 2; continue; }
    // fix round 1 (review I1): `!=` is a comparison; a lone `!` (negation) stays outside the grammar
    if (s.startsWith('!=', i)) { out.push({ t: 'op', v: '!=' }); i += 2; continue; }
    if (c === '(' || c === ')') { out.push({ t: 'op', v: c }); i++; continue; }
    const id = /^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*/.exec(s.slice(i, i + 300));
    if (id !== null) { out.push({ t: 'id', v: id[0] }); i += id[0].length; continue; }
    const num = /^[0-9]{1,15}/.exec(s.slice(i, i + 16));
    if (num !== null) { out.push({ t: 'num', v: num[0] }); i += num[0].length; continue; }
    return null;
  }
  return out;
}

/** and := eq ('&&' eq)* ; eq := primary (('==' | '!=') primary)? ; primary := '(' and ')' | success() | path | literal. */
function parse(toks: readonly Tok[]): Node | null {
  let i = 0;
  const peek = () => toks[i];
  const isOp = (v: string) => { const t = peek(); return t !== undefined && t.t === 'op' && t.v === v; };
  const primary = (depth: number): Node | null => {
    const t = peek();
    if (t === undefined || depth > MAX_DEPTH) return null;
    if (t.t === 'op' && t.v === '(') {
      i++;
      const e = and(depth + 1);
      if (e === null || !isOp(')')) return null;
      i++;
      return { n: 'group', e };
    }
    if (t.t === 'id') {
      i++;
      if (isOp('(')) {
        // the one function allowed: a plain success() (every other function, status or not, ends the parse)
        if (t.v.toLowerCase() !== 'success') return null;
        i++;
        if (!isOp(')')) return null;
        i++;
        return { n: 'success' };
      }
      const low = t.v.toLowerCase();
      return low === 'true' || low === 'false' || low === 'null' ? { n: 'lit', v: low } : { n: 'path', v: low };
    }
    if (t.t === 'str' || t.t === 'num') {
      i++;
      return { n: 'lit', v: t.v };
    }
    return null;
  };
  const eq = (depth: number): Node | null => {
    const a = primary(depth);
    if (a === null) return null;
    const ne = isOp('!=');
    if (!isOp('==') && !ne) return a;
    i++;
    const b = primary(depth);
    if (b === null || isOp('==') || isOp('!=')) return null;
    return ne ? { n: 'ne', a, b } : { n: 'eq', a, b };
  };
  const and = (depth: number): Node | null => {
    const parts: Node[] = [];
    for (;;) {
      const e = eq(depth);
      if (e === null) return null;
      parts.push(e);
      if (!isOp('&&')) break;
      i++;
    }
    return parts.length === 1 ? parts[0] as Node : { n: 'and', parts };
  };
  const e = and(0);
  return e !== null && i === toks.length ? e : null;
}

/** The top-level `&&` terms (a group that is itself a conjunction is flattened); success() inside an `==` ends it. */
function termsOf(node: Node, out: Term[]): boolean {
  if (node.n === 'and') return node.parts.every((p) => termsOf(p, out));
  if (node.n === 'group') return termsOf(node.e, out);
  if (node.n === 'success') { out.push({ kind: 'success' }); return true; }
  if (node.n === 'eq') {
    if (node.a.n === 'success' || node.b.n === 'success' || hasSuccess(node.a) || hasSuccess(node.b)) return false;
    const op = (x: Node): Operand | null => (x.n === 'path' ? { path: x.v } : x.n === 'lit' ? { lit: x.v } : null);
    const a = op(node.a);
    const b = op(node.b);
    out.push(a !== null && b !== null ? { kind: 'eq', a, b } : { kind: 'other' });
    return true;
  }
  // fix round 1 (review I1): an `a != b` term only narrows the run (no status function in it, so GitHub's implied
  // success() still holds); it is never a guard
  if (node.n === 'ne' && (hasSuccess(node.a) || hasSuccess(node.b))) return false;
  out.push({ kind: 'other' });
  return true;
}
const hasSuccess = (x: Node): boolean => x.n === 'success' || (x.n === 'group' && hasSuccess(x.e)) || (x.n === 'and' && x.parts.some(hasSuccess))
  || ((x.n === 'eq' || x.n === 'ne') && (hasSuccess(x.a) || hasSuccess(x.b)));

/**
 * A job or step `if:` as its top-level `&&` terms: [] when there is none; null when it is anything else than a plain
 * conjunction pipegen reads to the end (a status function other than a top-level success(), `||`, a lone `!`, another
 * function, a second `${{ }}`, a non-string value other than true). A `!=` comparison is a term that never guards.
 */
export function ifTerms(v: unknown): Term[] | null {
  if (v === undefined || v === null || v === true) return [];
  if (typeof v !== 'string' || v.length > MAX_EXPR || !regexSafe(v)) return null;
  let s = v.trim();
  if (s.startsWith('${{') && s.endsWith('}}')) s = s.slice(3, -2);
  if (s.includes('${{') || s.includes('}}')) return null;
  if (s.trim() === '') return [];
  const toks = tokens(s);
  if (toks === null) return null;
  const node = parse(toks);
  if (node === null) return null;
  const out: Term[] = [];
  return termsOf(node, out) ? out : null;
}

type Guard = 'wr-success' | 'wr-push' | 'wr-same-repo' | 'ref-default' | 'push-event';
const isPath = (o: Operand, path: string) => 'path' in o && o.path === path;
const isLit = (o: Operand, v: string) => 'lit' in o && o.lit.toLowerCase() === v.toLowerCase();

function guardOf(t: Term, p: RepoProfile): Guard | null {
  if (t.kind !== 'eq') return null;
  for (const [x, y] of [[t.a, t.b], [t.b, t.a]] as [Operand, Operand][]) {
    if (isPath(x, 'github.event.workflow_run.conclusion') && isLit(y, 'success')) return 'wr-success';
    if (isPath(x, 'github.event.workflow_run.event') && isLit(y, 'push')) return 'wr-push';
    if (isPath(x, 'github.event.workflow_run.head_repository.full_name') && (isPath(y, 'github.repository') || isLit(y, `${p.owner}/${p.repo}`))) return 'wr-same-repo';
    // GitHub's == ignores letter case, so this tells a push from a pull request, never the default branch from a
    // branch named `Main` (fix round 1, security review S-b): form (b) takes the branch from the push trigger's filter
    if (isPath(x, 'github.ref') && p.defaultBranch !== '' && isLit(y, `refs/heads/${p.defaultBranch}`)) return 'ref-default';
    if (isPath(x, 'github.event_name') && isLit(y, 'push')) return 'push-event';
  }
  return null;
}

// ---------- jobs and their needs ----------

interface Job { id: string; job: Obj; needs: string[]; terms: Term[] }

/** The file's jobs with their direct needs and `if:` terms, or null when one can't be read that far. */
function jobsOf(doc: Obj): Map<string, Job> | null {
  const raw = doc.jobs;
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const entries = Object.entries(raw as Obj);
  if (entries.length === 0 || entries.length > MAX_GATE_JOBS) return null;
  const out = new Map<string, Job>();
  for (const [id, j] of entries) {
    if (!regexSafe(id) || !JOB_ID_RE.test(id) || j === null || typeof j !== 'object' || Array.isArray(j)) return null;
    const job = j as Obj;
    const n = job.needs;
    const needs = n === undefined ? [] : typeof n === 'string' ? [n] : Array.isArray(n) && n.every((x) => typeof x === 'string') ? n as string[] : null;
    if (needs === null) return null;
    const terms = ifTerms(job.if);
    if (terms === null) return null;
    // job-level continue-on-error: a failed job counts as passed for the jobs that need it
    if (job['continue-on-error'] !== undefined && job['continue-on-error'] !== false) return null;
    out.set(id, { id, job, needs, terms });
  }
  for (const j of out.values()) if (j.needs.some((x) => !out.has(x))) return null;
  return out;
}

/** `id` and every job it needs, transitively; null on a cycle. */
function chainOf(jobs: ReadonlyMap<string, Job>, id: string): Set<string> | null {
  const seen = new Set<string>();
  const onPath = new Set<string>();
  const visit = (x: string): boolean => {
    if (onPath.has(x)) return false;
    if (seen.has(x)) return true;
    seen.add(x);
    onPath.add(x);
    for (const n of (jobs.get(x) as Job).needs) if (!visit(n)) return false;
    onPath.delete(x);
    return true;
  };
  return visit(id) ? seen : null;
}

const deploysJob = (j: Job) => jobDeploys(j.job) || namesDeploy(j.id) || namesDeploy(j.job.name);
const stepsOf = (j: Job): Obj[] | null => {
  const s = j.job.steps;
  if (!Array.isArray(s) || s.length > 500 || !s.every((x) => x !== null && typeof x === 'object' && !Array.isArray(x))) return null;
  return s as Obj[];
};

// ---------- checkouts ----------

const HEAD_EXPR = /^\$\{\{\s*github\.event\.workflow_run\.head_sha\s*\}\}$/i;
const SHA_EXPR = /^\$\{\{\s*github\.sha\s*\}\}$/i;
const REPO_EXPR = /^\$\{\{\s*github\.repository\s*\}\}$/i;
const isCheckout = (st: Obj) => typeof st.uses === 'string' && regexSafe(st.uses) && /^actions\/checkout@[^\s]{1,100}$/i.test(st.uses.trim());

/** A checkout's ref: 'none' (no ref, or github.sha), 'head' (the tested commit), or null (anything else, another repository). */
function checkoutRef(st: Obj): 'none' | 'head' | null {
  if (st.with === undefined || st.with === null) return 'none';
  if (typeof st.with !== 'object' || Array.isArray(st.with)) return null;
  const w = st.with as Obj;
  const keys = Object.keys(w).map((k) => k.toLowerCase());
  if (keys.filter((k) => k === 'ref').length > 1 || keys.filter((k) => k === 'repository').length > 1) return null;
  const val = (name: string) => Object.entries(w).find(([k]) => k.toLowerCase() === name)?.[1];
  const repo = val('repository');
  if (repo !== undefined && !(typeof repo === 'string' && REPO_EXPR.test(repo))) return null;
  const ref = val('ref');
  if (ref === undefined || (typeof ref === 'string' && SHA_EXPR.test(ref))) return 'none';
  return typeof ref === 'string' && HEAD_EXPR.test(ref) ? 'head' : null;
}

// ---------- the commit check step ----------

type Side = 'head' | 'current' | 'rev-parse' | null;
const OP = '"[^"\\\\`]*"';
const S1 = new RegExp(`^(?:\\[ (${OP}) ==? (${OP}) \\]|test (${OP}) ==? (${OP})|\\[\\[ (${OP}) ==? (${OP}) \\]\\])(?: \\|\\| (.*))?$`);
const S2 = new RegExp(`^if (?:\\[ (${OP}) != (${OP}) \\]|test (${OP}) != (${OP})|\\[\\[ (${OP}) != (${OP}) \\]\\])$`);
// fix round 1 (security review S-a): no quote character, so an echo line can't open a string that swallows the check
const ECHO = /^echo(?: [^;&|<>()`{}\\'"]*)?$/;
const SET = /^set(?: -[eux]{1,3}| -o (?:errexit|nounset|pipefail|xtrace)| -[eux]{0,3}o (?:errexit|nounset|pipefail|xtrace))*$/;
const exitOf = (s: string) => {
  const m = /^exit ([0-9]{1,3})$/.exec(s);
  return m !== null && nonZeroExit(m[1] as string);
};

/** An env layer: a plain map (or none), else 'unknown' (an expression there could set anything). */
const envLayer = (v: unknown): Obj | 'unknown' | undefined => (v === undefined || v === null ? undefined : typeof v === 'object' && !Array.isArray(v) ? v as Obj : 'unknown');

/**
 * Whether a step is a commit check: see the header. `checkouts` is the checkouts before it in its job; `doc`/`job` give
 * the outer env layers and the shell.
 */
function isCheckStep(st: Obj, job: Obj, doc: Obj, before: readonly Obj[]): boolean {
  if (typeof st.run !== 'string' || st.uses !== undefined || st.if !== undefined) return false;
  if (st['continue-on-error'] !== undefined && st['continue-on-error'] !== false) return false;
  if (!shellStops(st, job, doc)) return false;
  const layers = [envLayer(st.env), envLayer(job.env), envLayer(doc.env)];
  if (layers.includes('unknown')) return false;
  const maps = layers.filter((l): l is Obj => l !== undefined && l !== 'unknown');
  if (maps.some((m) => Object.keys(m).some((k) => k.toUpperCase() === 'GITHUB_SHA'))) return false;
  const envOf = (name: string): unknown => {
    for (const m of maps) if (Object.hasOwn(m, name)) return m[name];
    return undefined;
  };
  // `git rev-parse HEAD` is the run's commit only after exactly one plain checkout and nothing else
  const plainCheckout = before.length === 1 && checkoutRef(before[0] as Obj) === 'none';
  const side = (quoted: string): Side => {
    const s = quoted.slice(1, -1);
    if (s === '$(git rev-parse HEAD)') return plainCheckout ? 'rev-parse' : null;
    const expr = /^\$\{\{([^{}]*)\}\}$/.exec(s);
    if (expr !== null) return HEAD_EXPR.test(s) ? 'head' : SHA_EXPR.test(s) ? 'current' : null;
    const v = /^\$(?:([A-Za-z_][A-Za-z0-9_]{0,63})|\{([A-Za-z_][A-Za-z0-9_]{0,63})\})$/.exec(s);
    if (v === null) return null;
    const name = (v[1] ?? v[2]) as string;
    if (name === 'GITHUB_SHA') return 'current';
    const val = envOf(name);
    return typeof val === 'string' && HEAD_EXPR.test(val) ? 'head' : typeof val === 'string' && SHA_EXPR.test(val) ? 'current' : null;
  };
  const pair = (m: RegExpExecArray): boolean => {
    const ops = [m[1] ?? m[3] ?? m[5], m[2] ?? m[4] ?? m[6]];
    if (ops.some((o) => o === undefined)) return false;
    const sides = ops.map((o) => side(o as string));
    return sides.includes('head') && (sides.includes('current') || sides.includes('rev-parse'));
  };
  if (st.run.length > MAX_LINES * MAX_LINE) return false;
  const lines = lineList(st.run);
  if (lines === null) return false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line === '' || line.startsWith('#') || SET.test(line) || ECHO.test(line)) continue; // the prelude
    const s1 = S1.exec(line);
    if (s1 !== null) {
      const rest = s1[7];
      // relies on the shell's -e, or `|| exit N`, or `|| { echo …; exit N; }`
      return pair(s1) && (rest === undefined || exitOf(rest) || orBlock(rest));
    }
    const s2 = S2.exec(line);
    if (s2 === null || !pair(s2)) return false;
    // `then`, echo lines and an exit, `fi`
    if (lines[i + 1] !== 'then') return false;
    let exits = false;
    for (let k = i + 2; k < lines.length; k++) {
      const b = lines[k] as string;
      if (b === 'fi') return exits;
      if (exitOf(b)) exits = true;
      else if (!ECHO.test(b)) return false;
    }
    return false;
  }
  return false;
}

/** `{ echo …; exit N; }` after `||`. */
function orBlock(s: string): boolean {
  const m = /^\{ (.*); \}$/.exec(s);
  if (m === null) return false;
  const parts = (m[1] as string).split('; ');
  return parts.length >= 1 && exitOf(parts[parts.length - 1] as string) && parts.slice(0, -1).every((x) => ECHO.test(x));
}

/**
 * Fix round 1 (security review S-a): every quote on the line is closed on the same line, and no here-document starts
 * (`<<` outside quotes). A string or here-document left open runs on into the next lines and can swallow the check.
 */
function quotesClosed(line: string): boolean {
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '\\') { i++; continue; }
    if (c === "'") {
      const end = line.indexOf("'", i + 1);
      if (end < 0) return false;
      i = end;
    } else if (c === '"') {
      let k = i + 1;
      while (k < line.length && line[k] !== '"') k += line[k] === '\\' ? 2 : 1;
      if (k >= line.length) return false;
      i = k;
    } else if (c === '`') return false;
    else if (c === '<' && line[i + 1] === '<') return false;
  }
  return true;
}

/**
 * The script's lines, trimmed, spaces collapsed, with `if …; then …; fi` on one line split up; null past the bounds,
 * on a continuation, or when a line (other than a whole-line comment) leaves a quote or a here-document open.
 */
function lineList(run: string): string[] | null {
  const out: string[] = [];
  for (const raw of run.split('\n')) {
    if (raw.length > MAX_LINE || out.length > MAX_LINES) return null;
    const line = raw.trim().replace(/[ \t]+/g, ' ');
    if (line.endsWith('\\')) return null;
    if (!line.startsWith('#') && !quotesClosed(line)) return null;
    if (line.startsWith('if ') && line.includes('; then')) {
      for (const part of line.split(/ ?; ?/)) {
        if (part.startsWith('then ')) out.push('then', part.slice(5));
        else if (part !== '') out.push(part);
      }
    } else out.push(line);
  }
  return out;
}

/** The step stops on a failed command: the default shell off Windows (bash or sh with -e), or `shell: bash` / `shell: sh`. */
function shellStops(st: Obj, job: Obj, doc: Obj): boolean {
  const shell = st.shell ?? asObj(asObj(job.defaults).run).shell ?? asObj(asObj(doc.defaults).run).shell;
  if (shell === 'bash' || shell === 'sh') return true;
  if (shell !== undefined) return false;
  const ro = job['runs-on'];
  const labels = typeof ro === 'string' ? [ro] : Array.isArray(ro) && ro.every((x) => typeof x === 'string') ? ro as string[] : null;
  return labels !== null && labels.length > 0 && labels.every((l) => regexSafe(l) && !l.includes('${{') && !/windows/i.test(l));
}

/** The index of a commit check step in `j`, after nothing but checkouts, with no status function on any later step; or -1. */
function checkIndex(j: Job, doc: Obj): number {
  const steps = stepsOf(j);
  if (steps === null) return -1;
  for (let k = 0; k < steps.length; k++) {
    const st = steps[k] as Obj;
    if (isCheckStep(st, j.job, doc, steps.slice(0, k))) {
      return steps.slice(k + 1).every((x) => ifTerms(x.if) !== null) ? k : -1;
    }
    if (!isCheckout(st)) return -1;
  }
  return -1;
}

// ---------- the two forms ----------

/** Raw trigger names (also those parseOn drops), so another trigger is never missed. */
function triggerNames(on: unknown): string[] | null {
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.every((x) => typeof x === 'string') ? on as string[] : null;
  if (on !== null && typeof on === 'object') return Object.keys(on as Obj);
  return null;
}

// fix round 1 (review M3): an allow-list, so a category added later never counts as a check by itself
const CHECK_CATEGORIES: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'lint', 'format-lint', 'hooks-ci', 'image-scan', 'dast', 'iac',
  'format', 'type-check', 'coverage', 'dead-code', 'duplication', 'dockerfile-lint', 'workflow-lint', 'workflow-pin-check', 'dependency-review', 'licences', 'api-dast', 'fuzzing']);
/** Whether `path` (in one of `jobIds`, when given) runs a check that blocks: a run pipegen recognises, reason null. */
function runsCheck(hits: readonly Hit[], path: string, jobIds?: readonly string[]): boolean {
  const prefixes = jobIds === undefined ? [`${path} (job `] : jobIds.map((id) => `${path} (job ${id})`);
  return hits.some((h) => !h.opaque && h.reason === null && prefixes.some((x) => h.where.startsWith(x))
    && h.categories.some((c) => CHECK_CATEGORIES.has(c)));
}

function workflowRunGate(doc: Obj, path: string, p: RepoProfile, others: readonly GateWorkflow[], hits: readonly Hit[], branch: string | BranchGuess): string | null {
  const on = doc.on ?? doc.true;
  const names = triggerNames(on);
  if (names === null || names.length !== 1 || names[0] !== 'workflow_run') return null;
  const wr = asObj(asObj(on).workflow_run);
  const listed = typeof wr.workflows === 'string' ? [wr.workflows] : Array.isArray(wr.workflows) ? wr.workflows : [];
  if (listed.length !== 1 || typeof listed[0] !== 'string') return null;
  const target = listed[0];
  // a pattern, or a path (GitHub may read an unnamed workflow's path as its name): can't tell which workflows it names
  if (target === '' || target.length > 200 || /[*?[\]!/]/.test(target)) return null;
  // (d) exactly one workflow of that name, never this one; every other file readable, so none is missed
  const matches: GateWorkflow[] = [];
  for (const o of others) {
    if (o.doc === null) return null;
    const nm = o.doc.name;
    if (nm !== undefined && typeof nm !== 'string') return null;
    if (typeof nm === 'string' && nm.toLowerCase() === target.toLowerCase()) matches.push(o);
  }
  if (matches.length !== 1 || (matches[0] as GateWorkflow).path === path) return null;
  const ci = matches[0] as GateWorkflow;
  const ciDoc = ci.doc as Obj;
  const ciEvents = parseOn(ciDoc.on ?? ciDoc.true);
  if (fitOf(ciEvents, branch, false).pushDefault !== true || !runsCheck(hits, ci.path)) return null;
  // (c) the ref form needs branches: [<default>] exactly; and (fix round 1, review M1) CI's push trigger limited to
  // branches with no tag filter, so a tag named like the default branch never runs CI (head_branch is a tag's name)
  const br = wr.branches;
  const ciPush = ciEvents.get('push') ?? {};
  const ciBranchesOnly = (ciPush.branches !== undefined || ciPush['branches-ignore'] !== undefined) && ciPush.tags === undefined && ciPush['tags-ignore'] === undefined;
  const branchesExact = Array.isArray(br) && br.length === 1 && br[0] === p.defaultBranch && wr['branches-ignore'] === undefined && ciBranchesOnly;
  const jobs = jobsOf(doc);
  if (jobs === null) return null;
  const all = [...jobs.values()];
  // (e) a reusable call anywhere in the file: what it builds or deploys can't be seen
  if (all.some((j) => j.job.uses !== undefined)) return null;
  let deploying = all.filter(deploysJob);
  if (deploying.length === 0) deploying = all;
  const chains = new Map<string, Set<string>>();
  for (const j of all) {
    const chain = chainOf(jobs, j.id);
    if (chain === null) return null;
    chains.set(j.id, chain);
    // (g) the three guards on every job's chain
    const guards = new Set([...chain].flatMap((x) => (jobs.get(x) as Job).terms.map((t) => guardOf(t, p))));
    if (!guards.has('wr-success') || !guards.has('wr-push') || !guards.has('wr-same-repo')) return null;
  }
  for (const d of deploying) {
    const chain = chains.get(d.id) as Set<string>;
    const members = [...chain].map((x) => jobs.get(x) as Job);
    const steps = members.map(stepsOf);
    if (steps.some((s) => s === null)) return null;
    const refs = (steps as Obj[][]).flat().filter(isCheckout).map(checkoutRef);
    if (refs.includes(null)) return null;
    // (b) a commit check in a job every other job of the chain needs, before any build step
    const checked = members.some((c) => checkIndex(c, doc) >= 0
      && members.every((x) => x.id === c.id || (chains.get(x.id) as Set<string>).has(c.id)));
    // (c) the ref form: every checkout on the chain takes the tested commit
    const byRef = branchesExact && refs.length > 0 && refs.every((r) => r === 'head');
    if (!checked && !byRef) return null;
  }
  return `${path} runs after ${ci.path} passed for a push to ${safeText(p.defaultBranch, 100)} in this repo, and deploys only the commit that run tested`;
}

function ciRunGate(doc: Obj, path: string, p: RepoProfile, hits: readonly Hit[], branch: string | BranchGuess): string | null {
  const on = doc.on ?? doc.true;
  const names = triggerNames(on);
  if (names === null || !names.includes('push') || !names.every((n) => n === 'push' || n === 'pull_request')) return null;
  const events = parseOn(on);
  if (fitOf(events, branch, false).pushDefault !== true) return null;
  // fix round 1 (security review S-b): the push trigger itself is limited to exactly [<default>] (filters match the
  // branch name exactly; an `if:` comparison ignores letter case), with no tag filter
  const push = events.get('push') ?? {};
  const pushExact = Array.isArray(push.branches) && push.branches.length === 1 && push.branches[0] === p.defaultBranch
    && push['branches-ignore'] === undefined && push.tags === undefined && push['tags-ignore'] === undefined;
  if (!pushExact) return null;
  const prToo = names.includes('pull_request');
  const jobs = jobsOf(doc);
  if (jobs === null) return null;
  const all = [...jobs.values()];
  const deploying = all.filter(deploysJob);
  const ci = all.filter((j) => !deploysJob(j));
  if (deploying.length === 0 || ci.length === 0 || !runsCheck(hits, path, ci.map((j) => j.id))) return null;
  for (const d of deploying) {
    const chain = chainOf(jobs, d.id);
    if (chain === null || ci.some((j) => !chain.has(j.id))) return null;
    const members = [...chain].map((x) => jobs.get(x) as Job);
    if (members.some((m) => m.job.uses !== undefined)) return null;
    // with pull_request too, a term that holds only for a push keeps the deploy job off pull-request runs
    if (prToo && !members.some((m) => m.terms.some((t) => { const g = guardOf(t, p); return g === 'ref-default' || g === 'push-event'; }))) return null;
    const steps = members.map(stepsOf);
    if (steps.some((s) => s === null)) return null;
    if ((steps as Obj[][]).flat().filter(isCheckout).some((st) => checkoutRef(st) !== 'none')) return null;
  }
  return `${path} deploys only on a push to ${safeText(p.defaultBranch, 100)}, after every other job of the same run passed`;
}

/**
 * Ruling B3: the evidence line when the deploying workflow `doc` (at `path`) deploys only through one of the two
 * accepted forms (see the header), else null. `others` is every listed workflow with its parsed file (this one too; a
 * null doc = unreadable); `hits` the runs the mapper found, for "CI runs a check".
 */
export function deployGateOf(doc: Obj, path: string, p: RepoProfile, others: readonly GateWorkflow[], hits: readonly Hit[], branch: string | BranchGuess = p.defaultBranch): string | null {
  if (p.defaultBranch === '') return null;
  return workflowRunGate(doc, path, p, others, hits, branch) ?? ciRunGate(doc, path, p, hits, branch);
}

/** The gate over the whole repo (h): the evidence of every deploying workflow, or null when any piece is missing. */
export interface DeployGates { evidence: string[]; paths: string[] }

/**
 * (h): every workflow with `deploys: true` passes deployGateOf, there is at least one, and no listed workflow was
 * unreadable or past the budget. Under a rate stop only the widest world may credit (see the header).
 */
export async function deployGates(ctx: Ctx, p: RepoProfile, branchGuess?: BranchGuess['guess']): Promise<DeployGates | null> {
  if (branchGuess === 'narrowest' || p.defaultBranch === '' || ctx.unreadable || ctx.budget.truncated || p.existingWorkflows.length > MAX_WORKFLOWS) return null;
  if (!p.existingWorkflows.some((w) => w.deploys)) return null;
  const all: GateWorkflow[] = [];
  for (const w of p.existingWorkflows) {
    if (!regexSafe(w.path) || safeText(w.path) !== w.path || !WORKFLOW_FILE.test(w.path)) return null;
    const doc = await ctx.read.yaml(w.path);
    if ('fail' in doc) return null;
    all.push({ path: w.path, doc: doc.ok });
  }
  const branch: string | BranchGuess = branchGuess === undefined ? p.defaultBranch : { guess: branchGuess };
  const evidence: string[] = [];
  const paths: string[] = [];
  for (const w of [...p.existingWorkflows].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    if (!w.deploys) continue;
    const doc = all.find((x) => x.path === w.path)?.doc as Obj;
    const ev = deployGateOf(doc, w.path, p, all, ctx.hits, branch);
    if (ev === null) return null;
    evidence.push(ev);
    paths.push(w.path);
  }
  return { evidence, paths };
}
