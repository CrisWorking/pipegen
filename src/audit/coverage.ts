// Coverage mapper (Plan U Task 1): which floor needs a repo's existing workflows and git hooks already cover.
//
// Rules (plan + pre-flight rulings S1-S6, S26):
// - covered: a matching tool runs on the right trigger for the layer and can fail the run. Push layer = every push
//   to any branch; merge layer = pull_request to the default branch; deploy layer = a workflow that deploys, or runs on
//   push to the default branch, on a tag push or on release. Pre-commit = the active hook manager's pre-commit hook
//   runs a matching tool; `hooks` = a hook manager exists (p.precommit).
// - partial: the right tool on the wrong trigger (incl. pull_request_target, workflow_dispatch, schedule, a push filter
//   that leaves out feature branches), or allowed to fail (continue-on-error true or an expression).
// - unknown: a remote reusable workflow, an action from the repo owner's own account (likely a composite action), a
//   second-level local call, a local call pipegen refused or couldn't read, or more workflow text than the budget.
// - missing: nothing matches. `gate` and `deploy-verify` are always missing: they are pipegen's own checks.
// A job with a working directory (workflow or job default, step working-directory, or `cd <dir>` in a run line)
// covers only the service under that directory; any other job covers every service (S26).
//
// Hostile input: workflow, action and hook files are attacker-controlled. They are read only by path from the list
// readProject made (p.existingWorkflows) plus local `uses: ./…` targets, every path level checked for symbolic links,
// the real path checked to stay inside the repo, through the read limits (1 MB, binary refused, YAML alias cap), with
// jobs, steps, files and scanned bytes capped. Regexes are linear and only run on lines of 4 KB or less.
// Output follows the src/types.ts rule, RAW but VALIDATED, cleaned at output: `why` is pipegen's own text only;
// `by` is a tool-signature id from data/tool-signatures.yml, an own-script phrase built from fixed words, a hook manager
// name, or a repo `uses:` value kept only when it matches REF_RE (ASCII letters, digits and . _ - / @; at most 200
// characters; unchanged by safeText); `where` joins workflow and action paths that are unchanged by safeText with job
// ids that pass JOB_ID_RE (else "#n"), cut to MAX_WHERE code points. Task 3 still cleans `by` and `where` with
// safeText / safeMarkdown when it prints them.
import { readFileSync } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { join, posix, sep } from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import { linkedLevel, parseYamlLimited, readTextLimitedWithReason, regexLines, regexSafe } from '../read/limits.js';
import { asObj, type Obj } from '../read/manifest.js';
import { JOB_ID_RE, MAX_WORKFLOWS, TRIGGER_RE, WORKFLOW_FILE } from '../read/workflows.js';
import { NEED_CATEGORIES, type Layer, type Need, type RepoProfile, type Service } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';

export interface Coverage { need: Need; status: 'covered' | 'partial' | 'missing' | 'unknown'; by?: string; where?: string; why: string }

// ---------- tool signatures (ruling S1) ----------

const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PART_RE = /^[A-Za-z0-9_.-]+$/;

/** owner/name, optionally with a sub-path (owner/name/sub): parts split on "/", each a plain name. */
function isActionRef(s: string): boolean {
  const parts = s.split('/');
  return s.length <= 200 && parts.length >= 2 && parts.every((x) => PART_RE.test(x) && x !== '.' && x !== '..');
}
/** Words of [A-Za-z0-9_.-] joined by one space or one slash, e.g. "gitleaks", "npm audit", ".husky/pre-commit". */
function isCommand(s: string): boolean {
  return s.length <= 64 && s.split(/[ /]/).every((x) => PART_RE.test(x));
}

const signatureSchema = z.strictObject({
  id: z.string().regex(ID_RE),
  categories: z.array(z.enum(NEED_CATEGORIES)).min(1),
  actions: z.array(z.string().refine(isActionRef, 'must be owner/name')).min(1).optional(),
  commands: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
}).refine((t) => t.actions !== undefined || t.commands !== undefined, { message: 'needs actions or commands' });

const signaturesSchema = z.strictObject({ tools: z.array(signatureSchema).min(1) })
  .refine((f) => new Set(f.tools.map((t) => t.id)).size === f.tools.length, { message: 'ids must be unique' });

export type ToolSignature = z.infer<typeof signatureSchema>;

/** Reads and checks the tool signatures (default: pipegen's own data/tool-signatures.yml). Throws on any problem. */
export function loadToolSignatures(path: string = packageDataPath('tool-signatures.yml')): ToolSignature[] {
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new Error(`pipegen's tool signatures (${path}) could not be read: ${e instanceof Error ? e.message.split('\n')[0] : 'unreadable'}`);
  }
  const parsed = signaturesSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`pipegen's tool signatures (${path}) are not valid: ${issue?.path.join('.') || 'file'}: ${issue?.message ?? 'invalid'}`);
  }
  return parsed.data.tools;
}

/** One way to recognise a tool in a line: the first word, then (for multi-word commands) the rest, anchored after it. */
interface CommandMatcher { tool: ToolSignature; rest: RegExp | null }
interface Compiled { byFirstWord: Map<string, CommandMatcher[]>; actions: { tool: ToolSignature; parts: string[] }[] }

const WORD_CHARS = 'A-Za-z0-9_.-';
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');

function compile(tools: ToolSignature[]): Compiled {
  const byFirstWord = new Map<string, CommandMatcher[]>();
  const actions: Compiled['actions'] = [];
  for (const tool of tools) {
    for (const cmd of tool.commands ?? []) {
      const first = cmd.split(/[ /]/)[0] as string;
      const tail = cmd.slice(first.length);
      // " audit" → /\s+audit(?![A-Za-z0-9_.-])/y: the separator is one space (any whitespace in a line) or a slash.
      const rest = tail === '' ? null : new RegExp(`${tail.split(' ').map(escapeRe).join('\\s+')}(?![${WORD_CHARS}])`, 'y');
      byFirstWord.set(first, [...(byFirstWord.get(first) ?? []), { tool, rest }]);
    }
    for (const a of tool.actions ?? []) actions.push({ tool, parts: a.toLowerCase().split('/') });
  }
  return { byFirstWord, actions };
}

let defaultCompiled: Compiled | undefined;

// ---------- bounds ----------

const MAX_JOBS = 100;              // per workflow
const MAX_STEPS = 200;             // per job or composite action
const MAX_STEP_VISITS = 50_000;    // per mapCoverage call, followed files included
const MAX_SCAN_BYTES = 32_000_000; // run text scanned per mapCoverage call
const MAX_LOCAL_FILES = 100;       // distinct local workflows and actions followed
const MAX_HOOKS = 200;             // pre-commit repos, hooks per repo, lefthook commands
const MAX_FILTER_PATTERNS = 100;
const MAX_GLOB = 256;
const MAX_WHERE = 300;
const MAX_DIR = 512;               // a tracked directory longer than this is unknown (a chain of cd's can't grow it)
const MAX_HITS = 100_000;          // tool and opaque findings kept per mapCoverage call

// ---------- why (pipegen's own text only) ----------

const MISSING_WHY: Readonly<Record<string, string>> = {
  secrets: 'Without a secret scan in CI, a key committed without the local hook is only found after it leaks.',
  sast: 'Without a code scan, common security bugs reach the main branch unnoticed.',
  deps: 'Without a dependency scan, packages with known vulnerabilities ship unnoticed.',
  'unit-tests': 'Without unit tests in CI, broken code is only found after it has been shared.',
  'full-tests': 'Without the full test suite before merge, broken code can reach the main branch.',
  lint: 'Without a lint check in CI, mistakes the linter would catch can be merged.',
  'format-lint': 'Without a format and lint hook, style problems are only found later, in CI or in review.',
  hooks: "Without a git hook manager, no check runs on a developer's machine before a commit.",
  'hooks-ci': 'Without running the hooks in CI, anyone who skips them locally is never caught.',
  'image-build': 'Without one image build in CI, the image that is scanned may not be the image that is deployed.',
  'image-scan': 'Without an image scan, known vulnerabilities in the container image ship unnoticed.',
  dast: 'Without a scan of the running app, security problems that only show at run time go unnoticed.',
  iac: 'Without an infrastructure scan, insecure Terraform settings can be merged and applied.',
  sbom: 'Without an SBOM, nobody can tell later which components went into a build.',
  signing: 'Without image signing, nothing proves that a deployed image came from this pipeline.',
  attestation: 'Without an attestation, nothing records how and where the image was built.',
};
const PRECOMMIT_SECRETS_WHY = 'Without a secret scan before commit, a leaked key is in git history forever.';
const GATE_WHY = 'No single required check sums up every scan, so a pull request with a failing scan can still be merged.';
const DEPLOY_VERIFY_WHY = "Deploys don't check that the commit passed the pipeline, so an unchecked commit can be deployed.";
const FALLBACK_MISSING_WHY = 'No workflow or git hook in this repo runs this check.';

const OPAQUE_WHY = {
  remoteWorkflow: "A job calls a reusable workflow from another repo, and pipegen can't see inside it.",
  ownerAction: "A step uses an action from the repo owner's own account, and pipegen can't see inside it.",
  localCode: "A step uses a local action that runs its own code, and pipegen can't see inside it.",
  secondLevel: "A called workflow or action calls another local one, and pipegen follows only one level, so it can't tell.",
  unreadable: "A job or step calls a local workflow or action that pipegen couldn't read (missing, a symbolic link, too large or not valid YAML), so it can't tell.",
  outside: "A job or step calls a local workflow or action that points outside the repo, so pipegen didn't read it.",
  truncated: "The workflows are too large to read in full, so pipegen can't tell.",
  hookUnreadable: "The git hook file couldn't be read (a symbolic link, too large or not valid), so pipegen can't tell.",
} as const;

const LAYER_DONE: Readonly<Record<Exclude<Layer, 'pre-commit'>, string>> = {
  push: 'on every push',
  merge: 'on every pull request',
  deploy: 'when the code is deployed or released',
};

const HOOK_PLACE = { 'pre-commit': 'the pre-commit framework', husky: 'the husky pre-commit hook', lefthook: 'the lefthook pre-commit hook' } as const;
const HOOK_NAME = { 'pre-commit': 'the pre-commit framework', husky: 'husky', lefthook: 'lefthook' } as const;

// ---------- small helpers ----------

type Manager = NonNullable<RepoProfile['precommit']>;
type CiLayer = Exclude<Layer, 'pre-commit'>;
type Fit = Record<CiLayer, boolean>;

interface Found { categories: readonly string[]; by: string; subject: string; dir: string | null }
interface Hit {
  opaque: boolean;
  categories: readonly string[];
  by?: string;
  subject: string;
  dir: string | null;
  nonBlocking: boolean;
  fit: Fit;
  where: string;
  why?: string;
}

const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strs = (v: unknown): string[] => (typeof v === 'string' ? [v] : list(v).filter((x): x is string => typeof x === 'string'));

function cut(s: string): string {
  const chars = Array.from(s);
  return chars.length <= MAX_WHERE ? s : `${chars.slice(0, MAX_WHERE - 1).join('')}…`;
}

const REF_RE = /^[A-Za-z0-9_./-]+(?:@[A-Za-z0-9_./-]+)?$/;
/** A repo `uses:` value kept raw for `by`, or undefined when it doesn't pass REF_RE. */
const validRef = (u: string): string | undefined => (u.length <= 200 && REF_RE.test(u) && safeText(u) === u ? u : undefined);

/** True for continue-on-error values that let the step or job fail without failing the run (true, or an expression). */
function nonBlocking(v: unknown): boolean {
  if (v === true) return true;
  if (typeof v !== 'string') return false;
  const t = v.trim();
  return t !== '' && t !== 'false';
}

/** `base` joined with `rel` inside the repo ('.' = root), or null when it can't be known or leaves the repo. */
function resolveDir(base: string | null, rel: string): string | null {
  if (base === null || base.length + rel.length > MAX_DIR) return null;
  const joined = posix.normalize(posix.join(base, rel)).replace(/\/+$/, '');
  if (joined === '' || joined === '.') return '.';
  if (joined === '..' || joined.startsWith('../') || posix.isAbsolute(joined)) return null;
  return joined;
}

const WORKSPACE_PREFIX = /^(?:\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?)(?:\/|$)/;
/** A working-directory value: undefined = not set, null = can't be resolved (an expression, a variable, absolute). */
function workingDir(v: unknown): string | null | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string' || !regexSafe(v)) return null;
  const s = v.trim().replace(WORKSPACE_PREFIX, '');
  if (/[$`~\\]/.test(s) || s.startsWith('/')) return null;
  return resolveDir('.', s === '' ? '.' : s);
}

const defaultsDir = (doc: Obj) => workingDir(asObj(asObj(doc.defaults).run)['working-directory']);
const firstSet = (...dirs: (string | null | undefined)[]): string | null => {
  for (const d of dirs) if (d !== undefined) return d;
  return '.';
};

// ---------- reading run lines ----------

const WORD = /[A-Za-z0-9_.-]+/g;
const CD_ARG = /[ \t]+([^\s;&|()]+)/y;
const COMMENT = /^\s*#/;
// The service's own scripts (ruling S5), keyed by first word; the rest is matched right after it.
const OWN_SCRIPT: Readonly<Record<string, RegExp | null>> = {
  npm: /\s+(?:test|run\s+(?:test|lint))(?![A-Za-z0-9_.-])/y,
  pnpm: /\s+(?:run\s+)?(?:test|lint)(?![A-Za-z0-9_.-])/y,
  yarn: /\s+(?:run\s+)?(?:test|lint)(?![A-Za-z0-9_.-])/y,
  bun: /\s+(?:run\s+)?(?:test|lint)(?![A-Za-z0-9_.-])/y,
  python: /\s+-m\s+pytest(?![A-Za-z0-9_.-])/y,
  python3: /\s+-m\s+pytest(?![A-Za-z0-9_.-])/y,
  pytest: null,
};
const TEST_CATEGORIES = ['unit-tests', 'full-tests'] as const;

/** True when a `cd` word at `at` starts a command: at the line start or after ; & | ( { (spaces allowed between). */
function startsCommand(line: string, at: number): boolean {
  let i = at - 1;
  while (i >= 0 && (line[i] === ' ' || line[i] === '\t')) i--;
  return i < 0 || ';&|({'.includes(line[i] as string);
}

function cdTarget(raw: string): string | null {
  const s = raw.replace(/^["']/, '').replace(/["']$/, '');
  if (s === '' || s === '-' || /[$`~\\]/.test(s) || s.startsWith('/')) return null;
  return s;
}

interface Budget { visits: number; bytes: number; truncated: boolean }

/**
 * Tools found in shell text (a run step, a hook script, a hook entry). Whole words only; `#` comment lines skipped.
 * `cd <dir>` moves the directory for the rest of the text; a tool's `dir` is where it ran (null = unknown).
 */
function scanShell(text: string, base: string | null, sigs: Compiled, budget: Budget): Found[] {
  budget.bytes += text.length;
  if (budget.bytes > MAX_SCAN_BYTES) {
    budget.truncated = true;
    return [];
  }
  const found: Found[] = [];
  const seen = new Set<string>(); // one finding per tool and directory per text
  const add = (f: Found) => {
    const key = `${f.by}\u0000${f.dir ?? ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      found.push(f);
    }
  };
  let cwd = base;
  for (const line of regexLines(text)) {
    if (COMMENT.test(line)) continue;
    for (const m of line.matchAll(WORD)) {
      const word = m[0];
      const end = m.index + word.length;
      if (word === 'cd' && startsCommand(line, m.index)) {
        CD_ARG.lastIndex = end;
        const arg = CD_ARG.exec(line);
        const target = arg ? cdTarget(arg[1] as string) : null;
        cwd = target === null ? null : resolveDir(cwd, target);
        continue;
      }
      for (const c of sigs.byFirstWord.get(word) ?? []) {
        if (c.rest !== null) {
          c.rest.lastIndex = end;
          if (!c.rest.test(line)) continue;
        }
        add({ categories: c.tool.categories, by: c.tool.id, subject: `The ${c.tool.id} check`, dir: cwd });
      }
      if (Object.hasOwn(OWN_SCRIPT, word)) {
        const rest = OWN_SCRIPT[word] as RegExp | null;
        let stop = end;
        if (rest !== null) {
          rest.lastIndex = end;
          if (!rest.test(line)) continue;
          stop = rest.lastIndex;
        }
        // Only fixed words and whitespace were matched, so the phrase is safe to show; whitespace becomes one space.
        const cmd = line.slice(m.index, stop).split(/\s+/).join(' ');
        const categories = cmd.endsWith('lint') ? ['lint'] : TEST_CATEGORIES;
        add({ categories, by: `your own \`${cmd}\``, subject: `Your own \`${cmd}\``, dir: cwd });
      }
    }
  }
  return found;
}

// ---------- triggers (ruling S6) ----------

type Tok = { kind: 'star' | 'dstar' } | { kind: 'char'; test: (c: string) => boolean; q: '' | '?' | '+' };

/** GitHub filter glob → tokens: * (not /), ** (anything), [a-z0-9] classes, ? and + after a character, \ escapes. */
function globTokens(pattern: string): Tok[] | null {
  const toks: Tok[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i] as string;
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        toks.push({ kind: 'dstar' });
        i++;
      } else toks.push({ kind: 'star' });
    } else if ((c === '?' || c === '+') && toks.length > 0 && toks[toks.length - 1]?.kind === 'char') {
      const last = toks[toks.length - 1] as Extract<Tok, { kind: 'char' }>;
      if (last.q !== '') return null;
      last.q = c;
    } else if (c === '[') {
      const close = pattern.indexOf(']', i + 1);
      if (close < 0) return null;
      const body = pattern.slice(i + 1, close);
      const ranges: [string, string][] = [];
      for (let k = 0; k < body.length; k++) {
        if (body[k + 1] === '-' && k + 2 < body.length) {
          ranges.push([body[k] as string, body[k + 2] as string]);
          k += 2;
        } else ranges.push([body[k] as string, body[k] as string]);
      }
      toks.push({ kind: 'char', test: (x) => ranges.some(([a, b]) => x >= a && x <= b), q: '' });
      i = close;
    } else {
      const lit = c === '\\' && i + 1 < pattern.length ? (pattern[++i] as string) : c;
      toks.push({ kind: 'char', test: (x) => x === lit, q: '' });
    }
  }
  return toks;
}

/** GitHub branch-filter glob match, simulated over the tokens (O(pattern × name), no backtracking regex). */
function globMatch(pattern: string, name: string): boolean {
  if (pattern.length > MAX_GLOB || name.length > MAX_GLOB) return false;
  const toks = globTokens(pattern);
  if (toks === null) return false;
  const close = (set: Set<number>) => {
    for (const i of set) {
      const t = toks[i];
      if (t && (t.kind !== 'char' || t.q === '?')) set.add(i + 1); // Set iteration visits added items too
    }
    return set;
  };
  let cur = close(new Set([0]));
  for (const ch of name) {
    const next = new Set<number>();
    for (const i of cur) {
      const t = toks[i];
      if (!t) continue;
      if (t.kind === 'dstar' || (t.kind === 'star' && ch !== '/')) next.add(i);
      else if (t.kind === 'char' && t.test(ch)) {
        next.add(i + 1);
        if (t.q === '+') next.add(i);
      }
    }
    cur = close(next);
    if (cur.size === 0) return false;
  }
  return cur.has(toks.length);
}

/** `branches` semantics: patterns in order, a later match wins, `!` excludes. */
function branchesInclude(patterns: string[], name: string): boolean {
  let included = false;
  for (const p of patterns.slice(0, MAX_FILTER_PATTERNS)) {
    const negated = p.startsWith('!');
    if (globMatch(negated ? p.slice(1) : p, name)) included = !negated;
  }
  return included;
}

/** Whether a push or pull_request filter lets `name` through (`branches` and `branches-ignore` together are invalid). */
function branchFilter(cfg: Obj): (name: string) => boolean {
  const hasB = 'branches' in cfg && cfg.branches !== null;
  const hasBi = 'branches-ignore' in cfg && cfg['branches-ignore'] !== null;
  if (hasB && hasBi) return () => false;
  if (hasB) return (n) => branchesInclude(strs(cfg.branches), n);
  if (hasBi) return (n) => !strs(cfg['branches-ignore']).slice(0, MAX_FILTER_PATTERNS).some((p) => globMatch(p, n));
  return () => true;
}

/** Event names → their config, from the three YAML forms of `on:` (string, list, map). */
function parseOn(on: unknown): Map<string, Obj> {
  const events = new Map<string, Obj>();
  const add = (name: string, cfg: unknown) => {
    if (regexSafe(name) && TRIGGER_RE.test(name)) events.set(name, asObj(cfg));
  };
  if (typeof on === 'string') {
    add(on, null);
  } else if (Array.isArray(on)) {
    for (const n of on.slice(0, MAX_FILTER_PATTERNS)) if (typeof n === 'string') add(n, null);
  } else {
    for (const [n, cfg] of Object.entries(asObj(on))) add(n, cfg);
  }
  return events;
}

/** Branch names a developer's push would use; a push trigger must let both through to count for the push layer. */
const FEATURE_BRANCHES = ['pipegen-feature', 'feature/pipegen-feature'];

function fitOf(events: Map<string, Obj>, defaultBranch: string, deploys: boolean): Fit {
  let everyPush = false;
  let pushDefault = false;
  let pushTags = false;
  const push = events.get('push');
  if (push) {
    const branchesSet = ['branches', 'branches-ignore'].some((k) => k in push && push[k] !== null);
    pushTags = ['tags', 'tags-ignore'].some((k) => k in push && push[k] !== null);
    // A push trigger with only a tag filter never runs for branch pushes.
    const includes = !branchesSet && pushTags ? () => false : branchFilter(push);
    everyPush = FEATURE_BRANCHES.every(includes);
    pushDefault = includes(defaultBranch);
  }
  const pr = events.get('pull_request');
  const types = pr ? strs(pr.types) : [];
  const merge = pr !== undefined && branchFilter(pr)(defaultBranch) && (types.length === 0 || types.includes('synchronize'));
  return { push: everyPush, merge, deploy: deploys || pushDefault || pushTags || events.has('release') };
}

// ---------- reading files safely (ruling S2) ----------

type Read<T> = { ok: T } | { fail: 'missing' | 'unreadable' | 'outside' };

class Reader {
  private cache = new Map<string, Promise<Read<string>>>();
  private rootReal: Promise<string | null>;
  constructor(private dir: string) {
    this.rootReal = realpath(dir).catch(() => null);
  }

  /**
   * Text of `rel` (repo-relative), only when no level of the path is a symbolic link, its real path stays inside the
   * repo, and it passes the read limits. Each distinct file is read once.
   */
  text(rel: string): Promise<Read<string>> {
    let r = this.cache.get(rel);
    if (!r) {
      r = this.cache.size >= MAX_WORKFLOWS + MAX_LOCAL_FILES + 2 ? Promise.resolve({ fail: 'unreadable' as const }) : this.load(rel);
      this.cache.set(rel, r);
    }
    return r;
  }

  async yaml(rel: string): Promise<Read<Obj>> {
    const r = await this.text(rel);
    if (!('ok' in r)) return r;
    try {
      return { ok: asObj(parseYamlLimited(r.ok)) };
    } catch {
      return { fail: 'unreadable' };
    }
  }

  private async load(rel: string): Promise<Read<string>> {
    if (!regexSafe(rel) || safeText(rel) !== rel || rel.startsWith('/') || rel.split('/').some((x) => x === '..' || x === '')) return { fail: 'unreadable' };
    if ((await linkedLevel(this.dir, rel)) !== null) return { fail: 'unreadable' };
    const abs = join(this.dir, rel);
    if ((await lstat(abs).catch(() => null)) === null) return { fail: 'missing' };
    const [root, real] = await Promise.all([this.rootReal, realpath(abs).catch(() => null)]);
    if (root === null || real === null) return { fail: 'unreadable' };
    if (!real.startsWith(root + sep)) return { fail: 'outside' };
    const read = await readTextLimitedWithReason(abs);
    return 'text' in read ? { ok: read.text } : { fail: 'unreadable' };
  }
}

/** A local `uses: ./…` value as a repo-relative path ('.' = root), or 'outside' when it leaves the repo. */
function localPath(uses: string): string | 'outside' | null {
  if (!regexSafe(uses) || uses.includes('\\') || uses.includes('\0')) return null;
  const rel = posix.normalize(uses).replace(/\/+$/, '');
  if (rel === '' || rel === '.') return '.';
  if (rel === '..' || rel.startsWith('../') || posix.isAbsolute(rel)) return 'outside';
  return rel;
}

// ---------- walking workflows (rulings S3, S26) ----------

interface Ctx { p: RepoProfile; sigs: Compiled; read: Reader; budget: Budget; hits: Hit[]; localFiles: Set<string> }
interface StepCtx { fit: Fit; where: string; dir: string | null; nonBlocking: boolean; depth: number }

function spend(ctx: Ctx): boolean {
  if (ctx.budget.visits >= MAX_STEP_VISITS) {
    ctx.budget.truncated = true;
    return false;
  }
  ctx.budget.visits++;
  return true;
}

function opaque(ctx: Ctx, why: string, by: string | undefined, c: { fit: Fit; where: string; dir: string | null }): void {
  if (ctx.hits.length >= MAX_HITS) {
    ctx.budget.truncated = true;
    return;
  }
  ctx.hits.push({ opaque: true, categories: [], ...(by === undefined ? {} : { by }), subject: '', dir: c.dir, nonBlocking: false, fit: c.fit, where: c.where, why });
}

function addFound(ctx: Ctx, found: Found[], c: StepCtx): void {
  if (ctx.hits.length + found.length > MAX_HITS) {
    ctx.budget.truncated = true;
    return;
  }
  for (const f of found) ctx.hits.push({ opaque: false, categories: f.categories, by: f.by, subject: f.subject, dir: f.dir, nonBlocking: c.nonBlocking, fit: c.fit, where: c.where });
}

/** Signatures whose action parts are a prefix of `uses` (owner/name[/sub]@ref), case-insensitively. */
function actionMatches(sigs: Compiled, uses: string): ToolSignature[] {
  const at = uses.indexOf('@');
  const parts = (at < 0 ? uses : uses.slice(0, at)).toLowerCase().split('/');
  if (parts.length < 2 || !parts.every((x) => PART_RE.test(x))) return [];
  const out: ToolSignature[] = [];
  for (const a of sigs.actions) {
    if (a.parts.length <= parts.length && a.parts.every((x, i) => parts[i] === x) && !out.includes(a.tool)) out.push(a.tool);
  }
  return out;
}

async function walkStep(ctx: Ctx, step: Obj, c: StepCtx): Promise<void> {
  if (!spend(ctx)) return;
  const sc: StepCtx = { ...c, nonBlocking: c.nonBlocking || nonBlocking(step['continue-on-error']) };
  if (typeof step.uses === 'string' && regexSafe(step.uses)) {
    const uses = step.uses.trim();
    if (uses === '.' || uses.startsWith('./')) {
      await followAction(ctx, uses, sc);
    } else if (uses.startsWith('docker://')) {
      addFound(ctx, scanShell(uses, c.dir, ctx.sigs, ctx.budget), sc);
    } else {
      const tools = actionMatches(ctx.sigs, uses);
      for (const t of tools) addFound(ctx, [{ categories: t.categories, by: t.id, subject: `The ${t.id} check`, dir: c.dir }], sc);
      const owner = uses.split('/')[0]?.toLowerCase();
      if (tools.length === 0 && owner !== undefined && owner === ctx.p.owner.toLowerCase()) opaque(ctx, OPAQUE_WHY.ownerAction, validRef(uses), sc);
    }
  }
  if (typeof step.run === 'string') {
    const base = firstSet(workingDir(step['working-directory']), c.dir);
    addFound(ctx, scanShell(step.run, base, ctx.sigs, ctx.budget), sc);
  }
}

/** A local action (`uses: ./dir`): a composite one is followed one level; anything else can't be seen into. */
async function followAction(ctx: Ctx, uses: string, c: StepCtx): Promise<void> {
  const by = validRef(uses);
  if (c.depth > 0) return opaque(ctx, OPAQUE_WHY.secondLevel, by, c);
  const rel = localPath(uses);
  if (rel === 'outside') return opaque(ctx, OPAQUE_WHY.outside, by, c);
  if (rel === null) return opaque(ctx, OPAQUE_WHY.unreadable, by, c);
  let file = '';
  let doc: Read<Obj> = { fail: 'missing' };
  for (const name of ['action.yml', 'action.yaml']) {
    file = rel === '.' ? name : `${rel}/${name}`;
    doc = await readLocal(ctx, file);
    if (!('fail' in doc) || doc.fail !== 'missing') break;
  }
  if ('fail' in doc) return opaque(ctx, doc.fail === 'outside' ? OPAQUE_WHY.outside : OPAQUE_WHY.unreadable, by, c);
  const runs = asObj(doc.ok.runs);
  if (runs.using !== 'composite') return opaque(ctx, OPAQUE_WHY.localCode, by, c);
  const where = cut(`${c.where} → ${file}`);
  for (const step of list(runs.steps).slice(0, MAX_STEPS)) await walkStep(ctx, asObj(step), { ...c, where, depth: 1 });
  if (list(runs.steps).length > MAX_STEPS) ctx.budget.truncated = true;
}

/** A local workflow or action file, counted against MAX_LOCAL_FILES. */
async function readLocal(ctx: Ctx, rel: string): Promise<Read<Obj>> {
  if (!ctx.localFiles.has(rel)) {
    if (ctx.localFiles.size >= MAX_LOCAL_FILES) {
      ctx.budget.truncated = true;
      return { fail: 'unreadable' };
    }
    ctx.localFiles.add(rel);
  }
  return ctx.read.yaml(rel);
}

async function walkWorkflow(ctx: Ctx, doc: Obj, path: string, fit: Fit, depth: number, prefix: string): Promise<void> {
  const wfDir = defaultsDir(doc);
  const jobs = Object.entries(asObj(doc.jobs));
  if (jobs.length > MAX_JOBS) ctx.budget.truncated = true;
  for (const [i, [id, raw]] of jobs.slice(0, MAX_JOBS).entries()) {
    const job = asObj(raw);
    const label = regexSafe(id) && JOB_ID_RE.test(id) ? id : `#${i + 1}`;
    const where = cut(`${prefix}${path} (job ${label})`);
    const dir = firstSet(defaultsDir(job), wfDir);
    if (typeof job.uses === 'string' && regexSafe(job.uses)) {
      await callWorkflow(ctx, job.uses.trim(), { fit, where, dir, nonBlocking: false, depth });
      continue;
    }
    const steps = list(job.steps);
    if (steps.length > MAX_STEPS) ctx.budget.truncated = true;
    const c: StepCtx = { fit, where, dir, nonBlocking: nonBlocking(job['continue-on-error']), depth };
    for (const step of steps.slice(0, MAX_STEPS)) await walkStep(ctx, asObj(step), c);
  }
}

/** A job-level `uses:`: a local reusable workflow is followed one level; a remote one can't be seen into. */
async function callWorkflow(ctx: Ctx, uses: string, c: StepCtx): Promise<void> {
  if (!spend(ctx)) return;
  const by = validRef(uses);
  if (!uses.startsWith('./')) return opaque(ctx, OPAQUE_WHY.remoteWorkflow, by, c);
  if (c.depth > 0) return opaque(ctx, OPAQUE_WHY.secondLevel, by, c);
  const rel = localPath(uses);
  if (rel === 'outside') return opaque(ctx, OPAQUE_WHY.outside, by, c);
  if (rel === null || !WORKFLOW_FILE.test(rel)) return opaque(ctx, OPAQUE_WHY.unreadable, by, c);
  const doc = await readLocal(ctx, rel);
  if ('fail' in doc) return opaque(ctx, doc.fail === 'outside' ? OPAQUE_WHY.outside : OPAQUE_WHY.unreadable, by, c);
  // The called workflow runs on the caller's event, so the caller's trigger fit applies.
  await walkWorkflow(ctx, doc.ok, rel, c.fit, 1, `${c.where} → `);
}

// ---------- hooks ----------

interface Hooks { manager: Manager | null; where: string; readable: boolean; found: Found[] }

async function readHooks(ctx: Ctx): Promise<Hooks> {
  const manager = ctx.p.precommit;
  const none: Hooks = { manager, where: '', readable: true, found: [] };
  if (manager === null) return none;
  const scan = (text: string, base: string | null = '.') => scanShell(text, base, ctx.sigs, ctx.budget);
  if (manager === 'husky') {
    const where = '.husky/pre-commit';
    const r = await ctx.read.text(where);
    if ('fail' in r) return { ...none, where: '.husky', readable: r.fail === 'missing' };
    return { manager, where, readable: true, found: scan(r.ok) };
  }
  if (manager === 'pre-commit') {
    const where = '.pre-commit-config.yaml';
    const r = await ctx.read.yaml(where);
    if ('fail' in r) return { ...none, where, readable: r.fail === 'missing' };
    const defaultStages = strs(r.ok.default_stages);
    const found: Found[] = [];
    for (const repo of list(r.ok.repos).slice(0, MAX_HOOKS)) {
      for (const raw of list(asObj(repo).hooks).slice(0, MAX_HOOKS)) {
        const hook = asObj(raw);
        const stages = 'stages' in hook ? strs(hook.stages) : defaultStages;
        if (stages.length > 0 && !stages.some((s) => s === 'pre-commit' || s === 'commit')) continue;
        found.push(...scan([hook.id, hook.entry].filter((x): x is string => typeof x === 'string').join(' ')));
      }
    }
    return { manager, where, readable: true, found };
  }
  // lefthook: the first of lefthook.yml / lefthook.yaml that exists (readPrecommit's order)
  for (const where of ['lefthook.yml', 'lefthook.yaml']) {
    const r = await ctx.read.yaml(where);
    if ('fail' in r && r.fail === 'missing') continue;
    if ('fail' in r) return { ...none, where, readable: false };
    const hook = asObj(r.ok['pre-commit']);
    const entries = [...Object.values(asObj(hook.commands)), ...list(hook.jobs)].slice(0, MAX_HOOKS).map(asObj);
    const found = entries.flatMap((e) => (typeof e.run === 'string' ? scan(e.run, firstSet(workingDir(e.root))) : []));
    return { manager, where, readable: true, found };
  }
  return none;
}

// ---------- per need ----------

const normalPath = (s: string) => {
  const n = posix.normalize(s).replace(/\/+$/, '');
  return n === '' ? '.' : n;
};

/** Whether a tool that ran in `dir` counts for the need's service (ruling S26). */
function appliesTo(dir: string | null, serviceName: string | undefined, services: Service[]): boolean {
  if (serviceName === undefined || dir === '.') return true;
  if (dir === null) return false;
  const paths = services.map((s) => ({ name: s.name, path: normalPath(s.path) }));
  const target = paths.find((s) => s.name === serviceName);
  if (!target) return false;
  const owner = paths
    .filter((s) => s.path === '.' || dir === s.path || dir.startsWith(`${s.path}/`))
    .sort((a, b) => b.path.length - a.path.length)[0];
  if (owner?.name === serviceName) return true;
  return target.path !== '.' && target.path.startsWith(`${dir}/`); // a job run above several services covers each
}

function missingWhy(need: Need): string {
  if (need.layer === 'pre-commit' && need.category === 'secrets') return PRECOMMIT_SECRETS_WHY;
  return MISSING_WHY[need.category] ?? FALLBACK_MISSING_WHY;
}

const located = (h: { by?: string; where: string }) => ({ ...(h.by === undefined ? {} : { by: h.by }), where: h.where });

function ciCoverage(need: Need, layer: CiLayer, hits: Hit[], services: Service[], truncated: boolean): Coverage {
  let partialFailOk: Hit | undefined;
  let partialTrigger: Hit | undefined;
  let strongOpaque: Hit | undefined;
  let weakOpaque: Hit | undefined;
  for (const h of hits) {
    if (!appliesTo(h.dir, need.service, services)) continue;
    const right = h.fit[layer];
    if (h.opaque) {
      if (right) strongOpaque ??= h;
      else weakOpaque ??= h;
      continue;
    }
    if (!h.categories.includes(need.category)) continue;
    if (right && !h.nonBlocking) return { need, status: 'covered', ...located(h), why: `${h.subject} runs ${LAYER_DONE[layer]}.` };
    if (right) partialFailOk ??= h;
    else partialTrigger ??= h;
  }
  if (strongOpaque) return { need, status: 'unknown', ...located(strongOpaque), why: strongOpaque.why as string };
  if (truncated) return { need, status: 'unknown', why: OPAQUE_WHY.truncated };
  if (partialFailOk) {
    return { need, status: 'partial', ...located(partialFailOk), why: `${partialFailOk.subject} runs, but is allowed to fail (continue-on-error), so it can't block anything.` };
  }
  if (partialTrigger) return { need, status: 'partial', ...located(partialTrigger), why: `${partialTrigger.subject} runs, but not ${LAYER_DONE[layer]}.` };
  if (weakOpaque) return { need, status: 'unknown', ...located(weakOpaque), why: weakOpaque.why as string };
  return { need, status: 'missing', why: missingWhy(need) };
}

function hookCoverage(need: Need, hooks: Hooks, services: Service[]): Coverage {
  const m = hooks.manager;
  if (need.category === 'hooks') {
    return m === null
      ? { need, status: 'missing', why: missingWhy(need) }
      : { need, status: 'covered', by: m, where: m === 'lefthook' && hooks.where !== '' ? hooks.where : HOOK_FILE[m], why: `The repo uses ${HOOK_NAME[m]} to run git hooks.` };
  }
  if (m !== null) {
    const f = hooks.found.find((x) => x.categories.includes(need.category) && appliesTo(x.dir, need.service, services));
    if (f) return { need, status: 'covered', by: f.by, where: hooks.where, why: `${f.subject} runs in ${HOOK_PLACE[m]} before each commit.` };
    if (!hooks.readable) return { need, status: 'unknown', where: hooks.where, why: OPAQUE_WHY.hookUnreadable };
  }
  return { need, status: 'missing', why: missingWhy(need) };
}

const HOOK_FILE = { 'pre-commit': '.pre-commit-config.yaml', husky: '.husky', lefthook: 'lefthook.yml' } as const;

/**
 * One Coverage per need, in order. Reads only the workflows in p.existingWorkflows (the list readProject made), the
 * local workflows and actions they call (one level), and the active hook manager's pre-commit hook.
 */
export async function mapCoverage(p: RepoProfile, needs: Need[], dir: string): Promise<Coverage[]> {
  const sigs = (defaultCompiled ??= compile(loadToolSignatures()));
  const ctx: Ctx = { p, sigs, read: new Reader(dir), budget: { visits: 0, bytes: 0, truncated: false }, hits: [], localFiles: new Set() };
  for (const w of [...p.existingWorkflows].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).slice(0, MAX_WORKFLOWS)) {
    if (!regexSafe(w.path) || safeText(w.path) !== w.path || !WORKFLOW_FILE.test(w.path)) continue;
    const doc = await ctx.read.yaml(w.path);
    if ('fail' in doc) continue;
    const events = parseOn(doc.ok.on ?? doc.ok.true);
    events.delete('workflow_call'); // a reusable workflow runs when it is called; its callers carry it
    if (events.size === 0) continue;
    await walkWorkflow(ctx, doc.ok, w.path, fitOf(events, p.defaultBranch, w.deploys), 0, '');
  }
  const hooks = await readHooks(ctx);
  return needs.map((need) => {
    if (need.layer === 'pre-commit') return hookCoverage(need, hooks, p.services);
    if (need.category === 'gate') return { need, status: 'missing', why: GATE_WHY };
    if (need.category === 'deploy-verify') return { need, status: 'missing', why: DEPLOY_VERIFY_WHY };
    return ciCoverage(need, need.layer, ctx.hits, p.services, ctx.budget.truncated);
  });
}
