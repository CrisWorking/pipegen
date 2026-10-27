// Coverage mapper (Plan U Task 1): which floor needs a repo's existing workflows and git hooks already cover.
//
// Rules (plan + pre-flight rulings S1-S6, S26; review rulings U1-U5):
// - covered: a matching tool runs on the right trigger for the layer, unconditionally, and fails the run when it finds
//   something. Push layer = every push to any branch; merge layer = pull_request to the default branch; deploy layer =
//   a workflow that deploys, or runs on push to the default branch, on a tag push or on release. A `paths` or
//   `paths-ignore` filter makes the event the wrong trigger. Pre-commit = the active hook manager's pre-commit hook
//   runs a matching tool; `hooks` = a hook manager exists (p.precommit).
// - partial: the right tool on the wrong trigger (pull_request_target, workflow_dispatch, schedule, a push filter that
//   leaves out feature branches, a paths filter), or a run that can't block: continue-on-error, `|| true` / `|| :` /
//   `|| exit 0` / `set +e`, a soft-fail flag or input, a tool that only fails when told to (trivy, grype, semgrep scan,
//   the trufflehog CLI, the ZAP actions) or never fails (CodeQL, ruling U5), or a job or step `if:` other than status
//   functions and a fork guard. A need that is not blocking (format-lint) only cares whether the tool runs.
// - unknown: a remote reusable workflow, an action from the repo owner's own account (likely a composite action), a
//   second-level local call, a local call pipegen refused or couldn't read, a listed workflow that couldn't be read
//   again (or that readWorkflows skipped: opts.skippedWorkflows), or more workflow text than the budget.
// - missing: nothing matches. `gate` and `deploy-verify` are always missing: they are pipegen's own checks.
// A tool counts only where a command starts: at the line start, after ; && || | & ( $( { or a wrapper (npx, sudo, env
// VAR=…, time, pnpm/yarn dlx, uv run, pipx run, python -m, sh/bash, …), as the basename of a path, or as the image
// after `docker run [flags]`. A `run:` step's directory is its working-directory, else the job's or workflow's
// defaults.run working-directory, then `cd <dir>`; the tool covers only the service under that directory (S26).
// `uses:` steps, composite actions and called workflows start at the repo root (U3).
//
// Hostile input: workflow, action and hook files are attacker-controlled. They are read only by path from the list
// readProject made (p.existingWorkflows) plus local `uses: ./…` targets, every path level checked for symbolic links,
// the real path checked to stay inside the repo, through the read limits (1 MB, binary refused, YAML alias cap), with
// jobs, steps, files, findings and scanned bytes capped. Regexes are linear and only run on lines of 4 KB or less; the
// shell scan is one tokenising pass per line plus bounded look-ahead.
// Output follows the src/types.ts rule, RAW but VALIDATED, cleaned at output: `why` is pipegen's own text only
// (including a signature's `partialWhy`, from pipegen's data file); `by` is a tool-signature id from
// data/tool-signatures.yml, an own-script phrase built from fixed words, a hook manager name, or a repo `uses:` value
// kept only when it matches REF_RE (ASCII letters, digits and . _ - / @; at most 200 characters; unchanged by safeText);
// `where` joins workflow and action paths that are unchanged by safeText with job ids that pass JOB_ID_RE (else "#n"),
// cut to MAX_WHERE code points. Task 3 still cleans `by` and `where` with safeText / safeMarkdown when it prints them.
//
// mapCoverage throws when data/tool-signatures.yml is missing or invalid (loadToolSignatures); the caller (Plan U
// Task 2) must catch that and say so plainly.
import { readFileSync } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { join, posix, sep } from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import { READ_LIMITS, linkedLevel, parseYamlLimited, readTextLimitedWithReason, regexSafe } from '../read/limits.js';
import { asObj, type Obj } from '../read/manifest.js';
import { JOB_ID_RE, MAX_WORKFLOWS, TRIGGER_RE, WORKFLOW_FILE } from '../read/workflows.js';
import { NEED_CATEGORIES, type Layer, type Need, type RepoProfile, type Service } from '../types.js';
import { packageDataPath } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';

export interface Coverage { need: Need; status: 'covered' | 'partial' | 'missing' | 'unknown'; by?: string; where?: string; why: string }

export interface MapCoverageOptions {
  /** How many workflow files readWorkflows skipped (unreadable, over the cap): rows that would be missing say unknown. */
  skippedWorkflows?: number;
}

// ---------- tool signatures (ruling S1) ----------

const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PART_RE = /^[A-Za-z0-9_.-]+$/;
const LAST_PART_RE = /^[A-Za-z0-9_.-]+\*?$/;
const FLAG_RE = /^-{1,2}[A-Za-z0-9][A-Za-z0-9-]*(?:=[A-Za-z0-9._-]+)?$/;
const INPUT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const INPUT_VALUE_RE = /^(?:\*|[a-z0-9._ -]{1,64})$/;
const WHY_RE = /^[A-Z][^\n\r]{0,299}\.$/;

/** owner/name, optionally with a sub-path; the last part may end with * (a prefix: snyk/actions/python*). */
function isActionRef(s: string): boolean {
  const parts = s.split('/');
  return s.length <= 200 && parts.length >= 2
    && parts.every((x, i) => (i === parts.length - 1 ? LAST_PART_RE : PART_RE).test(x) && x !== '.' && x !== '..');
}
/** Words of [A-Za-z0-9_.-] joined by one space or one slash, e.g. "gitleaks", "npm audit", ".husky/pre-commit". */
function isCommand(s: string): boolean {
  return s.length <= 64 && s.split(/[ /]/).every((x) => PART_RE.test(x));
}

const inputs = z.record(z.string().regex(INPUT_RE), z.array(z.string().regex(INPUT_VALUE_RE)).min(1));

const signatureSchema = z.strictObject({
  id: z.string().regex(ID_RE),
  categories: z.array(z.enum(NEED_CATEGORIES)).min(1),
  actions: z.array(z.string().refine(isActionRef, 'must be owner/name[/sub]')).min(1).optional(),
  commands: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
  /** Longer commands that start like one of `commands` but are not this check (npm audit signatures). */
  excludes: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
  /** default: a run fails on findings; flag: only with one of failFlags; never: it only reports. */
  commandFails: z.enum(['default', 'flag', 'never']).optional(),
  failFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Flags that stop a run from failing ("--exit-code=0" also matches "--exit-code 0"). */
  softFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** default: the action fails on findings; input: only with one of failInputs; never: it only reports. */
  actionFails: z.enum(['default', 'input', 'never']).optional(),
  failInputs: inputs.optional(),
  /** `with:` inputs (name → lowercase values) that stop the action from failing. */
  softInputs: inputs.optional(),
  /** pipegen's own sentence for a run that can never block (commandFails or actionFails never). */
  partialWhy: z.string().regex(WHY_RE).refine((s) => safeText(s, 300) === s, 'must be plain text').optional(),
})
  .refine((t) => t.actions !== undefined || t.commands !== undefined, { message: 'needs actions or commands' })
  .refine((t) => t.commandFails !== 'flag' || t.failFlags !== undefined, { message: 'commandFails: flag needs failFlags' })
  .refine((t) => t.actionFails !== 'input' || t.failInputs !== undefined, { message: 'actionFails: input needs failInputs' })
  .refine((t) => t.excludes === undefined || t.commands !== undefined, { message: 'excludes needs commands' });

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

const WORD_CHARS = 'A-Za-z0-9_.-';
const NOT_WORD = `(?![${WORD_CHARS}])`;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
/** " audit" → /\s+audit(?!word char)/y, matched right after the first word. */
const restRegex = (tail: string) => new RegExp(`${tail.split(' ').map(escapeRe).join('\\s+')}${NOT_WORD}`, 'y');

/** One way to recognise a command: the first word (or a whole path), then the rest anchored after it. */
interface CommandRule { tool: ToolSignature; rest: RegExp | null; excludes: RegExp[] }
interface ActionRule { tool: ToolSignature; parts: string[]; prefixLast: boolean }
interface Compiled { byFirstWord: Map<string, CommandRule[]>; byPath: Map<string, CommandRule[]>; actions: ActionRule[] }

function compile(tools: ToolSignature[]): Compiled {
  const byFirstWord = new Map<string, CommandRule[]>();
  const byPath = new Map<string, CommandRule[]>();
  const actions: ActionRule[] = [];
  const firstOf = (cmd: string) => cmd.split(' ')[0] as string;
  for (const tool of tools) {
    for (const cmd of tool.commands ?? []) {
      const first = firstOf(cmd);
      const tail = cmd.slice(first.length);
      const excludes = (tool.excludes ?? []).filter((e) => firstOf(e) === first && e.length > first.length).map((e) => restRegex(e.slice(first.length)));
      const rule: CommandRule = { tool, rest: tail === '' ? null : restRegex(tail), excludes };
      // A command whose first word is a path (.husky/pre-commit) matches the whole path; any other its basename.
      const map = first.includes('/') ? byPath : byFirstWord;
      map.set(first, [...(map.get(first) ?? []), rule]);
    }
    for (const a of tool.actions ?? []) {
      const parts = a.toLowerCase().split('/');
      const last = parts[parts.length - 1] as string;
      const prefixLast = last.endsWith('*');
      if (prefixLast) parts[parts.length - 1] = last.slice(0, -1);
      actions.push({ tool, parts, prefixLast });
    }
  }
  return { byFirstWord, byPath, actions };
}

let defaultCompiled: Compiled | undefined;

// ---------- bounds ----------

const MAX_JOBS = 100;              // per workflow
const MAX_STEPS = 200;             // per job or composite action
const MAX_STEP_VISITS = 50_000;    // per mapCoverage call, followed files included
const MAX_SCAN_BYTES = 16_000_000; // run text scanned per mapCoverage call (worst case about 2 s of adversarial text)
const MAX_LOCAL_FILES = 100;       // distinct local workflows and actions followed
const MAX_HOOKS = 200;             // pre-commit repos, hooks per repo, lefthook commands
const MAX_FILTER_PATTERNS = 100;
const MAX_GLOB = 256;
const MAX_WHERE = 300;
const MAX_DIR = 512;               // a tracked directory longer than this is unknown (a chain of cd's can't grow it)
const MAX_HITS = 100_000;          // tool and opaque findings kept per mapCoverage call
const MAX_FLAG_WORDS = 64;         // words after a command read for its flags

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
  workflowsUnreadable: "Some workflow files couldn't be read, so pipegen can't tell.",
  hookUnreadable: "The git hook file couldn't be read (a symbolic link, too large or not valid), so pipegen can't tell.",
} as const;

const LAYER_DONE: Readonly<Record<Exclude<Layer, 'pre-commit'>, string>> = {
  push: 'on every push',
  merge: 'on every pull request',
  deploy: 'when the code is deployed or released',
};

/** Why a run that is found can't block anything (or might not run). */
type Reason = 'continue' | 'suppressed' | 'soft' | 'no-fail' | 'never' | 'condition';
const REASON_WHY: Readonly<Record<Reason, (subject: string, when: string) => string>> = {
  continue: (s) => `${s} runs, but is allowed to fail (continue-on-error), so it can't block anything.`,
  suppressed: (s) => `${s} runs, but its exit code is ignored (|| true, || exit 0 or set +e), so it can't block anything.`,
  soft: (s) => `${s} runs, but is set not to fail on findings, so it can't block anything.`,
  'no-fail': (s) => `${s} runs, but doesn't fail on findings unless told to, so it can't block anything.`,
  never: (s) => `${s} reports findings but doesn't fail the job, so it can't block anything.`,
  condition: (s, when) => `${s} runs only when a condition holds, so it may not run ${when}.`,
};

const HOOK_PLACE = { 'pre-commit': 'the pre-commit framework', husky: 'the husky pre-commit hook', lefthook: 'the lefthook pre-commit hook' } as const;
const HOOK_NAME = { 'pre-commit': 'the pre-commit framework', husky: 'husky', lefthook: 'lefthook' } as const;
const HOOK_FILE = { 'pre-commit': '.pre-commit-config.yaml', husky: '.husky', lefthook: 'lefthook.yml' } as const;

// ---------- small helpers ----------

type Manager = NonNullable<RepoProfile['precommit']>;
type CiLayer = Exclude<Layer, 'pre-commit'>;
type Fit = Record<CiLayer, boolean>;

/** A tool found in shell text or a step. `reason` null = it runs and can fail the run. */
interface Found { categories: readonly string[]; by: string; subject: string; dir: string | null; reason: Reason | null; partialWhy?: string }
interface Hit {
  opaque: boolean;
  categories: readonly string[];
  by?: string;
  subject: string;
  dir: string | null;
  reason: Reason | null;
  partialWhy?: string;
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
function allowedToFail(v: unknown): boolean {
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

// ---------- if: conditions (review I3) ----------

type Cond = 'none' | 'never' | 'partial';
const STATUS_FN = /^!?\s*(?:always|success|cancelled)\(\s*\)$/;
const FORK_GUARD = /^github\.repository(?:_owner)?\s*==\s*(?:'[^']*'|"[^"]*")$/;

/** Trims spaces and outer parentheses with a loop (no regex backtracking on long runs of parentheses). */
function stripParens(s: string): string {
  let a = 0;
  let b = s.length;
  for (;;) {
    while (a < b && /\s/.test(s[a] as string)) a++;
    while (b > a && /\s/.test(s[b - 1] as string)) b--;
    if (a < b && s[a] === '(' && s[b - 1] === ')') {
      a++;
      b--;
    } else return s.slice(a, b);
  }
}

/**
 * A job or step `if:`: false drops the run; status functions (always(), success(), !cancelled()) and a fork guard
 * (github.repository[_owner] == '…') are ignored; anything else (including failure(), which runs only after a failure)
 * means the run may not happen on every event.
 */
function condition(v: unknown): Cond {
  if (v === undefined || v === null || v === true) return 'none';
  if (v === false || v === 0) return 'never';
  if (typeof v !== 'string' || !regexSafe(v)) return 'partial';
  let s = v.trim();
  if (s.startsWith('${{') && s.endsWith('}}') && s.indexOf('${{', 3) < 0) s = s.slice(3, -2).trim();
  if (s === 'false') return 'never';
  if (s === 'true' || s === '') return 'none';
  const parts = s.split(/&&|\|\|/).map(stripParens);
  return parts.every((x) => STATUS_FN.test(x) || FORK_GUARD.test(x)) ? 'none' : 'partial';
}

// ---------- soft-fail settings (review I1) ----------

const unquote = (w: string) => {
  let a = 0;
  let b = w.length;
  while (a < b && (w[a] === '"' || w[a] === "'")) a++;
  while (b > a && (w[b - 1] === '"' || w[b - 1] === "'")) b--;
  return w.slice(a, b);
};

/** "--fail" matches --fail and --fail=x; "--exit-code=0" matches --exit-code=0 and --exit-code 0. */
function flagGiven(spec: string, words: readonly string[]): boolean {
  const eq = spec.indexOf('=');
  if (eq < 0) return words.some((w) => w === spec || w.startsWith(`${spec}=`));
  const name = spec.slice(0, eq);
  const value = spec.slice(eq + 1);
  return words.some((w, i) => w === spec || (w === name && words[i + 1] === value));
}

function commandReason(tool: ToolSignature, words: readonly string[]): Reason | null {
  if ((tool.softFlags ?? []).some((f) => flagGiven(f, words))) return 'soft';
  if (tool.commandFails === 'never') return 'never';
  if (tool.commandFails === 'flag' && !(tool.failFlags ?? []).some((f) => flagGiven(f, words))) return 'no-fail';
  return null;
}

/** A `with:` value as lowercase text; an expression (`${{ }}`) can't be known. */
function inputText(v: unknown): string | null {
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  return typeof v === 'string' && regexSafe(v) ? v.trim().toLowerCase() : null;
}

/** Whether `with:` sets one of the inputs to a listed value. `exprCounts`: an expression counts (errs to "can't block"). */
function inputGiven(spec: Record<string, string[]> | undefined, w: Obj, exprCounts: boolean): boolean {
  for (const [name, values] of Object.entries(spec ?? {})) {
    if (!Object.hasOwn(w, name)) continue;
    const s = inputText(w[name]);
    if (s === null) continue;
    if (s.includes('${{')) {
      if (exprCounts) return true;
      continue;
    }
    if (values.includes(s) || values.includes('*')) return true;
  }
  return false;
}

function actionReason(tool: ToolSignature, w: Obj): Reason | null {
  if (inputGiven(tool.softInputs, w, true)) return 'soft';
  if (tool.actionFails === 'never') return 'never';
  if (tool.actionFails === 'input' && !inputGiven(tool.failInputs, w, false)) return 'no-fail';
  return null;
}

const foundOf = (tool: ToolSignature, dir: string | null, reason: Reason | null): Found => ({
  categories: tool.categories, by: tool.id, subject: `The ${tool.id} check`, dir, reason,
  ...(tool.partialWhy === undefined ? {} : { partialWhy: tool.partialWhy }),
});

// ---------- reading shell text (review M2: command position only) ----------

// Shell tokens: $( && || and single separators, else a run of anything that isn't space or a separator.
const SHELL_TOKEN = /\$\(|&&|\|\||[;|&(){}`]|[^\s;|&(){}`]+/g;
const STARTS = new Set(['$(', '&&', '||', ';', '|', '&', '(', '{', '`']);
const ENDS = new Set([')', '}']);
/** Tokens that end an and-or list: a later `|| true` doesn't reach a command before them. */
const LIST_END = new Set([';', '&', '`']);
const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** Words after which the next non-flag word is a command. `env` also skips VAR=value words. */
const WRAPPERS = new Set(['sudo', 'time', 'npx', 'bunx', 'uvx', 'env', 'nohup', 'exec', 'command', 'xargs', 'sh', 'bash', 'zsh', 'dash']);
/** Two-word wrappers: pnpm dlx, uv run, python -m, … */
const SUB_WRAPPERS: Readonly<Record<string, readonly string[]>> = {
  pnpm: ['dlx', 'exec'], yarn: ['dlx', 'exec'], npm: ['exec'], bun: ['x'], uv: ['run'], pipx: ['run'], poetry: ['run'],
  pdm: ['run'], hatch: ['run'], python: ['-m'], python3: ['-m'],
};
/** `yarn eslint .` and `pnpm eslint .` run a package binary: the next word is a command too. */
const BIN_RUNNERS = new Set(['yarn', 'pnpm']);
const DOCKER_VALUE_FLAGS = new Set(['-v', '--volume', '-e', '--env', '--env-file', '-w', '--workdir', '-u', '--user', '-p', '--publish', '--name',
  '--entrypoint', '--network', '--platform', '--mount', '-l', '--label', '--add-host', '--pull', '-m', '--memory', '--cpus', '--cidfile', '-h', '--hostname']);
// The service's own scripts (ruling S5), keyed by first word; the rest is matched right after it.
const OWN_SCRIPT: Readonly<Record<string, RegExp | null>> = {
  npm: new RegExp(`\\s+(?:test|run\\s+(?:test|lint))${NOT_WORD}`, 'y'),
  pnpm: new RegExp(`\\s+(?:run\\s+)?(?:test|lint)${NOT_WORD}`, 'y'),
  yarn: new RegExp(`\\s+(?:run\\s+)?(?:test|lint)${NOT_WORD}`, 'y'),
  bun: new RegExp(`\\s+(?:run\\s+)?(?:test|lint)${NOT_WORD}`, 'y'),
  python: new RegExp(`\\s+-m\\s+pytest${NOT_WORD}`, 'y'),
  python3: new RegExp(`\\s+-m\\s+pytest${NOT_WORD}`, 'y'),
  pytest: null,
};
const TEST_CATEGORIES = ['unit-tests', 'full-tests'] as const;

const basename = (w: string) => w.slice(w.lastIndexOf('/') + 1);
/** The image's name: no registry or owner, no :tag or @digest (ghcr.io/zricethezav/gitleaks:v8 → gitleaks). */
function imageName(image: string): string {
  const at = image.indexOf('@');
  const noDigest = at < 0 ? image : image.slice(0, at);
  const name = basename(noDigest);
  const colon = name.indexOf(':');
  return colon < 0 ? name : name.slice(0, colon);
}

/** Lines with `\` continuations joined; a logical line over 4 KB is skipped. */
function logicalLines(text: string): string[] {
  const out: string[] = [];
  let parts: string[] = [];
  let size = 0;
  const flush = () => {
    const line = parts.join(' ');
    if (size <= READ_LIMITS.maxRegexLineBytes && regexSafe(line)) out.push(line);
    parts = [];
    size = 0;
  };
  for (const raw of text.split(/\r?\n/)) {
    const cont = raw.endsWith('\\');
    const piece = cont ? raw.slice(0, -1) : raw;
    size += piece.length + 1;
    if (size <= READ_LIMITS.maxRegexLineBytes) parts.push(piece);
    if (!cont) flush();
  }
  if (parts.length > 0) flush();
  return out;
}

interface Budget { visits: number; bytes: number; truncated: boolean }

/**
 * Tools found in shell text (a run step, a hook script, a hook entry). A tool counts only in command position (see the
 * module header). `cd <dir>` moves the directory for the rest of the text; `set +e` turns off errexit for the rest.
 */
function scanShell(text: string, base: string | null, sigs: Compiled, budget: Budget): Found[] {
  budget.bytes += text.length;
  if (budget.bytes > MAX_SCAN_BYTES) {
    budget.truncated = true;
    return [];
  }
  const found: Found[] = [];
  const seen = new Set<string>(); // one finding per tool, directory and reason per text
  const add = (f: Found) => {
    const key = `${f.by}\u0000${f.dir ?? ''}\u0000${f.reason ?? ''}`;
    if (!seen.has(key)) {
      seen.add(key);
      found.push(f);
    }
  };
  let cwd = base;
  let errexitOff = false;
  for (const line of logicalLines(text)) {
    const toks: { t: string; i: number }[] = [];
    for (const m of line.matchAll(SHELL_TOKEN)) {
      if (m[0].startsWith('#')) break; // a comment runs to the end of the line
      toks.push({ t: m[0], i: m.index });
    }
    const n = toks.length;
    const word = (k: number) => (k < n && !STARTS.has(toks[k]!.t) && !ENDS.has(toks[k]!.t) ? unquote(toks[k]!.t) : null);
    // Right to left: where each command's words end, and whether a later `|| true` / `|| :` / `|| exit 0` in the same
    // and-or list swallows its exit code.
    const segEnd = new Int32Array(n);
    const swallowed = new Uint8Array(n);
    let end = n;
    let swallow = 0;
    for (let k = n - 1; k >= 0; k--) {
      const t = toks[k]!.t;
      if (LIST_END.has(t)) swallow = 0;
      if (t === '||') {
        const a = word(k + 1);
        if (a === 'true' || a === ':' || (a === 'exit' && word(k + 2) === '0')) swallow = 1;
      }
      if (STARTS.has(t) || ENDS.has(t)) end = k;
      segEnd[k] = end;
      swallowed[k] = swallow;
    }
    const argsAfter = (k: number) => {
      const out: string[] = [];
      for (let j = k + 1; j < Math.min(segEnd[k]!, k + 1 + MAX_FLAG_WORDS); j++) out.push(unquote(toks[j]!.t));
      return out;
    };
    const ruleReason = (k: number, tool: ToolSignature): Reason | null => (swallowed[k] || errexitOff ? 'suppressed' : commandReason(tool, argsAfter(k)));
    /** Signatures and own scripts for the command word at k (`name` = its basename, or an image name). */
    const match = (k: number, w: string, name: string) => {
      const at = toks[k]!.i + toks[k]!.t.length;
      const tryRules = (rules: CommandRule[] | undefined) => {
        for (const r of rules ?? []) {
          if (r.rest !== null) {
            r.rest.lastIndex = at;
            if (!r.rest.test(line)) continue;
          }
          if (r.excludes.some((x) => ((x.lastIndex = at), x.test(line)))) continue;
          add(foundOf(r.tool, cwd, ruleReason(k, r.tool)));
        }
      };
      if (w.includes('/')) tryRules(sigs.byPath.get(w.replace(/^(?:\.\/)+/, '')));
      tryRules(sigs.byFirstWord.get(name));
      if (w === name && Object.hasOwn(OWN_SCRIPT, name)) {
        const rest = OWN_SCRIPT[name] as RegExp | null;
        let stop = at;
        if (rest !== null) {
          rest.lastIndex = at;
          if (!rest.test(line)) return;
          stop = rest.lastIndex;
        }
        // Only fixed words and whitespace were matched, so the phrase is safe to show; whitespace becomes one space.
        const cmd = line.slice(toks[k]!.i, stop).split(/\s+/).join(' ');
        const categories = cmd.endsWith('lint') ? ['lint'] : TEST_CATEGORIES;
        add({ categories, by: `your own \`${cmd}\``, subject: `Your own \`${cmd}\``, dir: cwd, reason: swallowed[k] || errexitOff ? 'suppressed' : null });
      }
    };
    const skipFlags = (k: number, assigns: boolean) => {
      let j = k;
      for (let w = word(j); w !== null && (w.startsWith('-') || (assigns && ASSIGN.test(w))); w = word(j)) j++;
      return j;
    };

    let cmd = true;
    let k = 0;
    while (k < n) {
      const t = toks[k]!.t;
      if (STARTS.has(t)) {
        cmd = true;
        k++;
        continue;
      }
      if (ENDS.has(t) || !cmd) {
        cmd = false;
        k++;
        continue;
      }
      const w = unquote(t);
      if (ASSIGN.test(w)) { // VAR=value before a command
        k++;
        continue;
      }
      const name = basename(w);
      if (w === 'cd') {
        const target = word(k + 1);
        cwd = target === null || target === '' || target === '-' || /[$`~\\]/.test(target) || target.startsWith('/') ? null : resolveDir(cwd, target);
        cmd = false;
        k += target === null ? 1 : 2;
        continue;
      }
      if (w === 'set') {
        const opt = word(k + 1) ?? '';
        if (/^\+[a-z]*e/.test(opt) || (opt === '+o' && word(k + 2) === 'errexit')) errexitOff = true;
        else if (/^-[a-z]*e/.test(opt) || (opt === '-o' && word(k + 2) === 'errexit')) errexitOff = false;
        cmd = false;
        k++;
        continue;
      }
      match(k, w, name);
      const next = word(k + 1);
      if (name === 'docker' && next === 'run') {
        let j = k + 2;
        for (let f = word(j); f !== null && f.startsWith('-'); f = word(j)) j += !f.includes('=') && DOCKER_VALUE_FLAGS.has(f) ? 2 : 1;
        const image = word(j);
        if (image !== null) match(j, image, imageName(image));
        k = j + 1; // the container's command follows the image
        cmd = true;
        continue;
      }
      if (next !== null && SUB_WRAPPERS[name]?.includes(next)) {
        k = skipFlags(k + 2, false);
        cmd = true;
        continue;
      }
      if (WRAPPERS.has(name)) {
        k = skipFlags(k + 1, name === 'env');
        cmd = true;
        continue;
      }
      cmd = BIN_RUNNERS.has(name);
      k++;
    }
  }
  return found;
}

/** A `uses: docker://image` step: the image name as a command, with `with.args` as its flags. */
function scanImage(uses: string, w: Obj, sigs: Compiled): Found[] {
  const name = imageName(uses.slice('docker://'.length));
  const args = typeof w.args === 'string' && regexSafe(w.args) ? w.args.split(/\s+/).slice(0, MAX_FLAG_WORDS).map(unquote) : [];
  return (sigs.byFirstWord.get(name) ?? []).filter((r) => r.rest === null).map((r) => foundOf(r.tool, '.', commandReason(r.tool, args)));
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

const isSet = (cfg: Obj, key: string) => key in cfg && cfg[key] !== null;

/** Whether a push or pull_request filter lets `name` through (`branches` and `branches-ignore` together are invalid). */
function branchFilter(cfg: Obj): (name: string) => boolean {
  const hasB = isSet(cfg, 'branches');
  const hasBi = isSet(cfg, 'branches-ignore');
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
/** A `paths` or `paths-ignore` filter: the event doesn't run on every change, so it isn't the right trigger (review I2). */
const pathFiltered = (cfg: Obj) => isSet(cfg, 'paths') || isSet(cfg, 'paths-ignore');

function fitOf(events: Map<string, Obj>, defaultBranch: string, deploys: boolean): Fit {
  let everyPush = false;
  let pushDefault = false;
  let pushTags = false;
  const push = events.get('push');
  if (push && !pathFiltered(push)) {
    const branchesSet = isSet(push, 'branches') || isSet(push, 'branches-ignore');
    pushTags = isSet(push, 'tags') || isSet(push, 'tags-ignore');
    // A push trigger with only a tag filter never runs for branch pushes.
    const includes = !branchesSet && pushTags ? () => false : branchFilter(push);
    everyPush = FEATURE_BRANCHES.every(includes);
    pushDefault = includes(defaultBranch);
  }
  const pr = events.get('pull_request');
  const types = pr ? strs(pr.types) : [];
  const merge = pr !== undefined && !pathFiltered(pr) && branchFilter(pr)(defaultBranch) && (types.length === 0 || types.includes('synchronize'));
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

// ---------- walking workflows (rulings S3, S26, U3) ----------

interface Ctx { p: RepoProfile; sigs: Compiled; read: Reader; budget: Budget; hits: Hit[]; localFiles: Set<string>; unreadable: boolean }
interface StepCtx {
  fit: Fit;
  where: string;
  /** Where `run:` steps start: defaults.run.working-directory of the job or workflow, else the root. */
  runDir: string | null;
  continueOnError: boolean;
  conditional: boolean;
  depth: number;
}

function spend(ctx: Ctx): boolean {
  if (ctx.budget.visits >= MAX_STEP_VISITS) {
    ctx.budget.truncated = true;
    return false;
  }
  ctx.budget.visits++;
  return true;
}

/** Something pipegen can't see inside. It runs from the repo root, so it may cover any service. */
function opaque(ctx: Ctx, why: string, by: string | undefined, c: { fit: Fit; where: string }): void {
  if (ctx.hits.length >= MAX_HITS) {
    ctx.budget.truncated = true;
    return;
  }
  ctx.hits.push({ opaque: true, categories: [], ...(by === undefined ? {} : { by }), subject: '', dir: '.', reason: null, fit: c.fit, where: c.where, why });
}

function addFound(ctx: Ctx, found: Found[], c: StepCtx): void {
  if (ctx.hits.length + found.length > MAX_HITS) {
    ctx.budget.truncated = true;
    return;
  }
  for (const f of found) {
    const reason: Reason | null = c.continueOnError ? 'continue' : (f.reason ?? (c.conditional ? 'condition' : null));
    ctx.hits.push({
      opaque: false, categories: f.categories, by: f.by, subject: f.subject, dir: f.dir, reason,
      ...(f.partialWhy === undefined ? {} : { partialWhy: f.partialWhy }), fit: c.fit, where: c.where,
    });
  }
}

/** Signatures listing exactly this `uses:` path (owner/name[/sub], case-insensitive, @ref ignored); `x*` is a prefix. */
function actionMatches(sigs: Compiled, uses: string): ToolSignature[] {
  const at = uses.indexOf('@');
  const parts = (at < 0 ? uses : uses.slice(0, at)).toLowerCase().split('/');
  if (parts.length < 2 || !parts.every((x) => PART_RE.test(x))) return [];
  const out: ToolSignature[] = [];
  for (const a of sigs.actions) {
    if (a.parts.length !== parts.length || out.includes(a.tool)) continue;
    const last = a.parts.length - 1;
    if (a.parts.every((x, i) => (i === last && a.prefixLast ? (parts[i] as string).startsWith(x) : parts[i] === x))) out.push(a.tool);
  }
  return out;
}

async function walkStep(ctx: Ctx, step: Obj, c: StepCtx): Promise<void> {
  if (!spend(ctx)) return;
  const cond = condition(step.if);
  if (cond === 'never') return;
  const sc: StepCtx = { ...c, continueOnError: c.continueOnError || allowedToFail(step['continue-on-error']), conditional: c.conditional || cond === 'partial' };
  const withInputs = asObj(step.with);
  if (typeof step.uses === 'string' && regexSafe(step.uses)) {
    const uses = step.uses.trim();
    if (uses === '.' || uses.startsWith('./')) {
      await followAction(ctx, uses, sc);
    } else if (uses.startsWith('docker://')) {
      addFound(ctx, scanImage(uses, withInputs, ctx.sigs), sc);
    } else {
      const tools = actionMatches(ctx.sigs, uses);
      addFound(ctx, tools.map((t) => foundOf(t, '.', actionReason(t, withInputs))), sc);
      const owner = uses.split('/')[0]?.toLowerCase();
      if (tools.length === 0 && owner !== undefined && owner === ctx.p.owner.toLowerCase()) opaque(ctx, OPAQUE_WHY.ownerAction, validRef(uses), sc);
    }
  }
  if (typeof step.run === 'string') {
    const base = firstSet(workingDir(step['working-directory']), c.runDir);
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
  // A composite action's run steps start at the repo root (plus their own working-directory), not at the job's default.
  for (const step of list(runs.steps).slice(0, MAX_STEPS)) await walkStep(ctx, asObj(step), { ...c, where, runDir: '.', depth: 1 });
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

async function walkWorkflow(ctx: Ctx, doc: Obj, path: string, fit: Fit, depth: number, prefix: string, conditional: boolean): Promise<void> {
  const wfDir = defaultsDir(doc);
  const jobs = Object.entries(asObj(doc.jobs));
  if (jobs.length > MAX_JOBS) ctx.budget.truncated = true;
  for (const [i, [id, raw]] of jobs.slice(0, MAX_JOBS).entries()) {
    const job = asObj(raw);
    const cond = condition(job.if);
    if (cond === 'never') continue;
    const label = regexSafe(id) && JOB_ID_RE.test(id) ? id : `#${i + 1}`;
    const where = cut(`${prefix}${path} (job ${label})`);
    const jobConditional = conditional || cond === 'partial';
    if (typeof job.uses === 'string' && regexSafe(job.uses)) {
      await callWorkflow(ctx, job.uses.trim(), { fit, where, runDir: '.', continueOnError: false, conditional: jobConditional, depth });
      continue;
    }
    const steps = list(job.steps);
    if (steps.length > MAX_STEPS) ctx.budget.truncated = true;
    const c: StepCtx = { fit, where, runDir: firstSet(defaultsDir(job), wfDir), continueOnError: allowedToFail(job['continue-on-error']), conditional: jobConditional, depth };
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
  // The called workflow runs on the caller's event (and only when the calling job's `if:` holds).
  await walkWorkflow(ctx, doc.ok, rel, c.fit, 1, `${c.where} → `, c.conditional);
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
        // the hook id and its entry are each read as a command line of their own
        found.push(...scan([hook.id, hook.entry].filter((x): x is string => typeof x === 'string').join('\n')));
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

/** The reason that counts for this need: a need that doesn't block (format-lint) only cares whether the tool runs. */
const effectiveReason = (need: Need, reason: Reason | null): Reason | null => (need.blocking || reason === 'condition' ? reason : null);

function reasonWhy(h: { subject: string; partialWhy?: string }, reason: Reason, when: string): string {
  return reason === 'never' && h.partialWhy !== undefined ? h.partialWhy : REASON_WHY[reason](h.subject, when);
}

function ciCoverage(need: Need, layer: CiLayer, hits: Hit[], services: Service[], ctx: { truncated: boolean; unreadable: boolean }): Coverage {
  let partialRight: { h: Hit; reason: Reason } | undefined;
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
    const reason = effectiveReason(need, h.reason);
    if (right && reason === null) return { need, status: 'covered', ...located(h), why: `${h.subject} runs ${LAYER_DONE[layer]}.` };
    if (right) partialRight ??= { h, reason: reason as Reason };
    else partialTrigger ??= h;
  }
  if (strongOpaque) return { need, status: 'unknown', ...located(strongOpaque), why: strongOpaque.why as string };
  if (ctx.truncated) return { need, status: 'unknown', why: OPAQUE_WHY.truncated };
  if (partialRight) return { need, status: 'partial', ...located(partialRight.h), why: reasonWhy(partialRight.h, partialRight.reason, LAYER_DONE[layer]) };
  if (partialTrigger) return { need, status: 'partial', ...located(partialTrigger), why: `${partialTrigger.subject} runs, but not ${LAYER_DONE[layer]}.` };
  if (weakOpaque) return { need, status: 'unknown', ...located(weakOpaque), why: weakOpaque.why as string };
  if (ctx.unreadable) return { need, status: 'unknown', why: OPAQUE_WHY.workflowsUnreadable };
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
    let partial: { f: Found; reason: Reason } | undefined;
    for (const f of hooks.found) {
      if (!f.categories.includes(need.category) || !appliesTo(f.dir, need.service, services)) continue;
      const reason = effectiveReason(need, f.reason);
      if (reason === null) return { need, status: 'covered', by: f.by, where: hooks.where, why: `${f.subject} runs in ${HOOK_PLACE[m]} before each commit.` };
      partial ??= { f, reason };
    }
    if (partial) return { need, status: 'partial', by: partial.f.by, where: hooks.where, why: reasonWhy(partial.f, partial.reason, 'before each commit') };
    if (!hooks.readable) return { need, status: 'unknown', where: hooks.where, why: OPAQUE_WHY.hookUnreadable };
  }
  return { need, status: 'missing', why: missingWhy(need) };
}

/**
 * One Coverage per need, in order. Reads only the workflows in p.existingWorkflows (the list readProject made), the
 * local workflows and actions they call (one level), and the active hook manager's pre-commit hook. Pass the number
 * of workflow files readWorkflows skipped (its notes) as `opts.skippedWorkflows`. Throws when pipegen's tool
 * signatures can't be loaded.
 */
export async function mapCoverage(p: RepoProfile, needs: Need[], dir: string, opts: MapCoverageOptions = {}): Promise<Coverage[]> {
  const sigs = (defaultCompiled ??= compile(loadToolSignatures()));
  const ctx: Ctx = {
    p, sigs, read: new Reader(dir), budget: { visits: 0, bytes: 0, truncated: false }, hits: [], localFiles: new Set(),
    unreadable: (opts.skippedWorkflows ?? 0) > 0,
  };
  if (p.existingWorkflows.length > MAX_WORKFLOWS) ctx.budget.truncated = true;
  for (const w of [...p.existingWorkflows].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).slice(0, MAX_WORKFLOWS)) {
    // A listed workflow that fails the path check or can't be read again is never skipped silently (review M1).
    if (!regexSafe(w.path) || safeText(w.path) !== w.path || !WORKFLOW_FILE.test(w.path)) {
      ctx.unreadable = true;
      continue;
    }
    const doc = await ctx.read.yaml(w.path);
    if ('fail' in doc) {
      ctx.unreadable = true;
      continue;
    }
    const events = parseOn(doc.ok.on ?? doc.ok.true);
    events.delete('workflow_call'); // a reusable workflow runs when it is called; its callers carry it
    if (events.size === 0) continue;
    await walkWorkflow(ctx, doc.ok, w.path, fitOf(events, p.defaultBranch, w.deploys), 0, '', false);
  }
  const hooks = await readHooks(ctx);
  const state = { truncated: ctx.budget.truncated, unreadable: ctx.unreadable };
  return needs.map((need) => {
    if (need.layer === 'pre-commit') return hookCoverage(need, hooks, p.services);
    if (need.category === 'gate') return { need, status: 'missing', why: GATE_WHY };
    if (need.category === 'deploy-verify') return { need, status: 'missing', why: DEPLOY_VERIFY_WHY };
    return ciCoverage(need, need.layer, ctx.hits, p.services, state);
  });
}
