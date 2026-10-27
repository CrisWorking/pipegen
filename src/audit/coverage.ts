// Coverage mapper (Plan U Task 1): which floor needs a repo's existing workflows and git hooks already cover.
//
// Rules (plan + pre-flight rulings S1-S6, S26; review rulings U1-U6):
// - covered: a matching tool runs on the right trigger for the layer, unconditionally, and its failure fails the run.
//   Push layer = every push to any branch; merge layer = pull_request to the default branch; deploy layer = a workflow
//   that deploys, or runs on push to the default branch, on a tag push or on release. A `paths` or `paths-ignore`
//   filter makes the event the wrong trigger. Pre-commit = the active hook manager's pre-commit hook runs a matching
//   tool; `hooks` = a hook manager exists (p.precommit).
// - partial: the right tool on the wrong trigger (pull_request_target, workflow_dispatch, schedule, a push filter that
//   leaves out feature branches, a paths filter), or a run whose failure can't fail the step:
//   - continue-on-error;
//   - shell: a `||` after it (unless the right side is `exit <non-zero>` or `false`), also for a `{ …; }` or `( … )`
//     group before the `||`; a `&&` after it outside the step's last list (bash -e ignores those); a pipe stage other
//     than the last without pipefail (the default shell and `shell: sh` have none; `shell: bash` and `set -o pipefail`
//     do); a background `&`; an `if`/`while`/`until` condition or `!`; `$( … )` or backticks other than `VAR=$( … )`;
//     a shell function body (it runs only where called); errexit off (`set +e`, or a custom `shell:` without -e such as
//     `bash {0}`, pwsh or python; a Windows `runs-on` without `shell:` means pwsh) unless it is in the step's last list.
//     `set` and `cd` inside `( … )` end with the subshell;
//   - a soft-fail flag or input (also inside `args` / `cmd_options` / `options` inputs), a tool that only fails when
//     told to (trivy, grype, semgrep scan, the trufflehog CLI, the ZAP actions) or never fails (CodeQL U5, the bandit
//     action);
//   - a job or step `if:` other than always(), success(), !cancelled() and a guard naming this repo.
//   A need that is not blocking (format-lint) only cares whether the tool runs.
// - unknown: a remote reusable workflow, an action from the repo owner's own account (likely a composite action), a
//   second-level local call, a local call pipegen refused or couldn't read, a listed workflow that couldn't be read
//   again (or that readWorkflows skipped: opts.skippedWorkflows), or more workflow text than the budget.
// - missing: nothing matches. `gate` and `deploy-verify` are always missing: they are pipegen's own checks.
// A tool counts only where a command starts: at the start, after ; && || | & ( $( { a newline, a shell keyword or a
// wrapper (npx, sudo, env, time, command without -v, pnpm/yarn dlx, uv run, pipx run, python -m, sh/bash, …), as the
// basename of a path, or as the image after `docker run [flags]`. Quoted text and here-document bodies never start a
// command; `2>&1`, `&>` and other redirections are words, not list ends. A version, help or completion call is not a
// run. A `run:` step's directory is its working-directory, else the job's or workflow's
// defaults.run working-directory, then `cd <dir>`; the tool covers only the service under that directory (S26).
// `uses:` steps, composite actions and called workflows start at the repo root (U3).
//
// Hostile input: workflow, action and hook files are attacker-controlled. They are read only by path from the list
// readProject made (p.existingWorkflows) plus local `uses: ./…` targets, every path level checked for symbolic links,
// the real path checked to stay inside the repo, through the read limits (1 MB, binary refused, YAML alias cap), with
// jobs, steps, files, findings and scanned bytes capped. Shell text is read by a hand-written, quote-aware tokenizer
// (one pass, no regex) and one right-to-left pass; words over 4 KB are kept opaque. The few regexes left are linear and
// run only on short values (lines or words of 4 KB or less).
// Output follows the src/types.ts rule, RAW but VALIDATED, cleaned at output: `why` is pipegen's own text only
// (including a signature's `partialWhy`, from pipegen's data file); `by` is a tool-signature id from
// data/tool-signatures.yml, an own-script phrase built from fixed words (plus a script name matching OWN_NAME_RE), a
// hook manager name, or a repo `uses:` value kept only when it matches REF_RE (ASCII letters, digits and . _ - / @; at
// most 200 characters; unchanged by safeText); `where` joins workflow and action paths that are unchanged by safeText
// with job ids that pass JOB_ID_RE (else "#n"), cut to MAX_WHERE code points. Task 3 still cleans `by` and `where` with
// safeText / safeMarkdown when it prints them.
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
/** Words of [A-Za-z0-9_.-] separated by one space; the first may be a path ("npm audit", ".husky/pre-commit"). */
function isCommand(s: string): boolean {
  const words = s.split(' ');
  return s.length <= 64 && words.every((x, i) => (i === 0 ? x.split('/').every((p) => PART_RE.test(p)) : PART_RE.test(x)));
}

/** `with:` inputs: name → lowercase values; `*` = any non-empty value. */
const inputs = z.record(z.string().regex(INPUT_RE), z.array(z.string().regex(INPUT_VALUE_RE)).min(1));

const signatureSchema = z.strictObject({
  id: z.string().regex(ID_RE),
  categories: z.array(z.enum(NEED_CATEGORIES)).min(1),
  actions: z.array(z.string().refine(isActionRef, 'must be owner/name[/sub]')).min(1).optional(),
  commands: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
  /** Longer commands that start like one of `commands` but are not this check (npm audit signatures, gitleaks version). */
  excludes: z.array(z.string().refine(isCommand, 'must be whole-word command names')).min(1).optional(),
  /** default: a run fails on findings; flag: only with one of failFlags; never: it only reports. */
  commandFails: z.enum(['default', 'flag', 'never']).optional(),
  failFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Flags that stop a run from failing ("--exit-code=0" also matches "--exit-code 0"); also read in action args inputs. */
  softFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** default: the action fails on findings; input: only with one of failInputs; never: it only reports. */
  actionFails: z.enum(['default', 'input', 'never']).optional(),
  failInputs: inputs.optional(),
  /** `with:` inputs set to one of these values stop the action from failing. */
  softInputs: inputs.optional(),
  /** `with:` inputs set to anything (non-empty) except these values stop the action from failing. */
  softUnless: inputs.optional(),
  /** pipegen's own sentence for a check that never fails the job (commandFails or actionFails never). */
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

/** One way to recognise a command: the first word (or a whole path), then the following words exactly. */
interface CommandRule { tool: ToolSignature; rest: string[]; excludes: string[][] }
interface ActionRule { tool: ToolSignature; parts: string[]; prefixLast: boolean }
interface Compiled { byFirstWord: Map<string, CommandRule[]>; byPath: Map<string, CommandRule[]>; actions: ActionRule[] }

function compile(tools: ToolSignature[]): Compiled {
  const byFirstWord = new Map<string, CommandRule[]>();
  const byPath = new Map<string, CommandRule[]>();
  const actions: ActionRule[] = [];
  for (const tool of tools) {
    for (const cmd of tool.commands ?? []) {
      const [first, ...rest] = cmd.split(' ') as [string, ...string[]];
      const excludes = (tool.excludes ?? []).map((e) => e.split(' ')).filter((e) => e[0] === first && e.length > 1).map((e) => e.slice(1));
      const rule: CommandRule = { tool, rest, excludes };
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
const MAX_SCAN_BYTES = 16_000_000; // run text scanned per mapCoverage call (worst case about 3 s of adversarial text)
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
type Reason = 'continue' | 'suppressed' | 'function' | 'soft' | 'no-fail' | 'never' | 'condition';
const REASON_WHY: Readonly<Record<Reason, (subject: string, when: string) => string>> = {
  continue: (s) => `${s} runs, but is allowed to fail (continue-on-error), so it can't block anything.`,
  suppressed: (s) => `${s} runs, but its exit code is ignored (by ||, a pipe, an if, set +e, the background & or the step's shell), so it can't block anything.`,
  function: (s) => `${s} runs inside a shell function, so pipegen can't tell whether its failure fails the step.`,
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
interface RepoId { owner: string; repo: string }
/** Conditions that hold on every normal run: always(), success(), !cancelled(). */
const STATUS_RUNS = /^(?:always|success)\(\s*\)$|^!\s*cancelled\(\s*\)$/;
/** A condition that never holds. */
const STATUS_NEVER = /^!\s*always\(\s*\)$/;
const REPO_GUARD = /^github\.repository(_owner)?\s*(==|!=)\s*(?:'([^']*)'|"([^"]*)")$/;

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

function atomCond(a: string, self: RepoId): Cond {
  if (a === 'true' || STATUS_RUNS.test(a)) return 'none';
  if (a === 'false' || STATUS_NEVER.test(a)) return 'never';
  const m = REPO_GUARD.exec(a);
  if (m) {
    // A guard naming this repo (or its owner) holds here; one naming another repo never does.
    const want = m[1] === undefined ? `${self.owner}/${self.repo}` : self.owner;
    const same = (m[3] ?? m[4] ?? '').toLowerCase() === want.toLowerCase();
    return same === (m[2] === '==') ? 'none' : 'never';
  }
  return 'partial'; // cancelled(), !success(), failure(), github.event_name == …, anything else
}

/**
 * A job or step `if:`: 'never' drops the run, 'none' ignores the condition, 'partial' means it may not run on every
 * event. `a && b` holds only if both do; `a || b` is treated as 'none' only when every side is, 'never' when every side is.
 */
function condition(v: unknown, self: RepoId): Cond {
  if (v === undefined || v === null || v === true) return 'none';
  if (v === false || v === 0) return 'never';
  if (typeof v !== 'string' || !regexSafe(v)) return 'partial';
  let s = v.trim();
  if (s.startsWith('${{') && s.endsWith('}}') && s.indexOf('${{', 3) < 0) s = s.slice(3, -2).trim();
  if (s === '') return 'none';
  const ors = s.split('||').map((side) => {
    const ands = side.split('&&').map((x) => atomCond(stripParens(x), self));
    return ands.includes('never') ? 'never' : ands.every((x) => x === 'none') ? 'none' : 'partial';
  });
  return ors.every((x) => x === 'none') ? 'none' : ors.every((x) => x === 'never') ? 'never' : 'partial';
}

// ---------- soft-fail settings (review I1) ----------

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

/** A `with:` value as lowercase text, or null when it isn't a scalar. */
function inputText(v: unknown): string | null {
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  return typeof v === 'string' && regexSafe(v) ? v.trim().toLowerCase() : null;
}

/** Inputs a step sets, by lowercase name. GitHub reads input names case-insensitively and keeps the last spelling; pipegen
 *  keeps every spelling, and a soft value in any of them counts (a failing value must hold in all of them). */
type Inputs = Map<string, unknown[]>;
function lowerInputs(w: Obj): Inputs {
  const out: Inputs = new Map();
  for (const [k, v] of Object.entries(w)) out.set(k.toLowerCase(), [...(out.get(k.toLowerCase()) ?? []), v]);
  return out;
}

/** Whether one value is a listed value (`*` = any non-empty); an expression counts only when `exprCounts`. */
function valueListed(v: unknown, values: string[], exprCounts: boolean): boolean {
  const s = inputText(v);
  if (s === null) return false;
  if (s.includes('${{')) return exprCounts;
  return values.includes(s) || (values.includes('*') && s !== '');
}

/** Soft check: some spelling of a listed input has a listed value (an expression counts: errs to "can't block"). */
function softInputGiven(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => (w.get(name.toLowerCase()) ?? []).some((v) => valueListed(v, values, true)));
}

/** Fail check: a listed input is set, and every spelling of it has a listed value (an expression doesn't count). */
function failInputGiven(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => {
    const all = w.get(name.toLowerCase()) ?? [];
    return all.length > 0 && all.every((v) => valueListed(v, values, false));
  });
}

/** Whether some spelling of an input is set (non-empty) to anything but the listed values; an expression counts. */
function inputSetOtherwise(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => (w.get(name.toLowerCase()) ?? []).some((v) => {
    const s = inputText(v);
    return s !== null && s !== '' && (s.includes('${{') || !values.includes(s));
  }));
}

/** Every string value of an input, split into words (bounded). */
const inputWords = (w: Inputs, name: string) => (w.get(name) ?? []).flatMap((v) =>
  (typeof v === 'string' && regexSafe(v) ? tokenize(v).filter((t) => t.op === null).map((t) => t.w) : [])).slice(0, MAX_FLAG_WORDS);

/** Inputs many actions pass straight to the tool's command line; read for the tool's soft flags. */
const ARGS_INPUTS = ['args', 'cmd_options', 'options'];

function actionReason(tool: ToolSignature, w: Inputs): Reason | null {
  const args = ARGS_INPUTS.flatMap((name) => inputWords(w, name));
  if (softInputGiven(tool.softInputs, w) || inputSetOtherwise(tool.softUnless, w) || (tool.softFlags ?? []).some((f) => flagGiven(f, args))) return 'soft';
  if (tool.actionFails === 'never') return 'never';
  if (tool.actionFails === 'input' && !failInputGiven(tool.failInputs, w)) return 'no-fail';
  return null;
}

const foundOf = (tool: ToolSignature, dir: string | null, reason: Reason | null): Found => ({
  categories: tool.categories, by: tool.id, subject: `The ${tool.id} check`, dir, reason,
  ...(tool.partialWhy === undefined ? {} : { partialWhy: tool.partialWhy }),
});

// ---------- reading shell text (review M2: command position only; round 2: quotes, lists, groups, pipes) ----------

/** How a step's shell treats failures. GitHub: default `bash -e {0}`; `bash` adds -o pipefail; `sh` is `sh -e {0}`. */
interface ShellMode { errexit: boolean; pipefail: boolean }
const DEFAULT_SHELL: ShellMode = { errexit: true, pipefail: false };

/** The mode of a step's `shell:` (or defaults.run.shell). A custom shell without -e (bash {0}, pwsh, python) has no errexit. */
function shellMode(v: unknown): ShellMode {
  if (v === undefined || v === null) return DEFAULT_SHELL;
  if (typeof v !== 'string' || !regexSafe(v)) return { errexit: false, pipefail: false };
  const s = v.trim();
  if (s === 'bash') return { errexit: true, pipefail: true };
  if (s === 'sh') return { errexit: true, pipefail: false };
  const parts = s.split(/\s+/).slice(0, 16);
  const prog = basename(parts[0] ?? '');
  if (prog !== 'bash' && prog !== 'sh') return { errexit: false, pipefail: false };
  const e = parts.some((x) => x.startsWith('-') && !x.startsWith('--') && /^-[a-z]+$/.test(x) && x.includes('e'));
  return { errexit: e, pipefail: prog === 'bash' && parts.includes('pipefail') };
}

/** One shell token: an operator (incl. '\n' between commands) or a word (`w`: quotes and escapes removed). */
interface Tk { op: string | null; w: string }
/** Characters that end a word and are operators of their own (`&` only when not part of a redirection). */
const BREAK_CHARS = ';|&()`';
/** After these, a newline doesn't end the command list (`a ||⏎ b`, `{⏎`). */
const JOINERS = new Set(['&&', '||', '|', '(', '{', '$(', '\n']);
/** Reserved words after which a `{` still opens a group. */
const GROUP_AFTER = new Set(['then', 'do', 'else', '!', 'time', 'if', 'elif', 'while', 'until']);
const MAX_WORD = READ_LIMITS.maxRegexLineBytes;
const isBlank = (ch: string | undefined) => ch === undefined || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';

/**
 * Shell text → tokens, in one linear pass.
 * - Quoted text ('…', "…") stays inside its word, so a separator in quotes never starts a command; `${…}` / `${{ … }}`
 *   stay inside the word too; `#` at a word start comments out the rest of the line; `\` + newline joins lines.
 * - `&` is part of a redirection word after `>`/`<` or before `>` (`2>&1`, `>&2`, `<&0`, `&>`, `&>>`); `|&` is a pipe;
 *   any other single `&` runs the command in the background.
 * - `{` opens a group only where a command starts and when a blank follows it; `}` closes one only where a command
 *   starts (bash reserved words). Elsewhere both are plain characters (`echo {a`, `xargs -I {}`).
 * - A backtick substitution `` `…` `` becomes `$(` … `)`.
 * - Here-document bodies (`<<WORD`, `<<-WORD`, quoted or not) are skipped up to the line holding WORD alone; an
 *   unterminated one skips the rest of the text.
 * A word longer than MAX_WORD keeps an empty value (it can't name a tool).
 */
function tokenize(text: string): Tk[] {
  const toks: Tk[] = [];
  const n = text.length;
  let i = 0;
  let atCmd = true; // where a command could start: `{` / `}` are group brackets here
  let afterFunction = false; // `function name {`: the `{` after the name opens the body
  let inBacktick = false;
  const heredocs: { delim: string; tabs: boolean }[] = [];
  let delimNext: boolean | null = null; // `<< WORD`: the next word is the delimiter (value: strip tabs)
  const pushOp = (op: string) => {
    toks.push({ op, w: '' });
    atCmd = true;
    afterFunction = false;
  };
  /** Skips the bodies of the here-documents opened on the line that just ended; returns where the text goes on. */
  const skipHeredocs = (from: number) => {
    let at = from;
    for (const h of heredocs) {
      while (at < n) {
        const nl = text.indexOf('\n', at);
        const stop = nl < 0 ? n : nl;
        let a = at;
        if (h.tabs) while (a < stop && text[a] === '\t') a++;
        const b = stop > a && text[stop - 1] === '\r' ? stop - 1 : stop;
        const done = text.slice(a, b) === h.delim;
        at = nl < 0 ? n : nl + 1;
        if (done) break;
      }
    }
    heredocs.length = 0;
    return at;
  };
  while (i < n) {
    const c = text[i] as string;
    const next = text[i + 1];
    if (c === '\n') {
      const last = toks[toks.length - 1];
      if (last !== undefined && !(last.op !== null && JOINERS.has(last.op))) toks.push({ op: '\n', w: '' });
      atCmd = true;
      i = heredocs.length > 0 ? skipHeredocs(i + 1) : i + 1;
    } else if (c === ' ' || c === '\t' || c === '\r') {
      i++;
    } else if (c === '\\' && (next === '\n' || (next === '\r' && text[i + 2] === '\n'))) {
      i += next === '\n' ? 2 : 3;
    } else if (c === '#') {
      while (i < n && text[i] !== '\n') i++;
    } else if (c === '$' && next === '(') {
      pushOp('$(');
      i += 2;
    } else if (c === '`') {
      pushOp(inBacktick ? ')' : '$(');
      inBacktick = !inBacktick;
      i++;
    } else if ((c === '&' || c === '|') && next === c) {
      pushOp(c + c);
      i += 2;
    } else if (c === '|' && next === '&') { // |& pipes stderr too
      pushOp('|');
      i += 2;
    } else if (c === '&' && next !== '>') {
      pushOp('&');
      i++;
    } else if (c === ';' || c === '|' || c === '(' || c === ')') {
      pushOp(c);
      i++;
    } else if (c === '{' && (atCmd || afterFunction) && isBlank(next)) {
      pushOp('{');
      afterFunction = false;
      i++;
    } else if (c === '}' && atCmd) {
      pushOp('}');
      i++;
    } else {
      let w = '';
      let quote = '';
      let brace = ''; // '}' or '}}' while inside ${…} / ${{ … }}
      const add = (ch: string) => {
        if (w.length <= MAX_WORD) w += ch;
      };
      const start = i;
      while (i < n) {
        const ch = text[i] as string;
        if (brace !== '') {
          if (text.startsWith(brace, i)) {
            i += brace.length;
            brace = '';
          } else i++;
          add(ch);
          continue;
        }
        if (quote !== '') {
          if (ch === quote) quote = '';
          else if (ch === '\\' && quote === '"' && i + 1 < n) add(text[++i] as string);
          else add(ch);
          i++;
          continue;
        }
        if (ch === '"' || ch === "'") {
          quote = ch;
          i++;
          continue;
        }
        if (ch === '\\' && i + 1 < n) {
          if (text[i + 1] === '\n') break;
          add(text[i + 1] as string);
          i += 2;
          continue;
        }
        if (ch === '$' && text[i + 1] === '{') {
          brace = text[i + 2] === '{' ? '}}' : '}';
          add(ch);
          i++;
          continue;
        }
        if (ch === '&' && (text[i + 1] === '>' || text[i - 1] === '>' || text[i - 1] === '<')) { // a redirection: 2>&1, &>
          add(ch);
          i++;
          continue;
        }
        if (ch === '<' && text[i + 1] === '<' && i > start && text[i - 1] !== '<') break; // cat<<EOF: `<<` starts a word
        if (isBlank(ch) || BREAK_CHARS.includes(ch) || (ch === '$' && text[i + 1] === '(')) break;
        add(ch);
        i++;
      }
      const value = w.length > MAX_WORD ? '' : w;
      toks.push({ op: null, w: value });
      atCmd = GROUP_AFTER.has(value);
      const prev = toks[toks.length - 2];
      afterFunction = prev !== undefined && prev.op === null && prev.w === 'function'; // this word names the function
      if (delimNext !== null) {
        heredocs.push({ delim: value, tabs: delimNext });
        delimNext = null;
      } else if (value.startsWith('<<') && !value.startsWith('<<<')) {
        const tabs = value[2] === '-';
        const delim = value.slice(tabs ? 3 : 2);
        if (delim === '') delimNext = tabs;
        else heredocs.push({ delim, tabs });
      }
    }
  }
  return toks;
}

const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** Words after which the next non-flag word is a command. */
const WRAPPERS = new Set(['sudo', 'time', 'npx', 'bunx', 'uvx', 'env', 'nohup', 'exec', 'command', 'xargs', 'sh', 'bash', 'zsh', 'dash']);
/** Flags of a wrapper that take the next word as their value. */
const WRAPPER_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-T', '-U', '--user', '--group', '--chdir', '--host', '--prompt']),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  xargs: new Set(['-I', '-L', '-n', '-P', '-s', '-d', '-E', '-a']),
};
/** Two-word wrappers: pnpm dlx, uv run, python -m, … */
const SUB_WRAPPERS: Readonly<Record<string, readonly string[]>> = {
  pnpm: ['dlx', 'exec'], yarn: ['dlx', 'exec'], npm: ['exec'], bun: ['x'], uv: ['run'], pipx: ['run'], poetry: ['run'],
  pdm: ['run'], hatch: ['run'], python: ['-m'], python3: ['-m'],
};
/** `yarn eslint .` and `pnpm eslint .` run a package binary: the next word is a command too. */
const BIN_RUNNERS = new Set(['yarn', 'pnpm']);
const DOCKER_VALUE_FLAGS = new Set(['-v', '--volume', '-e', '--env', '--env-file', '-w', '--workdir', '-u', '--user', '-p', '--publish', '--name',
  '--entrypoint', '--network', '--platform', '--mount', '-l', '--label', '--label-file', '--add-host', '--pull', '-m', '--memory', '--cpus',
  '--cidfile', '-h', '--hostname', '--security-opt', '--cap-add', '--cap-drop', '--device', '--dns', '--log-driver', '--log-opt',
  '--restart', '--runtime', '--tmpfs', '--ulimit', '--group-add', '--shm-size', '--ipc', '--pid', '--gpus', '--expose', '--link',
  '--volumes-from', '--stop-signal', '-a', '--attach', '-c', '--cpu-shares', '--ip', '--mac-address', '--userns', '--uts']);
/** Shell keywords: the next word is a command; in a condition its exit status is consumed. */
const COND_KEYWORDS = new Set(['if', 'elif', 'while', 'until']);
const BODY_KEYWORDS = new Set(['then', 'do', 'else']);
const END_KEYWORDS = new Set(['fi', 'done', 'esac']);
/** A call that only prints the version or help, not a run. */
const probeCall = (args: readonly string[]) =>
  args.includes('--version') || args.includes('--help') || (args.length === 1 && ['-v', '-V', '-h'].includes(args[0] as string));
/** Script names after `npm run` etc. (ruling S5): test, lint, or test:… / lint:… */
const OWN_NAME_RE = /^(?:test|lint)(?::[A-Za-z0-9_.-]{1,64})?$/;
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
const stripDotSlash = (w: string) => {
  let i = 0;
  while (w.startsWith('./', i)) i += 2;
  return w.slice(i);
};

/**
 * A redirection word (`>`, `2>&1`, `&>out`, `<in`): null when the word isn't one; true when it carries its target
 * (`>out`, `2>&1`); false when the target is the next word (`>`, `2>`, `<`).
 */
function redirection(w: string): boolean | null {
  let j = 0;
  while (j < w.length && w[j]! >= '0' && w[j]! <= '9') j++;
  if (!(w[j] === '<' || w[j] === '>' || w.startsWith('&>', j))) return null;
  while (j < w.length && (w[j] === '<' || w[j] === '>' || w[j] === '&' || w[j] === '|')) j++;
  return j < w.length;
}

interface Budget { visits: number; bytes: number; truncated: boolean }

/**
 * Tools found in shell text (a run step, a hook script, a hook entry). See the module header for what counts as a
 * command and when its failure can't fail the step. `cd <dir>` moves the directory for the rest of the text.
 */
function scanShell(text: string, base: string | null, sigs: Compiled, budget: Budget, mode: ShellMode = DEFAULT_SHELL): Found[] {
  budget.bytes += text.length;
  if (budget.bytes > MAX_SCAN_BYTES) {
    budget.truncated = true;
    return [];
  }
  const toks = tokenize(text);
  const n = toks.length;
  const isWord = (k: number) => k >= 0 && k < n && toks[k]!.op === null;
  const word = (k: number) => (isWord(k) ? toks[k]!.w : null);

  // Matching group brackets (forward pass with a stack), so the right-to-left pass knows what a ')' closes.
  const opener = new Int32Array(n).fill(-1);
  const closer = new Int32Array(n).fill(-1);
  const open: number[] = [];
  for (let k = 0; k < n; k++) {
    const op = toks[k]!.op;
    if (op === '(' || op === '{' || op === '$(') open.push(k);
    else if ((op === ')' || op === '}') && open.length > 0) {
      const o = open.pop() as number;
      opener[k] = o;
      closer[o] = k;
    }
  }
  /** Whether the right side of the `||` at k lets the list succeed (anything but exit <non-zero>, return <non-zero>, false). */
  const rightSwallows = (k: number) => {
    let j = k + 1;
    const end = toks[j]?.op === '{' || toks[j]?.op === '(' ? Math.min(closer[j]! < 0 ? n : closer[j]!, j + MAX_FLAG_WORDS) : j + 1;
    for (; j <= end && j < n; j++) {
      const w = word(j);
      if (w === null || (j > k + 1 && isWord(j - 1))) continue; // only words in command position
      if (w === 'false') return false;
      if ((w === 'exit' || w === 'return') && word(j + 1) !== '0') return false;
    }
    return true;
  };

  // Right to left: where each simple command ends, and whether its failure is swallowed by a later `||`, hidden by a
  // later pipe stage, exempt from errexit by a later `&&`, or run in the background by a later `&`. A group takes on the
  // state of what follows it.
  const segEnd = new Int32Array(n);
  const swallowed = new Uint8Array(n);
  const piped = new Uint8Array(n);
  const andAfter = new Uint8Array(n);
  const background = new Uint8Array(n);
  type State = { sw: number; pp: number; aa: number; bg: number };
  let cur: State = { sw: 0, pp: 0, aa: 0, bg: 0 };
  let outer: State = { sw: 0, pp: 0, aa: 0, bg: 0 }; // what a list end inside the current group goes back to
  const stack: { outer: State; cur: State }[] = [];
  let end = n;
  for (let k = n - 1; k >= 0; k--) {
    const op = toks[k]!.op;
    if (op !== null) end = k;
    segEnd[k] = end;
    if (op === ')' || op === '}') {
      stack.push({ outer, cur });
      // `VAR=$( … )` keeps the substitution's status; in any other command `$( … )` can't fail the step.
      const o = opener[k]!;
      const subst = o >= 0 && toks[o]!.op === '$(' && !(isWord(o - 1) && (toks[o - 1]!.w.endsWith('=')) && !isWord(o - 2));
      outer = { ...cur, sw: subst ? 1 : cur.sw };
      cur = { ...outer };
    } else if (op === '(' || op === '{' || op === '$(') {
      const f = stack.pop();
      if (f) {
        outer = f.outer;
        cur = f.cur;
      }
    } else if (op === ';' || op === '\n') {
      cur = { ...outer };
    } else if (op === '&') { // the and-or list before it runs in the background
      cur = { ...outer, bg: 1 };
    } else if (op === '&&') {
      cur = { ...cur, pp: outer.pp, aa: 1 };
    } else if (op === '||') {
      cur = { ...cur, sw: rightSwallows(k) ? 1 : outer.sw, pp: outer.pp, aa: 0 };
    } else if (op === '|') {
      cur = { ...cur, pp: 1 };
    }
    swallowed[k] = cur.sw;
    piped[k] = cur.pp;
    andAfter[k] = cur.aa;
    background[k] = cur.bg;
  }
  // The step's last command list starts after the last list end that has a word after it.
  let lastWord = n - 1;
  while (lastWord >= 0 && !isWord(lastWord)) lastWord--;
  let lastList = -1;
  for (let k = lastWord; k >= 0; k--) {
    const op = toks[k]!.op;
    if (op === ';' || op === '&' || op === '\n') {
      lastList = k;
      break;
    }
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
  let errexit = mode.errexit;
  let pipefail = mode.pipefail;
  let inCondition = false;
  let negateEnd = -1;
  let functionEnd = -1; // tokens before this index are inside a function body
  // `( … )` and `$( … )` run in a subshell: `set` and `cd` inside them end at the closing bracket.
  const subshells: { close: number; errexit: boolean; pipefail: boolean; cwd: string | null }[] = [];

  /** Why the failure of the command at k can't fail the step, or null. */
  const shellReason = (k: number): Reason | null => {
    if (k < functionEnd) return 'function';
    const inLast = k > lastList;
    const exempt = swallowed[k] === 1 || (piped[k] === 1 && !pipefail) || background[k] === 1 || inCondition || k < negateEnd
      || (!errexit && !inLast) || (errexit && andAfter[k] === 1 && !inLast);
    return exempt ? 'suppressed' : null;
  };
  const argsAfter = (k: number) => {
    const out: string[] = [];
    for (let j = k + 1; j < Math.min(segEnd[k]!, k + 1 + MAX_FLAG_WORDS); j++) out.push(toks[j]!.w);
    return out;
  };
  /** The words right after k equal `rest`. */
  const followedBy = (k: number, rest: readonly string[]) => rest.every((x, i) => word(k + 1 + i) === x);
  /** Signatures and own scripts for the command word at k (`name` = its basename, or an image name). */
  const match = (k: number, w: string, name: string) => {
    const args = argsAfter(k);
    if (probeCall(args)) return;
    const tryRules = (rules: CommandRule[] | undefined) => {
      for (const r of rules ?? []) {
        if (!followedBy(k, r.rest) || r.excludes.some((x) => followedBy(k, x))) continue;
        add(foundOf(r.tool, cwd, shellReason(k) ?? commandReason(r.tool, args)));
      }
    };
    if (w.includes('/')) tryRules(sigs.byPath.get(stripDotSlash(w)));
    tryRules(sigs.byFirstWord.get(name));
    if (w !== name) return;
    // The service's own scripts (ruling S5): npm test, npm run test|lint, pnpm|yarn|bun [run] test|lint, pytest,
    // python -m pytest. Only fixed words and a script name matching OWN_NAME_RE go into the phrase.
    let words: string[] | null = null;
    const a = word(k + 1);
    const b = word(k + 2);
    if (name === 'pytest') words = ['pytest'];
    else if ((name === 'python' || name === 'python3') && a === '-m' && b === 'pytest') words = [name, '-m', 'pytest'];
    else if (name === 'npm' && a === 'test') words = ['npm', 'test'];
    else if (['npm', 'pnpm', 'yarn', 'bun'].includes(name) && a === 'run' && b !== null && OWN_NAME_RE.test(b)) words = [name, 'run', b];
    else if (['pnpm', 'yarn', 'bun'].includes(name) && a !== null && OWN_NAME_RE.test(a)) words = [name, a];
    if (words === null) return;
    const cmd = words.join(' ');
    const categories = (words[words.length - 1] as string).startsWith('lint') ? ['lint'] : TEST_CATEGORIES;
    add({ categories, by: `your own \`${cmd}\``, subject: `Your own \`${cmd}\``, dir: cwd, reason: shellReason(k) });
  };
  /** If the command word at k starts a function definition, the index of its body's opening bracket, else -1. */
  const functionBody = (k: number) => {
    let j = k;
    if (toks[k]!.w === 'function') {
      if (!isWord(k + 1)) return -1;
      j = k + 2;
      if (toks[j]?.op === '(' && toks[j + 1]?.op === ')') j += 2;
    } else if (toks[k + 1]?.op === '(' && toks[k + 2]?.op === ')') {
      j = k + 3;
    } else return -1;
    while (toks[j]?.op === '\n') j++;
    return toks[j]?.op === '{' || toks[j]?.op === '(' ? j : -1;
  };
  const skipFlags = (k: number, wrapper: string) => {
    const valued = WRAPPER_VALUE_FLAGS[wrapper];
    let j = k;
    for (let w = word(j); w !== null && (w.startsWith('-') || (wrapper === 'env' && ASSIGN.test(w))); w = word(j)) j += valued?.has(w) ? 2 : 1;
    return j;
  };

  let cmd = true;
  let k = 0;
  while (k < n) {
    const op = toks[k]!.op;
    if (op !== null) {
      if ((op === '(' || op === '$(') && closer[k]! >= 0) subshells.push({ close: closer[k]!, errexit, pipefail, cwd });
      while (subshells.length > 0 && subshells[subshells.length - 1]!.close <= k) {
        const s = subshells.pop()!;
        if (s.close === k) ({ errexit, pipefail, cwd } = s);
      }
      cmd = op !== ')' && op !== '}';
      k++;
      continue;
    }
    if (!cmd) {
      k++;
      continue;
    }
    const w = toks[k]!.w;
    if (ASSIGN.test(w)) { // VAR=value before a command
      k++;
      continue;
    }
    const redirect = redirection(w);
    if (redirect !== null) { // `> out cmd`, `2>&1 cmd`: a redirection before the command (and its target word)
      k += redirect ? 1 : 2;
      continue;
    }
    // A function definition, `name() { … }` or `function name [()] { … }`: its body runs only where it is called,
    // so tools inside it count as partial.
    const fnBody = functionBody(k);
    if (fnBody >= 0) {
      functionEnd = Math.max(functionEnd, closer[fnBody]! < 0 ? n : closer[fnBody]!);
      k = fnBody;
      continue;
    }
    if (COND_KEYWORDS.has(w)) {
      inCondition = true;
      k++;
      continue;
    }
    if (BODY_KEYWORDS.has(w)) {
      inCondition = false;
      k++;
      continue;
    }
    if (END_KEYWORDS.has(w)) {
      cmd = false;
      k++;
      continue;
    }
    if (w === '!') {
      negateEnd = segEnd[k]!;
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
      for (let j = k + 1; j < segEnd[k]!; j++) {
        const f = toks[j]!.w;
        if (!(f.startsWith('-') || f.startsWith('+')) || f.startsWith('--') || f.length < 2) continue;
        const on = f[0] === '-';
        if (f.includes('e')) errexit = on;
        if (f.endsWith('o')) {
          const opt = word(j + 1);
          if (opt === 'errexit') errexit = on;
          if (opt === 'pipefail') pipefail = on;
        }
      }
      cmd = false;
      k++;
      continue;
    }
    if (name === 'command' && /^-[a-zA-Z]*[vV]/.test(word(k + 1) ?? '')) { // command -v X: only checks that X exists
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
      k = skipFlags(k + 2, name);
      cmd = true;
      continue;
    }
    if (WRAPPERS.has(name)) {
      k = skipFlags(k + 1, name);
      cmd = true;
      continue;
    }
    cmd = BIN_RUNNERS.has(name);
    k++;
  }
  return found;
}

/** A `uses: docker://image` step: the image name as a command, with `with.args` as its flags. */
function scanImage(uses: string, w: Inputs, sigs: Compiled): Found[] {
  const name = imageName(uses.slice('docker://'.length));
  const args = inputWords(w, 'args');
  if (probeCall(args)) return [];
  return (sigs.byFirstWord.get(name) ?? []).filter((r) => r.rest.length === 0).map((r) => foundOf(r.tool, '.', commandReason(r.tool, args)));
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
  /** defaults.run.shell of the job or workflow (a step's own `shell:` wins). */
  shell: unknown;
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

const repoId = (ctx: Ctx): RepoId => ({ owner: ctx.p.owner, repo: ctx.p.repo });

async function walkStep(ctx: Ctx, step: Obj, c: StepCtx): Promise<void> {
  if (!spend(ctx)) return;
  const cond = condition(step.if, repoId(ctx));
  if (cond === 'never') return;
  const sc: StepCtx = { ...c, continueOnError: c.continueOnError || allowedToFail(step['continue-on-error']), conditional: c.conditional || cond === 'partial' };
  const withInputs = lowerInputs(asObj(step.with));
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
    addFound(ctx, scanShell(step.run, base, ctx.sigs, ctx.budget, shellMode(step.shell ?? c.shell)), sc);
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
  // A composite action's run steps start at the repo root (plus their own working-directory and shell), not at the
  // job's defaults.
  for (const step of list(runs.steps).slice(0, MAX_STEPS)) await walkStep(ctx, asObj(step), { ...c, where, runDir: '.', shell: undefined, depth: 1 });
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

const defaultsShell = (doc: Obj): unknown => asObj(asObj(doc.defaults).run).shell;

const mentionsWindows = (texts: string[]) => texts.some((t) => regexSafe(t) && t.toLowerCase().includes('windows'));
/**
 * Whether a job may run on a Windows runner, where a step without `shell:` runs in pwsh: `runs-on` (a string, a list
 * or `{ labels }`) names windows, or it is an expression and the job's matrix names windows somewhere.
 */
function onWindows(job: Obj): boolean {
  const ro = job['runs-on'];
  const labels = [...strs(ro), ...strs(asObj(ro).labels), ...strs(asObj(ro).group)];
  if (mentionsWindows(labels)) return true;
  if (!labels.some((t) => t.includes('${{'))) return false;
  const matrix = asObj(asObj(job.strategy).matrix);
  const values = Object.values(matrix).slice(0, MAX_FILTER_PATTERNS).flatMap((v) =>
    [...strs(v), ...list(v).slice(0, MAX_FILTER_PATTERNS).flatMap((e) => Object.values(asObj(e)).flatMap(strs))]);
  return mentionsWindows(values);
}

async function walkWorkflow(ctx: Ctx, doc: Obj, path: string, fit: Fit, depth: number, prefix: string, conditional: boolean): Promise<void> {
  const wfDir = defaultsDir(doc);
  const wfShell = defaultsShell(doc);
  const jobs = Object.entries(asObj(doc.jobs));
  if (jobs.length > MAX_JOBS) ctx.budget.truncated = true;
  for (const [i, [id, raw]] of jobs.slice(0, MAX_JOBS).entries()) {
    const job = asObj(raw);
    const cond = condition(job.if, repoId(ctx));
    if (cond === 'never') continue;
    const label = regexSafe(id) && JOB_ID_RE.test(id) ? id : `#${i + 1}`;
    const where = cut(`${prefix}${path} (job ${label})`);
    const jobConditional = conditional || cond === 'partial';
    if (typeof job.uses === 'string' && regexSafe(job.uses)) {
      await callWorkflow(ctx, job.uses.trim(), { fit, where, runDir: '.', shell: undefined, continueOnError: false, conditional: jobConditional, depth });
      continue;
    }
    const steps = list(job.steps);
    if (steps.length > MAX_STEPS) ctx.budget.truncated = true;
    const c: StepCtx = {
      fit, where, runDir: firstSet(defaultsDir(job), wfDir), shell: defaultsShell(job) ?? wfShell ?? (onWindows(job) ? 'pwsh' : undefined),
      continueOnError: allowedToFail(job['continue-on-error']), conditional: jobConditional, depth,
    };
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
/** husky runs a hook with `sh -e` (https://github.com/typicode/husky/blob/main/husky); lefthook runs each command
 *  with `sh -c`, without -e (internal/run/controller/exec/exec_unix.go). */
const HUSKY_SHELL: ShellMode = { errexit: true, pipefail: false };
const LEFTHOOK_SHELL: ShellMode = { errexit: false, pipefail: false };

async function readHooks(ctx: Ctx): Promise<Hooks> {
  const manager = ctx.p.precommit;
  const none: Hooks = { manager, where: '', readable: true, found: [] };
  if (manager === null) return none;
  const scan = (text: string, base: string | null, mode: ShellMode) => scanShell(text, base, ctx.sigs, ctx.budget, mode);
  if (manager === 'husky') {
    const where = '.husky/pre-commit';
    const r = await ctx.read.text(where);
    if ('fail' in r) return { ...none, where: '.husky', readable: r.fail === 'missing' };
    return { manager, where, readable: true, found: scan(r.ok, '.', HUSKY_SHELL) };
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
        // the hook id and its entry are each read as a command of their own (pre-commit runs the entry directly)
        for (const text of [hook.id, hook.entry]) if (typeof text === 'string') found.push(...scan(text, '.', DEFAULT_SHELL));
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
    const found = entries.flatMap((e) => (typeof e.run === 'string' ? scan(e.run, firstSet(workingDir(e.root)), LEFTHOOK_SHELL) : []));
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
