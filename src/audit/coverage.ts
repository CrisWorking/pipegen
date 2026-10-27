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
//     group or a compound command (if … fi, for/while/until/select … done, case … esac) before the `||`: a group and a
//     compound command take on what follows them; a `&&` after it outside the step's last list (bash -e ignores
//     those); a pipe stage other than the last without pipefail (the default shell and `shell: sh` have none;
//     `shell: bash` and `set -o pipefail` do); a background `&`; an `if`/`while`/`until` condition or `!`; `$( … )` or
//     backticks other than `VAR=$( … )`; a shell function body, whatever compound command it is (it runs only where
//     called); errexit off (`set +e`, or a custom `shell:` without -e such as `bash {0}`, pwsh or python; a Windows
//     `runs-on` without `shell:` means pwsh) unless it is in the step's last list. `set` and `cd` inside `( … )` end
//     with the subshell;
//   - a soft-fail flag or input (also inside `args` / `cmd_options` / `options` inputs), a tool that only fails when
//     told to (trivy, grype, semgrep scan, the trufflehog CLI, the ZAP actions) or never fails (CodeQL U5, the bandit
//     action);
//   - more `with:` inputs than pipegen reads: over MAX_INPUT_KEYS keys in the step, or over MAX_SPELLINGS spellings
//     (differing only in case) of an input the tool reads;
//   - a job or step `if:` other than always(), success(), !cancelled() and a guard naming this repo.
//   A need that is not blocking (format-lint) only cares whether the tool runs.
// - unknown: a remote reusable workflow, an action from the repo owner's own account (likely a composite action), a
//   second-level local call, a local call pipegen refused or couldn't read, a listed workflow that couldn't be read
//   again (or that readWorkflows skipped: opts.skippedWorkflows), or more workflow text than the budget. A per-service
//   row that would be missing is unknown when the repo has more services (MAX_SERVICES) or more distinct run dirs
//   (MAX_HIT_DIRS) than pipegen matches; a cap only drops runs, so it never makes a row covered.
// - missing: nothing matches. `gate` and `deploy-verify` are always missing: they are pipegen's own checks.
// Task 5 (accuracy from real repos):
// - own scripts: `npm|pnpm|yarn|bun run <name>` for a name other than test/lint[:x] counts only through the script's
//   own text in <dir>/package.json (the run's directory), read as npm runs it (sh -c, no -e), following the own
//   scripts it calls (each worked out once; a cycle adds nothing): what it runs for tests, lint or format-lint counts,
//   under "your own `npm run <name>`". A name only fixes (a :fix/-fix/:write part) never counts, also for lint:fix.
//   Flags after the name other than --silent, -s and --if-present (npm's --workspace, pnpm's --filter) stop it.
// - tox / tox run and nox are the project's own test runner unless the command line or an env var (TOX…, NOX…, in
//   the job's env or run text) picks other envs or sessions. `uv run` and `nyc` flags are matched against their full
//   lists (a flag pipegen doesn't know: no command); pipenv run is a wrapper.
// - .pre-commit-config.yaml: `meta` hooks never count; a local hook only by its `entry` (never `language: fail` or
//   `pygrep`); a hook of a repo listed in tool signatures (`precommitHooks`) by its id or its `entry`; a hook of any
//   other repo is partial (`hook-repo`). `args` are read for soft flags; an entry is one command (no shell). A hook
//   with `files`/`exclude`/`types`/`types_or`/`exclude_types` (or a top-level `files`/`exclude`) is partial (`files`:
//   pipegen never runs those regexes); one set up for another stage is partial (`stage`). CI's
//   `pre-commit run --all-files` at the repo root (pre-commit/action by default) also covers lint with the hooks' lint
//   tools (their reasons carried, `stage` hooks left out); SKIP in the job makes that run partial (`skip`) and carries
//   nothing.
// - a signature can need a flag (`npm publish --provenance`), be switched off by `with:` inputs (pypi-publish with a
//   password or attestations off) or by a version (`actionRef`: pypi-publish before v1.11.0 is missing with its own
//   why, an unknown ref partial), so a publish without an attestation is never counted.
// - Fix round 1: a script counted by name (S5) whose text is readable may only be lowered by it (ruling U23); commands
//   after a top-level `exit` don't run; pytest/jest modes that only list or collect tests don't count.
// - Fix rounds 2–3: classifyScript sorts every command of a by-name script (no-op, dead, runs nothing, a call to own
//   scripts that do nothing, real); own-script calls (npm aliases, yarn <script>, run-s/run-p/npm-run-all and
//   concurrently `npm:` globs) are followed with no depth limit, each (dir, script) once, at most MAX_SCRIPTS (then
//   the row is unknown). A local composite action's env gate is worked out once per action path (compositeGate).
// A tool counts only where a command starts: at the start, after ; && || | & ( $( { a newline, a shell keyword or a
// wrapper (npx, sudo, env, time, command without -v, pnpm/yarn dlx, uv run, pipx run, python -m, sh/bash, …), as the
// basename of a path, or as the image after `docker run [flags]`. Quoted text, here-document bodies and case patterns
// never start a command (a case arm's commands do); `2>&1`, `&>` and other redirections are words, not list ends; a
// `<<` inside `$(( … ))` or `(( … ))` is a shift, not a here-document. A version, help or completion call is not a
// run. A `run:` step's directory is its working-directory, else the job's or workflow's
// defaults.run working-directory, then `cd <dir>`; the tool covers only the service under that directory (S26).
// `uses:` steps, composite actions and called workflows start at the repo root (U3).
//
// Hostile input: workflow, action and hook files are attacker-controlled. They are read only by path from the list
// readProject made (p.existingWorkflows) plus local `uses: ./…` targets, every path level checked for symbolic links,
// the real path checked to stay inside the repo, through the read limits (1 MB, binary refused, YAML alias cap), with
// jobs, steps, files, findings, scanned bytes, run dirs and services capped. Each need is answered from tables built in
// one pass over the runs, so the cost grows with runs + needs + services, not with their product (review C1). Shell
// text is read by a hand-written, quote-aware tokenizer (one pass, no regex) and one right-to-left pass; words over
// 4 KB are kept opaque. The few regexes left are linear and run only on short values (lines or words of 4 KB or less).
// Output follows the src/types.ts rule, RAW but VALIDATED, cleaned at output: `why` is pipegen's own text only
// (including a signature's `partialWhy`, from pipegen's data file); `by` is a tool-signature id from
// data/tool-signatures.yml, an own-script phrase built from fixed words (plus a script name matching OWN_NAME_RE or
// SCRIPT_NAME_RE), a hook manager name, or a repo `uses:` value kept only when it matches REF_RE (ASCII letters, digits and . _ - / @; at
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
const INPUT_VALUE_RE = /^(?:\*|[a-z0-9._ :/-]{1,64})$/; // ':' and '/' for URL values (repository-url)
/** A pre-commit hook repo, exactly as its README gives it (https://github.com/owner/name). */
const HOOK_REPO_RE = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const HOOK_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
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
  /** Task 5: a command counts only when one of these words is given exactly (npm publish --provenance). */
  onlyWithFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Task 5: a command doesn't count when one of these flags is given (same matching as softFlags). */
  notWithFlags: z.array(z.string().regex(FLAG_RE)).min(1).optional(),
  /** Task 5: `with:` inputs set to one of these values (or an expression) mean the action doesn't do this check. */
  skipInputs: inputs.optional(),
  /** Task 5: `with:` inputs set (non-empty) to anything but these values (or an expression) mean the same. */
  skipUnless: inputs.optional(),
  /**
   * Task 5 fix round 1 (C1): the action does this check only from some version on. A `uses:` ref counts when it is one
   * of `moving` (branches that follow the newest release), a tag vX.Y[.Z] or branch release/vX.Y at or above
   * `minVersion`, or a commit SHA in `shas`; a version below `minVersion` doesn't count (missing, `oldWhy`); any other
   * ref (an unknown SHA, main, an expression) is partial (`unknownWhy`).
   */
  actionRef: z.strictObject({
    moving: z.array(z.string().regex(/^[A-Za-z0-9._/-]{1,64}$/)).min(1),
    minVersion: z.tuple([z.number().int().min(0), z.number().int().min(0)]),
    shas: z.array(z.string().regex(/^[0-9a-f]{40}$/)).min(1),
    oldWhy: z.string().regex(WHY_RE).refine((s) => safeText(s, 300) === s, 'must be plain text'),
    unknownWhy: z.string().regex(WHY_RE).refine((s) => safeText(s, 300) === s, 'must be plain text'),
  }).optional(),
  /** Task 5: pre-commit hooks that run this tool: the hook repo (exact URL) and its hook ids. */
  precommitHooks: z.array(z.strictObject({ repo: z.string().regex(HOOK_REPO_RE), ids: z.array(z.string().regex(HOOK_ID_RE)).min(1) })).min(1).optional(),
})
  .refine((t) => t.actions !== undefined || t.commands !== undefined, { message: 'needs actions or commands' })
  .refine((t) => t.commandFails !== 'flag' || t.failFlags !== undefined, { message: 'commandFails: flag needs failFlags' })
  .refine((t) => t.actionFails !== 'input' || t.failInputs !== undefined, { message: 'actionFails: input needs failInputs' })
  .refine((t) => t.excludes === undefined || t.commands !== undefined, { message: 'excludes needs commands' })
  .refine((t) => (t.onlyWithFlags === undefined && t.notWithFlags === undefined) || t.commands !== undefined, { message: 'onlyWithFlags and notWithFlags need commands' })
  .refine((t) => (t.skipInputs === undefined && t.skipUnless === undefined) || t.actions !== undefined, { message: 'skipInputs and skipUnless need actions' })
  .refine((t) => t.actionRef === undefined || t.actions !== undefined, { message: 'actionRef needs actions' });

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
interface Compiled {
  byFirstWord: Map<string, CommandRule[]>; byPath: Map<string, CommandRule[]>; actions: ActionRule[];
  /** `hookRepoKey(repo, id)` → the tools a pre-commit hook of that repo and id runs (Task 5). */
  hooks: Map<string, ToolSignature[]>;
  /** The hook repos listed in `precommitHooks` (normalised by hookRepo): pipegen knows what their hooks run. */
  hookRepos: Set<string>;
}

/** A pre-commit `repo:` URL compared exactly, ignoring letter case, a trailing slash and a trailing .git. */
const hookRepo = (repo: string) => repo.trim().toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
const hookRepoKey = (repo: string, id: string) => `${hookRepo(repo)}\u0000${id}`;

function compile(tools: ToolSignature[]): Compiled {
  const byFirstWord = new Map<string, CommandRule[]>();
  const byPath = new Map<string, CommandRule[]>();
  const actions: ActionRule[] = [];
  const hooks = new Map<string, ToolSignature[]>();
  const hookRepos = new Set<string>();
  for (const tool of tools) {
    for (const h of tool.precommitHooks ?? []) {
      hookRepos.add(hookRepo(h.repo));
      for (const id of h.ids) hooks.set(hookRepoKey(h.repo, id), [...(hooks.get(hookRepoKey(h.repo, id)) ?? []), tool]);
    }
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
  return { byFirstWord, byPath, actions, hooks, hookRepos };
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
const MAX_INPUT_KEYS = 256;        // `with:` keys read per step; a step with more is partial
const MAX_SPELLINGS = 8;           // spellings kept per input name (they differ only in case); more counts as soft
const MAX_HIT_DIRS = 10_000;       // distinct dirs (besides the root) that runs are matched to services in; a run in a
                                   // further dir counts only for repo-wide needs, and per-service rows can't be missing
const MAX_SERVICES = 5_000;        // services matched against run dirs; with more, per-service needs count only runs at
                                   // the root, and their rows can't be missing (review C1)

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
  tooMany: "There are too many services or workflow steps to check in full, so pipegen can't tell.",
} as const;

const LAYER_DONE: Readonly<Record<Exclude<Layer, 'pre-commit'>, string>> = {
  push: 'on every push',
  merge: 'on every pull request',
  deploy: 'when the code is deployed or released',
};

/** Why a run that is found can't block anything (or might not run). */
type Reason = 'continue' | 'suppressed' | 'function' | 'soft' | 'inputs' | 'no-fail' | 'never' | 'condition'
  | 'hook-repo' | 'files' | 'stage' | 'skip' | 'ref';
/**
 * Reasons that say the tool may not run at all (not just "can't block"): they make even a need that doesn't block
 * (format-lint) partial. Task 5 fix round 1 adds the pre-commit ones (hook-repo, files, stage) and SKIP.
 */
const MAY_NOT_RUN: ReadonlySet<Reason> = new Set<Reason>(['condition', 'hook-repo', 'files', 'stage', 'skip', 'ref']);
const REASON_WHY: Readonly<Record<Reason, (subject: string, when: string) => string>> = {
  continue: (s) => `${s} runs, but is allowed to fail (continue-on-error), so it can't block anything.`,
  suppressed: (s) => `${s} runs, but its exit code is ignored (by ||, a pipe, an if, set +e, the background & or the step's shell), so it can't block anything.`,
  function: (s) => `${s} runs inside a shell function, so pipegen can't tell whether its failure fails the step.`,
  soft: (s) => `${s} runs, but is set not to fail on findings, so it can't block anything.`,
  inputs: (s) => `${s} runs, but its step sets more inputs than pipegen reads, so pipegen can't tell whether it blocks anything.`,
  'no-fail': (s) => `${s} runs, but doesn't fail on findings unless told to, so it can't block anything.`,
  never: (s) => `${s} reports findings but doesn't fail the job, so it can't block anything.`,
  condition: (s, when) => `${s} runs only when a condition holds, so it may not run ${when}.`,
  'hook-repo': (s) => `${s} comes from a pre-commit hook repo pipegen doesn't know, so pipegen can't tell what it really runs.`,
  files: (s) => `${s} runs only on the files its pre-commit files, exclude or types settings allow, and pipegen doesn't check which files those are.`,
  stage: (s) => `${s} is set up for another pre-commit stage, so it doesn't run before each commit.`,
  skip: (s) => `${s} runs, but SKIP is set in this job, so some pre-commit hooks don't run here.`,
  ref: (s) => `${s} runs at a version pipegen can't place, so pipegen can't tell whether it does this check.`,
};

const HOOK_PLACE = { 'pre-commit': 'the pre-commit framework', husky: 'the husky pre-commit hook', lefthook: 'the lefthook pre-commit hook' } as const;
const HOOK_NAME = { 'pre-commit': 'the pre-commit framework', husky: 'husky', lefthook: 'lefthook' } as const;
const HOOK_FILE = { 'pre-commit': '.pre-commit-config.yaml', husky: '.husky', lefthook: 'lefthook.yml' } as const;

// ---------- small helpers ----------

type Manager = NonNullable<RepoProfile['precommit']>;
type CiLayer = Exclude<Layer, 'pre-commit'>;
type Fit = Record<CiLayer, boolean>;

/** A tool found in shell text or a step. `reason` null = it runs and can fail the run. */
interface Found {
  categories: readonly string[]; by: string; subject: string; dir: string | null; reason: Reason | null; partialWhy?: string;
  /** Task 5: `npm|pnpm|yarn|bun run <script>`, counted only once the script's own text is read (resolveScripts). */
  script?: string;
  /**
   * Task 5: a tox or nox run; an environment variable that picks other envs or sessions (TOX*, NOX*) drops it. 'npm':
   * an npm publish, which NPM_CONFIG_DRY_RUN turns into a dry run (fix round 1, M1).
   */
  envGate?: 'tox' | 'nox' | 'npm';
  /** Fix round 1 (U23): a script counted by name (test, lint[:x]); its text, when readable, can only lower it. */
  byName?: string;
  /** Task 5: `pre-commit run` over all files at the pre-commit stage: the hooks' lint tools run here too (SKIP drops it). */
  hookRun?: boolean;
}
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
  hookRun?: boolean;
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

/**
 * Inputs a step sets, by lowercase name. GitHub reads input names case-insensitively and keeps the last spelling; pipegen
 * keeps up to MAX_SPELLINGS spellings, and a soft value in any of them counts (a failing value must hold in all of them).
 * A name with more spellings is `crowded` (it counts as soft for a tool that reads it); a step with more than
 * MAX_INPUT_KEYS keys is `unread` past them (every tool the step runs is partial). One pass, appending in place.
 */
interface Inputs { byName: Map<string, unknown[]>; crowded: Set<string>; unread: boolean }
function lowerInputs(w: Obj): Inputs {
  const out: Inputs = { byName: new Map(), crowded: new Set(), unread: false };
  const keys = Object.keys(w);
  if (keys.length > MAX_INPUT_KEYS) out.unread = true;
  for (const k of keys.slice(0, MAX_INPUT_KEYS)) {
    const name = k.toLowerCase();
    const all = out.byName.get(name);
    if (all === undefined) out.byName.set(name, [w[k]]);
    else if (all.length < MAX_SPELLINGS) all.push(w[k]);
    else out.crowded.add(name);
  }
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
  return Object.entries(spec ?? {}).some(([name, values]) => (w.byName.get(name.toLowerCase()) ?? []).some((v) => valueListed(v, values, true)));
}

/** Fail check: a listed input is set, and every spelling of it has a listed value (an expression doesn't count). */
function failInputGiven(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => {
    const all = w.byName.get(name.toLowerCase()) ?? [];
    return all.length > 0 && all.every((v) => valueListed(v, values, false));
  });
}

/** Whether some spelling of an input is set (non-empty) to anything but the listed values; an expression counts. */
function inputSetOtherwise(spec: Record<string, string[]> | undefined, w: Inputs): boolean {
  return Object.entries(spec ?? {}).some(([name, values]) => (w.byName.get(name.toLowerCase()) ?? []).some((v) => {
    const s = inputText(v);
    return s !== null && s !== '' && (s.includes('${{') || !values.includes(s));
  }));
}

/** Every string value of an input, split into words (bounded). */
const inputWords = (w: Inputs, name: string) => (w.byName.get(name) ?? []).flatMap((v) =>
  (typeof v === 'string' && regexSafe(v) ? tokenize(v).filter((t) => t.op === null).map((t) => t.w) : [])).slice(0, MAX_FLAG_WORDS);

/** Inputs many actions pass straight to the tool's command line; read for the tool's soft flags. */
const ARGS_INPUTS = ['args', 'cmd_options', 'options'];

/** Whether an input the tool is read by (its listed inputs, or `names`) has more spellings than pipegen keeps. */
function inputsCrowded(tool: ToolSignature, w: Inputs, names: readonly string[]): boolean {
  if (w.crowded.size === 0) return false;
  const listed = [tool.softInputs, tool.softUnless, tool.failInputs, tool.skipInputs, tool.skipUnless].flatMap((spec) => Object.keys(spec ?? {}));
  return [...listed, ...names].some((name) => w.crowded.has(name.toLowerCase()));
}

function actionReason(tool: ToolSignature, w: Inputs): Reason | null {
  if (inputsCrowded(tool, w, ARGS_INPUTS)) return 'inputs';
  const args = ARGS_INPUTS.flatMap((name) => inputWords(w, name));
  if (softInputGiven(tool.softInputs, w) || inputSetOtherwise(tool.softUnless, w) || (tool.softFlags ?? []).some((f) => flagGiven(f, args))) return 'soft';
  if (tool.actionFails === 'never') return 'never';
  if (tool.actionFails === 'input' && !failInputGiven(tool.failInputs, w)) return 'no-fail';
  return null;
}

/** Task 5: the step's inputs mean the action doesn't do this check at all (pypi-publish with a password: no attestation). */
function actionSkipped(tool: ToolSignature, w: Inputs): boolean {
  if (tool.skipInputs === undefined && tool.skipUnless === undefined) return false;
  const names = [tool.skipInputs, tool.skipUnless].flatMap((spec) => Object.keys(spec ?? {}));
  if (names.some((name) => w.crowded.has(name.toLowerCase()))) return true; // can't tell: it doesn't count
  return softInputGiven(tool.skipInputs, w) || inputSetOtherwise(tool.skipUnless, w);
}

/** Pseudo-category prefix for runs of a version known not to do the check (actionRef, Task 5 fix round 1). */
const OLD_PREFIX = '\u0000old:';
/** Pseudo-category prefix for runs pipegen couldn't follow to the end (more scripts than MAX_SCRIPTS; fix round 3). */
const UNKNOWN_PREFIX = '\u0000unknown:';
/**
 * Where an action's `uses:` ref stands against the signature's actionRef: 'ok' (it does the check), 'old' (a version
 * known not to), 'unknown' (pipegen can't place it). A signature without actionRef is always 'ok'.
 */
function refVerdict(tool: ToolSignature, uses: string): 'ok' | 'old' | 'unknown' {
  const rule = tool.actionRef;
  if (rule === undefined) return 'ok';
  const at = uses.indexOf('@');
  if (at < 0) return 'unknown';
  const ref = uses.slice(at + 1);
  if (rule.moving.includes(ref)) return 'ok';
  if (/^[0-9a-f]{40}$/.test(ref)) return rule.shas.includes(ref) ? 'ok' : 'unknown';
  const m = /^(v|release\/v)(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?$/.exec(ref);
  if (!m || (m[1] === 'release/v' && m[4] !== undefined)) return 'unknown';
  const [x, y] = [Number(m[2]), Number(m[3])];
  const [mx, my] = rule.minVersion;
  if (x < mx || (x === mx && y < my)) return 'old';
  return x === mx ? 'ok' : 'unknown'; // a later major version: not checked upstream, so not counted as covered
}

/** Task 5: a command signature that counts only with (onlyWithFlags) or without (notWithFlags) some flags. */
const flagsAllow = (tool: ToolSignature, args: readonly string[]) =>
  (tool.onlyWithFlags === undefined || tool.onlyWithFlags.some((f) => args.includes(f)))
  && !(tool.notWithFlags ?? []).some((f) => flagGiven(f, args));

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

/**
 * One shell token: an operator (incl. '\n' between commands) or a word (`w`: quotes and escapes removed). `kw` marks a
 * reserved word that opens (if, while, until, for, select, case) or closes (fi, done, esac) a compound command.
 */
interface Tk { op: string | null; w: string; kw: 'open' | 'close' | null } // every token has all three (one object shape)
/** Characters that end a word and are operators of their own (`&` only when not part of a redirection). */
const BREAK_CHARS = ';|&()`';
/** After these, a newline doesn't end the command list (`a ||⏎ b`, `{⏎`). */
const JOINERS = new Set(['&&', '||', '|', '(', '{', '$(', '\n']);
/** Reserved words bash reads only where a command starts, and where the next word starts a command again ('any'). */
const LEAD_WORDS: ReadonlyMap<string, Pos> = new Map([['if', 'any'], ['while', 'any'], ['until', 'any'], ['!', 'any'], ['time', 'any'], ['for', 'none'], ['select', 'none'], ['case', 'none']]);
/** Reserved words bash also reads right after a compound command ends (`} fi`, `done }`). */
const FOLLOW_WORDS: ReadonlyMap<string, Pos> = new Map([['then', 'any'], ['do', 'any'], ['else', 'any'], ['elif', 'any'], ['fi', 'close'], ['done', 'close'], ['esac', 'close']]);
const OPEN_KW = new Set(['if', 'while', 'until', 'for', 'select', 'case']);
const CLOSE_KW = new Set(['fi', 'done', 'esac']);
const MAX_WORD = READ_LIMITS.maxRegexLineBytes;
const isBlank = (ch: string | undefined) => ch === undefined || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';
/**
 * Where the tokenizer is: 'any' = a command can start (every reserved word, `{` and `}` count); 'close' = right after a
 * compound command or a subshell ended (only `}`, `)` and the FOLLOW_WORDS count); 'none' = inside a command.
 */
type Pos = 'any' | 'close' | 'none';
/** An open parenthesis: a subshell, a `$(` substitution, `$((` / `((` arithmetic, or a parenthesis inside arithmetic. */
type Paren = 'sub' | 'cmd' | 'arith$' | 'arithcmd' | 'arith';
/** Inside `case WORD in … esac`: before `in`, at a pattern, or in an arm's commands. */
type CaseState = 'subject' | 'pattern' | 'body';

/**
 * Shell text → tokens, in one linear pass.
 * - Quoted text ('…', "…") stays inside its word, so a separator in quotes never starts a command; `${…}` / `${{ … }}`
 *   stay inside the word too; `#` at a word start comments out the rest of the line; `\` + newline joins lines.
 * - `&` is part of a redirection word after `>`/`<` or before `>` (`2>&1`, `>&2`, `<&0`, `&>`, `&>>`); `|&` is a pipe;
 *   any other single `&` runs the command in the background.
 * - `{` opens a group only where a command starts and when a blank follows it; `}` closes one only where a command
 *   starts or right after a compound command (`done }`, `fi }`, `esac }`, `) }`, `} }`). Elsewhere both are plain
 *   characters (`echo {a`, `xargs -I {}`). Unquoted reserved words count only where bash reads them.
 * - A backtick substitution `` `…` `` becomes `$(` … `)`.
 * - Here-document bodies (`<<WORD`, `<<-WORD`, quoted or not) are skipped up to the line holding WORD alone; an
 *   unterminated one skips the rest of the text. Inside `$(( … ))` and `(( … ))` a `<<` is a shift and `#` is not a
 *   comment.
 * - In `case … in`, each pattern up to its `)` is skipped and becomes a `;` (the arm's commands follow); `;;`, `;&` and
 *   `;;&` end an arm.
 * A word longer than MAX_WORD keeps an empty value (it can't name a tool).
 */
function tokenize(text: string): Tk[] {
  const toks: Tk[] = [];
  const n = text.length;
  let i = 0;
  let pos: Pos = 'any';
  let afterFunction = false; // `function name {`: the `{` after the name opens the body
  let inBacktick = false;
  const heredocs: { delim: string; tabs: boolean }[] = [];
  let delimNext: boolean | null = null; // `<< WORD`: the next word is the delimiter (value: strip tabs)
  const parens: Paren[] = [];
  const cases: CaseState[] = [];
  const pushOp = (op: string, after: Pos = 'any') => {
    toks.push({ op, w: '', kw: null });
    pos = after;
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
  /** Skips a case pattern (`a|b)`, `(a)`, `@(x|y))`) up to the `)` that ends it; returns the index after that `)`. */
  const skipPattern = (from: number) => {
    let j = text[from] === '(' ? from + 1 : from;
    let depth = 0;
    while (j < n) {
      const ch = text[j] as string;
      if (ch === '\\') j += 2;
      else if (ch === "'") {
        const e = text.indexOf("'", j + 1);
        j = e < 0 ? n : e + 1;
      } else if (ch === '"') {
        j++;
        while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
        j++;
      } else if (ch === '(') {
        depth++;
        j++;
      } else if (ch === ')') {
        if (depth === 0) return j + 1;
        depth--;
        j++;
      } else j++;
    }
    return n;
  };
  while (i < n) {
    const c = text[i] as string;
    const next = text[i + 1];
    // (length checks first: reading index -1 of an empty array is a slow lookup in V8)
    const top = parens.length > 0 ? parens[parens.length - 1] : undefined;
    const arith = top === 'arith$' || top === 'arithcmd' || top === 'arith';
    const inCase = arith || cases.length === 0 ? undefined : cases[cases.length - 1];
    if (c === '\n') {
      const last = toks[toks.length - 1];
      if (last !== undefined && !(last.op !== null && JOINERS.has(last.op))) toks.push({ op: '\n', w: '', kw: null });
      pos = 'any';
      i = heredocs.length > 0 ? skipHeredocs(i + 1) : i + 1;
    } else if (c === ' ' || c === '\t' || c === '\r') {
      i++;
    } else if (c === '\\' && (next === '\n' || (next === '\r' && text[i + 2] === '\n'))) {
      i += next === '\n' ? 2 : 3;
    } else if (c === '#' && !arith) {
      while (i < n && text[i] !== '\n') i++;
    } else if (inCase === 'pattern') {
      if (text.startsWith('esac', i) && (isBlank(text[i + 4]) || BREAK_CHARS.includes(text[i + 4] as string))) {
        cases.pop();
        toks.push({ op: null, w: 'esac', kw: 'close' });
        pos = 'close';
        afterFunction = false;
        i += 4;
      } else {
        i = skipPattern(i);
        cases[cases.length - 1] = 'body';
        pushOp(';');
      }
    } else if (c === ';' && inCase === 'body' && (next === ';' || next === '&')) { // ;; ;& ;;& end a case arm
      i += next === ';' && text[i + 2] === '&' ? 3 : 2;
      cases[cases.length - 1] = 'pattern';
      pushOp(';');
    } else if (c === '$' && next === '(') {
      parens.push(text[i + 2] === '(' ? 'arith$' : 'cmd'); // a $( … ) inside arithmetic is a command again
      pushOp('$(');
      i += 2;
    } else if (c === '`') {
      pushOp(inBacktick ? ')' : '$(', inBacktick ? 'none' : 'any');
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
    } else if (c === ';' || c === '|') {
      pushOp(c);
      i++;
    } else if (c === '(') {
      // `((` where a command starts, or after `for`, is arithmetic (bash reads it so first)
      const prev = toks[toks.length - 1];
      const arithCmd = next === '(' && (pos === 'any' || (prev !== undefined && prev.kw === 'open' && prev.w === 'for'));
      parens.push(arith ? 'arith' : arithCmd ? 'arithcmd' : 'sub');
      pushOp('(');
      i++;
    } else if (c === ')') {
      const p = parens.pop();
      const fnParens = toks[toks.length - 1]?.op === '('; // `name()`: a function body (a compound command) follows
      pushOp(')', fnParens ? 'any' : p === 'cmd' || p === 'arith$' || p === 'arith' ? 'none' : 'close');
      i++;
    } else if (c === '{' && (pos === 'any' || afterFunction) && isBlank(next)) {
      pushOp('{');
      i++;
    } else if (c === '}' && pos !== 'none') {
      pushOp('}', 'close');
      i++;
    } else {
      let w = '';
      let quote = '';
      let quoted = false;
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
          quoted = true;
          i++;
          continue;
        }
        if (ch === '\\' && i + 1 < n) {
          if (text[i + 1] === '\n') break;
          add(text[i + 1] as string);
          quoted = true;
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
      const tk: Tk = { op: null, w: value, kw: null };
      toks.push(tk);
      // A reserved word counts only unquoted, outside arithmetic, and where bash reads it.
      const reserved = !quoted && !arith;
      const at = pos as Pos; // pushOp (a closure) also sets pos, so TypeScript's narrowing doesn't apply here
      const lead = reserved && at === 'any' ? LEAD_WORDS.get(value) : undefined;
      const follow = reserved && at !== 'none' ? FOLLOW_WORDS.get(value) : undefined;
      if (lead !== undefined || follow !== undefined) {
        if (OPEN_KW.has(value)) tk.kw = 'open';
        if (CLOSE_KW.has(value)) tk.kw = 'close';
        if (value === 'case') cases.push('subject');
        if (value === 'esac' && inCase !== undefined) cases.pop();
      } else if (reserved && value === 'in' && inCase === 'subject') {
        cases[cases.length - 1] = 'pattern';
      }
      pos = lead ?? follow ?? 'none';
      const prev = toks[toks.length - 2];
      afterFunction = prev !== undefined && prev.op === null && prev.w === 'function'; // this word names the function
      if (delimNext !== null) {
        heredocs.push({ delim: value, tabs: delimNext });
        delimNext = null;
      } else if (!arith && value.startsWith('<<') && !value.startsWith('<<<')) {
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
const WRAPPERS = new Set(['sudo', 'time', 'npx', 'bunx', 'uvx', 'env', 'nohup', 'exec', 'command', 'xargs', 'sh', 'bash', 'zsh', 'dash', 'nyc', 'cross-env']);
/** Commands that always succeed and do nothing a check needs (fix round 2, N1). */
const OK_COMMANDS: ReadonlySet<string> = new Set(['true', ':', 'echo', 'printf']);
/** Flags of a wrapper that take the next word as their value. */
const WRAPPER_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-T', '-U', '--user', '--group', '--chdir', '--host', '--prompt']),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  xargs: new Set(['-I', '-L', '-n', '-P', '-s', '-d', '-E', '-a']),
};
/** Two-word wrappers: pnpm dlx, uv run, python -m, … */
const SUB_WRAPPERS: Readonly<Record<string, readonly string[]>> = {
  pnpm: ['dlx', 'exec'], yarn: ['dlx', 'exec'], npm: ['exec'], bun: ['x'], uv: ['run'], pipx: ['run'], poetry: ['run'],
  pdm: ['run'], hatch: ['run'], pipenv: ['run'], python: ['-m'], python3: ['-m'],
};
/**
 * Task 5: wrappers whose flags pipegen knows in full. A flag outside these lists ends the match (no command at all), so
 * the value of a flag pipegen doesn't know (`uv run --with ruff python …`) can never be read as the command.
 * - uv run: https://docs.astral.sh/uv/reference/cli/#uv-run (checked 2026-10-27; `-m`/`--module` is a plain flag).
 * - nyc: its options are the nyc entries of https://github.com/istanbuljs/schema/blob/master/index.js (array, string and
 *   number options take a value); nyc exits with the wrapped command's exit code
 *   (https://github.com/istanbuljs/nyc/blob/main/bin/nyc.js: `let exitCode = process.exitCode || code`).
 */
interface StrictFlags { valued: ReadonlySet<string>; boolean: ReadonlySet<string> }
const STRICT_WRAPPER_FLAGS: Readonly<Record<string, StrictFlags>> = {
  uv: {
    valued: new Set(['--allow-insecure-host', '--trusted-host', '--cache-dir', '--color', '--config-file', '--config-setting', '--config-settings', '-C',
      '--config-settings-package', '--default-index', '--directory', '--env-file', '--exclude-newer', '--exclude-newer-package', '--extra',
      '--extra-index-url', '--find-links', '-f', '--fork-strategy', '--group', '--index', '--index-strategy', '--index-url', '-i', '--keyring-provider',
      '--link-mode', '--no-binary-package', '--no-build-isolation-package', '--no-build-package', '--no-editable-package', '--no-extra', '--no-group',
      '--no-sources-package', '--only-group', '--package', '--prerelease', '--prerelease-package', '--project', '--python', '-p', '--python-platform',
      '--refresh-package', '--reinstall-package', '--resolution', '--upgrade-group', '--upgrade-package', '-P', '--with', '-w', '--with-editable',
      '--with-requirements']),
    boolean: new Set(['--active', '--all-extras', '--all-groups', '--all-packages', '--compile-bytecode', '--compile', '--exact', '--frozen', '--gui-script',
      '--isolated', '--locked', '--managed-python', '--module', '-m', '--no-binary', '--no-build', '--no-build-isolation', '--no-cache', '--no-cache-dir',
      '-n', '--no-config', '--no-default-groups', '--no-dev', '--no-editable', '--no-env-file', '--no-index', '--no-managed-python', '--no-progress',
      '--no-project', '--no_workspace', '--no-python-downloads', '--no-require-build-hashes', '--no-sources', '--no-sync', '--offline', '--only-dev',
      '--quiet', '-q', '--refresh', '--reinstall', '--force-reinstall', '--require-build-hashes', '--script', '-s', '--system-certs', '--upgrade', '-U',
      '--verbose', '-v']),
  },
  nyc: {
    valued: new Set(['--cwd', '--nycrc-path', '--temp-dir', '-t', '--temp-directory', '--exclude', '-x', '--include', '-n', '--extension', '-e',
      '--ignore-class-methods', '--parser-plugins', '--require', '-i', '--branches', '--functions', '--lines', '--statements', '--reporter', '-r',
      '--report-dir', '--cache-dir']),
    boolean: new Set(['--exclude-node-modules', '--auto-wrap', '--es-modules', '--compact', '--preserve-comments', '--produce-source-map', '--source-map',
      '--instrument', '--exclude-after-remap', '--per-file', '--check-coverage', '--show-process-tree', '--skip-empty', '--skip-full', '--silent', '-s',
      '--all', '-a', '--eager', '--cache', '-c', '--babel-cache', '--use-spawn-wrap', '--hook-require', '--hook-run-in-context',
      '--hook-run-in-this-context', '--clean', '--in-place', '--exit-on-error', '--delete', '--complete-copy']),
  },
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
/** Script names after `npm run` etc. (ruling S5): test, lint, or test:… / lint:…, counted by name. */
const OWN_NAME_RE = /^(?:test|lint)(?::[A-Za-z0-9_.-]{1,64})?$/;
/** Task 5: any other script name, counted only when the script's own text runs a known test or lint tool. */
const SCRIPT_NAME_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.:-]{0,63}$/;
/** Fix round 3: a script name or an npm-run-all glob, as it may appear in the `by` phrase. */
const SCRIPT_PATTERN_RE = /^[A-Za-z0-9_.*][A-Za-z0-9_.:*-]{0,63}$/;
const PACKAGE_MANAGERS = ['npm', 'pnpm', 'yarn', 'bun'];
/** Task 5: a script that only fixes (lint:fix, lint-fix, format:write) is not a check. */
const fixOnly = (name: string) => name.toLowerCase().split(/[:_-]/).some((seg) => seg === 'fix' || seg === 'write');
const ownName = (name: string) => OWN_NAME_RE.test(name) && !fixOnly(name);
const TEST_CATEGORIES = ['unit-tests', 'full-tests'] as const;
/** pytest modes that collect or list tests without running them (https://docs.pytest.org/en/stable/reference/reference.html#command-line-flags). */
const PYTEST_NO_RUN: ReadonlySet<string> = new Set(['--co', '--collect-only', '--setup-plan', '--fixtures', '--fixtures-per-test', '--markers']);
/** What an own script can count for, from what its text runs (Task 5). */
const SCRIPT_CATEGORIES: ReadonlySet<string> = new Set(['unit-tests', 'full-tests', 'lint', 'format-lint']);

/**
 * Task 5: tox and nox count as the project's own test runner (like `npm test`) only when the command line picks no
 * other envs or sessions. A long flag also matches by an abbreviation (argparse's default); short flags may be grouped.
 * tox 4 (https://tox.wiki/en/latest/reference/config.html: "Set a CLI option's default with TOX_<option>", so TOX_ENV
 * picks envs like -e); TOXENV and every other variable named TOX… or NOX… is handled where the step's environment is read.
 */
const TOX_RUN_SUBS: ReadonlySet<string> = new Set(['run', 'r', 'run-parallel', 'p']);
const TOX_LONG = ['--env', '--labels', '--factors', '--notest', '--skip-env', '--override', '--listenvs', '--listenvs-all', '--showconfig', '--help-ini', '--devenv'];
const TOX_SHORT = 'emfnxla';
const NOX_LONG = ['--session', '--sessions', '--keywords', '--tags', '--list', '--list-sessions', '--json', '--install-only', '--usage'];
const NOX_SHORT = 'sektl';
function picksOther(flag: string, long: readonly string[], short: string): boolean {
  if (flag.startsWith('--')) {
    const name = flag.split('=')[0] as string;
    return name.length > 2 && long.some((f) => f.startsWith(name));
  }
  return [...(flag.slice(1).split('=')[0] as string)].some((c) => short.includes(c));
}

/**
 * Task 5: `pre-commit run` words (after `run`) that run every pre-commit-stage hook on every file: `--all-files`/`-a`,
 * no hook id, no other stage, no other config, no file list (https://pre-commit.com/#pre-commit-run). Without
 * --all-files, `pre-commit run` checks the staged files, and a CI checkout has none.
 */
function preCommitAllFiles(words: readonly string[]): boolean {
  let all = false;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string;
    const r = redirection(w);
    if (r !== null) {
      if (!r) i++;
      continue;
    }
    if (!w.startsWith('-')) return false; // a hook id, or the value of a flag pipegen doesn't know
    const eq = w.indexOf('=');
    const name = eq < 0 ? w : w.slice(0, eq);
    const value = eq < 0 ? undefined : w.slice(eq + 1);
    if ((name === '-a' || name === '--all-files') && value === undefined) all = true;
    else if (value === undefined && ['--show-diff-on-failure', '-v', '--verbose', '--fail-fast'].includes(name)) continue;
    else if (name === '--color') i += value === undefined ? 1 : 0;
    else if (name === '--hook-stage') {
      const stage = value ?? words[++i];
      if (stage !== 'pre-commit' && stage !== 'commit') return false;
    } else return false;
  }
  return all;
}

const basename = (w: string) => w.slice(w.lastIndexOf('/') + 1);
const PRE_COMMIT_ID = 'pre-commit';
const NPM_PROVENANCE_ID = 'npm-provenance';
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
/**
 * Fix round 2 (N1): one command scanShell saw, for a caller that classes every command of a script (`onCmd`).
 * `wrapper`: the word only starts another command (npx, env, cross-env, uv run, yarn <bin>…), which is reported too.
 * `dead`: it never runs (after a top-level `exit`, or right of `true ||` / `false &&`).
 */
interface CmdInfo { name: string; args: readonly string[]; dir: string | null; reason: Reason | null; dead: boolean; wrapper: boolean; afterBin: boolean }

function scanShell(text: string, base: string | null, sigs: Compiled, budget: Budget, mode: ShellMode = DEFAULT_SHELL, onCmd?: (c: CmdInfo) => void): Found[] {
  budget.bytes += text.length;
  if (budget.bytes > MAX_SCAN_BYTES) {
    budget.truncated = true;
    return [];
  }
  const toks = tokenize(text);
  const n = toks.length;
  const isWord = (k: number) => k >= 0 && k < n && toks[k]!.op === null;
  const word = (k: number) => (isWord(k) ? toks[k]!.w : null);

  // Matching group brackets (forward pass with a stack), so the right-to-left pass knows what a ')' closes. A compound
  // command (if … fi, for/while/until/select … done, case … esac) is a group too: fi/done/esac close only a compound
  // command, and one still open when a ')' or '}' comes stays unmatched (a plain word).
  const opener = new Int32Array(n).fill(-1);
  const closer = new Int32Array(n).fill(-1);
  const open: number[] = [];
  const depth = new Int32Array(n); // how many brackets and compound commands are open at k (fix round 1: `exit`)
  const pair = (k: number) => {
    const o = open.pop() as number;
    opener[k] = o;
    closer[o] = k;
  };
  for (let k = 0; k < n; k++) {
    const t = toks[k]!;
    depth[k] = open.length;
    if (t.op === '(' || t.op === '{' || t.op === '$(' || t.kw === 'open') open.push(k);
    else if (t.kw === 'close') {
      if (open.length > 0 && toks[open[open.length - 1]!]!.kw === 'open') pair(k);
    } else if (t.op === ')' || t.op === '}') {
      while (open.length > 0 && toks[open[open.length - 1]!]!.kw === 'open') open.pop();
      if (open.length > 0) pair(k);
    }
  }
  const closes = (k: number) => toks[k]!.op === ')' || toks[k]!.op === '}' || (toks[k]!.kw === 'close' && opener[k]! >= 0);
  const opens = (k: number) => toks[k]!.op === '(' || toks[k]!.op === '{' || toks[k]!.op === '$(' || (toks[k]!.kw === 'open' && closer[k]! >= 0);
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
  // later pipe stage, exempt from errexit by a later `&&`, or run in the background by a later `&`. A group (and a
  // compound command) takes on the state of what follows it.
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
    if (closes(k)) {
      stack.push({ outer, cur });
      // `VAR=$( … )` keeps the substitution's status; in any other command `$( … )` can't fail the step.
      const o = opener[k]!;
      const subst = o >= 0 && toks[o]!.op === '$(' && !(isWord(o - 1) && (toks[o - 1]!.w.endsWith('=')) && !isWord(o - 2));
      outer = { ...cur, sw: subst ? 1 : cur.sw };
      cur = { ...outer };
    } else if (opens(k)) {
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
    const key = `${f.by}\u0000${f.dir ?? ''}\u0000${f.reason ?? ''}\u0000${f.hookRun === true ? 1 : 0}`;
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
  let deadAfter = n; // fix round 1 (M3): commands after an unconditional top-level `exit` never run
  let deadTo = -1;   // fix round 2 (N1): commands up to here are the right side of `true ||` or `false &&`
  let lastCmd: { kind: 'ok' | 'fail' | 'other'; start: number; end: number } | null = null; // the last command run, where it starts and its list end
  const isDead = (k: number) => k > deadAfter || k <= deadTo;
  let binNext = -1; // the word after `yarn` / `pnpm` that may be a binary (or a script: classifyScript decides)
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
    if (isDead(k)) return;
    const args = argsAfter(k);
    if (probeCall(args)) return;
    const tryRules = (rules: CommandRule[] | undefined) => {
      for (const r of rules ?? []) {
        if (!followedBy(k, r.rest) || r.excludes.some((x) => followedBy(k, x)) || !flagsAllow(r.tool, args)) continue;
        const f = foundOf(r.tool, cwd, shellReason(k) ?? commandReason(r.tool, args));
        // `pre-commit run --all-files` at the repo root (the whole list of words read: none past MAX_FLAG_WORDS); in
        // another folder pre-commit reads that folder's .pre-commit-config.yaml (fix round 1, I2)
        if (r.tool.id === PRE_COMMIT_ID && r.rest.length === 1 && r.rest[0] === 'run' && segEnd[k]! - k - 1 <= MAX_FLAG_WORDS
          && cwd === '.' && preCommitAllFiles(args.slice(1))) f.hookRun = true;
        if (r.tool.id === NPM_PROVENANCE_ID) f.envGate = 'npm';
        add(f);
      }
    };
    if (w.includes('/')) tryRules(sigs.byPath.get(stripDotSlash(w)));
    tryRules(sigs.byFirstWord.get(name));
    if (w !== name) return;
    // The service's own scripts (ruling S5): npm test, npm run test|lint, pnpm|yarn|bun [run] test|lint, pytest,
    // python -m pytest; never a script that only fixes. Task 5: `npm|pnpm|yarn|bun run <other name>` (counted once
    // resolveScripts has read the script's text) and the tox / nox runners. Only fixed words and a script name
    // matching OWN_NAME_RE or SCRIPT_NAME_RE go into the phrase.
    let words: string[] | null = null;
    let script: string | undefined;
    let byName: string | undefined;
    let envGate: Found['envGate'];
    const a = word(k + 1);
    const b = word(k + 2);
    if (name === 'pytest') words = args.some((x) => PYTEST_NO_RUN.has(x)) ? null : ['pytest'];
    else if ((name === 'python' || name === 'python3') && a === '-m' && b === 'pytest') words = args.some((x) => PYTEST_NO_RUN.has(x)) ? null : [name, '-m', 'pytest'];
    else if (name === 'npm' && a !== null && NPM_TEST.has(a) && scriptFlagsOk(k + 1)) [words, byName] = [['npm', a], 'test'];
    else if (PACKAGE_MANAGERS.includes(name) && a !== null && (a === 'run' || (name === 'npm' && NPM_RUN.has(a))) && b !== null && ownName(b)
      && scriptFlagsOk(k + 2)) [words, byName] = [[name, a, b], b];
    else if (['pnpm', 'yarn', 'bun'].includes(name) && a !== null && ownName(a) && scriptFlagsOk(k + 1)) [words, byName] = [[name, a], a];
    else if (PACKAGE_MANAGERS.includes(name) && a !== null && (a === 'run' || (name === 'npm' && NPM_RUN.has(a))) && b !== null && SCRIPT_NAME_RE.test(b)
      && !fixOnly(b) && !OWN_NAME_RE.test(b) && scriptFlagsOk(k + 2)) {
      words = [name, a, b];
      script = b;
    } else if ((name === 'yarn' || name === 'pnpm') && a !== null && a !== 'run' && SCRIPT_NAME_RE.test(a) && !fixOnly(a) && !OWN_NAME_RE.test(a)
      && scriptFlagsOk(k + 1)) {
      // fix round 3: `yarn <script>` runs that script when package.json has it (resolveScripts drops it otherwise)
      words = [name, a];
      script = a;
    } else if (RUN_ALL.has(name) || name === 'concurrently') {
      // fix round 3: npm-run-all / run-s / run-p and concurrently `npm:` arguments run own scripts (followed when every
      // part is understood; a soft runner flag makes each partial)
      const call = scriptCall(name, args);
      if (call === null || call.unknown) return;
      for (const p of call.patterns) {
        if (!SCRIPT_PATTERN_RE.test(p) || fixOnly(p)) continue;
        add({
          categories: [], by: `your own \`${name} ${p}\``, subject: `Your own \`${name} ${p}\``, dir: cwd,
          reason: shellReason(k) ?? (call.soft ? 'soft' : null), script: p,
        });
      }
      return;
    } else if (name === 'tox') {
      const sub = toxRun(k);
      if (sub !== null) [words, envGate] = [sub === '' ? ['tox'] : ['tox', sub], 'tox'];
    } else if (name === 'nox' && noxRun(k)) [words, envGate] = [['nox'], 'nox'];
    if (words === null) return;
    const cmd = words.join(' ');
    const categories = script !== undefined ? [] : (words[words.length - 1] as string).startsWith('lint') ? ['lint'] : TEST_CATEGORIES;
    add({
      categories, by: `your own \`${cmd}\``, subject: `Your own \`${cmd}\``, dir: cwd, reason: shellReason(k),
      ...(script === undefined ? {} : { script }), ...(envGate === undefined ? {} : { envGate }), ...(byName === undefined ? {} : { byName }),
    });
  };
  /**
   * The words of the simple command at k, past redirections (more than MAX_FLAG_WORDS: false). `onWord` sees each
   * other word with the one before it, and returns false to refuse the command line.
   */
  const commandWords = (k: number, onWord: (w: string, prev: string) => boolean): boolean => {
    if (segEnd[k]! - k - 1 > MAX_FLAG_WORDS) return false;
    let prev = '';
    for (let j = k + 1; j < segEnd[k]!; j++) {
      const w = toks[j]!.w;
      const r = redirection(w);
      if (r !== null) {
        if (!r) j++;
        continue;
      }
      if (w === '--') { // the rest goes to the tests themselves; a pytest collect-only mode runs none (fix round 1, M2)
        for (let r = j + 1; r < segEnd[k]!; r++) if (PYTEST_NO_RUN.has(toks[r]!.w)) return false;
        return true;
      }
      if (!onWord(w, prev)) return false;
      prev = w;
    }
    return true;
  };
  /**
   * After `<pm> run <script>`: no flag before `--` other than --silent, -s or --if-present. npm reads such flags as its
   * own settings (`--workspace=x` runs another package's script; pnpm has --filter and -r), so the script read from
   * this directory's package.json might not be the one that runs.
   */
  const scriptFlagsOk = (k: number): boolean => {
    for (let j = k + 1; j < Math.min(segEnd[k]!, k + 1 + MAX_FLAG_WORDS); j++) {
      const w = toks[j]!.w;
      if (w === '--') return true;
      if (w.startsWith('-') && redirection(w) === null && !['--silent', '-s', '--if-present'].includes(w)) return false;
    }
    return segEnd[k]! - k - 1 <= MAX_FLAG_WORDS;
  };
  /** `tox` / `tox run|r|run-parallel|p` picking no other envs: the subcommand ('' for none), or null. */
  const toxRun = (k: number): string | null => {
    let sub = '';
    const ok = commandWords(k, (w, prev) => {
      if (w.startsWith('-')) return !picksOther(w, TOX_LONG, TOX_SHORT);
      if ((prev === '-p' || prev === '--parallel') && /^(?:auto|all|\d{1,4})$/.test(w)) return true;
      if (sub === '' && TOX_RUN_SUBS.has(w)) {
        sub = w;
        return true;
      }
      return false; // a positional word: another subcommand (list, exec, …) or a flag value pipegen doesn't know
    });
    return ok ? sub : null;
  };
  /** `nox` picking no sessions, with no positional word. */
  const noxRun = (k: number): boolean => commandWords(k, (w) => w.startsWith('-') && !picksOther(w, NOX_LONG, NOX_SHORT));
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
    return toks[j]?.op === '{' || toks[j]?.op === '(' || toks[j]?.kw === 'open' ? j : -1; // any compound command
  };
  /** Past a strict wrapper's flags (STRICT_WRAPPER_FLAGS): the index of its command, or -1 for a flag it doesn't know. */
  const skipStrictFlags = (k: number, f: StrictFlags) => {
    let j = k;
    for (let w = word(j); w !== null && w.startsWith('-'); w = word(j)) {
      if (w === '--') return j + 1;
      const eq = w.indexOf('=');
      const name = eq < 0 ? w : w.slice(0, eq);
      if (f.valued.has(name)) j += eq < 0 ? 2 : 1;
      else if (eq < 0 && (f.boolean.has(name) || (name.startsWith('--no-') && f.boolean.has(`--${name.slice(5)}`)))) j += 1;
      else return -1;
    }
    return j;
  };
  const skipFlags = (k: number, wrapper: string) => {
    const strict = STRICT_WRAPPER_FLAGS[wrapper];
    if (strict !== undefined) return skipStrictFlags(k, strict);
    const valued = WRAPPER_VALUE_FLAGS[wrapper];
    let j = k;
    // cross-env takes only VAR=value words before the command (https://github.com/kentcdodds/cross-env, src/index.ts)
    if (wrapper === 'cross-env') {
      while (word(j) !== null && ASSIGN.test(word(j) as string)) j++;
      return j;
    }
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
      // fix round 3: a `( … )` / `{ …; }` group holding only that command (and list ends) takes on its kind: `(true) || x`
      if ((op === ')' || op === '}') && lastCmd !== null && opener[k]! >= 0 && (toks[opener[k]!]!.op === '(' || toks[opener[k]!]!.op === '{')) {
        let j: number = lastCmd.end;
        while (j < k && (toks[j]!.op === ';' || toks[j]!.op === '\n')) j++;
        let i: number = opener[k]! + 1;
        while (i < lastCmd.start && toks[i]!.op === '\n') i++;
        if (j === k && i === lastCmd.start) lastCmd = { kind: lastCmd.kind, start: opener[k]!, end: k + 1 };
      }
      // `true || x`, `: || x`, `echo … || x`, `false && x`: x never runs (a bracketed x as a whole)
      if ((op === '||' || op === '&&') && lastCmd !== null && lastCmd.end === k && lastCmd.kind === (op === '||' ? 'ok' : 'fail') && k + 1 < n) {
        const after: number = k + 1;
        const group: boolean = (toks[after]!.op === '(' || toks[after]!.op === '{') && closer[after]! >= 0;
        const until: number = group ? closer[after]! : segEnd[after]!;
        deadTo = Math.max(deadTo, until);
        lastCmd = { kind: lastCmd.kind, start: lastCmd.start, end: group ? until + 1 : until };
      }
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
    // `exit` on its own in the step's top-level list (not in a group, a compound command, a function or a condition,
    // and not joined by && || | &): nothing after it runs
    if ((w === 'exit' || w === 'return') && depth[k] === 0 && !inCondition && k >= functionEnd && k > negateEnd
      && (k === 0 || toks[k - 1]!.op === ';' || toks[k - 1]!.op === '\n')
      && (segEnd[k]! >= n || toks[segEnd[k]!]!.op === ';' || toks[segEnd[k]!]!.op === '\n')) deadAfter = Math.min(deadAfter, k);
    match(k, w, name);
    const next = word(k + 1);
    const visit = (wrapper: boolean) => {
      const dead = isDead(k);
      onCmd?.({ name, args: argsAfter(k), dir: cwd, reason: shellReason(k), dead, wrapper, afterBin: binNext === k });
      if (!dead && !wrapper) lastCmd = { kind: OK_COMMANDS.has(name) ? 'ok' : name === 'false' ? 'fail' : 'other', start: k, end: segEnd[k]! };
    };
    if (name === 'docker' && next === 'run') {
      visit(false);
      let j = k + 2;
      for (let f = word(j); f !== null && f.startsWith('-'); f = word(j)) j += !f.includes('=') && DOCKER_VALUE_FLAGS.has(f) ? 2 : 1;
      const image = word(j);
      if (image !== null) match(j, image, imageName(image));
      k = j + 1; // the container's command follows the image
      cmd = true;
      continue;
    }
    if (next !== null && SUB_WRAPPERS[name]?.includes(next)) {
      const j = skipFlags(k + 2, name);
      visit(j >= 0 && word(j) !== null);
      cmd = j >= 0; // a flag a strict wrapper doesn't know: no command follows
      k = j >= 0 ? j : k + 2;
      continue;
    }
    if (WRAPPERS.has(name)) {
      const j = skipFlags(k + 1, name);
      visit(j >= 0 && word(j) !== null);
      cmd = j >= 0;
      k = j >= 0 ? j : k + 1;
      continue;
    }
    // `yarn eslint .` runs a package binary; `yarn run x` and `yarn test` run a script (no command word follows)
    const bin = BIN_RUNNERS.has(name) && next !== null && next !== 'run' && !(next === 'test' || OWN_NAME_RE.test(next));
    visit(bin);
    if (bin) binNext = k + 1;
    cmd = bin;
    k++;
  }
  return found;
}

/** A `uses: docker://image` step: the image name as a command, with `with.args` as its flags. */
function scanImage(uses: string, w: Inputs, sigs: Compiled): Found[] {
  const name = imageName(uses.slice('docker://'.length));
  const args = inputWords(w, 'args');
  if (probeCall(args)) return [];
  return (sigs.byFirstWord.get(name) ?? []).filter((r) => r.rest.length === 0)
    .map((r) => foundOf(r.tool, '.', inputsCrowded(r.tool, w, ['args']) ? 'inputs' : commandReason(r.tool, args)));
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

interface Ctx {
  p: RepoProfile; sigs: Compiled; read: Reader; budget: Budget; hits: Hit[]; localFiles: Set<string>; unreadable: boolean;
  /** Task 5: package.json files, read through their own Reader so they never use up the workflow reads. */
  pkgRead: Reader;
  pkgScripts: Map<string, Promise<ReadonlyMap<string, string> | null>>;
  /** Task 5: what each (dir, script) runs, worked out once; an entry being worked out is [] (a cycle ends there). */
  scriptMemo: Map<string, Found[]>;
  /** Fix round 2: classifyScript's answer per (dir, script). */
  scriptClass: Map<string, ScriptClass>;
  /** Fix round 3 (N6): the env gate of each local composite action path, worked out once. */
  compositeGates: Map<string, Promise<EnvGate>>;
  precommitConfig?: Promise<{ readable: boolean; found: Found[] }>;
}
/**
 * Task 5: environment variables that change what a run does, seen anywhere in the job (the workflow's, the job's or a
 * step's `env:` keys, any letter case, or any step's run text, where `echo X=… >> $GITHUB_ENV` would set one): TOX… and
 * NOX… pick envs or sessions (tox 4 reads TOX_<option>; TOXENV; NOXSESSION), SKIP skips pre-commit hooks
 * (https://pre-commit.com/#temporarily-disabling-hooks). An action that sets one through GITHUB_ENV isn't seen.
 */
interface EnvGate { tox: boolean; nox: boolean; skip: boolean; npm: boolean }
const NO_GATE: EnvGate = { tox: false, nox: false, skip: false, npm: false };
const ALL_GATE: EnvGate = { tox: true, nox: true, skip: true, npm: true };
const orGate = (a: EnvGate, b: EnvGate): EnvGate => ({ tox: a.tox || b.tox, nox: a.nox || b.nox, skip: a.skip || b.skip, npm: a.npm || b.npm });
function gateOf(texts: readonly string[], envs: readonly unknown[], base: EnvGate = NO_GATE): EnvGate {
  // an `env:` given as one expression could set anything
  if (envs.some((e) => e !== undefined && e !== null && (typeof e !== 'object' || Array.isArray(e)))) return ALL_GATE;
  const keys = envs.flatMap((e) => Object.keys(asObj(e)).slice(0, MAX_INPUT_KEYS)).map((k) => k.toUpperCase());
  const inText = (needle: string) => texts.some((t) => t.includes(needle));
  return {
    tox: base.tox || keys.some((k) => k.startsWith('TOX')) || inText('TOX'),
    nox: base.nox || keys.some((k) => k.startsWith('NOX')) || inText('NOX'),
    skip: base.skip || keys.includes('SKIP') || inText('SKIP'),
    // npm reads npm_config_* in any letter case
    npm: base.npm || keys.includes('NPM_CONFIG_DRY_RUN') || texts.some((t) => t.toLowerCase().includes('npm_config_dry_run')),
  };
}
/**
 * Drops the tox / nox runs an env var may point elsewhere and an npm publish NPM_CONFIG_DRY_RUN makes a dry run. With
 * SKIP set (fix round 1, I3), `pre-commit run` itself is partial (some hooks don't run) and its hooks' tools aren't
 * carried over.
 */
const gated = (found: Found[], g: EnvGate): Found[] => found
  .filter((f) => !((f.envGate === 'tox' && g.tox) || (f.envGate === 'nox' && g.nox) || (f.envGate === 'npm' && g.npm)))
  .map((f) => (g.skip && f.by === PRE_COMMIT_ID ? { ...f, hookRun: false, reason: f.reason ?? 'skip' } : f));

interface StepCtx {
  fit: Fit;
  where: string;
  /** Where `run:` steps start: defaults.run.working-directory of the job or workflow, else the root. */
  runDir: string | null;
  /** defaults.run.shell of the job or workflow (a step's own `shell:` wins). */
  shell: unknown;
  continueOnError: boolean;
  conditional: boolean;
  /** The step (or the local action step that led here) sets more `with:` inputs than pipegen reads. */
  inputsUnread: boolean;
  depth: number;
  /** Task 5: env vars seen in the job that change what tox, nox or pre-commit run. */
  gate: EnvGate;
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
    const reason: Reason | null = c.continueOnError ? 'continue' : (f.reason ?? (c.inputsUnread ? 'inputs' : c.conditional ? 'condition' : null));
    ctx.hits.push({
      opaque: false, categories: f.categories, by: f.by, subject: f.subject, dir: f.dir, reason,
      ...(f.partialWhy === undefined ? {} : { partialWhy: f.partialWhy }), fit: c.fit, where: c.where, ...(f.hookRun === true ? { hookRun: true } : {}),
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

// ---------- own scripts read from package.json (Task 5) ----------

/** How npm runs a script: `/bin/sh -c` on POSIX (https://docs.npmjs.com/cli/v11/using-npm/scripts), so no -e. */
const NPM_SCRIPT_SHELL: ShellMode = { errexit: false, pipefail: false };
const MAX_PACKAGE_FILES = 50; // distinct package.json files read for scripts
const MAX_SCRIPTS = 1_000;    // distinct (dir, script) pairs worked out (fix round 3: was 200, with a depth limit of 4)

/** The `scripts` of `<dir>/package.json` (string values only), or null when it can't be read. */
function packageScripts(ctx: Ctx, dir: string): Promise<ReadonlyMap<string, string> | null> {
  let r = ctx.pkgScripts.get(dir);
  if (r === undefined) {
    r = ctx.pkgScripts.size >= MAX_PACKAGE_FILES ? Promise.resolve(null) : ctx.pkgRead.text(dir === '.' ? 'package.json' : `${dir}/package.json`).then((t) => {
      if (!('ok' in t)) return null;
      try {
        const scripts = asObj(asObj(JSON.parse(t.ok)).scripts);
        return new Map(Object.entries(scripts).filter((e): e is [string, string] => typeof e[1] === 'string'));
      } catch {
        return null;
      }
    });
    ctx.pkgScripts.set(dir, r);
  }
  return r;
}

/**
 * What the script `name` of `<dir>/package.json` runs that counts for an own script (tests, lint, format-lint): its
 * text is read as npm runs it (sh -c, no -e), and the own scripts it calls in turn are read the same way. Worked out
 * once per (dir, name); a cycle, an unreadable package.json or a missing script gives [].
 */
async function scriptRuns(ctx: Ctx, dir: string, name: string): Promise<Found[]> {
  const key = `${dir}\u0000${name}`;
  const known = ctx.scriptMemo.get(key);
  if (known !== undefined) return known;
  if (ctx.scriptMemo.size >= MAX_SCRIPTS) return [];
  ctx.scriptMemo.set(key, []); // being worked out: a script that calls itself (directly or not) adds nothing
  const text = (await packageScripts(ctx, dir))?.get(name);
  if (text === undefined) return [];
  const inner = gated(await resolveScripts(ctx, scanShell(text, dir, ctx.sigs, ctx.budget, NPM_SCRIPT_SHELL)), gateOf([text], []));
  const out = inner.flatMap((g) => {
    const categories = g.categories.filter((x) => SCRIPT_CATEGORIES.has(x));
    return categories.length === 0 ? [] : [{ ...g, categories, hookRun: false }];
  });
  ctx.scriptMemo.set(key, out);
  return out;
}

/**
 * Own-script candidates (`npm run <name>` for a name not counted by name) become what their script runs, under the
 * caller's phrase, in the directory the script's tool runs in; the caller's reason (an `||`, a pipe, …) comes first. A candidate whose script runs
 * nothing that counts is dropped.
 */
async function resolveScripts(ctx: Ctx, found: Found[]): Promise<Found[]> {
  if (!found.some((f) => f.script !== undefined || f.byName !== undefined)) return found;
  const out: Found[] = [];
  for (const f of found) {
    if (f.byName !== undefined) {
      const lowered = await byNameRun(ctx, f);
      if (lowered !== null) out.push(lowered);
      continue;
    }
    if (f.script === undefined) {
      out.push(f);
      continue;
    }
    if (f.dir === null) continue;
    for (const name of expandScripts([f.script], await packageScripts(ctx, f.dir))) for (const g of await scriptRuns(ctx, f.dir, name)) {
      out.push({ // the script's own `cd` counts: `cd api && jest` tests the api service only
        categories: g.categories, by: f.by, subject: f.subject, dir: g.dir, reason: f.reason ?? g.reason,
        ...(f.reason === null && g.partialWhy !== undefined ? { partialWhy: g.partialWhy } : {}),
        ...(g.envGate === undefined ? {} : { envGate: g.envGate }),
      });
    }
  }
  return out;
}

/**
 * Fix round 3 (N7): a command that runs package scripts. `patterns`: script names or globs; `soft`: the runner can't fail
 * on them (npm-run-all -c, concurrently --success other than all); `unknown`: part of it is something pipegen can't
 * follow (an unknown flag, a plain command given to concurrently, a flag before the script name).
 * - npm: run, run-script, rum, urn <name>; test, t, tst (https://github.com/npm/cli/blob/latest/lib/utils/cmd-list.js).
 * - yarn | pnpm | bun: run <name>; test; lint[:x]; and `yarn|pnpm <name>` when that script exists (`scripts` given).
 * - npm-run-all, run-s, run-p: every non-flag argument is a script pattern; `*` stays inside one `:` part, `**`
 *   crosses them (https://github.com/mysticatea/npm-run-all/blob/master/docs/npm-run-all.md).
 * - concurrently: `npm:`, `yarn:`, `pnpm:` and `bun:` arguments name scripts (globs allowed).
 * After the name(s), a flag other than --silent, -s or --if-present (npm's --workspace, pnpm's --filter) is unknown.
 */
interface ScriptCall { patterns: string[]; soft: boolean; unknown: boolean }
const NPM_RUN: ReadonlySet<string> = new Set(['run', 'run-script', 'rum', 'urn']);
const NPM_TEST: ReadonlySet<string> = new Set(['test', 't', 'tst']);
const RUN_ALL: ReadonlySet<string> = new Set(['npm-run-all', 'run-s', 'run-p']);
const RUN_ALL_FLAGS: ReadonlySet<string> = new Set(['-s', '--serial', '--sequential', '-p', '--parallel', '-l', '--print-label', '-n', '--print-name', '-r', '--race',
  '--silent', '--aggregate-output']);
const CONCURRENTLY_VALUED: ReadonlySet<string> = new Set(['-n', '--names', '--name-separator', '-c', '--prefix-colors', '-p', '--prefix', '-l', '--prefix-length',
  '-t', '--timestamp-format', '--default-input-target', '--restart-tries', '--restart-after', '-m', '--max-processes', '--kill-signal', '--hide']);
const CONCURRENTLY_BOOLEAN: ReadonlySet<string> = new Set(['-k', '--kill-others', '--kill-others-on-fail', '-r', '--raw', '--no-color', '-g', '--group', '-i',
  '--handle-input', '--pad-prefix', '-P', '--passthrough-arguments', '--timings']);
const SCRIPT_FLAGS_OK: ReadonlySet<string> = new Set(['--silent', '-s', '--if-present']);
const MAX_SCRIPT_TARGETS = 200;

function scriptCall(name: string, args: readonly string[], scripts?: ReadonlyMap<string, string> | null): ScriptCall | null {
  const after = (from: number): boolean => { // unknown flags after the name(s), before `--`
    for (const w of args.slice(from)) {
      if (w === '--') return false;
      if (w.startsWith('-') && redirection(w) === null && !SCRIPT_FLAGS_OK.has(w)) return true;
    }
    return false;
  };
  const one = (pattern: string, from: number): ScriptCall => ({ patterns: [pattern], soft: false, unknown: after(from) });
  const [a, b] = args;
  if (a === undefined) return null;
  if (name === 'npm') {
    if (NPM_TEST.has(a)) return one('test', 1);
    if (NPM_RUN.has(a) && b !== undefined && b !== '' && !b.startsWith('-')) return one(b, 2);
    return null;
  }
  if (PACKAGE_MANAGERS.includes(name)) {
    if (a === 'run' && b !== undefined && b !== '' && !b.startsWith('-')) return one(b, 2);
    if (a === 'test' || ownName(a)) return one(a, 1);
    if ((name === 'yarn' || name === 'pnpm') && scripts?.has(a) === true && !a.startsWith('-')) return one(a, 1);
    return null;
  }
  if (RUN_ALL.has(name)) {
    const out: ScriptCall = { patterns: [], soft: false, unknown: false };
    for (let i = 0; i < args.length; i++) {
      const w = args[i] as string;
      if (w === '--') break;
      if (w === '-c' || w === '--continue-on-error') out.soft = true;
      else if (w === '--max-parallel' || w === '--npm-path') i++;
      else if (w.startsWith('--max-parallel=') || w.startsWith('--npm-path=') || RUN_ALL_FLAGS.has(w)) continue;
      else if (w.startsWith('-')) out.unknown = true;
      else out.patterns.push(w.trim().split(/\s+/)[0] as string); // "build:* -- --watch": the task is the first word
    }
    return out;
  }
  if (name === 'concurrently') {
    const out: ScriptCall = { patterns: [], soft: false, unknown: false };
    for (let i = 0; i < args.length; i++) {
      const w = args[i] as string;
      const eq = w.indexOf('=');
      const flag = eq > 0 ? w.slice(0, eq) : w;
      if (flag === '-s' || flag === '--success') {
        const v = eq > 0 ? w.slice(eq + 1) : args[++i];
        if (v !== 'all') out.soft = true;
      } else if (CONCURRENTLY_VALUED.has(flag)) i += eq > 0 ? 0 : 1;
      else if (CONCURRENTLY_BOOLEAN.has(w)) continue;
      else if (w.startsWith('-')) out.unknown = true;
      else {
        const m = /^(?:npm|yarn|pnpm|bun):(.+)$/.exec(w.trim());
        if (m) out.patterns.push((m[1] as string).split(/\s+/)[0] as string);
        else out.unknown = true; // a plain command: not followed
      }
    }
    return out;
  }
  return null;
}

/** Script names a call's patterns name: a plain name as is, a glob (* ? [) against this package.json's scripts (capped). */
function expandScripts(patterns: readonly string[], scripts: ReadonlyMap<string, string> | null | undefined): string[] {
  const out: string[] = [];
  for (const p of patterns) {
    if (!/[*?[]/.test(p)) out.push(p);
    else for (const name of scripts?.keys() ?? []) if (scriptGlob(p, name)) out.push(name);
  }
  return [...new Set(out)].slice(0, MAX_SCRIPT_TARGETS);
}
/** npm-run-all's script globs: `:` separates parts like `/` in a path (globMatch: linear, capped at MAX_GLOB). */
const scriptGlob = (pattern: string, name: string) => globMatch(pattern.replace(/\//g, '\u0001').replace(/:/g, '/'), name.replace(/\//g, '\u0001').replace(/:/g, '/'));

/** What a script really runs, for ruling U23: `real` = something other than no-ops; `soft` = a reason when none of those runs can fail it; `capped` = more scripts than pipegen follows. */
interface ScriptClass { real: boolean; soft: Reason | null; capped?: boolean }

/** A known tool called in a mode that runs nothing: a version/help probe, a `notWithFlags` flag, or a pytest collect-only flag. */
function runsNothing(c: CmdInfo, sigs: Compiled): boolean {
  if (probeCall(c.args)) return true;
  const afterDash = c.args.indexOf('--');
  if ((c.name === 'tox' || c.name === 'nox') && afterDash >= 0 && c.args.slice(afterDash + 1).some((a) => PYTEST_NO_RUN.has(a))) return true;
  if ((c.name === 'pytest' || ((c.name === 'python' || c.name === 'python3') && c.args[0] === '-m' && c.args[1] === 'pytest')) && c.args.some((a) => PYTEST_NO_RUN.has(a))) return true;
  return (sigs.byFirstWord.get(c.name) ?? []).some((r) => r.rest.every((x, i) => c.args[i] === x) && (r.tool.notWithFlags ?? []).some((f) => flagGiven(f, c.args)));
}

/**
 * Fix round 2 (N1, N3) and 3 (N7; ruling U23): every top-level command of a package script, read as npm runs it (sh -c,
 * no -e), is (a) a no-op (echo, printf, true, :, false, an exit or return of 0, a bare exit), (b) dead (after a
 * top-level exit, right of `true ||` / `false &&`, also with the no-op in a `( … )` / `{ …; }` group), (c) a known tool
 * in a mode that runs nothing (--version, --help, jest --listTests, pytest --co…), (d) a call to other own scripts
 * (scriptCall: npm run/run-script/rum/urn, npm test/t/tst, yarn|pnpm|bun run X, yarn|pnpm X for a script that exists,
 * npm-run-all/run-s/run-p and concurrently `npm:` arguments, globs matched) that all do nothing by this same rule
 * (followed with no depth limit; each (dir, script) worked out once, a cycle doing nothing, at most MAX_SCRIPTS), or
 * (e) anything else. `real` when some command is (e); `soft` when every (e) has a reason that keeps it from failing
 * the script (`x || true`, `x; exit 0`: under sh -c only the last list can fail it). An unreadable script is unknown
 * and counts as real; past MAX_SCRIPTS the answer is `capped` (the row becomes unknown).
 */
async function classifyScript(ctx: Ctx, dir: string, name: string): Promise<ScriptClass> {
  const key = `${dir}\u0000${name}`;
  const known = ctx.scriptClass.get(key);
  if (known !== undefined) return known;
  const scripts = await packageScripts(ctx, dir);
  const text = scripts?.get(name);
  if (text === undefined || scripts === null || scripts === undefined) return { real: true, soft: null };
  if (ctx.scriptClass.size >= MAX_SCRIPTS) return { real: true, soft: null, capped: true };
  ctx.scriptClass.set(key, { real: false, soft: null }); // being worked out: a cycle does nothing
  const cmds: CmdInfo[] = [];
  scanShell(text, dir, ctx.sigs, ctx.budget, NPM_SCRIPT_SHELL, (c) => { cmds.push(c); });
  let real = false;
  let capped = false;
  let soft: Reason | null = null;
  let allSoft = true;
  const realRun = (reason: Reason | null) => {
    real = true;
    if (reason === null) allSoft = false;
    else soft ??= reason;
  };
  let scriptBin = false; // the previous command was `yarn|pnpm <script>`: its next word is that script, not a binary
  for (const c of cmds) {
    const call = scriptCall(c.name, c.args, scripts);
    const skip = scriptBin && c.afterBin;
    scriptBin = call !== null && c.wrapper;
    if (skip || c.dead || (c.wrapper && call === null)) continue;
    // no-ops: they run no check (`false` only fails the script, it tests nothing)
    if (OK_COMMANDS.has(c.name) || c.name === 'false' || ((c.name === 'exit' || c.name === 'return') && (c.args.length === 0 || /^0+$/.test(c.args[0] as string)))) continue;
    if (runsNothing(c, ctx.sigs)) continue;
    if (call !== null && c.dir !== null && !call.unknown) {
      const targets = expandScripts(call.patterns, c.dir === dir ? scripts : await packageScripts(ctx, c.dir));
      let innerReal = false;
      let innerAllSoft = true;
      let innerSoft: Reason | null = null;
      for (const t of targets) {
        const inner = await classifyScript(ctx, c.dir, t);
        if (inner.capped === true) capped = true;
        if (!inner.real) continue;
        innerReal = true;
        if (inner.soft === null) innerAllSoft = false;
        else innerSoft ??= inner.soft;
      }
      if (targets.length === 0) realRun(c.reason); // nothing matched: the runner fails, pipegen can't tell more
      else if (innerReal) realRun(c.reason ?? (call.soft ? 'soft' : innerAllSoft ? innerSoft : null));
      continue;
    }
    realRun(c.reason);
  }
  const out: ScriptClass = { real, soft: real && allSoft ? soft : null, ...(capped ? { capped } : {}) };
  ctx.scriptClass.set(key, out);
  return out;
}

/**
 * Ruling U23: a script counted by name (S5) whose text can be read may only be LOWERED by it: no text (no package.json,
 * no such script) keeps it; a script that runs nothing (classifyScript) drops it (missing); one whose real runs all
 * can't fail it is partial; one whose runs of a known tool for this need all have a reason (|| true, a soft flag, …) is
 * partial with that reason; anything else keeps it (an unknown runner such as `node test.js` or tape stays counted).
 */
async function byNameRun(ctx: Ctx, f: Found): Promise<Found | null> {
  if (f.dir === null || f.byName === undefined) return f;
  const text = (await packageScripts(ctx, f.dir))?.get(f.byName);
  if (text === undefined) return f;
  const cls = await classifyScript(ctx, f.dir, f.byName);
  if (cls.capped === true) {
    return { ...f, categories: f.categories.map((c) => `${UNKNOWN_PREFIX}${c}`), reason: null, partialWhy: `There are more package scripts than pipegen follows (${MAX_SCRIPTS.toLocaleString('en-US')}), so it can't tell what ${f.subject.charAt(0).toLowerCase()}${f.subject.slice(1)} runs.` };
  }
  if (!cls.real) return null;
  if (cls.soft !== null) return { ...f, reason: f.reason ?? cls.soft };
  const runs = (await scriptRuns(ctx, f.dir, f.byName)).filter((g) => g.categories.some((c) => f.categories.includes(c)));
  const first = runs[0];
  if (first !== undefined && runs.every((g) => g.reason !== null)) return { ...f, reason: f.reason ?? first.reason };
  return f;
}

/** Task 5: pre-commit/action runs `pre-commit run … ${extra_args}`, `--all-files` by default (https://github.com/pre-commit/action/blob/main/action.yml). */
function preCommitActionAllFiles(w: Inputs): boolean {
  if (w.crowded.has('extra_args')) return false;
  const all = w.byName.get('extra_args') ?? [];
  if (all.length === 0) return true;
  return all.every((v) => {
    if (v === null || v === undefined) return true; // `extra_args:` with no value: the default
    if (typeof v !== 'string' || !regexSafe(v) || v.includes('${{')) return false;
    const toks = tokenize(v);
    return toks.every((t) => t.op === null) && preCommitAllFiles(toks.map((t) => t.w));
  });
}

async function walkStep(ctx: Ctx, step: Obj, c: StepCtx): Promise<void> {
  if (!spend(ctx)) return;
  const cond = condition(step.if, repoId(ctx));
  if (cond === 'never') return;
  const withInputs = lowerInputs(asObj(step.with));
  const sc: StepCtx = {
    ...c, continueOnError: c.continueOnError || allowedToFail(step['continue-on-error']), conditional: c.conditional || cond === 'partial',
    inputsUnread: c.inputsUnread || withInputs.unread, gate: gateOf(typeof step.run === 'string' ? [step.run] : [], [step.env], c.gate),
  };
  if (typeof step.uses === 'string' && regexSafe(step.uses)) {
    const uses = step.uses.trim();
    if (uses === '.' || uses.startsWith('./')) {
      await followAction(ctx, uses, sc);
    } else if (uses.startsWith('docker://')) {
      addFound(ctx, scanImage(uses, withInputs, ctx.sigs), sc);
    } else {
      const tools = actionMatches(ctx.sigs, uses);
      addFound(ctx, gated(tools.filter((t) => !actionSkipped(t, withInputs)).map((t) => {
        const verdict = refVerdict(t, uses);
        const f = foundOf(t, '.', actionReason(t, withInputs) ?? (verdict === 'unknown' ? 'ref' : null));
        if (verdict === 'unknown' && t.actionRef !== undefined) f.partialWhy = t.actionRef.unknownWhy;
        if (verdict === 'old' && t.actionRef !== undefined) {
          return { ...f, categories: t.categories.map((c) => `${OLD_PREFIX}${c}`), reason: null, partialWhy: t.actionRef.oldWhy };
        }
        if (t.id === PRE_COMMIT_ID && preCommitActionAllFiles(withInputs)) f.hookRun = true;
        return f;
      }), sc.gate), sc);
      const owner = uses.split('/')[0]?.toLowerCase();
      if (tools.length === 0 && owner !== undefined && owner === ctx.p.owner.toLowerCase()) opaque(ctx, OPAQUE_WHY.ownerAction, validRef(uses), sc);
    }
  }
  if (typeof step.run === 'string') {
    const base = firstSet(workingDir(step['working-directory']), c.runDir);
    const found = await resolveScripts(ctx, scanShell(step.run, base, ctx.sigs, ctx.budget, shellMode(step.shell ?? c.shell)));
    addFound(ctx, gated(found, sc.gate), sc);
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

/**
 * Fix round 3 (N6): the env gate a local composite action (`uses: ./dir`) adds to the job that uses it: its steps' run
 * text and `env:`. Worked out once per action path per mapCoverage call (one read, one parse, its text counted
 * against the scan-byte budget). Anything that isn't a readable composite action adds nothing; past the budget pipegen
 * can't tell, so the gate is all on (rows lean partial, and the truncated budget makes would-be-missing rows unknown).
 */
function compositeGate(ctx: Ctx, uses: string): Promise<EnvGate> {
  if (!(uses === '.' || uses.startsWith('./'))) return Promise.resolve(NO_GATE);
  const rel = localPath(uses);
  if (rel === null || rel === 'outside') return Promise.resolve(NO_GATE);
  let gate = ctx.compositeGates.get(rel);
  if (gate === undefined) {
    gate = (async () => {
      for (const name of ['action.yml', 'action.yaml']) {
        const file = rel === '.' ? name : `${rel}/${name}`;
        const doc = await readLocal(ctx, file);
        if ('fail' in doc && doc.fail === 'missing') continue;
        if ('fail' in doc) return NO_GATE;
        const text = await ctx.read.text(file);
        ctx.budget.bytes += 'ok' in text ? text.ok.length : 0;
        if (ctx.budget.bytes > MAX_SCAN_BYTES) {
          ctx.budget.truncated = true;
          return ALL_GATE;
        }
        const runs = asObj(doc.ok.runs);
        if (runs.using !== 'composite') return NO_GATE;
        const steps = list(runs.steps).slice(0, MAX_STEPS).map(asObj);
        return gateOf(steps.flatMap((st) => (typeof st.run === 'string' ? [st.run] : [])), steps.map((st) => st.env));
      }
      return NO_GATE;
    })();
    ctx.compositeGates.set(rel, gate);
  }
  return gate;
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
      await callWorkflow(ctx, job.uses.trim(), { fit, where, runDir: '.', shell: undefined, continueOnError: false, conditional: jobConditional, inputsUnread: false, depth, gate: NO_GATE });
      continue;
    }
    const steps = list(job.steps);
    if (steps.length > MAX_STEPS) ctx.budget.truncated = true;
    const kept = steps.slice(0, MAX_STEPS).map(asObj);
    // fix round 2 (N4): a local composite action the job uses runs in the same job, so its steps' env and run text
    // (`echo SKIP=… >> $GITHUB_ENV`) count for the whole job too
    // each distinct `uses:` once per job; each action read once per call (compositeGate caches it)
    let compositeGates = NO_GATE;
    for (const uses of new Set(kept.flatMap((st) => (typeof st.uses === 'string' && regexSafe(st.uses) ? [st.uses.trim()] : [])))) {
      compositeGates = orGate(compositeGates, await compositeGate(ctx, uses));
    }
    const c: StepCtx = {
      fit, where, runDir: firstSet(defaultsDir(job), wfDir), shell: defaultsShell(job) ?? wfShell ?? (onWindows(job) ? 'pwsh' : undefined),
      continueOnError: allowedToFail(job['continue-on-error']), conditional: jobConditional, inputsUnread: false, depth,
      gate: gateOf(kept.flatMap((st) => (typeof st.run === 'string' ? [st.run] : [])), [doc.env, job.env, ...kept.map((st) => st.env)], compositeGates),
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

/**
 * Task 5: a pre-commit `entry` (or a hook id) and its `args` as ONE command: pre-commit runs the entry without a
 * shell (https://pre-commit.com/#new-hooks), so `;`, `&&` or `|` in it are plain words, never a second command. The
 * words before the first operator are kept, up to the first word with a character outside [A-Za-z0-9_./:=@+,%-]
 * (a word with spaces or quotes, like `bash -c '…'`, isn't read into).
 */
function hookCommand(entry: string, args: readonly string[]): string {
  const out: string[] = [];
  for (const t of [...tokenize(entry), ...args.flatMap((a) => (regexSafe(a) ? [{ op: null, w: a, kw: null } as Tk] : []))]) {
    if (t.op !== null || !/^[A-Za-z0-9_./:=@+,%-]+$/.test(t.w) || out.length > MAX_FLAG_WORDS) break;
    out.push(t.w);
  }
  return out.join(' ');
}

/**
 * The tools `.pre-commit-config.yaml` runs. A hook runs before each commit when its `stages` (else `default_stages`)
 * include pre-commit or the legacy commit; one for another stage is kept with reason `stage`. Read once per call.
 * - `repo: local`: only the hook's `entry` runs; its id is just a name (Task 5). `repo: meta`: never counts.
 * - another repo: an `entry` set in the config replaces the hook's own; else a hook listed in tool-signatures.yml
 *   (`precommitHooks`: the exact repo URL and id) runs that tool, with the hook's `args` read for soft flags; else the
 *   id is read as a command (the hook's own entry isn't in this repo), with its args, as partial (`hook-repo`).
 * Fix round 1 (C2, I2): `meta` never counts; local `language: fail`/`pygrep` entries are a message or a regex, not a
 * command; a repo not listed in `precommitHooks` gives `hook-repo` (partial); any file filter gives `files`
 * (partial, never evaluated); another stage gives `stage` (partial). Not modelled: `always_run`, `fail_fast`.
 */
const NOT_A_COMMAND_LANGUAGES: ReadonlySet<string> = new Set(['fail', 'pygrep', 'script', 'unsupported_script', 'docker_image']);

function readPrecommitConfig(ctx: Ctx): Promise<{ readable: boolean; found: Found[] }> {
  ctx.precommitConfig ??= (async () => {
    const r = await ctx.read.yaml(HOOK_FILE['pre-commit']);
    if ('fail' in r) return { readable: r.fail === 'missing', found: [] };
    const defaultStages = strs(r.ok.default_stages);
    const isSet = (o: Obj, key: string) => key in o && o[key] !== null && o[key] !== undefined;
    const topFiltered = isSet(r.ok, 'files') || isSet(r.ok, 'exclude');
    const found: Found[] = [];
    const scan = (text: string) => scanShell(text, '.', ctx.sigs, ctx.budget, DEFAULT_SHELL);
    const tag = (fs: Found[], reason: Reason): Found[] => fs.map((f) => ({ ...f, reason: f.reason ?? reason }));
    for (const rawRepo of list(r.ok.repos).slice(0, MAX_HOOKS)) {
      const repo = asObj(rawRepo);
      const url = typeof repo.repo === 'string' && regexSafe(repo.repo) ? repo.repo : '';
      if (url === 'meta') continue; // pre-commit's own config checks; `entry` can't be set there
      const local = url === 'local';
      const known = !local && ctx.sigs.hookRepos.has(hookRepo(url));
      for (const raw of list(repo.hooks).slice(0, MAX_HOOKS)) {
        const hook = asObj(raw);
        const args = strs(hook.args).slice(0, MAX_FLAG_WORDS);
        const id = typeof hook.id === 'string' && regexSafe(hook.id) ? hook.id : '';
        const entry = typeof hook.entry === 'string' && regexSafe(hook.entry) ? hook.entry : undefined;
        let hookFound: Found[] = [];
        if (local) {
          // `language: fail` prints its entry as a message and `pygrep` reads it as a regex; `script` and
          // `unsupported_script` run the entry as a file in the repo, and `docker_image` starts with an image name
          // (https://pre-commit.com/#supported-languages): none of them runs the named tool (fix round 2, N2)
          if (entry !== undefined && !(typeof hook.language === 'string' && NOT_A_COMMAND_LANGUAGES.has(hook.language))) hookFound = scan(hookCommand(entry, args));
        } else if (entry !== undefined) {
          hookFound = known ? scan(hookCommand(entry, args)) : tag(scan(hookCommand(entry, args)), 'hook-repo');
        } else if (id !== '') {
          const tools = known ? ctx.sigs.hooks.get(hookRepoKey(url, id)) : undefined;
          hookFound = tools !== undefined ? tools.map((t) => foundOf(t, '.', commandReason(t, args))) : tag(scan(hookCommand(id, args)), 'hook-repo');
        }
        // a file filter pipegen doesn't evaluate (they are Python regexes from the repo), or another stage
        const filtered = topFiltered || ['files', 'exclude', 'types', 'types_or', 'exclude_types'].some((k) => isSet(hook, k));
        if (filtered) hookFound = tag(hookFound, 'files');
        const stages = 'stages' in hook ? strs(hook.stages) : defaultStages;
        if (stages.length > 0 && !stages.some((st) => st === 'pre-commit' || st === 'commit')) hookFound = hookFound.map((f) => ({ ...f, reason: 'stage' }));
        found.push(...hookFound);
      }
    }
    return { readable: true, found: await resolveScripts(ctx, found) };
  })();
  return ctx.precommitConfig;
}

async function readHooks(ctx: Ctx): Promise<Hooks> {
  const manager = ctx.p.precommit;
  const none: Hooks = { manager, where: '', readable: true, found: [] };
  if (manager === null) return none;
  const scan = async (text: string, base: string | null, mode: ShellMode) =>
    gated(await resolveScripts(ctx, scanShell(text, base, ctx.sigs, ctx.budget, mode)), gateOf([text], []));
  if (manager === 'husky') {
    const where = '.husky/pre-commit';
    const r = await ctx.read.text(where);
    if ('fail' in r) return { ...none, where: '.husky', readable: r.fail === 'missing' };
    return { manager, where, readable: true, found: await scan(r.ok, '.', HUSKY_SHELL) };
  }
  if (manager === 'pre-commit') {
    const config = await readPrecommitConfig(ctx);
    return { manager, where: HOOK_FILE['pre-commit'], readable: config.readable, found: config.found };
  }
  // lefthook: the first of lefthook.yml / lefthook.yaml that exists (readPrecommit's order)
  for (const where of ['lefthook.yml', 'lefthook.yaml']) {
    const r = await ctx.read.yaml(where);
    if ('fail' in r && r.fail === 'missing') continue;
    if ('fail' in r) return { ...none, where, readable: false };
    const hook = asObj(r.ok['pre-commit']);
    const entries = [...Object.values(asObj(hook.commands)), ...list(hook.jobs)].slice(0, MAX_HOOKS).map(asObj);
    const found: Found[] = [];
    for (const e of entries) if (typeof e.run === 'string') found.push(...(await scan(e.run, firstSet(workingDir(e.root)), LEFTHOOK_SHELL)));
    return { manager, where, readable: true, found };
  }
  return none;
}

/**
 * Task 5: a CI run of `pre-commit run --all-files` (hookRun) runs the hooks' lint tools there too. Only `lint` is
 * carried over: a secret-scan hook such as gitleaks' scans the staged changes (`--staged`, pass_filenames: false,
 * https://github.com/gitleaks/gitleaks/blob/master/.pre-commit-hooks.yaml), and a CI checkout has none staged. One run
 * per (trigger fit, reason) is enough (the first run of each kind is what a need reads), so this stays small.
 */
async function hookRunHits(ctx: Ctx): Promise<void> {
  const reps = new Map<string, Hit>();
  for (const h of ctx.hits) {
    const key = `${h.fit.push ? 1 : 0}${h.fit.merge ? 1 : 0}${h.fit.deploy ? 1 : 0}\u0000${h.reason ?? ''}`;
    if (h.hookRun === true && !reps.has(key)) reps.set(key, h);
  }
  if (reps.size === 0) return;
  const tools = new Map<string, Found>();
  for (const f of (await readPrecommitConfig(ctx)).found) {
    const key = `${f.by}\u0000${f.reason ?? ''}`;
    // a hook set up for another stage doesn't run in `pre-commit run` (its default stage is pre-commit)
    if (f.categories.includes('lint') && f.reason !== 'stage' && !tools.has(key)) tools.set(key, f);
  }
  for (const rep of reps.values()) {
    for (const t of tools.values()) {
      if (ctx.hits.length >= MAX_HITS) {
        ctx.budget.truncated = true;
        return;
      }
      ctx.hits.push({
        opaque: false, categories: ['lint'], by: t.by, subject: `${t.subject} in the pre-commit hooks`, dir: '.', reason: rep.reason ?? t.reason,
        fit: rep.fit, where: cut(`${rep.where} → ${HOOK_FILE['pre-commit']}`),
      });
    }
  }
}

// ---------- which runs count for which need (ruling S26, review C1) ----------
//
// A run in `dir` counts for a service when the service owns `dir` (the longest service path at or above it, '.' always
// at or above; on a tie the service listed first) or when the service sits below `dir` (a job run above several
// services covers each). A run at the root counts for every need, and a run whose dir can't be known only for
// repo-wide needs. The repo is hostile, so the work is linear, not needs × runs × services: each distinct dir is
// matched against the services once, through trees of path segments; one pass over the runs keeps, per (dir,
// category, layer), only the first run of each kind (the run the per-run loop used to pick, so `by` and `where` are
// unchanged); each need then reads those first runs for the dirs that count for it.

const normalPath = (s: string) => {
  const n = posix.normalize(s).replace(/\/+$/, '');
  return n === '' ? '.' : n;
};

const ALL = 0;  // every run, whatever its dir: what a repo-wide need reads
const ROOT = 1; // '.'

/** Distinct dirs that runs were found in, by id. Past MAX_HIT_DIRS a new dir gets no id (its runs count only in ALL). */
class Dirs {
  readonly names: string[] = ['', '.'];
  private readonly ids = new Map<string, number>([['.', ROOT]]);
  capped = false;
  /** The dir's id, or -1: the dir can't be known (null) or is over the cap. */
  idOf(dir: string | null): number {
    if (dir === null) return -1;
    const known = this.ids.get(dir);
    if (known !== undefined) return known;
    if (this.names.length - 2 >= MAX_HIT_DIRS) {
      this.capped = true;
      return -1;
    }
    this.ids.set(dir, this.names.length);
    this.names.push(dir);
    return this.names.length - 1;
  }
}

// What a run is, for one layer: on the layer's trigger and nothing stops it blocking (FN), on the trigger under an
// `if:` (FC), on the trigger for another reason it can't block (FO), or on another trigger (NF).
const FN = 0;
const FC = 1;
const FO = 2;
const NF = 3;
const LAYER_SLOT: Readonly<Record<CiLayer, number>> = { push: 0, merge: 4, deploy: 8 };
const CI_LAYERS: readonly CiLayer[] = ['push', 'merge', 'deploy'];
const OPAQUE_KEY = '\0opaque'; // not a category: the opaque runs (they have none)

/** Per (category, dir): the index of the first run of each kind, for each layer (-1 = none). */
class Firsts {
  private readonly byKey = new Map<string, Map<number, Int32Array>>();

  constructor(readonly hits: readonly Hit[], dirs: Dirs) {
    for (let i = 0; i < hits.length; i++) {
      const h = hits[i] as Hit;
      const d = dirs.idOf(h.dir);
      for (const key of h.opaque ? [OPAQUE_KEY] : h.categories) {
        this.put(key, ALL, h, i);
        if (d >= 0) this.put(key, d, h, i);
      }
    }
  }

  private put(key: string, dir: number, h: Hit, i: number): void {
    let byDir = this.byKey.get(key);
    if (!byDir) this.byKey.set(key, (byDir = new Map()));
    let at = byDir.get(dir);
    if (!at) byDir.set(dir, (at = new Int32Array(12).fill(-1)));
    for (const layer of CI_LAYERS) {
      const slot = LAYER_SLOT[layer] + (!h.fit[layer] ? NF : h.reason === null ? FN : MAY_NOT_RUN.has(h.reason) ? FC : FO);
      if ((at[slot] as number) < 0) at[slot] = i;
    }
  }

  /** The first run in these dirs of one of these kinds on the layer. */
  first(key: string, dirs: readonly number[], layer: CiLayer, kinds: readonly number[]): Hit | undefined {
    const byDir = this.byKey.get(key);
    if (!byDir) return undefined;
    let best = -1;
    for (const d of dirs) {
      const at = byDir.get(d);
      if (!at) continue;
      for (const k of kinds) {
        const i = at[LAYER_SLOT[layer] + k] as number;
        if (i >= 0 && (best < 0 || i < best)) best = i;
      }
    }
    return best < 0 ? undefined : this.hits[best];
  }
}

interface SegNode { kids: Map<string, SegNode>; id: number }
const segNode = (): SegNode => ({ kids: new Map(), id: -1 });
function segInsert(tree: SegNode, path: string, id: number): void {
  let n = tree;
  for (const seg of path.split('/')) {
    let next = n.kids.get(seg);
    if (!next) n.kids.set(seg, (next = segNode()));
    n = next;
  }
  if (n.id < 0) n.id = id;
}

/** Which dirs count for each service. Built once per mapCoverage call, after every run's dir is known. */
class Scope {
  /** More services than MAX_SERVICES: per-service needs read only the runs at the root. */
  readonly capped: boolean;
  private readonly target = new Map<string, string>(); // service name → path of the first service with that name
  private readonly owned = new Map<string, number[]>(); // service name → the dirs it owns
  private readonly dirTree = segNode();
  private readonly memo = new Map<string, readonly number[]>();

  constructor(services: readonly Service[], dirs: Dirs) {
    this.capped = services.length > MAX_SERVICES;
    if (this.capped) return;
    const tree = segNode();
    let root = -1;
    services.forEach((s, i) => {
      const path = normalPath(s.path);
      if (!this.target.has(s.name)) this.target.set(s.name, path);
      if (path !== '.') segInsert(tree, path, i);
      else if (root < 0) root = i;
    });
    for (let d = ROOT + 1; d < dirs.names.length; d++) {
      const dir = dirs.names[d] as string;
      segInsert(this.dirTree, dir, d);
      // the owner: the deepest service path at or above dir; '.' (length 1) wins a tie on length by coming first
      let n: SegNode | undefined = tree;
      let best = -1;
      let bestLen = 0;
      let len = -1;
      for (const seg of dir.split('/')) {
        n = n.kids.get(seg);
        if (!n) break;
        len += seg.length + 1;
        if (n.id >= 0) {
          best = n.id;
          bestLen = len;
        }
      }
      if (root >= 0 && (best < 0 || bestLen < 1 || (bestLen === 1 && root < best))) best = root;
      if (best < 0) continue;
      const name = (services[best] as Service).name;
      const list = this.owned.get(name);
      if (list) list.push(d);
      else this.owned.set(name, [d]);
    }
  }

  /** The dirs whose runs count for a need of this service (ALL for a repo-wide need). */
  dirsOf(service: string | undefined): readonly number[] {
    if (service === undefined) return [ALL];
    if (this.capped) return [ROOT];
    const known = this.memo.get(service);
    if (known) return known;
    const out = [ROOT];
    const path = this.target.get(service);
    if (path !== undefined) {
      for (const d of this.owned.get(service) ?? []) out.push(d); // a loop, not a spread: up to MAX_HIT_DIRS entries
      if (path !== '.') {
        // the dirs above the service's path: a run there covers each service below it
        const segs = path.split('/');
        let n: SegNode | undefined = this.dirTree;
        for (let k = 0; k < segs.length - 1 && n; k++) {
          n = n.kids.get(segs[k] as string);
          if (n && n.id >= 0) out.push(n.id);
        }
      }
    }
    this.memo.set(service, out);
    return out;
  }
}

function missingWhy(need: Need): string {
  if (need.layer === 'pre-commit' && need.category === 'secrets') return PRECOMMIT_SECRETS_WHY;
  return MISSING_WHY[need.category] ?? FALLBACK_MISSING_WHY;
}

const located = (h: { by?: string; where: string }) => ({ ...(h.by === undefined ? {} : { by: h.by }), where: h.where });

/** The reason that counts for this need: a need that doesn't block (format-lint) only cares whether the tool runs. */
const effectiveReason = (need: Need, reason: Reason | null): Reason | null => (need.blocking || (reason !== null && MAY_NOT_RUN.has(reason)) ? reason : null);
/** The kinds of run that cover a need, and the kinds that run on its trigger but can't block it. */
const coverKinds = (need: Need) => (need.blocking ? [FN] : [FN, FO]);
const partialKinds = (need: Need) => (need.blocking ? [FC, FO] : [FC]);

function reasonWhy(h: { subject: string; partialWhy?: string }, reason: Reason, when: string): string {
  return (reason === 'never' || reason === 'ref') && h.partialWhy !== undefined ? h.partialWhy : REASON_WHY[reason](h.subject, when);
}

interface Decide { ci: Firsts; hooks: Firsts; scope: Scope; dirsCapped: boolean; truncated: boolean; unreadable: boolean }

/** A per-service need that a cap kept pipegen from checking in full: never missing, never covered by the cap. */
const capped = (need: Need, d: Decide) => need.service !== undefined && (d.scope.capped || d.dirsCapped);

function ciCoverage(need: Need, layer: CiLayer, d: Decide): Coverage {
  const dirs = d.scope.dirsOf(need.service);
  const cover = d.ci.first(need.category, dirs, layer, coverKinds(need));
  if (cover) return { need, status: 'covered', ...located(cover), why: `${cover.subject} runs ${LAYER_DONE[layer]}.` };
  const unknownRun = d.ci.first(`${UNKNOWN_PREFIX}${need.category}`, dirs, layer, [FN, FC, FO]);
  if (unknownRun?.partialWhy !== undefined) return { need, status: 'unknown', ...located(unknownRun), why: unknownRun.partialWhy };
  const strongOpaque = d.ci.first(OPAQUE_KEY, dirs, layer, [FN]);
  if (strongOpaque) return { need, status: 'unknown', ...located(strongOpaque), why: strongOpaque.why as string };
  if (d.truncated) return { need, status: 'unknown', why: OPAQUE_WHY.truncated };
  const partialRight = d.ci.first(need.category, dirs, layer, partialKinds(need));
  if (partialRight) {
    return { need, status: 'partial', ...located(partialRight), why: reasonWhy(partialRight, effectiveReason(need, partialRight.reason) as Reason, LAYER_DONE[layer]) };
  }
  const partialTrigger = d.ci.first(need.category, dirs, layer, [NF]);
  if (partialTrigger) return { need, status: 'partial', ...located(partialTrigger), why: `${partialTrigger.subject} runs, but not ${LAYER_DONE[layer]}.` };
  const weakOpaque = d.ci.first(OPAQUE_KEY, dirs, layer, [NF]);
  if (weakOpaque) return { need, status: 'unknown', ...located(weakOpaque), why: weakOpaque.why as string };
  if (d.unreadable) return { need, status: 'unknown', why: OPAQUE_WHY.workflowsUnreadable };
  if (capped(need, d)) return { need, status: 'unknown', why: OPAQUE_WHY.tooMany };
  // Task 5 fix round 1 (C1): a version known not to do this check (pypi-publish before v1.11.0): missing, saying why
  const old = d.ci.first(`${OLD_PREFIX}${need.category}`, dirs, layer, [FN, FC, FO, NF]);
  if (old && old.partialWhy !== undefined) return { need, status: 'missing', ...located(old), why: old.partialWhy };
  return { need, status: 'missing', why: missingWhy(need) };
}

function hookCoverage(need: Need, hooks: Hooks, d: Decide): Coverage {
  const m = hooks.manager;
  if (need.category === 'hooks') {
    return m === null
      ? { need, status: 'missing', why: missingWhy(need) }
      : { need, status: 'covered', by: m, where: m === 'lefthook' && hooks.where !== '' ? hooks.where : HOOK_FILE[m], why: `The repo uses ${HOOK_NAME[m]} to run git hooks.` };
  }
  if (m !== null) {
    // the hook's runs sit in their own table, every one on the "push" layer's trigger
    const dirs = d.scope.dirsOf(need.service);
    const cover = d.hooks.first(need.category, dirs, 'push', coverKinds(need));
    if (cover) return { need, status: 'covered', by: cover.by as string, where: hooks.where, why: `${cover.subject} runs in ${HOOK_PLACE[m]} before each commit.` };
    const unknownRun = d.hooks.first(`${UNKNOWN_PREFIX}${need.category}`, dirs, 'push', [FN, FC, FO]);
    if (unknownRun?.partialWhy !== undefined) return { need, status: 'unknown', by: unknownRun.by as string, where: hooks.where, why: unknownRun.partialWhy };
    const partial = d.hooks.first(need.category, dirs, 'push', partialKinds(need));
    if (partial) return { need, status: 'partial', by: partial.by as string, where: hooks.where, why: reasonWhy(partial, effectiveReason(need, partial.reason) as Reason, 'before each commit') };
    if (!hooks.readable) return { need, status: 'unknown', where: hooks.where, why: OPAQUE_WHY.hookUnreadable };
    if (capped(need, d)) return { need, status: 'unknown', why: OPAQUE_WHY.tooMany };
  }
  return { need, status: 'missing', why: missingWhy(need) };
}

const HOOK_FIT: Fit = { push: true, merge: true, deploy: true };

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
    unreadable: (opts.skippedWorkflows ?? 0) > 0, pkgRead: new Reader(dir), pkgScripts: new Map(), scriptMemo: new Map(), scriptClass: new Map(), compositeGates: new Map(),
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
  await hookRunHits(ctx);
  const hooks = await readHooks(ctx);
  // Each need is answered from tables built once, not by a pass over every run (review C1).
  const dirs = new Dirs();
  const ci = new Firsts(ctx.hits, dirs);
  const hookRuns = new Firsts(hooks.found.map((f): Hit => ({
    opaque: false, categories: f.categories, by: f.by, subject: f.subject, dir: f.dir, reason: f.reason,
    ...(f.partialWhy === undefined ? {} : { partialWhy: f.partialWhy }), fit: HOOK_FIT, where: hooks.where,
  })), dirs);
  const d: Decide = {
    ci, hooks: hookRuns, scope: new Scope(p.services, dirs), dirsCapped: dirs.capped,
    truncated: ctx.budget.truncated, unreadable: ctx.unreadable,
  };
  return needs.map((need) => {
    if (need.layer === 'pre-commit') return hookCoverage(need, hooks, d);
    if (need.category === 'gate') return { need, status: 'missing', why: GATE_WHY };
    if (need.category === 'deploy-verify') return { need, status: 'missing', why: DEPLOY_VERIFY_WHY };
    return ciCoverage(need, need.layer, d);
  });
}
