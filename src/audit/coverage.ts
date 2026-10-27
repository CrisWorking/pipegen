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
// - tox / tox run and nox are the project's own test runner unless the command line picks other envs or sessions
//   (then no run). An env var that may pick them (TOX…, NOX…, in the job's env or run text, a matrix value included)
//   makes the run partial (Plan U final review I2): never covered, never missing. `uv run` and `nyc` flags are
//   matched against their full lists (a flag pipegen doesn't know: no command); pipenv run is a wrapper.
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
// - Fix round 4: script globs are bounded (at most 16 patterns a call, 64 characters each, fewer than
//   MAX_SCRIPT_TARGETS matches, names over 64 characters never matched, a shared work budget, one walk per
//   (dir, glob)); past a bound the row is unknown. A local action pipegen can't fully read gives the all-on env gate.
// Plan P Task 3 (the catalogue's tools; rulings PB3, PB5, PS11-PS19):
// - new signature fields (data/tool-signatures.yml header): reusableWorkflows (a listed called workflow counts like an
//   action, before U2's "remote reusable workflow → unknown"; a ref that isn't a SHA or a vX tag is partial),
//   onlyWithFlagValue, onlyWithInputs, availability (+ unavailableWhy; MapCoverageOptions.capabilities, read through
//   codeSecurityAvailable), requireInputs (all-of, any-of, unset; partial with its why) and scanTarget (grype: an image
//   or a folder). onlyWithFlags now matches like notWithFlags, and a value that reads as false never counts.
// - trivy and grype count by subcommand and target, so `trivy config` never counts as an image scan (PB3).
// - egress: an egress step counts only when it is the first step of every job of its workflow (the jobs of the local
//   workflows it calls included); otherwise every egress run there is partial (PB5).
// - scheduled checks (SCHEDULED_CATEGORIES, merge-layer needs) are read on their own trigger: `schedule` or a push to
//   the default branch; workflow_dispatch or a pull request alone is partial.
// - CI `pre-commit run --all-files` also carries the hooks' format, type-check, dockerfile-lint and workflow-lint runs;
//   a known formatter hook that writes or checks counts for format (PS14). lefthook and husky carry nothing.
// - own scripts count for format, type-check, coverage, dead-code and duplication through their text (PS11), also a
//   script counted by name (`npm run test:coverage` → coverage).
// - a command with more words than pipegen reads (MAX_FLAG_WORDS) is partial ('long'): a soft flag could hide past them.
// - a step or job `if:` wins over a reason a run can't block, so a check that doesn't block is partial under it.
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
//
// Layout (Plan P Task 0): this file keeps the public API (Coverage, MapCoverageOptions, mapCoverage, and the re-exported
// loadToolSignatures, ToolSignature and COVERAGE_LIMITS). The rest lives in ./coverage/: signatures, bounds, tokenize
// (a leaf), settings, shell, triggers, scripts, walk, hooks, decide, helpers, and types (types only). test/module-graph
// checks that there is no runtime import cycle among them.
import { regexSafe } from '../read/limits.js';
import { MAX_WORKFLOWS, WORKFLOW_FILE } from '../read/workflows.js';
import type { Capabilities, Need, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { DEPLOY_VERIFY_WHY, Dirs, Firsts, GATE_WHY, Scope, ciCoverage, hookCoverage, type Decide } from './coverage/decide.js';
import { hookRunHits, readHooks } from './coverage/hooks.js';
import { compile, loadToolSignatures } from './coverage/signatures.js';
import { fitOf, parseOn } from './coverage/triggers.js';
import type { Compiled, Ctx, Fit, Hit } from './coverage/types.js';
import { Reader, walkWorkflow } from './coverage/walk.js';

export { COVERAGE_LIMITS } from './coverage/bounds.js';
export { loadToolSignatures, type ToolSignature } from './coverage/signatures.js';

export interface Coverage { need: Need; status: 'covered' | 'partial' | 'missing' | 'unknown'; by?: string; where?: string; why: string }

export interface MapCoverageOptions {
  /** How many workflow files readWorkflows skipped (unreadable, over the cap): rows that would be missing say unknown. */
  skippedWorkflows?: number;
  /**
   * Plan U final review M4: true for a need whose service builds no image (a package that is released, not run), so the
   * signing and attestation whys talk about the release, not an image. Default: always false.
   */
  noImage?: (need: Need) => boolean;
  /**
   * Plan P Task 3 (ruling PS16): what GitHub allows here. Only `codeScanning` is read (with the repo's visibility and
   * owner type from the profile) for actions some repos can't use; absent = no code scanning.
   */
  capabilities?: Capabilities;
}

let defaultCompiled: Compiled | undefined;

const HOOK_FIT: Fit = { push: true, merge: true, deploy: true, scheduled: false };

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
    globMemo: new Map(), globWork: 0, ...(opts.capabilities === undefined ? {} : { caps: opts.capabilities }),
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
    truncated: ctx.budget.truncated, unreadable: ctx.unreadable, noImage: opts.noImage ?? (() => false),
  };
  return needs.map((need) => {
    if (need.layer === 'pre-commit') return hookCoverage(need, hooks, d);
    if (need.category === 'gate') return { need, status: 'missing', why: GATE_WHY };
    if (need.category === 'deploy-verify') return { need, status: 'missing', why: DEPLOY_VERIFY_WHY };
    return ciCoverage(need, need.layer, d);
  });
}
