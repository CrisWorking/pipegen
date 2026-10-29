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
// DoD G11 (fix round 1, P50 I1 I2): a Trivy licence scan is covered only with no severity filter or one holding
//   UNKNOWN, HIGH and CRITICAL (partialWithFlagValue, read with Trivy's flag grammar), and only when every service in
//   scope is npm (package-lock.json); otherwise it is at most partial.
// DoD run 2026-10-29 (fastapi): a repo shell script file run as a command (`bash scripts/test.sh`, `./ci.sh`; a plain
//   relative `.sh` path, no `..`) is read like a step (no -e unless it sets it, in the caller's folder) and followed
//   like an own package script: its tests, lint, format, type-check, coverage and dead-code runs count under "your own
//   `<file>`"; a file pipegen can't read is unknown. `coverage run [flags] -m pytest` runs the tests.
//   Fix round 1 (ruling P50): only `bash|sh|zsh|dash [-e -u -x -v, combined, -o pipefail|errexit|nounset|xtrace, --]
//   <file>` (or the file run directly) is followed; any other shell flag (-n, --noexec, -c, unknown) gives no
//   coverage from that command. `set -n` / `set -o noexec` ends coverage from that line on (in steps too). Script files
//   have their own reader and bound (MAX_SCRIPT_FILES, failed reads counted); past it a call is unknown. A script
//   pipegen can't place (a variable, an absolute or `..` path, a `cd` it can't follow, a `docker run` container's copy)
//   is unknown for every service (an unknown run of unknown folder sits at the root), never missing.
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
// Plan P Task 4 (src/audit/config-checks.ts; rulings PB4, PS17, PS22): update-config is read from the Dependabot or
// Renovate file (covered only with a 7-day cooldown on every ecosystem and folder; Renovate only with a scheduled run of
// Renovate itself, since the app can't be seen); publishing is never covered from the profile alone; a coverage run that
// only measures (PS17) is covered only when a minimum above 0 is found (a flag, or a config file in the folder it runs
// in; a threshold only found in JS config text stays partial); versionAdjust is the last step (ESLint 10 with only
// .eslintrc is partial; end-of-life notes).
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
import { SUPPORTED_STACKS, unsupportedStackWhy } from '../read/support.js';
import { MAX_WORKFLOWS, WORKFLOW_FILE } from '../read/workflows.js';
import type { Capabilities, ExistingWorkflow, Need, RepoProfile } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { coverageMinimumRow, frameworkAdjust, publishingCoverage, updateConfigCoverage, versionAdjust } from './config-checks.js';
import { DEPLOY_VERIFY_WHY, Dirs, Firsts, GATE_WHY, Scope, ciCoverage, firstPartialHit, hookCoverage, type Decide } from './coverage/decide.js';
import { hookRunHits, readHooks } from './coverage/hooks.js';
import { compile, loadToolSignatures } from './coverage/signatures.js';
import { fitOf, parseOn, scheduleFires, type BranchGuess } from './coverage/triggers.js';
import type { Compiled, Ctx, Fit, Hit } from './coverage/types.js';
import { Reader, configFilesPass, releaseEgress, releaseSigns, walkWorkflow } from './coverage/walk.js';

export { COVERAGE_LIMITS } from './coverage/bounds.js';
export { loadToolSignatures, type ToolSignature } from './coverage/signatures.js';

export interface Coverage {
  need: Need; status: 'covered' | 'partial' | 'missing' | 'unknown'; by?: string; where?: string; why: string;
  /**
   * update-config rows only (hand checks, P55): whether the update tool already waits at least COOLDOWN_DAYS before an
   * update (Dependabot: every active entry's cooldown; Renovate: minimumReleaseAge), whatever else the row says, so
   * "would add" never tells a repo to set a wait it has. Absent when pipegen couldn't read the config that far.
   */
  cooldown?: 'set' | 'short';
}

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
  /**
   * DoD run 2026-10-29: GitHub's rate limit kept pipegen from reading the default branch; p.defaultBranch is then a
   * placeholder and this bound is used instead (see BranchGuess). The audit maps coverage under both bounds.
   */
  branchGuess?: BranchGuess['guess'];
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
    unreadable: (opts.skippedWorkflows ?? 0) > 0, pkgRead: new Reader(dir), pkgScripts: new Map(), scriptMemo: new Map(), scriptRead: new Reader(dir), scriptFileReads: 0, scriptClass: new Map(), compositeGates: new Map(),
    globMemo: new Map(), globWork: 0, ...(opts.capabilities === undefined ? {} : { caps: opts.capabilities }),
    // fix round 1 (P8): a workflow readWorkflows skipped may be a release workflow
    releaseJobs: [], releaseUnread: (opts.skippedWorkflows ?? 0) > 0,
  };
  if (p.existingWorkflows.length > MAX_WORKFLOWS) ctx.budget.truncated = true;
  const listed = new Map(p.existingWorkflows.slice(0, MAX_WORKFLOWS).map((w) => [w.path, w]));
  const releases = (w: ExistingWorkflow | undefined) => w !== undefined && (w.deploys || (w.publishes?.length ?? 0) > 0);
  const calleeSigns = new Map<string, boolean>(); // each called workflow's own signs, worked out once
  const usesSecrets = (w: ExistingWorkflow | undefined) => w !== undefined && w.secretsUsed.some((n) => n.toUpperCase() !== 'GITHUB_TOKEN');
  for (const w of [...p.existingWorkflows].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).slice(0, MAX_WORKFLOWS)) {
    // fix round 1 (P8, concern 2): a workflow that deploys or publishes is a release workflow (refined below, round 2)
    let release = releases(w);
    // A listed workflow that fails the path check or can't be read again is never skipped silently (review M1).
    if (!regexSafe(w.path) || safeText(w.path) !== w.path || !WORKFLOW_FILE.test(w.path)) {
      ctx.unreadable = true;
      ctx.releaseUnread ||= release;
      continue;
    }
    const doc = await ctx.read.yaml(w.path);
    if ('fail' in doc) {
      ctx.unreadable = true;
      ctx.releaseUnread ||= release;
      continue;
    }
    const on = doc.ok.on ?? doc.ok.true;
    const events = parseOn(on);
    events.delete('workflow_call'); // a reusable workflow runs when it is called; its callers carry it
    if (events.size === 0) continue;
    const fit = fitOf(events, opts.branchGuess === undefined ? p.defaultBranch : { guess: opts.branchGuess }, w.deploys, scheduleFires(on));
    // fix round 2 (ruling P9): it is also a release workflow when it calls a local workflow that deploys or publishes
    // (one level), or when it runs on a deploy trigger and uses a secret other than GITHUB_TOKEN, grants id-token,
    // packages or contents write, or pushes an image (its own signs, or those of the local workflows it calls)
    if (!release) {
      const signs = releaseSigns(doc.ok);
      const callees = signs.calls.map((c) => listed.get(c));
      release = callees.some(releases);
      if (!release && fit.deploy) {
        let callSigns = false;
        for (const c of new Set(signs.calls)) {
          if (callSigns || !listed.has(c)) continue;
          let known = calleeSigns.get(c);
          if (known === undefined) {
            const cd = await ctx.read.yaml(c);
            const cs = 'fail' in cd ? null : releaseSigns(cd.ok);
            known = cs === null || cs.grants || cs.pushes; // unreadable: can't tell, so lean towards checking it
            calleeSigns.set(c, known);
          }
          callSigns = known;
        }
        release = usesSecrets(w) || callees.some(usesSecrets) || signs.grants || signs.pushes || signs.passesSecrets || callSigns;
      }
    }
    await walkWorkflow(ctx, doc.ok, w.path, fit, 0, '', false, release);
  }
  releaseEgress(ctx);
  await hookRunHits(ctx);
  await configFilesPass(ctx);
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
  // Plan P Task 4: a scheduled run of Renovate by the repo itself is the only sign pipegen can see that Renovate is in use
  const renovateRuns = ctx.hits.some((h) => h.by === 'renovate' && !h.opaque && h.fit.scheduled && h.reason === null);
  const rows: Coverage[] = [];
  for (const need of needs) {
    if (need.layer === 'pre-commit') rows.push(hookCoverage(need, hooks, d));
    else if (need.category === 'gate') rows.push({ need, status: 'missing', why: GATE_WHY });
    else if (need.category === 'deploy-verify') rows.push({ need, status: 'missing', why: DEPLOY_VERIFY_WHY });
    else if (need.category === 'update-config') rows.push(await updateConfigCoverage(p, need, dir, renovateRuns));
    else if (need.category === 'publishing') rows.push(publishingCoverage(p, need));
    else if (need.category === 'coverage') {
      const row = ciCoverage(need, need.layer, d);
      rows.push(row.status === 'partial' ? await coverageMinimumRow(row, firstPartialHit(need, need.layer, d), dir) : row);
    } else rows.push(ciCoverage(need, need.layer, d));
  }
  // PS22: the last steps, so the chooser reads the adjusted row
  return unsupportedStack(licenceInstall(noLockfile(frameworkAdjust(versionAdjust(rows, p), p), p), p), p);
}

/**
 * DoD G11, fix round 1 (P50 I1): Trivy's licence scan reads licences by itself only from npm's package-lock.json.
 * Trivy's own coverage docs and the G11 measurement (Trivy 0.76.0): yarn, pnpm, bun, requirements files and go.mod need
 * the packages installed first; poetry.lock, Pipfile.lock and uv.lock give none at all. So a licences row covered by
 * trivy-license stays covered only when every service in scope is npm (package-lock.json); anything else (another
 * lockfile, none, a language pipegen can't place) is partial.
 */
const LICENCE_INSTALL_WHY = "The Trivy licence scan reads licences by itself only from npm's package-lock.json: from yarn, pnpm, bun, requirements files or go.mod only once the packages are installed, and from poetry.lock, Pipfile.lock or uv.lock not at all. pipegen doesn't check for an install step, so a clean run may have checked nothing.";
/** DoD G11 / P50 I1: a Trivy licence scan is covered only over npm package-lock.json services; otherwise partial. */
function licenceInstall(rows: Coverage[], p: RepoProfile): Coverage[] {
  return rows.map((r) => {
    if (r.need.category !== 'licences' || r.status !== 'covered' || r.by !== 'trivy-license') return r;
    const scope = r.need.service === undefined ? p.services : p.services.filter((s) => s.name === r.need.service);
    return scope.length > 0 && scope.every((s) => s.packageManager === 'npm') ? r : { ...r, status: 'partial', why: LICENCE_INSTALL_WHY };
  });
}

/**
 * Checks whose tools and commands depend on the service's stack (its test runner, linter, formatter, type checker,
 * coverage tool, dead-code finder, code scanner and dependency scanner).
 */
const STACK_CATEGORIES: ReadonlySet<string> = new Set(['unit-tests', 'full-tests', 'lint', 'format-lint', 'format', 'type-check', 'coverage', 'dead-code', 'sast', 'deps']);
/**
 * DoD run (spf13/cobra): for a service in a stack pipegen doesn't support yet (Go, or a language it can't name), a
 * stack check that would be missing is unknown "not supported yet": pipegen doesn't know that stack's own commands
 * (`make richtest` running `go test`), so "missing" would be a guess. Covered and partial rows are what pipegen really
 * found, so they stay; checks that don't depend on the stack (secrets, images, the deploy checks) are answered as usual.
 */
function unsupportedStack(rows: Coverage[], p: RepoProfile): Coverage[] {
  return rows.map((r) => {
    const s = r.need.service === undefined ? undefined : p.services.find((x) => x.name === r.need.service);
    if (s === undefined || SUPPORTED_STACKS.includes(s.language) || r.status !== 'missing' || !STACK_CATEGORIES.has(r.need.category)) return r;
    return { need: r.need, status: 'unknown', why: unsupportedStackWhy(s.language) };
  });
}

const NO_LOCKFILE_WHY = "No lockfile is committed, so new-dependency review and licence checks can't run until one is.";
/** Task 9: a repo with a manifest but no lockfile: these two checks can't run yet, which is a gap, never "not applicable". */
function noLockfile(rows: Coverage[], p: RepoProfile): Coverage[] {
  if (p.services.some((s) => s.packageManager !== undefined)) return rows;
  return rows.map((r) => ((r.need.category === 'dependency-review' || r.need.category === 'licences') && r.status === 'missing' ? { ...r, why: NO_LOCKFILE_WHY } : r));
}
