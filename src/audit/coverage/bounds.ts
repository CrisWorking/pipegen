// Coverage mapper (see ../coverage.ts for the rules): every budget (MAX_*) and the COVERAGE_LIMITS the report prints.
import { MAX_WORKFLOWS } from '../../read/workflows.js';

// ---------- bounds ----------

export const MAX_JOBS = 100;              // per workflow
export const MAX_STEPS = 200;             // per job or composite action
export const MAX_STEP_VISITS = 50_000;    // per mapCoverage call, followed files included
export const MAX_SCAN_BYTES = 16_000_000; // run text scanned per mapCoverage call (worst case about 3 s of adversarial text)
export const MAX_LOCAL_FILES = 100;       // distinct local workflows and actions followed
export const MAX_HOOKS = 200;             // pre-commit repos, hooks per repo, lefthook commands
export const MAX_FILTER_PATTERNS = 100;
export const MAX_GLOB = 256;
export const MAX_WHERE = 300;
export const MAX_DIR = 512;               // a tracked directory longer than this is unknown (a chain of cd's can't grow it)
export const MAX_HITS = 100_000;          // tool and opaque findings kept per mapCoverage call
export const MAX_FLAG_WORDS = 64;         // words after a command read for its flags
export const MAX_INPUT_KEYS = 256;        // `with:` keys read per step; a step with more is partial
export const MAX_SPELLINGS = 8;           // spellings kept per input name (they differ only in case); more counts as soft
export const MAX_HIT_DIRS = 10_000;       // distinct dirs (besides the root) that runs are matched to services in; a run in a
                                   // further dir counts only for repo-wide needs, and per-service rows can't be missing
export const MAX_SERVICES = 5_000;        // services matched against run dirs; with more, per-service needs count only runs at
                                   // the root, and their rows can't be missing (review C1)

/**
 * The per-run budgets past which rows read unknown (never covered, never missing), for the report's "what this audit
 * can't see" list (Plan U final review M3), so the numbers it prints are the ones the code uses.
 */
export const COVERAGE_LIMITS = Object.freeze({
  workflows: MAX_WORKFLOWS, jobs: MAX_JOBS, steps: MAX_STEPS, localFiles: MAX_LOCAL_FILES, runTextMb: MAX_SCAN_BYTES / 1_000_000,
  stepVisits: MAX_STEP_VISITS, hits: MAX_HITS, hitDirs: MAX_HIT_DIRS, services: MAX_SERVICES,
});

// ---------- own scripts read from package.json (Task 5) ----------

export const MAX_PACKAGE_FILES = 50; // distinct package.json files read for scripts
/** P50 (C2): distinct repo shell script files tried (read or not); past it a script call is unknown. Below the Reader's cache cap. */
export const MAX_SCRIPT_FILES = 100;
export const MAX_SCRIPTS = 1_000;    // distinct (dir, script) pairs worked out (fix round 3: was 200, with a depth limit of 4)
export const MAX_SCRIPT_TARGETS = 200;

/**
 * Fix round 4 (N8): bounds on npm-run-all / concurrently script globs. A call names at most MAX_SCRIPT_PATTERNS of them
 * (each SCRIPT_PATTERN_RE: at most 64 characters); a glob matches at most MAX_SCRIPT_TARGETS names, never one longer
 * than MAX_GLOB_NAME; each name tried costs pattern length × name length against MAX_GLOB_WORK per mapCoverage call
 * (about 0.5 s of matching). Past any of them the expansion is 'capped': the row is unknown, never covered or missing.
 */
export const MAX_SCRIPT_PATTERNS = 16;
export const MAX_GLOB_NAME = 64;
export const MAX_GLOB_WORK = 20_000_000;
