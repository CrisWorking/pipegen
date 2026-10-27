// Tool flags pipegen never passes, in one leaf module (no imports) so every rule that checks them uses the same list
// (Plan P ruling PS34): the reviewed-list loader (reviewed.ts) and the local secret scan's own argv (Task 7).

/**
 * betterleaks flags pipegen never passes (catalogue §3 PC2: no egress, no config from the scanned repo). Taken from
 * the pinned v1.9.0 source (cmd/root.go at tag v1.9.0, lines 109-127, read with `gh api` on 2026-10-27):
 * - `--validation` checks findings against live provider APIs (it sends the candidate secrets out); every
 *   `--validation-*` flag tunes it, and `--validation-env-vars` lets its expressions read the runner's environment;
 * - `--diagnostics` (`http` serves net/http/pprof) and `--diagnostics-dir`, and `--experiments` (unreviewed features);
 * - `--verbose` (`-v`) prints each finding, secret included, into the CI log.
 * Also the names later releases use for the same features (main: `--validate`/`-v`, `--analyze`/`-a`,
 * `--unsafe-auto-load-config`), so a version bump can't bring them in unnoticed. The loader also refuses any flag the
 * pinned version doesn't have (tool-grammar.ts).
 */
export const BETTERLEAKS_FORBIDDEN_FLAGS = [
  '--validation', '--validation-status', '--validation-timeout', '--validation-workers', '--validation-max-requests',
  '--validation-max-request', '--validation-rps', '--validation-rps-rule', '--validation-extract-empty', '--validation-debug',
  '--validation-env-vars', '--diagnostics', '--diagnostics-dir', '--experiments', '--verbose', '-v',
  '--validate', '--analyze', '-a', '--unsafe-auto-load-config',
] as const;

/**
 * betterleaks subcommands pipegen never runs (v1.9.0 cmd/*.go `Use:`): `validate` calls provider APIs with a secret;
 * `github`, `gitlab`, `huggingface` and `s3` scan remote services with a token; `analyze` is main's name for
 * validation. pipegen runs only `git`, `dir` and `stdin` (BETTERLEAKS_SUBCOMMANDS).
 */
export const BETTERLEAKS_FORBIDDEN_SUBCOMMANDS = ['validate', 'analyze', 'github', 'gitlab', 'huggingface', 's3'] as const;
/** The only betterleaks subcommands pipegen runs: local scans. */
export const BETTERLEAKS_SUBCOMMANDS = ['git', 'dir', 'stdin'] as const;
