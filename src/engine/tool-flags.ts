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

// ---------- argv allowlists for every cli entry (Plan P Task 6 fix round 1, rulings P19-P21, P24, P25, P27) ----------

/**
 * How one flag may be used: `bool` (a switch; only ever on), `optional` (a value only as `--flag=v`), `output` (its
 * value is the entry's own output.path), or `{ values }` (a value from this exact list; `optional` when the flag takes
 * its value only as `--flag=v`). A value may be a `{choice}` placeholder: the renderer puts the chosen value there, and
 * every value of that choice must be on the list.
 */
export type FlagSpec = 'bool' | 'output' | { readonly values: readonly string[]; readonly optional?: true };

/** One command of a tool: its leading words (subcommand), its flags, the flags that must be in effect, its other words. */
export interface CommandPolicy {
  /** The words right after the executable, exactly (`['check']`, `['scan', 'source']`). */
  readonly sub: readonly string[];
  /** The only flags (long names, no short forms) pipegen may pass; any other flag is refused (default deny). */
  readonly flags: Readonly<Record<string, FlagSpec>>;
  /** Flags that must be in effect with this exact value ('true' for a switch, '' for an optional flag alone, null: any listed value). */
  readonly required?: Readonly<Record<string, string | null>>;
  /** The other words (paths) the template may name, exactly. */
  readonly positionals?: readonly string[];
}

/**
 * The argv policy of one reviewed cli entry, by entry id. `exe` is command[0], exactly (no path, shell, launcher or
 * package manager). `dialect`: `long` reads `--name[=value]` only (every short form is refused); `goflags` reads Go's
 * `-name[=value]`. `config` is pipegen's pinned config, passed as this flag with exactly this content (any change to
 * the data file needs the same change here). `env`: the only env names the entry may set (default none). `then`: the
 * follow-up commands the entry must run, in order (P24). `dedicated`: trivy, betterleaks and nuclei have their own
 * full-grammar rules in reviewed.ts (Task 5); only `exe` is checked here.
 */
export interface ArgvPolicy extends CommandPolicy {
  readonly exe: string;
  readonly dialect: 'long' | 'goflags';
  readonly config?: { readonly flag: string; readonly content: string };
  readonly env?: readonly string[];
  readonly then?: readonly CommandPolicy[];
  readonly dedicated?: true;
}

const DEDICATED = (exe: string): ArgvPolicy => ({ exe, dialect: 'long', sub: [], flags: {}, dedicated: true });
/** Coverage minimums the AI may choose (P24): never 0. */
export const COVERAGE_MINIMUMS = ['60', '70', '80', '90'] as const;
const ESLINT_FILES = "files: ['**/*.{js,mjs,cjs,jsx,vue,svelte,astro}']";
const ESLINT_TS_FILES = "files: ['**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx,vue,svelte,astro}']";

/**
 * Ruling P19: every reviewed cli entry's argv, by entry id (a cli entry without one fails to load). Flags were read
 * from each pinned version's own `--help` (or its source in the downloaded package) on pin day. A flag that turns
 * failing off (`--exit-zero`, `-no-fail`, `--no-fail`, `--write`, `--fix`, `--failure-threshold none`, …) is never
 * on a list (P20).
 */
export const ARGV_POLICIES: Readonly<Record<string, ArgvPolicy>> = Object.freeze({
  'trivy-config': DEDICATED('trivy'), 'trivy-image': DEDICATED('trivy'), 'trivy-licence': DEDICATED('trivy'),
  betterleaks: DEDICATED('betterleaks'), nuclei: DEDICATED('nuclei'),
  // gitleaks 8.30.1 (`gitleaks git --help`), the secrets fallback (P21): the same locks as betterleaks
  gitleaks: {
    exe: 'gitleaks', dialect: 'long', sub: ['git'], positionals: ['.'],
    flags: { 'no-banner': 'bool', 'ignore-gitleaks-allow': 'bool', redact: { values: ['', '100'], optional: true }, 'report-format': { values: ['sarif'] }, 'report-path': 'output', 'exit-code': { values: ['1'] } },
    required: { 'ignore-gitleaks-allow': 'true', redact: '', 'report-format': 'sarif', 'report-path': null, 'exit-code': '1' },
    config: { flag: '--config', content: '[extend]\nuseDefault = true\n' },
  },
  // osv-scanner v2.7.0
  'osv-scanner': {
    exe: 'osv-scanner', dialect: 'long', sub: ['scan', 'source'], positionals: ['.'],
    flags: { recursive: 'bool', format: { values: ['sarif'] }, output: 'output' }, required: { format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned osv-scanner config: no ignored vulnerabilities\n" },
  },
  lefthook: { exe: 'lefthook', dialect: 'long', sub: ['run', 'pre-commit'], flags: { 'all-files': 'bool' }, required: { 'all-files': 'true' } },
  syft: {
    exe: 'syft', dialect: 'long', sub: ['scan'], flags: { output: { values: ['spdx-json=sbom.spdx.json'] } }, required: { output: 'spdx-json=sbom.spdx.json' },
    config: { flag: '--config', content: 'check-for-app-update: false\n' },
  },
  cosign: { exe: 'cosign', dialect: 'long', sub: ['sign'], flags: { yes: 'bool' }, required: { yes: 'true' } },
  actionlint: {
    exe: 'actionlint', dialect: 'goflags', sub: [], flags: { 'no-color': 'bool', shellcheck: { values: [''] }, pyflakes: { values: [''] } },
    required: { shellcheck: '', pyflakes: '' },
    config: { flag: '-config-file', content: "self-hosted-runner:\n  labels: []\npaths:\n  .github/workflows/**/*.{yml,yaml}:\n    ignore:\n      - 'unexpected key \"cache-mode\" for \"job\" section'\n" },
  },
  zizmor: { exe: 'zizmor', dialect: 'long', sub: [], positionals: ['.github/workflows'], flags: { offline: 'bool' }, required: { offline: 'true' }, config: { flag: '--config', content: 'rules: {}\n' } },
  // Biome 2.5.15: `biome ci` (lint + format check, never writes)
  biome: {
    exe: 'biome', dialect: 'long', sub: ['ci'], flags: {},
    config: { flag: '--config-path', content: '{\n  "linter": {\n    "rules": {\n      "complexity": {\n        "noExcessiveCognitiveComplexity": { "level": "error", "options": { "maxAllowedComplexity": 15 } }\n      }\n    }\n  }\n}\n' },
  },
  // ESLint 10.13.0: no warnings allowed; the pinned flat config lints the framework files too (P25)
  eslint: {
    exe: 'eslint', dialect: 'long', sub: [], positionals: ['.'], flags: { 'max-warnings': { values: ['0'] } }, required: { 'max-warnings': '0' },
    config: { flag: '--config', content: `export default [{ ${ESLINT_FILES}, languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } }, rules: { complexity: ['error', 15] } }];\n` },
  },
  'eslint-typescript': {
    exe: 'eslint', dialect: 'long', sub: [], positionals: ['.'], flags: { 'max-warnings': { values: ['0'] } }, required: { 'max-warnings': '0' },
    // built in two parts so the bundled CLI holds no import statement of a non-node module (test/package.test.ts)
    config: { flag: '--config', content: [`import tseslint from`, `'typescript-eslint';\nexport default [...tseslint.configs.recommended, { ${ESLINT_TS_FILES}, rules: { complexity: ['error', 15] } }];\n`].join(' ') },
  },
  // Oxlint 1.89.0
  'oxlint-typeaware': {
    exe: 'oxlint', dialect: 'long', sub: [], flags: { 'type-aware': 'bool', 'deny-warnings': 'bool' }, required: { 'type-aware': 'true', 'deny-warnings': 'true' },
    config: { flag: '--config', content: '{ "categories": { "correctness": "error" } }\n' },
  },
  // Prettier 3.9.10: check only (never --write); the repo's own Prettier config is used (catalogue §2)
  prettier: { exe: 'prettier', dialect: 'long', sub: [], positionals: ['.'], flags: { check: 'bool' }, required: { check: 'true' } },
  // Vitest 5.0.5: coverage on, with a minimum the AI chooses (P24)
  'vitest-coverage': {
    exe: 'vitest', dialect: 'long', sub: ['run'], flags: { coverage: 'bool', 'coverage.thresholds.lines': { values: COVERAGE_MINIMUMS } },
    required: { coverage: 'true', 'coverage.thresholds.lines': null },
  },
  // c8 12.0.0
  c8: { exe: 'c8', dialect: 'long', sub: [], flags: { 'check-coverage': 'bool' }, required: { 'check-coverage': 'true' } },
  // Knip 6.42.1
  knip: { exe: 'knip', dialect: 'long', sub: [], flags: { 'no-progress': 'bool' } },
  // jscpd 5.4.2 (the release binary): new copy-paste against the base only; no semantic mode (jscpdProblems)
  jscpd: {
    exe: 'jscpd', dialect: 'long', sub: [], positionals: ['.'],
    flags: { 'baseline-from-ref': { values: ['origin/main'] }, 'fail-on-new-clones': { values: [''], optional: true }, reporters: { values: ['sarif'] }, output: { values: ['jscpd-report'] } },
    required: { 'baseline-from-ref': 'origin/main', 'fail-on-new-clones': '' },
    config: { flag: '--config', content: '{}\n' },
  },
  // hadolint 2.15.1: fails on warnings and errors (never --no-fail or a lower threshold)
  hadolint: {
    exe: 'hadolint', dialect: 'long', sub: [], flags: { 'no-color': 'bool', 'failure-threshold': { values: ['warning'] }, format: { values: ['sarif'] }, output: 'output' },
    required: { 'failure-threshold': 'warning', format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned hadolint config: every rule at its default level, nothing ignored\nignored: []\n" },
  },
  // kube-linter 0.8.3: an unrenderable chart, a bad path or YAML it can't parse fails the check (P25)
  'kube-linter': {
    exe: 'kube-linter', dialect: 'long', sub: ['lint'],
    flags: { 'fail-if-no-objects-found': 'bool', 'fail-on-invalid-resource': 'bool', format: { values: ['sarif'] }, output: 'output' },
    required: { 'fail-if-no-objects-found': 'true', 'fail-on-invalid-resource': 'true', format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned kube-linter config: the default checks\nchecks:\n  doNotAutoAddDefaults: false\n" },
  },
  // Schemathesis 4.32.2: exactly 25 examples per operation, JUnit report
  schemathesis: {
    exe: 'schemathesis', dialect: 'long', sub: ['run'], flags: { 'max-examples': { values: ['25'] }, report: { values: ['junit'] }, 'report-junit-path': 'output' },
    required: { 'max-examples': '25', report: 'junit', 'report-junit-path': null },
  },
  // pinact 5.0.0: check only (never rewrites the workflows), and every version comment checked
  pinact: { exe: 'pinact', dialect: 'long', sub: ['run'], flags: { check: 'bool', 'verify-comment': 'bool' }, required: { check: 'true', 'verify-comment': 'true' } },
  // poutine 1.1.6
  poutine: {
    exe: 'poutine', dialect: 'long', sub: ['analyze_local'], positionals: ['.'], flags: { 'disable-version-check': 'bool', 'fail-on-violation': 'bool', quiet: 'bool' },
    required: { 'disable-version-check': 'true', 'fail-on-violation': 'true' },
    config: { flag: '--config', content: "# pipegen's pinned poutine config: no skipped rules\nskip: []\n" },
  },
  // gosec 2.29.0 (Go flags): never -no-fail; every #nosec suppression is reported in the SARIF (P27)
  gosec: {
    exe: 'gosec', dialect: 'goflags', sub: [], positionals: ['./...'], flags: { fmt: { values: ['sarif'] }, out: 'output', 'track-suppressions': 'bool' },
    required: { fmt: 'sarif', out: null, 'track-suppressions': 'true' },
  },
  // Ruff 0.17.1 (never --exit-zero, --fix or a format without --check)
  ruff: {
    exe: 'ruff', dialect: 'long', sub: ['check'], flags: { 'no-cache': 'bool', 'output-format': { values: ['sarif'] }, 'output-file': 'output' },
    required: { 'no-cache': 'true', 'output-format': 'sarif', 'output-file': null },
    config: { flag: '--config', content: '[lint]\nextend-select = ["C901"]\n\n[lint.mccabe]\nmax-complexity = 15\n' },
  },
  'ruff-format': {
    exe: 'ruff', dialect: 'long', sub: ['format'], flags: { check: 'bool', 'no-cache': 'bool' }, required: { check: 'true', 'no-cache': 'true' },
    config: { flag: '--config', content: "# pipegen's pinned ruff config: the default format\n" },
  },
  // mypy 2.4.0 (never --install-types: it installs unpinned stub packages)
  mypy: { exe: 'mypy', dialect: 'long', sub: [], positionals: ['.'], flags: { 'no-incremental': 'bool' } },
  // coverage.py 7.16.2: pytest under coverage, then the minimum (P24)
  'coverage-py': {
    exe: 'coverage', dialect: 'long', sub: ['run'], positionals: ['pytest'], flags: { module: 'bool' }, required: { module: 'true' },
    then: [{ sub: ['report'], flags: { 'fail-under': { values: COVERAGE_MINIMUMS } }, required: { 'fail-under': null } }],
  },
  creosote: { exe: 'creosote', dialect: 'long', sub: [], flags: {} },
  vulture: { exe: 'vulture', dialect: 'long', sub: [], positionals: ['.'], flags: { 'min-confidence': { values: ['80'] } }, required: { 'min-confidence': '80' } },
  // Bandit 1.9.4 (never --exit-zero)
  bandit: {
    exe: 'bandit', dialect: 'long', sub: [], positionals: ['.'], flags: { recursive: 'bool', format: { values: ['sarif'] }, output: 'output' },
    required: { recursive: 'true', format: 'sarif', output: null },
  },
} satisfies Record<string, ArgvPolicy>);
