// Tool flags pipegen never passes, in one leaf module (it imports only the import-free types.ts) so every rule that checks them uses the same list
// (Plan P ruling PS34): the reviewed-list loader (reviewed.ts) and the local secret scan's own argv (Task 7).

import { RESULT_ARTIFACT_PREFIX } from '../types.js';

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
  /**
   * How the entry installs its tool and exactly what (ruling P28, review M-R3): the release asset, npm or pip package,
   * or image. An entry that changes its kind or package under a reviewed id doesn't match the policy.
   */
  readonly method: 'npm' | 'pip' | 'github-release' | 'docker';
  readonly package: string;
  readonly exe: string;
  /** An image run with its own entrypoint (registry): the command is empty, with no args, config, env or then. */
  readonly entrypoint?: true;
  /** Choices that aren't argv placeholders, with their allowed values (semgrep's rule set, picked by the renderer). */
  readonly extraChoices?: Readonly<Record<string, readonly string[]>>;
  readonly dialect: 'long' | 'goflags';
  /**
   * The pinned config. `fileName` (6b, ruling S4) is what the renderer writes it as, under `$RUNNER_TEMP/pipegen-cfg/<artifact>/`:
   * tools pick the parser by name or extension (biome wants biome.json, the ESLint flat config must be .mjs, ruff .toml,
   * viper tools read the extension). One plain file name, never a path.
   */
  readonly config?: { readonly flag: string; readonly content: string; readonly fileName: string };
  /**
   * Docker entries only (6b, ruling S26): where the renderer mounts a folder in the container. `source: 'repo'` is the
   * service folder (with `workdir` also `-w <at>`); `source: 'work'` is a fresh folder under runner temp that holds the
   * config and receives the result (ZAP reads `-c` and writes `-J` under /zap/wrk). A docker entry with no mount is not rendered.
   */
  readonly mount?: { readonly at: string; readonly source: 'repo' | 'work'; readonly workdir?: true };
  /**
   * Docker entries only: `none` (semgrep, whose rules are mounted and which needs no network) or `host` (DAST steps only, ruling
   * R-D: their target is the app started on the runner at localhost, which a bridge network can not reach).
   */
  readonly network?: 'none' | 'host';
  /**
   * Docker DAST entries only (zap, nuclei): the container runs as its image's own user (no `--user` override), with the
   * fresh work folder made world-writable (it is empty and holds only pipegen's output). Needs `network: 'host'`'s kind of
   * step: a DAST check with a fresh work folder and no repo mount (ruling R-D).
   */
  readonly asImageUser?: true;
  /**
   * Why this entry is not rendered yet, in plain words (a missing target, a tool pipegen does not run): a RenderError
   * now, instead of a step that fails at run time (6b fix round 1, R-E). Removed when the slot exists (6c).
   */
  readonly needsSlot?: string;
  readonly env?: readonly string[];
  readonly then?: readonly CommandPolicy[];
  readonly dedicated?: true;
  /**
   * npm entries only (6b fix round 1): the tool's own bin file inside its package, a constant reviewed here and never read
   * from a repo-influenced file. The renderer runs `node <package folder>/<npmBin>`, never npx.
   */
  readonly npmBin?: string;
  /**
   * The tool executes the repo's own tests or hooks (vitest, c8, lefthook): its step is a repo-code step for the
   * referee's order rule (S6 c), it needs the repo's own dependency tree, and it is the only kind of step that may get
   * declared secrets. Every other npm tool is a checker: it reads code and is installed from pipegen's own closure lock.
   */
  readonly runsRepoCode?: true;
  /**
   * The tool only reads code and can not load repo plugins or hooks (see READS_ONLY for the reason per entry). Without it
   * the run step is a repo-code step (`repocode-…`): the default fails closed.
   */
  readonly readsOnly?: true;
  /**
   * An npm checker that still loads files from the repo by design (prettier runs a repo `.prettierrc.cjs` and its plugins, knip
   * runs `knip.ts` and the repo's tool configs). It keeps the closure install, but its run step is a repo-code step too
   * (`repocode-…` id, runsRepoCode(id) is true), so the referee's order rule applies to it.
   */
  readonly loadsRepoConfig?: true;
  /**
   * npm checkers only: variables the renderer sets for the tool, name → a path inside the install folder (relative to
   * it), so the tool finds the pinned copy of a helper and never the repo's (oxlint's tsgolint, which it otherwise
   * looks up in the repo's node_modules/.bin). Passed through the `env -i` allowlist by name.
   */
  readonly closureEnv?: Readonly<Record<string, string>>;
}

// the dedicated tools (trivy, betterleaks, nuclei) have their own full-grammar rules in reviewed.ts; only the pinned config is listed here, for the renderer
const DEDICATED = (exe: string, pkg: string, config?: ArgvPolicy['config']): ArgvPolicy => ({ method: 'github-release', package: pkg, exe, dialect: 'long', sub: [], flags: {}, dedicated: true, ...(config === undefined ? {} : { config }) });
const TRIVY_CONFIG = { flag: '--config', content: "# pipegen's pinned trivy config: no cache kept between runs\ncache:\n  backend: memory\n", fileName: 'trivy.yaml' } as const;
const GH = 'github-release' as const;
const TRIVY_ASSET = 'trivy_0.76.0_Linux-64bit.tar.gz';
const RUFF_ASSET = 'ruff-x86_64-unknown-linux-gnu.tar.gz';
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
const POLICIES = {
  'trivy-config': DEDICATED('trivy', TRIVY_ASSET, TRIVY_CONFIG), 'trivy-image': { ...DEDICATED('trivy', TRIVY_ASSET, TRIVY_CONFIG), needsSlot: 'needs an image to scan, a target slot that is rendered in 6c (ruling B6)' }, 'trivy-licence': DEDICATED('trivy', TRIVY_ASSET, TRIVY_CONFIG),
  betterleaks: DEDICATED('betterleaks', 'betterleaks_1.9.0_linux_x64.tar.gz', { flag: '--config', content: '[extend]\nuseDefault = true\n', fileName: 'betterleaks.toml' }),
  nuclei: DEDICATED('nuclei', 'nuclei_3.11.1_linux_amd64.zip'),
  // ruling P28: the image entries too. registry runs the image's own entrypoint, nothing else
  registry: { method: 'docker', package: 'registry', exe: '', entrypoint: true, dialect: 'long', sub: [], flags: {} },
  // ZAP baseline (zaproxy/zap-stable): getopt short options, read as Go-style words; no -I (warnings that never fail)
  'zap-baseline': {
    needsSlot: 'needs the URL of the running app (-t), a target slot that is rendered in 6c (ruling B6)', network: 'host', asImageUser: true,
    method: 'docker', package: 'zaproxy/zap-stable', exe: 'zap-baseline.py', dialect: 'goflags', sub: [], flags: { J: 'output', z: { values: ['-silent'] } },
    required: { J: null, z: '-silent' }, mount: { at: '/zap/wrk', source: 'work' }, config: { flag: '-c', content: "# pipegen's pinned ZAP baseline rules: the defaults, nothing ignored\n", fileName: 'zap-baseline.conf' },
  },
  // Semgrep CE 1.181.0: rules only from the verified archive (semgrepProblems), no metrics, no version check
  semgrep: {
    method: 'docker', package: 'semgrep/semgrep', exe: 'semgrep', dialect: 'long', sub: ['scan'],
    flags: { metrics: { values: ['off'] }, 'disable-version-check': 'bool', config: { values: ['/pipegen-rules'] }, sarif: 'bool', output: 'output' },
    required: { metrics: 'off', 'disable-version-check': 'true', config: '/pipegen-rules' },
    env: ['PIPEGEN_RULES_URL', 'PIPEGEN_RULES_SHA256', 'PIPEGEN_RULES_TREE'], extraChoices: { rules: ['javascript', 'typescript', 'python'] },
    mount: { at: '/src', source: 'repo', workdir: true }, network: 'none',
  },
  // gitleaks 8.30.1 (`gitleaks git --help`), the secrets fallback (P21): the same locks as betterleaks
  gitleaks: { method: GH, package: 'gitleaks_8.30.1_linux_x64.tar.gz',
    exe: 'gitleaks', dialect: 'long', sub: ['git'], positionals: ['.'],
    flags: { 'no-banner': 'bool', 'ignore-gitleaks-allow': 'bool', redact: { values: ['', '100'], optional: true }, 'report-format': { values: ['sarif'] }, 'report-path': 'output', 'exit-code': { values: ['1'] } },
    required: { 'ignore-gitleaks-allow': 'true', redact: '', 'report-format': 'sarif', 'report-path': null, 'exit-code': '1' },
    config: { flag: '--config', content: '[extend]\nuseDefault = true\n', fileName: 'gitleaks.toml' },
  },
  // osv-scanner v2.7.0
  'osv-scanner': { method: GH, package: 'osv-scanner_linux_amd64',
    exe: 'osv-scanner', dialect: 'long', sub: ['scan', 'source'], positionals: ['.'],
    flags: { recursive: 'bool', format: { values: ['sarif'] }, output: 'output' }, required: { format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned osv-scanner config: no ignored vulnerabilities\n", fileName: 'osv-scanner.toml' },
  },
  lefthook: { method: GH, runsRepoCode: true, package: 'lefthook_2.2.2_Linux_x86_64', exe: 'lefthook', dialect: 'long', sub: ['run', 'pre-commit'], flags: { 'all-files': 'bool' }, required: { 'all-files': 'true' } },
  syft: { method: GH, needsSlot: 'needs an image to scan, a target slot that is rendered in 6c (ruling B6)', package: 'syft_1.55.0_linux_amd64.tar.gz',
    exe: 'syft', dialect: 'long', sub: ['scan'], flags: { output: { values: ['spdx-json=sbom.spdx.json'] } }, required: { output: 'spdx-json=sbom.spdx.json' },
    config: { flag: '--config', content: 'check-for-app-update: false\n', fileName: 'syft.yaml' },
  },
  cosign: { method: GH, needsSlot: "is run by Plan G's sign job, which adds its own reviewed flags (ruling B6)", package: 'cosign-linux-amd64', exe: 'cosign', dialect: 'long', sub: ['sign'], flags: { yes: 'bool' }, required: { yes: 'true' } },
  actionlint: { method: GH, package: 'actionlint_1.7.12_linux_amd64.tar.gz',
    exe: 'actionlint', dialect: 'goflags', sub: [], flags: { 'no-color': 'bool', shellcheck: { values: [''] }, pyflakes: { values: [''] } },
    required: { shellcheck: '', pyflakes: '' },
    config: { flag: '-config-file', content: "self-hosted-runner:\n  labels: []\npaths:\n  .github/workflows/**/*.{yml,yaml}:\n    ignore:\n      - 'unexpected key \"cache-mode\" for \"job\" section'\n", fileName: 'actionlint.yaml' },
  },
  zizmor: { method: GH, package: 'zizmor-x86_64-unknown-linux-gnu.tar.gz', exe: 'zizmor', dialect: 'long', sub: [], positionals: ['.github/workflows'], flags: { offline: 'bool' }, required: { offline: 'true' }, config: { flag: '--config', content: 'rules: {}\n', fileName: 'zizmor.yml' } },
  // Biome 2.5.15: `biome ci` (lint + format check, never writes)
  biome: { method: 'npm', package: '@biomejs/biome', npmBin: 'bin/biome',
    exe: 'biome', dialect: 'long', sub: ['ci'], flags: {},
    config: { flag: '--config-path', content: '{\n  "linter": {\n    "rules": {\n      "complexity": {\n        "noExcessiveCognitiveComplexity": { "level": "error", "options": { "maxAllowedComplexity": 15 } }\n      }\n    }\n  }\n}\n', fileName: 'biome.json' },
  },
  // ESLint 10.13.0: no warnings allowed; the pinned flat config lints the framework files too (P25)
  eslint: { method: 'npm', package: 'eslint', npmBin: 'bin/eslint.js',
    exe: 'eslint', dialect: 'long', sub: [], positionals: ['.'], flags: { 'max-warnings': { values: ['0'] } }, required: { 'max-warnings': '0' },
    config: { flag: '--config', content: `export default [{ ${ESLINT_FILES}, languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } }, rules: { complexity: ['error', 15] } }];\n`, fileName: 'eslint.config.mjs' },
  },
  'eslint-typescript': { method: 'npm', package: 'eslint', npmBin: 'bin/eslint.js',
    exe: 'eslint', dialect: 'long', sub: [], positionals: ['.'], flags: { 'max-warnings': { values: ['0'] } }, required: { 'max-warnings': '0' },
    // built in two parts so the bundled CLI holds no import statement of a non-node module (test/package.test.ts)
    config: { flag: '--config', content: [`import tseslint from`, `'typescript-eslint';\nexport default [...tseslint.configs.recommended, { ${ESLINT_TS_FILES}, rules: { complexity: ['error', 15] } }];\n`].join(' '), fileName: 'eslint.config.mjs' },
  },
  // Oxlint 1.89.0
  'oxlint-typeaware': { method: 'npm', package: 'oxlint', npmBin: 'bin/oxlint', closureEnv: { OXLINT_TSGOLINT_PATH: 'node_modules/.bin/tsgolint' },
    exe: 'oxlint', dialect: 'long', sub: [], flags: { 'type-aware': 'bool', 'deny-warnings': 'bool' }, required: { 'type-aware': 'true', 'deny-warnings': 'true' },
    config: { flag: '--config', content: '{ "categories": { "correctness": "error" } }\n', fileName: 'oxlintrc.json' },
  },
  // Prettier 3.9.10: check only (never --write); the repo's own Prettier config is used (catalogue §2)
  prettier: { method: 'npm', package: 'prettier', npmBin: 'bin/prettier.cjs', loadsRepoConfig: true, exe: 'prettier', dialect: 'long', sub: [], positionals: ['.'], flags: { check: 'bool' }, required: { check: 'true' } },
  // Vitest 5.0.5: coverage on, with a minimum the AI chooses (P24)
  'vitest-coverage': { method: 'npm', package: 'vitest', npmBin: 'vitest.mjs', runsRepoCode: true,
    exe: 'vitest', dialect: 'long', sub: ['run'], flags: { coverage: 'bool', 'coverage.thresholds.lines': { values: COVERAGE_MINIMUMS } },
    required: { coverage: 'true', 'coverage.thresholds.lines': null },
  },
  // c8 12.0.0
  c8: { method: 'npm', package: 'c8', npmBin: 'bin/c8.js', runsRepoCode: true, exe: 'c8', dialect: 'long', sub: [], flags: { 'check-coverage': 'bool' }, required: { 'check-coverage': 'true' } },
  // Knip 6.42.1
  knip: { method: 'npm', package: 'knip', npmBin: 'bin/knip.js', loadsRepoConfig: true, exe: 'knip', dialect: 'long', sub: [], flags: { 'no-progress': 'bool' } },
  // jscpd 5.4.2 (the release binary): new copy-paste against the base only; no semantic mode (jscpdProblems)
  jscpd: { method: GH, package: 'jscpd-linux-x64-gnu.tar.gz',
    exe: 'jscpd', dialect: 'long', sub: [], positionals: ['.'],
    flags: { 'baseline-from-ref': { values: ['origin/main'] }, 'fail-on-new-clones': { values: [''], optional: true }, reporters: { values: ['sarif'] }, output: { values: ['jscpd-report'] } },
    required: { 'baseline-from-ref': 'origin/main', 'fail-on-new-clones': '' },
    config: { flag: '--config', content: '{}\n', fileName: 'jscpd.json' },
  },
  // hadolint 2.15.1: fails on warnings and errors (never --no-fail or a lower threshold)
  hadolint: { method: GH, needsSlot: 'needs the Dockerfile to check, a repo-path slot that is rendered in 6c', package: 'hadolint-linux-x86_64',
    exe: 'hadolint', dialect: 'long', sub: [], flags: { 'no-color': 'bool', 'failure-threshold': { values: ['warning'] }, format: { values: ['sarif'] }, output: 'output' },
    required: { 'failure-threshold': 'warning', format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned hadolint config: every rule at its default level, nothing ignored\nignored: []\n", fileName: 'hadolint.yaml' },
  },
  // kube-linter 0.8.3: an unrenderable chart, a bad path or YAML it can't parse fails the check (P25)
  'kube-linter': { method: GH, needsSlot: 'needs the folder to check, a repo-path slot that is rendered in 6c', package: 'kube-linter-linux',
    exe: 'kube-linter', dialect: 'long', sub: ['lint'],
    flags: { 'fail-if-no-objects-found': 'bool', 'fail-on-invalid-resource': 'bool', format: { values: ['sarif'] }, output: 'output' },
    required: { 'fail-if-no-objects-found': 'true', 'fail-on-invalid-resource': 'true', format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned kube-linter config: the default checks\nchecks:\n  doNotAutoAddDefaults: false\n", fileName: 'kube-linter.yaml' },
  },
  // Schemathesis 4.32.2: exactly 25 examples per operation, JUnit report
  schemathesis: { method: 'pip', package: 'schemathesis',
    exe: 'schemathesis', dialect: 'long', sub: ['run'], flags: { 'max-examples': { values: ['25'] }, report: { values: ['junit'] }, 'report-junit-path': 'output' },
    required: { 'max-examples': '25', report: 'junit', 'report-junit-path': null },
  },
  // pinact 5.0.0: check only (never rewrites the workflows), and every version comment checked
  pinact: { method: GH, package: 'pinact_linux_amd64.tar.gz', exe: 'pinact', dialect: 'long', sub: ['run'], flags: { check: 'bool', 'verify-comment': 'bool' }, required: { check: 'true', 'verify-comment': 'true' } },
  // poutine 1.1.6
  poutine: { method: GH, package: 'poutine_Linux_x86_64.tar.gz',
    exe: 'poutine', dialect: 'long', sub: ['analyze_local'], positionals: ['.'], flags: { 'disable-version-check': 'bool', 'fail-on-violation': 'bool', quiet: 'bool' },
    required: { 'disable-version-check': 'true', 'fail-on-violation': 'true' },
    config: { flag: '--config', content: "# pipegen's pinned poutine config: no skipped rules\nskip: []\n", fileName: 'poutine.yml' },
  },
  // gosec 2.29.0 (Go flags): never -no-fail; every #nosec suppression is reported in the SARIF (P27)
  gosec: { method: GH, needsSlot: 'is for Go: Go is not supported in v0.2 (it needs setup-go discovery, 6c)', package: 'gosec_2.29.0_linux_amd64.tar.gz',
    exe: 'gosec', dialect: 'goflags', sub: [], positionals: ['./...'], flags: { fmt: { values: ['sarif'] }, out: 'output', 'track-suppressions': 'bool' },
    required: { fmt: 'sarif', out: null, 'track-suppressions': 'true' },
  },
  // Ruff 0.17.1 (never --exit-zero, --fix or a format without --check)
  ruff: { method: GH, package: RUFF_ASSET,
    exe: 'ruff', dialect: 'long', sub: ['check'], flags: { 'no-cache': 'bool', 'output-format': { values: ['sarif'] }, 'output-file': 'output' },
    required: { 'no-cache': 'true', 'output-format': 'sarif', 'output-file': null },
    config: { flag: '--config', content: '[lint]\nextend-select = ["C901"]\n\n[lint.mccabe]\nmax-complexity = 15\n', fileName: 'ruff.toml' },
  },
  'ruff-format': { method: GH, package: RUFF_ASSET,
    exe: 'ruff', dialect: 'long', sub: ['format'], flags: { check: 'bool', 'no-cache': 'bool' }, required: { check: 'true', 'no-cache': 'true' },
    config: { flag: '--config', content: "# pipegen's pinned ruff config: the default format\n", fileName: 'ruff.toml' },
  },
  // mypy 2.4.0 (never --install-types: it installs unpinned stub packages)
  mypy: { method: 'pip', package: 'mypy', exe: 'mypy', dialect: 'long', sub: [], positionals: ['.'], flags: { 'no-incremental': 'bool' } },
  // coverage.py 7.16.2: pytest under coverage, then the minimum (P24)
  'coverage-py': { method: 'pip', package: 'coverage',
    exe: 'coverage', dialect: 'long', sub: ['run'], positionals: ['pytest'], flags: { module: 'bool' }, required: { module: 'true' },
    then: [{ sub: ['report'], flags: { 'fail-under': { values: COVERAGE_MINIMUMS } }, required: { 'fail-under': null } }],
  },
  creosote: { method: 'pip', package: 'creosote', exe: 'creosote', dialect: 'long', sub: [], flags: {} },
  vulture: { method: 'pip', package: 'vulture', exe: 'vulture', dialect: 'long', sub: [], positionals: ['.'], flags: { 'min-confidence': { values: ['80'] } }, required: { 'min-confidence': '80' } },
  // Bandit 1.9.4 (never --exit-zero)
  bandit: { method: 'pip', package: 'bandit',
    exe: 'bandit', dialect: 'long', sub: [], positionals: ['.'], flags: { recursive: 'bool', format: { values: ['sarif'] }, output: 'output' },
    required: { recursive: 'true', format: 'sarif', output: null },
  },
} satisfies Record<string, ArgvPolicy>;

/**
 * The tools whose run step may carry a harmless id (`tool-run-…` / `checker-run-…`) instead of `repocode-…` (controller
 * ruling on 6b Part 0): the default is repo code, because a tool that reads a repo config can load plugins or hooks from
 * it (mypy, schemathesis, pinact). An entry is listed only with a reason it can not load repo code. Everything with a
 * pinned config passed by flag reads that one (the loop test in test/job-order.test.ts checks this); semgrep and nuclei
 * have no config file but a verified rules archive. NOT listed, on purpose: lefthook, vitest-coverage, c8 (run repo code),
 * prettier, knip (load repo config), pinact (reads .pinact.yaml, no pinned config), gosec, cosign, registry (not rendered
 * as a step), and every pip tool and schemathesis.
 */
const READS_ONLY: readonly string[] = [
  // pinned config passed by flag
  'trivy-config', 'trivy-image', 'trivy-licence', 'betterleaks', 'gitleaks', 'osv-scanner', 'syft', 'actionlint', 'zizmor',
  'biome', 'eslint', 'eslint-typescript', 'oxlint-typeaware', 'jscpd', 'hadolint', 'kube-linter', 'poutine', 'ruff', 'ruff-format', 'zap-baseline',
  // no config file, but verified rules/templates only, no repo plugin mechanism on the allowlist
  'semgrep', 'nuclei',
];

export const ARGV_POLICIES: Readonly<Record<string, ArgvPolicy>> = Object.freeze(Object.fromEntries(
  Object.entries(POLICIES as Record<string, ArgvPolicy>).map(([id, pol]) => [id, READS_ONLY.includes(id) ? { ...pol, readsOnly: true as const } : pol]),
));

/** Whether a reviewed entry runs or loads the repo's own code (tests, hooks, a JS config): the referee's order rule treats its step as a repo-code step. */
export function runsRepoCode(entryId: string): boolean {
  return Object.hasOwn(ARGV_POLICIES, entryId) && (ARGV_POLICIES[entryId]?.runsRepoCode === true || ARGV_POLICIES[entryId]?.loadsRepoConfig === true);
}

/** The id of the run step of an entry that runs repo code: `repocode-` plus a hash of its artifact name (not `pipegen-…`, so a job's dedupe never drops it). */
export const REPO_CODE_STEP_ID_RE = /^repocode-[0-9a-f]{16}$/;
/** The id of a checker's step: install from pipegen's own lock, check and run in ONE step (a checker only reads code). */
export const CHECKER_STEP_ID_RE = /^checker-run-[0-9a-f]{16}$/;
/** The ids of a release/docker/pip tool's install (or image pull) step and of its run step: tools that only read code, installed from a pinned hash or digest. */
export const TOOL_STEP_ID_RE = /^tool-(?:install|pull|run)-[0-9a-f]{16}$/;
/** The ids of the Node and Python setup steps that the CLI renderer adds (a pinned platform action). */
export const SETUP_STEP_ID_RE = /^pipegen-setup-(?:node-\d{1,3}|python)$/;
/** The id of a scrub step (Plan C's gate action) in a job: the order rule treats it like an upload. */
export const SCRUB_STEP_ID_RE = /^scrub-[0-9a-f]{16}$/;

// ---------- pip closures (Plan B 6b, ruling B5) ----------

/**
 * Reviewed hash-locked requirement closures for the pip entries, by entry id: the exact `requirements.txt` text (one
 * `name==version --hash=sha256:<hex>` per line, the tool, its plugins and every dependency). pip refuses a requirement
 * without a hash under `--require-hashes`, and the renderer installs with `--no-deps`, so nothing outside this text is
 * ever installed. EMPTY today: no pip entry has a reviewed closure yet (v0.4, Plan D), so every pip tool is a
 * RenderError "not available yet". A closure is added here with its entry, by a code-reviewed change.
 */
export const PIP_CLOSURES: Readonly<Record<string, string>> = Object.freeze({});

// ---------- input allowlists for every action entry (Plan P Task 6 fix round 2, ruling P29) ----------

/**
 * One action input: its allowed values, and whether the template fixes it (in step.action.with and
 * fixedInputs.with, the same value), the AI chooses it (choices), or either. `required`: it must be fixed.
 */
export interface InputSpec { readonly values: readonly string[]; readonly as: 'fixed' | 'choice' | 'either'; readonly required?: true }

/**
 * Ruling P29: every reviewed action's inputs, by its EXACT `owner/repo[/path]` (lowercased, the `uses:` value without
 * `@<sha>`; ruling S14, review M-R7). An action whose path has no policy fails to load (so a renamed or typo fork, or
 * another sub-action of the same repo, never gets the reviewed locks' benefit of the doubt); any input not listed is
 * refused (default deny). Inputs the renderer fills per run (an artifact's name and path, a SARIF file, the subject of
 * an attestation) are not template inputs and aren't listed here: they are RENDERER_INPUTS below.
 */
export const ACTION_POLICIES: Readonly<Record<string, Readonly<Record<string, InputSpec>>>> = Object.freeze({
  'actions/checkout': {
    'persist-credentials': { values: ['false'], as: 'fixed', required: true },
    'allow-unsafe-pr-checkout': { values: ['false'], as: 'fixed', required: true },
    'fetch-depth': { values: ['1', '0'], as: 'choice' },
  },
  'actions/setup-node': {
    'package-manager-cache': { values: ['false'], as: 'fixed', required: true },
    'node-version': { values: ['22', '24', '26'], as: 'choice' },   // 22 (maintenance until 2027-04-30), 24, 26; the renderer maps the repo's own version onto these (render-step.ts mapNodeVersion)
  },
  'actions/setup-python': { 'python-version': { values: ['3.11', '3.12', '3.13', '3.14'], as: 'choice' } },
  // hidden files (.env and the like) are never uploaded; a missing file is an error. `path` is set by the renderer
  // from the scanning entries' own output paths, never by the template
  'actions/upload-artifact': {
    'include-hidden-files': { values: ['false'], as: 'fixed' },
    'if-no-files-found': { values: ['error'], as: 'fixed' },
  },
  'actions/download-artifact': {},
  'docker/login-action': { logout: { values: ['true'], as: 'fixed', required: true }, registry: { values: ['ghcr.io'], as: 'choice' } },   // ghcr.io only: the login sends the workflow token, which must never go to another registry (review 6a)
  'docker/setup-buildx-action': { 'cache-binary': { values: ['false'], as: 'fixed', required: true } },
  'docker/build-push-action': {
    context: { values: ['.'], as: 'fixed', required: true }, 'github-token': { values: [''], as: 'fixed', required: true },
    'no-cache': { values: ['true'], as: 'fixed', required: true }, push: { values: ['false', 'true'], as: 'choice' },
  },
  'github/codeql-action/upload-sarif': {},
  'actions/attest': {},
  'bullfrogsec/bullfrog': {
    'egress-policy': { values: ['block'], as: 'fixed', required: true },
    'dns-policy': { values: ['allowed-domains-only'], as: 'fixed', required: true },
    'enable-sudo': { values: ['false'], as: 'fixed', required: true },
    'allowed-domains': { values: ['github-core', 'npm', 'pypi', 'dockerhub', 'ghcr'], as: 'choice' },
    'allowed-ips': { values: ['172.16.0.0/12'], as: 'choice' },
  },
  // dependency review checks vulnerabilities (never off), blocks on low, moderate or high, never only warns, and never
  // compares a ref pipegen didn't choose (base-ref/head-ref: an empty diff passes; T3)
  'actions/dependency-review-action': {
    'comment-summary-in-pr': { values: ['never'], as: 'fixed', required: true },
    'vulnerability-check': { values: ['true'], as: 'fixed' },
    'fail-on-severity': { values: ['low', 'moderate', 'high'], as: 'either' },
    'warn-only': { values: ['false'], as: 'fixed' },
  },
  'ossf/scorecard-action': {
    publish_results: { values: ['false'], as: 'fixed', required: true },
    results_format: { values: ['sarif'], as: 'fixed' },
    results_file: { values: ['scorecard.sarif'], as: 'fixed' },
  },
  // trusted publishing with attestations, to PyPI or TestPyPI only (P22)
  'pypa/gh-action-pypi-publish': {
    attestations: { values: ['true'], as: 'fixed', required: true },
    'repository-url': { values: ['https://upload.pypi.org/legacy/', 'https://test.pypi.org/legacy/'], as: 'fixed' },
    'packages-dir': { values: ['dist'], as: 'fixed' },
    'skip-existing': { values: ['false', 'true'], as: 'fixed' },
    'print-hash': { values: ['true', 'false'], as: 'fixed' },
    verbose: { values: ['true', 'false'], as: 'fixed' },
  },
} satisfies Record<string, Record<string, InputSpec>>);

// ---------- inputs the renderer fills (ruling S15) ----------

/** One input the renderer (never a template, never the AI) fills at render time, with the check its value must pass. */
export interface RendererInput {
  readonly describe: string; readonly check: (v: string) => boolean;
  /** A condition on the action's whole `with:` (template, chosen and filled inputs), e.g. the login token only goes to ghcr.io. */
  readonly whenWith?: { readonly check: (all: Readonly<Record<string, string>>) => boolean; readonly describe: string };
}

const rx = (re: RegExp, describe: string, whenWith?: RendererInput['whenWith']): RendererInput => ({ describe, check: (v) => re.test(v), ...(whenWith === undefined ? {} : { whenWith }) });
/** A repo-relative file path: not absolute, not an option (`-x`), no `..`, plain characters, no `*`. Shared by the renderer's folder checks. */
export const PLAIN_REL_RE = /^(?![-/])(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,200}$/;
const GHCR_ONLY = { check: (all: Readonly<Record<string, string>>) => all.registry === 'ghcr.io', describe: 'only when the registry is ghcr.io' } as const;
const RUNNER_TEMP_PATH = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-out\/[a-z0-9][a-z0-9-]{0,120}(?:\/[A-Za-z0-9_][A-Za-z0-9._-]{0,100}){0,3}$/, 'a path under ${{ runner.temp }}/pipegen-out/<artifact>');
const ARTIFACT_NAME = rx(new RegExp(`^${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120}$`), `a result artifact name (${RESULT_ARTIFACT_PREFIX}…)`);

/**
 * Ruling S15: the inputs the renderer sets on a platform action, by the same `owner/repo[/path]` key as ACTION_POLICIES,
 * each with a checker. The renderer refuses any other input it is asked to set, and the referee's template check
 * accepts only these beyond the reviewed template. No name here is also a template input.
 * - upload/download-artifact: the result's name (resultArtifactName) and its place under runner.temp (ruling S7);
 * - upload-sarif: the scrubbed SARIF file and the code-scanning category;
 * - attest: the image and its digest; build-push: the Dockerfile (Service.dockerfile) and the one image tag;
 * - docker login: the actor and the workflow token, nothing else.
 */
export const RENDERER_INPUTS: Readonly<Record<string, Readonly<Record<string, RendererInput>>>> = Object.freeze({
  'actions/upload-artifact': { name: ARTIFACT_NAME, path: RUNNER_TEMP_PATH },
  'actions/download-artifact': { name: ARTIFACT_NAME, path: RUNNER_TEMP_PATH },
  'github/codeql-action/upload-sarif': { sarif_file: RUNNER_TEMP_PATH, category: rx(/^pipegen-[a-z0-9][a-z0-9-]{0,100}$/, 'a category starting pipegen-') },
  'actions/attest': {
    'subject-name': rx(/^(?:ghcr\.io|docker\.io)\/[a-z0-9][a-z0-9._/-]{0,200}$/, 'an image name on ghcr.io or docker.io, with no tag'),
    'subject-digest': rx(/^sha256:[0-9a-f]{64}$/, 'a sha256 digest'),
  },
  'docker/build-push-action': {
    file: rx(PLAIN_REL_RE, 'a repo-relative file path'),
    tags: rx(/^[a-z0-9][a-z0-9._/-]{0,200}:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/, 'one image reference with a tag'),
  },
  'docker/login-action': {
    username: rx(/^\$\{\{ github\.actor \}\}$/, '${{ github.actor }}'),
    password: rx(/^\$\{\{ secrets\.GITHUB_TOKEN \}\}$/, '${{ secrets.GITHUB_TOKEN }}', GHCR_ONLY),
  },
} satisfies Record<string, Record<string, RendererInput>>);

/**
 * Plain-English problems with renderer-filled inputs for an action (its `uses` path without `@sha`, any letter case).
 * `all` is the action's whole `with:` (defaults to `inputs`), for the inputs that depend on another one.
 */
export function rendererInputProblems(usesPath: string, inputs: Readonly<Record<string, string>>, all: Readonly<Record<string, string>> = inputs): string[] {
  const key = usesPath.toLowerCase();
  const table = Object.hasOwn(RENDERER_INPUTS, key) ? RENDERER_INPUTS[key] : undefined;
  const out: string[] = [];
  for (const [name, value] of Object.entries(inputs)) {
    const spec = table !== undefined && Object.hasOwn(table, name) ? table[name] : undefined;
    if (spec === undefined) out.push(`${usesPath} takes no renderer-filled input ${JSON.stringify(name.slice(0, 40))}${table === undefined ? '' : ` (only ${Object.keys(table).join(', ')})`}`);
    else if (typeof value !== 'string' || !spec.check(value)) out.push(`${usesPath} input ${name} must be ${spec.describe}`);
    else if (spec.whenWith !== undefined && !spec.whenWith.check(all)) out.push(`${usesPath} input ${name} is allowed ${spec.whenWith.describe}`);
  }
  return out;
}
