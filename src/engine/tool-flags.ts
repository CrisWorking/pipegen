// The policy leaf: every argv and action policy pipegen applies, in one module (it imports only the import-free types.ts, node:crypto, and slots.ts as a
// type), so the loader, the renderers and the referee check against the same tables (Plan P ruling PS34): the tool flags pipegen never
// passes, the argv policies (ARGV_POLICIES), the reviewed action input policies, the platform action paths and locks, the step-id
// patterns, the pip closures and the renderer-filled inputs (RENDERER_INPUTS with their checkers).

import { createHash } from 'node:crypto';
import { NEED_CATEGORIES, RESULT_ARTIFACT_PREFIX } from '../types.js';
import type { SlotKind } from './slots.js';

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
   * Why this entry is never rendered as a step by renderStep, in plain words (cosign: Plan G's sign job; gosec: Go is not
   * supported in v0.2): a RenderError now, instead of a step that fails at run time. (Named `needsSlot` in 6b, when the
   * target slots did not exist yet; they do now, see `slots`.)
   */
  readonly needsSlot?: string;
  /**
   * Run-time slots (6c, ruling B6), by flag (`-t`, `--baseline-from-ref`) or `''` for a trailing positional: the kind of value
   * the renderer fills from the render context or the profile (never the AI), checked by slots.ts and passed in env. A flag
   * that is already in the command has its value replaced; otherwise `flag value` is appended.
   */
  readonly slots?: Readonly<Record<string, SlotKind>>;
  /** For a `repo-path` slot: where the path comes from, a service's Dockerfile or the Kubernetes folder (context target, else `.` when the repo has Kubernetes files). */
  readonly repoPathFrom?: 'dockerfile' | 'k8s-dir';
  /**
   * A pinned git archive of rules or templates (6c, ruling S12): fetched by commit into a fresh runner-temp folder, and
   * HEAD and HEAD^{tree} are checked against the reviewed values before anything uses it. `treeEnv` and `commitEnv` (or
   * `urlEnv`, whose archive URL holds the commit) name the template env variables with the reviewed values; `dir` is the
   * word of the command that names the folder (docker: the path inside the container, mounted read-only; otherwise it is
   * replaced by the checked-out folder); `subChoice` is the choice that picks a sub-folder to mount.
   */
  readonly archive?: { readonly repo: string; readonly treeEnv: string; readonly commitEnv?: string; readonly urlEnv?: string; readonly dir: string; readonly subChoice?: string };
  /**
   * The tool's own scope file (6d fix round 1, ruling 6, DECISIONS #108): semgrep reads every `.semgrepignore` in the tree and, with
   * none, applies built-in ignores that skip test/, tests/, build/, vendor/ and dist/ at any depth. The renderer deletes every
   * file of this name under the step folder (links included, never followed) and writes pipegen's own, whose `lines` are reviewed
   * constants. A file at the scan root replaces the defaults (measured on semgrep 1.181.0).
   */
  readonly scopeIgnore?: { readonly file: string; readonly lines: readonly string[] };
  /**
   * Repo files the tool reads to drop findings (C1b fix round 2, review R1-I1): betterleaks and gitleaks silence a finding named by a
   * `file:rule:line` entry of `.gitleaksignore` / `.betterleaksignore` at the scan root, and `--gitleaks-ignore-path` cannot turn that off.
   * The renderer deletes every file of these names under the step folder (links included, never followed) before the scan and writes
   * nothing in their place; the files stay protected paths, so a PR that changes one is still flagged.
   */
  readonly removeFiles?: readonly string[];
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
  /**
   * Plan C ruling B2, for every entry whose result is `sarif` or `zap-json` (a findings tool): the exit codes that mean "the
   * scan worked and found something", besides 0. The run step treats an exit in `{0} ∪ findingsExit` with a regular result
   * file as success and moves the file to `pipegen-raw`; any other exit deletes the result and fails the step. So the step
   * fails only when the tool itself failed, and the gate never reads a job's failure as a finding. `[]` for a tool that
   * exits 0 on findings (semgrep without `--error`, nuclei). An entry with no result file keeps failing on any non-zero exit.
   */
  readonly findingsExit?: readonly number[];
}

// the dedicated tools (trivy, betterleaks, nuclei) have their own full-grammar rules in reviewed.ts; only the pinned config is listed here, for the renderer
const DEDICATED = (exe: string, pkg: string, config?: ArgvPolicy['config']): ArgvPolicy => ({ method: 'github-release', package: pkg, exe, dialect: 'long', sub: [], flags: {}, dedicated: true, ...(config === undefined ? {} : { config }) });
/** The exit codes of a findings tool that mean "found something" (ArgvPolicy.findingsExit): 1 for most, none for a tool that exits 0 on findings. */
const FOUND_1 = [1] as const;
/** trivy, betterleaks and gitleaks are told `--exit-code 10`: their errors, and betterleaks' partial scan, exit 1, so 1 can not also mean a finding (C0a fix round 1). */
const FOUND_10 = [10] as const;
const TRIVY_CONFIG = { flag: '--config', content: "# pipegen's pinned trivy config: no cache kept between runs\ncache:\n  backend: memory\n", fileName: 'trivy.yaml' } as const;
/** The ignore files betterleaks 1.9.0 and gitleaks 8.30.1 read from the scan root (`--help` of `dir`: `.betterleaksignore` or `.gitleaksignore`). */
const SECRETS_IGNORE_FILES = ['.gitleaksignore', '.betterleaksignore'] as const;
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
  'trivy-config': { ...DEDICATED('trivy', TRIVY_ASSET, TRIVY_CONFIG), findingsExit: FOUND_10 },
  'trivy-image': { ...DEDICATED('trivy', TRIVY_ASSET, TRIVY_CONFIG), slots: { '': 'image-digest' }, findingsExit: FOUND_10 },
  'trivy-licence': { ...DEDICATED('trivy', TRIVY_ASSET, TRIVY_CONFIG), findingsExit: FOUND_10 },
  betterleaks: { ...DEDICATED('betterleaks', 'betterleaks_1.9.0_linux_x64.tar.gz', { flag: '--config', content: '[extend]\nuseDefault = true\n', fileName: 'betterleaks.toml' }), findingsExit: FOUND_10, removeFiles: SECRETS_IGNORE_FILES },
  nuclei: { ...DEDICATED('nuclei', 'nuclei_3.11.1_linux_amd64.zip'), slots: { '-target': 'local-url' }, findingsExit: [],
    archive: { repo: 'projectdiscovery/nuclei-templates', commitEnv: 'PIPEGEN_NUCLEI_TEMPLATES_COMMIT', treeEnv: 'PIPEGEN_NUCLEI_TEMPLATES_TREE', dir: '/pipegen-nuclei-templates' } },
  // ruling P28: the image entries too. registry runs the image's own entrypoint, nothing else
  registry: { method: 'docker', package: 'registry', exe: '', entrypoint: true, dialect: 'long', sub: [], flags: {} },
  // ZAP baseline (zaproxy/zap-stable): getopt short options, read as Go-style words; no -I (warnings that never fail)
  'zap-baseline': {
    slots: { '-t': 'local-url' }, network: 'host', asImageUser: true,
    method: 'docker', package: 'zaproxy/zap-stable', exe: 'zap-baseline.py', dialect: 'goflags', sub: [], flags: { J: 'output', z: { values: ['-silent'] } },
    findingsExit: [1, 2],   // 1: a FAIL alert, 2: a WARN alert (0 is a clean run)
    required: { J: null, z: '-silent' }, mount: { at: '/zap/wrk', source: 'work' }, config: { flag: '-c', content: "# pipegen's pinned ZAP baseline rules: the defaults, nothing ignored\n", fileName: 'zap-baseline.conf' },
  },
  // Semgrep CE 1.181.0: rules only from the verified archive (semgrepProblems), no metrics, no version check, and no file-size skip
  // (--max-target-bytes=0: by default semgrep silently skips every file over 1 MB, so padding a file would hide it from SAST; DECISIONS #108)
  semgrep: {
    method: 'docker', package: 'semgrep/semgrep', exe: 'semgrep', dialect: 'long', sub: ['scan'], findingsExit: [],
    flags: { metrics: { values: ['off'] }, 'disable-version-check': 'bool', 'max-target-bytes': { values: ['0'] }, config: { values: ['/pipegen-rules'] }, sarif: 'bool', output: 'output' },
    required: { metrics: 'off', 'disable-version-check': 'true', 'max-target-bytes': '0', config: '/pipegen-rules' },
    scopeIgnore: { file: '.semgrepignore', lines: ['node_modules'] },
    env: ['PIPEGEN_RULES_URL', 'PIPEGEN_RULES_SHA256', 'PIPEGEN_RULES_TREE'], extraChoices: { rules: ['javascript', 'typescript', 'python'] },
    mount: { at: '/src', source: 'repo', workdir: true }, network: 'none',
    archive: { repo: 'semgrep/semgrep-rules', urlEnv: 'PIPEGEN_RULES_URL', treeEnv: 'PIPEGEN_RULES_TREE', dir: '/pipegen-rules', subChoice: 'rules' },
  },
  // gitleaks 8.30.1 (`gitleaks dir --help`; dir mode since C1b fix round 1, so the scanner reads the bytes the scrub reads), the secrets fallback (P21): the same locks as betterleaks
  gitleaks: { method: GH, package: 'gitleaks_8.30.1_linux_x64.tar.gz',
    exe: 'gitleaks', dialect: 'long', sub: ['dir'], positionals: ['.'], findingsExit: FOUND_10, removeFiles: SECRETS_IGNORE_FILES,
    flags: { 'no-banner': 'bool', 'ignore-gitleaks-allow': 'bool', redact: { values: ['', '100'], optional: true }, 'report-format': { values: ['sarif'] }, 'report-path': 'output', 'exit-code': { values: ['10'] }, 'max-archive-depth': { values: ['0'] } },
    required: { 'ignore-gitleaks-allow': 'true', redact: '', 'report-format': 'sarif', 'report-path': null, 'exit-code': '10', 'max-archive-depth': '0' },
    config: { flag: '--config', content: '[extend]\nuseDefault = true\n', fileName: 'gitleaks.toml' },
  },
  // osv-scanner v2.7.0
  'osv-scanner': { method: GH, package: 'osv-scanner_linux_amd64',
    exe: 'osv-scanner', dialect: 'long', sub: ['scan', 'source'], positionals: ['.'], findingsExit: FOUND_1,
    flags: { recursive: 'bool', format: { values: ['sarif'] }, output: 'output' }, required: { format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned osv-scanner config: no ignored vulnerabilities\n", fileName: 'osv-scanner.toml' },
  },
  lefthook: { method: GH, runsRepoCode: true, package: 'lefthook_2.2.2_Linux_x86_64', exe: 'lefthook', dialect: 'long', sub: ['run', 'pre-commit'], flags: { 'all-files': 'bool' }, required: { 'all-files': 'true' } },
  syft: { method: GH, slots: { '': 'image-digest' }, package: 'syft_1.55.0_linux_amd64.tar.gz',
    exe: 'syft', dialect: 'long', sub: ['scan'], flags: { output: { values: ['spdx-json=sbom.spdx.json'] } }, required: { output: 'spdx-json=sbom.spdx.json' },
    config: { flag: '--config', content: 'check-for-app-update: false\n', fileName: 'syft.yaml' },
  },
  cosign: { method: GH, needsSlot: "is run by Plan G's sign job, which adds its own reviewed flags", package: 'cosign-linux-amd64', exe: 'cosign', dialect: 'long', sub: ['sign'], flags: { yes: 'bool' }, required: { yes: 'true' } },
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
    config: { flag: '--config', content: [`import js from`, `'@eslint/js';\nexport default [js.configs.recommended, { ${ESLINT_FILES}, languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } }, rules: { complexity: ['error', 15] } }];\n`].join(' '), fileName: 'eslint.config.mjs' },
  },
  'eslint-typescript': { method: 'npm', package: 'eslint', npmBin: 'bin/eslint.js',
    exe: 'eslint', dialect: 'long', sub: [], positionals: ['.'], flags: { 'max-warnings': { values: ['0'] } }, required: { 'max-warnings': '0' },
    // built in parts so the bundled CLI holds no import statement of a non-node module (test/package.test.ts)
    config: { flag: '--config', content: [`import js from`, `'@eslint/js';\nimport tseslint from`, `'typescript-eslint';\nexport default [js.configs.recommended, ...tseslint.configs.recommended, { ${ESLINT_TS_FILES}, rules: { complexity: ['error', 15] } }];\n`].join(' '), fileName: 'eslint.config.mjs' },
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
  jscpd: { method: GH, slots: { '--baseline-from-ref': 'git-ref' }, package: 'jscpd-linux-x64-gnu.tar.gz',
    exe: 'jscpd', dialect: 'long', sub: [], positionals: ['.'],
    flags: { 'baseline-from-ref': { values: ['origin/main'] }, 'fail-on-new-clones': { values: [''], optional: true }, reporters: { values: ['sarif'] }, output: { values: ['jscpd-report'] } },
    required: { 'baseline-from-ref': 'origin/main', 'fail-on-new-clones': '' },
    config: { flag: '--config', content: '{}\n', fileName: 'jscpd.json' },
  },
  // hadolint 2.15.1: fails on warnings and errors (never --no-fail or a lower threshold)
  hadolint: { method: GH, slots: { '': 'repo-path' }, repoPathFrom: 'dockerfile', package: 'hadolint-linux-x86_64',
    exe: 'hadolint', dialect: 'long', sub: [], findingsExit: FOUND_1, flags: { 'no-color': 'bool', 'failure-threshold': { values: ['warning'] }, format: { values: ['sarif'] }, output: 'output' },
    required: { 'failure-threshold': 'warning', format: 'sarif', output: null },
    config: { flag: '--config', content: "# pipegen's pinned hadolint config: every rule at its default level, nothing ignored\nignored: []\n", fileName: 'hadolint.yaml' },
  },
  // kube-linter 0.8.3: an unrenderable chart, a bad path or YAML it can't parse fails the check (P25)
  'kube-linter': { method: GH, slots: { '': 'repo-path' }, repoPathFrom: 'k8s-dir', package: 'kube-linter-linux',
    exe: 'kube-linter', dialect: 'long', sub: ['lint'], findingsExit: FOUND_1,
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
  gosec: { method: GH, needsSlot: 'is for Go: Go is not supported in v0.2 (a permanent refusal until Go setup is added)', package: 'gosec_2.29.0_linux_amd64.tar.gz',
    exe: 'gosec', dialect: 'goflags', sub: [], positionals: ['./...'], findingsExit: FOUND_1, flags: { fmt: { values: ['sarif'] }, out: 'output', 'track-suppressions': 'bool' },
    required: { fmt: 'sarif', out: null, 'track-suppressions': 'true' },
  },
  // Ruff 0.17.1 (never --exit-zero, --fix or a format without --check)
  ruff: { method: GH, package: RUFF_ASSET,
    exe: 'ruff', dialect: 'long', sub: ['check'], findingsExit: FOUND_1, flags: { 'no-cache': 'bool', 'output-format': { values: ['sarif'] }, 'output-file': 'output' },
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
    exe: 'bandit', dialect: 'long', sub: [], positionals: ['.'], findingsExit: FOUND_1, flags: { recursive: 'bool', format: { values: ['sarif'] }, output: 'output' },
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

/**
 * Whether the run step of a reviewed entry is a repo-code step (the order rule applies to it). This IS the renderer's rule,
 * which render-cli.ts calls: fail closed, a run is repo code unless its policy says it only reads (`readsOnly`) and it
 * neither runs the repo's code nor loads its config, and it is not an app-running tool (`appRunning`: tests, coverage, builds).
 * Pass an entry id (looked up in ARGV_POLICIES) or the policy the renderer holds. An unknown id is repo code.
 */
export function runsRepoCode(entry: string | ArgvPolicy | undefined, appRunning = false): boolean {
  const pol = typeof entry === 'string' ? (Object.hasOwn(ARGV_POLICIES, entry) ? ARGV_POLICIES[entry] : undefined) : entry;
  const harmless = pol !== undefined && pol.readsOnly === true && pol.runsRepoCode !== true && pol.loadsRepoConfig !== true && !appRunning;
  return !harmless;
}

/** The id of the run step of an entry that runs repo code: `repocode-` plus a hash of its artifact name (not `pipegen-…`, so a job's dedupe never drops it). */
export const REPO_CODE_STEP_ID_RE = /^repocode-[0-9a-f]{16}$/;
/** The id of a checker's step: install from pipegen's own lock, check and run in ONE step (a checker only reads code). */
export const CHECKER_STEP_ID_RE = /^checker-run-[0-9a-f]{16}$/;
/** The ids of a release/docker/pip tool's install (or image pull) step and of its run step: tools that only read code, installed from a pinned hash or digest. */
export const TOOL_STEP_ID_RE = /^tool-(?:install|pull|run)-[0-9a-f]{16}$/;
/** The ids of the checkout step of a project script and of the Node and Python setup steps the renderers add (a pinned platform action each): a job keeps the first of each. */
export const SETUP_STEP_ID_RE = /^pipegen-(?:checkout|setup-node-\d{1,3}|setup-python)$/;
/** The id of a scrub step (Plan C's gate action in `scrub` mode, ruling B1) in a job: the order rule treats it like an upload. */
export const SCRUB_STEP_ID_RE = /^scrub-[0-9a-f]{16}$/;
/** The first 16 hex digits of the SHA-256 of a text: the short, stable part of the ids that tie a result's steps together (scan, scrub). */
export const sha16 = (text: string): string => createHash('sha256').update(text).digest('hex').slice(0, 16);
/** The id of the scrub step of a result artifact: `scrub-<sha16(artifact)>`. The job outputs and the scrub cross-checks name a scrub by this id. */
export const scrubStepId = (artifact: string): string => `scrub-${sha16(artifact)}`;
/** The `uses` path of pipegen's own gate action (a leaf constant: the renderer, the order rule and the referee all name it from here). */
export const PIPEGEN_GATE_USES = 'crisworking/pipegen/gate';
/** A pinned use of the gate action: the path, `@`, a 40-character commit. The reviewed pin itself is the referee's question. */
export const GATE_USES_RE = new RegExp(`^${PIPEGEN_GATE_USES.replace(/[/.]/g, '\\$&')}@[0-9a-f]{40}$`);
/** The one secret a recognised scrub step may name (ruling B1 parts 5 and 6): the HMAC key of the fingerprints. */
export const SCRUB_SECRET = 'PIPEGEN_FP_KEY';

// ---------- pip closures (Plan B 6b, ruling B5) ----------

/**
 * Reviewed hash-locked requirement closures for the pip entries, by entry id: the exact `requirements.txt` text (one
 * `name==version --hash=sha256:<hex>` per line, the tool, its plugins and every dependency). pip refuses a requirement
 * without a hash under `--require-hashes`, and the renderer installs with `--no-deps`, so nothing outside this text is
 * ever installed. EMPTY today: no pip entry has a reviewed closure yet (v0.4, Plan D), so every pip tool is a
 * RenderError "not available yet". A closure is added here with its entry, by a code-reviewed change.
 */
export const PIP_CLOSURES: Readonly<Record<string, string>> = Object.freeze({});

/** The keys of PlatformActions (pin.ts), spelled here so this module stays a leaf. */
export type PlatformKey = 'checkout' | 'setup-node' | 'setup-python' | 'upload-artifact' | 'download-artifact' | 'docker-login' | 'setup-buildx' | 'build-push' | 'upload-sarif' | 'attest';

/** PlatformActions key → the `uses:` path (owner/repo[/path], lower case) its entry must have; a swapped entry is refused. */
export const PLATFORM_USES: Readonly<Record<PlatformKey, string>> = Object.freeze({
  checkout: 'actions/checkout', 'setup-node': 'actions/setup-node', 'setup-python': 'actions/setup-python',
  'upload-artifact': 'actions/upload-artifact', 'download-artifact': 'actions/download-artifact', 'docker-login': 'docker/login-action',
  'setup-buildx': 'docker/setup-buildx-action', 'build-push': 'docker/build-push-action', 'upload-sarif': 'github/codeql-action/upload-sarif', attest: 'actions/attest',
});

/**
 * Inputs a platform action's entry must FIX to these values (by `uses` path). They are checked on every render path
 * (renderStep, renderPlatformStep, the prelude, the upload), not only where an entry is first used, and an input listed
 * here can not also be an AI choice.
 */
export const PLATFORM_LOCKS: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  'actions/checkout': { 'persist-credentials': 'false', 'allow-unsafe-pr-checkout': 'false' },
  'actions/setup-node': { 'package-manager-cache': 'false' },
  'actions/upload-artifact': { 'include-hidden-files': 'false', 'if-no-files-found': 'error' },
  // the docker actions' cache and credential locks (6b, review R1-5): checked here, not only by the loader
  'docker/build-push-action': { 'no-cache': 'true', 'github-token': '', context: '.' },
  'docker/setup-buildx-action': { 'cache-binary': 'false' },
  'docker/login-action': { logout: 'true' },
});

/** The cache inputs of the reviewed locks with their only allowed value (everything else that names a cache is refused): derived from PLATFORM_LOCKS, never typed twice. */
export const CACHE_LOCKS: Readonly<Record<string, string>> = Object.freeze(Object.fromEntries(
  Object.values(PLATFORM_LOCKS).flatMap((locks) => Object.entries(locks)).filter(([k]) => /(?:^|[-_])cache(?:$|[-_])/i.test(k)),
));

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
/** The path of an upload or download sits in the folder of the artifact it names (`pipegen-out/<with.name>`): one rule for the renderer, the emitter and the referee (final review finding 2). */
const OWN_ARTIFACT_FOLDER = {
  check: (all: Readonly<Record<string, string>>) => {
    const folder = `\${{ runner.temp }}/pipegen-out/${all.name ?? ''}`;
    return typeof all.name === 'string' && typeof all.path === 'string' && (all.path === folder || all.path.startsWith(`${folder}/`));
  },
  describe: 'only inside its own artifact folder (${{ runner.temp }}/pipegen-out/<name>)',
} as const;
const OWN_FOLDER_PATH = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-out\/[a-z0-9][a-z0-9-]{0,120}(?:\/[A-Za-z0-9_][A-Za-z0-9._-]{0,100}){0,3}$/, 'a path under ${{ runner.temp }}/pipegen-out/<artifact>', OWN_ARTIFACT_FOLDER);
const ARTIFACT_NAME = rx(new RegExp(`^${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120}$`), `a result artifact name (${RESULT_ARTIFACT_PREFIX}…)`);

// ---------- the scrub chain's folders (Plan C ruling B1) ----------
// A tool's raw result is moved to `${{ runner.temp }}/pipegen-raw/<artifact>/<file>`; only the gate action in scrub mode
// writes `${{ runner.temp }}/pipegen-out/<artifact>/<file>`, rebuilt from allowlisted fields. The upload rules above accept
// `pipegen-out` only, so a raw result can never be uploaded: the renderer, the emitter and the referee refuse it alike.
const TEMP = '${{ runner.temp }}';
const RESULT_FILE = '[A-Za-z0-9_][A-Za-z0-9._-]{0,100}';
const RAW_PATH_RE = new RegExp(`^\\$\\{\\{ runner\\.temp \\}\\}/pipegen-raw/(${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120})/(${RESULT_FILE})$`);
/** The artifact name and file of a raw result path (`${{ runner.temp }}/pipegen-raw/<artifact>/<file>`), or null for any other text. */
export function rawResultParts(path: string): { artifact: string; file: string } | null {
  const m = RAW_PATH_RE.exec(path);
  return m === null ? null : { artifact: m[1] as string, file: m[2] as string };
}
/** Where a raw result path is scrubbed to: the same artifact and file under `pipegen-out`; null when the text is not a raw result path. */
export function scrubbedResultPath(rawPath: string): string | null {
  const parts = rawResultParts(rawPath);
  return parts === null ? null : `${TEMP}/pipegen-out/${parts.artifact}/${parts.file}`;
}
const MODE_SCRUB = { check: (all: Readonly<Record<string, string>>) => all.mode === 'scrub', describe: 'only in mode scrub' } as const;
/** The scrub inputs that name a path: valid in scrub mode only, the raw one in the artifact's raw folder and the scrubbed one at the same file in its pipegen-out folder. */
const SCRUB_RAW = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-raw\//, 'a path ${{ runner.temp }}/pipegen-raw/<artifact>/<file>', {
  check: (all) => MODE_SCRUB.check(all) && rawResultParts(all.raw ?? '')?.artifact === all.artifact,
  describe: 'only in mode scrub, inside the folder of the artifact it names (${{ runner.temp }}/pipegen-raw/<artifact>/<file>)',
});
const SCRUB_OUT = rx(/^\$\{\{ runner\.temp \}\}\/pipegen-out\//, 'a path ${{ runner.temp }}/pipegen-out/<artifact>/<file>', {
  check: (all) => MODE_SCRUB.check(all) && scrubbedResultPath(all.raw ?? '') === all.out && rawResultParts(all.raw ?? '')?.artifact === all.artifact,
  describe: 'only in mode scrub, at the same file as raw, in the folder of the artifact it names (${{ runner.temp }}/pipegen-out/<artifact>/<file>)',
});
const inScrubMode = (input: RendererInput): RendererInput => ({ ...input, whenWith: input.whenWith ?? MODE_SCRUB });

// ---------- the gate action's modes (Plan C ruling B3) ----------
/** The modes of the gate action pipegen renders today (Plan I adds `merged-red` to this list and its row). */
export const GATE_MODES = ['scrub', 'gate', 'find-run', 'nightly'] as const;
/** An input valid only in the listed modes: the whole `with:` must name one of them. */
const inModes = (modes: readonly (typeof GATE_MODES)[number][]): NonNullable<RendererInput['whenWith']> => ({
  check: (all) => modes.some((m) => all.mode === m), describe: `only in mode ${modes.join(' or ')}`,
});
const modeInput = (modes: readonly (typeof GATE_MODES)[number][], re: RegExp, describe: string): RendererInput => rx(re, describe, inModes(modes));
/** A literal input that must pass a schema function (a null return = fine), in the listed modes only. */
const literalInput = (modes: readonly (typeof GATE_MODES)[number][], problem: (v: string) => string | null, describe: string): RendererInput => ({
  describe, check: (v) => problem(v) === null, whenWith: inModes(modes),
});

const ID_LIST_MAX = 50;
/** Why a text is not a JSON list of need ids (`not-proven`, `skipped`), or null. */
function idListProblem(text: string): string | null {
  const list = parseJson(text);
  if (!Array.isArray(list) || list.length > ID_LIST_MAX) return `a JSON list of at most ${ID_LIST_MAX} need ids`;
  return list.every((x) => typeof x === 'string' && NEED_ID_TEXT_RE.test(x)) ? null : 'a JSON list of need ids (lower case letters, digits and dashes)';
}
/** Why a text is not the gate's policy (`{ "block": [severities], "warn": [severities] }`), or null. */
function policyProblem(text: string): string | null {
  const v = parseJson(text);
  if (!isPlainObject(v) || Object.keys(v).sort().join() !== 'block,warn') return 'a JSON object with exactly block and warn';
  const sev = ['critical', 'high', 'medium', 'low', 'info'];
  if (!['block', 'warn'].every((k) => Array.isArray(v[k]) && (v[k] as unknown[]).length <= 5 && (v[k] as unknown[]).every((x) => typeof x === 'string' && sev.includes(x)))) return 'block and warn lists of severities';
  const block = v.block as string[];
  const warn = v.warn as string[];
  // the floor (decision 13): a policy can never stop critical and high findings from blocking, and no severity is in both lists or twice
  if (!block.includes('critical') || !block.includes('high')) return 'a policy whose block list includes at least critical and high';
  if (new Set(block).size !== block.length || new Set(warn).size !== warn.length || warn.some((x) => block.includes(x))) return 'a policy with no duplicate and no severity in both lists';
  return null;
}
/** Extra protected paths: globs without `..`, a leading `/` or an option dash, in plain characters (ruling S22). */
const GLOB_RE = /^(?![-/])(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/*?-]{1,200}$/;
function pathListProblem(text: string): string | null {
  const list = parseJson(text);
  if (!Array.isArray(list) || list.length > 100) return 'a JSON list of at most 100 path globs';
  return list.every((x) => typeof x === 'string' && GLOB_RE.test(x)) ? null : 'a JSON list of plain relative path globs (no .., no leading /)';
}

// the job list literal (rulings B4 and S4): the shape of one entry, kept here so the gate row can check it; gate-job-list.ts builds it
const NEED_ID_TEXT_RE = /^(?!base-)(?!.*--)[a-z0-9][a-z0-9-]{0,63}$/;
const JOB_ID_TEXT_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,99}$/;
const SERVICE_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const TOOL_ID_TEXT_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const RESULT_NAME_TEXT_RE = new RegExp(`^${RESULT_ARTIFACT_PREFIX}[a-z0-9][a-z0-9-]{0,120}$`);
const DATE_TEXT_RE = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/;
/** The keys an entry of the gate's job list may have, in the order the list is written. */
export const JOB_LIST_KEYS = ['needId', 'service', 'job', 'category', 'tool', 'format', 'artifact', 'baseArtifact', 'blocking', 'needsSecrets', 'warnFirst'] as const;
const JOB_LIST_MAX = 500;
const JOB_LIST_MAX_TEXT = 200_000;
const isPlainObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
function parseJson(text: string): unknown {
  if (typeof text !== 'string' || text.length > JOB_LIST_MAX_TEXT) return undefined;
  try { return JSON.parse(text); } catch { return undefined; }
}
const FIELD_CHECKS: Readonly<Record<(typeof JOB_LIST_KEYS)[number], (v: unknown) => boolean>> = {
  needId: (v) => typeof v === 'string' && NEED_ID_TEXT_RE.test(v),
  service: (v) => typeof v === 'string' && v.length <= 40 && SERVICE_SLUG_RE.test(v) && !v.includes('--'),
  job: (v) => typeof v === 'string' && JOB_ID_TEXT_RE.test(v),
  category: (v) => typeof v === 'string' && (NEED_CATEGORIES as readonly string[]).includes(v),
  tool: (v) => typeof v === 'string' && TOOL_ID_TEXT_RE.test(v),
  format: (v) => v === 'sarif' || v === 'zap-json' || v === 'junit' || v === 'none',
  artifact: (v) => typeof v === 'string' && RESULT_NAME_TEXT_RE.test(v),
  baseArtifact: (v) => typeof v === 'string' && RESULT_NAME_TEXT_RE.test(v),
  blocking: (v) => typeof v === 'boolean',
  needsSecrets: (v) => typeof v === 'boolean',
  warnFirst: (v) => isPlainObject(v) && Object.keys(v).join() === 'since' && typeof v.since === 'string' && DATE_TEXT_RE.test(v.since),
};
const JOB_LIST_REQUIRED: readonly (typeof JOB_LIST_KEYS)[number][] = ['needId', 'job', 'category', 'format', 'blocking', 'needsSecrets'];
/**
 * Why a text is not a job list the gate may read (a JSON list of entries: known keys only, each field of its shape, the
 * required ones present, no job twice, at most 500 entries), or null. The text is the `job-list` input of the gate step.
 */
export function jobListLiteralProblem(text: string): string | null {
  const list = parseJson(text);
  if (!Array.isArray(list)) return 'it is not a JSON list';
  if (list.length > JOB_LIST_MAX) return `it has more than ${JOB_LIST_MAX} entries`;
  const jobs = new Set<string>();
  for (const [i, e] of list.entries()) {
    if (!isPlainObject(e)) return `entry ${i + 1} is not an object`;
    for (const k of Object.keys(e)) if (!(JOB_LIST_KEYS as readonly string[]).includes(k)) return `entry ${i + 1} has the key ${JSON.stringify(k.slice(0, 40))}, which a job list entry never has`;
    for (const k of JOB_LIST_REQUIRED) if (!Object.hasOwn(e, k)) return `entry ${i + 1} has no ${k}`;
    for (const k of JOB_LIST_KEYS) if (Object.hasOwn(e, k) && !FIELD_CHECKS[k](e[k])) return `entry ${i + 1} has a ${k} that is not in the form pipegen writes`;
    if (jobs.has(e.job as string)) return `the job ${JSON.stringify(e.job)} is listed twice`;
    jobs.add(e.job as string);
  }
  return null;
}

/**
 * The ONE base commit a base-scan checkout may name (ruling S16, C0c CF3a), switched on the event, so it holds in any file, a called
 * workflow included, whatever event starts it: a pull request's base, a merge group's base, a push's previous head. On every other event,
 * and on a push to a new branch (`before` all zeros), the value is the all-zero COMMIT sha, which can never exist: the checkout fails and
 * the base-scan job fails ("no base"), instead of an empty ref falling back to the head. Never a ref NAME as the sentinel: anyone with push
 * access can create a branch with that name. Only the job `base-scan` may use it (job-rules.ts).
 */
export const BASE_CHECKOUT_REF = `\${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event_name == 'merge_group' && github.event.merge_group.base_sha || github.event_name == 'push' && github.event.before || '${'0'.repeat(40)}' }}`;

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
  // the base commit, for the base-scan job only (the job rule is in job-rules.ts); no other ref is ever set
  'actions/checkout': { ref: { describe: 'the event-switched base commit (BASE_CHECKOUT_REF) and nothing else', check: (v) => v === BASE_CHECKOUT_REF } },
  'actions/upload-artifact': { name: ARTIFACT_NAME, path: OWN_FOLDER_PATH },
  'actions/download-artifact': { name: ARTIFACT_NAME, path: OWN_FOLDER_PATH },
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
  // pipegen's own gate action. Every input is the renderer's (the entry fixes none and offers no choice); each mode has its
  // own inputs, checked with `whenWith` on `mode`, so a mode's input is refused under another mode (Plan C rulings B1 and B3).
  [PIPEGEN_GATE_USES]: {
    mode: rx(new RegExp(`^(?:${GATE_MODES.join('|')})$`), `one of ${GATE_MODES.join(', ')}`),
    // scrub (ruling B1)
    artifact: inScrubMode(ARTIFACT_NAME),
    tool: inScrubMode(rx(/^[a-z0-9][a-z0-9-]{0,63}$/, 'a reviewed tool id')),
    format: inScrubMode(rx(/^(?:sarif|zap-json)$/, 'sarif or zap-json')),
    raw: SCRUB_RAW,
    out: SCRUB_OUT,
    // the fingerprint key: the scrub hashes with it, the gate checks the baseline's MAC with it (ruling B6)
    'fp-key': modeInput(['scrub', 'gate'], /^\$\{\{ secrets\.PIPEGEN_FP_KEY \}\}$/, '${{ secrets.PIPEGEN_FP_KEY }}'),
    // gate (ruling B3)
    jobs: modeInput(['gate'], /^\$\{\{ toJSON\(needs\) \}\}$/, '${{ toJSON(needs) }}'),
    'job-list': literalInput(['gate'], jobListLiteralProblem, 'a job list literal (a JSON list of entries)'),
    'not-proven': literalInput(['gate'], idListProblem, 'a JSON list of need ids'),
    skipped: literalInput(['gate'], idListProblem, 'a JSON list of need ids'),
    policy: literalInput(['gate'], policyProblem, 'a JSON policy { "block": [...], "warn": [...] }'),
    'protected-paths': literalInput(['gate'], pathListProblem, 'a JSON list of plain relative path globs'),
    // gate and nightly
    'block-from': modeInput(['gate', 'nightly'], /^\$\{\{ vars\.PIPEGEN_BLOCK_FROM \}\}$/, '${{ vars.PIPEGEN_BLOCK_FROM }}'),
    'block-from-recorded': modeInput(['gate', 'nightly'], DATE_TEXT_RE, 'a date YYYY-MM-DD'),
    // gate, find-run and nightly: the workflow token, nothing else
    'github-token': modeInput(['gate', 'find-run', 'nightly'], /^\$\{\{ secrets\.GITHUB_TOKEN \}\}$/, '${{ secrets.GITHUB_TOKEN }}'),
    // find-run
    sha: modeInput(['find-run'], /^\$\{\{ (?:github\.sha|github\.event\.workflow_run\.head_sha) \}\}$/, '${{ github.sha }} or ${{ github.event.workflow_run.head_sha }}'),
    'central-workflow': modeInput(['find-run'], PLAIN_REL_RE, 'a plain relative path of the central workflow'),
    'central-sha': modeInput(['find-run'], /^[0-9a-f]{40}$/, 'a 40-character commit'),
    // nightly
    'merged-at': modeInput(['nightly'], /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z)?$/, 'a date or an ISO time in UTC'),
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

/**
 * Actions whose action.yml runs a docker image (`runs.using: docker`), by `uses` path (ruling S13). Their reviewed entry
 * must record the image in `wrappedImage` (the loader checks it), and a render runs them only when that image is pinned
 * by digest. scorecard-action's is by tag today, so it stays refused.
 */
export const DOCKER_ACTION_USES: ReadonlySet<string> = new Set(['ossf/scorecard-action']);
/** Actions that build an image from a Dockerfile at run time (a composite that generates one): what runs can not be pinned, so they are refused. */
export const IMAGE_BUILT_ACTION_USES: ReadonlySet<string> = new Set(['pypa/gh-action-pypi-publish']);
