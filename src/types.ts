// Identifier rule for RepoProfile (and every type built from a repo): data is kept RAW but VALIDATED; it is
// cleaned only at output.
// - A reader keeps a repo-derived identifier exactly as found when it passes its pattern, and otherwise drops it
//   (with a note when it was a whole file) or replaces it with a safe fallback. It never stores a cleaned copy:
//   cleaning changes the value, so a later lookup or comparison with the raw repo would no longer match.
//   Patterns: workflow paths must be unchanged by safeText (else the file is skipped with a note); job ids
//   /^[A-Za-z_][A-Za-z0-9_-]*$/; triggers /^[a-z_]+$/; secret and env var names /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
//   Service.name /^[A-Za-z0-9._@/-]{1,214}$/, else the folder name (same pattern), else 'app'.
// - Every value is cleaned where it leaves pipegen: safeText() for the terminal, safeMarkdown() for Markdown.
//   Fields not validated at read time (Service.path, runtimeVersion, dockerfile, Dependency.evidence) must always
//   go through those at output. Service.name may contain '.', '..' and '/': never use it as a path component unchecked.
// ---------- project ----------
export type Language = 'node' | 'python' | 'go' | 'java' | 'dotnet' | 'ruby' | 'php' | 'other';
export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'pip' | 'poetry' | 'uv' | 'other';
export type Monorepo = 'none' | 'npm-workspaces' | 'pnpm-workspaces' | 'yarn-workspaces' | 'turbo' | 'nx' | 'folders';
export const DEPENDENCY_KINDS = ['postgres', 'mysql', 'redis', 'mongodb', 'rabbitmq', 'external'] as const;
export type DependencyKind = typeof DEPENDENCY_KINDS[number];

export interface Dependency { kind: DependencyKind; name: string; evidence: string; envVars: string[] }   // external = SaaS (Stripe, Auth0…)
/** P55 (batch B): a one-shot script, a folder built into another service's image, or an email-template package. */
export type NotStandalone = 'one-shot' | 'built-in-image' | 'email-templates';
export interface Service {
  name: string; path: string; language: Language; packageManager?: PackageManager; runtimeVersion?: string;
  /** P60 (R4): other languages the folder also holds (a Python app with a package.json for its asset build): tools of these cover it too. Set only when not empty. */
  alsoLanguages?: Language[];
  dockerfile?: string; port?: number; hasTests: boolean; testFramework?: string;
  envVars: string[]; dependsOn: Dependency[];
  scripts: string[];      // script names from package.json `scripts` / pyproject `[project.scripts]` + `[tool.poetry.scripts]` (names only, never the commands)
  frameworks: string[];   // detected server frameworks: express, fastify, @nestjs/core, next, koa, hapi; flask, fastapi, django (never the service's own package name: the express repo doesn't USE express). Used by isRunnable (Plan B Task 1)
  notStandalone?: NotStandalone;   // P55 (batch B): why this folder isn't a service of its own although it has a start or dev script (src/read/service-kind.ts). isRunnable is then false. Set only when true
  publishedPackage?: boolean;   // Plan U Task 5: the repo's only service, and a workflow publishes it to its registry (npm for node, PyPI for python). Set only when true. isRunnable then ignores a port found in its code (a library's default port isn't a server)
  quality: ServiceQuality;      // Plan P Task 1 (src/read/quality.ts): the facts the quality and supply-chain checks read. Always set; emptyServiceQuality() when nothing is known
}
// Plan P Task 1. Ruling PS5 left out what no task reads: QualityPackage 'jscpd', QualityConfig 'jscpd'/'hadolint', RepoFiles.rego.
export type UiFramework = 'next' | 'nuxt' | 'vue' | 'svelte' | 'astro' | 'react-native';
export type QualityPackage = 'typescript' | 'eslint' | 'prettier' | '@biomejs/biome' | 'oxlint' | 'vitest' | 'jest' | 'c8' | 'knip' | 'vue-tsc' | 'svelte-check' | '@astrojs/check' | 'xo';
export type QualityConfig = 'xo' | 'biome' | 'prettier' | 'knip' | 'oxlint' | 'ruff' | 'black' | 'flake8' | 'pylint' | 'mypy' | 'pyright' | 'basedpyright';
export interface ServiceQuality {
  tsconfig: boolean; versions: Partial<Record<QualityPackage, string>>; fromRange: QualityPackage[];   // versions: each matches /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]{1,40})?$/. fromRange: version from a package.json range (its lower bound), not the lockfile
  eslintConfig: 'flat' | 'eslintrc' | 'both' | 'none'; configs: QualityConfig[]; uiFrameworks: UiFramework[];
  pythonTyped: boolean; fuzzTargets: boolean;
  apiSpec: { kind: 'file'; path: string } | { kind: 'served'; by: 'fastapi' | '@nestjs/swagger' } | null;   // path: repo-relative, raw (unchanged by safeText, else not kept); clean it at output
}
export interface RepoFiles {
  dependabot: string | null; renovate: string | null; actionsLock: boolean; kubernetes: boolean;   // dependabot, renovate: the repo-relative path of the config file found ('package.json' for its `renovate` key)
  licenceConfig: 'deny.toml' | '.grant.yaml' | '.fossa.yml' | null; secretsBaseline: boolean;
}
export interface ExistingWorkflow {
  path: string; triggers: string[]; deploys: boolean; secretsUsed: string[]; jobs: string[];
  tagPinned?: number;   // Task 9 (PS36): how many `uses:` lines (steps and called workflows) point at an action by tag or branch, not by a 40-character commit. Absent = none
  usesUnchecked?: true;   // Task 9: a `uses:` line was too odd to check (regexSafe), so tagPinned may be too low
  publishes?: ('npm' | 'pypi')[];   // Plan U Task 5: registries a step publishes to (a run line that starts with a publish command, or the PyPI publish action). Absent = none
}
export type Plan = 'free' | 'pro' | 'team' | 'enterprise' | 'unknown';
export type OtherHookManager = 'simple-git-hooks' | 'githooks' | 'husky-v4' | 'yorkie' | 'pre-commit-npm' | 'overcommit' | 'linked-config';
export interface RepoProfile {
  owner: string; repo: string; defaultBranch: string; private: boolean;
  ownerType: 'User' | 'Organization'; plan: Plan;
  monorepo: Monorepo; services: Service[]; terraformDirs: string[]; hasCompose: boolean;
  existingWorkflows: ExistingWorkflow[]; precommit: 'pre-commit' | 'husky' | 'lefthook' | null;
  repoFiles: RepoFiles;   // Plan P Task 1: repo-level config files, read once
  /** Plan B 6d (DECISIONS #108): folders pipegen itself detected as vendored or generated (node_modules, vendor, dist, target, .next, .venv, or a folder named generated or __generated__), repo-relative and plain, sorted. Never a service folder, and never a folder that holds one. Per-repo tuning may skip them for lint and SAST only. Absent when none */
  generatedDirs?: string[];
  /** Plan B 6d fix rounds 1 and 2: hook managers other than the three `precommit` names (simple-git-hooks: a config file or a package.json key; githooks: a .githooks folder or core.hooksPath in .git/config; husky-v4: a `husky` key or a .huskyrc/husky.config file; yorkie: a `gitHooks` key; pre-commit-npm: the npm `pre-commit` package as a key or a dependency; overcommit: .overcommit.yml; linked-config: a symbolic link at the name of any hook manager's config, never followed). Per-repo tuning offers generated lefthook hooks only when `precommit` is null and this is absent. Absent when none */
  otherHookManagers?: OtherHookManager[];
}
// ---------- GitHub access (moved here from Plan A Task 6 in round 4: Plan U uses it too) ----------
export interface Auth {
  token: string | null;   // null only when kind is 'anonymous'. Sent only to https://api.github.com, never printed
  kind: 'app' | 'fine-grained' | 'classic' | 'installation' | 'anonymous';   // anonymous = public repo, no token (read mode only, rate-limited); installation = an Actions GITHUB_TOKEN (ghs_), read mode only
  repos: string[] | 'all'; canCreateRepos: boolean; canDeleteRepos: boolean;
}
export interface Capabilities {            // what GitHub allows for this repo + plan
  branchProtection: boolean; environments: boolean; envRequiredReviewers: boolean;
  deploymentBranchPolicies: boolean;   // the `pipegen-signing` environment is PROVEN (read back) to allow only the default branch; key-env signing needs it
  attestations: boolean; codeScanning: boolean; keylessSigningAllowed: boolean;   // false for private repos (no public logs)
}

// ---------- needs, tools, steps ----------
export type Layer = 'pre-commit' | 'push' | 'merge' | 'deploy';
export const NEED_CATEGORIES = ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'lint', 'format-lint', 'hooks', 'hooks-ci', 'image-build', 'image-scan', 'dast', 'iac', 'sbom', 'signing', 'attestation', 'deploy-verify', 'gate',
  // Plan P Task 2 (table in src/engine/needs.ts): quality, supply-chain and scheduled checks
  'format', 'type-check', 'coverage', 'dead-code', 'duplication', 'dockerfile-lint', 'workflow-lint', 'workflow-pin-check', 'dependency-review', 'licences', 'api-dast', 'publishing', 'egress', 'update-config', 'scorecard', 'fuzzing'] as const;
export type NeedCategory = typeof NEED_CATEGORIES[number];   // every Need.category is one of these; AI schemas use NEED_CATEGORIES as the enum
export interface Need { id: string; layer: Layer; category: string; service?: string; why: string; blocking: boolean; floor: boolean }  // floor = security floor, AI can't remove
export interface ToolStats { repo: string; stars: number; archived: boolean; lastReleaseAt: string | null; scorecard: number | null; scorecardAt: string | null; verifiedPublisher: boolean; license: string | null; advisories: number | null }   // advisories: known advisories for the version in question; null = the version couldn't be resolved or checked (the quality bar fails closed). scorecardAt: date of the Scorecard result (null = unknown; a stale or unknown date never counts as a strong score). verifiedPublisher: owner is a GitHub-verified Organization
export interface Candidate {
  id: string; name: string; kind: 'action' | 'cli' | 'docker';
  repo: string; version: string; pin: { sha?: string; checksum?: string; digest?: string };
  source: 'reviewed' | 'discovery' | 'memory'; reviewed: boolean;   // only reviewed tools may block
  stats?: ToolStats; categories: string[];
}
/** A candidate that comes from the reviewed list. The only kind a step may carry (B1): a discovery or memory Candidate does not fit. */
export type ReviewedCandidate = Candidate & { source: 'reviewed'; reviewed: true };
export type OutputFormat = 'sarif' | 'junit' | 'zap-json' | 'none';   // zap-json is converted by pipegen's parser
export interface InstallSpec { method: 'npm' | 'pip' | 'github-release' | 'docker'; package: string; version: string; checksum?: string; digest?: string }
/**
 * Per-repo tuning picks (Plan B 6d, DECISIONS #84 and #108): tuning option id → the values chosen, each from the enum the
 * renderer builds for that call from the profile (src/engine/tuning.ts). Enum values only, never free text.
 */
export type TuningPicks = Record<string, string[]>;
/** `StepSpec.choices`: the tool's own choices (name → one listed value) and, under `tuning`, the per-repo tuning picks. */
export interface StepChoices { [name: string]: string | TuningPicks | undefined; tuning?: TuningPicks }
export interface StepSpec {
  needId: string; service?: string;   // service: the Service.name the step is for (absent for repo-wide needs)
  tool: ReviewedCandidate;            // only a reviewed entry's candidate; renderStep checks it equals the entry it is given
  choices: StepChoices;               // the AI's picks among the entry's `choices` (Plan F fills them); a missing one takes the first listed value. `tuning` (6d) holds the per-repo tuning picks, enum values only
  // action/cli/output are copies of the reviewed template (memory or the AI may send them back): when present they must
  // deep-equal the template, and nothing renders from them. Rendering uses tool.step + tool.fixedInputs + choices only.
  action?: { uses: string; with: Record<string, string> };
  cli?: { install: InstallSpec; plugins?: InstallSpec[]; command: string[]; then?: string[][]; env?: Record<string, string> };   // plugins (Plan P Task 5): npm or pip packages installed next to the tool, each an exact version with its checksum; at most 4. then (Task 6, P24): follow-up commands of the same tool. The one rendering rule for choices (review M-R1): a `{name}` word in command/then is replaced by the chosen value of choice `name`, and `name` is the flag it fills with dots as dashes (`--fail-under={fail-under}`, `--coverage.thresholds.lines={coverage-thresholds-lines}`); dedicated tools (trivy, betterleaks, nuclei) instead get `--<choice> <value>` appended, and a bool choice (one whose values are exactly `false` and `true`) is written `--<choice>=<value>` (review M8, 6b: `--ignore-unfixed=true`, never a bare flag that a later word could swallow). The renderer never writes a chosen value into the shell text: it goes in a step env variable `PIPEGEN_ARG_<n>` and is quoted as `"$PIPEGEN_ARG_<n>"` (also inside a word, `--fail-under="$PIPEGEN_ARG_0"`); action choices are `with:` inputs
  output: { path: string; format: OutputFormat };
  workingDir?: string; needsServices?: DependencyKind[]; secrets?: string[];   // names only, never values
}

// ---------- created files, decisions ----------
export type Part = 'pipeline' | 'precommit' | 'docker' | 'compose' | 'tests' | 'test-migration' | 'codeowners' | 'deploy-verify' | 'docs';
export interface CreatedFile { path: string; content: string; part: Part; reason: string; repo: 'app' | 'central'; needsConfirm?: boolean; inserted?: PipegenInserted }   // needsConfirm: AI change to package.json scripts/dependencies → own preview section + own yes (Plan D Task 5, Plan E Task 5, Plan G)
/**
 * The marker convention for an edited user workflow (Plan B 7a, for Plan G's insertVerify): a CreatedFile field, set by
 * pipegen's own code and never by the AI or read from the file text, so no content can forge it. `original` is the user's
 * file exactly as it was before the edit; `jobs` are the jobs pipegen added (the referee judges them like any job of its
 * own); `needs` are the entries pipegen added to the user's own jobs. The referee checks that the edited file, without
 * those jobs and needs entries, is the original (anything else pipegen changed is an issue), and judges nothing else of
 * the user's. Linter findings on lines outside the added jobs and needs become notes (referee.ts `pipegenLines`).
 * A file without this field was written by pipegen whole, and every line is judged.
 */
export interface PipegenInserted { original: string; jobs: string[]; needs: { job: string; added: string[] }[] }
export interface NotProven { part: Part; needId?: string; reason: string; missingSecrets: string[] }
export interface TestDecision { service: string; current?: string; proposed?: string; reasons: string[]; choice: 'keep' | 'switch' | 'none' }
export interface PipelineDraft {
  profile: RepoProfile; capabilities: Capabilities; needs: Need[]; steps: StepSpec[];
  created: CreatedFile[]; notProven: NotProven[]; testDecisions: TestDecision[];
  layersSkipped: { layer: Layer; reason: string }[]; scoreboard: string[];
  requireDeployApproval: boolean;   // set by the judge (Plan F); used by Plan G environments
  skipped: { part: SkippablePart; reason: string }[];   // from --skip
  suggestions: { name: string; repo: string; why: string }[];   // unreviewed tools: MENTION-ONLY in PIPEGEN.md, never run
  centralPin?: { repo: string; sha: string };   // Plan B 7a fix round 1 (ruling 2): the central `<owner>/pipelines` repo and the commit pipegen itself resolved and wrote; the referee accepts a central `uses` only at this SHA (none recorded: every central `uses` is unknown-pin). Plan G fills it
}

// ---------- install record (written by Plan G deliver/finish, read by Plan V and `pipegen verify`) ----------
export type EditKind = 'verify-job' | 'hooks' | 'codeowners' | 'dependabot' | 'package-json';
export interface InstallRecord {
  pipegenVersion: string; cosignPubSha256?: string; blockFrom?: string;
  planned: { ruleset?: object; centralRuleset?: object; environments: { name: string; reviewers: boolean }[]; codeOwners: string[] };   // persisted so `finish` can run later
  repo: string; createdAt: string; mergedAt?: string; centralSha: string;
  files: { path: string; part: Part; sha: string; created: boolean }[];          // sha = blob sha at delivery
  edits: { path: string; kind: EditKind; inserted: string; anchor: string }[];   // exact text pipegen inserted, for precise revert
  secrets: { name: string; scope: 'repo' | 'central' | `env:${string}`; created: boolean }[];
  environments: { name: string; created: boolean; previous?: object }[];         // previous settings restored on uninstall
  variables: string[]; rulesetId?: number; classicProtection?: boolean; orgRequiredWorkflowId?: number;
  central?: { rulesetId?: number; codeowners?: { path: string; created: boolean } };   // central-repo locks (set by Plan G `finish` in every project's record, whether it created them or found pipegen's own); Plan V removes them when no project remains
  protectedPaths: string[];                                                      // used by the gate's integrity rule and `pipegen verify`
}

// ---------- constants ----------
export const GATE_CHECK_NAME = 'pipegen / gate';
export const GATE_CHECK_INTEGRATION_ID = 15368;   // GitHub Actions app id — spike S2 confirms; rulesets bind the required check to it   // caller job `name: pipegen` → job `name: gate`. Spike S2 confirms or changes this ONE constant; every plan uses it.
export const RESULT_ARTIFACT_PREFIX = 'pipegen-out-';          // read by the gate (exact names only)
export const DEFAULT_MODEL = 'claude-opus-5-5';               // user may override with --model
export const FLOOR_NEEDS = ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'gate'];   // can never be NOT-PROVEN. secrets + gate can never be skipped; tests may only be skipped explicitly with --skip tests (recorded)
export const PROTECTED_PATHS_BASE = ['.github/workflows/**', '.github/CODEOWNERS', 'CODEOWNERS', '.pre-commit-config.yaml', '.husky/**', 'lefthook.yml', 'docker-compose.pipegen.yml', '.gitleaksignore', '.semgrepignore', '.trivyignore', '.zap/**', '.github/actions/**', 'docs/CODEOWNERS', '.github/dependabot.yml'];
// Effective protected paths = PROTECTED_PATHS_BASE + every config/ignore file declared by the reviewed tools in use (ReviewedTool.configFiles)
export type SkippablePart = 'tests' | 'precommit' | 'docker' | 'compose' | 'deploy' | 'locks' | 'slack' | 'test-migration';   // never: secrets scan, gate
export type SupportLevel = 'full' | 'audit-only';

// ---------- results ----------
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface Finding { tool: string; ruleId: string; severity: Severity; file?: string; line?: number; message: string; fingerprint: string }
export interface PartResult { part: Part; needId?: string; status: 'proven' | 'failed' | 'not-proven'; detail: string; logsUrl?: string }
export interface ProofResult { ok: boolean; parts: PartResult[]; findings: Finding[]; minutesUsed: number; runUrls: string[] }

// ---------- AI ----------
export interface AiRequest { system: string; user: string; schemaName: string; jsonSchema: object; timeoutMs: number; maxOutputTokens?: number }   // maxOutputTokens: the most output (thinking included) the provider may produce; Claude's CLAUDE_MAX_TOKENS when unset
export interface AiUsage { inputTokens: number; outputTokens: number; cacheReadTokens?: number; cacheWriteTokens?: number }
export interface AiProvider { name: 'claude' | 'openai' | 'ollama'; model: string; complete(req: AiRequest): Promise<{ data: unknown; usage: AiUsage }> }   // usage feeds the AI cost meter (Plan E)

// ---------- reviewed tools (moved here from Plan B Task 8 in round 3: Plan B Task 4 needs it earlier) ----------
// Loaded from data/reviewed-tools.yml by Plan B Task 8 (`loadReviewed`). Only these tools ever run in a user's CI.
export interface ReviewedTool {
  id: string; categories: string[]; languages: (Language | 'any')[];
  candidate: ReviewedCandidate;                            // pinned exactly; reviewed: true
  step: Omit<StepSpec, 'needId' | 'service' | 'tool' | 'choices'>;   // the reviewed step template
  fixedInputs: {                                           // security-relevant inputs, set by the template; the AI can never change them
    with?: Record<string, string>; args?: string[]; env?: Record<string, string>;
    config?: { content: string; passAs: { flag: string } | { input: string } };   // explicit pinned config, so repo config files are never picked up silently
  };
  choices: Record<string, string[]>;                       // the only inputs the AI may set, each limited to these enum values
  configFiles: string[];                                   // config/ignore files the tool auto-loads from a repo (e.g. '.gitleaks.toml', '.trivyignore'); added to the protected paths
  configSections?: string[];                               // Plan P Task 6 (P23): '<file>:<section>' of shared files the tool reads (e.g. 'pyproject.toml:tool.mypy'); the v0.2 gate protects them. Matching (review M-R5): <file> is a repo-relative path or glob (as configFiles); <section> is the dotted table path (TOML), the INI section name or the top-level JSON key, where `*` matches any run of characters (`setup.cfg:mypy-*`, `setup.cfg:coverage:*`); a change inside a matching section, or to the section itself, counts
  wrappedImage?: { ref: string; digest: string };          // Plan P Task 6 (P26): the image an action's action.yml runs, and the digest that ref resolved to when pinned
  reviewedBy: string; reviewedAt: string; proofs: number;  // proofs = passed Plan E runs; full runs need proofs >= 1
  verifiedWith?: VerifiedWith;                             // Plan P Task 5: the signature or attestation check made when pinning (required for MUST_VERIFY repos)
}
// How a pinned release was verified when it was pinned (Plan P Task 5, ruling PS24, fix round 1). Keyless: identity is
// the exact certificate identity, the entry's own repo's workflow at the entry's version tag (never a regex or a
// branch); asset names the file whose signature was checked (e.g. checksums.txt). cosign-key (P10): a public key file
// in the entry's own repo at its version tag, with its sha256. verifiedOn: YYYY-MM-DD, not before the release or the
// list's pinnedOn day, not in the future.
export type VerifiedWith =
  | { method: 'cosign-bundle' | 'cosign-signature' | 'github-attestation'; asset: string; identity: string; issuer: 'https://token.actions.githubusercontent.com'; verifiedOn: string }
  | { kind: 'cosign-key'; keyUrl: string; keySha256: string; verifiedOn: string };
