// ---------- project ----------
export type Language = 'node' | 'python' | 'go' | 'java' | 'dotnet' | 'ruby' | 'php' | 'other';
export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'pip' | 'poetry' | 'uv' | 'other';
export type Monorepo = 'none' | 'npm-workspaces' | 'pnpm-workspaces' | 'yarn-workspaces' | 'turbo' | 'nx' | 'folders';
export type DependencyKind = 'postgres' | 'mysql' | 'redis' | 'mongodb' | 'rabbitmq' | 'external';

export interface Dependency { kind: DependencyKind; name: string; evidence: string; envVars: string[] }   // external = SaaS (Stripe, Auth0…)
export interface Service {
  name: string; path: string; language: Language; packageManager?: PackageManager; runtimeVersion?: string;
  dockerfile?: string; port?: number; hasTests: boolean; testFramework?: string;
  envVars: string[]; dependsOn: Dependency[];
  scripts: string[];      // script names from package.json `scripts` / pyproject `[project.scripts]` + `[tool.poetry.scripts]` (names only, never the commands)
  frameworks: string[];   // detected server frameworks: express, fastify, @nestjs/core, next, koa, hapi; flask, fastapi, django. Used by isRunnable (Plan B Task 1)
}
export interface ExistingWorkflow { path: string; triggers: string[]; deploys: boolean; secretsUsed: string[]; jobs: string[] }
export type Plan = 'free' | 'pro' | 'team' | 'enterprise' | 'unknown';
export interface RepoProfile {
  owner: string; repo: string; defaultBranch: string; private: boolean;
  ownerType: 'User' | 'Organization'; plan: Plan;
  monorepo: Monorepo; services: Service[]; terraformDirs: string[]; hasCompose: boolean;
  existingWorkflows: ExistingWorkflow[]; precommit: 'pre-commit' | 'husky' | 'lefthook' | null;
}
// ---------- GitHub access (moved here from Plan A Task 6 in round 4: Plan U uses it too) ----------
export interface Auth {
  token: string | null;   // null only when kind is 'anonymous'. Sent only to https://api.github.com, never printed
  kind: 'app' | 'fine-grained' | 'classic' | 'anonymous';   // anonymous = public repo, no token (read mode only, rate-limited)
  repos: string[] | 'all'; canCreateRepos: boolean; canDeleteRepos: boolean;
}
export interface Capabilities {            // what GitHub allows for this repo + plan
  branchProtection: boolean; environments: boolean; envRequiredReviewers: boolean;
  attestations: boolean; codeScanning: boolean; keylessSigningAllowed: boolean;   // false for private repos (no public logs)
}

// ---------- needs, tools, steps ----------
export type Layer = 'pre-commit' | 'push' | 'merge' | 'deploy';
export const NEED_CATEGORIES = ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'lint', 'format-lint', 'hooks', 'hooks-ci', 'image-build', 'image-scan', 'dast', 'iac', 'sbom', 'signing', 'attestation', 'deploy-verify', 'gate'] as const;
export type NeedCategory = typeof NEED_CATEGORIES[number];   // every Need.category is one of these; AI schemas use NEED_CATEGORIES as the enum
export interface Need { id: string; layer: Layer; category: string; service?: string; why: string; blocking: boolean; floor: boolean }  // floor = security floor, AI can't remove
export interface ToolStats { repo: string; stars: number; archived: boolean; lastReleaseAt: string | null; scorecard: number | null; verifiedPublisher: boolean; license: string | null; advisories: number }
export interface Candidate {
  id: string; name: string; kind: 'action' | 'cli' | 'docker';
  repo: string; version: string; pin: { sha?: string; checksum?: string; digest?: string };
  source: 'reviewed' | 'discovery' | 'memory'; reviewed: boolean;   // only reviewed tools may block
  stats?: ToolStats; categories: string[];
}
export type OutputFormat = 'sarif' | 'junit' | 'zap-json' | 'none';   // zap-json is converted by pipegen's parser
export interface InstallSpec { method: 'npm' | 'pip' | 'github-release' | 'docker'; package: string; version: string; checksum?: string; digest?: string }
export interface StepSpec {
  needId: string; tool: Candidate;
  action?: { uses: string; with: Record<string, string> };
  cli?: { install: InstallSpec; command: string[]; env?: Record<string, string> };
  output: { path: string; format: OutputFormat };
  workingDir?: string; needsServices?: DependencyKind[]; secrets?: string[];   // names only, never values
}

// ---------- created files, decisions ----------
export type Part = 'pipeline' | 'precommit' | 'docker' | 'compose' | 'tests' | 'test-migration' | 'codeowners' | 'deploy-verify' | 'docs';
export interface CreatedFile { path: string; content: string; part: Part; reason: string; repo: 'app' | 'central'; needsConfirm?: boolean }   // needsConfirm: AI change to package.json scripts/dependencies → own preview section + own yes (Plan D Task 5, Plan E Task 5, Plan G)
export interface NotProven { part: Part; needId?: string; reason: string; missingSecrets: string[] }
export interface TestDecision { service: string; current?: string; proposed?: string; reasons: string[]; choice: 'keep' | 'switch' | 'none' }
export interface PipelineDraft {
  profile: RepoProfile; capabilities: Capabilities; needs: Need[]; steps: StepSpec[];
  created: CreatedFile[]; notProven: NotProven[]; testDecisions: TestDecision[];
  layersSkipped: { layer: Layer; reason: string }[]; scoreboard: string[];
  requireDeployApproval: boolean;   // set by the judge (Plan F); used by Plan G environments
  skipped: { part: SkippablePart; reason: string }[];   // from --skip
  suggestions: { name: string; repo: string; why: string }[];   // unreviewed tools: MENTION-ONLY in PIPEGEN.md, never run
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
export interface AiRequest { system: string; user: string; schemaName: string; jsonSchema: object; timeoutMs: number }
export interface AiUsage { inputTokens: number; outputTokens: number; cacheReadTokens?: number; cacheWriteTokens?: number }
export interface AiProvider { name: 'claude' | 'openai' | 'ollama'; model: string; complete(req: AiRequest): Promise<{ data: unknown; usage: AiUsage }> }   // usage feeds the AI cost meter (Plan E)

// ---------- reviewed tools (moved here from Plan B Task 8 in round 3: Plan B Task 4 needs it earlier) ----------
// Loaded from data/reviewed-tools.yml by Plan B Task 8 (`loadReviewed`). Only these tools ever run in a user's CI.
export interface ReviewedTool {
  id: string; categories: string[]; languages: (Language | 'any')[];
  candidate: Candidate;                                    // pinned exactly; reviewed: true
  step: Omit<StepSpec, 'needId' | 'tool'>;                 // the reviewed step template
  fixedInputs: {                                           // security-relevant inputs, set by the template; the AI can never change them
    with?: Record<string, string>; args?: string[]; env?: Record<string, string>;
    config?: { content: string; passAs: { flag: string } | { input: string } };   // explicit pinned config, so repo config files are never picked up silently
  };
  choices: Record<string, string[]>;                       // the only inputs the AI may set, each limited to these enum values
  configFiles: string[];                                   // config/ignore files the tool auto-loads from a repo (e.g. '.gitleaks.toml', '.trivyignore'); added to the protected paths
  reviewedBy: string; reviewedAt: string; proofs: number;  // proofs = passed Plan E runs; full runs need proofs >= 1
}
