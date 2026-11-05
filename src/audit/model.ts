// The audit model (Plan U Task 2a): everything `pipegen audit` reports, built without changing anything and without
// any AI call. Task 3 renders it; Task 4 is the CLI; Task 2b (`addAiSuggestions`) fills `ai` after consent.
//
// What it holds (controller rulings B1, B3, S7-S12, S27, S29, S30 and the Plan U carry-forwards):
// - profile: readProject(dir) re-read here, with the caller's GitHub context laid over it (B1).
// - coverage: mapCoverage over the floor needs, told how many workflow files readWorkflows skipped. When pipegen's
//   tool signatures can't be loaded, every row is `unknown` with a plain note: never a false `missing`, never a crash.
// - wouldAdd: one row per floor need that isn't covered (S7): gate and deploy-verify are pipegen's own checks; else the
//   service's own test/lint script; else the first reviewed tool; else nothing ("suggestion only", or "reviewed list
//   unavailable" when the caller couldn't use the list, B3). A service without tests says pipegen would create
//   starter tests (S27); with no service at all, `testsNote` says so instead of showing a gap.
// - estimates: the full run's cost for DEFAULT_MODEL, from jobCategories(floorNeeds) and the last 30 days of activity
//   (0 with a basis line when GitHub won't say).
// - limits: from the capabilities and the signing mode only, never the plan name, never "make the repo public" (S9).
// - secretsInTree: a local scan of the files on disk (no git, no child process, symlinks never followed), rule names
//   and file names only, never a value (S10).
// - aiBundle: what the full run would send to the AI, counted from bundleCode without the secret scan (counting only).
// - warnings: a repo `.npmrc` with any key outside a small safe list (U12; Task 5 adds keys whose value only makes npm
//   stricter) or a local node_modules/.bin/pipegen could change which pipegen runs (the `.npmrc` is read for that one
//   fact; no value is kept), or a committed node_modules (swapRisk, Plan J J5); anonymous access.
// - ai (Task 2b, addAiSuggestions, `audit --ai` after consent): the needs the AI adds and MENTION-ONLY tool suggestions,
//   from a secret-scanned bundle, with the run's AI usage and cost cap (rulings B2, B3, B4, S11, S16-S19, U11).
//
// Output rule (src/types.ts): repo-derived strings are kept RAW (validated by the readers) and cleaned only where
// Task 3 prints them. Nothing here escapes a value, and no file content or secret value is ever stored.
import { lstat, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { count, outputLimit } from '../ai/errors.js';
import { ollamaHostOf } from '../ai/ollama.js';
import { AiError, COST_CAP_MESSAGE, refusalFallbackNoteFor, type AiErrorKind } from '../ai/provider.js';
import { AiSpendMeter, type AiAttempt } from '../ai/spend-meter.js';
import {
  bundleCode, bundleTopFolders, COUNTING_ONLY_NOTE, countedBundleRoot, EXCLUDED_PATTERNS, findSecretLike, isExcludedPath, redact, SECRET_SCANNER_ENV, SecretScanError, type SecretScanner, type SecretScannerName,
  HIDDEN_NAME, scrubKnownValues, type CodeBundle, type ScanFound,
} from '../ai/redact.js';
import { needLanguage, suggestTools } from '../engine/discover.js';
import { isRateStop, rateStopOf, resetText, type RateBudget } from '../engine/github-rate.js';
import { ensurePinnedBinary, loadPinnedBinaries, PinnedBinaryError } from '../engine/linters.js';
import type { MemoryStore } from '../engine/memory.js';
import { CHECK_LABELS, floorNeeds, isRunnable, jobCategories, needKey, needsPromptBytes, planNeeds, type NeedsPlan } from '../engine/needs.js';
import type { QualityBar } from '../engine/quality-bar.js';
import { projectScriptFor, type WouldAddTool } from '../engine/reviewed.js';
import {
  activity30d, aiRequestBytes, estimate, requestCeilingUsd, unpricedModel, usageCeilingUsd, usageCostUsd, type Activity, type Estimates,
} from '../estimate/estimate.js';
import { readOnlyTokenHint } from '../github/client.js';
import { readDefaultSetup, type DefaultSetup } from '../github/code-scanning-setup.js';
import { lastCompletedRun } from '../github/workflow-runs.js';
import { signingMode } from '../github/signing-mode.js';
import { readHeadCommit, type HeadCommit } from '../read/git-head.js';
import { readGitIndexPaths } from '../read/git-index.js';
import { loadIgnore } from '../read/gitignore.js';
import { IGNORED_DIRS, listFiles, READ_LIMITS, readTextLimited, readTextLimitedWithReason } from '../read/limits.js';
import { readProject } from '../read/project.js';
import { applyTypeOverrides, type TypeOverride } from '../read/project-type.js';
import { supportLevel } from '../read/support.js';
import { skippedWorkflowCount } from '../read/workflows.js';
import {
  DEFAULT_MODEL, type AiProvider, type AiTokenCounts, type Capabilities, type Need, type Part, type PipelineDraft, type RepoProfile,
  type ReviewedTool, type Service,
  type NeedCategory,
} from '../types.js';
import { usd } from '../util/format.js';
import { packageVersion } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { ConsentToken, CountingSummary, isSpent, spend } from './consent-token.js';
import { chooseTools, skippedGroups, wouldSetSettings, type SkippedGroup, type WouldSet } from './choose.js';
import { mapCoverage, type Coverage } from './coverage.js';
import { applyDefaultSetup, applyLastRuns, coveringWorkflow, type RunAnswer } from './github-signals.js';

// ---------- types ----------

/** The milestone this build belongs to; keys the "what's next" table (ruling S8). */
export const CURRENT_MILESTONE = 'v0.1' as const;
export type Milestone = typeof CURRENT_MILESTONE;

// Plan P Task 8: the type lives in engine/reviewed.ts (the chooser needs it); re-exported so importers don't change.
export type { BuiltInCheck, WouldAddTool } from '../engine/reviewed.js';
export interface WouldAddRow {
  need: Need;
  /** The need's coverage status (never `covered`: covered needs get no row). */
  status: Exclude<Coverage['status'], 'covered'>;
  tool: WouldAddTool;
  /** Plan P Task 8: further tools the same pick adds (workflow-lint: zizmor; python dead-code: vulture). Empty when none. */
  also: WouldAddTool[];
  /** pipegen's own label for the row (fixed words, plus a validated service name for starter tests). */
  note: string;
}
export interface SecretInTree {
  /** Repo-relative path (raw), or NAME_HIDDEN when the name itself looks like a secret. */
  file: string;
  /** A findSecretLike rule name, or 'secret-like-name' for the file name. Never a value. */
  rule: string;
  /** EXCLUDED_NOTE when the file matches EXCLUDED_PATTERNS (never sent to the AI, but on disk all the same). */
  note?: string;
}
/**
 * Hand checks 2026-10-29 (fix 1, ruling P55): what the on-disk check (scanTree, findSecretLike) looks for and what it
 * doesn't. It is a quick check for a few formats, not a secret scan, and every output says so, also when it finds
 * nothing, so an empty list never reads as "no secrets here".
 */
export interface SecretCheckScope { kind: 'quick-format-check'; looksFor: string; doesNotLookFor: string; fullScans: string }
export const SECRET_CHECK: Readonly<SecretCheckScope> = Object.freeze({
  kind: 'quick-format-check',
  looksFor: 'private keys, a few known token formats (AWS, GitHub, Slack, Stripe, Google and npm tokens, and sk- API keys), JWTs, '
    + 'passwords inside connection strings, and file names that look like a secret.',
  doesNotLookFor: '`name = value` lines, such as an API key or a password set in code, in a config file or in a .env file (in a .env '
    + 'file only a password inside a connection string is found), and any token format not listed. So this is not a secret scan: '
    + 'finding nothing here does not mean the repo holds no secrets.',
  fullScans: '`pipegen audit --ai` runs a full secret scanner (betterleaks, or gitleaks) on the files it would send, before anything '
    + 'is sent; the pipeline pipegen sets up (v0.2) runs betterleaks or gitleaks on every push and pull request.',
});

/**
 * supportLevel for v0.2 plus the next step (ruling S8): `nextStep` is prose; `nextCommand` is pipegen's own fixed command
 * for it (ruling U17), or null. The renderers print the command on its own, unescaped, so it copies exactly.
 */
export type AuditSupport = ReturnType<typeof supportLevel> & { nextStep: string; nextCommand: string | null };
/**
 * A warning shown at the top of the report. `text` is prose (cleaned at output like every other string). `command`, when
 * set, is one of pipegen's own fixed commands (ruling U17): built only from constants and pipegen's own version, never
 * from repo data, so the renderers print it unescaped (after checking it with isOwnCommand).
 */
export interface AuditWarning { text: string; command?: string }

export interface AuditReport {
  profile: RepoProfile;
  /** P55 (hand checks fix 10): the commit read (HEAD's SHA and branch, from .git as text), or null when it couldn't be read. */
  commit: HeadCommit | null;
  capabilities: Capabilities; support: AuditSupport;
  coverage: Coverage[]; wouldAdd: WouldAddRow[];
  /** Plan P Task 8: the checks that don't apply to this repo, one line per reason. */
  skipped: SkippedGroup[];
  /** Plan P Task 8 (ST1-ST3): the GitHub settings `finish` would turn on after the merge. */
  wouldSet: WouldSet[];
  wouldCreate: { what: Part; why: string }[];
  /** Ruling S27: "No service found to test." when the repo has no service (the tests rows are absent on purpose), else null. */
  testsNote: string | null;
  estimates: Estimates; permissions: { permission: string; why: string }[];
  limits: string[]; secretsInTree: SecretInTree[];
  /** Hand checks (P55): what the on-disk check behind secretsInTree looks for and what it doesn't (always SECRET_CHECK). */
  secretCheck: SecretCheckScope;
  /** What the full run would send to the AI (counts and folder names, never contents). */
  aiBundle: { files: number; bytes: number; truncated: boolean; excludedPatterns: string[]; topFolders: string[] };
  /** How pipegen was started (a repo .npmrc with a registry, a local node_modules/.bin/pipegen) and anonymous access. */
  warnings: AuditWarning[];
  /** Reader, workflow, capability-probe, bundle, coverage and quick-secret-check notes; deduped (ruling S11), each passed through redact() (a secret-like file name in a reader note is masked). */
  notes: string[];
  /** Ruling U11: the caller couldn't use the reviewed list (B3). Task 2b drops every discovery suggestion when true. */
  reviewedUnavailable: boolean;
  /**
   * DoD run 2026-10-29: what GitHub's rate limit kept pipegen from reading (null: GitHub was read in full). Every
   * coverage row whose answer depends on it is `unknown`; the report says so at the top, with the reset time.
   */
  githubIncomplete: GitHubIncomplete | null;
  /**
   * P51 (review M5): when GitHub's rate limit left facts unread, the "would add" picks were made with placeholders for
   * them (private, plan unknown, the unread capabilities off): this plain note says so in every output. Else null.
   */
  wouldAddNote: string | null;
  /** Only with --ai, after consent (Task 2b, addAiSuggestions); mention-only. */
  ai?: AuditAi;
}

/**
 * The GitHub facts a run couldn't read: 'repo' (visibility, owner, plan and default branch), 'branch-protection',
 * 'environments', 'deployment-branch-policies', 'code-scanning', 'activity' (pushes and pull requests, for the monthly
 * minutes), 'code-scanning-setup' (CodeQL default setup) and 'workflow-runs' (the last run of a covering workflow).
 */
export type GitHubFact = 'repo' | 'branch-protection' | 'environments' | 'deployment-branch-policies' | 'code-scanning' | 'activity'
  /** P55: whether GitHub's CodeQL default setup is on, and the last run of each workflow that covers a check. */
  | 'code-scanning-setup' | 'workflow-runs';
export interface GitHubIncomplete {
  reason: 'github-rate-limit';
  /** When GitHub said its limit resets (ISO 8601, UTC), or null when it didn't say. */
  resetsAt: string | null;
  unread: GitHubFact[];
  /** How many coverage rows are unknown because of it. */
  rows: number;
}

/**
 * What `audit --ai` adds (ruling S11). Every string is kept raw (no escaping): Task 3 cleans it at output (ruling U10).
 * Known values (the token, the AI key) are scrubbed from it all the same (ruling S19).
 */
export interface AuditAi {
  /** Needs the AI adds on top of the floor ("the AI also suggests checking …"). Floor needs are never changed. */
  extraNeeds: Need[];
  /** MENTION-ONLY tools ({ name, repo, why }): never run, never turned into a step. */
  suggestions: PipelineDraft['suggestions'];
  /** Planner, discovery and AI-step notes; deduped. */
  notes: string[];
  /** Every AI attempt of this step, summed by the spend meter (the needs call, its retry and every discovery attempt, failed ones included; rulings B2, U13). */
  usage: AiTokenCounts;
  /**
   * ABOUT what the AI step cost at list price (USD): the sum of `attempts[].listUsd`. It is an approximation: cache reads
   * are priced as full input (no cache discount). A run the refusal fallback sent to another model is priced at that
   * model's list price when the provider names it (AiUsage.attempts, Plan E S22), else at the primary model's. Each
   * attempt is priced in the tier its own prompt length falls in. 0 for a local model.
   */
  costUsd: number;
  /** One record per attempt that reported usage (failed ones included), in the order they settled. */
  attempts: AiAttempt[];
  /** The provider is Ollama: no cost is counted (it isn't a paid API). */
  local: boolean;
  /**
   * The hard limit on this step's AI spend the user agreed to on the consent screen (USD; AiSpendMeter.effectiveCapUsd).
   * null for a local model (no limit). Plan U final review M6: the report repeats it next to what was spent.
   */
  capUsd: number | null;
}

/** One settled AI attempt and its list cost (see AuditAi.costUsd for why the cost is "about"). */
export type { AiAttempt };

export interface AuditDeps {
  /** Always set; an anonymous client works for a public repo. */
  gh: Octokit;
  anonymous: boolean;
  /**
   * readGitHubContext's answer (the CLI reads it; ruling B1), or null when GitHub's rate limit stopped that read (DoD
   * run 2026-10-29): every check that depends on the visibility, the owner or the default branch is then unknown.
   */
  context: Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'> | null;
  /** probeCapabilities' answer; with a null context, a placeholder (every capability counts as unread). */
  capabilities: Capabilities;
  /** DoD run 2026-10-29: the capabilities GitHub's rate limit kept probeCapabilities from reading (their values are placeholders). */
  unreadCapabilities?: readonly (keyof Capabilities)[];
  /** What the full run would need (permissionsTable('write', …)); shown as given. */
  permissions: { permission: string; why: string }[];
  reviewed: ReviewedTool[];
  /** Ruling B3: the reviewed list couldn't be used (reviewed is then []): tool-less rows say so. */
  reviewedUnavailable?: boolean;
  now: () => number;
  /** Notes the caller already has (GitHub context, capability probe); merged into report.notes. */
  notes?: string[];
  /** The run's GitHub wait budget: the one newRateBudget() the CLI makes per run, shared by every GitHub call. */
  budget: RateBudget;
  sleep?: (ms: number) => Promise<void>;
  /**
   * Plan U final review M9: the counting-only bundle the caller already built for `dir` (bundleCode(dir, { knownValues }),
   * no secret scan), so a run builds it once and the report and the consent screen show the same count. Without it (or for
   * another folder, or a bundle that isn't a counting one), buildAudit builds its own.
   */
  bundle?: CodeBundle;
  /**
   * Plan J J5 (ruling B1): the types the user set (`--type`, or the type question the CLI asks before any GitHub call),
   * applied with applyTypeOverrides right after the local read. Data, not a callback: nothing here asks anything.
   */
  typeOverrides?: readonly TypeOverride[];
}

// ---------- fixed texts ----------

const AUDIT_TODAY = ' You can run `pipegen audit` today.';
/**
 * Ruling U18: no runnable full-setup command in v0.1 output. The npm name `pipegen` isn't pipegen's yet (it was published
 * in 2019 and unpublished, so anyone can claim it), so `npx pipegen` could run someone else's package. `command` stays
 * null until the package is published; then fill it here and accept it in isOwnCommand.
 */
const NEXT_STEP: Readonly<Record<Milestone, Readonly<Record<'v0.2' | 'v0.4' | 'none', { text: string; command: string | null }>>>> = {
  'v0.1': {
    'v0.2': { text: 'The full setup arrives in v0.2 for single-package Node/TypeScript repos.', command: null },
    'v0.4': { text: 'The full setup arrives in v0.4 for Python and monorepos.', command: null },
    none: { text: 'The full setup is not planned yet for this repo.', command: null },
  },
};

const NPM_REGISTRY = 'https://registry.npmjs.org';
const SEMVER = /^\d{1,9}\.\d{1,9}\.\d{1,9}$/;
/**
 * The command that runs this pipegen from outside the repo, from npm's own registry (ruling S30/U17). Built only from
 * constants and `version` (pipegen's own package.json), which must be a plain x.y.z, else it is left out.
 */
export function safeRunCommand(version: string | null): string | null {
  // No exact version, no command: an unpinned `npx pipegen` runs whatever owns the npm name today (ruling U18).
  if (version === null || !SEMVER.test(version)) return null;
  return `npx --registry=${NPM_REGISTRY} pipegen@${version} audit --dir ./repo`;
}
/**
 * True for a command pipegen itself builds (safeRunCommand) and nothing else: the renderers print a
 * command unescaped only when this holds (no backtick, no space-separated repo text, nothing to break out of a code span).
 */
export function isOwnCommand(s: unknown): s is string {
  return typeof s === 'string'
    && /^npx --registry=https:\/\/registry\.npmjs\.org pipegen@\d{1,9}\.\d{1,9}\.\d{1,9} audit --dir \.\/repo$/.test(s);
}

/** pipegen's own checks (the merge gate, the deploy-time verify): pipegen adds them itself, so no tool is picked for them and they never make a layer "serious" (ruling U16). */
export function isBuiltInNeed(need: Pick<Need, 'category'>): boolean {
  return need.category === 'gate' || need.category === 'deploy-verify';
}

/** A plain-English name for each check, for the report (one map, shared by every output that names a check). */
const NEED_LABELS: Readonly<Record<NeedCategory | 'migration-check', string>> = {
  secrets: 'Secret scan', sast: 'Code scan (SAST)', deps: 'Dependency check', 'unit-tests': 'Unit tests', 'full-tests': 'Full test suite',
  lint: 'Lint', 'format-lint': 'Format and lint hook', hooks: 'Git hook manager', 'hooks-ci': 'Git hooks re-run in CI',
  'image-build': 'Container image build', 'image-scan': 'Container image scan', dast: 'Running-app scan (DAST)',
  iac: 'Infrastructure code scan (IaC)', sbom: 'Software bill of materials (SBOM)', signing: 'Image signing',
  attestation: 'Build attestation', 'deploy-verify': 'Deploy check (pipegen)', gate: 'Merge gate (pipegen)',
  'migration-check': 'Database migration check',
  ...CHECK_LABELS,
};
/** Plan U final review M4: the names that change for a package that is released and builds no image. */
const RELEASE_LABELS: Readonly<Record<string, string>> = { signing: 'Release signing' };
/**
 * The plain-English name of a check, or null for an id pipegen doesn't know (the caller shows the cleaned id).
 * `noImage`: the check's service builds no image (buildsNoImage), so signing is "Release signing".
 */
export function needLabel(id: string, opts: { noImage?: boolean } = {}): string | null {
  if (opts.noImage === true && Object.hasOwn(RELEASE_LABELS, id)) return RELEASE_LABELS[id] as string;
  return Object.hasOwn(NEED_LABELS, id) ? (NEED_LABELS as Record<string, string>)[id] as string : null;
}

/**
 * Plan U final review M4: true when the need's service builds no image, so its deploy checks protect a release, not an
 * image: the service isn't runnable (a package), or the need has no service and none of the repo's services runs.
 * The same split floorNeeds makes when it targets signing at the runnable services first (src/engine/needs.ts).
 */
export function buildsNoImage(need: Pick<Need, 'service'>, p: Pick<RepoProfile, 'services'>): boolean {
  if (need.service === undefined) return !p.services.some(isRunnable);
  const s = p.services.find((x) => x.name === need.service);
  return s !== undefined && !isRunnable(s);
}

const ROW_NOTE = {
  builtIn: "pipegen's own check",
  reviewed: 'reviewed tool',
  suggestion: 'no reviewed tool yet; pipegen would only mention one, never run it as a check',
  unavailable: "pipegen's reviewed tool list couldn't be loaded, so it has no tool to add here",
  script: (script: 'test' | 'lint') => `your own \`${script}\` script would run here`,
} as const;
const starterTests = (service: string) => `No tests found for ${service}: pipegen would create starter tests.`;
const NO_SERVICE_TO_TEST = 'No service found to test.';

const LIMIT = {
  noLock: 'No merge lock: anyone with write access can merge without checks (GitHub Pro for personal accounts, GitHub Team for organisations, adds it).',
  fakeGate: 'Without a merge lock, a pull request could replace the gate with a fake one; only code-owner review stops it.',
  noApprovals: 'No deploy approvals: GitHub does not let this repo require a reviewer before a deploy.',
  noSigning: 'No image signing: this private repo has no artifact attestations, and no environment rule was proven to keep a signing key to the default branch.',
  noReleaseSigning: 'No release signing: this private repo has no artifact attestations, and no environment rule was proven to keep a signing key to the default branch.',
  noAttestations: 'No artifact attestations: GitHub does not offer them for this repo.',
  noCodeScanning: 'No code scanning: GitHub does not show scan results in the Security tab for this repo.',
} as const;

export const NAME_HIDDEN = HIDDEN_NAME;
export const EXCLUDED_NOTE = "(never sent to the AI; check it isn't committed)";
const NAME_RULE = 'secret-like-name';
const MAX_SECRET_ROWS = 200;
/** Secrets scan budget: past this many bytes read, the rest isn't scanned (with a note). */
const MAX_SCAN_BYTES = 200_000_000;
const SKIPPED_DIRS_NOTE = `The quick secret check did not check dependency and build folders (${IGNORED_DIRS.filter((d) => d !== '.git').join(', ')}) or .git, so committed build output was not checked either.`;
const UNTRACKED_NOTE = "pipegen reads the files on disk without git, so files that aren't committed (for example a local .env) are in this list too.";

// Worded so redact() leaves it whole at output ("No token: …" would be cut; review M3).
const NO_TOKEN = 'Without a GitHub token, pipegen reads public data only and is rate-limited.';
export const SWAP_TEXT = 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:';
export const SWAP_TEXT_NO_COMMAND = 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with an exact version (pipegen@x.y.z).';
/**
 * Ruling U12: the `.npmrc` keys that can't change which pipegen npx fetches or how it starts it (npm's config docs):
 * saving, lockfile, engine and output settings. Any other key warns: registries (any scope), proxies, TLS (`strict-ssl`,
 * `ca`, `cafile`, `cert`), scripts and shells, `node-options`, `prefix`, `cache`, auth, `_`-prefixed and per-registry
 * (`//host/:…`) keys, sections, and every key npm adds later. `audit` is safe only as `audit=true` or `audit=false`.
 */
const NPMRC_SAFE_KEYS: ReadonlySet<string> = new Set([
  'save-exact', 'save-prefix', 'engine-strict', 'fund', 'package-lock', 'loglevel', 'progress', 'legacy-peer-deps', 'lockfile-version',
  'update-notifier', 'color',
]);
/**
 * Task 5 (item 5): keys that are safe only with values that make npm stricter than its default, each checked against
 * npm's config docs (https://docs.npmjs.com/cli/v11/using-npm/config, 2026-10-27). The value (trimmed, any letter case)
 * must match; any other value of these keys warns, like any unknown key.
 * - ignore-scripts (default false): `true` only; npm then runs no package scripts. `false` is the default but stays on the
 *   warning side, as U12 decided for every script setting.
 * - min-release-age (default null; days): a whole number of days; npm then installs only versions older than that, so with
 *   pipegen's exact-version command it can refuse to start pipegen, never pick another one. (Not `before`: a date in
 *   the future means "no limit", and npm lets it win over min-release-age.)
 * - allow-git (default `all`, the most open value): `all`, `root` or `none`, each no wider than the default.
 * - strict-peer-deps (default false): `true` only; npm then fails on a peer-dependency conflict instead of warning.
 * Not added: audit-level. Its values `high`, `critical` and `none` make `npm audit` pass on findings it fails by default,
 * so not every value is as strict as the default.
 */
const NPMRC_STRICT_VALUES: ReadonlyMap<string, RegExp> = new Map([
  ['ignore-scripts', /^true$/i],
  ['min-release-age', /^\d{1,6}$/],
  ['allow-git', /^(?:all|root|none)$/i],
  ['strict-peer-deps', /^true$/i],
]);
/**
 * Only the start of a line (after its leading whitespace, which npm's ini parser trims too) is read for the key, so a
 * huge line can't stall the check and padding can't push the key out of view (a key that doesn't fit counts as unsafe).
 */
const NPMRC_KEY_WINDOW = 300;

/** The report's notes: deduped, each masked with redact() (a reader note can name a file whose name looks like a secret). */
class Notes {
  readonly #seen = new Set<string>();
  add(note: string): void {
    this.#seen.add(redact(note));
  }
  all(): string[] {
    return [...this.#seen];
  }
}

// ---------- buildAudit ----------

/**
 * The whole audit model for the repo in `dir`. Read-only: reads the repo through the read limits, makes only GET
 * requests through `deps.gh` (the last 30 days of activity), runs no child process and calls no AI.
 * Throws NotGitHubRepoError when `dir` isn't a GitHub checkout (readProject).
 */
export async function buildAudit(dir: string, deps: AuditDeps): Promise<AuditReport> {
  const notes = new Notes();
  const readerNotes: string[] = [];
  const local = applyTypeOverrides(await readProject(dir, { notes: readerNotes }), deps.typeOverrides ?? []);
  // DoD run 2026-10-29: with no context (GitHub's rate limit), the profile's GitHub facts are placeholders (the
  // fail-closed side: private, plan unknown); nothing below states them, and --json writes them as null
  const context = deps.context ?? { private: true, ownerType: 'User' as const, plan: 'unknown' as const, defaultBranch: local.defaultBranch };
  const profile: RepoProfile = {
    ...local,
    private: context.private, ownerType: context.ownerType, plan: context.plan, defaultBranch: context.defaultBranch,
  };
  for (const n of readerNotes) notes.add(n);
  for (const n of deps.notes ?? []) notes.add(n);
  for (const n of libraryNotes(profile)) notes.add(n);

  const caps = deps.capabilities;
  const unreadCaps: ReadonlySet<keyof Capabilities> = new Set(deps.context === null ? CAPABILITY_KEYS : deps.unreadCapabilities ?? []);
  const skippedWf = skippedWorkflowCount(readerNotes);
  let needs: Need[];
  let coverage: Coverage[];
  let skipped: SkippedGroup[];
  let wouldSetFor: RepoProfile[];
  let limits: string[];
  const same = <T>(a: readonly T[], b: readonly T[]) => { const keys = new Set(b.map((x) => JSON.stringify(x))); return a.filter((x) => keys.has(JSON.stringify(x))); };
  if (unreadCaps.size === 0) {
    needs = floorNeeds(profile, caps);
    coverage = await coverageOf(profile, needs, dir, skippedWf, notes, caps);
    skipped = skippedGroups(profile, caps);
    wouldSetFor = [profile];
    limits = limitsOf(profile, caps);
  } else {
    // DoD run 2026-10-29: GitHub's rate limit left facts unread. The coverage is mapped twice, with every unread fact
    // on its most permissive side (public, the capability there, every branch filter taking the default branch) and on
    // its least (private, the capability absent, only unfiltered triggers taking it). A row both give alike doesn't
    // depend on what wasn't read; any other row is unknown, saying why. Never a guessed covered, never a guessed missing.
    const world = (hi: boolean) => {
      const c = { ...caps };
      for (const k of unreadCaps) c[k] = hi;
      return { p: deps.context === null ? { ...profile, private: !hi } : profile, c };
    };
    const hi = world(true);
    const lo = world(false);
    const guess = (g: 'widest' | 'narrowest') => (deps.context === null ? g : undefined);
    const covHi = await coverageOf(hi.p, floorNeeds(hi.p, hi.c), dir, skippedWf, notes, hi.c, guess('widest'));
    const covLo = await coverageOf(lo.p, floorNeeds(lo.p, lo.c), dir, skippedWf, notes, lo.c, guess('narrowest'));
    coverage = bothWorlds(covHi, covLo, deps.context === null);
    needs = coverage.map((c) => c.need);
    skipped = same(skippedGroups(hi.p, hi.c), skippedGroups(lo.p, lo.c));
    wouldSetFor = [hi.p, lo.p];
    limits = same(limitsOf(hi.p, hi.c), limitsOf(lo.p, lo.c));
  }
  // P55 (hand checks): what GitHub itself says that the files can't show, read after the files and before the picks
  const signalsUnread: GitHubFact[] = [];
  coverage = await defaultSetupRows(deps, profile, coverage, signalsUnread);
  coverage = await lastRunRows(deps, profile, coverage, signalsUnread, notes);
  const wouldSet = wouldSetFor.map((x) => wouldSetSettings(x, coverage, skippedWf)).reduce((a, b) => same(a, b));
  const wouldAdd = wouldAddRows(profile, coverage, deps, caps);

  const activity = await activityOf(deps, profile);
  const estimates = estimate(profile, jobCategories(needs), 2, activity ?? { pushes: 0, prs: 0, capped: false }, { name: 'claude', model: DEFAULT_MODEL });
  if (activity === null) {
    const line = "Activity: pipegen couldn't read this repo's pushes and pull requests for the last 30 days, so monthly minutes assume 0 of each (the real number is likely higher).";
    const at = estimates.basis.findIndex((b) => b.startsWith('Activity:'));
    if (at >= 0) estimates.basis[at] = line;
    else estimates.basis.push(line);
  }
  if (deps.context === null) {
    estimates.basis.push("GitHub's rate limit kept pipegen from reading whether this repo is public, so these minutes assume a private repo with an unknown plan (on a public repo GitHub-hosted minutes are free).");
  }
  const stop = deps.budget.stopped;
  const githubIncomplete: GitHubIncomplete | null = stop === undefined ? null : {
    reason: 'github-rate-limit',
    resetsAt: stop.resetAt === null ? null : new Date(stop.resetAt).toISOString(),
    unread: [...unreadFacts(deps.context === null, unreadCaps, activity === null), ...signalsUnread],
    rows: coverage.filter((c) => c.status === 'unknown' && (Object.values(RATE_WHY) as string[]).includes(c.why)).length,
  };

  const secretsInTree = await scanTree(dir, notes);

  const bundle = await countingBundle(dir, deps.bundle);
  // A counting-only bundle says it "cannot be sent to the AI"; nothing is sent here, so that note would only confuse.
  for (const n of bundle.notes) if (n !== COUNTING_ONLY_NOTE) notes.add(n);

  return {
    profile,
    commit: await readHeadCommit(dir),
    capabilities: caps,
    support: supportOf(profile),
    coverage,
    wouldAdd,
    skipped,
    wouldSet,
    wouldCreate: wouldCreateOf(profile),
    testsNote: profile.services.length === 0 ? NO_SERVICE_TO_TEST : null,
    estimates,
    permissions: deps.permissions,
    limits,
    secretsInTree,
    secretCheck: { ...SECRET_CHECK },
    aiBundle: {
      files: bundle.files.length, bytes: bundle.bytes, truncated: bundle.truncated,
      excludedPatterns: [...EXCLUDED_PATTERNS], topFolders: bundleTopFolders(bundle),
    },
    warnings: [
      ...(stop === undefined ? [] : [{ text: rateLimitWarning(stop.resetAt, deps.now(), deps.anonymous, local.repo) }]),
      ...await warningsOf(dir, deps.anonymous),
    ],
    notes: notes.all(),
    reviewedUnavailable: deps.reviewedUnavailable === true,
    githubIncomplete,
    wouldAddNote: githubIncomplete === null ? null : WOULD_ADD_INCOMPLETE,
  };
}

/** P51 (M5): the "would add" note when GitHub's rate limit left facts unread. */
export const WOULD_ADD_INCOMPLETE = "These picks are based on incomplete GitHub data (rate limit): pipegen picked them as if the facts it couldn't read were the most restrictive (a private repo, an unknown plan, no GitHub feature it couldn't check).";
/** P51 (M5): the --ai consent screen's note when GitHub's rate limit left facts unread. */
export const CONSENT_INCOMPLETE = "Based on incomplete GitHub data (rate limit): GitHub's rate limit stopped pipegen reading some GitHub facts, so the repo facts sent to the AI may be wrong where GitHub wasn't read (a private repo and an unknown plan are assumed).";

// ---------- GitHub's rate limit (DoD run 2026-10-29) ----------

const CAPABILITY_KEYS: readonly (keyof Capabilities)[] = [
  'branchProtection', 'environments', 'deploymentBranchPolicies', 'envRequiredReviewers', 'attestations', 'codeScanning', 'keylessSigningAllowed',
];
/** The whys of rows GitHub's rate limit left unknown (pipegen's own text). */
export const RATE_WHY = {
  context: "pipegen couldn't check this: GitHub's rate limit kept it from reading this repo's default branch and settings, and the answer depends on them.",
  caps: "pipegen couldn't check this: GitHub's rate limit kept it from asking what GitHub allows here, and the answer depends on it.",
  applies: "pipegen couldn't tell whether this check applies here: it depends on what GitHub allows for this repo, which GitHub's rate limit kept it from reading.",
  setup: "pipegen couldn't check whether GitHub's CodeQL default setup is on: GitHub's rate limit was reached.",
} as const;

/** P55 (fix 3): the most workflows whose last run one audit asks about (one call each). */
export const MAX_RUN_READS = 20;

/**
 * P55 (hand checks, fix 3): covered rows after the last completed run of their workflow on the default branch, one
 * GitHub call per workflow (at most MAX_RUN_READS). Not asked when the default branch wasn't read; a rate stop keeps
 * every row as it is and says so (a note, and 'workflow-runs' in githubIncomplete).
 */
async function lastRunRows(deps: AuditDeps, p: RepoProfile, rows: Coverage[], unread: GitHubFact[], notes: Notes): Promise<Coverage[]> {
  const listed = new Set(p.existingWorkflows.map((w) => w.path));
  const workflows = [...new Set(rows.map((r) => coveringWorkflow(r, listed)).filter((w): w is string => w !== null))].sort();
  if (workflows.length === 0) return rows;
  const clock = { budget: deps.budget, now: deps.now, ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }) };
  const runs = new Map<string, RunAnswer>();
  let stopped = deps.context === null || rateStopOf(deps.budget, deps.now()) !== null;
  for (const [i, wf] of workflows.entries()) {
    if (stopped) runs.set(wf, { state: 'unread', why: 'rate' });
    else if (i >= MAX_RUN_READS) runs.set(wf, { state: 'unread', why: 'cap' });
    else {
      try {
        runs.set(wf, await lastCompletedRun(deps.gh, p.owner, p.repo, wf, p.defaultBranch, clock));
      } catch (e) {
        if (!isRateStop(e)) throw e;
        stopped = true;
        runs.set(wf, { state: 'unread', why: 'rate' });
      }
    }
  }
  if ([...runs.values()].some((r) => r.state === 'unread' && r.why === 'rate')) unread.push('workflow-runs');
  const out = applyLastRuns(rows, runs, listed, deps.context === null ? 'the default branch' : p.defaultBranch);
  for (const n of out.notes) notes.add(n);
  return out.rows;
}

/**
 * P55 (hand checks, fix 2): code-scan rows after GitHub's CodeQL default setup, which no workflow file shows. Read only
 * when a code-scan row is missing; a rate stop (before or during the read) makes those rows unknown, never guessed.
 */
async function defaultSetupRows(deps: AuditDeps, p: RepoProfile, rows: Coverage[], unread: GitHubFact[]): Promise<Coverage[]> {
  if (!rows.some((c) => c.need.category === 'sast' && c.status === 'missing')) return rows;
  const clock = { budget: deps.budget, now: deps.now, ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }) };
  let setup: DefaultSetup;
  if (deps.context === null || rateStopOf(deps.budget, deps.now()) !== null) {
    setup = { state: 'unknown', why: RATE_WHY.setup };
  } else {
    try {
      setup = await readDefaultSetup(deps.gh, p.owner, p.repo, p.defaultBranch, clock, deps.anonymous);
    } catch (e) {
      if (!isRateStop(e)) throw e;
      setup = { state: 'unknown', why: RATE_WHY.setup };
    }
  }
  if (setup.state === 'unknown' && setup.why === RATE_WHY.setup) unread.push('code-scanning-setup');
  return applyDefaultSetup(rows, setup, p);
}

/** One row per need of either world: the row when both worlds agree on it, else unknown with RATE_WHY. */
function bothWorlds(hi: readonly Coverage[], lo: readonly Coverage[], contextUnread: boolean): Coverage[] {
  const loBy = new Map(lo.map((r) => [needKey(r.need), r]));
  const hiKeys = new Set(hi.map((r) => needKey(r.need)));
  const why = contextUnread ? RATE_WHY.context : RATE_WHY.caps;
  const alike = (a: Coverage, b: Coverage) => a.status === b.status && a.why === b.why && a.by === b.by && a.where === b.where;
  const out: Coverage[] = hi.map((h) => {
    const l = loBy.get(needKey(h.need));
    if (l === undefined) return { need: h.need, status: 'unknown', why: RATE_WHY.applies };
    return alike(h, l) ? h : { need: h.need, status: 'unknown', why };
  });
  for (const l of lo) if (!hiKeys.has(needKey(l.need))) out.push({ need: l.need, status: 'unknown', why: RATE_WHY.applies });
  return out;
}

function unreadFacts(contextUnread: boolean, caps: ReadonlySet<keyof Capabilities>, activityUnread: boolean): GitHubFact[] {
  const out: GitHubFact[] = [];
  if (contextUnread) out.push('repo');
  if (caps.has('branchProtection')) out.push('branch-protection');
  if (caps.has('environments')) out.push('environments');
  if (caps.has('deploymentBranchPolicies')) out.push('deployment-branch-policies');
  if (caps.has('codeScanning')) out.push('code-scanning');
  if (activityUnread) out.push('activity');
  return out;
}

/**
 * The top warning when GitHub's rate limit was reached: what it means for the report, when the limit resets, and (with
 * no token) the read-only fine-grained token that lifts it, with its exact permissions (Plan U: "says so plainly and
 * suggests GITHUB_TOKEN").
 */
export function rateLimitWarning(resetAt: number | null, nowMs: number, anonymous: boolean, repo: string, timeZone?: string): string {
  const head = "GitHub's rate limit was reached, so pipegen couldn't read everything it needs from GitHub. "
    + 'The checks that depend on it show as unknown (couldn\'t check), never as covered or missing. '
    + `${resetText(resetAt, nowMs, timeZone)} `;
  return head + (anonymous
    ? `Without a token GitHub allows 60 requests an hour. For a full check, ${readOnlyTokenHint(repo)}`
    : 'This limit counts the requests made with your token; run the audit again after it resets.');
}

// ---------- the local-only audit (GitHub not read) ----------

/** readProject's answer: the repo as found on disk, without its GitHub context. */
export type LocalProfile = Awaited<ReturnType<typeof readProject>>;

/**
 * What the audit can honestly say when GitHub couldn't be read (the `inspect` R10 rule): only what is on disk. No
 * coverage (it depends on the default branch), no plan limits, no estimates and no permissions, so nothing about
 * GitHub is guessed.
 */
export interface LocalAudit {
  profile: LocalProfile;
  commit: HeadCommit | null;
  secretsInTree: SecretInTree[];
  secretCheck: SecretCheckScope;
  aiBundle: AuditReport['aiBundle'];
  /** The `.npmrc` / node_modules/.bin/pipegen warning (no anonymous-access warning: pipegen doesn't know the access). */
  warnings: AuditWarning[];
  notes: string[];
}

/** The local-only audit of `dir`: reads files only (no GitHub, no AI, no child process). Throws NotGitHubRepoError like buildAudit. */
export async function buildLocalAudit(dir: string, deps: { notes?: string[]; typeOverrides?: readonly TypeOverride[] } = {}): Promise<LocalAudit> {
  const notes = new Notes();
  const readerNotes: string[] = [];
  const profile = applyTypeOverrides(await readProject(dir, { notes: readerNotes }), deps.typeOverrides ?? []);
  for (const n of readerNotes) notes.add(n);
  for (const n of deps.notes ?? []) notes.add(n);
  const secretsInTree = await scanTree(dir, notes);
  const bundle = await bundleCode(dir);
  for (const n of bundle.notes) if (n !== COUNTING_ONLY_NOTE) notes.add(n);
  return {
    profile,
    commit: await readHeadCommit(dir),
    secretsInTree,
    secretCheck: { ...SECRET_CHECK },
    aiBundle: {
      files: bundle.files.length, bytes: bundle.bytes, truncated: bundle.truncated,
      excludedPatterns: [...EXCLUDED_PATTERNS], topFolders: bundleTopFolders(bundle),
    },
    warnings: await warningsOf(dir, false),
    notes: notes.all(),
  };
}

// ---------- parts ----------

/**
 * Task 5 fix round 1 (I5): a service with a port that pipegen reads as a published library gets no image or running-app
 * checks; say so, so a real server that looks like a package isn't a silent gap.
 */
export function libraryNotes(p: Pick<RepoProfile, 'services'>): string[] {
  return p.services.filter((s) => s.port !== undefined && s.publishedPackage === true && !isRunnable(s)).map((s) =>
    `${s.name} listens on a port but looks like a published package, so pipegen didn't add container image or running-app (web) scan checks. If ${s.name} is an app, add a start script or a Dockerfile and pipegen will treat it as one.`);
}

/** supportLevel for v0.2, without the "You can run `pipegen audit` today." tail (this is that audit), plus the next step. */
function supportOf(p: RepoProfile): AuditSupport {
  const v02 = supportLevel(p, 'v0.2');
  const reasons = v02.reasons.map((r) => (r.endsWith(AUDIT_TODAY) ? r.slice(0, -AUDIT_TODAY.length) : r));
  const next = v02.level === 'full' ? 'v0.2' : supportLevel(p, 'v0.4').level === 'full' ? 'v0.4' : 'none';
  const step = NEXT_STEP[CURRENT_MILESTONE][next];
  return { level: v02.level, reasons, nextStep: step.text, nextCommand: step.command };
}

/** mapCoverage, or every need `unknown` with a plain note when it fails (the tool signatures can't be loaded). */
async function coverageOf(
  p: RepoProfile, needs: Need[], dir: string, skippedWorkflows: number, notes: Notes, capabilities: Capabilities, branchGuess?: 'widest' | 'narrowest',
): Promise<Coverage[]> {
  try {
    // Plan P Task 3 (PS16): the capabilities too, so an action this repo can't use is never read as covered
    return await mapCoverage(p, needs, dir, { skippedWorkflows, noImage: (need) => buildsNoImage(need, p), capabilities, ...(branchGuess === undefined ? {} : { branchGuess }) });
  } catch (e) {
    const why = e instanceof Error ? e.message.split('\n')[0] : 'unknown error';
    notes.add(`pipegen couldn't load its list of tool signatures, so it can't tell which checks your workflows already run (${why}).`);
    return needs.map((need) => ({ need, status: 'unknown', why: "pipegen couldn't look for this check: its tool signatures didn't load." }));
  }
}

function wouldAddRows(p: RepoProfile, coverage: Coverage[], deps: AuditDeps, caps: Capabilities): WouldAddRow[] {
  const rows: WouldAddRow[] = [];
  for (const c of coverage) {
    if (c.status === 'covered') continue;
    const need = c.need;
    const service = need.service === undefined ? undefined : p.services.find((s) => s.name === need.service);
    // S27: a service without tests gets starter tests; its own `test` script (npm's default "no test specified") is
    // then not offered as the tool, so the row's tool and note agree (fix round 1, M2).
    const starter = (need.category === 'unit-tests' || need.category === 'full-tests') && service !== undefined && !service.hasTests;
    const { tool, also, note } = pick(need, starter ? undefined : service, p, deps, caps, c);
    rows.push({ need, status: c.status, tool, also, note: starter ? starterTests(service.name) : c.lastRun === undefined ? note : failedRunNote(c.lastRun, tool, note) });
  }
  return rows;
}

/**
 * P55 (fix 3): the pick for a row whose covering workflow's last run failed. The project's own script already runs
 * there, so offering it again would be no advice: the note says to make that workflow pass. Another pick keeps its note,
 * with the failed run said after it.
 */
function failedRunNote(run: NonNullable<Coverage['lastRun']>, tool: WouldAddTool, note: string): string {
  if (tool !== null && 'kind' in tool && tool.kind === 'project-script') {
    return `your own \`${tool.script}\` script already runs in ${run.workflow}, but its last run on ${run.branch} failed: make that workflow pass first`;
  }
  return `${note}; the check pipegen found in ${run.workflow} may not be running: its last run on ${run.branch} failed`;
}

/**
 * Ruling S7, extended by Plan P Task 8: pipegen's own check → the service's own script → chooseTools (the catalogue's
 * choose-rules; the first reviewed entry for a check without a rule, PS35) → nothing. The list unavailable (B3/U11)
 * keeps its own note on a row that ends with no tool.
 */
function pick(need: Need, service: Service | undefined, p: RepoProfile, deps: AuditDeps, caps: Capabilities, row: Coverage): { tool: WouldAddTool; also: WouldAddTool[]; note: string } {
  if (isBuiltInNeed(need)) return { tool: { kind: 'built-in' }, also: [], note: ROW_NOTE.builtIn };
  const script = service === undefined ? null : projectScriptFor(need, service);
  if (script !== null) return { tool: script, also: [], note: ROW_NOTE.script(script.script) };
  const choice = chooseTools(need, service, p, caps, deps.reviewed, row);
  if (choice.tool !== null) return { tool: choice.tool, also: choice.also, note: choice.note };
  // Task 9: an unavailable list explains a pick that is null only for lack of its entry (or has no note at all); a null pick with a reason of its own keeps it
  if (deps.reviewedUnavailable === true && (choice.unlisted === true || choice.note === '')) return { tool: null, also: [], note: ROW_NOTE.unavailable };
  return { tool: null, also: [], note: choice.note === '' ? ROW_NOTE.suggestion : choice.note };
}

function wouldCreateOf(p: RepoProfile): { what: Part; why: string }[] {
  const out: { what: Part; why: string }[] = [];
  if (p.precommit === null) out.push({ what: 'precommit', why: 'No git hook manager found: pipegen would set up pre-commit hooks that check each commit.' });
  for (const s of p.services) {
    if (isRunnable(s) && (s.dockerfile ?? '') === '') out.push({ what: 'docker', why: `${s.name} runs but has no Dockerfile: pipegen would create one, so the image can be built and scanned.` });
  }
  // hand checks (P55 batch B): a database named only in a .env file (a sample's DATABASE_URL) isn't one the code uses
  const fromEnvFile = (d: { evidence: string }) => /(?:^|\/)\.env(?:\.[^:/]*)?: /.test(d.evidence);
  const kinds = [...new Set(p.services.flatMap((s) => s.dependsOn.filter((d) => !fromEnvFile(d)).map((d) => d.kind)).filter((k) => k !== 'external'))].sort();
  // hand checks (P55): a repo with its own Compose file (compose.y*ml, docker-compose.y*ml) is never offered one
  if (kinds.length > 0 && !p.hasCompose) out.push({ what: 'compose', why: `The app uses ${kinds.join(', ')}: pipegen would create a Compose file that starts them for the tests.` });
  for (const s of p.services) if (!s.hasTests) out.push({ what: 'tests', why: starterTests(s.name) });
  return out;
}

/** Ruling S9: from the capabilities and the signing mode only. Never the plan name; never "make the repo public". */
function limitsOf(p: RepoProfile, caps: Capabilities): string[] {
  const out: string[] = [];
  if (!caps.branchProtection) out.push(LIMIT.noLock, LIMIT.fakeGate);
  if (!caps.envRequiredReviewers) out.push(LIMIT.noApprovals);
  if (signingMode(p, caps) === 'none') out.push(p.services.some(isRunnable) ? LIMIT.noSigning : LIMIT.noReleaseSigning);
  if (!caps.attestations) out.push(LIMIT.noAttestations);
  if (!caps.codeScanning) out.push(LIMIT.noCodeScanning);
  return out;
}

/** The last 30 days of pushes and pull requests, or null when GitHub won't say (rate limit, no access, bad answer). */
async function activityOf(deps: AuditDeps, p: RepoProfile): Promise<Activity | null> {
  if (rateStopOf(deps.budget, deps.now()) !== null) return null; // GitHub's rate limit was hit: nothing more is asked (DoD run)
  try {
    return await activity30d(deps.gh, p, { budget: deps.budget, now: deps.now, ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }) });
  } catch {
    return null;
  }
}

/**
 * The counting-only bundle of `dir`: `given` when it is one bundleCode built without the secret scan for this same folder
 * (Plan U final review M9: the CLI's, built once with the run's known values), else a new one.
 */
async function countingBundle(dir: string, given: CodeBundle | undefined): Promise<CodeBundle> {
  if (given !== undefined) {
    const root = countedBundleRoot(given);
    if (root !== null && root === await realpath(dir).catch(() => null)) return given;
  }
  return bundleCode(dir);
}

// ---------- secrets in the current files (ruling S10) ----------

/** True when a file name itself looks like a secret (checked raw and as shown), the same test bundleCode uses. */
function nameLooksSecret(path: string): boolean {
  const shown = safeText(path, 1000);
  return redact(path) !== path || redact(shown) !== shown || findSecretLike(path).length > 0;
}

/**
 * Secret-like text in the files on disk now: every listed file (symlinks never followed; dependency and build folders
 * skipped, like every reader), lstat, then the limited reader, then findSecretLike. Rule names and file names only.
 *
 * Plan J J1 (DECISIONS #126): a file git ignores is skipped only when git's index can be read AND the file isn't in it
 * (it isn't committed). A committed file is always checked, even when .gitignore lists it (Review Focus #3: a
 * force-added .env.production), and with no readable index nothing is skipped (the check as it was before J1).
 */
async function scanTree(dir: string, notes: Notes): Promise<SecretInTree[]> {
  const listing = await listFiles(dir, ['**/*'], IGNORED_DIRS.map((d) => `**/${d}/**`));
  const index = await readGitIndexPaths(dir);
  const ignore = index === null ? null : await loadIgnore(dir, { whenUnsure: 'not-ignored' }); // unsure → checked
  let gitIgnored = 0;
  const rows: SecretInTree[] = [];
  let more = 0;
  let bytes = 0;
  let stopped = false;
  let tooLarge = 0;
  let unreadable = 0;
  const add = (row: SecretInTree) => {
    if (rows.length < MAX_SECRET_ROWS) rows.push(row);
    else more++;
  };
  for (const path of [...listing.files].sort()) {
    if (index !== null && ignore !== null && !index.has(path) && ignore.ignored(path)) {
      gitIgnored++;
      continue;
    }
    const hidden = nameLooksSecret(path);
    const file = hidden ? NAME_HIDDEN : path;
    const extra = isExcludedPath(path) ? { note: EXCLUDED_NOTE } : {};
    if (hidden) add({ file, rule: NAME_RULE, ...extra });
    if (stopped) continue;
    const abs = join(dir, path);
    const info = await lstat(abs).catch(() => null);
    if (info === null || info.isSymbolicLink() || !info.isFile()) continue;
    if (info.size > READ_LIMITS.maxFileBytes) {
      tooLarge++;
      continue;
    }
    if (bytes + info.size > MAX_SCAN_BYTES) {
      stopped = true;
      continue;
    }
    const read = await readTextLimitedWithReason(abs, dir);
    if (!('text' in read)) {
      if (read.skipped === 'unreadable') unreadable++;
      continue;
    }
    const text = read.text;
    bytes += Buffer.byteLength(text);
    for (const rule of findSecretLike(text).sort()) add({ file, rule, ...extra });
  }
  notes.add(SKIPPED_DIRS_NOTE);
  if (gitIgnored > 0) notes.add(`The quick secret check skipped ${gitIgnored === 1 ? '1 file' : `${gitIgnored} files`} git ignores (not committed).`);
  for (const n of ignore?.notes ?? []) notes.add(n);
  if (listing.truncated) notes.add('The quick secret check stopped listing files at the file limit; the rest were not checked.');
  if (stopped) notes.add(`The quick secret check stopped after ${MAX_SCAN_BYTES / 1_000_000} MB of files; the rest were not checked.`);
  if (tooLarge > 0) notes.add(`The quick secret check skipped ${tooLarge === 1 ? '1 file' : `${tooLarge} files`} larger than 1 MB.`);
  if (unreadable > 0) notes.add(`The quick secret check couldn't read ${unreadable === 1 ? '1 file' : `${unreadable} files`} (no permission, or it changed while being read); ${unreadable === 1 ? 'it was' : 'they were'} not checked.`);
  if (more > 0) notes.add(`…and ${more} more secret-like findings not listed.`);
  if (rows.length > 0) notes.add(UNTRACKED_NOTE);
  return rows;
}

// ---------- how pipegen was started ----------

/**
 * Ruling S30 / Review Focus 9 / U12: a repo `.npmrc` with any key outside NPMRC_SAFE_KEYS, a local
 * node_modules/.bin/pipegen, or (Plan J J5) a committed node_modules could change which pipegen runs when started from
 * inside the repo: the warning, when pipegen runs from outside (inside, the CLI stops first; see swapRisk).
 */
async function warningsOf(dir: string, anonymous: boolean): Promise<AuditWarning[]> {
  const out: AuditWarning[] = [];
  if (await swapRisk(dir, dir)) {
    const command = safeRunCommand(packageVersion());
    out.push(command !== null ? { text: SWAP_TEXT, command } : { text: SWAP_TEXT_NO_COMMAND });
  }
  if (anonymous) out.push({ text: NO_TOKEN });
  return out;
}

/** The most folders swapRisk walks in one chain (deeper is refused: it can't say no). */
const SWAP_WALK_MAX = 256;

/**
 * Plan J J5 (DECISIONS #124, ruling S8; J5 review fix round 1): what in the folders npm reads could change which
 * pipegen `npx pipegen` runs, in plain words (the thing and its folder), or null. npm reads the project `.npmrc` of the
 * nearest folder from the current one up that has a package.json or a node_modules, and npx runs a local bin of that
 * folder. So two chains of folders are checked, each from the current folder (by real path) up:
 * - when `cwd` is `dir` or inside it: every folder up to and including `dir` (the audited repo, with its git index);
 * - whatever `--dir` says (npx already obeyed the folder pipegen was started in): every folder up to and including the
 *   first one that holds `.git` (that repo's index), or, with none, up to npm's own project folder (the first with a
 *   package.json or a node_modules; else the current folder alone). The user's home folder and the folders above it
 *   are never part of it: `~/.npmrc` is the user's own npm config, not a repo's.
 * In each folder:
 * - a `.npmrc` with any key outside the safe list (read only for that yes/no; no value is kept; one that can't be read
 *   safely, a symbolic link or too large, counts);
 * - `node_modules/.bin/pipegen` (lstat: the last part is never followed, a dangling link counts; a symlinked
 *   node_modules or .bin on the way is followed, as npx would follow it);
 * - a committed node_modules: one the git index lists, in any letter case (on macOS and Windows `Node_Modules` is
 *   node_modules), or, when the index can't be read, any node_modules folder (the stricter side).
 */
export async function swapRiskWhy(cwd: string, dir: string): Promise<string | null> {
  const realDir = await realpath(dir).catch(() => null);
  const realCwd = await realpath(cwd).catch(() => null);
  if (realCwd === null) return null; // a folder that isn't there holds no settings
  let repoTop: string | null = null;
  if (realDir !== null) {
    const rel = relative(realDir, realCwd);
    if (!(rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel))) {
      repoTop = realDir;
      const why = await chainWhy(realDir, rel, 'the repo folder');
      if (why !== null) return why;
    }
  }
  const top = await startTop(realCwd);
  if (top === null || top === repoTop) return null;
  return chainWhy(top, relative(top, realCwd), top === realCwd ? 'the folder pipegen was started in' : top);
}

/**
 * The top of the cwd chain: the first folder from `realCwd` up that holds `.git`, else the first that holds a
 * package.json or a node_modules, else `realCwd`; null when `realCwd` is the home folder or above it.
 */
async function startTop(realCwd: string): Promise<string | null> {
  const home = await realpath(homedir()).catch(() => resolve(homedir()));
  /** False for the home folder and every folder that holds it (up to the root). */
  const notHomeOrAbove = (f: string) => {
    const homeFromF = relative(f, home);
    return homeFromF === '..' || homeFromF.startsWith(`..${sep}`) || isAbsolute(homeFromF);
  };
  if (!notHomeOrAbove(realCwd)) return null;
  const exists = async (p: string) => (await lstat(p).catch(() => null)) !== null;
  let npmTop: string | null = null;
  for (let f = realCwd, n = 0; notHomeOrAbove(f) && n < SWAP_WALK_MAX; n++) {
    if (await exists(join(f, '.git'))) return f;
    if (npmTop === null && (await exists(join(f, 'package.json')) || await exists(join(f, 'node_modules')))) npmTop = f;
    const up = dirname(f);
    if (up === f) break;
    f = up;
  }
  return npmTop ?? realCwd;
}

/** The checks for each folder from `top/rel` up to and including `top`; `topName` names `top` in the answer. */
async function chainWhy(top: string, rel: string, topName: string): Promise<string | null> {
  const parts = rel === '' ? [] : rel.split(sep);
  if (parts.length >= SWAP_WALK_MAX) return 'a folder nested too deep for pipegen to check';
  const index = await readGitIndexPaths(top);
  const folders = parts.map((_, i) => parts.slice(0, parts.length - i).join('/')).concat(['']);
  const committed = index === null ? null : committedNodeModules(index, folders);
  const gitInfo = index === null ? await lstat(join(top, '.git')).catch(() => null) : null;
  const noIndex = gitInfo?.isFile() === true
    ? '.git is a file here (a git worktree or submodule), so pipegen can\'t read its git index'
    : 'pipegen found no git index it can read';
  for (const relFolder of folders) {
    const folder = relFolder === '' ? top : join(top, ...relFolder.split('/'));
    const where = relFolder === '' ? topName : relFolder;
    if (await npmrcHasUnsafeKey(folder)) return `an .npmrc with settings that can change what npm runs, in ${where}`;
    if ((await lstat(join(folder, 'node_modules', '.bin', 'pipegen')).catch(() => null)) !== null) return `a local pipegen (node_modules/.bin/pipegen), in ${where}`;
    if (committed === null) {
      if ((await lstat(join(folder, 'node_modules')).catch(() => null)) !== null) return `a node_modules folder pipegen can't tell is not committed (${noIndex}), in ${where}`;
    } else if (committed.has(relFolder.toLowerCase())) {
      return `a committed node_modules folder, in ${where}`;
    }
  }
  return null;
}

/**
 * Of `folders` (repo-relative, '' for the top), those whose node_modules the index lists (the folder itself, a
 * committed link, or anything under it), in any letter case. One pass over the index, lower-cased keys.
 */
function committedNodeModules(index: ReadonlySet<string>, folders: readonly string[]): Set<string> {
  const wanted = new Set(folders.map((f) => f.toLowerCase()));
  const out = new Set<string>();
  for (const p of index) {
    const segs = p.toLowerCase().split('/');
    for (let i = 0; i < segs.length; i++) {
      if (segs[i] !== 'node_modules') continue;
      const parent = segs.slice(0, i).join('/');
      if (wanted.has(parent)) out.add(parent);
    }
  }
  return out;
}

/** True when swapRiskWhy has an answer: started from `cwd`, `npx pipegen` could run something other than pipegen. */
export async function swapRisk(cwd: string, dir: string): Promise<boolean> {
  return (await swapRiskWhy(cwd, dir)) !== null;
}

async function npmrcHasUnsafeKey(dir: string): Promise<boolean> {
  const path = join(dir, '.npmrc');
  const info = await lstat(path).catch(() => null);
  if (info === null) return false;
  if (info.isSymbolicLink() || !info.isFile()) return true; // npm would follow it; pipegen won't, so it can't say no
  const text = await readTextLimited(path);
  if (text === null) return true;
  return text.split(/\r\n|\r|\n/).some((line) => !npmrcLineIsSafe(line));
}

/**
 * One `.npmrc` line: blank, a comment (`#` or `;`), or `key = value` with a key on the safe list (quotes around the
 * key allowed, any letter case). A bare key (npm reads it as `key=true`), a section header or anything else is unsafe.
 */
function npmrcLineIsSafe(raw: string): boolean {
  const line = raw.trimStart();
  if (line === '' || line.startsWith('#') || line.startsWith(';')) return true;
  const eq = line.slice(0, NPMRC_KEY_WINDOW).indexOf('=');
  if (eq < 0) return false;
  const written = line.slice(0, eq).trim();
  const key = (/^(["'])(.*)\1$/.exec(written)?.[2] ?? written).toLowerCase();
  if (key === 'audit') return /^(?:true|false)$/.test(line.slice(eq + 1, eq + 1 + NPMRC_KEY_WINDOW).trim());
  const strict = NPMRC_STRICT_VALUES.get(key);
  if (strict !== undefined) return strict.test(line.slice(eq + 1, eq + 1 + NPMRC_KEY_WINDOW).trim());
  return NPMRC_SAFE_KEYS.has(key);
}

// ---------- addAiSuggestions (`audit --ai`, Task 2b) ----------

export interface AiSuggestDeps {
  ai: AiProvider; gh: Octokit; memory: MemoryStore; fetch: typeof fetch;
  /** The FULL reviewed list (discovery's look-alike check uses all of it); [] when the caller couldn't load it (B3). */
  reviewed: ReviewedTool[];
  /** loadQualityBar(), loaded once per run by the CLI. */
  bar: QualityBar;
  /** The run's one newRateBudget(), shared with every GitHub call (ruling S18). */
  budget: RateBudget;
  now: () => number;
  sleep?: (ms: number) => Promise<void>;
  /** The GitHub token (when set) and the AI key in use: never sent to the AI, never in the report (ruling S19). */
  knownValues: string[];
  /**
   * The checked secret scanner `name` (its path and version): the one the consent screen named. Default:
   * ensurePinnedBinary(name) and its pinned version. Called right before the bundle is built.
   */
  ensureSecretScanner?: (name: SecretScannerName) => Promise<SecretScanner>;
  /** No GitHub token: the search may stop early (ruling S17). */
  anonymous: boolean;
  /**
   * estimateAuditAi(provider, needCount, needsRequestBytes(r, knownValues)).capUsd, exactly as the consent screen showed
   * it: a hard cap on this step's AI spend (rulings B2, U13). null only for a local model (no cap): for a paid provider null counts as 0, so every AI call is refused (review H1).
   */
  capUsd: number | null;
  /**
   * The user's yes to the `audit --ai` consent screen (askConsent; Plan U T4b): no AI step without it. Its terms must
   * match `ai` (provider, model, Ollama host) and `capUsd`, and only files it counted may be sent.
   */
  consent: ConsentToken;
  /**
   * P40/P45: called with the secret-scanned bundle's `found` (flagged names, found values). The caller passes it to the
   * renderer (RenderOptions.found), so what the scan found is masked in the whole report, plain-audit parts too.
   */
  onScanFound?: (found: ScanFound) => void;
}

const AI_NOTE = {
  onlyActionsNpm: "In this version only GitHub Actions and npm packages can become suggestions (other tools can't be checked for known vulnerabilities yet).",
  // Ruling S17's text reworded: "No token: …" would be cut by redact() at output (notes are never "<secret-like word>: …").
  anonymous: 'Without a GitHub token, GitHub allows 60 requests an hour, so tool suggestions may stop early. Set GITHUB_TOKEN (read-only) for a full search.',
  lookAlike: "pipegen's reviewed tool list isn't usable in this build, so it couldn't check suggested tools for look-alike names; it shows no tool suggestions.",
  noSecretScan: (name: SecretScannerName, why: string) => `The AI step was skipped and nothing was sent to the AI: the required ${name} check couldn't run. ${why}`
    // the fallback, in words: pipegen's output cleaning (redact) would hide a `NAME=value` form
    + (name === 'betterleaks' ? ` To use the gitleaks fallback instead, set ${SECRET_SCANNER_ENV} to gitleaks and run again.` : ''),
  // the backstop (review I1): the walk reads only counted files, so this means a bug, not something the user can fix
  notConsented: "Nothing was sent to the AI: after the secret scan, the code held a file that wasn't on the consent screen, and pipegen sends only files it showed you.",
  stopped: (why: string) => `The AI step stopped: ${why}.`,
  searchStopped: (why: string) => `The tool search stopped: ${why}.`,
  fallbackTried: "Claude's refusal fallback had already run the request again on another Claude model, and it was declined there too.",
  /** The needs call (or its retry) didn't fit the cap: no AI call was made for it (ruling U13). */
  needsCapped: (cap: number) => `The AI step stopped: ${AI_KIND_TEXT['cost-cap']} (${usd(cap)}).`,
} as const;
/** Ruling S16: what each AI failure means, in plain words (pipegen's own text, never the provider's). */
const AI_KIND_TEXT: Readonly<Record<AiErrorKind, string>> = {
  timeout: "the AI didn't answer in time",
  invalid: "the AI's answer didn't match the expected format",
  http: 'the AI provider refused the request (check the key, the quota and the model name)',
  missing: 'no AI provider is set up',
  refusal: 'the AI declined the request',
  truncated: "the AI's answer was cut off",
  'cost-cap': 'one more AI call could pass the AI cost limit you agreed to',
};

// The audit's AI spend meter (ruling U13) lives in src/ai/spend-meter.ts since Plan E ruling B4 (one meter for the audit and the
// proof run); it is exported from here too, so the audit's callers and tests keep their import.
export { AiSpendMeter };

/**
 * The needs request's size (UTF-8 bytes) for estimateAuditAi, before consent: the counting bundle's bytes (aiBundle)
 * plus the rest of the needs prompt. The secret-scanned bundle sent after consent is normally the same files and the
 * same size. It can come out larger (replacements shrink files, so the cut to maxBytes keeps more of them): that extra
 * is paid out of the DISCOVERY share of the cap (the cap holds the needs call's worst case PLUS one discovery call's;
 * the framing margin is on both sides of the comparison, so it absorbs nothing). Past that share, the meter refuses
 * the needs call with a note and nothing is sent (review N6). Don't drop the discovery term from the cap.
 */
export function needsRequestBytes(r: AuditReport, knownValues: string[]): number {
  return r.aiBundle.bytes + needsPromptBytes(r.profile, r.capabilities, { knownValues });
}

/**
 * T4b (review M1, M2): the AI step runs only on a ConsentToken askConsent really issued for the audit --ai screen,
 * not used before, given for this provider, model (and Ollama host) and cap, and for the files counted in this folder
 * (a CountingSummary whose real path is `dir`'s). Anything else is a programming error, thrown before anything runs.
 * The token is then spent: a second AI step needs a new yes. Returns the counted files.
 */
async function checkConsent(dir: string, deps: AiSuggestDeps): Promise<CountingSummary> {
  const c: unknown = deps.consent;
  if (!ConsentToken.isToken(c) || c.terms.mode !== 'audit-ai') {
    throw new Error('addAiSuggestions needs the consent token askConsent() gives for the audit --ai screen; nothing was sent.');
  }
  if (isSpent(c)) throw new Error('This consent was already used for an AI step; each AI step needs its own yes. Nothing was sent.');
  // Spent here, before the first await, so two steps started at once can't both pass (review N1). A token refused by a
  // check below is spent too: the safe side, since the next AI step then needs a new yes.
  spend(c);
  const t = c.terms;
  const host = deps.ai.name === 'ollama' ? ollamaHostOf(deps.ai) ?? undefined : undefined;
  if (t.pricedFor.provider !== deps.ai.name || t.pricedFor.model !== deps.ai.model || t.pricedFor.host !== host || t.capUsd !== deps.capUsd) {
    throw new Error('addAiSuggestions was given another AI provider, model or cost cap than the user agreed to; nothing was sent.');
  }
  const files = t.files;
  const here = await realpath(dir).catch(() => null);
  if (!CountingSummary.isSummary(files) || t.dir === null || files.dir !== t.dir || here !== t.dir) {
    throw new Error('This consent was given for the files counted in another folder; nothing was sent.');
  }
  return files;
}

/** The service's own test/lint script would run for this need (S27: a service without tests has none for tests). */
function hasProjectScript(need: Need, p: RepoProfile): boolean {
  const service = need.service === undefined ? undefined : p.services.find((s) => s.name === need.service);
  if (service === undefined) return false;
  if ((need.category === 'unit-tests' || need.category === 'full-tests') && !service.hasTests) return false;
  return projectScriptFor(need, service) !== null;
}

/**
 * The pinned scanner `name`, downloaded and verified (ensurePinnedBinary), with its pinned version. The version comes
 * from the same pins table the binary is checked against (review M3), so the consent check below binds the version the
 * screen showed to the binarySha256 of the binary that runs. With a caller's ensureSecretScanner, that check guards
 * against the dependency handing back another scanner or version.
 */
async function defaultSecretScanner(name: SecretScannerName): Promise<SecretScanner> {
  const pins = loadPinnedBinaries();
  const path = await ensurePinnedBinary(name, undefined, { pins });
  return { name, path, version: pins[name].version };
}

/**
 * `audit --ai`, after consent: the needs the AI adds and mention-only tool suggestions, in `ai` of a copy of `r`
 * (the rest of the report is unchanged).
 * 0. `deps.consent` must be the ConsentToken askConsent gave for the audit --ai screen, for this provider, model, cap
 *    and folder, not used before (Plan U T4b, review M1/M2); anything else is thrown before anything runs, and the token
 *    is spent. The secret scan's walk reads only the files the screen counted (onlyPaths, review I1); covers() is the
 *    backstop (a note, nothing sent). File content can change between the count and the send; the cap still holds (M3).
 * 1. The secret scanner the consent screen named (betterleaks, or gitleaks with PIPEGEN_SECRET_SCANNER) is made ready
 *    right before the bundle is built with it (the path stays a local variable). No binary, another scanner or version
 *    than the screen named, or a scanner failure (an exit code other than clean/found): no AI call, a note (for
 *    betterleaks it names the gitleaks fallback).
 * 2. planNeeds(…, writers 0, knownValues): the needs it adds become `extraNeeds`; floor needs are never changed.
 * 3. suggestTools for every floor need that isn't covered, and every added need, that has no project script (it skips
 *    needs a reviewed tool covers). Skipped when the reviewed list is unavailable (look-alike checks need it; B3/U11).
 * Every AI attempt goes through an AiSpendMeter: a hard cap at `deps.capUsd` (ruling U13). An attempt that could pass it
 * is never sent: the needs call then stops the AI step with a note; a discovery call stops asking the AI (one note).
 * An AiError never escapes (S16): it becomes a note, and its billed usage still counts. Other errors are thrown.
 */
export async function addAiSuggestions(r: AuditReport, dir: string, deps: AiSuggestDeps): Promise<AuditReport> {
  const counted = await checkConsent(dir, deps);
  const notes = new Set<string>();
  // every AI attempt goes through the meter: the one record of usage and the hard cap (ruling U13, review M1)
  const meter = new AiSpendMeter(deps.ai, deps.capUsd);
  // a model with no price can't keep a hard cap: nothing is sent (ruling U14; the CLI already stops before consent)
  const unpriced = meter.effectiveCapUsd === null ? null : unpricedModel(deps.ai);
  let extraNeeds: Need[] = [];
  let suggestions: PipelineDraft['suggestions'] = [];
  const known = deps.knownValues.filter((v) => typeof v === 'string' && v.trim() !== '');
  const scrub = (t: string) => (known.length > 0 ? scrubKnownValues(t, known) : t);
  const done = (): AuditReport => {
    if (deps.anonymous) notes.add(AI_NOTE.anonymous);
    notes.add(AI_NOTE.onlyActionsNpm);
    return {
      ...r,
      ai: {
        extraNeeds: extraNeeds.map((n) => ({ ...n, why: scrub(n.why) })),
        // fail closed: no suggestion without the full reviewed list (B3/U11)
        suggestions: r.reviewedUnavailable ? [] : suggestions.map((x) => ({ name: scrub(x.name), repo: scrub(x.repo), why: scrub(x.why) })),
        notes: [...new Set([...notes].map(scrub))],
        usage: { ...meter.usage },
        costUsd: meter.costUsd,
        attempts: meter.attempts.map((a) => ({ ...a })),
        local: deps.ai.name === 'ollama',
        capUsd: meter.effectiveCapUsd,
      },
    };
  };

  if (unpriced !== null) {
    notes.add(unpriced.message);
    return done();
  }

  // 1. The secret-scanned bundle: the scanner the user was shown is made ready right before it runs, and its path is
  //    never kept.
  const named = deps.consent.terms.secretScanner;
  let bundle: CodeBundle;
  try {
    const scanner = await (deps.ensureSecretScanner ?? defaultSecretScanner)(named.name);
    if (scanner.name !== named.name || scanner.version !== named.version) {
      throw new SecretScanError(`pipegen was given ${safeText(scanner.name, 20)} ${safeText(scanner.version, 20)}, not the ${named.name} ${named.version} the consent screen named, and ran neither.`);
    }
    // only the files the consent screen counted (review I1): the checked bundle can only shrink
    bundle = await bundleCode(dir, { secretScanner: scanner, knownValues: deps.knownValues, onlyPaths: counted.paths() });
    deps.onScanFound?.(bundle.found);
  } catch (e) {
    if (!(e instanceof PinnedBinaryError || e instanceof SecretScanError)) throw e;
    notes.add(AI_NOTE.noSecretScan(named.name, e.message));
    return done();
  }
  // only files the user agreed to (the consent screen counted them before the secret scan, ruling S21)
  if (!counted.covers(bundle)) {
    notes.add(AI_NOTE.notConsented);
    return done();
  }
  const reportNotes = new Set(r.notes);
  for (const n of bundle.notes) if (!reportNotes.has(redact(n))) notes.add(n);

  // 2. The needs the AI adds.
  let plan: NeedsPlan;
  try {
    plan = await planNeeds(r.profile, r.capabilities, bundle, meter.provider, 0, { knownValues: deps.knownValues });
  } catch (e) {
    if (!(e instanceof AiError)) throw e;
    notes.add(e.kind === 'cost-cap' && meter.effectiveCapUsd !== null ? AI_NOTE.needsCapped(meter.effectiveCapUsd) : AI_NOTE.stopped(AI_KIND_TEXT[e.kind]));
    if (e.kind === 'refusal' && refusalFallbackNoteFor(deps.ai) !== null) notes.add(AI_NOTE.fallbackTried);
    return done();
  }
  for (const n of plan.notes) notes.add(n);
  const floor = new Set(floorNeeds(r.profile, r.capabilities).map(needKey));
  extraNeeds = plan.needs.filter((n) => !floor.has(needKey(n)));

  // 3. Mention-only tool suggestions.
  if (r.reviewedUnavailable) {
    notes.add(AI_NOTE.lookAlike);
    return done();
  }
  // Extra needs have no coverage row: they count as not covered.
  const search = [...r.coverage.filter((c) => c.status !== 'covered').map((c) => c.need), ...extraNeeds].filter((n) => !hasProjectScript(n, r.profile));
  if (search.length === 0) return done();
  // A discovery call that doesn't fit the cap is refused by the meter (AiError 'cost-cap'); discovery then asks the AI
  // nothing more, gives one note, and goes on with search results only.
  const found: string[] = [];
  try {
    suggestions = await suggestTools(search, r.profile, {
      ai: meter.provider, gh: deps.gh, memory: deps.memory, fetch: deps.fetch, reviewed: deps.reviewed, mode: 'audit', bar: deps.bar,
      budget: deps.budget, now: deps.now, ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }), notes: found,
    });
  } catch (e) {
    // defensive: discovery handles AI errors per need. Its usage was already recorded by the meter, attempt by attempt.
    if (!(e instanceof AiError)) throw e;
    notes.add(AI_NOTE.searchStopped(AI_KIND_TEXT[e.kind]));
  }
  for (const n of found) notes.add(n);
  return done();
}
