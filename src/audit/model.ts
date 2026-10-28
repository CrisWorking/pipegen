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
//   fact; no value is kept); anonymous access.
// - ai (Task 2b, addAiSuggestions, `audit --ai` after consent): the needs the AI adds and MENTION-ONLY tool suggestions,
//   from a secret-scanned bundle, with the run's AI usage and cost cap (rulings B2, B3, B4, S11, S16-S19, U11).
//
// Output rule (src/types.ts): repo-derived strings are kept RAW (validated by the readers) and cleaned only where
// Task 3 prints them. Nothing here escapes a value, and no file content or secret value is ever stored.
import { lstat, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { count, outputLimit } from '../ai/errors.js';
import { ollamaHostOf } from '../ai/ollama.js';
import { AiError, COST_CAP_MESSAGE, refusalFallbackNoteFor, type AiErrorKind } from '../ai/provider.js';
import {
  bundleCode, bundleTopFolders, COUNTING_ONLY_NOTE, countedBundleRoot, EXCLUDED_PATTERNS, findSecretLike, isExcludedPath, redact, SecretScanError, type SecretScanner,
  scrubKnownValues, type CodeBundle,
} from '../ai/redact.js';
import { needLanguage, suggestTools } from '../engine/discover.js';
import type { RateBudget } from '../engine/github-rate.js';
import { ensurePinnedBinary, loadPinnedBinaries, PinnedBinaryError } from '../engine/linters.js';
import type { MemoryStore } from '../engine/memory.js';
import { CHECK_LABELS, floorNeeds, isRunnable, jobCategories, needKey, needsPromptBytes, planNeeds, type NeedsPlan } from '../engine/needs.js';
import type { QualityBar } from '../engine/quality-bar.js';
import { projectScriptFor, type WouldAddTool } from '../engine/reviewed.js';
import {
  activity30d, aiRequestBytes, estimate, requestCeilingUsd, unpricedModel, usageCeilingUsd, usageCostUsd, type Activity, type Estimates,
} from '../estimate/estimate.js';
import { signingMode } from '../github/signing-mode.js';
import { IGNORED_DIRS, listFiles, READ_LIMITS, readTextLimited, readTextLimitedWithReason } from '../read/limits.js';
import { readProject } from '../read/project.js';
import { supportLevel } from '../read/support.js';
import { skippedWorkflowCount } from '../read/workflows.js';
import {
  DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage, type Capabilities, type Need, type Part, type PipelineDraft, type RepoProfile,
  type ReviewedTool, type Service,
  type NeedCategory,
} from '../types.js';
import { usd } from '../util/format.js';
import { packageVersion } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { ConsentToken, CountingSummary, isSpent, spend } from './consent-token.js';
import { chooseTools, skippedGroups, wouldSetSettings, type SkippedGroup, type WouldSet } from './choose.js';
import { mapCoverage, type Coverage } from './coverage.js';

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
  profile: RepoProfile; capabilities: Capabilities; support: AuditSupport;
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
  /** What the full run would send to the AI (counts and folder names, never contents). */
  aiBundle: { files: number; bytes: number; truncated: boolean; excludedPatterns: string[]; topFolders: string[] };
  /** How pipegen was started (a repo .npmrc with a registry, a local node_modules/.bin/pipegen) and anonymous access. */
  warnings: AuditWarning[];
  /** Reader, workflow, capability-probe, bundle, coverage and secrets-scan notes; deduped (ruling S11), each passed through redact() (a secret-like file name in a reader note is masked). */
  notes: string[];
  /** Ruling U11: the caller couldn't use the reviewed list (B3). Task 2b drops every discovery suggestion when true. */
  reviewedUnavailable: boolean;
  /** Only with --ai, after consent (Task 2b, addAiSuggestions); mention-only. */
  ai?: AuditAi;
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
  usage: Required<AiUsage>;
  /**
   * ABOUT what the AI step cost at list price (USD): the sum of `attempts[].listUsd`. It is an approximation: cache reads
   * are priced as full input (no cache discount), and a run the refusal fallback sent to another model is priced at the
   * primary model's list price. Each attempt is priced in the tier its own prompt length falls in. 0 for a local model.
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
export interface AiAttempt {
  model: string;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  listUsd: number;
}

export interface AuditDeps {
  /** Always set; an anonymous client works for a public repo. */
  gh: Octokit;
  anonymous: boolean;
  /** readGitHubContext's answer (the CLI reads it; ruling B1). */
  context: Pick<RepoProfile, 'private' | 'ownerType' | 'plan' | 'defaultBranch'>;
  capabilities: Capabilities;
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

export const NAME_HIDDEN = '(a file whose name looks like a secret)';
export const EXCLUDED_NOTE = "(never sent to the AI; check it isn't committed)";
const NAME_RULE = 'secret-like-name';
const MAX_SECRET_ROWS = 200;
/** Secrets scan budget: past this many bytes read, the rest isn't scanned (with a note). */
const MAX_SCAN_BYTES = 200_000_000;
const SKIPPED_DIRS_NOTE = `The secrets scan did not check dependency and build folders (${IGNORED_DIRS.filter((d) => d !== '.git').join(', ')}) or .git, so committed build output was not checked either.`;
const UNTRACKED_NOTE = "pipegen reads the files on disk without git, so files that aren't committed (for example a local .env) are in this list too.";

// Worded so redact() leaves it whole at output ("No token: …" would be cut; review M3).
const NO_TOKEN = 'Without a GitHub token, pipegen reads public data only and is rate-limited.';
const SWAP_TEXT = 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with:';
const SWAP_TEXT_NO_COMMAND = 'This repo could change which pipegen runs. Run pipegen from outside the repo, from the npm registry, with an exact version (pipegen@x.y.z).';
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
  const local = await readProject(dir, { notes: readerNotes });
  const profile: RepoProfile = {
    ...local,
    private: deps.context.private, ownerType: deps.context.ownerType, plan: deps.context.plan, defaultBranch: deps.context.defaultBranch,
  };
  for (const n of readerNotes) notes.add(n);
  for (const n of deps.notes ?? []) notes.add(n);
  for (const n of libraryNotes(profile)) notes.add(n);

  const caps = deps.capabilities;
  const needs = floorNeeds(profile, caps);

  const coverage = await coverageOf(profile, needs, dir, skippedWorkflowCount(readerNotes), notes, caps);
  const wouldAdd = wouldAddRows(profile, coverage, deps, caps);

  const activity = await activityOf(deps, profile);
  const estimates = estimate(profile, jobCategories(needs), 2, activity ?? { pushes: 0, prs: 0, capped: false }, { name: 'claude', model: DEFAULT_MODEL });
  if (activity === null) {
    const line = "Activity: pipegen couldn't read this repo's pushes and pull requests for the last 30 days, so monthly minutes assume 0 of each (the real number is likely higher).";
    const at = estimates.basis.findIndex((b) => b.startsWith('Activity:'));
    if (at >= 0) estimates.basis[at] = line;
    else estimates.basis.push(line);
  }

  const secretsInTree = await scanTree(dir, notes);

  const bundle = await countingBundle(dir, deps.bundle);
  // A counting-only bundle says it "cannot be sent to the AI"; nothing is sent here, so that note would only confuse.
  for (const n of bundle.notes) if (n !== COUNTING_ONLY_NOTE) notes.add(n);

  return {
    profile,
    capabilities: caps,
    support: supportOf(profile),
    coverage,
    wouldAdd,
    skipped: skippedGroups(profile, caps),
    wouldSet: wouldSetSettings(profile, coverage),
    wouldCreate: wouldCreateOf(profile),
    testsNote: profile.services.length === 0 ? NO_SERVICE_TO_TEST : null,
    estimates,
    permissions: deps.permissions,
    limits: limitsOf(profile, caps),
    secretsInTree,
    aiBundle: {
      files: bundle.files.length, bytes: bundle.bytes, truncated: bundle.truncated,
      excludedPatterns: [...EXCLUDED_PATTERNS], topFolders: bundleTopFolders(bundle),
    },
    warnings: await warningsOf(dir, deps.anonymous),
    notes: notes.all(),
    reviewedUnavailable: deps.reviewedUnavailable === true,
  };
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
  secretsInTree: SecretInTree[];
  aiBundle: AuditReport['aiBundle'];
  /** The `.npmrc` / node_modules/.bin/pipegen warning (no anonymous-access warning: pipegen doesn't know the access). */
  warnings: AuditWarning[];
  notes: string[];
}

/** The local-only audit of `dir`: reads files only (no GitHub, no AI, no child process). Throws NotGitHubRepoError like buildAudit. */
export async function buildLocalAudit(dir: string, deps: { notes?: string[] } = {}): Promise<LocalAudit> {
  const notes = new Notes();
  const readerNotes: string[] = [];
  const profile = await readProject(dir, { notes: readerNotes });
  for (const n of readerNotes) notes.add(n);
  for (const n of deps.notes ?? []) notes.add(n);
  const secretsInTree = await scanTree(dir, notes);
  const bundle = await bundleCode(dir);
  for (const n of bundle.notes) if (n !== COUNTING_ONLY_NOTE) notes.add(n);
  return {
    profile,
    secretsInTree,
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
async function coverageOf(p: RepoProfile, needs: Need[], dir: string, skippedWorkflows: number, notes: Notes, capabilities: Capabilities): Promise<Coverage[]> {
  try {
    // Plan P Task 3 (PS16): the capabilities too, so an action this repo can't use is never read as covered
    return await mapCoverage(p, needs, dir, { skippedWorkflows, noImage: (need) => buildsNoImage(need, p), capabilities });
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
    const { tool, also, note } = pick(need, starter ? undefined : service, p, deps, caps);
    rows.push({ need, status: c.status, tool, also, note: starter ? starterTests(service.name) : note });
  }
  return rows;
}

/**
 * Ruling S7, extended by Plan P Task 8: pipegen's own check → the service's own script → chooseTools (the catalogue's
 * choose-rules; the first reviewed entry for a check without a rule, PS35) → nothing. The list unavailable (B3/U11)
 * keeps its own note on a row that ends with no tool.
 */
function pick(need: Need, service: Service | undefined, p: RepoProfile, deps: AuditDeps, caps: Capabilities): { tool: WouldAddTool; also: WouldAddTool[]; note: string } {
  if (isBuiltInNeed(need)) return { tool: { kind: 'built-in' }, also: [], note: ROW_NOTE.builtIn };
  const script = service === undefined ? null : projectScriptFor(need, service);
  if (script !== null) return { tool: script, also: [], note: ROW_NOTE.script(script.script) };
  const choice = chooseTools(need, service, p, caps, deps.reviewed);
  if (choice.tool !== null) return { tool: choice.tool, also: choice.also, note: choice.note };
  if (deps.reviewedUnavailable === true) return { tool: null, also: [], note: ROW_NOTE.unavailable };
  return { tool: null, also: [], note: choice.note === '' ? ROW_NOTE.suggestion : choice.note };
}

function wouldCreateOf(p: RepoProfile): { what: Part; why: string }[] {
  const out: { what: Part; why: string }[] = [];
  if (p.precommit === null) out.push({ what: 'precommit', why: 'No git hook manager found: pipegen would set up pre-commit hooks that check each commit.' });
  for (const s of p.services) {
    if (isRunnable(s) && (s.dockerfile ?? '') === '') out.push({ what: 'docker', why: `${s.name} runs but has no Dockerfile: pipegen would create one, so the image can be built and scanned.` });
  }
  const kinds = [...new Set(p.services.flatMap((s) => s.dependsOn.map((d) => d.kind)).filter((k) => k !== 'external'))].sort();
  if (kinds.length > 0) out.push({ what: 'compose', why: `The app uses ${kinds.join(', ')}: pipegen would create a Compose file that starts them for the tests.` });
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
 */
async function scanTree(dir: string, notes: Notes): Promise<SecretInTree[]> {
  const listing = await listFiles(dir, ['**/*'], IGNORED_DIRS.map((d) => `**/${d}/**`));
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
    const read = await readTextLimitedWithReason(abs);
    if (!('text' in read)) {
      if (read.skipped === 'unreadable') unreadable++;
      continue;
    }
    const text = read.text;
    bytes += Buffer.byteLength(text);
    for (const rule of findSecretLike(text).sort()) add({ file, rule, ...extra });
  }
  notes.add(SKIPPED_DIRS_NOTE);
  if (listing.truncated) notes.add('The secrets scan stopped listing files at the file limit; the rest were not checked.');
  if (stopped) notes.add(`The secrets scan stopped after ${MAX_SCAN_BYTES / 1_000_000} MB of files; the rest were not checked.`);
  if (tooLarge > 0) notes.add(`The secrets scan skipped ${tooLarge === 1 ? '1 file' : `${tooLarge} files`} larger than 1 MB.`);
  if (unreadable > 0) notes.add(`The secrets scan couldn't read ${unreadable === 1 ? '1 file' : `${unreadable} files`} (no permission, or it changed while being read); ${unreadable === 1 ? 'it was' : 'they were'} not checked.`);
  if (more > 0) notes.add(`…and ${more} more secret-like findings not listed.`);
  if (rows.length > 0) notes.add(UNTRACKED_NOTE);
  return rows;
}

// ---------- how pipegen was started ----------

/**
 * Ruling S30 / Review Focus 9 / U12: a repo `.npmrc` with any key outside NPMRC_SAFE_KEYS, or a local
 * node_modules/.bin/pipegen, could change which pipegen runs when started from inside the repo. The `.npmrc` is read
 * only for that yes/no (key names, and the value of `audit` compared with true/false; no value is kept); one that
 * can't be read safely (a symbolic link, too large) counts as yes.
 * node_modules/.bin/pipegen is an existence check with lstat: the last part is never followed (a dangling link
 * counts), while a symlinked node_modules or .bin folder on the way is followed, as npx would follow it too.
 */
async function warningsOf(dir: string, anonymous: boolean): Promise<AuditWarning[]> {
  const out: AuditWarning[] = [];
  if (await npmrcHasUnsafeKey(dir) || (await lstat(join(dir, 'node_modules', '.bin', 'pipegen')).catch(() => null)) !== null) {
    const command = safeRunCommand(packageVersion());
    out.push(command !== null ? { text: SWAP_TEXT, command } : { text: SWAP_TEXT_NO_COMMAND });
  }
  if (anonymous) out.push({ text: NO_TOKEN });
  return out;
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
  /** The checked secret scanner (its path and version); default ensurePinnedBinary('gitleaks'). Called right before the bundle is built. */
  ensureSecretScanner?: () => Promise<SecretScanner>;
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
}

const AI_NOTE = {
  onlyActionsNpm: "In this version only GitHub Actions and npm packages can become suggestions (other tools can't be checked for known vulnerabilities yet).",
  // Ruling S17's text reworded: "No token: …" would be cut by redact() at output (notes are never "<secret-like word>: …").
  anonymous: 'Without a GitHub token, GitHub allows 60 requests an hour, so tool suggestions may stop early. Set GITHUB_TOKEN (read-only) for a full search.',
  lookAlike: "pipegen's reviewed tool list isn't usable in this build, so it couldn't check suggested tools for look-alike names; it shows no tool suggestions.",
  noSecretScan: (name: string, why: string) => `The AI step was skipped and nothing was sent to the AI: the required ${name} check couldn't run. ${why}`,
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

/**
 * The audit's AI spend meter (ruling U13), the single record of what the AI calls of this step used (review M1). Every
 * attempt goes through `provider` (planNeeds and suggestTools get it; completeValidated's retries are attempts of their
 * own), and before one is sent the meter reserves its worst case (requestCeilingUsd: every byte a token, the full output
 * limit, the highest price it could bill at). An attempt that doesn't fit (spent + reserved + its worst case > cap) is
 * refused with AiError('cost-cap') and never sent, the needs call included. After the attempt, the reservation is swapped
 * for the cost of its usage at the same prices; an error without usage (a timeout, a dropped connection) keeps the full
 * reservation, since the provider may still bill what it produced. capUsd null: nothing is refused for a local model (Ollama); for a paid provider null counts as 0, so everything is refused (review H1).
 */
export class AiSpendMeter {
  /** USD settled so far (usage priced at the ceiling rates, plus the reservations of attempts that ended without usage). */
  spentUsd = 0;
  /** USD reserved for attempts in flight. */
  reservedUsd = 0;
  /** Every attempt's usage, summed (failed attempts that reported usage included). */
  readonly usage: Required<AiUsage> = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
  /** Each settled attempt with its own list cost (tier by its own prompt length); costUsd is their sum. */
  readonly attempts: AiAttempt[] = [];
  /** The cap in force: capUsd, except that null means 0 for a paid provider. null only for Ollama (no cap). */
  readonly effectiveCapUsd: number | null;
  /** What planNeeds and suggestTools are given: the same name and model, every call metered (no other field is copied). */
  readonly provider: AiProvider;
  readonly #inner: AiProvider;
  constructor(inner: AiProvider, readonly capUsd: number | null) {
    this.#inner = inner;
    this.effectiveCapUsd = capUsd === null && inner.name !== 'ollama' ? 0 : capUsd;
    this.provider = { name: inner.name, model: inner.model, complete: (req) => this.#complete(req) };
  }
  async #complete(req: AiRequest): Promise<{ data: unknown; usage: AiUsage }> {
    let reserved = 0;
    const cap = this.effectiveCapUsd;
    if (cap !== null) {
      // one validator for the output limit (review N3): anything set but not a whole number above 0 is refused here;
      // no limit at all means no bound (Infinity), so the attempt can't fit any cap
      const worst = requestCeilingUsd(this.#inner, aiRequestBytes(req), outputLimit(req.maxOutputTokens) ?? Number.POSITIVE_INFINITY);
      if (worst !== 'local') {
        if (!(this.spentUsd + this.reservedUsd + worst <= cap)) throw new AiError('cost-cap', COST_CAP_MESSAGE);
        reserved = worst;
        this.reservedUsd += worst;
      }
    }
    let r: { data: unknown; usage: AiUsage };
    try {
      r = await this.#inner.complete(req);
    } catch (e) {
      if (e instanceof AiError && e.usage !== undefined) this.#settle(reserved, e.usage);
      else this.#keep(reserved);
      throw e;
    }
    this.#settle(reserved, r.usage);
    return r;
  }
  #settle(reserved: number, u: AiUsage | undefined): void {
    // An answer that reports no prompt tokens can't be priced: keep the full reservation (review N5).
    if (u === undefined || u === null || count(u.inputTokens) + count(u.cacheReadTokens) + count(u.cacheWriteTokens) === 0) {
      if (u !== undefined && u !== null) this.#addUsage(u);
      this.#keep(reserved);
      return;
    }
    this.reservedUsd -= reserved;
    this.#addUsage(u);
    const c = usageCeilingUsd(this.#inner, u);
    if (c !== 'local') this.spentUsd += c;
  }
  /** Total list cost of the attempts (USD). */
  get costUsd(): number {
    return this.attempts.reduce((sum, a) => sum + a.listUsd, 0);
  }
  #addUsage(u: AiUsage): void {
    const listUsd = usageCostUsd(this.#inner, u);
    this.attempts.push({
      model: this.#inner.model, input: count(u.inputTokens), output: count(u.outputTokens),
      cacheRead: count(u.cacheReadTokens), cacheWrite: count(u.cacheWriteTokens), listUsd: listUsd === 'local' ? 0 : listUsd,
    });
    this.usage.inputTokens += count(u.inputTokens);
    this.usage.outputTokens += count(u.outputTokens);
    this.usage.cacheReadTokens += count(u.cacheReadTokens);
    this.usage.cacheWriteTokens += count(u.cacheWriteTokens);
  }
  #keep(reserved: number): void {
    this.reservedUsd -= reserved;
    this.spentUsd += reserved;
  }
}

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
 * `audit --ai`, after consent: the needs the AI adds and mention-only tool suggestions, in `ai` of a copy of `r`
 * (the rest of the report is unchanged).
 * 0. `deps.consent` must be the ConsentToken askConsent gave for the audit --ai screen, for this provider, model, cap
 *    and folder, not used before (Plan U T4b, review M1/M2); anything else is thrown before anything runs, and the token
 *    is spent. The secret scan's walk reads only the files the screen counted (onlyPaths, review I1); covers() is the
 *    backstop (a note, nothing sent). File content can change between the count and the send; the cap still holds (M3).
 * 1. The secret scanner is made ready right before the bundle is built with it (the path stays a local variable). No
 *    binary, or a scanner failure: no AI call, a note.
 * 2. planNeeds(…, writers 0, knownValues): the needs it adds become `extraNeeds`; floor needs are never changed.
 * 3. suggestTools for every floor need that isn't covered, and every added need, that has no project script (it skips
 *    needs a reviewed tool covers). Skipped when the reviewed list is unavailable (look-alike checks need it; B3/U11).
 * Every AI attempt goes through an AiSpendMeter: a hard cap at `deps.capUsd` (ruling U13). An attempt that could pass it
 * is never sent: the needs call then stops the AI step with a note; a discovery call stops asking the AI (one note).
 * An AiError never escapes (S16): it becomes a note, and its billed usage still counts. Other errors are thrown.
 */
/** The pinned gitleaks, downloaded and verified (ensurePinnedBinary), with its pinned version. */
async function defaultSecretScanner(): Promise<SecretScanner> {
  return { name: 'gitleaks', path: await ensurePinnedBinary('gitleaks'), version: loadPinnedBinaries().gitleaks.version };
}

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

  // 1. The secret-scanned bundle: the binary is made ready right before it runs, and its path is never kept.
  let bundle: CodeBundle;
  try {
    const scanner = await (deps.ensureSecretScanner ?? defaultSecretScanner)();
    // only the files the consent screen counted (review I1): the checked bundle can only shrink
    bundle = await bundleCode(dir, { secretScanner: scanner, knownValues: deps.knownValues, onlyPaths: counted.paths() });
  } catch (e) {
    if (!(e instanceof PinnedBinaryError || e instanceof SecretScanError)) throw e;
    notes.add(AI_NOTE.noSecretScan('gitleaks', e.message));
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
