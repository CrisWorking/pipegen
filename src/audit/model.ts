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
// - aiBundle: what the full run would send to the AI, counted from bundleCode without gitleaks (counting only).
// - warnings: a repo `.npmrc` that sets a registry or a local node_modules/.bin/pipegen could change which pipegen
//   runs (the `.npmrc` is read for that one fact; no value is kept); anonymous access.
//
// Output rule (src/types.ts): repo-derived strings are kept RAW (validated by the readers) and cleaned only where
// Task 3 prints them. Nothing here escapes a value, and no file content or secret value is ever stored.
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { bundleCode, COUNTING_ONLY_NOTE, EXCLUDED_PATTERNS, findSecretLike, isExcludedPath, redact } from '../ai/redact.js';
import { needLanguage } from '../engine/discover.js';
import type { RateBudget } from '../engine/github-rate.js';
import { floorNeeds, isRunnable, jobCategories } from '../engine/needs.js';
import { projectScriptFor, reviewedFor, type ProjectScriptStep } from '../engine/reviewed.js';
import { activity30d, estimate, type Activity, type Estimates } from '../estimate/estimate.js';
import { signingMode } from '../github/signing-mode.js';
import { IGNORED_DIRS, listFiles, READ_LIMITS, readTextLimited, readTextLimitedWithReason } from '../read/limits.js';
import { readProject } from '../read/project.js';
import { supportLevel } from '../read/support.js';
import { skippedWorkflowCount } from '../read/workflows.js';
import {
  DEFAULT_MODEL, type Capabilities, type Need, type Part, type PipelineDraft, type RepoProfile, type ReviewedTool, type Service,
} from '../types.js';
import { packageVersion } from '../util/package-data.js';
import { safeText } from '../util/safe-text.js';
import { mapCoverage, type Coverage } from './coverage.js';

// ---------- types ----------

/** The milestone this build belongs to; keys the "what's next" table (ruling S8). */
export const CURRENT_MILESTONE = 'v0.1' as const;
export type Milestone = typeof CURRENT_MILESTONE;

/** pipegen's own check (the merge gate, the deploy-time verify): nothing to pick. */
export interface BuiltInCheck { kind: 'built-in' }
/** What would run for a need: a reviewed tool, the service's own script, pipegen's own check, or nothing yet. */
export type WouldAddTool = ReviewedTool | ProjectScriptStep | BuiltInCheck | null;
export interface WouldAddRow {
  need: Need;
  /** The need's coverage status (never `covered`: covered needs get no row). */
  status: Exclude<Coverage['status'], 'covered'>;
  tool: WouldAddTool;
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
export type AuditSupport = ReturnType<typeof supportLevel> & { nextStep: string };

export interface AuditReport {
  profile: RepoProfile; capabilities: Capabilities; support: AuditSupport;
  coverage: Coverage[]; wouldAdd: WouldAddRow[];
  wouldCreate: { what: Part; why: string }[];
  /** Ruling S27: "No service found to test." when the repo has no service (the tests rows are absent on purpose), else null. */
  testsNote: string | null;
  estimates: Estimates; permissions: { permission: string; why: string }[];
  limits: string[]; secretsInTree: SecretInTree[];
  /** What the full run would send to the AI (counts and folder names, never contents). */
  aiBundle: { files: number; bytes: number; truncated: boolean; excludedPatterns: string[]; topFolders: string[] };
  /** How pipegen was started (a repo .npmrc with a registry, a local node_modules/.bin/pipegen) and anonymous access. */
  warnings: string[];
  /** Reader, workflow, capability-probe, bundle, coverage and secrets-scan notes; deduped (ruling S11), each passed through redact() (a secret-like file name in a reader note is masked). */
  notes: string[];
  /** Ruling U11: the caller couldn't use the reviewed list (B3). Task 2b drops every discovery suggestion when true. */
  reviewedUnavailable: boolean;
  /** Only with --ai, after consent (Task 2b); mention-only. */
  ai?: { extraNeeds: Need[]; suggestions: PipelineDraft['suggestions']; notes: string[] };
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
}

// ---------- fixed texts ----------

const AUDIT_TODAY = ' You can run `pipegen audit` today.';
const NEXT_STEP: Readonly<Record<Milestone, Readonly<Record<'v0.2' | 'v0.4' | 'none', string>>>> = {
  'v0.1': {
    'v0.2': 'The full setup (`npx pipegen`) arrives in v0.2 for single-package Node/TypeScript repos.',
    'v0.4': 'The full setup (`npx pipegen`) arrives in v0.4 for Python and monorepos.',
    none: 'The full setup (`npx pipegen`) is not planned yet for this repo.',
  },
};

const ROW_NOTE = {
  builtIn: "pipegen's own check",
  reviewed: 'reviewed tool',
  suggestion: 'suggestion only',
  unavailable: 'reviewed list unavailable',
  script: (script: 'test' | 'lint') => `your own \`${script}\` script would run here`,
} as const;
const starterTests = (service: string) => `No tests found for ${service}: pipegen would create starter tests.`;
const NO_SERVICE_TO_TEST = 'No service found to test.';

const LIMIT = {
  noLock: 'No merge lock: anyone with write access can merge without checks (GitHub Pro for personal accounts, GitHub Team for organisations, adds it).',
  fakeGate: 'Without a merge lock, a pull request could replace the gate with a fake one; only code-owner review stops it.',
  noApprovals: 'No deploy approvals: GitHub does not let this repo require a reviewer before a deploy.',
  noSigning: 'No image signing: this private repo has no artifact attestations, and no environment rule was proven to keep a signing key to the default branch.',
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

const NO_TOKEN = 'No token: public data only, rate-limited.';
/**
 * `.npmrc` keys that change which package npx runs or how it starts it (any scope: `@acme:registry`): the registry,
 * node's options, and the shell `npm exec` uses.
 */
const NPMRC_KEY_RE = /^["']?(?:@[^\s:="']*:)?(?:registry|node-options|script-shell)["']?\s*=/i;
/**
 * Only the start of a line (after its leading whitespace, which npm's ini parser trims too) is matched, so a huge line
 * can't stall the pattern and padding can't push the key out of view.
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

  const caps = deps.capabilities;
  const needs = floorNeeds(profile, caps);

  const coverage = await coverageOf(profile, needs, dir, skippedWorkflowCount(readerNotes), notes);
  const wouldAdd = wouldAddRows(profile, coverage, deps);

  const activity = await activityOf(deps, profile);
  const estimates = estimate(profile, jobCategories(needs), 2, activity ?? { pushes: 0, prs: 0, capped: false }, { name: 'claude', model: DEFAULT_MODEL });
  if (activity === null) {
    const line = "Activity: pipegen couldn't read this repo's pushes and pull requests for the last 30 days, so monthly minutes assume 0 of each (the real number is likely higher).";
    const at = estimates.basis.findIndex((b) => b.startsWith('Activity:'));
    if (at >= 0) estimates.basis[at] = line;
    else estimates.basis.push(line);
  }

  const secretsInTree = await scanTree(dir, notes);

  const bundle = await bundleCode(dir);
  // A counting-only bundle says it "cannot be sent to the AI"; nothing is sent here, so that note would only confuse.
  for (const n of bundle.notes) if (n !== COUNTING_ONLY_NOTE) notes.add(n);

  return {
    profile,
    capabilities: caps,
    support: supportOf(profile),
    coverage,
    wouldAdd,
    wouldCreate: wouldCreateOf(profile),
    testsNote: profile.services.length === 0 ? NO_SERVICE_TO_TEST : null,
    estimates,
    permissions: deps.permissions,
    limits: limitsOf(profile, caps),
    secretsInTree,
    aiBundle: {
      files: bundle.files.length, bytes: bundle.bytes, truncated: bundle.truncated,
      excludedPatterns: [...EXCLUDED_PATTERNS], topFolders: topFolders(bundle.files.map((f) => f.path)),
    },
    warnings: await warningsOf(dir, deps.anonymous),
    notes: notes.all(),
    reviewedUnavailable: deps.reviewedUnavailable === true,
  };
}

// ---------- parts ----------

/** supportLevel for v0.2, without the "You can run `pipegen audit` today." tail (this is that audit), plus the next step. */
function supportOf(p: RepoProfile): AuditSupport {
  const v02 = supportLevel(p, 'v0.2');
  const reasons = v02.reasons.map((r) => (r.endsWith(AUDIT_TODAY) ? r.slice(0, -AUDIT_TODAY.length) : r));
  const next = v02.level === 'full' ? 'v0.2' : supportLevel(p, 'v0.4').level === 'full' ? 'v0.4' : 'none';
  return { level: v02.level, reasons, nextStep: NEXT_STEP[CURRENT_MILESTONE][next] };
}

/** mapCoverage, or every need `unknown` with a plain note when it fails (the tool signatures can't be loaded). */
async function coverageOf(p: RepoProfile, needs: Need[], dir: string, skippedWorkflows: number, notes: Notes): Promise<Coverage[]> {
  try {
    return await mapCoverage(p, needs, dir, { skippedWorkflows });
  } catch (e) {
    const why = e instanceof Error ? e.message.split('\n')[0] : 'unknown error';
    notes.add(`pipegen couldn't load its list of tool signatures, so it can't tell which checks your workflows already run (${why}).`);
    return needs.map((need) => ({ need, status: 'unknown', why: "pipegen couldn't look for this check: its tool signatures didn't load." }));
  }
}

function wouldAddRows(p: RepoProfile, coverage: Coverage[], deps: AuditDeps): WouldAddRow[] {
  const rows: WouldAddRow[] = [];
  for (const c of coverage) {
    if (c.status === 'covered') continue;
    const need = c.need;
    const service = need.service === undefined ? undefined : p.services.find((s) => s.name === need.service);
    // S27: a service without tests gets starter tests; its own `test` script (npm's default "no test specified") is
    // then not offered as the tool, so the row's tool and note agree (fix round 1, M2).
    const starter = (need.category === 'unit-tests' || need.category === 'full-tests') && service !== undefined && !service.hasTests;
    const { tool, note } = pick(need, starter ? undefined : service, p, deps);
    rows.push({ need, status: c.status, tool, note: starter ? starterTests(service.name) : note });
  }
  return rows;
}

/** Ruling S7: pipegen's own check → the service's own script → the first reviewed tool → nothing. */
function pick(need: Need, service: Service | undefined, p: RepoProfile, deps: AuditDeps): { tool: WouldAddTool; note: string } {
  if (need.category === 'gate' || need.category === 'deploy-verify') return { tool: { kind: 'built-in' }, note: ROW_NOTE.builtIn };
  const script = service === undefined ? null : projectScriptFor(need, service);
  if (script !== null) return { tool: script, note: ROW_NOTE.script(script.script) };
  const reviewed = reviewedFor(need, needLanguage(need, p), deps.reviewed, 'audit')[0];
  if (reviewed !== undefined) return { tool: reviewed, note: ROW_NOTE.reviewed };
  return { tool: null, note: deps.reviewedUnavailable === true ? ROW_NOTE.unavailable : ROW_NOTE.suggestion };
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
  if (signingMode(p, caps) === 'none') out.push(LIMIT.noSigning);
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

/** Top-level folders of the bundled files, most files first (like bundleSummary, which needs a gitleaks-checked bundle). */
function topFolders(paths: string[]): string[] {
  const counts = new Map<string, number>();
  for (const path of paths) {
    const cut = path.indexOf('/');
    if (cut > 0) counts.set(path.slice(0, cut), (counts.get(path.slice(0, cut)) ?? 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([name]) => name);
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
 * Ruling S30 / Review Focus 9: a repo `.npmrc` with a registry, node-options or script-shell line, or a local
 * node_modules/.bin/pipegen, could change which pipegen runs when started from inside the repo. The `.npmrc` is read
 * only for that yes/no (no value is kept); one that can't be read safely (a symbolic link, too large) counts as yes.
 * node_modules/.bin/pipegen is an existence check with lstat: the last part is never followed (a dangling link
 * counts), while a symlinked node_modules or .bin folder on the way is followed, as npx would follow it too.
 */
async function warningsOf(dir: string, anonymous: boolean): Promise<string[]> {
  const out: string[] = [];
  if (await npmrcSetsRegistry(dir) || (await lstat(join(dir, 'node_modules', '.bin', 'pipegen')).catch(() => null)) !== null) {
    const v = packageVersion();
    const pkg = v === null ? 'pipegen' : `pipegen@${v}`;
    out.push(`This repo could change which pipegen runs. Run it from outside the repo: \`npx --registry=https://registry.npmjs.org ${pkg} audit --dir ./repo\`.`);
  }
  if (anonymous) out.push(NO_TOKEN);
  return out;
}

async function npmrcSetsRegistry(dir: string): Promise<boolean> {
  const path = join(dir, '.npmrc');
  const info = await lstat(path).catch(() => null);
  if (info === null) return false;
  if (info.isSymbolicLink() || !info.isFile()) return true; // npm would follow it; pipegen won't, so it can't say no
  const text = await readTextLimited(path);
  if (text === null) return true;
  return text.split(/\r\n|\r|\n/).some((line) => NPMRC_KEY_RE.test(line.trimStart().slice(0, NPMRC_KEY_WINDOW)));
}
