// Plan E Task 5 / sub-task E7 (spec §9, §11, §19; rulings B1, S6, S7, S10, S15, S16, S24; E0a-R5 / DECISIONS #113; threats T12, T16,
// T32, T39): the fix loop and the key confirmation. When a part of the proof fails, the failure is CLASSIFIED BY RULES on the raw
// log, locally (classifyFailure); the AI is asked only when a fix is the answer (needs-fix), and only with a code-extracted excerpt
// (errorExcerpt) of a run that held no value the user typed. Every answer is checked by code before it runs; then the proof runs
// again. Hard limits: 5 attempts per failing part (then the next reviewed candidate with a fresh 5, then not-proven or failed), the
// part stops early when the same error comes twice in a row, 20 attempts per run in all, and the two caps (E6) at every stage boundary.
//
// The key confirmation (spec §19, plan Global Constraints; Review Focus 6). The scratch repo's secrets are the placeholders (and
// pipegen's throwaway key) while any AI-written file (aiWritten) has not been confirmed by the user at its current content:
//   - no AI-written code and the user typed values → the real values are stored before the first proof, no question;
//   - AI-written code → it runs with placeholders first; once nothing is left to fix with placeholders, deps.confirm(files) lists the
//     AI-written files not yet confirmed. Yes → keys.real(...) and the proof runs again. No → the keys stay placeholders, and the parts
//     that need real keys become not-proven ("you chose not to run AI-written code with your keys");
//   - a new AI change after a yes (an answer that changes a file) switches the keys back to placeholders (deleteAll, then
//     placeholders: E4's protocol, the excerpt brand comes back only after a full deleteAll) before the next run, and confirm is
//     asked again with only the changed files.
// DECISIONS #113 (E0a-R5): an excerpt is built only from a run whose secrets were all placeholders or throwaway keys. Before every
// push or re-run the loop takes keys.ticket(); after the run, keys.evidence(ticket, runIds) (the brand, or null); errorExcerpt gets
// the run id AND attempt of each log. A failure seen in a run that held the real keys is classified locally; when it needs a fix it
// is run once more with placeholders (ruling E7-R1 in the E7 report) and only that run's log may go to the AI. If it doesn't fail
// with placeholders, it failed only with the user's keys and ends with that reason, never sent to the AI.
// Logs: each failing job's log is bounded to its last 16 MiB, then only the failing step's section (the step that holds the first
// ##[error] line) cut to its last 1 MiB goes to errorExcerpt. Any throw from errorExcerpt (the secret scan included) = nothing is sent.
//
// What an answer may do (S16, S10): its ids are enums built per request: needId ∈ the failing part's needs, candidateId ∈ the
// reviewed candidates for them, path ∈ the failing part's own files minus starter tests, package.json, package-lock.json, workflow
// files (pipegen renders them from the steps) and .dockerignore (a fixed text); baseId ∈ the reviewed list's Node images (only for a
// base-image CVE failure, applied through createDockerfile's baseId option, deps.dockerfileFor). A Dockerfile answer keeps its FROM
// lines (pipegen's) and is guarded with its .dockerignore. Checks: the referee (deps.referee, Plan G's closure with the 7th
// argument, makeFixReferee), the guard on that part's files (deps.guard, makeFixGuard), and for a test file the count can't drop,
// no .skip/.only/.todo, plus deps.checkTests. A refused answer counts as an attempt. Any package.json a candidate change brings
// gets needsConfirm (its own preview section, Plan G) and joins the files the user confirms.
// pipegen never pushes here: deps.prove (Plan G: rerunProof / redeployProof, whose buildProofBranch runs checkProofWorkflows on
// every commit, E3 L1/C1) and deps.rerun (rerunFailedJobs in run.ts: POST …/rerun-failed-jobs, never a dispatch) do.
import { z } from 'zod';
import { FIX_SYSTEM, fixInstructions, neutralizeBlocks, untrustedLog, type FixAction } from '../ai/prompts/fix.js';
import { completeValidated, formatAiText } from '../ai/provider.js';
import { AiError } from '../ai/errors.js';
import { aiSchema, type AiSchema } from '../ai/schema.js';
import type { SecretScanner } from '../ai/secret-scan-config.js';
import { isCostCap, type AiSpendMeter } from '../ai/spend-meter.js';
import { ownFromLines } from '../create/dockerfile.js';
import { parseDockerfile } from '../create/dockerfile-rules.js';
import { guardCreatedFiles, type GuardCtx, type GuardResult } from '../create/guard.js';
import type { ReviewedClosure } from '../create/reviewed-closure.js';
import type { SecretVault } from '../create/secrets.js';
import { checkAttempt, type TestPlan } from '../create/tests.js';
import { fileStats, isTestName } from '../create/test-rules.js';
import { baseImageRef, loadBaseImages, type BaseImage } from '../engine/base-images.js';
import { CREATED_RULES, type CreatedInputs } from '../engine/created-files.js';
import { NEED_ID_CATEGORY } from '../engine/need-ids.js';
import type { PlatformActions } from '../engine/pin.js';
import { referee, type Linters, type RefereeDeps, type RefereeReport } from '../engine/referee.js';
import { FLOOR_NEEDS, type AiProvider, type AiRequest, type CreatedFile, type KnownValueCheck, type Part, type PartResult, type PipelineDraft, type ProofResult, type ReviewedTool, type StepSpec } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { capMessage, capReached, type CapReached } from './caps.js';
import { cleanLog, EMPTY_SECRET_RE, KEY_REFUSED_RE, mentionsName, NEEDS_REAL_KEY, type EvidenceSource, type PartEvidence } from './evaluate.js';
import { errorExcerpt, errorSignature } from './excerpt.js';
import type { ExcerptEvidence, RunTicket, ScratchKeys } from './keys.js';
import type { MinutesMeter } from './minutes.js';

export type FailureClass = 'missing-secret' | 'needs-real-keys' | 'runner-error' | 'rate-limit' | 'tool-error' | 'needs-fix';
export type KeysMode = 'none' | 'placeholder' | 'real';

/** Attempts per failing part (then the next reviewed candidate with a fresh count). */
export const FIX_MAX_ATTEMPTS = 5;
/** Attempts per run, all parts and re-runs together. */
export const FIX_MAX_TOTAL_ATTEMPTS = 20;
/** A job log is read from its last this many characters (E0a carry: the stream cap). */
export const FIX_LOG_CAP = 16 * 1024 * 1024;
/** The failing step's section passed to errorExcerpt: its last this many characters (E0a-R5 carry; excerpt.ts MAX_LOG_CHARS). */
export const FIX_SECTION_CAP = 1024 * 1024;
/** Logs (failed jobs) excerpted per failing part. */
const MAX_SOURCES = 3;
/** An earlier attempt's excerpt is shown from its last this many characters (whole lines). */
const EARLIER_EXCERPT_CHARS = 8 * 1024;
const FIX_TIMEOUT_MS = 240_000;
const FIX_MAX_OUTPUT_TOKENS = 16_000;
const MAX_CONTENT = 60_000;
const MAX_EXPLANATION = 2_000;
const MAX_CANDIDATE_TRIES = 8;
const MAX_ROUNDS = 200;

// ---------- classification (rules only, no AI) ----------

const RUNNER_ERROR_RE = /The runner has received a shutdown signal|lost communication with the server|The hosted runner (?:encountered an error|lost communication)|The job was not acquired by Runner|Received request to deprovision/i;
const RATE_LIMIT_RE = /API rate limit exceeded|secondary rate limit|toomanyrequests|429 Too Many Requests|You have reached your (?:unauthenticated )?pull rate limit/i;
const TOOL_ERROR_DETAIL_RE = /\btool error\b|could not be used:/i;
const TOOL_ERROR_LOG_RE = /\btool[- ]error\b/i;
const NOT_GIVEN_RE = /which was not given/;

/**
 * The class of a failure, by rules on the part's detail and its RAW log, read here locally (S15: only errorExcerpt's copy leaves the
 * machine). In order: a missing secret (a name the draft lacks, an empty secret input) → 'missing-secret'; a rate limit; a runner
 * error; a refused key → 'needs-real-keys' while the run had placeholders, 'missing-secret' when it had the real values (the value given
 * doesn't work: the user must fix it, the AI can't); a tool error (the scanner itself failed, not a finding); else 'needs-fix'.
 */
export function classifyFailure(part: PartResult, log: string, ctx: { missingSecrets: readonly string[]; keys: KeysMode }): FailureClass {
  const raw = String(log ?? '');
  const text = cleanLog(raw.length > FIX_LOG_CAP ? raw.slice(-FIX_LOG_CAP) : raw);
  const detail = String(part?.detail ?? '');
  const both = `${detail}\n${text}`;
  if ((ctx.missingSecrets ?? []).some((n) => typeof n === 'string' && mentionsName(both, n)) || EMPTY_SECRET_RE.test(text) || NOT_GIVEN_RE.test(detail)) return 'missing-secret';
  if (RATE_LIMIT_RE.test(text)) return 'rate-limit';
  if (RUNNER_ERROR_RE.test(text)) return 'runner-error';
  if (KEY_REFUSED_RE.test(both) || detail.includes(NEEDS_REAL_KEY)) return ctx.keys === 'real' ? 'missing-secret' : 'needs-real-keys';
  if (TOOL_ERROR_DETAIL_RE.test(detail) || TOOL_ERROR_LOG_RE.test(text)) return 'tool-error';
  return 'needs-fix';
}

// ---------- the log section ----------

const TIMESTAMP = /^\uFEFF?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z ?/;
const STEP_HEADER = /^(?:##\[group\](?:Run|Post) |Post job cleanup\.)/;

/** The text from the first line start at or after `from` (a cut never leaves half a line). */
function fromLineStart(text: string, from: number): string {
  if (from <= 0) return text;
  const nl = text.indexOf('\n', from - 1);
  return nl < 0 ? '' : text.slice(nl + 1);
}

/**
 * The failing step's section of a GitHub job log: from the step header (`##[group]Run …`) at or before the first `##[error]` line to
 * the next step header; the whole log when there is no error line. The log is first bounded to its last FIX_LOG_CAP characters, the
 * section to its last FIX_SECTION_CAP (both cut at a line start).
 */
export function failingSection(log: string): string {
  let text = String(log ?? '');
  if (text.length > FIX_LOG_CAP) text = fromLineStart(text, text.length - FIX_LOG_CAP);
  const lines = text.split('\n');
  const bare = (l: string): string => l.replace(TIMESTAMP, '');
  const err = lines.findIndex((l) => bare(l).startsWith('##[error]'));
  let from = 0;
  let to = lines.length;
  if (err >= 0) {
    for (let i = err; i >= 0; i--) if (STEP_HEADER.test(bare(lines[i] as string))) { from = i; break; }
    for (let i = err + 1; i < lines.length; i++) if (STEP_HEADER.test(bare(lines[i] as string))) { to = i; break; }
  }
  const section = lines.slice(from, to).join('\n');
  return section.length > FIX_SECTION_CAP ? fromLineStart(section, section.length - FIX_SECTION_CAP) : section;
}

// ---------- files ----------

const AI_PARTS: ReadonlySet<Part> = new Set<Part>(['docker', 'tests', 'test-migration']);
const base = (p: string): string => p.slice(p.lastIndexOf('/') + 1);
const isDockerfile = (p: string): boolean => /(?:^|\/)Dockerfile$/.test(p);
const isPackageFile = (p: string): boolean => base(p) === 'package.json' || base(p) === 'package-lock.json';
const fileKey = (f: Pick<CreatedFile, 'repo' | 'path'>): string => `${f.repo}:${f.path}`;
const STARTER_RULE = CREATED_RULES.find((r) => r.id === 'starter-tests');
/** A test file by its name: `.test.` or `.spec.` code, or a starter-test name. */
const isTestPath = (p: string): boolean => isTestName(base(p)) || /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(base(p));

/** Whether a path is one the starter-test registry rule claims (D7-R7: never offered, whatever its part). */
function isStarterTest(path: string, draft: PipelineDraft): boolean {
  try { return STARTER_RULE?.match(path, draft) === true; } catch { return true; }
}

/**
 * The files an AI answer may edit for `part` (S16): the part's own files in the app repo, minus starter tests (D7-R7), package.json and
 * package-lock.json (pipegen's code writes them), workflow files (rendered from the steps; E3 C1: an AI edit never reaches a
 * workflow) and the fixed .dockerignore.
 */
export function fixPaths(draft: PipelineDraft, part: Part): string[] {
  const out: string[] = [];
  for (const f of draft.created) {
    if (f.part !== part || f.repo !== 'app' || typeof f.path !== 'string') continue;
    if (isPackageFile(f.path) || base(f.path) === '.dockerignore' || f.path.startsWith('.github/workflows/')) continue;
    if (isStarterTest(f.path, draft) || (f.part === 'tests' && isTestPath(f.path))) continue;
    if (!out.includes(f.path)) out.push(f.path);
  }
  return out;
}

/**
 * Plan Task 5: the AI-written files: parts docker, tests and test-migration, every needsConfirm file, every file a fix answer changed
 * (E7-R14: marked `aiEdited` on the draft, so a resumed draft and Plan G's preview see it too; `fixedPaths` adds paths not yet marked).
 */
export function aiWritten(draft: PipelineDraft, fixedPaths: ReadonlySet<string> = new Set()): CreatedFile[] {
  return draft.created.filter((f) => AI_PARTS.has(f.part) || f.needsConfirm === true || f.aiEdited === true || fixedPaths.has(f.path));
}

/** Whether a package.json's scripts or dependencies differ (an unreadable text counts as a change). */
function scriptsOrDepsChanged(before: string | undefined, after: string): boolean {
  const pick = (t: string | undefined): string | null => {
    if (t === undefined) return '';
    try {
      const j = JSON.parse(t) as Record<string, unknown>;
      return JSON.stringify(['scripts', 'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'overrides'].map((k) => j?.[k] ?? null));
    } catch { return null; }
  };
  const a = pick(before), b = pick(after);
  return a === null || b === null || a !== b;
}

// ---------- the answer schema ----------

export interface FixAnswer { action: FixAction; needId: string | null; candidateId: string | null; path: string | null; content: string | null; baseId: string | null; explanation: string }

const enumOrNull = (xs: readonly string[]) => (xs.length > 0 ? z.enum([...new Set(xs)] as [string, ...string[]]).nullable() : z.null());

/** The answer's schema for one request: every id an enum of what this request offers (S16), else only null. */
export function fixSchema(o: { needIds: readonly string[]; candidateIds: readonly string[]; paths: readonly string[]; baseIds: readonly string[] }): AiSchema<FixAnswer> {
  const actions: FixAction[] = [
    ...(o.paths.length > 0 && o.baseIds.length === 0 ? ['edit-file' as const] : []),
    ...(o.candidateIds.length > 0 && o.needIds.length > 0 ? ['change-step' as const] : []),
    ...(o.baseIds.length > 0 ? ['change-base' as const] : []),
    'give-up',
  ];
  return aiSchema<FixAnswer>(z.strictObject({
    action: z.enum(actions as [FixAction, ...FixAction[]]),
    needId: enumOrNull(o.needIds), candidateId: enumOrNull(o.candidateIds), path: enumOrNull(o.paths),
    content: z.string().max(MAX_CONTENT).nullable(), baseId: enumOrNull(o.baseIds), explanation: z.string().max(MAX_EXPLANATION),
  }) as unknown as z.ZodType<FixAnswer>);
}

// ---------- the closures Plan G gives (S7) ----------

export interface FixRefereeOpts {
  /** Plan G's assemble: the files of the draft as delivered (signing mode none for the proof). */
  assemble: (d: PipelineDraft) => CreatedFile[] | Promise<CreatedFile[]>;
  platform: PlatformActions;
  reviewed: ReviewedTool[];
  linters: Linters;
  ghToken: string | null;
  /** The referee's 7th argument (Plan D final review I3): the vault and what delivery knows are REQUIRED. */
  deps: RefereeDeps & { vault: KnownValueCheck; createdInputs: CreatedInputs };
}

/** The referee closure of the fix loop: assemble, then the Plan B referee with all 7 arguments (S7). */
export function makeFixReferee(o: FixRefereeOpts): (d: PipelineDraft) => Promise<RefereeReport> {
  if (o?.deps?.vault === undefined || o.deps.createdInputs === undefined) throw new Error('makeFixReferee needs deps with the vault and createdInputs (the referee\'s 7th argument).');
  const deps: RefereeDeps = { ...o.deps, vault: o.deps.vault, createdInputs: o.deps.createdInputs };
  return async (d) => referee(await o.assemble(d), d, o.platform, o.reviewed, o.linters, o.ghToken, deps);
}

/** The guard closure of the fix loop (S7): guardCreatedFiles with the vault, the reviewed closure, the install record and the delivery base tree. */
export function makeFixGuard(ctx: GuardCtx & { vault: KnownValueCheck; closure: ReviewedClosure | null }): (files: CreatedFile[]) => Promise<GuardResult> {
  if (ctx?.vault === undefined || ctx.closure === undefined || ctx.baseTree === undefined || ctx.installRecord === undefined) {
    throw new Error('makeFixGuard needs the vault, the reviewed closure, the install record and the delivery base tree.');
  }
  return (files) => guardCreatedFiles(files, ctx);
}

// ---------- the deps ----------

/** What the fix loop uses of ScratchKeys (E4). */
export type FixKeys = Pick<ScratchKeys, 'mode' | 'setup' | 'real' | 'deleteAll' | 'ticket' | 'evidence' | 'scrubber' | 'lastRefusal'>;
/** S15: what one proof (or re-run) gives back: the evaluation and, per part (or part:needId), the failed jobs' logs with their runs. */
export interface ProofRun { result: ProofResult; evidence: ReadonlyMap<string, PartEvidence> }

export interface FixDeps {
  /** The run's AI, already wrapped by meteredProvider (E6): it must be meters.ai.provider. */
  ai: AiProvider;
  /** Plan G: the proof again with `d` ('pr' = push + PR runs; 'full' = up to the merge and the deploy layer), evaluated (S15). */
  prove: (d: PipelineDraft, scope: 'pr' | 'full') => Promise<ProofRun>;
  /** Plan G: rerunFailedJobs (run.ts) on these runs, waited for and evaluated. */
  rerun: (runIds: readonly number[]) => Promise<ProofRun>;
  /** The next reviewed candidate for a need, or null. May bring files pipegen's code made for it (a package.json edit). */
  nextCandidate: (needId: string, d: PipelineDraft) => Promise<StepSpec | { step: StepSpec; files?: CreatedFile[] } | null>;
  /** The reviewed candidates the AI may switch a need to (the candidateId enum). Absent: change-step is never offered. */
  candidates?: (needId: string, d: PipelineDraft) => readonly StepSpec[];
  /** S10: the created Dockerfile at `path` made again from base-image id `baseId` (createDockerfile(…, facts, { baseId })), with its .dockerignore. */
  dockerfileFor?: (path: string, baseId: string, d: PipelineDraft) => Promise<CreatedFile[]>;
  /** makeFixReferee (Plan G). */
  referee: (d: PipelineDraft) => Promise<RefereeReport>;
  /** makeFixGuard (Plan G). */
  guard: (files: CreatedFile[]) => Promise<GuardResult>;
  /** Plan D checkAttempt + validateGeneratedTests for a test file answer (default checkAttempt). */
  checkTests?: (prev: TestPlan | null, next: TestPlan) => string[];
  keys: FixKeys;
  vault: SecretVault;
  /** The pinned secret scanner errorExcerpt runs (E0a-R3). */
  scanner: SecretScanner;
  /** The secret names the proof stores (placeholders for every one); the real values are the vault's for these names. */
  secretNames: readonly string[];
  /** The mid-run screen "Run these AI-written files with your test keys?" (Plan G). */
  confirm: (aiFiles: CreatedFile[]) => Promise<boolean>;
  meters: { minutes: MinutesMeter; ai: AiSpendMeter };
  /** Plan G: stopAtCap (cancel the runs, save the state, the cleanup). Called before the loop returns `stopped` at a cap. */
  onCap?: (cap: CapReached) => Promise<unknown>;
  /** One line per event, for the terminal (already through safeText). */
  log?: (line: string) => void;
}

export interface FixOutcome {
  draft: PipelineDraft;
  result: ProofResult;
  /** Why the loop stopped before the proof could pass (a failed part, the global cap, a cap). */
  stopped?: string;
  /** Attempts in all (answers, re-runs, candidate switches, runs again with placeholders): the global cap counts these. */
  attempts: number;
  /** AI answers per failing part (part, or part:needId), over the whole run. */
  aiAttempts: Record<string, number>;
  /** E7-R14: the paths an AI fix answer changed in this run (also marked `aiEdited` on the returned draft's files). */
  aiChanged: string[];
  /** Tool errors (a scanner that failed to run), reported apart from findings. */
  toolErrors: string[];
  /** The keys of the run the result comes from. */
  keys: 'placeholder' | 'real';
  /** What the AI said (scrubbed, safeText) and what the loop did, for the developer. */
  notes: string[];
  cap?: CapReached;
}

// ---------- the loop ----------

interface Proof extends ProofRun { ticket: RunTicket; keys: 'placeholder' | 'real'; seq: number }
interface Unit { key: string; part: Part; needId?: string; entry: PartResult; keysOnly: boolean }
interface Earlier { n: number; action: string; target: string; explanation: string; outcome: string; error: string }
interface UState {
  attempts: number;
  ai: number;
  lastSig: string | null;
  appliedSinceSig: boolean;
  seenSeq: number;
  excerpt: string;
  history: Earlier[];
  reruns: number;
  aiDone: string | null;
  reproducedAt: number;
  reproduce: { unit: Unit } | null;
  /** The class of the part's latest failure (E7-R12: an ending names it). */
  lastClass: FailureClass | null;
}
interface Ended { part: Part; needId?: string; status: 'failed' | 'not-proven'; detail: string }

const PART_ORDER: readonly Part[] = ['pipeline', 'tests', 'docker', 'compose', 'precommit', 'deploy-verify', 'test-migration'];
const NOT_PROVEN_OK: ReadonlySet<Part> = new Set<Part>(['docker', 'compose', 'precommit', 'test-migration', 'tests']);
const PART_CATEGORIES: Readonly<Partial<Record<Part, readonly string[]>>> = {
  docker: ['image-build'], tests: ['unit-tests', 'full-tests', 'coverage'], precommit: ['hooks', 'hooks-ci'], 'deploy-verify': ['deploy-verify'],
};
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const DECLINED = 'you chose not to run AI-written code with your keys';
const st = (s: unknown, n = 300): string => safeText(String(s ?? ''), n);
const isRec = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null;
const EMPTY_RESULT: ProofResult = { ok: false, parts: [], findings: [], minutesUsed: 0, runUrls: [] };
const okSource = (s: unknown): s is EvidenceSource => isRec(s) && Number.isSafeInteger(s.runId) && (s.runId as number) > 0
  && Number.isSafeInteger(s.attempt) && (s.attempt as number) > 0 && typeof s.log === 'string';

function categoryOf(id: string, declared?: string): string {
  if (typeof declared === 'string' && declared !== '') return declared;
  return Object.hasOwn(NEED_ID_CATEGORY, id) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[id] as string : id;
}

/** The units the loop works on: each failed need of a failed part (else the part), and each "needs your real test key" note. */
function unitsOf(result: ProofResult): Unit[] {
  const parts = Array.isArray(result?.parts) ? result.parts.filter((p) => isRec(p) && typeof p.part === 'string' && typeof p.detail === 'string') : [];
  const rank = (p: Part): number => { const i = PART_ORDER.indexOf(p); return i < 0 ? PART_ORDER.length : i; };
  const out = new Map<string, Unit>();
  const add = (e: PartResult, keysOnly: boolean): void => {
    const key = e.needId === undefined ? e.part : `${e.part}:${e.needId}`;
    if (!out.has(key)) out.set(key, { key, part: e.part, ...(e.needId === undefined ? {} : { needId: e.needId }), entry: e, keysOnly });
  };
  for (const part of [...new Set(parts.map((p) => p.part))].sort((a, b) => rank(a) - rank(b))) {
    const es = parts.filter((p) => p.part === part);
    const verdict = es.find((p) => p.needId === undefined);
    const failedNeeds = es.filter((p) => p.needId !== undefined && p.status === 'failed');
    if (verdict?.status === 'failed' || (verdict === undefined && failedNeeds.length > 0)) for (const e of failedNeeds.length > 0 ? failedNeeds : [verdict as PartResult]) add(e, false);
    for (const e of es) if (e.status === 'not-proven' && e.detail.includes(NEEDS_REAL_KEY)) add(e, true);
  }
  return [...out.values()];
}

/**
 * The result with the loop's own endings put in (a part the final run proved keeps its verdict). `ok` follows E5's rule again: no part
 * failed, the pipeline proven, and a tests part that covers a floor need proven (or skipped with --skip); an ending never makes the
 * pipeline or a floor part pass (those end failed).
 */
function withEndings(result: ProofResult, ended: ReadonlyMap<string, Ended>, testsFloor: boolean, testsSkipped: boolean): ProofResult {
  if (ended.size === 0) return result;
  const ends = [...ended.values()];
  const parts = result.parts.map((p) => {
    if (p.status === 'proven') return p;
    const own = ends.filter((e) => e.part === p.part && (p.needId === undefined || e.needId === p.needId));
    if (own.length === 0) return p;
    if (p.needId !== undefined) { const e = own[0] as Ended; return { ...p, status: e.status, detail: e.detail }; }
    const rest = result.parts.filter((x) => x.part === p.part && x.needId !== undefined && x.status === 'failed' && !own.some((e) => e.needId === x.needId));
    const status = own.some((e) => e.status === 'failed') || rest.length > 0 ? 'failed' as const : 'not-proven' as const;
    return { ...p, status, detail: st(own.map((e) => e.detail).join('; '), 1500) };
  });
  const verdict = (part: Part): PartResult | undefined => parts.find((x) => x.part === part && x.needId === undefined);
  const ok = parts.every((x) => x.status !== 'failed') && verdict('pipeline')?.status === 'proven'
    && (!testsFloor || testsSkipped || verdict('tests')?.status === 'proven');
  return { ...result, parts, ok };
}

class FixLoop {
  draft: PipelineDraft;
  version = 0;
  total = 0;
  seq = 0;
  /** What the scratch repo holds now: 'none' only before the first store (M5). */
  keysNow: 'none' | 'placeholder' | 'real';
  /** The draft version the last 'full' proof ran on (E7-R13). */
  fullVersion = -1;
  declined = false;
  reproduceNext = false;
  proof: Proof | null = null;
  lastReal: { proof: Proof; version: number } | null = null;
  readonly states = new Map<string, UState>();
  readonly ended = new Map<string, Ended>();
  readonly fixed = new Set<string>();
  readonly confirmed = new Map<string, string>();
  readonly toolErrors: string[] = [];
  readonly notes: string[] = [];
  readonly realNames: string[];
  readonly missing: string[];
  readonly max: number;
  readonly maxTotal: number;

  constructor(draft: PipelineDraft, readonly deps: FixDeps, opts: { maxAttempts?: number; maxTotalAttempts?: number }) {
    this.draft = draft;
    this.max = opts.maxAttempts ?? FIX_MAX_ATTEMPTS;
    this.maxTotal = opts.maxTotalAttempts ?? FIX_MAX_TOTAL_ATTEMPTS;
    this.keysNow = deps.keys.mode === 'real' ? 'real' : deps.keys.mode === 'placeholder' ? 'placeholder' : 'none';
    this.realNames = [...new Set((deps.secretNames ?? []).filter((n) => typeof n === 'string' && !/^(?:PIPEGEN|GITHUB)_/i.test(n) && deps.vault.has(n)))];
    this.missing = [...new Set(draft.notProven.flatMap((n) => (Array.isArray(n.missingSecrets) ? n.missingSecrets : [])).filter((n) => typeof n === 'string' && n !== ''))];
  }

  // ----- keys -----

  unconfirmed(): CreatedFile[] {
    return aiWritten(this.draft, this.fixed).filter((f) => this.confirmed.get(fileKey(f)) !== f.content);
  }

  /** Real values only when there are some, the user didn't say no, no run with placeholders is due, and every AI-written file is confirmed. */
  desired(): 'placeholder' | 'real' {
    if (this.reproduceNext || this.declined || this.realNames.length === 0) return 'placeholder';
    return this.unconfirmed().length === 0 ? 'real' : 'placeholder';
  }

  async setKeys(want: 'placeholder' | 'real'): Promise<void> {
    if (want === this.keysNow) return;
    if (this.keysNow === 'none') {
      // M5: nothing stored yet is not "placeholders stored": every name gets its placeholder (and the throwaway key) first
      await this.deps.keys.setup([...new Set(this.deps.secretNames)]);
      this.keysNow = 'placeholder';
      if (want === 'placeholder') return;
    }
    if (want === 'real') {
      await this.deps.keys.real(this.realNames);
      this.keysNow = 'real';
      return;
    }
    // E4 carry: after a real store the brand comes back only after a full deleteAll, then placeholders (and the throwaway key)
    this.keysNow = 'placeholder';
    await this.deps.keys.deleteAll();
    await this.deps.keys.setup([...new Set(this.deps.secretNames)]);
  }

  // ----- stops -----

  finish(stopped?: string, cap?: CapReached): FixOutcome {
    const aiAttempts: Record<string, number> = {};
    for (const [k, s] of this.states) if (s.ai > 0) aiAttempts[k] = s.ai;
    return {
      draft: this.draft, result: withEndings(this.proof?.result ?? EMPTY_RESULT, this.ended, this.floor({ key: 'tests', part: 'tests', entry: { part: 'tests', status: 'failed', detail: '' }, keysOnly: false }), this.draft.skipped.some((x) => x.part === 'tests')),
      ...(stopped === undefined ? {} : { stopped }), attempts: this.total, aiAttempts, aiChanged: [...this.fixed], toolErrors: [...this.toolErrors],
      keys: this.proof?.keys ?? (this.keysNow === 'real' ? 'real' : 'placeholder'), notes: [...this.notes], ...(cap === undefined ? {} : { cap }),
    };
  }

  /** E6 M2: the caps, at every stage boundary. A cap reached → onCap (Plan G's stopAtCap), then stopped. */
  async capStop(error?: unknown): Promise<FixOutcome | null> {
    const cap = capReached({ minutes: this.deps.meters.minutes, ai: this.deps.meters.ai, ...(error === undefined ? {} : { error }) });
    if (cap === null) return null;
    await this.deps.onCap?.(cap);
    return this.finish(capMessage(cap), cap);
  }

  stopGlobal(): FixOutcome {
    return this.finish(`the fix loop reached its global cap of ${this.maxTotal} attempt${this.maxTotal === 1 ? '' : 's'} for this run (all parts and re-runs together), so it stopped with the last result`);
  }

  say(line: string): void {
    const l = st(line, 600);
    this.notes.push(l);
    this.deps.log?.(l);
  }

  // ----- units -----

  stateOf(u: Unit): UState {
    let s = this.states.get(u.key);
    if (s === undefined) {
      s = { attempts: 0, ai: 0, lastSig: null, appliedSinceSig: false, seenSeq: -1, excerpt: '', history: [], reruns: 0, aiDone: null, reproducedAt: -1, reproduce: null, lastClass: null };
      this.states.set(u.key, s);
    }
    return s;
  }

  needIdsOf(u: Unit): string[] {
    if (u.needId !== undefined) return [u.needId];
    const cats = PART_CATEGORIES[u.part] ?? [];
    return this.draft.needs.filter((n) => cats.includes(categoryOf(n.id, n.category))).map((n) => n.id);
  }

  /** A unit that covers a floor need (spec §19: never not-proven). The pipeline covers every floor need. */
  floor(u: Unit): boolean {
    if (u.part === 'pipeline') return true;
    const ids = this.needIdsOf(u);
    if (u.part === 'tests' && u.needId === undefined) return this.draft.needs.some((n) => ['unit-tests', 'full-tests'].includes(categoryOf(n.id, n.category)) && (n.floor || FLOOR.has(categoryOf(n.id, n.category))));
    return this.draft.needs.some((n) => ids.includes(n.id) && (n.floor || FLOOR.has(categoryOf(n.id, n.category))));
  }

  deployLayer(u: Unit): boolean {
    if (u.part === 'deploy-verify') return true;
    const ids = this.needIdsOf(u);
    return this.draft.needs.some((n) => ids.includes(n.id) && n.layer === 'deploy');
  }

  /** A base-image CVE failure of the docker part (E5's words; S10). */
  isCve(u: Unit): boolean {
    return u.part === 'docker' && /critical\/high[^;]*CVEs[^;]*; another base image tag is needed/.test(u.entry.detail);
  }

  /**
   * The unit ends: not-proven where the spec allows it (§9: a created part that can't be proven is delivered warn-only; never a part
   * that covers a floor need, never the pipeline or deploy-verify), else failed, which stops the run (plan Task 5 "End").
   */
  end(u: Unit, detail: string, failed = false): FixOutcome | null {
    const status = !failed && NOT_PROVEN_OK.has(u.part) && !this.floor(u) ? 'not-proven' : 'failed';
    const text = st(detail, 1200);
    this.ended.set(u.key, { part: u.part, ...(u.needId === undefined ? {} : { needId: u.needId }), status, detail: text });
    if (status === 'not-proven') { this.say(`${u.key}: not proven: ${text}`); return null; }
    return this.finish(`${u.part}${u.needId === undefined ? '' : ` (${u.needId})`} could not be proven, so the proof stopped: ${text}`);
  }

  evidenceOf(u: Unit, p: Proof): PartEvidence | undefined {
    return p.evidence.get(u.key) ?? (u.needId !== undefined ? p.evidence.get(u.part) : undefined);
  }

  rawOf(ev: PartEvidence | undefined): string {
    if (ev === undefined) return '';
    const src = Array.isArray(ev.sources) && ev.sources.length > 0 ? ev.sources.map((s) => (typeof s?.log === 'string' ? s.log : '')).join('\n') : String(ev.log ?? '');
    return src.length > FIX_LOG_CAP ? src.slice(-FIX_LOG_CAP) : src;
  }

  // ----- runs -----

  async proveNow(what: { kind: 'prove'; scope: 'pr' | 'full' } | { kind: 'rerun'; ids: number[] }): Promise<Proof | FixOutcome> {
    const before = await this.capStop();
    if (before !== null) return before;
    if (what.kind === 'prove') await this.setKeys(this.desired());
    this.reproduceNext = false;
    // M1: a re-run is a new attempt of the runs of the last proof, so it is recorded with THEIR keys (real if they or the repo held real values)
    const keys: 'placeholder' | 'real' = what.kind === 'rerun'
      ? (this.proof?.keys === 'real' || this.keysNow === 'real' ? 'real' : 'placeholder')
      : this.keysNow === 'real' ? 'real' : 'placeholder';
    const ticket = await this.deps.keys.ticket();   // E4 protocol: BEFORE the push or re-run that starts the runs
    const run = what.kind === 'prove' ? await this.deps.prove(this.draft, what.scope) : await this.deps.rerun(what.ids);
    if (!isRec(run) || !isRec(run.result) || !Array.isArray(run.result.parts) || !(run.evidence instanceof Map)) throw new Error('The proof gave back no result pipegen can read.');
    const p: Proof = { result: run.result, evidence: run.evidence, ticket, keys, seq: ++this.seq };
    this.proof = p;
    if (what.kind === 'prove' && what.scope === 'full') this.fullVersion = this.version;
    if (keys === 'real') this.lastReal = { proof: p, version: this.version };
    const after = await this.capStop();
    return after ?? p;
  }

  // ----- the excerpt -----

  async excerptFor(u: Unit, p: Proof): Promise<{ text: string; sig: string } | { none: string }> {
    if (this.isCve(u)) return { text: '', sig: errorSignature(u.entry.detail) };   // no run output is sent for this question
    if (p.keys !== 'placeholder') return { none: 'the run held your real test keys, and pipegen never sends the log of such a run to the AI' };
    const sources = (this.evidenceOf(u, p)?.sources ?? []).filter(okSource).slice(0, MAX_SOURCES);
    if (sources.length === 0) return { none: 'pipegen read no log of the failing job, so it had nothing to show the AI' };
    // DECISIONS #113: the brand for these runs (finished, started after the ticket, the repo held only placeholders)
    const brand: ExcerptEvidence | null = await this.deps.keys.evidence(p.ticket, [...new Set(sources.map((s) => s.runId))]);
    if (brand === null) return { none: `pipegen could not show that the run held only placeholders (${st(this.deps.keys.lastRefusal ?? 'no reason given', 200)}), so nothing was sent to the AI` };
    const vaultScrub = this.deps.vault.scrubber();
    const keysScrub = this.deps.keys.scrubber();
    const scrub = (t: string): string => keysScrub(vaultScrub(t));
    const out: string[] = [];
    for (const s of sources) {
      try {
        out.push(await errorExcerpt(failingSection(s.log), scrub, this.deps.scanner, brand, { runId: s.runId, attempt: s.attempt }));
      } catch {
        // E0a carry: any throw (SecretScanError included) = send nothing
        return { none: 'the log excerpt could not be made safe to send (a check or the secret scan failed), so nothing was sent to the AI' };
      }
    }
    const text = out.filter((x) => x.trim() !== '').join('\n[… the next failed job …]\n');
    if (text === '') return { none: 'the failing job left no log lines to show the AI' };
    return { text, sig: errorSignature(text) };
  }

  // ----- the main loop -----

  async run(): Promise<FixOutcome> {
    // no AI-written code and values typed: the real values from the start, no question (desired() decides it in proveNow)
    let next = await this.proveNow({ kind: 'prove', scope: 'full' });
    if (!('ticket' in next)) return next;
    for (let round = 0; ; round++) {
      if (round >= MAX_ROUNDS) return this.finish('the fix loop did not settle, so it stopped with the last result');
      const p = this.proof as Proof;
      const all = unitsOf(p.result);
      const failing = new Set(all.map((u) => u.key));
      // the run again with placeholders (E7-R1): a failure that didn't come back there happened only with the real keys
      if (p.keys === 'placeholder') {
        for (const [key, s] of this.states) {
          if (s.reproduce === null) continue;
          const r = s.reproduce;
          s.reproduce = null;
          if (!failing.has(key) && !this.ended.has(key)) {
            const stop = this.end(r.unit, `${r.unit.entry.detail}; it failed only in a run that held your real test keys, and pipegen never sends the log of such a run to the AI (DECISIONS #113)`);
            if (stop !== null) return stop;
          }
        }
      }
      const units = all.filter((u) => !this.ended.has(u.key));
      let changed = false, full = false, reprove = false, again = false;
      const rerun = new Set<number>();
      const deferred: Unit[] = [];
      for (const u of units) {
        if (this.ended.has(u.key)) continue;
        const s = this.stateOf(u);
        const ev = this.evidenceOf(u, p);
        const cls: FailureClass = u.keysOnly ? 'needs-real-keys' : classifyFailure(u.entry, this.rawOf(ev), { missingSecrets: this.missing, keys: p.keys });
        s.lastClass = cls;
        if (cls === 'missing-secret') {
          const stop = this.end(u, `${u.entry.detail}; a secret it needs is missing (or the value given was refused), so the AI was not asked`);
          if (stop !== null) return stop;
          continue;
        }
        if (cls === 'needs-real-keys') { deferred.push(u); continue; }
        if (cls === 'runner-error' || cls === 'rate-limit' || cls === 'tool-error') {
          const what = cls === 'tool-error' ? 'a tool error' : cls === 'rate-limit' ? 'a rate limit' : 'a runner error';
          if (cls === 'tool-error') { const t = st(`${u.key}: ${u.entry.detail}`, 400); if (!this.toolErrors.includes(t)) this.toolErrors.push(t); }
          if (s.reruns >= 1) {
            // E7-R12: a tool error that comes back after its one re-run ends failed (plan "re-run once, then failed")
            const stop = this.end(u, `failed after a re-run (last failure: ${cls}): ${u.entry.detail}; ${what} again after a re-run`, cls === 'tool-error');
            if (stop !== null) return stop;
            continue;
          }
          if (this.total >= this.maxTotal) return this.stopGlobal();
          this.total++;
          s.reruns++;
          const ids = (ev?.sources ?? []).filter(okSource).map((x) => x.runId);
          if (ids.length > 0) for (const id of ids) rerun.add(id); else reprove = true;
          if (this.deployLayer(u)) full = true;
          this.say(`${u.key}: ${what}; re-run without the AI`);
          continue;
        }
        // needs-fix
        if (p.keys === 'real' && !this.isCve(u)) {
          if (s.aiDone === null && s.attempts < this.max && s.reproducedAt !== this.version) {
            if (this.total >= this.maxTotal) return this.stopGlobal();
            this.total++;
            s.reproducedAt = this.version;
            s.reproduce = { unit: u };
            this.reproduceNext = true;
            reprove = true;
            if (this.deployLayer(u)) full = true;
            this.say(`${u.key} failed in a run that held your real test keys; it runs again with placeholders before the AI may see its log`);
            continue;
          }
          const why = s.reproducedAt === this.version
            ? 'it failed only in a run that held your real test keys, and pipegen never sends the log of such a run to the AI (DECISIONS #113)'
            : (s.aiDone ?? `the AI had its ${this.max} attempts`);
          const r = await this.nextOrEnd(u, s, why);
          if (typeof r !== 'string') return r;
          if (r === 'changed') { changed = true; if (this.deployLayer(u)) full = true; }
          continue;
        }
        const r = await this.attempt(u, s, p);
        if (typeof r !== 'string') return r;
        if (r === 'changed') { changed = true; if (this.deployLayer(u)) full = true; continue; }
        if (r === 'rejected') { again = true; continue; }
        const n = await this.nextOrEnd(u, s, s.aiDone ?? 'the AI could not fix it');
        if (typeof n !== 'string') return n;
        if (n === 'changed') { changed = true; if (this.deployLayer(u)) full = true; }
      }
      if (changed || reprove) {
        next = await this.proveNow({ kind: 'prove', scope: full ? 'full' : 'pr' });
        if (!('ticket' in next)) return next;
        continue;
      }
      if (rerun.size > 0) {
        next = await this.proveNow({ kind: 'rerun', ids: [...rerun] });
        if (!('ticket' in next)) return next;
        continue;
      }
      if (again) continue;
      // nothing left to fix with what is stored: the key confirmation (spec §19)
      if (p.keys === 'placeholder' && this.realNames.length > 0 && !this.declined) {
        const ask = this.unconfirmed();
        if (ask.length > 0) {
          const capped = await this.capStop();   // M2: never ask the user when the run must stop anyway
          if (capped !== null) return capped;
          const yes = await this.deps.confirm(ask.map((f) => ({ ...f })));
          if (yes !== true) {
            this.declined = true;
            this.say(`You chose not to run the AI-written files with your test keys; the parts that need them are not proven.`);
            for (const u of deferred) {
              const stop = this.end(u, `${u.entry.detail}; ${DECLINED}`);
              if (stop !== null) return stop;
            }
            if (this.fullVersion !== this.version) { const f = await this.finalFull(); if (f !== null) return f; continue; }
            break;
          }
          for (const f of ask) this.confirmed.set(fileKey(f), f.content);
        }
        // a real run of this very draft already happened (its failures were tried again with placeholders): it is the result
        if (this.lastReal !== null && this.lastReal.version === this.version) {
          this.proof = this.lastReal.proof;
          continue;
        }
        next = await this.proveNow({ kind: 'prove', scope: 'full' });
        if (!('ticket' in next)) return next;
        continue;
      }
      for (const u of deferred) {
        const why = this.declined ? DECLINED : p.keys === 'real' ? 'an external host refused it even with the test key you gave' : 'it needs your real test key, and pipegen has no value for it';
        const stop = this.end(u, `${u.entry.detail}; ${why}`);
        if (stop !== null) return stop;
      }
      // E7-R13: the result is returned only from a 'full' proof of the draft as it is now
      if (this.fullVersion !== this.version) { const f = await this.finalFull(); if (f !== null) return f; continue; }
      break;
    }
    return (await this.capStop()) ?? this.finish();   // M2: at the end too (the AI meter's sticky refusal included)
  }

  /** E7-R13: one 'full' proof of the current draft (a fix proven on 'pr' never left the deploy layer on an older draft), counted. */
  async finalFull(): Promise<FixOutcome | null> {
    if (this.total >= this.maxTotal) return this.stopGlobal();
    this.total++;
    this.say('the draft changed since the last full proof, so it runs once more up to the merge and the deploy layer');
    const next = await this.proveNow({ kind: 'prove', scope: 'full' });
    return 'ticket' in next ? null : next;
  }

  // ----- one AI attempt -----

  async attempt(u: Unit, s: UState, p: Proof): Promise<'changed' | 'rejected' | 'exhausted' | FixOutcome> {
    if (s.aiDone !== null) return 'exhausted';
    const cve = this.isCve(u);
    const needIds = cve ? [] : this.needIdsOf(u);
    const dockerfiles = this.draft.created.filter((f) => f.repo === 'app' && f.part === 'docker' && isDockerfile(f.path)).map((f) => f.path);
    const paths = cve ? dockerfiles : fixPaths(this.draft, u.part);
    const cands = cve ? [] : this.candidatesOf(needIds);
    const list = cve ? this.baseList() : [];
    const current = cve ? new Set(dockerfiles.map((pth) => this.baseIdOf(pth, list)).filter((x): x is string => x !== null)) : new Set<string>();
    const baseIds = list.filter((e) => /^node-\d+-bookworm-slim$/.test(e.id) && !current.has(e.id)).map((e) => e.id);
    if ((cve && (baseIds.length === 0 || this.deps.dockerfileFor === undefined)) || (!cve && paths.length === 0 && cands.length === 0)) {
      s.aiDone = 'nothing of this part may be changed by an answer';
      return 'exhausted';
    }
    if (s.seenSeq !== p.seq) {
      const ex = await this.excerptFor(u, p);
      if ('none' in ex) { s.aiDone = ex.none; return 'exhausted'; }
      // the same error twice in a row (its error after an applied answer is the one it answered): stop the AI for this part early
      if (s.appliedSinceSig && s.lastSig === ex.sig) { s.aiDone = 'the same error came twice in a row'; return 'exhausted'; }
      s.lastSig = ex.sig;
      s.appliedSinceSig = false;
      s.seenSeq = p.seq;
      s.excerpt = ex.text;
    }
    if (s.attempts >= this.max) { s.aiDone = `the AI had its ${this.max} attempts`; return 'exhausted'; }
    if (this.total >= this.maxTotal) return this.stopGlobal();
    const capped = await this.capStop();   // E6 M2: before each AI call
    if (capped !== null) return capped;
    const schema = fixSchema({ needIds, candidateIds: cands.map((c) => c.tool.id), paths, baseIds });
    const user = this.requestText(u, s, { paths, cands, cve, baseIds, dockerfiles, current: [...current], actions: (schema.jsonSchema as { properties: { action: { enum: FixAction[] } } }).properties.action.enum });
    if (this.deps.vault.containsKnownValue(user)) { s.aiDone = 'the request would have held a value you gave pipegen, so nothing was sent'; return 'exhausted'; }
    this.total++;
    s.attempts++;
    s.ai++;
    const n = s.attempts;
    const req: AiRequest = { system: FIX_SYSTEM, user, schemaName: 'fix_answer', jsonSchema: schema.jsonSchema, timeoutMs: FIX_TIMEOUT_MS, maxOutputTokens: FIX_MAX_OUTPUT_TOKENS };
    let ans: FixAnswer;
    try {
      ans = (await completeValidated(this.deps.ai, req, schema.zod)).data;
    } catch (e) {
      if (isCostCap(e)) return (await this.capStop(e)) ?? this.finish('the AI cost cap was reached');
      if (!(e instanceof AiError)) throw e;
      return this.refuse(s, n, { action: '?', target: '' }, '', e.kind === 'invalid' ? 'the answer did not match the schema (an id that was not offered, such as a file of another part, or a missing field)' : `the AI gave no usable answer (${e.kind})`);
    }
    const explanation = this.scrub(st(ans.explanation, MAX_EXPLANATION));
    const target = ans.path ?? ans.candidateId ?? ans.baseId ?? '';
    this.say(`The AI's answer for ${u.key} (attempt ${n}): ${ans.action}${target === '' ? '' : ` ${st(target, 120)}`}. ${formatAiText(explanation, 300)}`);
    const rec = { action: ans.action, target };
    if (ans.action === 'give-up') {
      s.history.push({ n, ...rec, explanation, outcome: 'gave up', error: s.excerpt });
      s.aiDone = 'the AI found no change it is allowed to make';
      return 'exhausted';
    }
    if (ans.action === 'change-base') {
      const capped = await this.capStop();   // M2: createDockerfile calls the AI too
      if (capped !== null) return capped;
    }
    let res: string | { draft: PipelineDraft; aiFiles: string[] };
    try {
      res = ans.action === 'edit-file' ? await this.applyEdit(ans, paths) : ans.action === 'change-step' ? await this.applyStep(ans, cands) : await this.applyBase(ans, dockerfiles, baseIds);
    } catch (e) {
      // createDockerfile (deps.dockerfileFor) calls the AI too: the cap stops the run; a refused or failed Dockerfile is a refused answer
      if (isCostCap(e)) return (await this.capStop(e)) ?? this.finish('the AI cost cap was reached');
      if (!(e instanceof AiError) && (e as { name?: unknown } | null)?.name !== 'DockerfileError') throw e;
      res = `the Dockerfile could not be made from that base image (${st((e as Error).message, 300)})`;
    }
    if (typeof res === 'string') return this.refuse(s, n, rec, explanation, res);
    // E7-R14: the files the answer wrote are marked on the draft (what E8 saves, what Plan G's preview reads)
    const marked = new Set(res.aiFiles);
    this.draft = { ...res.draft, created: res.draft.created.map((f) => (f.repo === 'app' && marked.has(f.path) ? { ...f, aiEdited: true as const } : f)) };
    this.version++;
    for (const pth of res.aiFiles) this.fixed.add(pth);
    s.appliedSinceSig = true;
    s.history.push({ n, ...rec, explanation, outcome: 'applied, and the proof ran again', error: s.excerpt });
    return 'changed';
  }

  refuse(s: UState, n: number, rec: { action: string; target: string }, explanation: string, why: string): 'rejected' {
    const reason = this.scrub(st(why, 800));
    s.history.push({ n, ...rec, explanation, outcome: `refused by pipegen: ${reason}`, error: s.excerpt });
    this.say(`pipegen refused the answer (attempt ${n}): ${reason}`);
    return 'rejected';
  }

  scrub(t: string): string {
    return this.deps.keys.scrubber()(this.deps.vault.scrubber()(t));
  }

  candidatesOf(needIds: readonly string[]): StepSpec[] {
    const out: StepSpec[] = [];
    for (const id of needIds) {
      const cur = this.draft.steps.filter((x) => x.needId === id).map((x) => x.tool?.id);
      for (const c of this.deps.candidates?.(id, this.draft) ?? []) {
        if (!isRec(c) || c.needId !== id || !isRec(c.tool) || c.tool.source !== 'reviewed' || c.tool.reviewed !== true || typeof c.tool.id !== 'string') continue;
        if (cur.includes(c.tool.id) || out.some((o) => o.tool.id === c.tool.id)) continue;
        out.push(c);
      }
    }
    return out;
  }

  baseList(): readonly BaseImage[] {
    try { return loadBaseImages(); } catch { return []; }
  }

  /** The list id whose reference the Dockerfile's first FROM is (pipegen wrote it), or null. */
  baseIdOf(path: string, list: readonly BaseImage[]): string | null {
    const ref = firstFrom(this.draft.created.find((f) => f.repo === 'app' && f.path === path)?.content ?? '');
    return list.find((e) => ref !== null && baseImageRef(e.id, list) === ref)?.id ?? null;
  }

  // ----- the request -----

  requestText(u: Unit, s: UState, o: { paths: string[]; cands: StepSpec[]; cve: boolean; baseIds: string[]; dockerfiles: string[]; current: string[]; actions: FixAction[] }): string {
    const block = (tag: string, body: string, attrs = ''): string => `<${tag}${attrs}>\n${neutralizeBlocks(this.scrub(body))}\n</${tag}>`;
    const blocks: string[] = [];
    blocks.push(block('failing_part', JSON.stringify({ part: u.part, needIds: o.cve ? [] : this.needIdsOf(u), attempt: s.attempts + 1, maxAttempts: this.max })));
    if (o.cve) {
      blocks.push(block('base_image', JSON.stringify({ dockerfiles: o.dockerfiles, current: o.current, choices: o.baseIds })));
      blocks.push('The image scan found critical or high CVEs in the base image of the created Dockerfile, so another base image tag is needed: choose one of the ids in "choices".');
    } else {
      blocks.push(block('what_failed', st(u.entry.detail, 1500)));
      const shown = new Set<string>();
      const files: string[] = [];
      for (const pth of o.paths) {
        const f = this.draft.created.find((x) => x.repo === 'app' && x.path === pth);
        if (f === undefined || shown.has(pth)) continue;
        shown.add(pth);
        files.push(block('file', f.content, ` path="${neutralizeBlocks(st(pth, 200))}" editable="yes"`));
        if (isDockerfile(pth)) {
          const di = this.dockerignoreOf(pth);
          if (di !== undefined && !shown.has(di.path)) { shown.add(di.path); files.push(block('file', di.content, ` path="${neutralizeBlocks(st(di.path, 200))}" editable="no"`)); }
        }
      }
      if (files.length > 0) blocks.push(`<part_files>\n${files.join('\n')}\n</part_files>`);
      const steps = this.draft.steps.filter((x) => this.needIdsOf(u).includes(x.needId)).map((x) => ({ needId: x.needId, service: x.service ?? null, tool: x.tool?.id, name: x.tool?.name }));
      if (steps.length > 0) blocks.push(block('steps', JSON.stringify(steps)));
      if (o.cands.length > 0) blocks.push(block('candidates', JSON.stringify(o.cands.map((c) => ({ needId: c.needId, candidateId: c.tool.id, name: c.tool.name })))));
    }
    if (s.history.length > 0) {
      const items = s.history.map((h) => {
        const err = h.error.length > EARLIER_EXCERPT_CHARS ? fromLineStart(h.error, h.error.length - EARLIER_EXCERPT_CHARS) : h.error;
        return `<attempt n="${h.n}">\n${neutralizeBlocks(JSON.stringify({ action: h.action, target: h.target, explanation: h.explanation, outcome: h.outcome }))}\nThe error this answer was for:\n${err === '' ? '(no log was shown)' : untrustedLog(err)}\n</attempt>`;
      });
      blocks.push(`<earlier_attempts>\n${items.join('\n')}\n</earlier_attempts>`);
    }
    if (!o.cve) blocks.push(untrustedLog(s.excerpt));
    blocks.push(fixInstructions({ part: u.part, actions: o.actions, attempt: s.attempts + 1, maxAttempts: this.max }));
    return this.scrub(blocks.join('\n\n'));
  }

  dockerignoreOf(dockerfilePath: string): CreatedFile | undefined {
    const dir = dockerfilePath.slice(0, dockerfilePath.lastIndexOf('/') + 1);
    return this.draft.created.find((f) => f.repo === 'app' && f.path === `${dir}.dockerignore`);
  }

  // ----- applying an answer (each returns the refusal reason, or the new draft) -----

  async check(next: PipelineDraft, guardFiles: CreatedFile[]): Promise<string | null> {
    if (guardFiles.length > 0) {
      const g = await this.deps.guard(guardFiles);
      const mine = new Set(guardFiles.map((f) => f.path));
      const refused = (g?.refused ?? []).filter((r) => mine.has(r.path));
      if (refused.length > 0) return `the guard refused it: ${refused.slice(0, 4).map((r) => `${r.path}: ${r.reason}`).join('; ')}`;
      const ok = new Set((g?.ok ?? []).map((f) => f.path));
      const missing = guardFiles.filter((f) => !ok.has(f.path));
      if (missing.length > 0) return `the guard did not accept ${missing.map((f) => f.path).join(', ')}`;
    }
    const rep = await this.deps.referee(next);
    if (rep?.ok !== true) return `the referee refused it: ${(rep?.issues ?? []).slice(0, 5).map((i) => `${i.file}: ${i.message}`).join('; ') || 'no reason given'}`;
    return null;
  }

  async applyEdit(ans: FixAnswer, paths: readonly string[]): Promise<string | { draft: PipelineDraft; aiFiles: string[] }> {
    const f = this.draft.created.find((x) => x.repo === 'app' && x.path === ans.path);
    if (f === undefined || typeof ans.path !== 'string' || !paths.includes(ans.path)) return 'the answer named no file of this part that it may edit';
    if (typeof ans.content !== 'string' || ans.content.trim() === '') return 'the answer gave no file content';
    let content = ans.content.replace(/\r\n/g, '\n');
    if (!content.endsWith('\n')) content += '\n';
    if (isDockerfile(f.path)) {
      // S10: pipegen owns every FROM; the AI's own FROM lines are written back to the reviewed reference this Dockerfile had
      const ref = firstFrom(f.content);
      if (ref === null) return 'the Dockerfile has no FROM line pipegen wrote';
      try { content = ownFromLines(content, ref); } catch { return 'the Dockerfile could not be read'; }
    }
    const next: CreatedFile = { ...f, content };
    if (isTestPath(f.path)) {
      const problems = [...testProblems(f, next), ...(this.deps.checkTests ?? checkAttempt)(planOf([f]), planOf([next]))];
      if (problems.length > 0) return problems.slice(0, 4).join(' ');
    }
    const guardFiles = [next, ...(isDockerfile(f.path) ? [this.dockerignoreOf(f.path)].filter((x): x is CreatedFile => x !== undefined) : [])];
    const draft = { ...this.draft, created: this.draft.created.map((x) => (x === f ? next : x)) };
    const bad = await this.check(draft, guardFiles);
    return bad ?? { draft, aiFiles: [f.path] };
  }

  async applyStep(ans: FixAnswer, cands: readonly StepSpec[]): Promise<string | { draft: PipelineDraft; aiFiles: string[] }> {
    const c = cands.find((x) => x.needId === ans.needId && x.tool.id === ans.candidateId);
    if (c === undefined) return 'the answer named no reviewed candidate of that need';
    const draft = withStep(this.draft, c);
    const bad = await this.check(draft, []);
    return bad ?? { draft, aiFiles: [] };
  }

  async applyBase(ans: FixAnswer, dockerfiles: readonly string[], baseIds: readonly string[]): Promise<string | { draft: PipelineDraft; aiFiles: string[] }> {
    if (typeof ans.baseId !== 'string' || !baseIds.includes(ans.baseId)) return 'the answer named no base image id of the list';
    const path = ans.path !== null && dockerfiles.includes(ans.path) ? ans.path : dockerfiles.length === 1 ? dockerfiles[0] as string : null;
    if (path === null) return 'the answer did not say which Dockerfile';
    const made = await this.deps.dockerfileFor?.(path, ans.baseId, this.draft) ?? [];
    const files = made.filter((f) => isRec(f) && f.repo === 'app' && f.part === 'docker' && typeof f.path === 'string' && typeof f.content === 'string');
    const df = files.find((f) => f.path === path);
    if (df === undefined) return `no Dockerfile could be made from ${ans.baseId}`;
    if (firstFrom(df.content) !== baseImageRef(ans.baseId, this.baseList())) return 'the new Dockerfile does not build from the chosen base image';
    let created = [...this.draft.created];
    for (const f of files) {
      const i = created.findIndex((x) => x.repo === f.repo && x.path === f.path);
      created = i < 0 ? [...created, f] : created.map((x, k) => (k === i ? f : x));
    }
    const draft = { ...this.draft, created };
    const bad = await this.check(draft, files);
    return bad ?? { draft, aiFiles: files.filter((f) => f.content !== this.draft.created.find((x) => x.path === f.path)?.content).map((f) => f.path) };
  }

  // ----- the next reviewed candidate -----

  async nextOrEnd(u: Unit, s: UState, why: string): Promise<'changed' | 'ended' | FixOutcome> {
    for (const id of this.needIdsOf(u)) {
      for (let k = 0; k < MAX_CANDIDATE_TRIES; k++) {
        const got = await this.deps.nextCandidate(id, this.draft);
        if (got === null || got === undefined) break;
        const step = isRec(got) && 'step' in got ? (got as { step: StepSpec }).step : got as StepSpec;
        const files = isRec(got) && 'step' in got && Array.isArray((got as { files?: unknown }).files) ? (got as { files: CreatedFile[] }).files : [];
        if (!isRec(step) || step.needId !== id || !isRec(step.tool) || step.tool.source !== 'reviewed' || step.tool.reviewed !== true) continue;
        if (this.total >= this.maxTotal) return this.stopGlobal();
        let draft = withStep(this.draft, step);
        const brought: CreatedFile[] = [];
        for (const f0 of files) {
          if (!isRec(f0) || typeof f0.path !== 'string' || typeof f0.content !== 'string' || (f0.repo !== 'app' && f0.repo !== 'central')) continue;
          const old = draft.created.find((x) => x.repo === f0.repo && x.path === f0.path);
          // spec §9: any change to package.json scripts or dependencies gets its own preview section and its own yes
          const f: CreatedFile = base(f0.path) === 'package.json' && scriptsOrDepsChanged(old?.content, f0.content) ? { ...f0, needsConfirm: true } : { ...f0 };
          brought.push(f);
          draft = { ...draft, created: old === undefined ? [...draft.created, f] : draft.created.map((x) => (x === old ? f : x)) };
        }
        const bad = await this.check(draft, brought);
        if (bad !== null) { this.say(`${u.key}: the next reviewed tool ${st(step.tool.id, 80)} was refused: ${this.scrub(bad)}`); continue; }
        this.total++;
        this.draft = draft;
        this.version++;
        s.attempts = 0;
        s.lastSig = null;
        s.appliedSinceSig = false;
        s.history = [];
        s.aiDone = null;
        s.reruns = 0;
        this.say(`${u.key}: ${why}; switched ${st(id, 60)} to the next reviewed tool, ${st(step.tool.id, 80)}, with a fresh count of ${this.max} attempts`);
        return 'changed';
      }
    }
    const n = s.ai;
    const stop = this.end(u, `failed after ${n} attempt${n === 1 ? '' : 's'} (last failure: ${s.lastClass ?? 'needs-fix'}): ${u.entry.detail}; ${why}; no other reviewed tool is left`);
    return stop ?? 'ended';
  }
}

// ---------- small helpers ----------

/** The image of the first FROM that is not an earlier stage alias (pipegen wrote it), or null. */
function firstFrom(text: string): string | null {
  try {
    for (const ins of parseDockerfile(text).instructions) {
      if (ins.kw !== 'FROM') continue;
      const w = ins.args.replace(/^(?:--\S+\s+)+/, '').split(/\s+/).filter((x) => x !== '');
      return w[0] ?? null;
    }
  } catch { /* unreadable */ }
  return null;
}

/** The draft with `step` in place of the step for its need (and service), or added. */
function withStep(d: PipelineDraft, step: StepSpec): PipelineDraft {
  const same = (x: StepSpec): boolean => x.needId === step.needId && (x.service ?? null) === (step.service ?? null);
  return { ...d, steps: d.steps.some(same) ? d.steps.map((x) => (same(x) ? step : x)) : [...d.steps, step] };
}

const planOf = (files: CreatedFile[]): TestPlan => ({ framework: '', reasons: [], files, configEdits: [], notes: [] });
const SKIP_RE = /\.(?:skip|only|todo|skipIf|runIf|fails)\b|\b(?:xit|xtest|xdescribe|fit|fdescribe)\s*\(/;

/** A test answer may not have fewer tests or assertions, and never skips, focuses or marks one (spec §19). */
function testProblems(before: CreatedFile, after: CreatedFile): string[] {
  const out: string[] = [];
  const a = fileStats(before.path, before.content), b = fileStats(after.path, after.content);
  if (b === null) out.push('The new test file could not be parsed.');
  else if (a !== null) {
    if (b.tests < a.tests) out.push(`The answer has ${b.tests} test${b.tests === 1 ? '' : 's'}, fewer tests than the ${a.tests} before; a failing test is fixed, not removed.`);
    if (b.assertions < a.assertions) out.push(`The answer has fewer assertions (${b.assertions}) than before (${a.assertions}); a test is not made to pass by checking less.`);
  }
  if (SKIP_RE.test(after.content)) out.push('The answer skips, focuses or marks a test (.skip, .only, .todo, xit), which is never accepted.');
  return out;
}

/**
 * The fix loop (plan Task 5). Proves `draft` (scope 'full'), then fixes the failing parts under the limits, with the key confirmation
 * (see the file header). Returns the last draft and result, with `stopped` when it ended early.
 */
export async function proveWithFixes(draft: PipelineDraft, deps: FixDeps, opts: { maxAttempts?: number; maxTotalAttempts?: number } = {}): Promise<FixOutcome> {
  if (deps?.meters?.ai === undefined || deps.ai !== deps.meters.ai.provider) throw new Error('The fix loop calls the AI only through the run\'s spend meter (meteredProvider); nothing was sent.');
  return new FixLoop(draft, deps, opts).run();
}
