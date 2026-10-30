// Plan C Task C2: the gate's decision. decideGate turns every listed check's job result, its scrubbed findings (read back with
// readScrubbed), the base and the settings into PASS or BLOCK, and writes the step summary. A wrong pass is the worst bug pipegen
// can have, so every unclear case blocks and says why.
//
// Pure: no file, no network, no clock, no environment. Everything comes in through GateInput (C5 fetches it: the job list, the
// `toJSON(needs)` results and outputs, the downloaded artifacts, the base-scan job, the ancestry fact, the trusted baseline (C3),
// the PR's added lines and integrity findings (C4), the settings). The same input always gives the same result.
//
// The rules, in the order they are applied (Plan C Task 2 rules 1-9 as amended by the pre-flight rulings B7, S2, S8, S12, S19,
// DECISIONS #110 and the must-dos CF3b, C1b I1/I2 and the coverage notes; the report task-C2-report.md has the full table):
//  1. Settings: the settings errors C5 found, a policy that is not one (policy-default.ts, shared with the engine), a floor need
//     in not-proven, warn-first on a floor need, a need that can never be skipped in `skipped`. Each blocks.
//  2. Each check's run (B7): clean only with result `success` (findings: also status `ok`, a file whose sha256 equals the job's
//     output, readable). Otherwise, in this order: skipped by the user (shown as skipped); on a fork PR a check that needs
//     secrets (#110: "not run on a fork PR", blocks if required); a tool error (its own section; blocks if required); a
//     not-proven check (warning); a non-blocking check (note, S19); a warn-first job-status check (warning, S12); else a failed
//     required check (blocks). A status `ok` with a missing or different hash, or a file problem C5 found, is tampered (blocks).
//  3. The base (CF3b): the base-scan result counts only when the commit it checked out equals the base of this event (pull_request
//     base.sha, merge_group base_sha, push before) and the ancestry fact says it is an ancestor of the head. Otherwise there is
//     no base: every finding compared with the base scan is new. A base tool error is a tool error (blocks if required).
//  4. Which base (rule 5): dependency and image tools (`sameRunTools`) only the same-run base scan; other tools the trusted
//     baseline when it covers the tool, else the base scan. A scanner that could not run on the base: warnings on an installing
//     PR, else every finding new.
//  5. New, per finding form (C1b I1, the brief): content forms are counted per (check, tool, fingerprint); position forms are
//     also new when the PR touched any of their lines or they have no repository file (only with a diff; without one, counts
//     only); an unmapped secret is always new; an unmapped non-secret is counted per (check, tool, rule); `secret:not-scanned`
//     is new unless the same file hash (the `file` form) is in the base.
//  6. What blocks: a check that is not required (not proven, ZAP while unverified, non-blocking) never blocks. A MAL- advisory
//     blocks even when old (S8). A new critical, high or secret blocks in any mode, warn-first too (rule 7, #13). A new
//     dependency-review finding blocks. An unknown licence warns ("needs a human"). Warn-first: the rest warns. Block mode:
//     the policy. Warn mode: critical, high and medium warn; low and info are counted.
//  7. Secrets in the PR's commit range (C1b I2): a range finding the HEAD scan does not have is always new and blocks.
//  8. Integrity (Task 4): blocks, or warns on an installing PR.
//  9. Coverage honesty (C1a): a nuclei "nothing reported" or an unstaged gitleaks zero-finding result is "no coverage /
//     completeness not provable", never clean; a required one blocks.
import { NEED_ID_CATEGORY } from '../../src/engine/need-ids.js';
import type { JobListEntry } from '../../src/engine/gate-job-list.js';
import { FLOOR_NEEDS, type Finding, type Severity } from '../../src/types.js';
import { safeMarkdown } from '../../src/util/safe-text.js';
import type { FpBy } from './fingerprint.js';
import { DEFAULT_POLICY, policyProblem, SEVERITIES, type Policy } from './policy-default.js';
import { SARIF_TOOLS } from './sarif.js';
import type { ScrubbedFinding, ScrubbedResult } from './scrub.js';
import { ZAP_JSON_VERIFIED, ZAP_TOOL } from './zap.js';

export type { Policy } from './policy-default.js';
export type GateMode = 'warn' | 'block';
/** `needs.<job>.result`, or `missing` when the job list names a job that `toJSON(needs)` does not hold. */
export type JobResult = 'success' | 'failure' | 'cancelled' | 'skipped' | 'missing';

/** The event the gate runs for: `github.event_name`, `github.sha` and the event payload (GITHUB_EVENT_PATH), unchanged. */
export interface GateEvent { name: string; sha: string; payload: unknown }
/** A job's outputs for one artifact (`<artifact>-status`, `-sha256`, `-error`), as `toJSON(needs)` gives them; absent ones absent. */
export interface JobOutputs { status?: string; sha256?: string; error?: string }
/**
 * A downloaded result artifact: the sha256 of its bytes (C5 computes it), the file read back with readScrubbed, and `problem`
 * when C5's own artifact checks failed (a second zip entry, a link, a wrong name, over the size cap): then it is tampered.
 */
export interface ResultFile { sha256: string; read: ScrubbedResult; problem?: string }
/** One entry of the trusted job list with everything this run says about it. */
export interface CheckInput {
  /** From the trusted job list (gateJobList, rendered as the gate's `job-list` literal): never from the needs object. */
  entry: JobListEntry;
  /** `needs[entry.job].result`, `missing` when absent. */
  result: JobResult;
  /** Findings entries: `needs[entry.job].outputs` for `entry.artifact`. Job-status entries: `{}`. */
  outputs: JobOutputs;
  /** Findings entries: the artifact `entry.artifact` of this run, when it could be downloaded. */
  file?: ResultFile;
  /** Findings entries: the base-scan job's outputs for `entry.baseArtifact`, and that artifact when it could be downloaded. */
  base?: { outputs: JobOutputs; file?: ResultFile };
}
/** A secrets scan of the PR's commit range (base..head, C1b review I2), read back like a result file; absent `findings` = no result. */
export interface RangeScan { tool: string; findings?: ScrubbedFinding[]; toolError?: string }
/** The trusted baseline (C3): counts by countKeyOf, and the tools it covers (a tool it does not cover falls back to the base scan). */
export interface Baseline { tools: readonly string[]; counts: ReadonlyMap<string, number> }
/** The PR's added lines per repository path (C4 addedLines); `complete: false` when the file list or a patch was cut. */
export interface PrDiff { added: ReadonlyMap<string, ReadonlySet<number>>; complete: boolean }

export interface GateInput {
  /** The event (base and head commits, fork or not, all from the payload). */
  event: GateEvent;
  /** One per job-list entry. */
  checks: readonly CheckInput[];
  /** The `base-scan` job: its result and the commit it checked out (its `base-sha` output); null when the run has no base-scan job. */
  baseScan: { result: JobResult; commit?: string } | null;
  /** C5's compare-API answer: whether `base` is an ancestor of `head` (the PR head or github.sha); null when not known. */
  ancestry: { base: string; head: string; isAncestor: boolean } | null;
  /** The trusted artifact baseline (C3); null when there is none (first run, expired, fork, other key). */
  baseline: Baseline | null;
  /** Dependency and image tools (from the built-in reviewed list): always compared with the same-run base scan only. */
  sameRunTools: readonly string[];
  /** The base commit has no pipegen install (C4 baseHasInstall), decided by the base's files, never by the branch name. */
  installing: boolean;
  /** The PR's added lines (C4); null on an event without a diff (push, merge_group, schedule). */
  diff: PrDiff | null;
  /** Secrets scans of the PR's commit range; empty when there is none on this event. */
  rangeScans: readonly RangeScan[];
  /** C3 resolveMode: warn mode for old findings until the block-from date or the first trusted clean run. */
  mode: GateMode;
  /** The policy (private repos: from the central workflow; public: the built-in default). Checked again here. */
  policy: unknown;
  /** Need ids judged as not proven (warn-only, never required). */
  notProvenNeeds: readonly string[];
  /** The user's --skip, by need id: shown as skipped, never as clean. */
  skipped: readonly { needId: string; reason: string }[];
  /** C5 resolveSettings errors (each blocks). */
  settingsErrors: readonly string[];
  /** C4 integrity findings, already filtered by a head-commit code-owner approval. */
  integrity: readonly Finding[];
}

/** A finding as decided: which check, new or old (`undefined`: no base to tell, an installing PR), and why. */
export interface DecidedFinding extends ScrubbedFinding { needId: string; job: string; isNew: boolean | undefined; reason: string }
export interface CheckRef { needId: string; job: string; tool?: string; reason: string }
export interface ToolErrorItem extends CheckRef { base: boolean; blocks: boolean }
export interface CheckState { needId: string; job: string; tool?: string; judgedBy: 'findings' | 'job status'; state: string }
export interface GateResult {
  pass: boolean;
  mode: GateMode;
  /** Findings that block, and findings that warn. Low and info findings that do neither are only counted. */
  blocking: DecidedFinding[];
  warnings: DecidedFinding[];
  counted: Record<Severity, number>;
  /** Every reason the gate blocks other than a finding (settings, runs, tool errors, tampering, integrity, coverage), raw text. */
  blockReasons: string[];
  /** Warnings other than a finding (a not-proven or warn-first check that failed, installing integrity), raw text. */
  warnReasons: string[];
  failedJobs: CheckRef[];
  notRun: CheckRef[];
  toolErrors: ToolErrorItem[];
  noCoverage: CheckRef[];
  notScanned: DecidedFinding[];
  skipped: { needId: string; job?: string; reason: string }[];
  notProven: CheckRef[];
  integrity: { blocks: boolean; findings: Finding[] };
  checks: CheckState[];
  notes: string[];
  /** The step summary (GitHub Markdown): every repo-derived string in it went through safeMarkdown exactly once. */
  summary: string;
}

/** DECISIONS #110: the text for a check that needs secrets and did not run on a fork PR. */
export const NOT_RUN_FORK = 'not run on a fork PR (no secrets): a maintainer must run it from a branch of this repository';
/** C1c: the rule id of a staged file the secrets scanner did not confirm it read. */
export const NOT_SCANNED_RULE_ID = 'secret:not-scanned';
/** How each fingerprint form is compared (fingerprint.ts FpBy): content forms by count, position forms by count and by the diff. */
export const FORM_OF: Readonly<Record<FpBy, 'content' | 'position'>> = Object.freeze({
  hash: 'content', region: 'content', quoted: 'content', file: 'content', line: 'position', nokey: 'position', 'quoted-nokey': 'position',
});
const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
/** Never in `skipped` (types.ts SkippablePart: the secrets scan and the gate never; sast and deps are not skippable parts). */
const NEVER_SKIPPED: ReadonlySet<string> = new Set(['secrets', 'sast', 'deps', 'gate']);
const SHA_RE = /^[0-9a-f]{40}$/;
const ZERO_SHA = '0'.repeat(40);
const GITLEAKS_NOTE = SARIF_TOOLS.gitleaks?.note ?? 'completeness not provable (gitleaks)';
const NOTHING_REPORTED = 'nothing reported';
const SHOWN_PER_TOOL = 10;

/** The count key of a finding in a check (C3 stores the baseline by this key): an unmapped non-secret by (check, tool, rule), anything else by (check, tool, fingerprint). */
export function countKeyOf(job: string, f: Pick<ScrubbedFinding, 'tool' | 'ruleId' | 'fingerprint' | 'secret' | 'uriUnmapped'>): string {
  return f.uriUnmapped && !f.secret ? `unmapped\0${job}\0${f.tool}\0${f.ruleId}` : `fp\0${job}\0${f.tool}\0${f.fingerprint}`;
}

// ---------- the event ----------

function at(o: unknown, ...path: string[]): unknown {
  let v = o;
  for (const k of path) {
    if (typeof v !== 'object' || v === null || Array.isArray(v) || !Object.hasOwn(v, k)) return undefined;
    v = (v as Record<string, unknown>)[k];
  }
  return v;
}
const sha40 = (v: unknown): string | undefined => (typeof v === 'string' && SHA_RE.test(v) ? v : undefined);

/**
 * The base commit this event compares with, from its own payload (the same switch the engine renders for the base-scan
 * checkout, tool-flags.ts BASE_CHECKOUT_REF), and the commits that count as its head (the payload's head and github.sha). No
 * base on any other event, for an all-zero base (a new branch), or for a base equal to a head.
 */
export function expectedBaseOf(ev: GateEvent): { base?: string; heads: string[]; why?: string } {
  const p = ev.payload;
  const pair = ev.name === 'pull_request' ? [at(p, 'pull_request', 'base', 'sha'), at(p, 'pull_request', 'head', 'sha')]
    : ev.name === 'merge_group' ? [at(p, 'merge_group', 'base_sha'), at(p, 'merge_group', 'head_sha')]
      : ev.name === 'push' ? [at(p, 'before'), at(p, 'after')] : undefined;
  const heads = [...new Set([sha40(pair?.[1]), sha40(ev.sha)].filter((x): x is string => x !== undefined))];
  if (pair === undefined) return { heads, why: `a ${ev.name} event has no base commit` };
  const base = sha40(pair[0]);
  if (base === undefined) return { heads, why: 'the event payload has no base commit' };
  if (base === ZERO_SHA) return { heads, why: 'the base commit is all zeros (a new branch)' };
  if (heads.includes(base)) return { heads, why: 'the base commit is the head' };
  return { base, heads };
}

/** A fork PR: `pull_request.head.repo.id` and `repository.id` are both numbers and differ (the scrub's rule, scrub.ts forkFromEvent). */
function isFork(payload: unknown): boolean {
  const head = at(payload, 'pull_request', 'head', 'repo', 'id');
  const repo = at(payload, 'repository', 'id');
  return typeof head === 'number' && typeof repo === 'number' && head !== repo;
}

type BaseState = { kind: 'verified' } | { kind: 'absent'; why: string } | { kind: 'unverified'; why: string };
function verifyBase(i: GateInput): BaseState {
  if (i.baseScan === null) return { kind: 'absent', why: 'this run has no base-scan job' };
  const exp = expectedBaseOf(i.event);
  if (exp.base === undefined) return { kind: 'unverified', why: exp.why ?? 'no base commit' };
  if (i.baseScan.commit !== exp.base) return { kind: 'unverified', why: 'the base-scan job did not check out the base commit of this event' };
  const a = i.ancestry;
  if (a === null || a.base !== exp.base || !exp.heads.includes(a.head)) return { kind: 'unverified', why: 'the base commit could not be verified as an ancestor of the head' };
  if (!a.isAncestor) return { kind: 'unverified', why: 'the base commit is not an ancestor of the head' };
  return { kind: 'verified' };
}

// ---------- the decision ----------

type Level = 'required' | 'not-proven' | 'advisory';
const isFindingsEntry = (e: JobListEntry): boolean => e.format === 'sarif' || e.format === 'zap-json';
const isFloorNeed = (needId: string): boolean =>
  FLOOR.has(needId) || (Object.hasOwn(NEED_ID_CATEGORY, needId) && FLOOR.has((NEED_ID_CATEGORY as Readonly<Record<string, string>>)[needId] as string));
const isFloorEntry = (e: JobListEntry): boolean => isFloorNeed(e.needId) || FLOOR.has(e.category);
const serious = (f: ScrubbedFinding): boolean => f.severity === 'critical' || f.severity === 'high' || f.secret;
const isPosition = (f: ScrubbedFinding): boolean => FORM_OF[f.fpBy] === 'position' || (f.secret && f.tool.startsWith('trivy'));

type FileState = { kind: 'ok'; read: ScrubbedResult } | { kind: 'absent' } | { kind: 'tool-error'; why: string } | { kind: 'tampered'; why: string } | { kind: 'missing-file' };
/** What a job's outputs and its downloaded file say: ok, no status (did not report / could not run), a tool error, tampered. */
function fileState(outputs: JobOutputs | undefined, file: ResultFile | undefined): FileState {
  const st = outputs?.status;
  if (st === undefined) return { kind: 'absent' };
  if (st === 'tool-error') return { kind: 'tool-error', why: outputs?.error ?? 'no detail' };
  if (st !== 'ok') return { kind: 'tampered', why: 'its status output is neither ok nor tool-error' };
  if (outputs?.sha256 === undefined) return { kind: 'tampered', why: 'it has no sha256 output' };
  if (file === undefined) return { kind: 'missing-file' };
  if (file.problem !== undefined) return { kind: 'tampered', why: file.problem };
  if (file.sha256 !== outputs.sha256) return { kind: 'tampered', why: 'its sha256 does not equal the job\'s output' };
  if (file.read.toolError !== undefined) return { kind: 'tool-error', why: `the result could not be read back: ${file.read.toolError}` };
  return { kind: 'ok', read: file.read };
}

function countsOf(job: string, fs: readonly ScrubbedFinding[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const f of fs) { const k = countKeyOf(job, f); m.set(k, (m.get(k) ?? 0) + 1); }
  return m;
}

function touched(diff: PrDiff, f: ScrubbedFinding): boolean {
  const set = f.file === undefined ? undefined : diff.added.get(f.file);
  if (set === undefined || set.size === 0) return false;
  if (f.line === undefined) return true;   // no line, in a file the PR changed (C1c open point)
  const from = f.line;
  const to = Math.max(f.endLine ?? f.line, from);
  if (to - from + 1 <= set.size) { for (let n = from; n <= to; n++) if (set.has(n)) return true; return false; }
  for (const n of set) if (n >= from && n <= to) return true;
  return false;
}

export function decideGate(i: GateInput): GateResult {
  const blocking: DecidedFinding[] = [];
  const warnings: DecidedFinding[] = [];
  const counted: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const blockReasons: string[] = [];
  const warnReasons: string[] = [];
  const failedJobs: CheckRef[] = [];
  const notRun: CheckRef[] = [];
  const toolErrors: ToolErrorItem[] = [];
  const noCoverage: CheckRef[] = [];
  const notScanned: DecidedFinding[] = [];
  const notProven: CheckRef[] = [];
  const checks: CheckState[] = [];
  const notes: string[] = [];
  const note = (n: string): void => { if (!notes.includes(n)) notes.push(n); };
  const block = (r: string): void => { if (!blockReasons.includes(r)) blockReasons.push(r); };
  const warn = (r: string): void => { if (!warnReasons.includes(r)) warnReasons.push(r); };

  // 1. settings
  for (const s of i.settingsErrors) block(s);
  const pp = policyProblem(i.policy);
  const policy: Readonly<Policy> = pp === null ? (i.policy as Policy) : DEFAULT_POLICY;
  if (pp !== null) block(`the policy is refused (it must be ${pp}), so the default policy is used`);
  const notProvenSet = new Set(i.notProvenNeeds);
  for (const n of notProvenSet) if (isFloorNeed(n)) block(`not-proven can't include floor need ${n}`);
  const skippedBy = new Map<string, string>();
  for (const s of i.skipped) {
    if (NEVER_SKIPPED.has(s.needId)) block(`${s.needId} can never be skipped`);
    else if (!skippedBy.has(s.needId)) skippedBy.set(s.needId, s.reason);
  }
  for (const c of i.checks) if (c.entry.warnFirst !== undefined && isFloorEntry(c.entry)) block(`warn-first can't be set on floor need ${c.entry.needId}`);

  const fork = isFork(i.event.payload);
  const baseState = verifyBase(i);
  if (baseState.kind === 'unverified') note(`no base: ${baseState.why}, so every finding compared with the base scan is new`);
  if (i.diff === null) note('no diff on this event: position-based fingerprints are compared by count only');
  const ranSkipped = new Set<string>();
  const headFindings: { job: string; f: ScrubbedFinding }[] = [];

  for (const c of i.checks) {
    const e = c.entry;
    const floor = isFloorEntry(e);
    const zapUnverified = e.tool === ZAP_TOOL && !ZAP_JSON_VERIFIED;
    const level: Level = !floor && (notProvenSet.has(e.needId) || zapUnverified) ? 'not-proven' : !e.blocking && !floor ? 'advisory' : 'required';
    const findings = isFindingsEntry(e);
    const tool = e.tool ?? e.needId;
    const name = `${tool} (${e.job})`;
    const ref = (reason: string): CheckRef => ({ needId: e.needId, job: e.job, ...(e.tool === undefined ? {} : { tool: e.tool }), reason });
    const state = (s: string): void => { checks.push({ needId: e.needId, job: e.job, ...(e.tool === undefined ? {} : { tool: e.tool }), judgedBy: findings ? 'findings' : 'job status', state: s }); };
    if (level === 'not-proven') notProven.push(ref(zapUnverified && !notProvenSet.has(e.needId) ? 'ZAP results are not verified yet, so this DAST check is judged as not proven (warnings only)' : 'not proven: warnings only'));
    const toolError = (why: string, base: boolean): void => {
      const blocks = level === 'required';
      toolErrors.push({ ...ref(why), base, blocks });
      const text = `tool error in ${name}${base ? ' on the base commit' : ''}: re-run the job`;
      if (blocks) block(text); else if (level === 'not-proven') warn(`${text} (not proven: a warning only)`); else note(`${text} (a non-blocking check)`);
    };
    const tampered = (what: string, why: string): void => { block(`result tampered or missing: ${e.job} (${what}: ${why})`); };
    const didNotReport = (): void => {
      const text = `scanner ${name} did not report`;
      if (level === 'required') block(text); else if (level === 'not-proven') warn(`${text} (not proven: a warning only)`); else note(`${text} (a non-blocking check)`);
    };

    // 2. the run (B7, #110)
    if (c.result !== 'success') {
      const skip = skippedBy.get(e.needId);
      if (skip !== undefined) { state('skipped'); continue; }
      if (fork && e.needsSecrets) {
        if (level === 'required') { notRun.push(ref(NOT_RUN_FORK)); block(`${name}: ${NOT_RUN_FORK}`); } else warn(`${name}: ${NOT_RUN_FORK} (${level === 'advisory' ? 'a non-blocking check' : 'not proven'})`);
        state('not run (fork PR)');
        continue;
      }
      if (findings && c.outputs.status === 'tool-error') { toolError(c.outputs.error ?? 'no detail', false); state('tool error'); continue; }
      const text = `${name} did not succeed (${c.result})`;
      if (level === 'not-proven') warn(`not-proven check ${text}: a warning only`);
      else if (level === 'advisory') note(`non-blocking check ${text}`);
      else if (e.warnFirst !== undefined && !findings) warn(`warn-first check ${text}: a warning until a reviewed pull request makes it blocking`);
      else { failedJobs.push(ref(c.result)); block(`required check ${text}`); }
      state(`failed (${c.result})`);
      continue;
    }
    ranSkipped.add(e.needId);
    if (!findings) { state('passed'); continue; }
    const head = fileState(c.outputs, c.file);
    if (head.kind === 'absent') { didNotReport(); state('did not report'); continue; }
    if (head.kind === 'tool-error') { toolError(head.why, false); state('tool error'); continue; }
    if (head.kind === 'tampered') { tampered(e.artifact ?? e.job, head.why); state('tampered'); continue; }
    if (head.kind === 'missing-file') {
      if (level === 'advisory') { note(`the result of non-blocking check ${name} is missing`); state('did not report'); } else { tampered(e.artifact ?? e.job, 'the artifact is missing'); state('tampered'); }
      continue;
    }
    const fs = head.read.findings;
    for (const n of head.read.notes) note(`${e.job}: ${n}`);
    for (const f of fs) headFindings.push({ job: e.job, f });

    // 9. coverage honesty
    const nothing = fs.length === 0 && (head.read.notes.some((n) => n.startsWith(NOTHING_REPORTED)) || e.tool === 'nuclei' || (e.tool === 'gitleaks' && head.read.notes.includes(GITLEAKS_NOTE)));
    if (nothing) {
      noCoverage.push(ref('nothing reported, so completeness is not provable: never counted as covered'));
      if (level === 'required') block(`no coverage for ${name}: completeness not provable, and a required check can't pass without it`);
      state('no coverage (completeness not provable)');
      continue;
    }

    // 3-4. the base
    const bf = c.base === undefined ? ({ kind: 'absent' } as FileState) : fileState(c.base.outputs, c.base.file);
    if (bf.kind === 'tool-error') toolError(bf.why, true);
    if (bf.kind === 'tampered') tampered(e.baseArtifact ?? `${e.job} base`, bf.why);
    if (bf.kind === 'missing-file') tampered(e.baseArtifact ?? `${e.job} base`, 'the base artifact is missing');
    const sameRun = e.tool !== undefined && i.sameRunTools.includes(e.tool);
    let counts: ReadonlyMap<string, number> | undefined;
    let noBase: 'installing' | 'new' | undefined;
    if (!sameRun && i.baseline !== null && e.tool !== undefined && i.baseline.tools.includes(e.tool)) counts = i.baseline.counts;
    else if (bf.kind === 'ok' && baseState.kind === 'verified') counts = countsOf(e.job, bf.read.findings);
    else if (bf.kind === 'absent' && baseState.kind !== 'unverified') {
      noBase = i.installing ? 'installing' : 'new';
      note(`scanner ${name} couldn't run on the base commit: ${i.installing ? 'its findings are warnings (installing pipegen)' : 'all its findings are new'}`);
    } else noBase = 'new';

    // 5. new or old, per finding form
    const decided: DecidedFinding[] = fs.map((f) => ({ ...f, needId: e.needId, job: e.job, isNew: undefined, reason: '' }));
    const groups = new Map<string, DecidedFinding[]>();
    for (const d of decided) {
      const set = (isNew: boolean | undefined, reason: string): void => { d.isNew = isNew; d.reason = reason; };
      if (d.ruleId === NOT_SCANNED_RULE_ID && d.fpBy !== 'file') { set(true, 'new: not scanned, and without a key its file can not be matched with the base'); continue; }
      if (d.secret && d.uriUnmapped) { set(true, 'new: a secret in a file that could not be mapped to a repository path'); continue; }
      if (noBase === 'installing' && d.ruleId !== NOT_SCANNED_RULE_ID) { set(undefined, 'no base: the scanner couldn\'t run on the base commit (installing pipegen)'); continue; }
      if (counts === undefined) { set(true, 'new: no base to compare with'); continue; }
      if (isPosition(d) && i.diff !== null) {
        if (d.file === undefined) { set(true, 'new: a position-based fingerprint with no repository file'); continue; }
        if (!i.diff.complete) { set(true, 'new: the pull request\'s file list is incomplete'); continue; }
        if (touched(i.diff, d)) { set(true, 'new: on a changed line of this pull request'); continue; }
      }
      const k = countKeyOf(e.job, d);
      const g = groups.get(k);
      if (g === undefined) groups.set(k, [d]); else g.push(d);
    }
    for (const [k, g] of groups) {
      const inBase = counts?.get(k) ?? 0;
      g.forEach((d, n) => { d.isNew = n >= inBase; d.reason = n >= inBase ? (inBase === 0 ? 'new: not in the base' : 'new: more than in the base') : 'old: also in the base'; });
    }

    // 6. what blocks
    for (const d of decided) {
      if (d.ruleId === NOT_SCANNED_RULE_ID) notScanned.push(d);
      const licenceUnknown = e.category === 'licences' && d.severity === 'info';
      const shown = serious(d) || d.severity === 'medium' || licenceUnknown;
      const put = (to: 'block' | 'warn' | 'count', why?: string): void => {
        if (why !== undefined) d.reason = `${d.reason}; ${why}`;
        if (to === 'block') blocking.push(d); else if (to === 'warn') warnings.push(d); else counted[d.severity]++;
      };
      if (level !== 'required') { put(shown ? 'warn' : 'count', level === 'advisory' ? 'a non-blocking check: never blocks' : 'not proven: never blocks'); continue; }
      if (/^MAL-/.test(d.ruleId)) { put('block', 'a malicious package advisory (MAL-): blocks even when old'); continue; }
      if (d.isNew === undefined) { put(shown ? 'warn' : 'count'); continue; }
      if (d.isNew && serious(d)) { put('block', 'a new critical, high or secret finding blocks in any mode'); continue; }
      if (e.warnFirst !== undefined) { put(shown ? 'warn' : 'count', 'warn-first: a warning until a reviewed pull request makes the check blocking'); continue; }
      if (d.isNew && e.category === 'dependency-review') { put('block', 'a new vulnerability in dependency review'); continue; }
      if (licenceUnknown) { put('warn', 'an unknown licence: needs a human, never blocks'); continue; }
      if (i.mode === 'block') put(policy.block.includes(d.severity) ? 'block' : policy.warn.includes(d.severity) ? 'warn' : 'count');
      else put(shown ? 'warn' : 'count');
    }
    state(fs.length === 0 ? 'no findings' : `${fs.length} finding(s)`);
  }

  // 7. secrets in the PR's commit range
  for (const rs of i.rangeScans) {
    const name = `${rs.tool} (the pull request's commit range)`;
    if (rs.toolError !== undefined) {
      toolErrors.push({ needId: 'secrets', job: 'commit range', tool: rs.tool, reason: rs.toolError, base: false, blocks: true });
      block(`tool error in ${name}: re-run the job`);
      continue;
    }
    if (rs.findings === undefined) { block(`scanner ${name} did not report`); continue; }
    const inHead = new Map<string, number>();
    for (const { f } of headFindings) if (f.tool === rs.tool) { const k = `${f.tool}\0${f.fingerprint}`; inHead.set(k, (inHead.get(k) ?? 0) + 1); }
    for (const f of rs.findings) {
      const k = `${f.tool}\0${f.fingerprint}`;
      const left = inHead.get(k) ?? 0;
      if (left > 0) { inHead.set(k, left - 1); continue; }
      blocking.push({ ...f, needId: 'secrets', job: 'commit range', isNew: true, reason: 'new: a secret in the pull request\'s commits that is not in its last commit; it was pushed, so treat it as leaked and rotate it' });
    }
  }

  // 8. integrity
  const integrityBlocks = i.integrity.length > 0 && !i.installing;
  if (i.integrity.length > 0) {
    if (i.installing) warn('installing pipegen: review these files');
    else block('pipeline files changed or suppressions added without code-owner approval on the current commit');
  }

  const skipped = i.skipped.filter((s) => skippedBy.get(s.needId) === s.reason && !ranSkipped.has(s.needId))
    .map((s) => { const job = i.checks.find((c) => c.entry.needId === s.needId)?.entry.job; return { needId: s.needId, ...(job === undefined ? {} : { job }), reason: s.reason }; });
  const pass = blockReasons.length === 0 && blocking.length === 0;
  const result: Omit<GateResult, 'summary'> = {
    pass, mode: i.mode, blocking, warnings, counted, blockReasons, warnReasons, failedJobs, notRun, toolErrors, noCoverage, notScanned,
    skipped, notProven, integrity: { blocks: integrityBlocks, findings: [...i.integrity] }, checks, notes,
  };
  return { ...result, summary: renderSummary(result, i.installing) };
}

// ---------- the summary ----------

/** The one place repo-derived text enters the summary: safeMarkdown, exactly once per value. */
const md = (s: string, max?: number): string => {
  const v = safeMarkdown(s, max);
  return v === '' ? '(empty)' : v;
};

function findingLines(fs: readonly DecidedFinding[]): string[] {
  const out: string[] = [];
  const byTool = new Map<string, DecidedFinding[]>();
  for (const f of fs) { const g = byTool.get(f.tool); if (g === undefined) byTool.set(f.tool, [f]); else g.push(f); }
  for (const [tool, g] of byTool) {
    out.push(`#### ${md(tool)}`);
    // one line per (severity, new or old, rule, file, message, reason), with its count (C1b review m4: the count per rule and file)
    const lines = new Map<string, { f: DecidedFinding; n: number }>();
    for (const f of g) {
      const k = JSON.stringify([f.severity, f.isNew, f.ruleId, f.file ?? f.displayPath ?? '', f.message, f.reason]);
      const l = lines.get(k);
      if (l === undefined) lines.set(k, { f, n: 1 }); else l.n++;
    }
    const all = [...lines.values()];
    for (const { f, n } of all.slice(0, SHOWN_PER_TOOL)) {
      const where = f.file !== undefined ? `${md(f.file, 300)}${n === 1 && f.line !== undefined ? `:${f.line}` : ''}`
        : f.displayPath !== undefined ? md(f.displayPath, 300) : f.uriUnmapped ? '(a path that could not be mapped)' : '(no repository file)';
      const age = f.isNew === true ? 'new' : f.isNew === false ? 'old' : 'no base';
      out.push(`- ${f.severity} · ${age} · ${md(f.ruleId)} · ${where} · ${md(f.message)} · ${md(f.reason, 300)}${n > 1 ? ` (×${n})` : ''}`);
    }
    if (all.length > SHOWN_PER_TOOL) out.push(`- +${all.length - SHOWN_PER_TOOL} more`);
  }
  return out;
}

function renderSummary(r: Omit<GateResult, 'summary'>, installing: boolean): string {
  const out: string[] = [];
  const section = (title: string, lines: string[]): void => { if (lines.length > 0) out.push('', `### ${title}`, ...lines); };
  out.push(`## pipegen gate: ${r.pass ? 'passed' : 'blocked'} (${r.mode} mode)`);
  const countedText = SEVERITIES.filter((s) => r.counted[s] > 0).map((s) => `${r.counted[s]} ${s}`).join(', ');
  out.push('', [
    `${r.blocking.length} blocking findings`, `${r.blockReasons.length} other reasons to block`, `${r.warnings.length} warnings`, `${r.warnReasons.length} other warnings`, `${r.toolErrors.length} tool errors`,
    `${r.failedJobs.length} failed checks`, `${r.notRun.length} not run`, ...(countedText === '' ? [] : [`only counted: ${countedText}`]),
  ].join(' · '));
  section('Blocking', [...r.blockReasons.map((b) => `- ${md(b, 400)}`), ...findingLines(r.blocking)]);
  section('Warnings', [...r.warnReasons.map((w) => `- ${md(w, 400)}`), ...findingLines(r.warnings)]);
  section('Tool errors', r.toolErrors.map((t) => `- ${md(t.tool ?? t.needId)} (${md(t.job)})${t.base ? ' on the base commit' : ''}: ${md(t.reason, 300)} · ${t.blocks ? 'blocks' : 'does not block'}`));
  section('Failed checks', r.failedJobs.map((f) => `- ${md(f.job)}: ${md(f.reason)}`));
  section('Not run (fork PR)', r.notRun.map((f) => `- ${md(f.job)}: ${NOT_RUN_FORK}`));
  section('No coverage (completeness not provable)', r.noCoverage.map((f) => `- ${md(f.job)}: nothing reported, so completeness is not provable; never counted as covered`));
  section('Not scanned', r.notScanned.map((f) => `- ${f.file !== undefined ? md(f.file, 300) : f.displayPath !== undefined ? md(f.displayPath, 300) : '(a path that could not be mapped)'}${f.line !== undefined ? ` lines ${f.line}-${f.endLine ?? f.line}` : ''} · ${f.isNew === false ? 'old' : 'new'}`));
  section('Skipped', r.skipped.map((s) => `- ${md(s.job ?? s.needId)}: skipped, ${md(s.reason)}; not checked, never counted as clean`));
  section('Not proven', r.notProven.map((n) => `- ${md(n.job)}: ${md(n.reason, 300)}`));
  if (r.integrity.findings.length > 0) {
    section('Integrity', [
      installing ? 'installing pipegen: review these files' : 'pipeline files changed or suppressions added without code-owner approval on the current commit',
      ...r.integrity.findings.slice(0, 50).map((f) => `- ${md(f.ruleId)} · ${f.file === undefined ? '(no file)' : md(f.file, 300)} · ${md(f.message)}`),
      ...(r.integrity.findings.length > 50 ? [`- +${r.integrity.findings.length - 50} more`] : []),
    ]);
  }
  section('Checks', r.checks.map((c) => `- ${md(c.job)}: ${md(c.state)} (judged by ${c.judgedBy})`));
  section('Notes', r.notes.slice(0, 100).map((n) => `- ${md(n, 400)}`));
  return `${out.join('\n')}\n`;
}
