// Plan C Task C5a: the gate's settings and job mapping. Pure: no file, no network, no environment; every value comes in as text.
//
// resolveSettings parses every input of the gate step in mode `gate` (the RENDERER_INPUTS row of src/engine/tool-flags.ts, ruling B3)
// with the same schema functions the renderer and the referee use, so a literal they accept is never read differently here. Any parse
// error is a settings error, and each settings error blocks (decide.ts rule 1). An input of another mode, or a name that is no input at
// all (the stage and scrub test options, `report-only`, a tool list), is a settings error too: an empty value is an unset input.
//
// Trust (Plan C Global Constraints, rulings S1, S4, S22): the job list is the `job-list` literal, which the referee checked equals
// gateJobList(draft); it is never read from the repository. `private` comes from the event payload. The secrets, dependency and image
// tool lists and the protected paths come from the built-in reviewed list (the gate view); inputs can only ADD protected paths. On a public
// repository the `policy` input is ignored. Floor needs can't be not-proven, and every floor need the job list names is required.
//
// mapJobs reads `toJSON(needs)` (hostile shape, read by own properties) only through the trusted job list: per entry its `result` and its
// artifact's `-sha256`, `-status` and `-error` outputs; the base-scan job's `base-sha` and base artifact outputs. needId, tool, blocking
// and needsSecrets always come from the job list. A listed job that is absent is `missing` (decide.ts blocks a required one); a job that is
// not listed is ignored, with a note.
import { resultArtifactName, SECRETS_RANGE_ARTIFACT } from '../../src/engine/artifact-names.js';
import { jobIdFor, type JobListEntry } from '../../src/engine/gate-job-list.js';
import { NEED_ID_CATEGORY } from '../../src/engine/need-ids.js';
import { effectiveProtectedPaths } from '../../src/engine/protected-paths.js';
import type { LicenceLockfiles } from '../../src/engine/licence-lockfiles.js';
import { idListProblem, JOB_LIST_KEYS, jobListLiteralProblem, licenceLockfilesProblem, pathListProblem, RANGE_TOOL, serviceRootsProblem } from '../../src/engine/tool-flags.js';
import { FLOOR_NEEDS, PROTECTED_SECTIONS_BASE, type ReviewedTool } from '../../src/types.js';
import { safeText } from '../../src/util/safe-text.js';
import { validDate } from './date.js';
import type { CheckInput, JobOutputs, JobResult } from './decide.js';
import { DEFAULT_POLICY, policyProblem, type Policy } from './policy-default.js';

// ---------- the built-in reviewed list, as the gate sees it ----------

/**
 * What the gate needs of a reviewed entry (ruling S5's gate view; C6 generates it at build time into gate/src/generated, without pins):
 * its categories (for the tool lists), the config files and sections it reads (protected paths), and the name of the result file it writes
 * (the one entry of its result artifact).
 */
export interface GateToolView {
  id: string; categories: readonly string[]; configFiles: readonly string[]; rootConfigFiles?: readonly string[]; configSections?: readonly string[];
  outputFile?: string;
}
const RESULT_FILE_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
/** The gate view of reviewed entries (the shape C6 bundles). */
export function gateToolView(list: readonly ReviewedTool[]): GateToolView[] {
  return list.map((t) => {
    const out = t.step.output?.path;
    return {
      id: t.id, categories: [...t.categories], configFiles: [...t.configFiles],
      ...(t.rootConfigFiles === undefined ? {} : { rootConfigFiles: [...t.rootConfigFiles] }),
      ...(t.configSections === undefined ? {} : { configSections: [...t.configSections] }),
      ...(typeof out === 'string' && RESULT_FILE_RE.test(out) ? { outputFile: out } : {}),
    };
  });
}
/** Secrets tools by category. */
const SECRETS_CATEGORIES = new Set(['secrets']);
/** Dependency and image tools (Plan C Global Constraints): compared with the same-run base scan only. Licences are dependency facts too. */
const SAME_RUN_CATEGORIES = new Set(['deps', 'image-scan', 'dependency-review', 'licences']);

// ---------- the inputs ----------

/** The inputs of the gate step in mode `gate` (the RENDERER_INPUTS row, ruling B3, plus `service-roots` of C5a and `licence-lockfiles` of the final review's fix round A). */
export const GATE_INPUTS = [
  'mode', 'jobs', 'job-list', 'not-proven', 'skipped', 'policy', 'protected-paths', 'service-roots', 'licence-lockfiles', 'block-from', 'block-from-recorded', 'github-token', 'fp-key',
] as const;
export type GateInputName = (typeof GATE_INPUTS)[number];
/** toJSON(needs) of a gate job is small (outputs are short texts); a bigger one is not GitHub's. */
export const MAX_JOBS_TEXT = 4 * 1024 * 1024;
const SKIP_REASON = 'skipped at setup (--skip)';
/** The cap the other JSON literals have (tool-flags.ts parseJson). */
const MAX_POLICY_TEXT = 200_000;

export interface SettingsContext {
  /** `github.event.repository.private` (the payload; a PR can't change it). */
  private: boolean;
  /** The built-in reviewed list's gate view. */
  reviewed: readonly GateToolView[];
}
export interface GateSettings {
  /** The trusted job list (the `job-list` literal), in its order. Empty when the literal is refused. */
  jobList: JobListEntry[];
  /**
   * Floor need ids the gate must find a check for: `secrets` always (every pipeline has it, repo-wide, on the merge layer), and every floor
   * need of the job list (C2 r4: the merge-layer filter of gateJobList, which IS the job list). Apart from `secrets`, a floor need taken from
   * the list has its check by construction, so this does not catch a floor need dropped from the list: the referee's check that the
   * `job-list` literal equals gateJobList(draft), and integrity on the file that holds the literal (a protected path), do.
   */
  floorNeeds: string[];
  policy: Policy;
  notProven: string[];
  skipped: { needId: string; reason: string }[];
  /** effectiveProtectedPaths(the whole built-in list, serviceRoots) + the extra `protected-paths`. */
  protectedPaths: string[];
  /** PROTECTED_SECTIONS_BASE + every configSections of the built-in list. */
  protectedSections: string[];
  serviceRoots: string[];
  /** The `licence-lockfiles` literal (fix round A, ruling 2): per service, each lockfile kind and whether the licence scan reads it. Undefined when unset or refused. */
  licenceLockfiles?: LicenceLockfiles[];
  secretsTools: string[];
  sameRunTools: string[];
  /** PIPEGEN_BLOCK_FROM when it is a real date; undefined when unset or not a date (noted). */
  blockFrom?: string;
  /** The `block-from-recorded` literal. */
  blockFromRecorded?: string;
  /** `toJSON(needs)`, parsed (hostile shape: mapJobs reads it). */
  needs: unknown;
  /** The workflow token (masked by the adapter before its first use). Never in an error or a note. */
  token: string;
  /** PIPEGEN_FP_KEY; undefined when empty (a fork PR has none). Never in an error or a note. */
  fpKey?: string;
  /** Each one blocks (decide.ts rule 1). Fixed texts and input names only, never an input's value. */
  errors: string[];
  notes: string[];
}

const FLOOR: ReadonlySet<string> = new Set(FLOOR_NEEDS);
const categoryOf = (needId: string): string | undefined =>
  Object.hasOwn(NEED_ID_CATEGORY, needId) ? (NEED_ID_CATEGORY as Readonly<Record<string, string>>)[needId] : undefined;
/** A floor need by its id or its category (a `migration-check` is a `full-tests`), as decide.ts reads it. */
export const isFloorNeed = (needId: string): boolean => FLOOR.has(needId) || FLOOR.has(categoryOf(needId) ?? '');
const isFindingsFormat = (f: string): boolean => f === 'sarif' || f === 'zap-json';
const parse = (text: string): unknown => { try { return JSON.parse(text) as unknown; } catch { return undefined; } };
const shownName = (k: string): string => JSON.stringify(safeText(k.replace(/[^A-Za-z0-9._-]/g, '?'), 40));

/** Why one parsed job-list entry does not hold together (beyond the referee's literal schema), or null. */
export function entryProblem(e: JobListEntry, i: number): string | null {
  const at = `entry ${i + 1}`;
  let job: string;
  try { job = jobIdFor(e.needId, e.service); } catch { return `${at} has a service that names no job`; }
  if (e.job !== job) return `${at} has the job ${shownName(e.job)}, but its need and service give ${shownName(job)}`;
  // C9: the secrets job's commit-range scan: its own artifact, no base twin (the schema, jobListLiteralProblem, holds the rest of its form)
  if (e.range === true) return e.needId === 'secrets' && e.service === undefined && e.artifact === SECRETS_RANGE_ARTIFACT && e.baseArtifact === undefined && e.tool === RANGE_TOOL && e.format === 'sarif'
    ? null : `${at} is a commit-range entry that is not the one of the secrets job`;
  if (isFindingsFormat(e.format)) {
    if (e.artifact === undefined || e.baseArtifact === undefined || e.tool === undefined) return `${at} is a findings check without its tool, artifact or base artifact`;
    let head: string; let base: string;
    try { head = resultArtifactName(e.needId, e.service); base = resultArtifactName(e.needId, e.service, { base: true }); } catch { return `${at} has a need id that names no artifact`; }
    if (e.artifact !== head || e.baseArtifact !== base) return `${at} has artifact names that are not the ones of its need and service`;
  } else if (e.artifact !== undefined || e.baseArtifact !== undefined) return `${at} is judged by job status but names an artifact`;
  return null;
}

/** The job list literal, parsed: the referee's schema (jobListLiteralProblem), then each entry rebuilt from its known keys only. */
function readJobList(text: string | undefined, errors: string[]): JobListEntry[] {
  if (text === undefined || text === '') { errors.push('the job-list input is missing: the gate has no trusted list of checks'); return []; }
  const p = jobListLiteralProblem(text);
  if (p !== null) { errors.push(`the job-list input is refused (${p})`); return []; }
  const raw = JSON.parse(text) as Record<string, unknown>[];
  const list = raw.map((r) => {
    const e: Record<string, unknown> = {};
    for (const k of JOB_LIST_KEYS) if (Object.hasOwn(r, k)) e[k] = k === 'warnFirst' ? { since: (r[k] as { since: string }).since } : r[k];
    return e as unknown as JobListEntry;
  });
  for (const [i, e] of list.entries()) {
    const problem = entryProblem(e, i);
    if (problem !== null) { errors.push(`the job-list input is refused (${problem})`); return []; }
  }
  return list;
}

/**
 * The gate's settings from the inputs of its step (`raw`, by input name; an empty value is unset, as @actions/core gives it). Never
 * throws; every problem is in `errors` (each blocks), with the input's name and never its value.
 */
export function resolveSettings(raw: Readonly<Record<string, string | undefined>>, ctx: SettingsContext): GateSettings {
  const errors: string[] = [];
  const notes: string[] = [];
  const get = (k: GateInputName): string | undefined => { const v = Object.hasOwn(raw, k) ? raw[k] : undefined; return typeof v === 'string' && v !== '' ? v : undefined; };
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined || v === '' || (GATE_INPUTS as readonly string[]).includes(k)) continue;
    // the name is shown only when it reads as an input name (the step's own names never hold a credential; a name that could, is not shown)
    errors.push(`the gate in mode gate does not take the input ${/^[A-Za-z][A-Za-z0-9-]{0,39}$/.test(k) && !/[0-9].*[0-9].*[0-9]/.test(k) ? JSON.stringify(k) : '(a name that is not shown)'}`);
  }
  if (get('mode') !== 'gate') errors.push('the mode input is not gate');

  // the trusted job list and the floor needs
  const jobList = readJobList(get('job-list'), errors);
  const floorNeeds = [...new Set(['secrets', ...jobList.filter((e) => isFloorNeed(e.needId) || FLOOR.has(e.category)).map((e) => e.needId)])];

  // not-proven and skipped
  const idList = (name: 'not-proven' | 'skipped'): string[] => {
    const v = get(name);
    if (v === undefined) return [];
    const p = idListProblem(v);
    if (p !== null) { errors.push(`the ${name} input is refused (it must be ${p})`); return []; }
    return [...new Set(JSON.parse(v) as string[])];
  };
  const notProven = idList('not-proven').filter((n) => {
    if (!isFloorNeed(n)) return true;
    errors.push(`not-proven can't include floor need ${n}`);
    return false;   // it stays required
  });
  const skipped = idList('skipped').map((needId) => ({ needId, reason: SKIP_REASON }));

  // policy: private repos take the central workflow's literal; public repos always the built-in default
  let policy: Policy = DEFAULT_POLICY;
  const pv = get('policy');
  if (!ctx.private) {
    if (pv !== undefined) notes.push('the policy input is ignored on a public repository: the built-in default policy is used');
  } else if (pv !== undefined && pv.length > MAX_POLICY_TEXT) {
    errors.push('the policy input is refused (it is over the size cap), so the default policy is used');
  } else if (pv !== undefined) {
    const doc = parse(pv);
    const p = policyProblem(doc);
    if (p === null) policy = doc as Policy;
    else errors.push(`the policy input is refused (it must be ${p}), so the default policy is used`);
  }

  // protected paths: the built-in list with the service roots, then the extra paths (inputs only add)
  let serviceRoots: string[] = [];
  const sr = get('service-roots');
  if (sr !== undefined) {
    const p = serviceRootsProblem(sr);
    if (p === null) serviceRoots = JSON.parse(sr) as string[];
    else errors.push(`the service-roots input is refused (it must be ${p})`);
  } else if (jobList.some((e) => e.service !== undefined)) {
    errors.push('the service-roots input is missing while the job list has per-service checks: the config files each service folder holds could not be protected');
  }
  // the licence check's lockfiles (fix round A, ruling 2): read for its coverage texts only, never to make a check pass
  let licenceLockfiles: LicenceLockfiles[] | undefined;
  const ll = get('licence-lockfiles');
  if (ll !== undefined) {
    const p = licenceLockfilesProblem(ll);
    if (p === null) licenceLockfiles = (JSON.parse(ll) as LicenceLockfiles[]).map((e) => ({ service: e.service, lockfiles: e.lockfiles.map((l) => ({ kind: l.kind, read: l.read })) }));
    else errors.push(`the licence-lockfiles input is refused (it must be ${p})`);
  }
  let extra: string[] = [];
  const pp = get('protected-paths');
  if (pp !== undefined) {
    const p = pathListProblem(pp);
    if (p === null) extra = JSON.parse(pp) as string[];
    else errors.push(`the protected-paths input is refused (it must be ${p})`);
  }
  const protectedPaths = [...new Set([...effectiveProtectedPaths(ctx.reviewed.map((t) => ({ configFiles: [...t.configFiles], ...(t.rootConfigFiles === undefined ? {} : { rootConfigFiles: [...t.rootConfigFiles] }) })), serviceRoots), ...extra])];
  const protectedSections = [...new Set([...PROTECTED_SECTIONS_BASE, ...ctx.reviewed.flatMap((t) => t.configSections ?? [])])];

  // the tool lists: the built-in list only
  const secretsTools = ctx.reviewed.filter((t) => t.categories.some((c) => SECRETS_CATEGORIES.has(c))).map((t) => t.id);
  const sameRunTools = ctx.reviewed.filter((t) => t.categories.some((c) => SAME_RUN_CATEGORIES.has(c))).map((t) => t.id);

  // dates: the variable can be moved by any writer (a bad one is unset, as mode.ts reads it); the recorded literal is pipegen's
  const bf = get('block-from');
  const blockFrom = validDate(bf);
  if (bf !== undefined && blockFrom === undefined) notes.push('PIPEGEN_BLOCK_FROM is not a date YYYY-MM-DD, so it is ignored');
  const rec = get('block-from-recorded');
  const blockFromRecorded = validDate(rec);
  if (rec !== undefined && blockFromRecorded === undefined) errors.push('the block-from-recorded input is refused (it must be a real calendar date YYYY-MM-DD)');

  // toJSON(needs)
  let needs: unknown = {};
  const jobs = get('jobs');
  if (jobs === undefined) errors.push('the jobs input (toJSON(needs)) is missing');
  else if (jobs.length > MAX_JOBS_TEXT) errors.push('the jobs input (toJSON(needs)) is over the size cap');
  else {
    const doc = parse(jobs);
    if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) errors.push('the jobs input (toJSON(needs)) is not a JSON object');
    else needs = doc;
  }

  // credentials: never echoed
  const token = get('github-token') ?? '';
  if (token === '') errors.push('the github-token input is missing');
  const fpKey = get('fp-key');

  return {
    jobList, floorNeeds, policy, notProven, skipped, protectedPaths, protectedSections, serviceRoots, ...(licenceLockfiles === undefined ? {} : { licenceLockfiles }), secretsTools, sameRunTools,
    ...(blockFrom === undefined ? {} : { blockFrom }), ...(blockFromRecorded === undefined ? {} : { blockFromRecorded }),
    needs, token, ...(fpKey === undefined ? {} : { fpKey }), errors, notes,
  };
}

// ---------- toJSON(needs) ----------

export const BASE_SCAN_JOB = 'base-scan';
export const BASE_SHA_OUTPUT = 'base-sha';
const RESULTS: ReadonlySet<string> = new Set(['success', 'failure', 'cancelled', 'skipped']);
const SHA_RE = /^[0-9a-f]{40}$/;
const MAX_OUTPUT_CHARS = 2000;
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);

/** One checked job: the CheckInput without its downloaded files, plus the base-scan job's outputs for its base artifact. */
export interface MappedCheck extends Omit<CheckInput, 'file' | 'base'> { baseOutputs?: JobOutputs }
export interface MappedJobs {
  checks: MappedCheck[];
  /** The base-scan job's result and the commit it checked out (its base-sha output, 40 hex); null when `needs` has no base-scan job. */
  baseScan: { result: JobResult; commit?: string } | null;
  notes: string[];
}

function jobOf(needs: unknown, job: string): { result: JobResult; outputs: Record<string, unknown> } | undefined {
  if (!isPlain(needs)) return undefined;
  const j = own(needs, job);
  if (j === undefined) return undefined;
  if (!isPlain(j)) return { result: 'missing', outputs: {} };
  const r = own(j, 'result');
  const o = own(j, 'outputs');
  return { result: typeof r === 'string' && RESULTS.has(r) ? (r as JobResult) : 'missing', outputs: isPlain(o) ? o : {} };
}
/** `<artifact>-sha256`, `-status` and `-error` of one artifact, text values only, cut. */
function outputsOf(outputs: Record<string, unknown>, artifact: string): JobOutputs {
  const o: JobOutputs = {};
  for (const n of ['sha256', 'status', 'error'] as const) {
    const v = own(outputs, `${artifact}-${n}`);
    if (typeof v === 'string') o[n] = v.length > MAX_OUTPUT_CHARS ? v.slice(0, MAX_OUTPUT_CHARS) : v;
  }
  return o;
}

/** `toJSON(needs)` read through the trusted job list (see the header). */
export function mapJobs(needs: unknown, list: readonly JobListEntry[]): MappedJobs {
  const notes: string[] = [];
  const base = jobOf(needs, BASE_SCAN_JOB);
  let baseScan: MappedJobs['baseScan'] = null;
  if (base !== undefined) {
    const c = own(base.outputs, BASE_SHA_OUTPUT);
    baseScan = { result: base.result, ...(typeof c === 'string' && SHA_RE.test(c) ? { commit: c } : {}) };
  }
  const checks: MappedCheck[] = list.map((entry) => {
    const j = jobOf(needs, entry.job);
    if (j === undefined) return { entry, result: 'missing', outputs: {} };
    if (j.result === 'missing') notes.push(`the job ${shownName(entry.job)} has no result GitHub gives (success, failure, cancelled or skipped): it counts as missing`);
    const findings = isFindingsFormat(entry.format) && entry.artifact !== undefined;
    const outputs = findings ? outputsOf(j.outputs, entry.artifact as string) : {};
    const baseOutputs = findings && base !== undefined && entry.baseArtifact !== undefined ? outputsOf(base.outputs, entry.baseArtifact) : undefined;
    return { entry, result: j.result, outputs, ...(baseOutputs === undefined ? {} : { baseOutputs }) };
  });
  if (isPlain(needs)) {
    const listed = new Set([...list.map((e) => e.job), BASE_SCAN_JOB]);
    const extra = Object.keys(needs).filter((k) => !listed.has(k));
    if (extra.length > 0) notes.push(`${extra.length} job${extra.length === 1 ? '' : 's'} the gate waits for ${extra.length === 1 ? 'is' : 'are'} not in the job list and ${extra.length === 1 ? 'was' : 'were'} not read: ${extra.slice(0, 10).map(shownName).join(', ')}`);
  }
  return { checks, baseScan, notes };
}
