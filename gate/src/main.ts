// Plan C Task C5b: the gate action (gate/action.yml runs dist/index.js, which C6 bundles from gate/src/index.ts: that entry calls main
// unconditionally, review-C5b Important 1; this module runs nothing on import, so tests import it). It reads `mode`
// and runs that mode's path:
//   - scrub           (C1b): the raw result of a scanner → the scrubbed copy, and the outputs sha256, status and error;
//   - stage           (C1c): the checkout → the read-only stage folder of a secrets scan with its manifest; outputs status and error;
//   - gate            (C5a + C2): every fact (gatherGateInput) → decideGate → result.json in RUNNER_TEMP/pipegen-gate, the job summary,
//                     the output `result`, and only THEN the exit status. On a trusted green push to the default branch it also writes
//                     the signed baseline (C3) and the clean-run marker there (ruling A of task-C5b-rulings.md);
//   - baseline-check  (C3, ruling A): the lookup: a verified trusted baseline exists or not → output `found` (found | missing);
//   - find-run        (C8): the proof that the exact commit passed the gate in a trusted push run on the default branch (gated-run.ts) →
//                     outputs run-id and run-url on success, a failing status with the reason otherwise;
//   - nightly         (C7): opens or updates ISSUES (warn mode ending, finish missing, a pipegen update with its patch); never writes a file or a
//                     workflow (nightly.ts). No outputs. A failed read is a log line; a failed issue write is an error exit;
// The rules for every mode:
//   - the token and the key come from the inputs only, and each is masked (`::add-mask::`, ruling 4) before anything else is written;
//   - an input that is not of the mode is refused (so a test-only option, such as the stage piece size, can never become an input);
//   - every error is caught into a fail-closed result with a short fixed text: no stack, no path, no secret. Everything this file writes
//     (the log, the outputs, the summary, the gate files) passes through one redaction of the masked values as a last belt;
//   - one log helper (log), which writes one line of safe text that can not start a workflow command.
// Uploads (ruling 2): the gate writes files; pinned upload-artifact steps that the engine renders after the gate step upload them
// (renderGateUploads): pipegen-gate-result with if: always(), pipegen-baseline and pipegen-clean-run with if-no-files-found: ignore.
// Gate mode never reads GITHUB_WORKSPACE (ruling S21): its facts come from the inputs, the event payload and the API.
import { randomUUID } from 'node:crypto';
import { accessSync, chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { GATE_UPLOAD_FILES, isStagedTool, PLAIN_REL_RE, TIMEOUT_MINUTES_RE } from '../../src/engine/tool-flags.js';
import { GATE_CHECK_NAME } from '../../src/types.js';
import { safeMarkdown, safeText } from '../../src/util/safe-text.js';
import { keyProblem } from './fingerprint.js';
import { buildCleanRunMarker, loadBaseline, saveBaseline, WORKFLOW_PATH, type ArtifactUploader, type BaselineCheck } from './baseline.js';
import { decideGate, type DecidedFinding, type GateInput, type GateResult } from './decide.js';
import { gatherGateInput, repoOf, type GateIo } from './facts.js';
import { findGatedRun, type GatedRunOpts } from './gated-run.js';
import { githubAdapter, type AdapterOptions, type GateGithubAdapter } from './github-adapter.js';
import { resolveRepo, runNightly, type NightlyAdapter } from './nightly.js';
import { scrubFile, type ScrubFileResult } from './scrub.js';
import { GATE_VIEW } from './generated/gate-view.js';
import { GATE_INPUTS, type GateToolView } from './settings.js';
import { stageWorkspace } from './stage.js';

/** The inputs of each mode (the RENDERER_INPUTS gate row split by mode; a test keeps them equal). Any other input is refused. */
export const MODE_INPUTS = {
  scrub: ['mode', 'artifact', 'tool', 'stage', 'format', 'raw', 'out', 'fp-key'],
  stage: ['mode', 'artifact', 'tool', 'stage'],
  gate: [...GATE_INPUTS],
  'baseline-check': ['mode', 'github-token', 'fp-key'],
  'find-run': ['mode', 'layout', 'sha', 'central-workflow', 'central-sha', 'timeout-minutes', 'github-token'],
  nightly: ['mode', 'block-from', 'block-from-recorded', 'github-token', 'fp-key'],
} as const;
type Mode = keyof typeof MODE_INPUTS;
const isMode = (m: string): m is Mode => Object.hasOwn(MODE_INPUTS, m);

export interface MainDeps {
  /** process.env. Read by name only (never spread), so gate mode can be shown never to read GITHUB_WORKSPACE. */
  env: Readonly<Record<string, string | undefined>>;
  /** stdout: workflow commands and the log. */
  write: (text: string) => void;
  now?: () => Date;
  /** Sleeping between polls of find-run (tests inject one that moves their clock). */
  sleep?: (ms: number) => Promise<void>;
  /** The GitHub client (tests inject a fake); the REST adapter by default. */
  github?: (opts: AdapterOptions) => GateGithubAdapter;
  /** The client of mode nightly (tests inject a fake); the REST adapter by default (it implements the reads and the two issue writes). */
  nightly?: (opts: AdapterOptions) => NightlyAdapter;
  /** The built-in reviewed list's gate view. C6 replaces the default with the generated view it bundles (ruling S5). */
  reviewed?: () => readonly GateToolView[];
  /** The file system calls that remove, move aside or lock gate files (tests inject failures; the real calls by default). */
  fs?: Partial<GateFs>;
}
/** The three file system calls the stale-file handling uses. */
export interface GateFs {
  unlink: (path: string) => void; rename: (from: string, to: string) => void; chmod: (path: string, mode: number) => void;
  /** Overwrites an existing file in place (never through a link). */
  overwrite: (path: string, data: string) => void;
  /** Throws unless the folder can be read. */
  access: (path: string) => void;
}
const REAL_FS: GateFs = {
  unlink: unlinkSync, rename: renameSync, chmod: chmodSync,
  overwrite: (path, data) => { writeFileSync(path, data, { flag: constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW } as unknown as { flag: string }); },
  access: (path) => { accessSync(path, constants.R_OK); },
};

/** The event payload and other runner files are read under this cap, without following a link. */
const MAX_EVENT_BYTES = 16 * 1024 * 1024;
const RESULT_ARTIFACT_RE = /^pipegen-out-[a-z0-9][a-z0-9-]{0,120}$/;
const TOOL_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const FILE_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,100}$/;
const GATE_DIR = 'pipegen-gate';
const RESULT_FILE = GATE_UPLOAD_FILES['pipegen-gate-result'] as string;

class StepError extends Error {}
/** A gate file that should be gone or replaced could not be (fix round 2, r1-2): the step exits with the distinct status 2. */
class StaleResultError extends StepError {}
/** The exit status when the gate folder may still hold a stale result, baseline or marker. */
export const STALE_EXIT = 2;
/** Whether the file is gone (removed now, or never there). */
function removeIfThere(fs: GateFs, dir: string, name: string): boolean {
  try { fs.unlink(join(dir, name)); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === 'ENOENT'; }
}
/** Whether any entry is still at the path, of any type (a link, a folder or a FIFO counts: upload-artifact follows links). */
function entryStillThere(dir: string, name: string): boolean {
  try { lstatSync(join(dir, name)); return true; } catch { return false; }
}
/**
 * C6 part 0 (review-C5b-r2 c1): the gate could not remove or replace a file of the gate folder, so the uploads (if: always()) would ship it.
 * The one design: move the whole folder aside (a rename needs only the parent folder, not the files). If that fails: overwrite result.json
 * with the block document (best effort), then lock the folder (mode 0) and check it really is unreadable now (root ignores the mode). Either
 * way the pinned result upload finds nothing it can read and fails (if-no-files-found: error). Only if nothing holds does the step say so.
 * ACCEPTED RESIDUAL: reaching this needs the runner's temp folder to fail writes in the middle of one process. Its trust impact is nil:
 * pipegen-gate-result is a report, never authority, and C3 trusts only a baseline or marker from a run that concluded `success`; this step
 * exits non-zero, so that run can not. No further hardening of this path (reviews of C5b-r2 and C6 part 0).
 */
function quarantine(step: Step, dir: string, blockDoc: string): void {
  const fs = step.fs;
  try { fs.rename(dir, join(dirname(dir), `${basename(dir)}.stale-${randomUUID()}`)); step.error('the gate folder holds a file that could not be removed, so the folder was moved aside: the result file may be stale, the upload finds nothing and fails'); return; } catch { /* lock it */ }
  try { fs.overwrite(join(dir, RESULT_FILE), blockDoc); } catch { /* best effort */ }
  try {
    fs.chmod(dir, 0);
    let readable = true;
    try { fs.access(dir); } catch { readable = false; }
    if (!readable) { step.error('the gate folder holds a file that could not be removed, so the folder was locked: the result file may be stale, the upload can not read it and fails'); return; }
  } catch { /* below */ }
  step.error('the gate folder holds a file that could not be removed, and the folder could not be moved aside or locked: the result file may be stale and the uploads may ship stale files');
}

/** Masked lines shorter than this are not redacted from what the action writes (they are still masked by the runner). */
const MIN_REDACTED = 8;
/** The fixed text for a key the fingerprint rules refuse (review-C5b minor 5): never the key or its length. */
const BAD_KEY = 'the fp-key input is not a usable PIPEGEN_FP_KEY (one line of at least 32 printable characters, no quote or backslash), so the step fails closed';
/** A non-empty key the fingerprint rules refuse (an empty one is unset: a fork pull request has none). */
const badKey = (key: string | undefined): boolean => key !== undefined && keyProblem(key, false, true) !== undefined;

/** A workflow command's data: `%`, CR and LF escaped as the runner expects (the text is already one line of safe text). */
const escapeData = (s: string): string => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');

/** What one run of the action writes, all through one place: masking first, the redaction belt, the outputs and the summary. */
class Step {
  private secrets: string[] = [];
  readonly fs: GateFs;
  constructor(private deps: MainDeps) { this.fs = { ...REAL_FS, ...deps.fs }; }
  env(name: string): string | undefined { const v = this.deps.env[name]; return typeof v === 'string' ? v : undefined; }
  /** `::add-mask::` for each line of a secret, before anything else is written with it. */
  mask(value: string | undefined): void {
    if (value === undefined) return;
    for (const line of value.split(/\r?\n/)) {
      if (line.trim() === '') continue;
      // a short line is masked by the runner too, but never redacted here: it would corrupt outputs such as a sha256 (review-C5b minor 5)
      if (line.length >= MIN_REDACTED) this.secrets.push(line);
      // the data escaped as core.setSecret does (review-C5b minor 4): the runner unescapes %25, %0D and %0A before it registers the value
      this.deps.write(`::add-mask::${escapeData(line)}\n`);
    }
    this.secrets.sort((a, b) => b.length - a.length);
  }
  /** Every masked value replaced, wherever it is (a last belt: nothing is meant to carry one). */
  redact(text: string): string { let t = text; for (const s of this.secrets) t = t.split(s).join('***'); return t; }
  private line(text: string): void { this.deps.write(`${this.redact(text)}\n`); }
  /** The one log helper: one line of safe text, prefixed so it never starts a workflow command. */
  log(text: string): void { this.line(`pipegen: ${safeText(text, 600)}`); }
  warn(text: string): void { this.line(`::warning::${escapeData(safeText(text, 600))}`); }
  error(text: string): void { this.line(`::error::${escapeData(safeText(text, 600))}`); }
  /** One step output, in GITHUB_OUTPUT's `name<<delimiter` form. No output file → a StepError (the step fails closed). */
  setOutput(name: string, value: string): void {
    const file = this.env('GITHUB_OUTPUT');
    if (file === undefined || !isAbsolute(file)) throw new StepError('GITHUB_OUTPUT is not set, so the step can not hand on its result');
    const v = this.redact(value);
    const delim = `ghadelimiter_${randomUUID()}`;
    if (v.includes(delim) || name.includes(delim)) throw new StepError('an output holds its own delimiter');
    appendFile(file, `${name}<<${delim}\n${v}\n${delim}\n`);
  }
  /** Appends Markdown to the job summary (an exclusive append to GITHUB_STEP_SUMMARY, never through a shell). */
  summary(markdown: string): void {
    const file = this.env('GITHUB_STEP_SUMMARY');
    if (file === undefined || !isAbsolute(file)) { this.log('GITHUB_STEP_SUMMARY is not set, so there is no job summary'); return; }
    appendFile(file, this.redact(markdown));
  }
  /** A file in the gate folder, created new (never over a file, never through a link). */
  writeGateFile(dir: string, name: string, bytes: Uint8Array | string): void {
    const data = typeof bytes === 'string' ? Buffer.from(this.redact(bytes)) : Buffer.from(bytes);
    let fd: number | undefined;
    try {
      fd = openSync(join(dir, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
      let at = 0;
      while (at < data.length) at += writeSync(fd, data, at, data.length - at);
    } catch {
      throw new StepError(`the gate file ${name} could not be written`);
    } finally {
      if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
    }
  }
}

function appendFile(path: string, text: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
    const data = Buffer.from(text);
    let at = 0;
    while (at < data.length) at += writeSync(fd, data, at, data.length - at);
  } catch {
    throw new StepError('a runner file (the outputs or the summary) could not be written');
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

/** A runner file (the event payload): a regular file, no link, at most the cap. */
function readRunnerFile(path: string | undefined, what: string): string {
  if (path === undefined || !isAbsolute(path)) throw new StepError(`${what} is not set`);
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_EVENT_BYTES) throw new StepError(`${what} is not a regular file within the size cap`);
    const buf = Buffer.alloc(st.size);
    let got = 0;
    while (got < buf.length) { const n = readSync(fd, buf, got, buf.length - got, got); if (n === 0) break; got += n; }
    return buf.subarray(0, got).toString('utf8');
  } catch (e) {
    throw e instanceof StepError ? e : new StepError(`${what} could not be read`);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* nothing left to do */ }
  }
}

/**
 * The step's inputs: every INPUT_* variable by its lower-case name, trimmed; an empty value is unset (the runner sets every declared input,
 * "" when the step does not give it). `twice`: a name two variables give (INPUT_MODE and INPUT_mode), which fails the step (review P15).
 */
function readInputs(env: Readonly<Record<string, string | undefined>>): { inputs: Map<string, string>; twice?: string } {
  const out = new Map<string, string>();
  const seen = new Set<string>();
  let twice: string | undefined;
  for (const key of Object.keys(env)) {
    if (!key.startsWith('INPUT_')) continue;
    const name = key.slice('INPUT_'.length).toLowerCase();
    if (seen.has(name)) twice ??= name;
    seen.add(name);
    const v = env[key];
    if (typeof v !== 'string' || v.trim() === '') continue;
    out.set(name, v.trim());
  }
  return twice === undefined ? { inputs: out } : { inputs: out, twice };
}

/** RUNNER_TEMP, an absolute path. */
function runnerTemp(step: Step): string {
  const t = step.env('RUNNER_TEMP');
  if (t === undefined || !isAbsolute(t)) throw new StepError('RUNNER_TEMP is not set');
  return t;
}

// ---------- the entry ----------

/** Runs the action once; the exit code (0 or 1). Never throws. */
export async function main(deps: MainDeps): Promise<number> {
  const step = new Step(deps);
  try {
    const { inputs, twice } = readInputs(deps.env);
    // the secrets first, whatever the mode: nothing is written before their masks
    step.mask(inputs.get('github-token'));
    step.mask(inputs.get('fp-key'));
    if (twice !== undefined) { step.error(`the input ${safeText(twice, 40)} is given more than once, so the step fails closed`); return 1; }
    const mode = inputs.get('mode');
    if (mode === undefined) { step.error('the mode input is missing, so the gate action does nothing (it fails closed)'); return 1; }
    if (!isMode(mode)) { step.error('the mode input is not one the gate action knows, so it does nothing (it fails closed)'); return 1; }
    const allowed: readonly string[] = MODE_INPUTS[mode];
    const extra = [...inputs.keys()].filter((k) => !allowed.includes(k));
    if (extra.length > 0) { step.error(`the input ${safeText(extra[0] as string, 40)} is not used in mode ${mode}, so the step fails closed`); return 1; }
    const get = (name: string): string | undefined => inputs.get(name);
    switch (mode) {
      case 'scrub': return runScrub(step, get);
      case 'stage': return runStage(step, get);
      case 'gate': return await runGate(step, deps, inputs);
      case 'baseline-check': return await runBaselineCheck(step, deps, get);
      case 'find-run': return await runFindRun(step, deps, get);
      case 'nightly': return await runNightlyMode(step, deps, get);
    }
  } catch (e) {
    step.error(e instanceof StepError ? `the gate action failed closed: ${e.message}` : 'the gate action failed unexpectedly, so it fails closed');
    return e instanceof StaleResultError ? STALE_EXIT : 1;
  }
}

// ---------- scrub ----------

function runScrub(step: Step, get: (n: string) => string | undefined): number {
  const r = scrubResult(step, get);
  step.setOutput('sha256', r.sha256 ?? '');
  step.setOutput('status', r.status);
  step.setOutput('error', r.error ?? '');
  if (r.status !== 'ok') { step.error(`the scrub reports a tool error: ${r.error ?? 'unknown'}`); return 1; }
  step.log(`scrubbed ${r.findings ?? 0} findings`);
  for (const n of (r.notes ?? []).slice(0, 20)) step.log(n);
  return 0;
}

function scrubResult(step: Step, get: (n: string) => string | undefined): ScrubFileResult {
  const bad = (error: string): ScrubFileResult => ({ status: 'tool-error', error });
  let temp: string;
  try { temp = runnerTemp(step); } catch { return bad('RUNNER_TEMP is not set'); }
  const artifact = get('artifact');
  const tool = get('tool');
  const format = get('format');
  const raw = get('raw');
  const out = get('out');
  const stage = get('stage');
  if (artifact === undefined || !RESULT_ARTIFACT_RE.test(artifact)) return bad('the artifact input is not a result artifact name');
  if (tool === undefined || !TOOL_RE.test(tool)) return bad('the tool input is not a reviewed tool id');
  if (format !== 'sarif' && format !== 'zap-json') return bad('the format input is not sarif or zap-json');
  const file = raw === undefined ? '' : basename(raw);
  if (raw === undefined || !FILE_RE.test(file) || raw !== `${temp}/pipegen-raw/${artifact}/${file}`) return bad('the raw input is not RUNNER_TEMP/pipegen-raw/<artifact>/<file>');
  if (out !== `${temp}/pipegen-out/${artifact}/${file}`) return bad('the out input is not RUNNER_TEMP/pipegen-out/<artifact>/<file> for the same file as raw');
  // C1c review: the stage folder only as the stage step of this artifact wrote it, never another place
  if (stage !== undefined && stage !== `${temp}/pipegen-stage/${artifact}`) return bad('the stage input is not RUNNER_TEMP/pipegen-stage/<artifact>');
  const workspace = step.env('GITHUB_WORKSPACE');
  if (workspace === undefined || !isAbsolute(workspace)) return bad('GITHUB_WORKSPACE is not set');
  const key = get('fp-key');
  if (badKey(key)) return bad(BAD_KEY);
  const eventPath = step.env('GITHUB_EVENT_PATH');
  // the parser gets the workspace exactly as the scanners saw it (C1a review: trivy findings are unmapped otherwise)
  return scrubFile({
    artifact, tool, format, raw, out, workspace, mask: () => undefined,
    ...(key === undefined ? {} : { fpKey: key }), ...(eventPath === undefined ? {} : { eventPath }), ...(stage === undefined ? {} : { stage }),
  });
}

// ---------- stage ----------

function runStage(step: Step, get: (n: string) => string | undefined): number {
  const done = (status: 'ok' | 'error', error: string): number => {
    step.setOutput('status', status);
    step.setOutput('error', error);
    if (status === 'error') { step.error(`the stage step failed: ${error}`); return 1; }
    return 0;
  };
  let temp: string;
  try { temp = runnerTemp(step); } catch { return done('error', 'RUNNER_TEMP is not set'); }
  const artifact = get('artifact');
  const tool = get('tool');
  const stage = get('stage');
  if (artifact === undefined || !RESULT_ARTIFACT_RE.test(artifact)) return done('error', 'the artifact input is not a result artifact name');
  if (tool === undefined || !isStagedTool(tool)) return done('error', 'the tool input is not a tool that scans a stage folder');
  if (stage !== `${temp}/pipegen-stage/${artifact}`) return done('error', 'the stage input is not RUNNER_TEMP/pipegen-stage/<artifact>');
  const workspace = step.env('GITHUB_WORKSPACE');
  if (workspace === undefined || !isAbsolute(workspace)) return done('error', 'GITHUB_WORKSPACE is not set');
  // never the test-only options (piece size, overlap, caps): they are not inputs (C1c review m5)
  const r = stageWorkspace({ workspace, stage });
  if (r.status === 'ok') step.log(`staged ${r.files} files as ${r.staged} names`);
  return done(r.status, r.status === 'ok' ? '' : r.error);
}

// ---------- gate ----------

type Verdict = 'pass' | 'warn' | 'block';
interface Decided { input?: GateInput; result?: GateResult; errors?: string[] }

/** The gate folder in RUNNER_TEMP: made here (or an existing real folder), never a link. */
function gateFolder(step: Step): string {
  const dir = join(runnerTemp(step), GATE_DIR);
  let st;
  try { st = lstatSync(dir); } catch { st = undefined; }
  if (st === undefined) {
    try { mkdirSync(dir, { mode: 0o755 }); } catch { throw new StepError('the gate folder could not be made'); }
    st = lstatSync(dir);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new StepError('the gate folder is a link or not a folder, so nothing is written there');
  return dir;
}

async function decide(step: Step, deps: MainDeps, inputs: Map<string, string>): Promise<Decided> {
  try {
    const notes: string[] = [];
    const gh = (deps.github ?? githubAdapter)({ token: inputs.get('github-token') ?? '', mask: () => undefined, notes });
    const io: GateIo = {
      readEvent: () => readRunnerFile(step.env('GITHUB_EVENT_PATH'), 'the event payload (GITHUB_EVENT_PATH)'),
      listRunArtifacts: (o, n, runId, name) => gh.listRunArtifacts(o, n, runId, name),
      artifactZip: (o, n, id, max) => gh.downloadArtifactZip(o, n, id, max),
    };
    const reviewed = (deps.reviewed ?? defaultReviewed)();
    const g = await gatherGateInput({
      inputs: Object.fromEntries(inputs),
      env: { eventName: step.env('GITHUB_EVENT_NAME') ?? '', sha: step.env('GITHUB_SHA') ?? '', runId: step.env('GITHUB_RUN_ID') ?? '', repository: step.env('GITHUB_REPOSITORY') ?? '' },
      now: (deps.now ?? (() => new Date()))(), reviewed, clientNotes: notes,
    }, gh, io);
    if ('kind' in g) return { errors: g.errors };
    return { input: g, result: decideGate(g) };
  } catch {
    return { errors: ['the gate could not finish reading what it needs, so it fails closed'] };
  }
}

const verdictOf = (d: Decided): Verdict => {
  const r = d.result;
  if (r === undefined || !r.pass) return 'block';
  return r.warnings.length > 0 || r.warnReasons.length > 0 ? 'warn' : 'pass';
};

/** A trusted green push to the default branch: the only run that writes a baseline or a clean-run marker (ruling A, C3 m5 i). */
export function greenPushToDefault(g: GateInput, r: GateResult): boolean {
  if (g.event.name !== 'push' || !r.pass) return false;
  const p = g.event.payload as Record<string, unknown>;
  const repo = typeof p.repository === 'object' && p.repository !== null ? p.repository as Record<string, unknown> : {};
  const def = Object.hasOwn(repo, 'default_branch') ? repo.default_branch : undefined;
  if (typeof def !== 'string' || !Object.hasOwn(p, 'ref') || p.ref !== `refs/heads/${def}`) return false;
  const skipped = new Set(g.skipped.map((s) => s.needId));
  const allRan = g.checks.every((c) => c.result === 'success' || (c.result === 'skipped' && skipped.has(c.entry.needId)));
  return allRan && (g.baseScan === null || g.baseScan.result === 'success') && r.toolErrors.length === 0 && g.settingsErrors.length === 0;
}

/** A clean run (C3): no blocking finding, no warning, no other warning and no tool error. */
export function isCleanRun(r: GateResult): boolean {
  return r.blocking.length === 0 && r.warnings.length === 0 && r.warnReasons.length === 0 && r.toolErrors.length === 0;
}

/** The scrubbed results of a run as C3's baseline reads them: only a result whose file is the job's own (hash) and readable counts as ok. */
function baselineChecks(g: GateInput, r: GateResult): BaselineCheck[] {
  const noCoverage = new Set(r.noCoverage.map((n) => n.job));
  return g.checks.flatMap((c): BaselineCheck[] => {
    const e = c.entry;
    if (e.tool === undefined || e.artifact === undefined || (e.format !== 'sarif' && e.format !== 'zap-json')) return [];
    const f = c.file;
    const ok = c.outputs.status === 'ok' && f !== undefined && f.problem === undefined && f.read.toolError === undefined && f.sha256 === c.outputs.sha256;
    return [{ job: e.job, tool: e.tool, status: ok ? 'ok' : 'tool-error', noCoverage: noCoverage.has(e.job), ...(ok && f.read.keyId !== undefined ? { keyId: f.read.keyId } : {}), findings: ok ? f.read.findings : [] }];
  });
}

/** Writes the baseline and the marker files when eligible. A failure is a warning, never a gate failure (C3 contract). */
async function saveTrusted(step: Step, dir: string, g: GateInput, r: GateResult, key: string | undefined, runId: number): Promise<{ baseline: string; marker: string; lines: string[] }> {
  const lines: string[] = [];
  if (!greenPushToDefault(g, r)) return { baseline: 'not eligible', marker: 'not eligible', lines };
  if (key === undefined) {
    step.warn('the baseline and the clean-run marker were not written: PIPEGEN_FP_KEY is missing on this push to the default branch');
    return { baseline: 'not written', marker: 'not written', lines: ['- the baseline and the clean-run marker were not written: PIPEGEN_FP_KEY is missing'] };
  }
  const uploader: ArtifactUploader = { upload: async (name, bytes) => step.writeGateFile(dir, GATE_UPLOAD_FILES[name] as string, bytes) };
  let baseline = 'written';
  try {
    await saveBaseline({ runId, key, checks: baselineChecks(g, r), sameRunTools: g.sameRunTools }, uploader);
    lines.push('- the signed baseline of this run was written (uploaded as pipegen-baseline)');
  } catch {
    baseline = 'failed';
    step.warn('the baseline of this run could not be written; the next green push writes one (this is not a gate failure)');
    lines.push('- the baseline of this run could not be written (not a gate failure)');
  }
  // the re-write rule (C3 contract): a clean run writes the marker; once a marker is seen (block mode reached through a clean run), every
  // trusted green push re-writes it, so the newest-10 window always holds one
  const clean = isCleanRun(r);
  let marker = 'not written';
  if (clean || g.cleanRun === 'seen') {
    try {
      await uploader.upload('pipegen-clean-run', buildCleanRunMarker(runId, key), { retentionDays: 90 });
      marker = 'written';
      lines.push(clean ? '- this run is clean: the clean-run marker was written (uploaded as pipegen-clean-run)' : '- block mode was reached through a clean run: the clean-run marker was written again');
    } catch {
      marker = 'failed';
      step.warn('the clean-run marker could not be written (this is not a gate failure)');
      lines.push('- the clean-run marker could not be written (not a gate failure)');
    }
  }
  return { baseline, marker, lines };
}

const ref = (f: DecidedFinding): Record<string, unknown> => ({
  needId: f.needId, job: f.job, tool: safeText(f.tool, 64), ruleId: safeText(f.ruleId, 200), severity: f.severity,
  ...(f.file === undefined ? {} : { file: safeText(f.file, 300) }), ...(f.line === undefined ? {} : { line: f.line }), isNew: f.isNew ?? null, secret: f.secret,
});
/** result.json: the decision and the summary data, built from structure. No SARIF message text, and every repo string as safe text. */
function resultDoc(d: Decided, verdict: Verdict, ev: { name: string; sha: string; runId: number }, saved: { baseline: string; marker: string }): string {
  const r = d.result;
  const text = (xs: readonly string[], max = 400): string[] => xs.map((x) => safeText(x, max));
  return `${JSON.stringify({
    pipegenGateResult: 1, result: verdict, pass: r?.pass ?? false, mode: r?.mode ?? null, event: safeText(ev.name, 40), sha: safeText(ev.sha, 40), runId: ev.runId,
    blockReasons: text(r?.blockReasons ?? d.errors ?? []), warnReasons: text(r?.warnReasons ?? []),
    counted: r?.counted ?? null,
    blocking: (r?.blocking ?? []).slice(0, 500).map(ref), warnings: (r?.warnings ?? []).slice(0, 500).map(ref),
    toolErrors: (r?.toolErrors ?? []).map((t) => ({ needId: t.needId, job: t.job, ...(t.tool === undefined ? {} : { tool: t.tool }), base: t.base, blocks: t.blocks, reason: safeText(t.reason, 300) })),
    failedJobs: (r?.failedJobs ?? []).map((f) => ({ needId: f.needId, job: f.job })), notRun: (r?.notRun ?? []).map((f) => ({ needId: f.needId, job: f.job })),
    checks: (r?.checks ?? []).map((c) => ({ needId: c.needId, job: c.job, ...(c.tool === undefined ? {} : { tool: c.tool }), judgedBy: c.judgedBy, state: safeText(c.state, 200) })),
    notes: text((r?.notes ?? []).slice(0, 100)), baseline: saved.baseline, marker: saved.marker,
  })}\n`;
}

/** The summary when nothing could be decided (the event or the inputs could not be trusted): built from the fixed texts. */
function blockedSummary(errors: readonly string[]): string {
  const md = (s: string): string => { const v = safeMarkdown(s); return v === '' ? '(empty)' : v; };
  return [`## pipegen gate: blocked`, '', '### Blocking', ...errors.map((e) => `- ${md(e)}`), ''].join('\n');
}

async function runGate(step: Step, deps: MainDeps, inputs: Map<string, string>): Promise<number> {
  const runIdText = step.env('GITHUB_RUN_ID') ?? '';
  const runId = /^[1-9][0-9]{0,15}$/.test(runIdText) ? Number(runIdText) : 0;
  const ev = { name: step.env('GITHUB_EVENT_NAME') ?? '', sha: step.env('GITHUB_SHA') ?? '', runId };
  let dir: string | undefined;
  let d: Decided;
  try {
    dir = gateFolder(step);
    d = badKey(inputs.get('fp-key')) ? { errors: [BAD_KEY] } : await decide(step, deps, inputs);
  } catch (e) {
    d = { errors: [e instanceof StepError ? e.message : 'the gate could not start, so it fails closed'] };
  }
  let verdict = verdictOf(d);
  let saved = { baseline: 'not eligible', marker: 'not eligible', lines: [] as string[] };
  if (dir !== undefined && d.input !== undefined && d.result !== undefined) {
    try { saved = await saveTrusted(step, dir, d.input, d.result, inputs.get('fp-key'), runId); } catch { step.warn('the baseline and the marker were not written (this is not a gate failure)'); }
  }
  // 1. the result file (pinned upload step, if: always()); a result that can not be written makes the gate fail closed
  let written = false;
  let stale = false;
  if (dir !== undefined) {
    // C6 part 0 (c2): a result.json that is already there (planted) is removed first, so a stale pass never survives a failed write
    if (!removeIfThere(step.fs, dir, RESULT_FILE) && entryStillThere(dir, RESULT_FILE)) stale = true;
    try { step.writeGateFile(dir, RESULT_FILE, resultDoc(d, verdict, ev, saved)); written = true; } catch { /* below */ }
  }
  if (!written) {
    verdict = 'block';
    d = { ...d, errors: [...(d.errors ?? []), 'the gate result file could not be written, so the gate fails closed'] };
    // scan finding: whatever entry remains at result.json after a failed write is stale
    if (dir !== undefined && entryStillThere(dir, RESULT_FILE)) stale = true;
    // fix round 2 (r1-3): no baseline or marker beside a result that is not there
    if (dir !== undefined) for (const f of [GATE_UPLOAD_FILES['pipegen-baseline'] as string, GATE_UPLOAD_FILES['pipegen-clean-run'] as string]) if (!removeIfThere(step.fs, dir, f)) stale = true;
  }
  // a stale file is handled at once, before the outputs and the summary can fail on their own (scan note)
  if (stale && dir !== undefined) {
    step.error('a gate file could not be removed beside a missing or planted result: the result file may be stale, so the step fails with status 2');
    quarantine(step, dir, resultDoc({ errors: [...(d.errors ?? []), 'the gate folder may hold a stale result'] }, 'block', ev, { baseline: 'removed', marker: 'removed' }));
  }
  // 2. the outputs, 3. the summary (each repo string through safeMarkdown once: decideGate's summary)
  try {
    step.setOutput('result', verdict);
    const summary = d.result !== undefined && written ? d.result.summary : blockedSummary([...(d.result?.blockReasons ?? []), ...(d.errors ?? [])]);
    step.summary(`${summary}${saved.lines.length > 0 ? `\n### Baseline\n${saved.lines.join('\n')}\n` : ''}`);
  } catch (e) {
    if (stale) throw new StaleResultError('the gate folder may hold a stale result'); // already quarantined above
    // review-C5b minor 6: the step fails after the files were written; the uploads (if: always()) must not ship a pass, a baseline or a marker
    if (dir !== undefined && written) {
      let left = false;
      for (const f of [GATE_UPLOAD_FILES['pipegen-baseline'] as string, GATE_UPLOAD_FILES['pipegen-clean-run'] as string]) if (!removeIfThere(step.fs, dir, f)) left = true;
      const failed: Decided = { errors: [...(d.result?.blockReasons ?? []), ...(d.errors ?? []), 'the gate could not hand on its result (the outputs or the summary), so it fails closed'] };
      // fix round 2 (r1-2): the block document under a temporary name, renamed over result.json (no moment without a result file); if that
      // fails, result.json is removed (the result upload then fails: closed); if even that fails, the result may be stale: status 2
      const tmp = `.${RESULT_FILE}.${randomUUID()}.tmp`;
      let replaced = false;
      try {
        step.writeGateFile(dir, tmp, resultDoc(failed, 'block', ev, { baseline: 'removed', marker: 'removed' }));
        renameSync(join(dir, tmp), join(dir, RESULT_FILE));
        replaced = true;
      } catch {
        removeIfThere(step.fs, dir, tmp);
        replaced = removeIfThere(step.fs, dir, RESULT_FILE);
      }
      if (left || !replaced) {
        step.error('the gate failed after writing its files, and they could not be replaced or removed: the result file may be stale, so the step fails with status 2');
        quarantine(step, dir, resultDoc(failed, 'block', ev, { baseline: 'removed', marker: 'removed' }));
        throw new StaleResultError('the gate folder may hold a stale result');
      }
    }
    throw e;
  }
  // 4. only then the exit status
  step.log(`gate result: ${verdict}`);
  if (stale) return STALE_EXIT; // quarantined and reported above
  if (verdict === 'block') { step.error('pipegen gate: blocked; the job summary says why'); return 1; }
  return 0;
}

// ---------- baseline-check ----------

async function runBaselineCheck(step: Step, deps: MainDeps, get: (n: string) => string | undefined): Promise<number> {
  let found = false;
  if (badKey(get('fp-key'))) {
    step.setOutput('found', 'missing');
    step.error(BAD_KEY);
    return 1;
  }
  try {
    const payload = JSON.parse(readRunnerFile(step.env('GITHUB_EVENT_PATH'), 'the event payload (GITHUB_EVENT_PATH)')) as unknown;
    const repo = repoOf(payload, step.env('GITHUB_REPOSITORY') ?? '');
    if (typeof repo === 'string') throw new StepError(repo);
    const gh = (deps.github ?? githubAdapter)({ token: get('github-token') ?? '', mask: () => undefined, notes: [] });
    const loaded = await loadBaseline(gh, repo, { key: get('fp-key'), now: (deps.now ?? (() => new Date()))() });
    found = loaded.baseline !== null;
    if (!found) step.warn(`no verified trusted baseline, so the base scan checks every tool on the base commit${loaded.note === undefined ? '' : `: ${loaded.note}`}`);
  } catch (e) {
    found = false;
    step.warn(`the stored baseline could not be looked up${e instanceof StepError ? ` (${e.message})` : ''}, so the base scan checks every tool on the base commit`);
  }
  step.setOutput('found', found ? 'found' : 'missing');
  step.log(`stored baseline: ${found ? 'found' : 'missing'}`);
  return 0;
}

// ---------- find-run ----------

const SHA_RE = /^[0-9a-f]{40}$/;
/** The default wait of find-run, in minutes. There is no default in action.yml (no input has one); the code says it. */
export const FIND_RUN_DEFAULT_MINUTES = 30;

/**
 * Mode find-run (C8): looks for the trusted run in which `sha` passed the gate. Fails closed on every error: the outputs run-id and run-url
 * are empty and the step exits 1 with the reason (none, wrong-central, gate-failed, timeout or error). The token was masked first by main.
 */
async function runFindRun(step: Step, deps: MainDeps, get: (n: string) => string | undefined): Promise<number> {
  const fail = (text: string): number => {
    step.error(`find-run: ${text}`);
    step.setOutput('run-id', '');
    step.setOutput('run-url', '');
    return 1;
  };
  const sha = get('sha');
  if (sha === undefined || !SHA_RE.test(sha)) return fail('the sha input is not a 40-character lower-case commit sha, so the step fails closed');
  // the layout is declared by the renderer (from the draft), never guessed from the repository's visibility
  const layout = get('layout');
  if (layout !== 'inline' && layout !== 'central') return fail('the layout input is not inline or central, so the step fails closed');
  const workflow = get('central-workflow');
  const centralSha = get('central-sha');
  if (layout === 'inline' && (workflow !== undefined || centralSha !== undefined)) return fail('layout inline takes no central-workflow or central-sha, so the step fails closed');
  if (layout === 'central' && (workflow === undefined || centralSha === undefined)) return fail('layout central needs both central-workflow and central-sha, so the step fails closed');
  if (workflow !== undefined && (!PLAIN_REL_RE.test(workflow) || workflow.includes('@'))) return fail('the central-workflow input is not a plain path of the central workflow, so the step fails closed');
  if (centralSha !== undefined && !SHA_RE.test(centralSha)) return fail('the central-sha input is not a 40-character lower-case commit sha, so the step fails closed');
  const minutes = get('timeout-minutes');
  if (minutes !== undefined && !TIMEOUT_MINUTES_RE.test(minutes)) return fail('the timeout-minutes input is not a whole number of minutes from 1 to 360, so the step fails closed');
  const token = get('github-token');
  if (token === undefined) return fail('the github-token input is missing, so the step fails closed');
  let repo: ReturnType<typeof repoOf>;
  try {
    repo = repoOf(JSON.parse(readRunnerFile(step.env('GITHUB_EVENT_PATH'), 'the event payload (GITHUB_EVENT_PATH)')) as unknown, step.env('GITHUB_REPOSITORY') ?? '');
  } catch (e) {
    return fail(e instanceof StepError ? `${e.message}, so the step fails closed` : 'the event payload could not be read, so the step fails closed');
  }
  if (typeof repo === 'string') return fail(`${repo}, so the step fails closed`);
  const notes: string[] = [];
  const clock = deps.now ?? (() => new Date());
  const opts: GatedRunOpts = {
    workflowPath: WORKFLOW_PATH, gateJobName: GATE_CHECK_NAME, waitMs: Number(minutes ?? FIND_RUN_DEFAULT_MINUTES) * 60_000, now: () => clock().getTime(),
    ...(workflow === undefined || centralSha === undefined ? {} : { central: { pathPrefix: workflow, sha: centralSha } }),
    ...(deps.sleep === undefined ? {} : { sleep: deps.sleep }),
  };
  let found;
  try {
    const gh = (deps.github ?? githubAdapter)({ token, mask: () => undefined, notes });
    found = await findGatedRun(gh, repo, sha, opts);
  } catch {
    return fail('GitHub could not be reached or set up, so the step fails closed');
  }
  for (const n of notes) step.warn(n);
  if (!found.ok) return fail(`no gated run for this commit (${found.reason}): ${found.detail}`);
  step.setOutput('run-id', String(found.runId));
  step.setOutput('run-url', found.url);
  step.log(`the gate passed for this commit in run ${found.runId}`);
  return 0;
}

// ---------- nightly ----------

/**
 * Mode nightly (C7): opens or updates issues (nightly.ts). Inputs: github-token (required), fp-key (optional; without it the baseline can not
 * be trusted, so the warn-ending issue is the softer one), block-from and block-from-recorded (optional). It never reads the event payload: the
 * repository is GITHUB_REPOSITORY checked against GITHUB_REPOSITORY_ID by one `GET /repos/{o}/{r}`. It writes nothing but issues. A read that fails is a log line (the pipegen repository is private until v0.4, so "no
 * update" is the normal case); an issue that could not be written, or an issue list that can not be searched to its end, fails the step.
 */
async function runNightlyMode(step: Step, deps: MainDeps, get: (n: string) => string | undefined): Promise<number> {
  const fail = (text: string): number => { step.error(`nightly: ${text}`); return 1; };
  const token = get('github-token');
  if (token === undefined) return fail('the github-token input is missing, so the step fails closed');
  if (badKey(get('fp-key'))) return fail(BAD_KEY);
  const notes: string[] = [];
  let done;
  try {
    const gh = (deps.nightly ?? githubAdapter)({ token, mask: () => undefined, notes });
    // the identity does not come from the event payload (a `schedule` run's payload is only {"schedule": "<cron>"}): GITHUB_REPOSITORY and one API read
    const repo = await resolveRepo(gh, step.env('GITHUB_REPOSITORY'), step.env('GITHUB_REPOSITORY_ID'));
    if (typeof repo === 'string') return fail(`${repo}, so the step fails closed`);
    done = await runNightly(gh, { repo, now: (deps.now ?? (() => new Date()))(), blockFrom: get('block-from'), recorded: get('block-from-recorded'), key: get('fp-key') });
  } catch {
    return fail('GitHub could not be reached or set up, so the step fails closed');
  }
  const summary = ['### pipegen nightly', ''];
  for (const i of done.issues) { step.log(`issue ${i.key}: #${i.number} ${i.action}`); summary.push(`- \`${i.key}\`: issue #${i.number} ${i.action}`); }
  if (done.issues.length === 0) summary.push('- no issue to open or update tonight');
  for (const n of [...notes, ...done.notes]) { step.log(n); summary.push(`- note: ${safeMarkdown(n, 300)}`); }
  for (const e of done.errors) { step.error(e); summary.push(`- error: ${safeMarkdown(e, 300)}`); }
  step.summary(`${summary.join('\n')}\n`);
  return done.errors.length === 0 ? 0 : 1;
}

// ---------- the reviewed view ----------

/** The built-in list's gate view: generated at build time (scripts/gate-view.ts, ruling S5), never read from disk at run time. */
function defaultReviewed(): readonly GateToolView[] {
  return GATE_VIEW;
}
