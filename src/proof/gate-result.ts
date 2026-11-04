// Reading the gate's result.json (artifact `pipegen-gate-result`) for the proof (v0.2 Plan E, E5; ruling S9; Plan C result doc
// from gate/src/main.ts resultDoc). It is a REPORT, never authority: the decision is the gate job's conclusion. The report is
// read beside it for the findings and the per-need state, and it must agree with the job and with the run it came from
// (the run id and the event), so a stale or planted file is never read as this run's report.
// Everything here is hostile-shaped input from a run in the scratch repo: strict shape checks, safeText on every string a person
// may see, and anything else is "report unreadable" (never a pass, never "no results").
import { GATE_RESULT_ARTIFACT } from '../engine/artifact-names.js';
import type { Finding, Severity } from '../types.js';
import { safeText } from '../util/safe-text.js';
import type { RunOutcome } from './run.js';

const SEVERITIES: ReadonlySet<string> = new Set<Severity>(['critical', 'high', 'medium', 'low', 'info']);
const VERDICTS: ReadonlySet<string> = new Set(['pass', 'warn', 'block']);
const MAX_ITEMS = 500;

export interface GateFinding { needId: string; job: string; tool: string; ruleId: string; severity: Severity; file?: string; line?: number; isNew: boolean | null; secret: boolean }
export interface GateCheck { needId: string; job: string; tool?: string; judgedBy: string; state: string }
export interface GateResultDoc {
  result: 'pass' | 'warn' | 'block';
  pass: boolean;
  event: string;
  runId: number;
  blockReasons: string[];
  warnReasons: string[];
  blocking: GateFinding[];
  warnings: GateFinding[];
  toolErrors: { needId: string; job: string; tool?: string; base: boolean; blocks: boolean; reason: string }[];
  failedJobs: { needId: string; job: string }[];
  notRun: { needId: string; job: string }[];
  checks: GateCheck[];
  notes: string[];
}
export type GateResultRead = { ok: true; doc: GateResultDoc } | { ok: false; reason: string };

const bad = (why: string): GateResultRead => ({ ok: false, reason: `report unreadable: ${safeText(why, 200)}` });
const isRec = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const str = (x: unknown, max = 400): string | undefined => (typeof x === 'string' && x.length <= 4 * max ? safeText(x, max) : undefined);
const list = (x: unknown): unknown[] | undefined => (Array.isArray(x) && x.length <= MAX_ITEMS ? x : undefined);

function findings(x: unknown): GateFinding[] | undefined {
  const l = list(x);
  if (l === undefined) return undefined;
  const out: GateFinding[] = [];
  for (const f of l) {
    if (!isRec(f)) return undefined;
    const needId = str(f.needId, 100), job = str(f.job, 120), tool = str(f.tool, 64), ruleId = str(f.ruleId, 200);
    if (needId === undefined || job === undefined || tool === undefined || ruleId === undefined || typeof f.severity !== 'string' || !SEVERITIES.has(f.severity)) return undefined;
    const file = f.file === undefined ? undefined : str(f.file, 300);
    if (f.file !== undefined && file === undefined) return undefined;
    if (f.line !== undefined && (typeof f.line !== 'number' || !Number.isSafeInteger(f.line) || f.line < 0)) return undefined;
    out.push({
      needId, job, tool, ruleId, severity: f.severity as Severity, ...(file === undefined ? {} : { file }), ...(f.line === undefined ? {} : { line: f.line as number }),
      isNew: typeof f.isNew === 'boolean' ? f.isNew : null, secret: f.secret === true,
    });
  }
  return out;
}
function refs(x: unknown): { needId: string; job: string }[] | undefined {
  const l = list(x);
  if (l === undefined) return undefined;
  const out: { needId: string; job: string }[] = [];
  for (const r of l) {
    if (!isRec(r)) return undefined;
    const needId = str(r.needId, 100), job = str(r.job, 120);
    if (needId === undefined || job === undefined) return undefined;
    out.push({ needId, job });
  }
  return out;
}
function texts(x: unknown): string[] | undefined {
  const l = list(x);
  if (l === undefined) return undefined;
  const out: string[] = [];
  for (const t of l) { const s = str(t, 400); if (s === undefined) return undefined; out.push(s); }
  return out;
}

/** Parses result.json text. `runId` and `event` are the run it was downloaded from; a report of another run or event is refused. */
export function parseGateResult(bytes: Uint8Array, from: { runId: number; event: string }): GateResultRead {
  let doc: unknown;
  try { doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return bad('it is not JSON'); }
  if (!isRec(doc) || doc.pipegenGateResult !== 1) return bad('it is not a pipegen gate result');
  if (typeof doc.result !== 'string' || !VERDICTS.has(doc.result) || typeof doc.pass !== 'boolean') return bad('it has no verdict');
  if (doc.pass !== (doc.result !== 'block')) return bad('its verdict and its pass flag disagree');
  if (doc.runId !== from.runId) return bad('it belongs to another run');
  if (doc.event !== from.event) return bad('it belongs to another event');
  const blocking = findings(doc.blocking), warnings = findings(doc.warnings);
  const failedJobs = refs(doc.failedJobs), notRun = refs(doc.notRun);
  const blockReasons = texts(doc.blockReasons), warnReasons = texts(doc.warnReasons), notes = texts(doc.notes);
  if (blocking === undefined || warnings === undefined || failedJobs === undefined || notRun === undefined || blockReasons === undefined || warnReasons === undefined || notes === undefined) return bad('a list in it is malformed');
  const tl = list(doc.toolErrors), cl = list(doc.checks);
  if (tl === undefined || cl === undefined) return bad('a list in it is malformed');
  const toolErrors: GateResultDoc['toolErrors'] = [];
  for (const t of tl) {
    if (!isRec(t)) return bad('a tool error is malformed');
    const needId = str(t.needId, 100), job = str(t.job, 120), reason = str(t.reason, 300);
    if (needId === undefined || job === undefined || reason === undefined || typeof t.base !== 'boolean' || typeof t.blocks !== 'boolean') return bad('a tool error is malformed');
    const tool = t.tool === undefined ? undefined : str(t.tool, 64);
    toolErrors.push({ needId, job, ...(tool === undefined ? {} : { tool }), base: t.base, blocks: t.blocks, reason });
  }
  const checks: GateCheck[] = [];
  for (const c of cl) {
    if (!isRec(c)) return bad('a check is malformed');
    const needId = str(c.needId, 100), job = str(c.job, 120), judgedBy = str(c.judgedBy, 40), state = str(c.state, 200);
    if (needId === undefined || job === undefined || judgedBy === undefined || state === undefined) return bad('a check is malformed');
    const tool = c.tool === undefined ? undefined : str(c.tool, 64);
    checks.push({ needId, job, ...(tool === undefined ? {} : { tool }), judgedBy, state });
  }
  return {
    ok: true,
    doc: { result: doc.result as GateResultDoc['result'], pass: doc.pass, event: doc.event, runId: doc.runId, blockReasons, warnReasons, blocking, warnings, toolErrors, failedJobs, notRun, checks, notes },
  };
}

/** The gate result of a run: its artifact's file, or why there is none ("report unreadable"). */
export function gateResultOf(outcome: Pick<RunOutcome, 'artifacts' | 'artifactProblems' | 'handle'>): GateResultRead {
  const problem = outcome.artifactProblems.get(GATE_RESULT_ARTIFACT);
  if (problem !== undefined) return bad(problem);
  const file = outcome.artifacts.get(GATE_RESULT_ARTIFACT);
  if (file === undefined) return bad('the run has no pipegen-gate-result artifact');
  if (file.file !== 'result.json') return bad('the artifact does not hold result.json');
  return parseGateResult(file.bytes, { runId: outcome.handle.runId, event: outcome.handle.event });
}

/** The gate's findings as the Finding shape the planted matcher and the fix loop use (no message: result.json carries none). */
export function asFindings(l: readonly GateFinding[]): Finding[] {
  return l.map((f) => ({
    tool: f.tool, ruleId: f.ruleId, severity: f.severity, ...(f.file === undefined ? {} : { file: f.file }), ...(f.line === undefined ? {} : { line: f.line }),
    message: `${f.ruleId} (${f.needId})`, fingerprint: `${f.needId}:${f.job}:${f.tool}:${f.ruleId}:${f.file ?? ''}:${f.line ?? ''}`,
  }));
}
