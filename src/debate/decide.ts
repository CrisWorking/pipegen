// The automatic decision of the disputes left after the debate (v0.2 Plan F Task 5; rulings S11-S14, F5-R3, F5-R4, F4-m6).
// No vote: each option of a dispute is proven on its own Plan E variant (`dispute-dN-a` the builder's, `dispute-dN-b` or
// `dispute-dN-<j>-b` the judge's), every variant carrying the same planted problems on the same base, and the scores decide
// (score.ts). A wrong winner can loosen a blocking check, so every fail-safe leans to "missed", and a near tie goes to the judge.
//
// Variant tree rule for Plan G (S14): one commit on the BASE: the option's app files + the same planted files as the `planted`
// branch + fresh C1b placements (plantedSecretPlacements). No fix loop (keepOpen false), so the PR is closed after the runs.
// Disputes run after pushProofSetup and before the main merge (S27); if a judge option wins, `main` and `planted` re-run through
// rerunProof with the new files before the merge. Plan G implements `canProve` from the minutes meter.
import { interrupting } from '../util/exit-hooks.js';
import { CapReachedError } from '../proof/caps.js';
import { jobNameMatches, latest, type PlantedItem as EvalItem, type VariantRuns } from '../proof/evaluate.js';
import { asFindings, gateResultOf } from '../proof/gate-result.js';
import { HARNESS_PATH } from '../proof/harness.js';
import type { JobOutcome, RunOutcome } from '../proof/run.js';
import { ScratchGuardError, ProofStopError } from '../proof/target.js';
import type { PlantedPlacement, Variant } from '../proof/snapshot.js';
import type { Finding } from '../types.js';
import type { Choice } from './builder.js';
import type { Dispute, DisputeOption } from './debate.js';
import { matchPlanted, type PlantedItem } from './planted.js';
import { NEAR_TIE, bothMissedLine, decideBetween, missedItems, plain, scoreOption, type OptionRun, type Reason, type Score } from './score.js';

/** At most this many disputes get a proof run; the rest go to the judge's option (S13). */
export const MAX_PROVEN_DISPUTES = 3;
/** The id of the one pseudo-item that stands for the C1b placements (all of them must be caught). */
export const PLACEMENTS_ITEM_ID = 'c1b-placements';
const DEFAULT_PIPEGEN_WORKFLOW = '.github/workflows/pipegen.yml';

// ---------- the planted placements as one item ----------

/**
 * The C1b placements (secrets in paths that allowlists commonly skip) as one critical item, for a dispute on the secrets check:
 * caught only when the option's secrets scanner reported every one of them. Null when there is no secret placement. Append it to
 * the planted items before scoring.
 */
export function placementItem(placements: readonly PlantedPlacement[]): PlantedItem | null {
  if (!placements.some((p) => p.kind === 'secret')) return null;
  return {
    id: PLACEMENTS_ITEM_ID, category: 'secrets', item: 'hard-coded API keys in files that path allowlists often skip', file: '', critical: true, minSeverity: 'high', needKey: 'secrets',
  };
}

/** Each need key → the tool of that key in `choices` (the option's own tool per job, F5-R3). */
export function toolsByKey(choices: readonly Choice[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const c of choices) {
    const id = c?.chosen?.tool?.id;
    if (typeof c?.key === 'string' && typeof id === 'string' && id !== '') out.set(c.key, id);
  }
  return out;
}

// ---------- OptionRun from a variant's runs (S12) ----------

export interface OptionRunContext {
  optionLabel: string;
  /** The planted items (plantedFiles' `expected`, plus placementItem when the placements are judged). */
  expected: readonly PlantedItem[];
  /** The C1b secret placements, judged only through the pseudo-item. */
  placements?: readonly PlantedPlacement[];
  /** This option's own tool per need key (toolsByKey of the choices it ran with), not per category (F5-R3). */
  toolOfKey: ReadonlyMap<string, string>;
  /** Pipegen's own workflow files (default `.github/workflows/pipegen.yml`); runs of any other file are no source here. */
  pipegenWorkflows?: readonly string[];
}

const normFile = (s: string): string => s.replace(/[^\x20-\x7e]/g, '');
/**
 * What one dispute variant's runs showed. Fail-safe (S12): the variant stopped, no pull request run of pipegen's workflow, the gate
 * job not `failure` (a pass, a cancel, a skip or an unfinished gate is not "blocked"), an unreadable report or one that says pass →
 * every item missed and criticalMissed true. Otherwise each item is matched (matchPlanted) with its own job's tool; an item whose job
 * has no tool is missed. timedOut: the variant stopped, or a pipegen or harness run ended timed_out or cancelled, or the time cannot be
 * read. durationMs = the last pull request job's completed_at - the first one's started_at on GitHub's clock.
 */
export function optionRunOf(runs: VariantRuns, ctx: OptionRunContext): OptionRun {
  const expected = ctx.expected;
  let why: OptionRun['why'];
  const allMissed = (timedOut: boolean, durationMs: number): OptionRun => ({
    optionLabel: ctx.optionLabel, durationMs, caught: [], missed: expected.map((e) => e.id), criticalMissed: true, timedOut, ...(timedOut && why !== undefined ? { why } : {}),
  });
  const pipegen = new Set(ctx.pipegenWorkflows ?? [DEFAULT_PIPEGEN_WORKFLOW]);
  const outcomes: RunOutcome[] = Array.isArray(runs?.outcomes) ? runs.outcomes.filter((o) => typeof o === 'object' && o !== null && typeof o.handle === 'object' && o.handle !== null && Array.isArray(o.jobs) && o.artifacts instanceof Map && o.artifactProblems instanceof Map) : [];
  const pr = outcomes.filter((o) => o.handle.event === 'pull_request' && pipegen.has(o.handle.workflow));

  // timedOut
  const stopped = runs?.stopped === true || outcomes.some((o) => o.stopped === true);
  const unfinished = stopped || outcomes.some((o) => (pipegen.has(o.handle.workflow) || o.handle.workflow === HARNESS_PATH) && (o.conclusion === 'timed_out' || o.conclusion === 'cancelled'));
  let timedOut = unfinished;
  if (unfinished) why = 'unfinished';
  // the duration, from GitHub's own job times (a job that never ran has none and is left out)
  const timed = pr.flatMap((o) => latest(o.jobs)).filter((j) => j.conclusion !== 'skipped');
  let durationMs = 0;
  if (timed.length === 0 || timed.some((j) => typeof j.startedAt !== 'number' || typeof j.completedAt !== 'number' || !Number.isFinite(j.startedAt) || !Number.isFinite(j.completedAt))) { timedOut = true; why ??= 'untimed'; }
  else {
    durationMs = Math.max(...timed.map((j) => j.completedAt as number)) - Math.min(...timed.map((j) => j.startedAt as number));
    if (durationMs < 0) { timedOut = true; durationMs = 0; why ??= 'untimed'; }
  }

  if (stopped || pr.length === 0) return allMissed(timedOut, durationMs);
  const gateHits = pr.flatMap((run) => latest(run.jobs).filter((job) => jobNameMatches(job.name, 'gate')).map((job) => ({ run, job })));
  if (gateHits.length === 0 || gateHits.some((h) => h.job.conclusion !== 'failure')) return allMissed(timedOut, durationMs);
  const read = gateResultOf((gateHits[0] as { run: RunOutcome }).run);
  if (!read.ok || read.doc.pass) return allMissed(timedOut, durationMs);

  const blocking = read.doc.blocking;
  const findings = asFindings(blocking);
  const caughtIds = new Set<string>();
  // group by (category, tool): matchPlanted takes one tool per category, so the option's tool per job is applied per group
  const groups = new Map<string, { category: string; tool: string; items: EvalItem[] }>();
  for (const item of expected) {
    if (item.id === PLACEMENTS_ITEM_ID) continue;
    const tool = typeof item.needKey === 'string' ? ctx.toolOfKey.get(item.needKey) : undefined;
    if (tool === undefined) continue;   // no tool for its job: missed
    const k = `${item.category}\u0000${tool}`;
    const g = groups.get(k) ?? { category: item.category, tool, items: [] };
    g.items.push(item);
    groups.set(k, g);
  }
  for (const g of groups.values()) {
    let m: { caught: string[]; missed: string[] } | undefined;
    try { m = matchPlanted(findings as Finding[], g.items.map((i) => ({ ...i })), new Map([[g.category, g.tool]])); } catch { m = undefined; }
    const missed = new Set(Array.isArray(m?.missed) ? m.missed : []);
    for (const id of Array.isArray(m?.caught) ? m.caught : []) if (!missed.has(id)) caughtIds.add(id);
  }
  // the C1b placements: every one must be reported by this option's secrets scanner, from the secrets job, in its file
  if (expected.some((e) => e.id === PLACEMENTS_ITEM_ID)) {
    const tool = ctx.toolOfKey.get('secrets');
    const secrets = (ctx.placements ?? []).filter((p) => p.kind === 'secret');
    const hits = blocking.filter((f) => f.tool === tool && f.job === 'secrets' && (f.needId === 'secrets' || f.secret));
    if (tool !== undefined && secrets.length > 0 && secrets.every((p) => hits.some((f) => f.file !== undefined && (p.nonUtf8 === true ? normFile(f.file) === normFile(p.path) : f.file === p.path)))) caughtIds.add(PLACEMENTS_ITEM_ID);
  }
  const caught = expected.filter((e) => caughtIds.has(e.id)).map((e) => e.id);
  const missed = expected.filter((e) => !caughtIds.has(e.id));
  return { optionLabel: ctx.optionLabel, durationMs, caught, missed: missed.map((e) => e.id), criticalMissed: missed.some((e) => e.critical === true), timedOut, ...(timedOut && why !== undefined ? { why } : {}) };
}

// ---------- the decision ----------

export interface DecideDeps {
  /**
   * Proves one option on its variant with `choices` (the debate's choices with this dispute's key set to the option's) and returns what it
   * showed (Plan G: proveVariant, then optionRunOf with toolsByKey(choices)). The variant is never 'main' or 'planted'.
   */
  prove: (variant: Variant, choices: Choice[]) => Promise<{ run: OptionRun }>;
  /** The planted items every option is scored against. */
  expected: readonly PlantedItem[];
  /** The debate's choices (DebateResult.choices): each option runs with these, its dispute's key replaced by the option's choice. */
  choices: readonly Choice[];
  /** Plan G: whether the next dispute's runs (`runs` of them) fit what is left of the minutes cap. Not given: always. */
  canProve?: (runs: number) => boolean | Promise<boolean>;
}
export interface Decision {
  /** need key → the winning choice, one per dispute. */
  winners: Map<string, Choice>;
  /** Plain lines for PIPEGEN.md, built by code from a plain alphabet. */
  scoreboard: string[];
}

const isJudge = (o: DisputeOption): boolean => o.label === 'judge';
function whoOf(d: Dispute, o: DisputeOption): string {
  if (o.label === 'pipegen') return "pipegen's pick";
  if (o.label === 'builder') return "the builder's pick";
  const judges = d.options.filter(isJudge);
  return judges.length > 1 ? `the judge's option ${judges.indexOf(o) + 1}` : "the judge's option";
}
const toolOf = (o: DisputeOption): string => plain(o.choice?.chosen?.tool?.id ?? 'unknown tool', 60);
const named = (d: Dispute, o: DisputeOption): string => `${whoOf(d, o)} (${toolOf(o)})`;
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

/** A run the prove call failed to give: every item missed, timed out. */
function lostRun(label: string, expected: readonly PlantedItem[]): OptionRun {
  return { optionLabel: label, durationMs: 0, caught: [], missed: expected.map((e) => e.id), criticalMissed: true, timedOut: true, why: 'error' };
}
/** A run from prove that cannot be trusted as given (wrong shape) is a lost run. */
function sane(run: unknown, label: string, expected: readonly PlantedItem[]): OptionRun {
  const r = run as Partial<OptionRun> | null | undefined;
  if (typeof r !== 'object' || r === null || !Array.isArray(r.caught) || !Array.isArray(r.missed) || typeof r.criticalMissed !== 'boolean' || typeof r.timedOut !== 'boolean' || typeof r.durationMs !== 'number') return lostRun(label, expected);
  // the reported flags are never trusted: a critical item not caught is a critical miss, and a time that is not a time is no time
  const out: OptionRun = { optionLabel: label, durationMs: r.durationMs, caught: r.caught as string[], missed: r.missed as string[], criticalMissed: r.criticalMissed, timedOut: r.timedOut, ...(r.why === undefined ? {} : { why: r.why }) };
  if (missedItems(out, expected).some((i) => i.critical === true)) out.criticalMissed = true;
  if (!Number.isFinite(out.durationMs) || out.durationMs < 0) { out.timedOut = true; out.durationMs = 0; out.why ??= 'untimed'; }
  return out;
}

function stopped(): ProofStopError { return new ProofStopError('pipegen is stopping, so the disputes are not decided.'); }

const REASON_TEXT: Record<Reason, (winner: string, loser: string, gap: number) => string> = {
  critical: (w, l) => `${w} won because ${l} missed a critical problem and it did not.`,
  timeout: (w, l) => `${w} won because ${l} did not finish in time and it did.`,
  points: (w, _l, gap) => `${w} won by ${gap} points.`,
  tie: (w) => `${w} won because the scores were within ${NEAR_TIE - 1} points of each other.`,
};

/**
 * Decides every dispute with no vote (S11, S13). A dispute is proven when fewer than MAX_PROVEN_DISPUTES are proven and canProve
 * allows it; the champion starts as the key's own option (builder or pipegen) and meets each judge option in objection order, each
 * option proven once. Against the builder side a near tie goes to the judge option; between two judge options it keeps the earlier
 * objection. A dispute not proven goes to its first judge option, with a scoreboard line saying so. ProofStopError (CapReachedError
 * too), a scratch guard error and an interrupt pass through; any other error from prove makes that option timedOut with every item missed.
 */
export async function decideDisputes(disputes: readonly Dispute[], deps: DecideDeps): Promise<Decision> {
  const winners = new Map<string, Choice>();
  const scoreboard: string[] = [];
  let proven = 0;
  for (const d of disputes) {
    if (interrupting()) throw stopped();
    const first = d.options.find(isJudge);
    const start = d.options.find((o) => !isJudge(o)) ?? d.options[0];
    if (start === undefined) continue;
    // catalog words only: the need key carries the service slug (repo text), which never goes into PIPEGEN.md
    const head = `Dispute ${plain(d.id, 20)} on the ${plain(d.needId, 40)} check`;
    if (first === undefined) { winners.set(d.key, start.choice); scoreboard.push(`${head} had no judge option, so ${named(d, start)} stays.`); continue; }
    const challengers = d.options.filter((o) => isJudge(o) && o !== start);
    let skip: string | null = null;
    if (proven >= MAX_PROVEN_DISPUTES) skip = `at most ${MAX_PROVEN_DISPUTES} disputes are proven`;
    else {
      let can: boolean;
      try { can = (await deps.canProve?.(d.options.length)) !== false; } catch (e) { if (e instanceof ProofStopError || e instanceof ScratchGuardError || interrupting()) throw e; can = false; }
      if (!can) skip = 'not enough Actions minutes are left for it';
    }
    if (skip !== null) {
      winners.set(d.key, first.choice);
      scoreboard.push(`${head} was decided for ${named(d, first)} without a proof run (${skip}).`);
      continue;
    }
    proven++;
    const runOf = async (o: DisputeOption): Promise<{ run: OptionRun; score: Score }> => {
      if (interrupting()) throw stopped();
      const choices = deps.choices.some((c) => c.key === d.key) ? deps.choices.map((c) => (c.key === d.key ? o.choice : c)) : [...deps.choices, o.choice];
      let run: OptionRun;
      try {
        run = sane((await deps.prove(o.variant, choices)).run, plain(whoOf(d, o), 60), deps.expected);
      } catch (e) {
        if (e instanceof ProofStopError || e instanceof CapReachedError || e instanceof ScratchGuardError || interrupting()) throw e;
        run = lostRun(plain(whoOf(d, o), 60), deps.expected);
      }
      return { run, score: scoreOption(run, deps.expected) };
    };
    scoreboard.push(`${head} was decided by a proof run: each option ran on its own branch with the same planted problems.`);
    let champ = start;
    let champRun = await runOf(champ);
    const report = (o: DisputeOption, r: { run: OptionRun; score: Score }): void => {
      scoreboard.push(`${head}, ${named(d, o)} scored ${r.score.points} points.`);
      for (const line of r.score.explanation) scoreboard.push(`${head}, ${named(d, o)}: ${line}`);
    };
    report(champ, champRun);
    for (const challenger of challengers) {
      const cr = await runOf(challenger);
      report(challenger, cr);
      const both = bothMissedLine(champRun.run, cr.run, deps.expected);
      if (both !== null) scoreboard.push(`${head}: ${both}`);
      const v = decideBetween(champRun.run, cr.run, champRun.score, cr.score, isJudge(champ) ? 'a' : 'b');
      const [w, l, wr, lr] = v.winner === 'a' ? [champ, challenger, champRun, cr] : [challenger, champ, cr, champRun];
      const text = v.reason === 'tie' && isJudge(champ) && v.winner === 'a'
        ? `${cap(named(d, w))} stays because the scores were within ${NEAR_TIE - 1} points of each other and it was objected first.`
        : cap(REASON_TEXT[v.reason](named(d, w), named(d, l), Math.abs(wr.score.points - lr.score.points)));
      scoreboard.push(`${head}: ${text}`);
      if (v.winner === 'b') { champ = challenger; champRun = cr; }
    }
    winners.set(d.key, champ.choice);
  }
  return { winners, scoreboard };
}
