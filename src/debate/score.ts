// Scoring one dispute option and comparing two (v0.2 Plan F Task 5; rulings S11, S12; Review Focus 4).
// Each option of a dispute is proven on its own Plan E variant, with the planted problems; the scores decide, with no vote and no
// AI. A wrong winner can loosen a blocking check, so every rule leans the safe way: a missed critical problem loses, a run that did
// not finish loses, and a near tie goes to the judge's (safer) option. Every explanation line is built here from fixed words and the
// planted items' fixed texts (never an id, which carries a service slug), from a plain alphabet, so it also passes the PIPEGEN.md
// judge (it goes into that file).
import type { PlantedItem } from './planted.js';

/** What one option's proof run showed (built by decide.ts optionRunOf). Ids are the planted items' ids. */
export interface OptionRun {
  optionLabel: string;
  durationMs: number;
  caught: string[];
  missed: string[];
  criticalMissed: boolean;
  timedOut: boolean;
}
export interface Score { optionLabel: string; points: number; explanation: string[] }

/** +20 for a caught critical problem, +10 for any other caught one, -1 per full minute the run took. */
export const POINTS_CRITICAL = 20;
export const POINTS_OTHER = 10;
export const MINUTE_MS = 60_000;
/** A difference below this is a near tie: the judge's option wins. */
export const NEAR_TIE = 3;

/** Why one option beat the other. */
export type Reason = 'critical' | 'timeout' | 'points' | 'tie';
export interface Verdict { winner: 'a' | 'b'; reason: Reason }

/** Plain text only: anything outside letters, digits, space and a few marks becomes a space (these lines go into PIPEGEN.md). */
export function plain(text: string, max = 160): string {
  // also no scheme:// or www. (the PIPEGEN.md judge refuses a bare URL) and no run of three tildes (a fence)
  const t = String(text).replace(/[^\p{L}\p{N} .,;:!?'()/_+=%*~-]+/gu, ' ').replace(/:\/\/|www\.|~{3,}/gi, ' ').replace(/ {2,}/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 3).trimEnd()}...` : t;
}

const ids = (l: unknown): string[] => (Array.isArray(l) ? l.filter((x): x is string => typeof x === 'string') : []);
/** The whole minutes of a duration; an unreadable or negative one counts as none (optionRunOf already marks that run timedOut). */
const fullMinutes = (ms: unknown): number => (typeof ms === 'number' && Number.isFinite(ms) && ms > 0 ? Math.floor(ms / MINUTE_MS) : 0);
const textOf = (item: PlantedItem): string => plain(typeof item.item === 'string' ? item.item : 'a planted problem');

/** The items of `expected` named by `list` (a caught id counts once, and never when it is also listed missed; an unknown id counts for nothing). */
function caughtItems(r: OptionRun, expected: readonly PlantedItem[]): PlantedItem[] {
  const missed = new Set(ids(r.missed));
  const seen = new Set<string>();
  const out: PlantedItem[] = [];
  for (const id of ids(r.caught)) {
    if (seen.has(id) || missed.has(id)) continue;
    seen.add(id);
    const item = expected.find((e) => e.id === id);
    if (item !== undefined) out.push(item);
  }
  return out;
}
/** Every expected item that was not caught (a missing answer is a miss), in expected order. */
export function missedItems(r: OptionRun, expected: readonly PlantedItem[]): PlantedItem[] {
  const caught = new Set(caughtItems(r, expected).map((i) => i.id));
  return expected.filter((e) => !caught.has(e.id));
}

export function scoreOption(r: OptionRun, expected: readonly PlantedItem[]): Score {
  const caught = caughtItems(r, expected);
  const criticalCaught = caught.filter((i) => i.critical === true).length;
  const minutes = fullMinutes(r.durationMs);
  const points = POINTS_CRITICAL * criticalCaught + POINTS_OTHER * (caught.length - criticalCaught) - minutes;
  const criticalTotal = expected.filter((i) => i.critical === true).length;
  const lines: string[] = [];
  lines.push(`Caught ${caught.length} of ${expected.length} planted problems${criticalTotal > 0 && criticalCaught === criticalTotal ? ' (all critical ones)' : ''}.`);
  if (r.criticalMissed === true) {
    const named = missedItems(r, expected).filter((i) => i.critical === true).map(textOf);
    lines.push(named.length > 0 ? `Missed a critical problem: ${named.join(', ')}.` : 'Missed a critical problem: the run could not be read as a block.');
  }
  if (r.timedOut === true) lines.push('Did not finish in time, so this option counts as lost.');
  const secs = Math.floor((typeof r.durationMs === 'number' && Number.isFinite(r.durationMs) && r.durationMs > 0 ? r.durationMs : 0) / 1000);
  const took = minutes > 0 ? `${minutes} min ${secs - minutes * 60} s` : `${secs} s`;
  lines.push(`Took ${took} (${minutes === 0 ? 'no points lost' : `-${minutes} point${minutes === 1 ? '' : 's'}`}).`);
  return { optionLabel: plain(String(r.optionLabel), 60), points, explanation: lines };
}

/**
 * The comparison, in this order: an option that missed a critical problem loses to one that did not; then one that timed out
 * loses to one that did not; then more points win; a difference below NEAR_TIE goes to `tieTo`. When both missed a critical
 * problem (or both timed out) the next rule decides. Returns the winner and why.
 */
export function decideBetween(a: OptionRun, b: OptionRun, ea: Score, eb: Score, tieTo: 'a' | 'b'): Verdict {
  if (a.criticalMissed === true && b.criticalMissed !== true) return { winner: 'b', reason: 'critical' };
  if (b.criticalMissed === true && a.criticalMissed !== true) return { winner: 'a', reason: 'critical' };
  if (a.timedOut === true && b.timedOut !== true) return { winner: 'b', reason: 'timeout' };
  if (b.timedOut === true && a.timedOut !== true) return { winner: 'a', reason: 'timeout' };
  const diff = ea.points - eb.points;
  if (!(Math.abs(diff) >= NEAR_TIE)) return { winner: tieTo, reason: 'tie' };
  return { winner: diff > 0 ? 'a' : 'b', reason: 'points' };
}

/** `b` is always the challenger (a judge option, ruling S11): a near tie goes to it. */
export function compare(a: OptionRun, b: OptionRun, ea: Score, eb: Score): 'a' | 'b' {
  return decideBetween(a, b, ea, eb, 'b').winner;
}

/** "Both options missed: X, Y." for the problems neither caught (null when there is none). The texts, never the ids. */
export function bothMissedLine(a: OptionRun, b: OptionRun, expected: readonly PlantedItem[]): string | null {
  const other = new Set(missedItems(b, expected).map((i) => i.id));
  const both = missedItems(a, expected).filter((i) => other.has(i.id)).map(textOf);
  return both.length === 0 ? null : `Both options missed: ${both.join(', ')}.`;
}
