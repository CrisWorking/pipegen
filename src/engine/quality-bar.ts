// Quality bar (Plan B Task 3): pipegen only suggests or uses a tool it hasn't reviewed when the tool is maintained,
// used and free of known advisories for the version in question. Every rule fails closed: a value that is missing
// or isn't a number fails its rule (the one exception, from the plan: a project OpenSSF Scorecard hasn't scored
// skips the score rule, but never counts as a strong score).
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { z } from 'zod';
import { packageDataPath } from '../util/package-data.js';
import type { ToolStats } from '../types.js';

export interface QualityBar { minStars: number; minScorecard: number; strongScorecard: number; maxMonthsSinceRelease: number }
/** `reasons`: plain English, every failing rule (empty when it passes). */
export interface QualityVerdict { pass: boolean; reasons: string[] }

const score = z.number().min(0).max(10);
const barSchema = z.strictObject({
  minStars: z.number().int().nonnegative(),
  minScorecard: score,
  strongScorecard: score,
  maxMonthsSinceRelease: z.number().int().positive(),
}).refine((b) => b.strongScorecard >= b.minScorecard, { message: 'strongScorecard must not be below minScorecard' });

/** Reads and checks the quality bar (default: pipegen's own data/quality-bar.yml). Throws on any problem. */
export function loadQualityBar(path: string = packageDataPath('quality-bar.yml')): QualityBar {
  let raw: unknown;
  try {
    raw = parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new Error(`pipegen's quality bar (${path}) could not be read: ${e instanceof Error ? e.message.split('\n')[0] : 'unreadable'}`);
  }
  const parsed = barSchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`pipegen's quality bar (${path}) is not valid: ${issue?.path.join('.') || 'file'}: ${issue?.message ?? 'invalid'}`);
  }
  return parsed.data;
}

/** A number for a reason text; anything that isn't a finite number shows as "?". */
const show = (n: number) => (Number.isFinite(n) ? String(Math.round(n * 10) / 10) : '?');

/** Whole calendar months (UTC) from `from` to `to`; 0 when `from` is in the future. */
function monthsBetween(from: Date, to: Date): number {
  let months = (to.getUTCFullYear() - from.getUTCFullYear()) * 12 + (to.getUTCMonth() - from.getUTCMonth());
  const fromRest = Date.UTC(1970, 0, from.getUTCDate(), from.getUTCHours(), from.getUTCMinutes(), from.getUTCSeconds(), from.getUTCMilliseconds());
  const toRest = Date.UTC(1970, 0, to.getUTCDate(), to.getUTCHours(), to.getUTCMinutes(), to.getUTCSeconds(), to.getUTCMilliseconds());
  if (toRest < fromRest) months--;
  return Math.max(0, months);
}

/** Checks `s` against every rule and lists every failure, in a fixed order. */
export function checkQualityBar(s: ToolStats, bar: QualityBar, now: Date): QualityVerdict {
  const reasons: string[] = [];
  if (s.archived !== false) reasons.push('Project is archived: it gets no more fixes.');

  if (s.lastReleaseAt === null) {
    reasons.push('No releases published.');
  } else {
    const at = new Date(s.lastReleaseAt);
    if (Number.isNaN(at.getTime())) {
      reasons.push("Couldn't read the date of the last release.");
    } else {
      const months = monthsBetween(at, now);
      if (months >= bar.maxMonthsSinceRelease) reasons.push(`No release in ${months} months.`);
    }
  }

  // null = not scored by OpenSSF Scorecard: the score rule is skipped. NaN fails (`>=` is false).
  if (s.scorecard !== null && !(s.scorecard >= bar.minScorecard)) {
    reasons.push(`OpenSSF security score ${show(s.scorecard)}/10 is below ${show(bar.minScorecard)}.`);
  }
  const strongScore = s.scorecard !== null && s.scorecard >= bar.strongScorecard;
  if (!(s.stars >= bar.minStars) && !strongScore) reasons.push(`Few users (${show(s.stars)} stars) and no strong security score.`);

  if (s.license === null || s.license.trim() === '' || s.license === 'NOASSERTION') reasons.push("No licence: can't be used safely.");

  // null = the version couldn't be resolved or checked (contract change S12): fail closed.
  if (s.advisories === null) reasons.push("Couldn't check known vulnerabilities for this version.");
  else if (!(s.advisories === 0)) reasons.push('Known vulnerability in this version.');

  return { pass: reasons.length === 0, reasons };
}
