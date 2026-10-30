// Plan C Task C3: warn or block (DECISIONS #96, preflight ruling S13). In warn mode, old findings only warn; in block mode they
// follow the policy. New critical or high findings and any new secret block in BOTH modes (decide.ts); this only says when old
// findings start to count.
//
// The block-from date comes from two places: the repository variable PIPEGEN_BLOCK_FROM, which anyone with write access can move
// or delete, and the date `finish` recorded at setup as the literal input `block-from-recorded`, which a PR can't edit (a
// protected path). So the EARLIER of the two valid dates counts: a writer who moves the variable later, or deletes it, can't delay
// blocking past the recorded date, and an earlier variable (a team that wants to block sooner) is honoured. A date that is not a
// real calendar date in the form YYYY-MM-DD counts as absent. A trusted clean run (the marker, verified in baseline.ts) ends
// warn mode on its own. No date at all and no clean run: warn (a repo that has not finished setup).
//
// "Today" is the UTC day: the date counts from 00:00 UTC. A clock that is not a date fails closed (block).
import type { GateMode } from './decide.js';

/** A real calendar date `YYYY-MM-DD` (year 0001 to 9999), as the same text; otherwise undefined. */
export function validDate(text: string | undefined): string | undefined {
  if (typeof text !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(text)) return undefined;
  const [y, m, d] = text.split('-').map(Number) as [number, number, number];
  if (y < 1) return undefined;
  const t = new Date(Date.UTC(y, m - 1, d));
  t.setUTCFullYear(y);   // years 0 to 99 would otherwise map to 1900 to 1999
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d ? text : undefined;
}

export interface ModeDecision { mode: GateMode; /** One line for the summary and the notes: why. */ why: string }

/** resolveMode with the reason. */
export function decideMode(blockFrom: string | undefined, recorded: string | undefined, today: Date, cleanRunSeen: boolean): ModeDecision {
  if (cleanRunSeen) return { mode: 'block', why: 'block mode: a trusted clean run has been seen' };
  if (!(today instanceof Date) || Number.isNaN(today.getTime())) return { mode: 'block', why: 'block mode: the clock is not a date, so the gate fails closed' };
  const day = today.toISOString().slice(0, 10);
  const v = validDate(blockFrom);
  const r = validDate(recorded);
  const dates = [v, r].filter((x): x is string => x !== undefined).sort();
  const effective = dates[0];
  if (effective === undefined) return { mode: 'warn', why: 'warn mode: no block-from date is set and no clean run has been seen yet' };
  const which = effective === r && effective !== v ? 'the date recorded at setup' : effective === v && effective !== r ? 'PIPEGEN_BLOCK_FROM' : 'PIPEGEN_BLOCK_FROM and the date recorded at setup';
  return day >= effective
    ? { mode: 'block', why: `block mode: ${which} (${effective}) has been reached` }
    : { mode: 'warn', why: `warn mode until ${effective} (${which})` };
}

/**
 * @param blockFrom the variable PIPEGEN_BLOCK_FROM (undefined or "" when unset)
 * @param recorded the date `finish` recorded (the `block-from-recorded` input)
 * @param today the current time (the UTC day counts)
 * @param cleanRunSeen a trusted, signed clean-run marker exists (baseline.ts cleanRunSeen)
 */
export function resolveMode(blockFrom: string | undefined, recorded: string | undefined, today: Date, cleanRunSeen: boolean): GateMode {
  return decideMode(blockFrom, recorded, today, cleanRunSeen).mode;
}
