// v0.2 Plan F, F6: scoring one dispute option and comparing two (plan Task 5; rulings S11, S12; Review Focus 4).
// Order: criticalMissed loses, then timedOut loses, then more points, then a difference below 3 goes to the judge (b, the challenger).
// Points: +20 per caught critical, +10 per other caught, -1 per full minute. Every explanation line is built by code from the items'
// fixed texts (never an id, which carries a service slug) and passes the PIPEGEN.md judge.
import { describe, expect, it } from 'vitest';
import { plantedFiles, type PlantedItem } from '../src/debate/planted.js';
import { bothMissedLine, compare, decideBetween, NEAR_TIE, plain, scoreOption, type OptionRun } from '../src/debate/score.js';
import { pipegenDocProblems } from '../src/engine/created-judges/pipegen-doc.js';
import { DOC_OPTS, P } from './helpers/debate-fixtures.js';

const ITEMS = plantedFiles(P).expected;
const item = (n: number): PlantedItem => ITEMS[n] as PlantedItem;
const CRIT = ITEMS.filter((i) => i.critical);
const OTHER = ITEMS.filter((i) => !i.critical);

/** A run that caught the items listed (by id) and missed the rest. */
const runOf = (caught: PlantedItem[], over: Partial<OptionRun> = {}): OptionRun => {
  const got = new Set(caught.map((i) => i.id));
  const missed = ITEMS.filter((i) => !got.has(i.id));
  return { optionLabel: 'x', durationMs: 0, caught: caught.map((i) => i.id), missed: missed.map((i) => i.id), criticalMissed: missed.some((i) => i.critical), timedOut: false, ...over };
};
const score = (r: OptionRun) => scoreOption(r, ITEMS);
const cmp = (a: OptionRun, b: OptionRun): 'a' | 'b' => compare(a, b, score(a), score(b));

describe('F6 scoring', () => {
  it('score: 20/10/−1 rules', () => {
    expect(CRIT.length).toBeGreaterThan(1);
    expect(OTHER.length).toBeGreaterThan(0);
    expect(score(runOf([])).points).toBe(0);
    expect(score(runOf([CRIT[0] as PlantedItem])).points).toBe(20);
    expect(score(runOf([OTHER[0] as PlantedItem])).points).toBe(10);
    expect(score(runOf(ITEMS)).points).toBe(20 * CRIT.length + 10 * OTHER.length);
    // -1 per FULL minute: 59.999 s costs nothing, 60 s one, 9 min 40 s nine
    expect(score(runOf([], { durationMs: 59_999 })).points).toBe(0);
    expect(score(runOf([], { durationMs: 60_000 })).points).toBe(-1);
    expect(score(runOf([], { durationMs: 580_000 })).points).toBe(-9);
    expect(score(runOf(ITEMS, { durationMs: 120_000 })).points).toBe(20 * CRIT.length + 10 * OTHER.length - 2);
    // an unknown id counts for nothing; an id listed both caught and missed counts as missed; one id counts once
    expect(score({ ...runOf([]), caught: ['no-such-item'] }).points).toBe(0);
    expect(score({ ...runOf([]), caught: [item(0).id], missed: [item(0).id] }).points).toBe(0);
    expect(score({ ...runOf([]), missed: [], caught: [item(0).id, item(0).id] }).points).toBe(item(0).critical ? 20 : 10);
    // an unreadable duration costs nothing and never throws
    expect(score({ ...runOf([]), durationMs: Number.NaN }).points).toBe(0);
    expect(score({ ...runOf([]), durationMs: -5 }).points).toBe(0);
  });

  it('compare: criticalMissed always loses to one without', () => {
    // a has every point in the world, b has none, but a missed a critical problem
    const a = runOf(ITEMS, { criticalMissed: true });
    const b = runOf([]);
    b.criticalMissed = false;
    expect(cmp(a, b)).toBe('b');
    expect(cmp(b, a)).toBe('a');
    // still true when the other timed out
    expect(cmp(a, { ...b, timedOut: true })).toBe('b');
  });

  it('compare: both missed critical → points decide, scoreboard says both missed', () => {
    const crit = CRIT[0] as PlantedItem;
    const rest = ITEMS.filter((i) => i.id !== crit.id);
    const a = runOf(rest);                                  // missed the critical, caught everything else
    const b = runOf(rest.filter((i) => !i.critical));       // missed all criticals
    expect(a.criticalMissed && b.criticalMissed).toBe(true);
    expect(cmp(a, b)).toBe('a');
    expect(cmp(b, a)).toBe('b');
    const line = bothMissedLine(a, b, ITEMS);
    expect(line).toBe(`Both options missed: ${crit.item}.`);
    expect(line).not.toContain(crit.id);
    expect(bothMissedLine(runOf(ITEMS), b, ITEMS)).toBeNull();
    expect(pipegenDocProblems(`# PIPEGEN\n\n- ${line}\n`, DOC_OPTS)).toEqual([]);
  });

  it('compare: timedOut loses', () => {
    const slow = runOf(ITEMS, { timedOut: true });
    const none = runOf([], { criticalMissed: false });
    expect(cmp(slow, none)).toBe('b');
    expect(cmp(none, slow)).toBe('a');
    // both timed out: the points decide
    expect(cmp(slow, { ...none, timedOut: true })).toBe('a');
    expect(cmp({ ...none, timedOut: true }, slow)).toBe('b');
    // criticalMissed is judged first: a timed-out run that missed nothing critical beats a finished one that did
    const finishedButMissed = runOf(OTHER, { criticalMissed: true });
    const timedButClean = runOf(ITEMS, { timedOut: true, criticalMissed: false });
    expect(cmp(finishedButMissed, timedButClean)).toBe('b');
  });

  it('compare: near tie → judge option', () => {
    const a = runOf(ITEMS);
    const aScore = score(a);
    const b = runOf(ITEMS);
    const bump = (points: number) => ({ ...score(b), points });
    expect(NEAR_TIE).toBe(3);
    // a ahead by 0, 1, 2: the judge's option (b) wins
    for (const gap of [0, 1, 2]) expect(compare(a, b, { ...aScore, points: 50 + gap }, bump(50))).toBe('b');
    // a behind by 0, 1, 2: still b
    for (const gap of [1, 2]) expect(compare(a, b, { ...aScore, points: 50 - gap }, bump(50))).toBe('b');
    // a ahead by 3: the builder's option wins; b ahead by 3: b
    expect(compare(a, b, { ...aScore, points: 53 }, bump(50))).toBe('a');
    expect(compare(a, b, { ...aScore, points: 47 }, bump(50))).toBe('b');
    expect(compare(a, b, { ...aScore, points: 80 }, bump(50))).toBe('a');
    expect(compare(a, b, { ...aScore, points: 20 }, bump(50))).toBe('b');
  });

  it('compare: b is the challenger; near tie between two judge options → the earlier objection', () => {
    const a = runOf(ITEMS), b = runOf(ITEMS);
    const sa = { ...score(a), points: 50 }, sb = { ...score(b), points: 51 };
    // as compare: the challenger takes a near tie
    expect(compare(a, b, sa, sb)).toBe('b');
    // between two judge options the earlier one (the champion, a) keeps it
    expect(decideBetween(a, b, sa, sb, 'a')).toEqual({ winner: 'a', reason: 'tie' });
    expect(decideBetween(a, b, sa, sb, 'b')).toEqual({ winner: 'b', reason: 'tie' });
    // a real gap still decides, whoever holds the tie
    expect(decideBetween(a, b, { ...sa, points: 40 }, sb, 'a').winner).toBe('b');
    expect(decideBetween(a, b, { ...sa, points: 60 }, sb, 'b').winner).toBe('a');
    // the reasons
    expect(decideBetween(runOf([], { criticalMissed: true }), runOf([], { criticalMissed: false }), sa, sb, 'b')).toEqual({ winner: 'b', reason: 'critical' });
    expect(decideBetween(runOf([], { timedOut: true, criticalMissed: false }), runOf([], { criticalMissed: false }), sa, sb, 'b')).toEqual({ winner: 'b', reason: 'timeout' });
  });

  it('score: explanation lines are built by code, never AI text', () => {
    const crit = CRIT[0] as PlantedItem;
    const hostile = { ...runOf(ITEMS.filter((i) => i.id !== crit.id), { durationMs: 580_000, timedOut: true }), optionLabel: 'x <img src=//e.example> @boss [a](http://e.example) ```' };
    const s = scoreOption(hostile, ITEMS);
    expect(s.explanation).toEqual([
      `Caught ${ITEMS.length - 1} of ${ITEMS.length} planted problems.`,
      `Missed a critical problem: ${crit.item}.`,
      'Did not finish in time, so this option counts as lost.',
      'Took 9 min 40 s (-9 points).',
    ]);
    expect(s.optionLabel).not.toMatch(/[<>@\[\]`]/);
    expect(scoreOption(runOf(ITEMS, { durationMs: 40_000 }), ITEMS).explanation).toEqual([
      `Caught ${ITEMS.length} of ${ITEMS.length} planted problems (all critical ones).`, 'Took 40 s (no points lost).',
    ]);
    expect(scoreOption(runOf(ITEMS, { durationMs: 60_000 }), ITEMS).explanation.at(-1)).toBe('Took 1 min 0 s (-1 point).');
    // never an item id (it carries a service slug), whatever the run holds
    const lines = [...s.explanation, ...scoreOption(runOf([]), ITEMS).explanation];
    for (const l of lines) for (const i of ITEMS) expect(l).not.toContain(i.id);
    // every line passes the PIPEGEN.md judge as it is
    for (const l of lines) expect(pipegenDocProblems(`# PIPEGEN\n\n- ${l}\n`, DOC_OPTS)).toEqual([]);
    // no critical item expected: nothing to be "all" of
    const plainItems = ITEMS.filter((i) => !i.critical);
    expect(scoreOption(runOf(plainItems), plainItems).explanation[0]).toBe(`Caught ${plainItems.length} of ${plainItems.length} planted problems.`);
    // a critical miss with nothing nameable (the run could not be read) still says so
    expect(scoreOption({ ...runOf([]), criticalMissed: true }, []).explanation).toContain('Missed a critical problem: the run could not be read as a block.');
    // an item text that is not plain is cleaned, never passed on
    const odd: PlantedItem = { ...item(0), id: 'odd', item: 'bad <b>text</b> with @boss and [x](http://e.example)', critical: true };
    const line = scoreOption({ optionLabel: 'x', durationMs: 0, caught: [], missed: ['odd'], criticalMissed: true, timedOut: false }, [odd]).explanation[1] as string;
    expect(pipegenDocProblems(`# PIPEGEN\n\n- ${line}\n`, DOC_OPTS)).toEqual([]);
    expect(plain('a<b>c')).toBe('a b c');
  });
});
