// v0.2 Plan F, F6: the automatic dispute decision (plan Task 5; rulings S11-S14, F5-R3, F5-R4, F4-m6).
// Each option of a dispute is proven on its own variant (a fake `prove`), the scores decide, a near tie goes to the judge's option.
// optionRunOf turns a variant's finished runs into the scoring input and fails safe (every item missed) on anything unclear.
import { beforeAll, describe, expect, it, vi } from 'vitest';
import type { Choice } from '../src/debate/builder.js';
import { decideDisputes, disputeExpected, MAX_PROVEN_DISPUTES, optionRunOf, PLACEMENTS_ITEM_ID, placementItem, toolsByKey, type OptionRunContext } from '../src/debate/decide.js';
import type { Dispute, DisputeOption } from '../src/debate/debate.js';
import { plantedFiles, type PlantedItem } from '../src/debate/planted.js';
import type { OptionRun } from '../src/debate/score.js';
import { pipegenDocProblems } from '../src/engine/created-judges/pipegen-doc.js';
import { GATE_RESULT_ARTIFACT } from '../src/engine/artifact-names.js';
import { CapReachedError, type CapReached } from '../src/proof/caps.js';
import type { VariantRuns } from '../src/proof/evaluate.js';
import type { PlantedPlacement, Variant } from '../src/proof/snapshot.js';
import { VARIANT_RE } from '../src/proof/snapshot.js';
import { ProofStopError, ScratchGuardError } from '../src/proof/target.js';
import { interrupting } from '../src/util/exit-hooks.js';
import { safeMarkdown } from '../src/util/safe-text.js';
import { choicesFor, DOC_OPTS, NEEDS, P } from './helpers/debate-fixtures.js';
import { file, HARNESS_PATH, job, PIPEGEN, run } from './helpers/proof-eval.js';

vi.mock(import('../src/util/exit-hooks.js'), async (orig) => ({ ...(await orig()), interrupting: vi.fn(() => false) }));

/** The gate finding's secret flag, built at runtime (a literal key with a value would match the redact patterns). */
const flagged = (v: boolean): Record<string, boolean> => Object.fromEntries([[['sec', 'ret'].join(''), v]]);
const PLANTED = plantedFiles(P);
const ITEMS: PlantedItem[] = PLANTED.expected;
const itemOf = (id: string): PlantedItem => ITEMS.find((i) => i.id === id) as PlantedItem;
const OTHER_NON_CRITICAL = ITEMS.filter((i) => !i.critical);

// ---------- scoring input for decideDisputes (a fake prove) ----------

const runOf = (caught: PlantedItem[], over: Partial<OptionRun> = {}): OptionRun => {
  const got = new Set(caught.map((i) => i.id));
  const missed = ITEMS.filter((i) => !got.has(i.id));
  return { optionLabel: 'x', durationMs: 0, caught: [...got], missed: missed.map((i) => i.id), criticalMissed: missed.some((i) => i.critical), timedOut: false, ...over };
};
const GOOD = runOf(ITEMS);
const WORSE = runOf(ITEMS.filter((i) => i.id !== (OTHER_NON_CRITICAL[0] as PlantedItem).id));   // -10 points
const BAD = runOf(ITEMS.filter((i) => i.critical === false));                                    // missed every critical

const base = choicesFor(NEEDS, P);
const choiceOf = (key: string, tool: string): Choice => {
  const c = choicesFor(NEEDS, P, { [key]: tool }).find((x) => x.key === key) as Choice;
  expect(c.chosen.tool.id).toBe(tool);
  return c;
};
const opt = (label: DisputeOption['label'], variant: string, choice: Choice): DisputeOption => ({ label, variant: variant as Variant, choice, argument: 'x', objectionIds: ['o1'] });
const SAST_A = choiceOf('sast--api', 'semgrep'), SAST_B = choiceOf('sast--api', 'bandit');
const SEC_A = choiceOf('secrets', 'betterleaks'), SEC_B = choiceOf('secrets', 'gitleaks');
const dispute = (id: string, key: string, options: DisputeOption[]): Dispute => ({ id, key, needId: key.split('--')[0] as string, options });
const d1 = (label: DisputeOption['label'] = 'builder'): Dispute => dispute('d1', 'sast--api', [opt(label, 'dispute-d1-a', SAST_A), opt('judge', 'dispute-d1-b', SAST_B)]);
const d2 = (): Dispute => dispute('d2', 'secrets', [opt('builder', 'dispute-d2-a', SEC_A), opt('judge', 'dispute-d2-b', SEC_B)]);

/** A fake prove: answers per variant from `script`, records every call. */
function fakeProve(script: Record<string, OptionRun | Error>) {
  const calls: { variant: string; choices: Choice[] }[] = [];
  const prove = async (variant: Variant, choices: Choice[]): Promise<{ run: OptionRun }> => {
    calls.push({ variant, choices });
    const r = script[variant];
    if (r === undefined) throw new Error(`unexpected variant ${variant}`);
    if (r instanceof Error) throw r;
    return { run: { ...r } };
  };
  return { prove, calls };
}
const doc = (line: string): string[] => pipegenDocProblems(`# PIPEGEN\n\n- ${line}\n`, DOC_OPTS);

describe('F6 decide', () => {
  it('decide: runs each option on its own dispute-<id>-a / dispute-<id>-b variant (with the planted files) and returns winners', async () => {
    const f = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-b': WORSE, 'dispute-d2-a': BAD, 'dispute-d2-b': GOOD });
    const r = await decideDisputes([d1('pipegen'), d2()], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    expect(f.calls.map((c) => c.variant)).toEqual(['dispute-d1-a', 'dispute-d1-b', 'dispute-d2-a', 'dispute-d2-b']);
    for (const c of f.calls) { expect(c.variant).toMatch(VARIANT_RE); expect(['main', 'planted']).not.toContain(c.variant); }
    // each run gets the debate's choices with only the dispute's key replaced by that option's choice
    const at = (v: string) => f.calls.find((c) => c.variant === v)?.choices as Choice[];
    expect(at('dispute-d1-a').find((c) => c.key === 'sast--api')).toBe(SAST_A);
    expect(at('dispute-d1-b').find((c) => c.key === 'sast--api')).toBe(SAST_B);
    expect(at('dispute-d1-b').find((c) => c.key === 'secrets')).toBe(base.find((c) => c.key === 'secrets'));
    expect(at('dispute-d1-b')).toHaveLength(base.length);
    // winners by need key: the stronger run wins; d1 builder side (label pipegen) is 20+ points ahead, d2 missed criticals
    expect(r.winners.get('sast--api')).toBe(SAST_A);
    expect(r.winners.get('secrets')).toBe(SEC_B);
    expect([...r.winners.keys()]).toEqual(['sast--api', 'secrets']);
    // the scoreboard: wording follows the label, the tools are named, item text is printed and no item id
    const text = r.scoreboard.join('\n');
    expect(text).toContain("pipegen's pick (semgrep)");
    expect(text).toContain("the builder's pick (betterleaks)");
    expect(text).toContain("the judge's option (gitleaks)");
    expect(text).not.toContain("builder's pick (semgrep)");
    expect(text).toContain('Missed a critical problem: hard-coded API key in a config file');
    for (const i of ITEMS) expect(text).not.toMatch(new RegExp(`(?<![\\w-])${i.id}(?![\\w-])`));
    expect(r.scoreboard.some((l) => /won because .* missed a critical problem/.test(l))).toBe(true);
    for (const l of r.scoreboard) { expect(doc(l)).toEqual([]); expect(l).not.toMatch(/[a-z]--[a-z]/); }
    // d1: the pipegen-labelled option is the champion that starts, and a 10-point gap decides (not a near tie)
    expect(r.scoreboard.some((l) => l === "Dispute d1 on the sast check: Pipegen's pick (semgrep) won by 10 points.")).toBe(true);
  });

  it('decide: the champion starts as the key\'s own option, wherever it is listed', async () => {
    const swapped = dispute('d1', 'sast--api', [opt('judge', 'dispute-d1-b', SAST_B), opt('builder', 'dispute-d1-a', SAST_A)]);
    const f = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-b': runOf(ITEMS, { durationMs: 60_000 }) });
    const r = await decideDisputes([swapped], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    expect(f.calls.map((c) => c.variant)).toEqual(['dispute-d1-a', 'dispute-d1-b']);
    expect(r.winners.get('sast--api')).toBe(SAST_B);   // a near tie: the judge's option
  });

  it('decide: no line prints a need key, a service slug or an item id (the check is named from catalog words)', async () => {
    const slugged = dispute('d1', 'sast--acme-internal-billing', [opt('builder', 'dispute-d1-a', SAST_A), opt('judge', 'dispute-d1-b', SAST_B)]);
    const f = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-b': WORSE });
    const sk = fakeProve({});
    const lines = [
      ...(await decideDisputes([slugged], { prove: f.prove, expected: ITEMS, placements: [], choices: base })).scoreboard,
      ...(await decideDisputes([slugged], { prove: sk.prove, expected: ITEMS, placements: [], choices: base, canProve: () => false })).scoreboard,
    ];
    expect(lines.length).toBeGreaterThan(8);
    for (const l of lines) { expect(l).not.toMatch(/[a-z]--[a-z]/); expect(l).not.toContain('acme'); expect(doc(l)).toEqual([]); }
    expect(lines[0]).toBe('Dispute d1 on the sast check was decided by a proof run: each option ran on its own branch with the same planted problems.');
  });

  it('decide: a run from prove is reconciled with the expected items (criticalMissed recomputed; a bad duration is timedOut with no time points)', async () => {
    // P1: the builder's run claims nothing missed and nothing critical missed, but caught nothing
    const liar: OptionRun = { optionLabel: 'x', durationMs: 0, caught: [], missed: [], criticalMissed: false, timedOut: false };
    const judge4 = runOf(ITEMS.filter((i) => i.id !== (ITEMS.find((x) => x.critical) as PlantedItem).id));   // one critical missed
    const p1 = await decideDisputes([d1()], { prove: fakeProve({ 'dispute-d1-a': liar, 'dispute-d1-b': judge4 }).prove, expected: ITEMS, placements: [], choices: base });
    // both missed a critical: points decide, and the judge's 4 caught beat 0
    expect(p1.winners.get('sast--api')).toBe(SAST_B);
    expect(p1.scoreboard.some((l) => /Missed a critical problem/.test(l) && l.includes("the builder's pick"))).toBe(true);
    // P2: an unreadable duration is timedOut with no time points: it loses to an equal run that finished
    for (const bad of [Infinity, Number.NaN, -60_000]) {
      const r = await decideDisputes([d1()], { prove: fakeProve({ 'dispute-d1-a': runOf(ITEMS, { durationMs: bad }), 'dispute-d1-b': runOf(ITEMS, { durationMs: 300_000 }) }).prove, expected: ITEMS, placements: [], choices: base });
      expect(r.winners.get('sast--api')).toBe(SAST_B);
      expect(r.scoreboard.join('\n')).toContain('Its run could not be timed.');
    }
    // a lying flag is only ever ORed in: a true flag stays
    const flagged = runOf(ITEMS, { criticalMissed: true });
    const r3 = await decideDisputes([d1()], { prove: fakeProve({ 'dispute-d1-a': flagged, 'dispute-d1-b': runOf(ITEMS, { criticalMissed: false }) }).prove, expected: ITEMS, placements: [], choices: base });
    expect(r3.winners.get('sast--api')).toBe(SAST_B);
  });

  it('decide: a dispute with only judge options proves each once and keeps the earlier objection on a near tie', async () => {
    const onlyJudges = dispute('d1', 'sast--api', [opt('judge', 'dispute-d1-1-b', SAST_B), opt('judge', 'dispute-d1-2-b', SAST_A)]);
    const f = fakeProve({ 'dispute-d1-1-b': GOOD, 'dispute-d1-2-b': GOOD });
    const r = await decideDisputes([onlyJudges], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    expect(f.calls.map((c) => c.variant)).toEqual(['dispute-d1-1-b', 'dispute-d1-2-b']);
    expect(r.winners.get('sast--api')).toBe(SAST_B);
  });

  it('decide: merged dispute → each option proven once (champion order); variants dispute-dN-a, dispute-dN-<j>-b', async () => {
    const SAST_C = structuredClone(SAST_B);
    (SAST_C.chosen.tool as { id: string }).id = 'cool-sast';
    const merged = dispute('d1', 'sast--api', [opt('builder', 'dispute-d1-a', SAST_A), opt('judge', 'dispute-d1-1-b', SAST_B), opt('judge', 'dispute-d1-2-b', SAST_C)]);
    for (const v of merged.options.map((o) => o.variant)) expect(v).toMatch(VARIANT_RE);
    // a: -20 (missed no critical but one less), b1 near tie with a → b1 (the judge side), b2 near tie with b1 → b1 stays (the earlier objection)
    const a = runOf(ITEMS, { durationMs: 2 * 60_000 });                // total - 2
    const b1 = runOf(ITEMS, { durationMs: 3 * 60_000 });               // total - 3
    const b2 = runOf(ITEMS, { durationMs: 1 * 60_000 });               // total - 1, within 2 of b1
    const f = fakeProve({ 'dispute-d1-a': a, 'dispute-d1-1-b': b1, 'dispute-d1-2-b': b2 });
    const r = await decideDisputes([merged], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    expect(f.calls.map((c) => c.variant)).toEqual(['dispute-d1-a', 'dispute-d1-1-b', 'dispute-d1-2-b']);   // once each, in order
    expect(r.winners.get('sast--api')).toBe(SAST_B);
    const text = r.scoreboard.join('\n');
    expect(text).toContain("the judge's option 1 (bandit)");
    expect(text).toContain("the judge's option 2 (cool-sast)");
    expect(text).toContain("Dispute d1 on the sast check: The judge's option 1 (bandit) stays because the scores were within 2 points of each other and it was objected first.");
    for (const l of r.scoreboard) expect(doc(l)).toEqual([]);
    // a clear win for the later objection takes the dispute
    const f2 = fakeProve({ 'dispute-d1-a': a, 'dispute-d1-1-b': b1, 'dispute-d1-2-b': runOf(ITEMS, { durationMs: 0 }) });   // total: 3 points over b1
    expect((await decideDisputes([merged], { prove: f2.prove, expected: ITEMS, placements: [], choices: base })).winners.get('sast--api')).toBe(SAST_C);
    // a judge option that beat the builder but loses to a later one on a missed critical
    const f3 = fakeProve({ 'dispute-d1-a': BAD, 'dispute-d1-1-b': WORSE, 'dispute-d1-2-b': BAD });
    expect((await decideDisputes([merged], { prove: f3.prove, expected: ITEMS, placements: [], choices: base })).winners.get('sast--api')).toBe(SAST_B);
    // when the builder side wins against the first judge option it then meets the second one
    const f4 = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-1-b': BAD, 'dispute-d1-2-b': BAD });
    const r4 = await decideDisputes([merged], { prove: f4.prove, expected: ITEMS, placements: [], choices: base });
    expect(f4.calls).toHaveLength(3);
    expect(r4.winners.get('sast--api')).toBe(SAST_A);
  });

  it('decide: canProve false or MAX_PROVEN_DISPUTES reached → judge option wins without a run, scoreboard says so', async () => {
    expect(MAX_PROVEN_DISPUTES).toBe(3);
    const mk = (n: number): Dispute => dispute(`d${n}`, `sast--s${n}`, [opt('builder', `dispute-d${n}-a`, SAST_A), opt('judge', `dispute-d${n}-b`, SAST_B)]);
    const script: Record<string, OptionRun> = {};
    for (let n = 1; n <= 5; n++) { script[`dispute-d${n}-a`] = GOOD; script[`dispute-d${n}-b`] = BAD; }
    const f = fakeProve(script);
    const r = await decideDisputes([mk(1), mk(2), mk(3), mk(4), mk(5)], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    // three proven (builder wins), the 4th and 5th go to the judge without a run
    expect(f.calls.map((c) => c.variant)).toEqual(['d1', 'd2', 'd3'].flatMap((d) => [`dispute-${d}-a`, `dispute-${d}-b`]));
    expect([...r.winners.values()].map((c) => c.chosen.tool.id)).toEqual(['semgrep', 'semgrep', 'semgrep', 'bandit', 'bandit']);
    const skipped = r.scoreboard.filter((l) => l.includes('without a proof run'));
    expect(skipped).toEqual([
      "Dispute d4 on the sast check was decided for the judge's option (bandit) without a proof run (at most 3 disputes are proven).",
      "Dispute d5 on the sast check was decided for the judge's option (bandit) without a proof run (at most 3 disputes are proven).",
    ]);
    // canProve: asked once per dispute (with the number of runs it needs); false → the judge's option, no run, other disputes go on
    const asked: number[] = [];
    const f2 = fakeProve(script);
    const r2 = await decideDisputes([mk(1), mk(2), mk(3)], { prove: f2.prove, expected: ITEMS, placements: [], choices: base, canProve: async (n) => { asked.push(n); return asked.length !== 2; } });
    expect(asked).toEqual([2, 2, 2]);
    expect(f2.calls.map((c) => c.variant)).toEqual(['dispute-d1-a', 'dispute-d1-b', 'dispute-d3-a', 'dispute-d3-b']);
    expect([...r2.winners.values()].map((c) => c.chosen.tool.id)).toEqual(['semgrep', 'bandit', 'semgrep']);
    expect(r2.scoreboard).toContain("Dispute d2 on the sast check was decided for the judge's option (bandit) without a proof run (not enough Actions minutes are left for it).");
    // a skipped dispute does not use up the budget; a canProve that throws counts as false
    const f3 = fakeProve(script);
    const r3 = await decideDisputes([mk(1), mk(2)], { prove: f3.prove, expected: ITEMS, placements: [], choices: base, canProve: () => { throw new Error('meter broke'); } });
    expect(f3.calls).toEqual([]);
    expect([...r3.winners.values()].map((c) => c.chosen.tool.id)).toEqual(['bandit', 'bandit']);
    // a merged dispute that is not proven goes to its first judge option (the earliest objection)
    const SAST_C = structuredClone(SAST_B);
    const merged = dispute('d1', 'sast--api', [opt('builder', 'dispute-d1-a', SAST_A), opt('judge', 'dispute-d1-1-b', SAST_B), opt('judge', 'dispute-d1-2-b', SAST_C)]);
    const r4 = await decideDisputes([merged], { prove: f3.prove, expected: ITEMS, placements: [], choices: base, canProve: () => false });
    expect(r4.winners.get('sast--api')).toBe(SAST_B);
    expect(asked).toHaveLength(3);
    // no dispute, no output
    expect(await decideDisputes([], { prove: f3.prove, expected: ITEMS, placements: [], choices: base })).toEqual({ winners: new Map(), scoreboard: [] });
    // the skipped line, as printed, passes the PIPEGEN.md judge
    for (const l of [...skipped, ...r2.scoreboard]) expect(doc(l)).toEqual([]);
  });

  it('decide: ProofStopError, CapReachedError and an interrupt pass through; another error in one option → that option timedOut, all missed', async () => {
    const dispute1 = d1();
    // another error in one option: that option is timedOut with every item missed, so it loses to a finished one
    const f = fakeProve({ 'dispute-d1-a': new Error('network went away'), 'dispute-d1-b': WORSE });
    const r = await decideDisputes([dispute1], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    expect(r.winners.get('sast--api')).toBe(SAST_B);
    const text = r.scoreboard.join('\n');
    expect(text).toContain("the builder's pick (semgrep) scored 0 points.");
    expect(text).toContain("Dispute d1 on the sast check, the builder's pick (semgrep): Its run failed with an error.");
    expect(text).toContain("Dispute d1 on the sast check, the builder's pick (semgrep): Caught 0 of ");
    expect(text).toContain('Missed a critical problem: hard-coded API key in a config file');
    expect(text).not.toContain('network went away');   // an error message never reaches the scoreboard
    // the same error in the judge's option → the builder's wins
    const g = fakeProve({ 'dispute-d1-a': BAD, 'dispute-d1-b': new Error('boom') });
    expect((await decideDisputes([dispute1], { prove: g.prove, expected: ITEMS, placements: [], choices: base })).winners.get('sast--api')).toBe(SAST_A);
    // both fail → both lost, the points tie, the judge's option wins
    const h = fakeProve({ 'dispute-d1-a': new Error('a'), 'dispute-d1-b': new Error('b') });
    expect((await decideDisputes([dispute1], { prove: h.prove, expected: ITEMS, placements: [], choices: base })).winners.get('sast--api')).toBe(SAST_B);
    // a run of the wrong shape is a lost run too
    const w = fakeProve({ 'dispute-d1-a': { not: 'a run' } as unknown as OptionRun, 'dispute-d1-b': WORSE });
    expect((await decideDisputes([dispute1], { prove: w.prove, expected: ITEMS, placements: [], choices: base })).winners.get('sast--api')).toBe(SAST_B);

    // passes through, whichever option throws it, and nothing after it runs
    const cap = new CapReachedError({ kind: 'minutes', limit: 10, used: 11 } as unknown as CapReached, [], []);
    for (const err of [new ProofStopError('stop'), cap, new ScratchGuardError('guard')]) {
      for (const where of ['dispute-d1-a', 'dispute-d1-b']) {
        const p = fakeProve({ 'dispute-d1-a': where === 'dispute-d1-a' ? err : GOOD, 'dispute-d1-b': where === 'dispute-d1-b' ? err : GOOD, 'dispute-d2-a': GOOD, 'dispute-d2-b': GOOD });
        await expect(decideDisputes([dispute1, d2()], { prove: p.prove, expected: ITEMS, placements: [], choices: base })).rejects.toBe(err);
        expect(p.calls.every((c) => c.variant.startsWith('dispute-d1'))).toBe(true);
      }
    }
    // an interrupt that has begun: nothing is proven; an error while interrupting is not turned into a lost run
    vi.mocked(interrupting).mockReturnValue(true);
    const i1 = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-b': GOOD });
    await expect(decideDisputes([dispute1], { prove: i1.prove, expected: ITEMS, placements: [], choices: base })).rejects.toBeInstanceOf(ProofStopError);
    expect(i1.calls).toEqual([]);
    vi.mocked(interrupting).mockReturnValue(false);
    let n = 0;
    const i2 = { prove: async (): Promise<{ run: OptionRun }> => { if (++n === 1) { vi.mocked(interrupting).mockReturnValue(true); throw new Error('killed'); } return { run: GOOD }; } };
    await expect(decideDisputes([dispute1], { prove: i2.prove, expected: ITEMS, placements: [], choices: base })).rejects.toThrow('killed');
    vi.mocked(interrupting).mockReturnValue(false);
    // an interrupt that began between the two options of one dispute stops before the second option
    const i4 = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-b': GOOD });
    await expect(decideDisputes([dispute1], { prove: async (v, c) => { const out = await i4.prove(v, c); vi.mocked(interrupting).mockReturnValue(true); return out; }, expected: ITEMS, placements: [], choices: base })).rejects.toBeInstanceOf(ProofStopError);
    expect(i4.calls.map((c) => c.variant)).toEqual(['dispute-d1-a']);
    vi.mocked(interrupting).mockReturnValue(false);
    // an interrupt stops the decision even when no dispute would be proven (budget or canProve says no)
    vi.mocked(interrupting).mockReturnValue(true);
    await expect(decideDisputes([dispute1], { prove: i4.prove, expected: ITEMS, placements: [], choices: base, canProve: () => false })).rejects.toBeInstanceOf(ProofStopError);
    vi.mocked(interrupting).mockReturnValue(false);
    // an interrupt between two disputes stops before the second
    let seen = 0;
    const i3 = fakeProve({ 'dispute-d1-a': GOOD, 'dispute-d1-b': GOOD, 'dispute-d2-a': GOOD, 'dispute-d2-b': GOOD });
    const wrapped = async (v: Variant, c: Choice[]) => { const out = await i3.prove(v, c); if (++seen === 2) vi.mocked(interrupting).mockReturnValue(true); return out; };
    await expect(decideDisputes([dispute1, d2()], { prove: wrapped, expected: ITEMS, placements: [], choices: base })).rejects.toBeInstanceOf(ProofStopError);
    expect(i3.calls).toHaveLength(2);
    vi.mocked(interrupting).mockReturnValue(false);
  });
});

// ---------- optionRunOf ----------

const TOOL_OF_KEY = new Map([['secrets', 'gitleaks'], ['sast--api', 'semgrep'], ['sast--web', 'semgrep'], ['deps--api', 'osv-scanner'], ['deps--web', 'osv-scanner']]);
const RUN_ID = 77;
const t0 = Date.parse('2026-11-05T10:00:00Z');
const at = (min: number, sec = 0): number => t0 + (min * 60 + sec) * 1000;
const ctxOf = (over: Partial<OptionRunContext> = {}): OptionRunContext => ({ optionLabel: 'opt', expected: ITEMS, placements: [], toolOfKey: TOOL_OF_KEY, ...over });

/** The finding the gate reports for a planted item: the item's own job (needKey), the tool of that job, the item's file. */
const findingOf = (i: PlantedItem, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  needId: i.category, job: i.needKey, tool: TOOL_OF_KEY.get(i.needKey), ruleId: 'r', severity: 'high', file: i.file, isNew: null, ...flagged(i.category === 'secrets'), ...over,
});
const gateFile = (blocking: object[], over: Record<string, unknown> = {}) => file(GATE_RESULT_ARTIFACT, 'result.json', JSON.stringify({
  pipegenGateResult: 1, result: 'block', pass: false, event: 'pull_request', runId: RUN_ID, blockReasons: [], warnReasons: [], blocking, warnings: [], toolErrors: [],
  failedJobs: [], notRun: [], checks: [], notes: [], ...over,
}));
const timedJob = (name: string, conclusion: string, from: number, to: number, over: object = {}) => job(name, conclusion, { startedAt: from, completedAt: to, ...over });
/** A pull request run of pipegen's workflow whose gate blocked with `blocking`; jobs run from minute 0 to minute 9 and 40 s by default. */
function prRun(blocking: object[], o: { gate?: string; jobs?: ReturnType<typeof job>[]; artifacts?: ReturnType<typeof file>[]; conclusion?: 'failure' | 'timed_out' | 'cancelled'; stopped?: true; workflow?: string; event?: 'pull_request' | 'push'; problems?: Record<string, string> } = {}) {
  return run({
    runId: RUN_ID, workflow: o.workflow ?? PIPEGEN, event: o.event ?? 'pull_request', conclusion: o.conclusion ?? 'failure',
    jobs: o.jobs ?? [timedJob('pipegen / sast--api', 'success', at(0), at(4)), timedJob('pipegen / gate', o.gate ?? 'failure', at(5), at(9, 40))],
    artifacts: o.artifacts ?? [gateFile(blocking)], ...(o.stopped === true ? { stopped: true as const } : {}), ...(o.problems === undefined ? {} : { problems: o.problems }),
  });
}
const ALL = ITEMS.map((i) => findingOf(i));
const variantOf = (...outcomes: ReturnType<typeof run>[]): VariantRuns => ({ variant: 'dispute-d1-a' as Variant, outcomes });
const everyMissed = (r: OptionRun): void => {
  expect(r.caught).toEqual([]);
  expect([...r.missed].sort()).toEqual(ITEMS.map((i) => i.id).sort());
  expect(r.criticalMissed).toBe(true);
};

describe('F6 optionRunOf', () => {
  beforeAll(() => { expect(ITEMS.length).toBeGreaterThanOrEqual(5); expect(ITEMS.some((i) => i.critical)).toBe(true); });

  it('optionRun: caught/missed from the gate\'s blocking findings through matchPlanted, with the option\'s own tool per category', () => {
    // the name says "per category" (required verbatim), but the tool is looked up per job (needKey), as F5-R3 requires
    const r = optionRunOf(variantOf(prRun(ALL)), ctxOf());
    expect(r).toMatchObject({ optionLabel: 'opt', criticalMissed: false, timedOut: false, missed: [] });
    expect([...r.caught].sort()).toEqual(ITEMS.map((i) => i.id).sort());
    // one item without a finding is missed (a non-critical one: criticalMissed stays false), and a critical one sets criticalMissed
    const sastWeb = ITEMS.find((i) => i.needKey === 'sast--web') as PlantedItem;
    const noSast = optionRunOf(variantOf(prRun(ALL.filter((f) => f.job !== 'sast--web'))), ctxOf());
    expect(noSast.missed).toEqual([sastWeb.id]);
    expect(noSast.criticalMissed).toBe(false);
    const crit = ITEMS.find((i) => i.critical) as PlantedItem;
    const noCrit = optionRunOf(variantOf(prRun(ALL.filter((f) => f.job !== crit.needKey))), ctxOf());
    expect(noCrit.missed).toEqual([crit.id]);
    expect(noCrit.criticalMissed).toBe(true);
    // the option's OWN tool per job: this option runs bandit for sast--api, so semgrep's finding there is no catch, while the
    // sast--web item (semgrep in this option) is still caught; and bandit's finding is
    const tools = new Map(TOOL_OF_KEY).set('sast--api', 'bandit');
    const sastApi = ITEMS.find((i) => i.needKey === 'sast--api') as PlantedItem;
    const own = optionRunOf(variantOf(prRun(ALL)), ctxOf({ toolOfKey: tools }));
    expect(own.missed).toEqual([sastApi.id]);
    expect(own.caught).toContain((ITEMS.find((i) => i.needKey === 'sast--web') as PlantedItem).id);
    const viaBandit = optionRunOf(variantOf(prRun(ALL.map((f) => (f.job === 'sast--api' ? { ...f, tool: 'bandit' } : f)))), ctxOf({ toolOfKey: tools }));
    expect(viaBandit.missed).toEqual([]);
    // a job with no tool at all in this option → its item is missed, not matched by another job's tool
    const noTool = new Map(TOOL_OF_KEY);
    noTool.delete('deps--web');
    expect(optionRunOf(variantOf(prRun(ALL)), ctxOf({ toolOfKey: noTool })).missed).toEqual([(ITEMS.find((i) => i.needKey === 'deps--web') as PlantedItem).id]);
    // a finding from another job (F5-R3: the origin must be the item's own need), a finding below high, one in another file: no catch
    const other = optionRunOf(variantOf(prRun(ALL.map((f) => (f.job === 'sast--api' ? { ...f, job: 'sast--web' } : f)))), ctxOf());
    expect(other.missed).toEqual([sastApi.id]);
    expect(optionRunOf(variantOf(prRun(ALL.map((f) => (f.job === 'sast--api' ? { ...f, severity: 'medium' } : f)))), ctxOf()).missed).toEqual([sastApi.id]);
    expect(optionRunOf(variantOf(prRun(ALL.map((f) => (f.job === 'sast--api' ? { ...f, file: 'elsewhere.py' } : f)))), ctxOf()).missed).toEqual([sastApi.id]);
    // an item without a need key is never caught (F5-R4)
    const keyless = ITEMS.map((i) => (i.id === sastApi.id ? ({ ...i, needKey: undefined } as unknown as PlantedItem) : i));
    expect(optionRunOf(variantOf(prRun(ALL)), ctxOf({ expected: keyless })).missed).toEqual([sastApi.id]);
    // only the BLOCKING findings count: a catch listed as a warning is not one
    const asWarning = prRun([], { artifacts: [gateFile([], { warnings: ALL })] });
    everyMissedExceptNone(optionRunOf(variantOf(asWarning), ctxOf()));
  });

  it('optionRun: gate didn\'t block, report unreadable or variant stopped → every item missed, criticalMissed', () => {
    const good = optionRunOf(variantOf(prRun(ALL)), ctxOf());
    expect(good.missed).toEqual([]);
    // the gate job passed, was cancelled, skipped, never finished, or is absent
    for (const gate of ['success', 'cancelled', 'skipped', 'timed_out', 'neutral']) everyMissed(optionRunOf(variantOf(prRun(ALL, { gate })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { jobs: [timedJob('pipegen / sast--api', 'success', at(0), at(4))] })), ctxOf()));
    // one of two gate jobs (a matrix or an attempt of another name) not failure → not blocked
    everyMissed(optionRunOf(variantOf(prRun(ALL, { jobs: [timedJob('pipegen / gate', 'failure', at(0), at(1)), timedJob('other / gate (x)', 'success', at(0), at(1))] })), ctxOf()));
    // the report: no artifact, a problem reading it, another run's, another event's, a pass, a broken one
    everyMissed(optionRunOf(variantOf(prRun(ALL, { artifacts: [] })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { problems: { [GATE_RESULT_ARTIFACT]: 'cut' } })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { artifacts: [gateFile(ALL, { runId: RUN_ID + 1 })] })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { artifacts: [gateFile(ALL, { event: 'push' })] })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { artifacts: [gateFile(ALL, { result: 'pass', pass: true })] })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { artifacts: [file(GATE_RESULT_ARTIFACT, 'result.json', '{not json')] })), ctxOf()));
    // the variant stopped (its flag, or a run that was stopped), or has no pull request run of pipegen's workflow
    const stopped = { ...variantOf(prRun(ALL)), stopped: true };
    const s = optionRunOf(stopped, ctxOf());
    everyMissed(s);
    expect(s.timedOut).toBe(true);
    const runStopped = optionRunOf(variantOf(prRun(ALL, { stopped: true, conclusion: 'cancelled' })), ctxOf());
    everyMissed(runStopped);
    expect(runStopped.timedOut).toBe(true);
    everyMissed(optionRunOf(variantOf(prRun(ALL, { event: 'push' })), ctxOf()));
    everyMissed(optionRunOf(variantOf(prRun(ALL, { workflow: '.github/workflows/not-pipegen.yml' })), ctxOf()));
    everyMissed(optionRunOf(variantOf(), ctxOf()));
    // pull request runs of pipegen's workflow with no job at all: nothing to time, timed out
    expect(optionRunOf(variantOf(prRun(ALL, { jobs: [] })), ctxOf())).toMatchObject({ timedOut: true, durationMs: 0 });
    // a workflow list says which files are pipegen's
    expect(optionRunOf(variantOf(prRun(ALL, { workflow: '.github/workflows/pipegen-merge.yml' })), ctxOf({ pipegenWorkflows: ['.github/workflows/pipegen-merge.yml'] })).missed).toEqual([]);
    // malformed outcomes are dropped, not trusted
    everyMissed(optionRunOf({ variant: 'dispute-d1-a' as Variant, outcomes: [{ handle: null } as never] }, ctxOf()));
    // nothing planted is ever "caught" by a run that proves nothing: an empty expected list stays empty
    expect(optionRunOf(variantOf(prRun(ALL, { gate: 'success' })), ctxOf({ expected: [] }))).toMatchObject({ caught: [], missed: [], criticalMissed: true });
  });

  it('optionRun: duration = last PR-layer job end − first start (GitHub\'s times); a missing time → timedOut', () => {
    const r = optionRunOf(variantOf(prRun(ALL)), ctxOf());
    expect(r.durationMs).toBe((9 * 60 + 40) * 1000);
    expect(r.timedOut).toBe(false);
    // the jobs may overlap and come in any order: last end minus first start
    const mixed = prRun(ALL, { jobs: [timedJob('pipegen / gate', 'failure', at(6), at(12)), timedJob('pipegen / a', 'success', at(1), at(8)), timedJob('pipegen / b', 'success', at(2), at(3))] });
    expect(optionRunOf(variantOf(mixed), ctxOf()).durationMs).toBe(11 * 60_000);
    // the push layer, the harness and other runs are not part of it
    const push = run({ runId: 5, event: 'push', workflow: PIPEGEN, jobs: [timedJob('pipegen / build', 'success', at(-30), at(60))] });
    const harness = run({ runId: 6, event: 'pull_request', workflow: HARNESS_PATH, jobs: [timedJob('pipegen proof: egress', 'success', at(-30), at(60))] });
    expect(optionRunOf(variantOf(prRun(ALL), push, harness), ctxOf()).durationMs).toBe((9 * 60 + 40) * 1000);
    // a skipped job has no runner time and is left out; a missing time on any other job → timedOut (duration 0), items still judged
    const skipped = prRun(ALL, { jobs: [timedJob('pipegen / gate', 'failure', at(0), at(2)), job('pipegen / deploy', 'skipped')] });
    expect(optionRunOf(variantOf(skipped), ctxOf())).toMatchObject({ durationMs: 120_000, timedOut: false });
    for (const missing of [{ startedAt: undefined }, { completedAt: undefined }]) {
      const m = prRun(ALL, { jobs: [timedJob('pipegen / sast--api', 'success', at(0), at(4), missing), timedJob('pipegen / gate', 'failure', at(5), at(9))] });
      const out = optionRunOf(variantOf(m), ctxOf());
      expect(out).toMatchObject({ timedOut: true, durationMs: 0, missed: [] });
    }
    const noJobTimes = optionRunOf(variantOf(prRun(ALL, { jobs: [job('pipegen / gate', 'failure')] })), ctxOf());
    expect(noJobTimes.timedOut).toBe(true);
    expect(noJobTimes.caught.length).toBe(ITEMS.length);
    // an end before the start (a clock gone wrong) is not trusted
    const backwards = optionRunOf(variantOf(prRun(ALL, { jobs: [timedJob('pipegen / gate', 'failure', at(9), at(1))] })), ctxOf());
    expect(backwards).toMatchObject({ timedOut: true, durationMs: 0 });
    // the latest attempt of a job is the one that counts
    const rerun = prRun(ALL, { jobs: [timedJob('pipegen / gate', 'failure', at(0), at(50), { attempt: 1 }), timedJob('pipegen / gate', 'failure', at(0), at(3), { attempt: 2 })] });
    expect(optionRunOf(variantOf(rerun), ctxOf()).durationMs).toBe(180_000);
    // timedOut: a pipegen or harness run that timed out or was cancelled; another workflow's does not count
    for (const conclusion of ['timed_out', 'cancelled'] as const) {
      expect(optionRunOf(variantOf(prRun(ALL, { conclusion })), ctxOf()).timedOut).toBe(true);
      expect(optionRunOf(variantOf(prRun(ALL), run({ runId: 6, workflow: HARNESS_PATH, conclusion, jobs: [] })), ctxOf()).timedOut).toBe(true);
      expect(optionRunOf(variantOf(prRun(ALL), run({ runId: 8, workflow: '.github/workflows/theirs.yml', conclusion, jobs: [] })), ctxOf()).timedOut).toBe(false);
    }
    // a timed-out push run of pipegen's workflow counts too
    expect(optionRunOf(variantOf(prRun(ALL), run({ runId: 9, event: 'push', workflow: PIPEGEN, conclusion: 'timed_out', jobs: [] })), ctxOf()).timedOut).toBe(true);
  });

  it('optionRun: the C1b placements are one critical item, caught only when the option\'s secrets scanner reported every one', () => {
    const placements: PlantedPlacement[] = [
      { kind: 'secret', path: 'gitleaks.toml/app.js', pathBytes: Buffer.from('gitleaks.toml/app.js'), rule: 'generic-api-key', line: 1 },
      { kind: 'secret', path: 'pipegen-c1b/k�y.txt', pathBytes: Buffer.from([0xe9]), rule: 'generic-api-key', line: 1, nonUtf8: true },
      { kind: 'integrity-warning', path: '.gitleaksignore', pathBytes: Buffer.from('.gitleaksignore'), line: 0 },
    ];
    const pItem = placementItem(placements) as PlantedItem;
    expect(pItem).toMatchObject({ id: PLACEMENTS_ITEM_ID, critical: true, needKey: 'secrets' });
    expect(placementItem([placements[2] as PlantedPlacement])).toBeNull();
    expect(placementItem([])).toBeNull();
    const expected = [...ITEMS, pItem];
    const f = (file: string, over: object = {}) => ({ needId: 'secrets', job: 'secrets', tool: 'gitleaks', ruleId: 'generic-api-key', severity: 'high', file, isNew: null, ...flagged(true), ...over });
    const both = [f('gitleaks.toml/app.js'), f('pipegen-c1b/k\ufffdy.txt')];
    const ctx = ctxOf({ expected, placements });
    expect(optionRunOf(variantOf(prRun([...ALL, ...both])), ctx)).toMatchObject({ missed: [], criticalMissed: false });
    const one = optionRunOf(variantOf(prRun([...ALL, both[0] as object])), ctx);
    expect(one.missed).toEqual([PLACEMENTS_ITEM_ID]);
    expect(one.criticalMissed).toBe(true);
    // another scanner's report, or one from another job, is not this option's secrets scanner
    expect(optionRunOf(variantOf(prRun([...ALL, ...both.map((x) => ({ ...x, tool: 'betterleaks' }))])), ctx).missed).toEqual([PLACEMENTS_ITEM_ID]);
    expect(optionRunOf(variantOf(prRun([...ALL, ...both.map((x) => ({ ...x, job: 'sast--api' }))])), ctx).missed).toEqual([PLACEMENTS_ITEM_ID]);
    // no secrets tool in this option, or no placements handed over → missed
    const noTool = new Map(TOOL_OF_KEY);
    noTool.delete('secrets');
    expect(optionRunOf(variantOf(prRun([...ALL, ...both])), ctxOf({ expected, placements, toolOfKey: noTool })).missed).toContain(PLACEMENTS_ITEM_ID);
    expect(optionRunOf(variantOf(prRun([...ALL, ...both])), ctxOf({ expected })).missed).toEqual([PLACEMENTS_ITEM_ID]);
    // the scoreboard prints its fixed text
    expect(pItem.item).toBe('hard-coded API keys in files that path allowlists often skip');
  });

  it('optionRun: toolsByKey reads the option\'s own tool per need key', () => {
    const m = toolsByKey(base);
    expect(m.get('sast--api')).toBe('semgrep');
    expect(m.get('secrets')).toBe('betterleaks');
    expect(toolsByKey(base.map((c) => (c.key === 'sast--api' ? SAST_B : c))).get('sast--api')).toBe('bandit');
    expect(toolsByKey([{ key: 'x', chosen: {} } as unknown as Choice]).size).toBe(0);
  });
});

function everyMissedExceptNone(r: OptionRun): void {
  // a gate that blocked but listed every catch as a warning: nothing was caught, and the critical items were missed
  expect(r.caught).toEqual([]);
  expect(r.criticalMissed).toBe(true);
}

// ---------- final review fixes (I1, m4) ----------

describe('final review fixes', () => {
  const PLACED_AT = 'gitleaks.toml/app.js';
  const PLACEMENTS: PlantedPlacement[] = [
    { kind: 'secret', path: PLACED_AT, pathBytes: Buffer.from(PLACED_AT), rule: 'generic-api-key', line: 1 },
    { kind: 'integrity-warning', path: '.gitleaksignore', pathBytes: Buffer.from('.gitleaksignore'), line: 0 },
  ];

  it('m4: disputeExpected is the planted items plus the C1b placement item (once), whatever the caller already appended', () => {
    const pItem = placementItem(PLACEMENTS) as PlantedItem;
    expect(disputeExpected(ITEMS, PLACEMENTS)).toEqual([...ITEMS, pItem]);
    expect(disputeExpected([...ITEMS, pItem], PLACEMENTS)).toEqual([...ITEMS, pItem]);
    expect(disputeExpected(ITEMS, [PLACEMENTS[1] as PlantedPlacement])).toEqual(ITEMS);
    expect(disputeExpected(ITEMS, [])).toEqual(ITEMS);
    // an appended item stays even with no placement handed over: it is then missed (fail closed), never dropped
    expect(disputeExpected([...ITEMS, pItem], [])).toEqual([...ITEMS, pItem]);
    // optionRunOf judges the placements from `placements` alone: the caller need not append the item
    const blocking = ITEMS.map((i) => findingOf(i));
    expect(optionRunOf(variantOf(prRun(blocking)), ctxOf({ expected: ITEMS, placements: PLACEMENTS }))).toMatchObject({ missed: [PLACEMENTS_ITEM_ID], criticalMissed: true });
  });

  it('m4: a secrets dispute is judged on both the planted secrets file and the C1b placements', async () => {
    const leakItem = ITEMS.find((i) => i.needKey === 'secrets') as PlantedItem;
    expect(leakItem.file).not.toBe(PLACED_AT);
    // the builder's betterleaks reports only the planted secrets file; the judge's gitleaks reports both files but runs 7 minutes longer
    const prove = async (variant: Variant, choices: Choice[]): Promise<{ run: OptionRun }> => {
      // the option's own tool per job; the deps jobs (no AI choice in these fixtures) keep osv-scanner
      const tools = new Map([...TOOL_OF_KEY, ...toolsByKey(choices)]);
      const judge = variant === 'dispute-d2-b';
      const blocking: object[] = ITEMS.map((i) => findingOf(i, { tool: tools.get(i.needKey) }));
      if (judge) blocking.push({ needId: 'secrets', job: 'secrets', tool: tools.get('secrets'), ruleId: 'generic-api-key', severity: 'high', file: PLACED_AT, isNew: null, ...flagged(true) });
      const end = judge ? 16 : 9;
      const jobs = [timedJob('pipegen / secrets', 'success', at(0), at(end - 1)), timedJob('pipegen / gate', 'failure', at(end - 1), at(end))];
      return { run: optionRunOf(variantOf(prRun(blocking, { jobs })), { optionLabel: variant, expected: ITEMS, placements: PLACEMENTS, toolOfKey: tools }) };
    };
    const r = await decideDisputes([d2()], { prove, expected: ITEMS, placements: PLACEMENTS, choices: base });
    expect(r.winners.get('secrets')?.chosen.tool.id).toBe('gitleaks');
    expect(r.scoreboard.join('\n')).toMatch(/won because the builder's pick \(betterleaks\) missed a critical problem/);
    expect(r.scoreboard.join('\n')).toContain('hard-coded API keys in files that path allowlists often skip');
    // without the placements the builder's faster run would have won on points: the placements are what decide here
    const blind = await decideDisputes([d2()], { prove: async (v, c) => { const out = await prove(v, c); return { run: { ...out.run, caught: out.run.caught.filter((id) => id !== PLACEMENTS_ITEM_ID), missed: out.run.missed.filter((id) => id !== PLACEMENTS_ITEM_ID), criticalMissed: false } }; }, expected: ITEMS, placements: [], choices: base });
    expect(blind.winners.get('secrets')?.chosen.tool.id).toBe('betterleaks');
  });

  it('I1: a long scoreboard line (every critical item missed) passes the PIPEGEN.md judge as written; safeMarkdown would break it', async () => {
    const f = fakeProve({ 'dispute-d1-a': BAD, 'dispute-d1-b': GOOD });
    const r = await decideDisputes([d1()], { prove: f.prove, expected: ITEMS, placements: [], choices: base });
    const long = r.scoreboard.filter((l) => [...l].length > 200);
    expect(long.length).toBeGreaterThan(0);
    for (const line of r.scoreboard) expect(doc(line), line).toEqual([]);
    for (const line of long) {
      expect(safeMarkdown(line)).not.toBe(line);
      expect(doc(safeMarkdown(line))).not.toEqual([]);
    }
  });
});
