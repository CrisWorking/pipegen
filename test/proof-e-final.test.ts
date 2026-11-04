// Plan E final review fix wave (review-E-final.md; ruling E-F1): I-2 (a proof that failed but returned is never saved as
// proven, and the state holds the verdict and the final draft), I-3 (the secret names the workflows read are recomputed on
// every proof), N2-a (no minutes read after the cleanup was cut, no unhandled rejection). The reviewer's probes
// (tmp-final-review/) are tests here, with the outcome they should have. No network.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { proveThenClean, proofVerdict, type CleanupResult } from '../src/proof/cleanup.js';
import { PLACEHOLDER_PREFIX } from '../src/proof/keys.js';
import { nextStage, StateError, StateStore } from '../src/proof/state.js';
import type { CreatedFile, PipelineDraft } from '../src/types.js';
import { draftOf } from './helpers/proof-eval.js';
import { app } from './helpers/scratch-secrets.js';

const RUN = '20261104-090000-abc123';
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const home = (): string => { const d = mkdtempSync(join(tmpdir(), 'pg-efinal-')); dirs.push(d); return d; };

const file = (path: string, content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'docker', repo: 'app', reason: 'r', ...over });
const PRE_FIX: PipelineDraft = draftOf({ created: [file('api/Dockerfile', 'FROM node:24\nEXPOSE 3000\n')] });
const FIXED: PipelineDraft = draftOf({ created: [file('api/Dockerfile', 'FROM node:24\nEXPOSE 8080\n', { aiEdited: true })] });
const cleaned = async (): Promise<CleanupResult> => ({ repoDeleted: true, leftovers: [] });

async function proving(): Promise<StateStore> {
  const store = await StateStore.open(app(), { home: home(), env: {} });
  store.begin(RUN, app(), { cap: 100, aiCap: 1, draft: PRE_FIX });
  for (const s of ['planned', 'debated', 'created', 'proving'] as const) store.setStage(s);
  store.markArmed(true);
  return store;
}

describe('final review I-2: the saved stage follows the verdict, and the state holds the final draft', () => {
  it('the reviewer\'s probe: a proof that failed but returned, then Ctrl-C at the preview → resume never delivers, never the pre-fix draft', async () => {
    const store = await proving();
    const outcome = { draft: FIXED, result: { ok: false }, stopped: 'pipeline could not be proven' };
    const r = await proveThenClean(store, async () => outcome, cleaned);
    expect(r.outcome).toBe(outcome);
    const saved = store.load();
    expect(saved).toMatchObject({ stage: 'stopped', interruptedAt: 'proving', stoppedBy: 'proof-failed', proofOk: false, proofStopped: 'pipeline could not be proven' });
    expect(nextStage(saved!)).toBe('proving');
    // the final (AI-fixed) draft, aiEdited kept, on disk
    expect(saved?.draft?.created).toEqual(FIXED.created);
    expect(saved?.draft?.created[0]?.aiEdited).toBe(true);
    // Ctrl-C at the preview
    store.setStage('interrupted');
    const after = store.load();
    expect(after).toMatchObject({ stage: 'interrupted', interruptedAt: 'proving' });
    expect(nextStage(after!)).toBe('proving');
    expect(after?.draft?.created).toEqual(FIXED.created);
    expect(() => store.setStage('delivered')).toThrow(StateError);
    expect(() => store.setStage('proven')).toThrow(StateError);
  });

  it('a proof that passed: proven → cleaned with the verdict and the final draft; Ctrl-C at the preview → resume delivers that draft', async () => {
    const store = await proving();
    await proveThenClean(store, async () => ({ draft: FIXED, result: { ok: true } }), cleaned);
    const saved = store.load();
    expect(saved).toMatchObject({ stage: 'cleaned', proofOk: true });
    // a verdict reader that says ok without a draft: not proven
    const other = await proving();
    await proveThenClean(other, async () => 'x', cleaned, () => ({ ok: true }));
    expect(other.load()).toMatchObject({ stage: 'stopped', stoppedBy: 'proof-failed', proofOk: false });
    // a verdict reader that throws: not proven, the cleanup still ran
    const thrown = await proving();
    let ran = false;
    await proveThenClean(thrown, async () => 'x', async () => { ran = true; return cleaned(); }, () => { throw new Error('unreadable'); });
    expect(ran).toBe(true);
    expect(thrown.load()).toMatchObject({ stage: 'stopped', proofOk: false });
    expect(saved?.proofStopped).toBeUndefined();
    expect(saved?.draft?.created).toEqual(FIXED.created);
    expect(nextStage(saved!)).toBe('delivered');
    store.setStage('interrupted');
    expect(nextStage(store.load()!)).toBe('delivered');
  });

  it('every ending that is not a pass: stopped (never proven), the verdict false, resume goes back to proving', async () => {
    const endings: [string, unknown, string][] = [
      ['ok false', { draft: FIXED, result: { ok: false } }, 'proof-failed'],
      ['ok true but stopped (the global cap)', { draft: FIXED, result: { ok: true }, stopped: 'the fix loop reached its global cap' }, 'proof-failed'],
      ['a cap that returned', { draft: FIXED, result: { ok: false }, stopped: 'the AI cost cap', cap: { kind: 'ai-cost' } }, 'ai-cost'],
      ['no verdict to read (fails closed)', 'done', 'proof-failed'],
      ['a result without ok', { draft: FIXED, result: {} }, 'proof-failed'],
      ['ok as a string', { draft: FIXED, result: { ok: 'true' } }, 'proof-failed'],
    ];
    for (const [name, outcome, by] of endings) {
      const store = await proving();
      await proveThenClean(store, async () => outcome, cleaned);
      const saved = store.load();
      expect(saved, name).toMatchObject({ stage: 'stopped', interruptedAt: 'proving', stoppedBy: by, proofOk: false });
      expect(nextStage(saved!), name).toBe('proving');
    }
    // a cap stop that already moved the stage (onCap → saveStopState) keeps it; the verdict and draft are still saved
    const store = await proving();
    await proveThenClean(store, async () => { store.setStage('stopped', { stoppedBy: 'actions-minutes' }); return { draft: FIXED, result: { ok: false }, cap: { kind: 'actions-minutes' } }; }, cleaned);
    expect(store.load()).toMatchObject({ stage: 'stopped', stoppedBy: 'actions-minutes', proofOk: false });
    expect(store.load()?.draft?.created).toEqual(FIXED.created);
  });

  it('proofVerdict reads a FixOutcome; anything else is not a pass', () => {
    expect(proofVerdict({ draft: FIXED, result: { ok: true } })).toEqual({ ok: true, draft: FIXED });
    expect(proofVerdict({ draft: FIXED, result: { ok: false }, stopped: 'x' })).toMatchObject({ ok: false, stopped: 'x' });
    expect(proofVerdict({ draft: FIXED, result: { ok: true }, cap: { kind: 'ai-cost' } })).toMatchObject({ ok: false, cap: 'ai-cost' });
    for (const bad of [null, undefined, 'ok', 1, {}, { result: null }, { result: { ok: 1 } }]) expect(proofVerdict(bad).ok, String(bad)).toBe(false);
    expect(proofVerdict({ result: { ok: true } }).ok).toBe(false);   // no draft: nothing a resume could deliver
  });

  it('setStage(proven) needs a saved passing verdict; a new proof clears the old verdict; an old state at cleaned without one re-proves', async () => {
    const store = await proving();
    expect(() => store.setStage('proven')).toThrow(/passed/);
    store.recordVerdict({ ok: true });   // a pass without its draft saved is not one: a resume would deliver the old draft
    expect(store.load()?.proofOk).toBe(false);
    expect(() => store.setStage('proven')).toThrow(/passed/);
    store.recordVerdict({ ok: true, draft: FIXED });
    store.setStage('proven');
    store.setStage('cleaned');
    expect(nextStage(store.load()!)).toBe('delivered');
    // a state written before this fix (no verdict) at proven or cleaned: a resume proves again, never delivers
    for (const stage of ['proven', 'cleaned'] as const) {
      expect(nextStage({ stage }), stage).toBe('proving');
      expect(nextStage({ stage, proofOk: false }), stage).toBe('proving');
      expect(nextStage({ stage: 'interrupted', interruptedAt: stage }), stage).toBe('proving');
    }
    // the resume runs the proof again: the old verdict goes with it
    store.update((n) => { delete n.proofOk; });
    store.setStage('proving');
    expect(store.load()?.proofOk).toBeUndefined();
    store.recordVerdict({ ok: false, stopped: 'x', draft: FIXED });
    store.setStage('stopped', { stoppedBy: 'proof-failed' });
    store.setStage('proving');
    expect(store.load()).toMatchObject({ stage: 'proving' });
    expect(store.load()?.proofOk).toBeUndefined();
    expect(store.load()?.proofStopped).toBeUndefined();
  });

  it('the state never holds a secret value: a final draft holding one is not saved, and the proof is not marked proven', async () => {
    const store = await proving();
    const leaky = draftOf({ created: [file('api/Dockerfile', `FROM node:24\nENV K=${PLACEHOLDER_PREFIX}STRIPE_SECRET_KEY\n`, { aiEdited: true })] });
    await proveThenClean(store, async () => ({ draft: leaky, result: { ok: true } }), cleaned);
    const saved = store.load();
    expect(JSON.stringify(saved)).not.toContain(PLACEHOLDER_PREFIX);
    expect(saved).toMatchObject({ stage: 'stopped', interruptedAt: 'proving', proofOk: false });
    expect(saved?.draft?.created).toEqual(PRE_FIX.created);   // the old draft stays; a resume proves it again, never delivers it
    expect(nextStage(saved!)).toBe('proving');
    expect(() => store.recordVerdict({ ok: true, draft: leaky })).toThrow(StateError);
    // a draft that doesn't match the state format is refused before anything is written
    expect(() => store.recordVerdict({ ok: true, draft: { created: 'x' } as never })).toThrow(StateError);
    expect(store.load()?.proofOk).toBe(false);
  });
});
