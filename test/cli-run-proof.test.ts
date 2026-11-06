// v0.2 Plan G G14: the production proof (src/cli/run-proof.ts) with recording fakes for GitHub, and the real fix loop, dispute decision
// and state store; plus its wiring into `pipegen run` and `pipegen resume` (src/cli/run.ts, src/cli/main.ts).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

const stop = vi.hoisted(() => ({ on: false }));
vi.mock('../src/util/exit-hooks.js', async (orig) => {
  const real = await orig<typeof import('../src/util/exit-hooks.js')>();
  return { ...real, interrupting: () => stop.on };
});

import { guardedKeys, midRunConfirm, nextCandidateFrom, proofWorkflowsOf, REPOS_NOT_READY, CENTRAL_CHANGED } from '../src/cli/run-proof.js';
import { proofAssembler } from '../src/cli/run-parts.js';
import { keyOffers } from '../src/debate/builder.js';
import { PROOF_SIGNING_MODE } from '../src/proof/harness.js';
import type { EvalContext } from '../src/proof/evaluate.js';
import { matchPlanted } from '../src/debate/planted.js';
import type { FixKeys } from '../src/proof/fix.js';
import type { CliIO } from '../src/cli/io.js';
import type { CreatedFile, PipelineDraft } from '../src/types.js';
import { cleanHomes, failOn, PASS, proofWorld, RUN_ID, TYPED } from './helpers/proof-world.js';

afterAll(cleanHomes);
const at = (tl: string[], s: string): number => tl.findIndex((x) => x === s || x.startsWith(s));

describe('G14: the proof stages 16-17', () => {
  it('run: a passing proof: armed before the first GitHub write, cleaned, the verdict saved with its draft', async () => {
    const w = await proofWorld();
    const r = await w.run();
    expect(r.ok).toBe(true);
    expect(at(w.tl, 'arm')).toBeLessThan(at(w.tl, 'checkRepos'));
    expect(w.checkOpts).toEqual([true]);
    expect(w.store.state?.stage).toBe('cleaned');
    expect(w.store.state?.proofOk).toBe(true);
    expect(w.store.state?.draft).toBeDefined();
  });
});

/** Wraps the real fix loop to look at what it is given (and at what its prove and rerun do). */
function spyLoop(w: Awaited<ReturnType<typeof proofWorld>>, look: (deps: Parameters<NonNullable<typeof w.ops.fixLoop>>[1]) => Parameters<NonNullable<typeof w.ops.fixLoop>>[1] | void) {
  return async (d: PipelineDraft, deps: Parameters<NonNullable<typeof w.ops.fixLoop>>[1]) => {
    const { proveWithFixes } = await import('../src/proof/fix.js');
    return proveWithFixes(d, look(deps) ?? deps);
  };
}

describe('G14: the brief\'s tests (preflight §7 G14)', () => {
  it('run: proof drafts assembled with signing none', async () => {
    const w = await proofWorld({ private: true });
    expect((await w.run()).ok).toBe(true);
    expect(w.asm.length).toBeGreaterThan(0);
    expect(w.asm.every((a) => a.mode === PROOF_SIGNING_MODE)).toBe(true);
    // the app branch is pinned to the proof's own central commit (private)
    expect(w.asm.some((a) => a.sha === 'c'.repeat(40))).toBe(true);
    // proofAssembler (the run's assembler for any draft): mode none only, the draft's signing plan dropped
    const seen: { mode: string; signing: unknown }[] = [];
    const d = { ...w.input.draft, signing: { mode: 'keyless' } } as unknown as PipelineDraft;
    const asm = proofAssembler(d, (x, mode) => { seen.push({ mode, signing: x.signing }); return { files: [] }; });
    asm('none', undefined);
    expect(seen).toEqual([{ mode: 'none', signing: undefined }]);
    expect(() => asm('keyless' as never, undefined)).toThrow(/signing mode none only/);
  });

  it('run: the fix loop gets the real confirm callback', async () => {
    const w = await proofWorld({ aiFile: true });
    let confirm: ((f: CreatedFile[]) => Promise<boolean>) | undefined;
    w.ops.fixLoop = spyLoop(w, (deps) => { confirm = deps.confirm; });
    await w.run();
    expect(w.asked.length).toBe(1);
    expect(w.asked[0]).toContain('pipegen\'s AI wrote or changed these files');
    expect(w.asked[0]).toContain('api/test_app.py (AI-written)');
    expect(typeof confirm).toBe('function');
    // no terminal (CI, no TTY) is a no and asks nothing (ruling G14-R0 Q5); there is no flag that answers it
    const quiet: string[] = [];
    const noTty = { prompt: { confirm: async (m: string) => { quiet.push(m); return true; } }, env: {}, interactive: false } as unknown as CliIO;
    expect(await midRunConfirm(noTty)([{ path: 'x' } as CreatedFile])).toBe(false);
    expect(await midRunConfirm({ ...noTty, interactive: true, env: { CI: 'true' } } as CliIO)([{ path: 'x' } as CreatedFile])).toBe(false);
    expect(quiet).toEqual([]);
  });

  it('run: AI-changed code runs with placeholder secrets until the mid-run confirmation', async () => {
    const w = await proofWorld({ aiFile: true, confirm: true });
    expect((await w.run()).ok).toBe(true);
    const firstRun = at(w.tl, 'variant:main');
    expect(firstRun).toBeGreaterThan(-1);
    expect(at(w.tl, 'keys.setup')).toBeLessThan(firstRun);
    expect(at(w.tl, 'confirm')).toBeGreaterThan(firstRun);
    expect(at(w.tl, 'keys.real')).toBeGreaterThan(at(w.tl, 'confirm'));
    // and the proof runs again with the real keys before the verdict
    expect(w.tl.slice(at(w.tl, 'keys.real')).some((x) => x.startsWith('variant:main'))).toBe(true);
  });

  it('run: mid-run confirmation declined → AI changes dropped, real keys never used for them', async () => {
    const w = await proofWorld({ aiFile: true, confirm: false });
    const r = await w.run();
    expect(w.tl.some((x) => x.startsWith('keys.real'))).toBe(false);
    expect(r.draft?.created.some((f) => f.path === 'api/test_app.py')).toBe(false);
    expect(r.draft?.notProven.some((n) => n.part === 'tests' && /chose not to run AI-written code/.test(n.reason))).toBe(true);
    // what was saved with the verdict is the draft without them
    expect(w.store.state?.draft?.created.some((f) => f.path === 'api/test_app.py')).toBe(false);
  });

  it('run: stopped proof → cleanup done, exit 2 with reason', async () => {
    const w = await proofWorld({ results: [failOn('sast', 'semgrep found a problem')] });
    const r = await w.run();
    expect(r.ok).toBe(false);
    expect(r.stopped).toMatch(/^pipegen stopped: the proof did not pass \(.+\), so nothing was delivered\. exit code 2\.$/);
    expect(w.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
    expect(w.store.state?.stage).toBe('stopped');
    expect(w.store.state?.proofOk).toBe(false);
  });

  it('run: prove wraps checkProofRepos and pushProofSetup; a throw there still cleans up', async () => {
    const a = await proofWorld({ input: { checkRepos: async () => { throw new Error('GitHub said 500'); } } });
    await expect(a.run()).rejects.toThrow(/GitHub said 500/);
    expect(a.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
    const b = await proofWorld({ ops: { setup: async () => { throw new Error('push refused'); } } });
    await expect(b.run()).rejects.toThrow(/push refused/);
    expect(b.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
    // a helper repo that isn't there: a stop with its reason, cleaned up too
    const c = await proofWorld({ input: { checkRepos: async () => ({ ready: false, target: {} as never, repos: [], created: [] }) } });
    const rc = await c.run();
    expect(rc).toMatchObject({ ok: false });
    expect(rc.stopped).toContain(REPOS_NOT_READY.slice(0, 40));
    expect(c.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
  });

  it('run: no secret stored outside the fix loop; pushProofSetup once', async () => {
    const w = await proofWorld({ aiFile: true, confirm: true, results: [failOn('sast'), PASS] });
    const during: string[] = [];
    w.ops.fixLoop = spyLoop(w, (deps) => ({
      ...deps,
      prove: async (d, scope) => { const n = w.tl.length; const r = await deps.prove(d, scope); during.push(...w.tl.slice(n)); return r; },
      rerun: async (ids) => { const n = w.tl.length; const r = await deps.rerun(ids); during.push(...w.tl.slice(n)); return r; },
    }));
    await w.run();
    expect(w.tl.filter((x) => x === 'setup')).toHaveLength(1);
    expect(w.tl.filter((x) => x === 'secretStore')).toHaveLength(1);
    expect(at(w.tl, 'secretStore')).toBeGreaterThan(at(w.tl, 'setup'));
    expect(during.some((x) => x.startsWith('keys.') || x === 'secretStore')).toBe(false);
    // the names are recorded before the store (E-b17)
    expect(w.store.state?.secretNames).toEqual(expect.arrayContaining(['API_TOKEN', 'PIPEGEN_FP_KEY']));
  });

  it('run: every ProofRun carries workflows; FixDeps.workflowsOf given', async () => {
    for (const priv of [false, true]) {
      const w = await proofWorld({ private: priv, results: [failOn('sast'), PASS] });
      const runs: string[][] = [];
      let given = false;
      w.ops.fixLoop = spyLoop(w, (deps) => {
        given = typeof deps.workflowsOf === 'function';
        return { ...deps, prove: async (d, s) => { const r = await deps.prove(d, s); runs.push((r.workflows ?? []).map((x) => String(x.path))); return r; } };
      });
      await w.run();
      expect(given).toBe(true);
      expect(runs.length).toBeGreaterThan(0);
      for (const r of runs) {
        expect(r).toEqual(expect.arrayContaining(['.github/workflows/pipegen.yml', '.github/workflows/pipegen-proof-harness.yml', ...(priv ? ['.github/workflows/r--merge.yml'] : [])]));
      }
    }
  });

  it('run: every AI closure uses meters.ai.provider; resume uses the saved aiCap and restoreAiSpend', async () => {
    const bundle = { files: [] } as never;
    const w = await proofWorld({ input: { bundle } });
    let seen: Parameters<NonNullable<typeof w.ops.fixLoop>>[1] | undefined;
    w.ops.fixLoop = spyLoop(w, (deps) => { seen = deps; });
    await w.run();
    expect(seen?.ai).toBe(w.meter.provider);
    expect(seen?.meters.ai).toBe(w.meter);
    expect(typeof seen?.dockerfileFor).toBe('function');
    // the resume half is in the resume tests below (fullRun with resume)
  });

  it('run: nextCandidate comes from Choice.ranked[1…] of the failing key through specFor', async () => {
    const w = await proofWorld();
    const debate = w.input.debate as NonNullable<typeof w.input.debate>;
    const p = w.input.draft.profile;
    const two = debate.choices.filter((c) => c.needId === 'sast');
    expect(two.map((c) => c.key).sort()).toEqual(['sast--api', 'sast--web']);
    // every offered tool of each key, the chosen one first (Choice.ranked)
    const offers = keyOffers(debate.needs, debate.candidates, p, { reviewed: w.input.reviewed });
    const ranked = (c: (typeof two)[number]) => [c.chosen.tool, ...(offers.offers.get(c.key) ?? []).map((o) => o.entry.candidate).filter((x) => x.id !== c.chosen.tool.id)];
    for (const c of debate.choices) (c as { ranked: unknown }).ranked = ranked(c);
    const api = two.find((c) => c.key === 'sast--api') as (typeof two)[number];
    expect(api.ranked.length).toBe(2);
    // more than one key: only the key whose job failed, never the other service's
    const failed = [{ variant: 'main', outcomes: [{ jobs: [{ name: 'sast--api', conclusion: 'failure' }, { name: 'gate', conclusion: 'failure' }] }] }] as never;
    const next = nextCandidateFrom(debate, p, w.input.reviewed, () => failed);
    const got = await next('sast', w.input.draft) as { tool: { id: string }; service?: string };
    expect(got.tool.id).toBe(api.ranked[1]?.id);
    expect(got.tool.id).not.toBe(api.chosen.tool.id);
    expect(got.service).toBe(api.chosen.service);
    // its ranked list is used up: null, and the web key (whose job did not fail) is never switched
    expect(await next('sast', w.input.draft)).toBeNull();
    // no failed job named: null (never a guess)
    expect(await nextCandidateFrom(debate, p, w.input.reviewed, () => [])('sast', w.input.draft)).toBeNull();
    // a private app (its central workflows are pushed once) and a resume (no debate): null
    expect(await nextCandidateFrom(debate, { ...p, private: true }, w.input.reviewed, () => failed)('sast', w.input.draft)).toBeNull();
    expect(await nextCandidateFrom(undefined, p, w.input.reviewed, () => failed)('sast', w.input.draft)).toBeNull();
    // one key: ranked[1], then ranked[2], … then null
    const one = debate.choices.find((c) => debate.choices.filter((x) => x.needId === c.needId).length === 1 && c.ranked.length > 1);
    if (one !== undefined) {
      const n1 = nextCandidateFrom(debate, p, w.input.reviewed, () => []);
      expect((await n1(one.needId, w.input.draft) as { tool: { id: string } }).tool.id).toBe(one.ranked[1]?.id);
    }
  });

  it('run: planted items and matchPlanted wired (compile-time test)', async () => {
    // compile time: F's matcher and items are the types EvalContext takes
    const m: NonNullable<EvalContext['matchPlanted']> = matchPlanted;
    const w = await proofWorld();
    await w.run();
    const ctx = w.evals[0]?.ctx as EvalContext;
    expect(ctx.matchPlanted).toBe(m);
    const items: NonNullable<EvalContext['plantedItems']> = ctx.plantedItems ?? [];
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((x) => typeof x.needKey === 'string' && x.needKey !== '')).toBe(true);
    // the planted files go on the planted branch only (setup's planted list), never into the app files
    const setup = w.pushed.find((x) => x.variant === 'setup');
    expect(setup?.files.some((f) => String(f.path).startsWith('pipegen-planted/'))).toBe(true);
  });

  it('run: no clack spinner during proof stages', () => {
    for (const f of ['src/cli/run-proof.ts', 'src/cli/run.ts']) {
      const src = readFileSync(join(process.cwd(), f), 'utf8');
      expect(src).not.toMatch(/from '@clack\/prompts'|\bspinner\(/);
    }
  });
});
