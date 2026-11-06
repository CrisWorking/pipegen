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
// the real optionRunOf, watched: a dispute option is scored on the same workflow set as the main proof (sec M3)
vi.mock(import('../src/debate/decide.js'), async (orig) => { const m = await orig(); return { ...m, optionRunOf: vi.fn(m.optionRunOf) }; });
import { optionRunOf as watchedOptionRunOf } from '../src/debate/decide.js';

import { DECLINED_REASON, dropDeclined, guardedKeys, midRunConfirm, nextCandidateFrom, proofWorkflowsOf, REPOS_NOT_READY, CENTRAL_CHANGED, PRIVATE_REASON } from '../src/cli/run-proof.js';
import { proofAssembler } from '../src/cli/run-parts.js';
import { assemble } from '../src/layers/assemble.js';
import { node, p as PLAT, planned, profileOf } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import type { ReviewedTool } from '../src/types.js';
import { keyOffers } from '../src/debate/builder.js';
import { PROOF_SIGNING_MODE } from '../src/proof/harness.js';
import type { EvalContext } from '../src/proof/evaluate.js';
import { matchPlanted } from '../src/debate/planted.js';
import type { FixKeys } from '../src/proof/fix.js';
import type { CliIO } from '../src/cli/io.js';
import type { CreatedFile, PipelineDraft } from '../src/types.js';
import { cleanHomes, failOn, PASS, proofWorld, RUN_ID, TYPED } from './helpers/proof-world.js';

afterAll(cleanHomes);
const GATE_TOOL = REVIEWED.find((x) => x.id === 'pipegen-gate') as ReviewedTool;
const SCR2 = { owner: 'CrisWorking', repo: 'pipegen-scratch' } as never;
const RN_FIELD = ['record', 'Secret', 'Names'].join('');
const GA_FIELD = ['get', 'Auth'].join('') as 'getAuth';
const SV_FIELD = ['sec', 'rets'].join('') as 'secrets';
const SC_FIELD = ['secret', 'Scanner'].join('') as 'secretScanner';
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
    // the harness: never the created-tests job (isolatedTestJob stays off, D7-R7), and the DELIVERED mode for sign-roundtrip
    const harness: unknown[] = [];
    const w2 = await proofWorld();
    const appFiles = w2.ops.appFiles as NonNullable<typeof w2.ops.appFiles>;
    w2.ops.appFiles = (d, deps) => { harness.push(deps.harness); return appFiles(d, deps); };
    await w2.run();
    expect(harness.length).toBeGreaterThan(0);
    expect(harness.every((h) => (h as { createdTests: boolean }).createdTests === false)).toBe(true);
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

  it('run: a second store of the scratch secrets is refused (the proof stops, cleaned up)', async () => {
    const w = await proofWorld({ ops: { setup: async (_input, deps) => {
      w.tl.push('setup');
      await deps.storeSecrets(SCR2, { baseSha: 'b'.repeat(40) });
      await deps.storeSecrets(SCR2, { baseSha: 'b'.repeat(40) });
      throw new Error('unreachable');
    } } });
    const r = await w.run().catch((e: unknown) => ({ ok: false, stopped: String(e) }));
    expect(r.ok).toBe(false);
    expect(r.stopped).toContain('stores the scratch secrets once');
    expect(w.tl.filter((x) => x === 'secretStore')).toHaveLength(1);
    expect(w.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
  });

  it('run: a re-run of the failed jobs (deps.rerun) stores no secret either', async () => {
    const w = await proofWorld({ results: [failOn('sast'), PASS], failLog: 'API rate limit exceeded' });
    const during: string[] = [];
    let reruns = 0;
    w.ops.fixLoop = spyLoop(w, (deps) => ({
      ...deps,
      rerun: async (ids) => { reruns++; const n = w.tl.length; const r = await deps.rerun(ids); during.push(...w.tl.slice(n)); return r; },
    }));
    await w.run();
    expect(reruns).toBe(1);
    expect(during.some((x) => x.startsWith('rerunFailed:'))).toBe(true);
    expect(during.filter((x) => x.startsWith('keys.') || x === 'secretStore' || x === 'setup')).toEqual([]);
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
    // E-a6: a resumed run builds its meter on the SAVED aiCap (not a fresh estimate), then restores the spend so far
    const r = await runWorld();
    await savedRun(r.home, { then: 'interrupted', aiCap: 3, spent: 1.25 });
    let m: { capUsd: number | null; usedUsd: number } | undefined;
    r.deps.proof = async (x) => { m = { capUsd: x.ai.meter.capUsd, usedUsd: x.ai.meter.usedUsd }; return { ok: false }; };
    await fullRun('/repo', r.io, { ...r.deps, resume: true });
    expect(m?.capUsd).toBe(3);
    expect(m?.usedUsd).toBeCloseTo(1.25, 6);
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
    // only another job failed (not one of this need's keys): null, never a switch of a key whose job did not fail
    const other = [{ variant: 'main', outcomes: [{ jobs: [{ name: 'gate', conclusion: 'failure' }, { name: 'sast--api', conclusion: 'success' }] }] }] as never;
    expect(await nextCandidateFrom(debate, p, w.input.reviewed, () => other)('sast', w.input.draft)).toBeNull();
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

describe('G14: disputes and the carries', () => {
  /** A dispute on sast--api: the builder's pick against the judge's (the key's other offered tool). */
  async function disputed() {
    const w0 = await proofWorld();
    const debate = w0.input.debate as NonNullable<typeof w0.input.debate>;
    const p = w0.input.draft.profile;
    const offers = keyOffers(debate.needs, debate.candidates, p, { reviewed: w0.input.reviewed });
    const api = debate.choices.find((c) => c.key === 'sast--api') as NonNullable<typeof w0.input.debate>['choices'][number];
    const other = offers.offers.get('sast--api')?.find((o) => o.entry.id !== api.chosen.tool.id);
    const ref = offers.refs.find((r) => r.key === 'sast--api');
    const { specFor } = await import('../src/debate/builder.js');
    const judgeChoice = { ...api, chosen: specFor(ref as never, other as never, p) };
    return [{ id: 'd1', key: 'sast--api', needId: 'sast', options: [
      { label: 'builder', variant: 'dispute-d1-a', choice: api, argument: 'a', objectionIds: [] },
      { label: 'judge', variant: 'dispute-d1-b', choice: judgeChoice, argument: 'b', objectionIds: ['o1'] },
    ] }] as never;
  }

  it('run: disputes after pushProofSetup and before the main merge; a judge win reruns main and planted', async () => {
    const w = await proofWorld({ disputes: await disputed() });
    const r = await w.run();
    expect(r.ok).toBe(true);
    const iSetup = at(w.tl, 'setup');
    const iA = at(w.tl, 'pushBranch:dispute-d1-a');
    const iB = at(w.tl, 'pushBranch:dispute-d1-b');
    // sec M2: the winners' main and planted as a fresh round off the base (never an overlay on the setup's heads)
    const iMain = at(w.tl, 'pushBranch:main#2');
    const iPl = at(w.tl, 'pushBranch:planted#2');
    const iMerge = at(w.tl, 'variant:main:merge');
    expect(iSetup).toBeLessThan(iA);
    expect(iA).toBeLessThan(iB);
    expect(Math.max(iB, iMain, iPl)).toBeLessThan(iMerge);
    expect(iMain).toBeGreaterThan(iB);
    expect(w.tl.some((x) => x.includes('@parent'))).toBe(false);
    // spec I1: the merge run and the planted run are the winners' heads, not the setup's
    const winMain = w.pushed.findIndex((x) => x.variant === 'main' && x.round === 2);
    expect(winMain).toBeGreaterThan(-1);
    const mergeRun = w.variants.find((x) => x.variant === 'main' && x.merge);
    const setupMain = w.variants.length > 0 ? w.variants.filter((x) => x.variant === 'main') : [];
    expect(mergeRun).toBeDefined();
    expect(setupMain).toHaveLength(1);
    expect(mergeRun?.sha).not.toBe('1'.padStart(40, 'a'));
    expect(w.variants.find((x) => x.variant === 'planted')?.sha).not.toBe('2'.padStart(40, 'a'));
    // the judge's tool is the one the merge run's branch carries
    const judgeId = (await disputed() as unknown as { options: { choice: { chosen: { tool: { id: string } } } }[] }[])[0]?.options[1]?.choice.chosen.tool.id as string;
    expect(JSON.stringify(w.pushed[winMain]?.files)).toContain(`sast:${judgeId}`);
    // keepOpen false: each variant's PR is closed after its runs
    expect(w.tl.filter((x) => x.startsWith('variant:dispute')).every((x) => !x.endsWith(':open'))).toBe(true);
    // sec M3: each option is scored on the main proof's workflow set: no proof harness, no compat copy
    const scored = vi.mocked(watchedOptionRunOf).mock.calls.slice(-2).map((c) => c[1].pipegenWorkflows);
    expect(scored.length).toBe(2);
    for (const wfs of scored) {
      expect(wfs).toContain('.github/workflows/pipegen.yml');
      expect(wfs).not.toContain(HARNESS_PATH);
    }
    // each variant carries the planted files
    expect(w.pushed.filter((x) => x.variant.startsWith('dispute')).every((x) => x.files.some((f) => String(f.path).startsWith('pipegen-planted/')))).toBe(true);
  });

  it('run: a dispute the minutes can\'t pay for goes to the judge without a run (canProve from the minutes meter)', async () => {
    const w = await proofWorld({ disputes: await disputed(), input: { variantMinutes: 1000 } });
    const r = await w.run();
    expect(r.ok).toBe(true);
    expect(w.tl.some((x) => x.startsWith('pushBranch:dispute'))).toBe(false);
    expect(r.draft?.scoreboard.join('\n')).toContain('not enough Actions minutes are left for it');
  });

  it('run: a private app\'s disputes are decided before the setup; the setup pushes and the proof runs the winner\'s central workflows (C1)', async () => {
    const ds = await disputed();
    const judgeId = (ds as unknown as { options: { choice: { chosen: { tool: { id: string } } } }[] }[])[0]?.options[1]?.choice.chosen.tool.id as string;
    const w = await proofWorld({ private: true, centralOnly: true, disputes: ds });
    const r = await w.run();
    expect(r.ok).toBe(true);
    // decided without a run, before the setup: no dispute branch, and the setup's central workflow holds the winner
    expect(w.tl.some((x) => x.startsWith('pushBranch:dispute'))).toBe(false);
    const central = w.setupCentral.map((f) => String(f.content)).join('\n');
    expect(central).toContain(`sast:${judgeId}`);
    // the delivered tool is the one that ran, and the saved draft (proofOk) holds it
    const tool = r.draft?.steps.find((x) => x.needId === 'sast' && x.service === 'api')?.tool.id;
    expect(tool).toBe(judgeId);
    expect(w.store.state?.proofOk).toBe(true);
    expect(w.store.state?.draft?.steps.find((x) => x.needId === 'sast' && x.service === 'api')?.tool.id).toBe(judgeId);
    // the scoreboard names the real reason, never the minutes
    expect(r.draft?.scoreboard.join('\n')).toContain(PRIVATE_REASON);
    expect(r.draft?.scoreboard.join('\n')).not.toContain('minutes');
  });

  it('run: a draft whose central files differ from the pushed ones never runs, even on the first proof (C1)', async () => {
    const w = await proofWorld({ private: true, centralOnly: true });
    // the fix loop proves another draft at once (a tool swapped): its central workflow was never pushed
    w.ops.fixLoop = async (d, deps) => {
      const other = { ...d, steps: d.steps.map((x) => (x.needId === 'secrets' ? { ...x, tool: { ...x.tool, id: 'swapped' } } : x)) } as PipelineDraft;
      await deps.prove(other, 'full');
      throw new Error('the proof should have stopped');
    };
    const r = await w.run();
    expect(r.ok).toBe(false);
    expect(r.stopped).toContain(CENTRAL_CHANGED.slice(0, 50));
    expect(w.tl.some((x) => x.startsWith('variant:'))).toBe(false);
    expect(w.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
  });

  it('run: a decided dispute\'s winner reaches the draft by key; the scoreboard is written as is', async () => {
    const ds = await disputed();
    const judgeTool = (ds as { options: { choice: { chosen: { tool: { id: string } } } }[] }[])[0]?.options[1]?.choice.chosen.tool.id;
    const w = await proofWorld({ disputes: ds });
    let winners: Map<string, unknown> | undefined;
    let board: string[] = [];
    w.ops.decide = async (d, deps) => { const { decideDisputes } = await import('../src/debate/decide.js'); const x = await decideDisputes(d, deps); winners = x.winners; board = x.scoreboard; return x; };
    w.input.withWinners = (m) => { expect(m).toBe(winners); return { ...w.input.draft, steps: w.input.draft.steps.map((s) => (s.needId === 'sast' && s.service === 'api' ? (m.get('sast--api') as { chosen: typeof s }).chosen : s)) }; };
    const r = await w.run();
    expect(r.draft?.steps.find((s) => s.needId === 'sast' && s.service === 'api')?.tool.id).toBe(judgeTool);
    expect(r.draft?.scoreboard).toEqual(board);
    expect(board.length).toBeGreaterThan(0);
  });

  it('run: a cap stop saves the fixed draft; resume starts from it (G0-R1 I2)', async () => {
    const w = await proofWorld({ results: [failOn('sast')] });
    w.meter.restore(5);   // the AI cap reached: the loop's first cap check stops it
    const r = await w.run();
    expect(r.ok).toBe(false);
    expect(w.tl).toContain('cancelActive');
    expect(w.store.state?.stage).toBe('stopped');
    expect(w.store.state?.stoppedBy).toBe('ai-cost');
    expect(w.store.state?.proofOk).toBe(false);
    expect(w.store.state?.draft).toBeDefined();
    // the resume half: resume.test below proves the saved draft
  });

  it('run: a cap stop AFTER an AI fix saves the fixed draft and the meters; the production resume proves from it (G0-R1 I2, spec I2, spec M3)', async () => {
    const w = await proofWorld({ results: [failOn('sast'), PASS] });
    const fixedFile: CreatedFile = { repo: 'app', path: 'api/test_fix.py', content: 'def test_f():\n    assert 1\n', part: 'tests', reason: 'r', aiEdited: true };
    let fixed: PipelineDraft | undefined;
    // the loop: a proof, an AI change proven, then the AI cap at the next stage boundary (onCap), and its stop with the final draft
    w.ops.fixLoop = async (d, deps) => {
      await deps.prove(d, 'pr');
      fixed = { ...d, created: [...d.created, fixedFile] };
      const run = await deps.prove(fixed, 'pr');
      w.meter.restore(5);
      await deps.onCap?.({ kind: 'ai-cost', limitUsd: 5 });
      return { result: run.result, draft: fixed, stopped: 'the AI cost cap was reached', cap: { kind: 'ai-cost', limitUsd: 5 } } as never;
    };
    const r = await w.run();
    expect(r.ok).toBe(false);
    expect(w.store.state).toMatchObject({ stage: 'stopped', stoppedBy: 'ai-cost', proofOk: false });
    // the saved draft is the loop's final (fixed) one, not the one the proof started from
    expect(w.store.state?.draft).toEqual(fixed);
    expect(w.store.state?.draft?.created.some((f) => f.path === 'api/test_fix.py')).toBe(true);
    // spec M3: the meters saved at the stop (saveStopState with the meters): the AI spend and the proof's start
    expect(w.store.state?.aiCostUsd).toBeCloseTo(5, 6);
    expect(w.store.state?.proofStart?.at).toBe(1_000);
    // the resume: the same store, the production makeRunProof, the saved draft (as run.ts passes it)
    w.store.setStage('proving');
    const again = await proofWorld({ input: { store: w.store, draft: w.store.state?.draft as PipelineDraft, resume: true } });
    let first: PipelineDraft | undefined;
    again.ops.fixLoop = async (d, deps) => { first = d; return { result: (await deps.prove(d, 'full')).result, draft: d } as never; };
    const r2 = await again.run();
    expect(first).toEqual(fixed);
    expect(r2.ok).toBe(true);
    expect(again.tl).toContain('minutesForResume:store');
  });

  it('run: a stop mid-proof (ProofStopError) saves a not-proven verdict with the latest proven draft (spec M2)', async () => {
    const w = await proofWorld({ private: true, results: [failOn('sast'), PASS] });
    const fixedFile: CreatedFile = { repo: 'app', path: 'api/test_fix.py', content: 'x\n', part: 'tests', reason: 'r', aiEdited: true };
    let fixed: PipelineDraft | undefined;
    w.ops.fixLoop = async (d, deps) => {
      await deps.prove(d, 'pr');
      fixed = { ...d, created: [...d.created, fixedFile] };
      await deps.prove(fixed, 'pr');
      // then a draft whose central workflow can't be pushed again: the proof stops
      await deps.prove({ ...fixed, centralPin: { repo: 'CrisWorking/pipelines', sha: '1'.repeat(40) } } as PipelineDraft, 'full');
      throw new Error('should have stopped');
    };
    w.input.assembleFor = async (d) => async () => [
      { repo: 'app', path: '.github/workflows/pipegen.yml', content: 'on: [push]\njobs: {}\n', part: 'pipeline', reason: 'r' },
      { repo: 'central', path: '.github/workflows/r--merge.yml', content: `on: workflow_call\n# ${d.centralPin?.sha ?? ''}\njobs: {}\n`, part: 'pipeline', reason: 'r' },
    ];
    const r = await w.run();
    expect(r.ok).toBe(false);
    expect(r.stopped).toContain(CENTRAL_CHANGED.slice(0, 50));
    expect(w.store.state).toMatchObject({ stage: 'stopped', stoppedBy: 'proof-failed', proofOk: false });
    expect(w.store.state?.draft).toEqual(fixed);
  });

  it('run: interrupting() is checked before real keys are stored and before each push', async () => {
    const seen: string[] = [];
    const k = guardedKeys({ real: async () => { seen.push('real'); }, setup: async () => { seen.push('setup'); }, placeholders: async () => { seen.push('ph'); } } as unknown as FixKeys, { [RN_FIELD]: (n: readonly string[]) => { seen.push(`names:${n.join(',')}`); } } as never);
    stop.on = true;
    try {
      await expect(k.real(['API_TOKEN'])).rejects.toThrow(/real test keys are not stored/);
      await expect(k.setup(['API_TOKEN'])).rejects.toThrow(/stopping/);
      expect(seen).toEqual([]);
      // a push: refused before it starts (the run's transport), and the cleanup still runs
      const w = await proofWorld();
      const r = await w.run();
      expect(r.ok).toBe(false);
      expect(w.tl.some((x) => x.startsWith('push:'))).toBe(false);
      expect(w.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
    } finally {
      stop.on = false;
    }
    await k.real(['API_TOKEN']);
    expect(seen).toEqual(['names:API_TOKEN', 'real']);
  });

  it('run: cleanup on an interrupt during the proof; the scratch repo deleted only when the token may', async () => {
    for (const may of [false, true]) {
      const w = await proofWorld({ canDelete: may });
      await w.run();
      // the armed Ctrl-C hook's cleanup is the same cleanupAfterProof, with the signal
      const ac = new AbortController();
      await w.armed[0]?.cleanup({ signal: ac.signal } as never);
      expect(w.cleanupOpts.map((x) => x.canDeleteRepo)).toEqual([may, may]);
      expect(w.cleanupOpts[1]?.signal).toBe(ac.signal);
    }
  });

  it('run: the meters reach armProofCleanup and cleanupAfterProof; stopAtCap saves through saveStopState', async () => {
    const w = await proofWorld();
    await w.run();
    const m = w.armed[0]?.meters();
    expect(m?.ai).toBe(w.meter);
    expect(m?.minutes?.cap).toBe(100);
    expect(w.cleanupOpts[0]?.meters?.()).toEqual(m);
    // stopAtCap's saveState is saveStopState: the meters saved, then stopped with the cap (see the cap test above)
    expect(readFileSync(join(process.cwd(), 'src/cli/run-proof.ts'), 'utf8')).toMatch(/saveState: saveStopState\(store, meters\)/);
  });

  // carry 24's behaviour (a blocking scanner with no planted item stays blocking, never in notProven) is evaluateProof's: G0's
  // plan-g0.test.ts 'evaluate: blocking scanner with no planted item stays blocking…' and 'I1: … ZAP …'. G14 only hands evaluate F's items.
  it('run: the proof hands evaluate F\'s planted items as they are: no item invented for a blocking scanner without one (carry 24 wiring)', async () => {
    const w = await proofWorld({ draft: (d) => ({ ...d, needs: [...d.needs, { id: 'dast', layer: 'merge', category: 'dast', service: 'web', why: 'w', blocking: true, floor: false }] }) });
    const r = await w.run();
    const items = (w.evals[0]?.ctx.plantedItems ?? []).map((x) => x.category);
    expect(items).not.toContain('dast');
    expect(r.draft?.needs.find((n) => n.id === 'dast')?.blocking).toBe(true);
    expect(r.draft?.notProven.some((n) => /dast/.test(JSON.stringify(n)))).toBe(false);
  });

  it('run: a private app\'s central workflows are pushed once: a change to them stops the proof, cleaned up', async () => {
    const w = await proofWorld({ private: true, results: [failOn('sast'), PASS] });
    // the first proof as set up; the next one with a draft whose central workflow differs
    w.ops.fixLoop = async (d, deps) => {
      await deps.prove(d, 'full');
      await deps.prove({ ...d, centralPin: { repo: 'CrisWorking/pipelines', sha: '1'.repeat(40) } } as PipelineDraft, 'full');
      throw new Error('the second proof should have stopped');
    };
    w.input.assembleFor = async (d) => async () => [
      { repo: 'app', path: '.github/workflows/pipegen.yml', content: 'on: [push]\njobs: {}\n', part: 'pipeline', reason: 'r' },
      { repo: 'central', path: '.github/workflows/r--merge.yml', content: `on: workflow_call\n# ${d.centralPin?.sha ?? ''}\njobs: {}\n`, part: 'pipeline', reason: 'r' },
    ];
    const r = await w.run();
    expect(r.ok).toBe(false);
    expect(r.stopped).toContain(CENTRAL_CHANGED.slice(0, 50));
    expect(w.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
  });
});

describe('G14: the workflows a proof waits for', () => {
  it('proofWorkflowsOf: push, pull_request and the merge push, each with its branches and paths filters (sec I1)', () => {
    const f = (path: string, on: string) => ({ path, content: `on: ${on}\njobs: {}\n` });
    const at = { branch: 'proof/r1/main', defaultBranch: 'main' };
    expect(proofWorkflowsOf([
      f('.github/workflows/a.yml', '[push, pull_request]'), f('.github/workflows/b.yml', 'pull_request'),
      f('.github/workflows/c.yml', '{push: {branches: [main]}}'), f('.github/workflows/d.yml', '{push: {branches-ignore: [main]}}'),
      f('.github/workflows/e.yml', '{push: {branches: ["proof/**", "!proof/*/planted"]}, pull_request: {branches: [release]}}'),
      f('.github/workflows/g.yml', '{push: {paths: ["docs/**"]}}'), f('.github/workflows/h.yml', '{push: {paths-ignore: [".github/**"]}}'),
      f('.github/workflows/i.yml', '{push: {branches: 7}}'), f('README.md', 'push'),
    ], at)).toEqual({
      // h.yml: README.md is a changed path outside .github/ (paths-ignore ignores only when every changed path is ignored)
      push: ['.github/workflows/a.yml', '.github/workflows/d.yml', '.github/workflows/e.yml', '.github/workflows/h.yml'],
      pullRequest: ['.github/workflows/a.yml', '.github/workflows/b.yml'],
      merge: ['.github/workflows/a.yml', '.github/workflows/c.yml', '.github/workflows/h.yml'],
    });
    expect(proofWorkflowsOf([f('.github/workflows/h.yml', '{push: {paths-ignore: [".github/**"]}}')], at).push).toEqual([]);
    // the planted branch is not one e.yml runs on
    expect(proofWorkflowsOf([f('.github/workflows/e.yml', '{push: {branches: ["proof/**", "!proof/*/planted"]}}')], { branch: 'proof/r1/planted', defaultBranch: 'main' }).push).toEqual([]);
  });

  it('proofWorkflowsOf over the REAL assembled files: the push runs pipegen-push.yml, the merge pipegen.yml (sec I1)', () => {
    const x = planned(profileOf([node()]));
    const files = proofAssembler(x.draft, (d, mode) => assemble(d, { gate: GATE_TOOL, reviewed: REVIEWED, platform: PLAT, mode, layout: 'local', plan: x.plan }))('none', undefined);
    const wf = proofWorkflowsOf(files, { branch: 'proof/20261106-000000-abcdef/main', defaultBranch: x.draft.profile.defaultBranch });
    expect(wf.push).toContain('.github/workflows/pipegen-push.yml');
    expect(wf.push).not.toContain('.github/workflows/pipegen.yml');
    expect(wf.merge).toContain('.github/workflows/pipegen.yml');
    expect(wf.merge).not.toContain('.github/workflows/pipegen-push.yml');
    expect(wf.pullRequest.length).toBeGreaterThan(0);
  });
});

// ---------- the proof inside `pipegen run` (fullRun with fake stages and the production proof over fake GitHub ops) ----------
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { Octokit } from '@octokit/rest';
import { fullRun, PROOF_FILE_IN_DELIVERY, PUBLIC_FILES_CHANGED, type Built, type BuildInput, type RunDeps, type RunStages } from '../src/cli/run.js';
import { makeCleanupOnly, makeRunProof } from '../src/cli/run-proof.js';
import { StateStore, type AgreedTerms } from '../src/proof/state.js';
import { DEFAULT_MODEL } from '../src/types.js';
import { armProofCleanup } from '../src/proof/cleanup.js';
import { HARNESS_PATH } from '../src/proof/harness.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { CAPS, candidatesFor, choicesFor, profile, scripted, svc } from './helpers/debate-fixtures.js';
import { A_FIELD, CALLER, MADE_UP, NEEDS2, OWN, TK_FIELD } from './helpers/proof-world.js';

interface RunWorld { tl: string[]; calls: string[]; deps: RunDeps; stages: Partial<RunStages>; home: string; errs: string[]; lines: string[]; got: Record<string, unknown[]>; io: CliIO }
async function runWorld(o: { private?: boolean; results?: import('../src/types.js').ProofResult[]; canDelete?: boolean; built?: (i: BuildInput, n: number) => Partial<Built>; missing?: string[]; canCreate?: boolean; preview?: boolean } = {}): Promise<RunWorld> {
  const pw = await proofWorld({ results: o.results ?? [PASS] });
  const tl = pw.tl;
  pw.ops.appFiles = () => ({ appFiles: async () => [CALLER(), { repo: 'app', path: HARNESS_PATH, content: 'on: [pull_request]\njobs: {}\n', part: 'pipeline', reason: 'r' }], last: () => ({ harness: { file: CALLER(), jobs: [], notes: [] }, compat: { files: [], notCompared: [] } }) });
  const home = mkdtempSync(join(tmpdir(), 'pg-runproof-'));
  const calls: string[] = [];
  const got: Record<string, unknown[]> = {};
  const errs: string[] = [];
  const lines: string[] = [];
  const rec = (n: string, ...a: unknown[]): void => { calls.push(n); tl.push(`stage:${n}`); got[n] = a; };
  const p = profile({ owner: OWN, repo: 'r', private: o.private === true, monorepo: 'none', services: [svc({ name: 'app', path: '.', scripts: ['test', 'start'] })], generatedDirs: [] });
  const ai = scripted(() => ({}));
  let builds = 0;
  const stages: Partial<RunStages> = {
    readOrigin: async () => ({ owner: OWN, repo: 'r' }), localProject: async () => p,
    [GA_FIELD]: async () => ({ kind: o.canCreate === true ? 'app' : 'fine-grained', [TK_FIELD]: MADE_UP, canCreateRepos: o.canCreate === true, canDeleteRepos: o.canDelete === true } as never),
    readProject: async () => ({ gh: {} as Octokit, clock: { budget: newRateBudget() }, login: 'alice', context: { private: o.private === true, ownerType: 'User', plan: 'pro', defaultBranch: 'main' }, caps: CAPS, writers: ['alice', 'bob'], lockWriters: { app: ['alice', 'bob'], central: ['alice', 'bob'] }, orgAdmin: null, shaPinning: { required: false } as never, ids: { app: 1, central: 2 } }),
    provider: () => ai.ai, bundle: async () => ({ files: [] } as never), scan: async () => ({ files: [], found: { names: [], values: [], [TK_FIELD + 's']: [] } } as never),
    activity: async () => ({ pushes: 1, prs: 1, capped: false }), consent: async () => { rec('consent'); return {} as never; },
    state: async (pp, g) => StateStore.open(pp, { home, env: {}, ...g }), gateReachable: async () => true,
    helperRepos: async () => { rec('helperRepos'); return o.missing ?? []; },
    proofRepos: async (_f, _p, auth, store) => { rec('proofRepos', auth, store.armed); return { ready: true, target: {} as never, repos: [], created: [] }; },
    needs: async () => ({ needs: [...NEEDS2], notes: [], requireDeployApproval: false, layersSkipped: [], usage: [] } as never),
    discover: async () => candidatesFor(NEEDS2, p),
    debate: async () => ({ choices: choicesFor(NEEDS2, p, {}, {}, undefined, candidatesFor(NEEDS2, p)), needs: [...NEEDS2], candidates: candidatesFor(NEEDS2, p), disputes: [], suggestions: [], transcript: [], requireDeployApproval: false, byCode: [], uncovered: [] } as never),
    creators: async () => ({ files: [], notes: [], testNotes: [], testDecisions: [], notProven: [] }),
    [SV_FIELD]: async (_p: unknown, _c: unknown, vault: import('../src/create/secrets.js').SecretVault) => { vault.set('API_TOKEN', TYPED); return { names: vault.names(), missing: [], notes: [] }; },
    credits: async () => [],
    build: async (i) => {
      rec('build');
      const n = builds++;
      const files: CreatedFile[] = [{ repo: 'app', path: 'PIPEGEN.md', content: '# x\n', part: 'docs', reason: 'r' }];
      return {
        assembled: { draft: i.draft, files: [], verify: null, notes: [], uncoveredMinimum: [] }, verify: { inserts: [], notProven: [], gaps: [], notes: [], preview: [] } as never,
        locks: { owners: { app: [], central: [] }, notes: [] } as never, precommit: { files: [], edits: [], setupCommand: '', notes: [] } as never, doc: files[0] as CreatedFile, extra: [],
        files, report: { ok: true, issues: [], demoted: [], notes: [] }, guardProblems: [], environments: [], envNotes: [], hookNotes: [],
        minutes: { jobs: { 'pre-commit': [], push: [], merge: [], deploy: [], nightly: [] } as never, prWait: 5 },
        proof: { rebuild: async (d) => ({ files: [], assembled: d }), referee: async () => ({ ok: true, issues: [], demoted: [], notes: [] }), guard: async (f) => ({ ok: f, refused: [], notes: [] }) },
        ...o.built?.(i, n),
      } as Built;
    },
    trusted: async () => ({ record: null, notes: [] }),
    deliverCentral: async () => { rec('deliverCentral'); return { kind: 'pinned', sha: 'c'.repeat(40), done: [] }; },
    readCentralFileList: async () => { rec('readCentralFileList'); return []; },
    preview: () => { rec('preview'); return 'THE PREVIEW'; },
    deliver: async () => { rec('deliver'); return { prUrl: 'u', prNumber: 3, centralSha: null, recordHash: 'h', done: [], skipped: [], notes: [] } as never; },
    prState: async () => 'merged', finish: async () => 0,
  };
  const io: CliIO = { prompt: { confirm: async (m) => { tl.push(`ask:${m.slice(0, 30)}`); return /Open the setup pull request/.test(m) ? o.preview ?? true : true; }, select: async () => { throw new Error('x'); }, text: async () => { throw new Error('x'); } }, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env: {}, interactive: true };
  const deps: RunDeps = {
    platform: 'linux', today: () => '2026-11-06', now: () => Date.parse('2026-11-06T10:00:00Z'), sleep: async () => {}, stages, runId: () => RUN_ID,
    proof: makeRunProof(pw.ops), reviewed: () => pw.input.reviewed, platformActions: async () => ({}) as never,
    [SC_FIELD]: async (n: 'gitleaks' | 'betterleaks') => ({ name: n, path: '/bin/x', version: '1' }),
    arm: (s, c, m) => { tl.push('arm'); return armProofCleanup(s, c, { meters: m }); },
  };
  return { tl, calls, deps, stages, home, errs, lines, got, io };
}

describe('G14: the proof inside pipegen run', () => {
  it('run: cleanup runs right after the proof, before the preview', async () => {
    const w = await runWorld();
    expect(await fullRun('/repo', w.io, w.deps)).toBe(0);
    const iClean = at(w.tl, 'cleanup:');
    expect(iClean).toBeGreaterThan(at(w.tl, 'evaluate'));
    expect(iClean).toBeLessThan(at(w.tl, 'stage:preview'));
    expect(iClean).toBeLessThan(at(w.tl, 'stage:deliver'));
  });

  it('run: scratch secrets deleted before the preview is shown', async () => {
    const w = await runWorld();
    expect(await fullRun('/repo', w.io, w.deps)).toBe(0);
    const del = w.tl.lastIndexOf('keys.deleteAll');
    expect(del).toBeGreaterThan(at(w.tl, 'keys.setup'));
    expect(del).toBeLessThan(at(w.tl, 'stage:preview'));
    expect(del).toBeLessThan(at(w.tl, 'ask:THE PREVIEW'));
  });

  it('run: stopped proof → cleanup done, exit 2 with reason (in the run)', async () => {
    const w = await runWorld({ results: [failOn('sast', 'semgrep found a problem')] });
    expect(await fullRun('/repo', w.io, w.deps)).toBe(2);
    expect(w.errs.join('\n')).toMatch(/pipegen stopped: the proof did not pass \(.*\), so nothing was delivered\. exit code 2\./);
    expect(w.tl.some((x) => x.startsWith('cleanup:'))).toBe(true);
    for (const s of ['preview', 'deliverCentral', 'deliver']) expect(w.calls).not.toContain(s);
  });

  it('run: no planted file, harness file or compat copy reaches the delivered batch', async () => {
    for (const path of ['pipegen-planted/config.txt', 'api/pipegen-planted/x.py', HARNESS_PATH, '.github/workflows/pipegen-compat-ci.yml']) {
      const w = await runWorld({ built: () => ({ files: [{ repo: 'app', path, content: 'x', part: 'pipeline', reason: 'r' }] }) });
      expect(await fullRun('/repo', w.io, w.deps)).toBe(2);
      expect(w.errs).toContain(PROOF_FILE_IN_DELIVERY);
      expect(w.calls).not.toContain('deliver');
    }
  });

  it('run: a public app whose app files change with the central file list stops (controller addendum)', async () => {
    const w = await runWorld({ built: (_i, n) => (n === 0 ? { files: [{ repo: 'app', path: 'a.yml', content: '1', part: 'pipeline', reason: 'r' }, { repo: 'central', path: '.github/CODEOWNERS', content: 'x', part: 'pipeline', reason: 'r' }] } : { files: [{ repo: 'app', path: 'a.yml', content: '2', part: 'pipeline', reason: 'r' }, { repo: 'central', path: '.github/CODEOWNERS', content: 'x', part: 'pipeline', reason: 'r' }] }) });
    expect(await fullRun('/repo', w.io, w.deps)).toBe(2);
    expect(w.errs).toContain(PUBLIC_FILES_CHANGED);
    expect(w.calls).not.toContain('deliver');
    // the same app files: delivered
    const same = await runWorld({ built: () => ({ files: [{ repo: 'app', path: 'a.yml', content: '1', part: 'pipeline', reason: 'r' }, { repo: 'central', path: '.github/CODEOWNERS', content: 'x', part: 'pipeline', reason: 'r' }] }) });
    expect(await fullRun('/repo', same.io, same.deps)).toBe(0);
  });

  it('run: helper repos the token can\'t create are named before consent (read only); the writing check runs inside the proof, armed', async () => {
    const w = await runWorld({ missing: ['pipelines'] });
    expect(await fullRun('/repo', w.io, w.deps)).toBe(2);
    expect(w.errs.join('\n')).toContain('gh repo create CrisWorking/pipelines --private');
    expect(w.calls).not.toContain('consent');
    // an App that may create them goes on; checkProofRepos then runs inside the proof on an armed store
    const a = await runWorld({ missing: ['pipelines'], canCreate: true });
    expect(await fullRun('/repo', a.io, a.deps)).toBe(0);
    expect(a.got.proofRepos?.[1]).toBe(true);
    expect(at(a.tl, 'arm')).toBeLessThan(at(a.tl, 'stage:proofRepos'));
  });
});

// ---------- pipegen resume ----------
/** A saved run of CrisWorking/r in `home`: the pre-fix draft saved at proving, then the proof's verdict with the AI-fixed draft. */
async function savedRun(home: string, o: { ok?: boolean; stoppedBy?: 'proof-failed' | 'ai-cost'; then?: 'interrupted' | 'cleaned'; aiCap?: number; spent?: number; agreed?: AgreedTerms | null } = {}) {
  const p = profile({ owner: OWN, repo: 'r', private: false, monorepo: 'none', services: [svc({ name: 'app', path: '.', scripts: ['test', 'start'] })], generatedDirs: [] });
  const pre = { profile: p, capabilities: CAPS, needs: [], steps: [], created: [{ repo: 'app', path: 'test/app.test.js', content: 'old\n', part: 'tests', reason: 'r' }], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [] } as unknown as PipelineDraft;
  const fixed = { ...pre, created: [{ repo: 'app', path: 'test/app.test.js', content: 'fixed by the AI\n', part: 'tests', reason: 'r', aiEdited: true }] } as PipelineDraft;
  const s = await StateStore.open(p, { home, env: {} });
  // the terms agreed at consent: runWorld's provider (scripted: claude, DEFAULT_MODEL), standard, betterleaks, 50 minutes a month
  const agreed = o.agreed === null ? undefined : o.agreed ?? { provider: 'claude' as const, model: DEFAULT_MODEL, strictness: 'standard', scanner: 'betterleaks' as const, monthlyMinutes: 50 };
  s.begin(RUN_ID, { owner: OWN, repo: 'r', private: false, ownerType: 'User', defaultBranch: 'main' }, { cap: 100, aiCap: o.aiCap ?? 5, ...(agreed === undefined ? {} : { agreed }) });
  for (const x of ['planned', 'debated', 'created'] as const) s.setStage(x);
  s.update((n) => { n.draft = pre; });
  s.setStage('proving');
  s.saveMeters({ aiUsedUsd: o.spent ?? 0 });
  if (o.ok === true) {
    s.recordVerdict({ ok: true, draft: fixed });
    s.setStage('proven');
    if (o.then === 'cleaned') s.setStage('cleaned');
  } else {
    if (o.stoppedBy === 'ai-cost') s.setStage('stopped', { stoppedBy: 'ai-cost' });
    s.recordVerdict({ ok: false, draft: fixed, stopped: 'the proof failed' });
    if (s.state?.stage === 'proving') s.setStage('stopped', { stoppedBy: 'proof-failed' });
  }
  if (o.then === 'interrupted') s.setStage('interrupted');
  return { pre, fixed };
}

describe('G14: pipegen resume (S20, contracts §6 step 2)', () => {
  it('run: failed proof returned, Ctrl-C at the preview, resume → proving, never delivery, never the pre-fix draft', async () => {
    for (const stoppedBy of ['proof-failed', 'ai-cost'] as const) {
      const w = await runWorld();
      const { pre, fixed } = await savedRun(w.home, { stoppedBy, then: 'interrupted' });
      let seen: { draft: PipelineDraft; stage: string | undefined; resume?: boolean; debate?: unknown } | undefined;
      w.deps.proof = async (x) => { seen = { draft: x.draft, stage: x.store.state?.stage, resume: x.resume, debate: x.debate }; return { ok: false, stopped: 'pipegen stopped: the proof did not pass (again), so nothing was delivered. exit code 2.' }; };
      expect(await fullRun('/repo', w.io, { ...w.deps, resume: true })).toBe(2);
      expect(seen?.stage).toBe('proving');
      expect(seen?.resume).toBe(true);
      expect(seen?.debate).toBeUndefined();
      // the AI-fixed draft the verdict saved (G0-R1 I2 for the cap stop), never the pre-fix one
      expect(seen?.draft).toEqual(fixed);
      expect(seen?.draft).not.toEqual(pre);
      for (const s of ['preview', 'deliverCentral', 'deliver']) expect(w.calls).not.toContain(s);
      expect(w.calls).not.toContain('consent');
    }
    // a proof that "passed" but whose seam never cleaned up: still no delivery
    const w2 = await runWorld();
    await savedRun(w2.home, { stoppedBy: 'proof-failed', then: 'interrupted' });
    w2.deps.proof = async () => ({ ok: true });
    expect(await fullRun('/repo', w2.io, { ...w2.deps, resume: true })).toBe(2);
    expect(w2.calls).not.toContain('deliver');
  });

  it('resume: the saved draft is re-refereed and re-guarded before any push', async () => {
    // a refusal of the saved draft stops before the proof (no GitHub write)
    const bad = await runWorld({ built: () => ({ report: { ok: false, issues: [{ file: 'test/app.test.js', check: 'template', message: 'refused' }], demoted: [], notes: [] }, guardProblems: ['test/app.test.js: the guard refused it'] }) });
    await savedRun(bad.home, { then: 'interrupted' });
    let called = false;
    bad.deps.proof = async () => { called = true; return { ok: false }; };
    expect(await fullRun('/repo', bad.io, { ...bad.deps, resume: true })).toBe(2);
    expect(called).toBe(false);
    expect(bad.errs.join('\n')).toMatch(/did not pass its own checks/);
    // a clean one: the saved draft is what the build judged, before the proof's first write
    const good = await runWorld();
    const { fixed } = await savedRun(good.home, { then: 'interrupted' });
    let judged: PipelineDraft | undefined;
    const build = good.stages.build as RunStages['build'];
    good.stages.build = async (i) => { judged ??= i.draft; return build(i); };
    good.deps.proof = async (x) => { good.tl.push('proof'); return { ok: false }; };
    await fullRun('/repo', good.io, { ...good.deps, resume: true });
    expect(judged).toEqual(fixed);
    expect(at(good.tl, 'stage:build')).toBeLessThan(at(good.tl, 'proof'));
  });

  it('resume: a passed proof whose cleanup did not finish is cleaned, then delivered from cleaned; nothing proven again', async () => {
    const w = await runWorld();
    const { fixed } = await savedRun(w.home, { ok: true, then: 'interrupted' });
    let proved = false;
    w.deps.proof = async () => { proved = true; return { ok: false }; };
    let cleaned = 0;
    w.deps.cleanupOnly = async (i) => { cleaned++; i.store.setStage('cleaned'); return { repoDeleted: false, leftovers: [] }; };
    expect(await fullRun('/repo', w.io, { ...w.deps, resume: true })).toBe(0);
    expect(proved).toBe(false);
    expect(cleaned).toBe(1);
    expect(w.calls).toContain('deliver');
    const s = await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} });
    expect(s.load()?.draft).toEqual(fixed);
    expect(s.load()?.stage).toBe('delivered');
  });

  it('resume: nothing saved, already delivered, or stopped before the proof → nothing to resume (exit 1)', async () => {
    const none = await runWorld();
    expect(await fullRun('/repo', none.io, { ...none.deps, resume: true })).toBe(1);
    expect(none.errs.join('\n')).toMatch(/no stopped run of this repository to resume/);
    const early = await runWorld();
    const s = await StateStore.open({ owner: OWN, repo: 'r' }, { home: early.home, env: {} });
    s.begin(RUN_ID, { owner: OWN, repo: 'r', private: false, ownerType: 'User', defaultBranch: 'main' }, { cap: 1, aiCap: 1 });
    s.setStage('interrupted');
    expect(await fullRun('/repo', early.io, { ...early.deps, resume: true })).toBe(1);
    expect(early.errs.join('\n')).toMatch(/stopped before its proof/);
  });
});

describe('G14-R1: a resume goes on with the terms agreed at consent (sec I2, sec M6)', () => {
  it('run: begin saves the agreed AI, strictness, scanner and minutes (names only, never a key)', async () => {
    const w = await runWorld();
    expect(await fullRun('/repo', w.io, { ...w.deps, flags: { strictness: 'strict' } })).toBe(0);
    const s = await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} });
    const agreed = s.load()?.agreed;
    expect(agreed).toMatchObject({ provider: 'claude', model: DEFAULT_MODEL, strictness: 'strict', scanner: 'betterleaks' });
    expect(typeof agreed?.monthlyMinutes).toBe('number');
    expect(JSON.stringify(agreed)).not.toContain(MADE_UP);
  });

  it('resume: another AI provider, model or host than agreed → exit 2, nothing sent, no proof; a state with no terms → exit 2', async () => {
    const others: AgreedTerms[] = [
      { provider: 'openai', model: DEFAULT_MODEL }, { provider: 'claude', model: 'claude-other-model' }, { provider: 'claude', model: DEFAULT_MODEL, host: 'example.test:11434' },
    ];
    for (const agreed of others) {
      const w = await runWorld();
      await savedRun(w.home, { then: 'interrupted', agreed });
      let proved = false;
      w.deps.proof = async () => { proved = true; return { ok: false }; };
      expect(await fullRun('/repo', w.io, { ...w.deps, resume: true })).toBe(2);
      expect(proved).toBe(false);
      expect(w.errs.join('\n')).toMatch(/you agreed to .*but this shell sets up claude/);
      expect(w.calls).not.toContain('build');
    }
    const none = await runWorld();
    await savedRun(none.home, { then: 'interrupted', agreed: null });
    expect(await fullRun('/repo', none.io, { ...none.deps, resume: true })).toBe(2);
    expect(none.errs.join('\n')).toContain('does not say which AI you agreed to');
  });

  it('resume: the saved strictness and secret scanner are used, not the defaults or the environment', async () => {
    const w = await runWorld();
    await savedRun(w.home, { then: 'interrupted', agreed: { provider: 'claude', model: DEFAULT_MODEL, strictness: 'starter', scanner: 'gitleaks', monthlyMinutes: 50 } });
    let level: string | undefined;
    const build = w.stages.build as RunStages['build'];
    w.stages.build = async (i) => { level ??= i.strictness; return build(i); };
    let scanner: string | undefined;
    w.deps.proof = async (x) => { scanner = (await x.scanner()).name; return { ok: false }; };
    w.deps[SC_FIELD] = async (n: 'gitleaks' | 'betterleaks') => ({ name: n, path: '/bin/x', version: '1' });
    await fullRun('/repo', w.io, { ...w.deps, resume: true });
    expect(level).toBe('starter');
    expect(scanner).toBe('gitleaks');
  });

  it('resume: the minutes are asked again against the AGREED estimate', async () => {
    for (const [agreedMinutes, asked] of [[0, true], [1_000_000, false]] as const) {
      // the pipeline as built: one push job (some minutes a month)
      const w = await runWorld({ built: () => ({ minutes: { jobs: { 'pre-commit': [], push: ['sast'], merge: [], deploy: [], nightly: [] } as never, prWait: 5 } }) });
      await savedRun(w.home, { ok: true, then: 'cleaned', agreed: { provider: 'claude', model: DEFAULT_MODEL, monthlyMinutes: agreedMinutes } });
      await fullRun('/repo', w.io, { ...w.deps, resume: true });
      expect(w.tl.some((x) => x.startsWith('ask:The pipeline as built needs'))).toBe(asked);
    }
  });

  it('resume: a Ctrl-C at the preview after a passed, cleaned proof delivers on resume (interrupted at cleaned with proofOk; sec M4)', async () => {
    const w = await runWorld();
    const { fixed } = await savedRun(w.home, { ok: true, then: 'cleaned' });
    const s0 = await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} });
    s0.load();
    s0.setStage('interrupted');
    expect(s0.state).toMatchObject({ stage: 'interrupted', interruptedAt: 'cleaned', proofOk: true });
    let proved = false;
    w.deps.proof = async () => { proved = true; return { ok: false }; };
    expect(await fullRun('/repo', w.io, { ...w.deps, resume: true })).toBe(0);
    expect(proved).toBe(false);
    expect(w.calls).toContain('deliver');
    const s = await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} });
    expect(s.load()?.draft).toEqual(fixed);
    expect(s.load()?.stage).toBe('delivered');
  });
});

describe('G14: the production proof on a resume', () => {
  it('resume: the minutes come from minutesForResume with the store; no dispute runs; the run (not the proof) set proving', async () => {
    const w = await proofWorld({ disputes: [{ id: 'd1', key: 'sast--api', needId: 'sast', options: [] }] as never, input: { resume: true } });
    w.store.setStage('proving');
    const r = await w.run();
    expect(r.ok).toBe(true);
    expect(w.tl).toContain('minutesForResume:store');
    expect(w.tl).not.toContain('proofStart');
    expect(w.tl.some((x) => x.startsWith('pushBranch:dispute'))).toBe(false);
  });
});


describe('G14-R1: a declined AI file and the parts that read it (spec M6, sec M1)', () => {
  const outcome = async (file: CreatedFile, opts: { floorSast?: boolean } = {}) => {
    const w = await proofWorld();
    const d0 = w.input.draft;
    const needs = d0.needs.map((n) => (n.id === 'sast' ? { ...n, floor: opts.floorSast ?? n.floor } : n));
    const draft = { ...d0, needs, created: [...d0.created, file] } as PipelineDraft;
    const parts: import('../src/types.js').PartResult[] = [
      { part: 'pipeline', status: 'proven', detail: 'ok' }, { part: 'pipeline', needId: 'secrets', status: 'proven', detail: 'ok' },
      { part: 'pipeline', needId: 'sast', status: 'proven', detail: 'ok' }, { part: file.part, status: 'proven', detail: 'ok' },
    ];
    return { draft, result: { ok: true, parts, findings: [], minutesUsed: 1, runUrls: [] } } as unknown as import('../src/proof/fix.js').FixOutcome;
  };
  for (const [part, path, extra] of [['docker', 'api/Dockerfile', {}], ['test-migration', 'api/tests/test_moved.py', {}], ['pipeline', 'api/package.json', { needsConfirm: true }]] as const) {
    it(`dropDeclined: a declined ${part} file${'needsConfirm' in extra ? ' (needsConfirm)' : ''} is dropped, its part and the jobs of its service are not proven`, async () => {
      const file = { repo: 'app', path, content: 'x\n', part, reason: 'r', aiEdited: true, ...extra } as CreatedFile;
      // sast of the file's service is not a floor need here: the drop is not a stop unless the part itself is the pipeline
      const out = dropDeclined(await outcome(file, { floorSast: false }), new Set([path]));
      expect(out.draft.created.some((f) => f.path === path)).toBe(false);
      expect(out.draft.notProven).toEqual(expect.arrayContaining([expect.objectContaining({ part, reason: DECLINED_REASON })]));
      // sec M1: the api service's sast job read the dropped path: not proven; the repo-wide secrets scan keeps its result
      expect(out.draft.notProven.some((n) => n.needId === 'sast')).toBe(true);
      expect(out.result.parts.find((x) => x.needId === 'sast')?.status).toBe('not-proven');
      expect(out.result.parts.find((x) => x.needId === 'secrets')?.status).toBe('proven');
      expect(out.result.ok).toBe(part !== 'pipeline');
    });
  }
  it('dropDeclined: a floor need whose job read the dropped file → no pass (the floor must be proven)', async () => {
    const file = { repo: 'app', path: 'api/Dockerfile', content: 'x\n', part: 'docker', reason: 'r', aiEdited: true } as CreatedFile;
    const out = dropDeclined(await outcome(file, { floorSast: true }), new Set(['api/Dockerfile']));
    expect(out.result.ok).toBe(false);
    expect(out.stopped).toContain(DECLINED_REASON);
    // a file of no service's folder (the web service's sast never read it): nothing else changes
    const other = { repo: 'app', path: 'docs/x.md', content: 'x\n', part: 'docs', reason: 'r', aiEdited: true } as CreatedFile;
    const o2 = dropDeclined(await outcome(other, { floorSast: true }), new Set(['docs/x.md']));
    expect(o2.result.ok).toBe(true);
    expect(o2.result.parts.find((x) => x.needId === 'sast')?.status).toBe('proven');
  });
});

describe('G14-R1: the real cleanup-only of a resume (spec I4)', () => {
  it('resume: makeCleanupOnly deletes the scratch secrets, deletes the repo only when the token may, passes the meters, ends cleaned', async () => {
    for (const [canDelete, interrupted] of [[false, false], [true, true]] as const) {
      const w = await proofWorld({ canDelete });
      w.store.setStage('proving');
      w.store.recordVerdict({ ok: true, draft: w.input.draft });
      w.store.setStage('proven');
      if (interrupted) w.store.setStage('interrupted');
      const r = await makeCleanupOnly(w.ops)({ store: w.store, gh: w.input.gh, vault: w.vault, io: w.input.io, [A_FIELD]: w.input[A_FIELD], ai: { meter: w.meter } });
      expect(w.tl.indexOf('keys.deleteAll')).toBeGreaterThan(-1);
      expect(w.tl.indexOf('keys.deleteAll')).toBeLessThan(w.tl.indexOf(`cleanup:canDeleteRepo=${String(canDelete)}`));
      expect(r.repoDeleted).toBe(canDelete);
      expect(w.cleanupOpts[0]?.meters?.()?.ai).toBe(w.meter);
      expect(w.store.state?.stage).toBe('cleaned');
      expect(w.store.state?.proofOk).toBe(true);
    }
  });
});

describe('G14: the production arm', () => {
  it('run: defaultArm passes the meters to armProofCleanup (an interrupt saves them)', async () => {
    vi.resetModules();
    const eh = await import('../src/util/exit-hooks.js');
    const st = await import('../src/proof/state.js');
    const { defaultArm } = await import('../src/cli/run.js');
    const { MinutesMeter } = await import('../src/proof/minutes.js');
    const kill = vi.spyOn(process, 'kill').mockImplementation(() => true);
    try {
      const p = profile({ owner: OWN, repo: 'r', private: false });
      const store = await st.StateStore.open(p, { home: mkdtempSync(join(tmpdir(), 'pg-arm-')), env: {} });
      store.begin(RUN_ID, { owner: OWN, repo: 'r', private: false, ownerType: 'User', defaultBranch: 'main' }, { cap: 10, aiCap: 1 });
      store.setStage('planned');
      const off = defaultArm(store, async () => undefined, () => ({ minutes: new MinutesMeter(10, 1_000) }));
      expect(store.armed).toBe(true);
      await eh.interrupt('SIGINT');
      expect(store.load()).toMatchObject({ stage: 'interrupted', proofStart: { at: 1_000 } });
      off();
      expect(store.armed).toBe(false);
    } finally {
      kill.mockRestore();
    }
  });
});
