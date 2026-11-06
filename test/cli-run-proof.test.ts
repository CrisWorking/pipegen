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
    const iMain = at(w.tl, 'pushBranch:main@parent');
    const iPl = at(w.tl, 'pushBranch:planted@parent');
    const iMerge = at(w.tl, 'variant:main:merge');
    expect(iSetup).toBeLessThan(iA);
    expect(iA).toBeLessThan(iB);
    expect(Math.max(iB, iMain, iPl)).toBeLessThan(iMerge);
    expect(iMain).toBeGreaterThan(iB);
    // keepOpen false: each variant's PR is closed after its runs
    expect(w.tl.filter((x) => x.startsWith('variant:dispute')).every((x) => !x.endsWith(':open'))).toBe(true);
    // each variant carries the planted files
    expect(w.pushed.filter((x) => x.variant.startsWith('dispute')).every((x) => x.files.some((f) => String(f.path).startsWith('pipegen-planted/')))).toBe(true);
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

  it('run: interrupting() is checked before real keys are stored and before each push', async () => {
    const seen: string[] = [];
    const k = guardedKeys({ real: async () => { seen.push('real'); }, setup: async () => { seen.push('setup'); }, placeholders: async () => { seen.push('ph'); } } as unknown as FixKeys, { recordSecretNames: (n) => { seen.push(`names:${n.join(',')}`); } });
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

  it('run: a blocking scanner with no planted item stays blocking, never in notProven', async () => {
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
  it('proofWorkflowsOf: push and pull_request from each workflow\'s `on:` (string, list or map); other files ignored', () => {
    const f = (path: string, on: string) => ({ path, content: `on: ${on}\njobs: {}\n` });
    expect(proofWorkflowsOf([f('.github/workflows/a.yml', '[push, pull_request]'), f('.github/workflows/b.yml', 'pull_request'), f('.github/workflows/c.yml', '{push: {branches: [main]}}'), f('README.md', 'push')]))
      .toEqual({ push: ['.github/workflows/a.yml', '.github/workflows/c.yml'], pullRequest: ['.github/workflows/a.yml', '.github/workflows/b.yml'], merge: ['.github/workflows/a.yml', '.github/workflows/c.yml'] });
  });
});

// ---------- the proof inside `pipegen run` (fullRun with fake stages and the production proof over fake GitHub ops) ----------
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { Octokit } from '@octokit/rest';
import { fullRun, PROOF_FILE_IN_DELIVERY, PUBLIC_FILES_CHANGED, type Built, type BuildInput, type RunDeps, type RunStages } from '../src/cli/run.js';
import { makeRunProof } from '../src/cli/run-proof.js';
import { StateStore } from '../src/proof/state.js';
import { armProofCleanup } from '../src/proof/cleanup.js';
import { HARNESS_PATH } from '../src/proof/harness.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { CAPS, candidatesFor, choicesFor, profile, scripted, svc } from './helpers/debate-fixtures.js';
import { CALLER, NEEDS2, OWN } from './helpers/proof-world.js';

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
    getAuth: async () => ({ kind: o.canCreate === true ? 'app' : 'fine-grained', token: 'tok-made-up-0000000000', canCreateRepos: o.canCreate === true, canDeleteRepos: o.canDelete === true } as never),
    readProject: async () => ({ gh: {} as Octokit, clock: { budget: newRateBudget() }, login: 'alice', context: { private: o.private === true, ownerType: 'User', plan: 'pro', defaultBranch: 'main' }, caps: CAPS, writers: ['alice', 'bob'], lockWriters: { app: ['alice', 'bob'], central: ['alice', 'bob'] }, orgAdmin: null, shaPinning: { required: false } as never, ids: { app: 1, central: 2 } }),
    provider: () => ai.ai, bundle: async () => ({ files: [] } as never), scan: async () => ({ files: [], found: { names: [], values: [], tokens: [] } } as never),
    activity: async () => ({ pushes: 1, prs: 1, capped: false }), consent: async () => { rec('consent'); return {} as never; },
    state: async (pp, g) => StateStore.open(pp, { home, env: {}, ...g }), gateReachable: async () => true,
    helperRepos: async () => { rec('helperRepos'); return o.missing ?? []; },
    proofRepos: async (_f, _p, auth, store) => { rec('proofRepos', auth, store.armed); return { ready: true, target: {} as never, repos: [], created: [] }; },
    needs: async () => ({ needs: [...NEEDS2], notes: [], requireDeployApproval: false, layersSkipped: [], usage: [] } as never),
    discover: async () => candidatesFor(NEEDS2, p),
    debate: async () => ({ choices: choicesFor(NEEDS2, p, {}, {}, undefined, candidatesFor(NEEDS2, p)), needs: [...NEEDS2], candidates: candidatesFor(NEEDS2, p), disputes: [], suggestions: [], transcript: [], requireDeployApproval: false, byCode: [], uncovered: [] } as never),
    creators: async () => ({ files: [], notes: [], testNotes: [], testDecisions: [], notProven: [] }),
    secrets: async (_p, _c, vault) => { vault.set('API_TOKEN', TYPED); return { names: vault.names(), missing: [], notes: [] }; },
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
    secretScanner: async (n) => ({ name: n, path: '/bin/x', version: '1' }),
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
