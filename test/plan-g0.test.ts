// v0.2 Plan G sub-task G0: the proof and debate MUSTs the Plan E and Plan F final reviews left for Plan G's first touch of
// src/proof and src/debate (rulings S4, B8; carries E-F2 m1/m3, E-a8, F-1, F-2, F-3, F-12). No network.
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { proveThenClean, type CleanupResult } from '../src/proof/cleanup.js';
import { nextStage, StateError, StateStore } from '../src/proof/state.js';
import type { CreatedFile, PipelineDraft } from '../src/types.js';
import { draftOf } from './helpers/proof-eval.js';
import { app } from './helpers/scratch-secrets.js';

const ROOT = resolve(import.meta.dirname, '..');
const RUN = '20261105-090000-abc123';
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const home = (): string => { const d = mkdtempSync(join(tmpdir(), 'pg-g0-')); dirs.push(d); return d; };

const file = (path: string, content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path, content, part: 'docker', repo: 'app', reason: 'r', ...over });
const PRE_FIX: PipelineDraft = draftOf({ created: [file('api/Dockerfile', 'FROM node:24\nEXPOSE 3000\n')] });
const FIXED: PipelineDraft = draftOf({ created: [file('api/Dockerfile', 'FROM node:24\nEXPOSE 8080\n', { aiEdited: true })] });
const OTHER: PipelineDraft = draftOf({ created: [file('api/Dockerfile', 'FROM node:24\nEXPOSE 9999\n')] });
const cleaned = async (): Promise<CleanupResult> => ({ repoDeleted: true, leftovers: [] });

async function at(stage: 'consented' | 'planned' | 'debated' | 'created' | 'proving'): Promise<StateStore> {
  const store = await StateStore.open(app(), { home: home(), env: {} });
  store.begin(RUN, app(), { cap: 100, aiCap: 1, draft: PRE_FIX });
  for (const s of ['planned', 'debated', 'created', 'proving'] as const) {
    if (store.state?.stage === stage) break;
    store.setStage(s);
  }
  store.markArmed(true);
  return store;
}

/** Every .ts file under src/, with its text. */
function srcFiles(): { path: string; text: string }[] {
  const out: { path: string; text: string }[] = [];
  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (p.endsWith('.ts')) out.push({ path: relative(ROOT, p).split('\\').join('/'), text: readFileSync(p, 'utf8') });
    }
  };
  walk(join(ROOT, 'src'));
  return out;
}
/** The code lines of a file (comment lines and trailing // comments dropped), with their 0-based line numbers. */
function codeLines(text: string): { n: number; code: string }[] {
  const out: { n: number; code: string }[] = [];
  let inBlock = false;
  text.split('\n').forEach((raw, n) => {
    let l = raw;
    if (inBlock) {
      const end = l.indexOf('*/');
      if (end < 0) return;
      l = l.slice(end + 2);
      inBlock = false;
    }
    l = l.replace(/\/\*.*?\*\//g, '');
    const open = l.indexOf('/*');
    if (open >= 0) { inBlock = true; l = l.slice(0, open); }
    l = l.replace(/(^|[^:'"`])\/\/.*$/, '$1');
    if (l.trim() !== '') out.push({ n, code: l });
  });
  return out;
}
/** The line span [start, end) of a top-level function in `text` (from its declaration to the first line that is just `}`). */
function functionSpan(text: string, decl: RegExp): [number, number] {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => decl.test(l));
  if (start < 0) throw new Error(`no ${decl} here`);
  const end = lines.findIndex((l, i) => i > start && l === '}');
  return [start, end < 0 ? lines.length : end + 1];
}
/** Every code use of `name` in src/ outside the allowed places (file + line span). */
function usesOutside(name: string, allowed: { file: string; span: [number, number] }[]): string[] {
  const re = new RegExp(`\\b${name}\\b`);
  const bad: string[] = [];
  for (const f of srcFiles()) {
    for (const { n, code } of codeLines(f.text)) {
      if (!re.test(code)) continue;
      if (allowed.some((a) => a.file === f.path && n >= a.span[0] && n < a.span[1])) continue;
      bad.push(`${f.path}:${n + 1}: ${code.trim()}`);
    }
  }
  return bad;
}
const textOf = (p: string): string => readFileSync(join(ROOT, p), 'utf8');

describe('G0 (E-F2 m1): who may record a proof verdict', () => {
  it('state: recordVerdict outside stage proving → refused', async () => {
    // at proving: accepted (the one place proveThenClean calls it)
    const ok = await at('proving');
    ok.recordVerdict({ ok: false, stopped: 'x', draft: FIXED });
    expect(ok.load()).toMatchObject({ stage: 'proving', proofOk: false });
    // before the proof: refused, nothing written
    for (const stage of ['consented', 'planned', 'debated', 'created'] as const) {
      const s = await at(stage);
      expect(s.state?.stage, stage).toBe(stage);
      expect(() => s.recordVerdict({ ok: true, draft: FIXED }), stage).toThrow(StateError);
      expect(s.load()?.proofOk, stage).toBeUndefined();
      expect(s.load()?.draft?.created, stage).toEqual(PRE_FIX.created);
    }
    // the review's probe c: after a passing proof reached cleaned, a new verdict with another draft is refused; the proven draft stays
    const done = await at('proving');
    await proveThenClean(done, async () => ({ draft: FIXED, result: { ok: true } }), cleaned);
    expect(done.load()).toMatchObject({ stage: 'cleaned', proofOk: true });
    expect(() => done.recordVerdict({ ok: true, draft: OTHER })).toThrow(StateError);
    expect(done.load()?.draft?.created).toEqual(FIXED.created);
    // stopped and interrupted: refused too (a failed verdict stays failed; a resume proves again)
    const stopped = await at('proving');
    stopped.setStage('stopped', { stoppedBy: 'proof-failed' });
    expect(() => stopped.recordVerdict({ ok: true, draft: OTHER })).toThrow(StateError);
    expect(nextStage(stopped.load()!)).toBe('proving');
    const interrupted = await at('proving');
    interrupted.setStage('interrupted');
    expect(() => interrupted.recordVerdict({ ok: true, draft: OTHER })).toThrow(StateError);
    expect(interrupted.load()?.proofOk).toBeUndefined();
    // the delivered stage: refused
    done.setStage('delivered');
    expect(() => done.recordVerdict({ ok: true, draft: OTHER })).toThrow(StateError);
  });

  it('source: only proveThenClean calls recordVerdict', () => {
    const state = textOf('src/proof/state.ts');
    const cleanup = textOf('src/proof/cleanup.ts');
    const def = state.split('\n').findIndex((l) => /^\s{2}recordVerdict\(v: /.test(l));
    expect(def).toBeGreaterThan(0);
    const bad = usesOutside('recordVerdict', [
      { file: 'src/proof/state.ts', span: [def, def + 1] },
      { file: 'src/proof/cleanup.ts', span: functionSpan(cleanup, /^export async function proveThenClean</) },
    ]);
    expect(bad).toEqual([]);
    // and it does call it there (the scan is not vacuous)
    const [s, e] = functionSpan(cleanup, /^export async function proveThenClean</);
    expect(cleanup.split('\n').slice(s, e).join('\n')).toMatch(/store\.recordVerdict\(/);
  });

  it('source: no Plan G code calls StateStore.markArmed', () => {
    const state = textOf('src/proof/state.ts');
    const cleanup = textOf('src/proof/cleanup.ts');
    const def = state.split('\n').findIndex((l) => /^\s{2}markArmed\(on: boolean\)/.test(l));
    expect(def).toBeGreaterThan(0);
    // armProofCleanup is the one way to arm (carry E-a8): anything else in src that names markArmed fails here
    const bad = usesOutside('markArmed', [
      { file: 'src/proof/state.ts', span: [def, def + 1] },
      { file: 'src/proof/cleanup.ts', span: functionSpan(cleanup, /^export function armProofCleanup\(/) },
    ]);
    expect(bad).toEqual([]);
    const [s, e] = functionSpan(cleanup, /^export function armProofCleanup\(/);
    expect(cleanup.split('\n').slice(s, e).join('\n')).toMatch(/store\.markArmed\(true\)/);
    // the scan sees a call written any other way too (bracket access is a code use of the name)
    expect(codeLines("  store['markArmed'](true);").length).toBe(1);
  });

  it('proveThenClean: a verdict reader can only make a result stricter, never pass a failed outcome', async () => {
    // the review's probe g: a reader that says ok over result.ok false → still stopped, never proven
    const failedOutcome = { draft: FIXED, result: { ok: false }, stopped: 'pipeline could not be proven' };
    const g = await at('proving');
    await proveThenClean(g, async () => failedOutcome, cleaned, () => ({ ok: true, draft: FIXED }));
    expect(g.load()).toMatchObject({ stage: 'stopped', stoppedBy: 'proof-failed', proofOk: false });
    expect(nextStage(g.load()!)).toBe('proving');
    // a reader over an outcome that is no FixOutcome at all: not a pass
    const h = await at('proving');
    await proveThenClean(h, async () => 'anything', cleaned, () => ({ ok: true, draft: FIXED }));
    expect(h.load()).toMatchObject({ stage: 'stopped', proofOk: false });
    // a capped or stopped outcome stays not a pass whatever the reader says
    for (const outcome of [
      { draft: FIXED, result: { ok: true }, cap: { kind: 'ai-cost' } },
      { draft: FIXED, result: { ok: true }, stopped: 'the fix loop reached its global cap' },
      { result: { ok: true } },
    ]) {
      const s = await at('proving');
      await proveThenClean(s, async () => outcome, cleaned, () => ({ ok: true, draft: FIXED }));
      expect(s.load()?.proofOk, JSON.stringify(outcome)).toBe(false);
      expect(s.load()?.stage, JSON.stringify(outcome)).toBe('stopped');
    }
    // a reader may not swap the draft a pass delivers: the FixOutcome's own final draft is the one saved
    const swap = await at('proving');
    await proveThenClean(swap, async () => ({ draft: FIXED, result: { ok: true } }), cleaned, () => ({ ok: true, draft: OTHER }));
    expect(swap.load()).toMatchObject({ stage: 'cleaned', proofOk: true });
    expect(swap.load()?.draft?.created).toEqual(FIXED.created);
    // stricter: a reader that says no over a passing outcome → not proven, with its reason
    const strict = await at('proving');
    await proveThenClean(strict, async () => ({ draft: FIXED, result: { ok: true } }), cleaned, () => ({ ok: false, stopped: 'a check of the caller failed' }));
    expect(strict.load()).toMatchObject({ stage: 'stopped', proofOk: false, proofStopped: 'a check of the caller failed' });
    // the default reader still passes a passing FixOutcome
    const plain = await at('proving');
    await proveThenClean(plain, async () => ({ draft: FIXED, result: { ok: true } }), cleaned);
    expect(plain.load()).toMatchObject({ stage: 'cleaned', proofOk: true });
  });
});

describe('G0 (E-F2 m3): the scratch default branch', () => {
  it('repos: scratch default branch set only to a commit pipegen built', async () => {
    const { setScratchDefaultBranch } = await import('../src/proof/repos.js');
    const { assertScratch, guardedWrite, proofTarget, ScratchGuardError } = await import('../src/proof/target.js');
    const { world, SHA_MAIN } = await import('./helpers/proof-github.js');
    const SCRATCH = 'pipegen-proof-shop';
    const BUILT = 'e'.repeat(40);   // the base commit pipegen built and pushed (snapshot.ts pushProofSetup)
    const OTHER_SHA = '2'.repeat(40);
    const develop = app({ defaultBranch: 'develop' });
    const scratchOf = (_g: ReturnType<typeof world>) => assertScratch(proofTarget(develop), develop);
    const writes = (g: ReturnType<typeof world>) => g.writes().map((c) => `${c.method} ${decodeURIComponent(c.url.pathname)}`);

    // the branch exists at a commit pipegen didn't build (no `built` given: checkProofRepos' call): nothing written, set later
    const foreign = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: OTHER_SHA } } } });
    expect(await setScratchDefaultBranch(foreign.gh, scratchOf(foreign))).toBe('pending');
    expect(writes(foreign)).toEqual([]);
    // the same with the base commit's sha: develop is not at it, so still nothing
    expect(await setScratchDefaultBranch(foreign.gh, scratchOf(foreign), undefined, BUILT)).toBe('pending');
    expect(writes(foreign)).toEqual([]);
    expect(foreign.repos[SCRATCH]?.default_branch ?? 'main').toBe('main');

    // the branch is missing: never made through the API (the base push makes it at pipegen's commit)
    const missing = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } } });
    expect(await setScratchDefaultBranch(missing.gh, scratchOf(missing))).toBe('pending');
    expect(await setScratchDefaultBranch(missing.gh, scratchOf(missing), undefined, SHA_MAIN)).toBe('pending');
    expect(writes(missing)).toEqual([]);

    // after the base push: develop is at the commit pipegen built → the default branch is set to it
    const pushed = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: BUILT } } } });
    expect(await setScratchDefaultBranch(pushed.gh, scratchOf(pushed), undefined, BUILT)).toBe('set');
    expect(writes(pushed)).toEqual([`PATCH /repos/CrisWorking/${SCRATCH}`]);
    expect(JSON.parse(pushed.writes()[0]?.body ?? '{}')).toEqual({ default_branch: 'develop' });
    expect(pushed.repos[SCRATCH]?.default_branch).toBe('develop');
    // a `built` that is not a full sha is no commit pipegen built
    const odd = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true, refs: { main: SHA_MAIN, develop: BUILT } } } });
    for (const bad of ['', 'HEAD', BUILT.slice(0, 12), BUILT.toUpperCase(), `${BUILT}\n`]) {
      expect(await setScratchDefaultBranch(odd.gh, scratchOf(odd), undefined, bad), bad).toBe('pending');
    }
    expect(writes(odd)).toEqual([]);
    // already the app's default branch: nothing to do
    const same = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } } });
    expect(await setScratchDefaultBranch(same.gh, assertScratch(proofTarget(app()), app()))).toBe('already');
    expect(writes(same)).toEqual([]);

    // the guard: no API write makes a branch in the scratch repo (any sha), and the default branch is only ever the app's
    const g = world({ repos: { pipelines: { private: true }, [SCRATCH]: { private: true } } });
    const s = assertScratch(proofTarget(app()), app());
    for (const sha of [SHA_MAIN, BUILT, OTHER_SHA]) {
      await expect(guardedWrite(g.gh, s, 'POST /repos/{owner}/{repo}/git/refs', { ref: 'refs/heads/main', sha })).rejects.toThrow(ScratchGuardError);
    }
    for (const branch of ['evil', 'develop', 'Main', 'main ']) {
      await expect(guardedWrite(g.gh, s, 'PATCH /repos/{owner}/{repo}', { default_branch: branch })).rejects.toThrow(ScratchGuardError);
    }
    expect(g.calls).toEqual([]);
    await guardedWrite(g.gh, s, 'PATCH /repos/{owner}/{repo}', { default_branch: 'main' });
    expect(g.calls).toHaveLength(1);
  });
});

describe('G0 (F-2, F-3): planted items judged per job; coverage without a planted item', async () => {
  const { evaluate } = await import('../src/proof/evaluate.js');
  const { gateJobList } = await import('../src/engine/gate-job-list.js');
  const { matchPlanted, plantedFiles, PLANTED_ITEM_TEXT } = await import('../src/debate/planted.js');
  const { c1b, gateDoc, gateFinding, greenMain, job, needOf, pipegenJobs, run, spec, ctxOf } = await import('./helpers/proof-eval.js');
  const { service } = await import('./helpers/render.js');
  const { GATE_RESULT_ARTIFACT } = await import('../src/engine/artifact-names.js');
  type Draft = ReturnType<typeof draftOf>;
  type Result = Awaited<ReturnType<typeof evaluate>>;
  const FLAG = ['sec', 'ret'].join('');

  /** A draft over `services` with `needs` and `steps` (draftOf's profile, its services replaced). */
  function draftFor(services: ReturnType<typeof service>[], needs: NonNullable<Parameters<typeof draftOf>[0]>['needs'], steps: NonNullable<Parameters<typeof draftOf>[0]>['steps']): Draft {
    const d = draftOf({ needs, steps });
    return { ...d, profile: { ...d.profile, services } };
  }
  /** The planted PR: the gate blocks, every C1b placement found, and one finding per item from `found` (its own job's tool). */
  function plantedOf(d: Draft, items: readonly { id: string; file: string; needKey: string; category: string }[], found: (i: { id: string; needKey: string }) => boolean = () => true) {
    const tools = new Map(gateJobList(d).filter((e) => e.range !== true).map((e) => [e.job, e.tool as string]));
    const blocking = [
      ...c1b().filter((p) => p.kind === 'secret').map((p) => gateFinding('secrets', tools.get('secrets') as string, { file: p.path, line: p.line, [FLAG]: true, ruleId: 'generic-api-key' })),
      ...items.filter(found).map((i) => gateFinding(i.category, tools.get(i.needKey) ?? 'none', { file: i.file, job: i.needKey, ...(i.category === 'secrets' ? { [FLAG]: true } : {}) })),
    ];
    const pr = run({ event: 'pull_request', runId: 2, jobs: [...pipegenJobs(d, ['hooks']).map((n) => job(n)), job('gate', 'failure')], conclusion: 'failure' });
    pr.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: 2, result: 'block', blocking }, d));
    return { variant: 'planted' as const, outcomes: [pr] };
  }
  const need = (r: Result, id: string) => r.parts.filter((x) => x.part === 'pipeline' && x.needId === id);
  const pipeline = (r: Result) => r.parts.find((x) => x.part === 'pipeline' && x.needId === undefined);
  const MOUNT = 'docker: Error response from daemon: bullfrog: mounting the host path /home/runner/work/shop/shop is not allowed while sudo is disabled';

  const API = service({ name: 'api', path: 'api', language: 'node' });
  const WORKER = service({ name: 'worker', path: 'worker', language: 'python', packageManager: 'pip' });
  const twoNeeds = [
    needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('sast', { service: 'worker', floor: true }),
    needOf('deps', { service: 'api', floor: true }), needOf('deps', { service: 'worker', floor: true }), needOf('gate', { floor: true }),
  ];
  const twoSteps = [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('bandit', 'sast', 'worker'), spec('osv-scanner', 'deps', 'api'), spec('osv-scanner', 'deps', 'worker')];

  it('evaluate: planted tool and refusal looked up per job (needKey); two services with bandit and semgrep both caught', async () => {
    const d = draftFor([API, WORKER], twoNeeds, twoSteps);
    const { expected } = plantedFiles(d.profile);
    expect(expected.map((e) => e.needKey).sort()).toEqual(['deps--api', 'deps--worker', 'sast--api', 'sast--worker', 'secrets']);
    const ctx = ctxOf({ plantedItems: expected, matchPlanted, harnessJobs: ['egress-check', 'verify-lookup'] });
    // both services' scanners caught their own item with their own tool: semgrep for api, bandit for worker
    const r = await evaluate(d, [greenMain(d), plantedOf(d, expected)], ctx);
    expect(pipeline(r)?.status, pipeline(r)?.detail).toBe('proven');
    expect(r.parts.filter((p) => p.status === 'failed')).toEqual([]);
    // the worker's item missed: named with the worker job's own tool (bandit), never semgrep's
    const missed = await evaluate(d, [greenMain(d), plantedOf(d, expected, (i) => i.needKey !== 'sast--worker')], ctx);
    expect(pipeline(missed)?.status).toBe('failed');
    expect(pipeline(missed)?.detail).toContain(`bandit didn't catch the planted ${PLANTED_ITEM_TEXT['sast-python']}`);
    expect(pipeline(missed)?.detail).not.toContain(`semgrep didn't catch`);
    // a finding of the right file from the OTHER service's job never counts (origin by need key)
    const crossed = plantedOf(d, expected, (i) => i.needKey !== 'sast--worker');
    const crossedDoc = JSON.parse(Buffer.from(crossed.outcomes[0]!.artifacts.get(GATE_RESULT_ARTIFACT)!.bytes).toString('utf8')) as { blocking: object[] };
    const workerItem = expected.find((e) => e.needKey === 'sast--worker')!;
    crossedDoc.blocking.push(gateFinding('sast', 'semgrep', { file: workerItem.file, job: 'sast--api' }));
    crossed.outcomes[0]!.artifacts.set(GATE_RESULT_ARTIFACT, gateDoc({ runId: 2, result: 'block', blocking: crossedDoc.blocking }, d));
    const rc = await evaluate(d, [greenMain(d), crossed], ctx);
    expect(pipeline(rc)?.detail).toContain(`bandit didn't catch the planted ${PLANTED_ITEM_TEXT['sast-python']}`);
    // the refusal per job: the worker's sast job refused its mount; the api's sast item is still required (and here missed)
    const refused = plantedOf(d, expected, (i) => i.needKey !== 'sast--api');
    const pr = refused.outcomes[0]!;
    const sastWorker = pr.jobs.find((j) => j.name === 'sast--worker')!;
    Object.assign(sastWorker, { conclusion: 'failure', log: `##[group]Run docker run bandit\n${MOUNT}\n##[error]Process completed with exit code 125.` });
    const rr = await evaluate(d, [greenMain(d), refused], ctx);
    expect(pipeline(rr)?.detail).toContain(`semgrep didn't catch the planted ${PLANTED_ITEM_TEXT['sast-node']}`);
    expect(pipeline(rr)?.detail).not.toContain(`bandit didn't catch`);
    expect(pipeline(rr)?.detail).toMatch(/bullfrog/i);
  });

  it('evaluate: service with no planted template → its sast/deps floor need not-proven with a plain reason', async () => {
    const GO = service({ name: 'billing', path: 'billing', language: 'go', packageManager: 'go' as never });
    const d = draftFor([API, GO], [
      needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('sast', { service: 'billing', floor: true }),
      needOf('deps', { service: 'api', floor: true }), needOf('deps', { service: 'billing', floor: true }), needOf('gate', { floor: true }),
    ], [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('gosec', 'sast', 'billing'), spec('osv-scanner', 'deps', 'api'), spec('osv-scanner', 'deps', 'billing')]);
    const { expected } = plantedFiles(d.profile);
    expect(expected.some((e) => e.needKey.endsWith('--billing'))).toBe(false);   // no Go template in v0.2
    const ctx = ctxOf({ plantedItems: expected, matchPlanted, harnessJobs: ['egress-check', 'verify-lookup'] });
    const r = await evaluate(d, [greenMain(d), plantedOf(d, expected)], ctx);
    for (const id of ['sast', 'deps']) {
      const billing = need(r, id).filter((p) => /billing/.test(p.detail));
      expect(billing, id).toHaveLength(1);
      expect(billing[0]?.status, id).toBe('not-proven');
      expect(billing[0]?.detail, id).toMatch(/no planted problem for this service's language yet, so it is not shown to catch anything/);
      // the api service's items were caught: nothing about api is not-proven or failed
      expect(need(r, id).filter((p) => /--api/.test(p.detail))).toEqual([]);
    }
    // a floor need is never left as a pass: the pipeline is not proven and the proof is not ok (never warn-only)
    expect(pipeline(r)?.status).toBe('not-proven');
    expect(r.ok).toBe(false);
    expect(r.parts.filter((p) => p.status === 'failed')).toEqual([]);
    // a repo-wide sast/deps need (no service) has no planted template either
    const repoWide = draftFor([API], [needOf('secrets', { floor: true }), needOf('sast', { floor: true }), needOf('deps', { floor: true }), needOf('gate', { floor: true })],
      [spec('gitleaks', 'secrets'), spec('semgrep', 'sast'), spec('osv-scanner', 'deps')]);
    const rw = await evaluate(repoWide, [greenMain(repoWide), plantedOf(repoWide, plantedFiles(repoWide.profile).expected)], ctxOf({ plantedItems: plantedFiles(repoWide.profile).expected, matchPlanted, harnessJobs: ['egress-check', 'verify-lookup'] }));
    expect(need(rw, 'sast')[0]).toMatchObject({ status: 'not-proven' });
    expect(need(rw, 'deps')[0]).toMatchObject({ status: 'not-proven' });
    expect(rw.ok).toBe(false);
    // a node service whose items were not passed (a wiring bug, not a missing template) still FAILS
    const lost = await evaluate(d, [greenMain(d), plantedOf(d, expected)], { ...ctx, plantedItems: expected.filter((e) => e.needKey !== 'sast--api') });
    expect(need(lost, 'sast').some((p) => p.status === 'failed' && /sast--api|semgrep/.test(p.detail))).toBe(true);
    expect(lost.ok).toBe(false);
  });

  it('evaluate: blocking scanner with no planted item stays blocking, shown as not shown to catch anything, never in notProven', async () => {
    // draftOf: image-scan for api (blocking, no planted item: no template exists for it)
    const d = draftOf();
    const items = (await import('./helpers/proof-eval.js')).PLANTED_ITEMS.filter((i) => i.category !== 'image-scan');
    const { plantedRuns } = await import('./helpers/proof-eval.js');
    const r = await evaluate(d, [greenMain(d), plantedRuns(d)], ctxOf({ plantedItems: items }));
    expect(need(r, 'image-scan')).toEqual([]);   // no not-proven (or any) need result: it never reaches draft.notProven
    expect(r.parts.some((p) => p.status === 'not-proven' && p.needId === 'image-scan')).toBe(false);
    expect(pipeline(r)?.status).toBe('proven');
    expect(pipeline(r)?.detail).toMatch(/image-scan[^;]*not shown to catch anything/);
    expect(r.ok).toBe(true);
    expect(d.needs.find((n) => n.id === 'image-scan')?.blocking).toBe(true);   // the draft is untouched: it stays blocking
    // nuclei (dast) without a planted item: the same, a note, never a not-proven need
    const n = draftOf({
      needs: [needOf('secrets', { floor: true }), needOf('sast', { service: 'api', floor: true }), needOf('deps', { service: 'api', floor: true }), needOf('unit-tests', { service: 'api', floor: true }), needOf('dast', { service: 'api' }), needOf('gate', { floor: true })],
      steps: [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'api'), spec('osv-scanner', 'deps', 'api'), spec('nuclei', 'dast', 'api')],
    });
    const rn = await evaluate(n, [greenMain(n), plantedRuns(n)], ctxOf());
    expect(need(rn, 'dast')).toEqual([]);
    expect(pipeline(rn)?.detail).toMatch(/nuclei[^;]*not shown to catch anything/);
    expect(rn.ok).toBe(true);
  });
});

describe('G0 (B8, F-1): the dev-only proof bootstrap', () => {
  it('reviewed: full mode with proofs 0 → no offer; PIPEGEN_BOOTSTRAP_PROOFS=1 offers them in a dev run with a note; refused in a release build', async () => {
    const { vi } = await import('vitest');
    const { BOOTSTRAP_PROOFS_NOTE, bootstrapProofs, bootstrapProofsNote, reviewedFor } = await import('../src/engine/reviewed.js');
    const { reviewedList } = await import('./helpers/render.js');
    const list = reviewedList();
    const sast = { id: 'sast', layer: 'merge' as const, category: 'sast', service: 'api', why: 't', blocking: true, floor: true };
    const ids = (env: Record<string, string | undefined>) => reviewedFor(sast, 'node', list, 'full', env).map((t) => t.id);
    // every entry has proofs 0 today: full mode offers nothing; the audit still lists them
    expect(list.filter((t) => t.categories.includes('sast')).every((t) => t.proofs === 0)).toBe(true);
    expect(ids({})).toEqual([]);
    expect(reviewedFor(sast, 'node', list, 'audit', {}).map((t) => t.id)).toContain('semgrep');
    for (const v of ['0', 'true', 'yes', ' 1', '1 ', '']) expect(ids({ PIPEGEN_BOOTSTRAP_PROOFS: v }), v).toEqual([]);
    // the switch in a dev run: the proofs-0 entries are offered, with the note for the preview and PIPEGEN.md
    const on = { PIPEGEN_BOOTSTRAP_PROOFS: '1' };
    expect(ids(on)).toContain('semgrep');
    expect(ids(on).every((id) => list.find((t) => t.id === id)?.categories.includes('sast'))).toBe(true);
    expect(bootstrapProofs(on)).toBe(true);
    expect(bootstrapProofs({})).toBe(false);
    expect(BOOTSTRAP_PROOFS_NOTE).toMatch(/these tools are proven on your repo but not yet counted as proven by pipegen/);
    expect(bootstrapProofsNote(on)).toBe(BOOTSTRAP_PROOFS_NOTE);
    expect(bootstrapProofsNote({})).toBeNull();
    // never a tool still waiting for its human review, never another language or category
    const pending = list.map((t) => (t.id === 'semgrep' ? { ...t, reviewedBy: 'PENDING', reviewedAt: 'PENDING' } : t));
    expect(reviewedFor(sast, 'node', pending, 'full', on).map((t) => t.id)).not.toContain('semgrep');
    expect(reviewedFor(sast, 'node', list, 'full', on).map((t) => t.id)).not.toContain('bandit');   // python only
    // a release build refuses the switch (any value): the run stops with a plain reason, nothing is offered
    vi.stubEnv('PIPEGEN_RELEASE', '1');
    try {
      expect(() => bootstrapProofs(on)).toThrow(/release/);
      expect(() => reviewedFor(sast, 'node', list, 'full', on)).toThrow(/release/);
      expect(() => bootstrapProofs({ PIPEGEN_BOOTSTRAP_PROOFS: '0' })).toThrow(/release/);
      expect(bootstrapProofs({})).toBe(false);
      expect(ids({})).toEqual([]);
    } finally {
      vi.unstubAllEnvs();
    }
    // and the real release bundle (tsup's define) refuses it under plain node
    const { build } = await import('tsup');
    const { tsupOptions } = await import('../tsup.config.js');
    const { execFileSync } = await import('node:child_process');
    const out = home();
    await build({ ...tsupOptions, entry: { probe: 'test/helpers/bootstrap-probe.ts' }, outDir: out, config: false, silent: true, clean: false });
    const env: NodeJS.ProcessEnv = { ...process.env, PIPEGEN_BOOTSTRAP_PROOFS: '1' };
    delete env.PIPEGEN_RELEASE;
    delete env.NODE_ENV;
    const res = JSON.parse(execFileSync('node', [join(out, 'probe.js')], { encoding: 'utf8', env }).trim()) as { on?: boolean; refused?: string };
    expect(res.refused).toMatch(/release/);
    expect(res.on).toBeUndefined();
  }, 60_000);
});

describe('G0 (F-12, ruling F-F2): the AI estimate scales with the need keys', () => {
  it('estimate: debate row grows with the number of need keys (many-service profile)', async () => {
    const { DEBATE_CALLS, DEBATE_MEASURED_KEYS, estimate, needKeyCount } = await import('../src/estimate/estimate.js');
    const { floorNeeds, jobCategories } = await import('../src/engine/needs.js');
    const { profile, service } = await import('./helpers/render.js');
    const { DEFAULT_MODEL } = await import('../src/types.js');
    const caps = { branchProtection: true, environments: true, envRequiredReviewers: false, deploymentBranchPolicies: true, attestations: false, codeScanning: false, keylessSigningAllowed: false };
    const opus = { name: 'claude', model: DEFAULT_MODEL } as const;
    const activity = { pushes: 10, prs: 2, capped: false };
    const one = profile([service({ name: 'web', path: '.', language: 'node' })]);
    const many = profile(Array.from({ length: 12 }, (_, i) => service({ name: `svc${i}`, path: `services/svc${i}`, language: i % 2 === 0 ? 'node' : 'python', packageManager: i % 2 === 0 ? 'npm' : 'pip' })));
    const keysOne = needKeyCount(floorNeeds(one, caps));
    const keysMany = needKeyCount(floorNeeds(many, caps));
    expect(keysMany).toBeGreaterThan(5 * DEBATE_MEASURED_KEYS);   // a large monorepo: far more keys than the 7 measured
    const row = (p: typeof one, keys?: number) => estimate(p, jobCategories(floorNeeds(p, caps)), 2, activity, opus, keys === undefined ? {} : { needKeys: keys });
    const debateOf = (e: ReturnType<typeof row>) => e.aiTokens.find((s) => s.stage === 'debate')!;
    // up to the measured 7 keys: the measured row exactly (Plan F's 261k / 35k)
    for (const k of [0, 1, 7]) expect(debateOf(row(one, k)), String(k)).toEqual({ stage: 'debate', input: 261_000, output: 35_000 });
    expect(debateOf(row(one))).toEqual({ stage: 'debate', input: 261_000, output: 35_000 });   // no count given: unchanged
    // more keys: every prompt (never the bundle) and the builder's answer grow in proportion, rounded up to 1k
    const up = (x: number, k: number) => Math.ceil((x * k) / DEBATE_MEASURED_KEYS / 1000) * 1000;
    const b = DEBATE_CALLS.builder;
    const c = DEBATE_CALLS.critique;
    const rd = DEBATE_CALLS.round;
    const big = debateOf(row(many, keysMany));
    expect(big).toEqual({
      stage: 'debate',
      input: b.calls * (b.bundle + up(b.prompt, keysMany)) + c.calls * up(c.prompt, keysMany) + rd.calls * up(rd.prompt, keysMany),
      output: b.calls * up(b.output, keysMany) + c.calls * c.output + rd.calls * rd.output,
    });
    expect(big.input).toBeGreaterThan(4 * 261_000);
    // monotone: one more key never lowers the row; the cap grows with it
    let last = 0;
    for (let k = 1; k <= keysMany; k++) { const i = debateOf(row(many, k)).input; expect(i).toBeGreaterThanOrEqual(last); last = i; }
    const small = row(one, keysOne);
    const large = row(many, keysMany);
    expect(large.aiCostCapUsd as number).toBeGreaterThan(small.aiCostCapUsd as number);
    expect(large.basis.join('\n')).toContain(`sized for ${keysMany} need keys`);
    // a count that is not a whole positive number is never read as more than measured, and never fewer
    for (const bad of [Number.NaN, -3, Number.POSITIVE_INFINITY, 2.5]) expect(debateOf(row(one, bad)).input, String(bad)).toBeGreaterThanOrEqual(261_000);
    expect(debateOf(row(one, Number.POSITIVE_INFINITY)).input).toBe(261_000);
  });
});
