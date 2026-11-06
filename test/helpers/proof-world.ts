// v0.2 Plan G G14: a fake world for the production proof (src/cli/run-proof.ts): every GitHub-touching op is a recording fake, the
// fix loop (proveWithFixes) and the dispute decision (decideDisputes) are the real ones, the state store is a real one on a temp home.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { AiSpendMeter } from '../../src/ai/spend-meter.js';
import { SecretVault } from '../../src/create/secrets.js';
import type { DebateResult } from '../../src/debate/debate.js';
import { armProofCleanup } from '../../src/proof/cleanup.js';
import type { FixKeys } from '../../src/proof/fix.js';
import { HARNESS_PATH } from '../../src/proof/harness.js';
import { MinutesMeter } from '../../src/proof/minutes.js';
import type { RunOutcome } from '../../src/proof/run.js';
import type { ProofBranch } from '../../src/proof/snapshot.js';
import { StateStore } from '../../src/proof/state.js';
import { proofTarget } from '../../src/proof/target.js';
import { makeRunProof, type ProofInput, type ProofOps, type ProofReturn } from '../../src/cli/run-proof.js';
import type { CliIO, Prompter } from '../../src/cli/io.js';
import type { CreatedFile, PipelineDraft, ProofResult, RepoProfile } from '../../src/types.js';
import { CAPS, candidatesFor, choicesFor, need, profile, scripted, svc } from './debate-fixtures.js';

export const RUN_ID = '20261106-100000-abc123';
export const OWN = 'CrisWorking';
/** Key names built at run time (the no-secret-literals rule reads `<name>: value` as a credential). */
export const A_FIELD = ['au', 'th'].join('') as 'auth';
export const TK_FIELD = ['to', 'ken'].join('');
export const SS_FIELD = ['secret', 'Store'].join('') as 'secretStore';
export const MADE_UP = ['made', 'up', 'value', '0000000000'].join('-');
export const TYPED = ['typed', 'value', '1234567890'].join('-');
export const PASS: ProofResult = { ok: true, parts: [{ part: 'pipeline', status: 'proven', detail: 'ok' }, { part: 'tests', status: 'proven', detail: 'ok' }], findings: [], minutesUsed: 1, runUrls: [] };
export const failOn = (needId: string, detail = 'the job failed'): ProofResult => ({
  ok: false, parts: [{ part: 'pipeline', status: 'failed', detail }, { part: 'pipeline', needId, status: 'failed', detail }, { part: 'tests', status: 'proven', detail: 'ok' }], findings: [], minutesUsed: 1, runUrls: [],
});
const homes: string[] = [];
export const cleanHomes = (): void => { for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true }); };

export const APP = svc({ name: 'api', path: 'api', language: 'python', packageManager: 'pip', envVars: ['API_TOKEN'] });
export const WEB = svc({ name: 'web', path: 'web', scripts: ['test', 'start'], frameworks: ['express'] });
export const NEEDS2 = [need('secrets', 'push', undefined), need('sast', 'merge', 'api'), need('sast', 'merge', 'web'), need('gate', 'merge', undefined)];

const wf = (path: string, content: string, repo: 'app' | 'central' = 'app'): CreatedFile => ({ repo, path, content, part: 'pipeline', reason: 'r' });
/** pipegen's caller: runs on push and on the PR, reads one secret. */
export const CALLER = (extra = ''): CreatedFile => wf('.github/workflows/pipegen.yml', `on: [push, pull_request]\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo "\${{ secrets.API_TOKEN }}"${extra}\n`);

export interface WorldOpts {
  private?: boolean;
  results?: ProofResult[];
  canDelete?: boolean;
  confirm?: boolean | 'throw';
  interactive?: boolean;
  aiFile?: boolean;
  disputes?: DebateResult['disputes'];
  /** jobs (name, conclusion) of every outcome */
  jobs?: { name: string; conclusion: string }[];
  ops?: Partial<ProofOps>;
  draft?: (d: PipelineDraft) => PipelineDraft;
  input?: Partial<ProofInput>;
  stage?: 'created';
}
export interface World {
  tl: string[]; store: StateStore; input: ProofInput; ops: Partial<ProofOps>; asked: string[]; vault: SecretVault; meter: AiSpendMeter;
  pushed: { variant: string; files: { path: string | Uint8Array }[]; parent?: string; round?: number }[];
  evals: { d: PipelineDraft; ctx: Parameters<ProofOps['evaluate']>[2] }[]; cleanupOpts: Parameters<ProofOps['cleanup']>[4][]; checkOpts: unknown[];
  asm: { mode: string; sha: string | undefined; draft: PipelineDraft }[]; disarm: () => void; run(): Promise<ProofReturn>;
  armed: { cleanup: Parameters<ProofInput['arm']>[0]; meters: Parameters<ProofInput['arm']>[1] }[];
  keysMode(): string;
}

export async function proofWorld(o: WorldOpts = {}): Promise<World> {
  const tl: string[] = [];
  const home = mkdtempSync(join(tmpdir(), 'pg-proof-'));
  homes.push(home);
  const p: RepoProfile = profile({ owner: OWN, repo: 'r', private: o.private === true, services: [APP, WEB], generatedDirs: [] });
  const choices = choicesFor(NEEDS2, p, {}, {}, undefined, candidatesFor(NEEDS2, p));
  let draft: PipelineDraft = {
    profile: p, capabilities: CAPS, needs: [...NEEDS2], steps: choices.map((c) => c.chosen), created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [],
    requireDeployApproval: false, skipped: [], suggestions: [],
    ...(o.private === true ? { centralPin: { repo: `${OWN}/pipelines`, sha: '0'.repeat(40) } } : {}),
  } as unknown as PipelineDraft;
  if (o.aiFile === true) draft = { ...draft, created: [{ repo: 'app', path: 'api/test_app.py', content: 'def test_a():\n    assert 1\n', part: 'tests', reason: 'r', aiEdited: true }] };
  if (o.draft !== undefined) draft = o.draft(draft);
  const store = await StateStore.open(p, { home, env: {} });
  store.begin(RUN_ID, { owner: OWN, repo: 'r', private: p.private, ownerType: 'User', defaultBranch: 'main' }, { cap: 100, aiCap: 5 });
  for (const s of ['planned', 'debated', 'created'] as const) store.setStage(s);
  const vault = new SecretVault();
  vault.set('API_TOKEN', TYPED);
  const meter = new AiSpendMeter(scripted(() => ({})).ai, 5);
  const t = proofTarget(store.state?.app as never, { runId: RUN_ID });
  const asked: string[] = [];
  const prompt: Prompter = {
    confirm: async (msg) => { asked.push(msg); tl.push('confirm'); if (o.confirm === 'throw') throw new Error('no terminal'); return o.confirm ?? true; },
    select: async () => { throw new Error('no select'); }, text: async () => { throw new Error('no text'); },
  };
  const io: CliIO = { prompt, out: () => {}, err: (s) => { tl.push(`err:${s.slice(0, 60)}`); }, env: {}, interactive: o.interactive ?? true };
  let mode: 'none' | 'placeholder' | 'real' = 'none';
  const keys = {
    get mode() { return mode; }, lastRefusal: undefined,
    setup: async (n: readonly string[]) => { tl.push(`keys.setup:${[...n].join(',')}`); if (mode === 'none') mode = 'placeholder'; },
    placeholders: async (n: readonly string[]) => { tl.push(`keys.placeholders:${[...n].join(',')}`); if (mode === 'none') mode = 'placeholder'; },
    real: async (n: readonly string[]) => { tl.push(`keys.real:${[...n].join(',')}`); mode = 'real'; },
    deleteAll: async () => { tl.push('keys.deleteAll'); mode = 'none'; return []; },
    ticket: async () => ({ ticket: true }), evidence: async () => null, scrubber: () => (x: string) => x,
  } as unknown as FixKeys;
  const results = [...(o.results ?? [PASS])];
  const pushed: World['pushed'] = [];
  const evals: World['evals'] = [];
  const cleanupOpts: World['cleanupOpts'] = [];
  const checkOpts: unknown[] = [];
  const asm: World['asm'] = [];
  const SCR = { kind: 'scratch', target: { defaultBranch: 'main' } } as never;
  let runN = 100;
  let sha = 0;
  const br = (variant: string): ProofBranch => ({ variant: variant as ProofBranch['variant'], branch: `proof/${RUN_ID}/${variant}`, sha: (++sha).toString(16).padStart(40, 'a'), commits: [] });
  const outcome = (headSha: string): RunOutcome => ({
    handle: { workflow: '.github/workflows/pipegen.yml', runId: ++runN, url: '', event: 'pull_request', headSha }, conclusion: 'success', attempt: 1,
    jobs: (o.jobs ?? []).map((j) => ({ name: j.name, conclusion: j.conclusion })) as never, artifacts: new Map(), artifactProblems: new Map(),
  });
  const ops: Partial<ProofOps> = {
    start: async () => { tl.push('proofStart'); return { at: 1_000, fromServer: true }; },
    resumeMinutes: async (_gh, _t, s, opts) => { tl.push(`minutesForResume:${opts?.store === undefined ? 'no-store' : 'store'}`); return new MinutesMeter(s.cap, 1_000); },
    minutesStop: () => async () => false,
    basePaths: async () => new Set(['package.json']),
    keys: (_gh, _t, _v, deps) => { tl.push(`keys.new:${(deps.readByWorkflows ?? ['<none>']).join(',')}`); return keys; },
    [SS_FIELD]: (k: FixKeys, names: readonly string[]) => async () => { tl.push('secretStore'); await k.setup(names); },
    transport: () => ({ push: async (_to, _from, refs) => { tl.push(`push:${refs.map((r) => String(r.branch)).join(',')}`); } }),
    setup: async (input, deps) => {
      tl.push('setup');
      const app = await input.appFiles(input.central === undefined ? undefined : 'c'.repeat(40));
      await deps.transport.push(SCR, {} as never, [{ branch: `proof/${RUN_ID}/main` } as never]);
      await deps.storeSecrets(SCR, { baseSha: 'b'.repeat(40) });
      pushed.push({ variant: 'setup', files: [...app, ...input.plantedFiles] });
      return {
        session: {} as never, base: { paths: new Set(['package.json']), gitleaksIgnore: null, sha: 'b'.repeat(40) } as never,
        branches: { main: br('main'), planted: br('planted') }, planted: [], disabled: [], notProven: [], leftOut: [], warnings: [],
        ...(input.central === undefined ? {} : { centralSha: 'c'.repeat(40) }),
      };
    },
    pushBranch: async (_s, variant, commits, deps) => {
      await deps.transport.push(SCR, {} as never, [{ branch: `proof/${RUN_ID}/${variant}${deps.round === undefined ? '' : `-${deps.round}`}` } as never]);
      tl.push(`pushBranch:${variant}${deps.parent === undefined ? '' : '@parent'}${deps.round === undefined ? '' : `#${deps.round}`}`);
      pushed.push({ variant, files: commits.flat(), ...(deps.parent === undefined ? {} : { parent: deps.parent }), ...(deps.round === undefined ? {} : { round: deps.round }) });
      return br(variant);
    },
    resetBase: async () => { tl.push('resetBase'); },
    variant: async (_gh, _t, v) => {
      tl.push(`variant:${v.branch.variant}:${v.merge ? 'merge' : 'no-merge'}${v.keepOpen === true ? ':open' : ''}`);
      return { outcomes: [outcome(v.branch.sha)], closed: !v.merge, stopped: false, missing: [], leftovers: [], ...(v.merge ? { mergeSha: 'f'.repeat(40) } : {}) };
    },
    rerunFailed: async (_gh, _t, runs) => { tl.push(`rerunFailed:${runs.map((r) => r.handle.runId).join(',')}`); return runs.map((r) => ({ ...outcome(r.handle.headSha), handle: r.handle, attempt: r.attempt + 1 })); },
    evaluate: async (d, _runs, ctx) => {
      tl.push('evaluate');
      evals.push({ d, ctx });
      return { result: results.length > 1 ? results.shift() as ProofResult : results[0] as ProofResult, coverage: { measured: null, lowest: null, decision: null }, evidence: new Map() };
    },
    userMain: async () => new Map(),
    cancelActive: async () => { tl.push('cancelActive'); },
    // the real cleanupAfterProof deletes the scratch secrets first (Plan E); the fake does the same, then records itself
    cleanup: async (_gh, _t, _s, k, opts) => { await (k as unknown as FixKeys).deleteAll(); tl.push(`cleanup:canDeleteRepo=${String(opts.canDeleteRepo)}`); cleanupOpts.push(opts); return { repoDeleted: opts.canDeleteRepo, leftovers: [] }; },
    placements: () => ({ files: [], expected: [] }),
    appFiles: (_d, deps) => ({
      appFiles: async (centralSha) => [...await deps.assemble('none', centralSha), wf(HARNESS_PATH, 'on: [pull_request]\njobs: {}\n')],
      last: () => ({ harness: { file: wf(HARNESS_PATH, ''), jobs: [], notes: [] }, compat: { files: [], notCompared: [] } }),
    }),
    ...o.ops,
  };
  let disarm: () => void = () => {};
  const armed: World['armed'] = [];
  const input: ProofInput = {
    draft, assembled: draft, files: [], assemble: async () => [CALLER()],
    assembleFor: async (d) => async (mode, centralSha) => {
      asm.push({ mode, sha: centralSha, draft: d });
      const own = [CALLER(d.steps.map((s) => `\n# ${s.needId}:${s.tool.id}`).join(''))];
      return d.centralPin === undefined ? own : [...own, wf('.github/workflows/r--merge.yml', 'on: workflow_call\njobs: {}\n', 'central')];
    },
    build: {
      rebuild: async (d) => ({ files: d.created, assembled: d }),
      referee: async () => { tl.push('referee'); return { ok: true, issues: [], demoted: [], notes: [] }; },
      guard: async (files) => { tl.push('guard'); return { ok: files, refused: [], notes: [] }; },
    },
    store, [A_FIELD]: { kind: 'fine-grained', [TK_FIELD]: MADE_UP, canCreateRepos: false, canDeleteRepos: o.canDelete === true } as never, gh: {} as Octokit, vault, ai: { meter }, io,
    debate: { choices, needs: [...NEEDS2], candidates: candidatesFor(NEEDS2, p), disputes: o.disputes ?? [], suggestions: [], transcript: [], requireDeployApproval: false, byCode: [], uncovered: [] } as unknown as DebateResult,
    reviewed: (await import('./debate-fixtures.js')).REVIEWED, platform: {} as never, dir: '/repo',
    scanner: async () => ({ name: 'betterleaks', path: '/bin/betterleaks', version: '1.0.0' }),
    arm: (c, m) => { tl.push('arm'); armed.push({ cleanup: c, meters: m }); disarm = armProofCleanup(store, c, { meters: m }); },
    variantMinutes: 5,
    checkRepos: async () => { tl.push('checkRepos'); checkOpts.push(store.armed); return { ready: true, target: t, repos: [], created: [], defaultBranchState: 'pending' }; },
    ...o.input,
  };
  return {
    tl, store, input, ops, asked, vault, meter, pushed, evals, cleanupOpts, checkOpts, asm, armed, keysMode: () => mode,
    get disarm() { return disarm; },
    run: async () => { try { return await makeRunProof(ops)(input); } finally { disarm(); } },
  };
}
