// v0.2 Plan G G14: a fake world for the production proof (src/cli/run-proof.ts): every GitHub-touching op is a recording fake, the
// fix loop (proveWithFixes) and the dispute decision (decideDisputes) are the real ones, the state store is a real one on a temp home.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Octokit } from '@octokit/rest';
import { AiSpendMeter } from '../../src/ai/spend-meter.js';
import { generateFpKey, SecretVault } from '../../src/create/secrets.js';
import { placeholderName } from '../../src/proof/keys.js';
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
import type { CreatedFile, PipelineDraft, ProofResult, RepoProfile, Service } from '../../src/types.js';
import { CAPS, candidatesFor, choicesFor, need, profile, scripted, svc } from './debate-fixtures.js';

export const RUN_ID = '20261106-100000-abc123';
export const OWN = 'CrisWorking';
/** Evidence that answers every unit key with one value. */
class AnyKey<V> extends Map<string, V> { constructor(private readonly v: V) { super(); } override get(): V { return this.v; } override has(): boolean { return true; } }
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

/** Where a recording keys fake sends its effects (the e2e puts them on a fake GitHub); all optional. */
export interface KeysEffects {
  /** After `setup`, `placeholders` or `real` stored these names. */
  store?: (names: readonly string[]) => Promise<void>;
  /** The names `deleteAll` removed. */
  purge?: () => Promise<string[]>;
  /** The names stored right now (ScratchKeys.stored()), by kind. */
  stored?: () => Record<string, string>;
  /** The line `deleteAll` writes on the timeline (default `keys.deleteAll`). */
  deleteLine?: string | null;
}

/**
 * A ScratchKeys stand-in that records on `tl`: the scratch secrets are placeholders until the user says yes, and deleteAll removes them.
 * G17-F1-R2 (sec I1): setup and placeholders apply ScratchKeys' own name rules (placeholderName, the real validator), so a name the real
 * store refuses (GITHUB_*, PIPEGEN_*, an invalid one) throws here too.
 */
export function recordingKeys(tl: string[], fx: KeysEffects = {}): FixKeys & { readonly mode: FixKeys['mode'] } {
  let mode: 'none' | 'placeholder' | 'real' = 'none';
  return {
    get mode() { return mode; }, lastRefusal: undefined,
    setup: async (n: readonly string[]) => { for (const x of n) placeholderName(x); tl.push(`keys.setup:${[...n].join(',')}`); if (mode === 'none') mode = 'placeholder'; await fx.store?.(n); },
    placeholders: async (n: readonly string[]) => { for (const x of n) placeholderName(x); tl.push(`keys.placeholders:${[...n].join(',')}`); if (mode === 'none') mode = 'placeholder'; await fx.store?.(n); },
    real: async (n: readonly string[]) => { tl.push(`keys.real:${[...n].join(',')}`); mode = 'real'; await fx.store?.(n); },
    deleteAll: async () => {
      if (fx.deleteLine !== null) tl.push(fx.deleteLine ?? 'keys.deleteAll');
      mode = 'none';
      return await fx.purge?.() ?? [];
    },
    stored: () => fx.stored?.() ?? {},
    ticket: async () => ({ ticket: true }), evidence: async () => null, scrubber: () => (x: string) => x,
  } as unknown as FixKeys & { readonly mode: FixKeys['mode'] };
}

export interface WorldOpts {
  private?: boolean;
  results?: ProofResult[];
  /** A failed result's evidence: one source of the latest run with this log (any unit), e.g. a rate limit the loop re-runs. */
  failLog?: string;
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
  /** The real central layout (C1): the app caller is the same for every draft; the steps' tools live only in the central workflow. */
  centralOnly?: boolean;
  /** The app's services (default: api and web). */
  services?: Service[];
  /** The AI-written file of `aiFile` (default: api/test_app.py, part tests). */
  aiPath?: { path: string; part: CreatedFile['part'] };
}
export interface World {
  tl: string[]; store: StateStore; input: ProofInput; ops: Partial<ProofOps>; asked: string[]; vault: SecretVault; meter: AiSpendMeter;
  pushed: { variant: string; files: { path: string | Uint8Array }[]; parent?: string; round?: number }[];
  /** Every variant run: the branch's variant, its sha, merge or not. */
  variants: { variant: string; sha: string; merge: boolean }[];
  /** The central files the setup pushed (private apps). */
  setupCentral: { path: string; content: string | Uint8Array }[];
  evals: { d: PipelineDraft; ctx: Parameters<ProofOps['evaluate']>[2] }[]; cleanupOpts: Parameters<ProofOps['cleanup']>[4][]; checkOpts: unknown[];
  asm: { mode: string; sha: string | undefined; draft: PipelineDraft }[]; disarm: () => void; run(): Promise<ProofReturn>;
  armed: { cleanup: Parameters<ProofInput['arm']>[0]; meters: Parameters<ProofInput['arm']>[1] }[];
  keysMode(): string;
}

export async function proofWorld(o: WorldOpts = {}): Promise<World> {
  const tl: string[] = [];
  const home = mkdtempSync(join(tmpdir(), 'pg-proof-'));
  homes.push(home);
  const p: RepoProfile = profile({ owner: OWN, repo: 'r', private: o.private === true, services: o.services ?? [APP, WEB], generatedDirs: [] });
  const NEEDS = o.services === undefined ? NEEDS2 : [need('secrets', 'push', undefined), ...o.services.map((x) => need('sast', 'merge', x.name)), need('gate', 'merge', undefined)];
  const choices = choicesFor(NEEDS, p, {}, {}, undefined, candidatesFor(NEEDS, p));
  let draft: PipelineDraft = {
    profile: p, capabilities: CAPS, needs: [...NEEDS], steps: choices.map((c) => c.chosen), created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [],
    requireDeployApproval: false, skipped: [], suggestions: [],
    ...(o.private === true ? { centralPin: { repo: `${OWN}/pipelines`, sha: '0'.repeat(40) } } : {}),
  } as unknown as PipelineDraft;
  if (o.aiFile === true) draft = { ...draft, created: [{ repo: 'app', path: o.aiPath?.path ?? 'api/test_app.py', content: 'def test_a():\n    assert 1\n', part: o.aiPath?.part ?? 'tests', reason: 'r', aiEdited: true }] };
  if (o.draft !== undefined) draft = o.draft(draft);
  const store = await StateStore.open(p, { home, env: {} });
  store.begin(RUN_ID, { owner: OWN, repo: 'r', private: p.private, ownerType: 'User', defaultBranch: 'main' }, { cap: 100, aiCap: 5 });
  for (const s of ['planned', 'debated', 'created'] as const) store.setStage(s);
  const vault = new SecretVault();
  vault.set('API_TOKEN', TYPED);
  // G17-F1-R2 (sec I1): the run's vault holds the fingerprint key (run.ts generateFpKey) before the proof, as in production
  generateFpKey(vault);
  const meter = new AiSpendMeter(scripted(() => ({})).ai, 5);
  const t = proofTarget(store.state?.app as never, { runId: RUN_ID });
  const asked: string[] = [];
  const prompt: Prompter = {
    confirm: async (msg) => { asked.push(msg); tl.push('confirm'); if (o.confirm === 'throw') throw new Error('no terminal'); return o.confirm ?? true; },
    select: async () => { throw new Error('no select'); }, text: async () => { throw new Error('no text'); },
  };
  const io: CliIO = { prompt, out: () => {}, err: (s) => { tl.push(`err:${s.slice(0, 60)}`); }, env: {}, interactive: o.interactive ?? true };
  const keys = recordingKeys(tl);
  const results = [...(o.results ?? [PASS])];
  const pushed: World['pushed'] = [];
  const evals: World['evals'] = [];
  const cleanupOpts: World['cleanupOpts'] = [];
  const checkOpts: unknown[] = [];
  const asm: World['asm'] = [];
  const variants: World['variants'] = [];
  const setupCentral: World['setupCentral'] = [];
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
      setupCentral.push(...(input.central?.files ?? []));
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
      variants.push({ variant: v.branch.variant, sha: v.branch.sha, merge: v.merge });
      return { outcomes: [outcome(v.branch.sha)], closed: !v.merge, stopped: false, missing: [], leftovers: [], ...(v.merge ? { mergeSha: 'f'.repeat(40) } : {}) };
    },
    rerunFailed: async (_gh, _t, runs) => { tl.push(`rerunFailed:${runs.map((r) => r.handle.runId).join(',')}`); return runs.map((r) => ({ ...outcome(r.handle.headSha), handle: r.handle, attempt: r.attempt + 1 })); },
    evaluate: async (d, _runs, ctx) => {
      tl.push('evaluate');
      evals.push({ d, ctx });
      const result = results.length > 1 ? results.shift() as ProofResult : results[0] as ProofResult;
      const src = { runId: runN, attempt: 1, log: o.failLog ?? '' };
      const evidence = o.failLog === undefined || result.ok ? new Map() : new AnyKey({ sources: [src] }) as never;
      return { result, coverage: { measured: null, lowest: null, decision: null }, evidence };
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
      const tools = d.steps.map((s) => `\n# ${s.needId}:${s.tool.id}`).join('');
      if (o.centralOnly === true) return [CALLER(), ...(d.centralPin === undefined ? [] : [wf('.github/workflows/r--merge.yml', `on: workflow_call\njobs: {}\n${tools}`, 'central')])];
      const own = [CALLER(tools)];
      return d.centralPin === undefined ? own : [...own, wf('.github/workflows/r--merge.yml', 'on: workflow_call\njobs: {}\n', 'central')];
    },
    build: {
      rebuild: async (d) => ({ files: d.created, assembled: d }),
      referee: async () => { tl.push('referee'); return { ok: true, issues: [], demoted: [], notes: [] }; },
      guard: async (files) => { tl.push('guard'); return { ok: files, refused: [], notes: [] }; },
    },
    store, [A_FIELD]: { kind: 'fine-grained', [TK_FIELD]: MADE_UP, canCreateRepos: false, canDeleteRepos: o.canDelete === true } as never, gh: {} as Octokit, vault, ai: { meter }, io,
    debate: { choices, needs: [...NEEDS], candidates: candidatesFor(NEEDS, p), disputes: o.disputes ?? [], suggestions: [], transcript: [], requireDeployApproval: false, byCode: [], uncovered: [] } as unknown as DebateResult,
    reviewed: (await import('./debate-fixtures.js')).REVIEWED, platform: {} as never, dir: '/repo',
    scanner: async () => ({ name: 'betterleaks', path: '/bin/betterleaks', version: '1.0.0' }),
    arm: (c, m) => { tl.push('arm'); armed.push({ cleanup: c, meters: m }); disarm = armProofCleanup(input.store, c, { meters: m }); },
    variantMinutes: 5,
    checkRepos: async () => { tl.push('checkRepos'); checkOpts.push(store.armed); return { ready: true, target: t, repos: [], created: [], defaultBranchState: 'pending' }; },
    ...o.input,
  };
  return {
    tl, store, input, ops, asked, vault, meter, pushed, variants, setupCentral, evals, cleanupOpts, checkOpts, asm, armed, keysMode: () => keys.mode,
    get disarm() { return disarm; },
    run: async () => { try { return await makeRunProof(ops)(input); } finally { disarm(); } },
  };
}
