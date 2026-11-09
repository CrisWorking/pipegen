// v0.2 Plan G G13: `pipegen run` (src/cli/run.ts) with fake stages, and its pure parts (src/cli/run-parts.ts) with the real modules.
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';

const childCalls: string[] = [];
vi.mock('node:child_process', async (orig) => {
  const real = await orig<typeof import('node:child_process')>();
  const spy = (name: string) => (...a: unknown[]) => { childCalls.push(name); return (real as unknown as Record<string, (...x: unknown[]) => unknown>)[name]?.(...a); };
  return { ...real, spawn: spy('spawn'), execFile: spy('execFile'), exec: spy('exec'), spawnSync: spy('spawnSync'), execFileSync: spy('execFileSync'), execSync: spy('execSync'), fork: spy('fork') };
});
const bootstrapOrder: string[] = [];
let bootstrapThrows = false;
vi.mock('../src/engine/reviewed.js', async (orig) => {
  const real = await orig<typeof import('../src/engine/reviewed.js')>();
  return { ...real, assertBootstrapAllowed: (env?: NodeJS.ProcessEnv) => { bootstrapOrder.push('assertBootstrapAllowed'); if (bootstrapThrows) throw new real.BootstrapProofsError('refused in a release build'); return real.assertBootstrapAllowed(env); } };
});

import type { Octokit } from '@octokit/rest';
import { AiSpendMeter } from '../src/ai/spend-meter.js';
import type { mapCoverage } from '../src/audit/coverage.js';
import type { CodeBundle } from '../src/ai/redact.js';
import { proofReposFor, onCreatedFor, scanCounted, provenDraft, NOT_IN_SCOPE, NO_MEMORY_FOLDER, SECRET_FOUND, notProvableNotes, auditCredits, createdInputsFor, dastWayPast, defaultProof, fullRun, judgeBuilt, NEVER_SKIPPED, parseSkip, runCreators, SCOPE_LINE, UNPINNED, WINDOWS_REFUSAL, GATE_UNREACHABLE, guardRecord, insertedBlock, type Built, type BuildInput, type GitHubFacts, type RunDeps, type RunStages } from '../src/cli/run.js';
import { assembledJobs, consentJobs, docFor, draftFromDebate, isAiNote, parseStrictness, pickOwners, prWaitMinutes, proofAssembler, proofLayout, warnFirstFor, signingFor } from '../src/cli/run-parts.js';
import { EXIT_UNSAFE_FOLDER, TYPE_CANCELLED } from '../src/cli/audit.js';
import { run as main, type Commands } from '../src/cli/main.js';
import { finishCommand, interactiveRun, updateCommand, verifyCommand } from '../src/cli/commands.js';
import type { CliIO, Prompter } from '../src/cli/io.js';
import { PromptCancelledError } from '../src/cli/io.js';
import { SecretVault } from '../src/create/secrets.js';
import type { DebateResult } from '../src/debate/debate.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { CALLER_WORKFLOW, NIGHTLY_WORKFLOW } from '../src/engine/job-rules.js';
import { floorNeeds, jobCategories, MINIMUM_CATEGORIES } from '../src/engine/needs.js';
import { estimate, needKeyCount } from '../src/estimate/estimate.js';
import { AssembleError } from '../src/layers/jobs.js';
import { DeliverError } from '../src/deliver/git-data.js';
import { pubKeySha256 } from '../src/engine/signing.js';
import { StateStore } from '../src/proof/state.js';
import type { CreatedFile, InstallRecord, Need, PipelineDraft, RepoProfile } from '../src/types.js';
import { fake } from './helpers/secret-repo.js';
import { betterleaksAt, CLEAN, makeStub } from './helpers/gitleaks-stub.js';
import { loadPinnedBinaries } from '../src/engine/linters.js';
import { proofWorld } from './helpers/proof-world.js';
import { API, CAPS, candidatesFor, choicesFor, need, NEEDS, profile, REVIEWED, scripted, svc } from './helpers/debate-fixtures.js';

const homes: string[] = [];
afterAll(() => { for (const h of homes) rmSync(h, { recursive: true, force: true }); });
const tmp = (prefix: string): string => { const h = mkdtempSync(join(tmpdir(), prefix)); homes.push(h); return h; };

const TK = fake.githubPat();
/** Key names built at runtime (the no-secret-literals rule reads `<name>: value` as a credential). */
const TK_KEY = ['to', 'ken'].join('');
const TL_KEY = ['tok', 'ens'].join('');
const SCANNER_DEP = ['secret', 'Scanner'].join('') as 'secretScanner';
const GA = ['get', 'Au', 'th'].join('') as 'getAuth';
const AF = ['au', 'th'].join('') as 'auth';
const SEC_STAGE = ['sec', 'rets'].join('') as 'secrets';
const PW_KEY = ['pass', 'word'].join('');
const GH_KEY = ['gh', 'To', 'ken'].join('');
const TODAY = '2026-11-06';
/** A made-up key-env pair (the PEM body lines and the password are known values for the run: sec M4). */
const KEY_BODY = ['QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo', 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo'];
const PEM_LABEL = ['ENCRYPTED SIGSTORE PRIV', 'ATE KEY'].join('');
const KEY_PEM = [`-----BEGIN ${PEM_LABEL}-----`, ...KEY_BODY, `-----END ${PEM_LABEL}-----`, ''].join('\n');
const KEY_PW = ['made', 'up', 'phrase', '4242'].join('-');
/** sec M2: v0.2 runs only on CrisWorking's repositories. */
const OWN = 'CrisWorking';

interface Answers { types?: 'cancel'; preview?: boolean; again?: boolean }
function io(answers: Answers = {}, over: Partial<CliIO> = {}): CliIO & { lines: string[]; errs: string[]; asked: string[] } {
  const lines: string[] = [];
  const errs: string[] = [];
  const asked: string[] = [];
  const prompt: Prompter = {
    confirm: async (msg) => {
      asked.push(msg);
      if (/Is this right/.test(msg)) { if (answers.types === 'cancel') throw new PromptCancelledError(); return true; }
      if (/more than the/.test(msg)) return answers.again ?? true;
      return answers.preview ?? true;
    },
    select: async (msg) => { asked.push(msg); if (answers.types === 'cancel') throw new PromptCancelledError(); throw new Error('no select'); },
    text: async (msg) => { asked.push(msg); throw new PromptCancelledError('no terminal'); },
  };
  return { prompt, out: (s) => { lines.push(s); }, err: (s) => { errs.push(s); }, env: {}, lines, errs, asked, ...over };
}

/** The app as read on disk (a node web service and a python api). */
const APP = svc({ name: 'app', path: '.', scripts: ['test', 'start'], frameworks: ['express'] });
const LOCAL = (over: Partial<RepoProfile> = {}): RepoProfile => profile({ owner: OWN, repo: 'r', monorepo: 'none', services: [APP], generatedDirs: [], ...over });

const facts = (over: Partial<GitHubFacts> = {}, ctx: Partial<GitHubFacts['context']> = {}): GitHubFacts => ({
  gh: {} as Octokit, clock: { budget: newRateBudget() }, login: 'alice',
  context: { private: true, ownerType: 'User', plan: 'pro', defaultBranch: 'main', ...ctx }, caps: CAPS,
  writers: ['alice', 'bob', 'carol'], lockWriters: { app: ['alice', 'bob'], central: ['alice', 'bob'] }, orgAdmin: null,
  shaPinning: { required: false } as unknown as GitHubFacts['shaPinning'], ids: { app: 1, central: 2 }, ...over,
});

const debateResult = (over: Partial<DebateResult> = {}): DebateResult => ({
  choices: choicesFor(NEEDS, profile()), needs: [...NEEDS], suggestions: [{ name: 'tool', repo: 'x/tool', why: 'why' }], disputes: [], transcript: ['the debate said so'],
  requireDeployApproval: true, candidates: candidatesFor(NEEDS, profile()), byCode: [], uncovered: [], ...over,
} as unknown as DebateResult);

const FILE = (path: string, repo: 'app' | 'central' = 'app', content = 'x\n'): CreatedFile => ({ repo, path, content, part: 'docs', reason: 'r' } as unknown as CreatedFile);

function builtOf(i: BuildInput, over: Partial<Built> = {}): Built {
  const draft = { ...i.draft, doc: { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 1, includedMinutes: 2000 }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [], credits: i.credits ?? [] } } as PipelineDraft;
  const files = [FILE('PIPEGEN.md'), ...(i.draft.profile.private ? [FILE('.github/workflows/r--merge.yml', 'central')] : [])];
  return {
    assembled: { draft, files: [], verify: {}, notes: [], uncoveredMinimum: [] } as unknown as Built['assembled'],
    verify: { inserts: [], notProven: [], gaps: [], notes: [], preview: [] } as unknown as Built['verify'],
    locks: { owners: { app: [], central: [] }, notes: [] } as unknown as Built['locks'],
    precommit: { files: [], edits: [], setupCommand: '', notes: [] } as unknown as Built['precommit'],
    doc: files[0] as CreatedFile, extra: [], files, report: { issues: [] } as unknown as Built['report'], guardProblems: [], environments: [],
    minutes: { jobs: { 'pre-commit': [], push: [], merge: [], deploy: [], nightly: [] }, prWait: 7 }, envNotes: [], hookNotes: [], ...over,
  };
}

/** A passing proof: proving → verdict → proven → cleaned. */
const passingProof: NonNullable<RunDeps['proof']> = async (x) => {
  const repos = await x.checkRepos?.();
  x.store.setStage('proving');
  x.store.recordVerdict({ ok: true, draft: x.draft });
  x.store.setStage('proven');
  x.store.setStage('cleaned');
  return { ok: true, ...(repos === undefined ? {} : { repos }) };
};

interface World {
  calls: string[]; got: Record<string, unknown[]>; vaults: SecretVault[]; builds: BuildInput[]; home: string;
  stages: Partial<RunStages>; deps: RunDeps;
}
function world(o: { local?: RepoProfile; facts?: GitHubFacts; debate?: DebateResult; who?: Record<string, unknown>; consent?: boolean; prState?: 'merged' | 'closed' | 'open'; built?: (i: BuildInput) => Built; record?: InstallRecord | null; central?: 'pinned' | 'central-pr'; gate?: boolean; missingRepos?: string[]; proof?: RunDeps['proof']; deps?: Partial<RunDeps>; found?: CodeBundle['found'] } = {}): World {
  const calls: string[] = [];
  const got: Record<string, unknown[]> = {};
  const vaults: SecretVault[] = [];
  const builds: BuildInput[] = [];
  const home = tmp('pg-run-');
  const ai = scripted(() => ({}));
  const rec = (name: string, ...args: unknown[]): void => { calls.push(name); got[name] = args; };
  const stages: Partial<RunStages> = {
    readOrigin: async (d) => { rec('readOrigin', d); return { owner: OWN, repo: 'r' }; },
    localProject: async (d) => { rec('localProject', d); return o.local ?? LOCAL(); },
    readProject: async (a, l) => { rec('readProject', a, l); return o.facts ?? facts(); },
    provider: () => { rec('provider'); return ai.ai; },
    bundle: async (d, k) => { rec('bundle', d, k); return { files: [] } as unknown as CodeBundle; },
    scan: async (d, c, k, agreed) => { rec('scan', d, c, k, agreed); return { files: [], found: o.found ?? { names: [], values: [], [TL_KEY]: [] } } as unknown as CodeBundle; },
    activity: async () => { rec('activity'); return { pushes: 10, prs: 5, capped: false }; },
    consent: async (f, p, prov, est, b, auth, extra, opts) => { rec('consent', f, p, prov, est, b, auth, extra, opts); return o.consent === false ? null : ({} as never); },
    state: async (p) => { rec('state', p); return StateStore.open(p, { home, env: {} }); },
    gateReachable: async () => { rec('gateReachable'); return o.gate ?? true; },
    helperRepos: async () => { rec('helperRepos'); return o.missingRepos ?? []; },
    proofRepos: async (f, p, auth, store, runId, actions) => { rec('proofRepos', f, p, auth, store, runId, actions); return { ready: true, target: {} as never, repos: [], created: [] }; },
    needs: async (p, caps, b, aiP, writers) => { rec('needs', p, caps, b, aiP, writers); return { needs: [...NEEDS], notes: [], requireDeployApproval: true, layersSkipped: [], usage: [] } as never; },
    discover: async () => { rec('discover'); return candidatesFor(NEEDS, profile()); },
    debate: async (...a) => { rec('debate', ...a); return o.debate ?? debateResult(); },
    creators: async (draft, b, aiP, d, vault) => { rec('creators', draft, b, aiP, d, vault); vaults.push(vault); vault.set('API_TK', 'typed-value-1234567890'); return { files: [], notes: [], testNotes: ['The AI explained: x', 'kept note'], testDecisions: [], notProven: [] }; },
    credits: async () => { rec('credits'); return [{ text: 'a credit', kind: 'push-default' }]; },
    build: async (i) => { rec('build', i); builds.push(i); return (o.built ?? ((x) => builtOf(x)))(i); },
    trusted: async () => { rec('trusted'); return { record: o.record ?? null, notes: [] }; },
    deliverCentral: async (f, p, files) => { rec('deliverCentral', files); return o.central === 'central-pr' ? { kind: 'central-pr', url: 'u', message: 'central PR opened; merge it, then run pipegen again' } : { kind: 'pinned', sha: 'c'.repeat(40), done: ['central files'] }; },
    readCentralFileList: async () => { rec('readCentralFileList'); return ['.github/workflows/r--merge.yml', 'installs/r.json']; },
    preview: (input) => { rec('preview', input); return 'THE PREVIEW'; },
    signingKey: async () => { rec('signingKey'); return { key: KEY_PEM, [PW_KEY]: KEY_PW, pub: 'PUB' } as never; },
    deliver: async (_f, _p, input, _v, _io, key) => { rec('deliver', input, key); return { prUrl: 'https://github.com/o/r/pull/3', prNumber: 3, centralSha: null, recordHash: 'h', done: [], skipped: [], notes: ['delivery note'] } as never; },
    prState: async () => { rec('prState'); return o.prState ?? 'merged'; },
    finish: async () => { rec('finish'); return 0; },
  };
  stages[GA] = async (x) => { rec('getAuth', x); return { kind: 'fine-grained', [TK_KEY]: TK, canCreateRepos: false, canDeleteRepos: false, ...o.who } as never; };
  stages[SEC_STAGE] = async (_p, _c, vault) => { rec('secrets'); return { names: vault.names(), missing: [], notes: [] }; };
  const deps: RunDeps = {
    platform: 'linux', today: () => TODAY, now: () => Date.parse('2026-11-06T10:00:00Z'), sleep: async () => {}, stages, runId: () => '20261106-100000-abc123',
    proof: o.proof ?? passingProof, reviewed: () => REVIEWED, platformActions: async () => ({}) as never, ...o.deps,
  };
  return { calls, got, vaults, builds, home, stages, deps };
}

const run = (w: World, i: ReturnType<typeof io> = io()): Promise<number> => fullRun('/repo', i, w.deps);

// ---------- parseSkip ----------

describe('G13: --skip', () => {
  it('skip: comma list parsed into draft.skipped with reason', () => {
    expect(parseSkip('tests,docker', TODAY)).toEqual([
      { part: 'tests', reason: `skipped with --skip on ${TODAY}` },
      { part: 'docker', reason: `skipped with --skip on ${TODAY}` },
    ]);
    expect(parseSkip(undefined, TODAY)).toEqual([]);
    expect(parseSkip('', TODAY)).toEqual([]);
  });
  it('skip: secrets or gate → error', () => {
    expect(() => parseSkip('secrets', TODAY)).toThrow(NEVER_SKIPPED);
    expect(() => parseSkip('tests,gate', TODAY)).toThrow('Secrets scanning and the gate can never be skipped.');
    expect(() => parseSkip(' Gate ', TODAY)).toThrow(NEVER_SKIPPED);
  });
  it('skip: unknown part → error listing valid parts', () => {
    expect(() => parseSkip('tests,lint', TODAY)).toThrow(/"lint".*tests, precommit, docker, compose, deploy, locks, slack, test-migration/);
  });
  it('skip: spaces and duplicates removed', () => {
    expect(parseSkip(' tests , tests,docker ,, ', TODAY).map((s) => s.part)).toEqual(['tests', 'docker']);
  });
  it('run: a bad --skip stops before anything is read', async () => {
    const w = world({ deps: { flags: { skip: 'gate' } } });
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(w.calls).toEqual([]);
    expect(i.errs.join('\n')).toContain(NEVER_SKIPPED);
  });
});

// ---------- the order ----------

describe('G13: the run, in order', () => {
  it('run: stages execute in order and save state', async () => {
    const w = world();
    const i = io();
    const code = await run(w, i);
    expect(code).toBe(0);
    // G14 (ruling G14-R0 1): the read-only helper-repo check before consent; the writing one (checkProofRepos) inside the proof
    const order = ['readOrigin', 'localProject', 'getAuth', 'readProject', 'provider', 'bundle', 'helperRepos', 'activity', 'consent', 'state', 'needs', 'discover', 'debate', 'trusted', 'creators', 'secrets', 'credits', 'build', 'proofRepos', 'deliverCentral', 'readCentralFileList', 'build', 'preview', 'deliver', 'prState', 'finish'];
    expect(w.calls.filter((c) => order.includes(c))).toEqual(order);
    const store = await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} });
    expect(store.load()?.stage).toBe('delivered');
    expect(store.load()?.proofOk).toBe(true);
    expect(i.errs[0]).toBe(SCOPE_LINE);
    expect(i.lines.join('\n')).toContain('delivery note');
  });

  it('run: remote read before auth, auth before readProject', async () => {
    const w = world();
    await run(w);
    expect(w.calls.indexOf('readOrigin')).toBeLessThan(w.calls.indexOf('getAuth'));
    expect(w.calls.indexOf('localProject')).toBeLessThan(w.calls.indexOf('getAuth'));
    expect(w.calls.indexOf('getAuth')).toBeLessThan(w.calls.indexOf('readProject'));
    // exactly the app, the central repo and the scratch repo, write mode
    expect(w.got.getAuth?.[0]).toEqual({ owner: OWN, repos: ['r', 'pipelines', 'pipegen-proof-r'], allowBroad: false });
  });

  it('run: no Slack question in v0.2; --skip slack accepted', async () => {
    const w = world({ deps: { flags: { skip: 'slack' } } });
    const i = io();
    expect(await run(w, i)).toBe(0);
    expect(i.asked.some((q) => /slack/i.test(q))).toBe(false);
    expect((w.builds[0]?.draft.skipped ?? []).map((s) => s.part)).toEqual(['slack']);
  });

  it('run: SCOPE line: v0.2 is for CrisWorking-owned repos only, said first (carry 35)', async () => {
    const i = io();
    await run(world(), i);
    expect(i.errs[0]).toMatch(/CrisWorking only/);
  });
});

// ---------- before GitHub ----------

describe('G13: before any GitHub call', () => {
  it('run: native Windows without cleanup → refused before any GitHub write', async () => {
    const w = world({ deps: { platform: 'win32' } });
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(w.calls).toEqual([]);
    expect(i.errs.join('\n')).toContain(WINDOWS_REFUSAL);
  });

  it('run: --type is parsed, applied and confirmed before consent and before any GitHub call', async () => {
    // a bad --type: exit 1, nothing read from GitHub
    const bad = world({ deps: { flags: { types: [{ service: 'nope', type: 'server' }] } } });
    const i = io();
    expect(await run(bad, i)).toBe(1);
    expect(bad.calls).toEqual(['readOrigin', 'localProject']);
    expect(i.errs.join('\n')).toMatch(/No service is named nope/);
    expect(i.errs.join('\n')).not.toMatch(/pipegen run failed/);
    // a good one is applied to the profile everything after it sees
    const good = world({ deps: { flags: { types: [{ service: 'app', type: 'static-site' }] } } });
    expect(await run(good)).toBe(0);
    const p = good.got.consent?.[1] as RepoProfile;
    expect(p.services.find((s) => s.name === 'app')?.projectType).toMatchObject({ types: ['static-site'], overridden: true });
    // at a terminal, a cancel of the type question: exit 0, nothing read from GitHub
    const cancel = world();
    const ci = io({ types: 'cancel' }, { interactive: true });
    expect(await run(cancel, ci)).toBe(0);
    expect(cancel.calls).toEqual(['readOrigin', 'localProject']);
    expect(ci.errs.join('\n')).toContain(TYPE_CANCELLED);
  });
});

// ---------- consent ----------

describe('G13: estimate and consent', () => {
  it('run: consent estimate uses jobCategories(floorNeeds) with nightly and 2 variants', async () => {
    const w = world();
    await run(w);
    const p = w.got.consent?.[1] as RepoProfile;
    const est = w.got.consent?.[3];
    const jobs = jobCategories(floorNeeds(p, CAPS).filter((n) => !((n.category === 'signing' || n.category === 'attestation') && !n.blocking)));
    expect(jobs.nightly.length).toBeGreaterThan(0);
    expect(est).toEqual(estimate(p, jobs, 2, { pushes: 10, prs: 5, capped: false }, w.got.consent?.[2] as never, { needKeys: needKeyCount(floorNeeds(p, CAPS)) }));
    expect(est).not.toEqual(estimate(p, jobs, 1, { pushes: 10, prs: 5, capped: false }, w.got.consent?.[2] as never, { needKeys: needKeyCount(floorNeeds(p, CAPS)) }));
  });

  it('run: estimate gets needKeys from the debate plan', async () => {
    const w = world();
    await run(w);
    const p = w.got.consent?.[1] as RepoProfile;
    const est = w.got.consent?.[3];
    expect(needKeyCount(floorNeeds(p, CAPS))).toBeGreaterThan(0);
    expect(est).not.toEqual(estimate(p, consentJobs(p, CAPS), 2, { pushes: 10, prs: 5, capped: false }, w.got.consent?.[2] as never));
  });

  it('run: estimate counts the org required workflow as a second merge run', () => {
    const p = LOCAL({ private: true, ownerType: 'Organization', plan: 'team' });
    const once = consentJobs({ ...p, plan: 'free' }, CAPS);
    expect(consentJobs(p, CAPS).merge).toEqual([...once.merge, ...once.merge]);
    expect(assembledJobs({ push: {}, merge: { a: {} as never }, nightly: {} }, [], p).merge).toEqual(['a', 'a']);
    expect(assembledJobs({ push: {}, merge: { a: {} as never }, nightly: {} }, [], { ...p, plan: 'free' }).merge).toEqual(['a']);
  });

  it('run: consent declined → exit 1, nothing created, vault empty', async () => {
    const w = world({ consent: false });
    expect(await run(w)).toBe(1);
    for (const s of ['state', 'proofRepos', 'needs', 'creators', 'secrets', 'build', 'deliver', 'deliverCentral']) expect(w.calls).not.toContain(s);
    expect(w.vaults).toEqual([]);
  });

  it('run: bootstrap switch checked before consent (assertBootstrapAllowed)', async () => {
    bootstrapOrder.length = 0;
    const w = world();
    const origConsent = w.stages.consent;
    w.stages.consent = async (...a) => { bootstrapOrder.push('consent'); return (origConsent as NonNullable<typeof origConsent>)(...a); };
    await run(w);
    expect(bootstrapOrder.slice(0, 2)).toEqual(['assertBootstrapAllowed', 'consent']);
    // refused (a release build with the switch on): no consent asked, exit 1
    bootstrapThrows = true;
    try {
      const w2 = world();
      expect(await run(w2)).toBe(1);
      expect(w2.calls).not.toContain('consent');
    } finally { bootstrapThrows = false; }
  });

  it('run: a service with no planted template is named before consent (the proof will end not-proven)', () => {
    const lines = notProvableNotes({ services: [API, svc({ name: 'svc-go', path: 'go', language: 'go' as never })] });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/svc-go.*no planted template.*not proven/);
    // in the run the lines reach the consent screen's caller (v0.2's support level stops a non-Node repo before that)
    expect(notProvableNotes(LOCAL())).toEqual([]);
  });

  it('run: consent estimate counts the assembled jobs', async () => {
    // 200 merge jobs: well over the consent estimate, which since G15a also counts the nightly extras (history scan, ZAP, Scorecard);
    // 60 jobs (600 min) fell under it (950 min) after the merge of G13 with G15a, so the re-ask was never reached
    const many = { 'pre-commit': [], push: [], merge: Array.from({ length: 200 }, () => 'sast'), deploy: [], nightly: [] };
    // more minutes than agreed: asked again; a no delivers nothing
    const w = world({ built: (i) => builtOf(i, { minutes: { jobs: many, prWait: 9 } }) });
    const i = io({ again: false });
    expect(await run(w, i)).toBe(1);
    expect(i.asked.some((q) => /more than the \d+ you agreed to/.test(q))).toBe(true);
    expect(w.calls).not.toContain('deliver');
    // the same or fewer: not asked again
    const w2 = world();
    const i2 = io();
    expect(await run(w2, i2)).toBe(0);
    expect(i2.asked.some((q) => /more than the/.test(q))).toBe(false);
    expect(i2.asked.find((q) => q.includes('THE PREVIEW'))).toMatch(/about 7 minutes at most/);
  });

  it('run: one AI meter per consent token, shared with the audit', async () => {
    let meter: AiSpendMeter | undefined;
    const w = world({ proof: async (x) => { meter = x.ai.meter; return passingProof(x); } });
    await run(w);
    const metered = w.got.needs?.[3];
    expect(meter).toBeInstanceOf(AiSpendMeter);
    expect(metered).toBe(meter?.provider);
    expect(w.got.debate?.[5]).toBe(metered);
    expect(w.got.creators?.[2]).toBe(metered);
    // the raw provider is never handed to an AI stage
    expect(metered).not.toBe(w.got.consent?.[2]);
  });
});

// ---------- stages 8-15 ----------

describe('G13: stages 8-15', () => {
  it('run: checkProofRepos gets canCreate and cleanupAfterProof gets canDeleteRepo from getAuth', async () => {
    const w = world({ who: { kind: 'app', canCreateRepos: true, canDeleteRepos: true } });
    await run(w);
    expect((w.got.proofRepos?.[2] as { canCreateRepos: boolean }).canCreateRepos).toBe(true);
    expect(w.got.proofRepos?.[4]).toBe('20261106-100000-abc123');
    // every pinned reviewed action the proof could run is checked against the scratch repo's settings
    expect((w.got.proofRepos?.[5] as string[]).length).toBeGreaterThan(0);
    expect((w.got.proofRepos?.[5] as string[]).every((a) => /^[^/]+\/[^@]+@[0-9a-f]{40}$/.test(a))).toBe(true);
    // G14, the cleanupAfterProof half: the proof gets getAuth's answer, and the production proof hands its canDeleteRepos to
    // cleanupAfterProof (after the proof and in the armed Ctrl-C hook)
    for (const may of [true, false]) {
      let given: { canDeleteRepos?: boolean } | undefined;
      const w2 = world({ who: { kind: 'app', canCreateRepos: true, canDeleteRepos: may }, proof: async (x) => { given = x[AF]; return passingProof(x); } });
      expect(await run(w2)).toBe(0);
      expect(given?.canDeleteRepos).toBe(may);
      const pw = await proofWorld({ input: { [AF]: given as never } });
      await pw.run();
      await pw.armed[0]?.cleanup({ signal: new AbortController().signal } as never);
      expect(pw.cleanupOpts.map((o) => o.canDeleteRepo)).toEqual([may, may]);
    }
  });

  it('run: works with a GitHub App token', async () => {
    const w = world({ who: { kind: 'app', canCreateRepos: true, canDeleteRepos: true } });
    const i = io();
    expect(await run(w, i)).toBe(0);
    expect(w.calls).toContain('deliver');
    expect(i.lines.join('\n')).not.toContain(TK);
  });

  it('run: planNeeds gets writers.length from listWriters', async () => {
    const w = world();
    await run(w);
    expect(w.got.needs?.[4]).toBe(3);
  });

  it('run: draft needs, byCode, uncovered, choices, suggestions and requireDeployApproval come from DebateResult', async () => {
    const d = debateResult({ uncovered: [{ key: 'k', why: 'w' }] as never });
    // no deploy exists: the approval is not applied (B-T1a)
    const w = world({ debate: d });
    await run(w);
    const b = w.builds[0] as BuildInput;
    expect(b.draft.needs).toEqual(d.needs);
    expect(b.draft.steps).toEqual(d.choices.map((c) => c.chosen));
    expect(b.draft.suggestions).toEqual(d.suggestions);
    expect(b.plan).toEqual({ needs: d.needs, candidates: d.candidates, uncovered: d.uncovered });
    expect(b.transcript).toEqual(d.transcript);
    expect(b.draft.requireDeployApproval).toBe(false);
    // a deploy exists: applied
    const w2 = world({ debate: d, local: LOCAL({ existingWorkflows: [{ path: '.github/workflows/deploy.yml', deploys: true, jobs: [] } as never] }) });
    await run(w2);
    expect(w2.builds[0]?.draft.requireDeployApproval).toBe(true);
    const dd = draftFromDebate({ ...b.draft }, d);
    expect(dd.byCode).toBe(d.byCode);
  });

  it('run: strictness level chosen (default Standard) fills draft.warnFirst; never a floor need', async () => {
    const extra = need('coverage', 'merge', 'web', true);
    // a floor need outside the minimum (a type check the floor holds): never warn-first, at any level
    const floorish = { ...need('unit-tests', 'merge', 'web'), floor: true };
    const typeNeed = need('dast', 'merge', 'web');
    const needs: Need[] = [extra, floorish, typeNeed, need('secrets', 'push', undefined)];
    const types = new Set([typeNeed.id]);
    expect(Object.keys(warnFirstFor(needs, 'standard', types, TODAY))).toEqual([extra.id]);
    expect(Object.keys(warnFirstFor(needs, 'starter', types, TODAY)).sort()).toEqual([extra.id, typeNeed.id].sort());
    expect(warnFirstFor(needs, 'strict', types, TODAY)).toEqual({});
    for (const level of ['starter', 'standard', 'strict'] as const) {
      const wf = warnFirstFor(needs, level, types, TODAY);
      expect(Object.keys(wf)).not.toContain(floorish.id);
      for (const n of needs) if ((MINIMUM_CATEGORIES as readonly string[]).includes(n.category)) expect(Object.keys(wf)).not.toContain(n.id);
    }
    expect(warnFirstFor([extra], 'standard', types, TODAY)[extra.id]).toEqual({ since: TODAY });
    expect(parseStrictness(undefined)).toBe('standard');
    expect(() => parseStrictness('lenient')).toThrow(/starter.*standard.*strict/);
    // in the run: the default level, recorded for PIPEGEN.md; --strictness strict leaves warnFirst empty
    const w = world();
    await run(w);
    expect(w.builds[0]?.strictness).toBe('standard');
    for (const n of w.builds[0]?.draft.needs ?? []) if (n.floor) expect(Object.keys(w.builds[0]?.draft.warnFirst ?? {})).not.toContain(n.id);
    const ws = world({ deps: { flags: { strictness: 'strict' } } });
    await run(ws);
    expect(ws.builds[0]?.draft.warnFirst).toEqual({});
    const bad = world({ deps: { flags: { strictness: 'lenient' } } });
    expect(await run(bad)).toBe(1);
    expect(bad.calls).toEqual([]);
  });

  it('run: blockFromRecorded comes from the earlier record\'s blockFrom, never from the delivery day', async () => {
    const w = world();
    await run(w);
    expect(w.builds[0]?.draft.gateSettings?.blockFromRecorded).toBeUndefined();
    const w2 = world({ record: { blockFrom: '2026-10-01', edits: [], files: [] } as unknown as InstallRecord });
    await run(w2);
    expect(w2.builds[0]?.draft.gateSettings?.blockFromRecorded).toBe('2026-10-01');
    expect(w2.builds[0]?.prev).toMatchObject({ blockFrom: '2026-10-01' });
  });

  it('run: the creators\' AI note never reaches draft.doc', async () => {
    const w = world();
    await run(w);
    expect(w.builds[0]?.testNotes).toEqual(['kept note']);
    expect(isAiNote('The AI explained: anything')).toBe(true);
    const doc = docFor({ transcript: [], verify: { gaps: [], notes: ['The AI explained: a'], preview: [] }, locks: { notes: [], gateRequired: true }, precommit: { setupCommand: '', notes: [] }, jobs: { notes: [], uncoveredMinimum: [] }, assembledNotes: [], testNotes: ['The AI explained: b', 'ok'], credits: [], estimates: { monthlyMinutes: 1, includedMinutes: 2 }, prWaitMinutes: 3, strictness: 'standard' });
    expect(JSON.stringify(doc)).not.toMatch(/The AI explained/);
    expect(doc.testNotes).toEqual(['ok']);
  });

  it('run: draft.doc is filled: deployGaps, lockNotes, setupCommand, uncoveredMinimum, notes, credits, estimates, strictness', () => {
    const doc = docFor({
      transcript: ['t'], verify: { gaps: [{ path: '.github/workflows/d.yml', triggers: ['push'], why: 'w' }] as never, notes: ['verify note', 'jobs note'], preview: ['preview note'] },
      locks: { notes: ['lock note'], gateRequired: false }, precommit: { setupCommand: 'npm run prepare', notes: ['hook note'] },
      jobs: { notes: ['jobs note'], uncoveredMinimum: [{ category: 'sast', why: 'none', service: 'web' }] as never }, assembledNotes: ['assembled note'],
      testNotes: [], credits: [{ text: 'c', kind: 'hooks-ci' }], estimates: { monthlyMinutes: 120, includedMinutes: 2000 }, prWaitMinutes: 14, strictness: 'strict',
    });
    expect(doc.deployGaps).toEqual([{ path: '.github/workflows/d.yml', triggers: ['push'], why: 'w' }]);
    expect(doc.lockNotes).toEqual(['lock note']);
    expect(doc.setupCommand).toBe('npm run prepare');
    expect(doc.uncoveredMinimum).toEqual([{ category: 'sast', why: 'none', service: 'web' }]);
    expect(doc.notes).toEqual(['jobs note', 'assembled note', 'hook note', 'verify note', 'preview note']);
    expect(doc.credits).toEqual([{ text: 'c', kind: 'hooks-ci' }]);
    expect(doc.estimates).toEqual({ monthlyMinutes: 120, includedMinutes: 2000, prWaitMinutes: 14, strictness: 'Strict' });
    expect(doc.gateRequired).toBe(false);
    expect(doc.transcript).toEqual(['t']);
  });

  it('run: the workflow-call note (VerifyPlan.notes) lands in draft.doc.notes for PIPEGEN.md (G7 spec m3)', () => {
    const note = 'it is started by workflow_call, not only by a push, so pipegen adds no check to it';
    const doc = docFor({ transcript: [], verify: { gaps: [], notes: [note], preview: [] }, locks: { notes: [], gateRequired: true }, precommit: { setupCommand: '', notes: [] }, jobs: { notes: [], uncoveredMinimum: [] }, assembledNotes: [], testNotes: [], credits: [], estimates: { monthlyMinutes: 1, includedMinutes: 2 }, prWaitMinutes: 1, strictness: 'standard' });
    expect(doc.notes).toContain(note);
  });

  it('run: credits come from the audit\'s coverage map: no child process, no AI (ruling G13-R0 13)', async () => {
    const dir = tmp('pg-credits-');
    mkdirSync(join(dir, '.husky'), { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', scripts: { test: 'vitest' } }));
    writeFileSync(join(dir, '.husky', 'pre-commit'), 'npx gitleaks protect --staged\n');
    childCalls.length = 0;
    const p = LOCAL({ services: [svc({ name: 'app', path: '.' })] });
    const credits = await auditCredits(p, { capabilities: CAPS }, dir);
    expect(childCalls).toEqual([]);
    expect(Array.isArray(credits)).toBe(true);
    for (const c of credits ?? []) expect(['push-default', 'hooks-ci', 'signing', 'deploy-gate']).toContain(c.kind);
    // spec M4: the audit's own options: the skipped workflows counted from the reader's notes, buildsNoImage, no branchGuess
    mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
    writeFileSync(join(dir, '.github', 'workflows', 'bad.yml'), 'on: [push\njobs: {\n');
    let opts: Parameters<typeof mapCoverage>[3] | undefined;
    const seen = await auditCredits(LOCAL({ services: [svc({ name: 'app', path: '.' }), svc({ name: 'img', path: 'img', dockerfile: 'Dockerfile' })] }), { capabilities: CAPS }, dir, async (_p, _n, _d, o) => {
      opts = o;
      return [{ credit: 'c1', creditKind: 'hooks-ci', status: 'covered' }, { credit: 'c1', creditKind: 'hooks-ci', status: 'covered' }, { status: 'missing' }] as never;
    });
    expect(seen).toEqual([{ text: 'c1', kind: 'hooks-ci' }]);
    expect(opts?.skippedWorkflows).toBe(1);
    expect(opts?.capabilities).toBe(CAPS);
    expect(opts).not.toHaveProperty('branchGuess');
    expect(opts?.noImage?.({ service: 'app' } as Need)).toBe(true);
    expect(opts?.noImage?.({ service: 'img' } as Need)).toBe(false);
    // and the run passes them to the build (doc.credits)
    const w = world();
    await run(w);
    expect(w.builds[0]?.credits).toEqual([{ text: 'a credit', kind: 'push-default' }]);
  });

  it('run: draft.signing holds only services that build an image', async () => {
    // the fixture app publishes no image: no signing plan at all (a plan for no-image services is refused by the referee)
    expect(signingFor(LOCAL(), CAPS)).toBeUndefined();
    const w = world();
    await run(w);
    expect(w.builds[0]?.draft.signing).toBeUndefined();
    expect(w.calls).not.toContain('signingKey');
    // an image service at the root with a Dockerfile: only that service, at its published repo, in the probed mode
    const img = LOCAL({ private: true, services: [{ ...APP, dockerfile: 'Dockerfile' }] });
    const s = signingFor(img, CAPS);
    expect(s?.mode).toBe('attest');
    expect(s?.images.map((x) => x.service)).toEqual(['app']);
    expect(signingFor({ ...img, private: false }, CAPS)?.mode).toBe('keyless');
    expect(signingFor(img, { ...CAPS, attestations: false, environments: false })).toBeUndefined();
    // a service with no image (a library) next to it: never in the plan
    const lib = LOCAL({ private: true, services: [{ ...APP, dockerfile: 'Dockerfile' }, svc({ name: 'lib', path: 'lib', scripts: [] })] });
    expect(signingFor(lib, CAPS)?.images.map((x) => x.service)).toEqual(['app']);
  });

  it('run: no Dockerfile is created for a hinted service, and no created image is scanned in its place', async () => {
    const dir = tmp('pg-creators-');
    const hinted = svc({ name: 'built-elsewhere', path: 'a', scripts: ['start'], containerHint: '.github/workflows/build.yml builds an image from a' });
    const plain = svc({ name: 'plain', path: 'b', scripts: ['start'] });
    // set to container by the user, with no Dockerfile: "pipegen would create one" is not acted on (the C2 extension)
    const told = svc({ name: 'told-container', path: 'c', scripts: ['start'], projectType: { types: ['container'], evidence: ['set to container by you'], unsure: false, overridden: true } as never });
    const asked: string[] = [];
    const draft = { profile: LOCAL({ services: [hinted, plain, told] }), skipped: [] } as unknown as PipelineDraft;
    const vault = new SecretVault();
    const r = await runCreators(draft, { files: [] } as unknown as CodeBundle, scripted().ai, dir, vault, REVIEWED, {
      dockerfile: async (s) => { asked.push(s.name); return { files: [], notes: [] } as never; },
      tests: async (s) => ({ decision: { service: s.name, reasons: [], choice: 'keep' }, files: [] }) as never,
      compose: () => ({ file: null, notes: [] }) as never,
    });
    expect(asked).toEqual(['plain']);
    expect(r.files).toEqual([]);
    vault.wipe();
  });

  it('run: isolatedTestJob never passed', async () => {
    const dir = tmp('pg-tests-');
    writeFileSync(join(dir, 'package.json'), '{"name":"x","workspaces":["b"]}');
    mkdirSync(join(dir, 'b'));
    writeFileSync(join(dir, 'b', 'package.json'), '{"name":"b"}');
    const s = svc({ name: 'b', path: 'b', hasTests: false });
    const starters: unknown[] = [];
    const draft = { profile: LOCAL({ services: [s] }), skipped: [] } as unknown as PipelineDraft;
    const vault = new SecretVault();
    await runCreators(draft, { files: [] } as unknown as CodeBundle, scripted().ai, dir, vault, REVIEWED, {
      dockerfile: async () => ({ files: [], notes: [] }) as never,
      tests: async (sv, _p, _b, d) => { starters.push(d.starter); return { decision: { service: sv.name, reasons: [], choice: 'keep' }, files: [] } as never; },
      compose: () => ({ file: null, notes: [] }) as never,
    });
    expect(starters).toHaveLength(1);
    expect(Object.hasOwn(starters[0] as object, 'isolatedTestJob')).toBe(false);
    // carry 52: the package.json as on disk, a workspace member (fail closed), the reviewed list
    expect(starters[0]).toMatchObject({ packageJson: '{"name":"b"}', packageLock: null, workspaceMember: true });
    vault.wipe();
    const inputs = createdInputsFor({ vault: new SecretVault() }, { appCo: { path: null, text: '', isSymlink: false, block: null, inserted: null }, centralCo: { path: null, text: '', isSymlink: false, block: null, inserted: null }, pipegenDoc: { baseSha: null, recordSha: null }, serviceTypes: {} });
    expect(Object.hasOwn(inputs, 'isolatedTestJob')).toBe(false);
  });
});

// ---------- the referee and the guard ----------

describe('G13: one referee call and the guard on the same batch', () => {
  const facts0 = { appCo: { path: 'CODEOWNERS', text: 'x', isSymlink: false, block: null, inserted: null }, centralCo: { path: null, text: '', isSymlink: false, block: null, inserted: null }, pipegenDoc: { baseSha: null, recordSha: 'a'.repeat(40) }, serviceTypes: { web: 'module' as const }, baseTree: { complete: true, entries: new Map() }, texts: new Map<string, string>() };
  const input = (vault: SecretVault, centralFiles?: string[]): BuildInput => ({ dir: '/repo', draft: {} as PipelineDraft, plan: {} as never, facts: facts(), vault, reviewed: REVIEWED, platform: { checkout: {} } as never, owners: [], strictness: 'standard', transcript: [], testNotes: [], est: {} as never, ...({ [['au', 'th'].join('')]: { kind: 'app', [TK_KEY]: TK } } as unknown as Pick<BuildInput, 'auth'>), credits: [], prev: null, ...(centralFiles === undefined ? {} : { centralFiles }) });

  it('run: referee gets platform, reviewed, linters and the token (also inside the fix loop)', async () => {
    const vault = new SecretVault();
    vault.set('K', 'value-one-two-three');
    let judged: unknown[] = [];
    let guarded: unknown[] = [];
    const hook = FILE('.husky/pre-commit');
    const assembled = { draft: { profile: LOCAL(), created: [hook] }, files: [FILE('.github/workflows/pipegen.yml')] } as never;
    const doc = FILE('PIPEGEN.md');
    const r = await judgeBuilt(input(vault, ['a.yml']), { assembled, files: [hook, FILE('.github/workflows/pipegen.yml'), doc, FILE('x.yml', 'central')], verify: { inserts: [{ path: '.github/workflows/deploy.yml' }] } as never, extra: [doc] }, facts0, {
      linters: () => ({ actionlint: 'a' }) as never,
      judge: (async (...a: unknown[]) => { judged = a; return { issues: [] }; }) as never,
      guard: (async (...a: unknown[]) => { guarded = a; return { ok: [], refused: [{ path: 'Dockerfile', reason: 'no .dockerignore' }], notes: [] }; }) as never,
    });
    expect(judged[0]).toBe(assembled);
    const deps = judged[1] as Record<string, unknown> & { refereeDeps: { vault: unknown; createdInputs: Record<string, unknown> } };
    expect(deps.platform).toEqual({ checkout: {} });
    expect(deps.reviewed).toBe(REVIEWED);
    expect(deps.linters).toEqual({ actionlint: 'a' });
    expect(deps[GH_KEY]).toBe(TK);
    expect(deps.refereeDeps.vault).toBe(vault);
    expect(deps.extra).toEqual([doc]);
    const ci = deps.refereeDeps.createdInputs;
    expect(ci.centralFiles).toEqual(['a.yml']);
    expect(ci.pipegenDoc).toEqual({ baseSha: null, recordSha: 'a'.repeat(40) });
    expect(ci.serviceTypes).toEqual({ web: 'module' });
    expect(ci.centralCodeowners).toBeNull();
    expect((ci.containsKnownValue as (t: string) => boolean)('has value-one-two-three in it')).toBe(true);
    // the guard: the app files of the same batch (the hook file among them), the vault, the reviewed closure, the inserted paths
    expect((guarded[0] as CreatedFile[]).map((f) => f.path)).toEqual(['.husky/pre-commit', '.github/workflows/pipegen.yml', 'PIPEGEN.md']);
    const ctx = guarded[1] as Record<string, unknown>;
    expect(ctx.vault).toBe(vault);
    expect(ctx.closure).toBeDefined();
    expect(ctx.allowWorkflowInsert).toEqual(['.github/workflows/deploy.yml']);
    expect(Object.hasOwn(ctx, 'isolatedTestJob')).toBe(false);
    expect(r.guardProblems).toEqual(['Dockerfile: no .dockerignore']);
    vault.wipe();
  });

  it('run: the referee judges AssembledFiles.draft, in the run and in makeFixReferee', async () => {
    // judgeBuilt hands judgeAssembled the AssembledFiles whose draft the jobs were rendered from (fix.test.ts covers makeFixReferee)
    let got: unknown;
    const assembled = { draft: { profile: LOCAL(), created: [] }, files: [] } as never;
    await judgeBuilt(input(new SecretVault()), { assembled, files: [], verify: { inserts: [] } as never, extra: [] }, facts0, { linters: () => ({}) as never, judge: (async (a: unknown) => { got = a; return { issues: [] }; }) as never, guard: (async () => ({ ok: [], refused: [], notes: [] })) as never });
    expect(got).toBe(assembled);
  });

  it('run: precommit files go through the guard and the referee', async () => {
    // a refused hook file (guard) or an issue (referee) stops the run before the proof, exit 2
    const w = world({ built: (i) => builtOf(i, { guardProblems: ['.husky/pre-commit: refused'] }) });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(i.errs.join('\n')).toContain('.husky/pre-commit: refused');
    expect(w.calls).not.toContain('deliver');
    const w2 = world({ built: (x) => builtOf(x, { report: { issues: [{ file: '.husky/pre-commit', message: 'bad' }] } as never }) });
    expect(await run(w2)).toBe(2);
    expect(w2.calls).not.toContain('deliverCentral');
  });

  it('run: the guard\'s record and the CODEOWNERS block come only from the trusted record', () => {
    const prev = { files: [{ repo: 'app', path: 'Dockerfile', part: 'docker', shas: ['a', 'b'] }, { repo: 'app', path: 'x', part: 'docs', shas: ['c'], adopted: true }, { repo: 'central', path: 'y', part: 'docs', shas: ['d'] }], edits: [{ repo: 'app', path: 'CODEOWNERS', kind: 'codeowners', inserted: 'BLOCK\n' }] } as unknown as InstallRecord;
    expect(guardRecord(prev)).toEqual({ files: [{ path: 'Dockerfile', part: 'docker', sha: 'b', created: true }, { path: 'x', part: 'docs', sha: 'c', created: false }] });
    expect(guardRecord(null)).toBeNull();
    expect(insertedBlock(prev, 'app', { path: 'CODEOWNERS', text: 'a\nBLOCK\n', isSymlink: false, block: null })).toBe('BLOCK\n');
    expect(insertedBlock(prev, 'app', { path: 'CODEOWNERS', text: 'BLOCK\nBLOCK\n', isSymlink: false, block: null })).toBeNull();
    expect(insertedBlock(null, 'app', { path: 'CODEOWNERS', text: 'BLOCK\n', isSymlink: false, block: 'BLOCK\n' })).toBeNull();
  });
});

// ---------- the proof seam ----------

describe('G13: the proof seam', () => {
  // G14 (ruling G14-R0 2) replaces G13's `run: the production proof seam stops before delivery with exit 2 (ruling G13-R0 1)`
  it('run: the production default runs the proof; no RunDeps path skips it', async () => {
    // no proof given: the production one runs (here it refuses, fail closed, because the fake build gives it no fix-loop referee)
    const w = world({ deps: { proof: undefined } });
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(i.errs.join('\n')).toMatch(/no referee for the proof's fix loop/);
    expect(w.calls).toContain('consent');
    for (const s of ['deliverCentral', 'deliver', 'preview', 'finish']) expect(w.calls).not.toContain(s);
    expect(w.vaults[0]?.names()).toEqual([]);
    // the seam is called once, always: no flag, stage or dep goes around it, and the G13 stand-in is gone
    const src = readFileSync(join(process.cwd(), 'src/cli/run.ts'), 'utf8');
    expect(src.match(/\(deps\.proof \?\? defaultProof\)\(/g)?.length).toBe(1);
    expect(src).not.toMatch(/PROOF_NOT_BUILT|deps\.proof === undefined/);
    expect(typeof defaultProof).toBe('function');
    // spec M5: the refusal above is the production proof's own (run-proof.ts makeRunProof), not a run.ts shortcut: the proof was entered
    const proofSrc = readFileSync(join(process.cwd(), 'src/cli/run-proof.ts'), 'utf8');
    expect(proofSrc).toContain('pipegen has no referee for the proof');
    expect(src).not.toContain('no referee for the proof');
    // with a fix-loop build it goes further: the production proof assembles its files (its own assembler refuses this fake draft's tool)
    const w2 = world({ deps: { proof: undefined }, built: (x) => ({ ...builtOf(x), proof: { rebuild: async (d) => ({ files: [], assembled: d }), referee: async () => ({ ok: true, issues: [], demoted: [], notes: [] }), guard: async (f) => ({ ok: f, refused: [], notes: [] }) } }) });
    const i2 = io();
    expect(await run(w2, i2)).not.toBe(0);
    expect(i2.errs.join('\n')).toMatch(/not a reviewed tool pipegen offered/);
    for (const s of ['deliverCentral', 'deliver', 'preview', 'finish']) expect(w2.calls).not.toContain(s);
  });

  it('run: no delivery without the stage cleaned and a passed verdict', async () => {
    // the proof says ok but never cleaned up: no delivery
    const w = world({ proof: async () => ({ ok: true }) });
    expect(await run(w)).toBe(2);
    expect(w.calls).not.toContain('deliverCentral');
  });

  it('run: the proof layout drops pull_request_review and the nightly file', () => {
    const caller = FILE(CALLER_WORKFLOW, 'app', 'on:\n  pull_request:\n  pull_request_review:\n    types: [submitted]\njobs: {}\n');
    const files = proofLayout([caller, FILE(NIGHTLY_WORKFLOW), FILE('.github/workflows/r--nightly.yml', 'central'), FILE('Dockerfile')]);
    expect(files.map((f) => f.path)).toEqual([CALLER_WORKFLOW, 'Dockerfile']);
    expect(files[0]?.content).not.toContain('pull_request_review');
    expect(files[0]?.content).toContain('pull_request');
    // the closure: signing none only, the signing plan dropped, the central commit the proof gives
    let seen: PipelineDraft | undefined;
    const draft = { profile: LOCAL(), signing: { mode: 'attest', images: [] }, centralPin: { repo: `${OWN}/pipelines`, sha: UNPINNED } } as unknown as PipelineDraft;
    const a = proofAssembler(draft, (d) => { seen = d; return { files: [caller] }; });
    expect(() => a('attest' as never, undefined)).toThrow(/signing mode none/);
    a('none', 'e'.repeat(40));
    expect(seen?.signing).toBeUndefined();
    expect(seen?.centralPin).toEqual({ repo: `${OWN}/pipelines`, sha: 'e'.repeat(40) });
  });

  it('run: public app with an unreachable gate stops before the proof with a plain message', async () => {
    const w = world({ gate: false, facts: facts({}, { private: false }) });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(i.errs.join('\n')).toContain(GATE_UNREACHABLE);
    for (const s of ['proofRepos', 'needs', 'creators', 'build']) expect(w.calls).not.toContain(s);
    // a private app needs no public gate read
    const w2 = world({ gate: false });
    expect(await run(w2)).toBe(0);
    expect(w2.calls).not.toContain('gateReachable');
  });
});

// ---------- delivery ----------

describe('G13: two-step delivery and after', () => {
  it('run: two-step delivery order: deliverCentral, re-pin, assemble, judge, readCentralFileList, preview, deliver', async () => {
    const w = world();
    expect(await run(w)).toBe(0);
    const i = (n: string, from = 0): number => w.calls.indexOf(n, from);
    const central = i('deliverCentral');
    const list = i('readCentralFileList');
    const build2 = i('build', central);
    expect(central).toBeGreaterThan(-1);
    expect(list).toBeGreaterThan(central);
    expect(build2).toBeGreaterThan(list);
    expect(i('preview')).toBeGreaterThan(build2);
    expect(i('deliver', build2)).toBeGreaterThan(i('preview'));
    // the first build is at the stand-in commit; the second at the pinned commit, with the central list
    expect(w.builds[0]?.draft.centralPin?.sha).toBe(UNPINNED);
    expect(w.builds[0]?.centralFiles).toBeUndefined();
    expect(w.builds[1]?.draft.centralPin).toEqual({ repo: `${OWN}/pipelines`, sha: 'c'.repeat(40) });
    // the same list reaches the referee (centralFiles) and the delivery (centralFileList)
    const listed = ['.github/workflows/r--merge.yml', 'installs/r.json'];
    expect(w.builds[1]?.centralFiles).toEqual(listed);
    expect((w.got.deliver?.[0] as { centralFileList: string[] }).centralFileList).toBe(w.builds[1]?.centralFiles);
    // only the project's own central workflows go to deliverCentral
    expect((w.got.deliverCentral?.[0] as CreatedFile[]).map((f) => f.path)).toEqual(['.github/workflows/r--merge.yml']);
  });

  it('run: deliver gets the helper repos pipegen created and the central Actions access level the proof changed (carries 16, 24)', async () => {
    expect(proofReposFor({ created: ['pipelines'], createdIds: { pipelines: 77 }, actionsAccess: { previous: 'none' } }, { scratchRepoId: 88 })).toEqual({
      central: { repoId: 77, createdByPipegen: true, actionsAccess: { previous: 'none' } }, scratch: { repoId: 88, createdByPipegen: true },
    });
    expect(proofReposFor({ created: [] }, {})).toEqual({ central: { createdByPipegen: false }, scratch: { createdByPipegen: false } });
    const w = world();
    w.stages.proofRepos = async () => ({ ready: true, target: {} as never, repos: [], created: [], actionsAccess: { previous: 'none' } });
    await run(w);
    expect((w.got.deliver?.[0] as { proofRepos: unknown }).proofRepos).toEqual({ central: { createdByPipegen: false, actionsAccess: { previous: 'none' } }, scratch: { createdByPipegen: false } });
  });

  it('run: a draft still at the stand-in central commit is never delivered (a second net under the re-pin)', async () => {
    const w = world({ built: (i) => builtOf({ ...i, draft: { ...i.draft, centralPin: { repo: `${OWN}/pipelines`, sha: UNPINNED } } }) });
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(w.calls).not.toContain('deliver');
    expect(w.calls).not.toContain('preview');
    expect(i.errs.join('\n')).toMatch(/no central commit pinned/);
  });

  it('run: a central pull request stops the run with exit 2 and its message', async () => {
    const w = world({ central: 'central-pr' });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(i.lines.join('\n')).toContain('central PR opened');
    expect(w.calls).not.toContain('deliver');
  });

  it('run: a public app delivers without a central commit', async () => {
    const w = world({ facts: facts({}, { private: false }) });
    expect(await run(w)).toBe(0);
    expect(w.calls).not.toContain('deliverCentral');
    expect(w.builds[0]?.draft.centralPin).toBeUndefined();
  });

  it('run: preview declined → nothing delivered, vault wiped', async () => {
    const w = world();
    const i = io({ preview: false });
    expect(await run(w, i)).toBe(1);
    expect(w.calls).not.toContain('deliver');
    expect(w.vaults).toHaveLength(1);
    expect(w.vaults[0]?.names()).toEqual([]);
    expect(i.errs.join('\n')).toMatch(/Nothing was delivered/);
  });

  it('run: what delivery says is shown: its notes, and on a DeliverError what it had stored (carry 19)', async () => {
    const w = world();
    w.stages.deliver = async () => { throw new DeliverError('the base moved', { leftovers: ['PIPEGEN_COSIGN_KEY in pipegen-signing'] }); };
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(i.errs.join('\n')).toContain('pipegen stopped: the base moved');
    expect(i.errs.join('\n')).toContain('left: PIPEGEN_COSIGN_KEY in pipegen-signing');
    const ok = world();
    const i2 = io();
    await run(ok, i2);
    expect(i2.lines.join('\n')).toContain('delivery note');
    expect(i2.lines.join('\n')).toContain('done: central files');
  });

  it('run: the vault is wiped on every exit (an error after the secrets too)', async () => {
    const w = world({ built: () => { throw new Error('boom'); } });
    expect(await run(w)).toBe(1);
    expect(w.vaults[0]?.names()).toEqual([]);
  });

  it('run: wait for the merge: merged → finish; open after 30 minutes → the finish commands; closed → nothing applied', async () => {
    const merged = world();
    expect(await run(merged)).toBe(0);
    expect(merged.calls).toContain('finish');
    let t = Date.parse('2026-11-06T10:00:00Z');
    const slept: number[] = [];
    const open = world({ prState: 'open', deps: { now: () => t, sleep: async (ms) => { slept.push(ms); t += ms; } } });
    const i = io();
    expect(await run(open, i)).toBe(0);
    expect(open.calls).not.toContain('finish');
    expect(slept.every((ms) => ms === 30_000)).toBe(true);
    expect(slept.length).toBe(60);
    expect(i.lines.join('\n')).toContain('After merging, run `npx pipegen finish`');
    expect(i.lines.join('\n')).toContain('npx pipegen finish --print');
    const closed = world({ prState: 'closed' });
    const ic = io();
    expect(await run(closed, ic)).toBe(0);
    expect(closed.calls).not.toContain('finish');
    expect(ic.lines.join('\n')).toMatch(/closed without merging: nothing was applied/);
  });

  it('run: key-env makes one key pair before the verify literal and hands deliver that pair; a recorded key makes none (carries 16, 60)', async () => {
    const keyCaps = { ...CAPS, attestations: false, environments: true, deploymentBranchPolicies: true };
    const local = LOCAL({ services: [{ ...APP, dockerfile: 'Dockerfile' }] });
    const seen: boolean[] = [];
    let scrubbed = '';
    const w = world({ local, facts: facts({ caps: keyCaps }), built: (i) => {
      // sec M4 (checked while the run holds them; both vaults are wiped at the end): the pair's password and private key lines are known values
      seen.push(i.vault.containsKnownValue(`x ${KEY_PW} y`), ...KEY_BODY.map((l) => i.vault.containsKnownValue(`k: ${l}`)), i.vault.containsKnownValue('typed-value-1234567890'));
      scrubbed = i.vault.scrubber()(`${KEY_PW} typed-value-1234567890`);
      return builtOf(i);
    } });
    const ki = io();
    const kc = await run(w, ki);
    expect(kc).toBe(0);
    expect(w.calls.filter((c) => c === 'signingKey')).toHaveLength(1);
    expect(w.calls.indexOf('signingKey')).toBeLessThan(w.calls.indexOf('build'));
    const plan = w.builds[0]?.draft.signing;
    expect(plan?.mode).toBe('key-env');
    expect(plan?.cosignPubSha256).toBe(pubKeySha256('PUB'));
    const handed = w.got.deliver?.[1] as (() => Promise<{ pub: string }>) | undefined;
    expect((await handed?.())?.pub).toBe('PUB');
    // sec M4: the pair's password and private key lines are known values for the build (referee, guard, doc), never delivered secret names
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every(Boolean)).toBe(true);
    expect(scrubbed).not.toMatch(/made-up|typed-value/);
    expect(((w.got.deliver?.[0] as Record<string, string[]>)[['secret', 'Names'].join('')] ?? []).some((n) => /COSIGN/.test(n))).toBe(false);
    // the record already names a key (finish --rotate-key): that hash, no pair made, none handed to deliver
    const w2 = world({ local, facts: facts({ caps: keyCaps }), record: { cosignPubSha256: 'b'.repeat(64), edits: [], files: [] } as unknown as InstallRecord });
    expect(await run(w2)).toBe(0);
    expect(w2.calls).not.toContain('signingKey');
    expect(w2.builds[0]?.draft.signing?.cosignPubSha256).toBe('b'.repeat(64));
    expect(w2.got.deliver?.[1]).toBeUndefined();
    // no image: no pair
    const w3 = world();
    await run(w3);
    expect(w3.calls).not.toContain('signingKey');
  });

  it('run: an owner list with no person stops before consent (G8-R2 I1); fewer than two owners gives no code-owner rule', async () => {
    const w = world({ facts: facts({ lockWriters: { app: ['dependabot[bot]'], central: [] } }) });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(w.calls).not.toContain('consent');
    expect(pickOwners({ app: ['alice'], central: ['alice'] }, 'alice')).toMatchObject({ owners: [] });
    expect(pickOwners({ app: ['bob', 'alice'], central: ['alice', 'bob'] }, 'alice')).toEqual({ owners: ['@alice', '@bob'], writers: 2 });
  });

  it('run: a hinted server\'s DAST stop names the way past', async () => {
    // the message as jobs.ts writes it (spec M3)
    const msg = 'The blocking check "dast" for "svc-a" can not run: no container. pipegen never makes it warn-only or leaves it out.';
    const lines = dastWayPast(msg, [{ name: 'svc-a', containerHint: 'compose.yml builds svc-a' }, { name: 'other' }, { name: 'svc', containerHint: 'x' }, { name: 'a', containerHint: 'x' }]);
    expect(lines).toHaveLength(1);
    // a hinted service whose name is only part of another's gets no line; another check's stop gives none
    expect(dastWayPast('The blocking check "dast" for "svc-ab" can not run: x.', [{ name: 'svc-a', containerHint: 'x' }])).toEqual([]);
    expect(dastWayPast('The blocking check "unit-tests" for "svc-a" can not run: x.', [{ name: 'svc-a', containerHint: 'x' }])).toEqual([]);
    expect(lines[0]).toMatch(/--type svc-a=static-site/);
    expect(lines[0]).toMatch(/add a Dockerfile/);
    expect(lines[0]).toMatch(/never skips the DAST check/);
    expect(dastWayPast('something else', [{ name: 'svc-a', containerHint: 'x' }])).toEqual([]);
    const hinted = svc({ name: 'svc-a', path: 'a', containerHint: 'compose.yml builds svc-a' });
    const w = world({ local: LOCAL({ services: [hinted] }), built: () => { throw new AssembleError(msg); } });
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(i.errs.join('\n')).toMatch(/--type svc-a=static-site/);
  });

  it('run: the PR wait is the longest needs chain of the merge jobs', () => {
    expect(prWaitMinutes({ a: { 'timeout-minutes': 5 }, b: { 'timeout-minutes': 10, needs: ['a'] }, c: { 'timeout-minutes': 3 } } as never)).toBe(15);
    expect(prWaitMinutes({})).toBe(0);
  });
});

// ---------- main.ts: the commands ----------

describe('G13: main dispatch', () => {
  const repoDir = (files: Record<string, string> = {}): string => {
    const dir = tmp('pg-main-');
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), '[remote "origin"]\n\turl = https://github.com/o/r.git\n');
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', scripts: { test: 'vitest run' } }));
    for (const [rel, body] of Object.entries(files)) writeFileSync(join(dir, rel), body);
    return dir;
  };
  const fakes = () => {
    const got: Record<string, unknown[]> = {};
    const g = { gh: {} as Octokit, login: 'alice' };
    const cmds: Partial<Commands> = {
      fullRun: async (...a) => { got.fullRun = a; return 0; },
      cleanup: async (...a) => { got.cleanup = a; return 0; },
      connect: async (...a) => { got.connect = a; return { app: { owner: 'o', repo: 'r' }, g, [TK_KEY]: TK } as never; },
      finish: async (...a) => { got.finish = a; return 0; },
      verify: async (...a) => { got.verify = a; return 1; },
      update: async (...a) => { got.update = a; return 0; },
    };
    return { got, cmds };
  };
  const mio = (cwd: string) => { const i = io({}, { cwd }); return i; };

  it('main: argv → main → resume; help lists resume; resume refuses --skip, --type and --strictness', async () => {
    const dir = repoDir();
    const { got, cmds } = fakes();
    expect(await main(['resume', '--dir', dir, '--allow-broad-token'], mio(tmpdir()), cmds)).toBe(0);
    expect(got.fullRun?.[0]).toBe(dir);
    expect(got.fullRun?.[2]).toMatchObject({ resume: true, flags: { allowBroad: true } });
    expect((got.fullRun?.[2] as RunDeps).flags).toEqual({ allowBroad: true });
    for (const bad of [['--skip', 'tests'], ['--type', 'app=static-site'], ['--strictness', 'starter']]) {
      const f = fakes();
      const e = mio(tmpdir());
      expect(await main(['resume', '--dir', dir, ...bad], e, f.cmds)).toBe(1);
      expect(e.errs.join('\n')).toMatch(new RegExp(`${bad[0]} works with pipegen (audit and pipegen )?run only`));
      expect(f.got.fullRun).toBeUndefined();
    }
    const h = mio(tmpdir());
    expect(await main(['--help'], h)).toBe(0);
    expect(h.lines.join('\n')).toMatch(/pipegen resume\s+Goes on with a run that stopped/);
    // fullRun itself refuses them too (a caller other than main)
    const w = world();
    const i = io();
    expect(await fullRun('/repo', i, { ...w.deps, resume: true, flags: { skip: 'tests' } })).toBe(1);
    expect(i.errs.join('\n')).toMatch(/resume takes no --skip, --type or --strictness/);
    expect(w.calls).toEqual([]);
  });

  it('main: argv → main → cleanupCommand (--dir, --allow-broad-token); help lists run, finish, verify, update, cleanup', async () => {
    const dir = repoDir();
    const { got, cmds } = fakes();
    expect(await main(['cleanup', '--dir', dir, '--allow-broad-token'], mio(tmpdir()), cmds)).toBe(0);
    expect(got.cleanup?.[0]).toBe(dir);
    expect(got.cleanup?.[2]).toEqual({ allowBroad: true });
    const h = mio(tmpdir());
    expect(await main(['--help'], h)).toBe(0);
    const help = h.lines.join('\n');
    for (const c of ['run', 'finish', 'verify', 'update', 'cleanup']) expect(help).toMatch(new RegExp(`pipegen ${c}\\b`));
    expect(help).toMatch(/npx pipegen\s+Audit this folder/);
    // spec M5: the help says what run does in this version (no proof step yet: it stops before spending anything)
    expect(help).not.toMatch(/proves it on a private test copy, then opens/);
    // G14: the proof exists now; the help says so (spec M5's "no proof step yet" is gone)
    expect(help).toMatch(/test copy \(the proof\), with its keys and branches cleaned up right after/);
    expect(help).not.toMatch(/no proof step yet/);
  });

  it('main: no command is still the audit; run, finish, verify, update take only their own flags', async () => {
    const dir = repoDir();
    const { got, cmds } = fakes();
    // the flags each command takes
    expect(await main(['run', '--dir', dir, '--skip', 'tests', '--strictness', 'strict', '--type', 'app=server'], mio(tmpdir()), cmds)).toBe(0);
    expect((got.fullRun?.[2] as RunDeps).flags).toEqual({ types: [{ service: 'app', type: 'server' }], allowBroad: false, skip: 'tests', strictness: 'strict' });
    expect(await main(['finish', '--dir', dir, '--print', '--rotate-key'], mio(tmpdir()), cmds)).toBe(0);
    expect(got.finish?.[2]).toEqual({ print: true, rotateKey: true });
    expect((got.connect?.[2] as { mode: string }).mode).toBe('write');
    // drift: verify's exit code 1 passes through; verify connects read-only
    expect(await main(['verify', '--dir', dir], mio(tmpdir()), cmds)).toBe(1);
    expect((got.connect?.[2] as { mode: string }).mode).toBe('read');
    expect(await main(['update', '--dir', dir], mio(tmpdir()), cmds)).toBe(0);
    expect(got.update).toBeDefined();
    // each option with its own command only
    for (const [argv, msg] of [
      [['finish', '--skip', 'tests'], '--skip works with pipegen run only.'],
      [['audit', '--skip', 'tests'], '--skip works with pipegen run only.'],
      [['verify', '--print'], '--print works with pipegen finish only.'],
      [['run', '--rotate-key'], '--rotate-key works with pipegen finish only.'],
      [['update', '--type', 'server'], '--type works with pipegen audit and pipegen run only.'],
      [['finish', '--strictness', 'strict'], '--strictness works with pipegen run only.'],
      [['run', '--json'], '--json works with pipegen audit only.'],
    ] as const) {
      const i = mio(dir);
      expect(await main([...argv], i, cmds), argv.join(' ')).toBe(1);
      expect(i.errs.join('\n')).toContain(msg);
    }
    // no command: the audit, never the run
    const before = Object.keys(got).length;
    const fetched: string[] = [];
    const i = io({}, { cwd: tmpdir(), fetch: (async (u: unknown) => { fetched.push(String(u)); return new Response('{}', { status: 404 }); }) as typeof fetch });
    await main(['--dir', dir, '--json'], i, cmds);
    expect(fetched.every((u) => u.startsWith('https://api.github.com/'))).toBe(true);
    expect(Object.keys(got).length).toBe(before);
    expect(i.lines.join('\n')).toMatch(/"profile"|"checks"|\{/);
  });

  it('run: unsafe folder stops with exit 4 before the type question, the remote read and any GitHub call', async () => {
    const dir = repoDir({ '.npmrc': 'registry=https://registry.example.invalid/\n' });
    for (const command of ['run', 'finish', 'verify', 'update', 'cleanup']) {
      const { got, cmds } = fakes();
      const i = io({ types: 'cancel' }, { cwd: dir, interactive: true });
      expect(await main([command], i, cmds), command).toBe(EXIT_UNSAFE_FOLDER);
      expect(got, command).toEqual({});
      expect(i.asked, command).toEqual([]);
    }
  });

  it('main: an error is one cleaned line with no token', async () => {
    const dir = repoDir();
    const { cmds } = fakes();
    cmds.finish = async () => { throw new Error(`boom with ${TK}`); };
    const i = mio(tmpdir());
    expect(await main(['finish', '--dir', dir], i, cmds)).toBe(1);
    expect(i.errs.join('\n')).toMatch(/pipegen finish failed: boom/);
    expect(i.errs.join('\n')).not.toContain(TK);
  });
});

// ---------- finish, verify, update: what they print ----------

describe('G13: finish, verify and update print their results', () => {
  const g = { gh: {} as Octokit, login: 'alice', local: { env: {} } };
  const app = { owner: 'o', repo: 'r' };

  it('finish --print: the commands, the applied and skipped steps, the record hash; exit 0', async () => {
    let deps: Record<string, unknown> = {};
    const i = io({}, { interactive: true, env: {} });
    const code = await finishCommand(i, app, { print: true }, g, (async (_gh: unknown, _a: unknown, _o: unknown, d: Record<string, unknown>) => {
      deps = d;
      return { applied: ['ruleset pipegen'], skipped: [{ what: 'org rule', why: 'not an org' }], notes: ['a note'], commands: ['gh api -X PUT x'], recordHash: 'f'.repeat(64), centralPrUrl: 'https://github.com/o/pipelines/pull/2' };
    }) as never);
    expect(code).toBe(0);
    const out = i.lines.join('\n');
    for (const s of ['applied: ruleset pipegen', 'skipped: org rule (not an org)', 'a note', 'gh api -X PUT x', `install record: sha256 ${'f'.repeat(64)}`, 'central pull request: https://github.com/o/pipelines/pull/2']) expect(out).toContain(s);
    expect(deps.interactive).toBe(true);
    expect(deps.local).toEqual({ env: {} });
    expect(typeof deps.cosignBin).toBe('function');
    expect(typeof deps.probe).toBe('function');
    // CI is never interactive (carry 18)
    const ci = io({}, { interactive: true, env: { CI: 'true' } });
    await finishCommand(ci, app, {}, g, (async (_g: unknown, _a: unknown, _o: unknown, d: Record<string, unknown>) => { deps = d; return { applied: [], skipped: [], notes: [] }; }) as never);
    expect(deps.interactive).toBe(false);
    expect(interactiveRun({ interactive: false, env: {} })).toBe(false);
  });

  it('verify: drift as a table → exit 1; none → exit 0', async () => {
    const i = io();
    expect(await verifyCommand(i, app, g, (async () => ({ drift: [{ what: 'environment pipegen-signing (default branch only)', expected: 'only main may use it', actual: 'any branch' }], warnings: ['w'], notes: ['n'] })) as never)).toBe(1);
    expect(i.lines.join('\n')).toContain('environment pipegen-signing (default branch only) | only main may use it | any branch');
    expect(i.lines.join('\n')).toContain('warning: w');
    const i2 = io();
    expect(await verifyCommand(i2, app, g, (async () => ({ drift: [], warnings: [], notes: [] })) as never)).toBe(0);
    expect(i2.lines.join('\n')).toMatch(/No drift/);
  });

  it('update: preview, PRs, prompts, ignored, refused and conflicts printed; an owner-edited file is listed, not overwritten', async () => {
    let deps: Record<string, unknown> = {};
    const i = io();
    expect(await updateCommand(i, app, g, (async (_g: unknown, _a: unknown, d: Record<string, unknown>) => {
      deps = d;
      return { done: true, preview: 'PREVIEW', prUrl: 'https://github.com/o/r/pull/9', prompts: [{ issue: 1, in: 'app', key: 'k', version: '1.2.3', patches: [] }], ignored: [{ issue: 2, in: 'app', why: 'old' }], refused: [{ issue: 3, in: 'central', why: 'differs', shown: 'both sides' }], conflicts: [{ repo: 'app', path: 'Dockerfile', why: 'you changed it' }], notes: ['n'] };
    }) as never)).toBe(0);
    const out = i.lines.join('\n');
    for (const s of ['PREVIEW', 'pull request: https://github.com/o/r/pull/9', 'issue #1', 'ignored: issue #2', 'refused: issue #3', 'both sides', 'not changed (your edits): Dockerfile: you changed it']) expect(out).toContain(s);
    expect(Array.isArray(deps.reviewed)).toBe(true);
    expect(deps.local).toEqual({ env: {} });
    expect(deps.interactive).toBe(false);
  });
});

// ---------- G13-R1 (fix round 1) ----------

/** A proof that saves `saved` with its pass and returns `returned` (the probe-P1 shape when they differ). */
const proofSaving = (change: (d: PipelineDraft) => PipelineDraft, ret: 'none' | 'saved' | 'other'): NonNullable<RunDeps['proof']> => async (x) => {
  const saved = change(x.draft);
  x.store.setStage('proving');
  x.store.recordVerdict({ ok: true, draft: saved });
  x.store.setStage('proven');
  x.store.setStage('cleaned');
  return ret === 'none' ? { ok: true } : ret === 'saved' ? { ok: true, draft: saved } : { ok: true, draft: x.draft };
};
const PROVEN = (d: PipelineDraft): PipelineDraft => ({ ...d, suggestions: [{ name: 'PROVEN', repo: 'x/proven', why: 'the fix loop' }] });

describe('G13-R1: consent, then the secret scan, then the AI', () => {
  it('run: the scan of the counted files runs after the yes and before any AI stage; a finding stops the run (sec I1)', async () => {
    const w = world();
    expect(await run(w)).toBe(0);
    const at = (n: string): number => w.calls.indexOf(n);
    expect(at('scan')).toBeGreaterThan(at('consent'));
    expect(at('scan')).toBeLessThan(at('needs'));
    const w2 = world({ found: { names: ['src/a.ts'], values: [], [TL_KEY]: [] } as unknown as CodeBundle['found'] });
    const i = io();
    expect(await run(w2, i)).toBe(2);
    expect(i.errs.join('\n')).toContain(SECRET_FOUND);
    for (const s of ['state', 'proofRepos', 'needs', 'discover', 'debate', 'creators', 'secrets']) expect(w2.calls).not.toContain(s);
    const w3 = world({ found: { names: [], values: ['API_TK'], [TL_KEY]: [] } as unknown as CodeBundle['found'] });
    expect(await run(w3)).toBe(2);
    expect(w3.calls).not.toContain('needs');
  });

  it('run: the REAL bundle and consent stages compose: the counting summary on the screen, the pinned scanner after the yes, only counted files (sec I1)', async () => {
    const dir = tmp('pg-run-real-');
    writeFileSync(join(dir, 'index.js'), 'console.log(1);\n');
    mkdirSync(join(dir, 'lib'));
    writeFileSync(join(dir, 'lib', 'a.js'), 'module.exports = 2;\n');
    const stub = makeStub(CLEAN).bin;
    const w = world({ consent: true });
    delete w.stages.bundle;
    delete w.stages.consent;
    delete w.stages.scan;
    const scanned: string[] = [];
    const gh = { request: async () => { throw new Error('no GitHub here'); } } as unknown as Octokit;
    w.deps.stages = { ...w.stages, readProject: async () => facts({ gh }) };
    w.deps[SCANNER_DEP] = async (name) => { scanned.push(name); return betterleaksAt(stub, loadPinnedBinaries().betterleaks.version) as never; };
    w.deps.stages.needs = async (_p, _c, b) => { w.calls.push('needs'); expect(b.files.map((f) => f.path).sort()).toEqual(['index.js', 'lib/a.js']); expect(b.secretScanChecked).toBe(true); return { needs: [...NEEDS], notes: [], requireDeployApproval: true, layersSkipped: [], usage: [] } as never; };
    const i = io();
    expect(await fullRun(dir, i, w.deps)).toBe(0);
    const screen = i.asked.find((q) => /at most 2 files/.test(q)) ?? i.errs.join('\n');
    expect(screen).toMatch(/at most 2 files/);
    expect(screen).toMatch(/before the betterleaks check/);
    expect(scanned).toEqual(['betterleaks']);
    expect(w.calls).toContain('needs');
    // a scanner other than the one the screen named is refused before any AI stage
    const w2 = world();
    delete w2.stages.bundle; delete w2.stages.consent; delete w2.stages.scan;
    w2.deps.stages = { ...w2.stages, readProject: async () => facts({ gh }) };
    w2.deps[SCANNER_DEP] = async () => betterleaksAt(stub, '0.0.1') as never;
    const i2 = io();
    expect(await fullRun(dir, i2, w2.deps)).toBe(1);
    expect(i2.errs.join('\n')).toMatch(/not the betterleaks/);
    expect(w2.calls).not.toContain('needs');
  });
});

describe('G13-R2: the scan checks the consent as the audit does (ruling G13-R2 5)', () => {
  it('scanCounted: the token is spent before the first await; another folder, provider, model or cap is refused', async () => {
    const dir = tmp('pg-run-tok-');
    writeFileSync(join(dir, 'index.js'), 'console.log(1);\n');
    const other = tmp('pg-run-tok2-');
    writeFileSync(join(other, 'index.js'), 'console.log(2);\n');
    const stub = makeStub(CLEAN).bin;
    const ensure = async () => betterleaksAt(stub, loadPinnedBinaries().betterleaks.version) as never;
    const gh = { request: async () => { throw new Error('no GitHub here'); } } as unknown as Octokit;
    /** One real run up to the scan: the token askConsent gave, and what the run agreed to (provider, cap). */
    type Got = { c: Parameters<typeof scanCounted>[1]; agreed: Parameters<typeof scanCounted>[4] };
    const capture = async (): Promise<Got> => {
      const w = world();
      delete w.stages.bundle; delete w.stages.consent;
      let got: Got | undefined;
      w.deps.stages = { ...w.stages, readProject: async () => facts({ gh }), scan: async (_d, c, _k, agreed) => { got = { c, agreed }; throw new Error('captured'); } };
      await fullRun(dir, io(), w.deps);
      if (got === undefined) throw new Error('no token');
      return got;
    };
    // the right folder, provider and cap: scanned; the same token again: refused (spent), even when both calls start at once
    const a = await capture();
    await expect(scanCounted(dir, a.c, [], ensure, a.agreed)).resolves.toBeDefined();
    await expect(scanCounted(dir, a.c, [], ensure, a.agreed)).rejects.toThrow(/already used/);
    const b = await capture();
    const [r1, r2] = await Promise.allSettled([scanCounted(dir, b.c, [], ensure, b.agreed), scanCounted(dir, b.c, [], ensure, b.agreed)]);
    expect([r1.status, r2.status].sort()).toEqual(['fulfilled', 'rejected']);
    // another folder
    const c = await capture();
    await expect(scanCounted(other, c.c, [], ensure, c.agreed)).rejects.toThrow(/another folder/);
    // another provider or model, another cap
    const d = await capture();
    await expect(scanCounted(dir, d.c, [], ensure, { ...d.agreed, ai: { ...d.agreed.ai, model: 'another-model' } })).rejects.toThrow(/another AI provider, model or cost cap/);
    const e = await capture();
    await expect(scanCounted(dir, e.c, [], ensure, { ...e.agreed, capUsd: (e.agreed.capUsd ?? 0) + 5 })).rejects.toThrow(/another AI provider, model or cost cap/);
  });
});

describe('G13-R1: before anything costs money', () => {
  it('run: a repository not owned by CrisWorking is refused before any GitHub call (sec M2)', async () => {
    const w = world();
    w.stages.readOrigin = async () => { w.calls.push('readOrigin'); return { owner: 'someone-else', repo: 'r' }; };
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(i.errs.join('\n')).toContain(NOT_IN_SCOPE('someone-else'));
    expect(w.calls).toEqual(['readOrigin']);
    // the owner compared without case
    const w2 = world({ local: LOCAL({ owner: 'crisworking' }) });
    w2.stages.readOrigin = async () => ({ owner: 'crisworking', repo: 'r' });
    expect(await run(w2)).toBe(0);
  });

  it('run: key-env with no memory folder is refused before consent (sec M4)', async () => {
    const keyCaps = { ...CAPS, attestations: false, environments: true, deploymentBranchPolicies: true };
    const local = LOCAL({ services: [{ ...APP, dockerfile: 'Dockerfile' }] });
    const w = world({ local, facts: facts({ caps: keyCaps }), deps: { isMemory: () => false } });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(i.errs.join('\n')).toContain(NO_MEMORY_FOLDER);
    expect(w.calls).not.toContain('consent');
    // no image to sign: the memory folder is not asked about
    const w2 = world({ deps: { isMemory: () => false } });
    expect(await run(w2)).toBe(0);
  });

  it('run: a central writer list with no person stops before consent (spec M7)', async () => {
    const w = world({ facts: facts({ lockWriters: { app: ['alice', 'bob'], central: ['renovate[bot]'] } }) });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(w.calls).not.toContain('consent');
    expect(i.errs.join('\n')).toMatch(/pipelines/);
    const w2 = world({ facts: facts({ lockWriters: { app: ['alice', 'bob'], central: [] } }) });
    expect(await run(w2)).toBe(2);
    expect(w2.calls).not.toContain('consent');
  });
});

describe('G13-R1: the meter, the state, the helper repos', () => {
  it('run: discover gets the metered provider and saves the meter after each call (sec I2, spec I1)', async () => {
    let meter: AiSpendMeter | undefined;
    const w = world({ proof: async (x) => { meter = x.ai.meter; return passingProof(x); } });
    let saves = 0;
    w.stages.discover = async (_n, _p, _f, _r, ai, onUsage) => {
      w.calls.push('discover');
      w.got.discover = [ai];
      onUsage(); saves += 1;
      return candidatesFor(NEEDS, profile());
    };
    const spy = vi.spyOn(StateStore.prototype, 'saveMeters');
    let saved: unknown[][] = [];
    try { expect(await run(w)).toBe(0); saved = [...spy.mock.calls]; } finally { spy.mockRestore(); }
    expect(saved.some(([m]) => (m as { aiUsedUsd?: number }).aiUsedUsd === 0)).toBe(true);
    expect(w.got.discover?.[0]).toBe(meter?.provider);
    expect(w.got.discover?.[0]).toBe(w.got.needs?.[3]);
    expect(saves).toBe(1);
  });

  it('run: stage created is saved after the creators and the secrets, before the build (spec M1)', async () => {
    const seen: Record<string, string | undefined> = {};
    const w = world();
    const read = async (): Promise<string | undefined> => (await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} })).load()?.stage;
    const creators = w.stages.creators as RunStages['creators'];
    w.stages.creators = async (...a) => { seen.creators = await read(); return creators(...a); };
    const build = w.stages.build as RunStages['build'];
    w.stages.build = async (i) => { seen.build ??= await read(); return build(i); };
    expect(await run(w)).toBe(0);
    expect(seen).toEqual({ creators: 'debated', build: 'created' });
  });

  it('run: onCreated records the scratch repo only; the probe-P4 shape (pipelines, 4242) is not recorded (sec I5)', () => {
    const ids: number[] = [];
    const st: { centralCreated?: boolean } = {};
    const cb = onCreatedFor({ scratchCreated: (id: number) => { ids.push(id); }, update: (f: (n: typeof st) => void) => { f(st); } } as never, 'r');
    cb('pipelines', 4242);
    cb('pipegen-proof-other', 1);
    expect(ids).toEqual([]);
    // G14-R1 (spec M1): the central repo pipegen made is remembered for a resume's record (never as the scratch id)
    expect(st.centralCreated).toBe(true);
    // and a resume's delivery record says so, though the repo exists by now (this run's check created nothing)
    expect(proofReposFor({ created: [] }, { centralCreated: true }).central?.createdByPipegen).toBe(true);
    expect(proofReposFor({ created: [] }, {}).central?.createdByPipegen).toBe(false);
    cb('pipegen-proof-r', 77);
    expect(ids).toEqual([77]);
  });

  it('run: the Actions access level is saved the moment it changed and reaches the record (sec M3)', async () => {
    const w = world();
    w.stages.proofRepos = async () => { w.calls.push('proofRepos'); return { ready: true, target: {} as never, repos: [], created: [], actionsAccess: { previous: 'none' } } as never; };
    expect(await run(w)).toBe(0);
    const store = await StateStore.open({ owner: OWN, repo: 'r' }, { home: w.home, env: {} });
    expect(store.load()?.actionsAccessPrevious).toBe('none');
    expect((w.got.deliver?.[0] as { proofRepos: { central: { actionsAccess?: { previous: string } } } }).proofRepos.central.actionsAccess).toEqual({ previous: 'none' });
    // a level an earlier run saved wins over this run's read
    expect(proofReposFor({ created: [], actionsAccess: { previous: 'organization' } }, { actionsAccessPrevious: 'none' }).central?.actionsAccess).toEqual({ previous: 'none' });
  });
});

describe('G13-R1: delivery is bound to the proven draft', () => {
  it('run: the draft saved with the pass is delivered, not the seam\'s return value; the probe-P1 shape (saved changed, none returned) delivers the saved one (sec I3)', async () => {
    const w = world({ facts: facts({}, { private: false }), proof: proofSaving(PROVEN, 'none') });
    expect(await run(w)).toBe(0);
    expect(w.builds.at(-1)?.draft.suggestions.map((s) => s.name)).toEqual(['PROVEN']);
    expect((w.got.deliver?.[0] as { draft: PipelineDraft }).draft.suggestions.map((s) => s.name)).toEqual(['PROVEN']);
  });

  it('run: a proof that returns another draft than the one it saved is refused: exit 2, no deliverCentral (sec I3)', async () => {
    const w = world({ proof: proofSaving(PROVEN, 'other') });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(i.errs.join('\n')).toMatch(/another draft than the one it saved/);
    for (const s of ['deliverCentral', 'deliver', 'preview']) expect(w.calls).not.toContain(s);
  });

  it('run: a verdict saved by another run, or with no draft, is refused (sec I3)', () => {
    const d = { suggestions: [] } as unknown as PipelineDraft;
    expect(provenDraft({ runId: '20261106-100000-abc123', draft: d }, '20261106-100000-abc124', undefined)).toHaveProperty('stop');
    expect(provenDraft({ runId: '20261106-100000-abc123' }, '20261106-100000-abc123', undefined)).toHaveProperty('stop');
    expect(provenDraft({ runId: '20261106-100000-abc123', draft: d }, '20261106-100000-abc123', { suggestions: [] } as unknown as PipelineDraft)).toEqual({ draft: d });
  });

  it('run: private app, a proof-changed draft is rebuilt and judged at the stand-in commit before deliverCentral, whose files come from that build (sec I4, spec I3)', async () => {
    const w = world({
      proof: proofSaving(PROVEN, 'saved'),
      built: (i) => builtOf(i, { files: [FILE('PIPEGEN.md'), FILE('.github/workflows/r--merge.yml', 'central', `tag: ${i.draft.suggestions.map((s) => s.name).join(',')}\n`)] }),
    });
    expect(await run(w)).toBe(0);
    const central = w.calls.indexOf('deliverCentral');
    const builds = w.calls.map((c, n) => (c === 'build' ? n : -1)).filter((n) => n >= 0);
    expect(builds.filter((n) => n < central)).toHaveLength(2);
    expect(w.builds[1]?.draft.suggestions.map((s) => s.name)).toEqual(['PROVEN']);
    expect(w.builds[1]?.draft.centralPin?.sha).toBe(UNPINNED);
    expect((w.got.deliverCentral?.[0] as CreatedFile[])[0]?.content).toBe('tag: PROVEN\n');
    // a proven draft that carries the proof's own central commit is still rebuilt at the stand-in (deliverCentral gives the real one)
    const pinned = (d: PipelineDraft): PipelineDraft => ({ ...PROVEN(d), centralPin: { repo: `${OWN}/pipelines`, sha: 'e'.repeat(40) } });
    const wp = world({ proof: proofSaving(pinned, 'saved') });
    expect(await run(wp)).toBe(0);
    expect(wp.builds[1]?.draft.centralPin?.sha).toBe(UNPINNED);
    // the rebuilt draft that fails its checks stops before deliverCentral
    let n = 0;
    const w2 = world({ proof: proofSaving(PROVEN, 'saved'), built: (i) => builtOf(i, n++ === 1 ? { guardProblems: ['bad'] } : {}) });
    expect(await run(w2)).toBe(2);
    expect(w2.calls).not.toContain('deliverCentral');
  });
});

describe('G13-R1: what the user is told', () => {
  it('run: delivery\'s done, skipped and central pull request are printed (spec I4, carry 19)', async () => {
    const w = world();
    w.stages.deliver = async () => ({ prUrl: 'https://github.com/x/r/pull/3', prNumber: 3, centralSha: null, recordHash: 'h', centralPrUrl: 'https://github.com/x/pipelines/pull/8', done: ['the branch'], skipped: [{ what: 'secret API_TK', why: 'no value was given; set it yourself' }], notes: ['n1'] }) as never;
    const i = io();
    expect(await run(w, i)).toBe(0);
    const out = i.lines.join('\n');
    for (const s of ['done: the branch', 'skipped: secret API_TK (no value was given; set it yourself)', 'n1', 'https://github.com/x/r/pull/3', 'https://github.com/x/pipelines/pull/8']) expect(out).toContain(s);
  });

  it('run: the note about hooks the install record does not hold reaches the preview (ruling G13-R2 7)', async () => {
    const w = world({ built: (i) => builtOf(i, { hookNotes: ['pipegen\'s hooks are already in lefthook.yml, but the install record pipegen trusts does not list them'] }) });
    const i = io();
    expect(await run(w, i)).toBe(0);
    expect(i.asked.find((q) => /Open the setup pull request/.test(q))).toContain('the install record pipegen trusts does not list them');
  });

  it('run: the environment plan\'s notes reach the preview (spec I7)', async () => {
    const w = world({ built: (i) => builtOf(i, { envNotes: ['pipegen asks for a deploy approval only on an environment your deploy jobs use'] }) });
    const i = io();
    expect(await run(w, i)).toBe(0);
    expect(i.asked.find((q) => /Open the setup pull request/.test(q))).toContain('only on an environment your deploy jobs use');
  });
});

describe('G13-R2: a public app\'s central CODEOWNERS', () => {
  it('run: a public app whose batch holds central files reads the central file list once, judges with it and delivers it', async () => {
    const w = world({ facts: facts({}, { private: false }), built: (i) => builtOf(i, { files: [FILE('PIPEGEN.md'), FILE('.github/CODEOWNERS', 'central')] }) });
    expect(await run(w)).toBe(0);
    expect(w.calls).not.toContain('deliverCentral');
    expect(w.calls.filter((c) => c === 'readCentralFileList')).toHaveLength(1);
    const listed = ['.github/workflows/r--merge.yml', 'installs/r.json'];
    expect(w.builds.at(-1)?.centralFiles).toEqual(listed);
    expect((w.got.deliver?.[0] as { centralFileList?: string[] }).centralFileList).toEqual(listed);
    // a public app with no central file reads no list
    const w2 = world({ facts: facts({}, { private: false }) });
    expect(await run(w2)).toBe(0);
    expect(w2.calls).not.toContain('readCentralFileList');
  });
});

describe('G13-R2: the state file never holds a known value (ruling G13-R2 4)', () => {
  it('run: the state store\'s tokens hold the AI key too (G14, controller addendum)', async () => {
    const w = world();
    let guard: Parameters<RunStages['state']>[1] | undefined;
    w.stages.state = async (p, g) => { guard = g; w.calls.push('state'); return StateStore.open(p, { home: w.home, env: {}, ...g }); };
    const aiKey = ['made', 'up', 'ai', 'key', '0123456789'].join('-');
    const other = ['other', 'ai', 'key', '0123456789'].join('-');
    expect(await run(w, io({}, { env: { [['ANTHROPIC', 'API', 'KEY'].join('_')]: aiKey, [['OPENAI', 'API', 'KEY'].join('_')]: other } }))).toBe(0);
    expect(guard?.tokens).toEqual([TK, aiKey, other]);
  });
  it('run: the state store gets the run\'s known-value check (the vault and the key vault, live) and the GitHub token', async () => {
    const w = world();
    let guard: Parameters<RunStages['state']>[1] | undefined;
    const seen: boolean[] = [];
    w.stages.state = async (p, g) => { guard = g; w.calls.push('state'); return StateStore.open(p, { home: w.home, env: {}, ...g }); };
    const asked = w.stages[SEC_STAGE] as RunStages['secrets'];
    w.stages[SEC_STAGE] = async (...a) => { seen.push(guard?.vault.containsKnownValue('x typed-value-1234567890 y') ?? false); return asked(...a); };
    expect(await run(w)).toBe(0);
    expect(guard?.tokens).toEqual([TK]);
    // the value typed after the store was opened is known to it (a live check, not a copy)
    expect(seen).toEqual([true]);
    // and a real store with that guard refuses to write it
    const d = tmp('pg-state-guard-');
    const v = new SecretVault();
    const store = await StateStore.open({ owner: OWN, repo: 'r' }, { home: d, env: {}, vault: v, [TL_KEY]: [TK] });
    store.begin('20261106-100000-abc123', { owner: OWN, repo: 'r', private: true, ownerType: 'User', defaultBranch: 'main' }, { cap: 1, aiCap: 1 });
    v.set('API_TK', 'typed-value-1234567890');
    expect(() => store.recordVerdict({ ok: false, stopped: 'typed-value-1234567890' })).toThrow();
  });
});

// ---------- G17 group C ----------

describe('G17C row 27: the central repo pipegen created, with its GitHub id, in the run state and the record', () => {
  it('state: onCreated keeps the central repo\'s id with centralCreated; begin carries both for the same app only', async () => {
    const home = mkdtempSync(join(tmpdir(), 'pg-g17c-'));
    const s = await StateStore.open({ owner: 'o', repo: 'r' }, { home, env: {} });
    const app = { owner: 'o', repo: 'r', private: true, ownerType: 'User' as const, defaultBranch: 'main' };
    s.begin('20261109-000000-abcdef', app, { cap: 1, aiCap: 1 });
    onCreatedFor(s, 'r')('pipelines', 4242);
    expect(s.state?.centralCreated).toBe(true);
    expect((s.state as { centralRepoId?: number }).centralRepoId).toBe(4242);
    s.update((n) => { n.cleanupDone = true; });
    s.begin('20261109-000001-abcdef', app, { cap: 1, aiCap: 1 });
    expect((s.state as { centralRepoId?: number }).centralRepoId).toBe(4242);
    s.update((n) => { n.cleanupDone = true; });
    s.begin('20261109-000002-abcdef', { ...app, repo: 'other' }, { cap: 1, aiCap: 1 });
    expect((s.state as { centralRepoId?: number }).centralRepoId).toBeUndefined();
    rmSync(home, { recursive: true, force: true });
  });

  it('run: a resume\'s delivery records the saved id with createdByPipegen; no id is ever taken from elsewhere', () => {
    expect(proofReposFor({ created: [] }, { centralCreated: true, centralRepoId: 4242 } as never).central).toEqual({ createdByPipegen: true, repoId: 4242 });
    expect(proofReposFor({ created: ['pipelines'], createdIds: { pipelines: 9 } }, {}).central).toEqual({ createdByPipegen: true, repoId: 9 });
    expect(proofReposFor({ created: [] }, {}).central).toEqual({ createdByPipegen: false });
  });
});

describe('G17C-R1 (F5): the central PR pipegen opened is remembered, so its merge proves pipegen\'s central files', () => {
  it('state: centralPrOpened keeps the PR number and pipegen\'s commit; begin carries them for the same app only', async () => {
    const home = mkdtempSync(join(tmpdir(), 'pg-g17c-'));
    const s = await StateStore.open({ owner: 'o', repo: 'r' }, { home, env: {} });
    const app = { owner: 'o', repo: 'r', private: true, ownerType: 'User' as const, defaultBranch: 'main' };
    s.begin('20261109-000000-abcdef', app, { cap: 1, aiCap: 1 });
    s.centralPrOpened(4, 'd'.repeat(40));
    expect((s.state as { centralPr?: unknown }).centralPr).toEqual({ number: 4, commit: 'd'.repeat(40) });
    expect(() => s.centralPrOpened(0, 'd'.repeat(40))).toThrow();
    expect(() => s.centralPrOpened(4, 'not a sha')).toThrow();
    s.update((n) => { n.cleanupDone = true; });
    s.begin('20261109-000001-abcdef', app, { cap: 1, aiCap: 1 });
    expect((s.state as { centralPr?: unknown }).centralPr).toEqual({ number: 4, commit: 'd'.repeat(40) });
    s.update((n) => { n.cleanupDone = true; });
    s.begin('20261109-000002-abcdef', { ...app, repo: 'other' }, { cap: 1, aiCap: 1 });
    expect((s.state as { centralPr?: unknown }).centralPr).toBeUndefined();
    rmSync(home, { recursive: true, force: true });
  });

  it('run: a central PR run saves the PR; the next run gives it to deliverCentral', async () => {
    const pr = { number: 4, commit: 'd'.repeat(40) };
    const w = world();
    const seen: unknown[] = [];
    w.stages.deliverCentral = (async (...a: unknown[]) => { seen.push(a[4]); return { kind: 'central-pr', url: 'u', message: 'merge it', pr }; }) as never;
    expect(await run(w)).toBe(2);
    w.stages.deliverCentral = (async (...a: unknown[]) => { seen.push(a[4]); return { kind: 'pinned', sha: 'c'.repeat(40), done: [] }; }) as never;
    w.deps.runId = () => '20261106-110000-abc123';
    expect(await run(w)).toBe(0);
    expect(seen).toEqual([undefined, pr]);
  });
});

describe('G17C row 28: only the central commit deliverCentral made in this run reaches the delivery', () => {
  it('run: centralCommitted is the pin only when deliverCentral says it committed; a pin already there is never passed as this run\'s commit', async () => {
    const sha = 'c'.repeat(40);
    for (const committed of [true, undefined, false]) {
      const w = world();
      w.stages.deliverCentral = async () => ({ kind: 'pinned', sha, done: [], ...(committed === undefined ? {} : { committed }) }) as never;
      expect(await run(w)).toBe(0);
      const input = w.got.deliver?.[0] as { centralCommitted?: string };
      if (committed === true) expect(input.centralCommitted).toBe(sha);
      else expect(input, String(committed)).not.toHaveProperty('centralCommitted');
    }
  });
});

// ---------- ruling G-SIGN1: the first run on a private repo signs when the plan allows ----------

describe('G-SIGN1: the signing mode re-derived after the run makes its own signing environment', () => {
  /** A private repo whose environments work but whose pipegen-signing rule is not proven (there is no such environment yet). */
  const UNPROVEN = { ...CAPS, attestations: false, environments: true, deploymentBranchPolicies: false };
  const IMAGE = (): RepoProfile => LOCAL({ services: [{ ...APP, dockerfile: 'Dockerfile' }] });
  const ENV = { name: 'pipegen-signing', created: true, githubCreatedAt: '2026-11-06T10:00:05Z', changed: [], branchPolicyIds: [7] };
  type Made = Awaited<ReturnType<RunStages['signingEnv']>>;
  function signWorld(made: Made | (() => Promise<Made>), o: Parameters<typeof world>[0] = {}): World {
    const w = world({ local: IMAGE(), facts: facts({ caps: UNPROVEN }), ...o });
    w.stages.signingEnv = async (f, p) => { w.calls.push('signingEnv'); w.got.signingEnv = [f, p]; return typeof made === 'function' ? made() : made; };
    return w;
  }

  it('run: G-SIGN1 a first private run with no proven signing environment makes it after consent, reads it back, and signs (key-env)', async () => {
    const w = signWorld({ env: ENV });
    const i = io();
    expect(await run(w, i)).toBe(0);
    // after the yes and before the needs (so the needs, the debate, the build and the referee all see the proven rule)
    expect(w.calls.indexOf('consent')).toBeLessThan(w.calls.indexOf('signingEnv'));
    expect(w.calls.indexOf('scan')).toBeLessThan(w.calls.indexOf('signingEnv'));
    expect(w.calls.indexOf('signingEnv')).toBeLessThan(w.calls.indexOf('needs'));
    expect(w.calls.filter((c) => c === 'signingEnv')).toHaveLength(1);
    expect((w.got.signingEnv?.[1] as RepoProfile).defaultBranch).toBe('main');
    expect((w.got.needs?.[1] as GitHubFacts['caps']).deploymentBranchPolicies).toBe(true);
    const d = w.builds[0]?.draft as PipelineDraft;
    expect(d.capabilities.deploymentBranchPolicies).toBe(true);
    expect(d.signing?.mode).toBe('key-env');
    expect(d.signing?.cosignPubSha256).toBe(pubKeySha256('PUB'));
    expect(w.builds[0]?.facts.caps.deploymentBranchPolicies).toBe(true);
    // one pair, handed to deliver with the environment the run made
    expect(w.calls.filter((c) => c === 'signingKey')).toHaveLength(1);
    expect((w.got.deliver?.[0] as DeliveryInputLike).signingEnv).toEqual(ENV);
    expect(typeof w.got.deliver?.[1]).toBe('function');
    expect(i.errs.join('\n')).toMatch(/made the environment pipegen-signing \(default branch only\) and read it back, so this run signs/);
  });

  it('run: G-SIGN1 an environment that is there already, can not be made or does not read back leaves the run unsigned (fail closed)', async () => {
    const unsigned = async (w: World, i: ReturnType<typeof io>): Promise<void> => {
      expect(await run(w, i)).toBe(0);
      const d = w.builds[0]?.draft as PipelineDraft;
      expect(d.signing).toBeUndefined();
      expect(d.capabilities.deploymentBranchPolicies).toBe(false);
      expect((w.got.needs?.[1] as GitHubFacts['caps']).deploymentBranchPolicies).toBe(false);
      expect(w.calls).not.toContain('signingKey');
      expect(w.got.deliver?.[0]).not.toHaveProperty('signingEnv');
      expect(w.got.deliver?.[1]).toBeUndefined();
      expect(i.errs.join('\n')).toMatch(/Signing is off \(mode none\)/);
      expect(i.errs.join('\n')).not.toMatch(/so this run signs/);
    };
    const i1 = io();
    await unsigned(signWorld({ off: "The environment pipegen-signing doesn't read back as usable from the default branch only." }), i1);
    expect(i1.errs.join('\n')).toMatch(/Signing is off \(mode none\): The environment pipegen-signing doesn't read back/);
    // an answer that is not a fresh environment of that name is never taken as proof
    await unsigned(signWorld({ env: { ...ENV, created: false } }), io());
    await unsigned(signWorld({ env: { ...ENV, name: 'production' } }), io());
    await unsigned(signWorld({ env: { ...ENV, branchPolicyIds: [] } }), io());
    // a stop the stage can't turn into "off" (the environment couldn't be listed locally) stops the run, naming what was left
    const w = signWorld(async () => { throw new DeliverError('pipegen made pipegen-signing but could not list it', { leftovers: ['environment pipegen-signing'] }); });
    const i = io();
    expect(await run(w, i)).toBe(1);
    expect(i.errs.join('\n')).toMatch(/left: environment pipegen-signing/);
    expect(w.calls).not.toContain('needs');
  });

  it('run: G-SIGN1 no memory folder: no environment is made and the run stays unsigned, not refused', async () => {
    const w = signWorld({ env: ENV }, { deps: { isMemory: () => false } });
    const i = io();
    expect(await run(w, i)).toBe(0);
    expect(w.calls).not.toContain('signingEnv');
    expect(w.builds[0]?.draft.signing).toBeUndefined();
    expect(i.errs.join('\n')).toMatch(/Signing is off \(mode none\).*\/dev\/shm/);
    expect(i.errs.join('\n')).not.toContain(NO_MEMORY_FOLDER);
  });

  it('run: G-SIGN1 nothing is made when the plan does not allow key-env or the rule is proven already', async () => {
    for (const [why, o] of [
      ['no image', { local: LOCAL() }],
      ['attestations sign', { facts: facts({ caps: { ...UNPROVEN, attestations: true } }) }],
      ['no environments', { facts: facts({ caps: { ...UNPROVEN, environments: false } }) }],
      ['proven already', { facts: facts({ caps: { ...UNPROVEN, deploymentBranchPolicies: true } }) }],
      ['public', { local: { ...IMAGE() }, facts: facts({ caps: UNPROVEN }, { private: false }) }],
    ] as const) {
      const w = signWorld({ env: ENV }, o as Parameters<typeof world>[0]);
      expect(await run(w), why).toBe(0);
      expect(w.calls, why).not.toContain('signingEnv');
      expect(w.got.deliver?.[0], why).not.toHaveProperty('signingEnv');
    }
  });

  // ---------- ruling G-SIGN1-R1 ----------

  function dropWorld(o: Parameters<typeof world>[0] = {}, drop: Awaited<ReturnType<RunStages['dropSigningEnv']>> = { dropped: true }): World {
    const w = signWorld({ env: ENV }, o);
    w.stages.dropSigningEnv = async (f, p, env) => { w.calls.push('dropSigningEnv'); w.got.dropSigningEnv = [f, p, env]; return drop; };
    return w;
  }

  it('run: G-SIGN1-R1 a run that made the environment and stops before delivery deletes it (failed proof, a no at the preview, an error)', async () => {
    const cases: [string, World, number][] = [
      ['failed proof', dropWorld({ proof: async () => ({ ok: false, stopped: 'the proof did not pass' }) }), 2],
      ['no at the preview', dropWorld(), 1],
      ['an error', dropWorld({ built: () => { throw new Error('boom'); } }), 1],
    ];
    for (const [why, w, code] of cases) {
      const i = why === 'no at the preview' ? io({ preview: false }) : io();
      expect(await run(w, i), why).toBe(code);
      expect(w.calls, why).not.toContain('deliver');
      expect(w.calls.filter((c) => c === 'dropSigningEnv'), why).toHaveLength(1);
      expect(w.got.dropSigningEnv?.[2], why).toEqual(ENV);
      expect(i.errs.join('\n'), why).toMatch(/pipegen deleted the environment pipegen-signing it made earlier in this run/);
    }
    // delivered: delivery owns it (the record names it), nothing is deleted
    const ok = dropWorld();
    expect(await run(ok)).toBe(0);
    expect(ok.calls).toContain('deliver');
    expect(ok.calls).not.toContain('dropSigningEnv');
    // nothing made (signing off): nothing to delete
    const off = signWorld({ off: 'x' });
    off.stages.dropSigningEnv = async () => { off.calls.push('dropSigningEnv'); return { dropped: true }; };
    expect(await run(off, io({ preview: false }))).toBe(1);
    expect(off.calls).not.toContain('dropSigningEnv');
  });

  it('run: G-SIGN1-R1 a delete that fails keeps the leftovers entry, and the message names it', async () => {
    const w = dropWorld({}, { left: 'HTTP 403; it stays listed in /home/u/.config/pipegen/records/crisworking__r.leftovers.json' });
    const i = io({ preview: false });
    expect(await run(w, i)).toBe(1);
    expect(i.errs.join('\n')).toMatch(/pipegen couldn't delete the environment pipegen-signing it made earlier in this run \(HTTP 403; it stays listed in .*crisworking__r\.leftovers\.json\)/);
    expect(i.errs.join('\n')).not.toMatch(/pipegen deleted the environment/);
  });

  it('run: G-SIGN1-R1 an interrupt before delivery deletes it too: armed when it is made, disarmed when delivery takes it', async () => {
    const armed: { cleanup?: () => Promise<void>; disarmed: number; at: string[] } = { disarmed: 0, at: [] };
    const w = dropWorld({ deps: { armSigningEnv: (cleanup) => { armed.cleanup = cleanup; armed.at.push(`armed after ${w.calls.at(-1)}`); return () => { armed.disarmed += 1; armed.at.push(`disarmed before ${w.calls.length}`); }; } } });
    expect(await run(w)).toBe(0);
    expect(armed.at[0]).toBe('armed after signingEnv');
    expect(armed.disarmed).toBe(1);
    expect(w.calls).not.toContain('dropSigningEnv');
    await armed.cleanup?.();
    expect(w.calls).toContain('dropSigningEnv');
    // the disarm came before delivery
    const w2 = dropWorld({ deps: { armSigningEnv: () => () => { w2.calls.push('disarm'); } } });
    expect(await run(w2)).toBe(0);
    expect(w2.calls.indexOf('disarm')).toBeLessThan(w2.calls.indexOf('deliver'));
    // a stop before delivery deletes once, through the run, and disarms too
    let dis = 0;
    let hook: (() => Promise<void>) | undefined;
    const w3 = dropWorld({ deps: { armSigningEnv: (cleanup) => { hook = cleanup; return () => { dis += 1; }; } } });
    expect(await run(w3, io({ preview: false }))).toBe(1);
    expect(dis).toBe(1);
    expect(w3.calls.filter((c) => c === 'dropSigningEnv')).toHaveLength(1);
    // an interrupt hook that fires as well deletes nothing twice
    await hook?.();
    expect(w3.calls.filter((c) => c === 'dropSigningEnv')).toHaveLength(1);
  });

  it('run: G-SIGN1-R1 the consent screen says pipegen creates pipegen-signing before the proof, only when that path can run', async () => {
    const asked = async (w: World): Promise<unknown> => { await run(w); return (w.got.consent?.[7] as { signingEnv?: boolean } | undefined)?.signingEnv; };
    expect(await asked(signWorld({ env: ENV }))).toBe(true);
    expect(await asked(signWorld({ env: ENV }, { local: LOCAL() }))).toBe(false);
    expect(await asked(signWorld({ env: ENV }, { deps: { isMemory: () => false } }))).toBe(false);
    expect(await asked(signWorld({ env: ENV }, { facts: facts({ caps: { ...UNPROVEN, deploymentBranchPolicies: true } }) }))).toBe(false);
    expect(await asked(signWorld({ env: ENV }, { facts: facts({ caps: { ...UNPROVEN, attestations: true } }) }))).toBe(false);
  });
});
type DeliveryInputLike = { signingEnv?: unknown };
