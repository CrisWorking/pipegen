// v0.2 Plan G G13: `pipegen run` (src/cli/run.ts) with fake stages, and its pure parts (src/cli/run-parts.ts) with the real modules.
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
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
import type { CodeBundle } from '../src/ai/redact.js';
import { notProvableNotes, auditCredits, createdInputsFor, dastWayPast, defaultProof, fullRun, judgeBuilt, NEVER_SKIPPED, parseSkip, PROOF_NOT_BUILT, runCreators, SCOPE_LINE, UNPINNED, WINDOWS_REFUSAL, GATE_UNREACHABLE, guardRecord, insertedBlock, type Built, type BuildInput, type GitHubFacts, type RunDeps, type RunStages } from '../src/cli/run.js';
import { assembledJobs, consentJobs, docFor, draftFromDebate, isAiNote, parseStrictness, pickOwners, prWaitMinutes, proofAssembleWith, proofLayout, warnFirstFor, signingFor } from '../src/cli/run-parts.js';
import { TYPE_CANCELLED } from '../src/cli/audit.js';
import type { CliIO, Prompter } from '../src/cli/io.js';
import { PromptCancelledError } from '../src/cli/io.js';
import { SecretVault } from '../src/create/secrets.js';
import type { DebateResult } from '../src/debate/debate.js';
import { newRateBudget } from '../src/engine/github-rate.js';
import { CALLER_WORKFLOW, NIGHTLY_WORKFLOW } from '../src/engine/job-rules.js';
import { floorNeeds, jobCategories, MINIMUM_CATEGORIES } from '../src/engine/needs.js';
import { estimate, needKeyCount } from '../src/estimate/estimate.js';
import { AssembleError } from '../src/layers/jobs.js';
import { pubKeySha256 } from '../src/engine/signing.js';
import { StateStore } from '../src/proof/state.js';
import type { CreatedFile, InstallRecord, Need, PipelineDraft, RepoProfile } from '../src/types.js';
import { API, CAPS, candidatesFor, choicesFor, need, NEEDS, profile, REVIEWED, scripted, svc } from './helpers/debate-fixtures.js';

const homes: string[] = [];
afterAll(() => { for (const h of homes) rmSync(h, { recursive: true, force: true }); });
const tmp = (prefix: string): string => { const h = mkdtempSync(join(tmpdir(), prefix)); homes.push(h); return h; };

const TOKEN = ['github', 'pat', '11AAAAAAA0', 'x'.repeat(40)].join('_');
const TODAY = '2026-11-06';

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
const LOCAL = (over: Partial<RepoProfile> = {}): RepoProfile => profile({ owner: 'o', repo: 'r', monorepo: 'none', services: [APP], generatedDirs: [], ...over });

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
    minutes: { jobs: { 'pre-commit': [], push: [], merge: [], deploy: [], nightly: [] }, prWait: 7 }, ...over,
  };
}

/** A passing proof: proving → verdict → proven → cleaned. */
const passingProof: NonNullable<RunDeps['proof']> = async (x) => {
  x.store.setStage('proving');
  x.store.recordVerdict({ ok: true, draft: x.draft });
  x.store.setStage('proven');
  x.store.setStage('cleaned');
  return { ok: true };
};

interface World {
  calls: string[]; got: Record<string, unknown[]>; vaults: SecretVault[]; builds: BuildInput[]; home: string;
  stages: Partial<RunStages>; deps: RunDeps;
}
function world(o: { local?: RepoProfile; facts?: GitHubFacts; debate?: DebateResult; auth?: Record<string, unknown>; consent?: boolean; prState?: 'merged' | 'closed' | 'open'; built?: (i: BuildInput) => Built; record?: InstallRecord | null; central?: 'pinned' | 'central-pr'; gate?: boolean; proof?: RunDeps['proof']; deps?: Partial<RunDeps> } = {}): World {
  const calls: string[] = [];
  const got: Record<string, unknown[]> = {};
  const vaults: SecretVault[] = [];
  const builds: BuildInput[] = [];
  const home = tmp('pg-run-');
  const ai = scripted(() => ({}));
  const rec = (name: string, ...args: unknown[]): void => { calls.push(name); got[name] = args; };
  const stages: Partial<RunStages> = {
    readOrigin: async (d) => { rec('readOrigin', d); return { owner: 'o', repo: 'r' }; },
    localProject: async (d) => { rec('localProject', d); return o.local ?? LOCAL(); },
    getAuth: async (x) => { rec('getAuth', x); return { kind: 'fine-grained', token: TOKEN, canCreateRepos: false, canDeleteRepos: false, ...o.auth } as never; },
    readProject: async (a, l) => { rec('readProject', a, l); return o.facts ?? facts(); },
    provider: () => { rec('provider'); return ai.ai; },
    bundle: async (d, k) => { rec('bundle', d, k); return { files: [] } as unknown as CodeBundle; },
    activity: async () => { rec('activity'); return { pushes: 10, prs: 5, capped: false }; },
    consent: async (f, p, prov, est, b, auth, extra) => { rec('consent', f, p, prov, est, b, auth, extra); return o.consent === false ? null : ({} as never); },
    state: async (p) => { rec('state', p); return StateStore.open(p, { home, env: {} }); },
    gateReachable: async () => { rec('gateReachable'); return o.gate ?? true; },
    proofRepos: async (f, p, auth, store, runId, actions) => { rec('proofRepos', f, p, auth, store, runId, actions); return { ready: true, target: {} as never, repos: [], created: [] }; },
    needs: async (p, caps, b, aiP, writers) => { rec('needs', p, caps, b, aiP, writers); return { needs: [...NEEDS], notes: [], requireDeployApproval: true, layersSkipped: [], usage: [] } as never; },
    discover: async () => { rec('discover'); return candidatesFor(NEEDS, profile()); },
    debate: async (...a) => { rec('debate', ...a); return o.debate ?? debateResult(); },
    creators: async (draft, b, aiP, d, vault) => { rec('creators', draft, b, aiP, d, vault); vaults.push(vault); vault.set('API_TOKEN', 'typed-value-1234567890'); return { files: [], notes: [], testNotes: ['The AI explained: x', 'kept note'], testDecisions: [], notProven: [] }; },
    secrets: async (_p, _c, vault) => { rec('secrets'); return { names: vault.names(), missing: [], notes: [] }; },
    credits: async () => { rec('credits'); return [{ text: 'a credit', kind: 'push-default' }]; },
    build: async (i) => { rec('build', i); builds.push(i); return (o.built ?? ((x) => builtOf(x)))(i); },
    trusted: async () => { rec('trusted'); return { record: o.record ?? null, notes: [] }; },
    deliverCentral: async (f, p, files) => { rec('deliverCentral', files); return o.central === 'central-pr' ? { kind: 'central-pr', url: 'u', message: 'central PR opened; merge it, then run pipegen again' } : { kind: 'pinned', sha: 'c'.repeat(40), done: ['central files'] }; },
    readCentralFileList: async () => { rec('readCentralFileList'); return ['.github/workflows/r--merge.yml', 'installs/r.json']; },
    preview: (input) => { rec('preview', input); return 'THE PREVIEW'; },
    signingKey: async () => { rec('signingKey'); return { key: 'k', password: 'pw', pub: 'PUB' }; },
    deliver: async (_f, _p, input, _v, _io, key) => { rec('deliver', input, key); return { prUrl: 'https://github.com/o/r/pull/3', prNumber: 3, centralSha: null, recordHash: 'h', done: [], skipped: [], notes: ['delivery note'] } as never; },
    prState: async () => { rec('prState'); return o.prState ?? 'merged'; },
    finish: async () => { rec('finish'); return 0; },
  };
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
    const order = ['readOrigin', 'localProject', 'getAuth', 'readProject', 'provider', 'bundle', 'activity', 'consent', 'state', 'proofRepos', 'needs', 'discover', 'debate', 'trusted', 'creators', 'secrets', 'credits', 'build', 'deliverCentral', 'readCentralFileList', 'build', 'preview', 'deliver', 'prState', 'finish'];
    expect(w.calls.filter((c) => order.includes(c))).toEqual(order);
    const store = await StateStore.open({ owner: 'o', repo: 'r' }, { home: w.home, env: {} });
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
    expect(w.got.getAuth?.[0]).toEqual({ owner: 'o', repos: ['r', 'pipelines', 'pipegen-proof-r'], allowBroad: false });
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
    const many = { 'pre-commit': [], push: [], merge: Array.from({ length: 60 }, () => 'sast'), deploy: [], nightly: [] };
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
    const w = world({ auth: { kind: 'app', canCreateRepos: true, canDeleteRepos: true } });
    await run(w);
    expect((w.got.proofRepos?.[2] as { canCreateRepos: boolean }).canCreateRepos).toBe(true);
    expect(w.got.proofRepos?.[4]).toBe('20261106-100000-abc123');
    // every pinned reviewed action the proof could run is checked against the scratch repo's settings
    expect((w.got.proofRepos?.[5] as string[]).length).toBeGreaterThan(0);
    expect((w.got.proofRepos?.[5] as string[]).every((a) => /^[^/]+\/[^@]+@[0-9a-f]{40}$/.test(a))).toBe(true);
  });

  it('run: works with a GitHub App token', async () => {
    const w = world({ auth: { kind: 'app', canCreateRepos: true, canDeleteRepos: true } });
    const i = io();
    expect(await run(w, i)).toBe(0);
    expect(w.calls).toContain('deliver');
    expect(i.lines.join('\n')).not.toContain(TOKEN);
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
    const floorish = { ...need('sast', 'merge', 'web'), floor: true };
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
    const asked: string[] = [];
    const draft = { profile: LOCAL({ services: [hinted, plain] }), skipped: [] } as unknown as PipelineDraft;
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
  const facts0 = { appCo: { path: 'CODEOWNERS', text: 'x', isSymlink: false, block: null, inserted: null }, centralCo: { path: null, text: '', isSymlink: false, block: null, inserted: null }, pipegenDoc: { baseSha: null, recordSha: 'a'.repeat(40) }, serviceTypes: { web: 'module' as const }, baseTree: { complete: true, entries: new Map() } };
  const input = (vault: SecretVault, centralFiles?: string[]): BuildInput => ({ dir: '/repo', draft: {} as PipelineDraft, plan: {} as never, facts: facts(), vault, reviewed: REVIEWED, platform: { checkout: {} } as never, owners: [], strictness: 'standard', transcript: [], testNotes: [], est: {} as never, auth: { kind: 'app', token: TOKEN } as never, credits: [], prev: null, ...(centralFiles === undefined ? {} : { centralFiles }) });

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
    const deps = judged[1] as { platform: unknown; reviewed: unknown; linters: unknown; ghToken: string; refereeDeps: { vault: unknown; createdInputs: Record<string, unknown> }; extra: unknown };
    expect(deps.platform).toEqual({ checkout: {} });
    expect(deps.reviewed).toBe(REVIEWED);
    expect(deps.linters).toEqual({ actionlint: 'a' });
    expect(deps.ghToken).toBe(TOKEN);
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
  it('run: the production proof seam stops before delivery with exit 2 (ruling G13-R0 1)', async () => {
    expect(await defaultProof({} as never)).toEqual({ ok: false, stopped: PROOF_NOT_BUILT });
    const w = world({ proof: defaultProof });
    const i = io();
    expect(await run(w, i)).toBe(2);
    expect(i.errs.join('\n')).toContain('the proof step');
    for (const s of ['deliverCentral', 'deliver', 'preview', 'finish']) expect(w.calls).not.toContain(s);
    expect(w.vaults[0]?.names()).toEqual([]);
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
    const draft = { profile: LOCAL(), signing: { mode: 'attest', images: [] }, centralPin: { repo: 'o/pipelines', sha: UNPINNED } } as unknown as PipelineDraft;
    const a = proofAssembleWith(draft, (d) => { seen = d; return { files: [caller] }; });
    expect(() => a('attest' as never, undefined)).toThrow(/signing mode none/);
    a('none', 'e'.repeat(40));
    expect(seen?.signing).toBeUndefined();
    expect(seen?.centralPin).toEqual({ repo: 'o/pipelines', sha: 'e'.repeat(40) });
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
    expect(w.builds[1]?.draft.centralPin).toEqual({ repo: 'o/pipelines', sha: 'c'.repeat(40) });
    // the same list reaches the referee (centralFiles) and the delivery (centralFileList)
    const listed = ['.github/workflows/r--merge.yml', 'installs/r.json'];
    expect(w.builds[1]?.centralFiles).toEqual(listed);
    expect((w.got.deliver?.[0] as { centralFileList: string[] }).centralFileList).toBe(w.builds[1]?.centralFiles);
    // only the project's own central workflows go to deliverCentral
    expect((w.got.deliverCentral?.[0] as CreatedFile[]).map((f) => f.path)).toEqual(['.github/workflows/r--merge.yml']);
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
    const w = world({ local, facts: facts({ caps: keyCaps }) });
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
    const msg = 'The blocking check dast (merge, svc-a) can not run: no container. pipegen never makes it warn-only or leaves it out.';
    const lines = dastWayPast(msg, [{ name: 'svc-a', containerHint: 'compose.yml builds svc-a' }, { name: 'other' }]);
    expect(lines).toHaveLength(1);
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
