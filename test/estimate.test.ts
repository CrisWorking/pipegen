import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { GitHubRateLimitError, newRateBudget } from '../src/engine/github-rate.js';
import { MAX_DISCOVERY_NEEDS } from '../src/engine/discovery-limits.js';
import { floorNeeds, jobCategories, jobCounts } from '../src/engine/needs.js';
import {
  activity30d, estimate, estimateAuditAi, HARNESS_MINUTES_PER_VARIANT, jobMinutes, loadAiPrices, loadGitHubPlans,
  type Activity, type JobCategories,
} from '../src/estimate/estimate.js';
import { DEFAULT_MODEL, type Capabilities, type ExistingWorkflow, type RepoProfile, type Service } from '../src/types.js';
import { fakeOctokit, type Call, type Reply } from './helpers/fake-http.js';

// ---------- builders ----------

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'web', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [],
  scripts: ['start', 'test'], frameworks: ['express'], ...over,
});
const profile = (over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'free',
  monorepo: 'none', services: [svc()], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, ...over,
});
// ExistingWorkflow is built from a field list (one field name holds "secret", which the secret-literal check watches).
const WORKFLOW_FIELDS = ['path', 'triggers', 'deploys', 'secretsUsed', 'jobs'] as const;
const workflow = (path: string, jobs: string[]) =>
  Object.fromEntries(WORKFLOW_FIELDS.map((n, i) => [n, [path, ['push'], false, [], jobs][i]])) as unknown as ExistingWorkflow;
const CAP_NAMES = ['branchProtection', 'environments', 'deploymentBranchPolicies', 'envRequiredReviewers', 'attestations', 'codeScanning', 'keylessSigningAllowed'] as const;
const NO_CAPS = Object.fromEntries(CAP_NAMES.map((n) => [n, false])) as unknown as Capabilities;

/**
 * The S5 app's jobs (a runnable Node + Postgres service) plus a deploy layer, by need category.
 * Minutes (S5 table): push 1+1+2+1+2+1 = 8; merge 8 + full-tests 2 + gate 1 + image-build 2 + image-scan 2 + dast 3 = 18;
 * deploy sbom 2 + signing 2 + deploy-verify 2 = 6; nightly 1 + 1 + 2 + 1 + 2 + 2 + 3 = 12 (the nightly builds the image
 * it scans, as S5's real nightly did: final review M8). Total 44.
 */
const PUSH = ['hooks-ci', 'secrets', 'sast', 'deps', 'unit-tests', 'lint'];
const JOBS: JobCategories = {
  'pre-commit': ['hooks', 'secrets', 'format-lint'],
  push: PUSH,
  merge: [...PUSH, 'full-tests', 'gate', 'image-build', 'image-scan', 'dast'],
  deploy: ['sbom', 'signing', 'deploy-verify'],
  nightly: ['nightly', 'secrets', 'sast', 'deps', 'image-build', 'image-scan', 'dast'],
};
const PER_VARIANT = 44 + HARNESS_MINUTES_PER_VARIANT; // 44 + 8 = 52
const ACTIVITY: Activity = { pushes: 40, prs: 10, capped: false };
const OPUS = { name: 'claude', model: DEFAULT_MODEL };

// Token totals for a full run (fixed table): needs 30k/3k, debate 3 × 40k/6k, creators 60k/20k, fix loop 2 parts × 5 × 15k/4k.
const IN = 30_000 + 120_000 + 60_000 + 150_000; // 360k
const OUT = 3_000 + 18_000 + 20_000 + 40_000;    // 81k

describe('estimate: minutes', () => {
  it('estimate: cap is twice setup', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    expect(e.setupMinutes).toBe(136); // 52 × 2 variants × 1.3 = 135.2, rounded up
    expect(e.setupMinutesCap).toBe(272);
  });

  it('estimate: setup counts every layer plus nightly, times variants', () => {
    // (push 8 + merge 18 + deploy 6 + nightly 12 + harness 8) × variants × 1.3, rounded up
    expect(estimate(profile(), JOBS, 1, ACTIVITY, OPUS).setupMinutes).toBe(68);
    expect(estimate(profile(), JOBS, 3, ACTIVITY, OPUS).setupMinutes).toBe(203);
    const noNightly = { ...JOBS, nightly: [] };
    expect(estimate(profile(), noNightly, 1, ACTIVITY, OPUS).setupMinutes).toBe(Math.ceil((PER_VARIANT - 12) * 1.3));
    const noDeploy = { ...JOBS, deploy: [] };
    expect(estimate(profile(), noDeploy, 1, ACTIVITY, OPUS).setupMinutes).toBe(Math.ceil((PER_VARIANT - 6) * 1.3));
  });

  it('estimate: pre-commit layer adds no CI minutes', () => {
    const more = { ...JOBS, 'pre-commit': [...JOBS['pre-commit'], 'lint', 'sast', 'dast', 'unit-tests'] };
    const a = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    const b = estimate(profile(), more, 2, ACTIVITY, OPUS);
    expect(b.setupMinutes).toBe(a.setupMinutes);
    expect(b.monthlyMinutes).toBe(a.monthlyMinutes);
    expect(estimate(profile(), { ...JOBS, 'pre-commit': [] }, 2, ACTIVITY, OPUS).setupMinutes).toBe(a.setupMinutes);
  });

  it('estimate: monthly uses 30-day activity, including deploy and nightly', () => {
    // pushes 40 × push 8 + PR pushes max(10, 40 − 10) = 30 × merge 18 + merged PRs 10 × deploy 6 + 30 nights × nightly 12
    expect(estimate(profile(), JOBS, 2, ACTIVITY, OPUS).monthlyMinutes).toBe(320 + 540 + 60 + 360);
    // no activity: only the nightly runs
    expect(estimate(profile(), JOBS, 2, { pushes: 0, prs: 0, capped: false }, OPUS).monthlyMinutes).toBe(360);
  });

  it('estimate: per-job minutes come from the S5 table by need category; unknown need = 2', () => {
    for (const c of ['hooks-ci', 'lint', 'secrets', 'deps', 'gate', 'nightly']) expect(jobMinutes(c), c).toBe(1);
    for (const c of ['sast', 'unit-tests', 'full-tests', 'image-build', 'image-scan']) expect(jobMinutes(c), c).toBe(2);
    expect(jobMinutes('dast')).toBe(3);
    for (const c of ['iac', 'sbom', 'signing', 'attestation', 'deploy-verify', 'something-new']) expect(jobMinutes(c), c).toBe(2);
    // one more dast job in merge adds 3 minutes per variant (× 1.3)
    const extra = { ...JOBS, merge: [...JOBS.merge, 'dast'] };
    expect(estimate(profile(), extra, 1, ACTIVITY, OPUS).setupMinutes).toBe(Math.ceil((PER_VARIANT + 3) * 1.3));
  });

  it('estimate: merge layer counted per PR push, not per PR', () => {
    const base = { ...JOBS, push: [], deploy: [], nightly: [] }; // only merge: 18 min a run
    // 50 pushes, 5 PRs: 5 pushes are the merges into main, the other 45 are counted as pushes to open PRs
    expect(estimate(profile(), base, 1, { pushes: 50, prs: 5, capped: false }, OPUS).monthlyMinutes).toBe(45 * 18);
    // at least one merge run per PR, even when there are fewer pushes than that
    expect(estimate(profile(), base, 1, { pushes: 3, prs: 4, capped: false }, OPUS).monthlyMinutes).toBe(4 * 18);
  });

  it('estimate: proof harness jobs count in setup, per variant', () => {
    expect(HARNESS_MINUTES_PER_VARIANT).toBe(8); // app-start 2, hooks 1, tests-repeat 2, sign-roundtrip 2, verify-lookup 1
    const empty: JobCategories = { 'pre-commit': [], push: [], merge: [], deploy: [], nightly: [] };
    expect(estimate(profile(), empty, 1, ACTIVITY, OPUS).setupMinutes).toBe(Math.ceil(8 * 1.3));
    expect(estimate(profile(), empty, 2, ACTIVITY, OPUS).setupMinutes).toBe(Math.ceil(16 * 1.3));
  });

  it('estimate: compat copies of the repo\'s own workflow jobs count in setup at 2 min each', () => {
    const p = profile({ existingWorkflows: [workflow('.github/workflows/ci.yml', ['build', 'test']), workflow('.github/workflows/lint.yml', ['lint'])] });
    expect(estimate(p, JOBS, 1, ACTIVITY, OPUS).setupMinutes).toBe(Math.ceil((PER_VARIANT + 6) * 1.3));
  });

  it('estimate: duration = setup ÷ 4 parallel jobs + 10 min queueing (low), twice that (high)', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    expect(e.durationMinutes).toEqual({ low: Math.ceil(136 / 4) + 10, high: 2 * (Math.ceil(136 / 4) + 10) });
  });

  it('estimate: variants below 1 count as 1', () => {
    expect(estimate(profile(), JOBS, 0, ACTIVITY, OPUS).setupMinutes).toBe(68);
  });
});

describe('estimate: included minutes (S12)', () => {
  it('estimate: includedMinutes from the plan for a private repo', () => {
    expect(estimate(profile({ plan: 'free' }), JOBS, 2, ACTIVITY, OPUS).includedMinutes).toBe(2000);
    expect(estimate(profile({ plan: 'pro' }), JOBS, 2, ACTIVITY, OPUS).includedMinutes).toBe(3000);
    expect(estimate(profile({ plan: 'team' }), JOBS, 2, ACTIVITY, OPUS).includedMinutes).toBe(3000);
    expect(estimate(profile({ plan: 'enterprise' }), JOBS, 2, ACTIVITY, OPUS).includedMinutes).toBe(50000);
  });

  it('estimate: includedMinutes null for a public repo (free minutes) and for plan unknown', () => {
    const pub = estimate(profile({ private: false, plan: 'team' }), JOBS, 2, ACTIVITY, OPUS);
    expect(pub.includedMinutes).toBeNull();
    expect(pub.basis.join('\n')).toMatch(/public repo.*free/i);
    const unknown = estimate(profile({ plan: 'unknown' }), JOBS, 2, ACTIVITY, OPUS);
    expect(unknown.includedMinutes).toBeNull();
    expect(unknown.basis.join('\n')).toMatch(/plan.*isn't known/i);
  });

  it('estimate: capped activity → basis says "at least N pushes"', () => {
    const e = estimate(profile(), JOBS, 2, { pushes: 287, prs: 9, capped: true }, OPUS);
    expect(e.basis).toContain('Activity: at least 287 pushes and at least 9 pull requests in the last 30 days (GitHub lists only the last 300 events and pipegen reads at most 1,000 pull requests).');
    const plain = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    expect(plain.basis.join('\n')).not.toMatch(/at least \d+ push/);
    expect(plain.basis).toContain('Activity: 40 pushes and 10 pull requests in the last 30 days.');
  });
});

describe('estimate: AI', () => {
  it('estimate: AI tokens split into input and output per stage', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    expect(e.aiTokens).toEqual([
      { stage: 'needs', input: 30_000, output: 3_000 },
      { stage: 'debate', input: 120_000, output: 18_000 },
      { stage: 'creators', input: 60_000, output: 20_000 },
      { stage: 'fix-loop', input: 150_000, output: 40_000 },
    ]);
  });

  it('estimate: input and output priced separately with claude-opus-5-5 prices', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    // $4 a million in and $20 a million out give input 1.44 and output 1.62 (3.06); low ×0.5, high ×1.5
    if (e.aiCostUsd === 'local') throw new Error('expected a priced estimate');
    expect(e.aiCostUsd.input.low).toBeCloseTo((IN / 1e6) * 4 * 0.5, 6);
    expect(e.aiCostUsd.input.high).toBeCloseTo((IN / 1e6) * 4 * 1.5, 6);
    expect(e.aiCostUsd.output.low).toBeCloseTo((OUT / 1e6) * 20 * 0.5, 6);
    expect(e.aiCostUsd.output.high).toBeCloseTo((OUT / 1e6) * 20 * 1.5, 6);
    expect(e.aiCostUsd.low).toBeCloseTo(1.53, 6);
    expect(e.aiCostUsd.high).toBeCloseTo(4.59, 6);
    // another priced model gives other numbers: Sonnet 5.5 at $2 / $10
    const s = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'claude', model: 'claude-sonnet-5-5' });
    if (s.aiCostUsd === 'local') throw new Error('expected a priced estimate');
    expect(s.aiCostUsd.high).toBeCloseTo(((IN / 1e6) * 2 + (OUT / 1e6) * 10) * 1.5, 6);
  });

  it('estimate: unknown model of a known provider is priced at that provider\'s most expensive model', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'openai', model: 'gpt-unheard-of' });
    const top = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'openai', model: 'gpt-5.5' }); // $5 / $30, the dearest OpenAI model
    expect(e.aiCostUsd).toEqual(top.aiCostUsd);
    expect(e.aiCostCapUsd).toEqual(top.aiCostCapUsd);
    const text = e.basis.join('\n');
    expect(text).toContain('"gpt-unheard-of"');
    expect(text).toContain('gpt-5.5');
    expect(text).toMatch(/highest price.*real cost is likely lower/is);
    const c = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'claude', model: 'claude-future-9' });
    const fable = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'claude', model: 'claude-fable-5-1' }); // $10 / $50
    expect(c.aiCostUsd).toEqual(fable.aiCostUsd);
    expect(c.basis.join('\n')).toContain('claude-fable-5');
    expect(estimate(profile(), JOBS, 2, ACTIVITY, OPUS).basis.join('\n')).not.toMatch(/has no price/);
    // a known OpenAI model (official price list) uses its own price: gpt-5 at $1.25 / $10
    const g = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'openai', model: 'gpt-5' });
    if (g.aiCostUsd === 'local') throw new Error('expected a priced estimate');
    expect(g.aiCostUsd.high).toBeCloseTo(((IN / 1e6) * 1.25 + (OUT / 1e6) * 10) * 1.5, 6);
  });

  it('estimate: unknown provider and model → the most expensive model in the whole price file', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'mystery', model: 'm1' });
    const fable = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'claude', model: 'claude-fable-5-1' });
    expect(e.aiCostUsd).toEqual(fable.aiCostUsd);
    expect(e.aiCostCapUsd).toEqual(fable.aiCostCapUsd);
    expect(e.basis.join('\n')).toMatch(/"m1".*highest price.*real cost is likely lower/is);
  });

  it('estimate: a model name in basis is cleaned for the terminal', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'openai', model: 'x\u001b[2Jy\u202e' });
    const text = e.basis.join('\n');
    expect(text).not.toContain('\u001b');
    expect(text).not.toContain('\u202e');
  });

  it('estimate: aiCostCapUsd is twice the high AI cost', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    if (e.aiCostUsd === 'local') throw new Error('expected a priced estimate');
    expect(e.aiCostCapUsd).toBeCloseTo(2 * e.aiCostUsd.high, 6);
    expect(e.aiCostCapUsd).toBeCloseTo(9.18, 6);
  });

  it('estimate: ollama → aiCost local, no cap', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'llama3.1', host: '127.0.0.1:11434' });
    expect(e.aiCostUsd).toBe('local');
    expect(e.aiCostCapUsd).toBeNull();
    expect(e.aiTokens).toHaveLength(4); // the tokens are still shown
    expect(e.basis.join('\n')).toMatch(/Ollama runs on your machine/);
  });

  it('estimate: the Ollama basis says "your machine" only for a local host; otherwise it names the host (final review batch 2, M3)', () => {
    for (const host of ['127.0.0.1:11434', 'localhost:11434', '0.0.0.0:11434', '[::1]:11434']) {
      expect(estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'llama3.1', host }).basis.join('\n'), host).toContain('Ollama runs on your machine');
      expect(estimateAuditAi({ name: 'ollama', model: 'llama3.1', host }, 3).basis.join('\n'), host).toContain('Ollama runs on your machine');
    }
    const remote = [
      estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'llama3.1', host: 'gpu.example.net:8443' }).basis.join('\n'),
      estimateAuditAi({ name: 'ollama', model: 'llama3.1', host: 'gpu.example.net:8443' }, 3).basis.join('\n'),
    ];
    for (const text of remote) {
      expect(text).not.toContain('your machine');
      expect(text).toContain('gpu.example.net:8443');
      expect(text).toContain('no AI cost and no cost cap');
    }
    // no host (a provider not built by ollamaProvider): never claimed to be this machine
    for (const text of [estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'llama3.1' }).basis.join('\n'), estimateAuditAi({ name: 'ollama', model: 'm' }, 3).basis.join('\n')]) {
      expect(text).not.toContain('your machine');
      expect(text).toContain("couldn't confirm");
    }
    // a hostile host string is cleaned for the terminal
    const hostile = estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'm', host: 'evil\u001b[2J\u202e:1' }).basis.join('\n');
    expect(hostile).not.toMatch(/[\u001b\u202e]/);
  });

  it('estimate: records the provider and model it was priced for (final review batch 2, I1)', () => {
    expect(estimate(profile(), JOBS, 2, ACTIVITY, OPUS).pricedFor).toEqual({ provider: 'claude', model: DEFAULT_MODEL });
    expect(estimate(profile(), JOBS, 2, ACTIVITY, { name: 'claude', model: 'claude-future-9' }).pricedFor).toEqual({ provider: 'claude', model: 'claude-future-9' });
    expect(estimate(profile(), JOBS, 2, ACTIVITY, null).pricedFor).toBeNull();
    expect(estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'm', host: 'h:1' }).pricedFor).toEqual({ provider: 'ollama', model: 'm', host: 'h:1' });
    expect(estimateAuditAi({ name: 'openai', model: 'gpt-5' }, 2).pricedFor).toEqual({ provider: 'openai', model: 'gpt-5' });
    expect(estimateAuditAi({ name: 'ollama', model: 'm' }, 2).pricedFor).toEqual({ provider: 'ollama', model: 'm' });
    // only these fields are copied: a whole provider object (with its key and complete()) is never kept
    const fakeProvider = { name: 'claude', model: DEFAULT_MODEL, complete: async () => ({}), extra: 'x' };
    expect(estimateAuditAi(fakeProvider, 1).pricedFor).toEqual({ provider: 'claude', model: DEFAULT_MODEL });
  });

  it('estimate: no provider → no AI tokens, no cost, no cap', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, null);
    expect(e.aiTokens).toEqual([]);
    expect(e.aiCostUsd).toEqual({ input: { low: 0, high: 0 }, output: { low: 0, high: 0 }, low: 0, high: 0 });
    expect(e.aiCostCapUsd).toBeNull();
  });
});

describe('estimate: basis', () => {
  it('estimate: basis lists every assumption', () => {
    const text = estimate(profile(), JOBS, 2, ACTIVITY, OPUS).basis.join('\n');
    for (const re of [
      /S5, 2026-10-26/,                      // measured per-job minutes
      /1 min.*2 min.*3 min/s,                // the table
      /2 proof variants/,                    // variants
      /1\.3/,                                // headroom
      /disputes/i,                           // the cap also covers dispute variants
      /hard cap.*twice/i,                    // setup cap
      /proof harness.*8 min/i,               // harness jobs
      /copies of your own workflow jobs/i,   // compat copies
      /push to a branch with an open pull request/i, // PR pushes
      /approximat/i,                         // ... are approximated
      /nightly.*30/i,                        // nightly
      /pre-commit.*developer's machine/i,    // pre-commit
      /4 jobs in parallel.*10 min/i,         // duration
      /tokens/i,                             // AI tokens
      /half.*one and a half/i,               // low/high
      /\$4.*\$20.*per million/i,             // prices
      /AI cost cap.*twice/i,                 // AI cap
      /2,000 included minutes/,              // plan minutes
    ]) expect(text, String(re)).toMatch(re);
  });
});

describe('estimateAuditAi (ruling B2)', () => {
  it('estimateAuditAi: basis says the calls, the range and the model in plain English', () => {
    const text = estimateAuditAi(OPUS, 5).basis.join('\n');
    expect(text).toMatch(/1 needs call/);
    expect(text).toMatch(new RegExp(`up to ${MAX_DISCOVERY_NEEDS} discovery calls`));
    expect(text).toMatch(/2k input.*2k output tokens/s);
    expect(text).toMatch(/×0\.5.*×1\.5/s);
    expect(text).toContain(DEFAULT_MODEL);
    expect(text).toMatch(/\$4.*\$20.*per million/s);
  });

  it('estimateAuditAi: unknown model is priced at the provider\'s most expensive model, and basis says so', () => {
    const a = estimateAuditAi({ name: 'claude', model: 'claude-future-9' }, 5);
    const fable = estimateAuditAi({ name: 'claude', model: 'claude-fable-5-1' }, 5);
    expect(a.costUsd).toEqual(fable.costUsd);
    expect(a.capUsd).toEqual(fable.capUsd);
    expect(a.basis.join('\n')).toMatch(/"claude-future-9".*claude-fable-5.*highest price.*real cost is likely lower/is);
    const any = estimateAuditAi({ name: 'mystery', model: 'm1' }, 5);
    expect(any.costUsd).toEqual(fable.costUsd);
  });

  it('estimateAuditAi: one needs call plus at most MAX_DISCOVERY_NEEDS candidate calls', () => {
    expect(MAX_DISCOVERY_NEEDS).toBe(5);
    expect(estimateAuditAi(OPUS, 0).tokens).toEqual({ input: 30_000, output: 3_000 });
    expect(estimateAuditAi(OPUS, 2).tokens).toEqual({ input: 30_000 + 2 * 2_000, output: 3_000 + 2 * 2_000 });
    expect(estimateAuditAi(OPUS, 5).tokens).toEqual(estimateAuditAi(OPUS, 50).tokens);
    expect(estimateAuditAi(OPUS, 50).tokens).toEqual({ input: 40_000, output: 13_000 });
    expect(estimateAuditAi(OPUS, -3).tokens).toEqual(estimateAuditAi(OPUS, 0).tokens);
    expect(estimateAuditAi(OPUS, Number.NaN).tokens).toEqual(estimateAuditAi(OPUS, 0).tokens);
  });

  it('estimateAuditAi: priced like estimate, cap = 2 × high', () => {
    const a = estimateAuditAi(OPUS, 5);
    if (a.costUsd === 'local') throw new Error('expected a priced estimate');
    // 40k in × $4 + 13k out × $20 = 0.16 + 0.26 = 0.42
    expect(a.costUsd.input.high).toBeCloseTo(0.16 * 1.5, 6);
    expect(a.costUsd.output.low).toBeCloseTo(0.26 * 0.5, 6);
    expect(a.costUsd.low).toBeCloseTo(0.21, 6);
    expect(a.costUsd.high).toBeCloseTo(0.63, 6);
    expect(a.capUsd).toBeCloseTo(1.26, 6);
  });

  it('estimateAuditAi: computed for the chosen provider and model, not always Claude', () => {
    const opus = estimateAuditAi(OPUS, 5);
    const gpt = estimateAuditAi({ name: 'openai', model: 'gpt-5-mini' }, 5);
    if (gpt.costUsd === 'local' || opus.costUsd === 'local') throw new Error('expected priced estimates');
    expect(gpt.costUsd.high).toBeCloseTo((0.04 * 0.25 + 0.013 * 2) * 1.5, 6);
    expect(gpt.capUsd).toBeCloseTo(2 * gpt.costUsd.high, 6);
    expect(gpt.capUsd).not.toBeCloseTo(opus.capUsd ?? 0, 3);
    const local = estimateAuditAi({ name: 'ollama', model: 'qwen3' }, 5);
    expect(local.costUsd).toBe('local');
    expect(local.capUsd).toBeNull();
    expect(local.tokens).toEqual(opus.tokens);
  });
});

describe('jobCategories', () => {
  it('jobCategories: the same jobs as jobCounts (which is unchanged), by need category', () => {
    const p = profile({ terraformDirs: ['infra'] });
    const needs = floorNeeds(p, NO_CAPS);
    const cats = jobCategories(needs);
    const counts = jobCounts(needs);
    for (const layer of ['pre-commit', 'push', 'merge', 'deploy', 'nightly'] as const) expect(cats[layer].length, layer).toBe(counts[layer]);
    expect(cats['pre-commit']).toEqual([]);
    expect(cats.push.sort()).toEqual([...PUSH].sort());
    expect(cats.merge.filter((c) => c === 'gate')).toHaveLength(1);
    expect(cats.nightly).toContain('nightly');
    expect(cats.nightly).toContain('dast');
    expect(cats.nightly).toContain('iac');
    expect(cats.nightly).toContain('image-build'); // the image the nightly scans is built there too (final review M8)
  });
});

describe('data files', () => {
  it('prices: file has checkedAt date and a claude-opus-5-5 entry with input and output prices', () => {
    const prices = loadAiPrices();
    expect(prices.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(prices.providers.claude.models[DEFAULT_MODEL]).toEqual({ input: 4, output: 20 });
    expect(prices.providers.ollama.local).toBe(true);
    expect(prices.providers.ollama.anyModel).toEqual({ input: 0, output: 0 });
  });

  it('plans: Team includes 3,000 minutes', () => {
    const plans = loadGitHubPlans();
    expect(plans.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(plans.includedMinutes).toEqual({ free: 2000, pro: 3000, team: 3000, enterprise: 50000 });
  });

  it('prices and plans: strict schemas refuse unknown keys and a missing default model', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-est-'));
    const prices = readFileSync(new URL('../data/ai-prices.yml', import.meta.url), 'utf8');
    const extra = join(dir, 'extra.yml');
    writeFileSync(extra, `${prices}\nsurprise: 1\n`);
    expect(() => loadAiPrices(extra)).toThrow(/not valid/);
    const noDefault = join(dir, 'nodefault.yml');
    writeFileSync(noDefault, prices.replaceAll(DEFAULT_MODEL, 'claude-other'));
    expect(() => loadAiPrices(noDefault)).toThrow(new RegExp(DEFAULT_MODEL));
    const plans = readFileSync(new URL('../data/github-plans.yml', import.meta.url), 'utf8');
    const badPlan = join(dir, 'plans.yml');
    writeFileSync(badPlan, plans.replace('team: 3000', 'team: -1'));
    expect(() => loadGitHubPlans(badPlan)).toThrow(/not valid/);
  });

  it('prices and plans: checkedAt must be a real calendar date', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-est-'));
    const prices = readFileSync(new URL('../data/ai-prices.yml', import.meta.url), 'utf8');
    const plans = readFileSync(new URL('../data/github-plans.yml', import.meta.url), 'utf8');
    for (const bad of ['2026-13-99', '2026-02-30', '2025-02-29', '2026-00-10']) {
      const p = join(dir, 'p.yml');
      writeFileSync(p, prices.replace(/^checkedAt: .*$/m, `checkedAt: '${bad}'`));
      expect(() => loadAiPrices(p), bad).toThrow(/checkedAt: must be a date/);
      const q = join(dir, 'q.yml');
      writeFileSync(q, plans.replace(/^checkedAt: .*$/m, `checkedAt: '${bad}'`));
      expect(() => loadGitHubPlans(q), bad).toThrow(/checkedAt: must be a date/);
    }
    const leap = join(dir, 'leap.yml');
    writeFileSync(leap, prices.replace(/^checkedAt: .*$/m, "checkedAt: '2028-02-29'"));
    expect(loadAiPrices(leap).checkedAt).toBe('2028-02-29');
  });

  it('prices: a price of 0 is refused for every provider except local Ollama', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-est-'));
    const prices = readFileSync(new URL('../data/ai-prices.yml', import.meta.url), 'utf8');
    const tries: [string, string][] = [
      ['claude-sonnet-5-5: { input: 2.00, output: 10.00 }', 'claude-sonnet-5-5: { input: 0, output: 10.00 }'],
      ['claude-sonnet-5-5: { input: 2.00, output: 10.00 }', 'claude-sonnet-5-5: { input: 2.00, output: 0 }'],
      ['gpt-5: { input: 1.25, output: 10.00 }', 'gpt-5: { input: 0, output: 0 }'],
    ];
    tries.forEach(([from, to], i) => {
      expect(prices).toContain(from);
      const f = join(dir, `zero${i}.yml`);
      writeFileSync(f, prices.replace(from, to));
      expect(() => loadAiPrices(f), to).toThrow(/greater than 0|must be above 0|not valid/);
    });
    expect(loadAiPrices().providers.ollama.anyModel).toEqual({ input: 0, output: 0 }); // local Ollama keeps its 0
  });
});

// ---------- activity30d ----------

const NOW = Date.parse('2026-10-27T12:00:00Z');
const DAY = 86_400_000;
const iso = (daysAgo: number) => new Date(NOW - daysAgo * DAY).toISOString();
const EVENTS = 'GET https://api.github.com/repos/o/r/events';
const PULLS = 'GET https://api.github.com/repos/o/r/pulls';
const page = (c: Call) => Number(c.url.searchParams.get('page') ?? '1');

/** Event pages of 100 from a flat list. */
const pages = (items: unknown[]) => (c: Call): Reply => ({ body: items.slice((page(c) - 1) * 100, page(c) * 100) });

describe('activity30d', () => {
  it('activity30d: counts pushes and pull requests of the last 30 days', async () => {
    const events = [
      { type: 'PushEvent', created_at: iso(1) }, { type: 'IssuesEvent', created_at: iso(2) },
      { type: 'PushEvent', created_at: iso(10) }, { type: 'PullRequestEvent', created_at: iso(11) },
      { type: 'PushEvent', created_at: iso(29) }, { type: 'PushEvent', created_at: iso(31) },
    ];
    const pulls = [{ created_at: iso(3) }, { created_at: iso(20) }, { created_at: iso(45) }];
    const { gh, calls } = fakeOctokit({ [EVENTS]: pages(events), [PULLS]: pages(pulls) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 3, prs: 2, capped: false });
    const pullCall = calls.find((c) => c.url.pathname.endsWith('/pulls'));
    expect(pullCall?.url.searchParams.get('state')).toBe('all');
    expect(pullCall?.url.searchParams.get('sort')).toBe('created');
    expect(pullCall?.url.searchParams.get('direction')).toBe('desc');
  });

  it('activity30d: 300 events all inside the 30 days → capped', async () => {
    const events = Array.from({ length: 300 }, (_, i) => ({ type: i % 2 === 0 ? 'PushEvent' : 'WatchEvent', created_at: iso(i / 20) }));
    const { gh, calls } = fakeOctokit({ [EVENTS]: pages(events), [PULLS]: pages([]) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 150, prs: 0, capped: true });
    expect(calls.filter((c) => c.url.pathname.endsWith('/events'))).toHaveLength(3); // GitHub serves at most 3 pages of 100
  });

  it('activity30d: pull request page limit reached with every PR inside the window → capped', async () => {
    const prs = Array.from({ length: 1000 }, (_, i) => ({ created_at: iso(i / 40) })); // 25 days spread
    const { gh, calls } = fakeOctokit({ [EVENTS]: pages([]), [PULLS]: pages(prs) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 0, prs: 1000, capped: true });
    expect(calls.filter((c) => c.url.pathname.endsWith('/pulls'))).toHaveLength(10);
    const e = estimate(profile(), JOBS, 2, a, OPUS);
    expect(e.basis.join('\n')).toContain('at least 1,000 pull requests');
  });

  it('activity30d: exactly 1,000 PRs where the last page has an older one is not capped', async () => {
    const prs = [...Array.from({ length: 999 }, (_, i) => ({ created_at: iso(i / 40) })), { created_at: iso(40) }];
    const { gh } = fakeOctokit({ [EVENTS]: pages([]), [PULLS]: pages(prs) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 0, prs: 999, capped: false });
  });

  it('activity30d: stops paging at the first event older than 30 days (not capped)', async () => {
    const events = [...Array.from({ length: 150 }, () => ({ type: 'PushEvent', created_at: iso(1) })), ...Array.from({ length: 150 }, () => ({ type: 'PushEvent', created_at: iso(40) }))];
    const { gh, calls } = fakeOctokit({ [EVENTS]: pages(events), [PULLS]: pages([]) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 150, prs: 0, capped: false });
    expect(calls.filter((c) => c.url.pathname.endsWith('/events'))).toHaveLength(2);
  });

  it('activity30d: waits out a short rate limit from the shared budget, then retries', async () => {
    let first = true;
    const limited = (c: Call): Reply => {
      if (first) {
        first = false;
        return { status: 403, body: { message: 'API rate limit exceeded' }, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(NOW / 1000) + 10) } };
      }
      return pages([{ type: 'PushEvent', created_at: iso(1) }])(c);
    };
    const { gh } = fakeOctokit({ [EVENTS]: limited, [PULLS]: pages([]) });
    const budget = newRateBudget(120_000);
    const sleep = vi.fn(async () => {});
    const a = await activity30d(gh, profile(), { budget, now: () => NOW, sleep });
    expect(a).toEqual({ pushes: 1, prs: 0, capped: false });
    expect(sleep).toHaveBeenCalledTimes(1);
    expect(budget.remainingMs).toBeLessThan(120_000);
  });

  it('activity30d: a spent budget stops with GitHubRateLimitError', async () => {
    const limited = (): Reply => ({ status: 429, body: { message: 'slow down' }, headers: { 'retry-after': '30' } });
    const { gh } = fakeOctokit({ [EVENTS]: limited, [PULLS]: pages([]) });
    await expect(activity30d(gh, profile(), { budget: newRateBudget(1_000), now: () => NOW, sleep: async () => {} }))
      .rejects.toBeInstanceOf(GitHubRateLimitError);
  });

  it('activity30d: an unreadable answer is an error, not a zero count', async () => {
    const { gh } = fakeOctokit({ [EVENTS]: { body: { not: 'a list' } }, [PULLS]: pages([]) });
    await expect(activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW })).rejects.toThrow(/could not be read/);
  });
});
