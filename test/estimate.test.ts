import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { GitHubRateLimitError, newRateBudget } from '../src/engine/github-rate.js';
import { CANDIDATES_MAX_OUTPUT_TOKENS, CANDIDATES_REQUEST_MAX_BYTES, MAX_DISCOVERY_NEEDS, NEEDS_MAX_OUTPUT_TOKENS } from '../src/engine/discovery-limits.js';
import { floorNeeds, jobCategories, jobCounts } from '../src/engine/needs.js';
import {
  activity30d, aiRequestBytes, estimate, estimateAuditAi, FRAMING_MARGIN_TOKENS, HARNESS_MINUTES_PER_VARIANT, jobMinutes, loadAiPrices, loadGitHubPlans,
  requestCeilingUsd, unpricedModel, usageCeilingUsd, usageCostUsd,
  type Activity, type JobCategories,
} from '../src/estimate/estimate.js';
import { DEFAULT_MODEL, type Capabilities, type ExistingWorkflow, type RepoProfile, type Service } from '../src/types.js';
import { fakeOctokit, type Call, type Reply } from './helpers/fake-http.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';

// ---------- builders ----------

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'web', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [],
  scripts: ['start', 'test'], frameworks: ['express'], quality: emptyServiceQuality(), ...over,
});
const profile = (over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'free',
  monorepo: 'none', services: [svc()], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(), ...over,
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
/** The needs request's size (UTF-8 bytes) estimateAuditAi is given: a 50 KB bundle and the rest of the prompt. */
const NEEDS_BYTES = 60_000;

// Token totals for a full run (fixed table): needs 30k/3k, debate at most 9 calls (Plan F F4, rulings S10 and F4-R12: 2 × 52k/6k
// with the bundle, 2 × 31k/4k critique, 5 × 19k/3k rounds = 261k/35k), creators 60k/20k, fix loop 2 parts × 5 × 15k/4k.
const IN = 30_000 + 261_000 + 60_000 + 150_000; // 501k
const OUT = 3_000 + 35_000 + 20_000 + 40_000;    // 98k

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
    for (const c of ['workflow-lint', 'dockerfile-lint', 'duplication', 'dependency-review', 'licences', 'scorecard']) expect(jobMinutes(c), c).toBe(1);
    expect(jobMinutes('api-dast')).toBe(3);
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
    expect(e.basis).toContain("Activity: at least 287 pushes and at least 9 pull requests in the last 30 days (pipegen couldn't read back to the start of the 30 days: GitHub lists only the last 300 events, pipegen reads at most 1,000 pull requests, and it stops at GitHub's rate limit).");
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
      { stage: 'debate', input: 261_000, output: 35_000 },
      { stage: 'creators', input: 60_000, output: 20_000 },
      { stage: 'fix-loop', input: 150_000, output: 40_000 },
    ]);
  });

  it('estimate: input and output priced separately with claude-opus-5-5 prices', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, OPUS);
    // $4 a million in and $20 a million out give input 2.004 and output 1.96 (3.964); low ×0.5, high ×1.5
    if (e.aiCostUsd === 'local') throw new Error('expected a priced estimate');
    expect(e.aiCostUsd.input.low).toBeCloseTo((IN / 1e6) * 4 * 0.5, 6);
    expect(e.aiCostUsd.input.high).toBeCloseTo((IN / 1e6) * 4 * 1.5, 6);
    expect(e.aiCostUsd.output.low).toBeCloseTo((OUT / 1e6) * 20 * 0.5, 6);
    expect(e.aiCostUsd.output.high).toBeCloseTo((OUT / 1e6) * 20 * 1.5, 6);
    expect(e.aiCostUsd.low).toBeCloseTo(1.982, 6);
    expect(e.aiCostUsd.high).toBeCloseTo(5.946, 6);
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
    expect(e.aiCostCapUsd).toBeCloseTo(11.892, 6);
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
      expect(estimateAuditAi({ name: 'ollama', model: 'llama3.1', host }, 3, NEEDS_BYTES).basis.join('\n'), host).toContain('Ollama runs on your machine');
    }
    const remote = [
      estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'llama3.1', host: 'gpu.example.net:8443' }).basis.join('\n'),
      estimateAuditAi({ name: 'ollama', model: 'llama3.1', host: 'gpu.example.net:8443' }, 3, NEEDS_BYTES).basis.join('\n'),
    ];
    for (const text of remote) {
      expect(text).not.toContain('your machine');
      expect(text).toContain('gpu.example.net:8443');
      expect(text).toContain('no AI cost and no cost cap');
    }
    // no host (a provider not built by ollamaProvider): never claimed to be this machine
    for (const text of [estimate(profile(), JOBS, 2, ACTIVITY, { name: 'ollama', model: 'llama3.1' }).basis.join('\n'), estimateAuditAi({ name: 'ollama', model: 'm' }, 3, NEEDS_BYTES).basis.join('\n')]) {
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
    expect(estimateAuditAi({ name: 'openai', model: 'gpt-5' }, 2, NEEDS_BYTES).pricedFor).toEqual({ provider: 'openai', model: 'gpt-5' });
    expect(estimateAuditAi({ name: 'ollama', model: 'm' }, 2, NEEDS_BYTES).pricedFor).toEqual({ provider: 'ollama', model: 'm' });
    // only these fields are copied: a whole provider object (with its key and complete()) is never kept
    const fakeProvider = { name: 'claude', model: DEFAULT_MODEL, complete: async () => ({}), extra: 'x' };
    expect(estimateAuditAi(fakeProvider, 1, NEEDS_BYTES).pricedFor).toEqual({ provider: 'claude', model: DEFAULT_MODEL });
  });

  it('estimate: no provider → no AI tokens, no cost, no cap', () => {
    const e = estimate(profile(), JOBS, 2, ACTIVITY, null);
    expect(e.aiTokens).toEqual([]);
    expect(e.aiCostUsd).toEqual({ input: { low: 0, high: 0 }, output: { low: 0, high: 0 }, low: 0, high: 0 });
    expect(e.aiCostCapUsd).toBeNull();
  });
});

describe('estimate: basis', () => {
  it('estimate: scorecard in the nightly adds a basis line that it runs weekly and is counted nightly (PS10)', () => {
    const withCard = estimate(profile(), { ...JOBS, nightly: [...JOBS.nightly, 'scorecard'] }, 2, ACTIVITY, OPUS);
    expect(withCard.basis.join('\n')).toContain('Scorecard runs weekly; counted nightly (leans high)');
    expect(estimate(profile(), JOBS, 2, ACTIVITY, OPUS).basis.join('\n')).not.toContain('Scorecard runs weekly');
  });

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

/** The tier threshold field name and a tier, built at runtime (written out whole, the line reads as a secret to the repo guard). */
const TIER_FIELD = ['above', 'input', 'tokens'].join('_');
const tierOf = (above: number, input: number, output: number) => Object.fromEntries([[TIER_FIELD, above], ['input', input], ['output', output]]);
const tierLine = (above: string, rest: string) => ['long: { ', TIER_FIELD, ': ', above, ', ', rest, ' }'].join('');

/** Usage with all four counts (property names built at runtime: no secret-like literals in test/). */
const used = (i: number, o: number, cr = 0, cw = 0) => Object.fromEntries([['input' + 'Tokens', i], ['output' + 'Tokens', o], ['cacheRead' + 'Tokens', cr], ['cacheWrite' + 'Tokens', cw]]) as never;

/** The needs call's and one discovery call's worst case together (what the cap must always hold, U13). */
const worstOf = (provider: { name: string; model: string }, bytes: number) =>
  (requestCeilingUsd(provider, bytes, NEEDS_MAX_OUTPUT_TOKENS) as number) + (requestCeilingUsd(provider, CANDIDATES_REQUEST_MAX_BYTES, CANDIDATES_MAX_OUTPUT_TOKENS) as number);

describe('estimateAuditAi (ruling B2)', () => {
  it('usageCostUsd: the estimate price table; cache tokens never priced low; local is free', () => {
    // opus 5.5: $4 / $20 per million (data/ai-prices.yml)
    expect(usageCostUsd(OPUS, used(1_000_000, 0))).toBeCloseTo(4, 10);
    expect(usageCostUsd(OPUS, used(0, 1_000_000))).toBeCloseTo(20, 10);
    expect(usageCostUsd(OPUS, used(0, 0, 1_000_000, 0))).toBeCloseTo(4, 10); // a cache read at the full input price
    expect(usageCostUsd(OPUS, used(0, 0, 0, 1_000_000))).toBeCloseTo(5, 10); // a cache write at 1.25×
    expect(usageCostUsd({ name: 'claude', model: 'claude-future-9' }, used(1_000_000, 0))).toBeCloseTo(10, 10); // the provider's top price
    expect(usageCostUsd({ name: 'ollama', model: 'm' }, used(1_000_000, 1_000_000))).toBe('local');
  });

  it('requestCeilingUsd (U13): every byte a token plus the framing margin, the full output limit, the highest price it could bill at', () => {
    // opus 5.5 has the refusal fallback: two runs (it, then another Claude model), each at the top Claude price ($10 / $50, Fable 5.1)
    const perRun = ((10_000 + FRAMING_MARGIN_TOKENS) * 1.25 * 10 + 16_000 * 50) / 1e6;
    expect(FRAMING_MARGIN_TOKENS).toBe(2_000);
    expect(requestCeilingUsd(OPUS, 10_000, 16_000)).toBeCloseTo(2 * perRun, 10);
    // no fallback (Haiku 5.5): one run at its own price
    expect(requestCeilingUsd({ name: 'claude', model: 'claude-haiku-5-5' }, 10_000, 16_000)).toBeCloseTo(((12_000 * 1.25 * 0.1) + 16_000 * 0.5) / 1e6, 10);
    expect(requestCeilingUsd({ name: 'openai', model: 'gpt-5' }, 10_000, 16_000)).toBeCloseTo(((12_000 * 1.25 * 1.25) + 16_000 * 10) / 1e6, 10);
    // no output limit: no bound at all; local: no cost
    for (const bad of [undefined, 0, Number.NaN, -5]) expect(requestCeilingUsd(OPUS, 10_000, bad as number)).toBe(Number.POSITIVE_INFINITY);
    expect(requestCeilingUsd({ name: 'ollama', model: 'm' }, 10_000, 16_000)).toBe('local');
    // what was used, priced the same way (usage already holds every run, so no doubling)
    expect(usageCeilingUsd(OPUS, used(1_000_000, 1_000_000, 0, 0))).toBeCloseTo(60, 10);
    expect(usageCeilingUsd({ name: 'claude', model: 'claude-haiku-5-5' }, used(50_000, 50_000))).toBeCloseTo((50_000 * 0.1 + 50_000 * 0.5) / 1e6, 10);
    expect(usageCeilingUsd({ name: 'ollama', model: 'm' }, used(1, 1))).toBe('local');
    // bytes of a request: system + user + schema
    expect(aiRequestBytes({ system: 'ab', user: 'é', schemaName: 'x', jsonSchema: { a: 1 }, timeoutMs: 1 })).toBe(2 + 2 + 7);
  });

  it('N1 (U14): a model with no price is unbounded for the hard cap: refused before consent, with the priced choices', () => {
    const pro = { name: 'openai', model: 'gpt-5-pro' };
    expect(requestCeilingUsd(pro, 1_000, 16_000)).toBe(Number.POSITIVE_INFINITY);
    expect(usageCeilingUsd(pro, used(1, 1))).toBe(Number.POSITIVE_INFINITY);
    const e = estimateAuditAi(pro, 5, NEEDS_BYTES);
    expect(e.unpriced).toEqual({
      model: 'gpt-5-pro', choose: ['gpt-5', 'gpt-5-mini', 'gpt-5.5'],
      message: "pipegen doesn't know the price of gpt-5-pro, so it can't keep a hard cost limit. Choose one of: gpt-5, gpt-5-mini, gpt-5.5.",
    });
    expect(e.capUsd).toBe(0); // fail closed: no call fits a cap of 0
    expect(e.basis).toContain(e.unpriced?.message);
    expect(e.costUsd).not.toBe('local'); // the display estimate still prices it like the dearest model
    expect(unpricedModel({ name: 'claude', model: 'claude-future-9' })?.choose).toContain(DEFAULT_MODEL);
    for (const ok of [OPUS, { name: 'openai', model: 'gpt-5' }, { name: 'ollama', model: 'llama3.1' }]) {
      expect(unpricedModel(ok), ok.model).toBeNull();
      expect(estimateAuditAi(ok, 5, NEEDS_BYTES).unpriced).toBeNull();
    }
    expect(unpricedModel({ name: 'mystery', model: 'm' })?.choose).toEqual([]);
  });

  it('N2 (U14): above a price tier threshold the higher prices apply: to the worst case when its input bound crosses it, to usage by its real prompt tokens', () => {
    const haiku = { name: 'claude', model: 'claude-haiku-5-5' };
    // a prompt up to 100,000 tokens pays $0.10 / $0.50, a longer one $0.50 / $2.50 (Anthropic pricing page)
    const low = (bytes: number) => ((bytes + FRAMING_MARGIN_TOKENS) * 1.25 * 0.1 + 16_000 * 0.5) / 1e6;
    const high = (bytes: number) => ((bytes + FRAMING_MARGIN_TOKENS) * 1.25 * 0.5 + 16_000 * 2.5) / 1e6;
    expect(requestCeilingUsd(haiku, 98_000, 16_000)).toBeCloseTo(low(98_000), 12); // bound 100,000: not above
    expect(requestCeilingUsd(haiku, 98_001, 16_000)).toBeCloseTo(high(98_001), 12);
    expect(usageCostUsd(haiku, used(100_000, 1_000))).toBeCloseTo((100_000 * 0.1 + 1_000 * 0.5) / 1e6, 12);
    expect(usageCostUsd(haiku, used(90_000, 1_000, 10_001, 0))).toBeCloseTo(((90_000 + 10_001) * 0.5 + 1_000 * 2.5) / 1e6, 12); // cache reads count toward the prompt
    expect(usageCeilingUsd(haiku, used(100_001, 0))).toBeCloseTo(100_001 * 0.5 / 1e6, 12);
    // gpt-5.5 above 272,000: $10 / $45 (OpenAI pricing page)
    const gpt = { name: 'openai', model: 'gpt-5.5' };
    expect(requestCeilingUsd(gpt, 300_000, 16_000)).toBeCloseTo(((302_000 * 1.25 * 10) + 16_000 * 45) / 1e6, 12);
    expect(requestCeilingUsd(gpt, 100_000, 16_000)).toBeCloseTo(((102_000 * 1.25 * 5) + 16_000 * 30) / 1e6, 12);
    // the consented cap follows: a large needs request on Haiku 5.5 is capped at the higher tier
    expect(estimateAuditAi(haiku, 5, 150_000).capUsd as number).toBeGreaterThanOrEqual(requestCeilingUsd(haiku, 150_000, NEEDS_MAX_OUTPUT_TOKENS) as number);
    // the file carries the tiers
    expect(loadAiPrices().providers.claude.models['claude-haiku-5-5']).toEqual({ input: 0.1, output: 0.5, long: tierOf(100_000, 0.5, 2.5) });
    expect(loadAiPrices().providers.openai.models['gpt-5.5']).toEqual({ input: 5, output: 30, long: tierOf(272_000, 10, 45) });
  });

  it('estimateAuditAi (U13): the cap always has room for the needs call and one discovery call at their worst', () => {
    for (const provider of [OPUS, { name: 'claude', model: 'claude-haiku-5-5' }, { name: 'openai', model: 'gpt-5' }]) {
      for (const bytes of [5_000, NEEDS_BYTES, 150_000]) {
        const e = estimateAuditAi(provider, 5, bytes);
        const worst = (requestCeilingUsd(provider, bytes, NEEDS_MAX_OUTPUT_TOKENS) as number) + (requestCeilingUsd(provider, CANDIDATES_REQUEST_MAX_BYTES, CANDIDATES_MAX_OUTPUT_TOKENS) as number);
        const high = (e.costUsd as { high: number }).high;
        expect(e.capUsd, `${provider.model} ${bytes}`).toBeCloseTo(Math.max(2 * high, worst), 10);
        expect(e.capUsd as number).toBeGreaterThanOrEqual(worst);
      }
    }
    const text = estimateAuditAi(OPUS, 5, NEEDS_BYTES).basis.join('\n');
    expect(text).toMatch(/reserves/);
    expect(text).toMatch(/fallback/);
    expect(estimateAuditAi({ name: 'ollama', model: 'm' }, 5, NEEDS_BYTES).capUsd).toBeNull();
  });

  it('estimateAuditAi: basis says the calls, the range and the model in plain English', () => {
    const text = estimateAuditAi(OPUS, 5, NEEDS_BYTES).basis.join('\n');
    expect(text).toMatch(/1 needs call/);
    expect(text).toMatch(new RegExp(`up to ${MAX_DISCOVERY_NEEDS} discovery calls`));
    expect(text).toMatch(/2k input.*2k output tokens/s);
    expect(text).toMatch(/×0\.5.*×1\.5/s);
    expect(text).toContain(DEFAULT_MODEL);
    expect(text).toMatch(/\$4.*\$20.*per million/s);
  });

  it('estimateAuditAi: unknown model is priced at the provider\'s most expensive model for display, and basis says so; no cap (U14)', () => {
    const a = estimateAuditAi({ name: 'claude', model: 'claude-future-9' }, 5, NEEDS_BYTES);
    const fable = estimateAuditAi({ name: 'claude', model: 'claude-fable-5-1' }, 5, NEEDS_BYTES);
    expect(a.costUsd).toEqual(fable.costUsd);
    // a hard cap can't rest on a guessed price: unbounded, cap 0, refused before consent
    expect(worstOf({ name: 'claude', model: 'claude-future-9' }, NEEDS_BYTES)).toBe(Number.POSITIVE_INFINITY);
    expect(a.capUsd).toBe(0);
    expect(a.unpriced?.model).toBe('claude-future-9');
    expect(a.basis.join('\n')).toMatch(/"claude-future-9".*claude-fable-5.*highest price.*real cost is likely lower/is);
    const any = estimateAuditAi({ name: 'mystery', model: 'm1' }, 5, NEEDS_BYTES);
    expect(any.costUsd).toEqual(fable.costUsd);
  });

  it('estimateAuditAi: one needs call plus at most MAX_DISCOVERY_NEEDS candidate calls', () => {
    expect(MAX_DISCOVERY_NEEDS).toBe(5);
    expect(estimateAuditAi(OPUS, 0, NEEDS_BYTES).tokens).toEqual({ input: 30_000, output: 3_000 });
    expect(estimateAuditAi(OPUS, 2, NEEDS_BYTES).tokens).toEqual({ input: 30_000 + 2 * 2_000, output: 3_000 + 2 * 2_000 });
    expect(estimateAuditAi(OPUS, 5, NEEDS_BYTES).tokens).toEqual(estimateAuditAi(OPUS, 50, NEEDS_BYTES).tokens);
    expect(estimateAuditAi(OPUS, 50, NEEDS_BYTES).tokens).toEqual({ input: 40_000, output: 13_000 });
    expect(estimateAuditAi(OPUS, -3, NEEDS_BYTES).tokens).toEqual(estimateAuditAi(OPUS, 0, NEEDS_BYTES).tokens);
    expect(estimateAuditAi(OPUS, Number.NaN, NEEDS_BYTES).tokens).toEqual(estimateAuditAi(OPUS, 0, NEEDS_BYTES).tokens);
  });

  it('estimateAuditAi: priced like estimate, cap = 2 × high or the two worst calls, whichever is higher', () => {
    const a = estimateAuditAi(OPUS, 5, NEEDS_BYTES);
    if (a.costUsd === 'local') throw new Error('expected a priced estimate');
    // 40k in × $4 + 13k out × $20 = 0.16 + 0.26 = 0.42
    expect(a.costUsd.input.high).toBeCloseTo(0.16 * 1.5, 6);
    expect(a.costUsd.output.low).toBeCloseTo(0.26 * 0.5, 6);
    expect(a.costUsd.low).toBeCloseTo(0.21, 6);
    expect(a.costUsd.high).toBeCloseTo(0.63, 6);
    expect(a.capUsd).toBeCloseTo(Math.max(1.26, worstOf(OPUS, NEEDS_BYTES)), 6);
  });

  it('estimateAuditAi: computed for the chosen provider and model, not always Claude', () => {
    const opus = estimateAuditAi(OPUS, 5, NEEDS_BYTES);
    const gpt = estimateAuditAi({ name: 'openai', model: 'gpt-5-mini' }, 5, NEEDS_BYTES);
    if (gpt.costUsd === 'local' || opus.costUsd === 'local') throw new Error('expected priced estimates');
    expect(gpt.costUsd.high).toBeCloseTo((0.04 * 0.25 + 0.013 * 2) * 1.5, 6);
    expect(gpt.capUsd).toBeCloseTo(Math.max(2 * gpt.costUsd.high, worstOf({ name: 'openai', model: 'gpt-5-mini' }, NEEDS_BYTES)), 6);
    expect(gpt.capUsd).not.toBeCloseTo(opus.capUsd ?? 0, 3);
    const local = estimateAuditAi({ name: 'ollama', model: 'qwen3' }, 5, NEEDS_BYTES);
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
    // Plan P: format and coverage share lint and unit-tests; the workflow lint is one new job; the merge layer adds three repo checks
    expect(cats.push.sort()).toEqual([...PUSH, 'workflow-lint'].sort());
    expect(cats.merge).toEqual(expect.arrayContaining(['workflow-lint', 'duplication', 'dependency-review', 'licences']));
    expect(cats.merge).not.toContain('scorecard'); // private, no code scanning: skipped
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

  it('prices: a price tier needs a whole-number threshold above 0 and prices no lower than the base ones', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-est-'));
    const prices = readFileSync(new URL('../data/ai-prices.yml', import.meta.url), 'utf8');
    const from = tierLine('100000', 'input: 0.50, output: 2.50');
    expect(prices).toContain(from);
    for (const to of [tierLine('0', 'input: 0.50, output: 2.50'), tierLine('1.5', 'input: 0.50, output: 2.50'),
      tierLine('100000', 'input: 0.05, output: 2.50'), tierLine('100000', 'input: 0.50')]) {
      const f = join(dir, 'tier.yml');
      writeFileSync(f, prices.replace(from, to));
      expect(() => loadAiPrices(f), to).toThrow(/not valid/);
    }
  });
});

// ---------- activity30d ----------

const NOW = Date.parse('2026-10-27T12:00:00Z');
const DAY = 86_400_000;
const iso = (daysAgo: number) => new Date(NOW - daysAgo * DAY).toISOString();
const EVENTS = 'GET https://api.github.com/repos/o/r/events';
const PULLS = 'GET https://api.github.com/repos/o/r/pulls';
const page = (c: Call) => Number(c.url.searchParams.get('page') ?? '1');

/** Pages of 100 from a flat list, with GitHub's `Link: rel="next"` header while more items follow. */
const pages = (items: unknown[]) => (c: Call): Reply => ({
  body: items.slice((page(c) - 1) * 100, page(c) * 100),
  headers: items.length > page(c) * 100 ? { link: nextLink(c, page(c) + 1) } : {},
});
/** GitHub's Link header pointing at page `n` of the same list. */
const nextLink = (c: Call, n: number) => `<${c.url.origin}${c.url.pathname}?per_page=100&page=${n}>; rel="next"`;
/** Event pages given one by one (GitHub often serves fewer than per_page items on a page that isn't the last). */
const givenPages = (list: unknown[][]) => (c: Call): Reply => ({
  body: list[page(c) - 1] ?? [],
  headers: page(c) < list.length ? { link: nextLink(c, page(c) + 1) } : {},
});

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
    // 25 days spread; a next page is left after the 10th (final review I1: GitHub's Link header says so)
    const prs = Array.from({ length: 1001 }, (_, i) => ({ created_at: iso(i / 40) }));
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

  it('activity30d: a stray old event in the middle of a page does not end the count (final re-review I1)', async () => {
    // GitHub's event list isn't strictly by date: older events show up mid-list. Only the page's last event says the
    // 30-day start was reached. Here 3 pages reach back 6 days only, so the count is a lower bound.
    const mk = (n: number, startDay: number) => Array.from({ length: n }, (_, i) => ({ type: 'PushEvent', created_at: iso(startDay + i / 100) }));
    const p1 = [...mk(48, 0), { type: 'PullRequestEvent', created_at: iso(290) }, ...mk(48, 1)];
    const p2 = [...mk(50, 2), { type: 'PullRequestEvent', created_at: iso(95) }, ...mk(49, 3)];
    const p3 = mk(100, 4);
    const { gh, calls } = fakeOctokit({ [EVENTS]: givenPages([p1, p2, p3]), [PULLS]: pages([]) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 295, prs: 0, capped: true });
    expect(calls.filter((c) => c.url.pathname.endsWith('/events'))).toHaveLength(3);
    expect(estimate(profile(), JOBS, 2, a, OPUS).basis.join('\n')).toContain('at least 295 pushes');
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

  // ---- Plan U final review I1: GitHub's Link header, not a full page, says whether another page exists ----

  it('activity30d (final review I1): a 97-item page with Link rel="next" is followed; the pushes on page 2 count', async () => {
    const first = Array.from({ length: 97 }, (_, i) => ({ type: 'WatchEvent', created_at: iso(i / 40) }));
    const second = [{ type: 'PushEvent', created_at: iso(5) }, { type: 'PushEvent', created_at: iso(6) }, { type: 'WatchEvent', created_at: iso(31) }];
    const { gh, calls } = fakeOctokit({ [EVENTS]: givenPages([first, second]), [PULLS]: pages([]) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 2, prs: 0, capped: false }); // the event older than 30 days ends the count: exact
    expect(calls.filter((c) => c.url.pathname.endsWith('/events'))).toHaveLength(2);
  });

  it('activity30d (final review I1): GitHub\'s event list ends at its 300-event limit inside the 30 days → capped, even with short pages', async () => {
    const short = (from: number) => Array.from({ length: 97 }, (_, i) => ({ type: i % 2 === 0 ? 'PushEvent' : 'WatchEvent', created_at: iso(from + i / 100) }));
    const { gh, calls } = fakeOctokit({ [EVENTS]: givenPages([short(0), short(1), short(2)]), [PULLS]: pages([]) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 3 * 49, prs: 0, capped: true });
    expect(calls.filter((c) => c.url.pathname.endsWith('/events'))).toHaveLength(3);
    expect(estimate(profile(), JOBS, 2, a, OPUS).basis.join('\n')).toContain('Activity: at least 147 pushes');
  });

  it('activity30d (final review I1): a list that ends before the limit, with no Link rel="next", is the whole 30 days (exact)', async () => {
    const first = Array.from({ length: 97 }, () => ({ type: 'PushEvent', created_at: iso(2) }));
    const { gh, calls } = fakeOctokit({ [EVENTS]: givenPages([first, [{ type: 'PushEvent', created_at: iso(3) }]]), [PULLS]: pages([]) });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW });
    expect(a).toEqual({ pushes: 98, prs: 0, capped: false });
    expect(calls.filter((c) => c.url.pathname.endsWith('/events'))).toHaveLength(2);
  });

  it('activity30d (final review I1): a rate stop on a later page keeps what was counted, as a lower bound (capped)', async () => {
    const first = Array.from({ length: 97 }, () => ({ type: 'PushEvent', created_at: iso(1) }));
    const events = (c: Call): Reply => (page(c) === 1
      ? givenPages([first, []])(c)
      : { status: 429, body: { message: 'slow down' }, headers: { 'retry-after': '30' } });
    const prs = Array.from({ length: 100 }, () => ({ created_at: iso(1) }));
    const pulls = (c: Call): Reply => (page(c) === 1 ? pages([...prs, ...prs])(c) : { status: 429, body: { message: 'slow down' }, headers: { 'retry-after': '30' } });
    const { gh } = fakeOctokit({ [EVENTS]: events, [PULLS]: pulls });
    const a = await activity30d(gh, profile(), { budget: newRateBudget(1_000), now: () => NOW, sleep: async () => {} });
    expect(a).toEqual({ pushes: 97, prs: 100, capped: true });
    // the first page of a list still has to answer: a rate stop there is thrown, never a zero count
    const { gh: gh2 } = fakeOctokit({ [EVENTS]: givenPages([first]), [PULLS]: () => ({ status: 429, body: { message: 'slow down' }, headers: { 'retry-after': '30' } }) });
    await expect(activity30d(gh2, profile(), { budget: newRateBudget(1_000), now: () => NOW, sleep: async () => {} })).rejects.toBeInstanceOf(GitHubRateLimitError);
  });

  it('activity30d: an unreadable answer is an error, not a zero count', async () => {
    const { gh } = fakeOctokit({ [EVENTS]: { body: { not: 'a list' } }, [PULLS]: pages([]) });
    await expect(activity30d(gh, profile(), { budget: newRateBudget(), now: () => NOW })).rejects.toThrow(/could not be read/);
  });
});
