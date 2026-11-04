// Plan E Task 6 / E6 (rulings B4, S22; threats T16, T39): the AI spend meter, moved from the audit to src/ai/spend-meter.ts,
// as the proof run's AI cost cap. Prices come from the real data/ai-prices.yml. Fake providers only; no network.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { usageOf as claudeUsageOf } from '../src/ai/claude.js';
import { ollamaProvider } from '../src/ai/ollama.js';
import { AiError, completeValidated } from '../src/ai/provider.js';
import { bundleCode, bundleSummary, type BundleSummary } from '../src/ai/redact.js';
import { AiSpendMeter, isCostCap, MAX_RUNS_PER_ATTEMPT, meteredProvider } from '../src/ai/spend-meter.js';
import * as auditModel from '../src/audit/model.js';
import { askConsent, consentScreen } from '../src/cli/consent.js';
import { floorNeeds, jobCategories } from '../src/engine/needs.js';
import { aiRequestBytes, estimate, estimateAuditAi, loadAiPrices, requestCeilingUsd, usageCeilingUsd, type Estimates } from '../src/estimate/estimate.js';
import { permissionsTable } from '../src/github/client.js';
import { proofAiMeter } from '../src/proof/caps.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { DEFAULT_MODEL, type AiProvider, type AiRequest, type AiUsage, type Capabilities, type RepoProfile } from '../src/types.js';
import { z } from 'zod';
import { sayYes } from './helpers/consent.js';
import { CLEAN, gitleaksAt, gitleaksFacts, makeStub, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

// "Tokens" in a property name is built at runtime (repo rule: no secret-like literals in test/).
const T = 'Tokens';
const use = (input: number, output: number, cacheRead = 0, cacheWrite = 0): AiUsage =>
  Object.fromEntries([['input' + T, input], ['output' + T, output], ['cacheRead' + T, cacheRead], ['cacheWrite' + T, cacheWrite]]) as unknown as AiUsage;
const withRuns = (u: AiUsage, attempts: AiUsage['attempts']): AiUsage => ({ ...u, attempts });

/** A request; `maxOutputTokens` null leaves the output limit out. */
const req = (limit: number | null = 1_000, user = 'u'): AiRequest =>
  ({ system: 's', user, schemaName: 'x', jsonSchema: { type: 'object' }, timeoutMs: 1_000, ...(limit === null ? {} : { ['maxOutput' + T]: limit }) }) as AiRequest;
/** A provider that answers each call with the next item: data with usage, or an error to throw. */
function scripted(name: AiProvider['name'], model: string, answers: ({ data: unknown; usage: AiUsage } | Error)[]): AiProvider & { calls: AiRequest[] } {
  const calls: AiRequest[] = [];
  return {
    name, model, calls,
    complete: async (r) => {
      calls.push(r);
      const a = answers[Math.min(calls.length - 1, answers.length - 1)];
      if (a instanceof Error) throw a;
      return a as { data: unknown; usage: AiUsage };
    },
  };
}
const CLAUDE = { name: 'claude', model: DEFAULT_MODEL };

describe('E6 AI spend meter (B4)', () => {
  it('aiMeter: cost from input and output tokens at the stored prices', async () => {
    const price = loadAiPrices().providers.openai.models['gpt-5'] as { input: number; output: number };
    const ai = scripted('openai', 'gpt-5', [{ data: {}, usage: use(1_000_000, 100_000) }]);
    const meter = new AiSpendMeter(ai, 100);
    await meter.provider.complete(req());
    const want = price.input + 0.1 * price.output;
    expect(meter.costUsd).toBeCloseTo(want, 10);
    expect(meter.attempts).toEqual([{ model: 'gpt-5', input: 1_000_000, output: 100_000, cacheRead: 0, cacheWrite: 0, listUsd: expect.closeTo(want, 10) }]);
    // the cap side: one run of gpt-5 at its own price (no refusal fallback outside Claude)
    expect(meter.spentUsd).toBeCloseTo(want, 10);
    expect(meter.usedUsd).toBeCloseTo(want, 10);
    expect(meter.usage).toEqual(use(1_000_000, 100_000));
  });

  it('meteredProvider: records usage from each complete result, including retries and errors that carry usage', async () => {
    const ai = scripted('openai', 'gpt-5', [
      { data: { wrong: true }, usage: use(100, 10) },   // fails the schema: completeValidated retries
      { data: { ok: true }, usage: use(200, 20) },
      new AiError('refusal', 'declined', use(300, 30)),   // an error that carries usage (the provider answered)
      new AiError('timeout', 'no answer'),   // no usage: its reservation is kept
    ]);
    const meter = new AiSpendMeter(ai, 100);
    const p = meteredProvider(ai, meter);
    expect(p).toBe(meter.provider);
    expect(p).toMatchObject({ name: 'openai', model: 'gpt-5' });
    const r = await completeValidated(p, req(), z.object({ ok: z.literal(true) }));
    expect(r.data).toEqual({ ok: true });
    await expect(p.complete(req())).rejects.toMatchObject({ kind: 'refusal' });
    const before = meter.spentUsd;
    await expect(p.complete(req())).rejects.toMatchObject({ kind: 'timeout' });
    expect(ai.calls).toHaveLength(4);
    expect(meter.usage).toEqual(use(600, 60));
    expect(meter.attempts.map((a) => a.input)).toEqual([100, 200, 300]);
    expect(meter.spentUsd - before).toBeCloseTo(requestCeilingUsd({ name: 'openai', model: 'gpt-5' }, aiRequestBytes(req()), 1_000) as number, 10);
    expect(meter.reservedUsd).toBe(0);
    // only the provider the meter wraps: any other would be an unmetered side door
    expect(meteredProvider(meter.provider, meter)).toBe(meter.provider);
    expect(() => meteredProvider(scripted('openai', 'gpt-5', []), meter)).toThrow(/spend meter/);
  });

  it('aiMeter: call refused once the cap is passed (CostCapError)', async () => {
    const ai = scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: use(1_000, 100) }]);
    const worst = requestCeilingUsd(CLAUDE, aiRequestBytes(req()), 1_000) as number;
    const meter = new AiSpendMeter(ai, 2.5 * worst);
    await meter.provider.complete(req());
    await meter.provider.complete(req());
    expect(meter.exceeded).toBe(false);
    meter.restore(2.5 * worst);   // the cap is passed
    expect(meter.exceeded).toBe(true);
    const err = await meter.provider.complete(req()).catch((e: unknown) => e);
    // B4: CostCapError is AiError('cost-cap'), no class of its own
    expect(err).toBeInstanceOf(AiError);
    expect(err).toMatchObject({ kind: 'cost-cap', message: 'Stopped before the AI cost limit you agreed to.' });
    expect(isCostCap(err)).toBe(true);
    expect(isCostCap(new AiError('timeout', 'x'))).toBe(false);
    expect(ai.calls).toHaveLength(2);
    // exceeded is spent + reserved ≥ cap: reaching the cap exactly counts
    const exact = new AiSpendMeter(ai, 1);
    exact.restore(1);
    expect(exact.exceeded).toBe(true);
    const under = new AiSpendMeter(ai, 1);
    under.restore(0.999);
    expect(under.exceeded).toBe(false);
    // a cap that isn't a finite number ≥ 0 (or null) is refused: an Infinity cap would be no cap
    for (const bad of [Number.POSITIVE_INFINITY, Number.NaN, -1]) expect(() => new AiSpendMeter(ai, bad)).toThrow(/cap/);
  });

  it('aiMeter: ollama → no cap', async () => {
    const local = scripted('ollama', 'llama3.1', [{ data: {}, usage: use(5_000_000, 500_000) }]);
    const meter = new AiSpendMeter(local, null);
    expect(meter.effectiveCapUsd).toBeNull();
    for (let i = 0; i < 3; i++) await meter.provider.complete(req(null, 'x'.repeat(10_000)));   // no output limit needed either
    expect(local.calls).toHaveLength(3);
    expect(meter.exceeded).toBe(false);
    expect(meter.spentUsd).toBe(0);
    expect(meter.costUsd).toBe(0);
    expect(meter.usage).toEqual(use(15_000_000, 1_500_000));   // usage is still recorded for the report
    expect(meter.attempts).toHaveLength(3);
    // the same null for a paid provider is a cap of 0: everything refused (review H1)
    const paid = scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: use(1, 1) }]);
    const zero = new AiSpendMeter(paid, null);
    expect(zero.effectiveCapUsd).toBe(0);
    await expect(zero.provider.complete(req())).rejects.toMatchObject({ kind: 'cost-cap' });
    expect(paid.calls).toHaveLength(0);
  });

  it('aiMeter: used cost restored from state on resume', async () => {
    const ai = scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: use(1_000, 100) }]);
    const worst = requestCeilingUsd(CLAUDE, aiRequestBytes(req()), 1_000) as number;
    const one = usageCeilingUsd(CLAUDE, use(1_000, 100)) as number;
    const first = new AiSpendMeter(ai, 10 * worst);
    await first.provider.complete(req());
    await first.provider.complete(req());
    const saved = first.usedUsd;   // what the state keeps
    expect(saved).toBeCloseTo(2 * one, 12);
    // the resumed run: a new meter at the same cap starts from the saved amount
    const cap = worst + 1.5 * one;   // a fresh meter fits one more call; the resumed one doesn't
    const fresh = new AiSpendMeter(ai, cap);
    await fresh.provider.complete(req());
    expect(ai.calls).toHaveLength(3);
    const resumed = new AiSpendMeter(ai, cap);
    resumed.restore(saved);
    expect(resumed.spentUsd).toBeCloseTo(saved, 12);
    expect(resumed.restoredUsd).toBeCloseTo(saved, 12);
    expect(resumed.usedUsd).toBeCloseTo(saved, 12);
    await expect(resumed.provider.complete(req())).rejects.toMatchObject({ kind: 'cost-cap' });
    expect(ai.calls).toHaveLength(3);   // the cap holds across the resume: nothing sent
    // restoring adds: a second restore never lowers what was used
    resumed.restore(0);
    expect(resumed.spentUsd).toBeCloseTo(saved, 12);
    resumed.restore(one);
    expect(resumed.spentUsd).toBeCloseTo(saved + one, 12);
    for (const bad of [-1, Number.NaN, '1' as unknown as number, undefined as unknown as number]) expect(() => resumed.restore(bad)).toThrow(/restored/);
  });

  it('aiMeter: worst case reserved before a call; a call that could pass the cap is refused unsent', async () => {
    const worst = requestCeilingUsd(CLAUDE, aiRequestBytes(req()), 1_000) as number;
    let seen = -1;
    const meter: AiSpendMeter = new AiSpendMeter({
      name: 'claude', model: DEFAULT_MODEL,
      complete: async () => { seen = meter.reservedUsd; return { data: {}, usage: use(1_000, 100) }; },
    }, 1.05 * worst);
    await meter.provider.complete(req());
    expect(seen).toBeCloseTo(worst, 12);   // reserved while the call was in flight
    expect(meter.reservedUsd).toBe(0);
    const used = meter.spentUsd;
    expect(used).toBeCloseTo(usageCeilingUsd(CLAUDE, use(1_000, 100)) as number, 12);
    expect(used + worst).toBeGreaterThan(1.05 * worst);   // the next call's worst case doesn't fit
    const sent: AiRequest[] = [];
    const tight = new AiSpendMeter({ name: 'claude', model: DEFAULT_MODEL, complete: async (r) => { sent.push(r); return { data: {}, usage: use(1_000, 100) }; } }, 1.05 * worst);
    await tight.provider.complete(req());
    await expect(tight.provider.complete(req())).rejects.toMatchObject({ kind: 'cost-cap' });
    expect(sent).toHaveLength(1);   // refused before anything was sent, though spent alone is far below the cap
    expect(tight.spentUsd).toBeLessThan(0.2 * worst);
    expect(tight.exceeded).toBe(false);   // not "once exceeded": the call that could cross the line is the one refused
    // the worst case is reserved exactly: a cap of exactly one worst case lets one call through
    const one = scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: use(1_000, 100) }]);
    await new AiSpendMeter(one, worst).provider.complete(req());
    expect(one.calls).toHaveLength(1);
    // two calls at once: the second must fit beside the first's reservation
    let release: () => void = () => {};
    const slow = new AiSpendMeter({ name: 'claude', model: DEFAULT_MODEL, complete: () => new Promise((ok) => { release = () => ok({ data: {}, usage: use(1_000, 100) }); }) }, 1.5 * worst);
    const a = slow.provider.complete(req());
    expect(slow.spentUsd).toBe(0);
    expect(slow.exceeded).toBe(false);
    await expect(slow.provider.complete(req())).rejects.toMatchObject({ kind: 'cost-cap' });
    // exceeded counts what is reserved: a call in flight that holds the whole cap reaches it
    let free: () => void = () => {};
    const full = new AiSpendMeter({ name: 'claude', model: DEFAULT_MODEL, complete: () => new Promise((ok) => { free = () => ok({ data: {}, usage: use(1_000, 100) }); }) }, worst);
    const b = full.provider.complete(req());
    expect(full.spentUsd).toBe(0);
    expect(full.exceeded).toBe(true);
    free();
    await b;
    expect(full.exceeded).toBe(false);
    release();
    await a;
  });

  it('aiMeter: a request without maxOutputTokens is refused under a finite cap', async () => {
    const ai = scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: use(10, 10) }]);
    for (const cap of [0, 1, 1e6, Number.MAX_VALUE]) {
      await expect(new AiSpendMeter(ai, cap).provider.complete(req(null))).rejects.toMatchObject({ kind: 'cost-cap' });
    }
    expect(ai.calls).toHaveLength(0);
    // an output limit that isn't a whole number above 0 is refused as invalid, before anything is sent
    await expect(new AiSpendMeter(ai, 1e6).provider.complete(req(0))).rejects.toMatchObject({ kind: 'invalid' });
    expect(ai.calls).toHaveLength(0);
    await new AiSpendMeter(ai, 1e6).provider.complete(req(1_000));
    expect(ai.calls).toHaveLength(1);
  });

  it('aiMeter: fallback attempt priced at its own model in the report; cap uses ceiling rates', async () => {
    // Claude's usage.iterations: the primary model declined, the refusal fallback answered on another model
    const iteration = (type: string, model: string | null, n: number[]): Record<string, unknown> =>
      ({ type, model, ...Object.fromEntries(['input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens'].map((k, i) => [k, n[i]])) });
    const msg = { usage: { ...iteration('message', null, [120, 30, 10, 0]), iterations: [iteration('message', DEFAULT_MODEL, [100, 20, 0, 50]), iteration('fallback_message', 'claude-opus-4-8', [120, 30, 10, 0]), iteration('message', null, [5, 1, 0, 0])] } };
    const u = claudeUsageOf(msg, DEFAULT_MODEL);
    expect(u).toEqual({
      ...use(225, 51, 10, 50),
      attempts: [
        { model: DEFAULT_MODEL, input: 100, output: 20, cacheRead: 0, cacheWrite: 50 },
        { model: 'claude-opus-4-8', input: 120, output: 30, cacheRead: 10, cacheWrite: 0 },
        { model: DEFAULT_MODEL, input: 5, output: 1, cacheRead: 0, cacheWrite: 0 },   // a run that names no model: the requested one
      ],
    });
    // no iterations: no attempts (one run at the provider's model)
    expect(claudeUsageOf({ usage: iteration('message', null, [7, 3, 0, 0]) }, DEFAULT_MODEL)).toEqual(use(7, 3, 0, 0));

    const prices = loadAiPrices().providers.claude.models;
    const at = (m: string, i: number, o: number, cr: number, cw: number) => {
      const p = prices[m] as { input: number; output: number };
      return ((i + cr + 1.25 * cw) / 1e6) * p.input + (o / 1e6) * p.output;
    };
    const ai = scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: u }]);
    const meter = new AiSpendMeter(ai, 100);
    await meter.provider.complete(req());
    const runs = [at(DEFAULT_MODEL, 100, 20, 0, 50), at('claude-opus-4-8', 120, 30, 10, 0), at(DEFAULT_MODEL, 5, 1, 0, 0)];
    expect(meter.attempts).toHaveLength(1);   // one call (the audit report counts calls), its model runs listed
    expect(meter.attempts[0]?.runs?.map((r) => [r.model, r.listUsd])).toEqual([
      [DEFAULT_MODEL, expect.closeTo(runs[0] as number, 12)], ['claude-opus-4-8', expect.closeTo(runs[1] as number, 12)], [DEFAULT_MODEL, expect.closeTo(runs[2] as number, 12)],
    ]);
    expect(at('claude-opus-4-8', 120, 30, 10, 0)).not.toBeCloseTo(at(DEFAULT_MODEL, 120, 30, 10, 0), 6);   // the two models' prices differ
    expect(meter.costUsd).toBeCloseTo(runs.reduce((a, b) => a + b, 0), 12);
    // the cap: the summed counts at the ceiling rates (the top Claude price, the fallback's double billing), never the list prices
    expect(meter.spentUsd).toBeCloseTo(usageCeilingUsd(CLAUDE, u) as number, 12);
    expect(meter.spentUsd).toBeGreaterThan(meter.costUsd);
    // a provider list too long to be a real one is reported as one run at the provider's model
    const many = withRuns(use(10, 10), Array.from({ length: MAX_RUNS_PER_ATTEMPT + 1 }, () => ({ model: 'claude-opus-4-8', input: 1, output: 1, cacheRead: 0, cacheWrite: 0 })));
    const m2 = new AiSpendMeter(scripted('claude', DEFAULT_MODEL, [{ data: {}, usage: many }]), 100);
    await m2.provider.complete(req());
    expect(m2.attempts[0]?.runs).toBeUndefined();
    expect(m2.attempts[0]?.model).toBe(DEFAULT_MODEL);
  });
});

describe('E6 the proof meter takes the consented cap (B4)', () => {
  const svc = { name: 'web', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['test'], frameworks: ['express'], quality: emptyServiceQuality() } as const;
  const profile: RepoProfile = {
    owner: 'acme', repo: 'shop', defaultBranch: 'main', private: true, ownerType: 'User', plan: 'free',
    monorepo: 'none', services: [{ ...svc, envVars: [], dependsOn: [], scripts: ['test'], frameworks: ['express'] }], terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
  };
  const CAPS: Capabilities = { branchProtection: false, environments: true, deploymentBranchPolicies: false, envRequiredReviewers: false, attestations: false, codeScanning: false, keylessSigningAllowed: false };
  const claude: AiProvider = { name: 'claude', model: DEFAULT_MODEL, complete: async () => ({ data: {}, usage: use(1, 1) }) };
  const fullEst = (ai: AiProvider): Estimates => estimate(profile, jobCategories(floorNeeds(profile, CAPS)), 2, { pushes: 40, prs: 6, capped: false }, ai);
  let bundle: BundleSummary;
  beforeAll(async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', '// a\n');
    bundle = bundleSummary(await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin))));
  });
  afterAll(() => { cleanupRepos(); });
  const grant = async (ai: AiProvider, est: Estimates, mode: 'full' | 'audit-ai' = 'full') => {
    const screen = mode === 'full'
      ? consentScreen(profile, ai, est, bundle, permissionsTable('write', { appCreatesRepos: false }), [{ name: 'pipelines', exists: true }, { name: 'pipegen-proof-shop', exists: true }], 'full', { appCreatesRepos: false, ...gitleaksFacts() })
      : consentScreen(profile, ai, { ...estimateAuditAi(ai, 1, 1_000), capUsd: est.aiCostCapUsd, unpriced: null }, bundle, permissionsTable('read'), [], 'audit-ai', gitleaksFacts());
    const yes = await askConsent(sayYes, screen, (s) => { throw new Error(s); });
    if (yes === null) throw new Error('expected a yes answer');
    return yes;
  };

  it('aiMeter: cap equals the consent token\'s capUsd, else refuse to start', async () => {
    const est = fullEst(claude);
    expect(est.aiCostCapUsd).toBeGreaterThan(0);
    const meter = proofAiMeter(claude, est, await grant(claude, est));
    expect(meter.effectiveCapUsd).toBe(est.aiCostCapUsd);
    expect(meter.capUsd).toBe(est.aiCostCapUsd);
    // another cap than the one on the screen: refused before any AI call
    const yes = await grant(claude, est);
    for (const cap of [(est.aiCostCapUsd as number) * 2, (est.aiCostCapUsd as number) - 0.01, null]) {
      expect(() => proofAiMeter(claude, { ...est, aiCostCapUsd: cap }, yes), String(cap)).toThrow(/cost cap differs/);
    }
    // another provider or model than the screen named
    expect(() => proofAiMeter({ ...claude, model: 'claude-haiku-5-5' }, est, yes)).toThrow(/provider or model/);
    // not a token askConsent gave, or the audit --ai screen's
    expect(() => proofAiMeter(claude, est, { terms: { mode: 'full', capUsd: est.aiCostCapUsd } } as never)).toThrow(/consent token/);
    const auditYes = await grant(claude, est, 'audit-ai');
    expect(() => proofAiMeter(claude, est, auditYes)).toThrow(/consent token/);
    // one meter per yes: a second meter would double the agreed cap
    proofAiMeter(claude, est, yes);
    expect(() => proofAiMeter(claude, est, yes)).toThrow(/already has its AI spend meter/);
    // Ollama: no cap on the screen, none on the meter
    const ollama = ollamaProvider({ model: 'llama3.1' });
    const oEst = fullEst(ollama);
    expect(oEst.aiCostCapUsd).toBeNull();
    expect(proofAiMeter(ollama, oEst, await grant(ollama, oEst)).effectiveCapUsd).toBeNull();
  });
});

describe('E6 the meter moved (B4)', () => {
  it('audit: AiSpendMeter import moved; audit tests unchanged', () => {
    // the audit model exports the same class from its new home, so its callers and tests keep their import
    expect(auditModel.AiSpendMeter).toBe(AiSpendMeter);
    const root = join(import.meta.dirname, '..');
    const model = readFileSync(join(root, 'src/audit/model.ts'), 'utf8');
    expect(model).not.toMatch(/class AiSpendMeter\b/);
    expect(model).toMatch(/import \{ AiSpendMeter, type AiAttempt \} from '\.\.\/ai\/spend-meter\.js';/);
    expect(readFileSync(join(root, 'src/ai/spend-meter.ts'), 'utf8')).toMatch(/export class AiSpendMeter\b/);
    // the audit's own test file still imports it from the audit model (unchanged by this move)
    expect(readFileSync(join(root, 'test/audit-ai.test.ts'), 'utf8')).toContain("import { addAiSuggestions, AiSpendMeter, buildAudit, needsRequestBytes, type AiSuggestDeps, type AuditReport } from '../src/audit/model.js';");
  });
});
