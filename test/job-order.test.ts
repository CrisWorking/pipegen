// Plan B 6c Part 0 (review-6b-r2 C1, C2, C5): the job order rule is an allowlist that fails closed and is enforced where a
// job is assembled; every rendered step has a recognised id; an npm checker is one step.
import { describe, expect, it } from 'vitest';
import { NO_SCANS } from '../src/engine/job-rules.js';
import { checkJobOrder, dedupeJobSteps, RenderError, renderProjectScript, renderScrub, renderStepWith, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { ARGV_POLICIES, type ArgvPolicy } from '../src/engine/tool-flags.js';
import type { ReviewedTool, StepSpec } from '../src/types.js';
import { ctxFor, entry, gateEntry, platform, reviewedList, service, specFor } from './helpers/render.js';

const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
// D9: c8 runs the service's test script, so the service has one
const ctx = ctxFor([service({ name: 'app', path: '.', scripts: ['test'] })]);
const render = (id: string, over: Partial<StepSpec> = {}, opts?: Parameters<typeof renderStepWith>[4]): RenderResult => {
  const t = entry(id);
  return renderStepWith(specFor(t, { needId: needFor(t), ...over }), t, platform(), ctx, opts);
};
const steps = (id: string): RenderedStep[] => render(id).steps;
const sha = 'a'.repeat(40);

describe('C1: checkJobOrder is an allowlist that fails closed (the reviewer\'s probes)', () => {
  it('a release scanner after vitest is refused', () => {
    expect(checkJobOrder([...steps('vitest-coverage'), ...steps('gitleaks')]).length).toBeGreaterThan(0);
  });
  it('a release tool after lefthook is refused', () => {
    expect(checkJobOrder([...steps('lefthook'), ...steps('actionlint')]).length).toBeGreaterThan(0);
  });
  it('a checker after the repo\'s own npm ci is refused (that step reads the repo .npmrc)', () => {
    const ci = steps('vitest-coverage').find((s) => s.id?.startsWith('pipegen-npm-ci-')) as RenderedStep;
    expect(ci).toBeDefined();
    expect(checkJobOrder([ci, ...steps('eslint')]).length).toBeGreaterThan(0);
  });
  it('a step with no id before a checker is refused', () => {
    expect(checkJobOrder([{ name: 'x', run: 'true', shell: 'bash' }, ...steps('eslint')]).length).toBeGreaterThan(0);
  });
  it('a repo-code step whose id was renamed still counts as repo code', () => {
    const renamed = steps('vitest-coverage').map((s) => (s.id?.startsWith('repocode-') ? { ...s, id: 'looks-harmless' } : s));
    expect(checkJobOrder([...renamed, ...steps('eslint')]).length).toBeGreaterThan(0);
  });
  it('an unknown action before a checker is refused (attest, build-push, anything not on the list)', () => {
    for (const uses of [`actions/attest-build-provenance@${sha}`, `docker/build-push-action@${sha}`, `someone/else@${sha}`]) {
      expect(checkJobOrder([{ name: 'a', uses }, ...steps('eslint')]).length, uses).toBeGreaterThan(0);
    }
  });
  it('a step with an id that only looks like a pipegen id (unknown prefix, wrong hash length) is repo code', () => {
    for (const id of ['pipegen-whatever', 'tool-123', 'checker-run-xyz', 'scrub-1', 'pipegen-npm-ci-0123456789abcdef']) {
      expect(checkJobOrder([{ id, name: 'x', run: 'true', shell: 'bash' }, ...steps('biome')]).length, id).toBeGreaterThan(0);
    }
  });
  it('after repo code only repo code follows: an upload, a scrub and an action are refused, another repo-code step is fine', () => {
    const vitest = steps('vitest-coverage');
    const upload: RenderedStep = { name: 'Upload', uses: `actions/upload-artifact@${sha}` };
    const scrub = renderScrub('pipegen-out-secrets', '${{ runner.temp }}/pipegen-raw/pipegen-out-secrets/gitleaks.sarif', 'gitleaks', 'sarif', gateEntry());
    expect(checkJobOrder([...vitest, upload]).length).toBeGreaterThan(0);
    expect(checkJobOrder([...vitest, scrub]).length).toBeGreaterThan(0);
    expect(checkJobOrder(dedupeJobSteps([...vitest, ...render('c8', { service: 'app' }).steps], { scans: NO_SCANS }))).toEqual([]);
    expect(checkJobOrder([...vitest, { name: 'mine', run: 'true' }]).length).toBe(0);
  });
  it('[checkers, then repo code] passes, with the prelude (checkout, setup-node) in front', () => {
    const prelude: RenderedStep[] = [{ name: 'Checkout', uses: `actions/checkout@${sha}` }, { name: 'Node', uses: `actions/setup-node@${sha}` }];
    const job = dedupeJobSteps([...prelude, ...steps('eslint'), ...steps('gitleaks'), ...steps('biome'), ...steps('vitest-coverage')], { scans: NO_SCANS });
    expect(checkJobOrder(job)).toEqual([]);
  });
  it('dedupeJobSteps throws on a bad order, so no job can be assembled in it', () => {
    expect(() => dedupeJobSteps([...steps('vitest-coverage'), ...steps('gitleaks')], { scans: NO_SCANS })).toThrow(RenderError);
    expect(() => dedupeJobSteps([{ name: 'x', run: 'true' }, ...steps('eslint')], { scans: NO_SCANS })).toThrow(/repo-code step/);
  });
});

describe('C2: every rendered step has a recognised id, and a checker is one step', () => {
  const RECOGNISED = /^(?:pipegen-setup-node-\d{1,3}|pipegen-setup-python|pipegen-npm-ci-[0-9a-f]{16}|checker-run-[0-9a-f]{16}|repocode-[0-9a-f]{16}|tool-(?:install|pull|run)-[0-9a-f]{16})$/;
  it('the render of every reviewed cli entry: each run step has a recognised id, and the steps alone pass the order rule', () => {
    let rendered = 0;
    for (const t of reviewedList().filter((e) => e.step.cli !== undefined)) {
      let r: RenderResult;
      try { r = renderStepWith(specFor(t, { needId: needFor(t) }), t, platform(), ctx); } catch (e) { if (e instanceof RenderError) continue; throw e; }
      rendered++;
      // the check of a repo-code tool's install has no id on purpose: it follows the repo's own `npm ci`, so it is repo code
      for (const s of r.steps.filter((x) => x.run !== undefined && !x.name.includes('Check the installed tool'))) expect(s.id, `${t.id}: ${s.name}`).toMatch(RECOGNISED);
      expect(new Set(r.steps.map((s) => s.id).filter((i) => i !== undefined)).size, t.id).toBe(r.steps.filter((s) => s.id !== undefined).length);
      expect(checkJobOrder(dedupeJobSteps(r.steps, { scans: NO_SCANS })), t.id).toEqual([]);
    }
    expect(rendered).toBeGreaterThan(15);
  });
  it('release, docker and pip install steps are tool-install/pull ids and the run is tool-run (not repo code)', () => {
    const g = steps('gitleaks');
    expect(g[0]?.id).toMatch(/^tool-install-[0-9a-f]{16}$/);
    expect(g[1]?.id).toMatch(/^tool-run-[0-9a-f]{16}$/);
    const z = render('zap-baseline', {}, { policies: { ...ARGV_POLICIES, 'zap-baseline': { ...ARGV_POLICIES['zap-baseline'], slots: undefined } as ArgvPolicy } }).steps;
    expect(z[0]?.id).toMatch(/^tool-pull-[0-9a-f]{16}$/);
    expect(z.at(-1)?.id).toMatch(/^tool-run-[0-9a-f]{16}$/);
  });
  it('every npm checker is ONE run step after setup-node: install, check and run together', () => {
    for (const id of ['eslint', 'eslint-typescript', 'biome', 'oxlint-typeaware']) {
      const r = render(id).steps;
      expect(r, id).toHaveLength(2);
      expect(r[0]?.uses).toMatch(/^actions\/setup-node@/);
      const run = r[1] as RenderedStep;
      expect(run.id, id).toMatch(/^checker-run-[0-9a-f]{16}$/);
      const text = run.run as string;
      const at = (needle: string): number => text.indexOf(needle);
      expect(at(' ci --ignore-scripts'), id).toBeGreaterThan(0);
      expect(at(' ci --ignore-scripts'), id).toBeLessThan(at('PIPEGEN_NPM_EXPECT=$PIPEGEN_NPM_EXPECT'));
      expect(run.env?.PIPEGEN_NPM_LOCK, id).toBeDefined();
      expect(run.env?.PIPEGEN_NPM_EXPECT, id).toBeDefined();
    }
    for (const id of ['prettier', 'knip']) {
      const r = render(id).steps;
      expect(r, id).toHaveLength(2);
      expect(r[1]?.id, id).toMatch(/^repocode-[0-9a-f]{16}$/);
      expect(r[1]?.env?.PIPEGEN_NPM_LOCK, id).toBeDefined();
    }
  });
});

describe('C5: a closureEnv path with .. is refused', () => {
  it('node_modules/../x', () => {
    const t = entry('oxlint-typeaware');
    const pol = { ...ARGV_POLICIES['oxlint-typeaware'], closureEnv: { OXLINT_TSGOLINT_PATH: 'node_modules/../evil' } } as ArgvPolicy;
    expect(() => renderStepWith(specFor(t, { needId: needFor(t) }), t, platform(), ctx, { policies: { ...ARGV_POLICIES, 'oxlint-typeaware': pol } })).toThrow(/not a plain path inside the install folder/);
    const ok = { ...pol, closureEnv: { OXLINT_TSGOLINT_PATH: 'node_modules/.bin/tsgolint' } } as ArgvPolicy;
    expect(() => renderStepWith(specFor(t, { needId: needFor(t) }), t, platform(), ctx, { policies: { ...ARGV_POLICIES, 'oxlint-typeaware': ok } })).not.toThrow();
  });
});

describe('readsOnly: a run step is repo code unless its policy says it only reads (controller ruling on Part 0)', () => {
  /** readsOnly tools without a pinned config flag, each with the reason it can not load repo code. */
  const DOCUMENTED: Record<string, string> = {
    semgrep: 'rules come only from the verified archive via --config /pipegen-rules, in a container with --network none (semgrepProblems)',
    nuclei: 'templates come only from the verified archive via -t; code templates need -code, which is not on its allowlist (nucleiProblems)',
  };
  it('every policy with readsOnly has a pinned config passed by flag, or a documented reason listed here', () => {
    const offenders: string[] = [];
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) {
      if (pol.readsOnly !== true) continue;
      if (pol.runsRepoCode === true || pol.loadsRepoConfig === true) offenders.push(`${id}: readsOnly with repo code`);
      if (pol.config === undefined && DOCUMENTED[id] === undefined) offenders.push(`${id}: no pinned config and no documented reason`);
    }
    expect(offenders).toEqual([]);
    for (const id of Object.keys(DOCUMENTED)) expect(ARGV_POLICIES[id]?.readsOnly, id).toBe(true);
  });
  it('pip tools, schemathesis, pinact and the repo-code tools are not readsOnly', () => {
    for (const id of ['mypy', 'coverage-py', 'creosote', 'vulture', 'bandit', 'schemathesis', 'pinact', 'lefthook', 'prettier', 'knip', 'vitest-coverage', 'c8']) expect(ARGV_POLICIES[id]?.readsOnly, id).not.toBe(true);
  });
  it('a policy with no readsOnly flag renders a repocode- run step; with it, tool-run / checker-run', () => {
    const t = entry('gitleaks');
    const without = { ...ARGV_POLICIES.gitleaks } as Record<string, unknown>;
    delete without.readsOnly;
    const r = renderStepWith(specFor(t, { needId: needFor(t) }), t, platform(), ctx, { policies: { ...ARGV_POLICIES, gitleaks: without as unknown as ArgvPolicy } });
    expect(r.steps.at(-1)?.id).toMatch(/^repocode-[0-9a-f]{16}$/);
    expect(steps('gitleaks').at(-1)?.id).toMatch(/^tool-run-/);
    const e = entry('eslint');
    const w = { ...ARGV_POLICIES.eslint } as Record<string, unknown>;
    delete w.readsOnly;
    const r2 = renderStepWith(specFor(e, { needId: needFor(e) }), e, platform(), ctx, { policies: { ...ARGV_POLICIES, eslint: w as unknown as ArgvPolicy } });
    expect(r2.steps.at(-1)?.id).toMatch(/^repocode-/);
    expect(steps('eslint').at(-1)?.id).toMatch(/^checker-run-/);
  });
});

describe('S11: the ESLint configs start from @eslint/js recommended (pinned plugin, isolated closure)', () => {
  it('both entries pin @eslint/js and their configs use js.configs.recommended; policy and data agree', () => {
    for (const id of ['eslint', 'eslint-typescript']) {
      const t = entry(id);
      expect(t.step.cli?.plugins?.map((p) => p.package), id).toContain('@eslint/js');
      expect(t.fixedInputs.config?.content, id).toContain("import js from '@eslint/js'");
      expect(t.fixedInputs.config?.content, id).toContain('js.configs.recommended');
      expect(ARGV_POLICIES[id]?.config?.content, id).toBe(t.fixedInputs.config?.content);
    }
  });
});

describe('6c fix round 1: an id counts only on the right kind of step, and actions must be pinned by SHA', () => {
  const eslint = (): RenderedStep[] => steps('eslint');
  it('M1: a checker, tool or scrub id on a uses: step is not harmless', () => {
    for (const id of ['checker-run-0123456789abcdef', 'tool-run-0123456789abcdef', 'tool-install-0123456789abcdef', 'scrub-0123456789abcdef']) {
      expect(checkJobOrder([{ id, name: 'x', uses: `someone/else@${sha}` }, ...eslint()]).length, id).toBeGreaterThan(0);
    }
  });
  it('M2: a setup id on a run: step, or on an unpinned or foreign action, is not harmless', () => {
    expect(checkJobOrder([{ id: 'pipegen-setup-node-24', name: 'x', run: 'true' }, ...eslint()]).length).toBeGreaterThan(0);
    expect(checkJobOrder([{ id: 'pipegen-checkout', name: 'x', run: 'true' }, ...eslint()]).length).toBeGreaterThan(0);
    expect(checkJobOrder([{ id: 'pipegen-setup-node-24', name: 'x', uses: `someone/else@${sha}` }, ...eslint()]).length).toBeGreaterThan(0);
    expect(checkJobOrder([{ id: 'pipegen-setup-python', name: 'x', uses: `actions/setup-python@${sha}`, run: 'true' }, ...eslint()]).length).toBeGreaterThan(0);
  });
  it('M4: a platform action not pinned by a 40-character SHA is repo code', () => {
    for (const uses of ['actions/checkout@v4', 'actions/checkout@main', `actions/checkout@${'a'.repeat(39)}`, `actions/checkout@${'A'.repeat(40)}`, 'actions/setup-node@v4']) {
      expect(checkJobOrder([{ name: 'x', uses }, ...eslint()]).length, uses).toBeGreaterThan(0);
    }
    expect(checkJobOrder([{ name: 'x', uses: `actions/checkout@${sha}` }, ...eslint()])).toEqual([]);
  });
});

describe('6c fix round 1: dedupe keeps the guarded repo npm ci (finding 5)', () => {
  const script = () => renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, platform(), ctxFor([service({ name: 'app', path: '.', scripts: ['test'] })])).steps;
  const guarded = (job: RenderedStep[]): RenderedStep => dedupeJobSteps(job, { scans: NO_SCANS }).find((s) => s.id?.startsWith('pipegen-npm-ci-')) as RenderedStep;
  it('[project script, vitest] and [vitest, project script]: the one npm ci that stays checks vitest\'s pins before installing', () => {
    const vitest = steps('vitest-coverage');
    const want = JSON.parse(vitest.find((s) => s.id?.startsWith('pipegen-npm-ci-'))?.env?.PIPEGEN_NPM_EXPECT as string) as { name: string }[];
    expect(want.length).toBeGreaterThan(0);
    for (const job of [[...script(), ...vitest], [...script().slice(0, 2), ...vitest, ...script().slice(2)]]) {
      const ci = guarded(job);
      expect(JSON.parse(ci.env?.PIPEGEN_NPM_EXPECT as string).map((w: { name: string }) => w.name).sort()).toEqual(want.map((w) => w.name).sort());
      expect(ci.run).toContain('process.env.PIPEGEN_NPM_EXPECT');
      expect(dedupeJobSteps(job, { scans: NO_SCANS }).filter((s) => s.id?.startsWith('pipegen-npm-ci-'))).toHaveLength(1);
    }
  });
  it('two project scripts of one service share one checkout, setup-node and npm ci', () => {
    const both = dedupeJobSteps([...script(), ...renderProjectScript({ kind: 'project-script', needId: 'lint', service: 'app', script: 'lint' }, platform(), ctxFor([service({ name: 'app', path: '.', scripts: ['test', 'lint'] })])).steps], { scans: NO_SCANS });
    expect(both.filter((s) => s.uses?.startsWith('actions/checkout@'))).toHaveLength(1);
    expect(both.filter((s) => s.id?.startsWith('pipegen-npm-ci-'))).toHaveLength(1);
    expect(both.filter((s) => s.id?.startsWith('repocode-'))).toHaveLength(2);
  });
  it('PL-D3: a merged npm ci keeps its pins readable (indented JSON, the same pins)', () => {
    const vitest = steps('vitest-coverage');
    const own = vitest.find((s) => s.id?.startsWith('pipegen-npm-ci-'))?.env?.PIPEGEN_NPM_EXPECT as string;
    const merged = guarded([...script(), ...vitest]).env?.PIPEGEN_NPM_EXPECT as string;
    expect(merged).toBe(JSON.stringify(JSON.parse(own), null, 2));
  });
  it('two guarded installs with different pins of one package are refused', () => {
    const a = steps('vitest-coverage');
    const b = steps('vitest-coverage').map((s) => (s.id?.startsWith('pipegen-npm-ci-') ? { ...s, env: { ...s.env, PIPEGEN_NPM_EXPECT: (s.env?.PIPEGEN_NPM_EXPECT as string).replace(/"version": ?"[^"]+"/, '"version": "0.0.1"') } } : s));
    expect(() => dedupeJobSteps([...a, ...b], { scans: NO_SCANS })).toThrow(RenderError);
  });
});

describe('7a Part 0 (review-6c-r1 minors 2 and 3): dedupe compares contents; setup ids are bound to their own action', () => {
  const app = ctxFor([service({ name: 'app', path: '.', scripts: ['test', 'lint'] })]);
  const script = (which: 'test' | 'lint' = 'test') => renderProjectScript({ kind: 'project-script', needId: which === 'test' ? 'unit-tests' : 'lint', service: 'app', script: which }, platform(), app).steps;
  const checkoutOf = (job: RenderedStep[]): RenderedStep => job.find((s) => s.id === 'pipegen-checkout') as RenderedStep;
  it('two same-id checkouts that differ (fetch-depth 1 vs 0) are refused, not silently merged', () => {
    const a = script('test');
    const b = script('lint').map((s) => (s.id === 'pipegen-checkout' ? { ...s, with: { ...s.with, 'fetch-depth': '0' } } : s));
    expect(checkoutOf(a).with?.['fetch-depth']).toBe('1');
    expect(() => dedupeJobSteps([...a, ...b], { scans: NO_SCANS })).toThrow(/pipegen-checkout/);
  });
  it('two same-id setup-node steps that differ in uses or with are refused', () => {
    const a = script('test');
    const otherSha = a.map((s) => (s.id?.startsWith('pipegen-setup-node-') ? { ...s, uses: (s.uses as string).replace(/@[0-9a-f]{40}$/, `@${'b'.repeat(40)}`) } : s));
    const otherWith = a.map((s) => (s.id?.startsWith('pipegen-setup-node-') ? { ...s, with: { ...s.with, extra: 'x' } } : s));
    expect(() => dedupeJobSteps([...a, ...otherSha.slice(1, 2)], { scans: NO_SCANS })).toThrow(RenderError);
    expect(() => dedupeJobSteps([...a.slice(0, 2), ...otherWith.slice(1, 2), ...a.slice(2)], { scans: NO_SCANS })).toThrow(RenderError);
  });
  it('the same step twice (only the display name differs) is still deduped', () => {
    const a = script('test');
    const again = a.slice(0, 2).map((s) => ({ ...s, name: `${s.name} again` }));
    expect(dedupeJobSteps([...a.slice(0, 2), ...again, ...a.slice(2)], { scans: NO_SCANS }).filter((s) => s.id?.startsWith('pipegen-'))).toHaveLength(3);
  });
  it('the npm ci pin merge stays: same folder, different tools (their home folders and pins differ) is one step', () => {
    expect(dedupeJobSteps([...script('test'), ...steps('vitest-coverage')], { scans: NO_SCANS }).filter((s) => s.id?.startsWith('pipegen-npm-ci-'))).toHaveLength(1);
  });
  it('two same-id npm ci steps that differ in anything but the pins and the home folder are refused', () => {
    const a = script('test');
    const b = script('lint').map((s) => (s.id?.startsWith('pipegen-npm-ci-') ? { ...s, run: `${s.run as string}\necho extra` } : s));
    expect(() => dedupeJobSteps([...a, ...b], { scans: NO_SCANS })).toThrow(RenderError);
    const c = script('lint').map((s) => (s.id?.startsWith('pipegen-npm-ci-') ? { ...s, env: { ...s.env, OTHER: 'x' } } : s));
    expect(() => dedupeJobSteps([...a, ...c], { scans: NO_SCANS })).toThrow(RenderError);
  });
  it('a setup or checkout id counts as harmless only on its own platform action', () => {
    const eslint = steps('eslint');
    const wrong: [string, string][] = [
      ['pipegen-checkout', 'actions/upload-artifact'], ['pipegen-checkout', 'actions/setup-node'], ['pipegen-checkout', 'github/codeql-action/upload-sarif'],
      ['pipegen-setup-node-24', 'actions/checkout'], ['pipegen-setup-node-24', 'actions/setup-python'], ['pipegen-setup-node-24', 'actions/upload-artifact'],
      ['pipegen-setup-python', 'actions/setup-node'], ['pipegen-setup-python', 'actions/checkout'],
    ];
    for (const [id, path] of wrong) expect(checkJobOrder([{ id, name: 'x', uses: `${path}@${sha}` }, ...eslint]).length, `${id} on ${path}`).toBeGreaterThan(0);
    for (const [id, path] of [['pipegen-checkout', 'actions/checkout'], ['pipegen-setup-node-24', 'actions/setup-node'], ['pipegen-setup-python', 'actions/setup-python']] as const) {
      expect(checkJobOrder([{ id, name: 'x', uses: `${path}@${sha}` }, ...eslint]), `${id} on ${path}`).toEqual([]);
    }
  });
});

describe('7a fix round 1 (ruling 1, ruling 4): download-artifact and the harden step are harmless, pinned and on their own action only', () => {
  it('a pinned download-artifact or bullfrog before a checker passes; by tag, or with a setup id on it, they are repo code', () => {
    for (const path of ['actions/download-artifact', 'bullfrogsec/bullfrog']) {
      expect(checkJobOrder([{ name: 'x', uses: `${path}@${sha}` }, ...steps('eslint')]), path).toEqual([]);
      expect(checkJobOrder([{ name: 'x', uses: `${path}@v4` }, ...steps('eslint')]).length, path).toBeGreaterThan(0);
      expect(checkJobOrder([{ id: 'pipegen-checkout', name: 'x', uses: `${path}@${sha}` }, ...steps('eslint')]).length, path).toBeGreaterThan(0);
    }
  });
  it('after repo code they are refused like any harmless step', () => {
    expect(checkJobOrder([...steps('vitest-coverage'), { name: 'x', uses: `actions/download-artifact@${sha}` }]).length).toBeGreaterThan(0);
  });
});
