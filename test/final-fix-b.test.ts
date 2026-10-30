// v0.2 Plan B final-review fix round, commit B (minors 7 to 10, 13, 15): one source for job rules; test-only hooks guarded.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import * as jobRules from '../src/engine/job-rules.js';
import * as renderStepMod from '../src/engine/render-step.js';
import { renderStep, RenderError } from '../src/engine/render-step.js';
import { APP_RUNNING_CATEGORIES, TRIVY_LAUNCH_RE } from '../src/engine/render-cli.js';
import { ARGV_POLICIES, CACHE_LOCKS, PLATFORM_LOCKS, PLATFORM_USES, runsRepoCode } from '../src/engine/tool-flags.js';
import { ctxFor, entry, platform, reviewedList, specFor } from './helpers/render.js';
import { liveToken } from './helpers/live-token.js';

const root = resolve(import.meta.dirname, '..');
const walk = (dir: string): string[] => readdirSync(dir).flatMap((n) => {
  const p = join(dir, n);
  return statSync(p).isDirectory() ? walk(p) : [p];
});
const srcFiles = (): string[] => walk(join(root, 'src')).filter((f) => f.endsWith('.ts'));
const rel = (f: string): string => relative(root, f);
async function graph(entryPoint: string): Promise<string[]> {
  const r = await build({ entryPoints: [resolve(root, entryPoint)], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
  return Object.keys(r.metafile.inputs).sort();
}

describe('minor 8: test-only hooks stay in tests', () => {
  it('no src file other than the defining one imports a *With hook or a *_FOR_TESTS export', () => {
    const defs: { name: string; file: string }[] = [];
    for (const f of srcFiles()) {
      for (const m of readFileSync(f, 'utf8').matchAll(/^export (?:async )?(?:function|const) (\w+(?:With|_FOR_TESTS))\b/gm)) defs.push({ name: m[1] as string, file: f });
    }
    expect(defs.map((d) => d.name).sort()).toEqual(expect.arrayContaining(['renderStepWith', 'tuningEffectsWith', 'TUNING_OPTIONS_FOR_TESTS']));
    const offenders: string[] = [];
    for (const f of srcFiles()) {
      const text = readFileSync(f, 'utf8');
      for (const d of defs) if (d.file !== f && new RegExp(`\\b${d.name}\\b`).test(text)) offenders.push(`${rel(f)} uses ${d.name}`);
    }
    expect(offenders).toEqual([]);
  });
});

describe('minor 9: runsRepoCode is the renderer\'s rule', () => {
  it('pinact, mypy, creosote and vulture run repo code (not readsOnly); gitleaks and eslint do not', () => {
    for (const id of ['pinact', 'mypy', 'creosote', 'vulture', 'vitest-coverage', 'prettier', 'knip', 'lefthook']) expect(runsRepoCode(id), id).toBe(true);
    for (const id of ['gitleaks', 'eslint', 'trivy-image', 'semgrep', 'biome']) expect(runsRepoCode(id), id).toBe(false);
    expect(runsRepoCode('not-a-tool')).toBe(true);   // unknown: fail closed
    expect(runsRepoCode('gitleaks', true)).toBe(true);   // an app-running category
  });
  it('every rendered cli run step has the id class runsRepoCode says (the renderer uses the function)', () => {
    let checked = 0;
    for (const t of reviewedList()) {
      if (t.candidate.kind === 'action') continue;
      const spec = specFor(t, { needId: t.categories.find((c) => !['platform'].includes(c)) ?? 'sast', service: 'app' });
      let steps;
      try { steps = renderStep(spec, t, platform(), ctxFor(undefined, { image: `ghcr.io/o/a@sha256:${'a'.repeat(64)}`, url: 'http://localhost:1', k8sDir: 'k8s' })).steps; } catch (e) { if (e instanceof RenderError) continue; throw e; }
      const run = steps.at(-1);
      if (run?.id === undefined || !/^(?:repocode|checker-run|tool-run)-/.test(run.id)) continue;
      const app = t.categories.some((c) => APP_RUNNING_CATEGORIES.has(c));
      expect(run.id.startsWith('repocode-'), `${t.id}: ${run.id}`).toBe(runsRepoCode(t.id, app));
      checked++;
    }
    expect(checked).toBeGreaterThan(20);
  });
});

describe('minor 10: one source for the job rules', () => {
  it('job-rules.ts is a leaf: it pulls in neither renderer, the referee, the linters nor the reviewed loader', async () => {
    const files = await graph('src/engine/job-rules.ts');
    for (const heavy of ['render-step', 'render-cli', 'referee', 'linters', 'reviewed', 'pin', 'tuning', 'needs']) expect(files, heavy).not.toContain(`src/engine/${heavy}.ts`);
    expect(files.filter((f) => f.startsWith('src/ai/') || f.startsWith('src/github/'))).toEqual([]);
  });
  it('the renderer, the referee and the linters share the rules from job-rules.ts (no second copy)', () => {
    for (const name of ['checkJobOrder', 'isKnownHarmless', 'checkExpressions', 'IF_VALUES', 'SECRET_REF_RE', 'STEP_KEYS', 'isDangerousName', 'isReviewed'] as const) {
      expect((renderStepMod as Record<string, unknown>)[name] ?? (jobRules as Record<string, unknown>)[name], name).toBeDefined();
      if (name in renderStepMod) expect((renderStepMod as Record<string, unknown>)[name], `${name} re-exported, not copied`).toBe((jobRules as Record<string, unknown>)[name]);
    }
    const defining = ['checkJobOrder', 'isKnownHarmless', 'checkExpressions', 'WORKFLOW_PATH_RE', 'ACTION_PATH_RE', 'TRUSTED_ACTION_RE', 'CACHE_LOCKS', 'isReviewed'];
    for (const f of ['render-step', 'referee', 'linters', 'render-cli']) {
      const text = readFileSync(join(root, `src/engine/${f}.ts`), 'utf8');
      for (const n of defining) expect(new RegExp(`^(?:export )?(?:function|const) ${n}\\b`, 'm').test(text), `${f}.ts defines ${n}`).toBe(false);
    }
  });
  it('the path regexes refuse .. (the linters\' stricter form is the one copy)', () => {
    expect(jobRules.WORKFLOW_PATH_RE.test('.github/workflows/pipegen.yml')).toBe(true);
    expect(jobRules.ACTION_PATH_RE.test('.github/actions/x/action.yml')).toBe(true);
    expect(jobRules.ACTION_PATH_RE.test('.github/actions/../x/action.yml')).toBe(false);
    expect(jobRules.ACTION_PATH_RE.test('.github/actions/a/../../x/action.yml')).toBe(false);
  });
  it('CACHE_LOCKS comes from PLATFORM_LOCKS (every cache-named lock, nothing typed twice)', () => {
    expect(CACHE_LOCKS).toEqual({ 'package-manager-cache': 'false', 'no-cache': 'true', 'cache-binary': 'false' });
    for (const [k, v] of Object.entries(CACHE_LOCKS)) expect(Object.values(PLATFORM_LOCKS).some((l) => l[k] === v), k).toBe(true);
  });
  it('the trusted actions are the platform actions that run no code, plus the harden step, derived from PLATFORM_USES', () => {
    for (const key of ['checkout', 'setup-node', 'setup-python', 'upload-artifact', 'download-artifact', 'upload-sarif'] as const) {
      expect(jobRules.TRUSTED_ACTION_RE.test(`${PLATFORM_USES[key]}@${'a'.repeat(40)}`), key).toBe(true);
    }
    for (const key of ['build-push', 'docker-login', 'setup-buildx', 'attest'] as const) expect(jobRules.TRUSTED_ACTION_RE.test(`${PLATFORM_USES[key]}@${'a'.repeat(40)}`), key).toBe(false);
    expect(jobRules.TRUSTED_ACTION_RE.test(`bullfrogsec/bullfrog@${'a'.repeat(40)}`)).toBe(true);
    expect(jobRules.TRUSTED_ACTION_RE.test(`actions/checkout@v4`)).toBe(false);
  });
  it('TRIVY_LAUNCH_RE is built from the renderer\'s launch text: a rendered trivy step matches it', () => {
    const t = entry('trivy-config');
    const r = renderStep(specFor(t, { needId: 'iac', service: undefined }), t, platform(), ctxFor());
    expect(TRIVY_LAUNCH_RE.test(r.steps.at(-1)?.run ?? '')).toBe(true);
    const other = entry('gitleaks');
    expect(TRIVY_LAUNCH_RE.test(renderStep(specFor(other, { needId: 'secrets', service: undefined }), other, platform(), ctxFor()).steps.at(-1)?.run ?? '')).toBe(false);
  });
});

describe('minor 13: live tests read the token in one place', () => {
  it('liveToken reads GITHUB_TOKEN, else GH_TOKEN, ignores blanks', () => {
    const G = ['GITHUB', 'TOKEN'].join('_');
    const H = ['GH', 'TOKEN'].join('_');
    expect(liveToken({})).toBeUndefined();
    expect(liveToken({ [H]: 'a' })).toBe('a');
    expect(liveToken({ [G]: 'b', [H]: 'a' })).toBe('b');
    expect(liveToken({ [G]: '  ', [H]: 'a' })).toBe('a');
  });
  it('no live test reads the token variables itself', () => {
    const offenders = walk(join(root, 'test')).filter((f) => f.endsWith('-live.test.ts') && /\[\s*\[?\s*'(?:GH|GITHUB)'/.test(readFileSync(f, 'utf8')));
    expect(offenders.map(rel)).toEqual([]);
  });
});

describe('minor 7: stale text', () => {
  it('no message says the action-with-output move is "not implemented in 6a"', () => {
    for (const f of srcFiles()) expect(readFileSync(f, 'utf8'), rel(f)).not.toMatch(/not implemented in 6a/);
  });
  it('the design doc says Trivy uses the pinned in-memory cache config, not cache: false', () => {
    const doc = readFileSync(join(root, 'docs/design.md'), 'utf8');
    expect(doc).not.toMatch(/Trivy `cache: false`/);
    expect(doc).toMatch(/cache\.backend: memory/);
  });
  it('the referee header no longer allows a local file in `files` and says slot values are checked by shape only', () => {
    const head = readFileSync(join(root, 'src/engine/referee.ts'), 'utf8').split('\n').slice(0, 30).join('\n');
    expect(head).not.toMatch(/or a local file that is in `files`/);
    expect(head).toMatch(/by shape only/);
  });
  it('ARGV_POLICIES still has pinact (the table the new runsRepoCode reads)', () => {
    expect(ARGV_POLICIES.pinact).toBeDefined();
  });
});
