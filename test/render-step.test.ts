import { DOCKER_STEP_IMAGES } from '../src/engine/tool-flags.js';
import { describe, expect, it } from 'vitest';
import { attestDigestRef } from '../src/engine/job-rules.js';
import { Document, parse } from 'yaml';
import {
  jobSettings, mapNodeVersion, RenderError, renderJobPrelude, renderPlatformStep, renderStep, renderUpload, stepsToYaml, validateSpec, type RenderedStep,
} from '../src/engine/render-step.js';
import { RENDERER_INPUTS, rendererInputProblems } from '../src/engine/tool-flags.js';
import { RESULT_ARTIFACT_PREFIX, type ReviewedCandidate, type StepSpec } from '../src/types.js';
import { ctxFor, entry, gateEntry, platform, reviewedList, service, specFor } from './helpers/render.js';

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
/** A copy of the checkout entry that counts as an app-running tool (secrets are refused for any other: final review finding 1), for the secret-name tests. */
const appRunning = () => { const t = checkout(); t.categories = [...t.categories, 'unit-tests']; return t; };
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
    const t = appRunning();
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

  it('renderStep: a cli entry is rendered by the CLI renderer (6b), and one that cannot be yet says why', () => {
    const t = entry('gitleaks');
    expect(renderStep(specFor(t), t, platform(), ctx).steps.length).toBeGreaterThan(1);
    for (const [id, why] of [['bandit', /not available yet/], ['registry', /service/]] as const) {
      const u = entry(id);
      expect(() => renderStep(specFor(u), u, platform(), ctx), id).toThrow(why);
    }
  });
});

describe('renderStep: actions', () => {
  const ctx = ctxFor();

  it('renderStep: uses is the reviewed step.action.uses (sub-path kept) with the version as a trailing comment', () => {
    const t = entry('codeql-upload-sarif');
    const step = renderPlatformStep('upload-sarif', platform(), { sarif_file: '${{ runner.temp }}/pipegen-out/pipegen-out-sast/r.sarif', category: 'pipegen-sast' });
    expect(step.uses).toBe(t.step.action?.uses);
    expect(step.uses).toMatch(/^github\/codeql-action\/upload-sarif@[0-9a-f]{40}$/);
    expect(step.usesComment).toBe(t.candidate.version);
    expect(yamlOf([step])).toContain(`uses: ${t.step.action?.uses} # ${t.candidate.version}\n`);
    // a scanner action goes through renderStep; its output is null (no result file)
    const dr = entry('dependency-review-action');
    const r = renderStep(specFor(dr, { needId: 'dependency-review' }), dr, platform(), ctx);
    expect(r.steps).toHaveLength(1);
    expect(r.steps[0]?.uses).toBe(dr.step.action?.uses);
    expect(r.output).toBeNull();
  });

  it('renderStep: every platform action renders pinned by a 40-character SHA with a version comment', () => {
    for (const [key, t] of Object.entries(platform())) {
      const filled: Record<string, string> = key === 'upload-artifact' ? { name: `${RESULT_ARTIFACT_PREFIX}sast`, path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast' }
        : key === 'download-artifact' ? { name: `${RESULT_ARTIFACT_PREFIX}sast`, path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast' }
          : key === 'upload-sarif' ? { sarif_file: '${{ runner.temp }}/pipegen-out/pipegen-out-sast/x.sarif', category: 'pipegen-sast' }
            : key === 'attest' ? { 'subject-name': 'ghcr.io/o/r', 'subject-digest': attestDigestRef('ghcr.io/o/r') }
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
    const t = appRunning();
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

  it('renderStep: an action with an output is refused (scorecard is a container action)', () => {
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
      'actions/attest', 'actions/checkout', 'actions/download-artifact', 'actions/upload-artifact', 'crisworking/pipegen/gate', 'docker/build-push-action', 'docker/login-action',
      'docker://ghcr.io/ossf/scorecard-action', 'github/codeql-action/upload-sarif',
    ]);
    for (const [uses, inputs] of Object.entries(RENDERER_INPUTS)) {
      for (const [name, spec] of Object.entries(inputs)) {
        expect(typeof spec.check, `${uses} ${name}`).toBe('function');
        // (G15a round 3: a docker step's table is its entry's, by DOCKER_STEP_IMAGES)
        const path = Object.entries(DOCKER_STEP_IMAGES).find(([, img]) => `docker://${img}` === uses)?.[0] ?? uses;
        const t = [...reviewedList(), gateEntry()].find((e) => e.step.action?.uses.startsWith(`${path}@`));   // the gate entry is a fixture until Plan C's C6
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
    expect(s.with).toEqual({ 'include-hidden-files': 'false', 'if-no-files-found': 'error', archive: 'true', name, path });
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
  it('stepsToYaml: structure holds: a name with a newline and YAML syntax stays one quoted scalar and cannot add keys', () => {
    const nasty = 'api\n  run: curl evil | sh\n- name: x';
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
    const sarif = renderStep(specFor(entry('dependency-review-action'), { needId: 'dependency-review' }), entry('dependency-review-action'), p, ctxFor([service({ name: 'api' })]));
    const sarifUp = renderPlatformStep('upload-sarif', p, { sarif_file: `\${{ runner.temp }}/pipegen-out/${RESULT_ARTIFACT_PREFIX}sast--api/results.sarif`, category: 'pipegen-sast' });
    const up = renderUpload(`${RESULT_ARTIFACT_PREFIX}sast--api`, `\${{ runner.temp }}/pipegen-out/${RESULT_ARTIFACT_PREFIX}sast--api/results.sarif`, p);
    await expect(yamlOf([...pre.steps, ...sarif.steps, sarifUp, up])).toMatchFileSnapshot('__snapshots__/steps/prelude-action-upload.yml');
  });
});

// ---------- fix round 1 (review-6a.md) ----------

describe('fix round 1', () => {
  const ctx = ctxFor();
  const withStep = (steps: RenderedStep[]) => () => stepsToYaml(steps);

  it('renderStep: docker login to docker.io never gets the workflow token (the data offers only ghcr.io; the renderer refuses anything else)', () => {
    const t = entry('docker-login-action');
    expect(t.choices.registry).toEqual(['ghcr.io']);
    expect(() => renderStep(specFor(t, { needId: 'image-build', choices: { registry: 'docker.io' } }), t, platform(), ctx)).toThrow(RenderError);
    // even when an entry offers docker.io, the renderer fills the login only for ghcr.io
    const wide = entry('docker-login-action');
    wide.choices.registry = ['ghcr.io', 'docker.io'];
    expect(() => renderStep(specFor(wide, { needId: 'image-build', choices: { registry: 'docker.io' } }), wide, platform(), ctx)).toThrow(/ghcr\.io/);
    expect(() => renderPlatformStep('docker-login', platform(), Object.fromEntries([['username', ACTOR], ['password', WF_CRED]]), { registry: 'docker.io' })).toThrow(RenderError);
  });

  it('rendererInputProblems: the login password is tied to registry ghcr.io', () => {
    const login = loginWith();
    expect(rendererInputProblems('docker/login-action', login, { ...login, registry: 'ghcr.io' })).toEqual([]);
    expect(rendererInputProblems('docker/login-action', login, { ...login, registry: 'docker.io' })).toEqual([expect.stringMatching(/ghcr\.io/)]);
    expect(rendererInputProblems('docker/login-action', login, login)).toEqual([expect.stringMatching(/ghcr\.io/)]);
  });

  it('renderStep: container actions (S13): pypi-publish builds its image at run time and scorecard runs one by tag, so both stay refused with the reason; a digest-pinned wrappedImage renders', () => {
    const pypi = entry('pypi-publish');
    expect(() => renderStep(specFor(pypi, { needId: 'publishing' }), pypi, platform(), ctx)).toThrow(/Dockerfile/);
    const sc = entry('scorecard-action');
    expect(() => renderStep(specFor(sc, { needId: 'scorecard' }), sc, platform(), ctx)).toThrow(/by tag/);
    // keyed by the uses path: a copy with another id and no wrappedImage is refused as a container action
    const copy = entry('scorecard-action');
    copy.id = 'other';
    copy.candidate.id = 'other';
    delete copy.wrappedImage;
    expect(() => renderStep(specFor(copy, { needId: 'scorecard' }), copy, platform(), ctx)).toThrow(/container action.*wrappedImage|wrappedImage/);
    // an entry that has a wrappedImage is a container action by definition
    const marked = entry('dependency-review-action');
    marked.wrappedImage = { ref: 'docker.io/x/y:1', digest: `sha256:${'a'.repeat(64)}` };
    expect(() => renderStep(specFor(marked, { needId: 'dependency-review' }), marked, platform(), ctx)).toThrow(/by tag/);
    // ... and renders when its image is pinned by the digest it recorded
    const pinned = entry('dependency-review-action');
    pinned.wrappedImage = { ref: `ghcr.io/x/y@sha256:${'a'.repeat(64)}`, digest: `sha256:${'a'.repeat(64)}` };
    expect(renderStep(specFor(pinned, { needId: 'dependency-review' }), pinned, platform(), ctx).steps[0]?.uses).toMatch(/@[0-9a-f]{40}$/);
    // a digest in the ref that is not the recorded one is not trusted
    const lying = entry('dependency-review-action');
    lying.wrappedImage = { ref: `ghcr.io/x/y@sha256:${'b'.repeat(64)}`, digest: `sha256:${'a'.repeat(64)}` };
    expect(() => renderStep(specFor(lying, { needId: 'dependency-review' }), lying, platform(), ctx)).toThrow(/by tag/);
  });

  it('renderStep: renders what it validated (a getter that changes after the first read cannot swap the secrets)', () => {
    const c = ctxFor([service({ name: 'api', envVars: ['STRIPE_KEY'] })]);
    const t = appRunning();
    const spec = specFor(t, { service: 'api' });
    let reads = 0;
    Object.defineProperty(spec, 'secrets', { enumerable: true, get: () => (++reads <= 1 ? ['STRIPE_KEY'] : ['NODE_OPTIONS', 'X }}${{ github.token']) });
    const r = renderStep(spec, t, platform(), c);
    expect(Object.keys(r.steps[0]?.env ?? {})).toEqual(['STRIPE_KEY']);
    // a spec that can't be copied (a function inside) is a RenderError, not a crash
    const odd = specFor(t);
    Reflect.set(odd, 'choices', { 'fetch-depth': () => '1' });
    expect(() => renderStep(odd, t, platform(), ctx)).toThrow(RenderError);
  });

  it("stepsToYaml: '${{' in name, run, id, if, working-directory, env or with keys throws; only the allowed forms pass", () => {
    const expr = '${{ github.head_ref }}';
    for (const step of [
      { name: `scan ${expr}` }, { name: 'n', run: `echo ${expr}` }, { name: 'n', id: expr }, { name: 'n', if: expr }, { name: 'n', 'working-directory': expr },
      { name: 'n', env: { X: expr } }, { name: 'n', env: { [expr]: 'x' } }, { name: 'n', env: { X: '${{ secrets.X }} ${{ github.token }}' } },
      { name: 'n', env: { X: '${{ secrets.lower }}' } }, { name: 'n', uses: `a/b@${'a'.repeat(40)}`, with: { x: expr } },
      { name: 'n', uses: `a/b@${'a'.repeat(40)}`, with: { x: '${{ secrets.OTHER }}' + expr } },
      { name: 'n', uses: `actions/checkout@${'a'.repeat(40)}`, with: { ref: expr } },
      { name: 'n', uses: `docker/login-action@${'a'.repeat(40)}`, with: { username: '${{ secrets.GITHUB_TOKEN }}' } },
    ] as RenderedStep[]) expect(withStep([step]), JSON.stringify(step)).toThrow(RenderError);
    const ok: RenderedStep[] = [
      { name: 'n', env: { STRIPE_KEY: '${{ secrets.STRIPE_KEY }}' } },
      { name: 'n', uses: `actions/upload-artifact@${'a'.repeat(40)}`, with: { name: 'pipegen-out-sast', path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast/x.sarif' } },
      { name: 'n', uses: `docker/login-action@${'a'.repeat(40)}`, with: { registry: 'ghcr.io', ...Object.fromEntries([['username', ACTOR], ['password', WF_CRED]]) } },   // the token only goes with ghcr.io (R1-1)
    ];
    expect(withStep(ok)).not.toThrow();
  });

  it('platform locks: checkout, setup-node and upload-artifact entries that lost a lock are refused by every render path', () => {
    const lose = (id: string, key: string, asChoice = false) => {
      const list = reviewedList();
      const t = list.find((e) => e.id === id) as ReturnType<typeof entry>;
      delete (t.fixedInputs.with as Record<string, string>)[key];
      delete (t.step.action?.with as Record<string, string>)[key];
      if (asChoice) t.choices[key] = ['true', 'false'];
      return platform(list);
    };
    // moved from fixed to a choice: the generic path refuses it too (not only the prelude)
    expect(() => renderPlatformStep('checkout', lose('actions-checkout', 'persist-credentials', true), {}, { 'persist-credentials': 'true' })).toThrow(/persist-credentials/);
    expect(() => renderPlatformStep('checkout', lose('actions-checkout', 'allow-unsafe-pr-checkout'))).toThrow(/allow-unsafe-pr-checkout/);
    expect(() => renderJobPrelude({ node: {} }, lose('actions-setup-node', 'package-manager-cache'))).toThrow(/package-manager-cache/);
    expect(() => renderPlatformStep('setup-node', lose('actions-setup-node', 'package-manager-cache'))).toThrow(/package-manager-cache/);
    expect(() => renderUpload(`${RESULT_ARTIFACT_PREFIX}sast`, `\${{ runner.temp }}/pipegen-out/${RESULT_ARTIFACT_PREFIX}sast/x`, lose('actions-upload-artifact', 'include-hidden-files'))).toThrow(/include-hidden-files/);
    expect(() => renderUpload(`${RESULT_ARTIFACT_PREFIX}sast`, `\${{ runner.temp }}/pipegen-out/${RESULT_ARTIFACT_PREFIX}sast/x`, lose('actions-upload-artifact', 'if-no-files-found'))).toThrow(/if-no-files-found/);
    // renderStep on a platform entry used as a step checks them too
    const noLock = reviewedList().find((e) => e.id === 'actions-checkout') as ReturnType<typeof entry>;
    delete (noLock.fixedInputs.with as Record<string, string>)['persist-credentials'];
    delete (noLock.step.action?.with as Record<string, string>)['persist-credentials'];
    expect(() => renderStep(specFor(noLock), noLock, platform(), ctx)).toThrow(/persist-credentials/);
  });

  it('guards: a spec tool that is not reviewed, a swapped platform entry and a disagreeing template are each refused on their own', () => {
    // M1: right id and pin, but marked as a discovery candidate
    const t = checkout();
    const p = validateSpec(specFor(t, { tool: { ...t.candidate, source: 'discovery', reviewed: false } as unknown as ReviewedCandidate }), t, ctx);
    expect(p).toEqual([expect.stringMatching(/^tool: .*reviewed tool/)]);
    // M2: the checkout slot holds another reviewed action
    const list = reviewedList();
    const swapped = platform(list);
    swapped.checkout = list.find((e) => e.id === 'actions-setup-node') as ReturnType<typeof entry>;
    expect(() => renderPlatformStep('checkout', swapped, {})).toThrow(/does not run actions\/checkout/);
    // M4: step.action.with and fixedInputs.with disagree (a key only in the step)
    const dis = entry('bullfrog');
    (dis.step.action?.with as Record<string, string>)['extra-input'] = 'x';
    expect(() => renderStep(specFor(dis), dis, platform(), ctx)).toThrow(/disagrees/);
    // the choice check of renderPlatformStep on its own
    expect(() => renderPlatformStep('checkout', platform(), {}, { 'fetch-depth': '9' })).toThrow(/fetch-depth/);
  });

  it('renderUpload: the path must be inside this artifact\'s own folder', () => {
    const a = `${RESULT_ARTIFACT_PREFIX}sast--api`;
    expect(() => renderUpload(a, `\${{ runner.temp }}/pipegen-out/${RESULT_ARTIFACT_PREFIX}secrets/raw.sarif`, platform())).toThrow(/artifact/);
    expect(() => renderUpload(a, `\${{ runner.temp }}/pipegen-out/${a}x/raw.sarif`, platform())).toThrow(RenderError);
    expect(renderUpload(a, `\${{ runner.temp }}/pipegen-out/${a}/raw.sarif`, platform()).with?.path).toBe(`\${{ runner.temp }}/pipegen-out/${a}/raw.sarif`);
    expect(renderUpload(a, `\${{ runner.temp }}/pipegen-out/${a}`, platform()).with?.path).toBe(`\${{ runner.temp }}/pipegen-out/${a}`);
  });

  it('renderStep: actions that only render through their own helper are refused (artifacts, sarif, attest)', () => {
    for (const [id, needId] of [['actions-upload-artifact', 'sast'], ['actions-download-artifact', 'gate'], ['codeql-upload-sarif', 'sast'], ['actions-attest', 'attestation']] as const) {
      const t = entry(id);
      expect(() => renderStep(specFor(t, { needId }), t, platform(), ctx), id).toThrow(/renderPlatformStep|renderUpload/);
    }
  });

  it('validateSpec: secret names that change how a runtime, proxy, TLS store, package index or locale behaves are refused (every family)', () => {
    const families: Record<string, string[]> = {
      proxy: ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'FTP_PROXY'],
      tls: ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'CURL_CA_BUNDLE', 'CURL_HOME', 'REQUESTS_CA_BUNDLE', 'OPENSSL_CONF', 'OPENSSL_MODULES'],
      pythonIndex: ['PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'UV_INDEX_URL', 'UV_DEFAULT_INDEX'],
      java: ['JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS'],
      perlRuby: ['PERL5OPT', 'PERL5LIB', 'PERLLIB', 'RUBYOPT', 'RUBYLIB', 'GEM_HOME', 'GEM_PATH', 'BUNDLE_GEMFILE'],
      rustGo: ['CARGO_HOME', 'CARGO_REGISTRIES_X_TOKEN', 'RUSTUP_HOME', 'RUSTFLAGS', 'GOFLAGS', 'GOPROXY', 'GOPRIVATE', 'GO111MODULE'],
      dirs: ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'TMPDIR', 'TMP', 'TEMP'],
      shell: ['SHELL', 'PROMPT_COMMAND', 'BASH_ENV', 'ENV', 'IFS', 'PS4'],
      resolver: ['HOSTALIASES', 'RES_OPTIONS', 'LOCALDOMAIN'],
      libc: ['GCONV_PATH', 'MALLOC_CHECK_', 'MALLOC_PERTURB_', 'GLIBC_TUNABLES', 'LD_PRELOAD', 'LD_LIBRARY_PATH'],
      locale: ['LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TERM', 'TERMINFO'],
    };
    for (const [family, names] of Object.entries(families)) {
      for (const name of names) {
        const c = ctxFor([service({ name: 'api', envVars: [name] })]);
        const t = appRunning();
        const problems = validateSpec(withNames(specFor(t, { service: 'api' }), [name]), t, c);
        expect(problems, `${family}: ${name}`).toHaveLength(1); // refused by the name rule or the dangerous list
      }
    }
    // an ordinary application secret that merely starts with GO, TERM, TMP… is not caught by accident
    for (const name of ['GOOGLE_API_KEY', 'STRIPE_KEY', 'DATABASE_URL', 'TWILIO_AUTH', 'SENDGRID_API_KEY']) {
      const c = ctxFor([service({ name: 'api', envVars: [name] })]);
      const t = appRunning();
      expect(validateSpec(withNames(specFor(t, { service: 'api' }), [name]), t, c), name).toEqual([]);
    }
  });
});
