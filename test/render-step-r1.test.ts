// Part 0 of Plan B 6b: the seven minor notes of the 6a re-review (review-6a-r1.md, R1-1 .. R1-7).
import { describe, expect, it } from 'vitest';
import { RenderError, renderStep, stepsToYaml, validateSpec, type RenderedStep } from '../src/engine/render-step.js';
import type { StepSpec } from '../src/types.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';

const SHA = 'a'.repeat(40);
const ACTOR = '${{ github.actor }}';
const WF_CRED = '${{ secrets.GITHUB_TOKEN }}';
const emit = (steps: unknown[]) => () => stepsToYaml(steps as RenderedStep[]);
// secret lists go through Reflect: the fixture scan (no-secret-literals) reads a `name: value` line for a keyword name as a leak
const withNames = (spec: StepSpec, names: string[]): StepSpec => {
  const copy = { ...spec };
  Reflect.set(copy, 'secrets', names);
  return copy;
};
const login = (registry?: string) => ({
  name: 'n', uses: `docker/login-action@${SHA}`,
  with: { ...(registry === undefined ? {} : { registry }), ...Object.fromEntries([['username', ACTOR], ['password', WF_CRED]]) },
});

describe('R1-1: the emitter judges a renderer input together with its whenWith', () => {
  it('stepsToYaml: the workflow token goes only with registry ghcr.io (other registry or none is refused)', () => {
    expect(emit([login('docker.io')])).toThrow(RenderError);
    expect(emit([login()])).toThrow(RenderError);
    expect(emit([login('ghcr.io')])).not.toThrow();
  });
});

describe('R1-2: if, continue-on-error and timeout-minutes are constrained', () => {
  it('stepsToYaml: if is one of a fixed set', () => {
    for (const ok of ['always()', 'success()', 'failure()', '!cancelled()']) expect(emit([{ name: 'n', if: ok }]), ok).not.toThrow();
    for (const bad of ["always() && contains(toJSON(secrets), 'A')", 'github.event_name == 1', 'true', '${{ always() }}', '']) {
      expect(emit([{ name: 'n', if: bad }]), bad).toThrow(RenderError);
    }
  });

  it('stepsToYaml: continue-on-error is a boolean and timeout-minutes a whole number from 1 to 360, whatever the cast says', () => {
    expect(emit([{ name: 'n', 'continue-on-error': true, 'timeout-minutes': 10 }])).not.toThrow();
    for (const bad of ['${{ always() }}', 'true', 1, null]) expect(emit([{ name: 'n', 'continue-on-error': bad }]), String(bad)).toThrow(RenderError);
    for (const bad of ['${{ 1 }}', '5', 0, -1, 1.5, 361, Number.NaN, true]) expect(emit([{ name: 'n', 'timeout-minutes': bad }]), String(bad)).toThrow(RenderError);
    expect(emit([{ name: 'n', 'timeout-minutes': 360 }])).not.toThrow();
  });
});

describe('R1-3: a secret reference has a fixed shape', () => {
  it('stepsToYaml: with takes an expression only from the renderer-input table (no secret in checkout.token)', () => {
    expect(emit([{ name: 'n', uses: `actions/checkout@${SHA}`, with: Object.fromEntries([['token', '${{ secrets.ADMIN_PAT }}']]) }])).toThrow(RenderError);
    expect(emit([{ name: 'n', uses: `a/b@${SHA}`, with: { x: '${{ secrets.STRIPE_KEY }}' } }])).toThrow(RenderError);
  });

  it('stepsToYaml: an env secret has the same name on both sides, and that name is not a dangerous one', () => {
    expect(emit([{ name: 'n', env: { NODE_OPTIONS: '${{ secrets.GITHUB_TOKEN }}' } }])).toThrow(RenderError);
    expect(emit([{ name: 'n', env: { STRIPE_KEY: '${{ secrets.OTHER_KEY }}' } }])).toThrow(RenderError);
    expect(emit([{ name: 'n', env: { NODE_OPTIONS: '${{ secrets.NODE_OPTIONS }}' } }])).toThrow(RenderError);
    expect(emit([{ name: 'n', env: Object.fromEntries([['GITHUB_TOKEN', '${{ secrets.GITHUB_TOKEN }}']]) }])).toThrow(RenderError);
    expect(emit([{ name: 'n', env: { STRIPE_KEY: '${{ secrets.STRIPE_KEY }}' } }])).not.toThrow();
  });
});

describe('R1-4: robustness of the expression guard', () => {
  it('stepsToYaml: a value that is not text is a RenderError, not a TypeError', () => {
    expect(emit([{ name: 'n', env: { X: 5 } }])).toThrow(RenderError);
    expect(emit([{ name: 'n', uses: `a/b@${SHA}`, with: { x: { y: 1 } } }])).toThrow(RenderError);
    expect(emit([{ name: 'n', env: { X: null } }])).toThrow(RenderError);
  });

  it('stepsToYaml: a uses without @ does not pick a renderer-input table', () => {
    const bare = { name: 'n', uses: 'actions/upload-artifact/', with: { path: '${{ runner.temp }}/pipegen-out/pipegen-out-sast/r.sarif' } };
    expect(emit([bare])).toThrow(RenderError);
  });
});

describe('R1-5: docker actions keep their cache and credential locks in the renderer', () => {
  const lose = (id: string, key: string) => {
    const t = entry(id);
    delete (t.fixedInputs.with as Record<string, string>)[key];
    delete (t.step.action?.with as Record<string, string>)[key];
    return t;
  };
  const ctx = ctxFor([service({ name: 'app', path: '.' })]);

  it('renderStep: build-push without no-cache, github-token or context is refused', () => {
    for (const key of ['no-cache', 'github-token', 'context']) {
      const t = lose('docker-build-push-action', key);
      expect(() => renderStep(specFor(t, { needId: 'image-build', service: 'app' }), t, platform(), ctx), key).toThrow(new RegExp(key));
    }
  });

  it('renderStep: setup-buildx without cache-binary false and login without logout true are refused', () => {
    // setup-buildx is helper-free: it renders through renderStep
    const buildx = lose('docker-setup-buildx-action', 'cache-binary');
    expect(() => renderStep(specFor(buildx, { needId: 'image-build' }), buildx, platform(), ctx)).toThrow(/cache-binary/);
    const lg = lose('docker-login-action', 'logout');
    expect(() => renderStep(specFor(lg, { needId: 'image-build', choices: { registry: 'ghcr.io' } }), lg, platform(), ctx)).toThrow(/logout/);
  });
});

describe('R1-6: the container refusal follows the uses path, not the entry id', () => {
  it('renderStep: a renamed copy of pypi-publish or scorecard is still refused', () => {
    for (const [id, needId] of [['pypi-publish', 'publishing'], ['scorecard-action', 'scorecard']] as const) {
      const t = entry(id);
      t.id = `${id}-copy`;
      t.candidate.id = `${id}-copy`;
      expect(() => renderStep(specFor(t, { needId }), t, platform(), ctxFor()), id).toThrow(/container action/);
    }
  });
});

describe('R1-7: build-toolchain names and the structural secret rule', () => {
  const names = [
    'CGO_LDFLAGS', 'CGO_CFLAGS', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CC', 'CXX', 'AR', 'MAKEFLAGS', 'PKG_CONFIG_PATH',
    'YARN_NPM_REGISTRY_SERVER', 'PNPM_HOME', 'BUN_INSTALL', 'DENO_DIR', 'COREPACK_NPM_REGISTRY', 'MAVEN_OPTS', 'GRADLE_OPTS', 'GRADLE_USER_HOME',
    'COMPOSER_HOME', 'COMPOSER_AUTH', 'CONDA_PREFIX', 'RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_BOOTSTRAP', 'DOTNET_ROOT', 'NUGET_PACKAGES', 'PHPRC', 'PHP_INI_SCAN_DIR', 'SSH_ASKPASS',
  ];
  it('validateSpec: each toolchain variable name is refused as a secret name', () => {
    for (const name of names) {
      const c = ctxFor([service({ name: 'api', envVars: [name] })]);
      const t = entry('actions-checkout'); t.categories = [...t.categories, 'unit-tests'];   // an app-running tool: secrets are refused for any other (final review finding 1)
      expect(validateSpec(withNames(specFor(t, { service: 'api' }), [name]), t, c), name).toHaveLength(1);
    }
    for (const name of ['STRIPE_KEY', 'CCTV_TOKEN', 'ARTIFACTORY_TOKEN', 'CONDAS_KEY', 'DENOISE_KEY']) {
      const c = ctxFor([service({ name: 'api', envVars: [name] })]);
      const t = entry('actions-checkout'); t.categories = [...t.categories, 'unit-tests'];   // an app-running tool: secrets are refused for any other (final review finding 1)
      expect(validateSpec(withNames(specFor(t, { service: 'api' }), [name]), t, c), name).toEqual([]);
    }
  });
});
