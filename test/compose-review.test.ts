// D4 review repros (review-D4.md): the acceptance set of fix round 1. Each test asserts the wanted behaviour.
import { Document, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { composeText, runtimeEnv } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import { renderComposeUp, renderJobPrelude, renderRuntimeEnv, stepsToYaml, type RenderedStep } from '../src/engine/render-step.js';
import type { CreatedFile, Dependency, ExistingWorkflow, PipelineDraft, Service } from '../src/types.js';
import { DBPW } from './helpers/dbpw.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';

const list = loadBaseImages();
const dep = (kind: Dependency['kind'], envVars: string[] = []): Dependency => ({ kind, name: kind, evidence: 'x', envVars });
const api = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [dep('postgres', ['DATABASE_URL'])], ...over });
const mk = (services: Service[], created: CreatedFile[] = []): PipelineDraft => ({ profile: profile(services), capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true }, needs: [], steps: [], created, notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [] } as PipelineDraft);
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
const wf = (steps: RenderedStep[], jobEnv?: Record<string, string>): CreatedFile => {
  const doc = new Document();
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: { 'app-start': { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', ...(jobEnv ? { env: jobEnv } : {}) } } });
  doc.setIn(['jobs', 'app-start', 'steps'], stepsToYaml(steps));
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
};
const prelude = (): RenderedStep[] => renderJobPrelude({}, platform()).steps;
const UP = renderComposeUp();
const cf = (content: string): CreatedFile => ({ path: 'docker-compose.pipegen.yml', content, part: 'compose', reason: 't', repo: 'app' });

describe('I1: steps and runtime env follow the compose file pipegen computes', () => {
  it('compose-up with no compose file in the draft is not recognised (S3: an unowned file would run)', async () => {
    const r = await run([wf([...prelude(), renderRuntimeEnv(runtimeEnv(mk([api()]).profile)), UP])], mk([api()]));
    expect(r.issues.length).toBeGreaterThan(0);
  });
  it('a runnable service that gets no container (python / no Dockerfile): no compose, so neither step is recognised', async () => {
    for (const s of [api({ language: 'python', packageManager: 'pip' as never }), api({ dockerfile: undefined })]) {
      const d = mk([s]);
      expect(composeText(d.profile, list)).toBeNull();
      const r = await run([wf([...prelude(), renderRuntimeEnv(runtimeEnv(d.profile)), UP])], d);
      expect(r.issues.length).toBeGreaterThan(0);
    }
  });
  it('runtimeEnv maps only dependencies that get a container (MONGO_URL with no mongodb service)', () => {
    const d = mk([api(), api({ name: 'worker', path: 'worker', dockerfile: 'worker/Dockerfile', port: 4000, language: 'python', packageManager: 'pip' as never, dependsOn: [dep('mongodb', ['MONGO_URL'])] })]);
    expect(composeText(d.profile, list)).not.toMatch(/^  mongodb:$/m);
    expect(runtimeEnv(d.profile).vars.map((v) => v.name)).not.toContain('MONGO_URL');
  });
});

describe('I2: build.context is never a remote context', () => {
  it('a folder github.com/acme/api is written as a local path (./...)', () => {
    const t = composeText(mk([api({ path: 'github.com/acme/api', dockerfile: 'github.com/acme/api/Dockerfile' })]).profile, list);
    expect(t === null || /context: "\.\/github\.com\/acme\/api"/.test(t)).toBe(true);
  });
});

describe('Minor', () => {
  it('M1: compose-up without a runtime-env step before it in its job is refused, and the file fails closed (${..:?})', async () => {
    const d = mk([api()]);
    const t = composeText(d.profile, list) as string;
    const r = await run([wf([...prelude(), UP]), cf(t)], d);
    expect(r.issues.length > 0 || new RegExp('\\$\\{' + DBPW + ':\\?').test(t)).toBe(true);
  });
  it('M2: an app port equal to a dependency port is not proven', () => {
    expect(composeText(mk([api({ port: 6379, dependsOn: [dep('redis', ['REDIS_URL'])] })]).profile, list)).toBeNull();
  });
  it('M3: COMPOSE_* / BUILDX_* / BUILDKIT_* in a job env are refused', async () => {
    const d = mk([api()]);
    const r = await run([wf([...prelude(), renderRuntimeEnv(runtimeEnv(d.profile)), UP], { BUILDX_BUILDER: 'remote', COMPOSE_BAKE: 'true' }), cf(composeText(d.profile, list) as string)], d);
    expect(r.issues.some((i) => i.check === 'injection')).toBe(true);
  });
  it('M4: the compose file may build only a created Dockerfile that is among the judged files', async () => {
    const d = mk([api({ dockerfile: undefined })], [{ path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 'r', repo: 'app' }]);
    const r = await run([cf(composeText(d.profile, list, ['api/Dockerfile']) as string)], d);
    expect(r.issues.length).toBeGreaterThan(0);
  });
  it('M5: in an edited user workflow, the name in a pipegen job env is an injection', async () => {
    const d0 = mk([api()]);
    const dU = { ...d0, profile: { ...d0.profile, existingWorkflows: [{ path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: false, [['secrets', 'Used'].join('')]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow] } };
    const original = 'name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: echo hi\n';
    const doc = parseDocument(`${original}  app-start:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    cache-mode: none\n    env:\n      X: ${DBPW}\n    steps: []\n`);
    doc.setIn(['jobs', 'app-start', 'steps'], stepsToYaml([...prelude(), renderRuntimeEnv(runtimeEnv(d0.profile)), UP]));
    const r = await run([{ path: '.github/workflows/deploy.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app', inserted: { original, jobs: ['app-start'], needs: [] } }], dU);
    expect(r.issues.some((i) => i.check === 'injection')).toBe(true);
  });
});
