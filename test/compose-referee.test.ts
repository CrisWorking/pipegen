// D4: the compose judge (the file must equal composeText(draft.profile, baseImages) byte for byte) and the referee's recognition of the
// runtime-env and compose-up steps. PIPEGEN_DB_PASSWORD is allowed only in the exact runtime-env step.
import { WORKFLOW_CONCURRENCY } from '../src/engine/job-rules.js';   // G17 row 1b: pipegen.yml carries the workflow concurrency
import { Document, parseDocument } from 'yaml';
import { describe, expect, it } from 'vitest';
import { composeText, createCompose, runtimeEnv } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { CREATED_RULES, createdFileProblems } from '../src/engine/created-files.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import { renderComposeUp, renderJobPrelude, renderRuntimeEnv, stepsToYaml, type RenderedStep } from '../src/engine/render-step.js';
import type { CreatedFile, Dependency, ExistingWorkflow, DependencyKind, PipelineDraft, Service } from '../src/types.js';
import { DBPW, runtimeOf } from './helpers/dbpw.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';
import { withEgress } from './helpers/egress-step.js';

const list = loadBaseImages();
const dep = (kind: DependencyKind, envVars: string[] = []): Dependency => ({ kind, name: kind, evidence: 'x', envVars });
const api = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [dep('postgres', ['DATABASE_URL'])], ...over });
const mkDraft = (services: Service[] = [api()], created: CreatedFile[] = []): PipelineDraft => ({
  profile: profile(services), capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true },
  needs: [], steps: [], created, notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const goodText = (d: PipelineDraft): string => composeText(d.profile, list) as string;
const cf = (content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path: 'docker-compose.pipegen.yml', content, part: 'compose', reason: 'test', repo: 'app', ...over });
const problems = (f: CreatedFile, d: PipelineDraft = mkDraft()): string[] => createdFileProblems(f, d).problems;

describe('compose judge', () => {
  it('the creator\'s output passes; one tampered byte gives an issue (parity)', () => {
    const d = mkDraft();
    const made = createCompose(d.profile, { repoPaths: new Set(['api/Dockerfile']), baseImages: list });
    expect(made.file).not.toBeNull();
    expect(createdFileProblems(made.file as CreatedFile, d)).toEqual({ claimed: true, problems: [] });
    const good = goodText(d);
    expect(good).toBe((made.file as CreatedFile).content);
    for (let i = 0; i < good.length; i += 7) {
      const t = good.slice(0, i) + (good[i] === 'x' ? 'y' : 'x') + good.slice(i + 1);
      expect(problems(cf(t), d).length, `byte ${i}`).toBeGreaterThan(0);
    }
    for (const t of ['', `${good}\n`, good.slice(0, -1), `${good}# x\n`, good.replace(/\n/g, '\r\n'), good.replace('127.0.0.1:', '0.0.0.0:'), good.replace('service_healthy', 'service_started'), `${good}  extra:\n    privileged: true\n`]) {
      expect(problems(cf(t), d).length, JSON.stringify(t.slice(0, 40))).toBeGreaterThan(0);
    }
  });

  it('the judge reads the draft\'s profile, not the file: other deps or another service give other text', () => {
    const d = mkDraft();
    const other = mkDraft([api({ dependsOn: [dep('redis', ['REDIS_URL'])] })]);
    expect(problems(cf(goodText(other)), d).length).toBeGreaterThan(0);
    expect(problems(cf(goodText(other)), other)).toEqual([]);
  });

  it('a draft with nothing to containerise: any compose file is refused', () => {
    expect(problems(cf('services: {}\n'), mkDraft([api({ dependsOn: [] })])).join()).toMatch(/would not write a compose file/);
  });

  it('a Dockerfile pipegen creates in the same draft counts (parity with createCompose createdDockerfiles)', () => {
    const noDocker = api({ dockerfile: undefined });
    const df: CreatedFile = { path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 'r', repo: 'app' };
    const d = mkDraft([noDocker], [df]);
    const made = createCompose(d.profile, { repoPaths: new Set<string>(), baseImages: list, createdDockerfiles: ['api/Dockerfile'] });
    expect(made.file).not.toBeNull();
    expect(problems(made.file as CreatedFile, d)).toEqual([]);
    expect(problems(made.file as CreatedFile, mkDraft([noDocker]))).not.toEqual([]);   // no Dockerfile in the draft: refused
  });

  it('only app-repo Dockerfiles of part docker, named exactly Dockerfile, count as created', () => {
    const noDocker = api({ dockerfile: undefined });
    const mk = (over: Partial<CreatedFile>): PipelineDraft => mkDraft([noDocker], [{ path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 'r', repo: 'app', ...over }]);
    const text = composeText(mkDraft([noDocker]).profile, list, ['api/Dockerfile']) as string;
    expect(problems(cf(text), mk({}))).toEqual([]);
    for (const over of [{ repo: 'central' as const }, { part: 'tests' as const }, { path: 'api/xDockerfile' }, { path: 'api/Dockerfile.prod' }, { path: 'web/Dockerfile' }]) expect(problems(cf(text), mk(over)).length, JSON.stringify(over)).toBeGreaterThan(0);
    expect(problems(cf(text), mkDraft([noDocker], [])).length).toBeGreaterThan(0);
  });

  it('only at the root path, as a new file, with part compose; never an edit; never with a non-text content', () => {
    const d = mkDraft();
    expect(createdFileProblems(cf(goodText(d), { path: 'api/docker-compose.pipegen.yml' }), d).claimed).toBe(false);
    expect(problems({ ...cf(goodText(d)), edited: { original: '' } }, d).join()).toMatch(/written whole/);
    expect(problems(cf(goodText(d), { part: 'docker' }), d).join()).toMatch(/part/);
    expect(problems(cf(undefined as unknown as string), d).join()).toMatch(/not text/);
  });
});

const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
// the compose file pipegen computes for the draft rides along (the steps are recognised only beside it, D4 I1) unless the test brings its own
const withCompose = (files: CreatedFile[], d: PipelineDraft): CreatedFile[] => {
  const t = composeText(d.profile, list);
  return t === null || files.some((f) => f.path === 'docker-compose.pipegen.yml') ? files : [...files, cf(t)];
};
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(withCompose(files, d), d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const has = (r: RefereeReport, check: string): boolean => r.issues.some((i) => i.check === check);
const wfText = (steps: RenderedStep[], top: Record<string, unknown> = {}, jobOver: Record<string, unknown> = {}): string => {
  const doc = new Document();
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, concurrency: { ...WORKFLOW_CONCURRENCY }, ...top, jobs: { 'app-start': { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', ...jobOver } } });
  doc.setIn(['jobs', 'app-start', 'steps'], stepsToYaml(withEgress(steps)));
  return doc.toString({ lineWidth: 0 });
};
const wf = (steps: RenderedStep[], top?: Record<string, unknown>, jobOver?: Record<string, unknown>): CreatedFile => ({ path: '.github/workflows/pipegen.yml', content: wfText(steps, top, jobOver), part: 'pipeline', reason: 'test', repo: 'app' });
const prelude = (): RenderedStep[] => renderJobPrelude({}, platform()).steps;
const d0 = mkDraft();
const RT = renderRuntimeEnv(runtimeEnv(d0.profile));
const UP = renderComposeUp();

describe('referee: runtime-env and compose-up steps', () => {
  it('referee: renderRuntimeEnv step accepted (with compose-up after it)', async () => {
    const r = await run([wf([...prelude(), RT, UP])], d0);
    expect(show(r)).toBe('');
  });

  it('PIPEGEN_DB_PASSWORD anywhere else -> injection: another run step, a with, an env, a name, the job env, the workflow env, a service', async () => {
    const bad: [string, RenderedStep[], Record<string, unknown>?, Record<string, unknown>?][] = [
      ['another run step', [...prelude(), { name: 'x', run: 'echo "$PIPEGEN_DB_PASSWORD"', shell: 'bash' }]],
      ['in an env of a step', [...prelude(), { ...UP, env: { ...UP.env, [DBPW]: 'x' } }]],
      ['in a step name', [...prelude(), { ...UP, name: 'PIPEGEN_DB_PASSWORD' }]],
      ['in the compose-up command', [...prelude(), { ...UP, run: `${UP.run as string}\necho "$PIPEGEN_DB_PASSWORD"` }]],
      ['in a with of an action', [{ ...(prelude()[0] as RenderedStep), with: { ...(prelude()[0] as RenderedStep).with, 'fetch-depth': 'PIPEGEN_DB_PASSWORD' } }]],
      ['in the job env', [...prelude(), RT], {}, { env: { [DBPW]: 'x' } }],
      ['in the workflow env', [...prelude(), RT], { env: { OTHER: 'PIPEGEN_DB_PASSWORD' } }],
      ['twice: a second copy of the runtime-env step text inside another step', [...prelude(), RT, { ...UP, run: `${UP.run as string}\n${RT.run as string}` }]],
    ];
    for (const [what, steps, top, job] of bad) {
      const r = await run([wf(steps, top, job)], d0);
      expect(has(r, 'injection'), `${what}\n${show(r)}`).toBe(true);
    }
  });

  it('the name in another letter case is caught too', async () => {
    const r = await run([wf([...prelude(), RT, { name: 'x', run: `echo "$${DBPW.toLowerCase()}"`, shell: 'bash' }, UP])], d0);
    expect(has(r, 'injection'), show(r)).toBe(true);
  });

  it('a tampered runtime-env step (one changed byte) is not recognised: injection for the name, plus an unreviewed run step', async () => {
    const run0 = RT.run as string;
    const nameAt = run0.indexOf('PIPEGEN_DB_PASSWORD');
    const outside = [0, 20, Math.floor(run0.length / 2), run0.length - 2].filter((i) => i < nameAt || i >= nameAt + 'PIPEGEN_DB_PASSWORD'.length);
    expect(outside.length).toBeGreaterThan(2);
    for (const i of [...outside, nameAt + 3]) {
      const t = { ...RT, run: run0.slice(0, i) + (run0[i] === 'x' ? 'y' : 'x') + run0.slice(i + 1) };
      const r = await run([wf([...prelude(), t, UP])], d0);
      // the name is still there unless the byte hit it: then the step is simply not recognised
      if (i !== nameAt + 3) expect(has(r, 'injection'), `byte ${i}\n${show(r)}`).toBe(true);
      expect(has(r, 'unreviewed') || has(r, 'template'), show(r)).toBe(true);
    }
    // another id, the same text
    const renamed = { ...RT, id: 'runtime-env-0000000000000000' };
    expect(has(await run([wf([...prelude(), renamed, UP])], d0), 'injection')).toBe(true);
    // the env of the step changed
    expect(has(await run([wf([...prelude(), { ...RT, env: { ...RT.env, X: '1' } }, UP])], d0), 'injection')).toBe(true);
  });

  it('a runtime-env step of another content than the draft\'s RuntimeEnv is not recognised', async () => {
    const other = renderRuntimeEnv(runtimeOf([{ name: 'REDIS_URL', kind: 'url', dep: 'redis' }]));
    const r = await run([wf([...prelude(), other, UP])], d0);
    expect(has(r, 'injection'), show(r)).toBe(true);
  });

  it('a draft with no container dependency recognises neither step', async () => {
    const none = mkDraft([api({ dependsOn: [] })]);
    const r = await run([wf([...prelude(), RT, UP])], none);
    expect(has(r, 'injection') || has(r, 'unreviewed'), show(r)).toBe(true);
    expect(r.issues.length).toBeGreaterThan(1);
    const r2 = await run([wf([...prelude(), UP])], none);
    expect(has(r2, 'unreviewed'), show(r2)).toBe(true);
    // a dependency of a service that does not run (a library) expects no start step either
    const lib = mkDraft([api({ scripts: [], frameworks: [], port: undefined, dockerfile: undefined })]);
    const r3 = await run([wf([...prelude(), UP])], lib);
    expect(has(r3, 'unreviewed'), show(r3)).toBe(true);
  });

  it('compose-up is recognised exactly: a changed flag, an added flag or another file is not', async () => {
    const variants = [
      (UP.run as string).replace('--env-file /dev/null', ''), (UP.run as string).replace('/dev/null', '.env'), `${UP.run as string} --build`, (UP.run as string).replace('docker-compose.pipegen.yml', 'docker-compose.yml'),
      (UP.run as string).replace(' --wait', ''), (UP.run as string).replace('set -euo pipefail', 'set -e'),
    ];
    for (const v of variants) {
      const r = await run([wf([...prelude(), RT, { ...UP, run: v }])], d0);
      expect(has(r, 'unreviewed') || has(r, 'template'), `${v}\n${show(r)}`).toBe(true);
    }
  });

  it('the compose file and both steps together: the whole set passes the referee', async () => {
    const files = [wf([...prelude(), RT, UP]), cf(goodText(d0))];
    expect(show(await run(files, d0))).toBe('');
  });

  it('a tampered compose file in the referee gives an issue', async () => {
    const files = [cf(goodText(d0).replace('127.0.0.1:5432', '0.0.0.0:5432'))];
    expect((await run(files, d0)).issues.length).toBeGreaterThan(0);
  });
});

describe('referee: the password name in an edited user workflow', () => {
  const dU = { ...d0, profile: { ...d0.profile, existingWorkflows: [{ path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: false, [['secrets', 'Used'].join('')]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow] } };
  const userWf = (extra = ''): string => `name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: echo hi${extra}\n`;
  const inserted = (original: string, steps: RenderedStep[]): CreatedFile => {
    const doc = parseDocument(`${original}  app-start:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    cache-mode: none\n    steps: []\n`);
    doc.setIn(['jobs', 'app-start', 'steps'], stepsToYaml(withEgress(steps)));
    return { path: '.github/workflows/deploy.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 'test', repo: 'app', inserted: { original, jobs: ['app-start'], needs: [] } };
  };
  it('the recognised runtime-env step in an added job passes; the name in an added unrecognised step is an injection; the user\'s own text is not judged', async () => {
    expect(show(await run([inserted(userWf(), [...prelude(), RT, UP])], dU))).toBe('');
    const r = await run([inserted(userWf(), [...prelude(), RT, { name: 'x', run: `echo "$${DBPW}"`, shell: 'bash' }])], dU);
    expect(has(r, 'injection'), show(r)).toBe(true);
    // the user's own step may spell it (pipegen does not judge the user's text); the added job is clean
    expect(has(await run([inserted(userWf(` ${DBPW}`), [...prelude(), RT, UP])], dU), 'injection')).toBe(false);
  });
});

describe('D4 carry C1: the steps are recognised only for a compose file a rule claims', () => {
  it('without a registry row that claims the compose path, the runtime-env step is not recognised (injection)', async () => {
    const createdRules = CREATED_RULES.filter((r) => r.id !== 'compose');
    const files = withCompose([wf([...prelude(), RT, UP])], d0);
    const r = await referee(files, d0, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [], createdRules });
    expect(has(r, 'injection'), show(r)).toBe(true);
    expect(r.issues.some((i) => /no rule claims/.test(i.message)), show(r)).toBe(true);
  });
});
