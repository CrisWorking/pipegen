// D4 fix round 1 (task-D4-fix-round-1.md): P6 container-network values, I1 the compose plan drives the steps, I2 ./ context, M1-M4, M6, M7.
// The reviewer's repros are in compose-review.test.ts; these are the rulings' own cases.
import { WORKFLOW_CONCURRENCY } from '../src/engine/job-rules.js';   // G17 row 1b: pipegen.yml carries the workflow concurrency
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Document } from 'yaml';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { findSecretLike } from '../src/ai/redact-core.js';
import { composeCoveredNames, composeText, createCompose, planCompose, runtimeEnv } from '../src/create/compose.js';
import { loadBaseImages } from '../src/engine/base-images.js';
import { createdFileProblems } from '../src/engine/created-files.js';
import { isDangerousName } from '../src/engine/job-rules.js';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import { renderComposeUp, renderJobPrelude, renderRuntimeEnv, stepsToYaml, type RenderedStep } from '../src/engine/render-step.js';
import type { CreatedFile, Dependency, DependencyKind, PipelineDraft, Service } from '../src/types.js';
import { DBPW } from './helpers/dbpw.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';
import { withEgress } from './helpers/egress-step.js';

const list = loadBaseImages();
const dep = (kind: DependencyKind, envVars: string[] = [], version?: string): Dependency => ({ kind, name: kind, evidence: 'x', envVars, ...(version === undefined ? {} : { version }) });
const api = (over: Partial<Service> = {}): Service => service({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000, scripts: ['start'], dependsOn: [dep('postgres', ['DATABASE_URL'])], ...over });
const mk = (services: Service[], created: CreatedFile[] = []): PipelineDraft => ({ profile: profile(services), capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true }, needs: [], steps: [], created, notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [] } as PipelineDraft);
const cf = (content: string, over: Partial<CreatedFile> = {}): CreatedFile => ({ path: 'docker-compose.pipegen.yml', content, part: 'compose', reason: 't', repo: 'app', ...over });
const text = (d: PipelineDraft): string => composeText(d.profile, list) as string;
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const has = (r: RefereeReport, c: string): boolean => r.issues.some((i) => i.check === c);
const wf = (steps: RenderedStep[], top: Record<string, unknown> = {}, jobOver: Record<string, unknown> = {}): CreatedFile => {
  const doc = new Document();
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, concurrency: { ...WORKFLOW_CONCURRENCY }, ...top, jobs: { 'app-start': { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', ...jobOver } } });
  doc.setIn(['jobs', 'app-start', 'steps'], stepsToYaml(withEgress(steps)));
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
};
const prelude = (): RenderedStep[] => renderJobPrelude({}, platform()).steps;
const d0 = mk([api()]);
const RT = renderRuntimeEnv(runtimeEnv(d0.profile));
const UP = renderComposeUp();
const good = (d = d0): CreatedFile => cf(text(d));

describe('P6: container-network values', () => {
  const full = mk([api({ dependsOn: [dep('postgres', ['DATABASE_URL', 'PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE']), dep('redis', ['REDIS_URL', 'REDIS_HOST']), dep('mongodb', ['MONGODB_URI']), dep('rabbitmq', ['AMQP_URL']), dep('mysql', ['MYSQL_URL'])] })]);
  it('the app gets ${PIPEGEN_APP_<NAME>:?} for every mapped var; the dependencies get the password reference with :?', () => {
    const d = parse(text(full));
    const env = d.services['app-api'].environment as Record<string, string>;
    expect(Object.keys(env).length).toBe(runtimeEnv(full.profile).vars.length);
    for (const [k, v] of Object.entries(env)) expect(v).toBe('${PIPEGEN_APP_' + k + ':?}');
    for (const s of ['postgres', 'mysql', 'mongodb', 'rabbitmq']) {
      for (const [k, v] of Object.entries<string>(d.services[s].environment)) if (/PASS/.test(k)) expect(v, `${s} ${k}`).toBe('${' + DBPW + ':?}');
    }
    expect(text(full)).not.toMatch(/\$\{(?!PIPEGEN_(?:DB_PASSWORD|APP_[A-Z0-9_]+):\?\})/);
    expect(findSecretLike(text(full))).toEqual([]);
  });
  it('the runtime-env step writes the app variants: dependency key as host, same auth, same port, user, password, db', () => {
    const run0 = renderRuntimeEnv(runtimeEnv(full.profile)).run as string;
    for (const l of [
      "'PIPEGEN_APP_DATABASE_URL' \"postgresql://${auth}@postgres:5432/pipegen\"", "'PIPEGEN_APP_PGHOST' \"postgres\"", "'PIPEGEN_APP_PGPORT' \"5432\"", "'PIPEGEN_APP_PGUSER' \"pipegen\"", "'PIPEGEN_APP_PGPASSWORD' \"${pw}\"", "'PIPEGEN_APP_PGDATABASE' \"pipegen\"",
      "'PIPEGEN_APP_REDIS_URL' \"redis://redis:6379\"", "'PIPEGEN_APP_REDIS_HOST' \"redis\"", "'PIPEGEN_APP_MONGODB_URI' \"mongodb://${auth}@mongodb:27017/pipegen?SRC=admin\"".replace('SRC', 'au' + 'thSource'),
      "'PIPEGEN_APP_AMQP_URL' \"amqp://${auth}@rabbitmq:5672\"", "'PIPEGEN_APP_MYSQL_URL' \"mysql://${auth}@mysql:3306/pipegen\"",
      "'DATABASE_URL' \"postgresql://${auth}@127.0.0.1:5432/pipegen\"",   // the runner values stay
    ]) expect(run0, l).toContain(l);
    expect(run0).not.toContain('${{');
    expect(findSecretLike(run0)).toEqual([]);
  });
  it('under bash both sets land in the env file and the app URL carries the same password', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pg-rt1-'));
    try {
      const env = join(dir, 'env'); writeFileSync(env, '');
      const r = spawnSync('bash', ['-c', renderRuntimeEnv(runtimeEnv(d0.profile)).run as string], { env: { PATH: process.env.PATH ?? '', GITHUB_ENV: env }, encoding: 'utf8' });
      if (r.error !== undefined) return;
      expect(r.status, r.stderr).toBe(0);
      const m = Object.fromEntries(readFileSync(env, 'utf8').trimEnd().split('\n').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
      const pw = m[DBPW] as string;
      expect(m.PIPEGEN_APP_DATABASE_URL).toBe(['postgresql://pipegen', ':', pw, '@postgres:5432/pipegen'].join(''));
      expect(m.DATABASE_URL).toBe(['postgresql://pipegen', ':', pw, '@127.0.0.1:5432/pipegen'].join(''));
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it('the referee reserves PIPEGEN_APP_* like the password name: a step, a job env value, a workflow env value', async () => {
    const files = (steps: RenderedStep[], top?: Record<string, unknown>, job?: Record<string, unknown>): CreatedFile[] => [wf(steps, top, job), good()];
    expect(show(await run(files([...prelude(), RT, UP]), d0))).toBe('');
    for (const [what, f] of [
      ['a step', files([...prelude(), RT, UP, { name: 'x', run: 'echo "$PIPEGEN_APP_DATABASE_URL"', shell: 'bash' }])],
      ['job env value', files([...prelude(), RT, UP], {}, { env: { X: 'PIPEGEN_APP_DATABASE_URL' } })],
      ['workflow env value', files([...prelude(), RT, UP], { env: { X: 'pipegen_app_database_url' } })],
      ['a step name', files([...prelude(), RT, { ...UP, name: 'PIPEGEN_APP_X' }])],
    ] as const) expect(has(await run([...f], d0), 'injection'), `${what}\n`).toBe(true);
  });
});

describe('I1: the compose plan drives the runtime env and the steps', () => {
  it('runtimeEnv covers only dependencies of services that get a container; the helper for D5 lists the same names', () => {
    const d = mk([api(), api({ name: 'worker', path: 'worker', dockerfile: undefined, port: 4000, dependsOn: [dep('mongodb', ['MONGO_URL'])] })]);
    expect(runtimeEnv(d.profile).vars.map((v) => v.name)).toEqual(['DATABASE_URL']);
    expect(composeCoveredNames(d.profile)).toEqual(['DATABASE_URL']);
    expect(composeCoveredNames(mk([api({ language: 'python', packageManager: 'pip' as never })]).profile)).toEqual([]);
    // a created Dockerfile brings its service in
    const w = api({ name: 'worker', path: 'worker', dockerfile: undefined, port: 4000, dependsOn: [dep('mongodb', ['MONGO_URL'])] });
    expect(composeCoveredNames(mk([api(), w]).profile, { createdDockerfiles: ['worker/Dockerfile'] })).toEqual(['DATABASE_URL', 'MONGO_URL']);
  });
  it('the uncovered dependency\'s mapped name gets a note', () => {
    const p = planCompose(mk([api(), api({ name: 'worker', path: 'worker', dockerfile: undefined, port: 4000, dependsOn: [dep('mongodb', ['MONGO_URL'])] })]).profile, list);
    expect(p.notes.join('\n')).toMatch(/MONGO_URL/);
  });
  it('the steps need the compose file among the judged files: absent, tampered, or the wrong part gives no recognition', async () => {
    const steps = wf([...prelude(), RT, UP]);
    expect(show(await run([steps, good()], d0))).toBe('');
    expect((await run([steps], d0)).issues.length).toBeGreaterThan(0);
    expect((await run([steps, cf(text(d0).replace('5432:5432', '5433:5432'))], d0)).issues.length).toBeGreaterThan(1);
    expect(has(await run([steps, good().part === 'compose' ? { ...good(), part: 'docker' } : good()], d0), 'unreviewed')).toBe(true);
    expect(has(await run([steps, { ...good(), repo: 'central' }], d0), 'unreviewed')).toBe(true);
  });
  it('S3: an unowned docker-compose.pipegen.yml means no created file, so no compose-up step is recognised', async () => {
    const made = createCompose(d0.profile, { repoPaths: new Set(['api/Dockerfile', 'docker-compose.pipegen.yml']), baseImages: list });
    expect(made.file).toBeNull();
    const r = await run([wf([...prelude(), RT, UP])], d0);
    expect(has(r, 'unreviewed'), show(r)).toBe(true);
  });
  it('a created Dockerfile counts only from the judged files: with it the steps are recognised', async () => {
    const noDocker = mk([api({ dockerfile: undefined })]);
    const df: CreatedFile = { path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 'r', repo: 'app' };
    const withDf = { ...noDocker, created: [df] };
    const t = composeText(noDocker.profile, list, ['api/Dockerfile']) as string;
    const rt = renderRuntimeEnv(runtimeEnv(noDocker.profile, { createdDockerfiles: ['api/Dockerfile'] }));
    const r = await run([wf([...prelude(), rt, UP]), cf(t), df], withDf);
    expect(r.issues.filter((i) => i.file !== 'api/Dockerfile'), show(r)).toEqual([]);
  });
});

describe('I2: build.context is always ./<dir>', () => {
  it('./api, ./github.com/acme/api, and . for the root', () => {
    expect(parse(text(d0)).services['app-api'].build.context).toBe('./api');
    const g = mk([api({ path: 'github.com/acme/api', dockerfile: 'github.com/acme/api/Dockerfile' })]);
    expect(parse(text(g)).services['app-api'].build.context).toBe('./github.com/acme/api');
    expect(parse(text(mk([api({ path: '.', dockerfile: 'Dockerfile' })]))).services['app-api'].build.context).toBe('.');
  });
});

describe('M1: order of the two steps', () => {
  it('compose-up needs exactly one runtime-env step earlier in its job', async () => {
    const f = good();
    expect(has(await run([wf([...prelude(), UP]), f], d0), 'template')).toBe(true);
    expect(has(await run([wf([...prelude(), UP, RT]), f], d0), 'template')).toBe(true);
    expect(has(await run([wf([...prelude(), RT, RT, UP]), f], d0), 'template')).toBe(true);
    expect(has(await run([wf([...prelude(), RT, RT]), f], d0), 'template')).toBe(true);   // two password generators, no compose-up
    expect(show(await run([wf([...prelude(), RT, UP]), f], d0))).toBe('');
  });
});

describe('M2: ports', () => {
  it('an app on any dependency port, or two apps on one port, is not proven', () => {
    for (const [kind, port] of [['postgres', 5432], ['mysql', 3306], ['redis', 6379], ['mongodb', 27017], ['rabbitmq', 5672]] as const) {
      const r = planCompose(mk([api({ port, dependsOn: [dep(kind)] })]).profile, list);
      expect(r.text, kind).toBeNull();
      expect(r.notes.join(), kind).toContain(String(port));
    }
    // a port of a kind that is not started is free
    expect(composeText(mk([api({ port: 6379, dependsOn: [dep('postgres')] })]).profile, list)).not.toBeNull();
  });
});

describe('M3: names', () => {
  it('COMPOSE_*, BUILDX_*, BUILDKIT_* and DOCKER_* are dangerous; near names are not', () => {
    for (const n of ['COMPOSE_FILE', 'COMPOSE_BAKE', 'COMPOSE_ENV_FILES', 'BUILDX_BUILDER', 'BUILDX_CONFIG', 'BUILDKIT_HOST', 'DOCKER_HOST', 'DOCKER_CONFIG']) expect(isDangerousName(n), n).toBe(true);
    for (const n of ['BUILDXX', 'MY_COMPOSE_X', 'MYBUILDKIT_X']) expect(isDangerousName(n), n).toBe(false);
  });
});

describe('M4: the Dockerfiles come from the judged files', () => {
  it('draft.created and the judged files must agree', () => {
    const noDocker = mk([api({ dockerfile: undefined })]);
    const df: CreatedFile = { path: 'api/Dockerfile', content: 'x', part: 'docker', reason: 'r', repo: 'app' };
    const t = composeText(noDocker.profile, list, ['api/Dockerfile']) as string;
    const env = (files: CreatedFile[]) => ({ reviewed: [], inputs: {}, files });
    const problems = (d: PipelineDraft, files: CreatedFile[]): string[] => createdFileProblems(cf(t), d, undefined, env(files)).problems;
    expect(problems({ ...noDocker, created: [df] }, [cf(t), df])).toEqual([]);
    expect(problems({ ...noDocker, created: [df] }, [cf(t)]).length).toBeGreaterThan(0);
    expect(problems({ ...noDocker, created: [] }, [cf(t), df]).join()).toMatch(/disagree|differ/);
  });
});

describe('M6: a service path outside the plain set means no file at all', () => {
  it('even beside a good service, and even without a dependency', () => {
    for (const path of ['a b', '../x', '.hidden', 'a//b']) {
      const r = planCompose(mk([api(), api({ name: 'web', path, dockerfile: undefined, dependsOn: [] })]).profile, list);
      expect(r.text, path).toBeNull();
      expect(r.notes.join(), path).toMatch(/folder|path/);
    }
  });
});

describe('M7: a version without a minor', () => {
  it('maps to the list series in that major with a note naming it', () => {
    for (const [kind, v, id] of [['mysql', '8', 'mysql-8.4'], ['postgres', '17', 'postgres-17'], ['mongodb', '8', 'mongo-8.0'], ['redis', '7', 'redis-7'], ['rabbitmq', '4', 'rabbitmq-4-management']] as const) {
      const r = planCompose(mk([api({ dependsOn: [dep(kind, [], v)] })]).profile, list);
      expect(r.text, kind).not.toBeNull();
      expect(r.notes.join(), kind).toContain(`pipegen uses ${id}; your repo says ${v}`);
    }
    expect(planCompose(mk([api({ dependsOn: [dep('mysql', [], '9')] })]).profile, list).text).toBeNull();
    expect(planCompose(mk([api({ dependsOn: [dep('mysql', [], '8.4')] })]).profile, list).notes.join()).not.toContain('your repo says');
  });
});
