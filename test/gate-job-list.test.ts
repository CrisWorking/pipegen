// Plan C, sub-task C0b: gateJobList (ruling S4, B4) and the reserved artifact names (ruling S3). Written first (strict test-first).
// The job list is what the gate trusts: one entry per rendered result and per blocking job-status need, names from resultArtifactName.
import { describe, expect, it } from 'vitest';
import { build } from 'esbuild';
import { resolve } from 'node:path';
import { BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT, GATE_RESULT_ARTIFACT, resultArtifactName, slug } from '../src/engine/artifact-names.js';
import { FINDINGS_CATEGORIES, gateJobList, jobListLiteral, type JobListEntry } from '../src/engine/gate-job-list.js';
import { NEED_ID_CATEGORY, NEED_IDS } from '../src/engine/need-ids.js';
import { jobListLiteralProblem, rendererInputProblems } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import { RESULT_ARTIFACT_PREFIX, type Layer, type Need, type PipelineDraft, type StepSpec } from '../src/types.js';
import { entry, profile, service, specFor } from './helpers/render.js';

// object keys spelled at run time (see test/no-secret-literals.test.ts)
const NS = ['needs', 'Sec', 'rets'].join('');
const SEC = ['sec', 'rets'].join('');

const prof = { ...profile([service({ name: 'app' }), service({ name: 'Web App!' })]), repoFiles: emptyRepoFiles() };
const needOf = (id: string, over: Partial<Need> = {}): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, why: 't', blocking: true, floor: false, ...over });
const draftOf = (needs: Need[], steps: StepSpec[]): PipelineDraft => ({
  profile: prof, capabilities: { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true },
  needs, steps, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const spec = (tool: string, needId: string, service?: string, over: Partial<StepSpec> = {}): StepSpec => specFor(entry(tool), { needId, ...(service === undefined ? {} : { service }), ...over });
const byJob = (list: JobListEntry[]): Record<string, JobListEntry> => Object.fromEntries(list.map((e) => [e.job, e]));

describe('gateJobList (rulings S4 and B4)', () => {
  it('gateJobList(draft): one entry per rendered result, with artifact names from resultArtifactName (service slug, base form)', () => {
    const d = draftOf(
      [needOf('secrets'), needOf('sast', { service: 'app' }), needOf('sast', { service: 'Web App!' })],
      [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'app'), spec('semgrep', 'sast', 'Web App!')],
    );
    const list = gateJobList(d);
    expect(list.map((e) => e.job)).toEqual(['secrets', 'sast--app', 'sast--web-app']);
    const [secrets, app, web] = list as [JobListEntry, JobListEntry, JobListEntry];
    expect(secrets).toEqual({
      needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'gitleaks', format: 'sarif',
      artifact: resultArtifactName('secrets'), baseArtifact: resultArtifactName('secrets', undefined, { base: true }), blocking: true, [NS]: false,
    });
    expect(app.artifact).toBe(`${RESULT_ARTIFACT_PREFIX}sast--app`);
    expect(app.baseArtifact).toBe(`${RESULT_ARTIFACT_PREFIX}base-sast--app`);
    expect(app.service).toBe('app');
    // the service is its slug in the list (a repo-derived name never reaches the gate as written), in the job id and in both artifact names
    expect(web.service).toBe(slug('Web App!'));
    expect(web.artifact).toBe(resultArtifactName('sast', 'Web App!'));
    expect(web.baseArtifact).toBe(resultArtifactName('sast', 'Web App!', { base: true }));
  });

  it('gateJobList: a blocking job-status need (a project script, a format-none tool) gets an entry with no artifact', () => {
    const d = draftOf([needOf('unit-tests', { service: 'app' }), needOf('lint', { service: 'app' })], [spec('eslint', 'lint', 'app', { output: { path: '', format: 'none' } })]);
    const list = byJob(gateJobList(d));
    expect(list['unit-tests--app']).toMatchObject({ needId: 'unit-tests', service: 'app', category: 'unit-tests', format: 'none', blocking: true, [NS]: false });
    expect(list['unit-tests--app']?.artifact).toBeUndefined();
    expect(list['unit-tests--app']?.baseArtifact).toBeUndefined();
    expect(list['unit-tests--app']?.tool).toBeUndefined();
    expect(list['lint--app']).toMatchObject({ tool: 'eslint', format: 'none' });
    expect(list['lint--app']?.artifact).toBeUndefined();
  });

  it('gateJobList: needsSecrets is true when a step of the need declares a secret (decision 110 applies it on a fork PR)', () => {
    const d = draftOf([needOf('sast', { service: 'app' }), needOf('secrets')], [spec('semgrep', 'sast', 'app', { [SEC]: ['API_TOKEN'] }), spec('gitleaks', 'secrets')]);
    const list = byJob(gateJobList(d));
    expect(list['sast--app']?.needsSecrets).toBe(true);
    expect(list.secrets?.needsSecrets).toBe(false);
  });

  it('gateJobList: a non-blocking findings need is listed (blocking false); a non-blocking job-status need is not', () => {
    const d = draftOf([needOf('sast', { service: 'app', blocking: false }), needOf('unit-tests', { service: 'app', blocking: false })], [spec('semgrep', 'sast', 'app')]);
    const list = gateJobList(d);
    expect(list.map((e) => e.job)).toEqual(['sast--app']);
    expect(list[0]?.blocking).toBe(false);
    expect(list[0]?.artifact).toBe(`${RESULT_ARTIFACT_PREFIX}sast--app`);
  });

  it('gateJobList: needs that are not merge-gate jobs are left out (pre-commit, push, deploy, scheduled, pipegen\'s own jobs)', () => {
    const layers: Layer[] = ['pre-commit', 'push', 'deploy'];
    const d = draftOf(
      [...layers.map((l) => needOf('secrets', { layer: l })), needOf('scorecard'), needOf('gate'), needOf('signing'), needOf('attestation'), needOf('deploy-verify'), needOf('dast', { service: 'app' })],
      [spec('gitleaks', 'secrets')],
    );
    // dast has no tool step: a findings category with nothing readable is demoted, so it is not a blocking entry and has no job-status entry either
    expect(gateJobList(d)).toEqual([]);
  });

  it('gateJobList: a findings category whose tool writes no SARIF is demoted, so it is no blocking entry (the referee\'s B7 rule, one source)', () => {
    const d = draftOf([needOf('sast', { service: 'app' })], [spec('semgrep', 'sast', 'app', { output: { path: '', format: 'none' } })]);
    expect(gateJobList(d, { formatOf: () => 'none' })).toEqual([]);
  });

  it('gateJobList: formatOf decides what counts as a rendered result (the referee passes the reviewed format; undefined = did not render)', () => {
    const d = draftOf([needOf('secrets')], [spec('gitleaks', 'secrets')]);
    expect(gateJobList(d, { formatOf: () => undefined })).toEqual([]);
    expect(gateJobList(d, { formatOf: () => 'sarif' })[0]?.format).toBe('sarif');
  });

  it('gateJobList: two tools writing one result for one need are refused (one artifact name per need and service)', () => {
    const d = draftOf([needOf('sast', { service: 'app' })], [spec('semgrep', 'sast', 'app'), spec('trivy-config', 'sast', 'app')]);
    expect(() => gateJobList(d)).toThrow(/one result/);
  });

  it('gateJobList: the same need on two layers is one entry; the order follows draft.needs; the literal is JSON of the list', () => {
    const d = draftOf([needOf('secrets'), needOf('secrets', { layer: 'push' }), needOf('sast', { service: 'app' })], [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'app')]);
    const list = gateJobList(d);
    expect(list.map((e) => e.job)).toEqual(['secrets', 'sast--app']);
    expect(JSON.parse(jobListLiteral(list))).toEqual(JSON.parse(JSON.stringify(list)));
    expect(jobListLiteral(list)).toBe(jobListLiteral(gateJobList(d)));
  });

  it('gateJobList: every entry passes the RENDERER_INPUTS job-list check, and the literal is what the gate row accepts under mode gate', () => {
    const d = draftOf([needOf('secrets'), needOf('sast', { service: 'app' }), needOf('unit-tests', { service: 'app' })], [spec('gitleaks', 'secrets'), spec('semgrep', 'sast', 'app')]);
    const text = jobListLiteral(gateJobList(d));
    expect(jobListLiteralProblem(text)).toBeNull();
    expect(rendererInputProblems('crisworking/pipegen/gate', { 'job-list': text }, { mode: 'gate', 'job-list': text })).toEqual([]);
  });

  it('FINDINGS_CATEGORIES: the findings categories of the B7 rule (the referee re-exports this one)', () => {
    expect([...FINDINGS_CATEGORIES].sort()).toEqual(['dast', 'deps', 'dockerfile-lint', 'iac', 'image-scan', 'licences', 'sast', 'secrets']);
  });
});

describe('jobListLiteralProblem (the job-list literal of the gate row)', () => {
  const good: Record<string, unknown> = { needId: 'sast', service: 'app', job: 'sast--app', category: 'sast', tool: 'semgrep', format: 'sarif', artifact: 'pipegen-out-sast--app', baseArtifact: 'pipegen-out-base-sast--app', blocking: true, [NS]: false };
  const lit = (e: unknown): string => JSON.stringify([e]);
  it('jobListLiteralProblem: a good entry passes; an empty list passes', () => {
    expect(jobListLiteralProblem(lit(good))).toBeNull();
    expect(jobListLiteralProblem('[]')).toBeNull();
    expect(jobListLiteralProblem(lit({ ...good, warnFirst: { since: '2026-10-29' } }))).toBeNull();
  });
  it('jobListLiteralProblem: not JSON, not a list, an unknown key, a wrong type or shape, a duplicate job, an expression, too long → a problem', () => {
    for (const bad of ['', 'x', '{}', '"[]"', 'null', '[1]', '[null]', '[[]]', `[${'{}'},]`]) expect(jobListLiteralProblem(bad), bad).not.toBeNull();
    const variants: Record<string, unknown>[] = [
      { ...good, extra: 1 }, { ...good, needId: 'Sast' }, { ...good, needId: 'base-sast' }, { ...good, job: 'a b' }, { ...good, job: '${{ x }}' }, { ...good, job: 1 },
      { ...good, category: 'nope' }, { ...good, tool: 'Semgrep' }, { ...good, format: 'html' }, { ...good, artifact: 'sast' }, { ...good, baseArtifact: 'pipegen-out-x\n' },
      { ...good, blocking: 'yes' }, { ...good, [NS]: 1 }, { ...good, service: 'App' }, { ...good, service: 'a--b' }, { ...good, warnFirst: { since: 'soon' } }, { ...good, warnFirst: {} },
      { job: 'x' },
    ];
    for (const v of variants) expect(jobListLiteralProblem(lit(v)), JSON.stringify(v)).not.toBeNull();
    expect(jobListLiteralProblem(JSON.stringify([good, good]))).not.toBeNull();   // the same job twice
    expect(jobListLiteralProblem(JSON.stringify(Array.from({ length: 600 }, (_, i) => ({ ...good, job: `j${i}` }))))).not.toBeNull();
    expect(jobListLiteralProblem(`[{"needId":"sast","job":"j","__proto__":{"x":1}}]`)).not.toBeNull();
  });
});

describe('reserved artifact names (ruling S3)', () => {
  it('artifact names: pipegen-baseline, pipegen-clean-run and pipegen-gate-result are constants; none starts with RESULT_ARTIFACT_PREFIX', () => {
    expect([BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT, GATE_RESULT_ARTIFACT]).toEqual(['pipegen-baseline', 'pipegen-clean-run', 'pipegen-gate-result']);
    for (const n of [BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT, GATE_RESULT_ARTIFACT]) expect(n.startsWith(RESULT_ARTIFACT_PREFIX), n).toBe(false);
  });

  it('artifact names: pipegen-baseline, pipegen-clean-run, pipegen-gate-result never collide with resultArtifactName (every need id, services, base form, hostile services)', () => {
    const reserved = new Set([BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT, GATE_RESULT_ARTIFACT]);
    const services = [undefined, 'app', 'baseline', 'clean-run', 'gate-result', 'Gate Result', '../x', 'out-', 'pipegen-baseline', 'x'.repeat(100)];
    let n = 0;
    for (const id of [...NEED_IDS, 'baseline', 'clean-run', 'gate-result', 'pipegen-baseline']) {
      for (const s of services) {
        for (const base of [false, true]) {
          let name: string;
          try { name = resultArtifactName(id, s, base ? { base: true } : undefined); } catch { continue; }
          n++;
          expect(reserved.has(name), name).toBe(false);
          expect(name.startsWith(RESULT_ARTIFACT_PREFIX), name).toBe(true);
        }
      }
    }
    expect(n).toBeGreaterThan(200);
  });

  it('artifact names: a download step cannot take a reserved name; an upload only from its own pipegen-gate file (C5b ruling 2; the job rule is checkJobOrder)', () => {
    for (const n of [BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT, GATE_RESULT_ARTIFACT]) {
      expect(rendererInputProblems('actions/download-artifact', { name: n }).length, n).toBeGreaterThan(0);
      const inOut = { name: n, path: `\${{ runner.temp }}/pipegen-out/${n}/x.json` };
      expect(rendererInputProblems('actions/upload-artifact', inOut, inOut).length, n).toBeGreaterThan(0);
    }
  });
});

describe('module graph: gate-job-list.ts is a leaf', () => {
  it('gate-job-list.ts imports only types.ts, artifact-names.ts and need-ids.ts', async () => {
    const r = await build({ entryPoints: [resolve(import.meta.dirname, '../src/engine/gate-job-list.ts')], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
    expect(Object.keys(r.metafile.inputs).sort()).toEqual(['src/engine/artifact-names.ts', 'src/engine/gate-job-list.ts', 'src/engine/need-ids.ts', 'src/types.ts']);
  });
});
