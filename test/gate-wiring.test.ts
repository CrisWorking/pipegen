// Plan C, sub-task C0b: the gate job and its links to the scanner jobs, in Plan B's engine (rulings B3, B4, S3, S4, S16, S21)
// plus the scrub cross-checks C0a left to this task. Written first (strict test-first).
import { createHash } from 'node:crypto';
import { NO_SCANS } from '../src/engine/job-rules.js';
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { gateJobList, jobListLiteral, type JobListEntry } from '../src/engine/gate-job-list.js';
import { checkJobOrder, jobOutputsFor, jobOutputsProblems, type ScanFact } from '../src/engine/job-rules.js';
import { JOB_STEP_POLICY, referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  dedupeJobSteps, RenderError, renderGateStep, renderJobPrelude, renderPlatformStep, renderProjectScript, renderScrub, renderStep, renderUpload, scanFactOf, scrubbedPath, stepsToYaml,
  type RenderContext, type RenderedStep, type RenderResult,
} from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { BASE_CHECKOUT_REF, GATE_MODES, rendererInputProblems, scrubStepId } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, ReviewedTool, StepSpec } from '../src/types.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { renderStage as renderStageC1c } from '../src/engine/render-step.js';
import { isStagedTool } from '../src/engine/tool-flags.js';

// object keys spelled at run time (see test/no-secret-literals.test.ts)
const NS = ['needs', 'Sec', 'rets'].join('');
const SEC = ['sec', 'rets'].join('');
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');

// ---------- builders ----------

/** `${{ secrets.NAME }}`, built at run time (test/no-secret-literals.test.ts). */
const sref = (n: string): string => ['${{', `secrets.${n}`, '}}'].join(' ');
const GATE_USES = 'crisworking/pipegen/gate';
const sha16 = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const p = platform();
const GATE = gateEntry();
const app = service({ name: 'app', path: '.', scripts: ['test', 'lint'] });
const web = service({ name: 'web', path: 'web', scripts: ['test'] });
const prof = { ...profile([app, web]), repoFiles: { ...emptyRepoFiles(), kubernetes: true } };
const ctx: RenderContext = { profile: prof, targets: { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080', k8sDir: 'k8s' } };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const needOf = (id: string, svcName?: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svcName === undefined ? {} : { service: svcName }), why: 't', blocking: true, floor: false });
const draftOf = (specs: StepSpec[], needs: Need[]): PipelineDraft => ({
  profile: prof, capabilities: caps, needs, steps: specs, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const LINTERS: Linters = { actionlint: async () => '/stub/actionlint', zizmor: async () => '/stub/zizmor' };
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, [...reviewedList(), GATE], LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const has = (r: RefereeReport, check: string, re?: RegExp): boolean => r.issues.some((i) => i.check === check && (re === undefined || re.test(i.message)));

type Job = Record<string, unknown>;
const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });
/** `raw`: steps written as plain YAML, for hostile steps the emitter itself refuses (the referee must refuse them too). */
function workflow(jobs: Record<string, Job>, raw = false): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) {
    const steps = j.steps as RenderedStep[];
    doc.setIn(['jobs', id, 'steps'], raw ? doc.createNode(steps.map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(steps));
  }
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
const prelude = (over: Parameters<typeof renderJobPrelude>[0] = {}): RenderedStep[] => renderJobPrelude(over, p).steps;

interface Block { steps: RenderedStep[]; scrub: RenderedStep; upload: RenderedStep; artifact: string; scan: { stepId: string; fact: ScanFact }; result: RenderResult }
/** The tool steps, the scrub and the upload of one spec (no prelude): what Plan G puts after the checkout. */
function block(spec: StepSpec, c: RenderContext = ctx): Block {
  const t = entry(spec.tool.id);
  const result = renderStep(spec, t, p, c);
  const out = result.output;
  if (out === null || (out.format !== 'sarif' && out.format !== 'zap-json')) throw new Error('not a findings tool');
  const artifact = resultArtifactName(spec.needId, spec.service, c.base === true ? { base: true } : undefined);
  const scrub = renderScrub(artifact, out.path, t.id, out.format, GATE);
  const upload = renderUpload(artifact, scrubbedPath(out.path), p);
  const scan = scanFactOf(result, t.id);
  if (scan === null) throw new Error('no scan fact');
  const stage = isStagedTool(t.id) ? [renderStageC1c(artifact, t.id, GATE)] : [];   // C1c: a secrets scan reads the stage folder its stage step filled
  return { steps: [...stage, ...result.steps, scrub, upload], scrub, upload, artifact, scan, result };
}
const gitleaksSpec = (): StepSpec => specFor(entry('gitleaks'), { needId: 'secrets' });
const semgrepSpec = (svc: string): StepSpec => specFor(entry('semgrep'), { needId: 'sast', service: svc });
const facts = (...bs: Block[]): ReadonlyMap<string, ScanFact> => new Map(bs.map((b) => [b.scan.stepId, b.scan.fact]));
const scrubOf = (steps: RenderedStep[]): RenderedStep => steps.find((s) => s.id?.startsWith('scrub-')) as RenderedStep;
const withScrub = (steps: RenderedStep[], f: (s: RenderedStep) => RenderedStep): RenderedStep[] => steps.map((s) => (s.id?.startsWith('scrub-') ? f(s) : s));

// ---------- jobOutputsProblems (ruling B3) ----------

describe('jobOutputsProblems (ruling B3)', () => {
  const g = block(gitleaksSpec());
  const steps = [...prelude(), ...g.steps];
  const id = scrubStepId(g.artifact);
  const ok = (): Record<string, string> => ({
    [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.sha256 }}`, [`${g.artifact}-status`]: `\${{ steps.${id}.outputs.status }}`, [`${g.artifact}-error`]: `\${{ steps.${id}.outputs.error }}`,
  });

  it('scrubStepId: scrub-<sha16(artifact)>, the id renderScrub gives', () => {
    expect(scrubStepId(g.artifact)).toBe(`scrub-${sha16(g.artifact)}`);
    expect(g.scrub.id).toBe(scrubStepId(g.artifact));
  });

  it('jobOutputsProblems: only <artifact>-sha256/-status/-error = ${{ steps.<scrub id of that artifact in this job>.outputs.<same> }}', () => {
    expect(jobOutputsProblems('secrets', ok(), steps)).toEqual([]);
    expect(jobOutputsProblems('secrets', undefined, steps)).toEqual([]);
    expect(jobOutputsProblems('secrets', {}, steps)).toEqual([]);
    expect(jobOutputsProblems('secrets', { [`${g.artifact}-status`]: ok()[`${g.artifact}-status`] as string }, steps)).toEqual([]);
    expect(jobOutputsFor(steps)).toEqual(ok());
  });

  it('jobOutputsProblems: any other key, value, step id or output name is a problem (each case on its own)', () => {
    const bad = (o: Record<string, unknown>, re: RegExp): void => {
      const problems = jobOutputsProblems('secrets', o, steps);
      expect(problems.length, JSON.stringify(o)).toBeGreaterThan(0);
      expect(problems.join('\n'), JSON.stringify(o)).toMatch(re);
    };
    bad({ 'has-pr': '${{ steps.x.outputs.y }}' }, /not one of/);
    bad({ digest: 'abc' }, /not one of/);
    bad({ [`${g.artifact}-sha256`]: 'literal' }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.status }}` }, /must be exactly/);                    // the wrong output name
    bad({ [`${g.artifact}-status`]: `\${{ steps.${id}.outputs.sha256 }}` }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: `\${{ steps.scrub-0123456789abcdef.outputs.sha256 }}` }, /must be exactly/);    // another step
    bad({ [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.sha256 }} ` }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: `\${{steps.${id}.outputs.sha256}}` }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: `x\${{ steps.${id}.outputs.sha256 }}` }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.sha256 }}\${{ secrets.GITHUB_TOKEN }}` }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: 1 }, /must be exactly/);
    bad({ [`${g.artifact}-sha256`]: null }, /must be exactly/);
    bad({ 'pipegen-out-other-sha256': `\${{ steps.${scrubStepId('pipegen-out-other')}.outputs.sha256 }}` }, /no scrub step/);   // an artifact with no scrub in this job
    bad({ [`${g.artifact}-sha256x`]: 'a' }, /not one of/);
    bad({ [`${g.artifact}-`]: 'a' }, /not one of/);
    bad({ '-sha256': 'a' }, /not one of/);
    bad({ [`${g.artifact}-sha256 `]: `\${{ steps.${id}.outputs.sha256 }}` }, /not one of/);
    for (const o of ['text', 5, true, ['a'], null]) {
      expect(jobOutputsProblems('secrets', o, steps).join('\n'), String(o)).toMatch(/map/);
    }
  });

  it('jobOutputsProblems: the scrub of the artifact must be in this job (a scrub in another job does not count) and be a scrub step', () => {
    const noScrub = steps.filter((s) => !s.id?.startsWith('scrub-'));
    expect(jobOutputsProblems('secrets', ok(), noScrub).join('\n')).toMatch(/no scrub step/);
    // a step with the scrub id that is not a scrub step (a run step)
    const fake = noScrub.concat({ id, name: 'x', run: 'true' });
    expect(jobOutputsProblems('secrets', ok(), fake).join('\n')).toMatch(/no scrub step/);
  });

  it('referee: job outputs in another form → injection; the allowed form → no issue', async () => {
    const spec = gitleaksSpec();
    const d = draftOf([spec], [needOf('secrets')]);
    const good = await run([workflow({ [SEC]: job(dedupeJobSteps([...prelude(), ...g.steps], { scans: facts(g) }), { outputs: ok() }) })], d);
    expect(show(good)).toBe('');
    for (const outputs of [
      { ...ok(), 'has-pr': '${{ github.event.pull_request.number }}' },
      { [`${g.artifact}-sha256`]: '${{ secrets.GITHUB_TOKEN }}' },
      { [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.status }}` },
      { digest: 'x' },
    ]) {
      const r = await run([workflow({ [SEC]: job(dedupeJobSteps([...prelude(), ...g.steps], { scans: facts(g) }), { outputs }) })], d);
      expect(has(r, 'injection'), JSON.stringify(outputs) + show(r)).toBe(true);
    }
  });
});

// ---------- RENDERER_INPUTS: the gate row per mode (ruling B3) ----------

describe('RENDERER_INPUTS: the gate action, per mode (ruling B3)', () => {
  const U = GATE_USES;
  const GH = sref('GITHUB_TOKEN');
  const list = jobListLiteral(gateJobList(draftOf([gitleaksSpec()], [needOf('secrets')])));
  const gateWith: Record<string, string> = {
    mode: 'gate', jobs: '${{ toJSON(needs) }}', 'job-list': list, 'not-proven': '["lint"]', skipped: '[]', policy: '{"block":["critical","high"],"warn":["medium"]}',
    'protected-paths': '[".github/workflows/**","docs/*.md"]', 'block-from-recorded': '2026-11-01', 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', [GH_IN]: GH, [FP_IN]: sref('PIPEGEN_FP_KEY'),
  };
  const findRunWith: Record<string, string> = { mode: 'find-run', layout: 'central', sha: '${{ github.sha }}', 'central-workflow': 'acme/pipelines/.github/workflows/acme--merge.yml', 'central-sha': 'a'.repeat(40), 'timeout-minutes': '30', [GH_IN]: GH };
  const nightlyWith: Record<string, string> = { mode: 'nightly', [GH_IN]: GH, 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', 'block-from-recorded': '2026-11-01', 'merged-at': '2026-10-29T12:00:00Z' };
  const problems = (w: Record<string, string>): string[] => rendererInputProblems(U, w, w);
  const SCRUB_SAMPLE_FOR_BASELINE: Record<string, string> = { artifact: 'pipegen-out-secrets', tool: 'gitleaks', format: 'sarif', raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-secrets/x.sarif', out: '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/x.sarif' };

  it('RENDERER_INPUTS gate, mode gate: the exact inputs pass', () => {
    expect(problems(gateWith)).toEqual([]);
  });

  it('RENDERER_INPUTS gate, mode gate: jobs only ${{ toJSON(needs) }}', () => {
    for (const bad of ['${{ toJSON(needs) }} ', '${{toJSON(needs)}}', '${{ toJSON(github) }}', '${{ toJSON(needs) }}${{ x }}', 'toJSON(needs)', '', '${{ toJSON(needs.a) }}', '${{ toJSON(secrets) }}', '{}']) {
      expect(problems({ ...gateWith, jobs: bad }).length, JSON.stringify(bad)).toBeGreaterThan(0);
    }
  });

  it('RENDERER_INPUTS gate, mode gate: block-from only ${{ vars.PIPEGEN_BLOCK_FROM }}, github-token only ${{ secrets.GITHUB_TOKEN }}, fp-key only the key', () => {
    for (const bad of ['2026-01-01', '${{ vars.OTHER }}', '${{ vars.PIPEGEN_BLOCK_FROM }} ', '${{ secrets.PIPEGEN_FP_KEY }}']) expect(problems({ ...gateWith, 'block-from': bad }).length, bad).toBeGreaterThan(0);
    for (const bad of [sref('PIPEGEN_FP_KEY'), sref('OTHER'), `${GH} `, 'ghp_x', '${{ github.token }}']) expect(problems({ ...gateWith, [GH_IN]: bad }).length, bad).toBeGreaterThan(0);
    for (const bad of [GH, sref('OTHER'), `${sref('PIPEGEN_FP_KEY')} `, 'k']) expect(problems({ ...gateWith, [FP_IN]: bad }).length, bad).toBeGreaterThan(0);
  });

  it('RENDERER_INPUTS gate, mode gate: job-list a literal that parses (the job-list schema), the other literals by their schemas', () => {
    for (const bad of ['', 'x', '{}', '[1]', '[{"job":"x"}]', '${{ toJSON(needs) }}', `${list}${'x'}`]) expect(problems({ ...gateWith, 'job-list': bad }).length, bad).toBeGreaterThan(0);
    for (const bad of ['lint', '["Lint"]', '["a b"]', '[1]', '${{ x }}', '["${{ x }}"]']) {
      expect(problems({ ...gateWith, 'not-proven': bad }).length, `not-proven ${bad}`).toBeGreaterThan(0);
      expect(problems({ ...gateWith, skipped: bad }).length, `skipped ${bad}`).toBeGreaterThan(0);
    }
    for (const bad of ['', '{}', '{"block":["urgent"],"warn":[]}', '{"block":[],"warn":[],"x":1}', '{"block":"critical","warn":[]}', 'strict']) expect(problems({ ...gateWith, policy: bad }).length, `policy ${bad}`).toBeGreaterThan(0);
    for (const bad of ['', '[".."]', '["../x"]', '["/etc"]', '[".github/../x"]', '["${{ x }}"]', '["a\\nb"]', 'x', '[1]', '["a b"]']) expect(problems({ ...gateWith, 'protected-paths': bad }).length, `protected-paths ${bad}`).toBeGreaterThan(0);
    for (const bad of ['', 'tomorrow', '2026-13-01x', '2026-11-01T00:00:00Z', '${{ vars.X }}']) expect(problems({ ...gateWith, 'block-from-recorded': bad }).length, `block-from-recorded ${bad}`).toBeGreaterThan(0);
  });

  it('RENDERER_INPUTS gate, mode find-run: sha only ${{ github.sha }} or ${{ github.event.workflow_run.head_sha }}; central-workflow and central-sha literals; github-token', () => {
    expect(problems(findRunWith)).toEqual([]);
    expect(problems({ ...findRunWith, sha: '${{ github.event.workflow_run.head_sha }}' })).toEqual([]);
    for (const bad of ['${{ github.head_ref }}', '${{ github.event.pull_request.head.sha }}', 'a'.repeat(40), '${{ github.sha }} ', '${{ github.event.workflow_run.head_branch }}', '']) {
      expect(problems({ ...findRunWith, sha: bad }).length, bad).toBeGreaterThan(0);
    }
    for (const bad of ['', '../x', '/abs', 'a b', '${{ x }}', 'a\nb']) expect(problems({ ...findRunWith, 'central-workflow': bad }).length, bad).toBeGreaterThan(0);
    for (const bad of ['', 'main', 'A'.repeat(40), 'a'.repeat(39), '${{ github.sha }}']) expect(problems({ ...findRunWith, 'central-sha': bad }).length, bad).toBeGreaterThan(0);
  });

  it('RENDERER_INPUTS gate, mode nightly: github-token, block-from, block-from-recorded, merged-at', () => {
    expect(problems(nightlyWith)).toEqual([]);
    for (const bad of ['', 'now', '2026-10-29T12:00:00', '${{ github.event.head_commit.timestamp }}', '2026-10-29 12:00']) expect(problems({ ...nightlyWith, 'merged-at': bad }).length, bad).toBeGreaterThan(0);
  });

  // C3: the gate action's mode for the job baseline-check
  const baselineWith: Record<string, string> = { mode: 'baseline-check', [GH_IN]: GH, [FP_IN]: sref('PIPEGEN_FP_KEY') };
  it('RENDERER_INPUTS gate, mode baseline-check: github-token and fp-key, each only the exact expression', () => {
    expect(problems(baselineWith)).toEqual([]);
    expect(problems({ mode: 'baseline-check' })).toEqual([]);   // the referee decides which inputs are needed; the row decides which are allowed
    for (const bad of [sref('PIPEGEN_FP_KEY'), sref('OTHER'), `${GH} `, 'ghp_x', '${{ github.token }}', '']) expect(problems({ ...baselineWith, [GH_IN]: bad }).length, bad).toBeGreaterThan(0);
    for (const bad of [GH, sref('OTHER'), `${sref('PIPEGEN_FP_KEY')} `, 'k', '']) expect(problems({ ...baselineWith, [FP_IN]: bad }).length, bad).toBeGreaterThan(0);
  });
  it('RENDERER_INPUTS gate, mode baseline-check: no gate, find-run or nightly input is allowed under it (whenWith)', () => {
    const others: Record<string, string> = {
      jobs: '${{ toJSON(needs) }}', 'job-list': list, 'not-proven': '[]', skipped: '[]', policy: '{"block":["critical","high"],"warn":["medium"]}', 'protected-paths': '[".github/workflows/**"]',
      'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}', 'block-from-recorded': '2026-11-01', layout: 'central', sha: '${{ github.sha }}', 'central-workflow': 'acme/pipelines/.github/workflows/acme--merge.yml', 'central-sha': 'a'.repeat(40), 'timeout-minutes': '30',
      'merged-at': '2026-10-29T12:00:00Z', ...SCRUB_SAMPLE_FOR_BASELINE,
    };
    for (const [input, value] of Object.entries(others)) {
      const pr = problems({ ...baselineWith, [input]: value });
      expect(pr.some((x) => x.includes(`input ${input} `) && /allowed only in mode/.test(x)), `${input}: ${pr.join(' | ')}`).toBe(true);
    }
  });
  it('RENDERER_INPUTS gate: baseline-check is one of the modes, and the other modes still refuse its sole inputs where they did', () => {
    expect(problems({ ...gateWith, mode: 'baseline-check' }).length).toBeGreaterThan(0);   // gate inputs under baseline-check
    expect(problems({ ...findRunWith, [FP_IN]: sref('PIPEGEN_FP_KEY') }).some((x) => /fp-key/.test(x))).toBe(true);   // fp-key still not under find-run
    expect(problems({ ...nightlyWith, [FP_IN]: sref('PIPEGEN_FP_KEY') }).some((x) => /fp-key/.test(x))).toBe(true);   // nor under nightly
    expect(GATE_MODES).toContain('baseline-check');
  });

  const SCRUB_SAMPLE: Record<string, string> = {
    artifact: 'pipegen-out-secrets', tool: 'gitleaks', format: 'sarif',
    raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-secrets/x.sarif', out: '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/x.sarif',
  };
  it('a mode\'s inputs are refused under another mode (whenWith on mode)', () => {
    const own: Record<string, string[]> = {
      gate: ['jobs', 'job-list', 'not-proven', 'skipped', 'policy', 'protected-paths'],
      'find-run': ['layout', 'sha', 'central-workflow', 'central-sha', 'timeout-minutes'],
      nightly: ['merged-at'],
      scrub: ['artifact', 'tool', 'format', 'raw', 'out'],
    };
    const all: Record<string, Record<string, string>> = { gate: gateWith, 'find-run': findRunWith, nightly: nightlyWith };
    for (const [mode, inputs] of Object.entries(own)) {
      for (const input of inputs) {
        for (const other of ['gate', 'find-run', 'nightly']) {
          if (other === mode) continue;
          const value = SCRUB_SAMPLE[input] ?? (all[mode] ?? gateWith)[input] ?? 'x';
          const w = { ...(all[other] as Record<string, string>), [input]: value };
          const pr = problems(w);
          expect(pr.some((x) => x.includes(`input ${input} `) && /allowed only in mode/.test(x)), `${input} under ${other}: ${pr.join(' | ')}`).toBe(true);
        }
      }
    }
    // block-from and block-from-recorded: gate and nightly, not find-run; fp-key: scrub and gate, not nightly or find-run; the workflow credential is never a scrub input
    expect(problems({ ...findRunWith, 'block-from': '${{ vars.PIPEGEN_BLOCK_FROM }}' }).some((x) => /block-from/.test(x))).toBe(true);
    expect(problems({ ...findRunWith, 'block-from-recorded': '2026-11-01' }).some((x) => /block-from-recorded/.test(x))).toBe(true);
    expect(problems({ ...nightlyWith, [FP_IN]: sref('PIPEGEN_FP_KEY') }).some((x) => /fp-key/.test(x))).toBe(true);
    expect(problems({ ...findRunWith, [FP_IN]: sref('PIPEGEN_FP_KEY') }).some((x) => /fp-key/.test(x))).toBe(true);
    const scrubW = { mode: 'scrub', [GH_IN]: GH };
    expect(problems(scrubW).some((x) => /github-token/.test(x))).toBe(true);
    // the scrub inputs refused under mode gate; a missing or other mode refused outright
    expect(problems({ ...gateWith, tool: 'gitleaks' }).some((x) => /tool/.test(x))).toBe(true);
    for (const mode of ['Gate', 'gate ', 'merged-red', '', 'verify']) expect(problems({ ...gateWith, mode }).some((x) => /input mode/.test(x)), mode).toBe(true);
    expect(rendererInputProblems(U, { 'job-list': '[]' }, { 'job-list': '[]' }).length).toBeGreaterThan(0);   // no mode at all
  });

  it('renderGateStep: the gate step the renderer writes passes the row, uses the job list literal, and the YAML emitter accepts it', () => {
    const d = draftOf([gitleaksSpec()], [needOf('secrets')]);
    const entries = gateJobList(d);
    const s = renderGateStep(GATE, entries);
    expect(s.with?.mode).toBe('gate');
    expect(s.with?.jobs).toBe('${{ toJSON(needs) }}');
    expect(s.with?.['job-list']).toBe(jobListLiteral(entries));
    expect(s.run).toBeUndefined();
    expect(() => stepsToYaml([s])).not.toThrow();
    expect(() => renderGateStep(entry('gitleaks'), entries)).toThrow(RenderError);
    const fixed = gateEntry();
    fixed.fixedInputs = { with: { mode: 'gate' } };
    (fixed.step.action as { with: Record<string, string> }).with = { mode: 'gate' };
    expect(() => renderGateStep(fixed, entries)).toThrow(RenderError);
  });
});

// ---------- the referee and the gate job ----------

describe('referee: the gate job (rulings S4 and S21)', () => {
  const specs = [gitleaksSpec(), semgrepSpec('app')];
  const needs = [needOf('secrets'), needOf('sast', 'app')];
  const d = draftOf(specs, needs);
  const entries = gateJobList(d);
  const g = block(specs[0] as StepSpec);
  const s = block(specs[1] as StepSpec);
  const scanJobs = (): Record<string, Job> => ({
    [SEC]: job(dedupeJobSteps([...prelude(), ...g.steps], { id: 'secrets', scans: facts(g) }), { outputs: jobOutputsFor(g.steps) }),
    'sast--app': job(dedupeJobSteps([...prelude(), ...s.steps], { id: 'sast--app', scans: facts(s) }), { outputs: jobOutputsFor(s.steps) }),
  });
  const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
  const gateJob = (step: RenderedStep, over: Job = {}): Job => job([step, ...renderGateUploads(p)], { name: 'gate', if: 'always()', needs: entries.map((e) => e.job), permissions: GATE_PERM, ...over });
  const withIn = (step: RenderedStep, w: Record<string, string>): RenderedStep => ({ ...step, with: { ...step.with, ...w } });

  it('referee: a gate job with the rendered gate step, the right job list and needs, and the scanner jobs → no issue', async () => {
    const r = await run([workflow({ ...scanJobs(), gate: gateJob(renderGateStep(GATE, entries)) })], d);
    expect(show(r)).toBe('');
  });

  it('referee: gate job-list literal ≠ gateJobList(draft) → not-gate-readable (a dropped entry, a flipped blocking, an extra entry, a changed artifact, bad JSON, none at all)', async () => {
    const step = renderGateStep(GATE, entries);
    const list = JSON.parse(step.with?.['job-list'] as string) as JobListEntry[];
    const variants: Record<string, string | null> = {
      dropped: JSON.stringify(list.slice(1)),
      flipped: JSON.stringify(list.map((e, i) => (i === 0 ? { ...e, blocking: false } : e))),
      extra: JSON.stringify([...list, { ...list[0], job: 'extra', needId: 'extra' }]),
      artifact: JSON.stringify(list.map((e, i) => (i === 0 ? { ...e, artifact: 'pipegen-out-other' } : e))),
      [SEC]: JSON.stringify(list.map((e, i) => (i === 0 ? { ...e, [NS]: true } : e))),
      tool: JSON.stringify(list.map((e, i) => (i === 0 ? { ...e, tool: 'semgrep' } : e))),
      reordered: JSON.stringify([...list].reverse()),
      badJson: '[{',
      none: null,
    };
    for (const [name, lit] of Object.entries(variants)) {
      const w = lit === null ? Object.fromEntries(Object.entries(step.with ?? {}).filter(([k]) => k !== 'job-list')) : { ...step.with, 'job-list': lit };
      const r = await run([workflow({ ...scanJobs(), gate: gateJob({ ...step, with: w }) }, true)], d);
      expect(has(r, 'not-gate-readable'), `${name}: ${show(r)}`).toBe(true);
    }
  });

  it('referee: gate needs ⊉ the job list jobs → not-gate-readable (a missing job, no needs at all, a string that names one)', async () => {
    const step = renderGateStep(GATE, entries);
    for (const needsList of [['secrets'], [], undefined, 'secrets', ['sast--app']]) {
      const j = gateJob(step, needsList === undefined ? { needs: undefined } : { needs: needsList });
      const r = await run([workflow({ ...scanJobs(), gate: j })], d);
      expect(has(r, 'not-gate-readable', /needs/), `${JSON.stringify(needsList)}: ${show(r)}`).toBe(true);
    }
    // more needs than the list (base-scan, anything) is fine
    const more = await run([workflow({ ...scanJobs(), gate: gateJob(step, { needs: [...entries.map((e) => e.job), 'secrets'] }) })], d);
    expect(show(more)).toBe('');
  });

  it('referee: the gate step without jobs or without mode, or with mode gate outside the gate job → refused', async () => {
    const step = renderGateStep(GATE, entries);
    const noJobs = { ...step, with: Object.fromEntries(Object.entries(step.with ?? {}).filter(([k]) => k !== 'jobs')) };
    const noMode = { ...step, with: Object.fromEntries(Object.entries(step.with ?? {}).filter(([k]) => k !== 'mode')) };
    const r1 = await run([workflow({ ...scanJobs(), gate: gateJob(noJobs) }, true)], d);
    expect(has(r1, 'not-gate-readable', /jobs/), show(r1)).toBe(true);
    const r2 = await run([workflow({ ...scanJobs(), gate: gateJob(noMode) }, true)], d);
    expect(has(r2, 'template', /must set its mode/), show(r2)).toBe(true);
    const r3 = await run([workflow({ ...scanJobs(), 'pipegen-verify': job([step], { permissions: { contents: 'read', actions: 'read', packages: 'read', attestations: 'read' }, needs: entries.map((e) => e.job) }) }, true)], d);
    expect(r3.ok, show(r3)).toBe(false);
  });

  it('referee: a gate step input from another mode (sha under mode gate), or an expression in job-list, is refused', async () => {
    const step = renderGateStep(GATE, entries);
    const r = await run([workflow({ ...scanJobs(), gate: gateJob(withIn(step, { sha: '${{ github.sha }}' })) }, true)], d);
    expect(has(r, 'template', /sha/), show(r)).toBe(true);
    const r2 = await run([workflow({ ...scanJobs(), gate: gateJob(withIn(step, { 'job-list': '${{ toJSON(needs) }}' })) }, true)], d);
    expect(r2.ok, show(r2)).toBe(false);
  });

  it('referee: gate row without checkout (the gate never reads the workspace, ruling S21)', async () => {
    expect(JOB_STEP_POLICY.gate).not.toContain('checkout');
    expect(JOB_STEP_POLICY.gate).toEqual(expect.arrayContaining(['harden', 'download-artifact', 'gate']));
    const r = await run([workflow({ ...scanJobs(), gate: gateJob(renderGateStep(GATE, entries)) })], d);
    expect(show(r)).toBe('');
    const withCheckout = job([...prelude(), renderGateStep(GATE, entries), ...renderGateUploads(p)], { name: 'gate', if: 'always()', needs: entries.map((e) => e.job), permissions: GATE_PERM });
    const r2 = await run([workflow({ ...scanJobs(), gate: withCheckout })], d);
    expect(has(r2, 'permissions', /checkout step/), show(r2)).toBe(true);
    // the other rows that read a workspace keep their checkout
    expect(JOB_STEP_POLICY.nightly).toContain('checkout');
    expect(JOB_STEP_POLICY['pipegen-verify']).toContain('checkout');
  });
});

// ---------- the base-scan checkout ref (ruling S16) ----------

describe('base-scan checkout ref (ruling S16)', () => {
  const BASE = '${{ github.event.pull_request.base.sha }}';
  const BEFORE = '${{ github.event.before }}';
  it('RENDERER_INPUTS actions/checkout: ref only the one event-switched base expression (the per-event forms alone are refused now)', () => {
    expect(rendererInputProblems('actions/checkout', { ref: BASE_CHECKOUT_REF })).toEqual([]);
    for (const bad of [BASE, BEFORE, 'main', '${{ github.head_ref }}', '${{ github.event.pull_request.head.sha }}', '${{ github.sha }}', `${BASE_CHECKOUT_REF} `, '', 'refs/pull/1/merge']) {
      expect(rendererInputProblems('actions/checkout', { ref: bad }).length, bad).toBeGreaterThan(0);
    }
  });

  it('renderJobPrelude: baseRef true gives the checkout the base expression; anything else is refused', () => {
    const pr = prelude({ baseRef: true });
    expect(pr[0]?.with?.ref).toBe(BASE_CHECKOUT_REF);
    expect(prelude()[0]?.with?.ref).toBeUndefined();
    expect(() => prelude({ baseRef: 'main' as unknown as true })).toThrow(RenderError);
    expect(() => stepsToYaml(pr)).not.toThrow();
  });

  it('base-scan checkout ref only in job base-scan: checkJobOrder and dedupeJobSteps refuse it in any other job (and with no job id)', () => {
    const steps = prelude({ baseRef: true });
    expect(checkJobOrder(steps, { id: 'base-scan' })).toEqual([]);
    expect(dedupeJobSteps(steps, { id: 'base-scan', scans: NO_SCANS })).toHaveLength(1);
    for (const ctxOf of [{ id: 'secrets' }, { id: 'gate' }, { id: 'base-scan2' }, { id: 'Base-Scan' }, {}]) {
      expect(checkJobOrder(steps, ctxOf).join(' '), JSON.stringify(ctxOf)).toMatch(/base-scan/);
      expect(() => dedupeJobSteps(steps, { ...ctxOf, scans: NO_SCANS }), JSON.stringify(ctxOf)).toThrow(RenderError);
    }
    expect(checkJobOrder(prelude())).toEqual([]);   // a checkout with no ref is fine anywhere
  });

  it('referee: a checkout ref in a job other than base-scan → refused; in base-scan → fine; another ref in base-scan → refused', async () => {
    const spec = gitleaksSpec();
    const dd = draftOf([spec], [needOf('secrets')]);
    const base = block(spec, { ...ctx, base: true });
    const baseSteps = [...prelude({ baseRef: true }), ...base.steps];
    const pr = block(spec);
    const prJob = job(dedupeJobSteps([...prelude(), ...pr.steps], { id: 'secrets', scans: facts(pr) }), { outputs: jobOutputsFor(pr.steps) });
    const ok = await run([workflow({ [SEC]: prJob, 'base-scan': job(dedupeJobSteps(baseSteps, { id: 'base-scan', scans: facts(base) }), { outputs: jobOutputsFor(base.steps) }) })], dd);
    expect(show(ok)).toBe('');
    const elsewhere = await run([workflow({ [SEC]: prJob, other: job(baseSteps) })], dd);
    expect(has(elsewhere, 'injection', /base-scan/), show(elsewhere)).toBe(true);
    for (const ref of ['main', '${{ github.head_ref }}', '${{ github.event.pull_request.head.sha }}']) {
      const bent = baseSteps.map((s, i) => (i === 0 ? { ...s, with: { ...s.with, ref } } : s));
      const r = await run([workflow({ [SEC]: prJob, 'base-scan': job(bent) }, true)], dd);
      expect(r.ok, ref).toBe(false);
    }
  });
});

// ---------- scrub cross-checks (C0a carry-forward) ----------

describe('scrub cross-checks (the shared rule and the referee)', () => {
  const spec = gitleaksSpec();
  const g = block(spec);
  const dd = draftOf([spec], [needOf('secrets')]);
  const base = (): RenderedStep[] => [...prelude(), ...g.steps];
  const rule = (steps: RenderedStep[], withFacts = true): string => checkJobOrder(steps, { id: 'secrets', ...(withFacts ? { scans: facts(g) } : {}) }).join('\n');
  const referee1 = async (steps: RenderedStep[]): Promise<RefereeReport> => run([workflow({ [SEC]: job(steps) }, true)], dd);

  it('scrub cross-checks: the rendered chain passes (with and without scan facts)', async () => {
    expect(rule(base())).toBe('');
    expect(rule(base(), false)).toBe('');
    expect(() => dedupeJobSteps(base(), { id: 'secrets', scans: facts(g) })).not.toThrow();
    expect(show(await referee1(base()))).toBe('');
  });

  it('a scrub\'s id equals scrub-<sha16(with.artifact)>', async () => {
    const bent = withScrub(base(), (s) => ({ ...s, id: 'scrub-0123456789abcdef' }));
    expect(rule(bent)).toMatch(/id/);
    expect(rule(bent)).toMatch(/scrub-0123456789abcdef/);
    expect(() => dedupeJobSteps(bent, { id: 'secrets', scans: facts(g) })).toThrow(RenderError);
    const r = await referee1(bent);
    expect(has(r, 'injection', /scrub step's id/), show(r)).toBe(true);
  });

  it('a scrub\'s tool equals the scan step\'s reviewed entry (semgrep over a gitleaks result)', async () => {
    const bent = withScrub(base(), (s) => ({ ...s, with: { ...s.with, tool: 'semgrep' } as Record<string, string> }));
    expect(rule(bent)).toMatch(/scrubs it as the tool "semgrep", but the scan step ran "gitleaks"/);
    expect(() => dedupeJobSteps(bent, { id: 'secrets', scans: facts(g) })).toThrow(RenderError);
    const r = await referee1(bent);
    expect(has(r, 'injection', /scan step ran "gitleaks"/), show(r)).toBe(true);
  });

  it('a scrub\'s format equals the scan step\'s output format (zap-json over a sarif result)', async () => {
    const bent = withScrub(base(), (s) => ({ ...s, with: { ...s.with, format: 'zap-json' } as Record<string, string> }));
    expect(rule(bent)).toMatch(/as the format "zap-json", but the scan step wrote "sarif"/);
    const r = await referee1(bent);
    expect(has(r, 'injection', /scan step wrote "sarif"/), show(r)).toBe(true);
  });

  it('a made-up tool id is refused (with and without scan facts)', async () => {
    const bent = withScrub(base(), (s) => ({ ...s, with: { ...s.with, tool: 'not-a-tool' } as Record<string, string> }));
    expect(rule(bent, false)).toMatch(/not-a-tool/);
    expect(rule(bent, false)).toMatch(/not a tool pipegen reviewed/);
    expect(rule(bent)).toMatch(/not-a-tool/);
    const r = await referee1(bent);
    expect(has(r, 'injection', /not-a-tool/), show(r)).toBe(true);
  });

  it('raw, out, fp-key and artifact are all present (each missing on its own is refused)', async () => {
    for (const key of ['raw', 'out', 'fp-key', 'artifact', 'tool', 'format']) {
      const bent = withScrub(base(), (s) => ({ ...s, with: Object.fromEntries(Object.entries(s.with ?? {}).filter(([k]) => k !== key)) }));
      expect(rule(bent), key).toMatch(new RegExp(`no ${key} input`));
      const r = await referee1(bent);
      expect(r.ok, key).toBe(false);
    }
  });

  it('exactly one scrub per artifact in a job (a second one with another id and tool is refused)', async () => {
    const second: RenderedStep = { ...scrubOf(g.steps), id: 'scrub-ffffffffffffffff', with: { ...scrubOf(g.steps).with, tool: 'trivy-config' } as Record<string, string> };
    const steps = [...prelude(), ...g.result.steps, g.scrub, second, g.upload];
    expect(rule(steps)).toMatch(/second scrub step for the result/);
    const dup = [...prelude(), ...g.result.steps, g.scrub, { ...g.scrub }, g.upload];
    expect(rule(dup)).toMatch(/second scrub step for the result/);
    const r = await referee1(steps);
    expect(has(r, 'injection', /second scrub step/), show(r)).toBe(true);
  });

  it('the scrub sits in the same job as its scan and after it', async () => {
    const before = [...prelude(), g.scrub, ...g.result.steps, g.upload];
    expect(rule(before)).toMatch(/no scan step of that result comes before it/);
    const alone = [...prelude(), g.scrub, g.upload];
    expect(rule(alone)).toMatch(/no scan step of that result comes before it/);
    const r1 = await referee1(alone);
    expect(r1.ok).toBe(false);
    const r2 = await referee1(before);
    expect(has(r2, 'injection', /no scan step of that result comes before it/), show(r2)).toBe(true);
    // a scrub of another artifact's scan: the id hash ties each scrub to its own scan step
    const other = block(semgrepSpec('app'));
    const mixed = [...prelude(), ...g.result.steps, other.scrub, other.upload];
    expect(rule(mixed)).toMatch(/no scan step of that result comes before it/);
  });

  it('with scan facts, a scan step that is not a reviewed scan (no fact for its id) is refused', () => {
    expect(rule(base(), true)).toBe('');
    const noFact = checkJobOrder(base(), { id: 'secrets', scans: new Map() }).join('\n');
    expect(noFact).toMatch(/not a scan step pipegen renders/);
  });

  it('scanFactOf: the last run step of a findings tool with its reviewed id and output format; null for a tool with no result', () => {
    expect(g.scan.fact).toEqual({ tool: 'gitleaks', format: 'sarif' });
    expect(g.scan.stepId).toMatch(/^tool-run-[0-9a-f]{16}$/);
    expect(g.scan.stepId).toBe(`tool-run-${sha16(g.artifact)}`);
    const noOut = renderStep(specFor(entry('actionlint'), { needId: 'workflow-lint' }), entry('actionlint'), p, ctx);
    expect(scanFactOf(noOut, 'actionlint')).toBeNull();
  });
});

// ---------- parity: a full draft ----------

describe('parity: a full draft (two services, scanners, base-scan, gate job) through the real helpers', () => {
  const specs = [gitleaksSpec(), semgrepSpec('app'), semgrepSpec('web')];
  const needs = [needOf('secrets'), needOf('sast', 'app'), needOf('sast', 'web'), needOf('unit-tests', 'app'), needOf('gate')];
  const d = draftOf(specs, needs);
  const entries = gateJobList(d);
  const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };

  function jobs(): Record<string, Job> {
    const out: Record<string, Job> = {};
    for (const spec of specs) {
      const b = block(spec);
      const id = `${spec.needId}${spec.service === undefined ? '' : `--${spec.service}`}`;
      out[id] = job(dedupeJobSteps([...prelude(), ...b.steps], { id, scans: facts(b) }), { outputs: jobOutputsFor(b.steps) });
    }
    const script = renderProjectScript({ kind: 'project-script', needId: 'unit-tests', service: 'app', script: 'test' }, p, ctx).steps;
    out['unit-tests--app'] = job(dedupeJobSteps(script, { id: 'unit-tests--app' , scans: NO_SCANS }));
    // base-scan: one checkout of the base commit, then the base twin of every findings check
    const baseBlocks = specs.map((s) => block(s, { ...ctx, base: true }));
    const baseSteps = [...prelude({ baseRef: true }), ...baseBlocks.flatMap((b) => b.steps)];
    out['base-scan'] = job(dedupeJobSteps(baseSteps, { id: 'base-scan', scans: facts(...baseBlocks) }), { outputs: jobOutputsFor(baseBlocks.flatMap((b) => b.steps)) });
    out.gate = job([renderGateStep(GATE, entries), ...renderGateUploads(p)], { name: 'gate', if: 'always()', needs: [...entries.map((e) => e.job), 'base-scan'], permissions: GATE_PERM });
    return out;
  }
  const files = (j: Record<string, Job>, raw = false): CreatedFile[] => [workflow(j, raw)];

  it('the job list has one entry per findings result and one for the blocking script need', () => {
    expect(entries.map((e) => e.job)).toEqual(['secrets', 'sast--app', 'sast--web', 'unit-tests--app']);
    expect(entries.map((e) => e.artifact)).toEqual([resultArtifactName('secrets'), resultArtifactName('sast', 'app'), resultArtifactName('sast', 'web'), undefined]);
  });

  it('a full draft passes dedupeJobSteps, stepsToYaml and the referee with 0 issues', async () => {
    const j = jobs();
    expect(Object.keys(j)).toEqual(['secrets', 'sast--app', 'sast--web', 'unit-tests--app', 'base-scan', 'gate']);
    for (const [id, x] of Object.entries(j)) expect(() => stepsToYaml(x.steps as RenderedStep[]), id).not.toThrow();
    const r = await run(files(j), d);
    expect(show(r)).toBe('');
    expect(r.ok).toBe(true);
    // the base-scan job's outputs name the base artifacts, scrub by scrub
    const baseOut = j['base-scan']?.outputs as Record<string, string>;
    expect(Object.keys(baseOut)).toContain(`${resultArtifactName('sast', 'web', { base: true })}-status`);
  });

  it('tampering with one link gives an issue: a job output', async () => {
    const j = jobs();
    const out = { ...(j.secrets?.outputs as Record<string, string>) };
    const key = Object.keys(out)[0] as string;
    out[key] = '${{ secrets.GITHUB_TOKEN }}';
    const r = await run(files({ ...j, [SEC]: { ...(j.secrets as Job), outputs: out } }), d);
    expect(has(r, 'injection'), show(r)).toBe(true);
    const r2 = await run(files({ ...j, [SEC]: { ...(j.secrets as Job), outputs: { ...(j.secrets?.outputs as object), 'has-pr': 'x' } } }), d);
    expect(has(r2, 'injection'), show(r2)).toBe(true);
  });

  it('tampering with one link gives an issue: a job-list entry', async () => {
    const j = jobs();
    const step = (j.gate?.steps as RenderedStep[])[0] as RenderedStep;
    const list = JSON.parse(step.with?.['job-list'] as string) as JobListEntry[];
    const bent = { ...step, with: { ...step.with, 'job-list': JSON.stringify(list.map((e) => (e.job === 'sast--web' ? { ...e, blocking: false } : e))) } };
    const r = await run(files({ ...j, gate: { ...(j.gate as Job), steps: [bent] } }), d);
    expect(has(r, 'not-gate-readable'), show(r)).toBe(true);
  });

  it('tampering with one link gives an issue: the gate\'s needs', async () => {
    const j = jobs();
    const r = await run(files({ ...j, gate: { ...(j.gate as Job), needs: ['secrets', 'sast--app', 'unit-tests--app', 'base-scan'] } }), d);
    expect(has(r, 'not-gate-readable', /sast--web/), show(r)).toBe(true);
  });

  it('tampering with one link gives an issue: the base ref', async () => {
    const j = jobs();
    const steps = (j['base-scan']?.steps as RenderedStep[]).map((s, i) => (i === 0 ? { ...s, with: { ...s.with, ref: '${{ github.head_ref }}' } } : s));
    const r = await run(files({ ...j, 'base-scan': { ...(j['base-scan'] as Job), steps } }, true), d);
    expect(r.ok, show(r)).toBe(false);
    const moved = (j['base-scan']?.steps as RenderedStep[]);
    const r2 = await run(files({ ...j, [SEC]: { ...(j.secrets as Job), steps: [...moved.slice(0, 1), ...(j.secrets?.steps as RenderedStep[]).slice(1)] } }), d);
    expect(has(r2, 'injection', /base-scan/), show(r2)).toBe(true);
  });

  it('tampering with one link gives an issue: a scrub tool', async () => {
    const j = jobs();
    const steps = withScrub(j['sast--web']?.steps as RenderedStep[], (s) => ({ ...s, with: { ...s.with, tool: 'gitleaks' } as Record<string, string> }));
    const r = await run(files({ ...j, 'sast--web': { ...(j['sast--web'] as Job), steps } }, true), d);
    expect(has(r, 'injection', /scan step ran "semgrep"/), show(r)).toBe(true);
  });
});

// ---------- C5b: the gate's uploads (rulings 2 and 5 of task-C5b-rulings.md) ----------
// The gate writes result.json (always) and baseline.json / marker.json (only when eligible) into ${{ runner.temp }}/pipegen-gate/;
// pinned upload-artifact steps after the gate step upload them under the three reserved names. Written first.
import { renderGateUploads } from '../src/engine/render-step.js';
import { isKnownHarmless } from '../src/engine/job-rules.js';
import { BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT, GATE_RESULT_ARTIFACT } from '../src/engine/artifact-names.js';

describe('C5b: renderGateUploads and the reserved gate uploads', () => {
  const UP = 'actions/upload-artifact';
  const T = '${{ runner.temp }}/pipegen-gate';
  const specs = [gitleaksSpec(), semgrepSpec('app')];
  const needs = [needOf('secrets'), needOf('sast', 'app')];
  const d = draftOf(specs, needs);
  const entries = gateJobList(d);
  const g = block(specs[0] as StepSpec);
  const s = block(specs[1] as StepSpec);
  const scanJobs = (): Record<string, Job> => ({
    [SEC]: job(dedupeJobSteps([...prelude(), ...g.steps], { id: 'secrets', scans: facts(g) }), { outputs: jobOutputsFor(g.steps) }),
    'sast--app': job(dedupeJobSteps([...prelude(), ...s.steps], { id: 'sast--app', scans: facts(s) }), { outputs: jobOutputsFor(s.steps) }),
  });
  const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
  const gateJob = (steps: RenderedStep[], over: Job = {}): Job => job(steps, { name: 'gate', if: 'always()', needs: entries.map((e) => e.job), permissions: GATE_PERM, ...over });
  const gateStep = (): RenderedStep => renderGateStep(GATE, entries);
  const uploads = (): RenderedStep[] => renderGateUploads(p);

  it('renderGateUploads: three uploads, each if: always(), at its own file in pipegen-gate; only the baseline and the marker ignore a missing file', () => {
    const u = uploads();
    expect(u.map((x) => x.with?.name)).toEqual([GATE_RESULT_ARTIFACT, BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT]);
    expect(u.map((x) => x.with?.path)).toEqual([`${T}/result.json`, `${T}/baseline.json`, `${T}/marker.json`]);
    expect(u.map((x) => x.if)).toEqual(['always()', 'always()', 'always()']);
    expect(u.map((x) => x.with?.['if-no-files-found'])).toEqual(['error', 'ignore', 'ignore']);
    for (const x of u) {
      expect(x.uses?.startsWith(`${UP}@`)).toBe(true);
      expect(x.with?.['include-hidden-files']).toBe('false');
      expect(x.with?.archive).toBe('true');
    }
    expect(() => stepsToYaml([gateStep(), ...u])).not.toThrow();
  });

  it('RENDERER_INPUTS: a reserved name only at its own pipegen-gate file; a result name never there; no other pipegen-gate path', () => {
    const ok = (w: Record<string, string>): boolean => rendererInputProblems(UP, w, w).length === 0;
    expect(ok({ name: GATE_RESULT_ARTIFACT, path: `${T}/result.json` })).toBe(true);
    expect(ok({ name: BASELINE_ARTIFACT, path: `${T}/baseline.json` })).toBe(true);
    expect(ok({ name: CLEAN_RUN_ARTIFACT, path: `${T}/marker.json` })).toBe(true);
    expect(ok({ name: BASELINE_ARTIFACT, path: `${T}/marker.json` })).toBe(false);
    expect(ok({ name: GATE_RESULT_ARTIFACT, path: `${T}/baseline.json` })).toBe(false);
    expect(ok({ name: GATE_RESULT_ARTIFACT, path: '${{ runner.temp }}/pipegen-out/pipegen-gate-result/result.json' })).toBe(false);
    expect(ok({ name: 'pipegen-out-secrets', path: `${T}/result.json` })).toBe(false);
    for (const path of [T, `${T}/`, `${T}/x.json`, `${T}/result.json/x`, '${{ runner.temp }}/pipegen-gate/../pipegen-out/x']) expect(ok({ name: GATE_RESULT_ARTIFACT, path }), path).toBe(false);
    for (const name of ['pipegen-gate-results', 'pipegen-Baseline', 'pipegen-clean-run-x']) expect(ok({ name, path: `${T}/result.json` }), name).toBe(false);
    // the download side is unchanged: the gate's own names are never downloaded by a step
    expect(rendererInputProblems('actions/download-artifact', { name: GATE_RESULT_ARTIFACT }).length).toBeGreaterThan(0);
    // result uploads keep their own rule
    expect(ok({ name: 'pipegen-out-secrets', path: '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/x.sarif' })).toBe(true);
  });

  it('isKnownHarmless: the gate step in mode gate (pinned, no run) runs no repo code; other modes and forms are not this rule', () => {
    expect(isKnownHarmless(gateStep())).toBe(true);
    expect(isKnownHarmless({ ...gateStep(), uses: 'crisworking/pipegen/gate@main' })).toBe(false);
    expect(isKnownHarmless({ ...gateStep(), run: 'echo' })).toBe(false);
    expect(isKnownHarmless({ ...gateStep(), with: { ...gateStep().with, mode: 'nightly' } })).toBe(false);
    expect(isKnownHarmless({ ...gateStep(), uses: (gateStep().uses as string).replace('crisworking/pipegen/gate', 'crisworking/pipegen/other') })).toBe(false);
  });

  it('checkJobOrder: in job gate the uploads after the gate step are fine; before it, elsewhere, without always(), twice, or another upload → problems', () => {
    const [r, b, m] = uploads() as [RenderedStep, RenderedStep, RenderedStep];
    expect(checkJobOrder([...prelude(), gateStep(), r, b, m], { id: 'gate', scans: NO_SCANS })).toEqual([]);
    expect(checkJobOrder([gateStep(), r], { id: 'gate', scans: NO_SCANS })).toEqual([]);
    const bad = (steps: RenderedStep[], id: string | undefined, re: RegExp): void => {
      const got = checkJobOrder(steps, id === undefined ? { scans: NO_SCANS } : { id, scans: NO_SCANS });
      expect(got.some((x) => re.test(x)), `${id}: ${got.join(' | ')}`).toBe(true);
    };
    bad([r, gateStep()], 'gate', /after the gate step/);
    bad([...prelude(), r], 'secrets', /only the gate job/);
    bad([gateStep(), r], undefined, /only the gate job/);
    bad([gateStep(), { ...r, if: 'success()' }], 'gate', /always\(\)/);
    bad([gateStep(), { ...r }, { ...r }], 'gate', /more than once/);
    bad([gateStep(), s.upload], 'gate', /gate job uploads only/);
  });

  it('referee: the gate job with its uploads → no issue', async () => {
    const r = await run([workflow({ ...scanJobs(), gate: gateJob([gateStep(), ...uploads()]) })], d);
    expect(show(r)).toBe('');
  });

  it('referee: if-no-files-found ignore only on the baseline and the marker, error on the result; a reserved upload outside the gate job, or before the gate step → issues', async () => {
    const [r0, b0, m0] = uploads() as [RenderedStep, RenderedStep, RenderedStep];
    const flip = (x: RenderedStep, v: string): RenderedStep => ({ ...x, with: { ...x.with, 'if-no-files-found': v } as Record<string, string> });
    const one = async (gateSteps: RenderedStep[], extra: Record<string, Job> = {}): Promise<RefereeReport> => run([workflow({ ...scanJobs(), ...extra, gate: gateJob(gateSteps) }, true)], d);
    expect(has(await one([gateStep(), flip(r0, 'ignore'), b0, m0]), 'template', /if-no-files-found/)).toBe(true);
    expect(has(await one([gateStep(), r0, flip(b0, 'error'), m0]), 'template', /if-no-files-found/)).toBe(true);
    expect(has(await one([gateStep(), r0, b0, flip(m0, 'warn')]), 'template', /if-no-files-found/)).toBe(true);
    // ignore on a result upload in a scanner job
    const j = scanJobs();
    const secSteps = (j[SEC] as Job).steps as RenderedStep[];
    const ignoring = secSteps.map((x) => (x.with?.name === g.artifact ? flip(x, 'ignore') : x));
    const rr = await run([workflow({ ...j, [SEC]: { ...(j[SEC] as Job), steps: ignoring }, gate: gateJob([gateStep(), r0, b0, m0]) }, true)], d);
    expect(has(rr, 'template', /if-no-files-found/), show(rr)).toBe(true);
    // a reserved upload in a scanner job
    const stray = await run([workflow({ ...j, [SEC]: { ...(j[SEC] as Job), steps: [...secSteps, b0] }, gate: gateJob([gateStep(), r0, m0]) }, true)], d);
    expect(show(stray)).toMatch(/only the gate job/);
    // before the gate step
    expect(show(await one([r0, gateStep(), b0, m0]))).toMatch(/after the gate step/);
  });

  it('JOB_STEP_POLICY: the gate row allows uploads (the reserved ones only, checkJobOrder) and still no checkout', () => {
    expect(JOB_STEP_POLICY.gate).toEqual(['harden', 'download-artifact', 'gate', 'upload-artifact']);
  });

  it('ruling 5: a scrub step\'s declared outputs are sha256, status and error; the job outputs keep <artifact>-<name> and reference them', () => {
    const out = jobOutputsFor(g.steps);
    const id = scrubStepId(g.artifact);
    expect(out).toEqual({
      [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.sha256 }}`, [`${g.artifact}-status`]: `\${{ steps.${id}.outputs.status }}`, [`${g.artifact}-error`]: `\${{ steps.${id}.outputs.error }}`,
    });
    expect(jobOutputsProblems('secrets', { [`${g.artifact}-sha256`]: `\${{ steps.${id}.outputs.${g.artifact}-sha256 }}` }, g.steps).length).toBe(1);
  });
});

// ---------- C5b fix round 1 (task-C5b-fix-round-1.md rulings 1 and 2) ----------
// The result upload is required right after the gate step; continue-on-error is allowed on exactly the baseline and the marker
// uploads in job gate (after the gate step), and refused everywhere else. Written first.
import { isGateDecideStep } from '../src/engine/job-rules.js';

describe('C5b fix round 1: the required result upload and the optional uploads that never fail the gate', () => {
  const specs = [gitleaksSpec(), semgrepSpec('app')];
  const needs = [needOf('secrets'), needOf('sast', 'app')];
  const d = draftOf(specs, needs);
  const entries = gateJobList(d);
  const g = block(specs[0] as StepSpec);
  const s = block(specs[1] as StepSpec);
  const scanJobs = (): Record<string, Job> => ({
    [SEC]: job(dedupeJobSteps([...prelude(), ...g.steps], { id: 'secrets', scans: facts(g) }), { outputs: jobOutputsFor(g.steps) }),
    'sast--app': job(dedupeJobSteps([...prelude(), ...s.steps], { id: 'sast--app', scans: facts(s) }), { outputs: jobOutputsFor(s.steps) }),
  });
  const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
  const gateJob = (steps: RenderedStep[]): Job => job(steps, { name: 'gate', if: 'always()', needs: entries.map((e) => e.job), permissions: GATE_PERM });
  const gateStep = (): RenderedStep => renderGateStep(GATE, entries);
  const coe = (x: RenderedStep, v: boolean | undefined): RenderedStep => { const c = { ...x }; if (v === undefined) delete c['continue-on-error']; else c['continue-on-error'] = v; return c; };
  const one = async (gateSteps: RenderedStep[], extra: Record<string, Job> = {}): Promise<RefereeReport> => run([workflow({ ...scanJobs(), ...extra, gate: gateJob(gateSteps) }, true)], d);

  it('renderGateUploads: continue-on-error true on the baseline and the marker uploads only', () => {
    expect(renderGateUploads(p).map((x) => x['continue-on-error'])).toEqual([undefined, true, true]);
    expect(() => stepsToYaml([gateStep(), ...renderGateUploads(p)])).not.toThrow();
  });

  it('isGateDecideStep: the gate step with an id is not the deciding step (ids belong to other kinds)', () => {
    expect(isGateDecideStep(gateStep())).toBe(true);
    expect(isGateDecideStep({ ...gateStep(), id: 'gate' })).toBe(false);
    expect(isKnownHarmless({ ...gateStep(), id: 'pipegen-gate' })).toBe(false);
  });

  it('checkJobOrder: continue-on-error only on the two optional gate uploads in job gate; on the result upload, a result upload, a tool step or elsewhere → problems', () => {
    const [r, b, m] = renderGateUploads(p) as [RenderedStep, RenderedStep, RenderedStep];
    expect(checkJobOrder([gateStep(), r, b, m], { id: 'gate', scans: NO_SCANS })).toEqual([]);
    const bad = (steps: RenderedStep[], id: string, re: RegExp): void => {
      const got = checkJobOrder(steps, { id, scans: id === 'secrets' ? facts(g) : NO_SCANS });
      expect(got.some((x) => re.test(x)), `${id}: ${got.join(' | ')}`).toBe(true);
    };
    bad([gateStep(), coe(r, true), b, m], 'gate', /continue-on-error/);
    bad([...prelude(), ...g.steps.map((x) => (x === g.upload ? coe(x, true) : x))], 'secrets', /continue-on-error/);
    bad([...prelude(), ...g.steps.map((x) => (x === g.scrub ? coe(x, true) : x))], 'secrets', /continue-on-error/);
    bad([gateStep(), r, b, m, coe(prelude()[0] as RenderedStep, true)], 'gate', /continue-on-error/);
    bad([...prelude(), b], 'secrets', /only the gate job/);
  });

  it('referee: the gate job with the rendered uploads (continue-on-error on the two optional ones) → no issue', async () => {
    const r = await one([gateStep(), ...renderGateUploads(p)]);
    expect(show(r)).toBe('');
  });

  it('referee: no result upload, the result upload not right after the gate step, without always(), or with continue-on-error → not-gate-readable / issues', async () => {
    const [r0, b0, m0] = renderGateUploads(p) as [RenderedStep, RenderedStep, RenderedStep];
    const none = await one([gateStep()]);
    expect(has(none, 'not-gate-readable', /pipegen-gate-result/), show(none)).toBe(true);
    const later = await one([gateStep(), b0, r0, m0]);
    expect(has(later, 'not-gate-readable', /right after the gate step/), show(later)).toBe(true);
    const ok = await one([gateStep(), r0, b0, m0]);
    expect(show(ok)).toBe('');
    const noAlways = await one([gateStep(), { ...r0, if: 'success()' }, b0, m0]);
    expect(has(noAlways, 'not-gate-readable', /pipegen-gate-result/), show(noAlways)).toBe(true);
    const lenient = await one([gateStep(), coe(r0, true), b0, m0]);
    // each layer on its own: the result-upload rule (not-gate-readable), the step template rule and the shared order rule (injection)
    expect(has(lenient, 'not-gate-readable', /continue-on-error/), show(lenient)).toBe(true);
    expect(has(lenient, 'template', /continue-on-error/), show(lenient)).toBe(true);
    expect(has(lenient, 'injection', /continue-on-error/), show(lenient)).toBe(true);
    // the optional ones without continue-on-error are still allowed (the ruling allows it, it does not require it)
    expect(show(await one([gateStep(), r0, coe(b0, undefined), coe(m0, undefined)]))).toBe('');
  });

  it('referee: continue-on-error anywhere else (a scanner upload, a scrub, a tool step) is still refused', async () => {
    const j = scanJobs();
    const secSteps = (j[SEC] as Job).steps as RenderedStep[];
    for (const pick of [(x: RenderedStep) => x.with?.name === g.artifact, (x: RenderedStep) => x.id?.startsWith('scrub-') === true, (x: RenderedStep) => x.run !== undefined]) {
      const steps = secSteps.map((x) => (pick(x) ? coe(x, true) : x));
      const r = await run([workflow({ ...j, [SEC]: { ...(j[SEC] as Job), steps }, gate: gateJob([gateStep(), ...renderGateUploads(p)]) }, true)], d);
      expect(has(r, 'template', /continue-on-error/), show(r)).toBe(true);
      expect(has(r, 'injection', /continue-on-error/), show(r)).toBe(true);
    }
  });
});

// ---------- C5b fix round 2 (review-C5b-r1 r1-1): the gate step is found once ----------
import { gateResultUploadProblems } from '../src/engine/job-rules.js';

describe('C5b fix round 2: the referee judges the gate step it found; an id on it is refused', () => {
  const specs = [gitleaksSpec()];
  const d = draftOf(specs, [needOf('secrets')]);
  const entries = gateJobList(d);
  const g = block(specs[0] as StepSpec);
  const scan = (): Record<string, Job> => ({ [SEC]: job(dedupeJobSteps([...prelude(), ...g.steps], { id: 'secrets', scans: facts(g) }), { outputs: jobOutputsFor(g.steps) }) });
  const GATE_PERM = { contents: 'read', actions: 'read', 'pull-requests': 'read' };
  const gateJob = (steps: RenderedStep[]): Job => job(steps, { name: 'gate', if: 'always()', needs: entries.map((e) => e.job), permissions: GATE_PERM });
  const withId = (): RenderedStep => ({ ...renderGateStep(GATE, entries), id: 'pipegen-gate' });

  it('a gate step with an id and no uploads → not-gate-readable (the id, and the missing result upload)', async () => {
    const r = await run([workflow({ ...scan(), gate: gateJob([withId()]) }, true)], d);
    expect(has(r, 'not-gate-readable', /gate step .*id/), show(r)).toBe(true);
    expect(has(r, 'not-gate-readable', /pipegen-gate-result/), show(r)).toBe(true);
  });
  it('a gate step with an id and the uploads → not-gate-readable (the id)', async () => {
    const r = await run([workflow({ ...scan(), gate: gateJob([withId(), ...renderGateUploads(p)]) }, true)], d);
    expect(has(r, 'not-gate-readable', /gate step .*id/), show(r)).toBe(true);
  });
  it('a gate step with no uploads (no id) → not-gate-readable; the rendered job passes', async () => {
    expect(has(await run([workflow({ ...scan(), gate: gateJob([renderGateStep(GATE, entries)]) }, true)], d), 'not-gate-readable', /pipegen-gate-result/)).toBe(true);
    expect(show(await run([workflow({ ...scan(), gate: gateJob([renderGateStep(GATE, entries), ...renderGateUploads(p)]) }, true)], d))).toBe('');
  });
  it('gateResultUploadProblems with the index the caller found: an id\'d gate step still needs the result upload after it', () => {
    expect(gateResultUploadProblems([withId()], 0).length).toBe(1);
    expect(gateResultUploadProblems([withId(), ...renderGateUploads(p)], 0)).toEqual([]);
    expect(gateResultUploadProblems([renderGateStep(GATE, entries)]).length).toBe(1);
  });
});
