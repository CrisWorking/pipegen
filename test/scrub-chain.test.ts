// Plan C, sub-task C0a: the scan → scrub → upload chain in Plan B's engine (rulings B1 and B2 of the pre-flight scan).
// Written first (strict test-first). Raw results go to `pipegen-raw` and are never uploadable; the gate action in `scrub`
// mode rebuilds them into `pipegen-out/<artifact>/`; a findings exit code of a tool is not a failed step.
import { createHash } from 'node:crypto';
import { NO_SCANS } from '../src/engine/job-rules.js';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { checkJobOrder, isKnownHarmless, isScrubStep } from '../src/engine/job-rules.js';
import { JOB_STEP_POLICY, referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import { dedupeJobSteps, RenderError, renderJobPrelude, renderPlatformStep, renderScrub, renderStep, renderStepWith, renderUpload, scrubbedPath, stepsToYaml, type RenderContext, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY, NEED_IDS } from '../src/engine/need-ids.js';
import { ARGV_POLICIES, BASE_CHECKOUT_REF, rendererInputProblems, SCRUB_STEP_ID_RE } from '../src/engine/tool-flags.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, ReviewedTool, StepSpec } from '../src/types.js';
import { entry, gateEntry, GATE_SHA, platform, profile, reviewedList, service, specFor, scansFor } from './helpers/render.js';
import { exec, fakeTool, sandbox, stepEnv, type Sandbox } from './helpers/step-harness.js';
import { parseSarifText, SYNTHESIZED_NUCLEI } from '../gate/src/sarif.js';
import { NUCLEI_EMPTY_SARIF } from '../src/engine/render-cli.js';
import { stageWorkspace } from '../gate/src/stage.js';
import { renderStage as renderStageC1c } from '../src/engine/render-step.js';
import { isStagedTool } from '../src/engine/tool-flags.js';
import { withEgress } from './helpers/egress-step.js';

// ---------- builders ----------

/** `${{ secrets.NAME }}`, built at run time (test/no-secret-literals.test.ts). */
const ref = (n: string): string => ['${{', `secrets.${n}`, '}}'].join(' ');
const FP = ref('PIPEGEN_FP_KEY');
/** The workflow's own credential, the wrong value for the fingerprint key. */
const OTHER_REF = ref('GITHUB_TOKEN');
/** The need id of the secret scanners, spelled at run time (a job or field named like a secret trips test/no-secret-literals.test.ts). */
const SCANNER_NEED = ['sec', 'rets'].join('');
const sha16 = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const p = platform();
const GATE = gateEntry();
const svc = service({ name: 'app', path: '.', dockerfile: 'Dockerfile', scripts: ['test', 'lint'] });
const prof = { ...profile([svc]), repoFiles: { ...emptyRepoFiles(), kubernetes: true } };
const ctx: RenderContext = { profile: prof, targets: { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080', k8sDir: 'k8s' } };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const needOf = (id: string, svcName?: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, ...(svcName === undefined ? {} : { service: svcName }), why: 't', blocking: true, floor: false });
const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const draftOf = (steps: StepSpec[]): PipelineDraft => ({
  profile: prof, capabilities: caps, needs: steps.map((s) => needOf(s.needId, s.service)), steps, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [],
  requireDeployApproval: false, skipped: [], suggestions: [],
});
const prelude = (depth: '0' | '1' = '1'): RenderedStep[] => renderJobPrelude({ fetchDepth: depth }, p).steps;
const LINTERS: Linters = { actionlint: async () => '/stub/actionlint', zizmor: async () => '/stub/zizmor' };
const withGate = (): ReviewedTool[] => [...reviewedList(), GATE];
type Job = Record<string, unknown>;
const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });
/** `raw`: the steps are written as plain YAML (for hostile steps the emitter itself refuses: the referee must refuse them too). */
function workflow(jobs: Record<string, Job>, raw = false): CreatedFile {
  const doc = new Document();
  const plain = Object.fromEntries(Object.entries(jobs).map(([id, j]) => [id, Object.fromEntries(Object.entries(j).filter(([k]) => k !== 'steps'))]));
  doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: plain });
  for (const [id, j] of Object.entries(jobs)) {
    const steps = j.steps as RenderedStep[];
    doc.setIn(['jobs', id, 'steps'], raw ? doc.createNode(withEgress(steps).map(({ usesComment: _c, ...rest }) => rest)) : stepsToYaml(withEgress(steps)));
  }
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 't', repo: 'app' };
}
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, withGate(), LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');

/** The steps of one scanner job as Plan G composes them: [harden?, checkout, tool steps, scrub, upload]. */
function scannerSteps(spec: StepSpec, c: RenderContext = ctx): { steps: RenderedStep[]; result: RenderResult; artifact: string } {
  const t = entry(spec.tool.id);
  const result = renderStep(spec, t, p, c);
  const out = result.output;
  if (out === null) throw new Error('not a tool with a result');
  const artifact = resultArtifactName(spec.needId, spec.service, c.base === true ? { base: true } : undefined);
  const scrub = renderScrub(artifact, out.path, t.id, out.format as 'sarif' | 'zap-json', GATE);
  const stage = isStagedTool(t.id) ? [renderStageC1c(artifact, t.id, GATE)] : [];   // C1c
  return { steps: [...prelude(result.fullHistory === true ? '0' : '1'), ...stage, ...result.steps, scrub, renderUpload(artifact, scrubbedPath(out.path), p)], result, artifact };
}
const gitleaksSpec = (): StepSpec => specFor(entry('gitleaks'), { needId: 'secrets' });

// ---------- renderScrub ----------

describe('renderScrub (ruling B1 part 7)', () => {
  const artifact = 'pipegen-out-secrets';
  const raw = `\${{ runner.temp }}/pipegen-raw/${artifact}/gitleaks.sarif`;
  const out = `\${{ runner.temp }}/pipegen-out/${artifact}/gitleaks.sarif`;

  it('renderScrub: id scrub-<sha16(artifact)>, the pinned gate path, with mode/artifact/tool/format/raw/out/fp-key, if always()', () => {
    const s = renderScrub(artifact, raw, 'gitleaks', 'sarif', GATE);
    expect(s.id).toBe(`scrub-${sha16(artifact)}`);
    expect(s.id).toMatch(SCRUB_STEP_ID_RE);
    expect(s.uses).toBe(`crisworking/pipegen/gate@${GATE_SHA}`);
    expect(s.usesComment).toBe('gate-v0.2.0');
    expect(s.if).toBe('always()');
    expect(s.run).toBeUndefined();
    expect(s.with).toEqual({ mode: 'scrub', artifact, tool: 'gitleaks', format: 'sarif', raw, out, 'fp-key': FP, stage: `\${{ runner.temp }}/pipegen-stage/${artifact}` });   // C1c: a secrets scrub reads its stage folder
    expect(s.env).toBeUndefined();
  });

  it('renderScrub: a zap-json result; the scrubbed path is the raw path in pipegen-out; the YAML emitter writes the step', () => {
    const zraw = `\${{ runner.temp }}/pipegen-raw/pipegen-out-dast/zap.json`;
    const s = renderScrub('pipegen-out-dast', zraw, 'zap-baseline', 'zap-json', GATE);
    expect(s.with?.out).toBe('${{ runner.temp }}/pipegen-out/pipegen-out-dast/zap.json');
    expect(scrubbedPath(zraw)).toBe(s.with?.out);
    expect(() => stepsToYaml([s])).not.toThrow();
  });

  it('renderScrub: refuses a raw path that is not <artifact>/<file> in pipegen-raw, a format it cannot scrub, a tool id that is not plain, and an entry that is not the pinned gate', () => {
    const bad = (f: () => unknown): void => expect(f).toThrow(RenderError);
    bad(() => renderScrub(artifact, out, 'gitleaks', 'sarif', GATE));   // the scrubbed folder is not a raw path
    bad(() => renderScrub(artifact, `\${{ runner.temp }}/pipegen-raw/pipegen-out-other/gitleaks.sarif`, 'gitleaks', 'sarif', GATE));   // another artifact's folder
    bad(() => renderScrub(artifact, `\${{ runner.temp }}/pipegen-raw/${artifact}/../x.sarif`, 'gitleaks', 'sarif', GATE));
    bad(() => renderScrub(artifact, `\${{ runner.temp }}/pipegen-raw/${artifact}/a b.sarif`, 'gitleaks', 'sarif', GATE));
    bad(() => renderScrub(artifact, `\${{ runner.temp }}/pipegen-raw/${artifact}/x\n.sarif`, 'gitleaks', 'sarif', GATE));
    bad(() => renderScrub(artifact, '$RUNNER_TEMP/pipegen-raw/x/y.sarif', 'gitleaks', 'sarif', GATE));
    bad(() => renderScrub('secrets', raw, 'gitleaks', 'sarif', GATE));   // not a result artifact name
    bad(() => renderScrub(artifact, raw, 'gitleaks', 'none' as 'sarif', GATE));
    bad(() => renderScrub(artifact, raw, 'gitleaks', 'junit' as 'sarif', GATE));
    for (const id of ['', 'Git Leaks', 'a\nb', '${{ x }}', 'x'.repeat(80)]) bad(() => renderScrub(artifact, raw, id, 'sarif', GATE));
    bad(() => renderScrub(artifact, raw, 'gitleaks', 'sarif', entry('gitleaks')));   // not an action entry
    const other = gateEntry();
    (other.step.action as { uses: string }).uses = `someone/else@${GATE_SHA}`;
    bad(() => renderScrub(artifact, raw, 'gitleaks', 'sarif', other));
    const moved = gateEntry();
    (moved.step.action as { uses: string }).uses = `crisworking/pipegen/gate@${'2'.repeat(40)}`;
    bad(() => renderScrub(artifact, raw, 'gitleaks', 'sarif', moved));   // not the reviewed pin
    const sub = gateEntry();
    (sub.step.action as { uses: string }).uses = `crisworking/pipegen/watcher@${GATE_SHA}`;
    bad(() => renderScrub(artifact, raw, 'gitleaks', 'sarif', sub));   // another action of the repo
  });

  it('renderScrub: a gate entry that fixes an input or offers a choice is refused (the renderer sets every input)', () => {
    const fixed = gateEntry();
    fixed.fixedInputs = { with: { mode: 'gate' } };
    (fixed.step.action as { with: Record<string, string> }).with = { mode: 'gate' };
    expect(() => renderScrub(artifact, raw, 'gitleaks', 'sarif', fixed)).toThrow(RenderError);
    const choice = gateEntry();
    choice.choices = { mode: ['scrub'] };
    expect(() => renderScrub(artifact, raw, 'gitleaks', 'sarif', choice)).toThrow(RenderError);
  });
});

// ---------- RENDERER_INPUTS ----------

describe('RENDERER_INPUTS: the gate action in scrub mode (ruling B1 part 2)', () => {
  const GATE_USES = 'crisworking/pipegen/gate';
  const art = 'pipegen-out-secrets';
  const good: Record<string, string> = {
    mode: 'scrub', artifact: art, tool: 'gitleaks', format: 'sarif',
    raw: `\${{ runner.temp }}/pipegen-raw/${art}/gitleaks.sarif`, out: `\${{ runner.temp }}/pipegen-out/${art}/gitleaks.sarif`, 'fp-key': FP,
  };
  const problems = (over: Record<string, string | null> = {}): string[] => {
    const all = Object.fromEntries(Object.entries({ ...good, ...over }).filter((e): e is [string, string] => e[1] !== null));
    return rendererInputProblems(GATE_USES, all);
  };

  it('RENDERER_INPUTS: the exact scrub step passes', () => {
    expect(problems()).toEqual([]);
  });

  it('RENDERER_INPUTS: raw only ${{ runner.temp }}/pipegen-raw/<artifact>/<file>, out only pipegen-out/<artifact>/<file>, both naming with.artifact', () => {
    const rawBase = '${{ runner.temp }}/pipegen-raw';
    const outBase = '${{ runner.temp }}/pipegen-out';
    for (const raw of [`${outBase}/${art}/gitleaks.sarif`, `${rawBase}/pipegen-out-other/gitleaks.sarif`, `${rawBase}/${art}`, `${rawBase}/${art}/`, `${rawBase}/${art}/../gitleaks.sarif`, `${rawBase}/${art}/a b`, `${rawBase}/${art}/x\n`, '$RUNNER_TEMP/pipegen-raw/x/y', `${rawBase}/${art}/a/b/c/d/e`, '/etc/passwd', `${rawBase}/${art}/gitleaks.sarif${' }}'}`]) {
      expect(problems({ raw }), JSON.stringify(raw)).not.toEqual([]);
    }
    for (const out of [`${rawBase}/${art}/gitleaks.sarif`, `${outBase}/pipegen-out-other/gitleaks.sarif`, `${outBase}/${art}`, `${outBase}/${art}/other.sarif`, `${outBase}/${art}/../gitleaks.sarif`, '/tmp/x']) {
      expect(problems({ out }), JSON.stringify(out)).not.toEqual([]);   // out must also name the same file as raw
    }
    expect(problems({ artifact: 'pipegen-out-secrets2' })).not.toEqual([]);   // both paths name another artifact
  });

  it('RENDERER_INPUTS: fp-key only ${{ secrets.PIPEGEN_FP_KEY }}', () => {
    for (const v of [ref('GITHUB_TOKEN'), ref('PIPEGEN_COSIGN_KEY'), ref('STRIPE_KEY'), 'literal', '', `${FP} `, `x${FP}`, `${FP}${FP}`, '${{ vars.PIPEGEN_FP_KEY }}', FP.toLowerCase()]) {
      expect(problems({ 'fp-key': v }), JSON.stringify(v)).not.toEqual([]);
    }
  });

  it('RENDERER_INPUTS: mode, artifact, tool and format are checked', () => {
    expect(problems({ mode: 'scrub2' })).not.toEqual([]);
    expect(problems({ mode: '' })).not.toEqual([]);
    expect(problems({ artifact: 'secrets' })).not.toEqual([]);
    expect(problems({ artifact: `${art}\n` })).not.toEqual([]);
    for (const tool of ['Git Leaks', 'a;b', '', '${{ x }}', 'x'.repeat(80), '../x']) expect(problems({ tool }), tool).not.toEqual([]);
    for (const format of ['none', 'junit', 'json', 'SARIF', '']) expect(problems({ format }), format).not.toEqual([]);
    expect(problems({ format: 'zap-json' })).toEqual([]);
    expect(rendererInputProblems(GATE_USES, { sarif: 'x' })).not.toEqual([]);   // an input the table does not know
  });

  it('RENDERER_INPUTS: the scrub inputs are allowed only when mode is scrub (whenWith on mode)', () => {
    for (const k of ['artifact', 'tool', 'format', 'raw', 'out']) {
      const all = { ...good, mode: 'gate' };
      expect(rendererInputProblems(GATE_USES, { [k]: good[k] as string }, all), k).not.toEqual([]);
    }
    // the key is also a gate input (it checks the baseline's MAC, ruling B6): allowed under mode gate, refused under find-run (nightly verifies the baseline too since C7)
    expect(rendererInputProblems(GATE_USES, { 'fp-key': good['fp-key'] as string }, { ...good, mode: 'gate' }), 'fp-key under gate').toEqual([]);
    for (const mode of ['find-run']) expect(rendererInputProblems(GATE_USES, { 'fp-key': good['fp-key'] as string }, { ...good, mode }), `fp-key under ${mode}`).not.toEqual([]);
    expect(rendererInputProblems(GATE_USES, { mode: 'gate' }, { mode: 'gate' })).toEqual([]);
  });
});

// ---------- the order rule ----------

/** The problem checkJobOrder reports for an upload with no scrub step of its result before it (not the step name "pipegen: scrub the result"). */
const NO_SCRUB = /but no scrub step for that result comes before it/;
describe('isKnownHarmless and the job order: the scrub step (ruling B1 part 3)', () => {
  const art = 'pipegen-out-secrets';
  const scrub = (): RenderedStep => renderScrub(art, `\${{ runner.temp }}/pipegen-raw/${art}/gitleaks.sarif`, 'gitleaks', 'sarif', GATE);
  const repoCode: RenderedStep = { name: 'mine', run: 'true' };
  // C0b: a scrub must follow the scan step of its result (tool-run-<sha16(artifact)>); a stub stands for the tool's run step here
  const scan: RenderedStep = { id: `tool-run-${sha16(art)}`, name: 'scan', run: 'true' };

  it('isKnownHarmless: a scrub id is harmless only on the pinned gate action with mode scrub; on a run step or another action it is repo code', () => {
    const s = scrub();
    expect(isKnownHarmless(s)).toBe(true);
    expect(isKnownHarmless({ ...s, with: { ...s.with, mode: 'gate' } })).toBe(false);
    const { mode: _m, ...noMode } = s.with as Record<string, string>;
    expect(isKnownHarmless({ ...s, with: noMode })).toBe(false);
    expect(isKnownHarmless({ ...s, with: undefined })).toBe(false);
    expect(isKnownHarmless({ ...s, uses: `crisworking/pipegen/watcher@${GATE_SHA}` })).toBe(false);
    expect(isKnownHarmless({ ...s, uses: `crisworking/pipegen/gate@v1` })).toBe(false);
    expect(isKnownHarmless({ ...s, uses: `crisworking/pipegen/gate@${'A'.repeat(40)}` })).toBe(false);
    expect(isKnownHarmless({ ...s, uses: `someone/else@${GATE_SHA}` })).toBe(false);
    expect(isKnownHarmless({ ...s, uses: undefined, run: 'true', with: undefined })).toBe(false);   // a scrub id on a run step
    expect(isKnownHarmless({ ...s, run: 'true' })).toBe(false);   // uses and run together
    expect(isKnownHarmless({ ...s, id: 'scrub-123' })).toBe(false);
    expect(isKnownHarmless({ ...s, id: undefined })).toBe(false);   // the gate action under no scrub id is not on the harmless list
    expect(isKnownHarmless({ ...s, id: 'tool-run-0123456789abcdef' })).toBe(false);
  });

  it('checkJobOrder: a scrub step (and an upload after it) after repo code is refused; before it, fine', () => {
    const up = renderUpload(art, scrubbedPath(`\${{ runner.temp }}/pipegen-raw/${art}/gitleaks.sarif`), p);
    expect(checkJobOrder([...prelude(), scan, scrub(), up])).toEqual([]);
    expect(checkJobOrder([repoCode, scrub()]).length).toBeGreaterThan(0);
    expect(checkJobOrder([repoCode, { ...scrub(), id: 'scrub-0123456789abcdef', run: 'true', uses: undefined, with: undefined }])).toEqual([]);   // a run step that only claims the id is just more repo code
  });

  it('checkJobOrder: an upload of pipegen-out/<X> needs an earlier scrub step for X in the same job', () => {
    const rawPath = `\${{ runner.temp }}/pipegen-raw/${art}/gitleaks.sarif`;
    const outPath = scrubbedPath(rawPath);
    const up = renderUpload(art, outPath, p);
    expect(checkJobOrder([...prelude(), up]).join(' ')).toMatch(NO_SCRUB);
    expect(checkJobOrder([...prelude(), up, scrub()]).join(' ')).toMatch(NO_SCRUB);   // a scrub after the upload is too late
    const other = renderScrub('pipegen-out-sast', '${{ runner.temp }}/pipegen-raw/pipegen-out-sast/semgrep.sarif', 'semgrep', 'sarif', GATE);
    expect(checkJobOrder([...prelude(), other, up]).join(' ')).toMatch(NO_SCRUB);   // a scrub for another artifact
    const notScrub = { ...scrub(), with: { ...scrub().with, mode: 'gate' } as Record<string, string> };
    expect(checkJobOrder([...prelude(), notScrub, up]).join(' ')).toMatch(NO_SCRUB);
    // a step that merely names the artifact is not a scrub step either
    const names: RenderedStep = { id: 'pipegen-checkout', name: 'x', uses: `actions/checkout@${'c'.repeat(40)}`, with: { artifact: art } };
    expect(checkJobOrder([...prelude(), names, up]).join(' ')).toMatch(NO_SCRUB);
    expect(checkJobOrder([...prelude(), scan, scrub(), up])).toEqual([]);
    expect(() => dedupeJobSteps([...prelude(), up], { scans: scansFor([...prelude(), up]) })).toThrow(RenderError);
  });

  it('checkJobOrder: an upload of a pipegen-raw path is refused (also written by hand, past renderUpload)', () => {
    const rawUp: RenderedStep = { name: 'Upload', uses: `actions/upload-artifact@${'b'.repeat(40)}`, with: { name: art, path: `\${{ runner.temp }}/pipegen-raw/${art}/gitleaks.sarif` } };
    const problems = checkJobOrder([...prelude(), scan, scrub(), rawUp]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('uploads the raw result folder (pipegen-raw)');
    expect(() => renderUpload(art, `\${{ runner.temp }}/pipegen-raw/${art}/gitleaks.sarif`, p)).toThrow(RenderError);
    expect(() => renderPlatformStep('upload-artifact', p, { name: art, path: `\${{ runner.temp }}/pipegen-raw/${art}` })).toThrow(RenderError);
    expect(() => stepsToYaml([rawUp])).toThrow(RenderError);
  });
});

// ---------- the referee ----------

describe('referee: the scrub chain', () => {
  it('scrub chain: [checkout, tool, renderScrub, renderUpload] passes dedupeJobSteps, stepsToYaml and the referee with 0 issues (probe S1)', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    expect(() => dedupeJobSteps(steps, { scans: scansFor(steps) })).not.toThrow();
    expect(() => stepsToYaml(steps)).not.toThrow();
    const r = await run([workflow({ scan: job(dedupeJobSteps(steps, { scans: scansFor(steps) })) })], draftOf([spec]));
    expect(show(r)).toBe('');
    expect(r.issues).toEqual([]);
  });

  it('scrub chain: a base-scan job (artifact pipegen-out-base-…) is also clean', async () => {
    const spec = gitleaksSpec();
    const { steps, artifact } = scannerSteps(spec, { ...ctx, base: true });
    expect(artifact).toBe('pipegen-out-base-secrets');
    // the PR-side scan of the same check sits in its own job; the base-scan job holds the target branch's twin of it
    const pr = scannerSteps(spec).steps;
    // the base-scan job checks out the base commit, as its first step (C0b fix round 1)
    const baseSteps = [{ ...(steps[0] as RenderedStep), with: { ...steps[0]?.with, ref: BASE_CHECKOUT_REF } }, ...steps.slice(1)];
    const r = await run([workflow({ scan: job(dedupeJobSteps(pr, { scans: scansFor(pr) })), 'base-scan': job(dedupeJobSteps(baseSteps, { id: 'base-scan', scans: scansFor(baseSteps) })) })], draftOf([spec]));
    expect(show(r)).toBe('');
  });

  it('referee: gate action with mode scrub → kind scrub (not allowed where the policy row has no scrub); with mode gate in a scanner job → refused', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    const asGate = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, with: { mode: 'gate' } } : s));
    // mode gate, still under a scrub id: it is the gate action, which runs only in its own job
    const r1 = await run([workflow({ scan: job(asGate) }, true)], draftOf([spec]));
    expect(r1.issues.some((i) => i.check === 'permissions' && /gate action runs only in its own job/.test(i.message)), show(r1)).toBe(true);
    // mode scrub in the gate job: its row lists gate, not scrub
    const scrubOnly = steps.filter((s) => s.id?.startsWith('scrub-'));
    const r2 = await run([workflow({ gate: job([...prelude(), ...scrubOnly]) })], draftOf([spec]));
    expect(r2.issues.some((i) => i.check === 'permissions' && /scrub step/.test(i.message)), show(r2)).toBe(true);
    expect(JOB_STEP_POLICY['base-scan']).toContain('scrub');
    expect(JOB_STEP_POLICY.gate).not.toContain('scrub');
  });

  it('referee: a scrub id on a gate step without mode scrub, or on a step with a gate mode of another case, is not a scrub step', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    for (const mode of ['Scrub', 'scrub ', 'gate', 'nightly']) {
      const bent = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, with: { ...s.with, mode } } : s));
      const r = await run([workflow({ scan: job(bent) }, true)], draftOf([spec]));
      expect(r.ok, mode).toBe(false);
    }
  });

  it('referee: PIPEGEN_FP_KEY on a recognised scrub step does not make the job privileged; on any other step it does', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    const ok = await run([workflow({ scan: job(steps) })], draftOf([spec]));
    expect(ok.issues.filter((i) => i.check === 'permissions')).toEqual([]);
    // the same key on a gate-mode step in the same kind of job: the job holds power and has no row
    const gateStep: RenderedStep = { name: 'gate', uses: `crisworking/pipegen/gate@${GATE_SHA}`, with: { mode: 'gate', 'fp-key': FP } };
    const bad = await run([workflow({ scan: job([...prelude(), gateStep]) }, true)], draftOf([spec]));
    expect(bad.issues.some((i) => i.check === 'permissions' && /holds power/.test(i.message)), show(bad)).toBe(true);
  });

  it('referee: PIPEGEN_FP_KEY on a run step → injection; on a scrub step under another input name, or with the workflow token instead, → refused', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    const runStep = steps.find((s) => s.run !== undefined && s.id?.startsWith('tool-run-')) as RenderedStep;
    const withKey = steps.map((s) => (s === runStep ? { ...s, env: { ...s.env, PIPEGEN_FP_KEY: FP } } : s));
    const r1 = await run([workflow({ scan: job(withKey) }, true)], draftOf([spec]));
    expect(r1.issues.some((i) => i.check === 'injection'), show(r1)).toBe(true);
    const asEnv = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, env: { PIPEGEN_FP_KEY: FP } } : s));
    const r2 = await run([workflow({ scan: job(asEnv) }, true)], draftOf([spec]));
    expect(r2.ok, show(r2)).toBe(false);
    const wrongRef = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, with: { ...s.with, 'fp-key': OTHER_REF } as Record<string, string> } : s));
    const r3 = await run([workflow({ scan: job(wrongRef) }, true)], draftOf([spec]));
    expect(r3.issues.some((i) => i.check === 'injection' && /GITHUB_TOKEN/.test(i.message)), show(r3)).toBe(true);
    expect(r3.issues.some((i) => i.check === 'template'), show(r3)).toBe(true);
  });

  it('referee: an upload of a pipegen-raw path → template; upload of pipegen-out/<X> needs a scrub step for X earlier in the job', async () => {
    const spec = gitleaksSpec();
    const { steps, result } = scannerSteps(spec);
    const rawPath = (result.output as { path: string }).path;
    const upIdx = steps.findIndex((s) => s.name === 'Upload the result');
    const rawUpload: RenderedStep = { ...(steps[upIdx] as RenderedStep), with: { ...(steps[upIdx]?.with as Record<string, string>), path: rawPath } };
    const r1 = await run([workflow({ scan: job(steps.map((s, i) => (i === upIdx ? rawUpload : s))) }, true)], draftOf([spec]));
    expect(r1.issues.some((i) => i.check === 'template' && /path/.test(i.message)), show(r1)).toBe(true);
    const noScrub = steps.filter((s) => !s.id?.startsWith('scrub-'));
    const r2 = await run([workflow({ scan: job(noScrub) }, true)], draftOf([spec]));
    expect(r2.issues.some((i) => /scrub/.test(i.message)), show(r2)).toBe(true);
    expect(r2.ok).toBe(false);
    const late = [...noScrub, steps.find((s) => s.id?.startsWith('scrub-')) as RenderedStep];
    const r3 = await run([workflow({ scan: job(late) }, true)], draftOf([spec]));
    expect(r3.ok, show(r3)).toBe(false);
  });

  it('referee: if always() allowed on a scrub step, still refused on a tool step', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    expect(steps.find((s) => s.id?.startsWith('scrub-'))?.if).toBe('always()');
    const toolIdx = steps.findIndex((s) => s.id?.startsWith('tool-run-'));
    const r = await run([workflow({ scan: job(steps.map((s, i) => (i === toolIdx ? { ...s, if: 'always()' } : s))) }, true)], draftOf([spec]));
    expect(r.issues.some((i) => i.check === 'template' && /if:/.test(i.message)), show(r)).toBe(true);
    // and the scrub step with if: failure() or none at all: the first is not a form pipegen writes for it
    const failing = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, if: 'failure()' } : s));
    expect((await run([workflow({ scan: job(failing) }, true)], draftOf([spec]))).ok).toBe(false);
  });

  it('referee: a scrub step with an input the table does not know, or with its out moved, is refused (a second scrub for one artifact: C0b)', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    const extra = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, with: { ...s.with, 'sarif-in': 'x' } as Record<string, string> } : s));
    const r = await run([workflow({ scan: job(extra) }, true)], draftOf([spec]));
    expect(r.issues.some((i) => i.check === 'template'), show(r)).toBe(true);
    const moved = steps.map((s) => (s.id?.startsWith('scrub-') ? { ...s, with: { ...s.with, out: '${{ runner.temp }}/pipegen-out/pipegen-out-secrets/other.sarif' } as Record<string, string> } : s));
    expect((await run([workflow({ scan: job(moved) }, true)], draftOf([spec]))).ok).toBe(false);
  });
});

// ---------- render-cli ----------

const lastRun = (r: RenderResult): RenderedStep => r.steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;
/** A stand-in secrets tool's body: it writes its (empty) report at the path its --report-path names (C1c: outside the stage folder). */
const REPORT_AT_PATH = `prev=""\nfor a in "$@"; do if [ "$prev" = --report-path ]; then echo '{"runs":[]}' > "$a"; fi; prev="$a"; done\n`;
const RAW_FORMATS = ['sarif', 'zap-json', 'json'];   // (G15a-R7 spec 7: json is the licence scan's raw Trivy JSON, scrubbed to SARIF)

describe('render-cli: the raw result folder (ruling B1 part 1)', () => {
  it('render-cli: a sarif/zap-json tool\'s result goes to pipegen-raw/<artifact>; nothing of it reaches pipegen-out', () => {
    const r = renderStep(gitleaksSpec(), entry('gitleaks'), p, ctx);
    expect(r.output).toEqual({ path: '${{ runner.temp }}/pipegen-raw/pipegen-out-secrets/gitleaks.sarif', format: 'sarif' });
    const text = lastRun(r).run as string;
    expect(text).toContain('pipegen-raw/pipegen-out-secrets');
    expect(text).not.toContain('pipegen-out/');
    expect(text).not.toMatch(/pipegen-out\b(?!-)/);
    // and really: the file lands in pipegen-raw, read-only, and no pipegen-out folder is made
    const sb = sandbox();
    expect(stageWorkspace({ workspace: sb.ws, stage: join(sb.rt, 'pipegen-stage', 'pipegen-out-secrets') }).status).toBe('ok');   // C1c: the stage step ran
    fakeTool(sb, 'pipegen-out-secrets', 'gitleaks', REPORT_AT_PATH);
    expect(exec(lastRun(r), sb, stepEnv(lastRun(r), sb)).status).toBe(0);
    const dir = join(sb.rt, 'pipegen-raw', 'pipegen-out-secrets');
    expect(readFileSync(join(dir, 'gitleaks.sarif'), 'utf8')).toContain('"runs"');
    expect(statSync(dir).mode & 0o222).toBe(0);
    expect(existsSync(join(sb.rt, 'pipegen-out'))).toBe(false);
    expect(existsSync(join(sb.ws, 'gitleaks.sarif'))).toBe(false);
  });

  it('render-cli: the raw path cannot be uploaded by renderUpload, whatever the result format', () => {
    for (const id of ['gitleaks', 'trivy-config']) {
      const spec = specFor(entry(id), { needId: id === 'gitleaks' ? SCANNER_NEED : 'iac' });
      const out = renderStep(spec, entry(id), p, ctx).output;
      expect(out?.path).toContain('/pipegen-raw/');
      expect(() => renderUpload(resultArtifactName(spec.needId), out?.path as string, p), id).toThrow(RenderError);
    }
  });

  it('render-cli: a tool with no output (format none) is unchanged: no result folder at all', () => {
    const r = renderStep(specFor(entry('actionlint'), { needId: 'workflow-lint' }), entry('actionlint'), p, ctx);
    expect(r.output).toBeNull();
    expect(lastRun(r).run).not.toMatch(/pipegen-raw|pipegen-out\//);
  });
});

describe('ArgvPolicy.findingsExit (ruling B2)', () => {
  const FINDINGS: Record<string, readonly number[]> = {
    // trivy, betterleaks and gitleaks are told to report findings with 10: their errors (and betterleaks' partial scan) exit 1 (C0a fix round 1)
    'trivy-config': [10], 'trivy-image': [10], 'trivy-licence': [10], betterleaks: [10], gitleaks: [10], 'osv-scanner': [1], hadolint: [1], 'kube-linter': [1], 'zap-baseline': [1, 2], semgrep: [], nuclei: [],
  };
  it('findingsExit: every cli entry with a sarif or zap-json result has a list (as ruled), and no other entry has one', () => {
    const seen: string[] = [];
    for (const t of reviewedList().filter((e) => e.step.cli !== undefined)) {
      const pol = ARGV_POLICIES[t.id];
      const isFindings = RAW_FORMATS.includes(t.step.output.format);
      if (isFindings) {
        seen.push(t.id);
        expect(Array.isArray(pol?.findingsExit), t.id).toBe(true);
        if (Object.hasOwn(FINDINGS, t.id)) expect(pol?.findingsExit, t.id).toEqual(FINDINGS[t.id]);
        // exit 0 is success already; a findings code is a small positive exit code, and not a signal
        for (const c of pol?.findingsExit ?? []) expect(Number.isInteger(c) && c >= 1 && c <= 125, `${t.id} ${c}`).toBe(true);
      } else expect(pol?.findingsExit, t.id).toBeUndefined();
    }
    for (const id of Object.keys(FINDINGS)) expect(seen, id).toContain(id);
  });
});

/**
 * A stand-in for /usr/bin/docker (E9, E3-R7: create, copy in, start, copy out; no bind mount): `start` exits with the given code, and
 * `cp <ctr>:<path> <dest>` (the copy-out of the result) writes the result there when the tool "wrote" one, else fails like a missing file.
 */
function fakeDocker(sb: Sandbox, _file: string, code: number, writeResult = true): string {
  const path = join(sb.dir, 'docker-stub');
  writeFileSync(path, [
    '#!/bin/sh',
    'case "$1" in',
    `  start) exit ${code} ;;`,
    `  cp) if [ "$2" = "-a" ]; then exit 0; fi; ${writeResult ? `echo '{"runs":[]}' > "$3"; exit 0` : 'exit 1'} ;;`,
    'esac',
    'exit 0', '',
  ].join('\n'));
  chmodSync(path, 0o755);
  return path;
}

/** Every cli entry with a findings result that renders, with the run step and the fixture files its slots need. */
function renderableFindings(): { id: string; art: string; step: RenderedStep; exe: string; file: string; docker: boolean; findings: readonly number[] }[] {
  const out: ReturnType<typeof renderableFindings> = [];
  for (const t of reviewedList().filter((e) => e.step.cli !== undefined && RAW_FORMATS.includes(e.step.output.format))) {
    const spec = specFor(t, { needId: needFor(t), service: 'app' });
    let r: RenderResult;
    try { r = renderStepWith(spec, t, p, ctx); } catch (e) { if (e instanceof RenderError) continue; throw e; }
    const pol = ARGV_POLICIES[t.id];
    out.push({ id: t.id, art: resultArtifactName(spec.needId, 'app'), step: lastRun(r), exe: pol?.exe ?? '', file: t.step.output.path, docker: pol?.method === 'docker', findings: pol?.findingsExit ?? [] });
  }
  return out;
}

describe('render-cli: a findings exit code is not a failed step (ruling B2), real bash', () => {
  /** Runs the entry's run step against a stub tool that writes its result and exits with `code`. */
  function runWith(e: ReturnType<typeof renderableFindings>[number], code: number, writeResult = true): { status: number | null; sb: Sandbox } {
    const sb = sandbox();
    writeFileSync(join(sb.ws, 'Dockerfile'), 'FROM scratch\n');
    mkdirSync(join(sb.ws, 'k8s'));
    for (const rules of ['javascript', 'typescript', 'python']) mkdirSync(join(sb.rt, 'pipegen-rules', e.art, rules), { recursive: true });   // the verified rules archive of semgrep, made by an earlier step
    let step = e.step;
    if (e.docker) {
      const docker = fakeDocker(sb, e.file, code, writeResult);
      step = { ...step, run: (step.run as string).replaceAll('/usr/bin/docker', docker) };
    } else if (ARGV_POLICIES[e.id]?.staged !== undefined) {
      // C1c: a secrets scan runs in the stage folder its stage step filled, and writes its report where --report-path says (outside it)
      expect(stageWorkspace({ workspace: sb.ws, stage: join(sb.rt, 'pipegen-stage', e.art) }).status).toBe('ok');
      fakeTool(sb, e.art, e.exe, `${writeResult ? REPORT_AT_PATH : ''}exit ${code}`);
    } else fakeTool(sb, e.art, e.exe, `${writeResult ? `echo '{"runs":[]}' > ./${e.file}\n` : ''}exit ${code}`);
    return { status: exec(step, sb, stepEnv(step, sb)).status, sb };
  }
  const rawFile = (sb: Sandbox, e: ReturnType<typeof renderableFindings>[number]): string => join(sb.rt, 'pipegen-raw', e.art, e.file);

  it('render-cli: findings exit code with a regular result → step passes, result in pipegen-raw; any other exit → result deleted, step fails (every findings entry)', () => {
    const entries = renderableFindings();
    expect(entries.map((e) => e.id)).toEqual(expect.arrayContaining(['gitleaks', 'betterleaks', 'osv-scanner', 'trivy-config', 'trivy-image', 'trivy-licence', 'hadolint', 'kube-linter', 'semgrep', 'nuclei', 'zap-baseline']));
    for (const e of entries) {
      const ok = runWith(e, 0);
      expect(ok.status, `${e.id}: exit 0`).toBe(0);
      expect(existsSync(rawFile(ok.sb, e)), `${e.id}: exit 0 moves the result`).toBe(true);
      for (const code of e.findings) {
        const f = runWith(e, code);
        expect(f.status, `${e.id}: findings exit ${code}`).toBe(0);
        expect(existsSync(rawFile(f.sb, e)), `${e.id}: findings exit ${code} moves the result`).toBe(true);
        expect(existsSync(join(f.sb.ws, e.file)), `${e.id}: the workspace file is gone`).toBe(false);
        expect(existsSync(join(f.sb.rt, 'pipegen-out')), `${e.id}: nothing in pipegen-out`).toBe(false);
        const none = runWith(e, code, false);   // a findings code and no result file at all: the scan did not work
        expect(none.status, `${e.id}: findings exit ${code}, no file`).not.toBe(0);
      }
      for (const code of [3, 99, 137]) {
        const err = runWith(e, code);
        expect(err.status, `${e.id}: error exit ${code}`).toBe(code);
        expect(existsSync(rawFile(err.sb, e)), `${e.id}: error exit ${code}: no result kept`).toBe(false);
        expect(existsSync(join(err.sb.ws, e.file)), `${e.id}: error exit ${code}: workspace result deleted`).toBe(false);
        expect(existsSync(join(err.sb.rt, 'pipegen-raw')), `${e.id}: error exit ${code}: no raw folder`).toBe(false);
      }
      if (!e.findings.includes(1)) {
        const one = runWith(e, 1);   // 1 is an error for semgrep and nuclei
        expect(one.status, `${e.id}: exit 1`).toBe(1);
        expect(existsSync(rawFile(one.sb, e)), `${e.id}: exit 1 keeps nothing`).toBe(false);
      }
    }
  });

  it('render-cli (C1a fix round 1): nuclei exits 0 and writes NO file when nothing matched; then, and only then, the step writes the marked empty result the gate reads as "nothing reported"', () => {
    const e = renderableFindings().find((x) => x.id === 'nuclei') as ReturnType<typeof renderableFindings>[number];
    const none = runWith(e, 0, false);
    expect(none.status).toBe(0);
    const marked = readFileSync(rawFile(none.sb, e), 'utf8');
    expect(marked.trim()).toBe(NUCLEI_EMPTY_SARIF);
    expect(JSON.parse(marked)).toEqual({ version: '2.1.0', runs: [{ tool: { driver: { name: SYNTHESIZED_NUCLEI.driver } }, results: [], properties: { pipegenSynthesized: SYNTHESIZED_NUCLEI.mark } }] });
    expect(existsSync(join(none.sb.ws, e.file)), 'the workspace file is moved, not copied').toBe(false);
    expect(existsSync(join(none.sb.rt, 'pipegen-out'))).toBe(false);
    // the gate's parser accepts exactly that file for nuclei only
    expect(parseSarifText(marked, 'nuclei')).toEqual({ findings: [], notes: ['nothing reported (synthesized empty result)'] });
    expect(parseSarifText(marked, 'semgrep').toolError).toBeDefined();
  });

  it('render-cli (C1b part 0, m4): a link the tool left at the result path (dangling, exit 0) is never written through; the step fails and the link target stays absent', () => {
    const e = renderableFindings().find((x) => x.id === 'nuclei') as ReturnType<typeof renderableFindings>[number];
    const sb = sandbox();
    const target = join(sb.dir, 'written-through-the-link');
    fakeTool(sb, e.art, e.exe, `ln -s ${JSON.stringify(target)} ./${e.file}\nexit 0`);
    const r = exec(e.step, sb, stepEnv(e.step, sb));
    expect(r.status, 'a link at the result path fails the step').not.toBe(0);
    expect(existsSync(target), 'nothing was written through the dangling link').toBe(false);
    expect(existsSync(join(sb.rt, 'pipegen-raw', e.art, e.file))).toBe(false);
  });

  it('render-cli (C1a fix round 1): nuclei\'s own file is never overwritten; any other exit with no file still fails and writes nothing; no other tool gets a synthesized file', () => {
    const entries = renderableFindings();
    const nuclei = entries.find((x) => x.id === 'nuclei') as ReturnType<typeof renderableFindings>[number];
    const own = runWith(nuclei, 0);
    expect(own.status).toBe(0);
    expect(readFileSync(rawFile(own.sb, nuclei), 'utf8').trim()).toBe('{"runs":[]}');
    for (const code of [1, 3, 99, 137]) {
      const r = runWith(nuclei, code, false);
      expect(r.status, `nuclei exit ${code}, no file`).toBe(code);
      expect(existsSync(join(r.sb.rt, 'pipegen-raw')), `nuclei exit ${code}: nothing written`).toBe(false);
    }
    for (const e of entries.filter((x) => x.id !== 'nuclei')) {
      const r = runWith(e, 0, false);
      expect(r.status, `${e.id}: exit 0 and no file is still a failed scan`).not.toBe(0);
      expect(existsSync(rawFile(r.sb, e)), `${e.id}: no synthesized result`).toBe(false);
    }
  });

  it('render-cli (C1a fix round 1, pinned): osv-scanner exit 127 (one unparsable lockfile) leaves an EMPTY sarif on disk; the result is deleted and the step fails with 127', () => {
    const e = renderableFindings().find((x) => x.id === 'osv-scanner') as ReturnType<typeof renderableFindings>[number];
    const sb = sandbox();
    const empty = '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"osv-scanner"}},"invocations":[],"results":[]}]}';
    fakeTool(sb, e.art, e.exe, `printf '%s' '${empty}' > ./${e.file}\nexit 127`);
    expect(exec(e.step, sb, stepEnv(e.step, sb)).status).toBe(127);
    expect(existsSync(rawFile(sb, e))).toBe(false);
    expect(existsSync(join(sb.ws, e.file))).toBe(false);
    expect(existsSync(join(sb.rt, 'pipegen-raw'))).toBe(false);
    // and exit 128 (no package source, no file) fails too
    const sb2 = sandbox();
    fakeTool(sb2, e.art, e.exe, 'exit 128');
    expect(exec(e.step, sb2, stepEnv(e.step, sb2)).status).toBe(128);
  });

  it('render-cli: a findings exit with a result that is a link, a folder or missing fails the step and keeps nothing', () => {
    const t = entry('gitleaks');
    const r = renderStepWith(gitleaksSpec(), t, p, ctx);
    const step = lastRun(r);
    for (const make of [(sb: Sandbox) => { writeFileSync(join(sb.dir, 'secret.txt'), 'top secret'); return `ln -s ${join(sb.dir, 'secret.txt')} ./gitleaks.sarif`; }, () => 'mkdir ./gitleaks.sarif']) {
      const sb = sandbox();
      fakeTool(sb, 'pipegen-out-secrets', 'gitleaks', `${make(sb)}\nexit 1`);
      expect(exec(step, sb, stepEnv(step, sb)).status).not.toBe(0);
      expect(existsSync(join(sb.rt, 'pipegen-raw', 'pipegen-out-secrets', 'gitleaks.sarif'))).toBe(false);
    }
  });

  it('render-cli: a format-none tool still fails on a non-zero exit', () => {
    for (const [id, needId, exe] of [['actionlint', 'workflow-lint', 'actionlint'], ['zizmor', 'workflow-lint', 'zizmor']] as const) {
      const spec = specFor(entry(id), { needId });
      const step = lastRun(renderStepWith(spec, entry(id), p, ctx));
      const art = resultArtifactName(needId);
      for (const code of [1, 2, 99]) {
        const sb = sandbox();
        fakeTool(sb, art, exe, `exit ${code}`);
        expect(exec(step, sb, stepEnv(step, sb)).status, `${id} exit ${code}`).toBe(code);
      }
      const sb = sandbox();
      fakeTool(sb, art, exe, 'exit 0');
      expect(exec(step, sb, stepEnv(step, sb)).status, `${id} exit 0`).toBe(0);
    }
  });
});

// ---------- the parity test, extended ----------

describe('the renderer and the referee agree: a full scanner job per findings tool', () => {
  it('parity: [harden, checkout, tool, scrub, upload] for every renderable findings tool gives no issue', async () => {
    const jobs: Record<string, Job> = {};
    const specs: StepSpec[] = [];
    const harden = renderStep(specFor(entry('bullfrog'), { needId: 'egress' }), entry('bullfrog'), p, ctx).steps;
    // several tools share a need (two DAST tools): one result artifact is uploaded once per file, so each later tool of a need gets a service of its own
    const ctxN: RenderContext = { ...ctx, profile: { ...prof, services: [svc, ...Array.from({ length: 12 }, (_, i) => ({ ...svc, name: `app${i + 2}` }))] } };
    const perNeed = new Map<string, number>();
    // G4-R1: the DAST tools run in their own key-free run job and are scrubbed in another (test/jobs-dast.test.ts), never one job
    for (const t of reviewedList().filter((e) => RAW_FORMATS.includes(e.step.output.format) && !e.categories.includes('dast'))) {
      const nth = (perNeed.get(needFor(t)) ?? 0) + 1;
      perNeed.set(needFor(t), nth);
      const spec = specFor(t, { needId: needFor(t), service: nth === 1 ? 'app' : `app${nth}` });
      let built: ReturnType<typeof scannerSteps>;
      try { built = scannerSteps(spec, ctxN); } catch (e) { if (e instanceof RenderError) continue; throw e; }
      specs.push(spec);
      jobs[`t-${t.id}`] = job(dedupeJobSteps([...harden, ...built.steps], { scans: scansFor([...harden, ...built.steps]) }));
    }
    expect(specs.map((s) => s.tool.id)).toEqual(expect.arrayContaining(['gitleaks', 'betterleaks', 'semgrep', 'osv-scanner', 'trivy-config', 'trivy-image', 'trivy-licence', 'hadolint', 'kube-linter', 'semgrep']));
    // without the harden step too (the job shape of Plan G's scanner jobs differs by the egress policy)
    const plain: Record<string, Job> = {};
    for (const s of specs) plain[`u-${s.tool.id}`] = job(dedupeJobSteps(scannerSteps(s, ctxN).steps, { scans: scansFor(scannerSteps(s, ctxN).steps) }));
    const r = await run([workflow(jobs), workflow(plain)].map((f, i) => ({ ...f, path: `.github/workflows/pipegen-${i}.yml` })), { ...draftOf(specs), profile: ctxN.profile });
    expect(show(r)).toBe('');
  });
});

// ---------- fix round 1, finding 1: the fingerprint key never shares a job with repo code ----------

const KEY_JOB = /holds the fingerprint key/;
describe('a job with a scrub step holds no repo code (C0a fix round 1, finding 1)', () => {
  const repoCodeSteps = (id: string, needId: string): RenderedStep[] => {
    const t = entry(id);
    return renderStep(specFor(t, { needId, service: 'app' }), t, p, ctx).steps;
  };
  const AFTER: [string, string][] = [['prettier', 'format'], ['knip', 'dead-code'], ['vitest-coverage', 'coverage']];

  it('checkJobOrder and dedupeJobSteps refuse repo code after the scrub and upload (prettier, knip, vitest-coverage with its npm ci, a hand step)', () => {
    const { steps } = scannerSteps(gitleaksSpec());
    for (const [id, needId] of AFTER) {
      const more = repoCodeSteps(id, needId);
      expect(more.some((x) => x.id !== undefined && /^(?:repocode-|pipegen-npm-ci-)/.test(x.id)), id).toBe(true);
      expect(checkJobOrder([...steps, ...more]).join('\n'), id).toMatch(KEY_JOB);
      expect(() => dedupeJobSteps([...steps, ...more], { scans: scansFor([...steps, ...more]) }), id).toThrow(KEY_JOB);
    }
    expect(checkJobOrder([...steps, { name: 'mine', run: 'true' }]).join('\n')).toMatch(KEY_JOB);
    expect(checkJobOrder([...steps, { name: 'mine', uses: `someone/else@${'d'.repeat(40)}` }]).join('\n')).toMatch(KEY_JOB);
  });

  it('checkJobOrder: repo code before the scrub is refused too (the key is in the job from its start), and says so', () => {
    const { steps } = scannerSteps(gitleaksSpec());
    const scrubAt = steps.findIndex(isScrubStep);
    const problems = checkJobOrder([...steps.slice(0, 1), { name: 'mine', run: 'true' }, ...steps.slice(1)]);
    expect(problems.join('\n')).toMatch(KEY_JOB);
    expect(scrubAt).toBeGreaterThan(0);
  });

  it('checkJobOrder: a clean scanner job (several checkers, scrubs and uploads) passes; a job with no scrub may hold repo code', () => {
    const a = scannerSteps(gitleaksSpec());
    const b = scannerSteps(specFor(entry('semgrep'), { needId: 'sast', service: 'app', choices: { rules: 'javascript' } }));
    expect(checkJobOrder(dedupeJobSteps([...a.steps, ...b.steps.slice(1)], { scans: scansFor([...a.steps, ...b.steps.slice(1)]) }))).toEqual([]);
    expect(checkJobOrder([...prelude(), ...repoCodeSteps('vitest-coverage', 'coverage')])).toEqual([]);
  });

  it('referee: the reviewer\'s job [checkout, gitleaks, scrub, upload, repo code] is refused for prettier, knip and vitest-coverage, and for a hand-written step', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    for (const [id, needId] of [...AFTER, ['hand', 'x']] as [string, string][]) {
      const more: RenderedStep[] = id === 'hand' ? [{ name: 'mine', run: 'true', shell: 'bash' }] : repoCodeSteps(id, needId);
      // the extra tool is in the draft, so the referee recognises its steps and the refusal is the key rule, not "not rendered"
      const extra = id === 'hand' ? [] : [specFor(entry(id), { needId, service: 'app' })];
      const r = await run([workflow({ scan: job([...steps, ...more]) }, true)], draftOf([spec, ...extra]));
      expect(r.ok, id).toBe(false);
      expect(r.issues.some((i) => i.check === 'injection' && KEY_JOB.test(i.message)), `${id}: ${show(r)}`).toBe(true);
      // and the exemption is gone: the job holds the key next to repo code, so it counts as privileged and has no row
      expect(r.issues.some((i) => i.check === 'permissions' && /holds power/.test(i.message)), `${id}: ${show(r)}`).toBe(true);
    }
  });

  it('referee: the same key in a clean scanner job stays unprivileged (the exemption holds without repo code)', async () => {
    const spec = gitleaksSpec();
    const r = await run([workflow({ scan: job(scannerSteps(spec).steps) })], draftOf([spec]));
    expect(show(r)).toBe('');
  });
});

describe('guards of the scrub chain that a second layer used to hide (C0a fix round 1, finding 4)', () => {
  const art = 'pipegen-out-secrets';
  const GATE_USES = 'crisworking/pipegen/gate';
  it('RENDERER_INPUTS: raw naming another artifact with no out is refused on its own', () => {
    const problems = rendererInputProblems(GATE_USES, { raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-sast/semgrep.sarif' }, { mode: 'scrub', artifact: art, raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-sast/semgrep.sarif' });
    expect(problems.join(' ')).toMatch(/inside the folder of the artifact it names/);
  });

  it('referee: another reviewed entry that runs the gate path is not a scrub step (kind comes from the gate entry id)', async () => {
    const spec = gitleaksSpec();
    const { steps } = scannerSteps(spec);
    const twin = { ...gateEntry(), id: 'pipegen-watcher' };   // same uses path and pin, another entry
    twin.candidate = { ...twin.candidate, id: 'pipegen-watcher', name: 'pipegen-watcher' };
    const files = [workflow({ scan: job(steps) })];
    const r = await referee(files, draftOf([spec]), p, [...reviewedList(), twin], LINTERS, 'tok', { runLinters: async () => [] });
    expect(r.issues.some((i) => i.check === 'permissions' && /watcher action runs only in its own job/.test(i.message)), show(r)).toBe(true);
  });
});
