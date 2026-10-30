// Plan B Task 6d: the referee accepts a tuned config only when it equals what the renderer produces from the same draft
// (one source of truth: the referee re-renders every draft step, tuning included). Written AFTER the tuning code, which the referee
// needed no change for; each tamper below is mutation-checked (a tamper must hit the env value or the script, not only the # tuning: comment).
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { referee, type Linters, type RefereeReport } from '../src/engine/referee.js';
import { renderJobPrelude, renderStep, stepsToYaml, type RenderContext, type RenderedStep } from '../src/engine/render-step.js';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { renderScrub, renderUpload, scrubbedPath } from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, StepSpec } from '../src/types.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';

const api = service({
  name: 'api', path: 'services/api', dockerfile: 'services/api/Dockerfile',
  scripts: ['start', 'test', 'lint', 'format:check'], quality: { ...emptyServiceQuality(), tsconfig: true },
});
const prof = { ...profile([api]), generatedDirs: ['services/api/dist', 'services/api/src/generated'], repoFiles: emptyRepoFiles() };
const ctx: RenderContext = { profile: prof, targets: { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' } };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const LINTERS: Linters = { actionlint: async () => '/stub/actionlint', zizmor: async () => '/stub/zizmor' };

const specOf = (id: string, needId: string, tuning: Record<string, string[]> | undefined, over: Partial<StepSpec> = {}): StepSpec =>
  specFor(entry(id), { needId, service: 'api', workingDir: 'services/api', choices: tuning === undefined ? {} : { tuning }, ...over });
const needOf = (s: StepSpec): Need => ({ id: s.needId, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[s.needId] ?? s.needId, ...(s.service === undefined ? {} : { service: s.service }), why: 't', blocking: true, floor: false });
const draftOf = (steps: StepSpec[]): PipelineDraft => ({
  profile: prof, capabilities: caps, needs: steps.map(needOf), steps, created: [], notProven: [], testDecisions: [],
  layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const GATE = gateEntry();
/** One job as Plan G composes it: checkout, the tool, and the scrub and upload of a result unless the job ran repo code. */
function job(s: StepSpec): { steps: RenderedStep[] } {
  const t = entry(s.tool.id);
  const r = renderStep(s, t, platform(), ctx);
  const repoCode = r.steps.some((x) => x.id?.startsWith('repocode-') === true);
  const art = resultArtifactName(s.needId, s.service);
  const up = r.output !== null && !repoCode ? [renderScrub(art, r.output.path, s.tool.id, r.output.format as 'sarif', GATE), renderUpload(art, scrubbedPath(r.output.path), platform())] : [];
  return { steps: [...renderJobPrelude({ fetchDepth: r.fullHistory === true ? '0' : '1' }, platform()).steps, ...r.steps, ...up] };
}
function file(jobs: Record<string, RenderedStep[]>): CreatedFile {
  const doc = new Document();
  doc.contents = doc.createNode({
    name: 'pipegen', on: { pull_request: null }, permissions: {},
    jobs: Object.fromEntries(Object.keys(jobs).map((id) => [id, { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none' }])),
  });
  for (const [id, steps] of Object.entries(jobs)) doc.setIn(['jobs', id, 'steps'], stepsToYaml(steps));
  return { path: '.github/workflows/pipegen.yml', content: doc.toString({ lineWidth: 0 }), part: 'pipeline', reason: 'test', repo: 'app' };
}
const run = (f: CreatedFile, d: PipelineDraft): Promise<RefereeReport> => referee([f], d, platform(), [...reviewedList(), GATE], LINTERS, 'gh-stub', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const has = (r: RefereeReport, c: string): boolean => r.issues.some((i) => i.check === c);

const TUNED: StepSpec[] = [
  specOf('semgrep', 'sast', { 'extra-rules': ['typescript', 'dockerfile'], 'skip-generated': ['services/api/dist'] }),
  specOf('eslint', 'lint', { 'skip-generated': ['services/api/dist', 'services/api/src/generated'] }),
  specOf('oxlint-typeaware', 'lint', { 'skip-generated': ['services/api/dist'] }),
  specOf('lefthook', 'hooks-ci', { hooks: ['lint', 'format:check'] }),
];

describe('referee parity: a tuned draft, rendered and refereed, gives no issue', () => {
  it('every tuned tool rendered from the draft is accepted, tuning and all', async () => {
    const jobs = Object.fromEntries(TUNED.map((s) => [s.tool.id, job(s).steps]));
    const f = file(jobs);
    expect(f.content).toContain('# tuning:');
    const r = await run(f, draftOf(TUNED));
    expect(show(r)).toBe('');
    expect(r.ok).toBe(true);
  });

  it('a tuned tool whose draft is not tuned is a template issue (the file holds tuning the draft never picked)', async () => {
    const tuned = TUNED[1] as StepSpec;
    const f = file({ lint: job(tuned).steps });
    const r = await run(f, draftOf([{ ...tuned, choices: {} }]));
    expect(has(r, 'template'), show(r)).toBe(true);
  });

  it('a draft that is tuned while the file is not is a template issue (a tuning the file lost)', async () => {
    const tuned = TUNED[1] as StepSpec;
    const f = file({ lint: job({ ...tuned, choices: {} }).steps });
    const r = await run(f, draftOf([tuned]));
    expect(has(r, 'template'), show(r)).toBe(true);
  });
});

describe('referee: tampering with one tuned value in the file is a template issue', () => {
  const tamper = async (specIdx: number, from: string | RegExp, to: string): Promise<RefereeReport> => {
    const s = TUNED[specIdx] as StepSpec;
    const f = file({ j: job(s).steps });
    const changed = f.content.replace(from, to);
    expect(changed, `the tamper "${String(from)}" did not apply`).not.toBe(f.content);
    return run({ ...f, content: changed }, draftOf([s]));
  };

  it('a skipped folder changed', async () => {
    const r = await tamper(1, 'PIPEGEN_ARG_0: dist/**', 'PIPEGEN_ARG_0: src/**');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('an extra rule folder dropped from the mounts', async () => {
    const r = await tamper(0, ' -v "$rules/dockerfile:/pipegen-rules-extra/dockerfile:ro"', '');
    expect(has(r, 'template') || has(r, 'unreviewed'), show(r)).toBe(true);
  });
  it('an extra rule folder added that the draft never picked', async () => {
    const r = await tamper(0, 'dockerfile:/pipegen-rules-extra/dockerfile:ro', 'dockerfile:/pipegen-rules-extra/dockerfile:rw');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('the semgrep scope block removed (the repo\'s .semgrepignore and semgrep\'s defaults would decide the scope again)', async () => {
    const r = await tamper(0, /# pipegen scope: begin\n(?:\s*[^\n]*\n)+?\s*# pipegen scope: end\n\s*/, '');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('an oxlint skip value changed in the env (not the comment)', async () => {
    const r = await tamper(2, 'PIPEGEN_ARG_0: dist/**', 'PIPEGEN_ARG_0: src/**');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('a Semgrep skip anchor removed from the env: the bare name would skip every folder of that name', async () => {
    const r = await tamper(0, /PIPEGEN_ARG_(\d+): \/dist/, 'PIPEGEN_ARG_$1: dist');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('a generated hook command changed', async () => {
    const r = await tamper(3, 'npm run lint', 'npm run evil');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
  it('the tuning comment edited while the command stays the same is also refused (the script is compared as a whole)', async () => {
    const r = await tamper(1, 'skips the vendored or generated folders', 'skips the folders');
    expect(has(r, 'template'), show(r)).toBe(true);
  });
});

describe('referee: a draft whose tuning is outside the enums renders nothing', () => {
  it('a hostile tuning value in the draft is not rendered, so no step may claim to be that tool\'s', async () => {
    const good = TUNED[1] as StepSpec;
    const hostile = specOf('eslint', 'lint', { 'skip-generated': ['../../etc'] });
    const r = await run(file({ lint: job(good).steps }), draftOf([hostile]));
    expect(has(r, 'unreviewed') || has(r, 'template'), show(r)).toBe(true);
    expect(r.ok).toBe(false);
  });
});
