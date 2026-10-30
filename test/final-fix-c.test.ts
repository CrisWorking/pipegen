// v0.2 Plan B final-review fix round 2: the referee judges or refuses every created file path (R1), and a blocking spec's
// job counts only when its tool's own run step is in a file (R2). Probes are the final reviewer's P12 and P14.
import { describe, expect, it } from 'vitest';
import { referee, type Linters } from '../src/engine/referee.js';
import { createdPathProblem } from '../src/engine/job-rules.js';
import { renderJobPrelude, renderStep, stepsToYaml, type RenderContext, type RenderedStep } from '../src/engine/render-step.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { Document } from 'yaml';
import type { Capabilities, CreatedFile, Need, PipelineDraft, StepSpec } from '../src/types.js';
import { entry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';

const prof = profile([service({ name: 'api', path: '.' })]);
const ctx: RenderContext = { profile: prof };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const need = (id: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, why: 't', blocking: true, floor: false });
const draftOf = (steps: StepSpec[], needs: Need[]): PipelineDraft => ({ profile: prof, capabilities: caps, needs, steps, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [] });
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const p = platform();
const run = (files: CreatedFile[], d: PipelineDraft) => referee(files, d, p, reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });
const file = (path: string, content: string): CreatedFile => ({ path, content, part: 'pipeline', reason: 't', repo: 'app' });
const hostile = ['name: x', 'on: pull_request', 'permissions: {}', 'jobs:', '  j:', '    runs-on: self-hosted', '    steps:', '      - run: echo ${{ github.head_ref }}', ''].join('\n');

const BAD_PATHS = [
  './.github/workflows/x.yml',
  'tests/../.github/workflows/x.yml',
  '.github//workflows/x.yml',
  '.github/actions/../workflows/action.yml',
  `.github/workflows/${'a'.repeat(101)}.yml`,
  '/.github/workflows/x.yml',
  '.github\\workflows\\x.yml',
  '.github/workflows/x\u0000.yml',
  '.github/workflows/é.yml',
  '.GitHub/workflows/x.yml',
  '.GITHUB/Workflows/x.yml',
  '.github/workflows/x.txt',
  '.github/workflows/sub/x.yml',
];
describe('R1: every created file path is judged or refused', () => {
  for (const path of BAD_PATHS) {
    it(`refuses ${JSON.stringify(path.length > 60 ? `${path.slice(0, 40)}...` : path)}`, async () => {
      const r = await run([file(path, hostile)], draftOf([], []));
      expect(r.ok).toBe(false);
      expect(r.issues.some((i) => i.check === 'template' && /path/i.test(i.message))).toBe(true);
    });
  }
  it('createdPathProblem: normalized paths pass, outside .github/ stays outside the referee\'s scope', () => {
    for (const ok of ['.github/workflows/pipegen.yml', '.github/actions/x/action.yml', 'docs/CODEOWNERS', 'Dockerfile', '.pre-commit-config.yaml', '.zap/rules.tsv']) expect(createdPathProblem(ok), ok).toBeNull();
    for (const bad of ['', '.', '..', 'a/./b', 'a/../b', 'a//b', '/a', './a', 'a\\b', 'a\u0000b', 'café', 'a/']) expect(createdPathProblem(bad), JSON.stringify(bad)).not.toBeNull();
  });
  it('a normalized path outside .github/ that no created-file rule claims is refused (D0a, B1)', async () => {
    const r = await run([file('docs/notes.txt', hostile)], draftOf([], []));
    expect(r.issues.some((i) => i.check === 'template' && /no file of this kind/.test(i.message))).toBe(true);
  });
  it('a valid workflow path is still judged (the hostile file is refused for its content)', async () => {
    const r = await run([file('.github/workflows/x.yml', hostile)], draftOf([], []));
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => i.message !== '' && !/path/i.test(i.message))).toBe(true);
  });
});

describe('R2: a blocking spec counts only when its tool run step is in a file', () => {
  const prelude = (): RenderedStep[] => renderJobPrelude({ fetchDepth: '1' }, p).steps;
  function wf(steps: RenderedStep[]): CreatedFile {
    const doc = new Document();
    doc.contents = doc.createNode({ name: 'pipegen', on: { pull_request: null }, permissions: {}, jobs: { j: { 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none' } } });
    doc.setIn(['jobs', 'j', 'steps'], stepsToYaml(steps));
    return file('.github/workflows/pipegen.yml', doc.toString({ lineWidth: 0 }));
  }
  const gl = specFor(entry('gitleaks'), { needId: 'secrets' });
  it('P12 a job holding only the install step is not-gate-readable; with the run step it is accepted', async () => {
    const steps = renderStep(gl, entry('gitleaks'), p, ctx).steps;
    expect(steps.filter((s) => s.run !== undefined).length).toBeGreaterThan(1);
    const onlyInstall = await run([wf([...prelude(), ...steps.slice(0, -1)])], draftOf([gl], [need('secrets')]));
    expect(onlyInstall.issues.some((i) => i.check === 'not-gate-readable')).toBe(true);
    const full = await run([wf([...prelude(), ...steps])], draftOf([gl], [need('secrets')]));
    expect(full.issues.some((i) => i.check === 'not-gate-readable')).toBe(false);
  });
});
