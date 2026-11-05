// C1c, the engine half: the secrets job stages the checkout before it scans. The job is [harden?, checkout, stage (pipegen's gate
// action in mode `stage`), the scanner's install and run (cwd = the stage folder), scrub (with the stage), upload]. The referee and
// checkJobOrder know the stage step as the harmless pinned-gate kind `stage`, allowed only in a secrets job and before its scan.
// The ignore-file delete block of C1b fix round 2 is gone (ignore files are staged under neutral names like everything else); a belt
// in the run step refuses a stage folder that holds a file of those names. Written first (strict test-first).
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Document } from 'yaml';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkJobOrder, isKnownHarmless, isStageStep, type ScanFact } from '../src/engine/job-rules.js';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { referee, JOB_STEP_POLICY, type Linters, type RefereeReport } from '../src/engine/referee.js';
import {
  dedupeJobSteps, RenderError, renderFindingsBlock, renderJobPrelude, renderScrub, renderStage, renderStep, renderStepWith, stepsToYaml, type RenderContext, type RenderedStep,
} from '../src/engine/render-step.js';
import { ARGV_POLICIES, rendererInputProblems, stagePath, stageStepId, STAGE_STEP_ID_RE } from '../src/engine/tool-flags.js';
import { NEED_ID_CATEGORY } from '../src/engine/need-ids.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, Need, PipelineDraft, StepSpec } from '../src/types.js';
import { readScrubbed, scrubFile } from '../gate/src/scrub.js';
import { stageWorkspace } from '../gate/src/stage.js';
import { entry, gateEntry, platform, profile, reviewedList, service, specFor } from './helpers/render.js';
import { exec, fakeTool, sandbox, stepEnv } from './helpers/step-harness.js';
import { cleanupRepos, writeIn } from './helpers/make-repo.js';
import { withEgress } from './helpers/egress-step.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const sha16 = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const SEC_NEED = ['sec', 'rets'].join('');
const SEC = 'sec' + 'ret:';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const p = platform();
const GATE = gateEntry();
const app = service({ name: 'app', path: '.' });
const prof = { ...profile([app]), repoFiles: emptyRepoFiles() };
const ctx: RenderContext = { profile: prof };
const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const needOf = (id: string): Need => ({ id, layer: 'merge', category: (NEED_ID_CATEGORY as Record<string, string>)[id] ?? id, why: 't', blocking: true, floor: false });
const draftOf = (specs: StepSpec[]): PipelineDraft => ({
  profile: prof, capabilities: caps, needs: specs.map((s) => needOf(s.needId)), steps: specs, created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const LINTERS: Linters = { actionlint: async () => '/stub/actionlint', zizmor: async () => '/stub/zizmor' };
const run = (files: CreatedFile[], d: PipelineDraft): Promise<RefereeReport> => referee(files, d, p, [...reviewedList(), GATE], LINTERS, 'tok', { runLinters: async () => [] });
const show = (r: RefereeReport): string => r.issues.map((i) => `${i.check}: ${i.message}`).join('\n');
const has = (r: RefereeReport, check: string, re?: RegExp): boolean => r.issues.some((i) => i.check === check && (re === undefined || re.test(i.message)));
type Job = Record<string, unknown>;
const job = (steps: RenderedStep[], over: Job = {}): Job => ({ 'runs-on': 'ubuntu-latest', permissions: { contents: 'read' }, 'cache-mode': 'none', steps, ...over });
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
const prelude = (): RenderedStep[] => renderJobPrelude({}, p).steps;
const specOf = (id: 'betterleaks' | 'gitleaks'): StepSpec => specFor(entry(id), { needId: 'secrets' });
const ART = 'pipegen-out-secrets';
const runStepOf = (steps: readonly RenderedStep[]): RenderedStep => steps.filter((s) => s.run !== undefined).at(-1) as RenderedStep;
const factsOf = (b: ReturnType<typeof renderFindingsBlock>): ReadonlyMap<string, ScanFact> => new Map([[b.scan.stepId, b.scan.fact]]);

describe('the policy and the run step of a staged scan', () => {
  it('only betterleaks and gitleaks scan a stage folder; no tool deletes repo files any more (the C1b r2 removeFiles block is gone)', () => {
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) {
      expect(pol.staged !== undefined, id).toBe(id === 'betterleaks' || id === 'gitleaks');
      expect((pol as { removeFiles?: unknown }).removeFiles, id).toBeUndefined();
    }
    expect(ARGV_POLICIES.gitleaks?.staged?.ignoreFiles).toEqual(['.gitleaksignore', '.betterleaksignore']);
  });

  for (const id of ['betterleaks', 'gitleaks'] as const) {
    it(`${id}: the run step checks the stage folder, cds into its files, refuses an ignore file there (belt), and writes the report outside it`, () => {
      const r = renderStep(specOf(id), entry(id), p, ctx);
      const step = runStepOf(r.steps);
      const text = step.run as string;
      const lines = text.split('\n');
      expect(text).toContain(`stage="$RUNNER_TEMP/pipegen-stage/${ART}"`);
      const cd = lines.indexOf('cd -- "$stage/files"');
      const launch = lines.findIndex((l) => l.includes(`"$bin/${id}" dir`));
      expect(cd).toBeGreaterThan(-1);
      expect(launch).toBeGreaterThan(cd);
      // the stage folder, its files folder and the manifest are checked (real folders, no link) before the cd
      expect(lines.slice(0, cd).join('\n')).toMatch(/\$stage\/manifest\.json/);
      for (const n of ['.gitleaksignore', '.betterleaksignore']) {
        const belt = lines.findIndex((l) => l.includes(`[ -e ${n} ]`));
        expect(belt, n).toBeGreaterThan(cd);
        expect(belt, n).toBeLessThan(launch);
      }
      expect(text).not.toMatch(/-delete/);
      expect(text).not.toContain('# pipegen ignore files');
      // the report: an absolute path in a fresh work folder of its own, then moved to pipegen-raw as for every tool
      expect(text).toContain(`work="$RUNNER_TEMP/pipegen-work/${ART}"`);
      expect(text).toContain(`out="$work/${id}.sarif"`);
      expect(lines[launch]).toContain('--report-path "$out"');
      expect(lines[launch]).not.toContain(`--report-path ${id}.sarif`);
      expect(lines[launch]).toMatch(/ \. \|\| rc=\$\?$/);   // it scans . (the cwd: the staged files)
      expect(r.output?.path).toBe(`\${{ runner.temp }}/pipegen-raw/${ART}/${id}.sarif`);
      expect(step.id).toBe(`tool-run-${sha16(ART)}`);
    });
  }

  it('a staged scan runs at the repository root: a service folder is refused', () => {
    expect(() => renderStep(specFor(entry('gitleaks'), { needId: 'secrets', workingDir: 'web' }), entry('gitleaks'), p, { profile: profile([service({ name: 'web', path: 'web' })]) })).toThrow(RenderError);
  });

  it('a staged policy on a tool with no plain result file is refused', () => {
    const pol = { ...ARGV_POLICIES.gitleaks, staged: { ignoreFiles: ['.x y'] } };
    expect(() => renderStepWith(specOf('gitleaks'), entry('gitleaks'), p, ctx, { policies: { ...ARGV_POLICIES, gitleaks: pol as never } })).toThrow(RenderError);
  });
});

describe('the stage step (gate action, mode stage)', () => {
  it('renderStage: id stage-<sha16(artifact)>, the pinned gate action, mode stage with the artifact, the tool and the stage folder of that artifact', () => {
    const s = renderStage(ART, 'gitleaks', GATE);
    expect(s.id).toBe(stageStepId(ART));
    expect(s.id).toBe(`stage-${sha16(ART)}`);
    expect(STAGE_STEP_ID_RE.test(s.id as string)).toBe(true);
    expect(s.uses).toBe(GATE.step.action?.uses);
    expect(s.with).toEqual({ mode: 'stage', artifact: ART, tool: 'gitleaks', stage: stagePath(ART) });
    expect(stagePath(ART)).toBe(`\${{ runner.temp }}/pipegen-stage/${ART}`);
    expect(s.if).toBeUndefined();
    expect(s.run).toBeUndefined();
    expect(isStageStep(s)).toBe(true);
    expect(isKnownHarmless(s)).toBe(true);
  });

  it('renderStage refuses a tool that does not scan a stage folder, and a name that is not a result artifact', () => {
    expect(() => renderStage(ART, 'semgrep', GATE)).toThrow(RenderError);
    expect(() => renderStage('not-an-artifact', 'gitleaks', GATE)).toThrow(RenderError);
    expect(() => renderStage(ART, 'gitleaks', entry('gitleaks'))).toThrow(RenderError);
  });

  it('renderScrub of a staged tool carries the stage folder; of any other tool it does not', () => {
    const raw = `\${{ runner.temp }}/pipegen-raw/${ART}/gitleaks.sarif`;
    expect(renderScrub(ART, raw, 'gitleaks', 'sarif', GATE).with?.stage).toBe(stagePath(ART));
    const sast = 'pipegen-out-sast--app';
    expect(renderScrub(sast, `\${{ runner.temp }}/pipegen-raw/${sast}/semgrep.sarif`, 'semgrep', 'sarif', GATE).with?.stage).toBeUndefined();
  });

  it('RENDERER_INPUTS: mode stage takes the artifact, a staged tool and the stage folder of that artifact; stage is refused anywhere else', () => {
    const U = 'crisworking/pipegen/gate';
    const pr = (w: Record<string, string>): string[] => rendererInputProblems(U, w, w);
    const good = { mode: 'stage', artifact: ART, tool: 'gitleaks', stage: stagePath(ART) };
    expect(pr(good)).toEqual([]);
    expect(pr({ ...good, tool: 'betterleaks' })).toEqual([]);
    expect(pr({ ...good, tool: 'semgrep' }).length).toBeGreaterThan(0);
    expect(pr({ mode: 'stage', artifact: ART, tool: 'semgrep' }).join('\n')).toMatch(/input tool /);   // the tool alone, without a stage input
    expect(pr({ ...good, stage: stagePath('pipegen-out-other') }).length).toBeGreaterThan(0);
    expect(pr({ ...good, stage: `${stagePath(ART)}/files` }).length).toBeGreaterThan(0);
    expect(pr({ ...good, stage: '/tmp/x' }).length).toBeGreaterThan(0);
    expect(pr({ ...good, artifact: 'x' }).length).toBeGreaterThan(0);
    expect(pr({ ...good, raw: `\${{ runner.temp }}/pipegen-raw/${ART}/x.sarif` }).length).toBeGreaterThan(0);   // a scrub input
    expect(pr({ ...good, ['fp' + '-key']: ['${{', 'secrets.PIPEGEN_FP_KEY', '}}'].join(' ') }).length).toBeGreaterThan(0);
    expect(pr({ mode: 'gate', stage: stagePath(ART) }).length).toBeGreaterThan(0);
    // in scrub mode, the stage input only with a staged tool and its own artifact
    const scrub = { mode: 'scrub', artifact: ART, tool: 'gitleaks', format: 'sarif', raw: `\${{ runner.temp }}/pipegen-raw/${ART}/gitleaks.sarif`, out: `\${{ runner.temp }}/pipegen-out/${ART}/gitleaks.sarif` };
    expect(pr({ ...scrub, stage: stagePath(ART) })).toEqual([]);
    expect(pr({ ...scrub, tool: 'semgrep', stage: stagePath(ART) }).length).toBeGreaterThan(0);
  });
});

describe('the secrets job: [checkout, stage, install, run, scrub, upload]', () => {
  for (const id of ['betterleaks', 'gitleaks'] as const) {
    it(`${id}: renderFindingsBlock gives stage, the tool steps, scrub and upload; the job passes dedupe and the order rule`, () => {
      const b = renderFindingsBlock(specOf(id), entry(id), p, ctx, GATE);
      expect(b.steps.map((s) => s.id ?? s.name)).toEqual([stageStepId(ART), `tool-install-${sha16(ART)}`, `tool-run-${sha16(ART)}`, `scrub-${sha16(ART)}`, 'Upload the result']);
      const steps = dedupeJobSteps([...prelude(), ...b.steps], { scans: factsOf(b) });
      expect(checkJobOrder(steps, { scans: factsOf(b) })).toEqual([]);
    });
  }

  it('renderFindingsBlock of a tool that is not staged has no stage step', () => {
    const b = renderFindingsBlock(specFor(entry('osv-scanner'), { needId: 'deps' }), entry('osv-scanner'), p, ctx, GATE);
    expect(b.steps.some((s) => s.id?.startsWith('stage-'))).toBe(false);
  });

  const block = renderFindingsBlock(specOf('gitleaks'), entry('gitleaks'), p, ctx, GATE);
  const steps = [...prelude(), ...block.steps];
  const facts = factsOf(block);
  const stageAt = steps.findIndex((s) => s.id === stageStepId(ART));
  const runAt = steps.findIndex((s) => s.id === `tool-run-${sha16(ART)}`);
  const problems = (xs: RenderedStep[]): string => checkJobOrder(xs, { scans: facts }).join('\n');

  it('checkJobOrder: a staged scan with no stage step before it, or a stage after the scan, is refused', () => {
    expect(problems(steps.filter((_, i) => i !== stageAt))).toMatch(/stage/);
    const late = [...steps];
    const [s] = late.splice(stageAt, 1);
    late.splice(runAt, 0, s as RenderedStep);
    expect(problems(late)).toMatch(/stage/);
  });

  it('checkJobOrder without scan facts (the order rule alone): a stage after its scan is still refused', () => {
    const late = [...steps];
    const [s] = late.splice(stageAt, 1);
    late.splice(runAt, 0, s as RenderedStep);
    expect(checkJobOrder(late).join('\n')).toMatch(/stage/);
    expect(checkJobOrder(steps)).toEqual([]);
  });

  it('checkJobOrder: a stage step of another artifact, twice, with another tool, or in a job with no staged scan, is refused', () => {
    const other = renderStage('pipegen-out-other', 'gitleaks', GATE);
    expect(problems([...steps.slice(0, stageAt), other, ...steps.slice(stageAt + 1)])).toMatch(/stage/);
    expect(problems([...steps.slice(0, stageAt + 1), steps[stageAt] as RenderedStep, ...steps.slice(stageAt + 1)])).toMatch(/stage/);
    const wrongTool = { ...(steps[stageAt] as RenderedStep), with: { ...(steps[stageAt] as RenderedStep).with, tool: 'betterleaks' } };
    expect(problems([...steps.slice(0, stageAt), wrongTool, ...steps.slice(stageAt + 1)])).toMatch(/stage/);
    expect(checkJobOrder([...prelude(), renderStage(ART, 'gitleaks', GATE)], { scans: new Map() }).join('\n')).toMatch(/stage/);
  });

  it('checkJobOrder: the scrub of a staged scan must carry its stage folder', () => {
    const scrubAt = steps.findIndex((s) => s.id === `scrub-${sha16(ART)}`);
    const noStage = { ...(steps[scrubAt] as RenderedStep), with: Object.fromEntries(Object.entries((steps[scrubAt] as RenderedStep).with ?? {}).filter(([k]) => k !== 'stage')) };
    expect(problems([...steps.slice(0, scrubAt), noStage, ...steps.slice(scrubAt + 1)])).toMatch(/stage/);
  });

  it('a stage id on a run step, or the gate action in mode stage under another id, is not a stage step (repo code in a key job)', () => {
    const fake: RenderedStep = { id: stageStepId(ART), name: 'x', run: 'true', shell: 'bash' };
    expect(isStageStep(fake)).toBe(false);
    expect(isKnownHarmless(fake)).toBe(false);
    const renamed = { ...(steps[stageAt] as RenderedStep), id: 'stage-x' };
    expect(isStageStep(renamed)).toBe(false);
    const otherMode = { ...(steps[stageAt] as RenderedStep), with: { ...(steps[stageAt] as RenderedStep).with, mode: 'gate' } };
    expect(isStageStep(otherMode)).toBe(false);
    expect(problems([...steps.slice(0, stageAt), fake, ...steps.slice(stageAt + 1)]).length).toBeGreaterThan(0);
  });

  it('referee: the full secrets job (both tools) gives 0 issues', async () => {
    for (const id of ['betterleaks', 'gitleaks'] as const) {
      const b = renderFindingsBlock(specOf(id), entry(id), p, ctx, GATE);
      const js = dedupeJobSteps([...prelude(), ...b.steps], { scans: factsOf(b) });
      const outputs = Object.fromEntries(['sha256', 'status', 'error'].map((n) => [`${ART}-${n}`, `\${{ steps.scrub-${sha16(ART)}.outputs.${n} }}`]));
      const r = await run([workflow({ [SEC_NEED]: job(js, { outputs }) })], draftOf([specOf(id)]));
      expect(show(r), id).toBe('');
    }
  });

  it('referee: order and kind tampering give an issue (stage after the scan, no stage, stage under a scrub id, mode changed, stage in another job)', async () => {
    const d = draftOf([specOf('gitleaks')]);
    const outputs = Object.fromEntries(['sha256', 'status', 'error'].map((n) => [`${ART}-${n}`, `\${{ steps.scrub-${sha16(ART)}.outputs.${n} }}`]));
    const ok = await run([workflow({ [SEC_NEED]: job(steps, { outputs }) })], d);
    expect(show(ok)).toBe('');
    const late = [...steps];
    const [s] = late.splice(stageAt, 1);
    late.splice(runAt, 0, s as RenderedStep);
    const variants: [string, Record<string, Job>][] = [
      ['stage after the scan', { [SEC_NEED]: job(late, { outputs }) }],
      ['no stage', { [SEC_NEED]: job(steps.filter((_, i) => i !== stageAt), { outputs }) }],
      ['stage under a scrub id', { [SEC_NEED]: job(steps.map((x, i) => (i === stageAt ? { ...x, id: `scrub-${sha16(ART)}` } : x)), { outputs }) }],
      ['mode changed to gate', { [SEC_NEED]: job(steps.map((x, i) => (i === stageAt ? { ...x, with: { ...x.with, mode: 'gate' } } : x)), { outputs }) }],
      ['stage before the checkout', { [SEC_NEED]: job([steps[stageAt] as RenderedStep, ...steps.filter((_, i) => i !== stageAt)], { outputs }) }],
      ['stage in another job', { [SEC_NEED]: job(steps.filter((_, i) => i !== stageAt), { outputs }), other: job([...prelude(), steps[stageAt] as RenderedStep]) }],
    ];
    for (const [what, jobs] of variants) {
      const r = await run([workflow(jobs, true)], d);
      expect(r.issues.length, what).toBeGreaterThan(0);
    }
  });

  it('the base-scan job may hold a stage step (its row lists the kind)', () => {
    expect(JOB_STEP_POLICY['base-scan']).toContain('stage');
  });
});

describe('the rendered run step, really run (bash, a stand-in tool)', () => {
  const made: string[] = [];
  afterAll(() => { for (const d of made) unlockTree(d); cleanupRepos(); });
  function unlockTree(d: string): void {
    if (!existsSync(d)) return;
    chmodSync(d, 0o755);
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const q = join(d, e.name);
      if (e.isDirectory()) unlockTree(q);
      else if (e.isFile()) chmodSync(q, 0o644);
    }
  }
  const step = runStepOf(renderStep(specOf('gitleaks'), entry('gitleaks'), p, ctx).steps);
  function staged(): ReturnType<typeof sandbox> {
    const sb = sandbox();
    made.push(sb.rt);
    writeIn(sb.ws, 'a.js', 'a\n');
    writeIn(sb.ws, '.gitleaksignore', 'a.js:rule:1\n');
    expect(stageWorkspace({ workspace: sb.ws, stage: join(sb.rt, 'pipegen-stage', ART) }).status).toBe('ok');
    // the stand-in tool records where it ran and writes a report at the path it was given
    fakeTool(sb, ART, 'gitleaks', `pwd > "$RUNNER_TEMP/cwd.txt"\nfor a in "$@"; do if [ "$prev" = --report-path ]; then printf '{}' > "$a"; fi; prev="$a"; done\nexit 0`);
    return sb;
  }
  it('runs the tool with its cwd in the stage folder and moves the report to pipegen-raw; the stage folder is left as it was', () => {
    const sb = staged();
    const before = readdirSync(join(sb.rt, 'pipegen-stage', ART, 'files')).sort();
    const r = exec(step, sb, stepEnv(step, sb));
    expect(r.status, r.stderr).toBe(0);
    expect(readFileSync(join(sb.rt, 'cwd.txt'), 'utf8').trim()).toBe(join(sb.rt, 'pipegen-stage', ART, 'files'));
    expect(existsSync(join(sb.rt, 'pipegen-raw', ART, 'gitleaks.sarif'))).toBe(true);
    expect(readdirSync(join(sb.rt, 'pipegen-stage', ART, 'files')).sort()).toEqual(before);
    expect(existsSync(join(sb.ws, '.gitleaksignore'))).toBe(true);   // the checkout is not changed any more
  });
  it('fails when the stage step did not run (no stage folder), and when the scan folder holds an ignore file (belt)', () => {
    const sb = sandbox();
    made.push(sb.rt);
    fakeTool(sb, ART, 'gitleaks', 'exit 0');
    expect(exec(step, sb, stepEnv(step, sb)).status).not.toBe(0);
    const sb2 = staged();
    const files = join(sb2.rt, 'pipegen-stage', ART, 'files');
    chmodSync(files, 0o755);
    writeFileSync(join(files, '.betterleaksignore'), 'x\n');
    const r = exec(step, sb2, stepEnv(step, sb2));
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/ignore/);
    expect(existsSync(join(sb2.rt, 'pipegen-raw', ART))).toBe(false);
  });
});

describe.skipIf(!live)('live: the rendered secrets step with the real binaries, then the scrub with the stage', () => {
  const bins: Record<string, string> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  for (const id of ['betterleaks', 'gitleaks'] as const) {
    it(`${id}: a key under node_modules/ and one named by an ignore entry are both reported at their original paths`, () => {
      const sb = sandbox();
      const k = 'sk' + '_live_' + createHash('sha256').update('stage-step').digest('hex').slice(0, 24);
      writeIn(sb.ws, 'node_modules/x.js', `stripe = "${k}"\n`);
      writeIn(sb.ws, 'a.js', `// x\nstripe = "${k}"\n`);
      writeIn(sb.ws, '.gitleaksignore', `a.js:${['stripe', 'access', 'tok' + 'en'].join('-')}:2\n`);
      expect(stageWorkspace({ workspace: sb.ws, stage: join(sb.rt, 'pipegen-stage', ART) }).status).toBe('ok');
      const dir = join(sb.rt, 'pipegen-bin', ART);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, id), readFileSync(bins[id] as string));
      chmodSync(join(dir, id), 0o755);
      const s = runStepOf(renderStep(specOf(id), entry(id), p, ctx).steps);
      const r = exec(s, sb, stepEnv(s, sb));
      expect(r.status, r.stderr).toBe(0);
      const res = scrubFile({ tool: id, format: 'sarif', artifact: ART, raw: join(sb.rt, 'pipegen-raw', ART, `${id}.sarif`), out: join(sb.rt, 'pipegen-out', ART, `${id}.sarif`), fpKey: KEY, eventText: '{}', stage: join(sb.rt, 'pipegen-stage', ART) });
      expect(res.status, res.error).toBe('ok');
      const f = readScrubbed(readFileSync(join(sb.rt, 'pipegen-out', ART, `${id}.sarif`)), 'sarif').findings;
      expect(f.map((x) => [x.file, x.line, x.ruleId.startsWith(SEC)]).sort()).toEqual([['a.js', 2, true], ['node_modules/x.js', 1, true]]);
    }, 120_000);
  }
});
