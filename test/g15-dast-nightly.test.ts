// G15a round 4 (b3, P-4): the nightly DAST scan, end to end (render, assemble, referee). Written first.
// When the merge layer has a DAST check on a service pipegen can start in a container, the nightly file runs nuclei 3.11.1 (the reviewed
// entry, its pinned templates) against that app in the same two jobs as the merge layer: dast-run--<svc> (with no key, secret or job token; the
// app in containers, the scan, the raw hand-off) and dast--<svc> (the sha256 check, the scrub, the upload). code-scanning-dast downloads
// each scrubbed result and uploads it to code scanning. Reported, never gated. Its format is the real nuclei 3.11.1 SARIF
// (test/fixtures/sarif/nuclei.sarif, captured from the pinned binary; gate/src/sarif.ts SARIF_TOOLS.nuclei).
// Round 6: ZAP's active scan (an Automation Framework plan) runs nightly too, in its own pair beside nuclei (test/g15-zap-nightly.test.ts).
import { describe, expect, it } from 'vitest';
import { DAST_HANDOFF_STEP_ID, dastCheckStepId, dastRawArtifact, DAST_UPLOAD_JOB, dastNightlyCategory, NIGHTLY_WORKFLOW } from '../src/engine/job-rules.js';
import { nightlyDastSpec, NIGHTLY_DAST_TOOL } from '../src/engine/dast-handoff.js';
import { RenderError } from '../src/engine/render-error.js';
import type { Job } from '../src/layers/jobs.js';
import type { CreatedFile, ReviewedTool, StepSpec } from '../src/types.js';
import { assemble, CAPS, editJob, files, judge, node, planned, profileOf, SEC, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { parse as parseYaml, parseDocument } from 'yaml';
import { assemble as assembleFiles, judgeAssembled } from '../src/layers/assemble.js';
import { LINTERS, p as P } from './helpers/assemble.js';

const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
const web = (name = 'app', port = 3000) => node({ name, dockerfile: 'Dockerfile', port });
const NUCLEI = REVIEWED.find((t) => t.id === 'nuclei') as ReviewedTool;
const TOK_REF = '${{ github.' + 'tok' + 'en }}';
const KEY_RE = new RegExp(`${SEC}\\.|github\\.token|fp-key|PIPEGEN_FP_KEY`);
const world = (caps = CAPS, services = [web()], priv = false) => {
  const a = assemble(planned(profileOf(services, priv ? { private: true } : {}), { caps, over: SKIP_DEPLOY }));
  return { a, fs: files(a) };
};
const nightlyOf = (fs: CreatedFile[]): CreatedFile => fs.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
const withFile = (fs: CreatedFile[], f: CreatedFile): CreatedFile[] => fs.map((x) => (x.path === f.path ? f : x));

const GATE_T = REVIEWED.find((t) => t.id === 'pipegen-gate') as ReviewedTool;
const JDEPS = { platform: P, reviewed: REVIEWED, linters: LINTERS, [['gh', 'Tok' + 'en'].join('')]: null, refereeDeps: { runLinters: async () => [] } } as unknown as Parameters<typeof judgeAssembled>[1];

describe('G15a round 4 (b3): the nightly DAST scan', () => {
  it('assemble: the delivered nightly file builds the image the archive start reads, runs the nuclei pair and its upload; the referee passes on every file', async () => {
    for (const layout of ['local'] as const) {
      const x = planned(profileOf([web()]), { caps: CAPS, over: SKIP_DEPLOY });
      const a = assembleFiles(x.draft, { gate: GATE_T, reviewed: REVIEWED, platform: P, mode: 'none', layout, plan: x.plan } as Parameters<typeof assembleFiles>[1]);
      const nightly = a.files.filter((f) => /nightly/.test(f.path)).map((f) => parseYaml(f.content) as Obj);
      const jobs = Object.assign({}, ...nightly.map((d) => d.jobs as Obj)) as Obj;
      for (const id of ['image-build--app', 'dast-run--app', 'dast--app', DAST_UPLOAD_JOB]) expect(Object.keys(jobs), `${layout}: ${id}`).toContain(id);
      expect(jobs['dast-run--app'].needs).toEqual(['image-build--app']);
      // the nightly image build pushes nothing (the archive hand-off only)
      expect(JSON.stringify(jobs['image-build--app'])).not.toMatch(/push: ['"]?true|packages: write/);
      expect(shown(await judgeAssembled(a, JDEPS)), layout).toBe('');
    }
  });


  it('dast-handoff: the nightly DAST spec is the reviewed nuclei entry for the same check and service, nothing chosen; no service is refused', () => {
    expect(NIGHTLY_DAST_TOOL).toBe('nuclei');
    const merge = { needId: 'dast', service: 'app', tool: { id: 'zap-baseline' }, choices: { x: 'y' }, output: { path: 'zap.json', format: 'zap-json' }, [SEC]: ['K'] } as unknown as StepSpec;
    const s = nightlyDastSpec(merge, NUCLEI);
    expect(s).toEqual({ needId: 'dast', service: 'app', tool: NUCLEI.candidate, choices: {}, output: NUCLEI.step.output });
    expect(() => nightlyDastSpec({ ...merge, service: undefined } as StepSpec, NUCLEI)).toThrow(RenderError);
    // only the reviewed nuclei entry
    expect(() => nightlyDastSpec(merge, REVIEWED.find((t) => t.id === 'zap-baseline') as ReviewedTool)).toThrow(RenderError);
  });

  it('render: the nightly file runs nuclei against the app in dast-run--<svc>, scrubs it in dast--<svc>, and code-scanning-dast uploads it; the referee passes', async () => {
    const { a, fs } = world();
    // the merge layer keeps its own DAST check (ZAP baseline here)
    expect(JSON.stringify(a.merge['dast-run--app'])).toMatch(/zap-baseline/);
    const run = a.nightly['dast-run--app'] as Job;
    const scrub = a.nightly['dast--app'] as Job;
    expect(run, 'the nightly run job').toBeDefined();
    expect(scrub, 'the nightly scrub job').toBeDefined();
    expect(run.permissions).toEqual({ contents: 'read' });
    expect(run.if).toBeUndefined();
    expect(JSON.stringify(run)).not.toMatch(KEY_RE);
    expect(JSON.stringify(run)).not.toMatch(/zap/);
    const scan = run.steps.find((s) => /nuclei/.test(s.name) && s.id?.startsWith('tool-run-') === true);
    expect(scan?.env?.PIPEGEN_ARG_0).toBe('http://127.0.0.1:3000');
    expect(run.steps[run.steps.length - 2]?.id).toBe(DAST_HANDOFF_STEP_ID);
    expect(run.steps[run.steps.length - 2]?.run).toContain('/nuclei.sarif"');
    expect(run.steps[run.steps.length - 1]?.with?.name).toBe(dastRawArtifact('app'));
    expect(scrub.needs).toEqual(['dast-run--app']);
    expect(scrub.permissions).toEqual({ contents: 'read' });
    expect(scrub.steps.some((s) => s.id === dastCheckStepId('app'))).toBe(true);
    const sc = scrub.steps.find((s) => s.with?.mode === 'scrub');
    expect(sc?.with).toMatchObject({ artifact: 'pipegen-out-dast--app', tool: 'nuclei', format: 'sarif', raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-dast--app/nuclei.sarif' });
    const up = a.nightly[DAST_UPLOAD_JOB] as Job;
    expect(DAST_UPLOAD_JOB).toBe('code-scanning-dast');
    // round 6: the ZAP AF active scan's scrub job beside nuclei's (test/g15-zap-nightly.test.ts)
    expect(up.needs).toEqual(['dast--app', 'zap-active--app']);
    expect(up.permissions).toEqual({ contents: 'read', 'security-events': 'write', actions: 'read' });
    const dl = up.steps.find((s) => /download-artifact/.test(String(s.uses)));
    expect(dl?.with?.name).toBe('pipegen-out-dast--app');
    const sarif = up.steps.find((s) => /upload-sarif/.test(String(s.uses)));
    expect(sarif?.with).toMatchObject({ sarif_file: '${{ runner.temp }}/pipegen-out/pipegen-out-dast--app/nuclei.sarif', category: dastNightlyCategory('app') });
    expect(dastNightlyCategory('app')).toBe('pipegen-dast-nightly--app');
    // never gated: the merge file's gate does not read the nightly scan, and the nightly file has no gate
    expect(JSON.stringify(a.merge)).not.toMatch(/code-scanning-dast|pipegen-dast-nightly/);
    expect(a.nightly.gate).toBeUndefined();
    // round 6: ZAP's active scan runs nightly too (its own pair), so no refusal note
    expect(a.notes.join('\n')).not.toMatch(/ZAP's active scan is not run nightly/);
    expect(shown(await judge(fs, a.draft))).toBe('');
  });

  it('assemble: two services give two nightly pairs and one upload job that needs both', async () => {
    const { a, fs } = world(CAPS, [web('api', 3000), web('web', 8080)]);
    for (const s of ['api', 'web']) {
      expect(a.nightly[`dast-run--${s}`], s).toBeDefined();
      expect(a.nightly[`dast--${s}`], s).toBeDefined();
    }
    const up = a.nightly[DAST_UPLOAD_JOB] as Job;
    expect(up.needs).toEqual(['dast--api', 'zap-active--api', 'dast--web', 'zap-active--web']);
    expect(up.steps.filter((s) => /upload-sarif/.test(String(s.uses))).map((s) => s.with?.category)).toEqual([dastNightlyCategory('api'), dastNightlyCategory('api', 'zap-active'), dastNightlyCategory('web'), dastNightlyCategory('web', 'zap-active')]);
    expect(shown(await judge(fs, a.draft))).toBe('');
  });

  it('assemble: without code scanning nothing would report the nightly DAST scan, so it is not written and a note says so', () => {
    const { a } = world({ ...CAPS, codeScanning: false }, [web()], true);
    expect(Object.keys(a.nightly).filter((k) => k.startsWith('dast') || k.startsWith('zap-active') || k === DAST_UPLOAD_JOB)).toEqual([]);
    expect(a.notes.join('\n')).toMatch(/The nightly DAST scan is not run: it reports through code scanning, which this repository does not have\./);
  });

  it('assemble: a repository with no DAST check gets no nightly DAST job', () => {
    const { a } = world(CAPS, [node()]);
    expect(Object.keys(a.nightly).filter((k) => k.startsWith('dast') || k === DAST_UPLOAD_JOB)).toEqual([]);
  });

  it('referee: the nightly nuclei scan outside the nightly file or its run job, a token in the run job, an edited scan, or the upload in the scrub job → refused', async () => {
    const { a, fs } = world();
    const night = nightlyOf(fs);
    const merge = fs.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile;
    const nucleiSteps = (a.nightly['dast-run--app'] as Job).steps;
    // 1. the nightly nuclei run job copied into the merge file in place of its ZAP run job
    const inMerge = editJob(merge, 'dast-run--app', (j) => { j.steps = JSON.parse(JSON.stringify(nucleiSteps)); });
    expect(shown(await judge(withFile(fs, inMerge), a.draft))).toMatch(/nightly/);
    // 2. the nuclei scan moved into the scrub job
    const moved = editJob(night, 'dast--app', (j) => { j.steps.splice(1, 0, JSON.parse(JSON.stringify(nucleiSteps.find((s) => s.id?.startsWith('tool-run-') === true)))); });
    expect(shown(await judge(withFile(fs, moved), a.draft))).not.toBe('');
    // 3. the job's own credential in the run job
    const withTok = editJob(night, 'dast-run--app', (j) => { const s = j.steps.find((x: Obj) => x.id === DAST_HANDOFF_STEP_ID); s.env = { ...(s.env ?? {}), T: TOK_REF }; });
    expect(shown(await judge(withFile(fs, withTok), a.draft))).toMatch(/token/);
    // 4. the scan edited (no template pin)
    const edited = editJob(night, 'dast-run--app', (j) => { const s = j.steps.find((x: Obj) => /nuclei/.test(String(x.name)) && String(x.id).startsWith('tool-run-')); s.run = String(s.run).replace('-duc', '-duc -ut'); });
    expect(shown(await judge(withFile(fs, edited), a.draft))).not.toBe('');
    // 5. code-scanning power in the scrub job (the upload there)
    const power = editJob(night, 'dast--app', (j) => { j.permissions = { contents: 'read', 'security-events': 'write' }; });
    expect(shown(await judge(withFile(fs, power), a.draft))).toMatch(/permission|security-events/);
    // 6. the upload job (security-events: write) in the merge file
    const upInMerge = editJob(merge, 'dast--app', () => undefined);
    const doc = upInMerge.content.replace(/\njobs:\n/, `\njobs:\n  ${DAST_UPLOAD_JOB}:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      security-events: write\n    steps: []\n`);
    expect(shown(await judge(withFile(fs, { ...merge, content: doc }), a.draft))).toMatch(new RegExp(`${DAST_UPLOAD_JOB} uploads the nightly DAST results of the nightly file only`));
    // 7. the nightly check step (nuclei SARIF) in the merge file's scrub job, standing for its ZAP check
    const checkSteps = (a.nightly['dast--app'] as Job).steps;
    const checkInMerge = editJob(merge, 'dast--app', (j) => { j.steps = JSON.parse(JSON.stringify(checkSteps)); });
    expect(shown(await judge(withFile(fs, checkInMerge), a.draft))).not.toBe('');
    // 8. the nightly run job copied whole under another job id of the nightly file (mutant N2)
    const d2 = parseDocument(night.content);
    d2.setIn(['jobs', 'other-scan'], (d2.getIn(['jobs', 'dast-run--app']) as { clone: () => unknown }).clone());
    expect(shown(await judge(withFile(fs, { ...night, content: d2.toString({ lineWidth: 0 }) }), a.draft))).toMatch(/the nightly DAST step "pipegen: run nuclei[^"]*" runs only in its own job dast-run--app/);
  });

  it('referee: the nightly scan is recognised only for a DAST check of the merge layer (mutant N12)', async () => {
    const { a, fs } = world();
    const draft = { ...a.draft, needs: a.draft.needs.map((n) => (n.id === 'dast' ? { ...n, layer: 'push' as const } : n)) };
    expect(shown(await judge(fs, draft))).toMatch(/"pipegen: install nuclei" is not a step pipegen renders/);
    expect(shown(await judge(fs, a.draft))).toBe('');
  });
});
