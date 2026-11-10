// G15a round 6 (P-4): the nightly ZAP Automation Framework active scan, end to end. Written first.
// The reviewed entry `zap-af-active` (the pinned zap-stable image of zap-baseline) runs `zap.sh -cmd -silent` with pipegen's reviewed AF plan
// (src/engine/zap-active.ts) as its -autorun config, written into the work folder and named by its absolute path; the target URL goes into the
// container env (PIPEGEN_ZAP_TARGET, the plan's ${…}), never as a word. Nightly only: never offered for a need, and the renderer refuses it
// outside the nightly lane. In the nightly file it runs in its own pair (zap-active-run--<svc>, zap-active--<svc>), like nuclei's; the scrub
// turns the real AF report (test/fixtures/zap/af-active-*.json) into SARIF, and code-scanning-dast uploads it. Reported, never gated.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseDocument } from 'yaml';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';
import { parseZapJsonText, ZAP_AF_TOOL, ZAP_TOOL } from '../gate/src/zap.js';
import { GATE_VIEW } from '../gate/src/generated/gate-view.js';
import { RenderError } from '../src/engine/render-error.js';
import { renderStep, renderStepWith, validateSpec } from '../src/engine/render-step.js';
import { renderCliTool } from '../src/engine/render-cli.js';
import { argvPolicyProblems, loadReviewed, reviewedFor, type ReviewedEntry } from '../src/engine/reviewed.js';
import { ARGV_POLICIES } from '../src/engine/tool-flags.js';
import { ZAP_ACTIVE_COMMAND, ZAP_ACTIVE_PLAN, ZAP_ACTIVE_POLICY, ZAP_ACTIVE_TARGET_ENV } from '../src/engine/zap-active.js';
import { nightlyDastSpec, zapActiveSpec, ZAP_ACTIVE_JOB_MINUTES, ZAP_ACTIVE_LANE } from '../src/engine/dast-handoff.js';
import {
  DAST_HANDOFF_STEP_ID, DAST_UPLOAD_JOB, dastCheckStepId, dastNightlyCategory, dastRawArtifact, dastResultArtifact, dastRunJobId, NIGHTLY_WORKFLOW,
} from '../src/engine/job-rules.js';
import { assembleJobs, type Job } from '../src/layers/jobs.js';
import type { CreatedFile, Need, ReviewedTool, StepSpec } from '../src/types.js';
import { assemble, CAPS, editJob, files, judge, node, p as P, planned, profileOf, SEC, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';

const FIX = join(import.meta.dirname, 'fixtures', 'zap');
const AF_ALERTS = readFileSync(join(FIX, 'af-active-alerts.json'));
const AF_CLEAN = readFileSync(join(FIX, 'af-active-clean.json'));
const AF = REVIEWED.find((t) => t.id === 'zap-af-active') as ReviewedTool;
const BASELINE = REVIEWED.find((t) => t.id === 'zap-baseline') as ReviewedTool;
const NUCLEI = REVIEWED.find((t) => t.id === 'nuclei') as ReviewedTool;
const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
const web = (name = 'app', port = 3000) => node({ name, dockerfile: 'Dockerfile', port });
const TOK_REF = '${{ github.' + 'tok' + 'en }}';
const KEY_RE = new RegExp(`${SEC}\\.|github\\.token|fp-key|PIPEGEN_FP_KEY`);
const world = (caps = CAPS, services = [web()]) => {
  const a = assemble(planned(profileOf(services), { caps, over: SKIP_DEPLOY }));
  return { a, fs: files(a) };
};
const nightlyOf = (fs: CreatedFile[]): CreatedFile => fs.find((f) => f.path === NIGHTLY_WORKFLOW) as CreatedFile;
const withFile = (fs: CreatedFile[], f: CreatedFile): CreatedFile[] => fs.map((x) => (x.path === f.path ? f : x));
const MERGE_SPEC = { needId: 'dast', service: 'app', tool: BASELINE.candidate, choices: {}, output: BASELINE.step.output } as unknown as StepSpec;
const URL = 'http://127.0.0.1:3000';
const bytesOf = (r: ReturnType<typeof scrubBytes>): Uint8Array => { if (r.status !== 'ok') throw new Error(r.error); return r.bytes; };
const runOf = (r: { steps: { id?: string; run?: string; env?: Record<string, string> }[] }) => r.steps.find((s) => s.id?.startsWith('tool-run-') === true);

describe('G15a round 6: the reviewed ZAP AF entry and its render', () => {
  it('reviewed: zap-af-active is the pinned zap-stable image of zap-baseline, runs zap.sh -cmd -silent with the reviewed AF plan as its -autorun config, writes zap-active.json (zap-json)', () => {
    expect(AF, 'the entry').toBeDefined();
    expect(AF.candidate.pin).toEqual(BASELINE.candidate.pin);
    expect(AF.candidate.version).toBe(BASELINE.candidate.version);
    expect(AF.step.cli?.install).toEqual(BASELINE.step.cli?.install);
    expect(AF.step.cli?.command).toEqual(['zap.sh', '-cmd', '-silent']);
    expect(AF.fixedInputs.args).toEqual(['-cmd', '-silent']);
    expect(AF.fixedInputs.config).toEqual({ content: ZAP_ACTIVE_PLAN, passAs: { flag: '-autorun' } });
    expect(AF.step.output).toEqual({ path: 'zap-active.json', format: 'zap-json' });
    expect(AF.choices).toEqual({});
    const pol = ARGV_POLICIES['zap-af-active'];
    expect(pol?.config).toEqual({ flag: '-autorun', content: ZAP_ACTIVE_PLAN, fileName: 'zap-active.yaml', atMount: true });
    expect(pol?.envSlots).toEqual({ [ZAP_ACTIVE_TARGET_ENV]: 'local-url' });
    expect(pol?.findingsExit).toEqual([]);
    expect(pol?.nightlyOnly).toBe(true);
    // the gate view carries the new id (a gate-bundled change)
    expect(GATE_VIEW.find((v) => v.id === 'zap-af-active')).toMatchObject({ categories: ['dast'], outputFile: 'zap-active.json' });
  });

  it('reviewed: the AF entry is never offered for a need (the AI can not pick it); zap-baseline and nuclei still are', () => {
    const need = { id: 'dast', category: 'dast', layer: 'merge', service: 'app' } as unknown as Need;
    const ids = reviewedFor(need, 'node', [...REVIEWED], 'audit').map((t) => t.id);
    expect(ids).toContain('zap-baseline');
    expect(ids).toContain('nuclei');
    expect(ids).not.toContain('zap-af-active');
    // no other policy is nightly-only
    expect(Object.entries(ARGV_POLICIES).filter(([, p]) => p.nightlyOnly === true).map(([k]) => k)).toEqual(['zap-af-active']);
  });

  it('render: the AF scan renders only in the nightly lane; there the plan is written to the work folder and named by its absolute path, the target goes in -e PIPEGEN_ZAP_TARGET, host network, image user, exit 0 only', () => {
    const spec = zapActiveSpec(MERGE_SPEC, AF);
    expect(spec).toEqual({ needId: ZAP_ACTIVE_LANE, service: 'app', tool: AF.candidate, choices: {}, output: AF.step.output });
    expect(ZAP_ACTIVE_LANE).toBe('zap-active');
    // outside the nightly lane: refused, as the merge layer's DAST check too
    expect(() => renderStep(spec, AF, P, { profile: profileOf([web()]), targets: { url: URL } })).toThrow(/nightly/);
    expect(() => renderStep({ ...MERGE_SPEC, tool: AF.candidate, output: AF.step.output }, AF, P, { profile: profileOf([web()]), targets: { url: URL } })).toThrow(RenderError);
    const r = renderStep(spec, AF, P, { profile: profileOf([web()]), targets: { url: URL }, nightly: true });
    const run = runOf(r);
    const text = String(run?.run);
    expect(run?.env?.PIPEGEN_CONFIG).toBe(ZAP_ACTIVE_PLAN);
    expect(text).toContain(`printf '%s' "$PIPEGEN_CONFIG" > "$work/zap-active.yaml"`);
    expect(text).toMatch(/--network host/);
    expect(text).not.toMatch(/--user/);
    expect(text).toMatch(/--cap-drop ALL/);
    expect(text).toContain(`-e ${ZAP_ACTIVE_TARGET_ENV}="$PIPEGEN_ARG_0"`);
    expect(run?.env?.PIPEGEN_ARG_0).toBe(URL);
    // G17B-R1 sec M1: the API answers only 127.0.0.1
    expect(text).toContain(`"$PIPEGEN_IMAGE" ${ZAP_ACTIVE_COMMAND.join(' ')} -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false > /dev/null`);
    expect(text).toContain('chmod 0777 "$work"');
    // the URL is never a word of the command
    expect(text).not.toContain(URL);
    expect(text).toContain('docker cp pipegen-tool-');
    expect(text).toContain(':/zap/wrk/zap-active.json "$out"');
    expect(text).toMatch(/case "\$rc" in 0\) ;; \*\)/);
    expect(r.output).toEqual({ path: '${{ runner.temp }}/pipegen-raw/pipegen-out-zap-active--app/zap-active.json', format: 'zap-json' });
    // a URL that is not the local app is refused (the slot check)
    expect(() => renderStep(spec, AF, P, { profile: profileOf([web()]), targets: { url: 'https://example.com' }, nightly: true })).toThrow(RenderError);
  });

  it('dast-handoff: the AF spec is the reviewed AF entry for the same service, in its own lane, nothing chosen; another entry or no service is refused', () => {
    expect(() => zapActiveSpec({ ...MERGE_SPEC, service: undefined } as StepSpec, AF)).toThrow(RenderError);
    expect(() => zapActiveSpec(MERGE_SPEC, BASELINE)).toThrow(RenderError);
    expect(() => zapActiveSpec(MERGE_SPEC, NUCLEI)).toThrow(RenderError);
    expect(() => nightlyDastSpec(MERGE_SPEC, AF)).toThrow(RenderError);
  });
});

describe('G15a round 6: the AF report through the gate (real reports of the pinned image)', () => {
  it('gate: the AF report reads with the ZAP reader under its own id, the same findings as zap-baseline; another tool id is refused', () => {
    expect(ZAP_AF_TOOL).toBe('zap-af-active');
    const af = parseZapJsonText(AF_ALERTS, ZAP_AF_TOOL);
    const base = parseZapJsonText(AF_ALERTS, ZAP_TOOL);
    expect(af.toolError).toBeUndefined();
    expect(af.findings.map(({ tool: _t, ...f }) => f)).toEqual(base.findings.map(({ tool: _t, ...f }) => f));
    expect(af.findings.length).toBe(13);
    expect(af.findings.every((f) => f.tool === ZAP_AF_TOOL)).toBe(true);
    expect(parseZapJsonText(AF_ALERTS, 'nuclei').toolError).toMatch(/not a tool whose ZAP report the gate reads/);
  });

  it('scrub: the real AF report scrubs to SARIF for code scanning (driver ZAP, the URL path as the uri, the fingerprint kept, no attack, query or host); the clean one is zero results', () => {
    const r = scrubBytes(AF_ALERTS, { tool: ZAP_AF_TOOL, format: 'zap-json' });
    expect(r.status).toBe('ok');
    const out = JSON.parse(Buffer.from(bytesOf(r)).toString('utf8')) as Obj;
    expect(out.version).toBe('2.1.0');
    expect(out.runs[0].tool.driver.name).toBe('ZAP');
    expect(out.runs[0].properties).toMatchObject({ pipegenScrubbed: true, pipegenTool: ZAP_AF_TOOL });
    const results = out.runs[0].results as Obj[];
    expect(results.length).toBe(13);
    const levels = new Set(results.map((x) => x.level));
    expect(levels).toEqual(new Set(['error', 'warning', 'note']));
    for (const x of results) {
      expect(x.partialFingerprints.pipegenFingerprint).toMatch(/^[0-9a-f]{64}$/);
      const uri = x.locations?.[0]?.physicalLocation?.artifactLocation?.uri as string | undefined;
      if (uri !== undefined) expect(uri).toMatch(/^\/[^?#:]*$/);
    }
    const text = JSON.stringify(out);
    expect(text).not.toMatch(/vuln:8080|<script|alert\(|\?q=|#jaVasCript/i);
    // the XSS findings are high (error)
    expect(results.filter((x) => x.ruleId === '40012' || x.ruleId === '40026').every((x) => x.level === 'error')).toBe(true);
    // the scrubbed SARIF reads back as the same findings
    const back = readScrubbed(bytesOf(r), 'sarif');
    expect(back.toolError).toBeUndefined();
    expect(back.findings.length).toBe(13);
    expect(back.findings.every((f) => f.tool === ZAP_AF_TOOL)).toBe(true);
    const clean = scrubBytes(AF_CLEAN, { tool: ZAP_AF_TOOL, format: 'zap-json' });
    expect(clean.status).toBe('ok');
    expect(JSON.parse(Buffer.from(bytesOf(clean)).toString('utf8')).runs[0].results).toEqual([]);
    // zap-baseline keeps its own scrubbed ZAP form (the merge-layer gate reads it)
    const b = scrubBytes(AF_ALERTS, { tool: ZAP_TOOL, format: 'zap-json' });
    expect(JSON.parse(Buffer.from(bytesOf(b)).toString('utf8'))).toMatchObject({ pipegenScrubbed: true, tool: ZAP_TOOL });
    // the AF id is never a SARIF tool (its raw result is ZAP's JSON only)
    expect(scrubBytes(Buffer.from(text), { tool: ZAP_AF_TOOL, format: 'sarif' }).status).toBe('tool-error');
  });
});

describe('G15a round 6: the nightly ZAP AF pair', () => {
  it('render: the nightly file runs the AF scan against the app in zap-active-run--<svc>, scrubs it in zap-active--<svc>, and code-scanning-dast uploads it; nuclei keeps its pair; the referee passes', async () => {
    const { a, fs } = world();
    const run = a.nightly[dastRunJobId('app', ZAP_ACTIVE_LANE)] as Job;
    const scrub = a.nightly['zap-active--app'] as Job;
    expect(dastRunJobId('app', ZAP_ACTIVE_LANE)).toBe('zap-active-run--app');
    expect(run, 'the AF run job').toBeDefined();
    expect(scrub, 'the AF scrub job').toBeDefined();
    expect(a.nightly['dast-run--app'], 'nuclei keeps its pair').toBeDefined();
    expect(run.permissions).toEqual({ contents: 'read' });
    expect(run.needs).toEqual(['image-build--app']);
    expect(JSON.stringify(run)).not.toMatch(KEY_RE);
    expect(JSON.stringify(run)).not.toMatch(/nuclei/);
    const scan = run.steps.find((s) => /zap\.sh/.test(s.name) && s.id?.startsWith('tool-run-') === true);
    expect(scan?.env?.PIPEGEN_ARG_0).toBe(URL);
    expect(scan?.env?.PIPEGEN_CONFIG).toBe(ZAP_ACTIVE_PLAN);
    expect(run.steps[run.steps.length - 2]?.id).toBe(DAST_HANDOFF_STEP_ID);
    expect(run.steps[run.steps.length - 2]?.run).toContain('/zap-active.json"');
    expect(run.steps[run.steps.length - 1]?.with?.name).toBe(dastRawArtifact('app', ZAP_ACTIVE_LANE));
    expect(dastRawArtifact('app', ZAP_ACTIVE_LANE)).toBe('pipegen-out-zap-active-raw--app');
    expect(scrub.needs).toEqual(['zap-active-run--app']);
    expect(scrub.permissions).toEqual({ contents: 'read' });
    expect(scrub.steps.some((s) => s.id === dastCheckStepId('app', ZAP_ACTIVE_LANE))).toBe(true);
    expect(dastCheckStepId('app', ZAP_ACTIVE_LANE)).toBe('pipegen-zap-active-check--app');
    const sc = scrub.steps.find((s) => s.with?.mode === 'scrub');
    expect(sc?.with).toMatchObject({ artifact: 'pipegen-out-zap-active--app', tool: 'zap-af-active', format: 'zap-json', raw: '${{ runner.temp }}/pipegen-raw/pipegen-out-zap-active--app/zap-active.json' });
    expect(dastResultArtifact('app', ZAP_ACTIVE_LANE)).toBe('pipegen-out-zap-active--app');
    const up = a.nightly[DAST_UPLOAD_JOB] as Job;
    expect(up.needs).toEqual(['dast--app', 'zap-active--app']);
    const dls = up.steps.filter((s) => /download-artifact/.test(String(s.uses))).map((s) => s.with?.name);
    expect(dls).toEqual(['pipegen-out-dast--app', 'pipegen-out-zap-active--app']);
    const sarifs = up.steps.filter((s) => /upload-sarif/.test(String(s.uses))).map((s) => s.with);
    expect(sarifs[1]).toMatchObject({ sarif_file: '${{ runner.temp }}/pipegen-out/pipegen-out-zap-active--app/zap-active.json', category: dastNightlyCategory('app', ZAP_ACTIVE_LANE) });
    expect(dastNightlyCategory('app', ZAP_ACTIVE_LANE)).toBe('pipegen-zap-active-nightly--app');
    expect(dastNightlyCategory('app')).toBe('pipegen-dast-nightly--app');
    // never gated; the refusal is lifted
    expect(JSON.stringify(a.merge)).not.toMatch(/zap-active|zap-af-active/);
    expect(a.notes.join('\n')).not.toMatch(/active scan is not run/);
    expect(shown(await judge(fs, a.draft))).toBe('');
  });

  it('assemble: two services give two AF pairs beside the two nuclei pairs; the upload job needs all four scrub jobs', async () => {
    const { a, fs } = world(CAPS, [web('api', 3000), web('web', 8080)]);
    for (const s of ['api', 'web']) {
      expect(a.nightly[`zap-active-run--${s}`], s).toBeDefined();
      expect(a.nightly[`zap-active--${s}`], s).toBeDefined();
    }
    expect((a.nightly[DAST_UPLOAD_JOB] as Job).needs).toEqual(['dast--api', 'zap-active--api', 'dast--web', 'zap-active--web']);
    expect(shown(await judge(fs, a.draft))).toBe('');
  });

  it('assemble: without the AF entry on the reviewed list, nuclei still runs nightly and a note says the active scan does not', () => {
    const x = planned(profileOf([web()]), { caps: CAPS, over: SKIP_DEPLOY });
    const a = assembleJobs(x.draft, x.plan, { reviewed: REVIEWED.filter((t) => t.id !== 'zap-af-active'), platform: P, mode: 'none' });
    expect(a.nightly['dast-run--app']).toBeDefined();
    expect(a.nightly['zap-active-run--app']).toBeUndefined();
    expect((a.nightly[DAST_UPLOAD_JOB] as Job).needs).toEqual(['dast--app']);
    expect(a.notes.join('\n')).toMatch(/ZAP's active scan is not run nightly: .* Nuclei scans the app nightly instead\./);
  });

  it('referee: the AF scan outside the nightly file or its run job, a token in its run job, an edited plan, a changed target, or its check in the merge file → refused', async () => {
    const { a, fs } = world();
    const night = nightlyOf(fs);
    const merge = fs.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile;
    const afSteps = (a.nightly['zap-active-run--app'] as Job).steps;
    // 1. the AF run job copied into the merge file in place of its ZAP baseline run job
    const inMerge = editJob(merge, 'dast-run--app', (j) => { j.steps = JSON.parse(JSON.stringify(afSteps)); });
    expect(shown(await judge(withFile(fs, inMerge), a.draft))).not.toBe('');
    // 2. the AF scan moved into nuclei's run job
    const moved = editJob(night, 'dast-run--app', (j) => { j.steps = JSON.parse(JSON.stringify(afSteps)); });
    expect(shown(await judge(withFile(fs, moved), a.draft))).not.toBe('');
    // 3. the job's own credential in the AF run job
    const withTok = editJob(night, 'zap-active-run--app', (j) => { const s = j.steps.find((x: Obj) => x.id === DAST_HANDOFF_STEP_ID); s.env = { ...(s.env ?? {}), T: TOK_REF }; });
    expect(shown(await judge(withFile(fs, withTok), a.draft))).toMatch(/token/);
    // 4. the plan edited (one rule turned off would be a policy change)
    const edited = editJob(night, 'zap-active-run--app', (j) => { const s = j.steps.find((x: Obj) => String(x.id).startsWith('tool-run-')); s.env.PIPEGEN_CONFIG = String(s.env.PIPEGEN_CONFIG).replace('defaultStrength: medium', 'defaultStrength: low'); });
    expect(shown(await judge(withFile(fs, edited), a.draft))).not.toBe('');
    // 5. the target changed to a host off the runner
    const target = editJob(night, 'zap-active-run--app', (j) => { const s = j.steps.find((x: Obj) => String(x.id).startsWith('tool-run-')); s.env.PIPEGEN_ARG_0 = 'https://example.com'; });
    expect(shown(await judge(withFile(fs, target), a.draft))).not.toBe('');
    // 6. the AF scrub job copied into the merge file in place of its ZAP baseline scrub job
    const checkInMerge = editJob(merge, 'dast--app', (j) => { j.steps = JSON.parse(JSON.stringify((a.nightly['zap-active--app'] as Job).steps)); j.needs = ['zap-active-run--app']; });
    expect(shown(await judge(withFile(fs, checkInMerge), a.draft))).not.toBe('');
    // 7. the AF run job copied whole under another job id of the nightly file
    const d2 = parseDocument(night.content);
    d2.setIn(['jobs', 'other-scan'], (d2.getIn(['jobs', 'zap-active-run--app']) as { clone: () => unknown }).clone());
    expect(shown(await judge(withFile(fs, { ...night, content: d2.toString({ lineWidth: 0 }) }), a.draft))).toMatch(/runs only in its own job zap-active-run--app/);
    // 8. the scrub of the AF result told it is nuclei's SARIF
    const lie = editJob(night, 'zap-active--app', (j) => { const s = j.steps.find((x: Obj) => x.with?.mode === 'scrub'); s.with.tool = 'nuclei'; s.with.format = 'sarif'; });
    expect(shown(await judge(withFile(fs, lie), a.draft))).not.toBe('');
    // 9. the AF scrub job needs nuclei's run job (reads another run's raw result)
    const wrongNeed = editJob(night, 'zap-active--app', (j) => { j.needs = ['dast-run--app']; });
    expect(shown(await judge(withFile(fs, wrongNeed), a.draft))).toMatch(/zap-active-run--app/);
    expect(shown(await judge(fs, a.draft))).toBe('');
  });

  it('referee: the AF scan is recognised only for a DAST check of the merge layer', async () => {
    const { a, fs } = world();
    const draft = { ...a.draft, needs: a.draft.needs.map((n) => (n.id === 'dast' ? { ...n, layer: 'push' as const } : n)) };
    expect(shown(await judge(fs, draft))).toMatch(/"Pull the zap\.sh image" is not a step pipegen renders|zap\.sh/);
  });

  it('referee: a draft that picks the AF entry for the merge-layer DAST check is refused (nightly only)', async () => {
    const x = planned(profileOf([web()]), { caps: CAPS, over: SKIP_DEPLOY, edit: (steps) => steps.map((s) => (s.needId === 'dast' ? { ...s, tool: AF.candidate, output: AF.step.output, choices: {} } : s)) });
    // the draft is refused before anything renders: the AF entry is never one pipegen offered for a check
    expect(() => assemble(x)).toThrow(/runs "zap-af-active", which is not a reviewed tool pipegen offered for that check/);
    // and the referee does not recognise it as the merge layer's DAST step
    const ok = world();
    expect(shown(await judge(ok.fs, x.draft))).toMatch(/runs "zap-af-active", which is pipegen's own nightly scan and never a check of the pipeline/);
  });
});

describe('G15a round 6: the mutation survivors (A2, A3, A5, A8, A12, A13, A15, A16, A29, A30) and the AF job timeout', () => {
  const PROF = profileOf([web()]);
  const SPEC = zapActiveSpec(MERGE_SPEC, AF);
  const hadolint = REVIEWED.find((t) => t.id === 'hadolint') as ReviewedTool;

  it('render: each nightly-only guard holds on its own: the renderer refuses outside the nightly lane, validateSpec refuses the lane for any other entry or need (A2, A3)', () => {
    // the renderer, reached without validateSpec
    const hooks = {} as Parameters<typeof renderCliTool>[0]['hooks'];
    expect(() => renderCliTool({ spec: SPEC, tool: AF, service: PROF.services[0], ctx: { profile: PROF, targets: { url: URL } }, hooks, options: {} })).toThrow(/runs only in pipegen's own nightly scan/);
    // validateSpec alone
    const lane = /runs only as pipegen's own nightly ZAP active scan/;
    expect(validateSpec(SPEC, AF, { profile: PROF, nightly: true })).toEqual([]);
    expect(validateSpec(SPEC, AF, { profile: PROF }).join(' ')).toMatch(lane);
    expect(validateSpec({ ...SPEC, needId: 'dast' }, AF, { profile: PROF, nightly: true }).join(' ')).toMatch(lane);
    expect(validateSpec({ ...SPEC, tool: NUCLEI.candidate, output: NUCLEI.step.output }, NUCLEI, { profile: PROF, nightly: true }).join(' ')).toMatch(lane);
  });

  it('render: an env slot is refused on any step but a docker DAST step in a fresh work folder, and for any value but the local URL (A5, A29)', () => {
    const lint = { needId: 'dockerfile-lint', service: 'app', tool: hadolint.candidate, choices: {}, output: hadolint.step.output } as unknown as StepSpec;
    const withEnv = { ...ARGV_POLICIES, hadolint: { ...ARGV_POLICIES.hadolint, envSlots: { PIPEGEN_X: 'local-url' } } } as typeof ARGV_POLICIES;
    expect(() => renderStepWith(lint, hadolint, P, { profile: PROF, targets: { url: URL } }, { policies: withEnv })).toThrow(/passes a slot in the container env/);
    const imageSlot = { ...ARGV_POLICIES, 'zap-af-active': { ...ARGV_POLICIES['zap-af-active'], envSlots: { [ZAP_ACTIVE_TARGET_ENV]: 'image-digest' } } } as unknown as typeof ARGV_POLICIES;
    expect(() => renderStepWith(SPEC, AF, P, { profile: PROF, targets: { url: URL, image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}` }, nightly: true }, { policies: imageSlot })).toThrow(/passes a slot in the container env/);
  });

  it('reviewed: an AF entry without -silent is refused by its argv policy and by the loader\'s ZAP rule, each on its own (A8, A30)', () => {
    const entry = { ...AF, step: { ...AF.step, cli: { ...AF.step.cli, command: ['zap.sh', '-cmd'] } }, fixedInputs: { ...AF.fixedInputs, args: ['-cmd'] } } as unknown as ReviewedEntry;
    expect(argvPolicyProblems(entry).map((x) => x.message).join(' ')).toMatch(/-silent/);
    // the loader, with a policy that would let it through: its ZAP rule still refuses
    const dir = mkdtempSync(join(tmpdir(), 'pg-zap-'));
    const file = join(dir, 'reviewed-tools.yml');
    const text = readFileSync(join(import.meta.dirname, '..', 'data', 'reviewed-tools.yml'), 'utf8');
    const at = text.indexOf('  - id: zap-af-active');
    const edited = text.slice(0, at) + text.slice(at).replace('command: ["zap.sh", "-cmd", "-silent"]', 'command: ["zap.sh", "-cmd"]').replace('args: ["-cmd", "-silent"]', 'args: ["-cmd"]');
    writeFileSync(file, edited);
    const loose = { ...ARGV_POLICIES, 'zap-af-active': { ...ARGV_POLICIES['zap-af-active'], required: { cmd: 'true' } } } as typeof ARGV_POLICIES;
    expect(() => loadReviewed(file, { argvPolicies: loose })).toThrow(/the ZAP AF entry must pass -silent/);
  });

  it('dast-handoff: the AF spec drops every choice of the merge check (A12)', () => {
    expect(zapActiveSpec({ ...MERGE_SPEC, choices: { x: 'y' } } as StepSpec, AF).choices).toEqual({});
  });

  it('referee: the AF run job in the merge file under its own id, or its hash check in nuclei\'s scrub job → refused with their own reasons (A13, A15, A16)', async () => {
    const { a, fs } = world();
    const merge = fs.find((f) => f.path === '.github/workflows/pipegen.yml') as CreatedFile;
    const d = parseDocument(merge.content);
    d.setIn(['jobs', 'zap-active-run--app'], d.createNode(JSON.parse(JSON.stringify(a.nightly['zap-active-run--app']))));
    const out = shown(await judge(withFile(fs, { ...merge, content: d.toString({ lineWidth: 0 }) }), a.draft));
    expect(out).toMatch(/is the nightly ZAP active scan's, so it runs only in the nightly file/);
    expect(out).toMatch(/belongs to the DAST run job dast-run--app only/);
    const night = nightlyOf(fs);
    const check = (a.nightly['zap-active--app'] as Job).steps.find((x) => x.id === dastCheckStepId('app', ZAP_ACTIVE_LANE));
    const inNuclei = editJob(night, 'dast--app', (j) => { j.steps.splice(1, 0, JSON.parse(JSON.stringify(check))); j.needs = ['dast-run--app', 'zap-active-run--app']; });
    expect(shown(await judge(withFile(fs, inNuclei), a.draft))).toMatch(/the hash check of the raw DAST result sits only in the job zap-active--app/);
  });

  it('assemble: the AF run job has the time its plan can take (spider, passive wait and active scan at their limits) and more', () => {
    const { a } = world();
    const budget = 5 + 5 + ZAP_ACTIVE_POLICY.maxScanDurationInMins;
    expect(ZAP_ACTIVE_JOB_MINUTES).toBeGreaterThanOrEqual(budget + 15);
    expect((a.nightly['zap-active-run--app'] as Job)['timeout-minutes']).toBe(ZAP_ACTIVE_JOB_MINUTES);
    // the other jobs keep the default
    expect((a.nightly['dast-run--app'] as Job)['timeout-minutes']).toBe(30);
    expect((a.nightly['zap-active--app'] as Job)['timeout-minutes']).toBe(30);
  });
});
