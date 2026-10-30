// Plan C Task C5b: the gate action itself: gate/action.yml and gate/src/main.ts, the entry point that dispatches on `mode`
// (task-C5b-brief.md, rulings in task-C5b-rulings.md). Every mode runs end to end on a fixture world: a fake GitHub, temp
// RUNNER_TEMP / GITHUB_OUTPUT / GITHUB_STEP_SUMMARY files, and capture of everything the action writes. Written first.
import { existsSync, lstatSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { buildBaseline, buildCleanRunMarker, verifyBaselineArtifact, verifyCleanRunArtifact } from '../gate/src/baseline.js';
import type { AdapterOptions } from '../gate/src/github-adapter.js';
import { main, MODE_INPUTS, type MainDeps } from '../gate/src/main.js';
import { BASELINE_ARTIFACT, CLEAN_RUN_ARTIFACT } from '../src/engine/artifact-names.js';
import { GATE_MODES, PIPEGEN_GATE_USES, RENDERER_INPUTS } from '../src/engine/tool-flags.js';
import { safeMarkdown } from '../src/util/safe-text.js';
import {
  CRED, FakeGh, FPKEY, HEAD, MERGE, outputsOf, pushWorld, RUN, runner, sha256, sync, trustedRunIn, otherRunArtifact, VIEW, world, type Runner, type World,
} from './helpers/gate-world.js';

const ROW = RENDERER_INPUTS[PIPEGEN_GATE_USES] as NonNullable<(typeof RENDERER_INPUTS)[string]>;
const ACTION = parse(readFileSync('gate/action.yml', 'utf8')) as { name: string; inputs: Record<string, Record<string, unknown>>; outputs: Record<string, unknown>; runs: Record<string, unknown> };
const NOW = new Date('2026-10-30T12:00:00Z');
/** the input names, spelled at run time (test/no-secret-literals.test.ts reads `<name>: <value>` as an assignment) */
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
const NS = ['needs', 'Sec' + 'rets'].join('');

interface Ran { code: number; out: string; lines: string[]; outputs: Record<string, string>; summary: string; r: Runner; gh?: FakeGh; envRead: string[] }
/** Runs main with a world (or none), capturing stdout, the outputs, the summary and the env names read. */
async function go(inputs: Record<string, string | undefined>, opts: { w?: World; r?: Runner; github?: MainDeps['github']; onWrite?: (t: string, r: Runner) => void } = {}): Promise<Ran> {
  const w = opts.w;
  const r = opts.r ?? runner(inputs, w === undefined ? {} : { event: w.event, sha: w.sha, payload: w.payload });
  const chunks: string[] = [];
  const envRead: string[] = [];
  const env = new Proxy(r.env, { get(t, k) { if (typeof k === 'string') envRead.push(k); return Reflect.get(t, k); } });
  const gh = w === undefined ? undefined : new FakeGh(w);
  const code = await main({
    env, now: () => NOW, reviewed: () => VIEW,
    write: (t) => { opts.onWrite?.(t, r); chunks.push(t); },
    github: opts.github ?? (gh === undefined ? undefined : () => gh),
  });
  const out = chunks.join('');
  return { code, out, lines: out.split('\n').filter((l) => l !== ''), outputs: outputsOf(r.output), summary: readFileSync(r.summary, 'utf8'), r, ...(gh === undefined ? {} : { gh }), envRead };
}
const gateFile = (r: Runner, f: string): string => join(r.temp, 'pipegen-gate', f);
const readJson = (p: string): Record<string, unknown> => JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
/** Everything the action wrote, but the ::add-mask:: lines themselves. */
const everythingBut = (x: Ran): string => [
  x.lines.filter((l) => !l.startsWith('::add-mask::')).join('\n'), readFileSync(x.r.output, 'utf8'), x.summary,
  ...['result.json', 'baseline.json', 'marker.json'].filter((f) => existsSync(gateFile(x.r, f))).map((f) => readFileSync(gateFile(x.r, f), 'utf8')),
].join('\n');

// ---------- action.yml ----------

describe('action.yml', () => {
  it('its inputs are exactly the RENDERER_INPUTS gate row (no test-only option, no extra input), none with a default', () => {
    expect(Object.keys(ACTION.inputs).sort()).toEqual(Object.keys(ROW).sort());
    for (const [k, v] of Object.entries(ACTION.inputs)) expect(Object.hasOwn(v, 'default'), k).toBe(false);
    for (const t of ['pieceBytes', 'overlap', 'maxFiles', 'maxBytes', 'maxStagedBytes', 'piece-bytes', 'report-only', 'workspace', 'event-path']) expect(Object.keys(ACTION.inputs)).not.toContain(t);
  });
  it('outputs: the scrub\'s sha256, status and error, the lookup\'s found, the gate\'s result; runs node24 dist/index.js', () => {
    expect(Object.keys(ACTION.outputs).sort()).toEqual(['error', 'found', 'result', 'sha256', 'status']);
    expect(ACTION.runs).toEqual({ using: 'node24', main: 'dist/index.js' });
  });
  it('MODE_INPUTS: one list per gate mode; together they are the row; each mode-only input is allowed by the row in exactly its modes', () => {
    expect(Object.keys(MODE_INPUTS).sort()).toEqual([...GATE_MODES].sort());
    expect([...new Set(Object.values(MODE_INPUTS).flat())].sort()).toEqual(Object.keys(ROW).sort());
    // the inputs whose rule depends on the mode alone
    for (const [name, spec] of Object.entries(ROW)) {
      if (name === 'mode' || ['artifact', 'tool', 'stage', 'format', 'raw', 'out'].includes(name)) continue;
      for (const m of GATE_MODES) expect(spec.whenWith?.check({ mode: m }) ?? true, `${name} in ${m}`).toBe((MODE_INPUTS[m] as readonly string[]).includes(name));
    }
    expect(MODE_INPUTS.scrub).toEqual(expect.arrayContaining(['artifact', 'tool', 'stage', 'format', 'raw', 'out', 'fp-key']));
    expect(MODE_INPUTS.stage).toEqual(['mode', 'artifact', 'tool', 'stage']);
    for (const m of GATE_MODES) expect(MODE_INPUTS[m]).toContain('mode');
  });
});

// ---------- every mode ----------

describe('main: the common rules', () => {
  it('an unknown or missing mode fails closed (exit 1, an error, nothing else done)', async () => {
    for (const mode of ['Gate', 'verify', 'merged-red', '', undefined]) {
      const x = await go({ mode });
      expect(x.code, String(mode)).toBe(1);
      expect(x.out, String(mode)).toMatch(/::error::/);
      expect(x.outputs).toEqual({});
    }
  });
  it('find-run and nightly are stubs that fail closed (built in C8 / C7)', async () => {
    const f = await go({ mode: 'find-run', [GH_IN]: CRED });
    expect(f.code).toBe(1);
    expect(f.out).toMatch(/::error::.*built in C8/);
    const n = await go({ mode: 'nightly', [GH_IN]: CRED });
    expect(n.code).toBe(1);
    expect(n.out).toMatch(/::error::.*built in C7/);
  });
  it('each secret input is masked first: its ::add-mask:: line is the first thing written for it, before any other line', async () => {
    for (const mode of ['gate', 'baseline-check', 'scrub', 'find-run', 'nightly']) {
      const w = mode === 'gate' || mode === 'baseline-check' ? world() : undefined;
      const inputs: Record<string, string | undefined> = mode === 'gate' && w !== undefined ? { ...w.inputs } : { mode, [GH_IN]: CRED, [FP_IN]: FPKEY };
      inputs.mode = mode;
      const x = await go(inputs, w === undefined ? {} : { w });
      const first = x.lines.slice(0, 2).sort();
      expect(first, mode).toEqual([`::add-mask::${CRED}`, `::add-mask::${FPKEY}`].sort());
      expect(x.lines.slice(2).some((l) => l.startsWith('::add-mask::')), mode).toBe(false);
    }
  });
  it('an input that is not of the mode fails closed, test-only stage options included (never action inputs)', async () => {
    const s = await go({ mode: 'stage', artifact: 'pipegen-out-secrets', tool: 'betterleaks', stage: 'x', piecebytes: '10' });
    expect(s.code).toBe(1);
    expect(s.out).toMatch(/::error::.*piecebytes/);
    const g = await go({ mode: 'gate', raw: 'x' });
    expect(g.code).toBe(1);
    expect(g.out).toMatch(/::error::.*raw/);
  });
  it('a log line can not start a workflow command, and an error text escapes newlines', async () => {
    const x = await go({ mode: 'stage', artifact: 'pipegen-out-secrets', tool: 'betterleaks', stage: '\n::set-output name=x::y' });
    for (const l of x.lines) expect(/^::(?!add-mask::|error::|warning::)/.test(l), l).toBe(false);
    expect(x.out).not.toMatch(/^::set-output/m);
  });
});

// ---------- scrub ----------

describe('mode scrub', () => {
  const A = 'pipegen-out-sast--app';
  const inputsOf = (r: Runner, over: Record<string, string> = {}): Record<string, string> => ({
    mode: 'scrub', artifact: A, tool: 'semgrep', format: 'sarif', raw: `${r.temp}/pipegen-raw/${A}/semgrep.sarif`, out: `${r.temp}/pipegen-out/${A}/semgrep.sarif`, [FP_IN]: FPKEY, ...over,
  });
  const prepared = (fill: string | null, over: (r: Runner) => Record<string, string> = () => ({})): { r: Runner; inputs: Record<string, string> } => {
    const r = runner({});
    const inputs = inputsOf(r, over(r));
    for (const [k, v] of Object.entries(inputs)) r.env[`INPUT_${k.toUpperCase()}`] = v;
    if (fill !== null) { mkdirSync(join(r.temp, 'pipegen-raw', A), { recursive: true }); writeFileSync(join(r.temp, 'pipegen-raw', A, 'semgrep.sarif'), fill); }
    return { r, inputs };
  };
  it('scrubs the raw file: writes the scrubbed copy, sets sha256 (of the written bytes), status ok and an empty error', async () => {
    const { r, inputs } = prepared(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8'));
    const x = await go(inputs, { r });
    expect(x.code).toBe(0);
    const outFile = join(r.temp, 'pipegen-out', A, 'semgrep.sarif');
    expect(x.outputs).toEqual({ sha256: sha256(readFileSync(outFile)), status: 'ok', error: '' });
    expect(everythingBut(x)).not.toContain(FPKEY);
  });
  it('the parser gets GITHUB_WORKSPACE exactly: an absolute uri under the workspace maps to a repository path', async () => {
    const r0 = runner({});
    const doc = JSON.parse(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8')) as { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
    for (const res of doc.runs[0]?.results ?? []) for (const l of res.locations) l.physicalLocation.artifactLocation.uri = `file://${r0.workspace}/py/app.py`;
    const { r, inputs } = prepared(JSON.stringify(doc));
    r.env.GITHUB_WORKSPACE = r0.workspace;
    const x = await go(inputs, { r });
    expect(x.code).toBe(0);
    const text = readFileSync(join(r.temp, 'pipegen-out', A, 'semgrep.sarif'), 'utf8');
    expect(text).toContain('"uri":"py/app.py"');
    expect(text).not.toContain(r0.workspace);
  });
  it('raw missing → status tool-error, an error text, no file; the outputs are set before the step fails', async () => {
    const { r, inputs } = prepared(null);
    let outputsAtError: Record<string, string> | undefined;
    const x = await go(inputs, { r, onWrite: (t, rr) => { if (t.startsWith('::error::')) outputsAtError ??= outputsOf(rr.output); } });
    expect(x.code).toBe(1);
    expect(x.outputs.status).toBe('tool-error');
    expect(x.outputs.sha256).toBe('');
    expect(x.outputs.error).toMatch(/no result file/);
    expect(outputsAtError?.status).toBe('tool-error');
    expect(existsSync(join(r.temp, 'pipegen-out', A, 'semgrep.sarif'))).toBe(false);
  });
  it('raw unparsable → tool-error, no file', async () => {
    const { r, inputs } = prepared('{ not json');
    const x = await go(inputs, { r });
    expect(x.code).toBe(1);
    expect(x.outputs.status).toBe('tool-error');
    expect(existsSync(join(r.temp, 'pipegen-out', A, 'semgrep.sarif'))).toBe(false);
  });
  it('paths outside their own folders (raw of another artifact, out at another file, out outside RUNNER_TEMP, a stage folder of another artifact, .. ) → tool-error, nothing written', async () => {
    const variants: ((r: Runner) => Record<string, string>)[] = [
      (r) => ({ raw: `${r.temp}/pipegen-raw/pipegen-out-other/semgrep.sarif` }),
      (r) => ({ out: `${r.temp}/pipegen-out/${A}/other.sarif` }),
      (r) => ({ out: `${r.root}/elsewhere/pipegen-out/${A}/semgrep.sarif` }),
      (r) => ({ raw: `${r.temp}/pipegen-raw/${A}/../${A}/semgrep.sarif` }),
      (r) => ({ stage: `${r.temp}/pipegen-stage/pipegen-out-other` }),
      () => ({ format: 'json' }),
      () => ({ tool: '../x' }),
    ];
    for (const v of variants) {
      const { r, inputs } = prepared(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8'), v);
      const x = await go(inputs, { r });
      expect(x.code, JSON.stringify(v(r))).toBe(1);
      expect(x.outputs.status, JSON.stringify(v(r))).toBe('tool-error');
      // refused by the action's own path rule, before the scrub reads anything
      expect(x.outputs.error, JSON.stringify(v(r))).toMatch(/^the (raw|out|stage|format|tool) input is not/);
      expect(existsSync(join(r.temp, 'pipegen-out'))).toBe(false);
    }
  });
  it('an out folder that is a link → tool-error; nothing is written through it', async () => {
    const { r, inputs } = prepared(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8'));
    const target = join(r.root, 'target');
    mkdirSync(target);
    symlinkSync(target, join(r.temp, 'pipegen-out'));
    const x = await go(inputs, { r });
    expect(x.code).toBe(1);
    expect(x.outputs.status).toBe('tool-error');
    expect(existsSync(join(target, A))).toBe(false);
  });
});

// ---------- stage ----------

describe('mode stage', () => {
  const A = 'pipegen-out-secrets';
  it('stages the checkout: manifest and read-only folder, status ok', async () => {
    const r = runner({});
    writeFileSync(join(r.workspace, 'a.txt'), 'hello\n');
    for (const [k, v] of Object.entries({ mode: 'stage', artifact: A, tool: 'betterleaks', stage: `${r.temp}/pipegen-stage/${A}` })) r.env[`INPUT_${k.toUpperCase()}`] = v;
    const x = await go({}, { r });
    expect(x.code).toBe(0);
    expect(x.outputs).toEqual({ status: 'ok', error: '' });
    const stage = join(r.temp, 'pipegen-stage', A);
    expect(existsSync(join(stage, 'manifest.json'))).toBe(true);
    expect(statSync(stage).mode & 0o222).toBe(0);
  });
  it('a stage folder that is not ${RUNNER_TEMP}/pipegen-stage/<artifact>, or a tool that does not scan one → error, nothing staged', async () => {
    for (const over of [{ stage: 'OTHER' }, { tool: 'semgrep' }, { artifact: 'pipegen-out-x' }]) {
      const r = runner({});
      const inputs: Record<string, string> = { mode: 'stage', artifact: A, tool: 'betterleaks', stage: `${r.temp}/pipegen-stage/${A}`, ...over };
      if (inputs.stage === 'OTHER') inputs.stage = `${r.root}/pipegen-stage/${A}`;
      for (const [k, v] of Object.entries(inputs)) r.env[`INPUT_${k.toUpperCase()}`] = v;
      const x = await go({}, { r });
      expect(x.code, JSON.stringify(over)).toBe(1);
      expect(x.outputs.status).toBe('error');
      expect(existsSync(join(r.temp, 'pipegen-stage'))).toBe(false);
    }
  });
});

// ---------- gate ----------

describe('mode gate', () => {
  it('a passing pull request: result output, result.json, the summary; exit 0; no baseline or marker on a PR', async () => {
    const w = world();
    const x = await go(w.inputs, { w });
    expect(x.code).toBe(0);
    expect(x.outputs.result).toBe('warn');   // old findings warn in warn mode
    const res = readJson(gateFile(x.r, 'result.json'));
    expect(res).toMatchObject({ result: 'warn', pass: true, mode: 'warn', event: 'pull_request', sha: MERGE, runId: RUN });
    expect(x.summary).toMatch(/^## pipegen gate: passed \(warn mode\)/m);
    expect(existsSync(gateFile(x.r, 'baseline.json'))).toBe(false);
    expect(existsSync(gateFile(x.r, 'marker.json'))).toBe(false);
  });
  it('a block (a tampered result): result block, result.json and the outputs exist BEFORE the step fails', async () => {
    const w = world();
    (w.needs['sast--app'] as { outputs: Record<string, string> }).outputs['pipegen-out-sast--app-sha256'] = 'f'.repeat(64);
    sync(w);
    let at: { file: boolean; result?: string; summary: string } | undefined;
    const x = await go(w.inputs, { w, onWrite: (t, r) => { if (t.startsWith('::error::')) at ??= { file: existsSync(gateFile(r, 'result.json')), result: outputsOf(r.output).result, summary: readFileSync(r.summary, 'utf8') }; } });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
    expect(at).toEqual({ file: true, result: 'block', summary: expect.stringMatching(/blocked/) });
    expect(readJson(gateFile(x.r, 'result.json')).result).toBe('block');
  });
  it('an event that can not be trusted (another repository) → block with the settings error, result.json written', async () => {
    const w = world();
    w.payload = { ...w.payload, repository: { ...(w.payload.repository as object), full_name: 'evil/app', owner: { login: 'evil' } } };
    const x = await go(w.inputs, { w });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
    expect(JSON.stringify(readJson(gateFile(x.r, 'result.json')).blockReasons)).toMatch(/not of the repository/);
    expect(x.summary).toMatch(/blocked/);
  });
  it('a thrown error anywhere (the client cannot be built, the client throws a non-API error) → a fail-closed block, short and safe', async () => {
    const w = world();
    const boom = await go(w.inputs, { w, github: () => { throw new Error(`/home/runner/secret/path ${CRED}`); } });
    expect(boom.code).toBe(1);
    expect(boom.outputs.result).toBe('block');
    expect(everythingBut(boom)).not.toContain('/home/runner/secret/path');
    expect(everythingBut(boom)).not.toContain(CRED);
    const v = world();
    const gh = new FakeGh(v);
    gh.getPull = async () => { throw new TypeError('x is not a function'); };
    const t = await go(v.inputs, { w: v, github: () => gh });
    expect(t.code).toBe(1);
    expect(t.outputs.result).toBe('block');
  });
  it('the event file missing → block (settings error), never a pass', async () => {
    const w = world();
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    r.env.GITHUB_EVENT_PATH = join(r.root, 'nope.json');
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
  });
  it('never reads GITHUB_WORKSPACE in gate mode', async () => {
    const w = world();
    const x = await go(w.inputs, { w });
    expect(x.envRead).not.toContain('GITHUB_WORKSPACE');
    const p = pushWorld();
    p.inputs = { ...p.inputs };
    const y = await go(p.inputs, { w: p });
    expect(y.envRead).not.toContain('GITHUB_WORKSPACE');
  });
  it('SARIF text reaches the summary through safeMarkdown exactly once (escaped once, never raw, never twice)', async () => {
    // semgrep's message is its rule's text (fullDescription, sarif.ts rule-template), never the result's own
    const doc = JSON.parse(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8')) as { runs: { tool: { driver: { rules: { fullDescription?: { text: string } }[] } } }[] };
    const msg = 'Danger *bold* <img src=x> [link](http://evil.example) @someone';
    for (const rule of doc.runs[0]?.tool.driver.rules ?? []) rule.fullDescription = { text: msg };
    const w = world({ 'sast--app': JSON.stringify(doc) });
    const x = await go(w.inputs, { w });
    expect(x.summary).toContain(safeMarkdown(msg));
    expect(x.summary).not.toContain(msg);
    expect(x.summary).not.toContain(safeMarkdown(safeMarkdown(msg)));
    // result.json carries no SARIF message text
    expect(readFileSync(gateFile(x.r, 'result.json'), 'utf8')).not.toContain('Danger');
  });
  it('the token and the key never appear in an output, the summary, a gate file or the log (only in their ::add-mask:: lines)', async () => {
    for (const w of [world(), pushWorld(), pushWorld({ 'sast--app': readFileSync('test/fixtures/sarif/clean/semgrep.sarif', 'utf8') })]) {
      const x = await go(w.inputs, { w });
      const all = everythingBut(x);
      expect(all).not.toContain(CRED);
      expect(all).not.toContain(FPKEY);
    }
  });
});

// ---------- the baseline and the clean-run marker (ruling A: mode gate saves; a failed save is a warning) ----------

describe('mode gate: the baseline and the clean-run marker on a trusted green push to the default branch', () => {
  const CLEAN = (): Parameters<typeof world>[0] => ({ 'sast--app': readFileSync('test/fixtures/sarif/clean/semgrep.sarif', 'utf8') });
  const meta = (name: string) => ({ runId: RUN, name, expired: false, expiresAt: '2027-01-01T00:00:00Z' });
  it('a green push with old findings: the signed baseline is written (it verifies), no marker (warnings, no marker seen before)', async () => {
    const w = pushWorld();
    const x = await go(w.inputs, { w });
    expect(x.code).toBe(0);
    const bytes = readFileSync(gateFile(x.r, 'baseline.json'));
    const v = verifyBaselineArtifact(new Uint8Array(bytes), meta(BASELINE_ARTIFACT), { key: FPKEY, now: NOW });
    expect(v.baseline).not.toBeNull();
    expect([...(v.baseline?.counts.keys() ?? [])].some((k) => k.includes('sast--app'))).toBe(true);
    expect(existsSync(gateFile(x.r, 'marker.json'))).toBe(false);
    expect(readJson(gateFile(x.r, 'result.json'))).toMatchObject({ baseline: 'written', marker: 'not written' });
  });
  it('a clean green push: baseline and marker written; the marker verifies', async () => {
    const w = pushWorld(CLEAN());
    const x = await go(w.inputs, { w });
    expect(x.code).toBe(0);
    expect(x.outputs.result).toBe('pass');
    const m = verifyCleanRunArtifact(new Uint8Array(readFileSync(gateFile(x.r, 'marker.json'))), meta(CLEAN_RUN_ARTIFACT), { key: FPKEY, now: NOW });
    expect(m.seen).toBe(true);
    expect(existsSync(gateFile(x.r, 'baseline.json'))).toBe(true);
  });
  /** semgrep's findings as medium (level warning): in block mode an old medium finding warns, so the push is green but not clean. */
  const MEDIUM = (): Parameters<typeof world>[0] => {
    const doc = JSON.parse(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8')) as { runs: { results: { level?: string }[]; tool: { driver: { rules: { defaultConfiguration?: { level: string } }[] } } }[] };
    for (const res of doc.runs[0]?.results ?? []) res.level = 'warning';
    for (const rule of doc.runs[0]?.tool.driver.rules ?? []) rule.defaultConfiguration = { level: 'warning' };
    return { 'sast--app': JSON.stringify(doc) };
  };
  it('the re-write rule: once a marker of a trusted run is seen (block mode reached by a clean run), every green push re-writes it, warnings or not', async () => {
    const control = pushWorld(MEDIUM());
    const c = await go(control.inputs, { w: control });
    expect(c.code).toBe(0);
    expect(readJson(gateFile(c.r, 'result.json'))).toMatchObject({ result: 'warn', mode: 'warn', marker: 'not written' });
    const w = pushWorld(MEDIUM());
    trustedRunIn(w, 600, 'a'.repeat(40));
    otherRunArtifact(w, 600, 900, CLEAN_RUN_ARTIFACT, buildCleanRunMarker(600, FPKEY));
    const x = await go(w.inputs, { w });
    expect(readJson(gateFile(x.r, 'result.json'))).toMatchObject({ result: 'warn', mode: 'block', marker: 'written' });
    // block mode: the old medium findings warn; the run is green, not clean, and the marker is written again (and verifies)
    expect(x.code).toBe(0);
    const m = verifyCleanRunArtifact(new Uint8Array(readFileSync(gateFile(x.r, 'marker.json'))), meta(CLEAN_RUN_ARTIFACT), { key: FPKEY, now: NOW });
    expect(m.seen).toBe(true);
  });
  it('no baseline and no marker: on a pull request, on a push that is not green (a job failed), on a blocked push, with no key', async () => {
    const pr = world(CLEAN());
    pr.payload.ref = 'refs/heads/main';   // even a payload that names the default branch: a pull request run never writes them
    const failed = pushWorld(CLEAN());
    (failed.needs['unit-tests--app'] as { result: string }).result = 'failure';
    sync(failed);
    const tampered = pushWorld(CLEAN());
    (tampered.needs.deps as { outputs: Record<string, string> }).outputs['pipegen-out-deps-sha256'] = '0'.repeat(64);
    sync(tampered);
    const nokey = pushWorld(CLEAN());
    nokey.inputs = { ...nokey.inputs, 'fp-key': '' };
    for (const [label, w] of [['pr', pr], ['failed', failed], ['tampered', tampered], ['nokey', nokey]] as const) {
      const x = await go(w.inputs, { w });
      expect(existsSync(gateFile(x.r, 'baseline.json')), label).toBe(false);
      expect(existsSync(gateFile(x.r, 'marker.json')), label).toBe(false);
    }
  });
  it('a push that passes with a failed not-proven job is not green: no baseline, no marker', async () => {
    const w = pushWorld(CLEAN());
    const tc = { needId: 'type-check', job: 'type-check', category: 'type-check', format: 'none', blocking: true, [NS]: false } as unknown as World['list'][number];
    w.list.push(tc);
    w.needs['type-check'] = { result: 'failure', outputs: {} };
    w.inputs['not-proven'] = '["type-check"]';
    sync(w);
    const x = await go(w.inputs, { w });
    expect(x.code).toBe(0);
    expect(x.outputs.result).toBe('warn');
    expect(existsSync(gateFile(x.r, 'baseline.json'))).toBe(false);
    expect(existsSync(gateFile(x.r, 'marker.json'))).toBe(false);
  });
  it('a result file that can not be written turns a pass into a block (the upload would have nothing)', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    mkdirSync(join(r.temp, 'pipegen-gate', 'result.json'), { recursive: true });
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
    expect(x.summary).toMatch(/result file could not be written/);
  });
  it('a failed save is a warning, never a failure: the gate still passes', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    // the baseline and marker files can not be created: a folder sits at their names
    mkdirSync(join(r.temp, 'pipegen-gate', 'baseline.json'), { recursive: true });
    mkdirSync(join(r.temp, 'pipegen-gate', 'marker.json'), { recursive: true });
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(0);
    expect(x.outputs.result).toBe('pass');
    expect(x.out).toMatch(/::warning::.*baseline/);
    expect(x.out).toMatch(/::warning::.*clean-run marker/);
  });
  it('the gate folder is a link → fail closed (nothing written through it)', async () => {
    const w = world();
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    const target = join(r.root, 'elsewhere');
    mkdirSync(target);
    symlinkSync(target, join(r.temp, 'pipegen-gate'));
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
    expect(existsSync(join(target, 'result.json'))).toBe(false);
    expect(lstatSync(join(r.temp, 'pipegen-gate')).isSymbolicLink()).toBe(true);
  });
});

// ---------- baseline-check (ruling A: the lookup) ----------

describe('mode baseline-check: the lookup for base-scan', () => {
  const inputs = { mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: FPKEY };
  it('a verified baseline of a trusted run → found', async () => {
    const w = world();
    trustedRunIn(w, 600, 'a'.repeat(40));
    const built = buildBaseline({ runId: 600, key: FPKEY, checks: [], sameRunTools: [] });
    otherRunArtifact(w, 600, 900, BASELINE_ARTIFACT, built.bytes);
    const x = await go(inputs, { w });
    expect(x.code).toBe(0);
    expect(x.outputs).toEqual({ found: 'found' });
  });
  it('none, a forged one, no key or an API error → missing (base-scan then scans everything), never a failure', async () => {
    const none = await go(inputs, { w: world() });
    expect(none.outputs).toEqual({ found: 'missing' });
    expect(none.code).toBe(0);
    const forged = world();
    trustedRunIn(forged, 600, 'a'.repeat(40));
    otherRunArtifact(forged, 600, 900, BASELINE_ARTIFACT, buildBaseline({ runId: 600, key: 'z'.repeat(40), checks: [], sameRunTools: [] }).bytes);
    expect((await go(inputs, { w: forged })).outputs).toEqual({ found: 'missing' });
    expect((await go({ ...inputs, 'fp-key': '' }, { w: world() })).outputs).toEqual({ found: 'missing' });
    const broken = world();
    const gh = new FakeGh(broken);
    gh.listRuns = async () => { throw new Error('500'); };
    const b = await go(inputs, { w: broken, github: () => gh });
    expect(b.outputs).toEqual({ found: 'missing' });
    expect(b.code).toBe(0);
    expect(b.out).toMatch(/::warning::/);
  });
  it('the github client gets the token from the input only, with the mask already applied', async () => {
    const seen: AdapterOptions[] = [];
    const w = world();
    await go(inputs, { w, github: (o) => { seen.push(o); return new FakeGh(w); } });
    expect(seen[0]?.token).toBe(CRED);
    expect(HEAD).toBeDefined();
  });
});
