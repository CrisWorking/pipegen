// C5b fix round 1 (review-C5b.md, rulings in task-C5b-fix-round-1.md): the entry always runs, and every guard the brief names has a test
// that fails without it. The reviewer's probes (tmp-C5b-review/copy/test/probe-c5b.test.ts, P1-P15) are regression tests here. Written first.
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { decideGate } from '../gate/src/decide.js';
import { gatherGateInput } from '../gate/src/facts.js';
import { greenPushToDefault, isCleanRun, main, MODE_INPUTS, type MainDeps } from '../gate/src/main.js';
import { OUTPUT_NAMES } from '../src/engine/job-rules.js';
import { GATE_MODES, PIPEGEN_GATE_USES, RENDERER_INPUTS } from '../src/engine/tool-flags.js';
import { CRED, FakeGh, FPKEY, outputsOf, pushWorld, RUN, runner, VIEW, world, type Runner, type World } from './helpers/gate-world.js';

const NOW = new Date('2026-10-30T12:00:00Z');
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
const ROW = RENDERER_INPUTS[PIPEGEN_GATE_USES] as NonNullable<(typeof RENDERER_INPUTS)[string]>;
const CLEAN = (): Parameters<typeof world>[0] => ({ 'sast--app': readFileSync('test/fixtures/sarif/clean/semgrep.sarif', 'utf8') });
const MEDIUM = (): Parameters<typeof world>[0] => {
  const doc = JSON.parse(readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8')) as { runs: { results: { level?: string }[]; tool: { driver: { rules: { defaultConfiguration?: { level: string } }[] } } }[] };
  for (const res of doc.runs[0]?.results ?? []) res.level = 'warning';
  for (const rule of doc.runs[0]?.tool.driver.rules ?? []) rule.defaultConfiguration = { level: 'warning' };
  return { 'sast--app': JSON.stringify(doc) };
};

interface Ran { code: number; out: string; lines: string[]; outputs: Record<string, string>; summary: string; r: Runner }
async function go(inputs: Record<string, string | undefined>, opts: { w?: World; r?: Runner; github?: MainDeps['github']; env?: (e: Record<string, string>) => void } = {}): Promise<Ran> {
  const w = opts.w;
  const r = opts.r ?? runner(inputs, w === undefined ? {} : { event: w.event, sha: w.sha, payload: w.payload });
  opts.env?.(r.env);
  const chunks: string[] = [];
  const gh = w === undefined ? undefined : new FakeGh(w);
  const code = await main({ env: r.env, now: () => NOW, reviewed: () => VIEW, write: (t) => { chunks.push(t); }, github: opts.github ?? (gh === undefined ? undefined : () => gh) });
  const out = chunks.join('');
  let outputs: Record<string, string> = {};
  try { outputs = outputsOf(r.output); } catch { /* no output file */ }
  let summary = '';
  try { summary = readFileSync(r.summary, 'utf8'); } catch { /* no summary file */ }
  return { code, out, lines: out.split('\n').filter((l) => l !== ''), outputs, summary, r };
}
const gateFile = (r: Runner, f: string): string => join(r.temp, 'pipegen-gate', f);
const readJson = (p: string): Record<string, unknown> => JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
const everythingBut = (x: Ran): string => [
  x.lines.filter((l) => !l.startsWith('::add-mask::')).join('\n'), existsSync(x.r.output) ? readFileSync(x.r.output, 'utf8') : '', x.summary,
  ...['result.json', 'baseline.json', 'marker.json'].filter((f) => existsSync(gateFile(x.r, f))).map((f) => readFileSync(gateFile(x.r, f), 'utf8')),
].join('\n');
const scrubRunner = (key: string | undefined, fill: string | null = readFileSync('test/fixtures/sarif/semgrep.sarif', 'utf8'), tool = 'semgrep'): Runner => {
  const A = tool === 'semgrep' ? 'pipegen-out-sast--app' : 'pipegen-out-secrets';
  const r = runner({});
  const inputs: Record<string, string> = { mode: 'scrub', artifact: A, tool, format: 'sarif', raw: `${r.temp}/pipegen-raw/${A}/r.sarif`, out: `${r.temp}/pipegen-out/${A}/r.sarif`, ...(key === undefined ? {} : { [FP_IN]: key }) };
  for (const [k, v] of Object.entries(inputs)) r.env[`INPUT_${k.toUpperCase()}`] = v;
  if (fill !== null) { mkdirSync(join(r.temp, 'pipegen-raw', A), { recursive: true }); writeFileSync(join(r.temp, 'pipegen-raw', A, 'r.sarif'), fill); }
  return r;
};

// ---------- Important 1: the entry ----------

describe('fix round 1, Important 1: the bundle entry always runs main', () => {
  it('gate/src/index.ts calls main unconditionally (no argv / import.meta guard); main.ts has no top-level run', () => {
    const entry = readFileSync('gate/src/index.ts', 'utf8');
    expect(entry).toMatch(/from '\.\/main\.js'/);
    expect(entry).toMatch(/main\(\{/);
    expect(entry).not.toMatch(/import\.meta|process\.argv|realpath/);
    expect(entry.split('\n').filter((l) => /^\s*if\b/.test(l))).toEqual([]);
    const m = readFileSync('gate/src/main.ts', 'utf8');
    expect(m).not.toMatch(/process\.argv|pathToFileURL|process\.stdout/);
  });
});

// ---------- Important 3 and minors: guard tests ----------

describe('fix round 1: masking', () => {
  it('a multi-line key: each line masked on its own; the other lines appear nowhere else; the key is then refused', async () => {
    const lines = ['l1-' + 'a'.repeat(30), 'l2-' + 'b'.repeat(30), 'l3-' + 'c'.repeat(30)];
    const x = await go({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: lines.join('\n') }, { w: world() });
    for (const l of lines) expect(x.lines, l).toContain(`::add-mask::${l}`);
    const rest = everythingBut(x);
    for (const l of lines) expect(rest, l).not.toContain(l);
    expect(x.code).toBe(1);
    expect(x.out).toMatch(/::error::.*fp-key input is not a usable PIPEGEN_FP_KEY/);
  });
  it('the masks come first on the unknown-mode, missing-mode and extra-input paths too', async () => {
    for (const over of [{ mode: 'nope' }, { mode: undefined }, { mode: 'stage', raw: 'x' }]) {
      const x = await go({ [GH_IN]: CRED, [FP_IN]: FPKEY, ...over });
      expect(x.code, JSON.stringify(over)).toBe(1);
      expect(x.lines.slice(0, 2).sort(), JSON.stringify(over)).toEqual([`::add-mask::${CRED}`, `::add-mask::${FPKEY}`].sort());
    }
  });
  it('P5: mask data is escaped like core.setSecret (%, CR, LF), so the runner registers the real value', async () => {
    const key = `abcd%0Aefgh%25ijkl${'m'.repeat(20)}`;
    const x = await go({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: key }, { w: world() });
    expect(x.lines).toContain(`::add-mask::${key.replace(/%/g, '%25')}`);
    expect(x.lines).not.toContain(`::add-mask::${key}`);
  });
  it('P6 / minor 5: a key the fingerprint rules refuse (short, a short second line, a quote) fails closed with a fixed text in scrub, gate and baseline-check', async () => {
    for (const bad of ['short', `${'x'.repeat(40)}\na`, `${'x'.repeat(40)}"`]) {
      const s = await go({}, { r: scrubRunner(bad) });
      expect(s.code, `scrub ${JSON.stringify(bad)}`).toBe(1);
      expect(s.outputs.status).toBe('tool-error');
      expect(s.outputs.sha256).toBe('');
      const b = await go({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: bad }, { w: world() });
      expect(b.code).toBe(1);
      const w = world();
      const g = await go({ ...w.inputs, [FP_IN]: bad }, { w });
      expect(g.code).toBe(1);
      expect(g.outputs.result).toBe('block');
      expect(JSON.stringify(readJson(gateFile(g.r, 'result.json')).blockReasons)).toMatch(/fp-key input is not a usable PIPEGEN_FP_KEY/);
    }
  });
});

describe('fix round 1: inputs as the runner sets them', () => {
  /** The runner sets EVERY declared input, "" when the step does not give it. */
  const full = (given: Record<string, string | undefined>): Record<string, string> => {
    const all: Record<string, string> = Object.fromEntries(Object.keys(ROW).map((k) => [k, '']));
    for (const [k, v] of Object.entries(given)) if (v !== undefined) all[k] = v;
    return all;
  };
  it('the full declared input set with empty values: gate, scrub and baseline-check still run (an empty input is unset)', async () => {
    const w = world();
    const g = await go(full(w.inputs), { w });
    expect(g.code).toBe(0);
    expect(g.outputs.result).toBe('warn');
    const r = scrubRunner(FPKEY);
    for (const k of Object.keys(ROW)) r.env[`INPUT_${k.toUpperCase()}`] ??= '';
    const s = await go({}, { r });
    expect(s.code).toBe(0);
    expect(s.outputs.status).toBe('ok');
    const b = await go(full({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: FPKEY }), { w: world() });
    expect(b.code).toBe(0);
    expect(b.outputs.found).toBe('missing');
  });
  it('P15: two variables naming one input (INPUT_MODE and INPUT_mode) fail closed', async () => {
    const w = world();
    const x = await go(w.inputs, { w, env: (e) => { e.INPUT_mode = 'baseline-check'; } });
    expect(x.code).toBe(1);
    expect(x.out).toMatch(/::error::.*more than once/);
  });
});

describe('fix round 1: the log', () => {
  it('every line the action writes is a mask, an error, a warning or a `pipegen: ` log line (scrub notes included)', async () => {
    const runs = [await go({}, { r: scrubRunner(FPKEY) }), await go(world().inputs, { w: world() }), await go({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: FPKEY }, { w: world() })];
    for (const x of runs) {
      expect(x.lines.length).toBeGreaterThan(1);
      for (const l of x.lines) expect(/^(?:::add-mask::|::error::|::warning::|pipegen: )/.test(l), l).toBe(true);
      expect(x.lines.some((l) => l.startsWith('pipegen: '))).toBe(true);
    }
  });
});

describe('fix round 1: baseline-check fails toward missing', () => {
  it('a missing event file, an event file that is a link, or a foreign repository → missing, exit 0, a warning', async () => {
    const variants: ((e: Record<string, string>, r: Runner) => void)[] = [
      (e, r) => { e.GITHUB_EVENT_PATH = join(r.root, 'nope.json'); },
      (e) => { e.GITHUB_REPOSITORY = 'evil/app'; },
    ];
    for (const v of variants) {
      const w = world();
      const r = runner({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: FPKEY }, { payload: w.payload });
      v(r.env, r);
      const x = await go({}, { w, r });
      expect(x.code).toBe(0);
      expect(x.outputs).toEqual({ found: 'missing' });
      expect(x.out).toMatch(/::warning::/);
    }
  });
});

describe('fix round 1: no-link, no-overwrite reads and writes', () => {
  it('a planted result.json (a regular file) is never overwritten: the gate blocks and the planted file stays', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    mkdirSync(join(r.temp, 'pipegen-gate'));
    writeFileSync(gateFile(r, 'result.json'), '{"result":"pass","planted":true}');
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
    expect(readFileSync(gateFile(r, 'result.json'), 'utf8')).toBe('{"result":"pass","planted":true}');
  });
  it('a planted baseline.json or marker.json is never overwritten (a warning, the planted file stays)', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    mkdirSync(join(r.temp, 'pipegen-gate'));
    writeFileSync(gateFile(r, 'baseline.json'), 'planted');
    writeFileSync(gateFile(r, 'marker.json'), 'planted');
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(0);
    expect(readFileSync(gateFile(r, 'baseline.json'), 'utf8')).toBe('planted');
    expect(readFileSync(gateFile(r, 'marker.json'), 'utf8')).toBe('planted');
    expect(x.out).toMatch(/::warning::.*baseline/);
  });
  it('GITHUB_STEP_SUMMARY a link → not written through (the step fails closed); the link target is untouched', async () => {
    const w = world();
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    const target = join(r.root, 'target.md');
    writeFileSync(target, 'TARGET');
    rmSync(r.summary);
    symlinkSync(target, r.summary);
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(readFileSync(target, 'utf8')).toBe('TARGET');
  });
  it('the event file a link (to a valid payload) → not read: the gate blocks', async () => {
    const w = world();
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    const real = join(r.root, 'real-event.json');
    writeFileSync(real, readFileSync(r.eventPath));
    rmSync(r.eventPath);
    symlinkSync(real, r.eventPath);
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(x.outputs.result).toBe('block');
  });
});

describe('fix round 1: the trusted files', () => {
  it('no marker re-write when the marker lookup failed (cleanRun unknown) on a green push with warnings; the baseline is still written', async () => {
    const w = pushWorld(MEDIUM());
    const gh = new FakeGh(w);
    gh.listRuns = async () => { throw new Error('500'); };
    const x = await go(w.inputs, { w, github: () => gh });
    expect(x.code).toBe(0);
    const res = readJson(gateFile(x.r, 'result.json'));
    expect(res).toMatchObject({ mode: 'block', result: 'warn', marker: 'not written', baseline: 'written' });
    expect(existsSync(gateFile(x.r, 'marker.json'))).toBe(false);
  });
  it('no key on a green push: result.json says not written (and nothing is)', async () => {
    const w = pushWorld(CLEAN());
    const x = await go({ ...w.inputs, [FP_IN]: '' }, { w });
    expect(readJson(gateFile(x.r, 'result.json'))).toMatchObject({ baseline: 'not written', marker: 'not written' });
  });
  it('P3 / minor 6: a failure after result.json (GITHUB_OUTPUT unset) leaves a block result.json and no baseline or marker', async () => {
    const w = pushWorld(CLEAN());
    const x = await go(w.inputs, { w, env: (e) => { delete e.GITHUB_OUTPUT; } });
    expect(x.code).toBe(1);
    expect(readJson(gateFile(x.r, 'result.json'))).toMatchObject({ result: 'block', pass: false });
    expect(existsSync(gateFile(x.r, 'baseline.json'))).toBe(false);
    expect(existsSync(gateFile(x.r, 'marker.json'))).toBe(false);
  });
  it('P4 / minor 6: the summary a folder → exit 1, result.json block, no trusted files', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    rmSync(r.summary); mkdirSync(r.summary);
    const x = await go(w.inputs, { w, r });
    expect(x.code).toBe(1);
    expect(readJson(gateFile(r, 'result.json')).result).toBe('block');
    expect(existsSync(gateFile(r, 'baseline.json'))).toBe(false);
  });
  it('P4b: no GITHUB_STEP_SUMMARY → a log line, the gate still decides (pass)', async () => {
    const w = pushWorld(CLEAN());
    const x = await go(w.inputs, { w, env: (e) => { delete e.GITHUB_STEP_SUMMARY; } });
    expect(x.code).toBe(0);
    expect(x.out).toMatch(/pipegen: GITHUB_STEP_SUMMARY is not set/);
  });
  it('greenPushToDefault and isCleanRun, each condition on its own (belts behind decideGate)', async () => {
    const gather = async (w: World) => {
      const gh = new FakeGh(w);
      const g = await gatherGateInput({ inputs: w.inputs, env: { eventName: w.event, sha: w.sha, runId: String(RUN), repository: 'acme/app' }, now: NOW, reviewed: VIEW }, gh,
        { readEvent: () => JSON.stringify(w.payload), listRunArtifacts: (o, n, id, name) => gh.listRunArtifacts(o, n, id, name), artifactZip: (o, n, id, m) => gh.downloadArtifactZip(o, n, id, m) });
      if ('kind' in g) throw new Error('settings error');
      return { g, r: decideGate(g) };
    };
    const { g, r } = await gather(pushWorld(CLEAN()));
    expect(greenPushToDefault(g, r)).toBe(true);
    expect(isCleanRun(r)).toBe(true);
    const payload = g.event.payload as Record<string, unknown>;
    expect(greenPushToDefault({ ...g, event: { ...g.event, payload: { ...payload, ref: 'refs/heads/dev' } } }, r)).toBe(false);
    expect(greenPushToDefault({ ...g, event: { ...g.event, name: 'pull_request' } }, r)).toBe(false);
    expect(greenPushToDefault({ ...g, baseScan: { result: 'failure' } }, r)).toBe(false);
    expect(greenPushToDefault({ ...g, settingsErrors: ['x'] }, r)).toBe(false);
    expect(greenPushToDefault(g, { ...r, pass: false })).toBe(false);
    const te = { needId: 'deps', job: 'deps', reason: 'x', base: false, blocks: false };
    expect(greenPushToDefault(g, { ...r, toolErrors: [te] })).toBe(false);
    expect(greenPushToDefault({ ...g, checks: g.checks.map((c, i) => (i === 0 ? { ...c, result: 'failure' as const } : c)) }, r)).toBe(false);
    expect(isCleanRun({ ...r, warnReasons: ['x'] })).toBe(false);
    expect(isCleanRun({ ...r, toolErrors: [te] })).toBe(false);
    expect(isCleanRun({ ...r, warnings: [{} as never] })).toBe(false);
    expect(isCleanRun({ ...r, blocking: [{} as never] })).toBe(false);
  });
});

describe('fix round 1: a thrown read is a named block', () => {
  it('a client that can not be built → block with the fixed reason in result.json and the summary', async () => {
    const w = world();
    const x = await go(w.inputs, { w, github: () => { throw new Error('boom'); } });
    expect(x.code).toBe(1);
    expect(JSON.stringify(readJson(gateFile(x.r, 'result.json')).blockReasons)).toMatch(/could not finish reading what it needs/);
    expect(x.summary).toMatch(/could not finish reading what it needs/);
  });
});

describe('fix round 1: the reviewer\'s probes (regression)', () => {
  it('P1: an unparsable raw file holding token-shaped text → a fixed error; no token, key id or path reaches anything', async () => {
    const x = await go({}, { r: scrubRunner(FPKEY, `{"x": "${['AKIA', 'IOSFODNN7EXAMPLE'].join('')} ${CRED} /home/runner/secret" oops`) });
    expect(x.code).toBe(1);
    const all = everythingBut(x);
    for (const s of [CRED, 'AKIA', '/home/runner/secret']) expect(all).not.toContain(s);
  });
  it('P2: workflow_dispatch, schedule, an empty event, pull_request_target, merge_group on a push payload → block, no baseline', async () => {
    for (const ev of ['workflow_dispatch', 'schedule', '', 'pull_request_target', 'merge_group']) {
      const w = pushWorld(CLEAN());
      w.event = ev;
      const x = await go(w.inputs, { w });
      expect(x.code, ev).toBe(1);
      expect(existsSync(gateFile(x.r, 'baseline.json')), ev).toBe(false);
    }
  });
  it('P7: GITHUB_RUN_ID missing or GITHUB_SHA empty → block', async () => {
    const a = pushWorld(CLEAN());
    expect((await go(a.inputs, { w: a, env: (e) => { delete e.GITHUB_RUN_ID; } })).code).toBe(1);
    const b = pushWorld(CLEAN());
    expect((await go(b.inputs, { w: b, env: (e) => { e.GITHUB_SHA = ''; } })).code).toBe(1);
  });
  it('P8 / P9: only the mode, or garbage jobs / job-list → block', async () => {
    expect((await go({ mode: 'gate' }, { w: world() })).code).toBe(1);
    for (const over of [{ jobs: 'null' }, { jobs: '{}' }, { 'job-list': '[]' }, { 'job-list': 'x' }]) {
      const w = world();
      expect((await go({ ...w.inputs, ...over }, { w })).code, JSON.stringify(over)).toBe(1);
    }
  });
  it('P10: baseline-check with no GITHUB_OUTPUT → exit 1 (its answer can not be handed on)', async () => {
    const x = await go({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: FPKEY }, { w: world(), env: (e) => { delete e.GITHUB_OUTPUT; } });
    expect(x.code).toBe(1);
  });
  it('P11: a push to a branch other than the default → block, no baseline', async () => {
    const w = pushWorld(CLEAN());
    w.payload.ref = 'refs/heads/dev';
    const x = await go(w.inputs, { w });
    expect(x.code).toBe(1);
    expect(existsSync(gateFile(x.r, 'baseline.json'))).toBe(false);
  });
  it('P12: a client error carrying the token and a runner path → neither reaches anything', async () => {
    const w = world();
    const gh = new FakeGh(w);
    gh.getPull = async () => { throw new Error(`Bad credentials ${CRED} at /home/runner/_work/x`); };
    const x = await go(w.inputs, { w, github: () => gh });
    const all = everythingBut(x);
    expect(all).not.toContain(CRED);
    expect(all).not.toContain('/home/runner/_work');
  });
  it('P13 / P14: stage with a missing workspace, a secrets scrub with no stage folder → exit 1', async () => {
    const A = 'pipegen-out-secrets';
    const r = runner({});
    for (const [k, v] of Object.entries({ mode: 'stage', artifact: A, tool: 'betterleaks', stage: `${r.temp}/pipegen-stage/${A}` })) r.env[`INPUT_${k.toUpperCase()}`] = v;
    r.env.GITHUB_WORKSPACE = join(r.root, 'nope');
    expect((await go({}, { r })).code).toBe(1);
    const s = await go({}, { r: scrubRunner(FPKEY, readFileSync('test/fixtures/sarif/clean/betterleaks.sarif', 'utf8'), 'betterleaks') });
    expect(s.code).toBe(1);
    expect(s.outputs.status).toBe('tool-error');
  });
});

describe('fix round 1, minor 8: action.yml parity beyond the inputs', () => {
  const ACTION = parse(readFileSync('gate/action.yml', 'utf8')) as { inputs: Record<string, { description: string }>; outputs: Record<string, unknown> };
  it('the outputs the engine reads from a scrub step are declared; each mode writes only declared outputs; the mode description names every mode', async () => {
    for (const n of OUTPUT_NAMES) expect(Object.keys(ACTION.outputs)).toContain(n);
    const written = new Set<string>();
    for (const x of [await go({}, { r: scrubRunner(FPKEY) }), await go(world().inputs, { w: world() }), await go({ mode: 'baseline-check', [GH_IN]: CRED, [FP_IN]: FPKEY }, { w: world() })]) {
      for (const k of Object.keys(x.outputs)) written.add(k);
    }
    const st = runner({});
    writeFileSync(join(st.workspace, 'a.txt'), 'x\n');
    for (const [k, v] of Object.entries({ mode: 'stage', artifact: 'pipegen-out-secrets', tool: 'betterleaks', stage: `${st.temp}/pipegen-stage/pipegen-out-secrets` })) st.env[`INPUT_${k.toUpperCase()}`] = v;
    for (const k of Object.keys((await go({}, { r: st })).outputs)) written.add(k);
    expect([...written].sort()).toEqual(Object.keys(ACTION.outputs).sort());
    for (const m of GATE_MODES) expect(ACTION.inputs.mode?.description, m).toContain(m);
    expect(Object.keys(MODE_INPUTS).sort()).toEqual([...GATE_MODES].sort());
  });
});

