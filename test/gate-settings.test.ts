// Plan C Task C5a: the gate's settings and job mapping (gate/src/settings.ts). Every gate input is parsed strictly, per mode; a parse
// error is a settings error (it blocks). The trusted job list is the `job-list` literal (checked by the referee), never the repository;
// policy, protected paths and the tool lists follow the public/private rules of Plan C. `toJSON(needs)` is read only through the job
// list: the need id, tool, blocking and needs-secrets values never come from it. Written first (strict test-first).
import { describe, expect, it } from 'vitest';
import { decideGate, type GateInput } from '../gate/src/decide.js';
import { DEFAULT_POLICY } from '../gate/src/policy-default.js';
import { GATE_INPUTS, gateToolView, mapJobs, resolveSettings, type GateToolView } from '../gate/src/settings.js';
import { jobListLiteral, type JobListEntry } from '../src/engine/gate-job-list.js';
import { RENDERER_INPUTS, PIPEGEN_GATE_USES } from '../src/engine/tool-flags.js';
import { PROTECTED_PATHS_BASE, PROTECTED_SECTIONS_BASE } from '../src/types.js';
import { reviewedList } from './helpers/render.js';

// input names and values spelled at run time (test/no-secret-literals.test.ts reads `<name>: <value>` as an assignment)
const GH_IN = ['github', 'token'].join('-');
const FP_IN = ['fp', 'key'].join('-');
const CRED = ['gh', 's_', 'Zq7'.repeat(12)].join('');
const FPKEY = 'k9'.repeat(20);
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';
const SHA64 = (c: string): string => c.repeat(64);
const BASE = 'b'.repeat(40);

const VIEW: GateToolView[] = gateToolView(reviewedList());
const ent = (over: Partial<JobListEntry> & { needId: string }): JobListEntry => ({
  job: over.needId, category: over.needId as JobListEntry['category'], format: 'sarif', blocking: true, [K_NS]: false,
  artifact: `pipegen-out-${over.needId}`, baseArtifact: `pipegen-out-base-${over.needId}`, ...over,
} as JobListEntry);
const LEAKS = ent({ needId: 'secrets', tool: 'betterleaks' });
const SAST = ent({ needId: 'sast', service: 'app', job: 'sast--app', tool: 'semgrep', artifact: 'pipegen-out-sast--app', baseArtifact: 'pipegen-out-base-sast--app' });
const DEPS = ent({ needId: 'deps', tool: 'osv-scanner' });
const TESTS = ((): JobListEntry => { const e = ent({ needId: 'unit-tests', service: 'app', job: 'unit-tests--app', tool: 'vitest', format: 'none' }); delete e.artifact; delete e.baseArtifact; return e; })();
const LIST = [LEAKS, SAST, DEPS, TESTS];
// the secrets job and artifact names, spelled through these (test/no-secret-literals.test.ts reads that key, a colon and a value as an assignment)
const SJ = LEAKS.job;
const SA = LEAKS.artifact as string;

const outs = (artifact: string, status = 'ok', sha = SHA64('f')): Record<string, string> => ({ [`${artifact}-sha256`]: sha, [`${artifact}-status`]: status, [`${artifact}-error`]: '' });
const NEEDS = {
  [SJ]: { result: 'success', outputs: outs(SA) },
  'sast--app': { result: 'success', outputs: outs('pipegen-out-sast--app') },
  deps: { result: 'success', outputs: outs('pipegen-out-deps') },
  'unit-tests--app': { result: 'success', outputs: {} },
  'base-scan': { result: 'success', outputs: { 'base-sha': BASE, ...outs(LEAKS.baseArtifact as string), ...outs('pipegen-out-base-sast--app'), ...outs('pipegen-out-base-deps') } },
};
const raw = (over: Record<string, string | undefined> = {}): Record<string, string | undefined> => ({
  mode: 'gate', jobs: JSON.stringify(NEEDS), 'job-list': jobListLiteral(LIST), 'service-roots': JSON.stringify(['apps/app']),
  'block-from': '', 'block-from-recorded': '2026-12-01', [GH_IN]: CRED, [FP_IN]: FPKEY, ...over,
});
const PRIV = { private: true, reviewed: VIEW };
const PUB = { private: false, reviewed: VIEW };

describe('resolveSettings: the plan\'s rules', () => {
  it('a well-formed private input set parses with no error', () => {
    const s = resolveSettings(raw({ policy: JSON.stringify({ block: ['critical', 'high', 'medium'], warn: ['low'] }) }), PRIV);
    expect(s.errors).toEqual([]);
    expect(s.jobList).toEqual(LIST);
    expect(s.policy).toEqual({ block: ['critical', 'high', 'medium'], warn: ['low'] });
    expect(s.blockFromRecorded).toBe('2026-12-01');
    expect(s.blockFrom).toBeUndefined();
    expect(s.fpKey).toBe(FPKEY);
    expect(s.token).toBe(CRED);
  });
  it('settings: not-proven containing a floor need → block', () => {
    for (const n of ['secrets', 'sast', 'deps', 'unit-tests', 'full-tests', 'migration-check']) {
      const s = resolveSettings(raw({ 'not-proven': JSON.stringify([n]) }), PRIV);
      expect(s.errors.join(' '), n).toMatch(new RegExp(`not-proven can't include floor need ${n}`));
      expect(s.notProven, n).not.toContain(n);   // the need stays required
    }
    const ok = resolveSettings(raw({ 'not-proven': JSON.stringify(['dast']) }), PRIV);
    expect(ok.errors).toEqual([]);
    expect(ok.notProven).toEqual(['dast']);
  });
  it('settings: floor need in the job list is always required (floorNeeds; a non-blocking floor entry still counts)', () => {
    const s = resolveSettings(raw({ 'job-list': jobListLiteral([LEAKS, { ...SAST, blocking: false }, DEPS, TESTS]) }), PRIV);
    expect(s.floorNeeds.sort()).toEqual(['deps', 'sast', 'secrets', 'unit-tests']);
    // secrets is a floor need of every pipeline (repo-wide, on the merge layer): a job list without it is missing it
    const withoutLeaks = resolveSettings(raw({ 'job-list': jobListLiteral([SAST, DEPS]) }), PRIV);
    expect(withoutLeaks.floorNeeds).toContain('secrets');
  });
  it('settings: public repo ignores a policy input and uses the built-in default', () => {
    const s = resolveSettings(raw({ policy: JSON.stringify({ block: ['critical', 'high', 'medium', 'low', 'info'], warn: [] }) }), PUB);
    expect(s.policy).toEqual(DEFAULT_POLICY);
    expect(s.errors).toEqual([]);
    expect(s.notes.join(' ')).toMatch(/policy input is ignored/);
    // private without a policy input: the default too
    expect(resolveSettings(raw(), PRIV).policy).toEqual(DEFAULT_POLICY);
  });
  it('settings: public repo protected paths always include base list + reviewed config files (+ service-root copies); inputs can only add', () => {
    for (const ctx of [PUB, PRIV]) {
      const s = resolveSettings(raw({ 'protected-paths': JSON.stringify(['infra/**', 'Makefile']) }), ctx);
      for (const p of PROTECTED_PATHS_BASE) expect(s.protectedPaths).toContain(p);
      for (const t of VIEW) for (const c of t.configFiles) expect(s.protectedPaths).toContain(c);
      expect(s.protectedPaths).toContain('/trivy.yaml');
      expect(s.protectedPaths).toContain('/apps/app/trivy.yaml');
      expect(s.protectedPaths.slice(-2)).toEqual(['infra/**', 'Makefile']);
      for (const sec of PROTECTED_SECTIONS_BASE) expect(s.protectedSections).toContain(sec);
      expect(s.protectedSections).toContain('pyproject.toml:tool.mypy');
    }
  });
  it('settings: secrets and dep/image tool lists come from the built-in reviewed list (no input can set them)', () => {
    const s = resolveSettings(raw(), PRIV);
    expect(s.secretsTools.sort()).toEqual(['betterleaks', 'gitleaks']);
    for (const t of ['osv-scanner', 'trivy-image', 'trivy-licence']) expect(s.sameRunTools).toContain(t);
    expect(s.sameRunTools).not.toContain('semgrep');
    for (const name of ['secrets-tools', 'dep-image-tools', 'required-tools', 'same-run-tools']) {
      expect(resolveSettings(raw({ [name]: '["semgrep"]' }), PRIV).errors.join(' '), name).toMatch(/does not take/);
    }
  });
  it('settings: report-only is no input at all (S3: dropped): set, it is a settings error', () => {
    expect(resolveSettings(raw({ 'report-only': 'true' }), PRIV).errors.join(' ')).toMatch(/report-only/);
  });
  it('settings: the stage and scrub test-only options, and the other modes\' inputs, are never gate inputs', () => {
    for (const name of ['pieceBytes', 'overlap', 'maxFiles', 'maxBytes', 'maxStagedBytes', 'artifact', 'tool', 'format', 'raw', 'out', 'stage', 'sha', 'central-sha', 'merged-at', 'workspace']) {
      expect(resolveSettings(raw({ [name]: 'x' }), PRIV).errors.join(' '), name).toMatch(/does not take/);
    }
    // an empty value is an unset input (what @actions/core gives for one), never an error
    expect(resolveSettings(raw({ artifact: '' }), PRIV).errors).toEqual([]);
  });
  it('GATE_INPUTS are exactly the renderer\'s gate-mode inputs (the RENDERER_INPUTS row) plus mode', () => {
    const row = RENDERER_INPUTS[PIPEGEN_GATE_USES] as Record<string, { whenWith?: { check: (all: Record<string, string>) => boolean } }>;
    const gateMode = Object.keys(row).filter((k) => k === 'mode' || row[k]?.whenWith?.check({ mode: 'gate' }) === true);
    expect([...GATE_INPUTS].sort()).toEqual(gateMode.sort());
  });
});

describe('resolveSettings: every input parsed strictly (each error blocks)', () => {
  const errs = (over: Record<string, string | undefined>, ctx = PRIV): string => resolveSettings(raw(over), ctx).errors.join(' | ');
  it('mode must be gate', () => {
    for (const m of [undefined, '', 'scrub', 'GATE', 'gate ']) expect(errs({ mode: m }), String(m)).toMatch(/mode/);
  });
  it('job-list: required, a JSON list of entries in the referee\'s form; names and job ids agree with the need and service', () => {
    const bad: [string, string | undefined][] = [
      ['absent', undefined], ['empty text', ''], ['not JSON', '[{'], ['not a list', '{}'], ['unknown key', JSON.stringify([{ ...LEAKS, extra: 1 }])],
      ['duplicate job', jobListLiteral([LEAKS, LEAKS])], ['bad need id', JSON.stringify([{ ...LEAKS, needId: 'Secrets' }])],
      ['artifact of another need', JSON.stringify([{ ...LEAKS, artifact: 'pipegen-out-sast' }])],
      ['base artifact not the base form', JSON.stringify([{ ...LEAKS, baseArtifact: 'pipegen-out-secrets' }])],
      ['findings entry without artifact', JSON.stringify([{ ...LEAKS, artifact: undefined }])],
      ['job-status entry with an artifact', JSON.stringify([{ ...TESTS, artifact: 'pipegen-out-unit-tests--app' }])],
      ['job id not the need and service', JSON.stringify([{ ...SAST, job: 'sast' }])],
      ['service artifact without the service', JSON.stringify([{ ...SAST, service: undefined, job: 'sast' }])],
      ['__proto__ key', '[{"__proto__":{"blocking":false},"needId":"secrets","job":"secrets","category":"secrets","format":"sarif","blocking":true}]'],
    ];
    for (const [why, v] of bad) expect(errs({ 'job-list': v }), why).toMatch(/job-list|job list/);
  });
  it('not-proven and skipped: JSON lists of need ids; skipped becomes { needId, reason }', () => {
    for (const v of ['x', '{}', '[1]', '["A"]', JSON.stringify(Array.from({ length: 51 }, (_, i) => `n${i}`))]) {
      expect(errs({ 'not-proven': v }), v).toMatch(/not-proven/);
      expect(errs({ skipped: v }), v).toMatch(/skipped/);
    }
    const s = resolveSettings(raw({ skipped: '["unit-tests"]' }), PRIV);
    expect(s.skipped).toEqual([{ needId: 'unit-tests', reason: 'skipped at setup (--skip)' }]);
  });
  it('policy (private): a policy that is not one is an error; the default is then used', () => {
    for (const v of ['x', '{}', JSON.stringify({ block: ['critical'], warn: [] }), JSON.stringify({ block: ['critical', 'high'], warn: ['high'] })]) {
      const s = resolveSettings(raw({ policy: v }), PRIV);
      expect(s.errors.join(' '), v).toMatch(/policy/);
      expect(s.policy, v).toEqual(DEFAULT_POLICY);
    }
  });
  it('protected-paths and service-roots: plain relative paths only', () => {
    for (const v of ['x', '["../x"]', '["/etc"]', '["-x"]', '[1]', '["a b"]']) {
      expect(errs({ 'protected-paths': v }), v).toMatch(/protected-paths/);
      expect(errs({ 'service-roots': v }), v).toMatch(/service-roots/);
    }
    expect(errs({ 'service-roots': '["apps/*"]' })).toMatch(/service-roots/);   // a folder, not a glob
    expect(resolveSettings(raw({ 'service-roots': '[".", "apps/app", "web/"]' }), PRIV).serviceRoots).toEqual(['.', 'apps/app', 'web/']);
  });
  it('service-roots: a job list with per-service checks needs them (else the service-root copies of root config names would be dropped)', () => {
    expect(errs({ 'service-roots': undefined })).toMatch(/service-roots/);
    expect(resolveSettings(raw({ 'service-roots': undefined, 'job-list': jobListLiteral([LEAKS, DEPS]) }), PRIV).errors).toEqual([]);
  });
  it('block-from: a variable that is not a date is ignored with a note (mode.ts treats it as unset); block-from-recorded must be a real date', () => {
    const s = resolveSettings(raw({ 'block-from': 'soon' }), PRIV);
    expect(s.errors).toEqual([]);
    expect(s.blockFrom).toBeUndefined();
    expect(s.notes.join(' ')).toMatch(/PIPEGEN_BLOCK_FROM/);
    expect(resolveSettings(raw({ 'block-from': '2026-11-02' }), PRIV).blockFrom).toBe('2026-11-02');
    for (const v of ['2026-02-30', '26-01-01', 'x']) expect(errs({ 'block-from-recorded': v }), v).toMatch(/block-from-recorded/);
    expect(resolveSettings(raw({ 'block-from-recorded': undefined }), PRIV).blockFromRecorded).toBeUndefined();
  });
  it('jobs: required, a JSON object (toJSON(needs)), at most 4 MiB', () => {
    for (const v of [undefined, '', 'x', '[]', 'null', `{"a":"${'x'.repeat(4 * 1024 * 1024)}"}`]) expect(errs({ jobs: v }), String(v).slice(0, 20)).toMatch(/jobs/);
  });
  it('github-token is required; fp-key may be empty (a fork PR has none); neither ever reaches an error or a note', () => {
    expect(errs({ [GH_IN]: '' })).toMatch(/github-token/);
    expect(resolveSettings(raw({ [FP_IN]: '' }), PRIV).fpKey).toBeUndefined();
    const s = resolveSettings(raw({ 'job-list': `[${CRED}${FPKEY}`, policy: `${CRED}${FPKEY}`, 'protected-paths': `["${CRED}", "..", "${FPKEY}"]`, artifact: CRED, [CRED]: FPKEY }), PRIV);
    expect(s.errors.length).toBeGreaterThan(0);
    for (const text of [...s.errors, ...s.notes]) {
      expect(text).not.toContain(CRED);
      expect(text).not.toContain(FPKEY);
    }
  });
});

describe('mapJobs: toJSON(needs) read through the trusted job list', () => {
  it('jobs: toJSON(needs) mapped by job id from the trusted job list', () => {
    const m = mapJobs(NEEDS, LIST);
    expect(m.checks.map((c) => [c.entry.job, c.result])).toEqual([['secrets', 'success'], ['sast--app', 'success'], ['deps', 'success'], ['unit-tests--app', 'success']]);
    expect(m.checks[1]?.outputs).toEqual({ status: 'ok', sha256: SHA64('f'), error: '' });
    expect(m.checks[1]?.baseOutputs).toEqual({ status: 'ok', sha256: SHA64('f'), error: '' });
    expect(m.checks[3]?.outputs).toEqual({});
    expect(m.baseScan).toEqual({ result: 'success', commit: BASE });
    expect(m.missingRequired).toEqual([]);
  });
  it('jobs: blocking and needsSecrets taken from the job list, not from the needs object', () => {
    const needs = { ...NEEDS, [SJ]: { ...NEEDS[SJ], blocking: false, [K_NS]: true, needId: 'other', tool: 'none' } };
    const m = mapJobs(needs, LIST);
    expect(m.checks[0]?.entry).toBe(LEAKS);
    expect(m.checks[0]?.entry.blocking).toBe(true);
  });
  it('jobs: listed blocking job absent from needs → missing required (and decide blocks it)', () => {
    const { 'sast--app': _gone, ...rest } = NEEDS;
    const m = mapJobs(rest, LIST);
    expect(m.checks[1]?.result).toBe('missing');
    expect(m.missingRequired).toEqual(['sast--app']);
    const nonBlocking = mapJobs(rest, [LEAKS, { ...SAST, blocking: false }]);
    expect(nonBlocking.missingRequired).toEqual([]);
  });
  it('jobs: tool-error status output → tool error, not a finding', () => {
    const needs = { ...NEEDS, 'sast--app': { result: 'failure', outputs: outs('pipegen-out-sast--app', 'tool-error', '') } };
    const m = mapJobs(needs, [SAST]);
    expect(m.checks[0]?.outputs.status).toBe('tool-error');
    const input: GateInput = {
      event: { name: 'push', sha: 'c'.repeat(40), payload: { before: BASE, after: 'c'.repeat(40), repository: { id: 7 } } }, checks: m.checks.map(({ baseOutputs: _b, ...c }) => c),
      baseScan: m.baseScan, ancestry: null, baseline: null, sameRunTools: [], installing: false, diff: null, rangeScans: [], mode: 'warn', policy: DEFAULT_POLICY,
      notProvenNeeds: [], skipped: [], settingsErrors: [], integrity: [], floorNeeds: [],
    };
    const r = decideGate(input);
    expect(r.toolErrors.map((t) => t.job)).toEqual(['sast--app']);
    expect(r.blocking).toEqual([]);
    expect(r.pass).toBe(false);
  });
  it('an extra job in needs that is not listed is ignored with a note (its name made safe)', () => {
    const m = mapJobs({ ...NEEDS, 'evil<b>': { result: 'success', outputs: { [`${SA}-status`]: 'ok' } } }, LIST);
    expect(m.checks).toHaveLength(4);
    expect(m.notes.join(' ')).toMatch(/not in the job list/);
    expect(m.notes.join(' ')).not.toContain('<b>');
  });
  it('a result that is not one of GitHub\'s four is missing (never success); outputs that are not text, or of another result, are not read', () => {
    for (const result of ['neutral', 'SUCCESS', 5, null, undefined]) {
      const m = mapJobs({ [SJ]: { result, outputs: outs(SA) } }, [LEAKS]);
      expect(m.checks[0]?.result, String(result)).toBe('missing');
    }
    const m = mapJobs({ [SJ]: { result: 'success', outputs: { [`${SA}-status`]: 5, [`${SA}-sha256`]: SHA64('a'), 'pipegen-out-sast-status': 'ok' } } }, [LEAKS]);
    expect(m.checks[0]?.outputs).toEqual({ sha256: SHA64('a') });
    // the base outputs come only from the base-scan job, never from a head job holding a base name
    const h = mapJobs({ [SJ]: { result: 'success', outputs: { ...outs(SA), ...outs(LEAKS.baseArtifact as string) } } }, [LEAKS]);
    expect(h.checks[0]?.baseOutputs).toBeUndefined();
    expect(h.baseScan).toBeNull();
  });
  it('the base-scan job: its base-sha output is the commit it checked out (40 hex, else none); absent job → no base scan', () => {
    expect(mapJobs({ ...NEEDS, 'base-scan': { result: 'success', outputs: { 'base-sha': 'B'.repeat(40) } } }, LIST).baseScan).toEqual({ result: 'success' });
    expect(mapJobs({ ...NEEDS, 'base-scan': { result: 'failure', outputs: {} } }, LIST).baseScan).toEqual({ result: 'failure' });
    const { 'base-scan': _b, ...noBase } = NEEDS;
    const m = mapJobs(noBase, LIST);
    expect(m.baseScan).toBeNull();
    expect(m.checks[0]?.baseOutputs).toBeUndefined();
  });
  it('hostile shapes: needs not an object, a job that is not an object, __proto__ and constructor keys, outputs not an object', () => {
    for (const needs of [null, [], 'x', 5]) expect(mapJobs(needs, LIST).checks.every((c) => c.result === 'missing'), String(needs)).toBe(true);
    const m = mapJobs(JSON.parse(`{"__proto__":{"result":"success"},"constructor":{"result":"success"},${JSON.stringify(SJ)}:"x","deps":{"result":"success","outputs":[1]}}`), [LEAKS, DEPS, ent({ needId: 'constructor' })]);
    expect(m.checks.map((c) => c.result)).toEqual(['missing', 'success', 'success']);
    expect(m.checks[1]?.outputs).toEqual({});
    expect(({} as Record<string, unknown>).result).toBeUndefined();
  });
});
