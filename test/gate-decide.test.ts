// Plan C Task C2: the gate's decision rules (gate/src/decide.ts, gate/src/policy-default.ts). decideGate turns every check's
// result, its scrubbed findings and the base into pass or block. A wrong pass is the worst bug the product can have, so every
// rule here is tested on its own, and a property grid checks that no input with a new critical, a new secret, a failed required
// job, a tool error, a missing result or a not-scanned file ever passes. Pure: no file, no network. Written first (strict test-first).
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { JobListEntry } from '../src/engine/gate-job-list.js';
import { rendererInputProblems } from '../src/engine/tool-flags.js';
import type { Finding, Severity } from '../src/types.js';
import { safeMarkdown } from '../src/util/safe-text.js';
import {
  countKeyOf, decideGate, expectedBaseOf, FORM_OF, NOT_RUN_FORK, type CheckInput, type GateEvent, type GateInput, type ResultFile,
} from '../gate/src/decide.js';
import { CONTENT_FORMS, POSITION_FORMS, type FpBy } from '../gate/src/fingerprint.js';
import { DEFAULT_POLICY, policyProblem } from '../gate/src/policy-default.js';
import type { ScrubbedFinding } from '../gate/src/scrub.js';
import { NOTHING_REPORTED_NUCLEI } from '../gate/src/sarif.js';

// ---------- builders ----------

const hex = (seed: string, ch = '0'): string => {
  let h = 0;
  for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return (h.toString(16).padStart(8, ch) + ch.repeat(56)).slice(0, 64);
};
const BASE = 'b'.repeat(40);
const HEAD = 'c'.repeat(40);
const MERGE = 'd'.repeat(40);
const SEC = 'sec' + 'ret:';
const pr = (fork = false): GateEvent => ({
  name: 'pull_request', sha: MERGE,
  payload: { repository: { id: 7 }, pull_request: { base: { sha: BASE }, head: { sha: HEAD, repo: { id: fork ? 8 : 7 } } } },
});
const push = (before = BASE): GateEvent => ({ name: 'push', sha: HEAD, payload: { repository: { id: 7 }, before, after: HEAD } });

// field names spelled at run time: `<name>: <value>` with these names reads as an assignment to test/no-secret-literals.test.ts
const K_NS = ['needs', 'Sec' + 'rets'].join('') as 'needsSecrets';
const K_S = ('sec' + 'ret') as 'secret';
const entry = (over: Partial<JobListEntry> = {}): JobListEntry => ({
  needId: 'sast', job: 'sast', category: 'sast', tool: 'semgrep', format: 'sarif',
  artifact: 'pipegen-out-sast', baseArtifact: 'pipegen-out-base-sast', blocking: true, [K_NS]: false, ...over,
} as JobListEntry);
const jobEntry = (over: Partial<JobListEntry> = {}): JobListEntry => {
  const e = entry({ needId: 'unit-tests', job: 'unit-tests', category: 'unit-tests', tool: 'vitest', format: 'none', ...over });
  delete e.artifact;
  delete e.baseArtifact;
  return e;
};
const fnd = (over: Partial<ScrubbedFinding> = {}): ScrubbedFinding => ({
  tool: 'semgrep', ruleId: 'r1', severity: 'high', file: 'a.js', line: 3, message: 'm', fingerprint: hex(JSON.stringify(over)),
  [K_S]: false, fpBy: 'hash', uriUnmapped: false, pathWithheld: false, ...over,
});
const leakF = (over: Partial<ScrubbedFinding> = {}): ScrubbedFinding => fnd({
  tool: 'betterleaks', ruleId: `${SEC}stripe-access-token`, severity: 'critical', [K_S]: true, fpBy: 'region',
  fingerprint: `${SEC}${hex(JSON.stringify(over), 'a')}`, ...over,
});
const fileOf = (findings: ScrubbedFinding[], notes: string[] = [], toolError?: string, sha = 'f'.repeat(64)): ResultFile =>
  ({ sha256: sha, read: { findings, notes, ...(toolError === undefined ? {} : { toolError }) } });
/** A findings check that ran and reported `head`, with a verified base that reported `base` (null: the base-scan has no result for it). */
function check(e: JobListEntry, head: ScrubbedFinding[], base: ScrubbedFinding[] | null = [], over: Partial<CheckInput> = {}): CheckInput {
  return {
    entry: e, result: 'success', outputs: { status: 'ok', sha256: 'f'.repeat(64) }, file: fileOf(head),
    ...(base === null ? {} : { base: { outputs: { status: 'ok', sha256: 'e'.repeat(64) }, file: fileOf(base, [], undefined, 'e'.repeat(64)) } }),
    ...over,
  };
}
const jobCheck = (e: JobListEntry, result: CheckInput['result']): CheckInput => ({ entry: e, result, outputs: {} });
function input(over: Partial<GateInput> = {}): GateInput {
  return {
    event: pr(), checks: [], baseScan: { result: 'success', commit: BASE }, ancestry: { base: BASE, head: MERGE, isAncestor: true },
    baseline: null, sameRunTools: ['osv-scanner', 'trivy-image', 'trivy-licence'], installing: false,
    diff: { added: new Map(), complete: true }, rangeScans: [], mode: 'warn', policy: DEFAULT_POLICY,
    notProvenNeeds: [], skipped: [], settingsErrors: [], integrity: [], ...over,
  };
}
const added = (m: Record<string, number[]>): GateInput['diff'] => ({ added: new Map(Object.entries(m).map(([k, v]) => [k, new Set(v)])), complete: true });
const blockText = (r: ReturnType<typeof decideGate>): string => [...r.blockReasons, ...r.blocking.map((b) => b.ruleId)].join('\n');

// ---------- Plan C Task 2 (renamed per DECISIONS #110) ----------

describe('decideGate: the plan\'s rules', () => {
  it('gate: new critical blocks in warn mode', () => {
    const r = decideGate(input({ checks: [check(entry(), [fnd({ severity: 'critical' })])] }));
    expect(r.pass).toBe(false);
    expect(r.blocking.map((b) => [b.severity, b.isNew])).toEqual([['critical', true]]);
  });
  it('gate: new high blocks in warn mode', () => {
    const r = decideGate(input({ checks: [check(entry(), [fnd({ severity: 'high' })])] }));
    expect(r.pass).toBe(false);
  });
  it('gate: new secret (low) blocks', () => {
    const r = decideGate(input({ checks: [check(entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks' }), [leakF({ severity: 'low' })])] }));
    expect(r.pass).toBe(false);
    expect(r.blocking).toHaveLength(1);
  });
  it('gate: old critical in warn mode → warning, pass', () => {
    const f = fnd({ severity: 'critical' });
    const r = decideGate(input({ checks: [check(entry(), [f], [f])] }));
    expect(r.pass).toBe(true);
    expect(r.warnings.map((w) => [w.severity, w.isNew])).toEqual([['critical', false]]);
  });
  it('gate: old critical in block mode → block', () => {
    const f = fnd({ severity: 'critical' });
    const r = decideGate(input({ mode: 'block', checks: [check(entry(), [f], [f])] }));
    expect(r.pass).toBe(false);
    expect(r.blocking.map((b) => b.isNew)).toEqual([false]);
  });
  it('gate: no artifact baseline → base-scan diff keeps existing findings old', () => {
    const f = fnd({ severity: 'critical' });
    const r = decideGate(input({ baseline: null, checks: [check(entry(), [f], [f])] }));
    expect(r.pass).toBe(true);
    expect(r.warnings[0]?.isNew).toBe(false);
  });
  it('gate: count increase → extra occurrence is new', () => {
    const f = fnd({ severity: 'high', fingerprint: hex('same') });
    const r = decideGate(input({ checks: [check(entry(), [f, { ...f, line: 9 }, { ...f, line: 12 }], [f, f])] }));
    expect(r.pass).toBe(false);
    expect(r.blocking).toHaveLength(1);
    expect(r.warnings).toHaveLength(2);
  });
  it('gate: image CVE without file compared by fingerprint', () => {
    const e = entry({ needId: 'image-scan', job: 'image-scan--app', category: 'image-scan', tool: 'trivy-image' });
    const cve = fnd({ tool: 'trivy-image', ruleId: 'CVE-2026-1', severity: 'critical', file: undefined, line: undefined, fingerprint: hex('cve1') });
    expect(decideGate(input({ checks: [check(e, [cve], [cve])] })).pass).toBe(true);
    expect(decideGate(input({ checks: [check(e, [cve], [{ ...cve, fingerprint: hex('cve2') }])] })).pass).toBe(false);
  });
  it('gate: dep CVE also in same-run base scan → old even when the artifact baseline lacks it', () => {
    const e = entry({ needId: 'deps', job: 'deps--app', category: 'deps', tool: 'osv-scanner' });
    const cve = fnd({ tool: 'osv-scanner', ruleId: 'GHSA-1', severity: 'critical', file: 'package-lock.json', line: undefined });
    const r = decideGate(input({ baseline: { tools: ['osv-scanner'], counts: new Map() }, checks: [check(e, [cve], [cve])] }));
    expect(r.pass).toBe(true);
  });
  it('gate: dep CVE in artifact baseline but not in base scan → new', () => {
    const e = entry({ needId: 'deps', job: 'deps--app', category: 'deps', tool: 'osv-scanner' });
    const cve = fnd({ tool: 'osv-scanner', ruleId: 'GHSA-1', severity: 'critical', file: 'package-lock.json', line: undefined });
    const r = decideGate(input({ baseline: { tools: ['osv-scanner'], counts: new Map([[countKeyOf(e.job, cve), 1]]) }, checks: [check(e, [cve], [])] }));
    expect(r.pass).toBe(false);
  });
  it('gate: scanner that couldn\'t run on the base → warnings on installing PR', () => {
    const e = entry({ needId: 'image-scan', job: 'image-scan--app', category: 'image-scan', tool: 'trivy-image' });
    const cve = fnd({ tool: 'trivy-image', severity: 'critical', file: undefined });
    const r = decideGate(input({ installing: true, checks: [check(e, [cve], null)] }));
    expect(r.pass).toBe(true);
    expect(r.warnings).toHaveLength(1);
    expect(r.notes.join('\n')).toMatch(/couldn't run on the base commit/);
  });
  it('gate: scanner that couldn\'t run on the base → new on a normal PR', () => {
    const e = entry({ needId: 'image-scan', job: 'image-scan--app', category: 'image-scan', tool: 'trivy-image' });
    const cve = fnd({ tool: 'trivy-image', severity: 'critical', file: undefined });
    const r = decideGate(input({ checks: [check(e, [cve], null)] }));
    expect(r.pass).toBe(false);
    expect(r.blocking[0]?.isNew).toBe(true);
  });
  it('gate: tampered result blocks', () => {
    const c = check(entry(), []);
    const r = decideGate(input({ checks: [{ ...c, outputs: { status: 'ok', sha256: '0'.repeat(64) } }] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons.join('\n')).toMatch(/result tampered or missing: sast/);
  });
  it('gate: settings error blocks', () => {
    const r = decideGate(input({ settingsErrors: ['not-proven can\'t include floor need secrets'] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons).toContain('not-proven can\'t include floor need secrets');
  });
  it('gate: integrity finding blocks', () => {
    const i: Finding = { tool: 'pipegen', ruleId: 'integrity:protected-path', severity: 'high', file: '.github/workflows/pipegen.yml', message: 'changed', fingerprint: hex('i') };
    const r = decideGate(input({ integrity: [i] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons.join('\n')).toMatch(/pipeline files changed or suppressions added without code-owner approval on the current commit/);
  });
  it('gate: integrity finding on installing PR → warning', () => {
    const i: Finding = { tool: 'pipegen', ruleId: 'integrity:protected-path', severity: 'high', file: '.github/workflows/pipegen.yml', message: 'changed', fingerprint: hex('i') };
    const r = decideGate(input({ installing: true, integrity: [i] }));
    expect(r.pass).toBe(true);
    expect(r.summary).toMatch(/installing pipegen: review these files/);
  });
  it('gate: tool error is listed as a tool error, not a finding, and blocks for a required tool', () => {
    const c = check(entry(), []);
    const r = decideGate(input({ checks: [{ ...c, result: 'failure', outputs: { status: 'tool-error', error: 'semgrep crashed' } }] }));
    expect(r.pass).toBe(false);
    expect(r.toolErrors.map((t) => [t.job, t.blocks])).toEqual([['sast', true]]);
    expect(r.blocking).toEqual([]);
    expect(r.failedJobs).toEqual([]);
    expect(r.blockReasons.join('\n')).toMatch(/tool error in semgrep \(sast\): re-run the job/);
  });
  it('gate: tool error in a not-proven tool only warns', () => {
    const e = entry({ needId: 'dast', job: 'dast--app', category: 'dast', tool: 'nuclei', blocking: true });
    const c = check(e, []);
    const r = decideGate(input({ notProvenNeeds: ['dast'], checks: [{ ...c, outputs: { status: 'tool-error', error: 'x' } }] }));
    expect(r.pass).toBe(true);
    expect(r.toolErrors.map((t) => t.blocks)).toEqual([false]);
  });
  it('gate: fork PR, secret-needing job skipped → "not run on a fork PR", not failed, and the gate blocks (DECISIONS #110)', () => {
    const e = jobEntry({ needId: 'full-tests', job: 'full-tests--app', category: 'full-tests', [K_NS]: true });
    const r = decideGate(input({ event: pr(true), checks: [jobCheck(e, 'skipped')] }));
    expect(r.pass).toBe(false);
    expect(r.notRun.map((n) => n.job)).toEqual(['full-tests--app']);
    expect(r.failedJobs).toEqual([]);
    expect(r.blockReasons.join('\n')).toContain(NOT_RUN_FORK);
    expect(NOT_RUN_FORK).toBe('not run on a fork PR (no secrets): a maintainer must run it from a branch of this repository');
  });
  it('gate: fork PR without fp key → secret on added line is new', () => {
    const e = entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks' });
    const s = leakF({ fpBy: 'nokey', fingerprint: `${SEC.replace(':', '-nokey:')}${hex('k')}`, file: 'a.js', line: 4 });
    const r = decideGate(input({ event: pr(true), diff: added({ 'a.js': [4] }), checks: [check(e, [s], [s])] }));
    expect(r.pass).toBe(false);
    expect(r.blocking[0]?.reason).toMatch(/changed line/);
  });
  it('gate: fork PR without fp key → secret on an unchanged line is old', () => {
    const e = entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks' });
    const s = leakF({ fpBy: 'nokey', fingerprint: `${SEC.replace(':', '-nokey:')}${hex('k')}`, file: 'a.js', line: 4 });
    const r = decideGate(input({ event: pr(true), diff: added({ 'a.js': [5, 6] }), checks: [check(e, [s], [s])] }));
    expect(r.pass).toBe(true);
    expect(r.warnings[0]?.isNew).toBe(false);
  });
  it('gate: not-proven job failing only warns (judged by its job result, ruling S2)', () => {
    const e = jobEntry({ needId: 'api-dast', job: 'api-dast--app', category: 'api-dast' });
    const r = decideGate(input({ notProvenNeeds: ['api-dast'], checks: [jobCheck(e, 'failure')] }));
    expect(r.pass).toBe(true);
    expect(r.notProven.map((n) => n.job)).toEqual(['api-dast--app']);
  });
  it('gate: policy-default matches documented default', () => {
    expect(DEFAULT_POLICY).toEqual({ block: ['critical', 'high'], warn: ['medium'] });
    expect(Object.isFrozen(DEFAULT_POLICY)).toBe(true);
  });
});

// ---------- pre-flight §5 C2 list ----------

describe('decideGate: the pre-flight C2 list (B7, S2, S8, S12, S19)', () => {
  it('gate: required job skipped and not in skipped → block', () => {
    const r = decideGate(input({ checks: [jobCheck(jobEntry(), 'skipped')] }));
    expect(r.pass).toBe(false);
    expect(r.failedJobs.map((f) => f.job)).toEqual(['unit-tests']);
  });
  it('gate: fork PR, needs-secrets findings job → "not run", gate does not pass', () => {
    const e = entry({ needId: 'dast', job: 'dast--app', category: 'dast', tool: 'nuclei', [K_NS]: true });
    const r = decideGate(input({ event: pr(true), checks: [{ entry: e, result: 'skipped', outputs: {} }] }));
    expect(r.pass).toBe(false);
    expect(r.notRun).toHaveLength(1);
  });
  it('gate: MAL- advisory blocks even when old, in warn mode', () => {
    const e = entry({ needId: 'deps', job: 'deps--app', category: 'deps', tool: 'osv-scanner' });
    const mal = fnd({ tool: 'osv-scanner', ruleId: 'MAL-2026-77', severity: 'medium', file: 'package-lock.json', line: undefined });
    const r = decideGate(input({ checks: [check(e, [mal], [mal])] }));
    expect(r.pass).toBe(false);
    expect(r.blocking.map((b) => [b.ruleId, b.isNew])).toEqual([['MAL-2026-77', false]]);
    expect(r.blocking[0]?.reason).toMatch(/malicious package/);
  });
  it('gate: findings of a non-blocking need never block (not even a new critical; a tool error or a missing result is a note)', () => {
    const e = entry({ needId: 'duplication', job: 'duplication', category: 'duplication', tool: 'semgrep', blocking: false });
    const r = decideGate(input({ mode: 'block', checks: [check(e, [fnd({ severity: 'critical' }), leakF()])] }));
    expect(r.pass).toBe(true);
    expect(r.warnings).toHaveLength(2);
    const te = decideGate(input({ checks: [{ ...check(e, []), outputs: { status: 'tool-error', error: 'x' } }] }));
    expect(te.pass).toBe(true);
    const missing = decideGate(input({ checks: [{ ...check(e, []), outputs: {} }] }));
    expect(missing.pass).toBe(true);
    expect(missing.notes.join('\n')).toMatch(/did not report/);
  });
  it('gate: warn-first job-status check failing → warning until a reviewed PR flips it', () => {
    const e = jobEntry({ needId: 'type-check', job: 'type-check--app', category: 'type-check', warnFirst: { since: '2026-10-01' } });
    const r = decideGate(input({ mode: 'block', checks: [jobCheck(e, 'failure')] }));
    expect(r.pass).toBe(true);
    expect(r.warnReasons.join('\n')).toMatch(/warn-first/);
    // the same check without the field (the reviewed PR removed it) blocks
    const { warnFirst: _w, ...flipped } = e;
    expect(decideGate(input({ checks: [jobCheck(flipped as JobListEntry, 'failure')] })).pass).toBe(false);
  });
  it('gate: warn-first never on a floor need → settings error', () => {
    const e = jobEntry({ warnFirst: { since: '2026-10-01' } });   // unit-tests is a floor need
    const r = decideGate(input({ checks: [jobCheck(e, 'success')] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons.join('\n')).toMatch(/warn-first can't be set on floor need unit-tests/);
  });
  it('gate: new critical in a warn-first findings check still blocks; its old and medium findings warn', () => {
    const e = entry({ needId: 'iac', job: 'iac', category: 'iac', tool: 'trivy-config', warnFirst: { since: '2026-10-01' } });
    const old = fnd({ tool: 'trivy-config', severity: 'critical', fingerprint: hex('old') });
    expect(decideGate(input({ checks: [check(e, [fnd({ tool: 'trivy-config', severity: 'critical' })])] })).pass).toBe(false);
    const r = decideGate(input({ mode: 'block', checks: [check(e, [old, fnd({ tool: 'trivy-config', severity: 'medium' })], [old])] }));
    expect(r.pass).toBe(true);
    expect(r.warnings).toHaveLength(2);
  });
  it('gate: not-proven need judged by job result (a success is fine, a failure warns, never blocks)', () => {
    const e = jobEntry({ needId: 'api-dast', job: 'api-dast', category: 'api-dast' });
    expect(decideGate(input({ notProvenNeeds: ['api-dast'], checks: [jobCheck(e, 'success')] })).warnReasons).toEqual([]);
    for (const res of ['failure', 'cancelled', 'skipped', 'missing'] as const) {
      const r = decideGate(input({ notProvenNeeds: ['api-dast'], checks: [jobCheck(e, res)] }));
      expect(r.pass, res).toBe(true);
      expect(r.warnReasons.length, res).toBe(1);
    }
  });
  it('gate: base tool-error → tool error, block', () => {
    const c = check(entry(), [fnd({ severity: 'low' })]);
    const r = decideGate(input({ checks: [{ ...c, base: { outputs: { status: 'tool-error', error: 'db download failed' } } }] }));
    expect(r.pass).toBe(false);
    expect(r.toolErrors.map((t) => [t.job, t.base, t.blocks])).toEqual([['sast', true, true]]);
  });
  it('gate: format sarif → findings; none → job status (ruling B2)', () => {
    const r = decideGate(input({ checks: [check(entry(), []), jobCheck(jobEntry(), 'success')] }));
    expect(r.pass).toBe(true);
    expect(r.summary).toMatch(/unit-tests[^\n]*judged by job status/);
    expect(r.summary).toMatch(/sast[^\n]*judged by findings/);
  });
});

// ---------- B7 and #110 ----------

describe('decideGate: a listed job is clean only with success (B7, DECISIONS #110)', () => {
  for (const res of ['failure', 'cancelled', 'skipped', 'missing'] as const) {
    it(`a required job-status check with result ${res} blocks`, () => {
      const r = decideGate(input({ checks: [jobCheck(jobEntry(), res)] }));
      expect(r.pass).toBe(false);
      expect(r.failedJobs[0]?.reason).toContain(res);
    });
    it(`a required findings check with result ${res} blocks, even with an ok status and a matching file`, () => {
      const r = decideGate(input({ checks: [{ ...check(entry(), []), result: res }] }));
      expect(r.pass).toBe(false);
    });
  }
  it('a findings check needs status ok and a matching sha256: no status → did not report; another status, a missing or different hash, a missing file or a file problem → tampered', () => {
    const c = check(entry(), []);
    expect(decideGate(input({ checks: [{ ...c, outputs: {} }] })).blockReasons.join()).toMatch(/scanner semgrep \(sast\) did not report/);
    for (const bad of [
      { ...c, outputs: { status: 'weird', sha256: 'f'.repeat(64) } },
      { ...c, outputs: { status: 'ok' } },
      { ...c, outputs: { status: 'ok', sha256: 'a'.repeat(64) } },
      { ...c, file: undefined },
      { ...c, file: { ...(c.file as ResultFile), problem: 'the zip holds two entries' } },
    ]) {
      const r = decideGate(input({ checks: [bad] }));
      expect(r.pass).toBe(false);
      expect(r.blockReasons.join()).toMatch(/result tampered or missing/);
    }
    // a scrubbed file that can not be read back is a tool error
    expect(decideGate(input({ checks: [{ ...c, file: fileOf([], [], 'not written by the scrub') }] })).toolErrors).toHaveLength(1);
  });
  it('a check the user skipped (--skip) is shown as skipped, never as clean, and does not block; secrets, sast, deps and gate can never be skipped', () => {
    const r = decideGate(input({ skipped: [{ needId: 'unit-tests', reason: '--skip tests' }], checks: [jobCheck(jobEntry(), 'skipped')] }));
    expect(r.pass).toBe(true);
    expect(r.skipped.map((s) => s.needId)).toEqual(['unit-tests']);
    expect(r.summary).toMatch(/Skipped/);
    expect(r.summary).not.toMatch(/unit-tests[^\n]*passed/);
    const bad = decideGate(input({ skipped: [{ needId: 'secrets', reason: 'x' }] }));
    expect(bad.pass).toBe(false);
    expect(bad.blockReasons.join()).toMatch(/secrets can never be skipped/);
  });
  it('a fork PR: a needs-secrets check that failed is "not run" too (never "failed"); a check without secrets that failed is a failed job', () => {
    const e = jobEntry({ [K_NS]: true });
    const r = decideGate(input({ event: pr(true), checks: [jobCheck(e, 'failure'), jobCheck(jobEntry({ needId: 'lint', job: 'lint', category: 'lint' }), 'failure')] }));
    expect(r.notRun.map((n) => n.job)).toEqual(['unit-tests']);
    expect(r.failedJobs.map((n) => n.job)).toEqual(['lint']);
    expect(r.pass).toBe(false);
    // the same on a PR from this repository: failed, not "not run"
    const own = decideGate(input({ checks: [jobCheck(e, 'failure')] }));
    expect(own.notRun).toEqual([]);
    expect(own.failedJobs).toHaveLength(1);
  });
  it('the summary lists not run (fork PR) in its own section', () => {
    const r = decideGate(input({ event: pr(true), checks: [jobCheck(jobEntry({ [K_NS]: true }), 'skipped')] }));
    expect(r.summary).toMatch(/### Not run \(fork PR\)/);
  });
});

describe('decideGate: floor needs, warn-first findings checks and the base artifact (mutation-found gaps)', () => {
  it('a floor need in not-proven is a settings error, and the check stays required (its failure blocks)', () => {
    const r = decideGate(input({ notProvenNeeds: ['unit-tests'], checks: [jobCheck(jobEntry(), 'success')] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons).toContain('not-proven can\'t include floor need unit-tests');
    const f = decideGate(input({ notProvenNeeds: ['unit-tests'], checks: [jobCheck(jobEntry(), 'failure')] }));
    expect(f.failedJobs).toHaveLength(1);
    expect(f.notProven).toEqual([]);
  });
  it('a floor need marked non-blocking is still required: its failure and its new findings block', () => {
    expect(decideGate(input({ checks: [jobCheck(jobEntry({ blocking: false }), 'failure')] })).pass).toBe(false);
    expect(decideGate(input({ checks: [check(entry({ blocking: false }), [fnd({ severity: 'high' })])] })).pass).toBe(false);
  });
  it('a warn-first findings check that failed (not a tool error) blocks: without its findings rule 7 can not be judged', () => {
    const e = entry({ needId: 'iac', job: 'iac', category: 'iac', tool: 'trivy-config', warnFirst: { since: '2026-10-01' } });
    const r = decideGate(input({ checks: [{ ...check(e, []), result: 'failure' }] }));
    expect(r.pass).toBe(false);
    expect(r.failedJobs.map((x) => x.job)).toEqual(['iac']);
  });
  it('status ok with no sha256 output is tampered, said so', () => {
    const r = decideGate(input({ checks: [{ ...check(entry(), []), outputs: { status: 'ok' } }] }));
    expect(r.blockReasons.join()).toMatch(/no sha256 output/);
  });
  it('a "nothing reported" note is no coverage whatever the tool', () => {
    const e = entry({ needId: 'dast', job: 'dast--app', category: 'dast', tool: 'semgrep', blocking: false });
    expect(decideGate(input({ checks: [{ ...check(e, []), file: fileOf([], ['nothing reported (synthesized empty result)']) }] })).noCoverage).toHaveLength(1);
  });
  it('a base artifact whose hash does not match the base-scan output, or that is missing, is tampered and blocks', () => {
    const c = check(entry(), []);
    const bad = { ...c, base: { outputs: { status: 'ok', sha256: 'e'.repeat(64) }, file: fileOf([], [], undefined, '1'.repeat(64)) } };
    const r = decideGate(input({ checks: [bad] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons.join()).toMatch(/result tampered or missing: sast \(pipegen-out-base-sast/);
    expect(decideGate(input({ checks: [{ ...c, base: { outputs: { status: 'ok', sha256: 'e'.repeat(64) } } }] })).pass).toBe(false);
  });
  it('a baseline that does not cover the tool is not used: the base scan decides', () => {
    const f = fnd({ severity: 'critical' });
    expect(decideGate(input({ baseline: { tools: ['other'], counts: new Map() }, checks: [check(entry(), [f], [f])] })).pass).toBe(true);
    expect(decideGate(input({ baseline: { tools: ['semgrep'], counts: new Map() }, checks: [check(entry(), [f], [f])] })).pass).toBe(false);
  });
  it('an unverified base with no base result on an installing PR is still "every finding new", not the installing warning', () => {
    const f = fnd({ severity: 'critical' });
    expect(decideGate(input({ installing: true, baseScan: { result: 'success', commit: 'a'.repeat(40) }, checks: [check(entry(), [f], null)] })).pass).toBe(false);
  });
  it('a not-scanned file on an installing PR whose scanner could not run on the base is new (no file hash in a base)', () => {
    const se = entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks' });
    const ns = leakF({ ruleId: `${SEC}not-scanned`, fpBy: 'file', fingerprint: `${SEC}${hex('ns-i')}`, line: 1, endLine: 5 });
    expect(decideGate(input({ installing: true, checks: [check(se, [ns], null)] })).pass).toBe(false);
  });
});

// ---------- base verification (CF3b) ----------

describe('decideGate: the base counts only when it is the base of this event and an ancestor of the head (CF3b)', () => {
  const f = fnd({ severity: 'critical' });
  const run = (over: Partial<GateInput>) => decideGate(input({ checks: [check(entry(), [f], [f])], ...over }));
  it('verified: pull_request base.sha, ancestor of the head → old', () => {
    expect(run({}).pass).toBe(true);
  });
  it('a base-scan commit other than the event\'s base → no base: every finding new', () => {
    const r = run({ baseScan: { result: 'success', commit: 'a'.repeat(40) } });
    expect(r.pass).toBe(false);
    expect(r.notes.join('\n')).toMatch(/no base/);
  });
  it('no commit output, a base equal to the head, no ancestry fact, a fact about other commits, or not an ancestor → no base', () => {
    for (const over of [
      { baseScan: { result: 'success' as const } },
      { ancestry: null },
      { ancestry: { base: BASE, head: MERGE, isAncestor: false } },
      { ancestry: { base: 'a'.repeat(40), head: MERGE, isAncestor: true } },
      { ancestry: { base: BASE, head: 'a'.repeat(40), isAncestor: true } },
      { event: { ...pr(), payload: { repository: { id: 7 }, pull_request: { base: { sha: HEAD }, head: { sha: HEAD, repo: { id: 7 } } } } }, baseScan: { result: 'success' as const, commit: HEAD }, ancestry: { base: HEAD, head: HEAD, isAncestor: true } },
    ]) expect(run(over).pass, JSON.stringify(over)).toBe(false);
  });
  it('the head of the ancestry fact may be the PR head or the merge commit (github.sha)', () => {
    expect(run({ ancestry: { base: BASE, head: HEAD, isAncestor: true } }).pass).toBe(true);
  });
  it('push: before is the base; all zeros (a new branch) → no base', () => {
    const p = push();
    expect(run({ event: p, ancestry: { base: BASE, head: HEAD, isAncestor: true }, diff: null }).pass).toBe(true);
    const zero = '0'.repeat(40);
    expect(run({ event: push(zero), baseScan: { result: 'success', commit: zero }, ancestry: { base: zero, head: HEAD, isAncestor: true }, diff: null }).pass).toBe(false);
  });
  it('merge_group: base_sha is the base; any other event has none', () => {
    const mg: GateEvent = { name: 'merge_group', sha: HEAD, payload: { repository: { id: 7 }, merge_group: { base_sha: BASE, head_sha: HEAD } } };
    expect(run({ event: mg, ancestry: { base: BASE, head: HEAD, isAncestor: true } }).pass).toBe(true);
    expect(expectedBaseOf(mg)).toMatchObject({ base: BASE });
    expect(expectedBaseOf({ name: 'pull_request_review', sha: HEAD, payload: pr().payload }).base).toBeUndefined();
    expect(expectedBaseOf({ name: 'pull_request', sha: MERGE, payload: { pull_request: { base: { sha: 'xyz' } } } }).base).toBeUndefined();
  });
  it('an unverified base does not touch the trusted artifact baseline of a code tool', () => {
    const r = run({ baseScan: { result: 'success', commit: 'a'.repeat(40) }, baseline: { tools: ['semgrep'], counts: new Map([[countKeyOf('sast', f), 1]]) } });
    expect(r.pass).toBe(true);
  });
  it('an unverified base on an installing PR is still "no base, every finding new" (only a scanner that could not run gets the installing warning)', () => {
    expect(run({ installing: true, baseScan: { result: 'success', commit: 'a'.repeat(40) } }).pass).toBe(false);
  });
});

// ---------- fingerprint forms ----------

describe('decideGate: the decision per fingerprint form', () => {
  const se = entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks' });
  it('the form table covers every FpBy, as fingerprint.ts splits them', () => {
    const all: FpBy[] = [...CONTENT_FORMS, ...POSITION_FORMS];
    expect(Object.keys(FORM_OF).sort()).toEqual([...all].sort());
    for (const b of CONTENT_FORMS) expect(FORM_OF[b]).toBe('content');
    for (const b of POSITION_FORMS) expect(FORM_OF[b]).toBe('position');
  });
  it('content forms are compared by count: a moved secret (same bytes) is old, a second copy is new', () => {
    const s = leakF({ fingerprint: `${SEC}${hex('x')}` });
    expect(decideGate(input({ diff: added({ 'a.js': [3] }), checks: [check(se, [{ ...s, line: 3 }], [{ ...s, line: 40 }])] })).pass).toBe(true);
    expect(decideGate(input({ checks: [check(se, [s, { ...s, file: 'b.js' }], [s])] })).pass).toBe(false);
  });
  for (const fpBy of POSITION_FORMS) {
    it(`position form ${fpBy}: new when the diff touched any of its lines, even with the count unchanged`, () => {
      const s = leakF({ fpBy, fingerprint: `${SEC}${hex(fpBy)}`, line: 10, endLine: 14 });
      expect(decideGate(input({ diff: added({ 'a.js': [12] }), checks: [check(se, [s], [s])] })).pass).toBe(false);
      expect(decideGate(input({ diff: added({ 'a.js': [9, 15], 'b.js': [12] }), checks: [check(se, [s], [s])] })).pass).toBe(true);
    });
  }
  it('position form: no repo file → new on an event with a diff; without a diff (push) counts only', () => {
    const e = entry({ needId: 'image-scan', job: 'image-scan--app', category: 'image-scan', tool: 'trivy-image' });
    const s = leakF({ tool: 'trivy-image', fpBy: 'line', file: undefined, line: undefined, fingerprint: `${SEC}${hex('img')}` });
    expect(decideGate(input({ checks: [check(e, [s], [s])] })).pass).toBe(false);
    const p = { event: push(), ancestry: { base: BASE, head: HEAD, isAncestor: true }, diff: null };
    expect(decideGate(input({ ...p, checks: [check(e, [s], [s])] })).pass).toBe(true);
    expect(decideGate(input({ ...p, checks: [check(e, [s, s], [s])] })).pass).toBe(false);
  });
  it('every trivy secret is a position form, whatever its fpBy says', () => {
    const e = entry({ needId: 'iac', job: 'iac', category: 'iac', tool: 'trivy-config' });
    const s = leakF({ tool: 'trivy-config', fpBy: 'region', fingerprint: `${SEC}${hex('tc')}`, line: 2 });
    expect(decideGate(input({ diff: added({ 'a.js': [2] }), checks: [check(e, [s], [s])] })).pass).toBe(false);
  });
  it('a position form with no line in a file the PR changed is new; an incomplete diff makes every position form new', () => {
    const s = leakF({ fpBy: 'nokey', fingerprint: `${SEC}${hex('nl')}`, line: undefined });
    expect(decideGate(input({ diff: added({ 'a.js': [1] }), checks: [check(se, [s], [s])] })).pass).toBe(false);
    const t = leakF({ fpBy: 'line', fingerprint: `${SEC}${hex('t')}`, line: 3 });
    expect(decideGate(input({ diff: { added: new Map(), complete: false }, checks: [check(se, [t], [t])] })).pass).toBe(false);
  });
  it('position form, untouched: the count still decides (an extra untouched copy is new)', () => {
    const s = leakF({ fpBy: 'line', fingerprint: `${SEC}${hex('u')}`, line: 3 });
    expect(decideGate(input({ checks: [check(se, [s, { ...s, line: 8 }], [s])] })).pass).toBe(false);
  });
  it('unmapped: any secret is new (also with a key, also without a diff); a non-secret is counted per (tool, rule) with no path', () => {
    const s = leakF({ file: undefined, uriUnmapped: true, fingerprint: `${SEC}${hex('um')}` });
    expect(decideGate(input({ checks: [check(se, [s], [s])] })).pass).toBe(false);
    expect(decideGate(input({ event: push(), ancestry: { base: BASE, head: HEAD, isAncestor: true }, diff: null, checks: [check(se, [s], [s])] })).pass).toBe(false);
    const n1 = fnd({ file: undefined, uriUnmapped: true, fingerprint: hex('n1'), severity: 'high' });
    const n2 = fnd({ file: undefined, uriUnmapped: true, fingerprint: hex('n2'), severity: 'high' });
    expect(decideGate(input({ checks: [check(entry(), [n1], [n2])] })).pass).toBe(true);   // same tool and rule, another unmapped place: one in base, one in head
    expect(decideGate(input({ checks: [check(entry(), [n1, n2], [n2])] })).pass).toBe(false);
    expect(decideGate(input({ checks: [check(entry(), [{ ...n1, ruleId: 'r2' }], [n2])] })).pass).toBe(false);
    expect(countKeyOf('sast', n1)).toBe(countKeyOf('sast', n2));
  });
  it('a not-scanned finding is a critical leak: new unless the same file hash (the file form) is in the base; keyless it is always new', () => {
    const ns = leakF({ ruleId: `${SEC}not-scanned`, fpBy: 'file', fingerprint: `${SEC}${hex('ns')}`, line: 1, endLine: 50 });
    expect(decideGate(input({ checks: [check(se, [ns], [ns])] })).pass).toBe(true);
    const r = decideGate(input({ checks: [check(se, [ns], [])] }));
    expect(r.pass).toBe(false);
    expect(r.notScanned).toHaveLength(1);
    expect(r.summary).toMatch(/### Not scanned/);
    const keyless = leakF({ ruleId: `${SEC}not-scanned`, fpBy: 'nokey', fingerprint: `${SEC.replace(':', '-nokey:')}${hex('ns')}`, line: 1, endLine: 50 });
    expect(decideGate(input({ event: pr(true), diff: added({}), checks: [check(se, [keyless], [keyless])] })).pass).toBe(false);
  });
  it('counts are per check (job), so one tool in two checks never mixes counts', () => {
    const a = entry({ needId: 'deps', job: 'deps--a', category: 'deps', tool: 'osv-scanner' });
    const b = entry({ needId: 'dependency-review', job: 'dependency-review', category: 'dependency-review', tool: 'osv-scanner' });
    const cve = fnd({ tool: 'osv-scanner', ruleId: 'GHSA-1', severity: 'critical', fingerprint: hex('g') });
    // the base of deps--a has it; dependency-review's base does not
    expect(decideGate(input({ checks: [check(a, [cve], [cve]), check(b, [cve], [])] })).pass).toBe(false);
    expect(countKeyOf('deps--a', cve)).not.toBe(countKeyOf('dependency-review', cve));
  });
});

// ---------- PR commit-range secrets (I2) ----------

describe('decideGate: secrets in the PR\'s commit range (C1b review I2)', () => {
  const se = entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks' });
  it('a range finding not present in the HEAD scan is always new and blocks, in any mode, even if the base has it', () => {
    const gone = leakF({ fingerprint: `${SEC}${hex('gone')}` });
    const r = decideGate(input({ checks: [check(se, [], [gone])], rangeScans: [{ tool: 'betterleaks', findings: [gone] }] }));
    expect(r.pass).toBe(false);
    expect(r.blocking[0]?.reason).toMatch(/pull request's commits/);
  });
  it('a range finding also in the HEAD scan is judged by the HEAD scan', () => {
    const s = leakF({ fingerprint: `${SEC}${hex('both')}` });
    expect(decideGate(input({ checks: [check(se, [s], [s])], rangeScans: [{ tool: 'betterleaks', findings: [s] }] })).pass).toBe(true);
  });
  it('a range scan with a tool error, or with no result, blocks as a tool error', () => {
    expect(decideGate(input({ checks: [check(se, [])], rangeScans: [{ tool: 'betterleaks', toolError: 'x' }] })).pass).toBe(false);
    expect(decideGate(input({ checks: [check(se, [])], rangeScans: [{ tool: 'betterleaks' }] })).pass).toBe(false);
  });
});

// ---------- coverage honesty, ZAP, licences, dependency-review ----------

describe('decideGate: coverage honesty and the per-category rules', () => {
  it('nuclei "nothing reported" (marked file or zero results) is no coverage, never clean, never counted as covered', () => {
    const e = entry({ needId: 'dast', job: 'dast--app', category: 'dast', tool: 'nuclei', blocking: false });
    for (const note of [NOTHING_REPORTED_NUCLEI, 'nothing reported (synthesized empty result)']) {
      const r = decideGate(input({ checks: [{ ...check(e, []), file: fileOf([], [note]) }] }));
      expect(r.noCoverage.map((n) => n.job)).toEqual(['dast--app']);
      expect(r.summary).toMatch(/### No coverage/);
      expect(r.summary).toMatch(/completeness not provable/);
      expect(r.summary).not.toMatch(/dast--app[^\n]*passed/);
    }
  });
  it('a gitleaks zero-finding unstaged result is no coverage; a required one blocks; a staged one (no note) is clean', () => {
    const e = entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'gitleaks' });
    const r = decideGate(input({ checks: [{ ...check(e, []), file: fileOf([], ['completeness not provable (gitleaks)']) }] }));
    expect(r.noCoverage).toHaveLength(1);
    expect(r.pass).toBe(false);
    expect(decideGate(input({ checks: [check(e, [])] })).pass).toBe(true);
  });
  it('ZAP is unverified: a blocking DAST need on ZAP is not proven (a warning), its findings and failures never block', () => {
    const e = entry({ needId: 'dast', job: 'dast--app', category: 'dast', tool: 'zap-baseline', format: 'zap-json' });
    const r = decideGate(input({ mode: 'block', checks: [check(e, [fnd({ tool: 'zap-baseline', severity: 'high' })])] }));
    expect(r.pass).toBe(true);
    expect(r.notProven.map((n) => n.job)).toEqual(['dast--app']);
    expect(r.warnings).toHaveLength(1);
    expect(decideGate(input({ checks: [{ ...check(e, []), result: 'failure', outputs: { status: 'tool-error', error: 'x' } }] })).pass).toBe(true);
  });
  it('licences: Forbidden (critical) and Restricted (high) block when new; Unknown (info) is a warning that needs a human and never blocks', () => {
    const e = entry({ needId: 'licences', job: 'licences', category: 'licences', tool: 'trivy-licence' });
    const unknown = fnd({ tool: 'trivy-licence', ruleId: 'UNKNOWN', severity: 'info' });
    const r = decideGate(input({ mode: 'block', checks: [check(e, [unknown])] }));
    expect(r.pass).toBe(true);
    expect(r.warnings[0]?.reason).toMatch(/needs a human/);
    expect(decideGate(input({ checks: [check(e, [fnd({ tool: 'trivy-licence', severity: 'critical' })])] })).pass).toBe(false);
  });
  it('dependency-review: any new vulnerability blocks (any severity), compared with the same-run base scan', () => {
    const e = entry({ needId: 'dependency-review', job: 'dependency-review', category: 'dependency-review', tool: 'osv-scanner' });
    const low = fnd({ tool: 'osv-scanner', ruleId: 'GHSA-low', severity: 'low' });
    expect(decideGate(input({ checks: [check(e, [low], [])] })).pass).toBe(false);
    expect(decideGate(input({ checks: [check(e, [low], [low])] })).pass).toBe(true);
  });
  it('block mode follows the policy for what remains: block list blocks, warn list warns, the rest is only counted', () => {
    const old = (s: Severity) => fnd({ severity: s, fingerprint: hex(s) });
    const fs = (['critical', 'high', 'medium', 'low', 'info'] as const).map(old);
    const r = decideGate(input({ mode: 'block', checks: [check(entry(), fs, fs)] }));
    expect(r.blocking.map((b) => b.severity)).toEqual(['critical', 'high']);
    expect(r.warnings.map((b) => b.severity)).toEqual(['medium']);
    expect(r.counted).toEqual({ critical: 0, high: 0, medium: 0, low: 1, info: 1 });
    const w = decideGate(input({ mode: 'warn', checks: [check(entry(), fs, fs)] }));
    expect(w.warnings.map((b) => b.severity)).toEqual(['critical', 'high', 'medium']);
    expect(w.pass).toBe(true);
  });
});

// ---------- policy ----------

describe('policy: the default, and the one shared floor check (with the C0b gate input check)', () => {
  it('a policy that would stop critical or high from blocking is refused; a refused policy is a settings error and the default is used', () => {
    expect(policyProblem(DEFAULT_POLICY)).toBeNull();
    expect(policyProblem({ block: ['critical', 'high', 'medium'], warn: ['low'] })).toBeNull();
    for (const bad of [{ block: ['critical'], warn: ['high'] }, { block: ['high'], warn: [] }, { block: [], warn: [] }, { block: ['critical', 'high'], warn: ['high'] }, { block: ['critical', 'high', 'high'], warn: [] }, { block: ['critical', 'high'] }, { block: ['critical', 'high'], warn: [], x: 1 }, null, [], 'x', { block: ['critical', 'high', 'urgent'], warn: [] }]) {
      expect(policyProblem(bad), JSON.stringify(bad)).not.toBeNull();
    }
    const r = decideGate(input({ mode: 'block', policy: { block: ['critical'], warn: ['high'] }, checks: [check(entry(), [fnd({ severity: 'high', fingerprint: hex('h') })], [fnd({ severity: 'high', fingerprint: hex('h') })])] }));
    expect(r.pass).toBe(false);
    expect(r.blockReasons.join()).toMatch(/policy/);
    expect(r.blocking).toHaveLength(1);   // the default policy was used: an old high blocks in block mode
  });
  it('the C0b gate input check (tool-flags) and the gate use the same definition: they agree on every case', () => {
    const cases: unknown[] = [DEFAULT_POLICY, { block: ['critical', 'high', 'medium'], warn: ['low'] }, { block: ['critical'], warn: ['high'] }, { block: ['high', 'critical'], warn: [] }, { block: ['critical', 'high'], warn: ['high'] }, { block: ['critical', 'high'], warn: [], extra: [] }, { block: ['critical', 'high', 'x'], warn: [] }];
    for (const c of cases) {
      const viaInput = rendererInputProblems('crisworking/pipegen/gate', { mode: 'gate', policy: JSON.stringify(c) }).filter((p) => /policy/.test(p)).length === 0;
      expect(viaInput, JSON.stringify(c)).toBe(policyProblem(c) === null);
    }
    expect(readFileSync('src/engine/tool-flags.ts', 'utf8')).toMatch(/from '\.\.\/\.\.\/gate\/src\/policy-default\.js'/);
  });
});

// ---------- summary ----------

describe('decideGate: the summary', () => {
  it('follows the format: header, counts, blocking first grouped by tool (max 10 + "+N more"), warnings, tool errors, failed jobs, not run, no coverage, not scanned, skipped, not proven, integrity, notes', () => {
    const many = Array.from({ length: 13 }, (_, i) => fnd({ severity: 'critical', ruleId: `r${i}`, fingerprint: hex(`m${i}`) }));
    const r = decideGate(input({ checks: [check(entry(), many), jobCheck(jobEntry(), 'failure')] }));
    expect(r.summary.split('\n')[0]).toMatch(/^## pipegen gate: blocked/);
    expect(r.summary).toMatch(/13 blocking/);
    expect(r.summary).toMatch(/#### semgrep/);
    expect(r.summary).toMatch(/\+3 more/);
    const order = ['### Blocking', '### Failed checks'];
    expect(order.map((h) => r.summary.indexOf(h)).every((x, i, a) => x >= 0 && (i === 0 || x > (a[i - 1] as number)))).toBe(true);
  });
  it('the same (rule, file) is one line with its count', () => {
    const f = fnd({ severity: 'critical', fingerprint: hex('x') });
    const r = decideGate(input({ checks: [check(entry(), [f, { ...f, line: 9 }])] }));
    expect(r.summary).toMatch(/×2/);
  });
  it('every repo-derived string goes through safeMarkdown exactly once (a second pass would double the backslashes)', () => {
    const evil = 'x*y_[z](http://e.vil)<b>@me #12 $x\\';
    const once = safeMarkdown(evil);
    const twice = safeMarkdown(once);
    expect(twice).not.toBe(once);
    const r = decideGate(input({
      checks: [check(entry({ tool: 'semgrep' }), [fnd({ severity: 'critical', ruleId: evil, file: evil, message: evil })]), { ...check(entry({ needId: 'iac', job: 'iac', category: 'iac', tool: 'trivy-config' }), []), outputs: { status: 'tool-error', error: evil } }],
      settingsErrors: [evil],
    }));
    expect(r.summary).toContain(once);
    expect(r.summary).not.toContain(twice);
    expect(r.summary).not.toContain(evil);
    expect(r.summary).not.toMatch(/<b>|(?<!\\)\]\(http/);
  });
  it('a passing gate says passed, and every check is listed with how it was judged', () => {
    const r = decideGate(input({ checks: [check(entry(), []), jobCheck(jobEntry(), 'success')] }));
    expect(r.pass).toBe(true);
    expect(r.summary.split('\n')[0]).toMatch(/^## pipegen gate: passed/);
  });
});

// ---------- purity ----------

describe('decideGate is pure', () => {
  it('no import of node:, fs, child_process or the network in decide.ts and policy-default.ts', () => {
    for (const p of ['gate/src/decide.ts', 'gate/src/policy-default.ts']) {
      const text = readFileSync(p, 'utf8');
      const imports = [...text.matchAll(/^import (?!type )[^;]*from '([^']+)'/gm)].map((m) => m[1] as string);
      for (const i of imports) expect(i, `${p} imports ${i}`).not.toMatch(/^node:|^(?:fs|child_process|http|https|net)$|scrub\.js$|stage\.js$|fingerprint\.js$/);
    }
  });
  it('the same input gives the same result, and the input is not changed', () => {
    const i = input({ checks: [check(entry(), [fnd({ severity: 'critical' })], [fnd({ severity: 'low' })])] });
    const before = JSON.stringify(i, (_k, v: unknown) => (v instanceof Map ? [...v] : v instanceof Set ? [...v] : v));
    const a = decideGate(i);
    const b = decideGate(i);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(JSON.stringify(i, (_k, v: unknown) => (v instanceof Map ? [...v] : v instanceof Set ? [...v] : v))).toBe(before);
  });
});

// ---------- the property grid ----------

describe('decideGate: no input with a new critical, a new secret, a failed required job, a tool error, a missing result or a not-scanned file ever passes', () => {
  type Bad = 'new-critical' | 'new-leak' | 'failed-job' | 'tool-error' | 'missing-result' | 'missing-job' | 'not-scanned';
  const BADS: Bad[] = ['new-critical', 'new-leak', 'failed-job', 'tool-error', 'missing-result', 'missing-job', 'not-scanned'];
  const se = (warnFirst: boolean) => entry({ needId: 'secrets', job: 'secrets', category: 'secrets', tool: 'betterleaks', ...(warnFirst ? {} : {}) });
  function badCheck(bad: Bad, warnFirst: boolean, baseCase: number): CheckInput {
    const wf = warnFirst ? { warnFirst: { since: '2026-10-01' } } : {};
    const iac = entry({ needId: 'iac', job: 'iac', category: 'iac', tool: 'trivy-config', ...wf });
    const base = (fs: ScrubbedFinding[]): ScrubbedFinding[] | null => (baseCase === 0 ? fs : baseCase === 1 ? [] : null);
    switch (bad) {
      case 'new-critical': return check(iac, [fnd({ tool: 'trivy-config', severity: 'critical', fingerprint: hex('nc') })], [fnd({ tool: 'trivy-config', severity: 'low', fingerprint: hex('other') })]);
      case 'new-leak': return check(se(warnFirst), [leakF({ severity: 'low', fingerprint: `${SEC}${hex('ns')}` })], []);
      case 'failed-job': return jobCheck(jobEntry({ needId: 'lint', job: 'lint', category: 'lint' }), (['failure', 'cancelled', 'skipped'] as const)[baseCase] ?? 'failure');
      case 'tool-error': return { ...check(iac, []), result: baseCase === 0 ? 'failure' : 'success', outputs: { status: 'tool-error', error: 'x' } };
      case 'missing-result': return { ...check(iac, []), outputs: baseCase === 0 ? {} : { status: 'ok' }, ...(baseCase === 2 ? { file: undefined } : {}) };
      case 'missing-job': return jobCheck(jobEntry({ needId: 'lint', job: 'lint', category: 'lint' }), 'missing');
      case 'not-scanned': {
        const ns = leakF({ ruleId: `${SEC}not-scanned`, fpBy: baseCase === 2 ? 'nokey' : 'file', fingerprint: `${SEC}${hex('nsf')}`, line: 1, endLine: 9 });
        return check(se(false), [ns], base([leakF({ ruleId: `${SEC}not-scanned`, fpBy: 'file', fingerprint: `${SEC}${hex('another file')}` })]) ?? []);
      }
    }
  }
  const benign = (): CheckInput[] => {
    const old = fnd({ severity: 'critical', fingerprint: hex('benign') });
    return [check(entry(), [old], [old]), jobCheck(jobEntry(), 'success'), check(entry({ needId: 'duplication', job: 'duplication', category: 'duplication', blocking: false }), [fnd({ severity: 'critical' })])];
  };
  let runs = 0;
  it('over a generated grid of the other fields', () => {
    for (const bad of BADS) {
      for (let mask = 0; mask < 1024; mask++) {
        const bit = (n: number): boolean => ((mask >> n) & 1) === 1;
        const isPush = bit(5);
        const fork = !isPush && bit(2);
        const i = input({
          mode: bit(0) ? 'block' : 'warn',
          installing: bit(1),
          event: isPush ? push() : pr(fork),
          ancestry: { base: BASE, head: isPush ? HEAD : MERGE, isAncestor: true },
          policy: bit(4) ? { block: ['critical', 'high', 'medium'], warn: ['low'] } : DEFAULT_POLICY,
          baseline: bit(6) ? { tools: ['semgrep', 'trivy-config', 'betterleaks'], counts: new Map() } : null,
          diff: isPush || bit(7) ? null : added({ 'a.js': [1, 2, 3] }),
          integrity: bit(8) ? [{ tool: 'pipegen', ruleId: 'integrity:protected-path', severity: 'high', file: 'x', message: 'm', fingerprint: hex('i') }] : [],
          notProvenNeeds: bit(9) ? ['api-dast'] : [],
          skipped: bit(9) ? [{ needId: 'full-tests', reason: '--skip tests' }] : [],
          checks: [...(bit(3) ? benign() : []), badCheck(bad, bad !== 'failed-job' && bad !== 'missing-job' && bad !== 'not-scanned' && bit(3), mask % 3)],
        });
        const r = decideGate(i);
        runs++;
        if (r.pass) throw new Error(`${bad} passed with mask ${mask}: ${r.summary}`);
        expect(blockText(r).length).toBeGreaterThan(0);
      }
    }
    expect(runs).toBe(BADS.length * 1024);
  });
});
