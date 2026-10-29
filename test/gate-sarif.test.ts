// Plan C Task C1a: hostile-safe SARIF parsing (gate/src/sarif.ts). The input is hostile: a PR author controls the code that
// was scanned, and a broken or compromised tool can write anything. A parser that reads "clean" when the scan covered
// less is a false pass, the worst bug this product can have (preflight-scan B8, S7, S8, S10).
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { MAX_RESULTS_PER_RUN, MAX_RAW_BYTES, MAX_RUNS, normaliseUri, parseSarif, parseSarifText, SARIF_TOOLS } from '../gate/src/sarif.js';
import { loadReviewed } from '../src/engine/reviewed.js';

type Obj = Record<string, unknown>;
const WS = '/home/runner/work/app/app';
// the prefix the parser puts on a secret rule id, built here so no committed test file holds a secret-like literal
const SEC = 'sec' + 'ret:';
const TAG = 'sec' + 'ret';

/** One SARIF document with one run, shaped like a real tool's. */
function doc(driver: string, results: unknown[] = [], extra: { rules?: unknown[]; invocations?: unknown; version?: unknown; run?: Obj } = {}): Obj {
  return {
    version: 'version' in extra ? extra.version : '2.1.0',
    runs: [{ tool: { driver: { name: driver, rules: extra.rules ?? [] } }, ...(extra.invocations === undefined ? {} : { invocations: extra.invocations }), results, ...extra.run }],
  };
}
function result(ruleId: string, over: Obj = {}): Obj {
  return { ruleId, message: { text: `message of ${ruleId}` }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/a.js' }, region: { startLine: 3 } } }], ...over };
}
function at(uri: unknown, line: unknown = 3): Obj {
  return { locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line } } }] };
}
const parse = (json: unknown, tool: string, opts = {}) => parseSarif(json, tool, { workspace: WS, ...opts });
function sev(driver: string, tool: string, r: Obj, rules: unknown[] = []) {
  const out = parse(doc(driver, [r], { rules }), tool);
  expect(out.toolError, JSON.stringify(out)).toBeUndefined();
  expect(out.findings).toHaveLength(1);
  return out;
}

describe('sarif: severity, per tool source (S8)', () => {
  it('sarif: trivy 9.8 → critical (rule-level security-severity); 7 high, 4 medium, 0.1 low, 0 info', () => {
    const rules = [{ id: 'CVE-1', properties: { 'security-severity': '9.8' } }, { id: 'CVE-2', properties: { 'security-severity': '7.0' } }, { id: 'CVE-3', properties: { 'security-severity': '4.0' } },
      { id: 'CVE-4', properties: { 'security-severity': '0.1' } }, { id: 'CVE-5', properties: { 'security-severity': '0' } }];
    const out = parse(doc('Trivy', ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-4', 'CVE-5'].map((id, i) => result(id, { ruleIndex: i })), { rules }), 'trivy-image');
    expect(out.toolError).toBeUndefined();
    expect(out.findings.map((f) => f.severity)).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('severity: the boundaries are 9 critical, 7 high, 4 medium, above 0 low', () => {
    const scores = ['10', '9.0', '8.9', '7.0', '6.9', '4.0', '3.9', '0.1', '0.0', 9, 8.99];
    const out = parse(doc('Trivy', scores.map((v) => result('x', { properties: { 'security-severity': v } }))), 'trivy-config');
    expect(out.findings.map((f) => f.severity)).toEqual(['critical', 'critical', 'high', 'high', 'medium', 'medium', 'low', 'low', 'info', 'critical', 'high']);
  });

  it('severity: trivy takes the result-level security-severity first, then the rule\'s (by ruleIndex, else by ruleId); a number works too', () => {
    const rules = [{ id: 'A', properties: { 'security-severity': '2.0' } }, { id: 'B', properties: { 'security-severity': '9.5' } }];
    const out = parse(doc('Trivy', [result('A', { properties: { 'security-severity': 8.1 } }), result('B'), result('A', { ruleIndex: 0 }), result('B', { ruleIndex: 1 })], { rules }), 'trivy-config');
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'critical', 'low', 'critical']);
  });

  it('severity: a ruleIndex that points at another rule is not trusted, the ruleId lookup decides', () => {
    const rules = [{ id: 'LOW', properties: { 'security-severity': '1.0' } }, { id: 'HIGH', properties: { 'security-severity': '9.9' } }];
    const out = parse(doc('Trivy', [result('HIGH', { ruleIndex: 0 })], { rules }), 'trivy-config');
    expect(out.findings[0].severity).toBe('critical');
  });

  it('sarif: semgrep error → high; warning medium, note low, none info; absent level takes the rule defaultConfiguration.level', () => {
    const rules = [{ id: 'R-warn', defaultConfiguration: { level: 'warning' } }, { id: 'R-note', defaultConfiguration: { level: 'note' } }];
    const out = parse(doc('Semgrep OSS', [result('x', { level: 'error' }), result('x', { level: 'warning' }), result('x', { level: 'note' }), result('x', { level: 'none' }), result('R-warn'), result('R-note', { ruleIndex: 1 })], { rules }), 'semgrep');
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'medium', 'low', 'info', 'medium', 'low']);
    expect(out.notes).toEqual([]);
  });

  it('sarif: gitleaks and betterleaks → critical with the secret prefix, whatever the caller says; the message is never the tool\'s text', () => {
    for (const tool of ['gitleaks', 'betterleaks']) {
      const driver = tool;
      for (const flag of [true, false, undefined]) {
        const out = parse(doc(driver, [result('github-pat', { message: { text: 'github-pat has detected a leak for file a at commit abc' }, level: 'note' })]), tool, flag === undefined ? {} : Object.fromEntries([['secretsTool', flag]]));
        expect(out.toolError).toBeUndefined();
        expect(out.findings).toHaveLength(1);
        expect(out.findings[0]).toMatchObject({ tool, ruleId: SEC + 'github-pat', severity: 'critical', file: 'src/a.js', line: 3 });
        expect(out.findings[0].message).not.toContain('detected a leak for file');
        expect(out.findings[0].message).toContain('github-pat');
      }
    }
  });

  it('sarif: trivy secret rule → secret prefix and critical, generic message (a rule tagged secret)', () => {
    const rules = [{ id: 'github-pat', properties: { 'security-severity': '9.5', tags: [TAG, 'security', 'CRITICAL'] } }];
    const out = parse(doc('Trivy', [result('github-pat', { message: { text: 'Match: some text' } })], { rules }), 'trivy-image');
    expect(out.findings[0]).toMatchObject({ ruleId: SEC + 'github-pat', severity: 'critical' });
    expect(out.findings[0].message).not.toContain('some text');
    // a secret rule is critical even when its own number is low
    const low = parse(doc('Trivy', [result('x', { properties: { tags: ['S' + TAG.slice(1)], 'security-severity': '1.0' } })]), 'trivy-image');
    expect(low.findings[0]).toMatchObject({ ruleId: SEC + 'x', severity: 'critical' });
  });

  it('severity: bandit reads issue_severity, gosec the severity word in the rule tags, nuclei security-severity', () => {
    const b = parse(doc('Bandit', [result('B1', { level: 'note', properties: { issue_severity: 'HIGH' } }), result('B2', { properties: { issue_severity: 'LOW' } }), result('B3', { level: 'error', properties: { issue_severity: 'MEDIUM' } })]), 'bandit');
    expect(b.findings.map((f) => f.severity)).toEqual(['high', 'low', 'medium']);
    const g = parse(doc('gosec', [result('G401', { level: 'error' }), result('G101', { level: 'error', ruleIndex: 1 })], { rules: [{ id: 'G401', properties: { tags: ['security', 'MEDIUM'] } }, { id: 'G101', properties: { tags: ['HIGH', 'security'] } }] }), 'gosec');
    expect(g.findings.map((f) => f.severity)).toEqual(['medium', 'high']);
    const n = parse(doc('Nuclei', [result('git-config', { level: 'note' })], { rules: [{ id: 'git-config', properties: { 'security-severity': '5' } }] }), 'nuclei');
    expect(n.findings[0].severity).toBe('medium');
  });

  it('severity: no value at the tool\'s own source → high, with ONE note per run and cause (never silently low)', () => {
    const out = parse(doc('Trivy', [result('A'), result('B'), result('C', { properties: { 'security-severity': 'high' } }), result('D', { properties: { 'security-severity': '11' } }), result('E', { properties: { 'security-severity': -1 } })]), 'trivy-config');
    expect(out.toolError).toBeUndefined();
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'high', 'high', 'high', 'high']);
    expect(out.notes).toHaveLength(1);
    expect(out.notes[0]).toMatch(/5 finding\(s\).*no severity.*high/i);
    // semgrep: a level that is not one of the four, and no rule default
    const sg = parse(doc('Semgrep OSS', [result('x', { level: 'catastrophic' })]), 'semgrep');
    expect(sg.findings[0].severity).toBe('high');
    expect(sg.notes).toHaveLength(1);
    // the level does not stand in for a missing security-severity on a trivy result (the source is the number)
    const t = parse(doc('Trivy', [result('x', { level: 'note' })]), 'trivy-image');
    expect(t.findings[0].severity).toBe('high');
  });
});

describe('sarif: tool errors (B8)', () => {
  it('sarif: semgrep Timeout notification (the exact 6d-r2 shape: executionSuccessful true + a warning notification) → toolError, never clean', () => {
    const json = doc('Semgrep OSS', [], {
      invocations: [{ executionSuccessful: true, toolExecutionNotifications: [{ descriptor: { id: 'Timeout' }, level: 'warning', message: { text: 'Timeout when running some.rule on src/huge.js:\n ' } }] }],
    });
    const out = parse(json, 'semgrep');
    expect(out.toolError).toMatch(/Timeout/);
    expect(out.toolError).toMatch(/notification/i);
    expect(out.findings).toEqual([]);
  });

  it('sarif: any toolExecutionNotification (any level, any id) → toolError', () => {
    for (const level of ['note', 'warning', 'error', 'none', undefined, 7]) {
      for (const id of ['Timeout', 'anything', undefined]) {
        const n = { ...(id === undefined ? {} : { descriptor: { id } }), ...(level === undefined ? {} : { level }) };
        const out = parse(doc('Semgrep OSS', [result('x', { level: 'error' })], { invocations: [{ executionSuccessful: true, toolExecutionNotifications: [n] }] }), 'semgrep');
        expect(out.toolError, JSON.stringify(n)).toBeDefined();
        expect(out.findings).toEqual([]);
      }
    }
    // an empty list is fine (a real clean semgrep run writes one), and a notification that is not an object still counts
    expect(parse(doc('Semgrep OSS', [], { invocations: [{ executionSuccessful: true, toolExecutionNotifications: [] }] }), 'semgrep').toolError).toBeUndefined();
    expect(parse(doc('Semgrep OSS', [], { invocations: [{ toolExecutionNotifications: ['oops'] }] }), 'semgrep').toolError).toBeDefined();
  });

  it('sarif: an error-level toolConfigurationNotification → toolError; a warning or note one does not', () => {
    const withCfg = (level: unknown) => parse(doc('Semgrep OSS', [], { invocations: [{ executionSuccessful: true, toolConfigurationNotifications: [{ level, descriptor: { id: 'cfg' } }] }] }), 'semgrep');
    expect(withCfg('error').toolError).toMatch(/configuration/i);
    expect(withCfg('warning').toolError).toBeUndefined();
    expect(withCfg('note').toolError).toBeUndefined();
  });

  it('sarif: executionSuccessful false → toolError, in any invocation', () => {
    const out = parse(doc('Semgrep OSS', [result('x')], { invocations: [{ executionSuccessful: true }, { executionSuccessful: false }] }), 'semgrep');
    expect(out.toolError).toMatch(/executionSuccessful/);
    expect(out.findings).toEqual([]);
  });

  it('sarif: kube-linter writes executionSuccessful false exactly when it found something (real output, measured): fine with results, a toolError without', () => {
    const inv = [{ executionSuccessful: false, endTimeUtc: '2026-10-29T20:13:09Z' }];
    expect(parse(doc('kube-linter', [result('latest-tag')], { invocations: inv }), 'kube-linter').toolError).toBeUndefined();
    expect(parse(doc('kube-linter', [], { invocations: inv }), 'kube-linter').toolError).toMatch(/executionSuccessful/);
    // every other tool keeps the rule
    expect(parse(doc('Hadolint', [result('DL3007', { level: 'warning' })], { invocations: inv }), 'hadolint').toolError).toMatch(/executionSuccessful/);
  });

  it('sarif: nuclei writes executionSuccessful false on every run it reports (real output, measured), so its value is ignored; its notifications still count', () => {
    const rules = [{ id: 'git-config', properties: { 'security-severity': '5' } }];
    const ok = parse(doc('Nuclei', [result('git-config')], { rules, invocations: [{ executionSuccessful: false, commandLine: 'nuclei' }] }), 'nuclei');
    expect(ok.toolError).toBeUndefined();
    const bad = parse(doc('Nuclei', [result('git-config')], { rules, invocations: [{ executionSuccessful: false, toolExecutionNotifications: [{ level: 'note' }] }] }), 'nuclei');
    expect(bad.toolError).toBeDefined();
  });

  it('sarif: runs empty or absent, a run without results (absent or not a list) → toolError', () => {
    expect(parse({ version: '2.1.0', runs: [] }, 'semgrep').toolError).toMatch(/no runs/i);
    expect(parse({ version: '2.1.0' }, 'semgrep').toolError).toBeDefined();
    expect(parse({ version: '2.1.0', runs: {} }, 'semgrep').toolError).toBeDefined();
    const noResults = doc('Semgrep OSS', []);
    delete (noResults.runs as Obj[])[0].results;
    expect(parse(noResults, 'semgrep').toolError).toMatch(/results/);
    expect(parse(doc('Semgrep OSS', [], { run: { results: 'none' } }), 'semgrep').toolError).toMatch(/results/);
    expect(parse(doc('Semgrep OSS', [], { run: { results: null } }), 'semgrep').toolError).toMatch(/results/);
    // a second run that lacks them fails the whole file
    const two = doc('Semgrep OSS', []);
    (two.runs as Obj[]).push({ tool: { driver: { name: 'Semgrep OSS' } } });
    expect(parse(two, 'semgrep').toolError).toMatch(/results/);
  });

  it('sarif: the version is not 2.1.0 (or not a string) → toolError', () => {
    for (const version of ['2.0.0', '2.1', '2.1.1', 2.1, undefined, null, '2.1.0 ']) {
      const out = parse(doc('Semgrep OSS', [], { version }), 'semgrep');
      expect(out.toolError, String(version)).toMatch(/version/i);
    }
  });

  it('sarif: a driver name that is not the one expected for the tool → toolError (every run)', () => {
    expect(parse(doc('Semgrep PRO', []), 'semgrep').toolError).toMatch(/driver/i);
    expect(parse(doc('semgrep oss', []), 'semgrep').toolError).toMatch(/driver/i);
    expect(parse(doc('Trivy', []), 'semgrep').toolError).toMatch(/driver/i);
    expect(parse(doc('', []), 'semgrep').toolError).toBeDefined();
    expect(parse(doc(7 as unknown as string, []), 'semgrep').toolError).toBeDefined();
    const noTool = { version: '2.1.0', runs: [{ results: [] }] };
    expect(parse(noTool, 'semgrep').toolError).toMatch(/driver/i);
    const two = doc('Semgrep OSS', []);
    (two.runs as Obj[]).push({ tool: { driver: { name: 'Other' } }, results: [] });
    expect(parse(two, 'semgrep').toolError).toMatch(/driver/i);
    // a name taken from the finding's text is not a driver
    expect(parse(doc('Semgrep OSS', []), 'trivy-image').toolError).toMatch(/driver/i);
  });

  it('sarif: a tool id that is not a gated SARIF writer → toolError; not a SARIF document at all → toolError', () => {
    expect(parse(doc('Semgrep OSS', []), 'made-up').toolError).toMatch(/not a tool/i);
    expect(parse(doc('scorecard', []), 'scorecard-action').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', []), '__proto__').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', []), 'constructor').toolError).toBeDefined();
    for (const bad of [null, undefined, 7, 'x', [], true]) expect(parse(bad, 'semgrep').toolError, String(bad)).toBeDefined();
  });

  it('sarif: a toolError returns no findings, and the shape is always { findings, toolError?, notes }', () => {
    const bad = parse(doc('Semgrep OSS', [result('x')], { version: '1.0' }), 'semgrep');
    expect(Object.keys(bad).sort()).toEqual(['findings', 'notes', 'toolError']);
    expect(bad.findings).toEqual([]);
    const ok = parse(doc('Semgrep OSS', [result('x', { level: 'error' })]), 'semgrep');
    expect(Object.keys(ok).sort()).toEqual(['findings', 'notes']);
    expect(Object.hasOwn(ok, 'toolError')).toBe(false);
  });

  it('sarif: a suppressed result is still a finding (gosec -track-suppressions writes the #nosec ones on purpose; they are read as findings, never dropped)', () => {
    const suppressed = result('G401', { level: 'error', suppressions: [{ kind: 'inSource', justification: 'trust me' }], kind: 'pass' });
    const out = parse(doc('gosec', [suppressed], { rules: [{ id: 'G401', properties: { tags: ['security', 'HIGH'] } }] }), 'gosec');
    expect(out.toolError).toBeUndefined();
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].severity).toBe('high');
  });

  it('sarif: a result that cannot be read as the tool writes it (no rule id, text or position of the wrong type) → toolError, never a skipped finding', () => {
    expect(parse(doc('Semgrep OSS', [{ message: { text: 'x' } }]), 'semgrep').toolError).toMatch(/ruleId/);
    expect(parse(doc('Semgrep OSS', ['not an object']), 'semgrep').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', [result('x', { message: { text: 5 } })]), 'semgrep').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', [result('x', { locations: 'here' })]), 'semgrep').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', [result('x', at('a.js', 'three'))]), 'semgrep').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', [result(5 as unknown as string)]), 'semgrep').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', [result('x', { level: 5 })]), 'semgrep').toolError).toBeDefined();
    expect(parse(doc('Semgrep OSS', [result('r'.repeat(5000))]), 'semgrep').toolError).toBeDefined();
    // a rule id from the rule reference is accepted
    const ref = parse(doc('Semgrep OSS', [{ rule: { id: 'via-ref' }, message: { text: 't' }, level: 'error' }]), 'semgrep');
    expect(ref.findings[0].ruleId).toBe('via-ref');
  });
});

describe('sarif: caps (S7)', () => {
  it('sarif: over the raw size cap → toolError, before any parsing; the production cap is 64 MiB', () => {
    expect(MAX_RAW_BYTES).toBe(64 * 1024 * 1024);
    const text = JSON.stringify(doc('Semgrep OSS', []));
    expect(parseSarifText(text, 'semgrep', { workspace: WS, limits: { maxBytes: text.length } }).toolError).toBeUndefined();
    const big = parseSarifText(text, 'semgrep', { workspace: WS, limits: { maxBytes: text.length - 1 } });
    expect(big.toolError).toMatch(/size/i);
    expect(big.findings).toEqual([]);
    // bytes, not characters
    const multi = JSON.stringify(doc('Semgrep OSS', [result('x', { level: 'error', message: { text: 'é'.repeat(50) } })]));
    expect(parseSarifText(multi, 'semgrep', { workspace: WS, limits: { maxBytes: multi.length + 10 } }).toolError).toMatch(/size/i);
    expect(parseSarifText(Buffer.from(multi), 'semgrep', { workspace: WS, limits: { maxBytes: Buffer.byteLength(multi) } }).toolError).toBeUndefined();
    expect(parseSarifText(Buffer.from(multi), 'semgrep', { workspace: WS, limits: { maxBytes: Buffer.byteLength(multi) - 1 } }).toolError).toMatch(/size/i);
    expect(parseSarifText(new TextEncoder().encode(multi), 'semgrep', { workspace: WS, limits: { maxBytes: 10 } }).toolError).toMatch(/size/i);
  });

  it('sarif: more results than the cap in one run (50,000) or more runs than 20 → toolError; exactly the cap is fine', () => {
    expect(MAX_RESULTS_PER_RUN).toBe(50_000);
    expect(MAX_RUNS).toBe(20);
    const three = doc('Semgrep OSS', [result('a', { level: 'note' }), result('b', { level: 'note' }), result('c', { level: 'note' })]);
    expect(parse(three, 'semgrep', { limits: { maxResults: 3 } }).findings).toHaveLength(3);
    const over = parse(three, 'semgrep', { limits: { maxResults: 2 } });
    expect(over.toolError).toMatch(/results/i);
    expect(over.findings).toEqual([]);
    const runs = (n: number) => ({ version: '2.1.0', runs: Array.from({ length: n }, () => ({ tool: { driver: { name: 'Semgrep OSS' } }, results: [] })) });
    expect(parse(runs(MAX_RUNS), 'semgrep').toolError).toBeUndefined();
    expect(parse(runs(MAX_RUNS + 1), 'semgrep').toolError).toMatch(/runs/i);
    // the result cap is per run, so a file cannot dodge it by spreading over many runs, only the total file cap stops that
    expect(parse(runs(2), 'semgrep', { limits: { maxResults: 1 } }).toolError).toBeUndefined();
  });

  it('sarif: JSON that does not parse, an empty file or a top-level that is not an object → toolError', () => {
    for (const text of ['', '{', 'null', '[]', '"x"', '{"runs":', '\u0000', 'NaN']) {
      const out = parseSarifText(text, 'semgrep', { workspace: WS });
      expect(out.toolError, JSON.stringify(text)).toBeDefined();
      expect(out.findings).toEqual([]);
    }
    expect(parseSarifText(Buffer.from([0xff, 0xfe, 0x00]), 'semgrep').toolError).toBeDefined();
  });

  it('sarif: parsed once with no reviver (a hostile text cannot run code while it is read)', () => {
    const text = JSON.stringify(doc('Semgrep OSS', [result('x', { level: 'error' })]));
    expect(parseSarifText(text, 'semgrep', { workspace: WS }).findings).toHaveLength(1);
    expect(parseSarifText(text, 'semgrep').toolError).toBeUndefined();
  });
});

describe('sarif: hostile keys and nesting (S7)', () => {
  it('sarif: __proto__ and constructor as ruleId, rule id and property keys parse as data, and no prototype changes', () => {
    const text = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[
        {"id":"__proto__","properties":{"security-severity":"9.9","__proto__":{"polluted":"yes"}}},
        {"id":"constructor","properties":{"security-severity":"1.0","constructor":{"prototype":{"polluted":"yes"}}}}]}},
      "results":[
        {"ruleId":"__proto__","ruleIndex":0,"message":{"text":"m"},"properties":{"__proto__":{"security-severity":"0.1"},"constructor":"x"}},
        {"ruleId":"constructor","message":{"text":"m"},"__proto__":{"ruleId":"hijacked"}},
        {"ruleId":"toString","message":{"__proto__":{"text":"hijack"},"text":"plain"}},
        {"ruleId":"hasOwnProperty","message":{"text":"m"}}]}]}`;
    const out = parseSarifText(text, 'trivy-config', { workspace: WS });
    expect(out.toolError).toBeUndefined();
    expect(out.findings.map((f) => [f.ruleId, f.severity])).toEqual([['__proto__', 'critical'], ['constructor', 'low'], ['toString', 'high'], ['hasOwnProperty', 'high']]);
    expect(out.findings[2].message).toBe('plain');
    expect(({} as Obj).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty('polluted');
    expect(Object.getPrototypeOf(out.findings[0])).toBe(Object.prototype);
    expect(Object.hasOwn(out.findings[0], 'polluted')).toBe(false);
  });

  it('sarif: a hostile key in a secrets result and a hostile tool id do not change what is read', () => {
    const text = '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"__proto__","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"__proto__/constructor"},"region":{"startLine":1}}}]}]}]}';
    const out = parseSarifText(text, 'gitleaks', { workspace: WS });
    expect(out.findings[0]).toMatchObject({ ruleId: SEC + '__proto__', file: '__proto__/constructor', severity: 'critical' });
  });

  it('sarif: deep nesting in an ignored field parses (50,000 levels); in a read field → toolError', () => {
    const deep = (n: number) => '['.repeat(n) + ']'.repeat(n);
    const ignored = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[{"ruleId":"x","level":"error","message":{"text":"m"},"codeFlows":${deep(50_000)},"fixes":${deep(5_000)}}],"taxonomies":${deep(20_000)}}]}`;
    const ok = parseSarifText(ignored, 'semgrep', { workspace: WS });
    expect(ok.toolError).toBeUndefined();
    expect(ok.findings).toHaveLength(1);
    const readField = (path: string) => parseSarifText(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[{"ruleId":"x","level":"error",${path}}]}]}`, 'semgrep', { workspace: WS });
    for (const field of [`"message":{"text":${deep(5_000)}}`, `"message":${deep(5_000)}`, `"locations":${deep(5_000)}`,
      `"locations":[{"physicalLocation":{"artifactLocation":{"uri":${deep(5_000)}}}}]`, `"locations":[{"physicalLocation":{"region":{"startLine":${deep(5_000)}}}}]`,
      `"properties":${deep(5_000)}`, `"message":{"text":"m","markdown":1},"rule":${deep(5_000)}`]) {
      const out = readField(field);
      expect(out.toolError, field.slice(0, 60)).toBeDefined();
      expect(out.findings).toEqual([]);
    }
    // a read field in the rules, the run header and an invocation
    const rules = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[{"id":"x","defaultConfiguration":{"level":${deep(5_000)}}}]}},"results":[{"ruleId":"x","message":{"text":"m"}}]}]}`;
    expect(parseSarifText(rules, 'semgrep').toolError).toBeDefined();
    const inv = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"invocations":[{"executionSuccessful":${deep(5_000)}}],"results":[]}]}`;
    expect(parseSarifText(inv, 'semgrep').toolError).toBeDefined();
  });

  it('sarif: only own properties are read: nothing inherited, and a polluted Object.prototype changes nothing', () => {
    const inherited = Object.create({ ruleId: 'inherited', level: 'error', message: { text: 'x' } }) as Obj;
    expect(parse(doc('Semgrep OSS', [inherited]), 'semgrep').toolError).toMatch(/ruleId/);
    const proto = Object.prototype as unknown as Obj;
    const keys = ['security-severity', 'level', 'tags', 'issue_severity', 'results', 'invocations', 'executionSuccessful', 'toolExecutionNotifications', 'locations', 'ruleIndex'];
    try {
      for (const k of keys) proto[k] = k === 'tags' ? [TAG] : k === 'security-severity' ? '0.1' : k === 'level' ? 'none' : k === 'ruleIndex' ? 0 : k === 'results' ? [] : k === 'executionSuccessful' ? false : k === 'locations' ? [] : [{ level: 'warning' }];
      const out = parse(doc('Trivy', [{ ruleId: 'A', message: { text: 'm' } }], { rules: [{ id: 'A', properties: { 'security-severity': '9.9' } }] }), 'trivy-config');
      expect(out.toolError).toBeUndefined();
      expect(out.findings.map((f) => [f.ruleId, f.severity])).toEqual([['A', 'critical']]);
      const noLevel = parse(doc('Semgrep OSS', [{ ruleId: 'B', message: { text: 'm' } }]), 'semgrep');
      expect(noLevel.findings[0].severity).toBe('high');
    } finally {
      for (const k of keys) delete proto[k];
    }
  });

  it('sarif: unknown keys are never walked or copied: a getter on one that throws is never called', () => {
    const r = result('x', { level: 'error' });
    Object.defineProperty(r, 'codeFlows', { enumerable: true, get() { throw new Error('walked an unknown key'); } });
    const json = doc('Semgrep OSS', [r], { run: {} });
    Object.defineProperty((json.runs as Obj[])[0], 'taxonomies', { enumerable: true, get() { throw new Error('walked an unknown run key'); } });
    expect(parse(json, 'semgrep').findings).toHaveLength(1);
  });
});

describe('uri: normalisation (S10, uri part)', () => {
  const n = (uri: unknown, workspace: string | undefined = WS) => normaliseUri(uri, { workspace });

  it('uri: relative paths stay, with ./ and // and . segments folded', () => {
    expect(n('src/a.js')).toBe('src/a.js');
    expect(n('./src/a.js')).toBe('src/a.js');
    expect(n('src//a/./b.js')).toBe('src/a/b.js');
    expect(n('.github/workflows/ci.yml')).toBe('.github/workflows/ci.yml');
    expect(n('a b/c d.js')).toBe('a b/c d.js');
    expect(n('my%20file.js')).toBe('my file.js');   // decoded once
    expect(n('..foo/bar')).toBe('..foo/bar');       // a name that only starts with two dots is not a traversal
  });

  it('uri: file://, /src/ and the workspace prefixes are stripped', () => {
    expect(n(`file://${WS}/src/a.js`)).toBe('src/a.js');
    expect(n(`${WS}/src/a.js`)).toBe('src/a.js');
    expect(n(`file://${WS}/src/a.js`, `${WS}/`)).toBe('src/a.js');   // trailing slash on the workspace
    expect(n('/src/app/main.py')).toBe('app/main.py');
    expect(n('file:///src/app/main.py')).toBe('app/main.py');
    expect(n(`file://${WS}/./src/a.js`)).toBe('src/a.js');
    expect(n(`file://${encodeURIComponent(WS)}/src/a.js`)).toBeUndefined();   // an encoded prefix is no prefix
  });

  it('uri: .., absolute paths and %2e%2e (any case, any encoding layer) become unmapped (undefined), never a path', () => {
    const bad: unknown[] = [
      '../x', 'a/../b', 'a/..', '..', '/etc/passwd', '/src/../etc/passwd', `${WS}/../x`, `${WS}/src/../../x`, `file://${WS}/../x`,
      '%2e%2e/x', '%2E%2E/x', '%2e%2E/x', '.%2e/x', '%2e./x', 'a/%2e%2e/b', 'a%2f..%2fb', 'a%2F%2e%2E%2Fb', '..%2fx', '%2e%2e%2fx', '..%5cx',
      '%252e%252e/x', '%252E%252E%252Fx', '%25252e%25252e/x', '%2525252e%2525252e/x', 'a%252f..%252fb',
      '%2fetc%2fpasswd', '%252fetc%252fpasswd', 'C:\\Windows\\x', 'C:/Windows/x', '\\\\server\\share\\x', 'a\\b', 'a%5Cb', '//server/share/x',
      'file://host/etc/passwd', 'file://localhost/x', 'file:///etc/passwd', 'http://example.com/a.js', 'ftp://x/y', 'data:text/plain,x',
      'a\u0000b', 'a%00b', 'a\nb', 'a%0ab', 'a%', 'a%zz', '%', '%e0%a4%a', `${'a/'.repeat(3000)}x`, '', '   ', '.', './', '/', '/src', '/src/', `file://${WS}`,
      `${WS}2/x`,      // the workspace is a whole path prefix, never a text prefix
      '/srcfoo/x', 'src/..%2f..%2fx',
    ];
    for (const uri of bad) expect(n(uri), JSON.stringify(uri)).toBeUndefined();
    for (const uri of [undefined, null, 7, {}, [], true, ['a.js']]) expect(n(uri), String(uri)).toBeUndefined();
    // no workspace given: an absolute path is not under it, so it is unmapped, not a repo path
    expect(normaliseUri(`file://${WS}/src/a.js`, {})).toBeUndefined();
  });

  it('uri: the finding keeps file undefined and says uriUnmapped, with one note for the run', () => {
    const out = parse(doc('Semgrep OSS', [result('a', { level: 'error', ...at('../../etc/passwd') }), result('b', { level: 'error', ...at('%2e%2e/x') }), result('c', { level: 'error', ...at('ok/a.js') })]), 'semgrep');
    expect(out.toolError).toBeUndefined();
    expect(out.findings.map((f) => [f.file, f.uriUnmapped])).toEqual([[undefined, true], [undefined, true], ['ok/a.js', false]]);
    expect(out.notes.filter((x) => /could not be mapped/i.test(x))).toHaveLength(1);
    expect(JSON.stringify(out)).not.toContain('etc/passwd');
    // a result with no location at all is not an unmapped path
    const none = parse(doc('Semgrep OSS', [{ ruleId: 'x', level: 'error', message: { text: 'm' } }]), 'semgrep');
    expect(none.findings[0]).toMatchObject({ file: undefined, uriUnmapped: false });
  });

  it('uri: the workspace prefix is applied to what the tools really write (osv-scanner, ruff: file:// + the workspace)', () => {
    const osv = parse(doc('osv-scanner', [result('CVE-1', { properties: { 'security-severity': '7.5' }, locations: [{ physicalLocation: { artifactLocation: { uri: `file://${WS}/package-lock.json` } } }] })]), 'osv-scanner');
    expect(osv.findings[0]).toMatchObject({ file: 'package-lock.json', line: undefined, uriUnmapped: false });
  });

  it('uri: trivy-image findings carry no path (the uri is an image layer path or the image archive), flagged unmapped', () => {
    const out = parse(doc('Trivy', [result('CVE-1', { properties: { 'security-severity': '7.5' }, ...at('/app/.env') }), result('CVE-2', { properties: { 'security-severity': '7.5' }, ...at('app/server.js') })]), 'trivy-image');
    expect(out.findings.map((f) => [f.file, f.uriUnmapped])).toEqual([[undefined, true], [undefined, true]]);
  });

  it('uri: message, rule id and line are bounded', () => {
    const out = parse(doc('Semgrep OSS', [result('x', { level: 'error', message: { text: 'm'.repeat(10_000) }, ...at('a.js', 2 ** 40) }), result('y', { level: 'error', ...at('a.js', 0) }), result('z', { level: 'error', ...at('a.js', -4) }), result('w', { level: 'error', ...at('a.js', 7.5) })]), 'semgrep');
    expect(out.findings[0].message.length).toBeLessThanOrEqual(2000);
    expect(out.findings.map((f) => f.line)).toEqual([undefined, undefined, undefined, undefined]);
  });
});

describe('sarif: the tool table', () => {
  it('sarif: every reviewed entry that writes SARIF is in the table, except scorecard-action (reported only, never gated); every table entry is a reviewed entry', () => {
    const sarifIds = loadReviewed().filter((t) => t.step.output.format === 'sarif').map((t) => t.id).filter((id) => id !== 'scorecard-action').sort();
    expect(Object.keys(SARIF_TOOLS).sort()).toEqual(sarifIds);
    expect(sarifIds).toEqual(['bandit', 'betterleaks', 'gitleaks', 'gosec', 'hadolint', 'kube-linter', 'nuclei', 'osv-scanner', 'ruff', 'semgrep', 'trivy-config', 'trivy-image', 'trivy-licence']);
  });

  it('sarif: the table is plain data with a driver name for each tool and a null prototype (no inherited ids)', () => {
    expect(Object.getPrototypeOf(SARIF_TOOLS)).toBeNull();
    for (const [id, t] of Object.entries(SARIF_TOOLS)) {
      expect(typeof t.driver, id).toBe('string');
      expect(t.driver.length, id).toBeGreaterThan(0);
    }
    expect(SARIF_TOOLS['__proto__' as string]).toBeUndefined();
  });
});

describe('gate/src: wiring (C1a)', () => {
  const root = resolve(import.meta.dirname, '..');
  async function graph(entry: string) {
    const r = await build({ entryPoints: [resolve(root, entry)], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
    return { inputs: Object.keys(r.metafile.inputs).sort(), externals: Object.values(r.metafile.outputs).flatMap((o) => o.imports.filter((i) => i.external).map((i) => i.path)) };
  }

  it('gate: sarif.ts and zap.ts bundle with esbuild (the same bundler tsup uses), pure TypeScript: only gate/src, the import-free types and safe-text, and no Node built-in at all', async () => {
    for (const entry of ['gate/src/sarif.ts', 'gate/src/zap.ts']) {
      const { inputs, externals } = await graph(entry);
      expect(inputs, entry).toContain(entry);
      expect(inputs.filter((f) => !f.startsWith('gate/src/') && f !== 'src/types.ts' && f !== 'src/util/safe-text.ts'), entry).toEqual([]);
      expect(externals, entry).toEqual([]);
    }
  });
});
