// C1a fix round 1: every probe of review-C1a.md as a regression test. These failed before the fixes.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { normaliseUri, parseSarif, parseSarifText } from '../gate/src/sarif.js';
import { parseZapJson, parseZapJsonText, ZAP_JSON_VERIFIED } from '../gate/src/zap.js';

type Obj = Record<string, unknown>;
const WS = '/home/runner/work/fixture/fixture';
const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const read = (name: string) => readFileSync(join(DIR, name));
const fixture = (name: string, tool: string) => parseSarifText(read(name), tool, { workspace: WS });
function doc(driver: string, results: unknown[] = [], extra: { rules?: unknown[]; invocations?: unknown; run?: Obj } = {}): Obj {
  return { version: '2.1.0', runs: [{ tool: { driver: { name: driver, rules: extra.rules ?? [] } }, ...(extra.invocations === undefined ? {} : { invocations: extra.invocations }), results, ...extra.run }] };
}
function result(ruleId: string, over: Obj = {}): Obj {
  return { ruleId, message: { text: `message of ${ruleId}` }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/a.js' }, region: { startLine: 3 } } }], ...over };
}
const parse = (json: unknown, tool: string, opts = {}) => parseSarif(json, tool, { workspace: WS, ...opts });

describe('I1: a target the tool could not read is a tool error, not a finding', () => {
  it('fixtures (real, measured): kube-linter failed-to-load-object alone and next to five check findings, hadolint DL1000, ruff invalid-syntax', () => {
    for (const [file, tool, rule] of [['failed/kube-linter-onlybad.sarif', 'kube-linter', 'failed-to-load-object'], ['failed/kube-linter-mixed.sarif', 'kube-linter', 'failed-to-load-object'],
      ['failed/hadolint-parse-error.sarif', 'hadolint', 'DL1000'], ['failed/ruff-syntax-error.sarif', 'ruff', 'invalid-syntax']] as const) {
      const out = fixture(file, tool);
      expect(out.toolError, file).toMatch(new RegExp(`could not read 1 target\\(s\\) \\(${rule}\\).*covered less`));
      expect(out.findings, file).toEqual([]);
    }
  });

  it('the mixed kube-linter run (executionSuccessful false, 5 findings and 1 failed-to-load-object) is a tool error, not five findings', () => {
    const raw = JSON.parse(read('failed/kube-linter-mixed.sarif').toString());
    expect(raw.runs[0].results.map((r: Obj) => r.ruleId).filter((id: string) => id === 'failed-to-load-object')).toHaveLength(1);
    expect(raw.runs[0].invocations[0].executionSuccessful).toBe(false);
    expect(fixture('failed/kube-linter-mixed.sarif', 'kube-linter').findings).toEqual([]);
  });

  it('every error rule of every tool, counted; a rule of another tool with the same id is a plain finding', () => {
    const cases: [string, string, string[]][] = [['kube-linter', 'kube-linter', ['failed-to-load-object']], ['Hadolint', 'hadolint', ['DL1000']], ['ruff', 'ruff', ['invalid-syntax', 'E999', 'E902', 'io-error']]];
    for (const [driver, tool, ids] of cases) {
      for (const id of ids) {
        const out = parse(doc(driver, [result('ok', { level: 'error' }), result(id, { level: 'error' }), result(id, { level: 'error' })]), tool);
        expect(out.toolError, `${tool} ${id}`).toMatch(new RegExp(`could not read 2 target\\(s\\) \\(${id}\\)`));
        expect(out.findings).toEqual([]);
      }
    }
    const other = parse(doc('Semgrep OSS', [result('DL1000', { level: 'error' }), result('invalid-syntax', { level: 'error' })]), 'semgrep');
    expect(other.toolError).toBeUndefined();
    expect(other.findings).toHaveLength(2);
    // an own-property lookup: ruleIds that are only prototype names are not error rules and not errors
    expect(parse(doc('ruff', [result('constructor', { level: 'error' }), result('__proto__', { level: 'error' })]), 'ruff').toolError).toBeUndefined();
  });
});

describe('I2: trivy writes 0.0 for a severity it does not know; that is no value, so high', () => {
  const unknownScore = (v: unknown) => doc('Trivy', [result('CVE-1', { properties: { 'security-severity': v } })]);
  it('trivy-image and trivy-config: 0, "0", "0.0" and "0.00" → high with the no-severity note', () => {
    for (const tool of ['trivy-image', 'trivy-config']) {
      for (const v of [0, '0', '0.0', '0.00']) {
        const out = parse(unknownScore(v), tool);
        expect(out.findings[0].severity, `${tool} ${String(v)}`).toBe('high');
        expect(out.notes.filter((n) => /1 finding\(s\).*no severity.*high/i.test(n))).toHaveLength(1);
      }
    }
    const rule = parse(doc('Trivy', [result('A')], { rules: [{ id: 'A', properties: { 'security-severity': '0.0', tags: ['vulnerability', 'UNKNOWN'] } }] }), 'trivy-image');
    expect(rule.findings[0].severity).toBe('high');
  });
  it('a real UNKNOWN result (from trivy-licence-unfiltered.sarif) read as trivy-image is high; read as trivy-licence it stays info (S9)', () => {
    const raw = read('trivy-licence-unfiltered.sarif').toString();
    expect(JSON.stringify(JSON.parse(raw).runs[0].tool.driver.rules)).toContain('"security-severity": "0.0"'.replace(': ', ':'));
    const asImage = parseSarifText(raw, 'trivy-image', { workspace: WS });
    expect(Object.fromEntries(asImage.findings.map((f) => [f.ruleId, f.severity]))).toEqual({ 'acme/gpl:GPL-3.0-only': 'high', 'acme/weird:SomeWeirdLicense-1.0': 'high' });
    const asLicence = parseSarifText(raw, 'trivy-licence', { workspace: WS });
    expect(Object.fromEntries(asLicence.findings.map((f) => [f.ruleId, f.severity]))).toEqual({ 'acme/gpl:GPL-3.0-only': 'high', 'acme/weird:SomeWeirdLicense-1.0': 'info' });
  });
  it('a score above zero still maps as before (0.1 is low)', () => {
    expect(parse(unknownScore('0.1'), 'trivy-image').findings[0].severity).toBe('low');
  });
});

describe('nuclei: no file is a marked empty result written by pipegen', () => {
  const marked = () => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'pipegen-empty-nuclei' } }, results: [], properties: { pipegenSynthesized: 'nuclei-no-file' } }] });
  it('the exact marked shape is accepted for nuclei only: no findings and a note, never a real nuclei run', () => {
    const out = parse(marked(), 'nuclei');
    expect(out).toEqual({ findings: [], notes: ['nothing reported (synthesized empty result)'] });
    for (const tool of ['semgrep', 'trivy-image', 'gitleaks', 'osv-scanner', 'kube-linter', 'hadolint', 'ruff']) {
      const refused = parse(marked(), tool);
      expect(refused.toolError, tool).toMatch(/driver/i);
      expect(refused.findings).toEqual([]);
    }
  });
  it('anything but the exact shape is a toolError for nuclei: results, a second run, a missing or other mark, another driver', () => {
    const variants: Obj[] = [
      { ...marked(), runs: [{ ...marked().runs[0], results: [result('git-config')] }] },
      { ...marked(), runs: [marked().runs[0], marked().runs[0]] },
      { ...marked(), $schema: 'x' },
      { ...marked(), runs: [{ ...marked().runs[0], properties: {} }] },
      { ...marked(), runs: [{ ...marked().runs[0], properties: { pipegenSynthesized: 'other' } }] },
      { ...marked(), runs: [{ ...marked().runs[0], tool: { driver: { name: 'pipegen-empty-semgrep' } } }] },
      { ...marked(), runs: [{ ...marked().runs[0], invocations: [{ executionSuccessful: true, toolExecutionNotifications: [{}] }] }] },
    ];
    for (const v of variants) expect(parse(v, 'nuclei').toolError).toBeDefined();
    // a real nuclei run is not marked and still parses as findings
    expect(parseSarifText(read('nuclei.sarif'), 'nuclei').notes).toEqual([]);
  });
});

describe('gosec: the severity word may sit on the result too', () => {
  it('a result-level tag word counts, and the highest of rule and result wins', () => {
    const out = parse(doc('gosec', [result('G1', { level: 'error', properties: { tags: ['HIGH'] } }), result('G2', { properties: { tags: ['LOW'] }, level: 'error' }), result('G3', { properties: { tags: ['LOW'] } })], { rules: [{ id: 'G1' }, { id: 'G2', properties: { tags: ['MEDIUM'] } }, { id: 'G3' }] }), 'gosec');
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'medium', 'low']);
  });
});

describe('gitleaks: completeness is not provable', () => {
  it('every gitleaks result carries the note, with or without findings; betterleaks does not', () => {
    const note = 'completeness not provable (gitleaks)';
    expect(fixture('clean/gitleaks.sarif', 'gitleaks').notes).toEqual([note]);
    expect(fixture('gitleaks.sarif', 'gitleaks').notes).toEqual([note]);
    expect(fixture('betterleaks.sarif', 'betterleaks').notes).toEqual([]);
    expect(fixture('clean/betterleaks.sarif', 'betterleaks').notes).toEqual([]);
  });
});

describe('zap-json is unverified', () => {
  it('ZAP_JSON_VERIFIED is false and every zap result says so', () => {
    expect(ZAP_JSON_VERIFIED).toBe(false);
    const report = { '@programName': 'ZAP', site: [{ alerts: [] }] };
    expect(parseZapJson(report, 'zap-baseline').notes).toEqual(['zap-json parsing is unverified against a real zap-baseline -J report']);
    expect(parseZapJsonText(JSON.stringify(report), 'zap-baseline').notes).toHaveLength(1);
    expect(parseZapJson({}, 'zap-baseline').toolError).toBeDefined();
  });
  it('riskcode strings that only look like numbers are high with a note ("3abc", "0.5", "-0", "0x3", " 3")', () => {
    const alert = (riskcode: string) => ({ pluginid: '1', name: 'n', riskcode, instances: [] });
    const out = parseZapJson({ '@programName': 'ZAP', site: [{ alerts: ['3abc', '0.5', '-0', '0x3', ' 3'].map(alert) }] }, 'zap-baseline');
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'high', 'high', 'high', 'high']);
    expect(out.notes.some((n) => /5 alert\(s\).*riskcode/.test(n))).toBe(true);
  });
  it('/zap/wrk/ is not a ZAP url path concern, but a SARIF uri under it is stripped like /src/ (S10)', () => {
    expect(normaliseUri('/zap/wrk/app/a.py')).toBe('app/a.py');
    expect(normaliseUri('/zap/wrkx/a.py')).toBeUndefined();
    expect(normaliseUri('/zap/wrk/../x')).toBeUndefined();
  });
});

describe('M1: guards that had no test', () => {
  it('numbers that only look like numbers are high with a note ("0x9", "1e1", "+9.8", "9.8abc")', () => {
    for (const v of ['0x9', '1e1', '+9.8', '9.8abc', ' ', '٩']) {
      const out = parse(doc('Trivy', [result('x', { properties: { 'security-severity': v } })]), 'trivy-config');
      expect(out.findings[0].severity, v).toBe('high');
      expect(out.notes).toHaveLength(1);
    }
  });
  it('an invalid UTF-8 byte inside a JSON string is a toolError (strict decoding), not a replacement character', () => {
    const head = Buffer.from('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[{"ruleId":"x","level":"error","message":{"text":"a');
    const tail = Buffer.from('b"}}]}]}');
    const bad = Buffer.concat([head, Buffer.from([0xc3, 0x28]), tail]);
    expect(parseSarifText(bad, 'semgrep').toolError).toMatch(/UTF-8/);
    expect(parseSarifText(Buffer.concat([head, Buffer.from('é'), tail]), 'semgrep').toolError).toBeUndefined();
  });
  it('a scheme that only appears after one decoding is unmapped', () => {
    for (const uri of ['a%3A%2F%2Fx', 'file%3A///etc/passwd', 'http%3A//x/a.js', 'C%3A/x']) expect(normaliseUri(uri), uri).toBeUndefined();
  });
  it('two rules with one id and different severity data are a toolError, in either order; identical duplicates are fine', () => {
    const hi = { id: 'D', properties: { 'security-severity': '9.8' } };
    const lo = { id: 'D', properties: { 'security-severity': '0.5' } };
    expect(parse(doc('Trivy', [result('D')], { rules: [hi, lo] }), 'trivy-config').toolError).toMatch(/same id/i);
    expect(parse(doc('Trivy', [result('D')], { rules: [lo, hi] }), 'trivy-config').toolError).toMatch(/same id/i);
    expect(parse(doc('Trivy', [result('D')], { rules: [hi, { ...hi }] }), 'trivy-config').findings[0].severity).toBe('critical');
    const lvl = (level: string) => ({ id: 'D', defaultConfiguration: { level } });
    expect(parse(doc('Semgrep OSS', [result('D')], { rules: [lvl('note'), lvl('error')] }), 'semgrep').toolError).toMatch(/same id/i);
  });
});

describe('M2: the work is capped', () => {
  it('more than 256 tags on a rule or a result is a toolError; 256 is fine', () => {
    const tags = (n: number) => Array.from({ length: n }, (_, i) => `t${i}`);
    expect(parse(doc('Trivy', [result('A')], { rules: [{ id: 'A', properties: { 'security-severity': '5', tags: tags(256) } }] }), 'trivy-config').toolError).toBeUndefined();
    expect(parse(doc('Trivy', [result('A')], { rules: [{ id: 'A', properties: { 'security-severity': '5', tags: tags(257) } }] }), 'trivy-config').toolError).toMatch(/tags/);
    expect(parse(doc('Trivy', [result('A', { properties: { tags: tags(257) } })]), 'trivy-config').toolError).toMatch(/tags/);
  });
  it('a crafted file (a rule with the most tags allowed, 20,000 results on it) is read in a bounded time', () => {
    const tags = Array.from({ length: 256 }, (_, i) => `t${i}`);
    const json = doc('gosec', Array.from({ length: 20_000 }, () => result('G1', { level: 'error' })), { rules: [{ id: 'G1', properties: { tags } }] });
    const start = Date.now();
    const out = parse(json, 'gosec');
    expect(out.findings).toHaveLength(20_000);
    expect(Date.now() - start).toBeLessThan(5_000);
  });
});

describe('M3: uriBaseId is resolved through originalUriBaseIds', () => {
  const withBase = (base: unknown, uri: string, baseId = 'ROOTPATH') => ({
    ...doc('Trivy', [result('x', { properties: { 'security-severity': '5' }, locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId: baseId }, region: { startLine: 1 } } }] })], { run: base === undefined ? {} : { originalUriBaseIds: { [baseId]: { uri: base } } } }),
  });
  const file = (json: unknown, tool = 'trivy-config') => parse(json, tool).findings[0]?.file;
  it('a base that is the workspace maps; one inside it prefixes the path; one outside, unknown, or relative is unmapped', () => {
    expect(file(withBase(`file://${WS}/`, 'infra/main.tf'))).toBe('infra/main.tf');
    expect(file(withBase(`file://${WS}`, 'main.tf'))).toBe('main.tf');
    expect(file(withBase(`file://${WS}/infra/`, 'main.tf'))).toBe('infra/main.tf');
    for (const base of ['file:///etc/', 'file:///home/runner/work/other/other/', `file://${WS}/../x/`, 'infra/', 'file://host/x/', '/etc/', `file://${WS}2/`]) expect(file(withBase(base, 'passwd')), base).toBeUndefined();
    expect(file(withBase(undefined, 'passwd'))).toBeUndefined();
    const out = parse(withBase('file:///etc/', 'passwd'), 'trivy-config');
    expect(out.toolError).toBeUndefined();
    expect(out.findings[0].uriUnmapped).toBe(true);
  });
  it('%SRCROOT% (semgrep) is the workspace without an entry; another id with no entry is unmapped; the real trivy files still map', () => {
    expect(file(withBase(undefined, 'src/a.js', '%SRCROOT%'))).toBe('src/a.js');
    expect(file(withBase(undefined, 'src/a.js', 'OTHER'))).toBeUndefined();
    const real = parseSarifText(read('trivy-config.sarif'), 'trivy-config', { workspace: WS });
    expect(real.findings.find((f) => f.ruleId === 'AWS-0092')?.file).toBe('terraform/main.tf');
    // without the workspace there is nothing to compare the base with
    expect(parseSarifText(read('trivy-config.sarif'), 'trivy-config').findings.every((f) => f.file === undefined)).toBe(true);
  });
  it('a uriBaseId that is not a string, or an originalUriBaseIds that is not an object, is a toolError', () => {
    expect(parse(withBase(`file://${WS}/`, 'a.tf', 5 as unknown as string), 'trivy-config').toolError).toBeDefined();
    const bad = doc('Trivy', [result('x', { properties: { 'security-severity': '5' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a', uriBaseId: 'R' } } }] })], { run: { originalUriBaseIds: [] } });
    expect(parse(bad, 'trivy-config').toolError).toBeDefined();
    const inner = doc('Trivy', [result('x', { properties: { 'security-severity': '5' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'a', uriBaseId: 'R' } } }] })], { run: { originalUriBaseIds: { R: { uri: 5 } } } });
    expect(parse(inner, 'trivy-config').toolError).toBeDefined();
    // hostile ids are data
    expect(file(withBase(`file://${WS}/`, 'a.tf', '__proto__'))).toBe('a.tf');
  });
});

describe('M4: two defaults that failed open', () => {
  const cfg = (level: unknown) => parse(doc('Semgrep OSS', [], { invocations: [{ executionSuccessful: true, toolConfigurationNotifications: [{ level }] }] }), 'semgrep');
  it('a configuration notification level that is not a SARIF level is an error; the four real ones keep their meaning', () => {
    for (const level of ['Error', 'ERROR', 'fatal', 'critical', '', 'warn']) expect(cfg(level).toolError, level).toBeDefined();
    for (const level of ['none', 'note', 'warning', undefined]) expect(cfg(level).toolError, String(level)).toBeUndefined();
    expect(cfg('error').toolError).toBeDefined();
  });
  it('an invocation with no executionSuccessful is a toolError (SARIF requires it); an empty invocations list is fine', () => {
    expect(parse(doc('Semgrep OSS', [], { invocations: [{}] }), 'semgrep').toolError).toMatch(/executionSuccessful/);
    expect(parse(doc('Semgrep OSS', [], { invocations: [{ executionSuccessful: true }, { toolConfigurationNotifications: [] }] }), 'semgrep').toolError).toMatch(/executionSuccessful/);
    expect(parse(doc('osv-scanner', [], { invocations: [] }), 'osv-scanner').toolError).toBeUndefined();
    expect(parse(doc('nuclei'.replace('n', 'N'), [], { invocations: [{ commandLine: 'nuclei' }] }), 'nuclei').toolError).toMatch(/executionSuccessful/);
  });
});
