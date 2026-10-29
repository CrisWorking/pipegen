// Plan C Task C1a: zap-json parsing (gate/src/zap.ts). The report is hostile too: the URLs and evidence come from the
// scanned application. Query, host and port are dropped (S10: pluginid + method + url path is the identity), and
// `evidence` (and every other free text of the report) is never read.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { MAX_RAW_BYTES } from '../gate/src/sarif.js';
import { parseZapJson, parseZapJsonText } from '../gate/src/zap.js';

type Obj = Record<string, unknown>;
const FIXTURE = join(import.meta.dirname, 'fixtures', 'zap', 'zap-traditional-json.json');

function instance(uri: string, over: Obj = {}): Obj {
  return { id: '-1', uri, method: 'GET', param: 'p', attack: 'a', evidence: 'ev', otherinfo: 'oi', ...over };
}
function alert(over: Obj = {}, instances: unknown[] = [instance('http://app.example:8080/a/b?x=1#frag')]): Obj {
  return { pluginid: '40012', alertRef: '40012', alert: 'Cross Site Scripting (Reflected)', name: 'Cross Site Scripting (Reflected)', riskcode: '2', confidence: '2', desc: 'd', instances, count: String(instances.length), solution: 's', reference: 'r', ...over };
}
function report(alerts: unknown[] = [alert()], over: Obj = {}): Obj {
  return { '@programName': 'ZAP', '@version': '2.16.0', '@generated': 'now', site: [{ '@name': 'http://app.example:8080', '@host': 'app.example', '@port': '8080', '@ssl': 'false', alerts }], ...over };
}
const parse = (json: unknown, tool = 'zap-baseline') => parseZapJson(json, tool);

describe('zap: findings', () => {
  it('zap: riskcode 2 → medium with the URL path as file; query, fragment, host and port are dropped', () => {
    const out = parse(report());
    expect(out.toolError).toBeUndefined();
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ tool: 'zap-baseline', ruleId: '40012', severity: 'medium', file: '/a/b', method: 'GET', uriUnmapped: false });
    expect(out.findings[0].message).toContain('Cross Site Scripting');
    const text = JSON.stringify(out);
    for (const dropped of ['x=1', 'frag', 'app.example', '8080', 'http']) expect(text, dropped).not.toContain(dropped);
  });

  it('zap: riskcode 3 → high, 2 medium, 1 low, 0 info (as a string or a number); anything else → high with a note', () => {
    const out = parse(report([alert({ riskcode: '3' }), alert({ riskcode: 2 }), alert({ riskcode: '1' }), alert({ riskcode: 0 }), alert({ riskcode: '0' }), alert({ riskcode: '4' }), alert({ riskcode: 'high' }), alert({ riskcode: undefined })]));
    expect(out.findings.map((f) => f.severity)).toEqual(['high', 'medium', 'low', 'info', 'info', 'high', 'high', 'high']);
    expect(out.notes).toHaveLength(1);
    expect(out.notes[0]).toMatch(/3 alert\(s\).*riskcode.*high/i);
  });

  it('zap: one finding per instance (the same alert on two urls is two findings), and an alert with no instances is still one finding', () => {
    const out = parse(report([alert({}, [instance('http://h/a'), instance('http://h/b'), instance('http://h/a', { method: 'POST' })]), alert({ pluginid: '10', name: 'Empty' }, []), alert({ pluginid: '11', name: 'Missing', instances: undefined })]));
    expect(out.toolError).toBeUndefined();
    expect(out.findings.map((f) => [f.ruleId, f.method, f.file])).toEqual([['40012', 'GET', '/a'], ['40012', 'GET', '/b'], ['40012', 'POST', '/a'], ['10', undefined, undefined], ['11', undefined, undefined]]);
  });

  it('zap: the url path is a path only: dot segments resolved by the URL rules, an unparsable or non-http uri is unmapped (file undefined), never a host', () => {
    const paths = ['http://h/a/../b', 'http://h/a/%2e%2e/b', 'http://h', 'https://h:1/', 'http://user' + ':pw@h/p?q', 'http://h/a b/c'];
    expect(parse(report([alert({}, paths.map((p) => instance(p)))])).findings.map((f) => f.file)).toEqual(['/b', '/b', '/', '/', '/p', '/a%20b/c']);
    const bad = parse(report([alert({}, ['', 'not a url', '/relative/path', 'javascript:alert(1)', 'file:///etc/passwd', 'ftp://h/x', null].map((u) => instance(u as string)))]));
    expect(bad.toolError).toBeUndefined();
    expect(bad.findings.map((f) => [f.file, f.uriUnmapped])).toEqual(Array.from({ length: 7 }, () => [undefined, true]));
    expect(JSON.stringify(parse(report([alert({}, [instance('http://user' + ':pw@h/p')])])))).not.toContain('pw');
  });

  it('zap: evidence, attack, param, otherinfo, desc, solution, reference and every other free text are never read', () => {
    const inst = instance('http://h/p');
    const al = alert({}, [inst]);
    const trap = (o: Obj, key: string) => Object.defineProperty(o, key, { enumerable: true, get() { throw new Error(`read ${key}`); } });
    for (const key of ['evidence', 'attack', 'param', 'otherinfo', 'nodeName', 'id']) trap(inst, key);
    for (const key of ['desc', 'solution', 'reference', 'otherinfo', 'riskdesc', 'confidence', 'cweid', 'wascid', 'sourceid', 'count', 'systemic', 'alertRef']) trap(al, key);
    const rep = report([al]);
    for (const key of ['@version', '@generated', 'created']) trap(rep, key);
    trap((rep.site as Obj[])[0], '@host');
    trap((rep.site as Obj[])[0], '@port');
    const out = parse(rep);
    expect(out.toolError).toBeUndefined();
    expect(out.findings).toHaveLength(1);
    // and a hostile text in them cannot reach a finding
    const hostile = parse(report([alert({ desc: 'SENTINEL', solution: 'SENTINEL' }, [instance('http://h/p', { evidence: 'SENTINEL', attack: 'SENTINEL', param: 'SENTINEL', otherinfo: 'SENTINEL' })])]));
    expect(JSON.stringify(hostile)).not.toContain('SENTINEL');
  });

  it('zap: pluginid and the alert name are bounded and must be strings; the method is one of the HTTP words or dropped', () => {
    expect(parse(report([alert({ pluginid: 40012 })])).toolError).toBeDefined();
    expect(parse(report([alert({ pluginid: undefined })])).toolError).toBeDefined();
    expect(parse(report([alert({ pluginid: 'p'.repeat(2000) })])).toolError).toBeDefined();
    const name = parse(report([alert({ name: 'n'.repeat(10_000), alert: undefined })]));
    expect(name.findings[0].message.length).toBeLessThanOrEqual(2000);
    const methods = parse(report([alert({}, ['get', 'POST', 'X'.repeat(500), 'bad method', null].map((m) => instance('http://h/p', { method: m })))]));
    expect(methods.findings.map((f) => f.method)).toEqual(['GET', 'POST', undefined, undefined, undefined]);
    expect(parse(report([alert({}, [instance('http://h/p', { method: 5 })])])).toolError).toBeDefined();
  });
});

describe('zap: tool errors', () => {
  it('zap: no site, an empty site list, a site with no alerts list, or a program that is not ZAP → toolError', () => {
    expect(parse({ '@programName': 'ZAP' }).toolError).toMatch(/site/);
    expect(parse(report([], { site: [] })).toolError).toMatch(/site/);
    expect(parse(report([], { site: {} })).toolError).toMatch(/site/);
    expect(parse(report([], { site: [{ '@name': 'x' }] })).toolError).toMatch(/alerts/);
    expect(parse(report([], { site: [{ alerts: 'none' }] })).toolError).toMatch(/alerts/);
    expect(parse(report([], { site: [null] })).toolError).toBeDefined();
    expect(parse(report([alert()], { '@programName': 'Burp' })).toolError).toMatch(/ZAP/);
    expect(parse(report([alert()], { '@programName': undefined })).toolError).toMatch(/ZAP/);
    // a site whose alerts list is empty is a clean report
    expect(parse(report([])).toolError).toBeUndefined();
    expect(parse(report([])).findings).toEqual([]);
  });

  it('zap: an alert or instance of the wrong type → toolError, never a skipped finding', () => {
    expect(parse(report(['x'])).toolError).toBeDefined();
    expect(parse(report([alert({ instances: 'many' })])).toolError).toBeDefined();
    expect(parse(report([alert({}, ['x'])])).toolError).toBeDefined();
    expect(parse(report([alert({}, [instance(7 as unknown as string)])])).toolError).toBeDefined();
    expect(parse(report([alert({ riskcode: {} })])).toolError).toBeDefined();
    expect(parse(report([alert({ name: 5, alert: 5 })])).toolError).toBeDefined();
  });

  it('zap: a tool id other than zap-baseline, and a document that is not an object → toolError', () => {
    expect(parse(report(), 'made-up').toolError).toMatch(/not a tool/i);
    expect(parse(report(), '__proto__').toolError).toBeDefined();
    for (const bad of [null, undefined, 3, 'x', [], true]) expect(parse(bad).toolError, String(bad)).toBeDefined();
  });

  it('zap: the size cap (64 MiB), the finding cap and invalid JSON → toolError; the shape is always { findings, toolError?, notes }', () => {
    expect(MAX_RAW_BYTES).toBe(64 * 1024 * 1024);
    const text = JSON.stringify(report());
    expect(parseZapJsonText(text, 'zap-baseline', { limits: { maxBytes: text.length } }).toolError).toBeUndefined();
    expect(parseZapJsonText(text, 'zap-baseline', { limits: { maxBytes: text.length - 1 } }).toolError).toMatch(/size/i);
    const many = report([alert({}, [instance('http://h/a'), instance('http://h/b'), instance('http://h/c')])]);
    expect(parseZapJson(many, 'zap-baseline', { limits: { maxResults: 3 } }).findings).toHaveLength(3);
    const over = parseZapJson(many, 'zap-baseline', { limits: { maxResults: 2 } });
    expect(over.toolError).toMatch(/findings/i);
    expect(over.findings).toEqual([]);
    for (const bad of ['', '{', 'null', '[]', '{"site":']) expect(parseZapJsonText(bad, 'zap-baseline').toolError, bad).toBeDefined();
    const err = parse(report([], { site: [] }));
    expect(Object.keys(err).sort()).toEqual(['findings', 'notes', 'toolError']);
    expect(Object.keys(parse(report())).sort()).toEqual(['findings', 'notes']);
  });

  it('zap: __proto__ and constructor as pluginid, alert, site and instance keys parse as data, with no prototype change', () => {
    const text = `{"@programName":"ZAP","__proto__":{"polluted":"yes"},"site":[{"__proto__":{"alerts":[]},"alerts":[
      {"pluginid":"__proto__","name":"constructor","riskcode":"3","__proto__":{"riskcode":"0"},"instances":[{"uri":"http://h/__proto__","method":"GET","__proto__":{"uri":"http://evil/x"}}]},
      {"pluginid":"constructor","name":"toString","riskcode":"1","instances":[]}]}]}`;
    const out = parseZapJsonText(text, 'zap-baseline');
    expect(out.toolError).toBeUndefined();
    expect(out.findings.map((f) => [f.ruleId, f.severity, f.file])).toEqual([['__proto__', 'high', '/__proto__'], ['constructor', 'low', undefined]]);
    expect(({} as Obj).polluted).toBeUndefined();
  });

  it('zap: deep nesting in an ignored field parses (50,000 levels); in a read field → toolError', () => {
    const deep = (n: number) => '['.repeat(n) + ']'.repeat(n);
    const ok = parseZapJsonText(`{"@programName":"ZAP","extra":${deep(50_000)},"site":[{"alerts":[{"pluginid":"1","name":"n","riskcode":"3","desc":${deep(50_000)},"instances":[{"uri":"http://h/p","method":"GET","evidence":${deep(50_000)}}]}]}]}`, 'zap-baseline');
    expect(ok.toolError).toBeUndefined();
    expect(ok.findings).toHaveLength(1);
    for (const field of [`"pluginid":${deep(5000)}`, `"name":${deep(5000)}`, `"riskcode":${deep(5000)}`, `"instances":[{"uri":${deep(5000)}}]`, `"instances":[{"uri":"http://h/p","method":${deep(5000)}}]`]) {
      const base = field.startsWith('"pluginid"') ? '' : '"pluginid":"1",';
      const out = parseZapJsonText(`{"@programName":"ZAP","site":[{"alerts":[{${base}${field}}]}]}`, 'zap-baseline');
      expect(out.toolError, field.slice(0, 30)).toBeDefined();
    }
  });
});

describe('zap: the real report (zaproxy/zap-extensions at a pinned commit)', () => {
  it('fixture zap-traditional-json.json: no toolError, two findings (one alert on one url, twice), high, path /example_3, nothing of the evidence', () => {
    const out = parseZapJsonText(readFileSync(FIXTURE), 'zap-baseline');
    expect(out.toolError).toBeUndefined();
    expect(out.notes).toEqual([]);
    expect(out.findings).toEqual([
      { tool: 'zap-baseline', ruleId: '1', severity: 'high', file: '/example_3', message: 'XSS', method: 'GET', uriUnmapped: false },
      { tool: 'zap-baseline', ruleId: '1', severity: 'high', file: '/example_3', message: 'XSS', method: 'GET', uriUnmapped: false },
    ]);
    const text = JSON.stringify(out);
    for (const dropped of ['example.com', 'Evidence', 'Attack', 'Other', 'Param']) expect(text, dropped).not.toContain(dropped);
  });
});
