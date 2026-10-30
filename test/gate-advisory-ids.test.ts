// C2 fix round 1, review-C2 I3: the parser and the scrub keep every advisory id and alias the SARIF carries for a finding, so the
// gate can see a malicious-package advisory (MAL-) whichever id the scanner shows. osv-scanner groups aliases under one rule and
// lists them in the rule's `deprecatedIds`. The chalk fixture is a real osv-scanner 2.7.0 run on a lockfile pinning chalk@5.6.1
// (the September 2025 npm compromise). Written first (strict test-first).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';
import { MAX_ADVISORY_IDS, parseSarif, parseSarifText } from '../gate/src/sarif.js';

const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const WS = '/home/runner/work/fixture/fixture';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const PUSH = JSON.stringify({ repository: { id: 7 } });
const read = (name: string): Buffer => readFileSync(join(DIR, name));

describe('advisory ids and aliases (review-C2 I3)', () => {
  it('the real chalk@5.6.1 run: osv-scanner shows the MAL- id as the rule id, with the GHSA alias in deprecatedIds; both are kept', () => {
    const r = parseSarifText(read('osv-scanner-chalk.sarif'), 'osv-scanner', { workspace: WS });
    expect(r.toolError).toBeUndefined();
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f?.ruleId).toBe('MAL-2025-46969');   // pinned: the id osv-scanner 2.7.0 displays for this group
    expect(f?.file).toBe('package-lock.json');
    expect(f?.advisoryIds).toEqual(['MAL-2025-46969', 'GHSA-2v46-p5h4-248w']);
  });
  it('the planted-repo osv fixture: each finding keeps its CVE and GHSA aliases', () => {
    const r = parseSarifText(read('osv-scanner.sarif'), 'osv-scanner', { workspace: WS });
    const lodash = r.findings.find((f) => f.ruleId === 'CVE-2020-28500');
    expect(lodash?.advisoryIds).toEqual(['CVE-2020-28500', 'GHSA-29mw-wpgm-hmr9']);
  });
  it('aliases from the rule\'s properties and from the result\'s properties are kept too, once each, in order', () => {
    const doc = {
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'osv-scanner', rules: [{ id: 'GHSA-x', deprecatedIds: ['GHSA-x', 'CVE-1'], properties: { aliases: ['MAL-2026-1'] } }] } },
        invocations: [],
        results: [{ ruleId: 'GHSA-x', ruleIndex: 0, message: { text: 'm' }, properties: { aliases: ['PYSEC-9', 'CVE-1'] }, locations: [{ physicalLocation: { artifactLocation: { uri: 'package-lock.json' } } }] }],
      }],
    };
    const r = parseSarif(doc, 'osv-scanner');
    expect(r.toolError).toBeUndefined();
    expect(r.findings[0]?.advisoryIds).toEqual(['GHSA-x', 'CVE-1', 'MAL-2026-1', 'PYSEC-9']);
  });
  it('an alias list of the wrong type, or over the cap, is a tool error (never silently dropped)', () => {
    const doc = (rule: Record<string, unknown>, props: Record<string, unknown> = {}) => ({
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'osv-scanner', rules: [{ id: 'A-1', ...rule }] } }, invocations: [], results: [{ ruleId: 'A-1', message: { text: 'm' }, properties: props }] }],
    });
    expect(parseSarif(doc({ deprecatedIds: 'MAL-1' }), 'osv-scanner').toolError).toMatch(/deprecatedIds/);
    expect(parseSarif(doc({ deprecatedIds: [1] }), 'osv-scanner').toolError).toMatch(/deprecatedIds/);
    expect(parseSarif(doc({}, { aliases: {} }), 'osv-scanner').toolError).toMatch(/aliases/);
    const many = Array.from({ length: MAX_ADVISORY_IDS + 1 }, (_, i) => `CVE-${i}`);
    expect(parseSarif(doc({ deprecatedIds: many }), 'osv-scanner').toolError).toMatch(/more than/);
  });
  it('two rules with one id and different aliases are a tool error (no side is picked silently)', () => {
    const doc = {
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'osv-scanner', rules: [{ id: 'GHSA-y' }, { id: 'GHSA-y', deprecatedIds: ['GHSA-y', 'MAL-2026-2'] }] } }, invocations: [], results: [{ ruleId: 'GHSA-y', message: { text: 'm' } }] }],
    };
    expect(parseSarif(doc, 'osv-scanner').toolError).toMatch(/same id/);
  });
  it('a secrets finding carries no advisory ids (nothing of a secrets tool\'s rules is written but the rule id)', () => {
    const r = parseSarifText(read('betterleaks.sarif'), 'betterleaks', { workspace: WS });
    for (const f of r.findings) expect(f.advisoryIds).toBeUndefined();
    const doc = { version: '2.1.0', runs: [{ tool: { driver: { name: 'betterleaks', rules: [{ id: 'k', deprecatedIds: ['k', 'x-1'] }] } }, results: [{ ruleId: 'k', message: { text: 'm' } }] }] };
    const one = parseSarif(doc, 'betterleaks');
    expect(one.toolError).toBeUndefined();
    expect(one.findings[0]?.advisoryIds).toBeUndefined();
  });
  it('the scrub writes them (pipegenAdvisoryIds) and readScrubbed gives them back; a malformed list in a scrubbed file is a tool error', () => {
    const out = scrubBytes(read('osv-scanner-chalk.sarif'), { tool: 'osv-scanner', format: 'sarif', fpKey: KEY, eventText: PUSH, workspace: WS });
    if (out.status !== 'ok') throw new Error(out.error);
    const back = readScrubbed(out.bytes, 'sarif');
    expect(back.toolError).toBeUndefined();
    expect(back.findings[0]?.advisoryIds).toEqual(['MAL-2025-46969', 'GHSA-2v46-p5h4-248w']);
    const text = out.bytes.toString('utf8');
    expect(text).toContain('pipegenAdvisoryIds');
    const bad = text.replace('"pipegenAdvisoryIds":["MAL-2025-46969","GHSA-2v46-p5h4-248w"]', '"pipegenAdvisoryIds":"MAL-2025-46969"');
    expect(bad).not.toBe(text);
    expect(readScrubbed(bad, 'sarif').toolError).toMatch(/advisory/);
  });
});
