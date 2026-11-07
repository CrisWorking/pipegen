// G15a round 5: the gate's ZAP reader (gate/src/zap.ts) on real reports of the pinned zap-stable image (test/fixtures/zap/README.md):
// the merge-layer baseline (`zap-baseline.py -J`) and the Automation Framework's traditional-json report, each clean and with alerts.
// With these, ZAP_JSON_VERIFIED is true: a blocking DAST check on ZAP blocks like any other required check.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';
import { parseZapJsonText, ZAP_JSON_VERIFIED } from '../gate/src/zap.js';
import { ZAP_JSON_VERIFIED as DOCS_ZAP_JSON_VERIFIED } from '../src/deliver/docs.js';

const DIR = join(import.meta.dirname, 'fixtures', 'zap');
const read = (name: string): Buffer => readFileSync(join(DIR, name));
const PUSH_EVENT = JSON.stringify({ repository: { id: 7 } });
const rows = (name: string): string[] => parseZapJsonText(read(name), 'zap-baseline').findings.map((f) => `${f.ruleId} ${f.severity} ${f.method ?? '-'} ${f.file ?? '-'}`);

describe('zap: the real reports of the pinned image', () => {
  it('zap: ZAP_JSON_VERIFIED is true (gate and PIPEGEN.md agree), and no result carries the unverified note', () => {
    expect(ZAP_JSON_VERIFIED).toBe(true);
    expect(DOCS_ZAP_JSON_VERIFIED).toBe(true);
    for (const f of ['baseline-clean.json', 'baseline-alerts.json', 'af-active-clean.json', 'af-active-alerts.json']) {
      const out = parseZapJsonText(read(f), 'zap-baseline');
      expect(out.toolError, f).toBeUndefined();
      expect(out.notes, f).toEqual([]);
    }
  });

  it('zap: a clean baseline run of the pinned image is one site with an empty alert list: no finding, no tool error', () => {
    const raw = JSON.parse(read('baseline-clean.json').toString('utf8')) as { '@version': string; site: { alerts: unknown[] }[] };
    expect(raw['@version']).toBe('2.17.0');
    expect(raw.site).toHaveLength(1);
    expect(raw.site[0]?.alerts).toEqual([]);
    expect(rows('baseline-clean.json')).toEqual([]);
    expect(rows('af-active-clean.json')).toEqual([]);
  });

  it('zap: the baseline run with alerts gives one finding per instance, riskcode 2 medium and 1 low, the URL path only', () => {
    expect(rows('baseline-alerts.json')).toEqual([
      '10038 medium GET /', '10038 medium GET /search', '10020 medium GET /', '10020 medium GET /search',
      '10036 low GET /', '10036 low GET /robots.txt', '10036 low GET /search', '10036 low GET /sitemap.xml',
      '10021 low GET /', '10021 low GET /search',
    ]);
    const text = JSON.stringify(parseZapJsonText(read('baseline-alerts.json'), 'zap-baseline'));
    for (const dropped of ['vuln', '8080', 'q=hello', 'q=ZAP', 'evidence', 'BaseHTTP']) expect(text, dropped).not.toContain(dropped);
  });

  it('zap: the AF active report reads the same way: the reflected and DOM XSS are high, the fragment and the attack query are dropped', () => {
    expect(rows('af-active-alerts.json')).toEqual([
      '40026 high GET /', '40026 high GET /search', '40012 high GET /search',
      '10038 medium GET /', '10038 medium GET /search', '10020 medium GET /', '10020 medium GET /search',
      '10036 low GET /', '10036 low GET /robots.txt', '10036 low GET /search', '10036 low GET /sitemap.xml',
      '10021 low GET /', '10021 low GET /search',
    ]);
    const text = JSON.stringify(parseZapJsonText(read('af-active-alerts.json'), 'zap-baseline'));
    for (const dropped of ['alert(', 'script', 'jaVasCript', 'vuln:8080']) expect(text, dropped).not.toContain(dropped);
  });

  it('scrub: the real reports scrub and read back with the same findings and no note; the clean one is zero findings', () => {
    for (const [f, n] of [['baseline-clean.json', 0], ['baseline-alerts.json', 10], ['af-active-clean.json', 0], ['af-active-alerts.json', 13]] as const) {
      const out = scrubBytes(read(f), { tool: 'zap-baseline', format: 'zap-json', fpKey: '', eventText: PUSH_EVENT });
      expect(out.status, f).toBe('ok');
      if (out.status !== 'ok') continue;
      expect(out.findings, f).toBe(n);
      expect(out.notes, f).toEqual([]);
      const back = readScrubbed(out.bytes, 'zap-json');
      expect(back.toolError, f).toBeUndefined();
      expect(back.findings, f).toHaveLength(n);
    }
  });
});
