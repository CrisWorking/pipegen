// The secret-scanner upgrade checklist (P34-P38): the release check and CI require three live tests to have run and
// passed (never skipped): the canary tests, the belt drift test and the chunk-size pin test. checkScannerLive judges
// vitest's JSON report; these tests feed it reports by hand, so nothing here downloads a scanner.
import { describe, expect, it } from 'vitest';
import { checkScannerLive, REQUIRED_SCANNER_TESTS, SCANNER_LIVE_FILES } from '../scripts/scanner-live.js';

const ROOT = '/repo';
const SKIP = `${ROOT}/test/secret-scan-skip-live.test.ts`;
/** The titles of the real required tests, as they are in test/secret-scan-skip-live.test.ts today. */
const TITLES = [
  'live: TMPDIR under node_modules/: bundleCode throws SecretScanError (the belt), and with the belt off the canary alone fails closed',
  'live: a normal temp folder: both scanners report every canary, and a real finding is redacted on its line',
  "live (belt drift): the belt mirrors every folder-level pattern of each pinned scanner's default path allowlist",
  'live (P38 pin): a file of exactly SCAN_CHUNK_SAFE_BYTES as written is read whole: every token and each canary is reported',
];
type Status = 'passed' | 'failed' | 'skipped' | 'pending' | 'todo';
const result = (name: string, tests: [string, Status][]) => ({ name, status: tests.some(([, s]) => s === 'failed') ? 'failed' : 'passed', assertionResults: tests.map(([title, status]) => ({ title, fullName: `suite ${title}`, status })) });
const others = SCANNER_LIVE_FILES.filter((f) => !f.endsWith('secret-scan-skip-live.test.ts')).map((f) => result(`${ROOT}/${f}`, [['live: something', 'passed']]));
const report = (skip: [string, Status][] = TITLES.map((t) => [t, 'passed']), more = others) => ({ success: true, testResults: [result(SKIP, skip), ...more] });

describe('scanner-live: the three required live tests', () => {
  it('lists the canary, belt drift and chunk-size pin tests, all in test/secret-scan-skip-live.test.ts', () => {
    expect(REQUIRED_SCANNER_TESTS.map((r) => r.label)).toEqual(['canary: a skipped scan path fails closed', 'canary: every file and every paths piece confirmed', 'belt drift', 'chunk-size pin']);
    for (const r of REQUIRED_SCANNER_TESTS) expect(r.file).toBe('test/secret-scan-skip-live.test.ts');
    expect(SCANNER_LIVE_FILES).toContain('test/secret-scan-skip-live.test.ts');
    // each pattern matches exactly one of today's titles
    for (const r of REQUIRED_SCANNER_TESTS) expect(TITLES.filter((t) => r.title.test(t)), r.label).toHaveLength(1);
  });

  it('passes when every required test passed and nothing failed or was skipped', () => {
    expect(checkScannerLive(report(), ROOT)).toMatchObject({ ok: true, problems: [] });
  });

  it('fails when a required test was skipped (PIPEGEN_LIVE_TESTS not set), failed, or is missing (renamed or deleted)', () => {
    for (const status of ['skipped', 'pending', 'todo', 'failed'] as const) {
      const c = checkScannerLive(report(TITLES.map((t, i) => [t, i === 3 ? status : 'passed'])), ROOT);
      expect(c.ok, status).toBe(false);
      expect(c.problems.join('\n'), status).toContain('chunk-size pin');
    }
    const c = checkScannerLive(report(TITLES.filter((_, i) => i !== 2).map((t) => [t, 'passed'])), ROOT);
    expect(c.ok).toBe(false);
    expect(c.problems.join('\n')).toContain('belt drift: not found');
  });

  it('fails when any other test in the scanner files failed or was skipped, or a file did not run', () => {
    const extra = checkScannerLive(report([...TITLES.map((t): [string, Status] => [t, 'passed']), ['live (P39): something else', 'skipped']]), ROOT);
    expect(extra.ok).toBe(false);
    expect(extra.problems.join('\n')).toContain('live (P39): something else');
    const missingFile = checkScannerLive(report(undefined, others.slice(1)), ROOT);
    expect(missingFile.ok).toBe(false);
    expect(missingFile.problems.join('\n')).toMatch(/did not run/);
  });

  it('fails closed on a missing or unreadable report', () => {
    for (const bad of [null, undefined, 'x', {}, { testResults: 'no' }]) expect(checkScannerLive(bad, ROOT).ok).toBe(false);
  });
});
