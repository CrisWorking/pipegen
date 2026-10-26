import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { checkQualityBar, loadQualityBar, type QualityBar } from '../src/engine/quality-bar.js';
import { packageDataPath } from '../src/util/package-data.js';
import type { ToolStats } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const root = resolve(import.meta.dirname, '..');
const BAR: QualityBar = { minStars: 500, minScorecard: 5, strongScorecard: 7, scorecardMaxAgeDays: 180, maxMonthsSinceRelease: 12 };
const NOW = new Date('2026-10-26T12:00:00Z');

/** Passes every rule: popular, scored 8/10 this month, released last month, MIT, no advisories. */
/** Writes a valid-looking file and returns its path. */
function writeOk(dir: string, text: string): string {
  writeIn(dir, 'ok.yml', text);
  return join(dir, 'ok.yml');
}

const good = (over: Partial<ToolStats> = {}): ToolStats => ({
  repo: 'o/r', stars: 2000, archived: false, lastReleaseAt: '2026-09-20T00:00:00Z', scorecard: 8, scorecardAt: '2026-10-20T00:00:00Z',
  verifiedPublisher: false, license: 'MIT', advisories: 0, ...over,
});

describe('quality bar', () => {
  it('qualityBar: a healthy tool passes with no reasons', () => {
    expect(checkQualityBar(good(), BAR, NOW)).toEqual({ pass: true, reasons: [] });
  });

  it('qualityBar: archived never passes', () => {
    const v = checkQualityBar(good({ archived: true, stars: 90_000, scorecard: 10 }), BAR, NOW);
    expect(v.pass).toBe(false);
    expect(v.reasons).toEqual(['Project is archived: it gets no more fixes.']);
  });

  it('qualityBar: null scorecard skips score rule', () => {
    expect(checkQualityBar(good({ scorecard: null }), BAR, NOW)).toEqual({ pass: true, reasons: [] });
    // a real score below the minimum fails
    expect(checkQualityBar(good({ scorecard: 4.3 }), BAR, NOW).reasons).toEqual(['OpenSSF security score 4.3/10 is below 5.']);
    // but null is never a "strong" score: few stars still fail
    expect(checkQualityBar(good({ scorecard: null, stars: 40 }), BAR, NOW).reasons).toEqual(['Few users (40 stars) and no strong security score.']);
  });

  it('qualityBar: few stars pass with scorecard 7', () => {
    expect(checkQualityBar(good({ stars: 12, scorecard: 7 }), BAR, NOW)).toEqual({ pass: true, reasons: [] });
    expect(checkQualityBar(good({ stars: 12, scorecard: 6.9 }), BAR, NOW).reasons).toEqual(['Few users (12 stars) and no strong security score.']);
    expect(checkQualityBar(good({ stars: 500, scorecard: 5 }), BAR, NOW).pass).toBe(true); // both minimums are inclusive
  });

  it('qualityBar: null licence fails', () => {
    for (const license of [null, 'NOASSERTION', '']) {
      const v = checkQualityBar(good({ license }), BAR, NOW);
      expect(v.pass, String(license)).toBe(false);
      expect(v.reasons).toEqual(["No licence: can't be used safely."]);
    }
  });

  it('qualityBar: advisory on pinned version fails', () => {
    const v = checkQualityBar(good({ advisories: 1 }), BAR, NOW);
    expect(v).toEqual({ pass: false, reasons: ['Known vulnerability in this version.'] });
  });

  it('qualityBar: unknown advisories fail closed', () => {
    const v = checkQualityBar(good({ advisories: null }), BAR, NOW);
    expect(v).toEqual({ pass: false, reasons: ["Couldn't check known vulnerabilities for this version."] });
  });

  it('qualityBar: no release within maxMonthsSinceRelease fails', () => {
    expect(checkQualityBar(good({ lastReleaseAt: '2025-11-01T00:00:00Z' }), BAR, NOW).pass).toBe(true); // under 12 months
    expect(checkQualityBar(good({ lastReleaseAt: '2025-09-01T00:00:00Z' }), BAR, NOW).reasons).toEqual(['No release in 13 months.']);
    expect(checkQualityBar(good({ lastReleaseAt: null }), BAR, NOW).reasons).toEqual(['No releases published.']);
    expect(checkQualityBar(good({ lastReleaseAt: 'not a date' }), BAR, NOW).reasons).toEqual(["Couldn't read the date of the last release."]);
  });

  it('qualityBar: a release date in the future fails', () => {
    // a forged commit or release date can't make an old project look maintained
    expect(checkQualityBar(good({ lastReleaseAt: '2099-01-01T00:00:00Z' }), BAR, NOW).reasons).toEqual(["Couldn't read the date of the last release."]);
    expect(checkQualityBar(good({ lastReleaseAt: '2026-10-27T13:00:00Z' }), BAR, NOW).pass).toBe(false); // more than a day ahead
    expect(checkQualityBar(good({ lastReleaseAt: '2026-10-27T11:00:00Z' }), BAR, NOW).pass).toBe(true); // clock skew under a day
  });

  it('qualityBar: a stale Scorecard result is not strong', () => {
    const few = { stars: 12, scorecard: 8 };
    expect(checkQualityBar(good({ ...few, scorecardAt: '2026-06-01T00:00:00Z' }), BAR, NOW).pass).toBe(true); // 147 days old
    for (const scorecardAt of ['2026-01-01T00:00:00Z', null, 'not a date', '2099-01-01T00:00:00Z']) {
      const v = checkQualityBar(good({ ...few, scorecardAt }), BAR, NOW);
      expect(v.reasons, String(scorecardAt)).toEqual(['Few users (12 stars) and no strong security score.']);
    }
    // the minimum-score rule still uses the score itself
    expect(checkQualityBar(good({ scorecard: 6, scorecardAt: '2026-01-01T00:00:00Z' }), BAR, NOW).pass).toBe(true);
  });

  it('qualityBar: values that are not numbers fail closed', () => {
    const v = checkQualityBar(good({ stars: Number.NaN, scorecard: Number.NaN, advisories: Number.NaN }), BAR, NOW);
    expect(v.pass).toBe(false);
    expect(v.reasons).toEqual([
      'OpenSSF security score ?/10 is below 5.',
      'Few users (? stars) and no strong security score.',
      'Known vulnerability in this version.',
    ]);
  });

  it('qualityBar: lists every failing reason', () => {
    const v = checkQualityBar({
      repo: 'o/r', stars: 3, archived: true, lastReleaseAt: '2024-10-01T00:00:00Z', scorecard: 2, scorecardAt: '2026-10-01T00:00:00Z',
      verifiedPublisher: true, license: null, advisories: 2,
    }, BAR, NOW);
    expect(v.pass).toBe(false);
    expect(v.reasons).toEqual([
      'Project is archived: it gets no more fixes.',
      'No release in 24 months.',
      'OpenSSF security score 2/10 is below 5.',
      'Few users (3 stars) and no strong security score.',
      "No licence: can't be used safely.",
      'Known vulnerability in this version.',
    ]);
  });
});

describe('loadQualityBar', () => {
  it('qualityBar: loadQualityBar reads data/quality-bar.yml', () => {
    expect(packageDataPath('quality-bar.yml')).toBe(join(root, 'data', 'quality-bar.yml'));
    expect(loadQualityBar()).toEqual(BAR);
  });

  it('qualityBar: loadQualityBar refuses a malformed file', () => {
    const dir = makeTempDir();
    const ok = { minStars: '500', minScorecard: '5', strongScorecard: '7', scorecardMaxAgeDays: '180', maxMonthsSinceRelease: '12' };
    const file = (over: Record<string, string | undefined>) => Object.entries({ ...ok, ...over })
      .filter(([, v]) => v !== undefined).map(([k, v]) => `${k}: ${v}`).join('\n') + '\n';
    expect(loadQualityBar(writeOk(dir, file({})))).toEqual(BAR); // the builder itself makes a valid file
    const bad = {
      missing: file({ maxMonthsSinceRelease: undefined }),
      noAge: file({ scorecardMaxAgeDays: undefined }),
      age: file({ scorecardMaxAgeDays: '0' }),
      extra: file({ skip: 'true' }),
      negative: file({ minStars: '-1' }),
      score: file({ minScorecard: '11' }),
      order: file({ minScorecard: '8' }),
      text: file({ minStars: '"500"' }),
      yaml: 'minStars: [\n',
    };
    for (const [name, text] of Object.entries(bad)) {
      writeIn(dir, `${name}.yml`, text);
      expect(() => loadQualityBar(join(dir, `${name}.yml`)), name).toThrow(/quality bar/i);
    }
  });
});

describe('packageDataPath', () => {
  it('packageData: resolves files under data/ and refuses any other path', () => {
    expect(packageDataPath('gitleaks-bundle.toml')).toBe(join(root, 'data', 'gitleaks-bundle.toml'));
    for (const rel of ['../package.json', '/etc/passwd', 'a/../../package.json', '', '.', 'missing.yml']) {
      expect(() => packageDataPath(rel), rel).toThrow();
    }
  });
});
