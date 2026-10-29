import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkCooldown, checkDataFresh, checkNoDependencies, checkNotices, checkPending, checkScannerTests, checkVersion, formatChecks } from '../scripts/release-check.js';

const NOW = new Date('2026-11-20T12:00:00Z');
const reviewedOk = 'tools:\n  - id: a\n    reviewedBy: Cristiano\n    reviewedAt: "2026-11-01"\n  - id: b\n    reviewedBy: Cristiano\n    reviewedAt: "2026-11-01"\n';
const binsOk = 'gitleaks:\n  version: 1.0.0\n  reviewedBy: Cristiano\n  reviewedAt: "2026-11-01"\n';

describe('release-check: PENDING review entries', () => {
  it('passes when every entry in both files is reviewed', () => {
    expect(checkPending({ 'data/reviewed-tools.yml': reviewedOk, 'data/pinned-binaries.yml': binsOk })).toMatchObject({ ok: true, problems: [] });
  });
  it('fails on a PENDING entry in reviewed-tools.yml and names it', () => {
    const c = checkPending({ 'data/reviewed-tools.yml': reviewedOk + '  - id: c\n    reviewedBy: PENDING\n    reviewedAt: PENDING\n', 'data/pinned-binaries.yml': binsOk });
    expect(c.ok).toBe(false);
    expect(c.problems.join('\n')).toMatch(/reviewed-tools\.yml: 1 of 3 .*: c/);
  });
  it('fails on a PENDING entry in pinned-binaries.yml', () => {
    const c = checkPending({ 'data/reviewed-tools.yml': reviewedOk, 'data/pinned-binaries.yml': binsOk + 'cosign:\n  version: 3.1.3\n  reviewedBy: PENDING\n  reviewedAt: PENDING\n' });
    expect(c.ok).toBe(false);
    expect(c.problems.join('\n')).toContain('pinned-binaries.yml: 1 of 2');
  });
  it('treats a missing marker, a lower-case pending and a missing file as failures (fail closed)', () => {
    expect(checkPending({ 'data/reviewed-tools.yml': 'tools:\n  - id: a\n', 'data/pinned-binaries.yml': binsOk }).ok).toBe(false);
    expect(checkPending({ 'data/reviewed-tools.yml': reviewedOk, 'data/pinned-binaries.yml': 'x:\n  reviewedBy: pending\n  reviewedAt: pending\n' }).ok).toBe(false);
    expect(checkPending({ 'data/reviewed-tools.yml': reviewedOk }).ok).toBe(false);
    expect(checkPending({ 'data/reviewed-tools.yml': 'tools: []\n', 'data/pinned-binaries.yml': binsOk }).ok).toBe(false);
  });
});

describe('release-check: zero dependencies', () => {
  it('passes with none or only devDependencies', () => {
    expect(checkNoDependencies('{"name":"x","devDependencies":{"a":"1"}}').ok).toBe(true);
  });
  it('fails with one dependency, and names it', () => {
    const c = checkNoDependencies('{"name":"x","dependencies":{"left-pad":"1.0.0"}}');
    expect(c.ok).toBe(false);
    expect(c.problems[0]).toContain('left-pad');
  });
  it('fails on an empty "dependencies" object, and on unreadable JSON', () => {
    expect(checkNoDependencies('{"dependencies":{}}').ok).toBe(false);
    expect(checkNoDependencies('{nope').ok).toBe(false);
    expect(checkNoDependencies(null).ok).toBe(false);
  });
});

describe('release-check: THIRD_PARTY_NOTICES freshness', () => {
  it('passes when identical, fails when stale, empty, missing or ungeneratable', () => {
    expect(checkNotices('a\n', 'a\n').ok).toBe(true);
    expect(checkNotices('a\n', 'b\n').ok).toBe(false);
    expect(checkNotices('', 'b\n').ok).toBe(false);
    expect(checkNotices(null, 'b\n').ok).toBe(false);
    const c = checkNotices('a\n', null, 'no metafile');
    expect(c.ok).toBe(false);
    expect(c.problems[0]).toContain('no metafile');
  });
});

describe('release-check: version matches the tag', () => {
  it('passes for v1.2.3 and 1.2.3, and for a pre-release', () => {
    expect(checkVersion('{"version":"1.2.3"}', 'v1.2.3').ok).toBe(true);
    expect(checkVersion('{"version":"0.4.0-rc.1"}', 'v0.4.0-rc.1').ok).toBe(true);
  });
  it('fails on a mismatch, a malformed or missing tag, and a missing version', () => {
    expect(checkVersion('{"version":"1.2.3"}', 'v1.2.4').ok).toBe(false);
    expect(checkVersion('{"version":"1.2.3"}', '1.2.3').ok).toBe(false);
    expect(checkVersion('{"version":"1.2.3"}', 'v1.2').ok).toBe(false);
    expect(checkVersion('{"version":"1.2.3"}', 'refs/heads/main').ok).toBe(false);
    expect(checkVersion('{"version":"1.2.3"}', undefined).ok).toBe(false);
    expect(checkVersion('{"name":"x"}', 'v1.2.3').ok).toBe(false);
  });
});

describe('release-check: data files checked recently', () => {
  const f = (a: string, b: string) => ({ 'data/ai-prices.yml': `checkedAt: '${a}'\n`, 'data/github-plans.yml': `checkedAt: '${b}'\n` });
  it('passes within 30 days, fails after, in the future, or without a date', () => {
    expect(checkDataFresh(f('2026-11-01', '2026-10-25'), NOW).ok).toBe(true);
    expect(checkDataFresh(f('2026-11-01', '2026-10-01'), NOW).ok).toBe(false);
    expect(checkDataFresh(f('2027-01-01', '2026-11-01'), NOW).ok).toBe(false);
    expect(checkDataFresh({ 'data/ai-prices.yml': 'x: 1\n', 'data/github-plans.yml': "checkedAt: '2026-11-01'\n" }, NOW).ok).toBe(false);
  });
});

describe('release-check: cooldown', () => {
  it('passes when nothing changed, and fails closed when the check cannot run', async () => {
    const unreachable = (async () => { throw new Error('offline'); }) as typeof fetch;
    const same = { 'package.json': '{}' };
    expect((await checkCooldown(same, same, unreachable, NOW)).ok).toBe(true);
    // a lockfile entry that needs a registry lookup, with the network down
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/zzz': { version: '1.0.0', resolved: 'https://registry.npmjs.org/zzz/-/zzz-1.0.0.tgz', integrity: 'sha512-x' } } });
    const c = await checkCooldown({}, { 'package-lock.json': lock }, unreachable, NOW);
    expect(c.ok).toBe(false);
    expect(c.problems.length).toBeGreaterThan(0);
  });
  it('fails on a version younger than 7 days', async () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/zzz': { version: '1.0.0', resolved: 'https://registry.npmjs.org/zzz/-/zzz-1.0.0.tgz', integrity: 'sha512-x' } } });
    const doc = { versions: { '1.0.0': { dist: { integrity: 'sha512-x' } } }, time: { '1.0.0': '2026-11-19T12:00:00Z' } };
    const fetchFn = (async () => new Response(JSON.stringify(doc), { status: 200 })) as typeof fetch;
    const c = await checkCooldown({}, { 'package-lock.json': lock }, fetchFn, NOW);
    expect(c.ok).toBe(false);
  });
});

describe('release-check: secret-scanner live tests (canary, belt drift, chunk-size pin)', () => {
  it('passes the live run\'s verdict through, and fails closed when the run throws', () => {
    const ok = { name: 'secret-scanner live tests (canary, belt drift, chunk-size pin)', ok: true, problems: [] };
    expect(checkScannerTests(() => ok)).toEqual(ok);
    const bad = { ...ok, ok: false, problems: ['chunk-size pin: skipped, not passed'] };
    expect(checkScannerTests(() => bad)).toEqual(bad);
    const thrown = checkScannerTests(() => { throw new Error('spawn failed'); });
    expect(thrown.ok).toBe(false);
    expect(thrown.problems.join('\n')).toContain('could not run');
  });
});

describe('release-check: report and command line', () => {
  it('lists every failed check', () => {
    const out = formatChecks([{ name: 'a', ok: true, problems: [] }, { name: 'b', ok: false, problems: ['bad thing'] }]);
    expect(out).toContain('FAIL b');
    expect(out).toContain('bad thing');
    expect(out).toContain('1 of 2 checks failed');
  });
  it('exits 2 without --tag (the full run needs the network, so it is not run here)', () => {
    const script = resolve(import.meta.dirname, '../scripts/release-check.ts');
    let code = 0;
    try {
      execFileSync('node', [script], { encoding: 'utf8', stdio: 'pipe' });
    } catch (e) {
      code = (e as { status: number }).status;
    }
    expect(code).toBe(2);
  });
});
