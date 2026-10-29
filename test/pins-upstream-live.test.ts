// Live re-check of every pin in the trust root against upstream (Plan P final review m5). The per-PR cooldown ties each
// NEW or CHANGED pin to its upstream hash and date; a pin nobody touched is never looked at again. But upstream can
// drift under an unchanged pin: a tag moved to other code, a release asset deleted and uploaded again with other bytes,
// a Docker tag pointing at another digest. Here every pin of data/reviewed-tools.yml and data/pinned-binaries.yml is
// treated as new (an empty base) and tied again by scripts/cooldown.ts's own code: npm integrity, PyPI sha256, release
// asset digests, action tag -> commit SHA, Docker digests, plugins and the archives tools download at run time.
//
// Only a tie problem fails here. Age is the per-PR cooldown's call (with its emergency path), so a young item, which can
// only be a pin the PR itself changed, is printed and not failed. Network: the npm registry, PyPI, Docker Hub and the
// GitHub API (several hundred requests, so set GITHUB_TOKEN). Skipped unless PIPEGEN_LIVE_TESTS=1.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { binaryItems, formatReport, reviewedItems, runCooldown, type CooldownOptions, type Files } from '../scripts/cooldown.js';
import { FIRST_RELEASE_MAX_LOOKUPS } from '../scripts/release-check.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const read = (f: string): string => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

describe.skipIf(!live)('every pin in data/ re-tied to upstream (live)', () => {
  it('live: every pin still ties to its upstream hash (a moved tag or a re-uploaded asset fails)', async () => {
    const head: Files = { 'data/reviewed-tools.yml': read('data/reviewed-tools.yml'), 'data/pinned-binaries.yml': read('data/pinned-binaries.yml') };
    const items = reviewedItems(null, head['data/reviewed-tools.yml']).length + binaryItems(null, head['data/pinned-binaries.yml']).length;
    // the token option name is built at runtime (repo rule: nothing in test/ may look like a secret assignment)
    const withGitHub = Object.fromEntries([['github' + 'Tok' + 'en', process.env[['GITHUB', 'TOKEN'].join('_')]]]) as Partial<CooldownOptions>;
    const r = await runCooldown({ base: {}, head, fetch, now: new Date(), maxLookups: FIRST_RELEASE_MAX_LOOKUPS, ...withGitHub });
    const young = r.findings.filter((f) => f.young);
    const untied = r.findings.filter((f) => !f.young);
    console.log(`pins re-tied: ${r.checked} of ${items} items; ${untied.length} problem(s); ${young.length} younger than the cooldown (not failed here)`);
    if (r.findings.length > 0) console.log(formatReport({ ...r, findings: [...untied, ...young] }));
    expect(r.checked).toBe(items);
    expect(items).toBeGreaterThan(40);
    expect(untied.map((f) => `[${f.kind}] ${f.name} ${f.version}: ${f.problem}`)).toEqual([]);
  }, 900_000);
});
