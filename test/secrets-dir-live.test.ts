// Live check (C1b fix round 1, review finding C1) against the REAL pinned betterleaks 1.9.0 and gitleaks 8.30.1, run with
// the reviewed entry's own command (dir mode on the checked-out tree). A scanner that reads git blobs reports blob columns
// while the scrub reads the checked-out file; `.gitattributes` `ident` makes the two differ. In dir mode both read the same
// bytes, so the region the scrub reads must be exactly the token, with the pinned COLUMN_RULES. Network: the pinned binaries
// come from the cache of ensurePinnedBinary (downloaded once). Skipped unless PIPEGEN_LIVE_TESTS=1.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { readRegion } from '../gate/src/fingerprint.js';
import { parseSarifText, SARIF_TOOLS } from '../gate/src/sarif.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { git, runEntry } from './helpers/secrets-live.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
// built at runtime: the repo's own check refuses secret-like literals in test/
const mk = (seed: string): string => `gh` + `p_` + createHash('sha256').update(seed).digest('hex').slice(0, 18).toUpperCase() + createHash('sha256').update(seed).digest('hex').slice(18, 36);
const PLANT_A = mk('one');
const PLANT_B = mk('two');
describe.skipIf(!live)('secrets tools in dir mode read what the scrub reads (live, real pinned binaries)', () => {
  const bins: Record<string, string> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterAll(cleanupRepos);

  for (const id of ['betterleaks', 'gitleaks'] as const) {
    it(`${id}: with .gitattributes ident the checked-out file has grown, and the region the scrub reads is exactly the token`, () => {
      const dir = makeTempDir();
      git(dir, 'init', '-q');
      writeIn(dir, '.gitattributes', 'b.js ident\n');
      writeIn(dir, 'b.js', `/* $Id$ */ var x = "${PLANT_A}";\n`);
      git(dir, 'add', '-A');
      git(dir, 'commit', '-q', '-m', 'x');
      execFileSync('rm', [join(dir, 'b.js')]);
      git(dir, 'checkout', '--', 'b.js');
      expect(readFileSync(join(dir, 'b.js'), 'utf8')).toMatch(/\$Id: [0-9a-f]{40} \$/);   // the checkout expanded the keyword
      const parsed = parseSarifText(runEntry(id, bins[id], dir), id, { workspace: dir });
      expect(parsed.toolError).toBeUndefined();
      expect(parsed.findings).toHaveLength(1);
      const region = readRegion(dir, parsed.findings[0]);
      expect(region.ok && region.bytes.toString('utf8')).toBe(PLANT_A);
    });

    it(`${id}: the uri is written raw: a file named src/%61pp.js is reported as src/%61pp.js (the SARIF_TOOLS row says raw), with its own region`, () => {
      const dir = makeTempDir();
      git(dir, 'init', '-q');
      writeIn(dir, 'src/%61pp.js', `var a = "${PLANT_A}";\n`);
      writeIn(dir, 'src/app.js', 'var a = 1;\n');   // the file a decoding parser would file the finding under
      git(dir, 'add', '-A');
      git(dir, 'commit', '-q', '-m', 'x');
      const text = runEntry(id, bins[id], dir);
      expect((JSON.parse(text) as { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] }).runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri)).toEqual(['src/%61pp.js']);
      expect(SARIF_TOOLS[id].uriEncoding).toBe('raw');
      const parsed = parseSarifText(text, id, { workspace: dir });
      expect(parsed.findings[0]).toMatchObject({ file: 'src/%61pp.js' });
      const region = readRegion(dir, parsed.findings[0]);
      expect(region.ok && region.bytes.toString('utf8')).toBe(PLANT_A);
    });

    it(`${id}: COLUMN_RULES hold in dir mode (line 1, a later line, non-ASCII before the token, CRLF)`, () => {
      const dir = makeTempDir();
      git(dir, 'init', '-q');
      writeIn(dir, 'a.js', `var a = "${PLANT_A}";\nvar b = 1;\nvar c = "é ü ${PLANT_B}";\r\nvar d = 2;\n`);
      git(dir, 'add', '-A');
      git(dir, 'commit', '-q', '-m', 'x');
      const parsed = parseSarifText(runEntry(id, bins[id], dir), id, { workspace: dir });
      expect(parsed.toolError).toBeUndefined();
      const seen = parsed.findings.map((f) => {
        const r = readRegion(dir, f);
        return r.ok ? r.bytes.toString('utf8') : `unreadable: ${r.reason}`;
      }).sort();
      expect(seen).toEqual([PLANT_A, PLANT_B].sort());
    });
  }
});
