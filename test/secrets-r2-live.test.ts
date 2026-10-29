// Live regressions of review-C1b-r1.md (C1b fix round 2) with the REAL pinned betterleaks 1.9.0 and gitleaks 8.30.1 and the reviewed
// entry's own command: R1-C1 (archives), R1-C2 (a file name that is not UTF-8). Skipped unless PIPEGEN_LIVE_TESTS=1.
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { crc32, deflateRawSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { parseSarifText } from '../gate/src/sarif.js';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { git, runEntry } from './helpers/secrets-live.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
// two Stripe-shaped keys derived at runtime (no secret-like literal under test/)
const mk = (seed: string): string => 'sk' + '_live_' + createHash('sha256').update(seed).digest('hex').slice(0, 24);
const OLD = mk('old');
const NEW = mk('new');

/** A gzip file whose decompressed text is `text` and whose header FNAME field is `name` (never scanned, as a betterleaks archive reader sees it). */
function gzipWithName(text: string, name: string): Buffer {
  const body = Buffer.from(text);
  const header = Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3]), Buffer.from(name), Buffer.from([0])]);
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(crc32(body), 0);
  tail.writeUInt32LE(body.length, 4);
  return Buffer.concat([header, deflateRawSync(body), tail]);
}

/** A zip with one stored member. */
function zip(member: string, data: string): Buffer {
  const name = Buffer.from(member);
  const body = Buffer.from(data);
  const crc = crc32(body);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(33, 12);
  local.writeUInt32LE(crc, 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(body.length, 22); local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(33, 14);
  central.writeUInt32LE(crc, 16); central.writeUInt32LE(body.length, 20); central.writeUInt32LE(body.length, 24); central.writeUInt16LE(name.length, 28);
  const localPart = Buffer.concat([local, name, body]);
  const cd = Buffer.concat([central, name]);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(localPart.length, 16);
  return Buffer.concat([localPart, cd, end]);
}

describe.skipIf(!live)('R1-C1 and R1-C2 against the real binaries', () => {
  const bins: Record<string, string> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterAll(cleanupRepos);

  const scrubbed = (id: 'betterleaks' | 'gitleaks', dir: string, over: Record<string, unknown> = {}) =>
    scrubBytes(Buffer.from(runEntry(id, bins[id], dir)), { tool: id, format: 'sarif', fpKey: KEY, eventText: '{}', workspace: dir, ...over } as Parameters<typeof scrubBytes>[1]);
  /** The scrubbed findings of a scan of `dir`. */
  const findings = (id: 'betterleaks' | 'gitleaks', dir: string, over: Record<string, unknown> = {}) => {
    const out = scrubbed(id, dir, over);
    if (out.status !== 'ok') throw new Error(out.error);
    return readScrubbed(out.bytes, 'sarif').findings;
  };
  const baseFingerprint = (id: 'betterleaks' | 'gitleaks') => {
    const dir = makeTempDir();
    git(dir, 'init', '-q');
    writeIn(dir, 'a.js', `stripe = "${OLD}"\n`);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'base');
    const f = findings(id, dir);
    expect(f).toHaveLength(1);
    return f[0].fingerprint;
  };

  for (const id of ['betterleaks', 'gitleaks'] as const) {
    it(`${id} (r1-gz): a new key inside notes.gz, with an old key in the gzip header, never gets the old key's fingerprint`, () => {
      const old = baseFingerprint(id);
      const dir = makeTempDir();
      git(dir, 'init', '-q');
      writeFileSync(join(dir, 'notes.gz'), gzipWithName(`x\nstripe = "${NEW}"\n`, `\nstripe = "${OLD}"`));
      git(dir, 'add', '-A');
      git(dir, 'commit', '-q', '-m', 'head');
      expect(findings(id, dir).map((f) => f.fingerprint)).not.toContain(old);
    });

    it(`${id} (r1-arch): a key inside x.zip with a decoy folder "x.zip!in/" never gets the old key's fingerprint, and no finding is mapped to the decoy`, () => {
      const old = baseFingerprint(id);
      const dir = makeTempDir();
      git(dir, 'init', '-q');
      writeFileSync(join(dir, 'x.zip'), zip('in/s.txt', `stripe = "${NEW}"\n`));
      mkdirSync(join(dir, 'x.zip!in'));
      writeFileSync(join(dir, 'x.zip!in', 's.txt'), `stripe = q${OLD}"\n`);   // the \b before sk_ fails: the scanner reports nothing here
      git(dir, 'add', '-A');
      git(dir, 'commit', '-q', '-m', 'head');
      const f = findings(id, dir);
      expect(f.map((x) => x.fingerprint)).not.toContain(old);
      expect(f.filter((x) => x.file?.includes('!'))).toEqual([]);
    });

    for (const keyed of [true, false]) {
      it(`${id} (r1-utf8, ${keyed ? 'keyed' : 'keyless'}): a file name that is not UTF-8 and a file named with U+FFFD: the finding is unmapped, never filed under the decoy`, () => {
        const old = baseFingerprint(id);
        const dir = makeTempDir();
        git(dir, 'init', '-q');
        writeFileSync(Buffer.concat([Buffer.from(`${dir}/k`), Buffer.from([0xff]), Buffer.from('.js')]), `stripe = "${NEW}"\n`);
        writeFileSync(join(dir, 'k�.js'), `stripe = q${OLD}"\n`);   // the decoy the scanner cannot see
        git(dir, 'add', '-A');
        git(dir, 'commit', '-q', '-m', 'head');
        const f = findings(id, dir, keyed ? {} : { fpKey: '', eventText: JSON.stringify({ repository: { id: 7 }, pull_request: { head: { repo: { id: 8 } } } }) });
        expect(f).toHaveLength(1);
        expect(f[0].file).toBeUndefined();
        expect(f[0].uriUnmapped).toBe(true);
        expect(f[0].fingerprint).not.toBe(old);
        if (keyed) expect(f[0].fpBy).toBe('line');
        // the parser alone says the same
        const parsed = parseSarifText(runEntry(id, bins[id], dir), id, { workspace: dir });
        expect(parsed.findings[0]).toMatchObject({ uriUnmapped: true });
      });
    }
  }
});
