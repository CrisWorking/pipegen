// C1c live: the staged secrets scan against the REAL pinned betterleaks 1.9.0 and gitleaks 8.30.1 (the cache of
// ensurePinnedBinary), the reviewed entries' own command run with its cwd in the stage folder and the canary rule added. Every key
// a pull request could hide before (review-C1b-r1 R1-C3: the path allowlists; review-C1b-r2 R2-C1: files taken for archives; R1-C2:
// a name that is not UTF-8; R1-I1: ignore files; P36: the chunk cut) must be reported and mapped back to its original path and
// line. Skipped unless PIPEGEN_LIVE_TESTS=1.
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { crc32, deflateRawSync } from 'node:zlib';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { readScrubbed, scrubBytes } from '../gate/src/scrub.js';
import { stageWorkspace } from '../gate/src/stage.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { runEntry, runStaged } from './helpers/secrets-live.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const SEC = 'sec' + 'ret:';
const PUSH = JSON.stringify({ repository: { id: 7 } });
// Stripe-shaped keys derived at runtime (no secret-like literal under test/)
const mk = (seed: string): string => 'sk' + '_live_' + createHash('sha256').update(seed).digest('hex').slice(0, 24);
const LIVE_KEY = mk('live');
const line = (k = LIVE_KEY): string => `stripe = "${k}"\n`;
type Tool = 'betterleaks' | 'gitleaks';
// spelled at run time (test/no-secret-literals.test.ts)
const STRIPE_RULE = ['stripe', 'access', 'tok' + 'en'].join('-');
const PW = 'pass' + 'word';
const val = (seed: string): string => createHash('sha256').update(seed).digest('hex').slice(0, 12);

/** A gzip file whose decompressed text is `text` and whose header FNAME field is `name` (the r1-gz attack of review-C1b-r1). */
function gzipWithName(text: string, name: string): Buffer {
  const body = Buffer.from(text);
  const header = Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3]), Buffer.from(name), Buffer.from([0])]);
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(crc32(body), 0);
  tail.writeUInt32LE(body.length, 4);
  return Buffer.concat([header, deflateRawSync(body), tail]);
}
/** A zip with one stored (not compressed) member. */
function storedZip(member: string, data: string): Buffer {
  const name = Buffer.from(member);
  const body = Buffer.from(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc32(body), 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(body.length, 22); local.writeUInt16LE(name.length, 26);
  return Buffer.concat([local, name, body]);
}

const stages: string[] = [];
function unlock(d: string): void {
  if (!existsSync(d)) return;
  chmodSync(d, 0o755);
  for (const e of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, e.name);
    if (e.isDirectory()) unlock(p);
    else if (e.isFile()) chmodSync(p, 0o644);
  }
}

describe.skipIf(!live)('C1c: the staged secrets scan, live with the real binaries', () => {
  const bins: Record<string, string> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterEach(() => { for (const s of stages.splice(0)) unlock(s); });
  afterAll(cleanupRepos);

  /** Stages `ws`, scans the stage folder with the real tool, scrubs with the stage: the findings as the gate reads them. */
  function scan(id: Tool, ws: string, over: Record<string, unknown> = {}) {
    const stage = join(makeTempDir(), 'pipegen-stage', 'pipegen-out-secrets');
    stages.push(join(stage, '..'));
    const st = stageWorkspace({ workspace: ws, stage });
    if (st.status !== 'ok') throw new Error(st.error);
    const raw = runStaged(id, bins[id] as string, stage);
    const out = scrubBytes(Buffer.from(raw), { tool: id, format: 'sarif', fpKey: KEY, eventText: PUSH, stage, ...over } as Parameters<typeof scrubBytes>[1]);
    if (out.status !== 'ok') throw new Error(out.error);
    const back = readScrubbed(out.bytes, 'sarif');
    if (back.toolError !== undefined) throw new Error(back.toolError);
    return { findings: back.findings, raw, stage, notes: back.notes };
  }
  const real = (fs: ReturnType<typeof scan>['findings']) => fs.filter((f) => f.ruleId !== `${SEC}not-scanned`);
  // the fingerprint of key `k` as the tool reports it in a plain file (its region is the match the rule reports, the closing quote
  // included for Stripe keys), so every placement of the same line must give the same one
  const refs = new Map<string, string>();
  const hmacOf = (id: Tool, k: string): string => {
    const known = refs.get(`${id}\0${k}`);
    if (known !== undefined) return known;
    const ws = makeTempDir();
    writeIn(ws, 'ref.js', line(k));
    const f = real(scan(id, ws).findings);
    if (f.length !== 1) throw new Error('the reference scan did not find the key once');
    refs.set(`${id}\0${k}`, (f[0] as { fingerprint: string }).fingerprint);
    return (f[0] as { fingerprint: string }).fingerprint;
  };

  for (const id of ['betterleaks', 'gitleaks'] as const) {
    it(`${id}: R1-C3, the reviewer's allowlisted placements: every one is reported at its own path and line (unstaged, only control.js was)`, () => {
      const ws = makeTempDir();
      const places = ['gitleaks.toml/app.js', 'lib/gitleaks.toml/client.js', 'src.gitleaks.toml.js', 'node_modules/x.js', 'vendor/bundle/x.rb', 'env/lib/x.py', 'docs/x.svg', 'docs/x.pdf', 'docs/x.png', 'go.sum', 'package-lock.json', 'control.js'];
      for (const p of places) writeIn(ws, p, `// a\n${line()}`);
      // the control: the reviewed command on the checkout itself sees only control.js
      const direct = JSON.parse(runEntry(id, bins[id] as string, ws)) as { runs: { results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[] }[] };
      expect(direct.runs[0]?.results.map((r) => r.locations[0]?.physicalLocation.artifactLocation.uri)).toEqual(['control.js']);
      const { findings } = scan(id, ws);
      expect(findings.map((f) => [f.file, f.line, f.ruleId]).sort()).toEqual(places.map((p) => [p, 2, `${SEC}${STRIPE_RULE}`]).sort());
      for (const f of findings) expect(f.fingerprint).toBe(hmacOf(id, LIVE_KEY));
    }, 120_000);

    it(`${id}: R2-C1, plain-text files taken for archives (by extension or by their first bytes) are scanned and mapped`, () => {
      const ws = makeTempDir();
      const exts = ['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'zst', 'lz4', 'br', 'Z', 'jar', 'docx', 'xlsx', 'whl', 'iso', 'cab'];
      for (const e of exts) writeIn(ws, `k.${e}`, line());
      const magics: Record<string, Buffer> = {
        'pk.js': Buffer.from([0x50, 0x4b, 0x03, 0x04]), 'gz.js': Buffer.from([0x1f, 0x8b, 0x08, 0x00]), 'bz.js': Buffer.from('BZh91AY&SY'), 'xz.js': Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
        '7z.js': Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), 'rar.js': Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]), 'zst.js': Buffer.from([0x28, 0xb5, 0x2f, 0xfd]),
      };
      for (const [n, m] of Object.entries(magics)) writeFileSync(join(ws, n), Buffer.concat([m, Buffer.from(`\n${line()}`)]));
      // ustar at byte 257 of the ORIGINAL file (the prefix moves it to 258, which nothing sniffs)
      const tar = Buffer.alloc(600, 0x61);
      Buffer.from(line()).copy(tar, 0);
      tar[Buffer.byteLength(line()) - 1] = 0x0a;
      Buffer.from('ustar').copy(tar, 257);
      writeFileSync(join(ws, 'tar_magic.js'), tar);
      const { findings } = scan(id, ws);
      const want = [...exts.map((e) => [`k.${e}`, 1]), ...Object.keys(magics).map((n) => [n, 2]), ['tar_magic.js', 1]];
      expect(real(findings).map((f) => [f.file, f.line]).sort()).toEqual(want.sort());
      expect(findings.filter((f) => f.ruleId === `${SEC}not-scanned`)).toEqual([]);
    }, 120_000);

    it(`${id}: R2-C1, a real stored zip and a real tar are read as raw bytes: the key in them is reported at its byte's line`, () => {
      const ws = makeTempDir();
      const body = Buffer.from(line());
      const name = Buffer.from('in/s.txt');
      const local = Buffer.alloc(30);
      local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc32(body), 14); local.writeUInt32LE(body.length, 18); local.writeUInt32LE(body.length, 22); local.writeUInt16LE(name.length, 26);
      writeFileSync(join(ws, 'x.zip'), Buffer.concat([local, name, body]));
      const header = Buffer.alloc(512);
      Buffer.from('s.txt').copy(header, 0);
      Buffer.from('ustar\x0000').copy(header, 257);
      writeFileSync(join(ws, 'x.tar'), Buffer.concat([header, body, Buffer.alloc(512 - body.length), Buffer.alloc(1024)]));
      const { findings } = scan(id, ws);
      expect(real(findings).map((f) => f.file).sort()).toEqual(['x.tar', 'x.zip']);
      for (const f of real(findings)) expect(f.fingerprint).toBe(hmacOf(id, LIVE_KEY));
    }, 120_000);

    it(`${id}: r1-gz staged: the gzip's raw bytes are scanned (the prefix stops the tool's gzip reader), so what is really in them is reported where it is; the compressed key is seen by no tool`, () => {
      const OLD = mk('old');
      const NEW = mk('new');
      const ws = makeTempDir();
      writeFileSync(join(ws, 'notes.gz'), gzipWithName(`x\n${line(NEW)}`, `\n${line(OLD).trimEnd()}`));
      const { findings } = scan(id, ws);
      // the old key is really in the header (line 2 of the raw file): its fingerprint is the old key's because those ARE its bytes
      expect(findings.map((f) => [f.file, f.line])).toEqual([['notes.gz', 2]]);
      expect(findings[0]?.fingerprint).toBe(hmacOf(id, OLD));
      expect(findings[0]?.fingerprint).not.toBe(hmacOf(id, NEW));
    }, 120_000);

    it(`${id}: r1-arch staged: a stored zip is scanned as raw bytes (the key is found in x.zip), and the decoy folder x.zip!in/ is a plain folder of its own`, () => {
      const OLD = mk('old');
      const ws = makeTempDir();
      writeFileSync(join(ws, 'x.zip'), storedZip('in/s.txt', line()));
      writeIn(ws, 'x.zip!in/s.txt', `stripe = q${OLD}"\n`);   // undetectable decoy
      const { findings } = scan(id, ws);
      expect(findings.map((f) => f.file)).toEqual(['x.zip']);
      expect(findings[0]?.fingerprint).toBe(hmacOf(id, LIVE_KEY));
    }, 120_000);

    it(`${id}: R1-C2, a name that is not UTF-8 next to its U+FFFD look-alike: the key is reported, read from its own file (not the decoy), unmapped (no lossless name)`, () => {
      const ws = makeTempDir();
      const OLD = mk('old');
      writeFileSync(Buffer.concat([Buffer.from(`${ws}/k`), Buffer.from([0xff]), Buffer.from('.js')]), `x\n${line()}`);
      writeFileSync(join(ws, 'k�.js'), `stripe = q${OLD}"\n`);   // the decoy the scanner can not see (no \b before sk_)
      const { findings } = scan(id, ws);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ uriUnmapped: true, line: 2, fpBy: 'region', fingerprint: hmacOf(id, LIVE_KEY) });
      expect(findings[0]?.fingerprint).not.toBe(hmacOf(id, OLD));
    }, 120_000);

    it(`${id}: R1-I1, a key inside .gitleaksignore / .betterleaksignore is scanned, and their entries hide nothing (no ignore file reaches the scan folder)`, () => {
      const ws = makeTempDir();
      writeIn(ws, 'a.js', `// x\n${line()}`);
      // entries for the original name, for the neutral name the stage gives a.js, and a key of its own
      const ignore = `a.js:${STRIPE_RULE}:2\nf00000003.txt:${STRIPE_RULE}:2\nf00000003.txt:${STRIPE_RULE}:3\n${line(mk('in-ignore'))}`;
      writeIn(ws, '.gitleaksignore', ignore);
      writeIn(ws, '.betterleaksignore', ignore);
      const { findings } = scan(id, ws);
      expect(real(findings).map((f) => [f.file, f.line]).sort()).toEqual([['.betterleaksignore', 4], ['.gitleaksignore', 4], ['a.js', 2]].sort());
    }, 120_000);

    it(`${id}: P36, a key across the scanner's own chunk cut in a 300 KB file: missed when the file is scanned whole, found through the pieces at its original line`, () => {
      const ws = makeTempDir();
      const rows = Array.from({ length: 3750 }, () => `${'x'.repeat(79)}\n`);
      const buf = Buffer.from(rows.join(''));
      // the key straddles byte 125,000 of the staged whole file (124,999 of the original), past the stretch of the 100,000-byte chunk
      const tok = Buffer.from(line().trimEnd());
      const start = 124_999 - 15;
      tok.copy(buf, start);
      writeFileSync(join(ws, 'big.js'), buf);
      const lineNo = buf.subarray(0, start).filter((c) => c === 0x0a).length + 1;
      // control: the same file staged whole (one piece) is missed by the scanner, while its canary is reported
      const wholeStage = join(makeTempDir(), 'pipegen-stage', 'whole');
      stages.push(join(wholeStage, '..'));
      expect(stageWorkspace({ workspace: ws, stage: wholeStage, pieceBytes: 400_000, overlap: 16_384 }).status).toBe('ok');
      const whole = JSON.parse(runStaged(id, bins[id] as string, wholeStage)) as { runs: { results: { ruleId: string }[] }[] };
      expect(whole.runs[0]?.results.map((r) => r.ruleId)).toEqual(['pipegen-canary']);
      const { findings } = scan(id, ws);
      expect(findings.map((f) => [f.file, f.line, f.ruleId])).toEqual([['big.js', lineNo, `${SEC}${STRIPE_RULE}`]]);
      expect(findings[0]?.fingerprint).toBe(hmacOf(id, LIVE_KEY));
    }, 180_000);

    it(`${id}: coverage, a file the scanner really skips (ustar at its sniffed byte after the prefix) is a critical not-scanned finding`, () => {
      const ws = makeTempDir();
      const b = Buffer.alloc(600, 0x61);
      Buffer.from(line()).copy(b, 0);
      Buffer.from('ustar').copy(b, 256);   // byte 257 once the one-byte prefix is in front
      writeFileSync(join(ws, 'skipped.js'), b);
      writeIn(ws, 'ok.js', 'ok\n');
      const { findings } = scan(id, ws);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ ruleId: `${SEC}not-scanned`, severity: 'critical', file: 'skipped.js', fpBy: 'file' });
    }, 120_000);

    it(`${id}: the five path rules still fire on their staged suffixes (pkcs12 on .p12 and .pfx, HashiCorp, Kubernetes, NuGet incl. mynuget.config)`, () => {
      const ws = makeTempDir();
      writeIn(ws, 'cert.pfx', 'binary\n');
      writeIn(ws, 'id.p12', 'x\n');
      writeIn(ws, 'main.tf', `resource "x" "y" {\n  ${PW} = "Xk9${val('tf')}"\n}\n`);
      writeIn(ws, 'mynuget.config', `<configuration>\n<packageSourceCredentials><f>\n<add key="ClearText${'Pass' + 'word'}" value="Zq8${val('nuget')}" />\n</f></packageSourceCredentials>\n</configuration>\n`);
      writeIn(ws, 'k8s/s.yaml', `apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  ${PW}: ${Buffer.from(`v-${val('k8s')}-x`).toString('base64')}\n`);
      const { findings } = scan(id, ws);
      const got = new Set(findings.map((f) => `${f.file} ${f.ruleId.slice(SEC.length)}`));
      for (const want of ['cert.pfx pkcs12-file', 'id.p12 pkcs12-file', 'main.tf hashicorp-tf-password', 'mynuget.config nuget-config-password', 'k8s/s.yaml kubernetes-secret-yaml']) expect(got, want).toContain(want);
      expect(findings.find((f) => f.file === 'cert.pfx')?.fpBy).toBe('file');
    }, 120_000);
  }

  it('the staged files hold the original bytes behind the prefix (sanity of the live setup)', () => {
    const ws = makeTempDir();
    writeIn(ws, 'a.js', line());
    const stage = join(makeTempDir(), 'pipegen-stage', 's');
    stages.push(join(stage, '..'));
    expect(stageWorkspace({ workspace: ws, stage }).status).toBe('ok');
    expect(readFileSync(join(stage, 'files', 'f00000001.txt')).subarray(1, 1 + Buffer.byteLength(line())).toString()).toBe(line());
  });
});
