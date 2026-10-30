// C1c: the gate's neutral-name staging for the secrets scan (gate/src/stage.ts) and the staged scrub (gate/src/scrub.ts with
// `stage`). Offline: the scanner's SARIF is built here the way the pinned betterleaks 1.9.0 and gitleaks 8.30.1 write it
// (measured in test/secrets-stage-live.test.ts). Written first (strict test-first).
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { asScannedBytes, isCanary, PIECE_OVERLAP_BYTES, SCAN_CHUNK_SAFE_BYTES, writtenCanaryLine } from '../src/ai/scan-staging.js';
import { readScrubbed, scrubBytes, scrubFile } from '../gate/src/scrub.js';
import { displayPathOf, listingMatches, MAX_STAGE_BYTES, MAX_STAGE_FILES, MAX_STAGED_BYTES, readStage, StageError, stageWorkspace, suffixFor } from '../gate/src/stage.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const KEY = ['fp', 'test', 'a'.repeat(40)].join('-');
const PUSH = JSON.stringify({ repository: { id: 7 } });
const FORK = JSON.stringify({ repository: { id: 7 }, pull_request: { head: { repo: { id: 8 } } } });
const SEC = 'sec' + 'ret:';
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
// Stripe-shaped keys derived at runtime (no secret-like literal under test/)
const mk = (seed: string): string => 'sk' + '_live_' + sha(seed).slice(0, 24);
const KEY_A = mk('a');
const KEY_B = mk('b');
// rule ids spelled at run time (test/no-secret-literals.test.ts reads a rule id and a line number as an assignment)
const STRIPE_RULE = ['stripe', 'access', 'tok' + 'en'].join('-');

const made: string[] = [];
/** The stage folder is read-only when the step is done; make it writable again so the temp folders can be removed. */
function unlock(dir: string): void {
  if (!existsSync(dir)) return;
  const walk = (d: string): void => {
    chmodSync(d, 0o755);
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) chmodSync(p, 0o644);
    }
  };
  walk(dir);
}
afterEach(() => { for (const d of made.splice(0)) unlock(d); cleanupRepos(); });
function stageOf(ws: string, over: Record<string, unknown> = {}): { stage: string; out: ReturnType<typeof stageWorkspace> } {
  const stage = join(makeTempDir(), 'pipegen-stage', 'pipegen-out-secrets');
  made.push(join(stage, '..'));
  return { stage, out: stageWorkspace({ workspace: ws, stage, ...over }) };
}
interface Entry { name: string; path: string; size: number; sha256: string; offset: number; length: number; line: number; column: number; lines: number; canary: string; stagedSize: number; stagedSha256: string; piece: number; pieces: number }
const manifestOf = (stage: string): { files: Entry[] } & Record<string, unknown> => JSON.parse(readFileSync(join(stage, 'manifest.json'), 'utf8')) as { files: Entry[] };
const pathOf = (e: Entry): Buffer => Buffer.from(e.path, 'base64');
const byPath = (stage: string, p: string | Buffer): Entry[] => manifestOf(stage).files.filter((e) => pathOf(e).equals(typeof p === 'string' ? Buffer.from(p) : p));
const one = (stage: string, p: string | Buffer): Entry => {
  const es = byPath(stage, p);
  if (es.length !== 1) throw new Error(`expected one entry for ${String(p)}, got ${es.length}`);
  return es[0] as Entry;
};

// ---------- the SARIF the scanners write for a staged folder ----------

type Tool = 'betterleaks' | 'gitleaks';
interface Hit { rule: string; uri: string; startLine: number; startColumn: number; endLine: number; endColumn: number }
function sarif(tool: Tool, hits: readonly Hit[]): string {
  return JSON.stringify({
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: tool, rules: [] } },
      results: hits.map((h) => ({
        message: { text: `${h.rule} has detected secret for file ${h.uri}.` }, ruleId: h.rule,
        locations: [{ physicalLocation: { artifactLocation: { uri: h.uri }, region: { startLine: h.startLine, startColumn: h.startColumn, endLine: h.endLine, endColumn: h.endColumn, snippet: { text: 'REDACTED' } } } }],
        partialFingerprints: { commitSha: '', email: '', author: '', date: '', commitMessage: '' }, properties: { tags: [] },
      })),
    }],
  });
}
/** Where `needle` is in a staged file, as the tool reports it: bytes from 1, end inclusive, gitleaks one more on every line after the first. */
function hitFor(tool: Tool, stage: string, name: string, needle: string, rule = STRIPE_RULE, nth = 0): Hit {
  const bytes = readFileSync(join(stage, 'files', name));
  let at = -1;
  for (let k = 0; k <= nth; k++) at = bytes.indexOf(needle, at + 1);
  if (at < 0) throw new Error(`token not in ${name}`);
  const before = bytes.subarray(0, at);
  const line = before.filter((c) => c === 0x0a).length + 1;
  const lineStart = before.lastIndexOf(0x0a) + 1;
  const shift = tool === 'gitleaks' && line >= 2 ? 1 : 0;
  const col = at - lineStart + 1 + shift;
  return { rule, uri: name, startLine: line, startColumn: col, endLine: line, endColumn: col + Buffer.byteLength(needle) - 1 };
}
/** The canary hit of every staged file (what a full scan reports). */
function canaries(tool: Tool, stage: string, except: readonly string[] = []): Hit[] {
  return manifestOf(stage).files.filter((e) => !except.includes(e.name)).map((e) => hitFor(tool, stage, e.name, e.canary, 'pipegen-canary'));
}
const scrub = (tool: Tool, stage: string, text: string, over: Record<string, unknown> = {}) =>
  scrubBytes(Buffer.from(text), { tool, format: 'sarif', fpKey: KEY, eventText: PUSH, stage, ...over } as Parameters<typeof scrubBytes>[1]);
function okFindings(o: ReturnType<typeof scrubBytes>) {
  if (o.status !== 'ok') throw new Error(`expected ok, got ${o.error}`);
  const back = readScrubbed(o.bytes, 'sarif');
  if (back.toolError !== undefined) throw new Error(back.toolError);
  return { back, text: o.bytes.toString('utf8') };
}

// ---------- staging ----------

describe('stageWorkspace: every regular file, by raw bytes, under a neutral name', () => {
  it('copies each regular file as prefix + bytes + blank line + its own canary, under f00000001… in raw-byte order; records the manifest; makes it read-only', () => {
    const ws = makeTempDir();
    writeIn(ws, 'a.js', `stripe = "${KEY_A}"\n`);
    writeIn(ws, 'sub/b.txt', 'no newline at the end');
    writeIn(ws, '.gitleaksignore', `f00000002.txt:${STRIPE_RULE}:2\n`);
    writeIn(ws, '.betterleaksignore', `x\n`);
    writeIn(ws, '.git/config', '[core]\n');                 // the root .git is git's, never content
    writeIn(ws, 'sub/.git-like/x', 'nested\n');           // anything else is content
    writeIn(ws, 'empty', '');
    const { stage, out } = stageOf(ws);
    expect(out).toMatchObject({ status: 'ok', files: 6, staged: 6 });
    const m = manifestOf(stage);
    expect(m.files.map((e) => e.name)).toEqual(['f00000001.txt', 'f00000002.txt', 'f00000003.txt', 'f00000004.txt', 'f00000005.txt', 'f00000006.txt']);
    expect(m.files.map((e) => pathOf(e).toString())).toEqual(['.betterleaksignore', '.gitleaksignore', 'a.js', 'empty', 'sub/.git-like/x', 'sub/b.txt']);
    for (const e of m.files) {
      const orig = readFileSync(join(ws, pathOf(e).toString()));
      const staged = readFileSync(join(stage, 'files', e.name));
      expect(isCanary(e.canary), e.name).toBe(true);
      expect(staged.equals(asScannedBytes(orig, e.canary)), e.name).toBe(true);
      expect(e).toMatchObject({ size: orig.length, sha256: sha(orig), offset: 0, length: orig.length, line: 1, column: 0, stagedSize: staged.length, stagedSha256: sha(staged), piece: 1, pieces: 1 });
      expect(statSync(join(stage, 'files', e.name)).mode & 0o777, e.name).toBe(0o444);
    }
    expect(new Set(m.files.map((e) => e.canary)).size).toBe(m.files.length);
    // the ignore files are content too: copied under a neutral name, and the scan folder holds no file of their names
    expect(readdirSync(join(stage, 'files')).some((n) => n.includes('ignore'))).toBe(false);
    expect(statSync(join(stage, 'files')).mode & 0o777).toBe(0o555);
    expect(statSync(join(stage, 'manifest.json')).mode & 0o777).toBe(0o444);
    expect(statSync(stage).mode & 0o777).toBe(0o555);
    expect(m).toMatchObject({ pipegenStage: 1, prefixBytes: 1, canaryRule: 'pipegen-canary', overlap: PIECE_OVERLAP_BYTES });
  });

  it('never follows a link: a file link, a folder link and a dangling link are not staged (their in-repo targets are, at their own paths)', () => {
    const ws = makeTempDir();
    writeIn(ws, 'real/a.js', 'a\n');
    const outside = makeTempDir();
    writeIn(outside, 'secret.txt', `stripe = "${KEY_B}"\n`);
    symlinkSync(join(ws, 'real/a.js'), join(ws, 'link.js'));
    symlinkSync(outside, join(ws, 'dirlink'));
    symlinkSync('/nonexistent/x', join(ws, 'dangling'));
    const { stage, out } = stageOf(ws);
    expect(out).toMatchObject({ status: 'ok', files: 1, skippedLinks: 3 });
    expect(manifestOf(stage).files.map((e) => pathOf(e).toString())).toEqual(['real/a.js']);
  });

  it('walks names as bytes: a name that is not UTF-8 and its U+FFFD look-alike are two files, each staged with its own bytes and path', () => {
    const ws = makeTempDir();
    const raw = Buffer.concat([Buffer.from('k'), Buffer.from([0xff]), Buffer.from('.js')]);
    writeFileSync(Buffer.concat([Buffer.from(`${ws}/`), raw]), `stripe = "${KEY_A}"\n`);
    writeFileSync(join(ws, 'k�.js'), 'decoy\n');
    const { stage, out } = stageOf(ws);
    expect(out).toMatchObject({ status: 'ok', files: 2 });
    const a = one(stage, raw);
    const b = one(stage, Buffer.from('k�.js'));
    expect(a.name).not.toBe(b.name);
    expect(readFileSync(join(stage, 'files', a.name)).includes(KEY_A)).toBe(true);
    expect(readFileSync(join(stage, 'files', b.name)).includes('decoy')).toBe(true);
  });

  it('is deterministic: the same tree gives the same names, paths and sizes (only the canaries differ)', () => {
    const ws = makeTempDir();
    for (const n of ['b', 'a', 'B', 'a/c', 'é', 'z.yaml']) writeIn(ws, n === 'a' ? 'a.txt' : n, n);
    const one1 = manifestOf(stageOf(ws).stage).files.map((e) => [e.name, e.path, e.size]);
    const two = manifestOf(stageOf(ws).stage).files.map((e) => [e.name, e.path, e.size]);
    expect(two).toEqual(one1);
  });

  it('a file a path rule targets keeps that rule\'s suffix (the original\'s own form when listed), every other file is .txt', () => {
    const ws = makeTempDir();
    for (const n of ['cert.PFX', 'id.p12', 'infra/main.tf', 'x.hcl', 'k8s/a.YML', 'k8s/b.yaml', 'mynuget.config', 'NuGet.Config', 'wp/a.php', 'v.tfvars', 'a.p12.bak', 'readme.md']) writeIn(ws, n, 'x\n');
    const { stage } = stageOf(ws);
    const suffixOf = (p: string): string => one(stage, p).name.slice('f00000000'.length);
    expect(Object.fromEntries(['cert.PFX', 'id.p12', 'infra/main.tf', 'x.hcl', 'k8s/a.YML', 'k8s/b.yaml', 'mynuget.config', 'NuGet.Config', 'wp/a.php', 'v.tfvars', 'a.p12.bak', 'readme.md'].map((p) => [p, suffixOf(p)]))).toEqual({
      'cert.PFX': '.pfx', 'id.p12': '.p12', 'infra/main.tf': '.tf', 'x.hcl': '.hcl', 'k8s/a.YML': '.yml', 'k8s/b.yaml': '.yaml', 'mynuget.config': '.nuget.config',
      'NuGet.Config': '.nuget.config', 'wp/a.php': '.php', 'v.tfvars': '.txt', 'a.p12.bak': '.txt', 'readme.md': '.txt',
    });
    expect(suffixFor('a/b/C.Pfx')).toBe('.pfx');
    expect(suffixFor(Buffer.concat([Buffer.from([0xff]), Buffer.from('.yml')]))).toBe('.yml');
  });

  it('a file larger than one chunk is staged as overlapping pieces, each with its own prefix, canary and offset, each written within the chunk, AND once whole (fix round 1, I1)', () => {
    const ws = makeTempDir();
    const body = Array.from({ length: 3750 }, (_, i) => `${String(i + 1).padStart(6, '0')}${'x'.repeat(73)}\n`).join('');   // 300,000 bytes
    writeIn(ws, 'big.js', body);
    writeIn(ws, 'small.js', 'small\n');
    const { stage, out } = stageOf(ws);
    expect(out).toMatchObject({ status: 'ok', files: 2 });
    const all = byPath(stage, 'big.js');
    const pieces = all.filter((e) => e.piece >= 1);
    expect(pieces.length).toBeGreaterThan(3);
    const orig = Buffer.from(body);
    pieces.forEach((p, i) => {
      expect(p).toMatchObject({ piece: i + 1, pieces: pieces.length, size: orig.length, sha256: sha(orig) });
      const staged = readFileSync(join(stage, 'files', p.name));
      expect(staged.length).toBeLessThanOrEqual(SCAN_CHUNK_SAFE_BYTES);
      expect(staged.equals(asScannedBytes(orig.subarray(p.offset, p.offset + p.length), p.canary))).toBe(true);
      expect(p.line).toBe(orig.subarray(0, p.offset).filter((c) => c === 0x0a).length + 1);
    });
    expect((pieces.at(-1) as Entry).offset + (pieces.at(-1) as Entry).length).toBe(orig.length);
    // the whole copy: piece 0, the whole file, line 1, its own canary (composite rules and long multi-line keys see the file as one)
    const whole = all.filter((e) => e.piece === 0);
    expect(whole).toHaveLength(1);
    expect(whole[0]).toMatchObject({ offset: 0, length: orig.length, line: 1, column: 0, pieces: pieces.length, size: orig.length });
    expect(readFileSync(join(stage, 'files', (whole[0] as Entry).name)).equals(asScannedBytes(orig, (whole[0] as Entry).canary))).toBe(true);
    expect(new Set(all.map((p) => p.canary)).size).toBe(all.length);
    // a small file is staged once, as piece 1 of 1
    expect(byPath(stage, 'small.js').map((e) => [e.piece, e.pieces])).toEqual([[1, 1]]);
  });

  it('the staged total is capped too (the whole copies count): above MAX_STAGED_BYTES the step fails, and leaves no stage folder', () => {
    expect(MAX_STAGED_BYTES).toBeGreaterThan(2 * MAX_STAGE_BYTES);
    const ws = makeTempDir();
    writeIn(ws, 'big.js', Array.from({ length: 3750 }, () => `${'x'.repeat(79)}\n`).join(''));   // 300,000 bytes: about 670 KB staged
    const capped = stageOf(ws, { maxStagedBytes: 500_000 });
    expect(capped.out.status === 'error' && capped.out.error).toMatch(/more than 500000 bytes.*not scanned/i);
    expect(existsSync(capped.stage)).toBe(false);
    expect(stageOf(ws, { maxStagedBytes: 1_000_000 }).out.status).toBe('ok');
  });

  it('a folder of the checkout that can not be read stops the step (it would go unscanned)', () => {
    if (process.getuid?.() === 0) return;   // root reads it anyway
    const ws = makeTempDir();
    writeIn(ws, 'a.js', 'a\n');
    writeIn(ws, 'locked/b.js', 'b\n');
    chmodSync(join(ws, 'locked'), 0o000);
    try {
      const r = stageOf(ws);
      expect(r.out.status === 'error' && r.out.error).toMatch(/can not be read/);
      expect(existsSync(r.stage)).toBe(false);
    } finally {
      chmodSync(join(ws, 'locked'), 0o755);
    }
  });

  it('displayPathOf: a byte form of a name that is not plain UTF-8, for people only (invalid bytes and controls as \\xNN, U+FFFD as \\u{fffd}, a backslash doubled)', () => {
    expect(displayPathOf(Buffer.concat([Buffer.from('src/k'), Buffer.from([0xff]), Buffer.from('.js')]))).toBe('src/k\\xff.js');
    expect(displayPathOf(Buffer.from('k\uFFFD.js'))).toBe('k\\u{fffd}.js');
    expect(displayPathOf(Buffer.from('a\\b\tc'))).toBe('a\\\\b\\x09c');
    expect(displayPathOf(Buffer.from('é/ok.js'))).toBe('é/ok.js');
    // two different raw names never share a display form
    expect(displayPathOf(Buffer.from('k\\xff.js'))).not.toBe(displayPathOf(Buffer.concat([Buffer.from('k'), Buffer.from([0xff]), Buffer.from('.js')])));
  });

  it('fails closed, and says so, above the file-count cap and the total-size cap; nothing is staged then', () => {
    expect(MAX_STAGE_FILES).toBeGreaterThanOrEqual(100_000);
    expect(MAX_STAGE_BYTES).toBeGreaterThanOrEqual(512 * 1024 * 1024);
    const ws = makeTempDir();
    for (const n of ['a', 'b', 'c']) writeIn(ws, n, '0123456789');
    const many = stageOf(ws, { maxFiles: 2 });
    expect(many.out.status).toBe('error');
    expect(many.out.status === 'error' && many.out.error).toMatch(/more than 2 files.*not scanned/i);
    expect(existsSync(many.stage)).toBe(false);
    const big = stageOf(ws, { maxBytes: 25 });
    expect(big.out.status === 'error' && big.out.error).toMatch(/more than 25 bytes.*not scanned/i);
    expect(existsSync(big.stage)).toBe(false);
    expect(stageOf(ws, { maxFiles: 3, maxBytes: 30 }).out.status).toBe('ok');
  });

  it('refuses a stage folder that exists, a link on the way to it, and a workspace that is not a real folder', () => {
    const ws = makeTempDir();
    writeIn(ws, 'a', 'a');
    const base = makeTempDir();
    mkdirSync(join(base, 'pipegen-stage', 'x'), { recursive: true });
    expect(stageWorkspace({ workspace: ws, stage: join(base, 'pipegen-stage', 'x') }).status).toBe('error');
    const other = makeTempDir();
    symlinkSync(other, join(base, 'linked'));
    expect(stageWorkspace({ workspace: ws, stage: join(base, 'linked', 'x') }).status).toBe('error');
    expect(readdirSync(other)).toEqual([]);
    const wsLink = join(makeTempDir(), 'ws');
    symlinkSync(ws, wsLink);
    expect(stageWorkspace({ workspace: wsLink, stage: join(makeTempDir(), 's') }).status).toBe('error');
    expect(stageWorkspace({ workspace: join(ws, 'a'), stage: join(makeTempDir(), 's') }).status).toBe('error');
    expect(stageWorkspace({ workspace: 'relative/ws', stage: join(makeTempDir(), 's') }).status).toBe('error');
  });
});

describe('readStage: the scrub checks the staged folder against its manifest', () => {
  it('the listing check is linear: 30,000 names compare in well under a second (fix round 1, I2)', () => {
    const names = Array.from({ length: 30_000 }, (_, i) => `f${String(i + 1).padStart(8, '0')}.txt`);
    const listed = [...names].reverse();
    const t = performance.now();
    expect(listingMatches(listed, names)).toBe(true);
    expect(performance.now() - t).toBeLessThan(500);
    expect(listingMatches([...listed.slice(1), 'f99999999.txt'], names)).toBe(false);
    expect(listingMatches(listed.slice(1), names)).toBe(false);
  });

  function staged(): string {
    const ws = makeTempDir();
    writeIn(ws, 'a.js', `stripe = "${KEY_A}"\n`);
    writeIn(ws, 'b.js', 'b\n');
    return stageOf(ws).stage;
  }
  it('reads a staged folder', () => {
    const s = readStage(staged());
    expect(s.entries.map((e) => e.name)).toEqual(['f00000001.txt', 'f00000002.txt']);
  });
  const tamper: [string, (stage: string) => void][] = [
    ['an extra file in the scan folder', (s) => { chmodSync(join(s, 'files'), 0o755); writeFileSync(join(s, 'files', '.gitleaksignore'), 'x'); }],
    ['a missing file', (s) => { chmodSync(join(s, 'files'), 0o755); unlinkSync(join(s, 'files', 'f00000002.txt')); }],
    ['a changed byte', (s) => { const p = join(s, 'files', 'f00000001.txt'); chmodSync(p, 0o644); const b = readFileSync(p); b[3] = 0x41; writeFileSync(p, b); }],
    ['a staged file replaced by a link', (s) => { chmodSync(join(s, 'files'), 0o755); const p = join(s, 'files', 'f00000002.txt'); const b = readFileSync(p); unlinkSync(p); const t = join(makeTempDir(), 't'); writeFileSync(t, b); symlinkSync(t, p); }],
    ['the manifest replaced by a link', (s) => { chmodSync(s, 0o755); const p = join(s, 'manifest.json'); const b = readFileSync(p); unlinkSync(p); const t = join(makeTempDir(), 'm'); writeFileSync(t, b); symlinkSync(t, p); }],
    ['an entry with a name out of the pattern', (s) => { chmodSync(s, 0o755); const p = join(s, 'manifest.json'); chmodSync(p, 0o644); const m = JSON.parse(readFileSync(p, 'utf8')); m.files[0].name = '../a.js'; writeFileSync(p, JSON.stringify(m)); }],
    ['a canary that is not a canary', (s) => { chmodSync(s, 0o755); const p = join(s, 'manifest.json'); chmodSync(p, 0o644); const m = JSON.parse(readFileSync(p, 'utf8')); m.files[0].canary = 'x'; writeFileSync(p, JSON.stringify(m)); }],
    ['no manifest at all (the stage step did not finish)', (s) => { chmodSync(s, 0o755); unlinkSync(join(s, 'manifest.json')); }],
    ['entries out of name order (each still matching its file)', (s) => { chmodSync(s, 0o755); const p = join(s, 'manifest.json'); chmodSync(p, 0o644); const m = JSON.parse(readFileSync(p, 'utf8')); m.files.reverse(); writeFileSync(p, JSON.stringify(m)); }],
    ['another prefix length', (s) => { chmodSync(s, 0o755); const p = join(s, 'manifest.json'); chmodSync(p, 0o644); const m = JSON.parse(readFileSync(p, 'utf8')); m.prefixBytes = 2; writeFileSync(p, JSON.stringify(m)); }],
  ];
  it('refuses a whole copy (piece 0) that does not stand for its whole file', () => {
    const ws = makeTempDir();
    writeIn(ws, 'big.js', Array.from({ length: 3750 }, () => `${'x'.repeat(79)}\n`).join(''));
    const { stage } = stageOf(ws);
    expect(() => readStage(stage)).not.toThrow();
    chmodSync(stage, 0o755);
    const p = join(stage, 'manifest.json');
    chmodSync(p, 0o644);
    const m = JSON.parse(readFileSync(p, 'utf8'));
    m.files[0].line = 2;
    writeFileSync(p, JSON.stringify(m));
    expect(() => readStage(stage)).toThrow(StageError);
  });

  for (const [what, change] of tamper) {
    it(`refuses ${what}`, () => {
      const s = staged();
      change(s);
      expect(() => readStage(s)).toThrow(StageError);
    });
  }
});

// ---------- the staged scrub ----------

describe('scrub with a stage: findings map back to the original file and line; the canaries prove coverage', () => {
  function setup(files: Record<string, string | Buffer>): { ws: string; stage: string } {
    const ws = makeTempDir();
    for (const [n, c] of Object.entries(files)) writeIn(ws, n, typeof c === 'string' ? c : c.toString('latin1'));
    const { stage, out } = stageOf(ws);
    if (out.status !== 'ok') throw new Error(out.error);
    return { ws, stage };
  }

  for (const tool of ['betterleaks', 'gitleaks'] as const) {
    it(`${tool}: a finding in a staged file is written under the original path and line; the canaries are gone; no neutral name is written`, () => {
      const { stage } = setup({ 'src/a.js': `one\ntwo\nstripe = "${KEY_A}"\n`, 'b.js': 'b\n' });
      const a = one(stage, 'src/a.js');
      const { back, text } = okFindings(scrub(tool, stage, sarif(tool, [...canaries(tool, stage), hitFor(tool, stage, a.name, KEY_A)])));
      expect(back.findings).toHaveLength(1);
      expect(back.findings[0]).toMatchObject({ ruleId: `${SEC}${STRIPE_RULE}`, file: 'src/a.js', line: 3, endLine: 3, fpBy: 'region', severity: 'critical' });
      const hmac = createHmac('sha256', KEY).update(Buffer.concat([Buffer.from(`${tool}\0${SEC}${STRIPE_RULE}\0`), Buffer.from(KEY_A)])).digest('hex');
      expect(back.findings[0].fingerprint).toBe(`${SEC}${hmac}`);
      expect(text).not.toMatch(/f0000000\d/);
      expect(text).not.toContain('pipegen-canary');
    });

    it(`${tool}: the region is read from the staged copy (the bytes the scanner saw), not from the workspace`, () => {
      const { ws, stage } = setup({ 'a.js': `stripe = "${KEY_A}"\n` });
      const a = one(stage, 'a.js');
      const hits = [...canaries(tool, stage), hitFor(tool, stage, a.name, KEY_A)];
      const before = okFindings(scrub(tool, stage, sarif(tool, hits))).back.findings[0]?.fingerprint;
      writeFileSync(join(ws, 'a.js'), `stripe = "${KEY_B}"\n`);   // the checkout changes after staging: the fingerprint does not
      expect(okFindings(scrub(tool, stage, sarif(tool, hits))).back.findings[0]?.fingerprint).toBe(before);
    });

    it(`${tool}: a staged file whose canary was not reported was not scanned: a critical not-scanned finding over its lines, fingerprinted by the file's content`, () => {
      const { stage } = setup({ 'a.js': 'a\nb\nc\n', 'skipped.js': 'x\ny\n' });
      const s = one(stage, 'skipped.js');
      const { back, text } = okFindings(scrub(tool, stage, sarif(tool, canaries(tool, stage, [s.name]))));
      expect(back.findings).toHaveLength(1);
      const f = back.findings[0];
      expect(f).toMatchObject({ ruleId: `${SEC}not-scanned`, severity: 'critical', file: 'skipped.js', line: 1, endLine: 2, fpBy: 'file', uriUnmapped: false });
      const hmac = createHmac('sha256', KEY).update(`file\0${tool}\0${SEC}not-scanned\0${sha('x\ny\n')}`).digest('hex');
      expect(f.fingerprint).toBe(`${SEC}${hmac}`);
      expect(text).toMatch(/not scanned/);
      // the same unscanned file in the base: the same fingerprint; another content: another one
      const again = setup({ 'skipped.js': 'x\ny\n' });
      expect(okFindings(scrub(tool, again.stage, sarif(tool, []))).back.findings[0]?.fingerprint).toBe(f.fingerprint);
      const changed = setup({ 'skipped.js': 'x\nz\n' });
      expect(okFindings(scrub(tool, changed.stage, sarif(tool, []))).back.findings[0]?.fingerprint).not.toBe(f.fingerprint);
      // without a key (a fork): a position form over the file and its lines, so the added-line rule can judge it
      const fork = okFindings(scrub(tool, stage, sarif(tool, canaries(tool, stage, [s.name])), { fpKey: '', eventText: FORK })).back.findings[0];
      expect(fork).toMatchObject({ fpBy: 'nokey', file: 'skipped.js', line: 1, endLine: 2 });
    });

    it(`${tool}: a canary reported twice, or on another line, does not prove the file was read`, () => {
      const { stage } = setup({ 'a.js': 'a\n' });
      const a = one(stage, 'a.js');
      const c = hitFor(tool, stage, a.name, a.canary, 'pipegen-canary');
      expect(okFindings(scrub(tool, stage, sarif(tool, [c, c]))).back.findings.map((f) => f.ruleId)).toEqual([`${SEC}not-scanned`]);
      // on the canary line, but not the canary's bytes (a part of it): no proof either
      const part = { ...c, startColumn: c.startColumn + 15 };   // its hex digits only
      expect(okFindings(scrub(tool, stage, sarif(tool, [part]))).back.findings.map((f) => f.ruleId).sort()).toEqual([`${SEC}not-scanned`, `${SEC}pipegen-canary`].sort());
      const moved = { ...c, startLine: c.startLine - 1, endLine: c.endLine - 1 };
      const r = okFindings(scrub(tool, stage, sarif(tool, [moved]))).back.findings.map((f) => f.ruleId).sort();
      expect(r).toEqual([`${SEC}not-scanned`, `${SEC}pipegen-canary`].sort());
    });

    it(`${tool}: a canary-shaped line in the repo's own text is a real finding (P35), and the file's own canary still proves coverage`, () => {
      const fakeCanary = `pipegen-canary-${'0'.repeat(32)}`;
      const { stage } = setup({ 'a.js': `x\n${fakeCanary}\n` });
      const a = one(stage, 'a.js');
      const hits = [...canaries(tool, stage), hitFor(tool, stage, a.name, fakeCanary, 'pipegen-canary')];
      const { back } = okFindings(scrub(tool, stage, sarif(tool, hits)));
      expect(back.findings).toHaveLength(1);
      expect(back.findings[0]).toMatchObject({ ruleId: `${SEC}pipegen-canary`, file: 'a.js', line: 2 });
    });

    it(`${tool}: a finding whose file is not a name in the manifest is a tool error (exact neutral names only)`, () => {
      const { stage } = setup({ 'a.js': `stripe = "${KEY_A}"\n` });
      const a = one(stage, 'a.js');
      const hit = hitFor(tool, stage, a.name, KEY_A);
      for (const uri of ['f00000099.txt', `./${a.name}`, `${a.name}!x/y`, `/abs/${a.name}`, 'a.js', `sub/${a.name}`, a.name.replace('.txt', '.TXT')]) {
        const r = scrub(tool, stage, sarif(tool, [...canaries(tool, stage), { ...hit, uri }]));
        expect(r.status, uri).toBe('tool-error');
      }
    });

    it(`${tool}: a key in an overlap is found in two pieces and written once, at its original line; one in a later piece maps through its offset`, () => {
      const lines = Array.from({ length: 3750 }, (_, i) => `${String(i + 1).padStart(6, '0')}${'x'.repeat(73)}\n`);
      const { stage } = setup({ 'big.js': lines.join('') });
      const pieces = byPath(stage, 'big.js');
      // a line inside the overlap of pieces 1 and 2, and a line only in the last piece
      const p2 = pieces[1] as Entry;
      const overlapLine = p2.line + 3;
      const lastLine = 3740;
      lines[overlapLine - 1] = `stripe = "${KEY_A}"\n`;
      lines[lastLine - 1] = `stripe = "${KEY_B}"\n`;
      const again = setup({ 'big.js': lines.join('') });
      const ps = byPath(again.stage, 'big.js');
      const hits: Hit[] = [...canaries(tool, again.stage)];
      for (const p of ps) {
        const b = readFileSync(join(again.stage, 'files', p.name));
        if (b.includes(KEY_A)) hits.push(hitFor(tool, again.stage, p.name, KEY_A));
        if (b.includes(KEY_B)) hits.push(hitFor(tool, again.stage, p.name, KEY_B));
      }
      expect(hits.filter((h) => h.rule !== 'pipegen-canary').length).toBeGreaterThanOrEqual(3);   // KEY_A twice (overlap), KEY_B at least once
      const { back } = okFindings(scrub(tool, again.stage, sarif(tool, hits)));
      expect(back.findings.map((f) => [f.file, f.line]).sort()).toEqual([['big.js', overlapLine], ['big.js', lastLine]].sort());
      expect(ps.length).toBe(pieces.length);
    });

    it(`${tool}: a file whose name is not UTF-8 is found and told apart from its U+FFFD look-alike: both unmapped (a U+FFFD name is never trusted as a path, C1b R1-C2), each with its own line and fingerprint`, () => {
      const ws = makeTempDir();
      const raw = Buffer.concat([Buffer.from('k'), Buffer.from([0xff]), Buffer.from('.js')]);
      writeFileSync(Buffer.concat([Buffer.from(`${ws}/`), raw]), `x\nstripe = "${KEY_A}"\n`);
      writeFileSync(join(ws, 'k\uFFFD.js'), `stripe = "${KEY_B}"\n`);
      const { stage } = stageOf(ws);
      const a = one(stage, raw);
      const b = one(stage, Buffer.from('k\uFFFD.js'));
      const hits = [...canaries(tool, stage), hitFor(tool, stage, a.name, KEY_A), hitFor(tool, stage, b.name, KEY_B)];
      const { back } = okFindings(scrub(tool, stage, sarif(tool, hits)));
      expect(back.findings).toHaveLength(2);
      for (const f of back.findings) expect(f).toMatchObject({ uriUnmapped: true, fpBy: 'region' });
      expect(back.findings.every((f) => f.file === undefined)).toBe(true);
      expect(back.findings.map((f) => f.line).sort()).toEqual([1, 2]);
      const hmacOf = (k: string): string => `${SEC}${createHmac('sha256', KEY).update(Buffer.concat([Buffer.from(`${tool}\0${SEC}${STRIPE_RULE}\0`), Buffer.from(k)])).digest('hex')}`;
      expect(back.findings.find((f) => f.line === 2)?.fingerprint).toBe(hmacOf(KEY_A));   // the key of the raw-named file, read from its own staged copy
      expect(back.findings.find((f) => f.line === 1)?.fingerprint).toBe(hmacOf(KEY_B));
      // keyless: the place is a hash of the raw bytes of each name, so the two never share a fingerprint
      const fork = okFindings(scrub(tool, stage, sarif(tool, hits), { fpKey: '', eventText: FORK })).back.findings;
      expect(new Set(fork.map((f) => f.fingerprint)).size).toBe(2);
      const forkSame = okFindings(scrub(tool, stage, sarif(tool, [...canaries(tool, stage), { ...hitFor(tool, stage, a.name, KEY_A), startLine: 2 }, { ...hitFor(tool, stage, b.name, KEY_B), startLine: 2, endLine: 2 }]), { fpKey: '', eventText: FORK })).back.findings;
      expect(new Set(forkSame.map((f) => f.fingerprint)).size, 'same line in both files: still two places').toBe(2);
    });
  }

  for (const tool of ['betterleaks', 'gitleaks'] as const) {
    it(`${tool}: a whole-file finding (pkcs12-file: line 0, no columns) takes the file form (the original file's content), once per file even across pieces`, () => {
      const big = Buffer.alloc(200_000, 0x41);
      const { stage } = setup({ 'cert.pfx': big, 'id.p12': 'x\n' });
      const pieces = byPath(stage, 'cert.pfx');
      expect(pieces.length).toBeGreaterThan(1);
      const whole = (uri: string): Hit => ({ rule: 'pkcs12-file', uri, startLine: 0, startColumn: 0, endLine: 0, endColumn: 0 });
      const hits = [...canaries(tool, stage), ...pieces.map((p) => whole(p.name)), whole(one(stage, 'id.p12').name)];
      const { back } = okFindings(scrub(tool, stage, sarif(tool, hits)));
      expect(back.findings.map((f) => [f.file, f.fpBy, f.line]).sort()).toEqual([['cert.pfx', 'file', undefined], ['id.p12', 'file', undefined]]);
      const fp = back.findings.find((f) => f.file === 'id.p12')?.fingerprint;
      expect(fp).toBe(`${SEC}${createHmac('sha256', KEY).update(`file\0${tool}\0${SEC}pkcs12-file\0${sha('x\n')}`).digest('hex')}`);
    });
  }

  for (const tool of ['betterleaks', 'gitleaks'] as const) {
    it(`${tool}: fix round 1, I1: a key only the whole copy of a large file shows (a composite rule, a long multi-line key) is written at its original line; the whole copy's canary is required too`, () => {
      const rows = Array.from({ length: 3750 }, (_, i) => `${String(i + 1).padStart(6, '0')}${'x'.repeat(73)}\n`);
      rows[2999] = `stripe = "${KEY_A}"\n`;
      const { stage } = setup({ 'big.js': rows.join('') });
      const whole = byPath(stage, 'big.js').find((e) => e.piece === 0) as Entry;
      const hit = hitFor(tool, stage, whole.name, KEY_A);
      const { back } = okFindings(scrub(tool, stage, sarif(tool, [...canaries(tool, stage), hit])));
      expect(back.findings.map((f) => [f.file, f.line, f.ruleId])).toEqual([['big.js', 3000, `${SEC}${STRIPE_RULE}`]]);
      // the same key found in the whole copy and in a piece: one finding
      const piece = byPath(stage, 'big.js').find((e) => e.piece >= 1 && readFileSync(join(stage, 'files', e.name)).includes(KEY_A)) as Entry;
      expect(okFindings(scrub(tool, stage, sarif(tool, [...canaries(tool, stage), hit, hitFor(tool, stage, piece.name, KEY_A)]))).back.findings).toHaveLength(1);
      // without the whole copy's canary: not scanned, over the whole file
      const nc = okFindings(scrub(tool, stage, sarif(tool, canaries(tool, stage, [whole.name])))).back.findings;
      expect(nc.map((f) => [f.ruleId, f.file, f.line, f.endLine])).toEqual([[`${SEC}not-scanned`, 'big.js', 1, 3750]]);
    });

    it(`${tool}: two rules on the same bytes stay two findings (the dedupe key holds the rule)`, () => {
      const { stage } = setup({ 'a.js': `stripe = "${KEY_A}"\n` });
      const a = one(stage, 'a.js');
      const h = hitFor(tool, stage, a.name, KEY_A);
      const { back } = okFindings(scrub(tool, stage, sarif(tool, [...canaries(tool, stage), h, { ...h, rule: 'generic-api-key' }])));
      expect(back.findings.map((f) => f.ruleId).sort()).toEqual([`${SEC}generic-api-key`, `${SEC}${STRIPE_RULE}`].sort());
    });

    it(`${tool}: a staged scan has no "completeness not provable" note (the canaries prove it); a name that is not UTF-8 carries a display form, outside the fingerprint`, () => {
      const ws = makeTempDir();
      const raw = Buffer.concat([Buffer.from('k'), Buffer.from([0xff]), Buffer.from('.js')]);
      writeFileSync(Buffer.concat([Buffer.from(`${ws}/`), raw]), `stripe = "${KEY_A}"\n`);
      writeIn(ws, 'plain.js', `stripe = "${KEY_A}"\n`);
      const { stage } = stageOf(ws);
      const hits = [...canaries(tool, stage), hitFor(tool, stage, one(stage, raw).name, KEY_A), hitFor(tool, stage, one(stage, 'plain.js').name, KEY_A)];
      const { back, text } = okFindings(scrub(tool, stage, sarif(tool, hits)));
      expect(back.notes.some((n) => /completeness not provable/.test(n))).toBe(false);
      const odd = back.findings.find((f) => f.file === undefined);
      expect(odd?.displayPath).toBe('k\\xff.js');
      expect(odd?.uriUnmapped).toBe(true);
      expect(back.findings.find((f) => f.file === 'plain.js')?.displayPath).toBeUndefined();
      // the same bytes give the same fingerprint as in a plainly named file: the display form is not part of it
      expect(odd?.fingerprint).toBe(back.findings.find((f) => f.file === 'plain.js')?.fingerprint);
      expect(text).toContain('pipegenDisplayPath');
    });
  }

  it('gitleaks in the whole copy of a large file (measured live): past its first chunk the +1 column shift is gone, so the canary there counts at either column; a finding only the whole copy has takes the line form; one a piece also has is kept once, from the piece', () => {
    const rows = Array.from({ length: 3750 }, (_, i) => `${String(i + 1).padStart(6, '0')}${'x'.repeat(73)}\n`);
    rows[2999] = `stripe = "${KEY_A}"\n`;
    rows[99] = `stripe = "${KEY_B}"\n`;
    const { stage } = setup({ 'big.js': rows.join('') });
    const whole = byPath(stage, 'big.js').find((e) => e.piece === 0) as Entry;
    const unshift = (h: Hit): Hit => ({ ...h, startColumn: h.startColumn - 1, endColumn: h.endColumn - 1 });
    const cs = canaries('gitleaks', stage).map((h) => (h.uri === whole.name ? unshift(h) : h));
    const r = okFindings(scrub('gitleaks', stage, sarif('gitleaks', cs))).back.findings;
    expect(r).toEqual([]);   // every entry proved, the whole copy by its canary line at the unshifted columns
    const wholeOnly = unshift(hitFor('gitleaks', stage, whole.name, KEY_A));
    const piece = byPath(stage, 'big.js').find((e) => e.piece >= 1 && readFileSync(join(stage, 'files', e.name)).includes(KEY_B)) as Entry;
    const both = [unshift(hitFor('gitleaks', stage, whole.name, KEY_B)), hitFor('gitleaks', stage, piece.name, KEY_B)];
    const f = okFindings(scrub('gitleaks', stage, sarif('gitleaks', [...cs, wholeOnly, ...both]))).back.findings;
    expect(f.map((x) => [x.line, x.fpBy]).sort()).toEqual([[100, 'region'], [3000, 'line']]);
  });

  it('a stage is only for the secrets tools, and the step entry (scrubFile) refuses a secrets result without one', () => {
    const { stage } = setup({ 'a.js': 'a\n' });
    expect(scrubBytes(Buffer.from(sarif('betterleaks', [])), { tool: 'semgrep', format: 'sarif', fpKey: KEY, eventText: PUSH, stage }).status).toBe('tool-error');
    const dir = makeTempDir();
    const raw = join(dir, 'pipegen-raw', 'pipegen-out-secrets', 'gitleaks.sarif');
    writeIn(dir, 'pipegen-raw/pipegen-out-secrets/gitleaks.sarif', sarif('gitleaks', []));
    const out = join(dir, 'pipegen-out', 'pipegen-out-secrets', 'gitleaks.sarif');
    const r = scrubFile({ tool: 'gitleaks', format: 'sarif', artifact: 'pipegen-out-secrets', raw, out, fpKey: KEY, eventText: PUSH, workspace: dir });
    expect(r.status).toBe('tool-error');
    expect(r.error).toMatch(/stag/);
    expect(existsSync(out)).toBe(false);
    const staged = scrubFile({ tool: 'gitleaks', format: 'sarif', artifact: 'pipegen-out-secrets', raw, out, fpKey: KEY, eventText: PUSH, stage });
    expect(staged.status, staged.error).toBe('ok');
  });

  it('a stage folder that fails its check is a tool error of the scrub, with no finding', () => {
    const { stage } = setup({ 'a.js': 'a\n' });
    chmodSync(join(stage, 'files'), 0o755);
    writeFileSync(join(stage, 'files', 'extra.txt'), 'x');
    const r = scrub('betterleaks', stage, sarif('betterleaks', canaries('betterleaks', stage)));
    expect(r.status).toBe('tool-error');
  });

  it('the canary line of a staged file is its last line (writtenCanaryLine), and stays so for pieces', () => {
    const { stage } = setup({ 'a.js': 'a\nb' });
    const a = one(stage, 'a.js');
    expect(writtenCanaryLine(readFileSync(join(stage, 'files', a.name)))).toBe(5);
    expect(lstatSync(join(stage, 'files', a.name)).isFile()).toBe(true);
  });
});
