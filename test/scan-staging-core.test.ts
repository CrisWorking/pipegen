// C1c, part 1: the pure scan-staging core shared by the audit's secret pass (src/ai/redact.ts, rulings P30-P38) and the gate's
// staged secrets scan (gate/src/stage.ts). Written first (strict test-first).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import * as core from '../src/ai/scan-staging.js';
import * as redactMod from '../src/ai/redact.js';

const root = resolve(import.meta.dirname, '..');

/** Every source file `entry` pulls in (npm packages left out). */
async function graph(entry: string): Promise<string[]> {
  const r = await build({ entryPoints: [resolve(root, entry)], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
  return Object.keys(r.metafile.inputs).sort();
}

describe('scan-staging core: a leaf', () => {
  it('module graph: scan-staging.ts imports nothing (no node: module, no npm package, no other source file)', async () => {
    const r = await build({ entryPoints: [resolve(root, 'src/ai/scan-staging.ts')], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
    expect(Object.keys(r.metafile.inputs)).toEqual(['src/ai/scan-staging.ts']);
    expect(r.metafile.inputs['src/ai/scan-staging.ts'].imports).toEqual([]);
    const text = readFileSync(resolve(root, 'src/ai/scan-staging.ts'), 'utf8');
    expect(text).not.toMatch(/^\s*import\s/m);
    expect(text).not.toMatch(/child_process|picomatch|limits\.js/);
  });

  it('redact.ts uses the core: it imports scan-staging.ts and re-exports the same SCAN_CHUNK_SAFE_BYTES', async () => {
    expect(await graph('src/ai/redact.ts')).toContain('src/ai/scan-staging.ts');
    expect(redactMod.SCAN_CHUNK_SAFE_BYTES).toBe(core.SCAN_CHUNK_SAFE_BYTES);
    const text = readFileSync(resolve(root, 'src/ai/redact.ts'), 'utf8');
    // the moved definitions are not kept as a second copy in redact.ts
    for (const name of ['SCAN_PREFIX', 'CANARY_RULE', 'LATE_MAGIC', 'SCAN_CHUNK_SAFE_BYTES']) expect(text, name).not.toMatch(new RegExp(`^(?:export )?const ${name} =`, 'm'));
    for (const name of ['asScanned', 'canaryLine', 'newCanary']) expect(text, name).not.toMatch(new RegExp(`^const ${name} = `, 'm'));
    expect(text, 'scannersWouldSkip').not.toMatch(/^function scannersWouldSkip\(/m);
  });
});

describe('scan-staging core: the audit forms, unchanged', () => {
  it('SCAN_PREFIX is one empty line; the canary rule and its token shape', () => {
    expect(core.SCAN_PREFIX).toBe('\n');
    expect(core.PREFIX_LINES).toBe(1);
    expect(core.CANARY_RULE).toBe('pipegen-canary');
    const c = core.newCanary();
    expect(c).toMatch(/^pipegen-canary-[0-9a-f]{32}$/);
    expect(core.isCanary(c)).toBe(true);
    expect(core.newCanary()).not.toBe(c);
    for (const bad of ['pipegen-canary-' + '0'.repeat(31), 'pipegen-canary-' + 'G'.repeat(32), ` ${c}`, `${c}\n`, 'x']) expect(core.isCanary(bad), bad).toBe(false);
    expect(core.CANARY_LENGTH).toBe(c.length);
  });

  it('CANARY_RULE_TOML is the audit config\'s canary rule (data/gitleaks-bundle.toml), id, regex and keyword', () => {
    const bundle = readFileSync(resolve(root, 'data/gitleaks-bundle.toml'), 'utf8');
    const rule = bundle.slice(bundle.indexOf('id = "pipegen-canary"'));
    for (const line of core.CANARY_RULE_TOML.split('\n').filter((l) => /^(?:id|regex|keywords) = /.test(l))) expect(rule, line).toContain(line);
    expect(core.CANARY_RULE_TOML.startsWith('[[rules]]\n')).toBe(true);
  });

  it('asScanned: prefix, content, a newline when the content has none at its end, a blank line, the canary line', () => {
    expect(core.asScanned('a', 'C')).toBe('\na\n\nC\n');
    expect(core.asScanned('a\n', 'C')).toBe('\na\n\nC\n');
    expect(core.asScanned('', 'C')).toBe('\n\nC\n');
    expect(core.canaryLine(core.asScanned('a\nb', 'C'))).toBe(4);   // unprefixed numbering (the audit's)
  });

  it('asScannedBytes is asScanned on bytes, for any bytes (not only UTF-8)', () => {
    for (const s of ['', 'a', 'a\n', 'é ü\r\n', 'x\n\n']) expect(Buffer.from(core.asScannedBytes(Buffer.from(s), 'C')).toString('utf8'), JSON.stringify(s)).toBe(core.asScanned(s, 'C'));
    const raw = Buffer.from([0xff, 0x00, 0x1f, 0x8b]);
    expect(Buffer.from(core.asScannedBytes(raw, 'C'))).toEqual(Buffer.concat([Buffer.from('\n'), raw, Buffer.from('\n\nC\n')]));
    // the line the canary is on, in the file as written (prefix line counted): its last line
    expect(core.writtenCanaryLine(core.asScannedBytes(Buffer.from('a\nb'), 'C'))).toBe(5);
    expect(core.writtenCanaryLine(core.asScannedBytes(Buffer.from(''), 'C'))).toBe(3);
  });

  it('SCAN_CHUNK_SAFE_BYTES and the late magic numbers (P36, P38, Task 7 R1) as the audit had them', () => {
    expect(core.SCAN_CHUNK_SAFE_BYTES).toBe(90_000);
    const at = (n: number, magic: string): string => `${'a'.repeat(n)}${magic}${'b'.repeat(10)}`;
    expect(core.scannersWouldSkip(at(257, 'ustar'))).toBe(true);
    expect(core.scannersWouldSkip(at(256, 'ustar'))).toBe(false);
    expect(core.scannersWouldSkip(at(128, 'DICM'))).toBe(true);
    for (const n of [32769, 34817, 36865]) expect(core.scannersWouldSkip(at(n, 'CD001')), String(n)).toBe(true);
    expect(core.scannersWouldSkip(Buffer.from(at(257, 'ustar')))).toBe(true);
    expect(core.scannersWouldSkip('plain text')).toBe(false);
  });

  it('SCAN_OVERHEAD_BYTES is the most asScannedBytes adds, so a piece of PIECE_BYTES is written within SCAN_CHUNK_SAFE_BYTES', () => {
    const worst = core.asScannedBytes(Buffer.alloc(core.PIECE_BYTES, 0x61), core.newCanary());
    expect(worst.length).toBe(core.PIECE_BYTES + core.SCAN_OVERHEAD_BYTES);
    expect(worst.length).toBeLessThanOrEqual(core.SCAN_CHUNK_SAFE_BYTES);
    expect(core.PIECE_BYTES + core.SCAN_OVERHEAD_BYTES).toBe(core.SCAN_CHUNK_SAFE_BYTES);
  });
});

describe('scan-staging core: pieces of a large file (P36 for the gate)', () => {
  const lines = (n: number, width: number): Buffer => Buffer.from(Array.from({ length: n }, (_, i) => `${String(i + 1).padStart(6, '0')}${'x'.repeat(width - 7)}\n`).join(''));
  const written = (p: core.Piece): number => p.length + core.SCAN_OVERHEAD_BYTES;

  it('a file that fits is one piece: offset 0, line 1, column 0, the whole length', () => {
    const b = lines(10, 40);
    expect(core.planPieces(b)).toEqual([{ offset: 0, length: b.length, line: 1, column: 0 }]);
    expect(core.planPieces(Buffer.alloc(0))).toEqual([{ offset: 0, length: 0, line: 1, column: 0 }]);
    expect(core.planPieces(Buffer.alloc(core.PIECE_BYTES, 0x61))).toHaveLength(1);
    expect(core.planPieces(Buffer.alloc(core.PIECE_BYTES + 1, 0x61)).length).toBeGreaterThan(1);
  });

  it('the overlap is at least 8 KiB (the safe floor); PIECE_OVERLAP_BYTES is what pieces share', () => {
    expect(core.PIECE_OVERLAP_BYTES).toBeGreaterThanOrEqual(8 * 1024);
    expect(core.PIECE_OVERLAP_BYTES).toBeLessThan(core.PIECE_BYTES / 2);
  });

  it('a 300 KB file of short lines: every piece written within the chunk, cuts on line ends, pieces overlap by at least the overlap, together they cover the file', () => {
    const b = lines(3750, 80);   // 300,000 bytes
    const ps = core.planPieces(b);
    expect(ps.length).toBeGreaterThan(3);
    expect(ps[0].offset).toBe(0);
    expect(ps.at(-1)?.offset ?? 0 + (ps.at(-1)?.length ?? 0)).toBeLessThanOrEqual(b.length);
    const last = ps.at(-1) as core.Piece;
    expect(last.offset + last.length).toBe(b.length);
    for (const [i, p] of ps.entries()) {
      expect(written(p), String(i)).toBeLessThanOrEqual(core.SCAN_CHUNK_SAFE_BYTES);
      expect(p.offset === 0 || b[p.offset - 1] === 0x0a, `piece ${i} starts at a line start`).toBe(true);
      expect(p.offset + p.length === b.length || b[p.offset + p.length - 1] === 0x0a, `piece ${i} ends at a line end`).toBe(true);
      expect(p.column).toBe(0);
      // line: the 1-based line of its first byte
      expect(p.line).toBe(b.subarray(0, p.offset).filter((c) => c === 0x0a).length + 1);
      if (i > 0) {
        const prev = ps[i - 1] as core.Piece;
        expect(prev.offset + prev.length - p.offset, `overlap ${i}`).toBeGreaterThanOrEqual(core.PIECE_OVERLAP_BYTES);
        expect(p.offset).toBeGreaterThan(prev.offset);
      }
    }
  });

  it('one long line (no newline at all) is cut mid-line; the column of each piece start is its byte offset in that line', () => {
    const b = Buffer.alloc(250_000, 0x61);
    const ps = core.planPieces(b);
    expect(ps.length).toBeGreaterThan(2);
    for (const p of ps) {
      expect(p.line).toBe(1);
      expect(p.column).toBe(p.offset);
      expect(written(p)).toBeLessThanOrEqual(core.SCAN_CHUNK_SAFE_BYTES);
    }
    expect((ps.at(-1) as core.Piece).offset + (ps.at(-1) as core.Piece).length).toBe(b.length);
  });

  it('brute force, small sizes: every window of at most the overlap lies inside one piece, every line no longer than a piece lies inside one piece, pieces progress', () => {
    let seed = 7;
    const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
    for (let round = 0; round < 300; round++) {
      const size = 1 + rnd(600);
      const b = Buffer.alloc(size);
      for (let i = 0; i < size; i++) b[i] = rnd(9) === 0 ? 0x0a : 0x61 + rnd(3);
      const pieceBytes = 20 + rnd(60);
      const overlap = 1 + rnd(Math.floor(pieceBytes / 2) - 1);
      const ps = core.planPieces(b, { pieceBytes, overlap });
      const at = `round ${round} size ${size} piece ${pieceBytes} overlap ${overlap}`;
      const inside = (a: number, e: number): boolean => ps.some((p) => p.offset <= a && e <= p.offset + p.length);
      for (const p of ps) expect(p.length, at).toBeLessThanOrEqual(pieceBytes);
      for (let a = 0; a < size; a++) for (let e = a + 1; e <= Math.min(size, a + overlap); e++) expect(inside(a, e), `${at}: window ${a}..${e}`).toBe(true);
      let start = 0;
      for (let i = 0; i <= size; i++) {
        if (i === size || b[i] === 0x0a) {
          const end = Math.min(size, i + 1);
          if (end - start <= pieceBytes - overlap) expect(inside(start, end), `${at}: line ${start}..${end}`).toBe(true);
          start = i + 1;
        }
      }
      for (const p of ps) {
        expect(p.line, at).toBe(b.subarray(0, p.offset).filter((c) => c === 0x0a).length + 1);
        const nl = b.lastIndexOf(0x0a, p.offset - 1);
        expect(p.column, at).toBe(p.offset === 0 ? 0 : p.offset - (nl < 0 || nl >= p.offset ? 0 : nl + 1));
      }
    }
  });

  it('pieceLines: a line of the piece as written maps to the line of the original file (the prefix line and the canary lines fold onto the piece)', () => {
    const p: core.Piece = { offset: 1000, length: 500, line: 40, column: 0 };
    expect(core.originalLine(p, 2, 10)).toBe(40);   // the first content line
    expect(core.originalLine(p, 7, 10)).toBe(45);
    expect(core.originalLine(p, 1, 10)).toBe(40);   // on the prefix line: the piece's first line
    expect(core.originalLine(p, 99, 10)).toBe(49);  // past the content (the blank and canary lines): its last line
  });
});
