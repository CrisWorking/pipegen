// Plan E E0a fix round 1 (review-E0a.md C1, I1-I3, M1, M2, M4): the review's repros p1-p9 as tests, the guard that keeps the unsafe
// unscannedExcerpt out of production code, and the differential test of the two redact-core helpers excerpt.ts copies.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { knownValueScrubber, redact } from '../src/ai/redact.js';
import { SecretVault } from '../src/create/secrets.js';
import { indentCols, keyMarkerFrom, unscannedExcerpt } from '../src/proof/excerpt.js';
import { repoFiles, root } from './helpers/repo-files.js';
import { fake } from './helpers/secret-repo.js';

const V = 'Qz7mK2pW9xLr4TbN8vYc3HsJ6dFa1GeU';
// built at runtime: no secret-looking literal is committed (test/no-secret-literals.test.ts)
const SKT = ['sk', '_test_'].join('');
const ESC = '\u001b';
const vaultScrub = (value = V) => {
  const v = new SecretVault();
  v.set('MY_KEY', value);
  return v;
};
/** Every run of 9 or more of the value's characters in `out` (the ruling's measure: none may show). */
const runs9 = (out: string, value = V) => Array.from({ length: value.length - 8 }, (_, i) => value.slice(i, i + 9)).filter((w) => out.includes(w));
const pad = (n: number) => Array.from({ length: n }, (_, i) => `step ${i} ok`);
const excerpt = (log: string, scrub: (t: string) => string, maxLogChars?: number) => unscannedExcerpt(log, scrub, maxLogChars === undefined ? {} : { maxLogChars }).join('\n');

describe('excerpt fix round 1: values that lose a character to an escape (C1)', () => {
  it('excerpt r1 C1: a value whose character an escape sequence ate shows no 9-character run (p3)', () => {
    const v = vaultScrub();
    const cases = [
      ['L1 CSI final eats one char', ['ok', `Error: v=${V.slice(0, 9)}${ESC}[${V.slice(9)}`, 'ok']],
      ['L2 CSI before the value eats its first char', ['ok', `Error: token ${ESC}[${V}`, 'ok']],
      ['L3 CSI with parameters eats two chars', ['ok', `Error: token ${V.slice(0, 5)}${ESC}[1;${V.slice(5)}`, 'ok']],
    ] as const;
    for (const [name, lines] of cases) expect(runs9(excerpt(lines.join('\n'), v.scrubber())), name).toEqual([]);
    // L4: an SGR that eats a value's `<digits>m`
    const l4 = 'Ab31mK2pW9xLr4TbN8vYc3HsJ';
    expect(runs9(excerpt(['ok', `Error: token Ab${ESC}[31mK2pW9xLr4TbN8vYc3HsJ`, 'ok'].join('\n'), knownValueScrubber([l4])), l4), 'L4').toEqual([]);
    // L5: a placeholder
    const ph = 'pipegen-placeholder-STRIPE_SECRET_KEY';
    expect(runs9(excerpt(['ok', `Error: key=${ph.slice(0, 8)}${ESC}[${ph.slice(8)}`, 'ok'].join('\n'), knownValueScrubber([ph])), ph), 'L5').toEqual([]);
    v.wipe();
  });
});

describe('excerpt fix round 1: values split over lines (I1) and the tag filter (I3)', () => {
  it('excerpt r1 I1: a split value with an invisible character or an eaten character shows no piece at a window edge or next to a dropped line (p1 B/C, p2 K)', () => {
    const v = vaultScrub();
    const cases = [
      ['B split + ZWSP at the window edge', [...pad(10), 'Error: boom', ...pad(4), `value=${V.slice(0, 8)}\u200b${V.slice(8, 16)}`, `${V.slice(16)} tail`, ...pad(10)]],
      ['C split + SHY at the window edge', [...pad(10), 'Error: boom', ...pad(4), `value=${V.slice(0, 16)}`, `${V.slice(16, 24)}\u00ad${V.slice(24)} tail`, ...pad(10)]],
      ['K dropped line ate a char, split', ['ok', `Error: v=${V.slice(0, 10)}${ESC}${V.slice(10, 16)}`, `${V.slice(16)} tail`, 'ok']],
      ['K5 CSI ate a char, split', ['ok', `Error: v=${V.slice(0, 9)}${ESC}[${V.slice(9, 16)}`, `${V.slice(16)} tail`, 'ok']],
    ] as const;
    for (const [name, lines] of cases) expect(runs9(excerpt(lines.join('\n'), v.scrubber())), name).toEqual([]);
    v.wipe();
  });

  it('excerpt r1 I3: two value spans that each swallow one end of a hidden line never show its middle (p9)', () => {
    const v = vaultScrub();
    const mid = 'HIDDENMIDDLEbodyAAAABBBBCCCCDDDD';
    const log = ['Error: a', `ok ${V.slice(0, 12)}`, `${V.slice(12)}${mid}${V.slice(0, 12)}${ESC}(B`, `${V.slice(12)} ok`, 'next'].join('\n');
    expect(excerpt(log, v.scrubber())).not.toContain('HIDDENMIDDLE');
    v.wipe();
  });
});

describe('excerpt fix round 1: an open block and colour codes', () => {
  it('excerpt r1: a line that starts with a colour code does not count as unsure indentation (it ends an open block like any line)', () => {
    const out = excerpt([`${ESC}(Bwarn thing`, `${ESC}[31mError: Invalid API key provided${ESC}[0m`, 'next'].join('\n'), (t) => t);
    expect(out.split('\n')).toEqual(['Error: Invalid API key provided', 'next']);
  });
});

describe('excerpt fix round 1: a key open across a cut (I2)', () => {
  it('excerpt r1 I2: after a cut, a BEGIN with an insertion in the cut-off head hides the tail up to END, interleaved lines or not (p4)', () => {
    let s = 7;
    const rnd = () => { s = (s * 1103515245 + 12345) % 2147483648; return s / 2147483648; };
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const body = Array.from({ length: 120 }, () => Array.from({ length: 64 }, () => B64[Math.floor(rnd() * 64)]).join(''));
    const begin = fake.keyBegin();
    const at = begin.lastIndexOf(' ');
    for (const beginLine of [begin, `${begin.slice(0, at)}\u200b${begin.slice(at)}`, `${begin.slice(0, at)}${ESC}${begin.slice(at)}`]) {
      const head = ['setup ok', 'Error: signing failed', beginLine, ...body.slice(0, 10)];
      const cutAt = head.join('\n').length + 1;
      const tail = [...body.slice(10)];
      tail.splice(3, 0, '[worker-2] Downloading dependencies ...');
      const all = [...head, ...tail, fake.keyEnd(), 'Error: key rejected', 'done'].join('\n');
      for (const out of [excerpt(all, (t) => t, all.length - cutAt), excerpt(all, (t) => t)]) {
        expect(body.filter((l) => out.includes(l.slice(10, 26))), JSON.stringify(beginLine)).toEqual([]);
      }
    }
  });
});

describe('excerpt fix round 1: rules the mutation run showed untested', () => {
  it('excerpt r1: the value passes catch a value an escape cut in the middle of a messy line, also when the line shows another copy', () => {
    const v = vaultScrub();
    // the value is in the middle (no edge rule applies): only the reading that keeps the CSI's final byte holds it whole
    expect(runs9(excerpt(['ok', `Error: token ${ESC}[${V} (401) retry`, 'ok'].join('\n'), v.scrubber())), 'mid').toEqual([]);
    // the line also shows the value whole once, so its shown form has a hit too: a messy line is hidden all the same
    expect(runs9(excerpt(['ok', `key ${V} and token ${ESC}[${V} (401) retry`, 'ok'].join('\n'), v.scrubber())), 'both').toEqual([]);
    v.wipe();
  });

  it('excerpt r1: a value split over lines with a tab inside one piece (not messy) is found by the value passes', () => {
    const v = vaultScrub();
    // the error window ends on the tab line: step 6 sees only that piece, so only the value pass can tell
    const out = excerpt([...pad(3), 'Error: x', ...pad(4), `value=${V.slice(0, 6)}\t${V.slice(6, 16)}`, `${V.slice(16)} tail`, ...pad(10)].join('\n'), v.scrubber());
    expect(runs9(out)).toEqual([]);
    expect(out.includes('pW9xLr4T')).toBe(false);
    v.wipe();
  });

  it('excerpt r1: a merged line built from a hidden line goes even when its first line is shown (p9, short first piece)', () => {
    const v = vaultScrub();
    const mid = 'HIDDENMIDDLEbodyAAAABBBBCCCCDDDD';
    const log = ['Error: a', `ok ${V.slice(0, 6)}`, `${V.slice(6)}${mid}${V.slice(0, 12)}${ESC}(B`, `${V.slice(12)} ok`, 'next'].join('\n');
    expect(excerpt(log, v.scrubber())).not.toContain('HIDDENMIDDLE');
    v.wipe();
  });

  it('excerpt r1: a head that opened a key (in a reading) hides a non-armor tail up to END, or to the end of the log with none', () => {
    const begin = fake.keyBegin();
    const at = begin.lastIndexOf(' ');
    const broken = `${begin.slice(0, at)}${ESC}${begin.slice(at)}`;
    const body = Array.from({ length: 80 }, (_, i) => `> ${fake.keyBody()}${String(i).padStart(2, '0')}`);
    for (const end of [[fake.keyEnd()], [] as string[]]) {
      const head = ['setup ok', broken, ...body.slice(0, 5)];
      const all = [...head, ...body.slice(5), ...end, 'Error: key rejected', 'done'].join('\n');
      const out = excerpt(all, (t) => t, all.length - head.join('\n').length - 1);
      expect(body.filter((b) => out.includes(b.slice(2))), `END ${end.length}`).toEqual([]);
    }
  });

  it('excerpt r1: 200k vault fuzz cases: a messy pair of lines each holding a piece of a split value hides both', () => {
    const cases: [string, string[]][] = [
      // seed 57508 case 37529: a CSI at the end of one piece, invisibles in the other
      ['8FC7SCTW-RWy/kO', ['url=postgres:/' + '/app:8FC7SCTW-RWy/' + `${ESC}[P`, '\t\ufe0fkO@db.internal:5432/a\ufeffpp']],
      // seed 57510 case 52778: an OSC payload between the pieces
      ['b4ZZbkQ7dxQ3g4aFmklcN', ['url=postgres:/' + '/app:b4ZZbkQ7dx', `  ${ESC}]0y+LwFWVtn\u0007;IdXA7IPUk\u0007  Q3g4aFmklcN@db.internal:5432/app`]],
      // seed 57510 case 60159: an unterminated C1 OSC in one piece, a tab splitting the other (the edge token counts without the tab)
      [`${SKT}66O4FXMxUaSu=3au4Fw-7IKNM5INAb`, [`${SKT}66O4FXMxUa\u009d+JQYIcmSu%3D3a`, 'u4Fw-7I\tKNM5INAb"']],
    ];
    for (const [value, lines] of cases) {
      const v = vaultScrub(value);
      const out = excerpt(['a step 0 ok', ...lines, 'c step 0 ok', 'Error: request failed'].join('\n'), v.scrubber());
      expect(Array.from({ length: value.length - 7 }, (_, i) => value.slice(i, i + 8)).filter((w) => out.includes(w)), value).toEqual([]);
      v.wipe();
    }
  });
});

describe('excerpt fix round 1: linear time (M2)', () => {
  const MAX = 4 * 1024 * 1024;
  it('excerpt r1 M2: dropped lines full of `[`, and a tab staircase before SGR lines, stay linear (p7, p5)', () => {
    const line = `${'['.repeat(4090)}${ESC}`;
    const brackets = Array(Math.floor(MAX / (line.length + 1))).fill(line).join('\n');
    let t0 = performance.now();
    unscannedExcerpt(brackets, (x) => x);
    const tBrackets = performance.now() - t0;
    const stair: string[] = [];
    for (let i = 0, used = 0; ; i++) {
      const l = `${'\t'.repeat(Math.floor(i / 8))}${' '.repeat(i % 8)}x`;
      if (used + l.length + 1 > MAX / 2) break;
      stair.push(l);
      used += l.length + 1;
    }
    const staircase = [...stair, ...Array(Math.floor((MAX - stair.join('\n').length) / 5)).fill(`${ESC}[0m`)].join('\n').slice(0, MAX);
    t0 = performance.now();
    unscannedExcerpt(staircase, (x) => x);
    const tStair = performance.now() - t0;
    expect({ tBrackets: tBrackets < 8000, tStair: tStair < 8000 }, `${Math.round(tBrackets)} ms, ${Math.round(tStair)} ms`).toEqual({ tBrackets: true, tStair: true });
  }, 60_000);
});

describe('excerpt fix round 1: guards (M1, M4)', () => {
  it('excerpt r1 M1: no src/ file but excerpt.ts names unscannedExcerpt (it is not safe to send)', () => {
    const name = ['unscanned', 'Excerpt'].join('');
    const hits = repoFiles('src').filter((f) => f !== 'src/proof/excerpt.ts' && readFileSync(join(root, f), 'utf8').includes(name));
    expect(hits).toEqual([]);
  });

  it('excerpt r1 M4: the copied key-marker and indentation helpers decide like redact on a shared table', () => {
    const kinds = ['RSA', 'EC', 'OPENSSH', '', 'ENCRYPTED', 'PGP', 'rsa', 'RSA2', 'R S A', 'DSA'];
    const tails = ['PRIVATE KEY', 'PRIVATE KEY BLOCK', 'PUBLIC KEY', 'PRIVATE  KEY', 'PRIVATE KEYS', 'private key'];
    const lines: string[] = [];
    for (const k of kinds) for (const t of tails) for (const dashes of ['-----', '----']) {
      for (const kind of ['BEGIN', 'END']) lines.push(`${dashes}${kind} ${k === '' ? '' : `${k} `}${t}${dashes}`, `x ${dashes}${kind} ${k} ${t}${dashes} y`);
    }
    for (const line of lines) {
      // redact drops the line after a BEGIN (a key continuation) exactly when it found a BEGIN with no END after it
      const opens = keyMarkerFrom(line, 'BEGIN', 0) !== null;
      const closesAfter = opens && keyMarkerFrom(line, 'END', (keyMarkerFrom(line, 'BEGIN', 0) as { end: number }).end) !== null;
      const dropped = !redact(`${line}\nzzcontinuation`).includes('zzcontinuation');
      expect(dropped, JSON.stringify(line)).toBe(opens && !closesAfter);
    }
    // redact hides a line after `name:` (a secret name, empty value) exactly when it is indented more, in redact's columns
    const key = ['pass', 'word'].join('');
    const indents = ['', ' ', '  ', '\t', ' \t', '\t ', '       ', '        ', '\t\t', '  \t', '         '];
    for (const a of indents) for (const b of indents) {
      const hidden = !redact(`${a}${key}:\n${b}zzvalue`).includes('zzvalue');
      expect(hidden, JSON.stringify([a, b])).toBe(indentCols(b) > indentCols(a));
    }
  });
});
