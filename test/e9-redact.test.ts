// E9 (carry E0a; DECISIONS #112 "known limit until E9"): two Plan A redact gaps in the gate-bundled core (src/ai/redact-core.ts), which
// the E0a fuzz measured (about 95 % of multi-line .env values and every next-line-host connection string leaked even in clean text):
// - a quoted value that goes on over the next lines (`.env` `KEY="…` up to a line holding the closing quote, a YAML quoted scalar,
//   Python/TOML triple quotes) is hidden up to its closing quote, whatever the indentation of those lines;
// - a connection string whose authority ends the line with `user:password` and no `@`, when the next line's first word holds the `@`
//   and the host: the password on the first line and the part of the next line's word before that `@` are hidden.
// Also the two helpers excerpt.ts copied are exported and used from the core (no copy left). Written first.
import { describe, expect, it } from 'vitest';
import * as core from '../src/ai/redact-core.js';
import { redact } from '../src/ai/redact.js';
import { indentCols, keyMarkerFrom, unscannedExcerpt } from '../src/proof/excerpt.js';

const R = '[REDACTED]';
// secret-bearing names, built at runtime (test/no-secret-literals.test.ts)
const PW = ['DB_PASS', 'WORD'].join('');
const KEY = ['API_TO', 'KEN'].join('');
const PK = ['PRIVATE', '_KEY'].join('');
const VAL = 'Zq81mVx0PLk2wYr7Ct5n';   // a 20-character run the leak check looks for
const MARK = (end: boolean) => ['-----', end ? 'END' : 'BEGIN', ' RSA PRIVATE', ' KEY-----'].join('');
const PG = ['url=postgres:', '//app:'].join('');

describe('E9: the Plan A redact gaps (carry E0a)', () => {
  it('redact: a .env value over several lines is hidden up to its closing quote, also lines at the same indent', () => {
    const text = `A=1\n${PW}="${VAL}\n${VAL}x\n${VAL}y"\nB=2`;
    const out = redact(text);
    expect(out).not.toContain(VAL);
    expect(out.split('\n')).toEqual(['A=1', `${PW}="${R}`, R, `${R}"`, 'B=2']);
    // single quotes, a backslash-escaped quote inside, and the closing quote with more after it
    expect(redact(`${KEY}='${VAL}\n${VAL}'\nB=2`)).toBe(`${KEY}='${R}\n${R}'\nB=2`);
    expect(redact(`${KEY}="${VAL}\n\\"${VAL}\\" still\n${VAL}" # end\nB=2`)).toBe(`${KEY}="${R}\n${R}\n${R}" # end\nB=2`);
    // a doubled quote is not the end ('it''s' / "a""b"), so nothing after it is shown
    expect(redact(`${KEY}='${VAL}\nit''s ${VAL}'\nB=2`)).not.toContain(VAL);
    // blank lines inside stay blank; the value never closes: hidden to the end
    expect(redact(`${PW}="${VAL}\n\n${VAL}`)).toBe(`${PW}="${R}\n\n${R}`);
    // a PEM key as a multi-line .env value (the common case): every body line is hidden, line count kept or key-dropped as before
    const body = Array.from({ length: 3 }, (_, i) => `${VAL}${i}`);
    const pem = redact([`${PK}="${MARK(false)}`, ...body, `${MARK(true)}"`, 'B=2'].join('\n'));
    expect(pem).not.toContain(VAL);
    expect(pem.split('\n').at(-1)).toBe('B=2');
  });

  it('redact: YAML quoted scalars and Python/TOML triple quotes over lines are hidden up to the close, in code files too', () => {
    const k = ['pass', 'word'].join('');
    expect(redact(`${k}: "${VAL}\n${VAL}"\nnext: 1`, { path: 'config.yml' })).toBe(`${k}: "${R}\n${R}"\nnext: 1`);
    const q3 = '"'.repeat(3);
    expect(redact(`${k} = ${q3}${VAL}\n${VAL}\n${q3}\nx = 1`, { path: 'app.py' })).toBe(`${k} = ${q3}${R}\n${R}\n${q3}\nx = 1`);
    expect(redact(`const ${k} = \`${VAL}\n${VAL}\`;\nlet x = 1;`, { path: 'a.js' })).toBe(`const ${k} = \`${R}\n${R}\`;\nlet x = 1;`);
  });

  it('redact: a connection string whose host is on the next line has its password hidden (and a password split before the @)', () => {
    expect(redact(`${PG}${VAL}\n@db.internal:5432/app\nnext`)).toBe(`${PG}${R}\n@db.internal:5432/app\nnext`);
    expect(redact(`${PG}${VAL}\n  ${VAL}@db.internal:5432/app`)).toBe(`${PG}${R}\n  ${R}@db.internal:5432/app`);
    // fuzz seed 57505 case 29110: a tab inside the password before the line break
    expect(redact(`${PG}${VAL}\tiE\n@db.internal:5432/app`)).toBe(`${PG}${R}\n@db.internal:5432/app`);
    // not a connection string split over lines: a URL with a port at the end of a line, and the next line has no @ in its first word
    expect(redact('listening on http://localhost:3000\nready')).toBe('listening on http://localhost:3000\nready');
    expect(redact('see https://example.com:8080\nmail me at a@b.c later')).toBe('see https://example.com:8080\nmail me at a@b.c later');
  });

  it('the copied helpers are gone: excerpt.ts uses redact-core\'s own findKeyMarker and indentOf', () => {
    expect(keyMarkerFrom).toBe(core.findKeyMarker);
    for (const s of ['', '  x', '\tx', ' \t x', '\t\t', '        x']) expect(indentCols(s), JSON.stringify(s)).toBe(core.indentOf(s).cols);
  });
});

// Security scan round 2 (E9): a change to the core may only ever hide MORE than the pre-E9 core. Probes of the three findings (and one
// more of the same kind, a section header inside an open quote), each a secret the pre-E9 core hid (checked against its copy in L/tmp-E9).
describe('E9 security scan r2: the quote rule never shows what the block, long-line or section rules hid', () => {
  const k = ['pass', 'word'].join('');
  it('a quote that closes on a line the indented-block rule hides: the whole line stays hidden (finding 1 and 3)', () => {
    expect(redact(`${k}: "abc\n    ${VAL}" tail_${VAL}\nnext: 1`)).not.toContain(VAL);
  });
  it('a long line inside an open quote is the long-line marker, and the more-indented lines after it stay hidden (finding 2)', () => {
    const out = redact(`    ${k}="abc\n${'x'.repeat(5000)}" ${VAL}\n  ${VAL}2\nnext`);
    expect(out).not.toContain(VAL);
    expect(out.split('\n')[1]).toBe(core.LONG_LINE);
  });
  it('a secret section header inside an open quote still starts the section', () => {
    expect(redact(`${k}="abc\n[secrets]\nmore"\nkey = ${VAL}`)).not.toContain(VAL);
  });
  it('the farthest close: a triple quote after a backslash, and for one quote character the later of the backslash and doubled readings', () => {
    expect(redact(`KEY_${k.toUpperCase()}="abc\nx\\"" ${VAL}\nB=2`)).not.toContain(VAL);
    expect(redact(`${k} = """abc\nx\\""" ${VAL}\n"""\nx = 1`)).not.toContain(VAL);
  });
  it('differential: on mixed multi-line texts, every line the pre-E9 rules hid any part of is hidden at least as much (redactPreE9)', () => {
    let seed = 7;
    const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)] as T;
    const parts = [`${k}: "a`, `${k}="a`, `${k} = """a`, `  ${VAL}`, `${VAL}"`, `${VAL}" t_${VAL}`, '[secrets]', '[other]', `key = ${VAL}`, `    ${VAL}`, '', `${k}:`, 'x'.repeat(4100), `tok${'en'}: '${VAL}`, `it''s ${VAL}'`, `\\" ${VAL}`, `url=post${'gres'}://u:${VAL}`, `@db:5432`, 'plain text'];
    for (let c = 0; c < 3000; c++) {
      const text = Array.from({ length: 2 + Math.floor(rnd() * 8) }, () => pick(parts)).join('\n');
      const old = core.redactPreE9(text).split('\n');
      const now = redact(text).split('\n');
      expect(now.length, text).toBe(old.length);
      old.forEach((l, i) => { if (!l.includes(VAL)) expect(now[i]?.includes(VAL), JSON.stringify(text)).toBe(false); });
    }
  });
});

describe('E9: the excerpt reads a connection string cut before its host on the canonical forms too', () => {
  it('fuzz seed 57505 case 179782: a tab inside `://` hides the URL from the shown line; both lines are left out of the excerpt', () => {
    const PG2 = ['url=postgres:/', '\t/app:'].join('');
    const log = ['Error: signing failed', `${PG2}${VAL}`, '@db.internal:5432/app', 'Error: key rejected'].join('\n');
    const out = unscannedExcerpt(log, (t) => t).join('\n');
    expect(out).not.toContain(VAL);
    expect(out).not.toContain('@db.internal');
  });
});
