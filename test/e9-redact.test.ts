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
import { indentCols, keyMarkerFrom } from '../src/proof/excerpt.js';

const R = '[REDACTED]';
// secret-bearing names, built at runtime (test/no-secret-literals.test.ts)
const PW = ['DB_PASS', 'WORD'].join('');
const KEY = ['API_TO', 'KEN'].join('');
const PK = ['PRIVATE', '_KEY'].join('');
const VAL = 'Zq81mVx0PLk2wYr7Ct5n';   // a 20-character run the leak check looks for

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
    const pem = redact([`${PK}="-----BEGIN RSA PRIVATE KEY-----`, ...body, '-----END RSA PRIVATE KEY-----"', 'B=2'].join('\n'));
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
    expect(redact(`url=postgres://app:${VAL}\n@db.internal:5432/app\nnext`)).toBe(`url=postgres://app:${R}\n@db.internal:5432/app\nnext`);
    expect(redact(`url=postgres://app:${VAL}\n  ${VAL}@db.internal:5432/app`)).toBe(`url=postgres://app:${R}\n  ${R}@db.internal:5432/app`);
    // not a connection string split over lines: a URL with a port at the end of a line, and the next line has no @ in its first word
    expect(redact('listening on http://localhost:3000\nready')).toBe('listening on http://localhost:3000\nready');
    expect(redact('see https://example.com:8080\nmail me at a@b.c later')).toBe('see https://example.com:8080\nmail me at a@b.c later');
  });

  it('the copied helpers are gone: excerpt.ts uses redact-core\'s own findKeyMarker and indentOf', () => {
    expect(keyMarkerFrom).toBe(core.findKeyMarker);
    for (const s of ['', '  x', '\tx', ' \t x', '\t\t', '        x']) expect(indentCols(s), JSON.stringify(s)).toBe(core.indentOf(s).cols);
  });
});
