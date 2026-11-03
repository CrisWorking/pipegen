// Plan E E0a (ruling B1): the known-value forms the fix loop's log excerpt needs. A value the user typed can reach a CI log as
// hex, as the base64 of a longer text that holds it at any byte offset (Basic auth `user:value`), as base64 or hex wrapped at
// fixed columns, or split by a line break. knownForms (src/ai/redact.ts) covers each one, so the vault's scrubber and its
// containsKnownValue do too.
import { describe, expect, it } from 'vitest';
import { encodedSpans, knownValueScrubber, MIN_ENCODED_FORM_BYTES, scrubKnownValues } from '../src/ai/redact.js';
import { MIN_VALUE_LENGTH, SecretVault } from '../src/create/secrets.js';
import { scrubForDisplay } from '../src/util/known-values.js';

const R = '[REDACTED]';
// built at runtime: no secret-looking literal is committed (test/no-secret-literals.test.ts)
const VALUE = 'sk' + '_test_' + 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
function vault(typed: string = VALUE): SecretVault {
  const v = new SecretVault();
  v.set('K_STRIPE', typed);
  return v;
}
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const hex = (s: string) => Buffer.from(s, 'utf8').toString('hex');
const id = (s: string) => s;
const HEADER = ['Authori', 'zation', ': Bas', 'ic'].join('');

/** Every 3-byte piece of `value` that can still be decoded (base64 at any alignment, hex at either) from `text`. */
function decodablePieces(text: string, value: string): string[] {
  const out: string[] = [];
  const flat = text.replace(/[\r\n\u2028\u2029 \t]/g, '');
  for (let i = 0; i + 3 <= value.length; i++) {
    const piece = value.slice(i, i + 3);
    if (encodedSpans(flat, piece).length > 0) out.push(piece);
  }
  return out;
}

const wrap = (s: string, cols: number, eol = '\n') => (s.match(new RegExp(`.{1,${cols}}`, 'g')) ?? []).join(eol);

describe('known-values: forms for the log excerpt (E0a, B1)', () => {
  it('known-values: hex (lower and upper) of a value → scrubbed and contained', () => {
    const v = vault();
    const lower = hex(VALUE);
    const upper = lower.toUpperCase();
    const text = `key=${lower} KEY=${upper} end`;
    expect(v.scrubber()(text)).toBe(`key=${R} KEY=${R} end`);
    expect(scrubKnownValues(text, [VALUE])).toBe(`key=${R} KEY=${R} end`);
    expect(scrubForDisplay(v, text, id)).toBe(`key=${R} KEY=${R} end`);
    expect(v.containsKnownValue(lower)).toBe(true);
    expect(v.containsKnownValue(upper)).toBe(true);
    expect(v.containsKnownValue(`0x${lower}`)).toBe(true);
    // a hex dump of a longer text that holds the value at an odd byte offset is still caught (the value's own bytes are whole)
    expect(v.scrubber()(hex(`x${VALUE}y`))).toBe(`78${R}79`);
    // a non-ASCII value: its UTF-8 bytes
    const accented = vault('pässwörd-Zq7Rk2mW');
    expect(accented.scrubber()(`h=${hex('pässwörd-Zq7Rk2mW')}`)).toBe(`h=${R}`);
    v.wipe();
    accented.wipe();
  });

  it('known-values: base64 of a value at byte offsets 0, 1, 2 inside a longer blob (Basic user:value) → scrubbed', () => {
    const v = vault();
    for (const prefix of ['', 'u', 'us', 'use', 'user:', 'admin:', 'x-access-' + 'tok' + 'en:']) {
      for (const suffix of ['', ':', 'xy', ':pw', '@host']) {
        const blob = b64(prefix + VALUE + suffix);
        for (const text of [`${HEADER} ${blob}`, `url=https://${blob}/x`]) {
          for (const out of [v.scrubber()(text), scrubKnownValues(text, [VALUE]), scrubForDisplay(v, text, id)]) {
            expect(out, `${prefix}|${suffix}`).toContain(R);
            expect(decodablePieces(out, VALUE), `${prefix}|${suffix}`).toEqual([]);
          }
          expect(v.containsKnownValue(text)).toBe(true);
        }
      }
    }
    // the URL-safe alphabet too, with a value whose base64 core holds + and / at every offset
    const odd = 'Zq7Rk2mW?>~Hy6Vb3Nc>>?';
    const w = vault(odd);
    for (const prefix of ['', 'u', 'us']) {
      const urlSafe = b64(`${prefix}${odd}!`).replaceAll('+', '-').replaceAll('/', '_');
      expect(urlSafe).toMatch(/[-_]/);
      const out = w.scrubber()(`t=${urlSafe}`);
      expect(out, prefix).toContain(R);
      expect(decodablePieces(out.replaceAll('-', '+').replaceAll('_', '/'), odd), prefix).toEqual([]);
    }
    w.wipe();
    v.wipe();
  });

  it('known-values: base64 wrapped at 60/64/76 columns → scrubbed', () => {
    const v = vault();
    const filler = 'The quick brown fox jumps over the lazy dog. '.repeat(3);
    for (const cols of [60, 64, 76]) {
      for (let shift = 0; shift < 48; shift++) {
        for (const eol of ['\n', '\r\n']) {
          const blob = wrap(b64(`${filler.slice(0, shift)}user:${VALUE}:${filler}`), cols, eol);
          const text = `-----DATA-----${eol}${blob}${eol}-----END-----`;
          const out = v.scrubber()(text);
          expect(out, `${cols}/${shift}`).toContain(R);
          expect(decodablePieces(out, VALUE), `${cols}/${shift}`).toEqual([]);
          expect(scrubForDisplay(v, text, id)).toContain(R);
        }
      }
      // indented, as in a YAML block or a wrapped log
      const indented = wrap(b64(`user:${VALUE}`), cols).split('\n').map((l) => `    ${l}`).join('\n');
      expect(decodablePieces(v.scrubber()(indented), VALUE)).toEqual([]);
    }
    // hex wrapped at 60 columns (xxd -p)
    const dump = wrap(hex(`header ${VALUE} trailer`), 60);
    expect(decodablePieces(v.scrubber()(dump), VALUE)).toEqual([]);
    v.wipe();
  });

  it('known-values: value split by \\n, \\r\\n, LS, PS → scrubbed (split class)', () => {
    const v = vault();
    for (const sep of ['\n', '\r\n', '\r', '\u2028', '\u2029', '\n    ', '  \n\t']) {
      for (const at of [1, 9, VALUE.length - 1]) {
        const text = `before ${VALUE.slice(0, at)}${sep}${VALUE.slice(at)} after`;
        expect(v.scrubber()(text), JSON.stringify(sep)).toBe(`before ${R} after`);
        expect(scrubKnownValues(text, [VALUE])).toBe(`before ${R} after`);
        expect(scrubForDisplay(v, text, id)).toBe(`before ${R} after`);
        expect(v.containsKnownValue(text)).toBe(true);
      }
    }
    // split into several pieces, one per line
    const many = VALUE.match(/.{1,5}/g)?.join('\n') ?? '';
    expect(v.scrubber()(`a\n${many}\nb`)).toBe(`a\n${R}\nb`);
    // other lines keep their line breaks
    expect(v.scrubber()(`one\ntwo ${VALUE.slice(0, 4)}\n${VALUE.slice(4)} three\nfour`)).toBe(`one\ntwo ${R} three\nfour`);
    v.wipe();
  });

  it('known-values: a split next to a space, and a lowercase percent form split across lines, are scrubbed too', () => {
    // the space belongs to the value: only the view that takes out the break alone (not the blanks next to it) holds it
    const spaced = vault('Zq7Rk2mW 9xLp4Tn8');
    expect(spaced.scrubber()('a Zq7Rk2mW \n9xLp4Tn8 b')).toBe(`a ${R} b`);
    spaced.wipe();
    // the URL form with lowercase escapes, split by a line break: the joined view is searched with its %xx in upper case too
    const typed = 'p%ss w\u00f6rd/+=Zq7Rk2';
    const v = vault(typed);
    const enc = encodeURIComponent(typed).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
    const cut = enc.indexOf('%2f') + 2;
    expect(v.scrubber()(`u=${enc.slice(0, cut)}\n${enc.slice(cut)} end`)).toBe(`u=${R} end`);
    v.wipe();
  });

  it('known-values: the encoded forms start at the vault minimum (8 bytes); shorter known values keep only the old forms', () => {
    expect(MIN_ENCODED_FORM_BYTES).toBe(MIN_VALUE_LENGTH);
    // a 3-byte known value (the audit's own known values can be short): its hex and shifted base64 are not looked for
    expect(scrubKnownValues(`616263 YWJj abc ${b64('xabc')}`, ['abc'])).toBe(`616263 ${R} ${R} ${b64('xabc')}`);
    // an 8-byte value has them
    expect(scrubKnownValues(hex('abcdefgh'), ['abcdefgh'])).toBe(R);
  });

  it('known-values: nothing changes in a text without the value (no join across lines makes a match out of thin air)', () => {
    const v = vault();
    const text = 'line one\nline two\r\nZq7Rk2mW\u2028 other\n\n  indented\n';
    expect(v.scrubber()(text)).toBe(text);
    expect(v.containsKnownValue(text)).toBe(false);
    const sc = knownValueScrubber([VALUE, 'other-value-123']);
    expect(sc(text)).toBe(text);
    v.wipe();
  });
});
