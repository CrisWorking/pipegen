// Plan E E0a (ruling B1): the log excerpt the fix loop sends to the AI, and the error signature. The excerpt is code-extracted from
// the raw CI log: timestamps and ANSI sequences out, a line with a leftover ESC or C1 dropped, the error lines and 5 around them
// (at most 150 lines and 64 KiB), Plan A redact, the composed known-value scrubber through fullScrub, and the secret scan.
// The scanner is the shared stub (test/helpers/gitleaks-stub.ts), so no real binary runs here.
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { knownValueScrubber, LONG_LINE, SecretScanError, secretScanText } from '../src/ai/redact.js';
import { SecretVault } from '../src/create/secrets.js';
import { EXCERPT_CONTEXT_LINES, EXCERPT_MAX_BYTES, EXCERPT_MAX_LINES, EXCERPT_WITHHELD, errorExcerpt, errorSignature, MAX_LOG_CHARS } from '../src/proof/excerpt.js';
import { betterleaksAt, CLEAN, gitleaksAt, makeStub } from './helpers/gitleaks-stub.js';
import { cleanupRepos } from './helpers/make-repo.js';
import { fake } from './helpers/secret-repo.js';

afterEach(() => cleanupRepos());

const R = '[REDACTED]';
// built at runtime: no secret-looking literal is committed (test/no-secret-literals.test.ts)
const VALUE = 'sk' + '_test_' + 'Zq7Rk2mW9xLp4Tn8Hy6Vb3Nc';
const PLACEHOLDER = 'pipegen-placeholder-' + 'STRIPE_SECRET_KEY-0f3a9c';
const THROWAWAY = 'b'.repeat(8) + '9e1d7c55aa04f3b2c8d6e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5';
const TS = '2026-11-03T10:00:00.1234567Z ';
const ESC = '\u001b';
const CFG_LINE = ['pass', 'word', ':'].join('');

function vault(): SecretVault {
  const v = new SecretVault();
  v.set('K_STRIPE', VALUE);
  return v;
}
/** The fix loop's composed scrubber (ruling B1): the vault's, then the placeholders and the throwaway key. */
function composed(v: SecretVault): (text: string) => string {
  const others = knownValueScrubber([PLACEHOLDER, THROWAWAY]);
  return (t) => others(v.scrubber()(t));
}
const clean = () => betterleaksAt(makeStub(CLEAN).bin);
const lines = (n: number, f: (i: number) => string) => Array.from({ length: n }, (_, i) => f(i)).join('\n');

describe('errorExcerpt (E0a, B1)', () => {
  it('excerpt: GitHub timestamp prefixes and ANSI CSI/OSC sequences removed before scrubbing', async () => {
    const v = vault();
    const log = [
      `\ufeff${TS}##[group]Run npm test`,
      `${TS}${ESC}[31m${ESC}[1mError: Invalid API key provided: ${VALUE}${ESC}[0m`,
      // the value split by a colour code: only whole once the code is gone
      `${TS}${ESC}[33mwarn${ESC}[39m key ${VALUE.slice(0, 3)}${ESC}[1;31m${VALUE.slice(3)}${ESC}[0m in config`,
      // an OSC 8 hyperlink (BEL- and ST-terminated) and an OSC title
      `${TS}see ${ESC}]8;;https://example.test/docs${ESC}\\the docs${ESC}]8;;${ESC}\\ ${ESC}]0;title\u0007for help`,
      `${TS}##[error]Process completed with exit code 1.`,
    ].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out.split('\n')).toEqual([
      '##[group]Run npm test',
      `Error: Invalid API key provided: ${R}`,
      `warn key ${R} in config`,
      'see the docs for help',
      '##[error]Process completed with exit code 1.',
    ]);
    expect(out).not.toMatch(/[\u001b\u0080-\u009f]/);
    expect(out).not.toContain('2026-11-03T');
    // split where the reading that keeps the code's final byte is shaped like a Stripe key: hidden whole, never shown in part
    const keyShaped = await errorExcerpt(`${TS}warn key ${VALUE.slice(0, 9)}${ESC}[1;31m${VALUE.slice(9)}${ESC}[0m\n${TS}Error: x`, composed(v), clean());
    expect(keyShaped).toContain('Error: x');
    for (const piece of [VALUE.slice(0, 9), VALUE.slice(9)]) expect(keyShaped).not.toContain(piece);
    v.wipe();
  });

  it('excerpt: a leftover ESC or C1 drops that line only, never the whole excerpt', async () => {
    const v = vault();
    const log = [
      `${TS}Error: first`,
      `${TS}${ESC}(Bcharset switch`, // an escape that is neither CSI nor OSC
      `${TS}x\u009b31m C1 CSI`, // the 8-bit CSI
      `${TS}${ESC}]0;never terminated`,
      `${TS}lone ${ESC} here`,
      `${TS}next \u0085 line`,
      `${TS}Error: second`,
    ].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out.split('\n')).toEqual(['Error: first', 'Error: second']);
    v.wipe();
  });

  it('excerpt: error lines + 5 around, ≤ 150 lines, ≤ 64 KiB', async () => {
    const v = vault();
    expect([EXCERPT_CONTEXT_LINES, EXCERPT_MAX_LINES, EXCERPT_MAX_BYTES]).toEqual([5, 150, 64 * 1024]);
    // one error: the line and 5 on each side
    const one = await errorExcerpt(lines(1000, (i) => `${TS}line ${i}${i === 500 ? ' FAILED' : ''}`), composed(v), clean());
    expect(one.split('\n')).toEqual(Array.from({ length: 11 }, (_, k) => `line ${495 + k}${495 + k === 500 ? ' FAILED' : ''}`));
    // two windows far apart: a marker between them
    const two = await errorExcerpt(lines(1000, (i) => `line ${i}${i === 100 || i === 900 ? ' error: boom' : ''}`), composed(v), clean());
    expect(two.split('\n')).toHaveLength(23);
    expect(two.split('\n')[11]).toMatch(/^\[… \d+ lines? not shown …\]$/);
    // errors everywhere: still at most 150 lines, the first error and the last ones kept
    const many = await errorExcerpt(lines(5000, (i) => `line ${i}${i % 7 === 0 ? ' Error' : ''}`), composed(v), clean());
    expect(many.split('\n').length).toBeLessThanOrEqual(150);
    expect(many).toContain('line 0 Error');
    expect(many).toContain('line 4998');
    // long lines: at most 64 KiB, and no line is cut (each line is whole or left out)
    const long = lines(400, (i) => `${i % 3 === 0 ? 'error ' : 'info '}${String(i).padStart(4, '0')} ${'x'.repeat(2000)}`);
    const longOut = await errorExcerpt(long, composed(v), clean());
    expect(Buffer.byteLength(longOut)).toBeLessThanOrEqual(64 * 1024);
    for (const l of longOut.split('\n')) expect(l).toMatch(/^(?:(?:error|info) \d{4} x{2000}|\[… \d+ lines? not shown …\])$/);
    // a line over 4 KB is hidden whole (Plan A redact's rule), never cut
    const huge = await errorExcerpt(`error: before\n${'y'.repeat(200_000)}\nafter`, composed(v), clean());
    expect(huge.split('\n')).toEqual(['error: before', LONG_LINE, 'after']);
    // no error line: the end of the log
    const tail = await errorExcerpt(lines(100, (i) => `step ${i}`), composed(v), clean());
    expect(tail.split('\n').at(-1)).toBe('step 99');
    expect(tail.split('\n').length).toBeLessThanOrEqual(30);
    // a window too big for what is left shrinks around its centre (the error line, or the last line) rather than being lost
    const wide = await errorExcerpt(lines(100, (i) => `step ${String(i).padStart(2, '0')} ${'w'.repeat(4000)}`), composed(v), clean());
    expect(wide.split('\n').at(-1)).toMatch(/^step 99 w+$/);
    expect(Buffer.byteLength(wide)).toBeLessThanOrEqual(64 * 1024);
    expect(wide.split('\n').length).toBeGreaterThanOrEqual(15);
    const wideErr = lines(100, (i) => `${i % 2 === 0 ? 'error' : 'info'} ${String(i).padStart(2, '0')} ${'w'.repeat(4000)}`);
    const wideOut = (await errorExcerpt(wideErr, composed(v), clean())).split('\n');
    expect(wideOut[0]).toMatch(/^error 00 /);
    expect(wideOut.at(-1)).toMatch(/^info 99 /);
    expect(wideOut.some((l) => l.startsWith('error 98 '))).toBe(true);
    v.wipe();
  });

  it('excerpt: Plan A redact runs (connection strings, tokens)', async () => {
    const v = vault();
    const conn = 'postgres://' + 'app:' + 'hunter2-db-pass' + '@db.internal:5432/app';
    const log = [
      `${TS}Error: connect ECONNREFUSED ${conn}`,
      `${TS}using ${fake.githubClassic()} for the API`,
      `${TS}npm ERR! ${fake.npmPublish()}`,
    ].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out).not.toContain('hunter2-db-pass');
    expect(out).not.toContain(fake.githubClassic());
    expect(out).not.toContain(fake.npmPublish());
    expect(out.split('\n')[1]).toBe(`using ${R} for the API`);
    v.wipe();
  });

  it('excerpt: every vault value, placeholder and throwaway scratch key scrubbed', async () => {
    const v = vault();
    const b64 = (s: string) => Buffer.from(s).toString('base64');
    const hex = (s: string) => Buffer.from(s).toString('hex');
    const log = [
      `${TS}Error: request failed with key ${VALUE}`,
      `${TS}header ${b64(`user:${VALUE}`)} sent`,
      `${TS}dump ${hex(VALUE)} end`,
      `${TS}placeholder ${PLACEHOLDER} rejected`,
      `${TS}fingerprint key ${THROWAWAY} used`,
      `${TS}encoded ${encodeURIComponent(PLACEHOLDER)} and ${b64(THROWAWAY)}`,
      // split over two lines (11 and 12), and the window of the error on line 17 starts on line 12: the second half only
      ...Array.from({ length: 5 }, (_, i) => `${TS}filler ${i}`),
      `${TS}tail of key ${VALUE.slice(0, 12)}`,
      `${TS}${VALUE.slice(12)} rest`,
      ...Array.from({ length: 4 }, (_, i) => `${TS}more ${i}`),
      `${TS}Error: done`,
    ].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    for (const piece of [VALUE.slice(0, 12), VALUE.slice(12), PLACEHOLDER, THROWAWAY, hex(VALUE), b64(THROWAWAY).slice(4, 40)]) expect(out).not.toContain(piece);
    expect(out).toContain(`Error: request failed with key ${R}`);
    expect(out).toContain(`placeholder ${R} rejected`);
    expect(out).toContain(`fingerprint key ${R} used`);
    expect(out).toContain(`tail of key ${R} rest`);
    v.wipe();
  });

  it('excerpt: secret scan over the excerpt; a finding removes its line', async () => {
    const v = vault();
    const found = 'zz-scanner-only-finding-7Qx2';
    const log = [`${TS}Error: one`, `${TS}token ${found} here`, `${TS}two`, `${TS}also ${found} again`, `${TS}three`].join('\n');
    // the stub reports the text on the line it finds it (the real scanners give the lines of the file as written)
    const reportOne = makeStub(`const all = findingsFor(${JSON.stringify(found)}); writeReport(JSON.stringify(all.slice(0, 1))); process.exit(1);`);
    for (const at of [betterleaksAt, gitleaksAt]) {
      const out = await errorExcerpt(log, composed(v), at(reportOne.bin));
      // the reported line goes, and so does every other line holding the found text
      expect(out.split('\n')).toEqual(['Error: one', 'two', 'three']);
    }
    // what the scanner read: the excerpt after redact and the scrubber, with pipegen's canary
    const rec = reportOne.record();
    const written = Object.values(rec.files)[0] as string;
    expect(written).toMatch(/^\nError: one\n/);
    expect(written).toMatch(/\npipegen-canary-[0-9a-f]{32}\n$/);
    // a finding with no line it can be placed on: the excerpt is withheld
    const noLine = makeStub(`const all = findingsFor(${JSON.stringify(found)}).map((f) => ({ ...f, StartLine: 0, EndLine: 0 })); writeReport(JSON.stringify(all)); process.exit(1);`);
    expect(await errorExcerpt(log, composed(v), betterleaksAt(noLine.bin))).toBe(EXCERPT_WITHHELD);
    // a scan that did not confirm it read the excerpt: nothing
    const unread = makeStub(`canary = 'none'; writeReport('[]'); process.exit(0);`);
    await expect(errorExcerpt(log, composed(v), betterleaksAt(unread.bin))).rejects.toThrow(SecretScanError);
    // the canary reported on another line than its own: nothing either
    const moved = makeStub(`canary = 'none'; writeReport(JSON.stringify(canaryFindings().map((f) => ({ ...f, StartLine: 2, EndLine: 2 })))); process.exit(1);`);
    await expect(errorExcerpt(log, composed(v), betterleaksAt(moved.bin))).rejects.toThrow(SecretScanError);
    // secretScanText itself refuses a text the scanners would skip (errorExcerpt drops such a line first)
    const late = `${'a'.repeat(255)}\nustar rest`;
    await expect(secretScanText(late, clean())).rejects.toThrow(/would skip it/);
    v.wipe();
  });
});

describe('errorExcerpt: scrub before cutting (E0a)', () => {
  it('excerpt: a private key whose BEGIN line is outside the error window stays hidden (redact runs before the lines are picked)', async () => {
    const v = vault();
    const body = Array.from({ length: 20 }, (_, i) => `${fake.keyBody()}${String(i).padStart(2, '0')}`);
    const log = [`${TS}${fake.keyBegin()}`, ...body.map((b) => `${TS}${b}`), `${TS}${fake.keyEnd()}`, `${TS}Error: key rejected`].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out).toContain('Error: key rejected');
    for (const b of body) expect(out).not.toContain(b);
    v.wipe();
  });

  it('excerpt: an ESC on a key\'s BEGIN line does not uncover the key body (lines are dropped after redact, not before)', async () => {
    const v = vault();
    const body = Array.from({ length: 12 }, (_, i) => `${fake.keyBody()}${String(i).padStart(2, '0')}`);
    const begin = fake.keyBegin();
    const cut = begin.indexOf(' ') + 1;
    for (const first of [`${ESC}(B${begin}`, `${begin}${ESC}7`, `${begin.slice(0, cut)}${ESC}(B${begin.slice(cut)}`, `\u009b${begin}`]) {
      const log = [`${TS}${first}`, ...body.map((b) => `${TS}${b}`), `${TS}${fake.keyEnd()}`, `${TS}Error: key rejected`].join('\n');
      const out = await errorExcerpt(log, composed(v), clean());
      expect(out, JSON.stringify(first)).toContain('Error: key rejected');
      for (const b of body) expect(out, JSON.stringify(first)).not.toContain(b);
    }
    // an ESC inside an indented secret block keeps the block hidden (redact's indent rule still sees the line)
    const block = [`${TS}${CFG_LINE}`, `${TS}  ${ESC}(Bfirst-hidden-line`, `${TS}  second-hidden-line`, `${TS}Error: bad config`].join('\n');
    const blockOut = await errorExcerpt(block, composed(v), clean());
    expect(blockOut).toContain('Error: bad config');
    expect(blockOut).not.toContain('second-hidden-line');
    v.wipe();
  });

  it('excerpt: a dropped BEGIN line split by an escape sequence still hides the key up to its END (whole sequences removed first)', async () => {
    const v = vault();
    const begin = fake.keyBegin();
    const at = begin.indexOf(' ') + 1;
    const body = Array.from({ length: 6 }, (_, i) => `${fake.keyBody()}${i}`);
    for (const split of [`\u009b31m`, `${ESC}(B`, `\u009b1;31m`, `${ESC}#8`]) {
      const first = `${begin.slice(0, at)}${split}${begin.slice(at)}`;
      // the body quoted, so it is not armor-shaped: only the marker can tell it is a key
      const log = [`${TS}${first}`, ...body.map((b) => `${TS}> ${b}`), `${TS}${fake.keyEnd()}`, `${TS}Error: key rejected`].join('\n');
      const out = await errorExcerpt(log, composed(v), clean());
      expect(out, JSON.stringify(split)).toContain('Error: key rejected');
      for (const b of body) expect(out, JSON.stringify(split)).not.toContain(b);
    }
    // fail closed: a dropped line that names a private key, in any case, starts a hidden block up to the END
    const named = [`${TS}${ESC}(Bloading private key:`, ...body.map((b) => `${TS}| ${b}`), `${TS}${fake.keyEnd()}`, `${TS}Error: done`].join('\n');
    const namedOut = await errorExcerpt(named, composed(v), clean());
    expect(namedOut).toContain('Error: done');
    for (const b of body) expect(namedOut).not.toContain(b);
    v.wipe();
  });

  it('excerpt: ruling E0a-R1: a dropped line is read three ways, and PRIVATE or KEY in any reading starts the key hide', async () => {
    const v = vault();
    const begin = fake.keyBegin();
    const body = Array.from({ length: 6 }, (_, i) => `${fake.keyBody()}${i}`);
    const at = begin.indexOf(' ') + 1;
    const keyAt = begin.lastIndexOf('KEY');
    for (const first of [
      `${begin.slice(0, at)}${ESC}[1;31${begin.slice(at)}`, // the first letter of the label eaten as a CSI final byte
      `${begin.slice(0, keyAt)}${ESC}[1;3${begin.slice(keyAt)}`, // the K of KEY eaten: only the character-stripped reading says KEY
      `${begin.slice(0, keyAt)}\u009b9${begin.slice(keyAt)}`,
      `pri\u200bvate ${ESC}(Bk\u00adey follows`, // invisible characters split the words: the third reading joins them
    ]) {
      const log = [`${TS}${first}`, ...body.map((b) => `${TS}> ${b}`), `${TS}${fake.keyEnd()}`, `${TS}Error: key rejected`].join('\n');
      const out = await errorExcerpt(log, composed(v), clean());
      expect(out, JSON.stringify(first)).toContain('Error: key rejected');
      for (const b of body) expect(out, JSON.stringify(first)).not.toContain(b);
    }
    v.wipe();
  });

  it('excerpt: scan 4: an armor line that also names a key is hidden while armor mode lasts (the armor check comes first)', async () => {
    const v = vault();
    // after a dropped line, no END anywhere: armor mode. The second body line holds KEY and a CR, so it also starts a key hide.
    const body = [`${fake.keyBody()}A1`, `MIIEKEYw\r${'w'.repeat(56)}B2`, `${fake.keyBody()}C3`];
    const log = [`${TS}${ESC}(Bdumping`, ...body.map((b) => `${TS}${b}`), `${TS}Error: done`].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out).toContain('Error: done');
    for (const b of body) expect(out).not.toContain(b.replace('\r', '').slice(-20));
    v.wipe();
  });

  it('excerpt: scan 5: a key line with an escape inside its name still hides its indented value and its secret section', async () => {
    const v = vault();
    const valueRun = ['Qx7', 'Lm2Wv9Rt4Zp8Kd3Hs'].join('');
    const name = ['pass', 'word'];
    for (const key of [`${name[0]}${ESC}[0m${name[1]}:`, `${name[0]}${ESC}[1;3${name[1]}:`, `${name[0]}\t${name[1]}:`, `${name[0]}${ESC}Z${name[1]}:`]) {
      const log = [`${TS}config:`, `${TS}  ${key}`, `${TS}    ${valueRun}`, `${TS}    more-${valueRun}`, `${TS}Error: bad config`].join('\n');
      const out = await errorExcerpt(log, composed(v), clean());
      expect(out, JSON.stringify(key)).toContain('Error: bad config');
      expect(out, JSON.stringify(key)).not.toContain(valueRun);
    }
    // a TOML secret section whose header holds an escape
    const toml = [`${TS}[data${ESC}[1;3base.${name.join('')}]`, `${TS}url = ${valueRun}`, `${TS}[other]`, `${TS}Error: done`].join('\n');
    const tomlOut = await errorExcerpt(toml, composed(v), clean());
    expect(tomlOut).toContain('Error: done');
    expect(tomlOut).not.toContain(valueRun);
    v.wipe();
  });

  it('excerpt: ruling E0a-R1: unterminated C1 OSC introducers stay linear (64 KiB line, and many 4 KB lines)', async () => {
    const v = vault();
    for (const log of [`Error: x\n${'\u009d'.repeat(64 * 1024)}`, `Error: x\n${Array.from({ length: 256 }, () => '\u009d'.repeat(4000)).join('\n')}`]) {
      const t0 = performance.now();
      const out = await errorExcerpt(log, composed(v), clean());
      expect(performance.now() - t0).toBeLessThan(2000);
      expect(out).toBe('Error: x');
    }
    v.wipe();
  });

  it('excerpt: an armor body with headers and blank lines stays hidden until its END (or the first non-armor line)', async () => {
    const v = vault();
    const body = Array.from({ length: 6 }, (_, i) => `${fake.keyBody()}${i}`);
    const armored = ['Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,0123456789ABCDEF', '', body[0], '', ...body.slice(1, 4), '   ', ...body.slice(4)];
    // a dropped line that names a key, and no END anywhere: armor mode (an intact BEGIN with no END is redact's: it hides the rest)
    const noEnd = [`${TS}${ESC}(BWriting new Private Key to stdout`, ...armored.map((l) => `${TS}${l}`), `${TS}Error: key rejected`].join('\n');
    const out = await errorExcerpt(noEnd, composed(v), clean());
    expect(out).toContain('Error: key rejected');
    for (const b of body) expect(out).not.toContain(b);
    // a cut inside a key block with no END in the tail: the same
    const kept = [...armored, 'Error: key rejected'].join('\n');
    const log = ['ok start', fake.keyBegin(), ...body, ...armored, 'Error: key rejected', 'f'.repeat(MAX_LOG_CHARS - kept.length - 2)].join('\n');
    const cutOut = await errorExcerpt(log, composed(v), clean());
    for (const b of body) expect(cutOut).not.toContain(b);
    v.wipe();
  });

  it('excerpt: a cut inside a 200-line key block hides the block up to its END, whatever the head guard', async () => {
    const v = vault();
    const body = Array.from({ length: 200 }, (_, i) => `${fake.keyBody()}${String(i).padStart(3, '0')}`);
    const after = [fake.keyEnd(), 'Error: key rejected'];
    // the cut lands after body line 49: lines 50-199 (150 lines, past the 64-line guard) are in the tail
    const kept = [...body.slice(50), ...after].join('\n');
    const filler = 'f'.repeat(MAX_LOG_CHARS - kept.length - 2);
    const log = ['ok start', fake.keyBegin(), ...body, ...after, filler].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out).toContain('Error: key rejected');
    for (const b of body) expect(out).not.toContain(b);
    v.wipe();
  });

  it('excerpt: a log over MAX_LOG_CHARS is read from its end, and the first 64 lines after the cut are never shown', async () => {
    const v = vault();
    const head = 'Error: early\n' + 'x'.repeat(MAX_LOG_CHARS);
    const guarded = Array.from({ length: 64 }, (_, i) => `guarded ${i} error`).join('\n');
    const out = await errorExcerpt(`${head}\n${guarded}\nlast line error`, composed(v), clean());
    expect(out).not.toContain('Error: early');
    expect(out).not.toContain('guarded');
    expect(out).toBe('last line error');
    v.wipe();
  });

  it('excerpt: a line with a format marker the scanners sniff at a fixed byte is dropped, and the rest is still scanned', async () => {
    const v = vault();
    // byte 257 of the file as written (pipegen's prefix line is byte 0): "ustar" there makes both scanners skip the file
    const first = 'Error: ' + 'a'.repeat(240);
    const second = 'b'.repeat(257 - 1 - first.length - 1) + 'ustar tail';
    const stub = makeStub(CLEAN);
    const out = await errorExcerpt(`${first}\n${second}\nthird`, composed(v), betterleaksAt(stub.bin));
    expect(out.split('\n')).toEqual([first, 'third']);
    expect(Object.values(stub.record().files)[0]).not.toContain('ustar');
    v.wipe();
  });
});

describe('errorSignature (E0a)', () => {
  it('signature: numbers, paths, times, ids and hex runs removed, then sha256', () => {
    const a = [
      'Error: expected 3 to equal 4 at /home/runner/work/app/src/x.test.ts:12:5',
      '  at 2026-11-03T10:00:00.123Z (took 15:04:05.123) request 3f9b2c1e-7d4a-4b8e-9c0f-1a2b3c4d5e6f',
      '  commit 9f8e7d6c5b4a in C:\\Users\\a\\app\\x.js pid 4242 hash deadbeefcafe0123',
    ].join('\n');
    const b = [
      'Error: expected 7 to equal 8 at /tmp/other/path/y.test.ts:99:1',
      '  at 2025-01-02T03:04:05Z (took 01:02:03.456) request 00000000-1111-2222-3333-444455556666',
      '  commit 0a1b2c3d4e5f in D:\\x\\y.js pid 1 hash 0123456789abcdef',
    ].join('\n');
    expect(errorSignature(a)).toMatch(/^[0-9a-f]{64}$/);
    expect(errorSignature(a)).toBe(errorSignature(b));
    // whitespace and the order of the words still matter as words, not as spacing
    expect(errorSignature(a)).toBe(errorSignature(a.replaceAll(' ', '   ')));
    expect(errorSignature('Error: cannot find module')).not.toBe(errorSignature('Error: module not installed'));
    // sha256 of the normalised text
    expect(errorSignature('Error: x 12')).toBe(createHash('sha256').update('Error: x 0').digest('hex'));
  });
});
