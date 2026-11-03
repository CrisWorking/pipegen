// Plan E E0a (ruling B1): the log excerpt the fix loop sends to the AI, and the error signature. The excerpt is code-extracted from
// the raw CI log: timestamps and ANSI sequences out, a line with a leftover ESC or C1 dropped, the error lines and 5 around them
// (at most 150 lines and 64 KiB), Plan A redact, the composed known-value scrubber through fullScrub, and the secret scan.
// The scanner is the shared stub (test/helpers/gitleaks-stub.ts), so no real binary runs here.
import { createHash } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { knownValueScrubber, LONG_LINE, SecretScanError, secretScanText } from '../src/ai/redact.js';
import { SecretVault } from '../src/create/secrets.js';
import {
  EXCERPT_CONTEXT_LINES, EXCERPT_MAX_BYTES, EXCERPT_MAX_LINES, EXCERPT_WITHHELD, errorExcerpt as errorExcerptWithEvidence, type ExcerptEvidence, errorSignature,
  MAX_LOG_CHARS, unscannedExcerpt,
} from '../src/proof/excerpt.js';
import { betterleaksAt, CLEAN, gitleaksAt, makeStub } from './helpers/gitleaks-stub.js';
import { cleanupRepos } from './helpers/make-repo.js';
import { placeholderEvidence } from './helpers/scratch-secrets.js';
import { fake } from './helpers/secret-repo.js';

afterEach(() => cleanupRepos());

// ruling E0a-R5: every excerpt here is built from a placeholders-only run: real evidence, minted by ScratchKeys over the fake (E4)
let PLACEHOLDERS_ONLY: ExcerptEvidence;
beforeAll(async () => { PLACEHOLDERS_ONLY = await placeholderEvidence(); });
const errorExcerpt = (logs: string, scrub: (t: string) => string, scanner: Parameters<typeof errorExcerptWithEvidence>[2], opts?: { timeoutMs?: number }) =>
  errorExcerptWithEvidence(logs, scrub, scanner, PLACEHOLDERS_ONLY, opts);

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
      // the value split by a colour code glued between two of its characters: the code may have eaten some, so the line is dropped
      // (fix round 1, C1(b)); a colour code next to a blank is ordinary output and stays
      `${TS}${ESC}[33mwarn${ESC}[39m key ${VALUE.slice(0, 3)}${ESC}[1;31m${VALUE.slice(3)}${ESC}[0m in config`,
      `${TS}${ESC}[31m${ESC}[1mError: Invalid API key provided: ${VALUE} (see docs)${ESC}[0m`,
      `${TS}##[error]Process completed with exit code 1.`,
      // an OSC 8 hyperlink (BEL- and ST-terminated) and an OSC title (a messy line: a neighbour's long token next to it would be hidden)
      `${TS}see ${ESC}]8;;https://example.test/docs${ESC}\\the docs${ESC}]8;;${ESC}\\ ${ESC}]0;title\u0007for help`,
    ].join('\n');
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out.split('\n')).toEqual([
      '##[group]Run npm test',
      `Error: Invalid API key provided: ${R} (see docs)`,
      '##[error]Process completed with exit code 1.',
      'see the docs for help',
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
    // the value split over lines 11 and 12: both lines are hidden (fix round 1: a value across lines can be cut by redact)
    expect(out).not.toContain('tail of key');
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

  it('excerpt: ordinary coloured output stays shown (the fail-closed rules need a secret shape)', async () => {
    const v = vault();
    const c = (code: string, text: string) => `${TS}${ESC}[${code}m${text}${ESC}[0m`;
    const log = [
      c('34', '[INFO] Building app 1.0.0'),
      c('34', '[INFO] token cache refreshed in 3 ms'),
      c('31', 'FAIL src/app.test.ts > loads config'),
      c('2', '    at loadConfig (src/config.ts:12:5)'),
      c('2', '    at Object.<anonymous> (src/app.test.ts:4:3)'),
      c('32', '[OK] lint'),
      c('31', 'Error: expected 200, received 500'),
    ].join('\n');
    const out = (await errorExcerpt(log, composed(v), clean())).split('\n');
    expect(out).toEqual([
      '[INFO] Building app 1.0.0', '[INFO] token cache refreshed in 3 ms', 'FAIL src/app.test.ts > loads config',
      '    at loadConfig (src/config.ts:12:5)', '    at Object.<anonymous> (src/app.test.ts:4:3)', '[OK] lint', 'Error: expected 200, received 500',
    ]);
    v.wipe();
  });

  it('excerpt: scan 6: the shape checks stay linear on hostile lines just under 4 KB', async () => {
    const v = vault();
    // a messy line (an OSC) with a `:` then blanks: the block-opener check; a line of blanks then one other character: the armor check
    const opener = `${ESC}]0;t\u0007:${' '.repeat(4080)}x`;
    const blanks = `${' '.repeat(4090)}!`;
    for (const log of [`Error: x\n${Array.from({ length: 300 }, () => opener).join('\n')}`, `${ESC}(B\n${Array.from({ length: 300 }, () => blanks).join('\n')}\nError: y`]) {
      const t0 = performance.now();
      await errorExcerpt(log, composed(v), clean());
      expect(performance.now() - t0).toBeLessThan(3000);
    }
    v.wipe();
  });

  it('excerpt: scan 6: a line with a control or an invisible character (not only SGR codes) gets the fail-closed name rules', async () => {
    const v = vault();
    const valueRun = ['Qx7', 'Lm2Wv9Rt4Zp8Kd3Hs'].join('');
    for (const ch of ['\u0001', '\u007f', '\u200b', '\u202e', '\u2066', '\ufeff', '\u00ad']) {
      // the character before the indentation hides nothing by itself; inside the name it splits it: shape decides
      const log = [`${TS}  db_pa${ch}${ch}word:`, `${TS}    ${valueRun}`, `${TS}Error: bad config`].join('\n');
      const out = await errorExcerpt(log, composed(v), clean());
      expect(out, JSON.stringify(ch)).toContain('Error: bad config');
      expect(out, JSON.stringify(ch)).not.toContain(valueRun);
    }
    v.wipe();
  });

  it('excerpt: ruling E0a-R1: unterminated C1 OSC introducers stay linear (64 KiB line, and many 4 KB lines)', async () => {
    const v = vault();
    // 2,040 of them are 4,080 UTF-8 bytes: under the 4 KB guard, so the whole-sequence reading does run on them
    for (const log of [`Error: x\n${'\u009d'.repeat(64 * 1024)}`, `Error: x\n${Array.from({ length: 400 }, () => '\u009d'.repeat(2040)).join('\n')}`]) {
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

describe('errorExcerpt: regressions from the mutation run and the 200k fuzz runs (E0a)', () => {
  const BEL = '\u0007';
  const run = ['Qx7', 'Lm2Wv9Rt4Zp8Kd3Hs'].join('');
  const PW = ['pass', 'word'].join('');
  const scrubOnly = (v: SecretVault) => composed(v);
  const shows = (out: string, piece: string) => out.includes(piece);

  it('excerpt: CRLF logs come out without CR, and a window too big for what is left shrinks around its error line', async () => {
    const v = vault();
    expect(await errorExcerpt(`Error: a\r\nnext\r\n`, composed(v), clean())).not.toContain('\r');
    const at = new Set([0, 50, 99]);
    const log = lines(100, (i) => `${at.has(i) ? 'error' : 'info'} ${String(i).padStart(2, '0')} ${'w'.repeat(4000)}`);
    const out = await errorExcerpt(log, composed(v), clean());
    expect(out).toMatch(/^error 50 /m);
    v.wipe();
  });

  it('excerpt: a vault value right after a token is scrubbed before redact can cut it', async () => {
    const v = new SecretVault();
    const typed = 'Zq7Rk2mW-9xLp4Tn8Hy';
    v.set('K_STRIPE', typed);
    const out = await errorExcerpt(`using ${fake.githubClassic()}${typed} now\nError: x`, composed(v), clean());
    expect(out).not.toContain('9xLp4Tn8Hy');
    v.wipe();
  });

  it('excerpt: a value split by an invisible character never shows, on one line or across two, and the other lines stay', async () => {
    const v = vault();
    // on one line: since fix round 1 the value pass finds it in the line's stripped form, and the messy line is hidden
    const one = await errorExcerpt(`Error: a\nkey ${VALUE.slice(0, 8)}\u200b${VALUE.slice(8)}\nnext`, composed(v), clean());
    expect(one.split('\n')).toEqual(['Error: a', 'next']);
    expect(one).not.toContain(VALUE.slice(8));
    const two = await errorExcerpt(`Error: a\ntail ${VALUE.slice(0, 8)}\u200b\n${VALUE.slice(8)} rest\nnext`, composed(v), clean());
    expect(two).not.toContain(VALUE.slice(8));
    v.wipe();
  });

  it('excerpt: a short scanner finding drops its line even when the found text is too short to look for elsewhere', async () => {
    const v = vault();
    const stub = makeStub(`writeReport(JSON.stringify(findingsFor('zq9').slice(0, 1))); process.exit(1);`);
    const out = await errorExcerpt('Error: a\nflagged zq9 here\nnext', composed(v), betterleaksAt(stub.bin));
    expect(out.split('\n')).toEqual(['Error: a', 'next']);
    v.wipe();
  });

  it('excerpt: a value split between a shown line and a dropped one shows neither part of the dropped line', async () => {
    const v = vault();
    // the value starts in the shown line and ends in the dropped one (its end tag holds), and the other way round (its start tag holds)
    const a = await errorExcerpt(`ok ${VALUE.slice(0, 10)}\n${VALUE.slice(10)} hidden-tail-text ${ESC}(B\nError: x`, scrubOnly(v), clean());
    expect(shows(a, 'hidden-tail-text')).toBe(false);
    const b = await errorExcerpt(`hidden-head-text ${ESC}(B ${VALUE.slice(0, 10)}\n${VALUE.slice(10)} ok\nError: x`, scrubOnly(v), clean());
    expect(shows(b, 'hidden-head-text')).toBe(false);
    v.wipe();
  });

  it('excerpt: a cut inside a key block hides a body that is not armor-shaped up to its END; a one-line key before the cut does not', () => {
    const body = Array.from({ length: 80 }, (_, i) => `> ${fake.keyBody()}${String(i).padStart(2, '0')}`);
    const tail = [...body.slice(10), fake.keyEnd(), 'Error: key rejected'].join('\n');
    const log = ['start', fake.keyBegin(), ...body, fake.keyEnd(), 'Error: key rejected'].join('\n');
    const out = unscannedExcerpt(log, (t) => t, { maxLogChars: tail.length }).join('\n');
    for (const b of body) expect(out).not.toContain(b.slice(2));
    // BEGIN and END on one line before the cut: the tail is not inside a key
    const tail2 = [...Array.from({ length: 70 }, (_, i) => `line ${i}`), 'Error: before', ...Array.from({ length: 6 }, (_, i) => `after ${i}`), fake.keyEnd(), 'done'].join('\n');
    const log2 = [`${fake.keyBegin()}${fake.keyBody()}${fake.keyEnd()}`, 'filler', tail2].join('\n');
    expect(unscannedExcerpt(log2, (t) => t, { maxLogChars: tail2.length }).join('\n')).toContain('Error: before');
  });

  it('excerpt: armor goes on through a messy body line whose readings keep a long run but no armor shape', async () => {
    const v = vault();
    const body = `${fake.keyBody()}Q9`;
    const out = await errorExcerpt([`${ESC}(Bdump`, `${body}\u2028;x`, 'Error: y'].join('\n'), composed(v), clean());
    expect(out).not.toContain(body.slice(8, 40));
    v.wipe();
  });

  it('excerpt: a dropped line whose reading opens a key with no END after it hides to the end of the log', async () => {
    const v = vault();
    const body = Array.from({ length: 4 }, (_, i) => `> ${fake.keyBody()}${i}`);
    // only the reading that keeps final bytes has the marker whole (the K of KEY is a CSI's final byte); the stray ESC drops the line
    const begin = fake.keyBegin();
    const keyAt = begin.lastIndexOf('KEY');
    const first = `${begin.slice(0, keyAt)}${ESC}[1;3${begin.slice(keyAt)}${ESC}(`;
    const out = await errorExcerpt([first, ...body, 'Error: x'].join('\n'), composed(v), clean());
    for (const b of body) expect(out).not.toContain(b.slice(2));
    v.wipe();
  });

  it('excerpt: a messy line that reads as a header does not end a secret section (an SGR-coloured header is clean text and may)', async () => {
    const v = vault();
    const sec = ['[sec', 'rets]'].join('');
    for (const header of [`${ESC}]0;x${BEL}[other]`]) {
      const out = await errorExcerpt([sec, `a = ${run}`, header, `b = more-${run}`, '[plain]', 'Error: x'].join('\n'), composed(v), clean());
      expect(out, JSON.stringify(header)).toContain('Error: x');
      expect(out, JSON.stringify(header)).not.toContain(run);
    }
    v.wipe();
  });

  it('excerpt: a log needing more probes than the budget gives an empty excerpt (fail closed)', () => {
    const log = Array.from({ length: 310_000 }, (_, i) => (i === 5 ? 'Error: x' : '\tx')).join('\n');
    expect(unscannedExcerpt(log, (t) => t)).toEqual([]);
  });

  it('excerpt: 200k fuzz regressions: an OSC that ate the `:`, a blank line inside the block, an OSC or a CSI that ate the indentation', async () => {
    const v = vault();
    const cases = [
      // seed 57507 case 83488: an OSC swallowed the opener's `:` (G6)
      [`  client_sec${ESC}]0;o4a5dlret: ${ESC}\\|\u2028-`, `    ${run}`, `    more-${run}`, 'Error: x'],
      // a messy opener redact can't name, then a blank line, then the value (G15)
      [`db_x${ESC}]0;t${BEL}:`, '', `  ${run}`, 'Error: x'],
      // seed 57506 case 28798: an OSC at the line start swallowed the indentation (G16)
      [`  ${PW}:`, `    first-${run}`, `${ESC}]0;t      xx${BEL}mid-${run}`, `    last-${run}`, 'Error: x'],
      // seed 57507 case 101726: a CSI whose intermediates were the indentation's spaces (G19)
      [`    ${PW}: >`, `      first-${run}`, ` ${ESC}[     omid-${run}`, `      last-${run}`, 'Error: x'],
    ];
    for (const c of cases) {
      const out = await errorExcerpt(c.join('\n'), composed(v), clean());
      expect(out, JSON.stringify(c[0])).toContain('Error: x');
      expect(out, JSON.stringify(c[0])).not.toContain(run);
    }
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
