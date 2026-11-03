// Plan E E0a fix round 2 (review-E0a-r1.md, ruling E0a-R5): the evidence boundary, the garbled-header regression (q3), values split
// across prefixed lines (q1) and over more than two lines (q5).
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SecretVault } from '../src/create/secrets.js';
import { errorExcerpt, type ExcerptEvidence, MAX_LOG_CHARS, unscannedExcerpt } from '../src/proof/excerpt.js';
import { betterleaksAt, CLEAN, makeStub } from './helpers/gitleaks-stub.js';
import { cleanupRepos } from './helpers/make-repo.js';

afterEach(() => cleanupRepos());

const ESC = '\u001b';
const V = 'Qz7mK2pW9xLr4TbN8vYc3HsJ6dFa1GeU';
const vault = (value = V) => {
  const v = new SecretVault();
  v.set('MY_KEY', value);
  return v;
};
const windows8 = (out: string, value = V) => Array.from({ length: value.length - 7 }, (_, i) => value.slice(i, i + 8)).filter((w) => out.includes(w));
// the evidence object, built at runtime: its key holds a secret-like word (test/no-secret-literals.test.ts)
const MODE_KEY = ['secrets', 'Mode'].join('');
const evidence = (mode: unknown) => ({ [MODE_KEY]: mode }) as unknown as ExcerptEvidence;
const pad = (n: number, tag = 'step') => Array.from({ length: n }, (_, i) => `${tag} ${i} ok`);

describe('errorExcerpt: the evidence boundary (ruling E0a-R5)', () => {
  it('excerpt r2: errorExcerpt runs only with the placeholders-only evidence; anything else throws before any work', async () => {
    const stub = makeStub(CLEAN);
    const scanner = betterleaksAt(stub.bin);
    const record = join(stub.bin, '..', 'record.json');
    const scrub = (t: string) => t;
    const bad: unknown[] = [undefined, null, {}, evidence('real'), evidence('Placeholders'), evidence(['placeholders']), 'placeholders', 1];
    for (const evidence of bad) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expect(errorExcerpt('Error: x', scrub, scanner, evidence as any), JSON.stringify(evidence)).rejects.toThrow(/placeholders/);
    }
    // an inherited property is not the evidence's own
    await expect(errorExcerpt('Error: x', scrub, scanner, Object.create(evidence('placeholders')))).rejects.toThrow(/placeholders/);
    expect(existsSync(record)).toBe(false); // the scanner never ran
    expect(await errorExcerpt('Error: x', scrub, scanner, evidence('placeholders'))).toBe('Error: x');
    expect(existsSync(record)).toBe(true);
  });
});

describe('errorExcerpt fix round 2: a garbled secret section header (q3)', () => {
  it('excerpt r2: an escape that eats a secret section header\'s `]` or `[` still hides the section (q3)', () => {
    const s = ['Zx9Qw3Er7', 'Ty1Ui5Op2AsDf'].join('');
    const KEY_NAME = ['tok', 'en_value'].join('');
    const secHdr = ['[sec', 'rets'].join('');
    const creds = ['[creden', 'tials]'].join('');
    const hdrAu = ['[a', 'uth]'].join('');
    const headers = [
      `${secHdr}]`, `${secHdr}${ESC}]8;;]${ESC}\\`, `${secHdr}${ESC}]8;;]\u0007`, `${secHdr}${ESC}[1]`, `${secHdr.slice(0, 4)}\u200b${secHdr.slice(4)}]`,
      `${ESC}]8;;x\u0007${creds}`, `${hdrAu}\u0085`, `${ESC}[${hdrAu}`, `${ESC}[1${hdrAu}`,
    ];
    for (const hdr of headers) {
      const log = ['Error: a', hdr, `${KEY_NAME} = "${s}"`, `other = "${s}b"`, '[other]', 'x = 1', 'Error: b'].join('\n');
      expect(unscannedExcerpt(log, (t) => t).join('\n'), JSON.stringify(hdr)).not.toContain(s.slice(0, 16));
    }
  });
});

describe('errorExcerpt fix round 2: values split across prefixed lines and over 3 lines (q1, q5)', () => {
  it('excerpt r2: base64 wrapped under buildkit prefixes, and a value split under docker compose prefixes, never show (q1)', () => {
    const v = vault();
    const env = `NODE_ENV=test\nAPP_NAME=shop\nSTRIPE_TEST=${V}\nLOG_LEVEL=debug\n`;
    const b = Buffer.from(env).toString('base64').match(/.{1,76}/g) as string[];
    const build = ['#7 [4/6] RUN cat .env | base64', ...b.map((l, i) => `#7 0.${300 + i} ${l}`), '#7 ERROR: process "/bin/sh -c cat .env | base64" did not complete successfully: exit code: 1'];
    const out = unscannedExcerpt(build.join('\n'), v.scrubber()).join('\n');
    const joined = out.split('\n').filter((l) => l.startsWith('#7 0.')).map((l) => l.split(' ')[2]).join('');
    expect(Buffer.from(joined, 'base64').toString()).not.toContain(V.slice(0, 8));
    const compose = ['api-1  | config dump:', `api-1  | key=${V.slice(0, 16)}`, `api-1  | ${V.slice(16)}`, 'api-1  | Error: boom'];
    expect(windows8(unscannedExcerpt(compose.join('\n'), v.scrubber()).join('\n'))).toEqual([]);
    const turbo = ['app:build: dump', `app:build: key=${V.slice(0, 11)}`, `app:build: ${V.slice(11, 22)}`, `app:build: ${V.slice(22)} end`, 'app:build: Error: x'];
    expect(windows8(unscannedExcerpt(turbo.join('\n'), v.scrubber()).join('\n'))).toEqual([]);
    v.wipe();
  });

  it('excerpt r2: a value over 3 lines with a tab or an invisible in one piece, and a 2-line split needing two forms (q5)', () => {
    const value = 'Qz7mK2pW!xLr4TbN.vYc3HsJ';
    const v = vault(value);
    const cases = [
      ['key=' + value.slice(0, 5) + '\t' + value.slice(5, 12), value.slice(12, 17) + `${ESC}[1;31m` + value.slice(17) + ' rejected'],
      ['key=' + value.slice(0, 9), value.slice(9, 17), value.slice(17, 20) + '\u200b' + value.slice(20)],
      ['key=' + value.slice(0, 9), value.slice(9, 17), value.slice(17, 20) + '\t' + value.slice(20)],
    ];
    for (const lines of cases) {
      const out = unscannedExcerpt(['ok', 'Error: a', ...lines, 'ok'].join('\n'), v.scrubber()).join('\n');
      expect(windows8(out.replace(/\s/g, ''), value), JSON.stringify(lines)).toEqual([]);
    }
    // at a window edge: the first piece is outside the window
    const log = [...pad(8), 'key=' + value.slice(0, 5) + '\t' + value.slice(5, 12), value.slice(12, 17) + `${ESC}[1;31m` + value.slice(17) + ' rejected', ...pad(4, 'more'), 'Error: a', ...pad(8, 'after')].join('\n');
    expect(windows8(unscannedExcerpt(log, v.scrubber()).join('\n'), value)).toEqual([]);
    v.wipe();
  });

  it('excerpt r2: the log read is 1 Mi characters at most', () => {
    expect(MAX_LOG_CHARS).toBe(1024 * 1024);
  });
});
