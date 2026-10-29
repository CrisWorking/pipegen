// Plan C Task C1b, fix round 2 (review-C1b-r1.md): R1-C1 belt (a uri with "!" from a secrets tool), R1-C2 (U+FFFD),
// the ASIA key shape (minor 1) and the segment check of secretShapedName (minor 3).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as core from '../src/ai/redact-core.js';
import { redact } from '../src/ai/redact.js';
import { normaliseUri, parseSarifText } from '../gate/src/sarif.js';

const DIR = join(import.meta.dirname, 'fixtures', 'sarif');
const WS = '/home/runner/work/fixture/fixture';
const sarif = (driver: string, uri: string) => JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: driver } }, results: [{ ruleId: 'github-pat', level: 'error', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 9 } } }] }] }] });

describe('R1-C2: a uri with U+FFFD is unmapped for every tool and every encoding', () => {
  it('normaliseUri', () => {
    for (const encoding of ['raw', 'percent', 'unmeasured'] as const) {
      for (const uri of ['k�.js', 'src/�/a.js', '�', 'src/a�b.js']) expect(normaliseUri(uri, { workspace: WS, encoding }), `${encoding} ${JSON.stringify(uri)}`).toBeUndefined();
    }
    expect(normaliseUri('src/é.js', { workspace: WS, encoding: 'raw' })).toBe('src/é.js');   // a valid non-ASCII name still maps
    expect(normaliseUri('src/%EF%BF%BD.js', { workspace: WS, encoding: 'percent' })).toBeUndefined();   // the same character, percent-encoded
  });
  it('the parser: betterleaks, gitleaks and an unmeasured tool all give an unmapped finding with no file', () => {
    for (const [driver, tool] of [['betterleaks', 'betterleaks'], ['gitleaks', 'gitleaks'], ['Hadolint', 'hadolint']] as const) {
      const f = parseSarifText(sarif(driver, 'k�.js'), tool, { workspace: WS }).findings[0];
      expect(f.file, tool).toBeUndefined();
      expect(f.uriUnmapped, tool).toBe(true);
    }
  });
});

describe('R1-C1 belt: a uri with "!" from a secrets tool is unmapped (an archive member path)', () => {
  it('betterleaks and gitleaks: unmapped; other tools: an ordinary name', () => {
    for (const tool of ['betterleaks', 'gitleaks'] as const) {
      for (const uri of ['x.zip!in/s.txt', 'a!b.js', 'outer.zip!in/inner.tar.gz!deep/t.txt', '!x']) {
        const f = parseSarifText(sarif(tool, uri), tool, { workspace: WS }).findings[0];
        expect(f.file, `${tool} ${uri}`).toBeUndefined();
        expect(f.uriUnmapped, `${tool} ${uri}`).toBe(true);
      }
    }
    expect(parseSarifText(sarif('Hadolint', 'docker/a!b/Dockerfile'), 'hadolint', { workspace: WS }).findings[0]).toMatchObject({ file: 'docker/a!b/Dockerfile', uriUnmapped: false });
    expect(parseSarifText(sarif('betterleaks', 'src/config.js'), 'betterleaks', { workspace: WS }).findings[0]).toMatchObject({ file: 'src/config.js' });
  });
  it('the real secrets fixtures still map their file', () => {
    for (const [file, tool] of [['betterleaks.sarif', 'betterleaks'], ['gitleaks.sarif', 'gitleaks']] as const) {
      expect(parseSarifText(readFileSync(join(DIR, file)), tool, { workspace: WS }).findings.every((f) => f.file === 'src/config.js'), tool).toBe(true);
    }
  });
});

describe('minor 1: AWS temporary keys (ASIA) and the other key id prefixes are token shapes', () => {
  const body = (n: number, seed: string) => seed.repeat(n).slice(0, n);
  const keys = ['AK' + 'IA' + 'QWERTY7654321ABC', 'AS' + 'IA' + 'QWERTY7654321ABC', 'AB' + 'IA' + 'QWERTY7654321ABC', 'AC' + 'CA' + 'QWERTY7654321ABC', 'A3' + 'TA' + 'QWERTY7654321ABC', 'AK' + 'IA' + '0189QWERTYABCDEF'];
  it('findSecretLike, redact and maskText all hide them', () => {
    for (const k of keys) {
      expect(core.findSecretLike(`x ${k} y`), k.slice(0, 4)).toContain('aws-access-key');
      expect(redact(`x ${k} y`), k.slice(0, 4)).toBe('x [REDACTED] y');
      expect(core.maskText(`x ${k} y`), k.slice(0, 4)).toBe('x [REDACTED] y');
    }
  });
  it('a random ASIA key is always masked (the review: 14% slipped through before)', () => {
    let seed = 12345;
    const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    for (let i = 0; i < 2000; i++) {
      let k = 'AS' + 'IA';
      for (let j = 0; j < 16; j++) k += alphabet[rnd() % alphabet.length];
      expect(core.maskText(`temp ${k} here`), k).not.toContain(k);
    }
    expect(body(3, 'ab')).toBe('aba');
  });
  it('ordinary words and short upper-case names are not touched', () => {
    for (const t of ['ASIA is a continent', 'ASIAN-MARKETS', 'ACCA', 'AKIA', 'AKIAIOSFODNN7EXAMPL', 'A3T is a prefix']) expect(core.maskText(t), t).toBe(t);
  });
});

describe('minor 3: secretShapedName', () => {
  it('still true for a token or an encoded token anywhere in the path, with the per-segment loop removed', () => {
    const gh = 'gh' + 'p_' + 'a'.repeat(36);
    for (const name of [`a/b/${gh}/c.js`, `${gh}`, `deep/${Buffer.from(gh).toString('base64')}.txt`, 'x/Zk3qP9xW2mT7vL5nR8cB4yH6/y']) expect(core.secretShapedName(name), name.slice(0, 12)).toBe(true);
    for (const name of ['src/lib/util.ts', 'docs/readme.md', 'a/b/c/d/e.txt']) expect(core.secretShapedName(name), name).toBe(false);
  });
});
