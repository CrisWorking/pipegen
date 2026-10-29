// C1b fix round 1 (review I3): the pure redaction core, shared by the AI bundler (redact.ts) and the gate.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import * as core from '../src/ai/redact-core.js';
import * as redactMod from '../src/ai/redact.js';
import { READ_LIMITS, regexSafe as limitsRegexSafe } from '../src/read/limits.js';
import { fake } from './helpers/secret-repo.js';

const root = resolve(import.meta.dirname, '..');

describe('redact-core (C1b fix round 1, I3)', () => {
  it('module graph: redact-core.ts is a leaf: no import of any kind (no node: module, no npm package, no other source file)', async () => {
    const r = await build({ entryPoints: [resolve(root, 'src/ai/redact-core.ts')], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent' });
    expect(Object.keys(r.metafile.inputs)).toEqual(['src/ai/redact-core.ts']);
    expect(r.metafile.inputs['src/ai/redact-core.ts'].imports).toEqual([]);
    expect(readFileSync(resolve(root, 'src/ai/redact-core.ts'), 'utf8')).not.toMatch(/^\s*import\s/m);
  });

  it('redact.ts re-exports the core: the same functions, so one tested list serves both sides', () => {
    expect(redactMod.redact).toBe(core.redact);
    expect(redactMod.findSecretLike).toBe(core.findSecretLike);
    expect(redactMod.highEntropyRuns).toBe(core.highEntropyRuns);
    expect(redactMod.decodedNamePieces).toBe(core.decodedNamePieces);
    expect(redactMod.LONG_LINE).toBe(core.LONG_LINE);
  });

  it('the core copy of regexSafe agrees with limits.ts (same limit, same answers)', () => {
    expect(core.MAX_REGEX_LINE_BYTES).toBe(READ_LIMITS.maxRegexLineBytes);
    for (const s of ['', 'a', 'a'.repeat(4096), 'a'.repeat(4097), 'é'.repeat(2048), 'é'.repeat(2049), '😀'.repeat(1024), '😀'.repeat(1025)]) expect(core.regexSafe(s), s.length.toString()).toBe(limitsRegexSafe(s));
  });

  it('maskText hides token shapes, JWTs, connection-string passwords, password-like assignments and high-entropy runs, and keeps plain text', () => {
    const pw = 'hunter' + '2' + 'Xq9vB';
    const conn = 'postgres' + '://' + 'app' + ':' + pw + '@' + 'db.internal/app';
    const entropic = 'Zk3' + 'qP9xW2' + 'mT7vL5nR8' + 'cB4yH6';   // 24 chars, letters and digits
    const values = [fake.githubClassic(), fake.awsKey(), fake.jwt(), fake.openaiKey(), fake.slackWebhook(), pw, entropic];
    const text = `a ${values[0]} b ${values[1]} c ${values[2]} d ${values[3]} e ${values[4]} f ${conn} g ${fake.assign('pass' + 'word', pw, ': ')} h ${entropic} i`;
    const out = core.maskText(text);
    for (const v of values) expect(out, v.slice(0, 4)).not.toContain(v);
    expect(out).toContain('[REDACTED]');
    expect(core.maskText('Dockerfile line 12: use COPY instead of ADD (DL3020)')).toBe('Dockerfile line 12: use COPY instead of ADD (DL3020)');
    expect(core.maskText('')).toBe('');
  });

  it('maskText hides the 128-hex value a semgrep message can start with, and a private key block', () => {
    const hex = 'a1b2c3d4e5f60718'.repeat(8);   // 128 hex
    expect(core.maskText(`${hex} Found a string literal assignment to a production Rails session secret`)).not.toContain(hex);
    const key = `${fake.keyBegin()}\n${fake.keyBody()}\n${fake.keyEnd()}`;
    expect(core.maskText(`before ${key} after`)).not.toContain(fake.keyBody());
  });

  it('a file name that holds a token shape, an encoded one or a high-entropy run is secret-shaped; ordinary names are not (secretShapedName)', () => {
    const gh = fake.githubClassic();
    expect(core.secretShapedName(`src/${gh}.js`)).toBe(true);                       // a known token shape
    expect(core.secretShapedName(`src/${Buffer.from(gh).toString('base64')}.txt`)).toBe(true);   // base64 of one (P48 decoding)
    expect(core.secretShapedName(`src/${Buffer.from(gh).toString('hex')}.txt`)).toBe(true);      // hex of one
    expect(core.secretShapedName(`src/${encodeURIComponent(fake.awsKey())}/x.js`)).toBe(true);
    expect(core.secretShapedName('src/Zk3qP9xW2mT7vL5nR8cB4yH6.js')).toBe(true);    // the entropy belt
    expect(core.secretShapedName(`conf/${fake.jwt()}`)).toBe(true);
    for (const ok of ['src/app.js', 'src/%61pp.js', 'src/lib/password.js', 'docs/token-guide.md', 'a b/c.txt', 'src/components/UserProfileCardHeader.tsx', 'package-lock.json']) expect(core.secretShapedName(ok), ok).toBe(false);
  });
});
