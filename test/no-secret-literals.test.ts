import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findSecretLike, redact } from '../src/ai/redact.js';
import { isBinary } from '../src/read/limits.js';
import { fake } from './helpers/secret-repo.js';

const root = resolve(import.meta.dirname, '..');

/** Committed files plus new files not yet committed (not ignored), so the check also covers the working tree. */
function repoFiles(dir: string): string[] {
  const out = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', dir], { cwd: root, encoding: 'utf8' });
  return out.split('\0').filter(Boolean);
}

describe('fixtures', () => {
  it('fixtures: secret-like strings built at runtime; no redact pattern matches any committed file under test/', () => {
    // the runtime-built values really are secret-like: each one is fully redacted
    for (const v of [fake.githubClassic(), fake.githubPat(), fake.stripeKey(), fake.openaiKey(), fake.awsKey(), fake.slackBot(), fake.jwt(), fake.slackWebhook(), fake.googleKey(), fake.npmAuth()]) {
      expect(redact(v), v.slice(0, 3)).toBe('[REDACTED]');
    }
    const testFiles = repoFiles('test');
    expect(testFiles).toContain('test/helpers/secret-repo.ts');
    for (const f of testFiles) {
      const buf = readFileSync(join(root, f));
      if (isBinary(buf)) continue;
      const text = buf.toString('utf8');
      expect(redact(text) === text, `a redact pattern matches ${f}`).toBe(true);
    }
  });

  it('fixtures: src/ and data/ hold no secret-like literal', () => {
    // the check itself finds secret-like text, and reports rule names only, never the value
    const hit = findSecretLike(`a ${fake.awsKey()} b ${fake.keyBegin()}`);
    expect(hit.length).toBe(2);
    expect(hit.join(' ')).not.toContain(fake.awsKey());
    const files = [...repoFiles('src'), ...repoFiles('data')];
    expect(files).toContain('data/gitleaks-bundle.toml');
    expect(files).toContain('src/ai/redact.ts');
    for (const f of files) {
      const text = readFileSync(join(root, f), 'utf8');
      expect(findSecretLike(text), f).toEqual([]);
    }
  });
});
