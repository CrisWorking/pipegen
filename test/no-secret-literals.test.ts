import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findSecretLike, redact } from '../src/ai/redact.js';
import { isBinary } from '../src/read/limits.js';
import { repoFiles, root, walkFiles } from './helpers/repo-files.js';
import { fake } from './helpers/secret-repo.js';

describe('fixtures', () => {
  it('fixtures: without git (not installed, or no .git) the file list falls back to a walk of the folder', () => {
    const path = process.env.PATH;
    process.env.PATH = ''; // git cannot be found
    let files: string[];
    try {
      files = ['test', 'src', 'data'].flatMap(repoFiles);
    } finally {
      process.env.PATH = path;
    }
    expect(files).toEqual(expect.arrayContaining(['test/helpers/secret-repo.ts', 'src/ai/redact.ts', 'data/gitleaks-bundle.toml']));
    for (const dir of ['test', 'src', 'data']) expect(walkFiles(dir)).toEqual(expect.arrayContaining(repoFiles(dir)));
  });

  it('fixtures: secret-like strings built at runtime; no redact pattern matches any committed file under test/', () => {
    // the runtime-built values really look like secrets, and each one is fully redacted
    for (const v of [fake.githubClassic(), fake.githubPat(), fake.stripeKey(), fake.openaiKey(), fake.awsKey(), fake.slackBot(), fake.jwt(), fake.slackWebhook(), fake.googleKey(), fake.npmPublish()]) {
      expect(redact(v), v.slice(0, 3)).toBe('[REDACTED]');
    }
    const testFiles = repoFiles('test');
    expect(testFiles).toContain('test/helpers/secret-repo.ts');
    for (const f of testFiles) {
      const buf = readFileSync(join(root, f));
      if (isBinary(buf)) continue;
      // Real scanner output (test/fixtures/sarif, C1a) holds two benign strings that look like secrets to redact(): osv-scanner's
      // empty `redactionTokens` array and trivy's already-masked match line. Nothing else is excused.
      const text = buf.toString('utf8').replaceAll('"redactionTokens": [],', '').replaceAll('GITHUB_TOKEN=****************************************', 'masked match');
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
