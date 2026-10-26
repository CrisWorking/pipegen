import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findSecretLike, redact } from '../src/ai/redact.js';
import { isBinary } from '../src/read/limits.js';
import { fake } from './helpers/secret-repo.js';

const root = resolve(import.meta.dirname, '..');

/** Every regular file under `dir` (repo-relative, forward slashes), for when git is not available (a tarball, no git). */
function walkFiles(dir: string): string[] {
  return readdirSync(join(root, dir), { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => relative(root, join(e.parentPath, e.name)).split('\\').join('/'))
    .sort();
}

/** Committed files plus new files not yet committed (not ignored), so the check also covers the working tree. Without git, a walk. */
function repoFiles(dir: string): string[] {
  try {
    const out = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', dir], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out.split('\0').filter(Boolean);
  } catch {
    return walkFiles(dir);
  }
}

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
