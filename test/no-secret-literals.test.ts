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
      // G15a round 3: Scorecard's real SARIF carries each check's help text as one JSON string over 4 KB, which redact() hides whole
      // (LONG_LINE) without scanning; split at its escaped line breaks so every piece is still scanned (each under 4 KB)
      // Three fragments of Scorecard's own help text look secret-like to redact() and are excused by exact text, nothing else:
      // the admin-token note before `DismissStaleReviews`, a GitHub docs anchor and an Azure docs slug (all built at runtime here).
      // (and the policy's Token-Permissions check name, whose next lines read as a value)
      const SCORECARD_PROSE = [['Token', 'Permissions:'].join('-'), ['admin to', 'ken: `DismissStaleReviews`'].join(''), ['understanding', 'the', 'risk', 'of', 'script', 'injections'].join('-'), ['3', 'ways', 'to', 'mitigate', 'risk', 'using', 'private', 'package', 'feeds'].join('-')];
      // Real scanner output (test/fixtures/sarif, C1a) holds two benign strings that look like secrets to redact(): osv-scanner's
      // empty `redactionTokens` array and trivy's already-masked match line. Nothing else is excused.
      const text = buf.toString('utf8').replaceAll('"redactionTokens": [],', '').replaceAll('GITHUB_TOKEN=****************************************', 'masked match');
      // Plan P PL-A5: the audit report's JSON golden files carry the report's own field names (the secret names a workflow uses, the secret-like files found,
      // the secret check's wording, the token counts of the AI cost). redact() reads `<name with secret/token>: <value>` as a secret, so only those exact keys are
      // excused, and only in those two files; every value is still scanned.
      const REPORT_KEYS = ['secretsUsed', 'secretsBaseline', 'secretsInTree', 'secretCheck', 'aiTokens', 'inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheWriteTokens'];
      const reportJson = /^test\/__snapshots__\/audit-render\.[a-z-]+\.json$/.test(f);
      const unkeyed = reportJson ? REPORT_KEYS.reduce((t, k) => t.replaceAll(`"${k}":`, '"field":'), text) : text;
      // G15a round 5: the real ZAP reports (test/fixtures/zap) carry ZAP's own HTML help text (an alert's `solution`) as one JSON string
      // over 4 KB; split it at its paragraph ends so every piece is still scanned (each under 4 KB). Nothing is excused.
      const scanned = f.startsWith('test/fixtures/scorecard/') ? SCORECARD_PROSE.reduce((t, x) => t.replaceAll(x, 'scorecard prose'), text.replaceAll('\\n', '\n'))
        : f.startsWith('test/fixtures/zap/') ? text.replaceAll('</p>', '</p>\n') : unkeyed;
      if (scanned !== text) expect(Math.max(...scanned.split('\n').map((l) => l.length)), f).toBeLessThan(4096);
      // ZAP's reports put `"@name": "http://<host>:<port>",` right before `"@host": …` on the next line, and redact() reads a URL's
      // authority across a line break up to that '@' (over-redaction, the safe side); so the ZAP reports are scanned line by line
      const pieces = f.startsWith('test/fixtures/zap/') ? scanned.split('\n') : [scanned];
      for (const piece of pieces) expect(redact(piece) === piece, `a redact pattern matches ${f}`).toBe(true);
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
