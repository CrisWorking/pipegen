import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import picomatch from 'picomatch';
import { afterEach, describe, expect, it } from 'vitest';
import {
  bundleCode, bundleText, EXCLUDED_PATTERNS, GitleaksError, GitleaksRequiredError, gitleaksConfigPath,
  isBinary, redact, scrubKnownValues, type CodeBundle,
} from '../src/ai/redact.js';
import { isBinary as limitsIsBinary } from '../src/read/limits.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { fake, makeSecretRepo } from './helpers/secret-repo.js';

const root = resolve(import.meta.dirname, '..');
const R = '[REDACTED]';

afterEach(() => cleanupRepos());

// ---------- gitleaks stub ----------
// A small node script standing in for the pinned gitleaks binary. It records what it was given
// (argv, cwd, env names, the scanned files) and then runs `body` to write a report and exit.
interface StubRecord { argv: string[]; cwd: string; envKeys: string[]; files: Record<string, string>; src: string }

function makeStub(body: string): { bin: string; record: () => StubRecord } {
  const dir = makeTempDir();
  const rec = join(dir, 'record.json');
  const bin = join(dir, 'gitleaks-stub.cjs');
  writeFileSync(bin, `#!/usr/bin/env node
const fs = require('fs'), path = require('path');
const argv = process.argv.slice(2);
const src = argv[argv.indexOf('--source') + 1];
const report = argv[argv.indexOf('--report-path') + 1];
const files = {};
for (const f of fs.readdirSync(src)) files[f] = fs.readFileSync(path.join(src, f), 'utf8');
fs.writeFileSync(${JSON.stringify(rec)}, JSON.stringify({ argv, cwd: process.cwd(), envKeys: Object.keys(process.env), files, src }));
function findingsFor(value, match) {
  const out = [];
  for (const [f, text] of Object.entries(files)) {
    const lines = text.split('\\n');
    lines.forEach((l, i) => { if (l.includes(value)) out.push({ File: path.join(src, f), StartLine: i + 1, EndLine: i + 1, Match: match || value, "Secret": value }); });
  }
  return out;
}
${body}
`);
  chmodSync(bin, 0o755);
  return { bin, record: () => JSON.parse(readFileSync(rec, 'utf8')) as StubRecord };
}

const CLEAN = `fs.writeFileSync(report, '[]'); process.exit(0);`;
const reportValue = (value: string) => `const f = findingsFor(${JSON.stringify(value)}); fs.writeFileSync(report, JSON.stringify(f)); process.exit(f.length ? 1 : 0);`;

const paths = (b: CodeBundle) => b.files.map((f) => f.path).sort();
const allText = (b: CodeBundle) => b.files.map((f) => f.content).join('\n');

describe('bundle: exclusions', () => {
  it('bundle: excludes .env and .pem', async () => {
    const { dir } = makeSecretRepo();
    const b = await bundleCode(dir);
    expect(paths(b)).not.toContain('.env');
    expect(paths(b)).not.toContain('config/dev.pem');
    expect(paths(b)).toContain('src/app.ts');
  });

  it('bundle: excludes tfstate, tfvars, .npmrc, .netrc, p12/pfx/jks and kubeconfig', async () => {
    const { dir, values } = makeSecretRepo();
    writeIn(dir, 'infra/prod.tfstate.backup', '{}\n');
    writeIn(dir, '.netrc', 'machine example.com login me\n');
    writeIn(dir, 'certs/app.pfx', 'pfx\n');
    writeIn(dir, 'certs/app.jks', 'jks\n');
    writeIn(dir, 'deploy/kubeconfig', 'clusters: []\n');
    const b = await bundleCode(dir);
    const got = paths(b);
    for (const p of ['infra/prod.tfstate', 'infra/prod.tfstate.backup', 'infra/prod.tfvars', '.npmrc', '.netrc', 'certs/app.p12', 'certs/app.pfx', 'certs/app.jks', 'deploy/kubeconfig', '.kube/config']) {
      expect(got, p).not.toContain(p);
    }
    expect(got).toContain('infra/main.tf');
    const text = allText(b);
    for (const v of values) expect(text).not.toContain(v);
  });

  it('EXCLUDED_PATTERNS: every excluded pattern above is listed, and bundleCode excludes exactly these', async () => {
    const required = [
      '**/.env*', '!**/.env.example', '!**/.env.sample', '**/*.pem', '**/*.key', '**/id_rsa*', '**/*secret*', '**/*secret*/**',
      '**/*.tfstate', '**/*.tfstate.backup', '**/*.tfvars', '**/.npmrc', '**/.netrc', '**/*.p12', '**/*.pfx', '**/*.jks',
      '**/kubeconfig', '**/.kube/config',
      '**/package-lock.json', '**/npm-shrinkwrap.json', '**/yarn.lock', '**/pnpm-lock.yaml', '**/bun.lockb', '**/bun.lock',
      '**/poetry.lock', '**/uv.lock', '**/Pipfile.lock', '**/Cargo.lock', '**/Gemfile.lock', '**/composer.lock', '**/go.sum',
      '**/node_modules/**', '**/.git/**', '**/.venv/**', '**/dist/**', '**/build/**', '**/vendor/**', '**/target/**',
    ];
    for (const p of required) expect(EXCLUDED_PATTERNS, p).toContain(p);

    const excluded = [
      '.env', '.env.local', 'api/.env.production', '.envrc', 'k.pem', 'a/server.key', 'id_rsa', '.ssh/id_rsa.pub',
      'config/secrets.yml', 'MY_SECRET.txt', 'secret/x.ts', 'Secrets/y.ts', 'secrets/.env.example',
      'x.tfstate', 'x.tfstate.backup', 'x.tfvars', '.npmrc', 'sub/.netrc', 'a.p12', 'a.pfx', 'a.jks', 'kubeconfig', '.kube/config',
      '.env.d/app.conf', 'id_dsa', 'keys/id_ecdsa', 'id_ed25519.pub', 'x.tfvars.json', 'kubeconfig.yaml', 'prod.kubeconfig', '.kube/cache/d.json',
      'package-lock.json', 'web/npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'poetry.lock', 'uv.lock',
      'Pipfile.lock', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'go.sum',
      'node_modules/x/index.js', '.git/config', '.venv/lib/x.py', 'dist/out.js', 'build/x.js', 'vendor/x.php', 'target/x.rs',
    ];
    const kept = ['.env.example', '.env.sample', 'api/.env.example', 'src/app.ts', 'README.md', 'config/settings.json', 'keys.ts', 'package.json', 'go.mod'];
    // every positive pattern is exercised by at least one sample
    for (const p of EXCLUDED_PATTERNS.filter((x) => !x.startsWith('!'))) {
      expect(excluded.some((f) => picomatch(p, { dot: true, nocase: true })(f)), p).toBe(true);
    }
    const dir = makeTempDir();
    for (const f of [...excluded, ...kept]) writeIn(dir, f, `// ${f}\n`);
    const b = await bundleCode(dir);
    expect(paths(b)).toEqual([...kept].sort());
  });

  it('EXCLUDED_PATTERNS: globs only; binaries skipped by isBinary(), not by a pattern', async () => {
    for (const p of EXCLUDED_PATTERNS) {
      expect(typeof p).toBe('string');
      expect(p.length).toBeGreaterThan(0);
      expect(p).not.toMatch(/\b(binary|binaries)\b/i);
      expect(p.startsWith('!') ? p.slice(1) : p).toMatch(/^\*\*\//); // matches at any depth
    }
    expect(Object.isFrozen(EXCLUDED_PATTERNS)).toBe(true);
    expect(isBinary).toBe(limitsIsBinary);
    const dir = makeTempDir();
    writeIn(dir, 'src/app.ts', 'export {};\n');
    writeFileSync(join(dir, 'src/image.ts'), Buffer.from([0x41, 0x00, 0x42]));
    const b = await bundleCode(dir);
    expect(paths(b)).toEqual(['src/app.ts']);
    expect(b.notes.join('\n')).toMatch(/binary/i);
    expect(b.notes.join('\n')).toContain('src/image.ts');
  });

  it('bundle: keeps .env.example', async () => {
    const { dir } = makeSecretRepo();
    writeIn(dir, '.env.sample', 'A=\n');
    const b = await bundleCode(dir);
    expect(paths(b)).toContain('.env.example');
    expect(paths(b)).toContain('.env.sample');
    expect(paths(b)).not.toContain('.env');
  });

  it('bundle: symlink to a file outside the repo is skipped, never read', async () => {
    const outside = makeTempDir();
    const marker = 'outside-' + 'marker-7731';
    writeIn(outside, 'data.txt', marker + '\n');
    const dir = makeTempDir();
    writeIn(dir, 'src/app.ts', 'export {};\n');
    symlinkSync(join(outside, 'data.txt'), join(dir, 'src/linked.ts'));
    symlinkSync(outside, join(dir, 'linkdir'));
    const b = await bundleCode(dir);
    expect(paths(b)).toEqual(['src/app.ts']);
    expect(allText(b)).not.toContain(marker);
    const notes = b.notes.join('\n');
    expect(notes).toMatch(/symbolic link/);
    expect(notes).toContain('src/linked.ts');
    expect(notes).not.toContain(marker);
  });

  it('bundle: roots limit the files; an absolute root or one with .. is refused', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'api/a.ts', 'a\n');
    writeIn(dir, 'apix/b.ts', 'b\n');
    writeIn(dir, 'web/c.ts', 'c\n');
    expect(paths(await bundleCode(dir, { roots: ['api', './web/'] }))).toEqual(['api/a.ts', 'web/c.ts']);
    await expect(bundleCode(dir, { roots: ['../x'] })).rejects.toThrow(/root/i);
    await expect(bundleCode(dir, { roots: ['api/../../x'] })).rejects.toThrow(/root/i);
    await expect(bundleCode(dir, { roots: ['/etc'] })).rejects.toThrow(/root/i);
  });
});

describe('redact', () => {
  it('redact: github token in package.json replaced', () => {
    const { dir } = makeSecretRepo();
    const text = readFileSync(join(dir, 'package.json'), 'utf8');
    const out = redact(text);
    expect(out).not.toContain(fake.githubClassic());
    expect(out).toContain(`GH_AUTH=${R} npm publish`);
    expect(out).toContain('"start": "node src/app.ts"');
  });

  it('redact: aws key, github pat, slack token and sk- key replaced', () => {
    for (const v of [fake.awsKey(), fake.githubPat(), fake.slackBot(), fake.openaiKey()]) {
      expect(redact(`x ${v} y`), v.slice(0, 4)).toBe(`x ${R} y`);
    }
  });

  it('redact: stripe secret key replaced', () => {
    const k = fake.stripeKey();
    expect(redact(`const stripe = new Stripe('${k}');`)).toBe(`const stripe = new Stripe('${R}');`);
    const t = 'sk' + '_test_' + 'Q'.repeat(12);
    expect(redact(t)).toBe(R);
  });

  // The name is joined at runtime so this file holds no literal connection string with a password.
  it('redact: postgres:/' + '/user:pass@host keeps user and host, hides pass', () => {
    const url = 'postgres' + '://user:' + 'pa55-word' + '@db.example.com:5432/app';
    expect(redact(`DATABASE_URL=${url}`)).toBe('DATABASE_URL=postgres' + `://user:${R}@db.example.com:5432/app`);
    const redis = 'redis' + '://default:' + 'r3dis' + '@cache:6379';
    expect(redact(redis)).toBe('redis' + `://default:${R}@cache:6379`);
    expect(redact('see https://example.com/docs for help')).toBe('see https://example.com/docs for help');
  });

  it('redact: jwt, slack webhook url, AIza key and npm_ token replaced', () => {
    const { dir } = makeSecretRepo();
    const cfg = redact(readFileSync(join(dir, 'src/config.ts'), 'utf8'));
    expect(cfg).not.toContain(fake.jwt());
    expect(cfg).not.toContain(fake.slackWebhook());
    expect(cfg).toBe(`export const session = '${R}';\nexport const hook = '${R}';\n`);
    expect(redact(`k=${fake.googleKey()};`)).toBe(`k=${R};`);
    expect(redact(`//registry/:_x=${fake.npmAuth()}`)).toBe(`//registry/:_x=${R}`);
  });

  it('redact: password/secret/token/api_key assignments lose only the value', () => {
    for (const name of ['pass' + 'word', 'PASS' + 'WD', 'db_sec' + 'ret', 'Tok' + 'en', 'api' + '_key', 'API' + 'KEY', 'api' + '-key']) {
      expect(redact(fake.assign(name, 'hunter2'))).toBe(fake.assign(name, R));
      expect(redact('  ' + fake.assign(name, ' "hunter2" # note', ':'))).toBe('  ' + fake.assign(name, ` ${R} # note`, ':'));
    }
    expect(redact('const x = 1;\nreturn tokens.length;')).toBe('const x = 1;\nreturn tokens.length;');
  });

  it('redact: private key block replaced, text around it kept', () => {
    const text = `before\n${fake.keyBegin()}\n${fake.keyBody()}\n${fake.keyBody()}\n${fake.keyEnd()}\nafter\n`;
    expect(redact(text)).toBe(`before\n${R}\nafter\n`);
    const inline = `const k = "${fake.keyBegin()}\\n${fake.keyBody()}\\n${fake.keyEnd()}";`;
    expect(redact(inline)).toBe(`const k = "${R}";`);
  });

  it('redact: unterminated private key block redacted to end', () => {
    const text = `before\n${fake.keyBegin()}\n${fake.keyBody()}\n${fake.keyBody()}\nafter\nmore\n`;
    const out = redact(text);
    expect(out).toBe(`before\n${R}`);
    expect(out).not.toContain(fake.keyBody());
    expect(out).not.toContain('after');
  });

  it('redact: line over 4 KB replaced, never sent', () => {
    const long = 'x'.repeat(5000) + fake.githubClassic();
    const out = redact(`first\n${long}\nlast`);
    expect(out).toBe('first\n[REDACTED: line too long]\nlast');
    // a key block that starts on an over-long line is still found and redacted
    const hidden = `${'y'.repeat(5000)}${fake.keyBegin()}\n${fake.keyBody()}\n${fake.keyEnd()}\nafter`;
    const out2 = redact(hidden);
    expect(out2).not.toContain(fake.keyBody());
    expect(out2).toBe('[REDACTED: line too long]\nafter');
  });
});

describe('scrubKnownValues', () => {
  it('scrubKnownValues: plain, base64 and url-encoded forms removed', () => {
    const v = 'k>>>???y tenant&id=1';
    const b64 = Buffer.from(v).toString('base64');
    const url = b64.replace(/\+/g, '-').replace(/\//g, '_');
    expect(url).not.toBe(b64); // the value was chosen so the URL-safe form differs
    expect(b64.endsWith('=')).toBe(true);
    const forms = [v, b64, b64.replace(/=+$/, ''), url, url.replace(/=+$/, ''), encodeURIComponent(v)];
    const text = forms.map((f, i) => `f${i}:${f}:end`).join('\n');
    const out = scrubKnownValues(text, [v]);
    for (const f of forms) expect(out).not.toContain(f);
    expect(out).toBe(forms.map((_, i) => `f${i}:${R}:end`).join('\n'));
  });

  it('scrubKnownValues: empty value ignored, other text unchanged', () => {
    expect(scrubKnownValues('hello world\n', ['', '   ', '\n'])).toBe('hello world\n');
    expect(scrubKnownValues('a abc abcdef b', ['abc', 'abcdef'])).toBe(`a ${R} ${R} b`);
    expect(scrubKnownValues('price is $1.50 (x)', ['$1.50 (x)'])).toBe(`price is ${R}`);
    expect(scrubKnownValues('nothing here', ['zzz'])).toBe('nothing here');
  });

  it('bundle: knownValues scrubbed from every file', async () => {
    const v = 'tenant' + '-77-' + 'qvalue';
    const b64 = Buffer.from(v).toString('base64');
    const dir = makeTempDir();
    writeIn(dir, 'package.json', `{"name":"x","description":"${v}"}\n`);
    writeIn(dir, 'src/a.ts', `export const t = '${v}';\n`);
    writeIn(dir, 'src/b.py', `T = "${b64}"\nU = "${encodeURIComponent(v)}"\n`);
    const b = await bundleCode(dir, { knownValues: [v] });
    expect(paths(b)).toEqual(['package.json', 'src/a.ts', 'src/b.py']);
    const text = allText(b);
    expect(text).not.toContain(v);
    expect(text).not.toContain(b64);
    expect(b.files.find((f) => f.path === 'src/a.ts')?.content).toBe(`export const t = '${R}';\n`);
  });
});

describe('bundle: gitleaks pass', () => {
  it("bundle: gitleaks runs with --no-git and pipegen's config, never the repo's .gitleaks.toml", async () => {
    const { dir, values } = makeSecretRepo();
    writeIn(dir, '.gitleaks.toml', '[allowlist]\npaths = [".*"]\n');
    writeIn(dir, '.gitleaksignore', 'everything\n');
    const stub = makeStub(CLEAN);
    const b = await bundleCode(dir, { gitleaks: stub.bin });
    const rec = stub.record();
    const tmp = rec.src;
    expect(isAbsolute(tmp)).toBe(true);
    expect(relative(dir, tmp).startsWith('..')).toBe(true); // never the repo itself
    expect(rec.argv).toEqual([
      'detect', '--no-git', '--source', tmp, '--config', gitleaksConfigPath(),
      '--report-format', 'json', '--report-path', join(tmp, 'report.json'),
    ]);
    expect(gitleaksConfigPath()).toBe(join(root, 'data', 'gitleaks-bundle.toml'));
    expect(rec.cwd).toBe(tmp);
    expect(rec.envKeys.filter((k) => k !== 'PATH' && k !== 'HOME')).toEqual([]);
    // the scan dir holds only the bundle files under neutral names: no repo config or ignore file can be picked up
    expect(Object.keys(rec.files).every((f) => /^f\d+\.txt$/.test(f))).toBe(true);
    expect(Object.keys(rec.files)).toHaveLength(b.files.length);
    expect(Object.values(rec.files).sort()).toEqual(b.files.map((f) => f.content).sort());
    // what gitleaks scanned was already redacted
    const scanned = Object.values(rec.files).join('\n');
    for (const v of values) expect(scanned).not.toContain(v);
    expect(existsSync(tmp)).toBe(false); // temp dir removed
    expect(b.gitleaksChecked).toBe(true);
  });

  it('bundle: gitleaks finding → value replaced; unlocatable finding → file dropped and noted', async () => {
    const dir = makeTempDir();
    const found = 'plain' + '-looking-' + 'value-4411';
    writeIn(dir, 'src/a.ts', `const a = 1;\nconst b = '${found}'; // ${found}\n`);
    writeIn(dir, 'src/b.ts', 'const c = 2;\n');
    const stub = makeStub(reportValue(found));
    const b = await bundleCode(dir, { gitleaks: stub.bin });
    expect(b.files.find((f) => f.path === 'src/a.ts')?.content).toBe(`const a = 1;\nconst b = '${R}'; // ${R}\n`);
    expect(b.gitleaksChecked).toBe(true);

    const lost = 'unlocatable' + '-marker';
    writeIn(dir, 'src/b.ts', `const c = '${lost}';\n`);
    const stub2 = makeStub(`
      const f = findingsFor(${JSON.stringify(lost)}).map((x) => ({ ...x, "Secret": 'not-in-the-file', Match: 'nope' }));
      fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b2 = await bundleCode(dir, { gitleaks: stub2.bin });
    expect(paths(b2)).toEqual(['src/a.ts']);
    expect(allText(b2)).not.toContain(lost);
    const notes = b2.notes.join('\n');
    expect(notes).toContain('src/b.ts');
    expect(notes).toMatch(/gitleaks/);
    expect(notes).not.toContain(lost);
    expect(b2.gitleaksChecked).toBe(true);
  });

  it('bundle: gitleaks error → bundle not returned, error raised', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'export {};\n');
    const stub = makeStub(`process.stderr.write('boom'); process.exit(2);`);
    await expect(bundleCode(dir, { gitleaks: stub.bin })).rejects.toBeInstanceOf(GitleaksError);
    expect(existsSync(stub.record().src)).toBe(false);
  });

  it('bundle: gitleaks error on timeout or bad exit code → error raised', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'export {};\n');
    const slow = makeStub(`setTimeout(() => {}, 600000);`);
    await expect(bundleCode(dir, { gitleaks: slow.bin, gitleaksTimeoutMs: 500 })).rejects.toThrow(/gitleaks/i);
    expect(existsSync(slow.record().src)).toBe(false);
    for (const body of [
      `process.exit(3);`,
      `process.kill(process.pid, 'SIGKILL');`,
      `process.exit(1);`, // leaks reported but no report file
      `fs.writeFileSync(report, '{"not":"an array"}'); process.exit(1);`,
      `fs.writeFileSync(report, 'not json'); process.exit(1);`,
      `fs.writeFileSync(report, '[{"File": 7}]'); process.exit(1);`,
      `process.exit(0);`, // clean exit but no report
    ]) {
      const stub = makeStub(body);
      await expect(bundleCode(dir, { gitleaks: stub.bin }), body).rejects.toBeInstanceOf(GitleaksError);
    }
    await expect(bundleCode(dir, { gitleaks: join(makeTempDir(), 'missing-gitleaks') })).rejects.toBeInstanceOf(GitleaksError);
    await expect(bundleCode(dir, { gitleaks: 'gitleaks' })).rejects.toBeInstanceOf(GitleaksError); // never looked up on PATH
  });

  it('bundle: gitleaks report pointing outside the temp dir is ignored and the file dropped', async () => {
    const dir = makeTempDir();
    const v = 'outside' + '-reported-' + 'value';
    writeIn(dir, 'src/a.ts', `const a = '${v}';\n`);
    writeIn(dir, 'src/b.ts', 'const b = 2;\n');
    const stub = makeStub(`
      const f = findingsFor(${JSON.stringify(v)}).map((x) => ({ ...x, File: src + '/../' + path.basename(x.File) }));
      fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b = await bundleCode(dir, { gitleaks: stub.bin });
    expect(paths(b)).toEqual(['src/b.ts']);
    expect(allText(b)).not.toContain(v);
    expect(b.notes.join('\n')).toContain('src/a.ts');
    expect(b.notes.join('\n')).not.toContain(v);
    expect(b.gitleaksChecked).toBe(true);
  });

  it('bundle: clean gitleaks pass → gitleaksChecked true', async () => {
    const { dir } = makeSecretRepo();
    const b = await bundleCode(dir, { gitleaks: makeStub(CLEAN).bin });
    expect(b.gitleaksChecked).toBe(true);
    expect(b.notes.join('\n')).toMatch(/gitleaks/);
    expect(bundleText(b)).toContain('--- src/app.ts ---');
  });

  it('bundle: no gitleaks path → gitleaksChecked false and noted (counting only)', async () => {
    const { dir } = makeSecretRepo();
    const b = await bundleCode(dir);
    expect(b.gitleaksChecked).toBe(false);
    expect(b.notes.join('\n')).toMatch(/gitleaks was not run/i);
    expect(b.files.length).toBeGreaterThan(0);
    expect(b.bytes).toBe(b.files.reduce((n, f) => n + Buffer.byteLength(f.content), 0));
  });

  it('bundle: gitleaks config path resolves in dev and from the build', () => {
    const dev = gitleaksConfigPath();
    expect(dev).toBe(join(root, 'data', 'gitleaks-bundle.toml'));
    expect(existsSync(dev)).toBe(true);
    const toml = readFileSync(dev, 'utf8');
    expect(toml).toMatch(/^\s*useDefault\s*=\s*true/m);
    expect(toml).not.toMatch(/^\s*\[\[?\s*(rules\.)?allowlists?\s*\]\]?/m); // no allowlist a repo could use to opt out

    // Built like dist/cli/main.js (same depth below the package root), the bundled code finds the same file.
    const out = join(root, `.probe-build-${process.pid}`);
    try {
      execFileSync('npx', ['tsup', '--no-config', 'test/helpers/config-probe.ts', '--format', 'esm', '--platform', 'node', '--target', 'node24', '--out-dir', join(out, 'cli')], { cwd: root, stdio: 'pipe' });
      const printed = execFileSync('node', [join(out, 'cli', 'config-probe.js')], { encoding: 'utf8' }).trim();
      expect(printed).toBe(dev);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
    // and the npm package ships it next to dist/
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { files: string[] };
    expect(pkg.files).toContain('data');
    // (retried: the package test rebuilds dist/ in parallel, which can briefly remove files npm is reading)
    const pack = () => execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    let raw = '';
    for (let attempt = 1; ; attempt++) {
      try {
        raw = pack();
        break;
      } catch (e) {
        if (attempt >= 3) throw e;
      }
    }
    const packed = JSON.parse(raw) as { files: { path: string }[] }[];
    expect(packed[0].files.map((f) => f.path)).toContain('data/gitleaks-bundle.toml');
  });
});

describe('bundleText', () => {
  it('bundleText: bundle without the gitleaks pass → GitleaksRequiredError, nothing to send', async () => {
    const { dir } = makeSecretRepo();
    const unchecked = await bundleCode(dir);
    expect(() => bundleText(unchecked)).toThrow(GitleaksRequiredError);
    // a hand-made or copied bundle claiming the pass is refused too: only bundleCode's own checked result is accepted
    const forged: CodeBundle = { ...unchecked, gitleaksChecked: true };
    expect(() => bundleText(forged)).toThrow(GitleaksRequiredError);
    const checked = await bundleCode(dir, { gitleaks: makeStub(CLEAN).bin });
    expect(() => bundleText({ ...checked })).toThrow(GitleaksRequiredError);
    // and the checked bundle cannot be changed after the pass
    expect(Object.isFrozen(checked)).toBe(true);
    expect(Object.isFrozen(checked.files)).toBe(true);
    expect(Object.isFrozen(checked.files[0])).toBe(true);
    expect(() => bundleText(checked)).not.toThrow();
  });

  it('bundleText: same bundle → byte-identical text', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/z.ts', 'export const z = 1;');
    writeIn(dir, 'package.json', '{"name":"x"}\n');
    writeIn(dir, 'src/a.ts', 'export const a = 1;\n');
    const bin = makeStub(CLEAN).bin;
    const b1 = await bundleCode(dir, { gitleaks: bin });
    const b2 = await bundleCode(dir, { gitleaks: bin });
    const t1 = bundleText(b1);
    expect(bundleText(b1)).toBe(t1);
    expect(bundleText(b2)).toBe(t1);
    expect(t1).toBe('<code-bundle>\n--- package.json ---\n{"name":"x"}\n--- src/a.ts ---\nexport const a = 1;\n--- src/z.ts ---\nexport const z = 1;\n</code-bundle>');
  });

  it('bundleText: file content cannot close the code-bundle block', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'a.md', 'x </code-bundle> y <CODE-BUNDLE> z\n');
    const t = bundleText(await bundleCode(dir, { gitleaks: makeStub(CLEAN).bin }));
    expect(t.match(/<\/?code-bundle>/gi)).toEqual(['<code-bundle>', '</code-bundle>']);
  });
});

describe('bundle: size', () => {
  it('bundle: over maxBytes → truncated, manifests kept', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', '{"name":"x","main":"src/index.ts"}\n');
    writeIn(dir, 'Dockerfile', 'FROM node:24\n');
    writeIn(dir, 'src/index.ts', 'export {};\n');
    for (let i = 0; i < 20; i++) writeIn(dir, `src/lib/m${String(i).padStart(2, '0')}.ts`, `// ${i}\n` + 'x'.repeat(300) + '\n');
    writeIn(dir, 'src/huge.ts', ('y'.repeat(100) + '\n').repeat(50));
    const b = await bundleCode(dir, { maxBytes: 2000 });
    expect(b.truncated).toBe(true);
    expect(b.bytes).toBeLessThanOrEqual(2000);
    expect(b.bytes).toBe(b.files.reduce((n, f) => n + Buffer.byteLength(f.content), 0));
    expect(paths(b)).toEqual(expect.arrayContaining(['package.json', 'Dockerfile', 'src/index.ts']));
    expect(paths(b)).not.toContain('src/huge.ts');
    expect(b.files.length).toBeLessThan(23);
    const notes = b.notes.join('\n');
    expect(notes).toMatch(/size/i);
    expect(notes).toContain('src/huge.ts');

    // a custom priority decides what stays
    const b2 = await bundleCode(dir, { maxBytes: 400, priority: (p) => (p === 'src/lib/m07.ts' ? 10 : 0) });
    expect(paths(b2)).toContain('src/lib/m07.ts');
  });
});
