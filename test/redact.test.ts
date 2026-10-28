import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import picomatch from 'picomatch';
import { build } from 'tsup';
import { tsupOptions } from '../tsup.config.js';
import { afterEach, describe, expect, it } from 'vitest';
import {
  bundleCode, bundleText, EXCLUDED_PATTERNS, SecretScanError, SecretScanRequiredError, secretScanArgv, secretScanConfigPath,
  isBinary, redact, scrubKnownValues, type CodeBundle,
} from '../src/ai/redact.js';
import { isBinary as limitsIsBinary } from '../src/read/limits.js';
import { BETTERLEAKS_FORBIDDEN_FLAGS, BETTERLEAKS_SUBCOMMANDS } from '../src/engine/tool-flags.js';
import { betterleaksAt, CHECKED_KEY, CLEAN, gitleaksAt, makeStub, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { fake, makeSecretRepo } from './helpers/secret-repo.js';

const root = resolve(import.meta.dirname, '..');
const R = '[REDACTED]';

afterEach(() => cleanupRepos());

const reportValue = (value: string) => `const f = findingsFor(${JSON.stringify(value)}); fs.writeFileSync(report, JSON.stringify(f)); process.exit(f.length ? 1 : 0);`;

// Byte length of bundleText(b), computed independently (works for count-only bundles too).
const textBytes = (b: CodeBundle) => Buffer.byteLength('<code-bundle>\n</code-bundle>')
  + b.files.reduce((n, f) => n + Buffer.byteLength(`--- ${f.path} ---\n${f.content}`) + (f.content === '' || f.content.endsWith('\n') ? 0 : 1), 0);
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
      '**/.git-credentials', '**/.aws/credentials', '**/.aws/config', '**/credentials.json', '**/.pgpass', '**/.pypirc',
      '**/.docker/config.json', '**/*.env', '**/*.keystore', '**/*.ppk', '**/*.p8', '**/.htpasswd', '**/service-account*.json',
      '**/node_modules/**', '**/.git/**', '**/.venv/**', '**/dist/**', '**/build/**', '**/vendor/**', '**/target/**',
    ];
    for (const p of required) expect(EXCLUDED_PATTERNS, p).toContain(p);

    const excluded = [
      '.env', '.env.local', 'api/.env.production', '.envrc', 'k.pem', 'a/server.key', 'id_rsa', '.ssh/id_rsa.pub',
      'config/secrets.yml', 'MY_SECRET.txt', 'secret/x.ts', 'Secrets/y.ts', 'secrets/.env.example',
      'x.tfstate', 'x.tfstate.backup', 'x.tfvars', '.npmrc', 'sub/.netrc', 'a.p12', 'a.pfx', 'a.jks', 'kubeconfig', '.kube/config',
      '.git-credentials', 'home/.aws/credentials', '.aws/config', 'gcp/credentials.json', '.pgpass', 'py/.pypirc',
      '.docker/config.json', 'config/prod.env', 'app.keystore', 'putty.ppk', 'keys/Signing.p8', 'web/.htpasswd', 'service-account-prod.json',
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
    expect(out).toContain(`GH_PUBLISH=${R} npm publish`);
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
    expect(redact(`//registry/:_x=${fake.npmPublish()}`)).toBe(`//registry/:_x=${R}`);
  });

  it('redact: password/secret/token/api_key assignments lose only the value', () => {
    for (const name of ['pass' + 'word', 'PASS' + 'WD', 'db_sec' + 'ret', 'Tok' + 'en', 'api' + '_key', 'API' + 'KEY', 'api' + '-key']) {
      expect(redact(fake.assign(name, 'hunter2'))).toBe(fake.assign(name, R));
      expect(redact('  ' + fake.assign(name, ' "hunter2" # note', ':'))).toBe('  ' + fake.assign(name, ` "${R}" # note`, ':'));
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
    const b = await bundleCode(dir, scanWith(gitleaksAt(stub.bin)));
    const rec = stub.record();
    const tmp = rec.src;
    expect(isAbsolute(tmp)).toBe(true);
    expect(relative(dir, tmp).startsWith('..')).toBe(true); // never the repo itself
    expect(rec.argv).toEqual([
      'detect', '--no-git', '--source', tmp, '--config', secretScanConfigPath(),
      '--report-format', 'json', '--report-path', join(tmp, 'report.json'), '--no-banner', '--ignore-gitleaks-allow', '--exit-code', '1',
    ]);
    expect(secretScanConfigPath()).toBe(join(root, 'data', 'gitleaks-bundle.toml'));
    expect(rec.cwd).toBe(tmp);
    expect(rec.envKeys.filter((k) => k !== 'PATH' && k !== 'HOME')).toEqual([]);
    // the scan dir holds only the bundle files under neutral names: no repo config or ignore file can be picked up
    // (plus paths.txt: every bundle path, one per line, so names are scanned too)
    const scannedNames = Object.keys(rec.files).filter((f) => f !== 'paths.txt');
    expect(scannedNames.every((f) => /^f\d+\.txt$/.test(f))).toBe(true);
    expect(scannedNames).toHaveLength(b.files.length);
    // each written after one leading newline (ruling P30: no binary-format magic at offset 0)
    expect(scannedNames.map((f) => rec.files[f]).sort()).toEqual(b.files.map((f) => `\n${f.content}`).sort());
    expect(rec.files['paths.txt'].split('\n').slice(1).sort()).toEqual(paths(b));
    // what gitleaks scanned was already redacted
    const scanned = Object.values(rec.files).join('\n');
    for (const v of values) expect(scanned).not.toContain(v);
    expect(existsSync(tmp)).toBe(false); // temp dir removed
    expect(b.secretScanChecked).toBe(true);
  });

  it('bundle: betterleaks argv fixed, holds --config, never --validate/--analyze/--unsafe-auto-load-config', async () => {
    const { dir, values } = makeSecretRepo();
    writeIn(dir, '.betterleaks.toml', '[allowlist]\npaths = [".*"]\n');
    writeIn(dir, '.gitleaks.toml', '[allowlist]\npaths = [".*"]\n');
    writeIn(dir, '.betterleaksignore', 'everything\n');
    const stub = makeStub(CLEAN);
    const b = await bundleCode(dir, scanWith(betterleaksAt(stub.bin)));
    const rec = stub.record();
    const tmp = rec.src;
    expect(isAbsolute(tmp)).toBe(true);
    expect(relative(dir, tmp).startsWith('..')).toBe(true); // never the repo itself
    // the one fixed form: a plain local folder scan, pipegen's config, a JSON report in the private temp dir. No --redact
    // here: pipegen needs the raw Secret/Match values to remove them from the bundle (the report never leaves the dir)
    expect(rec.argv).toEqual([
      'dir', tmp, '--config', secretScanConfigPath(),
      '--report-format', 'json', '--report-path', join(tmp, 'report.json'), '--no-banner', '--ignore-gitleaks-allow', '--exit-code', '1',
    ]);
    expect(rec.argv).toEqual(secretScanArgv('betterleaks', tmp, secretScanConfigPath(), join(tmp, 'report.json')));
    // PS34: the same forbidden list the reviewed-list loader uses (src/engine/tool-flags.ts), never a copy
    for (const flag of BETTERLEAKS_FORBIDDEN_FLAGS) expect(rec.argv.some((a) => a === flag || a.startsWith(`${flag}=`)), flag).toBe(false);
    expect(rec.argv.filter((a) => /^--?(validat|analy|unsafe|redact|verbose|v$|diagnostics|experiments)/.test(a))).toEqual([]);
    expect(rec.argv).not.toContain('-');
    expect(BETTERLEAKS_SUBCOMMANDS).toContain(rec.argv[0]);
    expect(rec.cwd).toBe(tmp);
    expect(rec.envKeys.filter((k) => k !== 'PATH' && k !== 'HOME')).toEqual([]);
    // only neutral names in the scanned folder: no repo config or ignore file can be picked up
    expect(Object.keys(rec.files).every((f) => /^f\d+\.txt$/.test(f) || f === 'paths.txt')).toBe(true);
    const scanned = Object.values(rec.files).join('\n');
    for (const v of values) expect(scanned).not.toContain(v);
    expect(existsSync(tmp)).toBe(false); // temp dir (and the report in it) removed
    expect(b.secretScanChecked).toBe(true);
    expect(b.notes.join('\n')).toMatch(/betterleaks checked the bundle/);
  });

  it('bundle: betterleaks:allow and gitleaks:allow comments neutralised', async () => {
    const gl = 'gitleaks' + ':allow';
    const bl = 'betterleaks' + ':allow';
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', `const a = 1; // ${gl}\nconst b = 2; // ${bl}\n# ${bl.toUpperCase()} ${gl}\n`);
    writeIn(dir, `src/${bl}.ts`, 'const c = 3;\n');
    writeIn(dir, `src/${gl}.ts`, 'const d = 4;\n');
    for (const at of [betterleaksAt, gitleaksAt]) {
      const stub = makeStub(CLEAN);
      const b = await bundleCode(dir, scanWith(at(stub.bin)));
      const rec = stub.record();
      const scanned = Object.values(rec.files).join('\n'); // the files and paths.txt
      expect(scanned.toLowerCase(), at.name).not.toContain(gl);
      expect(scanned.toLowerCase(), at.name).not.toContain(bl);
      expect(rec.files['paths.txt'].split('\n').length, at.name).toBe(4); // the leading newline, then 3 paths
      expect(b.files.map((f) => f.content).join('\n').toLowerCase(), at.name).not.toMatch(/(?:gitleaks|betterleaks):allow/);
    }
  });

  it('bundle: exit code "found" with no report or an empty one → SecretScanError (betterleaks exits 1 on a config error)', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'export const a = 1;\n');
    for (const at of [betterleaksAt, gitleaksAt]) {
      await expect(bundleCode(dir, scanWith(at(makeStub('process.exit(1);').bin))), at.name).rejects.toThrow(/wrote no report/);
      await expect(bundleCode(dir, scanWith(at(makeStub(`fs.writeFileSync(report, '[]'); process.exit(1);`).bin))), at.name).rejects.toThrow(/reported findings but listed none/);
      await expect(bundleCode(dir, scanWith(at(makeStub(`fs.writeFileSync(report, '[]'); process.exit(2);`).bin))), at.name).rejects.toBeInstanceOf(SecretScanError);
    }
  });

  it('bundle: every scanned file and paths.txt start with a newline (no binary-format magic at offset 0); reported lines map back', async () => {
    // ruling P30: both scanners skip a file whose first bytes look like a binary format (%PDF-, MZ, %!PS, …) and still
    // exit clean. pipegen writes one "\n" first, so nothing it scans starts with a magic number, and subtracts 1 from
    // every reported line.
    const found = 'plain' + '-looking-' + 'value-7731';
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', `MZ,Mozambique\nconst b = '${found}';\nconst c = 3;\n`);
    writeIn(dir, `MZ-${found}.csv`, 'x,y\n'); // a path whose shown name starts with MZ and holds the value
    for (const at of [betterleaksAt, gitleaksAt]) {
      const stub = makeStub(reportValue(found));
      const b = await bundleCode(dir, scanWith(at(stub.bin)));
      const rec = stub.record();
      for (const [name, text] of Object.entries(rec.files)) expect(text.startsWith('\n'), `${at.name} ${name}`).toBe(true);
      // the stub reports line 3 of the file as written (line 2 of the content): mapped back, the value is redacted in
      // place on line 2, and the file stays (P31 would leave it out if the lines pointed elsewhere)
      expect(b.files.find((f) => f.path === 'src/a.ts')?.content, at.name).toBe(`MZ,Mozambique\nconst b = '${R}';\nconst c = 3;\n`);
      // the paths.txt finding (line 2 as written = the first path): that file is left out, its name not shown
      expect(paths(b), at.name).toEqual(['src/a.ts']);
      expect(bundleText(b), at.name).not.toContain(found);
    }
  });

  it('bundle: a finding reported on the added first line (the empty prefix) → the file is left out', async () => {
    const found = 'plain' + '-looking-' + 'value-5520';
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', `const a = '${found}';\n`);
    writeIn(dir, 'src/b.ts', 'const b = 2;\n');
    // line 1 is pipegen's empty prefix: a finding there can't be mapped to the content
    const stub = makeStub(`const f = findingsFor(${JSON.stringify(found)}).map((x) => ({ ...x, StartLine: 1, EndLine: 1 })); fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b = await bundleCode(dir, scanWith(betterleaksAt(stub.bin)));
    expect(paths(b)).toEqual(['src/b.ts']);
    expect(b.notes.join('\n')).toMatch(/could not locate to redact/);
  });

  it('bundle: a finding whose reported lines do not hold the value, or tagged decoded:*, leaves the whole file out (never a whole-file search)', async () => {
    // ruling P31, the review's probe: a base64 blob of an api-key assignment holding S on one line, S plain on another.
    // betterleaks reports the DECODED S on the blob's line; a whole-file search would redact the plain copy and send the blob.
    const S = 'Zr8' + 'Kp2Wm5Qx9Lt4Vn7Bc3';
    const blob = Buffer.from(['api', 'key'].join('_') + '=' + S).toString('base64');
    const dir = makeTempDir();
    writeIn(dir, 'src/k.ts', `export const blob = "${blob}";\nexport const sample = "${S}";\n`);
    writeIn(dir, 'src/ok.ts', 'export const ok = 1;\n');
    const decoded = (tags: string) => `const f = [{ RuleID: 'generic-api-key', File: path.join(src, 'f000001.txt'), StartLine: 2, EndLine: 2, Match: ${JSON.stringify(S)}, ['Sec' + 'ret']: ${JSON.stringify(S)}, Tags: ${tags}, Fingerprint: 'x' }];
      fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`;
    for (const tags of ["['decoded:base64', 'decode-depth:1']", "['decoded:hex']", '[]']) {
      const stub = makeStub(decoded(tags));
      const b = await bundleCode(dir, scanWith(betterleaksAt(stub.bin), { priority: (p) => (p === 'src/k.ts' ? 9 : 0) }));
      expect(paths(b), tags).toEqual(['src/ok.ts']);
      expect(bundleText(b), tags).not.toContain(blob);
      expect(bundleText(b), tags).not.toContain(S);
      expect(b.notes.join('\n'), tags).toMatch(/could not locate to redact/);
    }
    // a Tags field that is not a list of strings is refused (the report is type-checked)
    const badTags = makeStub(decoded("'decoded:base64'"));
    await expect(bundleCode(dir, scanWith(betterleaksAt(badTags.bin)))).rejects.toBeInstanceOf(SecretScanError);
  });

  it('bundle: a finding with no or invalid line numbers leaves the whole file out (no path searches the whole file)', async () => {
    // ruling P32: without lines pipegen can't tell which occurrence the scanner meant, so it never guesses
    const S = 'Qm4' + 'Tz8Rw2Yv6Np1Hs5Kd9';
    const dir = makeTempDir();
    writeIn(dir, 'src/k.ts', `export const one = "${S}";\nexport const two = "${S}";\n`);
    writeIn(dir, 'src/ok.ts', 'export const ok = 1;\n');
    const lineFields = ['', 'StartLine: 2,', 'EndLine: 2,', 'StartLine: 0, EndLine: 0,', "StartLine: '2', EndLine: '2',", 'StartLine: 3, EndLine: 2,', 'StartLine: 2.5, EndLine: 2.5,', 'StartLine: 9, EndLine: 9,'];
    for (const lines of lineFields) {
      const stub = makeStub(`const f = [{ RuleID: 'x', File: path.join(src, 'f000001.txt'), ${lines} Match: ${JSON.stringify(S)}, ['Sec' + 'ret']: ${JSON.stringify(S)}, Tags: [] }];
        fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
      const b = await bundleCode(dir, scanWith(betterleaksAt(stub.bin), { priority: (p) => (p === 'src/k.ts' ? 9 : 0) }));
      expect(paths(b), lines || 'no lines').toEqual(['src/ok.ts']);
      expect(bundleText(b), lines || 'no lines').not.toContain(S);
      expect(b.notes.join('\n'), lines || 'no lines').toMatch(/could not locate to redact/);
    }
  });

  it('bundle: a clean exit (0) with findings in the report still redacts them', async () => {
    const found = 'plain' + '-looking-' + 'value-8812';
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', `const a = '${found}';\n`);
    for (const at of [betterleaksAt, gitleaksAt]) {
      const stub = makeStub(`fs.writeFileSync(report, JSON.stringify(findingsFor(${JSON.stringify(found)}))); process.exit(0);`);
      const b = await bundleCode(dir, scanWith(at(stub.bin)));
      expect(b.files.find((f) => f.path === 'src/a.ts')?.content, at.name).toBe(`const a = '${R}';\n`);
      expect(bundleText(b), at.name).not.toContain(found);
    }
  });

  it('bundle: SIGINT or SIGTERM during the scan removes the temp folder holding the raw report; the process still stops by that signal', async () => {
    const pkgDir = makeTempDir();
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'pipegen' }));
    writeIn(pkgDir, 'data/gitleaks-bundle.toml', readFileSync(join(root, 'data', 'gitleaks-bundle.toml'), 'utf8'));
    // the release build's own settings (one ESM file with a real `require`), as the package test builds its probe
    const { define: _define, ...opts } = tsupOptions;
    await build({ ...opts, entry: { 'scan-signal-probe': 'test/helpers/scan-signal-probe.ts' }, outDir: join(pkgDir, 'dist', 'cli'), config: false, silent: true, clean: false });
    const probe = join(pkgDir, 'dist', 'cli', 'scan-signal-probe.js');
    const repo = makeTempDir();
    writeIn(repo, 'src/a.ts', 'export const a = 1;\n');
    for (const sig of ['SIGTERM', 'SIGINT'] as const) {
      const tmp = makeTempDir(); // the probe's TMPDIR: only its own temp folders land here
      const started = join(makeTempDir(), 'started');
      // the stub writes a report (so the folder holds one), says it started, then waits far past the test
      const stub = makeStub(`fs.writeFileSync(report, '[]'); fs.writeFileSync(${JSON.stringify(started)}, 'x'); setTimeout(() => process.exit(0), 15000);`);
      const child = spawn('node', [probe, repo, stub.bin], { env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', TMPDIR: tmp }, stdio: 'ignore' });
      const exited = new Promise<NodeJS.Signals | null>((done) => child.on('exit', (_code, signal) => done(signal)));
      for (let i = 0; i < 200 && !existsSync(started); i++) await new Promise((r) => setTimeout(r, 50));
      expect(existsSync(started), sig).toBe(true);
      expect(readdirSync(tmp).filter((n) => n.startsWith('pipegen-secret-scan-')), sig).toHaveLength(1); // the scan is running
      child.kill(sig);
      expect(await exited, sig).toBe(sig); // the signal is not swallowed: the process stops by it
      expect(readdirSync(tmp).filter((n) => n.startsWith('pipegen-secret-scan-')), sig).toEqual([]);
    }
  }, 120_000);

  it('bundle: gitleaks finding → value replaced; unlocatable finding → file dropped and noted', async () => {
    const dir = makeTempDir();
    const found = 'plain' + '-looking-' + 'value-4411';
    writeIn(dir, 'src/a.ts', `const a = 1;\nconst b = '${found}'; // ${found}\n`);
    writeIn(dir, 'src/b.ts', 'const c = 2;\n');
    const stub = makeStub(reportValue(found));
    const b = await bundleCode(dir, scanWith(gitleaksAt(stub.bin)));
    expect(b.files.find((f) => f.path === 'src/a.ts')?.content).toBe(`const a = 1;\nconst b = '${R}'; // ${R}\n`);
    expect(b.secretScanChecked).toBe(true);

    const lost = 'unlocatable' + '-marker';
    writeIn(dir, 'src/b.ts', `const c = '${lost}';\n`);
    const stub2 = makeStub(`
      const f = findingsFor(${JSON.stringify(lost)}).map((x) => ({ ...x, ['Sec' + 'ret']: 'not-in-the-file', Match: 'nope' }));
      fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b2 = await bundleCode(dir, scanWith(gitleaksAt(stub2.bin)));
    expect(paths(b2)).toEqual(['src/a.ts']);
    expect(allText(b2)).not.toContain(lost);
    const notes = b2.notes.join('\n');
    expect(notes).toContain('src/b.ts');
    expect(notes).toMatch(/gitleaks/);
    expect(notes).not.toContain(lost);
    expect(b2.secretScanChecked).toBe(true);
  });

  it('bundle: gitleaks error → bundle not returned, error raised', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'export {};\n');
    const stub = makeStub(`process.stderr.write('boom'); process.exit(2);`);
    await expect(bundleCode(dir, scanWith(gitleaksAt(stub.bin)))).rejects.toBeInstanceOf(SecretScanError);
    expect(existsSync(stub.record().src)).toBe(false);
  });

  it('bundle: gitleaks error on timeout or bad exit code → error raised', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', 'export {};\n');
    const slow = makeStub(`setTimeout(() => {}, 600000);`);
    await expect(bundleCode(dir, scanWith(gitleaksAt(slow.bin), {}, 500))).rejects.toThrow(/gitleaks/i);
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
      await expect(bundleCode(dir, scanWith(gitleaksAt(stub.bin))), body).rejects.toBeInstanceOf(SecretScanError);
    }
    await expect(bundleCode(dir, scanWith(gitleaksAt(join(makeTempDir(), 'missing-gitleaks'))))).rejects.toBeInstanceOf(SecretScanError);
    await expect(bundleCode(dir, scanWith(gitleaksAt('gitleaks')))).rejects.toBeInstanceOf(SecretScanError); // never looked up on PATH
  });

  it('bundle: gitleaks report pointing outside the temp dir is ignored and the file dropped', async () => {
    const dir = makeTempDir();
    const v = 'outside' + '-reported-' + 'value';
    writeIn(dir, 'src/a.ts', `const a = '${v}';\n`);
    writeIn(dir, 'src/b.ts', 'const b = 2;\n');
    const stub = makeStub(`
      const f = findingsFor(${JSON.stringify(v)}).map((x) => ({ ...x, File: src + '/../' + path.basename(x.File) }));
      fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b = await bundleCode(dir, scanWith(gitleaksAt(stub.bin)));
    expect(paths(b)).toEqual(['src/b.ts']);
    expect(allText(b)).not.toContain(v);
    expect(b.notes.join('\n')).toContain('src/a.ts');
    expect(b.notes.join('\n')).not.toContain(v);
    expect(b.secretScanChecked).toBe(true);
  });

  it('bundle: clean gitleaks pass → secretScanChecked true', async () => {
    const { dir } = makeSecretRepo();
    const b = await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin)));
    expect(b.secretScanChecked).toBe(true);
    expect(b.notes.join('\n')).toMatch(/gitleaks/);
    expect(bundleText(b)).toContain('--- src/app.ts ---');
  });

  it('bundle: no gitleaks path → secretScanChecked false and noted (counting only)', async () => {
    const { dir } = makeSecretRepo();
    const b = await bundleCode(dir);
    expect(b.secretScanChecked).toBe(false);
    expect(b.notes.join('\n')).toMatch(/secret scan was not run/i);
    expect(b.files.length).toBeGreaterThan(0);
    expect(b.bytes).toBe(textBytes(b));
  });

  it('bundle: gitleaks config path resolves in dev and from the build', () => {
    const dev = secretScanConfigPath();
    expect(dev).toBe(join(root, 'data', 'gitleaks-bundle.toml'));
    expect(existsSync(dev)).toBe(true);
    const toml = readFileSync(dev, 'utf8');
    expect(toml).toMatch(/^\s*useDefault\s*=\s*true/m);
    expect(toml).not.toMatch(/^\s*\[\[?\s*(rules\.)?allowlists?\s*\]\]?/m); // no allowlist a repo could use to opt out

    // Built into an installed-package layout in a temp dir (<pkg>/dist/cli/, like dist/cli/main.js), the bundled
    // code walks up to the package.json named pipegen and finds <pkg>/data/gitleaks-bundle.toml.
    const pkgDir = makeTempDir();
    execFileSync('npx', ['tsup', '--no-config', 'test/helpers/config-probe.ts', '--format', 'esm', '--platform', 'node', '--target', 'node24', '--out-dir', join(pkgDir, 'dist', 'cli')], { cwd: root, stdio: 'pipe' });
    const probe = join(pkgDir, 'dist', 'cli', 'config-probe.js');
    const runProbe = () => execFileSync('node', [probe], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    writeIn(pkgDir, 'data/gitleaks-bundle.toml', toml);
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'pipegen' }));
    expect(runProbe()).toBe(join(pkgDir, 'data', 'gitleaks-bundle.toml'));
    // fails closed: no package.json named pipegen above it, or no config file → error, never a guess
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'other' }));
    expect(runProbe).toThrow();
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'pipegen' }));
    rmSync(join(pkgDir, 'data'), { recursive: true });
    expect(runProbe).toThrow();
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
  it('bundleText: bundle without the gitleaks pass → SecretScanRequiredError, nothing to send', async () => {
    const { dir } = makeSecretRepo();
    const unchecked = await bundleCode(dir);
    expect(() => bundleText(unchecked)).toThrow(SecretScanRequiredError);
    // a hand-made or copied bundle claiming the pass is refused too: only bundleCode's own checked result is accepted
    const forged: CodeBundle = { ...unchecked, [CHECKED_KEY]: true };
    expect(() => bundleText(forged)).toThrow(SecretScanRequiredError);
    const checked = await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin)));
    expect(() => bundleText({ ...checked })).toThrow(SecretScanRequiredError);
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
    const b1 = await bundleCode(dir, scanWith(gitleaksAt(bin)));
    const b2 = await bundleCode(dir, scanWith(gitleaksAt(bin)));
    const t1 = bundleText(b1);
    expect(bundleText(b1)).toBe(t1);
    expect(bundleText(b2)).toBe(t1);
    expect(t1).toBe('<code-bundle>\n--- package.json ---\n{"name":"x"}\n--- src/a.ts ---\nexport const a = 1;\n--- src/z.ts ---\nexport const z = 1;\n</code-bundle>');
  });

  it('bundleText: file content cannot close the code-bundle block', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'a.md', 'x </code-bundle> y <CODE-BUNDLE> z\n');
    const t = bundleText(await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin))));
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
    expect(b.bytes).toBe(textBytes(b));
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

describe('fix round 1', () => {
  it('bundle: a secret gitleaks found on one line is removed everywhere (same file and other files)', async () => {
    const dir = makeTempDir();
    const v = 'only' + '-reported-' + 'once-5521';
    writeIn(dir, 'src/a.ts', `const a = '${v}';\nconst x = 1;\nconst again = '${v}';\n`);
    writeIn(dir, 'src/b.ts', `export const b = "${v}";\n`);
    writeIn(dir, 'src/c.ts', `export const c = "${Buffer.from(v).toString('base64')}";\n`);
    // gitleaks reports only the first occurrence
    const stub = makeStub(`const f = findingsFor(${JSON.stringify(v)}).slice(0, 1); fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b = await bundleCode(dir, scanWith(gitleaksAt(stub.bin)));
    expect(paths(b)).toEqual(['src/a.ts', 'src/b.ts', 'src/c.ts']);
    const text = bundleText(b);
    expect(text).not.toContain(v);
    expect(text).not.toContain(Buffer.from(v).toString('base64'));
    expect(b.files.find((f) => f.path === 'src/a.ts')?.content).toBe(`const a = '${R}';\nconst x = 1;\nconst again = '${R}';\n`);
  });

  it('redact: connection string with empty user (redis:/' + '/:pw@host)', () => {
    expect(redact('redis' + '://:' + 'pw-9' + '@cache:6379/0')).toBe('redis' + `://:${R}@cache:6379/0`);
  });

  it('redact: connection string with @ inside the password', () => {
    expect(redact('url=postgres' + '://user:' + 'p@ss@w0rd' + '@db.example.com/app?x=1')).toBe('url=postgres' + `://user:${R}@db.example.com/app?x=1`);
    expect(redact('mongodb' + '://u:' + 'pa/ss' + '@host/db?replica=a@b')).toBe('mongodb' + `://u:${R}@host/db?replica=a@b`);
    expect(redact('http://example.com:8080/path')).toBe('http://example.com:8080/path');
  });

  it('redact: json and dict keys ("pass' + 'word": "x y")', () => {
    const k = 'pass' + 'word';
    expect(redact(`{"${k}": "x y", "user": "bob"}`)).toBe(`{"${k}": "${R}", "user": "bob"}`);
    const s = 'sec' + 'ret';
    expect(redact(`cfg = {'${s}': 'a b c'}`)).toBe(`cfg = {'${s}': '${R}'}`);
  });

  it('redact: suffixed names (AWS_SECRET_ACCESS_KEY' + '=, STRIPE_SECRET_KEY' + '=, apiKeyProd' + '=)', () => {
    for (const name of ['AWS_SEC' + 'RET_ACCESS_KEY', 'STRIPE_SEC' + 'RET_KEY', 'api' + 'KeyProd', 'GITHUB_TOK' + 'EN', 'db.pass' + 'word', 'PRIVATE' + '_KEY_PATH', 'client' + 'Secret', 'X_AU' + 'TH']) {
      expect(redact(fake.assign(name, 'v4lue-123')), name).toBe(fake.assign(name, R));
    }
  });

  it('redact: quoted value with spaces fully hidden', () => {
    const k = 'pass' + 'word';
    expect(redact(`${k} = "correct horse battery"`)).toBe(`${k} = "${R}"`);
    expect(redact(`${k}='correct horse'; next()`)).toBe(`${k}='${R}'; next()`);
    expect(redact(`${k}: \`correct horse\``)).toBe(`${k}: \`${R}\``);
    expect(redact(`${k} = "a\\" b c"`)).toBe(`${k} = "${R}"`);
  });

  it('redact: => and := separators', () => {
    const k = 'pass' + 'word';
    const t = 'tok' + 'en';
    expect(redact(`:${k} => 'x y'`)).toBe(`:${k} => '${R}'`);
    expect(redact(`${t} := os.Getenv("X")`)).toBe(`${t} := ${R}`);
    expect(redact(`${k}=>abc`)).toBe(`${k}=>${R}`);
  });

  it('bundle: a known value that redact() would partially change is still fully removed', async () => {
    const v = 'pre-' + fake.githubClassic() + '-post7';
    const dir = makeTempDir();
    writeIn(dir, 'src/a.ts', `const x = '${v}';\n`);
    const b = await bundleCode(dir, { knownValues: [v] });
    expect(b.files[0].content).toBe(`const x = '${R}';\n`);
  });

  it('redact: PGP private key block replaced', () => {
    const begin = '-----' + 'BEGIN PGP PRIV' + 'ATE KEY BLOCK-----';
    const end = '-----' + 'END PGP PRIV' + 'ATE KEY BLOCK-----';
    expect(redact(`a\n${begin}\n\n${fake.keyBody()}\n${end}\nb`)).toBe(`a\n${R}\nb`);
  });

  it('scrubKnownValues: overlapping values are removed as one span', () => {
    expect(scrubKnownValues('xabcdefghiy', ['abcdef', 'defghi'])).toBe(`x${R}y`);
    expect(scrubKnownValues('aaaa', ['aa'])).toBe(R);
  });

  it('scrubKnownValues: lowercase percent, form-encoded and JSON-escaped forms removed', () => {
    const v = 'a b/c"d';
    const lower = 'a%20b%2fc%22d';
    const form = 'a+b%2Fc%22d';
    const json = 'a b/c\\"d';
    const out = scrubKnownValues(`1 ${lower} 2 ${form} 3 ${form.toLowerCase()} 4 ${json} 5`, [v]);
    expect(out).toBe(`1 ${R} 2 ${R} 3 ${R} 4 ${R} 5`);
  });

  it('bundle: a secret in a file path found by gitleaks → that file left out, name not shown', async () => {
    const dir = makeTempDir();
    const flagged = 'zq' + 'name-flag-889';
    writeIn(dir, `src/${flagged}.ts`, 'export {};\n');
    writeIn(dir, 'src/ok.ts', 'export {};\n');
    const stub = makeStub(reportValue(flagged));
    const b = await bundleCode(dir, scanWith(gitleaksAt(stub.bin)));
    expect(stub.record().files['paths.txt']).toContain(flagged);
    expect(paths(b)).toEqual(['src/ok.ts']);
    expect(bundleText(b)).not.toContain(flagged);
    expect(b.notes.join('\n')).not.toContain(flagged);
    expect(b.notes.join('\n')).toMatch(/path/);
  });

  it('bundle: bytes counts the whole bundleText, which never exceeds maxBytes', async () => {
    const dir = makeTempDir();
    for (let i = 0; i < 10; i++) writeIn(dir, `src/file-with-a-long-name-${i}.ts`, 'x'.repeat(20) + '\n');
    const bin = makeStub(CLEAN).bin;
    const b = await bundleCode(dir, scanWith(gitleaksAt(bin), { maxBytes: 300 }));
    const t = bundleText(b);
    expect(Buffer.byteLength(t)).toBe(b.bytes);
    expect(b.bytes).toBeLessThanOrEqual(300);
    expect(b.truncated).toBe(true); // 10 × 21 content bytes fit, the headers do not
    const all = await bundleCode(dir, scanWith(gitleaksAt(bin)));
    expect(Buffer.byteLength(bundleText(all))).toBe(all.bytes);
  });
});

describe('redact: speed', () => {
  // Hostile shapes, each built for a given line length L (at most 4000, so every line is scanned). Two checks
  // catch quadratic behaviour without benchmarking the machine:
  // - per line: the same 256 KB built from 4 KB lines vs 512-byte lines must take under 3 times as long (code
  //   linear in the line length costs about the same per MB; quadratic costs about 8 times more);
  // - total size: 1 MB vs 256 KB (4 KB lines) must take under 6 times as long (linear is about 4).
  // Plus a ceiling of 1000 ms/MB. Each 256 KB timing is the median of 3 after one warm-up per shape (a ratio that
  // looks slow is timed again as the fastest of 3); times under 3 ms count as 3 ms, so timer noise on very fast
  // shapes cannot fail a ratio.
  it('redact: worst-case lines stay fast (linear in line length and in text size)', () => {
    const unit = (u: string) => (L: number) => u.repeat(Math.max(1, Math.floor(L / u.length)));
    const lineShapes: [string, (L: number) => string][] = [
      'tok' + 'en', 'ey' + 'J', 'ey' + 'J.', 'ey' + 'Ja.', 'a://', 'a://:', 'a://a:@/', 'a:/' + '/a:b', '@', 'sk-', 'x="', 'au' + 'th.',
      'a.tok' + 'en-', 'tok' + 'en:', 'tok' + 'en="', '"pass' + 'word":"', 'tok' + 'en="\\"', '--tok' + 'en ', '<pass' + 'word>', 'au' + 'thau' + 'th',
      '<a key="tok' + 'en" ', 'key="tok' + 'en" value="x" ', '<pass' + 'word ', '--pass' + 'word = ', 'pass' + 'word: &a !b ', 'x@y:/' + '/', 'smtp:/' + '/me@g:p#', '%', '\r', 'pass' + 'word:\r',
      // round 4: namespaced and closed elements, attribute runs
      '<a:pass' + 'word ', '<a:pass' + 'word>', '</pass' + 'word>', '<pass' + 'word>x</pass' + 'word>', '<a key="a:b/c d tok' + 'en" ',
      'a b:c/d tok' + 'en ', ' tok' + 'en', '<a:b:tok' + 'en ', '<x:tok' + 'en value="', '<add key="Smtp:Pass' + 'word" value="x"/>',
      // round 5: unclosed secret elements, JSON blocks, section headers
      '<tok' + 'en>a', '<tok' + 'en>', '"tok' + 'en": {', '[sec' + 'rets]', 'a'.repeat(30) + 'tok' + 'en ',
      // T0b fix round 1: doubled quotes, unclosed quotes
      "tok" + "en: 'a''", "tok" + "en: ''''", 'tok' + 'en: "a""',
    ].map((u): [string, (L: number) => string] => [u, unit(u)]);
    lineShapes.push(
      ['url with a long password', (L) => 'a:/' + '/b:' + 'c'.repeat(L - 6)],
      ['jwt with long segments', (L) => 'ey' + 'J' + 'a'.repeat((L >> 1) - 3) + '.' + 'b'.repeat((L >> 1) - 1)],
      ['many keys before one >', (L) => unit('<a key="tok' + 'en" value="')(L - 1) + '>'],
      ['mixed quotes before one >', (L) => unit("<a key='tok" + "en' value=\"")(L - 1) + '>'],
      ['many token tags then one closer', (L) => unit('<tok' + 'en>')(L - 8) + '</tok' + 'en>'],
      ['blanks before a quote, then keywords', (L) => '<a key=' + ' '.repeat(L >> 1) + '"' + unit(' tok' + 'en')((L >> 1) - 8)],
      ['block header then CRs', (L) => 'pass' + 'word: |' + '\r'.repeat(L - 11)],
    );
    const KB256 = 256 * 1024;
    const MB = 1024 * 1024;
    const fromLines = (make: (L: number) => string, L: number, bytes: number) => {
      const l = make(L) + '\n';
      return l.repeat(Math.max(1, Math.round(bytes / l.length)));
    };
    // shapes whose cost does not depend on the line length: only the total-size check and the ceiling
    const textShapes: [string, (bytes: number) => string][] = [
      ['indented block', (b) => 'pass' + 'word: |\n' + '  x\n'.repeat(Math.round(b / 4))],
      ['secret section', (b) => '[sec' + 'rets]\n' + 'a = b\n'.repeat(Math.round(b / 6))],
      ['alternating section headers', (b) => ('[sec' + 'rets]\nkey: x\n').repeat(Math.round(b / 17))],
      ['plain value then a continuation', (b) => ('pass' + 'word: a\n  b\n').repeat(Math.round(b / 16))],
    ];

    const median = (text: string) => {
      const runs = [0, 1, 2].map(() => {
        const t = performance.now();
        redact(text);
        return performance.now() - t;
      }).sort((a, b) => a - b);
      return runs[1];
    };
    const floor = (ms: number) => Math.max(ms, 3);
    const failures: string[] = [];
    const once = (text: string) => {
      const t = performance.now();
      redact(text);
      return performance.now() - t;
    };
    // The 1 MB text is timed once (the 256 KB runs warmed it up). A slow-looking result is timed again, both
    // sizes as the fastest of 3 runs (pauses only ever add time), so a stray pause cannot fail the check and
    // the test stays quick; a real quadratic (about 16 times) still fails.
    const fastest = (text: string) => Math.min(once(text), once(text), once(text));
    const checkSize = (name: string, small: string, tSmall: number, big: string) => {
      const looksSlow = (ms: number, base: number) => ms / floor(base) >= 6 || ms / (big.length / 1e6) >= 1000;
      let tBig = once(big);
      if (looksSlow(tBig, tSmall)) {
        tSmall = fastest(small);
        tBig = fastest(big);
      }
      const perMB = tBig / (big.length / 1e6);
      if (tBig / floor(tSmall) >= 6) failures.push(`${name}: 1 MB / 256 KB = ${(tBig / floor(tSmall)).toFixed(2)} (${tBig.toFixed(1)} ms vs ${tSmall.toFixed(1)} ms)`);
      if (perMB >= 1000) failures.push(`${name}: ${perMB.toFixed(0)} ms/MB`);
    };
    for (const [name, make] of lineShapes) {
      const long = fromLines(make, 4000, KB256);
      const short = fromLines(make, 512, KB256);
      redact(long); // warm-up
      let tLong = median(long);
      let tShort = median(short);
      // Like the size check: a slow-looking ratio is timed again, both texts as the fastest of 3 runs.
      if (tLong / floor(tShort) >= 3) {
        tLong = fastest(long);
        tShort = fastest(short);
      }
      if (tLong / floor(tShort) >= 3) failures.push(`${name}: 4 KB lines / 512 B lines = ${(tLong / floor(tShort)).toFixed(2)} (${tLong.toFixed(1)} ms vs ${tShort.toFixed(1)} ms per 256 KB)`);
      checkSize(name, long, tLong, fromLines(make, 4000, MB));
    }
    for (const [name, make] of textShapes) {
      const small = make(KB256);
      redact(small); // warm-up
      checkSize(name, small, median(small), make(MB));
    }
    expect(failures).toEqual([]);
  }, 120_000);
});

describe('fix round 2', () => {
  // Expected strings start with "'scheme' + `://...`" so this file holds no literal URL with a password.
  it('redact: connection strings found by a linear scan (user with @, password with quotes, / or @)', () => {
    const cases: [string, string][] = [
      ['redis' + '://:' + 'pw' + '@host:6379', 'redis' + `://:${R}@host:6379`],
      ['postgres' + '://u:' + 'p@ss' + '@host:5432/db', 'postgres' + `://u:${R}@host:5432/db`],
      ['smtp' + '://me@gmail.com:' + 'hunter2' + '@smtp.gmail.com', 'smtp' + `://me@gmail.com:${R}@smtp.gmail.com`],
      ['mysql' + '://admin@srv:' + 'pw' + '@db', 'mysql' + `://admin@srv:${R}@db`],
      ['postgres' + "://u:" + "pa'ss" + '@db/x', 'postgres' + `://u:${R}@db/x`],
      ['postgres' + '://u:' + 'pa"ss' + '@db/x', 'postgres' + `://u:${R}@db/x`],
      ['postgres' + '://u:' + 'pa/ss' + '@db/x', 'postgres' + `://u:${R}@db/x`],
      ['postgres' + '://u:' + 'pa?ss' + '@db/x', 'postgres' + `://u:${R}@db/x`],
      ['postgres' + '://u:' + 'p@a/b' + '@host/db', 'postgres' + `://u:${R}@host/db`],
      ['mongodb+srv' + '://u:' + 'p' + '@cluster/x?y=z@w', 'mongodb+srv' + `://u:${R}@cluster/x?y=z@w`],
      ['https://user@host/path', 'https://user@host/path'],
      ['see http://example.com:8080/a', 'see http://example.com:8080/a'],
      ['[db](postgres' + '://u:' + 'pw' + '@h/db) more', '[db](postgres' + `://u:${R}@h/db) more`],
      ['"postgres' + '://u:' + 'pw' + '@h/db"', '"postgres' + `://u:${R}@h/db"`],
      ['go https://a.com/?r=postgres' + '://u:' + 'pw' + '@h', 'go https://a.com/?r=postgres' + `://u:${R}@h`],
      ['xpostgres' + '://u:' + 'pw' + '@h', 'xpostgres' + `://u:${R}@h`],
      ['jdbc:postgresql' + '://u:' + 'pw' + '@h/db', 'jdbc:postgresql' + `://u:${R}@h/db`],
      ['a=postgres' + '://u:' + 'p1' + '@h1/db b=postgres' + '://v:' + 'p2' + '@h2', 'a=postgres' + `://u:${R}@h1/db b=postgres` + `://v:${R}@h2`],
    ];
    for (const [input, want] of cases) expect(redact(input), want).toBe(want);
  });

  it('redact: JWT glued after letters, digits or underscore is replaced', () => {
    const jwt = fake.jwt();
    for (const pre of ['x', '9', 'jwt_', '#id_' + 'tok' + 'en=', '']) expect(redact(`${pre}${jwt} end`)).toBe(`${pre}${R}${pre.endsWith('=') ? '' : ' end'}`);
    expect(redact('ey' + 'J' + 'abc no dots')).toBe('ey' + 'J' + 'abc no dots');
    expect(redact('ey' + 'Ja.b.c')).toBe('ey' + 'Ja.b.c'); // second segment shorter than 4
  });

  it('bundle: a found secret shorter than 6 characters drops its file and is removed elsewhere only as a whole token', async () => {
    const dir = makeTempDir();
    const short = 'Ab' + '3';
    writeIn(dir, 'src/a.ts', `const k = "${short}";\n`);
    writeIn(dir, 'src/b.ts', `const other = "${short}"; const x = "${short}x"; const y = "x${short}"; const z = ${short}_1;\n`);
    writeIn(dir, `src/${short}.ts`, 'export {};\n');
    writeIn(dir, 'src/c.ts', 'export {};\n');
    const stub = makeStub(`const f = findingsFor(${JSON.stringify(short)}).slice(0, 1); fs.writeFileSync(report, JSON.stringify(f)); process.exit(1);`);
    const b = await bundleCode(dir, scanWith(gitleaksAt(stub.bin)));
    expect(paths(b)).toEqual(['src/b.ts', 'src/c.ts']); // the reported file and the file named after the value are left out
    expect(b.files.find((f) => f.path === 'src/b.ts')?.content).toBe(`const other = "${R}"; const x = "${short}x"; const y = "x${short}"; const z = ${short}_1;\n`);
    const notes = b.notes.join('\n');
    expect(notes).toMatch(/short/);
    expect(notes).not.toContain('src/a.ts');
  });

  it('redact: auth counts only as a word (also authorization), not author, authority or OAuth', () => {
    for (const keep of ['author: Jane Doe', 'authority = central', 'OAuth: enabled', 'authenticate(user)']) expect(redact(keep)).toBe(keep);
    for (const name of ['au' + 'th', 'au' + 'th_mode', 'AU' + 'TH', 'au' + 'thorization', 'basic' + 'Auth', 'X-Au' + 'th-Key']) {
      expect(redact(fake.assign(name, 'v4lue')), name).toBe(fake.assign(name, R));
    }
  });

  it('redact: Authorization header keeps the scheme, hides the credentials', () => {
    const h = 'Author' + 'ization';
    expect(redact(`${h}: Bearer abc123`)).toBe(`${h}: Bearer ${R}`);
    expect(redact(`curl -H "${h}: Basic dXNlcjpw" https://x`)).toBe(`curl -H "${h}: Basic ${R}`);
    expect(redact(`{"${h}": "Token abc def", "a": 1}`)).toBe(`{"${h}": "Token ${R}", "a": 1}`);
    expect(redact(`${h.toLowerCase()} = digest x y`)).toBe(`${h.toLowerCase()} = digest ${R}`);
    expect(redact(`${h}: custom-value`)).toBe(`${h}: ${R}`);
  });

  it('redact: unquoted value hides the rest of the line', () => {
    const k = 'pass' + 'word';
    expect(redact(`${k}: my secret phrase`)).toBe(`${k}: ${R}`);
    expect(redact(`${k.toUpperCase()}=x y # note`)).toBe(`${k.toUpperCase()}=${R}`);
  });

  it('redact: YAML block and next-line values hidden by indentation', () => {
    const k = 'pass' + 'word';
    expect(redact(`${k}: |\n  line-one\n\n  line-two\nnext: 1`)).toBe(`${k}: |\n  ${R}\n\n  ${R}\nnext: 1`);
    expect(redact(`db:\n  ${k}:\n    on-next-line\n  user: bob`)).toBe(`db:\n  ${k}:\n    ${R}\n  user: bob`);
    expect(redact(`- ${k}: >-\n    folded\n    more\n- x: 1`)).toBe(`- ${k}: >-\n    ${R}\n    ${R}\n- x: 1`);
  });

  it('redact: long CLI flags, subscripts, XML and triple-quoted values', () => {
    const k = 'pass' + 'word';
    const q3 = '"'.repeat(3);
    expect(redact(`run --${k} hunter2 --verbose`)).toBe(`run --${k} ${R} --verbose`);
    expect(redact('run --tok' + 'en=abc --x')).toBe('run --tok' + `en=${R} --x`);
    expect(redact("os.environ['API_KEY" + "']='x y'")).toBe("os.environ['API_KEY" + `']='${R}'`);
    expect(redact('env["DB_PASS' + 'WORD"] = "x"')).toBe('env["DB_PASS' + `WORD"] = "${R}"`);
    expect(redact(`<${k}>hunter2</${k}>`)).toBe(`<${k}>${R}</${k}>`);
    expect(redact(`${k} = ${q3}abc def${q3}`)).toBe(`${k} = ${q3}${R}${q3}`);
  });

  it('redact: an over-long line also hides the indented lines right after it', () => {
    const k = 'pass' + 'word';
    expect(redact(`${k}:${' '.repeat(5000)}\n  hidden-value\nnext: 1`)).toBe(`[REDACTED: line too long]\n  ${R}\nnext: 1`);
  });

  it('bundle: a control character inside a file name cannot hide a secret-like name', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'pass' + 'word\x01=hunter2-Q8.ts', 'x\n');
    writeIn(dir, 'ok.ts', 'y\n');
    const b = await bundleCode(dir, scanWith(gitleaksAt(makeStub(CLEAN).bin)));
    expect(paths(b)).toEqual(['ok.ts']);
    expect(bundleText(b)).not.toContain('hunter2');
  });

  it('scrubKnownValues: encodeURI and mixed-case percent forms removed', () => {
    const v = 'p@ss w/rd+"é';
    const mixed = encodeURIComponent(v).replace('%2F', '%2f').replace('%C3', '%c3');
    const ascii = JSON.stringify(v).slice(1, -1).replace('é', '\\u00e9');
    const out = scrubKnownValues(`1 ${encodeURI(v)} 2 ${mixed} 3 ${ascii} 4`, [v]);
    expect(out).toBe(`1 ${R} 2 ${R} 3 ${R} 4`);
  });
});

describe('fix round 3', () => {
  const k = 'pass' + 'word';
  const t = 'tok' + 'en';

  it('redact: CRLF yaml block and next-line values hidden', () => {
    expect(redact(`${k}: |\r\n  line-one\r\n  line-two\r\nnext: 1\r\n`)).toBe(`${k}: |\r\n  ${R}\r\n  ${R}\r\nnext: 1\r\n`);
    expect(redact(`db:\r\n  ${k}:\r\n    on-next-line\r\n  user: bob`)).toBe(`db:\r\n  ${k}:\r\n    ${R}\r\n  user: bob`);
    expect(redact(`${k}=x y\r\nok=1`)).toBe(`${k}=${R}\r\nok=1`);
  });

  it('bundle: CRLF files are normalised before redaction', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'config/app.yml', `db:\r\n  ${k}:\r\n    hidden-value-1\r\n  user: bob\r\nold-mac: 1\rnext: 2\r\n`);
    const b = await bundleCode(dir);
    const c = b.files[0].content;
    expect(c).not.toContain('\r');
    expect(c).not.toContain('hidden-value-1');
    expect(c).toBe(`db:\n  ${k}:\n    ${R}\n  user: bob\nold-mac: 1\nnext: 2\n`);
  });

  it('scrubKnownValues: a value right after a literal % is removed', () => {
    const v = 'cafe' + '0123babe';
    expect(scrubKnownValues(`100%${v} done`, [v])).toBe(`100%${R} done`);
    expect(scrubKnownValues(`x %2f${v}`, [v])).toBe(`x %2f${R}`);
  });

  it('redact: YAML block headers with indentation digits, anchors, tags and comments', () => {
    for (const header of ['|2', '>2-', '|+1', '|-2', '&pw', '!secret |', '!!str', '&a !t |-', '# a comment', '&anchor # note']) {
      const out = redact(`${k}: ${header}\n  hidden-line\nnext: 1`);
      expect(out, header).not.toContain('hidden-line');
      expect(out, header).toContain(`\n  ${R}\nnext: 1`);
    }
    // a tag followed by a value is a value, hidden on its line
    expect(redact(`${k}: !secret hunter2\nnext: 1`)).toBe(`${k}: ${R}\nnext: 1`);
  });

  it('redact: tab indentation counts as the next multiple of 8 columns', () => {
    expect(redact(`  ${k}: |\n\thidden-line\n  next: 1`)).toBe(`  ${k}: |\n\t${R}\n  next: 1`);
    expect(redact(`\t${k}: |\n        same-column\n`)).toBe(`\t${k}: |\n        same-column\n`);
  });

  it('redact: python block keywords do not hide code bodies when path is .py', async () => {
    const py = `class ${t[0].toUpperCase()}${t.slice(1)}Store:\n    def get(self):\n        return 1\nif not ${t}:\n    run()\n${k} = "x y"\n`;
    expect(redact(py, { path: 'src/store.py' })).toBe(py.replace('"x y"', `"${R}"`));
    const dir = makeTempDir();
    writeIn(dir, 'src/store.py', py);
    writeIn(dir, 'config/app.yml', `${k}:\n  hidden-line\n`);
    const b = await bundleCode(dir);
    expect(b.files.find((f) => f.path === 'src/store.py')?.content).toBe(py.replace('"x y"', `"${R}"`));
    expect(b.files.find((f) => f.path === 'config/app.yml')?.content).toBe(`${k}:\n  ${R}\n`);
  });

  it('redact: no hint → block rule still applies', () => {
    const py = `if not ${t}:\n    body-line\n`;
    expect(redact(py)).toBe(`if not ${t}:\n    ${R}\n`);
    expect(redact(py, {})).toBe(`if not ${t}:\n    ${R}\n`);
    for (const path of ['a.yml', 'b.yaml', '.env.local', 'x.ini', 'x.cfg', 'x.conf', 'x.properties', 'x.toml', 'Procfile', 'prod.env']) {
      expect(redact(py, { path }), path).toBe(`if not ${t}:\n    ${R}\n`);
    }
  });

  it('redact: XML element with attributes and .NET key/value settings', () => {
    expect(redact(`<${k} type="t">hunter2</${k}>`)).toBe(`<${k} type="t">${R}</${k}>`);
    expect(redact(`<add key="Db${k}" value="x y"/>`)).toBe(`<add key="Db${k}" value="${R}"/>`);
    expect(redact(`<add value='x y' key='Api${t}' />`)).toBe(`<add value='${R}' key='Api${t}' />`);
    expect(redact('<add key="Theme" value="dark"/>')).toBe('<add key="Theme" value="dark"/>');
  });

  it('redact: unsigned JWT (empty signature) replaced', () => {
    const unsigned = 'ey' + 'JhbGciOiJub25lIn0' + '.' + 'ey' + 'JzdWIiOiIxIn0' + '.';
    expect(redact(`x ${unsigned} y`)).toBe(`x ${R} y`);
    expect(redact(unsigned)).toBe(R);
  });

  it('redact: auth compounds hidden (authkey, AUTHPASS, xauth)', () => {
    for (const name of ['au' + 'thkey', 'AU' + 'THPASS', 'xau' + 'th', 'basic' + 'Auth', 'au' + 'th_mode', 'au' + 'thorization', 'my' + 'auth' + 'value']) {
      expect(redact(fake.assign(name, 'v4lue')), name).toBe(fake.assign(name, R));
    }
  });

  it('redact: author/authority/OAuth kept', () => {
    for (const keep of ['author: Jane', 'authors = [a]', 'authored: x', 'authorship: y', 'authority = central', 'authoritative: yes', 'authentic: no', 'authenticity: z', 'OAuth: enabled', 'oauth = on']) {
      expect(redact(keep), keep).toBe(keep);
    }
  });

  it('redact: connection string password holding # or ? after an email user', () => {
    expect(redact('smtp' + '://me@gmail.com:' + 'pa#ss' + '@host')).toBe('smtp' + `://me@gmail.com:${R}@host`);
    expect(redact('smtp' + '://me@gmail.com:' + 'pa?ss' + '@host:25')).toBe('smtp' + `://me@gmail.com:${R}@host:25`);
    expect(redact('mongodb+srv' + '://u:' + 'p' + '@cluster/x?y=z@w')).toBe('mongodb+srv' + `://u:${R}@cluster/x?y=z@w`);
    expect(redact('https://user@host/@scope/pkg')).toBe('https://user@host/@scope/pkg');
  });

  it('redact: CLI flags with spaced or colon separators', () => {
    expect(redact(`run --${k} = x y`)).toBe(`run --${k} = ${R} y`);
    expect(redact(`run --${k}: x y`)).toBe(`run --${k}: ${R} y`);
    expect(redact(`run --${t} := "a b" c`)).toBe(`run --${t} := "${R}" c`);
  });
});

describe('fix round 4', () => {
  const k = 'pass' + 'word';
  const K = 'Pass' + 'word';
  const t = 'tok' + 'en';
  const sec = 'sec' + 'ret';
  const au = 'au' + 'th';
  const S = 'S3kr' + 'etV4l';

  // [input, expected] pairs; every input holds S, every expected output hides it.
  const xmlCases = (): [string, string][] => [
    // attributes after a tag whose name holds a keyword are still checked
    [`<basic${au[0].toUpperCase()}${au.slice(1)} user="admin" ${k}="${S}"/>`, `<basic${au[0].toUpperCase()}${au.slice(1)} user="admin" ${k}="${R}"/>`],
    [`<${au} username="u" ${k}="${S}"/>`, `<${au} username="u" ${k}="${R}"/>`],
    [`<${t} type="bearer" ${sec}="${S}">`, `<${t} type="bearer" ${sec}="${R}">`],
    [`<${t} type="bearer" ${sec}="${S}">abc</${t}>`, `<${t} type="bearer" ${sec}="${R}">${R}</${t}>`],
    [`<Au${'th'}Provider client${sec[0].toUpperCase()}${sec.slice(1)}="${S}">`, `<Au${'th'}Provider client${sec[0].toUpperCase()}${sec.slice(1)}="${R}">`],
    // (round 5: a tag with no end tag on the line also hides what follows its '>' up to the next '<')
    [`if (i <${t} && y) { ${k} = "${S}"; } else if (z > 1) {}`, `if (i <${t} && y) { ${k} = "${R}"; } else if (z >${R}`],
    // a tag named after a keyword also has its value attributes hidden
    [`<${k} value="${S}"/>`, `<${k} value="${R}"/>`],
    [`<${sec} name="db" value="${S}"/>`, `<${sec} name="db" value="${R}"/>`],
    // round-3 shapes
    [`<${k}>${S}</${k}>`, `<${k}>${R}</${k}>`],
    [`<${k} type="t">${S}</${k}>`, `<${k} type="t">${R}</${k}>`],
    [`<add key="Db${k}" value="${S}"/>`, `<add key="Db${k}" value="${R}"/>`],
    [`<add value='${S}' key='Api${t}' />`, `<add value='${R}' key='Api${t}' />`],
  ];

  it('redact: XML attributes after a secret-named tag are still checked', () => {
    for (const [input, want] of xmlCases()) expect(redact(input), want).toBe(want);
    // a generic type in code is not a tag: what follows is still scanned
    expect(redact(`List<${t[0].toUpperCase()}${t.slice(1)}> a = b; String ${k} = "${S}";`)).toBe(`List<${t[0].toUpperCase()}${t.slice(1)}>${R}`);
  });

  it('bundle: XML attributes after a secret-named tag are still checked', async () => {
    const dir = makeTempDir();
    const cases = xmlCases();
    const files = ['config/web.xml', 'src/App.tsx', 'src/loop.c'];
    files.forEach((f) => writeIn(dir, f, cases.map(([input]) => input).join('\n') + '\n'));
    const b = await bundleCode(dir);
    const want = cases.map(([, w]) => w).join('\n') + '\n';
    for (const f of files) expect(b.files.find((x) => x.path === f)?.content, f).toBe(want);
    expect(allText(b)).not.toContain(S);
  });

  it('redact: .NET and Spring key variants, Hibernate element text, namespaced elements', () => {
    const cases: [string, string][] = [
      [`<add key="Smtp:${K}" value="${S}" />`, `<add key="Smtp:${K}" value="${R}" />`],
      [`<add key="App/Db${K}" value="${S}" />`, `<add key="App/Db${K}" value="${R}" />`],
      [`<add key="Smtp ${K}" value="${S}" />`, `<add key="Smtp ${K}" value="${R}" />`],
      [`<add key="Smtp.${K}" value="${S}" />`, `<add key="Smtp.${K}" value="${R}" />`],
      [`<property name="hibernate.connection.${k}">${S}</property>`, `<property name="hibernate.connection.${k}">${R}</property>`],
      [`<entry key="db.${k}">${S}</entry>`, `<entry key="db.${k}">${R}</entry>`],
      [`<setting name="Db${K}" serializeAs="String"><value>${S}</value></setting>`, `<setting name="Db${K}" serializeAs="String">${R}</setting>`],
      [`<db:${k}>${S}</db:${k}>`, `<db:${k}>${R}</db:${k}>`],
      [`<db:${k} type="t">${S}</db:${k}>`, `<db:${k} type="t">${R}</db:${k}>`],
    ];
    for (const [input, want] of cases) expect(redact(input), want).toBe(want);
    for (const keep of ['<add key="Smtp:Host" value="mail.example.com" />', '<property name="hibernate.dialect">x</property>', '<db:host>h</db:host>']) {
      expect(redact(keep), keep).toBe(keep);
    }
  });

  it('redact: block rule off only for code files (denylist), template and backup suffixes stripped', () => {
    const text = `${k}:\n  hidden-line\n`;
    const hidden = `${k}:\n  ${R}\n`;
    for (const path of ['config.yml.example', 'values.yaml.j2', 'app.yaml.tmpl', 'README.md', 'settings.json', 'Dockerfile', 'notes.txt', 'x.unknown', 'deploy/app.yml.dist', '.env.local', 'Procfile']) {
      expect(redact(text, { path }), path).toBe(hidden);
    }
    for (const path of ['app.py.bak', 'x.py', 'src/a.ts', 'b.go', 'Main.JAVA', 'run.sh', 'x.py.example.bak', 'lib/x.rb.orig']) {
      expect(redact(text, { path }), path).toBe(text);
    }
  });

  it('bundle: block rule off only for code files (denylist)', async () => {
    const dir = makeTempDir();
    const text = `${k}:\n  hidden-line\n`;
    for (const f of ['config.yml.example', 'values.yaml.j2', 'README.md', 'settings.json', 'Dockerfile', 'app.py.bak', 'x.py']) writeIn(dir, f, text);
    const b = await bundleCode(dir);
    for (const f of ['config.yml.example', 'values.yaml.j2', 'README.md', 'settings.json', 'Dockerfile']) expect(b.files.find((x) => x.path === f)?.content, f).toBe(`${k}:\n  ${R}\n`);
    for (const f of ['app.py.bak', 'x.py']) expect(b.files.find((x) => x.path === f)?.content, f).toBe(text);
  });

  it('scrubKnownValues: a typed value holding CRLF or a lone CR is removed from an LF file', async () => {
    expect(scrubKnownValues('a pre\nmid b', ['pre\r\nmid'])).toBe(`a ${R} b`);
    expect(scrubKnownValues('a pre\nmid b', ['pre\rmid'])).toBe(`a ${R} b`);
    expect(scrubKnownValues('a pre\r\nmid b', ['pre\r\nmid'])).toBe(`a ${R} b`);
    const dir = makeTempDir();
    writeIn(dir, 'src/a.txt', 'x pre\nmid y\n');
    writeIn(dir, 'src/b.txt', 'x pre\r\nmid y\r\n');
    const b = await bundleCode(dir, { knownValues: ['pre\r\nmid'] });
    for (const f of b.files) expect(f.content, f.path).toBe(`x ${R} y\n`);
  });

  it('redact: several trailing CRs on a line all count as the line end', () => {
    expect(redact(`${k}: |\r\r\n  v\r\r\nnext: 1`)).toBe(`${k}: |\r\r\n  ${R}\r\r\nnext: 1`);
    expect(redact(`${k}:\r\r\n  v\r\nnext: 1`)).toBe(`${k}:\r\r\n  ${R}\r\nnext: 1`);
    expect(redact(`${k}=x y\r\r\nok=1`)).toBe(`${k}=${R}\r\r\nok=1`);
  });
});

describe('fix round 5', () => {
  const k = 'pass' + 'word';
  const K = 'Pass' + 'word';
  const sec = 'sec' + 'ret';
  const S = 'S3kr' + 'etV4l';

  const unclosed = (): string[] => [
    `<${k}>${S}`,
    `<${k}>${S} <b>x</b>`,
    `<add key="Db${K}" value="Ab>${S}"/>`,
    `<property name="db.${k}" value="Ab>${S}"/>`,
    `<${k} value="Ab>${S}"/>`,
  ];

  it('redact: a secret element with no end tag on the line hides what follows its ">" (also a ">" inside a value)', () => {
    for (const input of unclosed()) expect(redact(input), input).not.toContain(S);
    expect(redact(`<${k}>${S}`)).toBe(`<${k}>${R}`);
    expect(redact(`<${k}>${S} <b>x</b>`)).toBe(`<${k}>${R}<b>x</b>`);
    expect(redact(`<add key="Db${K}" value="Ab>${S}"/>`)).toBe(`<add key="Db${K}" value="${R}>${R}`);
  });

  it('bundle: a secret element with no end tag on the line hides what follows its ">"', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'config/web.xml', unclosed().join('\n') + '\n');
    writeIn(dir, 'src/App.tsx', unclosed().join('\n') + '\n');
    const b = await bundleCode(dir);
    expect(paths(b)).toEqual(['config/web.xml', 'src/App.tsx']);
    expect(allText(b)).not.toContain(S);
  });

  it('redact: a JSON object or array under a secret-named key is hidden in config files, not in code', () => {
    const json = `{\n  "Logging": { "Level": "Info" },\n  "${K}s": {\n    "Admin": "${S}",\n    "Ops": [\n      "${S}"\n    ]\n  },\n  "Name": "app"\n}\n`;
    const hidden = `{\n  "Logging": { "Level": "Info" },\n  "${K}s": {\n    ${R}\n    ${R}\n      ${R}\n    ${R}\n  },\n  "Name": "app"\n}\n`;
    expect(redact(json, { path: 'appsettings.json' })).toBe(hidden);
    expect(redact(json)).toBe(hidden);
    expect(redact(`"${k}": [\n  "${S}"\n]`, { path: 'x.json' })).toBe(`"${k}": [\n  ${R}\n]`);
    expect(redact(json, { path: 'src/settings.ts' })).toBe(json);
  });

  it('redact: TOML/INI sections named after a secret hide the values below them', () => {
    const toml = `[${sec}s]\nadmin = "${S}"\nops: ${S}\n\n[other]\nname = "y"\n`;
    expect(redact(toml, { path: 'config.toml' })).toBe(`[${sec}s]\nadmin = ${R}\nops: ${R}\n\n[other]\nname = "y"\n`);
    expect(redact(`[database.${k}]\nmain = ${S}\n[[servers]]\nhost = "h"`, { path: 'app.ini' })).toBe(`[database.${k}]\nmain = ${R}\n[[servers]]\nhost = "h"`);
    expect(redact(`[au${'th'}]\nkey_id = ${S}\n`, { path: 'a.cfg' })).toBe(`[au${'th'}]\nkey_id = ${R}\n`);
    expect(redact(`[author]\nname = Jane\n`, { path: 'a.toml' })).toBe('[author]\nname = Jane\n');
    // not a header (Markdown link), and code files are left alone
    expect(redact(`[${sec}s](https://x/docs)\nname = Jane\n`, { path: 'README.md' })).toBe(`[${sec}s](https://x/docs)\nname = Jane\n`);
    expect(redact(toml, { path: 'gen.py' })).toBe(toml);
  });

  it('redact: .NET setting element ending its line hides the more-indented lines after it', () => {
    const xml = `<setting name="Db${K}" serializeAs="String">\n    <value>${S}</value>\n</setting>\n<setting name="Theme">\n    <value>dark</value>\n</setting>\n`;
    expect(redact(xml, { path: 'App.config' })).toBe(`<setting name="Db${K}" serializeAs="String">\n    ${R}\n</setting>\n<setting name="Theme">\n    <value>dark</value>\n</setting>\n`);
    expect(redact(`<${k}>\n  ${S}\n</${k}>`, { path: 'a.xml' })).toBe(`<${k}>\n  ${R}\n</${k}>`);
    expect(redact(xml, { path: 'Gen.cs' })).toBe(xml);
  });
});

describe('closing patch', () => {
  const sec = 'sec' + 'ret';
  const S = 'S3kr' + 'etV4l';

  it('redact: in a secret section, a line is kept only when the text before its separator is a plain key name', () => {
    const head = `[${sec}s]\n`;
    const red = (body: string) => redact(head + body, { path: 'config.toml' }).slice(head.length);
    expect(red(`api ${S} = v`)).toBe(R);
    expect(red(`  note ${S} more: v`)).toBe(`  ${R}`);
    expect(red(`x(${S}) = v`)).toBe(R);
    expect(red(`${fake.githubClassic()} = v`)).toBe(`${R} = ${R}`); // a plain key still goes through the token rules
    expect(red('admin =')).toBe('admin =');
    expect(red('admin = x')).toBe(`admin = ${R}`);
    expect(red(`"db.main" = x`)).toBe(`"db.main" = ${R}`);
    expect(red(`  key-1: x`)).toBe(`  key-1: ${R}`);
  });

  it('redact: sections named after credentials hide their values', () => {
    for (const header of ['[credentials]', '[[credentials]]', '[aws.credentials]', '[Credential]']) {
      expect(redact(`${header}\nuser = u\nother = ${S}\n[pub]\nname = keep\n`, { path: 'a.toml' }), header)
        .toBe(`${header}\nuser = ${R}\nother = ${R}\n[pub]\nname = keep\n`);
    }
  });
});

// Plan U T0b: in GitHub workflow files (.github/workflows/*.yml|yaml) and action.yml|yaml, a value that is exactly one
// plain context reference, `id-token` set to write|read|none and `secrets` set to inherit stay readable. Everything else is hidden
// as before. Secret-like words are joined at runtime so this file passes its own redact check.
describe('workflow allow-list (T0b)', () => {
  const TOK = 'tok' + 'en';
  const SECS = 'sec' + 'rets';
  const NPM = `NPM_${TOK.toUpperCase()}`;
  const ID = `id-${TOK}`;
  const ref = (name = NPM, ctx = SECS) => '${{ ' + `${ctx}.${name}` + ' }}';
  const line = (key: string, value: string) => `          ${key}: ${value}`;
  const WF = '.github/workflows/release.yml';
  const hidden = (key: string) => line(key, R);

  it('redact: NPM key = one secrets reference stays in a workflow, is hidden in a .ts file', () => {
    const text = line(NPM, ref());
    expect(redact(text, { path: WF })).toBe(text);
    expect(redact(text, { path: 'src/release.ts' })).toBe(hidden(NPM));
    expect(redact(text)).toBe(hidden(NPM)); // no path: hidden
    expect(redact(text, { path: 'README.md' })).toBe(hidden(NPM));
    for (const path of ['.github/workflows/ci.yaml', 'action.yml', 'action.yaml', 'tools/setup/action.yml', '/abs/repo/.github/workflows/ci.yml', 'pkg/.github/workflows/ci.yml']) {
      expect(redact(text, { path }), path).toBe(text);
    }
  });

  it('redact: id-token write|read|none and secrets inherit stay in a workflow', () => {
    for (const v of ['write', 'read', 'none', '"write"', "'read'"]) {
      const text = `  ${ID}: ${v}`;
      expect(redact(text, { path: WF }), v).toBe(text);
      const q = v.startsWith('"') || v.startsWith("'") ? v[0] : '';
      expect(redact(text, { path: 'src/a.ts' }), v).toBe(`  ${ID}: ${q}${R}${q}`);
    }
    for (const v of ['inherit', '"inherit"']) {
      const text = `    ${SECS}: ${v}`;
      expect(redact(text, { path: WF }), v).toBe(text);
      expect(redact(text, { path: 'action.yml' }), v).toBe(text);
      expect(redact(text), v).toBe(`    ${SECS}: ${v.startsWith('"') ? `"${R}"` : R}`);
    }
  });

  it('redact: a whole workflow keeps its plain references, hides the rest (exact output)', () => {
    const pw = 'DB_PASS' + 'WORD';
    const AK = 'API' + '_KEY';
    const lines = [
      'name: release',
      'on: push',
      'permissions:',
      '  contents: read',
      `  ${ID}: write`,
      'jobs:',
      '  publish:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: npm publish',
      '        env:',
      `          ${NPM}: ${ref()}`,
      `          GH_${TOK.toUpperCase()}: "${ref(TOK, 'github')}"`,
      `          ${pw}: '` + '${{' + `${SECS}.${pw}` + "}}'",
      `          ${AK}: ${ref(AK, 'vars')}`,
      `          ${pw}_2: hunter2`,
      '  call:',
      '    uses: ./.github/workflows/x.yml',
      `    ${SECS}: inherit`,
      '',
    ];
    const expected = [...lines];
    expected[15] = `          ${pw}_2: ${R}`;
    expect(redact(lines.join('\n'), { path: WF })).toBe(expected.join('\n'));
  });

  it('redact: every allowed context, optional spaces, trailing blanks; other contexts and shapes hidden', () => {
    for (const ctx of [SECS, 'vars', 'github', 'env', 'inputs', 'steps', 'needs', 'matrix']) {
      const text = line(NPM, ref('a.B-c_9', ctx));
      expect(redact(text, { path: WF }), ctx).toBe(text);
    }
    for (const v of ['${{' + SECS + '.X}}', '${{   ' + SECS + '.X   }}', `${ref()}  `, `${ref()}\t`]) {
      const text = line(NPM, v);
      expect(redact(text, { path: WF }), v).toBe(text);
    }
    for (const v of [
      ref('X', 'runner'), ref('X', 'job'), ref('X', 'secret'), ref('X', 'Secrets'), ref('X', 'foo'), ref('', SECS),
      ref('a b'), ref("a'b"), ref('a[0]'), '${{\t' + SECS + '.X }}', '${{ ' + SECS + ' }}', '${ ' + SECS + '.X }', '{{ ' + SECS + '.X }}',
    ]) {
      expect(redact(line(NPM, v), { path: WF }), v).toBe(hidden(NPM));
    }
    expect(redact(line(NPM, `\`${ref()}\``), { path: WF })).toBe(line(NPM, `\`${R}\``)); // backticks are not YAML quotes
  });

  it('redact: hostile values next to or around a reference stay hidden in a workflow', () => {
    const X = ref('X');
    for (const v of [
      `${X}extra`, `prefix${X}`, `${X}${X}`, `${X} ${X}`, `${X} # note`, `${X}}`, `$${X}`,
      '${{ ' + SECS + ".X || 'hunter2' }}", "${{ format('{0}', 'pw') }}", '${{ ' + SECS + '.X }} || hunter2',
    ]) {
      expect(redact(line(NPM, v), { path: WF }), v).toBe(hidden(NPM));
    }
    // quoted: the inside is hidden, the quotes stay
    expect(redact(line(NPM, `"${X} x"`), { path: WF })).toBe(line(NPM, `"${R}"`));
    expect(redact(line(NPM, `'${X}"`), { path: WF })).toBe(line(NPM, `'${R}`));
    expect(redact(line(NPM, `"${X}`), { path: WF })).toBe(line(NPM, `"${R}`));
    expect(redact(line(NPM, `"${X}" x`), { path: WF })).toBe(line(NPM, `"${R}" x`));
    // a flow mapping is not a plain value
    expect(redact(`permissions: { ${ID}: write }`, { path: WF })).toBe(`permissions: { ${ID}: ${R}`);
  });

  it('redact: id-token and secrets keep only their exact values, under their exact keys', () => {
    for (const v of ['writeX', 'write extra', 'admin', 'inherit', '"write', "'write\"", 'write # c', 'Write']) {
      expect(redact(`  ${ID}: ${v}`, { path: WF }), v).not.toContain(v);
    }
    for (const v of ['inherited', 'write', 'inherit x', 'Inherit']) {
      expect(redact(`  ${SECS}: ${v}`, { path: WF }), v).toBe(`  ${SECS}: ${R}`);
    }
    for (const k of [`ID-${TOK.toUpperCase()}`, `x-${ID}`, `${ID}s`, `my_${SECS}`, 'Sec' + 'rets', `${SECS}.x`]) {
      expect(redact(`  ${k}: ${k.toLowerCase().includes('id') ? 'write' : 'inherit'}`, { path: WF }), k).toBe(`  ${k}: ${R}`);
    }
  });

  it('redact: a real token next to an allowed reference is still hidden', () => {
    const gh = fake.githubClassic();
    expect(redact(line(NPM, `${ref()} ${gh}`), { path: WF })).toBe(hidden(NPM));
    expect(redact(line(NPM, ref(gh)), { path: WF })).toBe(hidden(NPM)); // a token as the reference name
    expect(redact(`        run: echo ${ref()} ${fake.npmPublish()}`, { path: WF })).toBe(`        run: echo ${ref()} ${R}`);
    expect(redact(`${line(NPM, ref())}\n          OTHER: ${gh}`, { path: WF })).toBe(`${line(NPM, ref())}\n          OTHER: ${R}`);
    expect(redact(`  ${ID}: ${fake.jwt()}`, { path: WF })).toBe(`  ${ID}: ${R}`);
  });

  it('redact: a multi-line value under a key stays hidden, also after an allowed reference', () => {
    const X = ref('X');
    expect(redact(`${line(NPM, '|')}\n            ${X}\n            hunter2\n          next: 1`, { path: WF }))
      .toBe(`${line(NPM, '|')}\n            ${R}\n            ${R}\n          next: 1`);
    expect(redact(`${line(NPM, '>-')}\n            ${X}`, { path: WF })).toBe(`${line(NPM, '>-')}\n            ${R}`);
    expect(redact(`${line(NPM, '')}\n            ${X}`, { path: WF })).toBe(`${line(NPM, '')}\n            ${R}`);
    // a plain YAML value may go on over more-indented lines: those are hidden after a kept reference
    expect(redact(`${line(NPM, X)}\n              hunter2\n          next: 1`, { path: WF }))
      .toBe(`${line(NPM, X)}\n              ${R}\n          next: 1`);
    expect(redact(`  ${ID}: write\n    hunter2\n  contents: read`, { path: WF })).toBe(`  ${ID}: write\n    ${R}\n  contents: read`);
    // the nested `secrets` mapping of a reusable-workflow call is still hidden whole (over-redaction, documented)
    expect(redact(`    ${SECS}:\n      ${NPM}: ${X}`, { path: WF })).toBe(`    ${SECS}:\n      ${R}`);
  });

  it('redact: the allow-list holds only for workflow and action paths', () => {
    const text = `${line(NPM, ref())}\n  ${ID}: write\n    ${SECS}: inherit`;
    const all = `${hidden(NPM)}\n  ${ID}: ${R}\n    ${R}`; // the last line is more indented than a hidden plain value
    for (const path of [
      'workflows.yml.txt', '.github/workflows.yml.txt', '.github/workflows/ci.yml.txt', '.github/workflows/ci.yml.bak', '.github/workflows/ci.json',
      '.github/workflows/../../x.yml', '.github/workflows/./ci.yml', 'x/../.github/workflows/ci.yml', '.github/workflows//ci.yml',
      '.github/workflows/sub/ci.yml', '.github/ci.yml', 'workflows/ci.yml', '.GITHUB/WORKFLOWS/CI.YML', '.github/workflows/ci.YML',
      '.github\\workflows\\ci.yml', '.github/workflows/.yml', 'action.yml.txt', 'myaction.yml', 'action.json', 'dir/action.yml/x.yml', 'action.ymlx',
      '.github/workflows/ci.ym', '.github/workflows/ci.yaaml',
    ]) {
      expect(redact(text, { path }), path).toBe(all);
    }
  });

  it('redact: CRLF workflow keeps the allowed lines (with their CRs) and hides the hostile ones', () => {
    const X = ref('X');
    const text = [line(NPM, X), line(ID, 'write'), line(SECS, 'inherit'), line(NPM, `${X}extra`), line(NPM, `prefix${X}`), line(ID, 'writeX'), line(NPM, '|'), `            ${X}`, ''].join('\r\n');
    const expected = [line(NPM, X), line(ID, 'write'), line(SECS, 'inherit'), hidden(NPM), hidden(NPM), hidden(ID), line(NPM, '|'), `            ${R}`, ''].join('\r\n');
    expect(redact(text, { path: WF })).toBe(expected);
    // a lone CR inside the line is not a line end: the value is not exactly one reference
    expect(redact(line(NPM, `${X}\rhunter2`), { path: WF })).toBe(hidden(NPM));
  });

  it('bundle: known values and gitleaks still apply to workflow files', async () => {
    const known = 'tenant' + '-wf-' + 'q77';
    const found = 'GlFound' + 'Val' + '99';
    const dir = makeTempDir();
    const [A, B] = ['A_', 'B_'].map((p) => p + TOK.toUpperCase());
    writeIn(dir, '.github/workflows/ci.yml', [line(NPM, ref()), line(A, ref(known)), line(ID, 'write'), line(B, `${ref()} ${found}`), line('C', found), ''].join('\n'));
    const b = await bundleCode(dir, scanWith(gitleaksAt(makeStub(reportValue(found)).bin), { knownValues: [known] }));
    expect(b.files.map((f) => f.content)).toEqual([[line(NPM, ref()), hidden(A), line(ID, 'write'), hidden(B), line('C', R), ''].join('\n')]);
  });

  it('redact: workflow-path scanning stays linear', () => {
    const shapes = [
      `${TOK}: "${ref()}" `, `${TOK}: "` + '${{ ' + SECS + '.' + 'a'.repeat(60) + '" ', `${TOK}:'` + '${{' + ' '.repeat(40) + "' ", `${ID}: "write" `,
      `${TOK}: '${ref()}'` + ' '.repeat(30) + 'x ', `"${TOK}": "write" `,
    ];
    const fromLines = (u: string, L: number, bytes: number) => {
      const l = u.repeat(Math.max(1, Math.floor(L / u.length))) + '\n';
      return l.repeat(Math.max(1, Math.round(bytes / l.length)));
    };
    const best = (t: string) => Math.min(...[0, 1, 2].map(() => {
      const s = performance.now();
      redact(t, { path: WF });
      return performance.now() - s;
    }));
    const failures: string[] = [];
    for (const u of shapes) {
      const long = fromLines(u, 4000, 256 * 1024);
      const short = fromLines(u, 512, 256 * 1024);
      redact(long, { path: WF }); // warm-up
      const ratio = best(long) / Math.max(best(short), 3);
      if (ratio >= 3) failures.push(`${u}: ${ratio.toFixed(2)}`);
    }
    expect(failures).toEqual([]);
  }, 60_000);
});

// Plan U T0b fix round 1: a plain (unquoted) value can go on over the more-indented lines after it (YAML plain
// scalars, INI continuation lines), so those lines are hidden too; a section header hidden that way still counts;
// doubled quotes ('it''s', "a""b") are an escape; an unclosed double-quoted value goes on over the next lines.
describe('T0b fix round 1: continuation lines and quotes', () => {
  const X = 'Zq' + 'Sek9' + 'rt';
  const P = 'pass' + 'word';
  const T = 'TOK' + 'EN';
  const t = 'tok' + 'en';

  it('redact: the more-indented lines after a hidden plain value are hidden (YAML, INI, .env, no path)', () => {
    expect(redact(`db:\n  ${P}: abc\n    ${X}\n  host: h`, { path: 'config/app.yml' })).toBe(`db:\n  ${P}: ${R}\n    ${R}\n  host: h`);
    expect(redact(`${P}: abc\n  ${X}`)).toBe(`${P}: ${R}\n  ${R}`);
    expect(redact(`[db]\n${P} = abc\n  ${X}\nhost = h`, { path: 'setup.cfg' })).toBe(`[db]\n${P} = ${R}\n  ${R}\nhost = h`);
    expect(redact(`${T}=abc\n  ${X}`, { path: '.env.example' })).toBe(`${T}=${R}\n  ${R}`);
    expect(redact(`- ${P}: abc\n    ${X}`, { path: 'a.yaml' })).toBe(`- ${P}: ${R}\n    ${R}`);
    expect(redact(`  ${t}: abc\n    ${X}`, { path: '.github/workflows/c.yml' })).toBe(`  ${t}: ${R}\n    ${R}`);
  });

  it('redact: a sibling key in a YAML sequence entry is hidden too (over-redaction, accepted)', () => {
    expect(redact(`- ${P}: abc\n  host: h\n- name: n`, { path: 'a.yaml' })).toBe(`- ${P}: ${R}\n  ${R}\n- name: n`);
  });

  it('redact: continuation hiding holds across CRLF, tabs, blank lines and nested continuations', () => {
    expect(redact(`${P}: abc\r\n  ${X}\r\n`, { path: 'a.yml' })).toBe(`${P}: ${R}\r\n  ${R}\r\n`);
    expect(redact(`${P}: abc\n\t${X}`, { path: 'a.yml' })).toBe(`${P}: ${R}\n\t${R}`);
    expect(redact(`${P}: abc\n\n  ${X}`, { path: 'a.yml' })).toBe(`${P}: ${R}\n\n  ${R}`);
    expect(redact(`${P}: abc\n  def\n      ${X}\nnext: 1`, { path: 'a.yml' })).toBe(`${P}: ${R}\n  ${R}\n      ${R}\nnext: 1`);
  });

  it('redact: an unquoted Authorization value goes on over more-indented lines too', () => {
    const A = 'Author' + 'ization: Bearer';
    expect(redact(`${A} abc\n   ${X}`, { path: 'h.yml' })).toBe(`${A} ${R}\n   ${R}`);
  });

  it('redact: controls: code files, closed quoted values and same-indent lines are unchanged', () => {
    expect(redact(`${P} = abc\n    ${X}`, { path: 'a.py' })).toBe(`${P} = ${R}\n    ${X}`); // no block rule in code
    expect(redact(`${P}: "abc"\n  ${X}`, { path: 'a.yml' })).toBe(`${P}: "${R}"\n  ${X}`); // a closed quote can't go on
    expect(redact(`db:\n  ${P}: abc\n  host: ${X}`, { path: 'config/app.yml' })).toBe(`db:\n  ${P}: ${R}\n  host: ${X}`);
  });

  it('redact: a section header inside a hidden block still starts a secret section', () => {
    const C = '[credentials]';
    expect(redact(`${t}_ttl = 3600\n  ${C}\nuser = ${X}`, { path: 'a.toml' })).toBe(`${t}_ttl = ${R}\n  ${R}\nuser = ${R}`);
    expect(redact(`${P} =\n  ${C}\nuser = ${X}`, { path: 'a.toml' })).toBe(`${P} =\n  ${R}\nuser = ${R}`);
    expect(redact(`x = ${'a'.repeat(5000)}\n  ${C}\nuser = ${X}`, { path: 'a.toml' })).toBe(`[REDACTED: line too long]\n  ${R}\nuser = ${R}`);
    // a header hidden in a block never ends a secret section (it may be part of the hidden value)
    expect(redact(`[sec${'rets'}]\na = b\n${P} = x\n  [pub]\nname = v`, { path: 'a.toml' })).toBe(`[sec${'rets'}]\na = ${R}\n${P} = ${R}\n  ${R}\nname = ${R}`);
    expect(redact(`[credentials]\n${P}=\n    [db]\n-x\nk = ${X}`, { path: 'a.ini' })).toBe(`[credentials]\n${P}=\n    ${R}\n${R}\nk = ${R}`);
  });

  it('redact: a line in a secret section still starts the block it would start outside one', () => {
    // without this, a header hidden in a block turns the next lines into section lines, which show their keys
    const az = 'Author' + 'ization=';
    expect(redact(`${t}: x\n    [sec${'rets'}]\n- ${az}\n    name=v\nnext = 1`, { path: 'setup.cfg' }))
      .toBe(`${t}: ${R}\n    ${R}\n${R}\n    ${R}\nnext = ${R}`);
    expect(redact(`${t}: x\n  [sec${'rets'}]\n${P}: {\n  [db]\nm = 1`, { path: '.env' })).toBe(`${t}: ${R}\n  ${R}\n${P}: ${R}\n  ${R}\nm = ${R}`);
  });

  it('redact: a section header after a kept workflow value is still tracked', () => {
    expect(redact(`  id-${t}: write\n    [credentials]\n  user = ${X}`, { path: '.github/workflows/c.yml' }))
      .toBe(`  id-${t}: write\n    ${R}\n  user = ${R}`);
  });

  it('redact: doubled quotes are an escape inside a quoted value (YAML single quotes, SQL, CSV)', () => {
    expect(redact(`${P}: 'it''s${X}'`, { path: 'a.yml' })).toBe(`${P}: '${R}'`);
    expect(redact(`${P} = 'a''${X}' and more`, { path: 'q.sql' })).toBe(`${P} = '${R}' and more`);
    expect(redact(`"${P}": "a""${X}"`, { path: 'a.csv' })).toBe(`"${P}": "${R}"`);
    expect(redact(`${P}: ''\nuser: u`, { path: 'a.yml' })).toBe(`${P}: ''\nuser: u`); // an empty value is still empty
    // the doubled reading only adds hiding: a secret name after a plain closing quote is still found
    expect(redact(`${P}: 'x'' ${t}: 'hunter2'`, { path: 'a.yml' })).toBe(`${P}: '${R}'${R}'`);
    expect(redact(`${P}='abc'' ${T}='hunter2'`, { path: 'run.sh' })).toBe(`${P}='${R}'${R}'`);
  });

  it('redact: an unclosed double-quoted value goes on over the next, more-indented lines', () => {
    expect(redact(`${P}: "abc\n  ${X}"\nuser: u`, { path: 'a.yml' })).toBe(`${P}: "${R}\n  ${R}\nuser: u`);
  });
});
