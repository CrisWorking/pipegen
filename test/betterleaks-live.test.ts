// Live integration test against the REAL pinned betterleaks 1.9.0 (Plan P Task 7): the required local secret scan
// before `audit --ai` sends code to an AI. It checks redact.ts's assumptions (argv, exit codes, report fields, config,
// allow comments, ignore files) against the real binary, with the exact argv redact.ts builds (secretScanArgv).
// Network: it downloads the pinned release from github.com into ~/.cache/pipegen/tools (once; later runs re-verify the
// cache). Skipped unless PIPEGEN_LIVE_TESTS=1, so `npm test` stays offline; ci.yml runs it in its own step.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, isAbsolute, join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { bundleCode, bundleText, redact, SECRET_SCAN_EXIT, secretScanArgv, secretScanConfigPath, type SecretScannerName } from '../src/ai/redact.js';
import { ensurePinnedBinary, loadPinnedBinaries } from '../src/engine/linters.js';
import { BETTERLEAKS_FORBIDDEN_FLAGS } from '../src/engine/tool-flags.js';
import { betterleaksAt, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';

// Secret-like values, built at runtime (repo rule: no secret-like literals in test/). The first two get past pipegen's
// own redact() patterns, so only the scanner can catch them; the third is pipegen's own connection-string rule.
const shopifyValue = () => 'shp' + 'at_' + '0123456789abcdef'.repeat(2);
const gitlabValue = () => 'glp' + 'at-' + 'Ab12Cd34Ef56Gh78Ij90';
const connString = () => 'postgres' + '://' + 'app' + ':' + 'Zq9' + 'wX7vB5nM3' + '@' + 'db.internal:5432/app';
// redact()'s documented limit (src/ai/redact.ts connectionSpans): with a `#` in the password, the part after it stays.
// The scanner's connection-string rule is the second line there.
const connPastRedact = () => 'postgres' + '://' + 'admin' + ':' + 'P@ss' + '#' + 'Wq7Lz9' + '@' + 'db/app';
const GL_ALLOW = 'gitleaks' + ':allow';
const BL_ALLOW = 'betterleaks' + ':allow';
// A betterleaks ignore-file entry, file, rule id and line joined by colons (built at runtime: redact() would hide a
// literal one)
const fingerprint = (file: string, rule: string, line: number) => [file, rule, String(line)].join(':');
const SHOPIFY = ['shopify', 'access', 'token'].join('-');

interface Finding { File: string; StartLine: number; EndLine: number; RuleID: string; Secret?: string; Match?: string; Tags?: string[] }
interface Scan { argv: string[]; code: number; report: Finding[] | null }

let bin = '';

/** Runs the real betterleaks with redact.ts's own argv over `dir` (cwd `dir`, env PATH and HOME only). */
function scan(dir: string, config = secretScanConfigPath()): Scan {
  const argv = secretScanArgv('betterleaks', dir, config, join(dir, 'report.json'));
  const reportPath = join(dir, 'report.json');
  let code = 0;
  const env: Record<string, string> = {};
  if (process.env.PATH !== undefined) env.PATH = process.env.PATH;
  if (process.env.HOME !== undefined) env.HOME = process.env.HOME;
  try {
    execFileSync(bin, argv, { cwd: dir, env, stdio: 'pipe', timeout: 120_000 });
  } catch (e) {
    const status = (e as { status?: number | null }).status;
    if (typeof status !== 'number') throw e;
    code = status;
  }
  return { argv, code, report: existsSync(reportPath) ? (JSON.parse(readFileSync(reportPath, 'utf8')) as Finding[]) : null };
}
const key = (f: Finding) => `${basename(f.File)}:${f.StartLine}:${f.RuleID}`;

describe.skipIf(!live)('betterleaks (live, real pinned binary)', () => {
  beforeAll(async () => {
    bin = await ensurePinnedBinary('betterleaks');
  }, 600_000);
  afterEach(cleanupRepos);

  it('live: ensurePinnedBinary gives the verified pinned betterleaks; a second call re-checks the cached copy', async () => {
    const version = execFileSync(bin, ['version'], { encoding: 'utf8' }).trim();
    console.log(`pinned betterleaks: ${bin} (version ${version})`);
    expect(version).toBe(loadPinnedBinaries().betterleaks.version);
    expect(statSync(bin).mode & 0o777).toBe(0o700);
    expect(await ensurePinnedBinary('betterleaks')).toBe(bin);
  });

  it('live: the fixed argv runs; data/gitleaks-bundle.toml compiles under RE2 with [extend] useDefault; a clean folder exits 0 with an empty report', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', 'export const greeting = "hello";\n');
    const r = scan(dir);
    console.log(`betterleaks argv: ${JSON.stringify(r.argv.map((a) => a.split(dir).join('<tmp>')))}`);
    expect(r.argv.slice(0, 2)).toEqual(['dir', dir]);
    for (const flag of BETTERLEAKS_FORBIDDEN_FLAGS) expect(r.argv).not.toContain(flag);
    expect(r.argv.some((a) => a.startsWith('--redact'))).toBe(false);
    expect({ code: r.code, report: r.report }).toEqual({ code: SECRET_SCAN_EXIT.clean, report: [] });
  });

  it('live: betterleaks finds the planted shopify/gitlab/connection-string values; report fields parsed; repo .betterleaks.toml and .gitleaks.toml ignored', async () => {
    // 1. The raw scan: default rules and pipegen's own rule fire; exit "found"; the fields redact.ts reads, by these names
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `const shop = "${shopifyValue()}";\n`);
    writeIn(dir, 'f000002.txt', `line one\nconst lab = "${gitlabValue()}";\n`);
    writeIn(dir, 'f000003.txt', `DATABASE_URL=${connString()}\n`);
    // a config or ignore file in the scanned folder that would allow everything: --config wins over both configs
    writeIn(dir, '.betterleaks.toml', '[allowlist]\npaths = [".*"]\n');
    writeIn(dir, '.gitleaks.toml', '[allowlist]\npaths = [".*"]\n');
    const { code, report } = scan(dir);
    expect(code).toBe(SECRET_SCAN_EXIT.found);
    expect(report?.map(key).sort()).toEqual(['f000001.txt:1:shopify-access-token', 'f000002.txt:2:gitlab-pat', 'f000003.txt:1:pipegen-connection-string-password']);
    for (const f of report ?? []) {
      expect(isAbsolute(f.File)).toBe(true);
      expect(f.File.startsWith(`${dir}/`)).toBe(true);
      expect(Number.isInteger(f.StartLine) && f.StartLine >= 1 && f.EndLine >= f.StartLine).toBe(true);
      expect(typeof f.Secret).toBe('string');
      expect(f.Match).toContain(f.Secret);
    }
    const lab = report?.find((f) => f.RuleID === 'gitlab-pat') as Finding;
    expect([lab.StartLine, lab.EndLine, lab.Secret]).toEqual([2, 2, gitlabValue()]);
    expect(report?.find((f) => f.RuleID === 'pipegen-connection-string-password')?.Secret).toBe('Zq9wX7vB5nM3');

    // 2. End to end through bundleCode: the repo's own configs and ignore files allow everything, and change nothing
    const shop = shopifyValue();
    const line = `export const shop = '${shop}';`;
    expect(redact(line)).toBe(line); // pipegen's own patterns miss it: only the scanner can catch it
    expect(redact(connPastRedact())).toContain('Wq7Lz9'); // redact()'s documented limit
    const repo = makeTempDir();
    writeIn(repo, '.betterleaks.toml', '[allowlist]\npaths = [".*"]\n');
    writeIn(repo, '.gitleaks.toml', '[allowlist]\npaths = [".*"]\n');
    writeIn(repo, '.betterleaksignore', `${fingerprint('f000001.txt', SHOPIFY, 1)}\n`);
    writeIn(repo, '.gitleaksignore', `${fingerprint('f000001.txt', SHOPIFY, 1)}\n`);
    writeIn(repo, 'src/config.ts', `${line}\nexport const lab = '${gitlabValue()}';\n`);
    writeIn(repo, 'src/db.ts', `export const url = '${connString()}';\nexport const old = '${connPastRedact()}';\n`);
    writeIn(repo, 'docs/notes.md', `# Notes\nThe shop value is ${shop} (copied here by mistake).\n`);
    writeIn(repo, 'src/app.ts', "import { shop } from './config';\nconsole.log(typeof shop);\n");
    const bundle = await bundleCode(repo, scanWith(betterleaksAt(bin, loadPinnedBinaries().betterleaks.version)));
    expect(bundle.secretScanChecked).toBe(true);
    const text = bundleText(bundle);
    for (const v of [shop, gitlabValue(), connString(), 'Zq9wX7vB5nM3', 'Wq7Lz9']) expect(text).not.toContain(v);
    expect(text).toContain('src/app.ts'); // the clean file is still there
    expect(text).toContain('src/config.ts'); // redacted in place, not left out: the reported File/lines/Secret were used
    const notes = bundle.notes.join('\n');
    expect(notes).toMatch(/betterleaks checked the bundle: [1-9]\d* findings? redacted/);
    expect(notes).not.toMatch(/could not locate|outside the scanned folder/);
  });

  it('live: a config error exits 1 (the "found" code) and writes no report: redact.ts turns that into SecretScanError', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', 'hello\n');
    const cfg = makeTempDir();
    writeIn(cfg, 'bad.toml', 'this is [[[ not toml\n');
    writeIn(cfg, 'bad-regex.toml', "title = \"bad\"\n[[rules]]\nid = \"x\"\nregex = '''(?<=a)b'''\n"); // look-behind: not RE2
    for (const name of ['bad.toml', 'bad-regex.toml', 'missing.toml']) {
      const { code, report } = scan(dir, join(cfg, name));
      expect(code, name).toBe(SECRET_SCAN_EXIT.found);
      // redact.ts: exit "found" without a report → SecretScanError('wrote no report'); with an empty one → 'listed none'
      expect(report, name).toBeNull();
    }
  });

  it('live: allow comments: betterleaks honours gitleaks:allow and betterleaks:allow, but not with --ignore-gitleaks-allow nor once neutralised', () => {
    const shop = shopifyValue();
    for (const comment of [GL_ALLOW, BL_ALLOW]) {
      const raw = makeTempDir();
      writeIn(raw, 'f000001.txt', `const shop = "${shop}"; // ${comment}\n`);
      // without the flag the line is skipped (so the bundle never carries the comment); with it, it is found
      const argvNoFlag = secretScanArgv('betterleaks', raw, secretScanConfigPath(), join(raw, 'report.json')).filter((a) => a !== '--ignore-gitleaks-allow');
      let codeNoFlag = 0;
      try {
        execFileSync(bin, argvNoFlag, { cwd: raw, env: { PATH: process.env.PATH ?? '' }, stdio: 'pipe' });
      } catch (e) {
        codeNoFlag = (e as { status: number }).status;
      }
      expect(codeNoFlag, comment).toBe(SECRET_SCAN_EXIT.clean);
      const withFlag = makeTempDir();
      writeIn(withFlag, 'f000001.txt', `const shop = "${shop}"; // ${comment}\n`);
      expect(scan(withFlag).report?.map(key), comment).toEqual(['f000001.txt:1:shopify-access-token']);
      const neutral = makeTempDir();
      writeIn(neutral, 'f000001.txt', `const shop = "${shop}"; // ${comment.replace(':', '-')}\n`);
      expect(scan(neutral).report?.map(key), comment).toEqual(['f000001.txt:1:shopify-access-token']);
    }
  });

  it('live: an ignore file in the scanned folder is read (so redact.ts writes only neutral names there); the neutral names are not allow-listed', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `const shop = "${shopifyValue()}";\n`);
    writeIn(dir, 'paths.txt', `src/app.ts\nconfig/${gitlabValue()}.txt\n`);
    expect(scan(dir).report?.map(key).sort()).toEqual(['f000001.txt:1:shopify-access-token', 'paths.txt:2:gitlab-pat']);
    // a .betterleaksignore with that finding's fingerprint, in the scanned folder, hides it: never let a repo put one there
    writeIn(dir, '.betterleaksignore', `${fingerprint(join(dir, 'f000001.txt'), SHOPIFY, 1)}\n`);
    expect(scan(dir).report?.map(key).sort()).toEqual(['paths.txt:2:gitlab-pat']);
  });

  it('live: a base64-encoded secret is found decoded: its Secret is not in the file, so redact.ts leaves that file out', async () => {
    const encoded = Buffer.from(['tok' + 'en', shopifyValue()].join('=')).toString('base64');
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `blob = "${encoded}"\n`);
    const f = scan(dir).report?.[0] as Finding;
    expect(f.Tags).toContain('decoded:base64');
    expect(f.Secret).toBe(shopifyValue());
    const repo = makeTempDir();
    writeIn(repo, 'src/blob.ts', `export const blob = "${encoded}";\n`);
    writeIn(repo, 'src/app.ts', 'export const a = 1;\n');
    const bundle = await bundleCode(repo, scanWith(betterleaksAt(bin, loadPinnedBinaries().betterleaks.version)));
    expect(bundle.files.map((x) => x.path)).toEqual(['src/app.ts']);
    expect(bundle.notes.join('\n')).toMatch(/Left out because betterleaks found something pipegen could not locate to redact/);
  });

  it('live: the review probe (P31): a base64 blob of an api-key assignment plus the same value plain elsewhere in the file → the file is left out', async () => {
    const S = 'Zr8' + 'Kp2Wm5Qx9Lt4Vn7Bc3';
    const blob = Buffer.from(['api', 'key'].join('_') + '=' + S).toString('base64');
    const repo = makeTempDir();
    writeIn(repo, 'src/k.ts', `export const blob = "${blob}";\nexport const sample = "${S}";\n`);
    writeIn(repo, 'src/app.ts', 'export const a = 1;\n');
    const bundle = await bundleCode(repo, scanWith(betterleaksAt(bin, loadPinnedBinaries().betterleaks.version)));
    const text = bundleText(bundle);
    expect(text).not.toContain(blob);
    expect(text).not.toContain(S);
    expect(bundle.files.map((x) => x.path)).toEqual(['src/app.ts']);
  });
});

// Ruling P30 (Task 7 review C1): both pinned scanners sniff each file's first bytes and silently skip one that looks
// like a binary format, with a clean exit. These text heads (the review's list) all do that, so pipegen writes every
// scanned file, and paths.txt, after one leading newline.
const BINARY_HEADS = ['%!PS-Adobe-3.0', '%!', 'MZ', '%PDF-1.7', '{\\rtf1', 'SQLite format 3', 'FWS', 'CWS', 'BZh91AY&SY', 'MSCF', '!<arch>'];

describe.skipIf(!live)('secret scan (live, both pinned scanners): files that start like a binary format', () => {
  const bins: Partial<Record<SecretScannerName, string>> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterEach(cleanupRepos);

  /** One scan with redact.ts's argv for `name`; the report's findings by file name and line. */
  const scanWithArgv = (name: SecretScannerName, dir: string) => {
    const reportPath = join(dir, 'report.json');
    try {
      execFileSync(bins[name] as string, secretScanArgv(name, dir, secretScanConfigPath(), reportPath), { cwd: dir, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, stdio: 'pipe' });
    } catch (e) {
      if (typeof (e as { status?: unknown }).status !== 'number') throw e;
    }
    return (JSON.parse(readFileSync(reportPath, 'utf8')) as Finding[]).map((f) => `${basename(f.File)}:${f.StartLine}`).sort();
  };

  it('live: all 11 heads are skipped when written raw, and scanned once pipegen adds its leading newline (betterleaks and gitleaks)', () => {
    const shop = shopifyValue();
    for (const name of ['betterleaks', 'gitleaks'] as const) {
      const raw = makeTempDir();
      const prefixed = makeTempDir();
      BINARY_HEADS.forEach((head, i) => {
        const file = `f${String(i + 1).padStart(6, '0')}.txt`;
        writeIn(raw, file, `${head}\nconst shop = "${shop}";\n`);
        writeIn(prefixed, file, `\n${head}\nconst shop = "${shop}";\n`);
      });
      expect(scanWithArgv(name, raw), `${name} raw`).toEqual([]); // every one skipped: why the prefix is needed
      const want = BINARY_HEADS.map((_, i) => `f${String(i + 1).padStart(6, '0')}.txt:3`).sort(); // line 3 = content line 2
      expect(scanWithArgv(name, prefixed), `${name} prefixed`).toEqual(want);
    }
  });

  it('live: magic words at a fixed later byte (tar 257, DICOM 128, ISO 9660 32769) are skipped even after the leading newline (why redact.ts leaves such files out)', () => {
    const shop = shopifyValue();
    const at = (offset: number, magic: string) => {
      const fill = ('x'.repeat(99) + '\n').repeat(Math.floor((offset - 1) / 100));
      return '\n' + fill + 'x'.repeat(offset - 1 - fill.length) + magic + `\nconst shop = "${shop}";\n`;
    };
    for (const name of ['betterleaks', 'gitleaks'] as const) {
      const dir = makeTempDir();
      writeIn(dir, 'f000001.txt', at(257, 'ustar'));
      writeIn(dir, 'f000002.txt', at(128, 'DICM'));
      writeIn(dir, 'f000003.txt', at(32769, 'CD001'));
      writeIn(dir, 'f000004.txt', at(258, 'ustar')); // one byte off: found
      expect(scanWithArgv(name, dir).map((f) => f.split(':')[0]), name).toEqual(['f000004.txt']);
    }
  });

  it('live: end to end, a token after any of the 11 heads, or in a file name shown first as MZ…, never reaches the bundle text (betterleaks and gitleaks)', async () => {
    const shop = shopifyValue();
    const lab = gitlabValue();
    const repo = makeTempDir();
    BINARY_HEADS.forEach((head, i) => writeIn(repo, `assets/h${String(i).padStart(2, '0')}.txt`, `${head}\nconst shop = "${shop}";\n`));
    writeIn(repo, 'assets/logo.eps', `%!PS-Adobe-3.0 EPSF-3.0\n% key ${shop}\n`);
    writeIn(repo, 'data/MZ_regions.csv', `MZ,Mozambique\nshop,${shop}\n`);
    const names = makeTempDir(); // paths.txt: its first line is this file's name, which starts with MZ
    writeIn(names, `MZ-${lab}.csv`, 'a,b\n');
    for (const name of ['betterleaks', 'gitleaks'] as const) {
      const scanner = { name, path: bins[name] as string, version: loadPinnedBinaries()[name].version };
      const text = bundleText(await bundleCode(repo, scanWith(scanner)));
      expect(text, name).not.toContain(shop);
      const n = await bundleCode(names, scanWith(scanner));
      expect(n.files, name).toEqual([]); // the file whose name holds the token is left out
      expect(n.notes.join('\n'), name).toMatch(/flagged as secret-like/);
    }
  });
});
