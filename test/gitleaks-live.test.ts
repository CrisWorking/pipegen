// Live integration test against the REAL pinned gitleaks (ruling S28, the Plan A carry-forward): Plan A Task 5's
// gitleaks pass was built against a stub, so this checks its assumptions against the real binary. Network: it
// downloads the pinned release from github.com into ~/.cache/pipegen/tools (once; later runs re-verify the cache).
// Skipped unless PIPEGEN_LIVE_TESTS=1, so `npm test` stays offline; ci.yml runs it in its own step.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, isAbsolute, join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { bundleCode, bundleText, redact, secretScanConfigPath } from '../src/ai/redact.js';
import { ensurePinnedBinary, loadPinnedBinaries } from '../src/engine/linters.js';
import { gitleaksAt, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';

// Secret-like values, built at runtime (repo rule: no secret-like literals in test/). Each one gets past pipegen's
// own redact() patterns, so only the gitleaks pass can catch it.
const shopifyValue = () => 'shp' + 'at_' + '0123456789abcdef'.repeat(2);
const gitlabValue = () => 'glp' + 'at-' + 'Ab12Cd34Ef56Gh78Ij90';
// A database URL with a login in it: caught by pipegen's own connection-string rule (data/gitleaks-bundle.toml).
const connString = () => 'postgres' + '://' + 'app' + ':' + 'Zq9' + 'wX7vB5nM3' + '@' + 'db.internal:5432/app';

interface Finding { File: string; StartLine: number; EndLine: number; RuleID: string; Secret?: string; Match?: string }
interface Scan { code: number; report: Finding[] | null }

let bin = '';

/** Runs the real gitleaks the way src/ai/redact.ts does; returns the exit code and the report (null when none was written). */
function scan(args: string[], dir: string): Scan {
  const reportPath = join(makeTempDir(), 'report.json');
  let code = 0;
  try {
    execFileSync(bin, [...args, '--report-format', 'json', '--report-path', reportPath], { cwd: dir, stdio: 'pipe', timeout: 120_000 });
  } catch (e) {
    const status = (e as { status?: number | null }).status;
    if (typeof status !== 'number') throw e;
    code = status;
  }
  return { code, report: existsSync(reportPath) ? (JSON.parse(readFileSync(reportPath, 'utf8')) as Finding[]) : null };
}

const detect = (dir: string, config = secretScanConfigPath()) => scan(['detect', '--no-git', '--source', dir, '--config', config], dir);
const key = (f: Finding) => `${basename(f.File)}:${f.StartLine}:${f.RuleID}`;

describe.skipIf(!live)('gitleaks (live, real pinned binary)', () => {
  beforeAll(async () => {
    bin = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterEach(cleanupRepos);

  it('live: ensurePinnedBinary gives the verified pinned gitleaks; a second call re-checks the cached copy', async () => {
    const version = execFileSync(bin, ['version'], { encoding: 'utf8' }).trim();
    console.log(`pinned gitleaks: ${bin} (version ${version})`);
    expect(version).toBe(loadPinnedBinaries().gitleaks.version);
    expect(statSync(bin).mode & 0o777).toBe(0o700);
    expect(await ensurePinnedBinary('gitleaks')).toBe(bin);
  });

  it('live: data/gitleaks-bundle.toml compiles under RE2 with [extend] useDefault; a clean folder exits 0 with an empty report', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', 'export const greeting = "hello";\n');
    expect(detect(dir)).toEqual({ code: 0, report: [] });
  });

  it('live: default rules and pipegen rules both fire; exit 1 with findings', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `const shop = "${shopifyValue()}";\n`);
    writeIn(dir, 'f000002.txt', `DATABASE_URL=${connString()}\n`);
    const { code, report } = detect(dir);
    expect(code).toBe(1);
    expect(report?.map((f) => f.RuleID).sort()).toEqual(['pipegen-connection-string-password', 'shopify-access-token']);
  });

  it('live: report shape: File absolute under --source, 1-based StartLine/EndLine, Secret and Match present', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `line one\nconst lab = "${gitlabValue()}";\n`);
    const { report } = detect(dir);
    expect(report).toHaveLength(1);
    const f = report?.[0] as Finding;
    expect(isAbsolute(f.File)).toBe(true);
    expect(f.File).toBe(join(dir, 'f000001.txt'));
    expect([f.StartLine, f.EndLine]).toEqual([2, 2]);
    expect(f.Secret).toBe(gitlabValue());
    expect(f.Match).toContain(gitlabValue());
  });

  it('live: detect --no-git still works and finds exactly what `dir` finds (no switch needed)', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `a\nconst shop = "${shopifyValue()}";\n`);
    writeIn(dir, 'f000002.txt', `const lab = "${gitlabValue()}";\n`);
    const viaDetect = detect(dir);
    const viaDir = scan(['dir', dir, '--config', secretScanConfigPath()], dir);
    expect(viaDetect.code).toBe(1);
    expect(viaDir.code).toBe(1);
    expect(viaDetect.report?.map(key).sort()).toEqual(viaDir.report?.map(key).sort());
    expect(viaDetect.report).toHaveLength(2);
  });

  it('live: a config error exits non-zero and writes no report (redact.ts turns that into SecretScanError)', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', 'hello\n');
    const cfg = makeTempDir();
    writeIn(cfg, 'bad.toml', 'this is [[[ not toml\n');
    writeIn(cfg, 'bad-regex.toml', "title = \"bad\"\n[[rules]]\nid = \"x\"\nregex = '''(?<=a)b'''\n"); // look-behind: not RE2
    for (const name of ['bad.toml', 'bad-regex.toml']) {
      const { code, report } = detect(dir, join(cfg, name));
      expect(code, name).not.toBe(0);
      // redact.ts: exit code other than 0/1 → SecretScanError; exit 1 without a report → SecretScanError('wrote no report')
      expect(report, name).toBeNull();
    }
  });

  it('live: the neutral names f000001.txt and paths.txt are not allow-listed by the default config', () => {
    const dir = makeTempDir();
    writeIn(dir, 'f000001.txt', `const shop = "${shopifyValue()}";\n`);
    writeIn(dir, 'paths.txt', `src/app.ts\nconfig/${gitlabValue()}.txt\n`);
    const { report } = detect(dir);
    expect(report?.map(key).sort()).toEqual(['f000001.txt:1:shopify-access-token', 'paths.txt:2:gitlab-pat']);
  });

  it('live: end to end, a secret that gets past redact() is caught by the gitleaks pass and scrubbed from the whole bundle', async () => {
    const shop = shopifyValue();
    const lab = gitlabValue();
    const line = `export const shop = '${shop}';`;
    expect(redact(line)).toBe(line); // pipegen's own patterns miss it: only gitleaks can catch it
    const repo = makeTempDir();
    writeIn(repo, 'src/config.ts', `${line}\nexport const lab = '${lab}';\n`);
    writeIn(repo, 'docs/notes.md', `# Notes\nThe shop value is ${shop} (copied here by mistake).\n`);
    writeIn(repo, 'src/app.ts', "import { shop } from './config';\nconsole.log(typeof shop);\n");
    const bundle = await bundleCode(repo, scanWith(gitleaksAt(bin, loadPinnedBinaries().gitleaks.version)));
    expect(bundle.secretScanChecked).toBe(true);
    const text = bundleText(bundle);
    expect(text).not.toContain(shop);
    expect(text).not.toContain(lab);
    expect(text).toContain('src/app.ts'); // the clean file is still there
    expect(bundle.notes.join('\n')).toMatch(/gitleaks checked the bundle: [1-9]\d* finding/);
  });
});
