// Ruling P34 (final review I2), live on both pinned scanners: a scanner that skips a file must never let it reach the
// AI unscanned. The known cause: the default config's global path allowlist (inherited via `[extend] useDefault`)
// matches the ABSOLUTE scan path, so with TMPDIR under node_modules/ both scanners exit 0 with an empty report. pipegen
// refuses such a temp folder (the belt), and every scanned file carries a canary that must come back (the guarantee).
// The second test switches the belt off (a mock of skippedByDefaultPaths) so the canary alone is checked live.
// Network: downloads the pinned releases into ~/.cache/pipegen/tools once. Skipped unless PIPEGEN_LIVE_TESTS=1.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { bundleCode, bundleText, SecretScanError, secretScanArgv, secretScanConfigPath } from '../src/ai/redact.js';
import { DEFAULT_SKIPPED_PATHS, type SecretScannerName } from '../src/ai/secret-scan-config.js';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { betterleaksAt, gitleaksAt, scanWith } from './helpers/gitleaks-stub.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const belt = vi.hoisted(() => ({ on: true }));
vi.mock('../src/ai/secret-scan-config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ai/secret-scan-config.js')>();
  return { ...real, skippedByDefaultPaths: (p: string) => belt.on && real.skippedByDefaultPaths(p) };
});

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
// built at runtime (repo rule: no secret-like literals in test/); pipegen's own redact() does not catch it
const shopifyValue = () => 'shp' + 'at_' + '0123456789abcdef'.repeat(2);
const NAMES = ['betterleaks', 'gitleaks'] as const;

describe.skipIf(!live)('secret scan (live, both pinned scanners): a scan path the default allowlist skips (ruling P34)', () => {
  const bins: Partial<Record<SecretScannerName, string>> = {};
  beforeAll(async () => {
    bins.betterleaks = await ensurePinnedBinary('betterleaks');
    bins.gitleaks = await ensurePinnedBinary('gitleaks');
  }, 600_000);
  afterEach(() => {
    belt.on = true;
    cleanupRepos();
  });

  const scannerFor = (name: SecretScannerName) => (name === 'betterleaks' ? betterleaksAt : gitleaksAt)(bins[name] as string);

  /** bundleCode on a repo holding the token, with TMPDIR under `<tmp>/node_modules/.cache/tmp`. */
  async function underNodeModules(name: SecretScannerName): Promise<{ text: string | null; error: unknown }> {
    const repo = makeTempDir();
    writeIn(repo, 'src/a.ts', `export const k = "${shopifyValue()}";\n`);
    const tmp = join(makeTempDir(), 'node_modules', '.cache', 'tmp');
    mkdirSync(tmp, { recursive: true });
    const old = process.env.TMPDIR;
    process.env.TMPDIR = tmp;
    try {
      return { text: bundleText(await bundleCode(repo, scanWith(scannerFor(name)))), error: null };
    } catch (e) {
      return { text: null, error: e };
    } finally {
      if (old === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = old;
    }
  }

  it('live: the cause: a folder under node_modules/ is scanned as clean (exit 0, no findings) by both scanners', () => {
    for (const name of NAMES) {
      const dir = join(makeTempDir(), 'node_modules', 't', 'scan');
      mkdirSync(dir, { recursive: true });
      writeIn(dir, 'f000001.txt', `\nexport const k = "${shopifyValue()}";\n\npipegen-canary-${'0'.repeat(32)}\n`);
      const reportPath = join(dir, 'report.json');
      let code = 0;
      try {
        execFileSync(bins[name] as string, secretScanArgv(name, dir, secretScanConfigPath(), reportPath), { cwd: dir, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, stdio: 'pipe' });
      } catch (e) {
        code = (e as { status: number }).status;
      }
      const report = existsSync(reportPath) ? (JSON.parse(readFileSync(reportPath, 'utf8')) as unknown[]) : null;
      console.log(`P34 ${name}: raw scan under node_modules: exit ${code}, ${report === null ? 'no report' : `${report.length} findings`}`);
      expect(code, name).toBe(0);
      expect(report, name).toEqual([]); // not even the canary: the file was never read
    }
  });

  it('live: TMPDIR under node_modules/: bundleCode throws SecretScanError (the belt), and with the belt off the canary alone fails closed', async () => {
    for (const on of [true, false]) {
      belt.on = on;
      for (const name of NAMES) {
        const { text, error } = await underNodeModules(name);
        console.log(`P34 ${name}, belt ${on ? 'on' : 'off'}: ${error === null ? 'bundle returned' : `${(error as Error).constructor.name}: ${(error as Error).message}`}`);
        // the secret never reaches a bundle, whichever way it is stopped
        if (text !== null) expect(text, name).not.toContain(shopifyValue());
        expect(error, `${name} belt ${on}`).toBeInstanceOf(SecretScanError);
        expect((error as Error).message, `${name} belt ${on}`).toMatch(on ? /TMPDIR/ : /did not confirm it read/);
      }
    }
  });

  it('live: a normal temp folder: both scanners report every canary, and a real finding is redacted on its line', async () => {
    const repo = makeTempDir();
    writeIn(repo, 'src/a.ts', `const a = 1;\nexport const k = "${shopifyValue()}";`); // no final newline
    writeIn(repo, 'src/b.ts', 'export const b = 2;\n');
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name)));
      expect(b.files.map((f) => f.path).sort(), name).toEqual(['src/a.ts', 'src/b.ts']);
      expect(b.files.find((f) => f.path === 'src/a.ts')?.content, name).toBe('const a = 1;\nexport const k = "[REDACTED]";');
      expect(bundleText(b), name).not.toContain('pipegen-canary');
      expect(b.notes.join('\n'), name).toContain(`${name} checked the bundle: 1 finding redacted.`);
    }
  });

  it('live (P35/P37): canary-shaped text next to a real token never lets the canary rule hide it (betterleaks and gitleaks)', async () => {
    const shop = shopifyValue();
    const hex = shop.slice('shp'.length + 'at_'.length); // the token's own 32 hex digits
    const canaryLike = `pipegen-canary-${hex}`;
    const repo = makeTempDir();
    writeIn(repo, 'src/glued.ts', `export const a = "${canaryLike}${shop}";\n`);
    writeIn(repo, 'src/own-line.ts', `${canaryLike}\n${shop}\n`); // a whole canary-shaped line: its file is left out
    writeIn(repo, 'src/same-line.ts', `export const k = "${shop}"; // ${canaryLike}\n`);
    writeIn(repo, 'src/last-line.ts', `export const k = "${shop}";\n${canaryLike}`); // ditto
    writeIn(repo, `${canaryLike}.ts`, `export const k = "${shop}";\n`);
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name)));
      console.log(`P35 ${name}: ${b.files.map((f) => f.path)} sent; notes: ${JSON.stringify(b.notes.filter((n) => /checked|Left out/.test(n)))}`);
      expect(bundleText(b), name).not.toContain(shop);
      // the foreign marker's value counts as a found secret (P35), so the file whose NAME holds it is left out too
      expect(b.files.map((f) => f.path).sort(), name).toEqual(['src/glued.ts', 'src/same-line.ts']);
      expect(b.notes.join('\n'), name).toContain(`Left out because ${name} reported a check marker in them that pipegen did not write there: src/last-line.ts, src/own-line.ts.`);
    }
  });

  it('live (P37): `pipegen-canary-` glued before a word-boundary token (SendGrid), in content and in a file name, never hides it', async () => {
    const AN = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const an = (n: number) => [...randomBytes(n)].map((x) => AN[x % AN.length]).join('');
    const sendgrid = 'SG' + '.' + an(22) + '.' + an(43);
    const repo = makeTempDir();
    writeIn(repo, 'src/content.ts', `export const v = "pipegen-canary-${sendgrid}";\n`);
    writeIn(repo, `src/pipegen-canary-${sendgrid}`, 'export const a = 1;\n'); // no extension: the token ends the line
    writeIn(repo, 'src/b.ts', 'export const b = 2;\n');
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name)));
      console.log(`P37 ${name}: ${b.files.map((f) => f.path)} sent; notes: ${JSON.stringify(b.notes.filter((n) => /checked|Left out/.test(n)))}`);
      expect(bundleText(b), name).not.toContain(sendgrid);
      expect(b.files.map((f) => f.path).sort(), name).toEqual(['src/b.ts', 'src/content.ts']);
      expect(b.files.find((f) => f.path === 'src/content.ts')?.content, name).toBe('export const v = "pipegen-canary-[REDACTED]";\n');
    }
  });

  it("live (P36): a token across the scanners' 125,000-byte cut (the review's repro) never reaches the bundle; the file is left out as too large", async () => {
    const shop = shopifyValue();
    const head = 'const k = "';
    const start = 124_980; // content offset of the token (written offset +1, pipegen's prefix line)
    let pre = '';
    while (start - head.length - pre.length > 200) pre += `// filler ${'a'.repeat(68)}\n`;
    pre += `// ${'b'.repeat(start - head.length - pre.length - 4)}\n`;
    let content = `${pre}${head}${shop}";\n`;
    while (content.length < 140_000) content += `// tail ${'c'.repeat(70)}\n`;
    expect(content.indexOf(shop)).toBe(start);
    // the cause, raw: written the way pipegen wrote it before P36, both scanners miss the token yet report the canary
    for (const name of NAMES) {
      const dir = makeTempDir();
      writeIn(dir, 'f000001.txt', `\n${content}\npipegen-canary-${'0'.repeat(32)}\n`);
      const reportPath = join(dir, 'report.json');
      try {
        execFileSync(bins[name] as string, secretScanArgv(name, dir, secretScanConfigPath(), reportPath), { cwd: dir, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, stdio: 'pipe' });
      } catch (e) {
        if (typeof (e as { status?: unknown }).status !== 'number') throw e;
      }
      const rules = (JSON.parse(readFileSync(reportPath, 'utf8')) as { RuleID: string }[]).map((f) => f.RuleID);
      console.log(`P36 ${name}: raw scan of the 140 KB file reports ${JSON.stringify(rules)}`);
      expect(rules, name).toEqual(['pipegen-canary']);
    }
    // the fix, end to end
    const repo = makeTempDir();
    writeIn(repo, 'src/big.js', content);
    writeIn(repo, 'src/b.ts', 'export const b = 2;\n');
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name), { maxBytes: 1_000_000 }));
      console.log(`P36 ${name}: ${b.files.map((f) => f.path)} sent; notes: ${JSON.stringify(b.notes.filter((n) => /checked|Left out/.test(n)))}`);
      expect(bundleText(b), name).not.toContain(shop);
      expect(b.files.map((f) => f.path), name).toEqual(['src/b.ts']);
      expect(b.notes.join('\n'), name).toContain('too large to secret-scan safely');
    }
  });

  it("live (belt drift): the belt mirrors every folder-level pattern of each pinned scanner's default path allowlist", () => {
    // A pattern a scanner bump adds (or drops) fails here, so the belt and FILE_ONLY are reviewed with the bump.
    // FILE_ONLY: anchored to the end of a file name, so they never match f000001.txt / paths*.txt (checked below).
    const FILE_ONLY = [
      String.raw`(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$`, String.raw`(?i)\.(?:eot|[ot]tf|woff2?)$`, String.raw`go\.(?:mod|sum|work(?:\.sum)?)$`,
      String.raw`(?:^|/)vendor/modules\.txt$`, String.raw`(?:^|/)gradlew(?:\.bat)?$`, String.raw`(?:^|/)gradle\.lockfile$`, String.raw`(?:^|/)mvnw(?:\.cmd)?$`,
      String.raw`(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`,
      String.raw`(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$`,
      String.raw`(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$`,
      String.raw`(?:^|/)javascript\.json$`, String.raw`(?:^|/)(?:Pipfile|poetry)\.lock$`, String.raw`\.gem$`, String.raw`(?:^|/)\.git$`,
    ];
    // the office/binary extension list differs between the two scanners (`.dll` vs `dll`): matched by its head
    const isExtensionList = (p: string) => p.startsWith(String.raw`(?i)\.(?:docx?|xlsx?|pdf|bin|socket|`);
    const belt = new Set(DEFAULT_SKIPPED_PATHS.map((re) => (re.flags.includes('i') ? '(?i)' : '') + re.source.replaceAll('\\/', '/')));
    for (const name of NAMES) {
      const text = readFileSync(bins[name] as string).toString('latin1');
      const marker = name === 'gitleaks' ? 'description = "global allow lists"\npaths = [\n' : "prefilter = '''\nmatchesAny(attributes[\"path\"], [\n";
      const at = text.indexOf(marker);
      expect(at, name).toBeGreaterThan(0);
      const quoted = name === 'gitleaks' ? /^\s*'''(.*)''',?$/ : /^\s*`(.*)`,?$/;
      const patterns: string[] = [];
      for (const line of text.slice(at + marker.length).split('\n')) {
        const m = quoted.exec(line);
        if (m === null) break;
        patterns.push(m[1]);
      }
      console.log(`belt drift ${name}: ${patterns.length} default path patterns`);
      expect(patterns.length, name).toBeGreaterThan(20);
      for (const p of patterns) {
        expect(belt.has(p) || FILE_ONLY.includes(p) || isExtensionList(p), `${name}: a default path pattern the belt neither mirrors nor knows as file-only: ${p}`).toBe(true);
      }
      for (const b of belt) expect(patterns, `${name}: a belt pattern no longer in the defaults: ${b}`).toContain(b);
      // the file-only ones really can't match pipegen's neutral names
      for (const p of [...FILE_ONLY, ...patterns.filter(isExtensionList)]) {
        const re = new RegExp(p.replace('(?i)', ''), p.startsWith('(?i)') ? 'i' : '');
        for (const n of ['/t/f000001.txt', '/t/paths.txt', '/t/paths2.txt']) expect(re.test(n), `${p} ${n}`).toBe(false);
      }
    }
  });
});
