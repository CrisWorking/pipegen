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
import { bundleCode, bundleText, SCAN_CHUNK_SAFE_BYTES, SecretScanError, secretScanArgv, secretScanConfigPath } from '../src/ai/redact.js';
import { DEFAULT_SKIPPED_PATHS, type SecretScannerName } from '../src/ai/secret-scan-config.js';
import { ensurePinnedBinary } from '../src/engine/linters.js';
import { betterleaksAt, gitleaksAt, scanWith } from './helpers/gitleaks-stub.js';
import { counted } from './helpers/counted.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

const belt = vi.hoisted(() => ({ on: true }));
vi.mock('../src/ai/secret-scan-config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/ai/secret-scan-config.js')>();
  return { ...real, skippedByDefaultPaths: (p: string) => belt.on && real.skippedByDefaultPaths(p) };
});

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
// built at runtime (repo rule: no secret-like literals in test/); pipegen's own redact() does not catch it
const shopifyValue = () => 'shp' + 'at_' + '0123456789abcdef'.repeat(2);
const shopifyRandom = () => 'shp' + 'at_' + randomBytes(16).toString('hex');
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

  it('live: TMPDIR under node_modules/: bundleCode throws SecretScanError (the belt), and with the belt off the canary alone fails closed', counted(async () => {
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
  }));

  it('live: a normal temp folder: both scanners report every canary, and a real finding is redacted on its line', counted(async () => {
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
  }));

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
    // The cause, raw, as documentation: written the way pipegen wrote it before P36, both scanners miss the token yet
    // report the canary. Only a record of the 1.9.0 / 8.30.1 behaviour: what keeps pipegen safe is the P38 pin test below.
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
      expect(rules, `${name}: the documented 125,000-byte cut is no longer seen (the scanner's chunking changed; the P38 pin test says whether SCAN_CHUNK_SAFE_BYTES is still safe, and this record should be updated)`).toEqual(['pipegen-canary']);
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

  it("live (belt drift): the belt mirrors every folder-level pattern of each pinned scanner's default path allowlist", counted(() => {
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
  }));

  it(`live (P38 pin): a file of exactly SCAN_CHUNK_SAFE_BYTES as written is read whole: every token and each canary is reported`, counted(() => {
    // Two files laid out as pipegen writes them (prefix line, content, blank line, canary line), each exactly
    // SCAN_CHUNK_SAFE_BYTES bytes: unique Shopify tokens back to back on ONE line, no blank line anywhere, the second
    // file shifted by 19 bytes, so any cut inside the files splits a token in at least one of them. Fails if a scanner
    // version reads such a file in more than one piece (smaller chunks, an earlier cut): then the limit must come down.
    for (const name of NAMES) {
      const dir = makeTempDir();
      const planted: string[] = [];
      const canaries: string[] = [];
      for (const [file, shift] of [['f000001.txt', 0], ['f000002.txt', 19]] as const) {
        const canary = `pipegen-canary-${randomBytes(16).toString('hex')}`;
        const tail = 1 + 1 + canary.length + 1; // the newline after the content, the blank line, the canary line
        let body = 'x'.repeat(shift);
        for (;;) {
          const value = shopifyRandom();
          if (1 + body.length + value.length + 1 + tail > SCAN_CHUNK_SAFE_BYTES) break;
          planted.push(value);
          body += `${value} `;
        }
        body += 'y'.repeat(SCAN_CHUNK_SAFE_BYTES - tail - 1 - body.length);
        const written = `\n${body}\n\n${canary}\n`;
        expect(Buffer.byteLength(written)).toBe(SCAN_CHUNK_SAFE_BYTES);
        writeIn(dir, file, written);
        canaries.push(canary);
      }
      const reportPath = join(makeTempDir(), 'report.json');
      try {
        execFileSync(bins[name] as string, secretScanArgv(name, dir, secretScanConfigPath(), reportPath), { cwd: dir, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }, stdio: 'pipe', timeout: 300_000 });
      } catch (e) {
        if (typeof (e as { status?: unknown }).status !== 'number') throw e;
      }
      const report = JSON.parse(readFileSync(reportPath, 'utf8')) as Record<string, string>[];
      const valueOf = (f: Record<string, string>) => f['Sec' + 'ret'];
      const found = new Set(report.map(valueOf));
      const missed = planted.filter((t) => !found.has(t));
      console.log(`P38 ${name}: ${planted.length} tokens in two ${SCAN_CHUNK_SAFE_BYTES}-byte files; missed ${missed.length}`);
      expect(missed.length, `${name} split a ${SCAN_CHUNK_SAFE_BYTES}-byte file (missed ${missed.length} tokens): SCAN_CHUNK_SAFE_BYTES is no longer safe for this scanner`).toBe(0);
      for (const c of canaries) expect(report.filter((f) => f.RuleID === 'pipegen-canary' && valueOf(f) === c), `${name} canary`).toHaveLength(1);
    }
  }), 600_000);

  it('live (P39): a too-large file whose name holds a SendGrid-shaped value is scanned by name, masked in the note, never in the bundle', async () => {
    const AN = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const an = (n: number) => [...randomBytes(n)].map((x) => AN[x % AN.length]).join('');
    const sendgrid = 'SG' + '.' + an(22) + '.' + an(43);
    const repo = makeTempDir();
    writeIn(repo, `src/big-${sendgrid}`, `// ${'x'.repeat(77)}\n`.repeat(1_200)); // 96,000 bytes: over the limit
    writeIn(repo, 'src/b.ts', 'export const b = 2;\n');
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name), { maxBytes: 1_000_000 }));
      const notes = b.notes.join('\n');
      console.log(`P39 ${name}: ${b.files.map((f) => f.path)} sent; notes: ${JSON.stringify(b.notes.filter((n) => /checked|Left out/.test(n)))}`);
      expect(notes, name).not.toContain(sendgrid);
      expect(bundleText(b), name).not.toContain(sendgrid);
      expect(notes, name).toContain('too large to secret-scan safely');
      expect(notes, name).toContain('(a file whose name looks like a secret)');
      expect(b.files.map((f) => f.path), name).toEqual(['src/b.ts']);
    }
  });

  it('live (P45): a base64-encoded token as an excluded file name is scanned by name; the encoded text is a found value the report masks', async () => {
    const shop = shopifyRandom();
    const encoded = Buffer.from(['tok' + 'en', shop].join('=')).toString('base64url').replace(/=+$/, '');
    const repo = makeTempDir();
    writeIn(repo, 'src/a.ts', 'export const a = 1;\n');
    writeIn(repo, `config/${encoded}.env`, 'X=1\n'); // excluded from the bundle (.env): only its name is scanned
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name)));
      console.log(`P45 ${name}: names ${JSON.stringify(b.found.names.map((n) => n.replace(encoded, "<enc>")))}, values ${b.found.values.length}`);
      expect(b.found.names, name).toContain(`config/${encoded}.env`);
      expect(b.found.values.some((v) => encoded.includes(v) && v.length >= 16), `${name}: the encoded text is a found value`).toBe(true);
      expect(b.found.values, name).toContain(shop);
      expect(b.notes.join('\n'), name).not.toContain(encoded);
      expect(b.files.map((f) => f.path), `${name}: the other file is still sent`).toEqual(['src/a.ts']);
    }
  });
});
