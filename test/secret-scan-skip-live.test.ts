// Ruling P34 (final review I2), live on both pinned scanners: a scanner that skips a file must never let it reach the
// AI unscanned. The known cause: the default config's global path allowlist (inherited via `[extend] useDefault`)
// matches the ABSOLUTE scan path, so with TMPDIR under node_modules/ both scanners exit 0 with an empty report. pipegen
// refuses such a temp folder (the belt), and every scanned file carries a canary that must come back (the guarantee).
// The second test switches the belt off (a mock of skippedByDefaultPaths) so the canary alone is checked live.
// Network: downloads the pinned releases into ~/.cache/pipegen/tools once. Skipped unless PIPEGEN_LIVE_TESTS=1.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { bundleCode, bundleText, SecretScanError, secretScanArgv, secretScanConfigPath } from '../src/ai/redact.js';
import type { SecretScannerName } from '../src/ai/secret-scan-config.js';
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

  it('live (P35): canary-shaped text next to a real token never lets the canary rule hide it (betterleaks and gitleaks)', async () => {
    const shop = shopifyValue();
    const hex = shop.slice('shp'.length + 'at_'.length); // the token's own 32 hex digits
    const canaryLike = `pipegen-canary-${hex}`;
    const repo = makeTempDir();
    writeIn(repo, 'src/glued.ts', `export const a = "${canaryLike}${shop}";\n`);
    writeIn(repo, 'src/own-line.ts', `${canaryLike}\n${shop}\n`);
    writeIn(repo, 'src/same-line.ts', `export const k = "${shop}"; // ${canaryLike}\n`);
    writeIn(repo, 'src/last-line.ts', `export const k = "${shop}";\n${canaryLike}`);
    writeIn(repo, `${canaryLike}.ts`, `export const k = "${shop}";\n`);
    for (const name of NAMES) {
      const b = await bundleCode(repo, scanWith(scannerFor(name)));
      const text = bundleText(b);
      console.log(`P35 ${name}: ${b.files.length} files sent; notes: ${JSON.stringify(b.notes.filter((n) => /checked|Left out/.test(n)))}`);
      expect(text, name).not.toContain(shop);
      // neutralised in the content, and pipegen's own canary never sent (the file name in a header is the repo's own)
      for (const f of b.files) expect(f.content, `${name} ${f.path}`).not.toContain('pipegen-canary-');
      expect(b.notes.join('\n'), name).toContain(`${name} checked the bundle: 5 findings redacted.`);
      expect(b.files.length, name).toBeGreaterThan(0); // the scan still ran and confirmed the files
    }
  });
});
