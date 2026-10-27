import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, symlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ALLOWED_LICENSES, bundledPackageDirs, buildNotices, licenseIds, MAX_FILE_BYTES } from '../scripts/notices.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const root = resolve(import.meta.dirname, '..');

/** A fixture node_modules package: package.json plus the given files. */
function pkg(dir: string, rel: string, name: string, version: string, license: string | undefined, files: Record<string, string> = {}): void {
  const json: Record<string, unknown> = { name, version };
  if (license !== undefined) json.license = license;
  writeIn(dir, `${rel}/package.json`, JSON.stringify(json));
  for (const [f, text] of Object.entries(files)) writeIn(dir, `${rel}/${f}`, text);
}
const meta = (...inputs: string[]) => ({ inputs: Object.fromEntries(inputs.map((i) => [i, { bytes: 1, imports: [] }])) });

describe('bundledPackageDirs', () => {
  it('finds plain, scoped and nested packages, ignores src files, and lists each folder once in sorted order', () => {
    const dirs = bundledPackageDirs(meta(
      'src/cli/main.ts',
      'node_modules/zod/v4/index.js',
      'node_modules/zod/v4/other.js',
      'node_modules/@scope/pkg/dist/a.js',
      'node_modules/micromatch/node_modules/picomatch/lib/x.js',
      'node_modules/picomatch/lib/y.js',
      'node_modules/micromatch/index.js',
    ));
    expect(dirs).toEqual([
      'node_modules/@scope/pkg',
      'node_modules/micromatch',
      'node_modules/micromatch/node_modules/picomatch',
      'node_modules/picomatch',
      'node_modules/zod',
    ]);
  });
  it('rejects a metafile without inputs and an odd folder name', () => {
    expect(() => bundledPackageDirs({} as never)).toThrow(/no `inputs`/);
    expect(() => bundledPackageDirs(meta('node_modules/Bad Name/x.js'))).toThrow(/unexpected package folder name/);
  });
});

describe('licenseIds', () => {
  it('splits SPDX expressions', () => {
    expect(licenseIds('MIT')).toEqual(['MIT']);
    expect(licenseIds('(MIT OR Apache-2.0)')).toEqual(['MIT', 'Apache-2.0']);
  });
  it('the allowlist is the ruled one plus Unlicense', () => {
    expect([...ALLOWED_LICENSES]).toEqual(['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', '0BSD', 'BlueOak-1.0.0', 'CC0-1.0', 'Python-2.0', 'Unlicense']);
  });
});

describe('buildNotices', () => {
  function fixture(): string {
    const dir = makeTempDir();
    pkg(dir, 'node_modules/zod', 'zod', '4.0.0', 'MIT', { LICENSE: 'MIT zod text\r\n\r\n' });
    pkg(dir, 'node_modules/@scope/pkg', '@scope/pkg', '1.2.3', 'Apache-2.0', { LICENSE: 'Apache text', NOTICE: 'Notice line 1\nline 2\n', 'README.md': 'not a licence' });
    pkg(dir, 'node_modules/micromatch', 'micromatch', '4.0.8', 'MIT', { LICENSE: 'mm text' });
    pkg(dir, 'node_modules/micromatch/node_modules/picomatch', 'picomatch', '2.3.2', 'MIT', { LICENSE: 'pm2 text' });
    pkg(dir, 'node_modules/picomatch', 'picomatch', '4.0.7', 'MIT', { LICENSE: 'pm4 text' });
    return dir;
  }
  const inputs = ['node_modules/zod/a.js', 'node_modules/picomatch/a.js', 'node_modules/micromatch/node_modules/picomatch/a.js', 'node_modules/micromatch/a.js', 'node_modules/@scope/pkg/a.js'];

  it('writes name@version, licence id, then the text, with scoped packages, both picomatch copies and NOTICE verbatim', () => {
    const { text, count } = buildNotices(fixture(), meta(...inputs));
    expect(count).toBe(5);
    const order = [...text.matchAll(/^={80}\n(.+)\nLicense: (.+)$/gm)].map((m) => `${m[1]} ${m[2]}`);
    expect(order).toEqual(['@scope/pkg@1.2.3 Apache-2.0', 'micromatch@4.0.8 MIT', 'picomatch@2.3.2 MIT', 'picomatch@4.0.7 MIT', 'zod@4.0.0 MIT']);
    expect(text).toContain('pm2 text');
    expect(text).toContain('pm4 text');
    expect(text).toContain('File: LICENSE\n\nApache text\n\nFile: NOTICE\n\nNotice line 1\nline 2\n');
    expect(text).not.toContain('not a licence');
    expect(text).toContain('File: LICENSE\n\nMIT zod text\n'); // CRLF and trailing blank lines normalised
    expect(text).not.toContain('\r');
  });

  it('is stable: the input order of the metafile does not change the output', () => {
    const dir = fixture();
    const a = buildNotices(dir, meta(...inputs)).text;
    const b = buildNotices(dir, meta(...[...inputs].reverse())).text;
    expect(a).toBe(b);
    expect(buildNotices(dir, meta(...inputs)).text).toBe(a);
  });

  it('fails when a package has no licence field', () => {
    const dir = makeTempDir();
    pkg(dir, 'node_modules/nolic', 'nolic', '1.0.0', undefined, { LICENSE: 'text' });
    expect(() => buildNotices(dir, meta('node_modules/nolic/a.js'))).toThrow(/nolic@1\.0\.0: no `license`/);
  });

  it('fails on a licence outside the allowlist, including one half of an OR expression', () => {
    const dir = makeTempDir();
    pkg(dir, 'node_modules/gpl', 'gpl', '1.0.0', 'GPL-3.0-only', { LICENSE: 'text' });
    expect(() => buildNotices(dir, meta('node_modules/gpl/a.js'))).toThrow(/gpl@1\.0\.0: licence "GPL-3\.0-only" is not in the allowlist/);
    pkg(dir, 'node_modules/dual', 'dual', '1.0.0', '(MIT OR GPL-3.0-only)', { LICENSE: 'text' });
    expect(() => buildNotices(dir, meta('node_modules/dual/a.js'))).toThrow(/not in the allowlist/);
  });

  it('fails when there is no licence text, unless a reviewed override matches that exact name@version', () => {
    const dir = makeTempDir();
    pkg(dir, 'node_modules/bare', 'bare', '1.0.0', 'MIT');
    const m = meta('node_modules/bare/a.js');
    expect(() => buildNotices(dir, m)).toThrow(/no licence text found/);
    const override = { 'bare@1.0.0': { reason: 'reviewed', text: 'Declared MIT, no file.' } };
    expect(buildNotices(dir, m, override).text).toContain('Declared MIT, no file.');
    expect(() => buildNotices(dir, m, { 'bare@2.0.0': override['bare@1.0.0'] })).toThrow(/no licence text found/);
    expect(() => buildNotices(dir, m, { 'bare@1.0.0': { reason: '', text: 'x' } })).toThrow(/no licence text found/);
  });

  it('fails on an empty metafile, a name that does not match the folder, and an oversized licence file', () => {
    const dir = makeTempDir();
    expect(() => buildNotices(dir, meta('src/a.ts'))).toThrow(/no node_modules packages/);
    pkg(dir, 'node_modules/liar', 'other', '1.0.0', 'MIT', { LICENSE: 'x' });
    expect(() => buildNotices(dir, meta('node_modules/liar/a.js'))).toThrow(/does not match its folder/);
    pkg(dir, 'node_modules/big', 'big', '1.0.0', 'MIT', { LICENSE: 'x'.repeat(MAX_FILE_BYTES + 1) });
    expect(() => buildNotices(dir, meta('node_modules/big/a.js'))).toThrow(/larger than/);
  });

  it('does not follow a symlinked licence file or package folder', () => {
    const dir = makeTempDir();
    pkg(dir, 'node_modules/linked', 'linked', '1.0.0', 'MIT');
    writeIn(dir, 'secret.txt', 'SECRET');
    symlinkSync(join(dir, 'secret.txt'), join(dir, 'node_modules/linked/LICENSE'));
    expect(() => buildNotices(dir, meta('node_modules/linked/a.js'))).toThrow(/no licence text found/); // the link is skipped, never read
    pkg(dir, 'real', 'real', '1.0.0', 'MIT', { LICENSE: 'x' });
    symlinkSync(join(dir, 'real'), join(dir, 'node_modules/real'));
    expect(() => buildNotices(dir, meta('node_modules/real/a.js'))).toThrow(/symlink/);
  });
});

describe('the committed bundle', () => {
  it('every package in the real metafile passes with the real overrides, and THIRD_PARTY_NOTICES is current', () => {
    const metaPath = resolve(root, '.build/meta.json');
    if (!existsSync(metaPath)) execFileSync('npx', ['tsup'], { cwd: root, stdio: 'pipe' });
    const overrides = JSON.parse(readFileSync(resolve(root, 'scripts/notices-overrides.json'), 'utf8'));
    const { text, count } = buildNotices(root, JSON.parse(readFileSync(metaPath, 'utf8')), overrides);
    expect(count).toBeGreaterThan(40);
    expect(text).toContain('@opentelemetry/api@'); // Plan A: the Apache-2.0 API package must be listed
    expect(readFileSync(resolve(root, 'THIRD_PARTY_NOTICES'), 'utf8')).toBe(text);
  });
});
