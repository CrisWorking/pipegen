// D5 (S10): libsodium-wrappers is bundled like every dependency, and the BUNDLE works: it seals and opens, run with no node_modules around it.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { build } from 'tsup';
import { afterEach, describe, expect, it } from 'vitest';
import { tsupOptions } from '../tsup.config.js';

const root = resolve(import.meta.dirname, '..');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

describe('libsodium-wrappers: exact, bundled, working', () => {
  it('package.json pins an exact version (no range) as a devDependency, and the lockfile entry has integrity', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { devDependencies: Record<string, string>; dependencies?: Record<string, string> };
    expect(pkg.devDependencies['libsodium-wrappers']).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.dependencies?.['libsodium-wrappers']).toBeUndefined();
    const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')) as { packages: Record<string, { version?: string; resolved?: string; integrity?: string }> };
    for (const k of ['node_modules/libsodium-wrappers', 'node_modules/libsodium']) {
      expect(lock.packages[k]?.integrity, k).toMatch(/^sha512-/);
      expect(lock.packages[k]?.resolved, k).toMatch(/^https:\/\/registry\.npmjs\.org\//);
    }
    expect(lock.packages['node_modules/libsodium-wrappers']?.version).toBe(pkg.devDependencies['libsodium-wrappers']);
  });

  it('the release build bundles it: a probe built with the release settings seals and opens (repo and environment secrets) with no node_modules beside it', async () => {
    const out = mkdtempSync(join(tmpdir(), 'pg-sodium-'));
    dirs.push(out);
    const { define: _define, ...opts } = tsupOptions;
    await build({ ...opts, entry: { 'seal-probe': 'test/helpers/secrets-seal-probe.ts' }, outDir: out, config: false, silent: true, clean: false });
    const bundle = readFileSync(join(out, 'seal-probe.js'), 'utf8');
    expect(bundle).not.toMatch(/from ["']libsodium/);   // no import left to resolve at run time
    const got = execFileSync(process.execPath, [join(out, 'seal-probe.js')], { cwd: out, env: { PATH: process.env.PATH ?? '' }, timeout: 60_000, encoding: 'utf8' });
    expect(JSON.parse(got)).toEqual({ repo: 'sk_test_bundled_value_1', env: 'cosign_bundled_value_2', keyId: 'k1' });
  }, 120_000);
});
