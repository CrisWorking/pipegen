import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import { join, resolve } from 'node:path';
import { build } from 'tsup';
import { afterEach, describe, expect, it } from 'vitest';
import { tsupOptions } from '../tsup.config.js';
import { loadPinnedBinaries } from '../src/engine/linters.js';
import { loadQualityBar } from '../src/engine/quality-bar.js';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';

const root = resolve(import.meta.dirname, '..');
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

afterEach(cleanupRepos);

/** The data files the bundled probe loads at runtime. */
const DATA_FILES = ['quality-bar.yml', 'pinned-binaries.yml'];

/** Names passed to esbuild's __require shim (the CommonJS libraries' own require calls). Each must be a Node built-in. */
const shimRequires = (code: string) => [...code.matchAll(/__require\d*\(\s*["']([^"']+)/g)].map((m) => m[1] as string);

describe('package', () => {
  it('license Apache-2.0, bin dist/cli/main.js, repository url set, no dependencies field', () => {
    expect(pkg.license).toBe('Apache-2.0');
    expect(pkg.bin.pipegen).toBe('dist/cli/main.js');
    expect(pkg.repository.url).toBe('git+https://github.com/CrisWorking/pipegen.git');
    expect(pkg.engines.node).toBe('>=24');
    expect(pkg.type).toBe('module');
    expect('dependencies' in pkg).toBe(false);
  });
});

describe('build', () => {
  it('dist/cli/main.js starts with the node shebang and imports only node: built-ins', () => {
    execFileSync('npx', ['tsup'], { cwd: root, stdio: 'pipe' });
    const out = readFileSync(resolve(root, 'dist/cli/main.js'), 'utf8');
    expect(out.startsWith('#!/usr/bin/env node\n')).toBe(true);
    const specs = [
      ...out.matchAll(/\bfrom\s*["']([^"']+)["']/g),
      ...out.matchAll(/\bimport\s*["']([^"']+)["']/g),
      ...out.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g),
      ...out.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/g),
    ].map((m) => m[1]);
    for (const s of specs) expect(s.startsWith('node:'), `non-builtin import: ${s}`).toBe(true);
    for (const name of shimRequires(out)) expect(isBuiltin(name), `non-builtin require: ${name}`).toBe(true);
  });

  it('a probe bundled with the same options runs readProject, bundleCode and makeProvider under plain node', async () => {
    // An installed-package layout: <pkg>/package.json (name pipegen), <pkg>/data/, and the probe in <pkg>/dist/cli/,
    // so the bundled data loaders (packageDataPath) are exercised as they run from dist/cli/main.js.
    const pkgDir = makeTempDir();
    const outDir = join(pkgDir, 'dist', 'cli');
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'pipegen' }));
    for (const file of DATA_FILES) writeIn(pkgDir, `data/${file}`, readFileSync(resolve(root, 'data', file), 'utf8'));
    await build({ ...tsupOptions, entry: { probe: 'test/helpers/bundle-probe.ts' }, outDir, config: false, silent: true });
    const probe = join(outDir, 'probe.js');
    const code = readFileSync(probe, 'utf8');
    const names = shimRequires(code);
    expect(names.length).toBeGreaterThan(0); // the CommonJS libraries (fast-glob, picomatch, ...) really are inside
    for (const name of names) expect(isBuiltin(name), `non-builtin require: ${name}`).toBe(true);
    const repo = makeRepo('node-npm', 'https://github.com/o/r.git');
    let stdout: string;
    try {
      stdout = execFileSync('node', [probe, repo], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      const err = e as { status?: number; stderr?: string };
      throw new Error(`probe exited with ${err.status}: ${String(err.stderr).split('\n').slice(0, 8).join('\n')}`);
    }
    const result = JSON.parse(stdout.trim()) as { owner: string; repo: string; services: string[]; files: number; bytes: number; gitleaksChecked: boolean; providers: string[]; pushJobs: number; needsSchemaKeys: string[]; qualityBar: unknown; qualityReasons: number; pinnedBinaries: unknown };
    expect(result).toMatchObject({ owner: 'o', repo: 'r', services: ['.'], gitleaksChecked: false, providers: ['claude', 'openai', 'ollama'] });
    expect(result.pushJobs).toBe(6); // hooks-ci, secrets + sast, deps, unit-tests, lint for the one service
    expect(result.needsSchemaKeys).toEqual(['add', 'skipLayers', 'requireDeployApproval']);
    expect(result.qualityBar).toEqual(loadQualityBar()); // read from <pkg>/data/quality-bar.yml by the bundled loader
    expect(result.qualityReasons).toBe(3); // few stars, no releases, advisories unknown
    expect(result.pinnedBinaries).toEqual(loadPinnedBinaries()); // read from <pkg>/data/pinned-binaries.yml by the bundled loader
    expect(code).toContain('server-side-fallback-2026-07-01'); // the Anthropic SDK client really is in the bundle
    expect(result.files).toBeGreaterThan(0);
    expect(result.bytes).toBeGreaterThan(0);
  });
});
