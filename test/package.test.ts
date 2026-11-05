import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import { join, posix, resolve } from 'node:path';
import { build } from 'tsup';
import { afterEach, describe, expect, it } from 'vitest';
import { tsupOptions } from '../tsup.config.js';
import { loadPinnedBinaries } from '../src/engine/linters.js';
import { loadAiPrices, loadGitHubPlans } from '../src/estimate/estimate.js';
import { loadQualityBar } from '../src/engine/quality-bar.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { loadToolSignatures } from '../src/audit/coverage.js';
import { parse } from 'yaml';
import { cleanupRepos, makeRepo, makeTempDir, writeIn } from './helpers/make-repo.js';

const root = resolve(import.meta.dirname, '..');
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

afterEach(cleanupRepos);

/** The data files the bundled probe loads at runtime. */
const DATA_FILES = ['quality-bar.yml', 'pinned-binaries.yml', 'memory.json', 'reviewed-tools.yml', 'ai-prices.yml', 'github-plans.yml', 'tool-signatures.yml'];

/** Names passed to esbuild's __require shim (the CommonJS libraries' own require calls). Each must be a Node built-in. */
const shimRequires = (code: string) => [...code.matchAll(/__require\d*\(\s*["']([^"']+)/g)].map((m) => m[1] as string);

/**
 * The code of a bundle with its comments taken out, line by line, for the import scan (review M5): `//` lines and the
 * `*` lines inside a doc comment are dropped; a leading one-line block comment (`/* @__PURE__ *\/ require("x")`) is cut
 * and the rest of the line is kept; an unclosed block comment's opening line is dropped.
 */
function codeOf(text: string): string {
  return text.split('\n').flatMap((line) => {
    let l = line.replace(/^\s*(?:\/\*.*?\*\/\s*)+/, '');
    if (/^\s*(?:\/\/|\*|\/\*)/.test(l)) l = '';
    return l === '' ? [] : [l];
  }).join('\n');
}

/**
 * Plan J J2 bundles sucrase (it strips TypeScript from a next.config.ts before acorn parses it). Its transforms hold the import lines they
 * write as template text (`import {createRequire as ...} from "module"`, `from "${this.jsxImportSource}"`), which the text scan can't tell
 * from code. So the scan leaves out the modules under `node_modules/sucrase/` (each starts at esbuild's `// node_modules/...` path line and
 * runs to the next one), and the build test proves from esbuild's metafile that those modules import nothing outside the bundle.
 */
const TEXT_TEMPLATE_PACKAGES = ['sucrase'];
function withoutTemplatePackages(raw: string): string {
  let skipping = false;
  return raw.split('\n').filter((line) => {
    // any esbuild module path line ends the window (fix round 1, review J2 minor 1: also gate/src/… and other folders)
    if (/^\/\/ \S+\.(?:[cm]?[jt]sx?|json)$/.test(line)) skipping = TEXT_TEMPLATE_PACKAGES.some((p) => line.startsWith(`// node_modules/${p}/`));
    return !skipping;
  }).join('\n');
}

describe('package', () => {
  it('codeOf (M5): a line that starts with a one-line comment and goes on with code is still scanned', () => {
    const code = codeOf(['/* @__PURE__ */ require("x")', '  /* a */ /* b */ import y from "y";', '// from "c"', ' * from "d"', '/**', '/* open', 'const z = 1; /* trailing */'].join('\n'));
    expect(code).toContain('require("x")');
    expect(code).toContain('import y from "y";');
    expect(code).toContain('const z = 1;');
    expect(code).not.toMatch(/from "c"|from "d"|open/);
  });

  it('prepack builds the release dist (M4): npm pack never ships a stale dist', () => {
    expect(pkg.scripts.prepack).toBe('npm run build && npm run notices'); // the notices are rebuilt from the fresh bundle (B4)
    expect(pkg.scripts.build).toBe('tsup');
    expect(pkg.scripts.notices).toBe('node scripts/notices.ts');
  });

  it('files = dist, data, THIRD_PARTY_NOTICES (S16), and the packed list holds a non-empty THIRD_PARTY_NOTICES but no metafile', () => {
    expect(pkg.files).toEqual(['dist', 'data', 'THIRD_PARTY_NOTICES']);
    const packed = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, stdio: 'pipe' }).toString('utf8')) as { files: { path: string; size: number }[] }[];
    const files = packed[0]?.files ?? [];
    const notices = files.find((f) => f.path === 'THIRD_PARTY_NOTICES');
    expect(notices, 'THIRD_PARTY_NOTICES is in the packed file list').toBeDefined();
    expect(notices?.size).toBeGreaterThan(0);
    expect(files.filter((f) => (f.path.includes('meta.json') && !f.path.startsWith('data/npm-closures/')) || f.path.startsWith('.build'))).toEqual([]);
    expect(readFileSync(resolve(root, '.gitignore'), 'utf8').split('\n').map((l) => l.trim())).toContain('.build/');
  });

  it('the release build writes the esbuild metafile to .build/meta.json, not into dist; the dev build does not', async () => {
    const cfg = (await import('../tsup.config.js')) as { default: { esbuildPlugins?: unknown[] }; METAFILE_PATH: string };
    expect(cfg.METAFILE_PATH).toBe('.build/meta.json');
    expect(cfg.default.esbuildPlugins).toHaveLength(1);
    expect('esbuildPlugins' in tsupOptions).toBe(false); // the shared options (dev build, probe) carry no metafile writer
  });

  it('license Apache-2.0, bin dist/cli/main.js, repository url set, no dependencies field', () => {
    expect(pkg.license).toBe('Apache-2.0');
    expect(pkg.bin.pipegen).toBe('dist/cli/main.js');
    expect(pkg.repository.url).toBe('git+https://github.com/CrisWorking/pipegen.git');
    expect(pkg.engines.node).toBe('>=24');
    expect(pkg.type).toBe('module');
    expect('dependencies' in pkg).toBe(false);
  });
});

describe('dev build (ruling B3: internal runs before the reviewed list is reviewed)', () => {
  it('dev build: tsup.dev.config.ts = the release options without the release define, into .dev-dist/, which is gitignored, not in files and never packed', async () => {
    const dev = (await import('../tsup.dev.config.js')).devTsupOptions;
    const { define: _define, outDir: _outDir, ...release } = tsupOptions;
    expect(dev).toEqual({ ...release, outDir: '.dev-dist' });
    expect('define' in dev).toBe(false);
    expect(tsupOptions.define).toEqual({ 'process.env.PIPEGEN_RELEASE': '"1"' }); // the release build still refuses PENDING entries
    const ignored = readFileSync(resolve(root, '.gitignore'), 'utf8').split('\n').map((l) => l.trim());
    expect(ignored).toContain('.dev-dist/');
    expect(pkg.files).toEqual(['dist', 'data', 'THIRD_PARTY_NOTICES']);
    const packed = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, stdio: 'pipe' }).toString('utf8')) as { files: { path: string }[] }[];
    const paths = packed[0]?.files.map((f) => f.path) ?? [];
    expect(paths.length).toBeGreaterThan(0);
    expect(paths.filter((f) => f.startsWith('.dev-dist'))).toEqual([]);
    expect(paths.filter((f) => !f.startsWith('dist/') && !f.startsWith('data/'))).toEqual(expect.arrayContaining(['package.json', 'THIRD_PARTY_NOTICES']));
  });
});

describe('build', () => {
  it('dist/cli/main.js starts with the node shebang and imports only node: built-ins', () => {
    execFileSync('npx', ['tsup'], { cwd: root, stdio: 'pipe' });
    const raw = readFileSync(resolve(root, 'dist/cli/main.js'), 'utf8');
    expect(raw.startsWith('#!/usr/bin/env node\n')).toBe(true);
    // the release build refuses PENDING review entries: isReleaseBuild() is bundled as `return true`
    expect(raw).toMatch(/function isReleaseBuild\(\) \{\n\s*return true;/);
    // comments left out (the bundled Anthropic SDK's doc comments say things like "from 'queued' to 'starting'")
    const out = codeOf(withoutTemplatePackages(raw));
    expect(out.length).toBeGreaterThan(raw.length / 2); // the cut leaves most of the bundle to scan
    // the modules the text scan leaves out import nothing outside the bundle (esbuild's metafile lists every import of every input)
    const meta = JSON.parse(readFileSync(resolve(root, '.build/meta.json'), 'utf8')) as { inputs: Record<string, { imports: { path: string; external?: boolean }[] }> };
    const left = Object.entries(meta.inputs).filter(([f]) => TEXT_TEMPLATE_PACKAGES.some((p) => f.startsWith(`node_modules/${p}/`)));
    expect(left.length).toBeGreaterThan(0);
    // every input of the bundle (not only the left-out ones): an import esbuild marks external is a Node built-in, or a relative path to a
    // module that is itself an input of the bundle (esbuild marks one such import external in the metafile, src/audit/model.ts -> ../ai/errors.js,
    // while the module is inlined: dist/cli/main.js holds `// src/ai/errors.ts` and imports nothing but node: built-ins, which the scan above checks)
    const bundled = (from: string, rel: string) => rel.startsWith('.') && Object.hasOwn(meta.inputs, posix.join(posix.dirname(from), rel).replace(/\.js$/, '.ts'));
    for (const [f, input] of Object.entries(meta.inputs)) for (const i of input.imports) expect(i.external !== true || isBuiltin(i.path) || bundled(f, i.path), `${f} imports ${i.path}`).toBe(true);
    expect(readdirSync(resolve(root, 'dist'))).toEqual(['cli']); // no chunk next to main.js
    // Plan G G0 (carry E-b12, ruling S20): the JUnit worker entry is the one other file, next to main.js
    expect(readdirSync(resolve(root, 'dist/cli')).sort()).toEqual(['junit-thread.js', 'main.js']);
    const specs = [
      // a module specifier has no whitespace or comma (so a string list like "--volumes-from", "--stop-signal" isn't one)
      ...out.matchAll(/\bfrom\s*["']([^"'\s,]+)["']/g),
      ...out.matchAll(/\bimport\s*["']([^"'\s,]+)["']/g),
      ...out.matchAll(/\bimport\(\s*["']([^"'\s,]+)["']\s*\)/g),
      ...out.matchAll(/\brequire\(\s*["']([^"'\s,]+)["']\s*\)/g),
    ].map((m) => m[1]);
    for (const s of specs) expect(s.startsWith('node:'), `non-builtin import: ${s}`).toBe(true);
    for (const name of shimRequires(out)) expect(isBuiltin(name), `non-builtin require: ${name}`).toBe(true);
  });

  it('build: dist/cli/junit-thread.js is built and readJunitBytes from the bundle parses a report', async () => {
    // the release build makes the worker entry next to main.js (readJunitBytes' default: ./junit-thread.js next to the bundle)
    execFileSync('npx', ['tsup'], { cwd: root, stdio: 'pipe' });
    const thread = resolve(root, 'dist/cli/junit-thread.js');
    const code = readFileSync(thread, 'utf8');
    expect(code).toMatch(/parentPort/);   // the worker side, bundled on its own (no import of anything but node: built-ins)
    for (const s of [...codeOf(code).matchAll(/\bfrom\s*["']([^"'\s,]+)["']/g)].map((m) => m[1] as string)) expect(s.startsWith('node:'), s).toBe(true);
    // a probe bundled with the same options calls readJunitBytes with no workerUrl, next to a copy of the built worker file
    const dir = makeTempDir();
    await build({ ...tsupOptions, entry: { probe: 'test/helpers/junit-probe.ts' }, outDir: dir, config: false, silent: true });
    writeIn(dir, 'junit-thread.js', code);
    const report = resolve(root, 'test/fixtures/junit/vitest-5.0.5.xml');
    const out = JSON.parse(execFileSync('node', [join(dir, 'probe.js'), report], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()) as { ok: boolean; statuses?: string[]; reason?: string };
    expect(out).toEqual({ ok: true, statuses: ['pass', 'fail', 'skip', 'pass', 'pass'] });
    // without the worker file next to it the report is unreadable (fails closed), never a pass
    const bare = makeTempDir();
    await build({ ...tsupOptions, entry: { probe: 'test/helpers/junit-probe.ts' }, outDir: bare, config: false, silent: true });
    const none = JSON.parse(execFileSync('node', [join(bare, 'probe.js'), report], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()) as { ok: boolean };
    expect(none.ok).toBe(false);
  }, 120_000);

  it('a probe bundled with the same options runs readProject, bundleCode and makeProvider under plain node', async () => {
    // An installed-package layout: <pkg>/package.json (name pipegen), <pkg>/data/, and the probe in <pkg>/dist/cli/,
    // so the bundled data loaders (packageDataPath) are exercised as they run from dist/cli/main.js.
    const pkgDir = makeTempDir();
    const outDir = join(pkgDir, 'dist', 'cli');
    writeIn(pkgDir, 'package.json', JSON.stringify({ name: 'pipegen' }));
    for (const file of DATA_FILES) writeIn(pkgDir, `data/${file}`, readFileSync(resolve(root, 'data', file), 'utf8'));
    for (const file of readdirSync(resolve(root, 'data/npm-closures'))) writeIn(pkgDir, `data/npm-closures/${file}`, readFileSync(resolve(root, 'data/npm-closures', file), 'utf8')); // the checkers' closure locks (DECISIONS #107)
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
    const result = JSON.parse(stdout.trim()) as { owner: string; repo: string; services: string[]; files: number; bytes: number; checked: boolean; providers: string[]; pushJobs: number; needsSchemaKeys: string[]; qualityBar: unknown; qualityReasons: number; pinnedBinaries: { loaded?: unknown; refused?: string }; bundledMemory: unknown; reviewed: { loaded?: number; refused?: string }; aiPrices: unknown; githubPlans: unknown; toolSignatures: unknown; coverage: string[]; floorNeeds: number; estimate: { setupMinutes: number; includedMinutes: number | null; aiCostCapUsd: number | null } };
    expect(result).toMatchObject({ owner: 'o', repo: 'r', services: ['.'], checked: false, providers: ['claude', 'openai', 'ollama'] });
    expect(result.pushJobs).toBe(7); // hooks-ci, secrets + sast, deps, unit-tests, lint for the one service + workflow-lint (Plan P)
    expect(result.needsSchemaKeys).toEqual(['add', 'skipLayers', 'requireDeployApproval']);
    expect(result.qualityBar).toEqual(loadQualityBar()); // read from <pkg>/data/quality-bar.yml by the bundled loader
    expect(result.qualityReasons).toBe(3); // few stars, no releases, advisories unknown
    expect(result.bundledMemory).toEqual([]); // data/memory.json, read by the bundled loader
    // read from <pkg>/data/pinned-binaries.yml by the bundled loader: like the reviewed list, the release build refuses
    // it while any entry is still PENDING review (final review I2), and loads it once every entry is reviewed
    const pins = parse(readFileSync(resolve(root, 'data/pinned-binaries.yml'), 'utf8')) as Record<string, { reviewedBy: string }>;
    const pendingPins = Object.entries(pins).filter(([, e]) => e.reviewedBy === 'PENDING').map(([n]) => n);
    if (pendingPins.length > 0) {
      expect(result.pinnedBinaries).toEqual({ refused: expect.stringMatching(/wait for human review/) });
      for (const n of pendingPins) expect(result.pinnedBinaries.refused).toContain(n);
    } else {
      expect(result.pinnedBinaries).toEqual({ loaded: loadPinnedBinaries() });
    }
    expect(Object.keys(loadPinnedBinaries()).sort()).toEqual(['actionlint', 'betterleaks', 'cosign', 'gitleaks', 'zizmor']); // from src (dev build): loads
    expect(result.aiPrices).toEqual(loadAiPrices()); // read from <pkg>/data/ai-prices.yml by the bundled loader
    expect(result.githubPlans).toEqual(loadGitHubPlans()); // read from <pkg>/data/github-plans.yml by the bundled loader
    expect(result.toolSignatures).toEqual(loadToolSignatures()); // read from <pkg>/data/tool-signatures.yml by the bundled loader
    expect(result.coverage.length).toBe(result.floorNeeds); // one coverage row per floor need, from the bundled mapper
    expect(result.coverage.every((s) => s === 'missing')).toBe(true); // the fixture has no workflows and no hooks
    expect(result.estimate.includedMinutes).toBe(2000); // private Free repo
    expect(result.estimate.aiCostCapUsd).toBeGreaterThan(0);
    // ruling S21: the bundled (release) loader refuses the reviewed list while any entry is still PENDING; once every
    // entry is reviewed it loads the whole list. Run from src (no define, NODE_ENV=test), the same file loads.
    const tools = (parse(readFileSync(resolve(root, 'data/reviewed-tools.yml'), 'utf8')) as { tools: { id: string; reviewedBy: string }[] }).tools;
    const pending = tools.filter((t) => t.reviewedBy === 'PENDING').map((t) => t.id);
    if (pending.length > 0) {
      expect(result.reviewed).toEqual({ refused: expect.stringMatching(/wait for human review/) });
      expect(result.reviewed.refused).toContain(pending[0]);
    } else {
      expect(result.reviewed).toEqual({ loaded: tools.length });
    }
    expect(loadReviewed()).toHaveLength(tools.length);
    expect(code).toContain('server-side-fallback-2026-07-01'); // the Anthropic SDK client really is in the bundle
    expect(result.files).toBeGreaterThan(0);
    expect(result.bytes).toBeGreaterThan(0);
  });
});
