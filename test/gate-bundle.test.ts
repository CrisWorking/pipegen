// C6: the gate bundle gate/dist/index.js. Written first. The bundle is what GitHub runs (`runs.main`), so these tests run the BUNDLE, in a
// child process, on the same fixtures as the C5b action tests; the network is replaced by a preloaded fetch (test/helpers/fake-github-preload.mjs).
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { build } from 'tsup';
import { gateTsupOptions, GATE_BUNDLE } from '../tsup.gate.config.js';
import { gateViewModule } from '../scripts/gate-view.js';
import { GATE_VIEW } from '../gate/src/generated/gate-view.js';
import { loadReviewed } from '../src/engine/reviewed.js';
import { gateToolView } from '../gate/src/settings.js';
import { CRED, FakeGh, FPKEY, outputsOf, pushWorld, RUN, runner, type World } from './helpers/gate-world.js';

const ROOT = resolve(import.meta.dirname, '..');
const BUNDLE = join(ROOT, GATE_BUNDLE);
const PRELOAD = join(ROOT, 'test/helpers/fake-github-preload.mjs');
const text = (): string => readFileSync(BUNDLE, 'utf8');
const CLEAN = (): Parameters<typeof pushWorld>[0] => ({ 'sast--app': readFileSync(join(ROOT, 'test/fixtures/sarif/clean/semgrep.sarif'), 'utf8') });

interface Out { code: number | null; stdout: string; stderr: string }
function runNode(entry: string, env: Record<string, string>, preload?: string): Promise<Out> {
  return new Promise((done) => {
    const args = [...(preload === undefined ? [] : ['--import', preload]), entry];
    const child = spawn(process.execPath, args, { env: { PATH: process.env.PATH ?? '', ...env }, cwd: tmpdir() });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.on('close', (code) => { done({ code, stdout, stderr }); });
  });
}

/** The fake API of a world as a table for the preload: artifacts, their zips, the compares and the runs. */
async function tableOf(w: World, names: string[]): Promise<string> {
  const gh = new FakeGh(w);
  const routes: Record<string, unknown> = {};
  const zips: Record<string, string> = {};
  for (const n of names) routes[`/repos/acme/app/actions/runs/${RUN}/artifacts?name=${n}&per_page=100`] = await gh.listRunArtifacts('acme', 'app', RUN, n);
  for (const a of w.arts) zips[String(a.id)] = Buffer.from(a.zip).toString('base64');
  for (const [k, v] of w.compare) routes[`/repos/acme/app/compare/${k}`] = v;
  const file = join(mkdtempSync(join(tmpdir(), 'pipegen-c6-')), 'fake-gh.json');
  writeFileSync(file, JSON.stringify({ routes, zips, runs: { 1: { workflow_runs: w.runs } } }));
  return file;
}

describe('C6 bundle: the built-in reviewed view (S5)', () => {
  it('gate/src/generated/gate-view.ts equals gateToolView(loadReviewed()) and is exactly what the generator writes', () => {
    const list = loadReviewed();
    expect(GATE_VIEW).toEqual(gateToolView(list));
    expect(readFileSync(join(ROOT, 'gate/src/generated/gate-view.ts'), 'utf8')).toBe(gateViewModule(list));
  });
  it('the bundle holds no loader and reads no data file at run time', () => {
    const t = text();
    expect(t).not.toContain('reviewed-tools.yml');
    expect(t).not.toContain('packageDataPath');
    expect(t).not.toContain('PIPEGEN_RELEASE');
  });
});

describe('C6 bundle: what is in it', () => {
  it('imports only node: modules, and never child_process', () => {
    const t = text();
    // static imports are whole lines at the top level of an ESM bundle; dynamic import() and require() are looked for anywhere
    const specs = [...t.matchAll(/^import\s(?:[^"'\n]*?\sfrom\s)?["']([^"']+)["'];?$|\b(?:import|require)\s*\(\s*["']([^"']+)["']\s*\)/gm)].map((m) => (m[1] ?? m[2]) as string);
    expect(specs.length).toBeGreaterThan(3);
    expect(specs.filter((s) => !s.startsWith('node:'))).toEqual([]);
    expect(specs).not.toContain('node:child_process');
    expect(t).not.toContain('child_process');
  });
  it('is ESM, runs under the repo package type, and has no shebang', () => {
    expect((JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { type: string }).type).toBe('module');
    expect(text().startsWith('#!')).toBe(false);
    expect(text()).toMatch(/^import /m);
  });
  it('holds no secret literal (token shapes, key blocks, the fixtures\' credentials)', () => {
    const t = text();
    // concrete token shapes (a regex SOURCE such as `gh[pousr]_[A-Za-z0-9]{36,}` in the bundled redaction code is not a token)
    const shapes = [/gh[pousr]_[A-Za-z0-9]{30,}/, /github_pat_[A-Za-z0-9_]{20,}/, /sk-ant-[A-Za-z0-9_-]{20,}/, /AKIA[0-9A-Z]{16}/, /xox[abprs]-[A-Za-z0-9-]{10,}/, /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./,
      new RegExp(['-----', 'BEGIN [A-Z ]*PRIVATE KEY', '-----'].join(''))];
    for (const re of shapes) expect(t, String(re)).not.toMatch(re);
    expect(t).not.toContain(CRED);
    expect(t).not.toContain(FPKEY);
  });
  it('gate/dist holds exactly the three generated files, committed (an extra file would ship unreviewed code)', () => {
    const tracked = execFileSync('git', ['ls-files', 'gate/dist'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter((l) => l !== '').sort();
    expect(tracked).toEqual(['gate/dist/README.md', 'gate/dist/THIRD_PARTY_NOTICES', 'gate/dist/index.js']);
    expect(readdirSync(join(ROOT, 'gate/dist')).sort()).toEqual(['README.md', 'THIRD_PARTY_NOTICES', 'index.js']);
  });
  it('action.yml runs exactly node24 and dist/index.js: no pre, post, pre-if or post-if', () => {
    const runs = (parse(readFileSync(join(ROOT, 'gate/action.yml'), 'utf8')) as { runs: unknown }).runs;
    expect(runs).toEqual({ using: 'node24', main: 'dist/index.js' });
  });
  it('the gate THIRD_PARTY_NOTICES names the gate bundle, not the CLI\'s', () => {
    const t = readFileSync(join(ROOT, 'gate/dist/THIRD_PARTY_NOTICES'), 'utf8');
    expect(t).toContain('gate/dist/index.js');
    expect(t).not.toContain('dist/cli/main.js');
    expect(t).toContain('smol-toml@1.9.1\nLicense: BSD-3-Clause');
  });
  it('the trust-root files of the gate build are code-owner paths', () => {
    const owners = readFileSync(join(ROOT, '.github/CODEOWNERS'), 'utf8');
    for (const p of ['/tsup.gate.config.ts', '/test/gate-entry.test.ts', '/test/gate-bundle.test.ts', '/gate/', '/scripts/']) expect(owners, p).toMatch(new RegExp(`^${p.replace(/[./]/g, '\\$&')}\\s+@CrisWorking$`, 'm'));
  });
  it('docs/release.md lists gate-dist among the required checks', () => {
    expect(readFileSync(join(ROOT, 'docs/release.md'), 'utf8')).toMatch(/`gate-dist`/);
  });
  it('CI gate-dist also fails on an extra committed file in gate/dist', () => {
    const ci2 = parse(readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8')) as { jobs: Record<string, { steps: { run?: string }[] }> };
    expect((ci2.jobs['gate-dist']?.steps ?? []).map((s) => s.run ?? '').join('\n')).toMatch(/git ls-files gate\/dist/);
  });
  it('action.yml runs it (node24, dist/index.js)', () => {
    expect(readFileSync(join(ROOT, 'gate/action.yml'), 'utf8')).toMatch(/using: node24\n\s+main: dist\/index\.js/);
    expect(existsSync(join(ROOT, 'gate/dist/README.md'))).toBe(true);
  });
});

describe('C6 bundle: the build is fresh and deterministic', () => {
  it('two builds give the same bytes, and they are the committed gate/dist/index.js', async () => {
    const hashes: string[] = [];
    for (let i = 0; i < 2; i++) {
      const outDir = mkdtempSync(join(tmpdir(), 'pipegen-c6-build-'));
      await build({ ...gateTsupOptions, outDir, config: false, silent: true });
      hashes.push(createHash('sha256').update(readFileSync(join(outDir, 'index.js'))).digest('hex'));
    }
    expect(hashes[0]).toBe(hashes[1]);
    expect(hashes[0]).toBe(createHash('sha256').update(readFileSync(BUNDLE)).digest('hex'));
  });
});

describe('C6 bundle: node gate/dist/index.js, end to end', () => {
  it('mode gate on a clean push: exit 0, result pass, result.json written', async () => {
    const w = pushWorld(CLEAN());
    const r = runner(w.inputs, { event: w.event, sha: w.sha, payload: w.payload });
    const table = await tableOf(w, ['pipegen-out-secrets', 'pipegen-out-base-secrets', 'pipegen-out-sast--app', 'pipegen-out-base-sast--app', 'pipegen-out-deps', 'pipegen-out-base-deps']);
    const x = await runNode(BUNDLE, { ...r.env, PIPEGEN_FAKE_GH: table }, PRELOAD);
    expect(x.stdout + x.stderr).not.toMatch(/::error::/);
    expect(x.code).toBe(0);
    expect(outputsOf(r.output).result).toBe('pass');
    expect(JSON.parse(readFileSync(join(r.temp, 'pipegen-gate', 'result.json'), 'utf8'))).toMatchObject({ pipegenGateResult: 1, result: 'pass' });
  });
  it('mode gate with a bad key fails closed: exit 1, a block result.json', async () => {
    const w = pushWorld(CLEAN());
    const r = runner({ ...w.inputs, 'fp-key': 'short' }, { event: w.event, sha: w.sha, payload: w.payload });
    const x = await runNode(BUNDLE, r.env);
    expect(x.code).toBe(1);
    expect(JSON.parse(readFileSync(join(r.temp, 'pipegen-gate', 'result.json'), 'utf8'))).toMatchObject({ result: 'block' });
  });
  it('mode scrub: the scrubbed copy and the outputs', async () => {
    const A = 'pipegen-out-sast--app';
    const r = runner({});
    const inputs: Record<string, string> = { mode: 'scrub', artifact: A, tool: 'semgrep', format: 'sarif', raw: `${r.temp}/pipegen-raw/${A}/r.sarif`, out: `${r.temp}/pipegen-out/${A}/r.sarif` };
    for (const [k, v] of Object.entries(inputs)) r.env[`INPUT_${k.toUpperCase()}`] = v;
    mkdirSync(join(r.temp, 'pipegen-raw', A), { recursive: true });
    writeFileSync(join(r.temp, 'pipegen-raw', A, 'r.sarif'), readFileSync(join(ROOT, 'test/fixtures/sarif/semgrep.sarif')));
    const x = await runNode(BUNDLE, r.env);
    expect(x.code).toBe(0);
    expect(outputsOf(r.output)).toMatchObject({ status: 'ok' });
    expect(existsSync(join(r.temp, 'pipegen-out', A, 'r.sarif'))).toBe(true);
  });
  it('mode baseline-check with no github-token input: found=missing, exit 0', async () => {
    const w = pushWorld(CLEAN());
    const r = runner({ mode: 'baseline-check' }, { event: w.event, sha: w.sha, payload: w.payload });
    const x = await runNode(BUNDLE, r.env);
    expect(x.code).toBe(0);
    expect(outputsOf(r.output).found).toBe('missing');
  });
  it('mode nightly fails closed until C7; find-run without its inputs fails closed too', async () => {
    for (const mode of ['find-run', 'nightly']) {
      const r = runner({ mode });
      const x = await runNode(BUNDLE, r.env);
      expect(x.code, mode).toBe(1);
      expect(x.stdout, mode).toMatch(mode === 'nightly' ? /::error::.*not available yet/ : /::error::.*sha/);
    }
  });
  it('a missing or unknown mode fails closed (exit 1)', async () => {
    expect((await runNode(BUNDLE, runner({}).env)).code).toBe(1);
    expect((await runNode(BUNDLE, runner({ mode: 'nope' }).env)).code).toBe(1);
  });
  it('through a SYMLINKED action path the entry still runs main (a path guard would have run nothing and passed)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-c6-link-'));
    const link = join(dir, 'action');
    symlinkSync(join(ROOT, 'gate/dist'), link);
    const r = runner({ mode: 'nope' });
    const x = await runNode(join(link, 'index.js'), r.env);
    expect(x.stdout).toMatch(/::error::the mode input is not one/);
    expect(x.code).toBe(1);
  });
});

describe('C6 bundle: the CI freshness job', () => {
  const ci = parse(readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8')) as { jobs: Record<string, { steps: { uses?: string; run?: string }[]; permissions?: Record<string, string> }> };
  it('gate-dist builds the bundle and fails on any difference in gate/dist and the generated view; its actions are pinned by SHA like the other jobs', () => {
    const job = ci.jobs['gate-dist'];
    expect(job).toBeDefined();
    const runs = (job?.steps ?? []).map((s) => s.run ?? '').join('\n');
    expect(runs).toContain('npm run build:gate');
    expect(runs).toMatch(/git diff --exit-code -- gate\/dist gate\/src\/generated/);
    expect(runs).toContain('git status --porcelain');
    expect(job?.permissions).toEqual({ contents: 'read' });
    const pinned = (jobName: string): string[] => (ci.jobs[jobName]?.steps ?? []).flatMap((s) => (s.uses === undefined ? [] : [s.uses]));
    for (const u of pinned('gate-dist')) expect(u).toMatch(/^[\w./-]+@[0-9a-f]{40}$/);
    expect(pinned('gate-dist')).toEqual(pinned('notices-fresh'));
  });
  it('npm run build:gate is the one build command, and it writes the notices', () => {
    const scripts = (JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { scripts: Record<string, string> }).scripts;
    expect(scripts['build:gate']).toMatch(/^tsup --config tsup\.gate\.config\.ts && node scripts\/notices\.ts .*gate\/dist\/THIRD_PARTY_NOTICES$/);
    expect(existsSync(join(ROOT, 'gate/dist/THIRD_PARTY_NOTICES'))).toBe(true);
  });
});
