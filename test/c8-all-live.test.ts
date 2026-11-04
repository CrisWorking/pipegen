// LIVE (PIPEGEN_LIVE_TESTS=1; network: the npm registry only, for c8@12.0.0 and its dependencies): E9, D9 review I1. Before E9 the
// reviewed c8 step ran `c8 --check-coverage --lines=<n> -- npm test`, and a service whose test script loads no code (`"test": "true"`)
// gave an empty measurement that passed any minimum. With `--all` every source file under the folder counts, loaded or not, so the same
// service now fails at --lines. The REAL rendered steps run here, in order, as a runner would: the guarded `npm ci`, the lockfile check of
// the installed c8, and the c8 run. The lock is made from the registry (`npm install --package-lock-only --ignore-scripts`) and must pin
// the reviewed c8 integrity. Skipped unless PIPEGEN_LIVE_TESTS=1, so `npm test` stays offline.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { renderStepWith, type RenderedStep } from '../src/engine/render-step.js';
import { ctxFor, entry, platform, service, specFor } from './helpers/render.js';

const live = process.env.PIPEGEN_LIVE_TESTS === '1';
const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function steps(lines: string): RenderedStep[] {
  const t = entry('c8');
  const svc = service({ name: 'app', path: '.', packageManager: 'npm', scripts: ['test'] });
  return renderStepWith(specFor(t, { needId: 'coverage', service: 'app', choices: { lines } }), t, platform(), ctxFor([svc])).steps.filter((s) => s.run !== undefined);
}

/** A service folder with src/m.js (12 lines), the given test script, and a registry-made lock for c8@12.0.0. */
function fixture(testScript: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-e9-c8-'));
  dirs.push(dir);
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src', 'm.js'), "export function a(x) { return x + 1; }\nexport function b(x) {\n  if (x > 0) {\n    return 'pos';\n  }\n  return 'neg';\n}\nexport function c() {\n  const r = [];\n  for (let i = 0; i < 3; i++) r.push(i);\n  return r;\n}\n");
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'fx', version: '1.0.0', private: true, type: 'module', scripts: { test: testScript }, devDependencies: { c8: '12.0.0' } }));
  const lock = spawnSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: dir, encoding: 'utf8' });
  expect(lock.status, lock.stderr).toBe(0);
  const pinned = (entry('c8').candidate.pin as { checksum: string }).checksum;
  expect(JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8')).packages['node_modules/c8'].integrity).toBe(pinned);
  return dir;
}

/** Runs the rendered steps in order in `dir`; the last step's exit code and output (or the first failing step's). */
function runSteps(list: RenderedStep[], dir: string): { status: number | null; out: string; name: string } {
  const rt = mkdtempSync(join(tmpdir(), 'pipegen-e9-rt-'));
  dirs.push(rt);
  let last = { status: 0 as number | null, out: '', name: '' };
  for (const s of list) {
    const r = spawnSync('bash', ['--noprofile', '--norc', '-c', s.run as string], { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH ?? '/usr/bin:/bin', RUNNER_TEMP: rt, GITHUB_WORKSPACE: dir, ...(s.env ?? {}) } });
    last = { status: r.status, out: `${r.stdout}${r.stderr}`, name: s.name ?? '' };
    if (r.status !== 0) break;
  }
  return last;
}

describe.skipIf(!live)('E9: c8 --all (live, npm registry only)', () => {
  it('c8: rendered with --all; an empty measurement fails at --lines', () => {
    const list = steps('60');
    expect(list.at(-1)?.run).toContain('--check-coverage --all --lines="$PIPEGEN_ARG_0" -- "$nodebin/npm" test');
    // a test script that loads no code: every file under the folder counts at 0%
    const empty = runSteps(list, fixture('true'));
    expect(empty.name).toBe('pipegen: run c8');
    expect(empty.status).toBe(1);
    expect(empty.out).toMatch(/Coverage for lines \(0%\) does not meet global threshold \(60%\)/);
    // the same with a repo .c8rc.json that turns --all off: the command line wins
    const offDir = fixture('true');
    writeFileSync(join(offDir, '.c8rc.json'), '{ "all": false }\n');
    const off = runSteps(list, offDir);
    expect(off.status).toBe(1);
    expect(off.out).toMatch(/does not meet global threshold \(60%\)/);
    // and a fully covered service still passes at 90
    const fullDir = fixture('node --test');
    mkdirSync(join(fullDir, 'test'));
    writeFileSync(join(fullDir, 'test', 'm.test.js'), "import test from 'node:test';\nimport assert from 'node:assert';\nimport { a, b, c } from '../src/m.js';\ntest('all', () => { assert.equal(a(1), 2); assert.equal(b(1), 'pos'); assert.equal(b(-1), 'neg'); assert.deepEqual(c(), [0, 1, 2]); });\n");
    const full = runSteps(steps('90'), fullDir);
    expect(full.status, full.out).toBe(0);
  }, 600_000);
});
