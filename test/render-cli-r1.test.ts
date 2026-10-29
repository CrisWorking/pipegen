// Plan B 6b fix round 1 (review-6b.md and the controller's rulings R-A .. R-F, DECISIONS #107): isolated npm installs,
// injective dedupe, hardened system tools, DAST networking, and tools that are refused until their slot exists.
// The shell is run through real bash with stand-ins for node, npm and python (no network).
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { closureRootDependencies, expectedPins } from '../src/engine/npm-closure.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { checkJobOrder, dedupeJobSteps, RenderError, renderScrub, renderStep, renderStepWith, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { ARGV_POLICIES, REPO_CODE_STEP_ID_RE, runsRepoCode, type ArgvPolicy } from '../src/engine/tool-flags.js';
import type { ReviewedTool, StepSpec } from '../src/types.js';
import { ctxFor, entry, gateEntry, platform, service, specFor } from './helpers/render.js';
import { exec, fakeTool, FIXED_PATH, sandbox, stepEnv, type Sandbox } from './helpers/step-harness.js';
import { readFileSync as read } from 'node:fs';
import { packageDataPath } from '../src/util/package-data.js';

const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const spec = (t: ReviewedTool, over: Partial<StepSpec> = {}): StepSpec => specFor(t, { needId: needFor(t), ...over });
const withNames = (s: StepSpec, names: string[]): StepSpec => {
  const copy = { ...s };
  Reflect.set(copy, 'secrets', names);
  return copy;
};
const withPolicy = (id: string, drop: (keyof ArgvPolicy)[] = [], add: Partial<ArgvPolicy> = {}): { policies: Record<string, ArgvPolicy> } => {
  const p = { ...ARGV_POLICIES[id] } as Record<string, unknown>;
  for (const k of drop) delete p[k];
  return { policies: { ...ARGV_POLICIES, [id]: { ...p, ...add } as ArgvPolicy } };
};
const render = (id: string, over: Partial<StepSpec> = {}, c = ctx, opts?: Parameters<typeof renderStepWith>[4]): RenderResult => {
  const t = entry(id);
  return renderStepWith(spec(t, over), t, platform(), c, opts);
};
const runs = (r: RenderResult): RenderedStep[] => r.steps.filter((s) => s.run !== undefined);
const lastRun = (r: RenderResult): RenderedStep => runs(r).at(-1) as RenderedStep;
const closureText = (id: string): string => read(packageDataPath(`npm-closures/${id}.json`), 'utf8');
const ctx = ctxFor([service({ name: 'app', path: '.' })], { image: `ghcr.io/o/app@sha256:${'a'.repeat(64)}`, url: 'http://localhost:8080' });
const REAL_BASH = process.platform !== 'win32';
const it2 = it.skipIf(!REAL_BASH);
const hash16 = /^pipegen-npm-ci-[0-9a-f]{16}$/;

// ---------- stand-ins for node and npm ----------
/**
 * A folder holding a `node` that answers --version with the given major and otherwise runs the real node, and an `npm`
 * that "installs" by reading the package-lock.json in its working folder and making node_modules/<name>/package.json
 * (and the hidden lockfile) for every entry, as the mode file in runner temp says: ok, wrong-version, symlink or fail.
 */
function fakeNodeDir(sb: Sandbox, major = 22): string {
  const bin = join(sb.dir, 'nodebin');
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'node'), `#!/bin/sh\nif [ "$1" = --version ]; then echo v${major}.3.0; exit 0; fi\nexec ${process.execPath} "$@"\n`);
  writeFileSync(join(bin, 'npm'), `#!/bin/sh
echo "$PWD" > "$RUNNER_TEMP/npm-cwd.txt"
for a in "$@"; do printf '%s\\0' "$a"; done > "$RUNNER_TEMP/npm-args.bin"
env > "$RUNNER_TEMP/npm-env.txt"
mode=ok; [ -f "$RUNNER_TEMP/fake-mode" ] && mode="$(cat "$RUNNER_TEMP/fake-mode")"
[ "$mode" = fail ] && exit 1
FAKE_TARGET="$(cat "$RUNNER_TEMP/fake-target" 2>/dev/null)" exec ${process.execPath} -e '
const fs = require("fs"), path = require("path");
const mode = process.argv[1];
const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const hidden = { packages: {} };
for (const [k, e] of Object.entries(lock.packages)) {
  if (k === "") continue;
  const dir = k;
  fs.mkdirSync(dir, { recursive: true });
  let version = e.version;
  if (mode === "wrong-version" && k === "node_modules/" + process.env.FAKE_TARGET) version = "0.0.1";
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: k.split("node_modules/").pop(), version }));
  hidden.packages[k] = { version: e.version, resolved: e.resolved, integrity: e.integrity };
  // every package gets the bin files the policies name; running one records its arguments and the names of its environment
  for (const b of ["bin/eslint.js", "bin/oxlint", "bin/prettier.cjs", "bin/knip.js", "bin/biome", "vitest.mjs", "bin/c8.js"]) {
    fs.mkdirSync(path.join(dir, path.dirname(b)), { recursive: true });
    fs.writeFileSync(path.join(dir, b), "const fs = require(\\"fs\\"); fs.writeFileSync(process.env.RUNNER_TEMP + \\"/tool-ran\\", process.argv.slice(2).join(\\" \\")); fs.writeFileSync(process.env.RUNNER_TEMP + \\"/tool-env.json\\", JSON.stringify(process.env));");
  }
}
fs.mkdirSync("node_modules/.bin", { recursive: true });
fs.writeFileSync("node_modules/.bin/tsgolint", "#!/bin/sh\\n");
if (mode === "symlink") {
  const target = path.join(process.env.RUNNER_TEMP, "outside");
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, "package.json"), JSON.stringify({ name: "x", version: lock.packages["node_modules/" + process.env.FAKE_TARGET].version }));
  fs.rmSync("node_modules/" + process.env.FAKE_TARGET, { recursive: true });
  fs.symlinkSync(target, "node_modules/" + process.env.FAKE_TARGET);
}
fs.writeFileSync("node_modules/.package-lock.json", JSON.stringify(hidden));
' "$mode"
`);
  chmodSync(join(bin, 'node'), 0o755);
  chmodSync(join(bin, 'npm'), 0o755);
  return bin;
}
const withNode = (env: Record<string, string>, bin: string): Record<string, string> => ({ ...env, PATH: `${bin}:${process.env.PATH ?? FIXED_PATH}` });

describe('R-A: npm checkers install from pipegen\'s closure lock (DECISIONS #107)', () => {
  const c = ctxFor([service({ name: 'app', path: '.', runtimeVersion: '>=18 <21' })]);
  const r = render('eslint', { service: 'app' }, c);

  it('layout: setup-node, then ONE step that installs from the closure into a fresh folder, checks it and runs; no npx anywhere, nothing read from the repo\'s lockfile or .npmrc', () => {
    expect(r.steps).toHaveLength(2);
    expect(r.steps[0]?.uses).toMatch(/^actions\/setup-node@/);
    expect(r.steps[0]?.with).toMatchObject({ 'node-version': '22' });
    const all = r.steps.map((s) => s.run ?? '').join('\n');
    expect(all).not.toMatch(/npx/);
    expect(all).not.toMatch(/package-lock\.json[^"]*"\$PWD|\.\/package-lock|\.\/\.npmrc|node_modules\/\.bin/);
    const install = r.steps[1] as RenderedStep;
    expect(install.env?.PIPEGEN_NPM_LOCK).toBe(JSON.stringify(JSON.parse(closureText('eslint'))));
    const pkg = JSON.parse(install.env?.PIPEGEN_NPM_PACKAGE as string) as { dependencies: Record<string, string>; private: boolean };
    expect(pkg.dependencies).toEqual(closureRootDependencies(closureText('eslint')));
    expect(pkg.private).toBe(true);
    expect(install.run).toContain('npmdir="$RUNNER_TEMP/pipegen-npm/pipegen-out-lint--app"');
    expect(install.run).toContain('mkdir "$npmdir"');
    expect(install.run).toContain("printf '%s' \"$PIPEGEN_NPM_LOCK\" > \"$npmdir/package-lock.json\"");
    expect(install.run).toContain('cd -- "$npmdir"');
    expect(install.run).toContain('ci --ignore-scripts --no-audit --no-fund --userconfig "$npmdir/user.npmrc" --globalconfig "$npmdir/global.npmrc" --workspaces=false --registry=https://registry.npmjs.org/');
    expect(install.run).toContain(': > "$npmdir/.npmrc"');
  });

  it('run: node on the reviewed bin file inside the isolated folder, cwd the service folder, under env -i', () => {
    const run = lastRun(r).run as string;
    expect(run).toContain('"$nodebin/node" "$npmdir/node_modules/eslint/bin/eslint.js"');
    expect(run).toContain('/usr/bin/env -i');
    expect(run).not.toContain('npx');
    expect(lastRun(r).id).toMatch(/^checker-run-[0-9a-f]{16}$/);
    expect(r.steps[1]).toBe(lastRun(r));
  });

  it('every checker uses its own reviewed bin; the configs that import a plugin are written into the isolated folder (eslint-typescript now renders)', () => {
    for (const [id, bin] of [['biome', '@biomejs/biome/bin/biome'], ['oxlint-typeaware', 'oxlint/bin/oxlint'], ['prettier', 'prettier/bin/prettier.cjs'], ['knip', 'knip/bin/knip.js'], ['eslint-typescript', 'eslint/bin/eslint.js']]) {
      expect(lastRun(render(id)).run, id).toContain(`"$nodebin/node" "$npmdir/node_modules/${bin}"`);
    }
    const ts = lastRun(render('eslint-typescript')).run as string;
    expect(ts).toContain("printf '%s' \"$PIPEGEN_CONFIG\" > \"$npmdir/eslint.config.mjs\"");
    expect(ts).toContain('--config "$npmdir/eslint.config.mjs"');
    expect(lastRun(render('eslint-typescript')).env?.PIPEGEN_CONFIG).toContain("import tseslint from 'typescript-eslint'");
  });

  it2('install: runs npm ci in the isolated folder with the closure, empty configs and the registry on the command line; a repo .npmrc and lockfile beside the service are not used', () => {
    const sb = sandbox();
    const bin = fakeNodeDir(sb, 22);
    // hostile repo files in the service folder (the workspace root here)
    writeFileSync(join(sb.ws, '.npmrc'), 'node-options=--require=./evil.js\n');
    writeFileSync(join(sb.ws, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/eslint': { link: true, resolved: 'vendor/eslint' } } }));
    const install = r.steps[1] as RenderedStep;
    const res = exec(install, sb, withNode(stepEnv(install, sb), bin));
    expect(res.status, res.stderr).toBe(0);
    const cwd = readFileSync(join(sb.rt, 'npm-cwd.txt'), 'utf8').trim();
    expect(cwd).toBe(join(sb.rt, 'pipegen-npm', 'pipegen-out-lint--app'));
    const args = readFileSync(join(sb.rt, 'npm-args.bin'), 'utf8').split('\0').slice(0, -1);
    expect(args.slice(0, 4)).toEqual(['ci', '--ignore-scripts', '--no-audit', '--no-fund']);
    expect(args).toContain('--registry=https://registry.npmjs.org/');
    expect(args[args.indexOf('--userconfig') + 1]).toBe(join(cwd, 'user.npmrc'));
    expect(args[args.indexOf('--globalconfig') + 1]).toBe(join(cwd, 'global.npmrc'));
    expect(readFileSync(join(cwd, 'package-lock.json'), 'utf8')).toBe(install.env?.PIPEGEN_NPM_LOCK);
    expect(readFileSync(join(cwd, '.npmrc'), 'utf8')).toBe('');
    // the tool the npm "installed" is the pinned one, in the isolated folder, not under the workspace
    expect(existsSync(join(cwd, 'node_modules', 'eslint', 'package.json'))).toBe(true);
    expect(existsSync(join(sb.ws, 'node_modules'))).toBe(false);
    const envNames = readFileSync(join(sb.rt, 'npm-env.txt'), 'utf8').split('\n').map((l) => l.split('=')[0]).filter((n) => /^[A-Za-z_]/.test(n ?? ''));
    expect(envNames).not.toContain('PIPEGEN_NPM_LOCK');
  });

  it2('verify and run are one step: a tool that is a symlink or at another version fails it before the tool starts; a failing npm fails the install', () => {
    const run = lastRun(r);
    const target = expectedPins(entry('eslint'))[0]?.name as string;
    for (const mode of ['symlink', 'wrong-version', 'fail']) {
      const sb = sandbox();
      const bin = fakeNodeDir(sb, 22);
      writeFileSync(join(sb.rt, 'fake-mode'), mode);
      writeFileSync(join(sb.rt, 'fake-target'), target);
      expect(exec(run, sb, withNode(stepEnv(run, sb), bin)).status, mode).not.toBe(0);
      expect(existsSync(join(sb.rt, 'tool-ran')), `${mode}: the tool must not have started`).toBe(false);
    }
    const ok = sandbox();
    const bin = fakeNodeDir(ok, 22);
    const res = exec(run, ok, withNode(stepEnv(run, ok), bin));
    expect(res.status, res.stderr).toBe(0);
    expect(existsSync(join(ok.rt, 'tool-ran'))).toBe(true);
  });

  it2('after the check the install tree is made read-only (no write bits), and the config was written before that', () => {
    const run = lastRun(r);
    expect(run.run).toContain('chmod -R a-w "$npmdir"');
    expect((run.run as string).indexOf('eslint.config.mjs')).toBeLessThan((run.run as string).indexOf('chmod -R a-w'));
    expect((run.run as string).indexOf('-e "$js"')).toBeLessThan((run.run as string).indexOf('chmod -R a-w'));
    const sb = sandbox();
    const bin = fakeNodeDir(sb, 22);
    expect(exec(run, sb, withNode(stepEnv(run, sb), bin)).status).toBe(0);
    const dir = join(sb.rt, 'pipegen-npm', 'pipegen-out-lint--app');
    for (const f of [join(dir, 'node_modules', 'eslint', 'package.json'), join(dir, 'node_modules', 'eslint', 'bin', 'eslint.js'), join(dir, 'eslint.config.mjs')]) {
      expect(statSync(f).mode & 0o222, f).toBe(0);
    }
    expect(statSync(join(dir, 'node_modules', 'eslint')).mode & 0o222).toBe(0);
  });

  it2('node: a node of another major than setup-node was asked for (a poisoned PATH) fails every node step', () => {
    for (const step of [lastRun(r)]) {
      const sb = sandbox();
      const bin = fakeNodeDir(sb, 20);
      const res = exec(step, sb, withNode(stepEnv(step, sb), bin));
      expect(res.status).not.toBe(0);
      expect(res.stderr).toMatch(/node/);
    }
  });

  it('a malformed closure refuses the render (injected closure that is not a registry lock)', () => {
    const t = entry('eslint');
    const bad = JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { eslint: t.step.cli?.install.version } } } });
    expect(() => renderStepWith(spec(t), t, platform(), ctx, { npmClosures: { eslint: bad } })).toThrow(/closure/);
  });
});

describe('R-A: npm tools that run the repo\'s code (vitest, c8) keep the repo install, guarded', () => {
  const c = ctxFor([service({ name: 'app', path: '.', runtimeVersion: '24' })]);
  const choices = { 'coverage-thresholds-lines': '80' };
  const r = render('vitest-coverage', { service: 'app', choices }, c);

  it('layout: setup-node, pre-check + npm ci with the registry on the command line, a verify step, then node on the bin; the run step is marked as a repo-code step', () => {
    expect(r.steps).toHaveLength(4);
    expect(r.steps[1]?.id).toMatch(hash16);
    expect(r.steps[1]?.run).toContain('--registry=https://registry.npmjs.org/');
    expect(r.steps[1]?.run).toContain('ci --ignore-scripts');
    expect(r.steps.map((s) => s.run ?? '').join('\n')).not.toMatch(/npx/);
    expect(lastRun(r).run).toContain('"$nodebin/node" "$PWD/node_modules/vitest/vitest.mjs" run');
    expect(lastRun(r).id).toMatch(REPO_CODE_STEP_ID_RE);
    // a checker that only reads code is not marked (its id is checker-run-…)
    expect(lastRun(render('biome')).id).toMatch(/^checker-run-/);
  });

  it2('pre-check: a shrinkwrap, a link, an alias or a non-registry source for the tool or a plugin, or a non-sha512 integrity fails BEFORE npm ci runs', () => {
    const pins = expectedPins(entry('vitest-coverage'));
    const good = (): { lockfileVersion: number; packages: Record<string, Record<string, unknown>> } => {
      const packages: Record<string, Record<string, unknown>> = { '': {} };
      for (const p of pins) packages[`node_modules/${p.name}`] = { version: p.version, resolved: `https://registry.npmjs.org/${p.name}/-/${p.name.split('/').pop()}-${p.version}.tgz`, integrity: p.integrity };
      return { lockfileVersion: 3, packages };
    };
    const step = r.steps[1] as RenderedStep;
    const attempt = (edit: (l: ReturnType<typeof good>, ws: string) => void) => {
      const sb = sandbox();
      const bin = fakeNodeDir(sb, 24);
      const lock = good();
      edit(lock, sb.ws);
      writeFileSync(join(sb.ws, 'package-lock.json'), JSON.stringify(lock));
      const res = exec(step, sb, withNode(stepEnv(step, sb), bin));
      return { res, npmRan: existsSync(join(sb.rt, 'npm-args.bin')), sb };
    };
    const tool = `node_modules/${pins[0]?.name}`;
    const plugin = `node_modules/${pins[1]?.name}`;
    const cases: [string, (l: ReturnType<typeof good>, ws: string) => void][] = [
      ['shrinkwrap', (_l, ws) => writeFileSync(join(ws, 'npm-shrinkwrap.json'), '{}')],
      ['link on the tool', (l) => { (l.packages[tool] as Record<string, unknown>).link = true; }],
      ['link on a plugin', (l) => { (l.packages[plugin] as Record<string, unknown>).link = true; }],
      ['file: resolved', (l) => { (l.packages[tool] as Record<string, unknown>).resolved = 'file:../vendor/vitest'; }],
      ['alias (registry url of another package)', (l) => { (l.packages[plugin] as Record<string, unknown>).resolved = 'https://registry.npmjs.org/evil/-/evil-1.0.0.tgz'; }],
      ['git resolved', (l) => { (l.packages[tool] as Record<string, unknown>).resolved = 'git+https://github.com/a/b.git#abc'; }],
      ['sha1 integrity', (l) => { (l.packages[tool] as Record<string, unknown>).integrity = 'sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA='; }],
      ['another version', (l) => { (l.packages[tool] as Record<string, unknown>).version = '9.9.9'; }],
      ['a tool missing', (l) => { delete l.packages[tool]; }],
    ];
    for (const [why, edit] of cases) {
      const a = attempt(edit);
      expect(a.res.status, why).not.toBe(0);
      expect(a.npmRan, `${why}: npm must not have run`).toBe(false);
    }
    // the honest lockfile passes: npm ci runs with the registry on the command line, and the marker is written
    const ok = attempt(() => {});
    expect(ok.res.status, ok.res.stderr).toBe(0);
    const args = readFileSync(join(ok.sb.rt, 'npm-args.bin'), 'utf8').split('\0').slice(0, -1);
    expect(args).toContain('--registry=https://registry.npmjs.org/');
    expect(args).toContain('--ignore-scripts');
    expect(existsSync(join(ok.sb.rt, 'pipegen-npm-ci', (r.steps[1]?.id as string).replace('pipegen-npm-ci-', '')))).toBe(true);
  });

  it2('verify: needs the marker of its own npm ci, a real folder under the service\'s node_modules, the exact version and the registry entry', () => {
    const ci = r.steps[1] as RenderedStep;
    const verify = r.steps[2] as RenderedStep;
    const pins = expectedPins(entry('vitest-coverage'));
    const setup = (): { sb: Sandbox; bin: string } => {
      const sb = sandbox();
      const bin = fakeNodeDir(sb, 24);
      const packages: Record<string, Record<string, unknown>> = { '': {} };
      for (const p of pins) packages[`node_modules/${p.name}`] = { version: p.version, resolved: `https://registry.npmjs.org/${p.name}/-/${p.name.split('/').pop()}-${p.version}.tgz`, integrity: p.integrity };
      writeFileSync(join(sb.ws, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
      return { sb, bin };
    };
    const target = pins[0]?.name as string;
    // no marker: fails
    const a = setup();
    expect(exec(verify, a.sb, withNode(stepEnv(verify, a.sb), a.bin)).status).not.toBe(0);
    // ci then verify: passes
    const b = setup();
    expect(exec(ci, b.sb, withNode(stepEnv(ci, b.sb), b.bin)).status).toBe(0);
    expect(exec(verify, b.sb, withNode(stepEnv(verify, b.sb), b.bin)).status).toBe(0);
    // a symlinked tool folder, and another version
    for (const mode of ['symlink', 'wrong-version']) {
      const x = setup();
      writeFileSync(join(x.sb.rt, 'fake-mode'), mode);
      writeFileSync(join(x.sb.rt, 'fake-target'), target);
      exec(ci, x.sb, withNode(stepEnv(ci, x.sb), x.bin));
      expect(exec(verify, x.sb, withNode(stepEnv(verify, x.sb), x.bin)).status, mode).not.toBe(0);
    }
  });
});

describe('R-B: dedupe is injective, one Node version per job', () => {
  const at = (path: string) => render('vitest-coverage', { service: 'x', workingDir: path }, ctxFor([service({ name: 'x', path })]));

  it('folders a/b and a-b keep two npm ci steps (a hash, not a slug); the same folder spelled two ways keeps one', () => {
    const all = dedupeJobSteps([...at('a/b').steps, ...at('a-b').steps]);
    expect(all.filter((s) => s.run?.includes('ci --ignore-scripts'))).toHaveLength(2);
    expect(at('a/b').steps[1]?.id).toMatch(hash16);
    expect(at('a/b').steps[1]?.id).not.toBe(at('a-b').steps[1]?.id);
    const same = dedupeJobSteps([...at('a/b').steps, ...at('./a//b').steps]);
    expect(same.filter((s) => s.run?.includes('ci --ignore-scripts'))).toHaveLength(1);
  });

  it('run steps are never dropped by the dedupe (they carry a repocode id, not a pipegen- id)', () => {
    const all = dedupeJobSteps([...at('a').steps, ...at('a').steps]);
    expect(all.filter((s) => s.id?.startsWith('repocode-'))).toHaveLength(2);
  });

  it('two different Node majors in one job are a RenderError (Plan G splits the job)', () => {
    const one = render('prettier', { service: 'a' }, ctxFor([service({ name: 'a', path: '.', runtimeVersion: '22' })])).steps;
    const two = render('knip', { service: 'b' }, ctxFor([service({ name: 'b', path: '.', runtimeVersion: '26' })])).steps;
    expect(() => dedupeJobSteps([...one, ...two])).toThrow(RenderError);
    const same = render('knip', { service: 'b' }, ctxFor([service({ name: 'b', path: '.', runtimeVersion: '22' })])).steps;
    expect(dedupeJobSteps([...one, ...same]).filter((s) => s.uses?.startsWith('actions/setup-node@'))).toHaveLength(1);
  });
});

describe('R-C: the pip install does not import the repo', () => {
  const closure = (t: ReviewedTool): string => `${t.step.cli?.install.package}==${t.step.cli?.install.version} --hash=sha256:${'a'.repeat(64)}\n`;
  it2('python runs isolated (-I) from runner temp, with isolated pip, binary wheels only', () => {
    const t = entry('mypy');
    const r = renderStepWith(spec(t), t, platform(), ctx, { pipClosures: { mypy: closure(t) } });
    const install = r.steps[1] as RenderedStep;
    expect(install.run).toContain('cd "$RUNNER_TEMP"');
    expect(install.run).toContain('"$py" -I -m venv "$venv"');
    expect(install.run).toContain('-I -m pip install --isolated --no-input --only-binary=:all: --require-hashes --no-deps --no-cache-dir --disable-pip-version-check -r ');
    // run it with a stand-in python3 and a workspace that holds a venv.py and a pip/ folder
    const sb = sandbox();
    writeFileSync(join(sb.ws, 'venv.py'), 'raise SystemExit("PWNED")');
    mkdirSync(join(sb.ws, 'pip'));
    const bin = join(sb.dir, 'pybin');
    mkdirSync(bin);
    const py = join(bin, 'python3');
    writeFileSync(py, `#!/bin/sh\necho "$(pwd) @ $*" >> "$RUNNER_TEMP/py-calls.txt"\nif [ "$1 $2 $3" = "-I -m venv" ]; then mkdir -p "$4/bin"; cp "$0" "$4/bin/python"; fi\nexit 0\n`);
    chmodSync(py, 0o755);
    const res = exec(install, sb, { ...stepEnv(install, sb), PATH: `${bin}:${process.env.PATH ?? FIXED_PATH}` });
    expect(res.status, res.stderr).toBe(0);
    const calls = readFileSync(join(sb.rt, 'py-calls.txt'), 'utf8').trim().split('\n');
    expect(calls).toHaveLength(2);
    for (const line of calls) {
      expect(line.startsWith(`${sb.rt} @ -I -m `), line).toBe(true); // cwd is runner temp, never the workspace
    }
  });
});

describe('R-D: DAST steps (and only those) may use the host network', () => {
  const dastOnly = withPolicy('zap-baseline', ['slots']);

  it('zap: --network host, no --user override, a fresh work folder made world-writable, no repo mount, no -e, no secrets', () => {
    const t = entry('zap-baseline');
    const r = renderStepWith(spec(t), t, platform(), ctx, dastOnly);
    const run = lastRun(r).run as string;
    expect(run).toContain('--network host');
    expect(run).not.toContain('--user');
    expect(run).toContain('chmod 0777 "$work"');
    expect(run).not.toMatch(/-v "\$PWD/);
    expect(run).not.toMatch(/ -e [A-Z_]+ /);
    for (const bad of ['--privileged', 'docker.sock', '--pid host', '--cap-add']) expect(run, bad).not.toContain(bad);
    const c = ctxFor([service({ name: 'app', path: '.', envVars: ['STRIPE_KEY'] })]);
    expect(() => renderStepWith(withNames(spec(t, { service: 'app' }), ['STRIPE_KEY']), t, platform(), c, dastOnly)).toThrow(/run the app|scanner/);
  });

  it('every other docker step keeps the S26 rule: asking for host networking is refused, with or without the DAST mount', () => {
    const t = entry('zap-baseline');
    t.categories = ['sast'];
    expect(() => renderStepWith(spec(t), t, platform(), ctx, withPolicy('zap-baseline', ['slots', 'asImageUser'], { network: 'host' }))).toThrow(/host/);
    // a DAST step with a repo mount is refused too
    const d = entry('zap-baseline');
    expect(() => renderStepWith(spec(d), d, platform(), ctx, withPolicy('zap-baseline', ['slots'], { mount: { at: '/src', source: 'repo' } }))).toThrow(/host|work/);
    // the plain docker rule
    const plain = renderStepWith(spec(d), d, platform(), ctx, withPolicy('zap-baseline', ['slots', 'network', 'asImageUser']));
    expect(lastRun(plain).run).toContain('--user "$(id -u):$(id -g)"');
    expect(lastRun(plain).run).not.toContain('--network');
  });
});

describe('R-E (6c): the tools that wait for a target now render with one; the permanent refusals say why', () => {
  it('cosign and gosec are refused for good; trivy-image, syft, zap-baseline, nuclei, semgrep render with a target', () => {
    for (const [id, why] of [['cosign', /Plan G's sign job/], ['gosec', /Go is not supported in v0\.2/]] as const) expect(() => render(id), id).toThrow(why);
    for (const id of ['trivy-image', 'syft', 'zap-baseline', 'nuclei', 'semgrep']) expect(() => render(id), id).not.toThrow();
  });

  it('the rest of the github-release and npm tools still render', () => {
    for (const id of ['trivy-config', 'trivy-licence', 'betterleaks', 'gitleaks', 'osv-scanner', 'actionlint', 'zizmor', 'jscpd', 'pinact', 'poutine', 'ruff', 'ruff-format', 'lefthook']) expect(() => render(id), id).not.toThrow();
  });
});

describe('R-F: hardening (findings 6, 8, 9, 10)', () => {
  it('6: the system tools of the install and pull steps run under env -i with a fixed PATH; CDPATH is unset; cd uses ./; node is found before PATH is fixed and checked for its major', () => {
    const install = render('trivy-config').steps[0]?.run as string;
    for (const tool of ['curl', 'tar', 'find', 'sha256sum']) expect(install, tool).toMatch(new RegExp(`"\\$\\{sys\\[@\\]\\}" ${tool} `));
    expect(install).toContain('unset CDPATH');
    expect(install).toMatch(/sys=\(\n {2}\/usr\/bin\/env -i\n {2}"PATH=\/usr\/local\/sbin/);
    expect((render('osv-scanner').steps[0]?.run as string)).toContain('"${sys[@]}" sha256sum');
    const zap = renderStepWith(spec(entry('zap-baseline')), entry('zap-baseline'), platform(), ctx, withPolicy('zap-baseline', ['slots']));
    expect(zap.steps[0]?.run).toContain('"${sys[@]}" /usr/bin/docker pull');
    const wd = render('ruff', { service: 'api', workingDir: 'services/api' }, ctxFor([service({ name: 'api', path: 'services/api' })]));
    expect(lastRun(wd).run).toContain('cd -- ./services/api');
    const node = lastRun(render('eslint')).run as string;
    expect(node).not.toContain('dirname');
    expect(node.indexOf('command -v node')).toBeLessThan(node.indexOf('PATH=/usr/local/sbin'));
    expect(node).toContain('--version');
  });

  it2('6: a CDPATH in the environment does not redirect the cd into the service folder', () => {
    const c = ctxFor([service({ name: 'api', path: 'a/b' })]);
    const step = lastRun(render('ruff', { service: 'api', workingDir: 'a/b' }, c));
    const sb = sandbox();
    mkdirSync(join(sb.ws, 'a', 'b'), { recursive: true });
    mkdirSync(join(sb.dir, 'decoy', 'a', 'b'), { recursive: true });
    mkdirSync(join(sb.ws, 'decoy-link'), { recursive: true });
    fakeTool(sb, 'pipegen-out-lint--api', 'ruff', "echo '{}' > ./ruff.sarif");
    const res = exec(step, sb, stepEnv(step, sb, {}, { CDPATH: join(sb.dir, 'decoy') }));
    expect(res.status, res.stderr).toBe(0);
    expect(existsSync(join(sb.ws, 'a', 'b', 'argv.bin'))).toBe(true);
    expect(existsSync(join(sb.dir, 'decoy', 'a', 'b', 'argv.bin'))).toBe(false);
  });

  it('8: renderStep has four parameters (the policy hook is renderStepWith, for tests); the executable must be the reviewed command[0]', () => {
    expect(renderStep.length).toBe(4);
    const t = entry('ruff');
    (t.step.cli as { command: string[] }).command[0] = 'evil';
    expect(() => renderStep(spec(t), t, platform(), ctx)).toThrow(/executable|command/);
  });

  it('9: a follow-up command that runs another executable is refused; the moved result is checked again where it lands', () => {
    const t = entry('coverage-py');
    (t.step.cli as { then: string[][] }).then = [['sh', 'report', '--fail-under={fail-under}']];
    const closureText2 = 'coverage==7.16.2 --hash=sha256:' + 'a'.repeat(64) + '\n';
    expect(() => renderStepWith(spec(t), t, platform(), ctx, { pipClosures: { 'coverage-py': closureText2 } })).toThrow(/follow-up/);
    const run = lastRun(render('trivy-config')).run as string;
    expect(run).toContain('dest="$RUNNER_TEMP/pipegen-raw/pipegen-out-iac/trivy-config.sarif"');
    expect(run).toContain('[ -f "$dest" ] && [ ! -L "$dest" ]');
  });

  it('10: the steps are named after the reviewed executable, and the shared helpers live in the leaf module', async () => {
    const { own, EXPR, refuse } = await import('../src/engine/render-error.js');
    expect(own({ a: 1 }, 'a')).toBe(1);
    expect(own({ a: 1 }, 'toString')).toBeUndefined();
    expect(EXPR).toBe('${{');
    expect(() => refuse('x')).toThrow(RenderError);
    expect(lastRun(render('eslint')).name).toBe('pipegen: run eslint');
  });
});

describe('R-A: the unchanged checker data is what the policies say', () => {
  it('a fixture closure and a different Node major are the only things a checker render depends on', () => {
    expect(spawnSync('bash', ['-n'], { input: lastRun(render('knip')).run as string }).status).toBe(0);
    for (const s of render('knip').steps) if (s.run !== undefined) expect(spawnSync('bash', ['-n'], { input: s.run }).status).toBe(0);
  });
});

describe('round 2: prettier and knip load repo config (ruling 1)', () => {
  it('their run step is marked as a repo-code step, runsRepoCode says so, and they still install from their closure', () => {
    for (const id of ['prettier', 'knip']) {
      expect(ARGV_POLICIES[id]?.loadsRepoConfig, id).toBe(true);
      expect(runsRepoCode(id), id).toBe(true);
      const r = render(id);
      expect(lastRun(r).id, id).toMatch(REPO_CODE_STEP_ID_RE);
      expect(r.steps[1]?.env?.PIPEGEN_NPM_LOCK, id).toBeDefined(); // the closure install is kept
    }
  });

  it('every npm policy that neither runs repo code nor loads repo config has a pinned config passed by flag', () => {
    const offenders: string[] = [];
    for (const [id, pol] of Object.entries(ARGV_POLICIES)) {
      if (pol.method !== 'npm' || pol.runsRepoCode === true || pol.loadsRepoConfig === true) continue;
      if (pol.config === undefined || !/^-{1,2}[a-z-]+$/.test(pol.config.flag)) offenders.push(id);
    }
    expect(offenders).toEqual([]);
  });
});

describe('round 2: oxlint finds the closure\'s tsgolint, never the repo\'s (ruling 2)', () => {
  it('the run step sets OXLINT_TSGOLINT_PATH to the closure folder\'s tsgolint and passes it through the allowlist', () => {
    const run = lastRun(render('oxlint-typeaware')).run as string;
    expect(run).toContain('OXLINT_TSGOLINT_PATH="$npmdir/node_modules/.bin/tsgolint"');
    expect(run).toContain('"OXLINT_TSGOLINT_PATH=$OXLINT_TSGOLINT_PATH"');
    expect(lastRun(render('eslint')).run).not.toContain('OXLINT_TSGOLINT_PATH');
  });

  it2('the tool starts with that variable set (and nothing else from the allowlist is added)', () => {
    const r = render('oxlint-typeaware');
    const sb = sandbox();
    const bin = fakeNodeDir(sb, 24);
    for (const step of [lastRun(r)]) {
      const res = exec(step, sb, withNode(stepEnv(step, sb), bin));
      expect(res.status, res.stderr).toBe(0);
    }
    const env = JSON.parse(readFileSync(join(sb.rt, 'tool-env.json'), 'utf8')) as Record<string, string>;
    expect(env.OXLINT_TSGOLINT_PATH).toBe(join(sb.rt, 'pipegen-npm', 'pipegen-out-lint', 'node_modules', '.bin', 'tsgolint'));
    expect(Object.keys(env).filter((n) => n !== 'PWD').sort()).toEqual(['HOME', 'OXLINT_TSGOLINT_PATH', 'PATH', 'RUNNER_TEMP', 'TMPDIR']);   // PWD is added by the stand-in's own shell
  });
});

describe('round 2: npm ci never walks up to a parent workspace (ruling 3)', () => {
  it2('both npm ci commands carry --workspaces=false', () => {
    const sb = sandbox();
    const bin = fakeNodeDir(sb, 24);
    const checker = render('eslint');
    const installC = checker.steps[1] as RenderedStep;
    expect(installC.run).toContain('--workspaces=false');
    // a parent folder that is a workspace root with its own .npmrc and package.json
    writeFileSync(join(sb.rt, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['pipegen-npm/*'] }));
    writeFileSync(join(sb.rt, '.npmrc'), 'git=./evilgit.sh\n');
    expect(exec(installC, sb, withNode(stepEnv(installC, sb), bin)).status).toBe(0);
    expect(readFileSync(join(sb.rt, 'npm-args.bin'), 'utf8').split('\0')).toContain('--workspaces=false');
    const repo = render('vitest-coverage', { choices: { 'coverage-thresholds-lines': '80' } });
    expect(repo.steps[1]?.run).toContain('--workspaces=false');
  });
});

describe('round 2: lock size and order (rulings 5 and 7)', () => {
  it('a closure whose compact JSON is over 120 KiB is refused', () => {
    const t = entry('eslint');
    const big = JSON.parse(closureText('eslint')) as { packages: Record<string, Record<string, unknown>> };
    (big.packages['node_modules/eslint'] as Record<string, unknown>).description = 'x'.repeat(130 * 1024);
    expect(() => renderStepWith(spec(t), t, platform(), ctx, { npmClosures: { eslint: JSON.stringify(big) } })).toThrow(/too large/);
    const fine = JSON.parse(closureText('eslint')) as { packages: Record<string, Record<string, unknown>> };
    (fine.packages['node_modules/eslint'] as Record<string, unknown>).description = 'x'.repeat(10 * 1024);
    expect(() => renderStepWith(spec(t), t, platform(), ctx, { npmClosures: { eslint: JSON.stringify(fine) } })).not.toThrow();
  });

  it2('a finished result folder is read-only', () => {
    const run = lastRun(render('trivy-config'));
    expect(run.run).toContain('chmod -R a-w "$RUNNER_TEMP/pipegen-raw/pipegen-out-iac"');
    const sb = sandbox();
    fakeTool(sb, 'pipegen-out-iac', 'trivy', "echo '{}' > ./trivy-config.sarif");
    expect(exec(run, sb, stepEnv(run, sb)).status).toBe(0);
    const f = join(sb.rt, 'pipegen-raw', 'pipegen-out-iac', 'trivy-config.sarif');
    expect(statSync(f).mode & 0o222).toBe(0);
    expect(statSync(join(sb.rt, 'pipegen-raw', 'pipegen-out-iac')).mode & 0o222).toBe(0);
  });

  const projectScript: RenderedStep = { id: 'repocode-0123456789abcdef', name: 'project script', run: 'npm test' };
  const upload: RenderedStep = { name: 'Upload', uses: `actions/upload-artifact@${'a'.repeat(40)}` };

  it('checkJobOrder: [project-script, eslint] is refused, [eslint, project-script] passes', () => {
    const eslint = render('eslint').steps;
    expect(checkJobOrder([projectScript, ...eslint]).join(' ')).toMatch(/repo-code step/);
    expect(checkJobOrder([...eslint, projectScript])).toEqual([]);
  });

  it('checkJobOrder: a repo-code step before a scrub or an upload is refused; the repo-code tools themselves (vitest, prettier) count', () => {
    const scrub = renderScrub('pipegen-out-secrets', '${{ runner.temp }}/pipegen-raw/pipegen-out-secrets/gitleaks.sarif', 'gitleaks', 'sarif', gateEntry());
    expect(checkJobOrder([projectScript, scrub])).not.toEqual([]);
    expect(checkJobOrder([projectScript, upload])).not.toEqual([]);
    expect(checkJobOrder([scrub, upload, projectScript])).toEqual([]);
    const vitest = render('vitest-coverage').steps;
    expect(checkJobOrder([...vitest, ...render('biome').steps]).length).toBeGreaterThan(0);
    expect(checkJobOrder([...render('biome').steps, ...vitest])).toEqual([]);
    const prettier = render('prettier').steps;
    expect(checkJobOrder([...prettier, ...render('biome').steps]).length).toBeGreaterThan(0);
    expect(checkJobOrder([])).toEqual([]);
  });
});
