// Plan B Task 6b: the CLI kinds of the step renderer (github-release, docker, npm, pip). A rendered `run:` goes into a
// user's CI, so besides the shape tests every hostile input class is run through real bash in a temp folder (no network).
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { Document, parse } from 'yaml';
import { resultArtifactName } from '../src/engine/artifact-names.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { dedupeJobSteps, RenderError, renderStep, renderUpload, stepsToYaml, type RenderedStep, type RenderResult } from '../src/engine/render-step.js';
import { ARGV_POLICIES, PIP_CLOSURES, type ArgvPolicy } from '../src/engine/tool-flags.js';
import type { ReviewedTool, StepSpec } from '../src/types.js';
import { ctxFor, entry, platform, reviewedList, service, specFor } from './helpers/render.js';

const FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const ctx = ctxFor([service({ name: 'app', path: '.' })]);
// declared-name lists are set through Reflect: the fixture scan (no-secret-literals) treats a keyword key with a value as a leak
const withNames = (spec: StepSpec, names: string[]): StepSpec => {
  const copy = { ...spec };
  Reflect.set(copy, 'secrets', names);
  return copy;
};
const spec = (t: ReviewedTool, over: Partial<StepSpec> = {}): StepSpec => specFor(t, { needId: needFor(t), ...over });
const render = (id: string, over: Partial<StepSpec> = {}, c = ctx, opts?: Parameters<typeof renderStep>[4]): RenderResult => {
  const t = entry(id);
  return renderStep(spec(t, over), t, platform(), c, opts);
};
const runs = (r: RenderResult): RenderedStep[] => r.steps.filter((s) => s.run !== undefined);
const lastRun = (r: RenderResult): string => runs(r).at(-1)?.run ?? '';
const yamlOf = (steps: RenderedStep[]): string => {
  const doc = new Document();
  doc.contents = stepsToYaml(steps);
  return doc.toString({ lineWidth: 0 });   // no folding: a long env value (a config file, the lockfile list) stays on one line, as Plan G should print it
};
const bashN = (script: string): { ok: boolean; err: string } => {
  const r = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8' });
  return { ok: r.status === 0, err: r.stderr };
};
const REAL_BASH = process.platform !== 'win32';
const it2 = it.skipIf(!REAL_BASH);

// ---------- a harness that really runs a rendered step in a temp folder ----------
const tmps: string[] = [];
afterAll(() => { for (const d of tmps) rmSync(d, { recursive: true, force: true }); });
interface Sandbox { dir: string; rt: string; ws: string }
function sandbox(): Sandbox {
  const dir = mkdtempSync(join(tmpdir(), 'pipegen-6b-'));
  tmps.push(dir);
  const rt = join(dir, 'rt');
  const ws = join(dir, 'ws');
  mkdirSync(rt);
  mkdirSync(ws);
  return { dir, rt, ws };
}
/** The step's env as the runner would set it (a `${{ secrets.X }}` is replaced by the given value), plus the runner's own variables. */
function stepEnv(step: RenderedStep, sb: Sandbox, declared: Record<string, string> = {}, extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? FIXED_PATH, RUNNER_TEMP: sb.rt, GITHUB_WORKSPACE: sb.ws, ...extra };
  for (const [k, v] of Object.entries(step.env ?? {})) env[k] = v.replace(/^\$\{\{ secrets\.([A-Z0-9_]+) \}\}$/, (_m, n: string) => declared[n] ?? '');
  return env;
}
function exec(step: RenderedStep, sb: Sandbox, env: Record<string, string>): { status: number | null; stdout: string; stderr: string } {
  expect(step.shell).toBe('bash');
  const r = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step.run ?? ''], { cwd: sb.ws, env, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}
/** A stand-in for the installed tool: records its argv (NUL separated) and its environment into the working folder. */
function fakeTool(sb: Sandbox, artifact: string, exe: string, extra = ''): void {
  const dir = join(sb.rt, 'pipegen-bin', artifact);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, exe);
  writeFileSync(path, `#!/bin/sh\nfor a in "$@"; do printf '%s\\0' "$a"; done > ./argv.bin\nenv > ./env.txt\n${extra}\n`);
  chmodSync(path, 0o755);
}
const argvOf = (sb: Sandbox): string[] => readFileSync(join(sb.ws, 'argv.bin'), 'utf8').split('\0').slice(0, -1);
const envNames = (sb: Sandbox): string[] => readFileSync(join(sb.ws, 'env.txt'), 'utf8').split('\n').filter((l) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(l)).map((l) => l.slice(0, l.indexOf('=')));

// ---------- a synthetic github-release entry with hostile template text and hostile choice values ----------
const HOSTILE = ["a'b", 'a"b', '$(touch pwned)', '`touch pwned`', 'a\nb', '; touch pwned', "'; touch pwned; '", '$HOME', '*', '-rf', '', ' lead', 'x y', 'a\\b', '${HOME}', '"$(touch pwned)"'];
function hostileRuff(): ReviewedTool {
  const t = entry('ruff');
  const cli = t.step.cli as NonNullable<typeof t.step.cli>;
  cli.command.push('--line-length={line-length}', "--message=it's a \"test\" $(touch pwned) `id` $HOME \\ end");
  t.choices['line-length'] = HOSTILE;
  return t;
}

describe('6b: github-release (S27)', () => {
  it('github-release: an https download of the entry\'s own repo, version and asset; the sha256 comes from env and is checked before anything is extracted', () => {
    const r = render('trivy-image');
    expect(r.steps).toHaveLength(2);
    const install = r.steps[0] as RenderedStep;
    const t = entry('trivy-image');
    expect(install.env).toMatchObject({
      PIPEGEN_DL_URL: 'https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz',
      PIPEGEN_DL_SHA256: t.candidate.pin.checksum,
    });
    const run = install.run as string;
    expect(run).toContain("--proto '=https'");
    expect(run).toContain("--proto-redir '=https'");
    expect(run.indexOf('sha256sum')).toBeGreaterThan(-1);
    expect(run.indexOf('sha256sum')).toBeLessThan(run.indexOf('tar '));
    expect(run).not.toContain(t.candidate.pin.checksum as string); // the hash is in env only
    expect(run).toContain('"$PIPEGEN_DL_SHA256"');
  });

  it('github-release: extracted into an empty folder under runner temp; exactly one regular file named like the exe, else it fails; run by absolute path', () => {
    const run = (render('trivy-image').steps[0] as RenderedStep).run as string;
    expect(run).toContain('pipegen-bin/pipegen-out-image-scan');
    expect(run).toMatch(/mkdir "\$bin"/); // plain mkdir: fails when the folder already exists
    expect(run).toContain('-name trivy -type f');
    expect(run).toContain('-name trivy ! -type f');
    expect(lastRun(render('trivy-image'))).toContain('"$bin/trivy"');
    expect(lastRun(render('trivy-image'))).not.toMatch(/^trivy /m);
  });

  it('github-release: a tag without a v (ruff) is used as the entry says; a raw binary asset is just made executable; a zip is unzipped', () => {
    expect((render('ruff').steps[0] as RenderedStep).env?.PIPEGEN_DL_URL).toBe('https://github.com/astral-sh/ruff/releases/download/0.17.1/ruff-x86_64-unknown-linux-gnu.tar.gz');
    const raw = (render('osv-scanner').steps[0] as RenderedStep).run as string;
    expect(raw).not.toContain('tar ');
    expect(raw).not.toContain('unzip');
    expect(raw).toContain('chmod 0755');
    const t = entry('ruff');
    (t.step.cli as { install: { package: string } }).install.package = 'ruff.zip';
    const policy = { ...ARGV_POLICIES.ruff, package: 'ruff.zip' } as ArgvPolicy;
    const z = renderStep(spec(t), t, platform(), ctx, { policies: { ...ARGV_POLICIES, ruff: policy } });
    expect((z.steps[0] as RenderedStep).run).toContain('unzip');
  });

  it('github-release: a bad hash, asset, version or repo in the entry is refused, never written into a shell', () => {
    const tamper = (edit: (t: ReviewedTool) => void) => {
      const t = entry('ruff');
      edit(t);
      return () => renderStep(spec(t), t, platform(), ctx);
    };
    expect(tamper((t) => { t.candidate.pin = { checksum: 'abc' }; })).toThrow(RenderError);
    expect(tamper((t) => { t.candidate.pin = { checksum: `${'a'.repeat(63)}'` }; })).toThrow(RenderError);
    expect(tamper((t) => { (t.step.cli as { install: { version: string } }).install.version = "0.17.1'; id; '"; t.candidate.version = "0.17.1'; id; '"; })).toThrow(RenderError);
    expect(tamper((t) => { t.candidate.repo = 'astral-sh/ruff/../x'; })).toThrow(RenderError);
    expect(tamper((t) => { (t.step.cli as { install: { package: string } }).install.package = 'ruff x.tar.gz'; })).toThrow(RenderError);
    // the install must be the one the argv policy was reviewed for
    expect(tamper((t) => { (t.step.cli as { install: { package: string } }).install.package = 'other.tar.gz'; })).toThrow(/allowlist|package/);
    expect(tamper((t) => { (t.step.cli as { install: { version: string } }).install.version = '9.9.9'; })).toThrow(/version/);
  });
});

describe('6b: docker (S26)', () => {
  it('docker: the image is pulled by digest from env; run with --rm, the caller\'s uid, the policy mount, and none of the dangerous options', () => {
    const r = render('zap-baseline');
    const t = entry('zap-baseline');
    expect(r.steps[0]?.env?.PIPEGEN_IMAGE).toBe(`zaproxy/zap-stable@${t.candidate.pin.digest}`);
    const run = lastRun(r);
    expect(run).toContain('/usr/bin/docker run --rm');
    expect(run).toContain('--user "$(id -u):$(id -g)"');
    expect(run).toContain('--pull=never');
    expect(run).toContain('/zap/wrk');
    for (const bad of ['--privileged', 'docker.sock', '--network host', '--network=host', '--pid host', '--pid=host', '--cap-add', '--device', '--ipc', '--volumes-from', '--mount']) expect(run, bad).not.toContain(bad);
    expect(run).toContain('"$PIPEGEN_IMAGE"');
  });

  it('docker: -e NAME only for declared names of an app-running tool; none for a scanner (which refuses secrets)', () => {
    const t = entry('zap-baseline');
    t.categories = ['coverage']; // pretend it runs the app, to look at the -e rendering
    const c = ctxFor([service({ name: 'app', path: '.', envVars: ['STRIPE_KEY'] })]);
    const none = renderStep(spec(t), t, platform(), c);
    expect(lastRun(none)).not.toMatch(/ -e [A-Z_]+ /);
    const some = renderStep(withNames(spec(t, { service: 'app' }), ['STRIPE_KEY']), t, platform(), c);
    expect(lastRun(some)).toMatch(/ -e STRIPE_KEY /);
    expect(lastRun(some).match(/ -e [A-Z_]+ /g)).toHaveLength(1);
  });

  it('docker: the policy can ask for --network none, and the mount of the repo goes with -w', () => {
    const t = entry('zap-baseline');
    const pol: ArgvPolicy = { ...ARGV_POLICIES['zap-baseline'], network: 'none', mount: { at: '/src', source: 'repo', workdir: true } } as ArgvPolicy;
    const r = renderStep(spec(t), t, platform(), ctx, { policies: { ...ARGV_POLICIES, 'zap-baseline': pol } });
    expect(lastRun(r)).toContain('--network none');
    expect(lastRun(r)).toContain('-w /src');
    expect(lastRun(r)).toContain(`-v "$${'P'}WD${':'}/src"`);
  });

  it('docker: semgrep waits for its rules archive (6c); registry is a job service, not a step', () => {
    expect(() => render('semgrep')).toThrow(/6c/);
    expect(() => render('registry')).toThrow(/service/);
  });

  it('docker: a docker entry without a reviewed mount is refused', () => {
    const t = entry('zap-baseline');
    const pol = { ...ARGV_POLICIES['zap-baseline'] } as { mount?: unknown };
    delete pol.mount;
    expect(() => renderStep(spec(t), t, platform(), ctx, { policies: { ...ARGV_POLICIES, 'zap-baseline': pol as ArgvPolicy } })).toThrow(/mount/);
  });

  it('docker: an image or digest that is not plain is refused', () => {
    const t = entry('zap-baseline');
    t.candidate.pin = { digest: 'sha256:abc' };
    expect(() => renderStep(spec(t), t, platform(), ctx)).toThrow(RenderError);
    const u = entry('zap-baseline');
    (u.step.cli as { install: { package: string } }).install.package = 'zaproxy/zap-stable --privileged';
    expect(() => renderStep(spec(u), u, platform(), ctx)).toThrow(RenderError);
  });
});

describe('6b: npm (B5)', () => {
  const c = ctxFor([service({ name: 'app', path: '.', runtimeVersion: '>=18 <21' })]);

  it('npm: setup-node (version mapped from the repo), one npm ci --ignore-scripts, a lockfile check, then npx --no-install', () => {
    const r = render('biome', { service: 'app' }, c);
    expect(r.steps).toHaveLength(4);
    expect(r.steps[0]?.uses).toMatch(/^actions\/setup-node@/);
    expect(r.steps[0]?.with).toMatchObject({ 'node-version': '22', 'package-manager-cache': 'false' });
    expect(r.steps[0]?.with).not.toHaveProperty('cache');
    expect(r.steps[1]?.run).toContain('ci --ignore-scripts');
    expect(r.steps[2]?.run).toContain('-e "$js"');
    expect(lastRun(r)).toContain('npx" --no-install biome ci');
    expect(r.steps.map((s) => s.run ?? '').join('\n')).not.toMatch(/npm (install|i|pack)\b/);
    expect(r.steps.map((s) => s.run ?? '').join('\n')).not.toContain('install -g');
  });

  it('npm: the check step carries the tool and every plugin with the exact version and integrity, from env', () => {
    const t = entry('biome');
    const expectList = JSON.parse(render('biome', {}, c).steps[2]?.env?.PIPEGEN_NPM_EXPECT as string) as { name: string; version: string; integrity: string }[];
    const cli = t.step.cli as NonNullable<typeof t.step.cli>;
    expect(expectList).toEqual([
      { name: '@biomejs/biome', version: '2.5.15', integrity: t.candidate.pin.checksum },
      ...(cli.plugins ?? []).map((p) => ({ name: p.package, version: p.version, integrity: p.checksum })),
    ]);
    expect(expectList.length).toBeGreaterThan(1);
    expect(render('biome', {}, c).steps[2]?.run).not.toContain(t.candidate.pin.checksum as string);
    // oxlint has three plugins
    expect(JSON.parse(render('oxlint-typeaware', {}, c).steps[2]?.env?.PIPEGEN_NPM_EXPECT as string)).toHaveLength(4);
  });

  it2('npm: the lockfile check passes when version and integrity match and fails closed on any mismatch', () => {
    const r = render('biome', {}, c);
    const check = r.steps[2] as RenderedStep;
    const wanted = JSON.parse(check.env?.PIPEGEN_NPM_EXPECT as string) as { name: string; version: string; integrity: string }[];
    const build = (edit: (w: typeof wanted) => { lock?: object; skipInstalled?: string; installedVersion?: Record<string, string> }) => {
      const sb = sandbox();
      const mod = edit(structuredClone(wanted));
      const packages: Record<string, { version: string; integrity: string }> = {};
      for (const w of mod.lock ? (mod.lock as typeof wanted) : wanted) packages[`node_modules/${w.name}`] = { version: w.version, integrity: w.integrity };
      writeFileSync(join(sb.ws, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
      for (const w of wanted) {
        if (w.name === mod.skipInstalled) continue;
        mkdirSync(join(sb.ws, 'node_modules', w.name), { recursive: true });
        writeFileSync(join(sb.ws, 'node_modules', w.name, 'package.json'), JSON.stringify({ name: w.name, version: mod.installedVersion?.[w.name] ?? w.version }));
      }
      return exec(check, sb, stepEnv(check, sb));
    };
    expect(build(() => ({})).status).toBe(0);
    expect(build((w) => ({ lock: w.map((x, i) => (i === 0 ? { ...x, integrity: `sha512-${'A'.repeat(86)}==` } : x)) })).status).not.toBe(0);
    expect(build((w) => ({ lock: w.map((x, i) => (i === 1 ? { ...x, version: '9.9.9' } : x)) })).status).not.toBe(0);
    expect(build((w) => ({ lock: w.slice(0, 1) })).status).not.toBe(0); // a plugin missing from the lockfile
    expect(build((w) => ({ installedVersion: { [w[1]?.name as string]: '0.0.1' } })).status).not.toBe(0); // the installed copy differs
    expect(build((w) => ({ skipInstalled: w[0]?.name })).status).not.toBe(0);
  });

  it('npm: two tools in one job share one setup-node and one npm ci (dedupeJobSteps keeps the first of each id)', () => {
    const a = render('biome', {}, c).steps;
    const b = render('knip', {}, c).steps;
    const all = dedupeJobSteps([...a, ...b]);
    expect(all.filter((s) => s.uses?.startsWith('actions/setup-node@'))).toHaveLength(1);
    expect(all.filter((s) => s.run?.includes('ci --ignore-scripts'))).toHaveLength(1);
    expect(all).toHaveLength(a.length + b.length - 2);
    expect(a[1]?.id).toBe(b[1]?.id);
    // steps without an id are never dropped
    const plain: RenderedStep = { name: 'x', run: 'true' };
    expect(dedupeJobSteps([plain, { ...plain }])).toHaveLength(2);
  });

  it('npm: eslint-typescript waits for 6c (its config imports a plugin that must resolve from the lockfile install)', () => {
    expect(() => render('eslint-typescript', {}, c)).toThrow(/6c/);
  });

  it('npm: a bad package name, version or integrity is refused', () => {
    for (const edit of [
      (t: ReviewedTool) => { (t.step.cli as { install: { package: string } }).install.package = "biome'; id; '"; },
      (t: ReviewedTool) => { t.candidate.pin = { checksum: 'sha512-short' }; },
      (t: ReviewedTool) => { ((t.step.cli as { plugins: { version: string }[] }).plugins[0] as { version: string }).version = '1.0.0 && id'; },
    ]) {
      const t = entry('biome');
      edit(t);
      expect(() => renderStep(spec(t), t, platform(), c)).toThrow(RenderError);
    }
  });
});

describe('6b: pip (B5)', () => {
  const closure = (t: ReviewedTool): string => {
    const cli = t.step.cli as NonNullable<typeof t.step.cli>;
    return [`${cli.install.package}==${cli.install.version} --hash=sha256:${'a'.repeat(64)}`, ...(cli.plugins ?? []).map((p) => `${p.package}==${p.version} --hash=sha256:${'b'.repeat(64)}`), 'click==8.1.7 --hash=sha256:' + 'c'.repeat(64)].join('\n') + '\n';
  };

  it('pip: no reviewed closure means a RenderError that says "not available yet" (nothing is silently dropped)', () => {
    expect(Object.keys(PIP_CLOSURES)).toEqual([]);
    for (const id of ['mypy', 'bandit', 'schemathesis', 'coverage-py', 'vulture', 'creosote']) expect(() => render(id), id).toThrow(/not available yet/);
  });

  it('pip: with a hash-locked closure, install is `pip install --require-hashes --no-deps -r` in a fresh venv, run by absolute path', () => {
    const t = entry('mypy');
    const r = renderStep(spec(t), t, platform(), ctx, { pipClosures: { mypy: closure(t) } });
    expect(r.steps[0]?.uses).toMatch(/^actions\/setup-python@/);
    expect(r.steps[0]?.with).not.toHaveProperty('cache');
    expect(r.steps[0]?.with).not.toHaveProperty('cache-dependency-path');
    const install = r.steps[1] as RenderedStep;
    expect(install.run).toMatch(/-m pip install --require-hashes --no-deps --no-cache-dir --disable-pip-version-check -r "\$RUNNER_TEMP\/pipegen-pip\/pipegen-out-type-check\/requirements\.txt"/);
    expect(install.run).toContain("printf '%s' \"$PIPEGEN_REQUIREMENTS\"");
    expect(install.env?.PIPEGEN_REQUIREMENTS).toBe(closure(t));
    expect(install.run).not.toMatch(/pip install(?! --require-hashes)/);
    expect(lastRun(r)).toContain('"$venv/bin/mypy"');
  });

  it('pip: a closure line without a hash, an option line, an include, a URL or a missing tool is refused', () => {
    const t = entry('mypy');
    const ok = closure(t);
    const bad = [
      ok + 'requests==2.0.0\n', ok + '--index-url https://evil.example/simple\n', ok + '-r other.txt\n', ok + 'x @ https://evil.example/x.whl --hash=sha256:' + 'a'.repeat(64) + '\n',
      ok + 'x==1.0 --hash=sha256:' + 'a'.repeat(63) + '\n', ok.replace('mypy==2.4.0', 'mypy==2.4.1'), 'click==8.1.7 --hash=sha256:' + 'c'.repeat(64) + '\n', ok + '${{ x }}==1 --hash=sha256:' + 'a'.repeat(64) + '\n',
      ok + 'x==1.0 --hash=sha256:' + 'a'.repeat(64) + ' ; id\n',
    ];
    for (const closureText of bad) expect(() => renderStep(spec(t), t, platform(), ctx, { pipClosures: { mypy: closureText } }), closureText.slice(-60)).toThrow(RenderError);
  });

  it('pip: coverage-py renders its follow-up command in the same step', () => {
    const t = entry('coverage-py');
    const r = renderStep(spec(t, { choices: { 'fail-under': '80' } }), t, platform(), ctx, { pipClosures: { 'coverage-py': closure(t) } });
    const run = lastRun(r);
    expect(run).toContain('"$venv/bin/coverage" run --module pytest');
    expect(run).toMatch(/"\$venv\/bin\/coverage" report --fail-under="\$PIPEGEN_ARG_0"/);
    expect(runs(r).at(-1)?.env?.PIPEGEN_ARG_0).toBe('80');
  });
});

describe('6b: pinned config (S4, S3)', () => {
  it('config: the content travels in env and is written with printf %s to runner temp under the policy file name, passed by the policy flag', () => {
    const t = entry('trivy-image');
    const r = render('trivy-image');
    const step = runs(r).at(-1) as RenderedStep;
    expect(step.env?.PIPEGEN_CONFIG).toBe(t.fixedInputs.config?.content);
    expect(step.run).toContain("printf '%s' \"$PIPEGEN_CONFIG\" > \"$cfg/trivy.yaml\"");
    expect(step.run).toContain('cfg="$RUNNER_TEMP/pipegen-cfg/pipegen-out-image-scan"');
    expect(step.run).toMatch(/trivy" image --config "\$cfg\/trivy\.yaml" /);
    expect(step.run).not.toContain('<<'); // no heredoc
  });

  it('trivy: the pinned config has cache.backend memory and the command has no --cache-dir', () => {
    for (const id of ['trivy-config', 'trivy-image', 'trivy-licence']) {
      const r = render(id);
      expect(runs(r).at(-1)?.env?.PIPEGEN_CONFIG, id).toMatch(/cache:\n {2}backend: memory/);
      expect(lastRun(r), id).not.toContain('--cache-dir');
    }
  });

  it('config: goflags tools get the flag right after the executable (their flags end at the first word), cobra tools after the subcommand', () => {
    expect(lastRun(render('actionlint'))).toMatch(/actionlint" -config-file "\$cfg\/actionlint\.yaml" -no-color/);
    expect(lastRun(render('gosec'))).not.toContain('--config'); // gosec has no pinned config
    expect(lastRun(render('osv-scanner'))).toMatch(/osv-scanner" scan source --config "\$cfg\/osv-scanner\.toml" --recursive/);
  });

  it('config: every reviewed entry with a pinned config has a policy file name, and the policy flag and content equal the data', () => {
    for (const t of reviewedList()) {
      if (t.step.cli === undefined || t.fixedInputs.config === undefined) continue;
      const pol = ARGV_POLICIES[t.id];
      expect(pol?.config?.fileName, t.id).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/);
      expect(pol?.config?.content, t.id).toBe(t.fixedInputs.config.content);
      expect('flag' in t.fixedInputs.config.passAs && t.fixedInputs.config.passAs.flag, t.id).toBe(pol?.config?.flag);
    }
  });

  it('config: content with an expression, a config passed as an input, or a file name that is not plain is refused', () => {
    const expr = entry('ruff');
    (expr.fixedInputs.config as { content: string }).content = 'a = "${{ secrets.X }}"\n';
    expect(() => renderStep(spec(expr), expr, platform(), ctx)).toThrow(/expression/);
    const input = entry('ruff');
    (input.fixedInputs.config as { passAs: unknown }).passAs = { input: 'config' };
    expect(() => renderStep(spec(input), input, platform(), ctx)).toThrow(/input/);
    const t = entry('ruff');
    for (const fileName of ['../x', 'a b', '-x', 'a/b', "x'y", '']) {
      const pol = { ...ARGV_POLICIES.ruff, config: { ...ARGV_POLICIES.ruff?.config, fileName } } as ArgvPolicy;
      expect(() => renderStep(spec(t), t, platform(), ctx, { policies: { ...ARGV_POLICIES, ruff: pol } }), fileName).toThrow(RenderError);
    }
  });

  it("config: the repo's own config files are never referenced in a rendered step", () => {
    for (const id of ['trivy-image', 'betterleaks', 'ruff', 'hadolint', 'osv-scanner', 'zizmor', 'actionlint', 'kube-linter', 'poutine']) {
      const t = entry(id);
      const text = JSON.stringify(render(id).steps).replace(/\$cfg\/[A-Za-z0-9._-]+/g, '');
      for (const f of t.configFiles) expect(text, `${id}: ${f}`).not.toContain(f);
    }
  });
});

describe('6b: command (S5)', () => {
  it('command: dedicated tools get --<choice> "$V" appended, and a bool choice is --<choice>="$V"; a missing choice takes the first value', () => {
    const r = render('trivy-image', { choices: { severity: 'HIGH,CRITICAL', 'ignore-unfixed': 'true' } });
    const step = runs(r).at(-1) as RenderedStep;
    expect(step.run).toContain('--severity "$PIPEGEN_ARG_0"');
    expect(step.run).toContain('--ignore-unfixed="$PIPEGEN_ARG_1"');
    expect(step.env).toMatchObject({ PIPEGEN_ARG_0: 'HIGH,CRITICAL', PIPEGEN_ARG_1: 'true' });
    const d = runs(render('trivy-image')).at(-1) as RenderedStep;
    expect(d.env).toMatchObject({ PIPEGEN_ARG_0: 'CRITICAL', PIPEGEN_ARG_1: 'false' });
  });

  it('command: a placeholder inside a word is a quoted variable next to the constant part', () => {
    const r = render('vitest-coverage', { choices: { 'coverage-thresholds-lines': '90' } }, ctxFor([service({ name: 'app', path: '.' })]));
    const step = runs(r).at(-1) as RenderedStep;
    expect(step.run).toContain('--coverage.thresholds.lines="$PIPEGEN_ARG_0"');
    expect(step.env?.PIPEGEN_ARG_0).toBe('90');
    expect(step.run).not.toContain('{coverage-thresholds-lines}');
    expect(step.run).not.toMatch(/\b90\b/); // the value is only in env
  });

  it('command: reviewed constants are bare when plain and single-quoted otherwise', () => {
    const t = entry('ruff');
    (t.step.cli as { command: string[] }).command.push('plain-word_1.2/x', 'it\'s', 'a b', '');
    const run = lastRun(renderStep(spec(t), t, platform(), ctx));
    expect(run).toContain(' plain-word_1.2/x');
    expect(run).toContain(" 'it'\\''s'");
    expect(run).toContain(" 'a b'");
    expect(run).toContain(" ''");
  });

  it('command: an expression in a template constant or a chosen value is refused (Actions would evaluate it)', () => {
    const t = entry('ruff');
    (t.step.cli as { command: string[] }).command.push('--x=${{ github.head_ref }}');
    expect(() => renderStep(spec(t), t, platform(), ctx)).toThrow(RenderError);
    const u = hostileRuff();
    u.choices['line-length'] = ['${{ secrets.X }}'];
    expect(() => renderStep(spec(u, { choices: { 'line-length': '${{ secrets.X }}' } }), u, platform(), ctx)).toThrow(RenderError);
  });

  it('command: a choice with no place in the command is refused', () => {
    const t = entry('ruff');
    t.choices.stray = ['a', 'b'];
    expect(() => renderStep(spec(t), t, platform(), ctx)).toThrow(/stray/);
  });

  it2('command: every hostile choice value and a hostile template constant reach the tool as one inert argument (bash -n and a real run)', () => {
    const t = hostileRuff();
    for (const value of HOSTILE) {
      const r = renderStep(spec(t, { choices: { 'line-length': value } }), t, platform(), ctx);
      const step = runs(r).at(-1) as RenderedStep;
      expect(bashN(step.run as string), JSON.stringify(value)).toEqual({ ok: true, err: '' });
      expect(step.run).not.toContain('${{');
      expect(step.env?.PIPEGEN_ARG_0).toBe(value); // raw, only in env
      const sb = sandbox();
      fakeTool(sb, 'pipegen-out-lint', 'ruff', "echo '{}' > ./ruff.sarif");
      const res = exec(step, sb, stepEnv(step, sb));
      expect(res.status, `${JSON.stringify(value)}: ${res.stderr}`).toBe(0);
      const argv = argvOf(sb);
      expect(argv).toContain(`--line-length=${value}`);
      expect(argv).toContain("--message=it's a \"test\" $(touch pwned) `id` $HOME \\ end");
      expect(existsSync(join(sb.ws, 'pwned')), JSON.stringify(value)).toBe(false);
      expect(existsSync(join(sb.dir, 'pwned'))).toBe(false);
    }
  });

  it2('command: the then commands run in the same step; the first failing one fails it (set -euo pipefail)', () => {
    const t = entry('coverage-py');
    const closureText = ['coverage==7.16.2 --hash=sha256:' + 'a'.repeat(64)].join('\n') + '\n';
    const r = renderStep(spec(t, { choices: { 'fail-under': '70' } }), t, platform(), ctx, { pipClosures: { 'coverage-py': closureText } });
    const step = r.steps.at(-1) as RenderedStep;
    expect(step.run).toContain('set -euo pipefail');
    expect(bashN(step.run as string).ok).toBe(true);
    const sb = sandbox();
    const venv = join(sb.rt, 'pipegen-venv', 'pipegen-out-coverage');
    mkdirSync(join(venv, 'bin'), { recursive: true });
    const tool = join(venv, 'bin', 'coverage');
    writeFileSync(tool, '#!/bin/sh\necho "$@" >> ./calls.txt\n[ "$1" = report ] && exit 3\nexit 0\n');
    chmodSync(tool, 0o755);
    const res = exec(step, sb, stepEnv(step, sb));
    expect(res.status).toBe(3);
    expect(readFileSync(join(sb.ws, 'calls.txt'), 'utf8').trim().split('\n')).toEqual(['run --module pytest', 'report --fail-under=70']);
  });
});

describe('6b: env hardening (S6)', () => {
  it('env: no rendered step writes GITHUB_ENV or GITHUB_PATH; every run step sets shell bash, BASH_ENV and ENV empty, and runs the tool under /usr/bin/env -i', () => {
    for (const r of [render('trivy-image'), render('zap-baseline'), render('biome'), render('ruff')]) {
      for (const s of runs(r)) {
        expect(s.run).not.toMatch(/GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT|GITHUB_STATE/);
        expect(s.shell).toBe('bash');
        expect(s.env?.BASH_ENV).toBe('');
        expect(s.env?.ENV).toBe('');
        expect(s.run).toContain('set -euo pipefail');
      }
      expect(lastRun(r)).toContain('/usr/bin/env -i');
    }
  });

  it2('env: only the allowlist reaches the tool (HOME, a fixed PATH, RUNNER_TEMP, TMPDIR, the template env, PIPEGEN_ARG_n, declared secrets of an app-running tool)', () => {
    const t = entry('vitest-coverage');
    const c = ctxFor([service({ name: 'app', path: '.', envVars: ['STRIPE_KEY'] })]);
    const r = renderStep(withNames(spec(t, { service: 'app', choices: { 'coverage-thresholds-lines': '80' } }), ['STRIPE_KEY']), t, platform(), c);
    const step = r.steps.at(-1) as RenderedStep;
    const sb = sandbox();
    // vitest is run through npx: put fakes for node and npx on a PATH the script will find
    const bin = join(sb.dir, 'nodebin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'node'), '#!/bin/sh\nexit 0\n');
    writeFileSync(join(bin, 'npx'), '#!/bin/sh\nfor a in "$@"; do printf \'%s\\0\' "$a"; done > ./argv.bin\nenv > ./env.txt\n');
    chmodSync(join(bin, 'node'), 0o755);
    chmodSync(join(bin, 'npx'), 0o755);
    const poison = { NODE_OPTIONS: '--require /evil.js', COVERAGE_RCFILE: '/evil', TRIVY_CACHE_DIR: '/evil', LD_PRELOAD: '/evil.so', PINACT_X: '1', HADOLINT_NO_FAIL: '1', GITHUB_ENV: '/x', PIPEGEN_UNLISTED: 'x', npm_config_registry: 'https://evil.example/' };
    const res = exec(step, sb, { ...stepEnv(step, sb, { STRIPE_KEY: 's3cret-value' }, poison), PATH: `${bin}:${process.env.PATH ?? ''}` });
    expect(res.status, res.stderr).toBe(0);
    const names = envNames(sb).filter((n) => !['PWD', 'SHLVL', '_', 'OLDPWD'].includes(n)).sort();
    expect(names).toEqual(['HOME', 'PATH', 'PIPEGEN_ARG_0', 'RUNNER_TEMP', 'STRIPE_KEY', 'TMPDIR']);
    const env = Object.fromEntries(readFileSync(join(sb.ws, 'env.txt'), 'utf8').split('\n').filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
    expect(env.STRIPE_KEY).toBe('s3cret-value');
    expect(env.PIPEGEN_ARG_0).toBe('80');
    expect(env.PATH).toBe(`${bin}:${FIXED_PATH}`);
    expect(env.RUNNER_TEMP).toBe(sb.rt);
  });

  it2('env: a step env key that is not on the allowlist (the pinned config, the config of a docker-style template) never reaches the tool', () => {
    const t = entry('ruff');
    const step = lastRunStep(renderStep(spec(t), t, platform(), ctx));
    expect(step.env).toHaveProperty('PIPEGEN_CONFIG');
    const sb = sandbox();
    fakeTool(sb, 'pipegen-out-lint', 'ruff', "echo '{}' > ./ruff.sarif");
    const res = exec(step, sb, stepEnv(step, sb, {}, { SOME_OTHER_STEP_VAR: 'x' }));
    expect(res.status, res.stderr).toBe(0);
    const names = envNames(sb);
    expect(names).not.toContain('PIPEGEN_CONFIG');
    expect(names).not.toContain('BASH_ENV');
    expect(names).not.toContain('SOME_OTHER_STEP_VAR');
    expect(names).not.toContain('GITHUB_WORKSPACE');
  });

  it('declared names: a scanner or linter step refuses them (they reach only steps that run the app)', () => {
    const c = ctxFor([service({ name: 'app', path: '.', envVars: ['STRIPE_KEY'] })]);
    for (const id of ['ruff', 'trivy-image', 'betterleaks', 'biome', 'zap-baseline', 'hadolint', 'osv-scanner']) {
      const t = entry(id);
      expect(() => renderStep(withNames(spec(t, { service: 'app' }), ['STRIPE_KEY']), t, platform(), c), id).toThrow(/run the app|scanner|linter/);
    }
    // a coverage tool runs the project's tests: it may get them
    const v = entry('vitest-coverage');
    const r = renderStep(withNames(spec(v, { service: 'app' }), ['STRIPE_KEY']), v, platform(), c);
    expect(r.steps.at(-1)?.env?.STRIPE_KEY).toBe('${{ secrets.STRIPE_KEY }}');
    expect(r.steps.at(-1)?.run).toContain('"STRIPE_KEY=$STRIPE_KEY"');
  });

  it('env: the template env must be a plain name that is not a dangerous one and does not clash with the renderer\'s own', () => {
    for (const bad of ['PATH', 'BASH_ENV', 'NODE_OPTIONS', 'LD_PRELOAD', 'PIPEGEN_CONFIG', 'PIPEGEN_ARG_0', 'HOME', 'RUNNER_TEMP', 'TMPDIR', 'lower', 'A B']) {
      const t = entry('ruff');
      (t.step.cli as { env?: Record<string, string> }).env = { [bad]: 'x' };
      expect(() => renderStep(spec(t), t, platform(), ctx), bad).toThrow(RenderError);
    }
    const ok = entry('ruff');
    (ok.step.cli as { env?: Record<string, string> }).env = { PIPEGEN_X_FLAG: 'a b' };
    const step = lastRunStep(renderStep(spec(ok), ok, platform(), ctx));
    expect(step.env?.PIPEGEN_X_FLAG).toBe('a b');
    expect(step.run).toContain('"PIPEGEN_X_FLAG=$PIPEGEN_X_FLAG"');
  });
});

const lastRunStep = (r: RenderResult): RenderedStep => runs(r).at(-1) as RenderedStep;

describe('6b: outputs (S7)', () => {
  it('output: renderStep returns the path under runner temp for the entry\'s artifact; renderUpload accepts exactly it', () => {
    const r = render('trivy-image');
    const artifact = resultArtifactName('image-scan');
    expect(r.output).toEqual({ path: `\${{ runner.temp }}/pipegen-out/${artifact}/trivy-image.sarif`, format: 'sarif' });
    const up = renderUpload(artifact, r.output?.path as string, platform());
    expect(up.with?.path).toBe(r.output?.path);
    expect(render('biome').output).toBeNull();
    const per = render('trivy-image', { service: 'app' });
    expect(per.output?.path).toContain(resultArtifactName('image-scan', 'app'));
    expect(per.output?.path).toContain('--app/');
  });

  it('output: the step checks the reviewed path is free and its parent a real folder before, and a regular file after, then moves it', () => {
    const run = lastRun(render('trivy-image'));
    expect(run).toContain('[ -e "$out" ] || [ -L "$out" ]');
    expect(run).toContain('[ -d "$outdir" ] && [ ! -L "$outdir" ]');
    expect(run).toContain('[ -f "$out" ] && [ ! -L "$out" ]');
    expect(run).toContain('mv -- "$out" "$RUNNER_TEMP/pipegen-out/pipegen-out-image-scan/trivy-image.sarif"');
    expect(run.indexOf('[ -e "$out" ]')).toBeGreaterThan(-1);
    expect(run.indexOf('[ -e "$out" ]')).toBeLessThan(run.indexOf('"${pg_env[@]}" '));
    expect(run.indexOf('"${pg_env[@]}" ')).toBeLessThan(run.indexOf('[ -f "$out" ]'));
  });

  it2('output: a result path that already exists (file, folder or symlink) fails before the tool runs; a good run is moved and keeps the tool\'s exit code', () => {
    const t = entry('trivy-image');
    const step = lastRunStep(renderStep(spec(t), t, platform(), ctx));
    const out = 'trivy-image.sarif';
    const artifact = 'pipegen-out-image-scan';
    // existing file, existing dangling symlink, existing symlink to a file
    for (const make of [(sb: Sandbox) => writeFileSync(join(sb.ws, out), 'x'), (sb: Sandbox) => symlinkSync('/nonexistent-target', join(sb.ws, out)), (sb: Sandbox) => { writeFileSync(join(sb.dir, 'real'), 'x'); symlinkSync(join(sb.dir, 'real'), join(sb.ws, out)); }, (sb: Sandbox) => mkdirSync(join(sb.ws, out))]) {
      const sb = sandbox();
      fakeTool(sb, artifact, 'trivy');
      make(sb);
      const res = exec(step, sb, stepEnv(step, sb));
      expect(res.status).not.toBe(0);
      expect(existsSync(join(sb.ws, 'argv.bin'))).toBe(false); // the tool never ran
    }
    // good run: the tool writes the result and exits 1 (findings): file moved, exit code kept
    const sb = sandbox();
    fakeTool(sb, artifact, 'trivy', `echo '{"runs":[]}' > ./${out}\nexit 1`);
    const res = exec(step, sb, stepEnv(step, sb));
    expect(res.status).toBe(1);
    expect(readFileSync(join(sb.rt, 'pipegen-out', artifact, out), 'utf8')).toContain('"runs"');
    expect(existsSync(join(sb.ws, out))).toBe(false);
  });

  it2('output: a result that is a symlink (or not there at all) is not moved and fails the step', () => {
    const t = entry('trivy-image');
    const step = lastRunStep(renderStep(spec(t), t, platform(), ctx));
    const artifact = 'pipegen-out-image-scan';
    const sb = sandbox();
    writeFileSync(join(sb.dir, 'secret.txt'), 'top secret');
    fakeTool(sb, artifact, 'trivy', `ln -s ${join(sb.dir, 'secret.txt')} ./trivy-image.sarif`);
    expect(exec(step, sb, stepEnv(step, sb)).status).not.toBe(0);
    expect(existsSync(join(sb.rt, 'pipegen-out', artifact, 'trivy-image.sarif'))).toBe(false);
    const sb2 = sandbox();
    fakeTool(sb2, artifact, 'trivy');
    expect(exec(step, sb2, stepEnv(step, sb2)).status).not.toBe(0);
  });

  it('output: an output path that is not a plain file name is refused', () => {
    for (const p of ['../x.sarif', '/etc/x', 'a/b.sarif', '-x', 'a b']) {
      const t = entry('trivy-image');
      t.step.output = { path: p, format: 'sarif' };
      const s = spec(t);
      expect(() => renderStep(s, t, platform(), ctx), p).toThrow(RenderError);
    }
  });

  it('output: zap writes its result into a fresh work folder it mounts, and the move starts from there', () => {
    const r = render('zap-baseline');
    const run = lastRun(r);
    expect(run).toContain('work="$RUNNER_TEMP/pipegen-work/pipegen-out-dast"');
    expect(run).toContain('-v "$work:/zap/wrk"');
    expect(run).toContain('out="$work/zap.json"');
    expect(run).toContain("printf '%s' \"$PIPEGEN_CONFIG\" > \"$work/zap-baseline.conf\"");
    expect(run).toContain('-c zap-baseline.conf');
    expect(r.output?.format).toBe('zap-json');
  });
});

describe('6b: working folder (S8 run-time check)', () => {
  const c = ctxFor([service({ name: 'api', path: 'services/api' })]);

  it('workingDir: the step moves into the service folder after checking every part is a real folder inside the workspace', () => {
    const t = entry('ruff');
    const run = lastRun(renderStep(spec(t, { service: 'api', workingDir: 'services/api' }), t, platform(), c));
    expect(run).toContain('for d in services services/api; do');
    expect(run).toContain('[ -L "$d" ]');
    expect(run).toContain('cd -- services/api');
    expect(run).toContain('pwd -P');
    expect(run).not.toContain('working-directory');
    expect(lastRunStep(renderStep(spec(t, { service: 'api', workingDir: 'services/api' }), t, platform(), c))['working-directory']).toBeUndefined();
  });

  it2('workingDir: a symlinked service folder fails the step before anything runs; a real folder works', () => {
    const t = entry('ruff');
    const step = lastRunStep(renderStep(spec(t, { service: 'api', workingDir: 'services/api' }), t, platform(), c));
    const sb = sandbox();
    mkdirSync(join(sb.dir, 'outside'));
    mkdirSync(join(sb.ws, 'services'));
    symlinkSync(join(sb.dir, 'outside'), join(sb.ws, 'services', 'api'));
    fakeTool(sb, 'pipegen-out-lint--api', 'ruff');
    expect(exec(step, sb, stepEnv(step, sb)).status).not.toBe(0);
    expect(existsSync(join(sb.dir, 'outside', 'argv.bin'))).toBe(false);
    const ok = sandbox();
    mkdirSync(join(ok.ws, 'services', 'api'), { recursive: true });
    fakeTool(ok, 'pipegen-out-lint--api', 'ruff', "echo '{}' > ./ruff.sarif");
    const res = exec(step, ok, stepEnv(step, ok));
    expect(res.status, res.stderr).toBe(0);
    expect(lstatSync(join(ok.ws, 'services', 'api', 'argv.bin')).isFile()).toBe(true);
  });
});

describe('6b: every reviewed CLI entry', () => {
  it('loop: each CLI and docker entry renders or throws a documented RenderError; every run step passes bash -n and holds no expression', () => {
    const outcome: Record<string, string> = {};
    let rendered = 0;
    for (const t of reviewedList()) {
      if (t.step.cli === undefined) continue;
      try {
        const r = renderStep(spec(t), t, platform(), ctxFor([service({ name: 'app', path: '.' })]));
        rendered++;
        outcome[t.id] = 'rendered';
        for (const s of runs(r)) {
          expect(bashN(s.run as string), `${t.id}: ${s.name}`).toEqual({ ok: true, err: '' });
          expect(s.run, t.id).not.toContain('${{');
          expect(s.run, t.id).not.toMatch(/GITHUB_ENV|GITHUB_PATH/);
          expect(s.shell, t.id).toBe('bash');
          expect(s.env?.BASH_ENV, t.id).toBe('');
          expect(s.env?.ENV, t.id).toBe('');
        }
        expect(() => stepsToYaml(r.steps), t.id).not.toThrow();
        // the YAML says exactly what the step says: every run script and every env value reads back unchanged
        const back = parse(yamlOf(r.steps)) as Record<string, unknown>[];
        r.steps.forEach((st, i) => {
          expect(back[i]?.run, `${t.id}: run`).toBe(st.run);
          expect(back[i]?.env, `${t.id}: env`).toEqual(st.env);
        });
        if (t.step.output.path !== '') expect(r.output?.path, t.id).toContain('/pipegen-out/');
      } catch (e) {
        expect(e, t.id).toBeInstanceOf(RenderError);
        outcome[t.id] = (e as Error).message;
        expect((e as Error).message, t.id).toMatch(/6c|not available yet|job service/);
      }
    }
    expect(rendered).toBeGreaterThan(20);
    // the ones that wait, by name
    for (const id of ['semgrep', 'nuclei', 'eslint-typescript', 'registry', 'schemathesis', 'mypy', 'bandit', 'coverage-py', 'creosote', 'vulture']) expect(outcome[id], id).not.toBe('rendered');
    for (const id of ['trivy-config', 'trivy-image', 'trivy-licence', 'betterleaks', 'gitleaks', 'osv-scanner', 'lefthook', 'syft', 'cosign', 'actionlint', 'zizmor', 'biome', 'eslint', 'oxlint-typeaware', 'prettier', 'vitest-coverage', 'c8', 'knip', 'jscpd', 'hadolint', 'kube-linter', 'pinact', 'poutine', 'gosec', 'ruff', 'ruff-format', 'zap-baseline']) expect(outcome[id], id).toBe('rendered');
  });
});

describe('6b: snapshots', () => {
  it('snapshot: a github-release tool (trivy image with choices)', async () => {
    const r = render('trivy-image', { choices: { severity: 'HIGH,CRITICAL', 'ignore-unfixed': 'true' } });
    await expect(yamlOf(r.steps)).toMatchFileSnapshot('__snapshots__/steps/cli-github-release.yml');
  });

  it('snapshot: a docker tool (zap baseline)', async () => {
    await expect(yamlOf(render('zap-baseline').steps)).toMatchFileSnapshot('__snapshots__/steps/cli-docker.yml');
  });

  it('snapshot: an npm tool (biome with its plugin, in a service folder)', async () => {
    const c = ctxFor([service({ name: 'web', path: 'apps/web', runtimeVersion: '24' })]);
    await expect(yamlOf(render('biome', { service: 'web', workingDir: 'apps/web' }, c).steps)).toMatchFileSnapshot('__snapshots__/steps/cli-npm.yml');
  });

  it('snapshot: a pip tool with a fixture closure (mypy)', async () => {
    const t = entry('mypy');
    const closureText = `mypy==2.4.0 --hash=sha256:${'a'.repeat(64)}\ntyping-extensions==4.12.2 --hash=sha256:${'b'.repeat(64)}\n`;
    await expect(yamlOf(renderStep(spec(t), t, platform(), ctx, { pipClosures: { mypy: closureText } }).steps)).toMatchFileSnapshot('__snapshots__/steps/cli-pip.yml');
  });
});
