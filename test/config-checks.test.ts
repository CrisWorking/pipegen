// Plan P Task 4: checks decided by reading files (Dependabot/Renovate cooldown, coverage minimum, publishing, ESLint versions).
// Rulings PB4 (never "covered" when pipegen can't confirm), PS17, PS22, PS23, P2 (Go).
import { mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { build } from 'esbuild';
import { afterEach, describe, expect, it } from 'vitest';
import { mapCoverage, type Coverage } from '../src/audit/coverage.js';
import { coverageMinimum, frameworkAdjust, publishingCoverage, updateConfigCoverage, versionAdjust } from '../src/audit/config-checks.js';
import { floorNeeds } from '../src/engine/needs.js';
import { readPrecommit, readWorkflows } from '../src/read/workflows.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { Capabilities, Layer, Need, RepoProfile, Service } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(cleanupRepos);

const caps: Capabilities = {
  branchProtection: true, environments: true, envRequiredReviewers: true, deploymentBranchPolicies: false,
  attestations: true, codeScanning: true, keylessSigningAllowed: true,
};
const svc = (path: string, over: Partial<Service> = {}): Service => ({
  name: path === '.' ? 'app' : path.split('/').pop() as string, path, language: 'node', packageManager: 'npm', hasTests: true,
  envVars: [], dependsOn: [], scripts: ['test', 'lint'], frameworks: [], quality: emptyServiceQuality(), ...over,
});
async function profileOf(dir: string, over: Partial<RepoProfile> = {}): Promise<RepoProfile> {
  return {
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
    services: [svc('.')], terraformDirs: [], hasCompose: false,
    existingWorkflows: await readWorkflows(dir), precommit: readPrecommit(dir), repoFiles: emptyRepoFiles(), ...over,
  };
}
async function rows(dir: string, over: Partial<RepoProfile> = {}): Promise<Coverage[]> {
  const p = await profileOf(dir, over);
  return mapCoverage(p, floorNeeds(p, caps), dir);
}
function pick(all: Coverage[], layer: Layer, id: string, service?: string): Coverage {
  const found = all.find((r) => r.need.layer === layer && r.need.id === id && (service === undefined || r.need.service === service));
  if (!found) throw new Error(`no ${id} row in ${layer}`);
  return found;
}
const need = (id: string, layer: Layer, service?: string): Need => ({ id, layer, category: id, ...(service === undefined ? {} : { service }), why: '', blocking: id !== 'update-config', floor: false });
const wf = (dir: string, name: string, body: string) => writeIn(dir, `.github/workflows/${name}`, body);
const job = (steps: string) => `jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`;
const runStep = (cmd: string) => `      - run: ${cmd}\n`;
const onBoth = 'on: [push, pull_request]\n';
const DEP = '.github/dependabot.yml';
const dep = (dir: string, body: string) => writeIn(dir, DEP, body);
const SCHED = '    schedule:\n      interval: weekly\n';
const upd = (eco: string, directory: string, extra = '    cooldown:\n      default-days: 7\n') => `  - package-ecosystem: ${eco}\n    directory: ${directory}\n${SCHED}${extra}`;
const depFile = (...entries: string[]) => `version: 2\nupdates:\n${entries.join('')}`;
async function update(dir: string, over: Partial<RepoProfile> = {}, running = false): Promise<Coverage> {
  const p = await profileOf(dir, over);
  return updateConfigCoverage(p, need('update-config', 'merge'), dir, running);
}
const ADJUST_PS22 = /ESLint's migration tool \(@eslint\/migrate-config\)/;

// ---------- versionAdjust ----------

describe('versions: ESLint (PS22, PS23)', () => {
  const lintRow = (by: string, status: Coverage['status'] = 'covered'): Coverage => ({ need: need('lint', 'merge', 'app'), status, by, where: '.github/workflows/ci.yml (job t)', why: 'The eslint check runs on every pull request.' });
  const profile = (versions: Service['quality']['versions'], eslintConfig: Service['quality']['eslintConfig'], fromRange: Service['quality']['fromRange'] = []): RepoProfile => ({
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
    services: [svc('.', { quality: { ...emptyServiceQuality(), versions, eslintConfig, fromRange } })], terraformDirs: [], hasCompose: false,
    existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
  });

  it('versions: eslint 10 with only .eslintrc → lint partial with the migrate-config hint, tool stays the repo\'s eslint', () => {
    const [r] = versionAdjust([lintRow('eslint')], profile({ eslint: '10.0.1' }, 'eslintrc'));
    expect(r).toMatchObject({ status: 'partial', by: 'eslint', where: '.github/workflows/ci.yml (job t)' });
    expect(r?.why).toMatch(/ESLint 10 doesn't read \.eslintrc/);
    expect(r?.why).toMatch(ADJUST_PS22);
    expect(r?.why).not.toMatch(/npx/); // U18/N1: no runnable command without an exact version
  });

  it('versions: eslint 10 with a flat config, or both configs, stays covered', () => {
    for (const cfg of ['flat', 'both'] as const) expect(versionAdjust([lintRow('eslint')], profile({ eslint: '10.0.1' }, cfg))[0]?.status).toBe('covered');
  });

  it('versions: eslint 9 → covered, why adds the end-of-life date; eslint 8 gets its own date', () => {
    const [r] = versionAdjust([lintRow('eslint')], profile({ eslint: '9.39.5' }, 'flat'));
    expect(r?.status).toBe('covered');
    expect(r?.why).toMatch(/ESLint 9 reached end of life on 2026-08-06\./);
    expect(versionAdjust([lintRow('eslint')], profile({ eslint: '8.57.1' }, 'eslintrc'))[0]?.why).toMatch(/ESLint 8 reached end of life on 2024-10-05\./);
  });

  it('versions: a version from a package.json range may lower a row, never raise one; the end-of-life note says "at least"', () => {
    const lowered = versionAdjust([lintRow('eslint')], profile({ eslint: '10.0.0' }, 'eslintrc', ['eslint']))[0];
    expect(lowered?.status).toBe('partial');
    expect(lowered?.why).toMatch(/package\.json/);
    const nine = versionAdjust([lintRow('eslint')], profile({ eslint: '9.0.0' }, 'flat', ['eslint']))[0];
    expect(nine?.status).toBe('covered');
    expect(nine?.why).toMatch(/at least ESLint 9|ESLint 9 or later|at least/i);
    // a missing row stays missing (nothing is raised)
    const missing: Coverage = { need: need('lint', 'merge', 'app'), status: 'missing', why: 'Without a lint check in CI, mistakes the linter would catch can be merged.' };
    expect(versionAdjust([missing], profile({ eslint: '10.0.0' }, 'eslintrc'))[0]).toEqual(missing);
  });

  it('versions: an own-script lint row is adjusted too; another tool\'s row (biome) and other services are not', () => {
    const own = versionAdjust([lintRow('your own `npm run lint`')], profile({ eslint: '10.0.0' }, 'eslintrc'))[0];
    expect(own).toMatchObject({ status: 'partial', by: 'your own `npm run lint`' });
    expect(versionAdjust([lintRow('biome')], profile({ eslint: '10.0.0' }, 'eslintrc'))[0]?.status).toBe('covered');
    const other = { ...lintRow('eslint'), need: need('lint', 'merge', 'other') };
    expect(versionAdjust([other], profile({ eslint: '10.0.0' }, 'eslintrc'))[0]?.status).toBe('covered');
  });

  it('versions: through mapCoverage, eslint 10 with only .eslintrc makes the CI lint row partial', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${onBoth}${job(runStep('npx eslint .'))}`);
    const s = svc('.', { quality: { ...emptyServiceQuality(), versions: { eslint: '10.1.0' }, eslintConfig: 'eslintrc' } });
    const r = pick(await rows(dir, { services: [s] }), 'merge', 'lint', 'app');
    expect(r).toMatchObject({ status: 'partial', by: 'eslint' });
    expect(r.why).toMatch(/ESLint 10 doesn't read \.eslintrc/);
  });
});

// ---------- Dependabot ----------

describe('dependabot (PB4 d)', () => {
  it('dependabot: npm + github-actions with default-days 7 → covered', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${onBoth}${job(runStep('echo hi'))}`);
    dep(dir, depFile(upd('npm', '/'), upd('github-actions', '/')));
    expect(await update(dir)).toMatchObject({ status: 'covered', by: 'dependabot', where: DEP });
  });

  it('dependabot: no cooldown → partial; cooldown under 7 days → partial; a per-type day under 7, include and exclude → partial', async () => {
    const cases: [string, RegExp][] = [
      ['', /default wait is 3 days/],
      ['    cooldown:\n      default-days: 6\n', /7/],
      ['    cooldown:\n      default-days: 0\n', /7/],
      ['    cooldown:\n      default-days: 7\n      semver-patch-days: 0\n', /7/],
      ['    cooldown:\n      default-days: 7\n      include: [left-pad]\n', /./],
      ['    cooldown:\n      default-days: 7\n      exclude: ["*"]\n', /./],
    ];
    for (const [cooldown, why] of cases) {
      const dir = makeTempDir();
      dep(dir, depFile(upd('npm', '/', cooldown)));
      const r = await update(dir);
      expect(r.status, cooldown).toBe('partial');
      expect(r.why, cooldown).toMatch(why);
    }
    const dir = makeTempDir();
    dep(dir, depFile(upd('npm', '/', '    cooldown:\n      default-days: 30\n')));
    expect((await update(dir)).status).toBe('covered');
  });

  it('dependabot: Dockerfile without a docker entry → partial naming docker; a missing github-actions entry too', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${onBoth}${job(runStep('echo hi'))}`);
    dep(dir, depFile(upd('npm', '/')));
    const s = svc('.', { dockerfile: 'Dockerfile' });
    const r = await update(dir, { services: [s] });
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/docker/);
    expect(r.why).toMatch(/github-actions/);
  });

  it('dependabot: open-pull-requests-limit 0 means off; a non-number limit does not count either', async () => {
    for (const limit of ['0', '"5"', 'false']) {
      const dir = makeTempDir();
      dep(dir, depFile(upd('npm', '/', `    open-pull-requests-limit: ${limit}\n    cooldown:\n      default-days: 7\n`)));
      expect((await update(dir)).status, limit).toBe('partial');
    }
    const dir = makeTempDir();
    dep(dir, depFile(upd('npm', '/', '    open-pull-requests-limit: 10\n    cooldown:\n      default-days: 7\n')));
    expect((await update(dir)).status).toBe('covered');
  });

  it('dependabot: an entry that ignores every package is off', async () => {
    const dir = makeTempDir();
    dep(dir, depFile(upd('npm', '/', '    ignore:\n      - dependency-name: "*"\n    cooldown:\n      default-days: 7\n')));
    expect((await update(dir)).status).toBe('partial');
  });

  it('dependabot: every service folder needs an entry; "/" covers the root only; directories globs count; a "!" glob does not', async () => {
    const dir = makeTempDir();
    const services = [svc('.'), svc('packages/a'), svc('packages/b')];
    dep(dir, depFile(upd('npm', '/')));
    expect((await update(dir, { services })).status).toBe('partial');
    dep(dir, depFile(upd('npm', '/'), '  - package-ecosystem: npm\n    directories: ["/packages/*"]\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n'));
    expect((await update(dir, { services })).status).toBe('covered');
    dep(dir, depFile(upd('npm', '/'), '  - package-ecosystem: npm\n    directories: ["!/packages/zzz", "/packages/a"]\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n'));
    expect((await update(dir, { services })).status).toBe('partial');
    dep(dir, depFile(upd('npm', '/'), '  - package-ecosystem: npm\n    directories: ["/{packages}/*"]\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n'));
    expect((await update(dir, { services })).status).toBe('partial'); // unusual glob characters are not trusted
  });

  it('dependabot: python needs pip or uv; bun needs the bun entry, not npm', async () => {
    const dir = makeTempDir();
    const py = svc('.', { language: 'python', packageManager: 'uv' });
    dep(dir, depFile(upd('uv', '/')));
    expect((await update(dir, { services: [py] })).status).toBe('covered');
    dep(dir, depFile(upd('pip', '/')));
    expect((await update(dir, { services: [py] })).status).toBe('covered');
    dep(dir, depFile(upd('npm', '/')));
    expect((await update(dir, { services: [py] })).status).toBe('partial');
    const bun = svc('.', { packageManager: 'bun' });
    expect((await update(dir, { services: [bun] })).status).toBe('partial');
    dep(dir, depFile(upd('bun', '/')));
    expect((await update(dir, { services: [bun] })).status).toBe('covered');
  });

  it('dependabot: Go is not detected by any reader, so go.mod files are found here: no gomod entry → partial naming gomod', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'svc/go.mod', 'module x\n');
    dep(dir, depFile(upd('npm', '/')));
    const r = await update(dir);
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/gomod/);
    dep(dir, depFile(upd('npm', '/'), upd('gomod', '/svc')));
    expect((await update(dir)).status).toBe('covered');
    dep(dir, depFile(upd('npm', '/'), upd('gomod', '/')));
    expect((await update(dir)).status).toBe('partial'); // "/" is the root only
  });

  it('dependabot: a service in a language pipegen has no Dependabot rule for caps the row at partial', async () => {
    const dir = makeTempDir();
    dep(dir, depFile(upd('npm', '/')));
    const r = await update(dir, { services: [svc('.'), svc('java', { language: 'java' })] });
    expect(r.status).toBe('partial');
  });

  it('dependabot: nothing pipegen can check against the file → not covered', async () => {
    const dir = makeTempDir();
    dep(dir, depFile(upd('npm', '/')));
    expect((await update(dir, { services: [] })).status).not.toBe('covered');
  });

  it('config-checks: dependabot.yml as a symlink → unknown, not followed', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'real.yml', depFile(upd('npm', '/')));
    mkdirSync(join(dir, '.github'), { recursive: true });
    symlinkSync(join(dir, 'real.yml'), join(dir, DEP));
    const r = await update(dir);
    expect(r.status).toBe('unknown');
    expect(r.why).toMatch(/symbolic link/);
  });

  it('config-checks: a symlinked .github folder → unknown', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'elsewhere/dependabot.yml', depFile(upd('npm', '/')));
    symlinkSync(join(dir, 'elsewhere'), join(dir, '.github'));
    expect((await update(dir)).status).toBe('unknown');
  });

  it('dependabot (hostile): aliases over the limit, an oversized file, invalid YAML, repeated keys → unknown', async () => {
    const bomb = `version: 2\nx: &a [1,2,3]\n${Array.from({ length: 60 }, (_, i) => `k${i}: *a`).join('\n')}\nupdates:\n${upd('npm', '/')}`;
    const huge = `${depFile(upd('npm', '/'))}# ${'x'.repeat(1_100_000)}\n`;
    const bad = 'version: 2\nupdates: [\n';
    const dup = `version: 2\nupdates:\n${upd('npm', '/')}version: 3\n`;
    for (const [name, body] of [['alias bomb', bomb], ['huge', huge], ['invalid', bad], ['repeated key', dup]]) {
      const dir = makeTempDir();
      dep(dir, body as string);
      expect((await update(dir)).status, name as string).toBe('unknown');
    }
  });

  it('dependabot (hostile): a merge key could hide settings pipegen does not read → unknown', async () => {
    const dir = makeTempDir();
    dep(dir, `version: 2\ndefaults: &d\n  open-pull-requests-limit: 0\nupdates:\n  - <<: *d\n    package-ecosystem: npm\n    directory: /\n    cooldown:\n      default-days: 7\n`);
    expect((await update(dir)).status).toBe('unknown');
  });

  it('dependabot (hostile): wrong types are never covered and never throw', async () => {
    const bodies = [
      'version: 2\nupdates: "npm"\n',
      'version: 2\nupdates: [1, "x", null, [], {}]\n',
      'version: "2"\nupdates:\n' + upd('npm', '/'),
      'version: 1\nupdates:\n' + upd('npm', '/'),
      '- a\n- b\n',
      '"just a string"\n',
      'version: 2\nupdates:\n  - package-ecosystem: [npm]\n    directory: /\n    cooldown: {default-days: 7}\n',
      'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: [/]\n    cooldown: {default-days: 7}\n',
      'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown: 7\n',
      'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown: {default-days: "7"}\n',
      'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown: {default-days: 7.5}\n',
      'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown: {default-days: [7]}\n',
      'version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: 5\n    cooldown: {default-days: 7}\n',
    ];
    for (const body of bodies) {
      const dir = makeTempDir();
      dep(dir, body);
      const r = await update(dir);
      expect(r.status, body).not.toBe('covered');
    }
  });

  it('dependabot (hostile): thousands of entries and directories stay bounded and never cover', async () => {
    const many = Array.from({ length: 3000 }, (_, i) => upd('npm', `/p${i}`)).join('');
    const dir = makeTempDir();
    dep(dir, depFile(many));
    const r = await update(dir, { services: [svc('.')] });
    expect(r.status).not.toBe('covered');
  });
});

// ---------- Renovate ----------

describe('renovate (PB4 c)', () => {
  const renovate = (dir: string, body: unknown, file = 'renovate.json') => writeIn(dir, file, typeof body === 'string' ? body : JSON.stringify(body));

  it('renovate: minimumReleaseAge "7 days" with a workflow that runs Renovate → covered', async () => {
    const dir = makeTempDir();
    renovate(dir, { minimumReleaseAge: '7 days' });
    expect(await update(dir, {}, true)).toMatchObject({ status: 'covered', by: 'renovate', where: 'renovate.json' });
  });

  it('renovate: the same config with no sign that Renovate runs → partial, saying the app cannot be seen', async () => {
    const dir = makeTempDir();
    renovate(dir, { minimumReleaseAge: '7 days' });
    const r = await update(dir, {}, false);
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/can't see whether the Renovate app is installed/);
  });

  it('renovate: other spellings of at least 7 days count; shorter or unreadable ages do not', async () => {
    for (const age of ['1 week', '168 hours', '14 days', '7 Days', '10 d']) {
      const dir = makeTempDir();
      renovate(dir, { minimumReleaseAge: age });
      expect((await update(dir, {}, true)).status, age).toBe('covered');
    }
    for (const age of ['6 days', '3 days', '0 days', '167 hours', '7', 7, null, '', 'a week', '7 days; rm', ['7 days'], { a: 1 }, '-7 days']) {
      const dir = makeTempDir();
      renovate(dir, { minimumReleaseAge: age });
      expect((await update(dir, {}, true)).status, String(JSON.stringify(age))).toBe('partial');
    }
  });

  it('renovate: only extends config:best-practices → partial ("set by a preset pipegen can\'t read"); no key at all → partial', async () => {
    const dir = makeTempDir();
    renovate(dir, { extends: ['config:best-practices'] });
    const r = await update(dir, {}, true);
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/preset pipegen can't read/);
    const dir2 = makeTempDir();
    renovate(dir2, {});
    expect((await update(dir2, {}, true)).status).toBe('partial');
  });

  it('renovate: renovate.json5 (and .jsonc) → partial ("pipegen can\'t read JSON5 yet")', async () => {
    for (const file of ['renovate.json5', '.github/renovate.json5', '.renovaterc.json5', 'renovate.jsonc']) {
      const dir = makeTempDir();
      renovate(dir, "{ minimumReleaseAge: '7 days', // comment\n}", file);
      const r = await update(dir, {}, true);
      expect(r.status, file).toBe('partial');
      expect(r.why, file).toMatch(/JSON5/);
    }
  });

  it('renovate: the config in package.json "renovate" is read; it is used only when no other Renovate file exists', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', JSON.stringify({ name: 'x', renovate: { minimumReleaseAge: '7 days' } }));
    expect(await update(dir, {}, true)).toMatchObject({ status: 'covered', where: 'package.json' });
    renovate(dir, { extends: ['config:base'] });
    expect((await update(dir, {}, true)).status).toBe('partial'); // renovate.json comes first
  });

  it('renovate: packageRules with a lower age, enabled false, a disabling preset or a non-strict internalChecksFilter → partial', async () => {
    const cases: unknown[] = [
      { minimumReleaseAge: '7 days', packageRules: [{ matchPackageNames: ['*'], minimumReleaseAge: '1 day' }] },
      { minimumReleaseAge: '7 days', packageRules: [{ matchPackageNames: ['*'], minimumReleaseAge: null }] },
      { minimumReleaseAge: '7 days', enabled: false },
      { minimumReleaseAge: '7 days', extends: [':disableRenovate'] },
      { minimumReleaseAge: '7 days', internalChecksFilter: 'none' },
      { minimumReleaseAge: '7 days', internalChecksFilter: 'flexible' },
    ];
    for (const c of cases) {
      const dir = makeTempDir();
      renovate(dir, c);
      expect((await update(dir, {}, true)).status, JSON.stringify(c)).toBe('partial');
    }
    const ok = makeTempDir();
    renovate(ok, { minimumReleaseAge: '7 days', internalChecksFilter: 'strict', packageRules: [{ matchPackageNames: ['a'], minimumReleaseAge: '14 days' }] });
    expect((await update(ok, {}, true)).status).toBe('covered');
  });

  it('renovate (hostile): invalid JSON, arrays, strings, huge files, a symlink → never covered', async () => {
    for (const body of ['{', '[]', '"7 days"', 'null', '{"__proto__":{"minimumReleaseAge":"7 days"}}', `{"a":"${'x'.repeat(1_100_000)}","minimumReleaseAge":"7 days"}`]) {
      const dir = makeTempDir();
      renovate(dir, body);
      expect((await update(dir, {}, true)).status, body.slice(0, 30)).not.toBe('covered');
    }
    const dir = makeTempDir();
    writeIn(dir, 'real.json', JSON.stringify({ minimumReleaseAge: '7 days' }));
    symlinkSync(join(dir, 'real.json'), join(dir, 'renovate.json'));
    expect((await update(dir, {}, true)).status).toBe('unknown');
  });

  it('renovate: with both tools the better row wins; with neither the row is missing', async () => {
    const dir = makeTempDir();
    dep(dir, depFile(upd('npm', '/', '')));
    renovate(dir, { minimumReleaseAge: '7 days' });
    expect((await update(dir, {}, true)).status).toBe('covered');
    expect((await update(dir, {}, false)).status).toBe('partial');
    expect((await update(makeTempDir())).status).toBe('missing');
  });

  it('renovate: through mapCoverage, a scheduled renovatebot/github-action run is the sign the app runs', async () => {
    const run = (on: string, body = '      - uses: renovatebot/github-action@v43\n') => `${on}${job(body)}`;
    const sched = "on:\n  schedule:\n    - cron: '0 3 * * *'\n";
    for (const [name, wfBody, expected] of [
      ['scheduled action', run(sched), 'covered'],
      ['scheduled cli', run(sched, runStep('npx renovate o/r')), 'covered'],
      ['pull_request only', run('on: pull_request\n'), 'partial'],
      ['no workflow', null, 'partial'],
      ['custom config file input', run(sched, '      - uses: renovatebot/github-action@v43\n        with:\n          configurationFile: other.json\n'), 'partial'],
      ['config file by env', run(sched, `      - run: npx renovate o/r\n        env:\n          RENOVATE_CONFIG_FILE: other.json\n`), 'partial'],
      ['continue-on-error', run(sched, '      - uses: renovatebot/github-action@v43\n        continue-on-error: true\n'), 'partial'],
    ] as const) {
      const dir = makeTempDir();
      writeIn(dir, 'renovate.json', JSON.stringify({ minimumReleaseAge: '7 days' }));
      if (wfBody !== null) wf(dir, 'renovate.yml', wfBody);
      expect(pick(await rows(dir), 'merge', 'update-config').status, name).toBe(expected);
    }
  });
});

// ---------- coverage minimum ----------

describe('coverage-min (PB4 b, PS17)', () => {
  const ci = (dir: string, cmd: string, extra = '') => wf(dir, 'ci.yml', `${onBoth}jobs:\n  t:\n    runs-on: ubuntu-latest\n${extra}    steps:\n      - run: ${cmd}\n`);
  const covRow = async (dir: string, services: Service[] = [svc('.')]) => pick(await rows(dir, { services }), 'merge', 'coverage', services[0]?.name);
  const NO_MIN = /sets no minimum, so a drop can't fail the build/;
  const JS_ONLY = /found a coverage threshold setting in .* but can't read JS config to confirm it/;

  it('coverage-min: vitest --coverage with thresholds in vitest.config.ts → partial (JS config can\'t be read); commented-out thresholds → partial, no minimum', async () => {
    const a = makeTempDir();
    ci(a, 'npx vitest run --coverage');
    writeIn(a, 'vitest.config.ts', 'export default { test: { coverage: { thresholds: { lines: 80 } } } };\n');
    const ra = await covRow(a);
    expect(ra.status).toBe('partial');
    expect(ra.why).toMatch(JS_ONLY);
    const b = makeTempDir();
    ci(b, 'npx vitest run --coverage');
    writeIn(b, 'vitest.config.ts', 'export default { test: { coverage: {\n  // thresholds: { lines: 80 },\n  /* thresholds: { lines: 80 } */\n} } };\n');
    const rb = await covRow(b);
    expect(rb.status).toBe('partial');
    expect(rb.why).toMatch(NO_MIN);
    // a comment replaced by nothing would glue words together: `coverage/**/thresholds` must not turn into a match
    const c = makeTempDir();
    ci(c, 'npx vitest run --coverage');
    writeIn(c, 'vitest.config.ts', 'const coverageX/* a */Threshold = 1;\n');
    expect((await covRow(c)).why).toMatch(NO_MIN);
  });

  it('coverage-min: vitest threshold flags count only with a value above 0', async () => {
    for (const [cmd, expected] of [
      ['vitest run --coverage --coverage.thresholds.lines=80', 'covered'],
      ['vitest run --coverage --coverage.thresholds.branches 60', 'covered'],
      ['vitest run --coverage --coverage.thresholds.lines=0', 'partial'],
      ['vitest run --coverage --coverage.thresholds.lines 0', 'partial'],
      ['vitest run --coverage --coverage.thresholds.lines=0.0', 'partial'],
      ['vitest run --coverage --coverage.thresholds.lines=abc', 'partial'],
      ['vitest run --coverage --coverage.thresholds.autoUpdate=true', 'partial'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, cmd);
      expect((await covRow(dir)).status, cmd).toBe(expected);
    }
  });

  it('coverage-min: jest --coverage with coverageThreshold in package.json → covered; zero or absent → partial; threshold flag as JSON', async () => {
    const pkg = (jest: unknown) => JSON.stringify({ name: 'x', jest });
    for (const [jest, expected] of [
      [{ coverageThreshold: { global: { lines: 80 } } }, 'covered'],
      [{ coverageThreshold: { './src/': { branches: 40 } } }, 'covered'],
      [{ coverageThreshold: { global: { lines: 0 } } }, 'partial'],
      [{ coverageThreshold: {} }, 'partial'],
      [{ coverageThreshold: 'high' }, 'partial'],
      [{}, 'partial'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, 'npx jest --coverage');
      writeIn(dir, 'package.json', pkg(jest));
      const r = await covRow(dir);
      expect(r.status, JSON.stringify(jest)).toBe(expected);
      if (expected === 'partial') expect(r.why).toMatch(NO_MIN);
    }
    const f = makeTempDir();
    ci(f, `jest --coverage --coverageThreshold='{"global":{"lines":80}}'`);
    expect((await covRow(f)).status).toBe('covered');
    const g = makeTempDir();
    ci(g, `jest --coverage --coverageThreshold='{"global":{"lines":0}}'`);
    expect((await covRow(g)).status).toBe('partial');
    const h = makeTempDir();
    ci(h, 'jest --coverage');
    writeIn(h, 'jest.config.js', 'module.exports = { coverageThreshold: { global: { lines: 90 } } };\n');
    expect((await covRow(h)).why).toMatch(JS_ONLY);
  });

  it('coverage-min: a vitest run does not take its minimum from jest\'s package.json key (and the reverse)', async () => {
    const a = makeTempDir();
    ci(a, 'vitest run --coverage');
    writeIn(a, 'package.json', JSON.stringify({ jest: { coverageThreshold: { global: { lines: 80 } } } }));
    expect((await covRow(a)).why).toMatch(NO_MIN);
  });

  it('coverage-min: pytest --cov without fail_under → partial; [tool.coverage.report] fail_under = 80 → covered', async () => {
    const py = svc('.', { language: 'python', packageManager: 'pip' });
    const a = makeTempDir();
    ci(a, 'pytest --cov=pkg');
    expect((await covRow(a, [py])).why).toMatch(NO_MIN);
    for (const [toml, expected] of [
      ['[tool.coverage.report]\nfail_under = 80\n', 'covered'],
      ['[tool.coverage.report]\nfail_under = 79.5\n', 'covered'],
      ['[tool.coverage.report]\nfail_under = 0\n', 'partial'],
      ['[tool.coverage.report]\nfail_under = "80"\n', 'partial'],
      ['[tool.coverage.run]\nfail_under = 80\n', 'partial'],
      ['[tool.coverage.report]\nshow_missing = true\n', 'partial'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, 'pytest --cov=pkg');
      writeIn(dir, 'pyproject.toml', toml);
      expect((await covRow(dir, [py])).status, toml).toBe(expected);
    }
  });

  it('coverage-min: .coveragerc [report] and setup.cfg [coverage:report] fail_under count; other sections and zero do not', async () => {
    const py = svc('.', { language: 'python', packageManager: 'pip' });
    for (const [file, text, expected] of [
      ['.coveragerc', '[report]\nfail_under = 85\n', 'covered'],
      ['.coveragerc', '[report]\n; fail_under = 85\n', 'partial'],
      ['.coveragerc', '[run]\nfail_under = 85\n', 'partial'],
      ['.coveragerc', '[report]\nfail_under = 0\n', 'partial'],
      ['setup.cfg', '[coverage:report]\nfail_under = 90\n', 'covered'],
      ['setup.cfg', '[report]\nfail_under = 90\n', 'partial'],
      ['tox.ini', '[coverage:report]\nfail_under: 90\n', 'covered'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, 'pytest --cov');
      writeIn(dir, file, text);
      expect((await covRow(dir, [py])).status, `${file} ${text}`).toBe(expected);
    }
  });

  it('coverage-min: --cov-fail-under and --fail-under count only above 0', async () => {
    const py = svc('.', { language: 'python', packageManager: 'pip' });
    for (const [cmd, expected] of [
      ['pytest --cov=pkg --cov-fail-under=80', 'covered'],
      ['pytest --cov=pkg --cov-fail-under 80', 'covered'],
      ['pytest --cov=pkg --cov-fail-under=0', 'partial'],
      ['pytest --cov=pkg --cov-fail-under 0', 'partial'],
      ['pytest --cov=pkg --cov-fail-under=0.0', 'partial'],
      ['pytest --cov=pkg --cov-fail-under=-5', 'partial'],
      ['pytest --cov=pkg --cov-fail-under=', 'partial'],
      ['coverage report --fail-under=80', 'covered'],
      ['coverage report --fail-under=0', 'partial'],
      ['coverage report', 'partial'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, cmd);
      expect((await covRow(dir, [py])).status, cmd).toBe(expected);
    }
  });

  it('coverage-min: c8 and nyc count with --check-coverage plus a threshold above 0, not alone', async () => {
    for (const [cmd, expected] of [
      ['c8 --check-coverage --lines 80 mocha', 'covered'],
      ['nyc --check-coverage --branches=70 mocha', 'covered'],
      ['c8 --check-coverage --lines 0 mocha', 'partial'],
      ['c8 --check-coverage mocha', 'partial'],
      ['c8 --lines 80 mocha', 'partial'],
      ['nyc mocha', 'partial'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, cmd);
      expect((await covRow(dir)).status, cmd).toBe(expected);
    }
  });

  it('coverage-min: the minimum is read where the run happens, not in another folder', async () => {
    const py = svc('api', { language: 'python', packageManager: 'pip' });
    const dir = makeTempDir();
    ci(dir, 'pytest --cov=api');               // runs at the repo root
    writeIn(dir, 'api/pyproject.toml', '[tool.coverage.report]\nfail_under = 80\n'); // the minimum sits in api/
    expect((await covRow(dir, [py])).status).toBe('partial');
    const dir2 = makeTempDir();
    wf(dir2, 'ci.yml', `${onBoth}jobs:\n  t:\n    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: api\n    steps:\n      - run: pytest --cov=api\n`);
    writeIn(dir2, 'api/pyproject.toml', '[tool.coverage.report]\nfail_under = 80\n');
    expect((await covRow(dir2, [py])).status).toBe('covered');
  });

  it('coverage-min: a run that cannot fail stays as it was (continue-on-error is not raised by a minimum)', async () => {
    const dir = makeTempDir();
    ci(dir, 'vitest run --coverage --coverage.thresholds.lines=80', '    continue-on-error: true\n');
    expect((await covRow(dir)).status).toBe('partial');
    const py = svc('.', { language: 'python', packageManager: 'pip' });
    const d2 = makeTempDir();
    ci(d2, 'pytest --cov || true');
    writeIn(d2, 'pyproject.toml', '[tool.coverage.report]\nfail_under = 80\n');
    expect((await covRow(d2, [py])).status).toBe('partial');
    const d3 = makeTempDir();
    wf(d3, 'ci.yml', `${onBoth}jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest --cov\n        env:\n          COVERAGE_RCFILE: other.rc\n`);
    writeIn(d3, 'pyproject.toml', '[tool.coverage.report]\nfail_under = 80\n');
    expect((await covRow(d3, [py])).status).toBe('partial'); // COVERAGE_RCFILE swaps the config file
  });

  it('coverage-min (hostile): a symlinked or oversized config → unknown, never covered', async () => {
    const py = svc('.', { language: 'python', packageManager: 'pip' });
    const a = makeTempDir();
    ci(a, 'pytest --cov');
    writeIn(a, 'real.toml', '[tool.coverage.report]\nfail_under = 80\n');
    symlinkSync(join(a, 'real.toml'), join(a, 'pyproject.toml'));
    expect((await covRow(a, [py])).status).toBe('unknown');
    const b = makeTempDir();
    ci(b, 'pytest --cov');
    writeIn(b, 'pyproject.toml', `[tool.coverage.report]\nfail_under = 80\n# ${'x'.repeat(1_100_000)}\n`);
    expect((await covRow(b, [py])).status).toBe('unknown');
    const c = makeTempDir();
    ci(c, 'pytest --cov');
    writeIn(c, 'pyproject.toml', '[tool.coverage.report\nfail_under = 80\n');
    expect((await covRow(c, [py])).status).toBe('unknown');
    const d = makeTempDir();
    ci(d, 'jest --coverage');
    writeIn(d, 'package.json', '{"jest": {"coverageThreshold": {"global": {"lines": 80}}}');
    expect((await covRow(d)).status).toBe('unknown');
    const e = makeTempDir();
    ci(e, 'jest --coverage');
    writeIn(e, 'package.json', JSON.stringify({ jest: { coverageThreshold: JSON.parse('{"__proto__":{"lines":80}}') } }));
    expect((await covRow(e)).status).toBe('partial');
  });

  it('coverage-min: the exported coverageMinimum answers set, none or unknown', async () => {
    const dir = makeTempDir();
    expect(await coverageMinimum(dir, svc('.'))).toBe('none');
    writeIn(dir, 'package.json', JSON.stringify({ jest: { coverageThreshold: { global: { lines: 80 } } } }));
    expect(await coverageMinimum(dir, svc('.'))).toBe('set');
    const js = makeTempDir();
    writeIn(js, 'vite.config.mjs', 'export default { test: { coverage: { thresholds: { lines: 1 } } } }');
    expect(await coverageMinimum(js, svc('.'))).toBe('unknown');
    const link = makeTempDir();
    writeIn(link, 'x.json', '{}');
    symlinkSync(join(link, 'x.json'), join(link, 'package.json'));
    expect(await coverageMinimum(link, svc('.'))).toBe('unknown');
    writeIn(dir, 'sub/pyproject.toml', '[tool.coverage.report]\nfail_under = 50\n');
    expect(await coverageMinimum(dir, svc('sub', { language: 'python' }))).toBe('set');
  });
});

// ---------- publishing ----------

describe('publishing (PB4 a): never "otherwise covered"', () => {
  const pubWf = (dir: string, body: string) => wf(dir, 'release.yml', body);
  const SEC = 'secrets' + '.';
  const PW = 'pass' + 'word';
  const NAT = 'NODE_AUTH' + '_TOKEN';
  const publishNeed = need('publishing', 'deploy');
  async function publish(dir: string): Promise<Coverage> {
    const p = await profileOf(dir);
    return publishingCoverage(p, publishNeed);
  }

  it('publishing: npm publish with a long-lived token secret → partial, saying trusted publishing needs none', async () => {
    const dir = makeTempDir();
    pubWf(dir, `on: push\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          ${NAT}: \${{ ${SEC}NPM_TOKEN }}\n`);
    const r = await publish(dir);
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/publishes with a long-lived token; trusted publishing needs none/);
    expect(r.why).toMatch(/npmjs\.com/);
  });

  it('publishing: the PyPI action with a PYPI token → partial', async () => {
    const dir = makeTempDir();
    pubWf(dir, `on: push\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n        with:\n          ${PW}: \${{ ${SEC}PYPI_API_TOKEN }}\n`);
    expect((await publish(dir)).status).toBe('partial');
  });

  it('publishing: id-token only is never "covered" (trusted publishing is set up on npmjs.com/PyPI, which pipegen can\'t see) → unknown', async () => {
    const dir = makeTempDir();
    pubWf(dir, `on: push\npermissions:\n  id-${'tok' + 'en'}: write\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish --provenance\n`);
    const r = await publish(dir);
    expect(r.status).toBe('unknown');
    expect(r.why).toMatch(/npmjs\.com/);
    expect(r.why).toMatch(/PyPI/);
  });

  it('publishing: some other secret in a publishing workflow → unknown, not covered; no publishing workflow → missing', async () => {
    const dir = makeTempDir();
    pubWf(dir, `on: push\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          SOMETHING: \${{ ${SEC}CUSTOM_KEY }}\n`);
    expect((await publish(dir)).status).toBe('unknown');
    expect((await publish(makeTempDir())).status).toBe('missing');
  });

  it('publishing: through mapCoverage the publishing row takes this decision', async () => {
    const dir = makeTempDir();
    pubWf(dir, `on: push\njobs:\n  p:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          ${NAT}: \${{ ${SEC}NPM_TOKEN }}\n`);
    const p = await profileOf(dir);
    const out = await mapCoverage(p, [publishNeed], dir);
    expect(out[0]?.status).toBe('partial');
    const planned = floorNeeds(p, caps).filter((n) => n.id === 'publishing');
    for (const r of await mapCoverage(p, planned, dir)) expect(r.status).not.toBe('covered');
  });
});

// ---------- module graph ----------

describe('config-checks: module graph (PB1)', () => {
  it('config-checks.ts does not import walk.ts (nor decide/hooks/shell/scripts), at run time', async () => {
    const r = await build({
      entryPoints: [join(import.meta.dirname, '..', 'src/audit/config-checks.ts')], bundle: true, write: false, metafile: true, platform: 'node', format: 'esm', packages: 'external', logLevel: 'silent',
    });
    const files = Object.keys(r.metafile.inputs);
    for (const banned of ['walk', 'decide', 'hooks', 'shell', 'scripts', 'settings', 'signatures']) expect(files, banned).not.toContain(`src/audit/coverage/${banned}.ts`);
    expect(files).not.toContain('src/audit/coverage.ts');
  });
});

// ---------- fix round 1: the review's probes ----------

describe('fix round 1 (review of Task 4)', () => {
  const ci = (dir: string, cmd: string, extra = '') => wf(dir, 'ci.yml', `${onBoth}jobs:\n  t:\n    runs-on: ubuntu-latest\n${extra}    steps:\n      - run: ${cmd}\n`);
  const py = svc('.', { language: 'python', packageManager: 'pip' });
  const PYT = '[tool.coverage.report]\nfail_under = 80\n';
  const JESTPKG = JSON.stringify({ name: 'x', jest: { coverageThreshold: { global: { lines: 80 } } } });
  const VITEST_JS = 'export default {test:{coverage:{thresholds:{lines:80}}}}';
  async function covOf(dir: string, services: Service[] = [svc('.')]): Promise<Coverage> {
    return pick(await rows(dir, { services }), 'merge', 'coverage', services[0]?.name);
  }

  it('1. a symlinked working folder is never followed: the minimum there is unknown, not covered', async () => {
    const other = makeTempDir();
    writeIn(other, 'package.json', JESTPKG);
    const dir = makeTempDir();
    symlinkSync(other, join(dir, 'sub'));
    writeIn(dir, 'package.json', '{"name":"x"}');
    ci(dir, 'npx jest --coverage', '    defaults:\n      run:\n        working-directory: sub\n');
    expect((await covOf(dir)).status).toBe('unknown');
    const ok = makeTempDir();
    writeIn(ok, 'package.json', JESTPKG);
    ci(ok, 'npx jest --coverage');
    expect((await covOf(ok)).status).toBe('covered'); // the control: no link
    expect(await coverageMinimum(dir, svc('sub'))).toBe('unknown');
  });

  it('2. a flag that swaps the config file keeps the run partial', async () => {
    const cases: [string, Service[], () => [string, string][]][] = [
      ['pytest --cov --cov-config=other.ini', [py], () => [['pyproject.toml', PYT]]],
      ['pytest --cov -c other.ini', [py], () => [['pyproject.toml', PYT]]],
      ['coverage report --rcfile=other.ini', [py], () => [['pyproject.toml', PYT]]],
      ['npx jest --coverage --config o.json', [svc('.')], () => [['package.json', JESTPKG]]],
      ['npx jest --coverage -c o.json', [svc('.')], () => [['package.json', JESTPKG]]],
      ['npx jest --coverage --rootDir other', [svc('.')], () => [['package.json', JESTPKG]]],
      ['npx vitest run --coverage --config other.ts --coverage.thresholds.lines=80', [svc('.')], () => [['vitest.config.ts', VITEST_JS]]],
    ];
    for (const [cmd, services, files] of cases) {
      const dir = makeTempDir();
      for (const [f, t] of files()) writeIn(dir, f, t);
      ci(dir, cmd);
      expect((await covOf(dir, services)).status, cmd).toBe('partial');
    }
  });

  it('3. wrapper tools read minimum flags only before the command they wrap', async () => {
    for (const [cmd, expected] of [
      ['npx c8 npm test -- --check-coverage --lines 90', 'partial'],
      ['npx nyc mocha --check-coverage --lines 90', 'partial'],
      ['npx c8 node x.js --coverage.thresholds.lines=90', 'partial'],
      ['coverage run -m pytest --fail-under=90', 'partial'],
      ['npx c8 --check-coverage --lines 90 npm test', 'covered'],
      ['npx c8 --check-coverage --reporter lcov --lines 90 npm test', 'covered'],
      ['npx c8 --check-coverage --lines 0 npm test', 'partial'],
      ['nyc --check-coverage --lines 90 mocha', 'covered'],
    ] as const) {
      const dir = makeTempDir();
      ci(dir, cmd);
      expect((await covOf(dir)).status, cmd).toBe(expected);
    }
  });

  it('4. a minimum flag set to 0 or empty means no minimum; the config file is then ignored', async () => {
    for (const [cmd, services, file, text] of [
      ['pytest --cov --cov-fail-under=0', [py], 'pyproject.toml', PYT],
      ['pytest --cov --cov-fail-under 0', [py], 'pyproject.toml', PYT],
      ['npx jest --coverage --coverageThreshold=\'{}\'', [svc('.')], 'package.json', JESTPKG],
      ['npx jest --coverage --coverageThreshold={"global":{"lines":0}}', [svc('.')], 'package.json', JESTPKG],
      ['npx vitest run --coverage --coverage.thresholds.lines=0', [svc('.')], 'vitest.config.ts', VITEST_JS],
    ] as const) {
      const dir = makeTempDir();
      writeIn(dir, file, text);
      ci(dir, cmd);
      const r = await covOf(dir, [...services]);
      expect(r.status, cmd).toBe('partial');
    }
    const env = makeTempDir();
    writeIn(env, 'pyproject.toml', PYT);
    ci(env, 'pytest --cov', '    env:\n      COVERAGE_RCFILE: other.ini\n');
    expect((await covOf(env, [py])).status).toBe('partial');
  });

  it('5. a Dependabot allow list that limits updates, or an entry with no schedule interval, is not covered', async () => {
    const cd = '    cooldown:\n      default-days: 7\n';
    for (const allow of ['    allow:\n      - dependency-name: "left-pad"\n', '    allow:\n      - dependency-type: "development"\n', '    allow: left-pad\n']) {
      const dir = makeTempDir();
      dep(dir, depFile(upd('npm', '/', allow + cd)));
      expect((await update(dir)).status, allow).toBe('partial');
    }
    const all = makeTempDir();
    dep(all, depFile(upd('npm', '/', '    allow:\n      - dependency-name: "*"\n' + cd)));
    expect((await update(all)).status).toBe('covered');
    const noSchedule = makeTempDir();
    dep(noSchedule, `version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n${cd}`);
    const r = await update(noSchedule);
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/schedule\.interval/);
  });

  it('6. Renovate: rules that disable updates, ignorePaths, a schedule, or a preset that may override the age are not covered', async () => {
    const base = { minimumReleaseAge: '7 days' };
    const cases: unknown[] = [
      { ...base, packageRules: [{ matchPackageNames: ['*'], enabled: false }] },
      { ...base, packageRules: [{ matchPaths: ['**'], enabled: false }] },
      { ...base, packageRules: [{ matchPackageNames: ['*'], ignoreDeps: ['x'] }] },
      { ...base, ignorePaths: ['**'] },
      { ...base, ignoreDeps: ['react'] },
      { ...base, schedule: ['* * 30 2 *'] },
      { ...base, extends: ['config:best-practices'] },
      { ...base, extends: ['config:best-practices'], packageRules: [{ matchPackageNames: ['react'], minimumReleaseAge: '14 days' }] },
    ];
    for (const c of cases) {
      const dir = makeTempDir();
      writeIn(dir, 'renovate.json', JSON.stringify(c));
      expect((await update(dir, {}, true)).status, JSON.stringify(c)).toBe('partial');
    }
    for (const rule of [{ minimumReleaseAge: '7 days' }, { matchPackageNames: ['*'], minimumReleaseAge: '7 days' }]) {
      const dir = makeTempDir();
      writeIn(dir, 'renovate.json', JSON.stringify({ extends: ['config:best-practices'], packageRules: [rule] }));
      expect((await update(dir, {}, true)).status, JSON.stringify(rule)).toBe('covered');
    }
  });

  it('7. ESLint: a range whose lower bound is 9 with only .eslintrc may resolve to 10 and is never covered', () => {
    const lint: Coverage = { need: need('lint', 'merge', 'app'), status: 'covered', by: 'eslint', why: 'The eslint check runs on every pull request.' };
    const profile = (v: string, cfg: Service['quality']['eslintConfig'], fromRange: Service['quality']['fromRange']): RepoProfile => ({
      owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
      services: [svc('.', { quality: { ...emptyServiceQuality(), versions: { eslint: v }, eslintConfig: cfg, fromRange } })], terraformDirs: [], hasCompose: false,
      existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
    });
    const r = versionAdjust([lint], profile('9.0.0', 'eslintrc', ['eslint']))[0];
    expect(r?.status).toBe('partial');
    expect(r?.why).toMatch(/ESLint 10 doesn't read \.eslintrc/);
    // an exact lockfile version of 9: ESLint 9 itself reads only eslint.config.js (Task 9), so it is partial with its own wording
    expect(versionAdjust([lint], profile('9.1.0', 'eslintrc', []))[0]?.why).toMatch(/this will fail/);
  });

  it('8. a package.json in a subfolder no service owns still needs a Dependabot entry (found by a bounded glob)', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'package.json', '{"name":"root"}');
    writeIn(dir, 'web/package.json', '{"name":"web"}');
    writeIn(dir, 'node_modules/dep/package.json', '{}');
    writeIn(dir, 'tools/pyproject.toml', '[project]\nname = "t"\n');
    dep(dir, depFile(upd('npm', '/')));
    expect((await update(dir)).status).toBe('partial');
    dep(dir, depFile(upd('npm', '/'), upd('npm', '/web'), upd('pip', '/tools')));
    expect((await update(dir)).status).toBe('covered');
    dep(dir, depFile(upd('npm', '/'), upd('npm', '/web')));
    expect((await update(dir)).status).toBe('partial'); // the Python folder has no entry
  });
});

// ---------- Plan P Task 9 carry-forwards ----------

describe('Task 9: wording of rows the earlier tasks left rough', () => {
  const ci = (dir: string, cmd: string) => wf(dir, 'ci.yml', `${onBoth}${job(runStep(cmd))}`);
  const lint: Coverage = { need: need('lint', 'merge', 'app'), status: 'covered', by: 'eslint', where: '.github/workflows/ci.yml (job t)', why: 'The eslint check runs on every pull request.' };
  const profileWith = (quality: Partial<Service['quality']>): RepoProfile => ({
    owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'none',
    services: [svc('.', { quality: { ...emptyServiceQuality(), ...quality } })], terraformDirs: [], hasCompose: false,
    existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
  });

  it('coverage override: a minimum turned off by the command line has its own wording, not "set not to fail on findings"', async () => {
    const py = svc('.', { language: 'python', packageManager: 'pip' });
    for (const cmd of ['pytest --cov=pkg --cov-fail-under=0', 'coverage report --fail-under=0', 'npx vitest run --coverage --coverage.thresholds.lines=0']) {
      const dir = makeTempDir();
      ci(dir, cmd);
      const r = pick(await rows(dir, { services: [cmd.startsWith('npx') ? svc('.') : py] }), 'merge', 'coverage');
      expect(r.status, cmd).toBe('partial');
      expect(r.why, cmd).not.toMatch(/set not to fail on findings/);
      expect(r.why, cmd).toMatch(/a flag on its command line turns the minimum off \(0, or not a number\) or swaps the coverage config file, so a drop in coverage can't be counted on to fail it\.$/);
    }
    // a flag that swaps the config file gets the same coverage-specific sentence
    const dir = makeTempDir();
    ci(dir, 'pytest --cov=pkg --cov-config=other.cfg');
    const swapped = pick(await rows(dir, { services: [svc('.', { language: 'python', packageManager: 'pip' })] }), 'merge', 'coverage');
    expect(swapped.status).toBe('partial');
    expect(swapped.why).not.toMatch(/set not to fail on findings/);
    expect(swapped.why).toMatch(/swaps the coverage config file/);
  });

  it('versions: ESLint 9 (exact) with only .eslintrc says this run will fail, and is partial', () => {
    const r = versionAdjust([lint], profileWith({ versions: { eslint: '9.39.5' }, eslintConfig: 'eslintrc' }))[0];
    expect(r?.status).toBe('partial');
    expect(r?.why).toMatch(/ESLint 9 reads eslint\.config\.js, not \.eslintrc, so this will fail with "couldn't find an eslint\.config file" unless ESLINT_USE_FLAT_CONFIG=false is set/);
    expect(r?.why).toMatch(/pipegen can't see that variable/);
    // a flat config, or both, or ESLint 8 (which still reads .eslintrc) stay as they were
    for (const cfg of ['flat', 'both'] as const) expect(versionAdjust([lint], profileWith({ versions: { eslint: '9.39.5' }, eslintConfig: cfg }))[0]?.status).toBe('covered');
    expect(versionAdjust([lint], profileWith({ versions: { eslint: '8.57.1' }, eslintConfig: 'eslintrc' }))[0]?.status).toBe('covered');
    // the range case keeps its own wording (can resolve to 10)
    expect(versionAdjust([lint], profileWith({ versions: { eslint: '9.0.0' }, eslintConfig: 'eslintrc', fromRange: ['eslint'] }))[0]?.why).toMatch(/ESLint 10 doesn't read \.eslintrc/);
  });

  it('frameworks: ESLint on a Vue, Svelte, Astro or Nuxt repo is never a clean pass: the config reading those files is unchecked', () => {
    for (const ui of ['vue', 'svelte', 'astro', 'nuxt'] as const) {
      const p = profileWith({ versions: { eslint: '9.39.5' }, eslintConfig: 'flat', uiFrameworks: [ui] });
      const r = frameworkAdjust([lint], p)[0];
      expect(r?.status, ui).toBe('partial');
      expect(r?.by).toBe('eslint');
      expect(r?.why, ui).toContain("pipegen can't check yet that your ESLint config reads .vue, .svelte and .astro files");
      expect(r?.why, ui).not.toMatch(/not supported/);
      expect(r?.why, ui).toContain(lint.why);
    }
    // not a UI framework of those, or no ESLint config at all, or a missing row: unchanged
    expect(frameworkAdjust([lint], profileWith({ eslintConfig: 'flat', uiFrameworks: ['next'] }))[0]).toEqual(lint);
    expect(frameworkAdjust([lint], profileWith({ eslintConfig: 'none', uiFrameworks: ['vue'] }))[0]).toEqual(lint);
    const missing: Coverage = { ...lint, status: 'missing' };
    expect(frameworkAdjust([missing], profileWith({ eslintConfig: 'flat', uiFrameworks: ['vue'] }))[0]).toEqual(missing);
    // a Biome or other lint tool is not touched
    expect(frameworkAdjust([{ ...lint, by: 'biome' }], profileWith({ eslintConfig: 'flat', uiFrameworks: ['vue'] }))[0]?.status).toBe('covered');
  });

  it('frameworks: through mapCoverage, a Vue repo whose CI runs ESLint reads partial', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', `${onBoth}${job(runStep('npx eslint .'))}`);
    const s = svc('.', { quality: { ...emptyServiceQuality(), versions: { eslint: '9.39.5' }, eslintConfig: 'flat', uiFrameworks: ['vue'] } });
    const r = pick(await rows(dir, { services: [s] }), 'merge', 'lint', 'app');
    expect(r.status).toBe('partial');
    expect(r.why).toMatch(/can't check yet that your ESLint config reads/);
  });
});

describe('Task 9: a missing lockfile is not "not applicable"', () => {
  it('lockfile: a Node service with a package.json but no lockfile keeps new-dependency review and licence checks, missing, with the lockfile reason', async () => {
    const dir = makeTempDir();
    const s = svc('.', { language: 'node', packageManager: undefined });
    const all = await rows(dir, { services: [s] });
    for (const id of ['dependency-review', 'licences']) {
      const r = pick(all, 'merge', id);
      expect(r.status, id).toBe('missing');
      expect(r.why, id).toBe("No lockfile is committed, so new-dependency review and licence checks can't run until one is.");
    }
    // with a lockfile the usual missing text stays
    const withLock = await rows(dir, { services: [svc('.', { packageManager: 'npm' })] });
    expect(pick(withLock, 'merge', 'licences').why).not.toMatch(/No lockfile/);
    // no service with a manifest at all: still not applicable (skipped, no row)
    const none = await rows(dir, { services: [] });
    expect(none.some((r) => r.need.id === 'licences')).toBe(false);
  });
});

// Hand checks 2026-10-29 (ruling P55): the row says whether the wait (cooldown, minimumReleaseAge) is already set, so
// "would add" never tells a repo to set what it has.
describe('update-config: the row says whether the wait is already set (hand checks, P55)', () => {
  it('Dependabot: every entry waits 7 days, but an ecosystem is missing → partial with cooldown "set"; no cooldown → "short"', async () => {
    const dir = makeTempDir();
    wf(dir, 'ci.yml', onBoth + job(runStep('npm test'))); // needs a github-actions entry too
    dep(dir, depFile(upd('npm', '/')));
    expect(await update(dir)).toMatchObject({ status: 'partial', by: 'dependabot', cooldown: 'set' });
    dep(dir, depFile(upd('npm', '/', ''), upd('github-actions', '/', '')));
    expect(await update(dir)).toMatchObject({ status: 'partial', by: 'dependabot', cooldown: 'short' });
  });
  it('Renovate: minimumReleaseAge 7 days → "set" even while the row is partial (app not seen); none → "short"', async () => {
    const dir = makeTempDir();
    writeIn(dir, 'renovate.json', JSON.stringify({ minimumReleaseAge: '7 days' }));
    expect(await update(dir)).toMatchObject({ status: 'partial', by: 'renovate', cooldown: 'set' });
    writeIn(dir, 'renovate.json', JSON.stringify({}));
    expect(await update(dir)).toMatchObject({ status: 'partial', by: 'renovate', cooldown: 'short' });
  });
});
