// v0.2 Plan D, D6 (ruling B2): the producer of the reviewed test tools in package.json + package-lock.json, and the two judges. Offline: npm is
// injected and writes a lock built from the REAL reviewed closure data; the live test (PIPEGEN_LIVE_TESTS=1) runs the real npm.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { CREATED_RULES, createdFileProblems } from '../src/engine/created-files.js';
import { referee, type Linters } from '../src/engine/referee.js';
import { gitBlobSha, guardCreatedFiles, type BaseTree } from '../src/create/guard.js';
import { buildPackageJson } from '../src/create/package-edit.js';
import { planNpmDeps, type NpmRunner } from '../src/create/npm-deps.js';
import { loadReviewedClosure } from '../src/create/reviewed-closure.js';
import { lockEntryProblems, pinOk } from '../src/engine/npm-closure.js';
import { emptyRepoFiles } from '../src/read/quality.js';
import type { Capabilities, CreatedFile, PipelineDraft } from '../src/types.js';
import { packageDataPath } from '../src/util/package-data.js';
import { SecretVault } from '../src/create/secrets.js';
import { withActiveVault } from '../src/util/known-values.js';
import { platform, profile, reviewedList, service } from './helpers/render.js';

const caps: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: true, codeScanning: true, keylessSigningAllowed: true };
const mkDraft = (paths: string[] = ['.'], pm: 'npm' | 'pnpm' = 'npm'): PipelineDraft => ({
  profile: { ...profile(paths.map((p, i) => service({ name: `s${i}`, path: p, packageManager: pm }))), repoFiles: emptyRepoFiles() },
  capabilities: caps, needs: [], steps: [], created: [], notProven: [], testDecisions: [], layersSkipped: [], scoreboard: [], requireDeployApproval: false, skipped: [], suggestions: [],
});
const LINTERS: Linters = { actionlint: async () => '/x', zizmor: async () => '/x' };
const refereeOf = (files: CreatedFile[], d = mkDraft()) => referee(files, d, platform(), reviewedList(), LINTERS, 'tok', { runLinters: async () => [] });

const PJ = '{\n  "name": "app",\n  "version": "1.0.0",\n  "scripts": {\n    "build": "tsc",\n    "test": "echo \\"Error: no test specified\\" && exit 1"\n  },\n  "dependencies": {\n    "express": "4.21.0"\n  },\n  "devDependencies": {\n    "typescript": "5.6.0"\n  }\n}\n';
const expressEntries = { 'node_modules/express': { version: '4.21.0', resolved: 'https://registry.npmjs.org/express/-/express-4.21.0.tgz', integrity: `sha512-${Buffer.from('e'.repeat(64)).toString('base64')}` } };
const LOCK = JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'app', version: '1.0.0', dependencies: { express: '4.21.0' }, devDependencies: { typescript: '5.6.0' } }, ...expressEntries, 'node_modules/typescript': { version: '5.6.0', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.6.0.tgz', integrity: `sha512-${Buffer.from('t'.repeat(64)).toString('base64')}`, dev: true } } }, null, 2) + '\n';

const closureLock = (id: string): { packages: Record<string, Record<string, unknown>> } => JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.json`), 'utf8')) as never;
const before = (id: string): string => (JSON.parse(readFileSync(packageDataPath(`npm-closures/${id}.meta.json`), 'utf8')) as { before: string }).before;

/** A fake npm: records the call and writes the lock npm would write: the original plus every entry of the real closure, marked dev. */
function fakeNpm(): { runner: NpmRunner; calls: { cwd: string; argv: readonly string[]; env: Record<string, string>; files: string[]; pj: string }[] } {
  const calls: { cwd: string; argv: readonly string[]; env: Record<string, string>; files: string[]; pj: string }[] = [];
  const runner: NpmRunner = (cwd, argv, env) => {
    const pj = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as { devDependencies: Record<string, string> };
    calls.push({ cwd, argv, env: { ...env }, files: execFileSync('ls', ['-A', cwd], { encoding: 'utf8' }).split('\n').filter(Boolean), pj: readFileSync(join(cwd, 'package.json'), 'utf8') });
    const lock = JSON.parse(readFileSync(join(cwd, 'package-lock.json'), 'utf8')) as { packages: Record<string, Record<string, unknown>> };
    const root = lock.packages[''] as { devDependencies: Record<string, string> };
    root.devDependencies = Object.fromEntries(Object.entries(pj.devDependencies).sort(([a], [b]) => (a < b ? -1 : 1)));
    for (const id of ['vitest' in pj.devDependencies ? 'vitest-coverage' : 'c8']) {
      for (const [k, e] of Object.entries(closureLock(id).packages)) if (k !== '' && lock.packages[k] === undefined) lock.packages[k] = { ...e, dev: true };
    }
    writeFileSync(join(cwd, 'package-lock.json'), `${JSON.stringify(lock, null, 2)}\n`);
    return { status: 0, output: '' };
  };
  return { runner, calls };
}
const plan = (over: Partial<Parameters<typeof planNpmDeps>[0]> = {}) => planNpmDeps({ service: { path: '.', packageManager: 'npm' }, tool: 'vitest', packageJson: PJ, packageLock: LOCK, reviewed: reviewedList(), runner: fakeNpm().runner, ...over });

const made: string[] = [];
afterEach(() => { for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true }); });
function repoDir(files: Record<string, string>): { root: string; base: BaseTree } {
  const root = mkdtempSync(join(tmpdir(), 'pipegen-d6-'));
  made.push(root);
  for (const [p, t] of Object.entries(files)) { mkdirSync(join(root, dirname(p)), { recursive: true }); writeFileSync(join(root, p), t); }
  return { root, base: { complete: true, entries: new Map(Object.entries(files).map(([p, t]) => [p, { sha: gitBlobSha(t), mode: '100644', read: async () => t }])) } };
}

describe('npm-deps: the producer', () => {
  it('npm-deps: adds only vitest 5.0.5 + @vitest/coverage-v8 5.0.5 (starter tests / vitest coverage) or c8 12.0.0 (node:test coverage), only when absent; existing version never changed', () => {
    const v = plan();
    expect(v.notes).toEqual([]);
    expect(v.files.map((f) => f.path)).toEqual(['package.json', 'package-lock.json']);
    const pj = JSON.parse((v.files[0] as CreatedFile).content) as { devDependencies: Record<string, string>; scripts: Record<string, string> };
    expect(pj.devDependencies).toEqual({ typescript: '5.6.0', '@vitest/coverage-v8': '5.0.5', vitest: '5.0.5' });
    expect(pj.scripts).toEqual({ build: 'tsc', test: 'vitest run' });
    const c = plan({ tool: 'c8' });
    const cj = JSON.parse((c.files[0] as CreatedFile).content) as { devDependencies: Record<string, string>; scripts: Record<string, string> };
    expect(cj.devDependencies).toEqual({ typescript: '5.6.0', c8: '12.0.0' });
    expect(cj.scripts.test).toBe('echo "Error: no test specified" && exit 1');   // c8 wraps the repo's own test command; the script is not touched
    // only when absent: vitest already at 5.0.5 -> only the coverage plugin; both there -> nothing
    const withVitest = PJ.replace('"typescript": "5.6.0"', '"typescript": "5.6.0",\n    "vitest": "5.0.5"');
    const only = plan({ packageJson: withVitest });
    expect(only.notes).toEqual([]);
    expect(JSON.parse((only.files[0] as CreatedFile).content).devDependencies).toEqual({ typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' });
    expect(plan({ packageJson: withVitest.replace('"vitest": "5.0.5"', '"vitest": "5.0.5",\n    "@vitest/coverage-v8": "5.0.5"').replace('echo \\"Error: no test specified\\" && exit 1', 'jest') })).toEqual({ files: [], notes: [] });
    expect(plan({ tool: 'c8', packageJson: PJ.replace('"typescript": "5.6.0"', '"c8": "12.0.0"') })).toEqual({ files: [], notes: [] });
    // another vitest / c8 / coverage plugin: never changed, a not-proven note
    for (const [pjText, tool, re] of [
      [PJ.replace('"typescript": "5.6.0"', '"vitest": "^3.0.0"'), 'vitest', /pipegen's reviewed Vitest is 5\.0\.5/],
      [PJ.replace('"express": "4.21.0"', '"vitest": "5.0.5"'), 'vitest', /pipegen's reviewed Vitest is 5\.0\.5/],
      [PJ.replace('"typescript": "5.6.0"', '"@vitest/coverage-v8": "5.0.4"'), 'vitest', /coverage-v8/],
      [PJ.replace('"typescript": "5.6.0"', '"c8": "10.0.0"'), 'c8', /reviewed c8 is 12\.0\.0/],
    ] as const) {
      const r = plan({ packageJson: pjText, tool });
      expect(r.files, pjText).toEqual([]);
      expect(r.notes.join(' ')).toMatch(re);
    }
    // a service folder: paths follow it
    const sub = plan({ service: { path: './api/', packageManager: 'npm' } });
    expect(sub.files.map((f) => f.path)).toEqual(['api/package.json', 'api/package-lock.json']);
    // no devDependencies and no scripts yet: both objects are added
    const bareLock = JSON.parse(LOCK) as { packages: Record<string, Record<string, unknown>> };
    bareLock.packages[''] = { name: 'app', version: '1.0.0' };
    delete bareLock.packages['node_modules/typescript']; delete bareLock.packages['node_modules/express'];
    const bare = plan({ packageJson: '{\n  "name": "app",\n  "version": "1.0.0"\n}\n', packageLock: `${JSON.stringify(bareLock, null, 2)}\n` });
    expect(bare.notes).toEqual([]);
    expect((bare.files[0] as CreatedFile).content).toBe('{\n  "name": "app",\n  "version": "1.0.0",\n  "scripts": {\n    "test": "vitest run"\n  },\n  "devDependencies": {\n    "@vitest/coverage-v8": "5.0.5",\n    "vitest": "5.0.5"\n  }\n}\n');
  });

  it('npm-deps: lock generated in a temp copy with empty npm configs, --package-lock-only --ignore-scripts --before=<now−7d> --registry=https://registry.npmjs.org/ (--before from the closure meta, D1 carry)', () => {
    const f = fakeNpm();
    const r = plan({ runner: f.runner });
    expect(r.files).toHaveLength(2);
    const call = f.calls[0] as (typeof f.calls)[number];
    expect(call.argv).toEqual(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact', `--before=${before('vitest-coverage')}`, '--registry=https://registry.npmjs.org/']);
    // the date is the reviewed closure's, not now - 7 days
    expect(call.argv.find((a) => a.startsWith('--before='))).toBe('--before=2026-10-26T13:51:56.914Z');
    // a temp folder with only the two files, and empty user and global npm configs
    expect(call.files.sort()).toEqual(['package-lock.json', 'package.json']);
    expect(call.cwd).not.toBe(process.cwd());
    expect(call.pj).toBe((r.files[0] as CreatedFile).content);   // the NEW package.json is what npm resolves
    expect(Object.keys(call.env).sort()).toEqual(['HOME', 'PATH', 'npm_config_globalconfig', 'npm_config_userconfig']);
    expect(call.env.npm_config_userconfig).not.toBe(call.env.npm_config_globalconfig);
    expect(call.env.HOME?.startsWith(dirname(call.cwd))).toBe(true);
    expect(() => readFileSync(call.cwd)).toThrow();   // the temp folder is removed afterwards
    const c8 = fakeNpm();
    plan({ tool: 'c8', runner: c8.runner });
    expect(c8.calls[0]?.argv).toContain(`--before=${before('c8')}`);
    // a failing npm, or a lock the judge does not accept: nothing written, a note
    const failing = plan({ runner: () => ({ status: 1, output: 'E404 private registry' }) });
    expect(failing.files).toEqual([]);
    expect(failing.notes.join(' ')).toMatch(/npm could not generate the lockfile/);
    const forged = plan({ runner: (cwd) => { writeFileSync(join(cwd, 'package-lock.json'), LOCK.replace('"typescript": "5.6.0"\n    }', '"typescript": "5.6.0",\n      "vitest": "5.0.5"\n    }')); return { status: 0, output: '' }; } });
    expect(forged.files).toEqual([]);
    expect(forged.notes.join(' ')).toMatch(/not provably the reviewed one/);
    // the date: a meta without a usable one
    expect(plan({ closureBefore: () => 'yesterday' }).files).toHaveLength(2);   // injected dates are the caller's; the default reader validates
  });

  it('npm-deps: workspace member or no service-level package-lock.json → not-proven note', () => {
    const notes = (over: Parameters<typeof plan>[0]) => plan(over).notes;
    expect(notes({ workspaceMember: true })[0]).toMatch(/workspace/);
    expect(notes({ packageLock: null })[0]).toMatch(/no package-lock\.json of its own/);
    expect(notes({ packageJson: PJ.replace('"scripts"', '"workspaces": ["a"],\n  "scripts"') })[0]).toMatch(/workspaces/);
    expect(notes({ service: { path: '.', packageManager: 'pnpm' } })[0]).toMatch(/does not use npm/);
    expect(notes({ packageJson: PJ.replace('"scripts"', '"packageManager": "yarn@4.0.0",\n  "scripts"') })[0]).toMatch(/other than npm/);
    expect(notes({ packageJson: '{"a":1,"a":2}' })[0]).toMatch(/plain JSON/);
    for (const over of [{ workspaceMember: true }, { packageLock: null }]) expect(plan(over).files).toEqual([]);
    expect(plan({ runner: () => { throw new Error('boom'); } }).notes[0]).toMatch(/could not be generated/);
  });

  it('npm-deps: every edit needsConfirm', () => {
    const r = plan();
    expect(r.files.every((f) => f.needsConfirm === true && f.part === 'tests' && f.repo === 'app' && f.edited?.original !== undefined)).toBe(true);
    expect((r.files[0] as CreatedFile).edited?.original).toBe(PJ);
    expect((r.files[1] as CreatedFile).edited?.original).toBe(LOCK);
    // the registry demands it whoever wrote the file
    const rule = CREATED_RULES.filter((x) => x.id === 'package-json' || x.id === 'package-lock');
    expect(rule.map((x) => x.needsConfirm)).toEqual([true, true]);
    const noConfirm = r.files.map((f) => ({ ...f, needsConfirm: false }));
    for (const f of noConfirm) expect(createdFileProblems(f, mkDraft(), CREATED_RULES, { reviewed: reviewedList(), inputs: {}, files: noConfirm }).problems.join(' ')).toMatch(/confirmation/);
  });

  it('npm-deps: real producer output passes the referee and the guard (D0a review rule)', async () => {
    const r = plan();
    const rep = await refereeOf(r.files);
    expect(rep.issues.map((i) => `${i.check}: ${i.message}`)).toEqual([]);
    expect(rep.ok).toBe(true);
    const { root, base } = repoDir({ 'package.json': PJ, 'package-lock.json': LOCK });
    const g = await guardCreatedFiles(r.files, { root, baseTree: base, installRecord: null, profile: mkDraft().profile, closure: loadReviewedClosure(reviewedList()) });
    expect(g.refused).toEqual([]);
    expect(g.ok.map((f) => f.path)).toEqual(['package.json', 'package-lock.json']);
    // a service folder too
    const sub = plan({ service: { path: 'api', packageManager: 'npm' } });
    const d2 = mkDraft(['api']);
    expect((await refereeOf(sub.files, d2)).ok).toBe(true);
    const r2 = repoDir({ 'api/package.json': PJ, 'api/package-lock.json': LOCK });
    expect((await guardCreatedFiles(sub.files, { root: r2.root, baseTree: r2.base, installRecord: null, profile: d2.profile, closure: loadReviewedClosure(reviewedList()) })).refused).toEqual([]);
    // c8 as well
    const c = plan({ tool: 'c8' });
    expect((await refereeOf(c.files)).ok).toBe(true);
  });
});

describe('D6 fix round 1', () => {
  it('m4: lockEntryProblems scrubs with the active vault before it cuts: 0 four-char pieces of a value across a cut point', () => {
    const value = 'zzvaultvalue98765qwerty';
    const vault = new SecretVault();
    vault.set('K_LOCK', value);
    const pieces = (shown: string): void => { for (let k = 0; k + 4 <= value.length; k++) expect(shown, value.slice(k, k + 4)).not.toContain(value.slice(k, k + 4)); };
    const ok = { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity: `sha512-${Buffer.from('a'.repeat(64)).toString('base64')}` };
    for (const pad of [0, 30, 55, 66, 70, 75]) {
      const key = `node_modules/${'k'.repeat(pad)}${value}`;
      const shown = withActiveVault(vault, () => lockEntryProblems(key, 42).join(' | '));
      expect(shown.length).toBeGreaterThan(0);
      pieces(shown);
      const keyed = withActiveVault(vault, () => lockEntryProblems(key, { ...ok, version: 'x' }).join(' | '));
      pieces(keyed);
      const bundled = withActiveVault(vault, () => lockEntryProblems(key, { ...ok, link: true }).join(' | '));
      pieces(bundled);
    }
    for (const pad of [0, 10, 25, 33, 38, 45]) {
      const spec = `${'s'.repeat(pad)}${value}`;
      const shown = withActiveVault(vault, () => lockEntryProblems('node_modules/a', { ...ok, dependencies: { b: `git+https://x/${spec}` } }).join(' | '));
      expect(shown.length).toBeGreaterThan(0);
      pieces(shown);
    }
    // without a vault nothing changes
    expect(lockEntryProblems('node_modules/a', { ...ok, dependencies: { b: 'npm:evil@1' } }).join(' ')).toMatch(/npm:evil@1/);
  });
  it('m4: the producer\'s not-proven notes quote no judge text (a fixed sentence)', () => {
    const value = 'zzvaultvalue98765qwerty';
    const vault = new SecretVault();
    vault.set('K_LOCK', value);
    const evil = plan({ runner: (cwd) => { const l = JSON.parse(readFileSync(join(cwd, 'package-lock.json'), 'utf8')) as { packages: Record<string, unknown> }; l.packages[`node_modules/${value}`] = { version: '1.0.0' }; writeFileSync(join(cwd, 'package-lock.json'), JSON.stringify(l)); return { status: 0, output: '' }; } });
    const note = withActiveVault(vault, () => evil.notes.join(' '));
    expect(evil.files).toEqual([]);
    expect(note).toMatch(/not provably the reviewed one/);
    expect(note).not.toContain(value.slice(0, 8));
  });
  it('m8: vitest and the coverage plugin already at 5.0.5 with npm\'s default scripts.test: scripts.test is set (package.json edit, lock unchanged), through the referee and the guard', async () => {
    const both = PJ.replace('"typescript": "5.6.0"', '"typescript": "5.6.0",\n    "vitest": "5.0.5",\n    "@vitest/coverage-v8": "5.0.5"');
    const lock = JSON.parse(LOCK) as { packages: Record<string, Record<string, unknown>> };
    lock.packages[''] = { ...lock.packages[''], devDependencies: { typescript: '5.6.0', vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' } };
    for (const [id] of [['vitest-coverage']]) for (const [k, e] of Object.entries(closureLock(id as string).packages)) if (k !== '' && lock.packages[k] === undefined) lock.packages[k] = { ...e, dev: true };
    const lockText = `${JSON.stringify(lock, null, 2)}\n`;
    const calls: number[] = [];
    const r = plan({ packageJson: both, packageLock: lockText, runner: () => { calls.push(1); return { status: 1, output: '' }; } });
    expect(calls).toEqual([]);   // npm is not needed: only a script changes
    expect(r.notes).toEqual([]);
    expect(r.files.map((f) => f.path)).toEqual(['package.json', 'package-lock.json']);
    expect(JSON.parse((r.files[0] as CreatedFile).content).scripts.test).toBe('vitest run');
    expect((r.files[0] as CreatedFile).content).toBe(both.replace('"test": "echo \\"Error: no test specified\\" && exit 1"', '"test": "vitest run"'));
    expect((r.files[1] as CreatedFile).content).toBe(lockText);
    expect((await refereeOf(r.files)).issues.map((i) => i.message)).toEqual([]);
    const { root, base } = repoDir({ 'package.json': both, 'package-lock.json': lockText });
    expect((await guardCreatedFiles(r.files, { root, baseTree: base, installRecord: null, profile: mkDraft().profile, closure: loadReviewedClosure(reviewedList()) })).refused).toEqual([]);
    // already set to something else, or already vitest run: nothing to do
    expect(plan({ packageJson: both.replace('echo \\"Error: no test specified\\" && exit 1', 'jest'), packageLock: lockText })).toEqual({ files: [], notes: [] });
    expect(plan({ packageJson: both.replace('echo \\"Error: no test specified\\" && exit 1', 'vitest run'), packageLock: lockText })).toEqual({ files: [], notes: [] });
  });
});

describe('npm-deps: the package.json judge rebuilds the exact text', () => {
  const judge = (original: string, content: string, d = mkDraft()) => createdFileProblems({ path: 'package.json', content, part: 'tests', reason: 't', repo: 'app', needsConfirm: true, edited: { original } }, d, CREATED_RULES, { reviewed: reviewedList(), inputs: {} }).problems;
  const good = (plan().files[0] as CreatedFile).content;
  it('the producer text passes; the rebuilt text is byte-equal for many layouts (2 spaces, 4 spaces, tabs, compact, CRLF, no trailing newline)', () => {
    expect(judge(PJ, good)).toEqual([]);
    const layouts = [JSON.stringify(JSON.parse(PJ), null, 2), JSON.stringify(JSON.parse(PJ), null, 4) + '\n', JSON.stringify(JSON.parse(PJ), null, '\t') + '\n', JSON.stringify(JSON.parse(PJ)), JSON.stringify(JSON.parse(PJ), null, 2).replace(/\n/g, '\r\n') + '\r\n',
      JSON.stringify({ name: 'a' }, null, 2) + '\n', JSON.stringify({ name: 'a', scripts: {}, devDependencies: {} }, null, 2) + '\n', JSON.stringify({ name: 'a', scripts: { test: 'echo "Error: no test specified" && exit 1' } }, null, 2) + '\n', JSON.stringify({ name: 'a', "key with \"quote\"": 1 }, null, 2) + '\n'];
    for (const original of layouts) {
      const out = buildPackageJson(original, { add: { vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' }, setTest: true });
      expect(out, original).not.toBeNull();
      const parsed = JSON.parse(out as string) as { devDependencies: object; scripts: { test: string } };
      expect(parsed.devDependencies).toMatchObject({ vitest: '5.0.5', '@vitest/coverage-v8': '5.0.5' });
      expect(parsed.scripts.test).toBe('vitest run');
      expect(judge(original, out as string), original).toEqual([]);
      // only insertions: the original text minus nothing but the default test value
      expect(judge(original, (out as string).replace(/\n$/, '') + (original.endsWith('\n') ? '\n' : ''))).toEqual(judge(original, out as string));
    }
  });
  it('buildPackageJson gives null where it can not edit in place: not an object, empty, a non-default test value, an odd layout', () => {
    const add = { vitest: '5.0.5' };
    for (const bad of ['', '[]', '{}', '{ }', 'null', '"x"', '{"a":1,"a":2}', '{"name":"a","scripts":{"test":"jest"}}', '{"name":"a","scripts":[]}', '{"name":"a","devDependencies":[]}', '{"name":"a","devDependencies":"x"}', '/*c*/{"name":"a"}']) expect(buildPackageJson(bad, { add, setTest: bad.includes('jest') || bad.includes('scripts') }), bad).toBeNull();
    expect(buildPackageJson('{"name":"a"}', { add: { evil: '1.0.0' }, setTest: false })).toBeNull();
    expect(buildPackageJson('{"name":"a"}', { add, setTest: false })).toBe('{"name":"a","devDependencies":{"vitest":"5.0.5"}}');
  });
  it('anything but that exact text is refused: spacing, a reordered devDependencies, a changed byte elsewhere, a no-op', () => {
    const variants: [string, string][] = [
      ['reformatted (4 spaces)', JSON.stringify(JSON.parse(good), null, 4) + '\n'],
      ['compact', JSON.stringify(JSON.parse(good))],
      ['no trailing newline', good.replace(/\n$/, '')],
      ['an extra blank line', good.replace('"scripts"', '\n  "scripts"')],
      ['a space before a colon', good.replace('"vitest":', '"vitest" :')],
      ['entries first', good.replace('"typescript": "5.6.0",\n    "@vitest/coverage-v8": "5.0.5",\n    "vitest": "5.0.5"', '"@vitest/coverage-v8": "5.0.5",\n    "vitest": "5.0.5",\n    "typescript": "5.6.0"')],
      ['entries unsorted', good.replace('"@vitest/coverage-v8": "5.0.5",\n    "vitest": "5.0.5"', '"vitest": "5.0.5",\n    "@vitest/coverage-v8": "5.0.5"')],
      ['an escaped name', good.replace('"vitest":', '"v\\u0069test":')],
      ['a trailing byte', `${good}\n`],
      ['a BOM', `\uFEFF${good}`],
      ['a changed version', good.replace('"vitest": "5.0.5"', '"vitest": "5.0.6"')],
      ['the test value spelled differently', good.replace('"vitest run"', '"vitest  run"')],
    ];
    for (const [what, content] of variants) expect(judge(PJ, content).length, what).toBeGreaterThan(0);
    expect(judge(PJ, PJ).join(' ')).toMatch(/does not change anything/);
    // a hidden second change that packageJsonProblems alone would let through is still refused by the byte compare
    expect(packageJsonProblemsClean(PJ, good.replace('"name": "app",', '"name": "app", '))).toBe(true);
    expect(judge(PJ, good.replace('"name": "app",', '"name": "app", ')).join(' ')).toMatch(/not the original text/);
    // no original, or not an npm service
    expect(judge('', good).join(' ')).toMatch(/original text is missing/);
    expect(judge(PJ, good, mkDraft(['.'], 'pnpm')).join(' ')).toMatch(/not an npm service/);
  });
  it('text shown by the judge goes through the active vault', () => {
    const vault = new SecretVault();
    vault.set('K_PKG', 'zz-vault-value-98765');
    const bad = good.replace('"build": "tsc"', '"zz-vault-value-98765": "tsc"');
    const shown = withActiveVault(vault, () => judge(PJ, bad).join(' '));
    expect(shown.length).toBeGreaterThan(0);
    expect(shown).not.toContain('zz-vault-value-98765');
  });
});
const packageJsonProblemsClean = (a: string, b: string): boolean => {
  const { packageJsonProblems } = require_pr();
  return packageJsonProblems(a, b).length === 0;
};
import * as PR from '../src/create/package-rules.js';
function require_pr(): typeof PR { return PR; }

describe('npm-deps: the lock judge', () => {
  const generated = plan();
  const pkgFile = generated.files[0] as CreatedFile;
  const lockFile = generated.files[1] as CreatedFile;
  const OTHER = Object.keys((JSON.parse(lockFile.content) as { packages: object }).packages).find((k) => /^node_modules\/[a-z]+$/.test(k) && !['node_modules/vitest', 'node_modules/express', 'node_modules/typescript'].includes(k)) as string;
  const judge = (content: string, files: CreatedFile[] = [pkgFile], over: Partial<CreatedFile> = {}) => createdFileProblems({ ...lockFile, content, ...over }, mkDraft(), CREATED_RULES, { reviewed: reviewedList(), inputs: {}, files }).problems.join(' | ');
  const edit = (change: (l: { packages: Record<string, Record<string, unknown>> }) => void): string => { const l = JSON.parse(lockFile.content) as { packages: Record<string, Record<string, unknown>> }; change(l); return JSON.stringify(l, null, 2) + '\n'; };
  it('npm-deps: lock judge — existing entries deep-equal, new entries registry tarball + sha512, no link/inBundle/hasShrinkwrap, reviewed pins at top-level with reviewed integrity (same predicate as NPM_PRECHECK_JS)', () => {
    expect(judge(lockFile.content)).toBe('');
    expect(judge(edit((l) => { (l.packages['node_modules/express'] as Record<string, unknown>).version = '4.21.1'; }))).toMatch(/express/);
    expect(judge(edit((l) => { delete l.packages['node_modules/express']; }))).toMatch(/express/);
    expect(judge(edit((l) => { (l.packages['node_modules/typescript'] as Record<string, unknown>).dev = false; }))).toMatch(/typescript/);
    expect(judge(edit((l) => { (l.packages['node_modules/vitest'] as Record<string, unknown>).resolved = 'https://evil.example/vitest-5.0.5.tgz'; }))).toMatch(/vitest/);
    expect(judge(edit((l) => { (l.packages['node_modules/vitest'] as Record<string, unknown>).integrity = 'sha1-abc'; }))).toMatch(/vitest/);
    expect(judge(edit((l) => { (l.packages['node_modules/vitest'] as Record<string, unknown>).integrity = `sha512-${Buffer.from('x'.repeat(64)).toString('base64')}`; }))).toMatch(/integrity|reviewed/);
    for (const f of ['link', 'inBundle', 'hasShrinkwrap']) expect(judge(edit((l) => { (l.packages[OTHER] as Record<string, unknown>)[f] = true; })), f).toMatch(new RegExp(OTHER.replace('node_modules/', '')));
    expect(judge(edit((l) => { l.packages['node_modules/evil'] = { ...(l.packages[OTHER] as object), version: '1.0.0' }; }))).toMatch(/evil/);
    expect(judge(edit((l) => { (l.packages['node_modules/@vitest/coverage-v8'] as Record<string, unknown>).name = 'other'; }))).toMatch(/coverage-v8/);
    expect(judge(edit((l) => { (l.packages['node_modules/vitest'] as Record<string, unknown>).devOptional = true; }))).toMatch(/vitest/);
    // the root devDependencies must be the package.json's
    expect(judge(edit((l) => { delete (l.packages[''] as { devDependencies: Record<string, string> }).devDependencies.vitest; }))).toMatch(/vitest|agree/);
    // the lock must agree with the package.json of the batch (here the package.json lacks the coverage plugin the lock adds)
    const pkgLess = { ...pkgFile, content: pkgFile.content.replace('    "@vitest/coverage-v8": "5.0.5",\n', '') };
    expect(pkgLess.content).not.toBe(pkgFile.content);
    expect(judge(lockFile.content, [pkgLess])).toMatch(/do not agree/);
    // a pin that is an alias of another package (name field) is refused with the CI precheck's own words, whatever else differs
    expect(judge(edit((l) => { (l.packages['node_modules/vitest'] as Record<string, unknown>).name = 'other'; }))).toMatch(/CI precheck/);
    // without the package.json in the batch, or without the original, or in a non-npm service
    expect(judge(lockFile.content, [])).toMatch(/same batch/);
    expect(judge(lockFile.content, [pkgFile], { edited: { original: '' } })).toMatch(/original text is missing/);
    expect(createdFileProblems(lockFile, mkDraft(['.'], 'pnpm'), CREATED_RULES, { reviewed: reviewedList(), inputs: {}, files: [pkgFile] }).problems.join(' ')).toMatch(/not an npm service/);
    expect(judge(`${lockFile.content}${' '.repeat(9 * 1024 * 1024)}`)).toMatch(/over 8 MiB/);
    // an edit that adds nothing of the reviewed set is still the user's lock unchanged: fine only with an unchanged package.json (no-op)
    // the predicate is the CI precheck's: the same function, embedded in the rendered step
    const snap = readFileSync(join(import.meta.dirname, '__snapshots__/steps/cli-npm-repo-code.yml'), 'utf8');
    expect(snap).toContain(`const pinOk = ${pinOk.toString().replace(/^function pinOk/, 'function').replace(/\s*\n\s*/g, ' ')};`);
    const w = { name: 'vitest', version: '5.0.5', resolved: 'https://registry.npmjs.org/vitest/-/vitest-5.0.5.tgz', integrity: 'sha512-x' };
    const good = { version: '5.0.5', resolved: w.resolved, integrity: 'sha512-x' };
    expect(pinOk(good, w)).toBe(true);
    for (const bad of [undefined, { ...good, link: true }, { ...good, inBundle: true }, { ...good, name: 'other' }, { ...good, version: '5.0.6' }, { ...good, resolved: 'https://x/y.tgz' }, { ...good, integrity: 'sha512-y' }]) expect(pinOk(bad, w), JSON.stringify(bad)).toBe(false);
    expect(pinOk({ ...good, name: 'vitest' }, w)).toBe(true);
  });
  it('without a reviewed closure every lock edit is refused (the loader is not skipped)', () => {
    expect(loadReviewedClosure(reviewedList())).not.toBeNull();
    expect(loadReviewedClosure([])).toBeNull();
  });
});

// the live check (network: the npm registry only; PIPEGEN_LIVE_TESTS=1): the real npm, then the referee and the guard on its output
describe.skipIf(process.env.PIPEGEN_LIVE_TESTS !== '1')('npm-deps: the real npm (live)', () => {
  it('real npm 11 output for vitest and for c8 passes the lock judge, the referee and the guard', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pipegen-d6-live-'));
    made.push(dir);
    const home = join(dir, 'h'); mkdirSync(home);
    const PJ_LIVE = PJ.replace('5.6.0', '5.6.2');   // 5.6.0 was never published
    writeFileSync(join(dir, 'package.json'), PJ_LIVE);
    execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/'], { cwd: dir, env: { PATH: process.env.PATH ?? '', HOME: home }, stdio: 'pipe' });
    const lock = readFileSync(join(dir, 'package-lock.json'), 'utf8');
    for (const tool of ['vitest', 'c8'] as const) {
      const r = planNpmDeps({ service: { path: '.', packageManager: 'npm' }, tool, packageJson: PJ_LIVE, packageLock: lock, reviewed: reviewedList() });
      expect(r.notes).toEqual([]);
      expect(r.files).toHaveLength(2);
      expect((await refereeOf(r.files)).issues).toEqual([]);
      const { root, base } = repoDir({ 'package.json': PJ_LIVE, 'package-lock.json': lock });
      expect((await guardCreatedFiles(r.files, { root, baseTree: base, installRecord: null, profile: mkDraft().profile, closure: loadReviewedClosure(reviewedList()) })).refused).toEqual([]);
    }
  }, 280_000);
});
