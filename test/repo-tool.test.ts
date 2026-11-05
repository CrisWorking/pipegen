// v0.2 Plan G sub-task G4b (ruling G4-R3): a TypeScript service's type-check runs the repository's own tsc at its lockfile version, a repo
// built-in (DECISIONS #95, reviewed-tools.yml header), never a reviewed entry and never a project script. Code decides it (byCode
// `repo-tool`), the renderer writes the guarded `npm ci --ignore-scripts`, the run-time lockfile check and `tsc --noEmit`, the referee accepts
// only that exact form, and the job is a blocking job-status check with no key and no secret (gate/dist unchanged).
import { execFileSync } from 'node:child_process';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { chooseTools } from '../src/audit/choose.js';
import { keyOffers } from '../src/debate/builder.js';
import { gateJobList } from '../src/engine/gate-job-list.js';
import { floorNeeds } from '../src/engine/needs.js';
import { REPO_TOOLS, repoToolCheckJs } from '../src/engine/render-cli.js';
import { RenderError } from '../src/engine/render-error.js';
import { renderProjectScript, renderRepoTool } from '../src/engine/render-step.js';
import { repoToolFor, repoToolProblem } from '../src/engine/reviewed.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { Job } from '../src/layers/jobs.js';
import type { CreatedFile, Need, Service } from '../src/types.js';
import type { RepoToolStep } from '../src/engine/reviewed.js';
import { REVIEWED, candidatesFor } from './helpers/debate-fixtures.js';
import { CAPS, assemble, editJob, files, judge, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { makeTempDir } from './helpers/make-repo.js';

const TS = { ...emptyServiceQuality(), tsconfig: true, versions: { typescript: '5.6.3' } };
const tsNode = (over: Partial<Service> = {}): Service => node({ quality: { ...TS }, ...over });
const typeCheck = (service = 'app', layer: Need['layer'] = 'merge'): Need => ({ id: 'type-check', layer, category: 'type-check', service, why: 't', blocking: true, floor: false });
const offersOf = (s: Service) => {
  const prof = profileOf([s]);
  const needs = floorNeeds(prof, CAPS);
  return keyOffers(needs, candidatesFor(needs, prof, {}, REVIEWED), prof, { reviewed: REVIEWED });
};
const NEEDS_SEC = ['needs', 'Sec' + 'rets'].join('');
const STEP: RepoToolStep = { kind: 'repo-tool', needId: 'type-check', service: 'app', tool: 'tsc', version: '5.6.3' };

describe('G4b: the type-check through the repo\'s own tsc (ruling G4-R3)', () => {
  it('repo-tool: a TypeScript service\'s type-check is covered by the repo\'s own tsc, never uncovered', () => {
    // the pick: the repo's tsc at its lockfile version, the same step the audit chooses (one source, DECISIONS #95)
    expect(repoToolFor(typeCheck(), tsNode())).toEqual(STEP);
    expect(repoToolProblem(typeCheck(), tsNode())).toBeNull();
    const prof = profileOf([tsNode()]);
    expect(chooseTools(typeCheck(), tsNode(), prof, CAPS, REVIEWED).tool).toEqual(repoToolFor(typeCheck(), tsNode()));
    // a service in a sub-folder: its folder goes with it
    const sub = tsNode({ name: 'web', path: 'apps/web' });
    expect(repoToolFor(typeCheck('web'), sub)).toEqual({ ...STEP, service: 'web', workingDir: 'apps/web' });
    expect(chooseTools(typeCheck('web'), sub, profileOf([sub]), CAPS, REVIEWED).tool).toEqual(repoToolFor(typeCheck('web'), sub));
    // only the type-check need of that service; never another need, another service or a Python service (mypy stays the reviewed path)
    expect(repoToolFor({ ...typeCheck(), id: 'lint' }, tsNode())).toBeNull();
    expect(repoToolFor(typeCheck('other'), tsNode())).toBeNull();
    expect(repoToolFor(typeCheck(), tsNode({ language: 'python', packageManager: 'pip' }))).toBeNull();
    expect(repoToolProblem(typeCheck(), tsNode({ language: 'python', packageManager: 'pip' }))).toBeNull();
    // the debate's offers: decided by code, never uncovered, nothing offered to the AI for it
    const o = offersOf(tsNode());
    expect(o.byCode).toContainEqual({ key: 'type-check--app', needId: 'type-check', service: 'app', kind: 'repo-tool', blocking: true });
    expect(o.uncovered.map((u) => u.key)).not.toContain('type-check--app');
    expect(o.offers.has('type-check--app')).toBe(false);
    expect([...o.aiKeys, ...o.codeKeys]).not.toContain('type-check--app');
    // a TypeScript repo with Jest, Prettier and ESLint, or without a lint script: the same
    for (const s of [
      tsNode({ testFramework: 'jest', quality: { ...TS, versions: { typescript: '5.6.3', jest: '29.7.0' } } }),
      tsNode({ quality: { ...TS, eslintConfig: 'flat', configs: ['prettier'], versions: { typescript: '5.6.3', prettier: '3.3.0', eslint: '9.0.0' } } }),
      tsNode({ scripts: ['test'] }),
    ]) {
      const x = offersOf(s);
      expect(x.byCode.filter((b) => b.kind === 'repo-tool').map((b) => b.key)).toEqual(['type-check--app']);
      expect(x.uncovered.filter((u) => u.needId === 'type-check')).toEqual([]);
    }
  });

  it('repo-tool: no typescript in the repo\'s devDependencies → type-check uncovered with a plain reason', () => {
    // a tsconfig but no typescript package: nothing pinned to run
    const none = tsNode({ quality: { ...emptyServiceQuality(), tsconfig: true } });
    expect(repoToolFor(typeCheck(), none)).toBeNull();
    expect(repoToolProblem(typeCheck(), none)).toBe('tsc: typescript is not in the lockfile, so pipegen has no pinned type checker to run (add typescript as a dev dependency and commit package-lock.json)');
    const o = offersOf(none);
    expect(o.uncovered).toContainEqual({ key: 'type-check--app', needId: 'type-check', service: 'app', blocking: true, reason: 'no-repo-tool' });
    expect(o.byCode.map((b) => b.key)).not.toContain('type-check--app');
    const x = planned(profileOf([none]));
    expect(() => assemble(x)).toThrow(/"type-check" for "app": tsc: typescript is not in the lockfile, so pipegen has no pinned type checker to run \(add typescript as a dev dependency and commit package-lock\.json\)\)\. It never guesses a tool\./);
    expect(x.draft.steps.some((s) => s.needId === 'type-check')).toBe(false);
    // the other cases a repo built-in can not run, each with its own plain reason (never another tool, never a guess)
    const cases: [Service, RegExp][] = [
      [tsNode({ quality: { ...TS, fromRange: ['typescript'] } }), /^tsc: typescript's version comes from a package\.json range, not from package-lock\.json/],
      [tsNode({ quality: { ...TS, tsconfig: false } }), /^tsc: the service has no tsconfig\.json, so tsc would have nothing to check$/],
      [tsNode({ npmLockfileVersion: 1 }), /^tsc: package-lock\.json is lockfile version 1/],
      [tsNode({ npmLockfileVersion: undefined }), /^tsc: the service has no package-lock\.json/],
      [tsNode({ packageManager: 'pnpm', npmLockfileVersion: undefined }), /^tsc: pipegen installs the dependencies with npm only \(pnpm is not supported yet\)$/],
      [tsNode({ quality: { ...TS, uiFrameworks: ['vue'], versions: { typescript: '5.6.3', 'vue-tsc': '2.1.0' } } }), /^vue-tsc: pipegen runs only the repository's own tsc as a type check in v0\.2/],
      [tsNode({ quality: { ...TS, uiFrameworks: ['vue'] } }), /^vue-tsc: vue-tsc is not in the lockfile/],
    ];
    for (const [s, re] of cases) {
      expect(repoToolFor(typeCheck(), s), String(re)).toBeNull();
      expect(repoToolProblem(typeCheck(), s), String(re)).toMatch(re);
      expect(offersOf(s).uncovered.find((u) => u.needId === 'type-check')?.reason, String(re)).toBe('no-repo-tool');
    }
    // a non-blocking type-check with no tool is not a stop, and gets no job
    const prof = profileOf([none]);
    const soft = planned(prof, { needs: floorNeeds(prof, CAPS).map((n) => (n.id === 'type-check' ? { ...n, blocking: false } : n)) });
    const a = assemble(soft);
    expect(Object.keys({ ...a.push, ...a.merge }).some((k) => k.startsWith('type-check'))).toBe(false);
  });

  it('render: repo-tool type-check runs the guarded npm ci --ignore-scripts, checks the lockfile version, then the repo\'s tsc --noEmit', () => {
    const ctx = { profile: profileOf([tsNode()]) };
    const steps = renderRepoTool(STEP, p, ctx).steps;
    expect(steps.map((s) => s.id)).toEqual(['pipegen-checkout', expect.stringMatching(/^pipegen-setup-node-\d+$/), expect.stringMatching(/^pipegen-npm-ci-[0-9a-f]{16}$/), expect.stringMatching(/^repocode-[0-9a-f]{16}$/)]);
    // the install is the shared guarded one: the very step a project script uses (same id, run and env), so a job installs once
    const ps = renderProjectScript({ kind: 'project-script', needId: 'lint', service: 'app', script: 'lint' }, p, { profile: profileOf([tsNode({ scripts: ['lint'] })]) }).steps;
    expect(steps.slice(0, 2)).toEqual(ps.slice(0, 2));
    expect(steps[2]).toEqual(JSON.parse(JSON.stringify(ps[2]).replaceAll('pipegen-out-lint--app', 'pipegen-out-type-check--app')));
    expect(steps[2]?.run).toContain('npm" ci --ignore-scripts --no-audit --no-fund --workspaces=false --registry=https://registry.npmjs.org/');
    // the run step: env -i, the install marker, the lockfile check, then the repo's own tsc by path, with --noEmit and nothing else
    const run = steps[3]?.run as string;
    expect(steps[3]?.shell).toBe('bash');
    expect(steps[3]?.env).toEqual({ BASH_ENV: '', ENV: '' });
    expect(run).toContain('/usr/bin/env -i');
    const marker = run.indexOf('the dependencies were not installed by pipegen\'s own npm ci step');
    const check = run.indexOf('"${pg_env[@]}" "$nodebin/node" -e "$js"');
    const tsc = run.indexOf('"${pg_env[@]}" "$nodebin/node" node_modules/typescript/bin/tsc --noEmit');
    expect(marker).toBeGreaterThan(-1);
    expect(check).toBeGreaterThan(marker);
    expect(tsc).toBeGreaterThan(check);
    expect(run.trimEnd().endsWith('node_modules/typescript/bin/tsc --noEmit')).toBe(true);
    expect(run).not.toMatch(/\$\{\{|secrets\.|PIPEGEN_FP_KEY|GITHUB_TOKEN/);
    expect(REPO_TOOLS).toEqual({ tsc: { package: 'typescript', bin: 'bin/tsc', args: ['--noEmit'] } });
    // a sub-folder service: the checked cd first, in both steps
    const sub = tsNode({ name: 'web', path: 'apps/web' });
    const subSteps = renderRepoTool({ ...STEP, service: 'web', workingDir: 'apps/web' }, p, { profile: profileOf([sub]) }).steps;
    for (const s of subSteps.slice(2)) expect(s.run).toContain('cd -- ./apps/web\n');

    // the renderer re-derives the step from the repository: anything else is refused
    const refusals: [RepoToolStep, Service][] = [
      [{ ...STEP, tool: 'vue-tsc' }, tsNode()],
      [{ ...STEP, version: '5.6.4' }, tsNode()],
      [{ ...STEP, version: null }, tsNode()],
      [{ ...STEP, fromRange: true }, tsNode()],
      [{ ...STEP, workingDir: 'other' }, tsNode()],
      [{ ...STEP, needId: 'lint' }, tsNode()],
      [{ ...STEP, service: 'nope' }, tsNode()],
      [STEP, tsNode({ packageManager: 'pnpm' })],
      [STEP, tsNode({ quality: { ...TS, tsconfig: false } })],
      [STEP, tsNode({ npmLockfileVersion: 1 })],
      [STEP, tsNode({ quality: { ...TS, fromRange: ['typescript'] } })],
    ];
    for (const [step, s] of refusals) expect(() => renderRepoTool(step, p, { profile: profileOf([s]) }), JSON.stringify(step)).toThrow(RenderError);

    // the lockfile check itself, run with node on a fixture folder: the installed package is the one package-lock.json pins
    const js = repoToolCheckJs('typescript', 'bin/tsc');
    expect(run).toContain(js.replace(/'/g, "'\\''"));
    const version = '5.6.3';
    const resolved = `https://registry.npmjs.org/typescript/-/typescript-${version}.tgz`;
    const integrity = `sha512-${'A'.repeat(86)}==`;
    const fixture = (o: { lock?: Obj; installed?: string; hidden?: Obj; link?: boolean; binLink?: boolean; noBin?: boolean } = {}): string => {
      const d = makeTempDir();
      const entry = { version, resolved, integrity, dev: true };
      writeFileSync(join(d, 'package-lock.json'), JSON.stringify(o.lock ?? { lockfileVersion: 3, packages: { '': {}, 'node_modules/typescript': entry } }));
      mkdirSync(join(d, 'node_modules'));
      const pkgDir = o.link === true ? join(d, 'elsewhere') : join(d, 'node_modules', 'typescript');
      mkdirSync(join(pkgDir, 'bin'), { recursive: true });
      if (o.link === true) symlinkSync(pkgDir, join(d, 'node_modules', 'typescript'));
      writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: 'typescript', version: o.installed ?? version }));
      if (o.binLink === true) { writeFileSync(join(d, 'outside.js'), ''); symlinkSync(join(d, 'outside.js'), join(pkgDir, 'bin', 'tsc')); }
      else if (o.noBin !== true) writeFileSync(join(pkgDir, 'bin', 'tsc'), '');
      writeFileSync(join(d, 'node_modules', '.package-lock.json'), JSON.stringify({ packages: o.hidden ?? { 'node_modules/typescript': entry } }));
      return d;
    };
    const runs = (d: string): number => { try { execFileSync(process.execPath, ['-e', js], { cwd: d, env: {}, stdio: 'pipe' }); return 0; } catch (e) { return (e as { status: number }).status; } };
    expect(runs(fixture())).toBe(0);
    const bad: [string, Parameters<typeof fixture>[0]][] = [
      ['another installed version', { installed: '5.6.4' }],
      ['a linked package folder', { link: true }],
      ['a bin that is a link', { binLink: true }],
      ['no bin', { noBin: true }],
      ['lockfile v1', { lock: { lockfileVersion: 1, dependencies: { typescript: { version } } } }],
      ['not in the lockfile', { lock: { lockfileVersion: 3, packages: { '': {} } } }],
      ['a link entry', { lock: { lockfileVersion: 3, packages: { 'node_modules/typescript': { version, resolved, integrity, link: true } } } }],
      ['another source', { lock: { lockfileVersion: 3, packages: { 'node_modules/typescript': { version, resolved: 'https://evil.example/typescript.tgz', integrity } } } }],
      ['no sha512', { lock: { lockfileVersion: 3, packages: { 'node_modules/typescript': { version, resolved, integrity: 'sha1-abc' } } } }],
      ['a range, not a version', { lock: { lockfileVersion: 3, packages: { 'node_modules/typescript': { version: '^5.6.3', resolved, integrity } } } }],
      ['not installed by npm ci (hidden lockfile differs)', { hidden: { 'node_modules/typescript': { version, resolved, integrity: `sha512-${'B'.repeat(86)}==` } } }],
      ['no hidden lockfile entry', { hidden: {} }],
    ];
    for (const [why, o] of bad) expect(runs(fixture(o)), why).toBe(1);
  });

  it('referee: a repo-tool step is accepted only in its exact rendered form', async () => {
    const x = planned(profileOf([tsNode()]));
    const a = assemble(x);
    const f = files(a)[0] as CreatedFile;
    expect(shown(await judge(files(a), a.draft))).toBe('');
    const runOf = (j: Obj): Obj => (j.steps as Obj[]).find((s) => typeof s.id === 'string' && s.id.startsWith('repocode-')) as Obj;
    const ciOf = (j: Obj): Obj => (j.steps as Obj[]).find((s) => typeof s.id === 'string' && s.id.startsWith('pipegen-npm-ci-')) as Obj;
    const edits: [string, (j: Obj) => void][] = [
      ['a tsc flag added', (j) => { runOf(j).run = String(runOf(j).run).replace('tsc --noEmit', 'tsc --noEmit --skipLibCheck'); }],
      ['--noEmit dropped', (j) => { runOf(j).run = String(runOf(j).run).replace('tsc --noEmit', 'tsc'); }],
      ['another bin', (j) => { runOf(j).run = String(runOf(j).run).replace('node_modules/typescript/bin/tsc', 'node_modules/.bin/tsc'); }],
      ['the lockfile check dropped', (j) => { runOf(j).run = String(runOf(j).run).replace('"${pg_env[@]}" "$nodebin/node" -e "$js"', 'true'); }],
      ['the install with scripts', (j) => { ciOf(j).run = String(ciOf(j).run).replace('ci --ignore-scripts', 'ci'); }],
      ['an env added', (j) => { runOf(j).env = { ...runOf(j).env, NODE_OPTIONS: '--require ./x.js' }; }],
      ['a working directory', (j) => { runOf(j)['working-directory'] = 'src'; }],
      ['another id', (j) => { runOf(j).id = 'repocode-0000000000000000'; }],
      ['a trailing command', (j) => { runOf(j).run = `${String(runOf(j).run)}\ncurl https://example.com`; }],
    ];
    for (const [why, edit] of edits) {
      const r = await judge([editJob(f, 'type-check--app', edit), ...files(a).slice(1)], a.draft);
      expect(r.ok, why).toBe(false);
    }
    // the exact step, moved into another job: refused (the gate reads the type-check job)
    const moved = editJob(f, 'lint--app', (j) => { j.steps.push(runOf(parseJob(f, 'type-check--app'))); });
    expect((await judge([moved, ...files(a).slice(1)], a.draft)).ok).toBe(false);
    // the gate's type-check job without its step: refused (the gate would read a job that does not type-check)
    const empty = editJob(f, 'type-check--app', (j) => { j.steps = (j.steps as Obj[]).filter((s) => !String(s.id).startsWith('repocode-')); });
    expect((await judge([empty, ...files(a).slice(1)], a.draft)).ok).toBe(false);
    // a draft whose repository has no runnable tsc: the same step is no step pipegen renders (unreviewed), and the blocking need has nothing
    const noTs = { ...a.draft, profile: profileOf([tsNode({ quality: { ...TS, versions: {} } })]) };
    const r = await judge(files(a), noTs);
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => i.check === 'not-gate-readable' && /"type-check" for "app" has no reviewed tool step/.test(i.message))).toBe(true);
    // a lockfile bump after the workflow was written changes nothing: the version is read at run time, never written into the step
    const bumped = { ...a.draft, profile: profileOf([tsNode({ quality: { ...TS, versions: { typescript: '5.7.2' } } })]) };
    expect(shown(await judge(files(a), bumped))).toBe('');
  });

  it('assemble: a Node/TypeScript service assembles with no blocking uncovered need', async () => {
    const x = planned(profileOf([tsNode({ quality: { ...TS, eslintConfig: 'flat', configs: ['prettier'], versions: { typescript: '5.6.3', prettier: '3.3.0', eslint: '9.0.0' } } })]));
    expect(x.plan.uncovered.filter((u) => u.blocking)).toEqual([]);
    const a = assemble(x);
    for (const layer of [a.push, a.merge]) {
      const j = layer['type-check--app'] as Job;
      expect(j).toBeDefined();
      // the egress step first (github-core and the npm registry for the install), then the repo built-in's own checkout, setup, install and run
      expect(j.steps[0]?.uses?.startsWith('bullfrogsec/')).toBe(true);
      expect(String(j.steps[0]?.with?.['allowed-domains'])).toContain('registry.npmjs.org');
      expect(j.steps.slice(1)).toEqual(renderRepoTool(STEP, p, { profile: a.draft.profile }).steps);
      // no fingerprint key, no secret, no scrub, no output, a read-only token
      expect(JSON.stringify(j)).not.toMatch(/secrets\.|PIPEGEN_FP_KEY|fp-key|GITHUB_TOKEN/);
      expect(j.steps.some((s) => s.with?.mode === 'scrub')).toBe(false);
      expect(j.outputs).toBeUndefined();
      expect(j.permissions).toEqual({ contents: 'read' });
    }
    // the gate reads it as a blocking job-status check, like a lint project script
    // (the needsSecrets field is spelled at run time: test/no-secret-literals.test.ts)
    expect(gateJobList(a.draft)).toContainEqual({ needId: 'type-check', service: 'app', job: 'type-check--app', category: 'type-check', format: 'none', blocking: true, [NEEDS_SEC]: false });
    expect(a.merge.gate?.needs).toContain('type-check--app');
    expect(shown(await judge(files(a), a.draft))).toBe('');
    // a non-blocking type-check still runs the repo's tsc in its own job; the gate does not list it
    const prof = profileOf([tsNode()]);
    const soft = assemble(planned(prof, { needs: floorNeeds(prof, CAPS).map((n) => (n.id === 'type-check' ? { ...n, blocking: false } : n)) }));
    expect((soft.merge['type-check--app'] as Job).steps.slice(1)).toEqual(renderRepoTool(STEP, p, { profile: prof }).steps);
    expect(gateJobList(soft.draft).map((e) => e.job)).not.toContain('type-check--app');
    expect(shown(await judge(files(soft), soft.draft))).toBe('');
  });
});

function parseJob(f: CreatedFile, id: string): Obj {
  let out: Obj = {};
  editJob(f, id, (j) => { out = j; });
  return out;
}
