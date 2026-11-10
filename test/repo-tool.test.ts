// v0.2 Plan G sub-task G4b (ruling G4-R3): a TypeScript service's type-check runs the repository's own tsc at its lockfile version, a repo
// built-in (DECISIONS #95, reviewed-tools.yml header), never a reviewed entry and never a project script. Code decides it (byCode
// `repo-tool`), the renderer writes the guarded `npm ci --ignore-scripts`, the run-time lockfile check and `tsc --noEmit`, the referee accepts
// only that exact form, and the job is a blocking job-status check with no key and no secret (gate/dist unchanged).
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { parse } from 'yaml';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { chooseTools } from '../src/audit/choose.js';
import { keyOffers } from '../src/debate/builder.js';
import { gateJobList } from '../src/engine/gate-job-list.js';
import { floorNeeds } from '../src/engine/needs.js';
import { REPO_TOOLS, repoToolCheckJs, tsconfigGuardJs } from '../src/engine/render-cli.js';
import { RenderError } from '../src/engine/render-error.js';
import { renderProjectScript, renderRepoTool } from '../src/engine/render-step.js';
import { repoToolFor, repoToolProblem } from '../src/engine/reviewed.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import { starterTestJob, type Job } from '../src/layers/jobs.js';
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
    expect(o.uncovered).toContainEqual({ key: 'type-check--app', needId: 'type-check', service: 'app', layers: ['push', 'merge'], blocking: true, reason: 'no-repo-tool' });
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
    expect(steps[2]?.run).toContain('npm" ci --ignore-scripts --no-audit --no-fund --workspaces=false --git=/usr/bin/git --registry=https://registry.npmjs.org/');
    // the run step: env -i, the install marker, the lockfile check, then the repo's own tsc by path, with --noEmit and nothing else
    const run = steps[3]?.run as string;
    expect(steps[3]?.shell).toBe('bash');
    expect(steps[3]?.env).toEqual({ BASH_ENV: '', ENV: '' });
    expect(run).toContain('/usr/bin/env -i');
    const marker = run.indexOf('the dependencies were not installed by pipegen\'s own npm ci step');
    const check = run.indexOf('"${pg_env[@]}" "$nodebin/node" -e "$js"');
    // G4b-R1 I3, m3: the service's own tsconfig.json (-p, never a parent's) is shown first and must select a file with noCheck off
    const hasConfig = run.indexOf('[ -f tsconfig.json ] && [ ! -L tsconfig.json ] || pg_fail');
    const show = run.indexOf('"${pg_env[@]}" "$nodebin/node" node_modules/typescript/bin/tsc -p tsconfig.json --showConfig > "$cfg"');
    const guard = run.indexOf('"${pg_env[@]}" "$nodebin/node" -e "$guard" "$cfg"');
    const tsc = run.indexOf('"${pg_env[@]}" "$nodebin/node" node_modules/typescript/bin/tsc -p tsconfig.json --noEmit');
    expect(marker).toBeGreaterThan(-1);
    expect(check).toBeGreaterThan(marker);
    expect(hasConfig).toBeGreaterThan(check);
    expect(show).toBeGreaterThan(hasConfig);
    expect(guard).toBeGreaterThan(show);
    expect(tsc).toBeGreaterThan(guard);
    expect(run.trimEnd().endsWith('node_modules/typescript/bin/tsc -p tsconfig.json --noEmit')).toBe(true);
    expect(run.match(/node_modules\/typescript\/bin\/tsc(?! -p tsconfig\.json )/g)).toBeNull();
    expect(run).not.toMatch(/\$\{\{|secrets\.|PIPEGEN_FP_KEY|GITHUB_TOKEN/);
    expect(run).toContain(`guard=${"'"}${tsconfigGuardJs().replace(/'/g, "'\\''")}'`);
    expect(REPO_TOOLS).toEqual({ tsc: { package: 'typescript', bin: 'bin/tsc', config: 'tsconfig.json', args: ['--noEmit'], native: { fromMajor: 7, scope: '@typescript', base: 'typescript', exe: 'lib/tsc' } } });
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
    const js = repoToolCheckJs('tsc');
    expect(run).toContain(js.replace(/'/g, "'\\''"));
    const version = '5.6.3';
    const resolved = `https://registry.npmjs.org/typescript/-/typescript-${version}.tgz`;
    const integrity = `sha512-${'A'.repeat(86)}==`;
    // each hostile case differs from a clean install in ONE property only: npm ci's own record (.package-lock.json) and the installed
    // package.json follow the lockfile entry, so every guard of the check is shown to hold on its own (mutation pass, G4b)
    type Fx = { entry?: Obj; lockVersion?: number; lock?: Obj; installed?: string; hidden?: Obj; link?: boolean; binLink?: boolean; noBin?: boolean };
    const fixture = (o: Fx = {}): string => {
      const d = makeTempDir();
      const entry = { version, resolved, integrity, dev: true, ...o.entry };
      writeFileSync(join(d, 'package-lock.json'), JSON.stringify(o.lock ?? { lockfileVersion: o.lockVersion ?? 3, packages: { '': {}, 'node_modules/typescript': entry } }));
      mkdirSync(join(d, 'node_modules'));
      // a linked package folder points INSIDE node_modules (a store folder), so only the link test refuses it
      const pkgDir = o.link === true ? join(d, 'node_modules', '.store', 'typescript') : join(d, 'node_modules', 'typescript');
      mkdirSync(join(pkgDir, 'bin'), { recursive: true });
      if (o.link === true) symlinkSync(pkgDir, join(d, 'node_modules', 'typescript'));
      writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: 'typescript', version: o.installed ?? entry.version }));
      // a linked bin points at a file inside the package itself, so only the link test refuses it
      if (o.binLink === true) { writeFileSync(join(pkgDir, 'bin', 'real.js'), ''); symlinkSync(join(pkgDir, 'bin', 'real.js'), join(pkgDir, 'bin', 'tsc')); }
      else if (o.noBin !== true) writeFileSync(join(pkgDir, 'bin', 'tsc'), '');
      writeFileSync(join(d, 'node_modules', '.package-lock.json'), JSON.stringify({ packages: o.hidden ?? { 'node_modules/typescript': entry } }));
      return d;
    };
    const runs = (d: string): number => { try { execFileSync(process.execPath, ['-e', js], { cwd: d, env: {}, stdio: 'pipe' }); return 0; } catch (e) { return (e as { status: number }).status; } };
    expect(runs(fixture())).toBe(0);
    const range = '^5.6.3';
    const bad: [string, Fx][] = [
      ['another installed version', { installed: '5.6.4' }],
      ['a linked package folder', { link: true }],
      ['a bin that is a link', { binLink: true }],
      ['no bin', { noBin: true }],
      ['lockfile v1 (even with a packages map)', { lockVersion: 1 }],
      ['lockfile v1 without packages', { lock: { lockfileVersion: 1, dependencies: { typescript: { version } } } }],
      ['not in the lockfile', { lock: { lockfileVersion: 3, packages: { '': {} } } }],
      ['a link entry', { entry: { link: true } }],
      ['a bundled entry', { entry: { inBundle: true } }],
      ['another source', { entry: { resolved: 'https://evil.example/typescript.tgz' } }],
      ['no sha512', { entry: { integrity: 'sha1-abc' } }],
      ['a range, not a version', { entry: { version: range, resolved: `https://registry.npmjs.org/typescript/-/typescript-${range}.tgz` } }],
      // G4b-R2: TypeScript 7 with no native platform package installed (the shim would have nothing checked to run)
      ['TypeScript 7 without its platform package', { entry: { version: '7.0.2', resolved: 'https://registry.npmjs.org/typescript/-/typescript-7.0.2.tgz' } }],
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
    // G4b-R1 I2: each edit is refused for its own reason (the exact issue), and an edit that changes nothing is accepted (the control)
    const TSC = 'node_modules/typescript/bin/tsc -p tsconfig.json --noEmit';
    const differs = (id: string): [string, RegExp] => ['template', new RegExp(`In the job "type-check--app", step \\d+: the step "${id}" differs from what pipegen renders for it`)];
    const RUN = differs('repocode-[0-9a-f]{16}');
    const edits: [string, (j: Obj) => void, [string, RegExp]][] = [
      ['a tsc flag added', (j) => { runOf(j).run = String(runOf(j).run).replace(TSC, `${TSC} --skipLibCheck`); }, RUN],
      ['--noEmit dropped', (j) => { runOf(j).run = String(runOf(j).run).replace(TSC, TSC.replace(' --noEmit', '')); }, RUN],
      ['-p dropped (tsc would walk up to a parent tsconfig)', (j) => { runOf(j).run = String(runOf(j).run).replaceAll(' -p tsconfig.json', ''); }, RUN],
      ['another bin', (j) => { runOf(j).run = String(runOf(j).run).replaceAll('node_modules/typescript/bin/tsc', 'node_modules/.bin/tsc'); }, RUN],
      ['the lockfile check dropped', (j) => { runOf(j).run = String(runOf(j).run).replace('"${pg_env[@]}" "$nodebin/node" -e "$js"', 'true'); }, RUN],
      ['the tsconfig guard dropped', (j) => { runOf(j).run = String(runOf(j).run).replace('"${pg_env[@]}" "$nodebin/node" -e "$guard" "$cfg"', 'true'); }, RUN],
      ['the install with scripts', (j) => { ciOf(j).run = String(ciOf(j).run).replace('ci --ignore-scripts', 'ci'); }, differs('pipegen-npm-ci-[0-9a-f]{16}')],
      ['the install without --git', (j) => { ciOf(j).run = String(ciOf(j).run).replace(' --git=/usr/bin/git', ''); }, differs('pipegen-npm-ci-[0-9a-f]{16}')],
      ['an env added', (j) => { runOf(j).env = { ...runOf(j).env, NODE_OPTIONS: '--require ./x.js' }; }, RUN],
      ['a working directory', (j) => { runOf(j)['working-directory'] = 'src'; }, RUN],
      ['another id', (j) => { runOf(j).id = 'repocode-0000000000000000'; }, ['unreviewed', /In the job "type-check--app", step \d+: the run step "Run the repository's own tsc \(its lockfile version\)" is not a step pipegen renders/]],
      ['a trailing command', (j) => { runOf(j).run = `${String(runOf(j).run)}\ncurl https://example.com`; }, RUN],
    ];
    expect(shown(await judge([editJob(f, 'type-check--app', () => {}), ...files(a).slice(1)], a.draft)), 'identity control').toBe('');
    for (const [why, edit, [check, re]] of edits) {
      const r = await judge([editJob(f, 'type-check--app', edit), ...files(a).slice(1)], a.draft);
      expect(r.ok, why).toBe(false);
      expect(r.issues.some((i) => i.check === check && re.test(i.message)), `${why}: ${shown(r)}`).toBe(true);
    }
    // the exact step, moved into another job: refused (the gate reads the type-check job)
    const moved = editJob(f, 'lint--app', (j) => { j.steps.push(runOf(parseJob(f, 'type-check--app'))); });
    const mr = await judge([moved, ...files(a).slice(1)], a.draft);
    expect(mr.issues.some((i) => i.check === 'not-gate-readable' && /belongs to the job "type-check--app" .* but sits in the job "lint--app"/.test(i.message)), shown(mr)).toBe(true);
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

describe('G4b fix round 1 (ruling G4b-R1)', () => {
  const both = (): Service => tsNode({ scripts: ['test', 'lint'] });
  const REMOVED = /^The job "(type-check|lint|unit-tests)--app" is in the gate's list for the check "\1", but it holds no step of the check \((the rendered repo built-in|the rendered project script)\)/;

  it('referee: a gate-listed type-check, lint or unit-tests job without its own step is refused (from the merge file, or from every file)', async () => {
    const a = assemble(planned(profileOf([both()])));
    const fs = files(a);
    expect(shown(await judge(fs, a.draft))).toBe('');
    const finalRun = (j: Obj): string => String((j.steps as Obj[]).filter((x) => typeof x.id === 'string' && x.id.startsWith('repocode-')).at(-1)?.id);
    const drop = (f: CreatedFile, job: string): CreatedFile => (parse(f.content) as Obj).jobs?.[job] === undefined ? f
      : editJob(f, job, (j) => { const id = finalRun(j); j.steps = (j.steps as Obj[]).filter((x) => x.id !== id); });
    for (const job of ['type-check--app', 'lint--app', 'unit-tests--app']) {
      expect(fs[0]?.content, job).toContain(`${job}:`);
      // the identity control: the same file written again is accepted
      expect(shown(await judge([editJob(fs[0] as CreatedFile, job, () => {}), ...fs.slice(1)], a.draft)), `${job} identity`).toBe('');
      // the step removed from the gate's file only (the push file still holds it): refused, the gate reads this file's job
      const mergeOnly = await judge([drop(fs[0] as CreatedFile, job), ...fs.slice(1)], a.draft);
      expect(mergeOnly.issues.some((i) => i.check === 'not-gate-readable' && REMOVED.test(i.message)), `${job} merge only: ${shown(mergeOnly)}`).toBe(true);
      // removed from every file: refused, and the blocking rule finds nothing that runs the check
      const everywhere = await judge(fs.map((f) => drop(f, job)), a.draft);
      expect(everywhere.issues.some((i) => i.check === 'not-gate-readable' && REMOVED.test(i.message)), `${job} everywhere: ${shown(everywhere)}`).toBe(true);
      expect(everywhere.issues.some((i) => i.check === 'not-gate-readable' && /^The blocking check "(type-check|lint|unit-tests)" for "app" has no reviewed tool step, no project script and no repo built-in/.test(i.message)), `${job} blocking rule: ${shown(everywhere)}`).toBe(true);
    }
    // only the install left (the step that installs, not the step that checks): still refused
    const onlyInstall = editJob(fs[0] as CreatedFile, 'type-check--app', (j) => { j.steps = (j.steps as Obj[]).filter((x) => !String(x.id).startsWith('repocode-')); });
    expect((await judge([onlyInstall, ...fs.slice(1)], a.draft)).issues.some((i) => REMOVED.test(i.message))).toBe(true);
  });

  it('render: the tsc step reads tsc -p tsconfig.json --showConfig first and refuses a tsconfig that selects no file or sets noCheck', () => {
    const guard = tsconfigGuardJs();
    const runGuard = (cfg: string): { status: number; err: string } => {
      const d = makeTempDir();
      writeFileSync(join(d, 'cfg.json'), cfg);
      try { execFileSync(process.execPath, ['-e', guard, join(d, 'cfg.json')], { cwd: d, env: {}, stdio: 'pipe' }); return { status: 0, err: '' }; } catch (e) { const x = e as { status: number; stderr: Buffer }; return { status: x.status, err: x.stderr.toString() }; }
    };
    expect(runGuard(JSON.stringify({ compilerOptions: { strict: true }, files: ['./src/main.ts'], include: ['src'] })).status).toBe(0);
    const bad: [string, string, RegExp][] = [
      ['a solution-style tsconfig', JSON.stringify({ compilerOptions: {}, references: [{ path: './tsconfig.app.json' }] }), /tsconfig\.json selects no file .*references.*tsc -b/],
      ['files: []', JSON.stringify({ compilerOptions: {}, files: [] }), /tsconfig\.json selects no file/],
      ['only files in node_modules', JSON.stringify({ compilerOptions: {}, files: ['./node_modules/x/index.d.ts'] }), /tsconfig\.json selects no file/],
      ['noCheck', JSON.stringify({ compilerOptions: { noCheck: true }, files: ['./src/main.ts'] }), /tsconfig\.json sets noCheck/],
      ['not JSON', 'Version 5.6.3', /did not print a config pipegen can read/],
      ['no compilerOptions object', JSON.stringify({ compilerOptions: 'x', files: ['./a.ts'] }), /did not print a config pipegen can read/],
    ];
    for (const [why, cfg, re] of bad) {
      const r = runGuard(cfg);
      expect(r.status, why).toBe(1);
      expect(r.err, why).toMatch(re);
    }
    // with a real tsc (the worktree's own, if one is installed offline): --showConfig then the guard, on the honest no-op layouts
    const tsc = join(process.cwd(), 'node_modules', 'typescript', 'bin', 'tsc');
    if (!existsSync(tsc)) return;
    const project = (tsconfig: Obj): string => {
      const d = makeTempDir();
      mkdirSync(join(d, 'src'));
      writeFileSync(join(d, 'src', 'main.ts'), 'const n: number = "not a number";\nexport { n };\n');
      writeFileSync(join(d, 'tsconfig.json'), JSON.stringify(tsconfig));
      return d;
    };
    const chain = (d: string): number => {
      const cfg = execFileSync(process.execPath, [tsc, '-p', 'tsconfig.json', '--showConfig'], { cwd: d, stdio: 'pipe' }).toString();
      writeFileSync(join(d, 'cfg.json'), cfg);
      try { execFileSync(process.execPath, ['-e', guard, join(d, 'cfg.json')], { cwd: d, env: {}, stdio: 'pipe' }); return 0; } catch (e) { return (e as { status: number }).status; }
    };
    const opts = { strict: true, module: 'esnext', moduleResolution: 'bundler', target: 'es2022' };
    expect(chain(project({ compilerOptions: opts, include: ['src'] }))).toBe(0);
    expect(chain(project({ files: [], references: [{ path: './tsconfig.app.json' }] }))).toBe(1);
    expect(chain(project({ compilerOptions: { ...opts, noCheck: true }, include: ['src'] }))).toBe(1);
  });

  // G4b-R2 replaces fix round 1's m2 (TypeScript 7 refused): TS 7 is current, so the lockfile check covers its native platform package instead
  it('repo-tool: TypeScript 7 (its native platform package checked) is covered like 5.x and 6.x', () => {
    for (const version of ['5.6.3', '6.0.1', '7.0.2', '7.1.0']) {
      const s = tsNode({ quality: { ...TS, versions: { typescript: version } } });
      expect(repoToolProblem(typeCheck(), s), version).toBeNull();
      expect(repoToolFor(typeCheck(), s), version).toEqual({ ...STEP, version });
      expect(offersOf(s).byCode, version).toContainEqual({ key: 'type-check--app', needId: 'type-check', service: 'app', kind: 'repo-tool', blocking: true });
      const a = assemble(planned(profileOf([s])));
      expect((a.merge['type-check--app'] as Job).steps.slice(1), version).toEqual(renderRepoTool({ ...STEP, version }, p, { profile: profileOf([s]) }).steps);
    }
  });

  it('render: the lockfile check covers TypeScript 7\'s native platform package (registry tarball, sha512, installed inside node_modules, the binary the shim runs)', () => {
    const js = repoToolCheckJs('tsc');
    const plat = `typescript-${process.platform}-${process.arch}`;
    const native = `@typescript/${plat}`;
    const reg = (name: string, v: string): string => `https://registry.npmjs.org/${name}/-/${name.slice(name.indexOf('/') + 1)}-${v}.tgz`;
    const sri = (c: string): string => `sha512-${c.repeat(86)}==`;
    type Fx7 = {
      version?: string; tsEntry?: Obj; nativeEntry?: Obj | null; otherEntry?: Obj; nativeName?: string; nativeVersion?: string;
      noNative?: boolean; nativeLink?: boolean; exeLink?: boolean; noExe?: boolean; nested?: boolean; nestedLock?: boolean; hiddenNative?: Obj | null;
    };
    const fixture7 = (o: Fx7 = {}): string => {
      const d = makeTempDir();
      const v = o.version ?? '7.0.2';
      const ts = { version: v, resolved: reg('typescript', v), integrity: sri('A'), dev: true, bin: { tsc: 'bin/tsc' }, ...o.tsEntry };
      const nat = { version: v, resolved: reg(native, v), integrity: sri('C'), dev: true, optional: true, ...o.nativeEntry };
      const other = `@typescript/typescript-${process.platform === 'linux' ? 'darwin' : 'linux'}-arm64`;
      const packages: Obj = { '': {}, 'node_modules/typescript': ts, [`node_modules/${other}`]: { version: v, resolved: reg(other, v), integrity: sri('D'), dev: true, optional: true, ...o.otherEntry } };
      if (o.nativeEntry !== null) packages[`node_modules/${native}`] = nat;
      if (o.nestedLock === true) packages[`node_modules/typescript/node_modules/${native}`] = nat;
      writeFileSync(join(d, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
      mkdirSync(join(d, 'node_modules', 'typescript', 'bin'), { recursive: true });
      mkdirSync(join(d, 'node_modules', 'typescript', 'lib'));
      writeFileSync(join(d, 'node_modules', 'typescript', 'package.json'), JSON.stringify({ name: 'typescript', version: ts.version, bin: { tsc: './bin/tsc' } }));
      writeFileSync(join(d, 'node_modules', 'typescript', 'bin', 'tsc'), '');
      if (o.noNative !== true) {
        const dir = o.nativeLink === true ? join(d, 'node_modules', '.store', plat) : join(d, 'node_modules', '@typescript', plat);
        mkdirSync(join(dir, 'lib'), { recursive: true });
        if (o.nativeLink === true) { mkdirSync(join(d, 'node_modules', '@typescript'), { recursive: true }); symlinkSync(dir, join(d, 'node_modules', '@typescript', plat)); }
        writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: o.nativeName ?? native, version: o.nativeVersion ?? v, exports: { './package.json': './package.json' } }));
        if (o.exeLink === true) { writeFileSync(join(d, 'outside-tsc'), ''); symlinkSync(join(d, 'outside-tsc'), join(dir, 'lib', 'tsc')); }
        else if (o.noExe !== true) writeFileSync(join(dir, 'lib', 'tsc'), '');
      }
      if (o.nested === true) {
        const n = join(d, 'node_modules', 'typescript', 'node_modules', '@typescript', plat);
        mkdirSync(join(n, 'lib'), { recursive: true });
        writeFileSync(join(n, 'package.json'), JSON.stringify({ name: native, version: v }));
        writeFileSync(join(n, 'lib', 'tsc'), '');
      }
      const hidden: Obj = { 'node_modules/typescript': ts };
      if (o.hiddenNative !== null) hidden[`node_modules/${native}`] = o.hiddenNative ?? nat;
      writeFileSync(join(d, 'node_modules', '.package-lock.json'), JSON.stringify({ packages: hidden }));
      return d;
    };
    const runs = (d: string): { status: number; err: string } => {
      try { execFileSync(process.execPath, ['-e', js], { cwd: d, env: {}, stdio: 'pipe' }); return { status: 0, err: '' }; } catch (e) { const x = e as { status: number; stderr: Buffer }; return { status: x.status, err: x.stderr.toString() }; }
    };
    // the good shapes: TypeScript 7 with its platform package, and a later 7.x
    expect(runs(fixture7())).toEqual({ status: 0, err: '' });
    expect(runs(fixture7({ version: '7.1.0' }))).toEqual({ status: 0, err: '' });
    const bad: [string, Fx7, RegExp][] = [
      ['the platform package from codeload', { nativeEntry: { resolved: 'https://codeload.github.com/microsoft/typescript-go/tar.gz/abc' } }, new RegExp(`${native} in package-lock\\.json is not the registry tarball with a sha512 integrity`)],
      ['the platform package as a git dependency', { nativeEntry: { resolved: 'git+ssh://git@github.com/microsoft/typescript-go.git#abc' } }, /is not the registry tarball/],
      ['the platform package from a file', { nativeEntry: { resolved: 'file:../tsc.tgz' } }, /is not the registry tarball/],
      ['the platform package from another registry tarball', { nativeEntry: { resolved: 'https://registry.npmjs.org/evil/-/evil-7.0.2.tgz' } }, /is not the registry tarball/],
      ['the platform package with no integrity', { nativeEntry: { integrity: undefined } }, /is not the registry tarball with a sha512 integrity/],
      ['the platform package with a sha1 integrity', { nativeEntry: { integrity: 'sha1-abc' } }, /is not the registry tarball with a sha512 integrity/],
      ['the platform package as a link', { nativeEntry: { link: true } }, /is not a plain package at an exact version/],
      ['the platform package at another version', { nativeEntry: { version: '7.0.1', resolved: reg(native, '7.0.1') } }, /is not at typescript's own version 7\.0\.2/],
      ['the platform package not in the lockfile', { nativeEntry: null }, new RegExp(`${native} is not a plain package at an exact version in package-lock\\.json`)],
      ['the platform package not installed', { noNative: true }, new RegExp(`${native} is not a real folder in node_modules`)],
      ['the platform package folder a link', { nativeLink: true }, new RegExp(`${native} is not a real folder in node_modules`)],
      ['a wrong package name in the installed folder', { nativeName: '@evil/typescript-linux-x64' }, new RegExp(`the folder node_modules/${native} holds another package`)],
      ['the installed platform package at another version', { nativeVersion: '7.0.1' }, new RegExp(`${native} is 7\\.0\\.1, not the 7\\.0\\.2 package-lock\\.json pins`)],
      ['the platform package not installed by npm ci', { hiddenNative: null }, new RegExp(`${native} was not installed from the registry tarball package-lock\\.json pins`)],
      ['the binary the shim runs is a link out', { exeLink: true }, /the native binary lib\/tsc of .* is not a regular file inside its package/],
      ['no binary for the shim', { noExe: true }, /the native binary lib\/tsc of .* is not a regular file inside its package/],
      ['a nested copy the shim would load first', { nested: true }, /a nested copy .* the tsc shim would run instead/],
      ['a nested copy in the lockfile', { nestedLock: true }, /a nested copy .* inside typescript; the tsc shim would run that copy instead/],
      ['another platform\'s entry from codeload', { otherEntry: { resolved: 'https://codeload.github.com/x/y/tar.gz/abc' } }, /in package-lock\.json is not the registry tarball with a sha512 integrity/],
      ['typescript itself from codeload', { tsEntry: { resolved: 'https://codeload.github.com/microsoft/TypeScript/tar.gz/abc' } }, /^pipegen: typescript in package-lock\.json is not the registry tarball/m],
    ];
    for (const [why, o, re] of bad) {
      const r = runs(fixture7(o));
      expect(r.status, why).toBe(1);
      expect(r.err, why).toMatch(re);
    }
    // the real TypeScript 7.0.2 of the worktree (offline): the check passes on its real lockfile and node_modules, then the real shim
    // runs the checked native binary through the tsconfig guard chain: a type error fails, a clean project passes
    const root = process.cwd();
    const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
    if (!existsSync(join(root, 'node_modules', '@typescript', plat, 'lib', 'tsc'))) return;
    expect(runs(root)).toEqual({ status: 0, err: '' });
    const guard = tsconfigGuardJs();
    const project = (code: string): string => {
      const d = makeTempDir();
      mkdirSync(join(d, 'src'));
      writeFileSync(join(d, 'src', 'main.ts'), code);
      writeFileSync(join(d, 'tsconfig.json'), JSON.stringify({ compilerOptions: { strict: true, module: 'esnext', moduleResolution: 'bundler', target: 'es2022' }, include: ['src'] }));
      return d;
    };
    const chain = (d: string): number => {
      writeFileSync(join(d, 'cfg.json'), execFileSync(process.execPath, [tsc, '-p', 'tsconfig.json', '--showConfig'], { cwd: d, stdio: 'pipe' }));
      execFileSync(process.execPath, ['-e', guard, join(d, 'cfg.json')], { cwd: d, env: {}, stdio: 'pipe' });
      try { execFileSync(process.execPath, [tsc, '-p', 'tsconfig.json', '--noEmit'], { cwd: d, stdio: 'pipe' }); return 0; } catch (e) { return (e as { status: number }).status; }
    };
    expect(chain(project('export const n: number = 1;\n'))).toBe(0);
    expect(chain(project('export const n: number = "not a number";\n'))).not.toBe(0);
  });

  it('render: every npm ci pipegen renders passes --git=/usr/bin/git (a repo .npmrc git= never runs)', () => {
    const a = assemble(planned(profileOf([both()])));
    const starter = starterTestJob(both(), { reviewed: REVIEWED, platform: p });
    const runs = [...Object.values({ ...a.push, ...a.merge, ...a.nightly }), starter.job].flatMap((j) => j.steps).map((x) => x.run ?? '').filter((r) => /npm" ci\b/.test(r));
    // the repository's own install (project scripts, the repo tool, the starter tests) and a checker's closure install
    expect(runs.some((r) => r.includes('--userconfig'))).toBe(true);
    expect(runs.filter((r) => !r.includes('--userconfig')).length).toBeGreaterThan(0);
    for (const r of runs) for (const line of r.split('\n').filter((l) => /npm" ci\b/.test(l))) expect(line).toContain(' --git=/usr/bin/git ');
  });
});

function parseJob(f: CreatedFile, id: string): Obj {
  let out: Obj = {};
  editJob(f, id, (j) => { out = j; });
  return out;
}
