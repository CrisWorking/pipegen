// Plan B Task 6d: per-repo tool tuning (DECISIONS #84, narrowed by #108). Written first (strict test-first).
// The model (src/engine/tuning.ts) is reviewed policy: each option has a kind (`adds` or `scope-lint`), a value enum built per
// call from profile facts, and a fixed way of rendering. The AI picks only from the enums (StepSpec.choices.tuning). Nothing
// that narrows a secret, dependency or image scan exists, and the first describe walks the model to prove it.
import { Document } from 'yaml';
import { describe, expect, it } from 'vitest';
import { RenderError, renderStep, stepsToYaml, validateSpec, type RenderContext, type RenderedStep } from '../src/engine/render-step.js';
import { describeTuning, startScriptOf, TUNING_KINDS, TUNING_OPTIONS, tuningEffects, tuningEnums, SEMGREP_RULE_FOLDERS, type TuningOption } from '../src/engine/tuning.js';
import { NEED_IDS } from '../src/engine/need-ids.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import type { RepoProfile, ReviewedTool, Service, StepSpec } from '../src/types.js';
import { entry, platform, reviewedList, service, specFor } from './helpers/render.js';
import { argvOf, exec, fakeTool, sandbox, stepEnv } from './helpers/step-harness.js';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const needFor = (t: ReviewedTool): string => t.categories.find((c) => (NEED_IDS as readonly string[]).includes(c) && c !== 'platform') ?? 'sast';
const IMG = `ghcr.io/o/app@sha256:${'a'.repeat(64)}`;
const TARGETS = { image: IMG, url: 'http://localhost:8080' };

/** A repo with an API service (own lockfile, Dockerfile, tsconfig), a web service and generated folders. */
const api = service({
  name: 'api', path: 'services/api', dockerfile: 'services/api/Dockerfile', lockfile: 'services/api/package-lock.json',
  scripts: ['start', 'test', 'lint', 'format:check', 'build', 'dev'], quality: { ...emptyServiceQuality(), tsconfig: true },
});
const web = service({ name: 'web', path: 'apps/web', lockfile: 'apps/web/pnpm-lock.yaml', packageManager: 'pnpm', scripts: ['serve', 'lint'] });
const py = service({ name: 'py', path: 'py', language: 'python', packageManager: 'poetry', lockfile: 'py/poetry.lock', alsoLanguages: ['node'], scripts: [] });
const prof = (services: Service[], over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free', monorepo: 'folders', services,
  terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(),
  generatedDirs: ['apps/web/.next', 'services/api/dist', 'services/api/src/generated', 'vendor'], ...over,
});
const ctxOf = (services: Service[] = [api, web, py], over: Partial<RepoProfile> = {}): RenderContext => ({ profile: prof(services, over), targets: TARGETS });
const baseCtx = ctxOf();

const spec = (id: string, tuning: Record<string, string[]> | undefined, over: Partial<StepSpec> = {}): StepSpec => {
  const t = entry(id);
  return specFor(t, { needId: needFor(t), choices: tuning === undefined ? {} : { tuning }, ...over });
};
const problems = (s: StepSpec, c: RenderContext = baseCtx): string[] => validateSpec(s, entry(s.tool.id), c);
const render = (s: StepSpec, c: RenderContext = baseCtx) => renderStep(s, entry(s.tool.id), platform(), c);
const runStep = (s: StepSpec, c: RenderContext = baseCtx): RenderedStep => render(s, c).steps.filter((x) => x.run !== undefined).at(-1) as RenderedStep;
const argEnv = (st: RenderedStep): string[] => Object.entries(st.env ?? {}).filter(([k]) => /^PIPEGEN_ARG_\d+$/.test(k)).sort(([a], [b]) => a.localeCompare(b, 'en', { numeric: true })).map(([, v]) => v);
/** A run script with its long docker line broken at its flags, then its PIPEGEN_ARG values: a readable snapshot (and no line the secret scan of test/ calls too long). */
const scriptSnapshot = (st: RenderedStep): string =>
  `${(st.run as string).replaceAll('$PWD', '<cwd>').replace(/ (-v|--config|--exclude|--ignore-pattern|--metrics=off|--sarif|--output|--security-opt|--network) /g, ' \\\n    $1 ')}\n# PIPEGEN_ARG values\n${argEnv(st).join('\n')}\n`;
const yamlOf = (steps: RenderedStep[]): string => {
  const doc = new Document();
  doc.contents = stepsToYaml(steps);
  return doc.toString({ lineWidth: 0 });
};

/** Tools that run the secret, dependency, image, IaC, licence or SBOM scans (the floor): never narrowed (DECISIONS #108). */
const FLOOR_CATEGORIES = ['secrets', 'deps', 'dependency-review', 'image-scan', 'iac', 'licences', 'sbom', 'dast', 'api-dast'];
/** The only categories whose folder skips #108 allows. */
const SKIP_OK_CATEGORIES = ['lint', 'sast', 'duplication', 'dead-code', 'format-lint', 'format'];
const NARROWING = /skip|ignore|exclude|severity|unfixed|baseline|threshold|alert|allow|suppress|disable|warn/i;

describe('the model: nothing narrows a floor scan (#108)', () => {
  it('the kinds are exactly adds and scope-lint; no option has any other kind (there is no narrow)', () => {
    expect([...TUNING_KINDS]).toEqual(['adds', 'scope-lint']);
    expect((TUNING_KINDS as readonly string[]).includes('narrow')).toBe(false);
    for (const o of TUNING_OPTIONS) expect(TUNING_KINDS as readonly string[], `${o.tool}/${o.id}`).toContain(o.kind);
  });

  it('every option names a real reviewed tool, once; ids are plain', () => {
    const ids = new Set(reviewedList().map((t) => t.id));
    const seen = new Set<string>();
    for (const o of TUNING_OPTIONS) {
      expect(ids.has(o.tool), o.tool).toBe(true);
      expect(`${o.tool}/${o.id}`).toMatch(/^[a-z0-9-]+\/[a-z-]+$/);
      expect(seen.has(`${o.tool}/${o.id}`), `${o.tool}/${o.id} twice`).toBe(false);
      seen.add(`${o.tool}/${o.id}`);
      expect(o.max).toBeGreaterThanOrEqual(1);
      expect(o.summary).toMatch(/^[A-Za-z]/);
    }
  });

  it('walking the model: a scope-lint option exists only on a lint or SAST class tool, never on a secret, dependency, image, IaC, licence, SBOM or DAST tool', () => {
    const tools = new Map(reviewedList().map((t) => [t.id, t]));
    for (const o of TUNING_OPTIONS) {
      const t = tools.get(o.tool) as ReviewedTool;
      if (o.kind === 'scope-lint') {
        expect(t.categories.some((c) => FLOOR_CATEGORIES.includes(c)), `${o.tool} is a floor tool`).toBe(false);
        expect(t.categories.every((c) => SKIP_OK_CATEGORIES.includes(c)), `${o.tool}: ${t.categories.join(',')}`).toBe(true);
      }
    }
  });

  it('walking the model: an option on a floor tool only adds, and none of its flags is a skip, ignore, exclude, severity, unfixed, baseline, threshold or alert switch', () => {
    const tools = new Map(reviewedList().map((t) => [t.id, t]));
    const onFloor = TUNING_OPTIONS.filter((o) => (tools.get(o.tool) as ReviewedTool).categories.some((c) => FLOOR_CATEGORIES.includes(c)));
    expect(onFloor.length).toBeGreaterThan(0);   // osv-scanner (lockfiles), zap-baseline and nuclei (start-script)
    for (const o of onFloor) {
      expect(o.kind, `${o.tool}/${o.id}`).toBe('adds');
      for (const f of o.flags) expect(f, `${o.tool}/${o.id} ${f}`).not.toMatch(NARROWING);
    }
  });

  it('no floor tool of the reviewed list has any narrowing option: secrets, trivy and syft have none at all', () => {
    const none = ['gitleaks', 'betterleaks', 'trivy-config', 'trivy-image', 'trivy-licence', 'syft', 'hadolint', 'kube-linter', 'biome', 'knip', 'prettier', 'ruff', 'bandit'];
    for (const id of none) expect(TUNING_OPTIONS.filter((o) => o.tool === id), id).toEqual([]);
    expect(TUNING_OPTIONS.filter((o) => o.tool === 'osv-scanner').map((o) => [o.id, o.kind, ...o.flags])).toEqual([['lockfiles', 'adds', '--lockfile']]);
  });

  it('the model, tool by tool (the table in the 6d report)', () => {
    const rows = (TUNING_OPTIONS as readonly TuningOption[]).map((o) => `${o.tool} | ${o.id} | ${o.kind} | max ${o.max} | ${o.flags.join(' ') || '-'}`);
    expect(rows).toEqual([
      'semgrep | extra-rules | adds | max 4 | --config',
      'semgrep | skip-generated | scope-lint | max 8 | --exclude',
      'osv-scanner | lockfiles | adds | max 8 | --lockfile',
      'eslint | skip-generated | scope-lint | max 8 | --ignore-pattern',
      'eslint-typescript | skip-generated | scope-lint | max 8 | --ignore-pattern',
      'oxlint-typeaware | skip-generated | scope-lint | max 8 | --ignore-pattern',
      'jscpd | skip-generated | scope-lint | max 8 | --ignore',
      'zap-baseline | start-script | adds | max 1 | -',
      'nuclei | start-script | adds | max 1 | -',
      'lefthook | hooks | adds | max 4 | -',
    ]);
  });

  it('no reviewed tool has a choice named tuning (the name is the tuning section)', () => {
    for (const t of reviewedList()) expect(Object.keys(t.choices), t.id).not.toContain('tuning');
  });

  it('the Semgrep folder list holds plain folder names, and no option uses one that is not on it', () => {
    for (const f of SEMGREP_RULE_FOLDERS) expect(f).toMatch(/^[a-z][a-z0-9_]{0,30}$/);
    const rich = ctxOf([service({ name: 'a', path: '.', dockerfile: 'Dockerfile', alsoLanguages: ['python', 'go', 'java', 'ruby', 'php', 'dotnet'], quality: { ...emptyServiceQuality(), tsconfig: true } })], { terraformDirs: ['infra'], hasCompose: true });
    const all = tuningEnums(entry('semgrep'), { choices: {} }, rich)['extra-rules'] ?? [];
    expect(all.length).toBeGreaterThan(3);
    for (const f of all) expect(SEMGREP_RULE_FOLDERS as readonly string[]).toContain(f);
  });
});

describe('enums come from the profile', () => {
  it('semgrep extra-rules: folders for the languages and files the service really has, never the one already chosen', () => {
    const e = (s: StepSpec, c = baseCtx) => tuningEnums(entry('semgrep'), s, c)['extra-rules'];
    // api: node + tsconfig + Dockerfile (base rules default javascript); no terraform or Kubernetes
    expect(e(spec('semgrep', undefined, { service: 'api', workingDir: 'services/api' }))).toEqual(['typescript', 'dockerfile']);
    // the base set typescript chosen: typescript is no longer an extra, javascript is
    expect(e(spec('semgrep', undefined, { service: 'api', workingDir: 'services/api', choices: { rules: 'typescript' } }))).toEqual(['javascript', 'dockerfile']);
    // a python service that also holds node code
    expect(e(spec('semgrep', undefined, { service: 'py', workingDir: 'py', choices: { rules: 'python' } }))).toEqual(['javascript']);
    // terraform, Kubernetes and compose files
    const infra = ctxOf([api], { terraformDirs: ['infra'], repoFiles: { ...emptyRepoFiles(), kubernetes: true } });
    expect(e(spec('semgrep', undefined, { service: 'api' }), infra)).toEqual(['typescript', 'dockerfile', 'terraform', 'yaml']);
  });

  it('osv-scanner lockfiles: the lockfile the profile found per service, inside the step folder', () => {
    const e = (s: StepSpec) => tuningEnums(entry('osv-scanner'), s, baseCtx).lockfiles;
    expect(e(spec('osv-scanner', undefined, { needId: 'deps' }))).toEqual(['apps/web/pnpm-lock.yaml', 'py/poetry.lock', 'services/api/package-lock.json']);
    expect(e(spec('osv-scanner', undefined, { needId: 'deps', service: 'api', workingDir: 'services/api' }))).toEqual(['services/api/package-lock.json']);
    // a service whose lockfile is the root's has none inside its own folder
    const rootLock = ctxOf([service({ name: 's', path: 'sub', lockfile: 'package-lock.json' })]);
    expect(tuningEnums(entry('osv-scanner'), spec('osv-scanner', undefined, { needId: 'deps', service: 's', workingDir: 'sub' }), rootLock).lockfiles).toEqual([]);
  });

  it('skip-generated: the folders the profile marks as vendored or generated, inside the step folder', () => {
    const e = (id: string, s: Partial<StepSpec> = {}) => tuningEnums(entry(id), spec(id, undefined, s), baseCtx)['skip-generated'];
    expect(e('eslint')).toEqual(['apps/web/.next', 'services/api/dist', 'services/api/src/generated', 'vendor']);
    expect(e('eslint', { service: 'api', workingDir: 'services/api' })).toEqual(['services/api/dist', 'services/api/src/generated']);
    expect(e('semgrep', { service: 'web', workingDir: 'apps/web' })).toEqual(['apps/web/.next']);
    expect(tuningEnums(entry('eslint'), spec('eslint', undefined), ctxOf([api], { generatedDirs: undefined }))['skip-generated']).toEqual([]);
  });

  it('start-script: only a start or serve script the service has; dev and anything else never', () => {
    const e = (svc: string, wd: string, id = 'zap-baseline') => tuningEnums(entry(id), spec(id, undefined, { service: svc, workingDir: wd, needId: 'dast' }), baseCtx)['start-script'];
    expect(e('api', 'services/api')).toEqual(['start']);
    expect(e('web', 'apps/web')).toEqual(['serve']);
    expect(e('py', 'py')).toEqual([]);
    expect(e('api', 'services/api', 'nuclei')).toEqual(['start']);
    const devOnly = ctxOf([service({ name: 'd', path: '.', scripts: ['dev', 'build'] })]);
    expect(tuningEnums(entry('zap-baseline'), spec('zap-baseline', undefined, { service: 'd', needId: 'dast' }), devOnly)['start-script']).toEqual([]);
  });

  it('lefthook hooks: the service\'s own lint and format-check scripts (npm only), and none when the repo already has lefthook hooks', () => {
    const e = (c = baseCtx, svc = 'api') => tuningEnums(entry('lefthook'), spec('lefthook', undefined, { service: svc, needId: 'hooks-ci' }), c).hooks;
    expect(e()).toEqual(['lint', 'format:check']);
    expect(e(ctxOf([api, web, py], { precommit: 'lefthook' }))).toEqual([]);
    expect(e(baseCtx, 'web')).toEqual([]);   // pnpm: project scripts run with npm only
    expect(e(ctxOf([service({ name: 'x', path: '.', scripts: ['format', 'lint:fix', 'fix'] })]), 'x')).toEqual([]);   // scripts that write are not hooks
  });

  it('a hostile profile fact never reaches an enum: .., absolute, leading dash, newline, ${{, space, glob', () => {
    const bad = ['../x', '/etc', '-rf', 'a\nb', '${{ x }}', 'a b', 'a/*', 'a//b', '~/x', '', 'a\u001b[31m', 'x'.repeat(300)];
    const hostile = ctxOf([service({ name: 'h', path: '.', lockfile: bad[0] })], { generatedDirs: [...bad, 'ok/dist'] });
    expect(tuningEnums(entry('eslint'), spec('eslint', undefined), hostile)['skip-generated']).toEqual(['ok/dist']);
    for (const b of bad) {
      const c = ctxOf([service({ name: 'h', path: '.', lockfile: b })]);
      expect(tuningEnums(entry('osv-scanner'), spec('osv-scanner', undefined, { needId: 'deps' }), c).lockfiles, JSON.stringify(b)).toEqual([]);
    }
  });
});

describe('validateSpec checks every tuning value against the enum built for the call', () => {
  const ok = spec('eslint', { 'skip-generated': ['services/api/dist'] }, { service: 'api', workingDir: 'services/api' });

  it('a value in the enum passes; no tuning, an empty tuning and an empty option pass', () => {
    expect(problems(ok)).toEqual([]);
    expect(problems(spec('eslint', undefined))).toEqual([]);
    expect(problems(spec('eslint', {}))).toEqual([]);
    expect(problems(spec('eslint', { 'skip-generated': [] }))).toEqual([]);
  });

  it('a value outside the enum is refused, with the field path and the values the call allows', () => {
    const p = problems(spec('eslint', { 'skip-generated': ['src'] }, { service: 'api', workingDir: 'services/api' }));
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/^choices\.tuning\.skip-generated\[0\]: "src" is not one of the values this call allows \(services\/api\/dist, services\/api\/src\/generated\)/);
  });

  it('hostile folder names and lockfile paths are refused: .., absolute, a leading dash, a newline, ${{, quotes, a glob', () => {
    const hostile = ['..', '../x', 'services/api/../../etc', '/etc/passwd', '-rf', '--config=x', 'a\nb', '${{ secrets.X }}', "x';id;'", '$(id)', '*', 'services/api/*', 'services/api/dist/../..'];
    for (const h of hostile) {
      expect(problems(spec('eslint', { 'skip-generated': [h] }, { service: 'api', workingDir: 'services/api' })), `skip ${JSON.stringify(h)}`).toHaveLength(1);
      expect(problems(spec('osv-scanner', { lockfiles: [h] }, { needId: 'deps' })), `lock ${JSON.stringify(h)}`).toHaveLength(1);
      expect(() => render(spec('osv-scanner', { lockfiles: [h] }, { needId: 'deps' })), h).toThrow(RenderError);
    }
  });

  it('a folder the profile did not mark as vendored or generated is refused, even a real source folder', () => {
    for (const f of ['services/api/src', 'src', 'lib', 'services/api', '.', 'services/api/build', 'node_modules']) {
      expect(problems(spec('eslint', { 'skip-generated': [f] }, { service: 'api', workingDir: 'services/api' })), f).toHaveLength(1);
    }
    // a marked folder of ANOTHER service is outside this step's folder
    expect(problems(spec('eslint', { 'skip-generated': ['apps/web/.next'] }, { service: 'api', workingDir: 'services/api' }))).toHaveLength(1);
  });

  it('skips never appear on secret, dependency or image tools: the option does not exist there', () => {
    for (const id of ['gitleaks', 'betterleaks', 'osv-scanner', 'trivy-config', 'trivy-image', 'trivy-licence', 'syft', 'zap-baseline', 'nuclei']) {
      const p = problems(spec(id, { 'skip-generated': ['vendor'] }));
      expect(p, id).toHaveLength(1);
      expect(p[0], id).toMatch(/^choices\.tuning\.skip-generated: this tool has no tuning option with that name/);
    }
    // and the hostile option names that would narrow, on every tool
    for (const name of ['skip-dirs', 'skip-paths', 'ignore-unfixed', 'severity', 'ignore-paths', 'alerts', 'exclude']) {
      for (const id of ['gitleaks', 'osv-scanner', 'trivy-image', 'zap-baseline']) expect(problems(spec(id, { [name]: ['x'] })), `${id}/${name}`).toHaveLength(1);
    }
  });

  it('shape errors: not a map, a value that is not a list, not text, too many, twice, an option of another tool, prototype names', () => {
    const bad = (tuning: unknown) => problems(spec('eslint', tuning as never, { service: 'api', workingDir: 'services/api' }));
    expect(bad('dist')[0]).toMatch(/^choices\.tuning: must be a map/);
    expect(bad(['x'])[0]).toMatch(/^choices\.tuning: must be a map/);
    expect(bad(null)[0]).toMatch(/^choices\.tuning: must be a map/);
    expect(bad({ 'skip-generated': 'services/api/dist' })[0]).toMatch(/must be a list/);
    expect(bad({ 'skip-generated': [1] })[0]).toMatch(/must be text/);
    expect(bad({ 'skip-generated': [{ a: 1 }] })[0]).toMatch(/must be text/);
    expect(bad({ 'skip-generated': ['services/api/dist', 'services/api/dist'] })[0]).toMatch(/listed twice/);
    expect(bad({ 'extra-rules': ['dockerfile'] })[0]).toMatch(/no tuning option/);
    for (const n of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) expect(bad(JSON.parse(`{"${n}": ["x"]}`)), n).toHaveLength(1);
    // more values than the option's maximum
    const many = ctxOf([service({ name: 'm', path: '.' })], { generatedDirs: Array.from({ length: 10 }, (_, i) => `p${i}/dist`) });
    const dirs = tuningEnums(entry('eslint'), spec('eslint', undefined), many)['skip-generated'] ?? [];
    expect(dirs).toHaveLength(10);
    expect(problems(spec('eslint', { 'skip-generated': dirs }), many)[0]).toMatch(/at most 8/);
    expect(problems(spec('eslint', { 'skip-generated': dirs.slice(0, 8) }), many)).toEqual([]);
  });

  it('a tool without options takes no tuning; an action takes none either', () => {
    expect(problems(spec('gitleaks', { anything: ['x'] }))[0]).toMatch(/no tuning option/);
    const a = platform().checkout;
    expect(validateSpec(specFor(a, { needId: 'platform' as never, choices: { tuning: { x: ['y'] } } }), a, baseCtx).some((p) => /no tuning option/.test(p))).toBe(true);
  });

  it('a tool choice cannot be smuggled in as the tuning section, and the section is not read as a choice', () => {
    expect(problems(spec('semgrep', undefined, { choices: { rules: 'javascript' } }))).toEqual([]);
    // the tuning section is a map; a text value under that name is a shape error, not a choice value
    expect(problems(specFor(entry('semgrep'), { needId: 'sast', choices: { tuning: 'x' as never } }))[0]).toMatch(/choices\.tuning: must be a map/);
  });
});

describe('each option renders as ruled', () => {
  it('semgrep extra-rules: the folder is mounted read-only beside the base rules and named with its own --config', async () => {
    const s = spec('semgrep', { 'extra-rules': ['typescript', 'dockerfile'] }, { service: 'api', workingDir: 'services/api' });
    const r = render(s);
    const st = runStep(s);
    expect(r.steps.length).toBeGreaterThan(1);
    expect(st.run).toContain('-v "$rules/typescript:/pipegen-rules-extra/typescript:ro"');
    expect(st.run).toContain('-v "$rules/dockerfile:/pipegen-rules-extra/dockerfile:ro"');
    expect(st.run).toContain('--config /pipegen-rules-extra/typescript');
    expect(st.run).toContain('--config /pipegen-rules-extra/dockerfile');
    expect(st.run).toMatch(/-v "\$rules\/\$PIPEGEN_ARG_0:\/pipegen-rules:ro"/);   // the base set stays (its folder in env, as before)
    expect(argEnv(st)[0]).toBe('javascript');
    expect(st.run).toContain('--config /pipegen-rules');
    expect(st.run).toMatch(/pg_fail "the rules folder is missing or a link"/);
    await expect(scriptSnapshot(st)).toMatchFileSnapshot('__snapshots__/tuning/semgrep-extra-rules.sh');
  });

  it('semgrep skip-generated: --exclude, the folder relative to the step folder, the value in env and never in the shell text', async () => {
    const s = spec('semgrep', { 'skip-generated': ['services/api/dist', 'services/api/src/generated'] }, { service: 'api', workingDir: 'services/api' });
    const st = runStep(s);
    expect(argEnv(st)).toEqual(expect.arrayContaining(['dist', 'src/generated']));
    expect(st.run).toMatch(/--exclude "\$PIPEGEN_ARG_\d+" --exclude "\$PIPEGEN_ARG_\d+"/);
    expect((st.run as string).split('\n').filter((l) => !l.startsWith('# tuning:')).join('\n')).not.toContain('src/generated');   // only the comment names it
    await expect(scriptSnapshot(st)).toMatchFileSnapshot('__snapshots__/tuning/semgrep-skip-generated.sh');
  });

  it('eslint, eslint-typescript and oxlint: --ignore-pattern "<folder>/**" before the files; jscpd: --ignore', async () => {
    const wd = { service: 'api', workingDir: 'services/api' };
    for (const [id, flag, pos] of [['eslint', '--ignore-pattern', '.'], ['eslint-typescript', '--ignore-pattern', '.'], ['oxlint-typeaware', '--ignore-pattern', null], ['jscpd', '--ignore', '.']] as const) {
      const s = spec(id, { 'skip-generated': ['services/api/dist'] }, wd);
      const st = runStep(s);
      expect(argEnv(st), id).toContain('dist/**');
      expect(st.run, id).toMatch(new RegExp(`${flag} "\\$PIPEGEN_ARG_\\d+"`));
      // the files word stays last: the flag is before it (urfave and cobra tools stop reading flags at the first plain word)
      if (pos !== null) {
        const line = (st.run as string).split('\n').find((l) => l.includes(flag)) as string;
        expect(line.indexOf(flag), id).toBeLessThan(line.lastIndexOf(` ${pos} `) === -1 ? line.length : line.lastIndexOf(` ${pos} `));
      }
    }
    // the run script and its PIPEGEN_ARG values (the step's closure lock env is a long line the secret-pattern scan of test/ rejects)
    const st = runStep(spec('eslint', { 'skip-generated': ['services/api/dist'] }, wd));
    await expect(scriptSnapshot(st)).toMatchFileSnapshot('__snapshots__/tuning/eslint-skip-generated.sh');
  });

  it('a repo-wide step skips the folders as repo-relative patterns', () => {
    const st = runStep(spec('eslint', { 'skip-generated': ['vendor', 'services/api/dist'] }));
    expect(argEnv(st)).toEqual(expect.arrayContaining(['vendor/**', 'services/api/dist/**']));
  });

  it('osv-scanner lockfiles: --lockfile per path, right after the subcommand and before --recursive and the folder', async () => {
    const s = spec('osv-scanner', { lockfiles: ['apps/web/pnpm-lock.yaml', 'services/api/package-lock.json'] }, { needId: 'deps' });
    const st = runStep(s);
    expect(argEnv(st)).toEqual(expect.arrayContaining(['apps/web/pnpm-lock.yaml', 'services/api/package-lock.json']));
    const line = (st.run as string).split('\n').find((l) => l.includes('--recursive')) as string;
    expect(line).toMatch(/scan source --lockfile "\$PIPEGEN_ARG_\d+" --lockfile "\$PIPEGEN_ARG_\d+"/);
    expect(line.indexOf('--lockfile')).toBeLessThan(line.indexOf('--recursive'));
    await expect(yamlOf(render(s).steps)).toMatchFileSnapshot('__snapshots__/tuning/osv-lockfiles.yml');
  });

  it('lefthook hooks: a generated config of the service\'s own scripts, written beside the run and named by LEFTHOOK_CONFIG; env -i lets only that through', async () => {
    const s = spec('lefthook', { hooks: ['lint', 'format:check'] }, { service: 'api', needId: 'hooks-ci' });
    const st = runStep(s);
    expect(st.id).toMatch(/^repocode-/);   // repo code: the referee's order rule applies
    const cfg = st.env?.PIPEGEN_TUNED_CONFIG as string;
    expect(cfg).toBe('pre-commit:\n  commands:\n    lint:\n      root: services/api/\n      run: npm run lint\n    format-check:\n      root: services/api/\n      run: npm run format:check\n');
    expect(st.run).toContain('printf \'%s\' "$PIPEGEN_TUNED_CONFIG" > "$cfg/lefthook.yml"');
    expect(st.run).toContain('"LEFTHOOK_CONFIG=$cfg/lefthook.yml"');
    expect(st.run).not.toContain('npm run');   // the commands are data in the config, not shell text
    await expect(yamlOf(render(s).steps)).toMatchFileSnapshot('__snapshots__/tuning/lefthook-hooks.yml');
  });

  it('lefthook hooks, really run: the tool sees LEFTHOOK_CONFIG pointing at the generated file, and nothing else of the job env', () => {
    const s = spec('lefthook', { hooks: ['lint'] }, { service: 'api', needId: 'hooks-ci' });
    const st = runStep(s);
    const sb = sandbox();
    fakeTool(sb, 'pipegen-out-hooks-ci--api', 'lefthook', 'cat "$LEFTHOOK_CONFIG" > ./cfg-seen.txt');
    const res = exec(st, sb, stepEnv(st, sb, {}, { LEFTHOOK_CONFIG: '/planted/evil.yml' }));
    expect(res.status, res.stderr).toBe(0);
    expect(readFileSync(join(sb.ws, 'cfg-seen.txt'), 'utf8')).toContain('run: npm run lint');
    expect(readFileSync(join(sb.ws, 'env.txt'), 'utf8')).not.toContain('/planted/evil.yml');
    expect(argvOf(sb)).toEqual(['run', 'pre-commit', '--all-files']);
  });

  it('the start script (ZAP, nuclei) changes no step: the app is started by Plan G, which asks startScriptOf', () => {
    for (const id of ['zap-baseline', 'nuclei']) {
      const plain = spec(id, undefined, { service: 'api', needId: 'dast' });
      const tuned = spec(id, { 'start-script': ['start'] }, { service: 'api', needId: 'dast' });
      const strip = (st: RenderedStep) => ({ ...st, run: (st.run as string).split('\n').filter((l) => !l.startsWith('# tuning:')).join('\n') });
      expect(strip(runStep(tuned)), id).toEqual(strip(runStep(plain)));
      expect(startScriptOf(tuned, entry(id), baseCtx), id).toEqual({ service: 'api', script: 'start' });
      expect(startScriptOf(plain, entry(id), baseCtx), id).toBeNull();
    }
  });

  it('the start script without a reviewed start script in the profile is refused, with the reason', () => {
    const p = problems(spec('zap-baseline', { 'start-script': ['start'] }, { service: 'py', needId: 'dast' }));
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/^choices\.tuning\.start-script: the service "py" has no start or serve script in its package\.json, so pipegen can not start the app for the scan/);
    expect(problems(spec('zap-baseline', { 'start-script': ['dev'] }, { service: 'api', needId: 'dast' }))).toHaveLength(1);
    expect(() => render(spec('zap-baseline', { 'start-script': ['start'] }, { service: 'py', needId: 'dast' }))).toThrow(RenderError);
  });

  it('every tuned step shows its tuning in a comment line of its script', () => {
    const st = runStep(spec('semgrep', { 'extra-rules': ['dockerfile'], 'skip-generated': ['services/api/dist'] }, { service: 'api', workingDir: 'services/api' }));
    const lines = (st.run as string).split('\n').filter((l) => l.startsWith('# tuning:'));
    expect(lines).toEqual([
      '# tuning: also runs the Semgrep rule sets dockerfile (adds coverage)',
      '# tuning: skips the vendored or generated folders services/api/dist for this lint or SAST tool only',
    ]);
    const plain = runStep(spec('semgrep', undefined, { service: 'api', workingDir: 'services/api' }));
    expect(plain.run).not.toContain('# tuning');
  });

  it('a spec with no tuning renders exactly as before, and an empty tuning section renders the same', () => {
    for (const id of ['semgrep', 'eslint', 'osv-scanner', 'lefthook', 'zap-baseline']) {
      const a = render(spec(id, undefined, { needId: needFor(entry(id)) }));
      const b = render(spec(id, {}, { needId: needFor(entry(id)) }));
      const c = render(spec(id, Object.fromEntries(TUNING_OPTIONS.filter((o) => o.tool === id).map((o) => [o.id, []])), { needId: needFor(entry(id)) }));
      expect(b, id).toEqual(a);
      expect(c, id).toEqual(a);
    }
  });

  it('tuning effects of a validated spec; effects of an unvalidated one are not built', () => {
    const e = tuningEffects(spec('eslint', { 'skip-generated': ['vendor'] }), entry('eslint'), baseCtx);
    expect(e.flags).toEqual([{ flag: '--ignore-pattern', value: 'vendor/**', key: 'tune:skip-generated:0' }]);
    expect(() => tuningEffects(spec('eslint', { 'skip-generated': ['../x'] }), entry('eslint'), baseCtx)).toThrow(RenderError);
  });
});

describe('tuned scripts are valid shell', () => {
  it('bash -n accepts every tuned run script', () => {
    const wd = { service: 'api', workingDir: 'services/api' };
    const all: StepSpec[] = [
      spec('semgrep', { 'extra-rules': ['typescript', 'dockerfile'], 'skip-generated': ['services/api/dist'] }, wd),
      spec('eslint', { 'skip-generated': ['services/api/dist'] }, wd), spec('oxlint-typeaware', { 'skip-generated': ['services/api/dist'] }, wd), spec('jscpd', { 'skip-generated': ['services/api/dist'] }, wd),
      spec('osv-scanner', { lockfiles: ['services/api/package-lock.json'] }, { needId: 'deps' }),
      spec('lefthook', { hooks: ['lint'] }, { service: 'api', needId: 'hooks-ci' }), spec('zap-baseline', { 'start-script': ['start'] }, { service: 'api', needId: 'dast' }),
    ];
    for (const s of all) {
      const r = spawnSync('bash', ['-n'], { input: runStep(s).run, encoding: 'utf8' });
      expect(r.status, `${s.tool.id}: ${r.stderr}`).toBe(0);
    }
  });
});

describe('describeTuning', () => {
  it('plain-English lines for a tuned spec, none for an untuned one', () => {
    expect(describeTuning(spec('eslint', undefined))).toEqual([]);
    expect(describeTuning(spec('eslint', {}))).toEqual([]);
    expect(describeTuning(spec('osv-scanner', { lockfiles: ['py/poetry.lock'] }, { needId: 'deps' }))).toEqual(['also scans the lockfile py/poetry.lock (adds coverage)']);
    expect(describeTuning(spec('eslint', { 'skip-generated': ['vendor', 'services/api/dist'] }))).toEqual(['skips the vendored or generated folders vendor, services/api/dist for this lint or SAST tool only']);
    expect(describeTuning(spec('lefthook', { hooks: ['lint'] }, { service: 'api', needId: 'hooks-ci' }))).toEqual(['runs the service\'s own lint script as a pre-commit hook (adds coverage)']);
    expect(describeTuning(spec('zap-baseline', { 'start-script': ['start'] }, { needId: 'dast' }))).toEqual(['the app is started with its own start script before the scan (adds coverage)']);
  });

  it('every line is clean text: no control characters, no markup, short, even for hostile values', () => {
    const hostile = spec('eslint', { 'skip-generated': ['a\u001b[31m\nb', '\u202eevil', '${{ secrets.X }}', 'x'.repeat(500)], 'nope': ['y'], __proto__: ['z'] } as never);
    const lines = describeTuning(hostile);
    expect(lines.length).toBeGreaterThan(0);
    for (const l of lines) {
      // eslint-disable-next-line no-control-regex
      expect(l).not.toMatch(new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]'));
      expect(l.length).toBeLessThanOrEqual(400);
    }
    expect(lines.join('\n')).not.toContain('nope');
  });

  it('a spec that is not an object, or a tool with no model, gives no lines and does not throw', () => {
    for (const bad of [null, undefined, 5, 'x', [], { tool: null }, { tool: { id: 'eslint' }, choices: null }]) expect(describeTuning(bad as never)).toEqual([]);
    expect(describeTuning(spec('gitleaks', { x: ['y'] }))).toEqual([]);
  });
});

describe('the Semgrep folder choice', () => {
  it('only a reviewed folder of the rules tree can be mounted: anything else is refused', () => {
    for (const f of ['../etc', 'a/b', 'JavaScript', '', 'c d', "x'", 'yaml/..', 'problem-based-packs', 'scripts']) {
      expect(problems(spec('semgrep', { 'extra-rules': [f] }, { service: 'api' })), JSON.stringify(f)).toHaveLength(1);
    }
  });
});
