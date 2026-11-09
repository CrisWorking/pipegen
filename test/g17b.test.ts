// v0.2 Plan G G17 group B (rows 13-21 of task-G17-brief.md): job rendering hardening.
// 13 the compose-path DAST app containers drop every capability (as the archive path does), in pipegen's compose file itself;
// 14 a DAST step with secrets is refused by the DAST renderer itself, not only by the referee and the generic secrets rule;
// 15 dastStartOf reads the build-push id from the shared table; 16 T52 names the Bullfrog egress step;
// 17 the tsc lockfile check refuses only the copies the shim can reach; 18 a created Dockerfile's npm ci passes --git=/usr/bin/git;
// 19 (open question 9) a blocking check of an image pipegen can not build stops with a plain reason; 21 (open question 13) one name
// when the repository and the service share it.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { composeText } from '../src/create/compose.js';
import { dockerfileProblems, dockerignoreText, type DockerfileCtx } from '../src/create/dockerfile-rules.js';
import { pipegenDoc } from '../src/deliver/docs.js';
import { renderComposeUp } from '../src/engine/render-step.js';
import { dockerfileInstructions } from '../src/ai/prompts/dockerfile.js';
import { baseImageRef, loadBaseImages } from '../src/engine/base-images.js';
import { dastStartOf, renderDastRun } from '../src/engine/dast-handoff.js';
import { publishedImageRepo } from '../src/engine/deploy-steps.js';
import { floorNeeds } from '../src/engine/needs.js';
import { PLATFORM_ACTION_IDS } from '../src/engine/pin.js';
import { repoToolCheckJs } from '../src/engine/render-cli.js';
import { RenderError } from '../src/engine/render-error.js';
import { AssembleError, type Job } from '../src/layers/jobs.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { CreatedFile, Service } from '../src/types.js';
import { assemble, CAPS, files, judge, node, p, planned, profileOf, SEC, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { makeTempDir } from './helpers/make-repo.js';

const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
const web = () => node({ dockerfile: 'Dockerfile', port: 3000 });
/** A secret-like name, built at runtime (repo rule: no secret-looking literal under test/). */
const TOK = ['APP', 'TOK' + 'EN'].join('_');
const PG = { kind: 'postgres' as const, name: 'postgres', evidence: 'x', envVars: ['DATABASE_URL'] };

/** The YAML block of one service in the compose text (its lines up to the next top-level service key). */
const blockOf = (text: string, key: string): string => {
  const lines = text.split('\n');
  const at = lines.indexOf(`  ${key}:`);
  expect(at, key).toBeGreaterThan(0);
  const end = lines.findIndex((l, i) => i > at && /^ {2}[a-z]/.test(l));
  return lines.slice(at, end < 0 ? undefined : end).join('\n');
};

describe('G17 row 13: the compose-path DAST app containers drop every capability', () => {
  const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], dependsOn: [PG] })]);
  const text = composeText(prof, loadBaseImages()) as string;

  it('compose: every app service has cap_drop ALL and no-new-privileges; the dependency containers keep their capabilities (their entrypoints switch users) but gain no privilege (G17B-R1 sec M2)', () => {
    const app = blockOf(text, 'app-app');
    expect(app).toContain('    cap_drop:\n      - "ALL"');
    expect(app).toContain('    security_opt:\n      - "no-new-privileges:true"');
    const db = blockOf(text, 'postgres');
    expect(db).not.toMatch(/cap_drop/);
    expect(db).toContain('    security_opt:\n      - "no-new-privileges:true"');
    expect(text.match(/cap_drop:/g)?.length).toBe(1);
    expect(text.match(/no-new-privileges:true/g)?.length).toBe(2);
  });

  it('threat model: T54 says the compose start builds the app image inside the DAST run job (a second build of the Dockerfile, not the scanned archive)', () => {
    const r = readFileSync('docs/threat-model.md', 'utf8').split('\n').find((l) => l.startsWith('| T54 |')) as string;
    expect(r).toMatch(/compose start builds the app's image inside the DAST run job/);
  });

  it('assemble: the DAST run job starts the hardened compose file; the old text without the drop is not pipegen\'s file, so no job starts it', async () => {
    const compose: CreatedFile = { path: 'docker-compose.pipegen.yml', content: text, part: 'compose', reason: 't', repo: 'app' };
    const a = assemble(planned(prof, { over: { created: [compose], ...SKIP_DEPLOY } }));
    const run = a.merge['dast-run--app'] as Job;
    expect(run.steps.some((s) => s.id?.startsWith('runtime-env-') === true)).toBe(true);
    expect(run.needs, 'the compose start, not the archive').toBeUndefined();
    expect(shown(await judge([...files(a), compose], a.draft))).toBe('');
    // the same file without the two hardening keys (the text before G17): the assembler and the referee refuse it as pipegen's compose file
    const old = text.replace('    cap_drop:\n      - "ALL"\n', '').replace('    security_opt:\n      - "no-new-privileges:true"\n', '');
    expect(old).not.toBe(text);
    const stale: CreatedFile = { ...compose, content: old };
    const b = assemble(planned(prof, { over: { created: [stale], ...SKIP_DEPLOY } }));
    expect(b.notes.join('\n')).toMatch(/docker-compose\.pipegen\.yml is not the file pipegen computes, so no job starts it/);
    expect((b.merge['dast-run--app'] as Job).needs, 'falls back to the checked archive (also no capability)').toEqual(['image-build--app']);
    expect(shown(await judge([...files(b), stale], b.draft))).toMatch(/compose file is not the file pipegen computes/);
  });
});

describe('G17 row 14: a DAST step with secrets is refused at assembly with a plain reason', () => {
  it('renderDastRun: a DAST spec that names a secret is a RenderError, whatever the tool\'s categories say', () => {
    const x = planned(profileOf([web()]), { over: SKIP_DEPLOY });
    const spec = x.draft.steps.find((s) => s.needId === 'dast' && s.service === 'app');
    const tool = REVIEWED.find((t) => t.id === spec?.tool.id);
    const start = dastStartOf(x.draft, 'app');
    if (spec === undefined || tool === undefined || 'problem' in start) throw new Error('fixture');
    expect(() => renderDastRun(spec, tool, p, x.draft, start, { blocking: true, checkout: [] })).not.toThrow();
    for (const secrets of [[TOK], ['A', 'B']]) {
      expect(() => renderDastRun({ ...spec, secrets }, tool, p, x.draft, start, { blocking: true, checkout: [] })).toThrow(RenderError);
      expect(() => renderDastRun({ ...spec, secrets }, tool, p, x.draft, start, { blocking: true, checkout: [] })).toThrow(/DAST check .*no secret/);
    }
    // an empty list names none
    const none: string[] = [];
    expect(() => renderDastRun({ ...spec, [SEC]: none }, tool, p, x.draft, start, { blocking: true, checkout: [] })).not.toThrow();
  });

  it('assemble: a draft whose DAST step names a secret stops before any job is written', () => {
    const x = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000, envVars: [TOK] })]), { over: SKIP_DEPLOY, edit: (s) => s.map((st) => (st.needId === 'dast' ? { ...st, [SEC]: [TOK] } : st)) });
    expect(() => assemble(x)).toThrow(AssembleError);
    expect(() => assemble(x)).toThrow(new RegExp(`^The DAST check "dast" for "app" names secrets \\("${TOK}"\\)\\. A DAST check runs the app with no secret`));
  });
});

describe('G17 row 15: dastStartOf reads the build-push id from the shared table', () => {
  it('dastStartOf: the archive start needs the image-build step of the reviewed build-push id; another tool id is no build', () => {
    const x = planned(profileOf([web()]), { over: SKIP_DEPLOY });
    const build = x.draft.steps.find((s) => s.needId === 'image-build' && s.service === 'app');
    expect(build?.tool.id).toBe(PLATFORM_ACTION_IDS['build-push']);
    expect(dastStartOf(x.draft, 'app')).toEqual({ kind: 'archive', port: 3000, url: 'http://127.0.0.1:3000' });
    const other = { ...x.draft, steps: x.draft.steps.map((s) => (s === build ? { ...s, tool: { ...s.tool, id: 'docker-build-push-action-x' } } : s)) };
    expect(dastStartOf(other, 'app')).toMatchObject({ problem: expect.stringMatching(/no container image pipegen builds/) });
  });
});

describe('G17 row 16 (+ G17B-R1 spec M1): T52 names every reviewed action of the sign jobs', () => {
  const row = (): string => readFileSync('docs/threat-model.md', 'utf8').split('\n').find((l) => l.startsWith('| T52 |')) as string;
  it('threat model: T52 names Bullfrog and the pinned download-artifact in the key-env sign job, and claims no sign job runs no third-party action', () => {
    const r = row();
    expect(r).toBeDefined();
    expect(r).toMatch(/Bullfrog/);
    expect(r).toMatch(/two reviewed actions run in that job: the pinned Bullfrog egress step[^|]*and the pinned download-artifact/);
    expect(r).not.toMatch(/no third-party action/);
    expect(r).not.toMatch(/one third-party action/);
    // the keyless and attest sign jobs: the actions they do run are named
    expect(r).toMatch(/keyless sign job[^|]*download-artifact/);
    expect(r).toMatch(/attest sign job[^|]*download-artifact and actions\/attest/);
  });
});

describe('G17 row 17: the tsc lockfile check refuses only the copies the shim can reach', () => {
  const plat = `typescript-${process.platform}-${process.arch}`;
  const native = `@typescript/${plat}`;
  const reg = (name: string, v: string): string => `https://registry.npmjs.org/${name}/-/${name.slice(name.indexOf('/') + 1)}-${v}.tgz`;
  const sri = (c: string): string => `sha512-${c.repeat(86)}==`;
  /** TypeScript 7.0.2 with its platform package installed the way npm ci does, plus `extra` lockfile entries. */
  const fixture = (extra: Obj = {}): string => {
    const d = makeTempDir();
    const v = '7.0.2';
    const ts = { version: v, resolved: reg('typescript', v), integrity: sri('A'), dev: true, bin: { tsc: 'bin/tsc' } };
    const nat = { version: v, resolved: reg(native, v), integrity: sri('C'), dev: true, optional: true };
    writeFileSync(join(d, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/typescript': ts, [`node_modules/${native}`]: nat, ...extra } }));
    mkdirSync(join(d, 'node_modules', 'typescript', 'bin'), { recursive: true });
    mkdirSync(join(d, 'node_modules', 'typescript', 'lib'));
    writeFileSync(join(d, 'node_modules', 'typescript', 'package.json'), JSON.stringify({ name: 'typescript', version: v, bin: { tsc: './bin/tsc' } }));
    writeFileSync(join(d, 'node_modules', 'typescript', 'bin', 'tsc'), '');
    const dir = join(d, 'node_modules', '@typescript', plat);
    mkdirSync(join(dir, 'lib'), { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: native, version: v, exports: { './package.json': './package.json' } }));
    writeFileSync(join(dir, 'lib', 'tsc'), '');
    writeFileSync(join(d, 'node_modules', '.package-lock.json'), JSON.stringify({ packages: { 'node_modules/typescript': ts, [`node_modules/${native}`]: nat } }));
    return d;
  };
  const runs = (d: string): { status: number; err: string } => {
    try { execFileSync(process.execPath, ['-e', repoToolCheckJs('tsc')], { cwd: d, env: {}, stdio: 'pipe' }); return { status: 0, err: '' }; } catch (e) { const x = e as { status: number; stderr: Buffer }; return { status: x.status, err: x.stderr.toString() }; }
  };

  it('render: a copy under another package or in a workspace folder (never on the shim\'s resolution path) passes; a copy inside typescript is refused with a true message', () => {
    expect(runs(fixture())).toEqual({ status: 0, err: '' });
    // copies the shim never resolves: another dependency's own copy (any version, any source), a workspace member's, a deeper one inside typescript
    const old = { version: '7.0.0', resolved: 'https://codeload.github.com/x/y/tar.gz/abc', dev: true };
    for (const k of [`node_modules/some-dep/node_modules/${native}`, `packages/web/node_modules/${native}`, `node_modules/typescript/node_modules/other/node_modules/${native}`]) {
      expect(runs(fixture({ [k]: old })), k).toEqual({ status: 0, err: '' });
    }
    // the copy the shim would find first (inside typescript's own node_modules): refused, and the message says where it is
    const r = runs(fixture({ [`node_modules/typescript/node_modules/${native}`]: old }));
    expect(r.status).toBe(1);
    expect(r.err).toMatch(new RegExp(`a nested copy node_modules/typescript/node_modules/${native.replace('/', '\\/')} inside typescript; the tsc shim would run that copy instead of the one pipegen checks`));
    // G17B-R1 sec M3: a copy under typescript/lib/node_modules is on the shim's path too (it resolves from lib): refused from the lockfile
    const lib = runs(fixture({ [`node_modules/typescript/lib/node_modules/${native}`]: old }));
    expect(lib.status).toBe(1);
    expect(lib.err).toMatch(new RegExp(`a nested copy node_modules/typescript/lib/node_modules/${native.replace('/', '\\/')} inside typescript`));
    // a top-level entry of the prefix is still checked (registry tarball, sha512, typescript's own version)
    expect(runs(fixture({ [`node_modules/@typescript/typescript-plan9-arm`]: old })).err).toMatch(/is not the registry tarball with a sha512 integrity/);
  });
});

describe('G17 row 18: a created Dockerfile\'s npm ci passes --git=/usr/bin/git', () => {
  const LIST = loadBaseImages();
  const REF = baseImageRef('node-24-bookworm-slim');
  const svc: Service = { name: 'api', path: 'api', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: ['start'], frameworks: [], quality: emptyServiceQuality() };
  const ctx: DockerfileCtx = { port: 3000, baseImages: LIST, buildsInside: false, scripts: ['start', 'build'] };
  const text = (ci: string): string => [`FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', `RUN ${ci}`, 'COPY . .', 'EXPOSE 3000', 'USER node', 'CMD ["node", "index.js"]', ''].join('\n');

  it('dockerfile rules: npm ci needs --git=/usr/bin/git (a repo .npmrc or an npm_config_git ENV never names another git program); any other --git is refused', () => {
    expect(dockerfileProblems(text('npm ci --ignore-scripts --git=/usr/bin/git'), svc, ctx)).toEqual([]);
    expect(dockerfileProblems(text('npm ci --git=/usr/bin/git --omit=dev --ignore-scripts'), svc, ctx)).toEqual([]);
    expect(dockerfileProblems(text('npm ci --ignore-scripts'), svc, ctx).join('\n')).toMatch(/npm ci needs --git=\/usr\/bin\/git/);
    for (const bad of ['--git=./evil.sh', '--git=/usr/bin/git2', '--git=git']) {
      expect(dockerfileProblems(text(`npm ci --ignore-scripts ${bad}`), svc, ctx).join('\n'), bad).toMatch(/npm ci may only have/);
    }
    expect(dockerfileProblems(text('npm ci --ignore-scripts --git=/usr/bin/git --git=/usr/bin/git'), svc, ctx).join('\n')).toMatch(/npm ci may only have/);
  });

  it('prompt: the Dockerfile instructions ask for --git=/usr/bin/git on npm ci', () => {
    const f = { fromLines: [`FROM ${REF}`], buildsInside: true, port: 3000, hasStartScript: true } as Parameters<typeof dockerfileInstructions>[0];
    const s = dockerfileInstructions(f);
    expect(s).toContain('npm ci --ignore-scripts --git=/usr/bin/git');
    expect(s).not.toMatch(/npm ci --ignore-scripts(?! --git=\/usr\/bin\/git)/);
  });
});

describe('G17 row 19 (open question 9): a blocking check of an image pipegen can not build stops with a plain reason', () => {
  // a service in a sub-folder: the reviewed build template's context is the repository root (ruling S8), so its image can not be built yet
  const prof = profileOf([node({ name: 'api', path: 'api', dockerfile: 'api/Dockerfile', port: 3000 })]);
  const without = new Set(['dast', 'dockerfile-lint']);

  it('assemble: a blocking image scan (and image build) of an image that can not be built stops; never dropped, never another image scanned', () => {
    const needs = floorNeeds(prof, CAPS).filter((n) => !without.has(n.id));
    expect(needs.filter((n) => n.service === 'api' && (n.id === 'image-scan' || n.id === 'image-build')).every((n) => n.blocking)).toBe(true);
    const x = planned(prof, { needs, over: SKIP_DEPLOY, edit: (s) => s.filter((st) => !without.has(st.needId)) });
    expect(() => assemble(x)).toThrow(AssembleError);
    expect(() => assemble(x)).toThrow(/The blocking check "image-(?:build|scan)" for "api" can not run: its image is not built \(The service "api" is in a sub-folder[^)]*\)\. pipegen never scans another image in its place, makes it warn-only or leaves it out\. Next step: pipegen v0\.2 builds an image from the repository root only; move the service's Dockerfile and build context to the root, or wait for a later version, then run `npx pipegen run` again\./);
  });

  it('assemble: a blocking DAST check of the same service keeps its own reason (the image stop comes after the DAST starts)', () => {
    const x = planned(prof, { over: SKIP_DEPLOY });
    expect(() => assemble(x)).toThrow(/^The blocking check "dast" for "api" can not run: it has no container image pipegen builds/);
  });

  it('assemble: non-blocking, the same checks leave with a note (no job, no gate entry)', () => {
    const needs = floorNeeds(prof, CAPS).filter((n) => !without.has(n.id)).map((n) => (n.service === 'api' && (n.id === 'image-scan' || n.id === 'image-build') ? { ...n, blocking: false } : n));
    const x = planned(prof, { needs, over: SKIP_DEPLOY, edit: (s) => s.filter((st) => !without.has(st.needId)) });
    const a = assemble(x);
    expect(Object.keys(a.merge).filter((k) => /image/.test(k))).toEqual([]);
    expect(a.notes.join('\n')).toMatch(/The image of "api" is not built or scanned yet: The service "api" is in a sub-folder/);
  });
});

describe('G17B-R1 round 2, risk 1: a service with no Dockerfile at all (none created) stops like row 19', () => {
  it('assemble: no Dockerfile in the repository and none created: a blocking image check stops, with a next step', () => {
    const prof2 = profileOf([node({ frameworks: ['express'], port: 3000, scripts: ['test', 'lint', 'start'] })]);
    const needs = floorNeeds(prof2, CAPS).filter((n) => n.id !== 'dast');
    expect(needs.some((n) => n.id === 'image-build' && n.blocking)).toBe(true);
    const x = planned(prof2, { needs, over: SKIP_DEPLOY, edit: (s) => s.filter((st) => st.needId !== 'dast') });
    expect(() => assemble(x)).toThrow(AssembleError);
    expect(() => assemble(x)).toThrow(/^The blocking check "image-(?:build|scan)" for "app" can not run: its image is not built \(The service "app" has no Dockerfile to build\.\)\. pipegen never scans another image in its place, makes it warn-only or leaves it out\. Next step: add a Dockerfile to the service's folder, or let pipegen create one, then run `npx pipegen run` again\.$/);
  });
});

describe('G17 row 21 reverted (G17B-R1 sec I1, open question 13 closed as won\'t fix): always <repo>-<service>', () => {
  it('publishedImageRepo: the double name keeps pipegen\'s package apart from the repository\'s own ghcr.io/<owner>/<repo>, and across repositories', () => {
    expect(publishedImageRepo('acme', 'acme-shop', 'acme-shop')).toBe('ghcr.io/acme/acme-shop-acme-shop');
    expect(publishedImageRepo('Acme', 'Acme-Shop', 'acme-shop')).toBe('ghcr.io/acme/acme-shop-acme-shop');
    expect(publishedImageRepo('acme', 'acme-shop', 'web')).toBe('ghcr.io/acme/acme-shop-web');
    // the reviewer's P5 pair: two repositories of one owner never share a package name
    expect(publishedImageRepo('acme', 'acme-shop', 'acme-shop')).not.toBe(publishedImageRepo('acme', 'acme', 'shop'));
    expect(publishedImageRepo('acme', 'acme', 'shop')).toBe('ghcr.io/acme/acme-shop');
  });
});

describe('G17B-R1 sec M1: the ZAP API answers only 127.0.0.1 in every ZAP form pipegen renders', () => {
  const BIND = '-config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false';
  const zapLines = (jobs: Job[]): string[] => jobs.flatMap((j) => j.steps).flatMap((st) => (st.run ?? '').split('\n')).filter((l) => /docker create .*"\$PIPEGEN_IMAGE" (?:zap-baseline\.py|zap\.sh)\b/.test(l));
  it('render: zap-baseline passes the bind inside its -z options; the nightly AF zap.sh passes it as its own words', async () => {
    const a = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    const lines = zapLines([...Object.values(a.merge), ...Object.values(a.nightly)] as Job[]);
    const base = lines.filter((l) => / zap-baseline\.py /.test(l));
    const af = lines.filter((l) => / zap\.sh /.test(l));
    expect(base.length, 'the baseline scan').toBeGreaterThan(0);
    expect(af.length, 'the nightly AF scan').toBeGreaterThan(0);
    for (const l of base) expect(l).toContain(` -z '-silent ${BIND}'`);
    for (const l of af) expect(l).toMatch(new RegExp(` -cmd -silent ${BIND.replace(/[.]/g, '\\.')}(?: |$)`));
    // the rendered steps are the referee's too: the assembled pipeline still passes it
    expect(shown(await judge(files(a), a.draft))).toBe('');
  });

  it('threat model: T54 says the ZAP API answers only 127.0.0.1, so the scanned app can not drive it', () => {
    const r = readFileSync('docs/threat-model.md', 'utf8').split('\n').find((l) => l.startsWith('| T54 |')) as string;
    expect(r).toMatch(/ZAP API answers only 127\.0\.0\.1/);
  });
});

describe('G17B-R0/R1 round 2: the image build of a Dockerfile pipegen creates in the same run', () => {
  const REF = baseImageRef('node-24-bookworm-slim');
  const SINGLE = [`FROM ${REF}`, 'WORKDIR /app', 'COPY package.json package-lock.json ./', 'RUN npm ci --omit=dev --ignore-scripts --git=/usr/bin/git', 'COPY . .', 'ENV NODE_ENV=production', 'EXPOSE 3000', 'USER node', 'CMD ["npm", "start"]', ''].join('\n');
  const svcNoDf = () => node({ frameworks: ['express'], port: 3000, scripts: ['test', 'lint', 'start'] });
  const created = (): CreatedFile[] => [
    { path: 'Dockerfile', content: SINGLE, part: 'docker', reason: 't', repo: 'app' },
    { path: '.dockerignore', content: dockerignoreText(svcNoDf(), false), part: 'docker', reason: 't', repo: 'app' },
  ];

  it('assemble: the image build and the blocking image scan render from the created Dockerfile; DAST starts the checked archive; the referee passes', async () => {
    const a = assemble(planned(profileOf([svcNoDf()]), { over: { created: created(), ...SKIP_DEPLOY } }));
    const build = a.merge['image-build--app'] as Job;
    expect(build, 'the image build').toBeDefined();
    expect(build.steps.find((st) => st.with?.file !== undefined)?.with?.file).toBe('Dockerfile');
    expect(a.merge['image-scan--app'], 'the image scan').toBeDefined();
    expect((a.merge['dast-run--app'] as Job).needs).toEqual(['image-build--app']);
    expect(a.notes.join('\n')).not.toMatch(/not built or scanned yet/);
    expect(shown(await judge([...files(a), ...created()], a.draft))).toBe('');
  });

  it('assemble: only a Dockerfile created at the service\'s own folder counts (another folder\'s, or one of the other repository, is no build of it)', () => {
    const needs = floorNeeds(profileOf([svcNoDf()]), CAPS).filter((n) => n.id !== 'dast');
    for (const moved of [created().map((f) => ({ ...f, path: `other/${f.path}` })), created().map((f) => ({ ...f, repo: 'central' as const }))]) {
      const x = planned(profileOf([svcNoDf()]), { needs, over: { created: moved, ...SKIP_DEPLOY }, edit: (s) => s.filter((st) => st.needId !== 'dast') });
      expect(() => assemble(x)).toThrow(/its image is not built \(The service "app" has no Dockerfile to build\.\)/);
    }
  });

  it('referee: the image build of a created Dockerfile is pipegen\'s only while the draft creates that file', async () => {
    const a = assemble(planned(profileOf([svcNoDf()]), { over: { created: created(), ...SKIP_DEPLOY } }));
    // the same workflow files judged against a draft that creates no Dockerfile: the build and its scan are no steps of pipegen's
    const without = { ...a.draft, created: a.draft.created.filter((f) => f.part !== 'docker') };
    expect(shown(await judge(files(a), without))).toMatch(/image-build--app/);
  });
});

describe('G17B-R1 round 2: the referee refuses the registry form of an image scan for an image the draft does not build', () => {
  it('referee: a registry-form trivy-image for a service with no image build is no step of pipegen\'s', async () => {
    const a = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    // drop the image build from the draft only: the files keep a scan job, which must not pass as the registry form
    const d = { ...a.draft, steps: a.draft.steps.filter((st) => st.needId !== 'image-build'), needs: a.draft.needs.filter((n) => n.id !== 'image-build') };
    const r = await judge(files(a), d);
    expect(r.notes.join('\n')).toMatch(/The image scan "image-scan" \(trivy-image\) reads only the archive of the pull request's own image, and the draft builds no image for "app", so no step may claim to be it\./);
    expect(shown(r)).toMatch(/image-scan--app/);
  });
});

describe('G17B-R1 round 2, risk 4 (R0 concern 3): compose up fails with a fixed pipegen message', () => {
  it('render: compose up (and the proof form) ends with a fixed message on failure, naming the capability limit; no container log text', () => {
    for (const st of [renderComposeUp(), renderComposeUp({ proofOverride: true })]) {
      expect(st.run).toContain('|| { echo "::error::pipegen: the containers did not start. pipegen starts your app containers with no Linux capability and no privilege gain (cap_drop ALL, no-new-privileges), so an image that needs one (a root entrypoint that switches users or changes file owners) can not start: run the app as a non-root user. See PIPEGEN.md, Limits of these checks."; exit 1; }');
      expect(st.run).not.toMatch(/logs|\$\(/);
    }
  });
});

describe('G17B-R1 round 2: PIPEGEN.md says the DAST limits', () => {
  it('docs: the ZAP API bind, the second build on the compose path, and the capability limit of the compose containers', () => {
    const prof = profileOf([node({ dockerfile: 'Dockerfile', port: 3000, scripts: ['test', 'lint', 'start'], dependsOn: [PG] })]);
    const compose: CreatedFile = { path: 'docker-compose.pipegen.yml', content: composeText(prof, loadBaseImages()) as string, part: 'compose', reason: 't', repo: 'app' };
    const a = assemble(planned(prof, { over: { created: [compose], ...SKIP_DEPLOY } }));
    const doc = pipegenDoc(a.draft, REVIEWED).content;
    expect(doc).toContain('The running app scan talks to ZAP through its API, which answers only 127.0.0.1, so the scanned app can not reach it.');
    expect(doc).toContain('With pipegen\'s compose file, the running app scan builds the app\'s image itself, in its own job: a second build of the same Dockerfile. The image scan reads the other build.');
    expect(doc).toContain('The app containers in pipegen\'s compose file run with no Linux capability and no privilege gain, and the database and queue containers with no privilege gain. An app image that needs a capability (a root entrypoint that switches users or changes file owners) does not start: run the app as a non-root user.');
    // without a compose file, the archive start: no second build line
    const b = assemble(planned(profileOf([web()]), { over: SKIP_DEPLOY }));
    const docB = pipegenDoc(b.draft, REVIEWED).content;
    expect(docB).toContain('The running app scan talks to ZAP through its API, which answers only 127.0.0.1');
    expect(docB).not.toContain('a second build of the same Dockerfile');
  });
});
