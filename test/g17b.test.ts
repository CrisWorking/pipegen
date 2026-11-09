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
import { dockerfileProblems, type DockerfileCtx } from '../src/create/dockerfile-rules.js';
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
import { assemble, CAPS, files, judge, node, p, planned, profileOf, shown, type Obj } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { makeTempDir } from './helpers/make-repo.js';

const SKIP_DEPLOY = { skipped: [{ part: 'deploy' as const, reason: 't' }] };
const web = () => node({ dockerfile: 'Dockerfile', port: 3000 });
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

  it('compose: every app service has cap_drop ALL and no-new-privileges; the dependency containers keep their own (their entrypoints switch users)', () => {
    const app = blockOf(text, 'app-app');
    expect(app).toContain('    cap_drop:\n      - "ALL"');
    expect(app).toContain('    security_opt:\n      - "no-new-privileges:true"');
    const db = blockOf(text, 'postgres');
    expect(db).not.toMatch(/cap_drop|security_opt/);
    expect(text.match(/cap_drop:/g)?.length).toBe(1);
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
    for (const secrets of [['APP_TOKEN'], ['A', 'B']]) {
      expect(() => renderDastRun({ ...spec, secrets }, tool, p, x.draft, start, { blocking: true, checkout: [] })).toThrow(RenderError);
      expect(() => renderDastRun({ ...spec, secrets }, tool, p, x.draft, start, { blocking: true, checkout: [] })).toThrow(/DAST check .*no secret/);
    }
    // an empty list is no secret
    expect(() => renderDastRun({ ...spec, secrets: [] }, tool, p, x.draft, start, { blocking: true, checkout: [] })).not.toThrow();
  });

  it('assemble: a draft whose DAST step names a secret stops before any job is written', () => {
    const x = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000, envVars: ['APP_TOKEN'] })]), { over: SKIP_DEPLOY, edit: (s) => s.map((st) => (st.needId === 'dast' ? { ...st, secrets: ['APP_TOKEN'] } : st)) });
    expect(() => assemble(x)).toThrow(AssembleError);
    expect(() => assemble(x)).toThrow(/^The DAST check "dast" for "app" names secrets \("APP_TOKEN"\)\. A DAST check runs the app with no secret/);
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

describe('G17 row 16: T52 names the Bullfrog egress step in the key-env sign job', () => {
  it('threat model: T52 no longer says no third-party action runs in the key-env sign job; it names Bullfrog and what it can reach', () => {
    const row = readFileSync('docs/threat-model.md', 'utf8').split('\n').find((l) => l.startsWith('| T52 |')) as string;
    expect(row).toBeDefined();
    expect(row).not.toContain('no repo code and no third-party action (the referee\'s sign-job allowlist)');
    expect(row).toMatch(/Bullfrog/);
    expect(row).toMatch(/one third-party action/);
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
    expect(() => assemble(x)).toThrow(/The blocking check "image-(?:build|scan)" for "api" can not run: its image is not built \(The service "api" is in a sub-folder[^)]*\)\. pipegen never scans another image in its place, makes it warn-only or leaves it out\./);
  });

  it('assemble: non-blocking, the same checks leave with a note (no job, no gate entry)', () => {
    const needs = floorNeeds(prof, CAPS).filter((n) => !without.has(n.id)).map((n) => (n.service === 'api' && (n.id === 'image-scan' || n.id === 'image-build') ? { ...n, blocking: false } : n));
    const x = planned(prof, { needs, over: SKIP_DEPLOY, edit: (s) => s.filter((st) => !without.has(st.needId)) });
    const a = assemble(x);
    expect(Object.keys(a.merge).filter((k) => /image/.test(k))).toEqual([]);
    expect(a.notes.join('\n')).toMatch(/The image of "api" is not built or scanned yet: The service "api" is in a sub-folder/);
  });
});

describe('G17 row 21 (open question 13): one image name when the repository and the service share it', () => {
  it('publishedImageRepo: the service name alone when it equals the repository name; <repo>-<service> otherwise', () => {
    expect(publishedImageRepo('acme', 'acme-shop', 'acme-shop')).toBe('ghcr.io/acme/acme-shop');
    expect(publishedImageRepo('Acme', 'Acme-Shop', 'acme-shop')).toBe('ghcr.io/acme/acme-shop');
    expect(publishedImageRepo('acme', 'acme-shop', 'Acme Shop')).toBe('ghcr.io/acme/acme-shop');
    expect(publishedImageRepo('acme', 'acme-shop', 'web')).toBe('ghcr.io/acme/acme-shop-web');
    expect(publishedImageRepo('acme', 'shop', 'app')).toBe('ghcr.io/acme/shop-app');
    // no other service of that repository can take the short name: every other name keeps the `<repo>-` prefix
    expect(publishedImageRepo('acme', 'acme-shop', 'shop')).toBe('ghcr.io/acme/acme-shop-shop');
  });
});
