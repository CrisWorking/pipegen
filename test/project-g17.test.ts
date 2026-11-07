// G17 group F (carry rows 66-74): the project reader's container heuristics, under the GJ-R6 convergence rule.
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import { bakeBuildRefs, bakeJsonBuildRefs, composeBuildRefs, containerFilesIn, containerHintOf, workflowBuildRefs } from '../src/read/container-file.js';
import { parseYamlLimited } from '../src/read/limits.js';
import { readProject } from '../src/read/project.js';
import type { RepoProfile, Service } from '../src/types.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

afterEach(() => cleanupRepos());

function repo(files: Record<string, string>): string {
  const dir = makeTempDir();
  for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
  execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['remote', 'add', 'origin', 'https://github.com/o/r.git'], { cwd: dir, stdio: 'pipe' });
  return dir;
}
const read = async (files: Record<string, string>, notes: string[] = []): Promise<RepoProfile> => ({ ...(await readProject(repo(files), { notes })), private: false, ownerType: 'User', plan: 'free' } as RepoProfile);
const pkg = (o: Record<string, unknown>) => `${JSON.stringify({ name: 'site', version: '1.0.0', ...o }, null, 2)}\n`;
const LOCK = '{"lockfileVersion":3,"packages":{}}';
const PAGE = 'export default function Page() { return null; }\n';
const ws = (extra: Record<string, string>) => ({
  'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK,
  'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0', react: '19.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
  ...extra,
});
const express = (extra: Record<string, string>) => ({ 'package.json': pkg({ name: 'api', scripts: { start: 'node index.js', test: 'vitest run' }, dependencies: { express: '4.0.0' } }), 'package-lock.json': LOCK, 'index.js': "require('express')().listen(3000);\n", 'index.test.js': 'test("x", () => {});\n', Dockerfile: 'FROM node:24\nEXPOSE 3000\nCMD ["node", "index.js"]\n', ...extra });
const wf = (cmd: string) => `on: { push: { branches: [main] } }\njobs:\n  img:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${cmd}\n`;
const webHint = (p: RepoProfile) => (p.services.find((s) => s.name === 'web') as Service).containerHint;
const refs = (t: string) => [...workflowBuildRefs([t])].sort();
const compose = (text: string, file = 'compose.yaml') => { const out = new Set<string>(); composeBuildRefs(file, parseYamlLimited(text), out); return [...out].sort(); };
const bake = (text: string, file = 'docker-bake.hcl') => { const out = new Set<string>(); bakeBuildRefs(file, text, out); return [...out].sort(); };

describe('G17 row 66 (B2): container file and hint lookups are not quadratic in files and links', () => {
  it('4000 folders x 20k links and 40k files: every folder\'s container files and hint in well under the old 12.5 s', () => {
    const files: string[] = [];
    const links: string[] = [];
    const dirs: string[] = [];
    for (let i = 0; i < 4000; i++) {
      const d = `packages/p${i}`;
      dirs.push(d);
      for (let k = 0; k < 9; k++) files.push(`${d}/src/f${k}.ts`);
      files.push(i % 2 === 0 ? `${d}/Dockerfile` : `${d}/package.json`);
      for (let k = 0; k < 5; k++) links.push(`${d}/l${k}.txt`);
    }
    links.push('packages/p7/shared');
    const set = new Set(files);
    const t0 = performance.now();
    let own = 0;
    const hints: (string | undefined)[] = [];
    for (const d of dirs) {
      own += containerFilesIn(set, d).length;
      hints.push(containerHintOf(d, set, dirs, new Set(['packages/p9']), [], links));
    }
    const ms = performance.now() - t0;
    expect(own).toBe(2000);
    expect(hints[7]).toContain('packages/p7/shared');
    expect(hints[9]).toContain('a workflow, compose or bake file builds an image from it: packages/p9');
    expect(hints.filter((h) => h !== undefined).length).toBe(2);
    expect(ms).toBeLessThan(2000);
  });
  it('the lookups stay right after the file set grows (the index is rebuilt)', () => {
    const set = new Set(['a/Dockerfile']);
    expect(containerFilesIn(set, 'a')).toEqual(['a/Dockerfile']);
    set.add('a/Containerfile');
    expect(containerFilesIn(set, 'a')).toEqual(['a/Containerfile', 'a/Dockerfile']);
    expect(containerHintOf('a', set, ['a'], new Set(), [])).toBeUndefined();
    set.add('a/deep/Dockerfile.x');
    expect(containerHintOf('a', set, ['a'], new Set(), [])).toContain('a/deep/Dockerfile.x');
  });
});

describe('G17 row 67 (N6): compose merge keys and variables, compose-<x> names, one-line bake targets, bake JSON and variables', () => {
  it('a compose <<: *anchor merge key under build (and under the service) is resolved', () => {
    expect(compose('x-build: &b\n  context: ./apps/web\n  dockerfile: Dockerfile.ci\nservices:\n  web:\n    build:\n      <<: *b\n')).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    expect(compose('x-svc: &s\n  build: ./apps/api\nservices:\n  api:\n    <<: *s\n    ports: ["3000:3000"]\n')).toEqual(['apps/api']);
    // the mapping's own keys win over the merged ones
    expect(compose('x-b: &b\n  context: ./apps/web\nservices:\n  api:\n    build:\n      <<: *b\n      context: ./apps/api\n')).toEqual(['apps/api']);
    expect(compose('x-a: &a\n  context: apps/a\nx-b: &b\n  dockerfile: Dockerfile.b\nservices:\n  w:\n    build:\n      <<: [*a, *b]\n')).toEqual(['apps/a', 'apps/a/Dockerfile.b']);
  });
  it('a compose ${VAR:-default} context uses the default; a bare ${VAR} is no reference', () => {
    expect(compose('services:\n  web:\n    build:\n      context: ${WEB_CTX:-./apps/web}\n')).toEqual(['apps/web']);
    expect(compose('services:\n  web:\n    build: ${WEB_CTX-apps/web}\n')).toEqual(['apps/web']);
    expect(compose('services:\n  web:\n    build: ${WEB_CTX}\n')).toEqual([]);
  });
  it('docker-compose-prod.yml and compose_dev.yaml are read as compose files', async () => {
    expect(webHint(await read(ws({ 'docker-compose-prod.yml': 'services:\n  web:\n    build: ./apps/web\n' })))).toContain('apps/web');
    expect(webHint(await read(ws({ 'compose_dev.yaml': 'services:\n  web:\n    build: ./apps/web\n' })))).toContain('apps/web');
  });
  it('a commented-out context or dockerfile after the real one is ignored', () => {
    expect(bake('target "web" {\n  context = "apps/web"\n  # context = "apps/old"\n  // dockerfile = "old/Dockerfile"\n}\n')).toEqual(['apps/web']);
    expect(bake('target "web" {\n  context = "apps/web" # context = "apps/old"\n}\n')).toEqual(['apps/web']);
    expect(bake('target "web" {\n  context = "apps/#web"\n}\n')).toEqual(['apps/#web']);
  });
  it('a one-line bake target and bake variables', () => {
    expect(bake('target "web" { context = "apps/web" dockerfile = "Dockerfile.ci" }\n')).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    expect(bake('variable "CTX" {\n  default = "apps/web"\n}\ntarget "web" {\n  context = "${CTX}"\n}\n')).toEqual(['apps/web']);
    expect(bake('variable "CTX" { default = "apps" }\ntarget "web" {\n  context = "${CTX}/web"\n}\n')).toEqual(['apps/web']);
    expect(bake('target "web" {\n  context = "${UNKNOWN}"\n}\n')).toEqual([]);
  });
  it('a docker-bake.json target counts (unit and through readProject)', async () => {
    const out = new Set<string>();
    bakeJsonBuildRefs('docker-bake.json', { variable: { CTX: { default: 'apps' } }, target: { web: { context: '${CTX}/web', dockerfile: 'Dockerfile.ci' }, bad: { context: '../../etc' } } }, out);
    expect([...out].sort()).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    expect(webHint(await read(ws({ 'docker-bake.json': JSON.stringify({ target: { web: { context: 'apps/web' } } }) })))).toContain('apps/web');
  });
});

describe('G17 row 68: a long continued build chain of --build-arg lines is kept', () => {
  it('60 continued --build-arg lines (over 4 KB) still give -f and the context', () => {
    const lines = ['docker build \\', ...Array.from({ length: 60 }, (_, i) => `  --build-arg ARG_${i}=${'v'.repeat(70)} \\`), '  -f apps/web/Dockerfile.ci \\', '  apps/web'];
    expect(lines.join('\n').length).toBeGreaterThan(4096);
    expect(refs(lines.join('\n'))).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
  });
  it('the other noise flags (label, annotation, secret) are left out of a long chain too, in both spellings', () => {
    const chain = (...mid: string[]) => ['docker build \\', ...mid.map((m) => `  ${m} \\`), '  -f apps/web/Dockerfile.ci \\', '  apps/web'].join('\n');
    const S = '--sec' + 'ret'; // built at runtime so the file holds no secret-looking text
    for (const m of ['--label v=1.0', '--label=v=1.0', '--annotation "a=b c"', '--annotation=a=b', `${S} id=x,src=/tmp/s`, `${S}=id=x`, `--label a=1 --annotation b=2 ${S} id=c --build-arg D=4`]) {
      expect(refs(chain(...Array.from({ length: 60 }, () => m)))).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    }
    expect(refs(chain('--build-arg A=1 -f x/Dockerfile'))).toContain('x/Dockerfile');
  });
  it('a plain word `case` inside $( ) does not swallow the closing paren', () => {
    const r = refs('docker build -f a/Dockerfile.x a --label v=$(echo case)');
    expect(r).toEqual(['a', 'a/Dockerfile.x']);
    expect(r.some((x) => x.includes('case)'))).toBe(false);
  });
  it('a chain over the budget for other reasons is still dropped whole (the budget holds)', () => {
    expect(workflowBuildRefs([`docker build \\\n${'  -t x \\\n'.repeat(1000)}  apps/web`]).size).toBe(0);
  });
});

describe('G17 row 69: a folded `run: >` build command is joined', () => {
  const folded = (ind: string) => `jobs:\n  b:\n    steps:\n      - run: ${ind}\n          docker build\n          -f apps/web/Dockerfile.ci\n          apps/web\n      - run: echo done\n`;
  it.each(['>', '>-', '>+', '>2'])('run: %s', (ind) => {
    expect(refs(folded(ind))).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
  });
  it('a literal `run: |` block is not joined (each line is a command)', () => {
    expect(refs('      - run: |\n          docker build\n          -f apps/web/Dockerfile.ci\n')).toEqual([]);
  });
});

describe('G17 row 70: the 2 MB compose/bake skip writes one note', () => {
  it('two skipped files give one note naming both', async () => {
    const big = `# ${'x'.repeat(990_000)}\nservices:\n  x:\n    image: alpine\n`;
    const small = `# ${'x'.repeat(50_000)}\nservices:\n  x:\n    image: alpine\n`;
    const notes: string[] = [];
    await read(ws({ 'a/compose.yaml': big, 'b/compose.yaml': big, 'c/compose.yaml': small, 'd/compose.yaml': small }), notes);
    const skips = notes.filter((n) => n.includes('over 2 MB together'));
    expect(skips).toEqual(['Skipped 2 files (c/compose.yaml, d/compose.yaml): the compose and bake files pipegen reads for image builds are over 2 MB together.']);
  });
});

describe('G17 row 71: the note for a folder not taken as a service never says "part of the root app" when that is false', () => {
  it('a GitHub container action is never a service and its note says so', async () => {
    for (const extra of [{ '.github/actions/n/Dockerfile': 'FROM alpine\n' }, { '.github/actions/n/Dockerfile': 'FROM python:3.12\n', '.github/actions/n/entrypoint.py': 'print(1)\n' }] as Record<string, string>[]) {
      const notes: string[] = [];
      const p = await read(express(extra), notes);
      expect(p.services.map((s) => s.path)).toEqual(['.']);
      const n = notes.join('\n');
      expect(n).toMatch(/The folder \.github\/actions\/n [^\n]*GitHub Actions container file[^\n]*not the app/);
      expect(n).not.toMatch(/actions\/n[^\n]*part of the root app/);
    }
  });
  it('a tools/ image: no "part of the root app" claim; the packaging folders keep it', async () => {
    const notes: string[] = [];
    await read(express({ 'tools/Dockerfile.lint': 'FROM alpine\n', 'docker/Dockerfile.dev': 'FROM node:24\n' }), notes);
    const n = notes.join('\n');
    expect(n).toContain('The folder tools has container files but no plain Dockerfile or Containerfile, and no workflow, compose or bake file builds it, so pipegen does not take it as a service of its own and does not build or scan its image.');
    expect(n).toContain('The folder docker has container files but no plain Dockerfile or Containerfile, and no workflow, compose or bake file builds it, so pipegen takes it as part of the root app');
  });
});

describe('G17 row 72: a folder whose plain Dockerfile a workflow builds by context is a service, not taken into the root', () => {
  it('docker build tools (a release workflow) makes tools a service with tools/Dockerfile', async () => {
    const p = await read(express({ 'tools/Dockerfile': 'FROM alpine\n', '.github/workflows/rel.yml': wf('docker build -t ghcr.io/o/tools tools && docker push ghcr.io/o/tools') }));
    expect(p.services.map((s) => s.path).sort()).toEqual(['.', 'tools']);
    expect(p.services.find((s) => s.path === 'tools')?.dockerfile).toBe('tools/Dockerfile');
  });
  it('a context alone with only suffixed files still is not a build of them (GJ-R6 Ra b)', async () => {
    const p = await read(express({ 'tools/Dockerfile.lint': 'FROM alpine\n', '.github/workflows/rel.yml': wf('docker build -t x tools') }));
    expect(p.services.map((s) => s.path)).toEqual(['.']);
  });
});

describe('G17 row 73: workflow build lines (a-e, k)', () => {
  it('(a) a -f value with an expression keeps the folder up to the last /', () => {
    expect(refs('docker build -f apps/web/Dockerfile.${{ matrix.stage }} .')).toEqual(['.', 'apps/web']);
    expect(refs('docker build -f ${{ matrix.df }} svc')).toEqual(['svc']);
  });
  it('(b) an unbalanced $( or nesting over 16 no longer blanks the rest of the line', () => {
    expect(refs('echo $(unclosed ; docker build -f a/Dockerfile.x a')).toEqual(['a', 'a/Dockerfile.x']);
    // nesting over 16 still blanks the rest of the line: GJ-R5's test (project-type.test.ts, group G's file) holds that; see the report
    expect(refs(`X=${'$('.repeat(17)}y${')'.repeat(17)} ; docker build b`)).toEqual([]);
    expect(refs(`X=${'$('.repeat(16)}y${')'.repeat(16)} ; docker build b`)).toEqual(['b']);
  });
  it('(c) a ) in a case pattern inside $( … ) does not end the span', () => {
    expect(refs('docker build -t $(case "$E" in prod) echo p;; *) echo d;; esac) svc')).toEqual(['svc']);
  });
  it('(d) backticks are blanked, and a build inside them is read', () => {
    expect(refs('docker build svc --label v=`git describe --tags`')).toEqual(['svc']);
    expect(refs('IMG=`docker build -q -f Dockerfile.prod .`')).toEqual(['.', 'Dockerfile.prod']);
  });
  it('(e) a ; inside quotes does not cut the build line', () => {
    expect(refs('docker build --build-arg "A=1;2" -f e/Dockerfile.ci e')).toEqual(['e', 'e/Dockerfile.ci']);
    expect(refs("docker build --label 'x=a|b&c' f")).toEqual(['f']);
    // a path holding a quoted separator is no reference; a quote inside a word (it's) opens nothing
    expect(refs('docker build -f "a;b/Dockerfile" .')).toEqual(['.']);
    expect(refs("echo it's; docker build x; echo 'y'")).toEqual(['x']);
  });
  it('(k) a context expression with a quoted fallback gives that path', () => {
    expect(refs("          context: ${{ inputs.ctx || 'apps/web' }}")).toEqual(['apps/web']);
    expect(refs('          context: ${{ inputs.ctx }}')).toEqual([]);
  });
});
