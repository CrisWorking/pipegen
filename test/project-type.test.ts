// Plan J sub-task J2 (DECISIONS #121): the project type of each service, with its evidence. Every positive test uses at
// least two invented shapes (Plan J Global Constraints: generic, never one repo's layout).
import { execFileSync } from 'node:child_process';
import { mkdirSync, symlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { floorNeeds, isRunnable, MINIMUM_CATEGORIES, skippedChecks, STATIC_SKIP } from '../src/engine/needs.js';
import { applyTypeOverrides } from '../src/read/project-type.js';
import { readProject } from '../src/read/project.js';
import { wouldCreateOf } from '../src/audit/model.js';
import { workflowBuildRefs } from '../src/read/container-file.js';
import { regexLines } from '../src/read/limits.js';
import { readWorkflows } from '../src/read/workflows.js';
import type { Capabilities, ProjectType, RepoProfile, Service, ServiceType } from '../src/types.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';
import { expectScaling } from './helpers/scaling.js';
import { assemble, files, judge, planned, shown } from './helpers/assemble.js';

const GH = 'https://github.com/o/r.git';

afterEach(() => cleanupRepos());

/** A temp git repo holding `files`; `index: true` runs `git add -A` (test setup only), so git's index lists the tracked files. */
function repo(files: Record<string, string>, opts: { index?: boolean } = {}): string {
  const dir = makeTempDir();
  for (const [rel, text] of Object.entries(files)) writeIn(dir, rel, text);
  execFileSync('git', ['init', '-q'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['remote', 'add', 'origin', GH], { cwd: dir, stdio: 'pipe' });
  if (opts.index === true) execFileSync('git', ['add', '-A'], { cwd: dir, stdio: 'pipe' });
  return dir;
}
async function profileOf(files: Record<string, string>, opts: { index?: boolean } = {}) {
  return readProject(repo(files, opts));
}
async function typeOf(files: Record<string, string>, opts: { index?: boolean } = {}): Promise<ProjectType> {
  const p = await profileOf(files, opts);
  const t = p.services[0]?.projectType;
  if (t === undefined) throw new Error('no projectType');
  return t;
}
const pkg = (o: Record<string, unknown>) => `${JSON.stringify({ name: 'site', version: '1.0.0', ...o }, null, 2)}\n`;
const nextPkg = (scripts: Record<string, string> = { dev: 'next dev', build: 'next build' }, extra: Record<string, unknown> = {}) =>
  pkg({ scripts, dependencies: { next: '15.0.0', react: '19.0.0', 'react-dom': '19.0.0' }, ...extra });
const PAGE = 'export default function Page() { return null; }\n';

const isStatic = (t: ProjectType) => t.types.includes('static-site');

describe('project type: static sites', () => {
  it('next export → static-site with the next.config evidence', async () => {
    const shapes: [string, string][] = [
      ['next.config.mjs', "/** @type {import('next').NextConfig} */\nexport default { output: 'export' };\n"],
      ['next.config.ts', "import type { NextConfig } from 'next';\n\nconst nextConfig: NextConfig = {\n  output: 'export',\n  images: { unoptimized: true },\n  trailingSlash: true,\n};\n\nexport default nextConfig;\n"],
      ['next.config.js', "module.exports = {\n  output: \"export\",\n  basePath: '/docs',\n};\n"],
    ];
    for (const [file, text] of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), [file]: text, 'app/page.tsx': PAGE });
      expect(t.types, file).toEqual(['static-site']);
      expect(t.unsure, file).toBe(false);
      expect(t.evidence, file).toContain(`output: "export" in ${file}`);
    }
  });

  it('next output from a variable → server, unsure, evidence names --type', async () => {
    const shapes = [
      "export default { output: process.env.STATIC ? 'export' : undefined };\n",
      "const mode = 'export';\nexport default { output: mode };\n",
      "const config = { output: 'export' };\nconfig.output = 'standalone';\nexport default config;\n",
      "export default { get output() { return 'export'; } };\n",
    ];
    // CommonJS and TypeScript forms that could run something else than the literal export
    const more: [string, string][] = [
      ['next.config.js', "if (process.env.STATIC) module.exports = { output: 'export' };\n"],
      ['next.config.js', "module.exports = { output: 'export' };\nObject.assign(module.exports, { output: 'standalone' });\n"],
      ['next.config.ts', "const config = { output: 'export' };\nnamespace N { export const x = 1; }\nexport default config;\n"],
      // the file reaches its own exported object (a self-import, or a local module) and changes it after the export
      ['next.config.mjs', "export default { output: 'export' };\nimport self from './next.config.mjs';\nself.output = 'standalone';\n"],
      ['next.config.mjs', "export default { output: 'export' };\nimport self from './alias.mjs';\nObject.defineProperty(self, 'out' + 'put', { value: 'standalone' });\n"],
      ['next.config.mjs', "export default { output: 'export' };\nawait import('./change.mjs');\n"],
      // CommonJS handles on the module's own exports or Node's module cache
      ['next.config.js', "module.exports = { output: 'export' };\nObject.defineProperty(arguments[2].exports, 'out' + 'put', { value: 'standalone' });\n"],
      ['next.config.js', "module.exports = { output: 'export' };\nconst c = require.cache;\nfor (const k in c) c[k].exports.output = 'standalone';\n"],
      ['next.config.cjs', "module.exports = { output: 'export' };\nconst M = process.getBuiltinModule('module');\n"],
    ];
    for (const [file, text] of more) {
      const t = await typeOf({ 'package.json': nextPkg(), [file]: text, 'app/page.tsx': PAGE, 'alias.mjs': "export { default } from './next.config.mjs';\n", 'change.mjs': 'export {};\n' });
      expect(isStatic(t), text).toBe(false);
      expect(t.unsure, text).toBe(true);
    }
    // a package import is fine (it is not the repo's own code)
    const pkgImport = await typeOf({ 'package.json': nextPkg(), 'next.config.mjs': "import createMDX from '@next/mdx';\nconst withMDX = createMDX;\nexport default { output: 'export', pageExtensions: ['ts', 'tsx', 'mdx'] };\n", 'app/page.tsx': PAGE });
    expect(pkgImport.types).toEqual(['static-site']);
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), 'next.config.mjs': text, 'app/page.tsx': PAGE });
      expect(isStatic(t), text).toBe(false);
      expect(t.types, text).toContain('server');
      expect(t.unsure, text).toBe(true);
      expect(t.evidence.join('\n'), text).toMatch(/--type static-site/);
    }
  });

  it('next export plus an API route → server', async () => {
    const shapes: Record<string, string>[] = [
      { 'app/api/hello/route.ts': 'export async function GET() { return new Response("hi"); }\n' },
      { 'pages/api/users.js': 'export default function handler(req, res) { res.json([]); }\n' },
    ];
    for (const extra of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, ...extra });
      expect(isStatic(t)).toBe(false);
      expect(t.types).toContain('server');
      expect(t.unsure).toBe(true);
      expect(t.evidence.join('\n')).toMatch(/server route/);
    }
  });

  it('next.config output in a comment or a string elsewhere → not static', async () => {
    const shapes = [
      "// output: 'export'\nexport default { reactStrictMode: true };\n",
      "/* output: 'export' */\nmodule.exports = { distDir: 'export' };\n",
      "const note = \"output: 'export'\";\nexport default { env: { NOTE: note } };\n",
    ];
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), 'next.config.js': text, 'app/page.tsx': PAGE });
      expect(isStatic(t), text).toBe(false);
      expect(t.types, text).toContain('server');
    }
  });

  it('next export with src/app/api/x/route.ts or src/middleware.ts → server', async () => {
    const shapes: Record<string, string>[] = [
      { 'src/app/page.tsx': PAGE, 'src/app/api/x/route.ts': 'export function GET() { return new Response(""); }\n' },
      { 'src/app/page.tsx': PAGE, 'src/middleware.ts': 'export function middleware() {}\n' },
      { 'src/pages/index.tsx': PAGE, 'src/pages/api/ping.ts': 'export default function h() {}\n' },
    ];
    for (const extra of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), 'next.config.ts': "export default { output: 'export' };\n", ...extra });
      expect(isStatic(t), Object.keys(extra).join()).toBe(false);
      expect(t.types).toContain('server');
      expect(t.unsure).toBe(true);
    }
  });

  it('export default withX(config) or a spread → unsure', async () => {
    const shapes = [
      "import withX from 'next-x';\nconst config = { output: 'export' };\nexport default withX(config);\n",
      "import base from './base.config.mjs';\nexport default { ...base, output: 'export' };\n",
      "const withY = require('next-y')();\nmodule.exports = withY({ output: 'export' });\n",
    ];
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), 'next.config.mjs': text, 'base.config.mjs': 'export default {};\n', 'app/page.tsx': PAGE });
      expect(isStatic(t), text).toBe(false);
      expect(t.unsure, text).toBe(true);
      expect(t.types, text).toContain('server');
    }
  });

  it('two next.config files → unsure', async () => {
    const t = await typeOf({ 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'next.config.ts': "export default { output: 'export' };\n", 'app/page.tsx': PAGE });
    expect(isStatic(t)).toBe(false);
    expect(t.unsure).toBe(true);
  });

  it('static export with start: tsx scripts/serve.ts (port in that file) → unsure, evidence names the script and --type', async () => {
    const shapes: [Record<string, string>, string][] = [
      [{ start: 'npx tsx scripts/serve.ts' }, 'scripts/serve.ts'],
      [{ serve: 'node tools/preview.mjs' }, 'tools/preview.mjs'],
    ];
    for (const [scripts, file] of shapes) {
      const t = await typeOf({
        'package.json': nextPkg({ dev: 'next dev', build: 'next build', ...scripts }),
        'next.config.ts': "export default { output: 'export' };\n",
        'app/page.tsx': PAGE,
        [file]: "import { createServer } from 'node:http';\nconst port = Number(process.env.PORT ?? 4173);\ncreateServer(() => {}).listen(port);\n",
      });
      const name = Object.keys(scripts)[0] as string;
      expect(isStatic(t), file).toBe(false);
      expect(t.unsure, file).toBe(true);
      expect(t.types, file).toContain('server');
      const text = t.evidence.join('\n');
      expect(text).toContain(`the ${name} script`);
      expect(text).toContain(file);
      expect(text).toMatch(/--type static-site/);
    }
  });

  it('a custom server with no port default, no server package and no route file → unsure', async () => {
    const shapes: [string, string][] = [
      ['server/index.ts', "import http from 'node:http';\nhttp.createServer((q, s) => s.end()).listen(8080);\n"],
      ['edge.ts', 'Bun.serve({ fetch() { return new Response(""); } });\n'],
    ];
    for (const [file, text] of shapes) {
      const t = await typeOf({ 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, [file]: text });
      expect(isStatic(t), file).toBe(false);
      expect(t.unsure, file).toBe(true);
    }
  });

  it('astro default → static', async () => {
    const astro = (scripts: Record<string, string>) => pkg({ scripts, dependencies: { astro: '5.0.0', '@astrojs/mdx': '4.0.0' } });
    const shapes: Record<string, string>[] = [
      { 'package.json': astro({ dev: 'astro dev', build: 'astro build', preview: 'astro preview' }), 'src/pages/index.astro': '---\n---\n<h1>hi</h1>\n' },
      { 'package.json': astro({ dev: 'astro dev --host', start: 'astro dev', build: 'astro build' }), 'astro.config.mjs': "import { defineConfig } from 'astro/config';\nimport mdx from '@astrojs/mdx';\nexport default defineConfig({ site: 'https://example.com', integrations: [mdx()] });\n", 'src/pages/index.astro': '<h1>hi</h1>\n' },
      { 'package.json': astro({ dev: 'astro dev' }), 'astro.config.ts': "import { defineConfig } from 'astro/config';\nconst config = defineConfig({ output: 'static' });\nexport default config;\n", 'src/pages/a.md': '# a\n' },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      expect(t.types, Object.keys(files).join()).toEqual(['static-site']);
      expect(t.unsure).toBe(false);
      expect(t.evidence.join('\n')).toMatch(/Astro/);
    }
  });

  it('astro with @astrojs/node → server', async () => {
    const shapes: Record<string, string>[] = [
      { 'astro.config.mjs': "import { defineConfig } from 'astro/config';\nimport node from '@astrojs/node';\nexport default defineConfig({ output: 'server', adapter: node({ mode: 'standalone' }) });\n" },
      { 'astro.config.mjs': "import { defineConfig } from 'astro/config';\nexport default defineConfig({});\n" }, // the adapter package alone
    ];
    for (const files of shapes) {
      const t = await typeOf({ 'package.json': pkg({ scripts: { dev: 'astro dev', build: 'astro build' }, dependencies: { astro: '5.0.0', '@astrojs/node': '9.0.0' } }), 'src/pages/index.astro': '<h1/>\n', ...files });
      expect(isStatic(t)).toBe(false);
      expect(t.types).toContain('server');
    }
  });

  it('astro with any adapter key → server', async () => {
    const shapes = [
      "import { defineConfig } from 'astro/config';\nimport host from 'some-host-adapter';\nexport default defineConfig({ adapter: host() });\n",
      "import { defineConfig } from 'astro/config';\nimport { custom } from './adapter.mjs';\nconst adapter = custom();\nexport default defineConfig({ integrations: [], adapter });\n",
      "export default { output: 'hybrid' };\n",
    ];
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': pkg({ scripts: { dev: 'astro dev' }, dependencies: { astro: '5.0.0' } }), 'astro.config.mjs': text, 'adapter.mjs': 'export const custom = () => ({});\n', 'src/pages/index.astro': '<h1/>\n' });
      expect(isStatic(t), text).toBe(false);
      expect(t.types, text).toContain('server');
    }
  });

  it('vite SPA → static', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': pkg({ scripts: { dev: 'vite', build: 'tsc -b && vite build', preview: 'vite preview' }, dependencies: { react: '19.0.0' }, devDependencies: { vite: '7.0.0', typescript: '5.9.0' } }), 'src/main.tsx': 'console.log(1);\n', 'index.html': '<div id="root"></div>\n' },
      { 'package.json': pkg({ scripts: { dev: 'vite --host 0.0.0.0', serve: 'vite preview --port 5000', build: 'vite build' }, dependencies: { vue: '3.5.0' }, devDependencies: { vite: '7.0.0' } }), 'src/main.js': 'import { createApp } from "vue";\n' },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      expect(t.types).toEqual(['static-site']);
      expect(t.unsure).toBe(false);
      expect(t.evidence.join('\n')).toMatch(/Vite/);
    }
  });

  it('vite as a script word but not a dependency → not static', async () => {
    const shapes = [
      pkg({ scripts: { dev: 'vite', build: 'vite build' }, dependencies: { react: '19.0.0' } }),
      pkg({ scripts: { build: 'npx vite build' }, devDependencies: { typescript: '5.9.0' } }),
    ];
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': text, 'src/main.ts': 'export {};\n' });
      expect(isStatic(t)).toBe(false);
    }
  });

  it('other generators: docusaurus, eleventy, vitepress and gatsby without server parts → static; gatsby functions → unsure', async () => {
    const cases: [Record<string, unknown>, Record<string, string>][] = [
      [{ scripts: { start: 'docusaurus start', build: 'docusaurus build' }, dependencies: { '@docusaurus/core': '3.0.0' } }, {}],
      [{ scripts: { dev: 'eleventy --serve', build: 'eleventy' }, devDependencies: { '@11ty/eleventy': '3.0.0' } }, {}],
      [{ scripts: { dev: 'vitepress dev docs', build: 'vitepress build docs' }, devDependencies: { vitepress: '1.0.0', vite: '7.0.0' } }, {}],
      [{ scripts: { develop: 'gatsby develop', build: 'gatsby build', serve: 'gatsby serve' }, dependencies: { gatsby: '5.0.0' } }, { 'src/pages/index.js': PAGE }],
    ];
    for (const [manifest, files] of cases) {
      const t = await typeOf({ 'package.json': pkg(manifest), ...files });
      expect(t.types, JSON.stringify(manifest)).toEqual(['static-site']);
    }
    const g = { scripts: { build: 'gatsby build' }, dependencies: { gatsby: '5.0.0' } };
    const gatsbyServer: Record<string, string>[] = [{ 'src/api/hello.js': 'export default function h(req, res) { res.send(1); }\n' }, { 'src/pages/p.js': 'export async function getServerData() { return {}; }\n' }];
    for (const extra of gatsbyServer) {
      const t = await typeOf({ 'package.json': pkg(g), ...extra });
      expect(isStatic(t)).toBe(false);
      expect(t.unsure).toBe(true);
    }
  });

  it('a hosted functions folder or a server package next to the generator → unsure', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'functions/api/hello.ts': 'export const onRequest = () => new Response("");\n' },
      { 'package.json': pkg({ scripts: { build: 'vite build' }, dependencies: { express: '5.0.0' }, devDependencies: { vite: '7.0.0' } }) },
      { 'package.json': pkg({ scripts: { build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'netlify/functions/hello.mjs': 'export default async () => new Response("");\n' },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      expect(isStatic(t), Object.keys(files).join()).toBe(false);
      expect(t.unsure).toBe(true);
    }
  });

  it('a git-ignored, untracked build folder never flips the type; a tracked one counts', async () => {
    const shapes: [Record<string, string>, string][] = [
      [{ 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE }, 'out'],
      [{ 'package.json': pkg({ scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'src/main.ts': 'export {};\n' }, 'public-build'],
    ];
    for (const [files, folder] of shapes) {
      const built = { ...files, '.gitignore': `/${folder}/\n.next/\n`, [`${folder}/server.js`]: 'require("http").createServer().listen(process.env.PORT || 3000);\n', '.next/server/app/api/route.js': 'module.exports = 1;\n' };
      expect(isStatic(await typeOf(built, { index: true })), folder).toBe(true);
      // the same files tracked (no .gitignore): the server file is the repo's own code
      const { '.gitignore': _gi, ...tracked } = built;
      expect(isStatic(await typeOf(tracked, { index: true })), folder).toBe(false);
    }
  });
});

describe('project type: other types', () => {
  it('express app → server', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': pkg({ scripts: { start: 'node index.js' }, dependencies: { express: '5.0.0' } }), 'index.js': "require('express')().listen(process.env.PORT || 3000);\n" },
      { 'package.json': pkg({ scripts: { dev: 'tsx watch src/app.ts' }, dependencies: { fastify: '5.0.0' } }), 'src/app.ts': 'const port = 8080;\n' },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      expect(t.types).toEqual(['server']);
      expect(t.unsure).toBe(false);
      expect(t.evidence.join('\n')).toMatch(/runs as a server/);
    }
  });

  it('package with exports and no run script → library', async () => {
    const shapes = [
      pkg({ type: 'module', exports: { '.': './dist/index.js' }, scripts: { build: 'tsc', test: 'vitest run' } }),
      pkg({ main: './lib/index.cjs', module: './lib/index.mjs', scripts: { prepare: 'rollup -c' } }),
    ];
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': text, 'src/index.ts': 'export const one = 1;\n' });
      expect(t.types).toEqual(['library']);
      expect(t.unsure).toBe(false);
      expect(t.evidence.join('\n')).toMatch(/package\.json/);
    }
  });

  it('bin → cli', async () => {
    const shapes = [
      pkg({ bin: './cli.js', scripts: { test: 'node --test' } }),
      pkg({ bin: { tool: './bin/tool.mjs', 'tool-x': './bin/x.mjs' }, main: './index.js' }),
    ];
    for (const text of shapes) {
      const t = await typeOf({ 'package.json': text, 'cli.js': '#!/usr/bin/env node\nconsole.log(1);\n' });
      expect(t.types).toContain('cli');
      expect(t.evidence).toContain('bin in package.json');
    }
  });

  it('Dockerfile → container kept with static', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, Dockerfile: 'FROM nginx:1\nCOPY out /usr/share/nginx/html\nEXPOSE 80\n' },
      { 'package.json': pkg({ scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), Dockerfile: 'FROM caddy:2\nCOPY dist /srv\n' },
    ];
    for (const files of shapes) {
      const p = await profileOf(files);
      const s = p.services[0] as Service;
      expect(s.projectType?.types).toEqual(['static-site', 'container']);
      expect(s.projectType?.evidence).toContain('has a Dockerfile: Dockerfile');
      expect(isRunnable(s)).toBe(true); // a container keeps the image checks
    }
  });

  it("python service → today's rule, unsure false", async () => {
    const cases: [Record<string, string>, ServiceType[]][] = [
      [{ 'requirements.txt': 'flask==3.0.0\n', 'app.py': 'from flask import Flask\napp = Flask(__name__)\n' }, ['server']],
      [{ 'pyproject.toml': '[project]\nname = "tool"\nversion = "1.0"\ndependencies = ["fastapi"]\n', 'main.py': 'x = 1\n' }, ['server']],
      [{ 'pyproject.toml': '[project]\nname = "helpers"\nversion = "1.0"\n', 'helpers/__init__.py': 'x = 1\n' }, []],
    ];
    for (const [files, types] of cases) {
      const t = await typeOf(files);
      expect(t.types, Object.keys(files).join()).toEqual(types);
      expect(t.unsure).toBe(false);
    }
  });

  it('publishedPackage service → library after the workflow pass', async () => {
    const publish = (cmd: string) => `on:\n  push:\n    tags: ['v*']\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${cmd}\n`;
    const cases: Record<string, string>[] = [
      { 'package.json': pkg({ scripts: { start: 'node server.js' } }), 'server.js': 'const p = process.env.PORT || 3000;\n', '.github/workflows/release.yml': publish('npm publish --provenance') },
      { 'pyproject.toml': '[project]\nname = "pkg"\nversion = "1.0"\n', 'pkg/__init__.py': 'app_port = 5000\n', '.github/workflows/pypi.yml': publish('twine upload dist/*') },
    ];
    for (const files of cases) {
      const p = await profileOf(files);
      const s = p.services[0] as Service;
      expect(s.publishedPackage).toBe(true);
      expect(s.projectType?.types).toContain('library');
      expect(s.projectType?.evidence.join('\n')).toMatch(/published/);
    }
  });

  it('every evidence line holds fixed wording and plain paths only', async () => {
    const p = await profileOf({ 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, 'we ird$(x)/server.ts': "require('http').createServer().listen(1234);\n" });
    const t = p.services[0]?.projectType as ProjectType;
    expect(t.unsure).toBe(true);
    for (const line of t.evidence) expect(line).not.toMatch(/\$\(|we ird/);
  });
});

describe('project type: static hosts', () => {
  it('static host deploy lines set staticHosts and add evidence to a static site only', async () => {
    const wf = (steps: string) => `on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`;
    const files = {
      '.github/workflows/pages.yml': wf('      - run: npx wrangler pages deploy out --project-name site\n'),
      '.github/workflows/gh.yml': wf('      - uses: actions/deploy-pages@v4\n      - run: echo "netlify deploy"\n'),
      '.github/workflows/fb.yml': wf('      - run: |\n          npm ci\n          firebase deploy --only hosting\n      - run: netlify deploy --prod\n'),
      '.github/workflows/other.yml': wf('      - run: firebase deploy --only functions\n      - uses: peaceiris/actions-gh-pages@v4\n'),
    };
    const dir = repo(files);
    const w = await readWorkflows(dir);
    const by = Object.fromEntries(w.map((x) => [x.path, x.staticHosts]));
    expect(by['.github/workflows/pages.yml']).toEqual(['cloudflare-pages']);
    expect(by['.github/workflows/gh.yml']).toEqual(['github-pages']); // an echo is never a deploy
    expect(by['.github/workflows/fb.yml']).toEqual(['firebase-hosting', 'netlify']);
    expect(by['.github/workflows/other.yml']).toEqual(['github-pages']);

    const site = await typeOf({ ...files, 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE });
    expect(site.evidence).toContain('deploys with wrangler pages deploy (.github/workflows/pages.yml)');
    expect(site.evidence).toContain('deploys with firebase deploy --only hosting and netlify deploy (.github/workflows/fb.yml)');
    // a static host alone never makes a static site
    const server = await typeOf({ ...files, 'package.json': pkg({ scripts: { start: 'node index.js' }, dependencies: { express: '5.0.0' } }), 'index.js': '\n' });
    expect(server.types).toEqual(['server']);
    expect(server.evidence.join('\n')).not.toMatch(/deploys with/);
  });
});

// ---------- overrides and the minimum ----------

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: [], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const profile = (services: Service[], over: Partial<RepoProfile> = {}): RepoProfile => ({
  owner: 'o', repo: 'r', defaultBranch: 'main', private: false, ownerType: 'User', plan: 'free',
  monorepo: 'none', services, terraformDirs: [], hasCompose: false, existingWorkflows: [], precommit: null, repoFiles: emptyRepoFiles(), ...over,
});
const type = (types: ServiceType[], unsure = false): ProjectType => ({ types, evidence: [], unsure });
const CAPS = Object.fromEntries(['branchProtection', 'environments', 'deploymentBranchPolicies', 'envRequiredReviewers', 'attestations', 'codeScanning', 'keylessSigningAllowed'].map((n) => [n, true])) as unknown as Capabilities;

describe('project type: overrides', () => {
  it('applyTypeOverrides: single service, named service, unknown name → error', () => {
    const one = profile([svc({ name: 'web', scripts: ['dev'], frameworks: ['next'], projectType: type(['server'], true) })]);
    const a = applyTypeOverrides(one, [{ service: null, type: 'static-site' }]);
    expect(a.services[0]?.projectType).toMatchObject({ types: ['static-site'], unsure: false, overridden: true });
    expect(one.services[0]?.projectType?.types).toEqual(['server']); // the input is not changed

    const two = profile([svc({ name: 'web', scripts: ['dev'], projectType: type(['server']) }), svc({ name: 'docs', path: 'docs', projectType: type(['static-site']) })]);
    const b = applyTypeOverrides(two, [{ service: 'docs', type: 'server' }, { service: 'web', type: 'library' }]);
    expect(b.services.map((s) => s.projectType?.types)).toEqual([['library'], ['server']]);
    expect(b.services.every((s) => s.projectType?.overridden === true)).toBe(true);
    expect(applyTypeOverrides(two, []).services).toEqual(two.services);

    expect(() => applyTypeOverrides(two, [{ service: null, type: 'server' }])).toThrow(/--type <service>=<type>/);
    expect(() => applyTypeOverrides(two, [{ service: 'ghost', type: 'server' }])).toThrow(/No service is named ghost/);
    expect(() => applyTypeOverrides(two, [{ service: 'web', type: 'server' }, { service: 'web', type: 'cli' }])).toThrow(/twice/);
    expect(() => applyTypeOverrides(profile([]), [{ service: null, type: 'server' }])).toThrow();
  });

  it('override to static-site on a service with a Dockerfile keeps container', () => {
    const shapes = [
      svc({ name: 'web', dockerfile: 'Dockerfile', scripts: ['start'], frameworks: ['express'], projectType: type(['server', 'container']) }),
      svc({ name: 'site', path: 'site', dockerfile: 'site/Dockerfile', projectType: type(['container']) }),
    ];
    for (const s of shapes) {
      const p = applyTypeOverrides(profile([s]), [{ service: s.name, type: 'static-site' }]);
      const out = p.services[0] as Service;
      expect(out.projectType?.types).toEqual(['static-site', 'container']);
      expect(isRunnable(out)).toBe(true);
      const ids = floorNeeds(p, CAPS).map((n) => n.id);
      for (const id of ['image-build', 'image-scan', 'dast']) expect(ids).toContain(id);
    }
  });

  it('every type keeps secrets, deps, sast, workflow-lint, workflow-pin-check and gate needs', () => {
    expect([...MINIMUM_CATEGORIES]).toEqual(['secrets', 'deps', 'sast', 'workflow-lint', 'workflow-pin-check', 'gate']);
    const all: ServiceType[] = ['static-site', 'library', 'cli', 'server', 'container'];
    const shapes = [
      (t: ProjectType) => svc({ name: 'a', scripts: ['dev'], frameworks: ['next'], projectType: t }),
      (t: ProjectType) => svc({ name: 'b', path: 'b', language: 'python', packageManager: 'pip', dockerfile: 'b/Dockerfile', projectType: t }),
    ];
    for (const make of shapes) {
      for (const t of [...all.map((x) => type([x])), type([]), type(['static-site', 'container']), undefined]) {
        const s = make(t ?? type([]));
        if (t === undefined) delete (s as { projectType?: ProjectType }).projectType;
        const detected = profile([s]);
        for (const p of [detected, ...all.map((x) => applyTypeOverrides(detected, [{ service: s.name, type: x }]))]) {
          const needs = floorNeeds(p, CAPS);
          for (const c of MINIMUM_CATEGORIES) expect(needs.some((n) => n.category === c), `${c} for ${JSON.stringify(p.services[0]?.projectType)}`).toBe(true);
        }
      }
    }
  });

  it('static-site service → image-build, image-scan and dast listed in skippedChecks with the static reason', () => {
    const shapes = [
      svc({ name: 'site', scripts: ['dev', 'build'], frameworks: ['next'], projectType: type(['static-site']) }),
      svc({ name: 'docs', path: 'docs', scripts: ['start'], port: 3000, projectType: type(['static-site', 'library']) }),
    ];
    for (const s of shapes) {
      const skipped = skippedChecks(profile([s]), CAPS);
      for (const c of ['image-build', 'image-scan', 'dast', 'api-dast'] as const) {
        expect(skipped.find((k) => k.category === c && k.service === s.name)?.why, c).toBe(STATIC_SKIP);
      }
    }
    // a service that doesn't run (not static): today's wording
    const lib = skippedChecks(profile([svc({ name: 'lib', scripts: ['build'] })]), CAPS);
    expect(lib.find((k) => k.category === 'image-scan' && k.service === 'lib')?.why).toMatch(/doesn't run as a server/);
    // a runnable service: no image skip
    expect(skippedChecks(profile([svc({ name: 'web', scripts: ['start'] })]), CAPS).some((k) => k.category === 'image-scan')).toBe(false);
  });
});

// ---------- fix round 1 (review J2: I1, I2, I3, controller ruling on unsure) ----------

const vitePkg = (extra: Record<string, unknown> = {}) => pkg({ scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '7.0.0' }, ...extra });
const SERVER_JS = "require('http').createServer((q, s) => s.end()).listen(process.env.PORT || 8080);\n";

describe('project type: code pipegen did not read is never "no server sign" (review J2 I1)', () => {
  it('a code file over the read limit → unsure, the evidence names it', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': vitePkg(), 'server.js': `${'// pad\n'.repeat(150_000)}${SERVER_JS}` },
      { 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, 'tools/big.ts': `${'export const x = 1;\n'.repeat(60_000)}${SERVER_JS}` },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      const big = Object.keys(files).find((f) => (files[f] as string).length > 1_000_000) as string;
      expect(isStatic(t), big).toBe(false);
      expect(t.unsure).toBe(true);
      expect(t.evidence.join('\n')).toContain(`pipegen couldn't read ${big}`);
    }
  });

  it('a code line too long to check → unsure, the evidence names the file', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': vitePkg(), 'server.js': `/*${'x'.repeat(5000)}*/ ${SERVER_JS}` },
      { 'package.json': pkg({ scripts: { start: 'docusaurus start', build: 'docusaurus build' }, dependencies: { '@docusaurus/core': '3.0.0' } }), 'src/bundle.min.js': `var a=${'1+'.repeat(3000)}1;${SERVER_JS}` },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      expect(isStatic(t)).toBe(false);
      expect(t.unsure).toBe(true);
      expect(t.evidence.join('\n')).toMatch(/lines too long for pipegen to check/);
    }
  });

  it('a file list cut at the read limit → unsure', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': vitePkg(), 'src/main.ts': 'export {};\n' },
      { 'package.json': pkg({ scripts: { build: 'eleventy' }, devDependencies: { '@11ty/eleventy': '3.0.0' } }) },
    ];
    for (const files of shapes) {
      const dir = repo(files);
      // more files than the listing reads (READ_LIMITS.maxFiles = 20,000): plain pages
      for (let i = 0; i < 20_001; i++) writeIn(dir, `content/p${Math.floor(i / 1000)}/${i}.md`, '#\n');
      const t = (await readProject(dir)).services[0]?.projectType as ProjectType;
      expect(isStatic(t)).toBe(false);
      expect(t.unsure).toBe(true);
      expect(t.evidence.join('\n')).toMatch(/listed only part of the files/);
    }
  }, 120_000);
});

describe('project type: another server in the same folder (review J2 I2, I3)', () => {
  it('a Python, Go or other-language app in the same folder as a static build → unsure server', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': vitePkg(), 'requirements.txt': 'django==5.0\ngunicorn==22.0\n', 'manage.py': 'import django\n', Procfile: 'web: gunicorn site.wsgi\n' },
      { 'package.json': vitePkg(), 'go.mod': 'module example.com/app\n\ngo 1.23\n', 'main.go': 'package main\nimport "net/http"\nfunc main() { http.ListenAndServe(":8080", nil) }\n' },
      { 'package.json': pkg({ scripts: { build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), Gemfile: "source 'https://rubygems.org'\ngem 'sinatra'\n", 'config.ru': 'run App\n' },
    ];
    for (const files of shapes) {
      const p = await profileOf(files);
      const s = p.services[0] as Service;
      expect(isStatic(s.projectType as ProjectType), Object.keys(files).join()).toBe(false);
      expect(s.projectType?.unsure).toBe(true);
      expect(s.projectType?.types).toContain('server');
      expect(isRunnable(s)).toBe(true);
      expect(s.projectType?.evidence.join('\n')).toMatch(/another language's app in the same folder/);
    }
  });

  it('a Worker or serverless functions next to the static build → unsure server', async () => {
    const worker = 'export default { fetch() { return new Response("{}"); } };\n';
    const shapes: Record<string, string>[] = [
      { 'package.json': vitePkg({ devDependencies: { vite: '7.0.0', '@cloudflare/vite-plugin': '1.0.0', wrangler: '4.0.0' } }), 'wrangler.jsonc': '{\n  // the API\n  "name": "app",\n  "main": "worker/index.ts",\n}\n', 'worker/index.ts': worker },
      { 'package.json': vitePkg({ devDependencies: { vite: '7.0.0', wrangler: '4.0.0' } }), 'wrangler.toml': 'name = "app"\nmain = "src/worker.ts"\ncompatibility_date = "2026-01-01"\n', 'src/worker.ts': worker },
      { 'package.json': vitePkg(), 'wrangler.json': '{ "name": "app", "main": "edge.js" }\n', 'edge.js': worker },
      { 'package.json': vitePkg(), 'public/_worker.js': worker },
      { 'package.json': vitePkg(), 'netlify.toml': '[build]\n  publish = "dist"\n  functions = "lambda"\n', 'lambda/hello.js': 'exports.handler = async () => ({ statusCode: 200 });\n' },
      { 'package.json': vitePkg(), 'vercel.json': '{ "functions": { "server/*.js": { "memory": 128 } } }\n', 'server/hi.js': 'module.exports = (q, s) => s.end();\n' },
      { 'package.json': vitePkg(), 'firebase.json': '{ "hosting": { "public": "dist", "rewrites": [{ "source": "/api/**", "function": "api" }] } }\n' },
      { 'package.json': vitePkg({ dependencies: { '@netlify/functions': '3.0.0' } }) },
      // the Worker plugin alone (its config may sit elsewhere, or come from the plugin's defaults)
      { 'package.json': vitePkg({ devDependencies: { vite: '7.0.0', '@cloudflare/vite-plugin': '1.0.0' } }), 'src/main.ts': 'export {};\n' },
    ];
    for (const files of shapes) {
      const t = await typeOf(files);
      expect(isStatic(t), Object.keys(files).join()).toBe(false);
      expect(t.unsure, Object.keys(files).join()).toBe(true);
    }
  });

  it('a Pages-only wrangler config or a hosting-only firebase.json stays static', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': vitePkg({ devDependencies: { vite: '7.0.0', wrangler: '4.0.0' } }), 'wrangler.toml': 'name = "site"\npages_build_output_dir = "dist"\n# main is not set: a Pages project\n' },
      { 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, 'firebase.json': '{ "hosting": { "public": "out", "cleanUrls": true } }\n', 'wrangler.jsonc': '{ "name": "site", "pages_build_output_dir": "out" }\n' },
    ];
    for (const files of shapes) expect((await typeOf(files)).types, Object.keys(files).join()).toEqual(['static-site']);
  });
});

describe('project type: an unsure static site is a server (controller ruling, review J2 ⚠️1)', () => {
  it('unsure with no run script → type server, runnable, DAST planned', async () => {
    const shapes: Record<string, string>[] = [
      { 'package.json': pkg({ scripts: { build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'functions/api/hi.ts': 'export const onRequest = () => new Response("");\n' },
      { 'package.json': pkg({ scripts: { build: 'docusaurus build' }, dependencies: { '@docusaurus/core': '3.0.0' } }), 'api/ping.js': 'module.exports = (q, s) => s.end();\n' },
      { 'package.json': pkg({ scripts: { build: 'eleventy' }, devDependencies: { '@11ty/eleventy': '3.0.0' } }), 'netlify/functions/x.mjs': 'export default async () => new Response("");\n' },
    ];
    for (const files of shapes) {
      const p = await profileOf(files);
      const s = p.services[0] as Service;
      expect(s.projectType?.unsure, Object.keys(files).join()).toBe(true);
      expect(s.projectType?.types).toEqual(['server']);
      expect(isRunnable(s)).toBe(true);
      expect(floorNeeds({ ...p, private: false, ownerType: 'User', plan: 'free' }, CAPS).some((n) => n.id === 'dast' && n.service === s.name)).toBe(true);
    }
  });
});

// ---------- fix round 2 (review J2 r1: N1; controller ruling on library evidence) ----------

const LONG_LINE = `/*${'x'.repeat(6000)}*/ export const y = 1;\n`;

describe('project type: the unsure → server rule keeps the older guards (review J2 r1)', () => {
  it('an unsure static folder that is not standalone (built into another image, one-shot) → no server type, not runnable', async () => {
    const shapes: [Record<string, string>, string][] = [
      [{
        'package.json': pkg({ private: true, workspaces: ['web', 'api'] }),
        'web/package.json': pkg({ name: 'web', scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '7.0.0' } }),
        'web/src/main.js': LONG_LINE,
        'api/package.json': pkg({ name: 'api', scripts: { start: 'node server.js' }, dependencies: { express: '5.0.0' } }),
        'api/server.js': SERVER_JS,
        'api/Dockerfile': 'FROM node:24\nWORKDIR /app\nCOPY web ./web\nCOPY api ./api\nCMD ["node", "api/server.js"]\n',
      }, 'web'],
      [{
        'package.json': pkg({ scripts: { start: 'node tools/info.js', build: 'vite build' }, devDependencies: { vite: '7.0.0' } }),
        'tools/info.js': "console.log('built at', new Date().toISOString());\n",
        'src/main.js': 'export {};\n',
      }, 'site'],
    ];
    for (const [files, name] of shapes) {
      const p = await profileOf(files);
      const s = p.services.find((x) => x.name === name) as Service;
      expect(s.notStandalone, name).toBeDefined();
      expect(s.projectType?.unsure, name).toBe(true);
      expect(s.projectType?.types, name).not.toContain('server');
      expect(isRunnable(s), name).toBe(false);
      const mine = floorNeeds({ ...p, private: false, ownerType: 'User', plan: 'free' }, CAPS).filter((n) => n.service === name).map((n) => n.id);
      for (const id of ['image-build', 'image-scan', 'dast']) expect(mine, `${name} ${id}`).not.toContain(id);
      expect(s.projectType?.evidence.join('\n')).not.toMatch(/treats it as a server|treated as a server/);
      // isRunnable keeps the P55 guard whatever the type says (a hand-built or overridden server type)
      expect(isRunnable({ ...s, projectType: { types: ['server'], evidence: [], unsure: false, overridden: true } }), name).toBe(false);
    }
  });

  it('an unsure static build with library evidence (exports or main and no run script, or a published package) → library, not a server, not runnable', async () => {
    const publish = `on:\n  push:\n    tags: ['v*']\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n`;
    const shapes: Record<string, string>[] = [
      { 'package.json': pkg({ type: 'module', exports: { '.': './dist/index.js' }, scripts: { build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'src/index.js': LONG_LINE },
      { 'package.json': pkg({ main: './lib/index.cjs', scripts: { build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'functions/x.ts': 'export const onRequest = () => new Response("");\n' },
      { 'package.json': pkg({ scripts: { build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'src/index.js': LONG_LINE, '.github/workflows/release.yml': publish },
    ];
    for (const files of shapes) {
      const p = await profileOf(files);
      const s = p.services[0] as Service;
      expect(s.projectType?.unsure, Object.keys(files).join()).toBe(true);
      expect(s.projectType?.types).toEqual(['library']);
      expect(isRunnable(s)).toBe(false);
      const text = s.projectType?.evidence.join('\n') ?? '';
      expect(text).toMatch(/looks like a static site/);
      expect(text).toMatch(/--type static-site/);
      expect(text).not.toMatch(/treats it as a server|treated as a server/);
    }
  });
});

describe('GJ-R1 (review GJ sec I1): any container build file of the folder is container evidence', () => {
  const CAPS: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: true };
  const DEPLOY = '.github/workflows/deploy.yml';
  const deployWf = (file: string) => `on: push\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker build -f ${file} -t ghcr.io/o/site . && docker push ghcr.io/o/site\n`;
  for (const file of ['Dockerfile.prod', 'Containerfile', 'web.Dockerfile', 'Containerfile.release']) {
    it(`next export plus ${file}: a container, so image build, image scan and signing stay (never the static skip)`, async () => {
      const files = { 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, [file]: 'FROM nginx\nCOPY out /usr/share/nginx/html\n', [DEPLOY]: deployWf(file) };
      const p = { ...(await profileOf(files)), private: false, ownerType: 'User', plan: 'free' } as RepoProfile;
      const s = p.services[0] as Service;
      expect(s.dockerfile).toBe(file);
      expect(s.projectType?.types).toContain('container');
      expect(s.projectType?.evidence.join('\n')).toContain(file);
      expect(isRunnable(s)).toBe(true);
      const ids = floorNeeds(p, CAPS).filter((n) => n.service === s.name).map((n) => n.id);
      expect(ids).toEqual(expect.arrayContaining(['image-build', 'image-scan', 'signing']));
      expect(skippedChecks(p, CAPS).some((k) => k.why === STATIC_SKIP)).toBe(false);
      // a --type override keeps the container type too
      const over = applyTypeOverrides(p, [{ service: s.name, type: 'static-site' }] as never);
      expect(over.services[0]?.projectType?.types).toEqual(['static-site', 'container']);
      expect(isRunnable(over.services[0] as Service)).toBe(true);
    });
  }
  it('a Dockerfile.dockerignore or a Dockerfile in a sub-folder is not the folder\'s container file', async () => {
    const p = await profileOf({ 'package.json': nextPkg(), 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, 'Dockerfile.dockerignore': 'node_modules\n' });
    expect(p.services[0]?.dockerfile).toBeUndefined();
    expect(p.services[0]?.projectType?.types).toEqual(['static-site']);
  });
});

describe('GJ-R2 (review GJ-r1 N1, N2, N4): every container file that builds a folder keeps its image checks', () => {
  const CAPS: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: true };
  const NGINX = 'FROM nginx:1.27\nCOPY out /usr/share/nginx/html\nEXPOSE 80\n';
  const wf = (cmd: string) => `on: { push: { branches: [main] } }\njobs:\n  img:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${cmd}\n`;
  const site = (extra: Record<string, string>) => ({ 'package.json': nextPkg(), 'package-lock.json': '{"lockfileVersion":3,"packages":{}}', 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, ...extra });
  const ws = (extra: Record<string, string>) => ({
    'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': '{"lockfileVersion":3,"packages":{}}',
    'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0', react: '19.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
    'apps/api/package.json': pkg({ name: 'api', scripts: { start: 'node index.js' }, dependencies: { express: '4.0.0' } }), 'apps/api/index.js': "require('express')().listen(3000);\n", 'apps/api/Dockerfile': 'FROM node:24\nEXPOSE 3000\n',
    ...extra,
  });
  const read = async (files: Record<string, string>): Promise<RepoProfile> => ({ ...(await profileOf(files)), private: false, ownerType: 'User', plan: 'free' } as RepoProfile);
  const staticSkips = (p: RepoProfile) => skippedChecks(p, CAPS).filter((k) => k.why === STATIC_SKIP);
  /** the file keeps image checks: a service builds it (its Dockerfile) or names it as its container hint (unsure, so a server) */
  const kept = (p: RepoProfile, file: string): Service => {
    const s = p.services.find((x) => x.dockerfile === file || x.containerHint?.includes(file) === true);
    expect(s, `${file}: ${JSON.stringify(p.services.map((x) => [x.name, x.dockerfile, x.containerHint, x.projectType?.types]))}`).toBeDefined();
    expect(isRunnable(s as Service), file).toBe(true);
    expect(floorNeeds(p, CAPS).some((n) => n.service === (s as Service).name && n.id === 'image-build'), file).toBe(true);
    expect(staticSkips(p), file).toEqual([]);
    return s as Service;
  };

  for (const name of ['Dockerfile-prod', 'Dockerfile_prod', 'prod.dockerfile', 'dockerfile', 'dockerfile.prod', 'Containerfile-release']) {
    it(`a root static site with ${name} (any case, a . - or _ suffix, *.dockerfile) is a container`, async () => {
      const p = await read(site({ [name]: NGINX, '.github/workflows/img.yml': wf(`docker build -f ${name} -t ghcr.io/o/site . && docker push ghcr.io/o/site`) }));
      expect(kept(p, name).projectType?.types).toContain('container');
    });
  }
  it('names that are clearly not buildable stay out (.bak .orig .template .tmpl .example .sample .md .txt)', async () => {
    for (const name of ['Dockerfile.bak', 'Dockerfile.orig', 'Dockerfile.template', 'Dockerfile.tmpl', 'Dockerfile.example', 'Dockerfile.sample', 'Dockerfile.md', 'dockerfile.txt']) {
      const p = await read(site({ [name]: NGINX }));
      expect(p.services[0]?.dockerfile, name).toBeUndefined();
      expect(p.services[0]?.projectType?.types, name).toEqual(['static-site']);
    }
  });
  it('a root static site built from deploy/Dockerfile.prod keeps its image checks', async () => {
    kept(await read(site({ 'deploy/Dockerfile.prod': NGINX, '.github/workflows/img.yml': wf('docker build -f deploy/Dockerfile.prod -t ghcr.io/o/site . && docker push ghcr.io/o/site') })), 'deploy/Dockerfile.prod');
  });
  it('a workspace static site built from apps/web/docker/Dockerfile is unsure, so a server, and names the file', async () => {
    const p = await read(ws({ 'apps/web/docker/Dockerfile': NGINX, '.github/workflows/img.yml': wf('docker build -f apps/web/docker/Dockerfile apps/web && docker push ghcr.io/o/web') }));
    const web = kept(p, 'apps/web/docker/Dockerfile');
    expect(web.name).toBe('web');
    expect(web.projectType?.unsure).toBe(true);
    expect(web.projectType?.types).toContain('server');
    expect(web.projectType?.evidence.join('\n')).toMatch(/apps\/web\/docker\/Dockerfile/);
    // the audit names it as not covered (the file pipegen can't build), never "pipegen would create one"
    const row = wouldCreateOf(p).find((r) => r.what === 'docker' && r.why.startsWith('nothing for web,'));
    expect(row?.why).toMatch(/may be built into an image elsewhere \(a container file builds it: apps\/web\/docker\/Dockerfile\): pipegen can't build or scan that image yet, so it is not covered/);
  });
  it('a workspace static site built by a root Dockerfile.web (COPY of its folder) is unsure, so a server', async () => {
    const p = await read(ws({ 'Dockerfile.web': 'FROM nginx:1.27\nCOPY apps/web/out /usr/share/nginx/html\nEXPOSE 80\n' }));
    const web = p.services.find((s) => s.name === 'web') as Service;
    expect(web.containerHint).toMatch(/Dockerfile\.web/);
    kept(p, 'Dockerfile.web');
  });
  it('a workflow that builds the folder (docker build -f … <folder>) makes it unsure too', async () => {
    const p = await read(ws({ 'ops/web.Dockerfile': NGINX, '.github/workflows/img.yml': wf('docker build -f ops/web.Dockerfile apps/web && docker push ghcr.io/o/web') }));
    const web = p.services.find((s) => s.name === 'web') as Service;
    expect(web.projectType?.unsure).toBe(true);
    expect(isRunnable(web)).toBe(true);
    expect(staticSkips(p)).toEqual([]);
  });
  it('scoping controls: fixtures, tests, vendor, a sibling folder and another service\'s file never touch the static site', async () => {
    const a = await read(site({ 'test/fixtures/Dockerfile.x': NGINX, 'vendor/lib/Dockerfile.prod': NGINX, 'tests/Containerfile': NGINX }));
    expect(a.services.map((s) => [s.path, s.projectType?.types])).toEqual([['.', ['static-site']]]);
    const b = await read(ws({ 'apps/api/Dockerfile.prod': NGINX, 'apps/web/test/Dockerfile.ci': NGINX, 'apps/webx/Dockerfile.prod': NGINX }));
    const web = b.services.find((s) => s.name === 'web') as Service;
    expect(web.projectType?.types).toEqual(['static-site']);
    expect(web.containerHint).toBeUndefined();
    expect(web.dockerfile).toBeUndefined();
  });
  it('scoping: a service nested in the static site\'s folder keeps its container file to itself', async () => {
    const p = await read(ws({
      'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*', 'apps/web/admin'] }),
      'apps/web/admin/package.json': pkg({ name: 'admin', scripts: { start: 'node index.js' }, dependencies: { express: '4.0.0' } }), 'apps/web/admin/index.js': "require('express')().listen(3001);\n", 'apps/web/admin/Dockerfile.prod': 'FROM node:24\nEXPOSE 3001\n',
    }));
    const web = p.services.find((s) => s.name === 'web') as Service;
    expect(p.services.find((s) => s.name === 'admin')?.dockerfile).toBe('apps/web/admin/Dockerfile.prod');
    expect(web.containerHint).toBeUndefined();
    expect(web.projectType?.types).toEqual(['static-site']);
  });
  it('N2: service finding uses the same rule (a folder or workspace package with Dockerfile.prod is a service)', async () => {
    const folders = await read({
      'api/package.json': pkg({ name: 'api', scripts: { start: 'node index.js' }, dependencies: { express: '4.0.0' } }), 'api/index.js': "require('express')().listen(3000);\n", 'api/Dockerfile': 'FROM node:24\nEXPOSE 3000\n',
      'web/package.json': pkg({ name: 'web', scripts: { build: 'next build' }, dependencies: { next: '15.0.0' } }), 'web/next.config.mjs': "export default { output: 'export' };\n", 'web/app/page.tsx': PAGE, 'web/Dockerfile.prod': NGINX,
    });
    expect(folders.services.map((s) => s.path).sort()).toEqual(['api', 'web']);
    expect(folders.services.find((s) => s.path === 'web')?.dockerfile).toBe('web/Dockerfile.prod');
    const build = await read(ws({ 'apps/site/package.json': pkg({ name: 'site2', scripts: { build: 'vite build' }, devDependencies: { vite: '5.0.0' } }), 'apps/site/index.html': '<html></html>\n', 'apps/site/Dockerfile.prod': NGINX }));
    expect(build.services.find((s) => s.path === 'apps/site')?.dockerfile).toBe('apps/site/Dockerfile.prod');
  });
  it('N4: of several container files the one a workflow builds wins, with a note naming the chosen file and the others', async () => {
    const two = { 'Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.prod': NGINX };
    const notesOf = async (files: Record<string, string>) => { const notes: string[] = []; const p = await readProject(repo(files), { notes }); return { p, notes: notes.join('\n') }; };
    const built = await notesOf(site({ ...two, '.github/workflows/img.yml': wf('docker build -f Dockerfile.prod -t ghcr.io/o/site .') }));
    expect(built.p.services[0]?.dockerfile).toBe('Dockerfile.prod');
    expect(built.notes).toMatch(/several container files \(Dockerfile\.dev, Dockerfile\.prod\).*builds and scans Dockerfile\.prod \(the one a workflow builds\)/);
    // with no workflow naming one: a plain Dockerfile first, else the first by name; the note says which and lists the others
    const none = await notesOf(site(two));
    expect(none.p.services[0]?.dockerfile).toBe('Dockerfile.dev');
    expect(none.notes).toMatch(/several container files \(Dockerfile\.dev, Dockerfile\.prod\).*builds and scans Dockerfile\.dev \(the first by name/);
    const plain = await notesOf(site({ ...two, Dockerfile: NGINX }));
    expect(plain.p.services[0]?.dockerfile).toBe('Dockerfile');
  });

describe('GJ-R-sec1: workflowBuildRefs reads hostile workflow text within the regex budget', () => {
  it('long runs of spaces, slashes or unclosed quotes finish fast; real references are still found', async () => {
    const hostile = (n: number) => [
      `file:${' '.repeat(n)}x`, `context: ${'/'.repeat(n)}`, `      -f ${'/'.repeat(n)}a`, `docker build ${' '.repeat(n)}-f`,
      `${'\n'.repeat(n / 2)}file:${' \n'.repeat(n / 2)}`, `-f "${'a'.repeat(n)}`, `context: ${'./'.repeat(n / 2)}`,
    ];
    // G17: a ratio, not a wall-clock budget: ten times the text costs about ten times the time, a backtracking pattern about a hundred
    const inputs = { small: hostile(10_000), big: hostile(100_000) };
    await expectScaling('hostile workflow text', (size) => { const t0 = performance.now(); for (let r = 0; r < 200; r++) for (const h of inputs[size]) workflowBuildRefs([h]); return performance.now() - t0; }, 40);
    // values past the per-line budget are dropped, never parsed
    expect(workflowBuildRefs([`context: ${'/'.repeat(100_000)}`]).size).toBe(0);
    // the real forms still count
    expect([...workflowBuildRefs(['      - run: docker build -f apps/web/Dockerfile.prod -t x apps/web/ && docker push x', '          context: ./svc//', '          file: "ops/web.Dockerfile"'])].sort())
      .toEqual(['apps/web', 'apps/web/Dockerfile.prod', 'ops/web.Dockerfile', 'svc']);
  });
});
});

describe('GJ-R3 (review GJ-r2 H1, O1, O2, O3, B1, W1): builds the reader could not see, and no false hints', () => {
  const CAPS3: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: true };
  const NGINX = 'FROM nginx:1.27\nCOPY out /usr/share/nginx/html\nEXPOSE 80\n';
  const LOCK = '{"lockfileVersion":3,"packages":{}}';
  const wf = (cmd: string) => `on: { push: { branches: [main] } }\njobs:\n  img:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${cmd}\n`;
  const site = (extra: Record<string, string>) => ({ 'package.json': nextPkg(), 'package-lock.json': LOCK, 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, ...extra });
  const ws = (extra: Record<string, string>) => ({
    'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK,
    'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0', react: '19.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
    'apps/api/package.json': pkg({ name: 'api', scripts: { start: 'node index.js' }, dependencies: { express: '4.0.0' } }), 'apps/api/index.js': "require('express')().listen(3000);\n", 'apps/api/Dockerfile': 'FROM node:24\nEXPOSE 3000\n',
    ...extra,
  });
  /** a repo with `files` and symbolic links `links` (path → target, never followed by pipegen) */
  const readWith = async (files: Record<string, string>, links: Record<string, string> = {}): Promise<RepoProfile> => {
    const dir = repo(files);
    for (const [rel, target] of Object.entries(links)) { mkdirSync(dirname(join(dir, rel)), { recursive: true }); symlinkSync(target, join(dir, rel)); }
    return { ...(await readProject(dir)), private: false, ownerType: 'User', plan: 'free' } as RepoProfile;
  };
  const web = (p: RepoProfile) => p.services.find((s) => s.name === 'web' || s.path === '.') as Service;
  const staticSkips = (p: RepoProfile) => skippedChecks(p, CAPS3).filter((k) => k.category === 'image-build' && k.service === web(p).name && k.why === STATIC_SKIP);
  const hinted = (p: RepoProfile, name: string) => {
    const s = web(p);
    expect(s.containerHint, JSON.stringify(p.services.map((x) => [x.name, x.dockerfile, x.containerHint, x.projectType?.types]))).toContain(name);
    expect(s.projectType?.unsure).toBe(true);
    expect(isRunnable(s)).toBe(true);
    expect(staticSkips(p)).toEqual([]);
  };
  const stillStatic = (p: RepoProfile) => {
    expect(web(p).containerHint, JSON.stringify(web(p))).toBeUndefined();
    expect(web(p).projectType?.types).toEqual(['static-site']);
    expect(staticSkips(p)).toHaveLength(1);
  };

  it('H1 (a): a symbolic link with a container file name is a hint, by name only (never followed): a root Dockerfile.prod link', async () => {
    hinted(await readWith(site({ 'ops/web.conf': NGINX }), { 'Dockerfile.prod': 'ops/web.conf' }), 'Dockerfile.prod');
    // a link whose target is outside the repo is named, never read
    hinted(await readWith(site({}), { 'deploy/web.Dockerfile': '/nonexistent/outside' }), 'deploy/web.Dockerfile');
  });
  it('H1 (a): a workspace apps/web/Dockerfile link to a shared file is a hint', async () => {
    hinted(await readWith(ws({ 'infra/web.conf': NGINX }), { 'apps/web/Dockerfile': '../../infra/web.conf' }), 'apps/web/Dockerfile');
  });
  it('H1 (a): a linked folder inside the service folder may hold its container file: a hint naming the folder', async () => {
    hinted(await readWith(ws({ 'infra/web/Dockerfile': NGINX }), { 'apps/web/docker': '../../infra/web' }), 'apps/web/docker');
  });
  it('H1 (a) controls: a link with another file name, or one under tests or another service, keeps the site static', async () => {
    stillStatic(await readWith(ws({ 'shared/README.md': '# x\n', 'shared/tsconfig.json': '{}\n' }), { 'apps/web/README.md': '../../shared/README.md', 'apps/web/tsconfig.base.json': '../../shared/tsconfig.json', 'apps/web/e2e/Dockerfile': '../../../shared/README.md', 'apps/api/Dockerfile.prod': 'Dockerfile' }));
  });

  it('H1 (b): a compose build context (long form, short form, a compose file in a sub-folder) is a hint', async () => {
    hinted(await readWith(ws({ 'docker/web.Dockerfile': NGINX, 'compose.yaml': 'services:\n  web:\n    build:\n      context: ./apps/web\n      dockerfile: ../../docker/web.Dockerfile\n    image: ghcr.io/o/web\n' })), 'apps/web');
    hinted(await readWith(ws({ 'docker-compose.yml': 'services:\n  web:\n    build: ./apps/web\n' })), 'apps/web');
    hinted(await readWith(ws({ 'deploy/compose.prod.yml': 'services:\n  web:\n    build:\n      context: ../apps/web\n' })), 'apps/web');
  });
  it('H1 (b): a bake file context (docker buildx bake, docker/bake-action) is a hint', async () => {
    hinted(await readWith(ws({ 'docker/web.Dockerfile': NGINX, 'docker-bake.hcl': 'target "web" {\n  context = "apps/web"\n  dockerfile = "../../docker/web.Dockerfile"\n  tags = ["ghcr.io/o/web"]\n}\n' })), 'apps/web');
  });
  it('H1: at the root, a workflow that builds the repository root (context .) with no container file pipegen can see is a hint', async () => {
    hinted(await readWith(site({ '.github/workflows/img.yml': wf('docker build -t ghcr.io/o/site . && docker push ghcr.io/o/site') })), 'builds an image from it: .');
    // a build of another folder is not the root's
    stillStatic(await readWith(site({ 'tools/x.txt': 'x\n', '.github/workflows/img.yml': wf('docker build -t x ./tools') })));
  });
  it('H1 (b) controls: a compose file that only runs images, or builds another folder, keeps the site static', async () => {
    stillStatic(await readWith(ws({ 'compose.yaml': 'services:\n  db:\n    image: postgres:16\n  api:\n    build: ./apps/api\n', 'docker-bake.hcl': 'target "api" {\n  context = "apps/api"\n}\n' })));
  });
  it('H1 (b): compose and bake build files a folder\'s container file is chosen by', async () => {
    const notes: string[] = [];
    const p = await readProject(repo(site({ 'Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.prod': NGINX, 'compose.yaml': 'services:\n  site:\n    build:\n      context: .\n      dockerfile: Dockerfile.prod\n' })), { notes });
    expect(p.services[0]?.dockerfile).toBe('Dockerfile.prod');
  });

  it('H1 (c): the static skip states what pipegen found, and how to say otherwise', () => {
    const s = svc({ name: 'site', scripts: ['dev', 'build'], frameworks: ['next'], projectType: type(['static-site']) });
    const why = skippedChecks(profile([s]), CAPS).find((k) => k.category === 'image-build')?.why ?? '';
    expect(why).toBe(STATIC_SKIP);
    expect(why).not.toMatch(/[`<>*_|[\]\\]/);
  });

  // O1: a container file in a sub-folder with no app manifest builds the root app; the root stays the service (as at 2450960), never a
  // folder service with no language that stops the plan. Under NOT_BUILD_DIRS (e2e, example) it assembles as before; elsewhere the file is
  // the root's hint (N1: unsure, so a server), the blocking DAST stop names --type, and with it the site assembles as before
  const express = (extra: Record<string, string>) => ({ 'package.json': pkg({ name: 'api', scripts: { start: 'node index.js', test: 'vitest run' }, dependencies: { express: '4.0.0' } }), 'package-lock.json': LOCK, 'index.js': "require('express')().listen(3000);\n", 'index.test.js': 'test("x", () => {});\n', ...extra });
  const staticSite = (extra: Record<string, string>) => site({ 'package.json': nextPkg({ dev: 'next dev', build: 'next build', test: 'vitest run' }), ...extra });
  const assembled = async (p: RepoProfile) => { const a = assemble(planned(p, { over: { skipped: [{ part: 'deploy' as const, reason: 't' }] } })); return shown(await judge(files(a), a.draft)); };
  for (const file of ['docker/Dockerfile.dev', '.docker/dev.Dockerfile', 'e2e/Dockerfile.playwright', 'example/Dockerfile.demo', 'deploy/Dockerfile.prod']) {
    it(`O1: a root static site with ${file} keeps the root as its only service and assembles (with --type when the file is its hint)`, async () => {
      const p = await readWith(staticSite({ [file]: 'FROM node:24\n' }));
      expect(p.services.map((s) => [s.path, s.language])).toEqual([['.', 'node']]);
      if (/^(?:e2e|example)\//.test(file)) {
        stillStatic(p);
        expect(await assembled(p)).toBe('');
      } else {
        hinted(p, file);
        await expect(assembled(p)).rejects.toThrow(/--type site=static-site/);
        expect(await assembled(applyTypeOverrides(p, [{ service: 'site', type: 'static-site' }]))).toBe('');
      }
    });
  }
  it('O1: a root express app with docker/Dockerfile.dev stays the root service (not a "docker" service with no language)', async () => {
    const p = await readWith(express({ 'docker/Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n' }));
    expect(p.services.map((s) => [s.path, s.language])).toEqual([['.', 'node']]);
  });
  it('O1 controls: container folders that all have their own app manifest stay the services (as before); one more with none keeps the root too; no root manifest keeps the container folders', async () => {
    const worker = { 'worker/pyproject.toml': '[project]\nname = "worker"\n', 'worker/main.py': 'print(1)\n', 'worker/Dockerfile': 'FROM python:3.12\n' };
    expect((await readWith(express(worker))).services.map((s) => s.path)).toEqual(['worker']);
    const both = await readWith(express({ ...worker, 'docker/Dockerfile.dev': 'FROM node:24\n' }));
    expect(both.services.map((s) => s.path).sort()).toEqual(['.', 'worker']);
    const images = await readWith({ 'nginx/Dockerfile': NGINX, 'db/Dockerfile.prod': 'FROM postgres:16\n' });
    expect(images.services.map((s) => s.path).sort()).toEqual(['db', 'nginx']);
  });

  it('O2: -f counts only on a docker or podman build line, file: only with a container file name', () => {
    expect([...workflowBuildRefs([
      '      - uses: codecov/codecov-action@v3', '        with:', '          file: ./apps/web/coverage/lcov.info',
      '      - run: npm run build -w web && rm -f apps/web/out/robots.txt', '      - run: kubectl apply -f apps/web/k8s.yaml', '      - run: helm upgrade x -f apps/web/values.yaml',
    ])]).toEqual([]);
    expect([...workflowBuildRefs([
      '      - run: docker build --file=ops/a.Dockerfile -t x svc-a', '      - run: podman build -f ops/Containerfile.b svc-b', '      - run: docker buildx build -f "ops/c/Dockerfile" .',
      '          file: ./docker/web.Dockerfile', '          file: ${{ matrix.dockerfile }}',
    ])].sort()).toEqual(['.', 'docker/web.Dockerfile', 'ops/Containerfile.b', 'ops/a.Dockerfile', 'ops/c/Dockerfile', 'svc-a', 'svc-b']);
  });
  it('O2: codecov, rm -f and kubectl -f workflows keep a workspace static site static', async () => {
    stillStatic(await readWith(ws({ '.github/workflows/ci.yml': 'on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: codecov/codecov-action@v3\n        with:\n          file: ./apps/web/coverage/lcov.info\n' })));
    stillStatic(await readWith(ws({ '.github/workflows/pages.yml': wf('npm run build -w web && rm -f apps/web/out/robots.txt') })));
    stillStatic(await readWith(ws({ 'apps/web/k8s.yaml': 'kind: Deployment\n', '.github/workflows/deploy.yml': wf('kubectl apply -f apps/web/k8s.yaml') })));
  });

  it('O3: container files under example, e2e, playwright, cypress, .storybook, scripts, demo, samples, testdata or benchmark never build the site', async () => {
    for (const sub of ['example', 'e2e', 'playwright', 'cypress', '.storybook', 'scripts', 'demo', 'samples', 'testdata', 'benchmark']) {
      const p = await readWith(ws({ [`apps/web/${sub}/Dockerfile`]: 'FROM node:24\n' }));
      expect(web(p).containerHint, sub).toBeUndefined();
      expect(web(p).projectType?.types, sub).toEqual(['static-site']);
    }
  });
  it('O3: a blocking DAST check that can not start for an unsure service names --type <service>=static-site', async () => {
    const p = await readWith({
      'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK, 'apps/web/docker/Dockerfile': NGINX,
      'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build', test: 'vitest run' }, dependencies: { next: '15.0.0', react: '19.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
    });
    expect(web(p).projectType?.unsure).toBe(true);
    expect(() => assemble(planned(p, { over: { skipped: [{ part: 'deploy' as const, reason: 't' }] } }))).toThrow(/--type web=static-site/);
  });

  it('B1: the workflow text pass reads the first 200 workflow files in name order, like the workflow reader', async () => {
    const many = (at: number) => {
      const out: Record<string, string> = { 'ops/web.Dockerfile': NGINX };
      for (let i = 0; i <= 200; i++) out[`.github/workflows/w${String(i).padStart(3, '0')}.yml`] = wf(i === at ? 'docker build -f ops/web.Dockerfile apps/web' : 'echo ok');
      return out;
    };
    hinted(await readWith(ws(many(199))), 'apps/web');
    stillStatic(await readWith(ws(many(200))));
  });

  it('W1: the hint row reads as an entry of "pipegen would also create:" (it creates nothing for that image)', async () => {
    const p = await readWith(ws({ 'apps/web/docker/Dockerfile': NGINX }));
    const row = wouldCreateOf(p).find((r) => r.what === 'docker' && r.why.includes('web'));
    expect(row?.why).toMatch(/^nothing for web, which may be built into an image elsewhere/);
  });

  it('W1: the hint row is shown for a service that does not run too (its image is still not covered)', () => {
    const lib = svc({ name: 'lib', scripts: ['build'], projectType: type(['library']), containerHint: 'a container file builds it: lib/docker/Dockerfile' });
    expect(isRunnable(lib)).toBe(false);
    expect(wouldCreateOf(profile([lib])).find((r) => r.what === 'docker')?.why).toMatch(/^nothing for lib, which may be built into an image elsewhere/);
  });
  it('nit: .j2, .tpl, .in and .dist names are templates, not container files', async () => {
    for (const name of ['Dockerfile.j2', 'Dockerfile.tpl', 'Dockerfile.in', 'Dockerfile.dist']) {
      const p = await readWith(site({ [name]: NGINX }));
      expect(p.services[0]?.dockerfile, name).toBeUndefined();
      expect(p.services[0]?.projectType?.types, name).toEqual(['static-site']);
    }
  });
});

describe('GJ-R4 (review GJ-r3 N1-N5, N7): continued build lines, a container override that runs, the root keeps its own file', () => {
  const CAPS4: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: true };
  const NGINX = 'FROM nginx:1.27\nCOPY out /usr/share/nginx/html\nEXPOSE 80\n';
  const LOCK = '{"lockfileVersion":3,"packages":{}}';
  const run = (lines: string[]) => `on: { push: { branches: [main] } }\njobs:\n  img:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n${lines.map((l) => `          ${l}`).join('\n')}\n`;
  const site = (extra: Record<string, string>) => ({ 'package.json': nextPkg({ dev: 'next dev', build: 'next build', test: 'vitest run' }), 'package-lock.json': LOCK, 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, ...extra });
  const ws = (extra: Record<string, string>) => ({
    'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK,
    'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0', react: '19.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
    ...extra,
  });
  const read = async (files: Record<string, string>, notes: string[] = []): Promise<RepoProfile> => ({ ...(await readProject(repo(files), { notes })), private: false, ownerType: 'User', plan: 'free' } as RepoProfile);
  const staticSkip = (p: RepoProfile, name: string) => skippedChecks(p, CAPS4).some((k) => k.category === 'image-build' && k.service === name && k.why === STATIC_SKIP);
  const needsOf = (p: RepoProfile, name: string) => floorNeeds(p, CAPS4).filter((n) => n.service === name).map((n) => n.category);
  const assembled = async (p: RepoProfile) => { const a = assemble(planned(p, { over: { skipped: [{ part: 'deploy' as const, reason: 't' }] } })); return { a, issues: shown(await judge(files(a), a.draft)) }; };

  it('N1: a multi-line (\\-continued) buildx build counts its -f and its context', async () => {
    expect([...workflowBuildRefs([['docker buildx build \\', '  -f apps/web/Dockerfile.ci \\', '  -t ghcr.io/o/web \\', '  apps/web'].join('\n')])].sort()).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    const p = await read(ws({ '.github/workflows/img.yml': run(['docker buildx build \\', '  -f apps/web/Dockerfile.ci \\', '  -t ghcr.io/o/web --push \\', '  apps/web']) }));
    const web = p.services.find((s) => s.name === 'web') as Service;
    expect(web.containerHint).toContain('apps/web');
    expect(staticSkip(p, 'web')).toBe(false);
    // a continued line past the 4 KB budget is dropped whole, never parsed
    expect(workflowBuildRefs([`docker build \\\n${`  -t x \\\n`.repeat(1000)}  apps/web`]).size).toBe(0);
  });
  it('N1: a continued -f Dockerfile.prod wins the Dockerfile choice over the plain Dockerfile', async () => {
    const p = await read(site({ Dockerfile: 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.prod': NGINX, '.github/workflows/img.yml': run(['docker build \\', '  -f Dockerfile.prod \\', '  -t ghcr.io/o/site .']) }));
    expect(p.services[0]?.dockerfile).toBe('Dockerfile.prod');
  });

  it('N2: --type <svc>=container on a build-only site (no run script, framework or port) brings image build, image scan and DAST back', async () => {
    const eleventy = { 'package.json': pkg({ name: 'blog', scripts: { build: 'eleventy' }, devDependencies: { '@11ty/eleventy': '3.0.0' } }), 'package-lock.json': LOCK, '.eleventy.js': 'module.exports = {};\n', 'src/index.md': '# hi\n' };
    const p = await read(eleventy);
    expect(staticSkip(p, 'blog')).toBe(true);
    const c = applyTypeOverrides(p, [{ service: 'blog', type: 'container' }]);
    expect(isRunnable(c.services[0] as Service)).toBe(true);
    for (const cat of ['image-build', 'image-scan', 'dast']) expect(needsOf(c, 'blog'), cat).toContain(cat);
    // the skip text names this escape, and it is one the type list has
    expect(STATIC_SKIP).toMatch(/--type SERVICE=container/);
  });

  // N3: the root's own container file stays the root's; container folders with no app manifest are part of it (a note names each)
  const express = (extra: Record<string, string>) => ({ 'package.json': pkg({ name: 'api', scripts: { start: 'node index.js', test: 'vitest run' }, dependencies: { express: '4.0.0' } }), 'package-lock.json': LOCK, 'index.js': "require('express')().listen(3000);\n", 'index.test.js': 'test("x", () => {});\n', Dockerfile: 'FROM node:24\nEXPOSE 3000\nCMD ["node", "index.js"]\n', ...extra });
  const cases: [string, Record<string, string>, string | null][] = [
    ['root express + Dockerfile + docker/Dockerfile.dev', express({ 'docker/Dockerfile.dev': 'FROM node:24\n' }), 'docker'],
    ['root express + Dockerfile + deploy/Dockerfile.prod', express({ 'deploy/Dockerfile.prod': 'FROM node:24\n' }), 'deploy'],
    ['root express + Dockerfile + e2e/Dockerfile.playwright', express({ 'e2e/Dockerfile.playwright': 'FROM node:24\n' }), null],
    ['root static + Dockerfile.prod + docker/Dockerfile.dev', site({ 'Dockerfile.prod': NGINX, 'docker/Dockerfile.dev': 'FROM node:24\n' }), 'docker'],
  ];
  for (const [label, files, folder] of cases) {
    it(`N3: ${label} keeps the root as its only service, with image checks, and assembles cleanly`, async () => {
      const notes: string[] = [];
      const p = await read(files, notes);
      expect(p.services.map((s) => [s.path, s.language])).toEqual([['.', 'node']]);
      expect(needsOf(p, p.services[0]?.name as string)).toContain('image-build');
      if (folder !== null) expect(notes.join('\n')).toContain(`The folder ${folder} has container files but no plain Dockerfile or Containerfile, and no workflow, compose or bake file builds it, so pipegen takes it as part of the root app`);
      else expect(notes.join('\n')).not.toMatch(/takes it as part of the root app/);
      const { a, issues } = await assembled(p);
      expect(issues).toBe('');
      expect(Object.keys(a.merge).some((k) => /image/.test(k))).toBe(true);
    });
  }
  it('N3: the O3 folder names are never service folders either', async () => {
    for (const sub of ['example', 'e2e', 'playwright', 'cypress', '.storybook', 'scripts', 'demo', 'samples', 'testdata', 'benchmark']) {
      const p = await read({ [`${sub}/Dockerfile`]: 'FROM node:24\n', 'svc/Dockerfile': 'FROM node:24\n' });
      expect(p.services.map((s) => s.path), sub).toEqual(['svc']);
    }
  });

  it('N4: a workflow ref wins, then the plain Dockerfile, then a compose or bake ref (its own reason), then the first by name', async () => {
    const choose = async (extra: Record<string, string>) => { const notes: string[] = []; const p = await read(site(extra), notes); return { file: p.services[0]?.dockerfile, notes: notes.join('\n') }; };
    const devCompose = { 'compose.yaml': 'services:\n  site:\n    build:\n      context: .\n      dockerfile: Dockerfile.dev\n' };
    const three = { Dockerfile: 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.prod': NGINX };
    expect((await choose({ ...three, ...devCompose })).file).toBe('Dockerfile');
    expect((await choose({ ...three, ...devCompose, '.github/workflows/img.yml': run(['docker build -f Dockerfile.prod -t x .']) })).file).toBe('Dockerfile.prod');
    const composed = await choose({ 'Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.prod': NGINX, 'compose.yaml': 'services:\n  site:\n    build:\n      context: .\n      dockerfile: Dockerfile.prod\n' });
    expect(composed.file).toBe('Dockerfile.prod');
    expect(composed.notes).toContain('pipegen builds and scans Dockerfile.prod (the one a compose or bake file builds)');
    const byName = await choose({ 'Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n', 'Dockerfile.prod': NGINX });
    expect(byName.notes).toContain('(the first by name; no workflow, compose or bake file builds one of them)');
  });

  it('N5: compose and bake reads stop at 20 files each and 2 MB in all, with a note', async () => {
    const many: Record<string, string> = {};
    for (let i = 0; i < 21; i++) many[`c${String(i).padStart(2, '0')}/compose.yaml`] = 'services:\n  x:\n    image: alpine\n';
    many['c20/compose.yaml'] = 'services:\n  web:\n    build: ../apps/web\n';
    const notes: string[] = [];
    const p = await read(ws(many), notes);
    expect((p.services.find((s) => s.name === 'web') as Service).containerHint).toBeUndefined();
    expect(notes.join('\n')).toContain('Only the first 20 compose files were read for image builds.');
    const heavyOf = (comment: number): Record<string, string> => {
      const filler = `# ${'x'.repeat(comment)}\nservices:\n  x:\n    image: alpine\n`;
      return { 'a/compose.yaml': filler, 'b/compose.yaml': filler, 'c/compose.yaml': `# ${'x'.repeat(comment / 20)}\nservices:\n  web:\n    build: ../apps/web\n` };
    };
    const heavy = heavyOf(990_000);
    const notes2: string[] = [];
    const q = await read(ws(heavy), notes2);
    // G17: a ratio, not a wall-clock budget: ten times the comment text costs about ten times the time
    // G17-R2 (F6): readProject's fixed cost (about 70 ms) is measured on the same tree with empty comments and subtracted, so the
    // ratio sees the compose/bake reading itself; a floor of 5 ms for the small size means about 0.2 s of extra work fails
    const trees = { small: ws(heavyOf(99_000)), big: ws(heavy) };
    const base = ws(heavyOf(0));
    const timeRead = async (t: typeof base) => { const t0 = performance.now(); await read(t, []); return performance.now() - t0; };
    await expectScaling('compose and bake files', async (size) => Math.max(0, (await timeRead(trees[size])) - (await timeRead(base))), 40, 3, 5);
    expect(notes2.join('\n')).toMatch(/Skipped c\/compose\.yaml: the compose and bake files pipegen reads for image builds are over 2 MB together\./);
    expect((q.services.find((s) => s.name === 'web') as Service).containerHint).toBeUndefined();
  });

  it('N7: the hint row says "may be built" and the skip text names workflow, compose and bake files', async () => {
    const p = await read(ws({ 'apps/web/docker/Dockerfile': NGINX }));
    const row = wouldCreateOf(p).find((r) => r.what === 'docker' && r.why.includes('web'));
    expect(row?.why).toBe("nothing for web, which may be built into an image elsewhere (a container file builds it: apps/web/docker/Dockerfile): pipegen can't build or scan that image yet, so it is not covered.");
    expect(STATIC_SKIP).toBe('no workflow, compose or bake image build found; else use --type SERVICE=container');
  });
});

describe('GJ-R5 (review GJ-r4 R1, H1): code next to a suffixed container file is the root app\'s; expressions never cut a build line', () => {
  const CAPS5: Capabilities = { branchProtection: true, environments: false, envRequiredReviewers: false, deploymentBranchPolicies: false, attestations: false, codeScanning: true, keylessSigningAllowed: true };
  const NGINX = 'FROM nginx:1.27\nCOPY out /usr/share/nginx/html\nEXPOSE 80\n';
  const LOCK = '{"lockfileVersion":3,"packages":{}}';
  const read = async (files: Record<string, string>, notes: string[] = []): Promise<RepoProfile> => ({ ...(await readProject(repo(files), { notes })), private: false, ownerType: 'User', plan: 'free' } as RepoProfile);
  const assembled = async (p: RepoProfile) => { const a = assemble(planned(p, { over: { skipped: [{ part: 'deploy' as const, reason: 't' }] } })); return { a, issues: shown(await judge(files(a), a.draft)) }; };
  const express = (extra: Record<string, string>, own = true) => ({ 'package.json': pkg({ name: 'api', scripts: { start: 'node index.js', test: 'vitest run' }, dependencies: { express: '4.0.0' } }), 'package-lock.json': LOCK, 'index.js': "require('express')().listen(3000);\n", 'index.test.js': 'test("x", () => {});\n', ...(own ? { Dockerfile: 'FROM node:24\nEXPOSE 3000\nCMD ["node", "index.js"]\n' } : {}), ...extra });
  const site = (extra: Record<string, string>) => ({ 'package.json': nextPkg({ dev: 'next dev', build: 'next build', test: 'vitest run' }), 'package-lock.json': LOCK, 'next.config.mjs': "export default { output: 'export' };\n", 'app/page.tsx': PAGE, ...extra });

  const cases: [string, Record<string, string>][] = [
    ['root express + Dockerfile + docker/Dockerfile.dev + docker/healthcheck.js', express({ 'docker/Dockerfile.dev': 'FROM node:24\n', 'docker/healthcheck.js': '1;\n' })],
    ['root express + Dockerfile + deploy/Dockerfile.prod + deploy/scripts/smoke.js', express({ 'deploy/Dockerfile.prod': 'FROM node:24\n', 'deploy/scripts/smoke.js': '1;\n' })],
    ['root express + Dockerfile + .docker/dev.Dockerfile + .docker/seed.ts', express({ '.docker/dev.Dockerfile': 'FROM node:24\n', '.docker/seed.ts': 'export {};\n' })],
    ['root express + Dockerfile + docker/Dockerfile.test + docker/wait-for.js', express({ 'docker/Dockerfile.test': 'FROM node:24\n', 'docker/wait-for.js': '1;\n' })],
    ['root express + Dockerfile + infra/Dockerfile.lambda + infra/lambda/handler.py', express({ 'infra/Dockerfile.lambda': 'FROM public.ecr.aws/lambda/python:3.12\n', 'infra/lambda/handler.py': 'def h(e, c): return 1\n' })],
    ['root express + Dockerfile + .github/actions/n/Dockerfile.action + entrypoint.py', express({ '.github/actions/n/Dockerfile.action': 'FROM python:3.12\n', '.github/actions/n/entrypoint.py': 'print(1)\n', '.github/actions/n/action.yml': 'runs:\n  using: docker\n  image: Dockerfile.action\n' })],
    ['root static + Dockerfile.prod + docker/Dockerfile.dev + docker/dev-server.mjs', site({ 'Dockerfile.prod': NGINX, 'docker/Dockerfile.dev': 'FROM node:24\n', 'docker/dev-server.mjs': 'export {};\n' })],
  ];
  for (const [label, files] of cases) {
    it(`R1: ${label} keeps the root as its only service and assembles cleanly with image checks`, async () => {
      const notes: string[] = [];
      const p = await read(files, notes);
      expect(p.services.map((s) => [s.path, s.language])).toEqual([['.', 'node']]);
      expect(notes.join('\n')).toMatch(/has container files but no plain Dockerfile or Containerfile, and no workflow, compose or bake file builds it/);
      const { a, issues } = await assembled(p);
      expect(issues).toBe('');
      expect(Object.keys(a.merge).some((k) => /image/.test(k))).toBe(true);
    });
  }
  it('R1: with no container file of its own the root is still kept (its hint names the folder\'s file)', async () => {
    const p = await read(express({ 'docker/Dockerfile.dev': 'FROM node:24\n', 'docker/healthcheck.js': '1;\n' }, false));
    expect(p.services.map((s) => [s.path, s.language])).toEqual([['.', 'node']]);
    expect(p.services[0]?.containerHint).toContain('docker/Dockerfile.dev');
    const q = await read(site({ 'docker/Dockerfile.dev': 'FROM node:24\n', 'docker/dev-server.mjs': 'export {};\n' }));
    expect(q.services.map((s) => s.path)).toEqual(['.']);
    await expect(assembled(q)).rejects.toThrow(/--type site=static-site/);
    expect((await assembled(applyTypeOverrides(q, [{ service: 'site', type: 'static-site' }]))).issues).toBe('');
  });
  it('R1 control: a folder with code and a plain Dockerfile (or Containerfile) stays a service, as at 2450960', async () => {
    expect((await read(express({ 'worker/Dockerfile': 'FROM node:24\n', 'worker/index.js': '1;\n' }))).services.map((s) => s.path).sort()).toEqual(['.', 'worker']);
    expect((await read(express({ 'jobs/Containerfile': 'FROM node:24\n', 'jobs/run.py': 'print(1)\n' }))).services.map((s) => s.path).sort()).toEqual(['.', 'jobs']);
  });

  it('H1: a ${{ … || … }} expression on a build line (one line or continued) never ends it', async () => {
    const one = 'docker buildx build -t ghcr.io/o/web:${{ github.head_ref || github.ref_name }} -f apps/web/Dockerfile.ci apps/web';
    expect([...workflowBuildRefs([one])].sort()).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    const multi = ['docker buildx build \\', '  -t ghcr.io/o/web:${{ github.head_ref || github.ref_name }} \\', '  -f apps/web/Dockerfile.ci \\', '  apps/web'].join('\n');
    expect([...workflowBuildRefs([multi])].sort()).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    expect([...workflowBuildRefs(['docker build -t "x:$(git rev-parse --short HEAD || echo dev)" -f ops/a.Dockerfile svc-a'])].sort()).toEqual(['ops/a.Dockerfile', 'svc-a']);
    const ws = {
      'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK,
      'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
      '.github/workflows/img.yml': `on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${one} --push\n`,
    };
    const p = await read(ws);
    const web = p.services.find((s) => s.name === 'web') as Service;
    expect(web.containerHint).toContain('apps/web');
    expect(skippedChecks(p, CAPS5).some((k) => k.service === 'web' && k.why === STATIC_SKIP)).toBe(false);
  });
  it('H1: a value that is an expression is no reference', () => {
    expect([...workflowBuildRefs(['          context: ${{ matrix.context }}', '          file: ${{ matrix.df }}.Dockerfile'])]).toEqual([]);
    expect([...workflowBuildRefs(['docker build -f ${{ env.DF }} .'])]).toEqual(['.']);
  });
  it('R1 control: a folder with a plain Dockerfile and no code or manifest (an nginx image) is the root app\'s, with a note', async () => {
    const notes: string[] = [];
    const p = await read(express({ 'nginx/Dockerfile': 'FROM nginx:1.27\n' }), notes);
    expect(p.services.map((s) => s.path)).toEqual(['.']);
    expect(notes.join('\n')).toContain('The folder nginx has a plain Dockerfile but no app manifest or code, and no workflow, compose or bake file builds it');
  });
  it('H1: docker build apps/web -t img:${{ github.sha }} keeps its context', () => {
    expect([...workflowBuildRefs(['docker build apps/web -t img:${{ github.sha }}'])]).toEqual(['apps/web']);
    expect([...workflowBuildRefs(['docker build $(pwd)/x -t y apps/api'])]).toEqual(['apps/api']);
  });
  it('H1: expression blanking is bounded (deep nesting, unclosed spans, long runs finish fast and drop what they cover)', async () => {
    // G17: a ratio, not a wall-clock budget: ten times the text costs about ten times the time. G17-R2 (F5): each size runs its
    // inputs 200 times, so the per-line budget's near-zero time can't hide a quadratic
    const hostile = (n: number) => ['$('.repeat(n), '${{'.repeat(Math.floor(n * 13 / 15)), `docker build ${'$('.repeat(Math.floor(n / 15))} apps/x`, `docker build \${{ ${'|'.repeat(Math.floor(n * 8 / 3))}`];
    const inputs = { small: hostile(150), big: hostile(1500) };
    await expectScaling('expression blanking', (size) => { const t0 = performance.now(); for (let r = 0; r < 200; r++) for (const h of inputs[size]) workflowBuildRefs([h]); return performance.now() - t0; }, 40);
    expect([...workflowBuildRefs([`docker build -t x:${'$('.repeat(40)}${')'.repeat(40)} apps/x`])]).toEqual([]);
  });

  it('compose read order: shallow paths first, so a root docker-compose.yml is never pushed out by the cap', async () => {
    const files: Record<string, string> = {
      'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK,
      'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
      'docker-compose.yml': 'services:\n  web:\n    build: ./apps/web\n',
    };
    for (let i = 0; i < 21; i++) files[`apps/a${String(i).padStart(2, '0')}/docker-compose.yml`] = 'services:\n  x:\n    image: alpine\n';
    const notes: string[] = [];
    const p = await read(files, notes);
    expect(notes.join('\n')).toContain('Only the first 20 compose files were read for image builds.');
    expect((p.services.find((s) => s.name === 'web') as Service).containerHint).toContain('apps/web');
  });
});

describe('GJ-R6 (review GJ-r5 Ra, Ha, perf): suffixed app folders are the root\'s unless built; builds inside $( … ) count', () => {
  const LOCK = '{"lockfileVersion":3,"packages":{}}';
  const read = async (files: Record<string, string>, notes: string[] = []): Promise<RepoProfile> => ({ ...(await readProject(repo(files), { notes })), private: false, ownerType: 'User', plan: 'free' } as RepoProfile);
  const assembled = async (p: RepoProfile) => { const a = assemble(planned(p, { over: { skipped: [{ part: 'deploy' as const, reason: 't' }] } })); return { a, issues: shown(await judge(files(a), a.draft)) }; };
  const express = (extra: Record<string, string>) => ({ 'package.json': pkg({ name: 'api', scripts: { start: 'node index.js', test: 'vitest run' }, dependencies: { express: '4.0.0' } }), 'package-lock.json': LOCK, 'index.js': "require('express')().listen(3000);\n", 'index.test.js': 'test("x", () => {});\n', Dockerfile: 'FROM node:24\nEXPOSE 3000\nCMD ["node", "index.js"]\n', ...extra });
  const wf = (cmd: string) => `on: { push: { branches: [main] } }\njobs:\n  img:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${cmd}\n`;
  const cases: [string, string, Record<string, string>][] = [
    ['client/Dockerfile.dev (a React app with its own package.json)', 'client', { 'client/package.json': pkg({ name: 'client', scripts: { start: 'react-scripts start', build: 'react-scripts build' }, dependencies: { react: '19.0.0', 'react-scripts': '5.0.1' } }), 'client/src/App.jsx': 'export default function App() { return null; }\n', 'client/Dockerfile.dev': 'FROM node:24\nEXPOSE 3000\n' }],
    ['admin/Dockerfile.prod (a Vite app)', 'admin', { 'admin/package.json': pkg({ name: 'admin', scripts: { dev: 'vite', build: 'vite build' }, devDependencies: { vite: '7.0.0' } }), 'admin/index.html': '<html></html>\n', 'admin/src/main.ts': 'export {};\n', 'admin/Dockerfile.prod': 'FROM nginx:1.27\n' }],
    ['worker/Dockerfile.worker (requirements.txt + run.py)', 'worker', { 'worker/requirements.txt': 'requests==2.32.0\n', 'worker/run.py': 'print(1)\n', 'worker/Dockerfile.worker': 'FROM python:3.12\n' }],
  ];
  for (const [label, folder, extra] of cases) {
    it(`Ra: root express + Dockerfile + ${label} is the root only, with the note, and assembles cleanly`, async () => {
      const notes: string[] = [];
      const p = await read(express(extra), notes);
      expect(p.services.map((s) => s.path)).toEqual(['.']);
      expect(notes.join('\n')).toContain(`The folder ${folder} has container files but no plain Dockerfile or Containerfile, and no workflow, compose or bake file builds it`);
      const { a, issues } = await assembled(p);
      expect(issues).toBe('');
      expect(Object.keys(a.merge).some((k) => /image/.test(k))).toBe(true);
    });
  }
  it('Ra (b): the same folder is a service when a workflow, compose or bake file builds one of its container files (a pushed image)', async () => {
    const admin = cases[1]?.[2] as Record<string, string>;
    const byWorkflow = await read(express({ ...admin, '.github/workflows/img.yml': wf('docker build -f admin/Dockerfile.prod -t ghcr.io/o/admin admin && docker push ghcr.io/o/admin') }));
    expect(byWorkflow.services.map((s) => s.path).sort()).toEqual(['.', 'admin']);
    expect(byWorkflow.services.find((s) => s.path === 'admin')?.dockerfile).toBe('admin/Dockerfile.prod');
    const byCompose = await read(express({ ...admin, 'compose.yaml': 'services:\n  admin:\n    build:\n      context: ./admin\n      dockerfile: Dockerfile.prod\n' }));
    expect(byCompose.services.map((s) => s.path).sort()).toEqual(['.', 'admin']);
    // a context alone (no container file of the folder named) is not a build of its files
    const ctxOnly = await read(express({ ...admin, '.github/workflows/img.yml': wf('docker build -t x admin') }));
    expect(ctxOnly.services.map((s) => s.path)).toEqual(['.']);
  });
  it('Ra: the note says "no plain Dockerfile" also for a folder that holds code', async () => {
    const notes: string[] = [];
    await read(express({ 'docker/Dockerfile.dev': 'FROM node:24\n', 'docker/healthcheck.js': '1;\n' }), notes);
    expect(notes.join('\n')).toContain('The folder docker has container files but no plain Dockerfile or Containerfile');
    expect(notes.join('\n')).not.toMatch(/docker has .*no app manifest or code/);
  });

  it('Ha: a docker build inside $( … ) is read as a line of its own', async () => {
    expect([...workflowBuildRefs(['IMG=$(docker buildx build -q --load -f apps/web/Dockerfile.ci apps/web)'])].sort()).toEqual(['apps/web', 'apps/web/Dockerfile.ci']);
    expect([...workflowBuildRefs(['echo "image=$(docker build -q -f docker/web.Dockerfile apps/web)" >> "$GITHUB_OUTPUT"'])].sort()).toEqual(['apps/web', 'docker/web.Dockerfile']);
    expect([...workflowBuildRefs(['docker run --rm $(podman build -q $(pwd)/x svc)'])]).toEqual(['svc']);
    const ws = {
      'package.json': JSON.stringify({ name: 'mono', private: true, workspaces: ['apps/*'] }), 'package-lock.json': LOCK,
      'apps/web/package.json': pkg({ name: 'web', scripts: { dev: 'next dev', build: 'next build' }, dependencies: { next: '15.0.0' } }), 'apps/web/next.config.mjs': "export default { output: 'export' };\n", 'apps/web/app/page.tsx': PAGE,
      '.github/workflows/img.yml': wf('IMG=$(docker buildx build -q --load -f apps/web/Dockerfile.ci apps/web) && docker push "$IMG"'),
    };
    const p = await read(ws);
    expect((p.services.find((s) => s.name === 'web') as Service).containerHint).toContain('apps/web');
  });
  it('Ha: IMG=$(docker build -q -f Dockerfile.prod .) picks Dockerfile.prod', async () => {
    const p = await read(express({ 'Dockerfile.prod': 'FROM node:24\nEXPOSE 3000\n', '.github/workflows/img.yml': wf('IMG=$(docker build -q -f Dockerfile.prod .) && docker push "$IMG"') }));
    expect(p.services[0]?.dockerfile).toBe('Dockerfile.prod');
  });

  it('perf: 1 MB of plain lines costs about what the line regexes alone cost (8c5c368), not a character copy per line', async () => {
    const text = Array.from({ length: 25_000 }, (_, i) => `      - name: step ${i} runs the usual things here`).join('\n');
    const lineRegexes = () => { for (const line of regexLines(text)) { /^[ \t]*(?:-[ \t]+)?context:/.exec(line); /^[ \t]*(?:-[ \t]+)?file:/.exec(line); for (const _m of line.matchAll(/\b(?:docker(?:[ \t]+buildx)?|podman)[ \t]+build\b([^&|;]*)/g)) void _m; } };
    // G17: the two are timed together by expectScaling (best of 2, up to 3 attempts, a 5 ms floor on the baseline), so a pause from other
    // processes can't fail it: 'small' is the line regexes alone, 'big' is ours
    await expectScaling('workflowBuildRefs vs line regexes', (size) => {
      const t0 = performance.now();
      if (size === 'small') lineRegexes(); else workflowBuildRefs([text]);
      return performance.now() - t0;
    }, 3, 3, 5);
  });
});
