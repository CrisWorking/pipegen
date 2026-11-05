// Plan J sub-task J2 (DECISIONS #121): the project type of each service, with its evidence. Every positive test uses at
// least two invented shapes (Plan J Global Constraints: generic, never one repo's layout).
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import { floorNeeds, isRunnable, MINIMUM_CATEGORIES, skippedChecks } from '../src/engine/needs.js';
import { applyTypeOverrides } from '../src/read/project-type.js';
import { readProject } from '../src/read/project.js';
import { readWorkflows } from '../src/read/workflows.js';
import type { Capabilities, ProjectType, RepoProfile, Service, ServiceType } from '../src/types.js';
import { emptyRepoFiles, emptyServiceQuality } from '../src/read/quality.js';
import { cleanupRepos, makeTempDir, writeIn } from './helpers/make-repo.js';

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
        expect(skipped.find((k) => k.category === c && k.service === s.name)?.why, c).toBe('this service is a static site: nothing runs as a server or in a container');
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
